from __future__ import annotations

import io
import hashlib
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.ctap2.base import AssertionResponse, AttestationResponse
from fido2.webauthn import Aaguid, AttestedCredentialData, AuthenticatorData

from scripts import verify_pin


class FakeProtocol:
    VERSION = 2

    def authenticate(self, token: bytes, message: bytes) -> bytes:
        if token != b"synthetic-token" or len(message) != 32:
            raise AssertionError("unexpected synthetic PIN authorization input")
        return b"synthetic-auth-param"


class FakeResidentCtap:
    def __init__(self) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = ES256.from_cryptography_key(self.private_key.public_key())
        self.credential_id = b"synthetic-resident-credential"
        self.rp_hash = hashlib.sha256(verify_pin.RP_ID.encode()).digest()
        credential_data = AttestedCredentialData.create(
            bytes(Aaguid.NONE), self.credential_id, self.public_key
        )
        self.attestation = AttestationResponse(
            "none",
            AuthenticatorData.create(
                self.rp_hash,
                AuthenticatorData.FLAG.UP
                | AuthenticatorData.FLAG.UV
                | AuthenticatorData.FLAG.AT
                | AuthenticatorData.FLAG.ED,
                0,
                credential_data,
                {"credProtect": 3},
            ),
            {},
        )
        self.make_kwargs = None
        self.assertion_kwargs = None

    def make_credential(self, *args, **kwargs):
        self.make_kwargs = kwargs
        return self.attestation

    def get_assertions(self, rp_id, client_hash, allow_list, **kwargs):
        if rp_id != verify_pin.RP_ID or allow_list is not None:
            raise AssertionError("resident discovery must omit an allow list")
        self.assertion_kwargs = kwargs
        auth_data = AuthenticatorData.create(
            self.rp_hash,
            AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV,
            1,
        )
        signature = self.private_key.sign(
            bytes(auth_data) + client_hash, ec.ECDSA(hashes.SHA256())
        )
        return [
            AssertionResponse(
                {"type": "public-key", "id": self.credential_id},
                auth_data,
                signature,
                {"id": verify_pin.USER_ID, "name": "local-resident-test"},
            )
        ]


class FakeUnsetInfo:
    pin_uv_protocols = [2]
    options = {"clientPin": False, "rk": True}
    extensions = ["credProtect"]
    algorithms = [{"alg": -7}]
    max_pin_length = 63


class FakeUnsetCtap:
    def get_info(self):
        return FakeUnsetInfo()


class RefuseSetClientPin:
    @staticmethod
    def is_token_supported(info) -> bool:
        return True

    def __init__(self, ctap, protocol) -> None:
        pass

    def set_pin(self, pin: str) -> None:
        raise AssertionError("persisted verification must never set a new PIN")


class FakeClosingDevice:
    def close(self) -> None:
        pass


class FakeAuthorizedPin:
    def get_pin_retries(self):
        return 8, None


class PinVerifierTest(unittest.TestCase):
    def test_pin_validation_is_bounded_and_exact(self) -> None:
        verify_pin.validate_new_pin("four", "four", 63)
        for pin, confirmation, maximum in [
            ("abc", "abc", 63),
            ("four", "five", 63),
            ("null\0pin", "null\0pin", 63),
            ("four", "four", 3),
        ]:
            with self.assertRaises(verify_pin.PinVerificationError):
                verify_pin.validate_new_pin(pin, confirmation, maximum)

    def test_resident_creation_and_discovery_require_uv_and_credprotect3(self) -> None:
        fake = FakeResidentCtap()
        protocol = FakeProtocol()
        credential = verify_pin.make_resident_credential(fake, protocol, b"synthetic-token")
        self.assertEqual(fake.make_kwargs["extensions"], {"credProtect": 3})
        self.assertEqual(fake.make_kwargs["options"], {"rk": True})
        self.assertNotIn("uv", fake.make_kwargs["options"])

        verify_pin.verify_resident_assertion(fake, protocol, b"synthetic-token", credential)
        self.assertEqual(fake.assertion_kwargs["options"], {"up": True})
        self.assertNotIn("uv", fake.assertion_kwargs["options"])

    def test_persisted_mode_refuses_missing_pin_without_prompt_or_set(self) -> None:
        with patch.object(verify_pin, "ClientPin", RefuseSetClientPin):
            with self.assertRaisesRegex(
                verify_pin.PinVerificationError,
                "existing PIN to survive restart",
            ):
                verify_pin.prompt_for_pin(FakeUnsetCtap(), require_existing=True)

    def test_bad_assertion_signature_is_rejected(self) -> None:
        fake = FakeResidentCtap()
        credential = verify_pin.PublicCredential(fake.credential_id, fake.public_key)
        original = fake.get_assertions

        def corrupt_signature(*args, **kwargs):
            response = original(*args, **kwargs)[0]
            return [
                AssertionResponse(
                    response.credential,
                    response.auth_data,
                    b"invalid-signature",
                    response.user,
                )
            ]

        fake.get_assertions = corrupt_signature
        with self.assertRaises(InvalidSignature):
            verify_pin.verify_resident_assertion(
                fake,
                FakeProtocol(),
                b"synthetic-token",
                credential,
            )

    def test_initial_run_waits_before_each_fresh_token_and_operation(self) -> None:
        events = []
        permissions = verify_pin.ClientPin.PERMISSION

        def token(_client_pin, _pin, permission):
            events.append(f"token-{permission.name}")
            return b"synthetic-token"

        with patch.object(verify_pin, "select_device", return_value=FakeClosingDevice()), \
             patch.object(verify_pin, "Ctap2", return_value=object()), \
             patch.object(
                 verify_pin,
                 "prompt_for_pin",
                 return_value=(FakeProtocol(), FakeAuthorizedPin(), "private", "VERIFIED", 8),
             ), \
             patch.object(verify_pin, "wait_until_ready", side_effect=lambda: events.append("ready")), \
             patch.object(verify_pin, "get_permission_token", side_effect=token), \
             patch.object(
                 verify_pin,
                 "make_resident_credential",
                 side_effect=lambda *_: events.append("make") or object(),
             ), \
             patch.object(
                 verify_pin,
                 "verify_resident_assertion",
                 side_effect=lambda *_: events.append("assert"),
             ):
            with redirect_stdout(io.StringIO()):
                result = verify_pin.run(
                    SimpleNamespace(verify_persisted=False, save_public_record=False, pause=False)
                )

        self.assertEqual(result, 0)
        self.assertEqual(
            events,
            [
                "ready",
                f"token-{permissions.MAKE_CREDENTIAL.name}",
                "make",
                "ready",
                f"token-{permissions.GET_ASSERTION.name}",
                "assert",
            ],
        )

    def test_persisted_run_waits_before_fresh_assertion_token(self) -> None:
        events = []

        def token(_client_pin, _pin, permission):
            events.append(f"token-{permission.name}")
            return b"synthetic-token"

        with patch.object(verify_pin, "select_device", return_value=FakeClosingDevice()), \
             patch.object(verify_pin, "Ctap2", return_value=object()), \
             patch.object(verify_pin, "load_public_record", return_value=object()), \
             patch.object(
                 verify_pin,
                 "prompt_for_pin",
                 return_value=(FakeProtocol(), FakeAuthorizedPin(), "private", "VERIFIED", 8),
             ), \
             patch.object(verify_pin, "wait_until_ready", side_effect=lambda: events.append("ready")), \
             patch.object(verify_pin, "get_permission_token", side_effect=token), \
             patch.object(
                 verify_pin,
                 "verify_resident_assertion",
                 side_effect=lambda *_: events.append("assert"),
             ):
            with redirect_stdout(io.StringIO()):
                result = verify_pin.run(
                    SimpleNamespace(verify_persisted=True, save_public_record=False, pause=False)
                )

        self.assertEqual(result, 0)
        self.assertEqual(events, ["ready", "token-GET_ASSERTION", "assert"])

    def test_public_record_is_public_only_and_mode_0600(self) -> None:
        fake = FakeResidentCtap()
        credential = verify_pin.PublicCredential(fake.credential_id, fake.public_key)
        original_path = verify_pin.PUBLIC_RECORD
        with tempfile.TemporaryDirectory() as directory:
            verify_pin.PUBLIC_RECORD = Path(directory) / "resident.json"
            try:
                verify_pin.save_public_record(credential)
                loaded = verify_pin.load_public_record()
                self.assertEqual(verify_pin.PUBLIC_RECORD.stat().st_mode & 0o777, 0o600)
                self.assertEqual(loaded.credential_id, credential.credential_id)
                self.assertEqual(dict(loaded.public_key), dict(credential.public_key))
                self.assertNotIn("private", verify_pin.PUBLIC_RECORD.read_text().lower())

                private_shaped = ES256({**dict(fake.public_key), -4: b"not-a-private-key"})
                with self.assertRaises(verify_pin.PinVerificationError):
                    verify_pin.save_public_record(
                        verify_pin.PublicCredential(fake.credential_id, private_shaped)
                    )
            finally:
                verify_pin.PUBLIC_RECORD = original_path


if __name__ == "__main__":
    unittest.main()
