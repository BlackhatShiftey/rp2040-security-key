from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.ctap2.base import AssertionResponse, AttestationResponse
from fido2.webauthn import Aaguid, AttestedCredentialData, AuthenticatorData

from scripts import verify_key


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PICO_FIDO_SOURCE = Path(
    os.environ.get("PICO_FIDO_SOURCE", PROJECT_ROOT / "vendor/pico-fido")
).resolve()
MAKE_CREDENTIAL_SOURCE = PICO_FIDO_SOURCE / "src/fido/cbor_make_credential.c"
GET_INFO_SOURCE = PICO_FIDO_SOURCE / "src/fido/cbor_get_info.c"


def no_pin_presence_block(source: str) -> str:
    start_marker = "if (options.up == ptrue || options.up == NULL) { //14.1"
    start = source.index(start_marker)
    end = source.index("flags |= FIDO2_AUT_FLAG_UP;", start)
    return source[start:end]


class PresenceSourceRegressionTest(unittest.TestCase):
    def test_no_pin_registration_requires_presence_before_up(self) -> None:
        block = no_pin_presence_block(MAKE_CREDENTIAL_SOURCE.read_text(encoding="utf-8"))
        self.assertIn("else if (!(flags & FIDO2_AUT_FLAG_UP))", block)
        no_pin = block.split("else if (!(flags & FIDO2_AUT_FLAG_UP))", 1)[1]
        self.assertIn("check_user_presence() == false", no_pin)
        self.assertIn("CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED)", no_pin)
        self.assertIn("button_pressed = phy_data.up_btn != 0", no_pin)

    def test_pre_fix_shape_is_rejected(self) -> None:
        pre_fix = """
        if (options.up == ptrue || options.up == NULL) { //14.1
            if (pinUvAuthParam.present == true) {
                if (check_user_presence() == false) { return 1; }
            }
            flags |= FIDO2_AUT_FLAG_UP;
        }
        """
        self.assertNotIn(
            "else if (!(flags & FIDO2_AUT_FLAG_UP))",
            no_pin_presence_block(pre_fix),
        )


class TransportSourceRegressionTest(unittest.TestCase):
    def test_get_info_reports_exact_usb_transport_in_canonical_order(self) -> None:
        source = GET_INFO_SOURCE.read_text(encoding="utf-8")
        start = source.index("cbor_encode_uint(&mapEncoder, 0x08)")
        end = source.index("cbor_encode_uint(&mapEncoder, 0x0A)", start)
        transport_block = source[start:end]

        self.assertIn("uint8_t lfields = 21;", source)
        self.assertEqual(
            transport_block.count("cbor_encode_uint(&mapEncoder, 0x09)"), 1
        )
        self.assertIn(
            "cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 1)",
            transport_block,
        )
        self.assertEqual(
            transport_block.count('cbor_encode_text_stringz(&arrayEncoder, "usb")'),
            1,
        )
        self.assertIn(
            "cbor_encoder_close_container(&mapEncoder, &arrayEncoder)",
            transport_block,
        )


class FakeCtap:
    def __init__(self) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = ES256.from_cryptography_key(self.private_key.public_key())
        self.credential_id = b"synthetic-local-test-credential"
        self.rp_hash = hashlib.sha256(verify_key.RP_ID.encode()).digest()
        credential_data = AttestedCredentialData.create(
            bytes(Aaguid.NONE), self.credential_id, self.public_key
        )
        auth_data = AuthenticatorData.create(
            self.rp_hash,
            AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
            0,
            credential_data,
        )
        self.attestation = AttestationResponse("none", auth_data, {})
        self.assertion_calls = 0

    def make_credential(self, *args, **kwargs):
        return self.attestation

    def get_assertions(self, rp_id, client_hash, allow_list, **kwargs):
        self.assertion_calls += 1
        self.assertEqualRequest(rp_id, allow_list)
        if self.assertion_calls == 1:
            raise CtapError(CtapError.ERR.KEEPALIVE_CANCEL)
        auth_data = AuthenticatorData.create(
            self.rp_hash, AuthenticatorData.FLAG.UP, self.assertion_calls
        )
        signature = self.private_key.sign(
            bytes(auth_data) + client_hash, ec.ECDSA(hashes.SHA256())
        )
        return [
            AssertionResponse(
                {"type": "public-key", "id": self.credential_id},
                auth_data,
                signature,
            )
        ]

    def assertEqualRequest(self, rp_id, allow_list) -> None:
        if rp_id != verify_key.RP_ID or allow_list[0]["id"] != self.credential_id:
            raise AssertionError("unexpected assertion request")


class VerifierRegressionTest(unittest.TestCase):
    def test_assertion_gate_cancels_without_touch(self) -> None:
        fake = FakeCtap()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            verify_key,
            "LOCAL_CREDENTIAL_PATH",
            Path(directory) / "missing-synthetic-credential.json",
        ):
            verify_key.run_no_touch_assertion_test(fake)
        self.assertEqual(fake.assertion_calls, 1)

    def test_public_credential_round_trip_is_local_and_private(self) -> None:
        fake = FakeCtap()
        credential = verify_key.validate_credential(fake.attestation)
        original_path = verify_key.LOCAL_CREDENTIAL_PATH
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "local-test.invalid-credential.json"
            verify_key.LOCAL_CREDENTIAL_PATH = path
            try:
                verify_key.save_public_credential(credential)
                loaded = verify_key.load_public_credential()
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(loaded.credential_id, credential.credential_id)
                self.assertEqual(dict(loaded.public_key), dict(credential.public_key))
                content = path.read_text(encoding="utf-8")
                self.assertIn('"rp_id": "local-test.invalid"', content)
                self.assertNotIn("private", content.lower())
            finally:
                verify_key.LOCAL_CREDENTIAL_PATH = original_path


if __name__ == "__main__":
    unittest.main()
