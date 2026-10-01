from __future__ import annotations

import base64
import hashlib
import http.client
import io
import json
import threading
import unittest
from contextlib import redirect_stderr

from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.webauthn import (
    Aaguid,
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorData,
)

from scripts import diagnose_webauthn


TEST_AAGUID = "89fb94b7-06c9-3673-9b7e-30526d968145"
SENSITIVE_CREDENTIAL_ID = b"must-not-appear-credential-id"
SENSITIVE_SIGNATURE = b"must-not-appear-signature"


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def make_attestation(*, certificate: bool = False) -> bytes:
    public_key = ES256.from_cryptography_key(
        ec.generate_private_key(ec.SECP256R1()).public_key()
    )
    credential_data = AttestedCredentialData.create(
        bytes(Aaguid.parse(TEST_AAGUID)),
        SENSITIVE_CREDENTIAL_ID,
        public_key,
    )
    auth_data = AuthenticatorData.create(
        hashlib.sha256(diagnose_webauthn.RP_ID.encode("ascii")).digest(),
        AuthenticatorData.FLAG.UP
        | AuthenticatorData.FLAG.UV
        | AuthenticatorData.FLAG.BE
        | AuthenticatorData.FLAG.BS
        | AuthenticatorData.FLAG.AT,
        7,
        credential_data,
    )
    statement = {"alg": -7, "sig": SENSITIVE_SIGNATURE}
    if certificate:
        statement["x5c"] = [b"synthetic-certificate"]
    return bytes(AttestationObject.create("packed", auth_data, statement))


def make_payload(*, certificate: bool = False) -> dict[str, object]:
    return {
        "attestationObject": base64url(make_attestation(certificate=certificate)),
        "authenticatorAttachment": "cross-platform",
        "transports": ["usb"],
    }


class WebAuthnInspectionTest(unittest.TestCase):
    def test_extracts_only_classification_fields(self) -> None:
        result = diagnose_webauthn.inspect_attestation(make_payload())

        self.assertEqual(result["browser_authenticator_attachment"], "cross-platform")
        self.assertEqual(result["transports"], ["usb"])
        self.assertEqual(result["attestation_format"], "packed")
        self.assertEqual(result["aaguid"], TEST_AAGUID)
        self.assertEqual(
            result["flags"],
            {
                "user_present": True,
                "user_verified": True,
                "backup_eligible": True,
                "backup_state": True,
            },
        )
        self.assertFalse(result["attestation_certificate_present"])
        self.assertEqual(
            set(result),
            {
                "browser_authenticator_attachment",
                "transports",
                "attestation_format",
                "aaguid",
                "flags",
                "attestation_certificate_present",
                "classification_notes",
            },
        )

        serialized = json.dumps(result)
        self.assertNotIn(SENSITIVE_CREDENTIAL_ID.decode("ascii"), serialized)
        self.assertNotIn(SENSITIVE_SIGNATURE.decode("ascii"), serialized)
        for forbidden_name in (
            "credential_id",
            "clientDataJSON",
            "public_key",
            "signature",
            "attestationObject",
        ):
            self.assertNotIn(forbidden_name, serialized)

    def test_reports_x5c_presence_without_certificate_material(self) -> None:
        result = diagnose_webauthn.inspect_attestation(make_payload(certificate=True))
        self.assertTrue(result["attestation_certificate_present"])
        self.assertNotIn("synthetic-certificate", json.dumps(result))

    def test_rejects_oversize_and_malformed_data(self) -> None:
        oversized = base64url(b"x" * (diagnose_webauthn.MAX_ATTESTATION_BYTES + 1))
        with self.assertRaises(diagnose_webauthn.DiagnosticError):
            diagnose_webauthn.inspect_attestation(
                {
                    "attestationObject": oversized,
                    "authenticatorAttachment": "cross-platform",
                    "transports": ["usb"],
                }
            )
        with self.assertRaises(diagnose_webauthn.DiagnosticError):
            diagnose_webauthn.inspect_attestation(
                {
                    "attestationObject": "not_cbor",
                    "authenticatorAttachment": "cross-platform",
                    "transports": ["usb"],
                }
            )
        malformed = make_payload()
        malformed["unexpected"] = "field"
        with self.assertRaises(diagnose_webauthn.DiagnosticError):
            diagnose_webauthn.inspect_attestation(malformed)


class WebAuthnPageTest(unittest.TestCase):
    def test_page_requires_click_and_has_safe_creation_options(self) -> None:
        page = diagnose_webauthn._page("synthetic-nonce").decode("utf-8")
        self.assertIn('addEventListener("click"', page)
        self.assertIn('authenticatorAttachment: "cross-platform"', page)
        self.assertIn('residentKey: "discouraged"', page)
        self.assertIn("requireResidentKey: false", page)
        self.assertIn('userVerification: "preferred"', page)
        self.assertIn('attestation: "direct"', page)
        self.assertNotIn("navigator.credentials.create" , page.split('addEventListener("click"')[0])
        for forbidden_name in ("rawId", "clientDataJSON", "getPublicKey", "signature"):
            self.assertNotIn(forbidden_name, page)

    def test_default_server_binds_only_loopback(self) -> None:
        server = diagnose_webauthn.create_server()
        try:
            self.assertEqual(server.server_address[0], "127.0.0.1")
            self.assertGreater(server.server_port, 0)
        finally:
            server.server_close()


class WebAuthnHttpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server = diagnose_webauthn.create_server()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port
        self.host = f"localhost:{self.port}"
        self.origin = f"http://{self.host}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        request_headers = {"Host": self.host, **(headers or {})}
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_page_has_csp_and_no_store(self) -> None:
        status, headers, _body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store, max-age=0")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertIn("script-src 'nonce-", headers["Content-Security-Policy"])
        self.assertIn("connect-src 'self'", headers["Content-Security-Policy"])

    def test_post_returns_sanitized_result_and_no_logs(self) -> None:
        raw_body = json.dumps(make_payload()).encode("utf-8")
        captured = io.StringIO()
        with redirect_stderr(captured):
            status, headers, body = self.request(
                "POST",
                "/inspect",
                raw_body,
                {"Content-Type": "application/json", "Origin": self.origin},
            )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store, max-age=0")
        result = json.loads(body)
        self.assertEqual(result["aaguid"], TEST_AAGUID)
        self.assertNotIn(SENSITIVE_CREDENTIAL_ID.decode("ascii"), body.decode("utf-8"))
        self.assertEqual(captured.getvalue(), "")

    def test_rejects_bad_origin_malformed_and_oversize_without_logging_body(self) -> None:
        secret_marker = b"never-log-this-body"
        captured = io.StringIO()
        with redirect_stderr(captured):
            bad_origin_status, _, _ = self.request(
                "POST",
                "/inspect",
                secret_marker,
                {"Content-Type": "application/json", "Origin": "http://example.invalid"},
            )
            malformed_status, _, malformed_body = self.request(
                "POST",
                "/inspect",
                secret_marker,
                {"Content-Type": "application/json", "Origin": self.origin},
            )
            oversize_status, _, _ = self.request(
                "POST",
                "/inspect",
                b"",
                {
                    "Content-Type": "application/json",
                    "Origin": self.origin,
                    "Content-Length": str(diagnose_webauthn.MAX_REQUEST_BYTES + 1),
                },
            )
        self.assertEqual(bad_origin_status, 403)
        self.assertEqual(malformed_status, 400)
        self.assertEqual(oversize_status, 413)
        self.assertNotIn(secret_marker, malformed_body)
        self.assertEqual(captured.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
