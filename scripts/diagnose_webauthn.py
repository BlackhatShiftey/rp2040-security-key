#!/usr/bin/env python3
"""Serve a loopback-only WebAuthn authenticator-classification diagnostic.

The browser sends one attestation object to this process for in-memory parsing.
Only a small allowlist of classification fields is returned. Raw WebAuthn
material is neither logged nor persisted.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping

from fido2.webauthn import AttestationObject, AuthenticatorData


BIND_HOST = "127.0.0.1"
RP_ID = "localhost"
MAX_REQUEST_BYTES = 96 * 1024
MAX_ATTESTATION_BYTES = 64 * 1024
ALLOWED_ATTACHMENTS = {"cross-platform", "platform", None}
ALLOWED_TRANSPORTS = {"ble", "hybrid", "internal", "nfc", "smart-card", "usb"}


class DiagnosticError(ValueError):
    """An intentionally nonspecific error safe to return to the browser."""


def _decode_base64url(value: Any) -> bytes:
    if not isinstance(value, str) or not value or len(value) > MAX_REQUEST_BYTES:
        raise DiagnosticError("invalid diagnostic payload")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DiagnosticError("invalid diagnostic payload") from exc
    if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in value):
        raise DiagnosticError("invalid diagnostic payload")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DiagnosticError("invalid diagnostic payload") from exc
    if not decoded or len(decoded) > MAX_ATTESTATION_BYTES:
        raise DiagnosticError("invalid diagnostic payload")
    return decoded


def _validated_browser_fields(payload: Mapping[str, Any]) -> tuple[str | None, list[str]]:
    attachment = payload.get("authenticatorAttachment")
    if attachment not in ALLOWED_ATTACHMENTS:
        raise DiagnosticError("invalid browser classification fields")

    transports = payload.get("transports")
    if not isinstance(transports, list) or len(transports) > len(ALLOWED_TRANSPORTS):
        raise DiagnosticError("invalid browser classification fields")
    if any(not isinstance(item, str) or item not in ALLOWED_TRANSPORTS for item in transports):
        raise DiagnosticError("invalid browser classification fields")
    return attachment, sorted(set(transports))


def inspect_attestation(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Parse a WebAuthn response and return only non-secret classification data."""
    if not isinstance(payload, Mapping) or set(payload) != {
        "attestationObject",
        "authenticatorAttachment",
        "transports",
    }:
        raise DiagnosticError("invalid diagnostic payload")

    attachment, transports = _validated_browser_fields(payload)
    raw_attestation = _decode_base64url(payload["attestationObject"])
    try:
        attestation = AttestationObject(raw_attestation)
        auth_data = attestation.auth_data
        credential_data = auth_data.credential_data
        if credential_data is None or not auth_data.is_attested():
            raise DiagnosticError("attested credential data is missing")
        if auth_data.rp_id_hash != hashlib.sha256(RP_ID.encode("ascii")).digest():
            raise DiagnosticError("unexpected relying party data")
        if not isinstance(attestation.fmt, str) or not attestation.fmt or len(attestation.fmt) > 64:
            raise DiagnosticError("invalid attestation format")
        if not isinstance(attestation.att_stmt, Mapping):
            raise DiagnosticError("invalid attestation statement")
        x5c = attestation.att_stmt.get("x5c")
        if x5c is not None and not isinstance(x5c, (list, tuple)):
            raise DiagnosticError("invalid attestation certificate data")
    except DiagnosticError:
        raise
    except Exception as exc:
        raise DiagnosticError("malformed attestation data") from exc

    flags = auth_data.flags
    certificate_present = bool(x5c)
    notes: list[str] = []
    if attachment == "cross-platform":
        notes.append("The browser reports an external authenticator.")
    elif attachment is None:
        notes.append("The browser did not report an authenticator attachment type.")
    else:
        notes.append("The browser reports a platform authenticator.")
    if "usb" in transports:
        notes.append("The credential response advertises USB transport.")
    if certificate_present:
        notes.append("Attestation includes an x5c certificate chain that a relying party may use for model recognition.")
    else:
        notes.append("Attestation has no x5c certificate chain; a relying party may be unable to map it to a recognized hardware model.")
    notes.append("Only the relying party can determine its final hardware-key classification.")

    return {
        "browser_authenticator_attachment": attachment,
        "transports": transports,
        "attestation_format": attestation.fmt,
        "aaguid": str(credential_data.aaguid),
        "flags": {
            "user_present": bool(flags & AuthenticatorData.FLAG.UP),
            "user_verified": bool(flags & AuthenticatorData.FLAG.UV),
            "backup_eligible": bool(flags & AuthenticatorData.FLAG.BE),
            "backup_state": bool(flags & AuthenticatorData.FLAG.BS),
        },
        "attestation_certificate_present": certificate_present,
        "classification_notes": notes,
    }


def _page(nonce: str) -> bytes:
    html = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Local WebAuthn diagnostic</title>
  <style nonce="__NONCE__">
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    main { max-width: 48rem; margin: 3rem auto; padding: 0 1rem; }
    button { font: inherit; padding: .7rem 1rem; }
    pre { border: 1px solid #7778; border-radius: .4rem; padding: 1rem; white-space: pre-wrap; }
    .warning { border-left: .3rem solid #c98200; padding-left: .8rem; }
  </style>
</head>
<body>
<main>
  <h1>Local WebAuthn classification diagnostic</h1>
  <p>This creates one throwaway, non-discoverable credential for <code>localhost</code>. It does not contact OpenAI or modify your account.</p>
  <p class="warning">Use the Pico FIDO key when Chrome asks. Enter its PIN only in Chrome, then press the key's configured user-presence button.</p>
  <button id="start" type="button">Run diagnostic</button>
  <pre id="output" aria-live="polite">Waiting for your click.</pre>
</main>
<script nonce="__NONCE__">
"use strict";
const start = document.getElementById("start");
const output = document.getElementById("output");

function encodeBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

start.addEventListener("click", async () => {
  start.disabled = true;
  output.textContent = "Waiting for Chrome and the security key…";
  try {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      throw new Error("This browser does not expose WebAuthn.");
    }
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const credential = await navigator.credentials.create({ publicKey: {
      challenge,
      rp: { id: "localhost", name: "Local WebAuthn diagnostic" },
      user: { id: userId, name: "local-diagnostic", displayName: "Local diagnostic" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      timeout: 90000,
      authenticatorSelection: {
        authenticatorAttachment: "cross-platform",
        residentKey: "discouraged",
        requireResidentKey: false,
        userVerification: "preferred"
      },
      attestation: "direct"
    }});
    if (!credential || !credential.response || typeof credential.response.getTransports !== "function") {
      throw new Error("The browser returned an incomplete WebAuthn response.");
    }
    const response = await fetch("/inspect", {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        attestationObject: encodeBase64url(credential.response.attestationObject),
        authenticatorAttachment: credential.authenticatorAttachment,
        transports: credential.response.getTransports()
      })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "The local parser rejected the response.");
    output.textContent = JSON.stringify(result, null, 2);
  } catch (error) {
    output.textContent = `Diagnostic stopped: ${error && error.name ? error.name : "Error"}. ${error && error.message ? error.message : "No details available."}`;
  } finally {
    start.disabled = false;
  }
});
</script>
</body>
</html>
"""
    return html.replace("__NONCE__", nonce).replace("__NONCE__", nonce).encode("utf-8")


class DiagnosticServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class DiagnosticHandler(BaseHTTPRequestHandler):
    server: DiagnosticServer

    def log_message(self, _format: str, *args: Any) -> None:
        # Do not log paths, headers, request bodies, or parser failures.
        return

    @property
    def expected_host(self) -> str:
        return f"localhost:{self.server.server_port}"

    @property
    def expected_origin(self) -> str:
        return f"http://{self.expected_host}"

    def _send_headers(self, status: HTTPStatus, content_type: str, length: int, nonce: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Permissions-Policy", "publickey-credentials-create=(self)")
        if nonce is not None:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; "
                f"script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                "connect-src 'self'; img-src 'none'; font-src 'none'; "
                "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            )
        else:
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.end_headers()

    def _send_json(self, status: HTTPStatus, value: Mapping[str, Any]) -> None:
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._send_headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _valid_host(self) -> bool:
        return self.headers.get("Host") == self.expected_host

    def do_GET(self) -> None:
        if self.path != "/" or not self._valid_host():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        nonce = secrets.token_urlsafe(24)
        body = _page(nonce)
        self._send_headers(HTTPStatus.OK, "text/html; charset=utf-8", len(body), nonce)
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != "/inspect" or not self._valid_host():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if self.headers.get("Origin") != self.expected_origin:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "origin rejected"})
            return
        if self.headers.get_content_type() != "application/json":
            self._send_json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "JSON required"})
            return
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            content_length = -1
        if content_length < 1 or content_length > MAX_REQUEST_BYTES:
            self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request rejected"})
            return
        try:
            raw_request = self.rfile.read(content_length)
            if len(raw_request) != content_length:
                raise DiagnosticError("incomplete request")
            payload = json.loads(raw_request)
            result = inspect_attestation(payload)
        except (DiagnosticError, json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "diagnostic data rejected"})
            return
        self._send_json(HTTPStatus.OK, result)


def create_server(port: int = 0) -> DiagnosticServer:
    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    return DiagnosticServer((BIND_HOST, port), DiagnosticHandler)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a localhost-only WebAuthn classification diagnostic."
    )
    parser.add_argument("--port", type=int, default=0, help="localhost port (default: ephemeral)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        server = create_server(args.port)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"unable to start diagnostic server: {exc}") from exc
    url = f"http://localhost:{server.server_port}/"
    print(f"Open {url}", flush=True)
    print("The server is bound only to 127.0.0.1. Press Ctrl-C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDiagnostic stopped.", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
