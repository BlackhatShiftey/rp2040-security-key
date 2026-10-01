#!/usr/bin/env python3
"""Privately qualify a PIN-protected resident credential on Pico FIDO."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import stat
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Timer

from fido2 import cbor
from fido2.cose import CoseKey, ES256
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.hid import CtapHidDevice


VID = 0x2E8A
PID = 0x10FE
RP_ID = "local-test.invalid"
USER_ID = hashlib.sha256(b"rp2040-zero:local-test.invalid:resident-user").digest()
TIMEOUT_SECONDS = 45
PUBLIC_RECORD = Path(__file__).resolve().parents[1] / "evidence" / "local-test.invalid-resident.json"
PUBLIC_ES256_FIELDS = {1, 3, -1, -2, -3}


class PinVerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class PublicCredential:
    credential_id: bytes
    public_key: CoseKey


def select_device() -> CtapHidDevice:
    opened = list(CtapHidDevice.list_devices())
    matches = [device for device in opened if device.descriptor.vid == VID and device.descriptor.pid == PID]
    if len(matches) != 1:
        for device in opened:
            device.close()
        raise PinVerificationError("expected exactly one allowlisted Pico FIDO device")
    selected = matches[0]
    for device in opened:
        if device is not selected:
            device.close()
    return selected


def validate_new_pin(pin: str, confirmation: str, maximum_bytes: int) -> None:
    if pin != confirmation:
        raise PinVerificationError("PIN confirmation did not match")
    if "\0" in pin or len(pin) < 4:
        raise PinVerificationError("PIN must contain at least four characters")
    if len(pin.encode("utf-8")) > maximum_bytes:
        raise PinVerificationError("PIN exceeds the authenticator limit")


def require_private_terminal() -> None:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise PinVerificationError("PIN entry requires a private interactive terminal")
    try:
        descriptor = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError as exc:
        raise PinVerificationError("PIN entry requires a controlling terminal") from exc
    else:
        os.close(descriptor)


def private_getpass(prompt: str) -> str:
    require_private_terminal()
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt)
        except getpass.GetPassWarning as exc:
            raise PinVerificationError("hidden PIN entry is unavailable") from exc


def prompt_for_pin(ctap: Ctap2, require_existing: bool):
    info = ctap.get_info()
    if 2 not in info.pin_uv_protocols or not ClientPin.is_token_supported(info):
        raise PinVerificationError("permission-scoped PIN protocol 2 is unavailable")
    if "clientPin" not in info.options:
        raise PinVerificationError("client PIN is unsupported")
    if not info.options.get("rk"):
        raise PinVerificationError("resident credentials are unsupported")
    if "credProtect" not in info.extensions:
        raise PinVerificationError("credential protection level 3 is unsupported")
    if not any(item.get("alg") == -7 for item in info.algorithms):
        raise PinVerificationError("ES256 credentials are unsupported")

    protocol = PinProtocolV2()
    client_pin = ClientPin(ctap, protocol)
    if info.options.get("clientPin") is True:
        retries_before = client_pin.get_pin_retries()[0]
        if retries_before <= 0:
            raise PinVerificationError("PIN entry is blocked; power cycle the key and inspect it manually")
        pin = private_getpass("Security-key PIN: ")
        action = "VERIFIED"
    else:
        if require_existing:
            raise PinVerificationError("persisted verification requires the existing PIN to survive restart")
        pin = private_getpass("Choose final security-key PIN: ")
        confirmation = private_getpass("Confirm final security-key PIN: ")
        validate_new_pin(pin, confirmation, info.max_pin_length or 63)
        confirmation = ""
        client_pin.set_pin(pin)
        retries_before = client_pin.get_pin_retries()[0]
        action = "SET"
    return protocol, client_pin, pin, action, retries_before


def get_permission_token(client_pin: ClientPin, pin: str, permission: ClientPin.PERMISSION) -> bytes:
    return client_pin.get_pin_token(
        pin,
        permissions=permission,
        permissions_rpid=RP_ID,
    )


def wait_until_ready() -> None:
    try:
        response = input(
            "Press Enter when ready, then press/release BOOT promptly. "
            "Do not press RESET. Do not type PIN here. "
        )
    except EOFError as exc:
        raise PinVerificationError("interactive readiness input ended unexpectedly") from exc
    if response:
        response = ""
        raise PinVerificationError("readiness requires an empty Enter; no key operation was started")


def operation_event() -> tuple[Event, Timer]:
    event = Event()
    timer = Timer(TIMEOUT_SECONDS, event.set)
    timer.daemon = True
    timer.start()
    return event, timer


def request_hash(label: bytes) -> bytes:
    return hashlib.sha256(b"rp2040-zero-pin-test:" + label + b":" + os.urandom(32)).digest()


def validate_public_es256(public_key: CoseKey) -> None:
    if not isinstance(public_key, ES256) or set(public_key) != PUBLIC_ES256_FIELDS or -4 in public_key:
        raise PinVerificationError("resident credential public key is not public-only ES256")


def make_resident_credential(ctap: Ctap2, protocol: PinProtocolV2, token: bytes) -> PublicCredential:
    client_hash = request_hash(b"create")
    event, timer = operation_event()
    print("phase=touch-for-pin-protected-resident-credential", file=sys.stderr, flush=True)
    try:
        response = ctap.make_credential(
            client_hash,
            {"id": RP_ID, "name": "Local Security Key Verification"},
            {"id": USER_ID, "name": "local-resident-test", "displayName": "Local resident test"},
            [{"type": "public-key", "alg": -7}],
            extensions={"credProtect": 3},
            options={"rk": True},
            pin_uv_param=protocol.authenticate(token, client_hash),
            pin_uv_protocol=protocol.VERSION,
            event=event,
        )
    finally:
        timer.cancel()

    data = response.auth_data
    credential = data.credential_data
    expected_rp_hash = hashlib.sha256(RP_ID.encode()).digest()
    if data.rp_id_hash != expected_rp_hash or not data.is_user_present() or not data.is_user_verified():
        raise PinVerificationError("resident credential lacks required RP/UP/UV properties")
    if data.extensions is None or data.extensions.get("credProtect") != 3:
        raise PinVerificationError("resident credential did not confirm credential protection level 3")
    if credential is None:
        raise PinVerificationError("resident credential data is missing")
    validate_public_es256(credential.public_key)
    return PublicCredential(credential.credential_id, credential.public_key)


def verify_resident_assertion(
    ctap: Ctap2,
    protocol: PinProtocolV2,
    token: bytes,
    expected: PublicCredential,
) -> None:
    client_hash = request_hash(b"assert")
    event, timer = operation_event()
    print("phase=touch-for-pin-protected-resident-assertion", file=sys.stderr, flush=True)
    try:
        assertions = ctap.get_assertions(
            RP_ID,
            client_hash,
            allow_list=None,
            options={"up": True},
            pin_uv_param=protocol.authenticate(token, client_hash),
            pin_uv_protocol=protocol.VERSION,
            event=event,
        )
    finally:
        timer.cancel()
    matching = [
        item
        for item in assertions
        if item.credential is not None
        and item.credential.get("type") == "public-key"
        and item.credential.get("id") == expected.credential_id
    ]
    if len(matching) != 1:
        raise PinVerificationError("discoverable resident credential did not match")
    assertion = matching[0]
    data = assertion.auth_data
    if not data.is_user_present() or not data.is_user_verified():
        raise PinVerificationError("resident assertion lacks required UP/UV flags")
    if data.rp_id_hash != hashlib.sha256(RP_ID.encode()).digest():
        raise PinVerificationError("resident assertion RP ID mismatch")
    if assertion.user is None or assertion.user.get("id") != USER_ID:
        raise PinVerificationError("resident assertion user ID mismatch")
    assertion.verify(client_hash, expected.public_key)


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: object, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise PinVerificationError("invalid public credential field")
    padded = value + "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise PinVerificationError("invalid public credential encoding") from exc
    if not decoded or len(decoded) > maximum:
        raise PinVerificationError("invalid public credential length")
    return decoded


def save_public_record(credential: PublicCredential) -> None:
    validate_public_es256(credential.public_key)
    payload = {
        "schema": 1,
        "rp_id": RP_ID,
        "credential_id": _encode(credential.credential_id),
        "cose_public_key": _encode(cbor.encode(dict(credential.public_key))),
    }
    PUBLIC_RECORD.parent.mkdir(parents=True, exist_ok=True)
    temporary = PUBLIC_RECORD.with_name(f".{PUBLIC_RECORD.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, PUBLIC_RECORD)
        os.chmod(PUBLIC_RECORD, 0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_public_record() -> PublicCredential:
    try:
        metadata = PUBLIC_RECORD.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_size > 4096:
            raise PinVerificationError("public credential file metadata is invalid")
        payload = json.loads(PUBLIC_RECORD.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PinVerificationError("saved resident credential is missing") from exc
    except json.JSONDecodeError as exc:
        raise PinVerificationError("saved resident credential JSON is invalid") from exc
    fields = {"schema", "rp_id", "credential_id", "cose_public_key"}
    if not isinstance(payload, dict) or set(payload) != fields:
        raise PinVerificationError("saved resident credential fields are invalid")
    if payload["schema"] != 1 or payload["rp_id"] != RP_ID:
        raise PinVerificationError("saved resident credential scope is invalid")
    credential_id = _decode(payload["credential_id"], 1024)
    try:
        public_key = CoseKey.parse(cbor.decode(_decode(payload["cose_public_key"], 512)))
    except Exception as exc:
        raise PinVerificationError("saved resident public key is invalid") from exc
    validate_public_es256(public_key)
    return PublicCredential(credential_id, public_key)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Privately verify a PIN-protected resident Pico FIDO credential")
    parser.add_argument(
        "--verify-persisted",
        action="store_true",
        help="after restart, discover and verify the saved resident credential",
    )
    parser.add_argument(
        "--save-public-record",
        action="store_true",
        help="save only the local test credential ID and public key with mode 0600",
    )
    parser.add_argument(
        "--pause",
        action="store_true",
        help="wait for Enter after the sanitized result so a dedicated terminal stays open",
    )
    args = parser.parse_args()
    if args.verify_persisted and args.save_public_record:
        parser.error("--save-public-record cannot be combined with --verify-persisted")
    return args


def run(args: argparse.Namespace) -> int:
    device: CtapHidDevice | None = None
    pin = ""
    try:
        device = select_device()
        ctap = Ctap2(device)
        if args.verify_persisted:
            credential = load_public_record()
        protocol, client_pin, pin, pin_action, retries_before = prompt_for_pin(ctap, args.verify_persisted)
        if args.verify_persisted:
            wait_until_ready()
            token = get_permission_token(client_pin, pin, ClientPin.PERMISSION.GET_ASSERTION)
        else:
            wait_until_ready()
            token = get_permission_token(client_pin, pin, ClientPin.PERMISSION.MAKE_CREDENTIAL)
            try:
                credential = make_resident_credential(ctap, protocol, token)
            finally:
                token = b""
            wait_until_ready()
            token = get_permission_token(client_pin, pin, ClientPin.PERMISSION.GET_ASSERTION)
        try:
            verify_resident_assertion(ctap, protocol, token, credential)
        finally:
            token = b""
        retries_after = client_pin.get_pin_retries()[0]
        if retries_after <= 0 or retries_after < retries_before:
            raise PinVerificationError("PIN retry state changed unexpectedly")
        if args.save_public_record:
            save_public_record(credential)
        print("result=PASS")
        print(f"pin={pin_action}")
        print("pin_retry_check=PASS")
        print("credential_protection=UV_REQUIRED")
        print("resident_credential=PASS")
        print("assertion_signature=PASS")
        return 0
    except CtapError as exc:
        print("result=FAIL")
        print(f"reason=ctap_error_{exc.code.value:02x}_{exc.code.name}")
        return 1
    except PinVerificationError as exc:
        print("result=FAIL")
        print(f"reason={exc}")
        return 1
    except (EOFError, KeyboardInterrupt):
        print("result=FAIL")
        print("reason=private PIN entry cancelled")
        return 1
    except Exception as exc:
        print("result=FAIL")
        print(f"reason=unexpected_{type(exc).__name__}")
        return 1
    finally:
        pin = ""
        if device is not None:
            device.close()


def main() -> int:
    args = parse_args()
    result = run(args)
    if args.pause:
        try:
            input("Press Enter to close this private terminal...")
        except (EOFError, KeyboardInterrupt):
            pass
    return result


if __name__ == "__main__":
    sys.exit(main())
