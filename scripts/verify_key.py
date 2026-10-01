#!/usr/bin/env python3
"""Verify one allowlisted Pico FIDO authenticator without exposing credentials."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Timer

from fido2 import cbor
from fido2.cose import CoseKey
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice


VID = 0x2E8A
PID = 0x10FE
RP_ID = "local-test.invalid"
OPERATION_TIMEOUT_SECONDS = 45
NO_TOUCH_TIMEOUT_SECONDS = 5
NATURAL_TIMEOUT_SECONDS = 40
NATURAL_TIMEOUT_MINIMUM_SECONDS = 25
LOCAL_CREDENTIAL_PATH = (
    Path(__file__).resolve().parents[1] / "evidence" / "local-test.invalid-credential.json"
)


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class TestCredential:
    credential_id: bytes
    public_key: CoseKey


def select_device() -> CtapHidDevice:
    matches: list[CtapHidDevice] = []
    opened: list[CtapHidDevice] = []
    try:
        for device in CtapHidDevice.list_devices():
            opened.append(device)
            descriptor = device.descriptor
            if descriptor.vid == VID and descriptor.pid == PID:
                matches.append(device)
        if len(matches) != 1:
            raise VerificationError("device selection failed")
        selected = matches[0]
        for device in opened:
            if device is not selected:
                device.close()
        return selected
    except Exception:
        for device in opened:
            device.close()
        raise


def client_data_hash(label: bytes) -> bytes:
    return hashlib.sha256(b"rp2040-zero-security-key:" + label + b":" + os.urandom(32)).digest()


def make_credential(ctap: Ctap2, timeout_seconds: int):
    cancel = Event()
    timer = Timer(timeout_seconds, cancel.set)
    timer.daemon = True
    timer.start()
    try:
        return ctap.make_credential(
            client_data_hash(b"create"),
            {"id": RP_ID, "name": "Local Security Key Verification"},
            {"id": os.urandom(32), "name": "local-verification", "displayName": "Local verification"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": False, "uv": False},
            event=cancel,
        )
    finally:
        timer.cancel()


@contextmanager
def sanitized_ctap_diagnostic(ctap: Ctap2, operation: str):
    original_call = ctap.device.call

    def observed_call(command, data=b"", event=None, on_keepalive=None):
        keepalive_count = 0
        last_keepalive = "none"

        def observed_keepalive(status) -> None:
            nonlocal keepalive_count, last_keepalive
            keepalive_count += 1
            last_keepalive = getattr(status, "name", str(int(status)))
            if on_keepalive is not None:
                on_keepalive(status)

        started = time.monotonic()
        try:
            response = original_call(command, data, event, observed_keepalive)
        except Exception as exc:
            elapsed_ms = round((time.monotonic() - started) * 1000)
            print(
                f"diagnostic={operation},request_len={len(data)},response_len=unavailable,"
                f"status=unavailable,elapsed_ms={elapsed_ms},keepalives={keepalive_count},"
                f"last_keepalive={last_keepalive},transport_error={type(exc).__name__}",
                file=sys.stderr,
                flush=True,
            )
            raise
        elapsed_ms = round((time.monotonic() - started) * 1000)
        status = f"0x{response[0]:02x}" if response else "missing"
        print(
            f"diagnostic={operation},request_len={len(data)},response_len={len(response)},"
            f"status={status},elapsed_ms={elapsed_ms},keepalives={keepalive_count},"
            f"last_keepalive={last_keepalive}",
            file=sys.stderr,
            flush=True,
        )
        return response

    ctap.device.call = observed_call
    try:
        yield
    finally:
        ctap.device.call = original_call


def validate_credential(attestation) -> TestCredential:
    expected_rp_hash = hashlib.sha256(RP_ID.encode()).digest()
    auth_data = attestation.auth_data
    credential_data = auth_data.credential_data
    if auth_data.rp_id_hash != expected_rp_hash or not auth_data.is_user_present():
        raise VerificationError("invalid credential authenticator data")
    if credential_data is None or credential_data.public_key.get(3) != -7:
        raise VerificationError("missing or unexpected credential key")
    return TestCredential(credential_data.credential_id, credential_data.public_key)


def request_assertion(
    ctap: Ctap2,
    credential: TestCredential,
    label: bytes,
    timeout_seconds: int,
    phase: str,
):
    assertion_hash = client_data_hash(label)
    cancel = Event()
    timer = Timer(timeout_seconds, cancel.set)
    timer.daemon = True
    timer.start()
    print(f"phase={phase}", file=sys.stderr, flush=True)
    try:
        assertions = ctap.get_assertions(
            RP_ID,
            assertion_hash,
            allow_list=[{"type": "public-key", "id": credential.credential_id}],
            options={"up": True, "uv": False},
            event=cancel,
        )
    finally:
        timer.cancel()
    if len(assertions) != 1:
        raise VerificationError("unexpected assertion count")
    return assertion_hash, assertions[0]


def verify_assertion(assertion_hash: bytes, assertion, credential: TestCredential) -> None:
    expected_rp_hash = hashlib.sha256(RP_ID.encode()).digest()
    if assertion.auth_data.rp_id_hash != expected_rp_hash or not assertion.auth_data.is_user_present():
        raise VerificationError("invalid assertion authenticator data")
    if assertion.credential.get("id") != credential.credential_id:
        raise VerificationError("assertion credential mismatch")
    assertion.verify(assertion_hash, credential.public_key)


def run_no_touch_test(ctap: Ctap2) -> None:
    print("phase=do-not-touch", file=sys.stderr, flush=True)
    try:
        make_credential(ctap, NO_TOUCH_TIMEOUT_SECONDS)
    except CtapError as exc:
        if exc.code == CtapError.ERR.KEEPALIVE_CANCEL:
            return
        raise
    raise VerificationError("credential creation succeeded without physical touch")


def _validate_natural_timeout(started: float, error: CtapError, operation: str) -> None:
    if time.monotonic() - started < NATURAL_TIMEOUT_MINIMUM_SECONDS:
        raise VerificationError(f"{operation} failed before the natural touch timeout")
    if error.code not in (CtapError.ERR.OPERATION_DENIED, CtapError.ERR.USER_ACTION_TIMEOUT):
        raise error


def run_natural_registration_timeout_test(ctap: Ctap2) -> None:
    print("phase=do-not-touch-for-natural-registration-timeout", file=sys.stderr, flush=True)
    started = time.monotonic()
    with sanitized_ctap_diagnostic(ctap, "natural-registration-timeout"):
        try:
            make_credential(ctap, NATURAL_TIMEOUT_SECONDS)
        except CtapError as exc:
            _validate_natural_timeout(started, exc, "registration")
            return
        except TypeError as exc:
            raise VerificationError("malformed registration timeout response (TypeError)") from exc
    raise VerificationError("registration succeeded without physical touch")


def run_natural_assertion_timeout_test(ctap: Ctap2) -> None:
    credential = load_or_create_test_credential(ctap)
    assertion_hash = client_data_hash(b"natural-timeout-assert")
    cancel = Event()
    timer = Timer(NATURAL_TIMEOUT_SECONDS, cancel.set)
    timer.daemon = True
    timer.start()
    print("phase=do-not-touch-for-natural-assertion-timeout", file=sys.stderr, flush=True)
    started = time.monotonic()
    try:
        with sanitized_ctap_diagnostic(ctap, "natural-assertion-timeout"):
            try:
                ctap.get_assertions(
                    RP_ID,
                    assertion_hash,
                    allow_list=[{"type": "public-key", "id": credential.credential_id}],
                    options={"up": True, "uv": False},
                    event=cancel,
                )
            except CtapError as exc:
                _validate_natural_timeout(started, exc, "assertion")
                return
            except TypeError as exc:
                raise VerificationError("malformed assertion timeout response (TypeError)") from exc
    finally:
        timer.cancel()
    raise VerificationError("assertion succeeded without physical touch")


def run_no_touch_assertion_test(ctap: Ctap2) -> None:
    credential = load_or_create_test_credential(ctap)

    assertion_hash = client_data_hash(b"no-touch-assert")
    cancel = Event()
    timer = Timer(NO_TOUCH_TIMEOUT_SECONDS, cancel.set)
    timer.daemon = True
    timer.start()
    print("phase=do-not-touch-for-assertion", file=sys.stderr, flush=True)
    try:
        ctap.get_assertions(
            RP_ID,
            assertion_hash,
            allow_list=[{"type": "public-key", "id": credential.credential_id}],
            options={"up": True, "uv": False},
            event=cancel,
        )
    except CtapError as exc:
        if exc.code != CtapError.ERR.KEEPALIVE_CANCEL:
            raise
        return
    else:
        raise VerificationError("assertion succeeded without physical touch")
    finally:
        timer.cancel()

def run_credential_test(ctap: Ctap2) -> TestCredential:
    print("phase=touch-for-credential", file=sys.stderr, flush=True)
    credential = validate_credential(make_credential(ctap, OPERATION_TIMEOUT_SECONDS))
    assertion_hash, assertion = request_assertion(
        ctap,
        credential,
        b"assert",
        OPERATION_TIMEOUT_SECONDS,
        "touch-for-assertion",
    )
    verify_assertion(assertion_hash, assertion, credential)
    return credential


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64_decode(value: object, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise VerificationError("invalid persisted credential field")
    padded = value + "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise VerificationError("invalid persisted credential encoding") from exc
    if not decoded or len(decoded) > maximum:
        raise VerificationError("invalid persisted credential length")
    return decoded


def encode_public_credential(credential: TestCredential) -> dict[str, object]:
    return {
        "schema": 1,
        "rp_id": RP_ID,
        "credential_id": _b64_encode(credential.credential_id),
        "cose_public_key": _b64_encode(cbor.encode(dict(credential.public_key))),
    }


def decode_public_credential(payload: object) -> TestCredential:
    expected_fields = {"schema", "rp_id", "credential_id", "cose_public_key"}
    if (
        not isinstance(payload, dict)
        or set(payload) != expected_fields
        or payload.get("schema") != 1
        or payload.get("rp_id") != RP_ID
    ):
        raise VerificationError("invalid persisted credential metadata")
    credential_id = _b64_decode(payload.get("credential_id"), 1024)
    cose_data = _b64_decode(payload.get("cose_public_key"), 512)
    try:
        public_key = CoseKey.parse(cbor.decode(cose_data))
    except Exception as exc:
        raise VerificationError("invalid persisted public key") from exc
    if public_key.get(3) != -7:
        raise VerificationError("unexpected persisted public key algorithm")
    return TestCredential(credential_id, public_key)


def save_public_credential(credential: TestCredential) -> None:
    LOCAL_CREDENTIAL_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = LOCAL_CREDENTIAL_PATH.with_name(f".{LOCAL_CREDENTIAL_PATH.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(encode_public_credential(credential), stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, LOCAL_CREDENTIAL_PATH)
        os.chmod(LOCAL_CREDENTIAL_PATH, 0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_public_credential() -> TestCredential:
    try:
        stat = LOCAL_CREDENTIAL_PATH.stat()
        if stat.st_mode & 0o077:
            raise VerificationError("persisted credential permissions are too broad")
        if stat.st_size > 4096:
            raise VerificationError("persisted credential file is too large")
        with LOCAL_CREDENTIAL_PATH.open("r", encoding="utf-8") as stream:
            return decode_public_credential(json.load(stream))
    except FileNotFoundError as exc:
        raise VerificationError("persisted credential is missing") from exc
    except json.JSONDecodeError as exc:
        raise VerificationError("persisted credential JSON is invalid") from exc


def load_or_create_test_credential(ctap: Ctap2) -> TestCredential:
    if LOCAL_CREDENTIAL_PATH.exists():
        print("phase=using-persisted-local-test-credential", file=sys.stderr, flush=True)
        return load_public_credential()
    print("phase=touch-for-credential", file=sys.stderr, flush=True)
    return validate_credential(make_credential(ctap, OPERATION_TIMEOUT_SECONDS))


def run_persisted_test(ctap: Ctap2) -> None:
    credential = load_public_credential()
    assertion_hash, assertion = request_assertion(
        ctap,
        credential,
        b"persisted-assert",
        OPERATION_TIMEOUT_SECONDS,
        "touch-for-persisted-assertion",
    )
    verify_assertion(assertion_hash, assertion, credential)


def render_options(options: dict[str, bool]) -> str:
    if not options:
        return "none"
    return ",".join(f"{name}={str(value).lower()}" for name, value in sorted(options.items()))


def print_result(passed: bool, versions: list[str] | None, options: dict[str, bool] | None) -> None:
    print(f"result={'PASS' if passed else 'FAIL'}")
    print(f"versions={','.join(versions) if versions else 'unavailable'}")
    print(f"options={render_options(options) if options is not None else 'unavailable'}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify a Pico FIDO security key")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--info", action="store_true", help="read authenticator versions and options (default)")
    modes.add_argument("--no-touch-test", action="store_true", help="confirm creation times out when the key is not touched")
    modes.add_argument(
        "--natural-registration-timeout",
        action="store_true",
        help="confirm registration returns a valid natural touch-timeout error",
    )
    modes.add_argument(
        "--natural-assertion-timeout",
        action="store_true",
        help="touch-create, then confirm assertion returns a valid natural timeout",
    )
    modes.add_argument(
        "--no-touch-assertion-test",
        action="store_true",
        help="confirm assertion cancellation using the saved local test credential",
    )
    modes.add_argument("--test", action="store_true", help="create a nonresident test credential and verify an assertion")
    modes.add_argument(
        "--verify-persisted",
        action="store_true",
        help="verify the saved local-test.invalid credential after a restart",
    )
    parser.add_argument(
        "--save-local-credential",
        action="store_true",
        help="with --test, save only the test credential ID and public key",
    )
    args = parser.parse_args()
    if args.save_local_credential and not args.test:
        parser.error("--save-local-credential requires --test")
    return args


def main() -> int:
    args = parse_args()
    versions: list[str] | None = None
    options: dict[str, bool] | None = None
    device: CtapHidDevice | None = None
    try:
        device = select_device()
        ctap = Ctap2(device)
        info = ctap.get_info()
        versions = info.versions
        options = info.options
        if not any(version.startswith("FIDO_2") for version in versions):
            raise VerificationError("CTAP2 is unavailable")
        if args.no_touch_test:
            run_no_touch_test(ctap)
        elif args.natural_registration_timeout:
            run_natural_registration_timeout_test(ctap)
        elif args.natural_assertion_timeout:
            run_natural_assertion_timeout_test(ctap)
        elif args.no_touch_assertion_test:
            run_no_touch_assertion_test(ctap)
        elif args.test:
            credential = run_credential_test(ctap)
            if args.save_local_credential:
                save_public_credential(credential)
        elif args.verify_persisted:
            run_persisted_test(ctap)
        print_result(True, versions, options)
        return 0
    except CtapError as exc:
        print_result(False, versions, options)
        print(f"reason=ctap_error_{exc.code.value:02x}_{exc.code.name}")
        return 1
    except VerificationError as exc:
        print_result(False, versions, options)
        print(f"reason={exc}")
        return 1
    except Exception as exc:
        print_result(False, versions, options)
        frames = traceback.extract_tb(exc.__traceback__)
        location = frames[-1] if frames else None
        where = f"_line_{location.lineno}_{location.name}" if location else ""
        print(f"reason=unexpected_{type(exc).__name__}{where}")
        return 1
    finally:
        if device is not None:
            device.close()


if __name__ == "__main__":
    sys.exit(main())
