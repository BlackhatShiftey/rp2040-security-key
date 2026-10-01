#!/usr/bin/env python3
"""Run the final, user-paced Pico FIDO qualification sequence."""

from __future__ import annotations

import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Timer
from typing import TextIO

import verify_key
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
VERIFY_LOG = EVIDENCE_DIR / "final-interactive-verify.txt"
STATUS_FILE = EVIDENCE_DIR / "final-interactive-status.txt"
RECONNECT_TIMEOUT_SECONDS = 30
LATE_TOUCH_SIGNAL_SECONDS = 20
LATE_TOUCH_MINIMUM_SECONDS = 19


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize(value: object, maximum: int = 180) -> str:
    text = re.sub(r"[^A-Za-z0-9 .,:_+=/-]", "_", str(value))
    return text[:maximum] or "unavailable"


def record(stream: TextIO, check: str, result: str, detail: str = "") -> None:
    fields = [f"timestamp_utc={utc_now()}", f"check={sanitize(check)}", f"result={result}"]
    if detail:
        fields.append(f"detail={sanitize(detail)}")
    line = " ".join(fields)
    print(line, flush=True)
    stream.write(line + "\n")
    stream.flush()
    os.fsync(stream.fileno())


def ready(message: str) -> None:
    print("\n" + message, flush=True)
    try:
        input("Press Enter when ready: ")
    except EOFError as exc:
        raise verify_key.VerificationError("interactive input ended unexpectedly") from exc


def validate_fido2(ctap: Ctap2) -> list[str]:
    versions = list(ctap.get_info().versions)
    if not any(version.startswith("FIDO_2") for version in versions):
        raise verify_key.VerificationError("CTAP2 is unavailable")
    return versions


def make_late_touch_credential(ctap: Ctap2):
    def announce_touch_window() -> None:
        print(
            "\n\aGO NOW: press and release BOOT promptly within the remaining 10 seconds. "
            "Do not press RESET.",
            flush=True,
        )

    started = time.monotonic()
    signal = Timer(LATE_TOUCH_SIGNAL_SECONDS, announce_touch_window)
    signal.daemon = True
    signal.start()
    try:
        attestation = verify_key.make_credential(ctap, verify_key.OPERATION_TIMEOUT_SECONDS)
        elapsed = time.monotonic() - started
    finally:
        signal.cancel()

    if elapsed < LATE_TOUCH_MINIMUM_SECONDS:
        raise verify_key.VerificationError("registration completed before the late-touch GO signal")
    return verify_key.validate_credential(attestation), elapsed


def allowlisted_device_count() -> int:
    devices = list(verify_key.CtapHidDevice.list_devices())
    try:
        return sum(
            device.descriptor.vid == verify_key.VID and device.descriptor.pid == verify_key.PID
            for device in devices
        )
    finally:
        for device in devices:
            device.close()


def wait_for_device(expected_present: bool) -> None:
    deadline = time.monotonic() + RECONNECT_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        count = allowlisted_device_count()
        if count > 1:
            raise verify_key.VerificationError("more than one allowlisted Pico FIDO device is connected")
        if (count == 1) == expected_present:
            return
        time.sleep(0.25)
    state = "return" if expected_present else "disconnect"
    raise verify_key.VerificationError(f"timed out waiting for the Pico FIDO device to {state}")


def write_status(result: str, exit_code: int, phase: str, reason: str) -> None:
    temporary = STATUS_FILE.with_name(f".{STATUS_FILE.name}.{os.getpid()}.tmp")
    content = (
        f"result={result}\n"
        f"exit_code={exit_code}\n"
        f"phase={sanitize(phase)}\n"
        f"timestamp_utc={utc_now()}\n"
        f"reason={sanitize(reason)}\n"
    )
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, STATUS_FILE)
        os.chmod(STATUS_FILE, 0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def run_sequence(stream: TextIO, set_phase) -> None:
    device = None
    try:
        set_phase("selecting-device")
        device = verify_key.select_device()
        ctap = Ctap2(device)

        set_phase("no-touch-registration-cancel")
        ready(
            "NO-TOUCH REGISTRATION TEST: do not press BOOT or RESET. "
            "Enter starts a short cancellation window."
        )
        verify_key.run_no_touch_test(ctap)
        record(stream, "no_touch_registration_cancel", "PASS")

        set_phase("fido2-info")
        versions = validate_fido2(ctap)
        record(stream, "fido2_info", "PASS", ",".join(versions))

        set_phase("credential-creation")
        ready(
            "LATE-TOUCH REGISTRATION: after Enter, DO NOT TOUCH BOOT until this terminal beeps and prints GO NOW "
            "at 20 seconds. Then press and release BOOT promptly within the remaining 10 seconds. Do not press RESET."
        )
        credential, late_touch_elapsed = make_late_touch_credential(ctap)
        verify_key.save_public_credential(credential)
        record(
            stream,
            "late_touch_registration",
            "PASS",
            f"elapsed_seconds={late_touch_elapsed:.3f},public_record=saved",
        )
        record(stream, "credential_creation_and_public_record", "PASS")

        set_phase("same-connection-assertion")
        ready(
            "SAME-CONNECTION SIGNATURE: press and release BOOT promptly after Enter; the device window is 30 seconds. "
            "Do not press RESET."
        )
        assertion_hash, assertion = verify_key.request_assertion(
            ctap,
            credential,
            b"interactive-same-connection",
            verify_key.OPERATION_TIMEOUT_SECONDS,
            "touch-for-same-connection-assertion",
        )
        verify_key.verify_assertion(assertion_hash, assertion, credential)
        record(stream, "same_connection_assertion", "PASS")

        set_phase("no-touch-assertion-cancel")
        ready(
            "NO-TOUCH SIGNATURE CANCELLATION: do not press BOOT or RESET. "
            "Enter starts a short cancellation window."
        )
        verify_key.run_no_touch_assertion_test(ctap)
        record(stream, "no_touch_assertion_cancel", "PASS")

        set_phase("natural-assertion-timeout")
        ready(
            "NATURAL SIGNATURE TIMEOUT: do not press BOOT or RESET for the full timeout. "
            "Enter starts the approximately 30-second device timeout."
        )
        verify_key.run_natural_assertion_timeout_test(ctap)
        record(stream, "natural_assertion_timeout", "PASS")
    finally:
        if device is not None:
            device.close()

    set_phase("physical-disconnect")
    ready(
        "PHYSICAL DISCONNECT: unplug the RP2040-Zero, leave it unplugged, then press Enter. "
        "Do not use RESET."
    )
    wait_for_device(False)
    record(stream, "physical_disconnect_observed", "PASS")

    set_phase("physical-reconnect")
    ready(
        "PHYSICAL RECONNECT: plug the RP2040-Zero back in normally, wait for it to enumerate, "
        "then press Enter. Do not hold BOOT and do not press RESET."
    )
    wait_for_device(True)
    record(stream, "physical_reconnect_observed", "PASS")

    reopened_device = None
    try:
        set_phase("persisted-assertion")
        reopened_device = verify_key.select_device()
        reopened_ctap = Ctap2(reopened_device)
        versions = validate_fido2(reopened_ctap)
        record(stream, "reopened_fido2_info", "PASS", ",".join(versions))
        ready(
            "PERSISTED SIGNATURE: press and release BOOT promptly after Enter; the device window is 30 seconds. "
            "Do not press RESET."
        )
        verify_key.run_persisted_test(reopened_ctap)
        record(stream, "persisted_assertion_after_replug", "PASS")
    finally:
        if reopened_device is not None:
            reopened_device.close()


def main() -> int:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    phase = "startup"
    result = "FAIL"
    reason = "incomplete"
    exit_code = 1

    with VERIFY_LOG.open("w", encoding="utf-8") as stream:
        os.chmod(VERIFY_LOG, 0o600)

        def set_phase(value: str) -> None:
            nonlocal phase
            phase = value

        try:
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                raise verify_key.VerificationError("an interactive terminal is required")
            print(
                "This qualification uses only local-test.invalid synthetic credentials. "
                "It does not configure a PIN or contact an account.",
                flush=True,
            )
            run_sequence(stream, set_phase)
            phase = "finalizing"
            record(stream, "final_interactive_qualification", "PASS")
            phase = "complete"
            result = "PASS"
            reason = "all_interactive_checks_passed"
            exit_code = 0
        except CtapError as exc:
            reason = f"ctap_error_{exc.code.value:02x}_{exc.code.name}"
            record(stream, phase, "FAIL", reason)
        except verify_key.VerificationError as exc:
            reason = str(exc)
            record(stream, phase, "FAIL", reason)
        except KeyboardInterrupt:
            phase = "interrupted"
            reason = "user_interrupted"
            record(stream, phase, "FAIL", reason)
        except Exception as exc:
            reason = f"unexpected_{type(exc).__name__}"
            record(stream, phase, "FAIL", reason)
        finally:
            write_status(result, exit_code, phase, reason)

    print(f"\nfinal_status={result} exit_code={exit_code} phase={sanitize(phase)}", flush=True)
    print(f"verification_evidence={VERIFY_LOG}", flush=True)
    print(f"status_receipt={STATUS_FILE}", flush=True)
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            input("Press Enter to close this window.")
        except EOFError:
            pass
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
