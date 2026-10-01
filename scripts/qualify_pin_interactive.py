#!/usr/bin/env python3
"""User-paced PIN and physical-replug qualification for the local test key."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Callable, TextIO

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import qualify_interactive
import verify_pin


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
VERIFY_LOG = EVIDENCE_DIR / "final-pin-interactive-verify.txt"
STATUS_FILE = EVIDENCE_DIR / "final-pin-interactive-status.txt"


class QualificationError(RuntimeError):
    pass


def record(stream: TextIO, check: str, result: str, detail: str = "") -> None:
    qualify_interactive.record(stream, check, result, detail)


def write_status(result: str, exit_code: int, phase: str, reason: str) -> None:
    temporary = STATUS_FILE.with_name(f".{STATUS_FILE.name}.{os.getpid()}.tmp")
    content = (
        f"result={result}\n"
        f"exit_code={exit_code}\n"
        f"phase={qualify_interactive.sanitize(phase)}\n"
        f"timestamp_utc={qualify_interactive.utc_now()}\n"
        f"reason={qualify_interactive.sanitize(reason)}\n"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
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


def run_sequence(
    stream: TextIO,
    set_phase: Callable[[str], None],
    run_pin: Callable[[argparse.Namespace], int] = verify_pin.run,
    ready: Callable[[str], None] = qualify_interactive.ready,
    wait_for_device: Callable[[bool], None] = qualify_interactive.wait_for_device,
) -> None:
    set_phase("initial-pin-resident-verification")
    initial_args = argparse.Namespace(
        verify_persisted=False,
        save_public_record=True,
        pause=False,
    )
    if run_pin(initial_args) != 0:
        raise QualificationError("initial private PIN and resident verification failed")
    record(stream, "initial_pin_resident_verification", "PASS")

    set_phase("physical-power-cycle")
    ready(
        "PHYSICAL UNPLUG: unplug the RP2040-Zero completely, leave it disconnected, "
        "then press Enter. Do not press BOOT or RESET."
    )
    wait_for_device(False)
    ready(
        "PHYSICAL RECONNECT: plug the RP2040-Zero back in normally, wait for it to enumerate, "
        "then press Enter. Do not hold BOOT or press RESET."
    )
    wait_for_device(True)
    record(stream, "physical_unplug_replug_observed", "PASS")

    set_phase("persisted-pin-resident-verification")
    print(
        "Enter the same security-key PIN again in the hidden prompt. "
        "This is not your Linux password.",
        flush=True,
    )
    persisted_args = argparse.Namespace(
        verify_persisted=True,
        save_public_record=False,
        pause=False,
    )
    if run_pin(persisted_args) != 0:
        raise QualificationError("persisted private PIN and resident verification failed")
    record(stream, "persisted_pin_resident_verification", "PASS")


def failure_check_for_phase(phase: str) -> str:
    if phase == "complete":
        return "final_pin_interactive_qualification"
    if phase == "physical-power-cycle":
        return "physical_unplug_replug_observed"
    if phase == "persisted-pin-resident-verification":
        return "persisted_pin_resident_verification"
    return "initial_pin_resident_verification"


def main() -> int:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    phase = "startup"
    result = "FAIL"
    reason = "incomplete"
    exit_code = 1

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(VERIFY_LOG, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        os.chmod(VERIFY_LOG, 0o600)

        def set_phase(value: str) -> None:
            nonlocal phase
            phase = value

        try:
            if not sys.stdin.isatty() or not sys.stdout.isatty() or not sys.stderr.isatty():
                raise QualificationError("a private interactive terminal is required")
            print(
                "This sets or verifies your final RP2040 security-key PIN. "
                "It is not your Linux password. Choose it only in the hidden prompt, "
                "remember it privately, and never put it in chat or command arguments.",
                flush=True,
            )
            print(
                "The test uses only a synthetic local-test.invalid resident credential. "
                "It does not contact or enroll any account.",
                flush=True,
            )
            run_sequence(stream, set_phase)
            phase = "complete"
            record(stream, "final_pin_interactive_qualification", "PASS")
            result = "PASS"
            reason = "pin_resident_and_physical_persistence_checks_passed"
            exit_code = 0
        except QualificationError as exc:
            reason = str(exc)
            record(stream, failure_check_for_phase(phase), "FAIL", reason)
        except KeyboardInterrupt:
            reason = "user_interrupted"
            record(stream, failure_check_for_phase(phase), "FAIL", reason)
        except Exception as exc:
            reason = f"unexpected_{type(exc).__name__}"
            record(stream, failure_check_for_phase(phase), "FAIL", reason)
        finally:
            write_status(result, exit_code, phase, reason)

    print(
        f"\nfinal_status={result} exit_code={exit_code} "
        f"phase={qualify_interactive.sanitize(phase)}",
        flush=True,
    )
    print(f"verification_evidence={VERIFY_LOG}", flush=True)
    print(f"status_receipt={STATUS_FILE}", flush=True)
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            input("Press Enter to close this private terminal.")
        except (EOFError, KeyboardInterrupt):
            pass
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
