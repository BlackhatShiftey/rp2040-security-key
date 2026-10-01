# Qualification boundary

The RP2040-Zero source changes passed the project's defined offline and hardware
acceptance suite on 2026-09-28. This document is a sanitized summary. Raw device
logs, operator records, synthetic credential records, and machine-specific evidence
are intentionally excluded from the public repository.

## Tested private image

The hardware run used a private local build with SHA-256:

```text
25394aaf6c1b49c06bc45957d665926b2b4fe6de1a625d1070709e4ce4437549
```

It was built for a Waveshare-compatible RP2040-Zero from the pinned sources and
the first five patches documented in [../BUILD.md](../BUILD.md). The image is not
published because it contains machine-specific absolute build paths. That source and
patch set remains public; the current preview additionally applies patch `0006` to
report the USB transport.

## Results

| Acceptance check | Result |
| --- | --- |
| Frozen artifact digest, flash, and independent program readback | PASS |
| CTAP GetInfo and FIDO2 operation | PASS |
| Physical-presence configuration and reconnect persistence | PASS |
| Registration denied without touch, by cancellation and natural timeout | PASS |
| Deliberately late BOOT confirmation inside the configured window | PASS |
| Credential creation and ES256 signature verification | PASS |
| Signing denied without touch, by cancellation and natural timeout | PASS |
| Same-connection recovery after a cancelled request | PASS |
| Nonresident credential signature after physical unplug/replug | PASS |
| Credential rejected for an unrelated relying party | PASS |
| Private PIN setup and retry-state validation | PASS |
| UV-required, `credProtect=3` resident credential creation and signing | PASS |
| Original resident credential discovery/signature after unplug/replug | PASS |
| Protected request without PIN authorization rejected; retry count unchanged | PASS |
| Offline regression suite | PASS, 12/12 tests |

The historical offline suite covers the actual patched button-wait control flow, no-PIN
presence placement, cancellation behavior, public-record encoding, PIN validation,
permission scoping, signature rejection, readiness gates, and resident-credential
properties. The current public suite also checks the GetInfo USB transport source change;
that additional patch was not present in the hardware-tested private image.

## Public build status

`scripts/build_firmware.sh` creates
`dist/pico_fido_zero-8.0-public-preview.uf2` from a clean source checkout. That artifact
is source-qualified by the offline tests only. It was not the binary used in the private
hardware run and has not been independently flashed, read back, or exercised on a board.
Build paths and toolchain details can change UF2 bytes, so the private result must not be
transferred to a new digest by assumption. Source and build qualification of the USB
transport response does not prove that a browser or service will classify or accept the
authenticator as a hardware security key.

## What this does not prove

- This is not formal FIDO certification or exhaustive conformance testing.
- It does not establish resistance to physical key extraction. RP2040 has no secure element.
- It does not qualify boards other than the targeted RP2040-Zero profile.
- It does not prove every feature advertised by the upstream authenticator.
- It does not guarantee browser, operating-system, or service compatibility.
- OpenAI enrollment, acceptance, actual sign-in, and recovery were not tested.
- No test can guarantee that an experimental key will never fail or prevent account lockout.

Use an independently registered backup key, keep recovery codes private, and preserve
an existing signed-in session while testing a new account enrollment. Never reset or
reflash an enrolled key without a tested alternate sign-in method.
