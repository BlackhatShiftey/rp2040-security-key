# Canticle RP2040 Security Key

An experimental, source-first security-key build for the Waveshare-compatible
RP2040-Zero. This repository packages a narrowly scoped set of fixes, reproducible
source pins, and host-side verification around
[Pico FIDO](https://github.com/polhenarejos/pico-fido).

This is a modified Pico FIDO derivative. Pico FIDO and Pico Keys SDK are the work
of Pol Henarejos and their contributors; Canticle Research did not create that
firmware from scratch. See [NOTICE](NOTICE) for provenance and [LICENSE](LICENSE)
for the AGPL-3.0 terms.

## Current scope

- **Supported target:** Waveshare-compatible RP2040-Zero with 2 MiB flash.
- **Firmware base:** Pico FIDO v8.0 at pinned source revisions.
- **Delivered here:** five source patches, deterministic source bootstrap, a
  portable build helper, offline regression tests, and host-side qualification tools.
- **Future work:** a broader multi-board Canticle Key SDK is planned, but it is not
  implemented in this release. See [docs/SDK_ROADMAP.md](docs/SDK_ROADMAP.md).

No firmware binary is committed. Locally generated `firmware/`, `build/`, and
`dist/` trees are ignored. A clean public build produces a separate preview UF2;
it is source-qualified by the test suite but has not inherited the private board's
flash-readback or hardware qualification.

## Security boundary

RP2040 has no secure element and does not provide strong resistance to physical
flash extraction. Treat this as an experimental authenticator, not as a replacement
for a commercial secure-element-backed key.

Before using any experimental key with an account:

1. Register an independent backup security key.
2. Save recovery codes privately and verify the recovery path.
3. Preserve an existing signed-in session while testing enrollment and sign-in.
4. Keep the key's PIN out of chat, shell arguments, logs, and repository files.

Never flash, reset, or reprovision a key that already holds real credentials unless
you have a tested alternate sign-in method. Firmware replacement can erase or
invalidate credentials. Provision only a new or intentionally disposable board.

Local qualification does not constitute FIDO certification and cannot guarantee
service acceptance or prevent account lockout. OpenAI enrollment and sign-in were
not tested by this project.

## Build from a fresh clone

Requirements and platform notes are in [BUILD.md](BUILD.md). From the repository root:

```bash
uv sync --locked
python3 scripts/bootstrap_sources.py
PICO_FIDO_SOURCE="$PWD/build/public-sources/pico-fido" \
  uv run python -m unittest discover -s tests -v
bash scripts/build_firmware.sh
```

The bootstrap helper clones and validates the seven repositories pinned in
`sources.lock.json`, then applies `patches/0001` through `0005`. The build helper
uses fixed RP2040-Zero settings and writes:

```text
dist/pico_fido_zero-8.0-public-preview.uf2
dist/pico_fido_zero-8.0-public-preview.uf2.sha256
```

Verify the digest before moving an artifact between machines. Build paths can affect
firmware bytes, so a public preview is expected to differ from the privately tested
image. Do not describe a fresh build as hardware-qualified until that exact artifact
has been flashed, read back, and tested on its intended board.

## Provisioning a new test board

The public preview is intended for development on a new RP2040-Zero. Review the source,
offline test results, build log, and UF2 digest first. Then use the board's BOOTSEL
mode to provision that exact artifact and independently verify the written flash.
After reboot, run the complete local qualification sequence before registering any
account.

BOOT confirms a request after provisioning. RESET restarts the board and is not a
user-presence button. Do not use RESET while an operation is asking for a touch.

## Verification tools

The tools select exactly one allowlisted Pico FIDO USB device and use only the
synthetic relying party `local-test.invalid`:

- `scripts/configure_key.py` reads or applies the RP2040-Zero LED and presence timeout.
- `scripts/verify_key.py` runs focused no-PIN CTAP and signature checks.
- `scripts/qualify_interactive.py` guides the pre-PIN no-touch, late-touch,
  same-connection, unplug/replug, and persistence sequence.
- `scripts/verify_pin.py` tests PIN-authorized, UV-required resident credentials with
  hidden terminal input.
- `scripts/qualify_pin_interactive.py` guides PIN/resident verification across a real
  unplug/replug.

Run the no-PIN credential-creation suite before configuring a PIN. Once a PIN exists,
those requests may correctly return `PIN_REQUIRED`; do not erase the PIN to rerun them.
Use the PIN-aware helpers for later checks.

The verification scripts store only synthetic credential identifiers and public keys
when persistence testing requires them. Those local records are ignored by Git. They
must never contain a PIN, private credential key, account identifier, or recovery code.

## Qualification evidence

The qualification suite contained 12 offline regression tests. The current public
checkout adds three source-bootstrap tests and passes 15/15 offline tests. A private
build from the same pinned source and patch set also passed the defined RP2040-Zero hardware suite,
including late touch, no-touch denial, signature verification, RP separation,
physical reconnect persistence, PIN/UV-required resident credentials, and flash
readback. The sanitized evidence boundary is in
[docs/QUALIFICATION.md](docs/QUALIFICATION.md).

That result applies to the exact private image tested. It does not qualify a newly
built public preview binary by association.

## Repository layout

```text
patches/                 Firmware and SDK patches applied in order
scripts/                 Bootstrap, build, configuration, and verification tools
tests/                   Offline regression tests
docs/QUALIFICATION.md    Sanitized test coverage and limits
docs/SDK_ROADMAP.md      Planned multi-board SDK direction
sources.lock.json        Pinned upstream source revisions
NOTICE                   Attribution and third-party provenance
```

## License

This repository is licensed under GNU AGPL version 3. Upstream and third-party files
retain their own copyright and license notices. If you distribute firmware, provide
the corresponding source and preserve all applicable notices and licenses.
