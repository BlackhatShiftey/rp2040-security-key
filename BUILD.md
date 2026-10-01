# Portable RP2040-Zero firmware build

This build creates a clean public preview for the Waveshare-compatible RP2040-Zero.
It fetches pinned upstream source, validates every checkout and patch digest, builds a
pinned `picotool` package, and removes local source/build prefixes from the firmware.

The output is a source-qualified preview. It is not the privately tested binary and
does not inherit that image's hardware qualification. See
[docs/QUALIFICATION.md](docs/QUALIFICATION.md).

## Requirements

The reference environment is Ubuntu 24.04. Other Linux distributions may work when
they provide equivalent tools:

- Python 3.11 or newer;
- `uv` (CI pins 0.12.18);
- Git and GitHub CLI (`gh`) with access to public GitHub repositories;
- CMake and a build backend supported by CMake;
- Arm GNU embedded C/C++ toolchain with `arm-none-eabi-gcc` and
  `arm-none-eabi-g++`;
- standard utilities: Bash, `sha256sum`, `readlink`, and `install`.

The helper uses `.toolchain/root/usr` when that local toolchain exists. Otherwise it
detects `arm-none-eabi-gcc` on `PATH`. Pass `--toolchain-root` to select a different
prefix containing `bin/arm-none-eabi-gcc` and `bin/arm-none-eabi-g++`.

## Pinned sources

`sources.lock.json` is authoritative. It pins seven repositories and records the
before/after digest of every patched file.

| Source | Revision |
| --- | --- |
| `polhenarejos/pico-fido` | `6ffcb81191c7f4e44337e0eaecc788ba6db03b75` (`v8.0`) |
| `polhenarejos/pico-keys-sdk` | `7c5f4d9b95d5c17531a45c74c673822242d4d376` |
| `raspberrypi/pico-sdk` | `bddd20f928ce76142793bef434d4f75f4af6e433` (`2.1.1`) |
| `hathach/tinyusb` | `86ad6e56c1700e85f1c5678607a762cfe3aa2f47` |
| `Mbed-TLS/mbedtls` | `068ff080b369adfac81509f9b57b2afabaf82dc5` (`v3.6.7`) |
| `intel/tinycbor` | `c0aad2fb2137a31b9845fbaae3653540c410f215` (`v0.6.1`) |
| `raspberrypi/picotool` | `ba3df406c37774144a059b2bdae73ab52587a1d2` |

The bootstrap applies these patches in order:

1. `0001-require-touch-without-pin.patch`
2. `0002-complete-cancellation-after-cleanup.patch`
3. `0003-sdk-preserve-cancelled-transaction.patch`
4. `0004-sdk-complete-button-cancel-lifecycle.patch`
5. `0005-sdk-measure-release-timeout-from-press.patch`

They add the missing no-PIN presence gate, correct cancellation cleanup across the
FIDO and USB layers, and measure the button-release timeout from the detected press.
The last change preserves a full release interval for a valid press late in the
configured presence window.

## Fresh build

From the repository root:

```bash
uv sync --locked
python3 scripts/bootstrap_sources.py
PICO_FIDO_SOURCE="$PWD/build/public-sources/pico-fido" \
  uv run python -m unittest discover -s tests -v
bash scripts/build_firmware.sh
```

`bootstrap_sources.py` defaults to `build/public-sources` and `sources.lock.json`.
It is idempotent for checkouts whose origin, commit, working-tree changes, dependency
markers, and patched-file digests match the lock. It fails closed on unexpected state.

Custom locations are supported:

```bash
python3 scripts/bootstrap_sources.py \
  --source-dir /work/canticle-key-sources \
  --lock "$PWD/sources.lock.json"

bash scripts/build_firmware.sh \
  --source-dir /work/canticle-key-sources \
  --build-dir /work/canticle-key-build \
  --dist-dir "$PWD/dist" \
  --toolchain-root /opt/arm-gnu \
  --jobs 6
```

Do not point the helpers at a source tree containing unrelated edits. The bootstrap
accepts only the changes and dependency markers declared in the lock.

### Prepared source archives

The bootstrap also writes `source-manifest.json` inside the source directory. A release
publisher can archive that complete prepared tree. After expanding such an archive, a
consumer can build without Git metadata or GitHub CLI access:

```bash
bash scripts/build_firmware.sh \
  --source-dir /work/prepared-canticle-key-sources \
  --prepared-sources
```

This mode verifies the lock digest, the entire expanded tree, safe internal symlinks,
dependency markers, and all five post-patch file digests against the manifest. The
manifest detects changes relative to the publisher's prepared tree; it does not
authenticate the publisher. The release archive's separately published SHA-256 or
signature is the authenticity boundary.

## Fixed firmware configuration

The public build helper fixes these security-relevant options:

| Option | Value |
| --- | --- |
| Board | `waveshare_rp2040_zero` |
| Build type | `Release` |
| `FORCE_BUTTON_WAIT` | `ON` |
| `ENABLE_OTP_APP` | `OFF` |
| `ENABLE_OATH_APP` | `ON` |
| Dependency fetching during CMake | `OFF` |

OATH remains enabled because the upstream build uses it to retain the CCID management
interface. This project does not configure an OATH account or OTP secret.

The helper builds `picotool` from its pinned source with `PICOTOOL_NO_LIBUSB=ON` for
CMake packaging, then passes that exact package to the firmware build. Compiler prefix
maps normalize source, toolchain, build, and project roots. The helper also scans the
UF2 and fails if a selected local path remains embedded.

## Outputs

A successful build writes:

```text
dist/pico_fido_zero-8.0-public-preview.uf2
dist/pico_fido_zero-8.0-public-preview.uf2.sha256
```

The `dist/` directory is ignored. Record the digest with any test evidence for that
exact artifact. Compiler and build-tool versions remain part of the practical build
environment; do not claim byte-for-byte reproducibility across different toolchains
without comparing the outputs.

## Offline verification

The public checkout currently runs 15 offline tests: the 12 firmware, presence,
cancellation, signature, PIN, and persistence regressions used for local qualification,
plus three fail-closed bootstrap/build-helper tests. CI bootstraps the pinned sources
and runs this suite on Ubuntu 24.04 without accessing USB devices.

## Provisioning boundary

Provision only a new or intentionally disposable RP2040-Zero. Never use a firmware
build or BOOTSEL operation as a routine check on a key that contains real credentials.
Rewriting firmware may erase or invalidate those credentials, and these helpers make
no preservation guarantee.

Before provisioning:

1. inspect the source lock, patches, test output, and artifact digest;
2. confirm the board model and that it is not an enrolled key;
3. keep a separate registered security key and private recovery codes;
4. preserve an existing account session.

After provisioning, independently read back the written program and run the complete
hardware qualification against the exact artifact digest before account enrollment.
The repository does not auto-flash, auto-enroll accounts, or publish build artifacts.

## License and notices

This derivative is released under GNU AGPL version 3. Preserve [LICENSE](LICENSE),
[NOTICE](NOTICE), upstream source headers, and every dependency's own license files.
Distribution of an object-code firmware image requires the corresponding source and
applicable installation information under the license terms. Third-party components
remain governed by their respective licenses.
