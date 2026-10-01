#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source_dir="$project_root/build/public-sources"
build_dir="$project_root/build/public"
dist_dir="$project_root/dist"
toolchain_root=""
jobs="${BUILD_JOBS:-6}"
prepared_sources=0

usage() {
  printf '%s\n' \
    "Usage: scripts/build_firmware.sh [options]" \
    "  --source-dir PATH     Bootstrapped source root (default: build/public-sources)" \
    "  --build-dir PATH      Build root (default: build/public)" \
    "  --dist-dir PATH       Artifact directory (default: dist)" \
    "  --toolchain-root PATH ARM toolchain prefix containing bin/" \
    "  --jobs N              Parallel build jobs (default: 6 or BUILD_JOBS)" \
    "  --prepared-sources    Verify source-manifest.json instead of using Git/gh"
}

while (($#)); do
  case "$1" in
    --source-dir|--build-dir|--dist-dir|--toolchain-root|--jobs)
      if (($# < 2)); then
        printf 'build=FAIL reason=missing_value_for_%s\n' "$1" >&2
        exit 2
      fi
      case "$1" in
        --source-dir) source_dir="$2" ;;
        --build-dir) build_dir="$2" ;;
        --dist-dir) dist_dir="$2" ;;
        --toolchain-root) toolchain_root="$2" ;;
        --jobs) jobs="$2" ;;
      esac
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --prepared-sources)
      prepared_sources=1
      shift
      ;;
    *)
      printf 'build=FAIL reason=unknown_argument_%s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "$jobs" =~ ^[1-9][0-9]*$ ]]; then
  printf 'build=FAIL reason=jobs_must_be_a_positive_integer\n' >&2
  exit 2
fi

required_commands=(python3 cmake sha256sum install)
if ((prepared_sources == 0)); then
  required_commands+=(git gh)
fi
for command_name in "${required_commands[@]}"; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'build=FAIL reason=missing_command_%s\n' "$command_name" >&2
    exit 1
  fi
done

source_dir="$(readlink -m "$source_dir")"
build_dir="$(readlink -m "$build_dir")"
dist_dir="$(readlink -m "$dist_dir")"

if [[ "$build_dir" == "$source_dir"/* || "$source_dir" == "$build_dir"/* || \
      "$dist_dir" == "$source_dir"/* || "$source_dir" == "$dist_dir"/* ]]; then
  printf 'build=FAIL reason=source_build_and_dist_paths_must_be_disjoint\n' >&2
  exit 1
fi

if [[ -z "$toolchain_root" ]]; then
  if [[ -x "$project_root/.toolchain/root/usr/bin/arm-none-eabi-gcc" ]]; then
    toolchain_root="$project_root/.toolchain/root/usr"
  elif compiler_path="$(command -v arm-none-eabi-gcc 2>/dev/null)"; then
    compiler_path="$(readlink -f "$compiler_path")"
    toolchain_root="$(dirname "$(dirname "$compiler_path")")"
  else
    printf 'build=FAIL reason=arm_none_eabi_toolchain_not_found\n' >&2
    exit 1
  fi
fi
toolchain_root="$(readlink -m "$toolchain_root")"
if [[ ! -x "$toolchain_root/bin/arm-none-eabi-gcc" || ! -x "$toolchain_root/bin/arm-none-eabi-g++" ]]; then
  printf 'build=FAIL reason=invalid_toolchain_root\n' >&2
  exit 1
fi

if ((prepared_sources)); then
  python3 "$project_root/scripts/bootstrap_sources.py" \
    --source-dir "$source_dir" \
    --verify-manifest-only
else
  python3 "$project_root/scripts/bootstrap_sources.py" --source-dir "$source_dir"
fi

pico_fido="$source_dir/pico-fido"
pico_sdk="$source_dir/pico-sdk"
picotool_source="$source_dir/picotool"
for required_path in "$pico_fido/CMakeLists.txt" "$pico_sdk/pico_sdk_init.cmake" "$picotool_source/CMakeLists.txt"; do
  if [[ ! -f "$required_path" ]]; then
    printf 'build=FAIL reason=missing_bootstrapped_source\n' >&2
    exit 1
  fi
done

mkdir -p "$build_dir" "$dist_dir"
picotool_build="$build_dir/picotool-build"
picotool_install="$build_dir/picotool-install"
firmware_build="$build_dir/pico-fido"

export PATH="$toolchain_root/bin:$PATH"

cmake \
  -S "$picotool_source" \
  -B "$picotool_build" \
  -DPICO_SDK_PATH:PATH="$pico_sdk" \
  -DPICO_TOOLCHAIN_PATH:PATH="$toolchain_root" \
  -DPICOTOOL_NO_LIBUSB:BOOL=ON \
  -DPICOTOOL_FLAT_INSTALL:BOOL=ON \
  -DCMAKE_BUILD_TYPE:STRING=Release \
  -DCMAKE_INSTALL_PREFIX:PATH="$picotool_install"
cmake --build "$picotool_build" --target install --parallel "$jobs"

picotool_package="$picotool_install/picotool"
if [[ ! -x "$picotool_package/picotool" || ! -f "$picotool_package/picotoolConfig.cmake" ]]; then
  printf 'build=FAIL reason=pinned_picotool_install_incomplete\n' >&2
  exit 1
fi
"$picotool_package/picotool" version >/dev/null

compiler_launcher="$build_dir/prefix-map-launcher.py"
asm_compiler="$build_dir/prefix-map-asm-compiler.py"
python3 - "$compiler_launcher" "$asm_compiler" \
  "$toolchain_root/bin/arm-none-eabi-gcc" \
  "$source_dir" "$toolchain_root" "$build_dir" "$project_root" <<'PY'
from pathlib import Path
import os
import sys

launcher = Path(sys.argv[1])
asm_compiler = Path(sys.argv[2])
real_asm_compiler = sys.argv[3]
mappings = [
    (sys.argv[4], "/src"),
    (sys.argv[5], "/toolchain"),
    (sys.argv[6], "/build"),
    (sys.argv[7], "/project"),
]
flags = []
for source, replacement in mappings:
    flags.extend(
        [
            f"-ffile-prefix-map={source}={replacement}",
            f"-fmacro-prefix-map={source}={replacement}",
        ]
    )
content = """#!/usr/bin/env python3
import os
import sys

FLAGS = %r
compiler = sys.argv[1]
os.execv(compiler, [compiler, *FLAGS, *sys.argv[2:]])
""" % flags
launcher.write_text(content, encoding="utf-8")
os.chmod(launcher, 0o755)
asm_content = """#!/usr/bin/env python3
import os
import sys

COMPILER = %r
FLAGS = %r
os.execv(COMPILER, [COMPILER, *FLAGS, *sys.argv[1:]])
""" % (real_asm_compiler, flags)
asm_compiler.write_text(asm_content, encoding="utf-8")
os.chmod(asm_compiler, 0o755)
PY

cmake \
  -S "$pico_fido" \
  -B "$firmware_build" \
  -DPICO_SDK_PATH:PATH="$pico_sdk" \
  -DPICO_TOOLCHAIN_PATH:PATH="$toolchain_root" \
  -DPICO_BOARD:STRING=waveshare_rp2040_zero \
  -DFORCE_BUTTON_WAIT:BOOL=ON \
  -DENABLE_OTP_APP:BOOL=OFF \
  -DENABLE_OATH_APP:BOOL=ON \
  -DPICOKEYS_FETCH_DEPS_ON_DEMAND:BOOL=OFF \
  -DPICOTOOL_FORCE_FETCH_FROM_GIT:BOOL=OFF \
  -Dpicotool_DIR:PATH="$picotool_package" \
  -DCMAKE_BUILD_TYPE:STRING=Release \
  -DCMAKE_C_COMPILER_LAUNCHER:FILEPATH="$compiler_launcher" \
  -DCMAKE_CXX_COMPILER_LAUNCHER:FILEPATH="$compiler_launcher" \
  -DCMAKE_ASM_COMPILER:FILEPATH="$asm_compiler"
cmake --build "$firmware_build" --parallel "$jobs"

built_uf2="$firmware_build/pico_fido.uf2"
if [[ ! -s "$built_uf2" ]]; then
  printf 'build=FAIL reason=firmware_uf2_missing\n' >&2
  exit 1
fi

artifact_name="pico_fido_zero-8.0-public-preview.uf2"
artifact="$dist_dir/$artifact_name"
temporary="$dist_dir/.$artifact_name.$$.tmp"
trap 'rm -f -- "$temporary"' EXIT
install -m 0644 "$built_uf2" "$temporary"

python3 - "$firmware_build/pico_fido.elf" "$temporary" \
  "$source_dir" "$toolchain_root" "$build_dir" "$project_root" <<'PY'
from pathlib import Path
import struct
import sys

elf = Path(sys.argv[1]).read_bytes()
uf2 = Path(sys.argv[2]).read_bytes()
if len(uf2) % 512:
    raise SystemExit("build=FAIL reason=invalid_uf2_block_length")
chunks = []
for offset in range(0, len(uf2), 512):
    block = uf2[offset : offset + 512]
    first, second, _flags, address, size = struct.unpack_from("<IIIII", block)
    if first != 0x0A324655 or second != 0x9E5D5157 or size > 476:
        raise SystemExit("build=FAIL reason=invalid_uf2_block")
    chunks.append((address, block[32 : 32 + size]))
chunks.sort()
base = chunks[0][0]
end = max(address + len(data) for address, data in chunks)
firmware = bytearray(end - base)
for address, data in chunks:
    firmware[address - base : address - base + len(data)] = data

for forbidden in [*sys.argv[3:], "/home/", "/Users/", "C:\\Users\\"]:
    encoded = forbidden.encode()
    if encoded and (encoded in elf or encoded in firmware):
        label = Path(forbidden).name if forbidden not in {"/home/", "/Users/", "C:\\Users\\"} else forbidden
        raise SystemExit(f"build=FAIL reason=local_path_leaked_into_firmware label={label}")
PY

mv -f -- "$temporary" "$artifact"
trap - EXIT

(
  cd "$dist_dir"
  sha256sum "$artifact_name" > "$artifact_name.sha256"
)

printf 'build=PASS\n'
printf 'artifact=%s\n' "$artifact"
printf 'sha256_file=%s.sha256\n' "$artifact"
printf 'qualification=source-build-only_not-hardware-readback\n'
