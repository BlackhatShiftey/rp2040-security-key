#!/usr/bin/env bash
# Flash the frozen RP2040-Zero Pico FIDO image and verify it before rebooting.

set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
FIRMWARE="$PROJECT_ROOT/firmware/pico_fido_zero-8.0-localfix3.uf2"
MANIFEST="$PROJECT_ROOT/evidence/localfix3-firmware.sha256"
PICOTOOL="$PROJECT_ROOT/build/picotool-usb/picotool"
EVIDENCE_DIR="$PROJECT_ROOT/evidence"
VERIFY_LOG="$EVIDENCE_DIR/final-flash-verify.txt"
STATUS_FILE="$EVIDENCE_DIR/final-flash-status.txt"
EXPECTED_SHA256="25394aaf6c1b49c06bc45957d665926b2b4fe6de1a625d1070709e4ce4437549"
BOOTSEL_ID="2e8a:0003"
WAIT_SECONDS=180
TOOL_TIMEOUT_SECONDS=180
OUTPUT_LIMIT_BYTES=65536

PHASE="startup"
FIRMWARE_SHA256="not-checked"
USB_BUS="not-selected"
USB_ADDRESS="not-selected"
RAW_USB_BUS=""
RAW_USB_ADDRESS=""
DEVICE_LINE=""

finish() {
    local exit_code=$?
    local result="FAIL"
    local timestamp="unavailable"
    local status_tmp="${STATUS_FILE}.tmp.$$"

    trap - EXIT
    set +e
    if (( exit_code == 0 )); then
        result="PASS"
    fi
    timestamp="$(date -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf 'unavailable')"
    mkdir -p -- "$EVIDENCE_DIR"
    {
        printf 'result=%s\n' "$result"
        printf 'exit_code=%d\n' "$exit_code"
        printf 'phase=%s\n' "$PHASE"
        printf 'timestamp_utc=%s\n' "$timestamp"
        printf 'firmware_sha256=%s\n' "$FIRMWARE_SHA256"
        printf 'usb_bus=%s\n' "$USB_BUS"
        printf 'usb_address=%s\n' "$USB_ADDRESS"
    } > "$status_tmp"
    mv -f -- "$status_tmp" "$STATUS_FILE"

    printf '\nfinal_status=%s exit_code=%d phase=%s\n' "$result" "$exit_code" "$PHASE"
    printf 'status_receipt=%s\n' "$STATUS_FILE"
    if [[ -t 0 && -t 1 ]]; then
        printf 'Press Enter to close this window.'
        IFS= read -r _ || true
    fi
    exit "$exit_code"
}

trap finish EXIT
trap 'PHASE="interrupted"; exit 130' INT
trap 'PHASE="terminated"; exit 143' TERM

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v -- "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

detect_bootsel() {
    local listing=""
    local line=""
    local lsusb_exit=0
    local -a lines=()

    if listing="$(lsusb -d "$BOOTSEL_ID")"; then
        :
    else
        lsusb_exit=$?
        if (( lsusb_exit == 1 )) && [[ -z "$listing" ]]; then
            return 1
        fi
        return 2
    fi
    while IFS= read -r line; do
        [[ -n "$line" ]] && lines+=("$line")
    done <<< "$listing"

    if (( ${#lines[@]} == 0 )); then
        return 1
    fi
    if (( ${#lines[@]} != 1 )); then
        return 3
    fi

    DEVICE_LINE="${lines[0]}"
    if [[ "$DEVICE_LINE" =~ ^Bus[[:space:]]+([0-9]{3})[[:space:]]+Device[[:space:]]+([0-9]{3}):[[:space:]]+ID[[:space:]]+2[eE]8[aA]:0003([[:space:]].*)?$ ]]; then
        RAW_USB_BUS="${BASH_REMATCH[1]}"
        RAW_USB_ADDRESS="${BASH_REMATCH[2]}"
        USB_BUS="$((10#$RAW_USB_BUS))"
        USB_ADDRESS="$((10#$RAW_USB_ADDRESS))"
        return 0
    fi
    return 4
}

run_logged() {
    local label="$1"
    shift
    local -a pipeline_status=()
    local command_exit=0
    local filter_exit=0
    local tee_exit=0

    printf '\ncommand=%s\n' "$label" | tee -a -- "$VERIFY_LOG"
    set +e
    timeout --foreground "${TOOL_TIMEOUT_SECONDS}s" "$@" 2>&1 \
        | LC_ALL=C awk -v limit="$OUTPUT_LIMIT_BYTES" '
            BEGIN { used = 0; truncated = 0 }
            {
                size = length($0) + 1
                if (!truncated && used + size <= limit) {
                    print
                    used += size
                } else if (!truncated) {
                    print "[tool output truncated at configured byte limit]"
                    truncated = 1
                }
            }
        ' \
        | tee -a -- "$VERIFY_LOG"
    pipeline_status=("${PIPESTATUS[@]}")
    set -e

    command_exit="${pipeline_status[0]:-125}"
    filter_exit="${pipeline_status[1]:-125}"
    tee_exit="${pipeline_status[2]:-125}"
    printf 'receipt command=%s command_exit=%d filter_exit=%d tee_exit=%d\n' \
        "$label" "$command_exit" "$filter_exit" "$tee_exit" \
        | tee -a -- "$VERIFY_LOG"

    (( command_exit == 0 )) || return "$command_exit"
    (( filter_exit == 0 )) || return "$filter_exit"
    (( tee_exit == 0 )) || return "$tee_exit"
}

PHASE="preflight"
cd -- "$PROJECT_ROOT"
for required in awk date lsusb mkdir mv sha256sum sleep sudo tee timeout; do
    require_command "$required"
done
[[ -f "$FIRMWARE" && ! -L "$FIRMWARE" ]] || die "frozen firmware artifact is missing or is not a regular file"
[[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] || die "firmware digest record is missing or is not a regular file"
[[ -f "$PICOTOOL" && ! -L "$PICOTOOL" && -x "$PICOTOOL" ]] || die "USB-capable picotool build is missing or not executable"

digest_output="$(sha256sum -- "$FIRMWARE")" || die "unable to hash the frozen firmware"
FIRMWARE_SHA256="${digest_output%% *}"
[[ "$FIRMWARE_SHA256" == "$EXPECTED_SHA256" ]] || die "frozen firmware SHA-256 does not match the approved digest"
sha256sum -c -- "$MANIFEST" >/dev/null || die "firmware does not match its retained digest record"

mkdir -p -- "$EVIDENCE_DIR"
: > "$VERIFY_LOG"
printf 'firmware_sha256=%s\n' "$FIRMWARE_SHA256" | tee -a -- "$VERIFY_LOG"
printf 'preflight=PASS\n' | tee -a -- "$VERIFY_LOG"

PHASE="waiting-for-bootsel"
printf '\nPut the RP2040-Zero into BOOTSEL mode now:\n'
printf '  1. Hold BOOT.\n'
printf '  2. Tap RESET while still holding BOOT.\n'
printf '  3. Release BOOT.\n'
printf 'Waiting up to %d seconds for exactly one Raspberry Pi RP2 Boot device.\n' "$WAIT_SECONDS"

deadline=$((SECONDS + WAIT_SECONDS))
last_notice=$SECONDS
while (( SECONDS < deadline )); do
    if detect_bootsel; then
        break
    else
        detection_exit=$?
        case "$detection_exit" in
            1)
                if (( SECONDS - last_notice >= 15 )); then
                    printf 'Still waiting for BOOTSEL mode...\n'
                    last_notice=$SECONDS
                fi
                ;;
            2)
                die "lsusb could not inspect USB devices"
                ;;
            3)
                die "more than one RP2 Boot device is attached; disconnect all but the intended key"
                ;;
            *)
                die "the RP2 Boot device listing had an unexpected format"
                ;;
        esac
    fi
    sleep 1
done
[[ -n "$RAW_USB_BUS" && -n "$RAW_USB_ADDRESS" ]] || die "timed out waiting for the RP2040-Zero in BOOTSEL mode"
printf 'selected_device=RP2_BOOT usb_bus=%s usb_address=%s\n' "$USB_BUS" "$USB_ADDRESS" \
    | tee -a -- "$VERIFY_LOG"

PHASE="revalidating-device"
selected_raw_bus="$RAW_USB_BUS"
selected_raw_address="$RAW_USB_ADDRESS"
if ! detect_bootsel; then
    die "the selected RP2 Boot device disappeared or became ambiguous before flashing"
fi
[[ "$RAW_USB_BUS" == "$selected_raw_bus" && "$RAW_USB_ADDRESS" == "$selected_raw_address" ]] \
    || die "the RP2 Boot USB identity changed before flashing; refusing to write"
printf 'device_revalidation=PASS\n' | tee -a -- "$VERIFY_LOG"

PHASE="flashing"
printf '\nThe operating system may ask for your sudo password. Input stays in this terminal.\n'
printf 'Running verified flash for bus %s address %s.\n' "$USB_BUS" "$USB_ADDRESS"
run_logged "picotool-load-verified" \
    sudo -- "$PICOTOOL" load -v "$FIRMWARE" --bus "$USB_BUS" --address "$USB_ADDRESS" \
    || die "picotool load or its built-in verification failed"

PHASE="readback-verification"
printf 'Running independent firmware readback verification.\n'
run_logged "picotool-verify-readback" \
    sudo -- "$PICOTOOL" verify "$FIRMWARE" --bus "$USB_BUS" --address "$USB_ADDRESS" \
    || die "independent picotool readback verification failed"

PHASE="rebooting"
printf 'Readback matched; rebooting the key into the application.\n'
run_logged "picotool-reboot-application" \
    sudo -- "$PICOTOOL" reboot --bus "$USB_BUS" --address "$USB_ADDRESS" \
    || die "firmware verified, but the application reboot command failed"

PHASE="complete"
printf '\nFlash and independent readback verification completed successfully.\n'
printf 'verification_evidence=%s\n' "$VERIFY_LOG"
