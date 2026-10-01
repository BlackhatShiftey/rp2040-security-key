from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PICO_FIDO_SOURCE = Path(
    os.environ.get("PICO_FIDO_SOURCE", PROJECT_ROOT / "vendor/pico-fido")
).resolve()
BUTTON_SOURCE = PICO_FIDO_SOURCE / "pico-keys-sdk/src/button.c"


def extract_button_wait(source: str) -> str:
    start = source.index("int button_wait(void) {")
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError("button_wait function is incomplete")


HARNESS_PREFIX = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MODE_BUTTON 7u
#define SIGNAL_USER_PRESENCE_REQUEST 10
#define SIGNAL_USER_PRESENCE_COMPLETED 11
#define SIGNAL_USER_PRESENCE_TIMEOUT 12
#define SIGNAL_USER_PRESENCE_CANCELLED 13

typedef struct { uint32_t timeout; } signal_user_presence_request_data_t;
typedef struct { bool up_btn_present; uint32_t up_btn; } phy_data_t;

static phy_data_t phy_data = { true, 30 };
static bool req_button_pending = false;
volatile bool cancel_button = false;
volatile bool force_button_wait = false;

static uint32_t fake_now;
static uint32_t press_at;
static uint32_t release_at;
static uint32_t cancel_at;
static int final_signal;

static uint32_t board_millis(void) { return fake_now; }
static bool picok_board_button_read(void) {
    return fake_now >= press_at && fake_now < release_at;
}
void execute_tasks(void) {
    fake_now++;
    if (cancel_at != UINT32_MAX && fake_now >= cancel_at) cancel_button = true;
}
static uint32_t led_get_mode(void) { return 3; }
static void led_set_mode(uint32_t mode) { (void)mode; }
static void signal_emit_param(int signal, const void *data) {
    (void)signal;
    (void)data;
}
static void signal_emit(int signal) { final_signal = signal; }
"""


HARNESS_SUFFIX = r"""
static void run_case(
    const char *name,
    uint32_t pressed,
    uint32_t released,
    uint32_t cancelled,
    int expected_result,
    int expected_signal
) {
    fake_now = 0;
    press_at = pressed;
    release_at = released;
    cancel_at = cancelled;
    final_signal = 0;
    cancel_button = false;
    req_button_pending = false;
    int result = button_wait();
    if (result != expected_result || final_signal != expected_signal || req_button_pending) {
        fprintf(stderr, "%s failed: result=%d signal=%d time=%u pending=%d\n",
                name, result, final_signal, fake_now, req_button_pending);
        exit(1);
    }
}

int main(void) {
    run_case("timely-press", 2000, 2200, UINT32_MAX, 0, SIGNAL_USER_PRESENCE_COMPLETED);
    run_case("late-press", 20000, 20200, UINT32_MAX, 0, SIGNAL_USER_PRESENCE_COMPLETED);
    run_case("no-touch", UINT32_MAX, UINT32_MAX, UINT32_MAX, 1, SIGNAL_USER_PRESENCE_TIMEOUT);
    run_case("held-15-seconds", 20000, 40000, UINT32_MAX, 1, SIGNAL_USER_PRESENCE_TIMEOUT);
    run_case("cancel-waiting", UINT32_MAX, UINT32_MAX, 1000, 2, SIGNAL_USER_PRESENCE_CANCELLED);
    run_case("cancel-release", 2000, UINT32_MAX, 2200, 2, SIGNAL_USER_PRESENCE_CANCELLED);
    puts("button-timing-harness=PASS");
    return 0;
}
"""


class ButtonTimingRegressionTest(unittest.TestCase):
    def test_actual_button_wait_timing_and_cancellation(self) -> None:
        function = extract_button_wait(BUTTON_SOURCE.read_text(encoding="utf-8"))
        self.assertIn("uint32_t release_start = board_millis();", function)
        self.assertIn("(uint32_t)(now - release_start) >= 15000", function)
        self.assertNotIn("start_button + 15000", function)

        with tempfile.TemporaryDirectory() as directory:
            source_path = Path(directory) / "button_timing_harness.c"
            binary_path = Path(directory) / "button_timing_harness"
            source_path.write_text(HARNESS_PREFIX + function + HARNESS_SUFFIX, encoding="utf-8")
            compile_result = subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(source_path),
                    "-o",
                    str(binary_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [str(binary_path)],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)
            self.assertEqual(run_result.stdout.strip(), "button-timing-harness=PASS")


if __name__ == "__main__":
    unittest.main()
