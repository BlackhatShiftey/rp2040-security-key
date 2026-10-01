#!/usr/bin/env python3
"""Read or commission Pico FIDO physical controls over its CCID interface."""

from __future__ import annotations

import argparse
import struct
import sys
import time
from dataclasses import dataclass

import usb.core
import usb.util


VID = 0x2E8A
PID = 0x10FE
CCID_CLASS = 0x0B
CCID_POWER_ON = 0x62
CCID_XFR_BLOCK = 0x6F
CCID_DATA_BLOCK = 0x80
RESCUE_AID = bytes.fromhex("A0583FC19B7E4F21")

TAG_LED_GPIO = 0x04
TAG_LED_BRIGHTNESS = 0x05
TAG_UP_TIMEOUT = 0x08
TAG_LED_DRIVER = 0x0C

# Waveshare RP2040-Zero: WS2812 on GPIO16, GRB wire order. Brightness is 0..15.
DESIRED = {
    TAG_LED_GPIO: bytes([16]),
    TAG_LED_BRIGHTNESS: bytes([4]),
    TAG_UP_TIMEOUT: bytes([30]),
    TAG_LED_DRIVER: bytes([3, 2]),
}

KNOWN_LENGTHS: dict[int, tuple[int, ...]] = {
    0x00: (4,),
    0x04: (1,),
    0x05: (1,),
    0x06: (2,),
    0x08: (1,),
    0x09: tuple(range(1, 33)),
    0x0A: (4,),
    0x0B: (1,),
    0x0C: (1, 2),
}


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Tlv:
    tag: int
    value: bytes


def parse_tlvs(data: bytes) -> list[Tlv]:
    records: list[Tlv] = []
    seen: set[int] = set()
    offset = 0
    while offset < len(data):
        if len(data) - offset < 2:
            raise ConfigError("truncated TLV header")
        tag, length = data[offset], data[offset + 1]
        offset += 2
        if length > len(data) - offset:
            raise ConfigError("truncated TLV value")
        if tag in seen:
            raise ConfigError("duplicate TLV tag")
        if tag not in KNOWN_LENGTHS:
            raise ConfigError("unknown TLV tag; refusing a lossy rewrite")
        if length not in KNOWN_LENGTHS[tag]:
            raise ConfigError("invalid TLV length")
        records.append(Tlv(tag, data[offset : offset + length]))
        seen.add(tag)
        offset += length
    return records


def encode_tlvs(records: list[Tlv]) -> bytes:
    return b"".join(bytes([item.tag, len(item.value)]) + item.value for item in records)


def merge_config(records: list[Tlv]) -> list[Tlv]:
    merged = [Tlv(item.tag, DESIRED.get(item.tag, item.value)) for item in records]
    present = {item.tag for item in merged}
    merged.extend(Tlv(tag, value) for tag, value in DESIRED.items() if tag not in present)
    return merged


def verify_readback(before: list[Tlv], after: list[Tlv]) -> None:
    before_map = {item.tag: item.value for item in before}
    after_map = {item.tag: item.value for item in after}
    expected = before_map | DESIRED
    for tag, value in expected.items():
        if after_map.get(tag) != value:
            raise ConfigError("configuration readback mismatch")


class CcidDevice:
    def __init__(self) -> None:
        devices = list(usb.core.find(find_all=True, idVendor=VID, idProduct=PID))
        if len(devices) != 1:
            raise ConfigError("expected exactly one allowlisted Pico FIDO device")
        self.device = devices[0]
        try:
            configuration = self.device.get_active_configuration()
        except usb.core.USBError as exc:
            raise ConfigError("unable to read active USB configuration") from exc

        interfaces = [item for item in configuration if item.bInterfaceClass == CCID_CLASS]
        if len(interfaces) != 1:
            raise ConfigError("expected exactly one CCID interface")
        self.interface = interfaces[0]
        endpoints = list(self.interface.endpoints())
        bulk_in = [
            ep
            for ep in endpoints
            if usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
            and usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN
        ]
        bulk_out = [
            ep
            for ep in endpoints
            if usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
            and usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT
        ]
        if len(bulk_in) != 1 or len(bulk_out) != 1:
            raise ConfigError("invalid CCID bulk endpoint layout")
        self.endpoint_in = bulk_in[0]
        self.endpoint_out = bulk_out[0]
        self.sequence = 0
        self.detached = False

    def __enter__(self) -> CcidDevice:
        number = self.interface.bInterfaceNumber
        try:
            if self.device.is_kernel_driver_active(number):
                self.device.detach_kernel_driver(number)
                self.detached = True
            usb.util.claim_interface(self.device, number)
        except (NotImplementedError, usb.core.USBError) as exc:
            raise ConfigError("unable to claim the Pico FIDO CCID interface") from exc
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        number = self.interface.bInterfaceNumber
        try:
            usb.util.release_interface(self.device, number)
        except usb.core.USBError:
            pass
        if self.detached:
            try:
                self.device.attach_kernel_driver(number)
            except usb.core.USBError:
                pass
        usb.util.dispose_resources(self.device)

    def _next_sequence(self) -> int:
        value = self.sequence
        self.sequence = (self.sequence + 1) & 0xFF
        return value

    def _exchange(self, message_type: int, body: bytes, timeout_seconds: float) -> bytes:
        sequence = self._next_sequence()
        if message_type == CCID_POWER_ON:
            header = struct.pack("<BIBBBBB", message_type, len(body), 0, sequence, 0, 0, 0)
        else:
            header = struct.pack("<BIBBBH", message_type, len(body), 0, sequence, 0, 0)
        try:
            written = self.endpoint_out.write(header + body, timeout=2_000)
        except usb.core.USBError as exc:
            raise ConfigError("CCID write failed") from exc
        if written != len(header) + len(body):
            raise ConfigError("short CCID write")

        deadline = time.monotonic() + timeout_seconds
        while True:
            remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
            if time.monotonic() >= deadline:
                raise ConfigError("CCID operation timed out")
            try:
                raw = bytes(self.endpoint_in.read(4096, timeout=remaining_ms))
            except usb.core.USBTimeoutError as exc:
                raise ConfigError("CCID operation timed out") from exc
            except usb.core.USBError as exc:
                raise ConfigError("CCID read failed") from exc
            if len(raw) < 10:
                raise ConfigError("short CCID response")
            response_type, length, slot, response_sequence, status, error, chain = struct.unpack(
                "<BIBBBBB", raw[:10]
            )
            if response_type != CCID_DATA_BLOCK or slot != 0 or response_sequence != sequence:
                raise ConfigError("unexpected CCID response")
            command_status = status & 0xC0
            if command_status == 0x80:  # CCID time extension while waiting for touch.
                continue
            if command_status != 0:
                raise ConfigError(f"CCID command failed ({error:02x})")
            if chain != 0 or length != len(raw) - 10:
                raise ConfigError("unsupported or malformed CCID response")
            return raw[10:]

    def power_on(self) -> None:
        if not self._exchange(CCID_POWER_ON, b"", 5):
            raise ConfigError("CCID power-on returned no ATR")

    def transmit(self, apdu: bytes, timeout_seconds: float = 5) -> bytes:
        response = self._exchange(CCID_XFR_BLOCK, apdu, timeout_seconds)
        if len(response) < 2:
            raise ConfigError("short APDU response")
        data, status = response[:-2], response[-2:]
        if status != b"\x90\x00":
            raise ConfigError(f"APDU failed ({status.hex()})")
        return data


def select_rescue(device: CcidDevice) -> None:
    device.transmit(b"\x00\xA4\x04\x00\x08" + RESCUE_AID + b"\x00")


def read_config(device: CcidDevice) -> list[Tlv]:
    return parse_tlvs(device.transmit(b"\x80\x1E\x01\x00\x00"))


def write_config(device: CcidDevice, records: list[Tlv]) -> None:
    payload = encode_tlvs(records)
    if not 2 <= len(payload) <= 255:
        raise ConfigError("configuration payload length is invalid")
    device.transmit(b"\x80\x1C\x01\x00" + bytes([len(payload)]) + payload, 45)


def reboot_normal(device: CcidDevice) -> None:
    device.transmit(b"\x80\x1F\x00\x00\x00", 5)


def print_config(records: list[Tlv]) -> None:
    values = {item.tag: item.value for item in records}
    print("result=PASS")
    print(f"up_timeout_seconds={values[TAG_UP_TIMEOUT][0] if TAG_UP_TIMEOUT in values else 'absent'}")
    print(f"led_gpio={values[TAG_LED_GPIO][0] if TAG_LED_GPIO in values else 'absent'}")
    print(f"led_brightness={values[TAG_LED_BRIGHTNESS][0] if TAG_LED_BRIGHTNESS in values else 'absent'}")
    driver = values.get(TAG_LED_DRIVER)
    print(f"led_driver={driver[0] if driver else 'absent'}")
    print(f"led_order={driver[1] if driver and len(driver) == 2 else 'absent'}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read or commission Pico FIDO physical controls")
    parser.add_argument("--apply", action="store_true", help="write and verify the RP2040-Zero control configuration")
    parser.add_argument("--reboot", action="store_true", help="normally reboot after a verified --apply")
    args = parser.parse_args()
    if args.reboot and not args.apply:
        parser.error("--reboot requires --apply")
    return args


def main() -> int:
    args = parse_args()
    try:
        with CcidDevice() as device:
            device.power_on()
            select_rescue(device)
            before = read_config(device)
            if not args.apply:
                print_config(before)
                return 0
            desired = merge_config(before)
            write_config(device, desired)
            after = read_config(device)
            verify_readback(before, after)
            print_config(after)
            if args.reboot:
                reboot_normal(device)
            return 0
    except ConfigError as exc:
        print("result=FAIL")
        print(f"reason={exc}")
        return 1
    except Exception as exc:
        print("result=FAIL")
        print(f"reason=unexpected {type(exc).__name__}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
