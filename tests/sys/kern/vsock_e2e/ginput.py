#!/usr/bin/env python3
"""Strict Linux guest verifier for the bhyve virtio-input E2E test."""

import glob
import os
import struct
import sys
import tempfile
import time

# VirtIO 1.4 feature allocation (§6).
VIRTIO_F_IN_ORDER = 35
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40

MODERN_REQUIRED_FEATURES = (
    (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
    (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
)

EVENT = struct.Struct("@llHHi")
EV_SYN, EV_KEY, EV_REL, EV_ABS, EV_LED = 0, 1, 2, 3, 17
SYN_REPORT, KEY_A, REL_X, ABS_X, LED_CAPSL = 0, 30, 0, 0, 1
EXPECTED = [
    (EV_KEY, KEY_A, 1),
    (EV_SYN, SYN_REPORT, 0),
    (EV_REL, REL_X, 7),
    (EV_ABS, ABS_X, 321),
    (EV_KEY, KEY_A, 0),
    (EV_SYN, SYN_REPORT, 0),
]


def pci_parent(event):
    path = os.path.realpath(f"/sys/class/input/{event}/device")
    while path != "/":
        subsystem = path + "/subsystem"
        if os.path.islink(subsystem) and os.path.basename(
            os.path.realpath(subsystem)
        ) == "pci":
            return path
        path = os.path.dirname(path)
    raise RuntimeError("input device has no PCI parent")


def parse_vendor_capability(data):
    if len(data) < 64:
        raise RuntimeError("short PCI config space")
    offset, visited = data[0x34] & ~3, set()
    while offset:
        if offset in visited or offset < 0x40 or offset + 2 > len(data):
            raise RuntimeError("invalid PCI capability chain")
        visited.add(offset)
        if data[offset] == 0x09:
            return True
        offset = data[offset + 1] & ~3
    return False


def has_vendor_capability(config):
    return parse_vendor_capability(open(config, "rb").read(256))


def negotiated_feature(pci, bit):
    children = glob.glob(pci + "/virtio*")
    if len(children) != 1:
        raise RuntimeError(
            f"expected one virtio child below {pci}, found {len(children)}"
        )
    feature_path = children[0] + "/features"
    try:
        features = open(feature_path, encoding="ascii").read().strip()
    except OSError as error:
        raise RuntimeError(f"cannot read {feature_path}: {error}") from error
    if len(features) <= bit or any(value not in "01" for value in features):
        raise RuntimeError(f"invalid virtio feature bitmap: {features!r}")
    return features[bit] == "1"

def require_features(pci, required):
    for bit, name in required:
        if not negotiated_feature(pci, bit):
            raise RuntimeError(f"virtio-input did not negotiate {name}")


def check_event_prefix(received):
    if received != EXPECTED[: len(received)]:
        raise RuntimeError(f"unexpected event sequence: {received!r}")


def self_test():
    legacy = bytearray(256)
    legacy[0x34], legacy[0x40], legacy[0x41] = 0x40, 0x11, 0
    assert not parse_vendor_capability(legacy)
    modern = bytearray(legacy)
    modern[0x41], modern[0x44], modern[0x45] = 0x44, 0x09, 0
    assert parse_vendor_capability(modern)
    for broken in (b"short", bytearray(legacy)):
        if len(broken) >= 64:
            broken[0x41] = 0x40
        try:
            parse_vendor_capability(broken)
        except RuntimeError:
            pass
        else:
            raise AssertionError("malformed capability chain was accepted")
    for length in range(len(EXPECTED) + 1):
        check_event_prefix(EXPECTED[:length])
    for broken in (
        [(EV_KEY, KEY_A, 0)],
        EXPECTED[:2] + [EXPECTED[1]],
        EXPECTED + [(EV_SYN, SYN_REPORT, 0)],
    ):
        try:
            check_event_prefix(broken)
        except RuntimeError:
            pass
        else:
            raise AssertionError("bad event sequence was accepted")
    with tempfile.TemporaryDirectory() as root:
        child = os.path.join(root, "virtio0")
        os.mkdir(child)
        features = ["0"] * 64
        for bit, _ in MODERN_REQUIRED_FEATURES:
            features[bit] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        require_features(root, MODERN_REQUIRED_FEATURES)
        assert not negotiated_feature(root, 34)
        for missing_bit, missing_name in MODERN_REQUIRED_FEATURES:
            missing = features.copy()
            missing[missing_bit] = "0"
            with open(child + "/features", "w", encoding="ascii") as stream:
                stream.write("".join(missing) + "\n")
            try:
                require_features(root, MODERN_REQUIRED_FEATURES)
            except RuntimeError:
                pass
            else:
                raise AssertionError(
                    f"missing input feature {missing_name} was accepted"
                )
    print("SELFTEST PASS")


def find_device(name):
    matches = []
    for name_file in glob.glob("/sys/class/input/event*/device/name"):
        if open(name_file, encoding="utf-8").read().strip() == name:
            matches.append(name_file.split("/")[4])
    if len(matches) != 1:
        raise RuntimeError(f"expected one {name!r} input device, found {len(matches)}")
    return matches[0]


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) != 3 or sys.argv[2] not in ("modern", "legacy"):
        raise SystemExit("usage: ginput.py device-name modern|legacy")
    event = find_device(sys.argv[1])
    pci = pci_parent(event)
    if open(pci + "/vendor").read().strip() != "0x1af4":
        raise RuntimeError("wrong PCI vendor")
    if open(pci + "/device").read().strip() != "0x1052":
        raise RuntimeError("wrong PCI device ID")
    modern = has_vendor_capability(pci + "/config")
    if modern != (sys.argv[2] == "modern"):
        raise RuntimeError("PCI capability layout does not match requested transport")
    if modern:
        require_features(pci, MODERN_REQUIRED_FEATURES)
    in_order = modern and negotiated_feature(pci, VIRTIO_F_IN_ORDER)

    fd = os.open("/dev/input/" + event, os.O_RDWR | os.O_NONBLOCK)
    try:
        while True:
            try:
                if not os.read(fd, EVENT.size * 16):
                    break
            except BlockingIOError:
                break
        print(
            "FEATURE "
            f"in_order={'yes' if in_order else ('no' if modern else 'n/a')}",
            flush=True,
        )
        print("READY", flush=True)
        received, pending = [], b""
        deadline = time.monotonic() + 15
        while len(received) < len(EXPECTED) and time.monotonic() < deadline:
            try:
                pending += os.read(fd, EVENT.size * 16)
            except BlockingIOError:
                time.sleep(0.02)
                continue
            while len(pending) >= EVENT.size:
                record, pending = pending[: EVENT.size], pending[EVENT.size :]
                _, _, etype, code, value = EVENT.unpack(record)
                if etype in (EV_KEY, EV_REL, EV_ABS, EV_SYN):
                    received.append((etype, code, value))
                    check_event_prefix(received)
        if pending or received != EXPECTED:
            raise RuntimeError(f"incomplete event sequence: {received!r}")

        now = int(time.time())
        status = EVENT.pack(now, 0, EV_LED, LED_CAPSL, 1)
        written = os.write(fd, status)
        if written != len(status):
            raise RuntimeError(f"short status write: {written}/{len(status)}")
        print("STATUS_SENT type=17 code=1 value=1", flush=True)
        print("PASS", flush=True)
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
