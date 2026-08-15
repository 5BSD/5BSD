#!/usr/bin/env python3
"""Strict Linux guest verifier for the bhyve virtio-input E2E test."""

import glob
import os
import select
import struct
import sys
import tempfile
import time

# VIRTIO_ACTIVATION_ASSERTION: packed-negotiation-and-injected-events
# VIRTIO_ACTIVATION_ASSERTION: in-order-negotiation-and-ordered-events

# VirtIO 1.4 feature allocation (§6).
VIRTIO_F_RING_PACKED = 34
VIRTIO_F_IN_ORDER = 35
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40

MODERN_REQUIRED_FEATURES = (
    (VIRTIO_F_IN_ORDER, "VIRTIO_F_IN_ORDER"),
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


def atomic_count(path, count):
    temporary = path + ".new"
    with open(temporary, "w", encoding="ascii") as stream:
        stream.write(f"{count}\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def receive_frame(fd, timeout):
    received, pending = [], b""
    deadline = None if timeout is None else time.monotonic() + timeout
    while len(received) < len(EXPECTED):
        try:
            pending += os.read(fd, EVENT.size * 16)
        except BlockingIOError:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                break
            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                break
            continue
        while len(pending) >= EVENT.size:
            record, pending = pending[: EVENT.size], pending[EVENT.size :]
            _, _, etype, code, value = EVENT.unpack(record)
            if etype in (EV_KEY, EV_REL, EV_ABS, EV_SYN):
                received.append((etype, code, value))
                check_event_prefix(received)
    if pending or received != EXPECTED:
        raise RuntimeError(f"incomplete event sequence: {received!r}")


def send_caps_status(fd):
    now = int(time.time())
    status = EVENT.pack(now, 0, EV_LED, LED_CAPSL, 1)
    written = os.write(fd, status)
    if written != len(status):
        raise RuntimeError(f"short status write: {written}/{len(status)}")


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
        assert not negotiated_feature(root, VIRTIO_F_RING_PACKED)
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
        features[VIRTIO_F_RING_PACKED] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        assert negotiated_feature(root, VIRTIO_F_RING_PACKED)
        count = root + "/count"
        atomic_count(count, 9)
        with open(count, encoding="ascii") as stream:
            assert stream.read() == "9\n"
    read_fd, write_fd = os.pipe()
    try:
        os.set_blocking(read_fd, False)
        os.write(
            write_fd,
            b"".join(
                EVENT.pack(0, 0, event_type, code, value)
                for event_type, code, value in EXPECTED
            ),
        )
        receive_frame(read_fd, 0)
        try:
            receive_frame(read_fd, 0)
        except RuntimeError:
            pass
        else:
            raise AssertionError("empty input frame was accepted")
    finally:
        os.close(read_fd)
        os.close(write_fd)
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
    if len(sys.argv) < 3 or sys.argv[2] not in ("modern", "legacy"):
        raise SystemExit(
            "usage: ginput.py device-name modern|legacy [packed] "
            "[checkpoint count-file]"
        )
    options = sys.argv[3:]
    require_packed = options[:1] == ["packed"]
    if require_packed:
        options = options[1:]
    checkpoint_count = None
    if options:
        if len(options) != 2 or options[0] != "checkpoint":
            raise SystemExit(
                "usage: ginput.py device-name modern|legacy [packed] "
                "[checkpoint count-file]"
            )
        checkpoint_count = options[1]
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
    packed = modern and negotiated_feature(pci, VIRTIO_F_RING_PACKED)
    if require_packed and not packed:
        raise RuntimeError(
            "virtio-input did not negotiate VIRTIO_F_RING_PACKED"
        )
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
            f"in_order={'yes' if in_order else ('no' if modern else 'n/a')} "
            f"packed={'yes' if packed else ('no' if modern else 'n/a')}",
            flush=True,
        )
        print("READY", flush=True)
        if checkpoint_count is None:
            receive_frame(fd, 15)
            send_caps_status(fd)
            print("STATUS_SENT type=17 code=1 value=1", flush=True)
            print("PASS", flush=True)
        else:
            for stale in (checkpoint_count, checkpoint_count + ".new"):
                try:
                    os.unlink(stale)
                except FileNotFoundError:
                    pass
            count = 0
            while True:
                receive_frame(fd, None)
                send_caps_status(fd)
                count += 1
                atomic_count(checkpoint_count, count)
                print(f"PASS checkpoint-frame={count}", flush=True)
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
