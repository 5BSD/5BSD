#!/usr/bin/env python3
"""Linux guest end-to-end verifier for bhyve virtio-rtc."""

import glob
import os
import select
import signal
import sys
import tempfile
import time

# VIRTIO_ACTIVATION_ASSERTION: clock-read-and-state-check
# VIRTIO_ACTIVATION_ASSERTION: active-checkpoint-rtc-alarm

# Independent VirtIO 1.4 feature allocation (§6 and §5.23).
VIRTIO_RTC_F_ALARM = 0
VIRTIO_F_RING_PACKED = 34
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40

MODERN_REQUIRED_FEATURES = (
    (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
    (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
)

RUNNING = True


def stop_worker(_signum, _frame):
    global RUNNING
    RUNNING = False


def atomic_count(path, value):
    temporary = path + ".new"
    with open(temporary, "w", encoding="ascii") as stream:
        stream.write(f"{value}\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def negotiated_feature(child, bit):
    feature_path = child + "/features"
    try:
        features = open(feature_path, encoding="ascii").read().strip()
    except (OSError, ValueError) as error:
        raise RuntimeError(f"cannot read {feature_path}: {error}") from error
    if len(features) <= bit or any(value not in "01" for value in features):
        raise RuntimeError(f"invalid virtio feature bitmap: {features!r}")
    return features[bit] == "1"


def require_features(child, required):
    for bit, name in required:
        if not negotiated_feature(child, bit):
            raise RuntimeError(f"virtio-rtc did not negotiate {name}")


def find_bound_rtc():
    matches = []
    for pci in glob.glob("/sys/bus/pci/devices/*"):
        try:
            vendor = open(pci + "/vendor", encoding="ascii").read().strip()
            device = open(pci + "/device", encoding="ascii").read().strip()
        except OSError:
            continue
        if vendor != "0x1af4" or device != "0x1051":
            continue
        children = []
        for child in glob.glob(pci + "/virtio*"):
            driver = child + "/driver"
            if os.path.islink(driver) and os.path.basename(
                os.path.realpath(driver)
            ) == "virtio_rtc":
                children.append(child)
        if len(children) == 1:
            matches.append((pci, children[0]))
    if len(matches) != 1:
        raise RuntimeError(
            "expected one PCI 0x1051 device bound to virtio_rtc, "
            f"found {len(matches)}"
        )
    return matches[0]


def find_class_device(child, class_name):
    child_real = os.path.realpath(child)
    matches = []
    for class_device in glob.glob(f"/sys/class/{class_name}/{class_name}*"):
        device = class_device + "/device"
        if not os.path.exists(device):
            continue
        device_real = os.path.realpath(device)
        try:
            related = os.path.commonpath((child_real, device_real)) == child_real
        except ValueError:
            related = False
        if related:
            matches.append(class_device)
    return matches


def read_since_epoch(rtc):
    path = rtc + "/since_epoch"
    try:
        value = open(path, encoding="ascii").read().strip()
        return int(value, 10)
    except (OSError, ValueError) as error:
        raise RuntimeError(f"cannot read a valid {path}: {error}") from error


def read_ptp_seconds(ptp):
    path = "/dev/" + os.path.basename(ptp)
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as error:
        raise RuntimeError(f"cannot open {path}: {error}") from error
    try:
        # Linux FD_TO_CLOCKID(): invert the fd, shift it, and select
        # CLOCKFD.  Python passes this integer clock ID to clock_gettime(2).
        clock_id = ((~fd) << 3) | 3
        return time.clock_gettime(clock_id)
    except OSError as error:
        raise RuntimeError(f"cannot read {path}: {error}") from error
    finally:
        os.close(fd)


def read_exposed_clock(child):
    rtc_matches = find_class_device(child, "rtc")
    ptp_matches = find_class_device(child, "ptp")
    if len(rtc_matches) + len(ptp_matches) != 1:
        raise RuntimeError(
            "expected exactly one RTC or PTP clock below virtio-rtc, "
            f"found rtc={len(rtc_matches)} ptp={len(ptp_matches)}"
        )
    if rtc_matches:
        return "rtc", os.path.basename(rtc_matches[0]), read_since_epoch(
            rtc_matches[0]
        )
    return "ptp", os.path.basename(ptp_matches[0]), read_ptp_seconds(
        ptp_matches[0]
    )


def check_time(host_before, rtc_seconds, host_after, tolerance=5):
    lower = int(host_before) - tolerance
    upper = int(host_after) + tolerance
    if not lower <= rtc_seconds <= upper:
        raise RuntimeError(
            f"virtio-rtc time {rtc_seconds} outside host interval "
            f"[{lower}, {upper}]"
        )

def exercise_alarm(child):
    rtc_matches = find_class_device(child, "rtc")
    if len(rtc_matches) != 1:
        raise RuntimeError(
            "alarm qualification requires exactly one related RTC class "
            f"device, found {len(rtc_matches)}"
        )
    rtc = rtc_matches[0]
    wakealarm = rtc + "/wakealarm"
    device = "/dev/" + os.path.basename(rtc)
    fd = os.open(device, os.O_RDONLY | os.O_NONBLOCK)
    try:
        with open(wakealarm, "w", encoding="ascii") as stream:
            stream.write("0\n")
        with open(wakealarm, "w", encoding="ascii") as stream:
            stream.write("+2\n")
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        events = poller.poll(10000)
        if not events or not (events[0][1] & select.POLLIN):
            raise RuntimeError("virtio-rtc alarm notification timed out")
        event = os.read(fd, 8)
        if len(event) not in (4, 8):
            raise RuntimeError(f"invalid RTC event length {len(event)}")
        irq = int.from_bytes(event, sys.byteorder)
        if not (irq & 0x20) or not (irq & 0x80):
            raise RuntimeError(f"RTC event lacks AF|IRQF: {irq:#x}")
    finally:
        try:
            with open(wakealarm, "w", encoding="ascii") as stream:
                stream.write("0\n")
        except OSError:
            pass
        os.close(fd)


def checkpoint_alarm_worker(count_path, delay):
    if delay < 5 or delay > 120:
        raise RuntimeError("checkpoint alarm delay must be between 5 and 120s")
    _pci, child = find_bound_rtc()
    require_features(child, MODERN_REQUIRED_FEATURES)
    if not negotiated_feature(child, VIRTIO_RTC_F_ALARM):
        raise RuntimeError("checkpoint alarm worker requires VIRTIO_RTC_F_ALARM")
    rtc_matches = find_class_device(child, "rtc")
    if len(rtc_matches) != 1:
        raise RuntimeError(
            "checkpoint alarm worker requires exactly one RTC class device, "
            f"found {len(rtc_matches)}"
        )
    rtc = rtc_matches[0]
    wakealarm = rtc + "/wakealarm"
    device = "/dev/" + os.path.basename(rtc)
    fd = os.open(device, os.O_RDONLY | os.O_NONBLOCK)
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    signal.signal(signal.SIGTERM, stop_worker)
    signal.signal(signal.SIGINT, stop_worker)
    try:
        with open(wakealarm, "w", encoding="ascii") as stream:
            stream.write("0\n")
        with open(wakealarm, "w", encoding="ascii") as stream:
            stream.write(f"+{delay}\n")
        armed = open(wakealarm, encoding="ascii").read().strip()
        if not armed or not armed.isdigit():
            raise RuntimeError(f"invalid armed wakealarm value: {armed!r}")
        atomic_count(count_path, 1)
        print(f"READY alarm={armed}", flush=True)
        deadline = time.monotonic() + delay + 120
        while RUNNING:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("restored virtio-rtc alarm timed out")
            events = poller.poll(min(1000, max(1, int(remaining * 1000))))
            if not events:
                continue
            if not (events[0][1] & select.POLLIN):
                raise RuntimeError(
                    f"unexpected RTC poll events {events[0][1]:#x}"
                )
            event = os.read(fd, 8)
            if len(event) not in (4, 8):
                raise RuntimeError(f"invalid RTC event length {len(event)}")
            irq = int.from_bytes(event, sys.byteorder)
            if not (irq & 0x20) or not (irq & 0x80):
                raise RuntimeError(f"RTC event lacks AF|IRQF: {irq:#x}")
            atomic_count(count_path, 2)
            print(f"ALARM irq={irq:#x}", flush=True)
            while RUNNING:
                time.sleep(0.2)
            return
    finally:
        try:
            with open(wakealarm, "w", encoding="ascii") as stream:
                stream.write("0\n")
        except OSError:
            pass
        os.close(fd)


def self_test():
    with tempfile.TemporaryDirectory() as root:
        child = os.path.join(root, "virtio0")
        os.mkdir(child)
        features = ["0"] * 64
        for bit, _ in MODERN_REQUIRED_FEATURES:
            features[bit] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        require_features(child, MODERN_REQUIRED_FEATURES)
        assert not negotiated_feature(child, VIRTIO_RTC_F_ALARM)
        assert not negotiated_feature(child, VIRTIO_F_RING_PACKED)
        features[VIRTIO_F_RING_PACKED] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        assert negotiated_feature(child, VIRTIO_F_RING_PACKED)
        for missing_bit, missing_name in MODERN_REQUIRED_FEATURES:
            missing = features.copy()
            missing[missing_bit] = "0"
            with open(child + "/features", "w", encoding="ascii") as stream:
                stream.write("".join(missing) + "\n")
            try:
                require_features(child, MODERN_REQUIRED_FEATURES)
            except RuntimeError:
                pass
            else:
                raise AssertionError(
                    f"missing RTC feature {missing_name} was accepted"
                )
    check_time(100.1, 100, 100.9, tolerance=0)
    try:
        check_time(100, 94, 100, tolerance=5)
    except RuntimeError:
        pass
    else:
        raise AssertionError("out-of-range RTC reading was accepted")
    with tempfile.TemporaryDirectory() as root:
        count_path = os.path.join(root, "count")
        atomic_count(count_path, 7)
        assert open(count_path, encoding="ascii").read() == "7\n"
        assert not os.path.exists(count_path + ".new")
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) == 4 and sys.argv[1] == "checkpoint-alarm":
        try:
            delay = int(sys.argv[3], 10)
        except ValueError as error:
            raise SystemExit("checkpoint alarm delay must be numeric") from error
        checkpoint_alarm_worker(sys.argv[2], delay)
        return
    options = set(sys.argv[1:])
    if len(options) != len(sys.argv[1:]) or not options <= {
        "packed",
        "alarm",
    }:
        raise SystemExit(
            "usage: grtc.py [packed] [alarm] | "
            "grtc.py checkpoint-alarm count-file delay-seconds"
        )
    expect_packed = "packed" in options
    expect_alarm = "alarm" in options
    pci, child = find_bound_rtc()
    require_features(child, MODERN_REQUIRED_FEATURES)
    packed = negotiated_feature(child, VIRTIO_F_RING_PACKED)
    if packed != expect_packed:
        raise RuntimeError(
            "virtio-rtc packed negotiation mismatch: "
            f"expected={'yes' if expect_packed else 'no'} "
            f"actual={'yes' if packed else 'no'}"
        )
    alarm = negotiated_feature(child, VIRTIO_RTC_F_ALARM)
    if alarm != expect_alarm:
        raise RuntimeError(
            "virtio-rtc alarm negotiation mismatch: "
            f"expected={'yes' if expect_alarm else 'no'} "
            f"actual={'yes' if alarm else 'no'}"
        )
    before = time.time()
    clock_class, clock_name, reading = read_exposed_clock(child)
    after = time.time()
    check_time(before, reading, after)
    if alarm:
        exercise_alarm(child)
    print(
        f"PASS rtc pci={os.path.basename(pci)} "
        f"clock={clock_class}:{clock_name} utc={int(reading)} "
        f"alarm={'yes' if alarm else 'no'} "
        f"packed={'yes' if packed else 'no'} "
        "notification_data=yes ring_reset=yes"
    )


if __name__ == "__main__":
    main()
