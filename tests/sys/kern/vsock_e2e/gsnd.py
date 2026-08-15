#!/usr/bin/env python3
"""Linux guest activation test for bhyve's VirtIO 1.4 sound device."""

import glob
import os
import signal
import subprocess
import sys
import tempfile
import time

# Independent VirtIO 1.4 CS01 constants (§5.14 and §6).
VIRTIO_F_RING_PACKED = 34
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40
MODERN_DEVICE = "0x1059"  # 0x1040 + VirtIO device ID 25.
FRAME_BYTES = 4  # S16_LE, two channels.
RATE = 48000
PAYLOAD_BYTES = RATE * FRAME_BYTES
CHECKPOINT_PID = "/tmp/virtio-snd-checkpoint.pid"
CHECKPOINT_FEEDER_PID = "/tmp/virtio-snd-checkpoint-feeder.pid"
CHECKPOINT_FIFO = "/tmp/virtio-snd-checkpoint.fifo"
CHECKPOINT_LOG = "/tmp/virtio-snd-checkpoint.log"


def negotiated_feature(child, bit):
    path = child + "/features"
    try:
        features = open(path, encoding="ascii").read().strip()
    except OSError as error:
        raise RuntimeError(f"cannot read {path}: {error}") from error
    if len(features) <= bit or any(value not in "01" for value in features):
        raise RuntimeError(f"invalid virtio feature bitmap: {features!r}")
    return features[bit] == "1"


def find_bound_sound(sys_root="/sys"):
    matches = []
    for pci in glob.glob(sys_root + "/bus/pci/devices/*"):
        try:
            vendor = open(pci + "/vendor", encoding="ascii").read().strip()
            device = open(pci + "/device", encoding="ascii").read().strip()
        except OSError:
            continue
        if vendor != "0x1af4" or device != MODERN_DEVICE:
            continue
        for child in glob.glob(pci + "/virtio*"):
            driver = child + "/driver"
            if os.path.islink(driver) and os.path.basename(
                os.path.realpath(driver)
            ) == "virtio_snd":
                matches.append((pci, child))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {MODERN_DEVICE} device bound to virtio_snd, "
            f"found {len(matches)}"
        )
    return matches[0]


def find_card(child, sys_root="/sys"):
    child_real = os.path.realpath(child)
    matches = []
    for card in glob.glob(sys_root + "/class/sound/card[0-9]*"):
        if os.path.realpath(card + "/device") == child_real:
            suffix = os.path.basename(card)[4:]
            if suffix.isdigit():
                matches.append(int(suffix))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one ALSA card for {child_real}, found {matches!r}"
        )
    return matches[0]


def validate_capture(path, backend):
    data = open(path, "rb").read()
    if len(data) != PAYLOAD_BYTES:
        raise RuntimeError(
            f"capture returned {len(data)} bytes, expected {PAYLOAD_BYTES}"
        )
    if backend == "null" and any(data):
        raise RuntimeError("null sound backend returned nonzero capture data")
    if backend not in ("null", "oss"):
        raise RuntimeError(f"unknown sound backend {backend!r}")


def self_test():
    with tempfile.TemporaryDirectory() as root:
        sys_root = root + "/sys"
        pci = sys_root + "/bus/pci/devices/0000:00:11.0"
        child = pci + "/virtio7"
        driver = root + "/drivers/virtio_snd"
        card = sys_root + "/class/sound/card3"
        os.makedirs(child)
        os.makedirs(driver)
        os.makedirs(card)
        with open(pci + "/vendor", "w", encoding="ascii") as stream:
            stream.write("0x1af4\n")
        with open(pci + "/device", "w", encoding="ascii") as stream:
            stream.write(MODERN_DEVICE + "\n")
        os.symlink(driver, child + "/driver")
        os.symlink(child, card + "/device")
        features = ["0"] * 64
        features[VIRTIO_F_NOTIFICATION_DATA] = "1"
        features[VIRTIO_F_RING_RESET] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        found_pci, found_child = find_bound_sound(sys_root)
        assert found_pci == pci and found_child == child
        assert find_card(child, sys_root) == 3
        assert negotiated_feature(child, VIRTIO_F_NOTIFICATION_DATA)
        assert negotiated_feature(child, VIRTIO_F_RING_RESET)
        features[VIRTIO_F_RING_PACKED] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        assert negotiated_feature(child, VIRTIO_F_RING_PACKED)
        capture = root + "/capture.raw"
        with open(capture, "wb") as stream:
            stream.write(bytes(PAYLOAD_BYTES))
        validate_capture(capture, "null")
        with open(capture, "wb") as stream:
            stream.write(bytes([0x5A]) * PAYLOAD_BYTES)
        validate_capture(capture, "oss")
        try:
            validate_capture(capture, "null")
        except RuntimeError as error:
            assert "nonzero capture" in str(error)
        else:
            raise AssertionError("null backend accepted nonzero capture")
    print("SELFTEST PASS")


def run_command(command):
    subprocess.run(command, check=True, timeout=30)


def sound_common(card):
    return [
        "-q",
        "-D",
        f"hw:{card},0",
        "-t",
        "raw",
        "-f",
        "S16_LE",
        "-r",
        str(RATE),
        "-c",
        "2",
    ]


def read_pid_file(path, label):
    try:
        value = open(path, encoding="ascii").read().strip()
    except OSError as error:
        raise RuntimeError(f"cannot read {path}: {error}") from error
    if not value.isdigit() or int(value) <= 1:
        raise RuntimeError(f"invalid {label} pid: {value!r}")
    return int(value)


def read_checkpoint_pid():
    return read_pid_file(CHECKPOINT_PID, "checkpoint playback")


def checkpoint_process_matches(pid, card):
    try:
        command = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
    except OSError:
        return False
    decoded = [os.fsdecode(argument) for argument in command if argument]
    return (
        bool(decoded)
        and os.path.basename(decoded[0]) == "aplay"
        and f"hw:{card},0" in decoded
        and decoded[-1] == CHECKPOINT_FIFO
    )


def stop_process(pid, label):
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    for _ in range(100):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    os.kill(pid, signal.SIGKILL)
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    raise RuntimeError(f"{label} pid {pid} did not exit")


def checkpoint_start(card):
    if os.path.exists(CHECKPOINT_PID):
        try:
            pid = read_checkpoint_pid()
        except RuntimeError:
            pid = -1
        if pid > 1 and checkpoint_process_matches(pid, card):
            raise RuntimeError(f"checkpoint playback already running as pid {pid}")
        os.unlink(CHECKPOINT_PID)
    for path in (CHECKPOINT_FEEDER_PID, CHECKPOINT_FIFO):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    os.mkfifo(CHECKPOINT_FIFO, 0o600)
    feeder_code = (
        "import os,time;"
        f"f=os.open({CHECKPOINT_FIFO!r},os.O_WRONLY);"
        "b=bytes(4096);"
        "exec('while True:\\n os.write(f,b)\\n time.sleep(0.05)')"
    )
    feeder = subprocess.Popen(
        [sys.executable, "-c", feeder_code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    with open(CHECKPOINT_FEEDER_PID, "w", encoding="ascii") as stream:
        stream.write(f"{feeder.pid}\n")
    with open(CHECKPOINT_LOG, "wb") as log:
        process = subprocess.Popen(
            ["aplay", *sound_common(card), CHECKPOINT_FIFO],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    with open(CHECKPOINT_PID, "w", encoding="ascii") as stream:
        stream.write(f"{process.pid}\n")
    for _ in range(50):
        if process.poll() is not None:
            stop_process(feeder.pid, "checkpoint feeder")
            raise RuntimeError(
                f"checkpoint playback exited with status {process.returncode}"
            )
        if feeder.poll() is not None:
            stop_process(process.pid, "checkpoint playback")
            raise RuntimeError(
                f"checkpoint feeder exited with status {feeder.returncode}"
            )
        if checkpoint_process_matches(process.pid, card):
            print(f"PASS sound-checkpoint-start pid={process.pid}")
            return
        time.sleep(0.1)
    stop_process(process.pid, "checkpoint playback")
    stop_process(feeder.pid, "checkpoint feeder")
    raise RuntimeError("checkpoint playback did not become observable")


def checkpoint_verify(card):
    pid = read_checkpoint_pid()
    feeder_pid = read_pid_file(CHECKPOINT_FEEDER_PID, "checkpoint feeder")
    if not checkpoint_process_matches(pid, card):
        raise RuntimeError(f"checkpoint playback pid {pid} is not running")
    try:
        os.kill(feeder_pid, 0)
    except ProcessLookupError as error:
        raise RuntimeError(
            f"checkpoint feeder pid {feeder_pid} is not running"
        ) from error
    print(f"PASS sound-checkpoint-active pid={pid} feeder={feeder_pid}")


def checkpoint_stop(card):
    pid = read_checkpoint_pid()
    feeder_pid = read_pid_file(CHECKPOINT_FEEDER_PID, "checkpoint feeder")
    if not checkpoint_process_matches(pid, card):
        raise RuntimeError(f"checkpoint playback pid {pid} is not running")
    stop_process(pid, "checkpoint playback")
    stop_process(feeder_pid, "checkpoint feeder")
    for path in (CHECKPOINT_PID, CHECKPOINT_FEEDER_PID, CHECKPOINT_FIFO):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    print(f"PASS sound-checkpoint-stop pid={pid}")


def require_device(expect_packed):
    pci, child = find_bound_sound()
    for bit, name in (
        (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
        (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
    ):
        if not negotiated_feature(child, bit):
            raise RuntimeError(f"virtio-sound did not negotiate {name}")
    packed = negotiated_feature(child, VIRTIO_F_RING_PACKED)
    if packed != expect_packed:
        raise RuntimeError(
            "virtio-sound packed negotiation mismatch: "
            f"expected={'yes' if expect_packed else 'no'} "
            f"actual={'yes' if packed else 'no'}"
        )
    return pci, child, packed


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    args = sys.argv[1:]
    operation = "exercise"
    if args and args[0].startswith("checkpoint-"):
        operation = args.pop(0)
    if not args or args.pop(0) != "modern":
        raise SystemExit(
            "usage: gsnd.py "
            "[checkpoint-start|checkpoint-verify|checkpoint-stop] "
            "modern [packed] [null|oss]"
        )
    expect_packed = False
    if args and args[0] == "packed":
        expect_packed = True
        args.pop(0)
    backend = args.pop(0) if args else "null"
    if args or backend not in ("null", "oss"):
        raise SystemExit(
            "usage: gsnd.py "
            "[checkpoint-start|checkpoint-verify|checkpoint-stop] "
            "modern [packed] [null|oss]"
        )
    pci, child, packed = require_device(expect_packed)
    card = find_card(child)
    if operation == "checkpoint-start":
        checkpoint_start(card)
        return
    if operation == "checkpoint-verify":
        checkpoint_verify(card)
        return
    if operation == "checkpoint-stop":
        checkpoint_stop(card)
        return
    with tempfile.TemporaryDirectory(prefix="virtio-snd-") as work:
        playback = work + "/playback.raw"
        capture = work + "/capture.raw"
        pattern = bytes((index * 29 + 7) & 0xFF for index in range(4096))
        with open(playback, "wb") as stream:
            remaining = PAYLOAD_BYTES
            while remaining:
                chunk = pattern[:remaining]
                stream.write(chunk)
                remaining -= len(chunk)
        common = sound_common(card)
        run_command(["aplay", *common, playback])
        run_command(["arecord", *common, "-d", "1", capture])
        validate_capture(capture, backend)
    print(
        f"PASS sound pci={os.path.basename(pci)} card={card} "
        f"playback_bytes={PAYLOAD_BYTES} capture_bytes={PAYLOAD_BYTES} "
        f"backend={backend} "
        f"packed={'yes' if packed else 'no'} "
        "notification_data=yes ring_reset=yes"
    )


if __name__ == "__main__":
    main()
