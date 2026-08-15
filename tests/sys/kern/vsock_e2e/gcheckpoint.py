#!/usr/bin/env python3
"""Active Linux guest workloads for bhyve checkpoint qualification."""

# VIRTIO_ACTIVATION_ASSERTION: active-checkpoint-network-traffic
# VIRTIO_ACTIVATION_ASSERTION: active-checkpoint-rng-io
# VIRTIO_ACTIVATION_ASSERTION: active-checkpoint-block-io
# VIRTIO_ACTIVATION_ASSERTION: active-checkpoint-scsi-io
# VIRTIO_ACTIVATION_ASSERTION: active-checkpoint-pmem-io

import glob
import hashlib
import errno
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

RUNNING = True
CHUNK = 64 * 1024
PMEM_MARKER_OFFSET = 3 * 1024 * 1024
PMEM_MARKER_SIZE = 4096


def stop(_signum, _frame):
    global RUNNING
    RUNNING = False


def default_gateway():
    with open("/proc/net/route", encoding="ascii") as routes:
        next(routes)
        for line in routes:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "00000000":
                flags = int(fields[3], 16)
                if flags & 0x2:
                    return socket.inet_ntoa(
                        struct.pack("<I", int(fields[2], 16))
                    )
    raise RuntimeError("no usable default gateway")


def virtio_block(prefix):
    matches = []
    for path in glob.glob(f"/sys/block/{prefix}*"):
        device = os.path.realpath(path + "/device")
        if "/virtio" in device:
            matches.append("/dev/" + os.path.basename(path))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one virtio {prefix!r} block device, found {matches}"
        )
    return matches[0]


def atomic_count(path, count):
    temporary = path + ".new"
    with open(temporary, "w", encoding="ascii") as stream:
        stream.write(f"{count}\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def ping_gateway(gateway):
    """Complete one bounded guest-to-host-to-guest network round trip."""
    # A successful UDP send only proves that the guest accepted a packet for
    # local transmission; it says nothing about the device's receive path or
    # whether the packet reached the host.  The test environment already
    # requires a reachable default gateway, so use a bounded ICMP round trip
    # as the active network checkpoint workload.  Count only completed round
    # trips, which proves forward progress through both VirtIO directions
    # before and after a checkpoint.
    subprocess.run(
        ["ping", "-n", "-c", "1", "-W", "1", gateway],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=3,
    )


def run_network(count_path):
    gateway = default_gateway()
    count = 0
    while RUNNING:
        ping_gateway(gateway)
        if not RUNNING:
            break
        count += 1
        atomic_count(count_path, count)


def run_reader(count_path, path):
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
        if size < CHUNK:
            raise RuntimeError(f"{path} is too small for checkpoint workload")
        slots = size // CHUNK
        count = 0
        while RUNNING:
            offset = (count % slots) * CHUNK
            data = os.pread(fd, CHUNK, offset)
            if len(data) != CHUNK:
                raise RuntimeError(f"short checkpoint read from {path}")
            count += 1
            atomic_count(count_path, count)
            time.sleep(0.001)
    finally:
        os.close(fd)


def run_rng(count_path):
    # A checkpoint may pause the device while this worker is being stopped.
    # Do not strand the guest-side cleanup behind a blocking hwrng read: wait
    # for input with a finite timeout so SIGTERM is observed promptly.  The
    # nonblocking flag is also important for drivers whose poll readiness can
    # change between poll() and read().
    fd = os.open("/dev/hwrng", os.O_RDONLY | os.O_NONBLOCK)
    try:
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLERR | select.POLLHUP)
        count = 0
        while RUNNING:
            events = poller.poll(250)
            if not RUNNING:
                break
            if not events:
                continue
            event_mask = events[0][1]
            if event_mask & (select.POLLERR | select.POLLHUP):
                raise RuntimeError("virtio-rng became unavailable")
            try:
                data = os.read(fd, 4096)
            except BlockingIOError:
                continue
            except OSError as error:
                if error.errno == errno.EAGAIN:
                    continue
                raise
            if not data:
                raise RuntimeError("virtio-rng returned EOF")
            count += 1
            atomic_count(count_path, count)
            time.sleep(0.001)
    finally:
        os.close(fd)


def pmem_marker(count):
    seed = b"WASPNEST-PMEM-CHECKPOINT:" + count.to_bytes(8, "little")
    output = bytearray()
    block = 0
    while len(output) < PMEM_MARKER_SIZE:
        output.extend(
            hashlib.sha256(seed + block.to_bytes(8, "little")).digest()
        )
        block += 1
    return bytes(output[:PMEM_MARKER_SIZE])


def run_pmem(count_path):
    path = virtio_block("pmem")
    fd = os.open(path, os.O_RDWR | os.O_SYNC)
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
        if size < PMEM_MARKER_OFFSET + PMEM_MARKER_SIZE:
            raise RuntimeError(f"{path} is too small for checkpoint workload")
        count = 0
        while RUNNING:
            data = pmem_marker(count)
            written = os.pwrite(fd, data, PMEM_MARKER_OFFSET)
            if written != len(data):
                raise RuntimeError(f"short checkpoint write to {path}")
            os.fsync(fd)
            if os.pread(fd, len(data), PMEM_MARKER_OFFSET) != data:
                raise RuntimeError("pmem checkpoint read-after-flush mismatch")
            count += 1
            atomic_count(count_path, count)
            time.sleep(0.005)
    finally:
        os.close(fd)


def self_test():
    with tempfile.TemporaryDirectory() as root:
        count = root + "/count"
        atomic_count(count, 7)
        with open(count, encoding="ascii") as stream:
            assert stream.read() == "7\n"
        assert len(pmem_marker(0)) == PMEM_MARKER_SIZE
        assert pmem_marker(0) == pmem_marker(0)
        assert pmem_marker(0) != pmem_marker(1)
        route = root + "/route"
        with open(route, "w", encoding="ascii") as stream:
            stream.write(
                "Iface Destination Gateway Flags RefCnt Use Metric Mask\n"
            )
            stream.write(
                "eth0 00000000 0132A8C0 0003 0 0 0 00000000 0 0 0\n"
            )
        original = open

        def redirected(path, *args, **kwargs):
            if path == "/proc/net/route":
                path = route
            return original(path, *args, **kwargs)

        import builtins

        builtins.open = redirected
        try:
            assert default_gateway() == "192.168.50.1"
        finally:
            builtins.open = original
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK)
        try:
            poller = select.poll()
            poller.register(read_fd, select.POLLIN)
            assert poller.poll(0) == []
            assert os.write(write_fd, b"x") == 1
            assert poller.poll(0)[0][0] == read_fd
            assert os.read(read_fd, 1) == b"x"
        finally:
            os.close(read_fd)
            os.close(write_fd)

        calls = []

        def fake_run(arguments, **kwargs):
            calls.append((arguments, kwargs))

        saved_run = subprocess.run
        subprocess.run = fake_run
        try:
            # Exercise the command construction without entering the active
            # loop; live qualification proves its actual network behavior.
            ping_gateway("192.168.50.1")
        finally:
            subprocess.run = saved_run
        assert calls == [
            (
                ["ping", "-n", "-c", "1", "-W", "1", "192.168.50.1"],
                {
                    "check": True,
                    "stdin": subprocess.DEVNULL,
                    "stdout": subprocess.DEVNULL,
                    "stderr": subprocess.DEVNULL,
                    "timeout": 3,
                },
            )
        ]
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) != 3 or sys.argv[1] not in (
        "net",
        "rng",
        "block",
        "scsi",
        "pmem",
    ):
        raise SystemExit(
            "usage: gcheckpoint.py net|rng|block|scsi|pmem count-file"
        )
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    kind, count_path = sys.argv[1:]
    for stale in (count_path, count_path + ".new"):
        try:
            os.unlink(stale)
        except FileNotFoundError:
            pass
    if kind == "net":
        run_network(count_path)
    elif kind == "rng":
        run_rng(count_path)
    elif kind == "block":
        run_reader(count_path, virtio_block("vd"))
    elif kind == "scsi":
        run_reader(count_path, virtio_block("sd"))
    else:
        run_pmem(count_path)


if __name__ == "__main__":
    main()
