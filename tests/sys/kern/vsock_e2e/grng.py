#!/usr/bin/env python3
"""Linux guest end-to-end verifier for bhyve virtio-rng."""

import glob
import hashlib
import os
import sys


def find_bound_rng(expected_device):
    matches = []
    for pci in glob.glob("/sys/bus/pci/devices/*"):
        try:
            vendor = open(pci + "/vendor", encoding="ascii").read().strip()
            device = open(pci + "/device", encoding="ascii").read().strip()
        except OSError:
            continue
        if vendor != "0x1af4" or device != expected_device:
            continue
        children = []
        for child in glob.glob(pci + "/virtio*"):
            driver = child + "/driver"
            if os.path.islink(driver):
                children.append(os.path.basename(os.path.realpath(driver)))
        if "virtio_rng" in children:
            matches.append(pci)
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {expected_device} device bound to virtio_rng, "
            f"found {len(matches)}"
        )


def read_exact(fd, size):
    result = bytearray()
    while len(result) < size:
        chunk = os.read(fd, size - len(result))
        if not chunk:
            raise RuntimeError(f"unexpected /dev/hwrng EOF after {len(result)} bytes")
        result.extend(chunk)
    return result


def self_test():
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"abcdef")
    os.close(write_fd)
    try:
        assert read_exact(read_fd, 6) == b"abcdef"
    finally:
        os.close(read_fd)

    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"short")
    os.close(write_fd)
    try:
        try:
            read_exact(read_fd, 6)
        except RuntimeError:
            pass
        else:
            raise AssertionError("short RNG stream was accepted")
    finally:
        os.close(read_fd)
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) != 2 or sys.argv[1] not in ("modern", "legacy"):
        raise SystemExit("usage: grng.py modern|legacy")
    expected_device = "0x1044" if sys.argv[1] == "modern" else "0x1005"
    find_bound_rng(expected_device)
    current = open(
        "/sys/class/misc/hw_random/rng_current", encoding="ascii"
    ).read().strip()
    if not current.startswith("virtio_rng"):
        raise RuntimeError(f"virtio-rng is not the current hwrng: {current!r}")

    digest = hashlib.sha256()
    total = 0
    sizes = (1, 7, 31, 32, 255, 4095, 4096, 8193, 65536)
    fd = os.open("/dev/hwrng", os.O_RDONLY)
    try:
        for _ in range(8):
            for size in sizes:
                data = read_exact(fd, size)
                digest.update(data)
                total += len(data)
    finally:
        os.close(fd)
    print(f"PASS rng bytes={total} sha256={digest.hexdigest()}")


if __name__ == "__main__":
    main()
