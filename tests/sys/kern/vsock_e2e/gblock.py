#!/usr/bin/env python3
"""Linux guest verifier for a disposable bhyve virtio-blk device."""

import glob
import hashlib
import os
import sys
import tempfile


CHUNK_SIZE = 1024 * 1024


def find_bound_block(expected_device, sys_root="/sys", dev_root="/dev"):
    matches = []
    pattern = os.path.join(sys_root, "bus/pci/devices/*")
    for pci in glob.glob(pattern):
        try:
            vendor = open(pci + "/vendor", encoding="ascii").read().strip()
            device = open(pci + "/device", encoding="ascii").read().strip()
        except OSError:
            continue
        if vendor != "0x1af4" or device != expected_device:
            continue
        drivers = []
        blocks = []
        for child in glob.glob(pci + "/virtio*"):
            driver = child + "/driver"
            if os.path.islink(driver):
                drivers.append(os.path.basename(os.path.realpath(driver)))
            blocks.extend(glob.glob(child + "/block/*"))
        if drivers != ["virtio_blk"]:
            continue
        if len(blocks) != 1:
            continue
        matches.append(os.path.join(dev_root, os.path.basename(blocks[0])))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {expected_device} device bound to virtio_blk, "
            f"found {len(matches)}"
        )
    return matches[0]


def pattern_chunk(counter, size):
    seed = hashlib.sha256(f"bhyve-block-{counter}".encode()).digest()
    return (seed * ((size + len(seed) - 1) // len(seed)))[:size]


def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise RuntimeError("short block-device write")
        view = view[written:]


def write_pattern(path, size):
    digest = hashlib.sha256()
    fd = os.open(path, os.O_WRONLY)
    try:
        offset = 0
        counter = 0
        while offset < size:
            length = min(CHUNK_SIZE, size - offset)
            data = pattern_chunk(counter, length)
            write_all(fd, data)
            digest.update(data)
            offset += length
            counter += 1
        os.fsync(fd)
    finally:
        os.close(fd)
    return digest.hexdigest()


def read_digest(path, size):
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY)
    try:
        remaining = size
        while remaining:
            data = os.read(fd, min(CHUNK_SIZE, remaining))
            if not data:
                raise RuntimeError(
                    f"unexpected block-device EOF with {remaining} bytes remaining"
                )
            digest.update(data)
            remaining -= len(data)
    finally:
        os.close(fd)
    return digest.hexdigest()


def expected_device(transport):
    if transport == "modern":
        return "0x1042"
    if transport == "legacy":
        return "0x1001"
    raise RuntimeError(f"invalid transport: {transport}")


def self_test():
    with tempfile.TemporaryDirectory() as root:
        pci = root + "/sys/bus/pci/devices/0000:00:08.0"
        child = pci + "/virtio4"
        block = child + "/block/vdz"
        driver = root + "/sys/bus/virtio/drivers/virtio_blk"
        os.makedirs(block)
        os.makedirs(driver)
        with open(pci + "/vendor", "w", encoding="ascii") as stream:
            stream.write("0x1af4\n")
        with open(pci + "/device", "w", encoding="ascii") as stream:
            stream.write("0x1001\n")
        os.symlink(driver, child + "/driver")
        found = find_bound_block("0x1001", root + "/sys", root + "/dev")
        if found != root + "/dev/vdz":
            raise AssertionError(f"wrong block path: {found}")

        backing = root + "/backing"
        with open(backing, "wb") as stream:
            stream.truncate(2 * CHUNK_SIZE)
        wanted = write_pattern(backing, CHUNK_SIZE + 17)
        if read_digest(backing, CHUNK_SIZE + 17) != wanted:
            raise AssertionError("block pattern did not round-trip")
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) not in (4, 5):
        raise SystemExit(
            "usage: gblock.py --self-test | "
            "write transport bytes | verify transport bytes sha256"
        )
    command, transport, size_text = sys.argv[1:4]
    size = int(size_text)
    if size <= 0:
        raise RuntimeError("byte count must be positive")
    device = find_bound_block(expected_device(transport))
    if command == "write" and len(sys.argv) == 4:
        wanted = write_pattern(device, size)
        actual = read_digest(device, size)
        if actual != wanted:
            raise RuntimeError(f"block checksum mismatch: {actual} != {wanted}")
        print(f"PASS block bytes={size} sha256={actual} device={device}")
    elif command == "verify" and len(sys.argv) == 5:
        wanted = sys.argv[4]
        actual = read_digest(device, size)
        if actual != wanted:
            raise RuntimeError(f"block checksum mismatch: {actual} != {wanted}")
        print(f"PASS block-persist bytes={size} sha256={actual} device={device}")
    else:
        raise SystemExit("invalid gblock.py command or argument count")


if __name__ == "__main__":
    main()
