#!/usr/bin/env python3
"""Linux guest verifier for a disposable bhyve virtio-scsi LUN."""

import glob
import hashlib
import mmap
import os
import sys
import tempfile


CHUNK_SIZE = 1024 * 1024
DIRECT_ALIGNMENT = 4096


def find_bound_scsi(
    expected_device, expected_size, sys_root="/sys", dev_root="/dev"
):
    if expected_size <= 0 or expected_size % 512 != 0:
        raise RuntimeError("SCSI capacity must be a positive multiple of 512")
    matches = []
    for pci in glob.glob(os.path.join(sys_root, "bus/pci/devices/*")):
        try:
            vendor = open(pci + "/vendor", encoding="ascii").read().strip()
            device = open(pci + "/device", encoding="ascii").read().strip()
        except OSError:
            continue
        if vendor != "0x1af4" or device != expected_device:
            continue
        for child in glob.glob(pci + "/virtio*"):
            driver = child + "/driver"
            if not os.path.islink(driver) or os.path.basename(
                os.path.realpath(driver)
            ) != "virtio_scsi":
                continue
            child_path = os.path.realpath(child)
            for block in glob.glob(os.path.join(sys_root, "class/block/*")):
                block_device = block + "/device"
                if not os.path.islink(block_device):
                    continue
                device_path = os.path.realpath(block_device)
                if os.path.commonpath((child_path, device_path)) != child_path:
                    continue
                try:
                    sectors = int(
                        open(block + "/size", encoding="ascii").read().strip()
                    )
                except (OSError, ValueError):
                    continue
                if sectors * 512 == expected_size:
                    matches.append(
                        os.path.join(dev_root, os.path.basename(block))
                    )
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {expected_device} virtio_scsi LUN with "
            f"capacity {expected_size}, found {len(matches)}"
        )
    return matches[0]


def pattern_chunk(counter, size):
    seed = hashlib.sha256(f"bhyve-scsi-{counter}".encode()).digest()
    return (seed * ((size + len(seed) - 1) // len(seed)))[:size]


def write_all(fd, view):
    offset = 0
    while offset < len(view):
        written = os.writev(fd, [view[offset:]])
        if written <= 0:
            raise RuntimeError("short SCSI write")
        offset += written


def write_pattern(path, size, direct=False):
    digest = hashlib.sha256()
    flags = os.O_WRONLY
    if direct:
        flags |= os.O_DIRECT
    fd = os.open(path, flags)
    buffer = mmap.mmap(-1, CHUNK_SIZE)
    view = memoryview(buffer)
    try:
        offset = 0
        counter = 0
        while offset < size:
            length = min(CHUNK_SIZE, size - offset)
            data = pattern_chunk(counter, length)
            view[:length] = data
            write_all(fd, view[:length])
            digest.update(data)
            offset += length
            counter += 1
        os.fsync(fd)
    finally:
        view.release()
        buffer.close()
        os.close(fd)
    return digest.hexdigest()


def read_digest(path, size, direct=False):
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if direct:
        flags |= os.O_DIRECT
    fd = os.open(path, flags)
    buffer = mmap.mmap(-1, CHUNK_SIZE)
    view = memoryview(buffer)
    try:
        remaining = size
        while remaining:
            wanted = min(CHUNK_SIZE, remaining)
            received = os.readv(fd, [view[:wanted]])
            if received <= 0:
                raise RuntimeError(
                    f"unexpected SCSI EOF with {remaining} bytes remaining"
                )
            digest.update(view[:received])
            remaining -= received
    finally:
        view.release()
        buffer.close()
        os.close(fd)
    return digest.hexdigest()


def expected_pci_device(transport):
    if transport == "modern":
        return "0x1048"
    if transport == "legacy":
        return "0x1004"
    raise RuntimeError(f"invalid transport: {transport}")


def self_test():
    with tempfile.TemporaryDirectory() as root:
        sys_root = root + "/sys"
        pci = sys_root + "/bus/pci/devices/0000:00:09.0"
        child = pci + "/virtio5"
        scsi_device = child + "/host0/target0:0:0/0:0:0:0"
        block = sys_root + "/class/block/vdz"
        driver = sys_root + "/bus/virtio/drivers/virtio_scsi"
        os.makedirs(scsi_device)
        os.makedirs(block)
        os.makedirs(driver)
        with open(pci + "/vendor", "w", encoding="ascii") as stream:
            stream.write("0x1af4\n")
        with open(pci + "/device", "w", encoding="ascii") as stream:
            stream.write("0x1048\n")
        with open(block + "/size", "w", encoding="ascii") as stream:
            stream.write("4096\n")
        os.symlink(driver, child + "/driver")
        os.symlink(scsi_device, block + "/device")
        found = find_bound_scsi("0x1048", 2 * CHUNK_SIZE, sys_root, root)
        if found != root + "/vdz":
            raise AssertionError(f"wrong SCSI path: {found}")
        try:
            find_bound_scsi("0x1048", CHUNK_SIZE, sys_root, root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted the wrong SCSI capacity")

        backing = root + "/backing"
        with open(backing, "wb") as stream:
            stream.truncate(2 * CHUNK_SIZE)
        wanted = write_pattern(backing, CHUNK_SIZE + 17)
        if read_digest(backing, CHUNK_SIZE + 17) != wanted:
            raise AssertionError("SCSI pattern did not round-trip")
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) not in (5, 6):
        raise SystemExit(
            "usage: gscsi.py --self-test | write transport capacity bytes | "
            "verify transport capacity bytes sha256"
        )
    command, transport, capacity_text, size_text = sys.argv[1:5]
    capacity = int(capacity_text)
    size = int(size_text)
    if size <= 0 or size > capacity:
        raise RuntimeError("require 0 < byte count <= SCSI capacity")
    if size % DIRECT_ALIGNMENT != 0:
        raise RuntimeError(
            f"SCSI direct-I/O byte count must be a multiple of "
            f"{DIRECT_ALIGNMENT}"
        )
    device = find_bound_scsi(expected_pci_device(transport), capacity)
    if command == "write" and len(sys.argv) == 5:
        wanted = write_pattern(device, size, direct=True)
        actual = read_digest(device, size, direct=True)
        if actual != wanted:
            raise RuntimeError(f"SCSI checksum mismatch: {actual} != {wanted}")
        print(f"PASS scsi bytes={size} sha256={actual} device={device}")
    elif command == "verify" and len(sys.argv) == 6:
        wanted = sys.argv[5]
        actual = read_digest(device, size, direct=True)
        if actual != wanted:
            raise RuntimeError(f"SCSI checksum mismatch: {actual} != {wanted}")
        print(f"PASS scsi-persist bytes={size} sha256={actual} device={device}")
    else:
        raise SystemExit("invalid gscsi.py command or argument count")


if __name__ == "__main__":
    main()
