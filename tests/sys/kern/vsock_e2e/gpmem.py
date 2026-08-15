#!/usr/bin/env python3
"""Linux guest activation verifier for bhyve virtio-pmem.

Constants in this file are independent VirtIO 1.4 CS01 fixtures.  The helper
requires the real Linux virtio-pmem/libnvdimm path and performs an fsync-backed
write that the host harness verifies in the backing file.
"""

import glob
import hashlib
import os
import sys
import tempfile

# VirtIO 1.4 sections 5.19 and 6.
VIRTIO_PMEM_PCI_DEVICE = "0x105b"
VIRTIO_PMEM_F_SHMEM_REGION = 0
VIRTIO_F_RING_PACKED = 34
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40
MARKER_OFFSET = 2 * 1024 * 1024
MARKER_SIZE = 4096


def read_ascii(path):
    with open(path, encoding="ascii") as stream:
        return stream.read().strip()


def negotiated_feature(child, bit):
    features = read_ascii(os.path.join(child, "features"))
    if len(features) <= bit or any(value not in "01" for value in features):
        raise RuntimeError(f"invalid virtio feature bitmap: {features!r}")
    return features[bit] == "1"


def marker(label):
    seed = ("WASPNEST-VIRTIO-PMEM:" + label).encode("ascii")
    if not label or len(seed) > 512:
        raise ValueError("invalid marker label")
    output = bytearray()
    counter = 0
    while len(output) < MARKER_SIZE:
        output.extend(hashlib.sha256(seed + counter.to_bytes(8, "little")).digest())
        counter += 1
    return bytes(output[:MARKER_SIZE])


def find_bound_device(sys_root="/sys"):
    matches = []
    for pci in glob.glob(os.path.join(sys_root, "bus/pci/devices/*")):
        try:
            vendor = read_ascii(os.path.join(pci, "vendor"))
            device = read_ascii(os.path.join(pci, "device"))
        except OSError:
            continue
        if vendor != "0x1af4" or device != VIRTIO_PMEM_PCI_DEVICE:
            continue
        for child in glob.glob(os.path.join(pci, "virtio*")):
            driver = os.path.join(child, "driver")
            if os.path.islink(driver) and os.path.basename(
                os.path.realpath(driver)
            ) == "virtio_pmem":
                matches.append((pci, child))
    if len(matches) != 1:
        raise RuntimeError(
            "expected one PCI 0x105b device bound to virtio_pmem, "
            f"found {len(matches)}"
        )
    return matches[0]


def find_pmem_block(child, sys_root="/sys", dev_root="/dev"):
    child_real = os.path.realpath(child)
    matches = []
    for class_path in glob.glob(os.path.join(sys_root, "class/block/pmem*")):
        if os.path.realpath(class_path).startswith(child_real + os.sep):
            device = os.path.join(dev_root, os.path.basename(class_path))
            if os.path.exists(device):
                matches.append(device)
    if len(matches) != 1:
        raise RuntimeError(
            "expected one libnvdimm pmem block device below virtio-pmem, "
            f"found {len(matches)}"
        )
    return matches[0]


def write_marker(device, label):
    data = marker(label)
    fd = os.open(device, os.O_RDWR | os.O_SYNC)
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
        if size < MARKER_OFFSET + len(data):
            raise RuntimeError(f"pmem device is too small: {size}")
        written = os.pwrite(fd, data, MARKER_OFFSET)
        if written != len(data):
            raise RuntimeError(f"short pmem write: {written}/{len(data)}")
        os.fsync(fd)
        actual = os.pread(fd, len(data), MARKER_OFFSET)
    finally:
        os.close(fd)
    if actual != data:
        raise RuntimeError("pmem read-after-flush mismatch")
    return hashlib.sha256(data).hexdigest()


def self_test():
    assert len(marker("split")) == MARKER_SIZE
    assert marker("split") == marker("split")
    assert marker("split") != marker("packed")
    with tempfile.TemporaryDirectory() as root:
        child = os.path.join(root, "virtio0")
        os.mkdir(child)
        features = ["0"] * 64
        features[VIRTIO_PMEM_F_SHMEM_REGION] = "1"
        features[VIRTIO_F_NOTIFICATION_DATA] = "1"
        features[VIRTIO_F_RING_RESET] = "1"
        with open(os.path.join(child, "features"), "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        assert negotiated_feature(child, VIRTIO_PMEM_F_SHMEM_REGION)
        assert negotiated_feature(child, VIRTIO_F_NOTIFICATION_DATA)
        assert negotiated_feature(child, VIRTIO_F_RING_RESET)
        assert not negotiated_feature(child, VIRTIO_F_RING_PACKED)
        backing = os.path.join(root, "pmem")
        with open(backing, "wb") as stream:
            stream.truncate(MARKER_OFFSET + MARKER_SIZE)
        digest = write_marker(backing, "self-test")
        assert digest == hashlib.sha256(marker("self-test")).hexdigest()
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "packed"):
        raise SystemExit("usage: gpmem.py LABEL [packed]")
    label = sys.argv[1]
    expect_packed = len(sys.argv) == 3
    _, child = find_bound_device()
    required = (
        (VIRTIO_PMEM_F_SHMEM_REGION, "VIRTIO_PMEM_F_SHMEM_REGION"),
        (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
        (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
    )
    for bit, name in required:
        if not negotiated_feature(child, bit):
            raise RuntimeError(f"virtio-pmem did not negotiate {name}")
    packed = negotiated_feature(child, VIRTIO_F_RING_PACKED)
    if packed != expect_packed:
        raise RuntimeError(
            "virtio-pmem packed negotiation mismatch: "
            f"expected={'yes' if expect_packed else 'no'} "
            f"actual={'yes' if packed else 'no'}"
        )
    device = find_pmem_block(child)
    digest = write_marker(device, label)
    print(
        f"PASS pmem device={device} offset={MARKER_OFFSET} bytes={MARKER_SIZE} "
        f"sha256={digest} packed={'yes' if packed else 'no'} "
        "notification_data=yes ring_reset=yes"
    )


if __name__ == "__main__":
    main()
