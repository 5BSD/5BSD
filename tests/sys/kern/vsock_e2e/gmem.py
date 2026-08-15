#!/usr/bin/env python3
"""Live Linux qualification for the VirtIO 1.4 memory device."""

import hashlib
import ctypes
import mmap
import os
import signal
import struct
import sys
import time
from pathlib import Path

PCI_VENDOR = 0x1AF4
PCI_DEVICE = 0x1058
PCI_CAP_ID_VNDR = 0x09
VIRTIO_PCI_CAP_DEVICE_CFG = 4
CONFIG_SIZE = 56
VIRTIO_RING_F_INDIRECT_DESC = 28
VIRTIO_RING_F_EVENT_IDX = 29
VIRTIO_F_RING_PACKED = 34
VIRTIO_F_IN_ORDER = 35
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40
REQUIRED_FEATURES = (
    (VIRTIO_RING_F_INDIRECT_DESC, "VIRTIO_RING_F_INDIRECT_DESC"),
    (VIRTIO_RING_F_EVENT_IDX, "VIRTIO_RING_F_EVENT_IDX"),
    (VIRTIO_F_IN_ORDER, "VIRTIO_F_IN_ORDER"),
    (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
    (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
)
RUNNING = True
PAGEMAP_PRESENT = 1 << 63
PAGEMAP_PFN_MASK = (1 << 55) - 1
CHECKPOINT_PAGES = 8


def stop(_signum, _frame):
    global RUNNING
    RUNNING = False


def atomic_count(path, count):
    temporary = path + ".new"
    with open(temporary, "w", encoding="ascii") as stream:
        stream.write(f"{count}\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def pagemap_pfn(entry):
    if entry & PAGEMAP_PRESENT == 0:
        return None
    return entry & PAGEMAP_PFN_MASK


def read_pagemap_pfn(pagemap, address):
    page = mmap.PAGESIZE
    raw = os.pread(pagemap, 8, (address // page) * 8)
    if len(raw) != 8:
        raise RuntimeError("short /proc/self/pagemap read")
    return pagemap_pfn(struct.unpack("<Q", raw)[0])


def read_hex(path):
    return int(Path(path).read_text().strip(), 0)


def find_pci():
    for path in sorted(Path("/sys/bus/pci/devices").glob("*")):
        if read_hex(path / "vendor") == PCI_VENDOR and read_hex(
            path / "device"
        ) == PCI_DEVICE:
            return path
    raise RuntimeError("virtio-mem PCI device 1af4:1058 not found")


def device_config_capability(pci):
    raw = (pci / "config").read_bytes()
    if len(raw) < 0x40:
        raise RuntimeError("short PCI configuration space")
    cap = raw[0x34]
    seen = set()
    while cap:
        if cap in seen or cap + 16 > len(raw) or cap < 0x40:
            raise RuntimeError("malformed PCI capability chain")
        seen.add(cap)
        cap_id, nxt = raw[cap], raw[cap + 1]
        if cap_id == PCI_CAP_ID_VNDR and raw[cap + 2] >= 16:
            cfg_type = raw[cap + 3]
            bar = raw[cap + 4]
            offset, length = struct.unpack_from("<II", raw, cap + 8)
            if cfg_type == VIRTIO_PCI_CAP_DEVICE_CFG:
                if bar > 5 or length != CONFIG_SIZE:
                    raise RuntimeError("invalid virtio-mem device capability")
                return bar, offset, length
        cap = nxt
    raise RuntimeError("virtio device configuration capability not found")


def read_device_config(pci):
    bar, offset, length = device_config_capability(pci)
    page = mmap.PAGESIZE
    base = offset & ~(page - 1)
    delta = offset - base
    with open(pci / f"resource{bar}", "rb", buffering=0) as resource:
        mapping = mmap.mmap(
            resource.fileno(),
            delta + length,
            flags=mmap.MAP_SHARED,
            prot=mmap.PROT_READ,
            offset=base,
        )
        try:
            data = mapping[delta : delta + length]
        finally:
            mapping.close()
    if len(data) != CONFIG_SIZE:
        raise RuntimeError("short virtio-mem device configuration")
    block_size = struct.unpack_from("<Q", data, 0)[0]
    node_id = struct.unpack_from("<H", data, 8)[0]
    reserved = data[10:16]
    address, region, usable, plugged, requested = struct.unpack_from(
        "<QQQQQ", data, 16
    )
    return {
        "block_size": block_size,
        "node_id": node_id,
        "reserved": reserved,
        "address": address,
        "region": region,
        "usable": usable,
        "plugged": plugged,
        "requested": requested,
    }


def find_virtio_child(pci):
    children = sorted(pci.glob("virtio*"))
    if len(children) != 1:
        raise RuntimeError(f"expected one virtio child, found {len(children)}")
    child = children[0]
    if read_hex(child / "device") != 24:
        raise RuntimeError("virtio child has the wrong device ID")
    driver = child / "driver"
    if not driver.is_symlink() or driver.resolve().name != "virtio_mem":
        raise RuntimeError("Linux virtio_mem driver is not bound")
    return child


def negotiated_feature(child, bit):
    features = (child / "features").read_text().strip()
    if len(features) <= bit or any(value not in "01" for value in features):
        raise RuntimeError(f"invalid virtio feature bitmap: {features!r}")
    return features[bit] == "1"


def online_blocks(config):
    block_bytes = read_hex("/sys/devices/system/memory/block_size_bytes")
    start = config["address"]
    end = start + config["usable"]
    blocks = []
    for path in sorted(Path("/sys/devices/system/memory").glob("memory[0-9]*")):
        index = read_hex(path / "phys_index")
        address = index * block_bytes
        if start <= address < end:
            state = (path / "state").read_text().strip()
            if not state.startswith("online"):
                raise RuntimeError(f"{path.name} is not online: {state}")
            blocks.append(path.name)
    return blocks


def memory_workload():
    size = 32 * 1024 * 1024
    data = bytearray(size)
    for offset in range(0, size, 4096):
        data[offset] = (offset // 4096) & 0xFF
    digest = hashlib.sha256(data).hexdigest()
    if digest != hashlib.sha256(bytes(data)).hexdigest():
        raise RuntimeError("anonymous-memory workload mismatch")
    return digest


def find_and_pin_device_pages(config, allocation_mb):
    page = mmap.PAGESIZE
    if allocation_mb <= 0:
        raise RuntimeError("checkpoint allocation must be positive")
    allocation = allocation_mb * 1024 * 1024
    chunk_size = 32 * 1024 * 1024
    mappings = []
    selected = []
    libc = ctypes.CDLL(None, use_errno=True)
    pagemap = os.open("/proc/self/pagemap", os.O_RDONLY)
    try:
        allocated = 0
        while allocated < allocation and len(selected) < CHECKPOINT_PAGES:
            length = min(chunk_size, allocation - allocated)
            mapping = mmap.mmap(
                -1,
                length,
                flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
            mappings.append(mapping)
            base = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
            for offset in range(0, length, page):
                mapping[offset] = (allocated // page + offset // page) & 0xFF
            for offset in range(0, length, page):
                pfn = read_pagemap_pfn(pagemap, base + offset)
                if pfn is None:
                    continue
                physical = pfn * page
                if not (
                    config["address"]
                    <= physical
                    < config["address"] + config["usable"]
                ):
                    continue
                marker = hashlib.sha256(
                    f"virtio-mem-checkpoint:{physical:#x}".encode("ascii")
                ).digest()
                mapping[offset : offset + len(marker)] = marker
                if libc.mlock(
                    ctypes.c_void_p(base + offset), ctypes.c_size_t(page)
                ) != 0:
                    error = ctypes.get_errno()
                    raise OSError(error, os.strerror(error))
                selected.append((mapping, base, offset, marker, physical))
                if len(selected) == CHECKPOINT_PAGES:
                    break
            allocated += length
    finally:
        os.close(pagemap)
    if len(selected) != CHECKPOINT_PAGES:
        for mapping in mappings:
            mapping.close()
        raise RuntimeError(
            "could not allocate and pin enough pages from the "
            f"virtio-mem region: found={len(selected)} "
            f"required={CHECKPOINT_PAGES} allocation={allocation_mb}MiB"
        )
    return mappings, selected


def checkpoint_workload(count_path, expected, allocation_mb, expect_packed):
    pci = find_pci()
    child = find_virtio_child(pci)
    packed = negotiated_feature(child, VIRTIO_F_RING_PACKED)
    if packed != expect_packed:
        raise RuntimeError(
            "virtio-mem packed negotiation mismatch: "
            f"expected={expect_packed} actual={packed}"
        )
    config = read_device_config(pci)
    if config["plugged"] != expected or config["requested"] != expected:
        raise RuntimeError(
            "virtio-mem is not at the requested checkpoint size: "
            f"{config}"
        )
    mappings, selected = find_and_pin_device_pages(config, allocation_mb)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    count = 0
    pagemap = os.open("/proc/self/pagemap", os.O_RDONLY)
    try:
        while RUNNING:
            current = read_device_config(pci)
            if (
                current["address"] != config["address"]
                or current["region"] != config["region"]
                or current["usable"] != config["usable"]
                or current["plugged"] != expected
                or current["requested"] != expected
            ):
                raise RuntimeError(
                    "virtio-mem configuration changed during checkpoint "
                    f"workload: before={config} after={current}"
                )
            for mapping, _base, offset, marker, physical in selected:
                actual = mapping[offset : offset + len(marker)]
                if actual != marker:
                    raise RuntimeError(
                        "virtio-mem page marker changed at "
                        f"physical address {physical:#x}"
                    )
                current_pfn = read_pagemap_pfn(
                    pagemap, _base + offset
                )
                if current_pfn is None or current_pfn * mmap.PAGESIZE != physical:
                    raise RuntimeError(
                        "virtio-mem page mapping changed: "
                        f"expected={physical:#x} "
                        f"actual={current_pfn!r}"
                    )
            count += 1
            atomic_count(count_path, count)
            time.sleep(0.05)
    finally:
        os.close(pagemap)
        libc = ctypes.CDLL(None, use_errno=True)
        page = mmap.PAGESIZE
        for _mapping, base, offset, _marker, _physical in selected:
            libc.munlock(
                ctypes.c_void_p(base + offset), ctypes.c_size_t(page)
            )
        for mapping in mappings:
            mapping.close()


def self_test():
    sample = bytearray(CONFIG_SIZE)
    struct.pack_into("<Q", sample, 0, 2 << 20)
    struct.pack_into("<QQQQQ", sample, 16, 1 << 40, 256 << 20,
                     256 << 20, 128 << 20, 128 << 20)
    values = struct.unpack_from("<QQQQQ", sample, 16)
    if values != (1 << 40, 256 << 20, 256 << 20, 128 << 20, 128 << 20):
        raise RuntimeError("SELFTEST config decoding")
    if pagemap_pfn(0) is not None:
        raise RuntimeError("SELFTEST absent pagemap entry")
    if pagemap_pfn(PAGEMAP_PRESENT | 0x12345) != 0x12345:
        raise RuntimeError("SELFTEST present pagemap entry")
    print("SELFTEST PASS")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return
    if len(sys.argv) in (5, 6) and sys.argv[1] == "checkpoint":
        if len(sys.argv) == 6 and sys.argv[5] != "packed":
            raise SystemExit(
                "usage: gmem.py checkpoint COUNT_FILE "
                "EXPECTED_REQUESTED_BYTES ALLOCATION_MB [packed]"
            )
        checkpoint_workload(
            sys.argv[2],
            int(sys.argv[3], 0),
            int(sys.argv[4], 0),
            len(sys.argv) == 6,
        )
        return
    if len(sys.argv) not in (2, 3) or (
        len(sys.argv) == 3 and sys.argv[2] != "packed"
    ):
        raise SystemExit("usage: gmem.py EXPECTED_REQUESTED_BYTES [packed]")
    expected = int(sys.argv[1], 0)
    expect_packed = len(sys.argv) == 3
    pci = find_pci()
    child = find_virtio_child(pci)
    for bit, name in REQUIRED_FEATURES:
        if not negotiated_feature(child, bit):
            raise RuntimeError(f"virtio-mem did not negotiate {name}")
    packed = negotiated_feature(child, VIRTIO_F_RING_PACKED)
    if packed != expect_packed:
        raise RuntimeError(
            "virtio-mem packed negotiation mismatch: "
            f"expected={expect_packed} actual={packed}"
        )
    deadline = time.monotonic() + 90
    while True:
        config = read_device_config(pci)
        if config["plugged"] == expected:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"plugged size {config['plugged']} did not reach {expected}"
            )
        time.sleep(0.25)
    if (
        config["requested"] != expected
        or config["plugged"] != expected
        or config["requested"] > config["usable"]
        or config["usable"] > config["region"]
        or config["block_size"] == 0
        or config["address"] % config["block_size"]
        or config["region"] % config["block_size"]
        or config["node_id"] != 0
        or any(config["reserved"])
    ):
        raise RuntimeError(f"invalid virtio-mem configuration: {config}")
    blocks = online_blocks(config)
    if not blocks:
        raise RuntimeError("no Linux memory block was added from virtio-mem")
    digest = memory_workload()
    print(
        "PASS memory "
        f"pci={pci.name} virtio={child.name} address={config['address']:#x} "
        f"region={config['region']} requested={config['requested']} "
        f"plugged={config['plugged']} block_size={config['block_size']} "
        f"online_blocks={len(blocks)} packed={'yes' if packed else 'no'} "
        f"workload_sha256={digest}"
    )


if __name__ == "__main__":
    main()
