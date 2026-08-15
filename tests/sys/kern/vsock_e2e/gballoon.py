#!/usr/bin/env python3
"""Linux guest verifier for bhyve's modern VirtIO balloon device."""

import glob
import mmap
import os
import struct
import sys
import tempfile
import time

# Release-ledger anchors for target, accounting, and feature checks below.
# VIRTIO_ACTIVATION_ASSERTION: inflate-deflate-memory-accounting
# VIRTIO_ACTIVATION_ASSERTION: inflate-to-target
# VIRTIO_ACTIVATION_ASSERTION: target-and-actual-config
# VIRTIO_ACTIVATION_ASSERTION: target-reached
# VIRTIO_ACTIVATION_ASSERTION: stats-feature-negotiated
# VIRTIO_ACTIVATION_ASSERTION: deflate-on-oom-feature-negotiated
# VIRTIO_ACTIVATION_ASSERTION: free-page-hinting-feature-negotiated
# VIRTIO_ACTIVATION_ASSERTION: free-page-hint-command-state
# VIRTIO_ACTIVATION_ASSERTION: free-page-reporting-feature-negotiated
# VIRTIO_ACTIVATION_ASSERTION: page-poison-feature-negotiated
# VIRTIO_ACTIVATION_ASSERTION: page-poison-config-layout

VIRTIO_PCI_CAP_DEVICE_CFG = 4
VIRTIO_PCI_VENDOR_CAP = 0x09
VIRTIO_BALLOON_DEVICE = "0x1045"
VIRTIO_BALLOON_DRIVER = "virtio_balloon"
VIRTIO_BALLOON_F_MUST_TELL_HOST = 0
VIRTIO_BALLOON_F_STATS_VQ = 1
VIRTIO_BALLOON_F_DEFLATE_ON_OOM = 2
VIRTIO_BALLOON_F_FREE_PAGE_HINT = 3
VIRTIO_BALLOON_F_PAGE_POISON = 4
VIRTIO_BALLOON_F_PAGE_REPORTING = 5
VIRTIO_RING_F_INDIRECT_DESC = 28
VIRTIO_RING_F_EVENT_IDX = 29
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40
VIRTIO_F_RING_PACKED = 34

REQUIRED_FEATURES = (
    (
        VIRTIO_BALLOON_F_MUST_TELL_HOST,
        "VIRTIO_BALLOON_F_MUST_TELL_HOST",
    ),
    (VIRTIO_RING_F_INDIRECT_DESC, "VIRTIO_RING_F_INDIRECT_DESC"),
    (VIRTIO_RING_F_EVENT_IDX, "VIRTIO_RING_F_EVENT_IDX"),
    (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
    (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
)


def bound_devices(sys_root="/sys"):
    matches = []
    for pci in glob.glob(os.path.join(sys_root, "bus/pci/devices/*")):
        try:
            vendor = open(pci + "/vendor", encoding="ascii").read().strip()
            device = open(pci + "/device", encoding="ascii").read().strip()
        except OSError:
            continue
        if vendor != "0x1af4" or device != VIRTIO_BALLOON_DEVICE:
            continue
        for child in glob.glob(pci + "/virtio*"):
            driver = child + "/driver"
            if os.path.islink(driver) and os.path.basename(
                os.path.realpath(driver)
            ) == VIRTIO_BALLOON_DRIVER:
                matches.append((pci, child))
    return matches


def one_device(sys_root="/sys"):
    matches = bound_devices(sys_root)
    if len(matches) != 1:
        raise RuntimeError(
            "expected one modern virtio-balloon bound to "
            f"{VIRTIO_BALLOON_DRIVER}, found {len(matches)}"
        )
    return matches[0]


def negotiated_feature(bit, sys_root="/sys"):
    _, child = one_device(sys_root)
    path = child + "/features"
    features = open(path, encoding="ascii").read().strip()
    if len(features) <= bit or any(value not in "01" for value in features):
        raise RuntimeError(f"invalid virtio feature bitmap: {features!r}")
    return features[bit] == "1"


def require_features(
    packed,
    stats,
    deflate_on_oom,
    hinting,
    reporting,
    poison,
    sys_root="/sys",
):
    for bit, name in REQUIRED_FEATURES:
        if not negotiated_feature(bit, sys_root):
            raise RuntimeError(f"virtio-balloon did not negotiate {name}")
    if negotiated_feature(VIRTIO_F_RING_PACKED, sys_root) != packed:
        raise RuntimeError("unexpected VIRTIO_F_RING_PACKED negotiation")
    if negotiated_feature(VIRTIO_BALLOON_F_STATS_VQ, sys_root) != stats:
        raise RuntimeError("unexpected VIRTIO_BALLOON_F_STATS_VQ negotiation")
    if (
        negotiated_feature(VIRTIO_BALLOON_F_DEFLATE_ON_OOM, sys_root)
        != deflate_on_oom
    ):
        raise RuntimeError(
            "unexpected VIRTIO_BALLOON_F_DEFLATE_ON_OOM negotiation"
        )
    if (
        negotiated_feature(VIRTIO_BALLOON_F_FREE_PAGE_HINT, sys_root)
        != hinting
    ):
        raise RuntimeError(
            "unexpected VIRTIO_BALLOON_F_FREE_PAGE_HINT negotiation"
        )
    if (
        negotiated_feature(VIRTIO_BALLOON_F_PAGE_REPORTING, sys_root)
        != reporting
    ):
        raise RuntimeError(
            "unexpected VIRTIO_BALLOON_F_PAGE_REPORTING negotiation"
        )
    if negotiated_feature(VIRTIO_BALLOON_F_PAGE_POISON, sys_root) != poison:
        raise RuntimeError(
            "unexpected VIRTIO_BALLOON_F_PAGE_POISON negotiation"
        )


def device_config_capability(config):
    if len(config) < 0x40:
        raise RuntimeError("short PCI configuration space")
    offset = config[0x34]
    visited = set()
    while offset:
        if offset in visited or offset < 0x40 or offset + 16 > len(config):
            raise RuntimeError("invalid PCI capability chain")
        visited.add(offset)
        cap_id = config[offset]
        next_offset = config[offset + 1]
        cap_len = config[offset + 2]
        if cap_id == VIRTIO_PCI_VENDOR_CAP and cap_len >= 16:
            cfg_type = config[offset + 3]
            if cfg_type == VIRTIO_PCI_CAP_DEVICE_CFG:
                bar = config[offset + 4]
                bar_offset, length = struct.unpack_from(
                    "<II", config, offset + 8
                )
                if bar > 5 or length < 8:
                    raise RuntimeError("invalid balloon device capability")
                return bar, bar_offset, length
        offset = next_offset
    raise RuntimeError("missing VirtIO device configuration capability")


def read_resource(path, offset, length):
    fd = os.open(path, os.O_RDONLY)
    try:
        try:
            data = os.pread(fd, length, offset)
        except OSError:
            data = b""
        if len(data) == length:
            return data
        page_size = os.sysconf("SC_PAGE_SIZE")
        base = offset - offset % page_size
        delta = offset - base
        with mmap.mmap(
            fd,
            delta + length,
            flags=mmap.MAP_SHARED,
            prot=mmap.PROT_READ,
            offset=base,
        ) as mapping:
            return mapping[delta : delta + length]
    finally:
        os.close(fd)


def balloon_config(sys_root="/sys"):
    pci, _ = one_device(sys_root)
    config = open(pci + "/config", "rb").read(4096)
    bar, offset, _ = device_config_capability(config)
    data = read_resource(f"{pci}/resource{bar}", offset, 8)
    if len(data) != 8:
        raise RuntimeError("short balloon configuration read")
    return struct.unpack("<II", data)


def extended_balloon_config(sys_root="/sys"):
    pci, _ = one_device(sys_root)
    config = open(pci + "/config", "rb").read(4096)
    bar, offset, length = device_config_capability(config)
    if length < 16:
        raise RuntimeError(
            f"optional feature negotiated with short balloon config length {length}"
        )
    data = read_resource(f"{pci}/resource{bar}", offset, 16)
    if len(data) != 16:
        raise RuntimeError("short extended balloon configuration read")
    return struct.unpack("<IIII", data)


def wait_for_target(target_pages, timeout=45, sys_root="/sys"):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = balloon_config(sys_root)
        if last == (target_pages, target_pages):
            return last
        time.sleep(0.1)
    raise RuntimeError(
        f"balloon target did not converge: last={last}, "
        f"expected=({target_pages}, {target_pages})"
    )


def wait_for_hint_command(timeout=10, sys_root="/sys"):
    """Wait through the guest's transient STOP acknowledgement window."""
    deadline = time.monotonic() + timeout
    command = None
    while time.monotonic() < deadline:
        _, _, command, _ = extended_balloon_config(sys_root)
        if command != 0:
            return command
        time.sleep(0.05)
    raise RuntimeError(
        f"free-page hint command remained STOP: last={command}"
    )


def make_mock_device(
    root,
    target=16384,
    actual=16384,
    packed=False,
    stats=False,
    deflate_on_oom=False,
    hinting=False,
    reporting=False,
    poison=False,
):
    sys_root = os.path.join(root, "sys")
    pci = os.path.join(sys_root, "bus/pci/devices/0000:00:0c.0")
    child = os.path.join(pci, "virtio0")
    driver = os.path.join(
        sys_root, "bus/virtio/drivers", VIRTIO_BALLOON_DRIVER
    )
    os.makedirs(child)
    os.makedirs(driver, exist_ok=True)
    open(pci + "/vendor", "w", encoding="ascii").write("0x1af4\n")
    open(pci + "/device", "w", encoding="ascii").write(
        VIRTIO_BALLOON_DEVICE + "\n"
    )
    os.symlink(driver, child + "/driver")
    features = ["0"] * 64
    for bit, _ in REQUIRED_FEATURES:
        features[bit] = "1"
    if packed:
        features[VIRTIO_F_RING_PACKED] = "1"
    if stats:
        features[VIRTIO_BALLOON_F_STATS_VQ] = "1"
    if deflate_on_oom:
        features[VIRTIO_BALLOON_F_DEFLATE_ON_OOM] = "1"
    if hinting:
        features[VIRTIO_BALLOON_F_FREE_PAGE_HINT] = "1"
    if reporting:
        features[VIRTIO_BALLOON_F_PAGE_REPORTING] = "1"
    if poison:
        features[VIRTIO_BALLOON_F_PAGE_POISON] = "1"
    open(child + "/features", "w", encoding="ascii").write(
        "".join(features) + "\n"
    )
    config = bytearray(256)
    config[0x34] = 0x40
    config[0x40] = VIRTIO_PCI_VENDOR_CAP
    config[0x42] = 16
    config[0x43] = VIRTIO_PCI_CAP_DEVICE_CFG
    config[0x44] = 2
    struct.pack_into("<II", config, 0x48, 0x1000, 16)
    open(pci + "/config", "wb").write(config)
    resource = bytearray(0x2000)
    struct.pack_into(
        "<IIII",
        resource,
        0x1000,
        target,
        actual,
        2 if hinting else 0,
        0x5A5A5A5A,
    )
    open(pci + "/resource2", "wb").write(resource)
    return sys_root


def self_test():
    with tempfile.TemporaryDirectory() as root:
        sys_root = make_mock_device(root)
        require_features(False, False, False, False, False, False, sys_root)
        if balloon_config(sys_root) != (16384, 16384):
            raise AssertionError("wrong balloon configuration")
        wait_for_target(16384, timeout=0.2, sys_root=sys_root)
        try:
            wait_for_target(1, timeout=0.2, sys_root=sys_root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted an unconverged target")
        config_path = os.path.join(
            sys_root, "bus/pci/devices/0000:00:0c.0/config"
        )
        config = bytearray(open(config_path, "rb").read())
        config[0x41] = 0x40
        config[0x43] = 1
        open(config_path, "wb").write(config)
        try:
            balloon_config(sys_root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted a looping capability chain")
    with tempfile.TemporaryDirectory() as root:
        sys_root = make_mock_device(
            root,
            packed=True,
            stats=True,
            deflate_on_oom=True,
            hinting=True,
            reporting=True,
            poison=True,
        )
        require_features(True, True, True, True, True, True, sys_root)
        config = extended_balloon_config(sys_root)
        if config[2] == 0:
            raise AssertionError("wrong free-page hint command configuration")
        if config[3] != 0x5A5A5A5A:
            raise AssertionError("wrong balloon poison configuration")
        if wait_for_hint_command(timeout=0.2, sys_root=sys_root) != 2:
            raise AssertionError("did not observe the active hint command")
        pci, _ = one_device(sys_root)
        resource_path = pci + "/resource2"
        resource = bytearray(open(resource_path, "rb").read())
        struct.pack_into("<I", resource, 0x1008, 0)
        open(resource_path, "wb").write(resource)
        try:
            wait_for_hint_command(timeout=0.2, sys_root=sys_root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted a permanently stopped hint round")
    print("SELFTEST PASS")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return
    if len(sys.argv) < 2:
        raise SystemExit(
            "usage: gballoon.py TARGET_PAGES [packed] [stats] "
            "[deflate-on-oom] [hinting] [reporting] [poison]"
        )
    target = int(sys.argv[1], 10)
    options = set(sys.argv[2:])
    if len(options) != len(sys.argv[2:]) or not options <= {
        "packed",
        "stats",
        "deflate-on-oom",
        "hinting",
        "reporting",
        "poison",
    }:
        raise SystemExit(
            "usage: gballoon.py TARGET_PAGES [packed] [stats] "
            "[deflate-on-oom] [hinting] [reporting] [poison]"
        )
    packed = "packed" in options
    stats = "stats" in options
    deflate_on_oom = "deflate-on-oom" in options
    hinting = "hinting" in options
    reporting = "reporting" in options
    poison = "poison" in options
    require_features(
        packed, stats, deflate_on_oom, hinting, reporting, poison
    )
    poison_value = None
    hint_command = None
    if hinting or poison:
        _, _, free_page_hint_cmd_id, poison_value = extended_balloon_config()
        if not hinting and free_page_hint_cmd_id != 0:
            raise RuntimeError(
                "unnegotiated free-page-hint command id is nonzero"
            )
    num_pages, actual = wait_for_target(target)
    if hinting:
        hint_command = wait_for_hint_command()
    pci, _ = one_device()
    print(
        "PASS balloon "
        f"pci={os.path.basename(pci)} target_pages={num_pages} "
        f"actual_pages={actual} packed={'yes' if packed else 'no'} "
        f"stats={'yes' if stats else 'no'} "
        f"deflate_on_oom={'yes' if deflate_on_oom else 'no'} "
        f"hinting={'yes' if hinting else 'no'} "
        f"reporting={'yes' if reporting else 'no'} "
        f"poison={'yes' if poison else 'no'}"
        + (
            f" poison_value=0x{poison_value:08x}"
            if poison_value is not None
            else ""
        )
        + (
            f" hint_command={hint_command}"
            if hint_command is not None
            else ""
        )
    )


if __name__ == "__main__":
    main()
