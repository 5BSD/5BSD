#!/usr/bin/env python3
"""Linux guest verifier for bhyve's VirtIO 9P PCI function."""

import glob
import os
import sys
import tempfile


def expected_pci_device(transport):
    if transport == "modern":
        return "0x1049"
    if transport == "legacy":
        return "0x1009"
    raise RuntimeError(f"invalid transport: {transport}")


def find_bound_9p(transport, sys_root="/sys"):
    expected = expected_pci_device(transport)
    matches = []
    for pci in glob.glob(os.path.join(sys_root, "bus/pci/devices/*")):
        try:
            vendor = open(pci + "/vendor", encoding="ascii").read().strip()
            device = open(pci + "/device", encoding="ascii").read().strip()
        except OSError:
            continue
        if vendor != "0x1af4" or device != expected:
            continue
        for child in glob.glob(pci + "/virtio*"):
            driver = child + "/driver"
            if os.path.islink(driver) and os.path.basename(
                os.path.realpath(driver)
            ) == "9pnet_virtio":
                matches.append((pci, child))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {expected} device bound to 9pnet_virtio, "
            f"found {len(matches)}"
        )
    return os.path.basename(matches[0][0]), expected


def make_mock_device(root, device):
    sys_root = os.path.join(root, "sys")
    pci = os.path.join(sys_root, "bus/pci/devices/0000:00:0b.0")
    child = os.path.join(pci, "virtio7")
    driver = os.path.join(sys_root, "bus/virtio/drivers/9pnet_virtio")
    os.makedirs(child)
    os.makedirs(driver)
    with open(pci + "/vendor", "w", encoding="ascii") as stream:
        stream.write("0x1af4\n")
    with open(pci + "/device", "w", encoding="ascii") as stream:
        stream.write(device + "\n")
    os.symlink(driver, child + "/driver")
    return sys_root


def self_test():
    with tempfile.TemporaryDirectory() as root:
        sys_root = make_mock_device(root, "0x1049")
        pci, device = find_bound_9p("modern", sys_root)
        if (pci, device) != ("0000:00:0b.0", "0x1049"):
            raise AssertionError("wrong VirtIO 9P PCI function")
        try:
            find_bound_9p("legacy", sys_root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted the wrong VirtIO 9P device ID")
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) != 2:
        raise SystemExit("usage: g9p.py --self-test | modern|legacy")
    pci, device = find_bound_9p(sys.argv[1])
    print(f"PASS 9p pci={pci} device={device} driver=9pnet_virtio")


if __name__ == "__main__":
    main()
