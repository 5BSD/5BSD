#!/usr/bin/env python3
"""Linux guest verifier for bhyve's disposable virtio-net interface."""

import glob
import os
import sys
import tempfile


def bound_devices(expected_device, sys_root="/sys"):
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
            if os.path.islink(driver) and os.path.basename(
                os.path.realpath(driver)
            ) == "virtio_net":
                matches.append((pci, child))
    return matches


def find_bound_net(expected_device, interface="eth0", sys_root="/sys"):
    matches = bound_devices(expected_device, sys_root)
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {expected_device} device bound to virtio_net, "
            f"found {len(matches)}"
        )
    pci, child = matches[0]
    interface_device = os.path.join(sys_root, "class/net", interface, "device")
    if not os.path.islink(interface_device):
        raise RuntimeError(f"network interface {interface} has no device link")
    if os.path.realpath(interface_device) != os.path.realpath(child):
        raise RuntimeError(
            f"network interface {interface} is not attached to {expected_device}"
        )
    return os.path.basename(pci)


def make_mock_device(root, bdf, device, interface=None):
    sys_root = os.path.join(root, "sys")
    pci = os.path.join(sys_root, "bus/pci/devices", bdf)
    child = os.path.join(pci, "virtio0")
    driver = os.path.join(sys_root, "bus/virtio/drivers/virtio_net")
    os.makedirs(child)
    os.makedirs(driver, exist_ok=True)
    with open(pci + "/vendor", "w", encoding="ascii") as stream:
        stream.write("0x1af4\n")
    with open(pci + "/device", "w", encoding="ascii") as stream:
        stream.write(device + "\n")
    os.symlink(driver, child + "/driver")
    if interface is not None:
        net = os.path.join(sys_root, "class/net", interface)
        os.makedirs(net)
        os.symlink(child, net + "/device")
    return sys_root


def self_test():
    with tempfile.TemporaryDirectory() as root:
        sys_root = make_mock_device(root, "0000:00:04.0", "0x1041", "eth0")
        if find_bound_net("0x1041", sys_root=sys_root) != "0000:00:04.0":
            raise AssertionError("wrong virtio-net PCI function")
        try:
            find_bound_net("0x1000", sys_root=sys_root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted the wrong virtio-net device ID")
        make_mock_device(root, "0000:00:09.0", "0x1041")
        try:
            find_bound_net("0x1041", sys_root=sys_root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted duplicate virtio-net devices")
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) != 2 or sys.argv[1] not in ("modern", "legacy"):
        raise SystemExit("usage: gnet.py --self-test | modern|legacy")
    expected_device = "0x1041" if sys.argv[1] == "modern" else "0x1000"
    pci = find_bound_net(expected_device)
    print(
        f"PASS net interface=eth0 pci={pci} device={expected_device} "
        "driver=virtio_net"
    )


if __name__ == "__main__":
    main()
