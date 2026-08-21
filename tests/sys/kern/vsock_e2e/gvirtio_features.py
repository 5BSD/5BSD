#!/usr/bin/env python3
"""Linux guest audit for every attached VirtIO PCI feature bitmap."""

import glob
import os
import sys
import tempfile

VERSION_1 = 32
RING_PACKED = 34


def read(path):
    with open(path, encoding="ascii") as stream:
        return stream.read().strip()


def enabled(bitmap, bit):
    if len(bitmap) != 64 or set(bitmap) - {"0", "1"}:
        raise RuntimeError(f"invalid VirtIO feature bitmap {bitmap!r}")
    return bitmap[bit] == "1"


def devices(sys_root):
    result = []
    for pci in sorted(glob.glob(sys_root + "/bus/pci/devices/*")):
        try:
            if read(pci + "/vendor") != "0x1af4":
                continue
        except OSError:
            continue
        children = glob.glob(pci + "/virtio*")
        if len(children) != 1:
            raise RuntimeError(f"{os.path.basename(pci)} has {len(children)} children")
        child = children[0]
        bitmap = read(child + "/features")
        enabled(bitmap, 0)  # Validate the complete representation.
        driver = child + "/driver"
        result.append((
            os.path.basename(pci), read(pci + "/device"),
            os.path.basename(os.path.realpath(driver))
            if os.path.islink(driver) else "unbound", bitmap,
        ))
    return result


def audit(transport, count, packed_bdfs, sys_root="/sys"):
    if transport not in ("modern", "legacy"):
        raise RuntimeError(f"invalid transport {transport}")
    found = devices(sys_root)
    if len(found) != count:
        raise RuntimeError(f"found {len(found)} devices, expected {count}")
    bdfs = {item[0] for item in found}
    if packed_bdfs - bdfs:
        raise RuntimeError("packed expectation names an absent device")
    for bdf, device, driver, bitmap in found:
        if driver == "unbound":
            raise RuntimeError(f"{bdf} has no bound VirtIO driver")
        version_1 = enabled(bitmap, VERSION_1)
        packed = enabled(bitmap, RING_PACKED)
        if version_1 != (transport == "modern"):
            raise RuntimeError(f"{bdf} VERSION_1 does not match {transport}")
        if packed != (bdf in packed_bdfs):
            raise RuntimeError(f"{bdf} RING_PACKED={int(packed)} is unexpected")
        print(f"FEATURES bdf={bdf} device={device} driver={driver} "
              f"version1={int(version_1)} packed={int(packed)} bitmap={bitmap}")
    print(f"PASS virtio-feature-inventory devices={count} transport={transport}")


def make_device(root, bdf, bits):
    pci = root + "/bus/pci/devices/" + bdf
    child = pci + "/virtio0"
    driver = root + "/bus/virtio/drivers/test"
    os.makedirs(child)
    os.makedirs(driver, exist_ok=True)
    for name, value in (("vendor", "0x1af4"), ("device", "0x1041")):
        with open(pci + "/" + name, "w", encoding="ascii") as stream:
            stream.write(value + "\n")
    bitmap = ["0"] * 64
    for bit in bits:
        bitmap[bit] = "1"
    with open(child + "/features", "w", encoding="ascii") as stream:
        stream.write("".join(bitmap) + "\n")
    os.symlink(driver, child + "/driver")


def self_test():
    with tempfile.TemporaryDirectory() as root:
        make_device(root, "0000:00:04.0", (VERSION_1, RING_PACKED))
        audit("modern", 1, {"0000:00:04.0"}, root)
        try:
            audit("modern", 1, set(), root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted a packed mismatch")
    with tempfile.TemporaryDirectory() as root:
        make_device(root, "0000:00:04.0", ())
        audit("legacy", 1, set(), root)
        os.unlink(root + "/bus/pci/devices/0000:00:04.0/virtio0/driver")
        try:
            audit("legacy", 1, set(), root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted an unbound VirtIO device")
    print("SELFTEST PASS")


def main(argv):
    if argv == ["--self-test"]:
        self_test()
        return 0
    if len(argv) != 3:
        print("usage: gvirtio_features.py TRANSPORT COUNT PACKED_BDFS|-", file=sys.stderr)
        return 2
    try:
        count = int(argv[1])
        if count <= 0:
            raise ValueError
        packed = set() if argv[2] == "-" else set(argv[2].split(","))
        audit(argv[0], count, packed)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"FAIL virtio-feature-inventory: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
