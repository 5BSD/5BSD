#!/usr/bin/env python3
"""Linux guest verifier for bhyve's VirtIO-IOMMU DMA fabric."""

import glob
import os
import sys
import tempfile

VIRTIO_F_ACCESS_PLATFORM = 33
VIRTIO_F_RING_PACKED = 34
IOMMU_PCI_DEVICE = "0x1057"
BALLOON_PCI_DEVICE = "0x1045"


def pci_identity(path):
    try:
        vendor = open(path + "/vendor", encoding="ascii").read().strip()
        device = open(path + "/device", encoding="ascii").read().strip()
    except OSError:
        return None
    return vendor, device


def virtio_children(pci):
    return glob.glob(os.path.join(pci, "virtio*"))


def bound_iommu(sys_root="/sys"):
    matches = []
    for pci in glob.glob(os.path.join(sys_root, "bus/pci/devices/*")):
        if pci_identity(pci) != ("0x1af4", IOMMU_PCI_DEVICE):
            continue
        for child in virtio_children(pci):
            driver = child + "/driver"
            if os.path.islink(driver) and os.path.basename(
                os.path.realpath(driver)
            ) == "virtio_iommu":
                matches.append((pci, child))
    if len(matches) != 1:
        raise RuntimeError(
            "expected one PCI 0x1057 device bound to virtio_iommu, "
            f"found {len(matches)}"
        )
    return matches[0]


def negotiated_feature(child, bit):
    path = child + "/features"
    try:
        features = open(path, encoding="ascii").read().strip()
    except OSError as error:
        raise RuntimeError(f"cannot read {path}: {error}") from error
    if len(features) <= bit or any(value not in "01" for value in features):
        raise RuntimeError(f"invalid virtio feature bitmap: {features!r}")
    return features[bit] == "1"


def discover_protected_endpoints(sys_root="/sys", expected_count=None):
    """Return every non-IOMMU VirtIO PCI function in stable BDF order."""
    endpoints = []
    for pci in sorted(glob.glob(
        os.path.join(sys_root, "bus/pci/devices/*")
    )):
        identity = pci_identity(pci)
        if identity is None or identity[0] != "0x1af4":
            continue
        if identity[1] in (IOMMU_PCI_DEVICE, BALLOON_PCI_DEVICE):
            continue
        children = virtio_children(pci)
        if len(children) != 1:
            continue
        bdf = os.path.basename(pci)
        if not negotiated_feature(children[0], VIRTIO_F_ACCESS_PLATFORM):
            raise RuntimeError(
                f"DMA-capable VirtIO endpoint {bdf} did not negotiate "
                "VIRTIO_F_ACCESS_PLATFORM"
            )
        endpoints.append(bdf)
    if not endpoints:
        raise RuntimeError("no protected VirtIO PCI endpoints discovered")
    if expected_count is not None and len(endpoints) != expected_count:
        raise RuntimeError(
            f"discovered {len(endpoints)} ACCESS_PLATFORM endpoints, "
            f"expected {expected_count}"
        )
    return endpoints


def protected_endpoint(bdf, sys_root="/sys"):
    pci = os.path.join(sys_root, "bus/pci/devices", bdf)
    if pci_identity(pci) is None:
        raise RuntimeError(f"protected endpoint {bdf} is absent")
    children = virtio_children(pci)
    if len(children) != 1:
        raise RuntimeError(
            f"protected endpoint {bdf} has {len(children)} virtio children"
        )
    child = children[0]
    if not negotiated_feature(child, VIRTIO_F_ACCESS_PLATFORM):
        raise RuntimeError(
            f"protected endpoint {bdf} did not negotiate "
            "VIRTIO_F_ACCESS_PLATFORM"
        )
    group = pci + "/iommu_group"
    if not os.path.islink(group):
        raise RuntimeError(f"protected endpoint {bdf} has no IOMMU group")
    group_path = os.path.realpath(group)
    member = os.path.join(group_path, "devices", bdf)
    if not os.path.exists(member):
        raise RuntimeError(
            f"IOMMU group for {bdf} does not contain the endpoint"
        )
    return os.path.basename(group_path)


def verify(expected_packed, protected, sys_root="/sys"):
    pci, child = bound_iommu(sys_root)
    packed = negotiated_feature(child, VIRTIO_F_RING_PACKED)
    if packed != expected_packed:
        raise RuntimeError(
            f"virtio-iommu packed negotiation is {packed}, "
            f"expected {expected_packed}"
        )
    groups = [protected_endpoint(bdf, sys_root) for bdf in protected]
    return os.path.basename(pci), groups


def self_test():
    with tempfile.TemporaryDirectory() as root:
        sys_root = os.path.join(root, "sys")
        pci_root = os.path.join(sys_root, "bus/pci/devices")
        driver_root = os.path.join(sys_root, "bus/virtio/drivers")
        group = os.path.join(sys_root, "kernel/iommu_groups/7")
        os.makedirs(pci_root)
        os.makedirs(driver_root + "/virtio_iommu")
        os.makedirs(group + "/devices")

        iommu = pci_root + "/0000:00:0f.0"
        endpoint = pci_root + "/0000:00:04.0"
        balloon = pci_root + "/0000:00:0c.0"
        for pci, device in ((iommu, IOMMU_PCI_DEVICE),
                            (endpoint, "0x1041"),
                            (balloon, BALLOON_PCI_DEVICE)):
            os.makedirs(pci + "/virtio0")
            with open(pci + "/vendor", "w", encoding="ascii") as stream:
                stream.write("0x1af4\n")
            with open(pci + "/device", "w", encoding="ascii") as stream:
                stream.write(device + "\n")
        os.symlink(driver_root + "/virtio_iommu",
                   iommu + "/virtio0/driver")
        iommu_features = ["0"] * 64
        endpoint_features = ["0"] * 64
        endpoint_features[VIRTIO_F_ACCESS_PLATFORM] = "1"
        with open(iommu + "/virtio0/features", "w",
                  encoding="ascii") as stream:
            stream.write("".join(iommu_features))
        with open(endpoint + "/virtio0/features", "w",
                  encoding="ascii") as stream:
            stream.write("".join(endpoint_features))
        with open(balloon + "/virtio0/features", "w",
                  encoding="ascii") as stream:
            stream.write("".join(iommu_features))
        os.symlink(group, endpoint + "/iommu_group")
        os.symlink(endpoint, group + "/devices/0000:00:04.0")

        assert verify(False, ["0000:00:04.0"], sys_root) == (
            "0000:00:0f.0", ["7"])
        assert discover_protected_endpoints(sys_root) == ["0000:00:04.0"]
        try:
            discover_protected_endpoints(sys_root, 2)
        except RuntimeError:
            pass
        else:
            raise AssertionError("incorrect expected endpoint count accepted")
        endpoint_features[VIRTIO_F_ACCESS_PLATFORM] = "0"
        with open(endpoint + "/virtio0/features", "w",
                  encoding="ascii") as stream:
            stream.write("".join(endpoint_features))
        try:
            verify(False, ["0000:00:04.0"], sys_root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("endpoint without ACCESS_PLATFORM accepted")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        print("SELFTEST PASS")
        return
    expected_packed = False
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "packed":
        expected_packed = True
        arguments = arguments[1:]
    if len(arguments) == 2 and arguments[0] == "auto":
        try:
            expected_endpoints = int(arguments[1], 10)
        except ValueError as error:
            raise SystemExit(
                "auto endpoint count must be a decimal integer"
            ) from error
        if expected_endpoints <= 0:
            raise SystemExit("auto endpoint count must be positive")
        arguments = discover_protected_endpoints(
            expected_count=expected_endpoints
        )
    elif not arguments:
        raise SystemExit("usage: giommu.py [packed] auto COUNT|BDF...")
    pci, groups = verify(expected_packed, arguments)
    print(
        f"PASS iommu pci={pci} packed={'yes' if expected_packed else 'no'} "
        f"endpoints={','.join(arguments)} groups={','.join(groups)}"
    )


if __name__ == "__main__":
    main()
