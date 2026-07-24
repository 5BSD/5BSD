#!/usr/bin/env python3
"""Linux guest verifier for bhyve's VirtIO 9P PCI function."""

import glob
import os
import sys
import tempfile

# VirtIO 1.4 feature allocation (§5.9.3 and §6).
VIRTIO_9P_F_MOUNT_TAG = 0
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40


def validate_features(child, transport):
    if not negotiated_feature(child, VIRTIO_9P_F_MOUNT_TAG):
        raise RuntimeError(
            "virtio-9p did not negotiate VIRTIO_9P_F_MOUNT_TAG"
        )
    if transport == "modern":
        if not negotiated_feature(child, VIRTIO_F_NOTIFICATION_DATA):
            raise RuntimeError(
                "virtio-9p did not negotiate VIRTIO_F_NOTIFICATION_DATA"
            )
        if not negotiated_feature(child, VIRTIO_F_RING_RESET):
            raise RuntimeError(
                "virtio-9p did not negotiate VIRTIO_F_RING_RESET"
            )


def expected_pci_device(transport):
    if transport == "modern":
        return "0x1049"
    if transport == "legacy":
        return "0x1009"
    raise RuntimeError(f"invalid transport: {transport}")


def negotiated_feature(child, bit):
    feature_path = child + "/features"
    try:
        features = open(feature_path, encoding="ascii").read().strip()
    except OSError as error:
        raise RuntimeError(f"cannot read {feature_path}: {error}") from error
    if len(features) <= bit or any(value not in "01" for value in features):
        raise RuntimeError(f"invalid virtio feature bitmap: {features!r}")
    return features[bit] == "1"


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
    return os.path.basename(matches[0][0]), expected, matches[0][1]


def make_mock_device(root, device, features=()):
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
    feature_bits = ["0"] * 64
    for bit in features:
        feature_bits[bit] = "1"
    with open(child + "/features", "w", encoding="ascii") as stream:
        stream.write("".join(feature_bits) + "\n")
    os.symlink(driver, child + "/driver")
    return sys_root


def self_test():
    with tempfile.TemporaryDirectory() as root:
        sys_root = make_mock_device(root, "0x1049", features=(0, 38, 40))
        pci, device, child = find_bound_9p("modern", sys_root)
        if (pci, device) != ("0000:00:0b.0", "0x1049"):
            raise AssertionError("wrong VirtIO 9P PCI function")
        validate_features(child, "modern")
        for missing_bit, missing_name in (
            (VIRTIO_9P_F_MOUNT_TAG, "VIRTIO_9P_F_MOUNT_TAG"),
            (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
            (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
        ):
            features = (
                VIRTIO_9P_F_MOUNT_TAG,
                VIRTIO_F_NOTIFICATION_DATA,
                VIRTIO_F_RING_RESET,
            )
            feature_path = child + "/features"
            bitmap = ["0"] * 64
            for bit in features:
                if bit != missing_bit:
                    bitmap[bit] = "1"
            with open(feature_path, "w", encoding="ascii") as stream:
                stream.write("".join(bitmap) + "\n")
            try:
                validate_features(child, "modern")
            except RuntimeError:
                pass
            else:
                raise AssertionError(
                    f"missing 9P feature {missing_name} was accepted"
                )
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
    pci, device, child = find_bound_9p(sys.argv[1])
    validate_features(child, sys.argv[1])
    print(
        f"PASS 9p pci={pci} device={device} driver=9pnet_virtio "
        f"mount_tag=yes notification_data="
        f"{'yes' if sys.argv[1] == 'modern' else 'n/a'} "
        f"ring_reset={'yes' if sys.argv[1] == 'modern' else 'n/a'}"
    )


if __name__ == "__main__":
    main()
