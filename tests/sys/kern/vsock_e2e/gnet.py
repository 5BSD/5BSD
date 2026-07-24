#!/usr/bin/env python3
"""Linux guest verifier for bhyve's disposable virtio-net interface."""

import glob
import os
import sys
import tempfile

VIRTIO_RING_F_INDIRECT_DESC = 28
VIRTIO_RING_F_EVENT_IDX = 29
VIRTIO_NET_F_CTRL_VQ = 17
VIRTIO_NET_F_MQ = 22
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40

REQUIRED_FEATURES = (
    (VIRTIO_RING_F_INDIRECT_DESC, "VIRTIO_RING_F_INDIRECT_DESC"),
    (VIRTIO_RING_F_EVENT_IDX, "VIRTIO_RING_F_EVENT_IDX"),
)
MODERN_REQUIRED_FEATURES = REQUIRED_FEATURES + (
    (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
    (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
)
MULTIQUEUE_REQUIRED_FEATURES = (
    (VIRTIO_NET_F_CTRL_VQ, "VIRTIO_NET_F_CTRL_VQ"),
    (VIRTIO_NET_F_MQ, "VIRTIO_NET_F_MQ"),
)
MODERN_MULTIQUEUE_REQUIRED_FEATURES = (
    MODERN_REQUIRED_FEATURES + MULTIQUEUE_REQUIRED_FEATURES
)


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


def negotiated_feature(expected_device, bit, sys_root="/sys"):
    matches = bound_devices(expected_device, sys_root)
    if len(matches) != 1:
        raise RuntimeError(
            f"cannot read feature {bit}: expected one {expected_device} device"
        )
    feature_path = os.path.join(matches[0][1], "features")
    try:
        features = open(feature_path, encoding="ascii").read().strip()
    except OSError as error:
        raise RuntimeError(f"cannot read {feature_path}: {error}") from error
    if len(features) <= bit or any(value not in "01" for value in features):
        raise RuntimeError(f"invalid virtio feature bitmap: {features!r}")
    return features[bit] == "1"


def require_features(expected_device, required, sys_root="/sys"):
    for bit, name in required:
        if not negotiated_feature(expected_device, bit, sys_root):
            raise RuntimeError(f"virtio-net did not negotiate {name}")


def queue_pairs(interface="eth0", sys_root="/sys"):
    queue_root = os.path.join(sys_root, "class/net", interface, "queues")
    rx = glob.glob(os.path.join(queue_root, "rx-*"))
    tx = glob.glob(os.path.join(queue_root, "tx-*"))
    return len(rx), len(tx)


def require_queue_pairs(expected, interface="eth0", sys_root="/sys"):
    rx, tx = queue_pairs(interface, sys_root)
    if rx != expected or tx != expected:
        raise RuntimeError(
            f"virtio-net exposed rx={rx} tx={tx} queues, expected {expected}"
        )


def make_mock_device(
    root, bdf, device, interface=None, features=(), queues=1
):
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
    feature_bits = ["0"] * 64
    for bit in features:
        feature_bits[bit] = "1"
    with open(child + "/features", "w", encoding="ascii") as stream:
        stream.write("".join(feature_bits) + "\n")
    os.symlink(driver, child + "/driver")
    if interface is not None:
        net = os.path.join(sys_root, "class/net", interface)
        os.makedirs(net)
        os.symlink(child, net + "/device")
        queue_root = os.path.join(net, "queues")
        os.makedirs(queue_root)
        for pair in range(queues):
            os.makedirs(os.path.join(queue_root, f"rx-{pair}"))
            os.makedirs(os.path.join(queue_root, f"tx-{pair}"))
    return sys_root


def self_test():
    with tempfile.TemporaryDirectory() as root:
        sys_root = make_mock_device(
            root, "0000:00:04.0", "0x1041", "eth0",
            features=tuple(
                bit
                for bit, _ in MODERN_MULTIQUEUE_REQUIRED_FEATURES
            ),
            queues=2,
        )
        if find_bound_net("0x1041", sys_root=sys_root) != "0000:00:04.0":
            raise AssertionError("wrong virtio-net PCI function")
        require_features(
            "0x1041", MODERN_MULTIQUEUE_REQUIRED_FEATURES, sys_root
        )
        require_queue_pairs(2, sys_root=sys_root)
        feature_path = os.path.join(
            sys_root,
            "bus/pci/devices/0000:00:04.0/virtio0/features",
        )
        for missing_bit, missing_name in MODERN_MULTIQUEUE_REQUIRED_FEATURES:
            features = ["0"] * 64
            for bit, _ in MODERN_MULTIQUEUE_REQUIRED_FEATURES:
                features[bit] = "1"
            features[missing_bit] = "0"
            with open(feature_path, "w", encoding="ascii") as stream:
                stream.write("".join(features) + "\n")
            try:
                require_features(
                    "0x1041",
                    MODERN_MULTIQUEUE_REQUIRED_FEATURES,
                    sys_root,
                )
            except RuntimeError:
                pass
            else:
                raise AssertionError(
                    f"missing modern network feature {missing_name} "
                    "was accepted"
                )
        try:
            require_queue_pairs(1, sys_root=sys_root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted the wrong network queue count")
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
    if len(sys.argv) not in (2, 3) or sys.argv[1] not in (
        "modern", "legacy"
    ):
        raise SystemExit(
            "usage: gnet.py --self-test | modern|legacy [queue-pairs]"
        )
    try:
        expected_pairs = int(sys.argv[2]) if len(sys.argv) == 3 else 1
    except ValueError as error:
        raise SystemExit("queue-pairs must be a positive integer") from error
    if expected_pairs < 1:
        raise SystemExit("queue-pairs must be a positive integer")
    expected_device = "0x1041" if sys.argv[1] == "modern" else "0x1000"
    pci = find_bound_net(expected_device)
    require_features(expected_device, REQUIRED_FEATURES)
    notification_data = sys.argv[1] == "modern"
    if sys.argv[1] == "modern":
        require_features(expected_device, MODERN_REQUIRED_FEATURES)
        if expected_pairs > 1:
            require_features(
                expected_device, MULTIQUEUE_REQUIRED_FEATURES
            )
    elif expected_pairs != 1:
        raise RuntimeError("legacy virtio-net must use one queue pair")
    require_queue_pairs(expected_pairs)
    print(
        f"PASS net interface=eth0 pci={pci} device={expected_device} "
        f"driver=virtio_net indirect_desc=yes event_idx=yes "
        f"notification_data={'yes' if notification_data else 'n/a'} "
        f"ring_reset={'yes' if notification_data else 'n/a'} "
        f"queue_pairs={expected_pairs} "
        f"mq={'yes' if expected_pairs > 1 else 'no'}"
    )


if __name__ == "__main__":
    main()
