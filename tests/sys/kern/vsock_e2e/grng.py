#!/usr/bin/env python3
"""Linux guest end-to-end verifier for bhyve virtio-rng."""

import glob
import hashlib
import os
import sys
import tempfile

# VirtIO 1.4 feature allocation (§6).
VIRTIO_F_IN_ORDER = 35
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40

MODERN_REQUIRED_FEATURES = (
    (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
    (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
)


def find_bound_rng(expected_device):
    matches = []
    for pci in glob.glob("/sys/bus/pci/devices/*"):
        try:
            vendor = open(pci + "/vendor", encoding="ascii").read().strip()
            device = open(pci + "/device", encoding="ascii").read().strip()
        except OSError:
            continue
        if vendor != "0x1af4" or device != expected_device:
            continue
        children = []
        for child in glob.glob(pci + "/virtio*"):
            driver = child + "/driver"
            if os.path.islink(driver) and os.path.basename(
                os.path.realpath(driver)
            ) == "virtio_rng":
                children.append(child)
        if len(children) == 1:
            matches.append((pci, children[0]))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {expected_device} device bound to virtio_rng, "
            f"found {len(matches)}"
        )
    return matches[0][1]


def negotiated_feature(child, bit):
    feature_path = child + "/features"
    try:
        features = open(feature_path, encoding="ascii").read().strip()
    except OSError as error:
        raise RuntimeError(f"cannot read {feature_path}: {error}") from error
    if len(features) <= bit or any(value not in "01" for value in features):
        raise RuntimeError(f"invalid virtio feature bitmap: {features!r}")
    return features[bit] == "1"

def require_features(child, required):
    for bit, name in required:
        if not negotiated_feature(child, bit):
            raise RuntimeError(f"virtio-rng did not negotiate {name}")


def read_exact(fd, size):
    result = bytearray()
    while len(result) < size:
        chunk = os.read(fd, size - len(result))
        if not chunk:
            raise RuntimeError(f"unexpected /dev/hwrng EOF after {len(result)} bytes")
        result.extend(chunk)
    return result


def self_test():
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"abcdef")
    os.close(write_fd)
    try:
        assert read_exact(read_fd, 6) == b"abcdef"
    finally:
        os.close(read_fd)

    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"short")
    os.close(write_fd)
    try:
        try:
            read_exact(read_fd, 6)
        except RuntimeError:
            pass
        else:
            raise AssertionError("short RNG stream was accepted")
    finally:
        os.close(read_fd)

    with tempfile.TemporaryDirectory() as root:
        child = os.path.join(root, "virtio0")
        os.mkdir(child)
        features = ["0"] * 64
        for bit, _ in MODERN_REQUIRED_FEATURES:
            features[bit] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        require_features(child, MODERN_REQUIRED_FEATURES)
        assert not negotiated_feature(child, 34)
        for missing_bit, missing_name in MODERN_REQUIRED_FEATURES:
            missing = features.copy()
            missing[missing_bit] = "0"
            with open(child + "/features", "w", encoding="ascii") as stream:
                stream.write("".join(missing) + "\n")
            try:
                require_features(child, MODERN_REQUIRED_FEATURES)
            except RuntimeError:
                pass
            else:
                raise AssertionError(
                    f"missing RNG feature {missing_name} was accepted"
                )
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) != 2 or sys.argv[1] not in ("modern", "legacy"):
        raise SystemExit("usage: grng.py modern|legacy")
    expected_device = "0x1044" if sys.argv[1] == "modern" else "0x1005"
    child = find_bound_rng(expected_device)
    if sys.argv[1] == "modern":
        require_features(child, MODERN_REQUIRED_FEATURES)
    current = open(
        "/sys/class/misc/hw_random/rng_current", encoding="ascii"
    ).read().strip()
    if not current.startswith("virtio_rng"):
        raise RuntimeError(f"virtio-rng is not the current hwrng: {current!r}")

    digest = hashlib.sha256()
    total = 0
    sizes = (1, 7, 31, 32, 255, 4095, 4096, 8193, 65536)
    fd = os.open("/dev/hwrng", os.O_RDONLY)
    try:
        for _ in range(8):
            for size in sizes:
                data = read_exact(fd, size)
                digest.update(data)
                total += len(data)
    finally:
        os.close(fd)
    modern = sys.argv[1] == "modern"
    in_order = modern and negotiated_feature(child, VIRTIO_F_IN_ORDER)
    print(
        f"PASS rng bytes={total} sha256={digest.hexdigest()} "
        f"in_order={'yes' if in_order else ('no' if modern else 'n/a')} "
        f"notification_data={'yes' if modern else 'n/a'} "
        f"ring_reset={'yes' if modern else 'n/a'}"
    )


if __name__ == "__main__":
    main()
