#!/usr/bin/env python3
"""Linux guest verifier for a disposable bhyve virtio-blk device."""

import fcntl
import glob
import hashlib
import os
import struct
import sys
import tempfile


CHUNK_SIZE = 1024 * 1024
SECTOR_SIZE = 512
# Linux UAPI include/uapi/linux/fs.h: _IO(0x12, 127).
BLKZEROOUT = 0x127F
VIRTIO_BLK_F_WRITE_ZEROES = 14
VIRTIO_BLK_F_MQ = 12
VIRTIO_RING_F_INDIRECT_DESC = 28
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40

REQUIRED_FEATURES = (
    (VIRTIO_BLK_F_WRITE_ZEROES, "VIRTIO_BLK_F_WRITE_ZEROES"),
    (VIRTIO_RING_F_INDIRECT_DESC, "VIRTIO_RING_F_INDIRECT_DESC"),
)
MODERN_REQUIRED_FEATURES = REQUIRED_FEATURES + (
    (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
    (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
)


def find_bound_block(expected_device, sys_root="/sys", dev_root="/dev"):
    matches = []
    pattern = os.path.join(sys_root, "bus/pci/devices/*")
    for pci in glob.glob(pattern):
        try:
            vendor = open(pci + "/vendor", encoding="ascii").read().strip()
            device = open(pci + "/device", encoding="ascii").read().strip()
        except OSError:
            continue
        if vendor != "0x1af4" or device != expected_device:
            continue
        for child in glob.glob(pci + "/virtio*"):
            driver = child + "/driver"
            if not os.path.islink(driver) or os.path.basename(
                os.path.realpath(driver)
            ) != "virtio_blk":
                continue
            blocks = glob.glob(child + "/block/*")
            if len(blocks) == 1:
                matches.append(
                    (
                        os.path.join(dev_root, os.path.basename(blocks[0])),
                        child,
                    )
                )
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {expected_device} device bound to virtio_blk, "
            f"found {len(matches)}"
        )
    return matches[0]


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
            raise RuntimeError(f"virtio-blk did not negotiate {name}")


def require_multiqueue(child, device, expected, sys_root="/sys"):
    if expected < 1:
        raise RuntimeError(f"invalid expected queue count: {expected}")
    if expected > 1 and not negotiated_feature(child, VIRTIO_BLK_F_MQ):
        raise RuntimeError("virtio-blk did not negotiate VIRTIO_BLK_F_MQ")
    name = os.path.basename(device)
    mq_path = os.path.join(sys_root, "class/block", name, "mq")
    try:
        queues = [
            entry
            for entry in os.listdir(mq_path)
            if entry.isdigit() and os.path.isdir(os.path.join(mq_path, entry))
        ]
    except OSError as error:
        raise RuntimeError(f"cannot inspect {mq_path}: {error}") from error
    if len(queues) != expected:
        raise RuntimeError(
            f"virtio-blk exposed {len(queues)} Linux hardware queues, "
            f"expected {expected}"
        )


def pattern_chunk(counter, size):
    seed = hashlib.sha256(f"bhyve-block-{counter}".encode()).digest()
    return (seed * ((size + len(seed) - 1) // len(seed)))[:size]


def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise RuntimeError("short block-device write")
        view = view[written:]


def write_pattern(path, size):
    digest = hashlib.sha256()
    fd = os.open(path, os.O_WRONLY)
    try:
        offset = 0
        counter = 0
        while offset < size:
            length = min(CHUNK_SIZE, size - offset)
            data = pattern_chunk(counter, length)
            write_all(fd, data)
            digest.update(data)
            offset += length
            counter += 1
        os.fsync(fd)
    finally:
        os.close(fd)
    return digest.hexdigest()


def expected_pattern_digest(size, zero_offset=None, zero_length=0):
    digest = hashlib.sha256()
    offset = 0
    counter = 0
    zero_end = 0 if zero_offset is None else zero_offset + zero_length
    while offset < size:
        length = min(CHUNK_SIZE, size - offset)
        data = bytearray(pattern_chunk(counter, length))
        if zero_offset is not None:
            overlap_start = max(offset, zero_offset)
            overlap_end = min(offset + length, zero_end)
            if overlap_start < overlap_end:
                start = overlap_start - offset
                end = overlap_end - offset
                data[start:end] = b"\0" * (end - start)
        digest.update(data)
        offset += length
        counter += 1
    return digest.hexdigest()


def read_digest(path, size):
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY)
    try:
        remaining = size
        while remaining:
            data = os.read(fd, min(CHUNK_SIZE, remaining))
            if not data:
                raise RuntimeError(
                    f"unexpected block-device EOF with {remaining} bytes remaining"
                )
            digest.update(data)
            remaining -= len(data)
    finally:
        os.close(fd)
    return digest.hexdigest()


def read_range(path, offset, length):
    result = bytearray()
    fd = os.open(path, os.O_RDONLY)
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        while len(result) < length:
            data = os.read(fd, length - len(result))
            if not data:
                raise RuntimeError(
                    "unexpected block-device EOF while reading zero range"
                )
            result.extend(data)
    finally:
        os.close(fd)
    return bytes(result)


def zero_test_range(size):
    length = CHUNK_SIZE
    offset = CHUNK_SIZE
    if size < offset + length:
        raise RuntimeError(
            f"block byte count {size} is too small for WRITE ZEROES test"
        )
    return offset, length


def require_write_zeroes_limit(device, length, sys_root="/sys"):
    name = os.path.basename(device)
    limit_path = os.path.join(
        sys_root, "class/block", name, "queue/write_zeroes_max_bytes"
    )
    try:
        limit_text = open(limit_path, encoding="ascii").read().strip()
        limit = int(limit_text)
    except (OSError, ValueError) as error:
        raise RuntimeError(
            f"cannot read valid WRITE ZEROES limit from {limit_path}: {error}"
        ) from error
    if limit < length:
        raise RuntimeError(
            f"Linux WRITE ZEROES limit {limit} is below test length {length}"
        )
    return limit


def issue_write_zeroes(path, offset, length):
    if offset % SECTOR_SIZE or length % SECTOR_SIZE:
        raise RuntimeError("WRITE ZEROES range is not sector aligned")
    before = read_range(path, offset, length)
    if not any(before):
        raise RuntimeError("WRITE ZEROES test range was already all zero")
    fd = os.open(path, os.O_RDWR)
    try:
        # BLKZEROOUT takes two native-endian uint64_t values: offset, length.
        fcntl.ioctl(fd, BLKZEROOUT, struct.pack("=QQ", offset, length))
        os.fsync(fd)
    finally:
        os.close(fd)
    if any(read_range(path, offset, length)):
        raise RuntimeError("WRITE ZEROES completed but nonzero data remained")


def expected_device(transport):
    if transport == "modern":
        return "0x1042"
    if transport == "legacy":
        return "0x1001"
    raise RuntimeError(f"invalid transport: {transport}")


def self_test():
    with tempfile.TemporaryDirectory() as root:
        pci = root + "/sys/bus/pci/devices/0000:00:08.0"
        child = pci + "/virtio4"
        block = child + "/block/vdz"
        driver = root + "/sys/bus/virtio/drivers/virtio_blk"
        os.makedirs(block)
        os.makedirs(driver)
        with open(pci + "/vendor", "w", encoding="ascii") as stream:
            stream.write("0x1af4\n")
        with open(pci + "/device", "w", encoding="ascii") as stream:
            stream.write("0x1042\n")
        features = ["0"] * 64
        for bit, _ in MODERN_REQUIRED_FEATURES:
            features[bit] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        os.symlink(driver, child + "/driver")
        found, found_child = find_bound_block(
            "0x1042", root + "/sys", root + "/dev"
        )
        if found != root + "/dev/vdz" or found_child != child:
            raise AssertionError(
                f"wrong block device: {(found, found_child)!r}"
            )
        require_features(found_child, MODERN_REQUIRED_FEATURES)
        for missing_bit, missing_name in MODERN_REQUIRED_FEATURES:
            missing = features.copy()
            missing[missing_bit] = "0"
            with open(child + "/features", "w", encoding="ascii") as stream:
                stream.write("".join(missing) + "\n")
            try:
                require_features(found_child, MODERN_REQUIRED_FEATURES)
            except RuntimeError:
                pass
            else:
                raise AssertionError(
                    f"missing modern block feature {missing_name} "
                    "was accepted"
                )

        backing = root + "/backing"
        with open(backing, "wb") as stream:
            stream.truncate(2 * CHUNK_SIZE)
        test_size = CHUNK_SIZE + 17
        wanted = write_pattern(backing, test_size)
        if expected_pattern_digest(test_size) != wanted:
            raise AssertionError("pattern digest oracle disagreed with writer")
        if read_digest(backing, test_size) != wanted:
            raise AssertionError("block pattern did not round-trip")
        zero_offset = CHUNK_SIZE - 8
        zero_length = 16
        fd = os.open(backing, os.O_WRONLY)
        try:
            if os.pwrite(fd, b"\0" * zero_length, zero_offset) != zero_length:
                raise AssertionError("short self-test zero write")
        finally:
            os.close(fd)
        zero_digest = expected_pattern_digest(
            test_size, zero_offset, zero_length
        )
        if read_digest(backing, test_size) != zero_digest:
            raise AssertionError("post-zero digest oracle was wrong")

        queue = root + "/sys/class/block/vdz/queue"
        os.makedirs(queue)
        for index in range(4):
            os.makedirs(root + f"/sys/class/block/vdz/mq/{index}")
        with open(
            queue + "/write_zeroes_max_bytes", "w", encoding="ascii"
        ) as stream:
            stream.write(f"{4 * CHUNK_SIZE}\n")
        if (
            require_write_zeroes_limit(
                root + "/dev/vdz", CHUNK_SIZE, root + "/sys"
            )
            != 4 * CHUNK_SIZE
        ):
            raise AssertionError("wrong WRITE ZEROES queue limit")
        try:
            require_write_zeroes_limit(
                root + "/dev/vdz", 8 * CHUNK_SIZE, root + "/sys"
            )
        except RuntimeError:
            pass
        else:
            raise AssertionError("undersized WRITE ZEROES limit was accepted")
        try:
            require_multiqueue(found_child, found, 4, root + "/sys")
        except RuntimeError:
            pass
        else:
            raise AssertionError("missing VIRTIO_BLK_F_MQ was accepted")
        features[VIRTIO_BLK_F_MQ] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        require_multiqueue(
            found_child, found, 4, root + "/sys"
        )
        try:
            require_multiqueue(found_child, found, 3, root + "/sys")
        except RuntimeError:
            pass
        else:
            raise AssertionError("wrong Linux hardware queue count was accepted")
        if zero_test_range(2 * CHUNK_SIZE) != (CHUNK_SIZE, CHUNK_SIZE):
            raise AssertionError("wrong WRITE ZEROES test range")
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) not in (5, 6):
        raise SystemExit(
            "usage: gblock.py --self-test | "
            "write transport bytes queues | "
            "verify transport bytes sha256 queues"
        )
    command, transport, size_text = sys.argv[1:4]
    size = int(size_text)
    expected_queues = int(sys.argv[-1])
    if size <= 0:
        raise RuntimeError("byte count must be positive")
    device, child = find_bound_block(expected_device(transport))
    require_features(child, REQUIRED_FEATURES)
    if transport == "modern":
        require_features(child, MODERN_REQUIRED_FEATURES)
    require_multiqueue(child, device, expected_queues)
    if command == "write" and len(sys.argv) == 5:
        pattern_digest = write_pattern(device, size)
        zero_offset, zero_length = zero_test_range(size)
        expected = expected_pattern_digest(size, zero_offset, zero_length)
        if expected == pattern_digest:
            raise RuntimeError("WRITE ZEROES oracle did not change the checksum")
        zero_limit = require_write_zeroes_limit(device, zero_length)
        issue_write_zeroes(device, zero_offset, zero_length)
        actual = read_digest(device, size)
        if actual != expected:
            raise RuntimeError(
                f"WRITE ZEROES changed unexpected data: {actual} != {expected}"
            )
        print(
            f"PASS block bytes={size} sha256={actual} device={device} "
            f"indirect_desc=yes write_zeroes=yes queues={expected_queues} "
            f"zero_limit={zero_limit}"
        )
    elif command == "verify" and len(sys.argv) == 6:
        wanted = sys.argv[4]
        actual = read_digest(device, size)
        if actual != wanted:
            raise RuntimeError(f"block checksum mismatch: {actual} != {wanted}")
        zero_offset, zero_length = zero_test_range(size)
        if any(read_range(device, zero_offset, zero_length)):
            raise RuntimeError("WRITE ZEROES range did not persist across reboot")
        print(
            f"PASS block-persist bytes={size} sha256={actual} device={device} "
            f"indirect_desc=yes write_zeroes=yes queues={expected_queues}"
        )
    else:
        raise SystemExit("invalid gblock.py command or argument count")


if __name__ == "__main__":
    main()
