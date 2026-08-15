#!/usr/bin/env python3
"""Linux guest verifier for a disposable bhyve virtio-blk device."""

import errno
import fcntl
import glob
import hashlib
import os
import stat
import struct
import sys
import tempfile
import time

# Release-ledger anchors for the data-path checks performed by this verifier.
# VIRTIO_ACTIVATION_ASSERTION: packed-negotiation-and-write-read-digest
# VIRTIO_ACTIVATION_ASSERTION: queue-count-write-read-digest
# VIRTIO_ACTIVATION_ASSERTION: write-zeroes-and-readback
# VIRTIO_ACTIVATION_ASSERTION: discard-submit-followup-write-readback
# VIRTIO_ACTIVATION_ASSERTION: cache-mode-transition
# VIRTIO_ACTIVATION_ASSERTION: readonly-read-and-write-rejection
# VIRTIO_ACTIVATION_ASSERTION: notification-data-negotiated-and-io
# VIRTIO_ACTIVATION_ASSERTION: notification-config-data-negotiated-and-io


CHUNK_SIZE = 1024 * 1024
SECTOR_SIZE = 512
# Linux UAPI include/uapi/linux/fs.h: _IO(0x12, 127).
BLKZEROOUT = 0x127F
# Linux UAPI include/uapi/linux/fs.h: _IO(0x12, 119).
BLKDISCARD = 0x1277
VIRTIO_BLK_F_WRITE_ZEROES = 14
VIRTIO_BLK_F_DISCARD = 13
VIRTIO_BLK_F_RO = 5
VIRTIO_BLK_F_CONFIG_WCE = 11
VIRTIO_BLK_F_MQ = 12
VIRTIO_RING_F_INDIRECT_DESC = 28
VIRTIO_F_RING_PACKED = 34
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_NOTIF_CONFIG_DATA = 39
VIRTIO_F_RING_RESET = 40

REQUIRED_FEATURES = (
    (VIRTIO_BLK_F_WRITE_ZEROES, "VIRTIO_BLK_F_WRITE_ZEROES"),
    (VIRTIO_RING_F_INDIRECT_DESC, "VIRTIO_RING_F_INDIRECT_DESC"),
)
MODERN_REQUIRED_FEATURES = REQUIRED_FEATURES + (
    (VIRTIO_BLK_F_CONFIG_WCE, "VIRTIO_BLK_F_CONFIG_WCE"),
    (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
    (VIRTIO_F_NOTIF_CONFIG_DATA, "VIRTIO_F_NOTIF_CONFIG_DATA"),
    (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
)
READONLY_REQUIRED_FEATURES = (
    (VIRTIO_BLK_F_RO, "VIRTIO_BLK_F_RO"),
    (VIRTIO_RING_F_INDIRECT_DESC, "VIRTIO_RING_F_INDIRECT_DESC"),
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


def wait_bound_block(
    expected_device,
    sys_root="/sys",
    dev_root="/dev",
    timeout=30.0,
    require_block_device=True,
):
    """Wait for both the rebound VirtIO child and its device node.

    Linux publishes the PCI/virtio driver links before a userspace device
    manager necessarily recreates /dev/vdX.  Reset soak must not classify
    that ordinary asynchronous publication window as a block-device failure.
    """
    deadline = time.monotonic() + timeout
    last_error = None
    while True:
        try:
            device, child = find_bound_block(
                expected_device, sys_root, dev_root
            )
            try:
                node = os.stat(device)
            except OSError:
                node = None
            if node is not None and (
                not require_block_device or stat.S_ISBLK(node.st_mode)
            ):
                # A devfs entry can transiently exist while its backing
                # device is still being withdrawn or published after a PCI
                # rebind.  Do one nonblocking, side-effect-free open before
                # returning the path.  This is a readiness boundary, not an
                # I/O retry: callers still fail their real request normally
                # if the reset later makes the device unavailable.
                try:
                    fd = os.open(device, os.O_RDONLY | os.O_NONBLOCK)
                except OSError as error:
                    last_error = RuntimeError(
                        f"bound virtio-blk device is not openable: "
                        f"{device}: {error}"
                    )
                else:
                    os.close(fd)
                    return device, child
            else:
                suffix = ""
                if node is not None and require_block_device:
                    suffix = " (not a block device)"
                last_error = RuntimeError(
                    f"bound virtio-blk device node is not ready: "
                    f"{device}{suffix}"
                )
        except RuntimeError as error:
            last_error = error
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"timed out waiting for rebound virtio-blk: {last_error}"
            ) from last_error
        time.sleep(0.1)


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


def require_ring_format(child, transport, packed):
    negotiated = negotiated_feature(child, VIRTIO_F_RING_PACKED)
    if packed and transport != "modern":
        raise RuntimeError("packed virtio-blk requires the modern transport")
    if negotiated != packed:
        wanted = "packed" if packed else "split"
        actual = "packed" if negotiated else "split"
        raise RuntimeError(
            f"virtio-blk negotiated {actual} rings, expected {wanted}"
        )


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


def exercise_write_cache(device, sys_root="/sys"):
    name = os.path.basename(device)
    path = os.path.join(sys_root, "class/block", name, "cache_type")

    def read_mode():
        try:
            with open(path, "r", encoding="ascii") as stream:
                return stream.read().strip()
        except OSError as error:
            raise RuntimeError(f"cannot read {path}: {error}") from error

    def write_mode(mode):
        try:
            with open(path, "w", encoding="ascii") as stream:
                stream.write(mode + "\n")
        except OSError as error:
            raise RuntimeError(
                f"cannot set virtio-blk cache mode to {mode}: {error}"
            ) from error

    if read_mode() != "write back":
        raise RuntimeError("virtio-blk did not start in writeback mode")
    write_mode("write through")
    if read_mode() != "write through":
        raise RuntimeError("virtio-blk did not enter writethrough mode")
    write_mode("write back")
    if read_mode() != "write back":
        raise RuntimeError("virtio-blk did not return to writeback mode")
    write_mode("write through")
    if read_mode() != "write through":
        raise RuntimeError("virtio-blk did not finish in writethrough mode")


def exercise_readonly(device, child, size):
    require_features(child, READONLY_REQUIRED_FEATURES)
    for bit, name in (
        (VIRTIO_BLK_F_DISCARD, "VIRTIO_BLK_F_DISCARD"),
        (VIRTIO_BLK_F_WRITE_ZEROES, "VIRTIO_BLK_F_WRITE_ZEROES"),
    ):
        if negotiated_feature(child, bit):
            raise RuntimeError(f"read-only virtio-blk negotiated {name}")
    probe_length = min(size, CHUNK_SIZE)
    if probe_length <= 0 or len(read_range(device, 0, probe_length)) != probe_length:
        raise RuntimeError("read-only virtio-blk read did not complete")
    try:
        fd = os.open(device, os.O_WRONLY)
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM, errno.EROFS):
            raise RuntimeError(
                f"read-only virtio-blk write open failed unexpectedly: {error}"
            ) from error
    else:
        try:
            try:
                os.pwrite(fd, b"\x5a" * SECTOR_SIZE, 0)
            except OSError as error:
                if error.errno not in (errno.EACCES, errno.EPERM, errno.EROFS):
                    raise RuntimeError(
                        "read-only virtio-blk write failed unexpectedly: "
                        f"{error}"
                    ) from error
            else:
                raise RuntimeError("read-only virtio-blk accepted a write")
        finally:
            os.close(fd)


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


def pwrite_all(fd, data, offset):
    """Write an exact range without depending on a shared file offset."""
    view = memoryview(data)
    while view:
        written = os.pwrite(fd, view, offset)
        if written <= 0:
            raise RuntimeError("short positioned block-device write")
        offset += written
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


def expected_pattern_digest(
    size, zero_offset=None, zero_length=0, extra_zero_ranges=()
):
    digest = hashlib.sha256()
    offset = 0
    counter = 0
    zero_ranges = list(extra_zero_ranges)
    if zero_offset is not None:
        zero_ranges.append((zero_offset, zero_length))
    while offset < size:
        length = min(CHUNK_SIZE, size - offset)
        data = bytearray(pattern_chunk(counter, length))
        for range_offset, range_length in zero_ranges:
            overlap_start = max(offset, range_offset)
            overlap_end = min(
                offset + length, range_offset + range_length
            )
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


def discard_test_range(size):
    length = CHUNK_SIZE
    offset = 2 * CHUNK_SIZE
    if size < offset + length:
        raise RuntimeError(
            f"block byte count {size} is too small for DISCARD test"
        )
    return offset, length


def require_queue_limit(device, attribute, operation, length, sys_root="/sys"):
    name = os.path.basename(device)
    limit_path = os.path.join(
        sys_root, "class/block", name, "queue", attribute
    )
    try:
        limit_text = open(limit_path, encoding="ascii").read().strip()
        limit = int(limit_text)
    except (OSError, ValueError) as error:
        raise RuntimeError(
            f"cannot read valid {operation} limit from {limit_path}: {error}"
        ) from error
    if limit < length:
        raise RuntimeError(
            f"Linux {operation} limit {limit} is below test length {length}"
        )
    return limit


def require_write_zeroes_limit(device, length, sys_root="/sys"):
    return require_queue_limit(
        device, "write_zeroes_max_bytes", "WRITE ZEROES", length, sys_root
    )


def require_discard_limit(device, length, sys_root="/sys"):
    return require_queue_limit(
        device, "discard_max_bytes", "DISCARD", length, sys_root
    )


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


def issue_discard(path, offset, length):
    if offset % SECTOR_SIZE or length % SECTOR_SIZE:
        raise RuntimeError("DISCARD range is not sector aligned")
    before = read_range(path, offset, length)
    if not any(before):
        raise RuntimeError("DISCARD test range was already all zero")
    fd = os.open(path, os.O_RDWR)
    try:
        # BLKDISCARD takes two native-endian uint64_t values: offset, length.
        fcntl.ioctl(fd, BLKDISCARD, struct.pack("=QQ", offset, length))
        os.fsync(fd)
    finally:
        os.close(fd)


def overwrite_zero_range(path, offset, length):
    """Create deterministic data after DISCARD without defining its readback.

    VirtIO DISCARD requests backend deallocation; it does not make a
    zero-filled readback part of the device contract.  Do an ordinary write
    after a successful DISCARD so the whole-device digest remains a portable
    data-path check rather than an assertion about sparse-file read semantics.
    """
    fd = os.open(path, os.O_WRONLY)
    try:
        remaining = length
        position = offset
        zeros = b"\0" * min(CHUNK_SIZE, remaining)
        while remaining:
            chunk = zeros[:min(len(zeros), remaining)]
            pwrite_all(fd, chunk, position)
            position += len(chunk)
            remaining -= len(chunk)
        os.fsync(fd)
    finally:
        os.close(fd)
    if any(read_range(path, offset, length)):
        raise RuntimeError("post-DISCARD deterministic write did not persist")


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
        os.makedirs(root + "/dev")
        with open(root + "/dev/vdz", "wb"):
            pass
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
        # The synthetic fixture intentionally uses a regular file.  Live
        # verification retains the default block-special-file requirement.
        waited, waited_child = wait_bound_block(
            "0x1042",
            root + "/sys",
            root + "/dev",
            timeout=0,
            require_block_device=False,
        )
        if waited != found or waited_child != found_child:
            raise AssertionError(
                f"wrong waited block device: {(waited, waited_child)!r}"
            )
        # Rebind can publish the virtio child before the device manager
        # recreates /dev/vdX.  The wait helper must make that state a bounded,
        # diagnostic failure instead of returning a path that a later I/O
        # operation reports as a misleading ENOENT.
        try:
            wait_bound_block("0x1042", root + "/sys", root + "/dev",
                timeout=0)
        except RuntimeError as error:
            if "not a block device" not in str(error):
                raise AssertionError(f"wrong non-block-node error: {error!r}")
        else:
            raise AssertionError("accepted regular file as rebound block device")
        os.unlink(found)
        try:
            wait_bound_block("0x1042", root + "/sys", root + "/dev",
                timeout=0, require_block_device=False)
        except RuntimeError as error:
            if "device node is not ready" not in str(error):
                raise AssertionError(f"wrong missing-node error: {error!r}")
        else:
            raise AssertionError("accepted rebound block without device node")
        with open(found, "wb"):
            pass
        original_open = os.open

        def reject_rebound_open(path, flags):
            if path == found:
                raise OSError(errno.ENXIO, "synthetic withdrawing device")
            return original_open(path, flags)

        os.open = reject_rebound_open
        try:
            wait_bound_block(
                "0x1042",
                root + "/sys",
                root + "/dev",
                timeout=0,
                require_block_device=False,
            )
        except RuntimeError as error:
            if "not openable" not in str(error):
                raise AssertionError(f"wrong unopened-node error: {error!r}")
        else:
            raise AssertionError("accepted an unopened rebound block device")
        finally:
            os.open = original_open
        require_features(found_child, MODERN_REQUIRED_FEATURES)
        require_ring_format(found_child, "modern", False)
        features[VIRTIO_F_RING_PACKED] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        require_ring_format(found_child, "modern", True)
        try:
            require_ring_format(found_child, "legacy", True)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted packed rings on legacy virtio-blk")
        features[VIRTIO_F_RING_PACKED] = "0"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
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
        readonly = features.copy()
        readonly[VIRTIO_BLK_F_DISCARD] = "0"
        readonly[VIRTIO_BLK_F_WRITE_ZEROES] = "0"
        readonly[VIRTIO_BLK_F_RO] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(readonly) + "\n")
        require_features(found_child, READONLY_REQUIRED_FEATURES)
        if negotiated_feature(found_child, VIRTIO_BLK_F_DISCARD):
            raise AssertionError("read-only fixture retained DISCARD")
        if negotiated_feature(found_child, VIRTIO_BLK_F_WRITE_ZEROES):
            raise AssertionError("read-only fixture retained WRITE ZEROES")
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")

        backing = root + "/backing"
        with open(backing, "wb") as stream:
            stream.truncate(4 * CHUNK_SIZE)
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
        multi_size = 4 * CHUNK_SIZE
        multi_wanted = write_pattern(backing, multi_size)
        zero_range = zero_test_range(multi_size)
        discard_range = discard_test_range(multi_size)
        fd = os.open(backing, os.O_WRONLY)
        try:
            for range_offset, range_length in (zero_range, discard_range):
                if os.pwrite(
                    fd, b"\0" * range_length, range_offset
                ) != range_length:
                    raise AssertionError("short self-test range write")
        finally:
            os.close(fd)
        multi_expected = expected_pattern_digest(
            multi_size,
            zero_range[0],
            zero_range[1],
            (discard_range,),
        )
        if multi_expected == multi_wanted:
            raise AssertionError("multi-range digest oracle did not change")
        if read_digest(backing, multi_size) != multi_expected:
            raise AssertionError("multi-range digest oracle was wrong")

        queue = root + "/sys/class/block/vdz/queue"
        os.makedirs(queue)
        for index in range(4):
            os.makedirs(root + f"/sys/class/block/vdz/mq/{index}")
        with open(
            queue + "/write_zeroes_max_bytes", "w", encoding="ascii"
        ) as stream:
            stream.write(f"{4 * CHUNK_SIZE}\n")
        with open(
            queue + "/discard_max_bytes", "w", encoding="ascii"
        ) as stream:
            stream.write(f"{8 * CHUNK_SIZE}\n")
        with open(
            root + "/sys/class/block/vdz/cache_type",
            "w",
            encoding="ascii",
        ) as stream:
            stream.write("write back\n")
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
        if (
            require_discard_limit(
                root + "/dev/vdz", CHUNK_SIZE, root + "/sys"
            )
            != 8 * CHUNK_SIZE
        ):
            raise AssertionError("wrong DISCARD queue limit")
        try:
            require_discard_limit(
                root + "/dev/vdz", 16 * CHUNK_SIZE, root + "/sys"
            )
        except RuntimeError:
            pass
        else:
            raise AssertionError("undersized DISCARD limit was accepted")
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
        exercise_write_cache(found, root + "/sys")
        try:
            require_multiqueue(found_child, found, 3, root + "/sys")
        except RuntimeError:
            pass
        else:
            raise AssertionError("wrong Linux hardware queue count was accepted")
        if zero_test_range(2 * CHUNK_SIZE) != (CHUNK_SIZE, CHUNK_SIZE):
            raise AssertionError("wrong WRITE ZEROES test range")
        if discard_test_range(3 * CHUNK_SIZE) != (
            2 * CHUNK_SIZE,
            CHUNK_SIZE,
        ):
            raise AssertionError("wrong DISCARD test range")
        scratch = root + "/discard-scratch"
        with open(scratch, "wb") as stream:
            stream.write(b"\x5a" * (2 * SECTOR_SIZE))
        original_ioctl = fcntl.ioctl
        original_read_range = read_range
        discard_issued = False

        def synthetic_discard_ioctl(fd, request, argument):
            nonlocal discard_issued
            if request != BLKDISCARD or argument != struct.pack(
                "=QQ", 0, SECTOR_SIZE
            ):
                raise AssertionError("wrong BLKDISCARD request")
            discard_issued = True

        def reject_post_discard_read(path, offset, length):
            if discard_issued:
                raise AssertionError("DISCARD assumed a readback value")
            return original_read_range(path, offset, length)

        fcntl.ioctl = synthetic_discard_ioctl
        globals()["read_range"] = reject_post_discard_read
        try:
            issue_discard(scratch, 0, SECTOR_SIZE)
        finally:
            fcntl.ioctl = original_ioctl
            globals()["read_range"] = original_read_range
        if not discard_issued:
            raise AssertionError("DISCARD ioctl was not issued")
        overwrite_zero_range(scratch, 0, SECTOR_SIZE)
        if read_range(scratch, 0, SECTOR_SIZE) != b"\0" * SECTOR_SIZE:
            raise AssertionError("post-DISCARD deterministic write failed")

        # The deterministic post-DISCARD write must also handle a backend
        # which completes positioned writes only partially.  This is a
        # userspace I/O property, independent of the block device's discard
        # readback semantics, so exercise the exact retry loop directly.
        original_pwrite = os.pwrite
        partial_scratch = root + "/partial-pwrite-scratch"

        def partial_pwrite(fd, data, offset):
            return original_pwrite(fd, data[:7], offset)

        fd = os.open(partial_scratch, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600)
        os.pwrite = partial_pwrite
        try:
            pwrite_all(fd, b"partial-positioned-write", 3)
            os.fsync(fd)
        finally:
            os.pwrite = original_pwrite
            os.close(fd)
        if read_range(partial_scratch, 3,
            len(b"partial-positioned-write")) != b"partial-positioned-write":
            raise AssertionError("partial positioned write was not completed")
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    arguments = sys.argv[1:]
    options = set()
    while arguments[-1:] and arguments[-1] in ("discard", "packed"):
        option = arguments[-1]
        if option in options:
            raise SystemExit(f"duplicate gblock.py option: {option}")
        options.add(option)
        arguments = arguments[:-1]
    packed = "packed" in options
    discard = "discard" in options
    if len(arguments) not in (4, 5):
        raise SystemExit(
            "usage: gblock.py --self-test | "
            "write transport bytes queues [packed] [discard] | "
            "verify transport bytes sha256 queues [packed] [discard] | "
            "readonly transport bytes queues [packed]"
        )
    command, transport, size_text = arguments[:3]
    size = int(size_text)
    expected_queues = int(arguments[-1])
    if size <= 0:
        raise RuntimeError("byte count must be positive")
    device, child = wait_bound_block(expected_device(transport))
    if command == "readonly" and discard:
        raise RuntimeError("read-only block test cannot request DISCARD")
    if command == "readonly":
        require_features(child, READONLY_REQUIRED_FEATURES)
        if transport == "modern":
            require_features(
                child,
                (
                    (
                        VIRTIO_F_NOTIFICATION_DATA,
                        "VIRTIO_F_NOTIFICATION_DATA",
                    ),
                    (
                        VIRTIO_F_NOTIF_CONFIG_DATA,
                        "VIRTIO_F_NOTIF_CONFIG_DATA",
                    ),
                    (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
                ),
            )
    else:
        require_features(child, REQUIRED_FEATURES)
        if discard:
            require_features(
                child,
                ((VIRTIO_BLK_F_DISCARD, "VIRTIO_BLK_F_DISCARD"),),
            )
        if transport == "modern":
            require_features(child, MODERN_REQUIRED_FEATURES)
    require_ring_format(child, transport, packed)
    require_multiqueue(child, device, expected_queues)
    if transport == "modern" and command != "readonly":
        exercise_write_cache(device)
    if command == "readonly" and len(arguments) == 4:
        exercise_readonly(device, child, size)
        print(
            f"PASS block-readonly bytes={size} device={device} "
            f"read=yes write_rejected=yes queues={expected_queues} "
            f"packed={'yes' if packed else 'no'}"
        )
    elif command == "write" and len(arguments) == 4:
        pattern_digest = write_pattern(device, size)
        zero_offset, zero_length = zero_test_range(size)
        discard_ranges = ()
        if discard:
            discard_offset, discard_length = discard_test_range(size)
            discard_ranges = ((discard_offset, discard_length),)
        expected = expected_pattern_digest(
            size,
            zero_offset,
            zero_length,
            discard_ranges,
        )
        if expected == pattern_digest:
            raise RuntimeError(
                "WRITE ZEROES/DISCARD oracle did not change the checksum"
            )
        zero_limit = require_write_zeroes_limit(device, zero_length)
        issue_write_zeroes(device, zero_offset, zero_length)
        discard_limit = 0
        if discard:
            discard_limit = require_discard_limit(device, discard_length)
            issue_discard(device, discard_offset, discard_length)
            overwrite_zero_range(device, discard_offset, discard_length)
        actual = read_digest(device, size)
        if actual != expected:
            raise RuntimeError(
                f"WRITE ZEROES changed unexpected data: {actual} != {expected}"
            )
        print(
            f"PASS block bytes={size} sha256={actual} device={device} "
            f"indirect_desc=yes write_zeroes=yes "
            f"discard={'yes' if discard else 'no'} "
            f"queues={expected_queues} zero_limit={zero_limit} "
            f"discard_limit={discard_limit} "
            f"packed={'yes' if packed else 'no'} "
            f"notif_config_data={'yes' if transport == 'modern' else 'n/a'}"
        )
    elif command == "verify" and len(arguments) == 5:
        wanted = arguments[3]
        actual = read_digest(device, size)
        if actual != wanted:
            raise RuntimeError(f"block checksum mismatch: {actual} != {wanted}")
        zero_offset, zero_length = zero_test_range(size)
        if any(read_range(device, zero_offset, zero_length)):
            raise RuntimeError("WRITE ZEROES range did not persist across reboot")
        if discard:
            discard_offset, discard_length = discard_test_range(size)
            if any(read_range(device, discard_offset, discard_length)):
                raise RuntimeError("DISCARD range did not persist across reboot")
        print(
            f"PASS block-persist bytes={size} sha256={actual} device={device} "
            f"indirect_desc=yes write_zeroes=yes "
            f"discard={'yes' if discard else 'no'} "
            f"queues={expected_queues} "
            f"packed={'yes' if packed else 'no'} "
            f"notif_config_data={'yes' if transport == 'modern' else 'n/a'}"
        )
    else:
        raise SystemExit("invalid gblock.py command or argument count")


if __name__ == "__main__":
    main()
