#!/usr/bin/env python3
"""Linux guest verifier for a disposable bhyve virtio-scsi LUN."""

import glob
import hashlib
import mmap
import os
import sys
import tempfile


CHUNK_SIZE = 1024 * 1024
DIRECT_ALIGNMENT = 4096
VIRTIO_RING_F_INDIRECT_DESC = 28
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40

REQUIRED_FEATURES = (
    (VIRTIO_RING_F_INDIRECT_DESC, "VIRTIO_RING_F_INDIRECT_DESC"),
)
MODERN_REQUIRED_FEATURES = REQUIRED_FEATURES + (
    (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
    (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
)


def find_bound_scsi(
    expected_device, expected_size, sys_root="/sys", dev_root="/dev"
):
    if expected_size <= 0 or expected_size % 512 != 0:
        raise RuntimeError("SCSI capacity must be a positive multiple of 512")
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
            if not os.path.islink(driver) or os.path.basename(
                os.path.realpath(driver)
            ) != "virtio_scsi":
                continue
            child_path = os.path.realpath(child)
            for block in glob.glob(os.path.join(sys_root, "class/block/*")):
                block_device = block + "/device"
                if not os.path.islink(block_device):
                    continue
                device_path = os.path.realpath(block_device)
                if os.path.commonpath((child_path, device_path)) != child_path:
                    continue
                try:
                    sectors = int(
                        open(block + "/size", encoding="ascii").read().strip()
                    )
                except (OSError, ValueError):
                    continue
                if sectors * 512 == expected_size:
                    matches.append(
                        (
                            os.path.join(dev_root, os.path.basename(block)),
                            child,
                        )
                    )
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {expected_device} virtio_scsi LUN with "
            f"capacity {expected_size}, found {len(matches)}"
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
            raise RuntimeError(f"virtio-scsi did not negotiate {name}")


def require_multiqueue(device, expected, sys_root="/sys"):
    if expected < 1 or expected > 8:
        raise RuntimeError("expected SCSI queue count must be from 1 through 8")
    name = os.path.basename(device)
    mq_path = os.path.join(sys_root, "class/block", name, "mq")
    try:
        queues = [
            entry
            for entry in os.listdir(mq_path)
            if entry.isdigit() and os.path.isdir(os.path.join(mq_path, entry))
        ]
    except OSError as error:
        raise RuntimeError(
            f"cannot inspect Linux SCSI hardware queues at {mq_path}: {error}"
        ) from error
    if len(queues) != expected:
        raise RuntimeError(
            f"Linux exposed {len(queues)} SCSI hardware queues, "
            f"expected {expected}"
        )


def pattern_chunk(counter, size):
    seed = hashlib.sha256(f"bhyve-scsi-{counter}".encode()).digest()
    return (seed * ((size + len(seed) - 1) // len(seed)))[:size]


def write_all(fd, view):
    offset = 0
    while offset < len(view):
        written = os.writev(fd, [view[offset:]])
        if written <= 0:
            raise RuntimeError("short SCSI write")
        offset += written


def pwrite_all(fd, view, offset):
    while view:
        written = os.pwritev(fd, [view], offset)
        if written <= 0:
            raise RuntimeError("short positioned SCSI write")
        view = view[written:]
        offset += written


def expected_pattern_digest(size):
    digest = hashlib.sha256()
    offset = 0
    counter = 0
    while offset < size:
        length = min(CHUNK_SIZE, size - offset)
        digest.update(pattern_chunk(counter, length))
        offset += length
        counter += 1
    return digest.hexdigest()


def write_pattern(path, size, direct=False):
    digest = hashlib.sha256()
    flags = os.O_WRONLY
    if direct:
        flags |= os.O_DIRECT
    fd = os.open(path, flags)
    buffer = mmap.mmap(-1, CHUNK_SIZE)
    view = memoryview(buffer)
    try:
        offset = 0
        counter = 0
        while offset < size:
            length = min(CHUNK_SIZE, size - offset)
            data = pattern_chunk(counter, length)
            view[:length] = data
            write_all(fd, view[:length])
            digest.update(data)
            offset += length
            counter += 1
        os.fsync(fd)
    finally:
        view.release()
        buffer.close()
        os.close(fd)
    return digest.hexdigest()


def write_pattern_parallel(path, size, workers, direct=True, pin_cpus=True):
    if workers < 1:
        raise RuntimeError("parallel SCSI writer count must be positive")
    chunks = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
    workers = min(workers, chunks)
    if pin_cpus:
        try:
            cpus = sorted(os.sched_getaffinity(0))
        except (AttributeError, OSError) as error:
            raise RuntimeError(
                "cannot discover guest CPU affinity for SCSI multiqueue: "
                f"{error}"
            ) from error
        if len(cpus) < workers:
            raise RuntimeError(
                f"SCSI multiqueue needs {workers} available CPUs, "
                f"found {len(cpus)}"
            )
    else:
        cpus = [None] * workers

    children = []
    try:
        for worker in range(workers):
            pid = os.fork()
            if pid != 0:
                children.append(pid)
                continue
            status = 1
            try:
                if cpus[worker] is not None:
                    os.sched_setaffinity(0, {cpus[worker]})
                flags = os.O_WRONLY | (os.O_DIRECT if direct else 0)
                fd = os.open(path, flags)
                buffer = mmap.mmap(-1, CHUNK_SIZE)
                view = memoryview(buffer)
                try:
                    for counter in range(worker, chunks, workers):
                        offset = counter * CHUNK_SIZE
                        length = min(CHUNK_SIZE, size - offset)
                        view[:length] = pattern_chunk(counter, length)
                        pwrite_all(fd, view[:length], offset)
                finally:
                    view.release()
                    buffer.close()
                    os.close(fd)
                status = 0
            except BaseException as error:
                os.write(
                    2,
                    f"SCSI writer {worker} failed: {error}\n".encode(
                        "utf-8", "replace"
                    ),
                )
            finally:
                os._exit(status)
    except OSError as error:
        for pid in children:
            os.waitpid(pid, 0)
        raise RuntimeError(f"cannot start parallel SCSI writers: {error}") from error

    failed = []
    for pid in children:
        _, status = os.waitpid(pid, 0)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            failed.append(pid)
    if failed:
        raise RuntimeError(f"parallel SCSI writers failed: {failed}")
    fd = os.open(path, os.O_WRONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return expected_pattern_digest(size)


def read_digest(path, size, direct=False):
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if direct:
        flags |= os.O_DIRECT
    fd = os.open(path, flags)
    buffer = mmap.mmap(-1, CHUNK_SIZE)
    view = memoryview(buffer)
    try:
        remaining = size
        while remaining:
            wanted = min(CHUNK_SIZE, remaining)
            received = os.readv(fd, [view[:wanted]])
            if received <= 0:
                raise RuntimeError(
                    f"unexpected SCSI EOF with {remaining} bytes remaining"
                )
            digest.update(view[:received])
            remaining -= received
    finally:
        view.release()
        buffer.close()
        os.close(fd)
    return digest.hexdigest()


def expected_pci_device(transport):
    if transport == "modern":
        return "0x1048"
    if transport == "legacy":
        return "0x1004"
    raise RuntimeError(f"invalid transport: {transport}")


def self_test():
    with tempfile.TemporaryDirectory() as root:
        sys_root = root + "/sys"
        pci = sys_root + "/bus/pci/devices/0000:00:09.0"
        child = pci + "/virtio5"
        scsi_device = child + "/host0/target0:0:0/0:0:0:0"
        block = sys_root + "/class/block/vdz"
        driver = sys_root + "/bus/virtio/drivers/virtio_scsi"
        os.makedirs(scsi_device)
        os.makedirs(block)
        os.makedirs(driver)
        with open(pci + "/vendor", "w", encoding="ascii") as stream:
            stream.write("0x1af4\n")
        with open(pci + "/device", "w", encoding="ascii") as stream:
            stream.write("0x1048\n")
        with open(block + "/size", "w", encoding="ascii") as stream:
            stream.write("4096\n")
        for queue in range(4):
            os.makedirs(block + f"/mq/{queue}")
        features = ["0"] * 64
        for bit, _ in MODERN_REQUIRED_FEATURES:
            features[bit] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        os.symlink(driver, child + "/driver")
        os.symlink(scsi_device, block + "/device")
        found, found_child = find_bound_scsi(
            "0x1048", 2 * CHUNK_SIZE, sys_root, root
        )
        if found != root + "/vdz" or found_child != child:
            raise AssertionError(
                f"wrong SCSI device: {(found, found_child)!r}"
            )
        require_features(found_child, MODERN_REQUIRED_FEATURES)
        require_multiqueue(found, 4, sys_root)
        try:
            require_multiqueue(found, 3, sys_root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted the wrong SCSI hardware queue count")
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
                    f"missing modern SCSI feature {missing_name} "
                    "was accepted"
                )
        try:
            find_bound_scsi("0x1048", CHUNK_SIZE, sys_root, root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted the wrong SCSI capacity")

        backing = root + "/backing"
        with open(backing, "wb") as stream:
            stream.truncate(2 * CHUNK_SIZE)
        wanted = write_pattern(backing, CHUNK_SIZE + 17)
        if read_digest(backing, CHUNK_SIZE + 17) != wanted:
            raise AssertionError("SCSI pattern did not round-trip")
        with open(backing, "wb") as stream:
            stream.truncate(2 * CHUNK_SIZE)
        wanted = write_pattern_parallel(
            backing, CHUNK_SIZE + 17, 2, direct=False, pin_cpus=False
        )
        if read_digest(backing, CHUNK_SIZE + 17) != wanted:
            raise AssertionError("parallel SCSI pattern did not round-trip")
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) not in (6, 7):
        raise SystemExit(
            "usage: gscsi.py --self-test | "
            "write transport capacity bytes queues | "
            "verify transport capacity bytes sha256 queues"
        )
    command, transport, capacity_text, size_text = sys.argv[1:5]
    capacity = int(capacity_text)
    size = int(size_text)
    expected_queues = int(sys.argv[-1])
    if size <= 0 or size > capacity:
        raise RuntimeError("require 0 < byte count <= SCSI capacity")
    if size % DIRECT_ALIGNMENT != 0:
        raise RuntimeError(
            f"SCSI direct-I/O byte count must be a multiple of "
            f"{DIRECT_ALIGNMENT}"
        )
    device, child = find_bound_scsi(expected_pci_device(transport), capacity)
    require_features(child, REQUIRED_FEATURES)
    if transport == "modern":
        require_features(child, MODERN_REQUIRED_FEATURES)
    require_multiqueue(device, expected_queues)
    if command == "write" and len(sys.argv) == 6:
        if expected_queues > 1:
            wanted = write_pattern_parallel(device, size, expected_queues)
        else:
            wanted = write_pattern(device, size, direct=True)
        actual = read_digest(device, size, direct=True)
        if actual != wanted:
            raise RuntimeError(f"SCSI checksum mismatch: {actual} != {wanted}")
        print(
            f"PASS scsi bytes={size} sha256={actual} device={device} "
            f"indirect_desc=yes queues={expected_queues}"
        )
    elif command == "verify" and len(sys.argv) == 7:
        wanted = sys.argv[5]
        actual = read_digest(device, size, direct=True)
        if actual != wanted:
            raise RuntimeError(f"SCSI checksum mismatch: {actual} != {wanted}")
        print(
            f"PASS scsi-persist bytes={size} sha256={actual} device={device} "
            f"indirect_desc=yes queues={expected_queues}"
        )
    else:
        raise SystemExit("invalid gscsi.py command or argument count")


if __name__ == "__main__":
    main()
