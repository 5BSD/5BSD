#!/usr/bin/env python3
"""Linux guest end-to-end verifier for bhyve's VirtIO GPU 2D device."""

# VIRTIO_ACTIVATION_ASSERTION: active-checkpoint-gpu-framebuffer

import glob
import os
import signal
import sys
import tempfile
import time

# VirtIO 1.4 common feature allocation (§6).
VIRTIO_GPU_F_EDID = 1
VIRTIO_GPU_F_RESOURCE_BLOB = 3
VIRTIO_GPU_F_BLOB_ALIGNMENT = 5
VIRTIO_F_RING_PACKED = 34
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40
MODERN_DEVICE = "0x1050"  # 0x1040 + VirtIO device ID 16.
RUNNING = True
DISPLAY_FIRST_PIXEL = bytes((0x13, 0x57, 0x9B, 0x00))
DISPLAY_LAST_PIXEL = bytes((0x24, 0x68, 0xAC, 0x00))


def stop(_signum, _frame):
    global RUNNING
    RUNNING = False


def atomic_count(path, count):
    temporary = path + ".new"
    with open(temporary, "w", encoding="ascii") as stream:
        stream.write(f"{count}\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def checkpoint_pattern(count, amount):
    return bytes(
        ((index * 37) + (count * 53) + 11) & 0xFF
        for index in range(amount)
    )


def framebuffer_geometry(framebuffer):
    try:
        virtual_size = open(
            framebuffer + "/virtual_size", encoding="ascii"
        ).read().strip()
        bits_per_pixel = int(
            open(
                framebuffer + "/bits_per_pixel", encoding="ascii"
            ).read().strip(),
            10,
        )
        stride = int(
            open(framebuffer + "/stride", encoding="ascii").read().strip(),
            10,
        )
    except (OSError, ValueError) as error:
        raise RuntimeError(f"invalid framebuffer metadata: {error}") from error
    try:
        width, height = (int(value, 10) for value in virtual_size.split(","))
    except (ValueError, TypeError) as error:
        raise RuntimeError(
            f"invalid framebuffer virtual_size: {virtual_size!r}"
        ) from error
    if width <= 0 or height <= 0 or bits_per_pixel != 32:
        raise RuntimeError(
            "invalid framebuffer geometry: "
            f"size={virtual_size!r} bpp={bits_per_pixel}"
        )
    if stride < width * 4:
        raise RuntimeError(
            f"invalid framebuffer stride: {stride} for width {width}"
        )
    return width, height, stride


def negotiated_feature(child, bit):
    path = child + "/features"
    try:
        features = open(path, encoding="ascii").read().strip()
    except OSError as error:
        raise RuntimeError(f"cannot read {path}: {error}") from error
    if len(features) <= bit or any(value not in "01" for value in features):
        raise RuntimeError(f"invalid virtio feature bitmap: {features!r}")
    return features[bit] == "1"


def validate_modes(status, modes, expected_mode):
    if status != "connected":
        raise RuntimeError(f"virtio-gpu connector is {status!r}, not connected")
    listed = [mode.strip() for mode in modes.splitlines() if mode.strip()]
    if expected_mode not in listed:
        raise RuntimeError(
            f"virtio-gpu connector lacks {expected_mode}: {listed!r}"
        )


def validate_edid(edid, expected_mode):
    if len(edid) < 128 or len(edid) % 128 != 0:
        raise RuntimeError(f"invalid EDID length: {len(edid)}")
    if edid[:8] != b"\x00\xff\xff\xff\xff\xff\xff\x00":
        raise RuntimeError("invalid EDID header")
    if sum(edid[:128]) & 0xFF:
        raise RuntimeError("invalid EDID base-block checksum")
    hactive = edid[56] | ((edid[58] & 0xF0) << 4)
    vactive = edid[59] | ((edid[61] & 0xF0) << 4)
    if f"{hactive}x{vactive}" != expected_mode:
        raise RuntimeError(
            f"EDID preferred mode is {hactive}x{vactive}, "
            f"expected {expected_mode}"
        )


def find_bound_gpu():
    matches = []
    for pci in glob.glob("/sys/bus/pci/devices/*"):
        try:
            vendor = open(pci + "/vendor", encoding="ascii").read().strip()
            device = open(pci + "/device", encoding="ascii").read().strip()
        except OSError:
            continue
        if vendor != "0x1af4" or device != MODERN_DEVICE:
            continue
        for child in glob.glob(pci + "/virtio*"):
            driver = child + "/driver"
            if os.path.islink(driver) and os.path.basename(
                os.path.realpath(driver)
            ) == "virtio_gpu":
                matches.append((pci, child))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {MODERN_DEVICE} device bound to virtio_gpu, "
            f"found {len(matches)}"
        )
    return matches[0]


def find_connector(child):
    matches = []
    child_real = os.path.realpath(child)
    for connector in glob.glob("/sys/class/drm/card*-*"):
        if not os.path.isfile(connector + "/status"):
            continue
        device = connector + "/device"
        if os.path.realpath(device) == child_real:
            matches.append(connector)
    if len(matches) != 1:
        raise RuntimeError(
            "expected one DRM connector for the virtio-gpu device, "
            f"found {len(matches)}"
        )
    return matches[0]


def find_framebuffer(child, sys_root="/sys", dev_root="/dev"):
    child_real = os.path.realpath(child)
    matches = []
    for framebuffer in glob.glob(sys_root + "/class/graphics/fb[0-9]*"):
        device_real = os.path.realpath(framebuffer + "/device")
        if device_real != child_real and not device_real.startswith(
            child_real + os.sep
        ):
            continue
        node = dev_root + "/" + os.path.basename(framebuffer)
        if os.path.exists(node):
            matches.append((framebuffer, node))
    if len(matches) != 1:
        raise RuntimeError(
            "expected one framebuffer for the virtio-gpu device, "
            f"found {matches!r}"
        )
    return matches[0]


def exercise_framebuffer(child, width, height, sys_root="/sys", dev_root="/dev"):
    framebuffer, node = find_framebuffer(child, sys_root, dev_root)
    actual_width, actual_height, stride = framebuffer_geometry(framebuffer)
    if (actual_width, actual_height) != (width, height):
        raise RuntimeError(
            "framebuffer size is "
            f"{actual_width},{actual_height}, expected {width},{height}"
        )

    amount = min(stride, 4096)
    first_marker_offset = (width - 1) * 4
    first = bytearray((index * 17 + 3) & 0xFF for index in range(amount))
    if first_marker_offset + 4 <= amount:
        first[first_marker_offset:first_marker_offset + 4] = \
            DISPLAY_FIRST_PIXEL
    first = bytes(first)
    last = bytes((index * 29 + 7) & 0xFF for index in range(amount))
    # The host RFB verifier checks these two pixels after the guest-side
    # readback.  Linux's fbdev emulation exposes XRGB8888 here, whose
    # little-endian memory representation is B, G, R, X.
    last = DISPLAY_LAST_PIXEL + last[len(DISPLAY_LAST_PIXEL):]
    fd = os.open(node, os.O_RDWR)
    try:
        last_offset = (height - 1) * stride
        if os.pwrite(fd, first, 0) != len(first):
            raise RuntimeError("short write to first framebuffer row")
        if os.pwrite(fd, last, last_offset) != len(last):
            raise RuntimeError("short write to last framebuffer row")
        if os.pwrite(fd, DISPLAY_FIRST_PIXEL, first_marker_offset) != 4:
            raise RuntimeError("short write to first-row boundary pixel")
        if os.pread(fd, len(first), 0) != first:
            raise RuntimeError("first framebuffer row did not retain pixels")
        if os.pread(fd, len(last), last_offset) != last:
            raise RuntimeError("last framebuffer row did not retain pixels")
        if os.pread(fd, 4, first_marker_offset) != DISPLAY_FIRST_PIXEL:
            raise RuntimeError("first-row boundary pixel did not retain data")
    finally:
        os.close(fd)
    return os.path.basename(framebuffer)


def checkpoint_worker(child, width, height, count_path, control_path):
    framebuffer, node = find_framebuffer(child)
    actual_width, actual_height, stride = framebuffer_geometry(framebuffer)
    if (actual_width, actual_height) != (width, height):
        raise RuntimeError(
            "framebuffer size changed before checkpoint workload: "
            f"{actual_width},{actual_height}"
        )
    amount = min(stride, 4096)
    offset = (height - 1) * stride
    fd = os.open(node, os.O_RDWR)
    count = 1
    try:
        pattern = checkpoint_pattern(count, amount)
        if os.pwrite(fd, pattern, offset) != amount:
            raise RuntimeError("short initial checkpoint framebuffer write")
        if os.pread(fd, amount, offset) != pattern:
            raise RuntimeError("initial checkpoint framebuffer marker lost")
        atomic_count(count_path, count)
        while RUNNING:
            try:
                requested_text = open(
                    control_path, encoding="ascii"
                ).read().strip()
                requested = int(requested_text, 10)
            except FileNotFoundError:
                requested = count
            except (OSError, ValueError) as error:
                raise RuntimeError(
                    f"invalid checkpoint control file: {error}"
                ) from error
            if requested > count:
                old_pattern = checkpoint_pattern(count, amount)
                if os.pread(fd, amount, offset) != old_pattern:
                    raise RuntimeError(
                        "checkpoint framebuffer marker was not restored"
                    )
                new_pattern = checkpoint_pattern(requested, amount)
                if os.pwrite(fd, new_pattern, offset) != amount:
                    raise RuntimeError(
                        "short resumed checkpoint framebuffer write"
                    )
                if os.pread(fd, amount, offset) != new_pattern:
                    raise RuntimeError(
                        "resumed checkpoint framebuffer marker lost"
                    )
                count = requested
                atomic_count(count_path, count)
            time.sleep(0.01)
    finally:
        os.close(fd)


def self_test():
    with tempfile.TemporaryDirectory() as root:
        sys_root = root + "/sys"
        child = sys_root + "/devices/pci0/virtio0"
        os.makedirs(child)
        features = ["0"] * 64
        features[VIRTIO_GPU_F_EDID] = "1"
        features[VIRTIO_GPU_F_RESOURCE_BLOB] = "1"
        features[VIRTIO_GPU_F_BLOB_ALIGNMENT] = "1"
        features[VIRTIO_F_NOTIFICATION_DATA] = "1"
        features[VIRTIO_F_RING_RESET] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        assert negotiated_feature(child, VIRTIO_F_NOTIFICATION_DATA)
        assert negotiated_feature(child, VIRTIO_F_RING_RESET)
        assert negotiated_feature(child, VIRTIO_GPU_F_EDID)
        assert negotiated_feature(child, VIRTIO_GPU_F_RESOURCE_BLOB)
        assert negotiated_feature(child, VIRTIO_GPU_F_BLOB_ALIGNMENT)
        assert not negotiated_feature(child, VIRTIO_F_RING_PACKED)
        validate_modes("connected", "800x600\n1024x768\n", "1024x768")
        edid = bytearray(128)
        edid[:8] = b"\x00\xff\xff\xff\xff\xff\xff\x00"
        edid[56] = 0
        edid[58] = 0x40
        edid[59] = 0
        edid[61] = 0x30
        edid[127] = (-sum(edid[:127])) & 0xFF
        validate_edid(edid, "1024x768")
        framebuffer = sys_root + "/class/graphics/fb3"
        os.makedirs(framebuffer)
        os.symlink(child, framebuffer + "/device")
        for name, value in (
            ("virtual_size", "1024,768\n"),
            ("bits_per_pixel", "32\n"),
            ("stride", "4096\n"),
        ):
            with open(framebuffer + "/" + name, "w", encoding="ascii") as stream:
                stream.write(value)
        dev_root = root + "/dev"
        os.mkdir(dev_root)
        with open(dev_root + "/fb3", "wb") as stream:
            stream.truncate(4096 * 768)
        assert (
            exercise_framebuffer(child, 1024, 768, sys_root, dev_root) == "fb3"
        )
        with open(dev_root + "/fb3", "rb") as stream:
            stream.seek(4092)
            assert stream.read(4) == DISPLAY_FIRST_PIXEL
            stream.seek(4096 * 767)
            assert stream.read(4) == DISPLAY_LAST_PIXEL
        assert checkpoint_pattern(1, 64) != checkpoint_pattern(2, 64)
        count = root + "/count"
        atomic_count(count, 9)
        with open(count, encoding="ascii") as stream:
            assert stream.read() == "9\n"
        assert framebuffer_geometry(framebuffer) == (1024, 768, 4096)
        for status, modes in (("disconnected", "1024x768"), ("connected", "")):
            try:
                validate_modes(status, modes, "1024x768")
            except RuntimeError:
                pass
            else:
                raise AssertionError("invalid connector state was accepted")
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) == 6 and sys.argv[1] == "checkpoint":
        try:
            width = int(sys.argv[2], 10)
            height = int(sys.argv[3], 10)
        except ValueError as error:
            raise SystemExit(
                "checkpoint WIDTH and HEIGHT must be decimal integers"
            ) from error
        if width <= 0 or height <= 0:
            raise SystemExit("checkpoint WIDTH and HEIGHT must be positive")
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        for stale in (sys.argv[4], sys.argv[4] + ".new"):
            try:
                os.unlink(stale)
            except FileNotFoundError:
                pass
        _pci, child = find_bound_gpu()
        checkpoint_worker(child, width, height, sys.argv[4], sys.argv[5])
        return
    if len(sys.argv) < 4 or len(sys.argv) > 6 or sys.argv[1] != "modern":
        raise SystemExit("usage: ggpu.py modern WIDTH HEIGHT [packed] [blob]")
    options = sys.argv[4:]
    if any(option not in ("packed", "blob") for option in options) or (
        len(set(options)) != len(options)
    ):
        raise SystemExit("usage: ggpu.py modern WIDTH HEIGHT [packed] [blob]")
    try:
        width = int(sys.argv[2], 10)
        height = int(sys.argv[3], 10)
    except ValueError as error:
        raise SystemExit("WIDTH and HEIGHT must be decimal integers") from error
    if width <= 0 or height <= 0:
        raise SystemExit("WIDTH and HEIGHT must be positive")
    expected_mode = f"{width}x{height}"
    expect_packed = "packed" in options
    expect_blob = "blob" in options
    pci, child = find_bound_gpu()
    for bit, name in (
        (VIRTIO_GPU_F_EDID, "VIRTIO_GPU_F_EDID"),
        (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
        (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
    ):
        if not negotiated_feature(child, bit):
            raise RuntimeError(f"virtio-gpu did not negotiate {name}")
    packed = negotiated_feature(child, VIRTIO_F_RING_PACKED)
    if packed != expect_packed:
        raise RuntimeError(
            "virtio-gpu packed negotiation mismatch: "
            f"expected={'yes' if expect_packed else 'no'} "
            f"actual={'yes' if packed else 'no'}"
        )
    resource_blob = negotiated_feature(child, VIRTIO_GPU_F_RESOURCE_BLOB)
    blob_alignment = negotiated_feature(child, VIRTIO_GPU_F_BLOB_ALIGNMENT)
    if resource_blob != expect_blob or blob_alignment != expect_blob:
        raise RuntimeError(
            "virtio-gpu blob negotiation mismatch: "
            f"expected={'yes' if expect_blob else 'no'} "
            f"resource_blob={'yes' if resource_blob else 'no'} "
            f"blob_alignment={'yes' if blob_alignment else 'no'}"
        )
    connector = find_connector(child)
    with open(connector + "/status", encoding="ascii") as stream:
        status = stream.read().strip()
    with open(connector + "/modes", encoding="ascii") as stream:
        modes = stream.read()
    validate_modes(status, modes, expected_mode)
    try:
        with open(connector + "/edid", "rb") as stream:
            edid = stream.read()
    except OSError as error:
        raise RuntimeError(f"cannot read connector EDID: {error}") from error
    validate_edid(edid, expected_mode)
    framebuffer = exercise_framebuffer(child, width, height)
    print(
        f"PASS gpu pci={os.path.basename(pci)} "
        f"connector={os.path.basename(connector)} framebuffer={framebuffer} "
        f"mode={expected_mode} "
        f"packed={'yes' if packed else 'no'} "
        f"blob={'yes' if resource_blob else 'no'} "
        "edid=yes scanout_io=yes notification_data=yes ring_reset=yes"
    )


if __name__ == "__main__":
    main()
