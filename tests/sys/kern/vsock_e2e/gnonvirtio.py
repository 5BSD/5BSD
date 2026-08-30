#!/usr/bin/env python3
"""Guest-side, device-specific checks for the bhyve non-VirtIO lab.

The runner passes the fixed PCI address used by the reviewed VM topology.  We
still verify vendor, device and class so a different function cannot satisfy a
case merely by appearing at that address.
"""

import argparse
import fcntl
import glob
import mmap
import os
import stat
import struct
import tempfile
import time


MODELS = {
    "ahci": (0x8086, 0x2821, 0x010601),
    "nvme": (0xFB5D, 0x0A0A, 0x010802),
    "e82545": (0x8086, 0x100F, 0x020000),
    "hda": (0x8086, 0x27D8, 0x040300),
    "xhci": (0x8086, 0x1E31, 0x0C0330),
    "fbuf": (0xFB5D, 0x40FB, 0x030000),
    "pci-uart": (0x131F, 0x2000, 0x070002),
    "hostbridge": (0x1275, 0x1275, 0x060000),
    # i6300esb PCI watchdog: base class 0x08 (system peripheral), subclass
    # 0x80 (other), prog-if 0x00 -> class code 0x088000.  Non-VirtIO; the guest
    # driver is Linux "i6300esb" (/dev/watchdogN) or 5BSD "i6300esbwd"
    # (watchdog(4) via /dev/fido).
    "i6300esb": (0x8086, 0x25AB, 0x088000),
}
DISPLAY_FIRST_PIXEL = bytes((0x13, 0x57, 0x9B, 0x00))
DISPLAY_LAST_PIXEL = bytes((0x24, 0x68, 0xAC, 0x00))


def read_hex(path):
    with open(path, encoding="ascii") as source:
        return int(source.read().strip(), 0)


def pci_device(kind, bdf, sys_root="/sys"):
    path = os.path.join(sys_root, "bus/pci/devices", bdf)
    if not os.path.isdir(path):
        raise RuntimeError(f"PCI function {bdf} is absent")
    vendor, device, class_code = MODELS[kind]
    actual = (
        read_hex(path + "/vendor"),
        read_hex(path + "/device"),
        read_hex(path + "/class"),
    )
    if actual != (vendor, device, class_code):
        raise RuntimeError(
            f"{bdf} identity is {actual!r}, expected "
            f"{(vendor, device, class_code)!r} for {kind}"
        )
    return path


def bound_driver(path):
    driver = path + "/driver"
    if not os.path.islink(driver):
        raise RuntimeError(f"{os.path.basename(path)} has no bound driver")
    return os.path.basename(os.path.realpath(driver))


def block_node(path, dev_root="/dev"):
    names = []
    for candidate in glob.glob(path + "/**/block/*", recursive=True):
        name = os.path.basename(candidate)
        node = os.path.join(dev_root, name)
        try:
            mode = os.stat(node).st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISBLK(mode):
            names.append(node)
    names = sorted(set(names))
    if len(names) != 1:
        raise RuntimeError(f"expected one block node below PCI function, found {names!r}")
    return names[0]


def block_io(path, token):
    node = block_node(path)
    payload = ("WASPNEST-NONVIRTIO:" + token).encode("ascii")
    payload = payload.ljust(4096, b"\xa5")
    fd = os.open(node, os.O_RDWR)
    try:
        # This is a dedicated scratch disk.  Keep the label area untouched so
        # the same node remains discoverable if a guest kernel probes it.
        offset = 1024 * 1024
        written = os.pwrite(fd, payload, offset)
        if written != len(payload):
            raise RuntimeError("short raw-disk write")
        os.fsync(fd)
        if os.pread(fd, len(payload), offset) != payload:
            raise RuntimeError("raw-disk marker did not read back")
    finally:
        os.close(fd)
    return node


def framebuffer_node(path, sys_root="/sys", dev_root="/dev"):
    real = os.path.realpath(path)
    matches = []
    for fb in glob.glob(sys_root + "/class/graphics/fb[0-9]*"):
        owner = os.path.realpath(fb + "/device")
        if owner == real or owner.startswith(real + os.sep):
            node = os.path.join(dev_root, os.path.basename(fb))
            if os.path.exists(node):
                matches.append((fb, node))
    if len(matches) != 1:
        raise RuntimeError(f"expected one framebuffer below PCI function, found {matches!r}")
    return matches[0]


def framebuffer_io(path, token, last_pixel=DISPLAY_LAST_PIXEL):
    try:
        fb, node = framebuffer_node(path)
    except RuntimeError:
        # The bhyve framebuffer BAR is useful before, or without, a guest
        # fbdev driver.  The reviewed topology fixes it at 1024x768x32.
        node = path + "/resource1"
        fd = os.open(node, os.O_RDWR | getattr(os, "O_SYNC", 0))
        try:
            first_offset = (1024 - 1) * 4
            last_offset = (768 - 1) * 1024 * 4
            mapping = mmap.mmap(fd, 8 * 1024 * 1024)
            mapping[first_offset:first_offset + 4] = DISPLAY_FIRST_PIXEL
            mapping[last_offset:last_offset + 4] = last_pixel
            if mapping[first_offset:first_offset + 4] != DISPLAY_FIRST_PIXEL or \
                    mapping[last_offset:last_offset + 4] != last_pixel:
                raise RuntimeError("framebuffer BAR marker did not read back")
            mapping.close()
        finally:
            os.close(fd)
        return node
    with open(fb + "/virtual_size", encoding="ascii") as source:
        width, height = (int(value) for value in source.read().strip().split(","))
    stride = read_hex(fb + "/stride")
    if width <= 1 or height <= 1 or stride < width * 4:
        raise RuntimeError("invalid framebuffer geometry")
    fd = os.open(node, os.O_RDWR)
    try:
        first_offset = (width - 1) * 4
        last_offset = (height - 1) * stride
        if os.pwrite(fd, DISPLAY_FIRST_PIXEL, first_offset) != 4 or \
                os.pwrite(fd, last_pixel, last_offset) != 4:
            raise RuntimeError("short framebuffer write")
        if os.pread(fd, 4, first_offset) != DISPLAY_FIRST_PIXEL or \
                os.pread(fd, 4, last_offset) != last_pixel:
            raise RuntimeError("framebuffer marker did not read back")
    finally:
        os.close(fd)
    return node


def pvpanic(event, port_path="/dev/port"):
    if event not in (1, 2):
        raise RuntimeError("pvpanic event must be PANICKED(1) or CRASHLOADED(2)")
    fd = os.open(port_path, os.O_RDWR)
    try:
        supported = os.pread(fd, 1, 0x505)
        if len(supported) != 1 or not (supported[0] & event):
            raise RuntimeError("requested pvpanic event is not advertised")
        if os.pwrite(fd, bytes([event]), 0x505) != 1:
            raise RuntimeError("short pvpanic event write")
    finally:
        os.close(fd)


# ---- i6300esb PCI watchdog ---------------------------------------------------
#
# The verifier confirms that the emulated i6300esb is bound to the platform
# watchdog driver, that the no-feed reset is armed, and that a keepalive/pat is
# accepted.  The DEFAULT path never lets the watchdog lapse: it pats once and
# then disarms cleanly, so a self-check can never destroy the VM.  The
# destructive "let it fire and observe the host action" behaviour is gated
# behind WATCHDOG_EXPECT_RESET and is only used by the live case, exactly as
# pvpanic neutralises its panic at the device (action=none / action=notify).

# Linux <linux/watchdog.h> ioctls (WATCHDOG_IOCTL_BASE == 'W').
WDIOC_KEEPALIVE = 0x80045705
WDIOC_SETTIMEOUT = 0xC0045706
WDIOC_GETTIMEOUT = 0x80045707

# 5BSD/FreeBSD <sys/watchdog.h> ioctls (sbintime_t == int64).
WD_FREEBSD_SETTIMEOUT = 0x80085735  # _IOW('W', 53, sbintime_t)
WD_FREEBSD_GETTIMEOUT = 0x40085736  # _IOR('W', 54, sbintime_t)
WD_FREEBSD_CONTROL = 0x80045733     # _IOW('W', 51, int)
WD_CTRL_DISABLE = 0x00000000
SBT_1S = 1 << 32

# Short lapse target for the destructive case so a live reset observation does
# not stall the lab; the emulated timer is two-stage, so the host action lands
# near 2x this value.
WATCHDOG_FIRE_TIMEOUT = 2


def read_int(path):
    with open(path, encoding="ascii") as source:
        return int(source.read().strip(), 10)


def watchdog_node_linux(path, sys_root="/sys", dev_root="/dev"):
    real = os.path.realpath(path)
    matches = []
    for entry in glob.glob(sys_root + "/class/watchdog/watchdog[0-9]*"):
        owner = os.path.realpath(entry + "/device")
        if owner == real or owner.startswith(real + os.sep):
            node = os.path.join(dev_root, os.path.basename(entry))
            if os.path.exists(node):
                matches.append((entry, node))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one watchdog below PCI function, found {matches!r}")
    return matches[0]


def watchdog_linux(bdf, expect_reset):
    path = pci_device("i6300esb", bdf)
    driver = bound_driver(path)
    if driver != "i6300esb":
        raise RuntimeError(f"watchdog bound to {driver!r}, expected i6300esb")
    sysfs, node = watchdog_node_linux(path)
    identity = "unknown"
    identity_path = sysfs + "/identity"
    if os.path.exists(identity_path):
        with open(identity_path, encoding="ascii") as source:
            identity = source.read().strip()
    # Opening the device arms it; the countdown is now live.
    fd = os.open(node, os.O_WRONLY)
    try:
        try:
            buf = struct.pack("i", 0)
            fcntl.ioctl(fd, WDIOC_GETTIMEOUT, buf, True)
            timeout = struct.unpack("i", buf)[0]
        except OSError:
            timeout = read_int(sysfs + "/timeout") if \
                os.path.exists(sysfs + "/timeout") else 0
        if timeout <= 0:
            raise RuntimeError("watchdog reports a non-positive timeout")
        if not expect_reset:
            # Pat once to prove the keepalive path, then disarm with the magic
            # close so the timer can never lapse.
            os.write(fd, b"\0")
            os.write(fd, b"V")
            os.close(fd)
            fd = -1
            return f"node={node} identity={identity} timeout={timeout} armed=yes fired=no"
        # Destructive lane: shorten the timer if we can, stop patting, and let
        # it lapse.  bhyve is configured action=notify, so the host merely logs
        # and stops the timer -- the guest survives for the runner to observe.
        try:
            buf = struct.pack("i", WATCHDOG_FIRE_TIMEOUT)
            fcntl.ioctl(fd, WDIOC_SETTIMEOUT, buf, True)
            timeout = struct.unpack("i", buf)[0]
        except OSError:
            pass
        os.write(fd, b"\0")
        # Do NOT write the magic 'V': the timer must remain armed as it lapses.
        os.close(fd)
        fd = -1
        time.sleep(timeout * 3 + 10)
        return f"node={node} identity={identity} timeout={timeout} armed=yes fired=expected"
    finally:
        if fd >= 0:
            try:
                os.write(fd, b"V")
            except OSError:
                pass
            os.close(fd)


def watchdog_freebsd(expect_reset, dev_root="/dev"):
    node = os.path.join(dev_root, "fido")
    fd = os.open(node, os.O_RDWR)
    try:
        seconds = WATCHDOG_FIRE_TIMEOUT if expect_reset else 8
        sbt = struct.pack("q", seconds * SBT_1S)
        fcntl.ioctl(fd, WD_FREEBSD_SETTIMEOUT, sbt, False)
        buf = struct.pack("q", 0)
        fcntl.ioctl(fd, WD_FREEBSD_GETTIMEOUT, buf, True)
        total = struct.unpack("q", buf)[0]
        if total <= 0:
            raise RuntimeError("watchdog reports a non-positive timeout")
        if not expect_reset:
            # Pat once more, then disable so the timer can never lapse.
            fcntl.ioctl(fd, WD_FREEBSD_SETTIMEOUT, sbt, False)
            fcntl.ioctl(fd, WD_FREEBSD_CONTROL,
                        struct.pack("i", WD_CTRL_DISABLE), False)
            return f"node={node} timeout={seconds} armed=yes fired=no"
        # Destructive lane: stop patting and let it lapse (action=notify keeps
        # the guest alive for the runner to observe on the host log).
        time.sleep(seconds * 3 + 10)
        return f"node={node} timeout={seconds} armed=yes fired=expected"
    finally:
        os.close(fd)


def watchdog(bdf, expect_reset):
    system = os.uname().sysname
    if system == "Linux":
        return watchdog_linux(bdf, expect_reset)
    if system in ("FreeBSD", "5BSD"):
        # 5BSD exposes the i6300esbwd(4) driver through watchdog(4); the PCI
        # binding is confirmed natively by the 5BSD runner (pciconf), so here we
        # drive the platform watchdog device directly.
        return watchdog_freebsd(expect_reset)
    raise RuntimeError(f"watchdog verifier does not support {system!r}")


def self_test():
    with tempfile.TemporaryDirectory() as root:
        path = root + "/sys/bus/pci/devices/0000:00:15.0"
        os.makedirs(path)
        for name, value in (("vendor", "0x8086"), ("device", "0x2821"),
                            ("class", "0x010601")):
            with open(path + "/" + name, "w", encoding="ascii") as output:
                output.write(value + "\n")
        if pci_device("ahci", "0000:00:15.0", root + "/sys") != path:
            raise RuntimeError("synthetic PCI lookup failed")
        try:
            pci_device("nvme", "0000:00:15.0", root + "/sys")
        except RuntimeError:
            pass
        else:
            raise RuntimeError("PCI identity mismatch was accepted")
        watchdog = root + "/sys/bus/pci/devices/0000:00:1f.0"
        os.makedirs(watchdog)
        for name, value in (("vendor", "0x8086"), ("device", "0x25ab"),
                            ("class", "0x088000")):
            with open(watchdog + "/" + name, "w", encoding="ascii") as output:
                output.write(value + "\n")
        if pci_device("i6300esb", "0000:00:1f.0", root + "/sys") != watchdog:
            raise RuntimeError("synthetic i6300esb lookup failed")
    print("SELFTEST PASS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    subparsers = parser.add_subparsers(dest="command")
    probe = subparsers.add_parser("probe")
    probe.add_argument("kind", choices=sorted(MODELS))
    probe.add_argument("bdf")
    storage = subparsers.add_parser("block-io")
    storage.add_argument("kind", choices=("ahci", "nvme"))
    storage.add_argument("bdf")
    storage.add_argument("token")
    display = subparsers.add_parser("framebuffer-io")
    display.add_argument("bdf")
    display.add_argument("token")
    display.add_argument("last_pixel", nargs="?")
    panic = subparsers.add_parser("pvpanic")
    panic.add_argument("event", type=int)
    dog = subparsers.add_parser("watchdog")
    dog.add_argument("bdf")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.command == "probe":
        path = pci_device(args.kind, args.bdf)
        if args.kind == "hostbridge" and not os.path.islink(path + "/driver"):
            driver = "none"
        else:
            driver = bound_driver(path)
        print(f"PASS device={args.kind} bdf={args.bdf} driver={driver}")
    elif args.command == "block-io":
        path = pci_device(args.kind, args.bdf)
        print(f"PASS device={args.kind} node={block_io(path, args.token)}")
    elif args.command == "framebuffer-io":
        path = pci_device("fbuf", args.bdf)
        pixel = DISPLAY_LAST_PIXEL
        if args.last_pixel is not None:
            try:
                pixel = bytes.fromhex(args.last_pixel)
            except ValueError as error:
                raise RuntimeError("invalid framebuffer pixel") from error
            if len(pixel) != 4:
                raise RuntimeError("framebuffer pixel must contain four bytes")
        print(f"PASS device=fbuf node={framebuffer_io(path, args.token, pixel)}")
    elif args.command == "pvpanic":
        pvpanic(args.event)
        print(f"PASS device=pvpanic event={args.event}")
    elif args.command == "watchdog":
        expect_reset = os.environ.get("WATCHDOG_EXPECT_RESET", "") not in \
            ("", "0", "no", "false")
        print(f"PASS device=i6300esb {watchdog(args.bdf, expect_reset)}")
    else:
        parser.error("a command is required")


if __name__ == "__main__":
    main()
