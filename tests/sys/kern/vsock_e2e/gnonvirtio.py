#!/usr/bin/env python3
"""Guest-side, device-specific checks for the bhyve non-VirtIO lab.

The runner passes the fixed PCI address used by the reviewed VM topology.  We
still verify vendor, device and class so a different function cannot satisfy a
case merely by appearing at that address.
"""

import argparse
import glob
import mmap
import os
import stat
import tempfile


MODELS = {
    "ahci": (0x8086, 0x2821, 0x010601),
    "nvme": (0xFB5D, 0x0A0A, 0x010802),
    "e82545": (0x8086, 0x100F, 0x020000),
    "hda": (0x8086, 0x27D8, 0x040300),
    "xhci": (0x8086, 0x1E31, 0x0C0330),
    "fbuf": (0xFB5D, 0x40FB, 0x030000),
    "pci-uart": (0x131F, 0x2000, 0x070002),
    "hostbridge": (0x1275, 0x1275, 0x060000),
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
    else:
        parser.error("a command is required")


if __name__ == "__main__":
    main()
