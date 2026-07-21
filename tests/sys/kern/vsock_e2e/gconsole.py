#!/usr/bin/env python3
"""Linux guest verifier for a bhyve virtio-console port."""

import errno
import glob
import os
import select
import sys
import tempfile
import time


def expected_pci_device(transport):
    if transport == "modern":
        return "0x1043"
    if transport == "legacy":
        return "0x1003"
    raise RuntimeError(f"invalid transport: {transport}")


def find_port(transport, wanted_name, sys_root="/sys", dev_root="/dev"):
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
            if not os.path.islink(driver) or os.path.basename(
                os.path.realpath(driver)
            ) != "virtio_console":
                continue
            child_path = os.path.realpath(child)
            for port in glob.glob(
                os.path.join(sys_root, "class/virtio-ports/*")
            ):
                try:
                    name = open(port + "/name", encoding="utf-8").read()
                except OSError:
                    continue
                if name.strip() != wanted_name:
                    continue
                device_link = port + "/device"
                if not os.path.islink(device_link):
                    continue
                port_path = os.path.realpath(device_link)
                if os.path.commonpath((child_path, port_path)) != child_path:
                    continue
                matches.append(os.path.join(dev_root, os.path.basename(port)))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {expected} virtio_console port named "
            f"{wanted_name!r}, found {len(matches)}"
        )
    return matches[0]


def wait_io(fd, readable, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("virtio-console exchange timed out")
    rset = [fd] if readable else []
    wset = [] if readable else [fd]
    ready_r, ready_w, _ = select.select(rset, wset, [], remaining)
    if readable and not ready_r:
        raise RuntimeError("virtio-console receive timed out")
    if not readable and not ready_w:
        raise RuntimeError("virtio-console send timed out")


def exchange(path, incoming, outgoing, timeout=20):
    fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
    deadline = time.monotonic() + timeout
    received = bytearray()
    try:
        while len(received) < len(incoming):
            wait_io(fd, True, deadline)
            try:
                chunk = os.read(fd, len(incoming) - len(received))
            except BlockingIOError:
                continue
            if not chunk:
                raise RuntimeError("virtio-console closed during receive")
            received.extend(chunk)
        if bytes(received) != incoming:
            raise RuntimeError(
                f"virtio-console payload mismatch: {bytes(received)!r}"
            )
        offset = 0
        while offset < len(outgoing):
            wait_io(fd, False, deadline)
            try:
                written = os.write(fd, outgoing[offset:])
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
                raise
            if written <= 0:
                raise RuntimeError("short virtio-console write")
            offset += written
    finally:
        os.close(fd)


def self_test():
    with tempfile.TemporaryDirectory() as root:
        sys_root = root + "/sys"
        pci = sys_root + "/bus/pci/devices/0000:00:0a.0"
        child = pci + "/virtio6"
        port_device = child + "/virtio-ports/vport0p1"
        port = sys_root + "/class/virtio-ports/vport0p1"
        driver = sys_root + "/bus/virtio/drivers/virtio_console"
        os.makedirs(port_device)
        os.makedirs(port)
        os.makedirs(driver)
        with open(pci + "/vendor", "w", encoding="ascii") as stream:
            stream.write("0x1af4\n")
        with open(pci + "/device", "w", encoding="ascii") as stream:
            stream.write("0x1043\n")
        with open(port + "/name", "w", encoding="utf-8") as stream:
            stream.write("bhyve-e2e-console\n")
        os.symlink(driver, child + "/driver")
        os.symlink(port_device, port + "/device")
        found = find_port(
            "modern", "bhyve-e2e-console", sys_root=sys_root, dev_root=root
        )
        if found != root + "/vport0p1":
            raise AssertionError(f"wrong console path: {found}")
        try:
            find_port("legacy", "bhyve-e2e-console", sys_root, root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted wrong console transport")
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) not in (4, 6):
        raise SystemExit(
            "usage: gconsole.py --self-test | check transport name | "
            "exchange transport name incoming outgoing"
        )
    command, transport, name = sys.argv[1:4]
    path = find_port(transport, name)
    if command == "check" and len(sys.argv) == 4:
        print(f"PASS console-device name={name} device={path}")
    elif command == "exchange" and len(sys.argv) == 6:
        incoming = sys.argv[4].encode("ascii")
        outgoing = sys.argv[5].encode("ascii")
        exchange(path, incoming, outgoing)
        print(f"PASS console-exchange name={name} device={path}")
    else:
        raise SystemExit("invalid gconsole.py command or argument count")


if __name__ == "__main__":
    main()
