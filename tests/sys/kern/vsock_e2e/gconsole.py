#!/usr/bin/env python3
"""Linux guest verifier for a bhyve virtio-console port."""

import errno
import glob
import mmap
import os
import select
import socket
import struct
import sys
import tempfile
import threading
import time

# VIRTIO_ACTIVATION_ASSERTION: packed-negotiation-and-bidirectional-data
# VIRTIO_ACTIVATION_ASSERTION: in-order-negotiation-and-bidirectional-data
# VIRTIO_ACTIVATION_ASSERTION: emergency-write-config-and-host-byte

# VirtIO 1.4 feature allocation (§6).
VIRTIO_F_RING_PACKED = 34
VIRTIO_F_IN_ORDER = 35
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40
VIRTIO_CONSOLE_F_EMERG_WRITE = 2

# VirtIO PCI modern capability placement used by bhyve.  These are test-oracle
# literals from the advertised PCI capability layout and console config in
# VirtIO 1.4, not values imported from bhyve headers.
MODERN_DEVICE_CONFIG_OFFSET = 0x2000
CONSOLE_EMERG_WR_OFFSET = 8
MODERN_BAR_LENGTH = 0x4000
MODERN_DEVICE_FEATURE_SELECT_OFFSET = 0
MODERN_DEVICE_FEATURE_OFFSET = 4

MODERN_REQUIRED_FEATURES = (
    (VIRTIO_F_IN_ORDER, "VIRTIO_F_IN_ORDER"),
    (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
    (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
)


def expected_pci_device(transport):
    if transport == "modern":
        return "0x1043"
    if transport == "legacy":
        return "0x1003"
    raise RuntimeError(f"invalid transport: {transport}")


def negotiated_feature(virtio, bit):
    feature_path = virtio + "/features"
    try:
        features = open(feature_path, encoding="ascii").read().strip()
    except OSError as error:
        raise RuntimeError(f"cannot read {feature_path}: {error}") from error
    if len(features) <= bit or any(value not in "01" for value in features):
        raise RuntimeError(f"invalid virtio feature bitmap: {features!r}")
    return features[bit] == "1"


def find_port(
    transport, wanted_name, sys_root="/sys", dev_root="/dev",
    require_packed=False
):
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
                if transport == "modern":
                    for bit, feature_name in MODERN_REQUIRED_FEATURES:
                        if not negotiated_feature(child, bit):
                            raise RuntimeError(
                                "virtio-console did not negotiate "
                                f"{feature_name}"
                            )
                    if require_packed and not negotiated_feature(
                        child, VIRTIO_F_RING_PACKED
                    ):
                        raise RuntimeError(
                            "virtio-console did not negotiate "
                            "VIRTIO_F_RING_PACKED"
                        )
                matches.append((
                    os.path.join(dev_root, os.path.basename(port)),
                    child,
                ))
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


def exchange_fd(fd, incoming, outgoing, timeout=20):
    deadline = time.monotonic() + timeout
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

    received = bytearray()
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


def exchange(path, incoming, outgoing, timeout=20):
    fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
    try:
        # Write first so the host knows the guest has opened the port before
        # sending.  bhyve may discard host bytes delivered before PORT_READY.
        exchange_fd(fd, incoming, outgoing, timeout)
    finally:
        os.close(fd)


def emergency_write(child, value, resource_path=None):
    if not 0 <= value <= 0xff:
        raise RuntimeError("emergency character is outside one byte")
    pci = os.path.dirname(os.path.realpath(child))
    path = resource_path or os.path.join(pci, "resource2")
    offset = MODERN_DEVICE_CONFIG_OFFSET + CONSOLE_EMERG_WR_OFFSET
    fd = os.open(path, os.O_RDWR | os.O_SYNC)
    try:
        mapping = mmap.mmap(
            fd, MODERN_BAR_LENGTH, flags=mmap.MAP_SHARED,
            prot=mmap.PROT_READ | mmap.PROT_WRITE
        )
        try:
            old_select = mapping[
                MODERN_DEVICE_FEATURE_SELECT_OFFSET:
                MODERN_DEVICE_FEATURE_SELECT_OFFSET + 4
            ]
            mapping[
                MODERN_DEVICE_FEATURE_SELECT_OFFSET:
                MODERN_DEVICE_FEATURE_SELECT_OFFSET + 4
            ] = struct.pack("<I", 0)
            offered = struct.unpack(
                "<I", mapping[
                    MODERN_DEVICE_FEATURE_OFFSET:
                    MODERN_DEVICE_FEATURE_OFFSET + 4
                ]
            )[0]
            mapping[
                MODERN_DEVICE_FEATURE_SELECT_OFFSET:
                MODERN_DEVICE_FEATURE_SELECT_OFFSET + 4
            ] = old_select
            if not offered & (1 << VIRTIO_CONSOLE_F_EMERG_WRITE):
                raise RuntimeError(
                    "virtio-console did not offer emergency write"
                )
            mapping[offset:offset + 4] = struct.pack("<I", value)
        finally:
            mapping.close()
    finally:
        os.close(fd)


def hold_echo_fd(fd):
    while True:
        ready, _, _ = select.select([fd], [], [])
        if not ready:
            continue
        try:
            data = os.read(fd, 65536)
        except BlockingIOError:
            continue
        if not data:
            break
        offset = 0
        while offset < len(data):
            _, writable, _ = select.select([], [fd], [])
            if not writable:
                continue
            try:
                written = os.write(fd, data[offset:])
            except BlockingIOError:
                continue
            if written <= 0:
                raise RuntimeError("short virtio-console echo write")
            offset += written


def write_all(fd, data, timeout=20):
    deadline = time.monotonic() + timeout
    offset = 0
    while offset < len(data):
        wait_io(fd, False, deadline)
        try:
            written = os.write(fd, data[offset:])
        except BlockingIOError:
            continue
        if written <= 0:
            raise RuntimeError("short virtio-console write")
        offset += written


def hold_echo(path, ready_token):
    fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
    try:
        # This token crosses the virtio port.  Seeing it at the host proves
        # both endpoints are connected and avoids relying on the existence of
        # the guest device node as a PORT_READY indication.
        write_all(fd, ready_token)
        print("READY", flush=True)
        hold_echo_fd(fd)
    finally:
        os.close(fd)
    print("PASS hold-echo-closed", flush=True)


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
        features = ["0"] * 64
        for bit, _ in MODERN_REQUIRED_FEATURES:
            features[bit] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        os.symlink(driver, child + "/driver")
        os.symlink(port_device, port + "/device")
        found, child_path = find_port(
            "modern", "bhyve-e2e-console", sys_root=sys_root, dev_root=root
        )
        if found != root + "/vport0p1":
            raise AssertionError(f"wrong console path: {found}")
        if child_path != child:
            raise AssertionError(f"wrong console virtio device: {child_path}")
        try:
            find_port("legacy", "bhyve-e2e-console", sys_root, root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted wrong console transport")
        for missing_bit, missing_name in MODERN_REQUIRED_FEATURES:
            missing = features.copy()
            missing[missing_bit] = "0"
            with open(child + "/features", "w", encoding="ascii") as stream:
                stream.write("".join(missing) + "\n")
            try:
                find_port(
                    "modern", "bhyve-e2e-console", sys_root=sys_root,
                    dev_root=root
                )
            except RuntimeError:
                pass
            else:
                raise AssertionError(
                    f"accepted console without {missing_name}"
                )
        features[VIRTIO_F_RING_PACKED] = "0"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        try:
            find_port(
                "modern", "bhyve-e2e-console", sys_root=sys_root,
                dev_root=root, require_packed=True
            )
        except RuntimeError:
            pass
        else:
            raise AssertionError("accepted console without packed rings")
        features[VIRTIO_F_RING_PACKED] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        find_port(
            "modern", "bhyve-e2e-console", sys_root=sys_root,
            dev_root=root, require_packed=True
        )

        resource = pci + "/resource2"
        with open(resource, "wb") as stream:
            stream.truncate(MODERN_BAR_LENGTH)
        with open(resource, "r+b") as stream:
            stream.seek(MODERN_DEVICE_FEATURE_OFFSET)
            stream.write(struct.pack(
                "<I", 1 << VIRTIO_CONSOLE_F_EMERG_WRITE
            ))
        emergency_write(child, ord("E"), resource_path=resource)
        with open(resource, "rb") as stream:
            stream.seek(MODERN_DEVICE_CONFIG_OFFSET +
                        CONSOLE_EMERG_WR_OFFSET)
            if stream.read(4) != b"E\x00\x00\x00":
                raise AssertionError("emergency write used wrong wire bytes")

    incoming = b"host-ready"
    outgoing = b"guest-ready"
    left, right = socket.socketpair()
    peer_errors = []

    def peer():
        try:
            received = bytearray()
            while len(received) < len(outgoing):
                chunk = right.recv(len(outgoing) - len(received))
                if not chunk:
                    raise AssertionError("exchange self-test closed early")
                received.extend(chunk)
            if bytes(received) != outgoing:
                raise AssertionError(f"wrong guest payload: {received!r}")
            right.sendall(incoming)
        except BaseException as error:
            peer_errors.append(error)

    worker = threading.Thread(target=peer)
    worker.start()
    try:
        exchange_fd(left.fileno(), incoming, outgoing, timeout=2)
    finally:
        left.close()
        right.close()
    worker.join(timeout=2)
    if worker.is_alive():
        raise AssertionError("exchange self-test peer did not exit")
    if peer_errors:
        raise peer_errors[0]

    left, right = socket.socketpair()
    left.setblocking(False)
    write_all(left.fileno(), b"ready-token", timeout=2)
    if right.recv(11) != b"ready-token":
        raise AssertionError("hold readiness token corrupted")
    holder = threading.Thread(target=hold_echo_fd, args=(left.fileno(),))
    holder.start()
    right.sendall(b"checkpoint-console")
    if right.recv(18) != b"checkpoint-console":
        raise AssertionError("hold echo corrupted data")
    right.shutdown(socket.SHUT_WR)
    holder.join(timeout=2)
    if holder.is_alive():
        raise AssertionError("hold echo did not observe EOF")
    left.close()
    right.close()
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) not in (4, 5, 6, 7):
        raise SystemExit(
            "usage: gconsole.py --self-test | check transport name [packed] | "
            "exchange transport name incoming outgoing [packed] | "
            "exchange-emergency modern name incoming outgoing [packed] | "
            "hold transport name ready-token [packed]"
        )
    command, transport, name = sys.argv[1:4]
    packed_arg = (
        (command == "check" and len(sys.argv) == 5 and sys.argv[4] == "packed")
        or
        (command == "hold" and len(sys.argv) == 6 and sys.argv[5] == "packed")
        or
        (command == "exchange" and len(sys.argv) == 7
         and sys.argv[6] == "packed")
        or
        (command == "exchange-emergency" and len(sys.argv) == 7
         and sys.argv[6] == "packed")
    )
    if ((command == "check" and len(sys.argv) == 5)
            or (command == "hold" and len(sys.argv) == 6)
            or (command == "exchange" and len(sys.argv) == 7)
            or (command == "exchange-emergency" and
                len(sys.argv) == 7)) and not packed_arg:
        raise SystemExit("optional feature argument must be packed")
    path, child = find_port(transport, name, require_packed=packed_arg)
    modern = transport == "modern"
    in_order = modern and negotiated_feature(child, VIRTIO_F_IN_ORDER)
    packed = modern and negotiated_feature(child, VIRTIO_F_RING_PACKED)
    feature_status = (
        "yes" if in_order else ("no" if modern else "n/a")
    )
    packed_status = "yes" if packed else ("no" if modern else "n/a")
    if command == "check" and len(sys.argv) in (4, 5):
        print(
            f"PASS console-device name={name} device={path} "
            f"in_order={feature_status} packed={packed_status}"
        )
    elif command == "hold" and len(sys.argv) in (5, 6):
        hold_echo(path, sys.argv[4].encode("ascii"))
    elif command == "exchange" and len(sys.argv) in (6, 7):
        incoming = sys.argv[4].encode("ascii")
        outgoing = sys.argv[5].encode("ascii")
        exchange(path, incoming, outgoing)
        print(
            f"PASS console-exchange name={name} device={path} "
            f"in_order={feature_status} packed={packed_status}"
        )
    elif command == "exchange-emergency" and len(sys.argv) in (6, 7):
        if transport != "modern":
            raise RuntimeError("emergency mmap test requires modern PCI")
        fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
        try:
            exchange_fd(
                fd, sys.argv[4].encode("ascii"),
                sys.argv[5].encode("ascii")
            )
            emergency_write(child, ord("E"))
        finally:
            os.close(fd)
        print(
            f"PASS console-emergency-write name={name} device={path} "
            f"in_order={feature_status} packed={packed_status}"
        )
    else:
        raise SystemExit("invalid gconsole.py command or argument count")


if __name__ == "__main__":
    main()
