#!/usr/bin/env python3
"""Linux guest helper and strict preflight for bhyve virtio-vsock E2E."""

import errno
import glob
import os
import socket
import sys
import tempfile
import time


AF_VSOCK = getattr(socket, "AF_VSOCK", 40)
VMADDR_CID_ANY = getattr(socket, "VMADDR_CID_ANY", 0xFFFFFFFF)


def make_socket(sock_type):
    kind = socket.SOCK_SEQPACKET if sock_type == "seq" else socket.SOCK_STREAM
    return socket.socket(AF_VSOCK, kind)


def send_data(sock, sock_type, data):
    if sock_type == "stream":
        sock.sendall(data)
        return
    sent = sock.send(data)
    if sent != len(data):
        raise RuntimeError(f"short SEQPACKET send: {sent} of {len(data)}")


def recv_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise RuntimeError(f"unexpected EOF after {len(result)} of {size} bytes")
        result.extend(chunk)
    return bytes(result)


def expect_eof(sock, context):
    data = sock.recv(1)
    if data:
        raise RuntimeError(f"{context}: expected EOF, received {data!r}")


def find_bound_vsock(sys_root, expected_device):
    matches = []
    pattern = os.path.join(sys_root, "bus/pci/devices/*")
    for pci in glob.glob(pattern):
        try:
            with open(pci + "/vendor", encoding="ascii") as stream:
                vendor = stream.read().strip()
            with open(pci + "/device", encoding="ascii") as stream:
                device = stream.read().strip()
        except OSError:
            continue
        if vendor != "0x1af4" or device != expected_device:
            continue
        drivers = []
        for child in glob.glob(pci + "/virtio*"):
            driver = child + "/driver"
            if os.path.islink(driver):
                drivers.append(os.path.basename(os.path.realpath(driver)))
        if "vmw_vsock_virtio_transport" in drivers:
            matches.append(pci)
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {expected_device} device bound to "
            f"vmw_vsock_virtio_transport, "
            f"found {len(matches)}"
        )


def preflight(transport):
    expected = "0x1053" if transport == "modern" else "0x1013"
    probe = make_socket("stream")
    probe.close()
    find_bound_vsock("/sys", expected)
    print(f"PASS preflight transport={transport} pci={expected}")


def connect_error_name(exc):
    if isinstance(exc, TimeoutError):
        return "ETIMEDOUT"
    if isinstance(exc, OSError) and exc.errno is not None:
        return errno.errorcode.get(exc.errno, f"ERRNO_{exc.errno}")
    return type(exc).__name__


def failed_connect(cid, port, timeout):
    conn = make_socket("stream")
    conn.settimeout(timeout)
    try:
        conn.connect((cid, port))
    except (OSError, TimeoutError) as exc:
        return connect_error_name(exc)
    finally:
        conn.close()
    raise RuntimeError(f"reserved CID {cid} unexpectedly connected")


def reserved_cid_connects():
    cid0 = failed_connect(0, 7109, 3.0)
    if cid0 != "ETIMEDOUT":
        raise RuntimeError(f"CID 0 returned {cid0}, expected ETIMEDOUT")
    cid2 = failed_connect(2, 7109, 3.0)
    if cid2 != "ECONNRESET":
        raise RuntimeError(f"CID 2 returned {cid2}, expected ECONNRESET")
    print(f"PASS reserved-cids cid0={cid0} cid2={cid2}")


def make_fake_device(
    root, name, device, driver="vmw_vsock_virtio_transport"
):
    pci = os.path.join(root, "bus/pci/devices", name)
    os.makedirs(pci + "/virtio0")
    with open(pci + "/vendor", "w", encoding="ascii") as stream:
        stream.write("0x1af4\n")
    with open(pci + "/device", "w", encoding="ascii") as stream:
        stream.write(device + "\n")
    driver_path = os.path.join(root, "bus/virtio/drivers", driver)
    os.makedirs(driver_path, exist_ok=True)
    os.symlink(driver_path, pci + "/virtio0/driver")


def self_test():
    left, right = socket.socketpair()
    try:
        send_data(left, "stream", b"abcdef")
        if recv_exact(right, 6) != b"abcdef":
            raise AssertionError("stream helpers corrupted data")
        left.close()
        try:
            recv_exact(right, 1)
        except RuntimeError:
            pass
        else:
            raise AssertionError("short stream was accepted")
    finally:
        left.close()
        right.close()

    with tempfile.TemporaryDirectory() as root:
        make_fake_device(root, "0000:00:05.0", "0x1053")
        find_bound_vsock(root, "0x1053")
        make_fake_device(root, "0000:00:06.0", "0x1013", "wrong_driver")
        try:
            find_bound_vsock(root, "0x1013")
        except RuntimeError:
            pass
        else:
            raise AssertionError("device bound to wrong driver was accepted")
        make_fake_device(root, "0000:00:07.0", "0x1053")
        try:
            find_bound_vsock(root, "0x1053")
        except RuntimeError:
            pass
        else:
            raise AssertionError("duplicate devices were accepted")
    left, right = socket.socketpair()
    try:
        left.shutdown(socket.SHUT_WR)
        expect_eof(right, "self-test")
    finally:
        left.close()
        right.close()
    if connect_error_name(TimeoutError()) != "ETIMEDOUT":
        raise AssertionError("timeout outcome was misclassified")
    if connect_error_name(ConnectionResetError(errno.ECONNRESET, "reset")) != (
        "ECONNRESET"
    ):
        raise AssertionError("reset outcome was misclassified")
    print("SELFTEST PASS")


def echo_listener(sock_type, port):
    listener = make_socket(sock_type)
    listener.bind((VMADDR_CID_ANY, port))
    listener.listen(1)
    print("up", flush=True)
    conn, _ = listener.accept()
    with conn:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            send_data(conn, sock_type, data)


def receive_listener(sock_type, port):
    listener = make_socket(sock_type)
    listener.bind((VMADDR_CID_ANY, port))
    listener.listen(1)
    print("up", flush=True)
    conn, _ = listener.accept()
    records = total = 0
    with conn:
        while True:
            data = conn.recv(4 * 1024 * 1024)
            if not data:
                break
            records += 1
            total += len(data)
            print(f"RECORD len={len(data)}", flush=True)
    print(f"TOTAL recs={records} bytes={total}", flush=True)


def close_listener(sock_type, port, expected):
    listener = make_socket(sock_type)
    listener.bind((VMADDR_CID_ANY, port))
    listener.listen(1)
    print("up", flush=True)
    conn, _ = listener.accept()
    received = bytearray()
    with conn:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            received.extend(data)
    wanted = expected.encode()
    if received != wanted:
        raise RuntimeError(
            f"graceful-close payload mismatch: {bytes(received)!r} != {wanted!r}"
        )
    print(f"PASS graceful-close-listener type={sock_type}", flush=True)


def close_client(sock_type, port, payload):
    conn = make_socket(sock_type)
    conn.settimeout(5.0)
    with conn:
        conn.connect((2, port))
        send_data(conn, sock_type, payload.encode())
        conn.shutdown(socket.SHUT_WR)
        expect_eof(conn, "graceful-close client")
    print(f"PASS graceful-close-client type={sock_type}", flush=True)


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) == 3 and sys.argv[1] == "preflight" and sys.argv[2] in (
        "modern",
        "legacy",
    ):
        preflight(sys.argv[2])
        return
    if sys.argv[1:] == ["reserved-cids"]:
        reserved_cid_connects()
        return
    if len(sys.argv) < 4:
        raise SystemExit(
            "usage: gvsock.py --self-test | preflight modern|legacy | "
            "reserved-cids | "
            "echo-l|recv-l|close-l|close|send|send-echo "
            "stream|seq port [value]"
        )
    command, sock_type, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    if sock_type not in ("stream", "seq"):
        raise SystemExit("socket type must be stream or seq")
    if command == "echo-l" and len(sys.argv) == 4:
        echo_listener(sock_type, port)
    elif command == "recv-l" and len(sys.argv) == 4:
        receive_listener(sock_type, port)
    elif command == "close-l" and len(sys.argv) == 5:
        close_listener(sock_type, port, sys.argv[4])
    elif command == "close" and len(sys.argv) == 5:
        close_client(sock_type, port, sys.argv[4])
    elif command == "send" and len(sys.argv) == 5:
        size = int(sys.argv[4])
        conn = make_socket(sock_type)
        with conn:
            conn.connect((2, port))
            send_data(conn, sock_type, b"G" * size)
            conn.shutdown(socket.SHUT_WR)
            # Give the guest transport time to consume its queued close after
            # the payload; the host drain still independently verifies bytes.
            time.sleep(0.6)
        print(f"sent {size}", flush=True)
    elif command == "send-echo" and len(sys.argv) == 5:
        payload = sys.argv[4].encode()
        conn = make_socket(sock_type)
        with conn:
            conn.connect((2, port))
            send_data(conn, sock_type, payload)
            echoed = recv_exact(conn, len(payload))
        print("ECHO " + echoed.decode(), flush=True)
    else:
        raise SystemExit("invalid gvsock command or argument count")


if __name__ == "__main__":
    main()
