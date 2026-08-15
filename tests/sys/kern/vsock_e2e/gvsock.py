#!/usr/bin/env python3
"""Linux guest helper and strict preflight for bhyve virtio-vsock E2E."""

import array
import errno
import fcntl
import glob
import os
import socket
import sys
import tempfile
import threading
import time

# Release-ledger anchors for protocol and packed-ring data-path checks.
# VIRTIO_ACTIVATION_ASSERTION: bidirectional-stream-and-seqpacket
# VIRTIO_ACTIVATION_ASSERTION: packed-negotiation-and-bidirectional-data


AF_VSOCK = getattr(socket, "AF_VSOCK", 40)
VMADDR_CID_ANY = getattr(socket, "VMADDR_CID_ANY", 0xFFFFFFFF)
# Linux UAPI include/uapi/linux/vm_sockets.h:
#     #define IOCTL_VM_SOCKETS_GET_LOCAL_CID _IO(7, 0xb9)
IOCTL_VM_SOCKETS_GET_LOCAL_CID = 0x7B9

# VirtIO 1.4 socket-device and common feature allocation (§5.10.3 and §6).
VIRTIO_VSOCK_F_STREAM = 0
VIRTIO_VSOCK_F_SEQPACKET = 1
VIRTIO_VSOCK_F_NO_IMPLIED_STREAM = 2
VIRTIO_F_RING_PACKED = 34
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40

# PCI identities are a separate contract from the device feature bitmap.
# The modern value follows VirtIO 1.4 section 4.1.2.1 (0x1040 + device ID
# 19).  The legacy value is bhyve's documented compatibility extension;
# VirtIO assigns vsock no transitional identity.
VIRTIO_PCI_MODERN_VSOCK_DEVICE = "0x1053"
BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_DEVICE = "0x1013"

MODERN_REQUIRED_FEATURES = (
    (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
    (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
)


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


def disconnect_outcome(sock):
    try:
        data = sock.recv(1)
    except OSError as exc:
        if exc.errno in (errno.ECONNRESET, errno.ENOTCONN):
            return errno.errorcode[exc.errno]
        raise
    if data:
        raise RuntimeError(f"expected peer disconnect, received {data!r}")
    return "EOF"


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
        for child in glob.glob(pci + "/virtio*"):
            driver = child + "/driver"
            if os.path.islink(driver) and os.path.basename(
                os.path.realpath(driver)
            ) == "vmw_vsock_virtio_transport":
                matches.append(child)
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {expected_device} device bound to "
            f"vmw_vsock_virtio_transport, "
            f"found {len(matches)}"
        )
    return matches[0]


def negotiated_feature(child, bit):
    feature_path = os.path.join(child, "features")
    try:
        with open(feature_path, encoding="ascii") as stream:
            features = stream.read().strip()
    except OSError as error:
        raise RuntimeError(f"cannot read {feature_path}: {error}") from error
    if len(features) <= bit or any(value not in "01" for value in features):
        raise RuntimeError(f"invalid virtio feature bitmap: {features!r}")
    return features[bit] == "1"


def validate_socket_features(child):
    stream = negotiated_feature(child, VIRTIO_VSOCK_F_STREAM)
    seqpacket = negotiated_feature(child, VIRTIO_VSOCK_F_SEQPACKET)
    no_implied_stream = negotiated_feature(
        child, VIRTIO_VSOCK_F_NO_IMPLIED_STREAM
    )

    if not seqpacket:
        raise RuntimeError(
            "virtio-vsock did not negotiate VIRTIO_VSOCK_F_SEQPACKET"
        )
    if no_implied_stream and not stream:
        raise RuntimeError(
            "virtio-vsock negotiated NO_IMPLIED_STREAM without STREAM"
        )
    names = ["seqpacket"]
    if stream:
        names.insert(0, "stream")
    else:
        names.insert(0, "stream-implied")
    if no_implied_stream:
        names.append("no-implied-stream")
    return ",".join(names)


def validate_modern_features(child):
    features = validate_socket_features(child)
    for bit, name in MODERN_REQUIRED_FEATURES:
        if not negotiated_feature(child, bit):
            raise RuntimeError(f"virtio-vsock did not negotiate {name}")
    return features


def get_local_cid(path="/dev/vsock", ioctl_fn=fcntl.ioctl):
    cid = array.array("I", [0])
    with open(path, "rb", buffering=0) as device:
        ioctl_fn(
            device.fileno(),
            IOCTL_VM_SOCKETS_GET_LOCAL_CID,
            cid,
            True,
        )
    return cid[0]


def preflight(transport, expected_cid, require_packed=False):
    expected = (
        VIRTIO_PCI_MODERN_VSOCK_DEVICE
        if transport == "modern"
        else BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_DEVICE
    )
    probe = make_socket("stream")
    probe.close()
    local_cid = get_local_cid()
    if local_cid != expected_cid:
        raise RuntimeError(
            f"guest local CID is {local_cid}, expected {expected_cid}"
        )
    child = find_bound_vsock("/sys", expected)
    features = (
        validate_modern_features(child)
        if transport == "modern"
        else validate_socket_features(child)
    )
    packed = (
        transport == "modern"
        and negotiated_feature(child, VIRTIO_F_RING_PACKED)
    )
    if require_packed and not packed:
        raise RuntimeError(
            "virtio-vsock did not negotiate VIRTIO_F_RING_PACKED"
        )
    print(
        f"PASS preflight transport={transport} pci={expected} "
        f"guest_cid={expected_cid} features={features} "
        f"notification_data={'yes' if transport == 'modern' else 'n/a'} "
        f"ring_reset={'yes' if transport == 'modern' else 'n/a'} "
        f"packed={'yes' if packed else ('no' if transport == 'modern' else 'n/a')}"
    )


def connect_error_name(exc):
    if isinstance(exc, TimeoutError):
        return "ETIMEDOUT"
    if isinstance(exc, OSError) and exc.errno is not None:
        return errno.errorcode.get(exc.errno, f"ERRNO_{exc.errno}")
    return type(exc).__name__


def failed_connect(cid, port, timeout, sock_type="stream"):
    conn = make_socket(sock_type)
    conn.settimeout(timeout)
    try:
        conn.connect((cid, port))
    except (OSError, TimeoutError) as exc:
        return connect_error_name(exc)
    finally:
        conn.close()
    raise RuntimeError(f"reserved CID {cid} unexpectedly connected")


def reserved_cid_connects():
    cid2_seq = failed_connect(2, 7109, 3.0, "seq")
    if cid2_seq != "ECONNRESET":
        raise RuntimeError(
            f"SEQPACKET CID 2 returned {cid2_seq}, expected ECONNRESET"
        )
    cid2_before = failed_connect(2, 7109, 3.0)
    if cid2_before != "ECONNRESET":
        raise RuntimeError(
            f"initial CID 2 returned {cid2_before}, expected ECONNRESET"
        )
    cid0 = failed_connect(0, 7109, 3.0)
    if cid0 != "ETIMEDOUT":
        raise RuntimeError(f"CID 0 returned {cid0}, expected ETIMEDOUT")
    cid2_after = failed_connect(2, 7109, 3.0)
    if cid2_after != "ECONNRESET":
        raise RuntimeError(
            f"CID 2 after reserved-CID probe returned {cid2_after}, "
            "expected ECONNRESET"
        )
    print(
        f"PASS reserved-cids cid2-seq={cid2_seq} cid2-before={cid2_before} "
        f"cid0={cid0} cid2-after={cid2_after}"
    )


def refused_connect_storm(
    sock_type, port, attempts, connect_fn=failed_connect, emit=True
):
    if attempts < 1 or attempts > 1024:
        raise RuntimeError("refused-connect attempt count must be in [1, 1024]")
    for attempt in range(1, attempts + 1):
        outcome = connect_fn(2, port, 3.0, sock_type)
        if outcome != "ECONNRESET":
            raise RuntimeError(
                f"{sock_type} refused connect {attempt}/{attempts} returned "
                f"{outcome}, expected ECONNRESET"
            )
    if emit:
        print(
            f"PASS refused-connect-storm type={sock_type} "
            f"attempts={attempts}"
        )


def validate_parallel_range(base_port, count):
    if count < 2 or count > 64:
        raise RuntimeError("parallel connection count must be in [2, 64]")
    if base_port < 1 or base_port + count - 1 > 0xFFFFFFFF:
        raise RuntimeError("parallel port range is outside [1, 0xffffffff]")


def run_parallel(workers, context):
    errors = []
    error_lock = threading.Lock()

    def run(worker):
        try:
            worker()
        except BaseException as exc:
            with error_lock:
                errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=run, args=(worker,)) for worker in workers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise RuntimeError(f"{context}: " + "; ".join(errors))


def parallel_echo_listeners(sock_type, base_port, count):
    validate_parallel_range(base_port, count)
    listeners = []
    workers = []
    try:
        for offset in range(count):
            listener = make_socket(sock_type)
            listener.settimeout(20.0)
            listener.bind((VMADDR_CID_ANY, base_port + offset))
            listener.listen(1)
            listeners.append(listener)

        for listener in listeners:
            def worker(listener=listener):
                try:
                    conn, _ = listener.accept()
                    conn.settimeout(20.0)
                    with conn:
                        while True:
                            data = conn.recv(65536)
                            if not data:
                                break
                            send_data(conn, sock_type, data)
                finally:
                    listener.close()

            workers.append(worker)
        print("up", flush=True)
        run_parallel(workers, f"parallel {sock_type} listeners")
    finally:
        for listener in listeners:
            listener.close()
    print(
        f"PASS parallel-echo-listeners type={sock_type} count={count}",
        flush=True,
    )


def parallel_echo_clients(sock_type, base_port, count):
    validate_parallel_range(base_port, count)
    workers = []

    for offset in range(count):
        port = base_port + offset
        payload = f"PARALLEL-{sock_type}-{offset:02d}".encode()

        def worker(port=port, payload=payload):
            conn = None
            for attempt in range(5):
                candidate = make_socket(sock_type)
                candidate.settimeout(20.0)
                try:
                    candidate.connect((2, port))
                    conn = candidate
                    break
                except ConnectionResetError:
                    candidate.close()
                    if attempt == 4:
                        raise
                    time.sleep(0.2)
                except BaseException:
                    candidate.close()
                    raise
            if conn is None:
                raise RuntimeError(f"port {port} did not connect")
            with conn:
                send_data(conn, sock_type, payload)
                echoed = recv_exact(conn, len(payload))
                if echoed != payload:
                    raise RuntimeError(
                        f"port {port} echo mismatch: {echoed!r} != {payload!r}"
                    )
        workers.append(worker)

    run_parallel(workers, f"parallel {sock_type} clients")
    print(
        f"PASS parallel-echo-clients type={sock_type} count={count}",
        flush=True,
    )


def make_fake_device(
    root,
    name,
    device,
    driver="vmw_vsock_virtio_transport",
    features=(1,),
):
    pci = os.path.join(root, "bus/pci/devices", name)
    child = pci + "/virtio0"
    os.makedirs(child)
    with open(pci + "/vendor", "w", encoding="ascii") as stream:
        stream.write("0x1af4\n")
    with open(pci + "/device", "w", encoding="ascii") as stream:
        stream.write(device + "\n")
    driver_path = os.path.join(root, "bus/virtio/drivers", driver)
    os.makedirs(driver_path, exist_ok=True)
    os.symlink(driver_path, child + "/driver")
    feature_bits = ["0"] * 64
    for bit in features:
        feature_bits[bit] = "1"
    with open(child + "/features", "w", encoding="ascii") as stream:
        stream.write("".join(feature_bits) + "\n")
    return child


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
        make_fake_device(
            root,
            "0000:00:05.0",
            VIRTIO_PCI_MODERN_VSOCK_DEVICE,
            features=(1, 38, 40),
        )
        child = find_bound_vsock(root, VIRTIO_PCI_MODERN_VSOCK_DEVICE)
        if validate_modern_features(child) != "stream-implied,seqpacket":
            raise AssertionError("Linux-compatible implied STREAM was rejected")
        explicit = make_fake_device(
            root,
            "0000:00:08.0",
            BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_DEVICE,
            features=(0, 1, 2),
        )
        if validate_socket_features(explicit) != (
            "stream,seqpacket,no-implied-stream"
        ):
            raise AssertionError("explicit VirtIO 1.4 socket features failed")
        invalid = make_fake_device(
            root,
            "0000:00:09.0",
            BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_DEVICE,
            features=(1, 2),
        )
        try:
            validate_socket_features(invalid)
        except RuntimeError:
            pass
        else:
            raise AssertionError("NO_IMPLIED_STREAM without STREAM was accepted")
        if negotiated_feature(child, 3):
            raise AssertionError("unset vsock feature was reported")
        for missing_bit, missing_name in (
            (VIRTIO_VSOCK_F_SEQPACKET, "VIRTIO_VSOCK_F_SEQPACKET"),
            (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
            (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
        ):
            bitmap = ["0"] * 64
            for bit in (
                VIRTIO_VSOCK_F_SEQPACKET,
                VIRTIO_F_NOTIFICATION_DATA,
                VIRTIO_F_RING_RESET,
            ):
                if bit != missing_bit:
                    bitmap[bit] = "1"
            with open(child + "/features", "w", encoding="ascii") as stream:
                stream.write("".join(bitmap) + "\n")
            try:
                validate_modern_features(child)
            except RuntimeError:
                pass
            else:
                raise AssertionError(
                    f"missing vsock feature {missing_name} was accepted"
                )
        make_fake_device(
            root,
            "0000:00:06.0",
            BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_DEVICE,
            "wrong_driver",
        )
        try:
            find_bound_vsock(root, BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_DEVICE)
        except RuntimeError:
            pass
        else:
            raise AssertionError("device bound to wrong driver was accepted")
        make_fake_device(root, "0000:00:07.0", VIRTIO_PCI_MODERN_VSOCK_DEVICE)
        try:
            find_bound_vsock(root, VIRTIO_PCI_MODERN_VSOCK_DEVICE)
        except RuntimeError:
            pass
        else:
            raise AssertionError("duplicate devices were accepted")
        ioctl_path = os.path.join(root, "vsock")
        with open(ioctl_path, "wb"):
            pass

        def fake_local_cid_ioctl(fd, request, cid, mutate):
            if fd < 0 or request != IOCTL_VM_SOCKETS_GET_LOCAL_CID:
                raise AssertionError("incorrect local-CID ioctl request")
            if not mutate or len(cid) != 1:
                raise AssertionError("incorrect local-CID ioctl argument")
            cid[0] = 4
            return 0

        if get_local_cid(ioctl_path, fake_local_cid_ioctl) != 4:
            raise AssertionError("local-CID ioctl result was decoded incorrectly")
    left, right = socket.socketpair()
    try:
        left.shutdown(socket.SHUT_WR)
        expect_eof(right, "self-test")
    finally:
        left.close()
        right.close()
    left, right = socket.socketpair()
    try:
        left.close()
        if disconnect_outcome(right) != "EOF":
            raise AssertionError("closed peer was not classified as EOF")
    finally:
        left.close()
        right.close()
    if connect_error_name(TimeoutError()) != "ETIMEDOUT":
        raise AssertionError("timeout outcome was misclassified")
    if connect_error_name(ConnectionResetError(errno.ECONNRESET, "reset")) != (
        "ECONNRESET"
    ):
        raise AssertionError("reset outcome was misclassified")
    refused_calls = []

    def fake_refused(cid, port, timeout, sock_type):
        refused_calls.append((cid, port, timeout, sock_type))
        return "ECONNRESET"

    refused_connect_storm("seq", 7108, 3, fake_refused, emit=False)
    if refused_calls != [(2, 7108, 3.0, "seq")] * 3:
        raise AssertionError("refused-connect storm used incorrect endpoints")
    validate_parallel_range(7200, 8)
    for base_port, count in ((0, 8), (7200, 1), (0xFFFFFFFF, 2), (7200, 65)):
        try:
            validate_parallel_range(base_port, count)
        except RuntimeError:
            pass
        else:
            raise AssertionError(
                f"invalid parallel range {base_port}/{count} was accepted"
            )
    completed = []
    run_parallel(
        [lambda index=index: completed.append(index) for index in range(8)],
        "self-test",
    )
    if sorted(completed) != list(range(8)):
        raise AssertionError("parallel worker did not run exactly once")
    try:
        run_parallel(
            [lambda: None, lambda: (_ for _ in ()).throw(ValueError("test"))],
            "self-test-error",
        )
    except RuntimeError as exc:
        if "ValueError: test" not in str(exc):
            raise
    else:
        raise AssertionError("parallel worker failure was ignored")
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


def abrupt_listener(sock_type, port):
    token = b"VSOCK-LIFECYCLE"
    listener = make_socket(sock_type)
    listener.bind((VMADDR_CID_ANY, port))
    listener.listen(1)
    print("up", flush=True)
    conn, _ = listener.accept()
    conn.settimeout(10.0)
    with conn:
        received = recv_exact(conn, len(token))
        if received != token:
            raise RuntimeError(f"abrupt-close probe mismatch: {received!r}")
        send_data(conn, sock_type, received)
        outcome = disconnect_outcome(conn)
    print(f"PASS abrupt-disconnect-listener outcome={outcome}", flush=True)


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) in (4, 5) and sys.argv[1] == "preflight" and sys.argv[2] in (
        "modern",
        "legacy",
    ):
        if len(sys.argv) == 5 and sys.argv[4] != "packed":
            raise SystemExit("optional preflight feature must be packed")
        try:
            expected_cid = int(sys.argv[3], 0)
        except ValueError as exc:
            raise SystemExit("preflight guest CID must be an integer") from exc
        if expected_cid < 3 or expected_cid >= VMADDR_CID_ANY:
            raise SystemExit("preflight guest CID must be in [3, 0xfffffffe]")
        preflight(sys.argv[2], expected_cid, len(sys.argv) == 5)
        return
    if sys.argv[1:] == ["reserved-cids"]:
        reserved_cid_connects()
        return
    if len(sys.argv) < 4:
        raise SystemExit(
            "usage: gvsock.py --self-test | "
            "preflight modern|legacy guest-cid [packed] | "
            "reserved-cids | refused-storm stream|seq port attempts | "
            "parallel-echo-l|parallel-send-echo stream|seq base-port count | "
            "echo-l|hold-l|recv-l|close-l|close|abrupt-l|send|send-echo "
            "stream|seq port [value]"
        )
    command, sock_type, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    if sock_type not in ("stream", "seq"):
        raise SystemExit("socket type must be stream or seq")
    if command == "refused-storm" and len(sys.argv) == 5:
        refused_connect_storm(sock_type, port, int(sys.argv[4]))
    elif command == "parallel-echo-l" and len(sys.argv) == 5:
        parallel_echo_listeners(sock_type, port, int(sys.argv[4]))
    elif command == "parallel-send-echo" and len(sys.argv) == 5:
        parallel_echo_clients(sock_type, port, int(sys.argv[4]))
    elif command == "echo-l" and len(sys.argv) == 4:
        echo_listener(sock_type, port)
    elif command == "hold-l" and len(sys.argv) == 4:
        echo_listener(sock_type, port)
    elif command == "recv-l" and len(sys.argv) == 4:
        receive_listener(sock_type, port)
    elif command == "close-l" and len(sys.argv) == 5:
        close_listener(sock_type, port, sys.argv[4])
    elif command == "close" and len(sys.argv) == 5:
        close_client(sock_type, port, sys.argv[4])
    elif command == "abrupt-l" and len(sys.argv) == 4:
        abrupt_listener(sock_type, port)
    elif command == "send" and len(sys.argv) == 5:
        size = int(sys.argv[4])
        conn = make_socket(sock_type)
        with conn:
            conn.connect((2, port))
            send_data(conn, sock_type, b"G" * size)
            conn.shutdown(socket.SHUT_WR)
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
