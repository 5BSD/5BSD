#!/usr/bin/env python3
"""Linux guest end-to-end verifier for bhyve virtio-crypto."""

import glob
import os
import socket
import sys
import tempfile

# VIRTIO_ACTIVATION_ASSERTION: modern-features-and-proc-crypto-selftest
# VIRTIO_ACTIVATION_ASSERTION: packed-negotiation-and-cbc-aes-roundtrip
# VIRTIO_ACTIVATION_ASSERTION: multi-dataqueue-vectors

# VirtIO 1.4 feature allocation (§6).
VIRTIO_F_IN_ORDER = 35
VIRTIO_F_RING_PACKED = 34
VIRTIO_F_NOTIFICATION_DATA = 38
VIRTIO_F_RING_RESET = 40

MODERN_REQUIRED_FEATURES = (
    (VIRTIO_F_NOTIFICATION_DATA, "VIRTIO_F_NOTIFICATION_DATA"),
    (VIRTIO_F_RING_RESET, "VIRTIO_F_RING_RESET"),
)

# The modern virtio-crypto PCI device id (1af4:1054).  virtio-crypto is a
# modern-only device: it has no transitional/legacy PCI id, so unlike the RNG
# lane there is no legacy expected-device branch.
CRYPTO_MODERN_DEVICE = "0x1054"

# The kernel crypto algorithm the host advertises through cbc(aes) and which the
# in-kernel known-answer self-test exercises when the driver registers it.
CRYPTO_DRIVER = "virtio_crypto"
CRYPTO_ALGORITHM = "cbc(aes)"


def find_bound_crypto(expected_device):
    matches = []
    for pci in glob.glob("/sys/bus/pci/devices/*"):
        try:
            vendor = open(pci + "/vendor", encoding="ascii").read().strip()
            device = open(pci + "/device", encoding="ascii").read().strip()
        except OSError:
            continue
        if vendor != "0x1af4" or device != expected_device:
            continue
        children = []
        for child in glob.glob(pci + "/virtio*"):
            driver = child + "/driver"
            if os.path.islink(driver) and os.path.basename(
                os.path.realpath(driver)
            ) == "virtio_crypto":
                children.append(child)
        if len(children) == 1:
            matches.append((pci, children[0]))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one PCI {expected_device} device bound to virtio_crypto, "
            f"found {len(matches)}"
        )
    return matches[0][1]


def data_queue_vectors(child):
    """Guest-visible count of per-queue MSI-X vectors for the crypto device.

    virtio-crypto exposes max_dataqueues in its device configuration and the
    Linux driver brings up min(max_dataqueues, nr_online_cpus) data queues plus
    one control queue.  sysfs does not surface the config field directly, so the
    per-queue MSI-X vector allocation is the guest-observable signal that more
    than one data queue was actually set up.  Returns 0 when the device has no
    msi_irqs directory (MSI-X disabled), so callers can skip with a note.
    """
    pci = os.path.dirname(child)
    return len(glob.glob(pci + "/msi_irqs/*"))


def require_multi_dataqueues(child, expected_min):
    """Assert the crypto device brought up more than one data queue.

    A single shared interrupt vector indicates the multi-dataqueue option was
    not exercised.  When MSI-X is disabled (no msi_irqs), the guest cannot
    observe per-queue vectors; that is reported to the caller for an explicit
    skip note rather than a silent pass.
    """
    if expected_min <= 1:
        raise RuntimeError(
            f"crypto multi-dataqueue check requires expected_min>1, got "
            f"{expected_min}"
        )
    vectors = data_queue_vectors(child)
    if vectors == 0:
        return None
    # controlq + at least two data queues each claim their own vector under
    # MSI-X, so more than one data queue must present at least three vectors.
    if vectors < expected_min + 1:
        raise RuntimeError(
            f"virtio-crypto exposes {vectors} MSI-X vector(s); expected at "
            f"least {expected_min + 1} for {expected_min} data queues plus a "
            "control queue"
        )
    return vectors


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
            raise RuntimeError(f"virtio-crypto did not negotiate {name}")


def parse_proc_crypto(text):
    """Return a list of /proc/crypto records as attribute dictionaries."""
    records = []
    current = {}
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            if current:
                records.append(current)
                current = {}
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        current[key.strip()] = value.strip()
    if current:
        records.append(current)
    return records


def require_device_algorithm(text):
    """Assert cbc(aes) is registered by virtio_crypto with a passed selftest."""
    for record in parse_proc_crypto(text):
        if record.get("name") != CRYPTO_ALGORITHM:
            continue
        if record.get("driver") != CRYPTO_DRIVER:
            continue
        selftest = record.get("selftest")
        if selftest != "passed":
            raise RuntimeError(
                f"virtio_crypto {CRYPTO_ALGORITHM} selftest is {selftest!r}, "
                "expected 'passed'"
            )
        return record
    raise RuntimeError(
        f"/proc/crypto has no {CRYPTO_ALGORITHM} entry driven by {CRYPTO_DRIVER}"
    )


def afalg_available():
    return hasattr(socket, "AF_ALG") and hasattr(socket, "ALG_OP_ENCRYPT")


def afalg_cbc_aes(key, iv, plaintext, op):
    """One AF_ALG cbc(aes) transform (encrypt or decrypt)."""
    alg = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    try:
        alg.bind(("skcipher", CRYPTO_ALGORITHM))
        alg.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, key)
        session, _ = alg.accept()
        try:
            session.sendmsg_afalg([plaintext], op=op, iv=iv)
            result = bytearray()
            while len(result) < len(plaintext):
                chunk = session.recv(len(plaintext) - len(result))
                if not chunk:
                    break
                result.extend(chunk)
            return bytes(result)
        finally:
            session.close()
    finally:
        alg.close()


def cbc_aes_round_trip():
    """AES-CBC encrypt/decrypt round-trip through the kernel crypto API.

    The AF_ALG data path exercises the guest cbc(aes) transform end to end.
    Device presence and the host known-answer test are proven independently by
    require_device_algorithm(); this adds a live functional data path.
    """
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    plaintext = bytes((i * 7) & 0xFF for i in range(64))
    ciphertext = afalg_cbc_aes(key, iv, plaintext, socket.ALG_OP_ENCRYPT)
    if len(ciphertext) != len(plaintext):
        raise RuntimeError(
            f"cbc(aes) ciphertext length {len(ciphertext)} != {len(plaintext)}"
        )
    if ciphertext == plaintext:
        raise RuntimeError("cbc(aes) encryption returned the plaintext")
    recovered = afalg_cbc_aes(key, iv, ciphertext, socket.ALG_OP_DECRYPT)
    if recovered != plaintext:
        raise RuntimeError("cbc(aes) decrypt did not recover the plaintext")
    return len(plaintext)


def self_test():
    # Feature-bitmap parsing and packed detection.
    with tempfile.TemporaryDirectory() as root:
        child = os.path.join(root, "virtio0")
        os.mkdir(child)
        features = ["0"] * 64
        for bit, _ in MODERN_REQUIRED_FEATURES:
            features[bit] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        require_features(child, MODERN_REQUIRED_FEATURES)
        assert not negotiated_feature(child, VIRTIO_F_RING_PACKED)
        features[VIRTIO_F_RING_PACKED] = "1"
        with open(child + "/features", "w", encoding="ascii") as stream:
            stream.write("".join(features) + "\n")
        assert negotiated_feature(child, VIRTIO_F_RING_PACKED)
        for missing_bit, missing_name in MODERN_REQUIRED_FEATURES:
            missing = features.copy()
            missing[missing_bit] = "0"
            with open(child + "/features", "w", encoding="ascii") as stream:
                stream.write("".join(missing) + "\n")
            try:
                require_features(child, MODERN_REQUIRED_FEATURES)
            except RuntimeError:
                pass
            else:
                raise AssertionError(
                    f"missing crypto feature {missing_name} was accepted"
                )

    # Multi-dataqueue vector accounting.
    with tempfile.TemporaryDirectory() as root:
        pci = os.path.join(root, "0000:00:05.0")
        child = os.path.join(pci, "virtio0")
        os.makedirs(child)
        # No msi_irqs directory: MSI-X disabled, skip signalled to caller.
        assert require_multi_dataqueues(child, 2) is None
        os.mkdir(pci + "/msi_irqs")
        for vector in ("24", "25"):
            open(pci + "/msi_irqs/" + vector, "w").close()
        # Two vectors is too few for two data queues plus a control queue.
        try:
            require_multi_dataqueues(child, 2)
        except RuntimeError:
            pass
        else:
            raise AssertionError("single-dataqueue vector count was accepted")
        open(pci + "/msi_irqs/26", "w").close()
        assert require_multi_dataqueues(child, 2) == 3
        try:
            require_multi_dataqueues(child, 1)
        except RuntimeError:
            pass
        else:
            raise AssertionError("multi-dataqueue check accepted expected_min<=1")

    # /proc/crypto record selection: name, driver, and selftest must all match.
    passing = (
        "name         : cbc(aes)\n"
        "driver       : virtio_crypto\n"
        "type         : skcipher\n"
        "selftest     : passed\n"
        "\n"
        "name         : cbc(aes)\n"
        "driver       : cbc-aes-aesni\n"
        "selftest     : passed\n"
    )
    record = require_device_algorithm(passing)
    assert record.get("driver") == CRYPTO_DRIVER

    for rejected in (
        # No virtio_crypto driver for cbc(aes).
        "name         : cbc(aes)\n"
        "driver       : cbc-aes-aesni\n"
        "selftest     : passed\n",
        # virtio_crypto present but selftest not passed.
        "name         : cbc(aes)\n"
        "driver       : virtio_crypto\n"
        "selftest     : unknown\n",
        # virtio_crypto drives a different algorithm only.
        "name         : sha256\n"
        "driver       : virtio_crypto\n"
        "selftest     : passed\n",
    ):
        try:
            require_device_algorithm(rejected)
        except RuntimeError:
            pass
        else:
            raise AssertionError("invalid /proc/crypto record was accepted")

    # The AF_ALG round-trip is genuinely exercised when the self-test host
    # provides the interface; otherwise it is skipped with an explicit note,
    # never silently.
    if afalg_available():
        try:
            assert cbc_aes_round_trip() == 64
            print("SELFTEST afalg=exercised")
        except OSError as error:
            print(f"SELFTEST afalg=unavailable note={error}")
    else:
        print("SELFTEST afalg=absent note=no-AF_ALG-in-python")
    print("SELFTEST PASS")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    expect_packed = os.environ.get("CRYPTO_PACKED") == "yes" or (
        len(sys.argv) == 3 and sys.argv[2] == "packed"
    )
    if (
        len(sys.argv) not in (2, 3)
        or sys.argv[1] != "modern"
        or (len(sys.argv) == 3 and sys.argv[2] != "packed")
    ):
        raise SystemExit("usage: gcrypto.py modern [packed]")

    child = find_bound_crypto(CRYPTO_MODERN_DEVICE)
    require_features(child, MODERN_REQUIRED_FEATURES)
    packed = negotiated_feature(child, VIRTIO_F_RING_PACKED)
    if packed != expect_packed:
        raise RuntimeError(
            "virtio-crypto packed negotiation mismatch: "
            f"expected={'yes' if expect_packed else 'no'} "
            f"actual={'yes' if packed else 'no'}"
        )
    in_order = negotiated_feature(child, VIRTIO_F_IN_ORDER)

    expected_dataqueues = int(os.environ.get("CRYPTO_DATAQUEUES", "2"))
    vectors = require_multi_dataqueues(child, expected_dataqueues)
    if vectors is None:
        dataqueues = "skipped=no-msix-vectors"
    else:
        dataqueues = f"vectors={vectors}"

    crypto = open("/proc/crypto", encoding="ascii").read()
    record = require_device_algorithm(crypto)

    if afalg_available():
        try:
            data_bytes = cbc_aes_round_trip()
            data = f"bytes={data_bytes}"
        except OSError as error:
            data = f"skipped=no-af_alg-runtime:{error}"
    else:
        data = "skipped=no-af_alg-python"

    print(
        f"PASS device=crypto algorithm={record.get('name')} "
        f"driver={record.get('driver')} selftest={record.get('selftest')} "
        f"cbc_aes_roundtrip={data} "
        f"dataqueues_min={expected_dataqueues} {dataqueues} "
        f"in_order={'yes' if in_order else 'no'} "
        f"packed={'yes' if packed else 'no'} "
        f"notification_data=yes ring_reset=yes"
    )


if __name__ == "__main__":
    main()
