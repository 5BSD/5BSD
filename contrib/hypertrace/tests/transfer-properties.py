#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Independent HTX1/HJM1/HJX1 fixtures against production transfer helpers."""
import ctypes as C
import hashlib
import json
import random
import struct
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = out / 'adapter.c'
source.write_text('''#include "dtraced_transfer_wire.h"
int validate(const unsigned char *p, size_t n, const unsigned char *t) {
 return dtraced_transfer_wire_valid(p,n,t);
}
int inspect(const unsigned char *p, size_t n, const unsigned char *t, int *i, int *j) {
 return dtraced_transfer_wire_inspect(p,n,t,i,j);
}
int replay(const unsigned char *p, size_t n, const unsigned char *t, size_t e, size_t c, size_t *r) {
 return dtraced_transfer_wire_replay_controls(p,n,t,e,c,r);
}
int required(const unsigned char *p, size_t n, const unsigned char *t, int *r) {
 return dtraced_transfer_wire_requires_import(p,n,t,r);
}
''')
binary = out / 'adapter.so'
command = ['cc', '-shared', '-fPIC', '-O0', '-g', '-Wall', '-Wextra', '-Werror',
           '-I' + str(root / 'sys'), '-I' + str(root / 'usr.sbin/dtraced'),
           str(source), '-lcrypto', '-o', str(binary)]
subprocess.run(command, check=True)
lib = C.CDLL(str(binary), use_errno=True)
base = [C.c_void_p, C.c_size_t, C.c_void_p]
lib.validate.argtypes = base
lib.inspect.argtypes = base + [C.POINTER(C.c_int), C.POINTER(C.c_int)]
lib.replay.argtypes = base + [C.c_size_t, C.c_size_t, C.POINTER(C.c_size_t)]
lib.required.argtypes = base + [C.POINTER(C.c_int)]
for name in ('validate', 'inspect', 'replay', 'required'):
    getattr(lib, name).restype = C.c_int
rng = random.Random(0x5b5d2027)
token = bytes(range(1, 17))
results = []
def seal(body):
    return bytes(body) + hashlib.sha256(body).digest()
def bundle(manifest, frames):
    return seal(b'HTX1' + token + struct.pack('<III', len(manifest), len(frames), 0)
                + manifest + b''.join(struct.pack('<I', len(f)) + f for f in frames))
def wrapped(archive):
    manifest = b'HJM1' + struct.pack('<I', 1) + token + struct.pack('<II', 0, 0) + archive[-32:]
    return bundle(manifest, [archive])
def archive(records, deliveries, kills, cleanups):
    header = bytearray(64)
    header[:4] = b'HJX1'
    struct.pack_into('<I', header, 4, 1)
    header[8:24] = token
    struct.pack_into('<HHH', header, 56, deliveries, kills, cleanups)
    return seal(header + records)
def check(name, wire, valid, journal=0, controls=0, chunk=64, ingress=0):
    assert lib.validate(wire, len(wire), token) == int(valid), name
    if valid:
        i, j, r = C.c_int(-1), C.c_int(-1), C.c_int(-1)
        assert lib.inspect(wire, len(wire), token, C.byref(i), C.byref(j)) == 1, name
        assert (i.value, j.value) == (ingress, journal), name
        assert lib.required(wire, len(wire), token, C.byref(r)) == 1, name
        assert r.value == int(bool(ingress or journal)), name
        count = C.c_size_t(999)
        assert lib.replay(wire, len(wire), token, 24, chunk, C.byref(count)) == 1, name
        assert count.value == controls, (name, count.value, controls)
    results.append({'case': name, 'passed': True})
check('empty', bundle(b'', []), True)
check('ingress', bundle(b'abc', [b'frame']), True, ingress=1)
for sample in range(128):
    records = bytearray()
    deliveries, kills, cleanups = [rng.randrange(9) for _ in range(3)]
    chunk = rng.choice([1, 4, 63, 64, 65, 4096])
    expected = kills
    for _ in range(deliveries):
        revoked = rng.randrange(2)
        version = rng.choice([4, 5])
        record_size = 143 if version == 4 else 185
        record = ('HTD%d' % version).encode() + bytes(record_size - 4)
        bare = b'\x7fELF' + rng.randbytes(rng.randrange(256))
        payload = b'' if revoked else (bytes(24) if rng.randrange(2) else b'') + bare
        if not revoked:
            expected += (len(bare) + chunk - 1) // chunk
        records += struct.pack('<BBBBHHI', 1, rng.choice([97, 105]), revoked, 0,
                               record_size, 0, len(payload)) + record + payload
    for k in range(kills):
        records += struct.pack('<BBBBI', 2, 1, 0, 0, k + 2) + token
    for k in range(cleanups):
        active = rng.randrange(2)
        expected += active
        records += struct.pack('<BB6xQ', 3, 97 if active else 103, k + 1)
    wire = wrapped(archive(records, deliveries, kills, cleanups))
    check('journal-%d' % sample, wire, True, journal=1, controls=expected, chunk=chunk)
    # Corrupt each region without updating its digest.
    for pos in [0, 4, 20, 24, 28, 32, len(wire)//2, len(wire)-1]:
        damaged = bytearray(wire); damaged[pos] ^= 1
        check('corrupt-%d-%d' % (sample, pos), bytes(damaged), False)
# Every truncated prefix of a nonempty journal bundle must be rejected.
wire = wrapped(archive(struct.pack('<BB6xQ', 3, 97, 1), 0, 0, 1))
for n in range(len(wire)):
    check('truncate-%d' % n, wire[:n], False)
# Valid nested and outer hashes must not mask invalid replay record semantics.
bad_records = [
    (struct.pack('<BBBBI', 2, 1, 0, 0, 1) + token, 0, 1, 0),
    (struct.pack('<BBBBI', 2, 1, 0, 0, 2) + bytes(16), 0, 1, 0),
    ((struct.pack('<BBBBI', 2, 1, 0, 0, 2) + token)*2, 0, 2, 0),
    (struct.pack('<BB6xQ', 3, 97, 0), 0, 0, 1),
    (struct.pack('<BB6xQ', 3, 97, 1)*2, 0, 0, 2),
    (struct.pack('<BB6xQ', 3, 120, 1), 0, 0, 1),
    (b'\0', 0, 0, 0),
    (b'', 1, 0, 0), (b'', 0, 1, 0), (b'', 0, 0, 1),
]
for n, args in enumerate(bad_records):
    wire = wrapped(archive(*args))
    assert lib.validate(wire, len(wire), token) == 1
    i, j = C.c_int(), C.c_int()
    assert lib.inspect(wire, len(wire), token, C.byref(i), C.byref(j)) == 1
    count = C.c_size_t(999)
    assert lib.replay(wire, len(wire), token, 24, 64, C.byref(count)) == 0
    assert count.value == 0
    results.append({'case': 'resealed-invalid-record-%d' % n, 'passed': True})
# Recompute the outer digest after corrupting frame lengths/counts.
wire = bundle(b'abc', [b'frame'])
for offset, value in [(20, 0), (20, 0xffffffff), (24, 0), (24, 2),
                      (24, 65537), (28, 1), (35, 0), (35, 4), (35, 6),
                      (35, 0xffffffff)]:
    body = bytearray(wire[:-32])
    struct.pack_into('<I', body, offset, value)
    check('resealed-framing-%d-%d' % (offset, value), seal(body), False)
# Outer authentication succeeds, but malformed nested headers must fail inspection.
original = archive(b'', 0, 0, 0)
for offset in [0, 4, 8, 42, 43, 44, 45, 46, 47, 62, 63]:
    body = bytearray(original[:-32]); body[offset] ^= 1
    wire = wrapped(seal(body))
    assert lib.validate(wire, len(wire), token) == 1
    i, j, required = C.c_int(-1), C.c_int(-1), C.c_int(17)
    assert lib.inspect(wire, len(wire), token, C.byref(i), C.byref(j)) == 0
    assert lib.required(wire, len(wire), token, C.byref(required)) == 0
    assert required.value == 17
    results.append({'case': 'resealed-nested-header-%d' % offset, 'passed': True})
# Reject invalid API parameters before touching caller-provided output.
wire = bundle(b'', [])
assert lib.validate(None, 64, token) == 0
assert lib.validate(wire, len(wire), None) == 0
assert lib.validate(wire, len(wire), bytes(16)) == 0
assert lib.required(wire, len(wire), token, None) == 0
for envelope, chunk in [(0, 64), (24, 0)]:
    count = C.c_size_t(123)
    assert lib.replay(wire, len(wire), token, envelope, chunk, C.byref(count)) == 0
    assert count.value == 123
results.append({'case': 'invalid-api-parameters', 'passed': True})
paths = [Path(__file__), source, binary, root/'usr.sbin/dtraced/dtraced_transfer_wire.h',
         root/'usr.sbin/dtraced/dtraced_wire.h']
(out/'results.json').write_text(json.dumps({'results': results, 'command': command,
    'live_testing': False, 'sanitized': False,
    'sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}}, indent=2)+'\n')
print('PASS: %d independent transfer/journal cases' % len(results))
