#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Decode an explicit uuencoded fixture, optionally decompressing gzip."""
import argparse
import gzip
from pathlib import Path


def decode(data, compressed=False):
    lines = data.splitlines()
    if len(lines) < 3 or not lines[0].startswith(b"begin ") or lines[-1] != b"end":
        raise ValueError("invalid uuencoded fixture framing")
    chunks = []
    for line in lines[1:-1]:
        if not line or any(c < 32 or c > 96 for c in line):
            raise ValueError("invalid uuencoded line characters")
        count = (line[0] - 32) & 63
        if count > 45 or len(line) != 1 + 4 * ((count + 2) // 3):
            raise ValueError("invalid uuencoded line length")
        decoded = bytearray()
        for offset in range(1, len(line), 4):
            a, b, c, d = ((v - 32) & 63 for v in line[offset:offset + 4])
            decoded.extend(((a << 2) | (b >> 4),
                            ((b & 15) << 4) | (c >> 2),
                            ((c & 3) << 6) | d))
        # Traditional uuencoding specifies the byte count independently of
        # the last complete encoded group. BSD uudecode ignores its padding.
        chunks.append(bytes(decoded[:count]))
    payload = b"".join(chunks)
    return gzip.decompress(payload) if compressed else payload


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--gzip", action="store_true")
    p.add_argument("source", type=Path)
    p.add_argument("output", type=Path)
    a = p.parse_args()
    a.output.write_bytes(decode(a.source.read_bytes(), a.gzip))
