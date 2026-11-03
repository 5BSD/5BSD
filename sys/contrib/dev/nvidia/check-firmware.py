# SPDX-License-Identifier: BSD-2-Clause
"""Check source-decoded firmware bytes and a target ELF wrapper without execution."""
import argparse
import binascii
from pathlib import Path
import struct


def decode_source(path):
    lines = path.read_bytes().splitlines()
    if not lines or len(lines[0].split()) != 3 or lines[0].split()[0] != b"begin":
        raise ValueError("expected one uuencoded source payload")
    result = bytearray()
    ended = False
    for index, line in enumerate(lines[1:], 1):
        if line == b"end":
            if not ended or any(lines[index + 1:]):
                raise ValueError("invalid payload terminator or trailing data")
            return bytes(result)
        if ended or not line:
            raise ValueError("invalid uuencoded payload line")
        count = (line[0] - 32) & 63
        if count > 45:
            raise ValueError("unsupported uuencoded line length")
        value = binascii.a2b_uu(line)
        if len(value) != count:
            raise ValueError("uuencoded byte count mismatch")
        result.extend(value)
        ended = count == 0
    raise ValueError("missing payload terminator")


def verify(source, decoded, object_path, machine, symbol):
    payload = decode_source(source)
    if not payload or decoded.read_bytes() != payload:
        raise ValueError("decoded artifact differs from independently decoded source")
    data = object_path.read_bytes()
    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(data):
            raise ValueError("ELF structure outside artifact")
        return struct.unpack_from(fmt, data, offset)
    header = unpack("<16sHHIQQQIHHHHHH", 0)
    if header[0][:7] != b"\x7fELF\x02\x01\x01" or header[1:4] != (1, machine, 1):
        raise ValueError("expected selected little-endian ELF64 relocatable target")
    shoff, shsize, shnum, shstr = header[6], header[11], header[12], header[13]
    if shsize != 64 or shnum == 0 or not 0 < shstr < shnum:
        raise ValueError("unsupported ELF section table")
    sections = [unpack("<IIQQQQIIQQ", shoff + n * shsize) for n in range(shnum)]
    def content(section):
        offset, size = section[4:6]
        if offset > len(data) or size > len(data) - offset:
            raise ValueError("ELF section outside artifact")
        return data[offset:offset + size]
    strings = content(sections[shstr])
    def string(table, offset):
        if not 0 <= offset < len(table):
            raise ValueError("ELF string outside table")
        end = table.find(b"\0", offset)
        if end < 0:
            raise ValueError("unterminated ELF string")
        return table[offset:end].decode("ascii")
    selected = [(n, s) for n, s in enumerate(sections) if string(strings, s[0]) == ".rodata"]
    if len(selected) != 1:
        raise ValueError("expected one firmware rodata section")
    index, rodata = selected[0]
    if rodata[1] != 1 or rodata[2] != 2 or content(rodata) != payload:
        raise ValueError("ELF firmware section metadata or bytes differ from source")
    for section in sections:
        if section[1] in (4, 9) and section[7] == index and section[5]:
            raise ValueError("embedded firmware unexpectedly contains relocations")
    expected = {"_binary_" + symbol + "_start": (0, len(payload)),
                "_binary_" + symbol + "_end": (len(payload), 0)}
    seen = {}
    for section in sections:
        if section[1] != 2:
            continue
        if section[9] != 24 or section[5] % 24 or section[6] >= len(sections):
            raise ValueError("invalid ELF symbol table")
        names = content(sections[section[6]])
        for offset in range(section[4], section[4] + section[5], 24):
            name, info, other, shndx, value, size = unpack("<IBBHQQ", offset)
            name = string(names, name)
            if name in expected:
                if name in seen or (info, other, shndx) != (17, 0, index):
                    raise ValueError("invalid or duplicate firmware object symbol")
                seen[name] = (value, size)
    if seen != expected:
        raise ValueError("firmware object symbol ranges differ from source payload")
    print("PASS source decode, ELF payload and symbol ranges:", len(payload), "bytes")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--decoded", type=Path, required=True)
    p.add_argument("--object", type=Path, required=True)
    p.add_argument("--machine", type=int, required=True)
    p.add_argument("--symbol", required=True)
    args = p.parse_args()
    verify(args.source, args.decoded, args.object, args.machine, args.symbol)
