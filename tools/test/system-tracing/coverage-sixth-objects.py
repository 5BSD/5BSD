#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Verify this expansion's ELF64 amd64 SDT sites and inactive NOPs."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


class Object:
    def __init__(self, path):
        self.data = path.read_bytes()
        assert self.data[:6] == b'\x7fELF\x02\x01', path
        assert struct.unpack_from('<HH', self.data, 16) == (1, 62), path
        offset = struct.unpack_from('<Q', self.data, 40)[0]
        size, count, strings = struct.unpack_from('<HHH', self.data, 58)
        self.sections = [struct.unpack_from('<IIQQQQIIQQ', self.data,
                                          offset + i * size) for i in range(count)]
        names = self.section_data(strings)
        self.names = {self.string(names, s[0]): i for i, s in enumerate(self.sections)}
        index = self.names['.symtab']
        symtab = self.sections[index]
        strings = self.section_data(symtab[6])
        data = self.section_data(index)
        self.symbols = []
        for offset in range(0, len(data), symtab[9]):
            name, info, other, section, value, size = struct.unpack_from(
                '<IBBHQQ', data, offset)
            self.symbols.append(dict(name=self.string(strings, name),
                                     section=section, value=value))

    @staticmethod
    def string(data, offset):
        return data[offset:].split(b'\0', 1)[0].decode()

    def section_data(self, index):
        section = self.sections[index]
        return self.data[section[4]:section[4] + section[5]]

    def tracepoints(self):
        result = []
        index = self.names.get('set_sdt_tracepoint_set')
        if index is None:
            return result
        relocations = {}
        for i, sec in enumerate(self.sections):
            if sec[1] != 4 or sec[7] != index:  # SHT_RELA, target section
                continue
            assert sec[6] == self.names['.symtab']
            data = self.section_data(i)
            for offset in range(0, len(data), sec[9]):
                target, info, addend = struct.unpack_from('<QQq', data, offset)
                assert info & 0xffffffff == 1  # R_X86_64_64
                sym = self.symbols[info >> 32]
                relocations[target] = (sym['section'], sym['value'] + addend)
        assert self.sections[index][5] % 32 == 0
        for offset in range(0, self.sections[index][5], 32):
            probe, patch, target = [relocations[offset + n] for n in (0, 8, 16)]
            result.append((probe, patch, target))
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, default=Path('/usr/src'))
    parser.add_argument('--obj', type=Path, default=Path(
        '/usr/obj/5bsd-dtrace-sixth-validation'))
    args = parser.parse_args()
    inventory = json.loads((args.src /
        'tools/test/system-tracing/coverage-sixth.json').read_text())
    compiles = json.loads((args.obj / 'compile/compile-results.json').read_text())
    results = []
    for source, digest in inventory['sources'].items():
        if not source.startswith('sys/'):
            continue
        assert hashlib.sha256((args.src / source).read_bytes()).hexdigest() == digest
        jobs = [j for j in compiles if str(args.src / source) in j['command']]
        assert len(jobs) == (4 if source == 'sys/ufs/ufs/ufs_quota.c' else 2)
        wanted = [p for p in inventory['probes'] if p['source'] == source]
        for job in jobs:
            assert job['status'] == 0 and job['source_sha256'] == digest
            enabled = job['name'].endswith('-hooks')
            path = Path(job['command'][job['command'].index('-o') + 1])
            obj = Object(path)
            sites = obj.tracepoints()
            symbols = {s['name']: s for s in obj.symbols}
            for probe in wanted:
                name = 'sdt_' + probe['provider'] + '___' + probe['name'].replace('-', '__')
                if not enabled:
                    assert name not in symbols, (path, name)
                    continue
                symbol = symbols[name]
                location = (symbol['section'], symbol['value'])
                matches = [(patch, target) for p, patch, target in sites if p == location]
                assert matches, (path, name, 'no executable tracepoint')
                for patch, target in matches:
                    for section, offset in (patch, target):
                        assert obj.sections[section][2] & 4  # SHF_EXECINSTR
                        assert 0 <= offset < obj.sections[section][5]
                    section, offset = patch
                    # asm-goto leaves a NOP until SDT explicitly enables this site.
                    assert obj.section_data(section)[offset:offset + 5] == bytes.fromhex(
                        '66 0f 1f 04 00'), (path, name, patch)
            results.append(dict(object=str(path), hooks=enabled,
                                checked_probes=len(wanted), status=0))
    (args.obj / 'object-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(len(results), 'objects: executable SDT relocations, inactive NOPs and no-hooks absence PASS')


if __name__ == '__main__':
    main()
