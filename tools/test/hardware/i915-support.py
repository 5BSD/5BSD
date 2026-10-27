#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Audit compiled amd64 i915 PCI matches against the upstream table and retirement policy.

This is artifact coverage, not a GPU load/render/suspend test. No module is loaded.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

RETIRED = ('I830', 'I845G', 'I85X', 'I865G', 'I915G', 'I915GM', 'I945G',
           'I945GM', 'I965G', 'G33', 'I965GM', 'GM45', 'G45', 'PNV_G',
           'PNV_M', 'ILK_D', 'ILK_M')


def run(*args):
    return subprocess.check_output(list(map(str, args)), text=True)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--module', type=Path, required=True)
    p.add_argument('--pci-ids-header', type=Path, required=True)
    p.add_argument('--upstream-pci', type=Path, required=True)
    p.add_argument('--cc', required=True)
    p.add_argument('--readelf', required=True)
    p.add_argument('--nm', required=True)
    p.add_argument('--kldxref', required=True)
    a = p.parse_args()
    inputs = [a.module, a.pci_ids_header, a.upstream_pci]
    hashes = {str(path): digest(path) for path in inputs}
    data = a.module.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 62:
        raise ValueError('requires little-endian amd64 ELF module')
    symbols = run(a.readelf, '-sW', a.module)
    matches = [line.split() for line in symbols.splitlines()
               if line.split() and line.split()[-1] == 'pciidlist']
    if len(matches) != 1:
        raise ValueError('requires one unstripped pciidlist symbol')
    _, value, size, kind, bind, visibility, section, name = matches[0]
    if kind != 'OBJECT' or not section.isdecimal():
        raise ValueError('invalid PCI table symbol')
    sections = run(a.readelf, '-SW', a.module)
    row = re.search(r'^\s*\[\s*' + section + r'\]\s+\S+\s+PROGBITS\s+'
                    r'([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)', sections, re.M)
    if row is None:
        raise ValueError('PCI table section not found')
    address, offset, length = (int(v, 16) for v in row.groups())
    start, size = int(value, 16) - address, int(size)
    if start < 0 or size < 64 or size % 32 or start + size > length:
        raise ValueError('unexpected LinuxKPI amd64 PCI table geometry')
    table = data[offset + start:offset + start + size]
    records = list(struct.iter_unpack('<6IQ', table))
    if records[-1] != (0,) * 7:
        raise ValueError('missing PCI table terminator')
    actual = []
    for vendor, device, subvendor, subdevice, cls, mask, info in records[:-1]:
        if vendor != 0x8086 or cls != 0x030000 or mask != 0xff0000:
            raise ValueError('unexpected PCI table record layout')
        actual.append((vendor, device, subvendor, subdevice, cls, mask))
    source = a.upstream_pci.read_text()
    table_source = re.search(r'static const struct pci_device_id pciidlist\[\] = \{(.*?)\n\};', source, re.S)
    if table_source is None:
        raise ValueError('upstream PCI table missing')
    entries = re.sub(r'\{\s*\}\s*$', '', table_source.group(1)).rstrip().rstrip(',')
    entries = re.sub(r'&[A-Za-z_][A-Za-z0-9_]*', '0', entries)
    retired = ',\n'.join('INTEL_' + name + '_IDS(DEVICE_ID, 0)' for name in RETIRED)
    code = '''#include <stdio.h>
#include <stdint.h>
#define DEVICE_ID(id, ...) id
struct match { uint32_t vendor, device, subvendor, subdevice, cls, mask; uintptr_t info; };
_Static_assert(sizeof(struct match) == 32, "requires amd64 PCI record layout");
static const struct match baseline[] = {''' + entries + '''};
static const unsigned retired[] = {''' + retired + '''};
int main(void) {
 for (unsigned i=0; i<sizeof(baseline)/sizeof(baseline[0]); i++) {
  const struct match *m = &baseline[i];
  printf("b %u %u %u %u %u %u\\n",m->vendor,m->device,m->subvendor,m->subdevice,m->cls,m->mask);
 }
 for (unsigned i=0; i<sizeof(retired)/sizeof(retired[0]); i++) printf("r %u\\n",retired[i]);
 return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='i915-support-') as tmp:
        c = Path(tmp) / 'ids.c'; c.write_text(code)
        exe = Path(tmp) / 'ids'
        subprocess.run([a.cc, '-Wall', '-Werror', '-include', str(a.pci_ids_header.resolve()), str(c), '-o', str(exe)], check=True)
        expected = {'b': [], 'r': set()}
        for line in run(exe).splitlines():
            group, *values = line.split()
            if group == 'b': expected['b'].append(tuple(map(int, values)))
            elif group == 'r' and len(values) == 1: expected['r'].add(int(values[0]))
            else: raise ValueError('invalid compiler-expanded PCI record')
    if not expected['r'] <= {row[1] for row in expected['b']}:
        raise ValueError('retirement policy and upstream baseline disagree')
    retained = [row for row in expected['b'] if row[1] not in expected['r']]
    if actual != retained:
        raise ValueError('compiled PCI match records/order differ from upstream minus retired GPUs')
    undefined = run(a.nm, '-u', a.module)
    if re.search(r'\b(?:agp_|intel_gtt_|intel_gmch_gtt_|intel_ggtt_gmch_)', undefined):
        raise ValueError('compiled module still requires the retired backend')
    metadata = run(a.kldxref, '-d', '-m', a.module)
    if not re.search(r'^\s*depends on drmn\.', metadata, re.M):
        raise ValueError('missing i915 module dependency metadata; use the complete module')
    if re.search(r'^\s*depends on agp\.', metadata, re.M):
        raise ValueError('compiled module retains an AGP dependency')
    for path in inputs:
        if digest(path) != hashes[str(path)]:
            raise ValueError('input changed during audit')
    print(json.dumps(dict(result='PASS', retired_devices=len(expected['r']), retained_devices=len(actual),
                         physical_gpu_qualified=False, files_sha256=hashes), indent=2))


if __name__ == '__main__':
    main()
