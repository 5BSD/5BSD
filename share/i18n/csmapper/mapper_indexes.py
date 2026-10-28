# SPDX-License-Identifier: BSD-2-Clause
"""Preserve the Citrus mapper directory and pivot table formats."""
import json
from pathlib import Path
import sys


def generate(request):
    def source(name):
        return Path(request['sources'][name]).read_text()

    directories, pivots = [], []
    for family in request['families']:
        name, mode, parts = family['name'], family['mode'], family['parts']
        d = '' if mode == 'koi' else '# ' + name + '\n'
        p = d
        ds, ps = name + '/mapper.dir.' + name + '.src', name + '/charset.pivot.' + name + '.src'
        if mode in ('source', 'koi'):
            d += source(ds)
            p += source(ps)
        if mode == 'iso8859':
            d += '%-32s%-16s\n' % ('ISO-8859-1/UCS', 'mapper_none')
            d += '%-32s%-16s%s\n' % ('UCS/ISO-8859-1', 'mapper_zone', '0x00-0xFF')
        for part in parts:
            encoding = family['encoding'].replace('{part}', part)
            filename = part.replace(':', '@')
            if mode in ('generic', 'cp', 'iso8859'):
                forward = family['forward'].replace('{part}', filename)
                reverse = family['reverse'].replace('{part}', filename)
                fmt = '%-32s%-32s%s\n' if mode == 'generic' else '%-32s%-16s%s\n'
                d += fmt % (encoding + '/UCS', family['mapper'], name + '/' + forward)
                d += fmt % ('UCS/' + encoding, family['mapper'], family['reverse_prefix'] + name + '/' + reverse)
            elif mode == 'koi':
                d += '%-31s %-31s %s\n' % (encoding + 'EXT/UCS', 'mapper_std', 'KOI/' + encoding + '%UCS.mps')
                d += '%-31s %-31s %s\n' % ('UCS/' + encoding + 'EXT', 'mapper_std', 'KOI/UCS%' + encoding + '.mps')
            if mode != 'source':
                fmt = '%-31s %-31s%d\n' if mode == 'koi' else '%-32s%-32s%d\n'
                p += fmt % (encoding, 'UCS', 1) + fmt % ('UCS', encoding, 1)
            if mode == 'iso8859':
                gr = encoding + ':GR'
                d += '%-32s%-16s%s\n' % (gr + '/' + encoding, 'mapper_zone', '0x00 - 0x7F : +0x80')
                d += '%-32s%-16s%s\n' % (encoding + '/' + gr, 'mapper_zone', '0x80 - 0xFF : -0x80')
                d += '%-32s%-16s%s\n' % (gr + '/UCS', 'mapper_serial', gr + '/' + encoding + ',' + encoding + '/UCS')
                d += '%-32s%-16s%s\n' % ('UCS/' + gr, 'mapper_serial', 'UCS/' + encoding + ',' + encoding + '/' + gr)
                p += '%-32s%-32s%d\n' % (gr, 'UCS', 1) + '%-32s%-32s%d\n' % ('UCS', gr, 1)
        if mode == 'koi':
            for part in parts:
                encoding = family['encoding'].replace('{part}', part)
                d += '%-31s %-31s %s\n' % (encoding + '/UCS', 'mapper_parallel', 'GOST19768-74/UCS,' + encoding + 'EXT/UCS')
                d += '%-31s %-31s %s\n' % ('UCS/' + encoding, 'mapper_parallel', 'UCS/GOST19768-74,UCS/' + encoding + 'EXT')
        if mode == 'cp':
            d += source(ds)
            p += source(ps)
        if mode not in ('source', 'generic', 'cp', 'koi', 'iso8859'):
            raise ValueError('unknown mapper policy: ' + mode)
        directories.append(d + '\n')
        pivots.append(p + '\n')
    return ((''.join(directories) + source('mapper.dir.src')).rstrip('\n') + '\n',
            (''.join(pivots) + source('charset.pivot.src')).rstrip('\n') + '\n')


if __name__ == '__main__':
    directory, pivot = generate(json.loads(Path(sys.argv[1]).read_text()))
    Path(sys.argv[2]).write_text(directory)
    Path(sys.argv[3]).write_text(pivot)
