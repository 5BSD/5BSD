#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise source-declared license parent install targets inside buildenv.

These private rootless stages test declarations, not full world coverage.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    work = args.work.absolute()
    if not work.is_relative_to('/usr/obj/usr/src'):
        parser.error('requires a fresh private work directory under /usr/obj/usr/src')
    work.mkdir()
    cases = []
    pattern = re.compile(r'^(\w+)DIR=\s+(/usr/share/licenses/[^/\s]+/[^\s]+)\s*$', re.M)
    for base in ('lib', 'usr.sbin', 'tools/build'):
        for path in sorted((source / base).rglob('Makefile')):
            for match in pattern.finditer(path.read_text()):
                cases.append((path, match.group(1), str(Path(match.group(2)).parent)))
    if not cases:
        raise ValueError('no license file groups discovered')
    report = dict(result='RUNNING', scope='source-declared license ancestor installation', cases=[])
    try:
        for index, (makefile, group, expected_path) in enumerate(cases):
            stage = work / str(index); stage.mkdir()
            log = stage / 'METALOG'; root = stage / 'root'; root.mkdir()
            common = ['make', '-C', str(makefile.parent), 'NO_ROOT=yes']
            query = subprocess.run(common + ['-V', '${' + group + 'DIRTAGS}'],
                capture_output=True, text=True, timeout=60, check=True)
            tags = query.stdout.strip().split()
            if len(tags) != 1 or not tags[0].startswith('package='):
                raise ValueError('ambiguous source package tags: ' + str(makefile))
            command = common + ['installdirs-' + group + 'PARENT', 'DESTDIR=' + str(root),
                'INSTALL=install -U -M ' + str(log) + ' -D ' + str(root)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            item = dict(source=str(makefile), source_sha256=hashlib.sha256(makefile.read_bytes()).hexdigest(),
                        group=group, path=expected_path, tags=tags[0], command=command,
                        exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
            report['cases'].append(item)
            result.check_returncode()
            rows = log.read_text().splitlines()
            wanted = '.' + expected_path
            matched = [r.split() for r in rows if r.split()[0] == wanted]
            if len(matched) != 1 or set(matched[0][1:]) != {
                    'type=dir', 'uname=root', 'gname=wheel', 'mode=0755', 'tags=' + tags[0]}:
                raise AssertionError('directory metadata differs from explicit source expectation: ' + str(rows))
            if not (root / expected_path.lstrip('/')).is_dir():
                raise AssertionError('declared directory was not created')
            item.update(result='PASS', metalog_sha256=hashlib.sha256(log.read_bytes()).hexdigest())
        report.update(result='PASS', case_count=len(cases))
    except BaseException as error:
        report.update(result='FAIL', error=str(error))
        raise
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
