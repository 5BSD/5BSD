#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise PNP metadata in real synthetic ELF objects, never kernel-load them."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import shutil
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kldxref', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    tool = args.kldxref.resolve(strict=True)
    fixtures = args.fixtures.resolve(strict=True)
    work = args.work.resolve(strict=False); work.mkdir(mode=0o700)
    cases = []
    expected = None
    for index, name in enumerate(('valid', 'missing_colon', 'long_type', 'short_row', 'negative_count', 'bad_string', 'no_metadata', 'ignored_flags_before_description', 'missing_flags_before_description')):
        source = fixtures / f'pnp-{index}.ko'
        root = work / name; root.mkdir()
        shutil.copyfile(source, root / 'fixture.ko')
        if index and expected is not None:
            (root / 'linker.hints').write_bytes(expected)
        def limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
        try:
            result = subprocess.run([str(tool), str(root)], capture_output=True, timeout=10, preexec_fn=limits)
            code = result.returncode
            diagnostic = result.stderr.decode(errors='replace')
        except subprocess.TimeoutExpired:
            code, diagnostic = None, 'timeout'
        hints = root / 'linker.hints'
        if index in (0, 7):
            passed = code == 0 and hints.is_file() and b'fixture-device' in hints.read_bytes()
            if passed and index == 0:
                expected = hints.read_bytes()
        elif index == 6:
            passed = code == 0 and not hints.exists()
        else:
            passed = (expected is not None and code is not None and code > 0 and
                      hints.is_file() and hints.read_bytes() == expected)
        clean = not list(root.glob('lhint.*'))
        cases.append(dict(case=name, input_sha256=sha(source), returncode=code, stderr=diagnostic,
                          temporary_files_removed=clean, passed=passed and clean))
    report = dict(format=1, result='PASS' if all(c['passed'] for c in cases) else 'FAIL',
                  scope='synthetic ELF PNP parsing', tool_sha256=sha(tool), cases=cases)
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PNP_AUDIT ' + json.dumps(report, sort_keys=True))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
