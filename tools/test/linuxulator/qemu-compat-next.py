#!/usr/bin/env python3
"""Validate the four compatibility batches plus the proc/filesystem stress gate.

Accepts the same arguments as qemu-proc-views.py; use --stress. The guest image
must run guest-compat-next.sh followed by the existing proc/filesystem gate.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def validate(output):
    out = Path(output)
    text = (out / 'console.log').read_text(errors='replace').replace('\r', '')
    rows = re.findall(r'^NEXT (\w+) (\w+) (\d+)$', text, re.M)
    expected = {(u, c, '0') for u in ('root', 'unprivileged')
                for c in ('notify', 'notifyrace', 'discovery', 'abstractextra', 'abstractlife', 'xattredges', 'notifydelete')}
    expected |= {(mode, 'isolation', '0') for mode in ('jail', 'vnet', 'cap')}
    expected |= {(mode, case, '0') for mode in ('base', 'permissions', 'writeback')
                 for case in ('fuse', 'fuse_unprivileged', 'fuse_failure')}
    expected.add(('native', 'fuse_link', '0'))
    abstract = re.findall(r'^ABSTRACT (\d+) (\w+) (\w+) (\d+)$', text, re.M)
    expected_abstract = {(str(n), u, c, '0') for n in range(1, 4)
                         for u in ('root', 'unprivileged')
                         for c in ('stream', 'dgram', 'seqpacket', 'binary', 'autobind')}
    passed = (len(rows) == len(expected) and set(rows) == expected
              and len(abstract) == len(expected_abstract)
              and set(abstract) == expected_abstract
              and '[  PASSED  ] 6 tests.' in text and 'NEXT_DONE' in text
              and 'PROC_VIEWS_DONE' in text and 'Powering system off' in text
              and not re.search(r'panic:|Fatal trap|lock order reversal|'
                                r'non-sleepable locks held', text))
    result = dict(passed=passed, cases=rows, abstract=abstract,
                  native_fuse_tests=6, new_case_count=62)
    (out / 'compat-results.json').write_text(json.dumps(result, indent=2) + '\n')
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument('--output', required=True)
    args, _ = parser.parse_known_args()
    runner = Path(__file__).with_name('qemu-proc-views.py')
    rc = subprocess.call([sys.executable, str(runner), *sys.argv[1:]])
    passed = validate(args.output)
    print('Compatibility additions:', 'PASS' if passed else 'FAIL')
    return 0 if rc == 0 and passed else 1


if __name__ == '__main__':
    sys.exit(main())
