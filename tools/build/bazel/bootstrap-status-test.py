#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the actual Bazel bootstrap run helper's exit-status contract."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--buildenv', type=Path, required=True)
    parser.add_argument('--bash', type=Path, required=True)
    args = parser.parse_args()
    data = args.buildenv.read_bytes()
    source = data.decode()
    start = source.index('function run() {\n')
    end = source.index('\nfunction display()', start)
    function = source[start:end]
    checks = []
    with tempfile.TemporaryDirectory() as temporary:
        for verbose in ('yes', 'no'):
            for status in (0, 1, 37, 134):
                # The source body is the real helper, not a reimplementation.
                script = ('set -o errexit\nOUTPUT_DIR=$1\nVERBOSE=$2\n' + function +
                          '\nrun /bin/sh -c "exit $3"\nprintf "REACHED_END\\n"\n')
                result = subprocess.run([str(args.bash), '-c', script, 'bootstrap-status-test',
                    temporary, verbose, str(status)], text=True, capture_output=True, timeout=10)
                if result.returncode != status or ('REACHED_END' in result.stdout) != (status == 0):
                    raise SystemExit('bootstrap run helper lost status: ' + json.dumps(dict(
                        verbose=verbose, expected=status, actual=result.returncode,
                        stdout=result.stdout, stderr=result.stderr)))
                checks.append(dict(verbose=verbose, status=status))
    print(json.dumps(dict(result='PASS', checks=checks,
        buildenv_sha256=hashlib.sha256(data).hexdigest(),
        scope='native bootstrap helper error propagation, not Bazel compilation')))


if __name__ == '__main__':
    main()
