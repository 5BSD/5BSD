#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Build the three changed base programs in separate tracing variants."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, default=Path('/usr/src'))
    parser.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-dtrace-sixth-validation'))
    args = parser.parse_args()
    results = []
    jobs = [('usr.sbin/cron/lib', None)] + [
        (component, enabled) for component in
        ('bin/dd', 'bin/mv', 'usr.sbin/cron/cron') for enabled in (True, False)]
    for component, enabled in jobs:
        ident = component.replace('/', '_')
        if enabled is not None:
            ident += '-hooks' if enabled else '-nohooks'
        out = args.obj / 'base' / ident
        out.mkdir(parents=True, exist_ok=True)
        command = ['make', '-C', str(args.src / component), '-m', str(args.src / 'share/mk'),
                   '-j' + str(os.cpu_count()), 'SRCTOP=' + str(args.src),
                   'MAKEOBJDIR=' + str(out), 'MK_TESTS=no',
                   'MK_DTRACE=' + ('yes' if enabled else 'no')]
        if component == 'usr.sbin/cron/cron':
            command += ['LIBCRONDIR=' + str(args.obj / 'base/usr.sbin_cron_lib')]
            # Relink against this run's internal library, not a stale world copy.
            for name in ('cron', 'cron.full', 'cron.debug'):
                (out / name).unlink(missing_ok=True)
        command += ['all']
        with (out / 'build.log').open('w') as log:
            log.write(shlex.join(command) + '\n')
            log.flush()
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        results.append(dict(component=component, hooks=enabled, command=command,
                            directory=str(out), status=result.returncode))
        (args.obj / 'base-results.json').write_text(json.dumps(results, indent=2) + '\n')
        print(ident, 'PASS' if result.returncode == 0 else 'FAIL', flush=True)
        if result.returncode:
            print('\n'.join((out / 'build.log').read_text().splitlines()[-25:]))
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
