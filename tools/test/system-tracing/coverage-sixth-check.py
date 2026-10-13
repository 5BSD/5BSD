#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check expansion contracts, installed profile selection and offline D syntax.

This is not live provider/workload qualification. No DTrace device is needed.
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, default=Path('/usr/src'))
    parser.add_argument('--output', type=Path,
                        default=Path('/usr/obj/5bsd-dtrace-sixth-validation/profiles'))
    parser.add_argument('--bsdinstruments', default='/usr/sbin/bsdinstruments')
    args = parser.parse_args()
    tests = args.src / 'tools/test/system-tracing'
    inventory = json.loads((tests / 'coverage-sixth.json').read_text())
    helper = importlib.util.spec_from_file_location(
        'profile_contracts', tests / 'coverage-third-profile-check.py')
    contracts = importlib.util.module_from_spec(helper)
    helper.loader.exec_module(contracts)
    profile_dir = args.src / 'cddl/usr.sbin/bsdinstruments/profiles'
    installed = subprocess.check_output(
        ['make', '-C', str(profile_dir.parent), '-m', str(args.src / 'share/mk'),
         '-V', 'PROFILES'], text=True).split()
    for name in inventory['profiles']:
        assert name + '.d' in installed, 'profile omitted from install: ' + name
    for name, digest in inventory['sources'].items():
        assert hashlib.sha256((args.src / name).read_bytes()).hexdigest() == digest, \
            'source changed since inventory: ' + name
    # Declarations alone do not demonstrate an executable call site.
    sources = [args.src / name for name in inventory['sources'] if name.endswith('.c')]
    all_c = '\n'.join(p.read_text() for p in sources)
    for probe in inventory['probes']:
        name = probe['name'].replace('-', '__')
        if probe['kind'] == 'kernel':
            macro = r'(?:LIN_SDT_PROBE|SDT_PROBE|USB_TRANSFER_PROBE)\d+'
            pattern = macro + r'\([^;]*?\b' + re.escape(name) + r'\s*,'
        else:
            pattern = r'\bTRACE_' + probe['provider'].rstrip('*').upper() + '_' \
                + name.upper() + r'\('
        assert re.search(pattern, all_c, re.S), 'no call site: ' + probe['name']
    args.output.mkdir(parents=True, exist_ok=True)

    def check(job):
        name, filtered = job
        content = (profile_dir / (name + '.d')).read_text()
        selectors = contracts.check_contracts(content, inventory['probes'])
        command = [args.bsdinstruments, 'generate', '-f', str(profile_dir / (name + '.d'))]
        if filtered:
            command += ['--pid', '42', '--duration', '1']
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        assert '@bsdinstruments-' not in result.stdout
        rendered = args.output / (name + ('-filtered' if filtered else '') + '.d')
        rendered.write_text(result.stdout)
        command = ['dtrace', '-e', '-Z', '-s', str(rendered)]
        result = subprocess.run(command, capture_output=True, text=True)
        rendered.with_suffix('.log').write_text(result.stdout + result.stderr)
        return dict(profile=name, filtered=filtered, status=result.returncode,
                    selectors=selectors, command=command)

    jobs = [(name, filtered) for name in inventory['profiles'] for filtered in (False, True)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        results = list(pool.map(check, jobs))
    (args.output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    failures = [r for r in results if r['status']]
    print(f"{len(inventory['probes'])} call-site contracts; {len(installed)} install entries; "
          f"{len(results) - len(failures)}/{len(results)} offline profile checks passed")
    for failure in failures:
        print(failure)
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
