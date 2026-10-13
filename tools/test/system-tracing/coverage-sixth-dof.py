#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check linked USDT providers and enabled offsets in all three base programs."""
import argparse
import importlib.util
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, default=Path('/usr/src'))
    parser.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-dtrace-sixth-validation'))
    args = parser.parse_args()
    tests = args.src / 'tools/test/system-tracing'
    spec = importlib.util.spec_from_file_location('dof_reader', tests / 'coverage-fourth-dof.py')
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    inventory = json.loads((tests / 'coverage-sixth.json').read_text())
    results = []
    for component, binary, provider in [('bin_dd', 'dd', 'ddio'),
                                       ('bin_mv', 'mv', 'moveio'),
                                       ('usr.sbin_cron_cron', 'cron', 'cron')]:
        on = args.obj / 'base' / (component + '-hooks') / binary
        off = args.obj / 'base' / (component + '-nohooks') / binary
        probes = reader.dof_probes(reader.elf_sections(on).get('.SUNW_dof', b''))
        disabled = reader.dof_probes(reader.elf_sections(off).get('.SUNW_dof', b''))
        wanted = [p for p in inventory['probes'] if p['provider'] == provider + '*']
        if provider == 'cron':
            wanted += [dict(name='job-run', types=['char *', 'char *']),
                       dict(name='job-done', types=['char *', 'int'])]
        for expected in wanted:
            matches = [p for p in probes if p['provider'] == provider and p['name'] == expected['name']]
            assert matches and all(p['argc'] == len(expected['types']) and
                                   p['offsets'] > 0 and p['enabled_offsets'] > 0 for p in matches), (on, expected)
        assert not any(p['provider'] == provider for p in disabled), off
        results.append(dict(binary=str(on), provider=provider, probes=probes,
                            nohooks_provider_absent=True, status=0))
        print(provider, 'linked DOF sites, enable guards and disabled absence PASS')
    (args.obj / 'dof-results.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
