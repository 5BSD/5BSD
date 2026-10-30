#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check real module-hints error handling; a failing gate exits nonzero.

Use explicit matching kldxref/module inputs. This runs on a trusted builder,
not on the installed module directory. No kernel module is loaded.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import resource
import signal
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kldxref', type=Path, required=True)
    parser.add_argument('--module', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    tool = args.kldxref.resolve(strict=True)
    module = args.module.resolve(strict=True)
    if not tool.is_file() or not module.is_file():
        parser.error('executable and real module must be regular files')
    work = args.work.resolve(strict=False)
    work.mkdir(mode=0o700)  # Never reuse an earlier run or an installed root.
    records = []

    def invoke(label, arguments, limit=None):
        command = [str(tool), *map(str, arguments)]
        try:
            def constrain():
                signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
                resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
            result = subprocess.run(command, capture_output=True, timeout=30,
                                    preexec_fn=constrain if limit is not None else None)
            record = dict(case=label, argv=command, returncode=result.returncode,
                          stdout=result.stdout.decode(errors='replace'),
                          stderr=result.stderr.decode(errors='replace'))
        except subprocess.TimeoutExpired:
            record = dict(case=label, argv=command, returncode=None, error='timeout')
        records.append(record)
        return record

    seed = work / 'positive'
    seed.mkdir()
    shutil.copyfile(module, seed / 'selected.ko')
    positive = invoke('valid_module', [seed])
    hints = seed / 'linker.hints'
    positive['passed'] = positive['returncode'] == 0 and hints.is_file() and hints.stat().st_size > 4
    if positive['passed']:
        expected = digest(hints)
        positive['hints_sha256'] = expected
        for label, keep_valid in [('mixed_invalid_input', True), ('invalid_only_preserves_hints', False)]:
            root = work / label
            root.mkdir()
            shutil.copyfile(hints, root / 'linker.hints')
            if keep_valid:
                shutil.copyfile(module, root / 'selected.ko')
            (root / 'malformed.ko').write_bytes(b'not an ELF module\n')
            record = invoke(label, [root])
            output = root / 'linker.hints'
            record['previous_hints_preserved'] = output.is_file() and digest(output) == expected
            record['passed'] = record['returncode'] not in (None, 0) and record['previous_hints_preserved']
        record = invoke('explicit_invalid_module', ['-m', work / 'mixed_invalid_input/malformed.ko'])
        record['passed'] = record['returncode'] not in (None, 0)
        for label, limit in [('output_limit', 4), ('rename_failure', None)]:
            root = work / label
            root.mkdir()
            shutil.copyfile(module, root / 'selected.ko')
            if limit is not None:
                shutil.copyfile(hints, root / 'linker.hints')
            else:
                (root / 'linker.hints').mkdir()
                (root / 'linker.hints/sentinel').write_text('preserve')
            record = invoke(label, [root], limit=limit)
            preserved = (digest(root / 'linker.hints') == expected if limit is not None
                         else (root / 'linker.hints/sentinel').read_text() == 'preserve')
            record['previous_hints_preserved'] = preserved
            record['passed'] = record['returncode'] not in (None, 0) and preserved
        record = invoke('missing_directory', [work / 'does-not-exist'])
        record['passed'] = record['returncode'] not in (None, 0)
        empty = work / 'empty'; empty.mkdir()
        shutil.copyfile(hints, empty / 'linker.hints')
        record = invoke('valid_empty_directory', [empty])
        record['passed'] = record['returncode'] == 0 and not (empty / 'linker.hints').exists()
        for record in records:
            directory = work / record['case']
            if directory.is_dir():
                record['temporary_files_removed'] = not list(directory.glob('lhint.*'))
                record['passed'] = record['passed'] and record['temporary_files_removed']
    report = dict(format=1, scope='native module-hints error handling',
                  result='PASS' if len(records) == 8 and all(r['passed'] for r in records) else 'FAIL',
                  tool=str(tool), tool_sha256=digest(tool), module=str(module), module_sha256=digest(module),
                  library_path=os.environ.get('LD_LIBRARY_PATH'), cases=records,
                  secure_boot_qualified=False, protected_generation_qualified=False)
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
