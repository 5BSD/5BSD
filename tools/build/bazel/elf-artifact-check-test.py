#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Positive and negative cases for elf-artifact-check.py using real Make artifacts."""
import argparse
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile


def load():
    path = Path(__file__).with_name('elf-artifact-check.py')
    spec = importlib.util.spec_from_file_location('elf_artifact_check', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expect_failure(function, message):
    try:
        function()
    except ValueError as error:
        if message not in str(error):
            raise RuntimeError('wrong rejection: ' + str(error)) from error
        return str(error)
    raise RuntimeError('mismatch was accepted: ' + message)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('readelf', 'tools', 'program', 'other-program', 'archive', 'work'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    m = load()
    nm, ar, objcopy = (a.tools / x for x in ('llvm-nm', 'llvm-ar', 'llvm-objcopy'))
    a.work.mkdir(parents=False, exist_ok=False)
    scratch = Path(tempfile.mkdtemp(dir=a.work))
    passed = []

    m.compare_program(a.readelf, objcopy, a.program, a.program, scratch)
    passed.append('program-identical')
    expect_failure(lambda: m.compare_program(a.readelf, objcopy, a.other_program, a.program, scratch),
                   'Make program metadata mismatch')
    passed.append('program-metadata-mismatch-rejected')

    m.compare_archive(nm, ar, a.archive, a.archive)
    passed.append('archive-identical')
    members = subprocess.run([ar, 't', a.archive], check=True, text=True,
                             stdout=subprocess.PIPE).stdout.split()
    missing = a.work / 'missing-member.a'
    shutil.copyfile(a.archive, missing)
    subprocess.run([ar, 'd', missing, members[-1]], check=True)
    expect_failure(lambda: m.compare_archive(nm, ar, missing, a.archive), 'member set or order')
    passed.append('archive-missing-member-rejected')

    reordered = a.work / 'reordered.a'
    shutil.copyfile(a.archive, reordered)
    subprocess.run([ar, 'm', reordered, members[0]], check=True)  # move first member to the end
    expect_failure(lambda: m.compare_archive(nm, ar, reordered, a.archive), 'member set or order')
    passed.append('archive-member-order-rejected')

    renamed = a.work / 'renamed-symbol.a'
    shutil.copyfile(a.archive, renamed)
    extract = a.work / 'extract'
    extract.mkdir()
    subprocess.run([ar, 'x', renamed.resolve(), members[0]], check=True, cwd=extract)
    defined = subprocess.run([nm, '--defined-only', '--extern-only', '--format=just-symbols',
                              extract / members[0]], check=True, text=True,
                             stdout=subprocess.PIPE).stdout.split()
    subprocess.run([objcopy, '--redefine-sym', defined[0] + '=' + defined[0] + '_drift',
                    extract / members[0]], check=True)
    subprocess.run([ar, 'r', renamed.resolve(), members[0]], check=True, cwd=extract)
    expect_failure(lambda: m.compare_archive(nm, ar, renamed, a.archive), 'member symbols differ')
    passed.append('archive-symbol-drift-rejected')
    print('\n'.join(passed))


if __name__ == '__main__':
    main()
