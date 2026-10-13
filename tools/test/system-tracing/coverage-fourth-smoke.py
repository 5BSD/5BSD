#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise built base components without installing them or enabling DTrace."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, default=Path('/usr/src'))
    parser.add_argument('--objects', type=Path,
                        default=Path('/usr/obj/5bsd-dtrace-20-validation'))
    args = parser.parse_args()
    out = args.objects / 'smoke'
    out.mkdir(parents=True, exist_ok=True)
    results = []

    def run(name, command, expected=0):
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        (out / (name + '.log')).write_text(result.stdout + result.stderr)
        results.append(dict(name=name, command=list(map(str, command)),
                            status=result.returncode, expected=expected))
        assert result.returncode == expected, (name, result.returncode, result.stderr)

    for variant in ('hooks', 'nohooks'):
        libdirs = [args.objects / 'base' / (c + '-' + variant) for c in
                   ('lib_libfetch', 'lib_libarchive', 'lib_libthr', 'lib_libc')]
        command = ['cc', '-Wall', '-Wextra', '-Werror',
                   str(args.src / 'tools/test/system-tracing/coverage-fourth-smoke.c'),
                   '-o', str(out / ('libraries-' + variant))]
        for directory in libdirs:
            command += ['-L' + str(directory), '-Wl,-rpath,' + str(directory)]
        # libc's generated .so is a linker script: link its actual ELF explicitly.
        command += ['-lfetch', '-larchive', '-lthr', str(libdirs[-1] / 'libc.so.7')]
        run('compile-' + variant, command)
        for test in ('fetches', 'archives', 'waits'):
            run(test + '-' + variant, [out / ('libraries-' + variant), test])
        cp = args.objects / 'base' / ('bin_cp-' + variant) / 'cp'
        install = args.objects / 'base' / ('usr.bin_xinstall-' + variant) / 'xinstall'
        with tempfile.TemporaryDirectory(dir=out) as temporary:
            directory = Path(temporary)
            original = directory / 'original'
            copied = directory / 'copied'
            installed = directory / 'installed'
            data = bytes(range(256)) * 8192
            original.write_bytes(data)
            run('cp-regular-' + variant, [cp, original, copied])
            assert copied.read_bytes() == data
            run('install-safe-' + variant, [install, '-S', '-m', '600', original, installed])
            assert installed.read_bytes() == data
            assert installed.stat().st_mode & 0o777 == 0o600
            run('install-digest-' + variant,
                [install, '-h', 'sha256', '-m', '600', original, installed])
            assert installed.read_bytes() == data
            run('cp-missing-' + variant, [cp, directory / 'missing', copied], expected=1)
            fifo = directory / 'fifo'
            os.mkfifo(fifo)
            failures = []
            def send():
                try:
                    with fifo.open('wb') as stream:
                        stream.write(data)
                except Exception as exc:
                    failures.append(str(exc))
            writer = threading.Thread(target=send, daemon=True)
            writer.start()
            run('cp-fifo-fallback-' + variant, [cp, fifo, copied])
            writer.join(timeout=10)
            assert not writer.is_alive() and not failures
            assert copied.read_bytes() == data
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(f'{len(results)} functional build/run checks PASS; no live tracing claimed')


if __name__ == '__main__':
    main()
