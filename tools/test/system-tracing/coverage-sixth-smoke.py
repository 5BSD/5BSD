#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise instrumented tools without installing them or starting cron."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--src', type=Path, default=Path('/usr/src'))
    parser.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-dtrace-sixth-validation'))
    args = parser.parse_args()
    out = args.obj / 'smoke'
    out.mkdir(parents=True, exist_ok=True)
    results = []
    # Copy the exact wait helper; other USDT sites would retain job-launch code.
    command_source = (args.src / 'usr.sbin/cron/cron/do_command.c').read_text()
    helper = command_source[command_source.index('static WAIT_T\nwait_on_child('):]
    (out / 'cron-wait-under-test.h').write_text(helper)

    def run(name, command, expected=0, **kwargs):
        r = subprocess.run(list(map(str, command)), capture_output=True,
                           timeout=25, **kwargs)
        (out / (name + '.log')).write_bytes(r.stdout + r.stderr)
        results.append(dict(name=name, command=list(map(str, command)),
                            status=r.returncode, expected=expected))
        (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        assert r.returncode == expected, (name, r.returncode, r.stderr.decode(errors='replace'))
        return r

    for variant in ('hooks', 'nohooks'):
        dd = args.obj / 'base' / ('bin_dd-' + variant) / 'dd'
        mv = args.obj / 'base' / ('bin_mv-' + variant) / 'mv'
        with tempfile.TemporaryDirectory(dir=out) as local, tempfile.TemporaryDirectory(
                prefix='dtrace-mv-', dir='/tmp') as cross:
            local, cross = Path(local), Path(cross)
            assert local.stat().st_dev != cross.stat().st_dev, 'cross-filesystem test needs distinct mounts'
            source, dest = local / 'input', local / 'output'
            data = bytes(range(256)) * 1024 + b'partial tail'
            source.write_bytes(data)
            run('dd-copy-' + variant, [dd, 'if=' + str(source), 'of=' + str(dest), 'bs=8192'])
            assert dest.read_bytes() == data
            run('dd-count-zero-' + variant, [dd, 'if=' + str(source), 'of=' + str(dest), 'count=0'])
            assert dest.read_bytes() == b''
            run('dd-sync-' + variant, [dd, 'of=' + str(dest), 'bs=8', 'conv=sync'], input=b'abc')
            assert dest.read_bytes() == b'abc' + bytes(5)
            source.write_bytes(bytes(1024 * 1024) + b'end')
            run('dd-sparse-' + variant, [dd, 'if=' + str(source), 'of=' + str(dest), 'bs=4096', 'conv=sparse'])
            assert dest.read_bytes() == source.read_bytes()
            assert dest.stat().st_blocks * 512 < dest.stat().st_size
            run('dd-read-error-' + variant, [dd, 'if=' + str(local), 'of=' + str(dest)], expected=1)
            # A regular readable file opened as stdin yields a deterministic EBADF on output.
            with source.open('rb') as readonly:
                r = subprocess.run([str(dd), 'bs=4'], input=b'abcd', stdout=readonly,
                                   stderr=subprocess.PIPE, timeout=10)
            assert r.returncode == 1
            results.append(dict(name='dd-write-error-' + variant, status=1, expected=1))
            # Force partial pipe reads, then let iflag=fullblock assemble one block.
            proc = subprocess.Popen([str(dd), 'of=' + str(dest), 'ibs=4096', 'obs=4096',
                                     'iflag=fullblock', 'count=1'], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            failure = []
            payload = bytes(range(256)) * 16
            def feed():
                try:
                    for offset in range(0, len(payload), 256):
                        proc.stdin.write(payload[offset:offset + 256])
                        proc.stdin.flush()
                        time.sleep(0.005)
                    proc.stdin.close()
                except Exception as e:
                    failure.append(str(e))
            writer = threading.Thread(target=feed, daemon=True)
            writer.start()
            proc.wait(timeout=10)
            writer.join(timeout=1)
            assert not writer.is_alive() and not failure and proc.returncode == 0
            assert dest.read_bytes() == payload
            results.append(dict(name='dd-pipe-fullblock-' + variant, status=0, expected=0))
            source.write_bytes(data)
            source.chmod(0o640)
            run('mv-rename-' + variant, [mv, source, dest])
            assert not source.exists() and dest.read_bytes() == data
            source.write_bytes(b'keep')
            run('mv-no-clobber-' + variant, [mv, '-n', source, dest])
            assert source.read_bytes() == b'keep' and dest.read_bytes() == data
            target = cross / 'moved'
            run('mv-cross-file-' + variant, [mv, dest, target])
            assert not dest.exists() and target.read_bytes() == data
            assert target.stat().st_mode & 0o777 == 0o640
            directory = local / 'tree'
            directory.mkdir()
            (directory / 'file').write_bytes(data)
            (directory / 'link').symlink_to('file')
            target = cross / 'tree'
            run('mv-cross-directory-' + variant, [mv, directory, target])
            assert not directory.exists() and (target / 'file').read_bytes() == data
            assert os.readlink(target / 'link') == 'file'
            run('mv-missing-' + variant, [mv, local / 'missing', cross / 'absent'], expected=1)
            bad = cross / 'bad-parent'
            bad.write_bytes(b'not a directory')
            run('mv-bad-destination-' + variant, [mv, source, bad / 'child'], expected=1)
            assert source.read_bytes() == b'keep'
        # Exact cron wait helper, isolated from job-launch/PAM/mail code.
        objdir = args.obj / 'base' / ('usr.sbin_cron_cron-' + variant)
        obj = out / ('cron-wait-' + variant + '.o')
        binary = out / ('cron-wait-' + variant)
        command = ['cc', '-O2', '-fPIE', '-ffunction-sections', '-fdata-sections',
                   '-DLOGIN_CAP', '-DPAM', '-I' + str(objdir), '-I' + str(out),
                   '-I' + str(args.src / 'usr.sbin/cron/cron')]
        if variant == 'hooks':
            command += ['-DWITH_DTRACE']
        command += ['-c', args.src / 'tools/test/system-tracing/coverage-sixth-cron-wait.c', '-o', obj]
        run('compile-cron-wait-' + variant, command)
        objects = [obj]
        if variant == 'hooks':
            dof = out / 'cron-wait-dof.o'
            run('dof-cron-wait', ['dtrace', '-C', '-x', 'nolibs', '-G', '-o', dof,
                                 '-s', args.src / 'usr.sbin/cron/cron/cron_provider.d', obj])
            objects += [dof]
        run('link-cron-wait-' + variant, ['cc', '-pie', '-Wl,--gc-sections', '-o', binary, *objects])
        run('cron-wait-' + variant, [binary])
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(len(results), 'build/run checks PASS, including real cross-filesystem moves and cron waits')


if __name__ == '__main__':
    main()
