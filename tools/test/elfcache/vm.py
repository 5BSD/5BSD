#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Build and run a disposable cache API/measurement VM; never install on host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--stage', required=True, type=Path)
p.add_argument('--objtop', default='/usr/obj/usr/src/amd64.amd64', type=Path)
p.add_argument('--work', required=True, type=Path)
p.add_argument('--qemu', default='/usr/obj/5bsd-qemu-fstt/qemu-system-x86_64-fstt-fixed')
p.add_argument('--elfcache', type=Path, help='Native cache builder override for isolated tests')
p.add_argument('--loader', type=Path, help='Uninstrumented loader under test')
p.add_argument('--kernel', type=Path, help='Matching kernel override')
p.add_argument('--headers', type=Path, help='Matching staged include directory override')
p.add_argument('--sign-test-libraries', type=Path, metavar='CAPSIGN', help='Sign disposable copies using this native tool; private test key remains on host')
p.add_argument('--timeout', type=int, default=1800)
p.add_argument('--cpus', type=int, default=2)
p.add_argument('--memory-mb', type=int, default=2048)
p.add_argument('--dry-run', action='store_true')
p.add_argument('--run-prepared', action='store_true', help='Execute a hash-checked image previously prepared with --dry-run')
a = p.parse_args()
if min(a.timeout, a.cpus, a.memory_mb) <= 0:
    p.error('--timeout, --cpus and --memory-mb must be positive')
stage, obj, work = a.stage.resolve(), a.objtop.resolve(), a.work.resolve()
if a.run_prepared and a.dry_run:
    p.error('--run-prepared and --dry-run are mutually exclusive')
if work.exists() and not a.run_prepared:
    sys.exit('work must be a new directory')
if a.run_prepared and not work.is_dir():
    sys.exit('prepared work directory is missing')
if not str(work).startswith('/usr/obj/'):
    sys.exit('VM staging belongs under /usr/obj')
for path in (stage, obj, work):
    if re.search(r'\s', str(path)):
        sys.exit('paths with whitespace are unsupported')
if not a.run_prepared:
    work.mkdir(parents=True)
    log = (work / 'build.log').open('w')
    def run(args, **kw):
        print('RUN', ' '.join(map(str, args)), flush=True)
        subprocess.run(list(map(str, args)), check=True, stdout=log, stderr=subprocess.STDOUT, **kw)
    source = Path(__file__).resolve().parent
    probe = work / 'cache-vm-probe'
    run(['cc', '-isystem', a.headers or obj / 'tmp/usr/include', '-O2', '-Wall', '-Wextra', '-Werror', '-iquote/usr/src/sys',
         source / 'vm_probe.c', '-o', probe, '-lutil', '-Wl,--no-as-needed',
         f'-L{stage}/usr/lib', f'-Wl,-rpath-link,{stage}/lib', '-lchannel', '-lfidl_bsd'])
    root = work / 'cache-root'
    (root / 'lib').mkdir(parents=True)
    (root / 'usr/lib').mkdir(parents=True)
    for name in ('libc.so.7', 'libsys.so.7', 'libc++.so.1', 'libcxxrt.so.1',
                 'libthr.so.3', 'libm.so.5', 'libgcc_s.so.1', 'libutil.so.10'):
        shutil.copyfile(stage / 'lib' / name, root / 'lib' / name)
    for name in ('libchannel.so.1', 'libfidl_bsd.so.1'):
        shutil.copyfile(stage / 'usr/lib' / name, root / 'usr/lib' / name)
    fixture = work / 'cache-lifetime.c'
    fixture.write_text('int cache_private_state = 17; int cache_lifetime_value(void) { return 731; }\n')
    run(['cc', '-shared', '-fPIC', '-O2', '-Wl,-soname,libcache_lifetime.so.1',
         fixture, '-o', root / 'usr/lib/libcache_lifetime.so.1'])
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = str(obj / 'lib/libcapimage')
    # Cache-only fixtures enter the cache inventory, but not the guest FS.
    for name in ('libcache_only.so.1', 'libcache_only_alias.so.1'):
        shutil.copyfile(root / 'usr/lib/libcache_lifetime.so.1', root / 'usr/lib' / name)
    if a.sign_test_libraries:
        test_key = work / 'library-test-key.pem'
        policy = work / 'library-policy.ucl'
        policy.write_text('program = "cache-library-test";\n')
        run(['openssl', 'genpkey', '-algorithm', 'ed25519', '-out', test_key])
        for library in sorted(root.rglob('*.so.*')):
            temporary = library.with_name(library.name + '.signed')
            run([a.sign_test_libraries, 'sign', '-k', test_key, '-m', policy, '-o', temporary, library])
            temporary.replace(library)
    run([a.elfcache or obj / 'usr.sbin/elfcache/elfcache', 'build', '-r', root, '-o', work / 'cache.bin'], env=env)
    for name in ('libcache_only.so.1', 'libcache_only_alias.so.1'):
        (root / 'usr/lib' / name).unlink()
    # Populate a real source-only sibling after sealing the cache inventory.
    shutil.copyfile(root / 'usr/lib/libcache_lifetime.so.1',
                    root / 'usr/lib/libcache_uncached.so.1')
    loader = work / 'loader.conf.local'
    loader.write_text('console="comconsole"\nautoboot_delay="1"\n'
                      'init_path="/sbin/cache-vm-probe"\ncapability_plane="NO"\n'
                      'vfs.root.mountfrom="ufs:/dev/vtbd0p2"\n')
    overlay = {
        'boot/loader.conf.local': (loader, '0444'),
        'boot/kernel/kernel': (a.kernel or obj / 'sys/CACHE-TEST/kernel', '0444'),
        'libexec/ld-elf.so.1': (a.loader or obj / 'libexec/rtld-elf/ld-elf.so.1', '0555'),
        'sbin/cache-vm-probe': (probe, '0555'),
        'cache-test/cache.bin': (work / 'cache.bin', '0444'),
    }
    for library in root.rglob('*'):
        if library.is_file():
            overlay[str(library.relative_to(root))] = (library, '0444')
    # Last staged record wins, matching installation updates; normalize size on
    # overlay files because makefs uses metadata rather than the contents' stat.
    records = {}
    for line in (stage / 'METALOG').read_text().splitlines():
        if line.startswith('./'):
            target = line.split()[0][2:]
            # This PID-1 probe needs boot files and its linked libraries, not a
            # second world. Keep the maintained stage read-only and the VM small.
            keep = (target in ('', 'boot', 'boot/kernel', 'lib', 'libexec', 'sbin',
                               'usr', 'usr/lib', 'dev', 'tmp', 'etc') or
                    (target.startswith('boot/') and not target.startswith('boot/kernel/')) or
                    (root / target).is_file())
            if keep:
                records[target] = line
    records['cache-test'] = './cache-test type=dir uname=root gname=wheel mode=0755'
    snapshots = work / 'artifacts'
    snapshots.mkdir()
    for number, (target, (content, mode)) in enumerate(overlay.items()):
        frozen = snapshots / str(number)
        shutil.copyfile(content, frozen)
        content = frozen
        records[target] = (f'./{target} type=file uname=root gname=wheel mode={mode} '
                           f'size={content.stat().st_size} contents={content}')
    metadata = {
        'stage': str(stage), 'objtop': str(obj), 'signed_test_libraries': bool(a.sign_test_libraries), 'cpus': a.cpus, 'memory_mb': a.memory_mb,
        'accelerator': 'tcg,thread=multi', 'host_load_average': os.getloadavg(),
        'host_load_log': 'host-load.jsonl', 'trial_order': 'alternating',
        'qemu_version': subprocess.check_output([a.qemu, '--version'], text=True).splitlines()[0],
        'source_commit': subprocess.check_output(['git', '-C', str(source.parents[2]),
                                                 'rev-parse', 'HEAD'], text=True).strip(),
        'artifacts_sha256': {target: hashlib.sha256((snapshots / str(i)).read_bytes()).hexdigest()
                            for i, target in enumerate(overlay)},
        'libraries_sha256': {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in root.rglob('*') if path.is_file()},
    }
    (work / 'run.json').write_text(json.dumps(metadata, indent=2) + '\n')
    manifest = work / 'METALOG'
    manifest.write_text('#mtree\n' + '\n'.join(records[k] for k in sorted(records)) + '\n')
    run(['makefs', '-t', 'ffs', '-B', 'little', '-s', '512m', '-o',
         'version=2,softupdates=1,label=root', work / 'root.ufs', manifest], cwd=stage)
    run(['mkimg', '-s', 'gpt', '-f', 'raw', '-b', stage / 'boot/pmbr',
         '-p', f'freebsd-boot:={stage}/boot/gptboot', '-p', f'freebsd-ufs:={work}/root.ufs',
         '-o', work / 'guest.img'])
    (work / 'root.ufs').unlink()
    metadata['guest_sha256'] = hashlib.file_digest((work / 'guest.img').open('rb'), 'sha256').hexdigest()
    metadata['probe_source_sha256'] = hashlib.sha256((source / 'vm_probe.c').read_bytes()).hexdigest()
    (work / 'run.json').write_text(json.dumps(metadata, indent=2) + '\n')
    log.close()
else:
    metadata = json.loads((work / 'run.json').read_text())
    if metadata.get('stage') != str(stage):
        sys.exit('prepared image stage identity does not match')
    if metadata.get('cpus') != a.cpus or metadata.get('memory_mb') != a.memory_mb:
        sys.exit('prepared image VM resource settings do not match')
    with (work / 'guest.img').open('rb') as image:
        actual = hashlib.file_digest(image, 'sha256').hexdigest()
    if metadata.get('guest_sha256') != actual:
        sys.exit('prepared image digest missing or changed; prepare a fresh image')
    if subprocess.check_output([a.qemu, '--version'], text=True).splitlines()[0] != metadata['qemu_version']:
        sys.exit('prepared image emulator version does not match')
if a.dry_run:
    sys.exit(0)
command = [a.qemu, '-L', '/usr/local/share/qemu', '-accel', 'tcg,thread=multi',
           '-machine', 'q35', '-cpu', 'max', '-m', str(a.memory_mb), '-smp', str(a.cpus),
           '-drive', f'file={work}/guest.img,format=raw,if=none,id=root,snapshot=on',
           '-device', 'virtio-blk-pci,drive=root,bootindex=1', '-display', 'none',
           '-monitor', 'none', '-serial', f'file:{work}/serial.log', '-no-reboot']
print('VM', work / 'serial.log', flush=True)
# Exclusive creation prevents overlapping runs or overwriting prior evidence.
try:
    with (work / 'command.json').open('x') as command_file:
        command_file.write(json.dumps(command, indent=2) + '\n')
except FileExistsError:
    sys.exit('execution evidence already exists; use a new prepared work directory')
with (work / 'qemu.log').open('w') as out, (work / 'host-load.jsonl').open('w') as observations:
    started = time.monotonic()
    with subprocess.Popen(command, stdout=out, stderr=out) as process:
        (work / 'qemu.pid').write_text(str(process.pid) + '\n')
        while True:
            elapsed = time.monotonic() - started
            status = process.poll()
            observations.write(json.dumps({
                'unix_time_ns': time.time_ns(), 'elapsed_seconds': elapsed,
                'load_average': os.getloadavg(), 'vm_exit_code': status,
            }, allow_nan=False) + '\n')
            observations.flush()
            if status is not None:
                if status != 0:
                    raise subprocess.CalledProcessError(status, command)
                break
            remaining = a.timeout - elapsed
            if remaining <= 0:
                process.kill()
                status = process.wait()
                observations.write(json.dumps({
                    'unix_time_ns': time.time_ns(),
                    'elapsed_seconds': time.monotonic() - started,
                    'load_average': os.getloadavg(), 'vm_exit_code': status,
                    'deadline_exceeded': True,
                }, allow_nan=False) + '\n')
                sys.exit('VM deadline exceeded; inspect serial.log')
            try:
                process.wait(timeout=min(5, remaining))
            except subprocess.TimeoutExpired:
                pass
serial = (work / 'serial.log').read_text(errors='replace')
measurements = [line.strip() for line in serial.splitlines() if line.startswith(('MEASURE ', 'CPU '))]
(work / 'measurements.txt').write_text('\n'.join(measurements) + '\n')
print('\n'.join(measurements))
if 'ELFCACHE_VM_END failures=0' not in serial:
    sys.exit('VM checks failed or did not finish; inspect serial.log')
print('VM checks passed. Object residency counts each VM object once. Anonymous growth is a system delta, not per-process private RSS. Summed RSS is not physical memory.')
