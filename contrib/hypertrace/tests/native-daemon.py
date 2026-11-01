#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Build the actual native daemon and run component tests without starting it."""
from pathlib import Path
import concurrent.futures, json, os, subprocess, sys
root = Path(__file__).resolve().parents[3]
tests = Path(__file__).resolve().parent
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
daemon = root / 'usr.sbin/dtraced'
flags = ['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-Wno-gcc-compat',
         '-DDTRACED_NATIVE_TEST',
         '-UNDEBUG', '-pthread', '-fsanitize=address,undefined',
         '-ffunction-sections', '-fdata-sections', '-I' + str(daemon),
         '-I' + str(root / 'sys'),
         '-I' + str(root / 'sys/dev/dttransport')]
def compile_one(source):
    obj = out / (source.stem + '.o')
    result = subprocess.run(flags + ['-c', str(source), '-o', str(obj)],
                            capture_output=True, text=True)
    (out / (source.stem + '-build.log')).write_text(result.stdout + result.stderr)
    return {'source': source.name, 'status': result.returncode, 'object': str(obj)}
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
    builds = list(pool.map(compile_one, sorted(daemon.glob('*.cc'))))
(out / 'builds.json').write_text(json.dumps(builds, indent=2) + '\n')
if any(item['status'] for item in builds):
    raise SystemExit('Daemon compilation failed; inspect builds.json and logs')
objects = [item['object'] for item in builds]
compat = out / 'native-daemon-compat.o'
subprocess.run(flags + ['-c', str(tests / 'native-daemon-compat.cc'),
                        '-o', str(compat)], check=True)
objects.append(str(compat))
subprocess.run(flags + objects + ['-lcrypto', '-lutil', '-o', str(out / 'dtraced')], check=True)
components = [item['object'] for item in builds if item['source'] != 'dtraced.cc']
components.append(str(compat))
results = []
for name in ('fresh-session-startup', 'fresh-session-fence', 'fresh-session-consumers', 'fresh-session-stop-step', 'fresh-session-directory', 'protocol', 'daemon-config', 'release-attestation', 'release-keys', 'id-generation', 'job-lifetime', 'transport', 'socket-large-deadline', 'connect-deadline', 'events', 'event-model', 'spool-file', 'host-ingress', 'outbound-admission', 'outbound-replay', 'cleanup-routing', 'child-ownership', 'child-ledger', 'request-oom', 'dispatch-oom', 'directory-oom', 'send-info-oom', 'kill-oom', 'kill-ack', 'guest-kill-rekey', 'guest-delivery-rekey', 'kill-capacity', 'handoff-ledger', 'source-gate', 'source-journal-wire', 'handoff-control', 'thread-startup', 'spool-publish', 'process-launch', 'recovery-query', 'runtime-query', 'forwarder-rearm', 'installed-receipt', 'attestation-reject', 'admission-concurrency', 'admission-replay', 'consumer-registration'):
    linked = [obj for obj in components if name != 'source-journal-wire'
              or Path(obj).name != 'dtraced_directory.o']
    command = flags + ['-Wl,--gc-sections', str(tests / (name + '.cc'))] + linked
    if name == 'fresh-session-stop-step': command += ['-Wl,--wrap=pdopenpid,--wrap=poll,--wrap=sysctlbyname,--wrap=unlinkat']
    if name == 'fresh-session-startup': command += ['-Wl,--wrap=open,--wrap=ioctl,--wrap=write,--wrap=bind,--wrap=remove']
    if name == 'spool-publish': command += ['-Wl,--wrap=write,--wrap=read,--wrap=fsync,--wrap=renameat']
    if name in ('handoff-ledger', 'guest-kill-rekey',
                'guest-delivery-rekey'):
        command += ['-Wl,--wrap=fsync']
    if name in ('source-gate', 'fresh-session-fence', 'fresh-session-consumers', 'fresh-session-stop-step'):
        command += ['-Wl,--wrap=open,--wrap=ioctl,--wrap=fsync']
    if name in ('request-oom', 'dispatch-oom', 'directory-oom', 'send-info-oom', 'kill-oom'): command += ['-Wl,--wrap=_Znwm']
    if name == 'forwarder-rearm': command += ['-Wl,--wrap=kevent']
    if name == 'directory-oom': command += ['-Wl,--wrap=readdir']
    if name == 'connect-deadline': command += ['-Wl,--wrap=connect,--wrap=poll,--wrap=getsockopt']
    if name == 'socket-large-deadline': command += ['-Wl,--wrap=poll']
    if name == 'runtime-query': command += ['-Wl,--wrap=clock_gettime']
    if name == 'thread-startup': command += ['-Wl,--wrap=pthread_create']
    if name == 'admission-concurrency': command += ['-Wl,--wrap=pthread_create']
    if name == 'process-launch': command += ['-Wl,--wrap=ioctl']
    if name == 'child-ledger': command += ['-Wl,--wrap=ioctl,--wrap=pdopenpid']
    if name == 'host-ingress':
        command += ['-Wl,--wrap=open']
    if name in ('installed-receipt', 'spool-file', 'host-ingress', 'admission-replay'):
        command += ['-Wl,--wrap=ioctl']
    if name in ('handoff-control', 'source-journal-wire'):
        command += ['-Wl,--wrap=open,--wrap=ioctl']
    if name == 'attestation-reject': command += ['-Wl,--wrap=ioctl,--wrap=open']
    command += ['-lcrypto', '-lutil', '-o', str(out / name)]
    result = subprocess.run(command, capture_output=True, text=True)
    (out / (name + '-build.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise SystemExit('Test compilation failed: ' + name)
    result = subprocess.run([str(out / name)], capture_output=True, text=True,
                            timeout=80 if name == 'runtime-query' else 60)
    (out / (name + '.log')).write_text(result.stdout + result.stderr)
    results.append({'case': name, 'status': result.returncode})
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
for result in results: print(result)
if any(item['status'] for item in results): raise SystemExit(1)
print(f'PASS: sanitized native daemon build/link and {len(results)} component suites; no daemon started')
