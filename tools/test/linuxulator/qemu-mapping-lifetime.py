from pathlib import Path
import subprocess,os,time,json,re
import argparse
p=argparse.ArgumentParser(description='Run mapping lifetime tests in a disposable QEMU VM.')
p.add_argument('--image',required=True)
p.add_argument('--output',required=True)
p.add_argument('--cpus',default='4')
p.add_argument('--qemu',default='/usr/local/bin/qemu-system-x86_64')
p.add_argument('--firmware-dir',default='/usr/local/share/qemu')
p.add_argument('--manifest',required=True,help='JSON guest path to SHA256 mapping')
a=p.parse_args()
b=Path(a.output);b.mkdir(parents=True,exist_ok=False);log=b/'console.log'
hashes=json.loads(Path(a.manifest).read_text())
(b/'manifest.json').write_text(json.dumps(hashes,indent=2)+'\n')
env=dict(os.environ)
cmd=[a.qemu,'-L',a.firmware_dir,'-accel','tcg,thread=multi','-m','1536','-smp',a.cpus,'-nic','none','-display','none','-monitor','none','-serial','stdio','-no-reboot','-machine','q35','-cpu','max','-drive',f'file={Path(a.image).resolve()},format=raw,if=virtio,snapshot=on']
with log.open('wb') as f:
 p=subprocess.Popen(cmd,stdout=f,stderr=subprocess.STDOUT,env=env)
 deadline=time.monotonic()+3600
 while p.poll() is None:
  s=log.read_text(errors='replace')
  if time.monotonic()>deadline or re.search(r'panic:|Fatal trap|lock order reversal|non-sleepable locks held',s):p.kill();p.wait();break
  time.sleep(2)
s=log.read_text(errors='replace').replace('\r','')
cases = {
    'mapping-linux': set('private shared readonly split fork-unmap fork-exit fork-exec fixed two-maps two-opens remap-pages dontneed failed-fixed merge shrink fork-wired noreplace remap-merge'.split()),
    'lifetime-linux': set('dup opens directory shared-map private-map late-watch hardlink replace remove-watch close-watches fork-exit'.split()),
}
rows = re.findall(r'^MAPPING_RESULT (\S+) (\d+) (\S+) (\S+) (\S+) (\d+)$', s, re.M)
expected = {(fs, str(i), program, user, case, '0')
    for fs in ['zfs', 'tmpfs'] for i in range(1, 6)
    for program, names in cases.items()
    for user in ['root', 'unprivileged'] for case in names}
native = re.findall(r'^INOTIFY_NATIVE (\S+) (\d+)$', s, re.M)
expected_native = set(re.findall(r'ATF_TP_ADD_TC\(tp, (\w+)\)',
    (Path(__file__).resolve().parents[3] / 'tests/sys/kern/inotify_test.c').read_text()))
watch = re.findall(r'^MAPPING_WATCHES (\d+) (\d+)$', s, re.M)
hashes_ok = bool(hashes) and all(s.splitlines().count(
    f'SHA256 (/{path.lstrip("/")}) = {digest}') == 1
    for path,digest in hashes.items())
passed = (p.returncode == 0 and len(rows) == len(expected) and set(rows) == expected
    and hashes_ok and s.splitlines().count('MAPPING_BEGIN') == 1
    and re.search(r'^linuxgate\s+/\s+zfs\s',s,re.M) is not None
    and re.search(r'^tmpfs\s+/tmp\s+tmpfs\s',s,re.M) is not None
    and len(native) == len(expected_native)
    and set(native) == {(n, '0') for n in expected_native}
    and len(watch) == 1 and watch[0][0] == watch[0][1]
    and 'MAPPING_DONE' in s and 'MAPPING_EXIT 0' in s
    and 'Powering system off' in s and 'All buffers synced.' in s
    and 'all pools are healthy' in s
    and not re.search(r'panic:|Fatal trap|lock order reversal|non-sleepable locks held',s))
result = dict(passed=passed, command=cmd, probe_executions=len(rows),
    native_cases=len(native), watch_counts=watch, rows=rows, native=native,
    qemu_exit=p.returncode, hashes_ok=hashes_ok)
(b/'results.json').write_text(json.dumps(result,indent=2)+'\n')
print('Mapping lifetime:', 'PASS' if passed else 'FAIL', len(rows), 'probes,', len(native), 'native cases')
raise SystemExit(0 if passed else 1)
