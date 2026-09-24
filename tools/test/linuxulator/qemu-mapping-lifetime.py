from pathlib import Path
import subprocess,os,time,json,re
import argparse
p=argparse.ArgumentParser(description='Run mapping lifetime tests in a disposable QEMU VM.')
p.add_argument('--image',required=True)
p.add_argument('--output',required=True)
p.add_argument('--cpus',default='4')
a=p.parse_args()
b=Path(a.output);b.mkdir(parents=True,exist_ok=True);log=b/'console.log'
env=dict(os.environ,LD_LIBRARY_PATH='/home/koryheard/qemu-root/usr/local/lib',LD_PRELOAD='/home/koryheard/vm/libfreesized.so')
cmd=['/tmp/linuxulator-gate-20260919/linuxgate-vm-executor','-L','/home/koryheard/qemu-root/usr/local/share/qemu','-accel','tcg,thread=multi','-m','1536','-smp',a.cpus,'-nic','user,model=virtio-net-pci,restrict=on','-display','none','-monitor','none','-serial','stdio','-no-reboot','-machine','q35','-cpu','max','-drive',f'file={Path(a.image).resolve()},format=raw,if=virtio,snapshot=on']
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
passed = (p.returncode == 0 and len(rows) == len(expected) and set(rows) == expected
    and len(native) == len(expected_native)
    and set(native) == {(n, '0') for n in expected_native}
    and len(watch) == 1 and watch[0][0] == watch[0][1]
    and 'MAPPING_DONE' in s and 'MAPPING_EXIT 0' in s
    and 'Powering system off' in s and 'all pools are healthy' in s
    and not re.search(r'panic:|Fatal trap|lock order reversal|non-sleepable locks held',s))
result = dict(passed=passed, command=cmd, probe_executions=len(rows),
    native_cases=len(native), watch_counts=watch, rows=rows, native=native)
(b/'results.json').write_text(json.dumps(result,indent=2)+'\n')
print('Mapping lifetime:', 'PASS' if passed else 'FAIL', len(rows), 'probes,', len(native), 'native cases')
raise SystemExit(0 if passed else 1)
