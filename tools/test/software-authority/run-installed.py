"""Run the full software suite on a disposable overlay of a BSDInstall target."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
import time
from qmp_shutdown import ShutdownEvidence


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def send(sock, script):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(10)
        channel.connect(str(sock))
        for line in script.splitlines():
            channel.sendall(line.encode() + b'\r')
            time.sleep(0.1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installation', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--require-marker', action='append', default=[])
    parser.add_argument('--work', type=Path, help='new output directory; default is inside installation')
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--qemu-data', type=Path)
    parser.add_argument('--cpus', type=int, default=os.cpu_count() or 1)
    parser.add_argument('--timeout', type=int, default=1800)
    args = parser.parse_args()
    if not __debug__:
        parser.error('do not disable evidence assertions with Python -O')
    if args.cpus <= 0 or args.timeout <= 0:
        parser.error('cpus and timeout must be positive')
    subprocess.run([args.qemu, '--version'], check=True, stdout=subprocess.DEVNULL)
    installation = args.installation.resolve(strict=True)
    fixtures = args.fixtures.resolve(strict=True)
    install_result = json.loads((installation / 'install-result.json').read_text())
    boot = json.loads((installation / 'installed-boot/result.json').read_text())
    manifest = json.loads((fixtures / 'fixtures.json').read_text())
    assert install_result['result'] == boot['result'] == 'PASS'
    assert not boot['forced_termination'] and boot['qemu_exit'] == 0
    assert install_result['shutdown_evidence']['guest_poweroff']
    assert boot['shutdown_evidence']['guest_poweroff']
    assert boot['installation_evidence_sha256'] == digest(installation / 'install-result.json')
    assert boot['expected_kernel_sha256'] == manifest['kernel_sha256']
    assert digest(fixtures / 'fixtures.tar') == manifest['archive_sha256']
    qualified = Path(manifest['qualified_vm'])
    assert digest(qualified / 'software-result.json') == manifest['vm_result_sha256']
    qualification = json.loads((qualified / 'software-result.json').read_text())
    assert qualification['result'] == 'PASS'
    work = args.work.resolve() if args.work else installation / ('installed-suite-' + str(time.time_ns()))
    work.mkdir()
    media = work / 'media'
    media.mkdir()
    shutil.copyfile(fixtures / 'fixtures.tar', media / 'fixtures.tar')
    iso = work / 'fixtures.iso'
    subprocess.run(['makefs', '-t', 'cd9660', str(iso), str(media)], check=True)
    serial, sock = work / 'serial.log', work / 'serial.sock'
    disk = installation / 'installed.img'
    assert Path(install_result['disk']).resolve(strict=True) == disk
    command = [args.qemu, '-accel', 'tcg,thread=multi',
        '-machine', 'q35', '-cpu', 'max', '-m', '8192', '-smp', str(args.cpus),
        '-drive', f'file={disk},format=raw,if=none,id=target,snapshot=on',
        '-device', 'virtio-blk-pci,drive=target,serial=sw-installer-target',
        '-drive', f'file={iso},format=raw,media=cdrom,readonly=on',
        '-boot', 'c', '-nic', 'none', '-display', 'none', '-monitor', 'none',
        '-chardev', f'socket,id=serial,path={sock},server=on,wait=off,logfile={serial}',
        '-serial', 'chardev:serial']
    script = """sh <<'INSTALL_SUITE'
set -eu
trap 'echo SOFTWARE_INSTALLED_SETUP_FAIL' EXIT
[ "$(hostname)" = auth-policy-vm ]
[ "$(id -u)" = 0 ]
[ "$(mount -p | awk '$2 == "/" {print $1}')" = policyvm/ROOT/default ]
[ "$(sha256 -q /boot/kernel/kernel)" = KERNEL_HASH ]
[ "$(sha256 -q /usr/sbin/dtrace)" = DTRACE_HASH ]
pkg query '%n %v' > /tmp/suite-packages
cmp /root/installed-packages.txt /tmp/suite-packages
# Measure real approved-client exec/discovery/control round trips on the
# installed system. These are QEMU observations, not native performance claims.
/usr/bin/time -p -o /tmp/status-sequential.time sh -c '
 i=0
 while [ "$i" -lt 32 ]; do
  switchboardctl status >/dev/null || exit 1
  i=$((i + 1))
 done
'
/usr/bin/time -p -o /tmp/status-parallel.time sh -c '
 pids=""
 worker=0
 while [ "$worker" -lt 4 ]; do
  (
   i=0
   while [ "$i" -lt 8 ]; do
    switchboardctl status >/dev/null || exit 1
    i=$((i + 1))
   done
  ) &
  pids="$pids $!"
  worker=$((worker + 1))
 done
 failed=0
 for pid in $pids; do wait "$pid" || failed=1; done
 exit "$failed"
'
printf 'SOFTWARE_STATUS_SEQUENTIAL_SECONDS='
awk '$1 == "real" {print $2}' /tmp/status-sequential.time
printf 'SOFTWARE_STATUS_PARALLEL_SECONDS='
awk '$1 == "real" {print $2}' /tmp/status-parallel.time
printf '%s\n' SOFTWARE_STATUS_LOAD_PASS
mkdir -p /mnt/software-fixtures
mount -t cd9660 /dev/cd0 /mnt/software-fixtures
[ "$(sha256 -q /mnt/software-fixtures/fixtures.tar)" = ARCHIVE_HASH ]
tar -xpf /mnt/software-fixtures/fixtures.tar -C /
umount /mnt/software-fixtures
for program in trace-allow trace-deny revocation-probe reload-control application-probe; do
 ln -s /Capabilities/System/Fixture-$program.cap/Units/$program.unit/bin/$program /usr/bin/$program
done
# Compare the installed DTrace above before selecting the attributed test copy.
mv /usr/sbin/dtrace /root/installed-dtrace-original
ln -s /Capabilities/System/Fixture-dtrace.cap/Units/dtrace.unit/bin/dtrace /usr/sbin/dtrace
[ -d /Capabilities/System/Trace.cap/Units/bsdtrace.unit ]
mkdir -p /Capabilities/System/Trace.cap/Units/bsdtrace.unit/Config
printf '%s\n' system.Fixture-trace-allow/trace-allow > /Capabilities/System/Trace.cap/Units/bsdtrace.unit/Config/bsdtrace.allow
cat > /root/.profile <<'PROFILE'
case "$-" in *i*) ;; *) return ;; esac
if [ "$(tty)" = /dev/ttyu0 ]; then
 sh /root/software-application-guest.sh
fi
PROFILE
# root's login shell is zsh, which reads .zprofile rather than .profile.
printf '%s\n' "emulate sh -c '. /root/.profile'" > /root/.zprofile
trap - EXIT
printf '%s\n' SOFTWARE_INSTALLED_SUITE_SETUP_PASS
/usr/sbin/capsulectl reboot
INSTALL_SUITE
"""
    script = script.replace('KERNEL_HASH', manifest['kernel_sha256']).replace('DTRACE_HASH', manifest['dtrace_sha256']).replace('ARCHIVE_HASH', manifest['archive_sha256'])
    (work / 'setup.sh').write_text(script)
    subprocess.run(['sh', '-n', str(work / 'setup.sh')], check=True)
    shutdown = ShutdownEvidence(work)
    command += shutdown.arguments
    if args.qemu_data:
        command += ['-L', str(args.qemu_data.resolve())]
    (work / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    fatal = ('panic:', 'Fatal trap', 'lock order reversal')
    failures = ('SOFTWARE_INSTALLED_SETUP_FAIL', 'SOFTWARE_APPLICATION_FAIL')
    sent = diagnosed = forced = False
    started = time.monotonic()
    with (work / 'qemu.log').open('w') as output:
        process = subprocess.Popen(command, stdout=output, stderr=output)
        shutdown.start(process)
        try:
            while process.poll() is None and time.monotonic() - started < args.timeout:
                text = serial.read_text(errors='replace') if serial.exists() else ''
                lines = text.splitlines()
                if any(marker in text for marker in fatal):
                    break
                if not sent and 'SOFTWARE_INSTALLED_ROOT_BOOTED' in lines:
                    send(sock, script)
                    sent = True
                if not diagnosed and any(marker in lines for marker in failures):
                    send(sock, 'cat /var/log/capability.log; /usr/sbin/capsulectl poweroff\n')
                    diagnosed = True
                time.sleep(1)
        finally:
            if process.poll() is None:
                forced = True
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    shutdown_evidence = shutdown.finish()
    text = serial.read_text(errors='replace') if serial.exists() else ''
    # A smaller prerequisite result cannot silently weaken this acceptance gate.
    required = list(dict.fromkeys(['SOFTWARE_APPLICATION_DISCOVERY_PASS', 'SOFTWARE_APPLICATION_DTRACE_PASS', 'SOFTWARE_APPLICATION_SERVICES_PASS', 'SOFTWARE_STOCK_LOGIN_PASS', 'SOFTWARE_SSH_password_PASS', 'SOFTWARE_SSH_keyboard-interactive_PASS', 'SOFTWARE_SSH_KEYS_WITH_AND_WITHOUT_PAM_PASS', 'SOFTWARE_STOCK_UNIX_PASS', 'SOFTWARE_CLIENT_REGRESSIONS_PASS', 'SOFTWARE_MANIFEST_REGRESSIONS_PASS', 'SOFTWARE_CORE_DENIAL_PASS', 'SOFTWARE_APPLICATION_PASS', 'SOFTWARE_SU_PASSWORD_TRANSITIONS_PASS', 'SOFTWARE_HOSTILE_USER_AGENT_PASS', 'SOFTWARE_PROCESS_CONTEXT_PASS', 'PROCESS_CONTEXT_KERNEL_PASS', 'PROCESS_CONTEXT_EDGE_PASS', 'PROCESS_CONTEXT_IPC_PASS', 'SOFTWARE_RETIRED_PACKAGE_PASS', 'SOFTWARE_POLICY_RELOAD_PASS', 'SOFTWARE_CACHED_REVOCATION_PASS', 'SOFTWARE_MANAGED_CONTROL_PASS', 'SOFTWARE_TRACE_PROVIDER_PASS', 'SOFTWARE_BE_PREPARED', 'SOFTWARE_BE_CANDIDATE_PASS', 'SOFTWARE_BE_ROLLBACK_PASS', 'SOFTWARE_BE_CANDIDATE_DTRACE_PASS', 'SOFTWARE_BE_ROLLBACK_DTRACE_PASS', 'SOFTWARE_INSTALLED_SUITE_SETUP_PASS', 'SOFTWARE_STATUS_LOAD_PASS'] + qualification['required_markers'] + args.require_marker))
    missing = [marker for marker in required if marker not in text.splitlines()]
    timings = {}
    for mode in ('sequential', 'parallel'):
        matches = re.findall(r'^SOFTWARE_STATUS_' + mode.upper() + r'_SECONDS=([0-9]+(?:\.[0-9]+)?)\r?$', text, re.MULTILINE)
        if len(matches) == 1:
            timings[mode] = float(matches[0])
    passed = len(timings) == 2 and sent and not missing and not forced and process.returncode == 0 and shutdown_evidence['guest_poweroff'] and 'All buffers synced.' in text and 'Powering system off' in text and not any(marker in text for marker in fatal) and not any(marker in text.splitlines() for marker in failures)
    result = {'result': 'PASS' if passed else 'FAIL',
        'shutdown_evidence': shutdown_evidence,
        'scope': 'full software suite on BSDInstall target overlay with explicit test fixtures; production kernel and userland retained',
        'missing_markers': missing, 'required_markers': required,
        'status_load': {'scope': 'QEMU TCG end-to-end client execution plus discovery and status; not native IPC latency', 'sequential_requests': 32, 'parallel_workers': 4, 'requests_per_worker': 8, 'elapsed_seconds': timings},
        'forced': forced, 'exit': process.returncode,
        'serial_sha256': digest(serial) if serial.exists() else None,
        'fixtures_manifest_sha256': digest(fixtures / 'fixtures.json'),
        'installed_boot_result_sha256': digest(installation / 'installed-boot/result.json'),
        'elapsed_seconds': round(time.monotonic() - started, 1)}
    (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
