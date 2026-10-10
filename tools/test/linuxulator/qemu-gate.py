#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Boot the requested pre-staged guests and require complete Linux ABI gate results."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

CASES = {
    'memfd_valid', 'memfd_unknown', 'memfd_huge_encoding', 'memfd_faults',
    'memfd_seals', 'memfd_churn', 'readahead_valid', 'readahead_invalid', 'sync_valid',
    'sync_file_range_options', 'fadvise_options', 'epoll_options', 'xattr_options', 'umount_invalid', 'umount_lifecycle', 'umount_unprivileged',
}


UNSHARE_CASES = {"zero_preserves_sharing", "fs_detaches_only_paths_and_umask",
                 "invalid_flags", "rejection_preserves_sharing", "fs_unprivileged",
                 "fs_repeated", "fs_fork_exec_lifetime", "fs_root_lifetime",
                 "fs_concurrent_shared_mutation", "bsd_rejected_flags", "bsd_thread_rejection",
                 "files_detaches_only_descriptors", "fs_files_detach_both",
                 "files_preserves_open_description", "files_exec_detaches",
                 "fs_exec_preserves_sharing", "bsd_epoll_rejection"}

XSTATE_CASES = {'roundtrip', 'write_resume', 'lengths', 'invalid', 'init_state', 'faults', 'metadata'}
PEER_CASES = {'inet4', 'inet6', 'local', 'pathname', 'state', 'faults', 'lifetime'}
EVENT_CASES = {'exec', 'fork', 'vfork', 'clone', 'exit', 'signal', 'vfork_done', 'selective', 'isolation', 'waitid'}
MCAST_CASES = {'mixed', 'mixed_delivery', 'mixed_churn', 'roundtrip', 'replace', 'leave', 'lengths', 'invalid', 'faults', 'lifetime', 'duplicates', 'delivery', 'interfaces', 'churn'}
PTRACE_CASES = {'thread_target', 'bounds', 'permissions', 'faults', 'tls_write', 'xstate_read', 'gpr_partial', 'repeated', 'gpr_bad_base', 'gpr_read', 'fp_read', 'protected_memory', 'fp_setregset', 'gpr_fault_progress', 'fp_bad_mxcsr', 'fp_write', 'gpr_rax', 'unknown', 'lengths', 'unprivileged', 'gpr_write'}
COOKIE_CASES = {'identity', 'lifetime', 'rights', 'bounds', 'faults',
                'churn', 'unprivileged', 'caps'}
PTRACE_OPTION_CASES = {'linux_ptrace_lifecycle', 'linux_ptrace_user',
                       'linux_ptrace_metadata', 'linux_ptrace_sigmask', 'linux_proc_task',
                       'user_unprivileged',
                       'linux_ptrace_kill_native'}
QUOTA_CASES = {"hard_limit_roundtrip", "invalid_arguments", "device_path_validation",
               "quota_sync", "permissions", "ignored_fields", "descriptor_lifetime",
               "fork_exec_lifetime", "enforcement_and_usage", "group_enforcement_and_usage",
               "unsupported_updates_are_atomic"}

OFD_CASES = {"ranges", "invalid", "ownership", "posix", "flock_independent",
             "fork_lifetime", "wait_unlock", "wait_close", "interrupted",
             "killed_waiter", "churn", "deadlock", "faults", "descriptor_passing", "exec_lifetime"}


SEAL_CASES = {"mappings", "invalid", "lifetime", "resizing", "churn", "io_contract"}


RESOLVE_CASES = {"plain", "symlinks", "magic", "fd_links", "faults",
                 "beneath", "lifetime", "permissions", "race", "native_mounts", "zfs_datasets",
                 "xdev_basic", "xdev_mount", "xdev_magic", "xdev_churn", "xdev_mount_race", "root_paths", "root_symlinks",
                 "root_invalid", "root_magic", "root_mounts", "root_lifetime", "root_race", "root_permissions"}


PERF_CASES = {"basic_task_clock", "disabled_transitions", "read_formats",
              "software_counters", "attribute_sizes", "attribute_options",
              "target_and_flags", "fd_contract", "ioctl_validation",
              "cloexec_flag", "thread_exit_lifetime", "thread_close_race",
              "fork_inheritance"}


def artifact_errors(console, manifest):
    """Verify the bounded artifact section emitted before guest execution."""
    lines = console.replace('\r\n', '\n').splitlines()
    begin, end = 'GATE_ARTIFACTS_BEGIN', 'GATE_ARTIFACTS_END'
    if not manifest:
        return ['empty artifact manifest']
    if lines.count(begin) != 1 or lines.count(end) != 1:
        return ['missing or duplicate artifact section']
    first, last = lines.index(begin), lines.index(end)
    if first >= last:
        return ['artifact section reversed']
    observed = lines[first + 1:last]
    expected = [f'SHA256 ({path}) = {digest}' for path, digest in manifest.items()]
    if len(observed) != len(expected) or set(observed) != set(expected):
        return ['missing, duplicate, unexpected or mismatched artifact hashes']
    return []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--amd64-image', type=Path, required=True)
    parser.add_argument('--amd64-manifest', type=Path,
                        help='Expected path-to-SHA256 map in the bounded guest artifact section')
    parser.add_argument('--amd64-swap-image', type=Path, required=True,
                        help='Disposable second disk for the swapoff gate')
    parser.add_argument('--amd64-swap-image2', type=Path, required=True,
                        help='Disposable third disk for swap priority tests')
    parser.add_argument('--arm64-image', type=Path)
    parser.add_argument('--qemu-dir', type=Path, required=True)
    parser.add_argument('--firmware-dir', type=Path, required=True)
    parser.add_argument('--amd64-qemu', type=Path, help='Override the amd64 executable path')
    parser.add_argument('--arm64-qemu', type=Path, help='Override the arm64 executable path')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--memory-mib', type=int, default=2048)
    args = parser.parse_args()
    manifest = None
    if args.amd64_manifest is not None:
        manifest = json.loads(args.amd64_manifest.read_text())
        if not isinstance(manifest, dict) or not manifest or any(
                not isinstance(path, str) or not path.startswith('/') or
                not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
                for path, digest in manifest.items()):
            parser.error('invalid amd64 artifact manifest')
    if args.memory_mib < 1024:
        parser.error('QEMU guests need at least 1024 MiB of memory')
    if args.amd64_swap_image.resolve() == args.amd64_image.resolve():
        parser.error('the swap image must differ from the ZFS root image')
    if not args.amd64_swap_image.is_file() or args.amd64_swap_image.stat().st_size < 32 * 1024 * 1024:
        parser.error('the amd64 swap image must be a file of at least 32 MiB')
    if args.amd64_swap_image2.resolve() in (args.amd64_image.resolve(), args.amd64_swap_image.resolve()):
        parser.error('the second swap image must differ from the root and first swap images')
    if not args.amd64_swap_image2.is_file() or args.amd64_swap_image2.stat().st_size < 32 * 1024 * 1024:
        parser.error('the second swap image must be a file of at least 32 MiB')
    # Refuse to overwrite evidence from an earlier run.
    args.output.mkdir(parents=True, exist_ok=False)
    results = {}
    if manifest is not None:
        (args.output / 'amd64-manifest.json').write_text(
            json.dumps(manifest, indent=2) + '\n')
    guests = [('amd64', 'qemu-system-x86_64', args.amd64_image)]
    if args.arm64_image is not None:
        guests.append(('arm64', 'qemu-system-aarch64', args.arm64_image))
    for arch, binary, image in guests:
        executable = (args.amd64_qemu if arch == 'amd64' else args.arm64_qemu) or args.qemu_dir / binary
        command = [str(executable), '-L', str(args.firmware_dir),
                   '-accel', 'tcg,thread=multi', '-m', str(args.memory_mib), '-smp', '2',
                   '-nic', ('user,model=virtio-net-pci,restrict=on' if arch == 'amd64' else 'none'), '-display', 'none', '-monitor', 'none',
                   '-serial', 'stdio', '-no-reboot',
                   '-drive', f'file={image.resolve()},format=raw,if=virtio,snapshot=on']
        if arch == 'amd64':
            command += ['-machine', 'q35', '-cpu', 'max', '-drive',
                        f'file={args.amd64_swap_image.resolve()},format=raw,if=virtio,snapshot=on',
                        '-drive',
                        f'file={args.amd64_swap_image2.resolve()},format=raw,if=virtio,snapshot=on,discard=unmap']
        else:
            command += ['-machine', 'virt', '-cpu', 'cortex-a72', '-bios',
                        str(args.firmware_dir / 'edk2-aarch64-code.fd')]
        record = {'command': command, 'started': time.time(), 'passed': False}
        print(f'{arch}: booting isolated QEMU guest', flush=True)
        try:
            record['qemu_version'] = subprocess.check_output(
                [str(executable), '--version'], text=True)
            with (args.output / f'{arch}.console.log').open('wb') as output:
                completed = subprocess.run(command, stdin=subprocess.DEVNULL,
                                           stdout=output, stderr=subprocess.STDOUT,
                                           timeout=args.timeout, check=False)
            record['exit_code'] = completed.returncode
            text = (args.output / f'{arch}.console.log').read_text(errors='replace')
            rows = re.findall(r'^GATE_CASE (\d+) (\w+) (\d+)\r?$', text, re.M)
            expected = {(str(n), name, '0') for n in (1, 2, 3) for name in CASES}
            panics = re.findall(r'panic:|KDB: enter|lock order reversal|non-sleepable locks held|Fatal trap|'
                                r'Fatal data abort|use-after-free|acquiring duplicate lock', text, re.I)
            record.update(cases=rows, diagnostic_failures=panics)
            regressions = re.findall(r'^GATE_REGRESSION (\w+) (\d+)\r?$', text, re.M)
            expected_regressions = {('linux_fileflags', '0'), ('linux_fileattr', '0'), ('linux_fchroot', '0'), ('linux_machdep2', '0'), ('linux_openat2', '0'), ('linux_fallocate', '0')} if arch == 'amd64' else set()
            record['regressions'] = regressions
            aio = re.findall(r'^GATE_AIO_(CONTEXT|RW|FULL|CAPACITY|FLAGS|CANCEL|POLL|SIGNAL|TIMEOUT|COUNTS|NOSIGNAL) (?:(zfs|tmpfs) )?(\d+) (\d+)\r?$', text, re.M)
            expected_aio = ({('CONTEXT', '', str(n), '0') for n in (1, 2, 3)} |
                            {(kind, fs, str(n), '0')
                             for kind in ('RW', 'FULL', 'CAPACITY', 'FLAGS', 'CANCEL', 'POLL', 'SIGNAL', 'TIMEOUT', 'COUNTS', 'NOSIGNAL')
                             for fs in ('zfs', 'tmpfs') for n in (1, 2, 3)}) if arch == 'amd64' else set()
            record['aio'] = aio
            sysfs = re.findall(r'^GATE_SYSFS (zfs|tmpfs) (64|32) (\d+) (\d+)\r?$', text, re.M)
            expected_sysfs = {(fs, abi, str(n), '0') for fs in ('zfs', 'tmpfs')
                              for abi in ('64',) for n in (1, 2, 3)} if arch == 'amd64' else set()
            record['sysfs'] = sysfs
            unshare = re.findall(r'^GATE_UNSHARE (zfs|tmpfs) (\d+) (\w+) (\d+)\r?$', text, re.M)
            expected_unshare = {(fs, str(n), case, '0') for fs in ('zfs', 'tmpfs')
                                for n in (1, 2, 3) for case in UNSHARE_CASES} if arch == 'amd64' else set()
            record['unshare'] = unshare
            unshare_capmode = re.findall(r'^GATE_UNSHARE_CAPMODE (\d+) (\d+)\r?$', text, re.M)
            expected_unshare_capmode = {(str(n), '0') for n in (1, 2, 3)} if arch == 'amd64' else set()
            record['unshare_capmode'] = unshare_capmode
            ptrace = re.findall(r'^GATE_PTRACE (\d+) (\w+) (\d+)\r?$', text, re.M)
            expected_ptrace = {(str(n), case, '0') for n in (1, 2, 3)
                               for case in PTRACE_CASES} if arch == 'amd64' else set()
            cookie = re.findall(r'^GATE_COOKIE (\d+) (\w+) (\d+)\r?$', text, re.M)
            expected_cookie = {(str(n), case, '0') for n in (1, 2, 3)
                               for case in COOKIE_CASES} if arch == 'amd64' else set()
            record['cookie'] = cookie
            peer = re.findall(r'^GATE_PEER (\d+) (root|unprivileged) (\w+) (\d+)\r?$', text, re.M)
            events = re.findall(r'^GATE_EVENT (\d+) (root|unprivileged) (\w+) (\d+)\r?$', text, re.M)
            expected_peer = {(str(n), user, case, '0') for n in (1, 2, 3)
                             for user in ('root', 'unprivileged') for case in PEER_CASES} if arch == 'amd64' else set()
            expected_events = {(str(n), user, case, '0') for n in (1, 2, 3)
                               for user in ('root', 'unprivileged') for case in EVENT_CASES} if arch == 'amd64' else set()
            peer_caps = re.findall(r'^GATE_PEER_CAPS (\d+) (\d+)\r?$', text, re.M)
            exit_native = re.findall(r'^GATE_EXIT_NATIVE (\d+) (\d+)\r?$', text, re.M)
            expected_event_native = {(str(n), '0') for n in (1, 2, 3)} if arch == 'amd64' else set()
            record.update(peer=peer, events=events, peer_caps=peer_caps, exit_native=exit_native)
            xstate = re.findall(r'^GATE_XSTATE (\d+) (root|unprivileged) (\w+) (\d+)\r?$', text, re.M)
            expected_xstate = {(str(n), user, case, '0') for n in (1, 2, 3)
                               for user in ('root', 'unprivileged')
                               for case in XSTATE_CASES} if arch == 'amd64' else set()
            mcast = re.findall(r'^GATE_MCAST (\d+) (root|unprivileged) (\w+) (\d+)\r?$', text, re.M)
            expected_mcast = {(str(n), user, case, '0') for n in (1, 2, 3)
                              for user in ('root', 'unprivileged')
                              for case in MCAST_CASES} if arch == 'amd64' else set()
            mcast_native = re.findall(r'^GATE_MCAST_NATIVE (\d+) (\d+)\r?$', text, re.M)
            expected_mcast_native = {(str(n), '0') for n in (1, 2, 3)} if arch == 'amd64' else set()
            record.update(xstate=xstate, mcast=mcast, mcast_native=mcast_native)
            ptrace_options = re.findall(r'^GATE_PTRACE_OPTIONS (\d+) (\w+) (\d+)\r?$', text, re.M)
            expected_ptrace_options = {(str(n), case, '0') for n in (1, 2, 3)
                                       for case in PTRACE_OPTION_CASES} if arch == 'amd64' else set()
            record['ptrace_options'] = ptrace_options
            ptrace_seize = re.findall(r"^GATE_PTRACE_SEIZE (\d+) (\d+)\r?$", text, re.M)
            ptrace_interrupt = re.findall(r"^GATE_PTRACE_INTERRUPT (\d+) (\d+)\r?$", text, re.M)
            ptrace_listen = re.findall(r"^GATE_PTRACE_LISTEN (\d+) (\d+)\r?$", text, re.M)
            ptrace_native = re.findall(r'^GATE_PTRACE_NATIVE (\d+) (\d+)\r?$', text, re.M)
            ptrace_capmode = re.findall(r'^GATE_PTRACE_CAPMODE (\d+) (\d+)\r?$', text, re.M)
            expected_ptrace_extra = {(str(n), '0') for n in (1, 2, 3)} if arch == 'amd64' else set()
            record.update(ptrace=ptrace, ptrace_seize=ptrace_seize,
                          ptrace_interrupt=ptrace_interrupt,
                          ptrace_listen=ptrace_listen,
                          ptrace_native=ptrace_native, ptrace_capmode=ptrace_capmode)
            quota = re.findall(r'^GATE_QUOTA (\d+) (\w+) (\d+)\r?$', text, re.M)
            expected_quota = {(str(n), case, '0') for n in (1, 2, 3)
                              for case in QUOTA_CASES} if arch == 'amd64' else set()
            quota_cap = re.findall(r'^GATE_QUOTA_CAPMODE (\d+) (fd|path) (\d+)\r?$', text, re.M)
            expected_quota_cap = {(str(n), kind, '0') for n in (1, 2, 3)
                                  for kind in ('fd', 'path')} if arch == 'amd64' else set()
            quota_native = re.findall(r'^GATE_QUOTA_NATIVE (\d+) (\d+)\r?$', text, re.M)
            expected_quota_native = {(str(n), '0') for n in (1, 2, 3)} if arch == 'amd64' else set()
            quota_extra = re.findall(r'^GATE_QUOTA_(REMOUNT|READONLY|READONLY_POOL|DEFAULT|TMPFS) (\d+)\r?$', text, re.M)
            expected_quota_extra = {(case, '0') for case in ('REMOUNT', 'READONLY', 'READONLY_POOL', 'DEFAULT', 'TMPFS')} if arch == 'amd64' else set()
            record.update(quota=quota, quota_capmode=quota_cap,
                          quota_native=quota_native, quota_extra=quota_extra)
            rseq = re.findall(r'^GATE_RSEQ (zfs|tmpfs) (register|signal|threads|lifecycle|auxv|preempt|hold) (\d+) (\d+)\r?$', text, re.M)
            expected_rseq = {(fs, case, str(n), '0') for fs in ('zfs', 'tmpfs')
                             for case in ('register', 'signal', 'threads', 'lifecycle', 'auxv', 'preempt', 'hold') for n in (1, 2, 3)} if arch == 'amd64' else set()
            record['rseq'] = rseq
            perf = re.findall(r'^GATE_PERF (zfs|tmpfs) (\d+) (\w+) (\d+)\r?$', text, re.M)
            expected_perf = {(fs, str(n), case, '0') for fs in ('zfs', 'tmpfs')
                             for n in (1, 2, 3) for case in PERF_CASES} if arch == 'amd64' else set()
            record['perf'] = perf
            perf_native_exec = re.findall(r'^GATE_PERF_NATIVE_EXEC (\d+)\r?$', text, re.M)
            expected_perf_native_exec = ['0'] if arch == 'amd64' else []
            record['perf_native_exec'] = perf_native_exec
            remap = re.findall(r'^GATE_REMAP (zfs|tmpfs) (\d+) (\d+)\r?$', text, re.M)
            expected_remap = {(fs, str(n), '0') for fs in ('zfs', 'tmpfs')
                              for n in (1, 2, 3)} if arch == 'amd64' else set()
            record['remap'] = remap
            ioperm = re.findall(r'^GATE_IOPERM (zfs|tmpfs) (\d+) (\d+)\r?$', text, re.M)
            expected_ioperm = {(fs, str(n), '0') for fs in ('zfs', 'tmpfs')
                               for n in (1, 2, 3)} if arch == 'amd64' else set()
            record['ioperm'] = ioperm
            ioperm_native = re.findall(r'^GATE_IOPERM_NATIVE (zfs|tmpfs) (\d+) (\d+)\r?$', text, re.M)
            record['ioperm_native'] = ioperm_native
            iopl = re.findall(r'^GATE_IOPL (zfs|tmpfs) (\d+) (\d+)\r?$', text, re.M)
            expected_iopl = {(fs, str(n), '0') for fs in ('zfs', 'tmpfs')
                             for n in (1, 2, 3)} if arch == 'amd64' else set()
            record['iopl'] = iopl
            ldt = re.findall(r'^GATE_LDT (zfs|tmpfs) (\d+) (\d+)\r?$', text, re.M)
            expected_ldt = {(fs, str(n), '0') for fs in ('zfs', 'tmpfs')
                            for n in (1, 2, 3)} if arch == 'amd64' else set()
            record['ldt'] = ldt
            swapoff = re.findall(r'^GATE_SWAPOFF (zfs|tmpfs) (\d+) (\d+)\r?$', text, re.M)
            expected_swapoff = {(fs, str(n), '0') for fs in ('zfs', 'tmpfs')
                                for n in (1, 2, 3)} if arch == 'amd64' else set()
            record['swapoff'] = swapoff
            swapon_flags = re.findall(r'^GATE_SWAPON_FLAGS (zfs|tmpfs) (\d+) (\d+)\r?$', text, re.M)
            expected_swapon_flags = {(fs, str(n), '0') for fs in ('zfs', 'tmpfs')
                                     for n in (1, 2, 3)} if arch == 'amd64' else set()
            record['swapon_flags'] = swapon_flags
            swap_priority = re.findall(r'^GATE_SWAP_PRIORITY (zfs|tmpfs) (\d+) (\d+)\r?$', text, re.M)
            expected_swap_priority = {(fs, str(n), '0') for fs in ('zfs', 'tmpfs')
                                      for n in (1, 2, 3)} if arch == 'amd64' else set()
            record['swap_priority'] = swap_priority
            swap_discard = re.findall(r'^GATE_SWAP_DISCARD (zfs|tmpfs) (\d+) (\d+)\r?$', text, re.M)
            expected_swap_discard = {(fs, str(n), '0') for fs in ('zfs', 'tmpfs')
                                     for n in (1, 2, 3)} if arch == 'amd64' else set()
            record['swap_discard'] = swap_discard
            native_aio = re.findall(r'^GATE_NATIVE_AIO (zfs|tmpfs) (\d+) (\d+)\r?$', text, re.M)
            expected_native_aio = {(fs, str(n), '0') for fs in ('zfs', 'tmpfs')
                                   for n in (1, 2, 3)} if arch == 'amd64' else set()
            record['native_aio'] = native_aio
            ofd = re.findall(r'^GATE_OFD (zfs|tmpfs) (native|linux) (\d+) (\w+) (\d+)\r?$', text, re.M)
            expected_ofd = {(fs, abi, str(n), name, '0')
                            for fs in ('zfs', 'tmpfs') for abi in ('native', 'linux')
                            for n in (1, 2, 3) for name in OFD_CASES}
            record['ofd'] = ofd
            extra = re.findall(r'^GATE_OFD_EXTRA (zfs|tmpfs) (\d+) (\d+)\r?$', text, re.M)
            expected_extra = {(fs, str(n), '0') for fs in ('zfs', 'tmpfs') for n in (1, 2, 3)}
            record['ofd_extra'] = extra
            seals = re.findall(r'^GATE_SEAL (native|linux) (\d+) (\w+) (\d+)\r?$', text, re.M)
            expected_seals = {(abi, str(n), name, '0') for abi in ('native', 'linux')
                              for n in (1, 2, 3) for name in
                              (SEAL_CASES | ({'readonly'} if abi == 'native' else set()))}
            record['seals'] = seals
            resolve = re.findall(r'^GATE_RESOLVE (zfs|tmpfs) (\d+) (\w+) (\d+)\r?$', text, re.M)
            expected_resolve = {(fs, str(n), name, '0') for fs in ('zfs', 'tmpfs')
                                for n in (1, 2, 3)
                                for name in RESOLVE_CASES}
            record['resolve'] = resolve
            direct = re.findall(r'^GATE_RWF_DIRECT (zfs|tmpfs) (\d+) (\d+)\r?$', text, re.M)
            expected_direct = {(fs, str(n), '0') for fs in ('zfs', 'tmpfs') for n in (1, 2, 3)}
            record['rwf_direct'] = direct
            result_rows = {
                'ptrace': ptrace, 'ptrace_seize': ptrace_seize,
                'ptrace_interrupt': ptrace_interrupt, 'ptrace_listen': ptrace_listen,
                'ptrace_native': ptrace_native,
                'ptrace_options': ptrace_options, 'cookie': cookie,
                'ptrace_capmode': ptrace_capmode,
                'quota': quota, 'quota_capmode': quota_cap,
                'quota_native': quota_native, 'quota_extra': quota_extra,
                'perf': perf, 'perf_native_exec': perf_native_exec,
            }
            record['nonzero_results'] = {
                name: [row for row in entries if row[-1] != '0']
                for name, entries in result_rows.items()
                if any(row[-1] != '0' for row in entries)
            }
            hash_errors = artifact_errors(text, manifest) if arch == 'amd64' and manifest is not None else []
            record['artifact_errors'] = hash_errors
            record['verified_artifacts'] = len(manifest) if arch == 'amd64' and manifest is not None and not hash_errors else 0
            record['passed'] = (
                not hash_errors and
                (arch != 'amd64' or ('All buffers synced.' in text and
                                     'acpi0: Powering system off...' in text)) and
                len(ptrace) == len(expected_ptrace) and set(ptrace) == expected_ptrace and
                len(cookie) == len(expected_cookie) and set(cookie) == expected_cookie and
                len(peer) == len(expected_peer) and set(peer) == expected_peer and
                len(events) == len(expected_events) and set(events) == expected_events and
                len(peer_caps) == len(expected_event_native) and set(peer_caps) == expected_event_native and
                len(exit_native) == len(expected_event_native) and set(exit_native) == expected_event_native and
                (arch != 'amd64' or 'GATE_PEER_EVENTS_DONE' in text) and
                len(xstate) == len(expected_xstate) and set(xstate) == expected_xstate and
                len(mcast) == len(expected_mcast) and set(mcast) == expected_mcast and
                len(mcast_native) == len(expected_mcast_native) and set(mcast_native) == expected_mcast_native and
                len(ptrace_options) == len(expected_ptrace_options) and set(ptrace_options) == expected_ptrace_options and
                len(ptrace_seize) == len(expected_ptrace_extra) and set(ptrace_seize) == expected_ptrace_extra and
                len(ptrace_interrupt) == len(expected_ptrace_extra) and set(ptrace_interrupt) == expected_ptrace_extra and
                len(ptrace_listen) == len(expected_ptrace_extra) and set(ptrace_listen) == expected_ptrace_extra and
                len(ptrace_native) == len(expected_ptrace_extra) and set(ptrace_native) == expected_ptrace_extra and
                len(ptrace_capmode) == len(expected_ptrace_extra) and set(ptrace_capmode) == expected_ptrace_extra and
                len(quota) == len(expected_quota) and set(quota) == expected_quota and
                len(quota_cap) == len(expected_quota_cap) and set(quota_cap) == expected_quota_cap and
                len(quota_native) == len(expected_quota_native) and set(quota_native) == expected_quota_native and
                len(quota_extra) == len(expected_quota_extra) and set(quota_extra) == expected_quota_extra and
                len(aio) == len(expected_aio) and set(aio) == expected_aio and
                len(sysfs) == len(expected_sysfs) and set(sysfs) == expected_sysfs and
                len(unshare) == len(expected_unshare) and set(unshare) == expected_unshare and
                len(unshare_capmode) == len(expected_unshare_capmode) and
                set(unshare_capmode) == expected_unshare_capmode and
                len(rseq) == len(expected_rseq) and set(rseq) == expected_rseq and
                len(perf) == len(expected_perf) and set(perf) == expected_perf and
                perf_native_exec == expected_perf_native_exec and
                len(remap) == len(expected_remap) and set(remap) == expected_remap and
                len(ioperm) == len(expected_ioperm) and set(ioperm) == expected_ioperm and
                len(ioperm_native) == len(expected_ioperm) and set(ioperm_native) == expected_ioperm and
                len(iopl) == len(expected_iopl) and set(iopl) == expected_iopl and
                len(ldt) == len(expected_ldt) and set(ldt) == expected_ldt and
                len(swapoff) == len(expected_swapoff) and set(swapoff) == expected_swapoff and
                len(swapon_flags) == len(expected_swapon_flags) and
                set(swapon_flags) == expected_swapon_flags and
                len(swap_priority) == len(expected_swap_priority) and
                set(swap_priority) == expected_swap_priority and
                len(swap_discard) == len(expected_swap_discard) and
                set(swap_discard) == expected_swap_discard and
                len(native_aio) == len(expected_native_aio) and
                set(native_aio) == expected_native_aio and
                len(direct) == len(expected_direct) and set(direct) == expected_direct and
                len(resolve) == len(expected_resolve) and set(resolve) == expected_resolve and
                len(seals) == len(expected_seals) and set(seals) == expected_seals
                and len(extra) == len(expected_extra) and set(extra) == expected_extra
                and len(ofd) == len(expected_ofd) and set(ofd) == expected_ofd and
                completed.returncode == 0 and len(rows) == len(expected)
                and set(rows) == expected and not panics
                and set(regressions) == expected_regressions
                and len(regressions) == len(expected_regressions)
                and text.count('GATE_ROOT_FS zfs') == 1
                and text.count('GATE_POOL_HEALTHY') == 1
                and text.count('LINUXULATOR_GATE_BEGIN') == 1
                and text.count('LINUXULATOR_GATE_DONE') == 1
                and f'GATE_TOTAL passed={len(expected)} failed=0' in text
            )
        except (OSError, subprocess.SubprocessError) as error:
            record['error'] = str(error)
        record['finished'] = time.time()
        results[arch] = record
        (args.output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        print(f'{arch}: {"PASS" if record["passed"] else "FAIL"}', flush=True)
    return 0 if all(r['passed'] for r in results.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
