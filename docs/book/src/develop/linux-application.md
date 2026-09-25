# A Linux Application

5BSD runs 64-bit Linux binaries through the Linuxulator, on by default, with
a syscall table that covers Linux 7.3's x86_64 numbering (slots 0 to 472).
The reason to ship a Linux application on 5BSD rather than port it is that
the emulation gives you the Linux ABI while the kernel beneath it stays a
capability system: MAC and mac_capability policy apply to the translated
native operations, so a Linux program is policed by a layer it cannot see
and cannot attack through. This chapter is the developer's route from "I
have a Linux binary" to "it runs here, and I know what it cannot do". The
mechanism itself is in Part V, [Linux Emulation](../compat/linux/overview.md);
this chapter is about shipping.

## What to check first: a syscall census

The honest unit of Linux compatibility is the syscall, and the tree keeps
the ledger in `docs/linuxulator-syscall-coverage.md`. Its section 5 is a
386-row table of every named x86_64 slot with one of these statuses:

| Status | Meaning |
|---|---|
| STD-real | a handler or native alias exists; it may cover only a subset of the Linux contract |
| DUMMY | declared but stubbed: logs "syscall X not implemented" once per process and returns `ENOSYS` |
| STUB-reject | a hand-written handler that only rejects (`seccomp`) |
| UNIMPL-ancient | deliberately absent, removed from Linux long ago (`uselib`, `create_module`, `epoll_ctl_old`) |

At the last count in that document the numbers are 334 STD-real, 36 DUMMY,
1 reject-only and 15 UNIMPL-ancient, with the caveat the document itself
carries: a handler is not proof that every option of that syscall works.
The 36 DUMMY stubs are the ones to look for in your application:
`pivot_root`, `init_module`, `delete_module`, `finit_module`, `kexec_load`,
`kexec_file_load`, `add_key`, `request_key`, `keyctl`, `fanotify_init`,
`fanotify_mark`, `setns`, `listns`, `bpf`, `userfaultfd`, `memfd_secret`,
`process_mrelease`, `map_shadow_stack`, `uretprobe`, `uprobe`, the new mount
API (`open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`,
`mount_setattr`, `open_tree_attr`), the three `landlock_*` calls, the three
`lsm_*` calls, `lookup_dcookie` and `rseq_slice_yield`.

truss(1) decodes Linux syscalls on 5BSD (`usr.bin/truss/setup.c` registers
the `Linux ELF64` ABI, names come from libsysdecode's generated table), so
the census is one command:

```sh
truss -o truss.out ./myapp --some-workload
grep -o '^linux_[a-z0-9_]*' truss.out | sort | uniq -c | sort -rn
grep UNKNOWN truss.out
```

Names carry the `linux_` prefix because they come from
`sys/amd64/linux/syscalls.master`; a line that says `UNKNOWN` is a number
outside the table. Cross-check each name against the section 5 table, and
run the workload with `sysctl compat.linux.debug=3` so a DUMMY stub's
"not implemented" line lands in the log. ktrace(1) plus kdump(1) give the
same census (`kdump` knows `SV_ABI_LINUX`), and DTrace exposes every handler
as `syscall:linux:linux_<name>:entry` once `systrace_linux.ko` is loaded,
with SDT probes in the `linuxulator` provider for the newer subsystems.
`tests/sys/kern/linux_trace_test.sh` is the reference for all three and
fails if any of them prints an unknown syscall.

## Where a Linux program lives

Linux processes look paths up under `compat.linux.emul_path`, default
`/compat/linux`, before falling back to `/`: an open of `/etc/passwd` tries
`/compat/linux/etc/passwd` first (linux(4)). A dynamically linked Linux
binary therefore needs its loader and libraries under `/compat/linux/lib`
and `/compat/linux/lib64`, and the whole userland that goes with them.
linux(4) points at the FreeBSD ports `emulators/linux_base-c7` package or
debootstrap(8) for that; the reference userland the emulator is developed
against is Rocky Linux 9 (a minimal container root unpacked into a jail),
and the committed test evidence is Alpine's musl busybox at
`/compat/linux/bin/busybox` with `ld-musl-x86_64.so.1` in `/compat/linux/lib`.
There is no 5BSD package for a Linux userland.

The default configuration is already on. `libexec/rc/rc.conf` sets
`linux_enable="YES"` and `linux_mounts_enable="YES"`; `stand/defaults/loader.conf`
loads `linux_common` and `linux64`; and `libexec/rc/rc.d/linux` mounts, with `nocover`,
linprocfs on `/compat/linux/proc`, linsysfs on `/compat/linux/sys`, devfs on
`/compat/linux/dev`, fdescfs with `linrdlnk` on `/compat/linux/dev/fd` and a
tmpfs on `/compat/linux/dev/shm`, then sets `kern.elf64.fallback_brand=3` so
an unbranded ELF is treated as Linux. 5BSD is 64-bit only: the 32-bit
`linux.ko` is neither built nor loadable on amd64 (`sys/modules/Makefile`,
`nooptions COMPAT_FREEBSD32` in GENERIC), so an i386 Linux binary does not
run.

The advertised kernel is 5.15.0. The knobs are `compat.linux.*` sysctls
(`sys/compat/linux/linux_mib.c`), and the identity ones are per-jail
parameters so a jail can present a different Linux to its tenants.

| Sysctl | Default | Purpose |
|---|---|---|
| `compat.linux.osrelease` | `5.15.0` | reported kernel version; also jail param `linux.osrelease` |
| `compat.linux.osname` | `Linux` | reported OS name; jail param `linux.osname` |
| `compat.linux.oss_version` | `198144` | OSS version; jail param `linux.oss_version` |
| `compat.linux.emul_path` | `/compat/linux` | path translation root (loader tunable) |
| `compat.linux.debug` | `3` | log level for unimplemented calls and warnings; `0` silences |
| `compat.linux.default_openfiles` | `1024` | `RLIMIT_NOFILE` seen by Linux processes; `-1` for unlimited |
| `compat.linux.default_stacksize` | `8 MiB` | default stack |
| `compat.linux.dummy_rlimits` | `1` | return dummy values for Linux-only rlimits |
| `compat.linux.ignore_ip_recverr` | `1` | accept `IP_RECVERR` silently |
| `compat.linux.preserve_vstatus` | `1` | keep `VSTATUS` on ttys |
| `compat.linux.setid_allowed` | `1` | honour set-id bits on Linux executables |
| `compat.linux.map_sched_prio` | `1` | map `SCHED_OTHER` priorities (loader tunable only) |
| `compat.linux.use_real_ifnames` | `0` | show `em0` rather than `eth0` |

## Branding

The kernel identifies a Linux binary four ways, in `sys/kern/imgact_elf.c`:
a `.note.ABI-tag` section with vendor `GNU`, the `EI_OSABI` byte, the old
`compat_3_brand` string, and the interpreter path. glibc binaries carry the
note, and the three registered brands in `sys/amd64/linux/linux_sysvec.c`
match the interpreters `/lib64/ld-linux-x86-64.so.2`, `/lib64/ld-linux.so.2`
and `/lib/ld-musl-x86_64.so.1`, so ordinary distribution binaries need
nothing. A static, freestanding or oddly linked binary with no note and no
interpreter relies on `kern.elf64.fallback_brand`, or is branded once with
brandelf(1):

```sh
brandelf -t Linux ./myapp
brandelf -l                     # known brands: FreeBSD, Linux, Solaris, SVR4
```

That is what every Linuxulator test does to its payload after compiling it
with `clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static`.

## Running under the emulation

The busybox test in `tests/sys/kern/linux_busybox_test.sh` is the shape of a
real workload and a good template for your own smoke test: it runs the
applet inventory, a shell with pipes, traps and job control, a tar round trip
over 200 files verified by md5, text tools over the result, hard links and
`stat`, a `nc` client and server over loopback, `timeout`, `ps`, five hundred
fork-and-exec cycles, and a large pipe transfer. Each step is an `atf_check`
with an expected exit status and output, so a regression is a named line.

A Linux program in a jail sees the jail's `linux.osrelease`, `linux.osname`
and `linux.oss_version`; nothing else about the jail model changes, which is
the point of the next section.

## What a Linux program can and cannot reach on the plane

The enforcement model is that Linux code is policed beneath the translation
boundary. Every MAC hook fires on the native operation the Linuxulator
translates to; there is no Linux-specific hook and no seccomp, namespace or
LSM layer above. A program that would have been denied as a native process
is denied as a Linux process, and it sees `EACCES` or `EPERM` where Linux
would have given the same answer. OES labels the events it emits for such a
process with `EP_FLAG_LINUX` so an endpoint agent can tell them apart.

What a Linux program cannot do is act as a plane consumer. The per-process
lookup channel is created by a dynamically registered native syscall
(`mac_capability_channel_create` in `sys/dev/mac_capability/mac_capability_channel.c`)
that has no number in the Linux table; the switchboard bootstrap descriptor
is read with an `ENVFD_GETINFO` ioctl that the Linux ioctl dispatcher does
not know and answers with `EINVAL`; and `sys/compat/linux` contains no
reference to mac_capability at all. The wire protocol reserves a client-ABI
value for Linux (`SERVICE_CLIENT_ABI_LINUX` in libservice(3)), but no code
path sets it. So a Linux binary cannot call `service_open`, cannot receive a
delivered descriptor with its rights intact through libservice, and cannot
be given a system gate.

The supported shape is therefore a native unit that owns the plane side and
runs the Linux program as its child over ordinary descriptors: pipes, a
UNIX socket, files the unit opened through `service_open_isolated(3)` and
passed down. A native parent can also `cap_enter(2)` before executing a
Linux binary; the child then runs in capability mode and the Linuxulator
translates `ECAPMODE` to Linux `EPERM`
(`tests/sys/kern/linux_unshare_capmode.c` and its siblings prove this for
`unshare`, `ptrace` and `quotactl`). The Linux compatibility filesystems are
on the mac_capability mount whitelist, so a supervised service may assemble a
Linux jail without ambient mount privilege. Nothing in the tree runs a Linux
binary directly as a unit's `program`, and this chapter does not claim it
works.

## Debugging

GDB 16.3 is gate-passed: it starts a freestanding target, reads general,
x87 and SSE registers, changes `r12` and continues to a normal exit
(`docs/linuxulator-ptrace-debugger-options.md`). Behind that sit
`PTRACE_SEIZE`, `PTRACE_INTERRUPT` and `PTRACE_LISTEN`, `GETREGSET` and
`SETREGSET` for general, floating-point and XSAVE state, `PEEKUSER` and
`POKEUSER` including the debug registers, `PTRACE_ARCH_PRCTL`,
`GETSIGMASK`, `PEEKSIGINFO`, and fork and exec event messages, all in
`sys/compat/linux/linux_ptrace.c` and
`sys/amd64/linux/linux_ptrace_registers.c`. linprocfs provides
`/proc/<pid>/task/<tid>/` with `mem`, `maps`, `status`, `stat`, `comm`,
`auxv`, `fd/` and the rest for the process leader; it does not enumerate
non-leader threads, so full multithreaded GDB use is not claimed. strace is
not claimed either; the ptrace review documents note that event
classification and per-tracee option state still need work before it is.

The native tools are usually faster. truss(1) and kdump(1) decode arguments
and translate errnos per ABI. DTrace sees the Linux syscall provider and the
`linuxulator` SDT provider, with one caveat from the test suite: `dtrace -c`
cannot take control of a static Linux binary because libproc waits for an
rtld breakpoint, so the trace test runs a system-wide script with a `tick`
probe that calls `exit(0)` once the tracee has run. Known debugger rough edges:
GDB reports a `SIGBUS` warning in its ret-to-NX capability probe, and the
native restriction on debugging a post-setuid, pre-exec process applies to
Linux processes too.

## The QEMU gate

Anything you care about is qualified in a disposable guest, never on the
host. The acceptance contract is `docs/linuxulator-implementation-gate.md`
and its rule is unambiguous: QEMU is the correctness gate, the host only
builds artifacts and runs QEMU, and every guest image must boot from ZFS. A
UFS-root run fails the gate, because the base system is supported only on
ZFS. The runner is `tools/test/linuxulator/qemu-gate.py`:

```sh
python3 tools/test/linuxulator/qemu-gate.py \
    --amd64-image /tmp/gate/amd64.img \
    --amd64-swap-image /tmp/gate/amd64-swap.img \
    --amd64-swap-image2 /tmp/gate/amd64-swap2.img \
    --qemu-dir /path/to/qemu/bin \
    --firmware-dir /path/to/qemu/share/qemu \
    --output /tmp/gate/new-results-directory
```

Images come from `build-zfs-images.sh`; `guest-gate.sh` is staged as the
guest's `init_rc`, checks `/` and the test directory are ZFS, hashes the
kernel and modules, and emits `GATE_*` markers the host parses. The gate
requires complete named case sets (memfd, unshare, xstate, ptrace, socket
cookie, quota, OFD locks, seals, RESOLVE flags, squeue, io_uring, perf) and
fails on a missing or duplicate result, a timeout, an unclean QEMU exit, or a
recognised kernel fault string. The same portable cases are run against a
pinned Linux reference guest (Alpine 6.18.35, and 7.1.5 for newer io_uring
contracts) and an assertion is never weakened to match the emulator. The
full amd64 run takes over fifteen minutes under TCG.

For a shipped application the discipline is the same: build a guest image,
add your workload as a named case in the guest script, and treat only a
gate pass as evidence. The tree distinguishes claimed from gate-passed:
busybox, GDB 16.3, a Python 3.14 socket client and the Bun runtime are
gate-passed; Electron is explicitly not qualified (its Chromium sandbox
needs seccomp, and `--no-sandbox` is not a qualification); Docker, Steam
and systemd have never been claimed.

## Unsupported

State these before someone discovers them in production.

| Area | Status |
|---|---|
| Namespaces | none, and never planned: jails are not namespaces. `clone` and `clone3` with any `CLONE_NEW*` flag return `EINVAL`, like a Linux kernel built without them; `unshare` accepts only `CLONE_FS` for a single-threaded process; `setns`, `listns` and the new mount API are DUMMY |
| cgroups | `/proc/<pid>/cgroup` reads `0::/` and `cpuset` reads `/` so runtimes stop warning; no controller exists |
| seccomp | reject-only: `SECCOMP_GET_ACTION_AVAIL` gives `EOPNOTSUPP`, everything else `EINVAL`. A real implementation with Landlock is in progress and uncommitted |
| Keys, kexec, fanotify, bpf, uprobes, userfaultfd, `memfd_secret`, LSM attributes | DUMMY (`ENOSYS`) |
| Kernel modules from Linux | `init_module`, `finit_module`, `delete_module` are DUMMY; modules load through BSDExtension only |
| io_uring | `IORING_SETUP_IOPOLL` and `HYBRID_IOPOLL` rejected with `EINVAL` at setup; `SEND_ZC` copies and reports `ZC_COPIED`; hardware zero-copy receive and NVMe `URING_CMD` absent. Everything else is negotiated through `PROBE`, feature bits and `-EOPNOTSUPP`, never silently wrong |
| `perf_event_open` | software counters for the current thread only (task clock, faults, context switches); hardware, sampling, groups and mmap rings return an error |
| NUMA | single-domain bookkeeping: policies are validated and accepted, `move_pages` reports node 0, `FUTEX2_NUMA` is `EINVAL` |
| Quota | `quotactl` global `Q_SYNC` only; `quotactl_fd` ZFS query, byte hard limit and sync on amd64 |
| Sockets | `AF_PACKET`, `AF_ALG` and netlink families other than route, `SOCK_DIAG` and `KOBJECT_UEVENT` are not implemented |
| procfs corners | anonymous pipes cannot be reopened through `/proc/<pid>/fd`, deleted-file readlink text is lost after name-cache eviction |
| 32-bit and arm64 | i386 Linux binaries do not run; arm64 carries a larger stub set and is regated only when an arm64-specific path changes |

Two documents keep this list current: `docs/linuxulator-missing-syscalls-handoff.md`
for the 41 calls still needing work, and `docs/linuxulator-option-review.md`
for option-level gaps inside calls that otherwise exist. When your census
from the first section hits either list, the answer is there before you file
a bug.
