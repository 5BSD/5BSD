# The Linuxulator

5BSD's central bet is that the Linux syscall interface is a first-class
target, not a compatibility afterthought. The Linuxulator — the kernel's
Linux syscall translation layer in `sys/compat/linux/` with per-architecture
tables in `sys/amd64/linux/` (plus `linux32`, `i386`, and `arm64`) — turns
Linux syscalls into native BSD kernel operations *before* they execute, which
is what lets the entire BSD security stack (MACF, Capsicum, mac_capability,
capprotect, vnode_claim, coalitions) police Linux binaries that never know
it exists.

Unlike stock FreeBSD, 5BSD ships with the Linuxulator enabled at boot:
`stand/defaults/loader.conf` loads `linux_common.ko` and `linux64.ko`, and
`libexec/rc/rc.conf` defaults `linux_enable="YES"` and
`linux_mounts_enable="YES"` so Linux jails work out of the box (commit
`1db4be148f6`).

## The ABI target: RHEL/Rocky

5BSD does not chase every Linux distribution. The Linuxulator is developed
and tested against the RHEL/Rocky userland — glibc and the RHEL ABI surface —
because Rocky mirrors the library/ABI set that regulated and enterprise
environments actually certify against. A **Rocky Linux 9** userland — an
official Rocky minimal container base unpacked into a jail root — is the
reference target: RHEL-compatible software runs against it unmodified.

The kernel version the Linuxulator reports defaults to 5.15.0
(`LINUX_VERSION_STR` from `LINUX_KVERSION`/`LINUX_KPATCHLEVEL`/`LINUX_KSUBLEVEL`
in `sys/compat/linux/linux_mib.h`), which satisfies the glibc floor checks in
the RHEL 9 generation of userlands.

## Syscall coverage status

The coverage baseline was established by auditing the Linux v7.1-rc1 syscall
table (`arch/x86/entry/syscalls/syscall_64.tbl`, 472 entries) against the
tree: the Linuxulator has table entries for roughly 350 syscall numbers, of
which about 80 were DUMMY stubs returning `ENOSYS`, leaving roughly 270 truly
functional (commit `bdca0dddcdc`, recorded in the `5BSD.md` roadmap of that
era). On top of upstream's basics — `clone3`, `close_range`, `statx`,
`epoll_pwait2`, `memfd_create`, `copy_file_range`, `getrandom` — 5BSD has
implemented ten previously-stubbed syscalls, each verified against the Linux
kernel source and wired into all four architecture tables:

| Syscall (amd64 #) | Implementation |
|---|---|
| `membarrier` (324) | direct call to `kern_membarrier()`; unsupported RSEQ/per-CPU features reported honestly via `CMD_QUERY` |
| `vhangup` (153) | `PRIV_TTY_STI` check, then `VOP_REVOKE` on the session's controlling tty vnode |
| `readahead` (187) | `kern_posix_fadvise(POSIX_FADV_WILLNEED)` |
| `preadv2` (327), `pwritev2` (328) | `kern_preadv`/`kern_pwritev` with `pos=-1` routing to `kern_readv`/`kern_writev`; non-zero RWF flags return `EOPNOTSUPP` like Linux filesystems |
| `process_vm_readv` (310), `process_vm_writev` (311) | `proc_rwmem()` gated by `pget(PGET_CANDEBUG)`; `EACCES` mapped to `EPERM` per Linux convention |
| `init_module` (175), `delete_module` (176), `finit_module` (313) | return `EPERM`, matching Linux for unprivileged callers |

The implementations live mainly in `sys/compat/linux/linux_misc.c`; the
generated tables (`linux_proto.h`, `linux_sysent.c`, `linux_systrace_args.c`,
`syscalls.master`) were regenerated per architecture. Two follow-up commits
corrected ABI details: `c15e162e5ea` fixed the `readahead` and `membarrier`
signatures against the actual Linux ABI (dropping the later-kernel `cpu_id`
parameter), and `14c53e28647` fixed the `membarrier` build for the same
reason.

## Roadmap

The detailed roadmap — written from reading the Linux kernel source, not
estimates — was recorded in `5BSD.md` at commit `bdca0dddcdc` and later
trimmed from the working tree (`cbd47d0a463`, "detailed implementation notes
live in commit history"). Ordered by feasibility, the open steps are:

1. `pidfd_send_signal` — thin wrapper over FreeBSD's `pdkill(2)` (systemd ≥ 243 targeted signal delivery)
2. `signalfd4` — `EVFILT_SIGNAL` plus a new file type (the systemd sd-event loop; the single biggest remaining blocker in that tier)
3. `pidfd_open` — extend the procdesc layer (reliable process tracking)
4. `futex_waitv` and the futex2 family (452–455) — multi-wait on umtxq (Wine/Proton `WaitForMultipleObjects`, newer glibc/Rust locking)
5. `pidfd_getfd` — cross-process fd extraction
6. `unshare`/`setns` — partial namespace support (large)
7. `io_uring` — a new subsystem (very large; 26K lines in Linux)
8. `userfaultfd` — user-space page fault handling (CRIU checkpoint/restore, QEMU postcopy migration)

**Status.** All eight items are designed (with primitive mappings and Linux
reference line counts) but not built; the tree's implemented set is the ten
syscalls above plus the pre-existing ~270 functional entries.

## MACF interposition on translated syscalls

The Linuxulator gives 5BSD its security leverage for free. A Linux binary
calls `clone()`, `open()`, `mmap()`, `sendmsg()`; the translation layer
converts each into native operations — `fork1()`, `VOP_*`, `sosend()` — and
the MAC framework's hooks fire on those native paths. There are no separate
"Linux hooks" to maintain and nothing a Linux process can do to route around
them:

```text
Linux program ── Linux syscall ──> sys/compat/linux/ (translation)
                                        |
                                        v
                              native FreeBSD operation
                                        |
                              MACF hooks (38+ beyond stock)
                              Capsicum / vnode_claim / capprotect
                                        |
                                        v
                                   BSD kernel
```

Denials surface to the Linux program as ordinary `EACCES`/`EPERM` — errors
it already knows how to handle, from a layer it cannot see. The new
implementations follow the same discipline: `process_vm_readv/writev` pass
through `pget(PGET_CANDEBUG)` (and hence the MAC ptrace/debug policy) and
`vhangup` goes through the kernel `priv(9)` check, so capprotect shields and
MAC policies constrain Linux debugging and tty revocation exactly as they do
native code.

Filesystem support for Linux environments is also capability-mediated:
commit `46a88e468cf` added `linprocfs`, `linsysfs`, and `fusefs` to the
mac_capability mount whitelist and an `fsopts` field for fs-specific options
(e.g. `fdescfs` `linrdlnk` for Linux-compatible readlink, `tmpfs`
`size=128M,mode=1777` for `/dev/shm`) so Linux compatibility jails can be
assembled by supervised services without ambient mount privilege.

## Operator configuration

- **Modules:** `linux_common.ko` and `linux64.ko` load from
  `stand/defaults/loader.conf`; 64-bit Linux only — the 32-bit `linux.ko`
  module is not loaded by default.
- **rc:** `linux_enable="YES"` and `linux_mounts_enable="YES"` are the
  5BSD defaults in `libexec/rc/rc.conf`; the latter mounts the
  Linux-specific filesystems (`linprocfs`, `linsysfs`, etc.) under the
  emulation root.
- **Sysctls** (`sys/compat/linux/linux_mib.c`): `compat.linux.osrelease`
  (per-prison writable; defaults to 5.15.0) controls the kernel version
  reported to Linux binaries — glibc refuses to run if it is too low.
  Others include `compat.linux.debug`, `compat.linux.default_openfiles`,
  `compat.linux.default_stacksize`, `compat.linux.dummy_rlimits`,
  `compat.linux.ignore_ip_recverr`, `compat.linux.preserve_vstatus`,
  `compat.linux.map_sched_prio`, and `compat.linux.setid_allowed`.
- **Rootfs:** the supported Linux userland is a Rocky 9 root — an official
  Rocky minimal container base unpacked into the jail's emulation root by the
  operator.
