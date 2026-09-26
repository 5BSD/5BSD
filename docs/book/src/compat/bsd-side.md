# The BSD Side

5BSD is a fork of FreeBSD 16-CURRENT, and nearly everything a FreeBSD user or developer knows still holds: the same kernel, libc, toolchain, ports ABI, rc(8), jail(8), bhyve(8), ZFS and manual pages. This chapter is the list of what is different once you look closely. It is written for someone arriving from FreeBSD who wants to know what will break, what will look unfamiliar, and what they can rely on. The capability plane itself is covered in Parts II and III; here the subject is the base system underneath it.

## Identity

The kernel still reports itself as FreeBSD. `sys/conf/newvers.sh` keeps `TYPE="FreeBSD"` and `REVISION="16.0"`, and adds `BRAND="5BSD"`, which is what the version banner, motd and loader show. The pkg(8) ABI string is pinned to `FreeBSD:16:amd64` (`usr.sbin/pkg/config.c` registers `OSNAME` as `FreeBSD`), so binary packages from the FreeBSD ports repositories install and run unchanged. `uname -s` says `FreeBSD`; `/var/run/os-release` says otherwise:

```
NAME=5BSD
ID=5bsd
ID_LIKE=freebsd
PRETTY_NAME="5BSD 16.0-CURRENT"
HOME_URL="https://github.com/5BSD/5BSD"
```

Software that keys on `ID_LIKE` treats the system as FreeBSD; software that keys on `ID` sees 5BSD. Both are intended.

## 64-bit only

There is no 32-bit compatibility of any kind. `sys/amd64/conf/GENERIC` carries `nooptions COMPAT_FREEBSD32`, `share/mk/src.opts.mk` marks `LIB32` as a broken option (TrustedZFS capability descriptors require a 64-bit ABI; `sys/sys/zfshandle.h` refuses to compile otherwise), and i386 and armv7 are no longer universe targets. The Linux emulator loads only `linux64`: `/etc/rc.d/linux` loads the 64-bit ABI on amd64 and aarch64 alike and skips `kern.elf32.fallback_brand` because the sysctl does not exist. A 32-bit FreeBSD or Linux binary fails to exec.

## The kernel is GENERIC

GENERIC is the 5BSD kernel; there is no overlay configuration. The mac_capability plane is compiled in unconditionally through `sys/conf/files` and is never a loadable module. On top of the FreeBSD GENERIC, the following are added or changed:

| Line in GENERIC | Effect |
|---|---|
| `options HWT_HOOKS` | hardware trace hooks for hwt(4) and bsdtrace(8) |
| `options RACCT` without `RACCT_DEFAULT_TO_DISABLED` | resource accounting is on; `kern.racct.enable` defaults to 1 |
| `device vsock`, `device virtio_vsock` | the `AF_VSOCK` domain and its VirtIO transport |
| `options BHYVE_SNAPSHOT` | checkpoint and restore in bhyve(8) |
| `nooptions COMPAT_FREEBSD32` | no 32-bit binaries |
| `options OES` | OpenEndpointSecurity, oes(4) |
| `options MAC_ABAC` | the attribute-based access control policy |
| `options MAC_VERIEXEC`, `MAC_VERIEXEC_SHA256`, `device mac_veriexec_parser` | verified execution compiled in, inactive until a manifest is loaded |
| `device cryptodev` | `/dev/crypto` is static so system.Crypto can never be missing |

RACCT being on matters to anyone who tuned around it: rctl(8) rules are effective on a stock kernel, and the accounting the plane's coalitions use (see [Coalitions and Accounting](../capability/coalitions-and-accounting.md)) depends on it. A `GENERIC-DEBUG` configuration exists for INVARIANTS and WITNESS builds, and arm64 has `GENERIC-RPI`.

## Boot and rc defaults

The loader and rc(8) defaults differ from FreeBSD in a handful of lines.

| File | Setting | Why |
|---|---|---|
| `stand/defaults/loader.conf` | `init_path="/sbin/capsule:/sbin/init:/sbin/init.bak:/rescue/init"` | capsule(8) is PID 1; stock init is the fallback |
| `stand/defaults/loader.conf` | `zfs_load="YES"`, `linux64_load="YES"`, `hwt_load="YES"` | ZFS, Linux ABI and hardware trace are loaded at boot |
| `stand/defaults/loader.conf` | `splash="/boot/images/5bsd-logo.png"` | branding |
| `stand/efi/loader/main.c` | reads `/efi/5bsd/loader.env` from the ESP | install media sets `boot_policy=strict` there so the loader never falls back to a foreign boot pool |
| `libexec/rc/rc.conf` | `zfs_enable="YES"` | the storage plane needs a pool at first boot; a UFS root still boots |
| `libexec/rc/rc.conf` | `auditd_enable="YES"` | system.Audit can commit records only when auditd(8) runs |
| `libexec/rc/rc.conf` | `linux_enable="YES"` | Linux binaries run out of the box |
| `libexec/rc/rc.conf` | `osrelease_*_url` | point at the 5BSD repository |

The loader tunable `capability_plane="NO"` makes capsule exec stock `/sbin/init` and boots a plane-free system; see [Boot Knobs](../operations/boot-knobs.md). There are no `mac_capability*_load` lines: the plane is static, and only test-fixture modules are loadable.

The rc.d directory gains three scripts (`mac_abacd`, `blued`, `meshd`) and modifies four (`linux`, `routing`, `zfs`, `motd`, `os-release`). [rc and service(8)](rc-and-service.md) describes each and how switchboard runs `/etc/rc`.

## Filesystem layout and identity

Two additions to the root are visible to anyone who lists it.

The `capability` user and group, uid and gid 976, are defined in `etc/master.passwd` and `etc/group` with home `/nonexistent` and shell `/usr/sbin/nologin`. It is the identity switchboard runs units as; it is not a principal in the login policy and must not be listed there. The `runtime` package's pre- and post-install scripts create it on an upgraded root so an older system gains it without a merge step.

`/Capabilities` is in `etc/mtree/BSD.root.dist`, tagged `package=runtime`, with `Config`, `Run` (mode 0700), `State/switchboard` (mode 0700) and `System` beneath it. `/Capabilities/Run` is a tmpfs: bsdinstall's `zfsboot` script and `release/scripts/tools.subr` both write

```
tmpfs /Capabilities/Run tmpfs rw,mode=0700 0 0
```

into `/etc/fstab`. The rest of the tree (`Apps`, `Data`, `Users`) is created by switchboard and the providers at run time. hier(7) documents the layout; [Containers and Storage](../plane/containers-and-storage.md) explains what lives where.

The EFI system partition uses `/efi/5bsd/` rather than `/efi/freebsd/`.

## Native API changes

Most of the kernel work that landed for Linux emulation was done in the native subsystems rather than in `sys/compat/linux`, so a native program can use it too. The table lists the changes a FreeBSD developer will notice; each is documented in the manual page named.

| Change | Where | What to know |
|---|---|---|
| Open file description locks | fcntl(2) `F_OFD_GETLK`, `F_OFD_SETLK`, `F_OFD_SETLKW` | owner is the open file description; input `l_pid` must be 0; a conflicting OFD lock reports `l_pid` of -1; no `EDEADLK`; supported where the filesystem sets `VFCF_OFDLOCKS` (UFS, ZFS, tmpfs, fusefs), `EOPNOTSUPP` elsewhere |
| Sealing | fcntl(2) `F_SEAL_FUTURE_WRITE` | memfd seal parity with Linux |
| inotify open-path identity | inotify(2) | a file opened by a Linux-ABI process records (directory, name); events through that description report under that name only; native opens are attributed through the name cache; `IN_EXCL_UNLINK` supported; `vfs.inotify.*` sysctls expose limits and counters |
| Peer credentials | unix(4) `struct sockcred2` | gains `sc_capmode` (sender in capability mode); `SOCKCRED2_VERSION` is 1 |
| Capability-mode attestation on UNIX sockets | unix(4) `LOCAL_CAP_CONNECT`, `LOCAL_CAPMODE_SERVER`, `LOCAL_CAP_REQ`, `SO_PEERCAPMODE` | a peer can require that the other side is sandboxed |
| Abstract UNIX names | `sys/kern/uipc_usrreq.c` | exist only for sockets created by a Linux-ABI process (`UNP_LINUX_ABSTRACT`); native sockets keep path semantics |
| `AF_VSOCK` | vsock(4), `<sys/socket.h>` | `AF_VSOCK` is 46; `AF_IPFWLOG` and `AF_MAX` moved to 48; recompile anything that sized arrays by `AF_MAX` |
| Capability-required syscalls | `<sys/sysent.h>` `SYF_CAPREQUIRED` | a syscall so flagged (pdself(2)) returns `ENOTCAPABLE` when the caller is not in capability mode |
| New Capsicum rights | rights(4) | `CAP_JAIL_ATTACH`, `CAP_JAIL_REMOVE`, `CAP_JAIL_SET`, `CAP_TIMERFD_GETTIME`, `CAP_TIMERFD_SETTIME`, `CAP_FCNTL_READAHEAD`, `CAP_POSIX_FADVISE`, `CAP_ACL_*`; an existing sandbox that used these operations must add the rights |
| Process descriptors | pdfork(2) | pdkill(2) and pdwait do not perform credential, jail or MAC checks; new `EVFILT_PROCDESC` notes (`NOTE_CAPMODE`, `NOTE_JAILED`, `NOTE_SETUID`, `NOTE_CHROOT`, `NOTE_FORK`, `NOTE_EXEC`); pdself(2), pdcmp(2) |
| Descriptor transfer state | cap_xfer_limit(2), cap_cloexec_limit(2), cap_mmap_capmode(2) | per-descriptor limits on how often an fd may be passed, inherited or mapped |
| Dynamic executables in capability mode | `kern.elf64.capmode_interp` (default 1) | fexecve(2) of a dynamically linked binary is allowed in capability mode when the brand's interpreter is used |
| Descriptor-backed environment | envfd(2), kqueue(2) `EVFILT_ENVFD` | environment values delivered as descriptors; `kern.envfd.*` sysctls |
| Sized free | `free_sized(3)`, `free_aligned_sized(3)` | C23 wrappers in libc |
| Shutdown | reboot(8), shutdown(8) | request an ordered shutdown through capsulectl(8) and fall back to the classic signal path if the plane is unavailable |
| Audit | audit_kevents.h | 29 new `AUE_*` events, `BSM_PF_VSOCK` |

Sandboxed programs should test under the new rights before assuming an old rights mask still works: the enforcement of `CAP_ACL_*`, `CAP_POSIX_FADVISE` and `CAP_FCNTL_READAHEAD` is new.

## Kernel KPI changes for out-of-tree modules

A module built against FreeBSD headers will not load; these are the interfaces whose shape changed.

| Interface | Change |
|---|---|
| `vop_spare1` in `sys/kern/vnode_if.src` | consumed by `VOP_FILECLOSE(vp, fp, last, td)`, the per-open-description close hook used by fusefs; `vop_spare2` through `vop_spare5` remain |
| `struct vfsops` | gains `vfs_quota_t *vfs_quota` (kernel-buffer quota interface); `vfs_spare` shrinks from 6 to 5 entries |
| `fdcopy()` | `fdcopy(struct filedesc *, struct proc *, bool isfork)` |
| `fdcloseexec()` | `fdcloseexec(struct thread *, struct ucred *newcred)` |
| `fget_mmap()` | new: fetch a file for mmap with the descriptor's `UF_MMAP_CAPMODE` state checked |
| pseudofs | `MODULE_VERSION(pseudofs, 3)`; new node flags `PFS_MAGICLINK`, `PFS_TIDNAME`, `PFS_FDNAME`; a pseudofs consumer must depend on version 3 |
| sdhci | `SDHCI_VERSION` is 3; `SDHCI_PLATFORM_SET_POWER` added |
| MAC policy ops | `mac_policy.h` grew by 65 members (61 net-new hooks) and `MAC_MAX_SLOTS` rose from 4 to 7; a policy module must be rebuilt |
| syscall dispatch | `mac_proc_check_syscall` runs on every dispatch; a policy can veto by syscall number |
| kinfo_proc | `ki_paddr` is set to NULL when `mac_system_check_kas_info` denies the caller, so kernel addresses are hidden from unprivileged ps(1) and procstat(1) users |

The `kern_*_gated()` entry points (`kern_jail_set_gated`, `kern_kldload_gated`, `kern_settime_gated` and friends) exist for the plane's gate daemons and replace `priv_check` with a held capability; they are documented in [System Gates](../capability/system-gates.md).

## Hardening defaults

Three things were taken from HardenedBSD, deliberately few. `BIND_NOW` is on by default in `share/mk/bsd.opts.mk`, so every binary is linked with `DF_BIND_NOW` and gets full RELRO; `WITHOUT_BIND_NOW` in src.conf(5) turns it off. jail(8) allocates its configuration strings with `calloc` and `recallocarray` instead of `malloc` and `realloc` (`usr.sbin/jail/config.c`, `jail.c`), and `usr.sbin/jail/tests/jail_config_test.sh` grows strings across allocation size classes to prove it. Three defensive driver and tool fixes (logger(1) hostname buffer, qlnxe allocation, mrsas DCMD leak) came with them. PaX, ASLR hardening, SEGVGUARD and TPE were not imported; `docs/book/src/compat/bsd-side.md` records the triage.

## Tools that learned new descriptor types

fstat(1), procstat(1) and sockstat(1) know the new descriptor types. procstat(1) marks a mac_capability channel with type letter `M`, a crypto descriptor with `C`, an envfd with `N`, and sockstat(1) `-V` lists `AF_VSOCK` sockets. truss(1) and kdump(1) decode the new system calls. libprocstat exposes `PS_FST_TYPE_MAC_CAPABILITY`, `PS_FST_TYPE_CRYPTO`, `PS_FST_TYPE_ENVFD`, `PS_FST_TYPE_ZFSHANDLE` and `PS_FST_TYPE_SQUEUE` for programs that walk descriptor tables.

## What does not change

UFS, ZFS, jails, bhyve, pf, ipfw, the toolchain, ports, the FreeBSD Handbook's instructions for networking, storage and users all apply. `service(8)`, `sysrc(8)` and every rc.d script not listed above are byte-identical to FreeBSD. A FreeBSD ports package installs with `pkg install` from the FreeBSD repositories, because the ABI it was built for is the ABI 5BSD reports. What 5BSD adds sits beside these, and the rest of Part V explains where the two meet: [rc](rc-and-service.md), [sessions](sessions.md), [jails](jails.md), [packages](packages.md), [virtual machines](virtual-machines.md) and [Linux emulation](linux/overview.md).

## Status

Everything above is committed on `dev`. src.conf(5) still lists i386 and armv7 defaults that the build no longer honours. The Linux seccomp and Landlock work is in progress and uncommitted; nothing here depends on it.
