# DescriptorQueue (dq)

Status: design, revision 4 (2026-11-06). Not yet implemented. Revisions 1-3
were withdrawn after independent review; section 20 records every decision
and its source, section 19 every alternative. Sections marked *decision*
carry an entry in section 20; *open* names an item in section 21. Line
references are to the `proxy/objects` branch at the time of writing.

## 1. Purpose and principles

A DescriptorQueue lets one process, the **controller**, hand another
process, the **requester**, a descriptor the controller serves. To the
requester the descriptor is the one it asked for — a regular file, a
directory, a TCP socket — and every operation on it (`read`, `write`,
`mmap`, `sendfile`, `fstat`, `fstatfs`, `F_KINFO`, `realpath`, `ioctl`,
`flock`, `kqueue`, `getpeername`, reopening through `/dev/fd`, resolving
names relative to it, executing it) becomes a message on the controller's
queue, answered by the controller. The controller may deny, substitute,
invent, delay or revoke.

This is how 5BSD removes ambient authority from programs not written for
the capability plane: the program still calls `open("/etc/passwd")` and
`connect()`, and gets objects the plane controls. OES
([Endpoint Security](oes.md)) observes and vetoes; the DescriptorQueue
*substitutes*.

### Principles

1. **The action is on the descriptor.** A served file is a `struct file`
   whose `fileops` are the queue's; a served socket is a `struct socket`
   whose `protosw` is the queue's. No vnode, mount or filesystem stands
   behind a served object or represents one anywhere — not for the working
   directory, not for the root. Where the kernel today reaches past a
   descriptor to a vnode, the kernel is changed so it does not (sections
   4 and 6); that change stands on its own and lands first.
2. **Transparency to the requester is required; performance is not.**
   The kernel caches only what the controller permits.
3. **Fail closed.** When a controller goes away, everything it served stops
   answering; nothing falls through to a real object; the kernel never
   invents an answer. I10 lists the exceptions physics imposes and nothing
   else is excepted.
4. **Observers are not fooled.** Transparency is owed to the requester.
   The plane's policy modules and audit see every served operation, marked
   as served, from the first stage that serves anything; they see metadata,
   not the requester's data, unless explicitly granted.
5. **Existing software is unchanged.** A program not under an attachment
   sees no difference in behaviour, errno or timing from any part of this
   work (section 5).
6. **Attachment is a namespace substitution, not a sandbox boundary**
   (11.6). It decides what names and sockets mean to a process; it does
   not remove the process's other global namespaces. The agent consumer
   pairs it with a jail and a plane rule.

### Non-goals

- Not a filesystem, not FUSE (section 19).
- No user-visible descriptor type: kinfo and `fstat` report the presented
  kind. The internal `DTYPE_DQ` exists so each remaining
  `f_type == DTYPE_VNODE` test fails safe and so they can be counted.
- Not an ABI emulation layer: no per-process syscall table. The kernel's
  own enforcement (Capsicum, audit, MAC) runs before the controller is
  consulted; a syscall table would run before it.

## 2. Terms

| Term | Meaning |
|---|---|
| controller | process holding a queue; mints objects, answers operations |
| queue | one open of `/dev/dq`: a stream of events plus the ioctls that answer them |
| object | one served descriptor: a `struct file` with dq fileops, or a `struct socket` with the dq protosw. One object is one open; `dup`, `fork`, `SCM_RIGHTS` share it |
| requester | a process holding an object or running under an attachment; never learns which |
| attachment | a controller bound to a process's `pwddesc` as its resolver; inherited by everything the process creates (section 11) |
| virtual namespace | the working directory and root a requester believes it has, held in the attachment as references to served directory objects |
| user-origin lookup | a name resolution or socket creation requested by a system call of the requester itself, marked `NI_DQ_FD_OK`; everything else is kernel-origin |
| presented identity | what the kernel reports for an object: `st_dev/ino/gen`, mode, owner, size, times, path, `statfs`/`pathconf` fields; or domain, type, protocol, local and peer addresses |
| event / reply / push | kernel→controller operation with an id; the controller's answer; unsolicited controller→kernel message |

## 3. Invariants

Enforced by the kernel, not by controller policy. Each has tests (section
17) and a decision (section 20).

| # | Invariant |
|---|---|
| I1 | A controller acts only on objects minted on its own queue. |
| I2 | A served object conveys no authority over any real object. Presenting an identity is not holding it. |
| I3 | **No credential or authority change from anything served.** `MINT`/`SETIDENT` reject `S_ISUID`/`S_ISGID`; a served image never matches pinned software authority and never becomes an attributed image. |
| I4 | **Exec is a new principal.** The identity nonce rotates on every exec, served or real: the core calls `is_mac(RELABEL)` for either backend where `mac_vnode_execve_relabel` runs today (`kern_exec.c:1028-1040`), and mac_capability's `execve_relabel` hook — implemented for both the vnode and the `mac_file_*` entry points — does the rotation (D77). Nothing moves into the core. |
| I5 | **An attached process cannot gain credential, authority or namespace by any kernel path while attached — and nothing detaches it.** (Userland elevation paths such as BSDAuth are refused where they land in `proc_set_cred`; beyond that they are the plane rule of 11.6 step 4.) (a) exec: `imgp->credential_setid` is forced false, as the kernel already does for `P_TRACED` and capability mode (`kern_exec.c:717-723`); `authority_setid` is forced false; an image for which `mac_vnode_execve_will_transition` is true is refused `EACCES` between `kern_exec.c:710` and `:800`, before `exec_new_vmspace`, so the old image continues (`will_relabel` is not part of the predicate: `mac_capability` relabels every exec); the `#!` loop re-evaluates per interpreter. (b) non-exec: `setcred(2)`, `NODE_OP_SET_CRED`, BSDAuth elevation and `jail_attach(2)` targeting an attached process are refused `EPERM`; the `setuid` family keeps today's rules (an unprivileged member cannot raise). (c) attachment does **not** reduce privilege a process already had. |
| I6 | **Served objects flow only inside the attachment.** A served fd may be installed in a process only if that process is attached to the object's queue, or is the minting controller: enforced at `SCM_RIGHTS` externalize, at `mac_capability` channel-message and `CALL`-reply fd installation (`mac_capability_dev.c:867-888`, `:1558-1636`), and at `MINT`. Until stage 1c exists, minted fds are `CAP_XFER_NONE` and leave the controller only by inheritance (test-only delivery). |
| I7 | **Kernel-origin lookups never receive a served object.** Only a lookup whose `NDINIT` carries `NI_DQ_FD_OK` — set by the user-origin syscall entry (`kern_openat`, `do_execve` for `args->fname`, the `*at` family, the Linux wrappers) and never by `__elfN(load_interp_file)`, `linker_load_file`, coredump, ktrace, acct, firmware, nfsd — may receive `FD`; others receive `PASS` or errno. Kernel-origin `socreate` callers are never consulted and get real sockets. |
| I8 | **Capsicum is enforced by the kernel on what the controller returns.** Rights, `CAP_LOOKUP`, `UF_LOOKUP_CAPMODE` and `ENOTCAPABLE` for `..`/absolute are decided before any event is posted; a `RESOLVE FD` is installed with rights = start-dirfd caps ∩ `dp_rights` (ioctl and fcntl limits likewise), as `openat` does with `ni_filecaps` (`vfs_syscalls.c:1199-1207`); under `BENEATH`, `STRICTREL` or `RINROOT` the returned normalized `di_path` must extend the start's normalized `di_path` at a component boundary, else `ENOTCAPABLE`. Guarantee, stated honestly: the controller cannot be made to return an object *it labels* as outside the start; the kernel cannot verify bytes. |
| I9 | **Every served operation is observable as served**, through the `mac_file_*` hooks and OES events carrying the controller nonce and object id; observation is a capability, not a uid; observers see metadata unless granted data. |
| I10 | **Fail closed on revoke and queue close.** Operations fail `EIO`/`ECONNRESET`; cached pages are unmapped and dropped (`vm_object_page_remove` with `pmap_remove_all`); delivered-but-unread socket data is flushed (`sbflush`); waiters wake with an error; pending async page operations complete with error; knotes are cleared. Excepted and documented: bytes already copied into the requester's memory, including `MAP_PRIVATE` copy-on-write pages; pages already queued by `sendfile` into a socket buffer; I/O already handed to hardware. |
| I11 | **The kernel never waits on a controller where it cannot be interrupted or must not sleep**: not under `exit1`, `fo_close`, `pgo_dealloc`, the page daemon or laundry, `vm_object_terminate`. Those post and continue; the queue owns the result. |
| I12 | A waiting requester is bounded: signals interrupt syscall waits (`PCATCH`); page-fault waits break only on `SIGKILL`, `P_WEXIT` or the deadline (an interrupted fault would be `SIGBUS`, `vm_fault.c:1491-1505`); `SIGKILL` and `P_WEXIT` always break every wait (dq tests them in its own sleep loop; `cursig` ignores `P_WEXIT`); the deadline (`kern.dq.default_deadline_ms`, 30000, per-object override, `0` = none, explicit) turns a wait into `EIO`. |
| I13 | Nothing about a served object is stored in a vnode, `struct pwd`, the namecache, a mount, or `f_flag`. |

## 4. Where the kernel changes

### 4.1 Stage 0 — descriptor completeness (lands on `dev` first)

| File | Change |
|---|---|
| `sys/sys/file.h` | 11 new `fileops` members after `fo_fork`: `fo_pathconf`, `fo_statfs`, `fo_fsync`, `fo_setattr`, `fo_fadvise`, `fo_readdir`, `fo_copy_file_range`, `fo_acl`, `fo_extattr`, `fo_fcntl`, `fo_advlock`; `fo_spares[4]` kept, so `struct fileops` grows (the spare slots were fewer than the members; every table in the tree is initialised by designator and recompiled with the kernel, so the growth is a KBI change and nothing else — D72); the `fo_*` inline dispatchers fall back to `invfo_*` for a NULL member, so out-of-tree tables keep working; `DTYPE_DQ` reserved |
| `sys/kern/vfs_vnops.c` | the vnode implementations (`vn_advlock`, `vn_fsync`, …) built from the bodies moved out of the syscalls, each inside `vn_file_context_enter/leave` exactly as the per-open fileops are today; installed in `vnops`, `vn_openfileops`, and explicitly in the vnode-carrying tables of 6.1.1; `invfo_*` defaults only for types with no vnode |
| `sys/kern/sys_pipe.c` (`pipeops`), `sys/kern/tty_pts.c` (`ptsdev_ops`), `sys/fs/devfs/devfs_vnops.c` (`devfs_ops_f`, `devfs_ops_nonpassable_f`), `sys/compat/linuxkpi/common/src/linux_compat.c` (`linuxfileops`) | the new members installed per 6.1.1 so today's behaviour on FIFOs, ptys, ttys and DRM fds is unchanged. `pipeops` serves both pipes and FIFOs and branches on `PIPE_TYPE_NAMED` (`pipe_pathconf`, `pipe_statfs`, …, `pipe_advlock` which admits `F_FLOCK` only); `ptsdev_ops` and `linuxfileops` are *sometimes-vnode* tables — a master from `posix_openpt(2)` or a linuxkpi file from `fd_install()` carries no vnode, one opened through `/dev/ptmx` or a devfs node does — so they install the `vn_*_opt` variants, which delegate to the vnode when present and to `invfo_*` otherwise (found by a plane-on VM panic in `fpathconf_test:pts_master`, D72); `fifo_vnops.c` is untouched, FIFOs having no table of their own |
| `sys/kern/kern_descrip.c` | `F_SETLK*`/`F_GETLK*`/`flock`/`closef`/`fdclearlocks` call `fo_advlock`; the race-with-close recheck (`:915-947`), `P_ADVLOCK`, `FHASLOCK`/`FHASOFDLOCK`, the `l_pid` half of `fcntl_ofd_check`, `FREAD`/`FWRITE` and `SEEK_CUR` handling stay in the syscall, the `VFCF_OFDLOCKS` half moves into `vn_advlock` (it needs the vnode lock); `flock(2)` and the close paths probe `fo_advlock == NULL` for the old `EOPNOTSUPP`/skip, `fcntl(2)` lets `invfo_advlock` answer `EBADF`; `fpathconf` → `fo_pathconf`; `F_READAHEAD`/`F_RDAHEAD` → `fo_fcntl` (not `fo_fadvise`: read-ahead sets per-open state, `f_seqcount`/`FRDAHEAD`, not advice on a range — D72); `F_ISUNIONSTACK` → `fo_fcntl` (D64); `mac_file_check_fcntl` call; `path_fileops` gain the members listed in 6.1.1 so today's `O_PATH` behaviour is kept, and omit `fo_advlock`/`fo_fadvise`/`fo_readdir`/`fo_copy_file_range`, which `O_PATH` never answered |
| `sys/kern/vfs_syscalls.c` | `fstatfs`, `fchflags`, `futimes`, `futimens`, `fsync`, `fdatasync`, `posix_fadvise`, `copy_file_range`, `getdirentries` call the fileops; audit, `mac_mount_check_stat`, `vn_start_write`, `ERELOOKUP` retry and the union-mount `f_vnode` rewrite stay (the fileop takes `struct file *` and may update it) |
| `sys/kern/vfs_acl.c`, `vfs_extattr.c` | `_fd` variants call `fo_acl`/`fo_extattr` |
| `sys/kern/vfs_aio.c` | `LIO_SYNC` through `fo_fsync` |
| `sys/compat/linux/linux_file.c`, `linux_xattr.c`, `linux_stats.c` | the same calls through the same fileops (`linux_quota.c` is not converted: `quotactl_fd` needs a mount, 6.1) |
| `sys/vm/vm_mmap.c:470` | private-mapping write promotion keyed on `DFLAG_PRIVWRITE`, not `f_type` (the allowance is `PROT_WRITE` on a private mapping of a descriptor lacking `CAP_MMAP_W` — D74); `vm_mmap_file` refuses `prot ⊄ maxprot` with `EACCES` for every caller (a KASSERT was reachable from shm — D74) |
| `sys/security/mac/mac_framework.h`, `mac_policy.h`, `mac_system.c` | `mac_file_check_fcntl`, `_lock`, `_read`, `_write`, `_stat`, `_setattr`, `_fsync` (D76, built); `mac_file_check_exec` and `mac_file_execve_relabel` are defined in stage 3 with the dq image backend, their only caller — a hook without a caller is not added |
| `sys/dev/mac_capability/mac_capability_dev.c` | `mac_file_check_receive` on channel-message and `CALL`-reply fd installation (I6) |
| `sys/kern/kern_exec.c`, `imgact_elf.c`, `imgact_shell.c` | image-source abstraction with the vnode backend as moved code; `p_image` beside `p_textvp`; `NI_DQ_FD_OK` on `args->fname` only, never in `__elfN(load_interp_file)`; the two `p_textvp == NULL` kernel-process tests (`vm_map.c:5148`, `vfs_aio.c:1200`) → `P_KPROC` (done, D72 series); the contract as refined in 6.2.1/6.2.2 (D75, D77) |
| `sys/kern/kern_sendfile.c` | `sendfile_getobj` fills a `struct sendfile_src {ss_ops, ss_obj, ss_size, ss_vp, ss_shmfd}` whose ops are `lock`/`unlock` (pin the source for a chunk), `getsize` (NULL: fixed), `accessed`, `release`; the vnode and shm arms are today's two, the dq arm is stage 1b (D74) |
| `sys/vm/vm_object.c`, `vm_pager.h`, `vnode_pager.c`, `device_pager.c` | `pgo_sync(object, offset, size, syncio, invalidate)` entered and left with the object write-locked after the backing-chain walk (`vnode_pager_sync` and `dev_pager_sync` are the moved bodies, `vm.old_msync` moves with the former, no method means nothing to write back); `pgo_kinfo(object, struct vm_object_kinfo *, td)` on a referenced unlocked object through `vm_object_kinfo_hold` (never anonymous or dying objects) / `vm_object_kinfo` / `vm_object_kinfo_release`, used by `kern_proc_vmmap_out`, linprocfs maps and `vm.objects`; two observer changes: linprocfs names device mappings by cdev path, `vm.objects` withholds cdev paths from jails (D74) |
| `docs/descriptor-completeness-ledger.md`, `share/man/man9/file.9`, `docs/macf-new-hooks.md`, `docs/descriptor-addressing-ledger.md` | documentation |

Not changed in stage 0, by decision: `kern_lockf.c` (D14), `struct pwd`
(D9), `uipc_socket.c` (stage 2).

### 4.2 Stage 1 — queue, files, pages, resolution

| File | Change |
|---|---|
| `sys/dev/dq/dq.h` | installed ABI |
| `sys/dev/dq/dq_dev.c`, `dq_queue.c` | `/dev/dq`, queues, events, replies, deadlines, interrupt, stats, observer queues |
| `sys/dev/dq/dq_file.c` | dq fileops |
| `sys/dev/dq/dq_pager.c` | the dq pager type (section 10) |
| `sys/dev/dq/dq_resolve.c` | the attachment and the choke points' callee (section 11) |
| `sys/security/mac_dq/` | the dq MAC policy: `mac_file_check_receive`/`_inherit` for I6; `mac_cred_check_setcred`, `mac_prison_check_attach` refusals for I5(b); marks served objects for OES |
| `sys/kern/kern_descrip.c` (`pdinit`, `pdcopy`, `pdshare`, `pdunshare`, `pddrop`, `:2714-3241`) | attachment inherited and released exactly where `pd_pwd` is (D38) |
| `sys/sys/filedesc.h` (`struct pwddesc`) | `pd_dqres` |
| `sys/kern/vfs_lookup.c` (`namei_setup`, `namei_handle_root`), `kern_descrip.c` (`fgetvp_lookup`), `vfs_cache.c` (`cache_can_fplookup`, `vn_getcwd`) | the choke points (D39) |
| `sys/kern/vfs_syscalls.c` (`chdir`, `fchdir`, `chroot`, `fchroot`), `mac_capability_capprotect.c` (`CP_OP_CHROOT`), `kern_jail.c` (`jail_attach`) | virtual cwd/root; `jail_attach` refused when attached |
| `sys/kern/uipc_socket.c` (`socreate`), `uipc_syscalls.c` (`socketpair`) | `RESOLVE op=SOCKET/SOCKETPAIR` (D40) |
| `sys/kern/kern_exec.c` | I5(a) evaluated between `:710` and `:800`; `P2_DQ_EXECED` |
| `sys/dev/mac_capability/mac_capability_dev.c` | caller trailer carries `attached` (11.6) |
| `sys/dev/dq/dq_file.c` (`fo_flags`), `mac_vfs.c` (`mac_vnode_prepare_mmap`, `mac_mmap_image_close`) | dq fileops carry `DFLAG_PRIVWRITE` (the `vm_mmap.c:470` test is flag-based since stage 0, D65); NULL-vnode no-op in the two MAC helpers |
| `sys/security/oes/*` | file-level events, presented flag, controller nonce and object id, `NOTIFY_DQ_REPLY` |
| `sys/dev/mac_capability/mac_capability_isolation.c`, `sys/security/mac_abac/*` | implement the `mac_file_*` hooks for `DTYPE_DQ` files |
| `sys/fs/fdescfs/fdesc_vnops.c` | `readlink` via `fo_fill_kinfo`; `/dev/fd/N/child` on a served `N` is `ENOTDIR` (documented) |
| `sys/compat/linprocfs/linprocfs.c` | fd links via `fo_fill_kinfo`, maps via `pgo_kinfo` |
| `lib/libdq`, `tests/sys/dq`, `share/examples/dq/dqlaunch.c`, `dq.4`, `libdq.3`, this chapter, `docs/5bsd-inventory.md` | userland and documentation |

### 4.3 Stage 2 — sockets

`sys/kern/uipc_socket.c` (`socreate_proto`, `SO_SPLICE`, listen-overflow
log), `sys/sys/protosw.h` (`PR_OPAQUEPCB` = 0x200), `sys/kern/sys_socket.c`
(`'i'`/`'r'` ioctl groups), `sys/kern/uipc_ktls.c`, `sys/kern/kern_sendfile.c`
(mapped mbufs), `sys/security/mac_portacl/mac_portacl.c`,
`sys/security/audit/audit_arg.c`, `sys/compat/linux/linux_socket.c`,
`sys/dev/mac_capability/mac_capability_isolation.c` (`fi_net_check`),
`sys/dev/dq/dq_sock.c`, `usr.bin/sockstat`.

### 4.4 Stage 3 — exec from a descriptor

`sys/dev/dq/dq_exec.c` (the dq image backend),
`sys/dev/mac_capability/mac_capability_label.c` and
`mac_capability_authority.c` (nonce rotation through the image-level hook;
authority never matches a served image), `sys/security/mac_veriexec/*`
(served images denied under enforcement), the `p_textvp` consumers
audited in stage 0 (section 13).

### 4.5 Stage 4 — global attachment

`sys/kern/kern_exec.c` (attach decision, 11.5), `sys/security/oes/*`
(`OES_EVENT_AUTH_ATTACH`), `usr.sbin/BSDDescriptorQueue`.

## 5. How existing software behaves

- **Programs not under an attachment**: no change. Stage 0 moves code
  behind fileops without altering the vnode path's checks, lock order,
  audit or errno; the existing kyua suite is the oracle, run plane-on
  before and after, plus the 6.1.1 test row for FIFOs, ptys, ttys, DRM
  and `O_PATH` fds. The complete list of intentional stage-0 differences:
  the `kern_fsync_fp` `MPASS` that could panic on `fsync(fifo)` is gone;
  `copy_file_range` on non-vnode pairs stays `EINVAL` (today's behaviour,
  stated because the fileop could do otherwise); the new `mac_file_*` hooks
  are called on vnode paths too, are no-ops until a policy implements them,
  and OES/abac/isolation implement them only for `DTYPE_DQ` files (D18), so
  vnode operations are not evaluated twice. Everything else — including
  `fpathconf`/`fstatfs`/`extattr`/ACL on `O_PATH`, `flock` on FIFOs,
  `fpathconf` on ttys, `F_ISUNIONSTACK` on unionfs — returns what it
  returns today.
- **Kernel modules**: `struct fileops` grows into `fo_spares` (size
  unchanged); `struct proc` gains `p_image` and `P2_DQ_EXECED` (KBI
  change, `__FreeBSD_version` bump); `struct pwddesc` gains a pointer;
  `struct protosw` gains a flag bit; `struct pagerops` gains two members.
  `sys/lockf.h` is untouched. Modules must be rebuilt, which the plane
  already requires for every kernel change.
- **Programs under an attachment** (stage 1c onward): section 16 for what
  they see, 11.6 for what the attachment does not do. A launcher that
  `PASS`es everything is a no-op.
- **Security tools**: OES, mac_abac, isolation, audit, `procstat`,
  `sockstat` see served objects marked as such (section 14).
- **Capsicum programs**: unchanged rules; served dirfds obey
  `CAP_LOOKUP`, `UF_LOOKUP_CAPMODE`, `RESOLVE_BENEATH` and `RINROOT`
  identically; rights propagate into `RESOLVE`-opened fds exactly as into
  `openat`-opened fds (I8).

## 6. Stage 0: descriptor completeness

### 6.1 Contract of each new fileop

Signatures take `struct file *` and `struct thread *`, return errno, and
are documented in `file(9)`. The vnode implementation is the syscall's
former body wrapped in `vn_file_context_enter/leave`; the third column
lists what stays in the syscall so "moved code" is auditable.

| Fileop | Vnode body from | Stays in the syscall |
|---|---|---|
| `fo_advlock(fp, id, op, fl, flags, td)` | `kern_fcntl` lock cases, `sys_flock`, `closef`, `fdclearlocks` (`vn_open_vnode_advlock` and the `vn_closefile` unlock stay on the vnode they hold: at open the file has no table yet, at close it has `badfileops` — D72) | fd re-fetch and `F_UNLCK`-on-mismatch recheck; `P_ADVLOCK`; `FHASLOCK`/`FHASOFDLOCK`; the `l_pid != 0 → EINVAL` half of `fcntl_ofd_check` (its `VFCF_OFDLOCKS` mount test dereferences the vnode's mount and moves into `vn_advlock`); `FREAD`/`FWRITE`; `SEEK_CUR`; `CAP_FLOCK` |
| `fo_fsync(fp, mode, td)` | `kern_fsync_fp`; mode `FSYNC_FS` for Linux `syncfs` (`vfs_periodic` + `VFS_SYNC`) | `CAP_FSYNC`; `AUDIT_ARG_VNODE1` moves into the vnode body |
| `fo_setattr(fp, vap, td)` | `setutimes`, `setfflags` | `CAP_FUTIMES`/`CAP_FCHFLAGS`; audit in the vnode body |
| `fo_pathconf(fp, name, valp, td)` | `kern_fpathconf` vnode arm | `CAP_FPATHCONF`; pipe and socket fileops return today's fixed values |
| `fo_statfs(fp, sfp, td)` | `kern_fstatfs`: the whole of `kern_do_statfs` — `VFS_STATFS`, `mac_mount_check_stat`, `prison_enforce_statfs` — runs inside the vnode body because all three need the referenced mount; the dq body runs `mac_file_check_stat` | `CAP_FSTATFS`. Linux `quotactl_fd` needs a `struct mount` no fileop yields and stays `ENOSYS` for non-vnode files |
| `fo_setattr` on `path_fileops` | `fdesc_setattr` non-size path (`fdesc_vnops.c:612`) | `kern_futimes`, `kern_futimens`, `sys_fchflags` keep today's `EBADF` for `O_PATH` fds (`getvnode` rejects them at `vfs_syscalls.c:3470,3518,2862`): they test `f_ops == &path_fileops → EBADF` before calling the fileop (D71); `fdesc_setattr` runs the `fo_*` calls with the fdesc vnode unlocked (D73) |
| `fo_fadvise(fp, off, len, advice, td)` | `kern_posix_fadvise`, Linux `readahead(2)` | `DFLAG_SEEKABLE`; `AUDIT_ARG_FILE` |
| `fo_readdir(fp, uio, basep, ncookies, cookies, td)` | `kern_getdirentries` | `CAP_READ`; the union rewrite stays inside the vnode body, which receives `fp` |
| `fo_copy_file_range(infp, inoff, outfp, outoff, len, flags, td)` | `kern_copy_file_range` | `CAP_READ`/`CAP_WRITE`; mismatched pair → `EINVAL` as today |
| `fo_acl(fp, op, type, aclp, td)` | `vacl_*` | `CAP_ACL_*` |
| `fo_extattr(fp, op, ns, name, uio, td)` | `extattr_*_vp` | `CAP_EXTATTR_*` |
| `fo_fcntl(fp, cmd, arg, td)` | `F_READAHEAD`/`F_RDAHEAD` (D72), `F_ISUNIONSTACK` (D64), Linux rw-hint cases as the kernel-private `FO_FCNTL_{GET,SET}_RW_HINT` | all generic `fcntl` handling; the `O_PATH` refusal of read-ahead; the rw-hint `copyin`/`copyout` and range check |

`fo_chmod`/`fo_chown`: `mac_vnode_check_setmode/setowner` move into
`vn_chmod`/`vn_chown` (vnode checks on a vnode operation); non-vnode
fileops get `mac_file_check_setattr`.

Corrections from the ledger cross-check (D63-D66): `F_ISUNIONSTACK` tests
`MNTK_UNIONFS` (`kern_descrip.c:1085`), which `statfs` does not carry, so
it is a `fo_fcntl` command answered by the vnode body, not `fo_statfs`.
`fo_statfs`'s vnode body runs the whole of `kern_do_statfs` —
`VFS_STATFS`, `mac_mount_check_stat`, `prison_enforce_statfs` — because
all three need the referenced mount; the dq body runs `mac_file_check_stat`
and presents what the controller gave (a jailed requester's `dc_jid` is in
the event, so the controller can present a jail-shaped answer; no kernel
enforcement applies to a served `statfs`, stated in `dq(4)`). The `MPASS`
in `kern_fsync_fp` (`vfs_syscalls.c:3693`) is removed, not moved: it is a
latent panic for `fsync` on a FIFO or pts fd today. Linux `quotactl_fd`
needs a mount no fileop yields and stays `ENOSYS` for non-vnode files.
`kern_mmap`'s private-mapping write promotion (`vm_mmap.c:470`) keys on a
new `DFLAG_PRIVWRITE` in `fo_flags`, set in stage 0 on every table whose
descriptors are `DTYPE_VNODE` today — `vnops`, `vn_openfileops`,
`devfs_ops_f`, `devfs_ops_nonpassable_f` (devfs files are `DTYPE_VNODE`
under their own tables, `devfs_vnops.c:1356-1358`) — and on the dq
fileops in stage 1, instead of `f_type` (D65). The fileops-table audit
lists `fo_flags` per table so this class of flag is caught.

### 6.1.1 Descriptor types that carry a vnode without being `vnops`

Today's syscalls reach the vnode through `getvnode`/`getvnode_path`, which
test `f_vnode != NULL`, not `f_type`. Four fileops tables therefore
receive these calls on descriptors that are not `vnops`: FIFOs
(`pipeops`, `fifo_vnops.c:252`, `f_vnode` from `finit_open`), pty masters
(`ptsdev_ops`, `tty_pts.c:901`), devfs (`devfs_ops_f`,
`devfs_ops_nonpassable_f`, `devfs_vnops.c:2091-2130`), linuxkpi
(`linuxfileops`, `linux_compat.c:1850`), and `O_PATH` files
(`path_fileops`), where `fpathconf(tty)`, `fstatfs(tty)`, `flock(fifo)`,
`futimes`, `fchflags`, `fsync`, extattr and ACL calls work today. Stage 0
preserves every one of them (D63): each moved vnode body is a `vn_*(fp)`
operating on `fp->f_vnode`, and it is **installed explicitly** in those
tables for the members their descriptors answer today — `pipeops` members
branch on `PIPE_TYPE_NAMED`, delegating to `vn_*` for a FIFO and giving
today's pipe answer otherwise; `devfs_ops_f` and `devfs_ops_nonpassable_f`
take `vn_*` for every member they lack; `ptsdev_ops` and `linuxfileops`
are *sometimes-vnode* tables (a `posix_openpt(2)` master or an
`fd_install()`ed linuxkpi file has no vnode, one opened through `/dev/ptmx`
or a devfs node has) and take `vn_*_opt`, which delegates when
`f_vnode != NULL` and returns `invfo_*` otherwise (D72); `path_fileops`
takes `fo_pathconf`, `fo_statfs`, `fo_setattr` (non-size), `fo_acl`,
`fo_extattr`, `fo_fcntl` and `fo_fsync`, with the system calls that
refused `O_PATH` before (`fsync`, `fchflags`, `futimes`, ACL set/delete,
read-ahead) still testing `f_ops == &path_fileops → EBADF` ahead of the
table (D71), matching `getvnode`/`getvnode_path`'s acceptance today. No
`invfo_*` default inspects `f_vnode`; the only code that does is `vn_*_opt`,
installed explicitly in the two sometimes-vnode tables, so the ledger can
count every delegation. The ledger gains a
fileops-table audit (every `struct fileops` definition, which members are
`vn_*`, which are own, which are `invfo_*`/`badfo_*`) beside the call-site
tables, and stage 0 has a test row running every new fileop on a FIFO, a
pts master, a tty, a DRM fd and an `O_PATH` fd against today's results.
`linux_file.c:217`'s `TIOCSCTTY` attempt on a FIFO open and the
`vfs_aio.c:1713` `LIO_SYNC` gate on FIFOs are the two behaviour changes
this uncovers; both are made to preserve today's result.

### 6.2 Image source and `p_image`

Defined in stage 0 so the vnode backend is the moved code and stage 3 only
adds a backend:

```c
struct image_source_ops {
	int  (*is_check)(struct image_params *);      /* exec_check_permissions */
	int  (*is_read)(struct image_params *, void *, off_t, size_t); /* vn_rdwr */
	int  (*is_first_page)(struct image_params *);  /* exec_map_first_page */
	int  (*is_set_text)(struct image_params *);    /* VOP_SET_TEXT / ETXTBSY */
	void (*is_unset_text)(struct image_params *);
	int  (*is_path)(struct image_params *, char **); /* vn_fullpath... */
	bool (*is_nosuid)(struct image_params *);      /* MNT_NOSUID; dq: true */
	int  (*is_mac_transition)(struct image_params *, struct ucred *, struct ucred *, int phase);
	void (*is_close)(struct image_params *);       /* VOP_CLOSE/vput */
};
```

`is_mac_transition` carries the five phases the exec core runs today
(`execve_will_transition`, `will_relabel`, `check_exec`, `transition`,
`relabel`); the vnode backend calls the vnode hooks, the dq backend calls
`mac_file_*` equivalents. Nonce rotation stays where it is, in
mac_capability's `execve_relabel` hook, which the policy implements for
both the vnode and the `mac_file_*` entry points; nothing moves into the
core (I4, D77). `struct proc` gains `p_image {kind, vp, fp, path}`;
`p_textvp` stays valid for vnode images; the 20 `p_textvp` consumers
(`mac_grantbylabel`, `mac_do`, `hwpmc`, `kern_shutdown`, `coredump_vnode`,
`kern_proc`, `kern_fork`, `kern_exit`, veriexec, `vm_map_growstack`,
`vfs_aio`, …) are audited in stage 0; the two that mean "is a kernel
process" become `P_KPROC` tests (`vm_map_growstack` keeps its debugger
case via `map != &vm->vm_map`); the rest get a defined NULL fallback before
stage 3 sets one. Stage-0 tests include `aio_read` into a not-yet-grown
stack page.

#### 6.2.1 Contract as refined by the exec survey (2026-11-07, D75)

A line-by-line survey of `kern_exec.c`, `imgact_elf.c`, `imgact_shell.c`
and veriexec (118 vnode sites) before implementation showed that the ops
above leave vnode knowledge in the core at four places; the contract is
widened so the core is vnode-free and every backend answers through
`imgp->is_ops`. The vnode backend is moved code throughout.

| Op | Vnode backend (moved from) | dq backend (stage 3) |
|---|---|---|
| `is_lock(imgp)` / `is_unlock(imgp)` / `is_assert_locked(imgp)` | `vn_lock(vp, LK_SHARED \| LK_RETRY)` / `VOP_UNLOCK` / `ASSERT_VOP_LOCKED`; replaces the fourteen lock dances in `do_execve` and `exec_elf_imgact` (around `crdup`/`uifind`, `M_WAITOK` mallocs, `exec_new_vmspace`, `copyout_strings`, `fdsetugidsafety`, the hwpmc/HWT hooks) | no-ops |
| `is_check(imgp)` | `exec_check_permissions`: `VOP_GETATTR` into `imgp->attr`, `mac_vnode_check_exec`, `MNT_NOEXEC`, exec bits, `VREG`, nonzero size, `VOP_ACCESS(VEXEC)`, `VOP_SET_TEXT` (`imgp->textset`, `ETXTBSY`), `VOP_OPEN` (`imgp->opened`) | synthesises `attr` (`va_type = VREG`, exec bits, the served length in `va_size`, identity fields zero), `mac_file_check_exec`, asks the controller to pin the image (the `textset` equivalent) |
| `is_first_page(imgp)` | `imgp->object = vp->v_object` referenced, then `exec_map_first_page` (grab page 0 wired, `sf_buf`); `exec_unmap_first_page` stays core | `imgp->object` = the dq pager object; same page path |
| `is_read(imgp, buf, off, len)` | `vn_rdwr(UIO_READ, …, IO_NODELOCKED)` at the four sites (interpreter phdrs, `PT_INTERP`, phdrs, `PT_NOTE`) | controller `READ` |
| `is_map_cow(imgp)` → `int`, `is_map_text(imgp)` | `MAP_VN_EXEC` for `vm_map_fixed`; `VOP_SET_TEXT_CHECKED` after a successful mapping (`map_insert`); the `MPASS(vp->v_object == object)` becomes `MPASS(imgp->object == object)` | `0` (no vnode text refs on the map entries; the dq object's own pin outlives the mappings — 13); no-op |
| `is_unset_text(imgp)` | `VOP_UNSET_TEXT_CHECKED` when `textset` (re-interpret and `exec_fail_dealloc`) | releases the pin |
| `is_path(imgp, &retbuf, &freebuf)` | `vn_fullpath_hardlink(vp, dvp, binname)` when the lookup produced `dvp`/`binname`, else `vn_fullpath` (interpreter vnode, `fexecve`) | the presented path |
| `is_commname(imgp, buf, len)` | `vn_commname` (the `fexecve` fallback for `p_comm`) | the presented name's last component |
| `is_nosuid(imgp)` | `v_mount->mnt_flag & MNT_NOSUID` (both tests) | `true` always (I9) |
| `is_mac(imgp, phase, oldcred, newcred)` | `mac_vnode_execve_will_transition` / `will_relabel` / `transition` / `relabel` with `imgp->interpvplabel`; phase `INTERP_ENTER` = `mac_execve_interpreter_enter` (copies `v_label`) | `mac_file_execve_relabel` and `mac_file_check_exec`; `INTERP_ENTER` leaves the label `NULL` |
| `is_authority(imgp, p, phase)` | `cap_authority_exec_prepare(p, vp)` under `is_nosuid == false`, then `cap_authority_exec(p, vp, selected)`; pointer identity against pinned vnodes | never matches: prepare returns `NULL`, exec a no-op (`authority_setid` is already false under attachment) |
| `is_install(imgp, p, &old)` / `is_release_old(&old)` | swap `p_textvp`/`p_textdvp`/`p_binname` under `PROC_LOCK` and set `p_image = {VNODE, vp}`; release the old vnode state after `PROC_UNLOCK` | `p_textvp = NULL`, `p_image = {DQ, fp}` with a held `struct file` reference |
| `is_accessed(imgp)` | `VOP_UPDATE_ATIME` | controller `NOTIFY(EXEC)` |
| `is_close(imgp, error)` | `VOP_CLOSE(FREAD)` when `opened`, `is_unset_text`, `vput` on error else `VOP_UNLOCK` (the reference now belongs to `p_textvp`), `vrele(dvp)`, free `binname`, `NDFREE_PNBUF`; the private vnode state lives in `imgp->is_data` | drop the image `struct file` on error |

Construction: the core builds the source from the three entry forms
(`args->fname` lookup, `imgp->interpreter_vp` from binmisc, `fexecve`'s
descriptor); `__elfN(load_interp_file)` builds a vnode-backed source
directly from its own kernel-origin `namei` (`exec_image_vnode_init(imgp,
vp)`), never through the descriptor form and never with `NI_DQ_FD_OK`
(I7). The `#!` re-interpret path re-enters the `args->fname` form with the
script's interpreter name, which is script-origin: `NI_DQ_FD_OK` is set on
the first pass only. The `fexecve` form is where stage 3 selects the dq
backend from `fp->f_ops`; in stage 0 it still requires a vnode
(`fgetvp_exec`). `imgact_shell.c`'s `VOP_GETATTR` for `va_size` reads
`imgp->attr` instead. The veriexec `CHECK_FD` syscall builds an
`image_params` by hand with no ops; it keeps compiling and keeps calling
the vnode functions it calls today.

`p_textvp` consumers that dereference without a NULL test, and their
stage-0 fallback: `kern_reroot` (initproc only) → `EOPNOTSUPP` when
`p_image.kind != VNODE`; `mac_grantbylabel` at `priv_grant`,
`PRIV_VERIEXEC_DIRECT` (parent), `proc_check_resource` and the self case of
`FETCH_PID_GBL` → the process is treated as unlabeled (`EPERM`/`EINVAL`,
the answers those paths give an unlabeled vnode). Every other consumer
already tolerates NULL (survey, 2026-11-07).

#### 6.2.2 Review outcome (2026-11-07, D77)

An independent kernel review of 6.2.1 found seven points to settle before
code and six to record; all are adopted.

1. **Pin lifetime.** `imgp->textset` is released at `exec_fail_dealloc` on
   success too; the durable text references are the per-mapping ones
   (`VOP_SET_TEXT_CHECKED` + `MAP_VN_EXEC`, released by `vm_map` at
   unmap). For a served image the kernel provides **no** writer exclusion
   or immutability: `is_map_text` is a no-op, the mapping carries no text
   reference, and "ETXTBSY for writers" is the controller's promise, not
   a kernel guarantee (I10 already concedes that revoke drops pages). A
   pager-level text reference may come with the stage-1b pager; it is not
   promised here. The nullfs `v_usecount` hazard concerns the vnode in the
   old vmspace and stays as moved code in the vnode backend.
2. **Authority.** The dq `is_authority(EXEC)` calls
   `cap_authority_exec(p, NULL, NULL)`: besides matching pinned vnodes,
   that function invalidates a held authority with `nexec > 0`, bumps the
   generation and resets `p_cap_execution`; a no-op would let a process
   keep pinned software authority across a served exec (I3, I5). Only
   `prepare` is skipped for dq.
3. **Construction state.** `imgp->is_ops != NULL` (set only after
   construction succeeded) is the discriminator that `imgp->vp != NULL`
   is today; `exec_fail` before construction touches nothing. Four states:
   not constructed; constructed + error (`is_close(error)`: close, unset
   text, `vput`); constructed + success (`is_close(0)`: close, unset text,
   unlock — the reference now belongs to `p_image`); re-interpret
   (`is_unset_text`, `is_mac(INTERP_ENTER)`, close, `vm_object_deallocate`,
   `execve_nosetid`, in today's order). The `nameidata` moves into the
   vnode backend's `is_data`, and `NDFREE_PNBUF` into its `is_close`.
4. **Interpreter source.** `is_first_page` references `imgp->object` for
   both callers; `__elfN(load_interp_file)` therefore deallocates it in
   its close, where it did not reference before (neutral). It also never
   called `VOP_CLOSE` on the interpreter vnode it opened (upstream does
   not either): that is fixed in its own commit **before** the refactor
   so the refactor stays byte-for-byte; the effect is a `VOP_CLOSE(FREAD)`
   per dynamic exec — a no-op on ufs/zfs/nullfs, a released file handle
   on fusefs (leaked today), `nfs_close` attribute invalidation on nfs,
   and `vop_close_post` firing. Recorded in the ledger.
5. **`p_image` lifecycle.** `kern_fork` holds the image `struct file`
   (`fhold`) as it `vrefact`s `p_textvp`; `kern_exit` drops it, and the
   drop may be the last reference, so `fo_close` of a served image under
   `exit1` is an I11 case (post and continue). `is_release_old` runs where
   the deferred `vrele(oldtextvp)` runs today: after `is_close` has
   dropped the image lock and after `PROC_UNLOCK` (the same-vnode re-exec
   case). `struct proc` growth is KBI only; `kinfo_proc.ki_textvp` stays
   and is NULL for dq. `p_image` carries the presented path (`pi_path`),
   so `kern.proc.pathname` and `procstat` show what `is_path` gave at
   exec, not `""`.
6. **Attribute synthesis.** `credential_changing` is computed from
   `va_mode`'s set-id bits before the `MNT_NOSUID` test, so the dq
   backend synthesises `va_mode` with set-id bits clear (MINT refuses
   them, I3) and `va_uid`/`va_gid` as the caller's. veriexec:
   `mpo_file_execve_relabel` sets `EXEC_ID(new)->valid = false` (the
   crdup'd copy would otherwise carry the previous image's identity as
   valid) and `mpo_file_check_exec` denies under enforce (D28); the
   fingerprint path stays vnode-only and is never handed a NULL vnode.
7. **Nonce rotation** stays in mac_capability's relabel hooks (6.2 text
   corrected); `relabelcred` is allocated only when a policy answers
   `will_relabel`, as today.
8. Lock preconditions per op, asserted by the MAC entry points: `is_check`,
   `is_read` (`IO_NODELOCKED`), every `is_mac` phase, `is_authority(PREPARE)`,
   `is_install`, `is_accessed` run with the image locked; `TRANSITION` and
   `RELABEL` also under `PROC_LOCK`, NOSLEEP — the `mac_file_*` equivalents
   are NOSLEEP too; `INTERP_ENTER` allocates `M_WAITOK` under the image
   lock as today. `is_lock` = `vn_lock(LK_SHARED | LK_RETRY)` reproduces
   the `VOP_ISLOCKED` restore in `map_insert` because exec only holds
   shared.
9. The vnode `is_map_text` keeps `MPASS(vp->v_object == object)` (an
   `imgp->object` comparison would be a tautology). dq mappings carry
   `cow = 0` and may coalesce where `MAP_VN_EXEC` entries do not.
10. `struct image_params` appends `is_ops`/`is_data` after
    `interpreter_vp`; `vp`, `object`, `attr`, `opened`, `textset` stay, so
    veriexec's hand-built `image_params` and `exec_check_permissions`'s
    export keep working (KBI by size only).
11. Construction keeps the `args->fname[0] == '/'` shortcut, the
    `execpath = args->fname` fallbacks, `AUDIT_ARG_VNODE1` for the
    interpreter-vnode and `fexecve` forms and `AUDIT_ARG_FD`; `is_commname`
    for the fname form uses `binname` (the same bytes as `nd.ni_cnd`).
12. I7 names the function `__elfN(load_interp_file)`. A served ELF's
    `PT_INTERP` resolves against the real namespace only (`ENOENT` if the
    interpreter exists only in the virtual one). The stage-0 `fexecve`
    form keeps `fgetvp_exec`'s `EINVAL` for non-vnode descriptors.
13. The five NULL fallbacks stand; `kern_reroot`'s is unreachable in
    practice. For a dq-served script, `interpvplabel` stays NULL, so
    policies see "no interpreter label" on the real interpreter's exec.

#### 6.2.3 As built (2026-11-07, D78)

The vnode backend lives in `sys/kern/exec_image_vnode.c`; `struct
image_source_ops` in `sys/sys/imgact.h` has the 6.2.1 ops with these
settled details, found while moving the code:

- **Construction owns path, lock and audit for the vnode forms.** The
  binmisc and `fexecve` forms emit `AUDIT_ARG_VNODE1`, which asserts the
  vnode locked and runs `VOP_GETATTR`; there is no vnode-free way for the
  core to emit it, so `exec_image_vnode_from_vnode(imgp, vp)` does
  `vn_fullpath`, `vn_lock`, `AUDIT_ARG_VNODE1` itself. The `args->fname`
  form keeps its path work in the core through `is_path`, with the
  `args->fname[0] == '/'` shortcut in the core; `exec_image_vnode_from_namei`
  takes the `nameidata` by value, the parent and the last component. In
  stage 3 the `fexecve` form is where the dq constructor is selected from
  `fp->f_ops`; the audit argument for a served image is the stage-3
  constructor's business.
- **`is_path` for the fname form without a parent** (the mount-over-a-file
  case) returns 0 without touching the buffers, as today's code leaves
  `execpath` unresolved; the 6.2.1 row's "else `vn_fullpath`" applies to the
  other forms only.
- **`is_release_old` belongs to the displaced image's kind, not the new
  backend.** In stage 3 a served exec displaces a vnode image and vice
  versa, so the old state is a core-visible `struct image_source_old
  {iso_textvp, iso_textdvp, iso_binname}` that any backend's release can
  `vrele`/free, dispatched through the ops saved at `is_install`
  (`is_close` clears `imgp->is_ops`).
- **`is_close(imgp, error)`** uses a nonzero `error` to mean "drop the
  reference" (`vput`); the never-installed closes (re-interpret, the
  interpreter loader) pass `ENOEXEC`. A boolean would read better; stage 3
  may rename it when it adds the second backend.
- `is_authority_prepare` returns `struct cap_authority *` (typed, not
  `void *`); the ops that do not modify the image take a `const struct
  image_params *` so `map_insert`/`load_section(s)`/`parse_notes` keep
  their `const` parameters; `interpvplabel` moves from a `do_execve` local
  into `image_params` (zeroed by every constructor of the struct).
- `exec_check_permissions` is exported by name from the backend (the
  table's `is_check`); veriexec's `CHECK_FD` builds `image_params` by hand
  and never calls it, contrary to the earlier note — it keeps compiling
  because the existing fields stay where they are.
- `p_image` is appended at the end of `struct proc`, not beside `p_textvp`:
  `kern_thread.c` asserts the offsets of `p_filemon`, `p_comm` and
  `p_emuldata` (KBI), and a member inserted before them trips the build.
- `proc_get_binpath` copies `pi_path` out under `PROC_LOCK` and hands it
  back as `freebuf`, because `sysctl_kern_proc_pathname` frees its scratch
  buffer before reading `retbuf`; `kern_fork` `strdup`s `pi_path` (a shared
  pointer would be freed twice at exit).
- Behavioural deltas for vnode images, all accepted as neutral: one more
  `M_WAITOK` allocation under the shared image lock in the fname form (the
  backend's state, beside the existing `binname` one); `NDFREE_PNBUF` and
  `vrele(dvp)` swap order in the re-interpret close; the interpreter
  loader's object is referenced by `is_first_page` and deallocated after
  its close (6.2.2 item 4); `exec_shell_imgact` no longer issues its own
  `VOP_GETATTR`; `exec_fail_dealloc` keys on `is_ops`, and `is_close`
  clears `opened`/`textset`/`vp`, which nothing reads afterwards.

### 6.3 The ledger

`docs/descriptor-completeness-ledger.md` is generated by a recorded
command, committed with the output, and regenerated at the end of every
stage:

```sh
cd /usr/src/sys && git grep -n -E \
  'fgetvp(_(read|write|exec|lookup|lookup_smr|rights))?\(|getvnode(_path)?\(|->f_vnode|DTYPE_VNODE' \
  -- kern vm compat security fs/fdescfs fs/pseudofs dev/mac_capability \
     dev/filemon dev/ntsync cddl ufs netinet ofed \
  ':!kern/vfs_vnops.c' ':!fs/devfs' ':!fs/nfs*' ':!fs/nullfs' ':!fs/unionfs'
```

At `descriptor/completeness` HEAD it finds 277 references, 58 of them
`DTYPE_VNODE` tests. The ledger's own "not matched" audit shows the
command misses `DTYPE_FIFO` tests (which also reach `f_vnode`), the
`contrib/openzfs` file-handle code, `p_textvp` (30) and `imgp->vp` (76)
consumers; before stage 0 closes the command is revised to include
`DTYPE_FIFO|p_textvp|imgp->vp` and `contrib/openzfs/module/os/freebsd`,
and the ledger gains the fileops-table audit of 6.1.1 (D66). The ledger,
not this chapter, is the count of record; the count is authoritative only
for the command recorded beside it.

## 7. The queue and its objects

### 7.1 `/dev/dq`

Delivered like `/dev/oes`: BSDDevice opens it for a unit whose bundle
requires `system.dq` and hands the fd to the unit; the node is 0600 and
claimed through the isolation service at boot — **the claim is the
authority**. `priv_check(PRIV_DRIVER)` is kept as a belt for the plane-off
test path, as OES does; it is not the access rule. One open is one queue
(`cdevpriv`). `read(2)` returns batched events; ioctls mint, reply, push,
revoke, set identity and policy, read stats; `poll`/`kqueue` report
readiness. Modelled on `sys/security/oes/oes_dev.c`: batching reads,
per-queue sequence numbers, interruptible waits, bounded depth with
visible drops. The queue fd is hardened at delivery (`CAP_XFER_NONE`,
`CLOFORK_LOCKED`, `CLOEXEC_LOCKED`) as every plane fd is.

*Decision D3*: a cdev, not a `mac_capability` service. A queue is a
long-lived, `kqueue`-able stream of kernel-originated events with large
data replies and out-of-order answers; the framework's `co_call` is
single-reply in the caller's thread and its only kernel→user traffic is
fire-and-forget `notify`. Delivery and authority still go through the
plane exactly as for `/dev/oes`.

### 7.2 Observer queues

`DQ_IOC_MINT_OBSERVER {flags}` mints a read-only descriptor receiving a
copy of every event and reply on that queue **with data bodies removed**
(lengths kept); `DQ_OBS_F_DATA` at mint includes bodies and is a separate
right the holder cannot widen; `cap_ioctls_limit` leaves it `GET_STATS`.
The system observer — every queue's events, the live object table and the
socket list — is the `mac_capability` service `dq.observe`, mintable by
capsule **per queue set** under `system.dq.observe`, metadata-only unless
minted with data (D41). `sockstat` and `procstat` consume it through
libdq. No uid-keyed sysctl exposes served state (D21).

### 7.3 Kinds

| Kind | Object | Stage |
|---|---|---|
| `DQ_KIND_FILE` | `struct file`, dq fileops, `S_IFREG` | 1a |
| `DQ_KIND_DIR` | `struct file`, dq fileops, `S_IFDIR`; a start directory for resolution | 1c |
| `DQ_KIND_SYMLINK` | a `RESOLVE` answer (`ATTR`, `S_IFLNK`, target); open only as `O_PATH` | 1c |
| `DQ_KIND_SOCKET` | `struct socket`, dq protosw | 2 |
| `DQ_KIND_CDEV` | `struct file`, `S_IFCHR`, served ioctl/poll/mmap | 5 |

Pipes and pseudo-terminals are not kinds: the kernel already gives a
controller the other end of those.

### 7.4 Presented identity

```c
struct dq_ident_file {
	uint64_t di_dev, di_ino, di_gen;
	uint32_t di_mode;            /* type bits match the kind; S_ISUID|S_ISGID rejected (I3) */
	uint32_t di_nlink, di_uid, di_gid;
	uint64_t di_size, di_blocks; uint32_t di_blksize, di_flags; uint64_t di_rdev;
	struct dq_timespec di_atime, di_mtime, di_ctime, di_birthtime;
	uint32_t di_pathlen; char di_path[DQ_PATH_MAX];   /* absolute, normalized */
	struct dq_statfs   di_statfs;    /* f_mntonname: component-boundary prefix of di_path */
	struct dq_pathconf di_pathconf;
};
struct dq_ident_sock {
	int32_t ds_domain, ds_type, ds_protocol;
	struct sockaddr_storage ds_local, ds_peer;
	uint32_t ds_state;           /* UNCONNECTED | CONNECTING | CONNECTED | LISTENING */
};
```

Validated at `MINT`/`SETIDENT`: path absolute and normalized (no `.`,
`..`, `//`, trailing `/`), mount name a component-boundary prefix of the
path, type bits match the kind, no set-id bits, `di_blksize` nonzero. The
served mark is the object's `f_type == DTYPE_DQ`, never an `f_flag` bit
(I13, D51). With `dp_events` including `GETATTR` the controller answers
`fstat` per call instead of from the identity.

### 7.5 Policy

| Field | Values | Meaning |
|---|---|---|
| `dp_cache` | `NONE`, `ATTR`, `DATA` | `read`/`fstat` always ask; attributes from the identity; attributes and pages (section 10). Pages used by mappings exist in every mode |
| `dp_write` | `DENY`, `EVENT` | `RESOLVE` for `O_WRONLY/O_RDWR` fails `EACCES` and the fd is created without `FWRITE`; or writes are events |
| `dp_exec` | `DENY`, `ALLOW` | `RESOLVE op=EXEC`/`fexecve` fail `EACCES`, or are served (stage 3) |
| `dp_mmap_shared_write` | `DENY`, `ALLOW` | needs `dp_write = EVENT` |
| `dp_lock` | `EVENT` | every lock operation is an event; the controller owns the table (D14) |
| `dp_ioctl` | `DENY`, `EVENT` | `ENOTTY`, or events |
| `dp_deadline_ms` | `DQ_DEADLINE_DEFAULT`, `0`, or ms | default = `kern.dq.default_deadline_ms` (30000); `0` = none (explicit) |
| `dp_rights` | `cap_rights_t` | rights of the minted fd; default `CAP_ALL_RIGHTS` because that is what `open()` returns (D20); always intersected with the start dirfd's caps at `RESOLVE` install (I8) |
| `dp_events` | bitmask | optional `GETATTR`, `CLOSE`, `RCVD`, `SOCKOPT`, `SET_TEXT` |

`fchmod`/`fchown`/`futimens`/`fchflags` under `dp_write = DENY` are
`SETATTR` events — ownership, not `FWRITE`, governs them on real files —
and the controller answers.

## 8. Wire protocol

Fixed-width, native byte order, `DQ_API_VERSION` 1, additive like
`oes_message_t`; defined in `sys/dev/dq/dq.h`, the installed header.

### 8.1 Event header

```c
struct dq_event {
	uint32_t de_version, de_size, de_op, de_flags;
	uint64_t de_id;        /* reply token, unique per queue */
	uint64_t de_object;    /* object id; 0 = queue-level */
	uint64_t de_seq;       /* per-queue sequence; a gap is a drop */
	struct dq_caller {     /* from the requesting process, never curthread */
		pid_t dc_pid, dc_ppid; lwpid_t dc_tid;
		uid_t dc_uid, dc_euid; gid_t dc_gid, dc_egid;
		uint64_t dc_nonce; uint32_t dc_jid;
		uint32_t dc_flags; /* DQ_CALLER_F_KERNEL: pager/aio/sendfile completion */
	} de_caller;
	struct dq_timespec de_time;   /* CLOCK_MONOTONIC */
};
```

`de_caller` is taken from the `struct file`'s owner for pager, aio and
sendfile paths (`f_cred`, the aio job's `userproc`, the mapping owner),
so an aiod or kernel thread never appears as the requester (D24).

### 8.2 File and directory events

| Op | Body | Reply |
|---|---|---|
| `READ` | `offset`, `len ≤ kern.dq.max_io` | errno, `data[len']` (short = EOF at `offset+len'`) |
| `READ_ASYNC` | as `READ`, from `getpages_async` (sendfile) | as `READ`; completion runs the `sfio` callback |
| `WRITE` | `offset`, `data` | errno, `written` |
| `WRITE_ASYNC` | from `putpages` | errno; completion marks pages clean. From laundry, close and queue teardown it is never waited for (I11); from `msync(MS_SYNC)` via `pgo_sync` the calling thread waits, interruptibly and deadline-bounded, so `MS_SYNC` keeps its durability meaning (D42) |
| `GETATTR` / `SETATTR` | — / `mask`, attrs | identity / errno; the kernel updates the identity on success |
| `FSYNC`, `FALLOCATE`, `FSPACECTL` | `mode` / range | errno |
| `IOCTL` | `cmd`, `in[]` sized by `IOCPARM_LEN` | errno, `out[]`; ioctls embedding user pointers cannot be served and are `ENOTTY` |
| `LOCK` | `op` (`GETLK`/`SETLK`/`SETLKW`/`flock`), `flock`, owner id (as fusefs computes it) | errno, `flock` |
| `UNLOCK_ALL` | owner id | none — posted by `closef`/`fdclearlocks` only for objects on which a `LOCK` was ever posted (D14) |
| `READDIR` | `cookie`, `len` | errno, `dirent[]`, `next`, `eof` |
| `RESOLVE` | section 11.3 | section 11.3 |
| `SET_TEXT` / `UNSET_TEXT` | — | none (stage 3) |
| `CLOSE` | — | none |
| `INTERRUPT` | `id` of the abandoned event | none; the late reply is discarded and counted |

### 8.3 Socket events and pushes

Events: `CONNECT {sockaddr}` → errno (the kernel marks connecting; the
controller pushes `CONNECTED` or `RESET`); `BIND`, `LISTEN {backlog}`,
`SHUTDOWN {how}`, `DISCONNECT` → errno; `ACCEPT` → `MINT` body for the
child with its peer address, posted when the completed queue is empty and
the requester blocks; `SEND {data, sockaddr, flags}` → errno, `taken`
(`taken < len` leaves the rest queued, drained in order); `RCVD {bytes}`
(optional flow control); `SOCKOPT {level, name, get/set, val}` → errno,
`val` (non-`SOL_SOCKET` levels and the `SOL_SOCKET` options the generic
layer forwards; `SO_DOMAIN`/`SO_TYPE`/`SO_PROTOCOL` come from the
identity); `IOCTL` (`pr_control` and the `'i'`/`'r'` groups); `CLOSE`.

Pushes: `DELIVER {data, sockaddr}` (append to `so_rcv`, `sorwakeup`; a
control chain is `EINVAL`), `CONNECTED {peer}` (`soisconnected`),
`ACCEPTED {listener, child MINT body}` (`solisten_clone` + dq attach +
`solisten_enqueue`), `EOF` (`socantrcvmore`), `RESET {errno}` (`so_error`,
`soisdisconnected`, `sbflush(so_rcv)`).

### 8.4 Other pushes

`INVALIDATE {object, offset, len}` (section 10); `SETIDENT`; `REVOKE`;
`NOTIFY_VNODE {object, note}` for `EVFILT_VNODE` (`NOTE_WRITE`, `EXTEND`,
`ATTRIB`, `LINK`, `RENAME`, `DELETE`); `INOTIFY {object, mask, name}` for
inotify watches on served directories (D27).

### 8.5 Ioctls on the queue

`MINT` (installs the fd with `falloc_noinstall` + `finstall`, `O_CLOEXEC`,
`dp_rights`, as `/dev/zfs` does for `DTYPE_ZFSHANDLE`), `MINT_OBSERVER`,
`REPLY`, `PUSH`, `REVOKE`, `SETIDENT`, `SETPOLICY`, `GET_STATS`,
`SET_QUEUE_DEPTH`, `ATTACH {procdesc}`, `ATTACH_SELF`, `REGISTER_NAME`
(stage 4). There is no pid form of anything (D44).

### 8.6 Limits

`kern.dq.max_io` (131072; larger I/O is chunked into ordered events);
`kern.dq.queue_depth` (1024 per queue, lowerable by the controller; a
full queue fails the requester's operation with `EIO`, counts a drop, and
leaves a `de_seq` gap — never silent, never defaulted);
`kern.dq.max_inflight_per_object` (64; beyond it requesters wait for a
slot rather than overflow the queue); `kern.dq.max_inflight_per_requester`
(per nonce, default 256, below the depth: one requester cannot exhaust the
queue for another, D60); `kern.dq.max_inflight_bytes` (per queue, default
64 MiB, pending `WRITE_ASYNC` data charged to the dirtying requester's
`racct` and `swap_reserve_by_cred`; a fault at the bound blocks,
deadline-bounded, D59); `kern.dq.max_objects` per queue (65536);
`kern.dq.default_deadline_ms` (30000).

## 9. Files

`dofileread`/`dofilewrite` take `foffset_lock` for the implicit offset,
then call `fo_read`/`fo_write`. `dq_read` takes the object's
`struct rangelock` (the same type a vnode embeds) for `[offset,
offset+len)` shared, `dq_write` exclusive, giving POSIX read/write
atomicity between requesters of one object. With `dp_cache = NONE` the
operation is one or more events; with `DATA` reads are served from the
object's pages and misses are page-aligned `READ` events; writes update
pages only after the controller accepts them. No other lock is held while
waiting.

`dq_stat` fills `struct stat` from the identity (`st_dev`, `st_ino`,
`st_gen` included; nothing else in the kernel supplies these);
`dq_fill_kinfo` fills `kf_type = KF_TYPE_VNODE`, `kf_vnode_type` by kind,
`kf_path`, `kf_file_fsid`, `kf_file_fileid`; `dq_statfs` and `dq_pathconf`
answer from the identity. `realpath`, `readlink /dev/fd/N`, `procstat -f`,
`linprocfs` and `getcwd` all read these.

`dq_kqfilter`: `EVFILT_READ` reports `size - offset`; `EVFILT_WRITE`
ready when `FWRITE`; `EVFILT_VNODE` supports every note the kernel defines
— `NOTE_OPEN`, `CLOSE`, `CLOSE_WRITE`, `READ` raised by the kernel on the
object's own operations, `DELETE`, `WRITE`, `EXTEND`, `ATTRIB`, `LINK`,
`RENAME`, `REVOKE` by `NOTIFY_VNODE`/`SETIDENT`/`REVOKE` (D27).
`dq_ioctl` answers `FIONREAD`, `FIONBIO`, `FIOASYNC`, `FIODTYPE`,
`FIOSEEKDATA/HOLE` (one extent) locally and `FIOBMAP2` with `EOPNOTSUPP`;
others are `IOCTL` events when `dp_ioctl = EVENT`, else `ENOTTY`.
`dq_seek` is local, bounded by the identity's size for `SEEK_END`.
`dq_add/get_seals` → `EINVAL` as for a vnode. `dq_fallocate`/`fspacectl`
are events under `dp_write = EVENT`, else `EBADF` as on a read-only fd.
`dq_aio_queue` is the default (`aio_queue_file`), so aio runs through
`dq_read`/`dq_write` in the aio daemons. `dq_cmp` (`kcmp`): equal iff the
same object. `dq_poll`: always ready, as any regular file.

`dq_close` runs at the last reference (descriptor table entries,
`SCM_RIGHTS` messages in flight, mappings through the mapping owner, and
the attachment's `dr_cwd`/`dr_root`): posts pending dirty pages as
`WRITE_ASYNC`, `knlist_clear`/`destroy`, releases the VM object and lock
state, posts `CLOSE` if subscribed, retires the object id; it never waits
(I11). Revoke state (`LIVE`, `REVOKED`) is checked under the object mutex
at the entry of every fileop; there is one fileops table (D15); `fstat`
and `F_KINFO` keep answering from the frozen identity after revoke so a
requester's bookkeeping does not crash.

## 10. Pages

The dq pager is its own type (`vm_pager_alloc_dyn_type(&dq_pagerops, -1)`),
never `OBJ_SWAP` (with `OBJ_SWAP`, `vm_fault` zero-fills without calling
`getpages`, `vm_fault.c:252-258`), with every `pagerops` member
implemented: `alloc`, `dealloc`, `getpages` (posts `READ`, readahead
clamped to 0), `getpages_async` (posts `READ_ASYNC`, completes the `sfio`),
`putpages` (posts `WRITE_ASYNC`, returns `VM_PAGER_PEND`, completes from the
reply or with error on queue close; never blocks the laundry thread),
`haspage` (from the identity's size), `sync` (new `pgo_sync`: `msync` →
`putpages` of dirty pages, waited for by the caller under `MS_SYNC`),
`kinfo` (new `pgo_kinfo`: `kve_type = KVME_TYPE_VNODE`, `kve_path`,
fileid, fsid, mode, size from the identity), `update/release_writecount`,
`pageunswapped` (no-op), `freespace`, `page_inserted/removed`,
`can_alloc_page`. `MAP_VN_EXEC` on a dq object is harmless: a NULL
`pgo_getvp` is tolerated (`vm_map.c:620-621`).

**Cache contract (D11).** Pages exist while mapped, wired (exec text,
sendfile in flight) or cached under `dp_cache = DATA`. They are dropped by
`INVALIDATE`, `REVOKE`, queue close and object close, each via
`vm_object_page_remove` with `pmap_remove_all`, so a mapping observes the
change on its next access (wired pages are handled there too,
`vm_object.c:2059-2068`). `dp_cache = NONE` means `read`/`fstat` always
post; it does not mean "no pages". The OBJ_SWAP/OBJT_VNODE dispatch sites
(`vm_mmap.c:1036` mincore, `vm_map.c:3312` charge, `:4660` fork copy,
`vm_fault.c:2372`, `vm_pageout.c:552,902,1659,1941`, `vm_page.c:2888,3025`,
`vm_meter.c:240`, `vm_object.c:246,970,2574`) are each reviewed in stage
1b and the decision per site recorded in the ledger (*open*).

Each object has its own VM object; two objects presenting the same
identity never share pages, so per-requester redaction cannot leak through
the cache. Exceptions (I10): `MAP_PRIVATE` copy-on-write pages the
requester has written live in an anonymous shadow and survive revoke;
pages already queued by `sendfile` into a socket buffer are transmitted.
Documented in `dq(4)`.

## 11. Resolution and the virtual namespace

### 11.1 The attachment

```c
struct dq_resolver {               /* struct pwddesc: pd_dqres */
	u_int		dr_refs;
	struct dq_queue	*dr_queue;
	struct file	*dr_cwd;   /* served DIR object, or NULL = pd_pwd->pwd_cdir */
	struct file	*dr_root;  /* served DIR object, or NULL = pd_pwd->pwd_rdir */
	uint32_t	dr_flags;
};
```

`dr_cwd`/`dr_root` hold **file references** (D45): a requester's
`fd = open(dir); fchdir(fd); close(fd)` keeps the object alive through the
attachment, and `CLOSE` is posted when the last of fd, mapping and
attachment references drops. The kernel's `pd_pwd` stays a **real**
directory of the launcher's choosing (`/` for a launcher that `PASS`es, an
empty directory for one that does not); `pwd_ensure_dirs` and every other
`pwd` consumer keep working on real vnodes (I13, D9).

Inherited and released in `pdinit`/`pdcopy`/`pdshare`/`pdunshare`/`pddrop`
(`kern_descrip.c:2714-3241`), the same places `pd_pwd` is (D38), so
`fork`, `vfork`, `rfork` with any of `RFFDG`/`RFCFDG`/`RFPROC`, `pdfork`,
Linux `clone`, exec and exit all carry or release it. There is no detach
operation (I5), so shared `pwddesc` between `rfork(RFPROC)` siblings has
no divergent state.

**Attaching** — one form, by held descriptor (D44, D46, D55-D56):
`DQ_IOC_ATTACH {procdesc}`. Under `PROC_LOCK` of the target, in the same
critical section that installs `pd_dqres`, the kernel requires: the caller
holds the procdesc; the target has not exec'd (`P2_DQ_EXECED` clear) and is
not in an exec (`P_INEXEC` clear); the target's `pwddesc` is unshared
(`pd_refcount == 1`) and is not the caller's own; the target is not already
attached. Otherwise `EBUSY`. `P2_DQ_EXECED` is set at the exec commit
point (the `proc_set_cred` region, `kern_exec.c:1044`, under `PROC_LOCK`),
not at entry, so a failed first exec leaves the child attachable; it is
not inherited by fork. `do_execve` re-reads `pd_dqres` under `PROC_LOCK`
after `execve_block` and treats a process attached at any point during the
exec as attached for the I5(a) predicate (D55, D67). The `credential_changing`
side effect that clears `p_pdeathsig` (`:714`) is likewise skipped for an
attached process whose set-id was suppressed (D68).

The queue structure is reference-counted independently of its `cdevpriv`:
objects and attachments hold references, so `pddrop` → `fdrop(dr_cwd)` →
`dq_close` after the controller has closed the queue finds a dead queue and
posts nothing. `dr_cwd`/`dr_root` are released with `fdrop`, not `closef`
(no `fo_fdclose`, no POSIX unlock — directories have neither) (D69).
`mac_file_check_inherit` runs at `fork1`'s `fdcopy` and at `fdcloseexec`,
so a plain `fork()` by a controller cannot carry minted fds into an
unattached child; a refusal leaves that slot empty in the child, exactly
as `O_CLOFORK` does — `fdcopy` cannot fail a single fd (D70). Attachment is a property of the
`pwddesc`: every process sharing one is attached together, which is why an
unshared `pwddesc` is required at attach time and why a controller must
never share a `pwddesc` with a target (`pdfork` uses `pdcopy`; plain
`fork` shares). There is no `ATTACH_SELF` (D57): a controller that wants to
be inside the namespace it serves runs a child there.

### 11.2 The choke points

`namei_setup` (relative, `AT_FDCWD`), `namei_handle_root` (absolute),
`fgetvp_lookup` (dirfd), and `cache_can_fplookup` (the SMR entry, which
already aborts for capability mode, auditing and `ni_startdir`; it declines
to the slow path for any attached process before a component is consumed;
`fgetvp_lookup_smr` already returns `EAGAIN` for a vnode-less dirfd) (D39).
`ni_startdir` callers (`vop_std*`, inotify, nfsd, the ABI-root restart) are
kernel-origin from real vnodes and are not consulted. Each point already
runs after Capsicum's `CAP_LOOKUP`/`UF_LOOKUP_CAPMODE`/`ENOTCAPABLE`
decisions and inside the audited path. When the process is attached, or
the dirfd is a served directory, the choke point calls `dq_resolve()` with
the start (served object, or real vnode), the whole remaining path and the
lookup's rflags. Only `NI_DQ_FD_OK` lookups may receive `FD` (I7). The ELF
interpreter load is kernel-origin: a served-root process runs dynamic
binaries when the controller `PASS`es `/libexec/ld-elf.so.1`, and the real
interpreter loads from the real `pd_pwd` (D10).

### 11.3 `RESOLVE`

Body: `op` (`OPEN`, `STAT`, `ACCESS`, `READLINK`, `REALPATH`, `GETFH`,
`UNLINK`, `RENAME`, `LINK`, `SYMLINK`, `MKDIR`, `RMDIR`, `MKNOD`, `MKFIFO`,
`SETATTR`, `EXEC`, `EXEC_INTERP`, `CONNECT`, `BIND`, `SOCKET`,
`SOCKETPAIR`, `CHDIR`, `CHROOT`, `INOTIFY`, `XATTR`, `ACL`, `TRUNCATE`,
`REVOKE`, `INTERNAL`), start (`object id` or `0` = real start), `path`
(whole remaining path), `flags`, `mode`, `rflags` (`STRICTREL`, `BENEATH`,
`RINROOT`, `NOFOLLOW`, `EMPTYPATH`, `USER` = `NI_DQ_FD_OK`), second path
for `RENAME`/`LINK`; for `SOCKET`/`SOCKETPAIR`: `{domain, type, protocol}`
as resolved by `pffindproto`.

Reply: `PASS` (continue into `namei` from the real start; refused when the
start is served); `FD` + `MINT` body (open-type ops; installed by the
kernel after I8's rights intersection and the identity validation); `ATTR`
+ identity (+ target for `READLINK`); `OK` (the controller performed a
mutating op); errno.

Post-checks the kernel applies to every reply (I8): under `BENEATH`,
`STRICTREL` or `RINROOT` the normalized returned `di_path` must extend the
start directory's normalized `di_path` at a component boundary; `FD` for
a lookup without `USER` is `EINVAL`; `FD` with `FWRITE` when policy is
`DENY` is `EINVAL`; set-id bits `EINVAL`. `OPENNAMED` (`O_NAMEDATTR`) on a
served start is refused `EOPNOTSUPP` before any event (D43).

`SOCKET`: consulted **inside `socreate`** after `PR_CAPATTACH`/`ECAPMODE`,
`prison_check_af` and `pffindproto` have run (`uipc_socket.c:1062-1083`),
so the controller sees the resolved protocol and no event precedes the
kernel's own checks (D40). `socketpair` posts one `SOCKETPAIR` event whose
`FD` reply mints both ends connected. Kernel-origin `socreate` callers
(NFS, RPC, NLM, iSCSI, wg, vxlan, geneve, gre, SCTP, netgraph) are never
consulted (I7).

### 11.4 cwd, root, `getcwd`, jails

`fchdir`/`chdir`/`fchroot`/`chroot`/`CP_OP_CHROOT`: if the target is a
served directory, or the path resolves to one (`RESOLVE op=CHDIR/CHROOT` →
`FD`), set `dr_cwd`/`dr_root`, releasing the previous reference; if the
resolver answers `PASS`, the real `pd_pwd` changes **and** the
corresponding `dr_*` is cleared, so the virtual and real views never
disagree (D45). `vn_getcwd` and the kinfo `CWD`/`ROOT` export answer from
`dr_*` when set. `chroot_refuse_vdir_fds` counts served directories.
`jail_attach` by an attached process is refused `EPERM` (I5(b)); the agent
recipe jails first, then attaches.

### 11.5 Global attachment (stage 4, *open*)

The mechanism is independent of who attaches. Stage 4 is only the
**attach decision**, made once per exec in `do_execve` after the image is
identified and before the first page is mapped — never per operation, so
nothing in it is on the hot path. Inputs, in precedence order (D37,
direction not decision):

1. **Parent attachment** — inherited, cannot be shed. Always wins.
2. **Brand in the image's embedded policy** — the `.5bsd.policy` section
   the kernel already reads at exec names a resolver
   (`resolver = "system.AgentSandbox"`). Controllers register the name on
   their queue (`DQ_IOC_REGISTER_NAME`); a branded image whose controller
   is absent fails to exec (`EAGAIN`, fail closed). Static, verifiable
   offline, signed once manifests are embedded — the analogue of
   `Elf_Brandinfo` routing an image to its `sysentvec`. Constraint: a
   branded image must never be on the path that launches its own
   controller, or boot cannot start the thing that would start it (D62).
3. **ABI class** — a rule keyed on the image's `sysentvec` (every
   Linux-ABI image → resolver Y).
4. **OES `OES_EVENT_AUTH_ATTACH`** — one AUTH event per exec for images
   none of the above selected; the client answers "attach to queue Q" or
   "none"; OES's decision cache keyed on image identity makes repeat execs
   free. OES is an input to the decision, not the mechanism.

Which inputs are enabled, and their defaults, are decided in stage 4;
nothing before stage 4 depends on the choice.

### 11.6 What an attachment is and is not

An attachment substitutes the meaning of names and of `socket()`. It does
**not** remove any other global namespace an unsandboxed process has:
`kill`/`sigqueue`/`procctl`/`ptrace`/`thr_kill2` toward same-uid
processes; `kern.proc.*`, `kern.file`, `net.*`, `hw.*` sysctls; SysV and
named POSIX IPC (`shm_open`, `ksem_open`, `mq_open` are dictionaries, not
`namei`); descriptors inherited before attachment; `ioctl` on inherited
descriptors including the tty; and the plane's discovery route with the
ungated `mac_capability_channel_create(2)`, through which providers hand
out real sockets and files.

Inside a jail the named-IPC namespaces are prison-scoped
(`shm_open`/`ksem_open`/`mq_open` names are prefixed by the prison path),
so that escape applies to an unjailed attachment only; `posix_openpt` is
the one real object an attached process can always create.

Therefore the **agent consumer** (20.1) is, in order (D58-D62):

1. The controller runs **outside** the sandbox jail, as a plane unit, with
   its network and files delivered as capabilities (BSDNetwork,
   BSDFilesystem), every capability it holds `CLOFORK_LOCKED` (libservice's
   default), and itself shielded with capprotect (`CP_OP_PROTECT`:
   `CP_SF_PTRACE|CP_SF_SIGNAL|CP_SF_DEBUG`). It is **not** at real-time
   priority unless bounded by `rctl pcpu`; an unbounded RT controller
   driven by an agent's syscall loop starves the host.
2. The sandbox jail: `allow.sysvipc` off, `enforce_statfs=2`,
   `ip4/ip6 = disable` (the resolver serves sockets),
   `security.bsd.unprivileged_proc_debug=0`, and rctl rules on the jail or
   coalition for `maxproc`, `vmemoryuse`, `swapuse`, `openfiles`
   (`children.max` bounds nested jails, not processes).
3. The controller `pdfork`s; the child (still running launcher code, not
   yet attached) `jail_attach`es the sandbox, drops to the **agent uid**
   (different from the controller's; lowering is permitted), and signals
   readiness, then blocks; the controller `DQ_IOC_ATTACH`es the procdesc
   (D55 makes the handshake race-free); the child execs the agent. A
   coalition descriptor gives lifecycle and kill (D33).
4. The plane rule: switchboard and userland providers refuse requests whose
   caller trailer says `attached`; **kernel services** do not read the
   trailer, so `mac_capability_core` refuses `CALL`/`SENDMSG` from an
   attached caller on services flagged `MAC_CAPABILITY_SVC_NO_ATTACHED`
   (default on for isolation, system, mount, node, accounting) (D47, D61).
   The launcher must leak no instance descriptor into the child; that is
   descriptor hygiene the kernel cannot supply.
5. Resource bounds the attachment itself enforces: a per-queue in-flight
   byte bound for pending served writes, charged to the requester's
   `racct`/`swap_reserve_by_cred` at dirtying time (dirty served pages
   cannot be swapped), with the fault blocking, deadline-bounded, at the
   bound; and a per-requester (per-nonce) in-flight event quota below the
   queue depth so one requester cannot cause `EIO` for another (D59, D60).

With that, what the attachment adds over the jail alone is the thing
nothing else provides: the agent's files and sockets are what the
controller says they are, transparently, with every operation visible.
What the agent can still do, stated honestly: read jail-visible sysctls
and `kenv`; hold ptys; consume CPU up to its rctl bounds; and, after a
controller compromise, everything the controller holds — which is why
step 1 is not optional.

## 12. Sockets

A served socket is a `struct socket` created by a new
`socreate_proto(protosw, type, cred, td, &so)` in `uipc_socket.c` — the
`socreate` sequence with a caller-supplied, `pr_init`-filled protosw,
needed because `socreate` only reaches protosws registered in a domain and
TCP owns `(SOCK_STREAM, IPPROTO_TCP)`. dq keeps one protosw per presented
`(domain, type, protocol)`: `pr_domain` is the real domain (`inetdomain`,
`inet6domain`, `localdomain`), `pr_protocol` the presented protocol,
`pr_flags` by type (`STREAM`: `PR_CONNREQUIRED|PR_WANTRCVD`; `DGRAM`:
`PR_ATOMIC|PR_ADDR`; `SEQPACKET`: `PR_ATOMIC|PR_CONNREQUIRED`), plus
`PR_OPAQUEPCB` (0x200). `SO_DOMAIN`, `SO_PROTOCOL`, `kinfo_file`, OES and
`sotoxsocket` read those fields; `SO_TYPE` reads `so_type`.

Data goes through ordinary mbuf sockbufs (no `PR_SOCKBUF`), so the
generic `soreceive`/`sosend`/`sopoll`/`sokqfilter` give `MSG_PEEK`,
`MSG_WAITALL`, timeouts, `FIONREAD`, AIO, `fstat` sizes and readiness. The
dq protosw: `pr_send` turns the chain into ordered `SEND` events and
`sowwakeup`s as the controller takes bytes; `pr_rcvd` posts `RCVD` when
subscribed; `pr_connect` posts `CONNECT`, marks connecting, returns 0
(`kern_connectat` sleeps on `so_timeo`); `pr_bind`, `pr_listen`,
`pr_shutdown`, `pr_disconnect`, `pr_ctloutput` (`SOCKOPT`), `pr_control`
(`IOCTL`); `pr_sockaddr`/`pr_peeraddr` from the identity; `pr_accept`
fills the child's peer; `pr_rcvoob` → `EINVAL` (no OOB data);
`pr_sendfile_wait`/`pr_ready` implemented so `sendfile` to a served stream
works; `pr_detach` posts `CLOSE`. `SO_LINGER` is honoured by the
controller's `EOF`/`RESET` completing the disconnect.

`PR_OPAQUEPCB` makes every site that assumes an `inpcb` behind
`AF_INET`/`IPPROTO_TCP` treat `so_pcb` as opaque: ktls (12 sites, reached
only through `tcp_ctloutput`, which dq's `pr_ctloutput` never calls —
stated invariant); `SO_SPLICE` (`uipc_socket.c:1807`) → `EOPNOTSUPP`; the
listen-overflow log (`:1191`) → presented address; `mac_portacl` bind
autoport (`mac_portacl.c:445`) → skipped; Linux `IP_MTU`
(`linux_socket.c:1109`) → `ENOPROTOOPT`; `kern_sendfile.c:968` → mapped
mbufs; **`soo_ioctl` `'i'`/`'r'` groups** (`sys_socket.c:277-282`) →
`IOCTL` event or `ENOTTY`, never `ifioctl`/`rtioctl`; **`audit_arg_file`**
(`audit_arg.c:693-706`, `INP_CHECK_SOCKAF`) → skip; `kf_sock_inpcb` export
→ 0 (D26).

Control messages: `SCM_RIGHTS`, `SCM_CREDS`, `SCM_CREDS2`, `SCM_TIMESTAMP*`
are refused on served sockets in both directions (`sendmsg` →
`EOPNOTSUPP`; `DELIVER` with a control chain → `EINVAL`); `SO_PASSRIGHTS`
on a served `AF_LOCAL` socket → `EOPNOTSUPP` (D25). `RESET`/`REVOKE`:
`sbflush(so_rcv)` after `soisdisconnected` so delivered-but-unread and
`MSG_PEEK`ed data is gone (I10). Isolation's `fi_net_check` and OES socket
events: a served socket is evaluated under the **controller's** network
authority at `MINT` (`FI_OP_CLAIM_NET` by the controller), not the
requester's presented tuple; requester-side checks see `PR_OPAQUEPCB` and
defer; OES socket events carry `OES_SOCK_META_PRESENTED` (D23). Served
sockets are listed through `dq.observe` (7.2).

## 13. Exec

Stage 0 defines the image source (6.2); stage 3 adds the dq backend:
`RESOLVE op=EXEC` → `FD`; `is_read` posts `READ`; `imgp->object` is the dq
object; `is_first_page` grabs page 0 through the dq pager (wired for the
exec); `is_path` is the presented path; `is_nosuid` is true (I3);
`is_set_text` posts `SET_TEXT`; `is_mac_transition` calls
`mac_file_check_exec` and `mac_file_execve_relabel`, which every policy
that implements the vnode equivalent (OES `AUTH_EXEC`, veriexec, mac_abac,
isolation, capprotect) implements too — veriexec treats a served image as
unverified and denies under enforcement (D28). Nonce rotation runs in the
core (I4). `p_image = {DQ, fp}`; `p_textvp = NULL` with the stage-0
fallbacks in place. Software authority never matches a served image
(`cap_authority_exec_prepare` skipped; `authority_setid` false).

Under an attachment, for any image (served or real): the I5(a) predicate
(`credential_setid`, `authority_setid`, `will_transition`; not
`will_relabel`) is evaluated between `kern_exec.c:710` and `:800`, where
refusal is clean (`exec_fail_dealloc` frees `newcred`) and the old image
continues; there is no detach path (D48). `fexecve` of a served file uses
the same backend; of a real file, the same predicate.

## 14. Observation

- **MAC.** Every dq fileop calls its `mac_file_check_*` hook; the file is
  recognisable as served by `f_type == DTYPE_DQ`. OES, isolation and
  mac_abac implement the file hooks for `DTYPE_DQ` files in stage 1a/1b
  (they keep using vnode hooks for vnodes, so nothing is evaluated twice).
- **OES.** New events `OES_EVENT_AUTH/NOTIFY_FILE_{OPEN,READ,WRITE,STAT,
  SETATTR,FSYNC,LOCK,IOCTL,MMAP,CLOSE,EXEC,CHDIR,CHROOT}` with a file
  object carrying `OES_FILE_META_PRESENTED`, the controller nonce and the
  object id; plus `OES_EVENT_NOTIFY_DQ_REPLY` `(op, object, controller
  nonce, errno, byte count)` for every controller reply — a count, never
  content (D41) — so audit can reconstruct what was served. OES socket
  events on served sockets carry `OES_SOCK_META_PRESENTED`.
- **Observer capability** (7.2) for `procstat`, `sockstat`, and
  controllers' own monitoring; metadata-only by default.
- The `mac_capability` caller trailer carries `attached` so switchboard
  and providers can apply the agent rule (D47).

## 15. Concurrency, blocking, lifecycle

1. Serialization as today, before posting: `foffset_lock`, the object's
   range lock, `sblock`. Requesters see unchanged atomicity.
2. A waiter holds only those. There is no vnode, so no vnode lock.
3. Replies in any order from any controller thread; one waiter per id;
   replies for unknown or interrupted ids are discarded and counted.
4. A process holding a queue is refused operations on that queue's objects
   with `EDEADLK`; the test is by the queue reference in the caller's open
   files, not by pid, so a `pdfork`ed helper is covered (D16). A
   controller is never attached to its own queue (D56, D57), so its own
   lookups never reach it.
5. Syscall waits are interruptible (`PCATCH`); page-fault waits break on
   `SIGKILL`/`P_WEXIT`/deadline only; `SIGKILL` and `P_WEXIT` always break
   (I12); the deadline is configurable per object and system-wide (D3).
6. Contexts that never wait (I11): `fo_close`, `pgo_dealloc`,
   `pgo_putpages` from `pageproc`/laundry, `vm_object_terminate`, anything
   under `exit1`. They post and continue; the queue owns the result.
7. Queue full → `EIO` at once.
8. `REVOKE` and queue close per I10: wake waiters with `EIO`, unmap and
   drop pages, flush socket buffers, clear knotes, mark revoked, complete
   pending async page operations with error; existing references remain
   closable.
9. Object ids are never reused on a queue.

## 16. What the requester sees

| Call | Answered by | Indistinguishable? |
|---|---|---|
| `read` family, `aio_read`, `O_DIRECT` | `READ` / pages | yes |
| `write` family, `ftruncate`, `fsync`, `fallocate`, `fspacectl` | events | yes |
| `mmap` (all modes), faults, `msync` (incl. `MS_SYNC`), `mincore`, `mlock` | dq pager | yes; `MAP_SHARED|PROT_WRITE` is `EACCES` unless allowed, as on a read-only fd |
| `sendfile` | `getpages_async` | yes |
| `execve`, `fexecve` | stage 3 | yes with `ALLOW`; `EACCES` before stage 3 |
| `fstat`/`stat`/`lstat`/`fstatat`, `fstatfs`/`statfs`, `fpathconf`/`pathconf` | identity | yes, incl. `st_dev/ino/gen` |
| `F_KINFO`, `procstat -f`, `procstat -v`, `/proc/self/maps`, `realpath`, `/dev/fd/N` readlink, `getcwd` | `fo_fill_kinfo`, `pgo_kinfo`, attachment | yes |
| `fcntl` flags/dup/readahead; `F_GETFL` | generic / `fo_fcntl` | yes (no served bit exists in `f_flag`) |
| `flock`, `F_SETLK*`, `F_OFD_*`, `O_EXLOCK` | `LOCK` events; the controller can proxy to the real file's locks | yes |
| `fchmod`, `fchown`, `futimens`, `fchflags` (any `dp_write`) | `SETATTR` | yes |
| `ioctl` | `IOCTL`/`ENOTTY` | yes for the ioctls a regular file answers; pointer-embedding ioctls are `ENOTTY` |
| `poll`, `select`, `kqueue` (all `EVFILT_VNODE` notes) | local + `NOTIFY_VNODE` | yes |
| `inotify` on a served dir | `INOTIFY` push | yes |
| every `*at()` relative to a served dir; absolute paths under a served root; `socket`, `socketpair` | `RESOLVE` | yes |
| `getdirentries` | `fo_readdir` | yes |
| `dup`, `fork`, `rfork` (any flags), `pdfork`, `vfork`, `SCM_RIGHTS` within the attachment, `/dev/fd/N` reopen | shared file | yes |
| `SCM_RIGHTS` or channel transfer to a process outside the attachment | refused (I6) | **no**, by design |
| ACLs, extattrs | events / `EOPNOTSUPP` | yes |
| `getfh` | `RESOLVE ATTR` with a handle; `fhopen` of it `ESTALE` | **partial**, documented (*open* 21.2) |
| `__mac_get_fd` | empty label | yes (D22) |
| `/dev/fd/N/child` on a served `N` | `ENOTDIR` | **no**, documented (D29) |
| `O_NAMEDATTR` on a served start | `EOPNOTSUPP` | **no**, documented (D43) |
| `kcmp` | `fo_cmp` | yes |
| `getmntinfo`, `getfsstat` | nothing exists to hide | yes |
| sockets: data, `MSG_PEEK`, `MSG_WAITALL`, `shutdown`, `connect`, `bind`, `listen`, `accept`, names, `SO_*`, `SO_LINGER`, `sendfile` | buffers / events / identity | yes |
| `MSG_OOB` | `EINVAL` | yes (as a socket with no OOB data) |
| `SCM_RIGHTS`/`SCM_CREDS` on a served `AF_LOCAL` socket; `SO_PASSRIGHTS` | `EOPNOTSUPP` | **no**, documented (D25) |
| protocol-level `getsockopt` | `SOCKOPT` | yes when answered; `ENOPROTOOPT` otherwise is a difference |
| `SIOC*` interface/routing ioctls on a served socket | `IOCTL` event | yes (never the real interfaces) |
| kTLS, `SO_SPLICE` | `EOPNOTSUPP` | **no**, documented |
| `sockstat`/`netstat` | `dq.observe` through a provider | listed under dq to a holder of the capability; absent otherwise |
| set-id exec, attributed exec, `setcred`, `NODE_OP_SET_CRED`, BSDAuth elevation, `jail_attach` while attached | I5 | **no**, by design: unchanged uid / no attributes / `EPERM` |
| `PT_COREDUMP` to a served file, livedump, `ttyhook` | `EINVAL` | **no**, administrative |
| timing | — | **no**, not a goal |

Every "yes" is a test in section 17; every "no" is in `dq(4)`.

## 17. Test matrix

Tier: VM, capability plane on (`tools/build/fuchsia/vm-provider.sh`),
`GENERIC` (INVARIANTS+WITNESS) during development, `GENERIC-NODEBUG` for
the final run of each stage; `tests/sys/dq/` (kernel) and
`lib/libdq/tests/` (controller library), ATF C; `is_exclusive` where
tunables change; every test skips when `/dev/dq` is absent. Oracle method:
the same operation on a real object and a served object presenting its
identity, results compared field by field (`struct stat`, `struct statfs`,
`kinfo_file`, `kinfo_vmentry`, `pathconf`, errno, `revents`, `kevent`,
bytes). WITNESS must stay clean throughout.

| Group | Tests |
|---|---|
| stage 0 | full kyua suite unchanged plane-on; per-fileop unit tests on vnode, pipe, socket, shm, `O_PATH`, **FIFO, pts master, tty, DRM fd** (identical results and errnos to a pre-stage-0 kernel, recorded as fixtures); `fsync(fifo)` under INVARIANTS does not panic; `F_ISUNIONSTACK` on a unionfs mount; image source: full exec suite, setuid, `ETXTBSY`, coredump, `procstat -b`, stack growth, `aio_read` into an ungrown stack page; `mac_test_hooks` sees each new hook; channel fd transfer calls `mac_file_check_receive` |
| I3 | `MINT` set-id → `EINVAL`; served `04755` image → euid unchanged |
| I4 | `IDENTITY_OP_SELF` nonce differs across served and real exec |
| I5 | set-id real image exec'd under attachment runs with unchanged uid; attributed real image exec'd under attachment has no attributes (switchboard resolve denied); `will_transition` image → `EACCES`, process continues, still attached; truncated `04755` image → `ENOEXEC`, still attached; `#!` chain re-evaluated; `setcred`, `NODE_OP_SET_CRED`, `jail_attach` on attached → `EPERM`; root launcher's root child stays root (documented) |
| I6 | `SCM_RIGHTS` to an unattached process refused; served fd on a `mac_capability` channel message to an unattached peer refused; `CALL`-reply fd refused; stage 1a/1b minted fd `CAP_XFER_NONE`; controller holds its own objects |
| I7 | `execve` of a served image works (user-origin); interpreter lookup never gets `FD` (KASSERT under INVARIANTS); `kldload`/coredump/ktrace through a served root → defined errno, no `FD`; Linux-ABI `open` of a served path works; kernel-origin `socreate` (NFS mount) never consulted |
| I8 | `openat(limited_dirfd)` → installed rights = caps ∩ `dp_rights`, ioctl/fcntl limits propagated; `cap_rights_limit(dirfd, -CAP_LOOKUP)` → `ENOTCAPABLE` with no event; capability mode absolute path → `ENOTCAPABLE` with no event; `BENEATH` reply `/a` vs `/ab`, `/a/../x` → `ENOTCAPABLE`; `RINROOT` post-check; `O_NAMEDATTR` refused |
| I9 | every op has a hook call and an OES event with presented flag and nonce; `require_auth_clients=1` denies served exec without a client; `NOTIFY_DQ_REPLY` has a count only; observer without `DQ_OBS_F_DATA` sees lengths, not bytes; `dq.observe` lists objects; uid-0 shell without the capability sees nothing |
| I10 | `MAP_SHARED` after `REVOKE` → `SIGBUS`; `MAP_PRIVATE` written copy survives (documented); fork child's mapping → `SIGBUS`; `DELIVER`+`MSG_PEEK`+`RESET` → `ECONNRESET`, not data; aio/sendfile across `REVOKE` → `EIO`, KASAN clean; knote across close; `INVALIDATE` observed through an existing mapping without `munmap` |
| I11 | slow controller: `exit` completes, laundry thread not blocked, `munmap` returns |
| I12 | deadline → `EIO`; `SIGKILL` breaks every wait; fault on a served mapping during `SIGCHLD`/`SIGALRM` → no `SIGBUS` |
| I13 | assertion: no `pwd` field ever points at anything but a real vnode; `F_GETFL` shows no served bit |
| identity | `fstat` incl. `st_dev/ino/gen`; `fstatfs`; `fpathconf`; `F_KINFO`; `realpath`; `/dev/fd/N` readlink; `procstat -f`; `procstat -v` and `/proc/self/maps` of a mapped served file; `getcwd` after served `fchdir`; `__mac_get_fd` |
| data | `read` oracle; chunk boundaries at `dq_max_io`; EOF; redaction identical via `read`/`pread`/`mmap`/`sendfile`/`readv`/`aio_read`; two objects same identity different bytes, no leak; `mincore` residency oracle; `msync(MS_SYNC)` returns after `WRITE_ASYNC` completion |
| write | `DENY`: `open(O_RDWR)` → `EACCES` at `RESOLVE`; `EVENT`: oracle, short write, truncate, `fallocate`, `MAP_SHARED` writeback; `fchmod` under `DENY` served |
| locks | `SETLKW` blocks until reply; `GETLK` oracle; `closef` posts `UNLOCK_ALL` only for objects that locked; cross-process `flock` against a real holder via controller proxying |
| kqueue/inotify | all `EVFILT_VNODE` notes oracle; inotify oracle on a served dir |
| resolution | each `*at` family and each path-only syscall through a served dir/root; nested components; `..`; `AT_EMPTY_PATH`/`O_EMPTY_PATH` on a served file; served root + dynamic binary runs (interpreter `PASS`); `PASS` from attached process resolves against real `pd_pwd`; `chroot_refuse_vdir_fds`; `/dev/fd/N/child` → `ENOTDIR` |
| attachment | `rfork(RFCFDG)`, `rfork(RFCFDG\|RFPROC)`, `vfork`, Linux `clone`, `pdfork` stay attached; `fchdir; close` then `getcwd` and `AT_FDCWD` open work; `PASS`ed `chdir` clears `dr_cwd`; `ATTACH` to an exec'd child → `EBUSY`; `ATTACH` during the child's `P_INEXEC` → `EBUSY`, and a set-id exec racing `ATTACH` never yields a privileged attached process (D55); `ATTACH` on a child sharing its `pwddesc` (plain `fork`, `clone(CLONE_FS)`) → `EBUSY` (D56); attached process in the recipe jail: `mac_capability_channel_create` + switchboard resolve refused with `attached` in the trailer; `CALL` on isolation/system/mount/node/accounting instances from an attached caller refused (D61) |
| resources | per-requester in-flight quota: one requester saturating its quota leaves another's operations unaffected (D60); `max_inflight_bytes`: a `MAP_SHARED` dirtier against a stalled controller blocks at the bound, `racct` shows the charge, the host stays responsive (D59) |
| recipe (11.6) | the full agent recipe runs end to end under `vm-provider.sh`: controller outside the jail, child `jail_attach` + uid drop + handshake + `ATTACH` + exec; agent `ptrace`/`kill` of the controller fails; agent `connect` is served; `rctl` bounds hold under a fork bomb |
| dir | `readdir` oracle vs `getdents` on a real dir; cookies; `eof` |
| concurrency | 8 threads `pread`, replies reversed; shared offset from 2 threads; signal → `EINTR` + `INTERRUPT`; depth exhausted → `EIO` + drop + seq gap; `EDEADLK` incl. `pdfork` helper; in-flight limit |
| lifecycle | `CLOSE` once across dup/fork/SCM_RIGHTS/reopen/mapping-outlives-fd/attachment-holds-cwd; `REVOKE`; controller exit → every requester op fails, no hang, no panic; ids not reused |
| sockets (stage 2) | identity oracle vs real TCP: `SO_DOMAIN/TYPE/PROTOCOL`, names, `kinfo_file`; `socket()` in capability mode without `PR_CAPATTACH` → `ECAPMODE` with no event; `prison_check_af` denial precedes any event; protocol 0 arrives resolved; `socketpair` minted connected; async connect, `EINPROGRESS`, `poll`; `DELIVER`/`PEEK`/`WAITALL`; `SEND` order, `taken < len`; `shutdown`; `RESET`; `listen`/`ACCEPTED`/`accept`; `sendfile`; kTLS/`SO_SPLICE` → `EOPNOTSUPP`; `SIOCGIFCONF`/`SIOCSIFFLAGS` → event, not real interfaces; `sendmsg(SCM_RIGHTS)` and `DELIVER` with cmsg refused; `MSG_OOB`; `SO_LINGER` close returns; `TCP_NODELAY` oracle; `audit_arg_file` on a served socket; observer lists it |
| exec (stage 3) | served `/bin/sh` runs; exec path in OES event is `di_path`; `SET_TEXT`; `DENY` → `EACCES`; `fexecve`; stack growth; `mac_grantbylabel` loaded with a served image: no panic; veriexec enforcement denies |
| negative | identity validation (`EINVAL` cases incl. unnormalized paths, mount name not a prefix); `mmap_shared_write=ALLOW` with `write=DENY` → `EINVAL`; non-controller `open("/dev/dq")` refused under the plane; `MINT_OBSERVER` fd cannot reply |

## 18. Staging

One logical change per commit; each commit lands code, tests, man pages
and book text together. Each stage ends with a plane-on VM run and an
independent review before it is committed. Stage 0 lands on `dev` as its
own series (D2); stages 1-5 on `proxy/objects`, rebased on `dev` after
stage 0 lands.

| Stage | Content |
|---|---|
| 0 | descriptor completeness (4.1, 6): 11 fileops; ledger; image source and `p_image`; `mac_file_*` hooks incl. `receive` on channel installation; `pgo_sync`/`pgo_kinfo`; `sendfile_getobj` seam |
| 1a | `/dev/dq`, queue, `MINT FILE`, `READ`, identity, `REVOKE`, lifecycle, observer queue, `dq.observe`, OES file events (open/read/stat/close) |
| 1b | writes, `SETATTR`, `FSYNC`, dq pager (full ops), `mmap`, `sendfile`, cache `DATA`, locks, ioctl, kqueue notes, `INTERRUPT`, deadlines, `mac_dq`, isolation/abac file hooks |
| 1c | attachment in `pwddesc`, four choke points, `RESOLVE` incl. `SOCKET`, `DIR`/`SYMLINK`, `READDIR`, virtual cwd/root, I5(b) refusals, `attached` trailer, inotify, launcher example |
| 2 | sockets |
| 3 | exec from a descriptor |
| 4 | global attachment (11.5), `BSDDescriptorQueue` provider |
| 5 | `CDEV` kind |

Both sockets and exec are required (D1); order 2 then 3 because stage 3
depends on the `p_textvp` audit landing with stage 0 and the served-root
resolution of stage 1c, while stage 2 depends on neither. Stage 0 is not
blocked by any open item; stage 1c depends on D38-D46 as recorded.
`build-bsd` is unaffected until stage 4 adds a provider bundle.

## 19. Alternatives considered

| Alternative | Why not |
|---|---|
| served objects as vnodes on a hidden filesystem (rev 1) | action on a filesystem; hidden mount, visibility exceptions, path/statfs overrides; waits with the vnode locked |
| served cwd/root as NULL `pwd` fields (rev 2) | crashes in every `pwd` consumer; `pwd_ensure_dirs` fails open to `rootvnode` |
| a sentinel vnode in `pwd` for served cwd/root | avoids the crash but puts a vnode into the design; the resolver-owned virtual namespace needs none |
| virtual cwd/root as object ids (rev 3) | dangles after `fchdir; close` |
| resolution prologues at 23 syscall entry points (rev 2) | runs before Capsicum/audit inside `namei`; misses 16 path-only syscalls and every kernel-origin caller; `/dev/fd/N/child` cannot use it |
| `UIO_SYSSPACE` as the kernel-origin criterion (rev 3) | `do_execve` and Linux compat copy paths in first (`kern_exec.c:561`) |
| attachment inherit in `kern_fork.c` (rev 3) | `rfork(RFCFDG)` builds its `pwddesc` in `pdinit`; a one-call escape |
| SMR decline in `cache_fplookup_dirfd` (rev 3) | `AT_FDCWD`/absolute starts never pass it; the partial fallback via `ni_startdir` bypasses all |
| `RESOLVE op=SOCKET` in `kern_socket` (rev 3) | Capsicum, jail and protocol defaulting happen inside `socreate` |
| refuse set-id exec under attachment, or detach-then-exec (rev 3) | detach-then-exec left an unattached process when exec failed after the detach point; refusal breaks `ping`/`su` needlessly; `NOSUID` semantics run them unprivileged and their privileged operations become served `RESOLVE`s |
| observers with data by default (rev 3) | a content tap into `/var/log` |
| a per-process syscall table routing to userland | catches syscalls only (kernel-origin lookups escape); runs before the kernel's enforcement; visible ABI; nothing for the descriptor side |
| fusefs | cannot present `st_dev/gen/fsid/path`; visible mount; no `poll`; not loadable late; mount service rejects `from` |
| `struct file` wrapper over a real vnode | leaks at every `f_type` dispatch — the ledger this design reworks instead of avoiding |
| filter on the real vnode / nullfs-style transform | shared page cache; length-preserving only |
| userland relay through a pipe; `LD_PRELOAD`; ptrace interposition | not transparent |
| `mac_capability` service as the queue | no kernel-waits-for-user pattern; single-reply `co_call` |
| `OBJ_SWAP`-based pager (rev 2) | `vm_fault` zero-fills without `getpages`; swap pager asserts |
| local lock table in the kernel (rev 2 `dp_lock = LOCAL`) | `kern_lockf.c` is vnode-coupled and a KBI for NLM/NFS; a kernel table cannot conflict with the real file's locks |
| `f_ops` swap for revoke (rev 2) | no precedent, no ordering |

## 20. Decision record

| # | Date | Decision | Source | Reason |
|---|---|---|---|---|
| D1 | 2026-11-06 | Both sockets and exec-from-a-descriptor are required consumers; order 2 then 3 | user | both use cases wanted; dependency order |
| D2 | 2026-11-06 | Stage 0 lands on `dev` as its own series before any dq code | user | valuable and reviewable alone |
| D3 | 2026-11-06 | Deadline configurable: `kern.dq.default_deadline_ms` (30000) and per object; `0` = none | user | "forever" hangs exit; user wants it configurable |
| D4 | 2026-11-06 | Start with the parent path (launcher attaches); global identification deferred to stage 4 | user | |
| D5 | 2026-11-06 | The action is on the descriptor; no filesystem, no FUSE, no vnode represents anything served | user | principle 1; rev 1 withdrawn |
| D6 | 2026-11-06 | Kernel locks and internals may be reworked to make this work | user | "Apple had to do that" |
| D7 | 2026-11-06 | Resolution consulted at the `namei` choke points, not per syscall | kernel review | Capsicum/audit ordering; completeness incl. kernel-origin callers |
| D8 | 2026-11-06 | Kernel-origin lookups get `PASS`/errno only (I7) | both reviews | no controller-supplied modules or interpreters |
| D9 | 2026-11-06 | Virtual cwd/root live in the attachment; the kernel `pwd` stays real; no sentinel vnode | user suggestion + kernel review | rev 2's NULL fields crashed and failed open; a sentinel is still a vnode |
| D10 | 2026-11-06 | The ELF interpreter for a served-root process loads via `PASS` from the real `pd_pwd` | kernel review | dynamic binaries must run before stage 3 |
| D11 | 2026-11-06 | Cache contract: pages exist while mapped/wired/cached, dropped with `pmap_remove_all`; "serve once" withdrawn | kernel review | unimplementable as specified |
| D12 | 2026-11-06 | dq pager is its own type with every op; never `OBJ_SWAP`; async `putpages`/`getpages_async`; `pgo_sync`, `pgo_kinfo` | kernel review | `vm_fault` zero-fill; laundry blocking; `msync`; `procstat -v` |
| D13 | 2026-11-06 | Image-source abstraction in stage 0; nonce rotation in the core; served images `NOSUID`, never attributed, never pinned authority; `p_image`; `p_textvp == NULL` overload removed | both reviews | root via served exec; identity carry-over; stack growth |
| D14 | 2026-11-06 | Locks `EVENT`-only; `kern_lockf.c` untouched; `UNLOCK_ALL` fast path | kernel review | KBI for NLM/NFS; controller can proxy real locks |
| D15 | 2026-11-06 | Revoke is a state checked under the object mutex; one fileops table | kernel review | no `f_ops` swap precedent |
| D16 | 2026-11-06 | `EDEADLK` by queue reference in the caller's files, not pid | both reviews | `pdfork` helpers |
| D17 | 2026-11-06 | I11 blocking policy: `fo_close`, `exit1`, pager teardown, laundry never wait | kernel review | `P_WEXIT` ignores `PCATCH` |
| D18 | 2026-11-06 | OES/isolation/abac implement `mac_file_*` for `DTYPE_DQ` files in stage 1; vnode operations not evaluated twice | security review | principle 4 from the first served stage |
| D19 | 2026-11-06 | Set-id bits rejected in identities; dq image backend `NOSUID` (I3) | security review | root via served exec |
| D20 | 2026-11-06 | `dp_rights` default `CAP_ALL_RIGHTS`; intersected with dirfd caps at `RESOLVE` (D50); the queue fd is hardened | security review (modified) | transparency of `cap_rights_get`; `openat` semantics |
| D21 | 2026-11-06 | Observation is a capability (`dq.observe`, observer queues); no uid-0 sysctls | security review | authority model |
| D22 | 2026-11-06 | `__mac_get_fd` on a served file returns an empty label | security review | real files return a label |
| D23 | 2026-11-06 | Served sockets evaluated under the controller's network authority at `MINT`; requester-side checks defer on `PR_OPAQUEPCB` | kernel review | avoid double enforcement on a presented tuple |
| D24 | 2026-11-06 | `de_caller` from the file's owner, never aiod/kernel threads | both reviews | |
| D25 | 2026-11-06 | `SCM_RIGHTS`/`SCM_CREDS*` refused on served sockets both ways; `SO_PASSRIGHTS` `EOPNOTSUPP` | security review | confused deputy inside the requester |
| D26 | 2026-11-06 | `'i'`/`'r'` ioctl groups and `audit_arg_file` added to the opaque-pcb sites | both reviews | real interfaces reachable through a served socket |
| D27 | 2026-11-06 | All `EVFILT_VNODE` notes and inotify supported via pushes | security review | silent dead watches |
| D28 | 2026-11-06 | veriexec denies served images under enforcement | both reviews | a served image is never verified |
| D29 | 2026-11-06 | `/dev/fd/N/child` on a served `N` is `ENOTDIR`, documented | kernel review | `VOP_LOOKUP` inside `namei` |
| D30 | 2026-11-06 | The ledger is generated by a recorded command and committed | kernel review | "102" was not reproducible |
| D31 | 2026-11-06 | `socket(2)`/`socketpair(2)` of an attached process consult the resolver | user's original notes | otherwise sockets are real and `connect` unseen |
| D32 | 2026-11-06 | *(superseded by D48)* set-id exec under attachment refused by default with an opt-in detach | user's original notes | — |
| D33 | 2026-11-06 | The launcher example pairs the attachment with a coalition descriptor | user's original notes | subtree lifecycle and kill |
| D34 | 2026-11-06 | Data crosses the queue by copy; no mapping of requester memory into the controller | user's original notes considered | performance not a goal; controller cannot touch requester memory |
| D35 | 2026-11-06 | No rtld changes; served shared libraries work from stage 1b | user's original notes | |
| D36 | 2026-11-06 | Controller deployment (real-time priority, capability-mode birth, jail, delivered root fds) is unit configuration | user's original notes | requesters wait on the controller |
| D37 | 2026-11-06 | Stage-4 shape: attach decision once per exec; parent > brand > ABI class > OES `AUTH_ATTACH`; inputs decided in stage 4 | user discussion | OES must not be per-operation; branding gives a static, signed answer |
| D38 | 2026-11-06 | Attachment inherited/released in `pdinit`/`pdcopy`/`pdshare`/`pdunshare`/`pddrop` | kernel re-review | `rfork(RFCFDG)` escape otherwise |
| D39 | 2026-11-06 | SMR choke point is `cache_can_fplookup`; `ni_startdir` callers not consulted | kernel re-review | `AT_FDCWD`/absolute SMR starts; partial-fallback bypass |
| D40 | 2026-11-06 | `RESOLVE op=SOCKET` inside `socreate` after Capsicum/jail/`pffindproto`; `SOCKETPAIR` single event; kernel-origin `socreate` never consulted | kernel re-review | no event before kernel checks; resolved protocol |
| D41 | 2026-11-06 | Observers metadata-only by default; `DQ_OBS_F_DATA` separate right; `NOTIFY_DQ_REPLY` carries counts; `dq.observe` per queue set | security re-review | content tap; tenant isolation |
| D42 | 2026-11-06 | `msync(MS_SYNC)` waits for `WRITE_ASYNC` completion in the caller | kernel re-review | durability |
| D43 | 2026-11-06 | `RINROOT` in rflags and the I8 post-check; `OPENNAMED` refused on served starts | kernel re-review | |
| D44 | 2026-11-06 | `DQ_IOC_ATTACH` takes a procdesc only; no pid form anywhere | both re-reviews | authority is a held descriptor |
| D45 | 2026-11-06 | `dr_cwd`/`dr_root` are file references; `PASS`ed `chdir`/`chroot` clear them | kernel re-review | dangling ids; virtual/real divergence |
| D46 | 2026-11-06 | `ATTACH` only to a not-yet-exec'd pdfork child; `ATTACH_SELF` with implicit `PASS` for the controller's own lookups | kernel re-review | namespace takeover; `EDEADLK` on the launcher |
| D47 | 2026-11-06 | Caller trailer carries `attached`; switchboard/providers refuse attached requesters in the agent recipe; attachment documented as namespace substitution, not sandbox | security re-review | discovery route hands out real objects |
| D48 | 2026-11-06 | **No detach path.** Under attachment exec never changes credential or authority (`NOSUID` semantics, `authority_setid` false); `will_transition` images refused before `exec_new_vmspace`; non-exec credential changes and `jail_attach` refused | security re-review, kernel re-review | detach-then-exec escape; privilege via `setcred`/`NODE_OP_SET_CRED`; `PASS`ed attributed images |
| D49 | 2026-11-06 | I7 uses a positive `NI_DQ_FD_OK` set only at user-origin syscall entries | both re-reviews | `do_execve` uses `UIO_SYSSPACE` |
| D50 | 2026-11-06 | `RESOLVE FD` rights = start-dirfd caps ∩ `dp_rights`; paths normalized; I8 restated as a label guarantee | security re-review | Capsicum widening; byte-prefix bypass |
| D51 | 2026-11-06 | Served mark is `DTYPE_DQ`, never an `f_flag` bit | security re-review | `F_GETFL` leak |
| D52 | 2026-11-06 | `mac_file_check_receive` on channel and `CALL`-reply fd installation | security re-review | I6 completeness |
| D53 | 2026-11-06 | Page-fault waits break only on `SIGKILL`/`P_WEXIT`/deadline | security re-review | interrupted fault = `SIGBUS` |
| D54 | 2026-11-06 | Stages 1a/1b: minted fds `CAP_XFER_NONE`; the minting controller is exempt from I6 | security re-review | no attachment exists yet |

| D55 | 2026-11-06 | `ATTACH` refuses during `P_INEXEC` or after `P2_DQ_EXECED`, atomically with the install under `PROC_LOCK`; `do_execve` re-reads the attachment after `execve_block` | security final pass A1 | attach racing an in-progress set-id exec |
| D56 | 2026-11-06 | `ATTACH` requires an unshared `pwddesc` (`pd_refcount == 1`); attachment is per-`pwddesc` | security final pass A2 | attach on a shared `pwddesc` reaches siblings or the controller |
| D57 | 2026-11-06 | `ATTACH_SELF` removed | security final pass A9 | contradicts the `attached`-trailer rule |
| D58 | 2026-11-06 | Agent recipe: controller outside the jail with delivered capabilities, shielded by capprotect, `CLOFORK_LOCKED`, no unbounded RT; child `jail_attach`es and drops uid before attach; `unprivileged_proc_debug=0`; rctl bounds on the jail/coalition | security final pass A4-A6, A8 | controller cannot connect from a no-network jail; same-uid `ptrace`; `children.max` bounds jails |
| D59 | 2026-11-06 | `kern.dq.max_inflight_bytes` charged to the requester's `racct`/swap reserve; fault blocks at the bound | security final pass A3 | pending served writes are an uncharged memory sink |
| D60 | 2026-11-06 | Per-requester in-flight quota below queue depth | security final pass A8 | cross-tenant `EIO` |
| D61 | 2026-11-06 | `MAC_CAPABILITY_SVC_NO_ATTACHED` on kernel services, refused in `mac_capability_core` for attached callers | security final pass A7 | kernel services never read the trailer |
| D62 | 2026-11-06 | Branded images never on the path that launches their controller | security final pass A11 | boot deadlock |
| D63 | 2026-11-06 | Moved vnode bodies are `vn_*(fp)` installed explicitly in `pipeops` (FIFO), `ptsdev_ops`, `devfs_ops_f`/`_nonpassable_f`, `linuxfileops`, `path_fileops`; no default fileop inspects `f_vnode` | kernel final pass N1, L1 | `getvnode` accepted these today; "no change" must hold for ttys, FIFOs, DRM, `O_PATH` |
| D64 | 2026-11-06 | `F_ISUNIONSTACK` via `fo_fcntl`; `fo_statfs` vnode body runs all of `kern_do_statfs`; the `kern_fsync_fp` `MPASS` is removed; `quotactl_fd` stays `ENOSYS` | kernel final pass L2-L4, L6 | `MNTK_UNIONFS` not in `statfs`; prison check needs the mount; latent panic |
| D65 | 2026-11-06 | `vm_mmap.c:470` keys on `DFLAG_PRIVWRITE` in stage 0 | kernel final pass L7 | no `f_type` test |
| D66 | 2026-11-06 | Ledger command revised (`DTYPE_FIFO`, `p_textvp`, `imgp->vp`, `contrib/openzfs`) and a fileops-table audit added before stage 0 closes | kernel final pass L10 | the command's count was called authoritative while its own audit listed misses |
| D67 | 2026-11-06 | `P2_DQ_EXECED` set at exec commit under `PROC_LOCK`, not inherited | kernel final pass N2 | attach race window; failed first exec stays attachable |
| D68 | 2026-11-06 | `p_pdeathsig` clearing skipped when set-id was suppressed by attachment | kernel final pass N3 | NOSUID residue |
| D69 | 2026-11-06 | Queue refcounted independently of `cdevpriv`; `dr_*` released with `fdrop`; `CLOSE` on a dead queue is a no-op | kernel final pass N5 | use-after-free at `pddrop` after controller exit |
| D70 | 2026-11-06 | `mac_file_check_inherit` at `fork1`/`fdcopy` and `fdcloseexec`; refusal leaves the slot empty as `O_CLOFORK` does | kernel final pass N4, R4 | plain `fork()` by a controller |
| D71 | 2026-11-06 | `DFLAG_PRIVWRITE` also on `devfs_ops_f`/`_nonpassable_f`; `futimes`/`futimens`/`fchflags` keep `EBADF` for `O_PATH` despite `path_fileops.fo_setattr` | kernel confirmation pass R1, R2 | two regressions the N1 fix would have introduced |
| D72 | 2026-11-07 | Stage-0 implementation findings: `struct fileops` grows (the spares were fewer than the eleven members); `ptsdev_ops` and `linuxfileops` are *sometimes-vnode* tables and install `vn_*_opt` (delegate when `f_vnode != NULL`, `invfo_*` otherwise); `F_READAHEAD`/`F_RDAHEAD` go through `fo_fcntl`, not `fo_fadvise` (per-open state, not range advice); the `VFCF_OFDLOCKS` half of `fcntl_ofd_check` moves into `vn_advlock`; FIFO locks go through `pipe_advlock`, which admits `F_FLOCK` only; `vn_open_vnode_advlock` stays on the vnode (the file has no table yet at open time) | stage-0 build; plane-on VM run 1 panic in `fpathconf_test:pts_master` | `posix_openpt(2)` masters and `fd_install()` linuxkpi files carry no vnode; read-ahead sets `f_seqcount`/`FRDAHEAD` |
| D73 | 2026-11-07 | Plane-on VM run 3 findings: `fdesc_setattr` drops the fdesc vnode lock around the `fo_*` calls (the node contributes only the fd), because forwarding attributes to the underlying vnode under that lock orders fdescfs before every filesystem, the reverse of fdescfs unmount (covered vnode, then fdesc root) — WITNESS LOR, recorded in `~/5bsd-issues/2026-11-07-fdescfs-setattr-lock-order.md`; `invfo_advlock` answers `EOPNOTSUPP` to `F_FLOCK` and `EBADF` otherwise, so `flock(2)` dispatches unconditionally and an anonymous pipe keeps its `EOPNOTSUPP` (`pipeops` installs `pipe_advlock` for FIFOs, so a NULL-member probe in `flock(2)` misclassified pipes); the VM provider aborts a run on any LOR, so a LOR is a failing result, not a note | run 3 LOR; `advlock_fd_test:no_vnode` | the per-syscall errno of a type-neutral refusal belongs in `invfo_*`, not in the syscall's probe |
| D74 | 2026-11-07 | Plane-on VM runs 4–5 (183/184, the broken case pre-existing): the `fcntl(2)` record-lock cases probe `fo_advlock == NULL → EBADF` right after `fget`, because `path_test:path_lock` expects the descriptor refusal before argument validation (pipes and FIFOs, whose shared table has the member, validate first); `DFLAG_PRIVWRITE` is a Capsicum matter — `PROT_WRITE` on a private mapping of a descriptor lacking `CAP_MMAP_W`, not of a read-only one (shm already allowed the latter); `vm_mmap_file` refuses `prot ⊄ maxprot` with `EACCES`, a `CAP_MMAP_R`-only shm descriptor mapped private-writable having reached `vm_map_insert`'s KASSERT (`~/5bsd-issues/2026-11-07-mmap-shm-maxprot-assert.md`); `pgo_kinfo`'s lock contract is hold-under-lock, report-unlocked, with the two observer changes listed in 4.1; `sendfile_src` carries pin/size/notice/release ops | runs 4 and 5; code reading before the shm test ran | the in-tree suite is the oracle for error order; a KASSERT reachable from userland is a stage-0 fix, not a note |
| D75 | 2026-11-07 | Image-source contract widened (6.2.1) after a 118-site survey of the exec path: lock/unlock, per-mapping text refs (`is_map_cow`/`is_map_text`, no `MAP_VN_EXEC` for dq), path/commname, authority, install/release-old, accessed and close become backend ops so the core is vnode-free; `__elfN(load_interp_file)` builds a vnode source from its own namei; `#!` re-interpret keeps `NI_DQ_FD_OK` to the first pass; five NULL-unsafe `p_textvp` consumers get fallbacks. Under independent review before code | exec survey 2026-11-07 | the 6.2 op list left vnode knowledge in the core at the lock dances, `map_insert`, `cap_authority_*` and the `p_textvp` swap |
| D76 | 2026-11-07 | `mac_file_check_{fcntl,lock,read,write,stat,setattr,fsync}` built at the fileops boundary (`docs/macf-new-hooks.md` 3.4, 3.6, 3.9–3.13): read/write/stat fast-pathed, fcntl rare-fast-pathed to skip its extra lookup, setattr takes a `vattr` holding the attribute, fsync has no fd; the exec pair lands in stage 3 with its caller. Plane-on run 6: 183/184 | run 6 | a policy chooses the layer; vnode hooks untouched |
| D77 | 2026-11-07 | 6.2.1 review adopted (6.2.2): no kernel immutability promise for a served image; dq `is_authority(EXEC)` still calls `cap_authority_exec(p, NULL, NULL)`; `is_ops != NULL` is the construction discriminator with four states; `is_first_page` references the object for both callers and the interpreter loader deallocates and `VOP_CLOSE`s (two neutral commits before the refactor); `p_image` held across fork/exit and carrying the presented path; synthesised `va_mode` without set-id bits; veriexec's file relabel invalidates the identity; nonce rotation stays in mac_capability's hooks; per-op lock preconditions | independent kernel review of 6.2.1 | seven must-fix items, all in the contract's blind spots around success-path cleanup and policy side effects |
| D78 | 2026-11-07 | Image source built (6.2.3): the vnode constructors own path/lock/audit for the vnode forms (`AUDIT_ARG_VNODE1` needs the locked vnode); `is_path` leaves the fname form's path unresolved without a parent, as today; the displaced image state is a typed `struct image_source_old` released through the ops saved at install; `is_close` takes an errno meaning "drop the reference"; `exec_check_permissions` stays exported from the backend; `pi_path` copied out under `PROC_LOCK` and `strdup`'d at fork | implementation 2026-11-07, diff-reviewed | the moved code's own invariants decided the four open points |
| D79 | 2026-11-07 | Series review ("not yet") adopted. Fixed: `pgo_kinfo` observers take the object's **vnode** under the object lock and `vref` it (any pager answering `pgo_getvp`, so tmpfs mappings keep their path and the unreferenced-handle race is gone; `vm_object_kinfo_hold` yields a `{obj, vp}` hold, the object route only for pagers with `pgo_kinfo`); `fdesc_setattr` calls `fo_setattr` only for what the fileops left and maps its `EINVAL` to the old drop rule; `DFLAG_FLOCK`/`DFLAG_RECLOCK` table flags restore the refusal-before-arguments order for every type (pipes and FIFOs included) and `FHASLOCK`/`FHASOFDLOCK` come off again on `EOPNOTSUPP`; `path_fileops` gets an advlock that answers only the close-time POSIX unlock; `image_source_old` carries the displaced `p_image` file and path; `is_path`'s dead arm is an assertion; fchflags' `VNOVAL` refusal moved back behind the descriptor; `copy_file_range`'s type probe moved back behind the mode checks; Linux `F_SET_RW_HINT` fetches the descriptor first, `getdents` keeps `EINVAL` for types with no entries, `fileattr` maps `EINVAL`→`EOPNOTSUPP`; `mac_file_check_read` precedes the zero-length shortcut; shm gets `DFLAG_PRIVWRITE` (its private mappings are COW too) with the `vm_mmap_file` refusal as backstop (`EXTERROR`); the msync test proves write-back through `mincore(2)` on a non-tmpfs file. Declared, not reverted: Linux type gates classify through `fo_stat` (a MAC stat denial now answers where `ESPIPE`/0 did; fallocate on a kqueue, which reports `S_IFIFO`, is `ESPIPE` not `ENODEV`); `F_SET_RW_HINT`'s `EFAULT`/`EINVAL` now precede `EACCES`; an OFD request on a filesystem without `VFCF_OFDLOCKS` validates its arguments before `EOPNOTSUPP`; `flock(pipe, 0)` is `EBADF` (pipes share the FIFO table); the per-open vnode tables enter the file context for the new members (fuse/inotify see the per-open identity, 6.1); `fchmod`/`fchown`'s vnode MAC check moved into `vn_chmod`/`vn_chown` (so `/dev/fd/N` chmod/chown is now checked too); `fcntl(badfd, badcmd)` is `EBADF` under a policy registering `file_check_fcntl`; a 0-byte `read(2)` consults the policy | series review 2026-11-07 (21 findings) | observer paths and error order are where "byte-identical" claims failed; the suites oracle common errnos, not order or write-back |
| D81 | 2026-11-07 | Cleanup of the fix-up's warts before stage 1 builds on it: `fchflags` refuses `VNOVAL` plainly once the descriptor is known (a type without attributes answers `EOPNOTSUPP` to that one value instead of `EINVAL` — declared) rather than probing `fo_setattr` with an empty `vattr`; `fdesc_setattr` no longer swallows `EINVAL` from the fileops (a real `EINVAL`, e.g. truncating a FIFO through `/dev/fd/N`, must propagate): a table without `fo_setattr` keeps the drop rule, a table with one answers for its instance, so attribute changes through `/dev/fd/N` on an anonymous pipe or a `posix_openpt` master report `EINVAL` where the missing vnode once meant "dropped" (declared); `is_close` takes a `bool release`; the rw-hint commands are kernel-private `F_GET_RW_HINT`/`F_SET_RW_HINT` in `fcntl.h`, the GET result in `td_retval` (no pointer through `intptr_t`); `invfo_advlock` returns `EBADF` only, an anonymous pipe answers `flock(2)`'s `EOPNOTSUPP` itself, so the lock mechanisms are two with distinct roles (table flags for the system calls' refusal, member presence for the close paths); the exec core calls its source through `IS_*` wrappers like `VOP_*`. Left as is, on purpose: the fourteen `IS_UNLOCK`/`IS_LOCK` pairs in the core (vnode sleeping rules; stage 3 may add a sleep-prepare op), the `vattr` built for `mac_file_check_setattr`, the `error = 0; #ifdef MAC … #endif if (error == 0)` idiom (the alternatives duplicate the call or split an `if` across `#endif`) | self-review of the fix-up | a capability probe disguised as an operation and an errno swallowed at a bridge are the kind of thing a kernel reviewer rejects on sight |
| D80 | 2026-11-07 | Stage 0 landed on `dev` as merge `45dffd334d8` (31 commits over `46b84718217`; `dev` had moved by 14 unrelated commits, merge clean). The merged GENERIC, built from `/usr/src`, booted the plane-on guest and passed `sys/file`, `sys/vm`, `sys/kern/execve` 200/201 (run 13; the broken case is the pre-existing `devctl_device_test` metadata). Ledger of record `f788bbd974a`: 283 references, no open category-A row. Nothing installed, no reboot | run 13 | stage 0 complete; stage 1a starts from this design |

### 20.1 Origin

The user's original notes (2026-11-06) asked for: a brand on an ELF marking
it an agent, inherited by everything it launches; a process-backed
filesystem transparently redirecting file system calls to a sandboxed,
real-time userspace process; control of the socket and exec system calls;
control of the process tree as the condition for transparency; recording of
buffers and arguments; loader integration; and eventually containers on
these primitives. This design delivers each except the two it deliberately
changes — the redirect is on the descriptor rather than a filesystem (D5),
and data is copied rather than memory-mapped (D34) — and the first consumer
is the agent case: a launcher in a jail attaches a resolver, the agent
forks, execs, reads files and connects, and the controller sees and answers
every operation whether it comes through libc, a static binary or a raw
system call.

## 21. Open items

1. Stage 4 attach-decision inputs (11.5).
2. `getfh`: present a handle that only `fhopen`s to `ESTALE`, or refuse.
3. Per-site VM dispatch decisions (10), recorded in the ledger in stage 1b.
4. Tunable defaults after stage 1a measurements.
5. An atomic `pdfork` variant that attaches at fork, closing the handshake
   window entirely (D55 makes the handshake safe; this would make it
   unnecessary).
