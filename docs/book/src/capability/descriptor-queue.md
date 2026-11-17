# DescriptorQueue (dq)

Status: design, revision 4 (2026-11-06), with stage 0 landed on `dev`
(section 6) and stage 1a built on `proxy/objects` (section 7.6, D85-D91,
2026-11-07). Revisions 1-3 were withdrawn after independent review;
section 20 records every decision and its source, section 19 every
alternative. Sections marked *decision* carry an entry in section 20;
*open* names an item in section 21. Line references are to the
`proxy/objects` branch at the time of writing.

Direction of 2026-11-10 (D300, D303; decided, design under review, not
built): the supervisor answers an acquisition by **swapping in** a
descriptor it controls, first a real one and later a proxy object through
the same machinery. "Direction: swap first, then proxy" in section 1 states
the model and what it changes here. Text elsewhere saying that nothing real
stands behind a served object describes proxy objects as built.

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
   This describes proxy objects. A descriptor swapped in under D303 is the
   real object itself and needs no stand-in.
2. **Transparency to the requester is required; performance is not.**
   The kernel caches only what the controller permits.
   Principle 7 bounds the cost: where a real object exists the kernel
   works on it directly and the controller is not asked again.
3. **Fail closed.** When a controller goes away, everything it served stops
   answering; nothing falls through to a real object; the kernel never
   invents an answer. I10 lists the exceptions physics imposes and nothing
   else is excepted.
   A process attached to a controller dies with it (D186): a served
   program never outlives its supervisor.
   A swapped real descriptor (D303) cannot be revoked and does not stop
   answering; for it, D186 is the whole of this principle.
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
7. **The supervisor acquires and decides; the kernel executes against the
   real object whenever one exists** (D300). The default answers are to
   let the kernel proceed on the object named, or to give the program a
   different real descriptor. A proxy object fills in where no real object
   can stand, and presents as whatever kind was asked for. Objects whose
   bytes the supervisor produces itself stay supported and are the
   exception.

### Non-goals

- Not a filesystem, not FUSE (section 19).
- No user-visible descriptor type: kinfo and `fstat` report the presented
  kind. The internal `DTYPE_DQ` exists so each remaining
  `f_type == DTYPE_VNODE` test fails safe and so they can be counted.
- Not an ABI emulation layer: no per-process syscall table. The kernel's
  own enforcement (Capsicum, audit, MAC) runs before the controller is
  consulted; a syscall table would run before it.

### Direction: swap first, then proxy (D300, D303)

*Decided by the owner on 2026-11-10. The design note is under independent
review and nothing in this subsection is built. Where it disagrees with a
later section, that section describes what exists today.*

A program asks for something and the supervisor answers one of:

| Answer | What the program holds afterwards | Status |
|---|---|---|
| proceed | the object it named, opened by the kernel as always | built |
| refuse | an errno | built |
| swap in a real descriptor | a real descriptor the supervisor controls, of the kind the system call would have produced; every later operation is the kernel's own on that object | next: the first deliverable |
| swap in a proxy descriptor | a proxy object the supervisor controls, presenting as that kind; its operations are messages to the supervisor | built with its own installation path; moves onto the swap machinery |
| swap in a proxy over a real object | a proxy that presents an identity and can be revoked, while the kernel performs data, locks and mappings on a real descriptor behind it | after the two above; replaces open item 17 |

**One mechanism.** There is one mechanism, the swap: the supervisor
answers with a descriptor it holds and the kernel installs it in the
program as the result of the system call, in one step. What differs is the
thing swapped in. The kernel applies one rule to all of them: the supplied
descriptor must present as the kind, access mode and flags the program
asked for. A reply that does not is refused; the program gets an errno and
the supervisor learns that its reply was refused. The first version accepts
real objects only and refuses a proxy object or the queue descriptor
cleanly. Admitting proxy objects is a later commit on the same path, and
the installation path proxy objects use today is folded into it; there are
never two.

**The form of a proxy** (owner, 2026-11-10). Whatever is swapped in, the
program receives a descriptor of the kind it asked for. A proxy is either
one polymorphic virtual descriptor that presents as that kind, or, where
the kernel needs it, one virtual form per real type. The kernel needs a
form of its own where it tests the descriptor's type or reaches into the
type's own structure; sockets are the known case (principle 1: a served
socket is a `struct socket` with the queue's protocol switch). The choice
is made type by type in the designs of stages 2, 4 and 5, by what keeps the
program and every type test in the kernel seeing the real type. The swap
machinery does not assume that there is a single proxy descriptor type.

**The first use: a redacting supervisor.** The program's `open` is already
held in the kernel until the supervisor answers. The supervisor copies the
file, redacts the copy, and answers with a descriptor for the copy. The
program continues on the copy at the kernel's own speed, and no descriptor
for the original reaches it. This is the series' example program and its
end-to-end test.

**What each form provides.** The third column is the intent; it is not
designed yet.

| Property | swapped real descriptor | proxy descriptor | proxy over a real object |
|---|---|---|---|
| every operation behaves as on FreeBSD | yes, by construction: it is a real object | as far as each operation has been made so | data, locks and mappings yes; the rest as a proxy |
| messages to the supervisor after the open | none | every operation | none for data, locks and mappings |
| identity the program sees (device, inode, path, file system) | the real object's own | the supervisor's choice | the supervisor's choice |
| revocation | no | yes | yes |
| stops when the supervisor dies | no; the program is killed instead (D186) | yes | yes |
| bytes produced by the supervisor on demand | no; the supervisor prepares a real object first | yes | no |
| each operation seen and decided by the supervisor | no; decided once, at the acquisition | yes | lookup, attributes, close and policy |

The table is the rule for choosing: swap in a real descriptor unless the
program must not see the real object's identity, the object must be
revocable, or the bytes do not exist until asked for.

**What this changes in the rest of this document.**

- Principle 1, I13 and two rows of section 19 (the `struct file` wrapper
  and the kernel lock table) are about proxy objects. A swapped real
  descriptor is not a wrapper: the program holds the real `struct file`,
  so there is no type test for it to leak through and its locks are the
  kernel's own.
- Principle 3 and I10: a real descriptor cannot be revoked and outlives
  the supervisor. D186 (served programs die with their supervisor) is the
  backstop, so the swap relies on the supervisor-control series (open item
  20) for its fail-closed property.
- I2 and I6 govern proxy objects. A swapped descriptor conveys exactly the
  authority of the real descriptor the supervisor chose to give, narrowed
  by any Capsicum rights the supervisor set on it; a supervisor cannot give
  what it does not hold. The swap design states the rules for transfer
  onward.
- I8 applies unchanged: the kernel enforces the lookup's Capsicum
  restrictions on whatever is swapped in.
- I9: the swap is audited and visible to observers (the path asked for,
  the object supplied, whose decision). Operations afterwards are ordinary
  operations on a real object and are seen as such.
- Work that makes proxy objects indistinguishable from files (advisory
  locks, the remaining errno and ordering differences of served
  operations, open item 17) is parked until the swap works end to end. It
  is not dropped.
- `dq_serve_tree` already holds a real descriptor for every object it
  serves, and re-implements name resolution, access checks and mutations
  in userspace in order to mint proxy objects. It becomes a supervisor
  that swaps; the fully served mode stays as an option and as the
  comparison oracle.
- Tests (section 17): the descriptor-operation matrices run in three
  columns, unattached, swapped and proxied. Swapped must equal unattached
  exactly; proxied may differ only where a difference is listed and
  justified.

Open questions are in section 21, item 21.

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
| supervisor, userspace supervisor | the controller. The owner's term since 2026-11-08; sections written earlier say controller |
| supervisor queue | the queue |
| Capability Broker | the owner's name (2026-11-15) for a supervisor that attaches programs: it decides every capability they are about to obtain, at the capability lifecycle hooks, and answers allow (PASS), deny (an errno), substitute (SWAP) or proxy (FD). Not one of the brokered system services (BSDFilesystem's storage broker and the other providers), which hand out capabilities on request. Code and this chapter keep supervisor and controller |
| capability lifecycle hooks | the kernel points at which an attached program's acquisition is put to its Capability Broker first; today the naming hook (`DQ_OP_RESOLVE`) |
| proxy descriptor | an object: a descriptor whose operations the supervisor answers. Identifiers keep `dq_` and `DTYPE_DQ` |
| swap | the supervisor's answer to an acquisition with a descriptor it controls, which the kernel installs in the requester (D303). The descriptor is a real object or, later, a proxy object. The feature is named Descriptor Substitution, the substitute answer of a Capability Broker; code and ABI keep `SWAP` |
| confinement | what a supervisor builds for a program from swapped and proxy descriptors, the supervisor queue, OpenES, Capsicum rights and the transfer controls (open item 18) |

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

These invariants govern proxy objects and attachments. A descriptor swapped
in under D303 is a real object; section 1 ("Direction") lists the
invariants its design restates.

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
| `sys/kern/uipc_socket.c` (`socreate` = `socreate_find` + jail test + `socreate_proto`), `uipc_syscalls.c` (`kern_socket`, `kern_socketpair`) | `RESOLVE op=SOCKET/SOCKETPAIR` (D40, D139, D155) |
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

### 6.4 Stage 0 as a subsystem (D83)

What stage 0 leaves behind is not a list of patches but a layer with a
contract, and it is presented as one — the way Capsicum is "rights on
descriptors, checked at `fget`" and MACF is "policies behind named
entry points". Its name is **descriptor operations**; its one rule is:

> A system call that takes a file descriptor dispatches through the
> descriptor's `struct fileops` and nothing else. It never tests `f_type`,
> never follows `f_vnode`, and never names a table except to ask what the
> table declares about itself.

Everything below follows from that rule.

**Vocabulary**

| Term | Meaning | Where |
|---|---|---|
| member | a `fo_*` slot of `struct fileops`; the dispatcher `fo_X()` is the only caller | `sys/sys/file.h` |
| default | `invfo_X`, what a NULL member answers: the errno the operation always gave a descriptor of no particular type | `kern/kern_descrip.c` |
| vnode body | `vn_X(fp)`, the operation on `fp->f_vnode`, moved from the system call; installed by `vnops`, the per-open vnode tables, both devfs tables and `path_fileops` | `kern/vfs_vnops.c` |
| sometimes-vnode | a table whose descriptors carry a vnode on some creation paths only; it installs `vn_X_opt`, which answers through the vnode when present and with the default otherwise. `pipeops` (FIFO vs pipe), `ptsdev_ops` (`/dev/ptmx` vs `posix_openpt`), `linuxfileops` (devfs vs `fd_install`) — **one idiom**; a table keeps its own function only where it has its own answer (`pipe_pathconf`'s `PIPE_BUF`, `pipe_advlock`'s `EOPNOTSUPP` to `flock(2)`) | the three tables |
| capability flag | a `DFLAG_*` bit in `fo_flags`, the table's declaration about itself: `DFLAG_PRIVWRITE` (private mappings are copy-on-write), `DFLAG_FLOCK`, `DFLAG_RECLOCK` (takes `flock(2)` / record locks). A system call that must refuse before touching its arguments consults the flag; nothing else may be inferred from a table's identity | `sys/sys/file.h` |
| open-mode flag | `fp->f_flag & O_PATH`: the descriptor was opened as a path. The refusals `getvnode()` used to make for `O_PATH` test this flag of the *descriptor*, not the table's identity (`f_ops == &path_fileops` is not written by this layer) | the system calls |
| image source | `imgp->is_ops`, how exec reaches the image it activates; `IS_*` wrappers; the vnode backend is `kern/exec_image_vnode.c` | `sys/sys/imgact.h` |
| pager seam | `pgo_sync`, `pgo_kinfo`: how `msync(2)` and the mapping observers reach a mapping's object | `sys/vm/vm_pager.h` |
| boundary check | `mac_file_check_*`: a MAC entry point on the descriptor, whatever its type, beside the vnode entry points | `docs/macf-new-hooks.md` §3 |
| ledger | the regenerable list of every remaining reach past the table, classified | `docs/descriptor-completeness-ledger.md` |

**Idioms, one each**

- *The default answers.* No system call probes `fo_X == NULL` to decide
  anything the default could decide by being called; `copy_file_range(2)`
  dispatches and the default's `EINVAL` comes back where the vnode body's
  own type test stood. The two places that must know before dispatch —
  the record-lock commands and `flock(2)`, which set `P_ADVLOCK`,
  `FHASLOCK`, `FHASOFDLOCK` ahead of the request — consult the capability
  flags. The close paths skip a table whose `fo_advlock` is NULL because
  there is nothing to unlock, which is a statement about the member, not a
  probe of the type.
- *Bridges speak their own vocabulary.* fdescfs and the Linux layer give
  the fileop's answer; where their ABI demands another errno (`ENOTTY`
  for a Linux ioctl on a type without the operation) the bridge maps the
  *table's lack of a member*, never a returned errno.
- *`fo_setattr` is the whole `vattr`.* Size, mode and owner have direct
  operations, and every `fo_setattr` body applies them through those first
  (`file_setattr_direct`: `fo_truncate`, `fo_chmod`, `fo_chown`), so the
  table's answers stand — `badfo_*` for `O_PATH`, a pty master's `EINVAL`,
  `vn_chmod`'s MAC check and audit record. The vnode body then does times
  and flags through `VOP_SETATTR`; `invfo_setattr` returns `EINVAL` for
  them. fdescfs makes one call; for a table without the member it keeps
  `getvnode()`'s answer (`chflags` `EOPNOTSUPP`, all else silently dropped),
  mapping the lack of the member, not an errno. (The quality-pass review,
  D84, caught the first draft routing mode and owner through `setfmode`/
  `setfown` — past the MAC and audit steps of `vn_chmod`/`vn_chown` — and
  reaching a `/dev/ptmx` master's device node; the table is the route.)
- *`O_PATH` is the descriptor's flag.* An anonymous pipe reopened `O_PATH`
  through Linux `/proc/PID/fd/N` carries `pipeops`; the layer's refusals now
  treat it as `O_PATH` (EBADF where it got the pipe's EINVAL), the Linux
  answer. Upstream's five `path_fileops` identity tests (`F_SETFL`, `FEXEC`
  in `fget`, aio, Linux mmap, `getvnode()`) predate the layer and stay.
- *MAC checks precede dispatch*, for every type, as `read`/`write` always
  did; `copy_file_range` on a policy-denied socket gets the policy's errno.
- *Sometimes-vnode is `vn_X_opt`.* Nothing else inspects `f_vnode`.

**Observability (DTrace)**

The layer is traceable from the moment it lands, under the existing `fd`
provider beside `fd:::install`/`dup`/`close`/`advlock*`:

| Probe | Arguments | Fires when |
|---|---|---|
| `fd:::invfo` | `const char *member`, `struct file *fp`, `int errno` | a default answers for a descriptor whose table has no member |
| `fd:::refused` | `const char *syscall`, `struct file *fp`, `int why`, `int errno` | a system call refuses a descriptor by capability flag (`why` = the `DFLAG_*` bit) or by `O_PATH` (`why` = 0) before looking at its arguments |
| `proc:::exec__image__open` | `struct image_params *imgp`, `int form` | an image source is constructed (form: path lookup 0, interpreter vnode 1, `fexecve` 2, interpreter loader 3) |
| `proc:::exec__image__close` | `struct image_params *imgp`, `int released` | an image source is closed |

`mac_framework:::*` already traces every `mac_file_check_*` (hook-args
probes generated from `mac_policy.h`), and `vfs:::chflags` the flags
path. Stage 1 adds the `dq` provider for the queue itself (7.x).

**Documents of record**

`fileops(9)` (the contract, every member, the flags, the idioms),
`image_source(9)` (the exec contract), this chapter's handbook companion
"Descriptor Operations" (`capability/descriptor-operations.md`: what the
layer is, how to add a member, how to read the ledger, the probes),
`docs/macf-new-hooks.md` §3 (the boundary checks), and the ledger.

**Tests of record** `tests/sys/file/*_test` (one per member: the fd form
against the path form on every descriptor type, the refusal order, the
bridges), `tests/sys/vm/msync_pager_test`, `sys/kern/execve`, and a probe
presence test (`fileops_dtrace_test`). All run in the plane-on guest.

## 7. The queue and its objects

### 7.1 `/dev/dq`

Delivered like `/dev/oes` **as `/dev/oes` is actually delivered** (D85;
revision 4 described a mechanism that does not exist): the node is 0600
root:wheel, every open runs `priv_check(PRIV_DRIVER)` and refuses an ILP32
caller, and no isolation claim covers it (only `/dev/mac_capability` is
claimed at boot, `usr.sbin/capsule/mac_capability_claims.c`). A unit does
not open the node itself: a provider serving an endpoint the unit's bundle
names (`system.DQ`, `requires = ["system.dq"]`, the shape of
BSDFilesystem's `system.OES` endpoint with `requires = ["system.oes"]`,
`usr.sbin/BSDFilesystem/capbundle/bsdfilesystem.ucl`) opens it as root,
rights-limits the fd and hardens it (`service_harden_fd`: `CAP_XFER_ONCE`
or `NONE`, `CLOFORK_LOCKED`, `CLOEXEC_LOCKED`) before handing it over —
**the endpoint admission is the authority**. BSDDevice refuses the `oes`
leaf (`usr.sbin/BSDDevice/policy.c`) and will refuse `dq` the same way.
The `BSDDescriptorQueue` provider that serves `system.DQ` is stage 4
(section 18); until then the device permission and `PRIV_DRIVER` are the
rule, and tests open the node as root in the VM as the OES tests do. One
open is one queue (`cdevpriv`). `read(2)` returns batched events; ioctls
mint, reply, push, revoke, set identity and policy, read stats;
`poll`/`kqueue` report readiness. Modelled on
`sys/security/oes/oes_dev.c`: batching reads, per-queue sequence numbers,
interruptible waits, bounded depth with visible drops. A `/dev/fd/N`
reopen of the queue fd shares the existing file (fdescfs answers the open
with `dupfdopen`), so it is the same queue, as `dup` would give.

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
| `DQ_KIND_DIR` | `struct file`, dq fileops, `S_IFDIR`; `READDIR`; a start directory for resolution inside its attachment (D179) | 1c-iii-b |
| `DQ_KIND_SYMLINK` | a `RESOLVE` `FD` answer carrying its target (`S_IFLNK`, `di_size` = target length); open only as `O_PATH \| O_NOFOLLOW` (D179) | 1c-iii-b |
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
| `dp_cache` | `NONE`, `ATTR`, `DATA` | no page cache; attributes from the identity; attributes and pages (section 10). Pages used by mappings exist in every mode. Whether `fstat` posts is `dp_events & GETATTR` alone, in every mode (D91) |
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

### 7.6 Stage 1a as built (2026-11-07)

Branch `proxy/objects`, worktree `/usr/obj/5BSD-proxy-objects`, on `dev`
after the stage 0 quality pass. The plan of record (scratch
`stage1a-plan.md`, revision 2) was reviewed independently before code
("not yet", nineteen items, all adopted: D91) and the built stage again
("not yet", six blocking and sixteen further items, all adopted: below).

**What exists.**

| Piece | Where |
|---|---|
| installed ABI | `sys/dev/dq/dq.h` (fixed width, LP64, static size assertions, ioctl group `'j'`, dense `DQ_PC_*` pathconf index with `dq_pc_names[]`), `dq_observe_proto.h` |
| kernel | `sys/dev/dq/dq_dev.c` (cdev, `kern.dq.*` bounded tunables, SDT provider `dq` with twelve probes, module glue: device at `SI_SUB_DRIVERS`, the service via `SYSINIT` at `SI_SUB_PSEUDO`), `dq_queue.c` (queue, objects, events, replies, interrupts, deadlines, revoke, teardown), `dq_file.c` (the `DTYPE_DQ` fileops, identity and policy validation, `dq_file_ident()` for other subsystems), `dq_observer.c` (observer descriptors, `DTYPE_DEV` with their own table), `dq_observe.c` (the `dq.observe` service) |
| served mark | `DTYPE_DQ 134`; tested only in OES's four hooks and `dq_file_ident()` (which also asks `f_ops`) |
| MAC | `mac_file_notify_reply` (`docs/macf-new-hooks.md` 3.14), `mac_test`/`mac_test_hooks`, trace arguments regenerated |
| OES | `AUTH/NOTIFY_FILE_READ`, `AUTH/NOTIFY_FILE_STAT`, `NOTIFY_FILE_CLOSE`, `NOTIFY_DQ_REPLY` (D89), `OES_FILE_META_PRESENTED`, `oes_event_presented_t`, the presented filler through `dq_file_ident()` under `DEV_DQ` |
| bridges | fdescfs `readlink` and linprocfs fd links ask `fo_fill_kinfo` and use `kf_path` only when the presented type is a vnode |
| build | `device dq` (`DEV_DQ opt_dq.h`) in amd64 and arm64 GENERIC, `sys/modules/dq`, Bazel kernel catalog rows and groups, `opt_dq` header targets for amd64/arm64/riscv, public-header installation of the ABI only (`dq_kern.h`/`dq_var.h` stay private) |
| userland | `lib/libdq` (`libdq(3)`), `tests/sys/dq` (eleven ATF programs, ten C and one sh, 70 cases, incl. `dq_oes_test`), `share/man/man4/dq.4`, `share/examples/dq/dqserve.c`, pkgbase `dq`/`dq-tests` |

**Deviations from the staging table, recorded.** `INTERRUPT` and deadlines
are in 1a (the wait path needs them to be correct); `FILE_OPEN` waits for
`RESOLVE` (1c) because `MINT` is not an open; the I9 row "uid-0 shell
without the capability sees nothing" is stage 4 (D90); observer data
bodies for replies are 1b (open item 7).

**What the VM runs found (plane on, `GENERIC` with WITNESS).** Run 1: the
`dq.observe` service registered at `SI_SUB_DRIVERS`, before the capability
framework initialises its lock (`SI_SUB_PSEUDO`, `SI_ORDER_FIRST`) — boot
panic; the module now loads with the drivers (where `cold` still holds, so
a late `kldload` is refused as OES refuses it) and registers the service
from a `SYSINIT` at `SI_SUB_PSEUDO`. Run 4: `filecaps_init` means "every
ioctl", which the Capsicum invariant rejects for a rights set without
`CAP_IOCTL`; a minted descriptor's filecaps now mirror what
`cap_rights_limit` would leave (no right, no set). Run 5: the refusal reason
of a `MINT` never reached userland because a failing ioctl copies its
argument back to nobody — `dm_reasonp` is a user pointer now; the observer
descriptor could not be made non-blocking and was not `CLOFORK` (rights and
flags fixed); deadlines woke a few milliseconds early from the coarse clock
(`sbinuptime` now); `getdirentries` on a served file is `ENOTDIR` as on a
regular file. Run 6: 226/233; the shared-descriptor concurrency cases
posted one event at a time because `read(2)` holds the implicit-offset lock
across the wait (as a real file does) — they use `pread(2)` now; the
`sys/security/oes` hook-coverage program's `NOTIFY_SOCKET_POLL` failure is
pre-existing (it fails identically on the stage 0 kernel without `device
dq`, run 22 of that stage). Run 7: 230/233 (the OES test's own process
was self-muted by OES's default and so saw no `FILE_CLOSE`; the test
unmutes itself). Run 8: 231/233 — every dq case (70 of 70) and the stage 0
`sys/file` suite pass; the two non-passes are the pre-existing
`devctl_device_test` metadata break and the baselined OES socket-poll
failure. WITNESS clean throughout.

**What the review of the built stage found and changed.** A presented path
is a link target only when the presented type is a vnode (sockets, ptys and
shm put other strings in `kf_path`); the OES Bazel targets lacked the
`opt_dq` and dq header dependencies; a fault in a `readv` buffer could
return a count including a partial record (the uio is restored to the start
of the record that did not copy); `dq.observe`'s `SUBSCRIBE` handed out an
observer through the framework's reply descriptors, which arrive with full
rights and unlimited transfer — the service installs it itself with the
ioctl path's rights and locked state and returns the number; the Bazel
`dq` package lacked `dq.ko` and Make installed the private headers; a
revoke did not wake a requester sleeping on its per-requester quota; the
tunables accepted zero. Declared rather than changed: a deadline that
expires after the controller has read the event posts `INTERRUPT` like a
signal does (the event is abandoned either way); after the reply hook's
`fdrop` a `CLOSE` record may carry the controller as caller; an
`aio_read` from the controller (only with `vfs.aio.enable_unsafe`) is not
caught by the `EDEADLK` scan and waits out the deadline.

**Measured cost, for open item 6.** The `EDEADLK` scan walks the caller's
descriptor table under `FILEDESC_SLOCK` once per posted event; nothing
else in 1a is paid per operation beyond the event itself.

### 7.7 Stage 1b-i as built (2026-11-07)

Served writes, attributes, fsync, fallocate, fspacectl, locks, ioctls,
kqueue notes and data observers (D93-D101 as amended by D105), with the
boundary MAC calls `fallocate`, `fspacectl` and the Linux bridges lacked
and abac checks against the controller's label. Plan reviewed twice before
code; the built series reviewed independently ("not yet", five blocking
items, all adopted — D106).

**What the VM runs found (plane on, WITNESS).** Run 10 (new kernel, 1a
tests): only 1a pins the series moves. Runs 11-13: test and library
defects only, each traced — an fspacectl range overlapping the bytes it
checked, per-owner opens inherited across `fork` (an OFD lock lives while
any descriptor of its open file does: owner opens are now close-on-fork),
an abac-labelled result pipe (labels follow their creator; the labelled
controller runs in its own child because abac never relabels downward), a
dtrace count including the harness's own write, a NULL policy, a recorder
cap, and two expectations written before POSIX ownership spanned sibling
opens. Run 14: 280/282 — all 119 dq and libdq cases and the stage 0
`sys/file` suite pass; the non-passes are the pre-existing
`devctl_device_test` metadata break and the baselined OES socket-poll
failure.

### 7.8 Stage 1b-ii as built (2026-11-07)

Served files have pages: a dq pager type of their own (`dq_pager.c`), the
asynchronous page operations with queue-owned deadlines (`dq_async.c`),
`mmap` in every mode, `msync` and `fsync` write-back, `sendfile` through
`getpages_async`, the `DATA` cache, `INVALIDATE`, and the bound
`kern.dq.max_inflight_bytes`. Two shared changes carry it: a `pgo_flags`
word in `struct pagerops` (`PGO_WRITEBACK` lets `vm_object_page_clean`
serve any write-back pager, not only vnodes; `PGO_RESIDENT_LOOKUP` lets
`mincore` report resident pages), and `vn_sendfile` split into
`sendfile_getobj` and an exported `sendfile_send` with the source in
`<sys/sf_buf.h>`, so a table builds its own source.

**What changed against the plan (D108).** Close writes dirty pages back from
a deferred task and only then posts `CLOSE` (with the kernel as caller);
revoke and queue close still drop them. A shrink fails the page operations
it cuts off instead of sleeping on them, so a controller never waits on its
own unanswered events. No `dq_taskq` task sleeps on another task or on the
controller; the bounded sleeps it may take are listed in `dq_var.h`. An
`INVALIDATE` racing a page-in re-posts the run (at most eight times). A
short read reply inside the presented size is an error, never cached zeros.
`msync`/`fsync` report only their own range's failures. Page faults do not
run the `EDEADLK` scan (a controller faulting on its own served mapping
waits out the deadline: declared). `MS_SYNC` waits are bounded, not
interruptible (`vm_object_sync` can only report `EIO`).

**What the VM runs found.** Run 16: the pager's dealloc did not mark the
object dead (every pager must). Run 18: a false lock-order report (the task
queue's mutex shared the global dq mutex's name) and a use-after-free in
unix(4): an aborted `sendfile` into a unix stream socket left freed mbufs
in the peer's receive buffer — any `sendfile` I/O error could trigger it,
vnode sources included (issue file `2026-11-07-unix-sendfile-abort-uaf.md`);
run 19 showed the first fix had broken the not-ready chain (the queue link
and `m_next` share storage). Run 21: a failed write-back left its pages
dirty but the object clean (`vm_object_page_clean` moves the clean
generation when it posts), so the next `msync` skipped them; the failure
completion re-marks the object. Run 22: 477/479 — all 144 dq and libdq
cases, `sys/vm`, the unix-socket and `sendfile` suites and `sys/file` pass;
the non-passes are the pre-existing `devctl_device_test` metadata break and
the baselined OES socket-poll failure.

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
| `WRITE` | `offset`, `len`, `flags` (`APPEND`, `SYNC`, `DSYNC`), `data` | errno, `written`, `offset` (the offset the controller wrote at — for an append the authoritative EOF is the controller's; D95) |
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

The fileop owns the implicit offset: `dofileread`/`dofilewrite` pass
`offset = -1` and never touch `f_offset` (`sys_generic.c`), and `vn_read`
and `shm_read` take `foffset_lock_uio` themselves (D91 corrected the
revision 4 text here). `dq_read` does the same, then takes the object's
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
`REVOKE`, queue close and object close, each via
`vm_object_page_remove` with `pmap_remove_all`, so a mapping observes the
change on its next access (wired pages are handled there too,
`vm_object.c:2059-2068`). `dp_cache = NONE` means no page cache: `read`
always posts; whether `fstat` posts is `dp_events & GETATTR` alone (D91);
it does not mean "no pages".
(`vm_mmap.c:1036` mincore, `vm_map.c:3312` charge, `:4660` fork copy,
`vm_fault.c:2372`, `vm_pageout.c:552,902,1659,1941`, `vm_page.c:2888,3025`,
`vm_meter.c:240`, `vm_object.c:246,970,2574`) are each reviewed in stage
1b and the decision per site recorded in the ledger (*open*).
`INVALIDATE {offset, len}` on a live object uses `OBJPR_CLEANONLY`: clean pages
are dropped so the next access faults, dirty `MAP_SHARED` pages the controller
has not seen survive and are written back; data is lost only at revoke and
close (D105 B2). Pending async page operations are completed with an error
before any `vm_object_page_remove` or `vm_object_terminate`, which sleep on
busy pages and paging-in-progress (D105 B1/B2).

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
interpreter load is kernel-origin. As built in 1c-iii-c (D175, superseding
D10): under a served root its absolute path is consulted at the served root
(`EXEC_INTERP`, class 3, start `SERVED`) and answered `REAL` or an errno, so
the interpreter comes from the served tree; every other kernel-consumer,
kernel-origin or unmarked lookup that would start at a served cwd or root is
`EXDEV` with no event.

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

`SOCKET` (as built in 1c-ii, D139/D155): `socreate` is split into
`socreate_find` (`pffindproto` and its errors, then the
`PR_CAPATTACH`/`ECAPMODE` test) and `socreate_proto` (the socket itself);
`socreate` stays their composition with `prison_check_af` between them, so
kernel-origin callers (NFS, RPC, NLM, iSCSI, wg, vxlan, geneve, gre, SCTP,
netgraph, TCP-over-UDP tunnelling) are never consulted (I7). An
unattached process runs upstream's `kern_socket`/`kern_socketpair`
unchanged (`DQRES_ATTACHED_TD` chooses). An attached `kern_socket` runs
`mac_socket_check_create` → `fdroom(td, 1)` (`EMFILE`, upstream's
`falloc`-first precedence) → `socreate_find` → `prison_check_af` →
consult → re-find → `falloc` → `socreate_proto`, so the controller sees
the resolved protocol (a wildcard protosw such as raw IP posts the
requested protocol), no event precedes the MAC, descriptor-room,
protocol, capability and jail checks, and no descriptor slot exists
while the consultation waits. The protosw is found again after the wait
and must be the same (a protocol module may unregister); the capability
and jail tests are repeated. `socketpair` (upstream: both `socreate`
before both `falloc`) runs `socreate_find` → `prison_check_af` →
`fdroom(td, 2)` and posts one `SOCKETPAIR` event before either socket or
slot exists; in stage 2 its `FD` reply mints both ends connected. Until then
an `FD` reply is `EINVAL` to the controller. A dead controller is
`EACCES` to both calls (D136); their errno allow-list is their own
(`EPERM`, `EACCES`, `EAFNOSUPPORT`, `EPROTONOSUPPORT`, `EPROTOTYPE`,
`EOPNOTSUPP`, `ENOBUFS`, `EMFILE`, `ENFILE`).

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

As built (1c-iii-c, D183, D184): `pwd_hold_dqres` takes the pwd and a
`struct dqres_snap` (`fhold` of `dr_cwd`/`dr_root`) in one `PWDDESC_XLOCK`
section (D177), which `namei` holds to the end; `dqres_namei_setup_start`
makes an absolute path (not `RINROOT`) under a served root, and a relative
`AT_FDCWD` path under a served cwd, start at the served directory through
the served branch, with every served result held to the served root's
subtree (`ENOTCAPABLE` otherwise, the kernel's guard behind the
controller's clamp of `..`). `pwd_chdir`, `pwd_chroot` and
`pwd_chroot_chdir` clear `dr_*`; `dqres_set_cwd`/`dqres_set_root` install
them (the root under chroot's open-directory rule, where a served root
counts as chrooted, and only an attached process's served directories
count). `ATTACH` takes `da_rootfd`/`da_cwdfd`, sharing the controller's
`struct file` (Q8). Paths are presented per D174: own paths
under a served root relative to it (`ENOENT` when not underneath and for
real objects), another process's against the viewer (an attached viewer of
the same queue with a served root sees them against its own root, every
other viewer the raw `di_path`); a revoked `dr_*` keeps its frozen path in
`getcwd` and kinfo. `execpath` under a served cwd or root is the served
name (a relative one joined lexically).

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

A served socket is a `struct socket` created by
`socreate_proto(protosw, dom, &so, type, proto, cred, td)` in
`uipc_socket.c` (split out of `socreate` in 1c-ii, D155) — the
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
   `fo_close` does wait for a reply ioctl that is inside
   `mac_file_notify_reply` with the file (`o_notify`): kernel code on the
   controller's thread, bounded by the hook's contract and run with stops
   deferred.
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
| `execve`, `fexecve` | stage 3 | yes with `ALLOW`; `EACCES` before stage 3 (`fgetvp_exec`; a descriptor with no vnode is `EINVAL`, as before) |
| `fstat`/`stat`/`lstat`/`fstatat`, `fstatfs`/`statfs`, `fpathconf`/`pathconf` | identity (`dqres_ident_to_stat`, `dqres_ident_pathconf` for both the descriptor and the name) | yes, incl. `st_dev/ino`; `st_gen` only with `PRIV_VFS_GENERATION`, as `vn_stat` |
| `F_KINFO`, `procstat -f`, `procstat -v`, `/proc/self/maps`, `realpath`, `/dev/fd/N` readlink, `getcwd` | `fo_fill_kinfo`, `pgo_kinfo` (presented against the viewer), attachment | yes; under a served root a real object (pass-through, real answer, swap) shows no path: empty `kf_path`/`kve_path`, `/dev/fd/N` readlink `ENOENT`, `getcwd`/`realpath` `ENOENT` (D174, D396) |
| signals during served regular-file I/O, page faults, full queues | `dq_wait_event` (rev 8 ux-2, D192-D194) | yes: a wait is uninterruptible by default, as a local disk's; `DQ_PF_INTR` objects and `DQ_QF_INTR` lookups end on a signal (`EINTR`, or the short count after accepted bytes); `SIGKILL`, exit and single-threading for exit always end it |
| swap (`DQ_RESOLVE_SWAP`) | the supervisor's file, moved | yes for files that carry no state of their own (D399); the supervisor's descriptor is closed at the take (D401) |
| `fcntl` flags/dup/readahead; `F_GETFL` | generic / `fo_fcntl` | yes (no served bit exists in `f_flag`) |
| `flock`, `F_SETLK*`, `F_OFD_*`, `O_EXLOCK` | `LOCK` events; the controller can proxy to the real file's locks | yes |
| `fchmod`, `fchown`, `futimens`, `fchflags` (any `dp_write`) | `SETATTR` | yes |
| `ioctl` | `IOCTL`/`ENOTTY` | yes for the ioctls a regular file answers; pointer-embedding ioctls are `ENOTTY` |
| `poll`, `select`, `kqueue` (all `EVFILT_VNODE` notes) | local + `NOTIFY_VNODE` | yes |
| `inotify` on a served dir | `INOTIFY` push | yes |
| every `*at()` relative to a served dir; absolute paths under a served root; `socket`, `socketpair` | `RESOLVE` | yes |
| `getdirentries` | `fo_readdir` | yes |
| `dup`, `fork`, `rfork` (any flags), `pdfork`, `vfork`, `/dev/fd/N` reopen | shared file | yes |
| `SCM_RIGHTS` within the attachment | refused `ENOTCAPABLE` (`CAP_XFER_NONE`) until 1c-iv | **no** until 1c-iv |
| `SCM_RIGHTS` or channel transfer to a process outside the attachment | refused (I6) | **no**, by design |
| ACLs, extattrs | events / `EOPNOTSUPP` | yes |
| `getfh` | `RESOLVE ATTR` with a handle; `fhopen` of it `ESTALE` | **partial**, documented (*open* 21.2) |
| `__mac_get_fd` | `EINVAL` (no label; dq.4) | **no**, documented (D22 superseded as built) |
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
`lib/libdq/tests/` (controller library), ATF C, on the support library
`tests/sys/dq/libdqtest`; `is_exclusive` where tunables change, and every
global setting a case changes is saved and restored by its cleanup. One
skip policy: a skip in a plane-on run is not a pass, so a missing device,
module or program fails; the only skips are by architecture, a race a
one-CPU machine cannot run, and a case deferred by name to another VM tier
(`DEFERRED_DEVICE_TIER`, which the plane-on test tier never takes). A test that asserts something did not happen
proves it with a fence (`dqt_fence`, `dqt_close_fence`), not a sleep, and a
race case fails when the race was not exercised. Oracle method:
the same operation on a real object and a served object presenting its
identity, results compared field by field (`struct stat`, `struct statfs`,
`kinfo_file`, `kinfo_vmentry`, `pathconf`, errno, `revents`, `kevent`,
bytes). WITNESS must stay clean throughout.

For a run with nothing skipped the runner is given three things besides
the suites. `LOADER_EXTRA` preloads `mac_test_hooks` (with `linux64`,
`linprocfs`, `linsysfs`, `fdescfs`, `mqueuefs`, `dtraceall` and
`imgact_binmisc`, which `dq_resolve_test`'s binmisc row needs): the plane
refuses a module load after boot, and `dq_socket_test:mac_denial_no_event`
needs the policy's `socket_check_create` toggle.
`KYUA_VARS=test_suites.FreeBSD.allow_sysctl_side_effects=1` lets
`sys/kern/kern_descrip_test:kern_maxfiles__increase` run, and
`SYSCTL_WRITE=kern.maxfiles` lets it raise the limit: the plane reserves
`kern.maxfiles` for the `system.Sysctl` provider, the shipped policy lets
no client write it, and the test asks the provider when its own write is
refused. `SYSCTL_WRITE` changes the test image's `sysctl.conf` only; it
lets every client of that guest's provider write the names given. The
provider matches names as prefixes on a component boundary and has no
exact-match form, so a name also grants the subtree under it;
`kern.maxfiles` is a leaf, so the recipe grants that one variable.

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
| 1a | `/dev/dq`, queue, `MINT FILE`, `READ`, `GETATTR`, identity, `REVOKE`, lifecycle, `INTERRUPT`, deadlines, observer queue, `dq.observe`, OES file events (read/stat/close, `DQ_REPLY`; open with `RESOLVE`, D89), the `mac_file_notify_reply` hook — **built 2026-11-07, 7.6** |
| 1b-i | writes, `SETATTR`, `FSYNC`, `FALLOCATE`/`FSPACECTL`, locks, ioctl, kernel-raised and pushed kqueue notes, observer data bodies, the boundary MAC calls `fallocate`/`fspacectl`/Linux writes lacked, abac checks against the controller's label (D93-D101, D105) |
| 1b-ii | the dq pager, `mmap`, `msync`, `sendfile`, cache `DATA`, `INVALIDATE`, `WRITE_ASYNC`/`READ_ASYNC` with queue-owned deadlines, `max_inflight_bytes` (D102-D105) |
| 1c | `mac_dq` (I6 `receive`/`inherit`, I5(b) refusals, label lifecycle: D93), attachment in `pwddesc`, four choke points, `RESOLVE` incl. `SOCKET`, `DIR`/`SYMLINK`, `READDIR`, virtual cwd/root, I5(b) refusals, `attached` trailer, inotify, launcher example |
| 2 | sockets |
| 3 | exec from a descriptor |
| 4 | global attachment (11.5), `BSDDescriptorQueue` provider |
| 5 | `CDEV` kind |

Both sockets and exec are required (D1); order 2 then 3 because stage 3
depends on the `p_textvp` audit landing with stage 0 and the served-root
resolution of stage 1c, while stage 2 depends on neither. Stage 0 is not
blocked by any open item; stage 1c depends on D38-D46 as recorded.
`build-bsd` is unaffected until stage 4 adds a provider bundle.

**Order from 2026-11-10 (D303).** After stage 1c and the first slice of the
Unix-illusion series (an unattached program behaves exactly as on FreeBSD):

1. the swap with real descriptors, and the redacting-supervisor example;
2. the same machinery admits proxy objects, and the installation path
   proxy objects use today moves onto it;
3. a proxy over a real object (open item 17 in its new form);
4. the remaining Unix-illusion work for proxy objects, then the stages of
   open item 18. Stage 2 (sockets) and stage 4 (devices) are expected to
   answer through the same swap.

Before step 1 becomes reachable, the part of supervisor control (open
item 20) that kills served programs when their supervisor dies lands first
(D304): a real descriptor cannot be taken back, so that kill is what stops
a program from carrying on unsupervised. The rest of supervisor control
keeps its place in the order.

A swapped descriptor is an ordinary descriptor to the program. It may be
passed on to other processes as on FreeBSD; a supervisor may restrict a
particular answer, which is best effort and not containment (D305). The
program shares the open file the supervisor supplied, so the supervisor
opens afresh for each answer and closes its own descriptor afterwards
(D306).

The swap ships as **Descriptor Substitution** (built; `DQ_RESOLVE_SWAP`,
`dq_reply_resolve_swap(3)`). The open file is handed over exactly as it
is: the credential of the supervisor's open (`f_cred`) and the Capsicum
rights of its descriptor go with it, also when the supervisor is another
user, as with `SCM_RIGHTS`. What bounds what a supervisor can hand back is
what it can itself still open (owner decision, 2026-11-14): it opens the queue and
attaches the program as root, then enters a jail, gives up root and
enters capability mode, and only then opens the files it hands over. Only
the uid drop gives the program the ordinary treatment (set-ID bits,
reserved blocks and the quota exemption follow the opener's privilege;
root in a jail loses only the quota exemption); a jail or capability mode
bounds what the supervisor can reach.
`dq(4)` "The substituted file and the restricted Capability Broker" gives the
order and the rules; `tests/sys/dq/dq_restricted_test` and the `dqswap`
example show them. A kernel check that a handed-over file's credential
matches the program's is future work, opt-in per queue.

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
| `RESOLVE op=SOCKET` in `kern_socket` (rev 3) | Capsicum, jail and protocol defaulting happen inside `socreate` (later adopted with `socreate` split, D139: the consultation sits between the parts) |
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

D300 and D303 (2026-11-10) leave these rows standing and narrow two of
them. The wrapper row is about presenting one object as another; the swap
installs the real file itself, with nothing wrapped. The kernel lock table
row is about a table separate from the real file's locks; a swapped real
descriptor uses the real file's lock state because it is the real file,
and a proxy over a real object is to use that same state.

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
| D82 | 2026-11-07 | Second independent review of the fix-up and cleanup: no kernel correctness defect; fixed: the msync test leaked its `/var/tmp` file (the cleanup process never saw the `mkstemp` name — unlink right after creation) and could leave `vm.old_msync` flipped (restored from a file by an ATF cleanup); Linux `file_setattr` no longer maps the fileop's `EINVAL` to `EOPNOTSUPP` (it also converted devfs's own `EINVAL`), so both Linux setflags entry points give the descriptor's answer; `copy_file_range`'s type probe sits after the `len == 0` return, as the vnode body's own test did; `IS_RELEASE_OLD` wrapper. Declared: through `/dev/fd/N`, `chflags` on an anonymous pipe or `posix_openpt` master is `EINVAL` (bridge once said `EOPNOTSUPP`), and `chmod`/`chown`/`truncate` on a `/dev/ptmx` master or devfs-opened linuxkpi file is `EINVAL` (their tables have no such ops; the base ran `VOP_SETATTR` on the devfs node); `fchflags(devfd, -1)` is `EOPNOTSUPP` before the device privilege check (base `EPERM`); `copy_file_range` with a kqueue/socket/shm input and a bad output is `EBADF` (base `EINVAL`); Linux `FS_IOC_SETFLAGS` on pipes/pty masters is the fileop's `EINVAL` (base `ENOTTY`); `linux_pread` ignores an `fo_stat` error. D81's example was wrong: a FIFO truncate through `/dev/fd/N` is 0 before and after (filesystems ignore `va_size` on `VFIFO`); the propagating `EINVAL` is the anonymous pipe's. Inherited and now declared: `vm.objects` withholds cdev paths from jails and linprocfs names device mappings (D74) | second review 2026-11-07 (16 findings) | the bridge behaviours (fdescfs, Linux compat) are where "the descriptor answers" and "as before" part ways; declare, do not map |
| D83 | 2026-11-07 | Stage 0 presented as one subsystem, "descriptor operations" (6.4): one rule, a vocabulary (member, default, vnode body, sometimes-vnode, capability flag, open-mode flag, image source, pager seam, boundary check, ledger), one idiom per situation (the default answers — no `fo_X == NULL` probes except the lock flags that must precede side effects; `O_PATH` is the descriptor's `f_flag`, never a table identity; `fo_setattr` is the whole `vattr`; sometimes-vnode is `vn_X_opt` everywhere, `pipeops` included), DTrace probes `fd:::invfo`, `fd:::refused`, `proc:::exec__image__open/close`, and the documents and tests of record (`fileops(9)`, `image_source(9)`, the handbook chapter, the ledger) | user: "a kernel subsystem of record, DTrace-integrated, explainable" | a layer with a name and a contract is reviewable; a list of patches is not |
| D84 | 2026-11-07 | Quality-pass review (12 findings) adopted: size/mode/owner in `fo_setattr` go through the table's direct operations (`file_setattr_direct`), never `setfmode`/`setfown`/`vn_truncate` directly (two regressions: skipped `vn_chmod`/`vn_chown` MAC and audit; a `/dev/ptmx` master's `/dev/fd/N` chmod reaching the device node); fdescfs keeps upstream's silent drop for a table without the member (the first draft's "the default decomposes" would have applied chmod to shm through `/dev/fd/N`, a behaviour change the pass had no mandate for); `O_PATH` pipes (Linux `/proc` reopen) and the MAC-before-dispatch order recorded as deliberate; upstream's `path_fileops` identity tests left; man-page fixes (`.Fn A , Fn B`, NAME list, a false veriexec claim) | review | behaviour fidelity is the stage-0 contract; "the descriptor answers" never means "the helper answers" |
| D80 | 2026-11-07 | Stage 0 landed on `dev` as merge `45dffd334d8` (31 commits over `46b84718217`; `dev` had moved by 14 unrelated commits, merge clean). The merged GENERIC, built from `/usr/src`, booted the plane-on guest and passed `sys/file`, `sys/vm`, `sys/kern/execve` 200/201 (run 13; the broken case is the pre-existing `devctl_device_test` metadata). Ledger of record `f788bbd974a`: 283 references, no open category-A row. Nothing installed, no reboot | run 13 | stage 0 complete; stage 1a starts from this design |
| D85 | 2026-11-07 | How `/dev/oes` is really delivered, and so how `/dev/dq` is (7.1): BSDDevice refuses the `oes` leaf; BSDFilesystem's `system.OES` endpoint (`requires = ["system.oes"]`) opens the node as root, rights-limits and hardens the fd; no isolation claim exists on it; `priv_check(PRIV_DRIVER)` runs on every open. `/dev/dq` is 0600 with the same unconditional check and an ILP32 refusal; the `system.DQ` endpoint with `requires = ["system.dq"]` is stage 4's provider; tests open the node as root in the VM. Revision 4's "claimed through the isolation service, BSDDevice opens it, `priv_check` a belt" is withdrawn | exploration of the tree before stage 1a | the design must describe the plane that exists |
| D86 | 2026-11-07 | Stage 1a delivery of a minted descriptor: inheritance. Without `RESOLVE` (1c) the controller is the only receiver; it opens the queue `O_CLOFORK`, mints and forks, so the child holds the object and not the queue and the `EDEADLK` rule does not trip. The minted fd is `finstall_prop`'d with `CAP_XFER_NONE` (no `SCM_RIGHTS` transfer until an attachment exists to bound one — the I6 row for 1a/1b), `O_CLOEXEC`, rights = `dp_rights`. `fp->f_cred` of a minted object is the controller's credential (visible to `mac_file_check_*`'s `file_cred`); declared in `dq(4)`, revisited when `RESOLVE` installs | plan review | a served fd must cross `fork` to reach a requester before 1c |
| D87 | 2026-11-07 | What a 1a object answers (`dq(4)` STAGE 1A): `MINT` accepts `dp_write/exec/mmap_shared_write/ioctl = DENY`, `dp_lock = EVENT`, `dp_cache ∈ {NONE, ATTR}`, `dp_events ⊆ {GETATTR, CLOSE}`, else `EINVAL` with `dm_reason`; no `FWRITE`, so `write`/`fallocate`/`fspacectl` are the generic layer's `EBADF` and `ftruncate` its `EINVAL` (`kern_ftruncate`); `fchmod`/`fchown`/`futimens`/`fchflags`/`F_SET_RW_HINT` `EPERM` (the non-owner's answer; `SETATTR` events in 1b); `fsync` 0; `mmap` `ENODEV` (pager 1b); `sendfile` `EINVAL` (1b); `copy_file_range` default `EINVAL`; ACL/extattr `EOPNOTSUPP`; `getdirentries` `ENOTDIR`; `FIOBMAP2` `EOPNOTSUPP` (no `VOP_BMAP`); `fstatfs` unfiltered by `prison_enforce_statfs` (no mount exists); locks refused by the stage 0 capability flags. Every answer pinned by `dq_stage1a_test` | plan | a read-only descriptor's answers are the honest 1a answers |
| D88 | 2026-11-07 | Plane facts for 1c/4: `MAC_CAPABILITY_SVC_NO_ATTACHED` (D61) does not exist (flags are `NOTIFY`, `MINTABLE`, `REFATTACH`); the caller trailer is a pinned 24-byte ABI with three pad bytes after `abi`, so `attached` goes there additively or through a new ioctl; `CAPSULE_OP_DELEGATE_SERVICE` names are ≤ 16 bytes and allowlisted in capsule | exploration | recorded so 1c does not re-derive them |
| D89 | 2026-11-07 | OES file events for served descriptors (14): `AUTH_FILE_READ 0x002B`, `AUTH_FILE_STAT 0x002C` (NOTIFY `0x1043`, `0x1044`), `NOTIFY_FILE_CLOSE 0x1045`, `NOTIFY_DQ_REPLY 0x1046`, within the subscription bitmap's 128-per-class bound; `FILE_OPEN` waits for a requester-side open (`RESOLVE`, 1c) — `MINT` is not an open. OES implements `mpo_file_check_read/stat`, `mpo_file_notify_close` and the new `mpo_file_notify_reply`, each returning at once unless `f_type == DTYPE_DQ` (the documented served-mark use; registering the fast-path hooks turns them on system-wide). Payload from `dq_file_ident()` with `OES_FILE_META_PRESENTED`, object id and controller nonce; `NOTIFY_DQ_REPLY` carries a count, never content (D41). New MAC hook `mac_file_notify_reply(controller, fp, op, error, count)` (`MAC_POLICY_PERFORM`, `docs/macf-new-hooks.md` 3.14), posted from the reply path with the object's file held (2026-11-14: pinned by `o_notify`, which the last close waits for, not referenced; a reference made the reply ioctl the last close and a `flock` outlive the program's) | plan | the audit trail needs the controller's answers, not their bytes |
| D90 | 2026-11-07 | `dq.observe` is a `mac_capability` service (`MINTABLE`) registered by the device: `co_connect` admits a `PRIV_DRIVER` credential (the device's rule, D85) until stage 4's capsule admission under `system.dq.observe`; `co_call` ops `LIST_QUEUES`, `LIST_OBJECTS`, `SUBSCRIBE` (an observer descriptor in `reply_fds`, metadata-only, D41). Queues carry a kernel-wide id. The I9 row "uid-0 shell without the capability sees nothing" is therefore deferred to stage 4, not satisfied in 1a | plan | observation stays a capability (D21) even before the plane delivers it |
| D91 | 2026-11-07 | Independent review of the stage 1a plan ("not yet", 19 items, then "code may begin") adopted in full: the fileop owns `foffset_lock_uio` (section 9 corrected); ABI constants and padding (`DQ_MNAMELEN` 1024, `f_nvnodelistsize`, explicit pads, `dp_rights_version` + `cap_rights_is_valid`, distinct `DENY/EVENT/ALLOW`, dense `DQ_PC_*` pathconf index with `dq_pc_names[]`, ioctl group `'j'`); `fo_close` with `td == NULL`; `de_caller` from `td_ucred` with the `P_KPROC`/no-thread rule, never `f_cred`; the `EDEADLK` scan only in operations that post, `FILEDESC_SLOCK` before `q_mtx`; `DEV_DQ opt_dq.h` with `device dq`; the waiter reads the event state before the wake reason; one reader at a time on a queue, dequeue after a successful copy, re-check after relock; observer records `M_NOWAIT`; `fhold` may fail before the reply hook; `SEEK_HOLE` past the end is `ENXIO`; the fileops table answers verified against the real file (`fo_cmp`, `EVFILT_WRITE`, `poll_no_poll`, `FIODTYPE`, `vn_fcntl`, `bzero` + `PAGE_SIZE` floor in `fstat`) | plan review 2026-11-07 | a design that names its locks and errnos can be reviewed before it is code |
| D92 | 2026-11-07 | Stage 1a landed on `dev` as merge `b46b705b57a` (six commits `578eabbfcf9`..`fc4a63722fc` over the stage 0 quality pass). The merged GENERIC, built from `/usr/src`, booted the plane-on guest and passed `sys/dq` (70/70) and `sys/file`, 231/232 (run 9; the broken case is the pre-existing `devctl_device_test` metadata). Nothing installed on the host, no reboot. Later stages keep landing in order as each is built, reviewed and run | run 9 | stage 1a complete; stage 1b starts from 7.6 |
| D93 | 2026-11-07 | `mac_dq` moves to 1c (its content is the attachment's); isolation implements nothing for served files in 1b (claims are keyed by vnode; `fi_do_claim` refuses an fd without one) until stage 4 defines queue claims; abac checks served files through `mpo_file_check_read/write/stat/mmap/setattr`, gated on `DTYPE_DQ`, against the controller credential's label via `dq_file_cred()` — no stored label, D22 stands (D105 B9) | 1b plan + review | the posixshm precedent without a label slot |
| D94 | 2026-11-07 | Boundary MAC gaps closed for every type: `mac_file_check_write` before `fo_fallocate`/`fo_fspacectl` and at the three Linux `fo_write` callers, `mac_file_check_setattr` at Linux `FS_IOC_SETFLAGS`; `O_TRUNC` at open stays vnode-only (declared) | 1b plan | the stage 0 rule: checks precede dispatch |
| D95 | 2026-11-07 | Writes: `WRITE {offset, len, flags, data}` → `{errno, written, offset}`, the controller's offset validated (`written ≤ len`, no overflow) and applied only on the implicit-offset path; `vn_io_fault`'s range-lock rule (whole file for non-positioned or appending writes); chunked at `max_io` with `dofilewrite`'s count rule (no rollback across chunks, declared); `di_size` extended and `NOTE_WRITE`/`EXTEND` raised by the kernel; `RLIMIT_FSIZE` through a vnode-free `rlimit_fsize_check()` factored from `vn_rlimit_fsizex1` (`maxfsz = 0`), truncate through `vn_rlimit_trunc`, fallocate unchecked as `vn_fallocate`; `FWRITE` fixed at mint by `DQ_MINT_F_WRITE` | 1b plan + review | the serialization a real file has, in front of the queue |
| D96 | 2026-11-07 | `SETATTR {mask, attrs}`: the kernel applies the DAC and privilege rules a vnode applies, from the identity and `td_ucred` — `vaccess(VREG, …, VADMIN)`, utimes `VWRITE_ATTRIBUTES` or `VWRITE` with `UTIMES_NULL`, `ufs_chmod`'s sticky/setgid/setuid rules, chown's `PRIV_VFS_CHOWN`, chflags exactly as `ufs_setattr` (unknown bits `EOPNOTSUPP`, `SF_*` with `PRIV_VFS_SYSFLAGS` and `securelevel_gt`, `SF_SNAPSHOT`, immutable/append refusals on the new flags), set-id bits `EPERM` (I3) — then posts; on success the kernel applies the fields to the identity (birthtime pull-back, `ctime` now) and raises `NOTE_ATTRIB`; `fchmod`/`fchown` post the same event with one field; `dp_write = DENY` still posts | 1b plan + review | shm's shape: the object enforces what it can see |
| D97 | 2026-11-07 | `FSYNC {mode}` posts whenever `dp_write = EVENT`, whatever this fd's `FWRITE` (an `O_RDONLY` vnode fd flushes); `DENY` answers 0 without an event; with `DATA` (ii) dirty pages are written back and waited for first (D42) | 1b plan + review | |
| D98 | 2026-11-07 | Locks (D14 concrete): `fo_advlock` with `DFLAG_FLOCK|RECLOCK`; `LOCK {op, kind, type, start, len, owner, pid}` → errno (+ the lock for `GETLK`, validated); owner from the `id` argument — the leader's pid for `F_POSIX`, `SipHash24(boot key, &fp)` for flock/OFD — never the thread's pid; `LOCK` waits have no deadline and are outside `o_inflight` (blocked lockers never block readers); a signal posts `INTERRUPT`; the controller does POSIX deadlock detection, dq's `EDEADLK` is its own rule; close-time unlocks arrive with the new kernel-private `F_CLOSEUNLCK` flag from `closef`/`fdclearlocks`/the fcntl race recheck, posted as `UNLOCK_ALL` without waiting and only for a kind the object ever locked; flock/OFD release at the last reference in `dq_close` (which a mapping defers to the last `munmap`, declared); an explicit `F_UNLCK` is a waited `LOCK` | 1b plan + review | `lf_advlock` masks every flag test, `vn_advlock` strips the bit |
| D99 | 2026-11-07 | `IOCTL {cmd, len, in[]}` → `{errno, out[]}` with `in` the generic layer's post-copyin buffer (`IOCPARM_LEN`; the int for `IOC_VOID` of int size; no payload for `IOC_VOID` size 0, the pointer value never ships), `out` exactly `IOCPARM_LEN` on `IOC_OUT` success; `FIOSETOWN`/`F_SETOWN` are events; the kernel cannot see pointer-embedding commands, so **the controller refuses what it cannot serve with `ENOTTY`** (8.2 amended) | 1b plan + review | |
| D100 | 2026-11-07 | kqueue notes (D27 concrete): kernel-raised `NOTE_READ`, `WRITE`/`EXTEND` (write, fallocate, fspacectl, async completion), `ATTRIB` (setattr, truncate, `SETIDENT`), `REVOKE`; `NOTE_OPEN` at install and `CLOSE`/`CLOSE_WRITE` at close raised on the **sibling objects of the same identity on the queue** (an object has one `struct file`, whose knotes are detached before its close); `DELETE`/`LINK`/`RENAME` and others' changes pushed by `DQ_IOC_PUSH {NOTIFY_VNODE}`; inotify on a served file is an open item for 1c | 1b plan + review | the VOP post-hooks raise `OPEN`/`CLOSE` to a vnode's other opens |
| D101 | 2026-11-07 | Observer data bodies: a refcounted reply buffer shared by the waiter and `DQ_OBS_F_DATA` observers (no second copy under `q_mtx`); observer `WRITE` records hold the event; two-piece observer records restore the uio on a fault | 1b plan + review | |
| D102 | 2026-11-07 | The pager (D12 concrete, ii): own dynamic type, `OBJ_COLORED` only; `VM_PAGER_ERROR` on a served read failure (`FAIL` zero-fills), `BAD` past EOF; readahead clamped to 0; `getpages_async` calls `iodone` on every path and leaves requested pages busy; `putpages` through `dq_event_post_async` (M_NOWAIT, no scan, no quota sleeps, own `o_async` count and `q_async_bytes` bound; `AGAIN` on allocation failure/full queue/bounds, `ERROR` when closing or revoked), `PEND` for every page, data copied with the object lock dropped through `pmap_quick_enter_page`; un-waited async events carry a queue-enforced deadline (per-queue callout → dq taskqueue completion under the object write lock; always set, the default when the policy says 0); an `o_closing` gate set under the object lock before pending async work is completed at close/revoke/queue close, then `vm_object_page_remove`, then deallocate (I11 holds: dq waits only on its own completions); `object->size` maintained with the identity (`dq_object_setsize`, the `shm_dotruncate_locked` shape); `vm_object_page_clean` gains a `PGO_WRITEBACK` pager flag (vnode and dq only) so `dq_pager_sync` reuses it; `kern_mincore` learns the type; `vm_page_scan_contig`/`reclaim_run` leave dq pages unrelocatable and `vm_map_protect` charges nothing (declared). D59 amended: no racct (`racct_add_cred` enforces nothing and `RACCT_VMEM` is not sloppy); the bound is `kern.dq.max_inflight_bytes` at the post, visible in `GET_STATS2`; a sloppy `RACCT_DQPEND` is an open item | 1b plan + review | the VM code as it is, not as the design assumed |
| D103 | 2026-11-07 | `mmap` (ii) in `shm_mmap`'s shape: `maxprot` from `FREAD`/`FWRITE`/`dp_mmap_shared_write`, private mappings COW with `DFLAG_PRIVWRITE`, own writecount, `vm_mmap_file(..., fp)` so the mapping holds the file; the fault wait abandons only on `SIGKILL`/`P_WEXIT`/deadline, continuing with non-catching bounded slices after a caught signal (I12) | 1b plan + review | |
| D104 | 2026-11-07 | `sendfile` (ii): `vn_sendfile` split into `sendfile_getobj` + an exported `sendfile_send`; `dq_sendfile` builds its own `sendfile_src` (object, size, getsize, release) and calls `mac_file_check_read` itself (the syscall runs no file hook); the `f_type` switch in `sendfile_getobj` gains no arm | 1b plan + review | the table answers |
| D105 | 2026-11-07 | Stage 1b plan reviewed twice ("not yet", ten blocking and fifteen items; then "code may begin" after three corrections): the items above are the adopted set; also `dq_stats`/`GET_STATS` frozen with `DQ_IOC_GET_STATS2` (the size is in the ioctl word), reply errnos allow-listed per op (a controller's `EPIPE` must never raise `SIGPIPE`), `F_SET_RW_HINT` stays `EPERM`, `copy_file_range` stays the default, `dp_mmap_shared_write = ALLOW` refused until ii | plan review 2026-11-07 | a pager design has to be checked against the VM code's locks before it is code |
| D106 | 2026-11-07 | Built-series review of 1b-i ("not yet") adopted: the `EDEADLK` rule runs before any offset or range lock in every operation that posts (a controller touching its own served file could sleep uninterruptibly behind a requester's write lock); Linux splice and sendfile check reads too; `UNLOCK_ALL` and `INTERRUPT` are never dropped for depth (`ds2_overdepth`), since a lost unlock leaks a controller-side lock under a pid that gets reused; POSIX lock ownership spans every open of the same identity on the queue, as on a real file (siblings indexed by `(di_dev, di_ino)` per queue, which also bounds the note walk); libdq's `GETLK` creates no owner. Also: a non-append `WRITE` reply must echo its offset; a zero-byte success is `EIO`; allow-lists widened (`EDQUOT`, `ENOSPC`, `ESTALE`, `EACCES` where real files return them); the snapshot chmod rule; `RLIMIT_FSIZE` on truncate after the attribute checks. Declared: an immutable or append flag combined with other attributes in one `vattr` is `EPERM` (ufs ignores the rest); `file_setattr_direct` applies size, mode and owner before flags | built-series review 2026-11-07 | |
| D107 | 2026-11-07 | Stage 1b-i landed on `dev` as merge `e7af4595ac7` (four commits `66241e9182e`..`ee87e811087`). The merged GENERIC, built from `/usr/src`, passed `sys/dq`, `lib/libdq` and `sys/file` in the plane-on guest with only the pre-existing `devctl_device_test` metadata break (run 15). Nothing installed on the host, no reboot | run 15 | series ii (pages) starts from D102-D105 |
| D108 | 2026-11-07 | Stage 1b-ii built and reviewed ("not yet": a double close in the reply path from series i — `fhold` succeeds on a zero count, now `refcount_acquire_if_not_zero`; the I12 test's shape; INVALIDATE racing page-ins; tail zeroing; sendfile sized by the pager; task-queue sleeps; per-range `msync` errors; short replies; a race in the unix(4) abort fix — all fixed). Overruled at implementation: close drops dirty pages (now deferred write-back), a shrink sleeps on the controller's own events (now fails them). Declared: a fault on one's own served mapping is not `EDEADLK`; `MS_SYNC` is not interruptible; a mapping placed into another process's map does not hold the file; a failed `sendfile` page-in aborts the socket (`EIO`) after the call may have returned | 1b-ii review, runs 16-22 | |
| D109 | 2026-11-07 | Stage 1b-ii landed on `dev` as merge `07b591163f4` (four commits `512d7bbd66b`..`798cee1a4b2`). The merged GENERIC from `/usr/src` passed `sys/dq`, `lib/libdq`, `sys/vm`, `sys/file`, `sendfile_test` and `unix_stream` in the plane-on guest, 361/362 with only the pre-existing `devctl_device_test` metadata break (run 23). Nothing installed on the host, no reboot | run 23 | stage 1 is complete but for the OES events of the 1b operations |
| D110 | 2026-11-07 | Stage 1 complete: the OES events for the 1b operations (`9367e9c56a4`) landed on `dev` as merge `3f330ee172d`; the merged GENERIC passed `sys/dq`, `lib/libdq`, the whole `sys/security/oes` suite, `sys/file` and `sys/vm`, 950/953 (run 26). The three non-passes — `devctl_device_test` metadata, OES `test_event_metadata` access timestamp, OES `NOTIFY_SOCKET_POLL` — and two shutdown lock-order reversals in tmpfs/devfs/ufs unmount are identical on the stage 0 kernel without DescriptorQueue (issue file 2026-11-07-oes-suite-preexisting). Nothing installed on the host, no reboot | run 26 | stage 1c (resolution) starts from section 11 |
| D111-D153 | 2026-11-07 | Stage 1c planned against the code (exploration, pre-plan decisions D111-D121, plan revisions 1 and 2, independent review twice: "not yet" with seven blocking items — a path re-read on namei restart bypassing a cached answer, ATTACH racing pwddesc replacement and fork, fd-table sharing, the own-queue scan not atomic with the commit, a wait under `mnt_renamelock`, ERESTART escaping namei, and I5 gaps through `CAP_AUTH_INSTALL` — then "code may begin"). Key decisions: the attachment is inherited in `pdinit` and carried at every `pwddesc` replacement and late in `do_fork`; ATTACH requires a sole, unshared `pwddesc` and fd table, holds the target's table across the scan and the commit, sets `P2_NO_NEW_PRIVS`, and checks `p_candebug`; lookups carry an explicit intent with per-slot cached answers re-validated against the re-copied path; kernel-origin lookups of an attached process are consulted fail-closed with `PASS`/errno answers only; resolver waits are guarded by always-maintained lock counters and bounded for kernel lookups; `setcred(2)`, `NODE_OP_SET_CRED`, `jail_attach`, `CAP_AUTH_INSTALL` and core dumps are refused while attached; sockets are consulted from `kern_socket`/`kern_socketpair` before the jail's address-family check; `mac_dq` lives in `dq.ko`. Built in five series (attachment and consultation; sockets; served results and the virtual namespace; I6 and the plane rule; inotify and the launcher). Plan of record: scratch `stage1c-plan.md` (revision 2 with 0c) | 1c plan reviews 2026-11-07 | |
| D154 | 2026-11-08 | Stage 1c series i (attachment and consultation) built and reviewed twice by an independent reviewer ("not yet" both times; every finding fixed). As built, differing from the plan: marks are made by generated `kern_X` → `kern_X_dqimpl` wrappers for `UIO_USERSPACE` paths, so freebsd32 and Linux are covered through the same `kern_*`; a user path the kernel copies first is bound by a *content slot* (bytes, dirfd, segment) or a pointer slot consulted ahead (`dqres_consult_slot`: swapon, swapoff, the `Q_QUOTAON` quota file) and compared at its lookup, with start vnodes held and a change failing `EIO`; slot 1 of rename/link has its own start kind, vnode and hint, carried in the same event (`dq_resolve_body` 96 bytes, a fourth string, `DQ_RF_STARTPATH2_VALID`) and a change re-consults via `ERELOOKUP`; any other kernel-space lookup by an attached thread outside a `TDP2_DQ_NORESOLVE` region of kernel-computed paths fails `EPERM` and is counted (`ds2_resolve_unmarked`), never passed; attached callers get `EPERM` for md vnode attach, the CTL block backend, veriexec load, binmisc add, ZFS file vdevs and cachefile, netgraph `AF_LOCAL` ksocket, the vnode-reclaim sysctl, alq log paths, the OES mute path and pNFS server paths; unmount of an unresolvable path by an attached caller returns its error with no mount-on-name fallback; `EAGAIN` answers to rename/link/fhlink become `EIO`; one errno allow-list for all resolve ops; the ledger (`sys/tools/dq_resolve_ledger.sh`, 248 rows) classifies every user and kernel-space lookup and fails every kernel build on an unmarked or unclassified one. No `__FreeBSD_version` bump (5BSD does not move the shared sequence); `struct thread` and `struct pwddesc` grew, so out-of-tree modules rebuild. Plane-on VM run 31: `sys/dq`, `lib/libdq`, `sys/file`, `sys/kern/execve` and the PASS oracle 346/347, the one being the baselined `devctl_device_test` metadata | 1c-i reviews 2026-11-08, runs 27-31 | |
| D155 | 2026-11-08 | Stage 1c series ii (sockets) built and reviewed ("not yet"; no kernel defect; findings fixed). `socreate` split into `socreate_find` (protocol lookup and its errors, the `PR_CAPATTACH` test) and `socreate_proto` (the socket); `socreate` stays the composition with `prison_check_af` between them, so kernel callers are never consulted. `kern_socket`: MAC → `socreate_find` → `RESOLVE SOCKET` → `prison_check_af` → `falloc` → `socreate_proto`; `kern_socketpair` posts one `SOCKETPAIR` before either socket. **Amended 2026-11-08 (order restore):** as first built this order held for every process, so with a full table a bad domain, type or protocol, `ECAPMODE` or a jail refusal beat upstream's `EMFILE`; that broke the unattached illusion and is withdrawn. An unattached process now runs upstream's code unchanged (same errors, audit, ktrace, SDT). An attached `socket(2)`: MAC → `fdroom(td, 1)` (new in `kern_descrip.c`: `fdalloc`'s limit test — first free slot from `fd_freefile` below `getmaxfd`, racct `NOFILE` deny limit via `racct_get_available` — without reserving, growing or charging) → `socreate_find` → `prison_check_af` → consult → re-find (protosw, capability and jail tests again) → `falloc` (`EMFILE` after a `PASS` when another thread filled the table) → `socreate_proto`. The jail test moved before the consultation, socreate's own order (and D40's plan): a refused family posts nothing and the controller's answer cannot override it (`jail_af_after_pass` became `jail_af_before_consult`). An attached `socketpair(2)` keeps upstream's precedence too (both `socreate` before both `falloc`): `socreate_find` → `prison_check_af` → `fdroom(td, 2)` → consult → re-find → `socreate_proto` ×2 (with the second `CAPFAIL_PROTO` ktrace record upstream's second `socreate` makes) → `falloc` ×2; so a full table still loses to a bad type there. Remaining attached-only differences: `ENFILE` (`kern.maxfiles`) is not pre-tested (its test calls `priv_check` and logs), so at the system limit a protocol or capability error or the consultation precede it; `socketpair` with no room returns `EMFILE` before a `soattach` error such as `ENOBUFS`. Ledger: +3 `SOCKET` rows (the unattached `socreate` calls, `CONSULT` by function), 34 `SOCKET` rows. Tests: `full_table_unattached`, `full_table_attached`. Body: `drs_domain`, `drs_type` without `SOCK_*` flags, `drs_protocol` = the found protosw's `pr_protocol`; for a protosw whose `pr_protocol` is 0 the caller's number is posted as given and unvalidated (raw IP: the IP protocol the socket uses; `AF_UNIX`/`PF_ROUTE`: ignored, `SO_PROTOCOL` reports 0); start `NONE`, empty strings; no ABI change (1c-i reserved the fields). As built beyond the plan: after the wait `pffindproto` runs again and must return the same protosw, type and posted protocol (`protosw_unregister` exists: SCTP, SEND, pf divert), else `EPROTONOSUPPORT`, and the capability-mode test is repeated without a second `ktrcapfail`; a socket list of reply errnos (`EPERM`, `EACCES`, `EAFNOSUPPORT`, `EPROTONOSUPPORT`, `EPROTOTYPE`, `EOPNOTSUPP`, `ENOBUFS`, `EMFILE`, `ENFILE`; lookups keep 1c-i's list; libdq `dq_resolve_errno_allowed`); a dead controller is `EACCES` to both calls, a missed deadline `EIO`, both counted in `ds2_resolve_failclosed` and in the system-wide `kern.dq.stats.resolve_failclosed` (with `kern.dq.stats.resolve_unmarked`, counter(9), outliving the queue). Not consulted: sockets derived from a consulted one (`accept`, `accept4`, `sctp_peeloff`), `SCM_RIGHTS` receipt (no creation), children (they inherit the attachment), and kernel `socreate` on behalf of a request (NFS mount, NLM, iSCSI, wg/gre ioctls, netgraph ksocket, UDP tunnelling sysctls; I7). The MAC check stays before the protocol lookup (upstream order). Abstract `AF_UNIX` names are 1c-i's (`dqres_consult_sun`, rflag `ABSTRACT`), unchanged. The ledger records the two consult sites and classifies every `socreate`/`socreate_proto`/`sopeeloff` call in the scanned trees (also `nfs`, `nlm`, `rpc`, `netpfil`) as `CONSULT`, `DERIVED` or `KERNEL` with a reason, failing the build on an unclassified one (281 rows, 31 `SOCKET`) | 1c-ii build and review 2026-11-08 | plane-on VM run 35: `sys/dq`, `lib/libdq`, `sys/kern`, `sys/netinet` 3839/3955, 0 broken, no LOR or panic; the 11 failures (`inotify_lifetime_test:directory`, Linux adjtime, break_signals, peerpidfd, pkey, statx2, xattrat, and four needing the disposable ZFS-root VM) fail identically on dev before 1c-i (baseline run 34); the 105 skips are environmental plus `mac_denial_no_event` (no policy denies socket creation) |
| D156-D177 (iii-a) | 2026-11-08 | Stage 1c series iii planned in three sub-series (D156: iii-a served answers from real starts, iii-b served directories and starts, iii-c virtual cwd and root), reviewed (13 questions, B1-B5, amendments) and re-reviewed; iii-a built, not yet run or reviewed. D157: `EDQRESOLVED` is produced only in `dqres_namei` for slot 0 of an intent entered with `dq_intent_enter_served`, consumed only by the wrapper's `DQRES_SERVED` completion (run with `DQI_COMPLETING`, asserted lookup-free), and a stray one is mapped to `EIO` right after each `sy_call` return in `syscallenter` (`error` and a `TDP_NERRNO` `td_errno`) before audit, DTrace and `sv_set_syscall_retval`; the `KASSERT` there is suppressed only by the `debug.dqres.drop_completion` fault injection (`TDP2_DQ_INJECTED`). D158: `drs_accept` (@92, was `drs_pad1`) = PASS plus the entry point's served kinds for a class-1, non-carried, non-ahead slot 0 from a real start without STRICTREL/BENEATH/RINROOT/NOSYMLINKS/NOMAGICLINKS/NOXDEV/OPENNAMED; any other kind is `EINVAL` to the controller with the event in flight; `ENOTCAPABLE` is allowed only on STRICTREL/BENEATH/RINROOT events. D159/D130: `FD` is minted at the reply (validated before `q_mtx`, id from the atomic `q_next_object` copied out before linking, the link step re-checking `DQ_Q_CLOSING`/`max_objects`, `ev_robj` handed to the waiter), bound in the requester's thread (`dro_bind`, the creation reference becomes the file's) and installed with `dp_rights`, `CAP_XFER_NONE`, `O_CLOEXEC`/`O_CLOFORK` only as asked. D160/D161: OPEN→FD; STAT/ACCESS/REALPATH (and Linux statx, with served mount ids keyed by queue and fsid, 64 per queue plus one shared overflow id, freed through the `dq_queue_closed` event)→ATTR; READLINK→LINK; SETATTR/TRUNCATE→OK or FD (applied through `fo_*`; truncate also checks write access, `MINT_F_WRITE`, `RLIMIT_FSIZE`); the other mutating ops→OK. The setattr body follows the strings with `dsa_priv` (only the privileges the op needs), `ATIME_NOW`/`MTIME_NOW` and OMIT per field; utimes times are copied in once; symlink's target is path2; mknod `drs_dev`; `drs_cmode` (@84) per op. A set-id chmod and a truncate past `RLIMIT_FSIZE` withhold OK instead of a no-event pre-check, so PASS stays transparent and FD applies the kernel's `EPERM`/`EFBIG`. D164: `AT_EMPTY_PATH` fallbacks for fchmodat, fchownat, utimensat, chflagsat, faccessat, readlinkat (`EINVAL`) and linkat (`EXDEV`). D166/D176: the FD open checks `vaccess` with `VWRITE` for `O_TRUNC`, `EROFS`, immutable and append-only `EPERM`, `O_DIRECTORY` `ENOTDIR`, writes without `MINT_F_WRITE` and `O_EXEC` `EACCES`, `O_VERIFY` `EAUTH` under enforcing veriexec; O_PATH served files answer as `path_fileops`. D171: every failure after the reply retires the object exactly once (`dq_object_retire_unbound`, `ds2_resolve_retired`, `CLOSE` when subscribed). The ledger gains ACCEPT/COMPLETE/XFORM columns and an `EDQRESOLVED` containment check run in every kernel build. libdq: reply helpers and `dq_serve_tree`'s iii-a mode (di_path = the real-namespace name resolved) | stage1c-iii plan rev 2, review and re-review | iii-b: served directories and starts |
| D178 | 2026-11-08 | Stage 1c sub-series iii-a (served answers from real starts) built, reviewed independently twice (the first found a reply of any op whose first word equalled `DQ_RESOLVE_FD` being read as a mint — a GETLK `F_UNLCK` answer timed out three lock tests in run 37 — and a use-after-free of the reply in `dq_resolve_consult`; both fixed) and qualified. Plane-on VM run 39 (`sys/dq`, `lib/libdq`, `sys/kern`, `sys/file`): 3943/4005, no LOR or panic; the 11 failures are the baselined ones (D155) plus `linux_trace_test:dtrace_sdt`, which is intermittent on dev without iii-a too (1 of 4 isolated runs; recorded in 5bsd-issues 2026-11-08-linux-trace-sdt-flaky.md); `post_reply_enfile` skips because the capability plane's SYSCTL gate refuses `kern.maxfiles`, and `post_reply_enfile_inject` covers the same path through `debug.dq.fail_bind_enfile`. Carried to iii-b: `fchmodat`/`fchownat` with `AT_EMPTY_PATH` on an `O_PATH` served fd give `EBADF` (object-level setattr) | 1c-iii-a reviews 2026-11-08, runs 37-41 | |
| D179 | 2026-11-08 | Stage 1c sub-series iii-b (served directories and starts) built, not yet run or reviewed. Kinds `DIR` (MINT and FD; `S_IFDIR`; write/exec/mmap-shared `DENY`, cache NONE/ATTR) and `SYMLINK` (FD only, its target after the mint, `di_size` = target length kept by SETIDENT and GETATTR, `O_PATH` only, answers only `NOFOLLOW` lookups). `READDIR` (`dq_dir.c`): body `{cookie, len}`, reply `{next, eof, len}` + native dirents, every record validated (reclen multiple of 8 and ≥ `_GENERIC_DIRLEN`, namlen 1..MAXNAMLEN, NUL, no `/`, known `d_type`, `.`/`..` DT_DIR or DT_UNKNOWN), `next ≤ OFF_MAX`, empty-not-eof refused, malformed → `EINVAL` to the controller; a buffer below `sizeof(struct dirent)` is `EINVAL` with no event; the offset is the cookie. Directory descriptors: `read` `EISDIR`, `mmap` and `sendfile` `EINVAL` (the vnode oracle; the plan said `ENODEV` for mmap), `SEEK_DATA`/`SEEK_HOLE` `EINVAL`, kinfo VDIR/VLNK. Served starts through `fgetvp_lookup_start` asking the vector (`dqres_lookup_start`, `dro_start`); `namei_setup`'s served branch before the VDIR test; `dqres_namei_served`: unmarked/class 2/3/exempt `ENOTDIR`, `OPENNAMED` `EOPNOTSUPP`, D163 `EDEADLK`, revoked `EIO`, the B2 pre-checks (absolute, RINROOT, leading `..` after `.`/empty components; any `..` under capability-mode or limited-rights STRICTREL when `lookup_cap_dotdot=0` — `O_RESOLVE_BENEATH` alone keeps `..` as namei does), post-checks (component-boundary prefix of the start's `di_path`; NOXDEV `ds_fsid`/`di_dev`), never PASS, audit with the raw path and `dq_start`/`dq_object` tokens (`ARG_DQSTART`, `ARG_DQOBJ`). D170: mixed two-path starts `EXDEV` with no event (`ds2_resolve_exdev`), both served one OK event (`drs_start2`), fhlink into a served start `EXDEV`, funlinkat/frmdirat served fd → `drs_object` (a real path `EDEADLK`), real fd + served path `EDEADLK`. `REAL` (D167): accepted for class-1 non-PATH2 lookups (real and served starts, ahead/content slots) never under STRICTREL/BENEATH/RINROOT/OPENNAMED/NOSYMLINKS/NOMAGICLINKS/NOXDEV or an empty path; rewrite counts one `ni_loopcnt` step, `ni_rootdir = pwd_rdir`, `ISRESTARTED`, audit re-recorded; cached in the slot (`ds_real`) for restarts and carried slots. D172 (b): every symlink of a PASSed class-1 non-carried lookup is re-consulted (`REAL_ROOT` or `REAL_SYMDIR` + hint, `SYMLINK_RESTART`), skipping exempt regions and CAP_DOTDOT/STRICTREL/RINROOT; the re-consultation is not counted separately (its symlink step was), so attached processes keep `MAXSYMLINKS`. SETATTR answered FD on a SYMLINK, and `fchmodat`/`fchownat(AT_EMPTY_PATH)` of an `O_PATH` served fd, go through the object-level setattr (`dro_setattr`); `readlinkat(fd, "")` returns a served symlink's target; `O_EMPTY_PATH` on a served fd of the own queue posts OPEN/EMPTYPATH from it. Start rights ∩ policy rights (and fcntls; an ioctl-limited start gives no ioctls), `O_RESOLVE_BENEATH` inherited. Slots record the served start's object id (never reused per queue) rather than holding its file. libdq: dir/symlink/REAL/READDIR helpers, `dq_serve_file` READDIR and `O_PATH` setattr, `dq_serve_tree` iii-b mode (`DQ_TREE_F_SERVED`, `dq_tree_root`, REAL for device/FIFO/socket nodes, AF_UNIX, outside names and backing symlinks leaving the prefix; `DQ_TREE_F_EXEC_REAL`). Tests: `dq_start_test` (12 cases), `dq_tree_oracle_test`. Not in iii-b: the D177 snapshot, served cwd/root, `execpath` (nothing to do without a served cwd or root), Linux NOXDEV rows, the audit trail test | stage1c-iii plan rev 3, 1c-iiib notes | iii-c: virtual cwd and root |
| D180 | 2026-11-08 | iii-b review round 1 ("not yet") fixed. The second path of a two-path operation is checked against its own descriptor before posting, since an OK answer completes the operation without its namei: the operation's rights (`dq_intent_slot_rights`: `CAP_RENAMEAT_TARGET`, `CAP_LINKAT_TARGET`) plus `CAP_LOOKUP` through `fget_cap`, `UF_LOOKUP_CAPMODE`, capability mode (`ECAPMODE` at `AT_FDCWD`), the D165 pre-checks under its own STRICTREL/BENEATH (posted as `DQ_RF_STRICTREL2`/`DQ_RF_BENEATH2`), and the errors its lookup would give (`EBADF`, `ENOTDIR`, `EXDEV` for another queue's served directory, counted); a restricted real second start takes no OK. A REAL rewrite keeps a trailing `/`. `frmdirat`'s served descriptor needs `CAP_LOOKUP`. The start's ioctl list is carried and installed, intersected with the policy (deviation 6 withdrawn). A served `O_PATH` symlink gets `FKQALLOWED` when readable. A path consulted ahead under capability mode or a limited/BENEATH dirfd takes no REAL. The served branch checks carried slots inside exempt regions. `dq_serve_tree` resolves paths component by component through the backing tree (no lexical `..`), and REAL targets and `di_path` are the walked names. Tests: heads (root, timeout), fdescfs `ENOTDIR` row (devfs `/dev/fd` without fdescfs has only 0-2: `ENOENT`), full listing, observer READDIR and REAL replies, slot-1 restriction rows, vnode-less slot 1, trailing slash, limited-rights REAL, re-consultation skips, kqueue on a served directory and an `O_PATH` symlink, the validator rows, oracle rows for `..` and an escaping symlink, audit tokens (`tests/sys/audit/dq_served`). Not testable natively: RINROOT and NOXDEV (Linux `openat2` only), exempt-region re-consultation | iii-b review round 1 | |
| D181 | 2026-11-08 | iii-b review round 2 ("not yet") fixed. `dq_serve_tree` applies the lookup's restrictions (STRICTREL, BENEATH, RINROOT; the second path's STRICTREL2/BENEATH2): from the start's depth, a `..` above it, an absolute name or symlink target, and any `..` under capability mode with `vfs.lookup_cap_dotdot=0` are `ENOTCAPABLE` (RINROOT clamps); a restricted real lookup is PASSed without walking. Every backing access is confined with `O_RESOLVE_BENEATH`/`AT_RESOLVE_BENEATH` (mutations through an `O_RESOLVE_BENEATH` parent and the bare name; `readlinkat` through a confined `O_PATH` fd), so a swapped symlink cannot take the controller out. Symlink expansion past `MAXPATHLEN` is `ENAMETOOLONG`; names outside the prefix are canonical by `realpath(3)`. Kernel: a real second start that is restricted or unusable takes PASS only and its own lookup reports in FreeBSD's order (EXDEV for another queue's served directory and the served-second-start refusals stay early); an empty second path is `ENOENT` before posting; a REAL rewrite after a final `.` or `..` ends in `/`. FreeBSD's `linkat`/`renameat` never apply `AT_RESOLVE_BENEATH` to path 2: matched | iii-b review round 2 | |
| D182 | 2026-11-08 | iii-b review rounds 3 and 4 fixed and qualified. A served second start's deferred error is returned before posting, and with a served first start the second path's errors follow FreeBSD's order (empty path ENOENT, ECAPMODE, absolute-path ENOTCAPABLE, the descriptor's own error, ENOTDIR/EIO, then EXDEV); a real second start that is restricted or unusable is offered PASS only. `kern_dqres.c` lacked `opt_capsicum.h`, which silently compiled out the `UF_LOOKUP_CAPMODE` check (found by VM run 47; no other non-global option is compiled out in dq). `dq_serve_tree` mirrors `vfs.lookup_cap_dotdot_nonlocal` for STRICTREL and BENEATH. Reviewed independently four times ("ready to commit"); plane-on VM run 49 (`sys/dq`, `lib/libdq`, `sys/kern`, `sys/file`, `sys/audit`): 4384/4447, all 224 dq cases and the three `sys/audit/dq_served` cases pass, no LOR or panic; the failures are the baselined ones plus the two `sys/audit` clock-setting cases the VM's time service refuses | 1c-iii-b reviews 2026-11-08, runs 43-49 | |
| D182 | 2026-11-08 | iii-b review round 3 ("not yet") fixed. The second path's own lookup errors are recorded at fetch (`ds_ferr`: an empty path's ENOENT, ECAPMODE at `AT_FDCWD` or ENOTCAPABLE for an absolute path in capability mode, the descriptor's `fget_cap` error, `UF_LOOKUP_CAPMODE` outside capability mode, ENOTDIR for a file, EIO for a revoked served directory): behind a real first path the slot takes PASS only and its namei reports them in FreeBSD's order; behind a served first path they are returned before posting, ahead of the mixed-start EXDEV, so a `cap_lookup_capmode` served second start is refused. `dq_serve_tree` mirrors `vfs.lookup_cap_dotdot_nonlocal` (a `..` from a non-`MNT_LOCAL` directory under STRICTREL). Run 44: `open("new/", O_CREAT)` is ENOENT in FreeBSD (TRAILINGSLASH without WILLBEDIR), not EISDIR as the plan said; the kernel matched and the test compares with the real file system | iii-b review round 3, run 44 | |
| D183 | 2026-11-08 | Stage 1c sub-series iii-c (virtual cwd and root) built, not yet run or reviewed. D177: `pwd_hold_dqres` (the pwd and `fhold` of `dr_cwd`/`dr_root` in one `PWDDESC_XLOCK` section) in `namei_setup` and for every fetched slot (`dq_islot_fetch`), so a served start and a real pwd never come from both sides of a `chdir`. Served cwd and root starts (`dqres_namei_start`): absolute non-`RINROOT` paths under a served root and relative `AT_FDCWD` paths under a served cwd start at the served directory through the served branch (`DQRES_START_ROOT`/`CWD`), after `namei_handle_root`'s capability test; ahead and two-path slots fetch the same starts (both served on one queue: one event; mixed: `EXDEV`). D175: kernel-consumer slots (ktrace, acct, swapon, kldload, mount options, ...), kernel-origin lookups other than the absolute interpreter path under a served root, and unmarked user-space lookups whose start would be served are `EXDEV` with no event (`ds2_resolve_exdev`; unmarked counted too); the interpreter (`PT_INTERP`, absolute `#!`) is consulted at the served root as class 3 accepting only `REAL`/errno, after `exec_new_vmspace` for ELF (an errno kills the image); exempt regions keep the real pwd, carried slots excepted. D172 (a): an absolute symlink target met by any lookup of a process with a served root re-consults from the served root (served kinds of slot 0, `REAL`, errno); carried second paths `EXDEV`, ahead/content slots `EIO`, class 2 and unmarked `EXDEV`; `dq_symlink_served_root` joins the `EDQRESOLVED` producers in the ledger. New kernel guard: under a served root every `FD`/`ATTR`/`LINK` result must be at or under the root's `di_path` (`ENOTCAPABLE`, object retired) — the "post-check" behind the controller's clamp of `..`. D169: chdir/chroot answered `FD(DIR)` (`dqres_take_dir`: kind, D166 `VEXEC`, bind `FREAD`), chroot's privilege rule factored to `chroot_priv_check`; fchdir/fchroot of a served dir (`dqres_fchdir_file`, `dqres_dir_check`: `UF_RESOLVE_BENEATH` `ENOTCAPABLE`, kind `ENOTDIR`, D163 `EDEADLK`, revoked `EIO`, `VEXEC`); `ATTACH` `da_rootfd`/`da_cwdfd` (live served DIRs of the queue, `EINVAL`/`ENOTDIR`/`EIO`); `pwd_chdir`/`pwd_chroot` clear `dr_*`; `chroot_refuse_vdir_fds` counts served directories (`dro_file_kind`, lock-free) and a served root counts as chrooted. D174: `vn_getcwd` (`dqres_getcwd`: served cwd presented, real cwd under a served root `ENOENT`, dead `EIO`, short `ENOMEM`→`ERANGE`), `realpath` (`ATTR` presented; any real or `REAL` object under a served root `ENOENT`), kinfo CWD/ROOT rows from `dr_*` exported after unlocking (dead: no row), `dq_fill_kinfo` presenting against `curthread` (the viewer rule), linprocfs `cwd`/`root` (`dqres_proc_dirpath`) and `fd/` (through `fo_fill_kinfo`). `execpath`: absolute names verbatim, relative ones joined lexically to the served cwd's presented path (`dqres_execpath`). `kern_proc_filedesc_out`'s error path also drops the pwd it held (an upstream leak). libdq: `dq_attach_starts`, `dq_serve_tree` `DQ_TREE_F_ROOT` (absolute names from the event's start, `..` clamped at the tree root, CHDIR/CHROOT → FD(DIR), EXEC_INTERP → REAL of the tree's interpreter). Tests: `dq_cwd_test` (9), `dq_getcwd_test` (4), `dq_kclass_test` (2), `dq_exec_test` (5), the served-root suites oracle `dq_tree_suites_test` with `dqtree` and `dqtree.expected`, and `tests/sys/kern/pwd_paths_test` (13: the real paths at base 33ef5272d53, and the same cases under dqpass). Not built: the unmarked-lookup fault injection row, the `fhold`-overflow (`DR_*_DEAD`) rows, `$ORIGIN` library loading | stage1c-iii plan rev 3, 1c-iiic notes | iii-c review |
| D186 | 2026-11-09 | Owner decisions on supervisor control (open item 20). (1) Dynamic attachment carries control: ATTACH, whether of a child or of a process attached by Switchboard or an OpenES exec hold, gives the supervisor a process descriptor for the target (pdkill, pdwait; kill and stop/continue without a credential check), bounded to processes attached to that queue and to the descriptor's rights. (2) A reply may carry a signal that the kernel raises on the requesting thread with the errno, synchronously, as for SIGPIPE, SIGXFSZ, SIGBUS, SIGSEGV and SIGSYS. (3) Supervisor death kills its served processes, with a kernel-style signal (SIGKILL), instead of the fail-closed EIO they get today (the "Fail closed" rule above, D154); a dead supervisor never leaves a served program running. (4) Deep audit: attach, detach, every kill/stop/continue through the descriptor, every reply-raised signal, every revoke and every death-of-supervisor kill produce an audit record naming the supervisor, the target, the queue and the reason, and an OpenES event; the served process's death record says it was killed by its supervisor. (2) lands in ux-2; (1), (3), (4) in series sc before stage 4. | owner, 2026-11-09 | |
| D185 | 2026-11-09 | Served symlink targets may be empty, as on UFS: a `LINK` answer and a SYMLINK mint (`di_size` 0) accept a zero-length target (`dq_resolve_target_validate(..., emptyok)`), and the tree server returns readlink(2)'s 0; namei already answers `ENOENT` for an empty link before any D172 re-consult (`vfs_lookup.c:721`), so `stat` through it is `ENOENT` as upstream. A `REAL` path stays non-empty. Pathconf values are presented for every served type but symlinks (plan D248, done early): `sysconf(_SC_TTY_NAME_MAX)` in a served root works. Attached behaviour only. | run-59 triage (realpath2 empty symlink; ttyname listing abort) | |
| D184 | 2026-11-08 | iii-c review round 1 ("not yet") fixed, with the user's decisions. An unattached process (the controller included) using a served directory as a lookup start (dirfd, fchdir, fchroot, funlinkat's descriptor) is `EACCES`; one attached to another queue keeps `EDEADLK` (D163 amended). The served root namei_setup snapshots is held by namei until it returns, and the D172 (a) re-entry uses it, so a racing chroot cannot move the re-entry to the real root (D177 completed); the re-entry also runs D165's post-check. Every served answer under a served root is guarded, from real starts too (`dqres_namei`). The `RESOLVE` body grows to 112 bytes: `drs_root` (@96), `drs_rootpathlen` (@104), `drs_pad2` (@108) and the root's `di_path` as a fifth string, so a controller resolves `/`, absolute link targets and `..` at the process's own (possibly nested) root; `dq_serve_tree` does, matching chroot(2), and answers `EIO` for a served start whose hint is missing or not the object's own path. ATTACH: a root without a cwd makes the cwd the root; a cwd must be under the root (`EINVAL`); with a root the child's open directories follow chroot's rule (`kern.chroot_allow_open_directories`, `EPERM`) unless `DQ_ATTACH_F_NODIRS` refuses any real directory (`EBUSY`); other `da_flags` bits are `EINVAL`. `DQ_TREE_F_ROOT` trees refuse real-start names outside the tree with `EACCES` unless `DQ_TREE_F_OUTSIDE_PASS`. Served CWD/ROOT kinfo rows carry `KF_FLAG_READ`. Unattached behaviour is unchanged; attached behaviour is the controller's to choose. Round 2 of the review: `DQ_API_VERSION` becomes 2, because the `RESOLVE` body's strings moved (96 → 112 bytes); every versioned ioctl accepts 2 only (`EINVAL`) and events report 2. ATTACH's default open-directory rule is chroot's rule exactly, applied with a root, so with the default `kern.chroot_allow_open_directories=1` an unchrooted child keeps its inherited real directories; `DQ_ATTACH_F_NODIRS` refuses them with or without a root, and a root whose reference count cannot take the cwd's too is `EIO` (a dead start), not `EBUSY`. Only an attached process's served directories count for the open-directory rule, so an unattached process's `chroot(2)` is exactly upstream's. A dead served root (`DR_ROOT_DEAD`) makes every consulted lookup `EIO` before posting, so no event carries `drs_root` 0 for a served root and no answer escapes the guard; the guard checks against the root identity that was posted. A slot fetched ahead keeps the served root of its own start's snapshot (`ds_root`), and D172 (b)'s symlink re-consultation posts the root and is guarded too. The snapshot is `struct dqres_snap`, held by `namei` from `namei_setup` to the end | iii-c review rounds 1-2, user decisions 2026-11-08 | |
| D192 | 2026-11-17 | **Served waits are disk waits by default** (Unix-illusion plan rev 8 ux-2, landed in dq-transparency C8). A data or attribute wait of an object, and a process's own lookup, catch no signal: only the answer, the deadline, `SIGKILL`, the exit, or a sibling's `_exit` (`P_SINGLE_EXIT`) end them, in non-catching 100 ms slices that a signal storm cannot make spin. `DQ_PF_INTR` per object and `DQ_QF_INTR` per queue give NFS `intr` semantics; lock waits always catch, faults never | rev 8 3.1 | the FreeBSD local file system and fusefs contract |
| D193 | 2026-11-17 | **`EINTR` is the kernel's alone.** No controller answer carries `EINTR` (or `ERESTART`), for any operation; one that does is `EIO` and a bad reply | rev 8 2.2 | a program sees `EINTR` only for a signal it received |
| D194 | 2026-11-17 | **A served write's short count.** After at least one accepted chunk, any error that ends the call gives the count moved and is dropped (ZFS's and POSIX's rule); ufs's `IO_UNIT` rollback (`DQ_PF_WRITE_UNIT`) is not built yet | rev 8 3.2 | the offset and size already follow the accepted bytes |
| D205 | 2026-11-17 | **A full queue waits.** A waited post waits for a slot in its own mode and within its deadline (`ds2_full_waits`); each slot read off or withdrawn wakes one waiter, which passes it on if it cannot use it | rev 8 3.3 | no `EIO` and no lost event for a momentarily full queue |
| D300 | 2026-11-10 | **The supervisor acquires and decides; the kernel executes against the real object whenever one exists.** The default answers are to proceed on the object named or to provide a different real descriptor; proxy objects fill in where neither exists and are one mechanism presenting as whatever kind was asked for; objects whose bytes the supervisor produces stay supported as the exception. Applies to locks at once and to sockets in stage 2. Principle 7 | owner | a userspace re-implementation of kernel behaviour (lock table, access checks, mutations) can only approximate the kernel; executing on the real object is exact and needs no round trip |
| D303 | 2026-11-10 | **Swap first, then proxy; one mechanism.** The next deliverable is the swap: a program's acquisition is answered with a real descriptor the supervisor controls, of the same kind, installed by the kernel. The same machinery then swaps in a proxy object the supervisor controls, and after that a proxy over a real object. First use: a supervisor that holds the program's open, copies and redacts the file, and provides a descriptor for the redacted copy. Proxy-only work (advisory lock fixes, remaining served-operation differences, open item 17) is parked until the swap works end to end. Design note reviewed independently before any code; tests in three columns (unattached, swapped, proxied) | owner | the simplest path to a working confinement; a real descriptor behaves as FreeBSD by construction; one installation path instead of two |
| D304 | 2026-11-10 | **Death-kill before the swap.** The supervisor-control slices that kill served programs when their supervisor dies (pinning tests, the non-transferable queue descriptor, the kill, and the kill reaching a program stopped under a debugger) land before a program can receive a swapped descriptor | owner | a swapped real descriptor cannot be revoked and outlives the supervisor; the kill is the only fail-closed backstop |
| D305 | 2026-11-10 | **A swapped descriptor is transferable by default.** It may be passed to other processes as any FreeBSD descriptor may. A supervisor may restrict a particular answer; the restriction is best effort and is not documented as containment | owner ("that's default behavior") | the program sees ordinary Unix behaviour; the per-entry transfer restriction is not enforced on every path that moves a file |
| D306 | 2026-11-10 | **The swap shares the supervisor's open file.** The kernel installs the open file the supervisor supplied; it does not create a fresh one. File position and status flags are shared, so the contract is one fresh open per answer, closed by the supervisor after the reply succeeds | owner | less mechanism, and the same rule carries to objects that are not files |
| D307 | 2026-11-10 | **The confinement is a kernel boundary.** The purpose is redaction, so running attached programs under a dedicated user is a stopgap, not the answer. (1) An attached program cannot act on or inspect by process ID any process outside its supervisor's attached set; such a process is reported as not existing, as for a process outside a jail. Nothing changes for an unattached program, for an outside process acting on an attached one, or for waiting. (2) Named shared memory, semaphores and message queues are closed in the same series; the promise does not depend on a jail. (3) The kernel does not audit a target's descriptors in general at attach; the launcher library closes everything the supervisor does not name, by default. (4) The manual states the limit: the kernel stops an attached program taking, it cannot stop an outside process handing content over a channel the supervisor allowed. (5) The redaction demonstration waits for the boundary; the swap itself does not | owner ("for now") | "It's redaction. We will need a real solution." |
| D317 | 2026-11-10 | **`TIOCSTI` is refused to an attached caller**, with `EPERM`, the error the call already gives when the system-wide switch is off. An attached job that shares the launching shell's terminal could otherwise type commands into that shell | owner | closes a channel the boundary rule alone leaves open |
| D318 | 2026-11-10 | **Attach refuses a target whose address space is shared with another process.** Memory shared with an outside process is a channel the supervisor is never asked about | owner | closes a channel the boundary rule alone leaves open |
| D319 | 2026-11-10 | **No existence oracle.** `ktrace`, Linux `get_robust_list` and Linux `pidfd_open` answer an attached caller that an outside process does not exist, as the other calls do, and no longer distinguish it from a process ID that is not in use | owner | closes a channel the boundary rule alone leaves open |
| D320 | 2026-11-10 | **No rule on process groups or the terminal's foreground group.** `setpgid` and `TIOCSPGRP` behave as on FreeBSD for an attached program, so the launching shell's job control and an attached shell's own job control both work. Accepted cost: an attached background job can take the foreground for its own group and read what the user types on that terminal; a supervisor that cares gives the job a terminal of its own, and the manual says so | owner | closes a channel the boundary rule alone leaves open |
| D321 | 2026-11-10 | **A process descriptor is a name, not authority, to capability-plane services.** Where a plane service resolves a process descriptor on behalf of an attached caller, the boundary check applies. The plane's own open item on attached callers (D88) stays open and is stated as a condition | owner | closes a channel the boundary rule alone leaves open |
| D322 | 2026-11-10 | **`DQ_ATTACH_F_NOPROCS`, opt in.** With the flag, attach refuses a target whose descriptor table holds a process descriptor, a Linux pidfd or a plane instance. This refines D307 (3): it is the existing scan by descriptor kind, not a general audit | owner | closes a channel the boundary rule alone leaves open |
| D323 | 2026-11-10 | **Attach refuses a target that has more than one thread**, with `EBUSY`. The kernel cannot stop another process's threads from outside, and a second thread can change the target's state during attach. Accepted loss: adopting by process ID a threaded program that is already running | owner | closes a channel the boundary rule alone leaves open |
| D324 | 2026-11-10 | **System V IPC works for attached programs, in a namespace private to the confinement.** Shared memory, semaphores and message queues created by an attached program are found and used only by programs of the same confinement, and objects from outside are not visible inside; the answers are those a jailed program gets for another jail's objects. By default this holds in both directions, for root as well. A supervisor may, before it attaches anything, turn on outside visibility for its queue: unattached programs may then see that confinement's objects in listings and use them by identifier under the ordinary permission checks, so that an attached X11 client can share memory with a display server outside. Accepted cost of turning it on: an attached program can then make an identifier that an outside program still holds refer to its own object, as any local process can on FreeBSD. A confinement's objects are removed when its queue is closed for the last time. A segment from outside that a target has mapped when it is attached is the launcher's duty; an exec discards such mappings | owner | programs that need System V IPC must run confined ("Yeah we'd need that"); a refusal would not do |
| D325 | 2026-11-10 | **Signal-on-I/O ownership honours the boundary.** An attached program cannot make an outside process the owner of a descriptor's I/O signals (`F_SETOWN`), and such signals are not delivered across the boundary | owner | closes a channel the boundary rule alone leaves open |
| D326 | 2026-11-10 | **Swap covers the calls that name a path, and must look transparent on its own.** A supervisor substitutes a descriptor it provides only on calls by which a program names a file system path; calls that create a descriptor without naming a path (`socket`, `pipe`, `kqueue` and the like) are not consulted for swap. A swapped descriptor is to present the name the program expects without a proxy descriptor; how is a design question under review. Swap is made solid first; proxy descriptors and the emulation work for served objects follow later (D303) | owner | ambient authority enters through names; a real object needs no emulation |
| D327 | 2026-11-11 | **A queue may have a name root.** A supervisor may name one real directory for its queue, once, before the first attach, and keep substitutes below it at the paths the program expects. Path reports made to attached programs (`getcwd`, descriptor and mapping paths, the executable path) are cut at that directory; lookup is not moved. The kernel's own records (audit, OES, tracing, accounting, core dump names) keep the true path. Without a name root nothing changes. The name root cannot be changed or removed | owner | the reported path was the one visible difference a real object could not hide; a moved lookup root would need a full mirror |
| D328 | 2026-11-11 | **Swap may land before the boundary is complete.** The kill-first slices (D304) still precede it and the whole test suite is run in swap mode after the core commits. The redaction demonstration still waits for the boundary (D307) and until then swap is described as substitution, not confinement | owner | substitution is useful and testable on its own; the claim, not the code, depends on the boundary |
| D329 | 2026-11-11 | **The first version's remaining visible differences are accepted.** The substitute's own device, inode, link count, times and file system statistics; real mount names; the real entries of a swapped directory; `..` above the name root, which the supervisor must refuse; two objects reporting `/`; a supervisor's rename, link or unlink of a substitute showing at once; open-file state shared with the supervisor (D306); the lower path of a file mapped through a nullfs mirror; timing. None gives access to an original object. Removing them is the work of proxy descriptors (D303) | owner | each is a tell, not access; hiding them needs emulation, which comes second |
| D330 | 2026-11-11 | **Exec of a substitute follows the first version.** The first version answers an exec by name with allow or an error, so a script or a newly built binary in a substituted directory does not run until exec by descriptor lands as the next step | owner | exec is a shared kernel path with its own review; the open path is made solid first |
| D331 | 2026-11-11 | **Unix-domain socket names are not swapped in the first version.** `bind` and `connect` by path are answered allow or an error. These calls name a path and so belong to swap's scope (D326); they are deferred, and until then a socket an attached program binds exists at the real path | owner | a socket name has no descriptor to substitute at lookup; needs its own design |
| D332 | 2026-11-11 | **Root cannot remove a single System V object of a confinement.** `ipcrm` on one fails; closing the confinement's queue removes them all (D324). For a queue opened to outside processes the ordinary permission rules apply | owner | one rule with no exception; any local user can already fill these tables |
| D396 | 2026-11-17 | **A real object under a served root shows no path (Q1 default).** `F_KINFO`, `procstat -f`/`-v`, `/proc/self/maps`, `/dev/fd/N` readlink present a real object's path through `dqres_present_real`: empty (readlink `ENOENT`) for a viewer under a served root, unchanged for every other viewer. The "one rule" (rewrite to the presented path) is one switch in `kern_dqres.c`, off until the owner answers Q1 | dq-transparency C4 | closes the leak, matches `realpath` `ENOENT` |
| D397 | 2026-11-17 | **Post-op attributes (Q2).** A `READ`/`WRITE`/`FALLOCATE`/`FSPACECTL` reply may carry `struct dq_postop_attr` (`DQ_REPLY_F_POSTOP`); the kernel applies size and times, ignoring (and counting in the system-wide `kern.dq.postop_ignored`, with the queue named by `dq:::postop-attr`) a block whose size is below what the reply itself proves; with no block it stamps the times itself unless the policy has `DQ_PF_NO_STAMP`. All size writes go through one helper | dq-transparency C7a/b | NFS's post-op attributes; times move as on a local file |
| D398 | 2026-11-17 | **FSPACECTL remaining range.** A reply's remaining range is either empty at the end of the request or ends where the request ends; anything else is a bad answer (`EIO` to the program) | dq-transparency C7c | the `fspacectl(2)` contract |
| D399 | 2026-11-17 | **Strict swap admission (Q3).** A substitute is refused (`EFTYPE`, `dqres:::subst-refuse`) when the request's path has a trailing slash and the file is not a directory, its offset is not 0, it holds an OFD lock, it holds a `flock` the request did not ask for, an exclusive locked creation's file holds no lock, or its entry carries locked close-on-exec/close-on-fork or capability-mode flags | dq-transparency C3 | the program sees what its own open would have produced |
| D400 | 2026-11-17 | **The quota wait shares the event's deadline.** Waiting for an object's or a requester's in-flight slot is bounded by the deadline of the event it precedes, `EIO` and `ds_deadline_misses` at expiry, with nothing posted | dq-transparency C2 | no unbounded wait before a post |
| D401 | 2026-11-17 | **The swap moves the file (Q6).** The kernel closes the supervisor's descriptor under the same table lock as the take; the reply then returns 0 or `ECANCELED` (taken, program gone; swap-only), any other error leaving the descriptor the supervisor's. Answers §21 item 21 (a): moved, not shared | dq-transparency C3 | no forgotten close, no reused-number hazard; D306's duty becomes the kernel's |

D187-D299 are allocated to the Unix-illusion and supervisor-control series
and enter this record as those series land; D301 and D302 belong to the
first Unix-illusion slice.

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

1. Stage 4 attach-decision inputs (11.5). Direction from the owner (2026-11-08): **userspace supervisors**. A supervisor is a unit launched by Switchboard (or Capsule for early boot), possibly on demand as Switchboard launches providers; a program is marked for supervision (a brand: protected extended attribute or embedded ELF entitlement); OpenES holds its exec as an authorisation event until a supervisor has claimed it, and the supervisor attaches through its descriptor queue before the new image runs any code. The supervisor stands in for the kernel and keeps its ABI; unattached programs see no difference. Open: the brand, the attach-during-exec hook, set-id brands versus I5, and whether a trusted supervisor may grant privilege.
2. `getfh`: present a handle that only `fhopen`s to `ESTALE`, or refuse.
3. Per-site VM dispatch decisions (10), recorded in the ledger in stage 1b.
4. Tunable defaults after stage 1a measurements.
5. An atomic `pdfork` variant that attaches at fork, closing the handshake
   window entirely (D55 makes the handshake safe; this would make it
   unnecessary).
6. The `EDEADLK` rule scans the caller's descriptor table on every
   operation that posts (15.4, D91); measure it with stage 1a in place and
   decide whether a per-filedesc mark is warranted before stage 2's sockets
   multiply the posting paths.
7. Observer data bodies (`DQ_OBS_F_DATA`) for replies: in 1a the reply
   buffer belongs to the waiter and only lengths reach observers; a data
   observer arrives with the pager (1b), where pages can be shared.
8. How `attached` reaches the `mac_capability` caller trailer (D88): the
   three pad bytes after `abi`, or a new ioctl; and the `SVC_NO_ATTACHED`
   flag D61 assumes (1c).
9. BSDDevice's policy must refuse the `dq` leaf as it refuses `oes` when
   the stage 4 provider exists; until then the node's mode and
   `PRIV_DRIVER` are the rule (D85).
10. Found while testing D89, not dq's: OES's `oes_client_is_muted()` fails
    open when it cannot `mtx_trylock` the event process (`oes_client.c`,
    "Can't check, don't mute"), so a self-muted client occasionally receives
    its own events (a `NOTIFY_DQ_REPLY` reached the controller that way).
    `oes_client_is_muted_by_token()` could decide from the captured
    pid/genid without the lock; that changes OES mute semantics and is an
    OES change, recorded here for its owner.

11. A sloppy racct resource (`RACCT_DQPEND`) for pending served writes, so
    rctl can see and bound them; until then `kern.dq.max_inflight_bytes` and
    `GET_STATS2` are the bound and the view (D102, D59 amended).
12. inotify on a served *file* (`IN_MODIFY`/`ACCESS`/`ATTRIB`/`CLOSE`):
    watches live on directories, which `RESOLVE` serves in 1c; the file
    events must be raised there against the served parent.
13. A kernel without `KDTRACE_HOOKS` does not link on this tree, independent of dq:
    `AUDIT_RET_MBUFID` is defined only with `KDTRACE_HOOKS` but used by
    `uipc_socket.c` and `bpf.c`, `subr_mbufid.c` (standard) needs
    `dtrace_node_id`, and two files fail `-Werror` unused-but-set. dq's own
    objects compile in that configuration.
14. The Bazel side of 1c-i (dq header dependencies on 24 targets and
    `//sys/dev/dq:resolve_ledger_test`) has not been built: `bazel query`
    stops at the unregistered `bsd_sdk` module in this checkout. The Make
    kernel build is the authoritative ledger check.
15. `linkat(servedfd, "", AT_EMPTY_PATH, …)` with both paths served is
    `EXDEV` like every served empty-path link (Q5, D164); serving it as a
    link of the object itself is open.
16. `dq_serve_tree` checks parent-directory access with the requester's
    effective uid and gid only; supplementary groups are not presented in
    the event (Q11), so the suites oracle lists those cases in
    `dqtree.expected`.
17. **Pass-through I/O for proxy descriptors** (owner, 2026-11-08; since D303 this is "a proxy over a real object", built on the swap machinery as step 3 of section 18's order, and it covers locks as well as data). A supervisor attaches a real backing descriptor to a proxy object, at mint or later, and the kernel then performs that object's reads, writes and mappings on the backing file directly, with no round trip, while the supervisor keeps lookups, attributes, locks, close, revocation and policy; it can detach the backing file again. Comparable to Linux FUSE passthrough (2024). Open: revocation must still cut access at once (mappings of the backing file included), identity and size come from the object or the backing file, and how the data cache and the pager interact with a backing vnode.
18. **Stage order and the last stage** (owner, 2026-11-08; section 18 gives what D303 places before these stages). Stages after 1c and the Unix-illusion series: 2 sockets, 3 exec of proxy files, 4 devices, 5 every remaining descriptor type (each kind of descriptor gets a proxy form, from a type-by-type inventory), and 6, last, discovery and association: how the system decides that a program needs a confinement and which userspace supervisor provides it. Stage 6 keeps the direct-child attachment already built and adds (a) responsible processes, so that a program Switchboard execs on someone's behalf is matched by the party that asked, not by Switchboard; (b) registration, so that supervisors declare interest like device drivers (match on a brand, signing identity, path, responsible process or user, or a launcher's request, with probe priorities as in newbus) and are called, or launched on demand by Switchboard, for arbitrary programs; (c) the OpenES exec hold until a supervisor has claimed and attached the program; and (d) the policy when nothing matches. Terms: a confinement is built from proxy descriptors, the supervisor queue (this device), OpenES, Capsicum rights and the transfer controls, and capability-plane isolates. Direction for (b) (owner, 2026-11-08): a confinement is a capability bundle (`.cap`) whose manifest declares that it provides a confinement and what it matches: an identifier (a target bundle's reverse-DNS name or a signing identity), a path, or a MAC label stored in the program's extended attributes (the brand). Switchboard launches and supervises the bundle like any other; matching happens in one place, so the forms coexist.
19. **Readiness for every proxy descriptor type** (owner, 2026-11-08: proxy descriptors must work anywhere a descriptor does, poll, select and kqueue included, and inside any kqueue). Proxy files already behave as vnodes do (always ready under poll and select; EVFILT_READ, EVFILT_WRITE and EVFILT_VNODE in any kqueue). Stages 2, 4 and 5 need a readiness protocol: the supervisor pushes readiness (readable, writable, hang-up, error, with counts) through the supervisor queue; the kernel keeps each object's readiness so poll, select and kqueue answer without a round trip and wake waiters on change; kqueue keeps full semantics (kn_data, EV_EOF, NOTE_LOWAT, EVFILT_EXCEPT); non-blocking I/O returns EAGAIN exactly when not ready; tests compare each proxy type with its real counterpart, alone and mixed in one kqueue. ux-5 adds the file oracle (poll, select, kqueue against a vnode, including EVFILT_READ kn_data).
20. **Supervisor control over served processes** (owner, 2026-11-09; decided, see D186). A supervisor is the served program's kernel. Decided: (a) control without being the parent, for dynamic attachment: the kernel hands the supervisor a process descriptor for every process attached to its queue, however it was attached, so pdkill/pdwait give kill, stop/continue and exit notice with no credential check, limited to its own attached processes and by the descriptor's rights; (b) replies can raise a signal synchronously on the requesting thread with the errno, as the kernel does (ux-2); (c) when the supervisor dies, the programs it serves die too (this replaces failing closed with EIO for attached processes); (d) deep audit: every supervisor action and every consequence for a served process is audited and visible to OpenES. Scheduled: (b) in ux-2; (a), (c) and (d) in the "supervisor control" series (sc), after ux-2 and before stage 4. Attached processes gain no control over their supervisor.
21. **The swap** (D303; design note accepted in review on 2026-11-10; files and directories implemented; (e) is decided by D305; (a) is answered by D401, moved and not shared: the kernel closes the supervisor's descriptor at the take, which supersedes D306's close duty; (d) is answered by the transparency design's documented refusals: the real object's device, inode and file id show, and its path shows only outside a served root, D396). The first version swaps files and directories only: devices and FIFOs are not swapped, a restricted lookup from a real start is refused, and exec of a path outside directories the attached programs cannot change is refused until exec by descriptor follows. The questions the design answers, to be replaced by the implemented behaviour as it lands: (a) whether the supervisor's open file description is moved to the program or shared with it (offset, status flags and `flock` ownership follow the description); (b) how the kernel narrows or refuses a supplied descriptor whose access mode or flags differ from what the program asked for; (c) what a system call that takes a path and returns no descriptor (stat, unlink, rename, exec, chdir) does under this model: today's path rewrite, or an anchor descriptor the kernel operates at; (d) what the program can observe that differs from having opened the path it named (the real object's device, inode and path; relative lookups and `..` from a swapped directory), each either accepted as the supervisor's choice or listed as a reason to use a proxy; (e) rules for passing a swapped descriptor onward; (f) how the proxy installation path of today is folded into the swap without a period of two paths; (g) for each descriptor type, whether the polymorphic proxy suffices or the type needs a virtual form of its own.
22. **An attached program can act on unattached processes of its own user** (found 2026-11-10 in the swap design review, from source; not a swap defect). `p_candebug` has no attachment test and the `mac_dq` policy of section 5 is not in the tree, so an attached program can `ptrace` an unattached process of the same uid and take descriptors from it (`pddupfd`, `pidfd_getfd`, Linux `/proc/<pid>/fd`). Set-id helpers are already closed by I5. D307 decides that the kernel closes this. A design passed independent review on 2026-11-10 (three revisions); nothing of it is implemented or run. Until it lands, a confinement holds only when the attached programs run under a uid that owns no unattached process, and a supervisor marks itself untraceable. D317 to D332 record the owner's answers on the design's further refusals (numbers D308 to D316 are used by the design note for its mechanism and are entered here when implemented; among them, attach and fork exclude each other, so a target in the middle of a fork is refused with `EBUSY`). Not closable by the kernel and to be stated in the manual: what the target held at attach, and content handed over by an outside process through a channel the supervisor allowed.
