# Descriptor Operations

*The layer beneath DescriptorQueue: every operation on a file descriptor is
answered by the descriptor itself.*

## What it is

A file descriptor names a `struct file`, and a `struct file` carries a
table of operations, `struct fileops`. For most of the kernel's history a
number of system calls did not use that table: they looked at the
descriptor's type (`f_type == DTYPE_VNODE`), took the vnode out of it
(`f_vnode`) and operated on the vnode directly. `fpathconf(2)`,
`fstatfs(2)`, `fsync(2)`, `futimens(2)`, `fchflags(2)`,
`posix_fadvise(2)`, `getdirentries(2)`, `copy_file_range(2)`, the ACL and
extended-attribute `_fd` calls, `fcntl(2)`'s read-ahead and union-stack
commands and every advisory lock did this; so did `execve(2)` for the image
it ran, `msync(2)` for the pages it wrote back, and the observers that tell
`procstat(1)` what a mapping is.

The descriptor-operations layer closes that gap. Its rule is one sentence:

> A system call that takes a file descriptor dispatches through the
> descriptor's `struct fileops` and nothing else. It never tests `f_type`,
> never follows `f_vnode`, and never names a table except to ask what the
> table declares about itself.

With the rule in force a descriptor that is not a vnode can be *complete*:
it answers every operation a process can make on it, and nothing in the
kernel can tell it apart from the real thing by reaching around it. That is
what DescriptorQueue (the next chapter) needs: a controller in userland
hands a program a descriptor the controller serves, and the program — and
every observer — sees a file, a socket or an executable.

The layer is the kernel's; it is not tied to the queue. FIFOs, pseudo-
terminal masters, devices, shared memory, kqueues and `O_PATH` descriptors
all answer through it today, exactly as they did before, and the ledger
(below) records every place the kernel still reaches past a table and why.

"Exactly as they did before" is the stronger half of the rule. A program
that no controller serves must get the errno upstream FreeBSD gives it, in
the order upstream gives it, from every one of these calls. So where a
system call refused a descriptor before doing anything else — it has no
vnode, it is `O_PATH`, it is the wrong type — the call still makes that
refusal first, with upstream's predicate, and a served file (`DTYPE_DQ`) is
the one type let past it to its table. `getvnode_fp(fp, path)` is
`getvnode()` and `getvnode_path()` for a file the caller already holds:
`EINVAL` without a vnode, then `EBADF` for `O_PATH` unless `path` accepts
it; a served file is exempt from the first test. The regression matrices
in `tests/sys/dq_regress/fdops` pin the cells a test program can reach to
upstream's source, each with its citation; the header of each matrix lists
what it cannot reach and why.

## Vocabulary

| Term | Meaning |
|---|---|
| **member** | a `fo_*` slot of `struct fileops`. The inline dispatcher of the same name, `fo_pathconf()` and so on, is the only caller. |
| **default** | `invfo_*`: what a `NULL` member answers — the errno the operation has always given a descriptor of no particular type (`EINVAL` for most, `EOPNOTSUPP` for `pathconf`, `ENODEV` for `fadvise`, `EBADF` for `fcntl` and the record locks). |
| **vnode body** | `vn_*(fp)`: the operation on `fp->f_vnode`, moved out of the system call without change. Installed by `vnops`, the per-open vnode tables, both devfs tables and the `O_PATH` table. |
| **sometimes-vnode table** | a table whose descriptors carry a vnode on some creation paths only. A FIFO carries one, an anonymous pipe does not (`pipeops`); a master opened through `/dev/ptmx` does, one from `posix_openpt(2)` does not (`ptsdev_ops`); a linuxkpi file opened through devfs does, one made by `fd_install()` does not (`linuxfileops`). Such a table installs `vn_*_opt`, which answers through the vnode when it is there and with the default otherwise. It keeps a function of its own only where it has its own answer: `pipe_pathconf` says `PIPE_BUF`, `pipe_advlock` says `EOPNOTSUPP` to `flock(2)` on a pipe. |
| **capability flag** | a `DFLAG_*` bit in the table's `fo_flags`: the table's declaration about itself. `DFLAG_PRIVWRITE`: private mappings are copy-on-write, so `mmap(2)` grants `PROT_WRITE` on a private mapping without the `CAP_MMAP_W` right. `DFLAG_FLOCK`, `DFLAG_RECLOCK`: the type takes `flock(2)` locks, record locks. |
| **open-mode flag** | `fp->f_flag & O_PATH`: the descriptor was opened as a path. Read-ahead tests this flag of the descriptor. The refusals `getvnode()` made (`fsync`, `fchflags`, `futimens`, ACL changes, `getdirentries`) go through `getvnode_fp()`, which answers `EINVAL` for a descriptor without a vnode first and then `EBADF` for the `O_PATH` table (the flag, for a served file). |
| **image source** | `imgp->is_ops`: how `execve(2)` reaches the image it activates — check, first page, reads, mappings, text references, path, MAC phases, authority, install, close — through the `IS_*` wrappers of `image_source(9)`. The vnode backend is `sys/kern/exec_image_vnode.c`. |
| **pager seam** | `pgo_sync` and `pgo_kinfo`: how `msync(2)` and the mapping observers (`procstat`, `kinfo_getvmmap(3)`, linprocfs, `vm.objects`) reach a mapping's object. |
| **boundary check** | `mac_file_check_*`: a MAC entry point on the descriptor, whatever its type, beside the vnode entry points (`docs/macf-new-hooks.md` §3). |
| **ledger** | `docs/descriptor-completeness-ledger.md`: generated by a recorded `git grep`, every hit classified by hand, regenerated at the end of every stage. The count of record. |

## The idioms

One idiom per situation, applied everywhere:

- **The default answers.** No system call probes `fo_X == NULL` to decide
  what the default would decide by being called. The two places that must
  know before dispatch — the record-lock commands and `flock(2)`, which set
  `P_ADVLOCK`, `FHASLOCK` or `FHASOFDLOCK` ahead of the request — consult
  the capability flags instead, so the refusal comes before any argument is
  looked at and leaves no side effect, as the type tests did. An anonymous
  pipe shares the FIFO table, so `flock(2)` refuses it by type beside the
  flag; an `F_OFD` request is checked against the filesystem's
  `VFCF_OFDLOCKS` (`fcntl_ofd_check`) before anything else about it is
  looked at, a served file excepted. `FHASLOCK` stays set whatever the
  table then answers to an `flock(2)` request, as upstream leaves it. The
  close paths skip a table whose `fo_advlock` is `NULL` because there is
  nothing to unlock.
- **Bridges speak their own vocabulary.** fdescfs (`/dev/fd/N`) and the
  Linux compatibility layer make upstream's type test first and give its
  errno (`ENOTTY` from Linux `FS_IOC_SETFLAGS` on anything that is not a
  vnode file, `EOPNOTSUPP` from Linux `fileattr` on a descriptor without a
  vnode, `ESPIPE`, `ENODEV` or `EINVAL` from `fadvise64`, `fallocate`,
  `readahead` and `sync_file_range` by vnode type); a served file passes
  the test and reports its type through `fo_stat`. The bridge maps the
  *test*, never a returned errno: a returned `EINVAL` may be the
  filesystem's own.
- **`fo_setattr` is the whole `vattr`.** Size, mode and owner have direct
  operations of their own, and every `fo_setattr` body applies them through
  those first (`file_setattr_direct`: `fo_truncate`, `fo_chmod`, `fo_chown`,
  in that order), so the table's own answers stand: the `badfo_*` refusals
  of an `O_PATH` descriptor, a pty master's `EINVAL`, the vnode bodies' MAC
  checks and audit records. The vnode body then sets times and flags
  through `VOP_SETATTR`; the default returns `EINVAL` for them. A served
  file takes `fchflags(2)`, the Linux flags and a `/dev/fd/N` change through
  `fo_setattr` in one call. For every other file those three keep
  upstream's bodies: `setfflags()` on the vnode, and for fdescfs one
  `VOP_SETATTR` of the whole `vattr` after every check has passed
  (`vn_setattr_checked`), so a `/dev/fd/N` change is made in full or not at
  all; a descriptor without a vnode keeps the answer `getvnode()` gave
  fdescfs (`chflags` refused with `EOPNOTSUPP`, every other change silently
  dropped).
- **No vnode comes before `O_PATH`.** `getvnode()` returned `EINVAL` for a
  descriptor without a vnode before it looked for `O_PATH`, and
  `getvnode_fp()` keeps that order. An anonymous pipe reopened with `O_PATH`
  through Linux `/proc/PID/fd/N` (which carries `pipeops`, not
  `path_fileops`, and no vnode) therefore gets the pipe's `EINVAL` from
  `fsync`, `fchflags`, `futimens`, the ACL changes, `getdirentries` and the
  Linux xattr bridge, as upstream gives it; the Linux fileattr bridge maps
  the same refusal to its own `EOPNOTSUPP`. A served file opened
  `O_PATH` carries its own table (`dq_path_fileops`), which answers member
  by member as `path_fileops` does. Upstream's `path_fileops` identity
  tests predate the layer; the four a served file can reach (`F_SETFL`, the
  `FEXEC` check in `fget`, `aio`, Linux `mmap`) use `FILE_IS_OPATH()`, which
  is the identity test for every other descriptor and the open flag for a
  served one, so a served `O_PATH` file is refused where an `O_PATH` vnode
  is. `getvnode()` itself and Linux `fchroot` keep the bare identity test:
  a served file never gets that far, having no vnode.
- **MAC checks precede dispatch.** `mac_file_check_*` runs before the table
  answers: a descriptor a policy denies gets the policy's errno even where
  the table would have refused it, as `read` and `write` have always done.
  Where upstream made a refusal ahead of any check (`copy_file_range` on a
  descriptor without a vnode, say) the refusal still comes first. The
  attribute changes are the exception to "every type": a descriptor that is
  not served gets exactly upstream's checks in upstream's order (the
  vnode's `setmode`/`setowner` check ahead of `fo_chmod`/`fo_chown`, so the
  policy's errno precedes the `O_PATH` table's `EBADF` and a pty master's
  `EINVAL`), and only a served file, which has no vnode, gets
  `mac_file_check_setattr` — on every call that sets an attribute through
  the descriptor.
- **Sometimes-vnode is `vn_*_opt`.** Nothing else in the kernel inspects
  `f_vnode` to decide how to answer.
- **Observers take the vnode under the object lock.** `vm_object_kinfo_hold`
  takes a mapping's vnode through the pager's `pgo_getvp` — vnode and
  tmpfs objects alike — and references it before the object lock is
  dropped; a pager without a vnode but with `pgo_kinfo` (the device
  pagers) is held by an object reference instead.

## Tracing it

The layer registers probes from the moment it lands:

```
fd:::invfo         (const char *member, struct file *fp, int errno)
fd:::refused       (const char *syscall, struct file *fp, int why, int errno)
proc:::exec-image-open   (struct image_params *imgp, int form)
proc:::exec-image-close  (struct image_params *imgp, int released)
```

`fd:::invfo` fires whenever a default answers for a descriptor whose table
has no member — the first thing to look at when a program gets `EINVAL`
from an operation on an unusual descriptor. `fd:::refused` fires when a
system call refuses a descriptor before looking at its arguments, by
capability flag (`why` is the `DFLAG_*` bit the table lacks) or because the
descriptor has no vnode or is `O_PATH` (`why` is 0). The exec probes show which entry form
built an image source (`IS_FORM_PATH`, `IS_FORM_INTERP_VNODE`, `IS_FORM_FD`,
`IS_FORM_INTERP_LOADER`) and whether its close dropped the reference. The
existing `fd:::advlock-start`/`advlock-done`, `vfs:::chflags` and every
`mac_framework:::` probe for the `mac_file_check_*` hooks complete the
picture.

```sh
# Who is getting the default answer, and for what?
dtrace -n 'fd:::invfo { @[execname, stringof(arg0), arg2] = count(); }'
# Which system calls refuse descriptors, and why?
dtrace -n 'fd:::refused { printf("%s %s why=%x errno=%d", execname, stringof(arg0), arg2, arg3); }'
```

## Adding a member

1. Add the typedef, the member (after the last one — the spares are used
   up; `struct fileops` is KBI, every table in the tree is rebuilt with
   the kernel) and the inline dispatcher to `sys/sys/file.h`; the
   dispatcher calls `invfo_X` for a `NULL` member.
2. Write `invfo_X` in `kern/kern_descrip.c` returning the errno the
   operation has always given a descriptor of no particular type, with the
   `fd:::invfo` probe.
3. Move the vnode body out of the system call into `vn_X` in
   `kern/vfs_vnops.c`, unchanged; install it in `vnops` (through a
   `vn_openfile_*` wrapper unless the body enters the file context itself),
   `VN_OPENFILEOPS`, both devfs tables and, if `getvnode_path()` accepted
   `O_PATH` for the operation, `path_fileops`. Write `vn_X_opt` and install
   it in the three sometimes-vnode tables.
4. Convert the system call: `fget` with the rights it always required, the
   refusals `getvnode()` made through `getvnode_fp()` if it used one (and
   any type test it made, with `DTYPE_DQ` let through), then `fo_X`. Audit
   arguments, capability rights and generic argument validation stay in the
   system call; everything that touched the vnode moves.
5. Add `tests/sys/file/X_test.c`: the fd form against the path form on a
   regular file, a directory, a devfs node, a FIFO, both kinds of pty
   master, a pipe, a socket, a kqueue, shm, `O_PATH` and a closed
   descriptor — error *order* included.
6. Document the member in `fileops(9)`; regenerate the ledger.

## Reading the ledger

The ledger is generated by the command recorded in its *Generation*
section and lists every hit in one of seven tables: **A fileop** (should be
a member), **B resolution** (a lookup's start vnode — stage 1c), **C exec**
(the image — stage 3's backend), **D vm**, **E vfs-internal** (filesystems
talking to their own vnodes, which is their business), **F observer**
(reports to users that will show the presented identity), **G driver**.
Each row says what the code does at that line and what becomes of it.
Rows marked ⁽ᵀ⁾ are `f_type` tests; ⁽ᴺ⁾ marks code that already tolerates a
missing vnode. A separate audit lists every `struct fileops` in the tree
and what it installs for each member. The stage is not complete until the
regenerated ledger is committed.

## Where things live

| | |
|---|---|
| contract and members | `fileops(9)`, `sys/sys/file.h` |
| defaults | `sys/kern/kern_descrip.c` (`invfo_*`, `file_setattr_direct`, `path_advlock`, the probes) |
| vnode bodies | `sys/kern/vfs_vnops.c` (`vn_*`, `vn_*_opt`), `sys/kern/vfs_syscalls.c` (`vn_fadvise`, `vn_readdir`, `vn_copy_range`), `vfs_acl.c`, `vfs_extattr.c` |
| image source | `image_source(9)`, `sys/sys/imgact.h`, `sys/kern/exec_image_vnode.c` |
| pager seams | `sys/vm/vm_pager.h`, `vnode_pager.c`, `device_pager.c`, `vm_object.c` |
| boundary checks | `docs/macf-new-hooks.md` §3, `sys/security/mac/mac_system.c` |
| tests | `tests/sys/file/`, `tests/sys/vm/msync_pager_test.c`, `sys/kern/execve` |
| design and decisions | the DescriptorQueue chapter, sections 4.1, 6 and decisions D63–D83 |
| ledger | `docs/descriptor-completeness-ledger.md` |
