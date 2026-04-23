# 5BSD MACF Hook Additions — Design Reference

This document maps XNU MAC framework hooks that FreeBSD lacks to proposed
5BSD equivalents. Each entry includes the XNU hook name, the proposed 5BSD
name, the exact kernel call site, lock context, whether the hook can sleep,
the function signature, and implementation notes.

## How to Read This Document

Each hook entry follows this template:

- **XNU name** — the hook as it exists in Apple's kernel
- **5BSD name** — what we will call it
- **Category** — check (can deny), notify (void, post-event), or grant
- **Call site** — exact file, function, and line range where the call goes
- **Lock context** — what locks are held when the hook fires
- **Can sleep** — whether the hook implementation may block
- **Signature** — the proposed typedef
- **Composition macro** — which MAC_POLICY_* macro to use
- **Fast-path flag** — whether to add an FPFLAG for performance
- **Notes** — restrictions, edge cases, security rationale

## What Each Hook Requires in the Kernel

For every hook added, five pieces are needed:

| Layer | File | What to add |
|-------|------|-------------|
| Typedef + ops field | `sys/security/mac/mac_policy.h` | `typedef` and field in `struct mac_policy_ops` |
| Public API | `sys/security/mac/mac_framework.h` | Function declaration (+ inline FPFLAG wrapper if needed) |
| Framework glue | `sys/security/mac/mac_*.c` | DTrace probe define + implementation calling composition macro |
| Call site | The kernel source file | `#ifdef MAC` guard invoking the function |
| (Optional) Fast-path | `sys/security/mac/mac_framework.c` | Entry in `mac_policy_fastpath_array` |

No default implementations or test values are needed. If no loaded policy
sets the hook, `MAC_POLICY_CHECK*` iterates zero non-NULL entries and
returns 0 (allow). `MAC_POLICY_PERFORM*` does nothing. The FPFLAG
mechanism (when used) short-circuits entirely — the inline wrapper returns
0 without entering the framework function at all.

---

## 1. Process Lifecycle Hooks

### 1.1 mac_proc_check_fork

- **XNU name:** `mac_proc_check_fork`
- **5BSD name:** `mac_proc_check_fork`
- **Category:** check
- **Call site:** `sys/kern/kern_fork.c`, `fork1()`, between validation and
  `uma_zalloc(proc_zone)` (~line 1056-1061)
- **Lock context:** `pg->pg_killsx` SLOCK may be held (shared). No
  PROC_LOCK on the caller.
- **Can sleep:** YES — the surrounding code does M_WAITOK allocations
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** YES — `fork()` is frequent; avoid framework entry
  when no policy cares

```c
typedef int (*mpo_proc_check_fork_t)(struct ucred *cred, int flags);

int mac_proc_check_fork(struct ucred *cred, int flags);
```

**Signature rationale:** Pass `flags` (RFPROC, RFMEM, etc.) so policies
can distinguish `fork` from `vfork` from `rfork`. The child process does
not exist yet so there is no target `struct proc`.

**Notes:**
- Must be called BEFORE the new process is allocated — otherwise a denied
  fork leaks a partially-constructed proc.
- The `flags` argument lets policies allow `vfork` (RFMEM) but deny full
  `fork` (RFPROC) if needed.

---

### 1.2 mac_proc_check_core

- **XNU name:** `mac_proc_check_dump_core`
- **5BSD name:** `mac_proc_check_core`
- **Category:** check
- **Call site:** `sys/kern/kern_ucoredump.c`, `sigexit()`, between
  PROC_LOCK_ASSERT and `thread_single()` (~line 141-159)
- **Lock context:** `PROC_LOCK(p)` IS HELD (asserted at line 141)
- **Can sleep:** NO — PROC_LOCK is a mutex (non-sleepable)
- **Composition macro:** `MAC_POLICY_CHECK_NOSLEEP`
- **Fast-path flag:** No — core dumps are rare

```c
typedef int (*mpo_proc_check_core_t)(struct ucred *cred, struct proc *p);

int mac_proc_check_core(struct ucred *cred, struct proc *p);
```

**Notes:**
- PROC_LOCK is held. Implementations MUST NOT sleep, allocate with
  M_WAITOK, acquire sleepable locks, or perform VOP operations.
- Return EPERM to suppress the core dump. The process still dies from the
  signal — only the file write is prevented.
- Core files expose full process memory (keys, tokens, plaintext). This is
  the only enforcement point to prevent that.

---

### 1.3 mac_proc_check_thr_new

- **XNU name:** `mac_proc_check_remote_thread_create`
- **5BSD name:** `mac_proc_check_thr_new`
- **Category:** check
- **Call site:** `sys/kern/kern_thr.c`, `kern_thr_new()`, after argument
  validation, before `kern_thr_alloc()` (~line 202-244)
- **Lock context:** No locks held at this point
- **Can sleep:** YES — copyin and allocation happen nearby
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No — thread creation is not as frequent as fork

```c
typedef int (*mpo_proc_check_thr_new_t)(struct ucred *cred, struct proc *p);

int mac_proc_check_thr_new(struct ucred *cred, struct proc *p);
```

**Notes:**
- FreeBSD's `thr_new()` creates threads within the calling process (self).
  For the self case, `cred` and `p` belong to the same process and most
  policies will allow it.
- The security value is in combination with `thr_create()` or any future
  remote-thread-creation interface. If 5BSD adds cross-process thread
  creation, this hook gates it.
- Unlike XNU's Mach-layer `task_for_pid`, FreeBSD has no direct remote
  thread injection syscall today, but `ptrace` + register manipulation
  achieves the same effect (already gated by `proc_check_debug`).

---

### 1.4 mac_proc_check_suspend

- **XNU name:** `mac_proc_check_suspend_resume`
- **5BSD name:** `mac_proc_check_suspend`
- **Category:** check
- **Call site:** `sys/kern/kern_sig.c`, `tdsendsignal()`, in the
  SIGSTOP/SIGTSTP handling path (~line 2478-2485, before `P_STOPPED_SIG`
  flag is set)
- **Lock context:** `PROC_LOCK(p)` IS HELD
- **Can sleep:** NO — inside signal delivery with PROC_LOCK
- **Composition macro:** `MAC_POLICY_CHECK_NOSLEEP`
- **Fast-path flag:** No — suspension is rare

```c
typedef int (*mpo_proc_check_suspend_t)(struct ucred *cred, struct proc *p,
    int sig);

int mac_proc_check_suspend(struct ucred *cred, struct proc *p, int sig);
```

**Notes:**
- PROC_LOCK is held. Implementations MUST NOT sleep.
- This is separate from `proc_check_signal` because a policy might allow
  SIGSTOP delivery (for the signal audit trail) but deny the actual
  process suspension.
- `sig` is included so the policy can distinguish SIGSTOP (forced) from
  SIGTSTP (terminal-initiated).
- Return EPERM to silently drop the stop. The signal is consumed but the
  process continues running.

---

### 1.5 mac_proc_notify_exec_complete

- **XNU name:** `mac_proc_notify_exec_complete`
- **5BSD name:** `mac_proc_notify_exec_complete`
- **Category:** notify (void return)
- **Call site:** `sys/kern/kern_exec.c`, `do_execve()`, after
  `sv_setregs()` at line 960 and the SDT exec_success probe at line 964.
  PROC_LOCK was released at line 925. The function returns at line 1059.
  Best insertion point: between lines 964-1059.
- **Lock context:** No locks held — PROC_UNLOCK called at line 925
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)
- **Fast-path flag:** No — exec is already expensive

```c
typedef void (*mpo_proc_notify_exec_complete_t)(struct proc *p);

void mac_proc_notify_exec_complete(struct proc *p);
```

**Notes:**
- Fires AFTER exec succeeds and the new image is fully set up.
- Unlike `mpo_vnode_execve_transition` (which fires during exec with locks
  held and cannot sleep), this fires after all locks are released.
- Policies can safely allocate memory, perform lookups, update hash
  tables, or log.
- The process is fully transitioned: new credential, new VM space, new
  signal disposition. The nonce has already rotated (via
  `execve_transition`).

---

### 1.6 mac_proc_notify_exit

- **XNU name:** `mac_proc_notify_exit`
- **5BSD name:** `mac_proc_notify_exit`
- **Category:** notify (void return)
- **Call site:** `sys/kern/kern_exit.c`, `exit1()`, AFTER
  `PROC_UNLOCK(p)` at line 326. PROC_LOCK is held from line 259 through
  the `thread_single(SINGLE_EXIT)` call (line 286), the
  `KASSERT(p->p_numthreads == 1)` (line 300), and the `msleep` loop
  (line 323-324). It is not released until line 326.
- **Lock context:** PROC_LOCK is NOT held — the hook goes after line 326
  (`PROC_UNLOCK(p)`), between it and `callout_drain` at line 328.
- **Can sleep:** YES — single-threaded, no locks held, P_WEXIT set
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)
- **Fast-path flag:** No — exit is already expensive

```c
typedef void (*mpo_proc_notify_exit_t)(struct proc *p);

void mac_proc_notify_exit(struct proc *p);
```

**Notes:**
- The hook MUST go AFTER `PROC_UNLOCK(p)` at line 326, not merely after
  `thread_single()`. PROC_LOCK remains held from line 259 through
  thread_single (line 286), the numthreads KASSERT (line 300), P_WEXIT
  flag setting (line 317), and the p_lock msleep loop (line 323-324).
  Only at line 326 is PROC_LOCK released.
- After line 326, the process is single-threaded (KASSERT at line 300),
  P_WEXIT is set (line 317), and no locks are held. Policies can safely
  allocate memory, take sleepable locks, update hash tables, and perform
  full cleanup.
- Do NOT place this before line 326 — PROC_LOCK is held and the hook
  cannot sleep.
- CMI capprotect cleanup is NOT tied to this hook. Capprotect shield
  removal is driven by token fd close (`cmi_capprotect.c:374`), not
  process exit. This hook is for policies that maintain per-process state
  outside the fd lifecycle (e.g., audit logs, resource trackers).

---

## 2. Memory Protection Hooks

### 2.1 mac_proc_check_mmap_anon

- **XNU name:** `mac_proc_check_map_anon`
- **5BSD name:** `mac_proc_check_mmap_anon`
- **Category:** check
- **Call site:** `sys/vm/vm_mmap.c`, `kern_mmap()`, in the MAP_ANON path
  (~line 375-382, before `vm_mmap_object()`)
- **Lock context:** No locks held
- **Can sleep:** YES — surrounding code does M_WAITOK allocations
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** YES — `mmap()` is very frequent

```c
typedef int (*mpo_proc_check_mmap_anon_t)(struct ucred *cred,
    vm_offset_t addr, vm_size_t len, int prot, int flags);

int mac_proc_check_mmap_anon(struct ucred *cred, vm_offset_t addr,
    vm_size_t len, int prot, int flags);
```

**Notes:**
- This is the W^X enforcement hook for anonymous memory.
- FreeBSD already has `mpo_vnode_check_mmap` for file-backed mappings, but
  `mmap(NULL, sz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANON, -1, 0)` has
  NO MAC check at all.
- A policy enforcing W^X would return EACCES when
  `(prot & (PROT_WRITE|PROT_EXEC)) == (PROT_WRITE|PROT_EXEC)`.
- JIT engines (JavaScript VMs, etc.) legitimately need RWX anonymous pages.
  The policy, not the kernel, decides whether to allow it.
- `addr` and `len` are provided so policies can allow RWX in specific
  address ranges (e.g., a designated JIT region).

---

### 2.2 mac_proc_check_mprotect

- **XNU name:** `mac_proc_check_mprotect`
- **5BSD name:** `mac_proc_check_mprotect`
- **Category:** check
- **Call site:** `sys/vm/vm_mmap.c`, `kern_mprotect()`, before
  `vm_map_protect()` (~line 681-702)
- **Lock context:** No locks held (vm_map_protect handles its own locking)
- **Can sleep:** YES — but the hook should be lightweight since
  `mprotect()` is used in hot paths (dynamic linker, JIT)
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** YES — `mprotect()` is frequent (ld.so startup calls
  it per shared library)

```c
typedef int (*mpo_proc_check_mprotect_t)(struct ucred *cred,
    vm_offset_t addr, vm_size_t len, int prot);

int mac_proc_check_mprotect(struct ucred *cred, vm_offset_t addr,
    vm_size_t len, int prot);
```

**Notes:**
- Complements `mac_proc_check_mmap_anon`. Without this, an attacker does
  `mmap(PROT_READ|PROT_WRITE, MAP_ANON)` then `mprotect(PROT_EXEC)` to
  bypass the mmap check.
- FreeBSD has `mpo_vnode_check_mprotect` but it only fires for file-backed
  pages. Anonymous pages have no mprotect gate.
- Together, `mmap_anon` + `mprotect` close the W^X enforcement gap
  completely.
- The existing `mpo_vnode_check_mprotect` remains for file-backed pages.
  This new hook covers everything else.

---

## 3. File Descriptor Layer Hooks

FreeBSD's MAC framework operates at the vnode layer. There are zero hooks
at the file descriptor layer. XNU has a complete `file_check_*` family.
This is the single biggest structural gap in FreeBSD's MACF.

### 3.1 mac_file_check_dup

- **XNU name:** `mac_file_check_dup`
- **5BSD name:** `mac_file_check_dup`
- **Category:** check
- **Call site:** `sys/kern/kern_descrip.c`, `kern_dup()`, after
  FILEDESC_XLOCK but before `fdalloc()` (~line 1076-1099)
- **Lock context:** `FILEDESC_XLOCK(fdp)` IS HELD (non-sleepable sx lock
  in exclusive mode)
- **Can sleep:** NO — FILEDESC_XLOCK is held
- **Composition macro:** `MAC_POLICY_CHECK_NOSLEEP`
- **Fast-path flag:** No — dup is not extremely frequent

```c
typedef int (*mpo_file_check_dup_t)(struct ucred *cred, struct file *fp,
    int fd);

int mac_file_check_dup(struct ucred *cred, struct file *fp, int fd);
```

**Notes:**
- FILEDESC_XLOCK is held. Implementations MUST NOT sleep.
- `fd` is the source descriptor number. `fp` is the file struct.
- An alternative placement is BEFORE FILEDESC_XLOCK (~line 1070) where the
  hook could sleep, but then there's a TOCTOU window between the check and
  the actual dup.
- Recommended: keep inside XLOCK for atomicity, accept the no-sleep
  restriction. Dup checks should be trivial lookups anyway.

---

### 3.2 mac_file_check_inherit

- **XNU name:** `mac_file_check_inherit`
- **5BSD name:** `mac_file_check_inherit`
- **Category:** check
- **Call site:** `sys/kern/kern_descrip.c`, `fdcloseexec()`, inside the
  `FILEDESC_FOREACH_FDE()` loop (~line 2901-2907). Currently only checks
  `UF_EXCLOSE`. The MAC hook would fire for fds that are NOT marked
  close-on-exec.
- **Lock context:** `FILEDESC_XLOCK(fdp)` is acquired per-fd at line 2905
- **Can sleep:** NO — FILEDESC_XLOCK held during check
- **Composition macro:** `MAC_POLICY_CHECK_NOSLEEP`
- **Fast-path flag:** No — exec is already expensive

```c
typedef int (*mpo_file_check_inherit_t)(struct ucred *cred,
    struct ucred *newcred, struct file *fp, int fd);

int mac_file_check_inherit(struct ucred *cred, struct ucred *newcred,
    struct file *fp, int fd);
```

**Notes:**
- Called once per non-CLOEXEC fd during exec.
- FILEDESC_XLOCK is held. MUST NOT sleep.
- Return EPERM to force-close that specific fd before the new image runs.
  The fd is closed as if CLOEXEC were set.
- **Credential caveat:** `fdcloseexec()` runs at `kern_exec.c:766`,
  BEFORE the new credential is installed at `kern_exec.c:879`. The
  current `td->td_ucred` is still the OLD credential. To let the policy
  decide based on the new image's identity, the call site must explicitly
  pass `imgp->newcred` as a separate `newcred` parameter. The signature
  includes both `cred` (old, current) and `newcred` (post-exec) for this
  reason.
- If the new image is a setuid binary and the old process had a raw socket
  fd, this hook can prevent the raw socket from leaking into the
  privileged context — but only if `newcred` is passed explicitly.

---

### 3.3 mac_file_check_receive

- **XNU name:** `mac_file_check_receive`
- **5BSD name:** `mac_file_check_receive`
- **Category:** check
- **Call site:** `sys/kern/uipc_usrreq.c`, `unp_externalize()`, in the
  SCM_RIGHTS processing loop (~line 3502-3513, before FILEDESC_XLOCK is
  acquired to install the fds)
- **Lock context:** No locks held at the ideal hook point
  (`UNP_LINK_UNLOCK_ASSERT()` at line 3488 confirms UNP link lock is NOT
  held)
- **Can sleep:** YES — M_WAITOK allocations happen at line 3522
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No — fd passing is not extremely frequent but is
  security-critical

```c
typedef int (*mpo_file_check_receive_t)(struct ucred *cred,
    struct file *fp);

int mac_file_check_receive(struct ucred *cred, struct file *fp);
```

**Notes:**
- **This is the highest-priority fd-layer hook.** Fd passing via
  SCM_RIGHTS is the primary sandbox escape on Unix systems. Process A
  cannot open `/etc/shadow` but process B sends it an open fd to that
  file. Today there is zero MAC enforcement on the receive side.
- `cred` is the receiving process's credential.
- `fp` is the file being received.
- The hook fires per-fd in the SCM_RIGHTS message. If the message passes
  5 fds, the hook fires 5 times.
- **Call-site refactoring required:** The current `unp_externalize()` flow
  bundles all SCM_RIGHTS fd conversion into a single pass and returns one
  error code (lines 3499-3575). It does not support per-fd rejection with
  the rest accepted. To implement partial accept (reject one fd, keep the
  others), the call site must be refactored to: (a) check each fd before
  installation, (b) compact/rewrite the outgoing control message to
  exclude rejected fds, and (c) adjust the cmsg length. This is NOT a
  drop-in hook — it requires modifying `unp_externalize()` itself.
- **Alternative (simpler):** Reject the entire SCM_RIGHTS message if ANY
  fd fails the check. This is a simpler implementation (single check
  before the installation loop) but coarser — one bad fd blocks all fds
  in the message.
- Because no locks are held, the implementation can do full policy
  evaluation — vnode lookups, label checks, hash table queries, etc.

---

### 3.4 mac_file_check_fcntl

- **XNU name:** `mac_file_check_fcntl`
- **5BSD name:** `mac_file_check_fcntl`
- **Category:** check
- **Call site:** `sys/kern/kern_descrip.c`, `kern_fcntl()`, before the
  switch statement (~line 584-591)
- **Lock context:** No locks held at entry
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No

```c
typedef int (*mpo_file_check_fcntl_t)(struct ucred *cred, struct file *fp,
    int fd, int cmd, intptr_t arg);

int mac_file_check_fcntl(struct ucred *cred, struct file *fp, int fd,
    int cmd, intptr_t arg);
```

**Notes:**
- `cmd` lets the policy distinguish benign commands (F_GETFL) from
  dangerous ones (F_SETOWN, F_SETFL clearing O_APPEND, F_SETLK).
- `arg` is the command-specific argument (cast to intptr_t).
- No locks held — implementations can sleep.

---

### 3.5 mac_file_check_ioctl

- **XNU name:** `mac_file_check_ioctl`
- **5BSD name:** `mac_file_check_ioctl`
- **Category:** check
- **Call site:** `sys/kern/sys_generic.c`, `kern_ioctl()`, before
  lock acquisition for specific commands (~line 737-755)
- **Lock context:** No locks held at the hook point
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** YES — ioctl is very frequent (terminal I/O, socket
  ops, device control)

```c
typedef int (*mpo_file_check_ioctl_t)(struct ucred *cred, struct file *fp,
    int fd, u_long cmd);

int mac_file_check_ioctl(struct ucred *cred, struct file *fp, int fd,
    u_long cmd);
```

**Notes:**
- FreeBSD has `mpo_vnode_check_ioctl` for vnodes, but ioctl also works on
  sockets, pipes, devices, and other fd types. This covers ALL fd types.
- `cmd` is the ioctl command number. Policies can whitelist/blacklist
  specific ioctls per file type.
- Because no locks are held, this is a sleepable check.

---

### 3.6 mac_file_check_lock

- **XNU name:** `mac_file_check_lock`
- **5BSD name:** `mac_file_check_lock`
- **Category:** check
- **Call site:** `sys/kern/kern_descrip.c`, in the F_SETLK/F_SETLKW
  handling of `kern_fcntl()` (~line 729-737), before `VOP_ADVLOCK()`
- **Lock context:** No locks held (file has a reference but no lock)
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No — file locking is not extremely frequent

```c
typedef int (*mpo_file_check_lock_t)(struct ucred *cred, struct file *fp,
    int fd, int op, struct flock *fl);

int mac_file_check_lock(struct ucred *cred, struct file *fp, int fd,
    int op, struct flock *fl);
```

**Notes:**
- `op` is F_SETLK, F_SETLKW, F_UNLCK, F_FLOCK, etc.
- `fl` contains lock type (F_RDLCK, F_WRLCK), offset, and length.
- Lower priority than other fd hooks. Primary use case: preventing a
  malicious process from locking shared database files.

---

### 3.7 mac_file_check_mmap

- **XNU name:** `mac_file_check_mmap`
- **5BSD name:** `mac_file_check_mmap`
- **Category:** check
- **Call site:** `sys/vm/vm_mmap.c`, `kern_mmap()`, for fd-backed mappings,
  after `fget_mmap()` at line 399, before `fo_mmap()` (~line 383-419)
- **Lock context:** No locks held
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** YES — mmap is frequent

```c
typedef int (*mpo_file_check_mmap_t)(struct ucred *cred, struct file *fp,
    int fd, int prot, int flags, vm_offset_t addr, vm_size_t len);

int mac_file_check_mmap(struct ucred *cred, struct file *fp, int fd,
    int prot, int flags, vm_offset_t addr, vm_size_t len);
```

**Notes:**
- Complements `mpo_vnode_check_mmap` (which operates on the vnode).
  This operates on the fd and covers non-vnode fd types (device fds,
  shared memory objects).
- If the fd refers to a vnode, BOTH hooks fire (`vnode_check_mmap` from
  the VFS layer and `file_check_mmap` from the fd layer). Policies should
  implement one or the other, not both, unless they need different
  logic per layer.

---

### 3.8 mac_file_notify_close

- **XNU name:** `mac_file_notify_close`
- **5BSD name:** `mac_file_notify_close`
- **Category:** notify (void return)
- **Call site:** `sys/kern/kern_descrip.c`, `closef()`, before VOP
  operations (~line 2987-2998)
- **Lock context:** No locks held at entry
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)
- **Fast-path flag:** No

```c
typedef void (*mpo_file_notify_close_t)(struct ucred *cred,
    struct file *fp, int fd);

void mac_file_notify_close(struct ucred *cred, struct file *fp, int fd);
```

**Notes:**
- Notification only — cannot prevent the close.
- Fires before the file's VOP_CLOSE, so the file is still valid.
- Policies tracking per-fd state (audit logs, reference maps) use this
  to clean up.

---

## 4. Vnode Notification Hooks

FreeBSD has vnode check hooks (which deny/allow operations) but no
notification hooks (which fire after success). Policies that maintain state
— audit logs, integrity databases, label caches — need to know when
operations actually succeed, not just when they are attempted.

All notification hooks are `void` return (`MAC_POLICY_PERFORM`). They
cannot deny the operation.

### 4.1 mac_vnode_notify_create

- **XNU name:** `mac_vnode_notify_create`
- **5BSD name:** `mac_vnode_notify_create`
- **Call site:** `sys/kern/vfs_vnops.c`, `vn_open_cred()`, after
  successful `VOP_CREATE()` (~line 320+, after VOP_CREATE returns 0)
- **Lock context:** Vnode exclusive lock (LK_EXCLUSIVE) held on parent
  directory. Newly created vnode is also locked.
- **Can sleep:** YES — VOP context is sleepable
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_vnode_notify_create_t)(struct ucred *cred,
    struct vnode *dvp, struct vnode *vp, struct componentname *cnp);

void mac_vnode_notify_create(struct ucred *cred, struct vnode *dvp,
    struct vnode *vp, struct componentname *cnp);
```

**Notes:**
- `dvp` is the parent directory vnode (locked).
- `vp` is the newly created vnode (locked).
- `cnp` contains the filename component.
- Both vnodes are locked exclusive — implementations can read vnode
  attributes but should avoid long-running operations.

---

### 4.2 mac_vnode_notify_open

- **XNU name:** `mac_vnode_notify_open`
- **5BSD name:** `mac_vnode_notify_open`
- **Call site:** `sys/kern/vfs_vnops.c`, `vn_open_cred()`, after
  successful VOP_OPEN (~line 495-506)
- **Lock context:** Vnode locked (exclusive or shared depending on open
  mode)
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_vnode_notify_open_t)(struct ucred *cred,
    struct vnode *vp, int fmode);

void mac_vnode_notify_open(struct ucred *cred, struct vnode *vp,
    int fmode);
```

**Notes:**
- `fmode` is the open flags (FREAD, FWRITE, etc.).
- The `check_open` hook fires BEFORE the open. This fires AFTER success.
- Audit policies need this to record what was actually opened vs what was
  attempted.

---

### 4.3 mac_vnode_notify_rename

- **XNU name:** `mac_vnode_notify_rename`
- **5BSD name:** `mac_vnode_notify_rename`
- **Call site:** `sys/kern/vfs_syscalls.c`, `kern_renameat()`, after
  successful `VOP_RENAME()` (~line 3900+)
- **Lock context:** After VOP_RENAME, source and target vnodes are
  UNLOCKED (VOP_RENAME releases locks). `mnt_renamelock` may still be held
  briefly.
- **Can sleep:** YES — post-VOP context
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_vnode_notify_rename_t)(struct ucred *cred,
    struct componentname *fromcnp, struct componentname *tocnp);

void mac_vnode_notify_rename(struct ucred *cred,
    struct componentname *fromcnp, struct componentname *tocnp);
```

**Notes:**
- VOP_RENAME consumes its vnode references and locks. The implemented
  hook passes only `fromcnp` and `tocnp`, which remain valid until the
  later `NDFREE_PNBUF()` cleanup.
- This is intentionally a rename-telemetry hook keyed by pathname
  components, not a post-rename vnode-inspection hook.

---

### 4.4 mac_vnode_notify_unlink

- **XNU name:** `mac_vnode_notify_unlink`
- **5BSD name:** `mac_vnode_notify_unlink`
- **Call site:** `sys/kern/vfs_syscalls.c`, `kern_funlinkat()`, after
  successful `VOP_REMOVE()` (~line 2092+)
- **Lock context:** Parent dir and target vnode locked during VOP_REMOVE.
  After success, typically still locked.
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_vnode_notify_unlink_t)(struct ucred *cred,
    struct vnode *dvp, struct vnode *vp, struct componentname *cnp);

void mac_vnode_notify_unlink(struct ucred *cred, struct vnode *dvp,
    struct vnode *vp, struct componentname *cnp);
```

---

### 4.5 mac_vnode_notify_link

- **XNU name:** `mac_vnode_notify_link`
- **5BSD name:** `mac_vnode_notify_link`
- **Call site:** `sys/kern/vfs_syscalls.c`, `kern_linkat()`, after
  successful `VOP_LINK()` (~line 1789+)
- **Lock context:** Both vnodes locked exclusive. Mount write in progress.
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_vnode_notify_link_t)(struct ucred *cred,
    struct vnode *dvp, struct vnode *vp, struct componentname *cnp);

void mac_vnode_notify_link(struct ucred *cred, struct vnode *dvp,
    struct vnode *vp, struct componentname *cnp);
```

**Notes:**
- Hard links create new directory entries pointing to existing inodes.
  Integrity policies tracking file identity need this.

---

### 4.6 mac_vnode_notify_truncate

- **XNU name:** `mac_vnode_notify_truncate`
- **5BSD name:** `mac_vnode_notify_truncate`
- **Call site:** `sys/kern/vfs_vnops.c`, `vn_truncate()` or
  `vn_truncate_locked()`, after successful truncation (~line 1794+)
- **Lock context:** Vnode locked. Range lock held. Mount write in progress.
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_vnode_notify_truncate_t)(struct ucred *cred,
    struct vnode *vp);

void mac_vnode_notify_truncate(struct ucred *cred, struct vnode *vp);
```

---

### 4.7 mac_vnode_notify_setmode

- **XNU name:** `mac_vnode_notify_setmode`
- **5BSD name:** `mac_vnode_notify_setmode`
- **Call site:** `sys/kern/vfs_syscalls.c`, `kern_fchmodat()`, after
  successful `setfmode()` call (~line 3062+)
- **Lock context:** Inside `setfmode()`, vnode is locked and mount write
  is in progress during VOP_SETATTR.
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_vnode_notify_setmode_t)(struct ucred *cred,
    struct vnode *vp, mode_t mode);

void mac_vnode_notify_setmode(struct ucred *cred, struct vnode *vp,
    mode_t mode);
```

---

### 4.8 mac_vnode_notify_setowner

- **XNU name:** `mac_vnode_notify_setowner`
- **5BSD name:** `mac_vnode_notify_setowner`
- **Call site:** `sys/kern/vfs_syscalls.c`, `kern_fchownat()`, after
  successful `setfown()` call (~line 3175+)
- **Lock context:** Inside `setfown()`, vnode is locked.
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_vnode_notify_setowner_t)(struct ucred *cred,
    struct vnode *vp, uid_t uid, gid_t gid);

void mac_vnode_notify_setowner(struct ucred *cred, struct vnode *vp,
    uid_t uid, gid_t gid);
```

---

### 4.9 mac_vnode_notify_setflags

- **XNU name:** `mac_vnode_notify_setflags`
- **5BSD name:** `mac_vnode_notify_setflags`
- **Call site:** `sys/kern/vfs_syscalls.c`, `kern_chflagsat()`, after
  successful `setfflags()` call (~line 2931+)
- **Lock context:** Inside `setfflags()`, vnode is locked.
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_vnode_notify_setflags_t)(struct ucred *cred,
    struct vnode *vp, u_long flags);

void mac_vnode_notify_setflags(struct ucred *cred, struct vnode *vp,
    u_long flags);
```

---

### 4.10 vnode reclaim hook

`mac_vnode_notify_reclaim` was evaluated and intentionally dropped from the
current hook set. The reclaim path runs under `ASSERT_VOP_ELOCKED` and
`ASSERT_VI_LOCKED`, which makes the hook non-sleepable and awkward for the
current policy goals. The kernel no longer wires or documents it as an
implemented hook.

---

## 5. Syscall Gating

### 5.1 mac_proc_check_syscall

- **XNU name:** `mac_proc_check_syscall_unix`
- **5BSD name:** `mac_proc_check_syscall`
- **Category:** check
- **Call site:** `sys/kern/subr_syscall.c`, `syscallenter()`, before the
  syscall handler is invoked (~line 165 for traced path, ~line 193 for
  fast path)
- **Lock context:** No kernel locks held. Thread is in syscall context.
  AUDIT context may be active (functional, not a lock).
- **Can sleep:** YES — no locks held
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** **MANDATORY** — this fires on EVERY syscall. Without
  FPFLAG, every syscall takes a framework lock even when no policy
  implements the hook.

```c
typedef int (*mpo_proc_check_syscall_t)(struct ucred *cred, int syscall_num);

int mac_proc_check_syscall(struct ucred *cred, int syscall_num);
```

**Notes:**
- Fires on every single syscall if a policy registers for it. Performance
  is critical. The FPFLAG inline wrapper MUST be used so that the check
  compiles to a single branch-on-flag when no policy cares.
- `syscall_num` is the SYS_* number from sys/syscall.h.
- This is the equivalent of Linux's seccomp-bpf but via MACF.
- A policy can maintain a per-process allowed-syscall bitmap and check it
  in O(1). Do NOT do expensive work in this hook.
- Returning EACCES causes the syscall to fail without executing.

---

## 6. Mount and Snapshot Hooks

### 6.1 mac_mount_check_snapshot_create

- **XNU name:** `mac_mount_check_snapshot_create`
- **5BSD name:** `mac_mount_check_snapshot_create`
- **Category:** check
- **Call site:** `sys/contrib/openzfs/module/zfs/zfs_ioctl.c`,
  `zfs_ioc_snapshot()` (~line 4037), before snapshot creation begins
- **Lock context:** ioctl handler context, no locks held initially. ZFS
  acquires `spa_config` internally.
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No — snapshot ops are rare

```c
typedef int (*mpo_mount_check_snapshot_create_t)(struct ucred *cred,
    const char *snapname);

int mac_mount_check_snapshot_create(struct ucred *cred,
    const char *snapname);
```

---

### 6.2 mac_mount_check_snapshot_delete

- **XNU name:** `mac_mount_check_snapshot_delete`
- **5BSD name:** `mac_mount_check_snapshot_delete`
- **Category:** check
- **Call site:** `sys/contrib/openzfs/module/zfs/zfs_ioctl.c`,
  `zfs_ioc_destroy_snaps()` (~line 4273), before destroy
- **Lock context:** No locks held. `spa_config` read lock acquired
  internally at line 4298.
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)

```c
typedef int (*mpo_mount_check_snapshot_delete_t)(struct ucred *cred,
    const char *snapname);

int mac_mount_check_snapshot_delete(struct ucred *cred,
    const char *snapname);
```

---

### 6.3 mac_mount_check_snapshot_revert

- **XNU name:** `mac_mount_check_snapshot_revert`
- **5BSD name:** `mac_mount_check_snapshot_revert`
- **Category:** check
- **Call site:** `sys/contrib/openzfs/module/zfs/zfs_ioctl.c`,
  `zfs_ioc_rollback()` (~line 4965), before rollback
- **Lock context:** No locks held at entry. ZFS teardown write lock
  (rmslock) acquired at line 4989. Hook MUST fire BEFORE the teardown
  lock.
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)

```c
typedef int (*mpo_mount_check_snapshot_revert_t)(struct ucred *cred,
    const char *snapname);

int mac_mount_check_snapshot_revert(struct ucred *cred,
    const char *snapname);
```

**Notes:**
- Snapshot rollback is the most dangerous ZFS operation — it can revert
  security patches, restore deleted malware, or undo configuration
  hardening. This MUST fire before ZFS acquires the teardown lock.

---

### 6.4 mac_mount_check_fsctl

- **XNU name:** `mac_mount_check_fsctl`
- **5BSD name:** `mac_mount_check_fsctl`
- **Category:** check
- **Call site:** `sys/kern/vfs_vnops.c`, `vn_ioctl()`, before
  `VOP_IOCTL()` dispatch (~line 1884)
- **Lock context:** No vnode lock held at dispatch point
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)

```c
typedef int (*mpo_mount_check_fsctl_t)(struct ucred *cred,
    struct mount *mp, u_long cmd);

int mac_mount_check_fsctl(struct ucred *cred, struct mount *mp,
    u_long cmd);
```

---

## 7. System Information Hooks

### 7.1 mac_system_check_kas_info

- **XNU name:** `mac_system_check_kas_info`
- **5BSD name:** `mac_system_check_kas_info`
- **Category:** check
- **Call site:** `sys/kern/kern_proc.c`, `fill_kinfo_proc_only()`, before
  kernel pointer fields are filled (~line 1088-1091). Currently leaks:
  - `kp->ki_paddr = p` (process struct kernel address)
  - `kp->ki_fd = p->p_fd` (fd table kernel address)
  - `kp->ki_pd = p->p_pd` (proc details kernel address)
  - `kp->ki_vmspace = p->p_vmspace` (VM space kernel address)
- **Lock context:** `PROC_LOCK(p)` IS HELD (asserted at line 1088)
- **Can sleep:** NO — PROC_LOCK held
- **Composition macro:** `MAC_POLICY_CHECK_NOSLEEP`
- **Fast-path flag:** YES — `kern.proc.*` sysctl queries are frequent
  (ps, top, htop all use this)

```c
typedef int (*mpo_system_check_kas_info_t)(struct ucred *cred,
    struct proc *p);

int mac_system_check_kas_info(struct ucred *cred, struct proc *p);
```

**Notes:**
- PROC_LOCK(p) is held on the TARGET process. MUST NOT sleep.
- `cred` is the requesting process's credential. `p` is the target
  process whose kernel pointers would be disclosed. Both are available
  at the call site (`fill_kinfo_proc_only` receives `struct proc *p`
  and the caller's cred comes from the sysctl context).
- Passing `p` lets policies express per-target rules: "allow self, deny
  others", "allow same jail, deny cross-jail", "allow root viewing any
  process, deny unprivileged cross-user". A cred-only signature would
  be limited to global allow/deny.
- Return EPERM to suppress kernel address fields. The kinfo_proc struct
  is still returned but pointer fields are zeroed.
- This is not a binary allow/deny — the hook should cause the caller to
  zero the pointer fields rather than fail the entire sysctl.
  Implementation detail: the call site should check the return and zero
  `ki_paddr`, `ki_fd`, `ki_pd`, `ki_vmspace` on EPERM rather than
  failing the whole query.
- Without this, any unprivileged process can read kernel ASLR base
  addresses via `sysctl kern.proc.pid.<pid>`, defeating KASLR.

---

## 8. Mount Operation Hooks

These are fundamental and were missing from the initial analysis. FreeBSD
has VFS mount/unmount paths but no MAC gates on who can mount/unmount/
remount.

### 8.1 mac_mount_check_mount

- **XNU name:** `mac_mount_check_mount`
- **5BSD name:** `mac_mount_check_mount`
- **Category:** check
- **Call site:** `sys/kern/vfs_mount.c`, `vfs_domount()`, before the
  filesystem is mounted
- **Lock context:** No locks held at entry. Mount alloc and VFS setup
  happen after.
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No — mount is rare

```c
typedef int (*mpo_mount_check_mount_t)(struct ucred *cred,
    const char *fspath, const char *fstype, int flags);

int mac_mount_check_mount(struct ucred *cred, const char *fspath,
    const char *fstype, int flags);
```

**Notes:**
- `fspath` is the mount point path.
- `fstype` is the filesystem type name (e.g., "zfs", "ufs", "nullfs").
- `flags` includes MNT_RDONLY, MNT_NOSUID, MNT_NOEXEC, etc.
- Without this, any privileged process can mount arbitrary filesystems.
  A policy could restrict mounts to specific fstypes or paths.

---

### 8.2 mac_mount_check_umount

- **XNU name:** `mac_mount_check_umount`
- **5BSD name:** `mac_mount_check_umount`
- **Category:** check
- **Call site:** `sys/kern/vfs_mount.c`, `dounmount()`, before unmount
  begins
- **Lock context:** No locks held at the ideal hook point (before
  mount busy check)
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No

```c
typedef int (*mpo_mount_check_umount_t)(struct ucred *cred,
    struct mount *mp);

int mac_mount_check_umount(struct ucred *cred, struct mount *mp);
```

**Notes:**
- Prevents unauthorized unmounting of critical filesystems.
- A policy could protect / or /usr from being unmounted even by root.

---

### 8.3 mac_mount_check_remount

- **XNU name:** `mac_mount_check_remount`
- **5BSD name:** `mac_mount_check_remount`
- **Category:** check
- **Call site:** `sys/kern/vfs_mount.c`, `vfs_domount()`, in the
  `MNT_UPDATE` path before flags are applied
- **Lock context:** No locks held
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No

```c
typedef int (*mpo_mount_check_remount_t)(struct ucred *cred,
    struct mount *mp, int flags);

int mac_mount_check_remount(struct ucred *cred, struct mount *mp,
    int flags);
```

**Notes:**
- Remounting to drop `noexec`/`nosuid` is a classic privilege escalation.
  `mount -u -o exec /tmp` removes the noexec flag. No MAC check today.
- `flags` is the new set of mount flags. The policy can compare against
  `mp->mnt_flag` (current flags) to detect flag removal.

---

## 9. Vnode Check Hooks (Missing from Initial Analysis)

### 9.1 mac_vnode_check_uipc_bind

- **XNU name:** `mac_vnode_check_uipc_bind`
- **5BSD name:** `mac_vnode_check_uipc_bind`
- **Category:** check
- **Call site:** `sys/kern/uipc_usrreq.c`, `uipc_bindat()`, at line 641.
  Currently uses generic `mac_vnode_check_create()` before VOP_CREATE.
  A dedicated hook would replace the generic one for socket-specific
  policy decisions.
- **Lock context:** No locks held at the check point
- **Can sleep:** YES — VOP operations follow
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No

```c
typedef int (*mpo_vnode_check_uipc_bind_t)(struct ucred *cred,
    struct vnode *dvp, struct componentname *cnp, struct vattr *vap);

int mac_vnode_check_uipc_bind(struct ucred *cred, struct vnode *dvp,
    struct componentname *cnp, struct vattr *vap);
```

**Notes:**
- Gates creating a Unix domain socket node on the filesystem.
- `dvp` is the parent directory. `cnp` is the socket filename.
- Unix socket paths are a real attack surface — binding to
  `/tmp/.X11-unix/X0` or `/var/run/docker.sock` locations can hijack
  services.

---

### 9.2 mac_vnode_check_uipc_connect

- **XNU name:** `mac_vnode_check_uipc_connect`
- **5BSD name:** `mac_vnode_check_uipc_connect`
- **Category:** check
- **Call site:** `sys/kern/uipc_usrreq.c`, `unp_connectat()`, at line
  2922. Currently uses generic `mac_vnode_check_open()`. A dedicated hook
  would allow socket-connect-specific policy decisions.
- **Lock context:** No locks held at the check point
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No

```c
typedef int (*mpo_vnode_check_uipc_connect_t)(struct ucred *cred,
    struct vnode *vp, struct label *vplabel);

int mac_vnode_check_uipc_connect(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
```

**Notes:**
- Gates connecting to an existing Unix domain socket.
- A sandboxed process should not be able to connect to
  `/var/run/docker.sock` or other privileged socket endpoints.

---

### 9.3 mac_vnode_check_truncate

- **XNU name:** `mac_vnode_check_truncate`
- **5BSD name:** `mac_vnode_check_truncate`
- **Category:** check
- **Call site:** `sys/kern/vfs_vnops.c`, `vn_truncate()`, at line 1790.
  Currently uses generic `mac_vnode_check_write()`. A dedicated truncate
  hook would allow policies to distinguish destructive truncation from
  normal writes.
- **Lock context:** No locks at entry. Range lock and vnode lock acquired
  after.
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No

```c
typedef int (*mpo_vnode_check_truncate_t)(struct ucred *cred,
    struct vnode *vp);

int mac_vnode_check_truncate(struct ucred *cred, struct vnode *vp);
```

**Notes:**
- The document already had `vnode_notify_truncate` (post-event). This is
  the deny-side check that fires BEFORE truncation.
- Truncation is destructive — it permanently discards file data. This is
  the enforcement point.

---

### 9.4 mac_vnode_check_fsgetpath

- **XNU name:** `mac_vnode_check_fsgetpath`
- **5BSD name:** `mac_vnode_check_getpath`
- **Category:** check
- **Call site:** `sys/kern/vfs_cache.c`, `vn_fullpath()` at line 3392.
  Currently has NO MACF hook at all — this is a pure utility function.
- **Lock context:** Varies — vn_fullpath may be called with or without
  vnode lock depending on caller
- **Can sleep:** YES in most call contexts
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No

```c
typedef int (*mpo_vnode_check_getpath_t)(struct ucred *cred,
    struct vnode *vp);

int mac_vnode_check_getpath(struct ucred *cred, struct vnode *vp);
```

**Notes:**
- Reverse lookup from fd/vnode to pathname leaks filesystem layout.
- A sandboxed process with an inherited fd should not be able to discover
  where on the filesystem that fd points.
- FreeBSD exposes this via `__getcwd()`, `procfs`, `sysctl kern.proc.filedesc`,
  and `fcntl(F_KINFO)`.
- Follow-on item: re-evaluate whether hooking `vn_fullpath()` is broader
  than desired. The current placement gates all `vn_fullpath()` callers,
  including kernel/internal path lookups, not just user-visible path
  disclosure paths.

---

## 10. System Hooks (Additional)

### 10.1 mac_system_check_settime

- **XNU name:** `mac_system_check_settime`
- **5BSD name:** `mac_system_check_settime`
- **Category:** check
- **Call site:** `sys/kern/kern_time.c`, `sys_settimeofday()` and
  `sys_clock_settime()`, before the time is changed
- **Lock context:** No locks held
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No — time setting is rare

```c
typedef int (*mpo_system_check_settime_t)(struct ucred *cred);

int mac_system_check_settime(struct ucred *cred);
```

**Notes:**
- Time manipulation enables: log timestamp falsification, TLS certificate
  validation bypass (expired certs become "valid"), time-based token
  replay attacks, and Kerberos ticket manipulation.
- Today the only check is `priv_check(PRIV_CLOCK_SETTIME)`. A MAC policy
  can further restrict even privileged processes.

---

## 11. Vnode Notifications (Additional)

### 11.1 mac_vnode_notify_setextattr

- **XNU name:** `mac_vnode_notify_setextattr`
- **5BSD name:** `mac_vnode_notify_setextattr`
- **Category:** notify (void return)
- **Call site:** `sys/kern/vfs_extattr.c`, after successful
  `VOP_SETEXTATTR()`
- **Lock context:** Vnode locked
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_vnode_notify_setextattr_t)(struct ucred *cred,
    struct vnode *vp, int attrnamespace, const char *name);

void mac_vnode_notify_setextattr(struct ucred *cred, struct vnode *vp,
    int attrnamespace, const char *name);
```

**Notes:**
- Extended attributes store MAC labels, capabilities, and security
  metadata. Policies tracking label integrity need to know when
  extattrs change.

---

### 11.2 mac_vnode_notify_deleteextattr

- **XNU name:** `mac_vnode_notify_deleteextattr`
- **5BSD name:** `mac_vnode_notify_deleteextattr`
- **Category:** notify (void return)
- **Call site:** `sys/kern/vfs_extattr.c`, after successful
  `VOP_DELETEEXTATTR()`
- **Lock context:** Vnode locked
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_vnode_notify_deleteextattr_t)(struct ucred *cred,
    struct vnode *vp, int attrnamespace, const char *name);

void mac_vnode_notify_deleteextattr(struct ucred *cred, struct vnode *vp,
    int attrnamespace, const char *name);
```

---

### 11.3 mac_vnode_notify_setacl

- **XNU name:** `mac_vnode_notify_setacl`
- **5BSD name:** `mac_vnode_notify_setacl`
- **Category:** notify (void return)
- **Call site:** `sys/kern/vfs_acl.c`, after successful `VOP_SETACL()`
- **Lock context:** Vnode locked
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_vnode_notify_setacl_t)(struct ucred *cred,
    struct vnode *vp, acl_type_t type);

void mac_vnode_notify_setacl(struct ucred *cred, struct vnode *vp,
    acl_type_t type);
```

---

### 11.4 mac_vnode_notify_setutimes

- **XNU name:** `mac_vnode_notify_setutimes`
- **5BSD name:** `mac_vnode_notify_setutimes`
- **Category:** notify (void return)
- **Call site:** `sys/kern/vfs_syscalls.c`, after successful
  `kern_utimesat()` / `VOP_SETATTR()` with `va_atime`/`va_mtime`
- **Lock context:** Vnode locked
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_vnode_notify_setutimes_t)(struct ucred *cred,
    struct vnode *vp);

void mac_vnode_notify_setutimes(struct ucred *cred, struct vnode *vp);
```

---

## 12. Socket Hooks (Additional)

### 12.1 mac_socket_check_setsockopt

- **XNU name:** `mac_socket_check_setsockopt`
- **5BSD name:** `mac_socket_check_setsockopt`
- **Category:** check
- **Call site:** `sys/kern/uipc_syscalls.c`, `kern_setsockopt()`, before
  the option is applied
- **Lock context:** No locks held at the check point
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)
- **Fast-path flag:** No

```c
typedef int (*mpo_socket_check_setsockopt_t)(struct ucred *cred,
    struct socket *so, struct label *solabel, int level, int optname);

int mac_socket_check_setsockopt(struct ucred *cred, struct socket *so,
    struct label *solabel, int level, int optname);
```

**Notes:**
- `level` + `optname` identify the specific option (e.g.,
  `SOL_SOCKET`/`SO_REUSEADDR`, `IPPROTO_IP`/`IP_OPTIONS`).
- A sandboxed process should not be able to set raw socket options,
  change routing, or enable promiscuous mode.

---

## 13. PTY Notification Hooks

### 13.1 mac_pty_notify_grant

- **XNU name:** `mac_pty_notify_grant`
- **5BSD name:** `mac_pty_notify_grant`
- **Category:** notify (void return)
- **Call site:** `sys/kern/tty_pts.c`, after a PTY slave is granted
  via `posix_openpt()` / `grantpt()`
- **Lock context:** No locks held
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_pty_notify_grant_t)(struct ucred *cred, dev_t dev);

void mac_pty_notify_grant(struct ucred *cred, dev_t dev);
```

**Notes:**
- Useful for session auditing — tracks which user acquired which PTY.

---

### 13.2 mac_pty_notify_close

- **XNU name:** `mac_pty_notify_close`
- **5BSD name:** `mac_pty_notify_close`
- **Category:** notify (void return)
- **Call site:** `sys/kern/tty_pts.c`, when a PTY master is closed
- **Lock context:** No locks held
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_PERFORM` (void, sleepable)

```c
typedef void (*mpo_pty_notify_close_t)(struct ucred *cred, dev_t dev);

void mac_pty_notify_close(struct ucred *cred, dev_t dev);
```

---

## Implementation Plan

### 1. Implement Now (38 hooks)

These are correctly specified and ready to build. Check hooks provide
enforcement (AUTH events), notify hooks provide telemetry (NOTIFY events)
for OpenEndpointSecurity.

**Phase 1 — Core enforcement + process/file lifecycle (14 hooks)**

| # | Hook | Type | Sleep | ES event class |
|---|------|------|-------|---------------|
| 1 | `mac_proc_check_mmap_anon` | check | yes | AUTH_MMAP_ANON |
| 2 | `mac_proc_check_mprotect` | check | yes | AUTH_MPROTECT |
| 3 | `mac_file_check_receive` | check | yes | AUTH_FILE_RECEIVE |
| 4 | `mac_file_check_inherit` | check | **no** | AUTH_FILE_INHERIT |
| 5 | `mac_mount_check_mount` | check | yes | AUTH_MOUNT |
| 6 | `mac_mount_check_umount` | check | yes | AUTH_UNMOUNT |
| 7 | `mac_mount_check_remount` | check | yes | AUTH_REMOUNT |
| 8 | `mac_proc_check_fork` | check | yes | AUTH_FORK |
| 9 | `mac_proc_check_core` | check | **no** | AUTH_CORE_DUMP |
| 10 | `mac_proc_check_syscall` | check | yes | AUTH_SYSCALL |
| 11 | `mac_proc_notify_exec_complete` | notify | yes | NOTIFY_EXEC |
| 12 | `mac_system_check_kas_info` | check | **no** | AUTH_KAS_INFO |
| 13 | `mac_vmm_check_create` | check | yes | AUTH_VMM_CREATE |
| 14 | `mac_proc_notify_exit` | notify | yes | NOTIFY_EXIT |

**FPFLAG required:** `proc_check_fork`, `proc_check_mmap_anon`,
`proc_check_mprotect`, `proc_check_syscall`, `system_check_kas_info`.

**Phase 2 — Filesystem telemetry (18 hooks)**

| # | Hook | Type | Sleep | ES event class |
|---|------|------|-------|---------------|
| 15 | `mac_vnode_notify_create` | notify | yes | NOTIFY_CREATE |
| 16 | `mac_vnode_notify_open` | notify | yes | NOTIFY_OPEN |
| 17 | `mac_vnode_notify_rename` | notify | yes | NOTIFY_RENAME |
| 18 | `mac_vnode_notify_unlink` | notify | yes | NOTIFY_UNLINK |
| 19 | `mac_vnode_notify_link` | notify | yes | NOTIFY_LINK |
| 20 | `mac_vnode_notify_truncate` | notify | yes | NOTIFY_TRUNCATE |
| 21 | `mac_vnode_notify_setmode` | notify | yes | NOTIFY_SETMODE |
| 22 | `mac_vnode_notify_setowner` | notify | yes | NOTIFY_SETOWNER |
| 23 | `mac_vnode_notify_setflags` | notify | yes | NOTIFY_SETFLAGS |
| 24 | `mac_vnode_notify_setextattr` | notify | yes | NOTIFY_SETEXTATTR |
| 25 | `mac_vnode_notify_deleteextattr` | notify | yes | NOTIFY_DELETEEXTATTR |
| 26 | `mac_vnode_notify_setacl` | notify | yes | NOTIFY_SETACL |
| 27 | `mac_vnode_notify_setutimes` | notify | yes | NOTIFY_SETUTIMES |
| 28 | `mac_vnode_check_truncate` | check | yes | AUTH_TRUNCATE |
| 29 | `mac_vnode_check_uipc_bind` | check | yes | AUTH_UIPC_BIND |
| 30 | `mac_mount_check_snapshot_create` | check | yes | AUTH_SNAPSHOT_CREATE |
| 31 | `mac_mount_check_snapshot_delete` | check | yes | AUTH_SNAPSHOT_DELETE |
| 32 | `mac_mount_check_snapshot_revert` | check | yes | AUTH_SNAPSHOT_REVERT |

**Phase 3 — Complete telemetry (6 hooks)**

| # | Hook | Type | Sleep | ES event class |
|---|------|------|-------|---------------|
| 33 | `mac_file_check_dup` | check | **no** | AUTH_FILE_DUP |
| 34 | `mac_file_check_ioctl` | check | yes | AUTH_IOCTL |
| 35 | `mac_file_check_mmap` | check | yes | AUTH_FILE_MMAP |
| 36 | `mac_file_notify_close` | notify | yes | NOTIFY_CLOSE |
| 37 | `mac_vnode_check_uipc_connect` | check | yes | AUTH_UIPC_CONNECT |
| 38 | `mac_socket_check_setsockopt` | check | yes | AUTH_SETSOCKOPT |

**FPFLAG required:** `file_check_ioctl`, `file_check_mmap`.

**Dropped from Phase 3:** `mac_vnode_check_getpath` — `vn_fullpath()` is a
utility function called from many contexts without the vnode lock held,
making it incompatible with the `ASSERT_VOP_LOCKED` convention required
by all vnode check hooks.  Callers include `kern_proc.c` sysctl handlers
(no vnode lock), `kern_exec.c`, and `kern_lockf.c`.

### 2. Drop (14 hooks)

| Hook | Reason |
|------|--------|
| `mac_proc_check_thr_new` | FreeBSD `thr_new()` is self-thread creation only. No remote thread injection exists. This doesn't map to XNU's concept and no policy would deny a process creating its own threads. |
| `mac_file_check_lock` | Low signal. File locking contention attacks are theoretical. Adds framework surface area without meaningful ES telemetry. |
| `mac_file_check_fcntl` | Most fcntl commands are benign (F_GETFL, F_GETFD). The dangerous ones (F_SETOWN, clearing O_APPEND) are niche. Low signal-to-noise — every shell pipeline generates fcntl events. Defer until specific fcntl events are identified as needed. |
| `mac_pty_notify_grant` | Too niche. PTY lifecycle is audit noise unless you have a specific session-tracking product requirement. Can be added later if needed. |
| `mac_pty_notify_close` | Same as above. |
| `mac_proc_check_suspend` | Redundant with `mac_proc_check_signal`. SIGSTOP already goes through the signal path. A separate suspend hook adds complexity without new information. |
| `mac_rctl_check_add_rule` | Resource limit changes are already privilege-gated. Not central to ES telemetry. Can be added later if RCTL becomes a product concern. |
| `mac_rctl_check_remove_rule` | Same as above. |
| `mac_system_check_settime` | Already requires `PRIV_CLOCK_SETTIME`. MAC hook adds a second gate on a privilege-checked operation. Attack (cert bypass, log tampering) is real but rare. Defer. |
| `mac_mount_check_fsctl` | Too vague — "filesystem ioctls" is a catch-all without clear threat model. Better to add targeted hooks for specific dangerous fsctrls than one noisy hook. Defer. |
| `mac_proc_check_cpuset` | Bad shape. One hook can't cover PID/TID (PROC_LOCK held), CPUSET/JAIL/IRQ/DOMAIN (no process target) paths. Would need to be split into multiple hooks with different signatures and sleep contexts. Not worth the complexity. |
| `mac_proc_check_ktrace` | Bad shape. The real authorization is in ktrcanset() under PROC_LOCK in a per-process loop — fires N times per ktrace syscall, can't sleep. The alternative (sys_ktrace() entry) doesn't know the target yet. No clean call site. `p_candebug()` already calls `mac_proc_check_debug` on the ktrace path, providing most enforcement. |
| `mac_vmm_check_destroy` | Needs lock audit of vmmdev_lookup_and_destroy()/vm_destroy() before the spec can be trusted. Concept is fine but unverified. Defer until someone reads the bhyve code. |
| `mac_vmm_check_mem_access` | Same — VM memory access ioctls may hold per-VM locks. Guest physical address signature needs careful design. Defer. |

### Lock Context Reference

**Non-sleepable hooks** (MUST NOT sleep):

| Hook | Lock held | Phase |
|------|-----------|-------|
| `mac_proc_check_core` | PROC_LOCK(p) | 1 |
| `mac_file_check_inherit` | FILEDESC_XLOCK | 1 |
| `mac_system_check_kas_info` | PROC_LOCK(p) | 1 |
| `mac_file_check_dup` | FILEDESC_XLOCK | 3 |

All other "implement now" hooks are sleepable.

### All FPFLAG Hooks

| Hook | Why | Phase |
|------|-----|-------|
| `mac_proc_check_fork` | fork() frequency | 1 |
| `mac_proc_check_mmap_anon` | mmap() frequency | 1 |
| `mac_proc_check_mprotect` | mprotect() frequency (ld.so) | 1 |
| `mac_proc_check_syscall` | EVERY syscall | 1 |
| `mac_system_check_kas_info` | ps/top polling | 1 |
| `mac_file_check_ioctl` | ioctl() frequency | 3 |
| `mac_file_check_mmap` | mmap() frequency | 3 |

### Follow-on Work

- Re-evaluate `mac_vnode_check_getpath()` placement if policy semantics
  should cover only user-visible pathname disclosure instead of all
  `vn_fullpath()` callers.
- Add the `mac_test_hooks` policy module and userspace regression tests.
- Revisit dropped hooks only after real policy requirements justify them.

---

## Test Plan: mac_test_hooks Module

### Overview

Create a new MAC policy module `mac_test_hooks` in
`sys/security/mac_test_hooks/` that exercises every new hook. Unlike the
existing `mac_test` module (which always allows), this module adds
**per-hook sysctl deny toggles** so each hook can be switched between
allow and deny at runtime.

The module is paired with a userspace test program in
`tests/sys/mac/mac_test_hooks_test.c` that triggers every hook and
verifies both allow and deny paths.

### Module Design

**Sysctl tree:** `security.mac.test_hooks.*`

**Per-hook controls:**

```c
/*
 * Sysctl node declarations — required boilerplate before the
 * per-hook macros can reference _security_mac_test_hooks_counter
 * and _security_mac_test_hooks_deny as parent nodes.
 * (cf. sys/security/mac_test/mac_test.c:113-116)
 */
static SYSCTL_NODE(_security_mac, OID_AUTO, test_hooks,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "5BSD mac_test_hooks policy controls");

static SYSCTL_NODE(_security_mac_test_hooks, OID_AUTO, counter,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Per-hook invocation counters");

static SYSCTL_NODE(_security_mac_test_hooks, OID_AUTO, deny,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Per-hook deny toggles (0=allow, nonzero=errno)");

/*
 * For each hook, two sysctls:
 *   security.mac.test_hooks.counter.<name>  — invocation count (RD)
 *   security.mac.test_hooks.deny.<name>     — deny toggle (RW)
 *
 * When deny.<name> == 0: hook returns 0 (allow)
 * When deny.<name> != 0: hook returns deny.<name> as errno (e.g., EPERM)
 * Notify hooks have no deny toggle (void return).
 */

#define HOOK_CHECK_DECL(name)                                       \
    static int counter_##name;                                      \
    static int deny_##name;                                         \
    SYSCTL_INT(_security_mac_test_hooks_counter, OID_AUTO, name,    \
        CTLFLAG_RD, &counter_##name, 0, #name);                    \
    SYSCTL_INT(_security_mac_test_hooks_deny, OID_AUTO, name,      \
        CTLFLAG_RW, &deny_##name, 0, #name)

#define HOOK_CHECK_IMPL(name, ...)                                  \
    HOOK_CHECK_DECL(name);                                          \
    static int                                                      \
    test_##name(__VA_ARGS__)                                        \
    {                                                               \
        atomic_add_int(&counter_##name, 1);                         \
        return (deny_##name);                                       \
    }

#define HOOK_NOTIFY_DECL(name)                                      \
    static int counter_##name;                                      \
    SYSCTL_INT(_security_mac_test_hooks_counter, OID_AUTO, name,    \
        CTLFLAG_RD, &counter_##name, 0, #name)

#define HOOK_NOTIFY_IMPL(name, ...)                                 \
    HOOK_NOTIFY_DECL(name);                                         \
    static void                                                     \
    test_##name(__VA_ARGS__)                                        \
    {                                                               \
        atomic_add_int(&counter_##name, 1);                         \
    }
```

**Registration:** `MPC_LOADTIME_FLAG_UNLOADOK` — loadable and unloadable
at runtime for testing convenience. No label slot needed (pass NULL).

### Module File Layout

```
sys/security/mac_test_hooks/
    mac_test_hooks.c        — module source (all hook implementations)
sys/modules/mac_test_hooks/
    Makefile                — kernel module build
tests/sys/mac/
    mac_test_hooks_test.c   — userspace test program
    Makefile                — test build
```

### Userspace Test Program Design

The test program:

1. Loads the module via `kldload("mac_test_hooks")`
2. For each check hook:
   a. Read counter via sysctl, record baseline
   b. Trigger the operation (expect success)
   c. Read counter, verify it incremented
   d. Set deny sysctl to EPERM
   e. Trigger the operation (expect EPERM / failure)
   f. Read counter, verify it incremented again
   g. Reset deny sysctl to 0
3. For each notify hook:
   a. Read counter via sysctl, record baseline
   b. Trigger the operation
   c. Read counter, verify it incremented
4. Unloads the module via `kldunload("mac_test_hooks")`

### Per-Hook Test Triggers

Each hook needs a specific userspace action to trigger it:

| Hook | Test trigger |
|------|-------------|
| `proc_check_fork` | `fork()` |
| `proc_check_core` | `kill(child, SIGQUIT)` with core limit set |
| `proc_check_thr_new` | `pthread_create()` |
| `proc_check_suspend` | `kill(child, SIGSTOP)` |
| `proc_check_mmap_anon` | `mmap(NULL, 4096, PROT_READ, MAP_ANON, -1, 0)` |
| `proc_check_mprotect` | `mmap()` then `mprotect()` |
| `proc_check_syscall` | Any syscall (e.g., `getpid()`) |
| `file_check_dup` | `dup(STDOUT_FILENO)` |
| `file_check_inherit` | `fork()` + `exec()` with open fd (no CLOEXEC) |
| `file_check_receive` | Unix socket pair, send fd via `SCM_RIGHTS` |
| `file_check_fcntl` | `fcntl(fd, F_GETFL)` |
| `file_check_ioctl` | `ioctl(ttyfd, TIOCGWINSZ, &ws)` |
| `file_check_lock` | `flock(fd, LOCK_EX)` |
| `file_check_mmap` | `mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0)` |
| `file_notify_close` | `close(fd)` |
| `mount_check_mount` | `nmount()` (requires root, or skip) |
| `mount_check_umount` | `unmount()` (requires root, or skip) |
| `mount_check_remount` | `nmount()` with MNT_UPDATE (requires root) |
| `mount_check_snapshot_*` | `zfs snapshot` (requires ZFS, or skip) |
| `mount_check_fsctl` | `ioctl()` on mount fd |
| `vnode_check_uipc_bind` | `bind()` on AF_UNIX socket to path |
| `vnode_check_uipc_connect` | `connect()` to AF_UNIX socket path |
| `vnode_check_truncate` | `truncate("/tmp/testfile", 0)` |
| `vnode_check_getpath` | `__getcwd(buf, sizeof(buf))` |
| `system_check_settime` | `settimeofday()` (requires root, or skip) |
| `system_check_kas_info` | `sysctl kern.proc.pid.<pid>`, check ki_paddr |
| `socket_check_setsockopt` | `setsockopt(s, SOL_SOCKET, SO_REUSEADDR, ...)` |
| `proc_notify_exec_complete` | `fork()` + `exec("/bin/true")` |
| `proc_notify_exit` | `fork()`, child `_exit(0)` |
| `vnode_notify_create` | `open("/tmp/testfile", O_CREAT, 0644)` |
| `vnode_notify_open` | `open("/tmp/testfile", O_RDONLY)` |
| `vnode_notify_rename` | `rename("/tmp/a", "/tmp/b")` |
| `vnode_notify_unlink` | `unlink("/tmp/testfile")` |
| `vnode_notify_link` | `link("/tmp/a", "/tmp/b")` |
| `vnode_notify_truncate` | `truncate("/tmp/testfile", 0)` |
| `vnode_notify_setmode` | `chmod("/tmp/testfile", 0600)` |
| `vnode_notify_setowner` | `chown("/tmp/testfile", uid, gid)` (root) |
| `vnode_notify_setflags` | `chflags("/tmp/testfile", UF_IMMUTABLE)` |
| `vnode_notify_setextattr` | `extattr_set_file()` |
| `vnode_notify_deleteextattr` | `extattr_delete_file()` |
| `vnode_notify_setacl` | `acl_set_file()` |
| `vnode_notify_setutimes` | `utimes("/tmp/testfile", ...)` |
| `pty_notify_grant` | `posix_openpt(O_RDWR)` |
| `pty_notify_close` | Close PTY master fd |

### Tests Requiring Root

Some hooks gate privileged operations. The test program should:
- Detect if running as root
- Skip mount/time/chown tests if not root (with `SKIP` status)
- Use ATF (Automated Testing Framework) for structured pass/fail/skip

### Test Ordering Considerations

- `proc_check_fork` deny test must be careful — if fork is denied, the
  test can't spawn children for subsequent tests. Test deny LAST or use
  a subprocess that is expected to fail.
- `proc_check_syscall` deny is extremely broad — if enabled, almost
  nothing works. Test with a targeted syscall number if the hook supports
  it, or test very briefly and reset immediately.
- Mount/unmount deny tests should use a tmpfs test mount, not the root
  filesystem.

### Expected Output

```
$ ./mac_test_hooks_test
mac_test_hooks: loading module... ok
proc_check_fork: allow ok, counter ok, deny ok (EPERM), counter ok
proc_check_core: allow ok, counter ok, deny ok (EPERM), counter ok
...
vnode_notify_create: counter ok
vnode_notify_open: counter ok
...
mac_test_hooks: unloading module... ok
58 tests passed, 0 failed, 0 skipped
```

---

# Part 2: FreeBSD-Only Hooks (No XNU Equivalent)

FreeBSD has diverged significantly from XNU. The following subsystems exist
only in FreeBSD and have NO MAC framework hooks. These hooks would be
unique to 5BSD — Apple never needed them because these subsystems don't
exist in XNU.

## 14. Kernel Memory Device Hooks

The `/dev/mem` and `/dev/kmem` MAC hooks were removed from the current
scope. Access to those devices remains governed by the existing privilege
and securelevel checks.

## 15. bhyve Hypervisor Hooks

bhyve is FreeBSD's Type-2 hypervisor. VM operations are gated only by
`PRIV_VMM_*` privilege checks. XNU has no equivalent — Apple uses
Hypervisor.framework in userspace.

### 15.1 mac_vmm_check_create

- **5BSD name:** `mac_vmm_check_create`
- **Category:** check
- **Call site:** `sys/dev/vmm/vmm_dev.c`, in the VM creation ioctl path,
  before the VM is allocated
- **Lock context:** No locks held
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)

```c
typedef int (*mpo_vmm_check_create_t)(struct ucred *cred,
    const char *vmname);

int mac_vmm_check_create(struct ucred *cred, const char *vmname);
```

**Notes:**
- VM creation allocates significant kernel resources (EPT page tables,
  VMCS structures, APIC state).
- A policy could restrict which users/processes/jails can create VMs.
- `vmname` identifies the VM for policy decisions.

---

### 15.2 mac_vmm_check_destroy

- **5BSD name:** `mac_vmm_check_destroy`
- **Category:** check
- **Call site:** `sys/dev/vmm/vmm_dev.c`, in the VM destroy path
- **Lock context:** No locks held
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)

```c
typedef int (*mpo_vmm_check_destroy_t)(struct ucred *cred,
    const char *vmname);

int mac_vmm_check_destroy(struct ucred *cred, const char *vmname);
```

---

### 15.3 mac_vmm_check_mem_access

- **5BSD name:** `mac_vmm_check_mem_access`
- **Category:** check
- **Call site:** `sys/dev/vmm/vmm_dev.c`, in VM memory read/write ioctls
- **Lock context:** No locks held
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)

```c
typedef int (*mpo_vmm_check_mem_access_t)(struct ucred *cred,
    const char *vmname, vm_paddr_t gpa, size_t len, int prot);

int mac_vmm_check_mem_access(struct ucred *cred, const char *vmname,
    vm_paddr_t gpa, size_t len, int prot);
```

**Notes:**
- VM memory access from the host allows reading/writing guest memory.
- `gpa` is the guest physical address. `prot` indicates read/write.
- Critical for VM isolation — prevents a compromised host process from
  reading other VMs' memory.

---

## 20. ktrace Hooks

ktrace allows one process to trace another's syscalls, namei lookups,
I/O, and signal delivery. It's separate from ptrace and currently has
only a vnode write check on the output file.

### 20.1 mac_proc_check_ktrace

- **5BSD name:** `mac_proc_check_ktrace`
- **Category:** check
- **Call site:** `sys/kern/kern_ktrace.c`, inside the per-process
  authorization path in `ktrops()` (line ~1268) / `ktrcanset()` (line
  ~1477), where each target process is checked individually
- **Lock context:** `PROC_LOCK(p)` IS HELD on the target process. The
  per-target authorization in `ktrcanset()` runs under PROC_LOCK
  (line ~1193 acquires it, ~1477 checks within it).
- **Can sleep:** NO — PROC_LOCK held on target
- **Composition macro:** `MAC_POLICY_CHECK_NOSLEEP`

```c
typedef int (*mpo_proc_check_ktrace_t)(struct ucred *cred,
    struct proc *target, int ops);

int mac_proc_check_ktrace(struct ucred *cred, struct proc *target,
    int ops);
```

**Notes:**
- The hook does NOT go at `sys_ktrace()` entry — the target process is
  not yet known there. The actual per-target authorization happens in the
  `ktrops()` loop which iterates over matching processes and calls
  `ktrcanset()` under PROC_LOCK(p) for each one.
- PROC_LOCK is held. Implementations MUST NOT sleep.
- `ops` is the ktrace operation bitmask (KTRFLAG_ROOT, KTRACE_SET, etc.).
- ktrace records all syscalls, arguments, return values, and I/O data.
  This is a complete information disclosure channel.
- Currently gated by `PRIV_KTRACE` and `p_candebug()` (which invokes
  `mac_proc_check_debug`). But ktrace is passive monitoring, not active
  control — a policy might allow ptrace but deny ktrace.

---

## 21. RCTL (Resource Control) Hooks

RCTL provides per-process and per-jail resource limits (CPU, memory,
open files, etc.). XNU has no equivalent — Apple uses launchd-based
resource limits.

### 22.1 mac_rctl_check_add_rule

- **5BSD name:** `mac_rctl_check_add_rule`
- **Category:** check
- **Call site:** `sys/kern/kern_rctl.c`, `sys_rctl_add_rule()`, before
  the rule is added
- **Lock context:** No locks held at syscall entry
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)

```c
typedef int (*mpo_rctl_check_add_rule_t)(struct ucred *cred,
    const char *rule);

int mac_rctl_check_add_rule(struct ucred *cred, const char *rule);
```

**Notes:**
- `rule` is the rctl rule string (e.g., "user:www:memoryuse:deny=1g").
- Manipulating resource limits can be used to DoS specific users/jails
  or to relax limits that were imposed for security.

---

### 22.2 mac_rctl_check_remove_rule

- **5BSD name:** `mac_rctl_check_remove_rule`
- **Category:** check
- **Call site:** `sys/kern/kern_rctl.c`, `sys_rctl_remove_rule()`,
  before the rule is removed
- **Lock context:** No locks held
- **Can sleep:** YES
- **Composition macro:** `MAC_POLICY_CHECK` (sleepable)

```c
typedef int (*mpo_rctl_check_remove_rule_t)(struct ucred *cred,
    const char *rule);

int mac_rctl_check_remove_rule(struct ucred *cred, const char *rule);
```

---

## 23. Audit Subsystem — ALREADY COVERED

The BSM audit subsystem already has MAC hooks wired in:
- `sys_auditon()` calls `mac_system_check_auditon()` at
  `sys/security/audit/audit_syscalls.c:196`
- `sys_auditctl()` calls `mac_system_check_auditctl()` at
  `sys/security/audit/audit_syscalls.c:820`

No new hook is needed. The existing `mpo_system_check_auditon` and
`mpo_system_check_auditctl` hooks (defined in `mac_policy.h`) are
already operational and have stronger signatures than the proposed
unified hook (e.g., `auditctl` passes the vnode, which a unified
cmd-only signature would lose).

---

## Summary: All FreeBSD-Only Hooks

### By subsystem (3 new hooks)

| # | Hook | Subsystem | Priority |
|---|------|-----------|----------|
| 1 | `mac_vmm_check_create` | bhyve | HIGH |
| 2 | `mac_rctl_check_add_rule` | RCTL | MEDIUM |
| 3 | `mac_rctl_check_remove_rule` | RCTL | MEDIUM |

(Audit hooks already exist — `mac_system_check_auditon` and
`mac_system_check_auditctl` are wired in at
`audit_syscalls.c:196` and `:820`.)

### By severity

**HIGH — significant security gaps:**
- bhyve (1 — `vmm_check_create`)

**MEDIUM — defense in depth:**
- RCTL (2)

### Final Counts

| Category | Count |
|----------|-------|
| Implement now (Phases 1-3) | 43 |
| Drop | 14 |
| **Total evaluated** | **57** |

### By implementation phase

| Phase | Focus | Hooks | Cumulative |
|-------|-------|-------|------------|
| 1 | Core enforcement + process/file lifecycle | 18 | 18 |
| 2 | Filesystem telemetry (ES event stream) | 18 | 36 |
| 3 | Complete telemetry (fd, network, system) | 7 | 43 |
