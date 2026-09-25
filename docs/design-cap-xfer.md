# Descriptor Transfer Control

## Requirements

1. Per-fd state controlling SCM_RIGHTS transfer: unlimited, once, or never.
2. Opt-in only — existing software must behave identically.
3. `cap_rights_limit()`, `cap_rights_clear()`, `CAP_ALL` must not interact.
4. Policy propagates through send/receive and is inherited by dup/fork.

## Design

A `uint8_t fde_xfer_state` field on `struct filedescent`, orthogonal to
`cap_rights_t`.  Three monotonically-decreasing states:

| Value | Name | Meaning |
|-------|------|---------|
| 0 | `CAP_XFER_UNLIMITED` | No restriction (default) |
| 1 | `CAP_XFER_ONCE` | One send, then both sides exhausted |
| 2 | `CAP_XFER_NONE` | Transfer blocked (`ENOTCAPABLE`) |
| 3 | `CAP_XFER_TWICE` | Two-hop linear transfer budget |

## Transfer Semantics

```
UNLIMITED → send → sender: UNLIMITED,  receiver: UNLIMITED
ONCE      → send → sender: NONE,       receiver: NONE
NONE      → send → ENOTCAPABLE
```

## Lifecycle

| Event | fde_xfer_state |
|-------|-----------------|
| open / _finstall | set to 0 (UNLIMITED) |
| close / fdfree | zeroed |
| dup / dup2 / dup3 | inherited via fde_copy() |
| fork / fdcopy | inherited via bulk struct copy |
| SCM_RIGHTS send | validated, consumed if ONCE, copied to in-flight (XLOCK) |
| SCM_RIGHTS recv | propagated from in-flight after _finstall |
| cap_rights_limit | no interaction |
| cap_xfer_limit() | tighten only (UNLIMITED→ONCE→NONE) |

## Backward Compatibility

- `CAP_XFER_UNLIMITED = 0` matches `M_ZERO` allocation + explicit zeroing
  in `_finstall` and `fdfree`.  Every existing fd behaves identically.
- No existing code calls `cap_xfer_limit()` — restriction never activates.
- Field lives on `struct filedescent`, not in `cap_rights_t` — invisible
  to all `cap_rights_*` APIs.

## Locking

- `unp_internalize()` upgraded from `FILEDESC_SLOCK` to `FILEDESC_XLOCK`
  because the ONCE→NONE consume is a write.
- `unp_externalize()` already holds `FILEDESC_XLOCK`.
- `kern_cap_xfer_limit()` takes `FILEDESC_XLOCK`.
- No new locks.

## Changes

| File | What |
|------|------|
| `sys/sys/capsicum.h` | `CAP_XFER_UNLIMITED`, `CAP_XFER_ONCE`, `CAP_XFER_NONE`, `CAP_XFER_TWICE` |
| `sys/sys/filedesc.h` | `fde_xfer_state` field, `fde_copy()` line |
| `sys/kern/kern_descrip.c` | Zero in `_finstall()` and `fdfree()` |
| `sys/kern/uipc_usrreq.c` | Validate + consume in `unp_internalize()` (XLOCK), propagate in `unp_externalize()` |
| `sys/sys/syscallsubr.h` | `kern_cap_xfer_limit()` declaration |
| `sys/kern/sys_capability.c` | `kern_cap_xfer_limit()`, `sys_cap_xfer_limit()`, `!CAPABILITIES` stub |
| `sys/kern/syscalls.master` | Syscall 603 `cap_xfer_limit(int fd, int state)` |

## Verified Safe (no changes needed)

- `kern_dup()` — `fde_copy()` copies state, `fde_flags` reconstruction doesn't touch it
- `fdcopy()` (fork) — `*nfde = *ofde` bulk struct copy
- `dupfdopen()` — uses `fde_copy()`
- `dup2(fd, fd)` — same descriptor, no copy
- `fdgrowtable()` — `M_ZERO` + `memcpy`, both safe
- `fdinit()` — `M_ZERO` allocation
- `fdcloseexec()` — only touches `fde_flags`
- All `cap_rights_*` / `cap_fcntls_*` / `cap_ioctls_*` — operate on `filecaps` only
- In-flight `malloc` in `unp_internalize()` — not `M_ZERO` but `fde_xfer_state`
  is explicitly set before use
- accept() / pipe() / socketpair() / kqueue / eventfd / pdfork — all create
  new descriptors via `_finstall()`, get UNLIMITED, correct

## mac_capability Integration

mac_capability has its own fd transfer mechanism.  Changes:

| File | What |
|------|------|
| `sys/dev/mac_capability/mac_capability_internal.h` | `cm_xfer_state[]` array on `struct mac_capability_msg` |
| `sys/dev/mac_capability/mac_capability_dev.c` | SENDMSG: check + consume under XLOCK after fget_cap |
| `sys/dev/mac_capability/mac_capability_dev.c` | RECVMSG: fhold + fdalloc + _finstall + state write under one XLOCK |
| `sys/dev/mac_capability/mac_capability_kern.c` | `mac_capability_msg_alloc_full`: xfer_state param, forward copies it |

CALL reply fds are kernel-created — get UNLIMITED via _finstall, correct.
