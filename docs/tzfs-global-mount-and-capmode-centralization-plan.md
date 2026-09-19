# TrustedZFS delegatable mounts + capability-plane centralization

Status: Part 1 FIXED + VM-verified; Part 2 #1/#2/#3/#4-helper landed + fleet-verified (2026-09-05, commits b6d7e4245d1, bdb9784b3bc); #4 rollout + #5/#7/#9 pending. Owner: Kory Heard.

**Part 1 result:** the bsdfilesystem mount-lifetime fix landed and bsdlog is now born in
capability mode on the real plane — `system.Log/bsdlog running` with its storage
manager and all pool shard workers alive (`SC`), no more "exec failed" retry
loop. The store stays invisible to `find /` (anonymous-mount isolation intact).
No kernel change was needed. Fix = bsdfilesystem retains the mount-anchoring leaf handle
in the per-connection worker state (request.c); bsdlog needed no change because
libservice's `service_storage_session` is already process-lifetime persistent,
so the worker holding the anchor lives as long as bsdlog does.

This document captures two linked findings and their fixes:

1. **The TZFS mount-lifetime bug** that blocks born-in-capability-mode
   storage consumers (bsdlog today, every future one later): bsdfilesystem tears the
   mount down before the consumer can use the delivered directory. The fix is
   a *userland* lifetime fix in bsdfilesystem + bsdlog — no kernel change, no
   `/Capabilities` mount juggling (the existing anonymous isolation is already
   correct).
2. **The "wrong thing in every daemon" audit** — cross-cutting workarounds
   duplicated across the capability daemons that should collapse into
   `libservice`/`switchboard` once (fix roots, not leaves).

The guiding principle, from the maintainer: *stop threading per-daemon
exceptions around a few bad core decisions; change the core once so every
daemon uses the normal, correct pattern.*

---

## Part 1 — TrustedZFS mount lifetime

### The problem, precisely (corrected after kernel recon)

The born-in-capability-mode model needs a storage **directory** that one
process (bsdfilesystem, privileged) mounts and a *different* process (the consumer, in
capability mode) uses. The canonical Capsicum pattern is exactly this: hold a
directory descriptor, `openat` beneath it, delegate that descriptor to whoever
should have it.

The first hypothesis was that `ZFD_MOUNT`'s anonymous mount is *process-local*
(traversable only in the mounting process). **Kernel recon disproved that.** In
`sys/contrib/openzfs/module/os/freebsd/zfs/zfs_handle.c`:

- `zfshandle_anon_mount()` (≈:2271–2377) is `vfs_domount_first()` minus the
  namespace-attach step: it never sets `mnt_vnodecovered` / `v_mountedhere` /
  `VIRF_MOUNTPOINT` (so `vfs_lookup` can't path-cross into it — good isolation),
  but it **does** insert the mount on the global `mountlist` with **root cred**.
- The returned dir fd is an ordinary `DTYPE_VNODE` file on the mount's root
  vnode. Nothing conditions the mount, the vnode, or the fd on the mounting
  `proc`/`thread`/`cred`. **A live anon mount is traversable by any process
  holding the dir fd.**
- `ENOTDIR` for `openat(dirfd,".")` comes only from `v_type != VDIR`
  (`vfs_lookup.c:408`), i.e. the root vnode has been **reclaimed** (doomed).

The mount is anchored **to the handle fd** (`zh_anon_mp`), not the dir fd, and
`zfshandle_close()` does `dounmount(mp, MNT_FORCE, …)` on last handle close
("the handle anchors any anonymous mount: last close unmounts", ≈:2918–2929).
`MNT_FORCE` reclaims the root vnode even though a dir fd still references it →
subsequent `openat(dirfd,".")` returns `ENOTDIR`.

**bsdfilesystem's `grant()` DELIVER_MOUNTED path does exactly this:**

```c
int dfd = tzfs_mount(leaf_fd, false);  /* mount, anchored on leaf_fd  */
...
(void)close(leaf_fd);                  /* <-- closes the anchor -> forced unmount */
(void)close(ns_fd);
return (dfd);                          /* delivers a dir fd on a doomed vnode */
```

So bsdfilesystem **tears the mount down before bsdlog uses the delivered dir fd.** This
matches every observation: bsdfilesystem's own `openat(dfd,".")` succeeded (handle still
open at that point) but bsdlog's failed (handle closed → forced unmount →
`ENOTDIR`). The "fix A re-open in bsdfilesystem" was disproven precisely because bsdfilesystem
still closed the handle afterward. It is a **lifetime bug, not affinity, and not
a namespace problem.**

Consequence: **no kernel change is required, and no `/Capabilities` mount
juggling is needed.** The anonymous mount already provides exactly the isolation
we want (invisible to path lookup, reachable only via the delegated fd). We only
have to keep the mount **alive** for as long as the consumer holds the store.

### The fix: keep the anchoring handle alive for the lease's lifetime (userland)

The mount lives as long as the handle it is anchored to stays open. So the
consumer's storage session must keep that handle open in bsdfilesystem for the store's
lifetime, and bsdfilesystem must not close it prematurely.

1. **bsdfilesystem (`request.c`, DELIVER_MOUNTED):** do **not** `close(leaf_fd)` after
   `tzfs_mount`. Retain the mount-anchoring handle in the per-connection state
   (`struct tzfs_conn`) so it lives for the worker's lifetime; close it in the
   worker teardown (and on an explicit RELEASE). The bsdfilesystem worker is
   per-connection, so the mount is anchored exactly as long as the client's
   connection to bsdfilesystem is open.
2. **bsdlog (`logcmp.c`):** do **not** `service_release()` the storage context
   right after `service_storage_open()`. Retain it (the "storage lease") for
   bsdlog's lifetime, so the bsdfilesystem worker — and therefore the mount — stays alive
   while bsdlog is using the delivered directory. When bsdlog exits, the connection
   closes, the bsdfilesystem worker exits, the retained handle closes, and the mount is
   unmounted. Lifetime is tied to the consumer, which is the correct capability
   semantic.

No `zfd_mount_args` ABI change, no `ZM_GLOBAL` flag, no kernel edit. The
`ZM_GLOBAL`/isolated-mountpoint design is retained below only as a *rejected
alternative* for the record.

### Consumer side (bsdlog) — storage I/O unchanged

bsdlog's `store.c`/`storage.c` keep holding a directory fd and using
`openat`/`*at`/`readdir` under it. No file-server protocol, no per-daemon
storage rewrite. Every future storage consumer stays normal too — it just has to
hold its storage lease open (which `service_storage_open` should encapsulate).

### Rejected alternative: `ZM_GLOBAL` + isolated mountpoint (not needed)

Considered before recon: add a delegatable global-namespace mount mode
(`zm_rdonly` repurposed as flags, `ZM_GLOBAL = 0x2`), mounted under a root-owned
`0700` tree such as `/Capabilities/.run/<claim>` so ambient path lookup can't
reach it. Recon showed the mount is *already* global-on-mountlist and
already path-invisible, and the only defect is lifetime — so this larger change
(and the path-reachability it would reintroduce) is unnecessary. Kept here only
so the reasoning isn't re-litigated.

---

## Part 2 — capability-plane centralization audit ("fix roots, not leaves")

`libservice` already centralizes the *provider* capmode-entry path and the
TZ/NLS preflight correctly. The smell is the *worker* path and the cross-cutting
concerns that leaked into every daemon. Ranked by duplication:

| # | Duplicated workaround | Daemons | Fix — centralize in |
|---|---|---|---|
| 1 | `cap_*_limit` "harden channel/fd" boilerplate (`harden_factory_channel`/`harden_worker_channel` copy-pasted) | 9 | `libservice`: `service_harden_channel(fd, flags)` (XFER_NONE / XFER_ONCE) |
| 2 | Worker capmode entry: `service_worker_protect` → `service_worker_drop_inherited_authority` → `cap_enter` (only remaining raw `cap_enter()`s in daemons) | 6 | `libservice`: `service_worker_enter_capability_mode(flags)` (mirror the provider call; folds in preflight) |
| 3 | "try `service_config_open(CONFIG_FD)` else open path" call-site fallback | 5 | `libservice`: `service_config_open_or_path(name, fallback, &fd)` |
| 6 | Logging sink after `cap_enter`: everyone `openlog`+`syslog()`, but the syslog socket doesn't work in capmode — only bsdlog and bsdnetwork actually solved it | 14 (3 solved) | `libservice`: `service_log()` → `system.Log`, pre-capmode fallback to `syslog` |
| 5 | Casper skip-guard: bsdlog gates `cap_init` on `cap_getmode()`; bsdnetwork/authagentd do not | 3 | `libservice`: `service_in_capability_mode()` helper; gate Casper on it |
| 4 | TZ/NLS preflight — already central; bsdaudit hand-rolls a redundant copy | 1 stray | delete the bsdaudit copy (comes free once #2 lands) |
| 7 | Fail-**hard** on a missing provider: `authagentd` does `err(1,"casper")` (violates the fail-soft rule) | 1 | fix authagentd to fail soft + retry |
| 9 | `setproctitle`: ~6 sandboxed daemons set none → show as `ld-elf.so.1` in `ps` (born-in-capmode exec via rtld) | ~6 | `switchboard`/`libservice` sets a uniform title at launch |
| 8 | Storage consumption | 0 | already clean (`service_storage_open`) |

Top priorities (3+ daemons duplicating the same workaround): **#1 harden
helpers, #2 worker cap_enter, #3 config fallback, #6 log sink.** Note that **#6
(a real `service_log` → system.Log)** is the proper fix for the same
capmode-logging breakage seen killing bsdlog's *error path* in the VM (`/etc/localtime`
`ECAPMODE`, syslog `sendto` `EBADF`).

---

## Part 2 progress (2026-09-05)

Landed + real-plane verified (full fleet green, 0 "exec failed"), commit
`bdb9784b3bc`:
- **#1 `service_harden_fd`** — adopted by bsdlog, bsdnotify, traced, bsdnetwork,
  bsdaudit, bsdcrypto (helper bodies swapped in place; semantics
  unchanged). Rights-limiting helpers (harden_file etc.) left alone.
- **#2 `service_worker_enter_capability_mode`** — adopted at the cleanly-grouped
  worker sites (traced, bsdnetwork, bsdaudit, bsdcrypto, bsdlog/storage).
- **#3 `service_config_open_or_path`** — helper added; found to have narrow
  applicability (most daemons fall back to *in-memory defaults*, not a config
  path, or compute a fallback path that can itself fail — so collapsing would
  regress the CONFIG_FD-only launch). Left those as-is.
- **#4 `logcmp_log`/`logcmp_vlog`** — the capmode-safe syslog sink is built in
  **liblogcmp** (not libservice: liblogcmp already depends on libservice, so the
  reverse is circular). Root helper only; daemon adoption is follow-up.

Remaining Part 2 work:
- **#4 rollout** — switch each daemon's post-`cap_enter` `syslog()` to
  `logcmp_log` (add liblogcmp to LIBADD where missing); per-daemon VM check.
- **#2 leftovers** — two sites where `service_worker_protect` is fused into a
  multi-condition `if` (bsdlog/logcmp.c ~1165, bsdnotify ~783); refactor the
  surrounding `if` first, then adopt.
- **#5** `service_in_capability_mode()` helper + gate Casper on it
  (bsdnetwork/authagentd); **#7** authagentd `err(1,"casper")` → fail-soft;
  **#9** uniform `setproctitle` for born-in-capmode daemons (switchboard-side).

Update (2026-09-05, commit 5ac3304f0cb): #5 helper, #7, and #9's
`service_set_proctitle()` helper landed; fleet re-verified green.  Findings:

- **#9 FIXED (commit 3beceb7f385), root cause verified end-to-end by dtrace.**
  switchboard `cap_enter()`s the child (execute.c:782) *before* `fexecve`
  (execute.c:784) for every non-privileged unit, so a born-in-capability-mode
  daemon's `main()` runs in capability mode from instruction one.
  `setproctitle(3)` sets the ps title by *writing* `kern.proc.args`
  (KERN_PROC_ARGS) via sysctl.  That node already carries `CTLFLAG_CAPWR` and
  its handler restricts the write to the calling process (`PGET_ISCURRENT`), so
  stock Capsicum permits it — the blocker was **our own MAC policy**:
  `sys_mac_system_check_sysctl` in sys/dev/mac_capability/mac_capability_system.c
  gates *every* sysctl write from a capability-mode cred behind
  `SYS_GATE_SYSCTL`, returning EPERM before the handler runs.  (dtrace proof:
  `SYSCTL kern.proc.7 err=1`, handler never entered; reads pass because the hook
  returns 0 when `newptr==NULL`.  Normal non-capmode processes are unaffected —
  the gate only bites capability-mode creds.  Two earlier guesses — capmode
  sysctl framework, then `AT_PS_STRINGS` — were both wrong.)
  **Fix:** exempt exactly `kern.proc.args` from that write gate (the handler's
  `PGET_ISCURRENT` means it can only rename the caller itself — self-contained,
  no tunable touched, every other sysctl write still gated).  Verified on the
  real plane: all born-in-capmode daemons now show their own names in ps
  (`traced`, `bsdlog`, `bsdaudit`, `bsdnotify`, `Crypto: [CRYPTO]…`), zero
  `ld-elf.so.1 -f` processes, fleet still green.
- Build-hygiene: bsdaudit/tests compiles `auditcmp.c` without
  `-I${SRCTOP}/lib/libservice`, so it reads the stale installed `libservice.h`;
  add the include (or reinstall the header) so `make all` incl. tests is clean.

## Sequencing

1. **TZFS mount-lifetime fix** (Part 1) — bsdfilesystem retains the anchoring handle +
   bsdlog holds its storage lease. Userland only. Unblocks bsdlog. Do first.
2. **bsdlog born-in-capmode green** — verify on the real plane (storage delivered,
   worker starts, provider ready).
3. **libservice centralizations** (Part 2), in priority order #1, #2, #3, #6,
   then #5/#4/#7/#9 — each with a clean-VM check.
4. Retire the now-dead per-daemon copies as each centralization lands.

Every step: build → stage → real-plane VM check (the born-in-capmode daemons
only exercise their capmode paths on a live plane).
