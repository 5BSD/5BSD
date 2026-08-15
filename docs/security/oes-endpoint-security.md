# OpenEndpointSecurity (oes) — base integration

`oes(4)` is an endpoint-security event monitoring and authorization framework
for 5BSD, inspired by Apple's Endpoint Security API but built on the 5BSD MAC
framework and the Capsicum capability model. This document describes the
in-base implementation and how it is wired into the tree.

Upstream source: <https://github.com/5BSD/OpenEndpointSecurity>. The code below
is the imported, in-tree copy; the external repository additionally carries the
prose design documents (`DESIGN.md`, `REQUIREMENTS.md`, `ROADMAP.md`, …) and the
out-of-tree deploy/test scripts, which are intentionally not imported.

## Architecture

| Component | Location | Role |
| --- | --- | --- |
| Kernel MAC policy | `sys/security/oes/` | Turns MAC hooks into events; owns `/dev/oes` |
| Userland library | `lib/liboes/` | `liboes(3)` client API (subscribe, mute, read, respond) |
| Tests | `tests/sys/security/oes/` | Integration tests (require the module + root) |
| Man pages | `share/man/man4/oes.4`, `lib/liboes/liboes.3` | |
| Examples + DTrace | `share/examples/oes/` | Reference clients and `.d` scripts |

The kernel module registers a MAC policy (manually, not via `MAC_POLICY_SET`, so
it controls cdev/eventhandler ordering across dynamic load). MAC check hooks and
a few `EVENTHANDLER`s (process fork/exit, mount, kld) generate events. Events
are **AUTH** (from sleepable check hooks; a client may allow/deny and the
operation blocks for the response or the per-client timeout) or **NOTIFY**
(informational, never blocking).

### Clients

Each `open("/dev/oes")` creates an independent client stored in `cdevpriv`, so
clients are **per-open and per-process**. Multiple clients in different
processes may be active simultaneously (bounded by `security.oes.max_clients`,
default 64); every event fans out to all subscribed clients. Each client has
its own subscription bitmap, mute state, mode, timeout, and decision cache.

### Event ABI

`security/oes/oes.h` defines a versioned ABI (`OES_API_VERSION`, currently 4).
Event types are generated from an X-macro table (`oes_event_table.h`): AUTH in
`0x0001`–`0x0FFF`, NOTIFY in `0x1001`–`0x1FFF`. Subscription bitmaps in `oes.h`
must stay in sync with the table.

### DTrace

The module defines an `oes` SDT provider with probes for authorization outcomes
(`auth-allow`, `auth-deny`, `auth-timeout`), event flow (`event-enqueue`,
`event-drop`), and the decision cache (`cache-hit`, `cache-miss`). Scripts live
in `share/examples/oes/dtrace/`.

## The `mac_vnode_check_close` hook

Apple ES delivers a `NOTIFY_CLOSE` event, but the 5BSD MAC framework had no close
hook. This integration adds `mac_vnode_check_close(cred, vp)`:

* `sys/security/mac/mac_policy.h` — `mpo_vnode_check_close_t` typedef + ops entry
* `sys/security/mac/mac_framework.h` — prototype
* `sys/security/mac/mac_vfs.c` — sleepable wrapper (`ASSERT_VOP_LOCKED`)
* `sys/kern/vfs_vnops.c` — call site in `vn_close1()` before `VOP_CLOSE()`

A close cannot be denied, so the call site invokes the hook as `(void)` and
`oes(4)` treats `NOTIFY_CLOSE` as notify-only. Verified by a full GENERIC kernel
build.

Note: three hooks that OES's upstream documentation lists as "not implementable"
already exist in 5BSD (`mac_kld_check_unload`, `mac_vnode_check_truncate`,
`mac_mount_check_unmount`); only `mac_vnode_check_close` was genuinely missing.

## Build wiring

* `sys/conf/files` — `security/oes/*.c optional oes`
* `sys/conf/options` — `OES`
* `sys/modules/oes/Makefile`, `sys/modules/Makefile` — loadable module
* `lib/Makefile` — `liboes`
* `tests/sys/security/{Makefile,oes/}`, `tests/sys/Makefile` — test suite
* `share/man/man4/Makefile`, `share/examples/Makefile` — man page, examples
* pkgbase: `PACKAGE=oes` (lib), `PACKAGE=oes-tests` (tests), with
  `release/packages/ucl/oes-all.ucl` and `oes-tests-all.ucl`

## Review notes / open items

* **MODULE ABI (fixed):** the module hardcoded `MODULE_DEPEND(oes,
  kernel_mac_support, 6, 6, 6)` while `MAC_VERSION` is 9, so it would have
  refused to load. Changed to depend on `MAC_VERSION` exactly.
* **Test harness (fixed):** `TEST_FAIL`/`ASSERT_MSG` only printed and the process
  still exited 0 — a failing test scored as a pass. The harness now records
  failures and forces a non-zero exit.
* **Unique process identity (open):** `oes` currently identifies processes by raw
  `p_pid`, which is reuse-prone. `mac_capability` exposes
  `mac_capability_proc_nonce(cred)` (a stable per-credential program identity);
  `oes` should use it for tokens rather than PID. Not yet implemented.
* **Live qualification (open):** loading the module and running the test suite
  under `kyua` on a VM, plus KASAN/KUBSAN and the DTrace scripts, is pending.

## Testing

Tests are plain C integration tests in `tests/sys/security/oes/` that open
`/dev/oes`; they require the `oes` module loaded and root. The shared harness
(`test_common.h`) exits non-zero on any failed assertion. `liboes` builds clean
under `-fsanitize=address,undefined`.
