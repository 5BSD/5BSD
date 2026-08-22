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

The `oesd` reference broker creates a root-only `0600` Unix socket and verifies
peer credentials before delegating a Capsicum-restricted passive descriptor.
Broader delegation requires an explicit local authorization policy.

The kernel module registers a MAC policy (manually, not via `MAC_POLICY_SET`, so
it controls cdev/eventhandler ordering across dynamic load). MAC check hooks and
a few `EVENTHANDLER`s (process fork/exit, mount, kld) generate events. Events
are **AUTH** (from sleepable check hooks; a client may allow/deny and the
operation blocks for the response or the message deadline) or **NOTIFY**
(informational, never blocking).

### Clients

Each `open("/dev/oes")` creates an independent client stored in `cdevpriv`, so
clients are **per-open and per-process**. Multiple clients in different
processes may be active simultaneously (bounded by `security.oes.max_clients`,
default 64); every event fans out to all subscribed clients. Each client has
its own subscription bitmap, mute state, mode, deadline policy, and decision
cache.

### Event ABI

`security/oes/oes.h` defines a versioned pre-1.0 API (`OES_API_VERSION`,
currently 1).
OES is intentionally LP64-only: the public header rejects 32-bit kernel and
userspace builds, and the ioctl structures contain native 64-bit pointers and
`size_t` counts without compat32 translations.
Event types are generated from an X-macro table (`oes_event_table.h`): AUTH in
`0x0001`–`0x0FFF`, NOTIFY in `0x1001`–`0x1FFF`. Subscription bitmaps in `oes.h`
must stay in sync with the table.

Message v1 uses fixed-width timestamps and event fields, records the fixed
structure size, and permits additive future message versions. Each delivered
message carries per-client global and per-event sequence numbers. A NOTIFY
event derived from an AUTH event is queued only after authorization completes
and carries the applied allow/deny result in `em_result` with
`OES_MSG_FLAG_AUTH_RESULT` set.

The v1 API includes descendants-scoped clients, matching Apple's
`es_new_descendants_client` visibility model: the root receives NOTIFY events,
its complete descendant subtree receives AUTH and NOTIFY events, and unrelated
processes are filtered before authorization. The scope is selected before mode
or subscription configuration. FreeBSD still requires permission to open
`/dev/oes`; OES does not have Apple's code-signing entitlement authority.

It also includes per-AUTH-event deadline bounds. Every client may cap a deadline;
descendants clients may also establish a minimum. Setting a minimum above the
current maximum raises the effective maximum, and lowering a maximum below the
current minimum lowers the minimum. A zero SET value removes that override and
returns the event to the client's inherited default deadline. A client's
`OES_DEADLINE_MISS_FAIL_CLOSED` setting also applies when its AUTH queue is
full, providing fail-closed behavior for both missed and dropped requests.
Source-process flags now also include `EP_FLAG_OES_CLIENT`, the portable
equivalent of Apple's `es_process_t.is_es_client`; `oeslogger` emits it as
`is_oes_client`.

### Apple macOS 27 API delta

Apple's macOS 27 Endpoint Security API also adds deadline-miss modes,
per-event deadline minimum/maximum controls, `es_sync_client`, exec entitlement
retrieval, and bootstrap/XPC/TCC events. OES implements fail-open/fail-closed
deadline-miss policy and portable deadline bounds. It does not expose Apple's
`KILL` deadline-miss mode yet.

`es_sync_client` synchronizes Apple's private asynchronous handler queue. OES
does not own a callback queue: reads and `oes_dispatch` execute on the caller's
thread, while event enqueueing is already synchronous. A same-named API would
therefore promise semantics OES cannot provide without first adding an owned
asynchronous delivery queue.

Exec entitlements and the new code-signing fields remain intentionally
deferred until OES has a signing authority. Bootstrap service, XPC, and TCC
events describe macOS Mach/launchd/TCC facilities with no truthful FreeBSD MAC
event equivalent; OES does not publish placeholder events for them.

Default process/path mutes remain ordinary per-client state. `liboes` exposes
bulk unmute helpers, and `oeslogger -n` clears both kernel-configured defaults
and the logger's normal self and `/dev/` noise filters. `oeslogger -m path`
adds repeatable prefix filters, while `-d` uses descendants scope.

Decision-cache entries are invalidated on content and metadata mutations;
namespace mutations conservatively clear all client caches. Cache lookup is
limited to event types whose security-relevant parameters are represented in
the key.

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
  failures and forces a non-zero exit. It also retains independent batched-read
  state per descriptor and measures timeouts with the monotonic clock, so
  alternating multi-client reads cannot lose messages or expire by event
  count.
* **Unique process identity:** process tokens combine PID with process start
  time, and execution IDs survive fork but change at exec. This prevents simple
  PID-reuse collisions without making OES depend on another MAC policy.
* **Live qualification (open):** loading the module and running the test suite
  under `kyua` on a VM, plus KASAN/KUBSAN and the DTrace scripts, is pending.

## Testing

Tests are plain C integration tests in `tests/sys/security/oes/` that open
`/dev/oes`; they require the `oes` module loaded and root. The shared harness
(`test_common.h`) exits non-zero on any failed assertion. Unit tests cover the
message ABI, bounded metadata helpers, interleaved multi-descriptor batches,
batched library reads (including corrupt later messages and fragments), and
scope/deadline API errors without requiring the module. Integration coverage
includes deadline bound transitions, actual deadline selection, invalid and
late responses, queue-saturation fail-closed behavior, and separate
outside/root/child processes for descendants visibility and isolation.
`liboes` and the batch-reader tests build clean under
`-fsanitize=address,undefined`.
