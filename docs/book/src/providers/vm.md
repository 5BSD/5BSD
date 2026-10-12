# system.VM (BSDVM)

## What it brokers

BSDVM is the virtual-machine authority on the capability plane. Its
eventual role is to run virtual machines under bhyve(8), which keeps its
name and remains the engine; today it brokers one thing, AF_VSOCK
endpoints, handing sandboxed units listening and connected vsock sockets
that a capability-mode process could not create for itself. 5BSD has it
because vsock addresses are a global namespace: brokering them behind a
label-scoped port window is what lets a born-in-capmode unit talk to a
guest or to another unit without a manifest declaration and without
switchboard doing socket work. The hypervisor, its device models, migration
and nested VMX are covered in [Virtual Machines](../compat/virtual-machines.md);
this chapter covers only the broker and the transport beneath it.
5BSD adds a complete virtio-vsock stack: an `AF_VSOCK` socket domain
(vsock(4), `device vsock` in GENERIC) with stream and seqpacket sockets
addressed by context ID and port, a guest driver (`virtio_vsock`), and a
bhyve host device model with either a Unix-socket backend or native
attachment to the host's own `AF_VSOCK` domain. There is no datagram
support. Host-local traffic uses `VMADDR_CID_LOCAL` (1); `VMADDR_CID_HOST`
is 2 and `VMADDR_CID_ANY` is the wildcard `0xffffffff`. Limits and
counters are under `kern.vsock.*` (`max_connections`,
`max_connections_per_cid`, `buf_default`, `buf_min`, `buf_max`,
`seqpacket_frag_max`, `userspace_providers`, `guest_cid`, `connections`,
`cur_connections`, `tx_*`, `rx_*`).

A plane unit does not call socket(2) for vsock. It calls
`service_vsock_listen(3)`, which opens `system.VM` over the lookup channel
(pulling BSDVM up on demand) and asks BSDVM to bind and listen a host-local
socket in the caller's port window; the reply carries the listening socket
as its single attachment, limited to `CAP_ACCEPT`, `CAP_EVENT`,
`CAP_FSTAT`, `CAP_READ`, `CAP_WRITE`, `CAP_SHUTDOWN`, `CAP_GETSOCKOPT` and
`CAP_SETSOCKOPT`, so accepted sockets are directly usable. A peer that has
learned the concrete (cid, port) calls `service_vsock_connect(3)`; BSDVM
connect(2)s on its behalf and returns the connected socket with data-plane
rights. `service_vsock_list(3)` reports the caller's own window so a unit
can advertise a base port without guessing.

The window is the authority. BSDVM hashes the caller's unforgeable channel
label to a home slot and keeps a registry keyed by the full label,
relocating on collision, so each active label exclusively owns
`[VMD_PORT_BASE + offset * 16, VMD_PORT_BASE + (offset + 1) * 16)` with
`VMD_PORT_BASE = 0x40000000`, 4096 windows and 16 ports per window. The
`index` in Bind is only an index 0 to 15 into that window; a unit
cannot name another's port. Connect scopes nothing: it dials whatever
concrete address the peer advertised, and the listener authorizes its own
clients, exactly the client/server model. A slot is released when the
label's last worker exits.

Why BSDVM is the one ambient provider: its unit sets `user = "root"` and
`ambient = true`. The stated reason (unit file, BSDVM.8, proto header) is
that managing bhyve and the vsock transport needs device access and
global-namespace lookups (`loadat`/`openat` of the tool and its libraries)
that capability mode forbids. Switchboard honors `ambient` only for a
verified base-system bundle and clears it, with a warning, for anything
under `/Capabilities/Apps`. Each client is still served by a pdfork(2)
worker that only ever binds within the base the parent resolved. The
`mac_vsock_provider_check_attach` and `_access` hooks in
`sys/security/mac/mac_socket.c` gate which credential may register or use a
userspace vsock transport for a guest CID.

## Unit

Source: `usr.sbin/BSDVM/capbundle/Bundle.ucl` and `capbundle/bsdvm.ucl`
(installed as `Unit.ucl`).

| Field | Value |
|---|---|
| Wire name | `system.VM` |
| Bundle | `/Capabilities/System/VM.cap` (bundle_id `system.VM`) |
| Unit | `Units/bsdvm.unit` |
| Program | `Units/bsdvm.unit/bin/BSDVM` |
| Activation | `ipc = ["system.VM"]` (on demand) |
| User | `root` |
| Launch mode | ambient (`ambient = true`); readiness is `SVC_OP_READY`, not capability-mode entry |
| Declared gates | none |
| Control | `system` |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 1024`, `nproc = 128`, `core = 0`; `umask = "0022"` |
| Package | `runtime`; tests in `waspnest-tests` |

No `visible` key: SYSTEM-domain only. The unit file's comments still call
the daemon `vmd`; the program and bundle are BSDVM.

## Wire operations

The provider and client use `lib/libvmcmp/vmcmp.fidl`, library `bsd.vm.v1`,
with generated C bindings over native capability channels (see
[FIDL and Capability IPC](../develop/fidl.md)). The schema installs as
`/usr/share/fidl/vmcmp.fidl` and imports `/usr/share/fidl/zx.fidl` for the
descriptor type. No payload carries an identity: every operation is scoped to
the window BSDVM's registry resolved for the accepted session's label.
`lib/libcapsulert/bsdvm_proto.h` keeps the window constants (`VMD_*`, the
unchanged names from before the rename) and the legacy records.

| Method | Request | Reply | Errors |
|---|---|---|---|
| `GetProtocolInfo` | empty | wire version 1 | none |
| `Bind` | `index` (window slot 0..15), `backlog` (0 = default 8, clamped to `SOMAXCONN`) | the listening socket, plus the concrete host-local `cid`/`port` to advertise | `EINVAL` index out of window; `ENOSPC` registry full (4096 labels active); `EBUSY` label already has 128 sessions; `ENAMETOOLONG` label; socket/bind/listen errnos |
| `Connect` | concrete target `cid` (not `VMADDR_CID_ANY`) and `port` | the connected socket | `EINVAL` wildcard CID; connect(2) errnos such as `ECONNREFUSED` |
| `List` | empty | `cid`, `port_base`, `port_limit`, `port_count`, data-only | none |

A session must negotiate before any other method. A method before
negotiation, an unknown method, a malformed, truncated or trailing frame, a
pre-FIDL record or an attached descriptor closes the session without a reply.
Delivered sockets keep their Capsicum limits and `CAP_XFER_ONCE`; the FIDL
transport preserves that state (`fidl_bsd_connection_preserve_sent_inheritance()`).
The `bsd.vm.v1` ordinals and layouts are a compatibility contract;
`usr.sbin/BSDVM/tests/evolution/vmcmp_next.fidl` is the same schema at
`bsd:1` and adds a method at `bsd:2` for the pairing test.

Listeners are bound with `SO_REUSEADDR` so a relaunched unit reclaims its
port deterministically. The `BSDVM` USDT provider fires `vsock-list` with
the client label, window bounds and result, and `request-done` with the
historical `VMD_OP_*` code (0 for negotiation).

## Client library

Header `<vmcmp.h>`, link `-lvmcmp` (`SHLIB_MAJOR 1`, depends on libservice,
the FIDL runtime and pthread; the calls moved out of libservice in October
2026 with the same names). Manual: libvmcmp(3).

| Group | Functions |
|---|---|
| Listen | `service_vsock_listen(ctx, port, backlog, &cid, &port, &fd)` |
| Connect | `service_vsock_connect(ctx, cid, port, &fd)` |
| Discover | `service_vsock_list(ctx, &cid, &port_base, &port_count)` |
| Constants (from the proto header) | `VMD_PORT_BASE`, `VMD_LABEL_WINDOWS`, `VMD_PORTS_PER_LABEL` |

Descriptors come back close-on-exec. `cidp`/`portp` may be NULL. The
`system.VM` session is opened by name once, negotiated, and cached for the
process (a forked child opens its own). A timeout (30 seconds, shortened by an
active `service_budget_begin()`), transport failure or malformed reply drops
the cached session; application errors keep it.

```c
#include <sys/socket.h>
#include <err.h>
#include <stdio.h>
#include <vmcmp.h>

/* Listen on window slot 0 and serve one peer. */
void
serve(struct service_context *ctx)
{
	unsigned cid, port;
	int lfd, cfd;

	if (service_vsock_listen(ctx, 0, 0, &cid, &port, &lfd) == -1)
		err(1, "service_vsock_listen");
	printf("advertise cid %u port %u\n", cid, port);
	cfd = accept(lfd, NULL, NULL);
	if (cfd == -1)
		err(1, "accept");
	/* read/write on cfd */
}
```

The peer side is `service_vsock_connect(ctx, cid, port, &fd)` with the
advertised values. A guest that speaks vsock natively (Linux or 5BSD with
`virtio_vsock`) connects with a plain `socket(AF_VSOCK, SOCK_STREAM, 0)` to
the host CID and the advertised port when the VM's device is attached to
the host `AF_VSOCK` domain; see bhyve(8) and vsock(4).

## Command-line tool

There is no ctl tool for BSDVM. Observe the transport with the `kern.vsock`
sysctls (`sysctl kern.vsock.cur_connections`, `kern.vsock.pcblist`) and the
DTrace scripts under `/usr/share/dtrace/vsock-*`. VM lifecycle is still
driven by bhyve(8) and bhyvectl(8) directly.

## Policy

BSDVM has no policy file. Its rules are structural:

| Rule | Effect |
|---|---|
| SYSTEM-domain only | `system.VM` does not resolve for USER-domain units |
| Label-scoped window | 16 host-local ports per label, exclusively owned while any session is live; Bind takes an index, never a concrete port |
| Connect is unscoped | any concrete (cid, port) except the wildcard CID; the listener is the policy point |
| Per-label caps | 128 concurrent sessions per label; 4096 active labels |
| Ambient only for the base bundle | switchboard ignores `ambient` on an application bundle |
| Kernel hooks | `mac_vsock_provider_check_attach`/`_access` gate transport registration and use per credential |

There is no admin bypass; an ADMIN session gets the same window as any
other session of its label.

## Tests

`usr.sbin/BSDVM/tests` (package `waspnest-tests`, installed under
`/usr/tests/usr.sbin/BSDVM`), compiling `bsdvm.c` with `-DVMD_TESTING`
to expose the registry, validators and worker:

| Program | Kind | Proves |
|---|---|---|
| `registry_test` | pure unit | distinct labels never share a window, same label is deterministic, full registry refused, slot reclaimed on last release and held while a worker remains, Bind/Connect argument validation (on the legacy record shape the worker still uses internally), backlog clamp never negative |
| `provider_test` | plane (real channel, vsock-capable kernel, root) | with the generated client bindings: Bind returns an accept-only listener, Connect reaches a bound listener, List reports only the caller's window, an out-of-window index or wildcard CID is `EINVAL` and keeps the session; hand-built frames (before negotiation, unknown method, truncated header, missing or trailing body, pre-FIDL record, attached descriptor) close the session |
| `evolution_test` | plane | the `bsd:1` libvmcmp client against a `bsd:2` peer, and a `bsd:2` client against the real `bsd:1` worker (the added strict method closes only that session) |
| `lifecycle_test`, `serve_test` | pure unit | worker reaping and window release; the accept loop against a scripted provider |

`latency_bench` (installed beside the tests) times List round trips through
libvmcmp and the real worker for `tools/build/fuchsia/vm-daemons.sh`.

Run with `kyua test -k /usr/tests/usr.sbin/BSDVM/Kyuafile`. The transport
itself is exercised by `tests/sys/kern/waspnest_core` (`vsock_test`,
`vsock_wire_test`, `vsock_iov_test`) and the `vsock_e2e` guest lanes in the
same package.

## Status and gaps

Shipped as a vsock broker; the inventory records Bind, Connect and List as
VM-proven. FIDL `bsd.vm.v1` (October 2026); unit attributes, visibility and
the window rules are unchanged by the migration, and the provider and
libvmcmp ship together (mixed peers fail at negotiation). Gaps: VM launch and lifecycle are not
provided (the "VM authority" is a title, not yet a function); it is the
only ambient provider, and the justification is forward-looking (bhyve
management) rather than required by the vsock role it plays today; Bind is
host-local only, with no brokering of guest-CID listeners; no ctl tool;
the unit file's comments still name `vmd`. Everything else about
virtualization, including the honest live-qualification status of the
device models, migration and nested VMX, is in
[Virtual Machines](../compat/virtual-machines.md).
