# system.Trace (BSDTrace)

## What it brokers

BSDTrace is the DTrace descriptor broker. It is the only process that opens
`/dev/dtrace`; everyone else who traces receives a rights-limited consumer
descriptor from it and builds a libdtrace handle with dtrace_fdopen(3).
5BSD has it so that tracing, which reads arbitrary kernel and process
state, is no longer tied to being root: the right to trace is an anointment
plus an allow-list entry, held by a label, not a uid. It ships in the
`bsdtrace-provider` package together with tracectl(8) and is described by
BSDTrace(8).
One naming point up front: bsdtrace(8), lowercase, in the `bsdtrace`
package, is the Intel Processor Trace execution tracer built on hwt(4). It
has nothing to do with this provider. This chapter is about BSDTrace, the
`system.Trace` broker. The wider observability story (bsdinstruments, hwtlm,
the SDT and USDT catalog) is in [Observability](../operations/observability.md)
and [Logging, Audit and Trace](../plane/logging-audit-trace.md).

A client opens `system.Trace` over its lookup channel, negotiates version
1.0.0 with HELLO, and asks OPEN for one independently opened DTrace consumer
descriptor. BSDTrace forks a capability-mode worker per connection; the
worker checks the caller's switchboard-authenticated label against the
allow-list and, if listed, opens `/dev/dtrace` through the delivered `/dev`
directory descriptor with openat(2), limits the new descriptor to the ioctl
set libdtrace needs, marks it close-on-fork, close-on-exec and transferable
exactly once, and sends it as the reply's single attachment. Unlisted
callers get `EACCES` before the consumer device is touched.

Reaching the name at all requires the `system.trace.client` anointment: the
unit's activation entry is
`ipc = [{ name = "system.Trace"; requires = ["system.trace.client"] }]`,
so a session that does not hold it sees `ENOENT`, the same as for an
unknown name. The shipped `/Capabilities/Config/principal-policy.ucl` gives
the admin principal `anointments = ["*"]`; an operator can be granted only
`system.trace.client` to trace without being an administrator. See
[Anointments and Principal Policy](../plane/anointments.md).

What the descriptor can and cannot do is the honest core of this chapter.
Capsicum rights and the ioctl allow-list bound which operations a client
may issue on the consumer; they cannot express which probes, predicates,
actions or targets a D program may use, nor cap buffer allocation beyond
the kernel's limits. Raw DTrace authority is therefore administrator-class
by construction. `tracecmp_dtrace_open()` applies bounded RAM- and
CPU-scaled buffer defaults on the client side, but an authorized client can
change them. A provider-owned query and aggregation protocol for untrusted
consumers is still to be built.
Delegations and denials are audited through BSM and fire the `bsdtrace`
USDT provider (`session-start`, `session-end`, `delegate`, `reject`). A
session that has not asked for its descriptor within 30 seconds is closed.
The supervisor admits at most 256 workers, holds their process descriptors,
and on quiesce stops admission, gives workers five seconds after SIGTERM,
then kills stragglers before acknowledging switchboard.

## Unit

Source: `usr.sbin/BSDTrace/capbundle/Bundle.ucl` and
`capbundle/bsdtrace.ucl` (installed as `Unit.ucl`).

| Field | Value |
|---|---|
| Wire name | `system.Trace`, interface version `1.0.0` |
| Bundle | `/Capabilities/System/Trace.cap` (bundle_id `system.Trace`) |
| Unit | `Units/bsdtrace.unit` |
| Program | `Units/bsdtrace.unit/bin/BSDTrace` |
| Activation | `boot = true`; `ipc = [{ name = "system.Trace"; requires = ["system.trace.client"] }]` |
| User | `root` (opening and operating a consumer, and committing its BSM records, still need kernel privilege) |
| Launch mode | born in capability mode (`ambient` absent); `/dev` delivered as a directory descriptor |
| Declared gates | none |
| Control | `system` |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 1024`, `nproc = 64`, `core = 0`; `umask = "0077"` |
| Package | `bsdtrace-provider` (with tracectl) |

## Wire operations

Protocol header: `lib/libtracecmp/tracecmp_protocol.h`. Every message
starts with a 16-byte `struct tracecmp_msg { magic, version, opcode, flags,
status }`; magic is `TRACECMP_MAGIC` (`0x54524343`, "TRCC"), version is
`TRACECMP_ABI_VERSION` (1), flags must be zero, and a message is at most
`TRACECMP_MAX_MESSAGE` (256) bytes. Roles are REQUEST, REPLY and EVENT.

| Op | Request | Reply | Errors |
|---|---|---|---|
| `TRACECMP_OP_HELLO` (1) | header only | `tracecmp_hello_reply { version, features }`; `TRACECMP_FEATURE_RAW_DTRACE_FD` is set only for a listed label or an ADMIN session | `EPROTO` on a bad header; version mismatch fails the handshake |
| `TRACECMP_OP_OPEN` (2) | header only | header with one attachment in slot `TRACECMP_OPEN_FD_DTRACE`: the consumer descriptor | `EACCES` label not listed; `EPROTO` malformed or unexpected attached descriptor (poisons the session); a second OPEN on one session is refused (one-shot) |
| `TRACECMP_OP_STATS` (3) | header only | `tracecmp_stats { opened, rejected }` | `EPROTO` |

The client side times out after `TRACECMP_CLIENT_TIMEOUT_MS` (30 s).

## Client library

Header `<tracecmp.h>` (which includes `<dtrace.h>` and the protocol header),
link `-ltracecmp`; libtracecmp(3).

| Group | Functions |
|---|---|
| Handle construction (normal use) | `dtrace_hdl_t *tracecmp_dtrace_open(int flags, int *errp)` |
| Raw descriptor | `int tracecmp_open(int *dtracefd)` |
| Counters | `int tracecmp_stats(struct tracecmp_stats *)` |
| libdtrace entry it wraps | `dtrace_hdl_t *dtrace_fdopen(int fd, int version, int flags, int *errp)` in `<dtrace.h>`, dtrace_fdopen(3) |

`tracecmp_dtrace_open()` connects, negotiates, requests the descriptor,
calls dtrace_fdopen(3) and closes the intermediate fd; the handle owns a
duplicate. `DTRACE_O_NODEV` is rejected. Defaults: automatic buffer resize,
switch buffers, 250 ms switch rate, principal and aggregation buffers scaled
by RAM and CPU count and capped at 32 MiB per CPU, dynamic variables capped
at 64 MiB, 4 MiB fallback when topology cannot be read. Call
`dtrace_setopt()` before enabling probes to change them. dtrace_fdopen(3)
itself never opens provider device paths, never loads modules and cannot
use fasttrap; provider modules must already be loaded.

```c
#include <err.h>
#include <stdio.h>
#include <tracecmp.h>

int
main(void)
{
	dtrace_hdl_t *dtp;
	int error;

	dtp = tracecmp_dtrace_open(0, &error);
	if (dtp == NULL)
		errx(1, "tracecmp_dtrace_open: %s",
		    dtrace_errmsg(NULL, error));
	printf("consumer ready\n");
	dtrace_close(dtp);
	return (0);
}
```

Beyond that point the program is ordinary libdtrace code: `dtrace_program_strcompile`, `dtrace_program_exec`, `dtrace_go`, `dtrace_work`.

## Command-line tool

tracectl(8) validates a policy file with the daemon's own parser:

```
# tracectl configtest /Capabilities/System/Trace.cap/Units/bsdtrace.unit/Config/bsdtrace.allow
/Capabilities/System/Trace.cap/Units/bsdtrace.unit/Config/bsdtrace.allow: valid (labels=2, default=explicit-allow)
```

An empty or missing file prints `labels=0, default=deny`.

With no argument it reads `/etc/bsdtrace.allow`, which is only tracectl's
default input; the daemon never consults that path. It rejects wildcard,
duplicate, malformed and oversized entries and treats a missing or empty
file as valid default-deny. There is no verb that talks to the running
daemon; `tracecmp_stats()` is the programmatic way to read its counters.

## Policy

Two layers gate a trace client.

| Layer | Where | Effect |
|---|---|---|
| Anointment | `/Capabilities/Config/principal-policy.ucl` | `system.trace.client` must be held for `system.Trace` to resolve at all |
| Allow-list | `Config/bsdtrace.allow` in the unit's delivered Config directory, opened with `service_config_open(3)` | one label per line; only a listed label receives a consumer descriptor |

The allow-list file: `#` comments and surrounding whitespace are ignored; a
label is 1 to 63 characters from `[A-Za-z0-9._-]`, may not start or end
with `.` and may not contain `..`; no wildcards; duplicates are an error;
the file must be a regular file owned by the daemon's effective user, not
group- or world-writable, at most 64 KiB, with no NUL bytes, and is opened
without following symlinks. An absent Config directory or file is an empty
default-deny policy; an unsafe file is a fatal configuration error. The
base system does not install a `Config/bsdtrace.allow`, so a fresh install
denies every OPEN until an operator adds one. The policy names who may
trace, not what they may trace. An ADMIN session on the channel is granted
the raw-descriptor feature without a listing.

## Tests

| Location | Programs | Proves |
|---|---|---|
| `usr.sbin/BSDTrace/tests` (`bsdtrace-provider-tests`, `/usr/tests/usr.sbin/BSDTrace`) | `policy_test` | default deny, exact-label matching (no prefix or child match), wildcard, malformed, duplicate and oversized entries rejected, unsafe and over-size files rejected |
| same | `session_test` | authorized descriptor is one-shot, authorization and device failures, unexpected descriptor poisons the session, unauthorized OPEN denied without touching the consumer, authorized label receives the fd, worker descriptors cross exactly one fork |
| same | `bundle_test.sh` | the built bundle verifies with `switchboardctl verify` and carries (or, without DTrace, lacks) a `.SUNW_dof` section |
| `lib/libtracecmp/tests` (`libtracecmp-tests`) | `tracecmp_test`, `client_lifecycle_test` | header ABI, validation, API and buffer tuning; concurrent sessions, discovery and peer failures, feature and attachment validation, delegated fd not inherited, repeated open/close, stats counters, all against a fake service |
| `usr.sbin/tracectl/tests` | `tracectl_test.sh` | valid policy, empty is default-deny, policy errors, argument handling |

Run with `kyua test -k /usr/tests/usr.sbin/BSDTrace/Kyuafile` and the
matching Kyuafiles under `/usr/tests/lib/libtracecmp` and
`/usr/tests/usr.sbin/tracectl`.

## Status and gaps

Shipped; renamed from `traced`; policy file spelling reconciled across
BSDTrace.8, libtracecmp.3 and tracectl.8. Gaps recorded in the inventory:
the policy is coarse (who, not what); the delegated descriptor cannot bound
D programs, so untrusted consumers still need a broker-owned query and
aggregation protocol that does not exist; fasttrap (pid provider) is
unavailable over a delegated descriptor; tracectl has no live verbs; the
allow-list is not shipped, so tracing is off by default until configured.
