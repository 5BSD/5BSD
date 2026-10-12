# system.Trace (BSDTrace)

## What it brokers

BSDTrace is the DTrace descriptor broker. It is the only process that opens
`/dev/dtrace`; everyone else who traces receives a rights-limited consumer
descriptor from it and builds a libdtrace handle with dtrace_fdopen(3).
5BSD has it so that tracing, which reads arbitrary kernel and process
state, is no longer tied to being root: the right to trace is a software attribute
plus an allow-list entry, held by a label, not a uid. It ships in the
`bsdtrace-provider` package together with tracectl(8) and is described by
BSDTrace(8).
One naming point up front: bsdtrace(8), lowercase, in the `bsdtrace`
package, is the Intel Processor Trace execution tracer built on hwt(4). It
has nothing to do with this provider. This chapter is about BSDTrace, the
`system.Trace` broker. The wider observability story (bsdinstruments, hwstat,
the SDT and USDT catalog) is in [Observability](../operations/observability.md)
and [Logging, Audit and Trace](../plane/logging-audit-trace.md).

A client opens `system.Trace` over its lookup channel, learns during protocol negotiation whether it may receive a descriptor, and asks `Open` for one independently opened DTrace consumer
descriptor. BSDTrace forks a capability-mode worker per connection; the
worker checks the caller's switchboard-authenticated label against the
allow-list and, if listed, opens `/dev/dtrace` through the delivered `/dev`
directory descriptor with openat(2), limits the new descriptor to the ioctl
set libdtrace needs, marks it close-on-fork, close-on-exec and transferable
exactly once, and sends it as the reply's single attachment. Unlisted
callers get `EACCES` before the consumer device is touched.

Reaching the name requires the `system.trace.client` attribute. The provider
publishes `ipc = [{ name = "system.Trace"; requires = ["system.trace.client"] }]`.
Approved client software declares that attribute in its own manifest; a caller
without it sees `ENOENT`. This is independent of the UNIX user executing the
client. See [Software attributes](../plane/attributes.md).

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
The supervisor admits at most 256 workers globally and 16 per authenticated
client label, holds their process descriptors,
and on quiesce stops admission, gives workers five seconds after SIGTERM,
then kills stragglers before acknowledging switchboard.

## Unit

Source: `usr.sbin/BSDTrace/capbundle/Bundle.ucl` and
`capbundle/bsdtrace.ucl` (installed as `Unit.ucl`).

| Field | Value |
|---|---|
| Wire name | `system.Trace` |
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

The provider and client use `lib/libtracecmp/tracecmp.fidl`, library
`bsd.trace.v1`, with generated C bindings over native capability channels
(see [FIDL and Capability IPC](../develop/fidl.md)). The schema installs as
`/usr/share/fidl/tracecmp.fidl` and imports `/usr/share/fidl/zx.fidl` for the
descriptor type. No payload carries an identity or a grant: the session's
switchboard-stamped rights and the allow-list decide.

| Method | Request | Reply | Errors |
|---|---|---|---|
| `GetProtocolInfo` | empty | wire version 1 and `features`; `TRACECMP_FEATURE_RAW_DTRACE_FD` is set only for a listed label or an ADMIN session whose consumer is open | none |
| `Open` | empty | the consumer descriptor | `EACCES` label not listed; `EALREADY` a second `Open` on one session (one-shot); device errors such as `ENXIO` |
| `Stats` | empty | `opened`, `rejected` | none |

A session must negotiate before `Open` or `Stats`. A method before
negotiation, an unknown method, a malformed, truncated or oversized frame, a
pre-FIDL record or an attached descriptor ends the session without a reply
and without delivering a consumer (the `bsdtrace` provider's `request-done`
probe still fires with opcode `UINT32_MAX` for a frame the bindings refused).
The delivered descriptor keeps the provider's hardening (transfer once,
close-on-exec locked); the client then locks it against further transfer and
fork. The worker times out an idle session after `TRACECMP_CLIENT_TIMEOUT_MS`
(30 s); the client bounds each call by the same 30 s, shortened by an active
`service_budget_begin()`. The `bsd.trace.v1` ordinals and layouts are a
compatibility contract; `usr.sbin/BSDTrace/tests/evolution/tracecmp_next.fidl`
is the same schema at `bsd:1` and adds a method at `bsd:2` for the pairing
test. `tracecmp_protocol.h` keeps the constants and the pre-FIDL records for
compatibility only.

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
| Software attribute | Client bundle `Unit.ucl` | `system.trace.client` must be held for `system.Trace` to resolve at all |
| Allow-list | `Config/bsdtrace.allow` in the unit's delivered Config directory, opened with `service_config_open(3)` | one label per line; only a listed label receives a consumer descriptor |

The allow-list file: `#` comments and surrounding whitespace are ignored; a
label is 1 to 63 characters from `[A-Za-z0-9._-]`, may not start or end
with `.` and may not contain `..`; no wildcards; duplicates are an error;
the file must be a regular file owned by the daemon's effective user, not
group- or world-writable, at most 64 KiB, with no NUL bytes, and is opened
without following symlinks. An absent Config directory or file is an empty
default-deny policy; an unsafe file is a fatal configuration error. The
base system does not install a `Config/bsdtrace.allow`, so a fresh install
denies every `Open` until an operator adds one. The policy names who may
trace, not what they may trace. An ADMIN session on the channel is granted
the raw-descriptor feature without a listing.

## Tests

| Location | Programs | Proves |
|---|---|---|
| `usr.sbin/BSDTrace/tests` (`bsdtrace-provider-tests`, `/usr/tests/usr.sbin/BSDTrace`) | `policy_test` | default deny, exact-label matching (no prefix or child match), wildcard, malformed, duplicate and oversized entries rejected, unsafe and over-size files rejected |
| same | `session_test` | over the generated bindings: authorized descriptor is one-shot, authorization and device failures, unauthorized `Open` denied without touching the consumer, authorized label receives the fd, worker descriptors cross exactly one fork; with hand-built frames: an attached descriptor, a method before negotiation, an unknown method, a truncated frame, trailing bytes and a pre-FIDL record each end the session |
| same | `evolution_test` | the `bsd:1`/`bsd:2` schema pairing in both directions |
| same | `bundle_test.sh` | the built bundle verifies with `switchboardctl verify` and carries (or, without DTrace, lacks) a `.SUNW_dof` section |
| `lib/libtracecmp/tests` (`libtracecmp-tests`) | `tracecmp_test`, `client_lifecycle_test` | retained legacy record ABI, API and buffer tuning; against a scripted `bsd.trace.v1` provider over real channels: concurrent sessions, discovery and peer failures, feature, version and reply validation (including a pre-FIDL provider), delegated fd not inherited, repeated open/close, stats counters |
| `usr.sbin/tracectl/tests` | `tracectl_test.sh` | valid policy, empty is default-deny, policy errors, argument handling |

Run with `kyua test -k /usr/tests/usr.sbin/BSDTrace/Kyuafile` and the
matching Kyuafiles under `/usr/tests/lib/libtracecmp` and
`/usr/tests/usr.sbin/tracectl`.

## Status and gaps

Shipped; FIDL `bsd.trace.v1` (October 2026; unit, attributes and policy unchanged; provider and libtracecmp ship together); renamed from `traced`; policy file spelling reconciled across
BSDTrace.8, libtracecmp.3 and tracectl.8. Gaps recorded in the inventory:
the policy is coarse (who, not what); the delegated descriptor cannot bound
D programs, so untrusted consumers still need a broker-owned query and
aggregation protocol that does not exist; fasttrap (pid provider) is
unavailable over a delegated descriptor; tracectl has no live verbs; the
allow-list is not shipped, so tracing is off by default until configured.
