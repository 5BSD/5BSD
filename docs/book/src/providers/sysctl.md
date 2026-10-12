# system.Sysctl (BSDSysctl)

## What it brokers

BSDSysctl is the `system.Sysctl` provider: it reads and, policy permitting, writes kernel sysctl(3) variables by name on behalf of a capability-mode unit. In capability mode `__sysctl(2)` is confined to nodes flagged `CTLFLAG_CAPRD`/`CTLFLAG_CAPWR`, which excludes almost the entire MIB tree, so a sandboxed process cannot read `kern.ostype` for itself and cannot write anything. Instead it holds a `system.Sysctl` channel, names the variable, and the broker performs the operation after a per-label policy check. There is no Casper `cap_sysctl` helper anywhere in the path.

The broker is itself born in capability mode. What lets it reach the tree is a `SYS_GATE_SYSCTL` "system" gate token, minted by [Capsule](../plane/capsule.md) from the unit's veriexec-verified manifest declaration `capabilities { system = ["sysctl"]; }`, delivered by switchboard and authorized with `service_provider_authorize_capabilities(3)`. A `Get` or `Set` goes through `service_system_sysctl(3)`, which the kernel executes in kernel context after verifying the held claim (`SCTL_GATED` in `sys/kern/kern_sysctl.c`). The raw syscall stays confined; the gate claim replaces `PRIV_SYSCTL_WRITE`, and the daemon runs as the unprivileged `capability` user. The token is close-on-fork, so BSDSysctl multiplexes every client in the single token-holding process (one kqueue reactor, at most 128 sessions and 16 per label, one bounded dispatch batch per ready session) rather than using `pdfork(2)` workers, with a 30 second idle deadline per session. See [System Gates](../capability/system-gates.md) for the gate mechanism.

The same manifest also declares `isolate = ["kern.maxfiles"]`. A non-empty `isolate` list makes switchboard ask Capsule to mint the SYSCTL token scoped to exactly those OIDs, and BSDSysctl becomes the sole writer of them outside Capsule: a direct `__sysctl(2)` write to an isolated OID from any other process is denied by the mac_capability sysctl hook, whatever its uid. The isolate set governs only which tunables are protected from other writers; what BSDSysctl may touch through the gate is bounded separately by `sysctl.conf`. The design is `docs/book/src/capability/system-gates.md`.

## Unit

Source: `usr.sbin/BSDSysctl/capbundle/bsdsysctl.ucl` and `Bundle.ucl`.

| Field | Value |
|---|---|
| Wire name | `system.Sysctl` |
| Bundle | `/Capabilities/System/Sysctl.cap` (`bundle_id = "system.Sysctl"`) |
| Program | `/Capabilities/System/Sysctl.cap/Units/bsdsysctl.unit/bin/BSDSysctl` |
| Unit | `bsdsysctl` |
| User | `capability` |
| Launch | born in capability mode; `activation { boot = true; ipc = ["system.Sysctl"]; }` |
| Control | `core` |
| Gates | `capabilities { system = ["sysctl"]; isolate = ["kern.maxfiles"]; }` |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 1024; nproc = 128; core = 0`; `umask = "0077"` |
| Config | `Units/bsdsysctl.unit/Config/sysctl.conf` |

## Wire operations

The provider and client use `lib/libsysctlcmp/sysctlcmp.fidl`, library
`bsd.sysctl.v1`, with generated C bindings over native capability channels
(see [FIDL and Capability IPC](../develop/fidl.md)); the schema installs as
`/usr/share/fidl/sysctlcmp.fidl`. Names are at most 255 bytes and may not
contain a NUL (`EINVAL`); values are at most 8192 bytes. No payload carries an
identity: the session label and `sysctl.conf` decide.

| Method | Request | Reply | Errors |
|---|---|---|---|
| `GetProtocolInfo` | empty | wire version 1 | none |
| `Get` | name | raw value bytes | `EPERM` name outside read policy; `ENOENT` no such OID; `ENOMEM` value exceeds 8192 |
| `Set` | name and value as text | empty | `EPERM` outside write policy; `EINVAL` text does not parse for the OID's type, or NODE/OPAQUE; `ENOMEM`; kernel errors |
| `OidFormat` | name | `{ uint32 kind; fmt[] }` bytes (`CTLTYPE` low bits, `CTLFLAG_*` high bits, NUL-terminated printf-style format) | `EPERM` read policy |
| `Describe` | name | NUL-terminated description (as `sysctl -d`) | `EPERM` read policy |
| `Next` | cursor name (empty = root) | next permitted name, NUL-terminated | `ENOENT` past the last permitted variable; `ENOMEM` |
| `ListInterfaces` | empty | up to 256 interfaces: index, `IFF_*` flags, MTU, link state, name (no addresses or counters) | `EPERM` unless the label may read `net.routetable` |

A session must negotiate before any other method. A method before
negotiation, an unknown method, a malformed, truncated or oversized frame, a
pre-FIDL record or an attached descriptor closes that session without a reply
(the other sessions are unaffected). The `Set` value is text; the broker looks
up the OID's kind, encodes the text to the native binary width (int, uint,
long, s8 through u64, or a string) and then performs the gated write, so a
client never has to know the kernel type. `Next` walks `CTL_SYSCTL_NEXT` and
skips every name the label may not read, so enumeration never reveals a name
outside the caller's read policy; the cursor itself is not gated. The
`bsdsysctl` DTrace provider fires `request-start` and `request-done` (label,
opcode, bytes, status, transport error) around every method with the
historical opcodes (0 negotiation, 1 Get, 2 Set, 3 OidFormat, 4 Describe,
5 Next, 6 ListInterfaces), and with opcode 65535 and `EPROTO` for a frame the
bindings refused. The `bsd.sysctl.v1` ordinals and layouts are a
compatibility contract; `usr.sbin/BSDSysctl/tests/evolution/sysctlcmp_next.fidl`
is the same schema at `bsd:1` and adds a method at `bsd:2` for the pairing
test. `sysctlcmp_protocol.h` keeps the limits, the interface record and the
pre-FIDL records (compatibility only).

## Client library

Header `<sysctlcmp.h>` (installs `sysctlcmp.h`, `sysctlcmp_protocol.h` and the legacy `sysctlcmp_server.h`); link with `-lsysctlcmp` (`SHLIB_MAJOR 1`, depends on libservice and the FIDL runtime). Manual: libsysctlcmp(3).

| Group | Functions |
|---|---|
| Session | `sysctlcmp_client_open`, `sysctlcmp_client_create`, `sysctlcmp_client_close` |
| Read | `sysctlcmp_get(client, name, buf, &len)`, `sysctlcmp_oidfmt(client, name, &kind, fmt, &fmtlen)`, `sysctlcmp_describe(client, name, buf, &len)` |
| Write | `sysctlcmp_set(client, name, value, len)` |
| Enumerate | `sysctlcmp_next(client, name, buf, &len)`, `sysctlcmp_interfaces(client, out, &count)` |

`sysctlcmp_get()` follows sysctlbyname(3): `buf == NULL` with `*lenp == 0` queries the size; a value that does not fit fails with `ENOMEM` and `*lenp` holds the needed size, except that a value larger than the transport cap fails with `ENOMEM` and leaves `*lenp` unchanged. Values are opaque bytes; the caller interprets them with the kind from `sysctlcmp_oidfmt()`. The first call checks the wire version (`EPROTONOSUPPORT` for an incompatible provider). Each call has a five-second deadline, shortened by an active `service_budget_begin()`; a timeout cancels just that call (`ETIMEDOUT`) and the session stays usable, as with the earlier libservice transport. A transport failure or malformed reply (`EPROTO`, including an unterminated or empty string) makes the client terminal; close it and open a new one. Application errors keep it. A client may be shared between threads; its calls are serialized.

```c
#include <sysctlcmp.h>
#include <err.h>
#include <stdio.h>

int
ncpu(void)
{
	struct sysctlcmp_client *sc;
	int n;
	size_t len = sizeof(n);

	if (sysctlcmp_client_open(&sc) == -1)
		err(1, "system.Sysctl");
	if (sysctlcmp_get(sc, "hw.ncpu", &n, &len) == -1)
		err(1, "hw.ncpu");	/* EPERM if not in this label's read list */
	sysctlcmp_client_close(sc);
	return (n);
}
```

## Command-line tool

sysctlcmpctl(8) is the operator front end for the same five verbs, subject to the invoking label's policy like any other client.

| Verb | Example | Output shape |
|---|---|---|
| `get name` | `sysctlcmpctl get kern.ostype` | `FreeBSD` (strings printed as text, 4- and 8-byte integers as numbers, anything else as hex) |
| `set name value` | `sysctlcmpctl set net.inet.tcp.msl 15000` | exit status; `EPERM` unless the label's `write` list covers it |
| `fmt name` | `sysctlcmpctl fmt hw.ncpu` | `kind=0x<flags> fmt=I` (the kind word as sysctl(9) oidfmt reports it) |
| `descr name` | `sysctlcmpctl descr hw.physmem` | the description line |
| `list [start-name]` | `sysctlcmpctl list kern` | one permitted name per line, in tree order, until `ENOENT` |

Under the shipped default policy a shell that resolves `system.Sysctl` sees exactly eight names from `list` and every `set` fails with `EPERM`.

## Policy

`/Capabilities/System/Sysctl.cap/Units/bsdsysctl.unit/Config/sysctl.conf` (UCL) is delivered as a directory descriptor and read once at startup. `default {}` applies to any label without a `clients {}` entry. `read` and `write` are lists of dotted-path prefixes matched on a component boundary: a name is permitted if it equals or lies under a listed prefix, so `kern` covers `kern.maxfiles` but `kern.ost` does not cover `kern.ostype`. Reads of unlisted names and any unlisted write are `EPERM`. Writes are denied unless listed.

Shipped default:

```ucl
default {
	read = [
		"kern.ostype", "kern.osrelease", "kern.osreldate",
		"kern.version", "kern.hostname", "hw.machine",
		"hw.ncpu", "hw.physmem"
	];
	write = [];
}
clients {
	"org.example.telemetry" { read = ["kern", "hw", "vm.stats"]; }
	"org.example.tuner"     { read = ["net.inet"]; write = ["net.inet.tcp"]; }
}
```

A missing or malformed file fails soft to the compiled-in default (the same small read set and no writes) with a warning. There is no `SERVICE_RIGHTS_ADMIN` bypass in BSDSysctl; an ambient root session with no entry gets the default read set like everyone else. The isolation set (`kern.maxfiles`) is separate policy: it is declared in the manifest, not in `sysctl.conf`, and it protects the OID from every other writer whether or not any label may write it through the broker.

## Tests

| Where | Programs | What they prove |
|---|---|---|
| `usr.sbin/BSDSysctl/tests` (package `libsysctlcmp-tests`, `/usr/tests/usr.sbin/BSDSysctl`) | `provider_test` (9 cases), `reactor_test` (3), `evolution_test` (2), `config_test` (10), `interfaces_test`, `observability_test.sh` (1) | provider_test drives the reactor (`-DSYSCTLCMP_TESTING`) over a channel with the real client: policy-gated `Get` and `Set`, gated introspection, `Next` never reveals denied names, malformed frames (pre-FIDL record, before negotiation, unknown method, truncated, trailing bytes) fail closed while a negotiated frame is served, an embedded NUL is `EINVAL`, argument validation, `Set` encodes a typed value from text, multiplexed clients and idle expiry. reactor_test runs the production reactor with real channels: per-session policy isolation, a malformed peer that cannot stall the others, idle expiry and admission bounds with slot reuse. evolution_test is the `bsd:1`/`bsd:2` schema pairing. config_test covers prefix matching on component boundaries, the closed schema and fail-soft loading. observability_test.sh asserts the `request-start`/`request-done` probes exist, are wired into the bsdinstruments `capability-services.d` profile, and that the binary carries a `.SUNW_dof` section when DTrace is built. |
| `lib/libsysctlcmp/tests` (`libsysctlcmp-tests`) | `sysctlcmp_test` (7), `client_strings_test` (5) | retained legacy record ABI and argument checks; against a scripted server: NUL-terminated strings, size queries that keep the session, unterminated or empty strings and a future wire version are terminal, interface inventory validation without partial copies |
| `usr.sbin/sysctlcmpctl/tests` | `sysctlcmpctl_test.sh` (4) | arguments, each verb against a fake provider, `list` from a start name, failure exits |

Run with `kyua test -k /usr/tests/usr.sbin/BSDSysctl/Kyuafile` on a booted plane ([Testing](../develop/testing.md)). The gate itself is exercised only on a real plane where Capsule mints the token; under the test build `gate_sysctl()` falls back to sysctlbyname(3) when no token is held, so the unit tests prove policy and encoding, not the kernel gate. The provider and libsysctlcmp ship together: `system.Sysctl` is a core unit and mixed peers fail at negotiation.

## Status and gaps

Status: shipped; capmode; user `capability`; gate `sysctl` plus `isolate`; FIDL `bsd.sysctl.v1` (October 2026) with Get, Set, OidFormat, Describe, Next and ListInterfaces. Unit attributes, visibility and policy are unchanged by the migration.

Known gaps and drift:

- The provider tests do not cover the gate path or the isolation hook; a foreign-writer-denied test for `kern.maxfiles` exists only as a design requirement in `docs/book/src/capability/system-gates.md`.
- All sessions share the one token-holding process; a slow sysctl handler (for example a long `Next` walk) delays the other sessions' next batch, although no client can hold the loop beyond one bounded dispatch.
- The book chapter this one replaces described BSDSysctl as an ambient provider; that was true before the gate framework and is no longer accurate.
- Only one OID is isolated. Extending `isolate` is the intended way to bring more tunables under sole-broker protection, but nothing beyond `kern.maxfiles` has been done.
- `set` accepts only numeric and string kinds; OPAQUE and NODE values are `EINVAL`.
