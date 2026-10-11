# Capability daemons: FIDL migration plan

Status: plan, 2026-10-11.  Branch `fidl/daemons` (worktree
`/usr/obj/5BSD-fidl-daemons`).  Roadmap item 1, before embedded manifests and
the shared library cache.  The reference migration is BSDTime (`cf97f876797`,
visibility `58977d8dfd1`); every conversion copies its pattern.

## Inventory (tree at `4e87e953034`)

Fifteen daemons call `service_provider_expose`, exposing 21 endpoints.
BSDTime is the only one already on FIDL.  BSDMemory serves nothing (it is a
client of system.Sysctl and system.Notify).  Every other protocol is a
hand-written fixed-layout C struct protocol over libchannel
(`service_session_call` / `channel_send_reply`), with descriptors as channel
attachments.  Every protocol's largest message fits libfidl_bsd's
14,336-byte / 32-attachment limit (largest: Log 8192, Sysctl ~8.5 KiB,
Network.State 8216).

| Provider | Endpoint(s) | Current protocol | Ops | Var-len | FDs | Server model | Unit (activation / control / visible) | In-tree clients | Risk |
|---|---|---|---|---|---|---|---|---|---|
| BSDTime | system.Time | FIDL `bsd.time.v1` | 4 | no | no | kqueue, 32 sessions | boot / core / user | libtimecmp: BSDTimectl | done |
| BSDPower | system.Power | `powercmp_protocol.h` | 5 | no | no | kqueue, 64 sessions | boot / core / user | libpowercmp: BSDPowerctl | low |
| BSDDevice | system.Device | `devicecmp_protocol.h` | 2 | name | 1 reply | pdfork/session | boot / system / system | libdevicecmp: tests only | low |
| BSDTrace | system.Trace (requires system.trace.client) | `tracecmp_protocol.h` | 3 | no | 1 reply | pdfork/session | boot / system / - | libtracecmp: authority fixtures | low |
| BSDSysctl | system.Sysctl | `sysctlcmp_protocol.h` | 6 | name+value | no | kqueue, 128 sessions | boot / core / user | libsysctlcmp: BSDMemory, BSDNamespace, BSDNetwork, sysctlcmpctl | low-medium |
| BSDCrypto | system.Crypto | `cryptocmp_protocol.h` | 10 | per-op | 0-1 reply | pdfork/session + reaper | boot / system / - | libcryptocmp: cryptoprobe | low-medium |
| BSDAudit | system.Audit | `auditcmp_protocol.h` | 2 | small | no | pdfork/session | boot / core / - | libauditcmp: BSDCrypto, BSDLog, BSDNetwork, BSDNotify | medium |
| BSDVM | system.VM | `libcapsulert/bsdvm_proto.h` | 3 | fixed | 1 reply | pdfork/client | ipc / system / - | libservice `service_vsock_*` | medium |
| BSDNamespace | system.Namespace | `libcapsulert/bsdnamespace_proto.h` | 3 | PATH_MAX | 1 reply | thread/client | ipc / system / - | libservice `service_enter_namespace*`: jailprobe | medium |
| BSDNetwork | system.Network, .Admin, .PF, .State | `networkcmp_protocol.h`, `network_state_protocol.h`, `pf_protocol.h` | 5+1+1 | yes | socket, /dev/pf | pdfork/session + threads | boot / system / per-endpoint `requires` | libnetworkcmp: networkcmpctl | medium |
| BSDNotify | system.Notify, .System | `notify_protocol.h` | 14 | yes, long polls | refused | router process + watcher | boot / system / user | libnotify: BSDMemory, BSDNetwork, libcache, notifyctl | medium-high |
| BSDExtension | system.SystemExtension | `libcapsulert/sysext_proto.h` (no magic) | 12 | fixed | no | thread/client + reclaim | boot / core / - | libservice `service_extension_*`: BSDCrypto, BSDBluetooth, sysextctl, rc boot authority | high |
| BSDFilesystem | system.Filesystem, system.OES | `bsdfilesystem_proto.h`, `oes_broker_protocol.h` | 17+1 | PATH_MAX | many reply | pdfork/connection | boot / core / user | libservice `service_storage_*` (BSDLog, BSDNamespace, BSDNetwork, BSDBluetooth, probes), libbsdfilesystem: tzfsctl, liboes: oeslogger | high |
| BSDLog | system.Log | `logcmp_protocol.h` + shared-memory ring | 8 | yes | ATTACH: 5 fds | shard pool + watcher | boot / core / user | liblogcmp: nearly every daemon, logctl, probes | high |
| BSDBluetooth | system.Bluetooth, .Controller | ATTACH (`blued_plane.h`) then `libble/ipc_proto.h` over a socket | 1 (+18 socket types) / 1 | yes | socket handoff | kqueue + threads | ipc / system / user | libble: bluedctl, meshd, examples | high (socket protocol) |

Not in scope: switchboard's own control endpoints (system.switchboard,
system.lifecycle; `sctl`/`ctl_request`/`SVC_OP_*`) are the plane substrate,
not providers, and a summary reply (16 KiB) exceeds the FIDL message limit.

Facts that shape every conversion:

- Core units (Power, Sysctl, Audit, Extension, Filesystem, Log, Time) cannot
  be restarted at runtime; provider and client library ship together in one
  release transaction (BSDTime precedent: no legacy fallback, the client
  negotiates the wire major before any operation).
- The libservice-embedded clients (Filesystem, Extension, Namespace, VM) are
  part of libservice's ABI; converting them makes libservice depend on
  libfidl_bsd or moves those clients into separate libraries.  Either is a
  library-layout change to raise with the user before doing it.
- BSDLog's shared-memory ring is a data plane, not a message protocol; only
  its control messages (HELLO/ATTACH/query) are FIDL candidates.
- Bluetooth's `ipc_proto` runs over an ordinary socket handed out by ATTACH,
  not over a capability channel; only ATTACH and the Controller message are
  provider protocols.

## Conversion contract (each daemon)

One self-contained commit (or series) per daemon, nothing in the tree left
speaking the old protocol:

1. `.fidl` library `bsd.<name>.v1` next to the client library, installed under
   `/usr/share/fidl`; closed protocol, strict methods, `GetProtocolInfo`
   negotiation first (as `bsd.time.v1`); application errors are errno values.
   Generated C/C++ bindings checked in under `generated/` with a
   `SOURCE.sha256` stamp (see "Generated bindings" below); the library is
   listed in `tools/build/fuchsia/test-bindings.py`.
2. Provider and every in-tree client converted together.  The old
   `*_validate_message` symbol and protocol header stay only for ABI
   compatibility and are marked legacy; the provider rejects legacy records.
3. Authority unchanged: same endpoint names, unit attributes/`requires`,
   visibility, policy files, OES hooks, gate tokens, capability mode,
   fail-closed defaults, per-label quotas, session limits and idle expiry,
   descriptor rights, DTrace probes (historical opcode numbers are kept as
   probe arguments).  Any change in who can reach a service is stopped and
   reported, not made.
4. Tests: provider tests drive the real client against the real provider over
   a capability channel; adversarial cases hand-build FIDL frames (unknown
   method, before negotiation, truncated, trailing bytes, missing body, legacy
   record, attached descriptor).  Schema evolution: a `next` schema in the
   provider's `tests/evolution/` is exactly the production schema at `bsd:1`
   (checked by test-bindings.py) and adds a method at `bsd:2`; an ATF test
   pairs a peer built from `bsd:2` with the real `bsd:1` client and provider
   in both directions.
5. Docs: provider book page, client manual, daemon manual; this file,
   `REMAINING.md`, `HANDOFF.md`, `VALIDATION.json`.
6. Validation only in QEMU VMs (4 vCPUs, patched QEMU), restaged from scratch:
   plane-on `vm-provider.sh` with the daemon's suites, its ctl tool against the
   live provider, and a request-latency comparison (libchannel
   `request-start`/`request-done` USDT probes in the client) against the
   pre-conversion baseline build.

Shared pieces added once (first conversion): `fidl_bsd_connections_wait()`
(the FIDL analogue of `service_channels_wait()`) and the header-only
`<fidl/bsd/sync_c.h>` synchronous-call helpers, which also honour the
caller's `service_budget_begin()` deadline.

## Generated bindings

Bindings are committed, so a `.fidl` edit could ship with stale output.
Three pieces prevent that (since the first conversion commit):

- `make -C tools/build/fuchsia regen` regenerates every checked-in tree
  (runtime fixtures, BSDTime, each provider and each evolution schema) and
  writes `generated/fidl/<library>/SOURCE.sha256`: the SHA-256 of each input
  schema relative to the source root, plus the pinned Fuchsia revision and
  generator script digests as comments.
- `lib/libfidl/fidl-bindings.mk`, included by every Makefile that compiles a
  tree (`FIDL_BINDINGS=` paths relative to `SRCTOP`), hooks `beforebuild`
  and fails with "`<file>.fidl` changed; run make -C tools/build/fuchsia
  regen and commit the result".  It uses only `sh` and `sha256(1)` (the
  `sbin/md5` bootstrap tool), so buildworld still needs no Python or Go.
- `make -C tools/build/fuchsia check-bindings` (in `check`) regenerates into
  a scratch tree and diffs everything, stamps included, catching hand-edited
  output and generator changes.

Verified in a scratch worktree: appending to `lib/libtimecmp/timecmp.fidl`
makes `make -C lib/libtimecmp all` stop before compiling with the message
above; `regen` then makes it pass; a hand edit to a generated header fails
`check-bindings` naming the file.

Follow-up (not part of this migration): generate the bindings into the
object tree at build time, so nothing generated is committed.  Then the
stamps, `fidl-bindings.mk` and `regen` are deleted together; nothing else
depends on them.  See "Binding generation: end state" below.

## Binding generation: end state

Measured 2026-10-11 on this tree (15 binding trees: runtime fixtures,
BSDTime, six providers, six evolution schemas, Network in progress).

Today's pipeline per library: fidlc (C++, `contrib/fuchsia`) writes JSON IR;
fidlgen_cpp (Go, upstream plus the 239-line `fuchsia-native.patch`) writes
C++ natural types; `generate-bsd.py` keeps 5 of fidlgen_cpp's ~20 output
kinds (`natural_types.{h,cc}`, `common_types.{h,cc}`, `markers.h`) and adds
the C++ client/server adapter (`cpp/bsd.h`) and, with `generate_bsd_c*.py`,
the C bridge (`c/bsd.h`, `c/bridge.h`, `c/bsd.cc`).

What the BSD bindings take from fidlgen_cpp: only declarations.  The kept
files are the natural classes (storage, constructors, accessors, clone,
equality) and the trait tables (`IsFidlType`, `TypeTraits` sizes,
`NaturalCodingTraits` member offsets) that the upstream natural codec
templates in `sdk/lib/fidl/cpp` (already in the runtime) consume.  No
messaging, wire-types, HLCPP or ostream output is used.  Every value in
those files (names, inline sizes, offsets, depths, handle counts, ordinals)
is in fidlc's JSON IR, so a BSD generator can read the IR directly and the
Go stage can be removed.  The templates involved are about 1,650 lines
(`natural_{struct,table,union}.tmpl` 812, file headers/sources 260, enum,
bits, const and alias fragments 535) plus the parts of `lib/fidlgen_cpp`
they use (names, keyword escaping, type mapping; that package is 6,254 Go
lines in all, mostly messaging).  The in-tree schemas use structs, resource
structs, one table, one flexible union, result unions, aliases, arrays,
vectors, strings, `box`, optional and `zx.Handle`; no enums, bits or
constants yet.  The committed output is a byte-exact test oracle for any
replacement: 150 files, 46,242 lines (2.0 MB), of which 32,174 lines come
from fidlgen_cpp.

| | (a) native C++ generator | (b) bootstrap CPython | (c) committed + checks |
|---|---|---|---|
| Build-time cost | fidlc as a bootstrap tool: 52 translation units, about 11 CPU-s each at `-O1` (sampled under load), so ~10 CPU-min, under 1 min wall at `-j16`; generation in-process in fidlc (today's whole pipeline, fidlc + fidlgen_cpp + Python for all 15 trees and 6 compatibility compiles, takes 11.9 s wall, 3.2 s user) | fidlc as in (a) plus CPython: ~400k lines of C for the interpreter (estimate) and the few extension modules needed (`_json`, `_sre`, `_posixsubprocess`, `select`, `fcntl`), estimated 3-5 CPU-min (not measured; no CPython in tree); generation cost as today minus the Go process | none (stamp check: one `sha256` per schema) |
| Code to write / maintain | ~2-3k lines C++: a backend inside fidlc walking the compiled AST (no JSON reader needed), replacing fidlgen_cpp's natural output and the 650 Python lines | port ~1.5k lines of Go templates to the existing Python, keep 650 Python lines; import and track CPython in `contrib` (~110 MB unpacked, a subset kept) | none new; 940 lines of Python tooling and the Go fidlgen_cpp build stay host-only |
| Cross-build host needs | host C++20 compiler (already required); fidlc's RE2 use (4 identifier patterns in `utils.cc`, linter) and OpenSSL `SHA256` (ordinals) must be patched to `<regex>`/hand matching and libmd | as (a) for fidlc, plus CPython's configure on every supported host (FreeBSD, Linux, macOS) | none for buildworld; developers who change a schema need Python 3.12, Go and RE2 from ports (`bootstrap`) |
| Determinism | deterministic if the backend sorts like fidlc's JSON; verifiable against the oracle | the Python generators already sort; repeated `regen` runs are byte-identical | byte-identical regeneration checked by `check-bindings`; nothing generated at build time |
| Other | no Python in the build; generated files leave the tree | also enables LLVM `lit` in the build; Python becomes a long-lived build dependency | 46k generated lines in diffs; generator changes need a regen commit |

Recommendation: (a), done after the daemon migration.  It removes both Go
and Python from schema changes, adds the least to buildworld (fidlc is
needed by any build-time option), and fidlc's own AST is a better input
than re-parsing JSON.  (b) is only cheaper if CPython enters the build for
another reason (lit); if the user wants that, the Go stage can still be
dropped by porting the natural templates to Python first, against the same
oracle.  Until then (c) is in place and safe.  Either (a) or (b) deletes
`SOURCE.sha256`, `lib/libfidl/fidl-bindings.mk`, `regen` and the committed
`generated/` trees in one change; nothing else depends on them.

## Order

Smallest and most isolated first; boot-critical and widely linked providers
last:

1. BSDPower (system.Power)
2. BSDDevice (system.Device)
3. BSDTrace (system.Trace)
4. BSDSysctl (system.Sysctl; BSDMemory, BSDNamespace, BSDNetwork clients move
   with it)
5. BSDCrypto (system.Crypto)
6. BSDAudit (system.Audit; four daemon clients move with it)
7. BSDVM, 8. BSDNamespace (libservice-embedded clients; needs the library
   layout decision above)
9. BSDNetwork (four endpoints)
10. BSDNotify
11. BSDExtension, 12. BSDFilesystem (+ OES), 13. BSDLog (control plane only)
14. BSDBluetooth ATTACH and Controller messages only

## Progress

| # | Provider | Status | Commits | VM evidence | Latency (p50 before -> after) |
|---|---|---|---|---|---|
| 1 | BSDPower | in progress | | | |
