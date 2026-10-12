# FIDL and Capability IPC

**Status (October 9, 2026):** The experimental native C++ backend and generated
C ABI now work over 5BSD capability channels. They reuse upstream FIDL natural
types and codecs with libchannel's native transport and lifecycle machinery.
The compiler, formatter, linter, and C++/Rust generators also build. BSDTime and libtimecmp now use FIDL in the source tree; production activation
and provider VM validation remain incomplete. Native runtime/header/manual build targets and
package registration exist, with C/C++ consumers tested against a staged
installation. The optional host SDK also has staging targets. Full world/package and
external tool dependency validation remain. Use existing typed service libraries for production applications.
Rust runtime bindings remain unported.

## What FIDL would improve

FIDL describes a service interface in a schema and generates code to encode,
decode, and dispatch its messages. The current provider pattern defines C
wire structures and checks their fields and attachment slots by hand; see
[A Capability Provider](provider.md). Moving that repeated work into a
shared compiler and binding runtime is the main reason to adopt FIDL.
It also gives reviewers an explicit interface to inspect independently of
either peer's implementation.

| Concern | Current 5BSD capability IPC | Intended FIDL integration |
|---|---|---|
| Protocol definition | Shared C headers and service-specific validation | Schemas, compiler checks, generated bindings |
| Compatibility | Each service defines its ABI and version checks | FIDL evolution rules plus a deliberate service compatibility policy |
| Asynchronous calls | libchannel requests, replies, events, cancellation, and bounded queues | Native adapters use libchannel readiness and lifecycle semantics |
| Capability enforcement | Kernel descriptors, Capsicum rights, transfer ceilings, and revocation | The same native enforcement beneath FIDL |
| Discovery and admission | libservice and SwitchBoard | Retain these responsibilities while migrating their message formats |
| Readiness for use | Existing deployed interfaces | Tested experimental C++ backend and C bridge; production migration remains |

FIDL is a promising improvement to protocol maintenance. It is not yet an
operational replacement for the current stack. No comparative latency,
throughput, allocation, or memory measurements have been made on 5BSD.
Generated validation can reduce repeated parsing mistakes, but application
authorization, resource limits, and correct descriptor cleanup still need
implementation and testing. Compatible schema evolution also needs review;
changing a schema does not automatically make old and new peers compatible.

The cost is a larger toolchain and binding runtime, upstream maintenance,
and a language boundary: the native runtime is C++, whereas current service
interfaces are predominantly C. A generated C ABI now bridges that boundary
for supported payloads. The Rust generator builds, but its runtime is unported.

## What the runtime is

The compiler and generators run while software is being built. Their output
calls a support library when the client or server executes: this is the
FIDL runtime. Generated code supplies protocol-specific types and method
handling; shared runtime code supports message validation, transport,
request/reply tracking, dispatch, and resource cleanup. The precise division
of work depends on the language binding.

For example, calling an Echo method needs more than a generated function:
its message must reach the channel, its reply must reach the waiting caller,
and any attached descriptors must have a defined owner if the peer exits.
The 5BSD backend must connect that runtime machinery to native capability
channels, descriptors, and kqueue. It is library support used by each
participating program; it does not require a new central routing daemon.
That native path now works through the BSD adapters; the Fuchsia WireClient
and dispatcher APIs themselves are not the native interface.

## Where it fits

The experimental backend uses this layering:

```text
typed service API and application authorization
FIDL schema, generated encoding/decoding, and dispatch
5BSD binding backend: descriptor ownership, transactions, kqueue
native capability channels and kernel enforcement
```

Generated C++ and C test services exercise this path on live kernel channels.
The adapter explicitly reconciles FIDL resource ownership with libchannel
borrowing/queueing, and FIDL transaction IDs with native reply tokens. Existing
service payloads do not become FIDL messages merely by compiling a schema.

Fuchsia's Component Manager and `/svc` namespace examples describe its
component framework. Importing FIDL does not import that framework into
5BSD. Here, [discovery and admission](../plane/discovery-and-lookup.md)
remain responsibilities of libservice, SwitchBoard, and the kernel's
software-authority context. A protocol name or method ordinal is not a
grant of authority. Traditional sockets, pipes, shared memory, and kernel
service interfaces remain available; this work targets capability-service
protocols.

## Descriptors as capabilities

A handle-bearing message must carry descriptors through the native channel's
attachment mechanism. A number encoded in its payload is ordinary data;
it cannot designate a capability in another process. The receiving kernel
installs a descriptor in the receiver's table, and the binding associates
that attachment with the appropriate schema field.

The expected descriptor type is in the FIDL schema, not a self-describing
label in the message body. The wire body contains a presence marker, and
attachments are associated with fields in encoding order. The receiver checks
the actual kernel descriptor against its own generated schema; it does not
trust a peer's claimed type or rights. A generic descriptor has no narrower
object-type constraint. A typed channel endpoint checks that it is a native
channel; that check alone cannot prove the peer implements the named protocol.

A descriptor restricted with `CAP_XFER_NONE` cannot be sent to another process
through these channels: the kernel rejects the transfer with `ENOTCAPABLE`.
Objects the kernel cannot pass, such as kqueues, are rejected with `EINVAL`.
The C bridge's private duplicate preserves transfer restrictions. An immediate
send failure returns the error and leaves the caller's original descriptor
open; a two-way call that fails immediately does not invoke its callback.
Queued output can fail later during dispatch, so acceptance is not delivery.

Descriptor work is folded into the message system calls, whatever the number
of attachments. The sender passes each schema's type and rights as an
expectation; the kernel checks all of them before accepting the message,
narrows the delivered copies, and closes the moved originals. The receiver
gets each descriptor's type and rights with the message and validates against
that report, so a descriptor the sender narrowed to exactly the schema's
rights needs no further call; otherwise one `cap_rights_limit(2)` narrows it.
A C sender's lent descriptor costs one duplicate, delivered with inheritance
locked by the send. On older kernels libchannel performs the same checks in
userland.

Measured with `ktrace` in a VM (`ipc_bench cppfd|cfd`, one read-only pipe
descriptor per two-way call, both processes counted; the four message ioctls,
the benchmark's own `dup`, and the server's `close` are the remaining
baseline):

| System calls per call | Userland checks | Kernel checks |
|---|---:|---:|
| C++ client and server | 13.15 | 6.15 |
| C client and server | 15.15 | 6.15 |

The removed calls are two `cap_rights_get`, two `cap_rights_limit`, a
duplicate and two `close` calls for C++, plus the C bridge's two inheritance
locks. On the kernel path, checking, narrowing and moving further
descriptors in the same message add no system calls; a C sender still
duplicates each lent descriptor once.

The backend preserves the rules in
[Descriptor and Process Protections](../capability/descriptor-protections.md):

- Validate attachment counts, descriptor types, and required rights before
  exposing a decoded request. Reject malformed messages and close every
  attachment whose ownership has not been transferred to the application.
- Preserve Capsicum attenuation, transfer ceilings, revocation, and enforced
  exec/fork restrictions. Schema annotations must never synthesize rights.
- Specify ownership on send success, queued sends, failure, cancellation,
  and peer death. The runtime sends with `CHANNEL_SEND_MOVE`: an accepted
  send, immediate or queued, consumes the descriptors without duplicating
  them, and a failed send leaves them with the packet, which closes them.
- Preserve kernel sender and authority metadata. Payload UID/PID fields
  cannot authorize requests; attribution alone does not grant authority.
- Treat descriptor zero as valid. Zircon handle sentinels and rights are
  not interchangeable with BSD descriptor values and rights.
- Map FIDL's 32-bit transaction IDs to native 64-bit reply tokens explicitly,
  including wraparound, late replies, and cancellation. Do not truncate tokens.

The imported C++ host transport still rejects handles. The native backend
uses its own codec ownership hooks and libchannel integration instead of
pretending Zircon handles are BSD integers. Its internal codec slots use
fd+1, with zero for absence; these numbers are never sent as authority.

## Tools and evidence available now

Sources live under `contrib/fuchsia`; maintained integration scripts are in
`tools/build/fuchsia`. Run these from `/usr/src`, after satisfying the host
dependencies recorded in `tools/build/fuchsia/README`:

```sh
python3.12 tools/build/fuchsia/build-fidl.py --test
python3.12 tools/build/fuchsia/build-generators.py --go /path/to/go --test  # gidl/Rust only
python3.12 tools/build/fuchsia/test-fd.py
python3.12 tools/build/fuchsia/build-runtime.py --test
python3.12 tools/build/fuchsia/build-runtime.py --test --sanitize
```

Replace `/path/to/go` with the installed Go executable; Go now builds only
the GIDL conformance generator and the Rust generator. The host compiler
build requires Python 3.12+, C++20, RE2 development files (for
`fidl-lint`), base libmd and OpenSSL (for the compiler tests), and the
tree's googletest import. Output defaults to `/usr/obj/5bsd-fidl`;
compilation uses all logical CPUs. These commands do not install or activate
a service. Exact revisions, licenses, local patches, and refresh commands
are recorded in `tools/build/fuchsia/README`, `sources.json`, and
`contrib/README.5BSD`.

The initial native run passed 2,203 enabled compiler tests, including the
local lexer regression; four upstream tests remain disabled. The Go IR,
C++/Rust generator, and compiler-helper suites passed. The descriptor
experiment passed across `fork` and `cap_enter`, checking a kernel sender
stamp, rights attenuation, and rejection of a second transfer of a one-hop
descriptor. It uses an upstream wire header and handle marker, not generated
client/server bindings. Results are recorded in
`tools/build/fuchsia/VALIDATION.json`. The subsequent runtime suite passes
67 native tests, a C11 client/server integration test, and 36 generator
contract checks. All 32 accepted binding fixtures also compile and link,
and repeated generation is identical. Eight dependency-graph checks and a
three-library C round trip also pass, including composed/base protocol
interoperation and generation from extracted pkgbase tools. ASan and UBSan
pass the runtime suites. This host cannot run
LeakSanitizer; descriptor cleanup is checked explicitly with pipe EOF after
all intended owners are gone, including rejected and queued messages.

`build-runtime.py --test` also runs the pinned upstream GIDL conformance
suite (`contrib/fuchsia/src/tests/fidl/conformance_suite`) through the same
encode/decode entry points as the native runtime: 1,033 encode, decode and
failure cases pass in ordinary and ASan/UBSan builds. The 193 cases that need
Zircon handle objects or rights are compiled out (GIDL guards them with
`__Fuchsia__`); native descriptor transfer has its own tests. A schema
evolution test compiles one schema at two `@available` versions and runs
separately built old and new C peers against each other over native
channels: unknown table fields are dropped, unknown flexible union variants
report `_unknown_tag`, flexible enum and bits values pass through, added
flexible methods return `EOPNOTSUPP` and added flexible events reach the
`unknown_interaction` hook, with the connection remaining usable.
`check-closure.py` fails the build if any runtime archive member becomes
unreachable from the runtime, C and conformance consumers.

## Installed tests and native CI

`MK_TESTS` builds and installs the normal `bsd.test.mk` targets under
`/usr/tests/lib/libfidl`, packaged as `libfidl-tests`. The C integration test is
always included; `MK_GOOGLETEST` controls the C++ runtime suite. These static
binaries need no compiler, Python, Go, or source checkout at run time. Run their
`Kyuafile` with Kyua on a matching 5BSD kernel.

### Bindings generated at build time

buildworld generates every FIDL binding the system uses (the runtime
fixtures, BSDTime, each migrated provider and each evolution test's next
schema) into the object tree; nothing generated is checked in. A Makefile
that needs bindings names a set and includes `lib/libfidl/fidl-bindings.mk`:

```make
FIDL_BINDINGS+=	timecmp
FIDL_SCHEMAS.timecmp=	lib/libtimecmp/timecmp.fidl
FIDL_LIBRARY.timecmp=	bsd.time.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"
```

then adds `-I${FIDLGEN.timecmp}` to `CFLAGS` and, where it compiles the
bindings (the library itself, or an evolution peer), `${FIDLGEN_SRCS.timecmp}`
to `SRCS`. Schemas list dependencies first (`lib/libfidl/tests/zx.fidl` for
`zx.Handle`); `FIDL_FLAGS.NAME` passes extra `fidlc` arguments, such as
`--available bsd:2` for a next schema. Generation runs in `beforebuild`,
before anything is compiled, and again whenever a schema or the generator
changes, so a `.fidl` edit cannot ship with stale bindings.

The pipeline is `fidlc` (C++, built from `contrib/fuchsia` in buildworld's
bootstrap-tools stage by `tools/build/fuchsia/fidlc`; patched to use
`<regex>` and libmd instead of RE2 and OpenSSL), then
`tools/build/fuchsia/fidlgen-build.py`. The natural C++ types come from
upstream's own `fidlgen_cpp` templates, executed by a Python port of the
`fidlgen_cpp` model and of Go's `text/template` (`fidlgen_natural.py`,
`gotemplate.py`); `generate-bsd.py` adds the C++ client/server adapters and
the C bridge. There is no Go in the build. The port's output was checked
byte for byte against the previously committed bindings (180 files) before
they were deleted.

Python is a **build-only** prerequisite: it is never installed into the
target. buildworld needs Python 3.12 or newer on the build host and stops
first thing (`_python_check` in `Makefile.inc1`) when it is missing,
naming the `python312` package and its port, `lang/python312` in the 5BSD
ports tree (`PORTSDIR`, currently `/usr/obj/5BSD-ports`). `PYTHON=` selects
another interpreter. Cross-build hosts (Linux, macOS) need the same Python
and a C++20 host compiler for `fidlc`; see build(7).

`make -C tools/build/fuchsia check-bindings` (part of `check`) generates
every set named in the tree's Makefiles twice and requires byte-identical
output, and proves that each provider's evolution schema is the production
schema at `bsd:1`.

After bootstrapping the host tools, `make -C tools/build/fuchsia check-native`
runs native and sanitizer suites, staged SDK consumers, normal native tests,
and extracted pkgbase checks. `test-installed.py --packages` runs the staged
SDK/test/package portion. Host checks use installed base libraries matched to
the running kernel; validating a complete new world remains a separate gate.

For longer resource checks, `make -C tools/build/fuchsia check-soak` runs a
600-second native provider soak and a 300-second ASan/UBSan soak. Override
`FIDL_SOAK_SECONDS` and `FIDL_SANITIZER_SOAK_SECONDS` for longer runs.
The installed `bsdtime-tests` package also includes
`/usr/tests/usr.sbin/BSDTime/resource_soak N`, where `N` is seconds; ordinary
Kyua runs do not invoke it. Eight C clients and four idle peers repeatedly
connect through real native channels in capability mode. Each epoch checks
policy results, operation counts and descriptor recovery. JSON output records
live allocated bytes and peak RSS; after a ten-second warmup, growth over
1 MiB of live allocation or 64 MiB of native peak RSS fails. ASan RSS is
observed only because its quarantine retains freed memory. Runs under 30
seconds are smoke checks. Clock writes and logging are simulated; this does
not establish installed-plane behavior or comparative performance.

## Measured overhead

`make -C tools/build/fuchsia check-bench` builds an `-O2` tree and times
synchronous cross-process request/reply over one native channel, comparing raw
libchannel with pre-encoded bytes, generated C++ bindings and generated C
bindings. It also counts heap allocations per call through link-time wrappers.
On October 10, 2026 (16 logical CPUs, other work present, three runs of 20,000
calls each) the medians were:

| Path | 8-byte string p50 | 256-byte string p50 | Calls/s (8 B) | Heap allocations per call (client/server) | Bytes allocated per call (client) |
|---|---|---|---|---|---|
| raw libchannel | 8.1 µs | 8.0 µs | 115,700 | 2 / 1 | 864 |
| FIDL C++ | 10.4 µs | 10.9 µs | 89,500 | 10-12 / 6-7 | 2,144-3,168 |
| FIDL C | 10.7 µs | 11.1 µs | 87,200 | 10-12 / 7-9 | 2,144-3,168 |

FIDL adds 2.3-3.1 µs and 8-10 client allocations per round trip; synchronous
throughput is 23-27% lower than raw libchannel. Earlier the same day,
libchannel allocated a 14 KiB receive buffer for every message and for the
final would-block attempt of each dispatch (about 29 KiB per call). It now
uses one block sized from recent messages and reuses it across empty
receives, which cut raw allocation traffic 34-fold and raw p50 latency by
about 10%. These numbers describe one ping-pong pattern on one host, not
multi-day stability, pipelined throughput, or kernel memory.

## C and C++ interfaces

`lib/libfidl/README` records the build and API contracts. The BSD generator
wraps upstream natural types/codecs; it does not implement a second wire
format. Use `generate-bsd.py --json ... --root ... --c` to produce the C ABI
as well as C++ adapters. Include `fidl/LIBRARY/cpp/bsd.h` or
`fidl/LIBRARY/c/bsd.h`. Generated C bridge sources compile as C++20; the
application itself compiles as C and links against the same native runtime.

C++ descriptor fields move into calls and are consumed on error as well as
success. The C interface borrows outgoing buffers and duplicates outgoing
FDs; the caller keeps the original descriptor and rights. C callback buffers
last only until callback return. Use `fidl_bsd_take_fd` to retain a received
FD and copy any bytes that must survive. Retain/release a C request context
for a deferred reply; that does not retain its decoded buffers.

A connection has one dispatch thread. Closing from callbacks is supported;
destroying the connection object from its own callback is not. The library
provides kqueue-based polling and accessors for integration into existing
event loops. Cancellation is local. Server shutdown sends an epitaph and
requires continued polling until peer closure or an application deadline;
an accepted send alone is not a delivery guarantee.

## C interfaces and dictionaries

C is the primary application API. The generated bridge and runtime may use
C++ internally, while application sources use C11 headers, opaque connection
objects, ordinary structs, callbacks, and integer descriptors.

FIDL has no built-in dictionary/map type. A dictionary can be represented as
a bounded vector of entries, each containing a key and value. For example:

```fidl
library example;
type Entry = struct { key string:64; value string:256; };
type Dictionary = struct { entries vector<Entry>:128; };
closed protocol Store { strict Put(Dictionary) -> (); };
```

The protocol must define duplicate-key handling and any ordering rules;
vector validation does not enforce key uniqueness. A FIDL table has fixed,
schema-defined ordinal fields and is not a dictionary with arbitrary keys.
The generated C projection supports this representation:

```c
struct example_Entry entries[] = {
    {.key = "name", .key_size = 4, .value = "printer", .value_size = 7}
};
struct example_Dictionary dictionary = {
    .entries = entries, .entries_size = 1
};
```

C strings and vectors use pointer/size pairs; arrays are inline arrays.
Optional strings and vectors also have a `_present` flag, which distinguishes
absence from a present empty value. An absent outgoing value has a null pointer
and zero size. Boxed structs and optional unions use nullable pointers. Tables
have `has_MEMBER` flags; unions have `tag` and `value` fields with generated tag
constants. `error` replies expose a result union whose `response` and
`err` alternatives are application results. The callback's errno argument
reports transport or conversion failure separately.

All nested callback buffers are borrowed until callback return. Copy data to
retain it, and use `fidl_bsd_take_fd()` on a nested descriptor field to keep that
descriptor. Conversion rejects cyclic boxed inputs and excessive allocation
work. If creating a C response view runs out of memory, the callback completes
once with `ENOMEM` and unclaimed descriptors are closed.

## Protocol evolution

The C and C++ bindings support closed, ajar, and open protocols. A closed
protocol rejects unknown interactions. An ajar protocol accepts unknown flexible
one-way calls and events. An open protocol also handles unknown flexible two-way
calls by returning the standard FIDL unknown-method reply. The client callback
reports `EOPNOTSUPP` (and a null result in C), leaving the connection usable.
Application errors remain in the generated result union.

Open/ajar C handler structures have an optional `unknown_interaction` callback;
C++ handlers have `OnUnknownMethod` and `OnUnknownEvent` hooks. These report the
ordinal and, for server requests, whether a reply was required. The runtime
closes unknown attachments rather than exposing untyped capabilities to a hook.
Unknown strict interactions still close the connection.

For known interactions, a different strict/flexible header flag is accepted.
Creating a generated client installs a default event handler if no handler is
bound: it decodes and discards known events and applies the protocol's openness
rules to unknown events. In C this happens on the first generated client call;
bind event handlers explicitly to receive events before making a call.
Applications can bind their own event handlers.

These rules follow [FIDL's unknown-interaction design](https://fuchsia.dev/fuchsia-src/contribute/governance/rfcs/0138_handling_unknown_interactions).
They support adding methods while old and new peers coexist; they do not replace
service versioning, authorization, or a tested migration and rollback policy.

## Shared schema libraries

Use `--dependency-json` for each dependency-library compiler JSON file,
including transitive dependencies:

```sh
fidlc --json common.json --files common.fidl
fidlc --json service.json --files common.fidl --files service.fidl
fidlgen-bsd --json service.json --dependency-json common.json \
    --root generated --c
```

The adapter orders the graph and generates every supplied library. Types-only
libraries also receive public C headers. Imported types retain one definition
in their declaring library; a service header includes that header. Composed
protocol methods keep the original ordinals and payload types, allowing a
composed client to talk to the original base-protocol server.

Compile each generated library's `cpp/natural_types.cc`, `cpp/common_types.cc`,
and `c/bsd.cc` once. Generated `c/bridge.h` files share private inline C++
conversions between libraries. Application C sources include `c/bsd.h`.

Missing or duplicate libraries, dependency cycles, and inconsistent available
imported-declaration metadata are rejected before output publication. A later
schema rejection also preserves previously generated files. Supply IR from a
coherent schema build: the compiler's imported metadata cannot prove every
semantic compatibility property. The native `zx.Handle` mapping needs no
separate Zircon runtime library.

## Current feature gaps

C and C++ bindings accept closed, ajar and open protocols with strict and
flexible calls, one-way methods and events, using named or anonymous local or
imported payload types, plus payload-free methods. Names come from upstream
C++ transformations. The C
projection accepts local and imported structs, tables, unions, enums/bits, nested arrays
and vectors, optional values, descriptors, and typed protocol endpoints.
Strict application-error results are supported. C keyword and
helper-field collisions use deterministic name escaping. Unsupported schemas fail during
generation rather than silently using Fuchsia APIs.

Rust runtime bindings should be added as tested implementation work. They are not permanent
5BSD restrictions. Upstream conformance covers every non-handle GIDL case;
Zircon handle-object cases do not apply to native descriptors.

Generic FD, socket, and capability-channel handles have native mappings.
READ/WRITE constraints map explicitly to Capsicum rights; SAME_RIGHTS preserves
existing attenuation. Socket type checks need fstat rights, which explicit
socket rights preserve. Channels need GETINFO permission and currently require
SAME_RIGHTS. Unsupported rights and Zircon-only object types fail closed.
An additional object type needs a real native capability contract; importing
an emulated Zircon object merely to compile a binding is not the goal.

## Requirements before service migration

The native backend is now exercised with generated bindings, malformed input,
rights and type mismatches, queue limits, peer death, cancellation, transaction
exhaustion, descriptor cleanup, and protocol shutdown. Extend that coverage
as the schema subset grows.

Migrate each service schema and both peers with an explicit compatibility
strategy. Update provider, adversarial, and lifecycle tests, validate the
complete capability plane in the [VM test rig](testing.md), and integrate
the toolchain and runtime into the base build and packages. Measure against
the current implementation before making a performance claim. Standalone
backend tests do not establish a completed service migration.

Binary applications use installed `fidl/bsd/runtime_c.h` or
`fidl/bsd/runtime.h`, generated protocol headers, and `libfidl_bsd`.
`pkgconf --cflags --libs fidl` supplies installed include/link flags.
The C API exposes sized queue-limit options, ABI version, and peer epitaphs.
`tools/build/fuchsia/test-installed.py` verifies C11 and C++ shared/static runtime
consumers without source-tree include paths. The remaining maturity gates
are tracked in `lib/libfidl/MATURITY`.

The manual overview is `fidl(7)`; native API contracts are in `libfidl_bsd(3)`. Upstream background is available in
[Fuchsia's FIDL introduction](https://fuchsia.dev/fuchsia-src/get-started/learn/fidl/fidl)
and [Connecting components](https://fuchsia.dev/fuchsia-src/get-started/learn/fidl/connecting-components);
their build and component-routing instructions target Fuchsia.

The installed SDK test also generates its own bindings with the staged
`fidlc` and `fidlgen-bsd`, then checks both shared and static runtime linking.
The C executable links with `cc` and the C++ support libraries from
`pkgconf`; application sources need no C++ syntax. The optional host tools
use Python 3.12 and RE2. These build dependencies are not part of generated
application startup.

Typed `client_end` and `server_end` fields now transfer native channel
capabilities in both bindings. C++ preserves the protocol and direction in
its endpoint type; C uses an FD field. Optional endpoints distinguish absence
from descriptor zero. The runtime checks the actual attachment type and
retains kernel rights enforcement. C keyword and generated size-field
collisions are escaped deterministically with `_fidl` suffixes.

The first source-tree provider migration is [BSDTime](../providers/time.md);
the remaining capability daemons follow the plan in
`tools/build/fuchsia/DAEMONS.md`, starting with [BSDPower](../providers/power.md).
Providers serving many sessions use `fidl_bsd_connections_wait()` (the FIDL
form of `service_channels_wait()`), and synchronous C clients use the
`<fidl/bsd/sync_c.h>` helpers, which honour a caller's
`service_budget_begin()` deadline.
Its public C API remains compatible while its wire protocol uses generated
bindings. Host-safe policy/adversarial/lifecycle tests use simulated clock gates. In a
plane-on VM (`tools/build/fuchsia/vm-provider.sh`) the FIDL provider activates
under SwitchBoard, the real clock-gate test passes, and BSDTimectl reaches the
live provider through the broker. Release-transaction upgrade and rollback
across boot environments still need the integrated software-authority run.
