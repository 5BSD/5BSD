# ARM64 / RISC-V64 Netgraph module candidates

2026-11-01. Native cross-target declarations cover the seventeen previously
converted amd64 Netgraph modules: async, car, checksum, gif_demux, hub, ip_input,
one2many, patch, pipe, pppoe, socket, split, tag, tcpmss, tee, vlan and vlan_rotate.
All seventeen directories are selected by both architecture-checked GENERIC
Make inventories. This does not qualify the remaining Netgraph modules, a
complete kernel/module set or packet/socket behavior. Make remains the production
backend; BIP is excluded.

## Target headers and native graph

The common Netgraph kernel header library previously depended directly on amd64
KDB/NETGRAPH options. It now uses native Bazel select against target CPU
constraints: x86_64, aarch64 and riscv64 each select their actual config headers.
Unsupported CPUs fail analysis with an explicit diagnostic. The amd64 dependency
ordering is preserved. ARM64/RISC-V KDB/NETGRAPH options are extracted from their
actual generated GENERIC trees; existing IPv4/IPv6 option targets gain Netgraph
consumer visibility. No empty substitute option headers or SDK header fallback
are introduced.

All seventeen original C sources and their declared transitive headers compile
through the registered target C++ toolchains. The existing relocatable/CTF/
export/shared-link/debug/install pipeline handles both cross architectures.
Explicit module/source labels and kernel package assignments remain source-owned
BUILD metadata. No production Make parser, C behavior, probe/audit path or
output rewriting is introduced.

## Independent reference and dependency correction

The first temporary reference runner failed during nested log-directory setup,
before invoking Make. That report remains at
`/usr/obj/usr/src/bazel-cross-netgraph-make-20261101/`. After correcting runner
setup, 64 actual Make combinations passed and the four ng_socket combinations
failed: syscallsubr.h includes mount.h/vnode.h, requiring generated vnode_if.h,
but that module's SRCS omitted the dependency. The maintained Makefile now lists
vnode_if.h; ordinary Make rules generate it. No parent-header copy masks it.
The actual successful cases and failures remain at
`/usr/obj/usr/src/bazel-cross-netgraph-make-r2-20261101/`.

Only the four affected ng_socket cases were freshly repeated; all pass under
`/usr/obj/usr/src/bazel-cross-netgraph-make-r3-20261101/`. Each review row names
its successful reference explicitly. Commands, target parent ARCH_FLAGS,
object/generated inputs, resource counters and install METALOGs are retained.
Builds use all sixteen logical CPUs. Unprivileged NO_ROOT staging uses normal
-U/-M/-D flags; NO_XREF excludes linker.hints. No host installation or module
loading occurred.

## Actual comparisons

Four maintained `build-bsd bazel-test --arch arm64|riscv64` kernel-profile runs
each built 34 explicit module/install targets with the existing typed CTF/debug
settings. Receipts are at
`/usr/obj/usr/src/bazel-cross-netgraph-{arm64,riscv}-{plain,ctf}-r1-20261101/`.
The maintained frontend API, signing and publication behavior are unchanged;
the manual records this expanded candidate coverage.

All 34 no-debug module files match Make byte for byte. All 34 installed CTF/debug
modules match every ELF section and file offset except build-ID/debuglink
contents, including code/data, symbols, relocations, CTF and SDT sections where
present. Both native and Make debuglink CRCs validate against actual separate
debug files. Separate DWARF/build-ID/symbol/layout differences remain retained;
debugger source lookup and full debug-file identity remain unqualified. All 102
file/debug install records match destination, type, ownership, mode and tags.
Directory metadata and linker.hints are outside this cross file comparison.

Because a shared header target changed, all 34 existing amd64 module/install
targets were repeated with their exact prior settings. Every one of the 51
module/file-metadata/directory-metadata payloads matches the previous qualified
candidate byte for byte. Receipt:
`/usr/obj/usr/src/bazel-cross-netgraph-amd64-regression-20261101/`;
`amd64-regression.json` retains the comparison with the prior consolidated
seventeen-module candidate. This is not a new amd64 runtime or CTF qualification.

Reports, input/source hashes, direct-marker scan, input JSON and reproduction
scripts are retained at `/usr/obj/usr/src/bazel-cross-netgraph-review-20261101/`.
Kernel-profile runs intentionally build artifacts without executing target tests.
Resource counters are not a controlled CPU/RAM/disk performance comparison.

## Remaining gates

The bounded seventeen-C-source scan finds no direct SDT provider/schema or audit
marker. This does not establish absent observation in Netgraph core, headers,
network/socket subsystems or wrappers. No source was changed to remove probes.
Review control-message graph reconfiguration, socket credential/privilege checks,
queue behavior and error paths against existing tracing/audit coverage before
adding new instrumentation. Live event semantics and overhead remain unqualified.

Matching-kernel load/unload, graph/node control, socket/data/packet forwarding,
protocol checks, queue/failure behavior and security enforcement remain open.
Remaining Netgraph/core modules, full kernel/world/pkgbase production, debugger,
cache/input mutation and controlled CPU, aggregate memory, disk-I/O and allocated-
disk comparisons remain required.
