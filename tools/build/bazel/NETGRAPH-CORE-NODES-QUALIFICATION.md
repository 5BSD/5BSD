# New Netgraph core and node modules on three architectures

2026-11-01. Eighteen additional modules now have native source/object/link/install
candidates for amd64, ARM64 and RISC-V64: netgraph core and ng_bpf, ng_bridge,
ng_deflate, ng_device, ng_eiface, ng_ether, ng_gif, ng_iface, ng_ksocket, ng_l2tp,
ng_macfilter, ng_nat, ng_netflow, ng_ppp, ng_tty, ng_UI and ng_vjc. These were
previously missing native declarations on all three architectures. This does
not complete Netgraph, all modules, or a bootable Bazel kernel. Make remains
the production backend; BIP is excluded.

## Source-owned native graph

`sys/netgraph/nodes.bzl` owns one named-field source/header/dependency/option
inventory for all three targets. The BUILD file instantiates ordinary header
libraries and the maintained native module object/artifact macros from that
inventory. The twenty-three original C translation units include the existing
BPF and SLIP reachover sources and three NetFlow sources. Narrow Netgraph-only
source/header exports preserve package ownership; no whole-tree include escape
or runtime Make parser is introduced. Named fields and shared common dependencies
keep architecture source lists from drifting apart.

BPF options are extracted from each target's actual generated GENERIC tree.
The previously qualified Netgraph KDB/NETGRAPH/network option selectors are
reused. Netgraph core preserves Make's export-all policy; nodes retain default
exports. Existing relocatable, CTF/export, final link, separate debug and install
rules are reused. No C, Makefile, tracing/audit path, source probe or output
rewriting changes are introduced. The distinction between BUILD declarations
and loaded Starlark constants follows Bazel's maintained
[BUILD/loading model](https://bazel.build/concepts/build-files).

All six runs use the maintained `build-bsd bazel-test` kernel profile with the
registered freestanding C++ toolchains, including amd64. The native host SDK
provides execution tools. For each of the six successful configurations, the
execution-log audit finds all twenty-three actual Netgraph compile actions,
with the selected target triple, -nostdinc/-ffreestanding and no SDK include-file
inputs. This is real target compilation, not foreign execution or a host-header
substitute. No frontend API, signing or publication change is required; the
manual records expanded candidate coverage.

## Real independent comparison

All 108 independent Make build/install combinations pass: eighteen modules,
three architectures and CTF/debug disabled or enabled. Commands, queried target
ARCH_FLAGS, objects, generated files, resource counters and METALOGs are retained
under `/usr/obj/usr/src/bazel-netgraph-new-make-20261101/`. Builds use all sixteen
logical CPUs. Unprivileged NO_ROOT staging uses normal -U/-M/-D flags; NO_XREF
excludes linker.hints. No host installation or module loading occurs.

Native receipts use
`/usr/obj/usr/src/bazel-netgraph-new-{amd64,arm64,riscv}-{plain,ctf}-r4-20261101/`.
Each run selects 36 explicit module/install targets. All 54 no-debug module files
match Make byte for byte. All 54 installed CTF/debug modules match every ELF
section and file offset except build-ID/debuglink contents, including code/data,
symbols, relocations, CTF and SDT where present. Both native and Make debuglink
CRCs validate against actual separate debug files. Separate DWARF/build-ID/
symbol/layout differences remain retained; debugger source lookup and full
debug-file identity remain unqualified. All 162 file/debug install records match
destination, type, ownership, mode and package/debug tags. Directory metadata
and linker.hints are outside this file comparison.

The initial native load failed because struct values were placed directly in a
BUILD context. The inventory now resides in an ordinary .bzl module. Subsequent
compile failures identified missing real SCTP/libalias transitive headers; those
headers are explicitly declared. No compiler isolation was weakened and no C
behavior changed. The failed r1/r2/r3 attempts and commands remain retained.
Final comparison, compiler audit, input/source hashes, marker scan, input JSON
and reproduction scripts are at
`/usr/obj/usr/src/bazel-netgraph-new-review-20261101/`.

Kernel-profile receipts intentionally select artifacts without executable tests.
Counters/logs are not a controlled CPU, aggregate memory, disk-I/O or allocated-
disk performance benchmark. Full source bootstrap/compiler qualification also
remains separate from this prepared-SDK comparison.

## Reconciled coverage and remaining gates

Fresh architecture-checked recursive Make inventories are retained under
`/usr/obj/usr/src/bazel-netgraph-new-inventory-20261101/`:

| Target | Selected leaf KMODs | Direct amd64 macro declarations in selected directories |
| --- | ---: | ---: |
| amd64 | 729 | 124 |
| ARM64 | 615 | 115 |
| RISC-V64 | 543 | 115 |

The macro count is explicitly a source inventory, not target compatibility,
complete configuration coverage, module loading or a runtime pass. Separate
component evidence establishes the 115 current ARM64/RISC-V module candidates.
Netgraph now has 35 core/node candidates; seven selected Bluetooth modules and
ng_mppc still lack declarations. MPPC's source/configuration switches must be
modeled explicitly rather than assuming GENERIC enables compression/encryption.

The bounded twenty-three-C-source scan records four SDT schemas in ng_base.c;
other scanned sources have no direct provider/schema/audit marker. Header/core/
network observation remains separate. Live probe arguments, socket/control/data
semantics, routing/NAT/NetFlow/BPF/bridge/compression/PPP behavior, queues and
failure paths need matching-kernel tests. Review privileged graph/control and
socket authorization against existing audit coverage before adding new hooks.
Complete kernels/module sets, world/pkgbase production, debugger, cache/input
mutation and controlled resource comparisons remain open.
