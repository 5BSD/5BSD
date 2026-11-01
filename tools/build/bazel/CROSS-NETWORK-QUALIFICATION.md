# ARM64 / RISC-V64 TCP and virtual-interface modules

2026-11-01. Explicit native declarations cover fifteen module candidates:
cc_cdg, cc_chd, cc_cubic, cc_dctcp, cc_hd, cc_htcp, cc_newreno, cc_vegas,
bridgestp, if_disc, if_edsc, if_enc, if_gif, if_gre and if_me. Each is selected
by both architecture-checked GENERIC Make inventories. This is build/install
qualification for those candidates, not a complete network stack/kernel/module
set or runtime transport test. Make remains the production backend; BIP is
excluded.

## Native source ownership

The eight TCP modules share the existing maintained _CC_MODULES source/dependency
table across amd64 and cross declarations. Virtual/tunnel interfaces keep their
explicit source/header dependencies, including separate IPv4/IPv6 translation
units. All nineteen original C sources compile through registered target C++
toolchains. IPv4/IPv6, IPsec, kernel TLS and RSS option contents are extracted
from each target's actual generated GENERIC config tree, including legitimate
empty headers. Existing network option targets gain actual network consumer
visibility; no substitute option values or SDK headers are used.

The established relocatable/CTF/export/shared-link/separate-debug/install pipeline
is reused. Shared export-all for if_gif and bridgestp is preserved; other modules
retain their export policy. No C behavior, probe/audit path, Makefile, production
Make parser or artifact rewriting changes are introduced. Existing amd64 source
selections and dependency lists remain unchanged.

## Independent Make comparison

Fresh independent Make build/install runs passed all sixty combinations:
fifteen modules, two target architectures and CTF/debug disabled or enabled.
Commands, target parent-kernel ARCH_FLAGS, objects/generated inputs, resource
counters and install METALOGs are under
`/usr/obj/usr/src/bazel-cross-network-make-20261101/`. All sixteen logical CPUs
are available. Normal NO_ROOT and -U/-M/-D flags stage without host installation;
NO_XREF excludes linker.hints. No module was loaded.

Four maintained `build-bsd bazel-test --arch arm64|riscv64` kernel-profile runs
each built thirty explicit module/install targets with the existing typed
CTF/debug settings. Receipts:
`/usr/obj/usr/src/bazel-cross-network-{arm64,riscv}-{plain,ctf}-r1-20261101/`.
No frontend API, signing or publication behavior changes are needed; the manual
records this expanded candidate coverage.

All thirty no-debug module files match Make byte for byte. All thirty installed
CTF/debug modules match every ELF section and file offset except build-ID/
debuglink contents, including code/data, symbols, relocations, CTF and SDT where
present. Both native and Make debuglink CRCs validate against actual separate
debug files. Separate DWARF/build-ID/symbol/layout differences remain retained;
debugger source resolution and full debug-file identity remain unqualified.
All ninety file/debug install records match destination, type, ownership, mode
and tags. Directory metadata and linker.hints are outside this file comparison.

The full reports, input/source hashes, bounded marker scan, input JSON and
reproduction scripts are retained at
`/usr/obj/usr/src/bazel-cross-network-review-20261101/`. Kernel-profile runs
intentionally select artifacts without executing target tests. Captured resource
counters do not establish a controlled CPU/RAM/disk performance comparison.

## Observability and remaining gates

The bounded C-source scan records three SDT schemas in if_gif.c and three in
if_gre.c. Other scanned sources have no direct provider/schema/audit marker;
header-defined and TCP/network/core observation remain separate questions.
Code/SDT/CTF preservation does not demonstrate live firing, argument semantics,
audit event delivery or overhead. No probe was removed to obtain parity.

Matching-kernel load/unload, interface create/destroy, IPv4/IPv6 tunnel and IPsec
traffic, bridge-state transitions, queues/errors and privilege/MAC checks remain
open. TCP algorithms require real throughput/latency/loss/ECN/congestion and
failure testing; no transport performance result is implied by identical
artifacts. Complete kernels/module sets, world/pkgbase production, debugger,
cache/input mutation and controlled CPU, aggregate memory, disk-I/O and allocated-
disk comparisons remain required.
