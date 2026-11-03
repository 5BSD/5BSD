# ARM64 / RISC-V routing and diagnostic modules

2026-11-03. Source-owned native declarations now build dummymbuf, fib_dxr,
dpdk_lpm4 and dpdk_lpm6 for ARM64 and RISC-V64. All four are present in both
retained parent-export-aware GENERIC selections. This is eight architecture/
module combinations, not complete kernel, driver or world coverage. Make stays
production/default; BIP stays excluded.

## Native graph and real dependency correction

Six C sources remain in their owning net, netinet and DPDK packages. Each
architecture uses its existing registered kernel C++ toolchain, configuration-
derived INET/INET6/global headers, offset generator, CTF conversion/merge,
ordered relocatable/export/shared links, separate debug and typed installation
rules. Original dummymbuf export-all and all four original object orders remain
explicit. No C source, original Make rule, compiler option or shared build rule
changes. Existing amd64 declarations remain unchanged.

The first ARM64 build rejected a real missing dependency: its inherited precise
CK view contained x86 headers and omitted ARM64 atomic headers. A new source-only
CK view lists the union of actual original ARM64/RISC-V consumed CK headers,
with visibility restricted to these three source owners. It does not widen or
replace the existing amd64 view. DPDK receives narrow visibility to the existing
target-derived INET/INET6 views. No fabricated configuration header or blanket
architecture compatibility relaxation is used.

## Independent original controls and comparisons

Sixteen original Make build/install controls pass: four modules, two
architectures, plain and CTF/debug enabled. Every compilation receives all 16
logical CPUs; independent control jobs run sequentially. The first controls
omitted parent-supplied SYSDIR before .PATH evaluation, so twelve failed while
dummymbuf passed; these remain rejected. Corrected controls pass all sixteen.
Parallel Make stdout interleaved DPDK commands, so fresh controls additionally
record per-object .meta commands using meta/nofilemon; no truncated command is
accepted as policy evidence. 8,357 source/header/generated-header/tool bindings
remain equal before and after the accepted controls.

Four normal maintained build-bsd format-5 kernel profiles pass, with explicit
--arch arm64/riscv64 and typed CTF/debug settings. Actual compact logs are fully
drained and dependency files/link parameters retained before switching profiles.
All 24 actual module compiler contexts match original effective flags and 3,056
canonical consumed source/generated-input pairs. An additional generated-offset
helper appears in three profile logs; it is not counted as another module source
or as complete bootstrap/helper hermeticity proof. Thirty-two actual ordered
link stages match original flags; initial links bind every ordered object input.

RISC-V original Make first supplies default -march/-mabi and later overrides
them with kernel settings. A rejected set-only flag comparison exposed this.
Actual original and native command expansion with the same hash-bound compiler
and -### proves equal effective triple, CPU, lp64 ABI and target-feature state.
The final comparison uses those effective ISA/ABI values, not both overridden
defaults. Include/forced-header contents are checked by actual consumed inputs;
output/dependency paths, random-seed paths and debug/macro source-map policy are
outside the semantic flag set. Complete original commands remain retained.

All eight plain installed modules match original Make whole-file bytes.
All eight CTF/debug runtime modules match every section's payload, offsets and
metadata except build-ID/debuglink values. Those sections' metadata also agree;
GNU SHA-1 note encoding and both actual debuglink CRCs pass. Complete merged CTF
payloads agree. All eight separate debug files differ; full DWARF/source lookup
remains open. Twenty-four original file/debug install records match destination,
type, owner/group, mode and package/debug tags. Directory metadata, linker.hints,
full kernel/module layout and complete pkgbase closure remain separate gates.

Earlier rejected inspections are retained: truncated stdout could not identify
an original compiler, a CTF inspection selected the strip target instead of the
original .ko.full link, and the set-only RISC-V option comparison described above.
The final result neither rewrites artifacts nor relabels failed builds as passed.

## Observability, frontend and remaining scope

A bounded scan of the six physical sources finds zero recognized SDT/DTrace/
CTR/audit marker candidates. Identical plain bytes and CTF/runtime section proof
preserve compiled behavior, but do not establish provider completeness, live
firing, event semantics or appropriate audit coverage. No probe source changes.

The existing build-bsd C frontend/backend and format-5 inputs carry the new
targets and architectures unchanged; no new CLI, SDK, security, signing,
staging or publication policy is introduced. The manual and completion plan
record this scope. Prepared SDK provenance, standalone debugger/source lookup,
alternate configurations, complete cross kernels/drivers/world/rescue/pkgbase,
bootstrap/hardware/combined publication, VM/module loading and controlled CPU,
memory, disk-I/O, allocated-disk and cache/sandbox testing remain required.
Resource counters and disk reserve guards are not performance comparisons.
Nothing is installed or loaded on the host.

Evidence under /usr/obj/usr/src/:

- bazel-cross-routing-work-r1-20261103/: exact before/after declarations, inputs,
  cohort, commands and reproduction scripts.
- bazel-cross-routing-arm64-plain-r{1,2}-20261103/: failed and passed requests;
  the other three requests use bazel-cross-routing-{arm64,riscv}-{plain,ctf}-
  r1-20261103 naming. Corresponding -actual-capture directories retain actual
  action/dependency/parameter hashes.
- bazel-cross-routing-make-r{1,2,3}-20261103/: rejected initial controls, corrected
  controls and accepted complete per-object command controls respectively.
- bazel-cross-routing-review-r{1,2,3,4}-20261103/: rejected inspection assumptions
  and final strict summary/supplement with 24 compiler and 32 link reviews.
- bazel-cross-routing-riscv-driver-r1-20261103/: actual non-compiling compiler
  command expansion and equal effective target-feature/ABI state.

Corresponding stdout/stderr records are retained beside these directories.
