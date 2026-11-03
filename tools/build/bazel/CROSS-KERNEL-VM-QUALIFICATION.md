# ARM64/RISC-V kernel VM conversion (2026-11-03)

Status: selected default GENERIC built-ins pass native compilation and strict
original Make comparison on ARM64 and RISC-V.
This is not evidence of complete Bazel cross kernels or runtime compatibility.

## Source rules

`sys/vm/BUILD.bazel` selects the 24 default GENERIC VM subsystem C sources
for each architecture. They use the existing native `cc_library` built-in
policy and typed CTF conversion, without loadable-module ABI flags. This
selection includes the pagers, UMA, faults, mappings, page management and
swapout. Runtime VM implementation and instrumentation are unchanged.

Ten option headers per architecture are extracted from that architecture's
maintained config output. Their contents are not copied into BUILD files.
The existing declared offset and vnode interface producers supply generated
interfaces. Ten source owners declare 53 physical header members observed in
the original compiler dependencies; native dependency discovery is checked
against actual compilation. No Make queries or original prebuilt
objects are used to implement these targets.

## Completed selected qualification

The retained preparation is under
`/usr/obj/usr/src/bazel-cross-kernel-vm-preparation-r1-20261103`.
Its original input selection covers 6,870 consumed occurrences across the
48 original objects. Static review establishes the selected source lists,
option names, physical header existence and original audit hashes only.

Four maintained format-5 `build-bsd bazel-test` profiles pass: ARM64 and
RISC-V, each with plain or CTF/debug settings. All four declared DTS host
artifact test invocations pass. Actual action captures finish before switching
configurations. Fresh independent Make plain controls use separate object roots;
the original default CTF/debug controls are retained unchanged.

The final record is
`/usr/obj/usr/src/bazel-cross-kernel-vm-work-r1-20261103/qualification-summary.json`.
Across 96 object configurations, all allocated section metadata/bytes, named
symbols and runtime relocations match the independent originals. All 48 plain
objects are whole-byte identical; all 48 CTF payloads match exactly. Separate
DWARF bytes differ and source lookup remains unqualified. There is no object,
source-path or output-byte rewrite in these comparisons.

The 96 actual compiler contexts match 13,740 original physical consumed
identities and hashes, including generated options and vnode interfaces.
ARM64 adds 48 explicitly reported source-derived DTS version header inputs;
their values match the original compiler definition. The audit does not remove
those additions from an assertion of identical dependency sets.

The retained source observation covers 24 distinct C files and 122 lexical
DTrace/SDT/audit marker lines. Their hashes are unchanged. Runtime section and
relocation comparison preserves the compiled instrumentation metadata; it does
not establish live probe firing, audit completeness or workload overhead.

The existing frontend accepts these source-owned targets without new CLI
inputs, staging, signing, packaging or publication behavior; no build-bsd.c
change is required for this source conversion. No new frontend, package,
bootstrap, sandbox, cache or performance qualification is claimed here.

## Remaining gates

Complete cross-kernel source inventory, ordered linking, other configurations,
separate DWARF/source lookup, boot/runtime tests, package closure,
bootstrap/sandbox/cache checks and comparative CPU/memory/disk I/O/usage remain
unfinished. This cohort does not make a complete kernel or installed system.
Make remains production/default and BIP remains excluded.
