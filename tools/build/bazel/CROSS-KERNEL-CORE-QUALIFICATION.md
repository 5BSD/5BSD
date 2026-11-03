# ARM64/RISC-V core kernel source owner (2026-11-03)

Status: the selected default GENERIC core source-owner products pass four
maintained composite-SDK profiles and independent original object/input checks.
This does not establish complete kernels or boot/runtime behavior.

## Source rules

The selected default GENERIC source owner covers 212 ARM64 and 209 RISC-V
original products. Ordinary C, stack-protector implementation, compressor and
assembly use separate native cc_library policies derived from their original
recipes. Stack-protector implementation omits recursive stack protection;
compression declares its source-owned zstd header root; assembly preserves
LOCORE and the original CTF invocation policy.

The existing genoffset producer and new OFFSET_TEST compile checks share the
maintained target layout flags. The auxiliary policy retains fcommon and omits
WERROR and CTF, matching the original recipes. ARM64 obtains its DTS macro
from the declared source-derived header, reported as an explicit extra input.
The firmware wrapper decodes the checked-in uuencoded source through native
bintrans and declares that output as an assembler input; it is not a prebuilt
firmware substitute from the SDK or original control tree.

A declared host artifact test independently decodes the source and checks the
full ELF payload and symbol ranges. Its private test controls accept the
untouched original object containing the 132,608-byte payload and reject
corrupted decoded and ELF payload copies. The actual native plain/CTF artifact
tests also pass; neither check executes
target firmware or establishes hardware behavior.

## Qualification

Four maintained format-5 build-bsd bazel-test profiles select target-matched
composite SDKs for ARM64/RISC-V plain and CTF/debug configurations. Compilation
uses all available logical CPUs. Captures explicitly retain selected kernel
compiler contexts, generators and all failed actions, together with the
complete raw execution log. Unselected successful host-tool compiler records
are not expanded or claimed as qualified.

Preparation and actual source/evidence bindings are retained under
`/usr/obj/usr/src/bazel-cross-kernel-core-preparation-r2-20261103` and
`/usr/obj/usr/src/bazel-cross-kernel-core-work-r1-20261103`.
The existing frontend supports these source-owned targets and the existing
host artifact test contract; no build-bsd.c, CLI, stage, signing, package or
publication interface change is required. This manual and plan track progress.

The final evidence ledger is
`/usr/obj/usr/src/bazel-cross-kernel-core-work-r1-20261103/qualification-summary.json`.
All four profiles and six declared artifact test invocations pass. Separate
fresh original Make plain controls and untouched CTF references cover all
421 products. Across 842 object configurations, allocated section metadata and
bytes, named symbols and runtime relocations match. All 421 plain objects are
whole-byte identical. Of 421 CTF configurations, 414 nonempty raw CTF payloads
match and seven have matching CTF absence (assembly/firmware/layout auxiliaries).
Separate DWARF differences remain retained; no debug parity or object rewriting
is claimed.

The compiler dependency ledger checks 103,994 logical pairs: 103,782 are raw
byte identical and 212 are independently reproduced KOBJ source-path provenance
pairs. Fourteen architecture/member controls use 28 independent invocations of
the maintained generator. Both architectures cover bus_if, clock_if, cpufreq_if,
device_if, linker_if, msi_if and pic_if. Original absolute-path and native
basename policies reproduce their respective raw headers exactly. Cached
headers are not counted as fresh generator executions. The audit binds actual
compiler outputs through CTF conversion actions to final artifact hashes.

The audit explicitly reports 424 additional ARM64 DTS version header inputs,
whose values match the original compiler definition. Firmware adds two separate
binary assembly-input contexts because compiler .d files omit .incbin payloads.
One fresh native decode action binds the checked-in uuencoded source to the
original 132,608-byte payload; the second configuration reuses that output.
These additions are not hidden in the ordinary dependency equality count.

An initial actual profile failed analysis because public MSI/PIC generated
header views were missing. Standard filegroup/header-provider views corrected
the declarations; the failed attempt remains retained. The first private input
observer also rejected comparing a pre-CTF hash directly with a post-CTF hash.
Its replacement verifies the actual conversion input/output chain, without
waiving object equality or changing product bytes.

All 212 distinct primary source hashes remain identical to original reference
bindings. The source audit records 1,813 lexical DTrace/SDT/audit marker lines
(pattern DTRACE|SDT_|AUDIT_|audit_), including declarations, calls and comments.
The marker-free source list is retained for semantic follow-up; counts establish
neither instrumentation completeness nor live delivery. Object comparisons
preserve the existing compiled instrumentation, without adding runtime probes.

Disk reserve guards completed without interruption. Timing/RSS/disk records
are retained observations, not a comparative CPU/memory/disk performance result.
No host installation, target module activation or reboot occurred.

## Remaining gates

Generated sources owned elsewhere, complete kernel ordered linking, other configurations, debug/source packages,
boot/runtime, full world/pkgbase/hardware publication, bootstrap/sandbox/cache
and comparative CPU/memory/disk I/O/usage remain unfinished.

Other helper execution-runtime declarations require the role audit described
in KOBJ-EXECUTION-RUNTIME-QUALIFICATION.md. Make remains production/default;
BIP remains excluded. No host installation, module activation or reboot occurs.
