# KOBJ execution runtime correction (2026-11-03)

Status: failure reproduced and corrected; selected ARM64/RISC-V composite
plain networking profiles pass. This is not complete cross-kernel qualification.

## Finding and correction

The maintained ARM64 composite-SDK networking profile failed in BSDKobjInterface
for ifdi_if: the native awk process's loader rejected the target libc with
"unsupported machine". The default library declarations in bsd_kobj.bzl used
the selected target sysroot for libc and libsys despite execution-configured
tools. SDK ELF inspection confirms four incompatible declarations across the
ARM64 and RISC-V SDKs. The native SDK did not expose this architecture mismatch.

The correction selects the existing execution-runtime libc/libsys labels.
The source-built libm remains execution-configured. It changes neither the
original AWK generator nor its source-basename provenance policy and does not
rewrite generated headers or object bytes. No SDK snapshot, target compiler
flags, runtime kernel code or instrumentation is changed.

The existing maintained format-5 build-bsd bazel-test route and SDK runtime
interface supply these inputs. There is no new CLI, configuration, staging,
signing, installation, packaging or publication contract; build-bsd.c and
backend interfaces need no change. The manual and plan track the correction.

## Retained evidence

The unchanged failing profile is
`bazel-cross-kernel-network-composite-arm64-plain-r1-20261103` under the standard
object root `/usr/obj/usr/src`. Its complete execution.compact, command/event
logs and loader diagnostic are retained. The work-root
`bazel-cross-kernel-kobj-composite-runtime-r1-20261103` binds source files,
SDK ELF inspection, the before/after correction and disk budget result.
The job used all 16 available compilation CPUs; the disk reserve did not fire.

The first private broad capture was stopped to avoid expanding thousands of
unrelated successful host-tool compiler records into several GB of JSON.
Its partial output remains. The r3 capture explicitly selects networking
compiler contexts, generator/link actions and every failed action; it retains
the complete raw execution log unchanged. It does not establish host-tool
compilation parity or accept the failed overall build.

## Completed selected qualification

The corrected ARM64 and RISC-V composite profiles pass using the maintained
frontend. All 175 final plain objects (89 ARM64, 86 RISC-V) are byte-identical
to untouched original Make outputs, including runtime sections, symbols and
relocations. Five ARM64 KOBJ generators actually execute with 20 bound native
ELF awk/library inputs. RISC-V reuses cached generator outputs: its two consumed
KOBJ header members independently match the maintained-generator controls. No
fresh RISC-V generator execution is claimed or forced.

All 175 final compiler outputs are bound to actual retained compiler contexts.
Of these, 45 ARM64 contexts come from successful compiles in the initial failed
attempt; their output digests equal the final captured artifacts. The other
130 contexts are from corrected successful profiles. This does not turn the
initial overall failure into a passing build.

The input ledger contains 27,140 raw exact pairs and 13 separately recorded KOBJ
provenance-policy pairs. Independent absolute-source and source-basename
generator controls reproduce those header bytes without rewriting them. The
pre-correction helper is retained and bound because only its execution-library
labels changed; generator and source provenance policy remain unchanged.
ARM64 explicitly adds 89 source-derived DTS header inputs, whose values match
the original macro; RISC-V adds none.

The final source/evidence record is
`/usr/obj/usr/src/bazel-cross-kernel-kobj-composite-runtime-r2-20261103/qualification-summary.json`.
Timing and time -l observations are retained. The failed run built a cold
host-tool closure and successful runs reused caches; their elapsed times are
not a comparative performance benchmark. Parent-process maximum RSS is not
proof of aggregate build memory consumption.

## Remaining gates

Audit other helper and caller declarations by input role. Current source still
contains target-sysroot library references in CTF/module, RPC filtering,
device-ID, locale, crunch and boot-image execution paths. These require
individual classification and composite execution qualification. Do not
globally replace target-sysroot inputs: pkg-create's abi_file intentionally
inspects target ABI data and must remain target-configured. Target preprocessor
headers must also be distinguished from executable runtime inputs.

The interpreter, ELF loader and makeobjops system() shell dependencies remain
part of the full sandbox/host closure audit; this correction is not hermeticity
proof. Other configs/CTF profiles, full kernel/link/source/debug/boot/runtime/
package qualification, bootstrap, cache behavior and comparative CPU/memory/
disk I/O/usage remain open. Make remains production/default; BIP is excluded.

## Broader static role audit (2026-11-03)

The follow-up ledger at
`/usr/obj/usr/src/bazel-execution-runtime-role-audit-r2-20261103` inspects 538
literal target-sysroot library references across 185 BUILD/bzl files, resolving
public rule attribute configurations and relative loads. It classifies 380 as
intentional target inputs and 148 as host execution-runtime candidates. Six
references occur in variables shared by target tests and host generation
(file2c and DTS fixtures); these require distinct input lists. Four references
remain unresolved by the bounded static data-flow observer. No source parsing
errors occur, but this does not establish complete dynamically computed label
coverage, action execution or hermeticity.

Intentional target uses include ordinary target test runtime files, pkg-create
ABI inspection and DTrace drti target objects. They must retain target identity.
Host candidates include 29 FIDL compiler runtime lists and CTF/module, RPC,
locales, syscall-table, device-ID, crunch, boot-image and other generators.
Actual ELF inspection of the four distinct candidate library names in all
three frozen SDKs confirms target architecture in sysroot and native x86_64
in execution-runtime; eight foreign SDK/library pairs are incompatible with
native execution. This is declaration evidence, not a claim that all candidate
actions have failed.

An isolated two-helper candidate selects execution-runtime libraries for cross
module CTF conversion/merge and export processing. It is prepared only. Before
applying it, run the unchanged nullfs CTF/debug path against a composite SDK,
retain actual action evidence, then qualify corrected ARM64/RISC-V outputs and
inputs. Other classified families require their own meaningful action/output
checks. A global replacement would corrupt intentional target inputs.
