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
module CTF conversion/merge and export processing. The unchanged ARM64 nullfs CTF/debug profile reproduced the
loader architecture rejection in both converter actions; failed actions and
inputs are retained. The two-helper correction is now applied. Both corrected
ARM64/RISC-V frontend builds and captures pass, and ten converter/merger/export
actions bind 74 native ELF tool/library inputs. This proves host runtime
selection only; complete target artifact qualification remains rejected. Other classified families require their own meaningful action/output
checks. A global replacement would corrupt intentional target inputs.

## Rejected module CTF metadata (2026-11-03)

The strict nullfs target review rejected the corrected ARM64 module's raw CTF.
Independent ctfdump observations find all 69 named object/type mappings agree
with the older original artifact before native export localization. After that
transformation, five globals have different type associations; installed output
preserves those wrong associations. SDT probe/provider records, a sysctl record
and the two exported vnode operation vectors are affected. This is a semantic
metadata error, not an allowed compression or debug-path difference.

The RISC-V installed mapping agrees with its older Make reference, but earlier
stage differences and zero type entries mean that raw agreement does not prove
semantic correctness there. The selected pipeline needs a semantic regression
that follows actual symbol/type associations through localization, final link
and debug splitting. Determine whether the maintained Make pipeline and other
module helpers need the same correction, using independent staged controls.
Do not rewrite outputs, disable CTF or replace the SDK to hide the difference.

Actual linker inputs are bound to each captured action and frozen SDK receipt;
the shared execution tree's external SDK alias can switch with another profile
and must not be used as historical tool identity. The selected ARM64/RISC-V
linkers and original world linker have distinct byte hashes while all report
LLD 21.1.8. A causal linker defect is not established by those hashes.

Evidence is retained in
`/usr/obj/usr/src/bazel-cross-module-execution-runtime-preparation-r1-20261103`:
unchanged failure, corrected commands/captures, host-runtime-review.json, and
ctf-symbol-order-diagnosis-r2/diagnosis.json with raw observer output. Initial
strict artifact review failures remain recorded. The second diagnostic observer
preserves duplicate local symbol names as type lists; it does not collapse them.
Disk guards retain the enforced 16 GiB reserve. The same-leaf measured allocation
justifies the explicitly recorded 17.75 GiB corrected-profile admission gate;
no compiler, artifact or test acceptance condition is weakened.

## Existing source fix and stale foreign SDK tools (2026-11-03)

Source/history review recovered the already committed CTF-aware LLVM objcopy
fix, d7f9be55deb, and its maintained semantic/format regression suite. It retains
original symbol identities through transformations; the previously rejected
name-based post-localization merge is not the solution. The pipeline ordering
must not be redesigned merely to accommodate an obsolete SDK tool.

The explicit unchanged-tool format controls at
`/usr/obj/usr/src/bazel-cross-module-ctf-sdk-diagnosis-r1-20261103` pass all
65 checks for the native r4 SDK and fail localization for both foreign r4 SDKs.
The native SDK selects objcopy cb860873912726be094227e17e54326c990c0ff5a41239173cb24a668e5f7f7d;
ARM64 selects ccf032820f7a2b10cd26c1f445946a37369462066c7ac554b09fb1751713e1fc;
RISC-V selects 6b46d4de747038a2fc597d1ce81dff6db556599bf240aa1d800aa9b0641b3253.
All are unchanged static execution binaries. Their recorded origins are each
architecture's world/tmp/usr/bin tools; the foreign stages are stale despite
matching the nominal LLVM version. No SDK or receipt was patched.

Next rebuild foreign cross-tools through maintained targets, create new SDK
snapshots/receipts, run the existing format/semantic suites on each selected
tool and rerun the real module profiles. Preserve the failing r4 snapshots.
Extend maintained qualification selection to cover each SDK's actual tools;
version strings or native-SDK success cannot establish foreign SDK capability.
Whole native Bazel toolchain bootstrap remains a separate open requirement.

Storage recovery used OS copy_file_range/ZFS copy-on-write block cloning for
identical canonical archives in 31 completed private repository caches. Every
archive hash and verified complete cache identity remains unchanged. It changes
no source, SDK, tool binary, receipt or artifact. Records are retained in
bazel-completed-cache-blockclone-r1-20261103 and r2-20261103 under /usr/obj/usr/src.
This is workspace storage recovery, not a comparative build I/O benchmark.

## Controlled bootstrap refresh in progress (2026-11-03)

The original libcrypto controls have released the shared compiler and world/tmp
window. The ARM64 bootstrap refresh is running with 16 compilation jobs at
`/usr/obj/usr/src/bazel-objcopy-bootstrap-refresh-aarch64-r1-20261103`.
This is an in-progress build, not a refreshed-SDK or CTF qualification result.
Its disk guard admits at 18 GiB free and preserves a 16 GiB reserve.

The invocation derives XMAKE from the recorded target profile and rechecks the
queried context before building. Only the query's metadata flags and root-only
Makefile selection are removed for source-owner leaf invocation. libllvm is
built without installation; llvm-objcopy uses its maintained all/install rules
with DESTDIR set to the selected world/tmp, as in cross-tools. The observer
hashes all target headers/libraries and source/profile bindings before and
after, retains actual commands/logs and time -l observations, and runs the
existing format suite on the resulting staged tool. No result is accepted
until these checks finish. Frozen r4 SDKs remain unchanged.

Do not replay the complete cross-tools installation over a completed foreign
sysroot: some cross-tools libraries are native bootstrap products installed
before target world libraries in the normal staged build. This repair must
preserve the completed target ABI inventory. The normal frontend already
accepts newly staged tools through fresh SDK plans and receipts; no CLI,
configuration, security, package or publication interface changes here.

A third completed-cache block-clone pass also finished with unchanged cache
identities. Its records are under bazel-completed-cache-blockclone-r3-20261103;
this is storage recovery only, not build performance evidence.


## ARM64-stage tool qualified; RISC-V refresh active (2026-11-03)

The ARM64 bootstrap LLVM library and objcopy program rebuild/install completed.
The broad inventory observer rejected its program debug output as a change under
usr/lib. Preserve that initial rejection: target-before/after.json differ in
exactly usr/lib/debug/usr/bin/llvm-objcopy.debug. The follow-up proves the
installed file equals the actual newly built separate native debug artifact,
checks its native ELF machine, and verifies every other inventory entry is
unchanged. This is an explicit program install output, not a target library or
an exception for the debug tree. Source/profile bindings also remain unchanged.
The build record is bazel-objcopy-bootstrap-refresh-aarch64-r1-20261103;
the accepted narrowed inventory review and format results are
bazel-objcopy-bootstrap-refresh-aarch64-review-r2-20261103, under /usr/obj/usr/src.

The refreshed staged tool SHA256 is
04c5e1a27322410954f2922a382eb010bb367ee67fc7496ec35ef02c1e8067e5.
It passes all 65 maintained format checks. The r4 frozen SDK is unchanged and
still contains its previously rejected tool; no fresh SDK or real module pass
is claimed yet. LLVM rebuilding took 694.77 elapsed seconds with 16 jobs; raw
time -l CPU, RSS and block-I/O observations are retained. The reported maximum
RSS is not an aggregate parallel-build memory peak, and this is not a Make
versus Bazel performance comparison. The disk reserve did not interrupt it.

The RISC-V refresh is running at
bazel-objcopy-bootstrap-refresh-riscv64-r2-20261103. Its observer explicitly
proves the single program debug output against its built bytes if that path
changes, while requiring all other target inventory entries unchanged. It
retains the same 18 GiB admission / 16 GiB reserve and all-CPU build policy.
No RISC-V refresh or format result is claimed until that run terminates.

Existing nullfs_artifacts_test remains AMD64 ET_REL-specific and uses the
older target-tool audit contract. A private follow-up test design reuses the
independent CTF graph parser with explicit shared-module opt-in and the existing
host-artifact rule; this must inspect actual foreign modules, their SYMTAB
links and source-policy global types. It is not implemented or Bazel-qualified.
Do not count the existing AMD64 test as foreign semantic module coverage.
