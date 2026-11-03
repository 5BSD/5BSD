# Native ARM64 / RISC-V firmware modules

2026-11-03. Seventeen selected ARM64 and twelve selected RISC-V firmware modules
now build natively through Bazel. All 29 architecture/module combinations pass
plain and CTF/debug comparisons against fresh original Make. These are firmware
artifact and installation results, not hardware execution, complete architecture
support, full world/pkgbase or performance qualification. Make remains the
production/default backend; BIP remains excluded.

## Shared source-owned pipeline

`bsd_firmware_module.bzl` composes the existing native decoder, AWK generator,
compiler, CTF, object-alias, ordered-link/export, debug and installation rules.
The existing amd64_firmware_module API delegates to it with unchanged names,
paths and default policy. Cross products have architecture-scoped target/output
names. Architecture selection fails for unsupported values; no host fallback or
compatibility-tag relaxation is used. All generators use their existing exec
tool/runtime declarations. Neither Make output nor a pregenerated stub replaces
a native producer.

Cross compilation gains two optional existing-cc_library concepts:
local_defines and additional_compiler_inputs. They supply LOCORE/firmware symbols
and each real .incbin payload. The latter is essential because ordinary compiler
dependency files omit binary data. Defaults preserve prior cross consumers.
No compiler-policy, source C/assembly/AWK, original Make rule, SDK or security
policy change belongs to this cohort. All 17 owning BUILD files retain original
firmware image/specification order, raw/uu encoding, versions, exports and package
ownership; new cross declarations reuse that source-owned metadata.

Selected ARM64 products: ice_ddp; two Otus images; ten rtwn firmware leaves;
and t4/t5/t6/t7 Chelsio firmware configuration modules. RISC-V selects the two
Otus and ten rtwn leaves. ARM64 has 29 image instances (19 raw, ten decoded);
RISC-V has twelve (two raw, ten decoded). Selection uses retained actual
parent-export-aware GENERIC inventories. Image lists remain versioned source
metadata; optional images/other configurations and nonempty-license behavior
are not newly qualified. LiquidIO is not in this selected cross cohort; its
existing amd64 real-driver composition remains included in regression proof.

## Original Make and native qualification

All 58 original Make build/install controls pass, sequentially between jobs with
16 compilation slots per build. Explicit parent SYSDIR and actual target kernel
ARCH_FLAGS preserve source/path and architecture context. Complete per-object
meta/nofilemon command records prevent parallel stdout interleaving from being
mistaken for compiler evidence. All 8,402 before/after source/header/generated-
header/payload/Makefile/tool bindings remain stable. No host install occurs.

Four normal maintained build-bsd kernel profiles pass with explicit architecture
and typed CTF/debug settings: ARM64 plain/CTF select 155/172 targets, RISC-V
84/96. Actual compact logs are drained and compiler dependency/link parameter
files captured before the next profile. Twenty-nine registration AWK actions
bind the original specifications and script hash, and twenty decoder actions
bind the actual encoded sources. CTF-profile cached generators are not reported
as fresh executions.

All 140 actual module compiler contexts agree with original effective flags and
5,108 canonical consumed source/generated-input pairs. This includes 82 assembly
instances and 58 generated registration C instances. All original/native
registration source bytes agree. All 82 image/embedding instances preserve exact
raw/decoded payload bytes; embedded .rodata equals the complete payload. Each
binary input also appears with its actual digest in the compiler action, beyond
the normal depfile closure. Source/preprocessing language, symbols and compiler
tool hashes agree. Effective RISC-V ISA/ABI options preserve the previously
verified kernel override policy; debug/random/output/source-map path policy is
outside the semantic flag set and complete original commands remain retained.

All 116 actual link stages match original flags and initial object order. Every
ordered firmware alias input binds to its captured embedded object; generated
registration remains last. Final module ELF headers agree. All 29 plain modules
match original whole-file bytes. All 29 CTF/debug runtime modules agree in
section payloads, offsets and metadata except build-ID/debuglink values; those
sections' metadata, GNU SHA-1 note encoding and both actual debuglink CRCs pass.
Merged CTF agrees. All 29 separate debug files differ; standalone DWARF/source
lookup is still open. All 87 file/debug installation records match original
destinations, ownership, modes and package/debug tags. Directory metadata,
linker.hints and complete kernel/module pkgbase layout remain separate gates.

The shared amd64 refactor also passes a normal 114-target regression profile.
All 38 modules, separate debug files and install manifests match the current
pre-refactor aggregate's immutable captures exactly. Every selected payload is
independently receipt/manifest/content verified. This preserves current cached
results; it does not claim a fresh 38-module original Make rebuild.

The first generator inspection assumed every compact-log input had a digest;
an empty runfiles marker does not. That failed inspection is retained. The final
inspection explicitly requires and checks the actual source/script digests.
No build was accepted after failure, no artifact was rewritten, and no weak
whole-file/section comparison was reported as stronger proof.

## Observability, frontend and remaining gates

A bounded scan of firmw.S, fw_stub.awk and 29 architecture-specific generated C
instances finds zero recognized SDT/DTrace/CTR/audit marker candidates. Compiled
payload equality preserves observed instrumentation; it does not establish live
firing, firmware-load audit policy or provider completeness. No probe source or
firmware is executed by these inspections.

Existing build-bsd/backend format-5 target selection, --arch and typed settings
carry this work without new CLI or frontend-C behavior. The manual and completion
plan record the scope. Completed receipts bind their original prepared SDK/tool
state. Later receipt-bound tooling changes require fresh matching SDK snapshots;
never update an old receipt's hashes to reuse it. Separate userland target/exec
SDK work is not qualified by these kernel-profile results.

Complete cross kernels/drivers/world/rescue/pkgbase, alternate configurations,
bootstrap/native base Bazel packaging, hardware/combined publication, debugger
source lookup, actual firmware/device and VM/runtime behavior, and controlled
CPU/memory/disk-I/O/allocated-disk/cache/sandbox qualification remain required.
Resource counters/reserve guards are safety evidence, not performance comparison.
No host installation, module loading, upgrade or reboot occurs.

Evidence under /usr/obj/usr/src/:

- bazel-cross-firmware-work-r1-20261103/: guarded source changes, cohorts, inputs
  and reproduction commands/scripts.
- bazel-cross-firmware-{arm64,riscv}-{plain,ctf}-r1-20261103/: four normal passed
  profiles; corresponding -actual-capture directories bind actual actions.
- bazel-cross-firmware-amd64-ctf-r1-20261103/ and
  bazel-cross-firmware-amd64-regression-r1-20261103/: current amd64 regression.
- bazel-cross-firmware-make-r1-20261103/: all 58 original controls, commands,
  dependencies, metadata, stage files and before/after bindings.
- bazel-cross-firmware-generators-r{1,2}-20261103/: rejected empty-marker
  assumption and accepted actual producer/source/specification checks.
- bazel-cross-firmware-review-r1-20261103/: final artifact/compiler/input/link/
  install summary, bounded scan, declarations and reproduction scripts.

Corresponding stdout/stderr logs are retained beside these directories.
