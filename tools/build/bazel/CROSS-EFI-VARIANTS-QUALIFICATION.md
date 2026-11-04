# Cross EFI Forth/simple loader qualification (2026-11-04)

## Native model

The maintained `stand/efi/loader/variants.bzl` selects AMD64, ARM64 and RISC-V
through ordinary Bazel target configuration. ARM64 and RISC-V share the existing
Lua source/ABI/link model in `cross_profiles.bzl`. Interpreter flags, source,
version dependency and private interpreter archive remain explicit branches.
Every cross variant has 48 entry objects. Per-object RISC-V medium code-model
flags are preserved, including the interpreter object. Source-owner header groups
and narrow source exports declare the consumed files. Make metadata is used for
independent review, never parsed by a build action.

Forth uses native private Ficl, `version.veriexec` and no installed help file.
Simple uses no interpreter archive, the ordinary version input and FDT-aware help.
Each links native libefi, common FDT, EFI FDT and EFI libsa after its ordered
entry objects; Forth prepends private Ficl. Existing AMD64 public labels remain
stable. Cross images use their assembly-authored PE headers and binary extraction.
The selected default-Lua variants install no default-loader alias.

The shared firmware host artifact test now also checks Forth/simple ELF and PE
identity, entry, unresolved strong symbols/runtime dependencies, allocated bytes
across debug splitting, debuglink CRC and installation records. Simple's help is
a declared input. These tests inspect target files without executing target code.

## Qualification results

Four independent original Make builds have passed: ARM64/RISC-V Forth and simple,
with explicit original EFI/FDT/standalone/Ficl archive receipt bindings. No SDK
archive is replaced by a Bazel artifact. Before application, the shared source
model's full compiler flag lists and final object order were checked against all
192 original entry recipes. That recipe comparison does not prove executed Bazel
actions or final output parity; those native builds and reviews are in progress.

Original references under `/usr/obj/usr/src/`:

- `bazel-efi-loader_{simp,4th}-aarch64-make-r1-20261104`
- `bazel-efi-loader_{simp,4th}-riscv64-make-r1-20261104`

Both native cross builds pass their four artifact wrappers (boot1, gptboot,
Forth and simple). Each architecture has 92/96 direct raw allocated-section and
relocation matches; disk/gfx_fb differ in assertion filename strings for each
interpreter. Independent original compiler filename controls explain all four
entry differences. Existing original EFI/standalone controls and fifteen private
Ficl controls are checked against the new native archive, with original archive
member order preserved. Original link/debug/image recipes then establish matching
loadable ELF contents and complete PE bytes for both programs on both architectures.
Raw PE bytes differ and remain recorded. Full ELF/separate-DWARF byte equality is
not claimed. Debug splitting, debuglink CRC, actual help bytes and all installation
file metadata pass. All fifty prior Lua object/link/font captures per architecture
remain byte-identical after the shared profile refactoring.

Native evidence under `/usr/obj/usr/src/`:

- `bazel-cross-efi-variants-{aarch64,riscv64}-r1-20261104`
- `bazel-cross-efi-variants-{aarch64,riscv64}-object-review-r1-20261104`
- `bazel-cross-efi-variants-<arch>-<program>-controls-r1-20261104`
- `bazel-cross-efi-variants-{aarch64,riscv64}-payload-review-r1-20261104`
- `bazel-cross-efi-variants-{aarch64,riscv64}-lua-review-r1-20261104`

Real action reviews now bind 96 successful executed compiler producers per
architecture and 4,857 ARM64 / 4,891 RISC-V original-consumed input digests.
They verify exact original object order, all nine native archive occurrences
across the two links, configured linker scripts, both image producers and both
ordinary/veriexec version-generator dependencies. Original-object digests are
bound through the actual link inputs. AMD64 passes five artifact wrappers and
retains all 225 prior qualified captures. Across the three profiles thirteen
Bazel wrappers execute successfully; this is component qualification.

The first two execution-log audits failed in the review helper: CppLink uses a
response file, while the helper compared the unexpanded command. Failed helpers
and diagnoses are retained in input-review-r1 for both architectures. No product
object or image changed. The corrected input-review-r2 reconstructs the declared
response bytes from the configured action graph and requires their SHA-256 to
match the actual executed response-file input digest before expansion. It never
trusts a mutable execroot file. Source/object/archive digests and all 48 link
positions per program are checked. Both response files per architecture pass.

Official execution-log conversion is expensive because complete execution-tool
input lists are expanded. Selected records are now retained with original log,
converter and record-file hashes before validation, allowing subsequent audit
iterations to reuse evidence without another full conversion. This does not
claim a faster converter or complete build-cache/performance qualification.

Additional evidence under `/usr/obj/usr/src/`:

- `bazel-cross-efi-variants-{aarch64,riscv64}-actions-r1-20261104`
- `bazel-cross-efi-variants-{aarch64,riscv64}-selected-actions-r1-20261104`
- `bazel-cross-efi-variants-{aarch64,riscv64}-input-review-r2-20261104`
- `bazel-cross-efi-variants-amd64-r1-20261104`
- `bazel-cross-efi-variants-amd64-regression-review-r1-20261104`
- `bazel-cross-efi-variants-final-review-r1-20261104`

The consolidated review binds these reports, qualification receipts and source
hashes. A separate commit binding is recorded after the reviewed files commit.

The native Bazel build reports retain 552.448 seconds / 7,193 sandboxed processes
for ARM64, and 40.285 seconds / 549 sandboxed processes for RISC-V. ARM64 reports
1,158 action-cache hits and RISC-V 7,804. The SDK verification, analysis context,
cache warmth and initial targets differ; these numbers are not a fair comparative
performance result. A large execution-tool rebuild occurred in the ARM64 run.
Its cause and cross-profile execution-tool reuse need review. `/usr/bin/time -l`
output is retained with the qualifications; client maximum RSS does not measure
the aggregate Bazel server/worker/compiler memory peak.

## Remaining system gates

The maintained build-bsd C frontend was reviewed: format-5 target lists, typed
settings, architecture and jobs already cover this construction. No new frontend
switch is needed. The maintained manual describes the new candidate scope.
Builds are development qualifications using sixteen jobs. No publication, host
installation, reboot or firmware VM is authorized by these checks.

Complete bootloader aggregation, remaining entry/interpreter/option profiles,
shared userland warning policy (`werror=false`), full world/kernel/pkgbase,
firmware/runtime, bootstrap/output-query/reproducibility, sandbox/cache and
comparative CPU/memory/disk performance gates remain open. Make remains the
production backend; BIP remains excluded. This contribution does not establish
verified boot or protection against compromised root.

## Input and review-cost observation

One retained RISC-V firmware compiler action lists 4,346 file inputs, including
4,104 beneath the SDK sysroot, despite the freestanding compilation's -nostdinc.
The declared consumed source inputs still match Make. This does not prove an
incorrect build, but broad toolchain inputs can increase invalidation and audit
expansion costs. Review a distinct minimal freestanding toolchain input closure
for boot/kernel contexts, preserving actual compiler/resource/runtime inputs and
validating native/cross ABI and cache behavior. Do not hide required inputs or
disable dependency validation to reduce the count.

The host was concurrently loaded (about 31 on sixteen CPUs) during the retained
ARM64 conversion. Its wait is not a reliable standalone performance benchmark.
