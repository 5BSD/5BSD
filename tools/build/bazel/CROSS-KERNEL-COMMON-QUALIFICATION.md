# Native cross-kernel common built-ins (2026-11-03)

This checkpoint establishes the native compilation foundation for complete
ARM64/RISC-V kernels. It does not link or boot complete Bazel cross kernels.

## Source-owned build rules

`cross_generic_kernel.bzl` declares ordinary `cc_library` built-in objects and
existing typed CTF conversions. It preserves the architecture's compiler,
stack protection, warnings and common ABI policy. Built-ins have no KLD_MODULE,
KLD_TIED or loadable-module PIC policy. RISC-V retains its original PIE policy.
Source owners declare selection and exceptional flags; no build-time Make
query, generated Makefile parsing or prebuilt-object substitution is used.

Qualification covers default GENERIC in opt mode, with explicit plain or
CTF/debug settings. Other configurations remain unqualified.

The first owners select 46 ARM64 and 48 RISC-V common libkern C sources. ARM64's
crypto wrapper additionally retains its original SIMD/O3 policy and explicitly
permits just the required target SDK headers. `bsd_sdk_headers` can now select
exact compiler resource members without embedding a Clang version; its existing
complete-resource default is unchanged. The wrapper declares arm_neon.h,
arm_bf16.h, arm_vector_types.h and ssp/ssp.h. The independent original control
binds these four headers before compilation.

The kernel toolchain splits standard-include suppression from freestanding
compilation. Ordinary targets retain both features. The crypto owner disables
only `bsd_kernel_no_standard_includes`, leaving freestanding behavior intact.
Actual input review checks target-header origins and hashes, not just identical
content from a different namespace.

ARM64's LINUX_DTS_VERSION macro is produced from the maintained
sys/dts/freebsd-compatible.dts property. The version number is not duplicated in
native metadata. A declared native awk action emits the header; the host
artifact test independently compares the produced macro with its declared
source property. Additional private checks change the property and reject
missing, duplicated and malformed definitions. The dependency audit explicitly
reports this new header alongside original consumed inputs and verifies its
value against the original compiler -D argument. It does not silently remove
that difference from a claim of complete input equality.

Execution generators and CTF conversion use explicit execution-runtime
libraries. A composite target sysroot must not supply the dynamic libraries for
native config, awk or other host tools. Native SDK and composite ARM64 SDK
profiles qualify these paths without executing target code.

## Public archive API correction

A genuine composite profile exposed a defect in libc++'s custom archive action:
the selected archiver was in the host toolchain, but the declared caller SDK
filegroup contained the target toolchain path. The action failed rather than
falling back to a host command.

`native_cc.bzl` now delegates archive actions to the public
`cc_common.create_linking_context_from_compilation_outputs` API. The selected
C++ toolchain supplies its archive tool inputs. Each original explicit variant
keeps its object order and filename. Automatic PIC sibling creation is disabled
for that archive invocation only, because the rule has already compiled and
named its separate regular/PIC variants. Compilation PIC flags are unchanged.
The obsolete archive_inputs attribute and its sole libc++ caller are removed.
No private rules_cc provider fields, broad all_files input set, executable-path
guessing or shell wrapper is introduced. The original configured rcsD archive
policy remains checked.

The successful composite PIC archive retains all 55 original ordered compiler
inputs as exact member bytes. The old failed action supplies only a command
and ordered-object comparison, not a successful original archive. Existing
native libc++ dynamic/static runtime tests are a separate regression gate.
The public API is documented at
https://bazel.build/rules/lib/toplevel/cc_common#create_linking_context_from_compilation_outputs.

## Evidence and distinctions

Evidence is retained below /usr/obj/usr/src:

- bazel-cross-kernel-common-work-r1-20261103: exact source bindings, normal
  format-5 profile inputs/commands, final controls and observability inventory.
- bazel-cross-kernel-common-*-r4-20261103: six successful build-bsd profiles and
  immutable artifacts, with actual-capture-r2 compiler/dependency observations.
- bazel-cross-kernel-common-review-r3-20261103: 280 common object comparisons.
  All allocated section metadata/payloads, named symbols and runtime relocations
  match. All 140 plain objects are whole-byte equal to matching fresh original
  non-debug controls. All 140 CTF objects have exact raw CTF against the original
  default CTF builds. Separate DWARF bytes differ and remain an open gate.
- bazel-cross-kernel-common-plain-references-r1-20261103: independent maintained
  Make controls with DEBUG empty, MK_CTF=no and MK_KERNEL_SYMBOLS=no. Earlier
  ordinary CTF/debug objects remain unchanged; no output normalization is used.
- bazel-cross-kernel-composite-archive-review-r1-20261103: actual public archive
  action, correctly declared host archiver and 55 retained ordered member hashes.

The final summary is
bazel-cross-kernel-common-work-r1-20261103/qualification-summary.json. All 282
production object configurations pass allocated/symbol/runtime-relocation
checks, including both crypto variants. All 141 plain objects are whole-byte
equal and all 141 CTF objects have exact raw CTF. Actual compiler review covers
282 contexts/19,054 canonical consumed pairs, with 186 additional source-derived
version headers explicitly reported. Both crypto controls bind the four target
SDK headers before compilation. Eight normal profiles pass ten declared test
invocations, including existing native libc++ dynamic/static runtime behavior.
The two native archive captures retain 119 source-ordered members. Final
composite crypto replay after widening version-string parsing retains exactly
the earlier object bytes. Evidence: bazel-cross-kernel-crypto-review-r1-20261103,
bazel-cross-kernel-common-input-review-r3-20261103,
bazel-libcxx-public-archive-review-r1-20261103 and
bazel-cross-kernel-final-composite-crypto-r1-20261103.
Rejected initial profile inputs, archive attempts and mismatched debug-policy
comparisons remain evidence; none count as a successful parity result.

## Remaining work

Continue source-owned built-in owners across the complete selected config
inventory, preserving generated producers, special compiler policies and exact
ordered links/installations. Complete full cross kernels, all module aggregates,
pkgbase and actual installed/booted runtime. Separate DWARF/source lookup,
configuration/option breadth, sandbox/bootstrap, incremental/cache behavior and
comparative CPU/aggregate memory/disk I/O/allocated disk remain open. Original
time -l logs are observations, not comparative performance qualification.
Make remains the production backend. No host installation, module loading,
upgrade or reboot occurs. BIP remains out of scope.
