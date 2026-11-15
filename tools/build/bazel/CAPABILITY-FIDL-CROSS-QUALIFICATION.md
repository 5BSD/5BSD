# Capability libraries and FIDL execution ABI (2026-11-15)

## Changes

The Tier 1 target selections now cover libchannel, libshmring, libfidl,
libcapsulert, libservice, libcapability, libtrustedzfs, libcapreclaim and
libcryptocmp. Other CPUs remain explicitly incompatible for these producers.
Their Make recipes use the same source inventories on AMD64 and ARM64.
Five instrumented libraries use the maintained target_dtrace_bootstrap selector:
the object ABI is selected before the tool transitions to the execution platform.
No C/C++ source, policy or wire format changes are included.

The first actual ARM64 run exposed a compiler/runtime mismatch. Although
bsd_fidl_ir.runtime_libraries already has cfg="exec", raw SDK source-file labels
still refer to the target SDK's files. They do not become host files by changing
configuration. As a result, the AMD64 fidlc attempted to load the ARM64
libgcc_s.so.1 and failed with unsupported machine. The failed run is retained.

All 29 FIDL IR consumers now use one runtime filegroup beside the compiler in
//tools/build/fuchsia/fidlc:runtime_libraries. Its configured source-built libmd,
libc++, libcxxrt, libm and libgcc_s producers follow the execution transition.
Libc/libsys use the existing execution_c_runtime SDK alias, which explicitly
selects the execution SDK. This is still a Make-produced seed boundary for those
two libraries. It does not establish independent native bootstrap. The compiler
currently supports AMD64 execution hosts; ARM64 is the target in this cross run.

## Verification

Both maintained build-bsd qualifications complete, including every one of the
29 actual FIDL IR targets. ARM64 passes three host-artifact provenance targets
(40 Python cases) and captures 86 files. AMD64 passes those checks plus the
existing native wire-format test and captures 87 files. Every captured artifact,
report and test log/XML hash verifies against its terminal receipt.

A public Bazel aquery review inspects all 29 configured ARM64 BSDFidlCompile
actions. Their actual declared executable and seven runtime DSOs are AMD64 ELF;
no target ARM64 runtime DSO enters the compiler's LD_LIBRARY_PATH. The initial
review driver omitted JAVA_HOME, causing a different local JDK discovery failure;
that diagnostic is retained, and the corrected review uses the exact maintained
request's Java input. No generated repository or qualification receipt is patched.

All 29 IR outputs match in bytes across AMD64 and ARM64. All nine generated
Crypto source/header files per architecture match independent original Make
outputs in bytes. No source-root normalization or output rewriting is applied.
The first inventory diagnostic mistakenly counted Make's compiled .o/.pico/.meta
side effects as generated source/header output; it is retained separately.

All 18 independent original Make library references pass. Nine static archives
per platform match member order/symbol contracts; nine DSOs match checked ELF
metadata, dependencies and hardening. All 344 complete component installation
records per platform match Make, including ownership names/IDs, modes, flags,
tags, links and noncompiled data payloads. The 27 compiled archive/DSO/debug raw differences
per platform remain retained; full code/DWARF equivalence is not claimed.

The five static-library DTrace providers match Make schemas and all 65
symbol-relative locations per platform. The relocatable verifier also validates
actual target patch instructions against companion objects. This checks emitted
metadata/sites; it does not prove live probe registration/firing or shared-library
provider behavior. No broad host FBT tracing is performed.

## Evidence

Under /usr/obj/usr/src:

- bazel-capability-libraries-native-aarch64-r1-20261115: retained real runtime failure.
- bazel-capability-libraries-native-aarch64-r2-20261115: final ARM64 qualification.
- bazel-capability-libraries-native-amd64-r1-20261115: AMD64 regression and wire test.
- bazel-fidlc-runtime-action-review-aarch64-r2-20261115: 29 execution ABI closures.
- bazel-capability-fidl-generated-parity-r2-20261115: exact IR/binding comparisons.
- bazel-capability-library-make-references-r1-20261115: 18 original Make references.
- Per-platform capability-library-parity, install-parity, provider-parity and review
  directories: captured output, metadata and probe contracts.

Normal frontend format-5 target/test and explicit SDK/Java inputs already carry
these changes. The SDK producer already supplies execution_c_runtime; no new
frontend option or seed format is needed. Signing, stage verification, hardware
identity and combined publication interfaces do not change. The source-owned
compiler runtime is shared by production and test FIDL consumers.

These are component/generator checkpoints. Complete ARM64 world, tests-enabled
system installation, capability service runtime, full kernel/modules/pkgbase,
independent bootstrap, filesystem isolation and controlled performance remain
open. Make remains production/default and BIP is excluded.

## Provider-client batch and consolidated closeout (2026-11-15)

The last component batch before the execution reset adds ARM64 declarations for
libauditcmp, libdevicecmp, libextensioncmp, libfilesystemcmp, liblogcmp,
libnamespacecmp, libnetworkcmp, libnotify, liboes, libpowercmp, libsysctlcmp,
libtimecmp, libvmcmp and libbsdfilesystem. Existing source inventories and the
ordinary/PIE variants remain unchanged. Five instrumented clients use the same
explicit DTrace object-ABI selection as the foundation libraries.

Both maintained native runs pass three provenance targets (40 Python cases) and
capture 73 files each. All 28 original Make references pass. Fourteen static
archives and fourteen shared ELF contracts per architecture match; all 344
complete install records per platform match ownership/IDs/modes/flags/tags/links.
The 42 compiled payload differences per platform remain retained. Five static
providers match schemas, 36 symbol-relative locations and target patch
instructions per platform. No ARM64 execution, complete application protocol,
OpenES/mac_abac runtime, full DWARF or live DTrace claim is made.

Evidence under /usr/obj/usr/src: bazel-provider-clients-native-aarch64-r2-20261115,
bazel-provider-clients-native-amd64-r1-20261115, provider-client-make-references,
per-platform parity/install-parity/provider-parity and capture-review records.
The first request incorrectly assumed archive target names; the corrected one
binds the actual parent library contribution declarations. Premature AMD64
reference-review failures remain retained; final R2 comparisons use all completed
references. The strict frontend inventory and comparison rules are unchanged.

The Trace client remains a separate identified dependency gap: libdtrace needs
its actual ARM64 ISA source/header inventory and supporting libraries. This
batch does not remove that restriction or replace it with target-independent
x86 implementation files. Existing format-5 inputs carry these declaration
changes; frontend/backend/signing/hardware/publication interfaces do not change.
Further work follows the complete-endpoint execution order in COMPLETION-PLAN.md.
