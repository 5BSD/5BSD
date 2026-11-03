# ARM64/RISC-V kernel migration baseline (2026-11-03)

This checkpoint establishes complete original Make GENERIC built-in kernels and
actual dependency/producer evidence for implementing their native Bazel graph.
It does **not** establish complete Bazel cross-kernel builds.

## Original build and installation

Both architectures use the maintained Makefile.inc1 cross environment, original
GENERIC configuration, default CTF and split debug, and all 16 logical CPUs.
NO_MODULES=yes explicitly excludes separate modules. Installation uses NO_ROOT
and private fresh staging directories under /usr/obj; the running kernel and
boot environment are untouched. The references bind source/tool inputs before
and after compilation and retain actual commands, metadata and staged files.

| Architecture | Selected link products | Auxiliary generator products | Consumed input pairs | Generated inputs |
| --- | ---: | ---: | ---: | ---: |
| ARM64 | 2,035 | 3 | 266,926 | 312 |
| RISC-V | 1,194 | 3 | 141,521 | 239 |

Selected products include the existing shared force-dynamic-hack helper; each
architecture has one compiler-driver shared link in addition to its -c actions.
The auxiliary products are genoffset, genoffset_test and genassym. Actual final
link order agrees with the maintained config inventory. Ordinary source/tool
bindings number 37,403 for ARM64 and 37,402 for RISC-V. These conservative
reference snapshots are not proposed as native action dependency closures.

Authoritative local evidence below /usr/obj/usr/src:

- bazel-cross-kernel-original-references-r2-20261103/summary.json: successful
  complete original builds, isolated installations and unchanged input bindings.
- bazel-cross-kernel-fresh-config-reference-r2-20261103: current config
  inventories, actual kernel objects, dependencies and Make metadata.
- bazel-cross-kernel-actual-input-audit-r2-20261103/summary.json: actual ordered
  compiler/source identities, canonical input pairs and generated producers.
- bazel-cross-kernel-maintained-environment-r1-20261103: maintained compiler,
  linker and native cross-DTrace execution environments.

## Input gaps and retained distinctions

ARM64's crypto wrapper consumes four headers outside the initial source/tool
snapshot: target sysroot ssp/ssp.h and Clang arm_neon.h, arm_bf16.h and
arm_vector_types.h. An independent original Make control binds these inputs
before compilation. All non-DWARF section metadata/payloads, CTF, relocations
and symbols match the ordinary original object; .debug_str and .rela.debug_info
differ with the build directory. The initial four-input provenance gap remains
explicit. Evidence: bazel-cross-kernel-arm64-crypto-control-r1-20261103.

The original vers.o recipe does not emit compiler dependencies. Separate
preprocessing-only observations preserve all original preprocessing flags and
leave original objects and kernel files unchanged. Evidence:
bazel-cross-kernel-version-dependency-observation-r2-20261103. This does not
resolve native version metadata, reproducibility or separate DWARF parity.

ARM64 tegra210_xusb.fwo embeds firmware through firmw.S .incbin; the binary is
absent from compiler .d output. The audit additionally binds the actual Make
prerequisite and firmware producer. Native actions must declare this binary.
Rejected early inventory, observer and partial audit attempts are retained;
they do not count as successful evidence.

## Maintained frontend foundation

Format-5 kernel profiles retain native-SDK freestanding cross compilation and
also accept a matching composite ARM64/RISC-V SDK with its separately bound
amd64 execution toolchain. A foreign SDK cannot select a different target.
The same receipt policy as cross userland validates the execution origin and
host closure; the normal frontend checks input and snapshot hashes. Target
headers remain explicit owning-rule inputs, not global kernel dependencies.
No new CLI or alternate build driver is introduced; build-bsd.c is unchanged.
The backend source_graph.py, settings tests and manual change together.

The 17 settings methods pass; all three real r4 SDK snapshots independently
verify, with matching/foreign kernel selection accepted/rejected as specified.
Evidence: bazel-cross-kernel-frontend-r1-20261103/summary.json. This is platform
selection and SDK validation, not an actual composite kernel Bazel profile.

## Remaining work, in order

1. Model precise built-in source owners and original compiler policies; retain
   target crypto intrinsic headers and selectively relaxed -nostdinc policy.
2. Derive ARM64 Linux DTS version from its declared source, not a literal.
3. Connect config-owned generated headers, offsets, assembly/firmware, DTrace,
   version policy and ordered architecture-specific final links/installations.
4. Build complete native Bazel cross kernels and compare actual outputs against
   appropriate independent original controls, including debug/source lookup.
5. Complete cross-module aggregates, pkgbase, installed/booted runtime and
   performance qualification with CPU, aggregate memory and disk I/O/usage.

Original time -l logs are observations, not comparative performance proof.
No host activation, runtime module loading, cache/sandbox qualification or
complete world/publication result is claimed. Make remains the production
backend. BIP remains out of scope.
