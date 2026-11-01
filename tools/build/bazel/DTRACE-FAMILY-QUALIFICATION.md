# Complete native DTrace module family

2026-11-01. Native directory targets now compose the complete maintained
sys/modules/dtrace/Makefile selections for amd64, ARM64 and RISC-V64. The native
BUILD inventory contains the twelve common entries, amd64 fasttrap/Linux
systrace additions and kinst on all three supported architectures. Order and
membership exactly match independent Make SUBDIR queries: fifteen modules on
amd64, thirteen on ARM64 and thirteen on RISC-V64. PowerPC is not included.

Explicit per-architecture generic_modules, generic_debug and install_manifests
filegroups forward genuine child artifacts. There is no additional compile,
link, copy or subprocess action in the aggregation. Runtime Make parsing is not
used. These directory targets represent the directory selection; the future
parent system graph must apply the CDDL/DTrace choices that decide whether the
directory is selected. This change does not silently change those choices.

## Evidence

All six plain/CTF build-bsd format-5 profiles passed under
/usr/obj/usr/src/bazel-dtrace-family-{amd64,arm64,riscv}-{plain,ctf}-r1-20261101.
Each selects the three family targets. All eighty-two module/configuration
entries and 123 installed payloads plus 123 install records equal the earlier
immutable component qualifications exactly. Every compared capture is verified
through qualification_artifacts.resolve receipt/manifest/content bindings.

The comparison includes every module and separate debug file, all installation
JSON files, exact output membership and the legitimate empty debug group in
plain profiles. Prior independent Make comparisons for those component captures
are documented in DTRACE-PROVIDER-MODULES-QUALIFICATION.md,
DTRACE-CORE-MODULES-QUALIFICATION.md and
DTRACE-REMAINING-MODULES-QUALIFICATION.md. dttransport is qualified separately;
it is outside this maintained directory and was not added to its inventory.

A consecutive unchanged RISC-V64 CTF repeat passed under
/usr/obj/usr/src/bazel-dtrace-family-riscv-ctf-warm-r1-20261101. Its execution log
has zero records. All sixty-five target/output bindings, comprising thirty-nine
unique module/debug/manifest files, match the immediately preceding capture.
This proves unchanged warm action reuse for this configuration, not source
invalidation, remote cache portability or controlled performance.

Commands, exact inventory/order queries, artifact bindings, warm comparisons and
helpers reside in /usr/obj/usr/src/bazel-dtrace-family-review-20261101 and
bazel-dtrace-family-native-runs-r1-20261101. The first comparison helper assumed
debug outputs were in the binary group and omitted cross manifest prefixes;
it was corrected to the existing separate output-group contract and actual
architecture-prefixed filenames. Exact file membership and hash comparisons
remain mandatory; no build target or output was dropped to satisfy the audit.

## Boundaries and remaining work

These profiles have no runtime test targets. They establish complete native
composition of this directory for the selected GENERIC component configurations;
they do not establish whole-system kernel aggregation, native pkgbase creation,
module loading, provider firing or execution of dtrace_test. Additional kernel
configuration, source-change invalidation, runtime/permission/concurrency and
CPU/memory/disk performance gates remain open. No host module was loaded and no
host tracing session, storage or service state changed.

The maintained frontend already supports these explicit native target lists;
its C/CLI/backend policy does not require a change. The manual and native build
README are updated. Make remains production/default, and BIP remains excluded.
