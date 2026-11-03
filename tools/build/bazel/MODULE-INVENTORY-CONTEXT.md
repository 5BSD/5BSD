# Module inventory query context

## Correction on 2026-11-01

The recursive Make inventory now carries parent-exported variables into each
selected child query. It obtains their names and quoted values from Make's
`.MAKE.EXPORTED`; Python decodes the values as data without executing a shell.
This avoids a second, manually maintained list of kernel option exports.
Conflicting contexts for the same selected directory make the audit incomplete.
Report format 2 records exported names and context hashes, not environment values.

This matters because `sys/modules/Makefile` exports option values before a
leaf Makefile evaluates its early conditionals. In particular, MII selects
`micphy.c`, `mii_fdt.c` and `ofw_bus_if.h` when `OPT_FDT` is present. A standalone
leaf query missed those inputs on ARM64 and RISC-V64. Source entries across the
pending MII/MDIO/miiproxy cohort are 38 on amd64 and 40 on each FDT architecture.
These pending modules have not yet been qualified.

## Checks performed

The refreshed recursive queries completed without errors for amd64 GENERIC
(729 selected modules), ARM64 GENERIC (627), and RISC-V64 GENERIC (553).
The amd64 inventory has 219 direct native module declarations and 510 without.
The macro-presence diagnostic is amd64-specific; its cross-target values are
not counts of cross-target conversions.

For all selected leaves containing local BUILD files, standalone and
root-export-aware queries were compared for SRCS, CFLAGS, EXPORT_SYMS, DPSRCS,
SUBDIR, KMOD and .PATH. All 220 amd64, 192 ARM64 and 190 RISC-V64 descriptions
were unchanged in these seven fields. This is query evidence for 602 descriptions,
not a rebuild or runtime qualification of those modules.

Evidence is under
`/usr/obj/usr/src/bazel-module-export-context-20261101`: the architecture JSON
reports, `root-contexts.json`, and `existing-native-comparison.json`.
Regression tests cover real BSD Make parent-to-grandchild option propagation,
quoted values, malformed/conflicting exports, and duplicate directory selection
under different export contexts, in addition to the existing traversal checks.

## Integration and limits

The standalone inventory helper and its maintained Bazel test target are
updated together. No build-bsd C or CLI change is required: this is a read-only
selection audit, and native component qualification still uses the existing
format-5 frontend. The normal build backend remains Make.

This audit discovers selected source descriptions. It does not prove actual
native artifacts, installation records, package closure, complete kernel/world
builds, or VM behavior. Those completion gates remain open in the completion
plan. Parent Make exports are discovery inputs, not a replacement for explicit
native Bazel configuration and dependency declarations.

## Early source lookup correction on 2026-11-02

Normal kernel module recursion supplies `SYSDIR` and `MODULE_TIED=yes` from
`sys/conf/kern.post.mk` before parsing module Makefiles. The standalone inventory
now supplies the same context: `SYSDIR` comes from the explicit resolved `--src`
input plus `sys`, and `MODULE_TIED` is enabled for the selected kernel. Report
format 2 records `system_source_dir` and `module_tied`. Parent export discovery
continues to carry source-owned option variables without a fixed option list.

This matters for leaves such as dpdk_lpm4, dpdk_lpm6 and fib_dxr, whose early
`.PATH` directives use `SYSDIR` before including bsd.kmod.mk. The initial direct
Make controls for the pending network cohort omitted this normal kernel input:
68 of 74 controls passed and six failed source lookup before compilation. Those
results are retained under
`/usr/obj/usr/src/bazel-network-services-module-make-references-r1-20261102`.
They are rejected controls, not evidence against the module source or accepted
native artifacts. Fresh controls must use the selected kernel's actual SYSDIR.

The maintained `//tools/build/bazel:module_inventory_test` passes through the
normal build-bsd bazel-test frontend (11 Python test methods). Its new real BSD
Make fixture uses a temporary custom source root and checks early `.PATH`
expansion and the tied-kernel input. No fixture hardcodes the production source
location. Evidence:
`/usr/obj/usr/src/bazel-module-inventory-source-context-native-r1-20261102`.

Fresh recursive queries complete without errors and select exactly the same
(directory, KMOD) pairs as the preceding audit: amd64 729, ARM64 627 and RISC-V64
553. Local BUILD presence is respectively 628, 504 and 476; presence says nothing
about whether those rules support the queried architecture. The reports and
set comparison are under
`/usr/obj/usr/src/bazel-source-context-module-selection-20261102`.

Frontend review: this changes a read-only engineering inventory and its test,
not build inputs to the format-5 native qualifier, staging, signing, package
publication or the CLI. No build-bsd C, backend or manual option change is
required. Make remains the production/default backend; this query correction
does not close any full-system, runtime, performance or cross-target build gate.
