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
