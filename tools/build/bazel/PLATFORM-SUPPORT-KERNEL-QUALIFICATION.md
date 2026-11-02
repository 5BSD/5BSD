# Platform-support kernel qualification

## Scope (2026-11-02)

56 additional amd64 GENERIC link objects have native declarations: GDB/netgdb,
ISA, x86 CPU frequency and IOMMU support, ACPI platform support, Xen frontend/
backend infrastructure, PCI, x86 BIOS and the x86 emulator. 72 physical header
contexts preserve actual source prerequisites. No production C/assembly changes.

Original KOBJ and native GENERIC option generators provide interface/configuration
headers. The ACPI resume trampoline has its own native assembly action with the
real assym.inc prerequisite. Declared objcopy, native execution-platform file2c
and nm actions generate its binary and two headers using the original Make
transformations. The symbol-offset shell adapter preserves the original nm
ordering and emits literal tab-separated definitions with pipeline error checking.
The trampoline is a payload prerequisite, not an extra kernel final-link object.
No generated Make product is consumed by the native build graph.

Existing build-bsd format-5 target inputs, backend actions, CTF and artifact
capture cover this batch. Frontend C, security/staging/signing, publication and
manual option APIs require no change. Make remains production/default and BIP
remains excluded.

## Evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-platform-support-make-metadata-r1-20261102 records actual
  supported Make metadata for 56 objects, filemon disabled, all object hashes
  unchanged. bazel-kernel-acpi-wake-make-metadata-r1-20261102 records the
  four original ACPI generator recipes/products, also unchanged. These are
  recipe/input comparisons, not complete dynamic-input discovery.
- Native r1 preserves the missing acpi_wakecode.h failure. It exposed the
  missing generator dependency; r2 adds the real source-derived chain and passes
  through the maintained frontend with 16 jobs and disk-reserve monitoring.
- bazel-kernel-platform-support-review-r1-20261102 binds 56 successful original
  compiler actions to immutable captured outputs through CTF hashes. Per-log
  counts retain the r1/r2 execution union rather than claiming one fresh full run.
  Final configured argv equals actual executed argv. Checks cover ordered warnings,
  defines/undefines, code-generation flags, debug/stack/language/forced-header
  policies, 7,426 physical and 313 generated prerequisite occurrences.
- All 56 .text and CTF payloads are byte-identical to Make, with equivalent
  CTF graphs. Allocated payloads and 11,209 non-debug relocations agree after
  independently bound complete source-filename comparison (26 spelling changes).
  No binary is rewritten; full DWARF/string/symbol-table byte equality is not
  claimed for these C objects. KOBJ comparison adjusts only schema provenance
  comments, retaining original and comparison hashes.
- wake-generator-review.json separately establishes byte-identical ACPI binary,
  wake-code header and symbol-offset header. All assembly non-debug sections,
  including symbol/relocation tables, agree with Make. Actual assembly warnings,
  code-generation/macros/language and all physical/generated inputs are checked;
  execution output hashes bind the compiler object to the immutable capture.
- The bounded source-hash-bound tracing/audit-marker scan finds 0 matching
  files out of 56. This neither proves missing shared instrumentation nor live
  probe coverage. Existing production instrumentation remains.

Closure query r37 passes for 2,164 known groups and
2,339 compile actions, including the auxiliary wake-code assembler.
Reconciliation r30 finds 2,329 source-identity matches, two object-name-only
and four generated-name-only matches among 2,466 Make final-link products,
leaving 131 missing. These counts describe configured actions, not a linked kernel.

## Remaining gates

ACPI suspend/resume, emulation, IOMMU/device behavior, Xen frontend/backend,
debugger/network debugger and failure paths need runtime qualification. This
profile runs tests=[]; it performs no such operations. Full kernel linking,
post-processing/install, modules, alternate KERNCONF, ARM64/RISC-V64, world,
pkgbase/hardware publication, bootstrap and performance remain open. No managed
disk cache was enabled. No host installation, upgrade or reboot occurred.
