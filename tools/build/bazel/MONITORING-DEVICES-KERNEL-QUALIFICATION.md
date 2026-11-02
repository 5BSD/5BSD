# Monitoring and supporting-device kernel qualification

## Scope (2026-11-02)

52 additional amd64 GENERIC link objects now have native declarations: ACPI OS
services, hardware performance counters, hardware tracing, netmap, audit support,
legacy NFS service support and mac_ntpd. 66 physical prerequisite contexts share
identical sets. Production C files are unchanged. Original KOBJ schema producers
and native GENERIC options generate interface/configuration headers; no generated
Make reference file enters the native graph.

The audit DTrace object preserves its source-owned OpenZFS macro environment,
warning exceptions before Werror, early and late forced ccompile headers, and
ordering of consumed OpenZFS/legacy Solaris include roots around generic kernel
roots. An unused Make include directory is explicitly recorded rather than
populated with fabricated header dependencies. Source changes that consume new
headers must declare those inputs; sandbox compilation remains fail-closed.

The existing build-bsd format-5 workflow/backend, CTF and artifact capture support
these targets without frontend C, staging/signing/verification, publication or
manual option changes. Make remains production/default; BIP remains excluded.

## Evidence

All evidence paths below are under /usr/obj/usr/src.

- bazel-kernel-monitoring-devices-make-metadata-r1-20261102 records supported
  Make recipes, filemon disabled, with all 52 reference object hashes unchanged.
  This is not complete dynamic-input or performance qualification.
- bazel-kernel-monitoring-devices-amd64-ctf-r1-20261102 passes through the
  maintained frontend with 16 jobs and disk-reserve monitoring. All 52 compiler
  actions executed and bind through CTF input/output hashes to immutable captures.
- bazel-kernel-monitoring-devices-review-r1-20261102 retains declarations,
  implementations and source/hash-bound reports. Actual executed argv equals final
  configured argv. Checks cover ordered warnings, defines/undefines, code-generation
  options, debug/stack/language/forced-header policies, 7,332 physical and
  154 generated prerequisite occurrences. Consumed audit tracing header roots
  retain their original precedence.
- The first compiler observer incorrectly required an unused Make include root
  (OpenZFS include/os/freebsd/zfs) that contains none of this source's consumed
  prerequisites. Its rejected implementation remains. The correction derives
  required roots from the complete physical prerequisite inventory and records
  the omitted root explicitly. No source/declaration/artifact was altered to pass
  this check. Complete include-path text equality is not claimed.
- All 52 .text and CTF payloads are byte-identical to Make; CTF graphs agree.
  Complete allocated payloads and 10,056 non-debug relocations agree after
  independently bound source-filename comparison (35 string spelling changes).
  No artifacts are rewritten; full DWARF/string/symbol-table byte equality is
  not claimed. KOBJ provenance comparison changes only exact schema-path comments,
  retaining original and comparison hashes.
- A bounded source-bound scan finds call-shaped tracing/CTR/audit markers in
  1 of 52 files. It neither establishes live probe coverage nor proves other
  files lack shared hooks or indirect tracing machinery. Existing instrumentation
  remains; monitoring interfaces require runtime qualification.

Closure query r38 passes for 2,216 known groups and
2,391 compilation actions. Reconciliation r31 finds
2,381 source-identity matches, two object-name-only and four generated-name-only
matches among 2,466 Make final-link products, leaving 79 missing. These are
configured graph counts, not a fully compiled, linked or booted kernel.

## Remaining gates

Performance-counter sampling/overflow, hardware-trace lifecycle/permissions,
netmap transfer and error paths, ACPI OS services, NFS service behavior and audit
probe delivery need runtime tests. This profile has tests=[]; no host tracing,
network or authentication configuration is changed. Full linking/post-processing,
modules, alternate KERNCONF, ARM64/RISC-V64, world, pkgbase/hardware publication,
bootstrap and controlled CPU/memory/disk I/O/use comparisons remain open. No
managed disk cache was enabled. No host install, upgrade or reboot occurred.
