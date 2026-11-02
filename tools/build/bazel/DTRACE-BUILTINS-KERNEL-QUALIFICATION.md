# DTrace built-in kernel qualification

## Scope (2026-11-02)

15 additional amd64 GENERIC final-link objects now have native declarations:
Solaris compatibility, DTrace core, allocator/profile/SDT/FBT/syscall providers,
x86 instruction decoding and amd64 tracing/assembly support. Production C and
assembly sources are unchanged. Original KOBJ schemas and native GENERIC options
supply generated headers; the real assym producer supplies assembly constants.
No generated Make reference product enters the native graph.

Native built-ins preserve BUILDING_DTRACE, DIS_MEM, SMP and assembly LOCORE where
Make uses them, OpenZFS compatibility macros and forced ccompile headers, ordered
warning exceptions before Werror, FBT's early include roots and consumed Solaris
header precedence. 41 physical prerequisite contexts, one parent-namespace bridge
and one split late utility provider retain real source ownership across packages.
Only consumed headers populate these providers; omitted unused Make search roots
are recorded per compiler action.

Existing build-bsd format-5 target inputs, backend compilation/CTF/capture cover
this batch. Frontend C, staging/security/signing/verification, publication and
manual options require no change. Make remains production/default; BIP excluded.

## Evidence

All evidence paths below are under /usr/obj/usr/src.

- bazel-kernel-dtrace-builtins-make-metadata-r1-20261102 records supported
  Make compiler recipes with filemon disabled. All 15 object hashes stay unchanged.
  This is not complete dynamic-input discovery or performance qualification.
- Native build r1 passes but strict input-order review rejects a missing parent
  namespace for the child-owned dis_tables.h. The correction explicitly exports
  that real header to a parent provider. The observer separately excludes the
  current compilation source from header-root requirements; unused roots remain
  recorded. The rejected implementation is retained.
- Native r2 passes but the unchanged ordering assertion catches Solaris common/util
  grouped too early with uts/common. A separate late provider fixes the production
  declaration. Native r3 passes with all consumed Make roots in their original
  relative order. No ordering assertion was waived. Prior builds/observers and
  initial/intermediate CTF evidence remain available.
- bazel-kernel-dtrace-builtins-review-r1-20261102 binds 15 effective actual
  compiler executions to immutable final captures through CTF input/output hashes.
  Per-log execution counts identify reuse/retry rather than claiming one fresh
  full run. Final configured argv equals executed argv. Audits check ordered
  warnings, defines/undefines, code-generation flags, debug/stack/language/forced
  headers and 2,335 physical/33 generated prerequisite occurrences.
- All 15 .text and CTF payloads are byte-identical, with equivalent CTF graphs.
  Complete allocated payloads and 9,965 non-debug relocations agree after
  independently bound complete source-filename comparison (12 spelling changes).
  No binary is rewritten; full DWARF/string/symbol-table byte equality is not
  claimed. KOBJ comparison adjusts only exact schema-path provenance comments,
  preserving original and comparison hashes.
- The bounded source-bound marker scan finds call-shaped tracing/audit markers
  in 4 of 15 files. Provider implementations also use indirect machinery; this
  neither proves live probe delivery nor absence of shared instrumentation.

Closure query r40 passes for 2,231 known groups and
2,406 compilation actions. Reconciliation r33 finds
2,396 source-identity matches, two object-name-only and four generated-name-only
matches among 2,466 Make final-link products, leaving 64 missing. These are
configured graph counts, not a complete linked or booted kernel.

## Remaining gates

Live DTrace enumeration, SDT/FBT/syscall/profile delivery, lifecycle/privilege/error
paths and performance need runtime qualification. This profile has tests=[]; it
performs no host tracing operations. Full kernel linking/post-processing/install,
generated link products, modules, alternate KERNCONF, ARM64/RISC-V64, world,
pkgbase/hardware publication, bootstrap and controlled CPU/memory/disk I/O/use
comparisons remain open. No managed disk cache was enabled. No host install,
upgrade or reboot occurred.
