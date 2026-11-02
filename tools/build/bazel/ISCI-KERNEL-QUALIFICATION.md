# Intel SAS controller built-in qualification

## Scope (2026-11-02)

109 selected ISCI C sources now have native amd64 GENERIC built-in object
rules, including 98 SCIL engine sources. sys/dev/isci owns its previously
unowned sources/headers. Identical per-source physical header closures share
providers; there are 114 distinct closures across 10 source owners. Narrow
existing-owner views declare the CAM, PCI, networking and VM prerequisites.
Fourteen sources retain Make's -Wno-unused-but-set-variable exception; other
compiler settings remain normal built-in policy. No production C changes.

The existing config(8) tree supplies opt_global.h, offset.inc, opt_cam.h and
the new opt_isci.h extraction. Empty option headers remain actual config
outputs, not hardcoded substitutes. Bus/device and PCI interfaces reuse native
producers. Make recipes and dependencies serve as qualification references;
they are not queried or imported during native compilation.

The maintained build-bsd bazel-test format-5 interface handles SDK selection,
kernel platform, CTF/debug settings, compact logs and all 16 workers. These
component declarations require no new frontend C/backend API, command-line,
manual, staging/signing/verification or package-policy change. Make remains
production/default. BIP remains out of scope.

## Evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-isci-make-metadata-r1-20261102 records maintained Make recipes
  with filemon disabled. All 109 reference object hashes remain unchanged;
  selected source hashes match the independent completed-kernel inventory.
  Metadata capture is not fresh compilation or a full dynamic dependency trace.
- bazel-kernel-isci-amd64-ctf-r1-20261102 passes through the normal frontend,
  retaining immutable artifacts and compact execution logs. All 109 successful
  actual compiler actions report cacheHit=false. tests=[] does not exercise a
  live kernel, hardware or loadable module.
- bazel-kernel-isci-review-r1-20261102 records 109 exact .text and .SUNW_ctf
  comparisons, maintained CTF semantic checks, 13,464 physical-input bindings,
  362 generated-header bindings and 6,646 symbolically equal nondebug
  relocations. Allocated payloads/layout match except five exact source-path
  spellings in diagnostic strings, with corresponding string relocations.
  No other strings are normalized and no artifact is rewritten. Complete
  DWARF, string-table and symbol-index byte identity is not claimed.
- Actual compiler outputs bind by hash through CTF inputs/outputs to immutable
  final objects. Ordered warning vectors, defines, code-generation option sets,
  stack protection, final debug switch, language and forced includes match
  Make. Physical and generated inputs bind to their expected hashes. Only
  generated interface provenance comments use the actual generator basename;
  original Make header hashes remain recorded. Source-prefix maps, output paths
  and random seeds remain explicit build-system differences.
- Upstream Bazel compact-log reconstruction verifies all 189 recorded converter
  bindings before/after, retaining command/status/input hashes and resource
  observations. Expanded JSON is streamed, not stored. ELF reviewers read bytes
  and never edit original evidence. Source/profile/review implementations remain
  retained with hashes. Disk-reserve monitoring passes; comparative performance
  is not established by this run.

Known built-in configured analysis r18 passes for 778 groups and 953 compiler
actions. Product reconciliation r13 reports 944 source-identity matches, two
object-name matches, four generated-name matches and 1,516 unmatched products
among 2,466 Make final link inputs. Three auxiliary generator objects remain
separate. These counts cover the known amd64 graph, not a complete native
kernel or all architecture coverage.

## Remaining gates

The source-hash-bound call-shaped scan finds no DTrace/audit/CTR calls in these
109 files. This does not prove missing shared instrumentation. Probe plumbing
and production driver sources are unchanged. Controller attach, SAS/SATA disk
I/O, timeout/reset/recovery, suspend/resume and hardware fault handling remain
unqualified. The SCIL library is not a complete simulated-controller test.

Complete native kernel link/order/identity/post-processing/install, loadable
modules, alternate configurations, ARM64/RISC-V64, world/pkgbase/hardware
publication, bootstrap, runtime/VM checks and controlled CPU/memory/disk I/O/
disk-use/cache comparisons remain open. No host installation or reboot occurred.
