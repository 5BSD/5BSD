# Storage HBA built-in kernel qualification

## Scope (2026-11-02)

39 selected amd64 GENERIC C sources now have native built-in declarations:
22 OCS Fibre Channel and 17 SmartPQI. No PMC sources were selected in this batch.
Two new physical source packages own their headers; 25 distinct source-header
contexts reuse identical prerequisite sets. No production driver source changes.

Native cc_library compilation uses maintained common built-in kernel warnings,
including typed WERROR/debug/CTF settings and stack protection. Actual configured
option outputs supply opt_cam.h and opt_stack.h; empty options are extracted from
the config tree. Existing bus/device/PCI interfaces, vnode and offset producers
remain responsible for generated inputs. Make-generated files are reference
material only, never substituted into the native build graph.

The maintained build-bsd bazel-test format-5 workflow handles these targets with
16 workers and compact execution logs. No new frontend C/backend API, CLI/manual
option, staging, signing, verification or package-policy change is required.
Make remains production/default. BIP remains excluded.

## Retained evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-storage-hba-make-metadata-r1-20261102 captures supported Make
  recipes with filemon disabled. All 39 completed reference-object hashes remain
  unchanged. This does not establish complete dynamic dependencies or performance.
- bazel-kernel-storage-hba-amd64-ctf-r1-20261102 passes through the maintained
  frontend. Immutable object captures bind to 39 fresh successful compiler actions
  through CTF input/output digests, rather than mutable bazel-bin outputs.
- bazel-kernel-storage-hba-review-r1-20261102 checks 7,803 physical and 256
  generated prerequisites. Source hashes match the independent inventory. Actual
  ordered warning vectors, defines, code-generation option sets, stack protection,
  final debug switch, language and forced includes match Make.

All 39 .text and .SUNW_ctf sections are byte-identical to Make. Other allocated
payloads/layouts match except 46 exact known-source filename spellings. Complete
string pools and 24,059 nondebug relocations compare symbolically. Complete DWARF,
string-table and symbol-index byte parity is not claimed. No objects are rewritten.

CTF graph review uses the bounded read-only procedure in
OPENZFS-KERNEL-QUALIFICATION.md: typed symbol identities stay strict; zero-type
string object addresses use verified complete canonical strings and interior
offsets, with full-literal size checks. Separate allocated-layout, full-string-pool
and relocation gates bind the same original hashes. The production CTF verifier
is unchanged and is not claimed to pass a broader or different scope.

Generated-interface provenance comments normalize only the known schema source
path to its basename; original reference digests remain recorded. Log conversion
streams the verified upstream converter output and checks its 189 recorded
bindings before/after. Review code, declarations, profiles and source snapshots
are retained alongside the results.

Configured query r25 passes for 1,351 known built-in groups and 1,526 compiler
actions. Reconciliation r20 finds 1,517 source-identity matches, two object-name
matches and four generated-name matches among 2,466 Make final-link products,
leaving 943 unmatched. Three auxiliary generator objects remain separate.
These are known amd64 graph counts, not complete compiled or linked coverage.

## Observability and remaining gates

A bounded source-hash-bound scan finds no call-shaped tracing/audit markers in
these 39 files. This does not prove missing shared instrumentation. Driver attach,
firmware/interrupt/DMA, queue depth, CAM discovery, I/O errors/timeouts, reset and
recovery, hotplug and multipath need relevant hardware/runtime qualification.
The profile has tests=[] and performs no live storage operations.

Complete kernel link/order/identity/post-processing/install, loadable modules,
alternate KERNCONF, ARM64/RISC-V64, full world and pkgbase/hardware publication,
bootstrap and boot/service checks remain open. Disk reserve guards pass; controlled
CPU, memory, disk I/O, disk-use and cache comparisons remain open. No host install,
upgrade or reboot occurred.
