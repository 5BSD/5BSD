# ACPICA engine kernel qualification

## Scope (2026-11-02)

156 selected ACPICA engine C sources now have native amd64 GENERIC built-in
object declarations: dispatcher, events, executer, hardware, namespace, parser,
resources, tables and utilities. All compile through native cc_library actions
and the existing CTF producer. Source-owned physical header closures are deduplicated
into 54 distinct sets without broadening them. The existing config producer supplies
opt_acpi.h, opt_global.h and offset.inc. nsaccess.c retains Make's source-specific
-Wno-unused-but-set-variable exception; the other 155 use normal built-in warnings.
No production C, firmware policy or runtime behavior changed.

A new sys/contrib/dev/acpica Bazel package owns the upstream component sources
and compiler headers. Previously root-owned acpidb/iasl sources, grammar inputs
and header providers move together. The existing include subpackage remains a
separate owner. No new root catchall exports or imported Make-generated artifacts
are introduced. Source lists are maintained native declarations; Make metadata
is used as an independent qualification reference, not queried during compilation.

The maintained build-bsd bazel-test format-5 interface supplies the SDK, selected
kernel/userland platform, CTF/debug settings, compact logs and 16 workers. This
component addition requires no frontend C/backend API, staging/signing/verification
policy, packaging contract or command-line/manual change. Make remains production
and default; BIP remains out of scope.

## Evidence

Paths below are relative to /usr/obj/usr/src.

- bazel-kernel-acpica-engine-make-metadata-r1-20261102 records actual Make recipes;
  the 156 reference objects and selected source hashes match the earlier completed
  kernel reference. Metadata recapture is not a fresh compilation or filemon trace.
- bazel-kernel-acpica-engine-amd64-ctf-r1-20261102 is the successful maintained
  frontend build. All 156 actual compiler actions report cacheHit=false. Immutable
  object captures, raw compiler/CTF hash bindings and compact execution logs remain.
- bazel-kernel-acpica-engine-review-r1-20261102 records 156 exact machine-code and
  CTF section comparisons, allocated payload/layout checks, maintained CTF semantic
  checks, 15,010 physical input and 468 generated-header bindings, and 7,550 matching
  nondebug relocations. There are no allocated-section differences or filename
  spelling adjustments in this batch. Complete DWARF/symbol-table byte identity
  is not claimed. Compiler warnings/order, definitions, code-generation option
  sets, stack policy, final debug switch, language and forced includes match Make.
- The before/after native ACPICA ownership-context directories record two CcInfo
  header views and complete 6,696-action dependency graphs. comparison-r2.json
  explicitly maps only two relocated virtual include directories and their moved
  owner labels. All arguments, physical input paths, environment and execution-info
  fields then match; no missing or extra actions. The first comparison is retained:
  its ten differences were the moved header symlink owner labels omitted from the
  comparison mapping, not a production graph fix.
- An earlier before-context action query used the kernel compilation platform and
  failed at the userland drti PIC object selector. Its output remains in
  bazel-acpica-ownership-context-before-20261102. Native userland-platform queries
  replace it as evidence; no rule or feature was disabled to bypass that failure.
- bazel-acpica-userland-ownership-r1-20261102 successfully builds both acpidb and
  iasl plus their two installation archives after the move. Bounded iasl version
  and acpidb usage checks run verified copies under the host loader/libraries;
  original immutable captures remain hash-valid. This does not establish AML
  interpreter, hardware, system startup or package-installation behavior.

The upstream Bazel compact-log converter is verified against all 189 recorded
bindings before/after each streaming conversion, with exit status and log digest
recorded. Expanded JSON is not materialized. Review implementations and actual
source/profile hashes are retained. The ELF comparisons read bytes without
rewriting original captures. Both frontend runs pass disk-reserve monitoring;
these observations do not establish comparative performance.

Known built-in analysis r17 passes for 669 groups and 844 compiler actions.
Product reconciliation r12 finds 835 source-identity matches, two object-name
matches, four generated-name matches and 1,625 unmatched products among 2,466
Make final link inputs. Three auxiliary generator objects are separate. Counts
cover the known amd64 graph, not every architecture or a completed native kernel.

## Remaining gates

A bounded call-shaped scan finds no DTrace/audit/CTR marker calls in these 156
upstream sources; this does not prove missing shared instrumentation. Existing
source/probe plumbing is unchanged. Actual AML execution, ACPI hardware/events,
complete native kernel aggregation/link/order/identity/post-processing/install,
other KERNCONF choices, ARM64/RISC-V64 and modules remain open. So do full world,
pkgbase/hardware publication, bootstrap, runtime/VM tests and controlled CPU,
memory, disk I/O, disk use and cache comparisons. No host installation or reboot
was performed.
