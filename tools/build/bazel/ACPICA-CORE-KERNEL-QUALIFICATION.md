# ACPI platform built-in kernel qualification

## Scope (2026-11-02)

Twenty-nine selected ACPI platform C translation units now have native amd64
GENERIC built-in object targets. They retain exact source-owned prerequisites,
actual config-generated option headers and the maintained compiler/CTF policy.
Bus/device, ISA, ACPI/APEI, CPU-frequency and PCI/bridge interfaces reuse existing
producers and narrow header views. No production C or runtime policy changed.
Make remains production/default; BIP remains out of scope.

The first build rejected a missing acpi_quirks.h producer. The corrected graph
runs the unchanged maintained acpi_quirks2h.awk on the maintained acpi_quirks
data, using the existing declared file-producing AWK contract used by USB/MII.
The generator writes its real header basename in an isolated declared output
directory. AWK, the static cwd runner and runtime libraries are explicit inputs;
LC_ALL=C, PATH is empty and LD_LIBRARY_PATH names only that directory. The AWK
script does not invoke a shell. No Make-generated header is imported, script
rewritten or table data hardcoded into a build helper. The actual generated
header hash matches Make byte for byte.

The maintained build-bsd bazel-test format-5 API supplies SDK, kernel kind,
CTF/debug settings, target list and 16 workers. The new opt-in compact-log field
is used normally. These component declarations need no additional frontend C,
backend API, signing, staging, package-policy or manual option change. The new
AWK source export, provider declarations and documentation accompany the graph.

## Evidence

All paths below are under /usr/obj/usr/src.

- bazel-kernel-acpica-core-make-metadata-r1-20261102 records actual supported
  Make recipes with filemon disabled. All 29 earlier freshly built objects remain
  unchanged; metadata capture is not a fresh compilation or complete dynamic
  input trace. Selected C source hashes still match the independent inventory.
- bazel-kernel-acpica-core-amd64-ctf-r1-20261102 retains the original missing-
  producer failure. r2-20261102 is the successful corrected normal frontend
  build with immutable object captures and compact execution evidence.
  Its tests=[] profile runs no live kernel/ACPI cases.
- bazel-kernel-acpica-core-review-r1-20261102 retains actual compiler, CTF,
  source-input, allocated-section, filename/relocation and quirk-producer checks.
  The source/profile/review implementations are hash-bound and retained.

All 29 .text and .SUNW_ctf sections match Make byte for byte. All 29 also pass
the maintained binary CTF semantic checker. Allocated payloads/layout match
except diagnostic filenames: 18 exact known-source filename spellings account
for that difference. All other strings and all 8,394 nondebug relocation
targets/offsets match symbolically. No artifacts are rewritten for comparison;
complete debug, symbol-index or string-table byte identity remains unqualified.

Twenty-nine successful actual compiler actions are bound through raw object
hashes and converter input/output hashes to immutable final artifacts. All
4,002 physical and 211 generated prerequisite bindings pass, including the
native quirk header. Ordered warnings, macro definitions, code-generation option
sets, stack protection, final debug switch, language and forced includes match
Make. Debug/filename prefix maps and random-seed/output paths remain explicitly
recorded differences. Interface provenance comments use actual generator input
basenames; original Make hashes remain recorded.

The actual BSDAcpiQuirks action binds both physical script/data hashes, exact
arguments/environment and generated output hash to the unchanged Make header
saved in the review directory. Compact logs are reconstructed by Bazel's
upstream converter through the shared streaming JSON reader. Each invocation
checks all 189 recorded converter bindings before/after and zero exit status,
retaining commands, input hashes and resource observations. Expanded JSON is
not materialized. This is actual compiler/CTF/generator evidence, beyond the
initial compact-log Python test integration.

Known built-in configured analysis passes in
bazel-kernel-native-closure-query-r16-20261102: 513 groups, 688 compiler actions.
Guarded reconciliation in bazel-kernel-native-product-reconcile-r11-20261102 finds
679 source matches among 2,466 Make final products, plus two object-name and
four generated-name matches, with 1,781 unmatched in the known graph. Three
auxiliary generator objects are separate. These are analysis counts, not a
complete native kernel or compiled whole-system coverage.

## Observability and remaining gates

The bounded source-bound call-shaped scan recognizes tracing/audit/CTR markers
in acpi.c and acpi_ec.c, with none in 27 sources. Existing code/probe plumbing
is unchanged. Absence does not prove missing shared instrumentation. Firmware
AML evaluation, battery/thermal/power events, embedded controller, ACPI PCI and
interrupt routing, suspend/resume and actual tracing behavior require the
matching isolated kernel and relevant hardware/VM tests.

Disk reserve monitoring passed. Controlled CPU/memory/disk I/O/disk-use/cache
comparisons remain open. So do complete native kernel aggregation/link/order/
identity, post-processing/install, alternate KERNCONF, ARM64/RISC-V64 built-ins/
modules, world/pkgbase/hardware publication and runtime qualification. No host
installation, upgrade or reboot occurred.
