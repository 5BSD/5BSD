# x86 core built-in kernel qualification

## Scope (2026-11-02)

Twenty-two selected x86 C translation units now have native amd64 GENERIC
built-in declarations. They retain source-owned physical prerequisites and the
maintained native compiler/CTF policy. Generated option headers come from the
actual config tree; no option values are invented. Existing ISA, ACPI, bus,
device, CPU-frequency and PCI generators are reused. A narrow PCI bridge header
view exposes the existing pcib_if producer. No production C or runtime policy
changed. Make remains production/default; BIP remains out of scope.

New sys/dev/ic and sys/x86/iommu packages own the exact consumed physical
headers. The root bhyve header declaration now refers to ns16550.h through its
actual child owner. Before/after configured context queries preserve all 54
recorded headers and the recorded includes, quote/system include roots and
defines exactly. This is a header-context check, not another bhyve build/runtime
qualification. Other root bhyve physical inputs remain unchanged; a broad
catch-all package/glob was not introduced.

The maintained build-bsd bazel-test format-5 API supplies the explicit SDK,
kernel kind, CTF/debug settings, target list and 16 workers. No frontend C,
backend API, signing, staging, packaging or manual option change is required
for these component declarations. Complete world/kernel integration remains
a separate gate; this does not make Bazel the production backend.

## Evidence

All paths below are under /usr/obj/usr/src.

- bazel-kernel-x86-core-make-metadata-r1-20261102 captures supported actual Make
  recipes with filemon disabled. All 22 earlier freshly built reference objects
  remain unchanged; metadata capture is not another compilation or full dynamic
  input trace. Selected source hashes still match the independent kernel
  inventory baseline.
- bazel-kernel-x86-core-amd64-ctf-r1-20261102 records the successful normal
  frontend build, actual execution records and immutable final captures.
  The tests=[] profile runs no live kernel tests.
- bazel-kernel-x86-core-review-r1-20261102 retains compiler/section/CTF/input/
  filename/relocation checks and their source/profile hashes and scripts.
- bazel-x86-core-root-header-context-before-20261102 and the corresponding
  after-20261102 retain the exact configured bhyve header-context comparison.

All 22 original .text and .SUNW_ctf sections match Make byte for byte. All 22
also pass the maintained binary CTF semantic checker. Allocated payloads and
layout match except the diagnostic filename string section: nine exact known
source filename spellings are accounted for through the physical input list.
All other strings and all 7,261 nondebug relocation targets/offsets match
symbolically. No artifacts are rewritten for comparison. Full debug, symbol-
index and string-table byte identity is not claimed.

Twenty-two actual successful compiler actions are bound through raw output
hashes and CTF converter input/output hashes to the immutable final artifacts.
All 2,776 physical and 126 generated input bindings pass. Actual ordered warning
vectors, macro definitions, code-generation option sets, stack protection,
final debug switch, language and forced includes match Make. Filename/debug
prefix maps and random-seed/output paths are recorded separately. Interface
provenance comments use actual generator input basenames; original reference
hashes remain recorded.

Known built-in analysis passes across the new package boundaries in
bazel-kernel-native-closure-query-r14-20261102: 462 groups, 637 compiler actions.
Guarded reconciliation in bazel-kernel-native-product-reconcile-r9-20261102 finds
628 source matches among 2,466 final Make products, plus two object-name and
four generated-name matches, with 1,832 unmatched in this known graph. Three
auxiliary generator objects are separate. These are configured-analysis counts,
not compiled coverage or a complete native kernel.

## Observability and remaining gates

The bounded source-bound call-shaped scan recognizes tracing/audit/CTR markers
in cpu_machdep.c and mp_x86.c; 20 sources have none. Existing code/probe plumbing
is unchanged. Absence of direct markers does not prove missing shared hooks.
Live CPU identification/features, interrupts/APIC/MSI, SMP, clock/delay, suspend,
microcode, debugger/stack and hypervisor behavior require the matching isolated
kernel and relevant hardware/VM tests.

Disk reserve monitoring passed; controlled CPU/memory/disk I/O/disk-use/cache
qualification remains open. So do native aggregate kernel link/order/identity,
post-processing/install, alternate KERNCONF, ARM64/RISC-V64 built-ins/modules,
complete world/pkgbase/hardware publication and runtime qualification. No host
installation, upgrade or reboot occurred.
