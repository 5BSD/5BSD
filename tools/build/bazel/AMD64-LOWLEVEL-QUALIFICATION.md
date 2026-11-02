# Low-level amd64 built-in kernel qualification

## Scope (2026-11-02)

Thirty-two selected amd64 GENERIC translation units (23 C, nine assembly)
have native built-in declarations using the maintained compiler/CTF helpers.
Physical prerequisites belong to source packages. Four new narrow header
packages own consumed Xen, GDB and x86 ISA headers. Configuration headers come
from the actual config-generated tree; ISA and ACPI interfaces reuse existing
generators. Assembly consumes native assym.inc, and elf_machdep consumes the
native validated VDSO offset header. No Make-produced object/header is imported
by this graph and no production implementation or runtime policy changed.

Architecture header providers now preserve their nested PC and Xen headers
within the existing machine/ and x86/ namespaces. Initial builds rejected
missing headers rather than reaching outside declared inputs. The correction
is in these shared architecture providers, not separate per-consumer include
workarounds or a whole-source-tree glob.

Make's source-specific assembly policy is retained explicitly. locore.S uses
its custom raw assembly product without CTF conversion; xen-locore.S uses -g0
and no CTF conversion. The helper's new convert_ctf parameter defaults true
for existing consumers. The other 30 objects, including seven assembly files,
retain CTF. bhyve_hypercall.S keeps its distinct __asm__ and warning policy.
These are source-owned build rules, not result-dependent exceptions.

The maintained build-bsd bazel-test format-5 path supplies the explicit SDK,
kernel kind, CTF/debug settings and target list with 16 workers. No frontend C,
backend API, signing, staging or package-policy change is needed for these
component targets. Make remains production/default and BIP remains excluded.

## Evidence

All evidence paths below are under /usr/obj/usr/src.

- bazel-kernel-amd64-lowlevel-make-metadata-r1-20261102 records actual supported
  Make recipes with filemon disabled. All 32 earlier freshly built Make objects
  remain unchanged; this metadata query is not another compilation or complete
  dynamic file-access trace. Selected source hashes match the independent
  kernel inventory baseline.
- bazel-kernel-amd64-lowlevel-amd64-ctf-r4-20261102 is the successful corrected
  normal frontend run, with actual execution records and immutable final
  captures. Its tests=[] profile runs no live kernel tests.
- bazel-kernel-amd64-lowlevel-review-r1-20261102 retains section, compiler-input,
  CTF semantic and filename/relocation checks, source/profile hashes and scripts.
  Earlier failed header declarations and the incorrect initial assembly CTF
  policy remain visible in r1/r2/r3 qualification and review evidence.

All 32 original .text sections match Make byte for byte. All 30 CTF-bearing
objects have identical .SUNW_ctf sections and pass the maintained binary CTF
semantic checker; the other two match Make's absence of that section. Allocated
section payloads and layout match except the diagnostic filename string section.
Fifteen exact source-filename spellings are accounted for using the actual
physical input list, including ./machine/pmap.h and the lexical textual include
of ../../kern/subr_syscall.c. All other strings and all 10,734 nondebug relocation
targets/offsets match symbolically. No object is rewritten for comparison.

Thirty-two actual successful compiler actions are bound through their output
hashes and, where applicable, the CTF converter's input/output hashes to final
immutable captures. Their 3,191 physical and 136 generated input bindings pass.
Ordered warning vectors, macro definitions, code-generation option sets,
stack protection, final debug switch, input language and forced include match
Make. Filename/debug prefix maps and random-seed/output paths are recorded
rather than claimed identical. Generated interface provenance comments use
actual generator input basenames; original reference hashes are retained.

Known built-in analysis passes across the new package boundaries in
bazel-kernel-native-closure-query-r13-20261102: 440 groups and 615 compiler
actions. Guarded reconciliation in bazel-kernel-native-product-reconcile-r8-20261102
finds 606 source matches among 2,466 final Make link products, plus two object-name
and four generated-name matches, with 1,854 unmatched. Three auxiliary generator
objects are separate. These are configured-analysis counts, not compiled coverage
or a finished native kernel.

The bounded call-shaped tracing/audit scan finds markers in pmap.c and
sys_machdep.c; 30 sources have none. Existing probe/audit source is unchanged.
Marker absence is not proof of missing shared instrumentation. Live event,
exception/syscall and memory behavior remain runtime gates.

## Remaining gates

Component object qualification does not establish a linked or bootable native
kernel. Full aggregation/link order, kernel identity/post-processing/install,
alternate KERNCONF, ARM64/RISC-V64 built-ins/modules, world/pkgbase/hardware
publication and isolated runtime remain open. Live exception/syscall/signal,
context-switch/FPU, SMP/IPI, Xen, EFI, debugger, memory and pmap behavior require
the matching isolated kernel. No host installation, upgrade or reboot occurred.

Disk reserve monitoring is a resource guard, not a performance comparison.
Controlled CPU, memory, disk I/O, disk-use and incremental/cache gates remain
open. Complete debug/symbol/string-table byte identity is not established by
code, allocated payload and symbolic relocation checks.
