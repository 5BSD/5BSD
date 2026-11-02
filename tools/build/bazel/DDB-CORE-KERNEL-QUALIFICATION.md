# Debugger built-in kernel qualification

## Scope (2026-11-02)

Twenty-two selected debugger C translation units have native amd64 GENERIC
built-in object targets using maintained compiler and CTF rules. Physical
headers belong to their existing source packages. Configuration headers come
from the actual config-generated tree; no new option generator or package
boundary is introduced. Existing native offset/vnode producers remain declared
through the shared helper. No production C or runtime policy changed.

The maintained build-bsd bazel-test format-5 workflow supplies explicit SDK,
kernel kind, CTF/debug settings, selected targets and 16 workers. These component
rules require no frontend C, backend API, signing, staging, packaging or manual
option change. Make remains production/default and BIP remains out of scope.

## Evidence

All paths below are under /usr/obj/usr/src.

- bazel-kernel-ddb-core-make-metadata-r1-20261102 records actual supported Make
  recipes with filemon disabled. All 22 earlier freshly built reference objects
  remain unchanged. Recipe capture is not a fresh compilation or full dynamic
  input trace; selected source hashes still match the independent inventory.
- bazel-kernel-ddb-core-amd64-ctf-r1-20261102 records the successful normal
  frontend build, actual execution records and immutable final artifacts.
  Its tests=[] profile runs no live debugger/kernel cases.
- bazel-kernel-ddb-core-review-r1-20261102 retains source/profile/compiler/CTF/
  input/section/filename/relocation review evidence and implementation hashes.

All 22 original .text and .SUNW_ctf sections match Make byte for byte, and all
22 objects pass the maintained binary CTF semantic checker. Allocated payloads
and layout match except diagnostic source-filename strings: five exact known
physical-source spellings account for that difference. All other strings and
all 3,452 nondebug relocation targets/offsets match symbolically. No artifact
is rewritten. Full debug, symbol-index or string-table byte identity remains
unqualified.

Twenty-two successful actual compiler actions are bound through raw object
hashes and CTF conversion input/output hashes to final immutable captures.
All 2,003 physical and 49 generated prerequisite bindings pass. Ordered warning
vectors, macro definitions, code-generation option sets, stack protection,
final debug switch, input language and forced includes match Make. Debug and
filename prefix maps and random-seed/output paths are recorded separately.

Known built-in configured analysis passes in
bazel-kernel-native-closure-query-r15-20261102: 484 groups, 659 compiler actions.
Guarded reconciliation in bazel-kernel-native-product-reconcile-r10-20261102 finds
650 source matches among 2,466 Make final products, plus two object-name and
four generated-name matches, with 1,810 unmatched in this known graph. Three
auxiliary generator objects are separate. These are analysis counts, not
compiled coverage or a complete native kernel.

## Observability and remaining gates

The bounded source-bound call-shaped scan finds no recognized direct tracing/
audit/CTR markers in these 22 sources. Existing code remains unchanged. This
does not establish missing shared instrumentation or qualify actual debugger,
CTF type lookup, breakpoints/watchpoints, textdump, scripts or tracing behavior.
Those tests require an isolated matching kernel; no host debugger entry or
panic, installation, upgrade or reboot occurred.

Disk reserve monitoring passed. Controlled CPU/memory/disk I/O/disk-use/cache
qualification remains open, as do native kernel aggregation/link/order/identity,
post-processing/install, alternate KERNCONF, ARM64/RISC-V64 built-ins/modules,
complete world/pkgbase/hardware publication and VM/runtime qualification.
