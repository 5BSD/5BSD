# Virtualization built-in kernel qualification

## Scope (2026-11-02)

60 selected amd64 GENERIC built-ins now have native source-owned Bazel targets:
11 VirtIO, 22 Xen and 27 Hyper-V objects, including the Hyper-V assembly vector.
Existing package boundaries remain; the new Hyper-V parent package exports the three utility headers needed by the existing userland provider, whose target label and include namespace are preserved. Identical physical prerequisite sets share
127 source-header contexts. No production driver source changed.

The declarations use native cc_library compilation and the existing CTF pipeline.
The original config-tree generator supplies option headers; original KOBJ schemas
and the maintained generator supply interfaces. The assembly object consumes the
existing native assym producer, with visibility extended only to its Hyper-V
consumer package. No generated Make reference file enters the native graph.
Warnings, stack protection, typed debug/CTF settings and assembly language flags
remain explicit and checked against actual Make commands.

The normal build-bsd bazel-test format-5 workflow builds these targets with all
16 CPUs. Existing frontend C/backend APIs, staging, signing, verification, package
policy and manual options already cover the inputs; no frontend change is needed.
Make remains production/default; BIP remains out of scope.

## Evidence

All evidence paths below are under /usr/obj/usr/src.

- bazel-kernel-virtualization-make-metadata-r1-20261102 records actual supported
  Make meta recipes. All 60 reference object hashes remained unchanged. Filemon
  was disabled; this is not complete dynamic input or performance qualification.
- bazel-kernel-virtualization-amd64-ctf-r1-20261102 retains the initial analysis
  failure: the existing assym-header provider did not grant Hyper-V visibility.
  The retry r2 passes through the maintained frontend; no fallback was used.
  Closure query r29 caught three root-package utility-header labels crossing the
  new Hyper-V package boundary. Explicit owner labels/exports fix that issue;
  r30 reruns the full known kernel graph successfully.
- bazel-kernel-virtualization-review-r1-20261102 binds all 60 fresh successful
  compiler actions through CTF input/output hashes to immutable captures. It
  checks 8,548 physical and 349 generated prerequisite occurrences, exact source
  identities, ordered warning vectors, defines, code-generation option sets,
  stack protection, final debug selection, language and forced includes.
- All 60 objects have byte-identical .text and CTF. Typed CTF graph identities
  also agree. The separate complete allocated-payload and relocation checks
  permit only known source-filename spelling differences in read-only pools:
  37 such strings and 24,343 non-debug relocations are reconciled. No artifact
  was rewritten. Full DWARF/string/symbol table byte parity is not claimed.
- Original KOBJ provenance comments differ by physical source path versus
  generator input basename. Only that exact schema-bound comment is canonicalized
  for header comparison; original and comparison digests remain in the review.
  Other generated inputs, including assym.inc, match by exact content hash.
- The bounded call-shaped observability scan finds tracing/CTR/audit markers in
  eight selected files. This is not runtime probe coverage or evidence that the
  other drivers lack hooks provided elsewhere. Existing instrumentation remains.

## Remaining qualification

Real guest device attach, networking, storage, ballooning, clocks, hotplug, error
recovery and tracing need runtime qualification. This profile selects tests=[];
it does not boot a VM or access host devices. Full kernel link/order/identity,
post-processing/install, modules, alternate KERNCONF, ARM64/RISC-V64, world,
pkgbase/hardware publication and bootstrap remain open. Disk-reserve checks pass;
controlled CPU, memory and disk I/O/use comparisons remain open. Persistent cache
qualification remains separate; no managed disk cache was enabled. No host
installation, upgrade or reboot occurred.

Configured closure query r30 passes for 1686 known groups and 1861 compile actions. Reconciliation r24 finds 1852 source-identity matches, 2 object-name-only and 4 generated-name-only matches among 2466 Make final-link products, leaving 608 unmatched. These are graph counts, not a fully compiled or linked kernel.
