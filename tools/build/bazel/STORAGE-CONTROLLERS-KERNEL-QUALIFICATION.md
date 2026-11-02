# Storage-controller built-in kernel qualification

## Scope (2026-11-02)

62 selected amd64 GENERIC C sources now have native built-in targets: AAC,
AACRAID, AHCI, ARCMSR, CISS, HPTIOP, ISP, MFI, MPI3MR, MPR, MPS, MPT, MRSAS,
TWS and NVD. Existing package boundaries remain; new source packages explicitly
export the headers needed by the existing MPT/MPS/MFI userland providers. Their
public target labels and include namespaces remain. Identical prerequisite sets
share 68 physical source-header contexts. No production driver source changed.

Native cc_library compilation and the maintained CTF pipeline preserve kernel
warnings, stack protection and typed debug/CTF settings. The two mapping files
retain their sometimes-uninitialized exception, and the two SAS files retain
their unneeded-internal-declaration exception, in original ordered warning
vectors. These are existing Make per-source policies. Source-owned LinuxKPI
headers expose their original include root. Original config-tree and KOBJ
producers supply option/interface headers; no Make-generated reference file
enters the native graph.

The maintained build-bsd bazel-test format-5 workflow builds these targets with
16 CPUs. Existing frontend C/backend APIs, staging, signing, verification, package
policy and manual options cover these inputs; no frontend change is required.
Make remains production/default; BIP remains excluded.

## Retained evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-storage-controllers-make-metadata-r1-20261102 records supported
  Make recipes with filemon disabled. All 62 reference object hashes remain
  unchanged. This is not full dynamic input or performance qualification.
- bazel-kernel-storage-controllers-amd64-ctf-r2-20261102 passes through the
  maintained frontend. The review binds all 62 fresh successful compiler actions
  through CTF input/output hashes to immutable captured objects. The binding
  uses 61 effective recipes from r1 and the corrected mpi3mr_cam recipe from r2,
  not 62 fresh compiles in one run. The rejected r1 compiler review remains: it
  detected the omitted Make-required forced LinuxKPI kconfig.h include despite
  matching code bytes. The final declaration explicitly preserves that input.
- bazel-kernel-storage-controllers-review-r1-20261102 checks
  9,513 physical and 347 generated prerequisite occurrences, source identities,
  ordered warnings, defines, code-generation option sets, stack protection,
  final debug selection, language and forced includes against actual Make.
- All 62 objects have byte-identical .text and CTF, with equivalent typed CTF
  graphs. Complete allocated payloads and 31,058 non-debug relocations agree
  after reconciling 61 independently bound source-filename spellings in read-only
  strings. No ELF artifact was rewritten. Full DWARF/string/symbol table byte
  parity is not claimed. Original KOBJ provenance comments are canonicalized
  only from their exact physical schema path to the original generator basename;
  original and comparison hashes remain in the input review.
- The bounded source-hash-bound observability scan finds call-shaped markers in
  five of 62 files. It neither demonstrates live probes nor proves that other
  files lack shared hooks. Production instrumentation remains.

Configured closure query r32 passes for 1,748 known groups and
1,923 compile actions. Reconciliation r25 finds
1,914 source-identity matches, two object-name-only and four generated-name-only
matches among 2,466 Make final-link products, leaving 546 unmatched. These are
graph counts, not a fully compiled or linked kernel. Each selected final
configured compiler argv matches its actual audited execution.

## Remaining qualification

Controller attach, disks/arrays, I/O/error recovery, hotplug, DMA, firmware and
live tracing require runtime qualification. This profile selects tests=[]; no
controller or host storage operation occurred. Full kernel link/order/identity,
post-processing/install, modules, alternate KERNCONF, ARM64/RISC-V64, world,
pkgbase/hardware publication and bootstrap remain open. Disk reserves pass;
controlled CPU, memory and disk I/O/use comparisons remain open. Persistent cache
qualification is separate; no managed disk cache was enabled. No host install,
upgrade or reboot occurred.
