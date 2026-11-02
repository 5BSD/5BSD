# Ethernet built-in kernel qualification

## Scope (2026-11-02)

73 selected amd64 GENERIC C sources now have native built-in targets across ALC,
ALE, AQ, AXGBE, BCE, BGE, BXE, ET, IAVF, IGC, IXL, JME, MSK, NFE, RE, RGE and
SGE. Firmware initializer C sources remain real compiler inputs. Identical
prerequisite sets share 77 physical source-header contexts. Existing source
package boundaries remain; no production driver source changed.

Native cc_library compilation and the maintained CTF pipeline retain common
kernel warnings, defines, stack protection and typed debug/CTF settings. IAVF
and IXL expose their source-directory include roots. Original config-tree/KOBJ
producers generate options/interfaces; BCE/BGE consume the existing MII device-ID
generator. No generated Make reference file enters the native graph.

The maintained build-bsd bazel-test format-5 workflow builds these targets with
16 CPUs. Existing frontend C/backend APIs, staging, signing, verification, package
policy and manual options cover the inputs; no frontend change is required.
Make remains production/default; BIP remains excluded.

## Retained evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-ethernet-make-metadata-r1-20261102 records supported Make recipes
  with filemon disabled. All 73 reference object hashes remain unchanged. This
  does not establish complete dynamic inputs or a performance comparison.
- bazel-kernel-ethernet-amd64-ctf-r1-20261102 retains the initial missing
  miidevs.h dependency failure in BCE/BGE. Their declarations now depend on the
  existing native MII producer. Retry r2 passes through the normal frontend.
- bazel-kernel-ethernet-review-r1-20261102 binds 73 effective successful compiler
  recipes from retained execution logs to final immutable objects through CTF
  input/output hashes. The per-log counts are in summary.json; the union is not
  claimed as 73 fresh compiles in one run. Final configured argv matches every
  actual audited execution.
- The review checks 13,666 physical and 470 generated prerequisite
  occurrences, independent source identities, ordered warnings, defines,
  code-generation option sets, stack protection, final debug selection,
  language and forced includes against actual Make recipes.
- All 73 objects have byte-identical .text and CTF and equivalent typed CTF
  graphs. Complete allocated payloads and 49,674 non-debug relocations agree
  after reconciling 44 independently bound source-filename spellings in
  read-only strings. No ELF artifact was rewritten. Full DWARF/string/symbol
  table byte parity is not claimed. KOBJ provenance comparison canonicalizes only
  the exact schema-path comment to the original generator input basename;
  original and comparison digests remain in the input review.
- The bounded source-hash-bound scan finds call-shaped tracing/CTR/audit markers
  in 1 selected files. It neither proves live probe coverage nor establishes
  missing shared hooks in the others. Existing instrumentation remains.

Configured closure query r33 passes for 1,821 known groups and
1,996 compile actions. Reconciliation r26 finds
1,987 source-identity matches, two object-name-only and four generated-name-only
matches among 2,466 Make final-link products, leaving 473 unmatched. These are
graph counts, not a fully compiled or linked kernel.

## Remaining qualification

Device attach, firmware, packet traffic/offloads, link negotiation, netmap,
virtualization/SR-IOV, hotplug, error recovery and live tracing require runtime
qualification. This profile selects tests=[]; no host interface was configured.
Full kernel link/order/identity, post-processing/install, modules, alternate
KERNCONF, ARM64/RISC-V64, world, pkgbase/hardware publication and bootstrap remain
open. Disk reserves pass; controlled CPU, memory and disk I/O/use comparisons
remain open. Persistent cache qualification is separate; no managed disk cache
was enabled. No host install, upgrade or reboot occurred.
