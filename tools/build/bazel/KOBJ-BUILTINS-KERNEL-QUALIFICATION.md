# Generated kernel interface object qualification

## Scope (2026-11-02)

49 additional amd64 GENERIC final-link objects have native compilation of generated
KOBJ interfaces. The original source-owned .m generators already supply C/header
pairs; source output groups now feed normal cc_library compilation and the
maintained CTF pipeline. Original schemas remain in their 32 owning source
packages, including nested schemas already owned by a parent package. No schema,
production C, assembly or makeobjops.awk body is changed.

35 physical prerequisite contexts retain header ownership. Physical and generated
header target names are distinct. Interface wrappers expose original generated
headers; native GENERIC configuration supplies options. The two IRDMA interfaces
retain Make's explicit ice include root for their consumed ice_rdma.h. No Make
subprocess or reference-generated file is used by the native build graph.

The maintained build-bsd format-5 target workflow supports the 49 object targets
and 49 original generator targets directly, with immutable artifact captures for
all C/header pairs. Existing frontend C, staging/signing/verification, publication
and manual options need no API changes. Make remains production/default; BIP
remains excluded.

## Retained evidence

All paths below are under /usr/obj/usr/src.

- bazel-kernel-kobj-builtins-make-metadata-r1-20261102 records 49 original
  generate-and-compile recipes with filemon disabled. Every original object hash
  stays unchanged. The audit explicitly checks each recipe's original awk command,
  source schema and following compiler invocation; production builds parse none
  of this metadata. Complete dynamic-input discovery is not claimed.
- Native r1 retains the physical/generated header target-name collision. The
  preparation helper's original declaration identities and namespace failure are
  retained; distinct physical-provider names correct it. Native r2 then exposes
  the missing IRDMA include root through a real sandbox compiler failure.
  The physical header provider restores Make's explicit root. Native r3 passes
  for all 98 targets with 16 jobs and disk-reserve monitoring.
- bazel-kernel-kobj-builtins-review-r1-20261102 retains declaration copies,
  schema hashes, actual execution bindings and artifact reports. generation-review
  compares all 98 immutable C/header bodies with Make after changing only the
  exact schema-path provenance comment to input basename. Both original and
  canonical hashes are retained; artifacts are not rewritten.
- All 49 actual compiler actions bind to immutable final object captures through
  CTF input/output hashes. Final configured argv agrees with executed argv.
  Ordered warnings, defines/undefines, code-generation options, final debug/stack
  policies, language and forced headers agree. Checks cover
  4,065 physical and 277 generated prerequisite occurrences,
  including generated compilation sources and their original schema provenance.
- All 49 machine-code/CTF payloads and all runtime sections are byte-identical.
  CTF semantic graphs agree; 1,003 non-debug relocations are identical, with zero
  source-filename string changes in the compiled objects. Full DWARF/string/symbol
  table byte equality is not claimed.
- A bounded source-hash-bound scan of the original 49 schemas finds no matching
  call-shaped tracing/audit markers. Schemas can embed code or indirect hooks;
  this neither proves absent instrumentation nor live interface behavior.

Closure query r41 passes for 2,280 known groups and
2,455 compile actions. Reconciliation r34 finds 2,396 physical source-identity
matches, 53 generated-name-only and two object-name-only matches among 2,466
Make final-link products, leaving 15 missing. The graph-only generated-name
classification is intentionally retained: the separate artifact/generator checks
above establish stronger evidence for these 49 interfaces, not all generated
products. These are not complete linked-kernel or system-completion counts.

## Remaining gates

The remaining 15 unmatched products include RPC generation, renamed/custom
crypto/radix objects, VDSO payload and final-link additions. Four other generated
name matches and two object-name matches need independent identity reconciliation.
Full final-link order, versioning, post-processing/install, modules, alternate
KERNCONF, ARM64/RISC-V64, world, pkgbase/hardware publication, bootstrap, boot,
interface/driver runtime behavior and controlled CPU/memory/disk I/O/use comparisons
remain open. This profile has tests=[] and performs no device operations. No
managed disk cache was enabled. No host install, upgrade or reboot occurred.
