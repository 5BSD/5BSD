# Storage core built-in kernel qualification

## Scope (2026-11-02)

76 selected amd64 GENERIC C objects now have native built-in declarations:
25 CAM, 12 NVMe, 12 UFSHCI and 27 GEOM (including labels and partitions).
Existing CAM subdirectories and GEOM part sources retain their existing package
owners. Only the previously unowned UFSHCI directory gains a new package; no
existing native declarations refer across that new boundary. 67 physical header
contexts share identical prerequisite sets. No production storage sources change.

Native cc_library compilation uses maintained common built-in warning order and
typed WERROR/debug/CTF settings. Existing config-tree extraction supplies every
consumed option, including empty outputs. Existing bus/device/PCI/ACPI/NVMe and
GEOM partition schema actions produce native interfaces; scoped wrappers expose
only their generated header outputs. Vnode/offset producers remain native.
Make-generated files supply reference comparisons only, never build inputs.

The maintained build-bsd bazel-test format-5 interface handles SDK/platform,
16 workers and compact logs. No frontend C/backend API, CLI/manual option,
staging, signing/verification or package-policy change is needed. Make stays
production/default; BIP remains excluded.

## Retained evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-storage-core-make-metadata-r1-20261102 captures actual supported
  Make recipes with filemon disabled; all 76 completed reference objects retain
  their hashes. Metadata recording is not full dynamic input or performance proof.
- bazel-kernel-storage-core-amd64-ctf-r1-20261102 is the passing native frontend
  build. All 76 actual compiler actions are fresh, reporting cacheHit=false.
  Immutable final captures bind through native CTF input/output digests.
- bazel-kernel-storage-core-review-r1-20261102 verifies 10,076 physical and 330
  generated prerequisites. Selected source hashes match the independent inventory.
  Actual ordered warnings, defines, code-generation option sets, stack protection,
  final debug switch, language and forced includes match Make.

All 76 .text and .SUNW_ctf sections are byte-identical to Make. Allocated payloads
and layouts match except 51 exact known-source filename spellings; complete string
pools and 27,881 nondebug relocations compare symbolically. Full DWARF, symbol-index
and string-table byte parity is not claimed. No artifacts are rewritten.

CTF graph review uses the bounded read-only procedure documented in
OPENZFS-KERNEL-QUALIFICATION.md. Typed symbol identities stay strict. Only
zero-type string object addresses use verified complete canonical strings and
interior offsets, with full-literal size constraints. Separate full-string-pool,
allocated-layout and relocation gates bind the original hashes. No production
verifier is modified or claimed to pass a broader comparison scope.

Generated-interface provenance comments map only actual schema source paths to
basenames; original Make digests remain recorded. Compact-log review streams the
verified upstream converter and verifies its 189 recorded bindings before/after.
Source/declaration/profile and review implementations remain alongside results.

Configured query r26 passes for 1,427 known built-in groups and 1,602 compiler
actions. Reconciliation r21 finds 1,593 source matches, two object-name matches
and four generated-name matches among 2,466 Make final-link products, leaving
867 unmatched. Three auxiliary generator objects are separate. These are known
amd64 graph counts, not a complete compiled/linked kernel or architecture coverage.

## Observability and remaining gates

The bounded source-hash-bound call scan finds existing tracing/CTR-family markers
in 12 files across CAM, NVMe and GEOM. The other 64 files do not establish missing
shared instrumentation. Production hooks remain unchanged. Controller attach,
CAM discovery/queues, NVMe/UFSHCI interrupts/DMA/error/reset, partition/label
recognition and storage hotplug/multipath/recovery need device/runtime tests.
The profile has tests=[] and performs no host storage operations.

Complete kernel link/order/identity/post-processing/install, all modules,
alternate KERNCONF, ARM64/RISC-V64, complete world, pkgbase/hardware publication,
bootstrap and boot/service checks remain open. Disk reserves pass; controlled
CPU, memory, disk I/O/use and cache comparisons remain open. No host installation,
upgrade or reboot occurred. The recorded 2026-10-03 ZFS/filedesc issue was
consulted, including its appended October 12 diagnosis of the separately fixed
5BSD procdesc edge. This build migration makes no lock-order fix or runtime claim.
