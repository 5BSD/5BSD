# Network and RDMA module qualification (2026-11-02)

## Scope and native composition

Nine selected amd64 GENERIC leaves now have source-owned native module targets:
axgbe/if_axp; bnxt/bnxt_en and bnxt_re; bxe; cxgb/cxgb and cxgb_t3fw; and
qlnx/qlnxe, qlnxev and qlnxr. These are artifact/install qualifications, not device
or network operation tests.

The graph contains 98 compiler contexts, 76 distinct ordinary C source files and
five generated-C contexts from the single lkpi_iic_if.m schema, grouped into 82
native object groups. It uses 116 distinct physical header contexts (32 exact
existing contexts reused). LinuxKPI/OFED child files retain their physical owning
packages; parent namespace providers expose original ordered include roots with
narrow file visibility. The schema's existing declared generator supplies both
headers and C; the source filegroup is reused across contexts.

Original compile policies are explicit: LinuxKPI kconfig precedes opt_global for
AXGBE/BNXT and follows it for QLNX; OFED/LinuxKPI roots retain their actual used
order relative to BSD headers. Unused original search roots are not added as
undeclared directories. Per-driver defines, warnings, local debug flags and
-fno-inline are retained; WERROR remains a typed setting. All nine original
EXPORT_SYMS=NO and package=kernel policies agree with eighteen actual original
Make queries. No runtime C, Makefile, common-rule or security-policy change.

## Actual compiler and link evidence

Both profiles use the maintained build-bsd bazel-test format-5 path, sixteen
logical CPUs, the current captured SDK, opt compilation and strip=never. Each
profile independently records 98 successful compiler actions, checks 27,502
original Make dependency occurrences against action input digests, and retains
27,502 actual native compiler dependency occurrences with matching declared input
digests. Compiler/source identity, defines, warnings, semantic code-generation
flags, before/after forced-header order and physical include-root order pass.
Only exact single KOBJ provenance-comment paths differ for generated inputs.
Each profile also retains nine actual ordered linker argument files and input
hashes matching complete original OBJS order. No parameter reconstruction or
invented cached compiler execution was needed for this batch.

Six existing positive/negative provider regression targets report PASSED in each
profile. They do not test these nine drivers' protocol, RDMA or hardware behavior.
Static export contracts are not kernel-loader emulation; see
[MODULE-LOADER-EXPORT-CONTRACT.md](MODULE-LOADER-EXPORT-CONTRACT.md).

## Output comparisons and the rejected plain criterion

All nine CTF/debug modules preserve every recorded section inventory, metadata
and payload except build ID/debug-link values. CTF bytes agree; original/native
split-debug CRC checks pass. Eighteen CTF/debug and nine plain installed file
records agree exactly on destination, type, owner, group, mode and package tags.
This does not claim whole-file debug/DWARF identity.

Five plain modules are whole-file byte-identical to untouched Make. The first
unconditional whole-file check correctly rejected the other four: if_cxgb,
cxgb_t3fw, if_qlnxev and qlnxr. Each retains original per-module debug compilation
while global kernel debug is disabled. Final bytes differ only inside the
20-byte GNU build-ID descriptor; every byte outside that descriptor agrees.

The investigation retains the actual initial native links and independent
original-recipe linker controls. Replaying each original link with original
objects reproduces Make's build ID. Running the original SDK linker on the exact
native objects reproduces the complete native initial link byte-for-byte. The
final modules retain their respective initial-link IDs after debug stripping.
Decoded pre-strip DWARF confirms original object-directory compilation paths
versus native '.'. Raw DWARF identity is not claimed. No source, compiler policy,
Make recipe, final artifact or build ID was rewritten to obtain agreement. The
final comparator accepts these four only with hash-bound successful control
records and exact final-byte exclusion limited to the ID descriptor.

## Instrumentation and resource limits

The bounded explicit DTrace/SDT/CTR/audit-call scan finds zero candidate lines in
76 ordinary C files and one schema. Nevertheless if_bxe and if_cxgb contain SDT
tracepoint-set sections and relocation sections from included code: their
inventories and bytes match Make. Absence of direct source markers does not
mean absence of instrumentation. No live probe or new probe qualification.

The original eighteen Make controls retain CPU time, largest-child RSS, block
operation counters and observed object-tree logical/allocated size. These are
single-run observations, not aggregate parallel memory, physical device bytes,
controlled cold-cache benchmarks or complete-build performance comparisons.
Native build guards retain filesystem free-space bounds. CPU/memory/disk I/O,
cache/incremental and FreeBSD sandbox qualification remain open full-system gates.

## Retained evidence and integration

Evidence root: `/usr/obj/usr/src/bazel-network-families-modules-review-r1-20261102/`.
Original controls: `bazel-network-families-module-make-references-r1-20261102`.
Native captures: `bazel-network-families-modules-{ctf-debug,plain}-native-r1-20261102`.
The review root retains preparation versions, actual compiler/link logs and
bindings, native dependency files, original export/package policy, artifact and
install comparisons, raw original/native initial links and decoded debug dumps,
source instrumentation inventory and copied migration/review drivers. Initial
strict rejection is recorded separately; it is not reported as a passing run.

Existing build-bsd C inputs/format-5 backend and maintained module rules express
this composition, so no new CLI, manual behavior, staging, signing, verification
or publication requirement is introduced. Bundle signing is not verified boot
or protection against compromised root. Make stays production/default; BIP is
excluded. No host installation, module load, upgrade or reboot was performed.

## Remaining scope

Local BUILD presence is 543/729 selected amd64 leaves (186 missing), not a system
completion percentage. Fresh Make inventories using existing configuration
headers select 627 ARM64 and 553 RISC-V leaves; only 216/214 have recognized
cross_generic_module declarations, not build qualification. The corrected
parent-export audit exposes twelve/ten FDT-selected leaves absent from the older
cross inventory; see `/usr/obj/usr/src/bazel-current-module-selection-20261102/`.
Those inventories do not regenerate source configurations or qualify cross builds.

Alternate options/KERNCONF/WERROR, ARM64/RISC-V, actual attach/load/unload,
network/RDMA behavior, live probes, full world/rescue/pkgbase/hardware/bootstrap,
combined verified publication, VM/runtime and performance/cache/sandbox gates
remain required. No hardware support follows from successful artifact comparison.
