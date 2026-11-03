# ARM64/RISC-V storage module qualification

## Storage module checkpoint (2026-11-03)

Twenty-three shared storage module leaves per ARM64/RISC-V architecture and
two ARM64-only Linux compatibility children pass native builds and artifact
review. The shared components cover 92 plain/CTF variants, 380 compiler
contexts/55,888 canonical consumed pairs, 184 ordered links and 138 installation
records. Forty-two of 46 plain artifacts equal untouched Make bytes; four equal
explicit identical-source filename controls. CTF/runtime contracts retain that
42/4 distinction. All 46 shared separate DWARF files differ; source/debugger
qualification remains open.

Complete recursive MFI/MRSAS comparisons cover eight family variants and all
24 installation records, including the two ARM64 children. The children add
four compiler contexts/546 consumed pairs and eight ordered links. Family
records overlap component records; they are not extra installation coverage.
Original amd64 controls qualify MMC/consumer exports and MRSAS compiler policy.
Twelve actual positive/negative provider tests pass across six profiles.

The changes preserve real Make compiler options, forced headers, generated
schemas, exports and child selection. The normal format-5 build-bsd workflow
uses 16 CPUs and a disk reserve. Its C frontend needs no new command-line option.
No C implementation or probe changed. Full world/cross kernels, separate DWARF,
package publication, runtime, bootstrap/sandbox and performance gates remain
open. Make remains production/default; BIP remains excluded.

## Source-owned design and corrections

The shared leaves are cfiscsi, ctl, iscsi, iser, isp, md, mfi, mfip, mmc,
mmcsd, mpr, mps, mpt, mrsas, four nvmf components, rtsx, sdhci, sdhci_pci,
sdio and tws. ARM64 additionally selects mfi_linux and mrsas_linux through the
actual parent Make conditions. Source-owned BUILD targets express this selection;
Bazel execution does not discover sources or policy through Make or migration
JSON. Typed family manifests compose complete child/component installation
records without filtering original recursive records to make comparisons pass.

Actual independent compiler commands retain MRSAS's -fgnu89-inline on all three
ABIs. Its earlier omission was found by semantic flag review, even though some
binary comparisons already matched. ARM64's declared architecture view preserves
machine/../linux for the original source, using the existing architecture-header
rule. Shared module header overrides retain order without duplicating mandatory
system dependencies; configurable caller dependency lists remain supported.
ISER retains forced LinuxKPI configuration/header overlays and its definitions.

MMC now explicitly exports its public bus/bridge API in maintained Make and
native metadata. Positive tests require five mmcsd calls and the mmc_driver
references from rtsx/sdhci_pci. Negative tests relocalize the real provider and
must identify exactly those seven edges. The normal loader's local-symbol
lookup can conceal this defect; no runtime module-loading failure is claimed.

## Original controls and rejected evidence

Original references query real parent-inherited Make sources, object order,
exports, options, architecture flags and regular Makefiles. /dev/null is an
explicit empty configuration character-device sentinel. Actual .d/META compiler
commands independently confirm physical and generated prerequisites. Generated
KOBJ payload comparisons allow only the exact schema-provenance comment line;
raw hashes and the difference are retained.

CTL textually includes ctl_ser_table.c. Native declarations already included it,
but the initial original snapshot did not bind it. Fresh corrected controls bind
it before compilation; the initial rejection is retained. Independent NO_SUBDIR
yes controls establish component installation, while untouched recursion proves
the complete MFI/MRSAS family installation. Both families' actual child context
and physical source bindings are captured before their fresh recursive builds.

ISER and SDIO source filename spelling differs from canonical physical spelling
in four module/architecture pairs. Explicit Make controls add only the declared
macro-prefix maps; actual sources, semantics, forced headers, consumed inputs,
MD/MF/MT dependency policy and ordinary artifacts remain recorded. These are not
untouched-Make byte matches. Raw separate DWARF differences are not normalized
away; debuglink descriptors and CRCs are independently checked.

An external host update changed execution tools and runtime libraries. The old
native-r3 SDK receipt correctly rejected execution; the maintained SDK tools
captured native-r4 and verified 16,712 bindings. The old receipt remains intact.
Some ARM64 plain actions were cached from an earlier attempt. A later check of
mutable working outputs rejected stale objects after CTF builds. Acceptance uses
a fresh normal plain profile with immediate capture of all 97 module compilers
and 50 module links; the rejected cache-witness attempt establishes no cache
qualification. Dependency observation preserves raw compiler paths, checks
machine/../linux aliases against declared normalized paths, and verifies file
identity and SHA-256 before capture.

## Evidence and scope

Accepted shared review:
/usr/obj/usr/src/bazel-cross-storage-buses-review-r7-20261103/summary.json
and supplement.json. Complete family review:
/usr/obj/usr/src/bazel-storage-recursive-families-review-r5-20261103/summary.json.
Original amd64 regressions:
/usr/obj/usr/src/bazel-storage-mmc-amd64-review-r1-20261103/summary.json and
/usr/obj/usr/src/bazel-storage-mrsas-amd64-review-r1-20261103/summary.json.

The accepted cross profiles are ARM64 plain r6, ARM64 CTF r5 and RISC-V
plain/CTF r5, dated 20261103. Their actual-capture-r2 manifests retain compiler
commands, consumed-generated bytes, dependency files and ordered link parameter
files. Frontend receipts, source/SDK inputs, per-command resource observations,
disk guards and rejected attempts are under /usr/obj/usr/src. Original controls,
selection queries, filename-map proof and the 93-source lexical instrumentation
inventory are indexed under bazel-cross-storage-buses-work-r1-20261103.

No target modules were loaded or executed. This does not prove working hardware,
full cross kernels/world/packages, installation on a running machine, VM boot,
DTrace/audit delivery, aggregate memory/I/O regressions, full sandboxing or
reproducible bootstrap. Separate DWARF/source lookup remains a required gate.
Only full package publication may advance the combined repository's latest;
these selected module checks do not publish a system or change the production
backend. Ports retain Make.
