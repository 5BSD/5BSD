# RDMA, InfiniBand and Mellanox module qualification

## Scope (November 2, 2026)

Fourteen selected amd64 GENERIC leaves: ibcore, if_infiniband, ipoib, irdma,
iser, mlx4, mlx4en, mlx4ib, mlx5, mlx5en, mlx5ib, mlxfw, mthca and rdma/krping.
The native descriptions declare 206 compiler contexts: 194 ordinary C sources
and 12 KOBJ-generated source contexts from one shared schema. They use 171
source-owned object groups and 263 physical header contexts, including 83 exact
existing context reuses. LinuxKPI/OFED roots, forced kconfig.h before opt_global.h,
source-specific definitions/warnings and generated interfaces are explicit inputs.

These are amd64 module build/artifact checks, not device/driver/RDMA runtime
qualification. Make remains the production/default backend; BIP is excluded.
No host installation, reboot, upgrade or module loading occurred.

## Independent originals and actual compiler evidence

All 28 untouched original Make controls build and install in isolated object/
stage directories, using the actual selected kernel SYSDIR, tied-kernel setting,
parent option exports, original toolchain and all 16 logical CPUs. All 554
consumed module option-header occurrences match selected kernel headers byte-for-byte.

Both native CTF/debug and plain profiles pass through maintained build-bsd
format-5 inputs and the frozen SDK. Each has 206 actual successful uncached
compiler witnesses. Compiler/source hashes, defines, semantic code-generation
flags, warning order, forced-header order and physical include order match Make.
Each profile has exactly 83,230 original/native consumed dependency occurrences;
all per-context consumed basename/content-hash multisets reconcile without extra
or missing occurrences. Actual .d files and action inputs are retained. Generated
KOBJ outputs differ only the checked exact schema source-path provenance comment;
raw hashes and transformations remain bound to the review.

All 14 initial-link parameter files per profile are captured, digest-checked and
matched to original complete object order. This is actual executed evidence,
not a reconstructed parameter file or an invented cache execution.

irdma's original recipe also copies ice_rdma.h locally. The recorded dependency
files show the compiler instead consumes /usr/src/sys/dev/ice/ice_rdma.h directly.
The native rule declares that actual physical header; no unused copy action or
special authority is needed. Source hashes and original copy metadata are retained.

## Rejections and corrections

The first native profile built but strict review rejected iSER's physical include
order. Its original Make rule supplies the general kernel root before LinuxKPI/
OFED roots. Its native source groups now place the existing public kernel header
provider first. The first attempt to express that order failed Bazel analysis:
the maintained helper duplicated this provider in its default dependency list.
The helper now removes a default provider only when already supplied by the
ordered override list. Default vectors remain unchanged. All 39 module/debug/
install outputs of the other 13 modules are byte-identical across that correction.
The failed builds/comparisons remain retained.

After include-order correction, iSER's remaining allocated/relocation differences
come from embedded source filenames: original Make uses dev/iser//file.c, native
uses canonical dev/iser/file.c. A separate original Make control includes the
unchanged module Makefile and appends exactly one derived directory map:
-fmacro-prefix-map=/usr/src/sys/dev/iser//=/usr/src/sys/dev/iser/ .
All ten original/control compiler vectors (five module objects, two profiles)
differ by exactly that flag, preserving dependency-generation and other flags.
The ordinary baseline remains rejected/retained; no native source, compiler
flag, artifact or comparison tolerance was changed to conceal that difference.

## Artifact, install and instrumentation results

Thirteen plain native ELF files are whole-file byte-identical to untouched
original Make outputs. iSER's plain ELF is whole-file byte-identical to the
independent filename control. Do not describe all fourteen as untouched-original
byte parity.

All fourteen CTF/debug section inventories/payloads, including CTF itself, match
the corresponding controls except build-id/debuglink fields. Both original and
native debug CRCs validate. All 28 CTF/debug and 14 plain installation records
match original destinations, types, owner/group/mode and package/debug tags.

A bounded scan of 195 physical C/schema inputs records two candidate DTrace/SDT/
KTR/audit lines. All four modules with actual compiled SDT/DTrace sections retain
exact sections/relocations. No live probe, hardware, network or audit-completeness
claim follows from this scan. See observability-audit.md for the running log.

## Evidence, frontend review and remaining work

- Original controls: /usr/obj/usr/src/bazel-rdma-module-make-references-r1-20261102
- Explicit filename controls: /usr/obj/usr/src/bazel-rdma-module-filename-controls-r1-20261102
- Final CTF/debug: /usr/obj/usr/src/bazel-rdma-modules-ctf-debug-native-r3-20261102
- Plain: /usr/obj/usr/src/bazel-rdma-modules-plain-native-r1-20261102
- Compiler/link/install/artifact/dependency review: /usr/obj/usr/src/bazel-rdma-modules-review-r1-20261102

Review evidence retains source declarations, driver scripts, source/SDK bindings,
rejections and scope limits. Disk guards ran; timings are not controlled CPU,
memory, disk I/O or cache/sandbox benchmarks.

Frontend integration uses the normal build-bsd bazel-test action/backend and
existing format-5 inputs. This changes native source/header dependencies and
ordered composition, not CLI inputs, manual options, signing, staging or package
publication. No C frontend or security/publication policy change is required.

Local BUILD presence is 679 of 729 selected amd64 leaves (50 remain). This is
declaration presence, not a percentage of full qualification. ARM64/RISC-V builds,
current full GENERIC kernel refresh, complete world/rescue/library parity,
options, installation/pkgbase, bootstrap/hardware/publication, VM/runtime and
performance gates remain open. Make remains default pending those gates.

### Supplementary option-count correction

The initial supplementary observer skipped directory/KMOD mismatches and counted
some genoffset host-helper dependency files. The corrected object-driven audit
requires every original module metadata TARGET and -MF file; its option count
matches the complete original/native compiler-input review. See
[Chelsio qualification](CHELSIO-MODULES-QUALIFICATION.md) and the retained
option-audit-correction.json diagnostic in this cohort's review directory.
No native input, artifact or core compiler-coverage result changed.

### Separate-debug evidence scope correction

The CTF/debug payload comparisons above concern stripped installed module ELF
sections, including CTF. Separate debug files were independently CRC-checked;
that did not prove DWARF parity between Make and Bazel. Direct separate-file
comparisons now record five differing sections and leave semantic/source lookup
qualification open. See [module debug qualification](MODULE-DEBUG-QUALIFICATION.md)
for exact observed scope and required follow-up. Runtime ELF/CTF, compiler-input,
installation and instrumentation results remain unchanged.
