# NFS kernel modules on three architectures

2026-11-01. Native module/install candidates now cover nfscl, nfscommon, nfsd,
nfslockd and nfssvc on amd64, ARM64 and RISC-V64. They select the thirty-two
original C translation units, including checked-in kernel NLM RPC sources.
Nfscommon and nfssvc preserve Make's export-all policy; others preserve default
exports. Existing native freestanding object/module/CTF/debug/install rules are
reused. Original C, NFS protocol, audit, MAC and tracing behavior is unchanged.

## Source, configuration and generation contracts

The kernel NLM RPC C/headers are checked into the source tree and compiled
directly by maintained Make. This migration preserves that source contract;
it does not substitute regenerated userland RPC variants. The existing native
makeobjops pipeline supplies generated vnode interfaces. Source-owned modern and
legacy NFS, RPC/GSS, network and congestion-control header providers preserve
package boundaries, including legacy NFS headers still used by lock management.
No runtime Make parser or SDK include escape is introduced.

GENERIC enables NFS_ROOT on all three independently checked parent trees.
The typed boolean `//tools/build/bazel/config:kernel_nfs_root` defaults to true
for this GENERIC candidate and drives both actual config(8) overrides and native
select of the optional nfs_diskless object group. False emits a real nooptions
NFS_ROOT wrapper and removes that group. Feature/config/source selection share
one setting. Broader custom KERNCONF and other NFS option combinations remain
separate work; this is not arbitrary-configuration coverage.

The first native r5 load fails because a configurable source list was iterated
by an existing macro during loading. The corrected graph uses ordinary select
on optional object groups at module assembly, matching the existing GEOM pattern.
The r6 attempt then identifies missing declared legacy NFS headers; those actual
headers are declared. Failures remain retained. No C or compiler isolation is
changed to bypass them, and failed attempts do not count as successful runs.

## Independent comparison evidence

All thirty independent Make build/install references pass under
`/usr/obj/usr/src/bazel-nfs-modules-make-20261101/`. Commands, queried ARCH_FLAGS,
objects, generated inputs, resource counters and NO_ROOT METALOGs are retained.
Reference compilation uses sixteen aggregate slots. Six maintained build-bsd
kernel-profile runs pass under
`/usr/obj/usr/src/bazel-nfs-modules-{amd64,arm64,riscv}-{plain,ctf}-r7-20261101/`.
Each selects ten module/install targets; executable tests are empty in this
artifact-only profile.

All fifteen plain modules match Make byte for byte. All fifteen installed CTF
modules match every ELF section except build-ID/debuglink contents, including
code, symbols, relocations, CTF and SDT where present. Both actual native and Make
debuglink CRCs validate. Separate DWARF/build-ID/layout differences remain
recorded; source debugging is unqualified. All forty-five file/debug install
records match destination, type, owner, group, mode and package/debug tags.
Directory metadata and linker.hints are outside this file comparison.

Actual execution logs cover all 192 target compile actions, with correct triples,
-nostdinc/-ffreestanding, no SDK include-file inputs and the real enabled NFS-root
header in each diskless source action. The actual default opt_global.h input digests
also match each independent Make GENERIC parent, preserving existing global options.

Six additional independent Make/native client comparisons cover NFS-root false
on all three architectures and both CTF/debug modes. Independent config generates
actual include-GENERIC/nooptions-NFS_ROOT parent trees, not replacement headers.
Three plain modules match exactly; three installed CTF modules match within the
same debug limits, both actual debuglinks validate and all nine additional
install records match. The sixty-six client compile actions use actual empty
root-option headers and omit nfs_diskless.c. Both nfs_setup_diskless and
nfs_rootconf symbols are present in the enabled native modules and absent in all
six disabled modules. This proves build/configuration selection, not NFS-root boot.

Default review, compiler/source-input audit, bounded source/header marker scans
and reproduction scripts are under
`/usr/obj/usr/src/bazel-nfs-modules-review-20261101/`.
Root-disabled config, references, receipts and review use the prefix
`/usr/obj/usr/src/bazel-nfs-root-off-` with `config-20261101`, `make-20261101`,
`{amd64,arm64,riscv}-{plain,ctf}-r7-20261101` and `review-20261101`.

## Coverage and remaining gates

Fresh architecture-checked recursive Make inventories under
`/usr/obj/usr/src/bazel-nfs-modules-inventory-20261101/` report:

| Target | Selected leaf KMODs | Selected direct amd64 module macro declarations |
| --- | ---: | ---: |
| amd64 | 729 | 150 |
| ARM64 | 615 | 141 |
| RISC-V64 | 543 | 141 |

Macro presence is source inventory, not a target/runtime pass. Separate component
comparisons establish 141 current cross-module candidates, not all selected
modules, complete kernels or all option combinations.

The bounded thirty-two-source scan retains 92 direct SDT/KDTRACE/audit/CTR marker
lines across eleven files; the separately recorded nfs_kdtrace.h scan retains
nineteen wrapper/configuration lines. These are textual counts, not active-probe
counts. Existing NFS server SDT schemas and client callback paths are preserved;
sections and relocations compare with Make. NFS provider-module coverage and live
probe arguments still need qualification. Matching-kernel module loading,
client/server traffic, mounts, file locks/recovery, RPC authentication/TLS/GSS,
credential/MAC/audit denials, NFS-root boot and network/storage failure/concurrency
cases remain runtime work.

This tranche uses prepared Make SDK tools and does not establish full bootstrap,
sandbox, input mutation, controlled CPU/RAM/disk-I/O/disk-allocation performance,
world/kernel/pkgbase or publication. No host installation, module loading or
network/service changes occurred. The existing format-5 build-settings API passes
the typed root setting through the maintained frontend; no signing/publication
helper change is required for these module/manifest targets. Make remains the
production backend; BIP remains excluded.
