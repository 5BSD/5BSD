# Eight additional filesystem modules on three architectures

2026-11-01. Native module/install candidates now cover autofs, ext2fs, fusefs,
msdosfs, msdosfs_iconv, p9fs, tarfs and ufs on amd64, ARM64 and RISC-V64.
Explicit source-owned BUILD inputs select all sixty-four original C translation
units, including the UFS/FFS reachover sources. UFS preserves Make's export-all
policy; msdosfs preserves its single msdosfs_iconv export; others preserve default
exports. Existing freestanding object, module, CTF, debug and installation rules
are reused. Original filesystem C, audit and MAC behavior are unchanged.

## Real generated inputs and corrected dependencies

All DDB/direct-I/O/quota/SUID-directory/UFS/FFS/tarfs/ZSTD option headers come
from the actual target GENERIC configuration. Private filesystem headers keep
source package ownership; narrow FFS source exports feed UFS. FUSE explicitly
declares both Linux errno header and textual .inc data and its SipHash/debugger
headers. There is no SDK include escape or runtime Make parser in this graph.
The one-time migration inventory extracted Make's maintained SRCS lists into
ordinary explicit BUILD declarations; Bazel does not execute that inventory
script during a build.

The first independent Make batch passes forty-four cases and fails four cross
msdosfs_iconv cases: vnode_if.h is missing from its SRCS. amd64's existing kernel
object directory masks that missing generated dependency. The maintained Makefile
now declares vnode_if.h. All forty-eight clean Make build/install references pass
under `/usr/obj/usr/src/bazel-filesystem-modules-make-r2-20261101/`; the original
failure logs remain under `bazel-filesystem-modules-make-20261101`.
Commands, queried ARCH_FLAGS, objects, generated inputs, resource counters and
NO_ROOT METALOGs are retained. The repeat reference batch uses four parallel
module builds with four compilation jobs each: sixteen aggregate slots.

The initial native r4 amd64/plain attempt fails on the undeclared real Linux
errno .inc include. After declaring it, all six maintained build-bsd native
kernel-profile runs pass under
`/usr/obj/usr/src/bazel-filesystem-modules-{amd64,arm64,riscv}-{plain,ctf}-r5-20261101/`.
Each selects sixteen explicit module/install targets; executable tests are empty
in this artifact-only profile. No failed attempt is counted as a passed run.

## Artifact, metadata and option checks

All twenty-four plain modules match Make byte for byte. All twenty-four installed
CTF modules match every ELF section except build-ID/debuglink contents, including
code, symbols, relocations, CTF and SDT where present. Both native and Make
debuglink CRCs validate against actual separate debug files. Separate DWARF,
build-ID and layout differences remain recorded; source debugging is unqualified.
All seventy-two file/debug install records match destination, type, owner, group,
mode and package/debug tags. Directory metadata and linker.hints are outside this
file comparison.

The compiler audit covers all 384 source/configuration combinations using 391
successful compile records across the retained r4/r5 attempts. Sixteen amd64/plain
source actions reused from r4 are explicitly attributed to that log; successful
r5 receipts and independent final artifact comparisons establish the corrected
configuration. The failed FUSE compile remains separately recorded. Every audited
successful action uses the proper target triple, -nostdinc/-ffreestanding and no
SDK include-file inputs. Cache reuse is accounted for, not forced away merely to
create additional execution records.

Six more Make/native tarfs comparisons qualify kernel_zstdio=false on all three
architectures and both CTF/debug modes. Independent config generates actual
include-GENERIC/nooptions-ZSTDIO parent trees; opt_zstdio.h is empty rather than a
replacement fixture. Three plain modules match exactly, three installed CTF
modules match within the same documented debug limits, both actual debuglinks
validate and all nine additional install records match. Actual compile logs cover
all twenty-four disabled-branch source actions and their empty option inputs.
ZSTD undefined symbols appear in all six enabled native tarfs modules and none of
the six disabled modules. This establishes branch selection and artifacts, not
live decompression or malformed-archive behavior.

Default review, compiler audit, source/input hashes, marker scan and reproduction
scripts are under `/usr/obj/usr/src/bazel-filesystem-modules-review-20261101/`.
ZSTD-disabled config, references, native receipts and review use the prefix
`/usr/obj/usr/src/bazel-filesystem-zstd-off-` with `config-20261101`,
`make-20261101`, `{amd64,arm64,riscv}-{plain,ctf}-r5-20261101` and
`review-20261101`.

## Reconciled scope and open gates

Fresh architecture-checked recursive Make inventories at
`/usr/obj/usr/src/bazel-filesystem-modules-inventory-20261101/` report:

| Target | Selected leaf KMODs | Selected direct amd64 module macro declarations |
| --- | ---: | ---: |
| amd64 | 729 | 145 |
| ARM64 | 615 | 136 |
| RISC-V64 | 543 | 136 |

Macro presence is source inventory, not target build or runtime proof. Separate
component comparisons establish 136 current cross-module candidates, not complete
kernels or all selected module/configuration combinations. Custom configuration
and standalone non-KERNBUILDDIR defaults remain broader work.

The bounded sixty-four-source scan retains 312 audit/tracing marker lines in
twenty-nine files. C and existing SDT/audit/MAC paths are unchanged. Matching-
kernel module loading, mount/read/write/unmount, errors/corruption, concurrency,
credential/namespace checks, live probe/audit arguments, storage compatibility
and performance still need runtime qualification. Concurrent makefs userland VMs
use a Make kernel and do not qualify these Bazel module artifacts.

Prepared SDK verification reads thousands of source/snapshot/staged input files
before compilation. One cold preflight took several minutes during concurrent
work; later warm runs progressed faster. This is an observed qualification
startup cost, not a controlled benchmark or a reason to skip digest checks.
CPU, aggregate RAM, disk-I/O, allocated-disk and cold/warm/cache measurements,
bootstrap/sandbox/input-mutation checks, complete world/kernel/pkgbase and
publication remain open. No host installation or module loading occurred. The
maintained frontend needs no new API, signing or publication helper for these
normal module/manifest targets; its manual records coverage. Make remains the
production backend; BIP remains excluded.
