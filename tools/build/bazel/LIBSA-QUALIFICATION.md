# Regular AMD64 standalone library candidate (2026-11-03)

The later [cross and private EFI checkpoint](LIBSA-CROSS-EFI-QUALIFICATION.md)
extends this initial regular AMD64-only evidence. The scope below describes the
initial run.

## Native implementation

`//stand/libsa:static_archive` builds all 191 members of the maintained regular
AMD64 standalone library under the selected reference profile. Twenty native
`cc_library` groups preserve distinct source options and feed an explicitly
ordered component archive. One source-owned common flag sequence preserves early
ZFS/SPL include priority and per-source suffixes. No native action executes Make
or interprets its metadata. Source lists and flags were transcribed once during
migration and are now ordinary maintained Starlark declarations.

The inventory includes allocator/core I/O, network/boot filesystems, libc helpers,
compiler builtins, setjmp assembler, decompression, GELI, ZFS and crypto sources.
Physical source header/textual contexts and architecture aliases are declared.
Borrowed sources use owner-package filegroups, preserving existing exported-file
visibility. Existing safe include aliases and three empty xlocale compatibility
files reproduce the maintained Make beforedepend recipe; no replacement API or
ad hoc stub is introduced. The three Rijndael sources retain Make's existing
NDEBUG flag. Assertions were not disabled elsewhere to achieve equality.

This is an explicit initial candidate, not complete libsa migration. Its current
source inventory requires AMD64, enabled GELI/ZFS/disk and disabled global
verification; incompatible selections are rejected before compiling. The 260-unit
private EFI reference exists but its native implementation is still required.
ARM64/RISC-V, IA32 and alternate optional source inventories also remain required.
The scope will expand through native declarations, not default-profile fallback.

## Comparison and installation evidence

All records are under `/usr/obj/usr/src/`:

- `bazel-libsa-amd64-make-r1-20261103`: independent maintained Make reference,
  original per-object compiler metadata and installation records.
- `bazel-libsa-amd64-r2-20261103`: successful native archive and immutable
  captured output through the maintained frontend, with all sixteen CPUs.
- `bazel-libsa-amd64-review-r2-20261103`: exact member-order, external-symbol,
  allocated-section and symbolic-relocation comparison using a neutral archive
  scope caption. Revision 1 retains the earlier inherited Ficl caption.
  Both report the same original member contracts without normalization.
- `bazel-libsa-amd64-filename-controls-r1-20261103`: isolated original compiler
  controls for lz4, zfs_zstd and md5c, with only macro filename mapping and removed
  dependency-output bookkeeping. Original artifacts remain unchanged.
- `bazel-libsa-action-review-r1-20261103`: all 191 actual successful owned compiler
  outputs and ordered archive input/output digests bound to the captured archive.
  Every compiler owns its Bazel dependency output. The revision 3 repeat
  executes no compiler/archive/link actions while adding the manual/install
  targets; the separate repeat record retains that action evidence. Only the original three
  Rijndael compilers receive NDEBUG; no verifier is enabled in this context.
- `bazel-libsa-amd64-r3-20261103` and `bazel-libsa-install-review-r1-20261103`:
  compressed manual bytes, decompressed source and logical installation-file
  metadata match Make. Archive bytes remain unchanged from revision 2. Revision 4 verifies the
  final source declarations preserve archive, manual and manifest bytes.

Raw comparisons match all archive order and external symbol contracts. Allocated
bytes/relocations match 188/191 original members. The other three retain assertion
filename differences; separate original compiler controls match their complete
allocated bytes and relocations. No production mapping, binary rewriting or
normalization was added. Full object/debug bytes and debug/source lookup remain
open, as with the other standalone candidates.

The archive is internal and is not installed as a userland library. The regular
library owns `/usr/share/man/man3/libsa.3.gz`, root:wheel, mode 0444, tagged
`package=bootloader-dev`. Native compression uses the existing declared gzip
rule with `-cn`; the typed install manifest materializes its payload. Existing
`split_manpages` configuration selects `bootloader-man` when enabled, following
bsd.man.mk; only the default nonsplit file metadata was qualified here. This proves
the selected file payload/metadata, not full directory/mtree, tar/pkgbase or live
installation parity. No programs, hardware or OS updates were installed.

The first native analysis failed on duplicate visibility declarations for
already-exported borrowed OpenZFS sources. Owner-package source filegroups fixed
that without widening existing exported-file visibility. The failed analysis is
retained in `bazel-libsa-amd64-r1-20261103`.

The normal frontend also rejects a GELI-disabled request rather than silently
using this default source inventory; the expected failure and diagnostic are in
`bazel-libsa-option-rejection-r1-20261103`.

## Integration and outstanding qualification

The normal build-bsd format-5 interface selects `static_archive`, `manual_gzip`
and `install_manifest`; its existing backend materializes/captures them. No C
frontend option, signing/staging policy or publication backend contract changed.
The manual and observability ledger are updated in the same source change.

These runs build artifacts and compare them externally. They do not execute the
191 library routines, boot a loader or establish filesystem/crypto runtime safety.
Private EFI/global-verifier contexts, supported alternate options/architectures,
manual option/layout/package integration, full loader/world/kernel/module builds,
reproducible bootstrap and runtime/performance gates remain open. SDK input
breadth/verification costs recorded in the Ficl checkpoint still need work;
these component actions are not a controlled CPU/memory/disk benchmark.
Make remains production/default. BIP remains out of scope. No VM, host upgrade,
installation or reboot occurred.
