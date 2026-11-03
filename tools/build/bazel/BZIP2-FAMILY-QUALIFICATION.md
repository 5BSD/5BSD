# bzip2 recovery and package family on three ABIs (2026-11-03)

The normal format-5 `build-bsd` workflow now builds and checks the actual
libbz2/bzip2/bzip2recover family and its four selected pkgbase outputs on amd64,
ARM64 and RISC-V. This extends [the component qualification](BZIP2-THREE-ARCH-QUALIFICATION.md).
It does not establish full world/rescue closure, foreign execution, bootstrap,
package-manager installation, repository publication or boot qualification.

## Source-owned production and composition

`usr.bin/bzip2recover` preserves the original WARNS=6 warning vector, defines,
earlier `-fpie` and later `-fPIE`, target ISA/ABI, stack protection, executable
PIE/hardening and compressed-DWARF link policy. Its one actual program object is
a direct link input; no artificial archive changes extraction. Original
explicit debug directories, owners, modes and package tags are installed.
Runtime C, Make recipes and SDK/toolchain bytes are unchanged by this batch.

`packages/bzip2` composes the three original component manifests once for both
the installation archive and package layout. Original component installs repeat
three identical directory records per architecture. The existing
`bsd_install_manifest` gains default-off `merge_identical_directories`: an
explicit composition may coalesce a directory only when the complete record
matches, including flags and tags. Default duplicates, differing directory
metadata and repeated regular payloads remain errors. Payload collisions are
never waived. Six pre-existing library/program component archives are
whole-byte identical to the prior accepted component captures.

The selected original Make profiles enable debug files and disable split man
packages. Actual package Make queries select exactly `bzip2`, `bzip2-dbg`,
`bzip2-dev` and `bzip2-lib`; the maintained source marks LIB32 unsupported in
these selections. The existing original UCL generator, package templates,
layout, native pkg/tar tools and epoch-zero creation policy remain in use.
ABIs are derived from actual target ELFs. The package test covers this selected
four-package profile; split-man and other option matrices are separate gates.

## Independent original and actual action evidence

All paths below are under `/usr/obj/usr/src`:

- Fresh recovery originals: `bazel-bzip2recover-original-references-r1-20261103`.
- Original library/program references: `bazel-bzip2-original-references-r2-20261103`
  for amd64 and `r3` for the refreshed cross header floors.
- Final normal profiles and immutable captures:
  `bazel-bzip2-family-{amd64,aarch64,riscv64}-native-qualification-r2-20261103`.
- Actual compiler outputs, `.d` files and expanded link parameters:
  matching `bazel-bzip2-family-ARCH-action-collection-RUN-20261103` directories.
  The successful native compiler/link witnesses are from r1; cross witnesses
  are r2. Native r1 itself remains rejected because one analysis fixture used a
  private dependency. The fixture now uses its own source file; no visibility
  was broadened. Accepted final native output digests match the earlier actual
  witnesses. The fully drained official compact converter binds that rejected
  log separately, without inventing a successful receipt or fresh executions.
- Independent original `packages/bzip2` `stagepackages` recipes:
  `bazel-bzip2-family-make-package-references-r2-20261103`. These use the original
  component stages, original METALOG-to-plist script with complete directory
  ownership and original UCL generator. Outputs are private qualification
  packages, never a published repository. The earlier observer initialization
  rejection is retained in r1.
- Final hash-bound summary and engineering observers:
  `bazel-bzip2-family-package-review-r2-20261103/qualification-summary.json`.

All 48 production compiler contexts pass exact original warning, define,
language, ordered PIC/ISA and debug/code-generation policy checks. All 1,040
original/native consumed occurrences match actual action-input digests: 380
amd64, 330 ARM64 and 330 RISC-V. Each object's allocated sections and runtime
relocations match. Nine complete linked DSO/program/recovery images match all
original allocated sections and loader/import/export/hardening contracts.
Twelve actual link sequences are retained; 42 regular/PIC archive members are
bound to actual compiler-output bytes in original order. Default CcInfo static
extraction remains separately checked without whole-archive or section GC.

All 66 original component installation records match destination, ownership,
mode, flags, tags and type policy. The explicit composition has 57 unique
records. Nine installed native/original debuglink pairs pass maintained ELF,
DWARF-presence and actual CRC checks. Separate DWARF bytes and source lookup
remain open, as in the component qualification.

All twelve native packages are compared with twelve independent Make packages.
Package partition, names, version, ABI, annotations, dependencies, directory
ownership and file owner/group/mode match. Headers, pkg-config and manual data
match whole bytes; installed executable/DSO differences are restricted to their
independently verified debuglink CRCs, with exact allocated payloads. Regular
archive member allocated payloads match. Raw debug/archive member digests and
manifest differences are retained rather than normalized.

Ordinary Make pkg creation retains actual stage mtimes; native creation uses
its existing explicit epoch zero. Both timestamp policies are verified, and
raw manifest times are retained. Package archive byte equality is not claimed.
Separate debug payload/path differences and payload-derived checksums/flat
sizes are explicit; independent debugger semantic/source lookup parity is not
inferred from valid debuglinks or equal allocated payloads.

## Declared tests and bounded native runtime

All sixteen declared invocations pass: twelve native, two ARM64 and two RISC-V.
Nine analysis cases check inherited/direct identical-directory composition and
rejection of default duplicates, changed mode/owner/group/tags/flags and a
repeated regular payload. Host artifact tests inspect actual ELF/archive
contracts and all four package inventories, metadata, dependencies, exact
native-installation bytes, symlinks and hardlink identity using declared tools.
They do not execute foreign programs.

The native recovery test creates deterministic multiblock input, verifies
compression/decompression, recovers every healthy block exactly, corrupts the
first block CRC, rejects the damaged whole stream and damaged first block,
recovers intact later blocks exactly, and rejects a missing input. Its loader
trace proves use of the selected libbz2. Input executable/library hashes remain
unchanged. The same maintained test logic also passes against independent
original native Make artifacts. No environment filtering, installed-path
substitution, output rewriting or package-manager installation is involved.

Frontend/backend review: existing format-5 target/test selection, execution SDK
rules, test inventory validation and artifact capture support these source-owned
producers and tests. No new frontend switch or replacement workflow is needed.
The manual documents the composition contract and remaining gates. Full selected
world/rescue/pkgbase closure, dependency solving, installed-system behavior,
foreign runtime, bootstrap and publication remain incomplete.
