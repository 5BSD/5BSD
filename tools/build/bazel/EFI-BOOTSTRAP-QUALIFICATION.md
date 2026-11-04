# Native AMD64 boot1 and gptboot EFI programs (2026-11-04)

## Source-owned candidates

//stand/efi/boot1 and //stand/efi/gptboot each expose entry_objects, full, symbols,
debug, image and install_manifest targets. Each program compiles six actual
entry sources with rules_cc and uses the shared native firmware linker, debug
splitter and PE converter. The link selects the native private EFI and standalone
archives in Make order. The existing configured PE timestamp remains an input.
Neither program depends on a copied Make object, prebuilt SDK firmware image or
build-time Makefile/dependency-file parser.

boot1 retains UFS/ZFS selection and the existing verifier interfaces. gptboot
retains its own proto.c and drv.h context, GPT implementation, explicit EFI_DEBUG,
local ZFS exclusion and quoted BOOTPROG string. Its shared archives retain their
separately selected global context, matching Make. All original warning options
and freestanding ABI choices are preserved. Existing exposed GELI/disk/ZFS/EFI
secureboot and disabled VECTX/pass-manifest constraints bound this selected
profile. Other target architectures and optional profiles require qualification.

The source/header closure is explicit in owning packages. Architecture aliases
and the existing restricted standalone include view provide generated headers.
Shared file exports retain all previous/new consumers' visibility. An offline
migration helper initially failed on an unrelated computed export list after
processing some literal declarations; the resulting declarations and final build
are reviewed, and the corrected helper preserves computed declarations. Such a
helper is not part of any Bazel build action. Export cleanup also retains the
existing Lua loader, whose PE hash is unchanged.

The image records preserve 0555 root/wheel bootloader entries. gptboot also
produces its actual gzip manual and original default manual metadata, with the
existing typed manual split selection available. The symbol/debug artifacts
remain build-only under Make's INTERNALPROG convention. Complete bootloader
package/directory aggregation still needs the remaining programs/profiles.

## Evidence

Retained paths below are under /usr/obj/usr/src:

- bazel-efi-{boot1,gptboot}-amd64-make-r1-20261104: separate completed maintained
  Make references, six real object recipes per program, dependency files, full/
  debug/symbol/PE outputs and actual installation metadata.
- bazel-efi-bootstrap-amd64-r1-20261104: maintained frontend format-5 build with
  all 16 logical CPUs, native object/archive/link/debug/PE/manual producers.
- bazel-efi-bootstrap-amd64-review-r1-20261104/object-review.json: every one of
  the twelve entry object allocated sections and symbolic relocation sets agrees
  directly with the unmodified Make product. No entry filename control is needed.
- bazel-efi-bootstrap-amd64-closed-reference-r1-20261104: original link recipes
  rerun with all six original entries and explicit original private archives.
  Both raw and previously established archive filename-control variants are
  retained. The original debug and PE recipes run with original SDK tools.
  All original object/archive/script inputs remain unchanged across the controls.
- payload-review.json in the raw review: both native runtime ELF payloads match
  the controlled originals, including identity, entry, program headers, allocated
  section bytes/addresses/metadata and dynamic tables without DT_NEEDED. The
  debug split preserves runtime contents and validates separate data/debuglink
  names/CRCs. gptboot's PE is byte-identical to the raw closed Make PE; boot1's
  PE is byte-identical to the archive filename-controlled original. Raw original
  differences remain recorded. All default file/manual metadata agrees, and
  the compressed manual matches the original bytes.
- bazel-efi-bootstrap-amd64-action-review-r1-20261104: twelve actual compiler
  outputs, 784 exact original-consumed source/header digest pairs, two actual
  final links with complete six-object and two-archive order, script/input/output
  bindings, and both native PE producer digests. EFI_BOOT1, local ZFS/debug,
  BOOTPROG and verifier operands are inspected. No new assertion suppression or
  production macro filename mapping is added.

The qualification explicitly supplies the existing development verifier header
policy. Compilation and PE equality do not qualify production trust roots,
signatures, key rotation or firmware policy enforcement. Full object/DWARF
bytes, source lookup and debugger behavior are still open.

## Remaining work

bazel-efi-bootstrap-amd64-final-r1-20261104 passes on final source. The raw
review's final-repeat-review.json binds unchanged full/debug/symbol/PE/install
artifact hashes for both programs. The final execution log has no fresh spawn
actions; this is retained component-local reuse, not a full-system cache or
performance qualification.
ARM64/RISC-V and remaining EFI interpreters/IA32 variants, full bootloader package
aggregation (including shared directory package assignments), firmware execution
and actual filesystem/device/error behavior remain gates. Complete world/kernel/
module, reproducible bootstrap/output-query/sandbox/cache, separate hardware and
verified combined publication and comparative CPU/memory/disk I/O/storage gates
are still required. Make stays production/default. BIP remains excluded. No host
install, upgrade, reboot or VM was performed here.
