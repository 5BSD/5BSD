# AMD64 EFI loader entry objects (2026-11-04)

`//stand/efi/loader:entry_objects` compiles all 58 entry sources from the selected
AMD64 Lua/EFI secureboot Make profile using native rules_cc actions. This includes
startup/trampoline/exception assembly, both ELF widths, the original verity
interfaces, consoles, graphics, disk/network and Lua command integration. Font
and version C sources come from the maintained native generators. No object is
copied from the Make build, extracted from an SDK archive or manufactured.

The selected profile requires GELI, disk, network, memory-disk and ZFS support,
EFI secureboot, and disabled VECTX/pass-manifest options. Other exposed settings
are rejected as incompatible instead of compiling a mismatched inventory.
These restrictions match the existing private-library qualification; alternate
inventories/interpreters and ARM64/RISC-V entry construction remain open.
Lua paths use the existing typed source setting. The current common Lua-path
provider also supplies its existing unused LUA_PATH_DEFAULT definition.
Filesystem/compression, staging-size and other loader options still need full
source-owned configuration coverage before this becomes a system backend.

Source/header ownership is explicit, including textual C includes and machine/x86
header views. The existing standalone header generator/view supplies exactly the
restricted header namespace used by Make. Compiler options are maintained in
entry.bzl; no Makefile or dependency-file reader runs in a Bazel build action.
Per-source options and existing warning policy are retained. The help filename
operand is quoted for Bazel copts tokenization so the compiler receives the
actual C string literal. Assertions remain enabled and unmodified.

## Evidence

Retained paths below are under /usr/obj/usr/src:

- bazel-efi-loader-amd64-make-r1-20261104: existing Make entry reference with
  all 58 actual object recipes and dependency records.
- bazel-loader-entry-amd64-r3-20261104: successful maintained build-bsd format-5
  run, all 16 logical CPUs, captured 58 native compiler products.
- bazel-loader-entry-amd64-review-r1-20261104/review.json: all object ELF
  identities agree; 56 raw allocated-section and symbolic-relocation sets agree.
  disk.o and gfx_fb.o differ in assertion filename strings and relocations.
- bazel-loader-entry-amd64-controls-r1-20261104: two original compiler controls
  with only the source filename prefix mapped reproduce both differing objects'
  allocated sections and symbolic relocations. symbols.json in the raw review
  also confirms all 58 external defined/undefined symbol tables match Make.
  Native/original outputs are not
  rewritten, and production flags contain no such mapping or assertion removal.
- bazel-loader-entry-amd64-action-review-r1-20261104: all 58 actual successful
  compiler outputs bind to captured hashes; all 3,137 original consumed source,
  generated C and header input pairs match declared native action input digests.
  The check explicitly inspects freestanding ABI/verification/help operands,
  Bazel-owned dependency files, and absence of new assertion suppressions.

The r1 attempt failed on an invalid root-package label; r2 caught the help macro
quotation error. Both attempts are preserved. Neither failure was suppressed.
The symbol diagnostic originally globbed hidden .depend.*.o files; its corrected
selection uses the 58 actual object metadata records. These are diagnostic and
integration fixes, not changes to the original loader algorithms.

## Scope and next work

These are 58 entry object products for one selected profile, not 58 programs or
a complete loader. Full object/debug byte parity and source lookup remain open.
The Make reference's final link consumes existing world SDK archives; close that
reference and use the native private archives before claiming final loader
parity. Final linking must retain the real Make object/archive order, linker
script, entry/relocation rules, PE section policy and explicitly selected epoch.
Firmware execution, installation/debug metadata and boot remain separate gates.

The maintained build-bsd frontend already accepts this public target and the
existing format-5 settings; no one-off frontend, new C switch or default backend
was introduced. Full world/kernel/module, bootstrap/sandbox/cache, pkgbase,
hardware/combined publication and CPU/memory/disk I/O/storage qualification remain
required. Make stays production/default; BIP is excluded. No host installation,
upgrade, reboot or VM occurred in this qualification.
