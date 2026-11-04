# Native BTX startup construction (2026-11-04)

## Architecture

The BTX startup declaration previously compiled with the hosted AMD64 platform
and manual -m32 flags, then used cc_binary with -r to obtain a relocatable object.
It now compiles the three actual assembler sources in the verified SDK's i386
standalone configuration. The existing relocatable-link rule runs the explicitly
declared SDK linker in elf_i386_fbsd mode with original effective link flags and
exact btxcsu/btxsys/btxv86 order. No startup files, hosted libraries, runtime Make
query, imported Make objects or target execution enter this native graph.

The public component object and crt0 aliases cross an explicit freestanding ABI
boundary. The internal split produces crt0.o and crt0.o.debug. A public filegroup
selects the debug output group after that boundary; this retains the boundary's
executable/tool rejection. The first attempt selected a one-file filegroup before
the boundary, which Bazel advertises as executable, and was correctly rejected.
That failed attempt remains recorded. The general boundary rule is unchanged.

The existing boot2_headers and bios_libi386_headers source-only interfaces remain.
The startup component is internal and contributes no installed program or object.
The frontend's existing format-5 target/test selection supports these public
aliases without a new C action, stage override or publication path.

## Evidence

All paths below are under /usr/obj/usr/src.

- bazel-btxcrt-make-r1-20261104: independent original Make startup build and
  debug split, through the maintained helper with sixteen jobs and metadata.
- bazel-btxcrt-r1-20261104: retained rejected pre-boundary debug filegroup.
- bazel-btxcrt-r2-20261104: first successful standalone startup construction and
  twenty-one passing frontend artifact/regression tests.
- bazel-btxcrt-r3-20261104: adds the existing boot2 consumer and legacy BIOS
  format tests. All twenty-three tests pass, including the unchanged boot2 size
  and padding rejection checks. No target firmware executes.
- bazel-btxcrt-object-review-r1-20261104: all three assembler objects, the combined
  relocatable object, stripped startup object and debug artifact match original
  Make allocated/identity/external/symbolic relocation contracts. All six raw
  file byte comparisons differ; full DWARF/source mapping parity is not claimed.
- bazel-btxcrt-action-review-r1-20261104: actual three compiler producer records,
  exact source/header hashes and 32-bit flags, selected linker binary and input
  order, and both debug transformation digests bound across compact logs.
- bazel-btxcrt-final-review-r1-20261104: final source/evidence bindings, internal
  object metadata and sixteen unchanged prior EFI images. It confirms that the
  final captured startup objects retain the compared contracts.

The new host test inspects the real artifacts: every input/output is ELF32
ET_REL; _start begins .text at offset zero and precedes system-call startup;
expected symbols and unresolved client references remain; stripping preserves
allocated/symbolic contracts and the debug-link filename/CRC matches the separate
file. These are construction and debug-split integrity checks, not a claim of
complete debugger/source mapping equivalence.

## Complete BIOS Lua reference prepared

bazel-bios-loader-lua-make-r1-20261104 is a separate passed Make construction of
the complete BIOS Lua loader using explicit original Lua/libi386/libsa archive
bindings and reproducible version generation. Its original loader.bin size check
reports 16,600 bytes remaining under the existing 505,000-byte limit. The limit
was not changed. This reference uses the prepared SDK BTX prerequisites and host
BTX packaging tool. It establishes an original comparison input; it is not yet a
complete native Bazel BIOS Lua construction or firmware qualification.

Next compose the complete BIOS loader's entry/link/strip/BTX pipeline, preserving
its real size bound and default-loader installation policy. GPT/ZFS/ISO/PXE
consumers, alternate IA32 selection, full debug parity, world/kernel/pkgbase,
bootstrap, runtime/VM and broad CPU/memory/disk performance gates remain open.
Make remains production/default; no host installation or reboot occurred.
