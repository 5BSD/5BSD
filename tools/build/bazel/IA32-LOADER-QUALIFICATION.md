# Complete IA32 EFI Lua loader construction (2026-11-04)

## Source-owned graph

The loader_ia32 BUILD contribution crosses an explicit i386 standalone artifact
boundary into the shared EFI loader graph. AMD64 and IA32 have explicit startup
source inventories and share MI rows and common compiler policy. IA32 is not
created by filtering an AMD64-only source inventory. Its four startup sources
are amd64_tramp.S, start.S, setup.c and elf64_freebsd.c under arch/i386. The
complete order is 56 objects followed by the qualified private Lua, EFI and
standalone archives and the original i386 linker script. Native build actions
never invoke Make or import original Make objects.

The declared machine/x86 views come from the original consumed dependencies.
IA32 preserves -m32/-march=i386, no PIC, no SIMD, soft float, short wchar and
double alignment. Version generation identifies EFI loader amd64-ia32 using the
same typed reproducibility input. The installation contribution is only
/boot/loader_ia32.efi, root:wheel 0555 in bootloader. It creates neither the
native-width /boot/loader.efi link nor another shared loader help file.

## Producer defect found by the real image test

The original elfcopy unconditionally chose PE32+ for every EFI output format.
Consequently both original Make and the first native IA32 images had machine
I386 (0x14c) but optional-header magic PE32+ (0x20b). Matching Make alone would
have retained the defect. The actual image test required PE32 (0x10b), failed,
and remains unchanged in that assertion. The converter now treats IA32 EFI as
PE32 while preserving the existing other-format selection. This also produces
the PE32 header size and IMAGE_FILE_32BIT_MACHINE characteristics through libpe.
No post-conversion byte patch or architecture-specific test relaxation is used.

The analysis failure in r2 was separate: the installation target deliberately
returns both manifest and payload in DefaultInfo. The test now uses the existing
manifest output group through a filegroup, retaining the payload dependency.
No installation-provider contract was weakened. Failed receipts and reports
remain under their original output roots.

## Independent evidence

Evidence paths are under /usr/obj/usr/src.

- bazel-loader-ia32-make-r1-20261104 is an independent original Make build using
  sixteen jobs, reproducible versions, metadata and explicitly hash-bound original
  LIBLUA32/LIBEFI32/LIBSA32 reference artifacts. Its original image retains the
  converter defect and original diagnostic filenames; it is not rewritten.
- bazel-loader-ia32-r5-20261104 passes nineteen frontend tests, including the
  actual image's PE32 machine/magic/subsystem/entry/timestamp/import checks,
  ELF32 final-link symbols and exact installation contribution. The test reads
  the existing typed timestamp setting; it has no independent timestamp default.
- bazel-loader-ia32-object-review-r2-20261104 compares all 56 final captured
  objects with original Make. Fifty-four match all allocated-byte, symbolic
  relocation, external symbol and identity contracts directly. disk.o and
  gfx_fb.o differ only in allocated assertion filename data; their raw symbolic
  and external contracts match.
- bazel-loader-ia32-filename-controls-r1-20261104 contains two matching isolated
  original compiler filename controls. It also retains an intermediate image
  difference caused by the as-yet-uncontrolled original Teken assertion filename.
- bazel-loader-ia32-filename-controls-r2-20261104 adds the previously qualified
  single Teken filename control to the three previously qualified libsa controls.
  It reruns the original compiler/link/split/conversion sequence on private
  outputs using a separately Make-built corrected elfcopy. The complete resulting
  PE32 image equals native Bazel bytes. Raw original artifacts remain unchanged.
- bazel-elfcopy-ia32-make-r1-20261104 is that independent corrected converter
  build. The existing host converter is neither replaced nor claimed corrected.
- bazel-loader-ia32-action-review-r1-20261104 binds the actual final compiler
  dependency/output chains, complete object and library order, original script
  and corrected image producer across the recorded compact logs.
- bazel-loader-ia32-final-review-r1-20261104 binds final sources and evidence,
  checks all fifteen prior AMD64/ARM64/RISC-V EFI image bytes are unchanged and
  confirms the final IA32 image still equals the independent complete control.

Original versus native full ELF/debug bytes are different and remain unqualified.
The independent controlled image equality explains the selected executable
image, not full debug metadata or a complete hermetic Make tool/input closure.
The actual Make reference and controlled conversion use external SDK/host tools,
whose recorded hashes delimit these comparisons.

## Frontend and remaining gates

The maintained build-bsd format-5 target/test interface selects the new public
aliases without a special C command. Its manual and observability ledger are
updated with this change. No signing, staging, publication or host activation
policy changes. The normal build default remains Make.

Alternate IA32 interpreter consumers, remaining BIOS producers, full debug
parity, full world/kernel/pkgbase, bootstrap, firmware/VM/runtime execution,
secure boot qualification and broad CPU/memory/disk measurements remain open.
This is a constructed EFI application, not proof of a bootable complete system
or verified boot. No running-system installation or reboot occurred.
