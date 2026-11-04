# BIOS platform-support library (2026-11-04)

## Source ownership and native construction

The new stand/i386/libi386 package declares all thirty original BIOS platform
sources and the original archive member order. It builds through normal rules_cc
compilation and the owned-object archive rule, with a public static_archive
boundary selecting the verified SDK's i386 standalone ABI. The native graph never
invokes Make or imports Make object files or migration metadata.

The declared dependencies include physical source headers in their owning
packages, the actual sixteen root i386 headers, a separate machine/pc view for
bios.h and nine x86 sibling headers. The first native attempt exposed the nested
header-view requirement. The existing architecture-view API supplies the right
directory explicitly; neither compiler include fallback nor the general header
rule is changed. The failure receipt/log remains available.

Teken uses the existing source-owned AWK state-header generator and declared
header provider. The BIOS text console retains its per-source TERM_EMU flag;
PNG/Teken include options remain local to the original selected compilers. No
assertion or stack policy is changed to make the comparison pass.

Creating the new Bazel package also moves ownership of libi386.h and the three
console sources used by EFI. Existing parent header-provider interfaces now name
that source owner, and the common EFI entry inventory uses its source labels.
These are Bazel label changes; physical source paths and source bytes are intact.
The final regression comparison checks all sixteen previously qualified EFI
images, including the IA32 loader, remain byte-for-byte unchanged.

## Configurable policy

Four maintained settings mirror the original Make controls:

| Bazel setting under //tools/build/bazel/config | Original Make input | Default |
| --- | --- | --- |
| loader_comconsole_port | BOOT_COMCONSOLE_PORT | 1016 (0x3f8) |
| loader_comconsole_speed | BOOT_COMCONSOLE_SPEED | 115200 |
| loader_biosdisk_debug | BOOT_BIOSDISK_DEBUG presence | false |
| loader_bios_framebuffer | BOOT_FRAMEBUFFER_MODE=yes | false |

Port and speed are typed integers exposed as compiler definitions through CcInfo.
The provider checks the x86 I/O address range and a positive signed speed. Debug
and framebuffer flags affect only biosdisk.c and vidconsole.c respectively.
These are explicit frontend build-settings, with source-maintained defaults;
there are no developer-machine or host-clock inputs. Existing global loader
GELI, disk and verifier settings keep their separate typed selections.

The selected nondefault qualification uses COM2 port 760 (0x2f8), 57600 baud,
disk diagnostics and framebuffer default enabled. Exactly the intended three
member contracts change. Independent original compiler recipes, with only the
corresponding serial definitions or documented per-source Make option changed,
match those three native objects. This does not claim a separately reconfigured
full alternate Make traversal or an operational serial/framebuffer BIOS test.

## Evidence

All evidence below is under /usr/obj/usr/src.

- bazel-libi386-make-r1-20261104: independent original thirty-member Make build
  and installation reference, using the maintained helper and sixteen jobs.
  Its component METALOG is empty; the archive is internal.
- bazel-libi386-r1-20261104: retained failed nested-header attempt.
- bazel-libi386-r2-20261104: default source build and twenty passing frontend
  artifact/regression tests. The BIOS test checks exact member order, ELF32 ABI,
  BIOS/PXE/terminal APIs and absence of hosted stack-protector imports.
- bazel-libi386-object-review-r1-20261104: all thirty original archive members
  versus immutable native capture. Twenty-nine match allocated data, symbolic
  relocations, external symbols and identity directly. Teken's allocated
  assertion filename differs; its other raw contracts match directly.
- bazel-libi386-options-r1-20261104: nondefault typed-input build and actual
  passing BIOS artifact test.
- bazel-libi386-compiler-controls-r1-20261104: one isolated original Teken
  filename control and three original compiler option controls. All match;
  the other twenty-seven default/nondefault member contracts are unchanged.
  Original Make files and outputs are hashed before and after controls.
- bazel-libi386-action-review-r1-20261104: actual sixty compiler dependency and
  output chains, default/nondefault flags, generated header consumption and
  both native archive producers, bound across compact execution logs.
- bazel-libi386-final-review-r1-20261104: source/evidence bindings, unchanged
  sixteen EFI images and internal-archive metadata check.

Full object and DWARF/source mapping parity is unqualified. ELF32 artifact checks
and independent compiler comparisons do not execute BIOS or demonstrate complete
loader boot, PXE operation, disk I/O behavior or hardware console operation.

## Frontend and next work

The existing format-5 build-settings and target/test dispatch handle the public
archive/test labels. build-bsd.c needs no new action or scalar option parser;
its manual is updated in this change. No signing, stage, publication or activation
contract changes. Make remains the production default.

Complete BIOS loader, GPT/ZFS boot, ISO/PXE producer composition and runtime
qualification remain, along with alternate IA32 interpreters, full debug/system/
world/kernel/pkgbase, bootstrap, caching/sandbox acceptance and broad performance
gates. No running-system installation or reboot occurred.
