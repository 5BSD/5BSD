# Native ARM64 and RISC-V Lua EFI loaders (2026-11-04)

## Source-owned construction

The stable //stand/efi/loader targets now select complete 48-entry Lua/FDT
profiles for ARM64 and RISC-V alongside the existing 58-entry AMD64 profile.
Architecture-specific declarations retain source selection, assembly entry,
freestanding CPU ABI, machine headers, linker script, object order and five
ordered native archive dependencies: EFI Lua, EFI support, common FDT, EFI FDT
and EFI standalone support. No action reads Makefiles or substitutes SDK loader
objects, archives or images. Unsupported option profiles remain incompatible.

ARM64 preserves general-register-only code and reserved x18. RISC-V preserves
rv64imac/lp64 soft-float, medium code model and disabled relaxation. The existing
native debug/image/stage rules are reused. AMD64 uses the PE writer; ARM64 and
RISC-V copy the source startup assembly's embedded PE header through binary
conversion, matching Make. Their inspected PE timestamps are zero; the AMD64
SOURCE_DATE_EPOCH timestamp claim does not apply to these embedded headers.
Root-component help selects the FDT/common merge; source mtree/accounts supply
directory policy and numeric IDs. This remains a component contribution to
bootloader, with complete package publication refused.

## Cross-build failure and DTrace correction

The first ARM64 run, bazel-cross-efi-lua-aarch64-r1-20261104, failed in a
source-built host libarchive DTrace action: the explicit SDK path selected the
ARM64 drti.o while the host objects were AMD64. The failed log is retained.
Disabling probes or substituting an untraced library would conceal the error.

bsd_dtrace_runtime resolves the consumer's C/C++ toolchain and requires exactly
one declared sysroot/usr/lib/dtrace/drti.o. It exposes that existing artifact,
without copying it or choosing by host filesystem inspection. The runtime
follows the consumer configuration, so cfg=exec libraries receive the native
execution SDK and cross consumers receive their target SDK. All thirteen
source-owned DTrace provider declarations use this selection. The tools invoked
by DTrace remain execution dependencies; drti remains consumer link data.
The subsequent ARM64 and RISC-V builds pass with probes enabled.

## Independent references and retained differences

All evidence paths below are under /usr/obj/usr/src. Each architecture uses
bazel-efi-loader-<arch>-make-root-r4-20261104, a maintained Make reference for
the actual root loader component with explicit original library bindings.
Earlier private loader_lua references correctly suppress help installation;
they cannot establish the root component's help contribution. Initial review
helper assumptions about that ownership and hidden .depend.*.o files were
corrected; no installed output or source inventory was removed to pass a check.

- bazel-cross-efi-lua-aarch64-r2-20261104 and
  bazel-cross-efi-lua-riscv64-r1-20261104: completed native frontend builds,
  captured artifacts and execution logs, using all sixteen logical CPUs.
- bazel-cross-efi-lua-aarch64-object-review-r2-20261104 and the corresponding
  riscv64-object-review-r1 report: 46/48 entry objects per architecture match
  raw original allocated sections and symbolic relocations. Both retain disk.o
  and gfx_fb.o assertion filename differences. Target machine and ELF flags agree.
- <arch>-payload-review reports retain the raw final ELF/PE/debug differences;
  FDT help agrees exactly. No raw full-object/DWARF equality is claimed.
- <arch>-controls-r1 reports rerun the two original entry compiler recipes with
  isolated filename controls, retain all five original archives, and construct
  isolated original EFI/libsa archives using the already qualified original
  Teken and three standalone-library filename controls. No native object is
  supplied as an original reference input. Original link/debug/PE recipes run
  with recorded compiler and input digests, leaving raw originals unchanged.
- aarch64-final-review-r1 and riscv64-final-review-r2 reports establish final
  loadable ELF payload and PE byte equality to those independent controls,
  debug split/debuglink integrity, matching FDT help, source installation records,
  and the five-member archive's actual extraction, hardlink, modes and contents.

RISC-V's initial strict final comparison is retained as failed. All allocated
sections and runtime tables agree, but PT_RISCV_ATTRIBUTES points at a different
file offset because full debug layout differs. The subsequent review retains
both complete program headers and verifies each points to its actual non-loadable
.riscv.attributes section, with identical complete bytes and all other header
fields equal. The same check covers full-to-stripped output. This is a recorded
file-layout difference, not full ELF/debug byte equality or debugger qualification.

The component /boot directory's extra utilities package tag and the source mtree's
bootloader tag still need complete package aggregation. Help shared with other
interpreters needs idempotent identical contribution handling at that boundary.

## Remaining gates

Final-link-r1 builds on both architectures retain all 56 captured entry/link,
archive and generator outputs byte-for-byte from the qualified full image chains;
final-source-review-r1 reports bind that equality and the selected target drti.o
ELF machine (ARM64 183, RISC-V 243). This bounds the final repeat to changed
entry/link inputs; it does not claim another complete stage or firmware run.
The AMD64 regression-review-r1 report verifies all 225 captured prior outputs
remain byte-for-byte unchanged, including Lua/Forth/simple and boot1/gptboot.

The aarch64-input-review-r2 and riscv64-input-review-r1 reports verify all 48
actual final compiler producers per architecture and respectively 2,451/2,468
original-consumed source/header digest pairs. These final-link profiles contain
no host libarchive DTrace producer; those reports do not claim to audit one.
The initial broad ARM64 diagnostic was explicitly cancelled and recorded in
input-review-r1/SUPERSEDED.json after identifying its mutable execution-workspace
runtime lookup. The final audit uses immutable captures and receipt-bound SDK
paths. No native build was cancelled or restarted for an observation timeout.

The riscv64-unsupported-r1 run explicitly requests loader_disk=false and fails
analysis because entry_objects is incompatible. The retained failure does not
silently skip the target or substitute the default inventory.

These candidates do not qualify firmware execution, all options/interpreters/IA32, complete bootloader
packages, full world/kernel/modules, reproducible bootstrap/output query,
sandbox/cache guarantees, publication or comparative CPU/memory/disk I/O/storage.
The broad SDK dependency closure and verification/materialization costs remain
performance work; logical bytes hashed are not physical disk I/O measurements.

The maintained build-bsd format-5 input file already supplies architecture,
configuration, SDKs, target labels, execution logs and jobs. No new C frontend
switch is necessary. Make stays production/default. BIP remains out of scope.
No host installation, upgrade, reboot or firmware VM occurred in this work.
