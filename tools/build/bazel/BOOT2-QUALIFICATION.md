# Native boot2 producer and installation qualification

## Production graph

This cohort adds the selected amd64 world's real boot, boot1 and boot2 products,
not a boot fixture. Source-owned declarations compile seven i386 objects, link
the internal BTX startup object in original btxcsu/btxsys/btxv86 order, preserve
its original debug split, and link the boot1 and boot2 ELF intermediates with the
selected SDK linker and original linker script. The boot2 link consumes crt0,
boot2, sio and compiler-rt ashldi3 in that exact order. No implicit runtime or
host 32-bit library is substituted.

Declared nm output feeds the original XREADORG AWK computation with its explicit
ORG1/REL1 values. Declared objcopy actions produce flat images. The existing
source-built btxld utility runs in the execution configuration with declared
BTX kernel, zero loader and client inputs. Its original entry/page arguments
remain intact. Explicit byte operations produce the original 512-byte zero
loader, reject an image larger than 7,680 bytes, pad to exactly that size and
concatenate boot1 followed by boot2. There is no Make invocation or source-tree
inventory discovery during the native build.

The consumed libsa beforedepend header links are reproduced as declared aliases
to their actual include/sys owners; no Make-generated header is copied into the
native graph. Consumed physical system/UFS/BSM headers and the i386/x86 architecture
view have narrow owners. Textually included ufsread.c and compiler-rt private
headers are explicit inputs rather than extra link objects. Source, assembly and
original Make files are unchanged.

## Original and actual-action proof

Three fresh maintained original references build btxld, internal BTX crt0 and
boot2 sequentially at 16 jobs under the object-root disk guard. Nine original
dependency-only compiler controls retain complete consumed inputs while checking
that every original object hash remains unchanged. All 702 original stand/tool
source bindings are retained and rechecked.

The seven boot/CRT compiler policy vectors match their actual original recipes,
including debug flags, optimization positions, 32-bit calling convention and
instruction policy, UFS/serial values, warnings and compiler-rt exceptions.
Explicit source, generated-header and architecture/standalone include namespace
relocations preserve all 94 original consumed source/header occurrences. Every
actual native dependency appears with the same digest in the corresponding
action's declared inputs. All seven objects' allocated sections and nondebug
relocations match independently built originals. Separate object DWARF equality
is not claimed.

The existing btxld declaration initially omitted original common/warning/PIC
policy. That first build's byte-equal images remain evidence, not an accepted
tool-policy closure. The corrected existing target uses ordinary source-owned
object compilation and direct program objects, preserving its public program,
installation and archive labels. Four actual compiler contexts cover its two
sources in target and execution configurations: complete original ordered policy,
216 consumed occurrences and all allocated payloads match. Execution's earlier
-g0 is overridden by the explicit original -g; its normal execution-tool debug
strip remains explicit. The normal linked utility matches all original allocated
payloads and maintained PIE/interpreter, ordered NEEDED, imports/exports and
hardening checks. Three separate DWARF sections differ; source lookup and debugger
semantic equality remain open.

Five actual ordered link vectors cover CRT, boot1/boot2 and both tool
configurations. Compiler and linker bytes, script and full own-object input
identities are bound. Seven complete generated outputs match original bytes:
boot (8,192), boot1 (512), boot2 (7,680), unpadded BTX composition (7,536), client
image (5,344), zero loader (512), and XREADORG header (23). The BTX kernel input
matches the previously qualified immutable image and the original staged image.

The corrected execution-tool bytes equal its earlier stripped executable bytes.
The BTX producer therefore legitimately reuses its prior successful action; its
actual tool input digest equals the fresh corrected source link output digest.
Cached compiler/producer outputs are rebound to actual prior witnesses and
accepted current captures, not described as fresh execution. Official compact
conversion is fully drained with all 189 converter bindings verified before and
after. Rejected policy and installation comparisons remain retained.

## Installation and tests

The component installs three bootloader files and preserves the original explicit
/boot directory record, root:wheel 0755 with package=utilities, separately from
the files' package=bootloader tags. The directory tag is the current maintained
bsd.files.mk/bsd.dirs.mk result; this cohort does not silently replace it with
mtree's bootloader tag. A first-class bsd_install_directory entry uses the existing
BsdInstallFileInfo/manifest/archive protocol, so its metadata survives composition.
The internal startup object remains uninstalled.

The combined staging archive retains the existing btxld utility and manual/debug
installation contract: nine exact original records, six files and three explicit
directories. Four file payloads match whole bytes (three boot files and compressed
manual). The installed utility differs only in its debug-link CRC; its separate
debug file differs in .debug_info/.debug_line/.debug_str. Both original/native
pairs pass direct maintained debug-link/CRC validation. The internal ET_REL CRT
also passes its split-debug format/CRC checks. These are debug integrity checks,
not separate DWARF equality. The previous legacy boot archive remains unchanged
under the added directory entry primitive.

One maintained host artifact test passes six methods against actual declared
outputs: BIOS signature and final concatenation order, exact padding/zero-loader
and BTX metadata, symbol-derived XREADORG, internal ELF32/i386 ABI, exact size
boundary/overflow rejection and invalid byte-operation rejection. No boot image
is executed. The first profile executes these methods; later profiles reuse
unchanged declared test inputs and retain their passing report. A bounded scan of ten physical compiled/textually included sources
finds zero recognized call-shaped SDT/DTrace/CTR/audit sites; this is not a full
instrumentation or live-event claim.

## Frontend and remaining gates

Existing normal format-5 build-bsd targets, test inventory and installation
archive APIs carry this graph. The manual records the new primitive and targets;
no C frontend, backend CLI, SDK/bootstrap or signing policy is changed. Existing
manual diagnostics remain baseline warnings, not a lint-clean claim.

Make remains the production/default world builder. Other boot configuration
values, architectures, BIOS/EFI/ZFS loaders, libsa/libi386 and full stand/world/
rescue/package aggregation remain open. External SDK/host bootstrap dependencies
remain explicit. Byte equality does not prove bootability, hardware behavior,
performance, UEFI or bundle signing, verified boot or protection from compromised
root. No host installation, disk/partition write, boot, upgrade, package creation
or publication occurred.

## Retained evidence

All roots are under /usr/obj/usr/src/:

- bazel-boot2-make-references-r1-20261103: three maintained Make receipts, actual
  recipes, private stages, objects/images and 702 original source bindings.
- bazel-boot2-original-dependencies-r1-20261103: nine dependency-only original
  controls, unchanged reference object hashes and complete consumed input digests.
- bazel-boot2-native-qualification-r1/r2/r3-20261103: original tool declaration,
  corrected tool policy, and completed original directory policy/regression.
- bazel-boot2-native-action-collection-r1/r2/r3-20261103: official compact-log
  conversion, actual compiler/producer witnesses, immutable outputs and params.
- bazel-boot2-review-r1-20261103: byte/policy/input/link/tool/installation/debug
  reports, rejected comparisons, host test log, instrumentation scope, retained
  observers/profiles/stages, manual lint baseline and final source/commit bindings.
