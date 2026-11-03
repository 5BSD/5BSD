# libbz2 and bzip2 on three userland architectures (2026-11-03)

The source-owned `lib/libbz2` and `usr.bin/bzip2` declarations now build actual
amd64, ARM64 and RISC-V userland artifacts through normal format-5 `build-bsd`
profiles. This is a library/program component qualification, not full world,
rescue, package creation or foreign runtime qualification.

## Production graph

The library preserves the original seven-source member order: bzlib,
blocksort, compress, crctable, decompress, huffman, randtable. Ordinary CcInfo
consumers and installed `libbz2.a` select the same explicit regular archive.
A separate original-order small-PIC archive supplies the maintained SONAME
`libbz2.so.4`; its whole-archive state ends before remaining link inputs.
The bzip2 executable preserves original defines, ordered WARNS=3 vector and
PIE policy, including original earlier `-fpie` followed by `-fPIE`. Explicit
stack-protector linker flags are retained. Public headers and ABI labels remain
source-owned and source files are unchanged.

Pkg-config generation executes the original `gen-pc.sh`, original version sed
expression, declared native shell/sed/mv/rm and runtime inputs with LC_ALL=C.
It no longer substitutes a Python implementation. Existing installation
primitives provide the original explicit debug directories and component tags.
The two component archives stay separate in the aggregate archive-set provider,
including their shared debug-directory context.

## Independent original and actual action proof

Evidence:

- Native original: `bazel-bzip2-original-references-r2-20261103`.
- Refreshed cross originals: `bazel-bzip2-original-references-r3-20261103`.
- Final native/ARM64/RISC-V profiles:
  `bazel-bzip2-{amd64,aarch64,riscv64}-native-qualification-r3-20261103`.
- Fully drained original Bazel compact converters, copied actual compiler
  outputs/.d files and actual expanded link parameters:
  matching `bazel-bzip2-ARCH-action-collection-r3-20261103` directories.
- Immutable comparisons: matching `bazel-bzip2-ARCH-review-r3-20261103` and
  `bazel-bzip2-debug-review-r3-20261103.json` under `/usr/obj/usr/src`.

All 45 production compiler contexts (14 library regular/PIC plus one program
per architecture) pass original warning/define/language/code-generation,
ordered PIC/ISA and debug-flag checks. All 995 original/native consumed source
and header occurrences match actual action-input digests, not merely declared
search roots: 363 native, 316 ARM64, 316 RISC-V. Every production object's
allocated sections and runtime relocation sections match the original bytes.
The actual compiler matches the selected SDK; target machine/ABI is checked.
The three uninstalled static-consumer objects are additional controls.

All six complete linked DSO/program ELFs have exact original allocated sections
and pass type/machine, SONAME or PIE/interpreter, ordered NEEDED, versioned
imports/exports and hardening comparisons. No allocated difference is waived.
All nine actual link sequences are retained. Forty-two regular/PIC archive
members match complete actual compiler-output bytes in original source order;
regular archive member names match Make. Native PIC `.pic.o` versus Make
`.pico` is an explicit archive-envelope distinction, not rewritten output.
Archive and separate DWARF bytes are not claimed identical.

The actual default CcInfo static consumer links only the regular archive,
without whole-archive or section-GC flags, and retains precisely `BZ2_rNums`.
The DSO separately expands all seven original-order PIC members. The program
uses the native produced SONAME library. Host tests check actual target ELF
machines 62/183/243, archive order and executable DWARF compression using
declared native tools, never executing the foreign consumer or program.

All 18 original installation records per architecture match destinations,
ownership, modes, tags, explicit directories and link semantics: 54 component
records total. Original hard links are verified by original staging inodes;
METALOG `type=link` and native `symlink` are the same explicit link operation.
Headers, pkg-config and manual compressed payloads match whole bytes.
Six native and six original installed binary/debug pairs pass actual debuglink
name/CRC and positive DWARF-presence validation. ARM64/RISC-V raw program
symbol-table differences are specifically four/six
local `$d` mapping-symbol offsets into identified nonallocated DWARF sections;
raw differences and section identities are retained without rewriting. These
checks do not establish separate DWARF equality or debugger source-resolution
parity.

## Tests, rejected attempts and remaining gates

The final native profile passes the six existing compression/decompression
sample cases plus the archive/ABI host test. Each cross profile passes only its
host artifact test. Thus nine declared target invocations pass with no skipped
or expected-failure cases; no ARM64/RISC-V target executable runs.

The first original-reference attempt failed its helper stability guard and is
retained as rejected. The first native/ARM64 builds passed tests, but strict
recipe review caught the omitted earlier `-fpie` flag. The r2 profiles corrected
that declaration, but final debug review then
found omitted executable-link `-gz=zlib`: original Make compresses linked DWARF.
Final r3 preserves this flag and extends the existing host artifact test to
validate the actual ELF compression header and decode zlib DWARF to its
declared size. The checker rejects all three actual prior uncompressed outputs
and accepts all three original Make outputs. Final r3 profiles and fresh actual
captures qualify the corrected compile/link policy; earlier green tests do not
stand in for that proof. SDK/header floor repairs and their rejected attempts are detailed in
[USERLAND-SDK-QUALIFICATION.md](USERLAND-SDK-QUALIFICATION.md).

The SDK and target libc remain Make-built bootstrap floors. Other selected
programs, including the separate bzip2recover executable, full library-option
matrices, separate DWARF/source lookup, target execution, full world/rescue,
pkgbase creation/publication, performance and boot/security behavior remain
open. No installation on the host, upgrade, reboot, signing or verified-boot
claim is made.
