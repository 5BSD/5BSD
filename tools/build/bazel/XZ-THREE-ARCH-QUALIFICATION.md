# XZ/liblzma on three ABIs

## Selected default scope (2026-11-03)

Three normal `build-bsd bazel-test` format-5 profiles qualify liblzma, xz,
xzdec, lzmainfo and the four selected XZ packages on amd64, ARM64 and RISC-V.
Make remains production. Existing frontend/backend interfaces select, build,
capture and inspect these owner-local producers; no new CLI, shared primitive,
SDK change or build-time Make discovery is introduced by this checkpoint.
The default development inputs are not a world publication or installation.

Eight source owners change: lib/liblzma's BUILD, installation and declared host
checker; the three command BUILDs; packages/xz; and contrib/xz's private command
header view. Runtime C and original Make recipes are unchanged. The preceding
[libmd checkpoint](LIBMD-THREE-ARCH-QUALIFICATION.md) supplies actual optimized
amd64/ARM64 and portable RISC-V prerequisites without pretending that its
filename-sensitive original objects are ordinarily byte-identical.

The final hash-bound record is
`/usr/obj/usr/src/bazel-xz-family-review-r1-20261103/qualification-summary.json`.
Accepted profiles and full action/.d/link captures use
`bazel-xz-family-ARCH-*-r6-20261103`. They use verified native/target r4 SDKs with
separately bound native execution closures. Fifteen untouched original component
build/install references remain under
`bazel-xz-family-original-references-r1-20261103`; 719 original object records
and 718 distinct consumed paths were retained before native qualification.

## Compiler and header contracts

| Per ABI | Production contexts | Real static-command test contexts |
| --- | ---: | ---: |
| amd64 | 187 | 21 |
| ARM64 | 187 | 21 |
| RISC-V | 187 | 21 |

The 561 production contexts comprise 78 ordinary and 78 PIC library objects,
21 xz objects, four xzdec objects and six lzmainfo objects per ABI. All original
warning, define, language, optimization, small-PIC, PIE, SSP, debug and target
policies pass, with 46,575 consumed-file/digest occurrences. Every consumed
native dependency is declared with its matching digest in the actual action.
All 561 allocated object payloads and runtime relocation sections match the
untouched originals. No XZ filename-policy control or byte rewrite is needed.

Library compilation consumes source API headers. Original installed command
recipes instead consume staged SDK API headers. A header-free `lzma_link`
interface preserves that production origin; public `lzma` CcInfo retains the
source API for ordinary native consumers. Equal header bytes do not generally
waive origin mismatches. The test-only static variant of the real xz command
uses the public source API, separately checking 63 contexts/5,079 consumed
occurrences against its declared source-header contract. Its 39 raw origin
differences from the installed command references are explicitly retained;
all allocated and runtime relocation sections still match. This variant is
not represented as a distinct original Make installation product.

## Archives, shared boundaries and generated outputs

All 468 native archive members are bound to actual compiler output digests.
Ordinary archives preserve the original 78-member installed archive order;
default public CcInfo advertises that same archive with its separate PIC variant.
The native PIC archive preserves the original 78 `.pico` DSO input order, using
conventional `.pic.o` member names. Original Make does not install this PIC
archive by default; its native envelope is an implementation composition.

Fifteen actual final link vectors bind accepted output digests and archive
inputs. The DSO consumes the complete PIC archive with the original symbol map,
SONAME, md/pthread and SSP policy. Installed commands remain PIE and retain the
ARM64 Cortex-A53 linker workaround. Their direct dependencies do not gain md or
pthread merely because those are implementation dependencies of liblzma. Making
the header-free interface the shared-library root preserves that boundary.

The real static xz test links the ordinary installed archive without
whole-archive or section-GC forcing. Required lzma APIs are extracted while the
unrelated microlzma encoder remains absent. Its non-PIE link accepts the original
ordinary non-PIC archive; installed command policies remain unchanged.

The three version maps, pkg-config files and compressed command manuals agree
with original bytes (15 outputs). The version-map digest is also an actual
final DSO action input. Generator evidence explicitly distinguishes observed
executions from accepted cached target/output bindings; a missing new AWK
execution witness is not invented. The original version is 5.8.4, derived from
its maintained version header.

All twelve production linked ELF files match original dynamic metadata,
including ordered dependencies, imports/exports and hardening, and every
allocated section. These results do not imply separate DWARF equality.

## Installation and actual packages

Per ABI, 49 original component records compose to 44 unique records by merging
only completely identical directories. Destination, type, owner, group, mode,
flags, tags and link targets match; duplicate payloads remain errors. Twelve
hardlink records per ABI are checked against original staged inode identities.
The five xz binary/manual aliases are retained. Original xzdec installs the
binary alias `lzdec` but manual alias `lzmadec`; this distinction is preserved
without inventing another decoder mode.

Native and original debuglink/CRC validation passes for each DSO and three
commands. Their separate debug files remain different and source lookup is
unqualified. Original directory records are represented explicitly rather than
waived through mtree scaffolding.

Private original `packages/xz stagepackages` controls create xz, xz-lib, xz-dev
and xz-dbg on all three ABIs, using frozen native execution tools, isolated pkg
configuration/databases and no host installation or publication. SDK validation
passes before and after those controls. The explicit selected package version
is `16.snap20261025133323`; this is not a new release/latest claim. The original
minimal/minimal-jail sets and selected split-man-disabled policy are retained.

All twelve native packages match original names, ABI, version, dependency,
license, annotation, directory and file metadata, hardlink groups, and payload
membership. Non-ELF data agrees byte-for-byte. ELF allocated payloads and all
ordinary archive member allocated payloads agree. Native mtimes use epoch zero;
original package mtimes match the independently staged originals. Raw checksums,
flat sizes and section differences remain recorded. Installed non-debug ELF
byte differences are confined to their separately validated debuglink sections;
separate DWARF/archive debug bytes and whole package bytes are not claimed equal.

## Tests, rejection history and remaining gates

Three declared host artifact tests pass. They inspect target machine/type,
archive order and real static extraction on all ABIs, and execute programs only
on amd64. Native checks cover compression, the static command, aliases, decoder,
lzmainfo and truncated input. An independent original/native amd64 replay passes
19 exact raw stdout/stderr/status comparisons over nine command names, including
SHA256 streams, T1 and bounded T2 compression, LZMA and truncated-input rejection.
The replay uses private exact-byte executable copies, selected DSOs and identical
declared argv[0] names; no output filtering or normalization is applied.

Retained rejected candidates are significant:

- r1 incorrectly linked the test-only ordinary archive consumer as PIE.
- r2 lost the original DSO pthread policy through an archive wrapper.
- r3 matched runtime bytes but violated production SDK API header origins.
- r4 was rejected at analysis for an incomplete shared export owner set.
- r5 leaked md/pthread dependencies onto all installed command links after the
  header/link split. The corrected direct shared root restores original metadata.

These are native candidate defects, not original Make defects. Initial private
runtime helper attempts also retained a non-executable immutable-artifact mode
failure and the expected differing-argv[0]-path diagnostic mismatch. Their
corrections changed only private execution setup, preserving raw comparisons.

Foreign execution, i386-only CRC assembly, alternate options/compiler floors,
separate DWARF/source lookup, upstream suite breadth, full world/rescue closure,
package solver/installation/publication, bootstrap/sandbox/cache qualification
and measured CPU/memory/disk performance remain open. Binary/package generation
alone proves neither boot nor runtime operation on another architecture.
