# Private zstd library, CLI and packages on three ABIs

## Scope (2026-11-03)

Source-owned normal `build-bsd bazel-test` format-5 profiles qualify libzstd,
zstd and the four selected packages on amd64, ARM64 and RISC-V. This extends
bounded earlier native evidence; BUILD presence alone was not used as evidence.
The selected library has 33 C sources on amd64/ARM64 and 34 on RISC-V, including
the original `zstd_kfreebsd.c` runtime helpers. The CLI has eleven C sources.
No runtime C, original Make recipe, SDK, compiler configuration or shared build
helper changes are made. The existing frontend/backend selects the declared
producers, captures artifacts, and validates native host tests for cross builds.

Hash-bound results and engineering drivers are retained in
`/usr/obj/usr/src/bazel-zstd-family-package-review-r4-20261103/qualification-summary.json`.
Accepted normal profiles use `bazel-zstd-family-ARCH-native-qualification-`
`r4-20261103` for amd64/RISC-V and `r5-20261103` for ARM64. Actual compiler,
dependency and expanded-link captures use the corresponding action-collection
roots. The final additional linker select applies only on ARM64; its other
architecture branches are empty. This is not an action-key equivalence claim.

## Actual production and archive contracts

All 233 regular/PIC library and CLI compiler contexts pass the selected original
warning, define, visibility, small-PIC/PIE, ISA, debug and code-generation policy
checks, with 9,937 canonical consumed input/digest pairs. The retained actual
arguments include native header views; consumed header identity is checked
against original physical prerequisites. Lexical `..` spellings resolve only to
the exact declared input, and virtual public headers resolve only within the
zstd source owner. SDK/project producer identity is not generally waived.

The library preserves hidden visibility followed by the original pool.c default
visibility override, the huf_decompress warning exception, multithreading,
assembly-disable and namespace defines, and the real RISC-V-only source. Explicit
original-order regular/PIC archives advertise the default CcInfo interface;
installation and ordinary static consumers use the same regular archive.
All 200 archive members bind to actual compiler output digests. A real minimal
version API consumer proves selective extraction without forcing unrelated
compression or thread-pool objects into the executable. The DSO retains the
complete original PIC order, pthread dependency and private ABI
`libprivatezstd.so.5`. Nine actual core link sequences are retained.

The full CLI is an indirect requested family dependency. Its raw bytes come
from fully verified actual CppLink output captures, rather than an invented
direct artifact-index entry. Requested installation/package artifacts and
actual host-test inputs provide the enclosing accepted normal profile.

## Ordinary references and explicit filename controls

Six untouched original Make build/install references and twelve original
packages are retained under `bazel-zstd-original-references-r1-20261103` and
`bazel-zstd-family-make-package-references-r1-20261103`. Of the 233 production
objects, 206 have identical allocated payloads against those ordinary references.
Twenty-seven do not: divsufsort regular/PIC plus seven CLI source objects per ABI
embed absolute original source names versus native relative names. Their raw
rejections are retained, including relocation effects; ordinary byte equality
is not claimed for them or the affected linked payloads.

Independent controls under `bazel-zstd-filename-original-controls-r1-20261103`
include the unchanged original component Makefile, then append exactly
`-fmacro-prefix-map=/usr/src/=` to recursive CFLAGS. Every one of the 233 actual
compiler vectors is checked against its ordinary original with exactly that one
flag removed; original `-MD`, `-MF` and `-MT` remain intact. No producer source,
object or final bytes are rewritten. All 233 allocated object payloads/runtime
relocations and all six linked DSO/CLI allocated payloads match these explicit
same-source filename-policy controls. ELF architecture/type, SONAME, ordered
NEEDED, imports/exports and hardening also pass independent comparisons.

Earlier failures remain evidence: the initial DSO lost pthread linkage when
switching to explicit archive-backed CcInfo; its original DSO flag is now
explicit. Green builds were rejected for missing original CLI PIC/lower-case
PIE flags and a missing debug-directory record. ARM64's CLI later failed strict
text equality because its original Cortex-A53 linker workaround was absent.
The final actual ARM64 expanded link adds exactly that flag and has identical
other arguments and non-paramfile input records. The DSO already preserved it.
No broad ELF comparator relaxation was introduced.

## Installation, packages and tests

All 57 original component records compose to 54 unique records through the
existing explicit identical-directory opt-in. Complete owner/group/mode/flags/
tags/type metadata is preserved, including both components' original debug
directories. Eighteen actual hardlink records match original inode relationships
and installation-tar targets. Extracted package hardlink groups also agree.
Six native and six original debuglink/CRC pairs validate independently.

Twelve native packages match twelve independently constructed original packages
from the explicit filename-policy stages: zstd, zstd-dbg, zstd-dev and zstd-lib
per ABI. ABI, membership, dependencies, annotations, ownership, modes, directories,
links and non-ELF payloads match; ELF allocated data and every archive member
retain the production proofs. Native epoch zero is distinguished from each
verified original stage timestamp. Whole package/archive byte equality is not
claimed; separate DWARF and archive debug envelopes differ.

Five declared test invocations pass: two native static/shared API tests request
zero/four workers and check checksummed roundtrips/truncation, and three native
host tests inspect actual target architecture, archives and default extraction.
The native host test additionally exercises four command alias names safely;
foreign programs are never executed. Independent immutable native and original staged CLI/library
replays verify all four aliases, identical encoded bytes, decoded
payloads, truncation rejection and selected-DSO loader traces.

## Remaining work

Separate DWARF equality/source lookup, full upstream tests, alternate options
and split-manpage packages, performance/cache behavior, package-manager
installation/solver, complete world/rescue/bootstrap and foreign runtime remain
open. There is no installation to the host, publication, boot, signing or
verified-boot claim. Cross libmd/liblzma/xz and the larger libarchive dependency
stack remain distinct userland closure work.
