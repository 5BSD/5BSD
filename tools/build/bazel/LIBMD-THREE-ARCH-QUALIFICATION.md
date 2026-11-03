# Default libmd prerequisite on three ABIs

## Scope (2026-11-03)

Normal source-owned `build-bsd bazel-test` format-5 profiles qualify the default
libmd production library on amd64, ARM64 and RISC-V. This supplies the genuine
cross-architecture prerequisite for liblzma/XZ; it does not infer qualification
from existing BUILD files or merely remove architecture constraints.

The six owner changes are lib/libmd's BUILD and installation files, its existing
test BUILD and a host artifact checker, sys/crypto/sha2's narrow ARM source
exports, and sys/sys's libmd-only header view. Runtime C, original Make recipes,
SDK generators, compiler configuration and shared build primitives are unchanged.
Existing frontend/backend profiles select, build, capture and validate these
producers; no new CLI/API or build-time Make discovery is required.

Evidence is retained under
`/usr/obj/usr/src/bazel-libmd-three-abi-review-r1-20261103/qualification-summary.json`
and `qualified-source-bindings.json`. Accepted profiles and actual action/.d/link
captures use `bazel-libmd-three-abi-ARCH-*-r2-20261103`. All use the strictly
verified native/target r4 SDKs with a separately bound native execution closure.

## Original sources, policy and archive interface

All 158 regular/PIC library compiler contexts pass exact selected warning,
define, language, small-PIC, assembly, ISA, SSP and debug policy comparisons and
4,762 canonical consumed-file/digest pairs. Compiler witnesses are actual
executions from the accepted r2 streams, fully drained before profile switches.
Every consumed native dependency is present with its digest in the actual action
input record. Generated source identities and virtual header owners are explicit;
SDK/project header origins are not generally treated as interchangeable.

The original architecture selections remain distinct:

| ABI | Objects per archive | Optimized source selection |
| --- | ---: | --- |
| amd64 | 28 | MD5/SHA1 dispatch and assembly; Skein assembly |
| ARM64 | 28 | MD5/SHA1 assembly, SHA1 dispatch, SHA256/SHA512 crypto C |
| RISC-V | 23 | Portable implementation |

ARM64 crypto units preserve `-march=armv8-a+crypto` and
`-march=armv8.2-a+sha3`. The receipt-bound compiler supports the original
`aarch64-sha512` feature. A different compiler's feature-dependent selection and
BOOTSTRAPPING remain separate gates. The existing machdep_optimizations flag
selects portable versus optimized sources explicitly; nondefault compilation
qualification remains open.

Original C flags also apply to assembly; the Skein C/assembly loop selections
remain 995/0, with the original amd64 ELF/noexecstack flags. The regular and PIC
archives preserve original member order and bind every member to its actual
compiler output digest. Native PIC members use conventional `.pic.o` names
versus original `.pico`; this archive envelope is recorded, not rewritten.

The public md_link CcInfo and md_archive interface now advertise the explicit
ordinary archive and its separate PIC variant. The installed /usr/lib/libmd.a
is the same ordinary input used by default static consumers. All three actual
MD5 driver link vectors select it without whole-archive or section-GC forcing;
the checker proves MD5 extraction without unrelated digest members. The DSO uses
the complete PIC archive. Six actual DSO/default-consumer link contracts are
retained; ARM64 preserves its original Cortex-A53 linker workaround.

## Ordinary references and filename-policy controls

Fifteen original build/install references for libmd and the four XZ components
are retained under `bazel-xz-family-original-references-r1-20261103`. This
checkpoint accepts only the libmd prerequisite. All 719 original production
metadata/dependency records and 718 distinct consumed paths were bound before
native work; the libmd portion has 158 contexts.

Against untouched libmd originals, 146 allocated object payloads agree. The
remaining twelve are md5c and sha1c regular/PIC objects on each ABI, which embed
absolute original source names versus native relative names. The raw string and
relocation differences remain retained. Ordinary byte parity is not claimed for
these contexts or the affected DSOs.

Three independent controls under
`bazel-libmd-filename-original-controls-r1-20261103` include the unchanged
original Makefile and append exactly `-fmacro-prefix-map=/usr/src/=` to recursive
CFLAGS. All 158 actual original compiler vectors differ from their ordinary
baseline by exactly this one flag; dependency flags -MD/-MF/-MT remain present.
No source, object or final output is rewritten. All 158 allocated object payloads
and runtime relocations, and all three complete DSO allocated payloads, match
these explicit controls. SONAME, ordered NEEDED, imports/exports with versions
and shared-object policy also pass independent comparisons.

The first green profiles were rejected by policy review: ten assembly actions
omitted original SSP flags, and twelve MD4 actions consumed an unnecessary
source-header view instead of the original SDK sys/md4.h. The corrected view
exports only the sys/md5.h alias actually created by Make. R1 evidence is kept;
no comparator tolerance was widened.

## Installation and tests

All 381 library installation records (127 per ABI) match original destinations,
owner/group/mode/flags/tags and file/directory/link policy. Installed headers and
compressed manuals are byte-identical, and hardlink relationships match original
staged inode groups and native tar targets. The original explicit
/usr/lib/debug/lib directory is preserved. Native and original DSO/debuglink CRC
pairs validate independently on all three ABIs. Separate DWARF/source lookup and
whole archive/debug byte equality are not claimed.

Twenty-eight native tests run the existing fourteen genuine digest drivers
against maintained references in static and selected-shared modes. Three declared
native host artifact tests inspect target ELF identity, archive order and lazy
extraction without executing foreign programs. No replacement digest fixture is
introduced. The captured component archive also contains existing installed-test
payloads, but this checkpoint does not qualify their producer policy or complete
recursive installation; only the library's 127 records per ABI are accepted.

## Remaining work

Portable-option and bootstrap builds, different compiler feature selections,
foreign runtime, separate DWARF/source resolution, installed-test producer
parity, complete runtime/tests pkgbase composition, full libmd consumer rebuilds,
performance/cache behavior and whole world/rescue remain open. XZ/liblzma family
qualification follows separately. No host installation, publication, boot,
signing or verified-boot claim is made.
