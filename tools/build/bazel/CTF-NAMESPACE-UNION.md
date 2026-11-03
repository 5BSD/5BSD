# CTF namespace union and LLD section integration

## Why this exists

The module pipeline performs a multi-input relocatable link, then the maintained
ctfmerge, export localization and a final shared link. Fixing the final linker
must also account for the first link: concatenating independent CTF dictionaries
does not produce one valid namespace. The normal ctfmerge reads its explicit
original object inputs, uses the intermediate ELF symbol table, and replaces
that intermediate CTF. A valid disjoint union fits this pipeline without a new
flag, omitted metadata or name-based matching.

LLVM Object CTFSymbolTable::merge provides that union and LLD now uses it for
script-selected sections. Controlled ARM64/RISC-V module pipelines pass the
strict final CTF/export/debug-split policy. Fresh verified SDK/frontend profiles,
original controls and target runtime remain open; this is not system acceptance.

## Contract

- Input identities are `(container, original ELF symbol index, symbol type)`;
  output ordering is explicit. New symbols receive unknown associations.
- Every input type receives a distinct v3 ID. Type names, roots, literal
  encodings, layouts, signed enum values, cycles and exact type edges survive.
  This is namespace relocation, not structural type deduplication. Duplicate
  names remain distinct types; no lookup-name guess selects an identity.
- Both v2 and v3 are decoded. Widening accounts for extended sizes, arrays,
  enumeration/member string references, reference/qualifier types, function
  return/argument vectors and changed structure-member layout thresholds.
- Function associations stay packed. Function vectors inside the type section
  retain their separate alignment rule. External ELF strings are internalized;
  only referenced strings are interned, preventing unused string-table bloat.
- Output byte order and compression are explicit, and output is v3. Errors leave
  the caller's output unchanged. Dangling references in discarded input symbol
  associations are rejected as well as those in retained symbols/types.
- Self-contained dictionaries are supported. Parent references require explicit
  resolution and are rejected. Labels must either be absent from every input or
  have the same names covering each entire input dictionary. Different label
  order is accepted. Partial/different scopes are rejected: arbitrary prefixes
  cannot be faithfully represented by concatenating independent dictionaries.
- Header, type-ID and string-offset overflow checks are explicit. The tests do
  not allocate multi-gigabyte dictionaries to exercise every maximum-size limit.

Single-container symbol rewriting still preserves opaque type/string/label
payloads and the existing ObjCopy unchanged-order fast path. The new union does
not weaken those caller-side ELF link, eligibility or allocation checks.

## Qualification completed on 2026-11-03

Maintained source-owner Make rebuilt the host bootstrap library and objcopy with
16 jobs, without installing into the completed ARM64 target sysroot. Source
bindings and unchanged staged tool were checked. Records:
`/usr/obj/usr/src/bazel-ctf-shared-helper-union-build-r2-20261103`.
The default target triple of this HOST tool does not constitute ARM64 execution.

Normal build-bsd format-5 bazel-test then built the API test and union driver
from native Bazel LLVM Object/Support components. There is no Make wrapper or
import of the bootstrap LLVM archive in those targets. The selected tests are:

- `//tools/build/bazel/tests/ctf:symbol_table_api_test`: 160 API checks.
- `//tools/build/bazel/tests/ctf:union_graph_test`: 1,024 format-pair graph checks,
  256 independent source-built ctfdump checks, 16 rejection controls, four member
  size boundaries, reordered full labels, external zero references and proof
  that a 1 MiB unused external string does not increase output bytes.
- `//tools/build/bazel:ctf_semantics_test`: 30 unittest methods.

Actual source/module/compiler bindings, BEP test outputs, logs and receipts are
retained at `/usr/obj/usr/src/bazel-ctf-object-api-r5-20261103` and
`/usr/obj/usr/src/bazel-ctf-union-review-r2-20261103`. In r5 the graph test runs;
the API and semantic suites reuse their verified successful cached results.
The graph test declares its driver, fixture generator, reader, source-built
ctfdump and runtime libraries. Its temporary directory comes from Bazel's
TEST_TMPDIR. Outside Bazel, union-audit.py requires an explicit work directory
and explicit driver/fixture/reader/consumer paths.

The Make-library and native Bazel drivers serialize all 1,024 compared fixture
cases identically. That is helper serialization parity for these inputs, not
whole LLVM artifact, bootstrap, ABI, world/kernel or package parity. Inputs cover
both versions/byte orders/compression modes and internal/external names; output
encoding varies independently. The ELF consumer fixtures are AMD64, and
independent ctfdump checks cover little-endian output. No foreign code executes.

Earlier attempts remain recorded: the first native dependency build hit the
16 GiB disk reserve and was interrupted/rejected; a later test analysis omitted
shared-library labels from data for location expansion and was rejected/fixed.
An immutable captured executable blob has read-only mode; direct execution was
rejected. An execution copy with the recorded mode and identical hash passed.
No frozen SDK blob was modified or substituted. Final guarded profiles pass.

Resource cleanup records are at
`/usr/obj/usr/src/bazel-ctf-union-cache-reclaim-r2-20261103`. Verified redundant
canonical caches from 59 completed post-snapshot profiles were pruned; primary
inputs, outputs, receipts and extracted repositories remain. Earlier pruning
of 61 snapshot-held caches could not release those blocks, so those trees were
restored and verified. No snapshot, boot environment, SDK, object or binary was
removed. This is resource recovery, not a disk-performance benchmark.

## Remaining integration

LLD retains exact file/index provenance and connects namespace union,
script-selected placement, layout sizes, final symtab order and sh_link.
Controlled complete ARM64/RISC-V module pipeline replays pass. Next refresh tools
and immutable SDKs through maintained helpers, run actual frontend profiles and
independent refreshed Make controls on AMD64/ARM64/RISC-V, and qualify resource
use and footprint. Never infer identities from names, addresses or redirected
input symbol arrays.

The local libctf v2 width/rounding inconsistency is separate and remains open.
Parent resolution and broader label semantics remain unsupported by this union.
Full LLVM/bootstrap, configurations, world/kernel/modules, packages/publication,
runtime and comparative CPU/memory/disk qualification remain open.

Frontend assessment: Make and native Bazel Object source inventories include
CTFMerge.cpp, and normal build-bsd runs the new declared tests. No new frontend
option, config schema, SDK stage/signing, security policy or publication change
is needed for this foundation. Future linker tool changes require normal
bootstrap rebuilding, fresh verified SDKs and actual module profiles. Keep Make
production/default and BIP excluded. No installation or reboot was performed.

## 2026-11-03: selected-definition provenance foundation

LLD now records exact original input symbol indices alongside selected
symbols, without increasing SymbolUnion. CTF files retain their maps through
later symbol copies; normal files release transient maps after parsing.
COMMON conversion, version copies, wrapping and replacement invalidate or
transfer identities explicitly. This is still not CTF output synthesis.

A no-CTF file records one bit per global input during resolution. Only a
same-file collision promotes those recorded decisions to an index map, once
per file. Ordinary files avoid a hash-map entry for every global symbol.
No name/value/address matching reconstructs a defining index. CTF files track
all selected indices directly, including eligible local definitions. Parallel
parsing writes file-owned maps; postParse only queries the selected file's map
inside its file-identity guard, before releasing a non-CTF map.

The exact index also fixes a demonstrated existing section-selection bug: a
later losing weak entry in the same file could overwrite the section of the
winning strong entry while retaining the strong value and size. The regression
constructs both raw ELF entries explicitly and checks binding, size and actual
payload in relocatable and shared output, in both entry orders, with and without
a valid self-contained CTF section. Eight cases pass with the source-owner
Make-built LLD; the old staged LLD reproduces the wrong-section failure.
The maintained explicit-input script is tests/ctf/lld-symbol-origin-test.py.
The source-built Bazel lld_symbol_origin_test target is declared, but its native
Bazel build/test has NOT yet been run for this checkpoint.

Source-owner build records are under
/usr/obj/usr/src/bazel-lld-ctf-origins-build-r2-20261103. All 16 CPUs were used;
source hashes remained frozen, the disk guard was not interrupted and the
staged linker was unchanged. No installation was performed. Sixteen additional
baseline/candidate output or failure controls cover weak/strong resolution,
COMMON, wrapping, versions, GC and ICF. The version control uses the same
explicit SONAME; an earlier comparison differed because output basenames were
allowed to become different SONAMEs, not because symbol output differed.

An alternating five-pair 200,000-global-symbol no-CTF relocatable-link diagnostic
produces identical bytes. Baseline elapsed samples are 0.056–0.062 seconds,
candidate 0.053–0.055 seconds; reported peak RSS is 80,456–87,648 KiB versus
75,924–86,408 KiB. Full time(1) reports include block I/O and faults. These short
host diagnostics are not general performance acceptance. The first all-global
map implementation increased time/RSS on this workload and was replaced;
its evidence is retained. The final sparse implementation must still receive
whole-system CPU, memory, I/O and disk qualification.

Frontend assessment: no new build inputs, flags, security policy, staging or
publication format. The maintained LLVM source-owner build and native Bazel LLD
sources select these changes normally. build-bsd.c, signing and SDK helpers do
not require schema or option changes. Fresh SDK verification and actual module
qualification remain mandatory after CTF section/link synthesis is complete.

## 2026-11-03: CTF size planning for linker layout

The shared owning CTF table now exposes getUncompressedRewrittenSize. It
validates the same exact output identities as rewrite, counts known packed
function associations and new unknown associations, preserves the label/type/
string payload sizes, and includes subsection alignment and the header. It
does not copy the dictionary or compress it. Rewrite and sizing share identity
and overflow validation, preventing two independent eligibility contracts.
The size refers to uncompressed output even when the input was compressed.
It does not predict the compressed size, which can change with symbol order.

Normal build-bsd/Bazel qualification at
/usr/obj/usr/src/bazel-ctf-layout-sizing-r1-20261103 passes three suites. The
expanded API test actually executes 328 checks; the namespace-union graph test
actually executes 1,024 cases and 256 independent ctfdump controls; the semantic
reader suite reuses its verified cached pass. Size is checked against serialized
output in both versions/byte orders/compression modes, with a label prefix,
known functions of different argument counts, unknown functions, reordered and
removed symbols, and repeated new-symbol sentinels. Invalid identities/types
are rejected by both operations. The disk reserve was not interrupted.

LLD integration remains open. Its layout can add thunk symbols before the final
symtab sort. An eventual CTF synthetic section must participate in that layout
with an accurate size and serialize against the final symbol order. It must
also honor script input selection/discard and emit the correct sh_link; adding
an arbitrary late resize after file offsets are assigned is not acceptable.
The sizing API is a foundation for that implementation, not proof of a fixed
module pipeline. Frontend assessment: existing native Bazel API targets and
source-owner LLVM builds select the API normally. No build-bsd options, signing,
staging, policy or SDK formats change. No performance or final module acceptance
is claimed from this test run.

## 2026-11-03: LLD section integration and controlled pipeline qualification

LLD combines CTF after script selection and /DISCARD/, before input-section
finalization. File-specific rules therefore select the actual inputs. Each
output namespace is prepared once. Exact definition identities drive opaque
association rewriting. Dense membership avoids quadratic section replacement;
links without CTF skip the section-command walk entirely.

Size planning participates in the existing layout/relaxation loop, including
thunk symbols. Final serialization follows static symtab sorting and emits its
real sh_link. Stripped shared images link CTF to DYNSYM; stripped static images
retain a type-only dictionary with zero link. Kernel module tests still require
SYMTAB; the reader was not relaxed.

Zero-sized section/NOTYPE header labels, including AArch64 mapping symbols,
anchor to the rewritten header. Other definitions inside CTF, relocations into
CTF, allocated CTF, incorrect input links and mixed/padded output containers
fail explicitly. Parent resolution and broader label scopes remain unsupported.

Qualified with source-owner Make-built LLVM/LLD, all 16 CPUs, frozen source
bindings, disk reserve and no installation. Final build is
/usr/obj/usr/src/bazel-lld-ctf-section-build-r5-20261103.
Maintained lld-section-audit.py passes 138 cases: 128 format-pair relocatable/
shared links, three weak/strong selections with distinct graphs, script input
selection/discard, malformed linkage/flags/output and two strip-all contracts.
Graph checks preserve type multiplicities, roots, layouts and edges; only ELF
section placement/addresses are excluded across links. Maintained
lld-symbol-origin-test.py passes ten cases, including an actual AArch64 thunk
added during layout and an explicitly rejected dictionary reference. Its large
virtual span produces a 133,216-byte file under a child file-size limit.

Complete captured ARM64/RISC-V nullfs pipelines at
/usr/obj/usr/src/bazel-lld-ctf-section-pipeline-r3-20261103 pass initial links,
maintained ctfmerge/export, final links and actual debug splitting. Unchanged
strict full/runtime checks cover 112/114 associations and seven named types in
each output (14 checks per architecture). Initial and final outputs are also
read by ctfdump. Retained original action inputs are hashed; explicitly replaced
inputs are recorded. These are controlled replays, not fresh frontend profiles.

Eight no-CTF link controls match baseline bytes or expected failure. Five
alternating 200,000-symbol no-CTF pairs produce identical bytes. Baseline elapsed
samples are 0.056-0.061 seconds and reported RSS 78,804-87,924 KiB; candidate
0.052-0.056 seconds and 77,116-86,548 KiB. Full time reports retain faults and
block I/O. These short host samples are not broad performance acceptance.

Footprint remains an open gate: prepared output is currently uncompressed v3,
so final ordering cannot invalidate layout. Compared to prior broken final-link
outputs, ARM64 CTF grows 22,904 to 60,665 bytes (full module 250,872 to 288,632);
RISC-V CTF grows 22,674 to 60,148 (full module 297,248 to 334,720). Compression/
footprint needs further work and qualification. No namespace merge or dictionary
compression repeats during relaxation. Do not call this performance acceptance.

Earlier failures remain recorded: a C++ bit-field reference failed compilation
and was fixed; the first anchor policy rejected AArch64 $d and was corrected.
A source-graph diagnostic encountered ambiguous local identities and was not
used as acceptance. Final full/runtime checks use the unchanged strict reader.
One audit found a stale live original final input; the corrected audit verifies
retained inputs and records the explicit replacement. The first documentation
write did not execute because automatic permission review timed out.

Frontend assessment: implementation uses existing LLVM/LLD source owners and
Bazel component inputs. No compiler flag, frontend option, config/security policy,
signing or package format changes. Native Bazel lld_symbol_origin_test and
lld_section_test are declared but have NOT yet executed through Bazel; scripts
above use the maintained Make-built candidate. Fresh tool/SDK/frontend and
original-control qualification, AMD64 actual module coverage, target execution,
complete world/kernel/packages, bootstrap/sandbox/cache and broad performance
remain open. Make stays default; BIP is excluded. No host install or reboot.
