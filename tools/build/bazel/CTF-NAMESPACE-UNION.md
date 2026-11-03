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
script-selected sections. ARM64/RISC-V now pass both controlled pipelines and
normal maintained frontend profiles with fresh verified SDKs. AMD64 now passes
its normal profile too; see the latest checkpoint for pending action review. The strict final
CTF/export/debug-split tests actually run. Independent refreshed original
controls and target runtime remain open; this is not system acceptance.

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
script-selected placement, layout sizes, final symtab order and sh_link. Fresh
AMD64/ARM64/RISC-V source-owner tools, verified SDKs and normal frontend nullfs
profiles now pass, as do the selected source-built Bazel linker tests. Next
restore the converter and finish AMD64/native compact action reviews, independent
refreshed Make controls, debugger/runtime behavior and resource/footprint limits. Never
infer identities from names, addresses or redirected input symbol arrays.

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

## 2026-11-03: fresh SDKs and normal ARM64/RISC-V frontend qualification

Maintained source-owner Make all/install refreshed LLD and objcopy ONLY inside
the selected /usr/obj cross-build trees. LLVM libraries were built, not installed
into the foreign target sysroots. Complete inventories of 5,623 ARM64 and 5,498
RISC-V target header/library entries were compared before/after. The only changes
are exact native program debug outputs, checked against their built files and
AMD64 ELF identity. Running-system tool hashes remain unchanged. Sources and
recorded profile identities remain bound; all compilation uses sixteen CPUs.
Records: bazel-lld-ctf-bootstrap-{aarch64,riscv64}-r1-20261103 under /usr/obj/usr/src.

Maintained libmd-plan.py --sdk-only and libmd-stage-tools.py created NEW
bazel-userland-aarch64-sdk-r6-20261103 and bazel-userland-riscv64-sdk-r6-20261103
SDKs with the existing verified native execution SDK. Snapshot verification
passes and each new SDK tool matches its staged source-owner output. Earlier
SDKs were not edited. Preparation records are bazel-lld-ctf-sdk-preparation-r2
and -r3-20261103. The first preparation attempt referenced a misnamed historical
record and failed before planning; the corrected check uses the existing
verified SDK receipt's recorded .src_opts hash. Its failure log remains retained.

NORMAL format-5 build-bsd bazel-test profiles now pass:

- bazel-lld-ctf-fresh-arm64-r1-20261103: strict CTF test actually executes,
  checking machine 183 / ET_DYN, 112 associations and fourteen named-type checks
  across full/runtime outputs, with exactly the required exports.
- bazel-lld-ctf-fresh-riscv-r1-20261103: corresponding machine 243 / ET_DYN,
  114 associations and fourteen named checks; strict test actually executes.
- Each also reports the existing DTS test's verified cached pass. Neither run
  was interrupted by its disk guard. These are host artifact tests; no target
  code, kernel or module was executed or installed.

The corresponding *-review-r1-20261103 directories retain six actual action
records each: initial/final links, export localization, debug extraction/split,
and the noncached strict test. Tool input digests are checked against the
FROZEN selected SDK from each receipt, not the mutable external SDK alias.
Test reader/script/policy digests are checked, and the BEP-declared CTF JSON is
retained separately from stdout. This does not reconstruct initial inputs by
name or waive prior failed profiles. It qualifies the normal module path,
including normal verified SDK copying and declared execution dependencies.

Frontend assessment: the existing build-bsd command, format-5 inputs, maintained
Make source owners and SDK plan/materialization helpers select this work without
new flags, policy, signing, packaging or publication semantics. No C frontend
change is required. Native Bazel source-built LLD test targets, AMD64 refreshed
module qualification, original Make controls, full LLVM/bootstrap and system
coverage, debug/runtime, packaging and broad performance remain open. The
uncompressed CTF footprint limitation above is unchanged; Make stays default.

Administrative cleanup is recorded separately at bazel-space-cleanup-20261103-r3:
291 abandoned BIP image files and four verified duplicate terminal-run canonical
caches were removed. Primary inputs, sources, SDKs, outputs, logs, receipts,
published repositories and the unrelated active VM were retained. Snapshot-held
blocks and other concurrent work prevent attributing pool-free changes to those
file removals. Obsolete /var/cache/pkg cleanup was denied by OS permissions;
installed package versions are unchanged, and pkg clean -y requires root.
No snapshot, boot environment or running-system package was changed by this work.

## 2026-11-03: AMD64 frontend and source-built Bazel LLD tests

The maintained AMD64 source-owner bootstrap refresh completed with sixteen jobs.
Inventory checks cover 6,154 target header/library entries. Only the exact two
native program debug outputs changed; running-system LLD/objcopy hashes and
qualified source hashes are unchanged. Records are under
/usr/obj/usr/src/bazel-lld-ctf-bootstrap-amd64-r1-20261103.

A new native SDK, bazel-userland-native-sdk-r5-20261103, passes normal snapshot
and origin validation. Its LLD and objcopy match the refreshed build-tree tools.
Preparation r4 failed because concurrent cleanup removed its older tools config.
Preparation r5 rejected the old SDK's now-stale original linker binding, as it
should; r6 failed to normalize the readelf symlink before looking up its recorded input
key in preparation code. All
three failed records remain. Preparation r7 succeeds using newly declared inputs:

- Two standalone static tools (dtrace and gencat) are selected from retained SDK
  artifact copies. Each file matches both its recorded original-tool hash and
  snapshot hash; the old receipt itself matches its retained cross-SDK binding.
  The old SDK is NOT represented as currently revalidated or used as an SDK
  composition source. No receipt or verifier is weakened or rewritten.
- The normal materializer binds the actual selected files into a NEW receipt.
- A retained canonical repository cache matches the prior 544-entry fingerprint.
  No distdirs are selected, and downloads remain disabled. The old primary cache
  and distdirs were removed by other concurrent cleanup.

The normal AMD64 build-bsd profile bazel-lld-ctf-fresh-amd64-r1-20261103 passes.
Its strict CTF test actually executes, checking machine 62 / ET_REL, 112
associations, fourteen named-type checks and the exact required exports across
full/runtime outputs. Its BEP record and declared JSON are retained in the
corresponding review directory. Its compact action/tool-input review remains
INCOMPLETE: the old upstream converter and all 189 bound files were also removed.
The compact log is retained for exact-version converter restoration, not replaced
by an incomplete decoder or inferred action records.

Native source-built LLD qualification now runs through the same frontend:

- bazel-lld-ctf-native-linker-r1-20261103 builds LLD and its selected LLVM/source
  dependencies successfully; the 138-case section test passes. The symbol test
  fails at runtime because the Python runner's inherited library search path
  exposes the SDK compiler's older libprivatellvm.so.21 ahead of LLD's source-
  built library. Identical SONAMEs do not establish compatible implementations.
- The fixture compiler now receives its declared clang_runtime file group via
  normal Bazel test argument expansion. Only compiler subprocesses receive those
  library directories. LLD subprocesses remove inherited LD_LIBRARY_PATH and
  LD_PRELOAD and use their declared binary RUNPATHs. No fixture result or CTF
  assertion changes; the section test applies the same child-environment hygiene.
- r2 passes both tests with actual execution: 138 section cases and ten symbol/
  thunk/reference cases. r3 streams runtime hashes rather than reading entire
  libraries and re-executes the ten cases; its unchanged section test is cached
  from r2. Both executed records, declared JSON, compiler runtime hashes and
  child command environments are retained in
  bazel-lld-ctf-native-linker-review-r1-20261103.

This qualifies the selected source-built linker tests. Compact action-input
review, install/debug/package variants, LLVM/bootstrap breadth and full system
acceptance remain open. The first full native run reports 8,179 action-cache
hits and 4,236 processes; its wall time is about 1,119 seconds. This is not a fair
Make performance comparison: backend/runtime/configuration scopes differ, and
the time report wraps a client of a persistent server rather than aggregating
compiler/server memory and I/O. Do not use its client RSS as build memory usage.

The exact Bazel 9.3.1 distribution is retained locally. Maintained ports checksum,
extract and patch targets prepared a new converter source tree at
bazel-execlog-rebuild-r1-20261103, with distfile SHA-256 checked against current
ports distinfo and unchanged port inputs. Converter compilation and validation
are next. Preparation is not converter qualification.

Frontend assessment: format-5 explicit inputs, existing SDK planner/materializer,
and the normal build-bsd bazel-test command select all work. The test BUILD
arguments and scripts change together; no C frontend/schema, signing, staging
policy, packaging or publication change is required. The uncompressed CTF
footprint gate above remains open. Make stays production/default; BIP is excluded.
No running-system installation, upgrade, module loading or reboot occurred.
