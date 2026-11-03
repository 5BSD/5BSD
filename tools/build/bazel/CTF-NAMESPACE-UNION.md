# Standalone CTF namespace union foundation

## Why this exists

The module pipeline performs a multi-input relocatable link, then the maintained
ctfmerge, export localization and a final shared link. Fixing the final linker
must also account for the first link: concatenating independent CTF dictionaries
does not produce one valid namespace. The normal ctfmerge reads its explicit
original object inputs, uses the intermediate ELF symbol table, and replaces
that intermediate CTF. A valid disjoint union fits this pipeline without a new
flag, omitted metadata or name-based matching.

LLVM Object CTFSymbolTable::merge now provides that union. It is **not yet
connected to LLD**. Final ARM64/RISC-V module link failures remain open.

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

LLD must retain exact defining-file/index provenance through symbol resolution,
COMMON conversion, version aliases, wrapping, discarded sections and final
symtab sorting. Optional CTF-specific side tables can avoid enlarging every
linker symbol. The merger must be connected with correct script/section
placement, sizes and sh_link handling. Qualify real multi-input initial links,
maintained ctfmerge/export steps and final links against independent refreshed
original controls on AMD64/ARM64/RISC-V. Do not infer origins from names or final
addresses, and do not reconstruct origins from already redirected symbol arrays.

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
