# Module CTF localization regression

`localization-audit.py` is an explicit-tool diagnostic, not a release gate or a
replacement build workflow. It compares two transformation orders against a
baseline whose data and function types must agree with the fixture C sources.
It exits nonzero when either transformation corrupts a type association. The
second transformation is a rejected alternative; fixing the first does not
require making fuzzy matching a supported module build path.

Required inputs are `--cc`, `--ld`, `--objcopy`, `--ctfconvert`, `--ctfmerge`,
`--ctfdump`, and a fresh `--work` directory. Repeat
`--ctf-library-directory` for explicitly selected CTF runtime libraries.
Use the maintained SDK compiler/linker/objcopy and Bazel-built CTF tools for
native qualification. An optional comparison against installed CTF tools must
be labeled separately. Outputs belong under `/usr/obj`.

The fixture retains exports before symbols being localized, forcing a change
in the relative order of function and data symbols. A second translation unit
contains static functions and data with the same names but different types.
The checker identifies fixture symbols by name, kind, section, offset, and size;
it rejects ambiguous identities. This limited diagnostic identity is not a
proposed production symbol-remapping algorithm. Type names, rather than CTF
numeric type IDs, determine correctness.

Retained evidence (2026-10-28):

- `/usr/obj/usr/src/ctf-localization-fixture-r2-20261028`: selected SDK tools
  with installed CTF tools.
- `/usr/obj/usr/src/ctf-localization-native-r2-20261028`: selected SDK tools with
  native Bazel-built CTF tools and explicit runtime library directories.
- Both baselines pass. Both transformation orders fail for data and functions.
  Each directory retains commands, tool hashes, objects, CTF dumps and JSON.

LLVM objcopy now retains input symbol identities and rewrites CTF object and
function records when their symbol associations change. It defers parsing for
unchanged copying/debug stripping and explicitly removed CTF. This preserves
opaque unsupported CTF for operations that do not require understanding it;
reordering unsupported CTF is rejected. Fuzzy name matching remains rejected.
The real `nullfs_artifacts_test` passes with the freshly rebuilt SDK.

Frontend assessment: rebuild the maintained bootstrap tools and generate a new
SDK/receipt through maintained helpers. Never replace a frozen SDK binary in
place. Existing format-5 frontend selection runs the real nullfs test; no new
build-bsd C option is required. Full module/runtime coverage is still open.

Use `--mode merge-then-localize` to test only the maintained module order.
The default `--mode all` also runs the rejected fuzzy-merge comparison.

## Format checks

`format-audit.py` takes explicit `--objcopy`, `--baseline` (the localization
audit's baseline.o), `--ctfdump`, `--ldd` and fresh `--work` paths. Optional
repeated `--objcopy-library-directory` and `--ctf-library-directory` inputs
select each tool's runtime. The report captures the objcopy dependency paths
and hashes. It covers both SUNW CTF versions, byte orders and compression
settings, with independent ctfdump checks for little-endian types. The ELF
container remains amd64: this is not cross-architecture qualification.

The maintained tool/library pass 61 checks at
`/usr/obj/usr/src/ctf-format-maintained-r3-20261028`. See the development
checkpoint for remaining SDK/Bazel integration and consumer-review work.

The fresh SDK passes this format suite at
`/usr/obj/usr/src/ctf-format-sdk-20261028` and the real Bazel nullfs test at
`/usr/obj/usr/src/bazel-nullfs-ctf-fixed-20261028`. The repeated frontend run
reuses its cached test result; see the checkpoint for exact evidence and scope.

Final selected-tool evidence: 65 format checks at
`/usr/obj/usr/src/ctf-format-lazy-20261028` and 34 real Bazel nullfs checks at
`/usr/obj/usr/src/bazel-nullfs-ctf-lazy-20261028`. The format-tested bootstrap
binary and the frozen SDK binary have the same SHA256.

`objcopy-benchmark.py` accepts explicit old/new tool paths, input, export-options
file, iterations and a fresh work directory. It alternates tool order and records
per-child wait4 CPU/RSS/block-I/O counters, elapsed time and file sizes/hashes.
An empty options file measures copying. These are warm-cache microbenchmarks;
block counts and immediate filesystem allocation reports do not establish
physical disk throughput or durable allocation.


The optional --semantic-reader PATH input selects an explicit ctf_semantics.py
for additional baseline and transformed-output parses; its hash is recorded.
This extends the audit from 65 to 129 checks while retaining independent
ctfdump controls. Function associations are packed, including v2 odd-argument
records; only the following type section is aligned. A proposed per-record
padding change fails independent ctfdump and was rejected. The corrected
semantic reader passes the expanded suite; the previous reader rejects valid
packed v2 records. See CTF-SEMANTIC-CHECK.md and the retained review at
/usr/obj/usr/src/bazel-ctf-packed-associations-review-r2-20261103. These checks
exercise an AMD64 container, not foreign execution or the final shared linker.


## Shared Object helper and header-only association changes (2026-11-03)

LLVM Object now owns CTFSymbolTable, with ObjCopy retaining ELF selection,
section-link and allocation checks and the opaque unchanged-order fast path.
The helper owns its header/body and stores offsets rather than views, preserving
record identities through moves/copies. It validates input/output IDs and
symbol types; new output identities use an explicit reserved sentinel. Neither
errors nor unchanged results modify the caller's output buffer. Labels, types
and strings remain opaque: this is not a type-namespace merger.

Review found another original ObjCopy defect: replacing an unknown object with
an unknown function can retain identical zero payload bytes while moving the
function-section boundary. The unchanged check now includes header offsets.
The format audit adds eight controls; all fail with the old selected tool and
pass with the new tool. With --semantic-reader, the suite now has 137 checks.
Without that option it has 73. The earlier 65/129-check evidence is historical.

api-audit.cpp is an explicit-library native C++ diagnostic, separate from the
normal Bazel Python suite. It exercises 160 checks over both versions, byte
orders and compression settings: ownership after moves/copies, unchanged
output on errors/false, duplicate/reserved/unknown identities, changed symbol
types, repeated new symbols, removing all associations, and header-only changes.
Compile it with the selected LLVM include directories and the newly built LLVM,
zlib and zstd libraries plus the platform execinfo/pthread dependencies. Exact
compiler/link inputs, command, source snapshots and results are retained at
/usr/obj/usr/src/bazel-ctf-shared-helper-review-r1-20261103/summary.json.
This diagnostic is not yet a native Bazel LLVM API test target.

Maintained Make source-owner targets built the ARM64-stage HOST bootstrap
library and objcopy using 16 jobs, without installation. This is an AMD64 host
tool, not ARM64 execution. The first extraction attempt failed compilation and
is retained; the corrected attempt and disk guard pass. Build records are at
/usr/obj/usr/src/bazel-ctf-shared-helper-build-r2-20261103; the staged tool remains
unchanged. Actual newly built objcopy passes 137 checks at
/usr/obj/usr/src/bazel-ctf-shared-helper-format-r1-20261103. No frozen SDK was
modified. Make and native Bazel Object inventories both include Object/CTF.cpp;
complete native Bazel LLVM/bootstrap qualification remains open.

Frontend assessment: normal bootstrap rebuilding selects the new source through
the maintained LLVM Makefile; SDK creation/verification remains through existing
helpers. No build-bsd option, config schema, stage-signing or publication change
is required. Fresh SDK and real module checks must follow linker correction.
Final LLD association/link preservation, multi-container type handling and local
libctf's inconsistent v2 reader remain open. No target runtime or comparative
CPU/memory/disk performance acceptance is claimed.


## Namespace union foundation

CTFSymbolTable now also has an explicit standalone namespace-union API. It is
separate from opaque single-container symbol rewriting and is not yet connected
to LLD. The native Bazel symbol_table_api_test and union_graph_test build Object
and Support from source; the latter uses declared fixtures, reader, ctfdump and
runtime libraries. See ../../CTF-NAMESPACE-UNION.md for supported contracts,
1,024-case Make/Bazel serialization parity, normal frontend tests and remaining
linker work. The earlier statement that the helper was not a namespace merger
refers to that earlier checkpoint; general parent/label merging and semantic
type deduplication are still not implemented.
