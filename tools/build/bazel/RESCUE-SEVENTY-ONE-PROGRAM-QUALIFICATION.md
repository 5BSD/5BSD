# Native seventy-one-application rescue construction

## Source declarations and options (2026-11-05)

The selected AMD64 core adds xz, zstd, less, route, rtsol and mount_msdosfs.
It constructs 71 of 103 default rescue applications. Xz/zstd/less/rtsol now share
one explicit source inventory between their ordinary and rescue variants.
`bazel-rescue-71-ordinary-declarations-review-r1-20261105/review.json` proves all
existing declarations in all six owners exactly match committed source after
reversing only source-list sharing and removing new rescue declarations. This is
declaration equivalence, not fresh ordinary installed-world/runtime acceptance.

Less retains its original WARNS=1 through an explicit profile in the rescue
macro; existing levels 2/3/6 stay unchanged. Xz retains its configuration/header
inputs and HAVE_CONFIG_H. Zstd retains original threading/namespace definitions.
Rtsol omits Casper under the original RESCUE condition. No libraries or source
features are dropped to obtain a static link.

Route reuses the maintained declared AWK keyword producer and selects IPv4/IPv6,
Netlink source/object lists and WITHOUT_NETLINK as configured; it omits JAIL under
RESCUE. Core crunchgen metadata selects the same three/two route objects. The
separate full default catalog explicitly guards its default Netlink setting rather
than silently producing stale metadata. Full rescue configuration coverage beyond
these selected profiles remains open.

## Native runtime and original Make evidence

All retained evidence is under `/usr/obj/usr/src/`.

- `bazel-rescue-71-native-r2-20261105`: maintained frontend, sixteen jobs,
  construction and both wrappers pass. Runtime executes 84 actual methods;
  source-settings executes its separate 28 methods. Cases include xz/zstd
  round trips requesting two workers and bounded job/block sizes, original
  compression aliases, nonterminal less/more private-file behavior and usage
  rejection before network/mount mutation. These are functional tests, not
  worker-count observations, thread stress or comparative resource benchmarks.
- Native r1 builds and links, then fails one test because it requested an
  unsupported Zstd --jobsize spelling. Maintained source documents -B for job
  size. Only the test argument changes, preserving -T2 and the bounded job size.
  The failed qualification remains rejected, not relabeled as passed.
- `bazel-rescue-71-without-netlink-native-r1-20261105`: full selected native core
  and the same 84 runtime methods pass with netlink_support=false.
  `bazel-rescue-71-netlink-selection-review-r1-20261105/review.json` binds both
  artifact sets, verifies actual route object names are three/two, verifies the
  exact crunchgen descriptor change and unchanged generated main, and binds the
  actual false-setting commands. This does not establish independent Make legacy
  route binary parity or successful network administration.
- `bazel-rescue-pager-network-more-make-r1-20261105/report.json`: fresh actual
  six original generated `_make` targets, sixteen workers, isolated object roots.
  4998 source/policy/header/tool inputs are bound before/after, including complete
  original source directories. Eighty-one C objects and their actual compiler
  recipes/consumed dependencies are recorded; no new direct DTrace provider is
  declared by these six application recipes.
- `bazel-rescue-71-action-review-r1-20261105/review.json`: all 81 actual successful
  compiler actions from the failed-test r1 build match original warning/define
  vectors and optimization/C17/debug/SSP/non-PIE policies. Their raw object hashes
  independently match the passing r2 immutable captures before acceptance. The
  failed build itself remains failed. Copied raw objects/dependency files are
  bound to the original execution records; all 409 upstream converter/runtime
  bindings are checked before/after. Cached actions are not invented executions.
- `bazel-rescue-71-object-review-r1-20261105/review.json`: all 81 raw C contracts
  are compared. Seventy-four match allocated bytes, nondebug symbolic relocations
  and external symbols directly; seven Zstd objects retain assertion-filename
  string/relocation differences. `bazel-rescue-71-filename-controls-r1-20261105/`
  `review.json` verifies each with an isolated original compiler command plus
  explicit macro-prefix mapping, using up to sixteen workers. Native flags/bytes
  and original baseline objects remain unchanged. This explains diagnostic paths,
  not complete raw baseline or independent DWARF equality.
- `bazel-rescue-71-route-generator-review-r1-20261105/review.json`: native declared
  AWK header bytes exactly match the fresh original generated keywords.h consumed
  by the selected route objects, with original recipe metadata and both source
  inputs bound. This does not qualify all generator/bootstrap modes.
- `bazel-rescue-71-pipeline-review-r1-20261105/review.json`: fresh original
  crunchgen/generated Make on identical captured native application, archive and
  startup inputs match main C and all 144 whole-byte outputs: main object,
  71 stubs, 71 combined ld-r/crunchide objects and the executable. Static AMD64
  ELF, no interpreter/dynamic segment, nonexecutable stack and GNU_RELRO checks
  pass. This is pipeline behavior on identical inputs, not an independent full
  library/world reconstruction.

## Dependency evidence and retained difference

`bazel-rescue-71-dependency-review-r4-20261105/review.json` explicitly reports
**passed-with-differences**, not literal header byte parity. Across 81 actual
compiler closures, all 5535 consumed occurrences are present in declared executed
input digest inventories. Those digests are compared with independent retained
original payload hashes. All basename/byte multisets and multiplicities match
apart from one curses.h occurrence with an exact, separately proven comment-only
provenance difference. Full logical-path namespace and incremental invalidation
acceptance are still separate gates.

`bazel-rescue-71-ncurses-provenance-r1-20261105/review.json` runs unchanged
MKkey_defs.sh on identical bound Caps/Caps-ncurses bytes with absolute and relative
argument paths. It reproduces both entire key-definition fragments. Only the
known comment line describing those actual arguments differs; every other header
byte and line count agrees. Both raw headers/fragments are retained and remain
byte-different. No production code, generated header or binary is rewritten.

The earlier strict audit attempts are retained as rejected: r1 finds this actual
raw header difference; r2 rejects a dependency spelling with programs/../lib
although its canonical declared path names the same source; r3 attempts to read
an ephemeral execution-root SDK link after a configuration switch. R4 uses the
hash-bound actual execution inventory, independently retained payloads and the
captured provenance pair. Parent-directory spelling is accepted only after a
bounded relative-path check and filesystem-identity proof against its canonical
repository source. No basename search substitutes for a missing declaration.
Mutable execroot links do not provide retained input-content evidence.

## Integration and remaining gates

Existing maintained format-5 inputs support these targets/options. The frontend
manual, completion plan and observability ledger are updated. No C dispatcher,
settings schema, signing, installation or publication helper changes are required.
Make stays production/default and BIP stays excluded. No host installation,
upgrade or reboot occurred.

Finish the remaining 32 default applications and actual rescue library variants,
complete configuration/cross/installation/aliases/helper paths, independent
library/debug/metadata/pkgbase comparisons and mounted/privileged VM cases.
Retain the header provenance difference in full installed-output qualification;
do not promote it to literal byte equality. Complete world/kernel/modules,
bootstrap, hardware/combined publication, runtime and CPU/memory/disk/cache/
sandbox gates remain open. Ordinary gzip's existing SDK DTrace/drti path remains
an identified generator audit item before complete source-build acceptance.
