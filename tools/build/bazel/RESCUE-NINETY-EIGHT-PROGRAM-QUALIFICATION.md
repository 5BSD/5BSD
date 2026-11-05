# Native ninety-eight-application rescue construction

## Source-owned variants (2026-11-05)

Camcontrol, geom, ifconfig and pfctl bring the selected AMD64 core to 98 of 103
default applications. Existing ordinary/rescue sources are shared. Geom embeds
original label/part classes under STATIC_GEOM_CLASSES; its original default empty
GEOM_CLASS_DIR definition is retained in that static variant, whose loader branch
is compiled out. Ordinary dynamic class-directory configuration remains unchanged.
PF retains its forced compatibility header, parser and exact WARNS=2/NO_WFORMAT/
source warning policy. Camcontrol retains original non-PIE rescue compilation.

Ifconfig uses separate native cc_library compilation for ifpf.c with its original
source-specific options. Ordered declared sources determine object order across
those groups, preserving constructor registration order. IPv4/IPv6, wireless, USB,
PF and Netlink selections remain source-owned. Rescue omits ordinary JAIL.
Source-owned full compiler_options preserve the extra ordered warning vectors for
ifconfig/PF; other rescue callers retain their existing WARNS profiles.

## Native metadata and per-program linking

The native core no longer maintains a separate parent object table with manual
route/ping configuration cases. BSDComponentObjectsInfo carries ordered own
compiler artifacts, original object names and ordered program archive inputs.
Selection accepts explicit names or declared ordered sources and compilation
groups; it rejects unknown/missing/ambiguous outputs. It never discovers files or
parses Make during production construction.

BSDDTraceObjectsInfo records exact input-artifact to rewritten-artifact mappings.
Provider-bearing rescue outputs retain source order and original names through
that map; names are not inferred by stripping arbitrary filename suffixes. Earlier
rescue extractors also expose typed metadata; their compiler and DTrace recipes
are preserved. Crunchgen consumes the selected typed object/name lists, and the
same ordered objects/archives feed native relocatable linking. It records library
paths in its incidental metadata but does not execute that Makefile.

Camcontrol's nvmf/nv archives and ifconfig's nv archive are extracted in their own
partial links, matching original CRUNCH_LIBS_<program>, before crunchide hides
symbols. They are not silently moved to the final common library list. Native
80211/cam/ifconfig archives occupy original selected common-link positions.

## Retained independent and native evidence

All directories below reside under `/usr/obj/usr/src/`.

- `bazel-rescue-98-native-r3-20261105`: maintained format-5 frontend, sixteen
  jobs; 102 runtime methods and separate 28 source-settings methods pass. New
  cases reject invalid storage/network-control requests and parse/round-trip/reject
  private PF rules. PF uses no-action mode and an explicit nonexistent private
  device path, which remains absent; no host firewall state is changed.
  Successful device operations, interface changes and kernel PF behavior are
  separate VM gates.
- Native r1 failed analysis because early extraction targets lacked the mandatory
  typed provider. Their metadata forwarding was completed, without an untyped
  filename fallback. R2 then exposed missing helper imports in several legacy
  owners. Those imports were fixed; both rejected runs remain retained. R3 is
  the final passing default construction.
- `bazel-rescue-storage-network-pf-make-r1-20261105/report.json`: fresh actual
  original generated child Make builds produce 56 C objects, no new direct
  provider object, and bind 5799 original source/policy/tool/header inputs before
  and after construction.
- `bazel-rescue-98-declaration-review-r1-20261105`: across fourteen edited program
  owners, existing named compilation/DTrace/installation/configuration declarations
  agree after expanding exact shared source expressions and comparing associative
  concatenation with element order preserved. Intentionally replaced extraction
  wrappers are excluded explicitly; new source-specific compilation is qualified
  independently. This does not establish fresh whole ordinary-world acceptance.
- `bazel-rescue-98-action-review-r1-20261105`: all 56 actual successful compiler
  policies match original warnings/defines/optimization/C17/debug/SSP/non-PIE
  recipes, including the separate ifpf group. Raw objects/dependency files bind
  to execution digests; 409 converter/runtime bindings are checked before/after.
- `bazel-rescue-98-metadata-review-r2-20261105`: all 98 emitted ordered object
  descriptors agree with fresh original generated Make, including ifconfig's
  constructor order. Both program archive lists/order agree and bind to captured
  native artifacts. Audit r1 incorrectly requested an empty artifact selection
  for programs with no special archive; that driver failure remains recorded and
  r2 handles the empty case without manufacturing an artifact or changing data.
- `bazel-rescue-98-object-review-r1-20261105`: 50 C contracts agree directly in
  allocated bytes/nondebug symbolic relocations/external symbols. Six retain
  diagnostic filename differences. `bazel-rescue-98-filename-controls-r1-20261105`
  independently reproduces those contracts using original compiler commands plus
  explicit macro-prefix mapping, without changing native flags/objects or baseline
  objects. Full independent DWARF/raw debug identity remains open.
- `bazel-rescue-98-pipeline-review-r1-20261105`: original crunchgen/generated Make
  on identical captured application/archive/startup inputs match main C and all
  198 whole-byte outputs: main object, 98 stubs, 98 partial/crunchide objects and
  executable. Program-specific archives remain in their original partial stages;
  this also checks constructor layout. Static AMD64/no INTERP or DYNAMIC/NX stack/
  RELRO checks pass. This is identical-input pipeline parity, not independent
  full-library/world reconstruction.

## Dependencies and generated parser difference

`bazel-rescue-98-dependency-strict-r1-20261105` retains a rejected literal-byte
comparison for PF parse.c. `bazel-rescue-98-generator-controls-r1-20261105` binds
original yacc/source inputs and exactly reproduces both complete original and
native parser outputs using their respective source/output spellings. The raw
files remain different; no source bytes are normalized or substituted.

`bazel-rescue-98-dependency-review-r2-20261105` explicitly reports
**passed-with-differences**: all 4844 consumed occurrences are declared in the
executed input inventories and independently match original payload hashes by
name/bytes/multiplicity except that one exact generated C occurrence. The
exception requires the successful full producer controls. Relative parent spellings
still require bounded checks and source identity. Full logical namespace and
incremental invalidation acceptance remain separate gates.

## Netlink-disabled qualification

`bazel-rescue-98-without-netlink-native-r1-20261105` passes the same 102 runtime
methods and 28 source-settings methods with target netlink_support=false.
`bazel-rescue-98-without-netlink-make-metadata-r1-20261105` separately generates
original metadata with MK_NETLINK_SUPPORT=no in a fresh object root.
`bazel-rescue-98-without-netlink-metadata-review-r1-20261105` verifies all 98 ordered
descriptors and both archive lists against that original inventory: route selects
two objects; ifconfig selects 23, excluding its three Netlink-specific sources.
No manual parent list is edited for that configuration. This does not establish
independent alternate-profile compiler/library parity, successful network
administration or exhaustive configuration coverage.

## Integration and remaining gates

Existing maintained format-5 targets/settings support these changes and metadata
captures. The frontend manual, completion plan and observability ledger are updated;
no frontend C/schema/staging/signing/publication-helper changes are required.
These are unsigned development builds, not verified boot or compromised-root
protection. Make stays default; BIP excluded. No host installation/upgrade/reboot
occurred. Processwrapper execution is not complete sandbox or performance acceptance.

Five default applications remain: bectl, zfs, zfsbootcfg, zpool and zdb. Finish
those and actual rescue library overrides, complete configuration/cross/installation/
alias/helper-path coverage, independent library/debug/header/pkgbase comparisons,
world/kernel/modules refresh, bootstrap, separate hardware/combined publication,
boot/login/SSH/PAM/capability-service/mac_abac/openES VM cases and CPU/memory/disk/
cache/sandbox qualification. Earlier raw generated-header/source provenance,
csh catalog policy, iscsictl PCP warning and host-crypto configuration-cost
findings remain explicit.
