# Native 103-application rescue qualification

## Source-owned variants (2026-11-05)

Bectl, zfsbootcfg, zfs, zpool and zdb complete the default 103-program source
selection in the bounded AMD64 rescue core. Ordinary and rescue declarations
share sources. Original ordinary compiler/link/install declarations remain
unchanged after expanding the shared source variables (five-owner AST review).
This is not yet the installed production rescue executable: actual librescue
helper overrides, complete option composition, cross builds, install/package
and independent full-library/debug/runtime/resource qualification remain open.

The original generated nested Make reference built all 14 C objects. Source-owned
native options retain the inherited cddl/Makefile.inc compatibility definitions;
bectl instead retains its own original definitions, without NEED_SOLARIS_BOOLEAN.
Zfs_main.c has its own native compilation group for -Wno-unused-variable. Zdb
retains the original iso9899:1999 language mode and debug definitions. Original
source include precedence is explicit; header payloads are declared inputs.
Bazel tokenization preserves literal quotes in zpool's two path definitions.

Original per-program ld-r archive order is retained in typed compiler metadata:
bectl/zfs/zpool use be, zpool, zfs, zutil, zfs_core, zfsbootenv, icp_rescue, nvpair;
zdb additionally uses zdb; zfsbootcfg starts with zfsbootenv and omits be. These
archives are extracted before crunchide, not appended to the final common link.
The common list adds avl, pthread, umem, spl and rt in original order. The existing
native icp_rescue target remains distinct from normal ICP.

## Evidence

All evidence below is under /usr/obj/usr/src, not a home installation repository.

- bazel-rescue-zfs-family-make-r1-20261105/report.json: fresh original nested
  application builds, 14 objects, source/header/compiler inputs hash-bound.
- bazel-rescue-103-native-r4-20261105/receipt.json: maintained frontend, 16 jobs,
  107 runtime methods and 28 source-settings methods pass. Earlier r1 retains
  the quoted-path compilation failure; r2 the stale catalog expectation; r3
  the bectl help capitalization assertion. No baseline or failure is removed.
- bazel-rescue-103-action-review-r3-20261105/review.json: all 14 executed
  compiler policies match original warnings/definitions/language/optimization/
  SSP/debug/no-PIE policy. The passing run reused cached actions. Earlier r2
  then r1 execution records bind by exact object hash to final immutable passing
  captures. Initial review r1 found no new execution records in the cached run;
  review r2 stopped on the old macro command in r1, despite that object's bytes
  being unaffected. Final review uses the latest successful execution per object.
- bazel-rescue-103-dependency-review-r1-20261105/review.json: 2219 consumed
  dependency occurrences declared and independently matched to original Make by
  basename, exact bytes and multiplicity. No generated-source exception needed.
- bazel-rescue-103-metadata-review-r1-20261105/review.json: all 103 typed ordered
  object lists and all seven per-program archive lists match fresh original Make.
- bazel-rescue-103-object-review-r1-20261105/review.json: seven new objects
  match the allocated ELF/symbol/relocation contract directly; seven retain
  diagnostic path string differences. Raw bytes and differences remain recorded.
- bazel-rescue-103-filename-controls-r1-20261105/review.json: all seven
  diagnostic differences accounted for by independently replaying the original
  compiler recipes with explicit macro-prefix mapping. Original and native
  baseline objects are unchanged. This is not raw debug information identity.
- bazel-rescue-103-pipeline-review-r1-20261105/review.json: original crunchgen
  and generated Make reproduce 208 entire outputs (103 entry stubs, 103 combined
  program objects, dispatcher object, final executable) on identical captured
  native objects, archives and startup files. Static ELF has no interpreter or
  dynamic segment, a nonexecutable stack and RELRO. This is pipeline equivalence,
  not an independent complete-library or complete-system build.
- bazel-rescue-103-declaration-review-r1-20261105/review.json: existing named
  ordinary build and installation declarations unchanged for all five owners.

New host runtime cases exercise bectl -h, zfs/zpool --help, invalid zdb option,
and zfsbootcfg with two operands. Source review establishes these branches exit
before pool discovery or boot-environment access. They prove dispatch and safe
CLI behavior, not successful storage or boot-environment operations. Those need
private VM pools/disks and normal boot/recovery qualification.

## Frontend and remaining work

These variants use existing format-5 targets, settings and the maintained
build-bsd bazel-test action. No input schema, C frontend, signing/staging or
publication policy changes are required. The manual and completion plan record
this increment. Make remains the production/default backend. This qualification
is unsigned development work, not publication, verified boot or BIP.

Next: wire and qualify actual librescue helper overrides and full rescue
configuration/install semantics; then finish every full-system gate in
COMPLETION-PLAN.md. ARM64/RISC-V, independent world/debug/header/pkgbase parity,
current kernel/modules, bootstrap reproducibility, normal boot/services, hardware
publication and CPU/memory/disk/cache/sandbox gates are still required.

## Direct recovery helper integration (2026-11-05)

The follow-up now includes //rescue/librescue:regular_compiler_outputs directly
in rescue_core, after the crunched application objects and before ordinary
archive searching. No archive wrapper, lazy extraction or fallback to ordinary
libc replacements is used. These seven existing rescue variants preserve
/rescue helper/shell/search-path definitions and original no-SSP compilation.

- bazel-rescue-overrides-make-r2-20261105/report.json: fresh original regular
  helper build with explicit MK_NIS=yes, matching the native request's existing
  nis=true setting. All seven allocated ELF, external-symbol and nondebug
  symbolic-relocation contracts match in
  bazel-rescue-overrides-object-review-r2-20261105/review.json.
- bazel-rescue-overrides-native-r2-20261105/receipt.json: maintained frontend,
  16 jobs, all 107 runtime plus 28 source-setting methods pass with the overrides.
- bazel-rescue-overrides-pipeline-review-r2-20261105/review.json: original
  Make link with the same seven captured helper objects in its original LIBS
  position reproduces all 208 complete output bytes, including the final ELF.

Earlier evidence remains: Make reference r1 used selected-world NIS=no and
exposed a real getusershell configuration difference; native r1 put direct helper
objects earlier among source inputs and failed complete ELF comparison despite
passing runtime tests. The final reference explicitly matches configuration and
the final declaration matches original object order. Neither mismatch was
normalized or ignored. The prior helper compiler rules were unchanged.

This closes the missing direct-helper composition gap. It does not establish
installed /rescue links, successful system/popen/exec shell recovery in a guest,
NSS/credentials behavior, full option/cross/debug parity or resource performance.
Those remain qualification gates. No host installation or reboot occurred.
