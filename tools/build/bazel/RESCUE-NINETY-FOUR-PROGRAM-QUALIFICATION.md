# Native ninety-four-application rescue construction

## Source-owned variants and header ownership (2026-11-05)

Sh, csh and vi bring the selected AMD64 core to 94 of 103 default applications.
Ordinary/rescue pairs share exact source inventories, including the existing
native shell generators. Sh retains SHELL, csh retains original WARNS=1,
/rescue/csh and NO_NLS_CATALOGS definitions, and vi retains original WARNS=0,
private regex and wide-character definitions without ordinary iconv flags. The
rescue macro adds an explicit original WARNS=0 profile; existing profiles stay
unchanged. Native ncurses joins lazy archives at its original selected position.

The dependency review found a real ownership gap: public_headers exposed native
curses.h but omitted ncurses.h, allowing vi to mix that native header with an SDK
alias. Make already declares the alias in INCSLINKS and the native installation
manifest already preserves it. The compilation view now also exposes a declared
Skylib copy_file alias with allow_symlink=True, depending directly on the native
curses producer. No SDK header is copied as a replacement and no source include
is rewritten. Rebuilding consumers and checking actual dependency paths verifies
the fixed ownership boundary; full-world consumer qualification remains separate.

## Retained evidence

All directories below reside under `/usr/obj/usr/src/`.

- `bazel-rescue-94-native-r3-20261105`: maintained format-5 frontend, sixteen
  jobs; 99 runtime methods and separate 28 source-settings methods pass after
  the alias fix. New cases exercise sh builtins/expansion/arithmetic/functions,
  private redirection/pipelines, csh arrays/arithmetic and both command/file input
  modes, and vi/ex private batch substitution/append/undo. PATH is empty for
  these cases; private HOME/recovery/temp locations are supplied as appropriate.
  Interactive terminal behavior and installed helper paths are not qualified.
- Native r1 built but failed the csh -c loop expectation. Passing r2 corrected
  only that test and qualified the original header view; it does not establish
  the later alias fix. R3 is the final passing construction. All earlier evidence
  remains retained with its actual scope.
- `bazel-rescue-94-original-csh-runtime-r2-20261105`: a fresh isolated original
  Make build with explicit original CRUNCH_BUILDOPTS verifies rescue definitions
  in compiler metadata. Its -c input emits one loop iteration; the same private
  script file emits both. The maintained test checks both behaviors. The first
  runtime-control driver omitted those build options and linked new ordinary PIE
  objects; its corrected scope explicitly says ordinary-only. All 196 original
  rescue reference object hashes were checked unchanged. No production source
  change masks the failed expectation or the control-driver error.
- `bazel-rescue-shells-editor-make-r1-20261105/report.json`: fresh actual original
  generated Make child builds produce 196 C objects (sh 30, csh 52, vi 114), with
  5857 source/policy/tool/header bindings checked before/after. These three recipes
  declare no new direct rescue provider object.
- `bazel-rescue-94-ordinary-declarations-review-r1-20261105`: all three original
  ordinary declarations are structurally unchanged after expanding shared source
  expressions and removing the rescue declarations. This is declaration
  equivalence, not fresh ordinary installed-world/runtime acceptance.
- `bazel-rescue-94-action-review-r2-20261105`: 166 fresh compiler actions after
  the alias fix and 30 retained successful sh actions from rejected r1 collectively
  match all 196 original warning/define/optimization/C17/debug/SSP/non-PIE policies.
  Selected actions executed through processwrapper-sandbox, with no cache hits
  invented as executions. Raw objects/dependencies bind to recorded output
  digests; all 409 converter/runtime bindings are checked before/after.
  `bazel-rescue-94-passing-action-binding-r2-20261105` binds every selected raw
  object hash to the immutable passing r3 captures. Rejected r1 remains rejected.
- `bazel-rescue-94-generator-review-r2-20261105`: all eleven declared sh/csh
  generated C/header outputs match actual independent original generated payloads
  byte-for-byte, including the grouped shell headers and csh constants/host data.
  This does not establish cross-architecture bootstrap or incremental behavior.
- `bazel-rescue-94-object-review-r2-20261105`: 190 of 196 C contracts agree
  directly in allocated bytes/nondebug symbolic relocations/external symbols.
  Five csh objects and vi log.o retain diagnostic filename strings/relocations.
  `bazel-rescue-94-filename-controls-r2-20261105` reproduces all six contracts
  using isolated original compiler commands plus explicit macro-prefix mapping,
  without changing native flags/objects or original baselines. Full independent
  DWARF/raw debug identity remains open.
- `bazel-rescue-94-pipeline-review-r2-20261105`: fresh original crunchgen and
  generated Make on identical captured application/archive/startup inputs match
  main C and all 190 whole-byte outputs: main object, 94 stubs, 94 combined objects
  and complete ELF. Static AMD64/no INTERP or DYNAMIC/NX stack/RELRO checks pass.
  This is identical-input pipeline parity, not independent full-library/world
  reconstruction or full rescue installed-system acceptance.

## Dependencies, aliases and retained differences

`bazel-rescue-94-dependency-strict-r1-20261105` retains the rejected strict result
that exposed the mixed SDK/native alias view. The fixed alias control,
`bazel-rescue-94-curses-alias-review-r1-20261105`, binds identical native curses.h/
ncurses.h payloads and verifies the original installed alias resolves to the same
original curses.h. Both exact header hashes match immutable saved headers from
`bazel-rescue-71-ncurses-provenance-r1-20261105`; its generator/script/Caps bindings
remain unchanged. That prior full-fragment replay proves exactly one generated
comment-line difference with all other bytes and line counts equal. No old mutable
execroot is used as retained header-content evidence.

`bazel-rescue-94-dependency-review-r3-20261105` explicitly reports
**passed-with-differences**. All 17295 consumed occurrences are declared and checked
against recorded executed input digests and independent original payload hashes.
Eleven consumed header occurrences retain that exact comment difference. Five
ncurses.h uses have an explicit original/native alias identity proof; paths and
multiplicity remain recorded. Every consumed curses.h/ncurses.h in this selected
set belongs to the native public view; SDK fallback is rejected.

A conservative audit also rejected valid virtual-header bltin/../ spellings
(`bazel-rescue-94-dependency-parent-rejection-r1-20261105`). The final review
accounts for twelve such occurrences only after bounded relative-path checks,
filesystem same-file proof and repository-header ownership. Both spellings' bytes
must match the recorded declared-input digest; source bytes/identity are rechecked.
These current identity witnesses are not substitutes for historical execution
content. Full logical namespace and incremental invalidation acceptance remain
separate gates; no dependency is dropped or found by basename search.

## Integration and remaining work

The maintained format-5 target/settings API supports these declarations and the
alias capture. Manual, completion plan and observability ledger are updated;
no frontend C/schema/staging/signing/publication-helper change is required. These
are unsigned development builds, not verified boot or compromised-root protection.
Make stays default; BIP excluded. No host installation/upgrade/reboot occurred.
Processwrapper execution is not complete sandbox or performance qualification.

Csh preserves Make's NO_NLS_CATALOGS definition, but no consumer was found in the
bundled tcsh/configuration sources, while config.h enables NLS_CATALOGS. These
tests do not prove catalog loading disabled. Diagnose that existing policy and
qualify real catalog behavior before claiming it; no behavioral fix is hidden in
this migration.

Nine default applications remain: camcontrol, geom, ifconfig, pfctl, bectl, zfs,
zfsbootcfg, zpool and zdb. Finish those plus actual rescue library overrides,
configuration/cross/full installation/aliases/helper paths and independent library/
debug/header/pkgbase acceptance. Full world/kernel refresh, bootstrap, separate
hardware/combined publication, real boot/login/network/storage VM checks and
CPU/memory/disk/cache/sandbox gates remain open. Earlier generated-source/header
provenance and host-crypto configuration-cost findings remain recorded.
