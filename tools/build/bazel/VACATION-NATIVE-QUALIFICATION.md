# Native vacation and original internal archive binding (2026-11-04)

The AMD64 vacation target now compiles the maintained Sendmail source with the
original NEWDB/NOT_SENDMAIL/_FFR_LISTDB/_FFR_DEBUG definitions and PIE policy.
It reuses libsm's generated sm_os.h/header interface and native smdb/smutil/sm
PIE archives. The shared source package exports only the program and manual to
this consumer. Standard utility helpers retain the utilities package, original
manual, stripped program, debug file and explicit debug directories. SENDMAIL
selects its production contribution; disabled SENDMAIL excludes it and makes
the program incompatible. No C source or library generation recipe is replaced.
Custom SENDMAIL_CFLAGS/LDADD/LDFLAGS environments and foreign architectures still
need explicit declaration/qualification; this result is the maintained default.

## Original-reference correction

The first original reference correctly failed its link audit: LIBSM/LIBSMDB/
LIBSMUTIL overrides changed prerequisites, while Make still linked its existing
object-tree libraries through LIB<name>DIR-derived -L/-l operands. The reference
was not accepted as a comparison. The maintained comparison helper now binds
an existing corresponding directory variable to the explicit passed archive's
parent, checks that override, and verifies completed original metadata.

The archive resolver accepts direct operands or ordinary explicit -L/-l search.
For a named archive the first matching library in the recorded search order
must resolve to that exact hash-bound archive. An earlier archive/shared library,
a preferred .so, missing explicit search path, response-file/mode ambiguity or
unsupported alternate search syntax cannot witness it. This is not a fallback
to SDK/default libraries. Compiler/architecture/receipt/path checks remain intact.
Four new unit methods exercise named selection, shadows, unsupported modes and
missing paths. The full maintained libraries test has fifteen methods; the
existing option tests also pass through native Bazel. No production Make rules,
SDK, normal build-bsd argument schema or publication policy changes.

## Evidence under /usr/obj/usr/src

- bazel-vacation-native-r1-20261104: normal 16-job build-bsd format-5 passes the
  program archive and rmail archive. The safe missing-login case executes and
  returns EX_USAGE with empty stdout/stderr before opening a vacation database
  or sending a reply; the original syslog usage message remains source behavior.
  Source settings is cached. No mailbox/database or user account is changed.
- bazel-vacation-library-make-batch-r1-20261104 and individual libsmdb/libsmutil/
  libsm Make references: fresh original internal builds and private references
  pass, with original regular/PIE archives. Library archives are bound by receipt,
  artifact hash, target and original compiler identity.
- bazel-vacation-original-inputs-r1-20261104: explicit three-library input JSON
  and 130 program/include/src hashes frozen before the original consumer build.
- bazel-vacation-make-r{1,2}-20261104: rejected old-search-path run and passing
  corrected original build/stage. The passed metadata proves all three named
  original PIE archives resolve to their explicitly bound locations.
- bazel-vacation-review-r2-20261104: the original/native consumer object allocated/
  symbolic relocation contracts are exact. All three installed files and two
  explicit directories match Make's inventory, types, modes, ownership, flags
  and package tags. The compressed manual is byte-identical. Generated native
  sm_os.h aliases and the original Make symlink read the same source bytes.
  Actual native compiler/link/archive actions and immutable captures are bound;
  both independent debug-link CRCs pass. The rejected first inspection assumed
  a single generated-header path, overlooking its virtual alias.
- Its library-object-inspection.json reconciles all 87 source member identities:
  5 smdb and 6 smutil contracts are exact; 38 of 76 sm contracts are exact in the
  ordinary raw baseline. The other 38 include source-root filename strings.
  Raw objects, original archives and the differing linked images are retained.
- bazel-vacation-filename-control-r2-20261104: all 76 original libsm compiler
  recipes are rerun with only private output/dependency destinations and explicit
  -fmacro-prefix-map=<actual-source-root>/= added. All 76 contracts match native
  objects. Source/dependency/tool hashes are frozen/rechecked and sixteen workers
  are used. The original ar order/recipe and original program link then consume
  that controlled original archive. Every allocated section's bytes/metadata,
  entry point and all program headers match the native image. Original entry and
  other archive inputs remain unchanged. This is a declared compiler filename
  policy comparison, not ordinary raw Make equality or binary normalization.
  The initial control parser rejected empty metadata command records; the final
  parser ignores only empty records and requires each actual compiler recipe.
- bazel-vacation-production-native-r1-20261104: the complete SENDMAIL-enabled
  production parent passes with 268 archives and four selected tests. The two
  reference-helper tests execute; usage and source settings reuse cached results.
- bazel-vacation-production-review-r1-20261104: exactly vacation's three products
  are added; all 801 previous default archive/request/directory outputs remain
  byte-identical and non-directory destinations are collision-free.

## Remaining scope

Whole separate debug/DWARF byte parity and source lookup are not established by
valid CRCs. Mail delivery/reply, database initialization/listing/expiry and other
vacation modes require isolated functional scenarios; safe usage does not qualify
them. Complete installed tests, alternate profiles/architectures, world/pkgbase,
bootstrap, hardware/publication, mutation/cache/sandbox and controlled CPU/memory/
disk-I/O/resource gates remain open. Make stays production/default; BIP excluded.
No host installation, upgrade, module loading, publication, reboot or VM occurs.

The maintained generic build-bsd format-5 path already carries these targets and
settings. Its manual, completion plan, family closure and observability ledger
are updated; no one-off replacement production workflow is introduced.
