# libxo production parent composition (2026-11-05)

## Source ownership and selection

Original lib/libxo/Makefile selects libxo, then encoder after .WAIT, and tests
when MK_TESTS=yes. encoder/Makefile selects csv. The new source-owned Bazel
parents explicitly compose both original production contributions. Nested typed
bsd_install_archive_set providers preserve archive, request and directory-metadata
output groups. The encoder already depends on native libxo through its compile
and shared-link graph; no shell ordering or recursive Make evaluation is added.
The library archive grants visibility only to its legitimate parent package.

production_installation_archives is explicitly production coverage, even in a
configuration with tests enabled. installation_archives accepts tests disabled;
it rejects tests enabled because the original functional suite, eleven drivers,
saved outputs and encoder test hierarchy are not yet completely migrated.
The existing three native runtime tests are useful checks, not a replacement for
that original hierarchy. Both parents remain limited to the qualified AMD64 ABI.

## Evidence under /usr/obj/usr/src

- bazel-libxo-family-native-r1-20261105 retains the first failed parent analysis:
  the existing library archive was private. Parent-only visibility fixes this.
- bazel-libxo-family-native-r2-20261105 passes the maintained build-bsd format-5
  frontend at sixteen jobs. Static formatting, shared formatting and the CSV
  runtime wrapper actually execute; source_settings_test is cached. The CSV
  wrapper contains five methods covering quote escaping, header suppression,
  DOS newlines, invalid options and declared native loader dependencies.
- bazel-libxo-library-make-r1-20261105 and
  bazel-libxo-family-csv-make-r1-20261105 independently build and install the two
  original Make production children with sixteen jobs, metadata capture and an
  explicit WITHOUT_TESTS selection. No Bazel payload is supplied to Make.
- The native r2 composition-review/review.json and retained audit-source.py bind
  immutable captured artifacts to the original receipts/METALOGs. All ninety
  library and six encoder records match original types, owners, groups, modes
  and package tags. All eighty-five header/manual payloads match byte for byte;
  all fifty-six manual aliases retain original hardlink identity and targets.
  The symlink target agrees. There are no duplicate non-directory payloads and
  exactly six parent outputs: two archives and their request/directory metadata.
- Both installed DSOs pass the strict shared ELF comparison: SONAME, ordered
  dependencies, imports/exports and versions, hardening and section contents.
  The sole differing section in each installed DSO is .gnu_debuglink. Both
  original/native separate-debug names and CRCs validate. This does not establish
  debug-byte equality, full calling-convention ABI or every original compiler
  warning/configuration policy. The default installed code/data comparison is
  stronger than merely observing successful link completion.
- bazel-libxo-family-no-tests-native-r1-20261105 passes installation_archives
  with tests disabled, retaining byte-identical copies of both production tars.
  Its three selected runtime tests execute and pass; source settings is cached.
- bazel-libxo-family-reject-tests-native-r1-20261105 records the expected explicit
  incompatible-target rejection for the same full installation target with tests
  enabled. It is negative configuration evidence, not a successful build receipt.

## Frontend and remaining scope

The existing generic format-5 targets/settings route builds both new parent
labels; no new C dispatcher, backend format, signing, trust, staging or publication
input is required. The maintained manual documents the supported scope. No host
installation, root privilege, source C changes, path rewrites or runtime test
substitutions were introduced. A component archive is not a pkgbase repository.

Original installed test coverage, installed default encoder lookup, structured
syslog delivery/failure behavior, nondefault profiles, other ABIs and full world/
pkgbase/bootstrap/cache/sandbox/VM/resource qualification remain open. Earlier
single-encoder implementation evidence is in LIBXO-CSV-QUALIFICATION.md. Make
stays default; BIP remains excluded.
