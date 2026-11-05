# Capsicum helper production and protobuf parent composition

## Source-owned contributions

lib/libcapsicum now declares its original public header, compressed manual and
thirteen manual hardlinks as a production_install_archive contribution. It
retains original utilities/dev and configured manual tags. Existing header code,
Make recipes and test assertions are unchanged.

lib/libcapsicum/tests now builds both original NO_SHARED C/C++ ATF programs and
runs every original case: C narrow_stream, narrow_commands, ordinary_and_empty;
C++ narrow_commands. The standard maintained ATF runner supplies isolation and
Bazel results. No new source skip, relaxed assertion, generated expected success
or test-specific runtime implementation is introduced. Original tests use named
common rights where the source already accommodates older host rights ABIs.
These are execution targets; original installed test metadata remains separate.

lib/protobuf now has explicit build_libraries and production_installation_archives
parent targets. Four Make child owners build: protobuf-lite/protobuf private
libraries, internal libprotoc and internal upb. The build target requests the
four regular archives, both internal PIE archives and two actual shared libraries.
Only three installation contributions exist: protobuf-lite, protobuf and upb.
upb's internal status suppresses library installation but retains its two original
utilities licence files. libprotoc has no installed payload. No fake installed
archive or package is introduced for either internal library. Typed archive-set
metadata groups stay on the separate production target.

## Evidence (2026-11-04/05 UTC, under /usr/obj/usr/src)

- bazel-capsicum-protobuf-native-r1-20261105: preliminary parent/library build
  passes through normal format-5 build-bsd, 16 jobs. The preliminary all rule
  triggered Bazel's wildcard/name ambiguity warning; the final rule uses the
  unambiguous build_libraries name.
- bazel-capsicum-production-make-r1-20261105/receipt.json: fresh original Make
  production reference passes with installed TESTS explicitly disabled for this
  separate production comparison. All test source remains unchanged.
- bazel-capsicum-protobuf-native-r2-20261105/receipt.json: final parent and Capsicum
  contributions build. All four original ATF cases execute and pass; the selected
  source-settings test passes from cache. Both test binaries retain static linking.
- Its composition-review/review.json binds captured request/tar contents to the
  passed receipt/manifest. All fifteen Capsicum metadata records match original
  Make; actual bytes and all thirteen hardlink inode relationships match stage.
  The protobuf parent exposes exactly the three expected tar/request/directory
  triplets, all four original build owners and eight library outputs. Internal
  archive paths are absent from installed payloads; upb's payload is exactly its
  two licence files. No non-directory path collisions occur across the three
  installation archives, and no installed tests are silently mixed into them.

The protobuf implementation code is unchanged; this assembly result does not
refresh independent Make object/debug/ABI parity for its existing child libraries.
The Capsicum runtime tests use the declared static ATF/C++/SDK closure and the
current host kernel; they do not establish a complete native-world bootstrap.
The maintained frontend/backend already supports these explicit targets. Its C
schema needs no change; the manual and library-family ledger are updated.

## Remaining scope

Original installed Capsicum test metadata/parity, additional options/ABIs,
remaining source-owned library parents and producers, full world/pkgbase,
bootstrap/publication, VM/services, sandbox/cache and CPU/memory/disk performance.
Make stays default; BIP remains excluded.
