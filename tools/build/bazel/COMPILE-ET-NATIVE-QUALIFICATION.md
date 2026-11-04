# compile_et original consumer qualification

## Maintained reference dependencies

The existing format-1 library input schema retains archive as its default kind.
An optional kind=shared declares an original target ELF64 dynamic library, with
matching receipt architecture/compiler and bound file hashes. Explicit named
searches resolve the first actual .so/.a candidate; a shadow library cannot
witness the requested artifact. Symlinks in search directories must resolve to
the bound original object-tree library. A shared object cannot substitute for an
archive binding, or vice versa. Response/mode ambiguity still fails closed.

An optional include_directories list names relative directories within that
original reference's stage. Its component.METALOG must match the passed receipt;
every include file must match installed metadata. The complete directory
inventory and hashes are rechecked around commands; added files are rejected.
Compiler dependency files must actually consume the bound directory. Include
symlinks and paths outside the stage are rejected. This composes original
library/header dependencies without copying into or changing the recorded SDK.
Make CFLAGS_LAST and LDFLAGS_LAST carry explicit includes/search directories,
preserving preexisting values. The previous CFLAGS_EARLY knob was ineffective and
has been removed. Arguments are passed as structured assignments through the
existing single shell boundary, without nested quoting of flag values.

## Native correction and parent edge

The independent original comparison found native compile_et directly recording
libcrypt.so.5, although the original consumer requires only libroken.so.11 and
libc.so.7. Removing the extra direct dynamic_deps entry fixes this dependency
boundary; roken retains its own required crypt dependency. Existing native
version and generation tests pass again with declared native runtime libraries.
The usr.bin parent now selects compile_et under its original Heimdal condition.
The full Heimdal profile remains explicitly incompatible pending its remaining
dependencies; adding the edge does not establish a built parent profile.

## Evidence (2026-11-04, all under /usr/obj/usr/src)

- bazel-compile-et-make-r5-20261104/receipt.json: original build/stage passes,
  explicit WITHOUT_MITKRB5, original roken shared object and vers PIE archive,
  original roken staged headers. Both libraries occur in actual completed link
  recipes; compiler dependency records consume the bound original include stage.
- bazel-compile-et-shared-reference-native-r4-20261104/receipt.json: corrected
  native consumer/component archive and six selected test targets pass. The new
  link causes version and generation cases to execute again; other tests may
  reuse cached results. Library input regressions cover 22 unittest methods,
  including shared target identity/type, shadows, header metadata/payload,
  directory additions and actual compiler dependency requirements.
- bazel-compile-et-object-capture-r1-20261104/capture.json: three actual compiler
  contexts and the lexer/parser actions are captured from the earlier successful
  native build, with output and primary-source hashes checked. These are reused
  compiler witnesses, not fresh compilations in the final build.
- bazel-compile-et-parity-r2-20261104/final-link-binding.json binds all three
  captured object hashes to the corrected current actual link and captured
  executable. All three raw allocated code/data, symbolic relocation and external
  symbol contracts match original compile_et/parse/lex PIE objects.
- In that parity directory, review.json compares all five logical component
  records, manual gzip bytes and both installed executable/debug CRC pairs.
  elf.json compares identity, PIE/interpreter, hardening, imported/exported symbols,
  symbol versions and ordered runtime libraries. Its compared sections differ
  only in seven DWARF sections; full linked/debug bytes are not claimed equal.
  Native/original parser headers are byte-exact. Retained lexer/parser C diffs
  contain only #line filenames with the same line numbers; raw sources are kept.
- Both actual generators execute all eleven .et inputs named by maintained
  kerberos5/Makefile.inc, in separate private directories. Each uses its own roken;
  other runtime DSOs come from the explicit recorded Make SDK, with hashes
  checked before/after. All 22 C/H outputs match byte for byte. This is distinct
  from the Bazel runtime tests using native roken/crypt/md/libc/libsys.
  A private byte-verified executable copy is used for the captured native payload;
  its immutable content store permissions are preserved.
- bazel-compile-et-final-gates-r1-20261104/review.json: configured checks retain
  explicit full Heimdal and full installed-test incompatibility, no compilation.

Initial reference attempts rejected missing headers, the ineffective include hook,
nested flag quoting and missing public-library search path. These are failed
attempts, not qualification. The new shared-search regression also caught and
corrected an archive-only name extraction. Failed logs/output roots remain.

## Remaining scope

Complete other Heimdal libraries/programs and full parent profiles; full installed
tests, alternate configurations/architectures, complete world/pkgbase/bootstrap,
VM/services, cache/sandbox and CPU/memory/disk performance qualification. The Make
comparison uses a previously built SDK and does not prove bootstrap independence.
The maintained frontend uses its existing explicit targets; its C/backend schema
needs no change. Manual/reference schema/roadmap are updated. Make remains the
production default; BIP remains excluded.
