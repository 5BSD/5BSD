# Library production installation archive prerequisites

## Scope

Seven existing production manifests now have production_install_archive targets
under their owning packages. These are production contributions, not complete
selected installed-test hierarchies or package families. In particular, libmd's
existing testonly component_archive and component_package_layout remain separate.
No implementation C, compiler flags, Make recipes or shared archive primitive
changes. The libarchive contribution includes its two original debug ancestors;
the other manifests already declare their required component directories.

| Owner | Declared records | Regular files | Hardlinks |
| --- | ---: | ---: | ---: |
| lib/libarchive | 261 | 43 | 215 |
| lib/libexpat | 8 | 6 | 0 |
| lib/liblzma | 22 | 19 | 0 |
| lib/libmd | 127 | 23 | 102 |
| lib/libz | 11 | 8 | 1 |
| lib/libzstd | 8 | 5 | 0 |
| lib/libc_nonshared | 1 | 1 | 0 |

Counts describe archive payload/metadata, not converted programs or whole-system
coverage. Symlinks/directories account for the remaining declared records.

## Evidence (2026-11-04, under /usr/obj/usr/src)

- bazel-library-production-archives-native-r1-20261104/receipt.json passes normal
  maintained build-bsd bazel-test, format 5, 16 jobs, all seven contributions.
  Five existing runtime tests execute: libarchive static/shared roundtrip, expat
  shared parser, zlib shared example and zstd shared roundtrip. Source settings
  passes from cache. No new narrow mirrored-implementation tests were added.
- Its production-review/review.json binds all seven request/tar captures to the
  passed receipt/manifest. All 438 records map to actual tar types/modes and
  ownership, symlink targets are checked, hardlink targets exist, all names are
  canonical/unique and no /usr/tests content is selected. Across 429 non-directory
  members there are zero duplicate paths. Common parent directories may repeat.
- bazel-library-production-nonshared-make-r1-20261104/receipt.json passes a fresh
  original Make build/stage. Its single logical install record agrees with the
  new production contribution. Static archive member order and all twelve raw
  allocated object/data/relocation contracts match. Full archive/debug byte
  equality is not claimed. This fresh comparison covers libc_nonshared only;
  it does not refresh independent Make parity for the other six libraries.
- bazel-lib-family-plan-r1-20261104/components.json records actual selected Make
  SUBDIR configuration and input hashes. Excluding .WAIT, it selects 173 immediate
  entries, including recursion wrappers, internal libraries and tests. The
  production review retains its hash; no runtime Make query defines Bazel inputs.

The normal frontend supports these targets through existing explicit selection;
C/backend schema requires no change. The maintained manual is updated.

## Remaining work

Complete source-owned lib parent composition and missing installation producers,
then full world/test/configuration/architecture and pkgbase composition. The
production-only names do not waive original installed tests. Earlier bounded
three-architecture libmd/XZ/zlib/zstd/bsdxml evidence does not establish all seven
new archives on foreign ABIs. No full bootstrap/publication/VM/performance result
is claimed. Make remains production/default and BIP stays excluded.
