# Native world directory layout qualification (2026-11-06)

## Source-derived layout

The first complete-package VM attempt failed before installation because /dev
was missing. Payload ancestor directories do not constitute distrib-dirs. The
fixture was not patched to create that path. The maintained world backend now
consumes typed source etc/mtree specifications, including conditional TESTS and
SENDMAIL selections, and emits an actual directory archive plus directory
ownership metadata. All physical source directories are retained independently
of whether their package owner is selected. Unselected ownership claims are
reported, not reassigned to an arbitrary package.

The same configured package suffix list drives layout, inventory and pkg creation.
Equivalent literal/suffix owner spellings coalesce; conflicting physical metadata
and unsupported object types fail. Sticky modes and explicitly selected source
immutable flags are preserved. Existing default directory validation still rejects
flags unless its caller explicitly enables that support. This carries ordinary
source /var/empty flags; it does not restore BIP or provide immutable-base policy.

Original Make distrib-dirs also exposed two omitted NLS_ALIASES symlinks. They
are now declared in etc/distribution.bzl under the NLS option, using the original
source table, ownership, modes and package tags. No fixture-only substitute exists.

## Verified evidence

All paths below are relative to /usr/obj/usr/src. The selected default AMD64
profile has TESTS disabled, TESTS_SUPPORT enabled and SENDMAIL enabled.

- bazel-world-pkg-layout-native-r4-20261106/receipt.json passes all eleven test
  targets and produces all 445 selected packages from 1,281 source archives.
  SHA256 c3db19c1711a403dff49604a2d25286ba040aaf7afee6a0eb7078d1c1080ded5
- bazel-world-directory-layout-review-r2-20261106/review.json compares actual
  native archive records and policy with original Make distrib-dirs METALOG:
  exact 904 physical directory definitions, 454 unique ownership claims and six
  ordered source specifications. The original Make list has 457 raw claims.
  SHA256 39ff51ba82e2987d9de222ea2a76b1ea1e63017d4d01ce446e3f7e1a1730731e
- bazel-world-nls-alias-review-r1-20261106/review.json compares both complete
  alias records with original Make and proves both absent with NLS disabled.
  SHA256 7db3cd4940c252d5567be8490704df9ae9c676194b1b5840da404cd33b2c7309
- bazel-world-pkg-layout-inspection-r1-20261106/review.json independently reads
  all 445 actual package archives against all native source archives: 32,512
  packaged paths, contents, ownership, modes, flags, links and package-local
  inode equivalence pass. Thirteen source hardlink groups span package boundaries;
  separate package archives do not promise shared inodes across those boundaries.
  SHA256 5fe8c2b373895012ddf3c9afdecc8aa17d534b3b3af4608bf404d013f4299e49

Additional qualification passes:

- bazel-world-layout-make-reference-r1-20261106/review.json reruns all 177 selected
  original Make package families over the complete same native stage. All 445
  complete package manifests match, with zero differing fields. This is packaging
  parity on a shared native corpus, not independently Make-built payload bytes.
  SHA256 8cbcd7ed2e5b3547f3c3761071d6df4a358f6fbb582993ea0bebe607d0b9ace2
- bazel-world-layout-tests-on-native-r1-20261106/receipt.json passes the bounded
  TESTS-enabled layout target and its native test. Its independent option review
  checks both source test prefixes and roots, 2,497 physical directories, 2,048
  ownership claims and zero unselected claims. It does not compare a complete
  independent Make TESTS-enabled world.
  Review: bazel-world-layout-tests-on-review-r1-20261106/review.json
  SHA256 98d98cf66e30311370b5d6bc6b3b22b559f3927edf95ae9a6640701c97604d9a

Failed layout iterations (leading-zero sticky mode, unresolved dev suffix) and
the initial VM failure remain in their object-root qualification directories.
No assertion was weakened to accept those failures. The first VM also failed an
unchanged service deadline assertion under host load; the retry passes that
baseline assertion unchanged. Its complete package installation is still pending.

## Frontend and limits

The existing format-5 frontend selects these native targets and tests. Normal
world package construction automatically includes the layout archive; no C CLI,
new publication repository or production Make default changes are needed. The
manual and backend are updated together. Source selection belongs in source
Bazel declarations, not a host-installed package database or a hand-picked image.

This proves the selected source directory layout, not an independently Make-built
whole world or a usable installed OS. independent TESTS-enabled Make layout parity/custom layout selections,
actual package install,
new-version upgrades, normal startup/services, native kernel/module acceptance,
ARM64/RISC-V and bootstrap/cache/sandbox/reproducibility/performance gates remain.
