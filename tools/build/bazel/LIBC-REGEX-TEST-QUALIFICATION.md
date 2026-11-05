# Native libc regex construction and original cases (2026-11-05)

## Implementation

The libc regex suite now builds all three original C programs: h_regex,
exhaust_test and regex_att_test. Native libc supplies regular-expression behavior;
standalone libregex is not substituted. Private helper headers are declared.
The ATF programs retain REGEX_SPENCER/SKIP_LEFTASSOC and NetBSD compatibility;
libutil belongs only to regex_att_test. ABI imports and the existing link sequence
preserve original ATF/util/libc dependency order. No original C or shell source
was changed.

WARNS=3 now has an explicit shared libc-test policy, preserving the original
level-three warnings and low-level Clang suppressions. A direct comparison of the
previous and current policy functions confirms byte-for-byte identical flag lists
for existing WARNS=2/4 consumers. Existing unsupported-policy rejection remains.

Both original ATF shell scripts retain the standard atf-sh wrapper. Installation
includes the original README, nineteen .in files and seven AT&T .dat fixtures,
using the original basename flattening of data/att into data. Original Kyua and
split debug complete thirty-six non-directory records. Suite/data/debug directory
attributes also match the original staged system.

All thirty original cases are represented: the exhaustion case, seven AT&T cases,
nineteen regex shell cases and three multibyte shell cases. Original shell cases
execute each helper input in the three original modes; redundant helper-only
wrappers were removed after original shell execution passed. All native runtime
libraries and shell tools are declared, including ATF's dirname dependency,
libc++/libcxxrt/libgcc_s/math and native C.UTF-8 LC_CTYPE. The ATF runner supplies
private PATH, ATF_SHELL, library and locale paths. Multibyte cleanup is retained.

## Evidence

All evidence directories below are under /usr/obj/usr/src:

- bazel-libc-regex-native-r5-20261105: maintained frontend passes 31 targets:
  thirty original cases and source settings. The case reports distinguish thirty
  passes (including source settings) from one original expected failure, leftassoc.
  Thus twenty-nine original cases pass; the expected failure is not claimed fixed.
  Earlier r2 freshly ran exhaustion; r4 freshly ran original shell cases; final r5
  reuses successful cached tests. It does not claim thirty fresh executions in r5.
- bazel-libc-regex-review-r3-20261105: hash-bound immutable r5 installation capture
  matches all thirty-six original file records, ownership/modes/package/debug tags,
  exact scripts/README/fixture/Kyua bytes and physical suite/data/debug directories.
  Three distinct original program ELF metadata, ordered dependency, dynamic symbol/
  version and hardening comparisons pass. All three native and Make debug filename/
  CRC checks pass. Original source and tool/input hashes are checked and retained.
  The program inventory is queried from original Make and deduplicated across
  ATF_TESTS_C/PROGS; it is not a manually asserted program count.
- bazel-libc-installation-make-r1-20261105 supplies the original complete libc
  component stage/METALOG/receipt. It uses an existing prepared SDK and does not
  establish a new independent whole-world bootstrap.

Retained failures explain the corrections: r1 runtime passed but independent ELF
review found util after libc in NEEDED order. r2 corrects the final-consumer link
order and passes exhaustion. r3 shell tests fail because dirname was absent from
the declared PATH; r4 adds the actual dependency rather than a host PATH fallback.
An intermediate diagnostic repeated two program comparisons because Make lists
ATF programs in PROGS too; final review deduplicates the queried inventory and
reports three distinct programs. Failure directories remain available.

## Scope and maintained workflow

Existing explicit-input targets/tests, typed installation providers and frontend
artifact captures suffice. build-bsd.c, its input schema, backend selection and
signing/publication helpers require no change. The manual and completion/audit
ledgers record this contribution. Full-tests parent guards stay active.

This is selected AMD64 leaf installation/interface and original-case evidence.
It does not prove raw ELF/debug equality, complete installed test traversal,
other ABI/configuration behavior, hermetic whole-system bootstrap, live DTrace/
audit delivery, privileged installed-image behavior or performance acceptance.
Make remains production/default. BIP remains outside the goal.
