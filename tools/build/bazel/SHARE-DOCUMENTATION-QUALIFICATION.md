# Configured shared documentation parent (2026-11-05)

## Native implementation

The source-owned share/doc parent now composes the book and original legal
notices, with IPv6, compiler and test-document owners selected by inet6, clang
and tests respectively. Missing plain-file leaves have native BUILD.bazel
inventories, original installed names, modes, package tags and explicit owned
directories. The book reuses its existing native inventory guard: missing or
unlisted docs/book/src files reject the build. Original Make's check-book-list
also runs in the independent reference build.

Compiler notices retain the actual clang package for both LLVM and Clang owners.
ATF's four documents retain atf; IPv6/pjdfstest and the five selected firmware
licenses retain utilities. Original source text is unchanged. Direct source
exports expose the required notices without copying an SDK or prebuilt fixture.
The legal parent follows its actual five selected source children; it does not
invent installation of the unselected imx sibling. Historical roff families are
also not selected by the maintained parent/default _roffdocs value. Their native
coverage is not claimed by this configured-parent checkpoint.

## Complete independent original comparisons

| Profile | Archives | Unique records | Exact files | Unique directories |
| --- | ---: | ---: | ---: | ---: |
| Normal: compiler/IPv6, no test docs | 9 | 104 | 90 | 14 |
| Alternate: test docs, no compiler/IPv6 | 8 | 104 | 91 | 13 |

Both complete configured original Make subtrees pass exact installed inventories,
owner/group, numeric modes, package tags, payload bytes and archive serialization
checks. Every tar entry must be either an explicit record or required ancestor;
extra entries fail. Numeric accounts, modes and epoch zero are checked.

The five legal owners each explicitly install the same legal directory. The
original METALOG has five identical claims, as do the native components. The audit
reconciles only identical directory records and requires equal repetition counts
on both sides (four repeated claims after the first); non-directory duplicates
or unequal metadata remain failures. Thus each profile has 108 raw original
record claims and 104 unique records. The initial audit assumption of globally
unique original paths rejected these legitimate directory repetitions; inspection
proved their exact identity before reconciliation was added. The rejected audit
is not passing evidence and no file/path exception was added.

## Evidence under /usr/obj/usr/src

- bazel-share-doc-parent-native-r1-20261105 and
  bazel-share-doc-parent-make-r1-20261105: maintained build-bsd construction and
  independent original Make subtree build/stage with sixteen jobs; tests disabled.
- bazel-share-doc-parent-original-review-r2-20261105/review.json: complete normal
  comparison, including original source-hash rechecks, archive/request bindings
  and exact duplicate-directory reconciliation. Audit source retained. The r1
  audit stopped on repeated legal-directory metadata and remains rejected.
- bazel-share-doc-parent-options-native-r1-20261105 and
  bazel-share-doc-parent-options-make-r1-20261105: actual tests=yes, clang=no,
  inet6=no profile. bazel-share-doc-parent-options-original-review-r1-20261105/
  review.json retains its complete independent comparison and audit source.
- bazel-share-doc-parent-namespace-r1-20261105/review.json: cross-capture file
  ownership reconciliation with prior production/data/manual captures: 1144 unique
  archives, 27913 non-directory paths and zero conflicting file claims. This
  checks file claims, not complete cross-package directory ownership or a new
  combined world build.

Both native profiles pass the selected source-settings test. Selecting ATF and
pjdfstest documentation does not execute those suites.

## Frontend and remaining gates

The maintained format-5 frontend already accepts the parent targets and selected
settings. Its manual describes the documentation selections; no dispatcher,
input-schema, staging/signing or publication change is required. No tracked
Python implementation, application or instrumentation source changes are part
of this checkpoint. No host installation, upgrade, publication or reboot occurred.

Examples, zoneinfo and complete locale/encoding composition, other remaining world
roots, full installed tests/Make/pkgbase parity, cross architectures/configurations,
independent reproducible bootstrap/output-query closure, kernel/module installation,
hardware/publication, runtime/VM and comparative CPU/RAM/disk I/O/footprint/cache/
sandbox gates remain open. Unselected historical roff documentation and imx legal
selection still require explicit coverage/board-policy review. Make stays
production/default; BIP stays excluded.
