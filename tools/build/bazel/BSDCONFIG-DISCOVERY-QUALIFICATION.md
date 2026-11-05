# Bsdconfig and library/administration test roots

## Implemented candidate (2026-11-05)

The source-owned `usr.sbin/bsdconfig/BUILD.bazel` declares all 42 original Make
owners, including 158 script/data/manual payloads when examples are enabled.
Literal source/destination maps preserve the numbered libexec layout, shared
helpers, standard modes and bsdconfig package ownership. `includes.sh` installs
as `includes`, as in the original script-name rule. Examples follow the existing
native examples setting. There is no build-time Make parser, install glob,
source rewrite or substituted program.

`lib/tests` and `usr.sbin/tests` now install the original source-owned generic
Kyuafile and their package-owned suite directories. This Kyuafile discovers
installed child directories; no child list is invented. Only the two new packages
receive additional source visibility. The declarations register discovery roots;
they do not establish that every child is migrated or every test has run.

The maintained format-5 frontend already accepts these archive labels. No C
selector/schema, SDK, security policy, stage/signing or publication change is
needed. Make remains default; BIP remains excluded. No host install occurred.

## Performed checks

All evidence below is under `/usr/obj/usr/src/`:

- `bazel-bsdconfig-make-r1-20261105`: original production reference passes,
  201 logical component records, including 158 payloads and 43 directories.
- `bazel-lib-test-root-make-r1-20261105` and
  `bazel-usr-sbin-test-root-make-r1-20261105`: original references pass with
  TESTS explicitly enabled; each has its directory and exact source Kyuafile.
- `bazel-bsdconfig-analysis-r1-20261105/metadata-review/review.json`: the initial
  actual configured analysis compares all 42 owners and 201 metadata records.
- `bazel-admin-discovery-analysis-r1-20261105/metadata-review/review.json`:
  actual cquery of the three archive dependency closures selects all 44 expected
  manifests. Every one of the 205 records matches original type, path, owner,
  group, mode and package tags. All 159 source payloads match original installed
  bytes. Source/analysis/reference bindings and the audit program are retained.
  The generated compressed manual remains explicitly pending native production.

Cquery performs analysis with zero build actions; this is configured ownership
and source-payload parity, not successful native archive construction. The
standalone read-only query uses the verified SDK module and a separate heap-bound
batch process, without starting another compilation frontend.

## Remaining qualification

The maintained native request is retained in
`bazel-library-admin-composition-request-r1-20261105/inputs.json`. It combines
these owners with GEOM, LLVM/Clang, ATF, Googletest, fwget and periodic composition,
and source/reference helper tests. Its request.json records the exact command
and the requirement to wait for the running aggregate frontend to finish. It is
prepared, not a launched or queued job.

Native archive construction and comparison of all tar headers, payloads and the
generated manual remain required. Alternate examples/manual-package profiles,
installed Kyua traversal and bsdconfig functional scenarios remain open. These
results do not prove a full installed world, pkgbase, VM runtime, bootstrap,
publication, verified boot or performance.
