# usr.bin family composition prerequisites (2026-11-04)

The complete-world review queue's remaining production directories without local
BUILD files mostly have real parent-owned producers (iconv/OpenSSL modules,
Switchboard NSS and EFI Lua) or are Make recursion wrappers. This is not proof
that their installed contents or the whole world are complete. The larger next
gap is explicit family composition: usr.bin still lacks its full aggregate;
the LLVM family declaration is now under qualification. Do not use recursive //... patterns or BUILD-file counts
as an installed-world definition.

A fresh maintained component-plan query records 243 selected usr.bin entries.
The LLVM subtree has 18 SUBDIR tokens: 17 directories and one .WAIT barrier.
An unconfigured offline Bazel query loads 337 archive declarations beneath
usr.bin, including optional and test declarations. These counts have different
scopes and are not programs, built products or completion percentages.

## Closed prerequisites

Six already native programs had installation manifests but no component archive:
bzip2recover, gzip, xz, xzdec, lzmainfo and zstd. Each now has install_archive using
its existing manifest and the maintained account/mtree/archive helpers. World
family composition can consume these contributions without pulling entire
compression packages and accidentally including their library payloads. Package
composition and pkgbase creation remain separate. Epoch zero follows the current
component archive convention; no publication version is silently supplied.

The six actual archive actions were audited against immutable requests and their
logged payload digests. All 56 file/link records, including 29 hardlinks, have
exact payload bytes, inventory, permissions and ownership. Existing package tags,
manuals, aliases and debug-directory records are preserved. This is serialization
of existing component policy, not a new per-program Make compiler/stage audit.
Both existing bzip2 package-contract and recovery tests executed and passed.
The package test requires an explicit version; 16.0.qual.20261104 is a declared
unsigned qualification input, not a production release or publication.

The broad query also found bc_tests/dc_tests rule names colliding with their
output file names. Their producer rules now have copy_ prefixes, with installed
script names and Kyuafile entries preserved. The actual archive is built and
checked against original script bytes, 0555 mode and test names. All six earlier
archive/request/directory outputs remain exact in that final passing run.

## Evidence under /usr/obj/usr/src

- bazel-usrbin-family-plan-r1-20261104
- bazel-usrbin-archive-query-r3-20261104
- bazel-usrbin-compression-archives-r2-20261104 (actual initial test executions)
- bazel-usrbin-compression-archives-r3-20261104 (final passing products)
- bazel-usrbin-compression-archives-review-r2-20261104

The first analysis rejected the missing version input; it was not defaulted in
production code. An initial audit misparsed absolute Bazel labels; only that
label parser was corrected. Failed attempts remain retained.

Next: finish native LLVM family qualification and construct the source-owned
usr.bin aggregate with maintained option selection, explicit nested/test
contributions and coverage checks. The usr.bin root has not been built or qualified. Its metadata query and
unconfigured declaration query cannot establish installed-world coverage.
Other world/library/data/rescue/kernel/module/bootstrap/pkgbase/hardware and
runtime/VM/CPU/memory/disk gates remain open. The existing format-5 build-bsd path
already builds these archives and tests; no C dispatch change is needed and its
manual is updated. Make remains production/default; BIP remains excluded.

## LLVM family composition in progress

The new normal installed-family declaration separates MK_CLANG selection from
MK_CLANG_FULL feature selection. Analysis initially failed on a duplicate LLDB
visibility keyword; the corrected declaration preserves the existing lib/clang
consumer and admits the family owner. The initial native 17-archive graph is still compiling. Its analyzed source
is retained separately because the revised family closes overlap with seven
archive contributions. No passing native aggregate or runtime qualification is
claimed yet.

Review found the existing toolchain alias manifest already contains ten utility
manifests to close manual hardlinks. The revised family consumes that closed
contribution once, with strict combined-manifest validation. Repeating leaf
archives and that alias archive would duplicate installed payloads. Optional
CLANG_EXTRAS remains unfinished, not silently omitted. The compiler-disabled
binutils-only profile also needs its llvm-cov/manual-link ownership resolved.

The usr.bin test root now declares Make's existing regress.m4 and generic
source Kyuafile. Its directory discovery remains unchanged. A fresh maintained
Make reference supplies the two-file, 0444 root/wheel inventory and 0755 tests
directory; native archive comparison is pending. These are family prerequisites,
not evidence of complete world/pkgbase or installed test execution.

## Configured LLVM ownership checkpoint

bazel-llvm-family-analysis-r1-20261104 under /usr/obj/usr/src records a separate
configured query of both targets. The archive set has seven distinct immediate
owners; the toolchain contribution owns ten utility manifests. Their union
accounts for all 17 selected Make directories without repeating those utility
owners. All 50 bound inputs of the original metadata query still match. Strict
combined-manifest analysis succeeds and materializes no actions. That proves
configured ownership and link/destination validation, not compiled payloads,
archives, installation parity, runtime or complete-world acceptance. CLANG_EXTRAS
and compiler-disabled binutils-only installation are explicitly incompatible.
The normal format-5 frontend supports these targets and settings unchanged.

## Full test inventory gap found during family review

The retained selected-profile owner queue accounts for 243 immediate roots, but
that mapping is a review input, not completed build coverage. A conservative
source scan finds 84 selected roots mentioning HAS_TESTS or MK_TESTS recursion;
36 have a tests directory without a local native BUILD. Local native test rules
can also cover only samples: awk declares four upstream cases and comm three
legacy cases, while their Make test hierarchies have additional installation
responsibilities. cmp/tests has no local native BUILD. Reconcile the complete
configured recursion and original installed test inventory before accepting the
family with tests enabled. Neither a BUILD-file count nor successful sampled
execution closes that gate.

Review queues: bazel-usrbin-family-owner-queue-r1-20261104 and corrected r2 under
/usr/obj/usr/src. The second queue resolves tftp's distinct production/test
archives and records these source candidates and limitations. The text scan is
not an exhaustive configured test inventory. The LLVM build and small test-root
qualification are serialized by the maintained backend state lock; an isolated
Bazel output identifier does not bypass that lock.
