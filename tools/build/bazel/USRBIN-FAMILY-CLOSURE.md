# usr.bin family composition prerequisites (2026-11-04)

The complete-world review queue's remaining production directories without local
BUILD files mostly have real parent-owned producers (iconv/OpenSSL modules,
Switchboard NSS and EFI Lua) or are Make recursion wrappers. This is not proof
that their installed contents or the whole world are complete. The larger next
gap is explicit family composition: usr.bin and its LLVM subtree have no native
family aggregate yet. Do not use recursive //... patterns or BUILD-file counts
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

Next: construct source-owned usr.bin/LLVM family aggregates with maintained
Make option selection, explicit nested/test contributions and coverage checks.
The root family has not yet been built or qualified. Its metadata query and
unconfigured declaration query cannot establish installed-world coverage.
Other world/library/data/rescue/kernel/module/bootstrap/pkgbase/hardware and
runtime/VM/CPU/memory/disk gates remain open. The existing format-5 build-bsd path
already builds these archives and tests; no C dispatch change is needed and its
manual is updated. Make remains production/default; BIP remains excluded.
