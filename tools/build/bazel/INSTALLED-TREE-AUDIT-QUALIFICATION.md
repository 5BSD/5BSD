# Installed baseline audit and ZFS image flags (2026-11-07)

## Scope and retained failure

The maintained normal runtime runner accepts a format-2 plan naming the captured
METALOG and an explicit audit deadline. It authenticates METALOG against the image
construction report, requires complete record/digest coverage, and creates a
read-only mtree specification for every declared object. Numeric ownership,
permissions, flags, types, symlink text and regular SHA-256 are checked. It omits
no configuration files or generated databases. Extra runtime files, timestamps
and hardlink inode identity are outside this baseline check.

`bazel-system-normal-boot-vm-r6-20261107` uses image R9, a fresh disk overlay,
2 GB/four vCPUs and the normal boot path. All earlier 12 startup/authentication
checks pass. The complete 35,351-object audit fails (mtree exit 2), and the owned
VM is stopped. This is not an accepted installed-tree or clean-shutdown result.
Its complete `installed.mtree`, `installed-audit.log`, image/tool/runner bindings,
resource observations and failed result remain under `/usr/obj/usr/src`.

The raw audit exposes:

* Added `uarch` on baseline objects, including all 13 objects declared `schg`.
  The latter have lost their immutable flag, not just gained bookkeeping state.
* Changed hashes of group, master.passwd, passwd, pwd.db and spwd.db after the
  fixture's actual guest pw provisioning. These need producer-specific semantic
  validation; they are not accepted through blanket configuration exclusions.
* The consumed `/firstboot` marker.
* A traversal warning for an extra runtime device. Final audit generation checks
  the metadata of every baseline-empty directory but prunes its extra children
  with `ignore`, derived from the full tree. It rejects missing/non-directory
  parents. No declared child may be pruned.

Source inspection also confirms mtree can print a missing-path or traversal
warning without setting a nonzero status. Final acceptance therefore requires
both exit zero and an empty diagnostic log. The R6 runner predates that stricter
check; its actual nonzero status already makes R6 a retained failure.

## Actual constructor defect and correction

`usr.sbin/makefs/zfs/fs.c` previously set ZFS_ARCHIVE on every constructed object
and never mapped FSINODE_ST_FLAGS into ZPL flags. The corrected constructor maps
all BSD flags represented by FreeBSD ZFS getattr/setattr (system immutable,
append, nounlink; archive, nodump, readonly, system, hidden, reparse, offline and
sparse). Unsupported input bits fail construction rather than being ignored.
Internal ACL/AV bookkeeping flags retain their existing meaning. No new runtime
MAC, BIP, mount or I/O enforcement is introduced.

`bazel-makefs-flags-native-r1-20261107/receipt.json` passes the actual native makefs
and standard makefs_zfs_tests wrapper build. A new maintained ATF `file_flags`
case constructs from an input mtree without host chflags, imports its image, and
requires exact flags including an explicit no-flags control. Its source-owned
Bazel runtime inventory includes the new case. **That import case has not run.**

`bazel-makefs-flags-inspection-r1-20261107/review.json` passes a smaller rootless
construction using the actual captured corrected binary and read-only host zdb
(no host import or mount). It checks actual root/plain pflags 0x40000000044 and
protected pflags 0x49000000044: only the latter has immutable/nodump, and none has
an invented archive bit. A separate opaque-flag input fails with status 1 and an
explicit unsupported-flags diagnostic. Host zdb, runtime libraries, tool/input
hashes and full logs are retained; this is not hermetic runtime/import proof.

The follow-up `all-flags/review.json` under the same inspection directory passes
all 11 supported flag inputs plus `none`, by checking each actual ZPL pflags field
through read-only zdb. The input mtree, full output and all commands are retained.
This broadens construction evidence; the imported-image ATF case remains unrun.

## Tests and frontend

`bazel-installed-audit-native-r1-20261107` passes the initial three-case coverage
regression through maintained build-bsd bazel-test. The final four-case coverage
regression (including empty-directory pruning and missing-parent rejection)
passes `bazel-installed-audit-native-r2-20261107/receipt.json`. The eight-case
source/runtime inventory regression also passes through the maintained frontend
in `bazel-makefs-inventory-native-r1-20261107`, including exact registration of
the new file_flags case. Existing format-5 targets/tests support both the image
and new audit test without a C option/backend switch. The runtime guide and
build-bsd manual describe the exact new input/scope. Normal construction already
uses the corrected native makefs dependency; no replacement build script is used.

## Corrected complete image R10

`bazel-system-image-native-r10-20261107/receipt.json` passes the complete image
and six selected native tests. Counts remain 447 packages, 33,982 nondirectory
records and 1,369 directories. Image SHA-256:
`c30da868db19c1f8b6aa6bc15fa4074a3bb3cea418f82dfff9f1bea0409b2e18`;
construction report SHA-256:
`4a83adf5d4603a93b128007a35506d430f578f4c7b852a7456ce60aa152df7e4`.
The complete METALOG is unchanged: this is correction of the constructor to honor
existing inputs. Independent review at `bazel-system-image-review-r10-20261107`
confirms identical regular-path membership and unchanged kernel payloads. The
only changed regular payloads are makefs/debug, the two build-bsd manual aliases
and the generated private pkg database.

Bazel reports 426.63 s and 89,082 action-cache hits; makefs observes 31.86 s and
31,576 KiB child max RSS, mkimg 23.57 s and 8,180 KiB. These observations include
ordinary cache/I/O variation and are not controlled comparative performance.
Fresh VM R7 uses the final audit generator, 2 GB/four vCPUs and an explicit
600-second audit/900-second total deadline. Its acceptance is still pending;
construction success does not replace the installed-file check.

## Remaining work

Rebuild the complete package image with corrected makefs, repeat the full audit,
and reconcile legitimate firstboot changes against their actual producers.
Qualify archive-bit normalization separately from security flags; do not suppress
all flag differences. Exercise the imported-image flag case, full inode/link and
runtime-added-state checks where required, then actual version/BE upgrade,
rollback and old-BE removal. The earlier R5 startup/authentication pass remains
valid in its narrower scope. No exhaustive installed-tree pass is claimed.
Make remains default; BIP, verified boot and global performance qualification
are not established by this work.
