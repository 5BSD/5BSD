# Installed baseline audit and ZFS image flags (2026-11-07)

## Strict retry result: cleanup errno confirmed (2026-11-11 review)

The November 7 R2 VM is terminal failed. All 14 baseline checks passed; the
upgraded boot then reports runtime-directory unlink/rmdir failures with
`Read-only file system`, and the strengthened gate correctly rejects the run.
The source still sweeps before rc makes root writable. The lifecycle fix and
successful service-aware upgrade qualification remain outstanding. See
COMPLETION-PLAN.md for the current six closeout gates. Earlier statements that
this retry is running or that the cleanup errno is unproven are superseded.


## Real BE upgrade exposes capability-service restart failure (2026-11-07)

`bazel-system-upgrade-vm-r1-20261107` completes the signed network upgrade of all
447 packages in an inactive ZFS BE, boots its new kernel, passes positive/negative
SSH and su, rolls back with shared-file persistence, and deletes the unused BE
(reclaiming 2,805,727,232 bytes). This is useful mechanism evidence, **not an
accepted full-system upgrade qualification**: the new boot logs existing runtime
containers and failed capability-service launches. The old automatic gate omitted
those diagnostics and incorrectly reports overall `passed`.

`bazel-system-upgrade-acceptance-review-r1-20261107/review.json` preserves both
original result/serial hashes and rejects that upgrade log under the strengthened
service-failure gate; the earlier normal-boot R8 log still passes that gate.
Historical result files are unchanged. Runtime cleanup now reports failed
unlink/rmdir/fdopendir operations instead of hiding them. The cleanup cause remains
unproven; root starts read-only and cleanup precedes rc, which is a hypothesis to
verify, not a license to move cleanup after live services or adopt old directories.

NEXT: capture the cleanup errno on the real upgraded boot, fix its lifecycle at
the production boundary, and check required services from installed manifests,
including useful operations rather than process existence alone. Diagnostic
rejection alone does not prove all services healthy. Cross-platform completion,
fresh Make parity, native bootstrap/reproducibility, sandbox/cache/performance,
hardware and combined publication remain open. Make stays production/default;
BIP remains excluded. No host upgrade or installation was performed.


Native `bazel-startup-diagnostics-native-r1-20261107` passes all five selected
Python test targets and builds the actual traced Switchboard binary with the
cleanup diagnostics. The new Python suite runs three methods, including recorded
service-failure rejection, preserved kernel/shell failure gates, and normal
startup/expected authentication refusal. The frontend's format-5 target/test
inputs need no C option/backend change. Real upgraded-boot diagnostic validation
is still pending; no lifecycle fix is claimed from logging alone.

## Diagnostic candidate and strict retry

`bazel-system-upgrade-native-r2-20261107/receipt.json` passes the complete
447-package candidate and both selected solver/SSP test targets. It includes
Switchboard cleanup-error logging. The actual packaged kernel digest still
matches explicit policy input
`6ba5fcdd17aad4f7b4b179cddd721ba25bab66b51aefac77c95666f3542a3f98`.
`bazel-system-upgrade-repository-r3-20261107/receipt.json` passes signed-catalogue
verification, all archive verification and actual wrong-key rejection.

Fresh `bazel-system-upgrade-vm-r2-20261107` is running with those frozen inputs,
the unchanged complete baseline R11 image, 2 GB/four vCPUs, and the stronger
service-failure gate (implementation ac3f2ad48ea, final-drain fix 874d50cadd1).
This retry is diagnostic: a failure is to be retained and investigated, not
avoided by adopting old service directories or clearing them in the fixture.
No lifecycle fix or successful upgrade qualification is claimed yet. Compilation
uses 16 jobs; package compression's configured single-thread-per-package tail
is not a controlled Make performance comparison.

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

## Corrected-image raw runtime audit R7

`bazel-system-normal-boot-vm-r7-20261107` passes all 12 startup/authentication
checks on the actual R10 image. Its complete raw installed audit still **fails**
with status 2, now showing only archive bookkeeping, five provisioned account
file hashes and the consumed firstboot marker. No dropped schg flag, other
permission/ownership/type/link or unrelated content difference is reported. The
owned VM is stopped; this is not a normal-shutdown pass. It observed 520 QEMU
samples, 2,370,789,376 bytes maximum RSS, 525.70 s last CPU and 532.49 s last elapsed
sample; allocated overlay max 16,409,088 bytes. Host load was approximately 34 on
16 logical CPUs with unrelated compilation. This is not a controlled performance
comparison and does not attribute a timing regression to constructor flags.

The new format-3 driver keeps the original complete specification and raw mtree
result. It requires hash-bound baseline/producer inputs and an explicit firstboot
transition policy. Exact complete account/group/public content is checked; only
already-authenticated accounts may have new salted passwords. It stages a
captured native read-only db(3) comparator and uses real guest pwd_mkdb in a new
private directory, checking every live DB key/value in both directions. Live
account state is never rewritten. Content hashes become reconciliation proof only
after these checks, not by treating observed hashes as expected without validation.
Consumed empty markers must be independently absent. Optional normalization is
limited to uarch; all security flag or other metadata changes fail. Full raw
logs and structured reconciliation remain reviewable.

`bazel-account-db-native-r2-20261107` passes three actual generated-database test
cases: equal records, changed records, and extra records in either direction,
including before/after byte checks proving the comparator is read-only. `bazel-firstboot-proof-native-r1-20261107` passes all four selected native test
targets (13 cases: DB comparison, accounts, mtree reconciliation and complete
specification coverage), and captures the real comparator executable. Actual
format-3 VM qualification remains pending. No reconciled runtime pass is claimed yet. Existing maintained
frontend target/test inputs carry all helpers; the C backend/default is unchanged.

## Accepted format-3 runtime: R10 image and R8 VM

`bazel-system-normal-boot-vm-r8-20261107/result.json` is **passed**, SHA-256
`dd47842c44dd1858cd625d8e2039c6116d24b6ec32f28011fe5fd1ecc890e1e8`.
The same complete 447-package R10 image now passes all 14 checks: the earlier
12 normal startup/authentication checks, actual firstboot transition proofs,
and the complete 33,982-file/1,369-directory baseline audit. It then syncs all
buffers and powers off normally (QEMU exit 0); backing bytes and every runner,
policy, baseline/producer and helper binding remain unchanged.

Raw mtree exit status remains 2 and its full 1,751-byte diagnostic log is retained,
SHA-256 `5fcb5c75d62dfdbe9850613161c7e12b6a332133eb2a3a2c06464ca5d6c01061`.
The explicit reconciliation covers exactly 23 uarch bookkeeping changes, five
independently validated account file hashes and one independently absent firstboot
marker. No security-flag, owner/mode, symlink or unrelated content change is
accepted. The complete original specification is retained, not shortened.

The real guest snapshot contains 30 accounts and 42 groups, with exact declared
fields/memberships and public projection. Both live DBs equal the actual private
pwd_mkdb rebuild: 90 logical records each. Independent review derives that count
from the actual local-account snapshot (name/ordinal/unique-UID keys and version
record), checks all snapshot hashes against the proof, all 14 named checks,
source/log bindings and normal shutdown. Record:
`bazel-system-installed-audit-review-r1-20261107/review.json`.
Firstboot proof SHA-256:
`2207e284c08a8d8655d4285ac8c464b312f6345d9a65258dcd2dc66c5a27a82d`;
serial SHA-256:
`e5f0b6cdca3ce5aa17327d2c413d9a7caa78435863604921274bb521ff6a3f72`.

The VM retains 2,048 MiB RAM/four vCPUs and disk-backed ZFS. Total driver run
441.08 s (including final hashes); 421 QEMU samples observe maximum RSS
2,417,192,960 bytes and last CPU 490.99 s. Maximum allocated overlay is
17,621,504 bytes. These are functional-run observations under concurrent host
compilation, not a controlled CPU, RAM or disk-I/O comparison. The audit excludes
timestamps, extra runtime objects and hardlink inode identity; those and broader
profile/service/cross/bootstrap/performance/publication gates remain open.
BIP and verified-boot qualification are outside this result; Make stays default.

## Actual next-version package candidate prepared

`bazel-system-upgrade-native-r1-20261107/receipt.json` passes the full system
package target and both selected tests (real pkg solver and kernel SSP regression).
The declared package version is `16.0.qual.20261107`; the kernel revision input is
`212d25780db9`. Independent review at
`bazel-system-upgrade-review-r1-20261107/review.json` verifies all 447 captured
package manifest names/versions and actual archive hashes, then reads the actual
kernel ELF through the maintained complete archive reader. It finds the new
version stamp and a changed kernel SHA-256:
`6ba5fcdd17aad4f7b4b179cddd721ba25bab66b51aefac77c95666f3542a3f98`.
This is a real package/kernel candidate for upcoming BE tests, not evidence that
it has been installed, booted, upgraded, rolled back or published. No host upgrade,
repository latest advancement or reboot was performed.

## Signed network repository and BE scenario implementation

`bazel-system-upgrade-repository-r2-20261107/receipt.json` passes preparation of
all 447 next-version packages, a real signed pkg catalogue, import using the
matching public key, authenticated fetching of every archive, and rejection of a
different public key. Keys are explicit development fixtures outside the served
repository; no private key enters the guest. This private qualification repository
is not a combined publication and does not advance latest.

R1 preparation correctly fails: the maintained verifier mistakes pkg's reserved
`files.pkg` file-list catalogue for a package archive. A central reserved-catalogue
set now covers inventory and bootstrap/application admission. A real `pkg repo -l`
regression checks that package inventory excludes the catalogue while still
rejecting a corrupt ordinary archive. That test and the existing full signed
consumer/tamper test pass (`catalogue-regression.log` under the fixture key run).
No missing-manifest or broad filename-pattern filter is used.

The format-4 VM scenario is implemented with explicit identities, resources,
repository/trust inputs, pkg role, guest host-network address and shared-data
location. It retains all 14 baseline checks, then performs actual network catalogue
verification and wrong-key refusal in isolated DBs, clone/mount/chroot pkg upgrade,
non-config package checksums, version/kernel verification, activation/new-kernel
boot, real authentication, rollback, shared-file persistence, active-removal
refusal, unused-BE removal and bounded space reclamation. It never invokes host
ZFS or installs on the host. Application database schema rollback and exhaustive
upgraded-tree metadata remain outside this scenario's acceptance.

Source review catches a second real fixture defect before this test: loader.conf
pins vfs.root.mountfrom to zroot/ROOT/default, defeating ordinary BE activation.
The maintained fixture now omits that override and follows normal loader/ZFS
bootfs selection. The declared image policy still chooses the initial bootfs.
Complete image R11 is rebuilding through the normal frontend; no guest edit or
manual root substitution is used to get around the fixture.

`bazel-upgrade-policy-native-r2-20261107` passes all four selected test targets
(10 cases: upgrade paths/version inventories, terminal protocol, firstboot account
changes and mtree reconciliation). R1 analysis fails on an undeclared cross-package
source visibility dependency; explicit limited exports_files fixes the dependency
without disabling visibility enforcement. The format-4 policy preflight validates
447 package identities and 456 repository/trust/control bindings. Actual VM
upgrade/rollback/removal acceptance is still pending. C frontend options/backend
are unchanged; maintained format-5 targets/tests carry the new regression and
runtime/manual documentation describes the added format.

The recorded October ZFS/filedesc issue was consulted. Its later diagnosis records
the local procdesc_knote proctree-lock edge fixed on dev; the separate upstream
cycle is not patched here. WITNESS/panic diagnostics continue to fail the VM run.

## Complete automatic-bootfs baseline R11 captured

`bazel-system-image-native-r11-20261107/receipt.json` passes the complete image
and all six selected tests. Counts remain 447 packages, 33,982 nondirectory records
and 1,369 directories. Image SHA-256:
`86c1b131fc622a7e58ec5e5f0f8ed0742e43d047c9da2e9ee231bc33982f0d4f`;
report SHA-256 `0415e1d66a1a21134c10e2a62730e6e929d613776462017033a9132c6c48b07e`.
The kernel bytes remain identical to R10; the loader configuration digest matches
the maintained source with its pinned-root override removed.

Fresh `bazel-system-upgrade-vm-r1-20261107` uses R11 with 2 GB/four vCPUs, the
passed signed repository R2 and an explicit format-4 policy (3,600-second whole
run, 2,400-second upgrade phase, 60-second space-reclamation bound). The shared
file is explicitly in zroot/home, outside the BE root; no existing user file is
reused. The new VM has already booted through normal ZFS selection and passed the
first 13 console/PAM/SSH/su/firstboot checks. The complete baseline audit and actual
upgrade/new-kernel/rollback/removal acceptance remain pending. No upgraded-system
pass is inferred from preparation or startup. Implementation commit: 590d397caab.
