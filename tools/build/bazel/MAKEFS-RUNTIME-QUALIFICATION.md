# Complete makefs runtime qualification

2026-11-01. Make remains the production/default backend. This work runs the
maintained makefs tests with native Bazel userland artifacts in a disposable
amd64 guest. It does not qualify a complete native world/kernel, normal Capsule
startup, SSH, publication, cross-architecture userland or controlled performance.

Current bounded outcome: all 63 cases were attempted in fresh VM r6 with the
explicit uniform scale-5 profile: 60 PASS and three intentional source SKIP.
All per-case and final cleanup checks passed. This is not source-scale-1 or
complete-system qualification; earlier failures remain recorded below.

## Complete inventory and prerequisites

The source-owned runtime inventory in usr.sbin/makefs/tests/BUILD.bazel records
all 63 original case identities: CD9660 18, FFS 12, FAT three and ZFS 30.
A Bazel regression reconciles those identities with the original test source;
the guest checker independently reconciles installed ATF listings before running
any body. Root requirements, mount helpers/modules, per-case program requirements,
timeouts and cleanup declarations remain intact. The ZFS permissions case now
accepts either capitalization of the shell's permission-denied diagnostic, as
detailed below; its mode and nonzero-exit checks are unchanged. Three unconditional CD9660 source skips remain skips, with their
original reasons: allow-max-name, isolevel=1 and isolevel=3. They are not passes.
The checker rejects missing fixture programs before executing test bodies.

The guest uses native makefs, newfs, mdconfig, mount tools, ZFS utilities and
explicit standard-path helpers. The bracket helper is an explicit argv[0] copy
of native test; the production package retains its original hardlink metadata.
No production hardlink/inode equivalence is inferred from this fixture alias.
Account data, group data, login configuration and PAM policy are actual declared
base inputs. Native pwd_mkdb builds the database, and native su with the standard
root Zsh/PAM configuration verifies the existing tests-account UID transition.
No account, shell or PAM policy is rewritten to make a test pass.

The preparer verifies the complete native ELF dependency/interpreter closure;
missing dependencies are errors, never host-library fallback. SDK Python and
loader remain separate bootstrap inputs. Optional execution-kernel modules must
come from the selected kernel build tree with explicit module and kernel hashes.
The selected execution kernel already provides ZFS, verified by guest kldstat;
a matching explicitly recorded zfs.ko is available only as bootstrap, not as a
claim of Bazel ZFS module qualification.

## Storage, isolation and cleanup

The maintained daemon-runtime harness creates a fresh disk-backed UFS/GPT root.
The guest-only adapter makes its ordinary root writable, mounts devfs and formats
its independently created private virtio scratch disk. It does not use a memory
disk for the whole system. Each maintained ATF body and declared cleanup uses its source timeout with
the explicit uniform emulation profile applied; timed-out process groups are killed. Before/after md,
mount and pool inventories must equal the baseline. A leaked resource stops
later execution rather than allowing contaminated results. Final scratch/devfs
unmount failures fail the adapter. No host mount, md, zpool, chroot, installation,
account, sysctl or policy changes are performed.

The declared profile is 2GiB guest RAM, four CPUs, 768MiB disk-backed root,
64GiB logical sparse scratch, 16GiB sampled scratch allocation cap, 1GiB sampled
host free-space floor and 3GiB sampled QEMU RSS cap. Large sparse image cases,
including 50GiB autoexpand, therefore have real disk-backed logical space rather
than forcing their contents into guest RAM. Scratch inode/type/size and resource
bounds are checked throughout. These samples do not measure all I/O, host page
cache or between-sample peaks, and do not establish a performance comparison.

## Native build and reduced configuration

The refreshed full-helper receipt, including the maintained permissions-test
portability fix, is
/usr/obj/usr/src/bazel-makefs-suite-qualification-r12-20261101/receipt.json:
176 selected targets and 27 passing Bazel test targets. Test results can be
cached; selected targets are not a count of newly migrated programs. Focused
regressions cover inventory/source reconciliation, required-program rejection,
module/kernel identity binding, scratch bounds and actual resource-limit errors.

The ZFS-disabled, tests-enabled receipt is
/usr/obj/usr/src/bazel-makefs-nozfs-tests-qualification-20261101/receipt.json.
It selects all three non-ZFS suites and their 33 cases. Independent Make staging
at bazel-makefs-nozfs-tests-make-20261101 and comparison reports at
bazel-makefs-nozfs-tests-parity-20261101 establish all 11 installation records,
non-ELF payload bytes, ELF contracts and separate debug links. This is build and
inventory coverage for that setting; it does not execute a second reduced guest.
Earlier default and ZFS/tests-disabled installation comparisons remain in
MAKEFS-QUALIFICATION.md. Existing makefs code/layout differences remain explicitly
open; matching ELF contracts are not whole-machine-code equivalence.

Explicit inputs, plans and comparison scripts are retained under
/usr/obj/usr/src/bazel-makefs-full-suite-evidence-20261101/.

## Retained failures

The first native fixture closure rejected the actual missing libicp dependency;
the native library is now an explicit input. The first runtime inventory test
rejected an incorrect runfiles path; the fixed test locates declared workspace
resources. No failing result was overwritten.

VM r1 could not make the fresh root writable: nmount required an explicit rw
option. Its cleanup also exposed an adapter bug: body-only ATF assertions cannot
be called from cleanup. Both adapters now return normal cleanup errors. VM r2
correctly rejected loading duplicate ZFS because the selected kernel already
provides it; the adapter now checks the actual provider first. VM r3 attempted
all 63 identities: 11 passes, three intentional source skips and 49 fixture
failures caused by missing helpers. Its normal account/PAM transition and
per-case/final cleanup passed. Native mtree, mktemp, cmp, echo, sync and bracket
inputs plus an explicit prerequisite gate address that incomplete fixture.
All serial, failure and resource reports remain under the distinct
bazel-makefs-suite-vm-r1/r2/r3-20261101 directories. Earlier failed fixtures do
not count as runtime qualification.

VM r4 used fixture r5/native r8 at the original timeout scale. It attempted
37 identities: 31 passes, three source skips and three failures. Both FFS
version cases failed with actual dumpfs exec status 127; their normal cleanup
restored baseline. A direct review of all four scripts and the common helper
also identified the rmdir prerequisite for ZFS empty_dir. Native r10 includes
both helpers and preflight requires both; no script/assertion was changed.

Compression completed several algorithm iterations, then hit its original
600-second limit while importing the gzip-2 pool. This was not a random-input
stall. Original cleanup returned zero but left the pool and three dataset
mounts: the test writes its pool-name file only after import returns. The
independent inventory gate correctly rejected that leaked state and refused
the remaining 26 identities. Final scratch unmount failed as busy. Shutdown
suspended the partially imported pool after syncing buffers. Only this failed
QEMU was manually terminated; manual-termination.json records the exact PID,
command, reason and signal. The harness's forced_termination field is false
because it did not initiate that external termination. This is a failed
qualification, not a successful shutdown/cleanup result.

The retained result is bazel-makefs-suite-vm-r4-20261101/result.json, alongside
the complete extracted makefs-runtime-results.json and serial log. Observations
are 1022.955 seconds, 782.79 QEMU CPU seconds, 1296977920 maximum sampled RSS
bytes and 15864320 maximum sampled scratch allocation bytes. No controlled
performance comparison is inferred.

## Explicit emulation deadline profile

The preparer's optional checker_profile contains only integer timeout_scale,
validated from 1 through 20, default 1. It is part of the hashed explicit plan,
copied to checker-profile.json and recorded in fixture.json. The shared validator
implementation is also a hashed bootstrap input. Unknown fields, booleans,
strings, fractions and case-specific exceptions are rejected. Every original
ATF timeout remains in metadata; the checker records its source limit, uniformly
scaled effective limit and each actual invocation's deadline. The same factor
applies to every body and declared cleanup, without changing test contents or
failure/skip/contamination rules.

The next TCG profile declares factor 5. It does not supersede the original-scale
FAIL or establish timing/performance qualification at factor 1. The outer adapter
uses the maintained --atf-case-budget tests/iconv_vm_driver:full_suite=7200
input, preserving its original 3600-second metadata; the separate VM limit is
8000 seconds. RAM/CPU/disk bounds remain unchanged. Failure records are emitted
in full immediately after cleanup/inventory checks with explicit delimiters and
truncated=false, as well as in the final complete report.

Bhyve exists on this host, but /dev/vmmctl is root:vmm mode 0660 and this user's
groups do not include vmm; /dev/vmm is absent. No permission, group or device
changes were made. Accelerated bhyve execution would require an operator with
the OS's VMM/device access (normally root) to run a reviewed maintained harness;
no privileged host setup or accelerated qualification is claimed here.

At this commit the complete runtime gate remains OPEN. A separately labeled
scaled-emulation result will be recorded only after actual execution terminates.

## Full scale-5 run: one maintained-test portability failure

The fresh r5-scale5 guest attempted all 63 identities: 59 PASS, three original
CD9660 SKIP, one FAIL (makefs_zfs_tests:perms). Its complete JSON report remains
in /usr/obj/usr/src/bazel-makefs-suite-vm-r5-scale5-20261101 together with serial,
result and resource evidence. All per-case md/mount/pool inventory checks and
cleanup passed; final scratch/devfs cleanup passed, shutdown synced all buffers,
QEMU exited zero and the harness did not force termination. The complete suite
remains FAIL; the three source skips are not passes.

The sole failure was the original case-sensitive expected text "Permission
denied" versus the actual default Zsh message "permission denied" from su -m
tests. The command correctly returned nonzero and the captured error identified
the inaccessible file. This is corrected in the maintained test source with
"[Pp]ermission denied" in both diagnostic assertions. All 512 input modes,
nonzero-status checks, su/PAM/default account shell, image construction, mtree
comparison and cleanup remain unchanged. The original execution checks concern
target input files; imported-image mode parity is checked through mtree. This
change does not extend their scope or prove execution checks on the imported
image. The subsequent fresh hash-bound complete-suite outcome is recorded below.

The r5 profile remained uniformly scale 5 with source deadlines retained.
Compression, which timed out under the original scale-1 profile, passed here.
Observed run duration was 4207.763 seconds, sampled QEMU RSS maximum 2381160448
bytes, QEMU CPU 3421.64 seconds, private scratch allocation maximum 127234560
bytes and minimum sampled host free space 71175016448 bytes. Host compilation
overlapped parts of execution; these are resource observations, not a controlled
performance or source-scale-1 timing result.

## Verified full-suite outcome under the explicit emulation profile

Fresh fixture r8 derives from the passing r12 native receipt and unchanged
explicit scale-5 plan. Its separate disk-backed r6 guest completed every case:
60 PASS and the three declared CD9660 source SKIPs, checker status
COMPLETE_WITH_SOURCE_SKIPS. The complete report and compact verification summary
are retained in /usr/obj/usr/src/bazel-makefs-suite-vm-r6-scale5-20261101/.
The permissions case now passes with the maintained capitalization-only fix.

All non-skipped body and declared-cleanup statuses are zero, every per-case
md/mount/pool inventory is restored, the outer adapter cleanup passes, and the
harness reports PASS. The guest synced all buffers and powered off normally;
QEMU exited zero and was not forcibly terminated. Native su with the actual
account/PAM/default Zsh inputs returned the tests-account UID 977. All original
case identities and requirements, all 512 permissions input modes, source/effective
timeouts and source skips remain explicit in the report. No missing programs or
unexpected skips are accepted as passes.

The selected runtime inputs are fixed by the native receipt, fixture artifact
bindings, implementation/input hashes and selected kernel/module identity.
The fixture payload is 410020901 bytes from 15 native installation archives and
124 explicit files; it is stored on disk, not loaded as a whole-image memdisk.
The original 2GiB RAM/4CPU, 768MiB root and independent 64GiB logical sparse-disk
profile and host resource caps remain in effect. Observations: 478.906 seconds,
QEMU CPU 863.67 seconds, sampled QEMU RSS maximum 2394578944 bytes, scratch
allocation maximum 134054400 bytes and sampled host free-space minimum
56256126976 bytes. These samples exclude host page cache and between-sample
peaks; concurrent host builds and large timing differences across attempts
preclude a controlled performance claim.

No additional VM is needed for this bounded gate. Original-scale qualification
remains unproven for the corrected complete fixture; the retained r4 run failed.
The executed root is still the disposable fixture PID1, with explicit Make-built
execution-kernel/bootstrap artifacts. Normal Capsule startup, SSH, a complete
native/published pkgbase system, reduced-option guest runtime, cross-userland and
controlled storage/memory/CPU comparisons remain separate gates.
