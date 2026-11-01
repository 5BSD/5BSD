# Complete makefs runtime qualification

2026-11-01. Make remains the production/default backend. This work runs the
maintained makefs tests with native Bazel userland artifacts in a disposable
amd64 guest. It does not qualify a complete native world/kernel, normal Capsule
startup, SSH, publication, cross-architecture userland or controlled performance.

## Complete inventory and prerequisites

The source-owned runtime inventory in usr.sbin/makefs/tests/BUILD.bazel records
all 63 original case identities: CD9660 18, FFS 12, FAT three and ZFS 30.
A Bazel regression reconciles those identities with the original test source;
the guest checker independently reconciles installed ATF listings before running
any body. Root requirements, mount helpers/modules, per-case program requirements,
timeouts and cleanup declarations remain intact. The original scripts are
unchanged. Three unconditional CD9660 source skips remain skips, with their
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
disk for the whole system. Each original ATF body and declared cleanup runs with
its original timeout; timed-out process groups are killed. Before/after md,
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

The final full-helper receipt is
/usr/obj/usr/src/bazel-makefs-suite-qualification-r10-20261101/receipt.json:
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

The current VM r4 uses fixture r5/native r8. It has already recorded two FFS
version-case failures; source review identified the missing dumpfs helper.
A complete direct review of all four scripts and their common helper also found
the ZFS empty_dir rmdir prerequisite. Native r10 includes both at their normal
paths and preflight now requires both. No nested Python tool is used by these
scripts. Fixture r6 is prepared for the next run. The active r4 ZFS suite and
its eventual retained stderr must finish before any full-suite result is claimed.
At this commit the complete runtime gate is explicitly OPEN. Earlier source-skip
and successful individual-case observations do not override a failing suite.
