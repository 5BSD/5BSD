# Native fresh-world account construction

## Composition and result (2026-11-06)

The maintained world graph now declares //:fresh_world_contributions as the
existing finalized_world_contributions plus //etc:account_install_archive.
world_contribution_products requests that fresh aggregate and the existing
noninstalled internal products. The existing finalized aggregate retains its
previous meaning and contents. Account archive visibility grants only the root
world package access. The declarations reuse native archive providers and the
source-owned account generator; no runtime path scan or copied host state is used.

The maintained build-bsd bazel-test run passes with 16 jobs, the explicit
NIS-disabled, production-malloc AMD64 profile, and source-settings/manual-database
tests. The audit verifies immutable metadata captures, all 1280 archive
manifests, 32518 unique nondirectory paths, and
1211 distinct explicit directory/package claims and
3562 repeated directory record occurrences over
789 total directory paths.
There are no nondirectory duplicates, directory metadata conflicts or
file/directory collisions. The fresh aggregate retains all
3837 finalized output files with identical
hashes and adds exactly the account archive, its manifest and directory policy.
The world product target includes these same archive payloads. Its ordinary
filegroup does not forward archive metadata output groups; metadata is checked
on the explicit aggregate targets.

The three added account files retain numeric root/wheel archive ownership,
0644 passwd/pwd.db and 0600 spwd.db modes, and no package tags. All three match
the independent complete original Make lib installconfig bytes. This applies to
the public source defaults in the selected profile. It does not qualify private
credential handling through action caches or custom account inputs.

## Deployment and package boundary

This is fresh-image construction output. It is not an overlay updater and must
not be extracted over existing account databases. No deployment is executed by
these targets. The runtime package's declared account construction remains
replace=false; no package metadata or account migration behavior is changed.
The existing package-oriented/finalized aggregate stays available independently.
Actual image materialization must preserve modes; raw Bazel file modes are not
installation policy. Installed account lookups/login/PAM/SSH, package-driven
construction and existing-account upgrade/nonreplacement tests remain open.

The original full-library payload comparison still correctly reports the three
paths absent from its selected library aggregate. They now have an explicit
whole fresh-system construction owner; that is not a reason to alter the library
comparison's selection or suppress missing-path reports.

## Evidence under /usr/obj/usr/src

- bazel-world-account-finalization-request-r1-20261106/inputs.json: explicit
  format-5 profile and targets, standard execution SDK and offline modules.
- bazel-world-account-finalization-native-r1-20261106: retained initial failure,
  root composer lacked account archive visibility; no source was skipped.
- bazel-world-account-finalization-native-r2-20261106: passed construction,
  immutable archive outputs and tests. Artifact manifest SHA-256:
  6b20d02d1fa8b1e8908056c1179cd1addd0d78ea05cbc58480a0815259ac235b.
- bazel-world-account-finalization-review-r2-20261106: retained audit and passed
  namespace/directory/output-extension/account-byte checks.
- bazel-library-complete-make-r2-20261106: independent original account control.
- LIBRARY-ACCOUNT-CONSTRUCTION-QUALIFICATION.md: separate generator evidence.

Existing format-5 frontend inputs select the new root. Maintained backend graph
and manual are updated; no new frontend C option, production default, signing,
publication or activation behavior is introduced. This is selected production
world contribution/product construction, not independent complete Make parity,
full tests-enabled world, a booted installed OS or performance qualification.
Kernel/modules, package/hardware/combined publication, normal service runtime,
ARM64/RISC-V, bootstrap/cache/sandbox/reproducibility and CPU/memory/disk-I/O/
footprint gates remain open. No host install or reboot was performed. Make
remains the production default; BIP remains excluded.
