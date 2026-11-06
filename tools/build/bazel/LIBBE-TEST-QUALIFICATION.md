# Original AMD64 libbe tests and complete parent (2026-11-06)

The original target_prog helper, be_create shell wrapper and Kyuafile now have
source-owned native construction and all four original installed test records.
The helper uses explicit original-order native zfs/spl/nvpair/be/thr ABI inputs,
header-only be/OpenZFS context, original configuration definitions, ccompile.h
preinclude and WARNS=6. No implementation archive is pulled in through a header
provider. No test body, implementation/provider or Makefile source is changed.

The new complete library installation parent selects the test child through the
maintained tests build setting; the existing library-only install_archive label
remains available. The lib root uses the complete child label, with its existing
full-tests guard intact. Existing format-5 build-bsd inputs express all targets;
frontend C/schema, stage/signing/verification/publication policy do not change.
The manual and completion plan record this scope in the same commit.

A fresh sixteen-job original tests-enabled Make libbe parent control matches all
45 non-directory installed records, original directory modes/owners/groups and
hardlink inode identities. All 39 non-ELF/non-static-archive payloads match exact
bytes, including compressed manual aliases, original shell script and Kyuafile.
The helper and production libbe DSO dynamic ELF/import/export/NEEDED-order/
hardening contracts and native/Make split-debug filenames/CRCs/DWARF presence
match. Raw ELF/DWARF/static-archive equality, actual debugger lookup and alternate
architecture/configuration profiles are not claimed.

Actual native/Make installed-script metadata listings are identical, using the
host ATF interpreter for this metadata-only control: one libbe_create case,
require.user=root and has.cleanup=true, with original description and implicit
300-second deadlines. The body is not executed. It creates a 1 GiB file-backed
ZFS pool and tests boot-environment depth/cloning, including snapshot and child
dataset behavior. Execution, successful teardown under failure/interruption and
resource measurements belong to a disposable-system run, not the host. The one
passing Bazel source-settings helper is not a libbe runtime-case pass. Building
these tests does not establish an upgrade/rollback workflow or root-policy proof.

Retained evidence under /usr/obj/usr/src:

- bazel-be-tests-request-r1-20261106: explicit existing format-5 tests-enabled
  parent/test construction request.
- bazel-be-tests-native-r1-20261106: successful construction, helper result,
  installation/action/source captures and receipt.
- bazel-be-parent-make-r1-20261106: fresh independent original Make parent
  build/install metadata and recipes, with TESTS explicitly enabled.
- bazel-be-parent-review-r2-20261106: all 45 records, real original hardlinks,
  39 exact data files, both ELF/debug contracts and root/cleanup metadata.
  Retained r1 incorrectly assumed the ATF metadata field order; the native and
  original listings were already byte-identical. r2 validates semantic fields.

This closes one more initially missing declaration root, leaving the ATF C tests
and ATF parent, with nested and existing roots still needing traversal closure.
Full tests-enabled world, independent world/kernel/modules/pkgbase/debug,
normal-service VM acceptance, ARM64/RISC-V gaps, bootstrap/cache/sandbox/
reproducibility, CPU/RAM/disk-I/O/footprint and verified combined publication
remain open. No live DTrace/audit-delivery qualification is added. Make remains
production/default; BIP remains excluded; no host installation/upgrade/reboot or
VM launch occurred in this batch.
