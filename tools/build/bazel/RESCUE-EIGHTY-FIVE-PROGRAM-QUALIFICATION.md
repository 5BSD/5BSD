# Native eighty-five-application rescue construction

## Source-owned variants (2026-11-05)

Dump, restore, fsck_ffs, fsdb and mount_nfs bring the selected AMD64 core to
85 of 103 default applications. Each ordinary/rescue pair shares one explicit
source inventory. `bazel-rescue-85-ordinary-declarations-review-r1-20261105`
proves every original ordinary declaration structurally unchanged after expanding
that exact literal and removing the new rescue declaration. This does not prove
fresh ordinary installed-world/runtime acceptance.

Rescue policies preserve WARNS=2 for the four UFS programs, normal WARNS=6 for
mount_nfs, RDUMP/RRESTORE/_ACL_PRIVATE/NFS definitions, original ordered object
lists and fsck_ffs's anchored provider. Fsdb reuses the source-owned fsck headers
without enabling fsck_ffs's program-specific provider. Native libedit joins lazy
static imports at its original selected archive position, before jail.

## Retained evidence

All directories below reside under `/usr/obj/usr/src/`.

- `bazel-rescue-85-native-r2-20261105`: maintained format-5 frontend, sixteen
  jobs; 92 runtime methods and separate 28 source-settings methods pass. Private
  UFS1/UFS2 regular images exercise all five read-only fsck phases, fsdb -r input,
  level-zero dump to a private archive and restore table reads. Source-image
  hashes remain unchanged. No live mount, device, remote tape, snapshot creation
  or dumpdates update is requested. NFS receives only pre-mutation argument tests.
- Native r1 compiled/linked but failed one new test's incorrect expectation of
  a clean-status message. Actual original source and retained output show five
  read-only phases instead. The test now asserts NO WRITE and all five phases;
  production behavior is unchanged. Rejected r1 remains retained. A separately
  hash-bound private backup probe passed before addition to the maintained suite.
- `bazel-rescue-ufs-nfs-more-make-r1-20261105/report.json`: fresh actual original
  generated child Make builds produce 51 C objects and one provider, with 4577
  original source/policy/tool/header bindings checked before and after.
- `bazel-rescue-85-action-review-r1-20261105`: all 51 actual successful compiler
  actions from rejected r1 match original warnings/defines/optimization/C17/debug/
  SSP/non-PIE policies; raw objects/dependencies bind to execution digests, and
  409 upstream converter/runtime bindings are checked before/after.
  `bazel-rescue-85-passing-action-binding-r1-20261105` proves those raw output
  hashes match immutable passing r2 captures, including explicitly retained
  fsck_ffs pre-DTrace objects. Cached actions are not invented executions and the
  original failed qualification remains failed.
- `bazel-rescue-85-dependency-review-r1-20261105`: all 3368 consumed dependency
  occurrences are declared in the executed input inventory and match independent
  original payload hashes by basename/bytes/multiplicity. Parent-directory
  spellings require bounded relative checks and repository identity. No mutable
  execroot provides retained-content evidence. Full logical-path namespace and
  incremental invalidation remain separate gates.
- `bazel-rescue-85-object-review-r1-20261105`: all 52 C/provider contracts are
  recorded. Forty-nine C contracts agree directly. Dump tape.o retains assertion
  filename strings/relocations; fsck_ffs main.o retains path-derived DTrace aliases;
  its provider retains raw DOF/relocation differences.
  `bazel-rescue-85-filename-controls-r1-20261105` reproduces the one diagnostic
  difference using the original compiler command plus explicit macro-prefix
  mapping, without changing baseline/native bytes or native flags.
  `bazel-rescue-85-provider-review-r1-20261105` checks provider schemas, actual
  functions/patch sites and independently verifies every alias against its actual
  object path. C allocated data/nondebug relocations agree after verified aliases.
  Raw DWARF/DOF identity and live registration/firing are not established.
- `bazel-rescue-85-pipeline-review-r1-20261105`: fresh original crunchgen and
  generated Make on identical captured application/archive/startup inputs match
  main C and all 172 whole-byte outputs: main object, 85 stubs, 85 combined objects
  and the executable. Static AMD64/no INTERP or DYNAMIC/nonexecutable stack/RELRO
  checks pass. This is identical-input pipeline parity, not an independent full
  library/world construction.

## Integration and remaining gates

Existing maintained format-5 targets/settings support these declarations and raw
captures; no frontend C/schema/staging/signing/publication-helper change is needed.
The frontend manual, completion plan and observability ledger are updated. This
is unsigned development qualification, not verified boot or root protection.
Make remains default; BIP excluded. No host installation/upgrade/reboot occurred.

The eighteen remaining default applications are sh, csh, camcontrol, geom,
ifconfig, init, ping, pfctl, bectl, zfs, zfsbootcfg, zpool, dhclient, tar, vi,
iscsictl, zdb and iscsid. Finish them plus actual rescue library overrides,
configuration/cross/full installation/aliases/helper paths and independent library/
debug/header/pkgbase parity. NFS mounts, dirty/corrupt recovery, privileged storage,
live DTrace/audit delivery, full world/kernel refresh, bootstrap, separate hardware/
combined publication and CPU/memory/disk/cache/sandbox acceptance remain open.
Earlier ncurses provenance and host-crypto configuration-cost findings remain open;
this checkpoint does not claim raw-header identity or comparative performance.
