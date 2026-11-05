# Native NSS, resolver and standard-time test construction (2026-11-05)

## Implementation

Source-owned declarations now cover all eight original NSS programs, the threaded
resolver program and both standard-time programs. All eleven original C sources
remain unchanged. Three original suite contributions contain twenty-seven regular
file records: eleven executables, eleven debug files, three Kyuafiles and two
copies of the original external-host-list fixture. NSS obtains mach through the
same resolver source as Make's .PATH; no manufactured localhost list is substituted.
The NSS gethostby Kyua timeout remains 1200. Resolver stays dynamically linked to
native pthread; a static executable would give spurious resolver passes.

The local_test_installation macro centralizes declared ATF C construction and
installation while leaves own exact sources, options, headers, libraries, fixtures,
metadata and runtime subsets. Per-program keys naming absent programs fail.
Native ABI imports and the existing final-consumer link sequence preserve original
ATF/pthread/libc ordering, without copying library producer objects into consumers.
Private NSS testutil and suite macro headers are explicit. The tzdir header belongs
only to detect_tz_changes_test. Its DETECT_TZ_CHANGES definition follows the existing
build setting, matching the selected disabled original Make profile here.

Common warning policy now includes WARNS=6. Original Make common C flags match
exactly after separating compiler/configuration-owned optimization/debug/SSP and
include flags. Existing WARNS=2/3/4 flag lists remain exactly unchanged. There is
no Make invocation in the native Bazel action graph to extract this metadata.

## Runtime and cache scope

All forty-four original account, group, protocol, RPC database, service and shell
cases run with native libc/libsys/ATF. They include enumeration, name/id lookups,
interleaving, two-pass behavior and snapshots. Snapshot output stays in each ATF
private working directory. This is host-database integration: /etc/nsswitch.conf
selects files for these services. It is not a hermetic private-database test.
No credential/private passwd database content is copied into artifacts.

These forty-four cases carry external and no-remote tags. They must execute again
when requested, rather than returning cached outcomes for changing host databases
or running against a remote worker's accounts. This uses Bazel's standard tags:
https://bazel.build/versions/9.2.0/reference/be/common-definitions#common.tags
Compilation and installation artifacts remain normally cacheable. The remaining
selected runtime case checks original strptime day-of-week behavior, with no host
database dependency. Source-settings qualification is the forty-sixth target.

External NSS host lookup cases and the three threaded resolver network cases are
installed but not executed here; their original external host inventory remains.
The timezone program's chroot/jail/setugid/change-detection and zoneinfo scenarios
also remain installed-system qualification work. This checkpoint does not replace
those cases with unprivileged passes or count their compilation as execution.

## Evidence

All retained evidence directories are under /usr/obj/usr/src:

- bazel-libc-local-batch-native-r1-20261105: all forty-five selected original cases
  and source-settings target pass; captures all three complete contributions.
- bazel-libc-local-batch-review-r1-20261105: independent original Make inventory,
  metadata, exact Kyua/fixture bytes and eleven distinct program ELF identity,
  ordered dynamic dependencies/symbols/versions and hardening contracts pass.
  Native and Make debug filename/CRC checks and scoped physical suite/debug
  directory attributes pass. All twenty-seven regular file records match.
  audit.py retains source/tool/reference/capture hash checks and original queried
  program inventories; no raw ELF/debug byte equality is claimed.
- bazel-libc-installation-make-r1-20261105: original Make libc parent reference,
  stage, METALOG and receipt. This uses a prepared SDK; it is not a fresh independent
  whole-world bootstrap.
- bazel-libc-test-warning-review-r1-20261105: exact source-profile Make common C
  option checks for all three new suites; prior warning-policy lists preserved.
- bazel-libc-local-batch-native-r2/r3/r4-20261105: each final receipt passes 46
  targets, with exactly 44 freshly executed NSS cases and two cache hits. The
  identical r2/r3 request/declarations verify unconditional external execution.
  r4 scopes the timezone header to its real consumer and consolidates inventories.
- bazel-libc-local-batch-final-bindings-r1-20261105: all nine final installation
  outputs (tar, records and directory metadata for each suite) have identical
  hashes to the independent r1 comparison. Final receipts/stdout also bind the
  observed repeated fresh execution.
- bazel-libc-local-host-inputs-r1-20261105: observed public NSS configuration and
  account/group/protocol/RPC/service/shell database hashes remain unchanged across
  r2 through r4. This observation is not a complete transitive host-input closure.

The first successful native run exposed a design concern on review: host-dependent
NSS outcomes could have been cached. External/no-remote tags correct that behavior;
three subsequent runs demonstrate fresh execution. No runtime failure was hidden.

## Maintained integration and remaining acceptance

Existing explicit-input labels, test selection, format-5 artifact captures and
installation providers express this contribution. build-bsd.c, backend selection,
input schema and signing/publication helpers need no change. The manual and
completion/observability ledgers are updated. Full-tests parent guards remain.

This is selected AMD64 leaf installation/interface and scoped native runtime
qualification. Full installed hierarchy, external DNS, timezone/privileged cases,
other ABI/configurations, bootstrap/cache/sandbox acceptance for the complete
system, live DTrace/audit delivery, pkgbase and performance/publication gates remain.
Make stays production/default, BIP excluded; no host installation or reboot.
