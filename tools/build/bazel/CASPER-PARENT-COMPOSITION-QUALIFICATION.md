# libcasper production parent and original connection tests (2026-11-05)

## Source-owned graph

lib/libcasper/Makefile selects libcasper and services; services/Makefile selects
cap_dns, cap_fileargs, cap_grp, cap_net, cap_netdb, cap_pwd, cap_sysctl and
cap_syslog. New typed archive-set parents retain those exact nine production
owners and all archive/request/directory output groups. No Make query, wildcard
producer selection or copied installed library supplies Bazel build metadata.

A shared source-owned production macro uses each leaf's existing install
manifest without selecting installed tests. Existing leaf install_archive
behavior is retained. The parent production_installation_archives target has
explicit production scope; installation_archives supports tests disabled and
rejects tests enabled until the original service-test/recursion hierarchy is
complete. Source opts require CASPER; unsupported casper-disabled leaf archives
remain incompatible. The accepted parent/runtime scope is AMD64.

The original cap_main_test.c now builds with native ATF, casper and nv libraries.
It retains Make's WITH_CASPER, PIE compile/link policy, and ATF-first direct
library order. Its original many_connections and connection_churn cases run
through the maintained ATF adapter with declared native runtime DSOs. No case,
assertion, resource requirement or skip condition was changed. Original test
program, Kyuafile and debug installation are declared separately from production.

## Authoritative evidence under /usr/obj/usr/src

- bazel-casper-family-make-r1-20261105 independently builds the original parent
  and all eight service children, sixteen jobs, metadata capture and explicit
  WITHOUT_TESTS. It records 139 production installation records, including nine
  identical contributions for the shared debug directory, and 131 unique paths.
- bazel-casper-main-tests-make-r1-20261105 independently builds and installs the
  original test owner with eight component metadata records.
- bazel-casper-family-native-r5-20261105 passes the maintained build-bsd format-5
  frontend with sixteen jobs. Both original connection cases actually execute
  and pass; source_settings_test is cached. Captured report counts are three
  passed cases, with no skipped case. The many-connections case crosses the
  original FD_SETSIZE boundary; churn tests closing/reusing connection slots.
- Its composition-review/review.json and audit-source.py bind immutable captures
  to original receipt/METALOG digests. All 139 production records and eight test
  records match original types, owners, groups, modes and package tags. The
  twenty-seven production parent outputs are exactly nine tar/request/directory
  triples. There are no non-directory collisions. All 103 header/manual paths
  have byte-identical payloads; all 83 manual aliases preserve original hardlink
  identity, and symlink targets agree. Both Kyuafile writers declare the same
  suite, ATF interface and test name; whitespace/comment byte equality is not
  claimed.
- All nine library ELF interfaces and the PIE test program match original Make:
  identity, imports/exports, symbol versions, hardening and ordered dependencies.
  All twenty original/native runtime-debug pairs pass debug-name and CRC checks.
  Allocated code/data, DOF and debug sections can differ; differing sections are
  retained in the report. This is not full object/code-byte or calling-convention
  ABI qualification, and does not refresh every existing leaf implementation.
- Emitted DOF inventories match nine providers and thirty-five function/probe
  schema entries. All sixty-eight ordinary probe sites validate against each
  build's actual function addresses/ranges and patched instruction bytes.
  There are no is-enabled sites in this selection. This establishes preserved
  emitted metadata/sites, not registration, live firing or tracing overhead.
- bazel-casper-family-no-tests-native-r1-20261105 passes installation_archives
  with tests disabled. All nine production archives are byte-identical to final
  r5; original service tests cannot leak into the production contributions.
- bazel-casper-family-reject-tests-native-r1-20261105 retains the expected
  explicit incompatible-target rejection for tests-enabled full installation.
  This is negative configuration evidence, not a successful build receipt.

## Rejected attempts and SDK provenance

The first attempt rejected changed /usr/bin/kyua origin bytes before compilation.
A fresh SDK was prepared with maintained libmd-plan.py --sdk-only and
libmd-stage-tools.py into bazel-casper-sdk-r1-20261105. It uses the current world
profile and the existing explicit execution-tools configuration from
bazel-libsa-sdk-refresh-r1-20261104/tools.json. Both plan and toolchain receipt
remain in that root. Additional changed host-tool origins were resnapshotted;
no old receipt digest was edited or verification bypassed. This SDK still derives
from the existing Make world and is not independent bootstrap completion.

Native r2 was terminated without a final receipt and remains unqualified. R3
passed functional cases but the strict program audit caught missing PIE policy.
The first audit also incorrectly assumed cap_sysctl's SONAME major; the corrected
reader selects the actual declared library inventory (including .so.2). R4 fixed
PIE but failed original direct-library order. R5 fixes the native dependency
ordering and reruns both original cases successfully. Failed audit directories
and candidates are retained. No strict ELF check was weakened to accept them.

## Frontend, observability and remaining work

The generic build-bsd C dispatcher already supports these explicit format-5
labels/settings. Backend input schema, signing, publication, stage policy and
host installation remain unchanged; the maintained manual documents this scope.
No C implementation was changed. No root privileges, host installation or VM
execution were used in this batch. Make remains production/default; BIP excluded.

Complete service tests (including fileargs and parent Kyuafiles), service runtime,
NSS/network/sysctl/syslog behavior, live DTrace/audit delivery, other profiles and
architectures, whole lib/world/pkgbase, independent bootstrap, cache/sandbox and
comparative CPU/memory/disk qualification remain open. Do not use production
parent assembly or the two connection cases to claim full system completion.
