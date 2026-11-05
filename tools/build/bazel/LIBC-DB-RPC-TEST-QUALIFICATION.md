# Native libc DB and RPC test completion (2026-11-05)

## Source-owned construction

The DB contribution builds all seven original C programs: five ATF programs
and the h_db/h_lfsr helpers. It also installs README and the original db_test
shell suite. The latter uses the maintained sed expression replacing /bin/csh
with /bin/cat and the existing ATF interpreter-prefix producer. The body is the
actual imported script; no replacement test body or helper is invented. Private
btree/hash structure headers are declared only for the DB test consumers,
preserving the tamper tests' use of real field definitions instead of offsets.
Only db_hash_seq_test receives original NetBSD compatibility linkage; helpers
and local ATF sources keep their original contexts. All sixteen C test cases
run through the standard ATF adapter with declared native libc/libsys/ATF.

RPC now builds and tests its actual installed rpc_test/xdr_test programs against
the native public libc interface and native rpcsvc/util libraries. Declared
rpcgen/preprocessor actions retain the original schema, flags and generated
header/XDR C inputs. Partial-XDR-object prototypes, SDK-libc runtime substitutions
and separate RPATH-bearing test binaries are removed. Existing target names
remain aliases to the actual programs/cases. Original network cases remain
explicit manual/requires-network targets; raw RPC and XDR run in this batch.
No imported C program is rewritten for Bazel.

Both families preserve the original Kyua program inventory, split-debug files,
package tags and typed archive/metadata/directory providers. The DB Kyuafile and
the common imported-test helper use Make's sorted program order. A small shared
source-owned test_policy.bzl now supplies the existing WARNS=2/4 C policy without
changing any prior flag sequence or broadening private headers into consumers.
There is no Make invocation or live package inventory in native construction.

## Verified evidence

All directories below are under /usr/obj/usr/src.

- bazel-libc-db-rpc-native-r2-20261105: maintained build-bsd bazel-test, AMD64,
  sixteen jobs. All sixteen original DB C cases and the two local RPC/XDR cases
  execute freshly and pass; source-settings is cached. Complete DB/RPC and the
  six prior installation contributions build. An independent comparison then
  correctly rejects DB's initial unsorted Kyuafile.
- bazel-libc-db-rpc-native-r3-20261105: corrected producer, all nineteen test
  targets pass as cache hits. Explicit inputs are
  bazel-libc-db-rpc-request-r1-20261105/inputs.json. The retained native r1 fails
  at Starlark parsing of an unparenthesized multiline dependency expression;
  no compilation/runtime success is claimed for it.
- bazel-libc-db-rpc-review-r3-20261105/review.json: complete independent comparison
  against the fresh original libc parent at
  bazel-libc-installation-make-r1-20261105. All nine program ELF identity,
  PIE/interpreter, ordered dependencies, dynamic symbols/versions and hardening
  contracts agree. Both original and native debug names/CRCs are checked.
  All 22 installed file records match owner/group/mode/tags/flags and inventory.
  Both Kyuafiles, the actual DB script and README agree byte for byte.
  Both h_testbits.h and h_testbits_xdr.c agree exactly with original Make products.
  Artifact/input hashes and original environments are bound; the record count is
  derived from the validated inventories. This does not prove raw program/debug
  equality, complete hermetic dependency closure or full ABI/semantic parity.
- bazel-libc-test-policy-preservation-r1-20261105/review.json: all eighteen
  archive/metadata/directory outputs from C063/inet/setjmp/termios/time/ttyio
  remain byte-identical to their prior passing capture after compiler-policy
  extraction and sorted Kyua policy. Thus old flags and installations are not
  silently changed by the shared helper refactor.

The first independent review fails on the Kyuafile order; the producer is fixed
rather than normalizing away that difference. Review r2 passes; r3 derives the
reported installed-record count from actual validated metadata. All byte and
ELF/debug comparisons stay enabled.

## Remaining qualification

The DB shell suite and its helper-driven dictionary/database scenarios are
installed, not executed here. The six external RPC service/network cases need an
isolated installed-system environment. DOF initialization is disabled in the
selected tests; no live trace/audit-delivery claim follows. Other libc test roots,
parent Kyua traversal, fixtures/helper DSOs, privilege/PTY/case-discovery coverage
and full installed-system runtime remain open. Full tests-enabled parent guards
remain intact. Raw whole-world/debug parity, other ABIs/options, bootstrap,
all pkgbase/hardware/publication and CPU/memory/disk/cache/sandbox gates remain.

The existing format-5 frontend target/test interface supports both contributions
and their declared generators. No C frontend, staging/signing/publication backend
or security-policy change is required. The normal Make sources are unchanged in
this batch. Make stays production/default; BIP is excluded. No host installation,
upgrade, reboot or service reconfiguration occurred.
