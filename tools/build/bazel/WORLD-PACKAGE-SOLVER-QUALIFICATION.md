# Complete world package solver qualification (2026-11-06)

## Maintained Bazel test

//:world_package_solver_test consumes the actual world_packages outputs, exact
package index and selected family catalogue. It validates archive membership and
hashes, creates a private unsigned file:// fixture catalogue with the declared SDK
pkg, and imports it into a fresh empty alternate root. ABI comes from the declared
target ELF; OSVERSION comes from sys/param.h. No host ABI/version exemption is used.
Every selected package name is supplied to a real pkg install -n dry-run. The test
requires an exact complete plan, zero conflicts, an unchanged source package set,
no installed payload trees and an empty actual pkg installed inventory. Nothing is
installed; package scripts, plugins, triggers and automatic repository updates are
disabled. This is dependency/conflict solver evidence, not actual installation.

The rule declares its interpreter/tool/runtime inputs and a host artifact execution
group. Target ELF files are inspected, not executed. No manually selected package
list, fixed package count, source Make parser or target program substitution is
used. Copied package archives, catalogue databases and the empty root live in
TEST_TMPDIR; retained outputs contain the command/configuration records and logs.
This avoids archiving another complete package copy with every test result.
The complete command record is printed into the hash-bound captured test log.

The final default AMD64 run passes all eight requested test targets. The solver
imports and plans all 445 packages with zero conflicts and reports zero installed
packages. Independent review resolves the actual selected catalogue from immutable
qualification outputs, verifies the complete install argument list and -n flag,
and checks effective configuration hashes and the empty inventory result. The
final test-only refinement executes zero package construction actions.

## Private root path correction

pkg -r relocates its default filesystem paths. An explicit PKG_DBDIR or PKG_CACHEDIR
override is a host pathname, so -o PKG_DBDIR=/var/db/pkg does not name the alternate
root's database. Initial unprivileged exploratory catalogue attempts failed their
access checks before catalogue update. Those failures are retained; they are not
passing private-root tests. The corrected command uses complete absolute paths
under the new private root and the actual INSTALL_AS_USER environment interface.

The maintained private-package-install-test.py helper had the same incorrect
explicit path assumption. It now constructs the correct private database/cache
paths, creates their directories, and checks actual pkg config output before any
mutating package command. The maintained solver test imports that exact command
builder and probes both effective paths with the actual SDK pkg. It also uses
pkg's own inventory query rather than an optional Python SQLite extension. The
root-shell helper now rejects both shell and Lua package scripts, disables
triggers/automatic repository updates/syslog, and still requires OS root for
actual add/check/delete. That privileged path has not been run in this step.

Other matching explicit /var/db/pkg paths in deploy.py, database_construction.py
and construction/pkg_registration.py were inspected: they execute inside a chroot
or private jail and are already relative to that isolated /. They require no
alternate-root path rewrite. No host package operation was performed.

## Evidence

All paths are relative to /usr/obj/usr/src. No publication pointer advances, host
installation, host upgrade or host reboot. The unsigned test catalogue is a private
fixture, not an installation/update repository or combined publication result.

- bazel-world-pkg-solver-native-r5-20261106/receipt.json
  SHA256 ead54275112c8a2bfb71d26edbc62a3c15642516d7b8166e0df897d5eb3a51d1
- Its test-reports/manifest.json
  SHA256 2315b533afa3752e3bed764daa836176681b63be3f17dd9d7f453f0f06291b25
- The captured //:world_package_solver_test log
  SHA256 1107fd2af54de7049d781a33ae4b714161d88cffc48a4dce1220fb27f72d3486
- bazel-world-pkg-solver-review-r1-20261106/review.json
  SHA256 561fbc7e79b9a4c5c7cd3d39c103e3f4519646ab72665457a0158136fc977448
- Its extracted solver-report.json
  SHA256 edea17a741aa1e0052ec3eb4f8f42ca4813d726a46adb9e072a01bd01b31d1f6
- bazel-world-pkg-solver-r3-20261106/review.json
  SHA256 797ce79b6b60b1cb748d82a231a628db5ac7a5b1b6e406429f3f303fab5ffbb9
  (earlier exploratory full solver control, not the maintained final test)

Additional retained inputs/failures: bazel-world-pkg-solver-request-r1-20261106,
bazel-world-pkg-solver-r1/r2-20261106 and native-r1/r2/r3/r4-20261106. Native r1
lacked the explicit driver export; r2 exposed an optional _sqlite3 module import.
The final checker uses the declared pkg inventory API, preserving the empty-state
assertion without an undeclared Python extension dependency. The failed r2 test
log is retained separately before later test executions replaced mutable logs.

## Frontend and remaining work

Existing format-5 target/test inputs select the new maintained root test through
build-bsd. Backend rules, tests, helper, manual and README are updated; no new C CLI
input, signing/verification mode, staging/publication contract or Make/ports default
is introduced. The standard combined publication location stays
/usr/obj/usr/src/repo with separate hardware staging and /usr/obj/5BSD-ports.

NEXT: privileged fresh installation and update/ownership/state tests inside a
disposable disk-backed VM, with declared construction inputs and real package
scripts. Account-name resolution must use the intended target account database;
a minimal bootstrap root's accounts must not stand in for installed-system users.
Then qualify normal startup/services and native kernel/module packages. The
existing daemon-runtime fixture can test package mechanisms but cannot establish
normal Capsule startup. Preserve that distinction in the evidence.

No current result closes installed numeric ownership, fresh/update construction,
script execution, service operation, independently Make-built world/debug parity,
cross-platform/bootstrap/cache/sandbox/reproducibility, CPU/RAM/disk I/O/footprint,
or combined base/hardware publication gates. Make stays production/default; BIP
stays excluded.
