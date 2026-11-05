# Eight-family native production composition (2026-11-05)

## Selected construction milestone

The maintained build-bsd frontend now qualifies one combined AMD64 request for
all eight currently composed production families, including their selected
internal library outputs. NIS, sendmail, printing, FDT, bootparamd and the legacy
updater are explicit enabled qualification inputs; installed tests are disabled,
with tests_support and Kerberos support explicitly enabled. This is an unsigned
selected build/test profile, not a complete installed or verified-boot system.

| Native family | Installation archives |
| --- | ---: |
| bin | 42 |
| sbin | 74 |
| libexec | 26 |
| usr.bin | 271 |
| usr.sbin | 368 |
| lib | 232 |
| cddl | 37 |
| secure | 21 |
| Total | 1071 |

These counts are installation archive contributions, not programs, converted
directories or completion percentages. Native parent declarations select actual
producers; the qualification request is not a replacement world definition.
Remaining roots must be composed before a complete world endpoint can pass.

## Actual integration failures and corrections

The first combined build compiles the complete selected graph, but three SSH
configuration tests fail at loading libwrap: their declared runtime supplies the
NIS-disabled bootstrap libc despite linking against the selected native NIS ABI.
The retained error names yp_get_default_domain@FBSD_1.0. The test bodies, expected
results and program links remain unchanged. nis_runtime_libraries now selects
the declared native libc/libsys pair for NIS, retaining the original explicit SDK
pair for default consumers. SSH configuration and direct SFTP tests use this
shared runtime selection. It is dependency correction, not relaxed test checking.

The second attempt passes all 34 selected tests, but immutable capture rejects
missing libsm test executable files. A cached test result does not itself prove
its executable has been materialized in the current output tree. Promoting the
suite members to explicit test-command targets and an explicit default output
group did not fix the observed behavior; those experiments are not retained
as implementation. A standard Bazel build of the same configured test target
materializes its executable and passes the unchanged capture verifier.

The qualification driver therefore records a normal build of the configured
compatible test leaves after successful testing. SDK, platform, feature, cache
and compilation flags are unchanged. The test command's original BEP digests
must still match every frozen output; no missing artifact is omitted, replaced
with a prior capture, or assigned a manufactured digest. Test caching remains
enabled, and the materialization build executes no tests again. Both commands,
timing, independent BEP and execution-log hashes are retained. The driver uses
standard [Bazel build/test commands](https://bazel.build/reference/command-line-reference);
the missing-output observation and correction are established by the actual
local probes, not inferred from documentation alone.

## Retained evidence under /usr/obj/usr/src

- bazel-eight-families-native-r1-20261105: actual combined construction with
  31 passing and three failing selected tests. Failed SSH logs and inventory
  are frozen in failure-test-reports; no passing qualification receipt exists.
- bazel-eight-families-native-r2-20261105: all 34 selected tests pass, including
  the corrected SSH/SFTP runtime, but capture rejects missing test_strl.
  r3 retains the ineffective target-promotion attempt and the same capture
  failure for test_match. Neither is accepted as qualified.
- bazel-cached-test-output-probe-r1-20261105 retains the explicit-default-group
  test attempt; r2 records an ordinary build of the same target and successful
  immutable capture. It uses the exact existing SDK/profile and public Bazel
  commands, without a replacement executable or cache disabling.
- bazel-eight-families-native-r4-20261105 passes the complete request through
  normal build-bsd with sixteen jobs. All 34 selected test targets pass. Its
  capture freezes 2215 unique files, 1785783593 logical bytes. That byte count
  is capture content size, not physical disk usage or a performance measurement.
  The separate test_artifact_build receipt field records the exact configured
  leaves and companion BEP/execution-log hashes.
- Its test-artifact-build-review.json verifies preservation of the original
  command's full SDK/platform/feature/cache flags, exact configured test target
  inventory, companion log hashes, absence of new test execution in the build
  phase, and hash-verified captures of all five formerly missing libsm programs.
- bazel-eight-families-namespace-r1-20261105/review.json hash-verifies every
  captured archive/request pair and reconciles all repeated filegroup archive
  selections. The 1071 unique archives claim 23156 distinct non-directory
  destinations, with zero conflicting file claims. Explicit directory claims
  are retained but not accepted as complete directory ownership reconciliation.
  This is complete namespace checking for these captures, not original Make
  installed-world/payload equivalence or pkgbase acceptance.
- bazel-secure-runtime-default-regression-r1-20261105 passes the NIS-disabled
  secure parent and all twelve selected runtime tests with the final driver.
  Its production-regression-review.json binds all 86 unchanged production
  output entries to the earlier accepted secure r3 capture. The new optional
  runtime selection does not change those default installed payloads/metadata.

## Frontend and remaining completion gates

This fixes the maintained qualification backend and documents its extra standard
Bazel build phase; no new user flag, C dispatcher or schema input is required.
The normal format-5 workflow carries both optional runtime settings and all
selected native targets. The manual and completion plan are updated. Signing
and publication behavior are unchanged.

Remaining world roots, full installed tests/metadata/payload/debug/pkgbase parity,
other architectures/configurations, kernel/module install/package integration,
independent reproducible bootstrap, hardware/verified combined publication, real
login/PAM/SSH/boot/runtime and comparative CPU/RAM/disk I/O/footprint/cache/sandbox
qualification remain required. A collision-free selected namespace and passing
bounded tests do not close these gates. Make stays production/default. BIP is
excluded; no host installation, upgrade, publication or reboot is performed.
