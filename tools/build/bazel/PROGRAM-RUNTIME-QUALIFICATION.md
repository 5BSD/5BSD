# Explicit program test runtimes (2026-11-03)

## Correction

The `ctladm`, `ctld`, `iscsid`, `ntptime`, `tcpdump` and `virtiofsd` Python
harnesses previously inherited the SDK interpreter's library path. This could
mix Python execution libraries with source-built program dependencies. The LLD
regression established that such inheritance can select the wrong shared
library even when the executable has a source-build RUNPATH.

Each selected test now declares a `test_program_runtime` filegroup as target
`data` and passes its actual output locations through Bazel's standard args
expansion. The harness selects only those directories for its program children
and removes inherited preload settings. The Python interpreter keeps its
execution-configured SDK runtime. This also avoids configuring source program
libraries as Python execution-runtime inputs. tcpdump retains its configurable
OFED library selection; the selected-default run does not qualify OFED-disabled
or other option combinations.

A new loader-trace check in each test requires every reported startup shared
library to resolve to an explicitly declared runtime file. The original help,
side-effect and offline decoding assertions remain unchanged. No executable
implementation, probe or shared Python runner changed.

This is explicit per-program dependency selection, not filesystem sandboxing.
Runtime-loaded plugins, NSS modules and other `dlopen` paths require their own
exercised cases. Startup loader traces cannot establish those closures.

## Qualification

Evidence: `/usr/obj/usr/src/bazel-explicit-program-runtimes-r1-20261103`.
The maintained `build-bsd bazel-test` format-5 workflow used all 16 logical CPUs,
the frozen native SDK, pinned offline repository inputs and the disk reserve.

All six targets executed freshly and passed. The retained unittest logs show
16 passing methods: six loader checks and ten original behavior checks. Bazel's
fallback XML counts six wrapper-level cases, not sixteen individually reported
XML cases. BEP confirms zero cached test results. `program-runtime-review.json`
binds the twelve changed BUILD/Python source hashes, logs and method counts;
`qualification-inputs.json` preserves the selected frontend configuration.

The run includes real source program/library build actions. Bazel reports
102.704 seconds elapsed, 603 action cache hits and 2,441 total actions, including
internal actions. Its client `time -l` RSS and I/O are not aggregate compiler/JVM
resource measurements. The disk guard reports initial/minimum/final free space;
these are not comparative disk-I/O benchmarks. No performance conclusion is
made from this run.

The tests exercise help rejection for five programs and tcpdump decoding of
private capture files. They do not start services, open live capture devices or
modify the host clock. This is not complete iSCSI/CTL/NTP/virtiofs service runtime
qualification, a complete world, package validation or cross-platform execution.

## Frontend and remaining audit

No C frontend option, backend target, signing/staging helper or manual interface
changes are needed: the maintained native frontend already consumes these test
rules and declarations. No signing, secure boot or compromised-root protection
is tested. Make remains production/default.

The repository-wide inventory covers 67 Python scripts. Six selected scripts
now have explicit program runtimes; the remaining tool calls still need manual
review. Some inherited environments are intentional: SDK archive tools have
explicit SDK runtime declarations, and nested `sys.executable` needs Python's
runtime. The ATF cleanup test's host `cc` call is its standalone path; inside
Bazel it uses the declared native runner. AST call counts alone must not be
reported as proven runtime defects.
