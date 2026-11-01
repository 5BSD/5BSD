# notifyctl native Bazel candidate

2026-11-01. This records a component candidate, not complete world, kernel,
pkgbase, tracing, bootstrap or performance qualification. Make remains the
production backend.

## Native declarations

`//usr.sbin/notifyctl:notifyctl` owns the two production translation units and
links native libnotify and libucl shared targets. The policy source and headers
come from the existing BSDNotify daemon package; there is one parser
implementation. Narrow exports retain the daemon's existing test consumers.

`//usr.sbin/notifyctl/tests:notifyctl_test_run` builds and executes the maintained
ATF shell program, with the real static helper, the maintained fake-service
helper, the ambient-route-clearing helper, and both configuration fixtures as
explicit suite inputs. The fake uses the maintained source-including wrappers;
the original sources are declared textual headers. The graph does not synthesize
BUILD files or invoke Make. `:install_archive` includes the program, separate
debug files, manual and the complete test installation when tests are enabled.

The new component has a FreeBSD OS constraint and no unnecessary CPU constraint.
Its existing native dependencies and prepared SDK are currently qualified only
for amd64; this does not establish ARM or RISC-V builds.

## Evidence

The initial maintained frontend run is
`/usr/obj/usr/src/bazel-notifyctl-qualification-20261101/receipt.json`.
All eleven ATF cases executed and passed with no skips. They cover policy
validation, malformed configurations, arguments and limits, successful fake
commands, tier selection, operation errors and broker unavailability. These
cases do not establish a live daemon session or authorization under a matching
kernel. The Kyua adapter's documented host shell/ancillary-tool execution limits
remain.

The independent Make build and complete staged installation are at
`/usr/obj/usr/src/bazel-notifyctl-make-20261101/`. Review scripts and full reports
are retained at `/usr/obj/usr/src/bazel-notifyctl-parity-20261101/`.
All nineteen component installation records match destination, type, owner,
group, mode and pkgbase tags. The compressed manual, maintained ATF shell script,
Kyuafile and configuration payloads match bytes. All four installed binaries have
valid CRCs and names referring to their respective separate debug files, on both
sides. This verifies split-debug linkage, not whole DWARF identity or debugger
source resolution.

The production executable's imported/exported symbol contracts, ordered dynamic
dependencies, hardening and every ELF section match Make except `.gnu_debuglink`.
That CRC refers to different debug-file bytes. Whole executable byte identity is
not claimed. All three static helpers have equal global symbol inventories, but
whole static ELF parity remains open for the reasons below.

## Inherited static DTrace archive difference

The experimental static archive integration retains DOF together with its
original traced translation unit. Inspection of the actual response files and
archive member list confirms ordinary archive extraction, rather than forcing
all libservice members into the executable. The staged Make archive instead
places libservice DOF and its registration in a separate provider member. Code
members define weak probe symbols, so linking ordinary code can leave that
provider member unextracted.

Normalized schema and instruction-site audits report:

| Helper | Native schemas | Make schemas | All Make schemas retained |
| --- | ---: | ---: | --- |
| notifyctl_test_bin | 76 | 26 | yes |
| notifyctl_success_bin | 12 | 12 | yes |
| no_ambient_exec | 27 | 26 | yes |

Both sides pass all inspected amd64 function-range and patched instruction
checks. Exact schema parity passes only for the fake helper. For
`no_ambient_exec`, the additional schema is `service_ambient`; its additional
registration accounts for one extra init/fini entry and 1,008 text bytes. This
is consistent with the previously recorded capsulectl/logctl/networkcmpctl
archive discrepancy. Full section differences and both complete DOF inventories
are retained. No probe was removed to match the reference.

The central static archive design still needs live provider registration and
firing checks, a decision on intended static-provider semantics, and CPU, memory,
disk and binary-size measurements. Per-member registration can retain multiple
copies of the registration routine. Its cost has not been qualified. This
conversion does not resolve that central design/performance gate.

## Frontend review and remaining gates

The maintained format-5 `build-bsd bazel-test` interface selects these native
labels and the existing typed tests setting. No new frontend argument, security
policy, signing, staging, publication or manual contract is needed. Component
installation uses the maintained shared helpers. Production remains Make.

Source mutation invalidation, live service behavior, source-level debugger
checks, remote-cache/bootstrap portability and comparative
CPU/memory/disk performance require separate evidence. BIP remains out of scope;
no system installation, upgrade, reboot or VM start is part of these checks.

## Tests-disabled composition and unchanged repeat

The final OS-constrained declarations also pass maintained `build-bsd` at
`/usr/obj/usr/src/bazel-notifyctl-cache-qualification-20261101/`.
The initial run of this configuration restoration recomposed one installation
archive and reused the test report; it is not claimed as a zero-action repeat.

Tests-disabled native composition passes at
`/usr/obj/usr/src/bazel-notifyctl-notests-qualification-20261101/`; the maintained
Make `install-reference.py` baseline is
`/usr/obj/usr/src/bazel-notifyctl-notests-make-20261101/`. All five component
installation records match and the archive contains no notifyctl test payload.
The comparator and result are in
`/usr/obj/usr/src/bazel-notifyctl-notests-parity-20261101/`.

A subsequent strictly unchanged enabled run passes at
`/usr/obj/usr/src/bazel-notifyctl-cache-repeat-20261101/`. It has an empty execution
log, zero external spawns, one internal action and identical retained artifact
hashes/modes/sizes. Its eleven-case test report is reused; the test bodies
executed in the original run. The parity directory's `cache-review.json` records
the comparison. This establishes local unchanged-input reuse, without proving
source mutation, remote cache or independent bootstrap behavior.
