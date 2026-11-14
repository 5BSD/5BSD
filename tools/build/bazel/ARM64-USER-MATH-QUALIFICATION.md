# ARM64 math execution through BSD user-mode QEMU (2026-11-14)

## What was exercised

The installed `/usr/local/bin/qemu-aarch64` identifies itself as a BSD CPU
emulator. Retained probes execute the actual 47 ARM64 math test programs from
`bazel-math-suite-native-aarch64-r2-20261114`, their native libm/libutil, and the
captured native ARM64 runtime linker. Every target ELF execution/runtime input must
have machine AArch64. Libc, libsys and ATF come from explicitly hash-checked
frozen ARM64 R8 SDK snapshot files; this is not a native-produced runtime SDK.
The complete dependency closure is derived from actual ELF NEEDED entries.

All 47 actual `-l` listings match the source-declared registration, including the
original exclusion of `hypotl_near_underflow` for binary128 long double. All
462 listed bodies execute with ordinary ATF result files and the maintained
300-second body limit. DOF constructor registration is disabled exactly as in
the existing math test rule; live DTrace registration is not tested. Commands,
emulator hash, runtime hashes, stdout/stderr and raw ATF results are retained.
The probe uses the emulator's default CPU, bound by its executable hash; a
maintained interface must expose explicit CPU/runtime selection.

## Results and independent comparison

Native Bazel and independently built original Make programs **and** libm/libutil
produce identical outcomes and result-file diagnostics:

| Outcome | Bazel | Make |
| --- | ---: | ---: |
| Passed | 448 | 448 |
| Source-declared expected failure | 13 | 13 |
| Skipped: unsupported FP exception trapping | 1 | 1 |
| Unexpected failure | 0 | 0 |

Only the explicit original source-root prefix `/usr/src/` is normalized in the
comparison; raw diagnostics remain. Original Make artifact hashes are checked
against the earlier complete program/shared-library contracts. Expected failures
cite existing source conditions for FreeBSD bugs 290099, 283017 and 253984.
The skip is the source's actual FP-trap capability check. No test or math source
was changed to obtain these outcomes.

The strict exploratory reports R3/R5 retain status `failed` because they required
every body to pass. The separate review reports matched Make behavior; it does
not turn these 14 residual outcomes into passes or claim their bugs are fixed.

Ninety-four actual loader startup traces verify that every reported DSO is in the
declared private target runtime and has its recorded digest. A separate missing-ATF
control fails: the loader attempts the host default directory, then rejects its
AMD64 DSO as unsupported machine. This proves rejection in that control, **not**
filesystem confinement or an inability to attempt undeclared default paths.
Unsupported QEMU ioctl diagnostics remain in stderr.

## Evidence and remaining work

Under `/usr/obj/usr/src`:

- `bazel-arm64-user-math-probe-r1-20261114`: successful selected listing.
- `bazel-arm64-user-math-probe-r2-20261114`: successful selected body.
- `bazel-arm64-user-math-probe-r3-20261114`: complete native Bazel execution.
- `bazel-arm64-user-math-probe-r4-20261114`: retained comparison-driver schema error.
- `bazel-arm64-user-math-probe-r5-20261114`: complete original Make execution.
- `bazel-arm64-user-math-review-r1-20261114`: all outcome/diagnostic/hash/loader checks.
- `bazel-arm64-user-math-missing-runtime-r1-20261114`: actual missing-DSO rejection.

These are retained exploratory execution probes, not a maintained Bazel test
adapter. Integrate declared emulator, target loader/program/runtime inputs and
explicit execution-mode metadata before counting `bazel test` acceptance.
Do not label foreign-program execution as host-artifact-only inspection.
Keep host test runtime and foreign target DSOs in separate contexts.
Full ARM64 kernel/VM startup, authentication, services, installed system,
bootstrap, filesystem isolation and performance qualification remain open.
