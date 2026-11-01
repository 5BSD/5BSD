# Core DTrace module migration: reference checkpoint

2026-11-01. Native Bazel conversion of core dtrace, fbt, kinst and dtraceall is
still pending. This checkpoint establishes independent Make references and
fixes one genuine generated-input omission. It does not qualify native module
artifacts, runtime tracing, complete kernels or performance.

The maintained Make queries select eight source entries for core DTrace on each
supported architecture, including one architecture-specific assembly source.
FBT selects two C sources, kinst three, and the aggregator one. Actual source
paths vary by architecture. Core DTrace additionally generates assym.inc and
offset.inc; native conversion must use genuine target-generated constants and
preserve per-assembly flags, warning policy, compatibility/header precedence,
textual source fragments and original object order.

Initial references under /usr/obj/usr/src/bazel-dtrace-core-make-20261101 passed
18 of 24 builds. All six core DTrace builds failed because the embedded
dtrace_db.c debugger implementation includes linker_if.h, but the module did
not declare this generated interface. AMD64 reaches the fragment through ISA
code; ARM64 and RISC-V reach it through dtrace_immstack.c. The maintained
module SRCS now declares linker_if.h, allowing the original Make generator to
produce it. No source fragment is rewritten or compiled as an extra translation
unit. No C source or runtime ABI was changed.

All 24 fresh corrected Make build/install references passed under
/usr/obj/usr/src/bazel-dtrace-core-make-r2-20261101: four modules, amd64/ARM64/
RISC-V64, plain and CTF/debug modes. Header-only KERNBUILDDIRs contain copied and
hashed genuine GENERIC option headers; no old generated interfaces or kernel
objects can hide the missing dependency. Each module generates its actual
constants/interfaces. Four independent jobs use -j4 each on this sixteen-CPU
host. Original failures and corrected commands/stdout/stderr/install metadata
remain retained. Discovery inputs and helpers are recorded in
/usr/obj/usr/src/bazel-dtrace-core-reference-review-20261101.

The ordinary build-bsd Make backend uses the corrected maintained module rule;
no new frontend C/CLI, source policy, signing, staging or publication input is
needed for this dependency correction. Future native declarations and their
actual qualification results will extend this document. No host module,
tracing session, service or installed system state changed. Make remains
production/default; BIP is excluded.
