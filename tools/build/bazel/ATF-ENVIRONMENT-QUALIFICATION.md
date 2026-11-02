# Source-owned ATF environment qualification (2026-11-02)

`bsd_atf_test.test_environment` is an explicit string dictionary passed through
its existing RunEnvironmentInfo. Bazel supplies these values before the runner
starts; child programs inherit them. There is no new C launcher, inherited host
environment interface, Make interpretation, or frontend/SDK configuration API.
The empty default preserves existing rule behavior. This follows the documented
[RunEnvironmentInfo environment provider](https://bazel.build/rules/lib/providers/RunEnvironmentInfo).

The rule rejects malformed names and reserves generated BSD_ATF protocol keys,
Bazel TEST/RUNFILES namespaces and XML_OUTPUT_FILE, and the ATF, path, home,
temporary, library-directory and locale variables managed by the runner.
Callers cannot override those variables through this attribute. Explicit ordinary
program variables remain available; no secret or host environment is inherited.

Evidence under `/usr/obj/usr/src/`:

- `bazel-atf-source-environment-native-qualification-r2-20261102` passes thirteen
  native Bazel tests: eleven real analysis-failure tests for malformed/reserved
  attributes and two executable ATF cases. Both executable cases inspect values
  captured in a C constructor before the ATF main function. They share a binary
  but require distinct values containing spaces or an equals sign, and require
  DTRACE_DOF_INIT_DISABLE=1 at constructor time.
- `bazel-atf-source-environment-native-qualification-r1-20261102` retains the
  first twelve-test run before the additional XML destination rejection.
  `bazel-atf-source-environment-action-audit-r1-20261102` streams that original
  compact log with the upstream converter, verifies all 189 converter bindings
  before/after, and checks the two actual test-setup records' declared values.
- The PAM module-resolution tests consume the supported environment attribute to
  disable DOF registration before loading the native traced PAM library. Their
  original-source/compiler/install/runtime qualification is a separate candidate
  tranche; passing environment checks alone does not qualify those consumers.

The maintained build-bsd format-5 test API is sufficient; no C/backend, staging,
publication, signing or boot policy changes are required. These checks qualify
explicit environment delivery and rejection behavior. They do not qualify host
tracing, installed authentication, complete test hermeticity or system runtime.
