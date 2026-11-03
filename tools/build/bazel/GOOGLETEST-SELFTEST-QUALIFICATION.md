# Native Googletest self-tests (2026-11-03)

## Added native build coverage

The four Make-selected directories now have native source-adjacent Bazel
program, test and installation declarations:

| Directory | Programs |
| --- | ---: |
| gtest | 8 |
| gtest_main | 16 |
| gmock | 1 |
| gmock_main | 15 |
| Total | 40 |

All 40 ordered C++ source lists (44 translation units) match independent
queries of the maintained Makefiles. Multi-file parameter, typed, production
and link tests retain their extra source files. Definitions, RTTI, C++17,
PIE, selected pthread use and component warning exceptions are modeled
explicitly. `tests/Makefile.inc` chooses `-O0 -g0` for empty DEBUG_FLAGS;
that default is the qualified configuration. Its unselected death-test copy
recipes are not silently added to GTESTS. Alternate DEBUG_FLAGS/configurations
remain work.

The existing native static framework bindings now also expose source-built
`libprivate{gtest,gtest_main,gmock,gmock_main}.so.0` targets. Their names and
`/usr/lib` location match Make queries. Framework link chains are explicit:
main libraries do not replace direct references to gtest/gmock from test objects.
This is functional shared-library evidence, not independent Make object/DSO
parity or complete framework installation qualification.

Private self-test sources and headers are explicitly exported from the parent
contrib source package, while the nested upstream BUILD files remain foreign
workspace definitions. Each test names its required private headers in srcs.
The include-roots helper contributes no unrelated public or private headers;
public framework headers come through the actual framework dependencies.

## Plain program reporting

Make registers these programs as Kyua `plain` tests. Their authoritative outer
result is the process exit status. Some framework self-tests deliberately run
zero tests or test failing inner assertions; their inner XML is not an outer
suite result.

The native `bsd_program_test` adapter now has an explicit `interface="plain"`
mode requiring its declared static program runner. It retains child XML at
`TEST_UNDECLARED_OUTPUTS_DIR/program.xml`; Bazel's standard test setup reports
the outer process. The runner still execs the actual program, preserving
arguments, nonzero exits and signals. It does not interpret or replace the
program's result. Default `native` mode preserves existing child XML behavior.

Bazel executes these programs directly under that plain contract; it does not
invoke Kyua for this run. Installed Kyuafiles retain the original Kyua plain
interface. No report-verifier check was weakened. Six runner controls cover
native/legacy XML compatibility, separate empty inner reports, nonzero exit,
signal propagation and rejection of invalid modes before child execution.

Thirty-nine raw inner XML reports are retained. One program supplies no inner
XML. These reports include self-test-specific behavior, disabled cases and
nested assertions; do not sum them into a claimed count of unique passing
external test cases.

## Tests and independent installation checks

Retained evidence:

- `bazel-googletest-make-selection-r2-20261103`: all 40 Make selections and
  ordered source lists match the final native declarations.
- `bazel-googletest-selftests-r4-20261103`: all 40 self-test targets and the
  runner-control target execute freshly and pass. The control log reports six
  unittest methods. XML reports 41 outer cases, not every inner framework case.
- `bazel-googletest-selftests-r8-20261103`: final header declarations and install
  payload build pass; all 41 tests are cached passes from that fresh execution.
- `bazel-googletest-install-review-r3-20261103`: source hashes, 39 inner reports,
  45 install entries, original Make Kyuafiles, framework SONAME/directory queries
  and explicit fresh/cached result accounting.
- `bazel-googletest-header-actions-r2-20261103/review.json`: normal/PIC configured
  compiler input variants for four representative programs have exactly their
  required private headers. This is action declaration evidence, not an executed
  source-edit incrementality experiment or sandbox proof.
- `bazel-python-runtime-audit-r3-20261103`: both complete offline native queries
  pass with staged source definitions unchanged. There are 97,566 declared
  rules, including 104 Python/host-artifact test rules backed by 68 scripts.
  These remain metadata counts, not unique programs or successful builds.

All directories above are under `/usr/obj/usr/src`. The maintained frontend
used 16 jobs, the frozen SDK, pinned offline repositories and disk reserves.
Bazel timing/client rusage and filesystem free-space samples do not establish
aggregate compiler/JVM CPU, RSS, disk-I/O or comparative performance.

The install manifest contains 40 stripped programs (root:wheel 0555) and five
Kyuafiles (root:wheel 0444), all in package=tests. No default debug entries are
invented where Make has MK_DEBUG_FILES=no. Four generated child registrations
preserve Make's alphabetical ordering. The parent uses the exact maintained
`tests/Kyuafile` auto-discovery source, preserving extensibility and its license.

Earlier failures remain retained: r1 source discovery, r2 incomplete framework
link chains, r3 empty inner XML, and r6 a missing cross-framework private header.
Independent installation review r1 caught ordering and parent-discovery mismatch;
those were corrected before the final qualification. A diagnostic aquery first
used the host wrapper's JDK default and failed; the corrected query explicitly
selects the staged JDK. The maintained frontend already selects that environment.

## Frontend and remaining gates

The normal format-5 build-bsd backend consumes these native targets without new
C frontend options, one-off build replacements, or Make translation at build
time. The generic program-test backend and its regression tests are updated in
this change. Staging/signing/publication and the frontend manual need no new
interface. No signing, secure boot or compromised-root protection is qualified.

This checkpoint covers default amd64 self-test build/execution and the selected
installation records. Framework header/archive/shared/debug installation,
independent Make compiler/object/link comparison, alternate flags, ARM64/RISC-V
execution, installed-suite execution and pkgbase package parity remain open.
The new test install manifest is a component artifact; this does not establish
whole-world package aggregation. No production daemon implementation or probe
changed. Full world/kernel/module/package/bootstrap/sandbox/runtime/performance
qualification remains open. Make remains production/default; BIP remains out
of scope.
