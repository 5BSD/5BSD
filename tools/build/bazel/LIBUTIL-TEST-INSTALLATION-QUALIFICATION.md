# libutil original tests and installation qualification

This cohort supplies the twelve original libutil test programs and their
installation subtree. Make remains the production/default world builder. It
uses the maintained build-bsd format-5 frontend, current frozen SDK, declared
native dependencies, compact execution records and immutable captures.

## Original ownership and source correction

The original lib/libutil/tests/Makefile selects six TAP programs and six ATF
programs, comprising sixteen compilation units. The two login-policy programs
retain their direct production-source compilation and exact linker wrappers.
Source owners narrowly export those translation units and the actually consumed
public/private headers. The original ordered direct object inputs and ATF/util
shared dependencies remain explicit.

Source review found a real failure bug in test_flopen_lock_child: failed fork
continued to the lock assertion, overwrote the fork error, and called
kill(-1, SIGINT). The correction guards the assertion and signal with pid > 0.
A safe original/corrected control replaces fork with EAGAIN and wraps kill so it
never sends a signal. Original code records one call with PID -1 and loses the
fork error; corrected code records no kill and preserves EAGAIN. A permanent
TAP regression checks both properties; successful original test behavior is
also exercised. No process-wide signal or credential-changing call ran.

## Compiler and ELF proof

A fresh maintained original component build/staging reference records all 68
library and 16 original test compiler contexts. Supplemental pre/post bindings
cover 310 preexisting files, including external libc getcap.c. All 96 fresh
original dependency files and 4,548 absolute consumed occurrences reconcile to
those bindings with no missing input. This supplements rather than replaces
the maintained reference's stated hermeticity limits.

The original baseline remains retained. A separate original Makefile control
includes the unchanged owning Makefile and appends one explicit compiler
-fmacro-prefix-map=/usr/src/= option. All sixteen actual vectors match the
originals except that flag, including their original -MD/-MF/-MT flags; the
control uses the separately reviewed corrected flopen source. No native source
path workaround or output rewriting is introduced.

All sixteen installed-program native compiler records preserve the original
ordered warnings, defines, optimization/debug/PIE/stack policy and source
identities. Their 740 consumed input occurrences independently match the
original control, including digests bound to actual action inputs and actual
native dependency files. All sixteen code, allocated sections and nondebug
relocation sections are exact. The twelve actual ordered object/library/wrapper link vectors match original
Make; all six TAP qualification objects are whole-byte identical to production.
All twelve final production executables also
have every allocated section exact against that original control. Strict raw
baseline and controlled differences remain recorded.

Seven DWARF sections differ in every full executable. Separate Make/native
DWARF equality and source lookup are not qualified. The actual twelve native
split/strip pairs preserve all allocated payloads and native DWARF sections;
all twelve debuglink names/CRCs match their actual separate debug files.

## Tests and environment contract

The native profile passes 31 explicit test rules: twenty original ATF cases,
six original TAP programs, the safe fork-failure TAP regression, a constructor
environment TAP regression and three existing clean-environment Kyua cases.
The six TAP programs run through real declared SDK Kyua and its result parser;
program exit status alone cannot establish TAP success. ATF programs use the
maintained ATF adapter, native declared shared libraries and original case
names. The forkpty failure case retains its unprivileged-user requirement and
changes only its isolated process resource limit.

TAP runtime qualification variants add an explicit inherited $ORIGIN RPATH so
the existing loader checker binds the declared native util and frozen SDK
libc/libsys. Installed program link policy does not receive that test-only
RPATH. Native ATF runtime libraries are supplied by the existing adapter.
DTRACE_DOF_INIT_DISABLE=1 reaches runners and children before constructors.
Tests use private scratch paths; no host configuration or installation changes.

The existing Kyua rule silently ignored test_environment when
clean_environment was false. It now returns RunEnvironmentInfo for that
existing attribute in the inherited-environment mode. Default empty and explicit
clean modes preserve their prior behavior. The new TAP fixture observes the
declared value in its constructor and also checks an unrelated inherited Bazel
workspace variable. No environment scrubbing is added. Its intentional wrong
value produces TAP failure despite exit status zero; that failure is retained.

## Installation and selected options

The component manifest includes the original tests subtree only with TESTS
selected. It declares 25 files: twelve programs, twelve separate debug files
and the original byte-exact generated Kyuafile. Five test/debug directories
retain their separate package=tests and package=tests,dbg ownership contexts.

The complete archive matches all 154 distinct original component logical
records for paths, types, owners, groups, modes, package tags and link policy.
Forty-four duplicate original directory records are identical. Original manual
hardlinks are independently checked by their staged inode identity. Every
regular archive payload matches its immutable captured native source. This is
an installation archive, not a final pkgbase package or host installation.

The TESTS-off profile omits the test subtree and its five directory records;
its retained runtime/dev records preserve the same policy. Other feature,
architecture and debug-mode combinations are not claimed.

## Maintained workflow and limits

Existing build-bsd targets/tests and installation/archive rules carry the
cohort. No build-bsd C/backend API, signing, publication, package-construction
or host-install policy changes are needed. The manual records the existing
Kyua attribute's corrected behavior and the original test/install scope.

Independent full libutil library/debug/ABI parity, experimental section mode
coverage for this newly installed test closure, general source/debug lookup,
DTrace host-provenance/cache hermeticity, live probes, world/rescue/pkgbase,
bootstrap, hardware/publication and performance remain separate gates. No host
installation, upgrade or reboot occurred.

## Evidence

Under /usr/obj/usr/src/:

- bazel-libutil-test-install-make-reference-r1-20261102: original component,
  recipes, staged installation, METALOG and reference receipt.
- bazel-libutil-test-install-reference-review-r1-20261102: supplemental before/
  after source/dependency bindings and complete fresh reconciliation.
- bazel-libutil-flopen-fork-failure-controls-r1-20261102: safe old/new controls.
- bazel-libutil-tests-filename-make-control-r1-20261102: independent original
  control and sixteen exact-vector audits with one explicit added map.
- bazel-libutil-test-install-native-qualification-r1/r2-20261102: retained
  analysis rejections (duplicate existing export; runtime-checker visibility).
- bazel-libutil-test-install-native-qualification-r3-20261102 and corresponding
  native-action-collection-r3: accepted tests/artifacts and fully drained,
  tool-bound compact log with actual objects/dependencies/link parameters.
- bazel-libutil-test-install-object-review-r2-20261102, linked-review-r1,
  linked-baseline-review-r1, layout-review-r2 and debug-review-r1: strict
  compiler/input, ELF, installation and native split/CRC reports. Initial
  observer prefix/suffix mistakes remain retained separately.

- bazel-libutil-test-install-link-review-r1-20261102: twelve actual ordered
  links, their input digests and six exact production/qualification object pairs.
- bazel-libutil-test-environment-negative-qualification-r1-20261103: intentional
  failed TAP assertion with process status zero; immutable failed XML/log.
- bazel-libutil-test-install-off-qualification-r1-20261103 and off-review-r1:
  selected TESTS-off archive and exact remaining 124-record/payload comparison.
- bazel-libutil-test-install-review-r1-20261103: final source bindings, retained
  external observers, command profiles, summary and manual lint comparison.
