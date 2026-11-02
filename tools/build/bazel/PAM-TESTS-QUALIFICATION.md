# Original PAM test producers and safe execution (2026-11-02)

## Native ownership

The maintained tests Makefile selects seven original programs. Native rules now
build all seven and install their original names, debug files and Kyuafile under
`/usr/tests/lib/libpam`, package pam-tests. The previously missing producers are
module_resolution_test, policy_include_test and lastlog_session_test. Their
original production C fragments are explicitly declared at their existing
OpenPAM/pam_lastlog source owners; no source bodies or assertions are changed.

All seven declarations use the maintained Make warning, language, macro, stack,
optimization and PIE policies. This also corrects the older four declarations.
Actual per-object recipes, rather than only aggregate CFLAGS queries, establish
the PIC macro. The source-owned dependency ordering matches Make's ATF-before-PAM
ordered NEEDED vector, including crypt for the password test. Original Kyua
program ordering, required_configs, timeout and root requirements are preserved.

The existing normal build-bsd format-5 API builds installation targets and runs
source-owned suites. No frontend C/backend, staging, signing or publication API
is added. Make remains production/default. The separately qualified
ATF-ENVIRONMENT-QUALIFICATION.md mechanism explicitly supplies
DTRACE_DOF_INIT_DISABLE=1 before safe runner/test startup; this does not change
production binaries or their probes. The embedded lastlog test source retains
Make's test-specific flags, which do not enable the production module's DTrace
compilation option. Production module/provider declarations remain unchanged.

## Independent controls and immutable comparisons

Evidence paths below are under `/usr/obj/usr/src/`.

- `bazel-pam-tests-libpam-make-r1-20261102` builds a fresh shared PAM reference.
  `bazel-pam-tests-make-r4-20261102` builds/installs the original seven programs
  with supported Make recipe metadata. Its explicit, recorded LIBPAM and
  LDADD_pam assignments bind both prerequisite and actual link selection to that
  fresh shared library. No arbitrary-variable channel is added to the maintained
  reference helper. Source/profile/include checks pass; this reference is not a
  complete hermetic dependency closure.
- `bazel-pam-tests-native-qualification-r4-20261102` passes the maintained native
  frontend with compact logging, 16 jobs and recorded disk-reserve guard.
- `bazel-pam-tests-final-elf-audit-r3-20261102` checks all seven captured installed
  program payloads against Make using the unchanged strict ELF checker. PIE,
  interpreter, ordered NEEDED, hardening, imports/exports and version requirements
  match. Full executable byte identity is not claimed.
- `bazel-pam-tests-install-audit-r3-20261102` verifies all twenty unique original
  file/directory records and exact original Kyuafile bytes. Fifteen file payloads
  comprise seven executables, seven debug files and registration. All fourteen
  native/Make debug CRCs validate. Twenty-four repeated identical Make directory
  lines are retained; differing records are never collapsed.
- `bazel-pam-tests-compiler-audit-r4-20261102` binds nineteen demanded object
  outputs to their nineteen corrected records within forty-two actual retained
  compiler records across the attempts, current output hashes, exact Make
  policies and 1,006 original prerequisite
  hashes. These are actual consumed dependency-file bindings, including the
  explicit byte-identical source-owned ATF header namespace. Four shared-source
  Make recipes omit -MD; `bazel-pam-tests-missing-dependency-control-r3-20261102`
  replays their hash-bound original compiler commands in dependency-only mode,
  with identical semantic flags/CWD and unchanged original objects. Those
  additional controls are explicit, not invented original .depend files.
- `bazel-pam-tests-object-audit-r5-20261102` verifies exact allocated object payload
  outside mergeable strings, complete string multiplicities, and 2,310 non-DWARF
  symbolic relocations across all nineteen objects. Seven source diagnostic
  filenames differ by the literal `/usr/src/` prefix; comparison expresses only
  those complete strings and their verified local string-symbol lengths as a
  common identity. No binaries are rewritten. Relocation sites, kinds, symbols,
  sections, values, sizes and addends otherwise match. Linked section/layout and
  debug-link differences remain recorded in the strict ELF reports.

The original ordered-NEEDED rejection, missing PIC macro rejection, initial
observer missing-tool/dependency/report-variable errors and exact diagnostic
string-size differences remain retained. Later passes use corrected declarations
or observers and fresh references; no strict production checker is weakened.

## Runtime coverage and open gates

`bazel-pam-tests-runtime-audit-r2-20261102` binds the final fourteen passing Bazel
wrapper results to actual test-setup records, explicit pre-startup DOF opt-out,
native linker output hashes and declared native module fixtures. They cover
seven original module-resolution cases, three dispatch cases, two Unix cases and
the original malformed-Kerberos-config case instantiated for two native modules.
Cached results and actual action runner/cache fields remain distinguished in the
retained records. No host module fallback or authentication configuration change
is used. Test bodies retain their original filesystem/permission assertions.

Nine policy-include cases require the native module at normal installed paths;
the accounting case requires guest root and creates five child chroots. Their
original bodies, declarations and metadata are built/installed but these ten
cases are unexecuted guest gates. No host chroot, account, SSH, login or PAM policy
is changed. Remaining gates include disposable guest execution, full PAM family
composition, other configurations/architectures, final pkg creation and the full
world/system/runtime/bootstrap/performance qualification.
