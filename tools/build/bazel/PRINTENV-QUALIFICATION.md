# printenv program and original tests (2026-11-02)

## Native graph and production test correction

The existing `//usr.bin/printenv:printenv` now compiles through an ordinary
source-owned `cc_library`, forwards its actual compiler object to `cc_binary`,
and preserves Make's `PIC` macro, PIE, C17, ordered warnings, optimization,
stack protection and debug policy. The prior declaration omitted `PIC` and
Make's warning vector. No program C source or generic toolchain policy changed.

`all_products` and `installation_archives` follow the existing typed `tests`
setting. The latter uses `bsd_install_archive_set` to preserve the program and
test component directory/package contexts. The program archive also records
Make's two explicit debug directories with their `utilities,dbg` ownership.
The test package installs the original executable ATF shell wrapper and
Kyuafile, not a replacement test implementation.

The original `basic` case reconstructed shell variables from `printenv` lines.
That rejects legal environment names which are not shell identifiers, including
Bazel's inherited `BASH_FUNC_rlocation%%`, and cannot represent multiline values.
The focused maintained test correction declares `env` in `require.progs` and
compares the complete original printenv bytes to an independently executed
native env program. It performs no sorting, filtering, normalization or skips.
The other three case bodies and all four case names/intents are unchanged.

Maintained Kyua `utils/process/isolation.cpp` only removes locale variables and
sets selected isolation variables; its test requires unrelated environment
variables to survive. Therefore this change does not clear or scrub the ATF
runner environment. The four native cases use the existing ATF adapter with
explicit native shell, ATF, program and helper inputs, including env, diff and
tr, declared native runtime libraries, and the selected SDK libgcc_s. DOF
registration is disabled before startup. Upstream standalone-outside-Kyua
warnings remain visible; this is not a complete Kyua isolation equivalence or
hermetic dynamic-loader claim. No host environment/account/configuration is
modified outside the child processes and temporary test work directories.

## Evidence

All paths below are under `/usr/obj/usr/src` and bind actual source/tool/log
hashes. Passed output comparisons use the maintained immutable artifact
resolver, never a mutable bazel-bin payload.

- `bazel-printenv-program-make-reference-r2-20261102` and
  `bazel-printenv-tests-make-reference-r2-20261102`: fresh original Make build
  and staging after the test correction, with supported per-object metadata.
  The original TESTS-off control is
  `bazel-printenv-program-notests-make-reference-r1-20261102`.
- `bazel-printenv-native-qualification-r3-20261102`: normal format-5 frontend,
  `bazel-posttar-sdk-20261102`, 16 jobs and the established 18 GiB start /
  16 GiB reserve guard. Four actual uncached TestRunner actions and four XML
  cases pass: basic, add_delete_env, multi and stdout. FIFO/streaming and
  variable addition/removal cases retain their original bodies and timeouts.
- `bazel-printenv-notests-native-qualification-r1-20261102`: successful
  build-only TESTS-off selection; only the program installation context remains.
  This is metadata/product qualification, not an execution result.
- `bazel-printenv-elf-review-r1-20261102`: the actual compiler object and full
  program match every original Make allocated section exactly, without a
  filename-policy control. The unchanged maintained program checker passes
  PIE/interpreter, ordered NEEDED (`libc.so.7`), versioned imports/exports,
  RELRO/NOW, no executable stack, no RPATH/RUNPATH and no text relocations.
  Whole-file/debug-byte identity is not claimed.
- `bazel-printenv-action-review-r3-20261102`: actual executed uncached compiler
  recipe, exact ordered warnings and PIC/PIE/O2/debug/SSP policy, all 73 original
  Make dependency occurrences hash-identical, actual object/direct-link output
  digests bound to accepted captures. The linker parameter file is verified
  against its executed input digest and contains the single program object.
- `bazel-printenv-install-review-r1-20261102`: all eight default and five
  TESTS-off Make installation records match paths, types, owners, groups,
  modes and package/debug tags in their original contexts. Original wrapper
  and Kyuafile bytes, manual decompression and actual debuglink CRC pass.
- `bazel-printenv-final-review-r2-20261102`: all eleven prior accepted
  non-test payload/context bindings remain byte-identical in the final r3
  capture. Four actual uncached cases bind the corrected body and native
  tr/env/diff inputs; logs contain no missing-helper diagnostics.

Compact records are fully streamed through Bazel's original converter with
all 189 retained converter tool bindings verified before and after. Actual
successful compile/link records originate in the initial failed suite run;
their output digests are checked against later passed immutable captures.
This is explicit action provenance, not a retroactive pass for that failed run.

## Retained failures and limits

Native r1 built successfully but its basic case failed on the inherited Bash
function environment name; it also lacked diff for diagnostics. Native r2
passed four cases but final log inspection found ATF startup lacked tr. That
closure defect was corrected and r3 was rerun, rather than accepting the green
XML alone. Original source, FAILED record, raw logs and the first two attempts
remain retained. Rejected observer attempts (parameter-file expansion,
runfiles spelling and report-manifest enumeration) remain alongside their
corrected strict checks. `bazel-printenv-review-drivers-20261102` preserves
review scripts and source/evidence bindings.

Existing typed settings, compatibility, ATF, script wrapper, Kyuafile and
archive-set APIs cover this graph. No frontend C, backend, manual, signing or
publication policy change is required. This closes the bounded amd64 printenv
program/test installation gap; complete world aggregation, cross-architecture
qualification, final package creation and full-system publication remain open.
Make remains the production path. No host installation or reboot occurred.
