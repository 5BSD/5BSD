# libutil++ native tests — AMD64 qualification

## Integration

All three original C++ test programs now use native final ABI interfaces,
GNU++17/WARNS=6, PIE and no installed RPATH. The internally built util++ PIE
archive is imported as an archive implementation, with its header context; final
cc_binary links explicitly select native ATF/C++/unwinder/C ABI providers rather
than propagating implementation-library link context or using the SDK unwinder.
Only pidfile_test links the original extra util DSO. Original program sources,
case logic and public test labels are preserved. SDK headers/startup objects
remain bootstrap inputs; self-hosted bootstrap is not established here.

The test directory now exposes its complete standalone installation archive.
The existing library parent already conditionally consumes its test manifest;
that selection remains. Its missing /usr/tests/lib/libutil++ package directory
claim is added to match Make. As an INTERNALLIB, util++ itself installs neither
archive nor header: the negative profile consists of the original seven manuals.
The positive profile adds the original seven test files. No new runtime Make
parser, replacement test body, reference output or runtime search path is used.

Existing format-5 build-bsd inputs already express these targets/profiles, so no
C frontend/schema/signing change is needed. The maintained manual is updated in
the same change. Make remains default; the wider tests-enabled lib parent guard
remains until all selected contributions are verified. BIP remains excluded.

## Authoritative evidence

All paths below are under `/usr/obj/usr/src`. Qualification uses build-bsd
bazel-test with `--arch amd64 --jobs 16`, explicit SDK/receipt/repository inputs,
TESTS_SUPPORT=yes, NIS disabled and MALLOC_PRODUCTION=yes. These are unsigned
qualification builds, not publication, verified-boot or host installation tests.

- `bazel-utilpp-tests-make-r1-20261106`,
  `bazel-utilpp-parent-make-r1-20261106` and
  `bazel-utilpp-parent-no-tests-make-r1-20261106`: complete independently
  built/staged Make test and parent controls for both option profiles.
- `bazel-utilpp-tests-request-r1-20261106/inputs.json` and
  `bazel-utilpp-tests-native-r1-20261106`: complete native suite, parent,
  declared runtime libraries and all four original bodies plus source helper.
- `bazel-utilpp-tests-review-r1-20261106/review.json`: all seven suite file
  records, five directory package claims, exact original Kyuafile, three
  executable ELF/split-debug contracts and all four actual ATF metadata records
  match Make. All final immutable test-report hashes verify five passes: four
  original cases and one separate source helper, with no skips/expected failures.
- `bazel-utilpp-parent-review-r1-20261106/review.json`: all fourteen positive
  parent file records, five directory claims, eight exact non-ELF payloads and
  three executable ELF/debug contracts match Make. Data includes original
  compressed manuals and Kyuafile; no internal archive is installed.
- `bazel-utilpp-parent-no-tests-request-r1-20261106/inputs.json`,
  `bazel-utilpp-parent-no-tests-native-r1-20261106` and
  `bazel-utilpp-parent-no-tests-review-r1-20261106/review.json`: all seven
  original manual files match Make exactly, with no component-owned directory
  claims, ELF programs or /usr/tests payload. Its source helper is not counted
  as an original body execution.

All original cases execute: stringf basic and va_list, up FILE_up and pidfile
basic. They use installed stripped programs, native runtime runfiles, original
300-second body deadlines, and external/no-remote tags. DOF initialization is
disabled for isolated execution. Registration metadata comparison also executes
native/Make -l with the selected native runtime library directory. This does not
establish a per-case strict loader trace or separate installed-system execution.

ELF comparison covers PIE, interpreter, ordered NEEDED libraries, dynamic symbols,
versions, hardening and absence of RPATH. Split-debug checks verify separation,
installed basename and debuglink CRC. Raw DWARF identity, debugger source lookup,
full internal static archive equivalence, reproducible bootstrap, cache/sandbox
and CPU/RAM/disk-I/O performance remain separate qualification gates. This is
AMD64 evidence; cross-target installed runtime is not established here.

## Remaining scope

The C libutil suite is a separate selected contribution and is not qualified by
these C++ wrapper cases. Continue it and the other selected library/world tests,
complete world/kernel/module/pkgbase/debug parity, normal Capsule/service/SSH/PAM
VM acceptance, resource/performance, bootstrap/cache/sandbox/reproducibility and
verified combined base/hardware publication. No host installation, upgrade or
reboot was performed.
