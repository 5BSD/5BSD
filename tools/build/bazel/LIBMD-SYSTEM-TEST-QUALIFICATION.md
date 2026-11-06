# libmd native system test contribution — AMD64

## Integration and compatibility boundary

The earlier libmd candidate has portable, testonly component artifacts and digest
checks. Those remain separate. Their helper function ASTs and original digest
order are unchanged; this change does not claim fresh cross-target qualification
of those earlier artifacts. The new system contribution builds fourteen original
drivers through native cc_binary, explicit MD/C ABI interfaces and the original
GNU17/WARNS=6/PIE policy. It is consumable by an ordinary system installation target
without testonly dependencies. SDK headers/startup objects remain bootstrap inputs.

A source-owned driver map holds original source/definition pairs and digest order.
Both legacy and installed ATF generation use that order. The generated script,
Kyuafile, fourteen references, fourteen installed programs and fourteen debug
files comprise the complete original 44-file test contribution. No runtime Make
query, substituted reference output, rewritten test body or installed RPATH is
introduced. The same original gen-tests.sh supplies script bytes.

The library's new installation_archives parent appends tests only under the
original tests flag. The selected lib parent now consumes that complete child
parent; its wider tests-enabled guard remains until all selected children close.
Existing format-5 frontend inputs already express these targets/profiles, so no
C frontend/schema/signing change is needed. The maintained manual is updated.
Make remains default; BIP is excluded.

## Evidence and executed scope

All paths below are under `/usr/obj/usr/src`. Qualification uses existing
build-bsd bazel-test with explicit format-5 SDK/receipt/repository inputs,
`--arch amd64 --jobs 16`, TESTS_SUPPORT=yes, NIS disabled and
MALLOC_PRODUCTION=yes. These are unsigned qualification builds; there is no host
installation, upgrade/reboot, package publication or verified-boot claim.

- `bazel-md-tests-make-r1-20261106`, `bazel-md-parent-make-r1-20261106` and
  `bazel-md-parent-no-tests-make-r1-20261106`: independently built/staged original
  test component and complete parent controls for both option profiles.
- `bazel-md-tests-request-r1-20261106/inputs.json` and
  `bazel-md-tests-native-r3-20261106`: complete native suite/positive parent and
  fourteen original shell bodies, plus the source helper.
- `bazel-md-tests-review-r1-20261106/review.json`: all 44 test files, five directory
  package claims, fourteen ELF/debug contracts and sixteen exact data/script
  files match Make. Actual original shell metadata lists the same fourteen
  cases using the host ATF shell interpreter; body execution is separately
  recorded by the native Bazel tests.
- `bazel-md-parent-review-r1-20261106/review.json`: all 170 positive parent
  file/link records, six directory claims, original manual hardlinks,
  138 exact non-ELF/non-static-archive payloads and fifteen ELF/debug contracts
  match Make. The contracts cover fourteen drivers and the MD library DSO.
- `bazel-md-parent-no-tests-request-r1-20261106/inputs.json`,
  `bazel-md-parent-no-tests-native-r1-20261106` and
  `bazel-md-parent-no-tests-review-r1-20261106/review.json`: all 126 negative
  file/link records, original directory policy, 122 exact data files and one
  DSO ELF/debug contract match Make; no test payload is installed. The negative
  run's source helper does not execute an original digest case.
- `bazel-md-legacy-declarations-review-r1-20261106/review.json`: unchanged
  historical helper function ASTs and exact original digest order. Existing
  legacy program/check targets remain. This source check does not prove fresh
  ARM64/RISC-V output or execution qualification.

All fourteen original cases pass: MD4, MD5, RIPEMD160, SHA0, SHA1, SHA224,
SHA256, SHA384, SHA512, SHA512/224, SHA512/256, Skein256, Skein512 and Skein1024.
Final captured reports contain fifteen passes including the source helper, with
no skips/expected failures. Each body runs the original generated ATF logic,
installed stripped driver and unchanged reference, with original 300-second
body deadline. Source-level native shell/ATF tools, nine runtime libraries and
per-case fixtures are declared; external/no-remote tags preserve actual execution.
DOF initialization is disabled for isolated checks. No per-case strict loader
trace, live provider firing, audit delivery or performance claim follows.

ELF checks include PIE, interpreter, ordered NEEDED libraries, dynamic symbols,
versions, hardening and no RPATH. Debug checks cover separation, debug basename
and debuglink CRC. Raw DWARF equivalence/debugger source lookup, static archive
identity, complete cache/sandbox/resource measurements and reproducible bootstrap
remain separate gates. Native Make uses copied digest-specific source names to
avoid object collisions; Bazel uses per-target object paths for original family
sources. Raw debug path/byte identity is not asserted.

## Retained errors and remaining work

Native r1 rejected a duplicate mode keyword introduced during implementation.
The existing mode declaration was already correct; it was misread, not an original
mode bug. Native r2 rejected load declarations placed after a function during
separation of the portable/native helpers. Both errors were corrected before
successful native r3 without relaxing checks; failed logs remain retained.

Continue remaining library/world test closure, complete world/kernel/module and
pkgbase/debug comparisons, normal Capsule/service/SSH/PAM VM acceptance, CPU/RAM/
disk-I/O/footprint, bootstrap/cache/sandbox/reproducibility and verified combined
base/hardware publication. This native installed-test closure is AMD64; broader
ARM64/RISC-V installed runtime remains open.
