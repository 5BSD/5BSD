# Native crypt library tests — AMD64 qualification

## Integration

The original two test programs now use explicit native ATF, crypt and libc ABI
interfaces. Imported crypt_test retains its original NetBSD compatibility archive;
crypt_tests retains the private crypt header. Native cc_binary owns compilation
and final linkage. Original GNU17/WARNS=6, PIE, installation/debug names, package
metadata, Kyuafile and program sources are preserved. There is no installed RPATH
and no SDK libc/libsys test runtime. SDK headers/startup objects remain bootstrap
inputs; a self-hosted toolchain is not established by this change.

The test directory now exposes its complete installation archive and manifest.
The existing library install_archive already selects these test manifests under
the original tests flag; it still does so. No second runtime selection table or
Make-parsing production graph was added. Existing three public native test labels
are retained. Existing format-5 build-bsd inputs express the targets and profiles;
no C frontend/schema/signing change is needed. The manual is updated with this
change. Make remains default and the wider full-tests guard remains.

## Authoritative evidence

All paths below are under `/usr/obj/usr/src`. Commands use explicit SDK, receipt,
repository inputs and `build-bsd bazel-test --arch amd64 --jobs 16`, with recorded
TESTS_SUPPORT=yes/NIS disabled/MALLOC_PRODUCTION=yes settings. They are unsigned
qualification builds, not package publication, verified boot or host installation.

- `bazel-libcrypt-tests-make-r1-20261106`: independently built/staged original
  test component; `bazel-libcrypt-parent-make-r1-20261106` and
  `bazel-libcrypt-parent-no-tests-make-r1-20261106`: complete parent controls.
- `bazel-crypt-tests-request-r1-20261106/inputs.json` and
  `bazel-crypt-tests-native-r2-20261106`: initial passing native construction,
  both programs, standalone suite archive, complete positive parent and cases.
- `bazel-crypt-tests-review-r2-20261106/review.json`: all five test file records,
  directory package claims, exact original Kyuafile and actual complete ATF
  metadata match Make. Both executable ELF/split-debug contracts match Make.
- `bazel-crypt-parent-review-r1-20261106/review.json`: all fourteen positive
  parent file/link records, six directory claims, original hardlinks, seven
  exact non-ELF/non-static-archive payloads and three ELF/debug contracts match
  Make. The ELF contracts cover the library DSO and both original test programs.
- `bazel-crypt-parent-no-tests-request-r1-20261106/inputs.json`,
  `bazel-crypt-parent-no-tests-native-r1-20261106` and
  `bazel-crypt-parent-no-tests-review-r1-20261106/review.json`: all nine negative
  file/link records, directory metadata, six exact non-ELF/non-static-archive
  files and one DSO ELF/debug contract match Make. No test payload is installed.
  Its source helper passes; it executes no original crypt case.
- `bazel-crypt-runtime-review-r1-20261106/review.json`: all three original body
  outcomes are identical for native and independently built Make test programs
  and crypt DSO. Common native ATF/MD/C/sys providers are held fixed explicitly;
  this is not a separately booted full Make system or a per-case loader trace.
- `bazel-crypt-tests-request-r2-20261106/inputs.json` selects JSON execution logs.
  `bazel-crypt-tests-native-r{3,4,5}-20261106` are the warm, temporary source-change
  and restored phases. `bazel-crypt-tests-cache-review-r1-20261106/review.json`
  proves zero, exactly one and zero executed compiles respectively. The changed
  compile is exactly original crypt_tests.c under its own cc_binary. Original
  source bytes are restored and hashed. This is a bounded incremental/cache check,
  not complete cache/sandbox or CPU/RAM/disk-I/O performance qualification.
- `bazel-crypt-tests-final-review-r2-20261106/review.json`: every final captured
  output is byte-identical to the initially compared native artifacts; final
  immutable test-report hashes and exact per-label outcomes remain valid. The
  source-restoration hash agrees with the original source and cache audit.

ELF comparison includes PIE, interpreter, ordered dynamic dependencies,
imports/exports, symbol versions, hardening and no RPATH. Split-debug checks cover
separation, installed debug name and debuglink CRC. Raw DWARF/debugger-source,
static archive equivalence and reproducible bootstrap remain separate gates.

## Actual outcomes and limitations

All three original cases execute. md5 and invalid pass. crypt_salts reports the
original expected failure: old-style/bad inputs fail on FreeBSD, with one failed
check. Make reports exactly the same ATF result. Final Bazel reports therefore
contain three passes (two original cases plus source helper) and one expected
failure; all_reported_cases_passed remains false. Nothing reclassifies the
expected failure as a passing original case or removes its assertions. The
known salt-compatibility issue remains separate from migration qualification.

Original 300-second body deadlines and external/no-remote test tags are preserved.
Five native runtime libraries are declared. DOF initialization is disabled for
isolated executions. No live tracing, audit delivery, password policy, normal
login/PAM, performance or whole-system runtime claim follows from these bodies.
The crypt-disabled option is not qualified by this default-crypt profile.

The initial native r1 analysis rejected an unused shared macro-header dependency
outside its declared visibility. Inspection confirmed the original imported
source does not include that header; the dependency was removed without widening
visibility. Suite review r1 used an obsolete audit-only libmd SONAME assumption
(6 instead of the captured/current 7); review r2 corrected it. Final review r1
used an incorrect artifact receipt field; review r2 uses its actual sha256 field.
Those failed attempts remain retained; none relaxed product or artifact checks.

Continue remaining library/world test installation contributions and full
world/kernel/module/pkgbase/debug, service/VM, resource/performance,
bootstrap/cache/sandbox/reproducibility and verified combined publication gates.
No host upgrade/reboot or BIP work is part of this change.
