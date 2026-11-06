# Original AMD64 general libc tests and children (2026-11-06)

## Complete selected construction

All sixty-four original ATF programs (sixty root, one execve and three posix_spawn)
and three child helper programs build natively. The original libdummy.so.0 DSO,
libdummy.so alias, root spawn script, invalid-interpreter child script and exact
2048-byte zero fixture are present. All 143 installed non-directory records match
original Make type/link targets, owner/group/mode/tags/flags. Test/debug directory
attributes match their original final claims. Exact Kyua/script/fixture bytes
match. All sixty-seven executable and one shared-library ELF contracts match
Make, including native and original split-debug filenames/CRCs. Raw ELF/debug
identity is not claimed. All original C/fixture sources and Makefiles are intact.

The pututxline program retains original fully static, fixed-address linking;
it is not converted to a PIE/shared program. Native ATF/libc/compiler-runtime
archives supply it. The verifier has an explicit static API/--static-program CLI
mode: require EXEC, no PIE/interpreter/SONAME/NEEDED/DYNAMIC segment, RELRO, no
runtime paths and no writable/executable loads or executable stack. Dynamic
program checks remain the default and retain immediate-binding requirements.
Real native/Make static comparison passes; real dynamic and wrong-kind CLI
inputs reject. Eighteen verifier contract methods cover static/dynamic boundaries,
paths and hardening using mocked readelf metadata; these unit fixtures are not
substitutes for the real executable comparisons.

Root imported tests declare native NetBSD compatibility. Original math, utility,
thread and Blocks links remain explicit. getentropy declares its selected public
source headers; FTS/fnmatch private headers and imported isqemu input are explicit.
Both child families retain their own original inventories. Existing prototype
program/case names remain aliases to their fully installed native counterparts.
This selected AMD64 profile does not qualify alternate sanitizer or other ABI
configurations.

## Fixtures and declared copy actions

The root no-shebang spawn script and child invalid-interpreter script are copied
byte-for-byte with explicit cat/redirect/runtime inputs. They are not wrapped or
given replacement interpreters. Output executable bits are explicit in the native
runfiles as well as package install metadata. The zero fixture is generated from
2048 NUL characters through the standard write_file action, with an executable
output and no trailing text. It matches Make's /dev/zero 1 KiB/count=2 payload.
This is a test fixture, not a filesystem/system image construction shortcut.

All three raw output bytes/modes are verified through the hash-bound artifact
manifest (0555 executable outputs). Immutable captured blobs are deliberately
0400 and are not mistaken for original runnable files. Installed root script
mode remains original 0755; child fixture modes remain original 0555. The six
final archive/directory outputs retain the pre-copy-refinement hashes; final
metadata/source-path bindings are independently reviewed after the copy change.

The first attempt used a C-style hex escape unsupported by Starlark; it fails
analysis and is retained. Supported JSON decoding expresses NUL without embedding
a precomputed fixture. The retained r2 zero payload is independently confirmed
as exactly 2048 zero bytes. The later refinement corrects executable runfile
semantics rather than replacing fixture contents to satisfy a test.

## Metadata and bounded runtime outcomes

Actual original Make and native -l listings match for all sixty-four ATF programs
and all 239 case registrations, including full metadata, cleanup/user requirements
and custom deadlines. Thirty-eight reviewed host cases exercise entropy/random,
contexts, directory positions/opening, format checking, signal names/sets, path
basenames and numeric/floating-point support. Thirty-six pass. Two original
architecture cases explicitly skip:

- fpclassify_test/no_test: original source selects an unavailable-test placeholder
  on non-i386. This does not establish i386 float classification coverage.
- fpsetround_test/fpsetround_basic: original source reports this architecture
  inapplicable. It is not counted as an exercised rounding test.

The final 40-target receipt includes those thirty-eight original cases plus source
settings and verifier helper targets. Detailed reports have 38 passed entries
(including the two helper entries), two skips and all_reported_cases_passed=false.
Do not describe it as forty original cases passing without skips.

The remaining 201 cases are built/installed but unexecuted. They retain explicit
manual/deferred adapters. Login-record bodies require a disposable root chroot;
exec/spawn cases need actual installed tools/fixtures; hostname/domain, process,
network, syslog, locale, filesystem and global-state cases require their original
environments and careful isolation. Manual adapters are not a qualified guest
harness. Only metadata listing of the static login program runs here, not its
record-writing test bodies. No VM or production syscall/audit/probe qualification
is claimed by this host cohort.

## Authoritative evidence

- Maintained frontend request:
  /usr/obj/usr/src/bazel-libc-gen-request-r3-20261106/inputs.json
- Final native construction/runtime capture:
  /usr/obj/usr/src/bazel-libc-gen-native-r5-20261106/receipt.json
- Complete original Make installation/ELF/debug/fixture comparison:
  /usr/obj/usr/src/bazel-libc-gen-review-r2-20261106/review.json
- All original case metadata/outcomes and executable fixture verification:
  /usr/obj/usr/src/bazel-libc-gen-case-review-r1-20261106/review.json
- Real maintained static-verifier CLI checks:
  /usr/obj/usr/src/bazel-libc-gen-static-cli-review-r1-20261106/review.json
- Original Make control:
  /usr/obj/usr/src/bazel-libc-installation-make-r1-20261105

Captured files resolve through completed receipt/manifest/content hash checks,
not mutable bazel-bin paths. Earlier attempts and the pre-copy review remain
recorded. Requests use all sixteen CPUs, explicit SDK/bootstrap inputs,
production-malloc selection and original non-NIS qualification settings. Existing
build-bsd format-5 qualification handles the targets and actual outcomes without
a new C frontend schema. Artifact helpers, regression checks, manual and completion
plan are updated together. This is unsigned qualification, not publication,
verified boot or a completed bootstrap.

## Remaining gates

Qualify the 201 deferred cases with actual guest environments and controls.
Complete remaining libc SSP/iconv installation and parent traversal, other ABI/
options, all independent full world/install/debug/pkgbase checks, native kernel/
module boot/runtime, reproducible bootstrap, sandbox/cache/incremental behavior,
normal system services, controlled CPU/memory/disk-I/O/storage comparisons and
combined hardware publication. Make remains default and full-tests guards remain.
BIP stays excluded.
