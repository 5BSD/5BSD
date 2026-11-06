# Original AMD64 libarchive test construction (2026-11-06)

## Native construction and original controls

The source-owned Bazel graph builds all 353 selected original test sources and
three helpers (356 translation units), the original generated registry and shell
wrapper, and all 446 original reference files. The 450 installed non-directory
records match a fresh sixteen-job original Make control: metadata, directories,
script/Kyuafile/reference bytes and program ELF/split-debug contracts. Raw
ELF/DWARF equality and debugger source lookup are not claimed. Native ABI inputs
preserve the original library order and OpenSSL configuration, including the
private digest context layout. The original timeout remains the string "600".

The three sources using test_fuzz_consumer.h have a scoped native dependency.
The original per-source test_utils.c warning exception remains scoped to that
helper. Original sources, Makefiles, implementation libraries and providers are
unchanged. The original disabled random fuzz source remains disabled. The two
original BROKEN_TESTS identifier fragments filter registry lines, potentially
multiple registrations each; they do not remove source compilation.

The shared generator now follows the original anchored grep selection, ordered
inputs and literal identifier-fragment exclusions. It rejects empty registries,
invalid/stale exclusions and NUL input. Seven boundary methods exercise these
rules, including CRLF and missing final newline. Independent original Make source
queries and BSD grep match all five generated registries: library 836, tar 73,
cpio 49, unzip 28 and bsdcat 18. Production generation never invokes Make or
extracts replacement sources from Make; source-owned declarations are reviewed
against Make as a development control.

## Runtime and incremental checks

Actual native and original Make harness listings match all 836 registrations.
Three reviewed original in-memory bodies execute directly from installation-form
code with explicitly captured native DSOs: test_archive_sha256 (11 assertions),
test_archive_cmdline (65) and test_archive_read_ahead_eof (20). All pass with zero
internal skips or assertion failures; original Make controls produce the same
counts. Real captured reference payloads are available to both. This is not a
run of the ATF wrapper or all 836 bodies; 833 bodies remain unexecuted here.

A controlled benign comment in the private fuzz-consumer header invalidates
exactly its three dependent compiles. The warm build and byte-restored build
execute zero compiles. The header is byte-restored, and final captured archives,
metadata, directories and all registries are identical to the independently
compared pre-mutation captures. This scoped test is not a general performance,
sandbox, reproducibility or whole-world incremental qualification.

## Retained evidence

All paths below are under /usr/obj/usr/src:

- bazel-archive-tests-request-r{1,2,3}-20261106: existing format-5 inputs.
- bazel-archive-tests-native-r1-20261106: retained initial missing private-header
  declaration failure. Scoped declarations fix it, without ambient include paths.
- bazel-archive-tests-native-r2-20261106: construction and two passing helper
  targets; the registry helper executes seven Python boundary methods. These
  targets do not represent original libarchive body execution.
- bazel-archive-tests-native-r{3,4,5}-20261106: warm/change/restore JSON execution
  logs, with r5 the final authoritative construction capture.
- bazel-archive-tests-make-r1-20261106: original Make build/install/control receipt.
- bazel-archive-tests-review-r1-20261106: all 450 installation records and
  program ELF/debug/control review.
- bazel-archive-tests-registry-review-r2-20261106: all five independent registry
  comparisons. The retained r1 audit incorrectly assumed bsdcat upstream lived
  in bsdcat/test; the actual original source path is cat/test.
- bazel-archive-tests-cache-review-r1-20261106: header snapshots, execution logs
  and exact three-source invalidation/restoration receipt.
- bazel-archive-tests-final-review-r1-20261106: restored final capture and actual
  836-case native/Make listing bindings, with zero bodies executed at that phase.
- bazel-archive-tests-runtime-review-r1-20261106: subsequent three-body native
  runtime and Make assertion-count controls, full stdout/stderr and bindings.

An initial pre-edit fixture inventory incorrectly treated generated Kyuafile as
a source file. Preflight rejected it; the corrected inventory distinguishes this
one generated artifact and requires all 446 actual reference sources to exist.
No source fixture is silently dropped or substituted.

## Remaining scope and frontend

These explicit targets are AMD64-qualified only. ARM64/RISC-V configurations and
runtimes, the full libarchive suite with real filesystem/privilege/compressor
requirements, full tests-enabled world composition, independent world/kernel/
module/pkgbase/debug comparison, normal startup/services and VM acceptance remain
open. Internal libarchive skips must be counted; ATF wrapper exit status alone is
insufficient. DTRACE_DOF_INIT_DISABLE is explicit for host runtime checks; live
provider firing and audit delivery are not established.

Existing build-bsd format-5 inputs express this construction and its helpers;
frontend C/schema, signing and publication requirements do not change. The manual
is updated with this scope. Make remains production/default; full-tests guards
remain; no host installation, upgrade, reboot or VM launch occurred. BIP remains
excluded. This closes one initially missing declaration root, leaving four in
that initial discovery; file presence does not establish nested traversal or
whole-system qualification.
