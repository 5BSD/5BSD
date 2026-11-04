# Native hosted userboot harness (2026-11-04)

The AMD64, debug-enabled original INTERNALPROG is now a native Bazel C++-rule
build of the actual stand/userboot/test/test.c with the declared callback header.
The original component installs no files; no install/archive contribution is
invented. Production does not query Make. Compiler policy is source-owned, with
original optimization/debug/warnings and no inherited SSP substitution. The
existing artifact helper extracts test.debug and adds the matching debug link.

The original object allocated/symbol/relocation contract matches directly. All
allocated linked sections match original Make exactly, including flags, address,
size, alignment and data. The audit binds 85 consumed source/header pairs, the
actual compiler, link and both debug producers, captured artifacts and the
GNU debuglink filename and CRC. Whole debug bytes are not claimed equal.

The Bazel runtime target executes the actual program through the declared BSD
runtime linker and SDK libc/libsys, with no host library-path fallback. Its
three methods exercise original usage, missing shared-object and missing-disk
errors in private temporary directories. The first attempt used an unsupported
Linux-style linker option and failed before program execution. The passing
attempt uses the BSD linker's supported -o LIBRARY_PATH=... interface and retains
all original program expectations. Successful compiler/link/debug actions from
that failed run are individually bound to the passing artifact digests; the
failed overall run is not counted as qualification. The first audit also had to
classify original SDK header symlinks by their sysroot namespace rather than by
the source paths they resolve to. Exact content digests remain required.

Evidence:

- Original: /usr/obj/usr/src/bazel-userboot-test-make-r1-20261104.
- Native: /usr/obj/usr/src/bazel-userboot-harness-native-r2-20261104.
- Audit: /usr/obj/usr/src/bazel-userboot-harness-review-r3-20261104.

The broader userboot conversion remains open. Configured metadata now records
42 sources each for Lua and Forth plus this harness; independent original shared
object references for both variants pass with explicit original interpreter and
libsa archive bindings. Their installed inventories include split debug files,
Lua-owned help and the selected-default alias. Preserve those inventories when
implementing native shared linking and installations:

- /usr/obj/usr/src/bazel-userboot-plan-r1-20261104.
- /usr/obj/usr/src/bazel-userboot-lua-make-r1-20261104.
- /usr/obj/usr/src/bazel-userboot-forth-make-r1-20261104.

At this harness checkpoint native userboot shared objects and callback execution
were still missing. The subsequent [shared construction checkpoint](USERBOOT-SHARED-CONSTRUCTION.md)
adds both variants and selected callbacks. Kernel/disk boot, VM execution and
complete cross-platform support remain open.
The maintained format-5 frontend already handles the harness and its native test;
its C dispatcher needs no new action and its manual is updated. Full system,
bootstrap/package/debug/runtime/performance gates remain open. Make remains the
production default; BIP is excluded.
