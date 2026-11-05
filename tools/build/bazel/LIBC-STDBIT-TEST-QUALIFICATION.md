# Native libc stdbit installed tests (2026-11-05)

## Implementation

lib/libc/tests/stdbit now declares all fourteen original ATF C programs and their
installed suite in source-owned Starlark. A single program list drives compilation,
installation, Kyua program metadata and the runtime test suite. Each compiles only
its actual translation unit; the framework and kernel .c inclusions are declared
textual headers, not extra translation units. The original -fno-builtin policy is
preserved so the tests call real libc functions. Original warning, language, PIC
and PIE policy is declared. Programs link the native public libc ABI interface
and native ATF framework. Runtime uses declared native libc/libsys/ATF libraries
through the existing ATF adapter, with DOF initialization disabled explicitly.
The installed programs gain no test-only runtime search path.

Original framework instantiations cover unsigned char/short/int/long/long long.
The source-owned runtime suite contains all seventy operation/type cases.
Installation includes all fourteen ordinary executables, fourteen split debug
files and the complete original Kyuafile, with original tests/dbg package tags.
The aggregate preserves typed archive, metadata and directory providers for
future parent composition; a plain filegroup is not substituted for them.

The shared bsd_test_install_archive helper now optionally accepts compiled debug
payloads. Their ancestor policy derives from the existing utility helper and
BSD.debug.dist, using the declared test directory. It does not introduce a flat
list of special test paths. Existing TAP callers keep the same default policy.
Existing build-bsd format-5 targets/tests express the suite, so no C frontend,
backend schema or stage/signing/publication change is needed. The manual and
completion plan record the new contribution.

## Evidence

All directories below are under /usr/obj/usr/src.

- bazel-libc-stdbit-native-r2-20261105: maintained frontend, AMD64, sixteen jobs;
  all seventy native ATF cases and the source-settings target pass, and the actual
  installed archive builds. The runtime suite expands through maintained Bazel
  test-suite discovery, rather than running selected cases outside Bazel.
- bazel-libc-stdbit-native-r3-20261105: typed installation aggregate additionally
  exposes metadata and directory outputs; all seventy cases remain passing.
- bazel-libc-stdbit-native-r4-20261105: final maintained frontend run also builds
  all nine existing shared-helper TAP consumers. All 71 test targets pass as cache
  hits. Inputs are bazel-libc-stdbit-request-r2-20261105/inputs.json.
- bazel-libc-stdbit-native-r5-20261105: final source review derives test-suite
  membership directly from each declared ATF target, removing duplicate type
  enumeration. All 71 targets still pass as cache hits. The r2 preservation
  review verifies all thirty stdbit/TAP outputs unchanged from r4.
- bazel-libc-stdbit-review-r2-20261105/review.json: immutable r3 archive against
  the fresh complete original libc Make parent reference at
  bazel-libc-installation-make-r1-20261105. All 29 installed file inventories,
  owners/groups, modes, tags and flags agree. Kyuafile bytes agree exactly.
  The current original Make ATF program query selects exactly the same fourteen
  programs, and original source hashes remain checked. All original program/debug
  payload hashes agree with the recorded Make METALOG. Every program matches the
  maintained ELF checker in ordered dependencies, imported/exported dynamic
  symbols and versions, ELF/PIE/interpreter identity and hardening. Each actual
  native binary still imports all five width-specific library functions; this
  rejects accidentally replacing the tested operations with compiler builtins.
  Native stripped/debug pairs have the right debug filename and CRC and separate
  debug information. Raw ELF/debug byte equality is not claimed.
- bazel-libc-stdbit-preservation-review-r1-20261105/review.json: all 27 outputs
  (tar, metadata and directory policy) of the nine previous shared-helper TAP
  consumers remain byte-identical to their passing original capture. The three
  final stdbit outputs also exactly match the independently reviewed r3 capture.
  This does not claim execution of the TAP programs.

The initial native r1 correctly fails: the TAP-oriented archive helper lacks
split-debug ancestor policy, and the initially chosen no-overrides Kyua runtime
check rejects ordinary system loader paths. The latter is not accepted as a
native-libc runtime pass. Using the existing ATF native-runtime adapter supplies
explicit test library inputs without modifying installed search policy. r2 is
the first passing runtime/installation checkpoint. Earlier diagnostic r1 is not
the accepted final review; r2 additionally requires Make METALOG digest bindings.

## Remaining scope

This completes the bounded stdbit component for the selected AMD64/default-debug
profile. Other libc installed-test owners, parent Kyuafiles/helper DSOs/data and
all full test hierarchy roots still need native installation composition. The
production-only parent guards continue to reject full tests-enabled builds;
this leaf contribution does not weaken those guards. Other ABIs/options, original
whole-world/debug payload parity, guest installation/pkgbase/service behavior,
bootstrap, cache/sandbox and comparative CPU/memory/disk gates remain open.
Make remains production/default. No host installation, upgrade or reboot occurs;
BIP remains excluded. The arithmetic test programs add no new security-audit
operation; this does not qualify runtime DTrace firing or audit delivery.
