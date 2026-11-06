# Complete original stdlib test construction (2026-11-06)

## Construction and original Make comparison

All thirty-four original ATF programs and both getopt helpers build natively,
including two C++ programs, both Blocks programs and the C2x free_sized program.
Both original dlopen libraries, dynthr_mod.so and libatexit.so, are native shared
objects, with original SONAME/dependency contracts and package-owned split debug.
The original getopt shell suite and exact Kyua are installed. All seventy-eight
non-directory records match original Make owner/group/mode/tags/flags; test/debug
directory attributes match. All thirty-six executable and two shared-library
ELF contracts match Make identity, dynamic symbols/versions, dependencies and
hardening. Native and original debug filenames/CRCs are checked for all thirty-
eight ELF files. Raw ELF/debug equality is not claimed. Original source, Makefiles,
expectations and selected program inventory are unchanged.

The C++ warning helper now shares original C warning levels while removing only
C-specific options and selecting the original C++ standard. Network C++20 targets
use this helper without changing their six Make-reviewed installation outputs.
The stdlib C++ programs preserve gnu++17, native ABI/header boundaries and private
compiler runtime selection. Blocks programs declare -fblocks and native runtime.

Plugin construction uses direct native cc_library dependencies under
cc_shared_library. An initial ordering wrapper hid transitive shared dependencies
from that rule's graph filtering; real dlopen cases exposed unresolved pthread/
C++ symbols. Direct graph edges fix the issue. Review also caught a forced,
unused gcc_s dependency in libatexit: original Clang uses --as-needed there. The
plugin now declares its actual libc++/libcxxrt/math/libc contract and native
private builtins. Actual imports/NEEDED match Make; no comparison was weakened.
Plugin files, private headers and runtime libraries are scoped to consuming
programs, avoiding unrelated plugin changes invalidating every stdlib test.

## Original metadata and runtime outcomes

All 136 original C/C++ registrations and their full -l metadata match original
Make programs, executed with hash-bound native runtime libraries. Custom source
case deadlines match: dynthr maintc three seconds; getenv setenv_basic 600 seconds.
The six system/benchmark cases remain explicit manual targets, outside automatic
host execution. Both original getopt shell cases execute unchanged with declared
native helpers, shell tools and libutil. Five native monetary/numeric payloads
support all thirty locale-formatting cases. Requested identities resolve through
maintained Unicode locale inventories/aliases; all five payloads match original
Make bytes, including alias resolution. No host locale is used as a substitute.

Of 132 selected original stdlib host cases, 130 pass, one retains its original
expected signal failure and one is an unconditional original skip:

- getenv_test/setenv_basic: SIGSEGV expected by the original test for FreeBSD
  PR bin/189805. Classified explicitly as expected_failure, not passed.
- cxa_thread_atexit_nothr_test/cxx__thread_inf_dtors: original source calls skip
  unconditionally because it only has the main thread. The threaded variant
  passes; the skipped variant is not claimed exercised.

The ATF supervisor now checks expected_signal with the real wait status, accepting
only a signaled body with the declared signal (or original any-signal form).
Wrong signals, ordinary exits, malformed numbers/reasons, cleanup failures and
missing XML reporting reject. Matched signals remain explicit expected failures
in XML and frontend reports. Thirty lifecycle regression methods pass, including
real process signals, malformed/mismatched expectations and cleanup failure.
Other unsupported expected-exit/death/timeout protocol forms remain unsupported;
this is not a complete Kyua replacement. The installed-VM checker has its own
supported result subset; expanding its plans to signal cases requires equivalent
qualification rather than assuming the host runner applies inside the guest.

The combined final run has 171 passing Bazel target statuses: 132 stdlib cases,
37 original network cases and two policy/runner helper targets. Detailed reports
correctly record 169 passed entries, one expected failure and one skip, and set
all_reported_cases_passed=false. These statuses must not be described as 171
original cases passing without skips. Network host-database cases remain uncached,
no-remote integrations. The remaining ordinary cases may reuse Bazel results.
No whole-system hermeticity/cache/performance claim is made.

## Authoritative evidence

- Final maintained frontend request:
  /usr/obj/usr/src/bazel-libc-stdlib-request-r4-20261106/inputs.json
- Final native build/runtime receipt and detailed reports:
  /usr/obj/usr/src/bazel-libc-stdlib-native-r7-20261106/receipt.json
- Independent original Make installation/ELF/debug review:
  /usr/obj/usr/src/bazel-libc-stdlib-review-r5-20261106/review.json
- Original metadata, deadlines, detailed outcomes, locale bytes and stable outputs:
  /usr/obj/usr/src/bazel-libc-stdlib-case-review-r3-20261106/review.json
- Original libc test Make control:
  /usr/obj/usr/src/bazel-libc-installation-make-r1-20261105
- Original monetary/numeric Make controls:
  /usr/obj/usr/src/bazel-shared-monetdef_unicode-make-r1-20261105
  /usr/obj/usr/src/bazel-shared-numericdef_unicode-make-r1-20261105

All captures resolve through completed receipt/manifest/content hashes, not mutable
bazel-bin paths. Final stdlib archive/record/directory hashes preserve native r4
bytes; final network outputs preserve all six prior Make-reviewed hashes. Earlier
failed attempts remain: r1 original dlopen and unsupported signal failures;
review-r1 Kyua order; review-r2 plugin NEEDED mismatch. Subsequent revisions retain
passing controls and the narrowing of declared dependencies. Build requests use
all sixteen CPUs, explicit SDK/bootstrap inputs and production-malloc selection.

The existing build-bsd format-5 frontend/backend runs and classifies this work;
no new C frontend schema is necessary. The maintained runner, its regression
suite, manual and completion plan are updated together. This is unsigned
qualification, not publication, verified boot or a complete system bootstrap.

## Remaining work

Five original system cases (one enters an empty root-only chroot, others invoke
the absolute /bin/sh) and the deliberately expensive qsort benchmark are built
and installed but unexecuted here. Qualify them in disposable guests with real
installed native tools and bounded resources. Earlier libc leaf contributions do not complete the unfinished gen/sys/ssp
families or the full test-parent traversal.

Continue all remaining test hierarchy work, independent full world/install/debug/
pkgbase comparisons, other ABI/options, native kernel/module execution,
bootstrap/reproducibility/sandbox/cache qualification, normal system services,
controlled CPU/memory/disk-I/O/storage comparisons and combined hardware
publication. Make remains default and full-tests guards remain; BIP is excluded.
