# Six native libc test-family installations (2026-11-05)

## Implementation

C063 (16 programs), inet (two), setjmp (two), termios (one), time (two)
and ttyio (one) now have complete selected original program installation
contributions: 24 executables, 24 split-debug files and six Kyuafiles.
The new source-owned netbsd_test_installation.bzl macro takes explicit source
labels, warning/definition policy and per-program libraries. Each leaf owns its
inventory and directory; there is no Make query or source discovery during native
construction. Unknown per-program policy keys fail instead of silently dropping
a dependency. Both ordinary WARNS=2 and setjmp WARNS=4 policies are retained,
as are PIC/PIE, C063's original feature definition and package=tests/dbg tags.

Imported source packages export only the selected C files to their owning test
family. NetBSD compatibility headers/PIE archive and the shared h_macros header
are declared inputs. Native public libc/ATF and per-program pthread/util libraries
are explicit. Executables retain ordinary system loader policy; the existing ATF
runner supplies declared native runtime libraries to selected cases. All original
ATF cases remain compiled into the installed programs, including cases not run
in this qualification. The source-owned cases table is explicitly a runtime
subset, not a replacement program or complete case inventory certificate.

Existing inet runtime target names remain aliases to the actual installed
programs/cases. Typed installation aggregates carry the complete tar, metadata
and directory policy for future parent composition. Source changes do not weaken
full-tests-enabled parent guards or silently add a partial hierarchy to world.

## Original pthread dependency correction

The original setjmp Makefile used LIBADD.t_threadjmp, which does not name the
built threadjmp_test program. Its prior recorded link omitted pthread despite
the source explicitly intending to test setjmp/TLS with pthreads linked.
LIBADD.threadjmp_test now selects the actual library; the native program also
declares libthr. A fresh original Make reference and native ELF comparison both
require libthr.so.3. Four native threadjmp cases now execute with the real native
pthread library, alongside six ordinary setjmp cases. This fixes the underlying
test dependency in both build systems; it does not accept the old stub-linked
reference merely because its tests passed.

## Evidence

All directories below are under /usr/obj/usr/src.

- bazel-libc-netbsd-batch-native-r1-20261105: maintained build-bsd bazel-test,
  AMD64, sixteen jobs. All six installed archives build. Twenty-six original ATF
  runtime cases execute freshly and pass: four inet, ten setjmp/threadjmp, eleven
  time and one actual openpty/ttyio ioctl case. Source-settings passes from cache.
  DOF initialization is explicitly disabled. Time tests can use host timezone
  data; this is not hermetic runtime or produced-image timezone qualification.
- bazel-libc-setjmp-pthread-make-r1-20261105: fresh complete original setjmp
  component build/private installation with sixteen jobs, recorded SDK profile
  and metadata after the pthread dependency correction. Other five families use
  the already fresh complete original libc parent reference at
  bazel-libc-installation-make-r1-20261105. These comparisons do not rebuild all
  external common libraries or prove a complete hermetic dependency closure.
- bazel-libc-netbsd-batch-review-r2-20261105/review.json: all 54 installed file
  inventories, owner/group/mode/tags/flags and exact six Kyuafile bytes match
  original Make. Original program/debug hashes agree with Make METALOG. All 24
  programs match ELF/PIE/interpreter identity, ordered NEEDED dependencies,
  dynamic imports/exports and versions, and hardening. Both native and original
  split-debug names/CRCs are checked. Original source inputs remain checked;
  intentionally changed Bazel declarations are distinguished from Make inputs.
  Raw ELF/debug equality and complete ABI/semantic parity are not claimed.
- bazel-libc-netbsd-batch-native-r2-20261105: final frontend invocation passes
  28 test targets: 27 cached targets plus the new eight-method ELF section-reader
  target executed freshly. Explicit inputs are
  bazel-libc-netbsd-batch-request-r2-20261105/inputs.json.
- bazel-libc-netbsd-batch-final-bindings-r1-20261105/review.json verifies all
  eighteen final archive/metadata/directory outputs exactly equal the r1 capture
  used by the independent review. Thus the final result retains that evidence.

The first independent review stops after encountering the intentionally changed
inet BUILD.bazel in the original component source snapshot. It is retained as
failed evidence. The corrected review checks actual original source inputs
without treating a native declaration as a Make compilation input; it keeps all
54-record, ELF interface, dependency and debug assertions. The ELF comparison
reader's separate I/O improvement and exact original hash controls are described
in ELF-SECTION-READER-QUALIFICATION.md.

## Runtime and remaining hierarchy limits

C063 programs are built/installed here, not exercised with their full privilege
and filesystem cases. Termios tcsetpgrp_err returns immediately when stdin is not
a terminal; a headless pass would not establish terminal behavior, so no such
runtime claim is made. Qualify it with an actual terminal in the installed-system
suite. The separate ttyio test does create a PTY and its actual ioctl case passes.
Remaining libc owners, parent Kyua traversal, helper DSOs/fixtures, complete case
inventory/requirements and privileged/PTY installed-system qualification remain.
The source programs are not rewritten to accommodate Bazel.

The maintained format-5 target/test interface already expresses this work.
No C frontend, stage/signing/publication or security-policy change is needed;
the normal Make workflow receives the pthread fix directly. The manual and plan
are updated with the contribution and its limits. Full world/tests/pkgbase,
other architectures/options, bootstrap, VM/service/runtime and comparative
CPU/memory/disk/cache/sandbox/publication gates remain open. Make stays default;
BIP is excluded. No host installation, upgrade or reboot occurred.
