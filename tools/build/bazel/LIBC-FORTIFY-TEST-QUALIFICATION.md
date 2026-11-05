# Native fortify test construction and terminal execution (2026-11-05)

## VM follow-up

The later installed-resource VM executes all 378 fortify cases successfully, including all ten root/jail and five terminal cases. The privileged runtime gap recorded below is now closed for this selected profile. See INSTALLED-ATF-VM-QUALIFICATION.md for final evidence and scope. The remaining sections record the earlier checkpoint.


## Complete original installation

All twelve original checked-in fortify programs now build/install natively:
random, select, socket, uio, poll, signal, stdlib, stdio, string, strings, unistd
and wchar. Original generated C files retain _FORTIFY_SOURCE=2 and their child
monitors requiring SIGABRT for detected overflows. No C test source, overflow
expectation, compiler hardening or input is rewritten. Regenerating checked-in
sources remains the original explicit Lua source-maintenance task, not a hidden
native build step.

Source-owned cases contain every original registration. The existing local ATF
installation helper retains original WARNS=6, native ATF/libc ABI imports and
split debug. Twelve programs, twelve debug files and original Kyua make twenty-
five regular installation records. Per-case user and stdin-terminal policies
reject references to missing programs/cases.

## Case requirements and real-terminal support

There are 378 original cases. Ten sethostname/setdomainname cases require root
and create private jails. They have a separate explicit privileged_runtime_tests
suite, manual/external/no-remote tags and the existing supervisor's required-user
check. They remain unexecuted here, for later disposable VM qualification.
The ordinary runtime_tests suite selects exactly the other 368 cases.

Five ttyname_r cases require an actual terminal on stdin. A new optional stdin_tty
attribute on the maintained bsd_atf_test adapter allocates a real POSIX pseudo-
terminal for each phase. Only stdin is connected; stdout/stderr and result/XML
reporting stay on their existing paths. The parent keeps the master alive, closes
unused descriptors and retains the existing process groups, monotonic deadlines,
descendant termination and separate cleanup phase. Allocation failures fail the
phase instead of substituting a pipe or suppressing the original isatty check.
Default tests retain their existing stdin without allocating a terminal.

This provides terminal identity on stdin, not a controlling-terminal/job-control
session or interactive input driver. Those scenarios still need their own tests.
The closed-stdin descriptor case is covered: the master can occupy fd 0, so the
child closes it before duplicating the slave rather than closing its new stdin.

## Evidence

All directories below are under /usr/obj/usr/src:

- bazel-libc-fortify-native-r1-20261105: all twelve programs build; 368 ordinary
  cases are selected. Detailed reports record 363 actual fortify passes and five
  ttyname_r skips because stdin is not a terminal. Two policy targets also pass.
  Bazel's 370 PASSED target statuses alone are not all-case execution proof.
- bazel-libc-fortify-review-r1-20261105: complete independent Make comparison of
  twenty-five file records, exact Kyua bytes, physical suite/debug directories,
  twelve distinct program ELF identity/interfaces/ordered dependencies/versions/
  hardening contracts and native/Make debug filenames/CRCs passes. The original
  stage is bazel-libc-installation-make-r1-20261105, using an existing prepared SDK;
  a new independent whole-world bootstrap is not claimed.
- bazel-libc-fortify-native-r2-20261105 freezes three native runtime DSOs and retains
  all installation outputs. It still has five terminal skips and is not the final
  all-ordinary-case runtime checkpoint.
- bazel-libc-fortify-native-r3-20261105: all 368 ordinary fortify cases pass with
  no skipped/expected-failure cases, including the five real-terminal cases.
  Three helper targets pass: source settings, selector inventory and ATF lifecycle.
  Thus detailed reports contain 371 passes. 369 targets run freshly; two policy
  targets reuse their valid cached outcomes.
- The ATF lifecycle target executes 25 methods: actual terminal presence in body
  and cleanup, default stdin preservation, malformed settings rejected before
  execution, initially closed stdin, timeout/descendant termination and cleanup,
  explicit-loader behavior, user preconditions, locale isolation and outcome XML.
  This tests the supervisor using its controlled protocol fixture, independently
  of original fortify runtime cases.
- bazel-libc-fortify-case-review-r2-20261105: captured native DSOs support independent
  original/native -l listing comparisons for all twelve actual programs. All 378
  case registrations and full ATF metadata agree, including exactly ten root
  requirements. The final configured suite contains exactly the other 368 cases;
  receipt-bound detailed results have no skips. All twelve final installation
  outputs retain review bindings: three secure outputs are identical to the
  independent fortify comparison, and all nine NSS/resolver/stdtime outputs remain
  identical to their earlier independently reviewed local-batch r4 checkpoint.

Early case-review-r1 checks registrations/selection and output preservation but
uses r2 with its terminal skips. Use case-review-r2 and native r3 for final ordinary
runtime acceptance. Earlier skips are retained, not relabeled as passes.

## Maintained workflow and open gates

Existing explicit-input targets/tests and artifact captures suffice. The maintained
ATF backend, leaf helper, lifecycle tests, manual and ledgers are updated together.
build-bsd.c, its schema, compiler backend selection and signing/publication helpers
need no change for this source-owned test contribution.

This proves selected AMD64 fortify leaf installation/interface and all 368 ordinary
cases. The ten privileged cases, other architectures/configurations, full installed
hierarchy, raw ELF/debug byte equality, whole-system bootstrap/runtime/resource/
cache/sandbox/pkgbase/publication gates remain open. DOF initialization is disabled
for isolated tests; live DTrace/audit delivery is not established. Make remains
production/default, full-tests parent guards remain and BIP stays excluded.
