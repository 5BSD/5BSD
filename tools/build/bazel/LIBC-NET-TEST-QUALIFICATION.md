# Original libc network/getaddrinfo construction (2026-11-06)

## Complete selected installation

All thirteen original programs build natively: seven root ATF programs (including
two C++20 programs), four root helper programs, the getaddrinfo ATF program and
h_gai. Four original shell suites, two root configuration fixtures and twenty-six
child expected-output fixtures install alongside exact original Kyua files.
Sixty non-directory records match independent original Make inventory, owner,
group, mode, tags and flags. Both suite/debug directory policies match their
respective Make directories. Thirteen ELF contracts match identity, PIE,
interpreter, hardening, dynamic symbols/versions and ordered dependencies.
Native and Make debug filenames/CRCs are checked; raw ELF/debug equality is not
claimed. Original C/C++/shell sources, expected files and Makefiles are unchanged.

The original NetBSD generator runs against declared sys/net/if_ethersubr.c and
matches Make bytes (see LIBC-NET-GENERATOR-QUALIFICATION.md). The current script
emits a prototype-only preamble; the original program therefore retains its
actual libc ether_aton_r import. The servent shell transformation preserves the
original services.cdb to services.db substitution. The child uses the actual
local VNET shell script and local expected-output files, not older imported
substitutes. Public typed archive composition includes both root and child.

Both C++ programs use declared source libc++/ATF headers, native shared ABI
imports, C++20, original warning policy and an ordered final link boundary.
Review initially caught two extra shared compiler-helper imports. Declaring the
native private compiler-rt archive before shared unwind resolution matches the
original Clang driver's -lgcc-before-gcc_s behavior. No symbols or comparison
requirements were suppressed to pass this check.

## Bounded host execution

All thirty-four original root C/C++ cases pass, plus all three original root
shell cases: recursive threaded nsdispatch, protocol enumeration and service
enumeration. Thirty-seven original host cases and the source-settings helper
pass with no skips in the final 38-target receipt. Ten host-sensitive cases
(seven protocol C cases and three shell cases) execute freshly using external,
no-remote tags; other passing cases can reuse Bazel test results. These are
read-only host database integrations, not hermetic fixtures: public host NSS,
protocol/service files and services.db influence their outcomes. They only write
private test directories. Native shell tools, helpers, libc/libsys, ATF, C++
execution libraries and threaded/helper dependencies are explicit. A retained
failed attempt exposed missing dirname required by the original ATF shell
library; declaring the native dependency fixes all three cases unchanged.

Actual original and native -l output matches for all forty C/C++ registrations
and their full metadata, including the six child resolver cases. Two ether host
lookup cases remain source-disabled by the original #if 0, not omitted enabled
cases. No network test source or expectation is modified.

## Evidence

- Final maintained build-bsd bazel-test request:
  /usr/obj/usr/src/bazel-libc-net-request-r2-20261106/inputs.json
- Final native build/runtime capture:
  /usr/obj/usr/src/bazel-libc-net-native-r5-20261106/receipt.json
- Independent original Make installation/ELF/debug review:
  /usr/obj/usr/src/bazel-libc-net-review-r3-20261106/review.json
- Forty-case metadata, 37-case selection and final output bindings:
  /usr/obj/usr/src/bazel-libc-net-case-review-r1-20261106/review.json
- Original Make reference:
  /usr/obj/usr/src/bazel-libc-installation-make-r1-20261105

The final six archive/record/directory output hashes equal independently reviewed
native r2 outputs. Captures resolve through receipt/hash verification, not mutable
bazel-bin paths. r1 preserves the initial passing cases but fails C++ import
parity; review-r1/r2 remain diagnostic attempts. Native r4 retains the failed
shell attempt and copied failed-test-logs. r2/r3/r5 retain subsequent passing
controls. Build requests use all sixteen CPUs, explicit SDK/bootstrap inputs,
production-malloc selection and original non-NIS qualification settings. This is
unsigned qualification, not package publication or a newly bootstrapped world.

## Open gates

Six getaddrinfo C cases (including external DNS and timeout scenarios) and all
fourteen root/VNET child shell cases are built/installed but unexecuted here.
They remain disposable-VM/network qualification work. Shell fixture installation
parity does not prove service -j, jail, VNET or live DNS behavior. These twenty
cases are not counted among the thirty-seven passing host cases. This turn runs
no VM. No performance or complete sandbox/cache/hermeticity claim is made.

Continue remaining libc families and test-parent traversal, independent complete
world/debug/pkgbase comparisons, other ABI/options, actual native kernel/module
execution, reproducible bootstrap/cache/sandbox checks, normal system/service
runtime and controlled CPU/memory/disk-I/O comparisons. Keep Make default and
full-tests guards until those gates pass. BIP remains outside scope.
