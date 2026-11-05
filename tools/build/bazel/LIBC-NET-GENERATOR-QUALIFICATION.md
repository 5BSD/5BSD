# Original libc network generator (2026-11-05)

The network leaf now declares the maintained NetBSD gen_ether_subr script and
sys/net/if_ethersubr.c as action inputs. bsd_script_output supports an explicit
output_mode="argument" for generators that open the final filename argument.
It requires argument input mode. Existing stdout capture remains the default.
The generator runs with an explicit shell, native AWK and declared runtime
libraries/tool-only PATH; no precomputed source or host AWK replaces the action.

The maintained script currently emits a 151-byte header/prototype preamble:
the current kernel input has no matching ether_aton_r definition. This is also
exactly what original Make emits. Do not replace it with an invented function.
The network program must preserve the resulting original link behavior.

## Evidence

- Native build-bsd bazel-test request:
  /usr/obj/usr/src/bazel-net-generator-request-r1-20261105/inputs.json
- Completed native qualification:
  /usr/obj/usr/src/bazel-net-generator-native-r1-20261105/receipt.json
- Independent captured-output comparisons:
  /usr/obj/usr/src/bazel-net-generator-review-r1-20261105/review.json

All three captured outputs match Make bytes: network aton_ether_subr.c,
AMD64 GENERIC assym.inc and offset.inc. The latter exercise unchanged stdout
mode. Source-settings regression passes. The request used all sixteen CPUs,
existing explicit format-5 SDK/bootstrap inputs and production-malloc selection.
The existing maintained frontend/backend require no C/schema change to build
this target; qualification ran through their normal explicit-input interface.
This is not publication, verified boot or a system/runtime performance result.

## Remaining work

Build and independently review the complete original network root/getaddrinfo
child: C and C++20 programs, helpers, generated source, transformed shell suites,
fixtures, Kyua, installation/debug metadata and runtime dependencies. Run safe
address tests on the host; keep jail/VNET/network mutations in disposable guests.
The network leaf is not complete and full test-parent guards remain in place.
