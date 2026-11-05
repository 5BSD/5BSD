# Native program and library composition, 2026-11-05

## Retained evidence

All evidence paths below are relative to `/usr/obj/usr/src/`.

| Evidence | Established scope |
| --- | --- |
| `bazel-world-program-families-native-r1-20261105/receipt.json` | Successful normal frontend construction of 408 selected installation archives and source-settings test; installed tests and automatic tests support disabled. |
| Same run, `archive-review-r1/review.json` and `archive-review-r1/prior-witness-review/review.json` | All 408 captured archives match requests, header/ownership/link metadata and logged producer payloads. Eight cached producer witnesses are explicitly bound to the prior successful csu/administration run; they are not fresh executions. |
| `bazel-library-admin-composition-native-r10-20261105/receipt.json` | Successful selected library/admin/program construction and five tests. Cached test results are not described as fresh executions. |
| `bazel-library-admin-composition-native-r9-20261105/admin-installation-review-r2/review.json` | Complete original metadata and exact archive payload/header parity: 273 records, 220 payloads across fwget, periodic, bsdconfig and lib/tests plus usr.sbin/tests. |
| Same r9 run, `spl-pthread-review/review.json` | SPL shared ELF identity, ordered libthr/libc dependencies, interfaces, hardening and both debug CRCs match the independent Make r2 reference. |
| r10 run, `daemon-program-review-r2/review.json` | Dtraced and switchboardctl full original component metadata, exact manuals/policy, ELF loader/interfaces/hardening and debug CRCs; switchboardctl retains exact unsigned .5bsd.policy bytes. |
| `bazel-execlog-host-runtime-r1-20261105/converter-receipt.json` | Refreshed observed host loader/library closure after eleven system ELF inputs changed; actual compact log round-trips 269 canonical records. Not full traced bootstrap closure. |

Each review retains its audit source and artifact/source bindings. References
remain evidence for their recorded checkpoint; later BUILD test-only edits must
not be described as present in older source-bound references.

## Corrections established by composition

CTF and SPL no longer export their implementation compatibility include paths.
CTF's standard C++ consumer exercises errno, math, string and wide-character
headers with declared native libc++ and a matching native runtime. Actual CTF
static and shared functional tests pass. The static test uses static libc with
static libthr, avoiding an unsupported protected-thread-table copy relocation.

SPL owns pthread calls. Both its original Make LIBADD and native dependencies now
name pthread/libthr; src.libnames declares the same dependency. The original SDK
source-binding check correctly refused the changed catalogue. Regeneration used
the maintained planning/staging helpers and kept the identical tool snapshot.
No receipt was silently edited to accept new source.

Dtraced uses declared libc++ headers (-nostdinc++ prevents mixing SDK wrappers)
and the original direct dependency order, including Make's late pthread position.
The first strict daemon ELF review failed on that order; the corrected r10
build and final independent review pass. Production C/C++ sources are unchanged.
Diagnostic/LTO action analyses predate these final fixes and do not establish
execution of those profiles.

Making SPL private exposed consumers that had relied on transitive include
leakage. AVL/nvpair now declare their implementation headers; additional OpenZFS
owners declare their own original compatibility context. Their static/shared
tests explicitly declare needed headers. Those changes now pass the nine selected library tests in the
openzfs-header-closure r3/r4/r5 runs. All nine results in r4/r5 are cached from
actual preceding executions. Both encodings and truncated-input checks remain
unchanged. CTF-enabled libproc compiles and its production archive builds; its
independent CTF-enabled original and runtime comparisons remain open.

The r2 follow-up exposed SIGUSR1 termination in both nvpair tests. An LLDB
reproduction stopped at nvs_xdr_nvpair's xdr_control call with an invalid x_ops
function pointer. Native RPC virtual includes preceded SPL's compatibility
wrapper; this bypassed the original userland adapter and mixed the kernel ops
layout with libc. The RPC header context now uses the original later physical
include root. No source fix, forced include, disabled encoding or ignored signal
substitutes for the real include precedence. All nine tests subsequently pass.
Fresh original Make comparison also caught a missing package-owned debug
directory; the final native installation declares it.

`bazel-openzfs-header-closure-native-r5-20261105/nvpair-wrapper-review-r3/review.json`
compares final immutable nvpair outputs against
`bazel-nvpair-wrapper-make-r2-20261105`: six original metadata records, exact
public header, static member order/symbols, shared SONAME/ordered dependencies/
versioned interfaces/hardening, and native/original debug CRCs pass. Complete
code-byte equivalence and exhaustive serialization remain unproven. The audit's
first attempt used the wrong static filename; its next attempt correctly caught
the directory omission. These failed attempts remain retained.

The broad r5 program run passes with tests_support=yes: 410 archives (40 bin,
74 sbin, 21 libexec, 267 usr.bin, eight administration). All 408 prior archive,
request and directory-metadata outputs remain identical; ATF and Kyua add two
contributions. The final r5 `archive-review-r2/review.json` and its
`prior-witness-review/review.json` now cover all 410 archives and 3,423 unique
non-directory paths. All requested metadata/inventories agree; 408 immutable
captures are identical to the earlier fully reviewed captures, and the two
added archives match actual r4 producer input/output payload hashes. These are
prior witnesses, not invented fresh r5 executions. Independent complete Make
installation, ancestor mtree and runtime qualification remain open. The broad r2/r3 failed runs remain
retained; no failure was accepted or test threshold weakened.

## Frontend and remaining gates

All construction uses the maintained build-bsd format-5 workflow with 16 jobs;
Make builds separate independent reference artifacts. Generic label/settings
selection already represents these changes, so no C dispatcher or schema change
is needed. The maintained Make backend dependency catalogue changed alongside
Bazel. Staging/signing/publication interfaces are unchanged. Unsigned policy
embedding is not signing or verified boot. BIP remains excluded.

The program profile has a separate explicit tests_support input: tests=false
controls installed suites, while tests_support=yes retains Kyua when required
by the original profile. No fixed list substitutes for that configuration.

Still required: complete installed-world and pkgbase equivalence; remaining
parents/owners and installed tests; libproc CTF-enabled original/runtime parity; diagnostic and
cross-platform profiles; bootstrap independence/reproducibility; daemon and
full-system VM/runtime checks; comparative CPU/RAM/disk I/O/footprint/cache and
sandbox qualification; separate hardware and combined publication. None of these
selected checks installs, upgrades, publishes or reboots the host.
