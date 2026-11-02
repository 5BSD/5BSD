# Wireless built-in kernel qualification

## Scope (2026-11-02)

Thirty-seven selected amd64 GENERIC sys/net80211 translation units now have
native built-in object targets. Source-owned rules express narrow physical
headers, selected config options and the existing native kernel/CTF helpers.
Existing module graphs retain their distinct module compiler policy.
No production C, service or runtime policy changed. Native actions do not
query Make or import Make objects. Make remains production/default; BIP is
excluded. Complete kernel/world/package/runtime migration remains open.

The unchanged maintained build-bsd bazel-test format-5 API supplies explicit
staged SDK, kernel kind, debug/CTF settings and target list. There is no new
frontend C option, backend or signing/packaging policy requirement for this
component. Both native builds use sixteen compilation workers.

## Retained evidence

All paths below are under /usr/obj/usr/src.

- bazel-kernel-wlan-make-metadata-r1-20261102 captures supported actual per-object
  Make recipes with filemon disabled. All 37 original reference objects remain
  unchanged. They belong to the earlier freshly linked Make kernel; recipe
  capture is not a new compilation or complete dynamic dependency trace.
- bazel-kernel-wlan-amd64-ctf-r1-20261102 records the first successful compile.
  The original policy audit rejected missing -Wno-unused-function on five
  sources even though generated code already matched. Actual failure output,
  status and review script remain in the review directory.
- sys/conf/files specifies that exception for ieee80211_adhoc, ieee80211_crypto,
  ieee80211_hostap, ieee80211_mesh and ieee80211_sta. Their native declarations
  now express the same explicit per-file compiler option.
- bazel-kernel-wlan-amd64-ctf-r2-20261102 records the corrected successful build
  and immutable final captures. It recompiles those five sources; unchanged
  converter outputs can remain cached. Original and incremental compiler
  digests bind through converter inputs to final captures. This is not a claim
  of 37 fresh compiler executions in the incremental run.
- bazel-kernel-wlan-review-r1-20261102 retains recipes/profile/source hashes,
  original section hashes, actual input checks, relocations and final CTF reports
  under ctf-semantic-r3. The SDK/config baseline was revalidated in
  bazel-resume-sdk-validation-r2-20261102.json. Both profiles set tests=[];
  no runtime cases ran.

All 37 original .text and .SUNW_ctf sections match Make byte for byte. All 37
also pass the maintained binary CTF semantic checker, bound to object and
implementation hashes. Actual compiler records match ordered warnings, macro
vectors and stack-protector policy, including the five source exceptions.
The audit checks 6,142 physical prerequisite bindings and 126 generated inputs.

24 objects have raw runtime-section differences. The review compares 25 exact
known-source diagnostic filename expansions and 12,778 nondebug relocations by
symbolic target/string offset. All checks pass. Original bytes and hashes remain
recorded; artifacts are not rewritten. Whole object/debug/symbol-index or
string-table byte identity is not claimed.

## Observability and remaining gates

The bounded call-shaped scan recognizes direct tracing/audit/CTR markers in
three sources (ieee80211_proto, ieee80211_scan and ieee80211_sta), and none in
34. Device-match scores and protocol-state constants are excluded. Existing
source and compiled probe plumbing are preserved. Shared instrumentation and
live attach/authentication/association, scanning, cipher, rate-control, AP,
mesh, roaming and device interactions need matching isolated runtime/hardware
qualification. Marker absence alone is not a defect or reason to add hot-path
instrumentation without measurement.

Disk reserve monitoring passed. These runs do not establish controlled CPU,
memory, disk I/O, disk-use or cache performance. Full native kernel aggregation,
link/post-processing/install, alternate configurations, ARM64/RISC-V64 built-ins,
modules, world/pkgbase/hardware publication and VM/runtime/performance gates
remain open.

The subsequent successful full known-built-in query
(bazel-kernel-native-closure-query-r10-20261102) and guarded reconciliation
(bazel-kernel-native-product-reconcile-r6-20261102) find 383 groups and 558
compiler actions. Make selects 2,466 final link products: 549 source-identity
matches, two object-name-only matches, four generated-name-only matches and
1,911 unmatched products in this known graph. These are analysis counts, not
complete compiled coverage or proof of a linked native kernel.
