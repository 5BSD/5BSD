# OpenCrypto built-in kernel qualification

## Scope (2026-11-02)

Twenty-five selected amd64 GENERIC OpenCrypto translation units now have native
built-in object targets. They retain explicit narrow physical prerequisites,
selected config headers, existing bus/device/cryptodev/vnode interfaces and the
maintained native kernel/CTF helpers. Existing module graphs retain their
distinct module compiler policy. No production C or runtime policy changed.
Make remains production/default; BIP remains excluded.

Consumed upstream libsodium headers now belong to sys/contrib/libsodium's BUILD
package, with four exact physical headers and the real include root. The two
Poly1305/ChaCha wrappers also declare the consumed kernel compatibility headers
and include root under sys/crypto. There is no root-package catch-all or broad
header-tree glob. Existing native labels did not reference libsodium across
this newly introduced boundary. Complete known-kernel analysis remains a
separate gate below; a narrow successful build alone is insufficient.

The existing build-bsd bazel-test format-5 API supplies explicit SDK, kernel
kind, CTF/debug settings and target list. The native graph neither queries Make
nor imports Make objects. There is no new frontend C option, backend API,
signing or packaging policy requirement for this component. Documentation is
updated alongside the source declarations.

## Evidence

All paths below are under /usr/obj/usr/src.

- bazel-kernel-opencrypto-make-metadata-r1-20261102 records supported actual
  per-object Make recipes with filemon disabled. All 25 reference object hashes
  remain unchanged. They belong to the earlier freshly linked Make kernel;
  metadata capture is not a fresh compilation or complete dynamic input trace.
- bazel-kernel-opencrypto-amd64-ctf-r1-20261102 records the successful normal
  frontend build with sixteen workers, actual execution records and immutable
  final captures. Its tests=[] profile runs no runtime cases.
- bazel-kernel-opencrypto-review-r1-20261102 retains actual recipe/profile/source
  hashes, section comparisons, input/relocation checks and binary CTF reports.
  SDK/config revalidation is recorded in
  bazel-resume-sdk-validation-r2-20261102.json.

All 25 original .text and .SUNW_ctf sections match Make byte for byte. All 25
also pass the maintained binary CTF semantic checker, bound to object and
implementation hashes. Actual compiler records preserve ordered warnings,
macro definitions and stack-protector policy. The audit checks 2,162 physical
prerequisite bindings and 61 generated inputs. Interface provenance comments
use documented generator input basenames; original hashes are retained.

Four objects have raw runtime-section differences. The review compares five
exact known-source diagnostic filenames and all 3,791 nondebug relocations by
symbolic target and string offset. All checks pass. Artifacts are not rewritten;
complete object/debug/symbol-index or string-table byte identity is not claimed.

## Observability and remaining gates

The bounded call-shaped scan recognizes tracing/audit/CTR markers in criov,
crypto, cryptodev and cryptodeflate, and none in 21 sources. Device scores and
protocol-state constants are excluded. Existing source and compiled probe
plumbing are preserved. Marker absence alone is not a defect or justification
for adding unmeasured hot-path instrumentation.

No live crypto provider/session, /dev/crypto, KTLS or known-answer vectors are
qualified by object comparison. Existing tests/sys/opencrypto tests, including
cryptotest, cryptodesc, Poly1305 and BLAKE2 vectors, need integration/runtime
qualification with the matching isolated kernel and dependencies.

Disk reserve monitoring passed. Controlled CPU/memory/disk I/O/disk-use/cache
performance remains open. So do complete native kernel aggregation, final link,
post-processing/install, alternate KERNCONF, cross-built built-ins, modules,
world/pkgbase/hardware publication and VM/runtime qualification. This cohort
is component progress, not a finished system-wide migration.

Complete known-built-in analysis passes after the new package boundary:
bazel-kernel-native-closure-query-r11-20261102 analyzes 408 groups and 583
compiler actions. Guarded reconciliation in
bazel-kernel-native-product-reconcile-r7-20261102 finds 574 source matches,
two object-name-only and four generated-name-only matches among Make's 2,466
final link products, with 1,886 unmatched in the known graph. These are
configured-analysis counts, not compiled coverage or a linked native kernel.
