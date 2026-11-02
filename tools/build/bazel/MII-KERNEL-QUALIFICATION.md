# MII built-in kernel qualification

## Scope (2026-11-02)

Thirty-six physical MII translation units selected by the fresh amd64 GENERIC
Make inventory now have native built-in object targets. Existing module objects
retain separate module compiler policy. Narrow source-owned header contexts
and existing bus/device, PCI and miibus interfaces are declared dependencies.
The existing miidevs generator supplies consumed device IDs. Existing selected
config option extraction is reused; no option contents or hardware IDs are
hardcoded in a replacement generator.

No production C or runtime policy changed. Native actions do not query Make or
import Make objects. The unchanged maintained build-bsd format-5 target API
builds this graph with explicit staged SDK, kernel kind and CTF/debug settings.
No frontend C option, backend, signing or packaging policy change is required.
Make remains production/default. BIP remains excluded.

## Evidence

Evidence paths are under /usr/obj/usr/src.

- bazel-kernel-mii-make-metadata-r1-20261102 records supported actual per-object
  Make recipes with filemon disabled. All 36 existing reference object hashes
  remain unchanged. They belong to the previously linked fresh Make kernel;
  capturing metadata is not a fresh compile or dynamic input trace.
- bazel-kernel-mii-amd64-ctf-r1-20261102 records successful normal frontend
  execution with sixteen workers, actual compiler/converter actions and
  immutable object captures. Its tests=[] profile runs no runtime cases.
- bazel-kernel-mii-review-r1-20261102 retains actual recipe/profile/source hashes,
  section comparisons, compiler inputs, symbolic relocations and CTF reports.
  The staged SDK and configuration revalidation are recorded in
  bazel-resume-sdk-validation-r2-20261102.json.

All 36 original .text and .SUNW_ctf sections match Make byte for byte. All 36
also pass the maintained binary CTF semantic checker, bound to original object
and implementation hashes. Actual compiler actions retain ordered warnings,
macro definitions and stack-protector policy. The audit checks 5,545 physical
prerequisite bindings and 244 consumed generated inputs, including miidevs,
miibus and selected platform configuration headers. Generator provenance comment
basenames are compared explicitly, with original hashes retained.

mii_physubr alone has raw runtime-section differences: one diagnostic filename
uses the native relative versus Make absolute source spelling. All 4,684
nondebug relocations compare equally by symbolic target after resolving that
exact filename/string offset. Artifacts are not rewritten. Complete object,
debug, symbol-index or string-table byte identity is not claimed.

## Observability and remaining gates

None of these 36 sources directly invokes the tracing/audit macro families
recognized by the bounded call-shaped scan. An initial broad _PROBE token scan
mistook BUS_PROBE_DEFAULT and similar device-match return scores for tracing.
That candidate scan is retained separately; the corrected scan requires actual
tracing/audit call syntax and rejects device scores and protocol-state constants.
This does not establish that shared bus/network instrumentation is absent.
Review shared hooks and hardware behavior before adding hot-path probes.
No live PHY attach, negotiation, link-state or hardware operation is qualified.

Disk reserve monitoring passed. A warm build and cache reuse do not establish
controlled CPU, memory, disk I/O, disk-use or cache performance. Complete native
kernel link/install, alternate configurations, cross-built built-ins, module
closure, full world/pkgbase/hardware publication and isolated VM/runtime and
performance qualification remain open.

The subsequent successful configured query (bazel-kernel-native-closure-query-r9-20261102)
and guarded reconciliation (bazel-kernel-native-product-reconcile-r5-20261102)
find 346 known built-in groups and 521 compiler actions. Of Make's 2,466 final
link products, 512 have source-identity matches, two only object-name matches
and four only generated-name matches; 1,948 remain unmatched in the known graph.
These are configured-analysis counts, not compiled coverage or a full kernel.
The earlier r7 query correctly rejected a missing explicit source revision;
its derived r3 counts are marked invalid. Later queries provide actual revision
and worktree hashes and reconciliation rejects failed or empty query evidence.
