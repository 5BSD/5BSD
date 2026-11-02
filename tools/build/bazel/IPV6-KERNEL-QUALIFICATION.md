# IPv6 built-in kernel qualification

## Scope (2026-11-02)

Twenty-nine previously unmatched physical sys/netinet6 translation units selected
by the fresh amd64 GENERIC inventory now have native built-in object targets.
This is component qualification, not complete kernel/network aggregation,
link/install, module closure, alternate configuration or cross-build completion.
No production C source, service configuration or runtime policy was changed.

Each source declares its compilation target and narrow physical header contexts
in the packages owning those files. The existing native kernel compilation and
CTF helpers are reused, including Make's built-in warning order and stack
protector policy. Existing config-derived option extraction rules are reused
through consumer-specific views; this cohort needs no new option extraction.
Native analysis/build actions do not query Make or interpret migration metadata.

The existing build-bsd bazel-test format-5 API expresses the selected SDK,
kernel target kind, CTF/debug settings and object list. No frontend C option,
backend replacement or helper API change is needed. The normal path was run
with sixteen logical CPUs and the post-upgrade SDK described in
VM-KERNEL-QUALIFICATION.md. Make remains production/default; BIP is excluded.

## References and evidence

Evidence under /usr/obj/usr/src:

- bazel-kernel-ipv6-make-metadata-r1-20261102 records supported Make per-object
  meta recipes with filemon disabled. All twenty-nine existing object hashes
  stayed unchanged. The reference objects belong to the previously linked fresh
  Make GENERIC kernel; this is not a new post-upgrade kernel compilation.
- bazel-kernel-ipv6-amd64-ctf-r1-20261102 retains the successful normal frontend
  build, immutable object captures, actual execution log and receipt. The profile
  builds twenty-nine object groups and has tests=[]; no runtime cases ran.
- bazel-kernel-ipv6-review-r1-20261102 retains recipes/profile, source hashes,
  review scripts, original section comparisons, compiler/CTF input bindings,
  filename/relocation checks and bounded observability findings.

All twenty-nine original .text sections match Make byte for byte. Twenty-eight
.SUNW_ctf sections match byte for byte; all twenty-nine pass the maintained
binary type-layout/reference and symbol-association comparison described in
CTF-SEMANTIC-CHECK.md. The checker has 29 native host regression methods and a
real-object negative member-name fixture that it rejects without changing text.
For in6_fib_algo.o, a filename char[28] coalesces with a real buffer char[28].
Make retains one unused empty nonroot type slot; type IDs/label boundaries shift.
The raw encoding difference remains recorded, not rewritten or exempted by name.
Final semantic reports and implementation hashes are in ctf-semantic-r2 under
the retained review directory. This checks supported metadata, not complete ABI.
Successful compiler output digests bind to actual
converter inputs and immutable captured object digests. Actual compiler actions
preserve Make's ordered warnings, macro definitions and stack-protector policy.
The review checks 4,932 physical prerequisite bindings and 129
consumed generated bindings, including actual option and vnode interface data.
Source/configuration freshness is checked separately; nofilemon is recipe
capture, not a complete dynamic dependency trace or hermeticity proof.

20 objects have raw runtime-section differences. 26 diagnostic
filename expansions use relative native versus absolute Make physical-input
spellings. All 12,306 nondebug relocations compare equally by symbolic target
after accounting for those exact filenames and string offsets. Every original
section hash/string is retained; the separate CTF encoding difference is
accounted for above. Production artifacts are not rewritten for
parity. Whole object/debug/symbol/string-table byte identity is not claimed.

The bounded source scan includes network-specific probe wrappers along with
SDT/DTrace, audit, CTR and lockstat markers: 6 sources contain recognized
markers and 23 do not. Existing code/interfaces and compiled probe
plumbing are preserved. Live packet, ICMPv6, neighbor discovery, routing,
fragmentation/session events and audit delivery still need the matching isolated
test kernel. Review shared instrumentation and measured tracing overhead before
adding hot-path events; marker absence alone is not a coverage defect.

IPV6-KERNEL-CHECKPOINT.md preserves the earlier failed strict-byte gate and
diagnostic prototype; it is superseded by these completed component checks.

Disk reserve monitoring passed. Timing/resource observations do not establish
controlled CPU/memory/disk/cache performance. Other kernel/custom objects,
complete native link/version/post-processing/install, cross builds, modules,
full world/pkgbase/hardware publication, VM/runtime and performance gates remain
open. This cohort does not narrow or complete the active full-system goal.
