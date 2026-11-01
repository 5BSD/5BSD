# ARM64 / RISC-V64 MAC and OpenEndpointSecurity modules

2026-11-01. Explicit native declarations cover ten module candidates selected
by both architecture-checked GENERIC Make inventories: mac_abac, mac_ddb, mac_do,
mac_ntpd, mac_pimd, mac_portacl, mac_priority, mac_test, mac_test_hooks and oes.
This qualifies build/install artifacts for these configurations, not policy
enforcement, event delivery, complete module sets or a bootable Bazel kernel.
Make remains the production backend; BIP is excluded. Other security modules,
including capability and Veriexec variants outside these inventories, remain
separate conversion/qualification work and are not implicitly covered.

## Native source and package ownership

The declarations compile the 28 original C sources with declared headers and
registered target C++ toolchains. OES uses each target's actual generated
opt_mac.h. Existing ABAC/OES source constants are shared with their amd64
module/built-in declarations. The established relocatable/CTF/export/shared-link/
separate-debug/install pipeline is reused. Package assignments remain mac-abac,
oes, kernel or tests according to the maintained Makefiles. No C behavior,
security check, event/probe site, runtime Make parser or substitute header is
introduced. Cross built-in kernel bodies are not qualified by these module runs.

## Independent Make reference and correction

The first clean Make matrix passed 36 combinations and failed the four mac_ddb
combinations: mount.h includes vnode.h, which requires generated vnode_if.h,
but this module's SRCS omitted that dependency. The maintained Makefile now
lists vnode_if.h, letting ordinary Make rules generate it. No parent-header
copy or prepopulated tree hides the omission. The original successes and failures
remain under `/usr/obj/usr/src/bazel-cross-security-make-20261101/`.
Only the four affected combinations were freshly repeated; all four pass under
`/usr/obj/usr/src/bazel-cross-security-make-r2-20261101/`. Each review row names
its exact successful reference directory. Unchanged modules use their original
successful reference, not an implicit fallback based on file existence.

The references retain commands, target parent-kernel ARCH_FLAGS, object and
generated inputs, resource counters and install METALOGs. All sixteen logical
CPUs are available for builds. Normal NO_ROOT and -U/-M/-D flags stage without
host installation; NO_XREF excludes linker.hints. No module is loaded.

## Actual native comparison

Four maintained `build-bsd bazel-test --arch arm64|riscv64` runs each build twenty
explicit module/install targets using the kernel target profile and existing
typed CTF/debug settings. Receipts are at
`/usr/obj/usr/src/bazel-cross-security-{arm64,riscv}-{plain,ctf}-r1-20261101/`.
No new frontend, signing or publication API is required; the manual records the
expanded candidate coverage.

All twenty no-debug module files match Make byte for byte. All twenty installed
CTF/debug modules match every ELF section and file offset except the contents
of build-ID/debuglink, including code/data, symbols, relocations, CTF and SDT.
Both native and Make debuglink CRCs validate against actual separate debug files.
Separate debug files retain DWARF/build-ID/symbol/layout differences; debugger
source resolution and full debug-file identity remain unqualified. All sixty
file/debug install records match destination, type, ownership, mode and package/
debug tags. Directory metadata and linker.hints are outside this comparison.

The reports, input hashes, original source scan, input JSON and reproduction
scripts are retained at `/usr/obj/usr/src/bazel-cross-security-review-20261101/`.
Kernel-profile builds intentionally select no executable target tests. The
receipts do not constitute runtime passes or controlled CPU/RAM/disk benchmarks.

## Unchanged local cache check

An immediate unchanged RISC-V64 CTF/debug repeat through the normal frontend
passed all twenty target selections with an identical artifact manifest and
identical actual payloads. Its execution log is empty (zero spawn records).
Receipt: `/usr/obj/usr/src/bazel-cross-security-riscv-ctf-repeat-20261101/`;
comparison: `cache-review.json` in the retained review directory. This qualifies
only unchanged same-profile local reuse, not source mutation, cross-mode reuse,
remote caching, server restarts or general build performance.

## Observability and remaining gates

The bounded C-source scan records 21 ABAC schemas in mac_abac.c, two in mac_do.c
and nine in oes_event.c, plus an audit marker in oes_mac.c. Header-defined sites
and subsystem observation are separate from this bounded direct-marker count.
Installed SDT sections match Make; no probe is removed. Live probe arguments,
audit delivery and overhead remain unqualified.

Matching-kernel tests must cover load/unload, ABAC rule/label transitions and
allow/deny behavior, MAC privilege/port/priority/debugger policies, and OES
subscription, authorization, timeout/cache/event and failure paths. Kernel/
world/pkgbase production, complete configurable module sets, debugger behavior,
cache/input mutation and controlled CPU, aggregate memory, disk-I/O and allocated-
disk comparisons remain open.
