# Network built-in kernel qualification

## Scope (2026-11-02)

Thirty-two selected amd64 GENERIC network translation units now have native
built-in object targets. They cover BPF, bridge/STP, interface lifecycle,
epair/loopback/tunnels/VLAN, iflib, packet filtering, routing sockets, RSS,
debug networking and VNET. Existing module targets are separate: built-ins
retain their actual compiler policy without KLD_MODULE definitions.

Each source owns its target and narrow physical prerequisite contexts. Existing
generators and header providers produce bus/device, ifdi, PCI and vnode
interfaces. The config tree supplies the selected option headers; opt_ifmedia
now has its own extraction from that tree. No config contents are invented.
Native actions do not query Make or import precompiled Make objects.
No production C source or runtime policy changed.

The existing build-bsd bazel-test format-5 API supplies explicit SDK, kernel
kind, debug/CTF settings and target list. This adds no CLI option or backend API;
the maintained frontend, staging, signing and package policies need no code
change for this cohort. Both builds used sixteen compilation workers.
Make remains production/default. BIP remains excluded.

## Evidence and comparisons

All paths below are under /usr/obj/usr/src.

- bazel-resume-sdk-validation-r2-20261102.json rechecks the committed checkpoint
  after the user's resume. All 16,812 SDK/source-config/tool hashes match. The
  running host remains the November 1 hypertrace40ea99e kernel; this is not
  evidence of a new host kernel installation or reboot.
- bazel-kernel-net-make-metadata-r1-20261102 records actual supported per-object
  Make metadata with filemon disabled. All 32 original object hashes stay
  unchanged. These references belong to the earlier freshly linked Make kernel;
  metadata capture is not a new compilation or complete dynamic input trace.
- bazel-kernel-net-amd64-ctf-r1-20261102 records the first successful native build.
  Review found three unnecessary interface-header views duplicating existing
  providers. They were removed; the final declarations reuse those providers.
- bazel-kernel-net-amd64-ctf-r2-20261102 records the successful corrected build
  and immutable final object captures. Its actual log reports one iflib C compile
  and one CTF conversion; other outputs reuse cached actions. The review binds
  retained original and incremental compiler outputs through converter input
  digests to final captures. It does not invent fresh compile events for cache
  hits. Both profiles have tests=[]: no runtime tests ran.
- bazel-kernel-net-review-r1-20261102 retains source/recipe/profile hashes,
  original section data, input reviews, relocation checks and CTF reports.

All 32 original .text and .SUNW_ctf sections match Make byte for byte. All 32
also pass the maintained binary CTF semantic checker; reports bind the exact
artifacts and checker implementation hashes. Compiler records preserve ordered
warning flags, macro definitions and stack-protector policy. The audit checks
5,249 physical prerequisite bindings and 135 consumed generated inputs.
Generated interface provenance differs only by the documented source basename
in the generator's comment; original and compared hashes are retained.

25 objects have raw runtime-section differences. The review retains all raw
hashes and compares 36 diagnostic filename expansions using exact known source
paths. All 16,571 nondebug relocations match by symbolic target after accounting
for these filenames and string offsets. Artifacts are not rewritten. Whole
object, debug, string-table or ELF symbol-index byte identity is not claimed.

The bounded observability scan finds recognized SDT/DTrace, audit, CTR or
lockstat/network probe markers in 12 sources and none in 20. Existing source
and compiled probe plumbing are preserved. Marker absence alone is not a defect;
live BPF, bridge/interface, filtering, routing, RSS and VNET behavior requires
runtime qualification with the matching isolated test kernel.

## Remaining gates

Disk reserve monitoring passed both builds. The second build exercises one
specific dependency correction and cache reuse; it does not establish controlled
clean/incremental or CPU/memory/disk/cache performance. The original build's
host-tool closure and expanded execution log remain recorded. Compact execution
evidence and execution-tool cache behavior are still full-system scaling gates.

Complete native kernel aggregation/link/post-processing/install, alternate
KERNCONF, ARM64/RISC-V64 built-ins, full modules/world/pkgbase/hardware
publication, VM/runtime and controlled performance qualification remain open.
This cohort does not finish the active system-wide migration goal.
