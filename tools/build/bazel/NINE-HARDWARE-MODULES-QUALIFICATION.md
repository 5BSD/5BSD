# Nine hardware modules: native qualification (2026-11-02)

## Scope and native ownership

The nine selected amd64 modules are aac, aac_linux, aacraid, aacraid_linux,
adlngpio, amdgpio, apple_bce, arcmsr and asmc. Their 19 source files now have
native compiler/CTF groups and module link/export/debug/install owners.
Source lists preserve original Make SRCS order. All use the original
EXPORT_SYMS=NO empty export policy. No production C source changes are needed.

Physical prerequisite sets come from fresh independent original Make builds.
23 contexts reuse existing providers with exactly the same header lists and
include roots; visibility extends to actual new consumers. Nine further exact
physical contexts are declared. Original KOBJ schema producers and GENERIC
option-header producers supply generated headers. Make-generated files are
comparison controls, not native build inputs.

The first build exposed the two Linux ioctl adapters' existing
machine/../linux includes. The new bsd_architecture_headers rule declares a
logical machine/linux sibling view with individual source-file symlink actions.
It exports CcInfo for that view; its include root is derived from declared
artifacts. Header paths reject traversal and collisions; generated header
inputs are rejected. The machine group uses source-owned architecture headers
and the Linux group uses its three declared source headers. There is no copying
of the host include tree, execution-root discovery or source include rewriting.
Both adapters compile and compare in both qualified configurations.

## Results

- All nine plain module files are byte-identical to original Make outputs.
- All nine CTF/debug runtime module section payloads and metadata match Make
  except GNU build-ID/debuglink bytes. CTF bytes are exact. Native and Make
  debug pairs independently pass the maintained module/debuglink verifier;
  complete DWARF byte identity is not claimed.
- All 27 installation records match Make ownership, modes, tags and paths:
  nine plain files plus eighteen CTF/debug runtime/debug files.
- Nineteen actual native compiler actions bind source identity, compiler
  binary, defines and code-generation policy to Make recipes. All 2,799
  Make dependency occurrences bind to native input digests, including the
  logical Linux header aliases. Original KOBJ headers differ only in their
  exact single provenance source-path comment; both headers are retained and
  every other byte must match. Make .depend/meta does not prove complete
  dynamic-input discovery; filemon was disabled.
- Final runtime/debug files are byte-identical to the captures used by the
  actual compiler/input audit. No cached compiler executions are invented.

Both configurations use the fresh SDK from HARDWARE-MODULE-GAP-QUALIFICATION.md,
with the current host tar input. All native builds use normal format-5
build-bsd bazel-test targets/settings, sixteen jobs and disk reserve monitoring.
No frontend C/schema, manual option, signing or publication changes are needed;
the maintained native backend and source graph handle the new owners.
Make remains production/default and BIP remains excluded.

## Evidence under /usr/obj/usr/src

- bazel-next-module-source-facts-r1-20261102: selected original Make facts.
- bazel-next-module-make-references-r2-20261102: original ordinary-plain and
  CTF/debug controls, actual recipes, isolated stages/METALOGs and artifact hashes.
- bazel-nine-hardware-modules-ctf-native-r1-20261102: retained initial failure
  at the legacy machine-relative Linux include.
- bazel-nine-hardware-modules-ctf-native-r2-20261102: successful initial CTF
  build and nineteen actual compiler executions.
- bazel-nine-hardware-modules-plain-native-r1-20261102 and
  bazel-nine-hardware-modules-ctf-native-r3-20261102: final current-rule builds,
  immutable captures, original execution logs and frontend receipts.
- bazel-nine-hardware-modules-review-r1-20261102: compiler/input audit and
  retained generated-header provenance differences.
- bazel-nine-hardware-modules-review-r2-20261102: eighteen final module
  comparisons, debug checks, 27 exact installation records and hash bindings
  to the original compiler audit.

The source-declaration preparation record retains original source order,
header closures, exact provider reuse and before/after source hashes. These
are qualification records; production builds consume the committed native
BUILD/rule declarations directly.

This qualifies the selected amd64 build configurations, not driver loading,
DMA or storage I/O, Linux ioctl behavior, GPIO operations, Apple bridge/USB
operation, fan controls, other architectures/options, complete module/kernel
package closure, VM operation or controlled performance. No host installation,
upgrade or reboot occurred. Runtime observability work remains in
observability-audit.md.
