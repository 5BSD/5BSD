# Atheros driver/HAL built-in qualification

## Scope (2026-11-02)

130 selected C sources have native amd64 GENERIC built-in object declarations:
106 under sys/dev/ath and 24 under sys/contrib/dev/ath. These two new source
packages own the driver, rate control and HAL sources/physical prerequisites.
108 distinct header contexts share identical dependency sets. The initial native
label audit found no consumers of root-owned Atheros labels; complete known-kernel
analysis passes after introducing the package boundaries.

Make's warning order is preserved, including the family unused-variable setting
and source-specific shift-count, constant-conversion and sometimes-uninitialized/
unused-function exceptions. No warnings or features were newly disabled. Native
config(8) outputs provide opt_ah.h and opt_ath.h, including empty generated files;
existing INET/WLAN/global/offset and bus/device/PCI producers are reused. Every
used CK/driver/HAL search root retains Make's order after the ordinary BSD sys
root. No placeholder directories or imported Make-generated headers are used.

All compilation uses native cc_library/CTF actions. Maintained Make recipes are
qualification references rather than runtime graph discovery. Production C,
radio behavior, kernel security policy and tracing hooks are unchanged.

The maintained build-bsd bazel-test format-5 interface handles SDK, kernel
platform, CTF/debug settings, compact logs and 16 workers. No frontend C/backend
API, CLI/manual option, signing/verification/staging or package-policy change is
needed. Make remains production/default; BIP remains excluded.

## Evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-ath-make-metadata-r1-20261102 records maintained Make recipes with
  filemon disabled. All 130 reference objects retain their earlier completed-kernel
  hashes; selected source hashes match the independent inventory. The capture
  does not prove complete dynamic dependency coverage or comparative performance.
- bazel-kernel-ath-amd64-ctf-r1-20261102 is the successful normal frontend build,
  with immutable captures and compact execution evidence. All 130 successful
  compiler actions report cacheHit=false.
- bazel-kernel-ath-review-r1-20261102 records 13,883 physical and 488 generated
  prerequisite bindings. Actual warnings/order, defines, code-generation option
  sets, stack policy, final debug switch, language and forced includes match Make.
  Actual include roots pass the maintained order check independently.

All 130 .text and .SUNW_ctf sections match byte for byte. Allocated payload/layout
matches except 16 exact known-source filename spellings. All other strings and
16,170 nondebug relocations compare symbolically without rewriting artifacts.
Complete DWARF/string-table/symbol-index byte equality is not claimed.

CTF graph comparison uses the bounded read-only procedure explained in
OPENZFS-KERNEL-QUALIFICATION.md: typed symbol identities remain strict, while only
zero-type string-section object addresses use their complete verified string
contents and interior offsets. A filename adjustment must cover the original
full literal; its size follows the canonical source filename. Complete string
pools and all separate allocated-layout/relocation checks bind the original
object hashes. Every normalized identity remains recorded. This is not a claim
that the standalone CTF CLI passes every relocated untyped-string identity, and
no production verifier was changed or relaxed.

Compiler outputs bind by hash through CTF conversion to final immutable captures.
Generated-interface provenance comments use actual source basenames, with original
Make hashes retained; output/debug/random-seed paths remain explicit build-system
differences. Upstream compact-log conversion verifies all 189 recorded bindings
before/after and retains commands, log hashes and exit status. Expanded JSON is
streamed. Review/source/profile implementations and hashes remain retained.

Final query r22 passes for 1,191 known groups and 1,366 compiler actions. Guarded
reconciliation r17 finds 1,357 source matches, two object-name and four generated-
name matches, with 1,103 unmatched among 2,466 Make final link products. Three
auxiliary generator objects remain separate. Counts cover the known amd64 graph,
not a complete linked kernel or all-architecture compiled coverage.

## Observability and remaining gates

The bounded call-shaped scan finds existing tracing/CTR-family markers in if_ath.c;
no matches in 129 other files do not prove missing shared instrumentation. No
production hooks changed. Attach, calibration, association/authentication, rate
control, transmit/receive, power save, channel transitions and error recovery need
relevant radio/runtime qualification. tests=[] runs no live wireless tests.

Complete native kernel link/order/identity/post-processing/install, loadable
modules, alternate KERNCONF, ARM64/RISC-V64, world/pkgbase/hardware publication,
bootstrap and runtime/VM checks remain open. Disk reserves pass; controlled CPU,
memory, disk I/O, disk-use and cache comparisons remain open. No host installation,
upgrade or reboot occurred.
