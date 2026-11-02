# Mellanox built-in kernel qualification

## Scope (2026-11-02)

52 selected Mellanox C sources have native amd64 GENERIC built-in declarations
under the existing sys/dev/mlx5 package, including core, Ethernet and acceleration
paths. 71 distinct physical header contexts share identical dependency sets.
CONFIG_INFINIBAND_USER_MEM, maintained warning order/exceptions and the forced
LinuxKPI kconfig.h include are preserved. No production source or device/runtime
security policy changed.

OFED then UAPI then LinuxKPI search roots precede ordinary BSD sys headers exactly
as in maintained OFED_CFLAGS. The new sys/ofed/include parent owns previously
unowned RDMA headers and refers to explicit narrowly exported files in the existing
UAPI/rdma child package. It does not change child file ownership. A new mlxfw owner
provides its physical firmware header. Existing LinuxKPI source packages remain.
The unused dummy search root has no consumed files and is omitted from sandbox
lookup; no placeholder directory or warning suppression is introduced.

Actual config-tree outputs supply INET/INET6, IPsec, TLS, rate-limit and RSS options.
Existing bus/device, PCI/PCI-IOV, vnode and offset producers are reused. No fixed
option contents or imported Make-generated headers substitute for native actions.
Reference recipes do not become runtime build-graph discovery.

The maintained build-bsd bazel-test format-5 interface handles SDK/platform,
CTF/debug settings, compact logs and all 16 workers. No additional frontend C/
backend API, CLI/manual option, signing/verification/staging or package-policy
change is needed. Make remains production/default; BIP remains excluded.

## Evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-mlx-make-metadata-r1-20261102 records supported Make recipes with
  filemon disabled. All 52 prior completed-kernel reference objects retain their
  hashes; selected C hashes match the independent inventory. This capture does
  not prove complete dynamic dependency coverage or comparative performance.
- bazel-kernel-mlx-amd64-ctf-r1-20261102 is the successful native frontend build,
  retaining immutable captures and compact logs. All 52 successful actual compiler
  actions report cacheHit=false.
- bazel-kernel-mlx-review-r1-20261102 binds 22,504 physical and 569 generated
  prerequisites. Actual ordered warnings, defines, code-generation option sets,
  stack protection, final debug switch, language and forced includes match Make.
  Every compile independently passes the OFED/UAPI/LinuxKPI include-order check.

All 52 .text and .SUNW_ctf sections match byte for byte. Allocated payload/layout
matches except 35 exact known-source filename spellings. All other strings and
12,602 nondebug relocations compare symbolically without artifact rewriting.
Complete DWARF/string-table/symbol-index byte equality remains unclaimed.

CTF graph review uses the bounded read-only procedure described in
OPENZFS-KERNEL-QUALIFICATION.md. Typed symbol identities stay strict. Only
zero-type string-section object addresses use complete verified canonical strings
and interior offsets; a filename size adjustment must cover its full original
literal. All adjustments remain recorded. Separate complete string-pool,
allocated-layout and relocation gates bind original object hashes. No production
verifier is changed or reported as passing a different comparison scope.

Compiler outputs bind through CTF input/output hashes to final immutable captures.
Generated-interface provenance comments map only actual schema paths to basenames,
retaining original Make hashes. Debug/output/random-seed paths remain explicit
build-system differences. Upstream compact-log reconstruction verifies all 189
converter bindings before/after, preserving commands, log hashes and exit status.
Expanded JSON is streamed. Source/profile/review implementations and hashes remain.

Final query r24 passes for 1,312 known groups and 1,487 compiler actions. Guarded
reconciliation r19 finds 1,478 source matches, two object-name and four generated-
name matches, leaving 982 unmatched among 2,466 Make final link products. Three
auxiliary generator objects remain separate. These counts cover known amd64
analysis, not a complete linked kernel or all-architecture compiled coverage.

## Observability and remaining gates

The bounded call-shaped scan finds existing tracing/CTR-family markers in
mlx5_health.c. No matches in 51 other files do not establish missing shared
instrumentation or absence of other tracing mechanisms. Production hooks stay
unchanged. Attach/firmware, queues/RSS, offload/IPsec/TLS, link transitions,
SR-IOV/RDMA, health/reset and recovery need relevant runtime/device tests.
tests=[] performs no live NIC or firmware activity.

Complete native kernel link/order/identity/post-processing/install, loadable
modules, alternate KERNCONF, ARM64/RISC-V64, world/pkgbase/hardware publication,
bootstrap and runtime/VM checks remain open. Disk reserves pass; controlled CPU,
memory, disk I/O, disk-use and cache comparisons remain open. No host installation,
upgrade or reboot occurred.
