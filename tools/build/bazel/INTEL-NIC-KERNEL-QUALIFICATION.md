# Intel NIC built-in qualification

## Scope (2026-11-02)

69 selected C sources have native amd64 GENERIC built-in declarations: 23 e1000,
24 ixgbe and 22 ice sources. New e1000/ixgbe packages own their sources/headers;
ice keeps its existing owner. 56 distinct physical header contexts share identical
dependency sets. Ordinary built-in warnings remain unchanged. The two ixgbe
sources with maintained -DSMP retain that definition independently.

The actual config tree supplies driver-failpoint, INET/INET6, RSS, polling and DDB
options, including the newly extracted opt_driver_failpoints.h. Bus/device, PCI/
PCI-IOV, MDIO, iflib and RDMA interface views reuse existing schema producers.
CK/driver search order follows Make. No runtime features, warnings or security
policy were altered and no generated option/interface headers were imported
from Make. Reference recipes do not become native build-time discovery.

The maintained build-bsd bazel-test format-5 interface handles SDK/platform,
CTF/debug settings, compact logs and all 16 workers. No new frontend C/backend API,
CLI/manual option, signing/verification/staging or package-policy change is needed.
Make remains production/default; BIP remains excluded.

## bhyve ownership compatibility

Root-owned bhyve header providers continue exposing the same virtual include
views. Four physical e1000 path strings become explicit source-owner labels;
the two header exports are narrowly visible to the root package. Files and
provider include spellings remain unchanged.

Before/after native context queries retain exact CcInfo and 9,662 dependency
actions over 34,442 artifact paths. The first all-field comparison correctly
rejects 333 changed compiler action keys; that report is retained. The second
comparison records those keys explicitly and proves no other emitted field
changes: arguments, exact dependency path sets, environment, configurations,
execution platforms, templates and other non-ID data match. No path mapping
is used. Dependency union uses exact shared path bitsets to bound review memory.

Action-key differences are not reported as cache identity. A separate normal
frontend build of //usr.sbin/bhyve:bhyve passes and captures the affected binary.
This proves an actual post-move build, not guest boot, hardware use, package
installation or fresh execution of every action. No VM was launched for this gate.

## Evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-intel-nic-make-metadata-r1-20261102 records supported Make metadata
  without filemon. All 69 prior completed-kernel reference hashes stay unchanged;
  selected source hashes match the independent inventory. This does not establish
  complete dynamic dependency coverage or a performance baseline.
- bazel-kernel-intel-nic-amd64-ctf-r1-20261102 is the successful kernel component
  build, with immutable captures and compact logs. All 69 successful compiler
  actions report cacheHit=false.
- bazel-kernel-intel-nic-review-r1-20261102 records 12,538 physical and 427 generated
  prerequisite bindings. Actual warnings/order, defines, code-generation options,
  stack policy, final debug switch, language, forced includes and source search
  order match Make. Compiler outputs bind through CTF hashes to final captures.
- bazel-intel-nic-bhyve-context-{before,after}-native-r1-20261102 contain the
  configured compatibility evidence. comparison-r2.json records all key changes.
  bazel-intel-nic-bhyve-ownership-r1-20261102 is the successful actual binary build.

All 69 .text and .SUNW_ctf sections match byte for byte. Allocated payload/layout
matches except 35 exact known-source filename spellings. All other strings and
35,807 nondebug relocations compare symbolically without artifact rewriting.
Complete DWARF/string-table/symbol-index byte equality remains unclaimed.

CTF graph review uses the bounded read-only procedure documented in
OPENZFS-KERNEL-QUALIFICATION.md. Typed symbol identities stay strict. Only
zero-type string-section object addresses use complete verified canonical strings
and interior offsets, with full-literal bounds for source filename size changes.
Complete string-pool, allocated-layout and relocation gates bind original hashes.
All adjustments remain recorded; no production verifier is modified or reported
as passing a different scope. Generated interface provenance comments map only
the actual schema path to its basename, retaining original Make hashes.

Upstream compact-log reconstruction verifies all 189 recorded converter bindings
before/after and records commands, log hashes and exit status. Expanded JSON is
streamed. Source/profile/review implementations and hashes remain retained.

Final known-kernel query r23 passes for 1,260 groups and 1,435 compiler actions.
Reconciliation r18 finds 1,426 source matches, two object-name and four generated-
name matches, leaving 1,034 unmatched among 2,466 Make final link inputs. Three
auxiliary generator objects stay separate. These are known amd64 analysis counts,
not a complete linked kernel or all-architecture compiled coverage.

## Observability and remaining gates

The bounded call-shaped scan finds existing tracing/CTR-family markers in
if_igb_iov.c, if_ix.c, if_sriov.c and ice_fw_logging.c. No production probes changed.
No matches in the other 65 files do not establish missing shared instrumentation.
NIC attach, queues/RSS, checksum/segmentation offload, interrupt moderation, link
transitions, reset/recovery, netmap, SR-IOV and RDMA require relevant runtime and
hardware qualification. tests=[] executes no live NIC/guest tests.

Full native kernel link/order/identity/post-processing/install, loadable modules,
alternate KERNCONF, ARM64/RISC-V64, world/pkgbase/hardware publication, bootstrap,
VM/runtime checks and controlled CPU/memory/disk I/O/disk-use/cache comparisons
remain open. Disk reserves pass. No host installation, upgrade or reboot occurred.
