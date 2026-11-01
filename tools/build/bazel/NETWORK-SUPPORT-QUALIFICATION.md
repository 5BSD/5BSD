# Native iflib, etherswitch and toecore qualification

2026-11-01. Native GENERIC-tied component candidates now cover these three
modules on amd64, ARM64 and RISC-V64 in plain and CTF/debug configurations.
All eighteen independent Make references pass under
`/usr/obj/usr/src/bazel-network-support-make-r1-20261101`.

## Native source and configuration graph

Permanent BUILD declarations compile the original iflib.c, mp_ring.c,
etherswitch.c and toecore.c, plus genuine ifdi_if.c and etherswitch_if.c
outputs from makeobjops.awk. They preserve original source/object order,
export policy, Make warning flags and target GENERIC option-header contents.
Source-owned header contexts include actual Make prerequisites with explicit
consumer visibility. No C source, warning suppression or Make source selection
changed. The native build does not invoke Make for discovery or compilation.

Additional option-file views extract genuine opt_sched.h and opt_acpi.h
outputs from the target config tree. The first ARM64
analysis failed because the existing ACPI-header provider omitted the new
sys/net consumer. Only that legitimate consumer was added, specifically for
ACPI; unrelated NVMe visibility was not widened. The failed r1 analysis and
its logs remain intact. An audit attempted before that failure was noticed
also rejected missing successful receipts. Earlier incomplete audit directories
are retained; the completed reports are under review-r2.

## Passed gates

The initial amd64 plain profile passes under
`bazel-network-support-amd64-plain-r1-20261101`. The other five corrected
profiles pass under `bazel-network-support-{arch}-{variant}-r2-20261101`,
where arch is amd64, arm64 or riscv and variant is plain or ctf. All paths
in this document are relative to `/usr/obj/usr/src` unless stated otherwise.

- 18 module configurations and 27 exact Make installation records.
- Nine plain installed modules byte-identical to Make.
- Nine installed CTF modules with equal section metadata/payload except
  build-ID/debuglink, exact .SUNW_ctf, and verified native/Make debug CRCs.
  Separate-debug DWARF byte identity is not claimed.
- 36 actual compiler actions with original warning vectors, target triples,
  forced opt_global.h and no SDK kernel-header fallback.
- 132 option-header hashes, 3,842 physical Make source/header hash checks
  across 207 unique files, and all 18 original object orders.

Artifacts resolve through immutable receipt/manifest/content bindings. Every
link parameter file was captured and hash-checked immediately before switching
profiles. Review reports, copied profiles and audit scripts reside in
`bazel-network-support-review-r2-20261101`.

All six complete generated interface source/header outputs for ifdi_if,
etherswitch_if and pci_iov_if match independent basename invocations of the
original generator. The five outputs actually requested by Make differ only
in one provenance-comment source pathname. Make requests only the PCI_IOV
header; its generated C output is captured but is not a module compilation
input. The etherswitch and PCI_IOV generators executed freshly; ifdi_if was
cached from the preceding Ethernet cohort. Source/generator hashes and actual
action environments are checked. Evidence is in
`bazel-network-support-generator-review-r2-20261101`.

## DTrace and SDT preservation

The four physical production sources were scanned; iflib.c contains thirteen
SDT/DTrace marker lines. All six iflib configurations retain eight SDT data
and relocation sections with exact Make payload/metadata, including provider,
probe, argument-type and tracepoint sets. Their SDT/DTrace symbol records
also match exactly: 70 on each amd64 variant and 67 on each cross variant.
All four suspend/resume probe descriptors are explicitly checked. This verifies
compiled instrumentation; live probe firing and hardware behavior are open.
See the retained sdt-review.json and observability.json.

## Resources, integration and remaining gates

Reference and native batches use all sixteen logical CPUs, with isolated
Make objects/staging and genuine copied/hashed target option inputs. Each
reference leaf asserts .OBJDIR and SRCS before compiling. Disk guards require
18 GiB free initially and retain a 16 GiB reserve; no reserve was breached.
A misspelled guard option was rejected before any build started and corrected.
Resource logs include concurrent work and qualification overhead; they are
not controlled performance comparisons.

The existing build-bsd format-5 action, module/install/configuration helpers
and C/CLI express this cohort without a new frontend option. README, manual,
observability notes and completion gates are updated together. Make remains
production/default. No host installation, module loading or runtime test is
part of these six build profiles.

Fresh source inventories in `bazel-network-support-module-inventory-20261101`
select 729 amd64, 627 ARM64 and 553 RISC-V64 modules without query errors.
The amd64 presence diagnostic now counts 225 direct native declarations and
504 without. Those are declaration counts, not qualified-product totals.

Full native world/kernel/pkgbase/image builds, alternate configurations,
hardware/network operation, live tracing, VM system/service acceptance and
comparative CPU/memory/disk/cache tests remain open. The inherited generator
uses AWK system(), which invokes host /bin/sh; this cohort does not establish
hermetic execution-platform closure. That remains an explicit completion gate.
BIP is out of scope.
