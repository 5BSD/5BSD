# Native NVMe, NVD and AHCI module candidates

2026-11-01. Native GENERIC-tied nvme, nvd and ahci module/install targets cover
amd64, ARM64 and RISC-V64. Make remains production/default. This is bounded
artifact qualification; hardware storage I/O, module runtime and performance
are not qualified by these builds.

## Graph and maintained Make correction

Source-owned declarations retain eleven NVMe C sources, one NVD source and
three common AHCI sources. ARM64 additionally compiles ahci_generic.c with its
real generated ACPI/platform option headers and ACPI/OFW interfaces. Original
Make selections include all three modules on all three supported architectures.

Module links forward declared compiler outputs through native selected-object
providers in original SRCS order. NVMe retains EXPORT_SYMS=YES. Generated
nvme_if, bus/device, PCI, vnode and ARM64 AHCI interfaces use the existing
maintained generators; source-owned providers supply physical source headers.
No source files or finished binaries are rewritten to make comparisons pass.
NVMe options are extracted from each real config tree; CAM reuses the existing
providers. Private source headers are not substituted with SDK user headers.
Existing userland NVMe/CAM exports remain available.

The independent Make references intentionally use header-only KERNBUILDDIRs,
containing copied and hashed actual GENERIC opt_*.h inputs. This exposed a real
Make omission: nvme_test.c includes syscallsubr/mount/vnode headers indirectly,
but the module did not declare generated vnode_if.h. All six NVMe reference
builds failed without an old GENERIC-generated header to hide the omission.
The maintained nvme Makefile now declares vnode_if.h, allowing normal generation.
No C/ABI, service policy or host installation changes were needed.

## Qualification evidence

Evidence resides under /usr/obj/usr/src:

- bazel-storage-make-20261101 retains the initial twelve successful references
  and six missing-vnode-header failures.
- bazel-storage-make-r2-20261101 contains eighteen fresh successful independent
  Make builds/installations: three modules, three architectures, plain and CTF.
  Four independent jobs use -j4 each on this 16-CPU host.
- bazel-storage-{amd64,arm64,riscv}-{plain,ctf}-r3-20261101 are six successful
  maintained build-bsd profiles. Format 5 and target-kind=kernel use the actual
  SDK receipt/toolchain, real generated options and sixteen jobs. Each selects
  three module targets and three install manifests, with tests empty; artifact
  success does not represent runtime test success.
- bazel-storage-review-20261101 retains the immutable artifact comparisons,
  actual compile/input and link-order audits, source hashes, profiles and
  reproduction helpers.

Targets are //sys/modules/{nvme,nvd,ahci}:generic_module and :install_manifest;
ARM64/RISC-V prefix these target names with arm64_ and riscv_. The profile files
and recorded argv supply the exact maintained frontend invocations.

All nine plain module files are byte-identical to fresh Make references. All
nine installed CTF modules match section metadata and payloads except expected
build ID/debuglink CRC differences; .SUNW_ctf matches exactly. Both native and
Make separate-debug CRC checks pass. Complete DWARF/layout parity is open.
ELF machine/type match each maintained architecture's module contract. All
27 installed file records match destination, type, owner/group, mode and tags;
directory aggregation and linker.hints remain outside this gate.

The action audit checks 92 distinct module C compilations across the matrix:
15 sources per amd64/RISC-V configuration, sixteen per ARM64 configuration.
Fifteen amd64 plain actions are retained from the successful r2 build and reused
by r3; 77 execute in r3. Each retained/executed source digest matches the reviewed
source. All use the expected target triple, freestanding flags, original warning
list and declared kernel inputs without SDK user include inputs. Required option
headers are independently derived per translation unit from Make .depend files;
520 declared option-header hash checks match the actual Make GENERIC headers.

All eighteen linker parameter files are captured and SHA-bound to successful
execution inputs, proving actual Make source/object order including ARM64's
appended AHCI source. Three amd64 plain link records are reused from r2, fifteen
execute in r3; provenance is explicit. Comparisons use immutable captured
artifact payloads and verify recorded SHA256 before inspection.

Earlier native attempts remain: r1 rejected a duplicate CAM provider declaration
in analysis; the existing generated provider is reused instead. r2 built amd64
but ARM64 analysis found a missing rules_cc import in the previously interface-only
OFW package; its new header declarations now load the proper rule explicitly.
Failures are retained and are not counted as completed matrix passes.

## Observability and remaining gates

The sixteen-source scan records seventeen direct textual SDT/DTRACE marker
lines across NVMe controller/queue and AHCI reset paths. Existing probe sections
are retained in the matching artifacts. This is not a live probe count or proof
of argument/runtime coverage. Thirteen sources without direct markers are
listed in observability-audit.md for contextual review.

Matching-kernel module load/unload, NVMe controller/namespace discovery, NVD/GEOM
attachment, AHCI/SATA/CAM operation, queue depth, interrupt/DMA/IOMMU behavior,
timeouts/abort/reset recovery, hotplug and failure/concurrency paths remain open.
QEMU storage devices and hardware should exercise these alongside filesystem
and disk I/O workloads, recording host/guest RAM, CPU, disk usage and I/O against
Make-built controls. No live host storage modules, datasets or services changed.

This batch uses existing build-bsd kernel profile support; no frontend C or CLI,
signing, staging or publication change is required. The manual documents the
new candidates. Complete kernels/world/pkgbase, sandbox/bootstrap closure,
input-mutation behavior, controlled performance, publication and complete
system boot/SSH remain open. BIP is excluded; Make remains the production backend.
