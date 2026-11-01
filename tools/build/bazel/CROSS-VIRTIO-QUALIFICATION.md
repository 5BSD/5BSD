# ARM64 / RISC-V64 VirtIO modules

2026-11-01. Native Bazel declarations cover all nineteen VirtIO modules selected
by the independently architecture-checked ARM64 and RISC-V64 GENERIC Make
inventories: balloon, block, console, crypto, dtrace, fs, gpu, input, iommu, mem,
network, p9fs, pci, random, rtc, scsi, sound, virtio and vsock. PMEM remains
amd64-only, matching Make's NVDIMM condition. This does not qualify an entire
kernel or module set. Make remains the production backend; BIP is excluded.

## Native inputs and artifact pipeline

The declarations use original C sources, declared header dependencies and
registered target C++ toolchains. Three interface translation units come from
the maintained makeobjops generator. CAM, evdev, IPv4/IPv6, SCSI and sound options
are extracted from each target's actual generated GENERIC config tree, including
legitimately empty headers. No test replacement headers, C changes, runtime Make
parser or output rewriting are introduced. Source/dependency lists remain
explicit BUILD metadata; changes to shared driver inputs must update the amd64
and cross declarations together.

The existing native relocatable-link, CTF/export, shared-link, separate-debug and
installation pipeline handles both architectures. Core export-all and PCI's
explicit virtio_pci_get_shmem_region export are retained. Generated-source
compiler prefix mappings preserve Make's source-name provenance. The maintained
`build-bsd bazel-test --arch arm64|riscv64` kernel profile builds explicit module
and install targets with existing typed CTF/debug settings. No frontend API,
signing, staging or publication behavior changes are needed for these targets;
the manual documents their coverage.

## Independent comparison

Fresh Make builds and unprivileged staging passed all 76 combinations:
nineteen modules, two architectures, and CTF/debug off or on. Build inputs,
commands, flags, objects, generated files and METALOGs are retained under
`/usr/obj/usr/src/bazel-cross-virtio-make-20261101/`. The reference uses target
parent-kernel ARCH_FLAGS and current world tools, with all sixteen logical CPUs
available. NO_ROOT installation uses normal -U/-M/-D flags. NO_XREF excludes
linker.hints; no host installation or loading occurred.

Four native frontend runs each built 38 explicit module/install targets:
`/usr/obj/usr/src/bazel-cross-virtio-{arm64,riscv}-{plain,ctf}-r1-20261101/`.
All 38 no-debug modules match Make byte for byte. All 38 installed CTF/debug
modules match every ELF section and section offset except build-ID/debuglink
contents, including code/data, symbols, relocations, CTF and SDT. Both sets of
actual separate debug files pass GNU debuglink CRC validation. Separate debug
files retain DWARF/build-ID/symbol/layout differences; debugger source lookup
and full debug-file identity are unqualified. The review records every section
and offset difference rather than normalizing outputs. All 114 module/debug
file installation records match destination, type, owner/group, mode and tags;
directory metadata and linker.hints are outside this comparison.

Reports, input hashes, source scan and reproduction scripts are retained at
`/usr/obj/usr/src/bazel-cross-virtio-review-20261101/`. This is build/install
qualification, not runtime test execution: kernel-profile receipts intentionally
have no executable test selections. No new controlled CPU, aggregate compiler/
JVM memory, disk-I/O or allocated-disk performance claim is made.

## Remaining gates

Matching-kernel boot/load/unload and device attach/detach, reset/failure handling,
storage/network/filesystem/audio/graphics/input/IOMMU behavior, HyperTrace
transport and live probe firing remain open. The bounded source scan records
providers in core virtio/virtqueue, block and network, plus vsock probe schemas;
other sources' lack of direct markers does not establish absent subsystem
observation. Full kernel/module production, pkgbase integration, debugger,
cache/mutation and controlled resource comparisons remain required.
