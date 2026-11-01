# VirtIO native module qualification

2026-11-01. This is an amd64 GENERIC module candidate, not complete kernel,
world, pkgbase, cross-architecture, runtime or performance qualification.
Make remains the production backend.

## Native graph

Fourteen new module declarations complete source-owned Bazel declarations for
all twenty VirtIO modules selected by the recorded amd64 GENERIC inventory:

- core `virtio` and PCI transport `virtio_pci`;
- `virtio_balloon`, `virtio_blk`, `virtio_console`, `virtio_crypto`;
- `virtio_dtrace`, `virtio_fs`, `virtio_gpu`, `virtio_input`, `virtio_iommu`;
- `if_vtnet`, `virtio_p9fs`, `virtio_scsi`.

The existing mem, pmem, random, rtc, sound and vsock module declarations remain.
The new BUILD files explicitly own real sources, headers, generated kobj
interfaces and ordered link inputs. Core preserves `EXPORT_SYMS=YES`; PCI exports
only `virtio_pci_get_shmem_region`; other new modules preserve default symbol
localization. FUSE, 9P, CAM/MMC, framebuffer/terminal, input, HyperTrace and netmap
headers remain source dependencies. Option headers are extracted from the real
config-generated GENERIC tree, including empty option headers. No replacement
OS sources or handwritten option contents are introduced.

New package boundaries required updating existing bhyve header labels. Source
exports retain the previous include layout. The common module compiler mapping
now covers inline code in transitive `sys/` headers as well as direct sources,
using the existing canonical `/usr/src` source-path convention. Generated
translation units retain their logical generated filenames. This is compiler
prefix mapping, not post-processing of compiled artifacts.

The source declaration refresh is
`/usr/obj/usr/src/bazel-module-declarations-virtio-20261101.json`:
106 direct module declarations against the previously recorded 729 selected
amd64 leaves; 623 still lack a direct declaration. It binds the preceding
inventory and current BUILD files by SHA-256. It is explicitly not a fresh
recursive Make selection or a count of qualified runtime products. ARM64 and
RISC-V remain required separate configurations and qualification work; these
module compilation rules currently constrain the target to amd64.

## Independent Make comparison

The maintained frontend run is
`/usr/obj/usr/src/bazel-virtio-family-qualification-r7-20261101/receipt.json`.
All fourteen new module files compare byte for byte with independent, fresh
Make output tied to the same GENERIC configuration, with CTF and split debug
disabled. All fourteen installation records match destination, owner, group,
mode, file type, flags and pkgbase tags. Symbol inventories, section tables and
relocations also match. No module was installed or loaded.

Make references and commands, including `/usr/bin/time -l` output:

- `/usr/obj/usr/src/bazel-virtio-transport-make-reference-20261101/evidence/`
- `/usr/obj/usr/src/bazel-virtio-devices-make-reference-20261101/evidence/`
- `/usr/obj/usr/src/bazel-virtio-network-make-reference-20261101/evidence/`

Comparison scripts, individual hashes and complete reports:

- `/usr/obj/usr/src/bazel-virtio-transport-parity-r7-20261101/`
- `/usr/obj/usr/src/bazel-virtio-devices-parity-r7-20261101/`
- `/usr/obj/usr/src/bazel-virtio-network-parity-r7-20261101/`

Earlier failures are retained. The initial runs identified parent-package
labels crossing new package boundaries and missing CAM/NVMe/MMC header closure.
The full independent Make dependency files were reviewed to complete that
closure. R6 then exposed relative filenames embedded by inline FUSE and netmap
headers; twelve modules matched bytes, two failed. The compiler path correction
resolved both; comparison criteria and binary outputs were not rewritten.

## CTF, debug and generated interfaces

`/usr/obj/usr/src/bazel-virtio-family-ctf-debug-qualification-20261101/`
builds all twenty VirtIO modules, plus backlight/filemon regressions and the
existing bhyve header groups, with CTF and split debug enabled: 78 selected
targets pass. Independent Make CTF/debug references for the fourteen new modules
are at `/usr/obj/usr/src/bazel-virtio-family-ctf-debug-make-reference-20261101/`.
Both profiles use the declared `5BSD-Bazel-virtio` CTF label. The reference uses
host CTF tools; Bazel builds its CTF tools from source.

All fourteen installed modules have matching file-backed ELF payloads apart
from build-ID and debuglink identity; raw CTF, symbol tables, relocations and
SDT sections match. Both sides' separate debuglink names and CRCs validate, all
debug-file symbol tables match, and all 28 installation records match. This is
not whole-file or whole-DWARF identity, nor source-debugger qualification.

The strict comparison is deliberately retained as failed in
`/usr/obj/usr/src/bazel-virtio-family-ctf-debug-parity-20261101/parity.json`.
Thirteen modules have only build-ID/debuglink differences. Console also differs
in the `.bss` section's `sh_offset`: Make records `0x6878`, native records
`0x6ab8`. Its type is `SHT_NOBITS`; size (36 bytes), alignment (8), flags,
address and all remaining fields match. This section has no file-backed payload.
The kernel loader (`sys/kern/link_elf_obj.c`) uses its size/alignment and zeroes
it, reading file offsets only for file-backed sections. A separate bounded
review verifies this exact difference and every other section field/payload in
`bounded-section-review.json`; it does not turn the strict failure green.
Reproducible CTF/debug container identity remains an open toolchain gate.

The seven generated `.c`/`.h` files actually consumed by Make have identical
bodies. Literal files differ in the provenance comment: Make names the absolute
`.m` input, the native generator names its basename. Both originals, raw diffs
and the narrowly bounded review are under the same parity directory's
`generated-r2/`. `fb_if.c` is generated by the native interface rule but is not
compiled by this driver; only `fb_if.h` is a comparable Make input.

## Unchanged-input reuse

`/usr/obj/usr/src/bazel-virtio-family-cache-20261101/cache-review.json`
verifies the repeated 78-target CTF/debug configuration produced an identical
captured artifact manifest (SHA-256
`641601bcebcbef0f74fd734163e62b509cfc2c405af232b9799dbd78a2d5e9f7`).
Bazel reported one internal action, and its external spawn log is empty. This
proves unchanged-input reuse for these configured targets. It does not prove
source mutation invalidation, clean bootstrap, remote cache or cross-workspace
portability.

## Frontend and outstanding gates

These declarations use the existing maintained format-5 `build-bsd bazel-test`
interface and native module, CTF, debug and installation helpers. No new CLI,
security policy, signing, publication or production-backend semantics are
introduced. Foundry/build-bsd does not invoke per-component Make to build the
Bazel targets; Make is used independently as the migration reference.

Kernel boot, module load/unload, device operation, live tracing, audit delivery,
source-level debugger paths, source mutation/cache invalidation, portable SDK
bootstrap and ARM64/RISC-V qualification remain open. Resource counters captured
for these commands are not a controlled Make/Bazel performance comparison;
CPU, memory, disk I/O and disk-usage gates remain required. BIP is out of scope.
