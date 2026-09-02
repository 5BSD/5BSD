# WASPNest Overview

WASPNest is 5BSD's virtualization stack. It is not a new hypervisor: it is
the FreeBSD bhyve hypervisor and its `vmm(4)` kernel subsystem, extended in
the 5BSD tree with substantially broader VirtIO device coverage, a versioned
checkpoint/state model, live-migration machinery, experimental Intel nested
VMX, and a ledger-driven qualification program.

## Architecture

The stack keeps bhyve's deliberate kernel/userspace split:

- The kernel `vmm` subsystem (`/usr/src/sys/amd64/vmm/`, with arm64 and
  RISC-V ports under `sys/arm64/vmm/` and `sys/riscv/vmm/`) executes guest
  vCPUs on Intel VMX/EPT or AMD SVM/NPT, and owns stage-2 translation,
  interrupt controllers, timers, and PCI passthrough.
- One `bhyve(8)` userspace process per VM (`/usr/src/usr.sbin/bhyve/`) builds
  the machine model, emulates devices, runs one pthread per vCPU plus a
  kqueue (`mevent`) reactor, and enters Capsicum capability mode before the
  guest runs.
- `libvmmapi` (`/usr/src/lib/libvmmapi/`) wraps the `/dev/vmm` ioctl ABI.
- `vmd` (`system.VM`) is the capability-plane broker for host-side vsock: a
  component asks for a listener by name with `service_vsock_listen(3)` and
  receives a port window scoped to its channel label, rather than opening
  `AF_VSOCK` itself. (Brokering bhyve VMs themselves is planned.)

A code-guided tour of the whole stack is maintained in
`/usr/src/BHYVE_ARCHITECTURE.md`.

## Naming transition

The hypervisor is being renamed from bhyve to WASPNest. The transition is
deliberately gradual: today `waspnest` is installed as a symlink to the
`bhyve` binary, with a matching man-page link, so packaging and tooling can
already reference the new name (`usr.sbin/bhyve/Makefile`):

```makefile
SYMLINKS+=	bhyve ${BINDIR}/waspnest
MLINKS+=	bhyve.8 waspnest.8
```

```console
$ ls -l /usr/sbin/waspnest
lrwxr-xr-x  1 root wheel 5 ... /usr/sbin/waspnest -> bhyve
```

Eventually the binary will be named `waspnest` with `bhyve` kept as the
compatibility alias. Both names ship in the `bhyve` package. Documentation
and test infrastructure in the tree already use the WASPNest name
(`tests/waspnest/`, `docs/waspnest-*.md`).

## What 5BSD adds over stock bhyve

The upstream-FreeBSD weaknesses called out in `BHYVE_ARCHITECTURE.md` —
legacy-only VirtIO transports for core devices, experimental save/restore, no
live migration, no nested virtualization, single-queue virtio-net — are the
work program of this tree. Additions include:

- Modern VirtIO 1.4 PCI transport work, packed rings, multiqueue, and
  administration virtqueues (`usr.sbin/bhyve/virtio_admin*.c`).
- New host device models: virtio-balloon, virtio-fs, virtio-gpu,
  virtio-iommu, virtio-mem, virtio-pmem, virtio-rtc, virtio-sound, and
  virtio-vsock (`usr.sbin/bhyve/pci_virtio_*.c`). See
  [VirtIO](virtio.md) and [vsock](vsock.md).
- Matching 5BSD guest drivers, including five added in the 2026-08 driver
  wave (sound, fs, mem, pmem, IOMMU) under `sys/dev/virtio/`.
- A versioned checkpoint/state model (`usr.sbin/bhyve/checkpoint_*.c`,
  `snapshot*.c`) and a live-migration session protocol
  (`usr.sbin/bhyve/migration_session.c`). See
  [Migration and nested VMX](migration-nested.md).
- Experimental Intel nested VMX
  (`sys/amd64/vmm/intel/vmx_nested_instruction_handoff.c`), default-off and
  Intel-only.

## Supported guests

The qualification lab exercises three guest families:

- **5BSD** guests, including kernels rebuilt from this tree with the new
  VirtIO drivers (`tests/sys/kern/vsock_e2e/run-5bsd-auto.sh`,
  `build-5bsd-virtio-modules.sh`).
- **FreeBSD** guests: 5BSD is a FreeBSD fork and the guest interface is
  unchanged, so stock FreeBSD guests run as upstream bhyve guests do; the
  qualification lanes themselves use 5BSD and Alpine images.
- **Linux** guests, using Alpine as the reference image
  (`tests/sys/kern/vsock_e2e/run-alpine-auto.sh`). Linux is also the primary
  consumer for host models whose 5BSD guest support is protocol-bounded
  (virtio-mem memory hotplug, virtio-iommu DMA translation).

## Completion status

Status: WASPNest is explicitly not feature-complete. Completion is tracked
per requirement row in machine-readable TSV ledgers, with
`docs/waspnest-completion-matrix.md` as the entry point. As of the 2026-08-13
snapshot:

- VirtIO: 237 of 240 requirement rows are `implemented-tested` (the other 3
  are explicit, fail-closed exclusions), but of 130 live activation rows only
  33 are `exercised` on Linux and 8 on 5BSD — host-model evidence is not
  live-guest evidence.
- Non-VirtIO devices (AHCI, NVMe, e82545, HDA, xHCI, framebuffer, UART, TPM
  CRB, pvpanic, fw_cfg, and others): host model tests exist, but all 13
  inventory rows are still `pending` for live guest and save/restore
  qualification.
- Intel nested VMX: 408 of 437 requirement rows `foundation-tested-
  experimental`, 29 `experimental-pending-live`; zero of twelve live
  qualification groups have passed, and nested VMX stays unexposed
  (default-off host tunable) until they do.

The release gate (`docs/waspnest-completion-matrix.md`) requires every live
row to be exercised or explicitly excluded before the project is called
complete. The qualification process itself is described in
[Qualification](qualification.md).
