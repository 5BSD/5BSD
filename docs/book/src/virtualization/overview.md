# WASPNest

WASPNest is 5BSD's virtualization stack. It builds on the in-tree bhyve
hypervisor and its `vmm(4)` kernel subsystem, adding substantially broader
VirtIO device coverage, a versioned checkpoint/state model, live-migration
machinery, and experimental Intel nested VMX.

The stack keeps bhyve's kernel/userspace split: the kernel `vmm` subsystem
executes guest vCPUs on Intel VMX/EPT or AMD SVM/NPT and owns stage-2
translation, interrupt controllers, timers, and PCI passthrough; one
`bhyve(8)` process per VM builds the machine model, emulates devices, and
enters Capsicum capability mode before the guest runs; `libvmmapi` wraps the
`/dev/vmm` ioctl ABI. On the capability plane, `vmd` (`system.VM`) brokers
host-side vsock (below); guest-facing VM management by `vmd` — launching and
brokering bhyve VMs — is not yet provided.

**Naming.** The hypervisor is being renamed from bhyve to WASPNest,
deliberately gradually: today `waspnest` is a symlink to the `bhyve` binary
with a matching man-page link, both shipped in the `bhyve` package, so
tooling can already reference the new name. Eventually the binary will be
`waspnest` with `bhyve` as the compatibility alias.

**Guests.** Three guest families are supported: 5BSD (including kernels
rebuilt with the new VirtIO drivers), other BSD guests (the classic bhyve
guest interface is unchanged), and Linux, with Alpine as the reference
image. Linux is the primary consumer for host models whose 5BSD guest
support is protocol-bounded (virtio-mem hotplug, virtio-iommu translation).

## VirtIO device models

The largest single work program is VirtIO: modern (virtio 1.4) PCI
transport support, packed rings, multiqueue, new host device models
(`usr.sbin/bhyve/pci_virtio_*.c`, 17 in all), and matching 5BSD guest
drivers under `sys/dev/virtio/`. The new device models:

| Device | Notes |
| --- | --- |
| balloon | stats, deflate-on-OOM, free-page hinting/reporting |
| crypto | AES-CBC, SHA-256, HMAC-SHA-256, AES-GCM over an OpenSSL EVP host backend; 5BSD guest driver registers with `opencrypto(9)` |
| fs | modern-only, up to 64 request queues, external backend over authenticated `SOCK_SEQPACKET`; guest bridges to `fusefs` |
| gpu | unaccelerated 2D, one scanout, feeds the framebuffer console |
| iommu | map/unmap, probe, fault queue, generated ACPI VIOT |
| mem | memory hot-plug |
| pmem | guest maps as NVDIMM |
| rtc | virtio 1.4 §5.23, UTC clock, opt-in alarm |
| sound | playback + capture bridged to `pcm(4)` |
| vsock | see [vsock](#vsock) below |

These join the pre-existing block, net, console, SCSI, 9P, input, and RNG
models. Outside VirtIO, 5BSD also adds an **i6300esb watchdog** model
(`pci_i6300esb.c`) — the Intel 6300ESB timer that Linux and Windows guest
drivers already bind to, with configurable expiry action
(`action=reset|poweroff|nmi|notify`) — and **pvclock**
(`sys/amd64/vmm/io/vpvclock.c`), a default-off KVM-pvclock MSR
implementation giving Linux `kvm-clock` and the 5BSD `kvm_clock(4)` driver
a paravirtual clocksource.

**Packed rings and multiqueue.** Packed-ring support is implemented for
every device model (`packed=true`, modern transport only) but kept out of
default feature masks; on the guest side
the shared `virtqueue.c` engine serves virtio-blk and virtio-sound.
virtio-blk, virtio-scsi, and virtio-fs negotiate multiqueue end to end.

Two guest drivers are deliberately capability-bounded: virtio-mem does not
online plugged pages, and virtio-iommu does not drive `busdma(9)`
translation. Both are protocol-complete and default-off; their production
consumers are Linux guests. Deliberate spec exclusions are
fail-closed and unadvertised (`VIRTIO_F_ACCESS_PLATFORM` outside the iommu
path, admin virtqueue/SR-IOV grouping, device suspend, block secure erase).

## vsock

5BSD adds a complete virtio-vsock stack: an `AF_VSOCK` socket family
(`sys/kern/uipc_vsock.c`, family 46, documented in `vsock(4)`), a
`virtio_vsock.ko` guest driver, and a host device model
(`pci_virtio_vsock.c`) — giving host and guest processes a socket channel
addressed by context ID (CID) and port with no network configuration inside
the guest. `SOCK_STREAM` and `SOCK_SEQPACKET` are supported, with
Linux-compatible `VMADDR_*` addressing; there is no datagram support.

The device model (`-s <slot>,virtio-vsock,cid=<n>,...`, see `bhyve(8)`)
offers two host backends: `backend=userspace` (default) maps host endpoints
to Unix domain sockets in a directory, and `backend=kernel` attaches the VM
to the host's own `AF_VSOCK` domain via `/dev/vsock`, so host applications
address the guest with plain vsock sockets; multiple concurrent guests are
supported. Checkpointing is fail-closed: a snapshot is accepted only with
no live connection or buffered data.

A 5BSD *component*, though, does not open `AF_VSOCK` directly: host-side
vsock is brokered by `vmd` (`system.VM`). A unit obtains a listener with
`service_vsock_listen(3)` or dials a peer with `service_vsock_connect(3)`;
each grant is scoped to a port window on the unit's unforgeable channel
label, and the listener carries data-plane rights so accepted sockets are
directly usable. `vmd` sits with the other system daemons in the
[Architecture](../architecture.md) overview and
[Service Manifests](../system/manifests.md); this chapter covers only the
transport beneath it.

vsock is among the most complete WASPNest devices, exercised by rootless
ATF harnesses and end-to-end guest suites under `tests/sys/kern/`.

## Live migration and nested VMX

Both capabilities are unexposed by default.

**Live migration** (`usr.sbin/bhyve/`) speaks a versioned, CRC-checked frame
protocol (`MIG1`) through explicit handshake, topology-validation,
pre-copy, stop-copy, commit, and release phases, with bounded convergence
and contract-based device eligibility. Both ends are handed an
already-connected socket: the destination runs `bhyve -R <fd>`, the source
issues a `migrate fd=<fd>` command over bhyve's control socket. The session
rides on the versioned checkpoint/state model (named, checksummed state
sections, explicit machine-type ABIs, named CPU baselines). The `-R`
listener is not authenticated, and live migration is not yet enabled for
production use.

**Nested VMX** (Intel-only) puts all VMX semantics in the kernel — VMCS12
validation, VMCS02 construction, combined EPT, exit reflection, nested
state serialization — behind a strict frozen-vCPU handoff transaction
(`sys/amd64/vmm/intel/vmx_nested_instruction_handoff.c`). Exposure is
triple-gated and default-off: the boot tunables `hw.vmm.vmx.nested` and
`hw.vmm.vmx.nested_vpid`, plus a per-VM `nested_vmx` capability each guest
must request. On AMD the capability is simply absent — fail-closed. Nested
VMX remains experimental.
