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
transport support, packed rings, multiqueue, a broad set of new host device
models, and matching 5BSD guest drivers. The new models are balloon,
crypto, filesystem (bridging to `fusefs` in the guest), GPU, IOMMU, memory
hot-plug, pmem, RTC, sound, and vsock ([below](#vsock)), joining the
pre-existing block, net, console, SCSI, 9P, input, and RNG models. Outside
VirtIO, 5BSD also adds an **i6300esb watchdog** model — the Intel timer
that Linux and Windows guest drivers already bind to, with a configurable
expiry action — and **pvclock**, a default-off KVM-pvclock implementation
giving Linux and 5BSD guests a paravirtual clocksource.

**Packed rings and multiqueue.** Packed-ring support is implemented for
every device model but kept out of default feature masks, and the
throughput-oriented devices (block, SCSI, filesystem) negotiate multiqueue
end to end.

Two guest drivers are deliberately capability-bounded: virtio-mem does not
online plugged pages, and virtio-iommu does not drive `busdma(9)`
translation. Both are protocol-complete and default-off; their production
consumers are Linux guests. Deliberate spec exclusions are
fail-closed and unadvertised (`VIRTIO_F_ACCESS_PLATFORM` outside the iommu
path, admin virtqueue/SR-IOV grouping, device suspend, block secure erase).

## vsock

5BSD adds a complete virtio-vsock stack: an `AF_VSOCK` socket family
(documented in `vsock(4)`), a guest driver, and a host device model —
giving host and guest processes a socket channel addressed by context ID
and port with no network configuration inside the guest. Stream and
seqpacket sockets are supported with Linux-compatible addressing; there is
no datagram support. The device model offers two host backends — Unix
domain sockets, or attachment to the host's own `AF_VSOCK` domain so host
applications address the guest with plain vsock sockets — and
checkpointing is fail-closed: a snapshot is accepted only with no live
connection or buffered data. See `bhyve(8)`.

A 5BSD *component*, though, does not open `AF_VSOCK` directly: host-side
vsock is brokered by `vmd` (`system.VM`). A unit obtains a listener with
`service_vsock_listen(3)` or dials a peer with `service_vsock_connect(3)`;
each grant is scoped to a port window on the unit's unforgeable channel
label, and the listener carries data-plane rights so accepted sockets are
directly usable. `vmd` sits with the other system daemons in the
[Architecture](../architecture.md) overview and
[Service Manifests](../system/manifests.md); this chapter covers only the
transport beneath it.

## Live migration and nested VMX

Both capabilities are unexposed by default.

**Live migration** speaks a versioned, checksummed frame protocol through
explicit handshake, topology-validation, pre-copy, stop-copy, commit, and
release phases, with bounded convergence and contract-based device
eligibility. Both ends are handed an already-connected socket, and the
session rides on WASPNest's versioned checkpoint/state model. The receive
listener is not authenticated, and live migration is not yet enabled for
production use.

**Nested VMX** (Intel-only) puts all VMX semantics in the kernel behind a
strict frozen-vCPU handoff transaction. Exposure is triple-gated and
default-off: two boot tunables plus a per-VM capability each guest must
request. On AMD the capability is simply absent — fail-closed. Nested VMX
remains experimental.
