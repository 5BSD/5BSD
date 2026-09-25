# Virtual Machines

bhyve(8) is 5BSD's hypervisor, and it keeps its name. 5BSD's virtualization work, tracked under the working name WASPNest, makes it a much larger program than FreeBSD's: a modern VirtIO 1.4 transport with packed rings and multiqueue, ten new VirtIO device models and nine new guest drivers, an `AF_VSOCK` socket domain end to end, a versioned checkpoint format with live-migration machinery, and experimental Intel nested VMX. On the capability plane, BSDVM (system.VM) brokers vsock endpoints for sandboxed units. This chapter names the pieces, states their bounds, and says plainly which of them have been qualified on live guests and which have not.

## Three names

The naming has moved and the tree is now settled on it. `usr.sbin/bhyve/Makefile` says it in a comment: bhyve is the underlying hypervisor engine and keeps its name; the `waspnest` name belongs to the VM capability daemon. That daemon is `BSDVM` in `usr.sbin/BSDVM`, wire name `system.VM`, and "waspnest" survives only as the name of the qualification program, its test package `5BSD-waspnest-tests`, and the `docs/waspnest-*.md` status documents. There is no `BSDVM` or `waspnest` binary that runs a VM; a `bhyve` command line from FreeBSD runs unchanged.

## The engine

The kernel and userspace split is bhyve's. The `vmm(4)` subsystem executes guest vCPUs on Intel VMX/EPT or AMD SVM/NPT and owns stage-2 translation, interrupt controllers, timers and PCI passthrough; one `bhyve(8)` process per VM builds the machine model, emulates devices and enters Capsicum capability mode before the guest runs; `libvmmapi` wraps the `/dev/vmm` ioctl ABI. Three guest families are in scope: 5BSD, other BSDs (the classic bhyve guest interface is unchanged) and Linux, with Alpine as the reference image. Linux is the primary consumer of the host models whose 5BSD guest side is protocol-bounded.

5BSD added to `vmm` a kernel-owned INIT/SIPI startup transaction (`VM_STARTUP_REQUEST`, `VM_RUN_GENERATION`), snapshot sessions and envelopes (`VM_SNAPSHOT_SESSION`, `VM_RESTORE_TIME`), a dirty-page log (`VM_DIRTY_LOG_REQUEST`), CPUID and compatibility queries, MTRR modelling, and a KVM-compatible pvclock. pvclock is off unless `hw.vmm.pvclock.enabled=1` is set in loader.conf. `options BHYVE_SNAPSHOT` is in GENERIC and `MK_BHYVE_SNAPSHOT` defaults to yes on amd64.

## VirtIO: transport, rings, devices

Every device model supports the modern (non-transitional) VirtIO PCI transport as an opt-in: `transport=modern` in bhyve_config(5) selects the non-transitional device ID (0x1049 for a block device, 0x1053 for vsock, and so on); omitted, the legacy transport is used so existing guests and launch scripts keep working. `packed=true` selects packed virtqueues and is off by default on every device; it is in no default feature mask. `queues=N` (1 to 64) selects multiqueue for net, block and SCSI. Deliberate spec exclusions are fail-closed and unadvertised: platform ordering and SR-IOV are not applicable to the emulated topology, and block secure erase is unsupported because the backend cannot promise its semantics.

The device models bhyve(8) lists:

| Device | What it is | Guest side on 5BSD |
|---|---|---|
| `virtio-fs` | FUSE over VirtIO to virtiofsd(8) | virtio_fs(4), `/dev/virtiofsN`, mount_virtiofs(8), fusefs |
| `virtio-gpu` | 2D display | virtio_gpu |
| `virtio-iommu` | paravirtual IOMMU with an ACPI VIOT binding | virtio_iommu(4), protocol only, off by default |
| `virtio-mem` | memory hot-plug | virtio_mem(4), protocol only, off by default |
| `virtio-pmem` | host-backed persistent memory | virtio_pmem(4) over nvdimm(4), amd64 module only |
| `virtio-rtc` | real-time clock | virtio_rtc |
| `virtio-snd` | audio | virtio_snd(4), a pcm(4) data path |
| `virtio-balloon` | memory balloon, modern transport | virtio_balloon(4), rewritten |
| `virtio-crypto` | crypto offload | virtio_crypto |
| `virtio-vsock` | host-guest sockets | virtio_vsock, see below |
| `virtio-input` | evdev input | virtio_input |
| `i6300esb` | Intel 6300ESB two-stage PCI watchdog with `action=reset|poweroff|nmi|notify` | Linux and Windows guests bind their existing drivers |
| `pvpanic` | ACPI `QEMU0001` crash notification on port 0x505 | `sys/dev/pvpanic`, reports `PANICKED` only |

The pre-existing block, net, console, SCSI, 9P, input and RNG models remain and gained the modern transport, and the non-VirtIO models (AHCI, NVMe, xHCI, HDA, e82545, UART, TPM CRB, fwcfg, passthru) were hardened and given checkpoint support. The guest driver modules are built from `sys/modules/virtio` (`fs`, `mem`, `iommu`, `crypto`, `sound`, `rtc`, `vsock`, and `pmem` on amd64 only; `virtio_pmem` is not in `sys/conf/files`, so it is loadable only), plus `pvpanic` and `vsock`.

Four of the new guest drivers are bounded by the kernel they run in, and the manual pages say so.

**virtio_mem(4)** negotiates, plugs, unplugs and accounts blocks, but does not online plugged memory into the page allocator: the physical-segment and `vm_page` arrays are sized at boot and cannot grow. Plugging would consume host backing without giving the guest usable memory, so the driver defaults to protocol-only operation and issues no PLUG requests unless `hw.virtio_mem.allow_plug=1`.

**virtio_iommu(4)** issues ATTACH, DETACH, MAP, UNMAP and PROBE and receives faults, but does not drive `busdma(9)` translation for other devices; that needs an ACPI VIOT parser and a busdma back end that do not exist in-tree. A non-translating IOMMU isolates nothing, so the driver declines the device unless `hw.virtio_iommu.enable=1`.

**virtiofsd(8)** is deliberately read-only and non-DAX. It opens the export and its socket, enters capability mode, limits each retained descriptor to what read-only traversal needs, and answers every mutating FUSE operation with `EROFS` or `ENOSYS`. It serves bhyve over a private `SOCK_SEQPACKET` protocol, and its state transfer for checkpoints is versioned and bounded. The guest mounts by tag: `mount_virtiofs share /mnt` resolves the tag through `dev.virtio_fs.N.tag`.

**virtio_pmem(4)** maps the region through nvdimm(4) and makes stores durable with a device FLUSH; it is a module only, and there is no packed-ring lane for it.

The value of the mem and iommu drivers on 5BSD is protocol compliance and host-model validation; the useful production deliverable is the bhyve host model, which a Linux guest can consume fully.

## vsock end to end

5BSD adds a complete virtio-vsock stack. vsock(4) documents the `AF_VSOCK` domain: stream and seqpacket sockets, no datagram, addressed by (CID, port) with `VSOCK_CID_LOCAL` (1) for loopback, `VSOCK_CID_HOST` (2) for the hypervisor, guests from 3, and `VSOCK_CID_ANY` as the bind wildcard. Ports below 1024 are privileged, as on Linux, and Linux-compatible ioctls are supported. `device vsock` and `device virtio_vsock` are in GENERIC. The guest transport is `sys/dev/virtio/vsock`; the domain is `sys/kern/uipc_vsock.c`; sysctls under `kern.vsock` set `max_connections`, `max_connections_per_cid`, `buf_default`, `buf_min`, `buf_max`, `seqpacket_frag_max`, and report `guest_cid`, connection counts and packet counters. share/dtrace ships `vsock-overview`, `vsock-connections`, `vsock-perf`, `vsock-provider` and `vsock-security` scripts.

On the host, `virtio-vsock,cid=N` in bhyve takes a `backend`: `userspace` (the default) exposes the guest's ports as Unix-domain sockets in a directory given by `path`, with a `<path>/sock` control socket for host-to-guest connections; `kernel` attaches the device to the host's own `AF_VSOCK` domain so a host program dials the guest with a plain vsock socket. Checkpointing is fail-closed: a snapshot is accepted only with no live connection or buffered data. Userspace transport providers are gated by `mac_vsock_provider_check_attach` and `mac_vsock_provider_check_access`, which decide which credential may register or use a transport for a guest CID.

A sandboxed unit does not open `AF_VSOCK` itself, because a process in capability mode cannot bind or connect a global address. It asks BSDVM:

```c
unsigned cid, port;
int lfd;

if (service_vsock_listen(ctx, 0, 0, &cid, &port, &lfd) == 0)
        /* accept(2) on lfd; advertise (cid, port) to peers */
```

The `port` argument is an index into the caller's label-scoped window (`VMD_PORTS_PER_LABEL` wide), never a concrete port, so a unit can never name another unit's port; the reply returns the concrete host-local CID and port bound. `service_vsock_connect(ctx, cid, port, &fd)` dials a peer's advertised address, and `service_vsock_list()` reports the caller's own window. Each grant is derived from the unit's unforgeable channel label. BSDVM resolves only for SYSTEM-domain clients and is the one ambient-mode provider in the fleet. Its wire operations are documented in [system.VM](../providers/vm.md); [A Consumer Application](../develop/consumer-app.md) shows the pattern in a full program.

## Checkpoint, restore and migration

`bhyvectl --checkpoint=<file>` writes an atomically published manifest whose generation-matched memory, kernel and metadata files are replaced only when every reader has moved on. Migration speaks a versioned, checksummed frame protocol through handshake, topology validation, pre-copy with the dirty log, stop-copy, commit and release: on the source, `bhyve`'s `migrate fd=N [max_rounds=n] [converge_pages=n]` command; on the destination, `bhyve -R fd`. Both ends are handed an already-connected socket; a device may be migrated only if it satisfies the eligibility contract in `migration_eligibility.h`. Two caveats are in the design document and stay in this chapter: the receive listener is not authenticated, and live two-host operation is not yet qualified. Loopback and model tests pass; production use is not enabled.

## Nested VMX

Intel-only, default-off and triple-gated. The loader tunable `hw.vmm.vmx.nested=1` must be set before `vmm` loads; `x86.nested_vmx=true` must be set per VM in bhyve_config(5); and the guest must request the `VM_CAP_NESTED_VMX` capability. All three are required so that enabling qualification on one host does not change the CPU model of unrelated guests. Nested VPID is a separate gate (`hw.vmm.vmx.nested_vpid`, which itself requires `nested=1`). On AMD the capability is absent, fail-closed. All VMX semantics live in the kernel (`sys/amd64/vmm/intel/vmx_nested_*.c`) behind a frozen-vCPU handoff transaction, with VMCS shadowing, nested EPT and L2 freeze/thaw for snapshots.

## MAC hooks

The plane's control points over VM lifecycle are MAC framework hooks in `sys/security/mac/mac_framework.h`, called from `sys/dev/vmm/vmm_dev.c`: `mac_vmm_check_create`, `mac_vmm_check_destroy`, `mac_vmm_check_reinit` and `mac_vmm_check_alloc_memseg` gate who may create, destroy, reset or size a VM; `mac_vmm_check_mem_access`, `mac_vmm_check_memseg_access` and `mac_vmm_check_passthrough` gate guest-memory reads, writes and mappings and PCI passthrough. A policy module can veto any of them by credential and VM name. mac(9) has not been updated to describe them; the prototypes in `mac_policy.h` are the reference.

## Honest status

`docs/waspnest-completion-matrix.md` is the entry point for what is finished, and it distinguishes two kinds of evidence. `implemented-tested` is rootless implementation evidence from the device harness (`tests/sys/kern/vsock_device_harness`, 98 sanitizer-instrumented targets against a 242-row requirements ledger). `exercised` means a named live case passed on a real guest with the host trace proving the path ran. Enumeration and feature-bit negotiation are never activation evidence. The dated snapshot in that file reads:

| Ledger | State |
|---|---|
| VirtIO requirement rows | 239 of 242 `implemented-tested`; 3 explicit non-applicable or unsupported, unadvertised |
| VirtIO live activation, Linux guest | 33 exercised, 81 pending, 5 driver-gap |
| VirtIO live activation, 5BSD guest | 8 exercised, 82 pending, 39 driver-gap |
| Non-VirtIO devices (14 rows) | 0 live exercised; all 14 save/restore rows pending |
| Nested VMX (437 rows) | 408 `foundation-tested-experimental`, 29 `experimental-pending-live`; 0 of 12 live qualification groups passed |

So: the code is committed and model-verified nearly everywhere, and the bhyve you get is a superset of FreeBSD's that boots the same guests. What is not yet true is that the new device models, the checkpoint paths and nested VMX have been qualified on live guests across the matrix. The gaps are recorded as pending rows, not hidden. `/usr/tests/waspnest/waspnest-test status` prints the current dispositions from the installed ledgers; `list` shows the twelve release gates; `audit` self-checks without creating a VM; `run` executes the full campaign on an Intel host and applies the `release-ready` gate, which fails while any required live row is pending. Root-only gates run from the installed `/usr/tests` payload. The `nonvirtio` profile carries 58 named live and checkpoint cases for Alpine and 5BSD, including dedicated fire lanes for i6300ESB expiry and the pvpanic event. AMD SVM and ARM64 nested virtualization have no implementation and are unsupported, not pending.

## Where the rest is

The design documents are `docs/bhyve-*.md` (packed rings, virtio-fs, virtio-gpu, virtio-iommu, balloon, rtc, pvclock, migration, the virtio-state and nested architecture) and `docs/waspnest-*.md`. The test layout and how to run the device harness, the e2e Alpine and 5BSD lanes and the root-only `tests/sys/vmm` suite are in [Testing](../develop/testing.md). `contrib/lwip` was imported for a network scaffold that was later deleted, and was removed; no lwIP stack exists in the tree.
