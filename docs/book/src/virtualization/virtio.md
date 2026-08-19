# VirtIO Devices and Guest Drivers

WASPNest's largest single work program is VirtIO: modern (virtio 1.4) PCI
transport support, packed rings, multiqueue, a set of new host device
models, and matching 5BSD guest drivers. The host models live in
`/usr/src/usr.sbin/bhyve/pci_virtio_*.c` (16 device models, plus split-out
engine modules such as `virtio_pci_modern.c`, `virtio_packed.c`, and the
`virtio_admin*.c` administration-virtqueue family); guest drivers live
under `/usr/src/sys/dev/virtio/`.

## Device models and drivers

| Device | Host model | 5BSD guest driver | Notes |
| --- | --- | --- | --- |
| balloon | `pci_virtio_balloon.c` | `sys/dev/virtio/balloon/` | stats, deflate-on-OOM, free-page hinting/reporting, page poison options; always advertises `MUST_TELL_HOST` |
| fs | `pci_virtio_fs.c` + `virtio_fs_*.c` | `sys/dev/virtio/fs/virtio_fs.c` | modern-only, non-DAX, 1 hiprio + up to 64 request queues; external backend over authenticated `SOCK_SEQPACKET` (VFSB protocol); guest bridges to `fusefs`, mount tag in `dev.vtfs.N.tag` |
| gpu | `pci_virtio_gpu.c` + `virtio_gpu_2d_*.c` | `sys/dev/virtio/gpu/` | unaccelerated 2D, EDID only, one scanout (default 1024x768); `display=true` feeds the framebuffer console via `fbuf,source=external` |
| iommu | `pci_virtio_iommu.c` + `virtio_iommu_*.c` | `sys/dev/virtio/iommu/` | map/unmap, probe, fault queue, generated ACPI VIOT; guest default-off (`hw.virtio_iommu.enable=0`) |
| mem | `pci_virtio_mem.c` | `sys/dev/virtio/mem/` | memory hot-plug; guest protocol-only by default (`hw.virtio_mem.allow_plug=0`) |
| pmem | `pci_virtio_pmem.c` + workers | `sys/dev/virtio/pmem/` | guest maps as NVDIMM SPA/GEOM (`MODULE_DEPEND(virtio_pmem, nvdimm)`) |
| rtc | `pci_virtio_rtc.c`, `virtio_rtc_alarm.c` | `sys/dev/virtio/rtc/` | virtio 1.4 §5.23, UTC clock 0, opt-in `alarm=true`; guest sysctl `dev.vtrtc.N.alarm_time_ns` |
| sound | `pci_virtio_snd.c` + queue/async | `sys/dev/virtio/sound/` | playback + capture streams bridged to `pcm(4)` |
| vsock | `pci_virtio_vsock.c` | `sys/dev/virtio/vsock/` | see [vsock](vsock.md) |

These join the pre-existing block, net, console, SCSI, 9P, input, and RNG
models. The five guest drivers added in the 2026-08 wave (sound, fs, mem,
pmem, IOMMU) are build- and model-verified; virtio-sound, virtio-fs, and
virtio-pmem deliver real 5BSD guest capability today.

Two guest drivers are deliberately capability-bounded: virtio-mem
negotiates and plugs/unplugs but does not online plugged pages into the
page allocator, and virtio-iommu models domains and mappings but does not
yet drive `busdma(9)` translation (no ACPI VIOT parser in-tree). Both are
protocol-complete, default-off, and exist mainly to validate the host
models, whose production consumers are Linux guests.

## Packed rings

The design is `docs/bhyve-virtio-packed-ring-design.md`. On the host,
packed-ring support is implemented for every bhyve VirtIO device model,
selected per device with `packed=true`; `VIRTIO_F_RING_PACKED` is kept out
of every default capability mask until the Linux release and checkpoint
cases pass. Packed requires the modern transport (legacy PCI stays
split-only), supports queue sizes 1..32768, and uses a host-owned reorder
table with fail-closed poisoning of duplicate or out-of-window completions.

On the guest side, the packed engine lives in the shared
`sys/dev/virtio/virtqueue.c` (`VIRTQUEUE_FLAG_PACKED`) and
`virtio_ring.h`, passed through by the modern PCI and MMIO transports.
Currently the virtio-blk and virtio-sound drivers negotiate
`VIRTIO_F_RING_PACKED`.

## Multiqueue

The 5BSD virtio-blk guest driver negotiates `VIRTIO_BLK_F_MQ` and sizes its
queue count to `MIN(num_queues, mp_ncpus)` (`dev.vtblk.N.num_queues`);
virtio-scsi likewise honors the device's `num_queues`
(`dev.vtscsi.N.num_queues`); virtio-net keeps its existing multiqueue path;
virtio-fs supports up to 64 request queues end to end.

## pvclock

pvclock is a kernel feature, not a VirtIO device: `sys/amd64/vmm/io/vpvclock.c`
implements the KVM pvclock MSR interface so Linux `kvm-clock` and the 5BSD
`kvm_clock(4)` guest driver get a paravirtual clocksource. It is default-off
via the host tunable `hw.vmm.pvclock.enabled` because enabling it moves the
KVM CPUID signature to leaf 0x40000000 (guests then identify the hypervisor
as KVM), relocating bhyve's own leaves to 0x40000100. The stable-clocksource
bit is advertised only with invariant, SMP-synchronized TSC. Design:
`docs/bhyve-pvclock-design.md`; model test:
`tests/sys/vmm/vpvclock_model_test.c`.

## VirtIO 1.4 validation

`docs/bhyve-virtio-1.4-validation-review.md` is the active validation
record. Every spec requirement is a row in
`tests/sys/kern/vsock_device_harness/virtio-1.4-requirements.tsv`, mapped
to production symbols and named tests and enforced by validator scripts;
normative references (VirtIO 1.4 CS01, Intel SDM, pinned Linux and QEMU
archives) are digest-pinned in `virtio-reference-corpus.tsv`. Linux and
QEMU serve as interoperability oracles, never as normative sources. Review
proceeds in nine passes (normative tracing, lifecycle/reset, boundary
validation, feature interop, soak, observability, independent re-reviews,
implementation-defined-interface inventory), each requiring a test that
fails without the corresponding change. Recorded evidence includes
ASan/UBSan and TSan harness runs with zero failures, a 4096-cycle queue
reset soak, and live Alpine Linux runs negotiating `NOTIFICATION_DATA` and
`RING_RESET` on the modern transport.

Deliberate exclusions are fail-closed and unadvertised:
`VIRTIO_F_ACCESS_PLATFORM` outside the virtio-iommu path, admin
virtqueue/SR-IOV grouping as a production feature, device suspend, and
block secure erase.

## Status

Per `docs/waspnest-completion-matrix.md` (2026-08-13 snapshot): 237 of 240
VirtIO requirement rows are `implemented-tested`, but live-guest activation
is the open front — of 130 activation rows, 33 are exercised on Linux and 8
on 5BSD. The new device models and guest drivers are model-verified, not
yet live-qualified; packed rings remain a qualification option rather than
a default.
