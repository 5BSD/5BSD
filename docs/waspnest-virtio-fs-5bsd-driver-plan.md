# 5BSD VirtIO-fs guest-driver integration boundary

Date: 2026-08-10

## Current source inventory

The source tree has all of the following, but they are deliberately separate:

| Component | Current location | Role |
| --- | --- | --- |
| VirtIO-fs device ID | `sys/dev/virtio/virtio_ids.h` | Defines `VIRTIO_ID_FS` (26), but has no matching child driver. |
| Existing VirtIO filesystem transport | `sys/dev/virtio/p9fs/virtio_p9fs.c` | Transports the 9P protocol for device 9; it is not a FUSE transport. |
| FUSE kernel session | `sys/fs/fuse/` | Owns FUSE tickets, request/answer queues, wakeups, cancellation state, and VFS integration. |
| Host VirtIO-fs model | `usr.sbin/bhyve/pci_virtio_fs.c` and `virtio_fs_*.c` | Provides the host side of device 26 and its external backend contract. |

Consequently, a successful 9P mount does not establish any VirtIO-fs guest
coverage.  The existing 9P driver must not be repurposed: it has different
wire framing, one request queue, no VirtIO-fs high-priority queue semantics,
and a different cancellation/lifetime contract.

## Required first implementation slice

Introduce a new `sys/dev/virtio/fs/` transport module, initially without DAX.
It should bind exactly `VIRTIO_ID_FS` and present a narrow in-kernel transport
interface to the FUSE session layer.  The first slice is complete only when it
provides all of these operations:

1. Read and validate the mount tag configuration, including its bounded
   length and zero-padding rules.
2. Allocate one high-priority queue and the negotiated number of request
   queues.  Request queue zero is not a substitute for the high-priority
   queue.
3. Negotiate only features implemented by both the device and guest driver.
   Do not advertise DAX, notification extensions, packed rings, queue reset,
   or device suspend merely because the common transport supports them.
4. Convert a FUSE ticket into an input/output descriptor chain without copying
   unbounded user-controlled lengths, retain the ticket until the device has
   returned the chain, and return the exact FUSE reply bytes to the ticket
   owner.
5. Map the FUSE INTERRUPT operation and device reset/detach to one ownership
   rule: all posted ticket storage is either completed with a defined error or
   drained before the FUSE layer may release it.
6. Tear down interrupts, task queues, virtqueues, and posted requests before
   destroying session locks or dropping FUSE tickets.

The FUSE layer currently has a userspace daemon-facing character-device
contract.  The transport must use an explicit internal adapter rather than
forge a userspace `struct uio`, a cdev-private session, or a daemon credential.
That adapter owns the queue transition between FUSE's message and answer
lists, preserves ticket unique IDs, and exposes a terminal transport failure
as the existing FUSE session error path.

## Explicit non-goals for the first slice

- DAX or any shared-memory mapping;
- cached host file handles across a reset or restore;
- transparent reconnect after an external backend identity change;
- packed rings, queue reset, or device suspend before each is independently
  enabled and tested by the guest driver;
- translating VirtIO-fs requests through the 9P client;
- claiming 5BSD live qualification based on a Linux-only mount.

## Required tests before enabling a feature

### Rootless kernel tests

- mount-tag valid, zero-length, overlong, and nonzero-padding cases;
- FUSE INIT request/reply round trip and protocol endian fixtures independent
  of the driver structures;
- every descriptor direction and segmented reply boundary;
- request queue selection, queue exhaustion, and high-priority request
  delivery;
- reset, detach, FUSE interrupt, timeout, and stale completion races;
- no ticket, DMA mapping, task, or interrupt callback after terminal drain;
- feature negotiation dependencies and unadvertised-feature rejection.

### Live guest tests

Linux remains the first activation guest.  A 5BSD result is valid only after
the new guest driver is loaded and reports the negotiated feature in the
guest, not merely after PCI attachment.  For each enabled feature, exercise
mount, create/read/write/rename/unlink, concurrent request queues, reset and
rebind, backend loss, and repeated checkpoint restore.  Packed rings,
selective queue reset, and suspend each require their own Linux and 5BSD
activation rows; ordinary split-ring mounting is not evidence for them.

## Save-state policy

The transport's portable state contains only configuration, negotiated
features, queue state, and a backend identity contract.  It never serializes
kernel pointers, `struct fuse_ticket`, credentials, file descriptors, or a
live daemon/host handle.  Checkpoint must first close request admission and
drain or fail every ticket.  Restore validates destination configuration and
backend identity before reopening admission.  Any unsupported active-ticket
state fails restore atomically rather than replaying a request whose FUSE
operation may have already reached the host filesystem.

## Completion decision

Until this driver and its live activation gates exist, device 26 is correctly
classified as **Linux-only for guest qualification**.  It is neither a test
skip nor a cross-guest completion claim.
