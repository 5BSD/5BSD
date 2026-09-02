# vsock

5BSD adds a complete virtio-vsock stack: an `AF_VSOCK` socket family in the
kernel, a virtio_vsock guest driver (see `vsock(4)`), and a bhyve/WASPNest host device
model with two host-side backends. vsock gives host and guest processes a
socket channel addressed by context ID (CID) and port, with no network
configuration inside the guest.

## Guest side: AF_VSOCK and virtio_vsock

The socket layer lives in `/usr/src/sys/kern/uipc_vsock.c` with
`AF_VSOCK` (46) defined in `sys/sys/socket.h` and addressing structures in
`sys/sys/vsock.h` (`struct sockaddr_vm`, well-known CIDs 0/1/2/`VSOCK_CID_ANY`,
Linux-compatible `VMADDR_*` aliases, `SO_VM_SOCKETS_*` socket options).
`SOCK_STREAM` and `SOCK_SEQPACKET` are supported; other types return
`EPROTOTYPE`. There is no datagram support. The family is documented in
`vsock(4)`.

Two kernel modules provide the transports:

- `virtio_vsock.ko` (`sys/dev/virtio/vsock/virtio_vsock.c`) — the guest
  driver, negotiating `VIRTIO_VSOCK_F_STREAM`, `F_SEQPACKET`, and
  `F_NO_IMPLIED_STREAM`, with credit-based flow control.
- `vsock.ko` (`sys/kern/uipc_vsock.c` plus `uipc_vsock_user.c`) — the socket
  domain and a `/dev/vsock` userspace transport provider used on the host
  side by bhyve's kernel backend.

## Host device model

The device model is `usr.sbin/bhyve/pci_virtio_vsock.c` (device name
`virtio-vsock`, documented in `bhyve(8)`). It implements the three virtio
1.4 vsock virtqueues (RX/TX/event), stream and seqpacket semantics, both the
legacy (0x1013) and modern (0x1053) PCI transports, and optional packed
rings. Configuration options:

```
-s <slot>,virtio-vsock,cid=<n>[,backend=userspace|kernel][,path=<dir>]
                       [,transport=legacy|modern][,packed=true]
```

- `cid` — required guest CID, >= 3.
- `backend=userspace` (default) — host endpoints are Unix domain sockets in
  `path`. Guest-to-host connections reach a socket named for the destination
  port inside that directory; host-to-guest connections go through a
  `<path>/sock` control socket with a small binary handshake. The relay
  socket type mirrors the vsock type (`SOCK_STREAM`/`SOCK_SEQPACKET`, with
  `MSG_EOR` record boundaries).
- `backend=kernel` — bhyve opens `/dev/vsock` and attaches the VM to the
  host's own `AF_VSOCK` domain, so host applications use plain
  `socket(AF_VSOCK, ...)` with CID 2 for the host and the guest's CID for
  the peer. Multiple concurrent guests are supported; a duplicate CID fails
  with `EADDRINUSE`.

On the host, a 5BSD component does not open `AF_VSOCK` directly. Host-side
vsock is brokered by `vmd` (`system.VM`): a unit asks for a listener by name
with `service_vsock_listen(3)`, and `vmd` grants a port window scoped to the
unit's unforgeable channel label. This keeps host vsock endpoints under the same
capability discipline as the rest of the plane, above the bhyve device model
described here.

A `vsock` DTrace USDT provider (`usr.sbin/bhyve/vsock_provider.d`) exposes
connection, credit, and overflow probes, mirroring the kernel SDT provider.
Checkpointing is fail-closed: a snapshot is accepted only with no live
connection or buffered data (the kernel backend uses freeze/thaw ioctls;
the userspace backend refuses while relay descriptors exist).

## Device harness

`tests/sys/kern/vsock_device_harness/` compiles the real
`pci_virtio_vsock.c` into an ATF binary (105 test cases) against mocked
bhyve interfaces, so the full device model runs rootless with no VM. It
covers malformed and spoofed TX headers, credit and flow-control stalls,
seqpacket reassembly and budget limits, the userspace control-socket
protocol, the kernel backend including freeze/thaw, virtio 1.4 wire layout,
and snapshot atomicity. `run.sh` additionally rebuilds the suite under
ASan/UBSan across multiple compile lanes and runs the ledger validators
first.

This directory is also the ledger home for the whole WASPNest VirtIO effort:
`virtio-1.4-requirements.tsv` (about 240 rows mapping virtio 1.4 spec
requirements to source symbols and named tests),
`virtio-feature-activation.tsv`, and `virtio-nonstandard-interfaces.tsv`.

## End-to-end tests

`tests/sys/kern/vsock_e2e/` runs real guests against the device:

```sh
# Disposable Alpine Linux guest (stock upstream virtio_vsock driver)
tests/sys/kern/vsock_e2e/run-alpine-auto.sh

# 5BSD guest image, run twice: transport=modern, then legacy
IMAGE=... FIVEBSD_IMAGE_SHA256=... FIVEBSD_BUILD_ID=... \
    tests/sys/kern/vsock_e2e/run-5bsd-auto.sh
```

The manual `run.sh` driver exercises echo, bulk, credit churn, dead-peer,
concurrency, EOF, mid-send kill, and seqpacket record cases in both
directions. `virtio-lab.lua` (a flua orchestrator reading
`virtio-lab.yaml`) schedules the declarative case matrix — userspace and
kernel backends, legacy/modern/packed transports, multi-guest kernel
backend, active-checkpoint rejection policy, and soak profiles — and each
guest run emits `VIRTIO_ACTIVATION_ASSERTION` anchors that feed the
activation ledger. Rootless guest-RX coverage lives in
`tests/sys/kern/vsock_rx_harness/`.

## Status

The device model, both backends, the guest driver, and the socket family
are implemented and heavily tested, including live Alpine and 5BSD guest
runs; vsock is among the most complete WASPNest devices. Remaining
activation rows (packed-ring and checkpoint lanes on some guests) are
tracked in `virtio-feature-activation.tsv` per the completion matrix.
