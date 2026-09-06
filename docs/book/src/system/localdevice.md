# localdevice: the device-node broker

`localdevice` exposes `system.Device` and hands a capability-mode component a
rights-limited descriptor for a single `/dev` node, so a component can talk to a
device without holding the authority to open device nodes for itself. It sits
one layer below [`system.Filesystem`](../storage/trustedzfs.md): where the
filesystem broker (`tzfsd`) brokers persistent storage — datasets and files —
`localdevice` brokers the raw device nodes of the driver model. Only the
`system` domain may resolve it.

## Born in capability mode

`localdevice` never names a global path. `serviced` delivers `/dev` as an
inherited directory descriptor — the manifest declares `directories = ["/dev"]`
— and the provider opens every requested leaf beneath it with `openat(2)`. It
enters capability mode before serving any client and forks a `pdfork(2)`'d
worker per connection; because the `/dev` descriptor is already open, a worker
needs no privileges and no further fork, IPC, socket, or exec authority, so it
is confined to reading its channel and calling `openat(2)` under the retained
directory descriptor.

## The open path

A client sends an `OPEN` naming one `/dev` leaf and a wanted-rights mask
(`READ`, `WRITE`, `IOCTL`, `MMAP`, `SEEK`, `EVENT`). The broker:

1. **validates the name** — it must be a single leaf component: empty names,
   names containing `/`, names beginning with `.`, and `..` are all rejected,
   so a request can never escape `/dev` or name a nested path.
2. **checks policy** — a default-deny per-label table (see below) yields the
   maximum rights this `(label, device)` pair may hold. No matching entry
   means `EACCES`.
3. **narrows rights** — the delivered descriptor is capped with
   `cap_rights_limit(2)` to the *intersection* of the wanted mask and the
   policy maximum (always including `CAP_FSTAT`); an `IOCTL` grant is further
   restricted to a per-device `cap_ioctls_limit(2)` command whitelist when
   policy carries one. Open flags are derived from the granted read/write
   rights, defaulting to the least-authority `O_RDONLY` for a control- or
   event-only descriptor.
4. **hardens for delivery** — the descriptor is transfer-confined so it may
   cross to the client exactly once (this reply) and no further, and cannot be
   re-delivered onward (see [Capability
   Transfer](../security/mac-capability.md)).

The reply carries the granted-rights mask alongside the single delivered
descriptor.

## Policy

Access is **default-deny**: the compiled-in policy grants nothing. An optional
`device.conf` in the unit's `Config/` directory grants, per client label, one
`/dev` leaf a set of rights and an optional ioctl whitelist. A request whose
`(label, device)` pair matches no entry is refused; a malformed configuration
leaves default-deny standing rather than widening access.

Reference: `localdevice(8)`, `libdevicecmp(3)`.
