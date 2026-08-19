# WASPNest disk-I/O qualification status

This note separates three materially different disk-I/O findings.  Passing
the ordinary VirtIO block matrix does not by itself qualify the root-only ZFS
stress case below.

## Resizing a mounted root disk — default-operation mitigation

The VirtIO block device no longer subscribes to backing-object resize events
unless its bhyve configuration explicitly includes `resize=true`.  The default
is a fixed guest-visible capacity for the complete lifetime of a device
instance.  This prevents a backing-file event from causing FreeBSD's guest
`vtblk_config_change()` path to call `disk_resize()` and churn a mounted root
partition provider during ordinary I/O.

`resize=true` remains an explicit operator opt-in for a disk whose guest
consumes capacity changes safely.  It must not be used for a mounted,
partitioned root disk without separately qualifying that guest's resize
behavior.  This deliberately retains the standard capacity-change mechanism;
it does **not** prove the UFS-root panic impossible when an operator enables
live resize.  That opt-in guest/host combination still needs a dedicated
reproduction and qualification before it can be called fixed.

Evidence:

* `virtio_block_test:resize_notifies_configuration_change` covers aligned,
  misaligned, suspended, and checkpoint-paused publication behavior.
* The block requirements ledger records resize as disabled by default.

## Short regular-file writes — fixed

The regular-file backend now handles a positive short `pwritev(2)` exactly as
the existing translated/GEOM backend handles a short `pwrite(2)`: it advances a
private iovec cursor and retries the unwritten suffix until completion.  A
zero-byte result is treated as `EIO`, preventing a non-progress loop.  The
original request iovec is not modified, preserving its completion and
cancellation lifetime.

Evidence:

* `block_if_test:file_write_retries_short_pwritev` forces repeated partial
  direct-file writes across iovec boundaries, verifies the complete byte
  pattern, and verifies that the caller-owned iovec bases and lengths were
  not changed by the private retry cursor.
* `block_if_test:file_write_zero_progress_fails` forces zero progress and
  verifies prompt `EIO` with the full residual retained.
* `block_if_test:read_write_reject_invalid_vectors` rejects malformed public
  blockif read/write requests before they are queued or can reach a backing
  object: invalid offsets, vector counts, null nonempty vectors, mismatched
  aggregate lengths, and overflowing ranges.

This is a host backend completion fix.  It must not be represented as a fix
for the ZFS livelock without the live stress result below.

## Pause-fence admission — fixed

The backend pause fence now distinguishes a guest FLUSH from the internal
write-completion durability fence used to drain a write that was admitted
before the pause.  A guest FLUSH is new frontend work and returns `EBUSY` while
the backend is paused.  The VirtIO block completion path alone uses the narrow
internal stability-flush operation, so an already accepted writethrough write
can still reach a durable completion without reopening frontend admission.

Evidence:

* `block_if_test:paused_backend_accepts_only_stability_flush` proves that a
  paused backend rejects the public guest FLUSH and write paths while accepting
  exactly the completion-side stability flush.

This closes a lifecycle-fence defect; it does not diagnose or waive the ZFS
issue below.

## ZFS sustained-write livelock — unresolved, root-only qualification

The reported issue is a ZFS-root guest that hangs during sustained writes
(`dd if=/dev/zero of=/root/stress.bin bs=1m count=1500; sync`).  The retained
debug evidence has the ZFS write issue/completion taskqueues active, the txg
sync thread waiting for ZIO completion, and guest file-vdev workers idle.  That
does not identify a completed VirtIO request-path defect, so no speculative
workaround is enabled.

Required root-only gate on a disposable ZFS-root guest image:

1. Use a uniquely named guest pool; do not import that pool on the host.
2. Provision a dump-capable guest image with a swap dump device and retained
   kernel symbols.
3. Run the sustained write plus `sync` at least three times, once with one
   VirtIO block queue and once with the intended multiqueue configuration.
4. If a run stalls, inject NMI, collect all lock chains and backtraces, force a
   dump, and save the core before terminating the VM.
5. Analyse the saved core with the exact guest `kernel.debug`, including the
   ZFS issue/completion taskqueues, txg waiter, outstanding bios, vtblk queue
   cursors, and host used-ring progress.
6. A proposed fix requires the original workload to pass repeatedly and must
   retain the normal Linux/5BSD block, reset, checkpoint, and soak gates.

### Request-lifetime trace for the next reproduction

`virtio_blk` exports metadata-only `vtblk` DTrace probes when the guest kernel
has KDTRACE support:

* `vtblk:::request-submit` — device, queue, wire request type, sector, byte
  count, and post-enqueue free descriptor count.
* `vtblk:::request-complete` — device, queue, wire request type, sector, byte
  count, and translated completion error.

Start a trace before the workload and retain its output beside the guest core.
For example, the following per-type/queue balance stays useful even when a
serial console stops responding:

```
dtrace -q -n '
vtblk:::request-submit   { @outstanding[args[1], args[2]] = sum(1); }
vtblk:::request-complete { @outstanding[args[1], args[2]] = sum(-1); }
tick-5s                  { printa("q=%d type=%d outstanding=%@d\\n", @outstanding); }
'
```

An increasing positive balance identifies a request lifetime that reached the
guest VirtIO queue but did not return.  A zero balance while ZFS is stalled
points instead at post-completion filesystem scheduling.  The probes contain
no buffer address or payload data and do not alter queue admission or
completion behavior.

Until that gate passes, status is **unresolved** rather than fixed or waived.
