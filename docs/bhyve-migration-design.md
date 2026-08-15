# bhyve live-migration control plane and cutover design

Status: control plane, session protocol, multi-frame chunking, snapshot-reuse
device-state bridge, `bhyve -R` destination listener, and highmem/MMIO-hole
handling implemented and loopback- and model-proven; live two-host operation
is NOT yet qualified.  Every claim below is rootless/model/build evidence
only.  The residual live-only work is enumerated in the final section and in
`docs/waspnest-remaining-work-handoff.md` §7.4.

Reference comparison: QEMU VMState/migration is the device-side behavioral
comparison; KVM's versioned state APIs are the CPU-state comparison.  Neither
defines this wire protocol.  No GPL code is copied or mechanically translated.

Primary sources:

- `usr.sbin/bhyve/migration_session.h` / `migration_session.c` — wire codec,
  negotiation/validation, and the source/destination session state machines;
- `usr.sbin/bhyve/migration_precopy.*`, `migration_dirty.*`,
  `migration_eligibility.h` — dirty logging and pre-copy generation
  composition;
- `usr.sbin/bhyve/snapshot.*`, `checkpoint_manifest.*` — the device
  serialization path reused for the DEV_STATE phase; and
- `usr.sbin/bhyve/bhyverun.c` — the `-R` (migrate-receive) bring-up.

## 1. Design goals

1. **One-copy invariant.**  The guest is never live on two hosts at once.  The
   source becomes defunct only after RELEASE; the destination resumes only
   after RELEASE.  A failure at any point before the acknowledged commit leaves
   the source runnable and publishes nothing on the destination.
2. **Portable, fixed-width wire.**  No host pointer, descriptor, `size_t`,
   lock, or native structure appears on the wire; every message is a
   fixed-width little-endian record with an explicit length and CRC.  CPU state
   is treated as non-portable and is match-gated, not converted.
3. **Fail-closed validation before quiesce.**  Identity, topology, per-device
   external-state contracts, and destination resources are validated while the
   source is still running.  The source quiesces only once the destination has
   accepted the machine.
4. **Testable without privilege.**  The codec and both state machines run
   in-process over a `socketpair` or an injected transport with no network, no
   root, and no running VM.  The transport is an injectable vtable
   (`struct migration_transport`); a thin file-descriptor adapter is the only
   piece that touches sockets.

## 2. Session protocol

The protocol is versioned (`MIGRATION_PROTO_MAGIC` = `"MIG1"`, version 1) and
message-framed.  Every frame is a 24-byte header
(`struct migration_frame_header`: magic, version, type, flags, seq, length,
payload CRC-32) followed by a typed payload.  The message types
(`enum migration_msg_type`) drive both state machines:

| Phase | Messages | Purpose |
| --- | --- | --- |
| HANDSHAKE | `HELLO` -> `CAPS_ACCEPT` / `CAPS_REJECT` | Exchange identity + capabilities; negotiate version with an explicit downgrade window. |
| VALIDATE | `TOPOLOGY` -> `TOPO_ACCEPT` / `TOPO_REJECT` | Exchange memory geometry, CPU topology, and the per-device manifest; destination validates before the source quiesces. |
| PRECOPY | `MEM_GEN` -> `MEM_ACK` (iterated) | Stream iterative dirty-memory generations until convergence or the round limit. |
| STOPCOPY | `MEM_GEN` (final), then `DEV_STATE`, then `FINAL` | Event-fenced final memory generation plus the device/CPU/kernel blob. |
| COMMIT | `COMMIT` | Destination atomically publishes all staged state (still not running). |
| RELEASE | `RELEASE` | Source acknowledges defunct; destination resumes the guest. |
| Abort | `ABORT` (+ structured `migration_reason`) | Any-time fail-closed teardown; source rolls back. |

`HELLO` (`struct migration_hello`) carries the version window, role
(`SOURCE`/`DEST`), `arch_id`, `page_size`, CPU family/model/stepping, a
`cpu_feature_hash`, the interrupt-controller identity, a machine ABI string,
and `capability_flags` (`PRECOPY`, `DEVICE_DIRTY`).  `migration_hello_validate()`
treats CPU state as non-portable: family, model, and feature hash must match
exactly, and page size, arch, interrupt controller, and machine ABI are all
match-gated with a structured `migration_reason` on mismatch.

`TOPOLOGY` (`struct migration_topology`) carries `mem_size`, `lowmem`,
`highmem`, CPU count/socket/core/thread geometry, and up to
`MIGRATION_MAX_DEVICES` device records.  Each `struct migration_device_record`
carries the device name, its `migration_flags`, a compatibility schema id, a
compat CRC, and a BAR hash.

## 3. Per-device external-state contract

The topology device-record `migration_flags` mirror the `PCI_MIGRATION_F_*`
bits in `pci_emul.h`; the pure codec core has no PCI dependency and the
production adapter static-asserts the two definitions stay identical.  A device
is eligible (`migration_device_flags_eligible()`) only if it advertises exactly
one compatibility policy, exactly one DMA policy, exactly one quiesce policy,
the mandatory portable-state-codec bit, and no unknown bits:

- compat: `STATE_CODEC` (mandatory) plus one of `COMPAT_FIXED` /
  `COMPAT_CALLBACK`;
- DMA: `DMA_NONE` or `DMA_TRACKED`; and
- quiesce: `QUIESCE_NONE` or `QUIESCE_CALLBACK`.

This is the wire-level enforcement of `pe_migration_flags`: a device whose
advertised flags do not encode a real external-state contract is refused before
the source quiesces, rather than silently migrated with lost state.
`migration_topology_validate()` additionally requires the destination to match
memory geometry and CPU topology and to confirm every source device is present
and eligible locally (via a caller-supplied match callback).

## 4. Multi-frame chunking

A logical message whose serialized form exceeds one frame
(`MIGRATION_MAX_PAYLOAD` = 16 MiB) is split into ordered chunks.  Each chunk
frame carries `MIGRATION_FFLAG_CHUNK` and a fixed-width
`struct migration_chunk` sub-header (`total_length`, `offset`, `chunk_length`,
`final`) placed immediately after any fixed message header — the memory-
generation header for `MEM_GEN`, nothing for `DEV_STATE`.  A message that fits
in one frame is sent with `flags == 0` and no sub-header, byte-identical to the
unchunked format, so single-frame and multi-frame producers share one decoder.

`migration_chunk_validate()` checks each chunk against the destination's
running reassembly cursor **before** any byte is copied: it requires strictly
contiguous, in-order offsets and rejects gaps, duplicates, oversize chunks, and
an inconsistent latched total.  `total_length == 0` signals an a-priori-unknown
streamed length (memory generations) terminated by `final`; the device/CPU blob
is bounded by `MIGRATION_MAX_DEV_STATE` (512 MiB) and rejected before any
allocation if a peer advertises more.

## 5. Pre-copy, convergence, and the event-fenced cutover

The source ops (`struct migration_source_ops`) back the state machine with the
real pre-copy and snapshot machinery:

- `so_precopy_enable` / `so_precopy_disable` start and retire dirty logging;
- `so_precopy_round` serializes a whole number of page records into the
  caller's buffer and reports `*converged`, `*dirty_pages` for this chunk, and
  `*more` (further page records in the current generation did not fit).  The
  session frames the chunk and, while `*more`, continues the same generation
  from where it left off — this is how one memory generation spans many frames;
- `so_quiesce` is the event fence that pauses every vCPU, device, backend, and
  timer; `so_resume` is its rollback inverse and must leave the source
  runnable; and
- `so_dev_state` serializes the device/backend/CPU/kernel blob at cutover.

Convergence is governed by `struct migration_session_config`: `max_rounds`, a
`converge_pages` dirty-page ceiling that declares cutover, an
`abort_if_unconverged` policy (fail with the source runnable rather than force a
cutover after `max_rounds`), an operator `cancel` flag, and an optional
`progress` sink (`struct migration_stat`: phase, round, bytes, last dirty page
count, converged).

When the dirty set falls under the ceiling (or the round limit forces a
decision), the source performs the event-fenced stop-and-copy: a final
`MEM_GEN`, the chunked `DEV_STATE` blob, then `FINAL`.

### 5.1 Balloon free-page-hint optimization (retain-until-finish)

If the guest has negotiated `VIRTIO_BALLOON_F_FREE_PAGE_HINT`, the source runs
one free-page-hint round before the initial memory walk
(`prod_collect_free_pages()` in `migration_session.c` ->
`virtio_balloon_migration_start()`): the host bumps the balloon free-page-hint
command id, the guest reports its currently-free pages, and those pages are
recorded in a `migration_precopy_free_set` so the initial generation can skip
copying them.  The set is honored **only for the initial copy**
(`migration_precopy_free_set_skip()` returns false for every later generation),
so any page written after being reported free is re-copied by ordinary dirty
tracking; the optimization is layered on dirty logging and is never a
correctness precondition.  A missing balloon, a declined feature, a timeout, or
any failure leaves the set invalid and the initial walk copies every page.

The safety invariant is **retain-until-finish**: the round is deliberately left
OPEN across the initial dirty snapshot.  The balloon device holds the guest's
STOP command descriptor uncompleted (`vbsc_migration_stop_held` in
`pci_virtio_balloon.c`) — because the guest driver returns its reported-free
pages to its allocator as soon as that descriptor completes — and
`prod_end_free_round()` calls `virtio_balloon_migration_finish()` to release the
guest only after the initial snapshot has been taken.  This closes the window in
which the guest could silently reallocate and write a just-reported-free page
between the report and the snapshot's dirty-bit clear; any post-`DONE` write is
then caught by dirty tracking.

Note this is now a second in-operation consumer of the balloon free-page-hint
command id; historically only snapshot-restore bumped it.

## 6. Snapshot-reuse `dev_state` bridge

The DEV_STATE phase does not invent a second device-serialization format.  On
the source, `so_dev_state` reuses the existing checkpoint device snapshot codecs
to produce the device/backend/CPU/vCPU/kernel blob; the session chunks and
frames it.  On the destination, `do_stage_dev` reassembles the chunked blob and,
at COMMIT, replays it through the **existing restore steps** — the same code
path `--restore` uses.  This keeps one serialization contract for both
checkpoint and migration and means each device's `pe_snapshot` /
`pe_snapshot_validate` work is shared, not duplicated.

## 7. Destination listener (`bhyve -R`)

The destination is brought up exactly like `--restore`: `bhyverun.c` treats
`-R` (migrate-receive, config `migrate.receive_fd`) as mutually exclusive with
`-r` (restore), creates a fresh VM, and holds the restore startup fence with
every vCPU idle.  `migration_prod_dest_serve(ctx, fd, cfg, result)` then runs a
complete destination session over the already-connected stream descriptor:

- `MEM_GEN` chunks are staged directly into guest RAM (`do_stage_mem`);
- `DEV_STATE` chunks are reassembled but **not** published (`do_stage_dev`);
- `COMMIT` atomically publishes every CPU/device/backend/interrupt/timer state
  through the restore steps, still without running the guest (`do_commit`); and
- the guest is resumed only after `RELEASE` (`do_resume`).

On any non-zero return, all staged state is discarded (`do_discard`) and nothing
is published — the destination never becomes a second live copy.

## 8. Highmem and the MMIO hole

Memory generations describe guest-physical ranges by `gpa`/`length`, and the
topology carries `lowmem` and `highmem` separately, so the pre-copy and staging
paths cover the high-memory segment above the 32-bit MMIO hole as first-class
guest RAM rather than assuming a single contiguous low segment.  The MMIO hole
itself is not RAM and is not streamed; device state that lives there is carried
in the DEV_STATE blob via the device snapshot codecs.

## 9. The one-copy invariant, precisely

The invariant is enforced by the ordering of the terminal messages and the
source/destination ops, not by timing:

- **Source-defunct-only-after-RELEASE.**  `so_defunct` (permanently stop the
  source) is called only after the source has sent `RELEASE`, which itself is
  sent only after the destination `COMMIT` has been acknowledged.  Any failure
  before that acknowledgement drives `so_resume` and returns
  `source_runnable == true`.
- **Dest-resume-only-after-RELEASE.**  `do_resume` runs the guest only after the
  destination receives `RELEASE`.  `do_commit` publishes state but does not run
  the guest; a failure between COMMIT and RELEASE still discards rather than
  resumes.

`migration_source_run()` returns 0 only when the migration committed (source
defunct, destination running); `migration_dest_run()` /
`migration_prod_dest_serve()` return 0 only when the destination committed and
resumed.

## 10. Live-only residuals (not yet qualified)

The following require a real two-host run and are the reason nothing here is
`exercised`:

1. **Listener authentication.**  The `-R` destination endpoint currently trusts
   an already-connected descriptor; a versioned authentication handshake on the
   listener is still required before exposure.
2. **Per-device compatibility identity across hosts.**  `name`,
   `migration_flags`, `compat_schema`, and the BAR-layout hash (`bar_hash`,
   computed host-independently from each BAR's type and size) are now populated
   by the source and enforced fail-closed in `migration_topology_validate()`
   before the source quiesces; a mismatch is refused with
   `MIGRATION_REASON_DEVICE`.  The remaining gap is `compat_crc32`: the field is
   carried and compared but still filled as 0 by the source pending the
   per-device compat-envelope capture in the device-state codec, so it does not
   yet distinguish device configurations.  End-to-end enforcement across two
   independently built hosts must still be qualified live.
3. **Kernel dirty-log confirmation.**  Iterative dirty logging is
   loopback-proven through the model ops; confirmation against the kernel
   dirty-log under a real two-host workload is pending.
4. **Cross-version fixtures and downgrade/rejection policy.**  The negotiation
   window exists; cross-version fixtures and a downgrade policy must be run.
5. **Eligible-device expansion.**  `pe_migration_flags` should grow to each
   additional device only when its external-state contract is real and tested.

Until those pass, describe live migration as an implemented, loopback-proven
control plane and cutover — not as a qualified migration product.
