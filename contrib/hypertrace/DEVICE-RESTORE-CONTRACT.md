# VirtIO DTrace restore contract

The device snapshot callback still returns `EOPNOTSUPP` for both save and
restore. The file-restore coordinator contains a staged-queue publication
path after daemon CLAIM and receipt binding, but its earlier preflight gate
keeps that path unreachable for HyperTrace images. The gate must stay closed
until the following ownership transitions are implemented and tested together.

1. **Source cut.** Pause the reader and communicator under the common VirtIO
   checkpoint gate. Serialize the queued controls, partial guest-to-host ELF,
   ready flags, and source VMID/epoch. Replayability now requires the guest's
   negotiated feature set to include every restore and receipt-query feature.
   The source daemon must durably bind the
   checkpoint ticket to the exact image digest before a source stop can be
   reported successful. If publication precedes an uncertain daemon COMMIT,
   retain the previous generation's member files for manual recovery; its
   manifest is no longer the visible one.
2. **Destination preflight.** Before guest-memory or device mutation, verify
   the image, source ticket and digest, destination VM attestation, required
   guest features, and the complete private queue. Reserve the ticket. Keep
   every vCPU under the restore startup fence.
3. **Receipt reconciliation.** A saved ELF control represents a delivery that
   the source host accepted, not proof that the guest installed it. Query each
   exact delivery ID, program ID, source ID, and ticket through the attested
   daemon; reject missing, revoked, or mismatched records. Bind eligible
   retained deliveries to the destination durably before allowing replay.
   Likewise reconcile pending KILL and host-receipt controls with exact
   source journal records. Handle partial ELF bytes without generating a
   second acceptance or losing an already acknowledged delivery.

   A queued `KILL` is valid against either a pending or applied durable source
   record; it has not yet proved guest application. A queued
   `HOST_KILL_APPLIED` receipt requires the applied marker. Both require the
   exact PID and source ID, and neither authorizes guest execution before
   destination KILL binding and replay. The guest KILL journal rekey clears
   applied markers on both source and destination identity records, including
   destination-only records left by an interrupted retry, before moving any
   source record. The restored guest must prove application again.

   A read-only private-image query helper now stages the serialized controls
   and checks the exact source ELF delivery, guest-ELF host receipt, and
   applied KILL records through the reserved ticket. It queries one ELF
   fragment run once and compares the SHA-256 of its saved bytes with the
   daemon's durable payload digest. A saved suffix missing earlier fragments
   cannot be authenticated and remains unsupported. It rejects missing,
   revoked, mismatched, or non-durable results. A queued `HOST_ELF` now
   carries the SHA-256 of its accepted bare ELF. Before queuing that receipt,
   bhyve queries the exact durable host acceptance record and checks its
   phase, revocation, and digest. The guest compares the digest with its
   in-flight upload, and restore compares it with the
   separate durable host ingress journal (scope 3), including source KILLs
   held in the outbound journal. This requires the
   `VTDTR_WIRE_F_HOST_ELF_DIGEST_V1` feature and private-image version 2.
   The receipt is never treated as a
   host-to-guest delivery (scope 0). It returns
   `EOPNOTSUPP` for control classes without an exact lookup, including
   install, exit and status replies, and for a partial guest-to-host ELF that
   has no durable acceptance receipt yet. During file restore, the
   coordinator captures the exact private-image span while validating the
   complete PCI/VirtIO record, reserves the handoff ticket, and runs this
   read-only query before opening a kernel restore session or changing guest
   memory. It then deliberately returns `EOPNOTSUPP` and requests ticket
   cancellation (logging any uncertain cancellation):
   the query does not bind a delivery or publish a queue. Direct device
   preflight retains its `EOPNOTSUPP` gate. Before the query or a mutating
   bind, the same private-image path now builds and discards a candidate
   destination queue. It prepends `NODE_REKEY`, places source KILLs ahead of
   ELF replay, rewrites only controls with exact receipt rules, and omits
   source `HOST_KILL_APPLIED` ACKs and saved READY/EOF markers. Allocation or
   translation failure leaves no published queue. This is a publication
   preflight, not a queue commit or guest-applied barrier. The guest driver
   now suppresses ordinary READY and queued TX while rekey is pending;
   an authenticated commit exchange must release that hold after the journals
   are durable.

   The host communicator normally drains more than one control per batch.
   It now stops after `NODE_REKEY`, retains later KILL/ELF controls, ignores
   ordinary guest READY while pending, rejects other ordinary guest-to-host
   controls, and refuses to checkpoint the barrier.
   The guest driver rejects a premature inbound control while pending.
   The host may not treat the guest driver's automatic READY as a journal
   commit acknowledgement. A complete exchange must: (a) stop the host
   batch immediately after `NODE_REKEY` and retain every later control;
   (b) prevent the guest driver from advertising ordinary READY while its
   exact old/new identity is pending; (c) let the guest daemon reconcile and
   durably rekey both journal directories, then call the exclusive
   `DTT_COMMIT_VM_REKEY` ioctl; (d) have that successful ioctl emit a distinct
   old/new-identity commit control to the host; and (e) have the host verify
   the exact transition before releasing the queued controls. A reset,
   shutdown, timeout, malformed commit, or failed journal write must leave
   those controls undelivered. Guest daemon startup now reconciles both
   journals against host receipts before the commit ioctl, and the host
   validates the exact commit control. This remains native-tested code behind
   the restore gate, not a qualified live handoff.

   Compatibility and liveness are part of the exchange. Both endpoints must
   negotiate a new commit-ACK feature before a restore queue can contain
   `NODE_REKEY`; an older peer must reject the restore before VM state changes.
   Staged queue publication now checks the complete negotiated restore
   feature set, including receipt queries, while the device is still paused.
   Restore preflight checks the authenticated source VirtIO compatibility
   image for the same negotiated feature set before memory mutation; generic
   compatibility also rejects features the destination does not offer.
   The guest driver must send the commit control directly through its TX ring,
   since ordinary TX waits for host READY, and must keep its pending identity
   if the ring has no descriptor or allocation fails. It must suppress its
   automatic READY and identity-bearing queued TX controls while pending.
   Bhyve must validate the commit control against the exact transition it
   sent, not just the destination VMID, and only then resume its control
   queue. A bounded timeout must fail the restore and quarantine the stopped
   destination; neither a guest reset nor a late ordinary READY may clear the
   wait. An ioctl reply lost after successful enqueue needs an idempotent
   recovery rule so daemon restart cannot produce a second transition or
   mistake an unsent acknowledgement for a committed host session. Qualify
   normal, missing, duplicate, stale and malformed ACKs, full TX rings,
   daemon crashes and timeouts under a live host/guest run before enabling the
   save/restore path.

   A separate private-image bind helper repeats the full read-only check,
   then durably binds each exact queued host-to-guest ELF delivery through the
   daemon's idempotent handoff API. An already accepted guest-to-host
   `HOST_ELF` receipt is queried again but has no outbound delivery to bind.
   It is intended for the
   `MUTATING` ticket phase; a timeout after one bind can be retried with the
   same ticket. The restore coordinator calls it after CLAIM, but the earlier
   `EOPNOTSUPP` gate makes that call unreachable. Queue publication is a
   separate later step.
4. **Identity and guest journal.** The host must prepend one `NODE_REKEY`
   control for the exact old and new VMID/epoch, then rewrite or replace saved
   controls only after their daemon records are bound. The guest driver already
   changes its node identity on `NODE_REKEY` and now queues a mandatory
   `DTT_VM_REKEY` notice at the front of its read queue. Guest `dtraced`
   stops on that notice, and startup
   refuses journals whose VMID/epoch differ from the driver's current
   identity. The identity ioctl retains the old VMID/epoch and a pending
   flag, and a second rekey is refused until a guest journal commit can
   clear that state. This is a fail-closed guard, not journal migration: durable
   inbound KILL and outbound delivery records still need an idempotent rekey
   transaction. A low-level guest KILL journal operation now renames source
   records to destination records durably and idempotently, clears old applied
   markers, and rejects foreign identities. It is deliberately not called
   until the host handoff and delivery receipts are reconciled. An exact-record
   guest delivery rewrite primitive also exists for already-bound inbound and
   HTD4 outbound journals. Older outbound journals lack a payload digest and
   are rejected. The primitive verifies the complete source image, writes the new
   VM identity with a new checksum through a durable same-directory rename,
   and tolerates interrupted retries. Before rewriting a delivery or moving
   guest KILLs, the journal publishes an exact old-to-new identity marker.
   Guest delivery and KILL writers consult it under the same cross-process
   lock and reject stale old-identity mutations even after the rewrite lock
   is released. The `fence_guest_rekey_pair()` preflight locks both guest
   journals in a stable cross-process order, validates their records and any
   existing markers, then publishes the inbound and outbound markers even
   when the directories have no records to rewrite. A failed preflight
   publishes no new fence. A failure publishing the second marker leaves an exact,
   retryable partial fence; the coordinator must not mutate records or commit
   the driver until both fences are durable. The marker survives
   restart; an exact retry is allowed, but a conflicting or already retired
   destination fails. Both per-record delivery and KILL rewrite primitives
   repeat that destination check under the journal lock, so a direct retry
   cannot move records into an identity already fenced for another rekey.
   A paired completion check now holds both journal locks and requires both
   exact fences, every delivery and KILL on the destination identity, no
   identity-free outbound record, and no KILL applied marker, including an
   orphan marker. It also refuses a destination subsequently fenced for a
   later rekey. It is a journal predicate only: it does not prove the
   source host's delivery receipts, authorize replay, or invoke the driver
   commit ioctl.
   Identity-free outbound records still
   need host receipt reconciliation and cannot be sent while the driver's
   rekey gate is pending. The primitive does not authorize a delivery: the
   host receipt reconciliation and guest journal transaction must precede its
   use. Unbound outbound records still require their original host receipt
   before any identity rewrite. A daemon
   restart between rekey and guest receipt must recover
   that transaction. Simply rewriting the host queue would leave guest records
   tied to the old VM. An event already being processed when rekey arrives
   still needs the host-side paused-guest transaction. The driver also
   refuses identity-free ingress-status
   queries after rekey until that transaction is implemented. The root-owned
   guest transport now has an exact-identity `DTT_COMMIT_VM_REKEY` operation:
   it records local journal commit only when the supplied old and new
   VMID/epoch match, and an exact retry after a lost ioctl reply succeeds.
   `DTT_GET_VM_IDENTITY` exposes a distinct locally committed phase with the
   original identity. Both this phase and the earlier pending phase keep
   ordinary traffic and daemon startup fenced. Host acknowledgement must be
   proven separately before retiring the transition. The daemon must not
   invoke the ioctl until all affected journals have been durably rekeyed and
   reconciled with host receipts. The pending-identity daemon startup path
   now enforces that sequence; it still needs live restored-guest evidence.
5. **Publication and startup.** Publish the staged device state atomically
   with common VirtIO restore or quarantine the destination on any failure.
   After kernel COMMIT and handoff CLAIM, bind all source KILLs into the
   destination incarnation. Finish all prestart queries before starting the
   long-lived connector, because those control APIs reject `started`.
   Admission ACKs prove daemon acceptance and KILL replay staging. A separate
   guest-applied barrier is needed if restored tracing processes must not run
   before pending KILLs take effect. Only then resume devices and release the
   vCPU startup fence.

Live migration uses `vm_snapshot_dev_state_to_mem()`,
`vm_migrate_commit_state()`, and `vm_migrate_resume()` rather than the file
restore coordinator. Those calls currently have no HyperTrace handoff ticket
or guest-journal rekey contract, so HyperTrace VMs are rejected before source
cut, destination mutation, and destination resume. This guard must remain
until the migration bridge implements the same transaction.

Qualification needs malformed and OOM image tests, exact receipt and KILL
reconciliation tests (including duplicate and lost replies), crash/restart
tests at every durable phase, failed common-VirtIO rollback tests, a restored
guest rekey/replay test, and live host/guest checkpoint plus migration runs.
Native parsing and build checks alone cannot open the gate.
