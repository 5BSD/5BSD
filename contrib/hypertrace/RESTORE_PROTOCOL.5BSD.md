# HyperTrace VM restore transaction (partial implementation)

The `pci_virtio_dtrace` save callback accepts a settled source. Format-4
restore now admits a ticket-bound private device image when the host-ingress
transfer is empty and the local HSL1 release witness exists. Pending or
accepted host ingress without an execution lease remains fenced; cross-host
release and live migration also remain unavailable.
The source device refuses another checkpoint while a destination queue or
handoff ticket is still attached, or a rekey ACK or receipt remains pending.
After REKEY_APPLIED, it clears the old ticket and ACK identity before a later
checkpoint generation can be considered.
The production live-migration source and destination now reject an initialized
HyperTrace session at entry, before pre-copy or destination RAM staging. The
device-blob and restore guards remain in place if another caller reaches them.
A VirtIO queue image cannot prove ownership of the host daemon's session or
reconcile the guest's durable delivery and revocation journals. The restored
guest remembers the source VMID and epoch; the destination VMM allocates a new
pair. The guest driver correctly rejects an ordinary `NODE_ID` change.
The host daemon has a durable handoff ledger keyed by a one-use ticket. Its
prepared, committed, reserved, mutating and claimed phases bind the source
identity, checkpoint digest and destination identity, and recover consistent
phase overlap after a crash. Source checkpoint invokes PREPARE and settles
COMMIT or ABORT after manifest publication. Destination preflight reserves the
ticket and queries saved delivery state, then deliberately stops before
memory mutation. A guest-to-host ELF upload now holds the outbound handoff
lock through its accepted journal fsync, so PREPARE waits for an in-flight
upload and rejects new ones. The source session is not yet fenced to an exact
cut across every daemon control class. PREPARE also refuses pending or
accepted inbound uploads until consumer processing has a durable receipt and
destination transfer rule. For an accepted upload it now checks the durable
recipient cohort, terminal execution receipts, VMID/epoch, the saved
bare-ELF digest, the exact HGI1 kernel gate, and every ticket-bound HGD1
consumer drain receipt before returning `EOPNOTSUPP` without publishing a ticket.
This distinguishes unfinished work from consumer state that still needs a
transfer lease; it does not authorize source save. A future transfer must
replace the source envelope name from a live attested identity rather than
treating that unjournaled string as transfer authority. A complete manifest
with HTP1 frames can now be rebound in memory to an attested destination
identity and stored as a hidden, fsynced HTB1 sidecar. Recovery validates its checksum,
file ownership, ticket, and destination identity before rebuilding the plan.
HTB1 can populate ticket-bound destination HTD5 records and verified spools
in pending phase; a restart can retry an incomplete population. Pending
records do not authorize consumer execution. Population requires the matching
durable destination ticket in reserved or mutating phase, held under the daemon's
handoff process lock; the private sidecar alone is never ticket authority.
Each imported HTD5 retains the source forwarder session and VM lifetime,
destination forwarder identity, and handoff token. Ordinary host ELF upload
retries cannot advance it through the local HTD4 acceptance path; the watcher
does not dispatch it even if its phase name is changed to accepted. A separate
crash-safe destination consumer lease and cohort publication transaction must
authorize that transition.
HTM1 still exports source HTD4/HCR1 entries only; a later checkpoint of a
promoted destination HTD5 needs explicit multi-hop lineage and receipt rules.
The destination can now reserve a candidate owner set in a private,
checksummed HTL1 sidecar. It binds the transfer sidecar digest and destination
VM lifetime to the exact HCO1 session/UID/PID/incarnation records of all
source recipient sessions. The reservation requires matching live consumer
connections and pending HTD5 records, and an exact retry preserves the same
bytes. CANCEL removes HRS1 and HCK1 before HTL1 and HTB1. HTL1 alone is not
an execution lease: its bytes do not store the consumer program digest or an
execution outcome, and it cannot authorize acceptance. Promotion must reread
the related records and verify live ownership under the same ticket and
journal locks.
The recovery reader validates HTL1's checksum, reserved fields, transfer
digest, sorted source recipient set, pending HTD5 phases, and exact HCO1
records before returning owner bytes. It does not require a currently live
socket, so a daemon restart can inspect the reservation without treating that
inspection as authority to execute.
The destination HCR2/HCB2 codecs now define the prospective recipient
identity without admitting it to the journal. HCR2 binds one complete
canonical HTD5 record, one checksummed HCO1 owner including its process
incarnation, and a nonzero 32-byte consumer-program digest. HCB2 fixes a
bounded recipient set in strict session order and checks every nested HCR2
before returning any members. Neither codec verifies that a live consumer
actually runs the named program; a later lease must establish that fact.
HCR2 is 329 bytes (`HCR2`, 185-byte canonical HTD5, 76-byte HCO1, 32-byte
program digest, SHA-256). HCB2 is `HCB2`, a little-endian 32-bit count, that
many HCR2 records, and SHA-256. The maximum count is 65,536.
The existing `dtrace_prog_t::dp_ident` is randomly assigned at compile time,
so hashing that identifier or the unnormalized generated ELF would falsely
reject a supervised restart of the same script. The source HCR1 format also
has no program image digest. libdtrace now exposes an HPI1 candidate identity:
SHA-256 over a domain-tagged hash of stripped DOF, with the process-local
`dofa_uarg` callback value cleared in that disposable DOF image. Six compiled
program cases were stable across separate compiler processes and changed when
their actions changed in the offline native test. This is evidence for the
matched compiler and ISA, not a guarantee across different builds or targets.
Protocol 48 now carries HPI1 from `dtrace -E`
on the primary ELF receiver. The daemon binds the first nonzero digest to
that authenticated connection and allows only an exact retry; HTL1 owner
reservation requires an announcement. The receiver still self-reports the
digest, and HCR1/HTM1 do not carry it. Source transfer and destination
recovery must bind the same digest before HCR2 may become a lease; protocol 48
alone cannot establish cross-host program equivalence or authorize execution.
For newly announced source consumers, HCP1 now records the exact pending
HCR1 receipt, the current checked HCO1 process incarnation, and HPI1 before
the daemon publishes that recipient's socket job. Its private file and
directory are fsynced. An exact retry keeps the same bytes; a different
incarnation or digest cannot replace them. The reader validates the complete
record without requiring the original HCO1 file to remain current, so owner
rotation cannot erase the program identity already recorded for a receipt.
Legacy HCR1 receipts without HCP1 remain valid for ordinary local processing
but lack program evidence for migration. HTM2 is a provisional overlay on an
exact HTM1 snapshot: it carries one complete HCP1 for each recipient in HTM1
order and checks the nested manifest, count, owner incarnation, and both
checksums. Its builder rereads the source snapshot after gathering the proofs
and rejects a changed cut. HANDOFF_EXPORT now places HTM2 in HTX1 when
accepted ingress exists and refuses a legacy recipient lacking HCP1. PREPARE
rebuilds the same HTM2 under the source handoff lock before comparing its
HTX1 digest, but still refuses accepted ingress until destination execution
leases exist. The destination retains the checked per-recipient program
evidence in an inert HTB1 staging plan; it cannot execute from this proof.
The kernel's privileged exact-epoch, ticket-bound DTrace gate can now suspend
source-origin ECB actions with a cross-CPU drain and resume them after an
abort. A stale ticket cannot resume a newer suspension, and a fresh SUSPEND
must compare the owner token read before the request. Source PREPARE now
requires that gate under the handoff publication lock; HGD1 additionally
proves drained principal output for each HCP1 recipient. Neither substitutes
for transferring durable destination execution ownership.
When the staged manifest is HTM2, HTL1 owner reservation compares each live
destination consumer's announced HPI1 with the corresponding source HCP1
digest before publishing its owner set. A mismatch refuses reservation, but
this comparison is still not a durable destination execution lease.
The destination derives canonical HCR2/HCB2 bytes for each pending HTD5
from the reloaded HTB1 plan and its HTL1 owners. The planner checks each
source receipt, source program digest, destination owner, and HTD5 identity.
HTL1 reservation first checks every cohort, then publishes HTL1 followed by
one private, fsynced HCK1 bundle binding the ticket, HTB1 digest, HTL1
digest, and ordered HCB2 bytes. An exact retry completes an interrupted HCK1
publication; the recovery reader recomputes the expected bytes and rejects a
changed sidecar. HRS1 now follows HCK1 with one immutable pending result slot
per HCR2 in the same order. Each slot records SHA-256 of its canonical HCR2
and a pending state; the HRS1 header binds the ticket and HCK1 digest. An
exact retry fills a missing HRS1, and the recovery reader verifies the whole
bundle. HPA1 follows HRS1 and fixes the ordered SHA-256 identities of every
staged HTD5, bound to the exact HRS1 digest. Exact retry completes an
interrupted HPA1 publication; the reader checks it against the staged plan.
CANCEL removes HPA1, HRS1, HCK1, HTL1, then HTB1. These records remain
inert: no outcome or accepted HTD5 is published yet.
The HPA1 recovery reader now verifies HTB1, HTL1, HCK1, HRS1, and HPA1
under the outbound ticket and inbound journal locks. It checks the current
durable HCO1 owners and rejects any unplanned record using the handoff token.
An explicit recovery view accepts a mix of pending and accepted HTD5 records
while preserving the same fixed identities; the ordinary view still requires
all pending. Neither view grants execution authority.
The attested `HANDOFF_IMPORT` request now completes that inert reservation
before acknowledging a nonempty transfer. It refuses a legacy manifest with
no HCP1 program evidence, publishes pending HTD5 and spools, then requires
the matching live HPI1 consumer and exact HTL1/HCK1/HRS1/HPA1 sidecars.
If the consumer is absent, the request fails with pending work still fenced;
an exact retry can finish the reservation, or CANCEL removes it.
The claimed-ticket promotion component now verifies the same complete
HTB1/HTL1/HCK1/HRS1/HPA1 chain under the outbound ticket, live-consumer,
and inbound journal locks. It rechecks the exact HCO1 incarnation and HPI1
program digest before changing any pending HTD5 phase. A crash after one
pending-to-accepted rename can retry the fixed cohort; each rename reaches
disk before the next. Only after every member is accepted does it publish
fsynced HLC1, binding the ticket, HPA1, HTL1, and destination lifetime.
An exact retry of HLC1 needs no new live consumer, but rejects a changed
marker or a pending member. CANCEL refuses an HLC1 even if the ticket state
is inconsistent. The watcher still ignores accepted HTD5, including after
HLC1; recipient execution and replay remain to be wired.
The read-only committed-import reader requires a claimed ticket, every
canonical sidecar and accepted HTD5, and the exact HLC1 bytes. It returns
absent when all HTD5 are accepted but HLC1 has not been published; a partial
phase transition is refused and never completed by the reader. An
orphan HLC1 with no HPA1 is corruption, not absence. This
check is a prerequisite for future execution and replay;
it does not itself grant an execution lease.
The same locked check can return the canonical HCR2 recipients per HTD5.
It decodes each HCB2 only after verifying the claimed ticket, HCK1/HRS1,
accepted delivery set, and HLC1. The result fixes owner incarnation and
consumer program digest for recovery without choosing a new consumer.
Protocol 49 now carries `HANDOFF_PROMOTE_IMPORT` on the attested destination
control channel. The daemon requires the exact claimed ticket, checkpoint
digest, and current VMM-attested destination identity. Under the revocation
lock it first binds saved source KILLs to the destination, including on an
exact retry, before promoting any imported ingress. A nonempty transfer
invokes the claimed promotion transaction; an absent stage is accepted only
when the ticket binds the canonical empty HTX1. The bhyve prestart helper can
send this opcode, but the restore path still rejects nonempty ingress before
mutation and does not invoke promotion until execution/replay is complete.
Protocol 50 adds `HANDOFF_ACTIVATE_IMPORT`. Once the guest reports
REKEY_APPLIED, bhyve retries the exact attested request if its reply is lost.
The daemon binds any late source KILLs, checks the durable guest-applied
record, then publishes fsynced HLA1 for a nonempty committed import. HLA1
binds the ticket, HLC1 digest, HRS1 digest, and destination incarnation.
The read-only recovery path verifies HLA1 and rejects a changed or orphaned
marker. Reservation rollback also refuses a stray HLA1 instead of removing
its stage records. A canonical empty transfer needs no HLA1. This gate does
not start recipient execution; nonempty restore remains fenced pending
dispatch and replay. A single locked read can return the fixed HCR2
recipients together with their HRO1 outcome states after verifying HLA1;
the view does not choose recipients or grant execution.
A report-side lookup now resolves a claimed ticket, destination stage, HLA1,
ingress session and delivery ID, and exact HCR2 owner into one outcome. It
rejects a different consumer, inactive import, or damaged marker. A consumer
recovery census walks accepted HTD5 records and returns only activated HCR2
recipients matching one live HCO1 incarnation and HPI1 program digest. Each
ticket is verified separately; a queued job must revalidate before dispatch.

Protocol 51 adds `HANDOFF_SOURCE_RELEASE` on an exclusive forwarder channel
opened with the original VMM attestation before stop-checkpoint destroys the
source. Admission also opens and retains the privileged HyperTrace device and
requires the exact bound epoch to be live before acknowledging the channel.
Failure stops bhyve before VM destruction. The post-destroy request uses that
retained device descriptor and carries the handoff token and checkpoint
digest. The source daemon requires the exact committed HTH2 ticket, a kernel
query showing that ticket's VM epoch has completed DTrace drain, and an
fsynced HSL1 sidecar before acknowledging. The channel cannot issue other
requests. Initial `reserve_handoff` requires HSL1 even for an empty transfer.
Every read of a reserved, mutating, or claimed ticket revalidates it; the
sidecar remains readable after later ticket phases. It witnesses the
local VMM lifetime and guest-origin ECB drain; source host consumers still
need a separate execution fence. A cross-host destination needs a trusted
way to receive and verify the release witness before it may reserve the
ticket. The existing bhyve migration frame CRC is not a peer-authentication
mechanism; its caller-supplied stream cannot by itself confer that authority.
The census does not send any ELF bytes. HLA1 activation queues pending HCR2
work for connected HPI1 receivers, and HPI1 registration queues pending work
after daemon restart. Each job rechecks HLA1, the fixed HCR2 owner and
program, the accepted HTD5, the destination envelope, and the bare ELF digest
before sending. A consumer execution report for HTD5 follows the lookup and
verifies the live HCO1
birth and HPI1 program digest, and requires a processed HRO1 of the same
outcome before writing the executed successor. That write verifies HLA1 and
audits all HRS1 slots under the journal locks. The nonempty restore fence
remains until the bhyve coordinator and crash windows use this dispatch path.
The HRO1 codec defines the recipient outcome record. It
binds the ticket, HRS1 digest, and one HCR2 digest to either a processed
`n`/`d` or executed `N`/`D` phase. A derived phase requires a nonzero HDU2
claim digest field; a no-derived phase requires zero. Its reserved bytes and
outer checksum are canonical. An internal journal transaction now requires a
claimed HLC1 commit and exact HRS1 slot before publishing an immutable HRO1
phase. It retains the processed phase when publishing the executed successor;
an executed phase without its processed predecessor, a changed claim digest,
or an opposing derived/no-derived branch is refused. A read under the same
ticket and journal locks validates both records and returns the latest phase.
An imported consumer execution report can call the activated transaction
only after an exact processed HRO1 already exists. The consumer job now
records that phase after an exact ACK. Under the outcome lock it resolves any
HDU2 claim against the activated HCR2, retained spool or delivered outbound
receipt, and canonical claim digest. A lost ACK may settle only a proven
derived result; otherwise the slot remains pending for replay.
A bulk recovery read walks HRS1 in canonical order, pairs each slot with its
fixed HCR2 recipient, and returns the pending or settled HRO1 phase. Under
the same journal lock it rejects any HRO1 name for this ticket that is not
one of those fixed slots. HRO1 without HLC1 is corruption rather than an
empty replay set. This view supplies replay planning; it does not dispatch
work.
The promotion transaction now verifies HCK1's fixed HCR2 recipients,
HRS1's pending slots, and HPA1's fixed HTD5 identities before committing
the accepted set as HLC1. HLA1 requires a claimed ticket and durable guest
rekey report. The explicit activation and HPI1 paths now queue only fixed
HCR2 owners, record ACK-backed HRO1 outcomes, and replay pending recipients
after a daemon restart. The ordinary spool watcher remains fenced for HTD5.
The bhyve nonempty restore coordinator and its crash windows still need
integration.
Destination queue publication and guest rebind are separate transactions. The host outbound
receipt journal now freezes source phase changes during handoff, while
allowing exact retries and terminal cleanup of a previously bound VM.
The host consumer send holds the source handoff lock through the complete
socket frame, then releases it before waiting for the processing ACK. The
consumer's synchronous derived publication needs that same lock. PREPARE
continues to refuse accepted ingress during the ACK interval, and new sends
defer until ABORT. COMMIT drops those deferred jobs on the old source. For an identified guest upload,
the host watcher holds that lock from recipient receipt creation through
job publication. If PREPARE already owns the cut, the watcher leaves the
spool unmemorized and ABORT requests another scan. This closes the pending
receipt publication race, but it does not make consumer execution durable.
Identified watcher and recovered-consumer jobs carry their source VM lifetime
from creation, allowing COMMIT to retire queued jobs before any send attempt.
A deferred worker checks the source phase and rejoins the queue under one
handoff lock, so COMMIT retirement and ABORT wakeup cannot cross that requeue.
The DTrace receiver synchronously sends any derived guest ELF to the daemon
before acknowledging; the daemon's ACK confirms crash-durable spool
publication, not guest installation or even outbound watcher dispatch. The
consumer frame carries the accepted journal's
program ID, source ID, delivery ID, VMID and epoch as the identity for a future
processing receipt. The DTrace receiver rejects an incomplete identity or one
whose VMID and epoch differ from the ELF envelope. Its processing ACK echoes
the delivery, program and source IDs and VM lifetime; the daemon rejects a
mismatch or malformed padding. Before source saves can be
enabled, consumer execution still needs a crash-safe recovery rule and a
destination transfer rule so restore can distinguish a program that ran on
the source from one that still needs delivery. In particular, the receiver's
`dtrace_send_elf_async()` still serves ordinary host programs; its success
means only that its local worker accepted a job. The identified consumer ACK
reports whether a derived ELF reached the daemon spool and is followed by a
durable HCR1 receipt with that outcome. The legacy processed phase does not
prove either outcome. The current receiver sends the ACK after parsing and
derived publication, then a separate execution thread calls
`process_new_pgp()`. HCR1 now has distinct `N`/`D` execution-settled phases:
after the host execution thread succeeds, a separate reporter opens a
consumer connection under the same session and sends the exact ingress identity. The
daemon checks the peer credentials and parsed `n`/`d` outcome, then renames
the HCR1 phase and fsyncs the directory before acknowledging. A NAK while
the earlier parsing ACK is still being committed is retried. The older
`n`/`d` phases do not prove execution. A crash between enablement and this
second receipt can leave execution uncertain; a crash after the receipt can
leave the consumer dead even though HCR1 says it executed. Source save must
still reconcile consumer liveness and recover or retire uncertain sessions.
The receiver queues an unrelated, ignored ingress as a settled no-op and a
duplicate behind its matching program. The reporter sends their exact result
without blocking the receiver's ACK and replay stream. A stopped or crashed
consumer still needs liveness and recovery handling, so these results do not
authorize a checkpoint yet.
The daemon now accepts that result only while the matching primary consumer
ELF receiver is registered, has finished replay admission, and has the same
session and peer credentials as the reporting socket. A reconnect can retry
after replay. This check does not prove that the consumer will remain alive
through a source cut or that its DTrace state exists on the destination.
Protocol 40 puts the ingress journal session in the identified ELF header's
parent slot and in a 72-byte execution-result body. The receiver checks that
the header mirrors the delivery identity before retaining the session. The
daemon resolves the accepted ingress and HCR1 receipt by their exact journal
names, including that session, rather than scanning every receipt for each
result. The original 56-byte parsing ACK keeps its wire format.
Protocol 41 gives a host-to-guest CLEANUP frame a nonzero queue-ACK token in
the eight-byte header slot used by INFO counts for INFO frames. The host daemon
holds the source handoff lock from frame send through bhyve's exact token ACK;
bhyve sends that ACK only after publishing the whole cleanup event to the
guest device queue. The daemon fsyncs a per-VM-lifetime pending cleanup marker
before publishing the job, and PREPARE rejects that lifetime while any such
marker remains. A matching VMM-attested forwarder reconnect requeues the
same token after a daemon crash. The pending marker becomes a retained
accepted marker, with a directory fsync, only after the exact queue ACK; a
request arriving after PREPARE is
rejected. This proves queue admission, not guest application or destination
reconciliation, so it does not enable source saves.
Protocol 42 adds an attested destination lookup for that retained CLEANUP
receipt. `HANDOFF_CLEANUP` carries the handoff token, source digest, and exact
cleanup delivery ID in a 56-byte body; a reserved or claimed destination can
query the accepted phase. A saved VirtIO CLEANUP control now carries the same
ID in private snapshot format 3. Queue planning retains the ID while mapping
the source VM lifetime to the destination, and rejects a control without its
accepted source receipt. This establishes a source-to-destination queue
admission link, but a guest-applied receipt and a complete source cut remain
required before checkpoint saves or restores can be enabled.
Protocol 43 defines an exact CLEANUP_APPLIED observation from the attested
guest forwarder. The guest daemon closes launch admission and waits for every
in-flight launch to register or terminate, then kills and waits for its owned
traced children. It reports the original cleanup ID before re-exec.
The guest driver retains and retries that report across daemon re-exec until
the host returns the exact HOST_CLEANUP_APPLIED receipt. The host advances the
accepted cleanup marker to a guest-applied phase and fsyncs its journal before
returning that receipt. Only this durable observation clears bhyve's
delivered-but-unapplied fence. The guest now holds each new tracing child
behind a pipe until its process-descriptor birth identity and boot ID are
fsynced in the inbound child ledger. A crash before that write leaves the
child unable to exec. On restart, the daemon audits each record, reopens the
process descriptor, compares its monotonic birth identity, and waits for an
exact matching child to exit after SIGKILL. A different process that reused
the PID is never signaled. A missing ledger marker, malformed record, or
unresolved process keeps startup closed. Only after this audit may a pending
guest cleanup token be reported as applied. The restarted daemon obtains the
exact token from `/dev/dttransport`; a pending-but-applied token continues
retrying from the driver across daemon re-exec.
Protocol 44 adds `HANDOFF_REKEY_APPLIED` for the destination VMM. After the
guest sends the exact REKEY_APPLIED control, bhyve sends the ticket and
checkpoint digest on a separate attested channel. The daemon requires the
claimed destination identity and fsyncs an idempotent receipt without
retiring the claimed ticket, which late KILL and delivery bindings still use.
Bhyve releases its rekey barrier only after that receipt, including an exact
retry when the first response is lost. An unresolved or late receipt leaves
the device quarantined. This records the host observation, not the complete
restore transaction or live guest proof.
Source save and destination restore remain disabled. A checkpoint after
host journal acceptance but before the guest receives the receipt also needs
an explicit transfer or final acknowledgement of the guest's pending state.
A crash before ACK can leave
a pending record, and a published outbound spool can still wait for the host
daemon watcher and guest forwarder. The recovery protocol must distinguish
these phases before source saves are enabled.
The receipt protocol must correlate that derived delivery with the original
ingress identity and remain queryable after either daemon or consumer exits.
The DTrace client assigns each new consumer socket a nonzero random session
ID and retains the ELF receiver's ID across a daemon reconnect. A supervised
host consumer can instead use `-E -x hypertrace_session_file=/absolute/path`
with any number of DTrace programs (dtrace(1) appends them into the one
program the session registers). Its pre-provisioned 52-byte HCS1 record contains
`HCS1`, a nonzero 16-byte session, and SHA-256 of those first 20 bytes. The
client requires an owner-only regular file with one link, opens it without
following a symlink, and holds an exclusive advisory lock for its lifetime.
It rejects missing, malformed, or concurrently held records without minting a
replacement session. This preserves the session identity for a supervised
restart. A replacement PID can pass HCR1 admission only when every receipt
under that session and an earlier PID is execution-settled (`N` or `D`), has
the same UID, and its old PID no longer exists. Pending, legacy processed,
and parsed-only receipts still refuse takeover. No old work is replayed in
this narrow case; an explicit crash-recovery protocol is required for it.
The DTrace client now includes a process-local random incarnation and PID in
its canonical consumer hello. The daemon checks the claimed PID against Unix
peer credentials, then writes an HCO1 owner record containing session, UID,
PID, incarnation, and SHA-256 before releasing that consumer to receive
ingress. Its creation is file- and directory-fsynced; startup validates every
HCO1 record and removes interrupted temporary records. A reconnect must match
the exact HCO1 bytes. Missing HCO1 with pending same-PID HCR1 work refuses
replay. A changed incarnation under a reused PID can atomically replace HCO1
only after every earlier receipt under that session and PID is `N` or `D`,
including all members of every HCB1 cohort. A cohort member whose HCR1 is
missing, pending, legacy processed, or parsed-only blocks the replacement.
The daemon fsyncs the replacement and directory before admitting new work.
First binding with no HCO1 also inspects every matching-session HCB1 under
the handoff process lock. A committed cohort without a settled HCR1 blocks
binding even if its member used an earlier PID and was absent from the
consumer's initial receipt scan; a settled earlier PID must have exited.
The incarnation is a
recovery discriminator, not an authorization secret against a peer with the
same UID. This still does not journal the lost consumer program or permit
checkpoint save. Protocol 45 requires the incarnation identifier on an ELF
consumer hello and rejects earlier peers at version negotiation. Protocol 40
first rejected ELF subscriptions that omit a session.
The socket ACK alone
does not establish a durable recipient record. The daemon now writes an HCR1
record keyed by that socket and the accepted ingress before queueing
its job and fsyncs the outcome transition after the exact ACK. It can read
and validate the fixed 158-byte HCR1 records after restart, rejecting wrong
ingress identities, duplicate phases, checksum failures, and non-regular
files. On admission, the daemon checks the exact session and peer UID/PID,
queues only pending startup-memorized deliveries, and skips processed ones.
If a replayed upload finds a derived program already valid, its ACK may report
no new ELF. The daemon resolves any earlier HDU2 claim and published spool or
accepted outbound receipt before recording the durable derived outcome.
Derived publication and outcome reconciliation hold the same cross-process
journal lock through their respective commits.
The watcher excludes that consumer until replay finishes. The receiver
reopens both daemon sockets after a transport loss while reading a frame.
An identified derived ELF carries the receiver session and exact inbound
delivery in the otherwise unused installed-event slot of its ELF frame.
The daemon requires a matching accepted ingress and HCR1 recipient, checks
the Unix peer credentials and target envelope, then publishes the derived
spool while holding the source checkpoint lock. Its stable program ID hashes
the parent identity and the full target-envelope/ELF payload, so an exact
retry names the same file. A restarted daemon can hash that retained file
and resolve its HCR1 parent without trusting a filename alone. Before spool
publication, an fsynced HDU2 record binds the recipient, inbound delivery,
and target VM lifetime to one derived program ID, full payload digest, and
bare ELF digest. An exact retry may complete an interrupted spool publication;
a distinct payload for
the same parent and target fails instead of creating a second result. Startup
validates each claim's checksum and canonical name, then audits its accepted
ingress, exact HCR1 recipient, both retained spool digests, and any matching
outbound delivery receipts. If the spool is
absent, an accepted, installed, or terminal host outbound delivery with the
same program, source, original target lifetime, and bare ELF digest can still
establish the parent. A terminal receipt remains durable after guest uninstall.
An exact consumer retry does not recreate a spool after such a completed
delivery. A
conflicting receipt fails startup audit and live parent resolution even when
the spool is retained; a receipt with the claimed program ID and a different
source ID is conflicting too. A claim
without either remains pending after an interrupted publication. An HCR1
result already marked `derived` must still have a matching hashed spool or
completed outbound receipt; startup audit and live resolution reject a claim
that lacks both forms of proof. No destination transfer consumes the HCR1/HDU2
relation yet.
At host-daemon startup an audited pending HCR1 recipient is durably marked
`derived` if its exact HDU2 claim has a matching retained spool or a completed
outbound receipt. A claim without either proof remains pending. This recovers
a daemon crash after derived publication but does not prove a consumer run
that produced no derived program.
The still-running consumer can re-emit its cached guest program for the exact
same session and ingress delivery after a reconnect. A distinct upload of the
same source program does not inherit that result. A stable HCS1 session does
not journal the cached program or consumer execution across a process crash.
Failures during execution, derived
dispatch, or the ACK still lack a complete crash-safe replay rule, and
migration of the HCR1 ledger is not implemented.
An accepted upload with no connected host DTrace
consumer remains unmemorized in the running daemon. Consumer admission
requests an inbound rescan so the pending file can be queued. A daemon
restart still does not replay a prior spool solely from its filename;
the accepted ingress journal and per-consumer receipts must authorize it.
If a consumer disconnects after the batch is queued, its unacknowledged
job can be discarded while another consumer may already have processed the
same upload. The watcher now publishes a checksummed HCB1 recipient cohort
before any HCR1 receipt or job. Startup uses that fixed cohort to complete
HCR1 writes interrupted by a crash; a later scan cannot grant a new consumer
session the same upload. Legacy HCR1 without HCB1 also remains fixed to its
earlier sessions. An exact-session reconnect can replay pending HCR1 work.
A cohort file is named by the ingress session and delivery ID; its HCB1 bytes
contain a little-endian recipient count, sorted canonical HCR1 records, and
a SHA-256 checksum. Both HCB1 and new HCR1 files are written and fsynced at a
temporary name, then linked and directory-synced before they become authority.
The HCR1 capacity check counts members promised by durable cohorts even when
their individual files are still missing; a later ingress cannot consume
those reserved slots. An HCR1 outside an existing cohort is invalid.
A process crash that loses its session or cached derived result still cannot
be recovered automatically; a durable consumer execution and result journal
plus destination transfer remain necessary.
The source can now form an `HTM1` ingress transfer metadata record under its
handoff lock. Its 50-byte header binds the source ticket, session, VM ID,
epoch, and entry count. Entries are sorted by ingress session and numeric
delivery ID; each contains the 143-byte HTD4 record, a recipient count, and
the HCB1 cohort's 158-byte HCR1 member records with their terminal `N` or
`D` phase. A SHA-256 digest ends the bounded record. Parsing checks every
embedded record and strict ordering, so changing the outer digest alone does
not make a malformed member valid. This is metadata only: the original ELF
spool is rechecked against HTD4 at the cut and still needs a separate,
authenticated copy. `HTM1` is not yet a ticket-bound durable transfer or a
destination enablement journal; PREPARE continues to reject accepted ingress.
Before that refusal, PREPARE checks each terminal `D` recipient against its
durable HDU2 claim and outbound publication while holding the source handoff
cut. A terminal HCR1 alone cannot certify that derived output exists.
The source verifier can return the exact VM-envelope and ELF bytes from the
same file descriptor it hashes. It publishes those bytes to its caller only
after the bare-ELF digest and file stability checks succeed, so an export
failure cannot leave a partial payload masquerading as a transfer.
The destination-side byte validator checks the copied frame's source VM
lifetime, envelope bounds, ELF magic, and bare-ELF SHA-256 against its decoded
HTD4 record before the frame can be staged. It never treats the envelope's
source name as destination identity; the destination must use its own live
VMM attestation when it eventually reconstructs the guest program.
`HTP1` defines one ticket-bound payload artifact: the 16-byte ticket token,
canonical 143-byte HTD4 record, 32-bit payload length, original VM-envelope
and ELF bytes, and a trailing SHA-256 over that prefix. A destination decoder
requires the exact HTD4 selected from HTM1, checks the frame length and
digest, and rechecks the bare ELF against HTD4 before releasing bytes.
The HTP1 checksum detects torn files; an authenticated checkpoint member and
durable destination import are still required before these bytes can authorize
restored execution.
The destination bundle decoder requires one ordered HTP1 frame for every HTM1
entry. It decodes into a private result and releases entries and payloads
only after all frames pass, so a missing, duplicate, reordered, or corrupt
frame cannot leave a partially accepted ingress set. This check does not
authenticate the checkpoint or publish destination journals.
The source export API takes the outbound handoff process lock for each HTP1
frame, recomputes the full HTM1 recipient set, and returns a frame only when
it still matches the caller's manifest and the original spool verifies.
The companion HTM1 snapshot export takes that lock and audits HDU2 claims
against outbound publications before releasing the manifest. An inconsistent
terminal `D` yields no manifest to the caller.
Both exports now check the ticket's durable phase under that lock. They allow
an unrecorded ticket while the checkpoint is being assembled and the exact
source's prepared ticket while the cut is held. A different source using the
same token, a different active ticket for the same VM lifetime, or a
committed or destination-owned ticket cannot read the provisional source
artifacts.
Requests can be interleaved with journal changes, so a completed checkpoint
member must be bound to that same manifest again by PREPARE before publication.
For a live consumer, a failed synchronous derived send now keeps the generated
program and exact parent in the process, reconnects the same session, and
re-emits only when that ingress is replayed. The receiver checks for that
match before parsing the replay as another response. A completed host program
remains in a separate replay list after leaving the active execution queue.
A replay waits for that host program's DTrace handle operations to finish.
A failed replay cannot acknowledge a no-derived success. This does not
recover a process crash.
The in-process derived cache now also binds the SHA-256 digest of the entire
received VM/ELF frame. An exact delivery identity with changed bytes, or a
cache entry without its digest, receives a failure rather than reusing the
earlier generated guest program. The daemon's accepted journal still needs
transfer and consumer execution still needs a durable crash journal.
When the consumer ACK socket closes, the running host daemon checks the exact
HDU2 claim under the outcome lock. A hashed derived spool or completed
outbound receipt lets it fsync the recipient HCR1 as `derived` immediately;
without that proof the HCR1 stays pending for replay. This does not prove a
no-derived consumer run or transfer the ledger to a destination.
An explicit failure or malformed consumer ACK is still rejected. The daemon
also checks independent durable derived proof on that path, so an already
accepted result can complete HCR1 while an unproven result stays pending.

## Safety invariants

1. One checkpoint generation has one random, nonzero handoff ticket, bound to
   the source forwarder session ID and source VMM identity. The ticket is
   persisted by the host daemon before the checkpoint manifest can publish.
   The HTH1 phase and guest-REKEY_APPLIED writers fsync a private temporary
   file before linking the final name; startup takes the cross-process handoff
   lock before removing an orphaned name, so a replacement daemon cannot
   delete an older publisher's live temporary inode. It finishes cleanup
   before accepting tickets. Phase and guest-REKEY_APPLIED readers reject special,
   multiply linked, or non-private files without blocking on a FIFO.
   The manifest covers the ticket-bearing device record. A ticket alone does
   not authenticate a destination: the daemon must also check its live,
   VMM-attested destination descriptor.
2. Source capture fences daemon ingress and egress, not only vCPUs and PCI
   workers. It records the exact durable delivery/revocation cut. A source
   checkpoint may publish only after that cut and all image members are
   durable. Abort reopens the source session without losing deferred work.
   Commit either retires the source lease or records explicit fork semantics;
   a live source and destination must never both own one replay lease.
3. Destination preflight verifies the checkpoint and asks the daemon to
   reserve the ticket before mutating memory. Reservation is idempotent for
   the same destination VMM identity and rejects another destination. Failed
   preflight releases the reservation. A crash after memory mutation leaves
   the ticket recoverable only through a daemon-checked abort/retry path; it
   never silently authorizes a second running VM.
4. The destination retains `checkpoint_restore_startup_hold` through kernel
   COMMIT, device resume, daemon handoff, and arming a restricted guest-rebind
   mode. The release point is after daemon claim and device resume in the
   current coordinator. The format-4 empty-transfer private-image path now
   executes this sequence; nonempty host ingress is still fenced. Protocol
   40's restore subscription obtains a bounded
   canonical KILL manifest after the daemon binds the source revocations;
   the coordinator takes it while PCI devices are paused, and the device
   inserts it into the private planned queue before saved ELF controls. The
   handoff ticket is attached to that plan, and only then is the queue
   published under the same device pause. The device publication function
   itself now refuses a missing ticket with `EACCES`, preserving the live
   queue and private plan even if a caller skips the coordinator's attach
   step.
   Failure here keeps destination vCPUs stopped. The guest
   daemon cannot reconcile its journal until vCPUs run; after release, the
   device must still fence normal tracing controls until that reconciliation
   is durably acknowledged. The connector must not publish old-session
   controls before the claim.
5. The guest driver changes VMID/epoch only upon a distinct restore-rebind
   control carrying the old and new identities and a one-use claim ID. It
   fences ordinary ELF, KILL, status and receipt controls until the guest
   daemon has checked the saved journal and acknowledged the rebind. An
   ordinary second `NODE_ID` remains stale and is rejected.
6. The daemon reconciles each saved delivery and KILL by exact token, source
   ID, payload digest and durable phase. Confirmed revocations remain
   effective; unconfirmed observations retry idempotently. The host daemon
   must persist the new session mapping before acknowledging the guest.
   A version-4 guest outbound record may still be unbound to a VM identity;
   current recovery permits its replay only after an exact host-pending
   response with the matching digest. Host absence is not replay authority.
   The restore handoff must preserve that distinction rather than treating
   every unbound token as a new destination delivery.
   Probe maps and time anchors are rebuilt for the new epoch before tracing
   resumes. A duplicate or old-epoch frame never becomes a new grant.

## Required ordering

Source: pause vCPUs and devices; fence and drain the forwarder and daemon;
persist a prepared ticket and exact journal cut; write and fsync the image;
publish the checkpoint manifest; durably commit or fork the source lease;
then either stop the source or reopen its distinct branch. The existing VMM
snapshot session only fences kernel event ingress and is not the daemon fence.

Destination: verify the manifest, device record and destination attestation;
reserve the ticket; hold every vCPU; restore memory, devices and kernel state;
commit the VMM snapshot session; resume devices while their tracing controls
remain fenced; claim the daemon lease; arm the restricted restore-rebind
control; then release the startup fence. The guest driver and daemon can now
run but must keep tracing stopped while they reconcile the saved journal.
Only the guest's durable ready acknowledgement opens normal controls. On any
error before release, retire the destination connector and leave vCPUs
stopped. A retry must query the durable ticket state rather than infer success
from a lost reply.

## Qualification gates

- Component tests: duplicate claim, different destination claim, daemon
  restart at every durable phase, interrupted manifest publication, failed
  claim ACK, partial guest ELF, pending install/exit and KILL receipts, and
  rebind with malformed or stale identities.
- Disposable matched host/guest VM: stop-and-restore, repeated restore,
  clone/fork, migration, teardown, disconnected collector, and daemon crash
  before/after each acknowledgement. Verify no duplicate probe install,
  no revoked replay, no stale callback, and monotonic restored clock anchors.
- Performance: event loss, VM exits, packet throughput and p99 latency at
  increasing load. The current host has no `/dev/vmm` or `/dev/dttransport`,
  so this live gate cannot be claimed here.

## Nonempty host-ingress restore gate

The experimental tree still refuses a source PREPARE containing accepted
host ingress, and `vm_restore_transaction()` still rejects a nonempty HTX1.
A format-4 private HyperTrace device image can now pass the reserved-ticket
query when its transfer is empty and the local HSL1 source-release witness is
present. A cross-host release witness remains unimplemented. The daemon
already has
pending HTD5 import, fixed HCR2/HCB2 recipients, HLC1 promotion, HLA1
post-rekey activation, and HRO1 result replay. Those components do not by
themselves make the coordinator safe to release a destination vCPU.

The coordinator change to review is precise: source PREPARE must publish only
the exact HTM2/HCP1-bound transfer it rechecks under the handoff lock; after
destination RESERVE and private-image query, IMPORT may stage pending HTD5
before MUTATE; after kernel commit, CLAIM, KILL binding, and saved device
delivery binding, PROMOTE_IMPORT may publish HLC1 before `start_ready()` and
device release. The guest's REKEY_APPLIED control then drives HLA1 while the
VirtIO device holds its rekey/READY fence; failure quarantines that device.
The current coordinator already runs PROMOTE_IMPORT after CLAIM and saved
delivery binding for an empty transfer, before `start_ready()` or vCPU release.
An uncertain promotion reply gets one exact retry; an explicit NAK or
malformed reply does not. Nonempty ingress remains fenced earlier.
The prestart IMPORT client also makes one exact retry for a lost transport or
reply, relying on the daemon's reserved-ticket idempotence. It does not retry
an explicit NAK, malformed ACK, or local validation failure. The coordinator
has the conditional IMPORT step after RESERVE and private-image query, before
MUTATE, with CANCEL on failure. The early nonempty-transfer fence keeps that
step unreachable until the source execution lease is implemented.
Any pre-MUTATE failure must cancel the reservation and its import sidecars.
Any later failure must leave vCPUs stopped and preserve the durable claimed
ticket for explicit recovery.

This ordering still needs a coordinator-level failure-window test, including
lost IMPORT and PROMOTE_IMPORT replies, a daemon restart between pending
publication and HLC1, and a guest rekey that fails before HLA1. The existing
component tests and cross-target builds are not that evidence.
