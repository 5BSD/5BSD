# dtraced and dtracedctl coverage record

Working record for the host daemon (`usr.sbin/dtraced`) and its control tool
(`usr.sbin/dtracedctl`). The coordinator merges it into COVERAGE.5BSD.md.
Offline only: no installed daemon, tracing device, VM or module was operated.
Evidence directories are under `/usr/obj/5BSD-hypertrace-validation/` and
start with `cov-daemon-`.

## Fixes

### Binary program identity rejected by the header decoder (2026-10-21)

Reported by the coordinator from the new libdtrace client test
(`tests/dtraced-client.c`, evidence `dtraced-client-dev4/elf/run.log`).
`dtraced_wire_decode_header()` required the 128-byte `elf.ident` to be a
canonical NUL-terminated string whenever `ident_present == 1`. libdtrace fills
`dp_ident` with `arc4random_buf()` (128 bytes) and `dtrace_send_elf_impl()`
sends those bytes unchanged, so the daemon rejected essentially every
identity-bearing ELF frame from dtrace(1) with EPROTO.

Fix (`usr.sbin/dtraced/dtraced_wire.h`): an identity that is present is
128 opaque bytes; an absent identity must still be all zero. The rest of the
daemon already treats the identity as binary: `dtraced_clientrequest.cc`
copies it into `std::array<char, 128>`, `dtraced_process.cc` transfers it with
fixed-size I/O and selects it with `std::find`/`memcmp`, and the launch result
compares `source_ident` with `memcmp`. No `strcmp`, `strlen`, `%s` logging or
journal string use of the program identity exists (`strcmp` uses in
`dtraced_connection.cc`/`dtraced_clientrequest.cc` concern connection names,
which remain canonical by protocol).

Regression tests:
- `tests/protocol.cc` (native-daemon suite): the old assertions that encoded
  the defect (hidden suffix and all-`x` identity rejected) now require
  acceptance and exact transfer of suffix, NUL-free and arbitrary binary
  identities, exact re-encoding, and continued rejection of a nonzero identity
  when `ident_present == 0`.
- `tests/io-wire.cc` (daemon-extra suite): 4,096 random 128-byte identities
  are accepted and carried exactly; the independent header model no longer
  constrains present identities.
- Both tests fail against the previous decoder (verified by compiling them
  against a scratch copy of the headers with the old check restored).

### Unsigned-char option loop in dtraced main (2026-10-21)

`dtraced.cc` stored getopt(3)'s result in `char ch`. Where `char` is unsigned
(arm64, riscv64 — both HyperTrace targets) `ch` can never equal -1, so the loop
never ends normally: after the last option getopt keeps returning -1, which
falls into the `default` case, prints the version and exits with status 255.
The daemon could therefore never start on those architectures. clang reports
`-Wtautological-constant-out-of-range-compare` for that build. Fix: `int ch`.

Regression: `daemon-extra.py` builds the `daemon-main` suite a second time with
`dtraced.cc` compiled `-funsigned-char`; `daemon-main.py` requires that build
to reach daemon startup (`-d -D ... -t 1` with an injected bind failure exits
1 with "failed to bind") and that `-v` still prints exactly one version.
Verified against the old source: the unsigned build of `char ch` exits 255
after printing the version.

### Log format mismatches; DTRACED_DEBUG build failure (2026-10-21)

The logging functions had no printf format attribute. Adding
`__attribute__((format(printf, 3, 4)))` to `dump_errmsg/warnmsg/logmsg/
debugmsg` (`dtraced_errmsg.h`) exposed four varargs type mismatches
(undefined behaviour; wrong values in diagnostics):
`dtraced_dttransport.cc` short-read size (`int` printed as `%zu`),
`dtraced_clientrequest.cc` unknown message type (`uint64_t` as `%d`),
`dtraced_job.cc` header size constant (`unsigned` as `%zu`), and
`dtraced_state.cc` admission subscription mask (`uint64_t` as `%x`). Each is
fixed with an explicit conversion. Independently of the attribute, the
`MK_DTRACED_DEBUG` configuration (`-DDTRACED_DEBUG`) did not compile:
`dtraced_clientrequest.cc` passed the private `std::string dir::dirpath`
through varargs (access error and non-POD varargs error); it now uses the
public `full_path().c_str()`. All daemon
sources compile without warnings with `-Wall -Wextra -Wformat=2` in the
default, `DTRACED_DEBUG` and `DTRACED_ROBUST` configurations. The attribute
is the regression guard: every maintained daemon test build uses
`-Wall -Werror`, so a new mismatch fails the build.

### Shutdown signals lost when inherited as ignored (2026-10-21)

Found by the process-level `daemon-main` suite when the coverage driver ran
in the background: `statistics-as-root` hung after SIGINT and was killed. Thread
stacks (lldb) showed every daemon thread idle and the signal thread still in
`sigwait()`. A background job of a non-interactive shell inherits SIGINT (and
SIGQUIT) as ignored across exec; the kernel discards a signal whose
disposition is SIG_IGN, so the blocked-signal `sigwait()` design never saw it.
The same applies to SIGTERM under any supervisor that leaves it ignored: the
daemon then cannot be stopped gracefully. Reproduced deterministically with
the pre-fix binary (`preexec_fn` setting SIG_IGN: SIGINT ignored, daemon keeps
running; default disposition: exit 0).

Fix (`dtraced.cc` `setup_sighdlrs`): after blocking SIGINT/SIGTERM in the main
thread (inherited by all later threads), reset both dispositions to SIG_DFL.
Delivery is still only through `sigwait()` in the signal thread.

Regression: `daemon-main.py` scenarios `stop-with-inherited-ignored-SIGINT`
and `-SIGTERM` start the daemon with both signals ignored, wait until the
control socket accepts a connection, deliver the signal and require exit 0
with the socket and pid file removed.

### INFO subscription reply could be stranded (2026-10-21)

Found by the `hostile-peers` process scenario: a client subscribing
`DTD_SUB_INFO` (the client-list reply used by dtrace(1)) intermittently never
received its INFO message. Admission arms EVFILT_WRITE (`enable_rw`) before
`send_info_async()` queues the SEND_INFO job, and releases the admission gate
in between. If the consumer thread handles that first write event before the
job exists, `dispatch_write()` finds nothing to dispatch and disables write
events; `send_info_async()` never re-armed them (every other job producer —
replayed KILLs/cleanups, live KILL/cleanup jobs, ELF notifications — calls
`re_enable_write()` after queueing). Measured with the pre-fix binary: INFO
delivered in 5 of 10 fresh daemon runs. Fix (`dtraced_state.cc`):
`send_info_async()` re-arms the write event after queueing. After the fix:
20 of 20 runs, and the `hostile-peers` scenario requires the exact client list
(the attested forwarder and the INFO consumer itself).

### Replayed ELF frame could precede the registration status (2026-10-21)

Found while extending the host-ingest scenarios. When a HyperTrace consumer
reconnects and re-registers its program (`DTRACED_MSG_CONSUMER_PROGRAM`,
HPI2), registration releases the replay of an upload the previous socket
received but never acknowledged. dtrace(1) (`dtrace_send_message`) then reads
exactly one status byte. Under scheduling pressure a worker could write the
replayed frame (`job::send_elf`, under the client's `output_mtx`) before
`job::read_data` wrote the status: the frame's first byte (msg_type ELF = 1)
reads as an ACK, the stream is misaligned by one byte, and `send_elf` keeps
the output lock while it waits up to its deadline for the consumer's execution
ACK, so the real status byte is held back. Measured with
`tests/registration-order-stress.py` (6 parallel x 15 cycles; same test
binary, only `dtraced_job.o` differs): pre-fix 10/90 and 2/90 cycles
frame-first; fixed 0/90 and 0/90 (evidence
`/usr/obj/5BSD-hypertrace-validation/cov-daemon-regorder-20261021`).
Fix (`dtraced_job.cc`, `job::read_data`): for `DTRACED_MSG_CONSUMER_PROGRAM`
the request is handled and its one-byte status written while holding the
client's `output_mtx`, so no job frame can precede the status. Lock order
matches admission (output stream before `sockfdsmtx`/journal/job-list locks);
registration itself takes no output lock. Regression: the stress driver runs
in `daemon-extra.py` after `daemon-main`; the idle-daemon scenario
`registration-ack-precedes-replay` checks status, then frame identity and
payload. A deterministic shim could not be built from existing call
boundaries (the release happens in more than one path), so the regression
is statistical; the coordinator's dtraced-client run exercises the real
client side.

### Base-program routing: guests never received it, host link result dropped (2026-10-21)

Investigated for the dtrace -E TYPECAST report. Contract (dtrace.c): the
host consumer sends its unlinked base program, bound to its source ID, to
location "base"; dtraced copies it to outbound for the guests and launches
`/usr/sbin/dtrace -q -Y <base>,host` (`process_base`), whose linked result
comes back to "inbound" (`process_elf_hypertrace`, host=1). Guests return
their linked programs as identified uploads. Registered host consumers
receive only inbound content (`process_inbound` -> `queue_elfwrite_batch`
with DTRACED_KIND_CONSUMER); the base and outbound directories are never
queued to consumers, so the daemon does not hand the base program to a host
consumer. Two defects were found on this path:

1. `dir::copy_data()` published the base copy to outbound as an anonymous
   spool, dropping the source lineage. A host forwarder accepts only
   `elf.<program>.<source>` spools (`job::send_elf`, `spool_program_id`), so
   the send failed with EPROTO and the job failure retired the guest's
   ELFWRITE channel: guests never received the base program. Fix: copy_data
   keeps the source suffix of a source-bound spool (the copy gets a fresh
   program ID, as any outbound publication does); `process_base` no longer
   publishes a sourceless base to guests (logged) and still launches the
   host link.
2. The host link result (`dtrace_send_elf(..., "inbound", 0)`: source ID set,
   program ID zero) was stored as `elf.<nonce>.<source>`, the name of a
   journaled guest upload; the host inbound watcher found no accepted record
   and dropped it silently, so the host consumer never received it. Fix
   (`handle_elfmsg`): on the host, a consumer's inbound program without a
   program ID is published without the lineage suffix and is delivered to
   registered consumers.

Evidence (`/usr/obj/5BSD-hypertrace-validation/cov-daemon-routing-20261021`,
the same probe against pre-fix and fixed builds): pre-fix, a source-bound
base gave the guest channel EOF and the consumer nothing; fixed, the guest
receives the exact base (SHA-256 prefix plus bytes, source lineage, fresh
program ID) and the consumer receives exactly the linked program. Regression
scenario `base-program-routing` (daemon-main.py; the shim's HT_EXEC_LOG and
HT_EXEC_FAKE record the launched command instead of executing it) checks the
guest frame, the two host `-Y ...,host` launches, that no base program
reaches the consumer, that the host and guest linked programs both do, and
that the guest channel stays admitted after a sourceless base.

Consequence for the TYPECAST report: a host consumer can only have received
that program from an inbound sender, i.e. the output of the host
`dtrace -q -Y <base>,host` instance (dtrace.c `process_elf_hypertrace`, which
runs `link_elf()` and `hypertrace_link()` and sends `dcp->dc_prog` to
"inbound") or of a guest's `dtrace -Y`. Before fix 2 the host instance's
result could not reach the consumer at all when it carried a source ID.

Observation, no change: when the host `dtrace -Y` launch fails (for example
the executable is missing), `process_base` returns false, the base watcher
reports "failed to process new files" and the daemon broadcasts shutdown. A
transient launch failure therefore stops the whole host daemon; whether that
fail-stop is intended is a decision for the owner.

### Lost deliveries F1-F3 (2026-10-21)

Found by the live-sweep fault mode, fixed per the coordinator's decision.
The protocol meaning of every ACK is unchanged: a publication ACK still
means the spool is durable, a guest upload ACK still means the upload is
durably accepted; what changed is that the daemon now always completes the
delivery it has accepted.

- F1, host outbound spool lost when its first send failed before the
  pending record existed: the spool was already memorized, and a restart
  memorizes every existing spool, so nothing resent it. Fix
  (dtraced_directory.cc `record_host_outbound_intent`, called from
  `queue_elfwrite_batch`): for each attested host forwarder the pending HTD4
  record (fresh delivery ID, bare-ELF digest and VM target taken from the
  spool exactly as `job::send_elf()` derives them) is made durable before
  the spool is memorized and the job queued; the job carries it
  (`notify_elfwrite_job::recorded`) and `send_elf()` sends with that
  identity instead of creating a new record (it verifies session, peer, VM
  lifetime, digest and that the record is still pending; an accepted
  record is not sent again). At host start
  `forget_unrecorded_host_spools()` leaves a spool that no record names
  unmemorized, because such a spool was never queued to anyone; the next
  forwarder receives it, exactly as a spool published while no forwarder was
  connected.
- F2, pending record whose frame write failed was never resent: on every
  host ELFWRITE forwarder admission `queue_pending_host_outbound()` queues
  this channel's pending HTD4 records (same bhyve session, peer and VM
  lifetime; source not revoked; spool present and matching the recorded
  digest, so a missing or replaced spool cannot cause a reconnect loop)
  with their recorded delivery IDs. Not duplicated: the guest daemon treats
  an exact token retry as the same delivery (dtraced_dttransport.cc: same
  program, same token, existing spool, so no second launch and no uninstall
  observation), and the fault oracle checks that no program reaches a VM
  under two tokens.
- F3, ACKed guest upload delivered to nobody when its first inbound scan
  failed before the cohort was recorded (the scan failure shuts the daemon
  down; the restart memorized the spool). Chosen fix: restart recovery,
  not a later ACK (delaying the upload ACK until a consumer cohort exists
  would change its meaning from "durably accepted" to "delivered", and an
  upload with no registered consumer could never be acknowledged). At host
  start `forget_unassigned_ingress()` leaves the spool of an accepted
  ingress with no cohort and no consumer receipt unmemorized; the watcher
  then forms the cohort from the consumers registered when it rescans
  (consumer registration requests that rescan), which is exactly the
  in-process rule for an upload accepted while no consumer was registered.
  An ingress with a cohort or any receipt is untouched, so no consumer is
  assigned an upload twice.
- Guest variant of F1 (found when the guest flow joined the fault sweep):
  the guest daemon's outbound spool (its dtrace -Y result for the host) was
  likewise memorized before its scope-2 token existed. The watcher now
  records that token for the transport forwarder in the current VM lifetime
  (identity queried before sockfdsmtx is taken, only when a forwarder is
  connected) and queues the job as an exact replay (`ne.replay`), which
  `send_elf()` already verifies; startup recovery settles or replays a
  pending token through the host ingest status as before. If the token
  write fails, the watcher checks whether it was published anyway and
  otherwise leaves recording to `send_elf()` (the previous behaviour)
  instead of shutting down, so a single failure no longer strands the
  spool. Residual: guest outbound records are deleted once the host
  accepts a program, so a crash between the publication and the watcher's
  scan still leaves an unshipped spool memorized after restart.
- Refused publications: a publication can fail after its spool became
  visible (e.g. fsync after the link); the publisher gets a NAK and the
  spool is removed. A token recorded for it in the meantime is withdrawn
  (`dir::withdraw_pending_delivery`, only while pending and only when the
  spool is absent) by `send_elf()` and by host admission recovery, instead
  of failing the channel or leaving a stale pending record.
- Fresh-session contract: recovery is keyed to the exact VM lifetime
  (vmid and epoch) and bhyve process (session, uid, pid); a fresh session
  has a new epoch and never receives a prior lifetime's pending work.
- Residual (documented, not fixed): with several forwarders connected, a
  failure between two of the per-forwarder intent records leaves the spool
  named by the first record, so a restart memorizes it and the forwarders
  without a record do not receive it. The single-VM sweeps cannot reach
  this; a per-spool recipient set (like the inbound cohort) would close it.

Regressions (live-sweep fault mode, strict oracle, evidence under
cov-daemon-scratch-20261021): outbound-delivery PUBLISH, entries send_elf
and record_delivery: 137 of 142 points fail on the previous binary
(`reg-old-out`), 0 of 107 on the fixed one (a later 517-point run over
PUBLISH/KILL/CLEANUP had 5 CLEANUP failures, all the harness channel-layout
race described above, since corrected); host-ingest, entries list_consumer_receipts and
queue_recovered_consumer: 108 of 140 fail before (`reg-old-in`), 0 of 155
after (`reg-new-in`). The full sweeps run in every coverage-daemon run.

### Guest daemon shutdown waited out a 10 s idle read (2026-10-22)

`write_dttransport()` (dtraced_dttransport.cc), the guest's transport
writer, read the next frame header from its daemon connection with a 10 s
deadline and checked the shutdown flag only after the deadline expired, so
an idle guest daemon took up to 10 s to exit after SIGTERM (measured
9.5-10 s). It now waits for readability in 1 s poll slices, checking the
flag between them; a frame, once started, keeps the full 10 s deadline.
Regression: daemon-main scenario `minion-prompt-shutdown` (transport
answering, writer connected, exit within 3 s of SIGTERM): 9.51 s and failed
on the previous binary (cov-daemon-scratch-20261021/reg-stop-x42), 0.45 s
on the fixed one (reg-stop-x43). Found because every guest sweep point paid
the 10 s on each stop.

### Protocol tightening: forwarder READDATA with CLEANUP refused (2026-10-22)

A forwarder hello may no longer combine READDATA with CLEANUP (READDATA with
ELFWRITE was already refused). On such a channel the daemon waits for the
peer's 8-byte ACK of a CLEANUP frame while the READ_DATA job may consume
those bytes as a request header, desynchronizing and dropping the channel;
the live sweeps hit exactly this with a wrongly laid out harness. bhyve is
the only forwarder and never combines them (`ht_connect`: rx =
ELFWRITE|KILL|CLEANUP|ADMISSION_ACK|REPLAY_MANIFEST, wx =
READDATA|ADMISSION_ACK, report channels READDATA), so accepting the layout
was unused attack surface (coordinator decision). `valid_initmsg()`
(dtraced_socket.h) refuses it; the refusal now logs `refused client hello
(kind, subscriptions)` with EPROTO instead of a stale errno. READDATA with
KILL stays accepted: the daemon reads no ACK for a KILL frame.
Regression: daemon-main scenario `forwarder-channel-layouts` (refused:
READDATA|CLEANUP with and without ADMISSION_ACK, with the log line; admitted:
bhyve's rx, wx and report layouts). Fails on the previous binary
(cov-daemon-scratch-20261021/reg-layout-x35: the combination is admitted),
passes on the fixed one (reg-layout-x37). The `cleanup-delivery-and-replay`
scenario now uses bhyve's layout (CLEANUP channel for frames and ACKs,
READDATA channel for CLEANUP_APPLIED).

### Refused CLEANUP replayed after restart (2026-10-21)

`dir::record_cleanup_pending()` (dtraced_directory.cc) removed the new
pending record when the record's own fsync failed, but not when the
following close() or the directory fsync failed. The caller then refused
the CLEANUP request with a NAK while the `.cleanup.*.p` record stayed; a
restarted daemon's recovery replayed it, so the refused cleanup was
applied, and the requester's retry applied a second one. Found by the
live-sweep fault mode (outbound-delivery CLEANUP step, failure at the
29th/30th call inside record_cleanup_pending). Fix: every failure after
the record was created removes it again (then syncs the directory) before
reporting. Regression: journal-faults
`test_cleanup_pending_refusal_not_durable` injects a failure at every
system call of the operation and requires that a refused operation leaves
no pending record for a restarted reader; it fails on the previous code at
the close() call ("refused at call 15 (__wrap_close) but left a pending
record") and passes with the fix.

### Removed: NAK after a truncated request body (2026-10-21, decision 3)

`job::read_data()` sent a NAK when the request body could not be received,
but `client_fd::recv()` has already shut the socket down ("a partial frame
must never be reused"), so the NAK could never arrive. The attempt is
removed; the behaviour stays fail closed (the peer sees EOF, the connection
is retired). `hostile-peers` checks it: a body that stalls is abandoned at the
10 s frame deadline with EOF and no status byte.

## Trace continuity (HT-C): disabled future feature, excluded from the target (2026-10-21)

Classification. dtraced's handoff/continuity code is the same concept the
fresh-session contract disables: trace continuity across VM restore or
migration. It serves the bhyve snapshot protocol (`usr.sbin/bhyve/hypertrace.c`
`hypertrace_handoff_*`, called from `snapshot.c`), whose checkpoint side
hard-codes `handoff_enabled = false` and whose restore side never sets
`handoff_required`. It is not daemon-incarnation handoff on one host: the
daemon's own restart recovery (populate_existing, delivery/kill/cleanup/
consumer-receipt recovery, fresh-session stop recovery, guest rekey) is
separate code and stays in the target.

Per the user's decision the continuity code stays in place, is marked, keeps
its behaviour and is excluded from the 97% target. Comment-only markers were
added (verified: removing the marker lines reproduces the previous sources
byte for byte):
- region `HT-C BEGIN: trace continuity across VM restore or migration ...` /
  `HT-C END` around runs of continuity-only functions (handoff phases,
  source gate/drain, export/import (HTX1/HTM1/HTM2/HJB1/HJR1/HTB1/HTL1/HLC1/
  HLA1), signed source release (HSL1/HSA1), rebind (HRI1/HRP1/HRC1),
  mutation reset, imported recipients (HCR2), the handoff request handlers,
  their wire codecs and the three continuity-only headers);
- block `HT-C BEGIN: disabled trace continuity.` / `HT-C END` around the
  body of a branch inside a live function that runs only for continuity state
  (HTD5 records, `replay_host` journal replays, release-recovery and
  source-release peers, handoff-deferred jobs, handoff-phase lineage).

Method: `classify` (a call-graph pass over the function list from llvm-cov:
a function is continuity when its name belongs to the handoff domain or all
its callers are continuity functions), then manual review of every
continuity function with a live caller. Corrections: `dtraced_io_transfer`,
`socket_transfer`, `handoff_process_lock`, `handoff_publish_at` (used by
fresh-session stop and consumer receipts), `source_gate_query_fd` and
`source_gate_for_epoch_at` (fresh-session gate) and the drain-step response
(used by SESSION_STOP) are live; `handle_release_recovery`, the transfer and
release responses and `request_consumer_drain` are continuity.

Continuity readers called from live paths (flagged for the owner): the live
code still calls, on every relevant operation, continuity readers that in
production only ever see an empty continuity journal: `handoff_state_at`,
`handoff_source_state_at`, `handoff_release_authority_locked`,
`source_journal_ready_raw_status_locked`, `source_journal_stage_status_locked`,
`source_handoff_for_vm`, `with_source_handoff_phase`, `bound_handoff_status`,
`queue_claimed_source_journal_replays`, and at every host start the
`populate_existing` audits (`handoff_mutating_resets_recover_locked`,
`handoff_rebind_commits_recover_locked`, `handoff_execution_starts_audit_locked`,
`handoff_rebinds_audit_locked`, `handoff_rebind_plans_audit_locked`,
`source_journal_stages_audit_locked`, `source_journal_ready_audit_locked`,
`imported_attestations_audit_locked`). They are inside HT-C regions (their
purpose is continuity state); their call sites stay live.

Attack surface (decision for the owner): the feature is disabled on the
bhyve side only. dtraced still accepts and serves every continuity request
(DTRACED_MSG_HANDOFF and its 29 operations, HANDOFF_IMPORT,
HANDOFF_RELEASE_IMPORT, HANDOFF_DELIVERY/KILL/CLEANUP and their bind forms,
RELEASE_RECOVERY peers) from any attested forwarder. Gating these in the
daemon would change behaviour and was not done.

Measured split (physical lines inside markers): directory.cc 13,374 of
21,6xx; clientrequest.cc 1,164; transfer_wire.h 524; wire.h 206;
state.cc 203; job.cc 142; release_attestation.h 96; connection.cc 93;
rebind_wire.h 82; clientrequest.h 9; release_keys.h 3. The exact ranges
are listed in the waiver table below (generated from the markers).

The coverage driver reports a `daemon/live` configuration: functions that
start inside an HT-C region are excluded with llvm-cov `-name-allowlist`
(exact llvm-cov accounting), and the lines and branch outcomes inside HT-C
blocks are subtracted from their live functions.

Already built before the decision and kept as tests (continuity only, not
counted): `tests/handoff-peers.py` (4 scenarios across daemon restarts and
two hosts with Ed25519 release keys; peers speak the bhyve protocol;
emulated VMM/HyperTrace kernel in the daemon-main shim) and
`tests/handoff-sweep.py` (snapshot-based fault/corruption/refusal sweeps;
fault mode, all five flows: 4,948 injected points, 0 failures, evidence
`cov-daemon-scratch-20261021/sw3`, `sw4`, `sw1`). Findings from that work:
PREPARE refuses every nonempty source (EOPNOTSUPP by design), a foreign
transfer carrying host ingress is refused at MUTATE, and therefore the
host-ingress import/promotion code is unreachable through the protocol in
this build (only a foreign journal-only transfer can be imported).

## Live code: the 97% target (2026-10-21)

The target applies to live daemon code: everything outside HT-C markers,
including same-host restart recovery (populate_existing, delivery, KILL,
cleanup, consumer-receipt, collector-owner and fresh-session recovery, guest
rekey) and the live fences that only read continuity journals. Reported by
coverage-daemon.py as the `daemon/live` configuration (method in the HT-C
section).

### Process-level drivers for live work (tests/live-sweep.py)

Peers speak the real protocols (tests/htpeerlib.py): a guest VM's channels
(an ELFWRITE writer that queues and acknowledges programs; a
READDATA|KILL|CLEANUP listener that reports KILLs applied and acknowledges
and applies cleanups from a separate thread, as bhyve does), a root
control consumer (publish, KILL, cleanup, statistics), a registered dtrace(1)
host consumer (acknowledgment, execution report, drain and stop proofs,
derived-program publication with an independent HDERIV1 encoder) and, for
guest daemons, host-side transport records injected into the shim's
scripted driver (HT_DTT_INJECT). Flows: outbound-delivery, host-ingest,
derived, fresh-session, guest. Every step runs in a new daemon incarnation
on a snapshot of the previous step's journals and emulated kernel state.

Modes (each with its own oracle, stated in the driver):
- fault: one injected failure (N-th file-system call, or N-th allocation)
  inside one daemon entry point reached by the step (request handler,
  job senders, directory watchers, and 38 journal operations called across
  objects); then a restarted incarnation with reconnected peers and
  real-peer retries must converge to the reference reply and the reference
  canonical journal state.
- corrupt: every journal and spool of every snapshot damaged ten ways; the
  daemon refuses to start, or the step fails, or returns exactly the
  reference reply; no sanitizer report.
- hostile: single-field mutations of every live request (forwarder
  observations, KILL_APPLIED, CLEANUP_APPLIED, guest uploads, statuses,
  publications, KILL, cleanup, consumer registration, execution reports,
  session stop/release and stop proofs) and of crafted HANDOFF requests (all
  message types, 14 operations, import and release-import frames): a refused
  request leaves the journal tree byte-for-byte unchanged.
- startup / guest-startup: the N-th file-system call, allocation or thread
  creation inside daemon startup (state::initialize) or shutdown (finalize),
  host and guest (clean, rekeyed, fresh-session, pending cleanup, guest
  journals restarted under a rekeyed identity): clean refusal or start, and
  the next clean incarnation reaches the same journal state as an
  undisturbed restart.
- callfault: the N-th call of kqueue, kevent, listen, socket, accept4,
  fcntl, pdwait, pdkill, pdfork, pipe2, socketpair, setsockopt or poll in
  any daemon thread while an incarnation starts, admits peers and serves;
  next clean incarnation as above.

Findings from the fault mode, all fixed (2026-10-21, coordinator decision:
lost deliveries are correctness bugs); see "Lost deliveries F1-F3" under
Fixes. The fault-mode oracle no longer allows any of them: every point must
converge to the reference reply and journal state, and no program may
reach a VM under two delivery IDs (the guest ledger is kept across daemon
incarnations). The only remaining allowance is R1 (below).
- By design, not a finding (R1): when the consumer's registration is
  refused, an upload accepted meanwhile may have no recipient in that
  incarnation; dtrace(1) exits on a refused registration. (With the F3 fix
  the restarted daemon delivers it to the next registered consumer, so R1
  normally converges to the reference.)
- A failed shutdown step (finalize, e.g. close EIO) is reported through
  exit status 1; the next start is clean.

Emulation added for the guest flow (daemon-main shim, HT_DTT_HOST_DB): the
emulated host remembers the guest uploads it accepted and the programs it
delivered, and answers the guest's DTT_INGRESS_STATUS (accepted or absent)
and DTT_STATUS (accepted with replay, or unavailable) queries from that
file, so guest restart recovery runs end to end. The one guest point
first reported open (HOST_ELF, failure at the fsync inside
record_delivery: the recovered token stays pending) is designed behaviour,
classified as R2: a recovered guest delivery is relaunched only for a
waiting dtrace(1) -N consumer, because the replayed launch must be
confirmed by that consumer's launch report (launch_program:
`require_report && !has_identifiers` -> EAGAIN -> request_reprocess). The
`guest` flow has no such consumer; the `guest-installed` flow repeats the
same points with one (HT_EXEC_FAKE=report) and converges to the reference
at every point (362 points, 0 failures).

Further guest emulation (daemon-main shim) for the live target:
HT_EXEC_FAKE=report makes the fake tracing child behave like dtrace(1) -Y
-N for the launch report: it closes its close-on-exec descriptors (as exec
does, so the daemon's exec-status pipe reaches EOF), reads the identifier
list, reports the first one installed and keeps running for
HT_EXEC_FAKE_HOLD_MS; the emulated host also answers the guest's journal
rekey receipt queries (DTT_REKEY_DELIVERY/INGRESS/KILL) from HT_DTT_HOST_DB.
New flows: `guest-installed` (an installed child reported over the
transport, its exit, a KILL of a running child) and `guest-rekey` (a
restore to a new VM lifetime: the guest daemon rewrites its journals under
the host's receipts, then serves the new lifetime). The process-wide call
faults also cover send, recv, recvmsg, shutdown and getsockopt.
journal-faults gained seven operations (consumer cohort, receipt
pending/processed/executed, cohort recovery, pending-token withdrawal,
guest delivery rekey): 27 operations, 513 injection points.

Harness models corrected along the way: the guest connector now uses
bhyve's channel layout exactly (`ht_connect` in usr.sbin/bhyve/hypertrace.c:
rx = ELFWRITE|KILL|CLEANUP|ADMISSION_ACK|REPLAY_MANIFEST receives ELF, KILL
and CLEANUP frames; wx = READDATA|ADMISSION_ACK carries uploads). An earlier
harness layout subscribed one channel to READDATA and CLEANUP; there the
daemon's READ_DATA job can consume the 8-byte cleanup ACK as a frame header
("invalid frame size") and drop the channel. That was the source of the
load-only CLEANUP failures; bhyve never subscribes that combination (the
daemon accepts it; noted for the owner, not changed). The model also re-reports
KILL/CLEANUP completions the daemon did not acknowledge; the consumer
retries its execution report from a separate thread until accepted, as
`report_identified_execution()` in dtrace.c does (60 s deadline; 15 s in
the sweeps).
- A failed shutdown step (finalize, e.g. close EIO) is reported through
  exit status 1; the next start is clean.

## Measurement method (checkpoint 2026-10-21)

Driver: `contrib/hypertrace/tests/coverage-daemon.py OUTPUT` (new directory
`/usr/obj/5BSD-hypertrace-validation/cov-daemon-*`). It runs the unchanged
`native-daemon.py` suites, the new `daemon-extra.py` suites (unmodified daemon
objects, `--wrap` boundaries only), and the dtracedctl make target with
`control-cli-offline.py` (plus `control-cli-extra.py` from round 3 on). It
records source/driver/test hashes, refuses a run whose production sources
change mid-run, and requires clean `llvm-profdata merge` logs.

Denominator corrections found while building the baseline:
- llvm-cov silently drops a function whose name occurs in the profile with a
  different structural hash. Test executables all define `main` (and several
  `__wrap_*`), so the never-executed production `main` vanished from
  `dtraced.cc` (57 instead of 193 lines, 6 instead of 72 branch outcomes) in
  every earlier daemon export. The driver now audits each measured export
  against an `--empty-profile` export of the same objects and restores dropped
  mappings as uncovered. The "29/30 mismatched functions" warnings recorded in
  COVERAGE.5BSD.md are these harness-name collisions plus that `main`; with the
  process-level suite executing production `main`, only harness symbols remain
  (listed by `llvm-profdata show` in each run; none is a production function).
- Unused inline header functions get a reduced "unused" mapping without
  branch regions. A header-denominator object (all daemon headers compiled with
  `-femit-all-decls`) and the executed suite binaries are added to the export,
  so header branch denominators are complete (e.g. `dtraced_wire.h` 462–466
  instead of 408 outcomes; `dtraced_io.h` 176 instead of 144).
- `source-journal-wire.cc` includes the unmodified `dtraced_directory.cc` to
  reach private readers; its copies are credited (same source, same flags).
- Production configuration: only `dtraced_process.cc` tests
  `DTRACED_NATIVE_TEST`; its production row comes from production-flag objects
  (no sanitizers, Makefile defines), all other rows are identical by
  construction. Headers never test the macro (asserted by the driver).
- Files without executable code stay listed as UNMAPPED with physical line
  counts: `_dtraced_connection.h`, `dtraced_child_ledger.h`,
  `dtraced_dttransport.h`, `dtraced_process.h` (declarations only) and
  `dtraced_id.cc` (empty, still in the Makefile SRCS).

| Run | Component | Lines | Branches | Functions |
| --- | --- | ---: | ---: | ---: |
| `cov-daemon-baseline-20261021` (existing suites, current sources) | dtraced, native-test | 22,684/30,331 (74.79%) | 12,794/21,902 (58.41%) | 738/795 (92.83%) |
| same | dtraced, production rule | 22,687/30,334 (74.79%) | 12,794/21,902 (58.41%) | 738/795 (92.83%) |
| same | dtracedctl.c | 235/258 (91.09%) | 117/132 (88.64%) | 7/7 |
| `cov-daemon-round2-20261021` | dtraced, native-test | 24,649/30,335 (81.26%) | 14,317/21,902 (65.37%) | 775/795 (97.48%) |
| same | dtraced, production rule | 24,652/30,338 (81.26%) | 14,317/21,902 (65.37%) | 775/795 (97.48%) |
| same | dtracedctl.c | 235/258 (91.09%) | 117/132 (88.64%) | 7/7 |
| `cov-daemon-round3-20261021` | dtraced, native-test | 24,837/30,335 (81.88%) | 14,565/21,902 (66.50%) | 776/795 (97.61%) |
| same | dtracedctl.c | 243/258 (94.19%) | 126/132 (95.45%) | 7/7 |
| `cov-daemon-round4-20261021` | dtraced, native-test | 24,965/30,335 (82.30%) | 14,709/21,902 (67.16%) | 776/795 (97.61%) |
| **`cov-daemon-final-20261021`** (final sources, incl. registration fix) | dtraced, native-test | 24,970/30,349 (82.28%) | 14,712/21,910 (67.15%) | 776/795 (97.61%) |
| same | dtraced, production rule | 24,973/30,352 (82.28%) | 14,712/21,910 (67.15%) | 776/795 (97.61%) |
| same | dtracedctl.c | 243/258 (94.19%) | 126/132 (95.45%) | 7/7 (100%) |
| **`cov-daemon-final2-20261021`** (same sources; driver also merges the stray `default.profraw` of native-daemon's process-launch child) | dtraced, native-test | 24,977/30,349 (82.30%) | 14,718/21,910 (67.17%) | 776/795 (97.61%) |
| same | dtraced, production rule | 24,980/30,352 (82.30%) | 14,718/21,910 (67.17%) | 776/795 (97.61%) |
| same | dtracedctl.c | 243/258 (94.19%) | 126/132 (95.45%) | 7/7 (100%) |

The final denominator grows by 14 lines/8 branch outcomes because of the
registration-ordering fix in `dtraced_job.cc`. Per-file rows for every run are
in `<run>.log` and `<run>/summary.json`.

Target status: the 97% function target is met for dtraced; the 97% line and
branch targets are not met for dtraced (`dtraced_directory.cc` alone is 18,992
of 30,349 lines at 79.4% / 63.1% branches, mostly continuity/handoff and
fresh-stop recovery code) nor for dtracedctl lines/branches (remaining lines
are unreachable by construction, below). Files at or above 97% lines:
`dtraced_wire.h` 98.5% (96.5% branches), `dtraced_errmsg.cc`, and the small
fully covered headers.

Remaining gaps by kind (final2 run; per-file rows in `cov-daemon-final2-20261021.log`):
- Dead code (no callers in the tree): `client_fd::re_enable_rw`,
  `disable_read`/`disable_write`/`disable_rw` members, `respond`, `send_ack`,
  `operator std::string`, `enable_fd`, `reenable_fd`, `disable_rw(int, int)`
  (`dtraced_connection.cc`, 10 of its 32 functions); `waitpid_timeout`
  (`dtraced_misc.cc`); `job::ident()`; `dtraced_id.cc` is empty but in SRCS.
- Unreachable by construction: dtracedctl `str == NULL`, `sun_path` overflow,
  `send_request` count/length limits (callers bound them), getopt case 0 and
  final default; `dtraced_errmsg.cc` `if (msg)` false arm; dttransport
  `sun_path` overflow, `valid_initmsg` failure after validation, SHA256 NULL;
  `dtraced_io.h` `read_size > SIZE_MAX` on LP64.
- Not reached offline: remaining `dtraced_directory.cc` continuity/handoff
  import/export, fresh-stop and rebind recovery branches (each needs a
  multi-incarnation handoff peer); `dtraced_job.cc` imported-recipient and
  lost-ACK reconciliation branches; `dtraced_clientrequest.cc` transfer and
  drain-step responders.

(The baseline summary's own production row, 22,582/30,334, used an earlier
stricter rule that excluded included-source copies; the row above recomputes
it with the final rule from the same exports.)

## Tests added (all offline; real daemon objects or the real executables)

Driver `tests/daemon-extra.py` links each suite against the unmodified
sanitized daemon objects (`-DDTRACED_NATIVE_TEST`, ASan/UBSan) with only the
`--wrap` boundaries listed in its table; `daemon-main` links `dtraced.o`
itself and is run by `daemon-main.py` as a process.

| Suite | Subject | Oracle | Checks |
| --- | --- | --- | ---: |
| `io-wire` | `dtraced_io.h` deadlines, framed I/O, connect, fd passing; every `dtraced_wire.h` codec | 128-bit clock arithmetic; scripted syscall results with exact bytes/errno/call counts; independent byte-layout encoders and acceptance predicates; single-byte mutation sweeps; 4,096 random binary program identities | 326,504 |
| `dtt-listen` | `listen_dttransport` reader: transport faults, guest ELF assembly/publication, host ELF receipts, kills, VM identity, cleanup/rekey/session-stop re-exec (forked children) | journal read-back, SHA-256 of published spool, decoded transport records, re-exec exit status 73 | 686 |
| `dtt-rekey` | `query_guest_rekey_receipt`, `recover_guest_rekey` with real inbound/outbound journals | query fields vs journal records; journals name only the new (success) or only the old (refusal) incarnation; deadline/retry/commit paths | 613 |
| `dtt-write` | `write_dttransport`, `setup_connection` with `listen_dttransport` alongside | byte-exact fragment reassembly and bookkeeping; ACK only after `DTT_HOST_ELF`; every malformed frame/fault stops before device writes | 513 |
| `dtt-status` | recovered-delivery status, outbound ingest status, startup recovery, kill-ACK failures | exact durable phase per reply; query decoding; reader-only clock skew for lost replies and rescans | 455 |
| `dtt-quiesce` | `quiesce_guest_tracing` with real pdfork children | all children dead and reaped; none signalled when any lacks a descriptor; exact errno per fault | 69 |
| `journal-faults` | 20 journal operations (delivery phases, retire, kill, kill-applied, revoke, cleanup phases, identified spool, fresh-stop/handoff publication) | one injected failure at every reachable fs call (271 points): restart view readable after `populate_existing()`, effect all-or-nothing, retry converges | 3,212 |
| `journal-names` | name-encoded `.kill.`/`.killack.`/`.cleanup.`/`.revoke.` journals | independent name builder; exact listing; every malformed name, non-empty or non-regular record, conflicting phase → EPROTO, never a partial list | 239 |
| `launch-child` | `launch_program()` with real pdfork children (`/usr/bin/true`, failing exec) | exactly the launched pid registered with its descriptor/source; child errno on exec failure; refusals never fork or ledger | 28 |
| `journal-corruption` | `list_deliveries`/`delivery_status` on independently encoded HTD2–HTD5 journals | exact fields for valid records; documented rule violations refused; every byte flip, truncation, name damage, duplicate phase and non-regular entry fails closed | 5,898 |
| `child-ledger-recovery` | guest child ledger record/retire/recover with real children | killed iff same-boot birth identity matches; reused PID/other boot never signalled; malformed ledgers EPROTO with children alive | 175 |
| `client-fd` | consumer stop/drain challenges, response encoders, forwarder attestation gate | production codecs decode every frame; per-field reply mismatch → EPROTO + stream shutdown; refusal/retirement errnos | 278 |
| `collector-evidence` | collector handle/pin/exit/reaper evidence helpers | independent decision table for all reaper flag combinations; never treat failure or mismatch as exit proof; no fd leaks | 80 |
| `header-props` | collector owner registry, ELF fragment assembly, derived-program identity, HSA1 attestations | 20,000-op registry model with fd accounting and batch fairness; 20,000-trial assembly model; independent HDERIV1 preimage; Ed25519 mutation sweep | 199,187 |
| `daemon-main` (process) | actual `main()`/startup/shutdown, overlord and minion (scripted transport), release keys, admission, revocation, cleanup, outbound delivery lifecycle, guest publication to host, journal recovery, hostile peers | exit status/diagnostics, pid file and socket lifecycle, decoded protocol frames, journal files on disk, statistics replies, delivery/ingress status replies (phase, revoked, replay grant, SHA-256 digest), lost-ACK ingest replay, 64-client admission storm, shutdown under connection churn | 77 scenarios |
| `registration-order-stress` (process) | consumer re-registration vs. replay release | status byte before replayed ELF frame (dtrace(1) one-byte read), 6 x 15 cycles | 90 cycles |
| `control-cli-extra` (process) | dtracedctl option ordering, positional lists, calloc failure, connect progress states, request clock failure | exit status, diagnostics, exact request frame, stdout | 12 cases |

Also collected by the driver: the existing `transfer-properties`,
`rebind-properties`, `protocol-fuzz` and `discovery-helpers` suites (daemon
header subjects), and the updated `protocol.cc` (identity regression).

### Fixed: double-linked records after a failed temporary unlink (2026-10-21, decision 4)

`journal-faults` found that when `unlinkat()` of a publication temporary
failed after `linkat()` had given its inode the final name (for example
`handoff_publish_at` under `begin_fresh_session_stop`), the authoritative
record kept two links. Readers that require a private single-link file
(`fresh_stop_read_at` and the other `st_nlink != 1` checks) then refused it
with EPROTO, so a retry in the same daemon process failed until the next
start, where `populate_existing()` removes stale temporaries. Fix
(`dtraced_directory.cc`): a new helper `unlink_published_temporary_at()`
retries the removal in place (up to four attempts; ENOENT means already
removed) at every link-then-unlink publication site (`publish_spool` link
path, `handoff_publish_at`, the two consumer-receipt publishers, the derived
claim publisher and the rebind/source-journal publisher). Regression
(`journal-faults`, `test_temporary_unlink_retry`): with 1, 2 or 3 injected
EIO failures of the temporary's removal, `begin_fresh_session_stop` succeeds
in the same process, exactly failures+1 removals were attempted, no
temporary remains, the stop record reads back and an exact retry succeeds; a
persistent failure is reported (EIO after 4 attempts, the temporary remains)
and a restarted directory still recovers. Against the pre-fix directory
object the first check fails (errno 5).

### Removed: superseded connection helpers and empty source (2026-10-21, decision 2)

The coordinator verified each against upstream (cadets hypertrace/main):
5BSD replaced them with direct `kevent()` registration in the client and
state code, encoded ACK records, and the child ledger/reaper. Before each
removal the whole tree (usr.sbin/dtraced, usr.sbin/dtracedctl,
contrib/hypertrace/tests, cddl, lib, sys, tools) was searched for callers.

Removed (no caller anywhere): `client_fd::re_enable_rw`,
`client_fd::disable_read`, `disable_write`, `disable_rw` (members),
`enable_fd`, `reenable_fd`, `disable_rw(int, int)`, the free `send_ack(int)`
declaration (never defined), `job::ident()`, and `dtraced_id.cc` (empty) with
its Makefile SRCS entry (`dtraced_id.h` stays: `dtraced_genid()` is used).
`disable_fd(int, int, int)` stays (used by `state` at two sites).

Kept because something still references them (reported to the
coordinator): `client_fd::respond` and the member `send_ack` (tests/connection.cc
lines 66, 70, 83), `client_fd::operator std::string` (tests/connection.cc
line 45), `waitpid_timeout` (tests/child-ownership.cc lines 30, 35, 75). The
only callers are those existing test suites. The free `send_nak(int)`
declaration is also never defined; it was not on the list and is unchanged.

### dtracedctl: redundant defensive checks removed, waivers (2026-10-21, decision 3)

Removed because an earlier check provably dominates them:
- `parse_names()` `str == NULL`: both callers pass a non-NULL string
  (`optarg` after an explicit NULL test, or `argv[optind]` with
  `optind < argc`). The empty-string check stays (reachable:
  `stats-empty-positional`).
- `send_request()` `n_strs > 4096` and per-name `length >= 4096`:
  `parse_names()` refuses a 4096th comma (at most 4096 names) and any name of
  4096 or more bytes (EMSGSIZE), and it is the only producer of `names_t`.
  The frame size is still computed from each name.
- `getopt_long()` case 0: no `longopts` entry has a flag pointer, so 0 is
  never returned.
- final `default:` of the action switch: `action` is checked to be CLEAN or
  STAT before connecting.
- `open_dtraced()` `sun_path` overflow: the path is the compile-time constant
  `DTRACED_SOCKPATH`; a `_Static_assert` now proves it fits, and the function
  no longer takes a path argument.

The same two kinds of redundant check were removed from
`dtraced_dttransport.cc` (`setup_connection`): the `sun_path` overflow
branch (constant `DTRACED_SOCKPATH`, now a `static_assert`) and the
`valid_initmsg()` test of the message `guest_forwarder_initmsg()` has just
built (forwarder kind, ELFWRITE only, nonempty ident, nonzero session by
construction).

Waivers (kept, not provably dominated):
- `dtraced_errmsg.cc` `if (msg)` false arms: the logging functions accept a
  NULL message by contract; every current caller passes a literal, but the
  guard protects `vfprintf()` from a future NULL caller.
- `dtraced_dttransport.cc` `SHA256() == NULL`: with OpenSSL 3 the one-shot
  digest can fail (provider unavailable); not reachable offline without
  breaking libcrypto.
- `dtraced_io.h` `read_size > SIZE_MAX`: the shared header is also compiled
  for ILP32 consumers, where the branch is reachable; on LP64 it is not.

## Change inventory for the per-area commits (2026-10-22)

Production (usr.sbin/dtraced, usr.sbin/dtracedctl), all from this work:
- `dtraced_directory.cc/.h`: unlink retry; record_cleanup_pending undo;
  F1-F3 (`record_host_outbound_intent`, `host_outbound_spool`,
  `record_guest_outbound_intent`, `queue_pending_host_outbound`,
  `forget_unrecorded_host_spools`, `forget_unassigned_ingress`,
  `withdraw_pending_delivery`, queue_elfwrite_batch intents); base-copy
  source suffix (routing); HT-C comment markers.
- `dtraced_job.cc/.h`: `notify_elfwrite_job::recorded`; send_elf recorded
  path and withdrawal; registration status under output_mtx; truncated-body
  NAK removed; dead code removed; HT-C markers.
- `dtraced_state.cc`: admission resend of pending host deliveries; startup
  forget calls; refused-hello log; HT-C markers.
- `dtraced_dttransport.cc`: writer idle poll (prompt shutdown); static_assert
  and removed self-check.
- `dtraced_socket.h`: forwarder READDATA|CLEANUP refused.
- `dtraced_clientrequest.cc/.h`: host -Y inbound routing; HT-C markers.
- `dtraced_connection.cc/.h`, `_dtraced_connection.h`, `dtraced.cc`,
  `dtraced_misc.cc`, `dtraced_errmsg.*`, `Makefile` (dtraced_id.cc removed):
  removals and earlier fixes listed above; header HT-C markers
  (`dtraced_wire.h`, `dtraced_transfer_wire.h`, `dtraced_rebind_wire.h`,
  `dtraced_release_attestation.h`, `dtraced_release_keys.h`).
- `usr.sbin/dtracedctl/dtracedctl.c`: redundant checks removed.

Harness and records (contrib/hypertrace):
- tests: `daemon-harness.h`, `io-wire.cc`, `dtt-listen.cc`, `dtt-rekey.cc`,
  `dtt-write.cc`, `dtt-status.cc`, `dtt-quiesce.cc`, `journal-faults.cc`,
  `journal-names.cc`, `launch-child.cc`, `journal-corruption.cc`,
  `child-ledger-recovery.cc`, `client-fd.cc`, `collector-evidence.cc`,
  `header-props.cc`, `daemon-main.cc` (shim), `daemon-main.py`,
  `registration-order-stress.py`, `control-cli-extra.py`, `daemon-extra.py`,
  `coverage-daemon.py`, `live-sweep.py`, `htpeerlib.py`, `handoff-peers.py`,
  `handoff-sweep.py`; `protocol.cc` (identity regression only).
- record: this file.
Not mine (left untouched): native-daemon.py, control-cli-offline.py,
native-daemon-compat.cc, connection.cc, child-ownership.cc.

## Final measurement: cov-daemon-final8-20261022 (2026-10-23)

Run: `/usr/obj/5BSD-hypertrace-validation/cov-daemon-final8-20261022`
(coverage-daemon.py; sources = commits 4f3166ebea9/85de37f6eb7 plus the
follow-on changes recorded after them in this file).

| Configuration | Lines | Branches | Functions |
| --- | --- | --- | --- |
| dtraced live (HT-C excluded; the target) | 15,389/16,983 (90.61%) | 9,899/12,462 (79.43%) | 519/520 |
| dtraced native-test (everything) | 26,336/30,778 (85.57%) | 16,016/22,264 (71.94%) | 790/797 |
| dtraced production build | 26,339/30,781 (85.57%) | 16,016/22,264 (71.94%) | 790/797 |
| dtracedctl | 238/239 (99.58%) | 121/122 (99.18%) | 7/7 |

The live figure is the honest endpoint for this hand-back; 97/97 is not
reached. Earlier checkpoints: final5 90.07%/78.75%.

Code split. Trace continuity (HT-C, disabled future feature, waived):
15,424 physical lines inside markers; mapped and excluded from the target:
13,795 lines and 9,802 branch outcomes (native-test minus live), of which
10,947 lines (79.4%) and 6,117 outcomes (62.4%) are nevertheless executed by
the continuity harness (handoff-peers, handoff-sweep refuse and the hostile
crafted-HANDOFF requests). Live (counted): 16,983 lines, 12,462 outcomes.

Sweep results in final8 (oracles stated under "Live code"):
- callfault 1,884 points, 0 failures; startup 2,136 points, 0 failures;
  corrupt 570 points, 0 failures; handoff refuse 15,456 points, 0 failures;
  hostile 30,219 mutated requests over the five original flows, 0 failures
  (the two new guest flows failed in their template builder, a harness
  KeyError since fixed; rerun below).
- fault: outbound-delivery 2,328, host-ingest 1,476, guest 768,
  guest-installed 852 points, 0 failures; derived 2,004 points, 1 failure
  (restart did not complete within the load allowance; passes in 13
  isolated and parallel reruns); fresh-session 2,976 points, 3 failures
  (the stop step ran before the consumer re-registered; the harness now
  repeats SESSION_STOP as bhyve's coordinator does). Oracle reruns against
  final8's instrumented binary with the corrected harness
  (cov-daemon-scratch-20261021/f8-oracle): fault derived 1,027 points and
  fresh-session 1,453 points, 0 failures; hostile guest-installed 489
  mutated requests, 0 failures.
- guest-startup did not finish within its 4 h limit (TIMEOUT, recorded by
  daemon-extra); the profiles of the points it executed are included in the
  figure, its oracle results are not.

Waivers with proof:
- HT-C continuity code (table below): disabled future feature by the
  user's decision; behaviour unchanged (removing the markers reproduces the
  previous sources byte for byte); unreachable in production because bhyve
  refuses format-4 restore and its checkpoint side hard-codes
  `handoff_enabled = false`; HANDOFF input from old or crafted peers is
  still exercised as a security property (refuse and hostile sweeps).
- dtracedctl: the one uncovered line and branch were recorded with their
  proof in the dtracedctl section above.
No other waivers are claimed: every remaining live line and branch below is
reachable work.

HT-C waiver table (R = region, B = block inside a live function; line
ranges at the measured revision):

| File | Ranges |
| --- | --- |
| `dtraced_clientrequest.cc` | B 163-170, B 271-277, B 364-375, B 604-665, B 824-825, R 1146-1190, R 1308-2266, B 2549-2613, B 2694-2695, B 2705-2706 |
| `dtraced_clientrequest.h` | R 115-118, R 130-134 |
| `dtraced_connection.cc` | R 290-307, R 331-347, R 418-475 |
| `dtraced_directory.cc` | B 1044-1056, R 1449-1768, B 1882-1920, R 1938-2010, R 2071-2740, B 2771-2822, R 2840-2973, R 3192-4440, B 4473-4507, R 4551-5117, B 5145-5191, R 5211-5228, B 5500-5507, R 5900-6241, B 7041-7048, R 8366-8856, B 8949-8950, B 9037-9038, B 9068-9102, B 9136-9155, R 9172-9600, R 10122-10831, R 11084-13580, B 13612-13636, B 13644-13647, B 13652-13655, R 13670-14437, B 14465-14524, R 14544-15070, B 15101-15179, B 15203-15256, B 15293-15353, R 15371-16337, B 16367-16389, B 16403-16407, R 16419-16635, R 16931-17009, R 18476-18967, R 19181-20978, B 21461-21461, B 21465-21465, B 21470-21470, B 21475-21475, B 21480-21480, B 21484-21484, B 21528-21528, B 21534-21534, B 21539-21539, B 21544-21544, B 21550-21550, B 21558-21558, B 22015-22015 |
| `dtraced_job.cc` | R 159-204, B 366-367, B 388-390, B 474-474, B 575-582, B 602-615, B 809-859, B 1036-1043, B 1264-1265, B 1276-1277, B 1285-1286, B 1303-1305 |
| `dtraced_rebind_wire.h` | R 34-115 |
| `dtraced_release_attestation.h` | R 21-116 |
| `dtraced_release_keys.h` | R 111-113 |
| `dtraced_state.cc` | B 956-957, B 975-991, B 1133-1134, B 1217-1223, B 1272-1293, R 1450-1491, R 1654-1670, B 2313-2371 |
| `dtraced_transfer_wire.h` | R 25-548 |
| `dtraced_wire.h` | R 528-733 |

Remaining live gap (reachable work, from final8's export; analysis and
script: /usr/obj/5BSD-hypertrace-validation/cov-daemon-final8-gap-20261023,
`live-gap.json`; line classes: error-return 473,
errno set-up 340, braces of those blocks 369,
log/shutdown 89, other 311):

| File | Lines open | Branch outcomes open | Functions |
| --- | ---: | ---: | ---: |
| `dtraced_directory.cc` | 814 | 1275 | 155 |
| `dtraced_state.cc` | 195 | 251 | 34 |
| `dtraced_clientrequest.cc` | 114 | 290 | 17 |
| `dtraced_job.cc` | 175 | 205 | 10 |
| `dtraced_dttransport.cc` | 161 | 179 | 24 |
| `dtraced_process.cc` | 61 | 175 | 18 |
| `dtraced_child_ledger.cc` | 14 | 50 | 8 |
| `dtraced_socket.h` | 5 | 25 | 4 |
| `dtraced_io.h` | 9 | 19 | 4 |
| `dtraced_connection.cc` | 4 | 21 | 13 |
| `dtraced.cc` | 14 | 8 | 3 |
| `dtraced_release_keys.h` | 2 | 17 | 2 |
| `dtraced_misc.cc` | 7 | 8 | 2 |
| `dtraced_wire.h` | 0 | 8 | 3 |
| `dtraced_protocol.h` | 0 | 6 | 1 |
| `dtraced_connection.h` | 3 | 2 | 1 |
| `dtraced_derived.h` | 3 | 2 | 2 |
| `dtraced_elf.h` | 1 | 2 | 1 |
| `dtraced_errmsg.cc` | 0 | 3 | 3 |
| `dtraced_collector_owner.h` | 0 | 1 | 1 |
| `dtraced_directory.h` | 0 | 1 | 1 |
| `dtraced_events.h` | 0 | 1 | 1 |

Largest functions (lines and branch outcomes open, line classes):

| File | Function | Lines | Outcomes | Classes |
| --- | --- | ---: | ---: | --- |
| `dtraced_job.cc` | `job::send_elf` | 112 | 134 | error-return 31, brace 28, other 28, errno 23, log/shutdown 2 |
| `dtraced_dttransport.cc` | `listen_dttransport` | 78 | 37 | log/shutdown 35, other 21, brace 19, errno 3 |
| `dtraced_clientrequest.cc` | `client_request::handle_elfmsg` | 49 | 65 | error-return 25, brace 12, errno 11, other 1 |
| `dtraced_process.cc` | `launch_program` | 43 | 58 | error-return 15, other 11, brace 9, errno 8 |
| `dtraced_directory.cc` | `process_inbound` | 38 | 33 | error-return 11, brace 10, log/shutdown 8, other 7, errno 2 |
| `dtraced_state.cc` | `state::accept_new_connection` | 30 | 33 | other 16, brace 8, error-return 3, errno 2, log/shutdown 1 |
| `dtraced_directory.cc` | `dir::verify_host_delivery_payload` | 14 | 48 | other 6, error-return 3, brace 3, errno 2 |
| `dtraced_clientrequest.cc` | `client_request::handle_consumer_executionmsg` | 15 | 41 | other 6, error-return 4, brace 3, errno 2 |
| `dtraced_directory.cc` | `queue_elfwrite_batch` | 17 | 38 | error-return 9, other 4, brace 2, errno 1, log/shutdown 1 |
| `dtraced_directory.cc` | `consumer_owner_publish_at` | 22 | 29 | errno 11, error-return 4, brace 4, other 3 |
| `dtraced_directory.cc` | `consumer_receipt_reserved_at` | 32 | 18 | errno 11, brace 9, other 8, error-return 4 |
| `dtraced_directory.cc` | `dir::queue_pending_host_outbound` | 22 | 28 | error-return 8, other 7, brace 4, errno 2, log/shutdown 1 |
| `dtraced_directory.cc` | `dir::source_transaction::publish_derived` | 13 | 36 | error-return 4, errno 3, brace 3, other 3 |
| `dtraced_directory.cc` | `publish_spool` | 22 | 26 | other 9, errno 6, brace 5, error-return 2 |
| `dtraced_directory.cc` | `dir::resolve_derived_outbound` | 20 | 28 | error-return 7, errno 5, brace 5, other 3 |
| `dtraced_directory.cc` | `dir::record_consumer_program` | 16 | 29 | error-return 6, errno 5, brace 5 |
| `dtraced_directory.cc` | `dir::hash_identified_data` | 13 | 28 | other 7, brace 4, errno 1, error-return 1 |
| `dtraced_job.cc` | `reconcile_lost_consumer_ack` | 11 | 28 | error-return 5, errno 3, brace 3 |
| `dtraced_directory.cc` | `dir::consumer_cohort` | 23 | 15 | errno 8, error-return 7, brace 7, other 1 |
| `dtraced_directory.cc` | `dir::rekey_guest_delivery` | 16 | 22 | error-return 7, errno 4, brace 4, other 1 |
| `dtraced_directory.cc` | `dir::populate_existing` | 9 | 29 | error-return 9 |
| `dtraced_state.cc` | `validate_guest_recovery_identity` | 14 | 24 | error-return 6, errno 4, brace 4 |
| `dtraced_state.cc` | `state::stop_fresh_session_step` | 9 | 27 | errno 4, other 3, error-return 1, brace 1 |
| `dtraced_directory.cc` | `dir::rekey_guest_kills` | 12 | 23 | error-return 8, errno 2, brace 2 |
| `dtraced_directory.cc` | `dir::record_consumer_receipt` | 18 | 17 | errno 6, error-return 6, brace 5, other 1 |
| `dtraced_directory.cc` | `derived_claim_record_at` | 16 | 19 | errno 5, error-return 4, brace 4, other 3 |
| `dtraced_directory.cc` | `dir::queue_recovered_outbound` | 15 | 19 | error-return 5, errno 4, brace 4, other 2 |
| `dtraced_directory.cc` | `dir::queue_recovered_consumer` | 15 | 19 | error-return 8, errno 3, brace 3, other 1 |
| `dtraced_directory.cc` | `dir::audit_derived_claims` | 14 | 18 | error-return 6, errno 4, brace 4 |
| `dtraced_directory.cc` | `guest_rekey_preflight_at` | 16 | 16 | errno 5, error-return 5, brace 5, other 1 |
| `dtraced_directory.cc` | `dir::fresh_consumer_stop_receipt` | 9 | 23 | errno 3, error-return 3, brace 2, other 1 |
| `dtraced_directory.cc` | `host_outbound_spool` | 13 | 19 | brace 4, other 3, errno 3, error-return 3 |
| `dtraced_dttransport.cc` | `recover_guest_rekey` | 11 | 21 | error-return 7, brace 2, errno 1, other 1 |
| `dtraced_process.cc` | `handle_host_status` | 6 | 26 | error-return 4, errno 1, brace 1 |
| `dtraced_dttransport.cc` | `write_dttransport` | 16 | 15 | other 9, brace 3, errno 2, log/shutdown 2 |
| `dtraced_state.cc` | `validate_guest_cleanup_recovery_state` | 9 | 22 | error-return 5, errno 2, brace 2 |
| `dtraced_clientrequest.cc` | `client_request::handle_uninstalledmsg` | 12 | 18 | other 5, brace 3, errno 2, error-return 2 |
| `dtraced_state.cc` | `activate_guest_fresh_session` | 10 | 19 | error-return 6, errno 2, brace 2 |
| `dtraced_directory.cc` | `dir::rekey_guest_journals_with_receipts` | 14 | 14 | error-return 6, errno 4, brace 4 |
| `dtraced_job.cc` | `job::send_kill` | 14 | 14 | error-return 5, brace 4, log/shutdown 3, errno 2 |

Follow-on order (coordinator): journal families in send_elf/spool
validation, consumer program/execution records (needs a constructed
client_fd), derived claims (paired directories), rekey sub-paths,
collector-owner recovery, capacity limits; then transport event handling
(listen_dttransport), handle_elfmsg, launch_program, accept_new_connection
attestation variants.

Follow-on changes after the commits (all harness): coverage-daemon.py
keeps the measurement when a driver times out and allows daemon-extra 12 h;
htpeerlib.py per-daemon start allowance (`start_timeout`); live-sweep.py
bhyve-style SESSION_STOP repetition, shorter start allowances in the
startup, callfault and guest-startup modes, guest-startup allocation
stride (each of the first 200 allocations, then every 5th) and hostile
templates for every guest flow. Everything else in this record (guest
flows and their shim emulation, new call faults, journal-faults
operations, fresh-session effects) is in 85de37f6eb7. No production source changed after the
commits: the transport writer idle poll and the READDATA|CLEANUP refusal
are in 4f3166ebea9 (`git diff HEAD -- usr.sbin/dtraced usr.sbin/dtracedctl`
is empty).
