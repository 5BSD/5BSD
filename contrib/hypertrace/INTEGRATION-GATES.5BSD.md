# HyperTrace integration gates

## Scope revision: fresh tracing sessions (2026-10-19)

The user has replaced tracing continuity across save/restore and migration
with a fresh-session contract. The release target is reliable tracing of a
running VM, explicit teardown before checkpoint or migration, and a fresh
guest/host session after startup or restore. Trace gaps and restarted
aggregations are expected. Previously queued tracing work is not replayed
into the new session.

Retain compiler and guest-memory fixes, transport validation, bounded queues,
session isolation, revocation, ordinary reconnect support, packet provenance,
and their useful tests. Preserve the experimental continuity implementation
for reference, but stop extending its transactional journal transfer, HRC2
commit, checkpoint-copy ownership, and continuity execution-lease machinery.
Those features are no longer release requirements.

Implementation still must quiesce old guest probes, retire the old host
session, discard old transport work, reset restored guest/device state, and
complete a fresh identity handshake before enabling newly requested programs.
Restarting the host collector alone does not meet this contract. The format-5
reset-and-reattach path is now connected as recorded below; unsupported paths
retain their refusals. This implementation does not certify live behavior.

The numbered gates below are historical implementation records. Their
continuity requirements no longer define completion of the revised target.
The remaining release work is the fresh-session lifecycle, ordinary tracing
semantics, supported-architecture integration, and matched host/guest testing.

Requirement audit against the active seven-part goal (2026-10-19):

| Requirement | Current authoritative implementation/evidence | Still unproven or unfinished |
| --- | --- | --- |
| 1. Coordinated shutdown and VM-state metadata | snapshot.c: hypertrace_checkpoint_stop waits for guest stop and collector completion before exporting FSS1; migration_session.c carries the fresh COMMIT/RELEASE binding. Native fresh-session checkpoint and migration fixtures pass. | Production source and managed destination now admit fresh migration under TLS, private journal and prepared-recovery/startup-fence preconditions. Userspace vCPU acknowledgment now precedes final RAM copying; matched live ordering and metadata transport remain unqualified. |
| 2. Destination discard, new identity, new authorization | pci_virtio_dtrace.c: discard_paused, restore staging and session_authorize; snapshot.c coordinates startup fencing. Native fresh restore/load/device tests pass. | No live demonstration of empty old queues/partial programs/aggregates or authorization-before-execution across restore/migration. |
| 3. Remote retirement before destination authorization | migration_source_run persists INTENT after accepted COMMIT, then RETIRED/RELEASED before sending RELEASE. HMR2, immutable source ownership, certificate pins and exact challenge bind recovery. Real-TLS fixtures verify ordering and one resume. | Live remote-retirement proof and enabled production migration remain unqualified; component evidence cannot close this gate. |
| 4. Collector crash before stop proof | dtraced_state.cc: recover_collector_owners and stop_fresh_session_step preserve missing evidence, recover exact pins when possible and require durable process/reaper/handle facts. Existing daemon and native suites cover these decisions. A verified HPB1 registration from an earlier kernel boot is now accepted as proof of all three facts for replacement/cohort retirement (featA). | Same-boot collector/daemon loss before durable exit evidence, and surviving descendants, remain unresolved: the 2026-10-21 evaluation found no sound after-the-fact proof among procdesc, procctl reaper, kqueue or birth-identity mechanisms. No inference from PID disappearance is permitted; live lifecycle evidence is still needed. |
| 5. Daemon restart and safe journal retirement | dtraced startup recovers cohorts/receipts before collector ownership; FSD1/FSI1 reader independently recovers completed stop. FSA1 retirement now revalidates completion and candidates under one lock, removes only matching acknowledgments, and syncs even partial/empty retries. Late ACK publication uses completion evidence. | Completed authenticated stop requests now attempt cleanup; failures retain completion and retry on the next request or daemon startup. Isolated unlink/sync/retry and late-publication tests pass. Receipt/cohort and shared process/reaper evidence are retained. |
| 6. Safe migration recovery | Retained destination owner, uncertainty quarantine, source canonical directory and controller lock, authenticated restart API, and recovery-only command are implemented. Native/TLS fixtures and full native links pass. | An optional locally supplied name now permits authenticated atomic exact-identity retirement, with drained witness and durable RETIRED required before RELEASE. Native fault fixtures pass; live behavior is unqualified. Destination controller-loss reconstruction is now implemented for destinations that opt in with `migrate.recovery_image` (HDI1 image + controller lock before STAGED; successor admission by lock, exact STAGED, kernel retirement witness and durable HDS1). It has component, real-TLS and full-link evidence only; image write time versus the COMMIT deadline and live behavior are unqualified. Without an image, recovery still requires the retained owner. Fresh production admission is connected but not live-qualified. |
| 7. Validation and matched live preparation | 145 native suites pass in the consolidated fresh-final-native run, including the latest console-fence and Capsicum recovery cases. Current AMD64 snapshot bhyve links; ARM64/RISC-V supported non-snapshot bhyve and local dependencies fully link with verified ELF identities; live evidence matrix is prepared (25 cases after featA added destination reconstruction, debugger fence and rollback repair cases). | Fresh whole-system builds and matched runtime libraries/kernel/guest deployment are not established by these checks. No live matrix case has run. Live fault injection requires authorized lab preparation. |

No row proves the full requirement complete. Production admission now has
explicit prerequisites; this is not evidence of live qualification. The user explicitly approved
orphan-retirement and FSA1-cleanup code plus isolated tests on 2026-10-19.
That approval does not authorize operating live VMs or deleting live journals.
Unavailable live evidence is not a pass. Preserve the fresh-session/no-old-buffer scope and the
no-rollback-after-retirement invariant while closing these gaps.

Current fresh-session implementation checklist:

- Consolidated featA regression (2026-10-21): `featA-final-native` runs the
  149 registered native-port suites (145 earlier plus migration-dest-image,
  migration-dest-reconstruct, gdb-migration-fence and
  migration-rollback-repair); 147 pass. migration-fresh-destination and
  migration-cpu-barrier fail to compile because their extracted bhyverun.c
  and snapshot.c slices now call `BHYVE_RESUME_RUNNABLE_CPUS`, introduced by
  the concurrent ARM64/RISC-V snapshot work in the untracked
  `snapshot_md.h`; those fixtures need that definition and were left to that
  work. Both passed in `featA-baseline-native` (145/145) before it. The 46
  daemon suites pass in `featA-boot-daemon`. These are component results,
  not live qualification.

- FSA1 (orphaned collector acknowledgment) deletion and maintenance hook:
  verified already implemented, 2026-10-21 (featA). The non-destructive
  planner notes below are historical. `fresh_session_ack_retirement_at()`
  revalidates durable FSD1/FSI1 completion and the complete exact candidate
  set (canonical name, private single-link file, FSA1 checksum, embedded
  fence/token/source session equal to the completed stop) under the
  publication mutex and cross-process lock before the first unlink, never
  deletes a differently bound or incomplete acknowledgment, and syncs the
  directory after partial or empty retries. It runs after an authenticated
  SESSION STOP request completes (`retire_fresh_session_acks`) and from
  control-daemon startup
  (`retire_completed_fresh_session_acks`) as the maintenance hook; FSI1,
  FSD1, receipts, cohorts and process/reaper/handle evidence are retained.
  No additional operator command was added because the existing paths
  already provide explicit, exact-candidate deletion; tests use only
  isolated fixture journals. Verification: `featA-fsa1-daemon` passes all 46
  sanitized daemon component suites (including the stop/cleanup fault
  cases: unlink failure, post-unlink fsync failure, empty retry, late
  publication, foreign-session preservation, corruption refusal) at the
  source before the featA daemon change; `featA-boot-daemon` passes the same
  46 after it. Live journal deletion remains unexercised.

- Collector crash before durable exit proof: evaluation and the one sound
  addition (2026-10-21, featA). A crash-stop needs three facts about the
  registered collector: process exit (HPE1), an owned and empty reaper at
  exit (HRE1), and retirement of its kernel DTrace handle lifetime. The
  unresolved window is daemon loss (alone or with the collector) when the
  collector exits while no daemon holds its process descriptor. Evaluated:
  * pdfork/pdwait: collectors are user-started and registered over the
    socket, not daemon children; a process descriptor lives in the daemon's
    file table and disappears with it (without PD_DAEMON its close kills the
    child but not descendants), so it cannot carry proof across daemon loss.
  * PDIOC_GET_REAPER_EXIT (already used for HRE1): the kernel keeps the exit
    snapshot only in a descriptor that was open when the collector exited.
  * procctl(PROC_REAP_STATUS/GETPIDS): describe only the caller's own reaper
    subtree; a restarted daemon is not the dead collector's reaper, orphaned
    descendants move to an ancestor reaper, and the kernel keeps no record
    that they once descended from the collector.
  * kqueue NOTE_EXIT: needs a live registration at the moment of exit; an
    exit during daemon loss is never delivered or recorded.
  * Birth identity (pdopenpid plus PDIOC_GET_BIRTH_IDENTITY): its absence is a
    PID inference prohibited by policy and, even if accepted, proves nothing
    about descendants.
  * HYPERTRACE_IOC_HANDLE_QUERY: remains available after restart and is used,
    but it is one fact of three.
  None of these closes the same-boot window, so it stays unresolved and
  fenced. The one sound proof found is reboot: kern.boot_id is generated once
  per kernel instance and no process, descendant or DTrace handle survives
  into another instance. `consumer_prior_boot_at()` accepts a checksummed,
  private, single-link HPB1 (published only for a kernel-birth-verified
  registration) whose every identity byte matches the receipt's owner,
  program and handle lifetime but whose recorded boot differs from the
  current nonzero boot. It is consulted first by replacement-PID replay
  retirement (`consumer_replay_retirement`, via the new
  `dir::consumer_prior_boot_retired`) and by the locked cohort recheck
  (`consumer_retired_at`); same-boot records fall through to the existing
  three-fact checks. It never consults the current occupant of the numeric
  PID and does not publish FSA1: the crash-stop publisher still requires a
  live suspended source gate, which no longer exists after reboot.
  Evidence (ASan/UBSan, no daemon started): `featA-boot-daemon` rebuilds all
  12 daemon translation units, links the sanitized daemon and passes all 46
  component suites, including new journal-backed `fresh-session-stop-step`
  cases (same boot 0, earlier boot 1, boot query ENXIO, zero/short boot
  EPROTO, checksummed identity mutation ESTALE, checksum corruption, zero
  recorded boot and permissive mode EPROTO); `featA-boot-restart-owner`
  (actual replay-retirement policy: prior-boot proof short-circuits, its
  errors fail closed, same boot falls through). `featA-fsa1-daemon` is the
  46/46 run of the same harness before this change. The cohort-recheck call
  site is exercised for the same-boot fall-through by existing ingress
  suites; its earlier-boot branch is covered by code review, not a
  dedicated test. Options that could close the same-boot window need a user
  decision: a kernel facility retaining exit snapshots of registered
  collectors after the last descriptor closes (new kernel state and
  resource policy), per-session collector jails whose removal proves the
  tree exited (launch-model change), or accepting handle retirement plus
  process exit without descendant proof (weaker policy).

- Repair of a failed pre-COMMIT rollback (2026-10-21, featA). When a
  migration leaves the source non-runnable and its retirement never began
  (no INTENT was attempted, so no RELEASE can exist and the destination
  cannot run), `vm_do_migrate()` now retries `prod_resume()` automatically up
  to three times with 0/100 ms/1 s backoff and reports `repaired`,
  `repair_attempts` and `repair_error`. The resume sequence is idempotent by
  construction: `vm_resume_devices()` resumes only devices that still hold
  pause ownership, the CPU barrier keeps its hold until the kernel resume
  succeeds, and console input reopens last. A successful repair restores a
  runnable source and releases the debugger fence. Otherwise IPC enters a new
  reversible quarantine (`ipc_wedge_vm`) that hides the context alias and
  admits only `get_vm_pid`, `migrate_recover` and the new `migrate_repair`;
  `migrate_repair` (and `bhyvectl --migrate-repair`) retries the same bounded
  sequence and calls `ipc_unwedge_vm()` only after success. Retirement
  (INTENT/retire) still uses the irreversible quarantine, which a wedge or
  unwedge can never weaken, and repair returns EPERM without touching devices
  or CPUs once retirement started, while INTENT is pending, after retirement,
  without the owned context, or once CPU retirement began.
  Evidence (ASan/UBSan, no VM): `featA-repair-fixture` (actual
  `prod_quiesce`/`prod_resume`/repair against stateful device-ownership,
  CPU-hold and console models: 21 checks including every device/CPU failure
  count, backoff timing, persistent failure then operator success, a failed
  device-pause unwind, and five retirement/ownership refusals);
  `featA-repair-admission` (actual `vm_do_migrate`/`vm_do_migrate_repair`
  under Capsicum, with and without BHYVE_GDB: no repair after INTENT,
  bounded failure with wedge, success on the second attempt, operator
  repair, EPERM/EALREADY refusals, debugger fence release only on repair);
  `featA-repair-ipc` (actual IPC dispatcher wedge/unwedge and irreversible
  upgrade); `featA-repair-cli-ipc` (built bhyvectl SHA-256
  840e52cbdfcf4493d69f609e0c26261c65f828c60e11364af5cec66f9e8a5536: 26 IPC
  cases including seven repair replies and three rejected conflicts);
  `featA-repair-build1` (16 native objects); `featA-full-link-repair`
  (snapshot bhyve SHA-256
  243f3c52dfc546ca796a651528e6c9e070e05ba4aa6b81d1b3c50211bb29a2a1 and
  bhyvectl). Real device resume behavior after a partial failure, and
  whether a failing device ever recovers, remain live qualification items.

- Debugger-aware source migration teardown (2026-10-21, featA). The blanket
  refusal of a configured GDB server is replaced, in debug-server builds, by
  a fence in gdb.c that migration acquires after transport setup and before
  `migration_source_run` can quiesce. It refuses precisely, with the source
  runnable and nothing quiesced, while a debugger owns the guest: an attached
  client, software breakpoints in guest RAM (which would otherwise migrate),
  pending single-step/breakpoint vCPU state, or any vCPU suspended or waiting
  in the server, including a `gdb.wait` start without a debugger. Otherwise
  the fence is held under `gdb_lock`; `new_connection()` closes every new
  client while it is held, so the migration barrier's debug exits cannot
  meet a debugger wait. Only a result with `source_runnable=true` releases
  it; wedged or retiring sources keep it. `prod_retire_destroy()` makes the
  fence permanent and clears the server's vmctx alias before vCPU
  retirement and kernel destruction, covering both normal retirement and
  same-process INTENT completion. Builds without the debug server keep the
  previous configured-port refusal. The destination needs no fence: its
  mevent loop (and therefore every debugger callback) does not start until
  the inbound coordinator returns after resume.
  Evidence (ASan/UBSan, no VM/debugger): `featA-gdb-fence` (actual gdb.c
  `new_connection()` and fence functions with real sockets: 13 checks, every
  refusal reason, permanent retirement, and 57,919 concurrent attach attempts
  refused inside 200 fenced windows with none installed);
  `featA-gdb-admission` (actual `vm_do_migrate` under Capsicum, built with and
  without BHYVE_GDB: refusal after transport but before migration, unfence
  only for runnable results, retained fence after retirement/wedge);
  `featA-gdb-retire` (actual retirement slices: fence retired before every
  one of six destruction attempts); `featA-gdb-build2` (16 native objects);
  `featA-gdb-arm64` (seven supported non-snapshot ARM64 objects plus gdb.c,
  ELF machine 183); `featA-full-link-gdb` (native snapshot bhyve link, SHA-256
  e9e874de8d563d1fbba6f51b146ea184824ddea995c95563372b23f0272adf19). Real
  debugger/guest interaction and live cutover remain unqualified.

- Destination controller-loss reconstruction (2026-10-21, featA). A fresh
  destination may opt in with `migrate.recovery_image=true`. A new optional
  core hook, `do_preserve`, runs after `do_prepare_commit` and before durable
  STAGED; the production hook takes a per-attempt controller lock
  (`d-<challenge>.controller`, never unlinked, held for the process lifetime)
  and writes `d-<challenge>.image` (HDI1: the exact HMR2 attempt binding,
  memory geometry, all guest RAM, the COMMIT-bound DEV_STATE blob and a
  whole-file SHA-256) with temp file, fsync, no-replace rename and directory
  fsync. Any failure aborts before STAGED and COMMIT, so the source never
  begins retirement and rolls back. Because COMMIT follows STAGED, a retired
  source always corresponds to a preserved image. The image is removed after
  RELEASED and a successful resume.
  A successor bhyve started with `migrate.reconstruct=<challenge>` (from the
  trusted local file name, never the peer) runs admission before Capsicum:
  it must acquire the existing controller lock (EBUSY while any earlier
  controller lives), find an HDI1 header for exactly that attempt and durable
  HMR2 phase exactly STAGED (RELEASED/RUNNING return ENOTRECOVERABLE: the
  guest may have executed; a missing STAGED returns ENOENT), use a context
  that differs from the previous, original destination and source lifetimes,
  and obtain an affirmative kernel retirement witness for the previous
  incarnation (`hypertrace_session_retired`; the optional
  `migrate.reconstruct_previous_name` only permits atomic
  name-plus-exact-identity destruction followed by the witness). Witness
  errors and missing devices/VMs are never retirement. It then publishes
  `d-<challenge>.successor` (HDS1: attempt digest, generation, previous and
  current lifetimes) durably before loading any state. After Capsicum it
  loads the image into guest RAM, verifies the whole-file and DEV_STATE
  digests and the FSS1 session record, installs device state through the
  existing fresh commit path, and becomes a paused retained owner served by
  the managed recovery worker. The owner validates its successor lifetime
  instead of the original destination lifetime while keeping the original
  HMR2 binding for HMX1, and resumes only through HXR1 after the
  authenticated source proves durable RETIRED. A successor that dies before
  resume is itself retired by the next generation.
  Evidence (all under the validation root, all ASan/UBSan, no VM/device):
  `featA-dest-image-2` (pure header: 2,578 malformed encodings rejected, 83
  injected write/fsync/rename/map faults fired with no temp residue, nine
  corrupted file regions refused, lock contention across processes and
  after a crashed holder, 24 admission refusals and two successor
  generations); `featA-dest-reconstruct-2` (actual production
  preserve/reconstruct/recovery slices with real journals and real mutual
  TLS, normal and after `cap_enter`: preservation refusals, refusal while
  the original lives, eight prepared() refusals each consuming admission,
  name-hinted exact destruction, live failed successor blocking, RAM and
  blob equality, INTENT-only source refusal with no resume, identity check
  of the successor lifetime, one resume with RELEASED/RUNNING/CONFIRMED
  ordering, lost-ACK reconnect without a second resume, image retirement,
  RELEASED quarantine); `featA-dest-receiver` (receiver worker serving a
  reconstructed owner; setup failures abandon, source failure consumes);
  `featA-dest-retained-owner` (existing owner suite plus recovery-image
  admission); `featA-dest-core` (38 ATF cases including
  `fresh_preserve_precedes_staged`); `featA-dest-ipc-startup` (admission
  before Capsicum and startup fence ordering); `featA-dest-build1` (16
  production objects, snapshot on/off); `featA-full-link` (native
  snapshot-enabled bhyve links against freshly built libvmmapi, SHA-256
  2d8576eb6dafd85a7dca2f3c62800c3173d403fb45863d65f276ab2fe65fbce3; not
  executed or installed).
  Limits: image writing adds downtime proportional to guest RAM and must fit
  the 30-second COMMIT receive deadline, otherwise the source rolls back
  (safe but the migration fails); the image holds guest RAM in the private
  recovery directory; a visible but unsynced HDS1 makes the same incarnation
  retry return EBUSY (fail closed); a crashed successor whose VM object
  persists needs reinitialization, exact named destruction, or another
  witness before the next generation. The kernel witness itself, live image
  timing, and the source/destination recovery pair on matched hosts are not
  qualified. Live matrix case `destination-controller-reconstruction` is
  prepared and not run.

- The compiled snapshot frontend additionally passes 16 real libnv IPC cases
  in `initiation-cli-ipc/results.json`. The disposable controller checks exact
  transferred credential-file identities and uses the transferred stream;
  initiation and recovery reject lost replies, controller errors, missing or
  mistyped fields and runnable sources. The driver records the tested binary
  hash. This closes the frontend-to-IPC test gap, not production TLS/controller
  or live VM qualification; the fixture deliberately mocks the source owner.

- The snapshot-enabled bhyvectl now exposes authenticated migration initiation
  with `--migrate-fd`, alongside `--migrate-recover-fd`. Both use source IPC and
  inherited TLS descriptors; neither opens a VM or selects a new journal root.
  Initiation validates COMPLETED/NONE/non-runnable rather than treating any
  error-free reply as completion. The expanded sanitizer fixture and native
  frontend links (snapshot enabled and disabled) pass in `initiation-cli`.
  Ten invalid/conflicting option cases also pass against the compiled frontend;
  these checks do not contact a VM and are not a live migration result.

- The consolidated `fresh-final-native/results.json` run passes all 145 suites
  after the destination console-input fence and expanded real-Capsicum recovery
  tests. This supersedes the earlier targeted-only evidence for those changes.
  The daemon audit remains 45/45 suites with all 12 production objects compiled
  and the sanitized daemon linked in `daemon-final-audit`. These are isolated
  component checks, not execution of the 22-case live qualification matrix.

- Full supported baseline bhyve cross-links now pass for ARM64 and RISC-V,
  including freshly compiled libvmmapi, lib9p, libuvmem and libfdt. Evidence
  and binary hashes are in `arm64-full-link/full-link-result.json` and
  `riscv-full-link/full-link-result.json` under the validation root. The builds
  use the existing `/usr/src` cross-world sysroots and target-specific host
  DTrace tools; they are not matched whole-system builds. Snapshot support
  remains disabled for these targets, as required by their maintained build
  configuration. Neither cross binary was executed or installed.

- Destination migration commit now drains external console input before device
  pause and state installation. The startup CPU fence alone did not exclude
  RFB keyboard/pointer callbacks reaching PS/2 or USB state. Fresh and ordinary
  resume reopen input only after checked CPU resume and startup-fence release;
  all earlier failures retain the input fence. The expanded actual coordinator
  fixture passes every commit/resume failure boundary in
  `destination-input-order`; the real callback-drain fixture passes in
  `destination-input-drain`, retained-owner uncertainty in
  `destination-input-owner`, all 16 production objects in
  `destination-input-build`, and the final native snapshot bhyve link in
  `recovery-full-link/destination-input-bhyve.log`. The existing destination
  startup live case now explicitly requires external-input admission evidence.
  These are targeted checks after the earlier full native run; no live VM or
  framebuffer was exercised and no new cross-target snapshot support is claimed.


- Consolidated daemon audit: all 12 actual daemon C++ objects compile, the
  sanitized native daemon links, and all 45 component suites pass in
  `daemon-final-audit/builds.json` and `daemon-final-audit/results.json`.
  This includes fresh-session startup/fence/consumer/stop-step tests, process
  ownership and ledger recovery, journal publication, OOM paths, runtime query,
  and admission concurrency/replay. The cleanup audit confirms both explicit
  and startup FSA1 retirement hold the publication mutex and process lock,
  validate the candidate set before unlink, and sync partial/empty retries.
  Collector recovery treats missing process evidence as unresolved; disconnected
  completion requires exact durable exit, empty-descendant and handle-retirement
  facts. These are component/code-audit results, not live collector/VM fault
  qualification. The daemon executable was linked but not started as a service.


- The actual managed receiver now has a Capsicum lifecycle test in addition
  to the TLS/journal executor tests. The fixture prepares a listening socket,
  credentials and queued local clients before entering capability mode in each
  receiver child, verifies absolute opens fail with ECAPMODE, then calls the
  real `migration_prod_dest_serve_managed()` implementation. It verifies worker
  creation failure before initial serve, listener flag restoration on failure,
  retained-owner acceptance, failed authentication, running despite lost ACK,
  repeated ACK replies without a second resume, independently retained
  credential/listener descriptors, and uncertainty that keeps main blocked.
  Normal and sandboxed cases pass in `receiver-capsicum`. VM execution and the
  receiver's recovery callback are substituted in this fixture; TLS/journal
  behavior is covered separately by `recovery-capsicum`. Their separate passes
  do not constitute an integrated live VM restore/migration qualification.


- Sandbox evidence now includes actual durable recovery execution after
  `cap_enter()`, not only a TLS handshake. The executor and production source
  restart adapter each run their 11 scenarios in separate sandboxed children
  using pre-opened credential and journal-directory descriptors. Each verifies
  that an absolute directory open fails with ECAPMODE before creating journals
  and establishing TLS. Lost-ACK retry, failed persistence, uncertain resume,
  exact binding and INTENT refusal remain enforced. Both normal and sandboxed
  runs pass in `recovery-capsicum`; the existing fresh TLS handshake and data
  transfer after Capsicum entry also pass in `recovery-capsicum-tls`. Kernel/VM
  operations remain substituted. This does not exercise the actual recovery
  listener with a live VM or the incoming VM restore coordinator.

- The live evidence matrix now contains 22 explicitly unexecuted cases. New
  cases cover source CPU acknowledgment and timeout/rollback, input/ACPI callback
  retirement, checked destination CPU startup, recovery inside Capsicum,
  interrupted completed-ACK cleanup, and authenticated exact-name orphan
  retirement/name reuse. Existing prerequisites now reflect enabled conditional
  production admission rather than a blanket capability refusal. Every case
  remains `not-run`, and execution authorization remains false.


- Destination resume now checks `vm_resume_all_cpus()` while the userspace
  startup fence is still held, then opens that fence. Both fresh and ordinary
  migration coordinators use this order. A kernel resume error cannot publish
  adapter RUNNING/ACK; the fresh adapter retains its existing uncertain-resume
  quarantine. Main no longer performs a later unchecked per-vCPU resume loop.
  Firmware/platform finalization now precedes incoming RAM/state restoration,
  avoiding writes into restored guest memory after cutover. For inbound
  migration, control endpoint preparation and Capsicum entry occur before the
  receive coordinator; IPC command admission remains gated until main finishes.
  Other startup modes use the same control helper at their prior boundary.
  The expanded actual coordinator fixture tests every fresh and ordinary resume
  failure, checks the startup fence remains held on error, and passes in
  `destination-cpu-resume-final`. The initial fixture build failed because its
  ioctl macro discarded ctx; the corrected macro retains that argument.
  Retained-owner uncertainty passes in `destination-cpu-owner`; startup ordering
  and gate concurrency pass in `destination-cpu-startup-final`. Sixteen native
  objects pass in `destination-cpu-build-final`, seven supported non-snapshot
  objects each pass in `destination-cpu-arm64` and `destination-cpu-riscv`, and
  the final native snapshot bhyve links in
  `recovery-full-link/destination-cpu-bhyve.log`. Actual inbound restore/TLS
  execution inside Capsicum and firmware behavior remain live qualification
  requirements; these compile/model/component checks do not establish them.
  All 145 native suites pass together in `destination-cpu-native/results.json`.


- CPU-barrier setup now checks held/retiring state under its mutex before
  condition initialization or deadline acquisition. Previously a clock failure
  could return `runnable=true` before discovering an existing CPU fence. The
  fault-injection fixture now checks deadline failure on an unfenced source and
  rejection of held/retiring sources without consulting the clock or issuing
  CPU ioctls. The actual barrier/thread tests pass in
  `cpu-barrier-setup-failure`, production quiesce/rollback in
  `cpu-barrier-setup-order`, 16 native object builds in `cpu-barrier-setup-build`,
  and seven supported non-snapshot objects each in `cpu-barrier-setup-arm64`
  and `cpu-barrier-setup-riscv`. The final native snapshot bhyve link passes in
  `recovery-full-link/cpu-barrier-setup-bhyve.log`. These are targeted checks
  after the full 145-suite run, not a new full-suite or live qualification.


- A failed pre-COMMIT rollback now preserves stopped-source admission state.
  `vm_do_migrate()` rejects retained `quiesced` state before clearing its adapter
  or starting transport setup; any non-runnable migration result quarantines
  ordinary IPC commands. This prevents a second request from forgetting held
  CPU/device/input fences and reporting a transport failure as a running source.
  `vm_do_migrate_recover()` also includes `quiesced` in its runnable report;
  lack of retirement intent does not prove the source is runnable. Such a
  pre-COMMIT failure still cannot authorize INTENT completion or remote RELEASE:
  recovery rejects it before connecting, and its retained context is preserved.
  Automatic repair of a failed pre-COMMIT rollback was not implemented at
  this point; it is now implemented (see the 2026-10-21 rollback-repair entry).
  Actual source admission under Capsicum passes in `wedged-source-admission`,
  dispatcher quarantine in `wedged-source-quarantine`, and recovery status plus
  no-retirement-authority checks in `wedged-source-recovery-final`. All 37 core
  migration cases pass in `wedged-source-core`, and all 16 production objects
  compile in `wedged-source-build-final`. The final native snapshot bhyve links
  in `recovery-full-link/wedged-source-final-bhyve.log`. These targeted checks follow the
  earlier full 145-suite CPU-barrier run; that entire suite was not rerun for
  this narrow change.


- The userspace vCPU cutover gap now has an explicit migration barrier.
  `fbsdrun_migration_pause_cpus()` arms a hold before requesting debug exits,
  then waits for all configured vCPU threads to acknowledge between completed
  VM-exit handlers. The wait uses a monotonic 30-second deadline. Device pause
  and final memory copying cannot start until all acknowledgments arrive.
  A timeout or failed suspend attempts CPU resume while retaining the userspace
  hold; failed resume leaves the source non-runnable and input fenced. Successful
  rollback clears the hold only after the resume ioctl succeeds. Retirement
  broadcasts to parked workers after publishing the permanent retiring flag,
  and those workers exit before another VM_RUN. The normal snapshot startup
  fence remains separate. The actual barrier fixture with real threads passes
  in `cpu-barrier-threads`; it covers delayed handler completion, injected
  timeout, failed rollback, and retirement wakeup without guest execution.
  Production adapter rollback tests pass in `cpu-barrier-order-final` and
  retirement bookkeeping in `cpu-barrier-retire`. Sixteen native production
  objects pass in `cpu-barrier-build`, and the final snapshot bhyve link passes
  in `recovery-full-link/cpu-barrier-bhyve.log`. These checks close the identified
  code omission; actual kernel debug-exit delivery and cutover still need matched
  live qualification.
  All 145 native suites pass together in `cpu-barrier-native/results.json`.
  Seven supported non-snapshot objects each pass in `cpu-barrier-arm64` and
  `cpu-barrier-riscv`; snapshot mode remains unsupported by those maintained
  target configurations. No test here loads a module or operates a live VM.

- Consolidated component evidence: all 144 registered native suites pass in
  `retirement-consolidated-native/results.json`, including the startup, ACPI,
  console, vCPU retirement, journal, recovery, and core-session fixtures. This is
  one complete run against the combined changes, replacing the earlier mixed
  full-run/focused-rerun evidence. It is not live qualification and does not
  include the subsequently added userspace CPU barrier fixture; that later validation is recorded separately above.

- Callback audit scope checked this round: the admitted fbuf renderer and its
  VGA renderer do not dereference a vmctx in their render paths. Virtio-gpu has
  no migration eligibility flags and is rejected by the current topology gate.
  e1000 pause disables RX, waits for active TX/RX, and retains esc_mtx; its ITR
  callback takes that mutex. UART pause disables its event and retains its
  mutex. NVMe pause fences the AEN worker, drains blockif, and checks pending
  I/O/queue-handler state. These are code observations, not proof that every
  worker exits: retained locks can park callbacks for the remaining lifetime
  of the retired source controller. Remaining device callback/lock-order
  qualification must not be inferred from these inspections.


- Console input is now drained before source CPU/device pause. RFB keyboard and
  pointer dispatch can reach PS/2 interrupt injection through a retained vmctx;
  pausing the LPC UART alone did not fence those aliases. The console write lock
  drains active input callbacks before device pause can hold callback-dependent
  locks. Successful rollback reopens admission only after devices and CPUs
  resume; failed rollback leaves input fenced. Source retirement permanently
  closes admission, so later resume calls cannot reopen it. The actual console
  gate/dispatch test with an in-flight callback passes in
  `retire-console-callback`; actual production quiesce/rollback ordering passes
  in `retire-console-order-verified`, and CPU retirement passes in
  `retire-console-cpus`. Native object validation passes 16 units in
  `retire-console-build`; supported non-snapshot ARM64/RISC-V validation passes
  seven units each in `retire-console-arm64` and `retire-console-riscv`. The final
  native snapshot bhyve links in `recovery-full-link/retire-console-bhyve.log`.
  This does not establish complete device/display callback qualification or
  support for standalone snapshot console quiescence. No live VM was used.


- Source startup now gates IPC command processing until main finishes time
  restoration and CPU resume. The socket is still bound and restricted before
  Capsicum; its worker waits on a mutex/condition predicate before accepting a
  command. This closes a race in which migration could destroy the context while
  main was still using it. `retire-startup-gate` exercises actual gate code with
  real threads, early publication and spurious notification; it also checks the
  production call ordering. Existing post-retirement command quarantine passes
  in `retire-startup-quarantine`.

- AMD64 retirement now fences the ACPI power-button callback under `pm_lock`
  before requesting kernel destruction. Acquiring that lock drains an active
  callback; later signals do not touch its retained context argument. The event
  remains registered while the controller serves recovery. The gate is permanent
  once source retirement begins, including failed destruction. The actual
  callback/fence concurrency fixture passes in `retire-acpi-callback`; the real
  CPU retirement fixture passes in `retire-acpi-cpus-final` after correcting its
  extraction boundary for the architecture-specific call. These fixtures do not
  establish a complete audit of every device/event callback or live lifecycle.
  Final production checks pass 14 native objects in `retire-acpi-build`, six
  supported non-snapshot objects each in `retire-startup-arm64` and
  `retire-startup-riscv`, and the full native snapshot bhyve link in
  `recovery-full-link/retire-acpi-bhyve.log`. ARM64/RISC-V snapshot mode remains
  unsupported by the maintained configuration. The two new fixtures are
  registered in native-port; the expanded full suite has not been rerun.


- Expected source destruction now exits vCPU threads without exiting the
  migration controller. Request-only libvmmapi destruction preserves vmctx;
  the controller retains pthread handles, joins every created vCPU, and only
  then closes the context. Existing checked-destroy APIs retain their previous
  close-on-success contract. Failed destruction preserves the original context;
  failed join preserves a separate controller-owned context. INTENT recovery
  drains that owner before publishing RETIRED, without destroying the VM twice.
  `retire-cpus-workers` exercises actual BSP/AP retirement bookkeeping with real
  threads and a failed partial join; `retire-cpus-intent-final` checks durable
  INTENT across join failure and retry. API, retirement-order, and real TLS
  recovery fixtures pass in `retire-cpus-api`, `retire-cpus-order`, and
  `retire-cpus-tls`. The initial expanded build exposed missing pthread
  declarations; corrected builds pass 12 native objects and five objects each
  for ARM64/RISC-V, including their VM-exit handlers, under
  `retire-cpus-build-verified`, `retire-cpus-arm64-verified`, and
  `retire-cpus-riscv-verified`. Snapshot support remains unsupported by the
  maintained ARM64/RISC-V build configuration, not a passing cross-target test.
  GDB retains a separate context and can park CPU threads; source migration now
  rejects a configured GDB server before transport setup or cutover. The actual
  source admission fixture covers this under Capsicum in `retire-cpus-admission`.
  Debugger-aware migration teardown was not implemented at this point; it is
  now implemented (see the 2026-10-21 debugger-fence entry). Full runtime device and
  thread lifecycle qualification still requires the matched lab; no live VM
  operation is performed by these tests.
  Final admission/controller builds pass all 12 native objects in
  `retire-cpus-admission-build`, and the full snapshot bhyve link passes in
  `recovery-full-link/retire-cpus-admission-bhyve.log`. The full native run
  `retire-cpus-native/results.json` records 140/141 passing suites: the journal
  fixture's extraction range accidentally included the new retirement helpers.
  Its corrected range passes in `retire-cpus-journal-final`; the original failed
  run is retained as evidence rather than relabeled as passing.

- Source retirement now stops and joins the HyperTrace reconnect connector
  after stopping the VirtIO workers and before freeing vmctx through checked
  destruction. Previously the connector could reconnect with the freed ctx
  while a source controller survived a lost ACK. `hypertrace_retire_transport`
  disconnects channels and closes spool/socket directory handles but preserves
  the epoch-query capability needed after destruction. Failed join prevents
  destruction and is retryable; final `hypertrace_destroy` closes the query
  capability. Both normal retirement and retained-context INTENT recovery use
  this ordering. `retire-transport` exercises actual teardown with a real worker,
  failed-join injection, idempotent retry and retained query authority;
  `retire-transport-order` and `retire-transport-intent` cover production order
  and recovery. Socket/connect/device sanitizer fixtures pass in
  `retire-transport-native`, real TLS recovery passes in `retire-transport-tls`,
  and ten production object builds pass in `retire-transport-build`. The current
  full bhyve link passes in `recovery-full-link/retire-transport-bhyve.log`. No live
  device query or VM destruction is performed by these fixtures.


- Initial destination resume failure now retains the committed image instead
  of dropping into discard after source retirement. The production resume
  adapter sets uncertainty before calling the restore coordinator; the initial
  session clears it only after success, while the recovery executor retains
  its post-resume observation requirement. A failed initial resume stays owned
  and quarantined, and reconnect returns EBUSY without attempting resume again.
  `initial-resume-core/result` passes the real socketpair core fault case;
  `initial-resume-owner` passes actual production owner retention/quarantine
  with VM boundaries mocked; `initial-resume-recovery` passes the real-TLS
  exchange/execution regressions. `initial-resume-all-core/results.json` passes
  all 37 isolated ATF migration state-machine/codec cases, and
  `initial-resume-build` passes ten supported native production object builds.
  This does not reconstruct a lost destination process or establish live VM
  behavior.

- The earlier broad daemon run `fresh-ack-startup/results.json` completed:
  44 cases passed, with only the intermediate cleanup-token assertion failing.
  The final rebuilt scan and affected stop/startup/consumer fixtures all pass
  in `fresh-ack-startup-final`, as recorded below; the earlier failure remains
  visible in its original artifact rather than being relabeled as a pass.


- Completed FSA1 cleanup now retries during control-daemon startup after the
  normal journal/owner audits, without requiring a surviving source VM or a new
  stop RPC. It validates each ACK's embedded FSI1 and exact durable FSD1, keeps
  incomplete or differently bound attempts, and deletes in bounded batches
  under the publication/process locks. FSI1, FSD1, program/receipt/cohort and
  process/reaper/handle evidence remain. An unavailable/corrupt dependency
  defers cleanup rather than changing stop completion. The final rebuilt
  `fresh-ack-startup-final` passes stop/RPC/cleanup fault, daemon startup and
  consumer fixtures and links the sanitized daemon without starting it. The
  earlier broad `fresh-ack-startup` run used the intermediate scan before
  different-token preservation was fixed; its cleanup assertion is superseded
  by these final fixture results. No live journals were accessed for cleanup.

- `source-capsicum-native/results.json` records 138 native suites passing with
  the pre-sandbox source storage, rollback failure handling, and full source
  IPC admission tests. This native suite is separate from the daemon startup
  cleanup tests above and does not claim live VM qualification.


- The full actual `vm_do_migrate` IPC handler now has a Capsicum integration
  fixture in `source-admission-capsicum`. Real nvlists carry inherited private
  descriptors into confined child processes. Missing TLS, cached storage
  failure, replacement directory, TLS setup failure and binding-export failure
  prevent migration execution; valid admission reaches the actual FRESH HELLO
  callback. A simulated post-INTENT failure leaves source quarantine persistent
  across a second IPC request without reconnecting or rerunning migration.
  TLS and VM/core execution boundaries are mocked in this fixture; real TLS
  itself retains its separate Capsicum test in `migration-tls`. Kernel/VM
  operations remain unexecuted. The descriptor audit confirms source retirement
  uses the retained vmctx control descriptor and the preopened HyperTrace query
  descriptor, rather than reopening device paths in capability mode.


- Sandboxed source storage is now prepared before IPC publication and
  `caph_enter`. The immutable canonical directory descriptor and any startup
  error are retained; a request descriptor can only match the pinned inode.
  This replaces the previous absolute-path canonical lookup inside the source
  IPC handler, which would fail with ECAPMODE. Missing storage does not prevent
  ordinary VM startup but must be corrected before starting a migration-capable
  instance. `source-storage-capsicum` runs a real confined child, proves absolute
  lookup is refused, then successfully creates its controller lock, immutable
  owner and durable INTENT using only the prepared fixture directory. It also
  verifies aliases, replacement rejection and cached preparation failure. No
  live journal, device or VM is used.

- The pre-COMMIT device-pause rollback now checks CPU-resume failure instead of
  unconditionally reporting a runnable source. Both failed device rollback and
  failed CPU restart leave the source conservatively non-runnable/quiesced.
  `quiesce-rollback` tests these branches plus the existing retirement/no-resume
  paths using the actual production functions with VM boundaries mocked.


- Current production-entry integration evidence: `fresh-entry-native/results.json`
  records 136 unique native suites, all passing after source TLS admission and
  prepared destination wiring. `fresh-entry-owner-final` verifies each missing
  credential/journal/startup-fence prerequisite refuses before session I/O,
  binding-export failure does not run the session, and a prepared tracing
  receiver retains ownership after the simulated lost release. `fresh-entry-tls`
  exercises real TLS with mocked VM boundaries, ordered retirement, one resume
  and lost-ACK recovery. `fresh-entry-build` passes ten native production objects;
  `recovery-full-link/fresh-entry-bhyve.log` records the current full native link.
  `fresh-entry-arm64` and `fresh-entry-riscv` each pass four supported baseline
  objects; snapshot mode remains explicitly unsupported by maintained build
  options on those targets. These checks do not execute a VM or qualify live
  migration, destination process-loss reconstruction, or missing collector proof.


- Production migration readiness audit: source and managed destination now
  admit tracing under explicit preconditions. The shared `migration_prod_fill_hello` starts with PRECOPY/DEVICE_DIRTY.
  The production source/destination callbacks now add FRESH through
  `migration_fresh_advertise` only after both exported TLS certificate pins,
  a private recovery directory, and directory fsync succeed. Missing pins, bad
  descriptors, non-directory files, permissive modes, and sync failure leave
  FRESH unadvertised. Both actual callbacks pass isolated fault fixtures in
  `fresh-preflight`; `fresh-preflight-build` passes ten production object builds.
  The managed receiver now uses an internal prepared entry only after retaining
  its listener/credentials and creating its worker. Tracing admission requires
  this entry, a held startup fence, TLS credentials, and private journal storage.
  Unmanaged entry points still refuse tracing. Source initiation requires TLS. The core already rejects peers
  whose FRESH capability differs and requires its retirement/record callbacks.
  `pci_de_vdtr` now declares PCI_MIGRATION_VIRTIO_FLAGS after the device audit:
  its only guest payload write is the control-copy path in fill_desc, which
  now marks the actual written iovec spans after copying and before releasing
  the request/mappings. Common VirtIO tracks used-ring writes. Both workers
  serialize guest/queue changes with vsd_mtx; pause closes reader admission,
  drains an active reader with a deadline, and retains the mutex on success.
  Snapshot validation/compatibility and pause/resume callbacks are registered.
  Coordinated fresh-session stop remains responsible for external collector
  state; the device codec does not restore it. The final device sanitizer
  fixture in `vtdtr-dirty-final` checks post-copy marks, exact byte coverage for
  split/contiguous controls, no marks for malformed controls, registration,
  and existing locking/reset/pause paths. `recovery-full-link/vtdtr-dirty-bhyve.log`
  records a successful production bhyve link. No VM/device operation was run.
  Admission/failure tests cover missing credentials, storage and startup fence,
  binding-export failure, and retained ownership after a lost release. Destination process-loss reconstruction also remains unavailable.
  Certificate-binding export errors are now propagated before either production
  session runs; the source remains runnable and the destination stays fenced.
  The current TLS exporter ordinarily cannot fail on a valid secure channel;
  fault injection verifies the adapter contract if export does fail. The new
  `migration-production-binding` native suite exercises both actual setup blocks,
  including plaintext compatibility and EACCES/EIO/EOPNOTSUPP failure paths.


- Approved orphan retirement and FSA1 cleanup are now implemented. The optional
  `migrate.recover_source_name` is a local lookup hint, never retirement proof.
  Original TLS pins, immutable ownership, exclusive controller lock and durable
  INTENT precede atomic kernel identity-checked destruction; a drained exact
  witness and durable RETIRED still precede RELEASE. There is no name-only
  fallback, module auto-load, VM start or source rollback. Fault fixtures cover
  identity/unsupported-ioctl/live-witness failures and authentication EBUSY.
  `approved-orphan-production-final` passes ten production object builds;
  `recovery-full-link/approved-libvmmapi.log` and `approved-bhyve.log` record
  the current library build and full snapshot-enabled bhyve link.

- Completed authenticated stop requests retire only matching FSA1 records under
  the same publication/process locks used by publishers. FSI1, FSD1, collector
  census/program receipts and all process/reaper/handle evidence remain. Cleanup
  revalidates the entire candidate set before unlinking and syncs the directory
  on partial failure and empty retry. Failures do not revoke durable completion.
  Late ACK publication validates the immutable recipient and uses FSD1 without
  recreating the ACK; completion retries still compare the full retained census.
  `approved-fsa-targeted/stop.log` passes the final sanitizer fixture covering
  authenticated RPC cleanup, unlink failure, post-unlink fsync failure, empty
  retry, late publication, foreign-session preservation and corruption refusal.
  These tests modify only isolated fixtures. No live journals were removed.
  The broader daemon run in `approved-fsa-retirement-final/results.json`
  passes all 45 component suites. The final RPC cleanup wiring is additionally
  compiled and tested in `approved-fsa-targeted`; the broader run began before
  that last wiring edit. Named orphan recovery also passes the real-TLS fixture
  in `approved-orphan-tls-final`, with VM operations mocked, and command routing
  passes in `approved-orphan-command-final`.


- The complete maintained native-port suite passes at the current revision:
  134 unique suites, all status zero in
  recovery-current-native-port/results.json. This includes the new recovery-only
  command and query-gate checks plus real-TLS recovery, source ownership and
  controller contention, journal adapters, guest/device/transport, library,
  collector and DTrace component regressions. Logs retain each result. These are
  isolated native/sanitizer fixtures, not live host/guest qualification, and do
  predate the approved orphan-retirement and journal-deletion changes.

- The updated bhyverun entry point now passes production cross-compilation
  alongside migration_session, migration_receiver and hypertrace for both ARM64
  and RISC-V. `recovery-entry-arm64` and `recovery-entry-riscv` each record four
  successful non-snapshot object builds with ELF machine identities 183 and 243,
  respectively. The maintained build marks snapshot mode unsupported on these
  targets; it is recorded as such, not counted as passing. Existing world sysroots
  supply target headers. These checks cover compilation of recovery-option
  rejection in unsupported configurations, not cross-target full linking or
  runtime execution. No live system was modified.

- Matched live acceptance preparation is tracked in
  tests/fresh-session-live-matrix.json: fifteen explicitly unexecuted cases cover
  baseline isolation, stop/restore freshness, authorization, collector crash/proof
  boundaries, daemon restart, migration ordering, RELEASE/ACK loss, source process
  exit, exact INTENT recovery, identity rejection, uncertain destination resume,
  and repeated fresh sessions. Each case identifies its invariant and required
  artifacts. README.5BSD documents the seven-option recovery-only invocation and
  evidence requirements, updating its stale retained-process-only description.
  Documented options match bhyverun's current dispatch.

  Preparation grants no execution authorization. Every case is not-run; missing
  evidence and blocked paths are not passes. Runtime libraries and dirty-tree
  identities must match. Cross-host ordering requires bound protocol/journal
  evidence, not unsynchronized timestamps. Live fault-injection controls still
  need lab preparation, migration tests remain blocked by capability gates, and
  QEMU smoke cannot qualify the bhyve VirtIO DTrace path. No live tests ran and
  no pending destructive change was implemented.

- Native full-link validation now passes with snapshot support both enabled
  and disabled, including a yes -> no -> yes transition in the same object tree.
  Maintained mode markers report the selected mode; symbol inspection confirms
  migration_prod_source_recover_restart is absent in the non-snapshot binary and
  present again after rebuilding with snapshots. The complete linked artifacts
  and SHA-256 manifests are retained under recovery-full-link/mode-artifacts.
  no-snapshot.log and snapshot-restored.log record the builds. The original
  single-build manifest is marked historical; binary-manifest.json describes
  the current restored snapshot-enabled artifact. Earlier checksum records
  identify that earlier build, not the current file at the reused object path.

  This verifies native linking and mode-transition rebuilding, not execution of
  the command or a VM. Both binaries remain unexecuted and uninstalled. The
  pending orphan-retirement API and FSA1 deletion approvals are unchanged; this
  validation adds neither capability. Other architecture/full-system and live
  qualification gaps remain open.

- Still-live orphaned-source recovery has a concrete proposed path, pending
  explicit approval to implement: after canonical-root ownership, exclusive
  controller locking, immutable INTENT/COMMIT binding and original-peer TLS
  authentication, use an operator-supplied VM name only as a lookup hint for
  the existing VMMCTL_VM_DESTROY_IDENTITY ioctl. The kernel must match the exact
  journal VM ID and epoch atomically. A userspace helper would open only the
  existing /dev/vmmctl, without vm_openf, VM creation/reinitialization or module
  auto-load. Destruction acceptance would not authorize RELEASE: recovery must
  still observe the exact drained retirement witness and durably persist RETIRED.
  Missing names, changed incarnations, absent devices and uncertain destruction
  remain errors, never proof of completion. No rollback or source resume follows.

  Automatic approval review rejected adding this production helper because it
  introduces an irreversible orphan-VM destruction capability beyond what that
  review considered explicitly authorized. The rejected command made no changes;
  no helper, prototype or new destruction call was added. Approval was requested
  for implementation and mocked tests only, excluding live destruction.
  Existing fail-closed recovery remains intact. The existing extracted-kernel
  `vm-destroy-identity` suite passes in `orphan-source-existing-kernel-check`,
  covering identity/reset races, MAC/privilege denial and preflight retry without
  live kernel operations. This verifies a prerequisite, not orphan recovery.

- A complete native snapshot-enabled bhyve development build now links in
  `recovery-full-link`, using maintained Makefiles and all logical CPUs. Current
  libvmmapi, lib9p and libuvmem were built in the same isolated object tree.
  Installed architecture headers lacked VM_RESET_PPTDEV; a private source-header
  overlay supplies this checkout's machine and x86 headers without changing the
  system. Environment CFLAGS defaults preserve maintained per-file flags (the
  initial command-line CFLAGS override incorrectly suppressed one include path
  and was discarded). The final libvmmapi and bhyve builds were clean rebuilds.

  `maintained-results.json`, per-component logs and `binary-manifest.json`
  record the commands, environment, statuses, ELF dependencies and checksum.
  The result is an AMD64 FreeBSD 16 PIE executable containing the restart
  recovery and query-only setup symbols. Its SHA-256 is
  95571066f974646028ed0ae6b11aa7883296cf1b82c1458c8c554dc931a08e7b.
  This closes native snapshot full-link validation at this revision; other
  libraries and toolchain came from the host, so it is not a clean buildworld,
  cross-architecture full link, matched deployment, or runtime qualification.
  The dynamically linked executable needs matching libraries when later tested;
  no binary was executed or installed, and no VM/device operation occurred.

- bhyve now dispatches a recovery-only command before VM initialization when
  any of migrate.recover_source_fd/vmid/epoch is supplied. All three values and
  the four migrate.tls credential settings are required. The command rejects
  guest names, restore and receiver settings, validates unsigned decimal bounds,
  stream descriptor type and credential descriptors, opens the canonical source
  journal root, and validates immutable ownership and phase. Only INTENT needs
  query-only HyperTrace setup; durable retirement can recover without reopening
  the query device. The existing authenticated restart adapter owns execution;
  all command outcomes close the journal and any query descriptor and exit
  instead of falling through to VM startup. Non-snapshot builds explicitly
  reject the recovery settings. Operator-supplied source identity must come
  from trusted local records. bhyve.8 documents invocation and limitations.

  `migration-restart-command-final` passes sanitizer checks for malformed and
  overflowing numbers, missing/conflicting settings, missing ownership, query
  setup failure, conditional device need and cleanup after adapter failure.
  This fixture uses real private journals/socket descriptors and substitutes
  canonical root access, query setup and the independently tested restart
  adapter. It is registered in native-port.py. The production validator now
  includes bhyverun.c; all ten native objects pass in
  `migration-restart-command-production-final` across both snapshot modes.
  Full linking, fresh whole-system builds and live end-to-end recovery remain
  unverified. Still-live source recovery after controller loss remains refused;
  no live device, daemon or VM was operated and migration capability stays gated.

- Recovery-only HyperTrace setup now opens the retirement-query descriptor
  without normal tracing initialization. `hypertrace_session_recovery_open`
  refuses an existing initialized/prepared instance, opens only the HyperTrace
  device with no-follow/nonblocking/close-on-exec flags, and under Capsicum limits
  the descriptor to CAP_IOCTL and HYPERTRACE_IOC_EPOCH_QUERY. It opens no daemon
  journals, attaches no VM, and starts no connector threads. Its paired close
  resets the descriptor and unavailable error state. Without Capsicum, the
  kernel device's normal permission policy applies; no capability restriction
  is claimed for that build configuration.

  `recovery-query-gate` passes an extracted-production ASan/UBSan test with
  substituted device calls: exact rights/command whitelist, open/rights/limit
  failures and cleanup, normal-lifecycle refusal, repeated setup/close, live
  epoch refusal, malformed ioctl response and unavailable evidence. It is
  registered in native-port.py. Eight production objects pass in
  `recovery-query-gate-production`. No real device was opened. This addresses
  the discovered dependency of INTENT recovery on normal HyperTrace startup;
  the pending recovery-only command must call this setup and paired cleanup.

- Source migration now has the fixed host recovery root
  `/var/db/bhyve/migration`. The maintained BSD.var.dist specification provisions
  /var/db/bhyve as root:wheel 0755 and its migration directory as root:wheel 0700,
  tagged for the bhyve package. Production root opening walks from / using
  descriptor-relative O_NOFOLLOW directory opens, verifies every ancestor is
  root-owned and not group/other-writable, and applies the private effective-owner
  check to the leaf. It does not create missing directories or fall back to
  another location. The source migration IPC validates recovery_fddir against
  this canonical inode before pinning it for the controller lifetime; alternate
  private roots now fail. Deployment must preserve the directory and permanent
  ownership/controller records. No existing journal migration is automatic.

  `source-canonical-root` passes sanitizer checks using an isolated filesystem
  root for missing directories, wrong ancestor owner, writable parent, nonprivate
  leaf, leaf/ancestor symlinks and replacement of an already pinned inode.
  Eight production objects pass in `source-canonical-root-production`.
  `mtree -C` validates the specification and reports the expected root ownership
  and directory modes. No system directory was created, installed or changed.
  The restart API still accepts a trusted preopened root; the pending post-exit
  controller command must obtain that descriptor with the canonical opener.
  Independently trusted source-lifetime selection and still-live source recovery
  remain open. This is source-root integration, not live migration qualification.

- Source migration and restart recovery now serialize controller ownership
  with a permanent `source-controller-<vmid>-<epoch>.lock` in the trusted root.
  Acquisition checks private file/directory ownership, refuses symlinks and
  multiply linked files, takes a nonblocking exclusive flock, and syncs the lock
  and directory before returning a close-on-exec descriptor. The original source
  acquires it before immutable INTENT ownership publication and retains it
  through retirement, reconnects and confirmation until process exit. Restart
  recovery acquires the same lock before TLS and holds it through completion or
  failure. Lock files are never removed. Lock possession is not retirement proof.

  `source-controller-contention` passes sanitizer tests with a real competing
  process, verifies EBUSY before TLS/retirement queries, and succeeds after the
  original descriptor closes. `source-controller-journal` passes publication and
  sync-failure retries; `source-controller-real-tls` passes exchange, execution
  and restart binaries. Eight production objects compile successfully in
  `source-controller-production`. Tests use temporary journals and mocked VM
  boundaries, not live VMs. This is exclusion within one trusted directory;
  canonical directory selection across restart remains open. Low-level helper
  APIs that require exclusive caller ownership retain that precondition.

- Restart recovery now has a real-TLS integration fixture in
  `tests/migration-recovery-exchange.py`. In addition to the exchange and
  execution binaries, it compiles the actual production INTENT/restart adapters
  into a third binary and runs them against the maintained TLS implementation
  and destination recovery executor over local socket pairs. Temporary files
  provide real immutable ownership and phase journals; only kernel retirement
  and VM operations are substituted. Any attempted VM stop/destruction aborts
  the fixture. No live tracing device or VM is accessed.

  `source-restart-real-tls` passes all three binaries under ASan/UBSan, including
  lost/corrupt ACK retries, uncertain destination resume, already-running
  destination recovery, an INTENT-only exact retirement witness, and a live
  source that stays at INTENT without releasing the destination. It checks
  durable phases, at most one destination resume, and no repeated retirement
  query once retirement is durable. This closes a mocked-TLS coverage gap for
  the restart adapter; it does not supply canonical root selection or a
  post-process-exit recovery command. Existing bhyvectl recovery still addresses
  only the retained bhyve process, so that controller wiring remains required.

- `migration_prod_source_recover_restart` now connects immutable ownership
  reload to authenticated source recovery. Given an independently known source
  lifetime and an exclusively owned trusted journal root, it loads the original
  attempt, establishes TLS, checks both original certificate fingerprints,
  finishes INTENT only with an exact kernel retirement witness, and calls the
  existing RELEASE recovery executor. It has no live VM context and cannot
  destroy or resume a VM. A still-live source returns EBUSY; absent devices and
  other witness errors are not retirement. Every established channel is cleaned
  up on failure or success, and exchange failure preserves the durable phase.

  `source-restart-adapter-final` passes ASan/UBSan cases for missing ownership,
  missing credentials, TLS initialization/binding failure, either wrong
  certificate, live-source refusal, unavailable witness, successful retirement,
  exchange failure and successful retry without a second retirement query.
  TLS and kernel boundaries are mocked in this adapter test; real journal I/O
  and the extracted production adapter run. Eight production objects pass in
  `source-restart-adapter-production`. No live VM or tracing device was operated.
  This adds the recovery API, not a complete restart command: canonical root
  selection, independently trusted lifetime acquisition and controller/CLI
  wiring remain open. Recovery of a still-live source after controller loss
  also remains unresolved. The migration capability remains disabled.

- Immutable source ownership now has a strict restart reader keyed by an
  independently known source VM ID and epoch in a trusted directory.
  `migration_source_owner_load_at` takes the existing ownership lock, validates
  private regular-file metadata, canonical HMR2 bytes/checksum, INTENT-only
  ownership phase and exact filename/lifetime binding, then syncs the file and
  directory before publishing its output. It creates no evidence and leaves
  output unchanged on failure. Existing production owner validation now uses
  this reader and compares the full expected attempt. The reusable HMR2 decoder
  is serialization only, not peer authentication or RELEASE authority.

  `source-owner-restart-reader-integrated` and
  `source-owner-restart-retained` pass ASan/UBSan checks. Coverage includes every
  single-byte record corruption, truncation, trailing bytes, public permissions,
  wrong lifetime, wrong ownership phase, missing records, both sync failures,
  exact retries, and the existing source-retirement/retained-owner cases.
  `source-owner-restart-production-integrated` records production compilation.
  The initial wrong-lifetime fixture accidentally equated source/destination
  epochs; it was corrected to a valid distinct wrong lifetime before passing.
  A restarted controller still needs canonical root selection and an entry point
  that obtains the independently trusted lifetime and authenticates the peer;
  adding a record reader does not close those orchestration gaps or authorize
  migration. The migration capability remains disabled and no VM was operated.

- Source-owner durability coverage now includes failure of the parent-directory
  sync after the immutable ownership file has been renamed. The
  `source-owner-directory-sync` sanitizer run reopens the directory, verifies
  that a competing destination cannot replace the visible original binding,
  and confirms that INTENT recovery rejects the competing attempt before any
  kernel retirement query. An exact retry propagates another directory-sync
  failure, then succeeds after durability is established. Existing checks for
  file-sync failure, concurrent ownership attempts, identity-checked destruction
  and retirement-publication retry also pass. These are real temporary journal
  files with injected sync errors and mocked VM operations; they do not simulate
  power loss or prove storage persistence across reboot. Canonical recovery-root
  selection across controller restart and end-to-end recovery remain open;
  the existing directory pin covers only one controller lifetime.

- Production adapter compilation is now reproducible with
  `tests/migration-production-build.py OUTPUT [--target ARCH --sysroot SYSROOT]`.
  It queries the maintained bhyve Makefile for compiler flags and selected
  sources, generates the provider header offline with `dtrace -h`, compiles
  selected production units in parallel, and checks each ELF machine identity.
  Outputs must be under /usr/obj. Commands, configuration, logs and results are
  retained. It respects BHYVE_SNAPSHOT in BROKEN_OPTIONS: snapshot-enabled
  ARM64 and RISC-V configurations are explicitly recorded as unsupported,
  rather than forced or counted as passing. Their machine snapshot headers
  are placeholders in the current source tree as well as the existing sysroots.

  `migration-production-supported` passes 14 production-object checks:
  AMD64 migration_session, migration_receiver and hypertrace in both modes,
  plus migration_tls and snapshot with snapshots enabled; ARM64 and RISC-V
  migration_session, migration_receiver and hypertrace with snapshots disabled.
  The cross builds use /usr/obj/usr/src/{arm64.aarch64,riscv.riscv64}/tmp.
  libvmmapi now declares vm_arm64_cpu_features at file scope so its public
  pointer signature does not depend on a newer installed machine/vmm.h.
  The earlier forced cross-snapshot failures remain in migration-production-cross
  as diagnostic evidence; they do not represent supported snapshot builds.
  These are compile checks against existing world headers, not full links,
  refreshed world/kernel builds, migration support on non-AMD64 targets, or live
  qualification. No tracing device, module, daemon or VM was operated.

- Migration destination recovery ACK status now describes the most recent
  attempt. The production adapter clears ack_sent before credential, retained
  incarnation, startup-fence, quarantine and TLS checks, preserving running VM
  and resume-uncertainty state. Previously an early failure after a successful
  recovery could expose the preceding attempt's ACK through receiver status.
  The generic executor also clears ACK status before rejecting invalid operation
  callbacks. Neither change alters release authorization, persistent phases,
  source-retirement order, VM ownership or resume behavior.

  migration-recovery-ack-status passes migration-retained-owner,
  migration-recovery-exchange (including its execution test) and
  migration-receiver under ASan/UBSan. Production-adapter regression cases cover
  missing credentials, disabled tracing, changed incarnation, inconsistent
  startup fence, TLS setup rejection and retained quarantine, verifying no extra
  executor/resume call and no stale ACK. Existing TLS cases still cover lost or
  corrupted ACKs, one resume, durable ordering and uncertain-resume quarantine.
  No live VM, tracing device, installed daemon or module was operated. FSA1
  deletion remained unimplemented at this point; it was implemented later
  (see the approved FSA1 cleanup entry and the 2026-10-21 verification note).

- A non-destructive FSA1 retirement planner now inventories only canonical
  `.fresh-ack.<sha256>` files whose embedded FSI1 exactly matches a durably
  completed stop. It holds the outbound journal/process lock across FSD1/FSI1
  verification and inventory, validates private regular-file metadata, checksum
  and filename binding, bounds and sorts the result, and preserves the caller's
  previous result on error. It does not unlink, rename, rewrite or schedule
  removal of any journal. Other stops' valid ACKs are excluded and retained.

  The reviewable mutation scope is only these per-collector acknowledgements.
  FSD1, FSI1 and all inbound receipts, cohorts, program/handle/process bindings
  and shared owner/reaper evidence remain retained. An eventual mutation must
  revalidate under the same locks rather than trust a previously returned list,
  sync the parent after partial or empty retries, and cover late collector ACK
  publication and stop-publisher retries after pruning. Startup reconstruction
  of inbound records remains a separate dependency; this planner does not bypass
  it. Actual deletion and its maintenance hook were not implemented at this
  point; both are now implemented (see the 2026-10-21 verification note).

  Regression cases verify refusal before completion, exact candidate selection,
  another stop's ACK exclusion, private-mode and corrupt-record refusal,
  unchanged inode/content, unchanged result on error, and empty inventory.
  fresh-stop-ack-plan-daemon rebuilds all 12 daemon translation units, links
  the daemon, and passes all 45 component suites under ASan/UBSan. No live
  daemon, tracing device, module or VM was operated; no journal deletion code
  or maintenance hook was added.

- Standalone FSD1 recovery lookup now validates the private regular file,
  exact size, single link, owner/mode, magic/reserved fields, bounded owner count,
  checksum, exact embedded stop identity and canonical empty-census digest. It
  requires the matching permanent FSI1 admission fence and synchronizes both
  file and parent before reporting durable completion. Missing FSD1 falls back
  to ordinary stop proof collection; malformed or mismatched evidence fails.

  The stop coordinator checks this completion first, so a restarted daemon can
  recover a completed collector stop without old per-recipient journals, live
  collector sockets, process queries or kernel queries. A nonempty census digest
  is the checksum-protected summary written by the trusted publisher; lookup
  does not reconstruct retired identities. The publisher still compares that
  digest against the full census on publication/republication. The live SESSION
  STOP RPC retains VM attestation and gate ownership checks. FSD1 does not grant
  VM retirement or destination RELEASE authority, and FSI1 remains mandatory.

  fresh-stop-recovery-progress passes coordinator selection/error tests.
  fresh-stop-recovery-final passes missing-fence, corrupt-summary, metadata,
  hardlink/symlink, file/parent-sync and empty-receipt-directory recovery tests.
  The initial symlink assertion expected ELOOP; this host returns EMLINK for
  O_NOFOLLOW, verified directly, and the corrected fixture accepts either refusal.
  fresh-stop-recovery-empty passes empty-session lookup and rejection of a
  checksummed but noncanonical empty digest. fresh-stop-recovery-daemon rebuilds
  all 12 daemon translation units and links the daemon; 44 of its 45 suites pass,
  with only the corrected symlink assertion failing in that original run. The
  corrected stop suite and final empty-session suite pass against the same objects;
  validated-results.json maps all 45 passing component results to their original
  or supplemental evidence without replacing the original failed result.
  No live daemon, tracing device, module or VM was operated. No journal deletion
  is enabled: startup's cohort reconstruction and collector-owner recovery, and
  other receipt/cohort/program/shared-owner consumers, still need a coordinated
  retirement transaction so partial deletion cannot resurrect or lose evidence.

- The coordinator now durably publishes FSD1 before returning completed
  collector-stop status. The publisher independently repeats the complete
  cohort/receipt census, verifies every exact FSA1, sorts the owner/program/
  handle identities, and revalidates the permanent source fence and suspended
  kernel gate before publication. Missing evidence or a publication/sync error
  remains incomplete. Exact retry validates and synchronizes the existing
  record; conflicting or corrupt evidence is not repaired.

  FSD1 is a private, immutable 160-byte record named
  `.fresh-done.<vmid>.<epoch>` in the outbound journal. Bytes 0..3 are FSD1,
  4..7 are reserved zero, 8..87 contain the complete FSI1 fence, 88..95 contain
  the little-endian owner count, 96..127 contain SHA256 of sorted 132-byte
  identities (76-byte owner, 32-byte program digest, 24-byte handle lifetime),
  and 128..159 checksum the preceding bytes. Empty censuses use SHA256 of the
  empty sequence. Source session, epoch and stop token remain bound by FSI1.

  Fault coverage includes missing FSA1, completion-file fsync failure,
  post-publication directory-fsync failure and exact retry, bad checksum,
  correctly checksummed mismatched census digest, empty epochs and reopened
  journals. fresh-stop-completion-progress passes the extracted coordinator
  test, including refusing completion when summary publication fails.
  fresh-stop-completion-daemon rebuilds all 12 daemon translation units, links
  the daemon, and passes all 45 component suites under ASan/UBSan. The empty-epoch
  fixture edit overlapped its initial compilation, so fresh-stop-completion-empty
  separately rebuilds and passes the final census, empty-epoch and reopened-journal
  cases against those same objects. No live daemon, tracing device, module or VM
  was operated. FSD1 currently supplements the original
  evidence: standalone recovery lookup is now connected as described above;
  dependency-aware retirement remains required before any journal deletion. It is not a
  source-VM retirement witness, migration COMMIT, or destination RELEASE.

- The retirement audit found that the fresh-stop census could omit HCB1
  cohort members whose HCR1 publication had not completed. It now compares
  canonical HCR1 identities against each matching ingress cohort while holding
  the permanent outbound source cut. Missing members refuse with EBUSY; corrupt
  cohort evidence refuses with its validation error. No stop query repairs or
  drops that evidence, and failures leave the caller's prior census unchanged.
  An absent cohort remains compatible with legacy individual receipts, which
  still require their immutable program/handle evidence.

  fresh-stop-cohort-census rebuilds the directory implementation and relinks
  against the consumer-first-registration-daemon baseline. The census, stop
  coordinator and host-ingress suites pass under ASan/UBSan. Tests cover HCB1
  before HCR1, HCR1 before HCP1, completed recovery, and cohort corruption.
  The additional reopened-journal regression passes both incomplete-member
  refusal and successful recovery from disk. This fixes a prerequisite
  for a trustworthy terminal stop record; the FSD1 publisher above builds on it.
  Neither change authorizes deletion of FSI1, FSA1, cohorts or receipts. No live daemon, tracing
  device, module or VM was operated.

- First-delivery admission now requires program registration as well as the
  completed admission/replay gates. queue_recovered_consumer defers an
  unregistered receiver even with no historical receipts and does not publish
  its owner. The watcher independently excludes unregistered receivers from
  both new cohorts and queued work; a prequeued send refuses before any frame
  bytes. Successful registration resumes recovery and requests a watcher scan.
  HPI1 remains supported for legacy work; frozen HPI2 work still requires its
  verified process descriptor and exact handle binding. Neither initial startup
  nor reconnect requires a wire-format change: the maintained collector already
  sends its program registration on both paths.

  Tests exercise the pre-registration watcher with and without a deferred flag,
  zero-byte first-send refusal, invalid registration preserving the gate, and
  successful HPI1/HPI2 registration. Ownership and lost-ACK fixtures explicitly
  model registered legacy receivers so the new gate cannot mask their original
  assertions. consumer-first-registration-daemon rebuilds all 12 daemon
  translation units, links the daemon, and passes all 45 component suites under
  ASan/UBSan. No live daemon, tracing device, module or VM was operated.
  Remaining migration recovery, journal retirement and live qualification are
  not implied by this admission check.

- Replay ownership now distinguishes a same-numeric-PID incarnation using the
  receipt's immutable HCP1 owner, including its birth identity. The mutable HCO1
  is a fallback only when the receipt has no frozen program owner, and must match
  exactly; missing owner evidence cannot identify a new incarnation as the old
  one. Changed birth requires settled execution plus the same durable process,
  descendant and kernel-handle retirement proofs as a changed PID. The final
  locked cohort scan applies the same identity rule, including after HCO1 rotates.

  consumer-incarnation-policy passes the extracted policy/evidence tests. The
  rebuilt directory implementation and relinked daemon pass host-ingress and
  fresh-session-stop-step under ASan/UBSan in consumer-incarnation-retirement.
  Journal-backed tests reject changed birth with a live old process or live old
  handle, permit exact rotation/retry with all three proofs, then reject a later
  reconnect with unproven old handle retirement even though HCO1 already names
  the new incarnation. Settled legacy receipts without retirement evidence now
  refuse incarnation rotation. Kernel observations are mocked in these tests;
  no daemon, tracing device, module or VM was operated.

  Modern frozen-receipt replay now waits for HPI2 registration before owner
  rotation or job publication. Registration verifies the peer's kernel birth;
  a hello birth string alone cannot open this gate. The admission/registration
  census serialization resumes deferred recovery once, whether registration
  arrives before or after the initial admission gate opens. HPI1 cannot claim
  modern work. The inbound watcher skips deferred recipients, and successful
  registration requests a new scan. Resumed jobs open their send gate under the
  job-list lock before dispatch can take them. Ordinary sends independently
  refuse missing registration, missing process pins, deferred replay, or a
  mismatched frozen handle before sending any frame bytes.

  Regression coverage exercises failed birth verification, deferred recovery,
  exact registration retries, closed-pin refusal, watcher deferral, and four
  zero-byte send refusals. consumer-registration-replay-final rebuilds all 12
  daemon translation units, links the daemon, and passes all 45 component suites
  under ASan/UBSan. The earlier consumer-registration-replay-daemon run exposed
  a test's deliberately closed pin; the final fixture explicitly checks refusal
  before restoring a mocked verified pin for its subsequent cases. No daemon,
  tracing device, module, or VM was operated. These checks cover already-frozen
  modern receipts. The subsequent first-delivery change above closes admission
  before registration while preserving HPI1 registration for legacy work. These
  checks do not establish end-to-end live reconnect or migration qualification.

- Auditing the admission dependencies before journal compaction exposed a
  legacy replacement-PID replay check that accepted kill(pid, 0) == ESRCH as
  process-exit evidence. That inference is removed. A different PID may reuse
  a consumer session only for execution-settled receipts and after the exact old
  receipt proves durable process exit, durable empty-reaper exit, and retirement
  of its registered kernel handle. Missing/corrupt/unsupported evidence refuses
  replacement; pending and parsed-only work retains its original owner. Existing
  UID and cohort-completeness checks remain required. The final locked cohort
  scan now independently revalidates HCP1/HHL1/HPB1, shared HPE1/HRE1 and kernel
  handle retirement for each different-PID member. It no longer tests the current
  occupant of a historical numeric PID, and it cannot rotate past a member that
  appeared after the earlier receipt snapshot without that member's proof.

  consumer-restart-retirement extracts the production policy and evidence helper
  and passes ASan/UBSan checks for unsettled work, UID mismatch, missing-PID errno
  without proof, each insufficient/error proof, and all-three success. The actual
  ingress regression now expects refusal for a reaped child whose old legacy
  receipts lack durable retirement evidence. The subsequent same-numeric-PID
  incarnation change above now extends the retirement requirement to birth changes.
  The daemon rebuild/relink and four affected ingress/stop/admission suites pass
  in consumer-restart-retirement-daemon after correcting the targeted harness to
  include host-ingress's required ioctl wrapper. The initial fixture failed at
  its preexisting ingress ioctl assertion with that wrapper omitted; it is not
  counted as a passing run. The final cohort recheck and additional journal-backed
  occupied-PID regression pass with a rebuilt directory object and daemon relink
  in consumer-restart-cohort-retirement (host-ingress and fresh-session-stop-step).
  The journal-backed test rejects a live old process and a live old kernel handle,
  then permits exact replacement/retry with all durable proofs even while the old
  numeric PID is occupied. Kernel process/handle observations are mocked; no
  daemon, tracing device, kernel module or live VM was operated.

- Control-daemon startup now reconciles the verified consumer-receipt inventory
  before setup_threads admits workers. recover_collector_owners first resolves
  durable exit evidence or an already-retained live pin. Otherwise it attempts
  the existing same-boot HPB1/kernel-birth live-pin recovery and checkpoints again
  to cover exit racing that recovery. Duplicate receipts reuse the retained key;
  the periodic reconciler takes over after startup.

  Missing/legacy evidence, absent processes, stale identities and unsupported
  evidence queries remain unresolved; none becomes a stop or fabricated process
  exit. Malformed journals, I/O failures, permission failures and resource
  exhaustion fail startup instead of silently dropping the recovery obligation.
  A simultaneous daemon/collector loss before durable evidence remains unresolved,
  as does a collector that exits before its pin can be reconstructed.

  collector-startup-recovery extracts the production startup method and passes
  sanitizer checks for durable exit, existing live pin, new live pin, raced exit,
  unresolved identities followed by later recipients, and fatal errors at each
  stage. The journal-backed component in collector-startup-daemon also passes:
  two receipts recover one exact descriptor, a repeated pass opens no additional
  process, and absent peers leave the restarted registry empty. Startup ordering
  was inspected: recovery runs after cohort/execution inventory and before
  setup_threads. The sanitized daemon build/link and all 45 component suites
  pass in collector-startup-daemon. No daemon, tracing device, kernel module or
  live VM was operated.

- Retained collector descriptors now receive bounded periodic reconciliation in
  the existing close_filedescs worker. Each wake copies at most 32 registry keys
  in rotating key order, without allocation, then performs journal work outside
  the socket-retirement mutex. A removed cursor remains a valid ordering point;
  a small registry is visited once per batch. Shutdown is checked between keys.
  Live collectors keep their pins. Explicit exit preserves affirmative HRE1 when
  available, synchronizes shared HPE1, and only then releases the descriptor.
  Query/publication failures leave the pin for a later retry and do not publish
  FSA1 or infer that descendants stopped.

  The identity-level checkpoint operates on an authenticated retained registry
  key, so it covers registration before any delivery was admitted and exit after
  an FSA1 stop receipt was already completed. Admission and reconciliation share
  the inbound journal lock. If reconciliation released a pin before a pending
  delivery writes HCP1, record_consumer_program can validate the exact same-boot
  shared HPE1 to preserve HPB1; absent or malformed evidence cannot backfill that
  binding. The source gate and ordinary admission checks remain independently
  required.

  collector-reconcile-batch passes sanitizer checks for 70 identities, 32-entry
  bounds, allocation-free snapshots, deleted cursors and fair wraparound. The
  journal/stop component in collector-reconcile-daemon passes live-pin retention,
  empty registration inventory, HRE1/HPE1 write failures retaining the pin,
  idempotent exit checkpoint, late receipt recovery from HPE1, and the actual
  periodic worker releasing a proven-exited registration. The sanitized daemon
  build/link and all 45 component suites pass in collector-reconcile-daemon,
  including thread startup, shutdown, admission concurrency and journal recovery.
  These are isolated worker/component tests; no daemon, tracing device, kernel
  module or live VM was operated.

- Redundant legacy HPX1 per-receipt process-exit records are now retired only
  after the shared HPE1 replacement has been validated and synchronized. Under
  the existing journal/process locks, checkpoint_consumer_process_exit validates
  the exact HPX1 owner/program/handle/boot binding, unlinks only its canonical
  receipt name, and synchronizes the parent directory before releasing a retained
  descriptor. Even an already-absent legacy name triggers the directory sync to
  complete an interrupted unlink-sync retry. HCP1, HHL1, HPB1, HPE1, HRE1 and FSA1
  dependencies remain in place; this is not general session-journal deletion.

  The changed directory implementation builds and the daemon relinks in
  collector-legacy-exit-retirement. Its sanitizer journal/stop regression passes
  replacement-fsync failure with HPX1 retained, unlink failure with HPX1 retained,
  successful unlink followed by failed parent sync, exact retry without HPX1,
  and another receipt's recovery through shared HPE1 without process queries.
  The native-daemon harness now includes the unlink fault injector. No daemon,
  tracing device or live VM was operated.

  The bounded reconciler above now covers process exit after a completed FSA1
  and registrations with no HCP1. An absent socket alone still cannot justify
  dropping either pin.
  Full session-journal retirement still needs dependency-aware replacement of
  migration/reconnect evidence. FSD1 now records completion and supplies the
  collector-stop recovery answer, but other journal consumers still need their
  dependency audit before those records can be removed.
  The current FSI1 source fence is permanent and is read by admission checks as
  well as stop/retry recovery; release_fresh_session_gate only releases an
  attested destination gate. Retirement must therefore preserve the old epoch's
  admission denial and exact stop identity in a terminal record before removing
  FSI1/FSA1/receipt dependencies. Neither file age nor a missing VM/PID establishes
  that replacement proof.

- The fresh-session coordinator can now publish a crash-stop FSA1 for an absent
  collector only after all three exact facts are proven: durable process exit
  (HPE1), durable owned-empty-reaper exit (HRE1), and retirement of the registered
  kernel handle lifetime. Live-pin recovery retries now retain their checkpoint
  result. Missing, failed or insufficient evidence leaves the session fenced and
  allows later connected recipients to receive stop requests. No PID-absence
  inference, missing socket, or process-only receipt authorizes a crash stop.

  The existing FSA1 publisher revalidates the immutable recipient owner/program,
  exact fresh-session token and source VM epoch, and currently suspended kernel
  gate before publication. The consumer census now also requires receipts grouped
  under one owner to agree on their kernel handle lifetime, including refusing
  mixed legacy/modern handle evidence. A correctly checksummed different lifetime
  cannot be deduplicated away behind a shared owner/program stop. Its durable retry
  handles a lost parent-directory fsync response. A restarted daemon can reuse the resulting exact receipt with
  no collector connection or retained descriptor. This is the empty-at-exit crash
  case only; surviving descendants, loss of both daemon and collector before any
  durable exit snapshot, journal retirement, and live qualification remain open.
  The migration capability remains disabled until the remaining gates pass.

  The extracted production coordinator regression passes in
  collector-crash-stop-progress, including process-only, missing/error descendant,
  live/error handle, all-three success and later-recipient progress cases. The
  journal-backed component also passes in collector-crash-stop-daemon: absent
  HRE1 refuses, live/unsupported handle refuses, crash FSA1 fsync failure remains
  retryable, and a fresh daemon recovers the durable completion. The sanitized
  daemon build/link and all 45 component suites pass in that directory. The final
  handle-consistency addition was rebuilt afterward and passes the consumer
  census, crash-stop and fresh-session fence suites in collector-crash-handle-census,
  including a correctly checksummed conflicting lifetime. No daemon, tracing
  device, kernel module or live VM was operated.

- Empty-reaper exit evidence now has a durable shared HRE1 record. The private
  192-byte record binds HCO1 owner, program digest, kernel handle lifetime and
  current boot; bytes 152..159 are reserved zero and the final 32 bytes checksum
  the first 160. Its .reaper-empty.<digest> name is distinct from HPE1. Reads
  validate the exact expected bytes, ownership, file shape and checksum and sync
  the file and parent directory through the existing private-record helper.

  checkpoint_consumer_process_exit preserves an affirmative pinned-descriptor
  snapshot before publishing HPE1 and releasing the pin. Query or persistence
  failures retain the descriptor. A nonempty/non-reaper snapshot adds no HRE1;
  old HPE1/HPX1 records with no retained descriptor cannot synthesize it. Exact
  retries with HPE1 already present preserve any still-retained snapshot before
  release. consumer_reaper_exit_status revalidates HCP1, HHL1 and same-boot HPB1
  before reading HRE1, so another receipt for the exact collector can recover
  evidence after restart without querying an absent or reused PID.

  The expanded journal component exercises unsupported snapshot query, HRE1
  fsync failure, preservation before HPE1 failure, descriptor retention/release,
  cross-receipt restart recovery, boot mismatch, reserved-byte corruption, and
  old process-only evidence without HRE1. The coordinator above now requires
  this query together with kernel-handle retirement for crash-stop publication.
  HRE1 also recovers a crash between its own durable write and
  HPE1 publication: because the snapshot explicitly includes exit, another exact
  receipt can complete HPE1 with an empty registry and no PID lookup. This final
  journal change and regression pass under sanitizers in
  collector-reaper-checkpoint-recovery. The collector-owner registry tests pass
  in collector-reaper-owner. The sanitized daemon build/link and all 45 component
  suites pass in collector-reaper-journal-daemon; that full run predates the final
  inter-record recovery change, whose rebuilt journal/stop-step regression is
  recorded separately above. No daemon, tracing device, or VM was operated.
  Surviving descendants, unrecorded exits, and dependency-aware journal cleanup
  remain open.

- Added PDIOC_GET_REAPER_EXIT as a process-descriptor exit snapshot. Under the
  existing exclusive process-tree lock and descriptor lock, procdesc_exit records
  whether the exiting process still owns a reaper and its descendant list is
  empty, before exit notification and before reaping abandons that list. The
  immutable flags remain queryable through the retained descriptor after reaping.
  A live descriptor returns zero flags; a non-reaper exit cannot claim emptiness,
  and descendants surviving the parent exit remain unproven even if they later
  exit. This does not terminate any process or alter ordinary reaper ownership.

  collector_process_reaper_empty decodes only an authenticated, previously pinned
  descriptor. Unsupported ioctl, reserved fields, unknown bits, and impossible
  flag combinations fail explicitly. Only exited + owned + empty returns proof.
  Actual kernel exit-hook and ioctl extraction tests pass under ASan/UBSan in
  procdesc-reaper-exit; actual daemon helper extraction tests pass in
  collector-reaper-exit-query. The changed kernel object compiles with the
  configured amd64, arm64, and riscv64 kernel flags; the actual daemon process
  implementation compiles with sanitizers. Build logs/results are retained in
  procdesc-reaper-exit. These are component tests and object builds, not a full
  kernel rebuild or running-kernel qualification. The durable HRE1 integration
  above preserves this evidence before HPE1 releases a retained descriptor; the
  coordinator combines it with kernel-handle retirement before publishing the
  exact fresh-session receipt. Previously retired descriptors cannot retroactively
  acquire this snapshot. Crashes with surviving
  descendants and simultaneous daemon/collector loss remain separate open cases.

- Coordinated collector stop now includes a descendant-process barrier. The
  host ELF collector acquires and verifies process-reaper ownership before
  admitting tracing work. After processing, reporting, output, and async workers
  are quiescent, stop retries require an empty owned descendant census. Each
  retry reaps at most 256 reported zombie children with nonblocking waitpid;
  live descendants, reaping races, and nonempty censuses remain pending under
  the stop deadline. Failed or changed reaper ownership cannot authorize a stop.
  Existing children from before reaper acquisition are not adopted by the kernel.
  No descendant is killed by this barrier.

  consumer-descendants extracts the actual production helpers and passes ASan/
  UBSan checks for acquisition/ownership errors, status and enumeration errors,
  bounded enumeration, zombie eligibility, invalid PIDs, wait failures, and the
  requirement to obtain a new empty census after reaping. A separate real process
  test creates a nested reaper, requires adoption of its still-running grandchild
  after the nested reaper exits, verifies stop remains pending, then allows the
  grandchild to exit and verifies complete reaping. This uses ordinary isolated
  test processes, without DTrace devices, daemons, or VMs. The collector stop
  regression passes in consumer-descendant-stop. The complete collector builds
  with all CPUs against the matched libraries; evidence is recorded in
  consumer-async-discard-library/descendant-collector-build.{log,json}.

  This proves the coordinated descendant barrier. The retained kernel exit
  snapshot above additionally covers collectors whose descendant set is empty at
  exit. Collectors with surviving descendants still require independent evidence
  before process/handle retirement can become FSA1.
  Live HyperTrace migration qualification and dependency-aware journal retirement
  remain open; the migration capability remains disabled.

- Added the async ELF worker to the collector's fresh-session stop barrier.
  dtrace_async_discard_step() terminally closes process-wide async admission,
  sets shutdown, interrupts the active worker's owned socket with shutdown(),
  and reports ready only after the worker has freed active/queued entries and
  completed their descriptor/path cleanup. It uses a queue-mutex trylock and
  never joins the worker in the step; the existing collector stop deadline bounds
  retries. The ordinary final teardown joins the already-idle worker. Descriptors
  remain worker-owned during cancellation, avoiding close/reuse races. New async
  requests return ESHUTDOWN even after ordinary teardown, preserving caller
  ownership of rejected input descriptors and paths.

  Stop acknowledgement now requires async idle as well as program processing,
  execution reporting and output-worker completion. Busy/error/timeout remains
  unproven; no cancellation request alone authorizes a stop. A frame transmitted
  before cancellation still requires the daemon's existing ingress/session fence;
  this API does not retract already-received remote bytes. Existing normal async
  teardown/restart remains supported when no terminal discard was requested.

  Actual-worker sanitizer tests passed in library-async-discard using real socket
  pairs: one frame awaiting an ACK, a second queued frame, busy-lock return,
  active socket interruption, no second-frame delivery, complete fd/path cleanup,
  and terminal admission rejection across teardown. The test also exposed and
  fixed loss of optional program identity in queued sends: absent programs stay
  absent, while supplied program lineage survives ident_present=0. The collector
  receiver regression passed with async-busy timeout and async-error refusal in
  consumer-async-stop. Complete static/shared libdtrace, matching libctf and the
  DTrace collector built with all CPUs in consumer-async-discard-library.
  No daemon, tracing device, module or live VM was operated. Descendant output,
  unrecorded exits and dependency-aware journal cleanup remain unfinished.

- Output discard is now terminal on the libdtrace handle. The quiesced collector
  calls dtrace_output_discard() before attempting kernel stop, so even stop failure
  cannot restore ordinary output cleanup. It purges both the caller FILE and the
  libdtrace-owned freopen() FILE, drops buffered callback output, discards the
  calling thread's formatter, and retains a terminal flag on failure for retry.
  dt_printf(), dtrace_sprintf() (including system()/freopen() formatting), and
  dtrace_work_consumer() reject subsequent work with ESHUTDOWN. This blocks new
  actions; it does not stop descendants launched before the fence.

  dtrace_close() honors the flag: it discards the closing thread's formatter and
  redirected stdio before cleanup and skips xo_finish(). This covers formatter
  state on a different thread from the stop requester. The collector's oprintf()
  also suppresses session-stopped output, and final benchmark dumping is skipped
  while benchmark memory is still freed. Ordinary close and benchmark output
  remain unchanged outside a fresh-session stop.

  The complete static/shared libdtrace build passed with all CPUs in
  consumer-terminal-output-library, and final collector/library object compilation
  passed in consumer-terminal-output-build. The sanitizer stop receiver test
  covers discard before kernel-stop failure, purge failure/retry and bounded
  worker waits (consumer-terminal-output). The five-style formatter/real-stream
  tests passed in consumer-terminal-output-discard. A test linked to the rebuilt
  library in DTRACE_O_NODEV mode passed for redirected output, cross-thread
  formatter close, repeated terminal printf/work/sprintf/system/freopen refusal,
  and preserved ordinary-close flushing (consumer-terminal-output-close).
  The runtime test uses the matching source-built libctf; the installed libctf
  lacks ctf_type_copied, so mixing it with the rebuilt library fails to load.
  No tracing device, daemon, module or live VM was operated. Descendant output,
  unrecorded process exits and dependency-aware journal cleanup remain open.

- Fresh-session collector shutdown now discards pending formatter and stdio
  output instead of following normal structured-output teardown. The output
  worker calls dtrace_oformat_discard() on its formatter-owning thread before
  publishing worker-done. It switches libxo away from encoder style, replaces
  writer/flush/close callbacks with a discard sink, and destroys that thread's
  formatter state without emitting buffered records or closing the caller's FILE.
  A stop observed after consumption also bypasses the ordinary fflush path.
  Once processing/reporting/output workers have stopped, the stop coordinator
  purges the collector FILE under the DTrace mutex before acknowledging the stop;
  purge failure refuses a positive acknowledgement. Ordinary non-session-stop
  teardown and output flushing are unchanged.

  The actual stop receiver/worker sanitizer test passed in consumer-output-discard,
  including a stop during consumption, suppressed flush/aggregates, purge failure
  and retry with no bytes written to a real temporary output file. The actual
  discard function also passed against the source-built libxo archive in text,
  XML, JSON, HTML and SDPARAMS styles with zero writer/flush/close callbacks and
  zero output (consumer-output-discard-library). Both dt_subr.o and the collector
  dtrace.o compiled with production flags in consumer-output-discard-build.
  The new library test is registered in native-port.py. No tracing device, daemon,
  module or VM was operated. This handles owned buffers; it does not yet fence
  output from shell descendants created by system() or arbitrary external workers.

- Process-exit evidence is now shared across exact collector identities as HPE1,
  closing a crash window between per-delivery checkpoints. Each 184-byte private
  record binds canonical HCO1 owner identity, program digest, kernel-handle
  lifetime and boot ID, with a checksum-derived filename and SHA256 integrity
  check. A requesting delivery still must independently validate HCP1/HHL1/HPB1;
  matching only a PID or program is insufficient. Thus a second delivery can
  recover the same process-exit fact after daemon restart without needing its own
  pre-crash checkpoint or opening a PID. Exact old HPX1 records can promote to
  HPE1; corrupt old records cannot. New checkpoints publish HPE1 rather than HPX1.

  After shared exit evidence is synced, the daemon releases the exact retained
  process descriptor, allowing bounded registry capacity to be reused. File or
  directory-sync failure retains the descriptor for retry. An exact durable
  retry closes it once; later retries need no descriptor. This retires process
  descriptors only: HPE1 and the ownership/stop journals remain durable evidence
  and are not deleted. Their dependency-aware cleanup remains outstanding.
  Shared process-exit evidence still does not establish kernel-handle retirement,
  descendant-output shutdown or FSA1, and does not enable migration by itself.

  Sanitized component coverage passed in collector-shared-exit for lost directory
  sync, cross-delivery restart recovery, descriptor preservation/closure, changed
  boot, corruption and exact legacy promotion; collector-shared-exit-registry
  verifies descriptor closure and idempotent release. The final sanitized daemon
  build/link and all 45 component suites passed in
  /usr/obj/5BSD-hypertrace-validation/collector-shared-exit-daemon. No daemon,
  module or live VM was started.

- Added durable HPX1 process-exit checkpoints. An exact retained descriptor must
  report explicit exit before the daemon publishes a new checkpoint; a missing
  PID, socket or descriptor cannot create it. The private 378-byte record binds
  the complete HCP1 receipt/owner/program tuple, HHL1 handle and current boot ID,
  with a separate magic/name and checksum. Checkpointing also requires the exact
  verified HPB1 binding. File and directory synchronization must succeed before
  reporting durable process exit. An exact existing checkpoint is validated and
  resynced on retry, allowing recovery after a lost directory-sync result or
  daemon restart without reopening or polling the PID.

  Missing-collector stop coordination now checks/checkpoints process exit,
  reconstructing a still-live pin from HPB1 when needed. It continues stopping
  later connected recipients, but neither successful pin reconstruction nor a
  durable HPX1 completes the missing collector's stop. HPX1 proves only that
  process exited: independent kernel-handle retirement and descendant-output
  ownership are still required before FSA1 crash publication. If the daemon
  loses its descriptor before checkpointing exit and the process has disappeared,
  that case remains unresolved. No PID absence is converted to a checkpoint.

  The sanitized stop-step regression passed in collector-process-exit, covering
  live/missing descriptor refusal, file-sync failure, directory-sync failure and
  exact retry, empty-registry journal reopen, changed boot and corruption. The
  coordinator regression passed in collector-process-exit-progress and confirms
  that durable process exit cannot bypass the stop-proof requirement. The final
  sanitized daemon build/link and all 45 component suites passed in
  /usr/obj/5BSD-hypertrace-validation/collector-process-exit-daemon. No daemon,
  kernel module or live VM was started.

- Added HPB1 boot-bound process-ownership journals alongside HHL1/HCP1.
  Each private, checksummed 378-byte record binds the complete HCP1 receipt,
  owner/program identity, kernel-handle lifetime and kern.boot_id. Only an exact
  registration-verified registry entry may publish HPB1. For new work HPB1 is
  synced before HCP1; a failed publication cannot admit work. An authenticated
  exact retry may also add this evidence to an existing HCP1/HHL1 tuple. Old
  records without HPB1 remain insufficient for offline process-pin recovery.

  Recovery validates HCP1, HHL1 and HPB1 under the journal locks, requires the
  current boot ID, then pins the recorded PID and rechecks its exact kernel birth.
  It retains an independent CLOEXEC/PD_DAEMON descriptor; closing the temporary
  descriptor never kills/reaps the process. Missing evidence, malformed/changed
  boot IDs, checksum corruption, changed birth and ESRCH fail without asserting
  exit. A retained descriptor can still supply explicit exit evidence later.
  Missing-collector stop coordination now attempts this pin recovery, but even
  success does not publish FSA1 or complete the stop: output-worker ownership
  remains a separate requirement. This supports recovery of a still-live process
  without waiting for its socket to reconnect. It cannot recover a descriptor
  after that process has already disappeared; a previously durable HPX1 can
  preserve its explicit exit evidence as described above.

  The sanitized journal/stop-step component passed in collector-process-journal:
  HPB1 fsync failure before HCP1, exact retry, missing/corrupt evidence, different
  boot, missing/zero/short boot identity, missing process, PID reuse, and idempotent
  live-pin reconstruction. The extracted coordinator regression also verifies
  that successful pin reconstruction does not bypass the missing stop proof.
  The final sanitized daemon build/link and all 45 component suites passed in
  /usr/obj/5BSD-hypertrace-validation/collector-process-journal-daemon. No daemon
  was started, modules loaded, or live VM operated.

- Audited authenticated collector reconnect after daemon restart with the real
  client registration, registry and durable journal implementations. A fresh
  state/empty registry and reopened HCP1/HHL1 initially return EAGAIN without
  polling any process. A missing peer (ESRCH) or changed kernel birth rejects
  registration and leaves ownership unresolved. Exact HPI2 registration and
  retry rebuild the pin, match the existing durable program/handle binding, and
  retain process evidence after the new connection releases its descriptor.
  The extended fresh-session-stop-step fixture passed under ASan/UBSan in
  /usr/obj/5BSD-hypertrace-validation/collector-owner-lookup. This is component
  restart/reconnect evidence, not a live daemon restart qualification; process
  pin/exit syscalls are mocked. The last full 45-suite run below predates these
  additional assertions; the changed fixture was rebuilt and rerun afterward.
  HPB1 live-pin recovery above now covers recovery without an authenticated
  reconnect. Recovery when both daemon and collector exited before durable stop
  proof remains incomplete. No PID absence
  or reconstructed historical nonce is accepted as proof of death.

- Verified collector process descriptors now survive connection destruction in a
  daemon-owned registry keyed by session, kernel process birth, UID/PID, program
  digest and kernel handle lifetime. Registration retains a CLOEXEC duplicate
  before admitting the program; allocation/duplication failure rejects admission.
  The 4096-entry bound refuses new identities rather than evicting unresolved
  evidence. Exact retries reuse the existing pin. Safe journal retirement must
  release entries only after durable shared process-exit evidence, as implemented
  above. Unproven entries are never automatically evicted. Boot-bound live-process
  reconstruction is also implemented above.
  The durable process lookup reads and validates HCP1/HHL1 under the journal's
  thread/process locks, then queries only the exact previously verified retained
  descriptor. Missing journals, legacy handles or an empty registry cannot prove
  death. Reopening the journal within the same daemon can recover the binding;
  restarting the daemon loses these descriptors until authenticated reconnect or
  validated HPB1 live-process recovery rebuilds the pin as described above. This
  query does not interpret historical random nonces as kernel births or publish
  FSA1. Standalone sanitizer coverage passes for exact ownership, socket-side
  close, identity substitution, allocation failure and final descriptor cleanup.
  The journal-backed stop-step fixture also passed in collector-owner-lookup.
  The final sanitized daemon build/link and all 45 component suites passed in
  /usr/obj/5BSD-hypertrace-validation/collector-owner-lookup-daemon, including
  journal corruption rejection without querying process state, descriptor close,
  exact journal reopen and refusal with a new empty registry. No daemon or VM
  was started. The earlier collector-owner-daemon run stopped on a compiler
  assertion in its last fixture during a concurrent header edit; it is not
  counted as a complete passing run.

  Worker coverage has a concrete outstanding edge: dt_printf.c:dtrace_system()
  invokes libc system(), so a shell or descendants can outlive a crashed
  collector and retain output descriptors even after its DTrace handle closes.
  A parent process descriptor plus kernel-handle retirement is therefore not
  sufficient for universal crash-stop proof. Descendant/output ownership needs
  explicit coverage before FSA1 crash publication can use these queries.

- Collector incarnation strings now encode kernel monotonic process birth from
  pdself (capability mode) or pdopenpid(getpid()) (ambient) and
  PDIOC_GET_BIRTH_IDENTITY, queried afresh for each connection so forked
  children cannot inherit their parent's identity. Query/close errors and malformed
  results leave output unchanged and fail explicitly. HPI2 registration now pins
  the authenticated socket peer PID with PD_DAEMON|PD_CLOEXEC and requires its
  kernel birth to match the incarnation before publishing program-valid state.
  Exact retries keep the descriptor; connection destruction closes it without
  killing or reaping the process. Legacy HPI1 does not gain process evidence.
  Birth-generator, reconnect and library transport sanitizer tests passed;
  production dt_subr.o compiled in collector-birth-registration.
  The sanitized daemon build/link and all 45 component suites also passed in
  /usr/obj/5BSD-hypertrace-validation/collector-birth-daemon, including wrong
  kernel-birth rejection before registration and exact retry.
  The registry described above now retains verified descriptors beyond connection
  cleanup; durable process-proof/versioning and daemon restart handling are
  not complete. Historical random-nonce owner records must not be interpreted
  as verified kernel births merely because their wire size is unchanged.
  Inherited user-space worker coverage and FSA1 crash publication remain open.

- Added collector process-evidence helpers using PD_DAEMON|PD_CLOEXEC descriptors.
  Pinning requires an independently known kernel birth identity, verifies the
  peer PID and exact monotonic start time through PDIOC_GET_BIRTH_IDENTITY, and
  leaves the caller output unchanged on error. Descriptor close never kills the
  observed process. Exit checks are nonblocking and accept only explicit POLLHUP;
  missing PIDs, ESRCH, unsupported ioctls, invalid descriptors and ambiguous poll
  events are errors, not death proof. Sanitized extracted-body tests cover those
  cases, PID reuse and cleanup errno preservation. The actual daemon process
  object compiled and the daemon relinked against the previously validated
  component objects in /usr/obj/5BSD-hypertrace-validation/collector-process-proof;
  it was not started. Authenticated registration-time birth binding and
  descriptor retention are now implemented above; durable process-proof
  versioning and restart handling remain open. Inherited output-worker coverage also remains to be established;
  no FSA1 publication uses this evidence yet.

- Added privileged HYPERTRACE_IOC_HANDLE_QUERY on /dev/dtrace/hypertrace,
  using the shared lifetime ABI and DTrace configuration lock. This control
  device creates no DTrace consumer state. Jail and DTrace privilege checks
  precede the query. The daemon can now load an exact durable HHL1 identity
  and query kernel retirement without treating missing devices, ENOTTY,
  stale module lifetimes, malformed echoes or close failures as retirement.
  Missing/legacy journal evidence returns EAGAIN. Tests cover the real control
  dispatcher and daemon query helper, including denied access, live/retired,
  missing device, unsupported ioctl and malformed replies. Both DTrace and
  HyperTrace control production objects compiled for amd64, arm64 and riscv64
  in /usr/obj/5BSD-hypertrace-validation/collector-handle-query.
  The sanitized daemon build/link and all 45 component suites passed in
  /usr/obj/5BSD-hypertrace-validation/collector-handle-control-daemon.
  This query is not yet used to publish FSA1: collector output-worker death
  still needs independent authoritative evidence. No module was loaded.

- Added immutable HHL1 per-recipient handle journals, binding the complete HCP1
  receipt/owner/program tuple and canonical HPI2 kernel lifetime with a checksum.
  Under the existing process lock, HHL1 is synced before HCP1 publication; an
  interrupted attempt can finish only with the exact identity. Existing legacy
  HCP1 without HHL1 cannot acquire a nonzero handle later. An explicit zero legacy
  binding cannot upgrade either. Both initial queueing and non-imported consumer
  send-time checks enforce the binding, including reconnect replay. The read API
  validates private regular-file ownership, exact size, tuple, checksum and
  identity before fsync and output publication; absent/legacy data yields no
  handle evidence. These records must be retained until journal retirement is
  implemented. The historical continuity import path does not transfer HHL1.
  The final sanitized daemon build/link and all 45 component suites passed in
  /usr/obj/5BSD-hypertrace-validation/collector-handle-binding-final, including
  failed HHL1 fsync/retry, reopen, corruption, substitution and downgrade cases.
  Kernel query integration and proof that user-space output has stopped remain
  open: HHL1 alone does not authorize FSA1 or crashed-collector completion.

- Added HPI2 program registration: a fixed 64-byte canonical message binds the
  compiled-program digest to the kernel handle generation and serial. Collectors
  obtain the identity before initial registration and reuse the identical HPI2
  bytes on reconnect. Missing ioctl support fails explicitly. The daemon accepts
  legacy 32-byte digest registrations as unbound, but a connection cannot replace
  its handle identity, upgrade or downgrade an established registration. Decode
  rejects truncation, reserved bits and zero identities without modifying output.
  Sanitized reconnect tests cover rejection/retry with exact HPI2 preservation;
  the collector compiled using its maintained Makefile flags. The sanitized
  daemon build/link and all 45 component suites passed in hpi2-daemon; the
  updated HPI2 handler fixture also passed separately in hpi2-reconnect.
  Durable per-receipt
  handle binding is still missing: this change records identity on the connection
  only, and cannot authorize crashed-collector stop proof. Kernel lifetime claims
  must also be bound to authenticated collector ownership before recovery use.

- Added libdtrace dtrace_handle_identity() and dtrace_handle_retired() wrappers
  for the kernel state-lifetime ioctls. Both preserve caller outputs on failure;
  identity responses require nonzero generation/serial and zero reserved fields;
  query responses must echo the exact identity and contain a Boolean retirement
  result. Unsupported kernels propagate ENOTTY, never implied retirement.
  Null/malformed requests fail before ioctl. Sanitizer tests exercise actual
  wrapper bodies including malformed kernel replies, altered identities,
  unsupported ioctls and I/O failures; production dt_work.o compiled with the
  established amd64 world-build flags in
  /usr/obj/5BSD-hypertrace-validation/library-handle-lifetime.
  These APIs attest kernel state only. Collector execution has not yet been
  bound durably to this identity, so the daemon still cannot infer FSA1 from
  a missing collector. User-space output-worker retirement remains required.

- Added FreeBSD DTrace HANDLE_ID/HANDLE_QUERY ioctls as kernel retirement
  evidence primitives. Each allocated state receives a gap-free serial within
  a random 128-bit module lifetime, shared by references to that state. Live
  states remain registered under dtrace_lock until state destruction has drained
  execution and freed buffers/speculations; only then can a query report retired.
  Queries reject zero/future serials, reserved input, and different module
  lifetimes. Address reuse cannot revive a retired identity; counter exhaustion
  refuses allocation rather than wrapping. No persistent retired-state list is
  required. Sanitized tests exercise actual registry/query and ioctl cases,
  address reuse, stale generations and malformed input. Production dtrace.o
  compiled for amd64, arm64 and riscv64 in
  /usr/obj/5BSD-hypertrace-validation/dtrace-handle-lifetime.
  This is not yet collector crash recovery: the exact identity must be durably
  bound before execution, authenticated in daemon receipts, and combined with
  evidence that user-space output workers cannot continue. Final kernel state
  destruction alone says nothing about copied user-space buffers. No daemon
  currently turns this query into FSA1; inherited-handle live tests and reboot/
  module-reload recovery remain unqualified. No modules were loaded.

- Collector stop coordination now continues past recipients with missing sockets
  to stop later connected recipients, retaining at most one stop RPC per step.
  Missing proof still returns pending when no further connected work is available;
  only exact durable receipts can make the complete census succeed. This avoids
  a crashed first collector starving all later collectors. The extracted actual
  coordinator passes sanitizer cases for mixed missing/live recipients, bounded
  progress, unaudited reconnects, transport loss and corrupt proof errors.
  The full sanitized native daemon build/link and all 45 component suites
  also passed in /usr/obj/5BSD-hypertrace-validation/fresh-stop-progress-daemon.
  No daemon or live VM was operated.
  This does not resolve the crashed collector's outstanding proof.
  Inspection confirms dtrace_state_destroy drains active execution and releases
  ECBs at final handle destruction; collector process death alone does not prove
  that final destruction occurred, because handles may be inherited. Epoch
  suspension alone also does not discard every state buffer. An authoritative
  handle-lifetime/retirement mechanism remains required before publishing stop
  proof for a collector that crashed before committing it.

- Closed the retained-process INTENT-publication retry gap. The source records
  intent_pending before writing its immutable ownership claim and HMR2 INTENT,
  and clears it only after successful file/directory fsync. Authenticated recovery
  may retry that exact publication using the original in-memory COMMIT binding,
  provided the source context remains owned, quiesced and not retired. It cannot
  resume the source. Disk-only recovery still requires both claim and journal
  and cannot manufacture absent intent evidence. Tests inject failure at each
  of the four initial publication fsync boundaries and verify exact retry;
  handler tests cover authentication failure before retry and invalid retained
  states. Process death before durable intent still needs a separate, explicit
  recovery policy; this change does not infer COMMIT from peer assertions.

- Added snapshot-enabled bhyvectl recovery options for an inherited connected
  stream fd, certificate/key/trust fds and destination certificate fingerprint.
  Recovery dispatch precedes vm_openf, since the source VM may be destroyed.
  Unrelated actions, partial credentials, invalid descriptors and malformed or
  unconfirmed replies fail. No replacement root or attempt binding is sent.
  Request-level sanitizer tests passed; production bhyvectl objects compile
  with snapshot support enabled and disabled. Fixed the snapshot build's shared
  HyperTrace wire-header include path. This frontend has not been run against
  a live VM. Process-restart ownership recovery and the remaining lifecycle
  gates still prevent enabling fresh migration initiation.

- Added `migrate_recover` IPC for the process-retained fresh source attempt.
  The quarantined dispatcher passes NULL, never the obsolete VM-context alias.
  The handler takes only a connected fd and complete TLS credential descriptors;
  it rejects any recovery_fddir override and takes the VM context, binding and
  directory exclusively from retained ownership. Both authenticated certificate
  fingerprints must match the original attempt before INTENT completion runs.
  It then completes checked retirement and runs the existing durable RELEASE/ACK
  executor on that same connection. Failure keeps the owner and quarantine for
  retry; it never resumes the source. Ordinary migration is not recovered by
  this fresh-session handler. Component fault injection covers missing/partial
  credentials, certificate mismatch, retirement failure, lost RELEASE and retry.
  Production IPC and migration objects compile with OpenSSL and NO_OPENSSL.
  This is an IPC API, not yet a bhyvectl recovery frontend or a process-restart
  owner reconstruction mechanism. Initial fresh migration remains disabled.

- Source retirement now irreversibly quarantines the serialized IPC dispatcher
  before INTENT publication or checked destruction. It clears the dispatcher's
  VM-context alias and rejects every subsequent command except the context-free
  PID query. This also protects ordinary migration's failed-RELEASE path from
  reuse of a freed context. The source adapter now persists for the process
  lifetime, with an independently duplicated recovery-directory descriptor.
  Requests may reuse that directory but cannot substitute another inode; request
  teardown no longer closes the adapter's journal descriptor. ASan/UBSan tests
  exercise the actual dispatcher, stale caller pointers, idempotent quarantine,
  directory substitution and descriptor lifetime; production IPC and migration
  objects compile, including the NO_OPENSSL migration configuration.
  Still pending: a recovery-only IPC command that owns the retained source,
  authenticates reconnects and completes INTENT/RELEASE without ordinary VM
  command access; trusted root selection across controller/process restart.
  Current root pinning is process-local, not a host-wide registry. No live
  migration or concurrent kernel qualification has been performed.

- Source production INTENT publication now first persists an immutable claim
  keyed by the source vmid and epoch. It binds the complete HMR2 attempt,
  including stop token, destination identity, challenge, state digest and both
  certificate pins. Later source phases, INTENT completion and recovered RELEASE
  require the existing exact claim; missing or conflicting evidence fails closed.
  Claims use a private permanent lock, atomic publication and file/directory
  fsync. They must survive confirmation and must not be garbage-collected with
  per-attempt journals. Concurrent process claims admit only one attempt.
  This guarantee is scoped to one trusted recovery root: the source controller
  still must enforce that root and retain exclusive VM-context ownership across
  IPC failures. Production fresh migration remains disabled pending that work
  and the other lifecycle gates. No live qualification is claimed.

- Implemented `migration_prod_source_finish_intent` under exclusive trusted
  source-owner access. It loads the exact durable HMR2 binding before querying
  the kernel. A live source requires matching ctx identity, transport stop,
  atomic identity-checked destruction, and the exact drained kernel retirement
  witness before RETIRED is persisted. Missing ctx or unavailable evidence is
  not completion. After successful destruction ctx is cleared even if proof
  or publication subsequently fails; retry can use the exact kernel witness
  without a second destruction. Already-retired evidence leaves an unrelated
  caller context untouched. Normal fresh migration retirement now also uses
  the identity-checked destroy and retirement witness; ordinary migration
  retains its previous destruction API.
  `/usr/obj/5BSD-hypertrace-validation/migration-source-intent` passes sanitized
  extracted-production recovery with real journals across 16 cases: missing
  journal/context, changed identity/certificate binding, stop/destroy/query
  failures, unsupported kernel, failed post-destroy proof/publication and
  retry, and already durable retirement. Normal production retirement and
  retained-owner fixtures pass, and production migration compiles with and
  without OpenSSL. No live VM was opened or destroyed.
  Source control integration remains unfinished: it must retain/serialize the
  source owner and ctx lifetime across failed migration IPC and bind a VM
  lifetime to one immutable destination attempt. Per-challenge HMR2 files alone
  do not enforce uniqueness across competing attempts. Those ownership gates
  must exist before wiring automatic recovery or enabling fresh migration.
- Added `VMMCTL_VM_DESTROY_IDENTITY` and
  `vm_destroy_identity_checked(ctx, vmid, epoch)` as the prerequisite for
  source INTENT recovery. The old checked destroy still selects by name;
  recovery must use the new operation. The kernel checks permission and the
  expected ID/epoch while holding the device-list and memseg locks, marks the
  cdev unavailable before dropping those locks, and rejects an already queued
  VM_REINIT after that mark. A reset before the check produces ESTALE. Existing
  MAC/creator/privileged checks and passthrough preflight retry behavior remain.
  The library closes ctx only on success, rejects truncation/invalid identities,
  and never falls back to name-only destruction if the kernel lacks the ioctl.
  `/usr/obj/5BSD-hypertrace-validation/vm-destroy-identity` passes sanitized
  extracted-kernel dispatcher/destruction/reset-order fixtures and the actual
  library wrapper fixture, including permission failures, malformed payloads,
  missing/reused targets, failed preflight, and unsupported-kernel behavior.
  Production VMM device objects compile for amd64, arm64, and riscv64, and
  libvmmapi compiles. Runtime WITNESS/concurrent-reset qualification has not
  been performed. The INTENT helper above now connects this operation
  and the exact kernel retirement witness to its journal transition; neither
  disappearance nor an ioctl error may be promoted to RETIRED.
- Connected an opt-in receiver recovery worker through
  `migrate.recovery_listen_fd`, a preopened exclusive listening stream socket.
  Configuration requires a receive fd, private recovery directory, and mutual
  TLS credentials. The worker and duplicated listener/credential descriptors
  are allocated before migration can reach COMMIT. A retained paused owner
  keeps main startup waiting; each accepted connection goes through the
  authenticated production recovery executor under the owner's mutex. Failed
  attempts preserve the owner. Once running, startup proceeds and the worker
  remains available for lost-ACK reconnects until VM process exit. Uncertain
  resumes do not unblock startup. No sockets are bound or listeners created
  automatically; the supplied listener must have no other acceptor.
  Successful fresh resume also suppresses the duplicate post-migration
  HyperTrace start in bhyverun. Early fresh-migration refusal remains active.
  `/usr/obj/5BSD-hypertrace-validation/migration-receiver` passes sanitized
  worker tests with local UNIX sockets and mocked VM/TLS adapters: thread
  allocation failure before migration, ordinary failure cleanup, paused
  recovery after rejected attempts, running reconnects, repeated ACK without
  duplicate resume, descriptor independence after caller close, and quarantine.
  The test caught and corrected the FreeBSD SO_ACCEPTCONN nonzero flag value.
  Production migration/worker compile with and without OpenSSL, worker without
  snapshot support, and bhyverun compile. Actual VM behavior and combined
  live controller/TLS/runtime qualification remain untested.
- Connected `migration_prod_dest_recover_release` to the retained production
  owner and HXR1 executor. Observation rechecks VM identity, saved device-state
  digest, FSS1, COMMIT binding, and consistency of the startup fence with the
  owner's running state. Resume calls the real `prod_dest_resume` /
  `vm_migrate_fresh_resume` path only from verified paused state. Recovery run
  state lives in the owner across connections, including uncertain-resume
  quarantine. Fresh running owners now survive the original serve call even
  after an apparently successful ACK send, since delivery remains ambiguous.
  The caller must serialize operations and keep the VM/process alive whenever
  an owner is returned; `result.resumed` distinguishes a running owner from
  the paused `result.retained` case. The worker above now owns that lifecycle;
  early fresh-migration refusal remains active.
  `/usr/obj/5BSD-hypertrace-validation/migration-destination-runtime` passes
  sanitized extracted-production owner/runtime tests (actual resume adapter,
  mocked VM primitives), identity/fence rejection, lost-ACK reconnect without
  duplicate resume, uncertain-resume retry rejection, running-owner retention
  for both ACK outcomes, and journal binding retention. Production migration
  compiles with/without OpenSSL and the receiver object compiles. This does
  not establish live VM readiness or authorization to run VM tests.
- Added HXR1 RELEASE/ACK execution after HMX1 authenticated fact exchange.
  The source executor requires durable checked retirement (INTENT returns
  EBUSY), persists RELEASED before exchange/transmission, and records CONFIRMED
  only after the exact attempt-bound ACK. The destination observes the retained
  incarnation through owner callbacks, reconciles the facts, persists RELEASED
  before resume, verifies RUNNING, and persists RUNNING before ACK. A running
  destination retries confirmation without another resume; an uncertain resume
  quarantines its persistent in-process run state instead of blindly retrying.
  Callers must retain and serialize that state across reconnects. This is not
  process-crash reconstruction of guest RAM.
  `migration_prod_source_recover_release` connects the checked-retired source
  case to a new mutual-TLS connection. Production destination callbacks are
  now connected through the opt-in receiver worker described above.
  INTENT recovery still needs checked source destruction. Fresh migration stays
  disabled until those paths and the other lifecycle gaps are completed.
  `/usr/obj/5BSD-hypertrace-validation/migration-recovery-execute` passes
  sanitized real-TLS tests of normal/already-running recovery, lost and ambiguous
  ACKs followed by reconnect, RUNNING persistence failure followed by reconnect,
  failed-resume quarantine, unavailable destination, INTENT refusal, and altered
  RELEASE/ACK challenges. Tests assert durable phases at resume/ACK and at most
  one resume across retries. Production source adapter checks and production
  migration compilation with/without OpenSSL also pass.
- Added HMX1 recovery-fact exchange on a dedicated mutual-TLS connection.
  Each side reloads/fsyncs its HMR2 journal, verifies both certificate pins
  against the authenticated channel, and validates direction, version,
  canonical bytes, and the complete attempt binding before exposing results.
  Source speaks first; destination validates before responding. Missing or
  corrupt evidence, plaintext, a different channel transport, and changed
  bindings cannot produce recovery facts. This exchange returns snapshots;
  it does not mutate journals, authorize tracing, or resume a VM.
  `migration_prod_dest_recovery_exchange` connects it to a retained production
  owner after checking the live VM identity, saved device-state digest, FSS1,
  and retained COMMIT binding. The caller must serialize owner operations.
  `/usr/obj/5BSD-hypertrace-validation/migration-recovery-exchange` passes
  sanitized real mutual-TLS socketpair tests with distinct certificates,
  disk-phase reload and reconciliation, missing/mismatched journal cases,
  every-byte wire mutation and all truncation lengths, production-owner
  reconnect checks, and production migration compilation with/without OpenSSL.
  HXR1 execution is now implemented as described above; receiver integration
  and source INTENT recovery remain unfinished. Fresh migration stays disabled.
- Added a production retained-owner entry point,
  `migration_prod_dest_serve_recoverable`. The adapter allocates its owner
  before receiving state and duplicates the recovery directory descriptor
  with CLOEXEC. An uncertain transport can hand back the exact context,
  device-state blob, COMMIT binding, and journal descriptor without freeing
  them; an existing owner cannot be overwritten by another serve call.
  Normal completion and setup errors release the temporary owner. The old
  entry point does not supply a retention callback, so callers without an
  owner lifecycle cannot accept fresh migration. Authenticated fact exchange
  is now connected as described above; the receiver still needs
  full runtime qualification of its worker and recovery executor. The early
  production HyperTrace refusal remains active in both entry points.
  `/usr/obj/5BSD-hypertrace-validation/migration-retained-owner` passed the
  sanitized extracted-production lifetime fixture (including independent fd
  lifetime, ownership reuse, setup/allocation failures and production refusal),
  production migration compilation with/without OpenSSL, and receiver
  compilation. No running VM or kernel device was used.
- Collector-crash audit: `dtrace_hypertrace_epoch_suspend` drains active
  guest-origin actions but does not destroy collector buffers or establish
  closure of inherited DTrace handles. The durable collector census must
  therefore continue to require exact FSA1 completion, even when the socket
  or process disappears. Crash-before-FSA1 recovery needs an authoritative
  handle-stop/discard mechanism; a PID/death check or epoch-gate query alone
  is insufficient. That implementation gap remains open.
- The migration session state machine now requires a `do_retain` recovery
  owner for fresh migration and rejects adapters without it before accepting
  state. After durable STAGED and an attempted COMMIT send, failures before
  resume hand the exact paused image and commit binding to that owner instead
  of discarding. `result.retained` and `MIGRATION_PHASE_RECOVERY` distinguish
  this from completion; callers must keep the owner alive. No source rollback
  rule changed. The owner must reserve resources before COMMIT and cannot
  resume the guest during handoff. Resume failures are not classified as an
  intact paused image. The production owner described above now implements
  handoff, but early fresh-migration refusal remains in place. Runtime qualification,
  authenticated reconnect and execution, and destination process-crash recovery
  are still unfinished.
  `/usr/obj/5BSD-hypertrace-validation/migration-retain` passed all 36 sanitized
  migration cases, the expanded COMMIT/RELEASE delivery-loss cases and durable
  boundary tests, and compilation of the production migration object.
- Added the recovery reconciliation decision function in
  `usr.sbin/bhyve/migration_reconcile.h`. It checks the entire HMR2 attempt
  binding and authenticated certificate pair, distinguishes retirement intent
  from checked retirement, and requires observation of the exact retained
  destination incarnation. Missing VM state never becomes permission to
  reconstruct or resume it. Contradictory phases hold recovery; lost RELEASE
  selects retransmission, whereas an already running destination selects
  durable confirmation without another resume. This is a planning function,
  not a recovery executor or authorization to start tracing. The caller must
  retain ownership locks, load durable facts, authenticate the peer, verify
  the VM/startup fence, and execute the normal persistence transitions.
  The sanitized recovery fixture in
  `/usr/obj/5BSD-hypertrace-validation/migration-reconciliation` covers all
  36 source/destination/availability combinations, binding and certificate
  mismatches, and reconciliation of both records after reopening their
  directory. The session retention handoff described above supersedes discard
  for fresh adapters, but the receiver owner lifecycle and authenticated
  reconnect/recovery execution remain necessary. Fresh production admission is connected but not live-qualified.
- Recovery journals now use HMR2 (224 bytes), binding both source and
  destination leaf-certificate SHA-256 fingerprints in addition to FSS1,
  destination VM identity, challenge, device-state digest, and phase. TLS
  exports fingerprints only after chain verification and peer-pin checks;
  both production adapters copy the identities in the same source/destination
  order before capture or restore. Plaintext/failed channels cannot export
  these identities. Journal lookup/update requires the exact pair and rejects
  unbound HMR1 records rather than inventing a trust binding. Certificate
  rotation cannot silently authorize recovery of an older attempt.
  `/usr/obj/5BSD-hypertrace-validation/migration-journal-peer-binding` passed
  production migration/TLS/receiver compilation and the no-OpenSSL migration
  path, sanitized TLS/channel tests (including distinct client/server
  certificates and Capsicum), journal mismatch/legacy rejection checks,
  production journal adapter checks, and credential-selection tests.
  Recovery reconciliation/execution is still unfinished; persistent records
  and authenticated connections alone do not authorize a new runnable VM.
- Production migration now selects mutual TLS when credentials are supplied.
  Source IPC requires the complete set `tls_certificate_fd`,
  `tls_private_key_fd`, `tls_trust_fd`, and `tls_peer_sha256`. Receiver keys
  are `migrate.tls.certificate_fd`, `.private_key_fd`, `.trust_fd`, and
  `.peer_sha256`. Pins are exactly 64 hexadecimal digits for the peer leaf
  certificate's DER SHA-256. Any supplied field requests TLS; partial/wrongly
  typed configuration, unsupported builds, or TLS verification failure cannot
  select plaintext. Receiver credentials are marked close-on-exec before
  sandbox entry. Existing ordinary migration without TLS configuration keeps
  its explicit legacy stream behavior; HyperTrace entry points remain disabled.
  `/usr/obj/5BSD-hypertrace-validation/migration-tls-selection` passed source
  and receiver production compilation with and without OpenSSL, credential
  combination/type/range tests, and TLS tests through the production channel
  selector. A separate fixture process successfully handshakes and exchanges
  data after `cap_enter()` using only pre-opened credentials and a socketpair.
  The OpenSSL implementation header is opaque to callers to avoid libmd SHA
  type collisions. Peer identity persistence is now connected as described
  above; recovery execution still needs completion before fresh migration is enabled.
- Added a TLS transport adapter (`migration_tls.c`) for snapshot-enabled
  OpenSSL builds. It requires TLS 1.3 or newer, mutual certificate-chain
  verification, and an exact configured peer leaf SHA-256 pin before exposing
  send/receive callbacks. PEM certificates, trust anchors, and the private key
  come from pre-opened descriptors; bounded pread leaves offsets unchanged.
  Private keys must be owned/private regular files, encrypted-key prompts
  are disabled, and no path-based configuration is loaded by initialization.
  The adapter enforces monotonic handshake/transfer deadlines, suppresses
  socket SIGPIPE, and restores borrowed descriptor blocking flags on cleanup.
  Session resumption/tickets are disabled so each connection verifies peers.
  `/usr/obj/5BSD-hypertrace-validation/migration-tls` passed sanitized local
  socketpair tests and production object compilation: mutual encrypted
  transfer, wrong pin, untrusted issuer, handshake and receive timeouts,
  exposed/mismatched private keys, descriptor offsets, and flag restoration.
  Production selection is now connected as described above. Recovery execution
  remains unfinished. No live network connection, VM, or installed credential changed.
- Fresh COMMIT is now canonical FMC1: destination VM identity, per-attempt
  challenge, and SHA-256 of the complete DEV_STATE blob (not guest RAM).
  The production source compares that digest with its own captured blob and
  rejects stale/invalid destination identity before recording retirement intent.
  The destination derives its identity from VMM and hashes the received blob.
  Both production persistence callbacks now call the HMR2 storage layer and
  reject wrong-role phases, mismatched challenges, and inconsistent execution
  state. Source journal descriptors arrive as IPC `recovery_fddir`; receiver
  `migrate.recovery_fd` is validated as a private owned directory before
  sandbox entry and passed through the explicit recovery-enabled config.
  These bindings do not authenticate the remote host; production HyperTrace
  entry points remain disabled pending trusted transport and recovery execution.
  `/usr/obj/5BSD-hypertrace-validation/migration-commit-binding` passed
  production migration/receiver compilation and all 36 sanitized migration
  model tests, including prepare/accept binding failures before retirement.
  Its `adapter` fixture exercises the actual production binding/persistence
  callbacks against real isolated files, including digest/identity mismatch,
  wrong-role phases, destruction/run prerequisites, and reloaded final states.
- The migration state machine now requires durable-record callbacks for fresh
  mode and invokes them at all seven recovery boundaries: source intent before
  retirement, checked retirement, release authorization before sending RELEASE,
  source confirmation after ACK; destination staged before COMMIT, release
  acceptance before resume, and running before ACK. Intent-persistence failure
  may have published a record, so it never permits source rollback. A failed
  running-record write keeps the already-running destination alive, withholds
  ACK, and reports a state error in the destination result. Record callback
  contracts bind every phase to the same challenge and VM/state tuple.
  The production adapters now implement these callbacks as described above.
  Authenticated peer binding is connected; recovery execution is still required.
  Fresh mode is rejected if required callbacks are absent.
  `/usr/obj/5BSD-hypertrace-validation/migration-recovery-boundaries` passed
  production compilation, all 36 sanitized migration model tests, and the
  durable journal fixture. The new model injects failure at each of the seven
  boundaries and checks that only a failed destination-staging publication
  permits source rollback; retirement-intent and later failures do not.
- Added durable migration fact storage in `migration_recovery.h` (now HMR2).
  Records bind canonical FSS1, destination identity, challenge, state digest,
  role, and a monotonic phase. Source phases distinguish retirement intent,
  checked retirement, release, and confirmation; destination phases distinguish
  staged, released, and running. Source and destination use separate files.
  A private pre-opened directory and per-attempt lock protect atomic replace;
  file and directory fsync complete publication. SHA-256 checks detect record
  corruption, not peer authenticity. Skipped/backward transitions, mismatched
  tuples, partial records, unsafe file permissions/types, and missing evidence
  are rejected. Exact retry finishes uncertain publication durability.
  Reopened reads require an independently known binding and publish no phase
  on failure. No record by itself authorizes restarting either VM.
  The sanitized fixture in
  `/usr/obj/5BSD-hypertrace-validation/migration-recovery-record` passes
  concurrent writers, file/directory fsync failures, retry, phase corruption,
  truncation, identity/digest mismatch, and reopened read tests.
  This storage layer is now connected to production migration callbacks;
  authenticated reconciliation and recovery execution remain unfinished.
- Fresh migration now requires RELEASE_ACK carrying the same destination
  challenge after successful destination resume. The source does not report
  confirmed completion until that acknowledgment arrives; timeout or an
  invalid acknowledgment leaves it retired, never rolled back. If ACK
  transmission fails after destination resume, the destination remains the
  running copy and reports a transport reason with `release_ack_sent=false`;
  it does not run discard or return an error that would make bhyverun exit.
  The production adapter logs that the source acknowledgment failed.
  `/usr/obj/5BSD-hypertrace-validation/migration-release-ack` passed production
  compilation and all 35 sanitized model tests, including ACK loss before
  delivery and an error reported after ACK delivery. Durable reconciliation
  after process restart remains unfinished; these in-memory results are not
  a persistent migration recovery journal.
- Transport audit: production accepts a caller-supplied stream descriptor;
  bhyverun validates SOCK_STREAM and sets close-on-exec. No authenticated
  remote migration wrapper was found in bhyvectl. Challenge/ACK frames alone
  do not authenticate a remote host. Production HyperTrace entry points stay
  disabled while trusted transport and durable recovery are implemented.
- Fresh migration COMMIT carries a nonzero random 32-byte destination
  challenge within FMC1. The source validates it before retirement and echoes it in
  RELEASE only after `so_retire()` succeeds. The destination requires both
  the successful release result and its exact challenge before calling the
  resume adapter. Legacy mode still requires an empty COMMIT and the ordinary
  release result. No challenge is treated as peer authentication or durable
  recovery proof; trusted transport and restart recovery remain unfinished.
  `/usr/obj/5BSD-hypertrace-validation/migration-release-challenge` passed
  production compilation and all 35 sanitized model tests. The retirement
  test now exercises ordinary and fresh success/failure paths and rejects a
  changed challenge with a valid CRC. Its final focused rerun also passed
  rejection of a fresh RELEASE downgraded to the legacy payload.
- Fresh migration destination restore/reset is now connected in the adapter:
  parse FSS1, preflight and hash the private image, stage the paused tracing
  device, restore device/kernel state, discard old TX descriptors, then
  commit while keeping the guest stopped. The migration-specific device
  stage permits preparation before remote retirement but blocks device
  resume, fresh attachment, and host authorization until explicit release.
  Release matches the exact staged FSS1 record and verifies the owned local
  destination gate; it is callable only by the trusted migration coordinator.
  It does not independently authenticate remote retirement.
  The post-RELEASE coordinator admits the daemon, rejects any old replay,
  restores time, releases/resumes the device, starts the fresh handshake,
  and finally releases the guest startup fence. Production entry points and
  fresh capability advertising remain disabled pending remote binding and
  recovery; the local epoch query is not used as remote retirement proof.
  `/usr/obj/5BSD-hypertrace-validation/migration-device-staging` passed the
  sanitized real-device fixture and production device compilation, including
  preparation with the source still present, resume refusal before release,
  wrong-record and gate failures, and duplicate exact release.
  `/usr/obj/5BSD-hypertrace-validation/migration-fresh-destination` passed
  production snapshot/migration compilation and fresh source/destination
  fixtures. Destination coverage injects failures at all 13 restore steps
  and seven resume steps, and rejects replay and a missing startup fence.
- Destination release validation now requires the exact successful result
  (reason NONE, detail zero), not just a RELEASE frame type. Empty, extended,
  failed, and nonzero-detail RELEASE messages cannot resume the guest after
  COMMIT. This validates protocol semantics; it is not cryptographic source
  authentication or durable recovery evidence.
- Added the shared `migration_snapshot_decode()` view parser for ordinary
  and fresh blobs. The caller selects the negotiated tracing mode; extra,
  missing, malformed, and overflowed records fail without publishing views.
  Both destination restore paths now use it. FSS1 validation does not
  establish remote retirement.
  `/usr/obj/5BSD-hypertrace-validation/migration-destination-release` contains
  passing production snapshot/migration compilation, sanitized fresh capture
  and blob parser checks, and all 35 sanitized migration model tests. The new
  destination test drives through COMMIT and checks four invalid RELEASE
  forms plus successful RELEASE. No live VM was run.
- Source migration now calls the shared guest/collector stop coordinator
  before vCPU and device pause, retaining the exported FSS1 record in its
  source context. Fresh device-state capture appends that canonical 40-byte
  record after metadata and kernel/device bytes, checks its current VM
  identity, and publishes no blob if the snapshot fence fails to release.
  Ordinary capture rejects active HyperTrace rather than omitting the record.
  Production entry points and fresh-capability advertising remain disabled:
  remote retirement binding and migration recovery remain unfinished.
  FSS1 is a stopped-session record, not source VM retirement evidence.
  Validation in `/usr/obj/5BSD-hypertrace-validation/migration-fresh-source`
  passed production snapshot/migration compilation, sanitized capture and
  production quiesce/retire fixtures, and the checkpoint stop coordinator
  fixture. Coverage includes stop-before-pause ordering, stop/pause failures,
  canonical record carriage, stale identities, and fence-release failure.
- Production migration retirement order approved by the user on 2026-10-19
  and implemented: after destination COMMIT, `prod_retire()` stops the
  checkpoint-paused tracing device and calls `vm_destroy_checked()` before
  RELEASE. Retirement failure and ambiguous RELEASE delivery cannot resume
  the source; `prod_resume()` independently rejects attempts after retirement
  begins. `prod_defunct()` only exits after confirming retirement succeeded.
  The previous automatic-review approval blocker is resolved.
- Recovery limitation: after retirement, transport failure can leave no
  running VM. The destination currently discards committed staging on a
  failed RELEASE exchange. Recovery may require an independent checkpoint
  or backup; there is no durable migration recovery/resume protocol yet.
  Never restart a source after ambiguous RELEASE delivery merely because
  the sender reported an error: the destination may already be running.
- Fresh tracing capability negotiation requires matching selection at both
  peers and a source retirement hook. Production does not advertise the
  capability, and both HyperTrace migration entry points still refuse it.
  Fresh-state carriage and destination reset have component coverage;
  remote retirement binding, recovery, and live qualification remain unfinished.
- Retirement validation artifacts are in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-production-retirement`.
  All 34 sanitized migration model tests, the sanitized production adapter
  fixture, and production migration object compilation passed.
  Production adapter fault injection exercises stop failure, checked-destroy
  failure, missing quiescence, success, and refusal to resume after retirement
  starts. The migration model covers retirement failure, RELEASE failure
  before delivery, and failure reported after delivery. These are isolated
  fixtures and production object compilation, not live VM qualification.
- Added authenticated consumer stop-proof commit (message 26). After worker
  quiescence and kernel gate verification, the CLI sends its original stop
  reply, then opens an independent connection using its existing consumer
  session and confirms HSA1 persistence before exit. Sending the reply first
  releases the waiting daemon worker so a single-worker configuration can
  process the commit. Failed/partial reply writes shut down that socket to
  release the waiting worker as well. The endpoint matches the permanent FSI1
  tuple, peer UID/PID, consumer birth/session, program digest, and durable
  recipient census before publishing FSA1. Wrong identities, refused stops,
  stale tokens, and absent gate ownership cannot create completion proof.
  Publication precedes the response; the collector makes one exact retry.
  The coordinator resolves a lost original reply using durable FSA1 instead
  of requiring that socket to remain alive. Protocol/endpoint fixtures and
  the actual receiver fixture pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-stop-commit`; the daemon
  links and the production CLI compiles there. The endpoint fixture drops
  the original stop reply entirely after independent proof publication.
  All 108 native port suites pass in `fresh-session-stop-commit-port` and
  the sanitized daemon build/link plus all 45 component suites pass in
  `fresh-session-stop-commit-daemon` under the same validation root. The
  final coordinator error-preservation adjustment also passes the focused
  collector-stop fixture in `fresh-session-stop-commit`.
  A process crash before proof publication is still unresolved; do not infer
  completion from PID disappearance. No live collector has been exercised.
  The final reply-before-commit ordering and dropped-reply recovery pass the
  actual receiver fixture in `fresh-session-stop-order`. This checks that a
  full reply is already available before opening the commit connection; it
  does not substitute for live single-worker daemon qualification.
  Delayed publication now reports pending progress: a missing collector or
  a disconnected/timed-out stop RPC without a receipt yields EAGAIN, which
  the authenticated endpoint maps to incomplete status. Broken collector
  sockets are retired; no missing proof becomes completion. Explicit refusal,
  malformed replies, corrupt receipts, and storage errors remain failures.
  Bhyve spaces incomplete collector steps by 100 ms under its existing
  ten-minute polling deadline. The fixture delays proof publication until
  after the coordinator returns pending, then verifies completion on retry.
  Coordinator timeout and interrupted-wait tests pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-stop-pending/coordinator`;
  the sanitized daemon collector-stop fixture and daemon link pass in the
  parent directory. No live delayed-proof recovery has been run.
- Reconnect recovery now checks permanent fresh-stop records before staging
  pending consumer deliveries. A stopped epoch creates no replay job; a
  corrupt stop record rejects recovery. Receipts and memorized spool entries
  remain intact for the collector-stop census, and the consumer connection
  remains available for its explicit stop exchange. The existing send-time
  source lock still handles a stop racing the recovery scan. This is one
  audited reconnect path, not completion of the full restart/reconnect audit.
  The sanitized collector-stop fixture verifies skipped old replay, retained
  connection/evidence, and corrupt-fence refusal in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-reconnect-regression`.
  The complete sanitized daemon build/link and all 45 component suites pass
  there. No daemon was started and no live recovery was performed.
- Current work status: the user resolved the restore-scope approval question
  and requested continued work. That approval is no longer a blocker.
  Remaining completion work includes authoritative recovery when a collector
  dies before committing stop proof; whole-epoch stop completion and safe journal
  retirement; auditing daemon restart/reconnect against permanent old-epoch
  fences; remote source-retirement proof and fresh-session migration;
  ordinary tracing and supported-architecture qualification; and execution
  of the matched host/guest acceptance checks in README.5BSD. Existing
  component tests do not establish those remaining requirements. Preserve
  old receipt journals until safe retirement is implemented.
- Connected format-5 restore after explicit user confirmation that VM restore
  should discard old tracing buffers and start fresh. The coordinator requires
  FSS1 without continuity transfer/release state, captures and verifies the
  stopped private image, stages the distinct destination gate, restores the
  VM, discards old transport descriptors before kernel commit, and rejects
  admission replay. After device resume it queues PREPARE before releasing
  the vCPU startup fence. The existing device communicator completes fresh
  authorization after guest ACTIVE, independently of posted receive buffers,
  with one exact retry and a reset-required failure state. It also bounds
  an unanswered fresh handshake. No old programs or aggregates are imported.
  Validation: production snapshot/device objects and sanitized actual-device
  tests pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-restore-integration`.
  Its new coordinator fixture executes the real restore function, checks
  ordering, injects failure at every boundary, rejects old replay/mixed
  continuity metadata, and forbids continuity calls. This is component
  evidence, not live restore or remote migration qualification.
- Checkpoint stop now checks all required stop/fresh capabilities under the
  device mutex before changing tracing state. A guest supporting stop alone
  remains usable for ordinary stop, but checkpoint begin rejects it before
  suspending the host gate or queuing a guest stop. Retry also checks the
  capabilities before accepting an existing stop operation.
  Validation: the sanitized actual-device fixture checks unsupported fresh
  restart leaves gate ownership and the queue unchanged, ordinary stop
  still works, and a supported checkpoint reuses the exact stop token.
  The coordinator fixture and production snapshot/device compilation pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-checkpoint-preflight`.
- Latest regression: all 108 native port suites pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-stop-commit-port`.
  This includes the fresh device authorization and consumer stop failure
  fixtures. It is not live host/guest qualification.
- Open recovery limitation: a consumer that crashes before persisting FSA1
  still leaves the coordinator unable to establish durable completion.
  The independent commit above handles a lost reply after publication; it
  does not establish completion for a crash before publication.
  Consumer process disappearance or a user-generated birth nonce cannot
  prove all inherited DTrace handles are closed. Keep the old epoch fenced
  and its receipt journals intact until an authoritative completion proof
  exists; do not turn this case into assumed success.
- Implemented device fresh authorization: `pci_vtdtr_session_authorize()`
  requires guest ACTIVE, matching destination identity, completed ring
  discard, and no paused/reset state. It sends authenticated release outside
  the device mutex, rejects concurrent calls, rechecks the exact identity and
  released gate, and only then opens ordinary publication. Failed or lost
  replies leave the local fence closed for retry. Success resets the real
  tracing channels and uses their returned generation, discards private queued
  controls/partial input, grants new READY credit, and wakes the reader.
  Duplicate success checks gate ownership without another release/reset.
  A subsequent stop clears the previous completion/handshake flags and binds
  a new stop to the current identity. Top-level format-5 restore now invokes
  attachment; the communicator authorizes asynchronously after guest ACTIVE.
  Validation: sanitized actual-device tests and production compilation pass
  in `/usr/obj/5BSD-hypertrace-validation/fresh-session-device-authorize-final`.
  Coverage includes pre-ACTIVE refusal, unlocked RPC/reentry, lost applied
  release, exact retry, transport reset generation, duplicate authorization,
  gate loss, and a new stop after authorization. No live session was run.
- Implemented authenticated fresh gate release: FRE1/SESSION_RELEASE has a
  distinct wire discriminator from FST1 stop. The daemon derives the current
  VM/epoch/session from its VMM-attested forwarder, serializes with source
  journal operations, refuses permanent fresh-stop fences and continuity
  tickets/gates, and resumes only the exact kernel gate owner. Kernel owner
  retention makes a lost resume result retryable without another resume;
  an unsuspended gate under another token is not success. The bhyve client
  checks ownership before sending and verifies the released state after the
  reply. This does not import programs or old deliveries. The device's fresh
  authorization transition above invokes it after ACTIVE, clears its local
  publication fence, and grants new ordinary traffic credit. The restore
  coordinator and communicator now invoke that path.
  Validation: all 107 native port suites pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-release-port`, including
  production client compilation. The final exact-owner released-state test
  passes in `/usr/obj/5BSD-hypertrace-validation/fresh-session-release-gate-final`.
  The daemon fixture covers source-fence refusal, wrong wire operation,
  stale attestation, wrong client/owner, uncertain applied resume, and exact
  idempotent retry. The final protocol fixture verifies discriminator and
  padding/zero-token rejection. The complete sanitized daemon build/link
  and all 45 component suites pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-release-daemon`.
  No live release has been performed.
- Implemented destination kernel gate ownership: fresh restore staging
  suspends the distinct destination epoch under a new locally generated
  token after validating the stopped source/private image. The token is
  retained across uncertain suspend/readback and exact retry. It is separate
  from the old source gate and is not serialized into FSS1. Device restore
  checks ownership again before importing the stopped metadata. Fresh attach
  also establishes/rechecks this gate, and attach status cannot report success
  after gate loss. This closes the kernel execution path in addition to the
  device publication fence. The communicator now releases this gate through
  fresh authorization after guest ACTIVE.
  Validation: sanitized actual-device tests and production compilation pass
  in `/usr/obj/5BSD-hypertrace-validation/fresh-session-destination-gate`.
  Tests cover uncertain suspend followed by same-token retry, gate loss at
  private restore, and gate loss during attach/status. No live VM is run.
- Implemented staged fresh private restore: while holding the device pause,
  the coordinator can bind FSS1 to an empty private image and a distinct
  destination epoch. Staging requires local source-epoch retirement and
  rejects queued controls, partial programs, runnable readiness, mismatched
  identity, and trailing private bytes. The actual restore callback reparses
  the image, rechecks identity and configuration, then imports stopped-session
  metadata instead of constructing a continuity replay queue. Resume remains
  blocked during staging and after import until ring discard succeeds.
  Top-level format-5 restore now selects this API before memory mutation.
  This integration does not qualify remote retirement.
  Validation: the sanitized actual-device fixture passes source-live,
  unpaused, runnable-image, post-preflight mutation, successful empty restore,
  and retained resume-fence checks in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-private-restore`.
- Implemented fresh checkpoint writer: HyperTrace checkpoints now select
  manifest version 5 and metadata tracing version 2. Before pausing vCPUs,
  the writer begins guest stop, waits for its exact acknowledgment, steps
  host collector shutdown to completion, exports FSS1, and writes/fsyncs it.
  A ten-minute overall stop budget bounds repeated progress; each collector
  RPC retains its own shorter deadline. Errors never release the old tracing
  gate or replay old work. Successful publication follows the existing
  checked device shutdown and VM destruction path, without HRC2 transfer or
  continuity release tickets. The continuity code remains preserved below
  the writer's disabled continuity selector. Stop-VM is still required.
  Replacing an old format-5 checkpoint removes its trace member as well.
  IMPORTANT: fresh restore remains explicitly ENOTSUP until the separate
  discard/reattach transaction is implemented. This writer is not yet an
  end-to-end usable checkpoint/restore feature. Live save has not been run.
  Validation: the actual stop helper passes guest wait/interrupted sleep,
  guest refusal, collector failure/progress/completion, timeout, and stale
  export cases in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-checkpoint-stop`.
  Production snapshot compilation passes there. The fixture is registered
  in the native port runner; it does not execute full checkpoint publication.
- Implemented stopped-session private save: device pause, size calculation,
  and private serialization accept a fresh source only after exact guest
  stop and collector completion. The source validator requires the owned
  host gate, fresh features, closed readiness, no pending continuity state,
  an empty control queue, and entirely empty partial-upload metadata.
  Saving additionally requires no unprocessed guest TX descriptors. The
  existing private record layout carries only identity/configuration with
  zero readiness, controls, and partial bytes; FSS1 remains the separate
  fresh-session manifest member. Continuity validation remains separate.
  The fresh writer selects this path. Fresh restore still requires its
  dedicated transaction rather than private-image replay.
  Validation: the sanitized actual-device fixture passes in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-private-save`, including
  missing collector proof, pending TX, stale partial metadata, successful
  pause/save/resume, and decoding an empty private image with exact identity.
- Implemented fresh checkpoint format distinction: manifest version 5 uses
  the same four hashed generation members as version 4, but its trace member
  is the fixed-size FSS1 stopped-session record. Version 4 remains the
  experimental continuity format. Serialization, parsing, generation names,
  member verification, and manifest identity hashing preserve this distinction.
  The snapshot loader verifies the trace digest and canonical FSS1 record,
  stores it separately from continuity transfer bytes, and skips continuity
  release recovery for version 5. The continuity restore transaction refuses
  version 5 until its separate discard/reattach transaction is connected.
  The fresh writer above selects version 5; no new restore capability is
  enabled by the format/loader work alone.
  Validation: sanitized manifest publication/readback, version-specific
  identity, and corrupted-member rejection pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-manifest`.
  The production loader's valid/truncated/checksum/noncanonical/wrong-format
  cases pass in `/usr/obj/5BSD-hypertrace-validation/fresh-session-load`.
  The loader fixture is registered in the native port runner. Snapshot,
  manifest, and VirtIO DTrace sources compile with production bhyve flags in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-manifest-production`.
- Implemented device collector coordination: after exact guest stop,
  `pci_vtdtr_session_collectors_stop_step()` calls the authenticated host
  endpoint without holding the device mutex. Concurrent calls are refused;
  each reply is checked against the same guest stop token, VM identity,
  host gate ownership, and current device state. Progress and errors cannot
  mark collectors stopped. Checkpoint export now requires collector
  completion as well as guest stop; guest-only quiescence cannot produce an
  FSS1 export. Import refuses an active collector RPC and does not inherit
  the source's local collector-completion flag. The caller must own device
  lifetime, as the checkpoint coordinator does. Source checkpoint wiring
  and fresh restore wiring are implemented above.
  Validation: the actual device's sanitized native fixture passes in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-device-collectors-final`.
  It covers RPC error/progress/completion, reentry rejection, unlocked RPC,
  changed stop token, lost gate, export refusal before completion, and
  idempotent completion. No live guest or checkpoint is exercised.
- Implemented control exchange: the separate FST1 `SESSION_STOP` request
  carries only the host gate token. The daemon derives the VM ID, epoch,
  and source session from a current VMM-attested forwarder, requires the
  exact suspended gate, publishes/rechecks the FSI1 admission fence, and
  invokes one collector stop step. Its reply distinguishes progress from
  a fully covered census. Malformed bodies, stale attestations, wrong
  client kinds, and conflicting sessions cannot report completion.
  `hypertrace_session_collectors_stop_step()` connects using bhyve's stable
  forwarder session, validates the reply, and rechecks host gate ownership.
  Control-response loss can be retried using durable collector receipts;
  collector-ACK loss without a receipt remains unresolved. The reply budget
  is renewed after the potentially 60-second collector operation, including
  refusal, instead of using the expired request-read deadline.
  The source checkpoint coordinator invokes this exchange through the
  device step. This exchange alone does not certify guest stop, identity
  retirement, or restored-session readiness.
  Validation: all 45 sanitized daemon component suites and the daemon link
  pass in `/usr/obj/5BSD-hypertrace-validation/fresh-session-stop-control-daemon`;
  all 105 native port suites pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-stop-control-port`.
  The expanded stop fixture exercises endpoint authentication, malformed
  bodies, unsuspended gates, missing collectors, conflicting sessions,
  progress/completion, repeat completion, and corrupted receipt refusal.
  The final protocol fixture separately passes canonical FST1 body/header
  checks. These tests do not execute a live bhyve/guest tracing session.
- Partially implemented: `begin_fresh_session_stop()` publishes a separate
  checksummed FSI1 admission fence for the old VM epoch. It requires the exact
  already-suspended host gate token, binds the source session, serializes with
  source journal operations, and fsyncs the record before publication. Exact
  retries are accepted; conflicting tokens or source sessions are refused.
  Failed final fsync/readback never removes a visible fence. A separate query
  can prove the durable fence without requiring the old VM to remain live.
  The common source admission check returns ECANCELED for fenced epochs,
  blocking uploads and ordinary journal transitions after daemon restart.
  Malformed evidence fails closed. New epochs remain independent. Queued
  consumer delivery cancellation retains its socket for the explicit stop
  exchange. This marker is permanent admission closure, not evidence that
  every collector has stopped or that the kernel identity has been retired.
  The checkpoint coordinator still must invoke the collector stop step,
  retire old journal contents, and audit complete daemon startup/reconnect
  behavior with those records present. No continuity transfer is introduced.
  Validation: sanitized daemon build/link and all 43 component suites pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-durable-fence-daemon`.
  The subsequent socket-retention changes pass a final rebuild and nine
  focused queue/admission/replay suites in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-durable-fence-final`.
  The new fence test covers exact/conflicting retries, publication and
  directory fsync failures, restart persistence, malformed records, blocked
  old-epoch uploads, and unaffected new-epoch admission.
- Implemented discovery API: `fresh_session_consumers()` takes the durable
  source admission cut before reading inbound receipts. It validates the
  exact stop token/session, finds collectors by the old VM ID and epoch, and
  uses persisted HCP1/HCO1 identity and program proof instead of the live
  socket list. Repeated deliveries to one process are deduplicated; conflicting
  program proofs fail. Missing process/program proof is not treated as a
  stopped collector. Other epochs are excluded. Aliased source/inbound
  directories are rejected before nested process locking. Preserved HTD5
  continuity recipients currently return ENOTSUP rather than being omitted.
  Discovery alone never claims collector retirement. The coordinator step
  below consumes this census; checkpoint orchestration is pending.
  The actual-daemon fixture passes for duplicate deliveries, disconnected
  recipients, missing proof, conflicting digests, and wrong stop identity in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-consumer-census-final`.
  The full sanitized daemon build/link and all 44 component suites pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-consumer-census-daemon`;
  the final directory-alias guard also passes the targeted census fixture and
  complete daemon relink. These checks do not execute live collector stops.
- Implemented coordinator step: `stop_fresh_session_step()` finds an exact
  live collector by session, UID/PID, process birth, and program digest. It
  holds a client reference but releases client/journal locks before the HST1
  exchange. Only a matching successful HSA1 reply may publish a checksummed
  FSA1 record bound to the FSI1 fence and collector owner/program. The record
  is fsynced before retiring the connection. One call records at most one
  new stop; subsequent calls skip exact durable proofs and return complete
  only when the current census is covered. Missing collectors and refused or
  lost replies remain unresolved. A failed final directory fsync can be
  resolved by an exact read-and-fsync retry. Corrupted or conflicting proof
  is never repaired in place. Individual receipt checks validate the exact
  HCR1/HCP1 identity without rescanning the complete census for every owner.
  The new actual-daemon fixture exercises RPC refusal/success, missing live
  collectors, durable receipt restart, file/directory fsync failure, and
  corruption. The authenticated endpoint above now exposes this step;
  bhyve checkpoint invocation is pending. Lost ACKs with no durable proof still require
  process-exit resolution. Preserve the source receipt/owner evidence until
  an epoch-wide completion record permits journal retirement; deleting it
  now would prevent durable per-collector proof validation.
  Validation: sanitized daemon build/link and all 45 component suites pass
  in `/usr/obj/5BSD-hypertrace-validation/fresh-session-stop-step-daemon`.
  Final direct receipt lookup and error-preservation changes pass the actual
  coordinator socketpair/journal fixture and complete daemon relink in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-stop-step-final`.

- Implemented: host and guest ordinary feature negotiation requires only
  CONTROL, KILL_APPLIED, HOST_ELF_DIGEST, and CLEANUP_APPLIED. NODE_REKEY,
  REKEY_COMMIT, and REKEY_RECEIPT remain optional experimental features.
  Continuity checkpoint admission still requires its complete feature set.
- Partially implemented: `quiesce_guest_tracing()` closes guest launch
  admission and waits for owned tracing children to exit without re-exec,
  a wire acknowledgment, or journal transfer. Admission and child-registry
  lock waits share the child-exit deadline. Failure keeps admission closed.
  Existing cleanup uses this operation before its ACK and re-exec.
  The host/guest stop control now exists as a separately negotiated
  SESSION_STOP_V1 feature. Bhyve's begin/status API binds a random stop
  token to the current VM identity, blocks new and in-flight publication,
  discards its pending queue/partial ELF, and accepts only an exact proof
  after delivery of the request. The guest driver fences ordinary traffic,
  retains stop state across daemon failure, and sends SESSION_STOPPED only
  after the daemon verifies the driver-owned token and quiesces children.
  The stop request replaces pending dttransport entries. An active read
  copyout or allocation failure leaves that queue intact and the driver
  retries from its communication worker while ordinary traffic stays fenced.
  Accepting the daemon's exact stop proof frees the driver's pending
  outbound controls; descriptors already owned by a ring are not freed early.
  Guest daemon startup recognizes a retained SESSION_STOP token, recovers
  the exact child cohort, and sends SESSION_STOPPED (including exact retry
  after an already-applied stop). It then refuses ordinary startup with
  ESHUTDOWN before worker creation or journal replay. Initialization handles
  that result by waiting for the matching fresh preparation, then re-execing.
  The live stop reader uses the same wait after its acknowledgment. The wait
  checks the original stop token and identity, accepts only a matching pending
  or ready fresh identity, and is cancellable on daemon shutdown. It has no
  idle timeout because a stopped VM may remain checkpointed indefinitely.
  A recovery failure sends no proof. Interrupted proof writes share a bounded
  deadline. Old outbound writers exit quietly during cleanup instead of
  shutting down the daemon that owns this wait.
  Ordinary cleanup receipts and guest reset cannot release this fence.
  Bhyve now suspends the kernel's guest-origin tracing epoch before issuing
  the guest stop request. A restricted descriptor retained before capability
  mode permits gate query, suspend, and epoch-liveness query, never resume. Failed readback
  retains the ownership token for exact retry; a partial stop prevents the
  old continuity checkpoint path from capturing state. Completion checks
  both the guest acknowledgment and the still-owned host gate.
  Userspace collector teardown has the separate coordinator step above;
  checkpoint now invokes both steps. The kernel gate alone does not
  stop collector output.
  Issue the stop while guest CPUs are running; awaiting its acknowledgment
  after pausing them would deadlock. A failed stop must prevent publishing
  a checkpoint containing active tracing state.
- Partially implemented: a distinct `DTRACED_MSG_CONSUMER_STOP` exchange
  carries HST1 requests and HSA1 acknowledgments. It binds the host gate token,
  source session, consumer session, program digest, VM ID, and epoch. The
  daemon sender validates every echoed field and uses one 60-second I/O
  deadline after output serialization. A failed or malformed exchange closes
  the stream; it never treats a lost reply as successful retirement. A drain
  acknowledgment cannot satisfy this stop exchange. All 104 native port suites
  pass in `/usr/obj/5BSD-hypertrace-validation/fresh-session-consumer-stop-native`;
  final field-mismatch coverage also passes in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-consumer-stop-sender-final`.
  The sanitized actual daemon build/link and all 42 component suites pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-consumer-stop-daemon`.
  The DTrace consumer receiver now handles this exchange. It verifies its
  session/digest and the held kernel gate, closes program admission, and waits
  for the active program, execution reporter, and output worker before stopping
  the DTrace handle and rechecking the gate. Queue-lock and worker waits share
  a 45-second deadline. The output worker suppresses final aggregates when it
  observes this stop and signals completion after output-format teardown.
  Old execution reports cease, queued reports are freed on exit, and normal
  shutdown skips old guest-kill messages. Failed stop leaves admission closed
  and sends no positive proof. A stopped receiver exits instead of reconnecting
  with its old session. The checkpoint coordinator still must invoke the
  collector step, retire durable authorizations and old session identity,
  and resolve missing acknowledgments; this is not whole-session retirement.
  Previously buffered downstream output is not a durable drain receipt.
  Ordinary consumer drain preserves output and cannot substitute for stop.
  Receiver/worker tests pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-consumer-stop-worker`;
  execution and report-cancellation tests pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-consumer-receiver-final`.
  All 105 native port suites pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-consumer-receiver-native-final`.
  The complete production DTrace consumer compiles and links against the
  existing experimental build libraries as
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-consumer-stop-dtrace`.
  No live tracing session was executed by these checks.
- Partially implemented: a separate fixed-size FSS1 record carries only the
  proven stopped identity, stop token, and fresh-session feature contract.
  Export checks guest and collector stop completion and the owned host gate. Paused
  import requires a distinct destination epoch and local old-epoch retirement;
  it rejects outstanding continuity operations before discarding private
  queued controls and partial ELF input. Import leaves the device paused and
  ordinary publication fenced. This is a metadata API, not a working restore
  path: coordinator wiring, complete ring recovery, and remote retirement
  proof remain pending. The record carries no programs, aggregates, gate
  ownership, or replay queues. The existing continuity format is unchanged.
  Validation: all 103 native port suites pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-record-native`.
  The device fixture covers truncated/malformed records, host-gate export
  refusal, unpaused import, live old-epoch refusal, outstanding continuity
  operations, private queue disposal, and exact/conflicting import retries.
  These checks do not execute a live VM restore.
- Partially implemented: `pci_vtdtr_session_discard_paused()` completes saved
  guest-to-host ring descriptors with zero length without parsing or forwarding
  their controls. It requires checkpoint ownership, imported stop metadata,
  both allocated rings, a distinct live destination identity, and confirmed
  old-epoch retirement. Import sets a pending flag that blocks both device
  resume and fresh attachment until discard succeeds. The drain is bounded by
  ring capacity; malformed chains retain the fence and request device reset.
  Host-to-guest receive buffers remain posted for the handshake; guest-owned
  descriptors are not freed or reset behind the guest's bookkeeping. The
  snapshot coordinator does not call this API yet. Host-to-guest stale-control
  handling and a matched full-ring restore test still need validation.
  Sanitized device tests pass in
  `/usr/obj/5BSD-hypertrace-validation/fresh-session-ring-device-final`, covering
  stale ELF/kill discard without host forwarding, incomplete ring restoration,
  ring-inspection failure, retirement refusal, malformed direction, bounded
  drain exhaustion, and resume fencing. The VirtIO core is mocked in this
  fixture; this is not proof of live split/packed ring restoration.
- Pending: discard saved ring contents, retire the
  old host identity, and reset the restored guest transport. Reuse the
  existing generation checks and teardown helpers where their guarantees
  apply; a socket reconnect alone does not reset guest state.
- Pending: establish a new guest/host identity and accept only newly
  authorized tracing programs. Do not import old pending deliveries or
  preserve aggregates. Define failure retry at this fresh-session boundary.
  The guest now implements SESSION_PREPARE under SESSION_FRESH_V1. It
  requires a completed stop, the exact old identity and stop token, and a
  distinct nonzero epoch. Preparation records the proposed identity as
  DTT_IDENTITY_FRESH_PENDING without changing the kernel's current identity
  or opening admission. Exact retries succeed; conflicting proposals fail.
  Bhyve advertises the fresh feature and provides attach begin/status APIs.
  Begin requires the proven stop tuple, a distinct destination epoch, and a
  local kernel query reporting the old epoch no longer live. It sends
  preparation, accepts readiness only after delivery of that preparation,
  queues commit, and accepts activation only after commit delivery. All
  replies must match both identities and the stop token. Exact replies are
  idempotent. A 60-second status deadline bounds incomplete attachment.
  Activation alone keeps host publication fenced: collector cleanup and the
  coordinator's admission release remain pending. The local epoch query is
  not a remote-host retirement certificate. Restored ring reset and checkpoint
  integration of the stop-tuple record remain pending; restore is not enabled.
  The driver also accepts DTT_SESSION_READY only for that prepared identity
  and original stop token, after applied shutdown. It retains
  DTT_IDENTITY_FRESH_READY and sends SESSION_READY carrying both identities
  and the token. Repeated preparation cannot downgrade readiness. This
  acknowledgment leaves the old kernel identity and traffic fence unchanged
  until an exact SESSION_COMMIT. The guest queues that commit for its worker,
  waits for old TX descriptors to be reclaimed, synchronizes the new kernel
  identity, and emits SESSION_ACTIVE. It retains FRESH_ACTIVE for daemon
  namespace selection and waits for host credit before ordinary transmission.
  Duplicate commits repeat the acknowledgment; another stop rejects the old
  commit and can prepare a subsequent fresh identity. Daemon startup now
  selects all three empty namespaces before sending local readiness, waits
  for the exact active identity, then recovers only that namespace before
  creating workers. Active restarts open existing namespaces without creating
  replacements. A stopped daemon re-execs when its driver reports matching
  preparation. Host coordination is now connected above; fresh restore remains
  unqualified on a live VM.
  `dir::fresh_empty_session()` provides a descriptor-relative, private
  directory named for the proposed VMID and epoch. It accepts an exact retry
  only while that directory is empty, rejects symlinks and unsafe ownership
  or permissions, and synchronizes the directory and its parent before
  returning it. Old parent journals are neither copied nor removed. This
  primitive is selected by daemon startup for pending/ready fresh identities;
  active identities instead require their existing session directories.
- Pending: validate stop, fresh attach, stale-message rejection, and
  failure/retry with matched host/guest images. Historical continuity
  fixtures are useful regressions, not acceptance criteria for this scope.

Bhyve fresh attach passes all 103 native port suites in
`fresh-session-host-attach-native-port/`. The final device fixture in
`fresh-session-host-attach-final/` additionally checks timeout fencing and
late old-session stop proofs. Coverage includes live-source refusal, missing
feature negotiation, wrong tokens, premature readiness/activation, exact
retry, and keeping host publication closed after activation. Epoch-query
validation passes `fresh-session-retired-gate/`; production `hypertrace.c`
also compiles with Capsicum enabled in `fresh-session-host-attach/`.
The coordinator does not yet call these attach APIs, and saved stop metadata,
collector retirement, host admission release, and restored ring handling
remain outstanding. No live restore is established by these tests.

Stopped-daemon handover passes `fresh-session-wait/` (matching preparation,
exact stop token, stale identity, interruption, and shutdown cancellation)
and `fresh-session-wait-recovery/`. The sanitized daemon build/link and all
42 component suites pass in `fresh-session-wait-native-daemon/`. Subsequent
writer and active-session stop refinements pass `fresh-session-wait-writer/`
and `fresh-session-wait-stop-wakeup/`; the final transport source is compiled
and linked into the daemon in `fresh-session-wait-final/`, whose real
child-ownership test also passes. These are component checks, not a live
checkpoint/restore or exec handover demonstration.

Daemon startup namespace selection and activation pass the source-extracted
fixture in `fresh-session-daemon-activate/`, the full sanitized daemon build
and 41 component suites in `fresh-session-daemon-activate-native/`, and the
additional `fresh-session-startup` fixture linked against those same objects.
That last fixture exercises the real initialize path and intercepts bind to
stop before workers start. It verifies readiness after all three directories
exist, activation before socket binding, active restart without another
readiness report, missing-active-directory refusal, and preservation of old
journals. The activation fixture checks timeout and stale identity refusal.
The native daemon runner now includes this additional fixture (42 cases).
No live daemon, guest, or host coordinator was started by these checks.

Guest activation passes all 102 native port suites in
`fresh-session-active-native-port/`, and the extended second-cycle fixture
passes `fresh-session-active-repeat-driver/`. Tests check premature/wrong
commit rejection, waiting for ring reclamation, new kernel identity, exact
active acknowledgment retry, stale stop-proof rejection, and another
stop/prepare cycle. The amd64 guest module builds successfully in
`fresh-session-active-virtio.log`. The complete host/guest attach lifecycle
is still unimplemented and unqualified.

Fresh local readiness passes the guest sanitizer fixture in
`fresh-session-local-ready-driver/`: stale identity/token rejection, exact
readiness retry, preparation retry after readiness, identity query, continued
traffic refusal, and the full readiness descriptor emitted by the TX worker.
Existing startup recovery passes `fresh-session-local-ready-recovery/`.
The changed amd64 guest module compiles in
`fresh-session-local-ready-virtio.log`. These paths are under the validation
root; no live guest or host activation is exercised.

The empty-session directory primitive passes its filesystem test and the
sanitized daemon build/link plus all 41 component suites in
`/usr/obj/5BSD-hypertrace-validation/fresh-session-directory-native/`.
The new test checks identity validation, empty retry, separate epochs,
preservation of old parent journals, rejection of populated directories and
symlinks, and rejection of unsafe parent/child permissions. Startup selection
and driver commit are still pending; this result does not prove fresh attach.

Fresh identity preparation passes the guest sanitizer fixture and all 102
native port suites in `fresh-session-prepare-driver/` and
`fresh-session-prepare-native-port/` under the validation root. The tests
cover absent feature negotiation, premature preparation, a wrong stop token,
unchanged epoch, exact retry, conflicting new identity, identity query, and
continued rejection of ordinary traffic. Both amd64 guest modules rebuild
successfully (`fresh-session-prepare-{dttransport,virtio}.log`). The transport
module ABI version is now 3, and the guest driver requires version 3 for its
new stop-queue symbol. No modules were installed or loaded.

Guest stopped-session startup recovery passes the sanitizer fixture in
`/usr/obj/5BSD-hypertrace-validation/fresh-session-daemon-stop-recovery/`.
It checks failed child recovery produces no acknowledgment, exact stop retry
still refuses ordinary startup, rekey/stop overlap is invalid, and write
failure or repeated interruption cannot produce success. The full sanitized
daemon build/link and all 40 component suites pass in
`fresh-session-daemon-recovery-native/`. Fresh attach and journal discard
remain separate outstanding work; ESHUTDOWN deliberately keeps startup closed.

Guest queue discard passes all 102 sanitized native port suites in
`/usr/obj/5BSD-hypertrace-validation/fresh-session-discard-native-port/`.
The transport fixture replaces a full 4096-entry queue with the stop request,
preserves entries across active-copyout refusal, and checks allocation/free
accounting. Additional allocation-failure cases pass separately in
`fresh-session-discard-allocation/`. Guest tests verify stop retry and that
the applied proof frees pending controls before transmitting SESSION_STOPPED.
Both changed amd64 modules build against the existing GENERIC build in
`fresh-session-discard-modules/`; the transport module exports the new stop
queue operation. This does not validate restored ring reset, journal discard,
or a live host/guest stop.

Host gate validation: all 102 sanitized native port suites pass in
`/usr/obj/5BSD-hypertrace-validation/fresh-session-host-gate-native-port/`.
The new ioctl fixture covers suspension followed by failed readback, exact
retry without a second suspension, foreign ownership, malformed replies,
identity changes, and a gate that is no longer suspended. The device fixture
checks that a failed host stop sends no guest stop request and blocks the old
checkpoint path, and that guest acknowledgment cannot hide loss of the host
gate. Production `hypertrace.c` also compiles with Capsicum enabled and
warnings treated as errors. These checks do not execute the live kernel gate
or establish userspace collector teardown, restore, or checkpoint safety.

The ordinary-feature split passes all 101 sanitized native port suites in
`/usr/obj/5BSD-hypertrace-validation/fresh-session-baseline-native-port/`.
The guest and bhyve fixtures accept the ordinary feature set without rekey,
reject each missing ordinary safety feature even when continuity features
are offered, and retain rejection of continuity restore for an ordinary-only
guest. This validates negotiation, not fresh-session restore or live tracing.

Guest-stop validation: the source-extracted ASan/UBSan fixture passes in
`/usr/obj/5BSD-hypertrace-validation/fresh-session-stop-focused/`, including
launch/registry contention timeouts, retirement failure, retry, and refusal
to acknowledge failure. The actual daemon-linked child-ownership fixture
passes in `fresh-session-stop-real-children/`: real process descriptors stop
the owned tracing child, preserve an unrelated process, and support an exact
retry after exit. This does not prove transport drain or checkpoint safety.
The sanitized native daemon build/link and all 40 component suites also pass
under `fresh-session-stop-native-daemon/`. The extended real-child case was
rerun separately against those same daemon objects after its fixture update.

The SESSION_STOP changes
pass all 101 native port suites in `fresh-session-stop-wire-native-port/`.
Final guest TX and host outbound-credit changes pass focused sanitizer runs
in `fresh-session-stop-driver-tx/` and `fresh-session-stop-host-final/`.
The daemon stop-token handler passes `fresh-session-stop-daemon-handler/`.
The full sanitized daemon build/link and all 40 component suites pass in
`fresh-session-stop-wire-native-daemon/`.
The fixtures cover exact retry, unsupported negotiation, wrong/premature
proofs, fenced old traffic, and stop proof transmission without re-exec.
The fresh reset/reattach path is still absent; checkpoint admission rejects
stop-state images until their reset semantics are implemented.

This file tracks the experimental implementation. A passing native test is
component evidence; it does not qualify a live VM. Do not promote this branch
or describe HyperTrace as mature until the revised target has matched
host/guest runtime evidence.

1. **Isolated candidate integration:** The V2 provenance candidate is merged
   into `experimental/hypertrace` with content hashes checked before each
   replacement and backups of the 52 prior files. The active branch passes
   54 native port suites and 35 daemon suites. This source merge is complete;
   live packet qualification remains under gate 8.
   The unbuilt `sys/cddl/dev/dtvirt` prototype has been removed from the
   active tree; `sys/cddl/dev/hypertrace` is the module selected by the
   DTrace module makefile and `sys/sys/hypertrace.h` owns the shared ABI.
2. **Source checkpoint cut and saved controls:** The save callback now refuses
   incomplete guest ingress, ELF suffixes missing their authenticated prefix,
   saved controls that destination queue planning cannot handle, and a guest
   that did not negotiate the complete restore feature set. A second source
   cut also refuses a private destination queue, an attached handoff ticket,
   a ticket wait, or outstanding rekey ACK/receipt state. Successful
   REKEY_APPLIED retires the ticket and clears its ACK identity, so the next
   checkpoint can start from a settled incarnation. The expanded native
   device fixture and all 68 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/source-settled-native-port/`;
   current-source 16-job development world builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `source-settled-buildworld-*.log` files. Existing
   queue validation rejects unfinished queued ELF runs. Source preflight now
   also inspects the paused guest-to-host VirtIO ring and rejects pending
   controls or an unreadable ring before writing snapshot bytes. The native
   device fixture covers both refusal paths; all 74 native port suites pass
   under `/usr/obj/5BSD-hypertrace-validation/source-vq-cut-native-port/`.
   Current-source 16-job development world builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the `source-vq-cut-*-buildworld.log`
   files under the same validation root.
   This closes the unsent guest-control cut but does not establish a
   transferable daemon/consumer execution state. A guest-to-host ELF
   upload holds the handoff process lock through its accepted journal fsync;
   PREPARE waits for that upload and now rejects any new upload until ABORT.
   PREPARE also rejects pending and accepted inbound uploads until a
   consumer recovery and destination transfer can account for them.
   PREPARE now audits an accepted upload's durable HCB1 recipient cohort,
   requires every HCR1 member to be execution-settled, and verifies that the
   original VM-envelope spool still contains the accepted bare-ELF digest.
   Missing cohorts, pending or parsed-only receipts, and absent spools report
   `EBUSY`; changed VM identity or ELF bytes report `EPROTO`. Even a fully
   checked upload reports `EOPNOTSUPP` before a ticket is written because its
   consumer enablement and derived delivery have no transfer lease yet.
   Source preflight now builds a bounded canonical `HTM1` metadata manifest
   from each accepted HTD4, its fixed HCB1 cohort, and terminal HCR1 phase.
   The manifest binds the source ticket and rejects changed bytes, reordered
   or duplicate entries, and a downgraded execution phase. Its digest detects
   torn transfer data; it is not an authentication credential. The verified
   ELF spool is referenced by HTD4 identity and must be copied and checked
   separately. No handoff ticket or durable transfer sidecar is published for
   this manifest yet, and PREPARE remains closed for accepted ingress.
   The source spool verifier can also return the exact bounded VM-envelope
   and ELF bytes it hashed, but only after the digest, file identity, and
   stability checks pass. A failed verification leaves the copy empty.
   The destination byte validator checks that copy against the decoded HTD4
   VM lifetime, envelope bounds, ELF magic, and bare-ELF digest before it can
   be staged. The focused fixture rejects changed ELF bytes, a changed VM ID,
   and a changed HTD4 digest. All 36 sanitized native daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/htm1-import-validation-native-daemon/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `htm1-import-*-buildworld.log` files under the same
   validation root. No destination journal import or program re-enablement
   has been enabled by these checks.
   Handoff HTH1 phase and REKEY_APPLIED publication now fsync a private
   temporary inode before linking the final name and syncing the directory.
   Restart removes
   abandoned temporary names, including the second link left by a crash
   after publication. Phase and REKEY_APPLIED readers open nonblocking and
   require a regular, owner-held, single-link private file, so a corrupted
   FIFO cannot hang recovery and a hard link or loose mode cannot silently
   become ticket authority. The handoff-ledger fixture covers failed phase
   fsync for both record kinds, both orphan windows, FIFO, link, and
   permission rejection. All 36 sanitized native daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/handoff-ledger-atomic-final-native-daemon/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `handoff-ledger-atomic-final-*-buildworld.log`
   files under the same validation root.
   Startup cleanup now takes the cross-process handoff lock only when it
   found a handoff temporary name, preventing a replacement daemon from
   deleting an older publisher's live inode without leaving lock files in
   unrelated directories. The forked recovery fixture proves cleanup waits
   for the publisher lock. All 36 sanitized daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/handoff-ledger-startup-lock-scoped-native-daemon/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `handoff-ledger-startup-lock-scoped-*-buildworld.log`
   files under the same validation root.
   Source PREPARE now audits the durable HDU2 claim and outbound publication
   behind every HTM1 recipient marked `executed_derived`. The audit reuses
   the outbound journal snapshot under the handoff lock, so it does not
   re-enter the directory publish mutex. A deliberately orphaned terminal
   `D` receipt fails with `EPROTO` and leaves no ticket; a reconciled
   no-derived cohort still reaches the deliberate `EOPNOTSUPP` transfer
   fence. All 36 sanitized native daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/derived-preflight-lockaware-native-daemon/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in
   `derived-preflight-lockaware-*-buildworld.log` under the same root.
   The new `HTP1` per-ingress frame binds copied VM-envelope and ELF bytes to
   the source ticket and canonical HTD4 record. Its decoder enforces the
   exact length, frame digest, and original bare-ELF digest, and releases no
   payload on failure. The host-ingress fixture covers a valid round trip,
   changed length, changed HTD4, changed payload with a recomputed outer
   digest, and a mismatched expected delivery. The frame is not yet carried
   by the checkpoint or imported into destination journals. All 36 sanitized
   native daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/htp1-frame-native-daemon/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `htp1-frame-*-buildworld.log` under the same validation
   root.
   Individual HTP1 encode/decode now requires the same prepared source
   ticket that HTM1 accepts; a committed digest or attached destination VM
   cannot authorize a frame even when the token matches. The host-ingress
   fixture covers both invalid ticket phases. All 36 sanitized native daemon
   suites pass under `htp1-phase-native-daemon/`, and current-source 16-job
   development world builds pass for amd64, arm64/aarch64, and riscv/riscv64
   in `htp1-phase-*-buildworld.log` under the validation root.
   A destination-side bundle decoder now requires the exact number and
   canonical order of HTP1 frames named by HTM1 before it returns any
   decoded entries or VM-envelope/ELF payloads. The fixture rejects missing,
   extra, reordered, corrupt, and wrong-ticket frames. This is local
   validation only; checkpoint authentication, durable destination import,
   and program re-enablement remain open. All 36 sanitized daemon suites
   pass under
   `/usr/obj/5BSD-hypertrace-validation/htm1-htp1-bundle-native-daemon/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `htm1-htp1-bundle-*-buildworld.log` under the same
   validation root.
   A private destination planner now accepts a structurally reserved ticket,
   decodes the complete source bundle, and replaces the source VM envelope,
   forwarder session, peer identity, VMID, and epoch with destination values.
   It rechecks each transformed bare-ELF digest before exposing any plan and
   preserves source execution receipts as evidence rather than treating them
   as destination execution. The host-ingress fixture covers rebinding,
   retained source bytes, missing destination authority, reused source
   session, and malformed destination name. All 36 sanitized daemon suites
   pass under `destination-rebind-native-daemon/`; current-source `-j16`
   development world builds pass for amd64, arm64/aarch64, and riscv/riscv64
   in `destination-rebind-*-buildworld.log` under the validation root. This
   does not publish journals, transfer bytes, or re-enable programs.
   The destination can now publish that verified source bundle as one hidden
   HTB1 sidecar, capped at 64 MiB and keyed by the handoff token. Its inode
   and containing directory are fsynced before success; an exact retry
   finishes a missed directory sync, while different bytes for the token
   fail. Recovery opens an owner-only regular single-link file without
   following symlinks, verifies its checksum and attested destination
   identity, and reconstructs the private plan. The host-ingress fixture
   covers absent, exact-retry, conflicting-name, loose-mode, and corrupted
   sidecars. All 36 sanitized daemon suites pass under
   `destination-stage-final-native-daemon/`; current-source `-j16`
   development world builds pass for amd64, arm64/aarch64, and riscv/riscv64
   in `destination-stage-*-buildworld.log` under the validation root. HTB1
   alone does not authorize DTrace execution; the pending-only importer
   described below consumes it.
   A destination pending importer now rereads HTB1 under its publication
   lock, checks program and delivery-key collisions and journal capacity,
   then publishes each destination HTD5 in pending phase before its verified
   spool. The host watcher ignores pending records. If a process dies after a
   pending record but before its spool, an exact retry completes the missing
   spool; no accepted phase or HCR1 receipt is imported. The separate
   destination fixture tests pending-only status, exact retry, spool repair,
   and final payload integrity. All 36 sanitized daemon suites pass under
   `destination-pending-native-daemon/`; current-source `-j16` development
   world builds pass for amd64, arm64/aarch64, and riscv/riscv64 in
   `destination-pending-*-buildworld.log` under the validation root. Durable
   consumer recovery and atomic promotion to accepted remain open.
   Pending import now also requires the exact durable destination ticket in
   reserved or mutating phase under the outbound cross-process handoff lock;
   a sidecar alone cannot create a journal. The fixture first denies import
   without that ledger state, then commits and reserves the matching ticket
   before testing import and retry. All 36 sanitized daemon suites pass under
   `destination-pending-authority-native-daemon/`; current-source `-j16`
   development world builds pass for amd64, arm64/aarch64, and riscv/riscv64
   in `destination-pending-authority-*-buildworld.log` under the validation
   root. Caller attestation, consumer liveness, and accepted promotion are
   still required before any imported program can execute.
   Imported pending ingress now uses HTD5 rather than an ordinary HTD4.
   Each destination record binds the handoff token, original forwarder
   session and VM lifetime, and attested destination identity. The normal
   upload retry API refuses HTD5, and the inbound watcher leaves it inert
   even if a record is wrongly renamed to accepted. The destination fixture
   checks the lineage fields, rejected normal promotion, and that an
   improperly accepted imported spool queues no consumer job. A separate
   destination execution lease and crash-safe accepted promotion remain
   necessary; HTM1 also needs multi-hop HTD5 lineage before another
   checkpoint can carry a restored ingress.
   All 36 sanitized daemon suites pass against the final source under
   `/usr/obj/5BSD-hypertrace-validation/import-htd5-bound-v47-final-native-daemon/`.
   The focused host-ingress rebuild passed after the watcher guard was
   added. Current-source `-j16 buildworld` passes for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `import-htd5-bound-v47-*-buildworld.log` files under the validation
   root; the amd64 log is named `import-htd5-bound-v47-final-amd64-buildworld.log`.
   A private HTL1 reservation now records the exact durable HCO1 owner bytes
   for each source recipient session, bound to the HTB1 digest, ticket, and
   destination VM lifetime. The destination requires live matching consumer
   sockets and pending HTD5 records before publishing HTL1; exact retry
   requires identical bytes. CANCEL removes HTL1 before HTB1 so a reserved
   ticket cannot leave an orphaned owner claim. The host-ingress fixture
   checks missing consumer and owner, exact retry, and cancellation. HTL1
   does not itself authorize an accepted phase or execution; HCR2/HCB2 and
   a consumer-program identity and recovery rule remain open.
   A recovery reader now validates the exact stage digest, canonical HTL1
   header and checksum, ordered recipient owners, pending HTD5 phases, and
   current HCO1 files without requiring a live socket. The fixture checks
   successful post-disconnect read, checksum rejection, and refusal while
   an imported record is wrongly marked accepted.
   The final focused host-ingress fixture, including conflicting-UID refusal
   and HTL1 removal on CANCEL, passes under
   `/usr/obj/5BSD-hypertrace-validation/import-owner-read-v47-uid-final/`.
   A later focused rebuild also verifies that removing an HCO1 owner makes
   HTL1 recovery refuse the reservation, then succeeds after the exact owner
   is restored; it passes under `import-owner-read-v47-hco1-final/`.
   The final sanitized daemon build and all 36 component suites pass under
   `/usr/obj/5BSD-hypertrace-validation/import-owner-read-v47-uid-final-native-daemon/`.
   Current-source `-j16 buildworld` passes on arm64/aarch64 and
   riscv/riscv64 in the `import-owner-read-v47-final-*-buildworld.log`
   files under the same validation root, and on amd64 in
   `import-owner-read-v47-uid-final-amd64-buildworld.log`.
   The destination now has separate HCR2/HCB2 codecs for imported HTD5
   recipients. HCR2 binds the full HTD5 bytes, one canonical HCO1 owner with
   process incarnation, and a nonzero consumer-program digest. HCB2 enforces
   a bounded, sorted, unique recipient set and validates nested records before
   returning any member. The host-ingress fixture covers exact round trips,
   wrong HTD5, missing program identity, duplicates, truncation, and a forged
   HCO1 incarnation with recomputed outer checksums. The sanitized native
   daemon build and all 36 component suites pass under
   `import-receipt-codec-v2-native-daemon/` in the validation root.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `import-receipt-codec-*-buildworld.log` under the same
   root. These codecs do not publish HCR2/HCB2 or accept imported HTD5.
   libdtrace now exposes HPI1, a domain-tagged digest of stripped compiled
   DOF with its process-local action callback value normalized in a temporary
   copy. The offline built-library suite verifies six programs across fresh
   compiler processes, distinguishes changed actions, and checks that the
   executable DOF is untouched. Protocol 48 carries that digest from
   `dtrace -E` to its primary ELF receiver. The daemon binds one nonzero
   digest per authenticated connection, allows an exact retry, rejects a
   changed digest, and requires the announcement before an HTL1 owner
   reservation. The protocol and host-ingress fixtures cover malformed
   headers, missing connection membership, zero digest, exact retry, and
   changed digest. All 36 sanitized native daemon suites pass under
   `program-announce-native-daemon/`, and the built-library suite passes
   under `program-announce-native-library/` in the validation root.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `program-announce-*-buildworld.log` under the same root.
   All 86 native port suites pass under `program-announce-v2-native-port/`; the
   transport fixture now excludes the unrelated HPI1 compiler function from
   its extracted library slice.
   A new HCP1 source sidecar is fsynced before a pending HCR1 recipient can
   receive an identified socket job. It binds that exact receipt, the current
   checked HCO1 process incarnation, and its announced HPI1 digest. Exact
   retry preserves it; the reader checks owner and outer checksums without
   requiring the old owner file to remain current. The host-ingress fixture
   checks publication, exact retry, and corruption rejection. All 36
   sanitized native daemon suites pass under
   `source-program-proof-native-daemon/`; current-source `-j16 buildworld`
   passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `source-program-proof-*-buildworld.log` under the validation root. Legacy
   HCR1 receipts can lack HCP1. A provisional HTM2 overlay now binds exact
   HTM1 bytes to one HCP1 per canonical recipient, validates both nested
   records, and rejects a source snapshot that changes while proofs are read.
   HANDOFF_EXPORT now carries HTM2 for accepted ingress, and PREPARE rebuilds
   the same program-bound HTX1 under the source lock before checking its
   digest. Legacy recipients without HCP1 cannot supply that export. The
   destination decoder retains checked program evidence in its inert HTB1
   plan. PREPARE still refuses accepted ingress because no destination
   execution lease exists; imported acceptance and execution remain fenced.
   The kernel now has privileged exact-epoch SUSPEND, RESUME, and gate-query
   ioctls for the DTrace origin-epoch fence. SUSPEND hides that VM epoch from
   the lock-free ECB firing path and drains in-flight actions; RESUME restores
   it after an abort, while VM release can revoke a suspended epoch. Each
   suspension binds a nonzero handoff token: exact retries are idempotent,
   RESUME requires the current owner token, and an exact SUSPEND retry cannot
   resuspend its completed ticket. A new SUSPEND must compare-and-swap the
   previously queried owner token, so an old request cannot re-freeze the VM
   after a later ticket completes. The daemon must still authorize any new
   ticket under its journal lock. A privileged query returns the gate state
   and last owner token;
   VM release clears that token. New
   guest-origin enables and probe registrations refuse the suspended epoch.
   This is a reversible source quiescence primitive, not yet a handoff lease.
   Buffered consumer output now has a ticket-bound HGD1 drain observation,
   but it still needs a durable destination ownership transition before
   PREPARE may accept ingress. The challenge binds HCO1/HCP1 evidence to the
   exact source ticket and HTX1 bundle.
   The outbound directory now has HGI1 source-gate begin and abort methods.
   Begin fsyncs an exact ticket/session/epoch/CAS-owner intent before the
   privileged SUSPEND ioctl, reuses it after a daemon restart, and rejects a
   second token or altered record. Abort requires the HTH2 ticket to be gone,
   verifies the current owner, issues exact-token RESUME, then unlinks and
   fsyncs the intent. Protocol 53 introduced these VMM-attested requests;
   protocol 54 retains them and adds the drain step. Bhyve begins the gate
   after pausing devices
   and the checkpoint session, before exporting HTX1, and aborts it after an
   unpublished ticket is settled. PREPARE requires the exact journaled gate
   owner and suspended kernel epoch under the handoff publication locks.
   Begin and abort each retry once through a new attested channel after a
   failed reply; unresolved results keep the source stopped. The destination
   execution lease still fences nonempty PREPARE. The source-gate fixture covers failed intent
   sync, failed SUSPEND, restart retry, exact abort, next-owner CAS, and record
   corruption without a live kernel gate. A second fault case covers directory
   sync failure after the intent link: retry finds the exact linked record
   without having suspended the epoch. A durable post-destroy HSL1 release
   retires the matching HGI1 intent, and a lost release acknowledgment can be
   replayed without restoring the dead gate. The source-gate fixture also
   forces a directory-sync failure after HSL1 publication and verifies that
   the exact retry removes the leftover intent.
   The final protocol-53 source-gate validation passed all 37 sanitized
   native daemon suites and all 92 native port suites under
   `/usr/obj/5BSD-hypertrace-validation/source-gate-final-native-{daemon,port}/`.
   Current-source 16-job development world builds passed on amd64,
   arm64/aarch64, and riscv/riscv64 in `source-gate-frozen-*-buildworld.log`
   under the same validation root. These checks do not exercise a live VM.
   The source-extracted epoch, privileged-ioctl, and probe-batch fixtures
   cover stale lifetimes, idempotence, authorization, release while suspended,
   token replacement, stale-request comparison, and registration refusal.
   All 89 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/epoch-cas-native-port/`.
   Current-source 16-job GENERIC kernel and development world builds pass
   for amd64, arm64/aarch64, and riscv/riscv64 in the
   `epoch-cas-*-buildkernel.log` and `epoch-cas-*-buildworld.log` files
   under the same validation root.
   A libdtrace `dtrace_consume_quiesced()` operation now forces a switch-policy
   buffer and aggregation snapshot after its caller fences producers, then
   flushes the consumer output stream. It refuses ring/fill policy, temporal
   ordering, structured output, and inactive handles. The normal work loop
   may skip a buffer pass, active ring/fill snapshots are rejected by the
   kernel, and structured output uses a separate sink.
   A consumer callback's positive abort is treated as a failed drain, not an
   acknowledgment of a partial pass.
   This API alone does not create the source fence or prove durable consumer
   output; the HGD1 checkpoint path below now supplies the ticket-bound
   request and receipt. PREPARE remains closed for nonempty ingress until the
   destination execution lease exists. The source-extracted fixture
   covers the forced pass and refusal/error paths. All 90 native port suites
   pass under `/usr/obj/5BSD-hypertrace-validation/consumer-quiesced-drain-native-port/`;
   current-source `-j16 buildworld` passes on amd64, arm64/aarch64, and
   riscv/riscv64 in
   `consumer-quiesced-drain-*-buildworld*.log` under the same validation root.
   The drain now asks the FreeBSD DTrace kernel whether this active state has
   ever enabled a speculative action, before and after the principal-buffer
   snapshot. An active speculation can retain records outside that snapshot,
   including from externally enabled DOF; the kernel returns `EOPNOTSUPP`
   rather than allowing a misleading HGD1 acknowledgment. A stopped state
   returns `EBUSY`. This is a conservative refusal, not speculation-state
   transfer, and the accepted-ingress execution lease remains open.
   The source-extracted library and FreeBSD ioctl fixtures pass; all 93
   native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/consumer-speculation-native-port/`.
   Current-source `-j16` GENERIC kernel and development world builds pass
   for amd64, arm64/aarch64, and riscv/riscv64 in the
   `consumer-speculation-*-buildkernel.log` and
   `consumer-speculation-*-buildworld.log` files under the validation root.
   Protocol 54 retains the fixed daemon-to-consumer drain challenge
   and echo reply carrying the handoff token, source and consumer sessions,
   HPI1 digest, and exact VM epoch. Decoders reject zero identities, an
   out-of-range VMID, nonzero padding, and malformed reply status. These
   codecs and header rules are covered by the daemon protocol fixture; they
   confer no handoff lease on their own. The consumer
   receiver now checks its exclusive session and announced HPI1 digest,
   verifies the kernel gate token before and after a serialized drain, and
   acknowledges success only after syncing a regular output file. Unsupported
   buffer modes, structured output, missing privileges, or a changed gate
   produce refusal; the HGD1 path now binds the sender to the source ticket
   and journals the durable observation.
   A successful reply only covers principal buffer output; aggregation and
   other in-process consumer state still need an execution-state lease or a
   deliberate refusal before accepted-ingress PREPARE can publish.
   A socket-level source-extracted test checks success and refusals for
   session mismatch, changed gate owner, unsuspended gate, failed consume,
   stopped tracing, and missing output. All 91 native port suites pass under
   `consumer-drain-receiver-native-port-final/`; current-source `-j16
   buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `consumer-drain-receiver-*-buildworld.log` under the validation root.
   The daemon consumer socket now has a serialized drain sender that validates
   an exact echo of all ticket, session, program, and VM-epoch fields. A clean
   refusal remains retryable; malformed replies close the socket. The sender
   now has a source-journal caller reached from bhyve's checkpoint request.
   The consumer re-announces its HPI1
   digest when reconnecting, so a replacement daemon can bind the same
   program before replay and later challenge it. Focused sender and reconnect
   fixtures cover those paths, including a refused first HPI1 announcement;
   neither by itself is a durable drain receipt. All 92 native port suites and 36
   sanitized native daemon suites pass under
   `consumer-drain-reconnect-native-port/` and
   `consumer-drain-reconnect-native-daemon/`. Current-source `-j16 buildworld`
   passes for amd64, arm64/aarch64, and riscv/riscv64 in the
   `consumer-drain-sender-amd64-buildworld.log` and
   `consumer-drain-reconnect-*-buildworld.log` files under the validation
   root.
   The outbound journal now has HGD1 per-recipient drain observations. A
   successful internal challenge can publish an exact, fsynced record bound
   to the source ticket, HTX1 digest, HCR1 receipt, HCO1 process birth, and
   HPI1 program digest. A retry accepts only the same record after checking
   the live source gate and rebuilding the bundle under the publication
   locks; a changed cut or corrupted record refuses. The host-ingress native
   fixture exercises the socket challenge, journal retry, restart read, and
   corruption fence. Protocol 54 adds a VMM-attested source drain step that
   includes the exact HTX1 digest and returns one byte: one recipient
   published or no work left. Bhyve loops over those steps after syncing the
   HTX1 sidecar and before PREPARE. Each request challenges at most one
   consumer, allowing a bounded reply deadline and an exact retry after a
   lost answer. The daemon rechecks the frozen source cut before publication
   and before reporting completion. HGD1 proves only flushed principal output;
   destination execution ownership remains absent, so nonempty PREPARE stays
   closed. The protocol, attested nonempty daemon request, and bhyve lost-ACK
   socket fixtures pass with all 37 sanitized daemon suites and 92 native
   port suites under `source-drain-step-native-{daemon,port}/` in the
   validation root. Current-source `-j16 buildworld` passes on amd64,
   arm64/aarch64, and riscv/riscv64 in
   `source-drain-step-*-buildworld.log` there.
   Each step currently rebuilds the bounded HTX1 bundle, so large cohorts
   still need a measured, restart-safe way to avoid repeated full ELF reads.
   Source PREPARE now reads every canonical HGD1 under its handoff publication
   lock after rebuilding HTM2 and comparing the HTX1 digest. Missing receipts
   return `EBUSY`; a changed or corrupt receipt returns `EPROTO`. A complete
   drained cohort reaches the deliberate `EOPNOTSUPP` execution-lease fence.
   The sanitized host-ingress fixture checks all three results.
   All 37 sanitized native daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/source-drain-receipt-final-native-daemon/`.
   Current-source `-j16` development world builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in
   `source-drain-receipt-*-buildworld.log` under the same validation root.
   Aborting a source gate now retires only that ticket's canonical HGD1
   observations after the exact kernel RESUME. An exact abort retry completes
   cleanup even if the directory sync failed after the unlink, while another
   ticket's receipts remain untouched. The 37 sanitized daemon suites pass
   under `source-drain-abort-native-daemon/`; the strengthened source-gate
   retry fixture passes after that suite. Current-source `-j16 buildworld`
   passes on amd64, arm64/aarch64, and riscv/riscv64 in
   `source-drain-abort-*-buildworld.log` under the validation root.
   All 36 sanitized native daemon suites and 90 native port suites pass under
   `consumer-drain-wire-native-daemon/` and `consumer-drain-final-native-port/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `consumer-drain-final-*-buildworld.log` and
   `consumer-drain-wire-riscv64-buildworld.log` under the same validation root.
   The quiesced consumer drain now refuses compiled aggregation identifiers,
   retained aggregation values, and values materialized by its final snapshot
   (including externally enabled DOF). Its ACK therefore cannot silently
   certify principal output while dropping aggregate state. The source-extracted
   fixture covers all three refusal points under
   `/usr/obj/5BSD-hypertrace-validation/consumer-quiesced-agg-refusal/`.
   The bhyve device fixture now initializes queue backpointers and indices
   like `vi_softc_linkup()`, fixing a worker-thread null dereference in the
   native suite. All 92 native port suites pass under
   `consumer-quiesced-agg-native-port-final/`. Current-source `-j16
   buildworld` passes on amd64, arm64/aarch64, and riscv/riscv64 in
   `consumer-quiesced-agg-*-buildworld.log` under the validation root.
   The source checkpoint now pauses devices and begins its exact kernel event
   session before exporting HTX1 or asking the daemon to PREPARE. The
   virtio-dtrace reader and kernel ingress are therefore fenced before the
   transfer digest is computed. The HTX1 sidecar and its directory entry are
   synced before PREPARE can publish a durable source ticket; an export or
   sync failure aborts the same kernel session before the source resumes.
   This fixes the previous ordering in which PREPARE could precede those
   checkpoint fences. The source now begins the separate DTrace origin-epoch
   gate before export; a durable consumer drain is still missing.
   All 92 native port suites pass under `source-cut-order-native-port/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `source-cut-durable-*-buildworld.log` under the validation
   root. These checks compile the reordered coordinator but do not exercise
   a live source VM.
   A program-bound source export now uses the frozen HCP1 process birth and
   HPI1 digest for a terminal HCR1 even after the current HCO1 disappears or
   rotates. Legacy HTM1 export still requires a current owner. The
   host-ingress fixture removes HCO1 and changes its UID and birth with valid
   checksums; HTM2 remains exact while the legacy path refuses missing or
   mismatched ownership. PREPARE still reaches its execution-lease fence.
   All 36 sanitized daemon suites pass under
   `source-proof-retention-native-daemon/`; `-j16 buildworld` passes for
   amd64, arm64/aarch64, and riscv/riscv64 in the
   `source-proof-retention-*-buildworld.log` files under the same
   validation root.
   Ordinary HCR1 execution reports now compare an available HCP1's frozen
   process birth and HPI1 digest with the live receiver before moving the
   durable receipt to an executed phase. The report socket's session/PID
   alone no longer lets a recycled process settle an older program; legacy
   receipts without HCP1 retain their existing path and remain ineligible
   for program-bound transfer. The host-ingress fixture checks changed birth
   and program digest without changing the receipt phase. All 36 sanitized
   native daemon suites pass under `source-execution-owner-native-daemon/`;
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `source-execution-owner-*-buildworld.log` under the validation root.
   HCE1 now journals an identity-checked HCP1 consumer execution report
   before moving HCR1 to an executed phase. Its checksum binds the exact
   HCR1, executed outcome, and frozen HCP1 digest; startup validates all
   HCE1 names and resumes an interrupted receipt rename. A report can
   settle an HCP1-backed pending HCR1 when its separate socket arrives
   before the job ACK, and the later ACK is idempotent. The host-ingress
   fixture simulates a crash after HCE1 publication and checks recovery
   from a pending HCR1. This closes a daemon journal gap; it does not grant
   destination execution or quiesce source host DTrace consumers. All 36
   sanitized native daemon suites pass under
   `source-execution-journal-final-native-daemon/`; `-j16 buildworld` passes
   for amd64, arm64/aarch64, and riscv/riscv64 in
   `source-execution-journal-*-buildworld.log` under the validation root.
   Guest-origin DTrace enablings and ECBs now carry the installing VM's
   lifetime epoch, including clauses that match host probes. The probe
   path skips a clause after that epoch is revoked; VM release clears the
   epoch and performs a cross-CPU DTrace sync, and VM destroy does this
   before memory teardown on amd64, arm64, and riscv64. Retained enablings
   cannot match newly registered probes after revocation, and replication
   refuses to combine different VM lifetimes. VM reset propagates a failed
   release instead of silently assigning the replacement identity. This
   supplies a source-side execution fence after VM destroy, but a durable
   release/grant protocol and matched live proof remain open. All 87
   sanitized native port suites pass under
   `source-epoch-gate-final-native-port/`, including the extracted kernel
   epoch lifecycle and VM-reset failure fixtures. `-j16 buildkernel`
   passes GENERIC on amd64, arm64/aarch64, and riscv/riscv64 in
   `source-epoch-gate-reset-*-buildkernel.log`; `-j16 buildworld` passes
   for those architectures in `source-epoch-gate-final-*-buildworld.log`,
   all under the validation root.
   Protocol 51 adds a dedicated source-release channel authenticated while
   the source VM still exists. Admission opens and retains the privileged
   HyperTrace device and requires the exact source epoch to be live before
   acknowledging the channel. If the device cannot be opened or queried,
   bhyve fails the preflight before destroying the VM; the retained descriptor
   permits the second query after destruction without reopening the device.
   Stop-checkpoint first quiesces the VirtIO
   workers, then checks VMM destruction, then requests a durable HSL1 record.
   The daemon accepts only that release operation on the channel, verifies
   the exact committed HTH2 source and checkpoint digest, and asks the
   privileged HyperTrace device whether the bound VM epoch is gone. The
   kernel answers after its DTrace ECB drain. HSL1 binds the committed
   ticket bytes and is fsynced before reply; destination reservation and
   reads of later ticket phases refuse a missing or damaged HSL1. A failed
   destroy or uncertain release
   acknowledgment exits without reporting a successful source cut. This is
   a local VMM-lifetime witness. Source host consumers, a portable cross-host
   lease, and destination recipient execution still need separate proof. No
   live VM evidence exists.
   HSA1 now defines a fixed Ed25519 attestation over the exact HSL1 bytes,
   pinned source public key, and intended destination public key. The source
   journal signing method refuses an absent HSL1 or changed committed ticket;
   the verifier independently reconstructs HSL1 from that ticket and rejects
   another source key or destination. The source journal now publishes HSA1
   as an atomic fsynced sidecar and recovers only an exact signature bound to
   the committed ticket and independently supplied keys. An exact retry
   returns those same durable bytes; corruption and changed keys fail closed.
   The production handoff now writes HSA1 beside a local checkpoint, but
   does not yet import and verify it at a destination; HSL1 alone remains
   local authority only.
   Nonempty handoff remains
   fenced pending that transport and a recipient execution lease.
   The standalone tamper/key-binding fixture and journal-backed signing
   fixture pass with all 38 sanitized native daemon suites under
   `/usr/obj/5BSD-hypertrace-validation/release-attestation-verified-native-daemon/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `release-attestation-*-buildworld.log` files under
   the same validation root.
   The durable HSA1 retry, restart, changed-destination, and on-disk
   signature-corruption cases pass with all 38 sanitized daemon suites under
   `release-sidecar-final-native-daemon/`. Current-source `-j16 buildworld`
   also passes for amd64, arm64/aarch64, and riscv/riscv64 in the
   `release-sidecar-*-buildworld.log` files under the same validation root.
   The source daemon now accepts an Ed25519 private key and independently
   pinned peer public key through paired `-K`/`-P` options. It checks file
   ownership, type, link count, and permissions before starting service.
   With keys configured, the actual VMM-attested source-release request
   writes HSL1 and HSA1 before acknowledging bhyve; a lost reply retries
   the exact sidecar. Unconfigured local release retains HSL1 behavior.
   The signed reply now reaches bhyve, but not an authenticated destination;
   it does not authorize cross-host admission.
   The key-loader and signed source-release control fixtures pass with all
   39 sanitized native daemon suites under `release-config-native-daemon/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `release-config-*-buildworld.log` files under the
   same validation root.
   Protocol 55 adds a post-release mode byte and, for configured hosts, the
   exact 324-byte HSA1 reply. Bhyve requires the complete reply after VM
   destruction, checks HSL1/HTH2 hashes and the checkpoint token/digest,
   then atomically publishes a token-named release sidecar beside the
   checkpoint. Restore loading rejects a malformed or mismatched sidecar
   before retaining it; old generation cleanup removes its sidecar. This
   structural check is not a signature trust decision. The destination
   daemon still needs to verify HSA1 with its pinned source key and receive
   the complete copied checkpoint member before cross-host admission.
   The HSA1 reply framing, truncation, checkpoint-sidecar retry/corruption,
   and source daemon control-path fixtures pass with all 94 native port and
   39 sanitized daemon suites under `release-reply-final-native-port/` and
   `release-reply-native-daemon/`. Current-source `-j16 buildworld` passes
   for amd64, arm64/aarch64, and riscv/riscv64 in the
   `release-reply-*-buildworld.log` files under the validation root.
   Protocol 56 adds a root-only local release-recovery channel with one
   read-only operation. It looks up the exact committed ticket and checkpoint
   digest, then returns only the previously fsynced HSA1 sidecar under the
   configured host and peer keys. Restore startup queries this channel only
   when its checkpoint sidecar is absent and atomically republishes an exact
   reply. Missing source state or an unsigned local release leaves the
   sidecar absent and grants no cross-host authority. The socket, request,
   and journal fixtures cover the exact response and wrong digest; matched
   live restart behavior remains unqualified.
   All 94 native port and 39 sanitized daemon suites pass under
   `release-recover-native-{port,daemon}/`. Current-source `-j16 buildworld`
   passes for amd64, arm64/aarch64, and riscv/riscv64 in the
   `release-recover-*-buildworld.log` files under the validation root.
   The destination-side journal decoder now reconstructs a committed ticket
   from HSA1's embedded HTH2, checks both nested hashes and canonical ticket
   bytes, then verifies Ed25519 against independently pinned source and
   destination keys and the expected checkpoint token and digest. It grants
   no reservation or execution authority. The tamper, wrong-key, wrong-token,
   and wrong-digest cases pass in all 39 sanitized daemon suites under
   `destination-decode-native-daemon/`. Current-source `-j16 buildworld`
   passes for amd64, arm64/aarch64, and riscv/riscv64 in the
   `destination-decode-*-buildworld.log` files under the validation root.
   The destination control channel and
   complete copied-checkpoint proof are still missing.
   Protocol 57 adds a VMM-attested release-import frame carrying the exact
   checkpoint token/digest and HSA1. The destination daemon checks HSA1
   against its configured peer source key and own destination key, then
   atomically stages it in a separate `.imported.<token>` journal sidecar.
   An exact retry is idempotent; restart reads reverify the signature and
   damaged sidecars fail closed. A same-host restore checks its existing
   HSL1 and HSA1 without creating a foreign sidecar. Bhyve sends the signed
   checkpoint sidecar before RESERVE and retries an uncertain lost ACK once.
   This staged foreign proof creates no handoff phase, destination execution
   lease, or authorization to run. Cross-host RESERVE still fails until a
   complete copied checkpoint and destination lease are implemented.
   The protocol, signature, corruption, restart, same-host, and lost-ACK
   cases pass with 39 sanitized daemon suites and 94 native port suites under
   `release-import-v57-native-{daemon,port}/` in the validation root.
   A focused sanitized rerun also passes the local-token collision assertion.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `release-import-v57-*-buildworld.log` files there.
   The release-only handshake, epoch query, journal retry, missing/corrupt
   HSL1 recovery, and reservation refusal pass in 36 sanitized daemon suites
   under `source-release-v51-witness-final-daemon/`. All 89 native port suites
   passed under `source-release-v51-final-native-port/`; focused tests for
   the final explicit ioctl padding and bhyve release-channel handshake also
   passed. `-j16 buildworld` completed for amd64, arm64/aarch64, and
   riscv/riscv64 in `source-release-v51-witness-final-*-buildworld.log`, and
   `-j16 buildkernel` completed for all three GENERIC targets in
   `source-release-v51-final-*-buildkernel.log`, under the validation root.
   The retained-device admission refinement passed all 36 sanitized daemon
   suites under `source-release-v51-preflight-final-daemon/`, including stale
   and live epoch admission and descriptor cleanup. A second fixture run under
   `source-release-v51-preflight-denial-daemon/` also checks device-open
   refusal before the channel is acknowledged. Its updated amd64, arm64,
   and riscv64 world builds passed in
   `source-release-v51-preflight-final-*-buildworld.log`.
   HTL1 reservation now checks each live destination consumer's announced
   HPI1 against the matching HTM2 source proof before it publishes the owner
   set; the fixture rejects a changed program digest. This live comparison
   is necessary but does not provide HCR2/HCB2 durability or result slots.
   An inert planner now derives canonical HCB2 cohorts from the reloaded HTB1
   program evidence and HTL1 owner snapshot. Reservation checks that every
   cohort can be encoded before publishing HTL1, then fsyncs one HCK1 bundle
   carrying the exact ordered HCB2 bytes and both sidecar digests. Exact
   retry can finish HCK1 after an interrupted publication; the reader
   recomputes and verifies it, and CANCEL deletes it before HTL1. The
   focused fixture found
   and fixed a staging-plan copy that dropped HTM2 proofs, then verified the
   reloaded sidecar, both HCB2 cohorts, zero-digest rejection, and reordered
   proof rejection. All 36 sanitized native daemon suites pass under
   `htm2-cohort-plan-native-daemon/` in the validation root. Current-source
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `htm2-cohort-plan-*-buildworld.log`. The HCK1 fixture additionally checks
   durable bytes, missing-sidecar retry, corruption refusal, recovery, and
   CANCEL cleanup. All 36 sanitized native daemon suites pass under
   `hck1-inert-publish-native-daemon/`; current-source `-j16 buildworld`
   passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `hck1-inert-publish-*-buildworld.log`. HRS1 now follows HCK1 with one
   immutable pending slot per HCR2 digest, bound to the ticket and HCK1
   digest. Exact retry fills a missing HRS1, the reader rejects changed
   bytes, and CANCEL removes it first. The focused sanitized fixture passes
   under `hrs1-pending-slots-focused/`. All 36 sanitized native daemon suites
   pass under `hrs1-pending-slots-native-daemon/`, and current-source
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `hrs1-pending-slots-*-buildworld.log`. No outcome or accepted HTD5 is
   published. The HRO1 codec now binds a proposed processed or executed
   outcome to the ticket, HRS1 digest, and HCR2 digest. It requires a nonzero
   claim digest field exactly for derived phases and rejects noncanonical reserved
   bytes. The focused sanitized host-ingress fixture passes under
   `hro1-outcome-codec-focused/`. All 36 sanitized native daemon suites pass
   under `hro1-outcome-codec-native-daemon/`, and current-source `-j16
   buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `hro1-outcome-codec-*-buildworld.log`. HRO1 has no journal publication yet.
   HPA1 now follows HRS1 with the fixed ordered HTD5 identity digests,
   bound to the HRS1 digest. Reservation publishes it only after the owner,
   cohort, and pending-slot sidecars; exact retry checks the same bytes.
   Its reader rejects a changed sidecar, and CANCEL deletes it before HRS1.
   The fixture also removes HPA1 and confirms that exact retry recreates it.
   All 36 sanitized native daemon suites pass under
   `hpa1-intent-native-daemon/`; the focused host-ingress rerun after the
   missing-sidecar check passes. Current-source `-j16 buildworld` passes for
   amd64, arm64/aarch64, and riscv/riscv64 in
   `hpa1-intent-*-buildworld.log`. HPA1 is inert and does not permit accepted
   delivery or execution.
   The HPA1 reader now verifies the entire staged sidecar chain under the
   outbound ticket and inbound journal locks, including the current durable
   HCO1 owners and the absence of unplanned records for the token. Its
   explicit recovery view accepts a mixed pending/accepted HTD5 set without
   changing the fixed HPA1 identities; the ordinary view still refuses an
   accepted member. The focused host-ingress fixture covers both views with
   one artificially renamed record, while the watcher remains fenced. This
   supplies recovery evidence but does not publish an execution lease. All
   36 sanitized native daemon suites pass under `hpa1-recovery-native-daemon/`;
   the focused fixture also passes under `hpa1-recovery-focused/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `hpa1-recovery-*-buildworld.log`.
   The attested `HANDOFF_IMPORT` handler now reserves the live destination
   consumer after writing pending HTD5 records. A missing consumer fails the
   request with pending work fenced; an exact retry with the matching HPI1
   image completes HTL1, HCK1, HRS1, and HPA1 before the ACK. The handler
   refuses a legacy manifest without HCP1 evidence. The focused host-ingress
   request fixture covers the failed first attempt and successful exact
   retries. All 36 sanitized native daemon suites pass under
   `import-owner-control-native-daemon/`; the focused fixture passes under
   `import-owner-control-focused/`. Current-source `-j16 buildworld` passes
   for amd64, arm64/aarch64, and riscv/riscv64 in
   `import-owner-control-*-buildworld.log`. Accepted promotion and dispatch
   still require a separate lease.
   A claimed-ticket promotion component now checks the fixed sidecar chain
   and live HCO1/HPI1 match under ticket, socket, and journal locks. It
   completes a partially accepted set without reselecting recipients, then
   fsyncs HLC1 only after every HTD5 is accepted. An exact retry validates
   HLC1 without requiring the consumer to remain connected; a changed marker
   fails. CANCEL refuses a stray HLC1 even on a reserved ticket. The focused
   fixture simulates a crash after the first phase rename and verifies the
   remaining rename, marker, retry, changed live HPI1 refusal, and continuing
   watcher fence. All 36 sanitized native daemon suites pass under
   `hlc1-promotion-native-daemon/`; the focused fixture passes under
   `hlc1-promotion-focused/` and with the later HPI1 check against those
   daemon objects. Current-source `-j16 buildworld` passes for amd64,
   arm64/aarch64, and riscv/riscv64 in `hlc1-promotion-*-buildworld.log`.
   Protocol 49 now exposes `HANDOFF_PROMOTE_IMPORT` through the attested
   destination control channel. The daemon requires a claimed ticket,
   checkpoint digest, and VMM-attested destination identity. It binds saved
   source KILLs under the revocation lock before invoking
   the HLC1 transaction. It accepts an absent stage only for a ticket bound
   to the canonical empty HTX1. The focused request fixture covers early
   phase refusal, wrong digest, successful nonempty promotion, and an exact
   retry after the consumer disconnects. The bhyve frame helper accepts the
   opcode, while restore still fences nonempty ingress until execution and
   replay are implemented. HLC1 is not yet an execution lease. The KILL bind
   regression passes with all 36 sanitized native daemon suites in
   `promote-kill-bind-native-daemon/`; `-j16 buildworld` passes for amd64,
   arm64/aarch64, and riscv/riscv64 in
   `promote-kill-bind-*-buildworld.log`.
   Protocol 50 adds an attested `HANDOFF_ACTIVATE_IMPORT` after the guest's
   REKEY_APPLIED report. The daemon first binds late KILLs, then requires the
   durable rekey record before it may publish HLA1. The marker binds the
   claimed ticket, HLC1, HRS1, and destination incarnation; exact retries
   validate it. Recovery rejects a damaged or orphaned HLA1; cancellation
   refuses an orphan rather than deleting its stage. The host ingress fixture
   covers early refusal, idempotent activation, and marker corruption. HLA1 is
   an activation gate, not a recipient execution lease;
   the nonempty restore fence remains until dispatch and replay are complete.
   An atomic read-only view now returns the fixed HCR2 recipients and HRO1
   outcomes only behind verified HLA1. It does not select or launch consumers.
   A report-side lookup resolves one exact HCR2 owner and outcome from the
   ingress session and delivery ID under the claimed ticket and HLA1 checks.
   An imported consumer execution report now verifies its live HCO1 birth,
   HPI1 program digest, processed HRO1 outcome, and exact HTD5 identity.
   The terminal HRO1 writer checks HLA1 and audits every fixed HRS1 slot
   under ticket and journal locks. The native fixture covers an exact report,
   conflicting outcome, changed consumer program, inactive import, damaged
   marker, and an activation marker whose stage record is missing.
   A per-consumer recovery census now walks accepted HTD5 records and returns
   only activated HCR2 recipients whose frozen HCO1 and HPI1 match the live
   receiver. HLA1 activation, later HPI1 registration, and admission replay
   completion queue pending fixed recipients. An exact HPI1 retry also
   rechecks work after a failed queue attempt; each job revalidates the
   ticket, recipient, and spool bytes before sending. Derived uploads from
   an imported parent now require its activated HCR2 and the live HCO1/HPI1
   receiver. After an exact ACK, the
   daemon resolves any HDU2 claim against a published spool or delivered
   outbound receipt, then writes the processed HRO1. A missing ACK can
   recover only a proven derived result. The focused fixture exercises
   HPI1 replay queueing, imported ELF send, derived ACK, and execution report
   through terminal HRO1. Bhyve still fences nonempty restore until its
   coordinator and crash windows use this path.
   The admission-replay and exact-HPI1-retry follow-up passes all 36
   sanitized native daemon suites under
   `/usr/obj/5BSD-hypertrace-validation/imported-admission-final-native-daemon/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `imported-admission-final-*-buildworld.log` files
   under the validation root.
   The 36 sanitized native daemon suites pass in
   `hla1-recovery-census-native-daemon/`, and the final-source focused
   host-ingress run passes as `host-ingress-final.log` in that directory.
   Final-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `hla1-census-race-*-buildworld.log` under the validation
   object root.
   The final orphan-marker change passes all 36 sanitized native daemon
   suites in `hla1-orphan-final-native-daemon/`.
   All 36 sanitized native daemon suites pass under
   `hla1-final-native-daemon/`, and all 86 native port suites pass under
   `hla1-native-port-rerun/`. The final-source activation and recovery view
   fixture passes under `hla1-active-view/`. Current-source `-j16 buildworld`
   passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `hla1-view-*-buildworld.log`, all within the validation object root.
   A read-only committed-import reader now checks the exact claimed ticket,
   fixed sidecar chain, accepted HTD5 set, and HLC1 without creating the
   marker. Its fixture tests a partial phase transition, absent marker,
   orphan marker, corrupt marker, and exact retry after consumer
   disconnection. Dispatch
   still waits for the execution and outcome transaction. All 36 sanitized
   native daemon suites pass under `hlc1-orphan-native-daemon/`, and
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `hlc1-orphan-*-buildworld.log`.
   The committed reader also returns typed HCR2 recipients per HTD5 under
   the same lock and verification path. This preserves the fixed HCB2 owner
   incarnation and program digest for later dispatch; no job is queued. All
   36 sanitized native daemon suites pass under
   `hlc1-recipients-native-daemon/`, and `-j16 buildworld` passes for
   amd64, arm64/aarch64, and riscv/riscv64 in
   `hlc1-recipients-*-buildworld.log`.
   HRO1 now has a ticket-bound, fixed-slot journal writer and reader. It
   retains processed evidence through executed publication, rejects terminal
   without processed, conflicting branches, changed claim digests, and
   corrupt records, and supports exact retries. No consumer ACK or replay
   handler calls it yet, so this does not authorize imported execution. The
   exact-retry path fsyncs the journal directory before acknowledgment. All
   36 sanitized native daemon suites pass under `hro1-retry-native-daemon/`,
   and `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64
   in `hro1-retry-*-buildworld.log`.
   A bulk recovery view now pairs every fixed HRS1 slot with its HCR2 owner
   and HRO1 phase under one claimed-ticket lock. It keeps pending recipients
   in canonical order and rejects stray or orphan HRO1 files for the ticket. Queue
   publication and ACK-backed outcomes remain to be connected. All 36
   sanitized native daemon suites pass under `hro1-audit-final-native-daemon/`,
   and `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64
   in `hro1-audit-final-*-buildworld.log`.
   The host-ingress fixture
   covers valid one- and two-recipient overlays in canonical order, a stale
   source snapshot, outer corruption, and a forged HCO1 birth even when the
   HCP1 and HTM2 checksums are recomputed. The source reader's corruption
   check now selects the exact receipt file when multiple HCP1 files exist.
   All 36 sanitized native daemon suites pass under
   `htm2-program-match-native-daemon/` in the validation root. Current-source
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `htm2-program-match-*-buildworld.log` there.
   The source can now export one HTP1 frame while holding the outbound
   handoff process lock. It recomputes HTM1 and requires exact bytes before
   reading the verified spool, so a newly accepted delivery makes an older
   requested manifest stale. The host-ingress fixture exercises a matching
   export, an invalid index, and stale-manifest rejection. Export alone is
   not checkpoint publication: PREPARE must bind the complete copied member
   before accepting the cut. All 36 sanitized native daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/htp1-source-export-native-daemon/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `htp1-source-export-*-buildworld.log` under the same
   validation root.
   A lock-protected HTM1 snapshot export now audits the matching derived
   claims and outbound publications before returning bytes. It clears its
   output when a terminal `D` is orphaned; the host-ingress fixture checks
   the valid and orphaned cases. This is still a provisional source export,
   with no published checkpoint member or destination import. All 36 sanitized
   native daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/htm1-locked-export-native-daemon/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `htm1-locked-export-*-buildworld.log` under the same
   validation root.
   An individual HTP1 frame export now repeats the same derived-claim and
   outbound-publication audit while holding the source handoff locks. HTM1
   bytes alone cannot authorize an ELF frame when a terminal derived HCR1
   has lost its matching durable claim. The host-ingress regression covers
   that missing-claim state; all 36 sanitized daemon and 81 native port
   suites pass under the `frame-claim-audit-native-*` validation
   directories. Current-source 16-job development world builds pass for
   amd64, arm64/aarch64, and riscv/riscv64 in the
   `frame-claim-audit-*-buildworld.log` files under
   `/usr/obj/5BSD-hypertrace-validation/`. The export remains provisional
   until a complete checkpoint member and PREPARE binding exist.
   The source HTM1 and HTP1 export functions now refuse a foreign or
   committed ticket under the same process lock. The fixture checks an
   unrecorded ticket, a matching prepared ticket, a mismatched source, a
   competing ticket for the same VM lifetime, and export refusal after
   COMMIT. All 36 sanitized daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/transfer-single-ticket-native-daemon/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `transfer-single-ticket-*-buildworld.log` under the
   validation root.
   The two-delivery fixture covers canonical ordering and duplicate rejection,
   alongside phase and digest tampering. All 36 sanitized native daemon suites
   pass under `/usr/obj/5BSD-hypertrace-validation/htm1-multi-native-daemon/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `htm1-*-buildworld.log` files under the same
   validation root.
   With explicit authorization to transfer verified VM-envelope and bare-ELF
   bytes to the authenticated bhyve forwarder, source export now assembles
   the complete ordered HTM1/HTP1 bundle under one outbound handoff lock.
   It verifies every exact spool and derived claim, checks the 64 MiB HTB1
   destination staging cap with room for the longest VM name, and exposes
   neither metadata nor frames on a failed member. The host-ingress fixture
   checks a foreign ticket and a complete two-delivery round trip. All 36
   sanitized native daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/ingress-bundle-export-native-daemon/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `ingress-bundle-export-*-buildworld.log` files under
   the same validation root.
   The source daemon now serves that complete export through an attested
   forwarder's read-only `HANDOFF_EXPORT` request. The bounded HTX1 response
   carries the ticket token, canonical lengths, ordered frames, and a
   checksum. bhyve reads the entire response with one deadline and exposes
   neither pointer nor length until framing, token, and checksum pass. The
   source path rejects a competing or foreign ticket before returning bytes.
   Source packing and destination unpacking share one codec with a 63 MiB
   total and 65536-frame cap. The destination decoder checks the inner HTM1
   and HTP1 identities after the outer checksum. A reserved destination can
   stage a nonempty HTX1 as an inert, durable HTB1 sidecar; empty HTX1 has a
   distinct no-ingress result. The host-ingress fixture covers a real
   two-delivery wire round trip, an inner manifest mutation with a valid
   outer checksum, empty ingress, durable staging, and exact staging retry.
   The native wire fixture checks corruption, truncation, wrong tokens, and
   noncanonical lengths; the handoff-control fixture checks the daemon's
   ACK, length, and exact empty-bundle bytes over a socket. All 86 native
   port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/transfer-codec-native-port/`, and
   all 36 sanitized daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/transfer-stage-native-daemon/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `transfer-stage-*-buildworld.log` under the validation
   root.
   HTX1 export is now bound to a source PREPARE ticket for the empty-ingress
   case. Bhyve sends the exported HTX1 SHA-256 trailer in PREPARE, and the
   daemon compares it with the canonical empty bundle under the source
   handoff lock before publishing an HTH2 record. HTH2 retains that digest
   through COMMIT, reservation, mutation, and claim; HTH1 records remain
   readable after restart. SOURCE_STATUS returns the transfer digest while
   prepared so a lost PREPARE ACK can only resolve for the exact export.
   An accepted source set still requires an atomic export comparison,
   accepted-record promotion, and an execution lease. Its checksum detects
   transport damage; the version-4 checkpoint digest separately binds the
   saved bytes to the ticket.
   HyperTrace stop checkpoints now use a version-4 generation with a fourth
   `trace` member. After pausing vCPUs, bhyve requests the attested HTX1
   export and writes it before PREPARE; publication fsyncs and hashes the
   member, so the checkpoint handoff digest includes its SHA256. Version-3
   checkpoints retain their three-member format. Restore admission opens
   all four version-4 members, rejects a trace hardlink to another member,
   verifies the member hash, rereads the trace bytes against that hash, and
   validates HTX1 and its ticket token before VM mutation. The destination
   import request is implemented on a fresh VMM-attested channel: it checks
   the reserved ticket, checkpoint digest, and destination identity, then
   durably stages HTB1 and publishes only pending deliveries. Restore still
   rejects a nonempty bundle before reserving the ticket. CANCEL now removes
   an exact pending import under the outbound and inbound process locks,
   fsyncs record and spool deletions before unlinking HTB1, and refuses any
   imported record that advanced beyond pending. A crash during cleanup can
   retry while the ticket is still reserved. The request handler rechecks
   the reserved ticket while holding the outbound process lock through HTB1
   publication; a concurrent CANCEL either removes that stage or wins first
   and makes the late stage fail. Accepted-ingress promotion and
   the execution lease must be implemented before restore invokes import.
   The prestart import client now makes one exact retry after a lost transport
   or reply. A daemon NAK, malformed ACK, and invalid local bundle fail
   without retry. The socket fixture sends the same populated HTX1 twice
   after a lost ACK and verifies that both refusal forms get one request.
   The coordinator now places conditional IMPORT after RESERVE and the
   private-image query, before MUTATE. Its existing pre-MUTATE failure path
   cancels the ticket and pending sidecars. The source execution-lease gate
   still fences nonempty restore before ticket reservation, so this branch
   is not yet live. All 89 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/restore-import-retry-native-port/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `restore-import-retry-*-buildworld.log` under the same
   validation root.
   The coordinator ordering check passes with `SRCTOP` set to this tree,
   all 89 native port suites pass again under
   `/usr/obj/5BSD-hypertrace-validation/restore-import-coordinator-native-port/`,
   and current-source `-j16 buildworld` passes for amd64, arm64/aarch64,
   and riscv/riscv64 in `restore-import-coordinator-*-buildworld.log`.
   The additive import
   request and bound PREPARE raise the local daemon protocol to version 47, so a mixed old
   daemon and new bhyve pair fails at connection setup.
   The handoff-control fixture rejects a foreign destination, mismatched
   checkpoint digest, and corrupted HTX1, and accepts exact empty retries.
   The host-ingress fixture drives the attested import handler with a
   complete two-delivery HTX1, verifies exact retry and pending-only journal
   phases, rechecks the saved payloads, then tests cancellation, accepted
   phase refusal, retry after a partial spool deletion, and a four-round
   stage/CANCEL race. The sanitized race fixture also passed ten repeated
   runs.
   The final sanitized daemon build
   and all 36 component suites pass under
   `/usr/obj/5BSD-hypertrace-validation/import-v46-atomic-native-daemon/`;
   the additional current-source race fixture passed separately.
   All 86 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/import-v46-final-native-port/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `import-v46-atomic-amd64-buildworld.log`,
   `import-v46-atomic-final-arm64-buildworld.log`, and
   `import-v46-atomic-riscv64-buildworld.log` files under the validation
   root.
   These are component and source-build checks, not live VM qualification.
   The protocol-47 source-binding follow-up passes all 36 sanitized daemon
   suites under
   `/usr/obj/5BSD-hypertrace-validation/handoff-bound-v47-verified-native-daemon/`
   and all 86 native port suites under
   `/usr/obj/5BSD-hypertrace-validation/handoff-bound-v47-native-port/`.
   The handoff fixture checks nonzero HTH2 transfer digests across restart
   and phase changes, rejects a changed digest, and reads a legacy HTH1
   phase record. The attested control fixture rejects a tampered PREPARE
   digest against the canonical empty HTX1 export, and the bhyve fixture
   checks bound PREPARE framing and prepared-status recovery.
   Current-source `-j16 buildworld` passes on amd64, arm64/aarch64, and
   riscv/riscv64 in the `handoff-bound-v47-*-buildworld.log` files under
   `/usr/obj/5BSD-hypertrace-validation/`. These checks do not exercise a
   live VM or close the accepted-ingress execution lease.
   The final strict journal check also rejects an unbound direct PREPARE in
   control-machine state. Its sanitized daemon run passes all 36 suites in
   `handoff-bound-v47-strict-native-daemon/`; the focused handoff-control
   fixture with an explicit zero-digest refusal passes against those daemon
   objects. Current-source `-j16 buildworld` again passes on amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `handoff-bound-v47-strict-*-buildworld.log` files.
   Destination `HANDOFF_IMPORT` also compares the validated HTX1 trailer
   with that HTH2 source-cut digest before staging. The attested import
   fixture rejects a different, correctly checksummed HTX1 for the same
   reserved ticket and accepts an exact two-delivery retry. All 36
   sanitized daemon suites pass under
   `import-source-bound-v47-native-daemon/`. Current-source `-j16
   buildworld` passes on amd64, arm64/aarch64, and riscv/riscv64 in the
   `import-source-bound-v47-*-buildworld.log` files under the validation
   root.
   The direct reserved-stage API also checks that HTX1 trailer against the
   durable HTH2 ticket while holding the destination handoff lock. The
   fixture rejects the alternate canonical bundle at both the attested
   request and direct stage entry points, then stages the exact bundle.
   All 36 sanitized daemon suites pass under
   `import-stage-bound-v47-native-daemon/`; current-source `-j16
   buildworld` passes on amd64, arm64/aarch64, and riscv/riscv64 in the
   `import-stage-bound-v47-*-buildworld.log` files.
   Source PREPARE now uses the same lock-held complete HTM1/HTP1 exporter
   as HANDOFF_EXPORT. It rebuilds canonical HTX1 and compares its SHA-256
   trailer with the bytes bhyve saved, before any ticket publication.
   The two-delivery fixture rejects a changed digest with `EPROTO` and
   reaches the deliberate `EOPNOTSUPP` execution-lease fence with the
   exact digest. The accepted path remains closed until destination
   consumer ownership and accepted-record promotion are transactional.
   All 36 sanitized daemon suites pass under
   `accepted-cut-bound-v47-native-daemon/`; current-source `-j16
   buildworld` passes on amd64, arm64/aarch64, and riscv/riscv64 in the
   `accepted-cut-bound-v47-*-buildworld.log` files under the validation
   root.
   Source PREPARE now checks each terminal HCR1 recipient against its
   fsynced HCO1 consumer owner record while reconstructing the complete
   export under the handoff lock. A missing owner refuses the cut with
   `EBUSY`; a changed UID, even with a valid HCO1 checksum, fails with
   `EPROTO`. The source fixture checks both cases and the exact-digest
   accepted path still reaches the deliberate `EOPNOTSUPP` fence. All 36
   sanitized daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/owner-bound-cut-v47-native-daemon/`;
   the final host-ingress fixture was rebuilt and passed after the UID
   tamper case was added. Current-source 16-job development world builds
   pass on amd64, arm64/aarch64, and riscv/riscv64 in the
   `owner-bound-cut-v47-*-buildworld.log` files under the same validation
   root. HCR1 does not carry HCO1's process incarnation, so this audit
   binds session/PID/UID only. HCO1 is durable source identity evidence,
   not a destination execution lease; accepted promotion and restore
   remain closed.
   The nine manifest harness cases pass, including version-3 compatibility,
   trace corruption and inode-alias refusal, and a check that the trace hash
   changes the handoff digest. All 86 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/manifest-v4-final-native-port/`;
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `manifest-v4-*-buildworld.log` under the same validation root. These are
   source and component checks, not a live restore qualification.
   The sanitized daemon build and all 36 component suites pass under
   `/usr/obj/5BSD-hypertrace-validation/ingress-transfer-preflight-native-daemon/`.
   The final host-ingress fixture also covers missing and parsed-only HCR1,
   a settled cohort, changed VMID and ELF bytes, and refusal without a
   ticket. Current-source `-j16 buildworld` passes for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `ingress-transfer-preflight-*-buildworld.log` files under that root.
   Outbound receipt phases are frozen at that cut;
   exact retries and terminal cleanup of a previously bound destination
   remain possible. The callback still returns `EOPNOTSUPP` for every
   save after this check. The source-to-daemon cut and all control classes
   still need an end-to-end reconciliation protocol before saves can be
   enabled. An accepted guest upload's send to a host DTrace consumer holds
   the source handoff lock through the complete socket frame, then releases
   that lock and the revocation mutex before waiting for the ACK. The
   consumer's synchronous derived publication needs both locks; retaining
   them through its ACK deadlocked the host daemon. PREPARE still rejects the
   accepted ingress during this interval. ABORT retries deferred sends, and
   COMMIT retires them on the old source. An identified upload's derived guest
   ELF now uses a
   synchronous send, so the ACK follows daemon spool acceptance. The
   consumer frame now names the exact accepted journal delivery, and the
   DTrace receiver checks its VM identity against the ELF envelope. Its
   ACK is followed by an fsynced HCR1 per-consumer processing receipt;
   pending recipient records are fsynced before jobs are published. The
   consumer ACK precedes the separate thread's host instrumentation
   enablement; HCR1 proves the parsing/derived outcome, not execution.
   The consumer execution thread now stops on a missing guest response,
   a host/guest VM identity mismatch, virtual-probe creation failure,
   failed program enablement or augmentation, and worker-start failure.
   It no longer starts tracing or counts a failed program as enabled.
   These failures still occur after the ingress ACK; the separate execution
   receipt below records only successful processing.
   A source-extracted sanitized fixture covers each failure, including a
   worker backend that clobbers its output handle on failure. All 71 native
   port suites and 35 sanitized daemon suites pass under the
   `consumer-execution-native-port` and `execution-failclosed-daemon`
   validation directories; current-source `-j16 buildworld` passes for
   amd64, arm64/aarch64, and riscv/riscv64 in the
   `execution-failclosed-*-buildworld.log` files.
   Protocol 40 now carries a second, exact-identity execution result on a
   separate consumer connection. HCR1 records `N` or `D` only after successful
   host execution or an explicitly ignored no-work delivery, followed by a
   daemon directory fsync; parsed-only `n`/`d` remains distinct. A premature
   result retries while the parsing ACK settles, and a
   conflicting outcome is rejected. The new source-extracted wire fixture
   checks the complete frame and NAK retry. A separate bounded reporter queue
   covers ignored and duplicate deliveries without blocking receiver replay;
   duplicate results wait for the matching program to finish. Process-crash
   recovery, live consumer liveness, and destination transfer remain open,
   so this does not lift the source-save or restore refusal.
   The source-extracted queue fixture covers dependent execution, ignored
   deliveries, failed execution, exact identity, and clean-stop draining.
   All 73 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/consumer-execution-queue-final-port/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `consumer-execution-queue-final-*-buildworld.log`
   files under the same validation root.
   The result handler now requires the matching primary consumer receiver
   to remain registered, finish replay admission, and have the same session
   and peer credentials as the one-shot reporter. It retries while that
   receiver reconnects, and refuses a result after the receiver is retired.
   The host-ingress fixture covers both refusals and an exact retry; all 35
   sanitized daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/execution-primary-live-final-daemon/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `execution-primary-live-*-buildworld.log` files.
   This is an admission check, not process-crash recovery or a transferable
   DTrace enablement journal; source save remains refused.
   Protocol 40 carries the ingress journal session in the identified ELF
   parent slot and a separate 72-byte execution-result body. The consumer
   validates the mirrored identity; the daemon uses the session to resolve
   one accepted ingress and HCR1 recipient by exact journal names. The
   56-byte parsing ACK remains unchanged. This removes the full-journal scan
   from each result without treating a matching receipt as a transferable
   instrumentation state.
   Protocol 41 also gives host-to-guest CLEANUP an exact queue-ACK token in
   the otherwise-unused INFO count slot of the 520-byte header. The daemon
   holds the source handoff lock until bhyve queues the complete cleanup and
   acknowledges that token. A pending cleanup marker is fsynced before the
   daemon queues the job; PREPARE rejects that VM lifetime until the exact
   ACK changes the marker to an accepted phase and fsyncs the directory. A
   reconnect of the same
   VMM-attested lifetime replays a pending marker with its original token,
   while a new cleanup request during PREPARE is rejected. This closes the
   daemon-crash send/cut gap but does not prove guest application or transfer
   the guest's cleanup state to a destination.
   Protocol 42 adds `HANDOFF_CLEANUP`, an attested lookup of the accepted
   source receipt by handoff token, digest, and exact delivery ID. The VirtIO
   control and private snapshot format 3 carry that ID to destination queue
   planning. A destination refuses the saved CLEANUP without the matching
   accepted source receipt. Guest application remains unproven, and source
   save and destination restore stay disabled pending the full transaction.
   The sanitized daemon suite passes all 35 cases under
   `/usr/obj/5BSD-hypertrace-validation/cleanup-lookup-daemon/`, and the
   expanded saved-control fixture passes with all 73 native port cases under
   `/usr/obj/5BSD-hypertrace-validation/cleanup-plan-port/`. Current-source
   16-job development world builds pass for amd64, arm64, and riscv64 in the
   `cleanup-lookup-*-buildworld.log` files; GENERIC kernel builds pass for
   those three architectures in `cleanup-lookup-*-buildkernel.log`.
   The guest driver now preserves the cleanup token and VM identity in its
   daemon event. Before terminating traced children, the daemon rechecks the
   current VM identity and refuses a stale event. This is an identity fence;
   the guest-applied acknowledgment and re-exec recovery protocol remain to
   be implemented.
   A source whose CLEANUP has left the host queue now fails checkpoint
   preflight with `EBUSY` until that receipt protocol exists. The guest
   driver can send READY before its daemon finishes cleanup, so READY alone
   cannot discharge this fence.
   Protocol 43 adds the host's exact CLEANUP_APPLIED message and a durable
   accepted-to-guest-applied journal transition. The guest daemon now reports
   the exact token after closing launch admission, waiting for in-flight
   launches, and terminating and waiting for its owned traced children; the
   driver retains and retries the report across daemon re-exec
   until a matching host receipt arrives. Bhyve fsyncs the host journal before
   clearing its delivered-but-unapplied fence and sending that receipt. A
   cleanup control also fences later host controls until the report commits.
   Guest daemon crash before its report now has an exact child-exit recovery
   path. A guest child waits behind a parent-controlled exec gate while its
   boot ID and raw monotonic process birth identity are fsynced to an inbound
   ledger. The daemon can reopen the process descriptor after a crash,
   compare that identity, kill and wait for the original child, and safely
   ignore a later process that reused the PID. Startup refuses a pending
   cleanup without the ledger marker or any unresolved child. An owner-only
   fixed-width dttransport ioctl exposes the driver's pending/applied state;
   startup reports an unapplied token only after recovering every child.
   Source save and destination
   restore remain disabled. Checkpointing the interval between the host
   journal commit and
   guest receipt also needs an explicit transfer or final acknowledgement of
   the guest's pending state. The guest driver refuses NODE_REKEY while a
   cleanup report is pending, so the unfinished source token cannot silently
   cross to a new VM epoch.
   The query and startup validation pass all 73 native port suites under
   `/usr/obj/5BSD-hypertrace-validation/cleanup-query-port/` and all 35
   sanitized daemon suites under `cleanup-query-daemon/`. The source-extracted
   fixtures cover no pending token, an unapplied token, an applied token,
   stale identity, reserved bits, and callback retirement.
   Current-source 16-job development world and GENERIC kernel builds pass for
   amd64, arm64/aarch64, and riscv/riscv64 in the
   `cleanup-query-*-buildworld.log` and `cleanup-query-*-buildkernel.log`
   files under the validation object root.
   The source-extracted birth-identity fixture and the sanitized native
   child-ledger fixture cover the exec gate's durable identity, a missing
   marker, malformed record, bounded exit retry, exact child exit, and PID
   reuse. All 36 native
   daemon suites and 74 native port suites pass under
   `child-ledger-retry-daemon/` and
   `child-ledger-final-port2/` in the validation root. Development world
   builds pass with 16 jobs on amd64, arm64/aarch64, and riscv/riscv64 in
   `child-ledger-retry-*-buildworld.log`; the GENERIC kernel builds pass for
   those architectures in `child-ledger-*-buildkernel.log`. Live guest/host
   qualification remains outstanding.
   The protocol, handoff, and daemon recovery changes pass all 35 sanitized
   daemon suites under
   `/usr/obj/5BSD-hypertrace-validation/cleanup-applied-daemon2/`; all 73
   native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/cleanup-applied-port/`. The focused
   protocol fixture also passes with the guest-applied status phase enabled.
   Final 16-job development world and GENERIC kernel builds pass for amd64,
   arm64, and riscv64 in `cleanup-final-*-buildworld.log` and
   `cleanup-final-*-buildkernel.log` under
   `/usr/obj/5BSD-hypertrace-validation/`.
   The connected guest/host receipt path passes 35 sanitized daemon suites
   and 73 native port suites under the `cleanup-guest-ack-daemon` and
   `cleanup-guest-ack-port2` validation directories. A source-extracted host
   fixture also covers a transient daemon socket failure, durable acceptance,
   and the exact receipt. Current-source 16-job development world and GENERIC
   kernel builds pass for amd64, arm64/aarch64, and riscv/riscv64 in the
   `cleanup-guest-ack-*-buildworld.log` and
   `cleanup-guest-ack-*-buildkernel.log` files under the same object root.
   The launch-admission barrier passes all 35 sanitized daemon suites under
   `cleanup-launch-gate-daemon`; its process-launch fixture refuses a new
   launch after cleanup begins, and the cleanup fixture waits for a held
   in-flight launch gate before re-exec. The host device fixture confirms the
   queue remains fenced if its receipt slot cannot be used. Current-source
   16-job development world builds pass for amd64, arm64/aarch64, and
   riscv/riscv64 in `cleanup-launch-gate-*-buildworld.log`; final GENERIC
   kernel builds pass for all three in
   `cleanup-launch-gate-final-*-buildkernel.log` under the validation root.
   The reopened-journal and handoff regression passes, all 35 sanitized
   daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/cleanup-journal-native-daemon/`,
   and all 73 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/cleanup-queue-ack-port2/`.
   The focused daemon case proves that two accepted ingress records with
   identical delivery and program IDs but different journal sessions retain
   independent HCR1 phases. All 35 sanitized daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/execution-session-exact-daemon/`,
   and all 73 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/execution-session-exact-port/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `execution-session-exact-*-buildworld.log` files.
   All 35 sanitized daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/consumer-execution-receipt-final-daemon/`;
   all 72 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/consumer-execution-receipt-final-port/`.
   Current-source `-j16 buildworld` passes on amd64, arm64/aarch64, and
   riscv/riscv64 in the `consumer-execution-receipt-*-buildworld.log` files.
   Derived outbound dispatch can occur later. At host-daemon startup the HCR1 ledger
   is validated; an admitted consumer with the same session and peer
   credentials receives only its pending, startup-memorized deliveries.
   Processed deliveries are skipped. Admission now excludes the consumer
   from watcher recipient selection until replay finishes. The host watcher
   now holds the source handoff lock while recording pending consumer receipts
   and publishing their jobs. A watcher fenced by PREPARE leaves its spool
   unmemorized; ABORT requests a fresh scan. Identified watcher and recovered
   consumer jobs now carry their source VM lifetime at creation, so COMMIT
   retires even jobs that have not yet tried to send. A deferred worker now
   checks the source phase and rejoins its queue under the same handoff lock;
   COMMIT cannot delete that job during the worker's phase check, and ABORT
   cannot miss its requeue. The DTrace
   receiver retains its session across transport loss while reading a frame
   and reconnects both daemon sockets. An identified derived ELF now carries
   its parent delivery and consumer session. The daemon verifies the exact
   accepted ingress, recipient receipt, peer credentials, target envelope,
   and content-derived spool ID before publishing under the source snapshot
   lock. An fsynced HDU2 claim binds each recipient and target VM lifetime to
   the full payload and bare ELF digests before its derived spool is visible.
   Exact retries use the same claim; conflicting payloads fail. A restarted
   daemon can resolve the parent from the retained spool or an accepted
   outbound receipt, together with the HDU2 claim and HCR1 ledger. Host
   startup audits those claims against accepted ingress, HCR1 recipients,
   both retained-spool digests, and any outbound delivery receipts. It
   permits a claim with no spool after an interrupted publication only while
   its HCR1 result is unresolved. An HCR1 `derived` result without a hashed
   spool or completed outbound receipt now fails startup audit and live
   resolution. The host-ingress fixture covers claim-only pending, false
   completion, and completed outbound proof. All 35 sanitized daemon suites
   pass under `/usr/obj/5BSD-hypertrace-validation/derived-proof-final-daemon/`;
   current-source 16-job development world builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `derived-proof-final-buildworld-*.log` files. A
   spool-free claim resolves only with an accepted, installed, or terminal
   host outbound delivery whose original target lifetime and bare ELF digest
   match. A terminal receipt preserves lineage after an authenticated guest
   uninstall; a conflicting receipt
   (including a different source ID for the derived program) fails startup
   audit or live parent resolution even if a spool remains. The
   ACK-to-enable crash window, failures during derived outbound dispatch
   or ACK, and destination transfer remain open.
   Protocol 40 distinguishes a consumer ACK with no derived ELF from one
   whose derived ELF reached the daemon spool. The HCR1 filename records
   that outcome durably; the old processed phase remains readable but cannot
   prove either outcome. Startup audit rejects a no-derived receipt with a
   claim, a derived receipt without its claim, and multiple claims for one
   recipient. A conflicting second target is rejected during publication.
   A replay ACK reporting no new ELF now resolves any earlier HDU2 claim
   against its published spool or completed outbound receipt before recording
   the durable outcome. A forged derived ACK without a matching claim is
   rejected; an interrupted claim with no published spool stays pending.
   Derived publication and ACK outcome reconciliation share a cross-process
   journal lock, so a claim cannot appear between the lookup and the HCR1
   outcome commit. An exact in-process consumer replay re-emits its cached
   guest program only for the same session and ingress delivery. The daemon
   suppresses spool recreation once an immutable accepted, installed, or
   terminal outbound receipt proves that derived result was delivered.
   These checks make the consumer outcome reconcilable but do not close the
   ACK-to-enable or destination-transfer gaps.
   Host-daemon startup now upgrades an HCR1 pending receipt to `derived`
   when its exact HDU2 claim has a matching, hashed derived spool or an
   accepted/installed/terminal outbound receipt. It audits every claim and
   recipient before changing a phase, fsyncs the outbound directory before
   using a recovered spool link, and fsyncs each HCR1 transition. A claim
   with no spool or completed outbound receipt remains pending. This closes
   the daemon-restart gap after derived publication; host instrumentation
   enablement, a crash before publication, and destination transfer still
   need a recovery protocol.
   The sanitized host-ingress fixture covers both retained-spool and
   terminal-receipt recovery, claim-only non-recovery, and repeat startup.
   All 35 native daemon suites passed under
   `/usr/obj/5BSD-hypertrace-validation/consumer-derived-reconcile-final-daemon/`;
   the expanded host-ingress case passed again after the fixture change.
   Current-source 16-job development world builds passed on amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `consumer-derived-reconcile-*-buildworld.log` files.
   HCR1 recovery now indexes the full accepted-ingress identity before
   matching recipient records, avoiding a quadratic startup scan at the
   journal limit while retaining duplicate and malformed-record rejection.
   An accepted ingress spool with no connected DTrace consumer stays
   eligible for a scan when one connects.
   An identified consumer ACK write failure now closes both daemon sockets
   and reconnects the same consumer session. The daemon can replay a pending
   HCR1 delivery on the replacement stream; the consumer does not send an
   ambiguous ACK a second time before that replay. A source-extracted socket
   fixture covers successful ACK, failed ACK, unchanged session, and ACK only
   after simulated replay. All 61 native port suites passed under
   `/usr/obj/5BSD-hypertrace-validation/consumer-ack-native-port/`, and
   current-source 16-job development world builds passed on amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `consumer-ack-*-buildworld.log` files. Process-crash recovery and
   destination transfer remain open; this change closes only the live
   transport-loss path.
   An identified ingress watcher now fsyncs one HCB1 record containing the
   complete sorted recipient cohort before writing individual HCR1 receipts
   or publishing jobs. Startup validates each cohort against its accepted
   ingress and reconstructs missing pending HCR1 entries, so a crash between
   recipient writes does not silently shrink the intended set. A rescan
   cannot assign the same upload to a new consumer session; an exact-session
   reconnect uses the pending HCR1 replay path. Legacy HCR1 without HCB1
   remains fenced to its earlier sessions. A process that loses its session
   and cached result still needs a durable execution/result journal, and
   destination transfer remains open. The host-ingress fixture covers a
   two-recipient interrupted write, idempotent restart, checksum corruption,
   and abandoned temporary-file cleanup. All 35 sanitized daemon suites pass
   under `/usr/obj/5BSD-hypertrace-validation/cohort-durable-verified-daemon/`.
   Current-source 16-job development world builds pass on amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `cohort-durable-verified-*-buildworld.log` files.
   Cohort admission now reserves capacity for its missing HCR1 records as
   well as files already present. A later upload cannot spend those promised
   slots; standalone HCR1 creation checks the same reservation total, and a
   record outside an existing cohort is rejected. The focused host-ingress
   fixture checks nonmember rejection. All 35 sanitized daemon suites pass
   under `/usr/obj/5BSD-hypertrace-validation/cohort-reserved-final-daemon/`;
   current-source 16-job development world builds pass on amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `cohort-reserved-final-*-buildworld.log` files. Process-crash execution
   recovery and cross-host transfer remain open.
   The live consumer now retains the generated guest program and exact
   derived parent when its synchronous daemon send fails, reconnects the
   same session, and re-emits that result only for a matching replayed
   ingress. Completed host programs also keep their derived result in a
   separate replay list after leaving the active execution queue. The match
   is checked before interpreting the replay as another host or guest
   response, and re-emission waits for the execution thread's DTrace handle
   operations to finish. A failed replay reports failure, never a
   successful no-derived outcome. This repairs an in-process send failure;
   a consumer process crash still loses the cached program and session. The
   focused source-extracted replay fixture and all 66 sanitized native port
   suites pass under `/usr/obj/5BSD-hypertrace-validation/derived-replay-serialized-port/`;
   current-source 16-job development world builds pass on amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `derived-replay-serialized-*-buildworld.log` files.
   In-process replay now binds the SHA-256 digest of the complete inbound
   VM/ELF frame to its exact delivery identity. Changed frame bytes or a
   missing cached digest fail before the previously generated guest program
   can be re-emitted. The source-extracted replay regression and all 76 native
   port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/consumer-digest-replay-native-port/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `consumer-digest-replay-*-buildworld.log` files under
   the same validation root.
   This integrity check does not persist the cache across a consumer crash or
   transfer its execution state to a destination.
   A supervised host `dtrace -E` consumer can now load a pre-provisioned HCS1
   session through `-x hypertrace_session_file=/absolute/path`. The client
   checks ownership, mode, link count, length, magic, nonzero identity, and
   SHA-256, rejects symlinks, and holds an exclusive lock until exit. Invalid
   or busy files fail closed without generating a new session. Since
   2026-10-30 the host `dtrace -E` serves every command-line program: it
   appends them, in order, into the one compiled program it registers
   (one HPI2 digest, one base ELF, one session, drain and stop), so the
   session file no longer refuses several programs; guests link the one ELF
   as before (`/usr/obj/5BSD-otel-validation/mp-*`). The
   source-extracted sanitized session-file fixture and all 77 native port
   suites pass under
   `/usr/obj/5BSD-hypertrace-validation/consumer-session-native-port/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64,
   and riscv/riscv64 in the `consumer-session-*-buildworld.log` files under
   the same validation root.
   This supplies a stable identity for future supervised restart. The daemon
   now admits a replacement PID only when every receipt from an earlier PID
   in that session is execution-settled (`N` or `D`), has the same UID, and
   its old PID no longer exists. It refuses pending, legacy processed, and
   parsed-only receipts, which still need a durable execution/result journal.
   The source-extracted restart-owner fixture covers live and exited PIDs and
   all receipt phases; all 78 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/consumer-restart-native-port/`.
   The sanitized daemon build and all 36 component suites pass under
   `/usr/obj/5BSD-hypertrace-validation/consumer-restart-native-daemon/`.
   The updated host-ingress component also verifies actual daemon replay
   admission after a dead old PID with an `N` receipt, then refusal when a
   parsed-only receipt is added to that same session.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `consumer-restart-*-buildworld.log` files under
   `/usr/obj/5BSD-hypertrace-validation/`.
   The DTrace client now sends a canonical process-incarnation identifier in
   its consumer hello. The daemon validates its PID against Unix peer
   credentials and fsyncs an HCO1 session/UID/PID/incarnation owner record
   before allowing new ingress. Protocol 45 rejects pre-incarnation peers at
   version negotiation. Reconnects require an exact owner record; missing
   owner state with pending same-PID work and changed incarnations refuse
   replay. Startup audits all HCO1 records and removes interrupted
   temporary files. A source-extracted producer fixture covers stable
   reconnects, forked children, and concurrent calls; the host-ingress
   component covers changed incarnation, exact replay, and checksum
   corruption. With protocol 45, all 79 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/consumer-birth-v45-native-port/`.
   The sanitized daemon build and all 36 component suites pass under
   `/usr/obj/5BSD-hypertrace-validation/consumer-birth-v45-native-daemon/`;
   a focused rebuild of the final directory source and host-ingress fixture
   passes the HCO1 startup-audit corruption case.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `consumer-birth-v45-*-buildworld.log` files under
   `/usr/obj/5BSD-hypertrace-validation/`.
   A reused numeric PID with a different incarnation can now replace its
   HCO1 record only when all earlier same-session/PID receipts and every
   durable HCB1 cohort member are execution-settled. The replacement is
   atomically renamed and directory-fsynced before new work is exposed.
   Missing HCR1 members, parsed-only outcomes, and changed UIDs refuse the
   rebind. The host-ingress fixture covers exact retry, successful rebind,
   unwritten cohort members, and parsed-only refusal.
   The sanitized daemon build and all 36 component suites pass under
   `/usr/obj/5BSD-hypertrace-validation/consumer-owner-rebind-native-daemon/`;
   the focused final host-ingress fixture passes under
   `/usr/obj/5BSD-hypertrace-validation/consumer-owner-rebind-host-ingress-final.log`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `consumer-owner-rebind-*-buildworld.log` files under
   `/usr/obj/5BSD-hypertrace-validation/`.
   The process incarnation fences accidental PID reuse; it is not a new
   authentication authority. The narrow admission case does not recover lost
   execution state or enable source save and destination restore.
   Admission with no HCO1 owner now also scans the fsynced HCB1 cohorts under
   the process lock before binding the new owner. It refuses an unwritten or
   parsed-only HCR1, including a cohort bound to an earlier PID in the same
   session, and requires an earlier settled PID to have exited. This closes
   the interval in which a cohort could be committed after the receipt
   snapshot but before first owner publication. The focused host-ingress
   fixture covers both same-PID and replacement-PID admission. All 36
   sanitized native daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/owner-cohort-all-native-daemon/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `owner-cohort-*-buildworld.log` files under the
   same validation root.
   If the ACK socket closes after a derived result is durable, the running
   host daemon now resolves that exact recipient from its HDU2 claim and
   hashed spool or completed outbound receipt under the outcome lock, then
   fsyncs HCR1 as `derived`. A claim without such proof, or no claim, stays
   pending for exact-session replay. This avoids requiring a daemon restart
   for the lost-ACK case; no-derived execution still has no crash journal.
   The sanitized host-ingress fixture covers proof, claim-only, and no-claim
   socket loss. All 35 native daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/lost-ack-live-verified-daemon/`;
   current-source 16-job development world builds pass on amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `lost-ack-live-*-buildworld.log` files. The final claim-only fixture
   extension also passes against those validated daemon objects.
   A malformed or explicit failure ACK now runs the same independent durable
   result reconciliation before the daemon rejects the ACK. No-result
   failures remain pending; a complete derived result can finish HCR1 without
   trusting that ACK. All 35 sanitized daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/lost-ack-failure-final-daemon/`;
   current-source 16-job development world builds pass on amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `lost-ack-failure-*-buildworld.log` files.
   Production HANDOFF_EXPORT now requires the exact HGI1 source-gate intent
   and a suspended VMM epoch owned by that ticket while it holds the journal
   publication and process locks. PREPARE uses the same gate check, so export
   and ticket publication cannot disagree about whether the source was
   fenced. The attested handoff fixture verifies refusal without a gate and
   a journal-bearing export with one, then aborts the gate before continuing.
   All 40 sanitized daemon suites pass under `gated-export-final-native-daemon/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `gated-export-*-buildworld.log` under the validation root.
   This validates the source cut boundary, not a live VMM handoff.
   An exact PREPARE retry now rechecks the owned, suspended source gate and
   rebuilds the transfer member under the same locks before accepting the
   stored ticket. A lost reply therefore cannot reauthorize a prepared cut
   after the gate is lost or the source journal changes. The source-gate,
   source-journal-wire, and handoff-control fixtures cover a valid retry,
   gate loss, changed transfer bytes, and a pending KILL. All 40 sanitized
   daemon suites pass under `prepare-retry-final-native-daemon/`; current-source
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `prepare-retry-*-buildworld.log` under the validation root. Nonempty
   PREPARE remains fenced pending a recoverable destination execution lease.
   The bhyve source-gate BEGIN/ABORT helper now retries only a potentially
   lost reply. An explicit NAK or malformed ACK is terminal, so a refused
   source-gate transition cannot be repeated after circumstances change.
   The attested socket fixture covers both refused operations and both bad
   reply forms with no second connection; the final native and build results
   are recorded under gate 3 below.
3. **Destination restore transaction:** Private image parsing, receipt query,
   queue planning, and bind exist. `snapshot.c` now admits a format-4 private
   HyperTrace device image only after the empty HTX1 transfer check, reserved
   ticket, and private-image query. Nonempty host ingress and older private
   images remain fenced. The device restore callback
   stages its planned queue without replacing the live queue. After daemon
   CLAIM and exact saved-delivery binding, the coordinator stages daemon
   admission KILLs and attaches the ticket to the private queue. It publishes
   that queue only after the admission manifest and ticket attachment succeed,
   while the device remains paused.
   A nonempty format-4 transfer now reaches read-only device,
   replay-capacity, and memory-layout preflight before its deliberate
   `EOPNOTSUPP` execution-lease refusal. Malformed or over-capacity transfers
   fail at the relevant preflight check before any daemon reservation or
   kernel restore session starts. The failure path releases the paused
   VirtIO-DTrace owner; no imported journal or queue is published.
   All 97 native port suites pass under `nonempty-preflight-native-port/`.
   Current-source `-j16` development world builds pass on amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `nonempty-preflight-*-buildworld.log` files under the validation root.
   The amd64 build rebuilt `snapshot.c`; arm64 and riscv64 currently build
   with `MK_BHYVE_SNAPSHOT=no`, so their world results do not compile this
   coordinator path.
   The loader now retains its shared checkpoint publication lock in the
   restore state until cleanup, including through the HyperTrace transaction;
   HyperTrace restore refuses a missing or non-regular lock descriptor.
   After verifying the manifest's four copied generation members, it also
   requires the loaded HTX1 member's digest to match the transfer digest in
   the signed HSA1 ticket before staging that ticket. The native bhyve
   fixture covers a valid empty transfer, changed payload/checksum, and a
   structurally valid HSA1 carrying a different transfer digest. This
   narrows the local copy/replacement window but does not prove an external
   copier's behavior or transfer the source daemon's delivery ledger.
   All 94 native port suites pass under `restore-transfer-lock-native-port/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `restore-transfer-lock-*-buildworld.log` files under
   the validation root.
   The format-4 empty-transfer admission passes all 89 native port suites
   under `restore-empty-device-final-native-port/` and the snapshot
   portability check. It relies on the local HSL1 release witness and has no
   matched live VM evidence yet; cross-host admission still needs trusted
   release transport. Current-source `-j16 buildworld` passes for amd64,
   arm64/aarch64, and riscv/riscv64 in
   `restore-empty-device-final-*-buildworld.log` under the validation root.
   The coordinator now asks the attested daemon to promote the claimed import
   after KILL and saved-delivery binding, before starting its connector or
   releasing vCPUs. An empty transfer is an exact no-op at this barrier;
   nonempty ingress still hits the earlier restore fence. The prestart helper
   retries one uncertain reply because promotion is idempotent, but stops on
   an explicit NAK or malformed reply. Its socket fixture covers a lost ACK,
   both refusal forms, and absence of a retry after refusal. All 89 native
   port suites pass under `restore-promote-prestart-verified-native-port/`.
   Publication requires the negotiated rekey-receipt feature along with the
   other restore controls; a legacy guest leaves the planned queue private.
   Once guest memory and the saved VirtIO ring have been installed, paused
   publication also rejects pending or unreadable guest-to-host controls
   before exposing the planned queue. The device fixture verifies that both
   failures leave the live and staged queues intact; all 74 native port
   suites pass under
   `/usr/obj/5BSD-hypertrace-validation/vtdtr-ring-cut-native-port/`.
   Current-source 16-job development world builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `vtdtr-ring-cut-*-buildworld.log` files.
   Resume refuses an unpublished plan, and shutdown frees it. Daemon mutation
   rollback and completed guest rekey have not been made one transaction for
   imported host programs. The empty-transfer restore path attaches its
   attested ticket and replay KILL manifest
   while the VirtIO checkpoint pause still owns the device mutex, before its
   reader can run. The attached ticket survives private-queue publication.
   Failure releases the paused DTrace worker before process-exit cleanup.
   The device fixture checks that stale admission leaves both queues and the
   ticket unchanged, then verifies the restored NODE_REKEY, admitted KILL, and
   saved controls appear in order only after publication. The 66 native port
   suites passed under
   `/usr/obj/5BSD-hypertrace-validation/restore-admission-final2-native-port/`.
   Current-source 16-job development world builds passed on amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `restore-admission-final-*-buildworld.log` files. These earlier tests
   preceded empty-transfer admission; nonempty ingress remains fenced.
   The paused device queue-publication function now requires an attached
   handoff ticket itself. A direct ticketless caller gets EACCES without
   replacing the live queue or consuming the private plan. The native device
   fixture covers this boundary; all 81 native port suites passed under
   `/usr/obj/5BSD-hypertrace-validation/restore-ticket-publish-native-port/`.
   Current-source `-j16` development world builds passed for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `restore-ticket-publish-*-buildworld.log` files under that validation root.
   Protocol 60 adds an exact, durable claimed-incarnation execution-start
   marker. Bhyve requests it after replay readiness and before releasing the
   restored vCPU startup fence. A lost reply retries the same marker; a
   rejected or uncertain request leaves startup closed. The daemon checks
   ticket phase and destination ownership, writes and syncs the marker, and
   rejects a corrupt marker on retry or status query. Absence is intended to
   distinguish a claimed restore that never released guest execution from
   one that may have run. This is only the write-ahead boundary: it does not
   yet rebind a failed claimed import to a new VM incarnation, and nonempty
   restore remains fenced until that recovery transaction is implemented.
   All 96 native port suites and the focused daemon protocol, ledger, and
   handler suites pass under the `execution-start-*` validation directories.
   The full sanitized daemon run passes all 40 cases under
   `rebind-intent-native-daemon-final/`. The `host-ingress` fixture's
   15-second alarm was increased to 45 seconds after its unchanged checks
   needed 18 seconds under load. A current-source amd64 world build also
   passes in `rebind-intent-amd64-buildworld.log`.
   Replacement-daemon startup now audits every execution-start marker under
   the handoff process lock. An orphan, malformed name, corrupt body, or
   marker for a nonclaimed ticket stops recovery rather than being ignored.
   The sanitized handoff-ledger fixture verifies corrupt-marker and orphan
   startup refusal, then successful recovery after repair under
   `execution-audit-focused/`. Its attested handoff-control fixture and
   sanitized daemon link also pass. The arm64/aarch64 `-j16` development
   world passed in `execution-start-arm64-buildworld.log`, with the audited
   daemon object compiled after the edit. Full native and other architecture
   world validation for this audit is still pending.
   A claimed ticket created before protocol 60 could have executed without
   an execution-start marker. CLAIM now fsyncs an exact HTH2 capability
   witness while still mutating, before it publishes the claimed phase.
   An old claimed ticket cannot acquire that witness through an exact CLAIM
   retry; the retry itself refuses a missing witness. A marker-aware restore
   refuses to release execution without it. The marker-status API also
   refuses a missing witness rather than
   reporting a legacy claim as unexecuted. Startup audits the witness in
   either the mutating or claimed phase and
   requires it for every execution-start marker. The sanitized handoff-ledger
   fixture covers a crash between witness and CLAIM publication, a missing
   legacy witness, corruption, and restart recovery; the attested handler
   fixture also passes under `claim-capability-focused/`. This closes the
   version-upgrade ambiguity for a future rebind check; it does not perform
   rebind or lift the nonempty restore fence. The final focused fixtures pass
   under `claim-capability-final-focused/`, and an amd64 `-j16` development
   world passes in `claim-capability-amd64-buildworld.log` with its daemon
   object compiled after the final source edit.
   Protocol 61 adds a ticket-bound REBIND_BEGIN request and durable HRI1
   intent. The attested new destination may publish it only after the old
   VMM epoch query says retired, the marker-aware CLAIM witness is exact,
   execution-start and guest REKEY_APPLIED are absent, and the source journal
   plan or exact empty transfer remains valid. HRI1 binds the old HTH2 claim
   to the proposed VM lifetime and daemon session/peer identity. Exact retries
   sync the same record. A staged HJB1 also refuses reuse of its old
   destination session. Replacement
   daemon startup checks the record, claimed ticket, witness, and still-closed
   execution boundary. The protocol, attested handler, and bhyve socket
   fixtures pass under `rebind-intent-focused/` and
   `rebind-intent-bhyve-connect`; the handler covers live-epoch refusal,
   exact retry, corruption, and post-rekey refusal. HRI1 is an intent, not a
   new execution lease. The durable receipt/journal remap and commit are
   still required before any claimed restore can be retried in the proposed
   incarnation. A second HRI1 proposal now replaces the first through a
   synced temporary inode and atomic rename only after the kernel reports
   both the original claimed VM and the first proposed VM
   epochs retired. It requires a distinct proposed VM lifetime and daemon
   session, retains the unchanged claimed HTH2, and audits the replacement
   after daemon restart. A live first proposal refuses replacement. This is
   still only an intent: there is no receipt or journal remap, commit, or
   execution lease. Publishing HRI1 also closes the old claim's
   execution-start and REKEY_APPLIED writers under the same process lock;
   neither marker can appear after an intent, and a corrupt intent refuses
   both writes. This preserves the no-execution condition during a later
   replacement attempt. The expanded attested handoff fixture and all 40
   sanitized daemon suites pass under
   `rebind-marker-exclusion-native-daemon/`; the earlier supersession
   fixture also passes under `rebind-supersession-focused/`. The current-source
   `-j16` development worlds pass for amd64, arm64/aarch64, and
   riscv/riscv64 in the `rebind-marker-exclusion-*-buildworld.log` files,
   with each daemon object built after the marker exclusion edit.
   Nonempty restore remains fenced.
   All 96 native port suites pass under `rebind-intent-native-port/`.
   HRI1 BEGIN now derives a proposed destination delivery plan before it
   publishes the intent. For a staged HJB1 it remaps the fixed source cut;
   for a local empty HTX1 it includes the HTD5 receipts already bound after
   CLAIM and their original HTD4/HTD5 source receipts. Exact old records are
   expected, while an unrelated delivery occupying the proposed session,
   delivery ID, or program identity refuses the intent with `EEXIST`. This is
   read-only preflight; KILL/cleanup remapping and a durable commit remain
   open. The expanded attested handoff fixture covers a colliding proposed
   delivery, its removal, and successful retry. All 40 sanitized daemon
   suites pass under `rebind-plan-native-daemon/`. Current-source `-j16`
   development worlds pass for amd64, arm64/aarch64, and riscv/riscv64 in
   `rebind-plan-*-buildworld.log`, with each daemon object rebuilt after the
   preflight edit.
   The proposed plan now includes KILL identities from either the fixed
   HJB1 source cut or the local source VM's durable KILL log. HRI1 BEGIN
   refuses a KILL already occupying the proposed VM lifetime, an
   unaccounted KILL in the old destination, or a KILL_APPLIED acknowledgment
   from the old destination. The latter is evidence that the old guest ran
   despite an absent execution-start marker. The attested handoff fixture
   covers both proposed-KILL collision and old-applied refusal, then
   successful retry after each test record is removed. This remains
   read-only planning; no KILL is copied to the proposed VM yet. All 40
   sanitized daemon suites pass under `rebind-kill-plan-native-daemon/`.
   Current-source `-j16` development worlds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in
   `rebind-kill-plan-*-buildworld.log`, with each daemon object rebuilt
   after the KILL preflight edit.
   HRI1 BEGIN also plans queued CLEANUP records from the staged cut or the
   local source journal. It refuses a pending local source cleanup, a
   proposed-VM cleanup ID collision, an unaccounted cleanup in the old
   destination, and an old-destination CLEANUP_APPLIED record. The latter
   would contradict the absent execution-start marker. The focused
   attested handoff fixture covers proposed collision, unaccounted old
   cleanup, old applied cleanup, and successful retry after removing each
   test record. This is still preflight: no proposed cleanup is published.
   All 40 sanitized daemon suites pass under
   `rebind-cleanup-plan-native-daemon/`. Current-source `-j16`
   development worlds pass for amd64, arm64/aarch64, and riscv/riscv64 in
   `rebind-cleanup-plan-*-buildworld.log`, with each daemon object rebuilt
   after the cleanup preflight edit.
   Protocol 62 adds HANDOFF_REBIND_STAGE. The attested proposed owner
   durably publishes HRP1 only after exact HRI1 matching and a fresh
   delivery, KILL, and CLEANUP preflight. HRP1 binds the full old claim and
   intent, sorted proposed HTD5 records and phases, KILL and CLEANUP
   identities, revocation sources, and the presence of host ingress. The
   sidecar is synced before publication; exact retry compares every byte.
   HRP1 blocks supersession while its proposed VMM epoch is live. Once both
   old and proposed epochs are retired, the daemon rederives the exact HRP1
   inventory, fsyncs its removal, and only then atomically replaces HRI1.
   A crash between those steps leaves the old intent without a stage, which
   can be retried. Startup rejects a corrupt, orphaned, or semantically
   inconsistent plan. The handoff fixture covers attested staging, exact
   retry, live-epoch refusal, retired-stage rollback, checksum
   corruption, a forged HTD5 owner and KILL revocation with recomputed
   checksums, and an orphaned plan. HRP1 is still a write-ahead inventory:
   no proposed journal record or execution lease is published.
   Record-by-record mutation, commit, rollback after mutation, and
   destination restore remain open.
   All 40 sanitized daemon suites pass under
   `rebind-stage-rollback-native-daemon/`. The 96 native port suites pass
   under `rebind-stage-native-port/`, and the updated bhyve-connect fixture
   passes its STAGE lost-ACK and retry cases. Current-source `-j16`
   development worlds pass for amd64, arm64/aarch64, and riscv/riscv64 in
   `rebind-stage-rollback-*-buildworld.log` under the validation root.
   Protocol 63 adds HANDOFF_REBIND_PENDING and
   HANDOFF_REBIND_CANCEL_PENDING. After an exact HRP1 stage, the proposed
   owner can publish only the pending HTD5 delivery receipts. An interrupted
   publication is repaired by exact retry; startup audits the staged plan
   against both old and proposed journal records. Cancellation requires
   privileged proof that both VM epochs are retired and refuses any proposed
   receipt that advanced beyond pending. It removes the inert receipts before
   a separate BEGIN can supersede the stage. No KILL, CLEANUP, host ingress,
   ownership commit, or execution authority is transferred by these ops.
   The attested fixture covers partial publication and restart, exact retry,
   corrupted pending receipt refusal, live-epoch cancellation refusal,
   advanced-receipt refusal, and retired-epoch cancellation and supersession.
   The bhyve-connect fixture covers lost-ACK, retry, and rejection framing
   for both new operations. All 40 sanitized daemon suites pass under
   `rebind-pending-final-native-daemon/`, and all 96 native port suites pass
   under `rebind-pending-native-port/`. Current-source `-j16` development
   world builds pass for amd64, arm64/aarch64, and riscv/riscv64 in
   `rebind-pending-final-*-buildworld.log`; the daemon object was rebuilt
   after the pending-publication edit on each target.
   A staged HJB1 regression exposed that the older HJB1 and HJR1 startup
   audits still assumed one HTD5 owner per ticket. A valid HRP1 rebind has
   both the old claimed receipt and a proposed pending receipt. Those audits
   now verify the old receipt directly when HRP1 is present; the preceding
   HRP1 audit verifies the exact combined inventory and rejects unexpected
   proposed records. Ordinary imports retain the single-owner census. The
   source-journal fixture now covers a nonempty HJB1 cut with delivery, KILL,
   and cleanup through pending publication, restart audit, and cancellation.
   All 40 sanitized daemon suites pass under
   `rebind-hjb1-audit-native-daemon/`. Current-source `-j16` development
   world builds pass for amd64, arm64/aarch64, and riscv/riscv64 in
   `rebind-hjb1-audit-*-buildworld.log` under the validation root.
   BEGIN now accepts an exact retry after STAGE/PENDING by verifying the
   staged plan and both old/proposed receipt sets before the strict fresh
   collision check. A later attested replacement may supersede a retired
   proposal with pending HTD5 receipts: the shared cancellation helper
   independently queries both VMM epochs at the deletion site, rederives
   HRP1, refuses advanced receipts, fsyncs each cancellation, and only then
   removes HRP1 so HRI1 can be replaced. A crash during deletion leaves
   HRI1/HRP1 for an exact retry. The attested fixture covers exact BEGIN
   retry, a live proposed-epoch refusal, and successful retired-proposal
   supersession without relying on the dead owner's cancellation channel.
   All 40 sanitized daemon suites pass under
   `rebind-supersede-native-daemon/`. Current-source `-j16` development
   worlds pass for amd64, arm64/aarch64, and riscv/riscv64 in
   `rebind-supersede-*-buildworld.log`; each rebuilt the changed daemon object.
   Rebind planning now requires every source-cut KILL to have its exact
   durable old-destination KILL file. A missing file refuses BEGIN, STAGE,
   pending publication, and restart audit instead of silently remapping a
   revocation that was never bound or was lost. BEGIN checks the old VMM
   epoch before interpreting a partly bound journal, then rechecks before
   publication. The handoff-control fixture binds all source KILLs as the
   restore coordinator does, then deletes one before BEGIN and again after
   STAGE to verify both refusal paths and recovery after replacement.
   All 40 sanitized native daemon suites pass under
   `rebind-kill-binding-final-native-daemon/`; current-source `-j16`
   development world builds pass for amd64, arm64/aarch64, and
   riscv/riscv64 in `rebind-kill-binding-*-buildworld.log` under the
   validation root. Ownership commit, failed-restore recovery, and nonempty
   restore remain open.
   Protocol 64 adds an attested `REBIND_COMMIT_EMPTY` control for a local
   handoff with an exactly empty source cut and replacement journal. After
   rechecking the old VMM epoch and the durable HRI1/HRP1 plan, the daemon
   fsyncs HRC1 before replacing the capability witness and claimed HTH2.
   A restart or later ticket lookup completes an interrupted switch before
   normal ticket audits. A separate durable completion witness binds the
   proposed session, UID, PID, and VM lifetime for exact retries after a
   lost reply; a subsequent rebind replaces that witness only after its own
   HRC1 is durable. The attested fixture covers normal completion, recovery
   after capability replacement, exact retry, a second hop, corrupted
   completion evidence, and refusal of a nonempty plan. This closes only
   empty-journal ownership commit; nonempty journal remap, restore
   coordinator integration, and failed-restore recovery remain open.
   All 40 sanitized native daemon suites passed under
   `/usr/obj/5BSD-hypertrace-validation/rebind-empty-done-verified-native-daemon/`;
   all 97 native port suites, including the bhyve control-channel retry,
   passed under `rebind-empty-done-native-port/`. Current-source `-j16`
   development world builds passed on amd64, arm64/aarch64, and
   riscv/riscv64 in the `rebind-empty-done-final-*-buildworld.log` files
   under the validation root. These are source and native-component checks,
   not a live restored-VM qualification.
   Protocol 65 adds an attested, read-only `REBIND_EMPTY_READY` check. The
   restore coordinator now classifies a previously claimed, unstarted ticket
   before opening the kernel restore session. It stages the replacement
   journal and requires the exact empty plan and retired old VMM epoch before
   kernel mutation; after a committed kernel session it uses the durable
   empty-journal rebind commit, then follows the existing KILL, queue, import,
   and execution-start fences before releasing vCPUs. A first restore still
   uses RESERVE/MUTATE/CLAIM. Nonempty transfer and journal plans remain
   fenced before kernel mutation. The updated attested daemon fixture and
   bhyve control fixture pass with all 40 sanitized daemon and 97 native port
   suites under the `rebind-coordinator-native-*` directories. Current-source
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `rebind-coordinator-*-buildworld.log` under the validation root; amd64
   rebuilt the changed bhyve restore coordinator. This is
   source/component validation, not proof that failed-restore recovery works
   in a live VM. Nonempty journal remap and restore remain open.
   The restore coordinator now carries a well-formed nonempty HTX1 past the
   read-only device, queue, and memory preflight into a reversible destination
   RESERVE and HANDOFF_IMPORT. It stages the source journal before querying
   saved device delivery/KILL/cleanup status, checks that the private image
   has not changed, and then deliberately refuses the still-incomplete
   execution lease. The failure path attempts to cancel the reserved import
   before any kernel restore session or vCPU release. Invalid or
   over-capacity transfers still fail before reservation. All 97 native port
   component suites pass
   under `import-preflight-native-port/`; an amd64 `-j16 buildworld` rebuilt
   `snapshot.c` and passed in `import-preflight-amd64-buildworld.log`.
   The pre-mutation handoff sequence is now one production helper with a
   source-extracted sanitized fixture. Fresh nonempty import reaches RESERVE,
   IMPORT, and private-image query before the deliberate refusal; a failed
   import or query retains the reservation flag for CANCEL. Nonempty retry
   reaches STAGE/PENDING and refuses without claiming a new reservation.
   Empty first restore and empty rebind remain admissible. The private-image
   digest fixture now extracts only its two production functions after this
   refactor. All 101 native port suites pass under
   `restore-handoff-preflight-final-native-port/`, and the amd64 16-job world
   build rebuilt `snapshot.c` and passed in
   `restore-handoff-preflight-amd64-buildworld.log`. This is component
   evidence; the complete coordinator still lacks a runtime fixture and
   end-to-end live VM evidence.
   A failed fresh restore now returns an unsuccessful CANCEL as its final
   error instead of only logging it and returning the original preflight
   error. The source-extracted handoff fixture verifies that CANCEL is
   attempted only for a reserved ticket before MUTATE or CLAIM, and checks
   both successful and failed cancellation. All 101 native port suites pass
   under `restore-cancel-native-port/`; the amd64 `-j16 buildworld` passes in
   `restore-cancel-amd64-buildworld.log` under the validation root. This
   reports an unresolved reservation; durable recovery and the nonempty
   execution lease are still open.
   A MUTATE request is now treated as an irreversible boundary before the
   daemon call, since an error can mean its reply was lost after publication.
   The coordinator no longer sends CANCEL after such an uncertain attempt.
   The source-extracted fixture checks the flag at send time, failed and
   successful MUTATE, and cancellation suppression. All 101 native port
   suites pass under `restore-mutate-uncertain-native-port/`; amd64 `-j16
   buildworld` passes in `restore-mutate-uncertain-amd64-buildworld.log`.
   Failed post-MUTATE recovery still needs a durable retry path.
   Destination RESERVE/CANCEL/MUTATE/CLAIM reconciliation now distinguishes
   an explicit daemon NAK or malformed ACK from a potentially lost reply.
   Either bad reply stops without a status query or retry; uncertain replies
   still reconcile against the durable phase. The bhyve socket fixture
   checks that neither form of MUTATE refusal creates a second connection.
   All 101 native port suites pass under `handoff-nak-final-native-port/`;
   current-source `-j16 buildworld` passes
   for amd64, arm64/aarch64, and riscv/riscv64 in the
   `handoff-nak-final-*-buildworld.log` files under the validation root.
   The optional REBIND_BEGIN classifier now treats a malformed first reply
   and a lost first reply followed by NAK as unresolved errors. An explicit
   first NAK selects the fresh path only after a read-only destination query
   proves the exact checkpoint is still committed; a reserved phase refuses
   classification. The bhyve socket fixture covers all four outcomes and
   verifies no third write after an ambiguous retry. All 101 native port
   suites pass under `rebind-classify-native-port/`; current-source `-j16
   buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in the
   `rebind-classify-*-buildworld.log` files. This prevents a wrong branch
   choice but does not recover a failed mutating or claimed incarnation.
   Nonempty import promotion and its execution lease remain open.
   A failed nonempty restore that reaches an eligible claimed ticket now
   stages the exact replacement HRP1 and publishes retryable pending HTD5
   receipts through the attested rebind controls. It then refuses before
   saved-device or kernel mutation; no ownership, KILL, or cleanup authority
   moves. This makes the reversible nonempty preparation reachable from the
   restore coordinator while the journal-and-owner commit remains unfinished.
   The bhyve control fixture already covers STAGE/PENDING reply recovery;
   all 97 native port suites pass under `rebind-nonempty-preflight-native-port/`.
   The amd64 `-j16 buildworld` rebuilt `snapshot.c` and passed in
   `rebind-nonempty-preflight-amd64-buildworld.log`. There is still no
   integrated coordinator runtime or live VM evidence for this path.
4. **Guest rekey barrier:** Guest and host have rekey messages and receipt
   queries. Guest journal rekey now verifies every old-incarnation inbound,
   outbound, and KILL receipt before renaming any journal entry, so a denied
   later receipt leaves the old identity intact. The guest daemon now retries
   a transient journal fsync or rekey TX-ring failure within its fixed recovery
   deadline. Each journal retry rechecks the original host receipts, and the
   driver treats an exact COMMIT retry as idempotent. Recovery after a locally
   committed rekey also retries transient journal-read I/O without issuing
   another COMMIT. A persistent failure still requires restart recovery.
   Protocol 44 adds `HANDOFF_REKEY_APPLIED`. The host sends the exact guest
   REKEY_APPLIED observation through a
   separately attested daemon channel before retiring its handoff ticket or
   releasing READY. The daemon fsyncs an idempotent ticket-and-destination
   receipt while retaining the claimed ticket for late KILL and delivery
   bindings. A lost response retries the exact request; unresolved failure
   or an expired rekey deadline quarantines the device. The ledger fixture
   verifies restart retry and stale-destination refusal, the control fixture
   verifies attested ownership, and the bhyve fixture covers a lost response.
   All 36 sanitized daemon and 74 native port suites pass under the
   `rekey-applied-v44-*` validation directories. Current-source 16-job development
   world builds pass for amd64, arm64/aarch64, and riscv/riscv64 in the
   `rekey-applied-v44-*-buildworld.log` files. This is a durable host
   observation; live guest execution and crash recovery still need proof.
   Prove exact journal
   remap, bounded retries, and committed guest acknowledgment in a live
   restored VM.
5. **Guest-applied KILL barrier:** Daemon KILL durability is not proof of guest
   application. A native-tested host queue fence now sends one saved KILL at
   a time and waits for the exact guest KILL_APPLIED report to reach the host
   daemon before releasing the next saved control. The handoff journal copies
   a KILL recorded after the source cut to the destination at CLAIM and
   blocks the next source cut until that copied KILL is applied. When a late
   KILL reaches bhyve before a saved ELF starts, the device now inserts it
   after NODE_REKEY and earlier KILLs, ahead of that ELF, with an exact
   KILL_APPLIED fence. It leaves an already started ELF run contiguous and
   reserves queue space for the KILL acknowledgment. Restore-specific daemon
   admission now takes a serialized journal cut and sends a bounded canonical
   KILL manifest after its ACK. The restore coordinator takes the entire
   manifest while PCI devices are paused; bhyve revalidates the destination
   identity and inserts those KILLs ahead of saved ELF controls before
   attaching the ticket that releases NODE_REKEY. READY is also withheld
   while that ticket is absent. Later live KILL jobs cannot overtake the
   manifest on the daemon socket. Ticket attachment now binds a canonical
   digest of the whole admission manifest and the destination VM identity,
   so an exact retry succeeds and a changed or omitted KILL set or changed
   incarnation fails without changing the queue. The daemon sorts the
   manifest by VM incarnation, PID, and source ID before sending it; bhyve
   rejects duplicate or out-of-order entries, so an unchanged durable KILL
   set retains the same digest across reconnects. Reconnect and crash
   recovery around this
   cut, live guest/daemon behavior, and failure recovery still need
   qualification.
   The guest VirtIO-DTrace driver now validates an incoming ELF or KILL
   control before clearing its ready state. Malformed identities and ELF
   bounds do not mutate readiness inside the event handler; the outer RX
   loop still stops the transport on that error. A valid control closes the
   gate before queueing, and queue failure remains fail-closed.
   The source-extracted sanitized guest-driver fixture covers both invalid
   and valid transitions. All 96 native port suites pass under
   `guest-invalid-ready-native-port/`; current-source `-j16` GENERIC kernel
   and module builds pass for amd64, arm64/aarch64, and riscv/riscv64 in
   `guest-invalid-ready-*-buildkernel.log` under the validation root.
6. **Live migration:** The current source and destination migration paths
   reject HyperTrace. Implement source fence, destination claim, failure
   rollback, and replay across a live handoff. The present migration transport
   is a caller-supplied stream with checksummed frames but no peer
   authentication. A future HyperTrace ticket or HSL1 release witness must
   not gain cross-host authority from this stream without an authenticated
   binding to the source and destination hosts.
   The current HTX1 member carries host-ingress state, but a foreign
   destination also needs the source outbound delivery receipts and verified
   ELF spool, KILL and applied-KILL records, CLEANUP state, and revocation
   lineage. The destination's existing delivery, KILL, and cleanup binders
   read those source records from the local journal, so a signed HSA1 and
   copied checkpoint alone cannot make a foreign ticket reservable.
   A portable, signed source-journal cut and destination import transaction
   must precede the foreign execution lease. The foreign release staging
   remains inert until those records and their rollback/recovery rules exist.
   Source PREPARE now checks each accepted or installed host-to-guest
   delivery under the handoff lock: it requires the ticket's source session,
   a transferable HTD4/HTD5 receipt, and the exact durable ELF spool unless
   that source is revoked. Missing and changed spools refuse the cut. This
   is a preflight check, not the portable journal export; the export must
   capture and recheck the actual bytes before signing its manifest.
   The missing, matching, and changed ELF cases pass in the source-gate
   fixture, and all 39 sanitized native daemon suites pass under
   `/usr/obj/5BSD-hypertrace-validation/source-outbound-cut-final-native-daemon/`.
   Current-source `-j16 buildworld` passes on amd64, arm64/aarch64, and
   riscv/riscv64 in the `source-outbound-cut-*-buildworld.log` files under
   the same validation object root.
   The outbound spool verifier can now return the exact bounded ELF or
   VM-envelope copy only after checking its HTD4/HTD5 digest and stable,
   private source inode. It leaves the copy empty on absence or failure.
   A path-independent destination validator checks copied bytes against
   the receipt's original payload VM, envelope, ELF magic, and digest.
   These are the payload primitives for the journal archive; neither
   publishes an archive or admits a foreign ticket yet.
   The bare-ELF and envelope validation fixtures pass with all 39 sanitized
   native daemon suites in `outbound-validator-final-native-daemon/`.
   Current-source `-j16 buildworld` passes on amd64, arm64/aarch64, and
   riscv/riscv64 in `outbound-validator-*-buildworld.log`.
   PREPARE now also constructs a bounded, sorted outbound-journal census
   under the source process lock. It includes accepted or installed HTD4/HTD5
   receipts, verified payload copies or revocation state, applied KILLs, and
   queued or guest-applied CLEANUP records. HTD5 ancestry must resolve to a
   claimed prior ticket. Duplicate CLEANUP phases and a census too large
   for an HTX1 member refuse PREPARE. The cut remains in memory for this
   preflight; its bytes are not yet encoded, signed, or imported, and source
   KILLs recorded after the cut still require a cross-host barrier.
   All 39 sanitized native daemon suites pass in
   `source-journal-census-native-daemon/`; the updated source-gate fixture
   separately passes its pending-to-queued CLEANUP transition.
   Current-source `-j16 buildworld` passes on amd64, arm64/aarch64, and
   riscv/riscv64 in `source-journal-census-*-buildworld.log`.
   The census now has a canonical `HJX1` wire image with a ticket/session/VM
   header, ordered HTD4/HTD5 delivery records and copied payloads, applied
   KILLs, and CLEANUP phases. Its decoder checks fixed little-endian fields,
   zero reserved bytes, strict ordering, bounds, each delivery record and
   ELF digest, and the final SHA-256 before publishing any decoded result.
   PREPARE checks that its census can be encoded. A native fixture round-trips
   the archive and rejects corruption even after its outer digest is
   recomputed. `HJX1` is still inert: its digest must be included in the
   signed HTX1/HSA1 handoff path, and the destination needs an atomic import
   before any foreign lease is allowed.
   All 40 sanitized native daemon suites pass in
   `source-journal-wire-native-daemon/`; the focused wire fixture also
   rejects resealed reserved fields, oversized payload lengths, and excessive
   entry counts. Current-source `-j16 buildworld` passes on amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `source-journal-wire-*-buildworld.log` files.
   An inert `HJM1` wrapper now defines how an `HJX1` archive and optional
   ingress manifest share one HTX1 digest. The transfer inspector distinguishes
   a journal-only member from accepted ingress; the synthetic round-trip
   fixture checks wrapper splitting and rejects a changed archive digest even
   when the outer HTX1 checksum is recomputed. The production source export
   does not emit HJM1 yet, so this does not transfer private journal bytes or
   open a foreign restore path.
   All 40 sanitized native daemon suites and 94 native port suites pass under
   `journal-wrapper-native-daemon/` and `journal-wrapper-native-port/`.
   Current-source `-j16 buildworld` passes on amd64, arm64/aarch64, and
   riscv/riscv64 in `journal-wrapper-*-buildworld.log` under the validation
   root. These are local checks of the inert format, not a handoff result.
   HJM1 parsing now checks the nested HJX1 ticket, version, and reserved
   header bytes before accepting a checksum-valid archive. The synthetic
   fixture reseals both the inner archive and outer transfer after changing
   each of those fields and verifies that wrapping, inspection, and splitting
   still refuse it. All 40 sanitized daemon suites pass under
   `journal-ticket-native-daemon/`; current-source `-j16 buildworld` passes
   on amd64, arm64/aarch64, and riscv/riscv64 in
   `journal-ticket-*-buildworld.log` under the validation root.
   Restore admission now treats a journal-only HJM1 transfer as state that
   requires an import transaction, even when its ingress set is empty. The
   shared transfer decision is used by bhyve both before restore mutation
   and before conditional destination import, so a journal-only checkpoint
   cannot take the empty-transfer path. The synthetic journal-only, empty,
   and combined-transfer cases pass with all 40 sanitized daemon suites and
   all 96 native port suites under the `journal-restore-fence-*` validation
   paths. This preserves the restore fence; it does not enable source journal
   export or destination journal import.
   A destination-side private decoder now requires the reserved ticket's exact
   HTX1 digest, validates the HJM1/HJX1 source identity and contents, and
   validates any nested ingress bundle before returning either decoded part.
   An empty archive, changed transfer digest or source session, and malformed
   nested ingress leave both outputs empty. All 40 sanitized native daemon
   component suites pass under `journal-destination-decode-native-daemon/`;
   current-source development `-j16 buildworld` passes for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `journal-destination-decode-*-buildworld.log` files. The decoded journal
   remains private; durable staging, atomic import, and a foreign execution
   lease are still missing.
   The destination outbound journal can now durably stage that validated
   transfer as an inert HJB1 sidecar while the exact ticket is reserved.
   The sidecar binds the checkpoint and destination identity, checksums the
   full HTX1 bytes, survives a daemon reopen, and accepts only an exact retry.
   CANCEL removes it and fsyncs the directory before returning the ticket to
   committed; a corrupt stage refuses both load and cancellation. The focused
   fixture and all 40 sanitized daemon component suites pass under
   `journal-durable-stage-final-native-daemon/`. Development `-j16 buildworld`
   passes for amd64, arm64/aarch64, and riscv/riscv64 in the
   `journal-durable-stage-*-buildworld.log` files. The stage does not publish
   source records or grant a foreign lease.
   Control-daemon startup now audits every HJB1 in the outbound journal under
   the same handoff process lock used by its publisher. A stage must have a
   canonical ticket name, a live reserved phase, valid private-file metadata,
   a correct HJB1 checksum, and a fully decodable ticket-bound HJM1/HTX1.
   Corruption or an orphan left after cancellation fails startup instead of
   silently retaining a misleading stage. The source-journal fixture covers
   valid recovery, corruption, and an orphan; all 40 sanitized daemon suites
   pass under `journal-startup-audit-native-daemon/`. Current-source
   development `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `journal-startup-audit-*-buildworld.log`. This audit does not
   import source records or authorize a restored guest to execute.
   The existing VMM-attested HANDOFF_IMPORT route now recognizes HJM1. It
   stages the complete source cut as HJB1 under the reserved ticket. It
   refuses to ACK an import that has not established an execution lease.
   The reserved-stage fixture covers the exact retry
   and a changed destination; all 40 sanitized daemon suites pass under
   `journal-handler-stage-native-daemon/`, and current-source development
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `journal-handler-stage-*-buildworld.log`. Current bhyve restore still
   refuses a nonempty transfer before reaching this request. Production
   source export and the atomic destination journal transaction remain open.
   A staged HJB1 now blocks the reserved-to-mutating handoff transition.
   Otherwise the ticket could advance while its source records remained inert,
   leaving startup with an orphan stage. A malformed HJB1 also blocks the
   transition with `EPROTO`; both cases leave the ticket reserved so the
   operator can repair or cancel it. The 40 sanitized daemon component suites
   pass under `journal-mutation-fence-native-daemon/`; development `-j16
   buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in the
   `journal-mutation-fence-*-buildworld.log` files. This guard must be replaced
   by a durable import-and-lease transaction before nonempty restore opens.
   The outbound daemon now has a source-cut builder that takes the same
   publication and process locks as ticket creation, combines validated HJX1
   with any ingress member, and emits one bounded HTX1. An empty source cut
   still yields the legacy empty HTX1. The component fixture checks an empty
   cut, an applied KILL, and the resulting HJM1 decode. All 40 sanitized daemon
   component suites pass under
   `journal-source-helper-native-daemon/`; development `-j16 buildworld`
   passes for amd64, arm64/aarch64, and riscv/riscv64 in the
   `journal-source-helper-*-buildworld.log` files. This builder is not connected to
   the production `HANDOFF_EXPORT` response; PREPARE still checks the legacy
   source member, so it must not be described as a usable nonempty handoff.
   A read-only re-export through that helper now requires its reconstructed
   HTX1 digest to match an already PREPARED ticket. The fixture prepares an
   empty cut, then records an applied KILL and verifies re-export fails with
   `EPROTO` and no returned bytes; after ABORT, a fresh HJM1 cut succeeds.
   All 40 sanitized daemon component suites pass under
   `journal-prepared-digest-native-daemon/`, and development `-j16 buildworld`
   passes for amd64, arm64/aarch64, and riscv/riscv64 in the
   `journal-prepared-digest-*-buildworld.log` files. This protects the helper's
   future retry path but does not yet make COMMIT recheck the source cut.
   Reserved-ticket delivery, KILL, and cleanup status queries now read a
   validated HJB1 source cut when one is staged. They return its exact source
   delivery phase and payload availability, applied KILL status, and cleanup
   phase without flattening foreign source VM identities into the local
   journal. A missing HJB1 retains the existing local-journal path. The
   staged-status fixture checks all three record kinds; all 40 sanitized
   daemon component suites pass under `journal-staged-status-native-daemon/`.
   Development `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `journal-staged-status-*-buildworld.log`. The query does
   not import source records, ACK HANDOFF_IMPORT, or grant an execution lease.
   A reserved HJB1 can now be mapped into a read-only destination plan.
   Live deliveries retain their verified ELF bytes and original payload VM
   lifetime while receiving the destination session, VM lifetime, peer, and
   ticket lineage. Applied source KILLs become pending destination KILLs;
   source revocations are deduplicated; only queued source cleanups are
   scheduled for destination replay. A contradictory live delivery and
   revocation fails the plan. The fixture checks the absent stage, mapped
   delivery, KILL, cleanup, and invalid destination session. All 40 sanitized
   daemon component suites pass under
   `journal-destination-plan-fixed-native-daemon/`; development `-j16
   buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in the
   `journal-destination-plan-*-buildworld.log` files. This plan publishes no
   spool or journal record and cannot yet ACK import or release a guest.
   New HJB1 stages use version 2 and bind the attested destination forwarder
   session, UID, and PID into their checksum. Exact retries with a different
   owner fail, and the read-only destination planner requires that same owner
   after restart. Version-1 HJB1 remains readable and cancellable as inert
   evidence, but cannot supply a recoverable import owner and is refused by
   the planner. The 40 sanitized daemon suites pass under
   `journal-bound-stage-native-daemon/`; the focused legacy-stage fixture
   passes against those daemon objects. Development `-j16 buildworld` passes
   for amd64, arm64/aarch64, and riscv/riscv64 in the
   `journal-bound-stage-*-buildworld.log` files. Outbound ELF spools are
   watcher-visible under their final names, so the eventual import must keep
   transferred bytes private until its execution lease is established.
   The outbound destination can now import the mapped source deliveries as
   ticket-bound HTD5 `pending` receipts while HJB1 retains every ELF byte.
   Import rechecks the reserved ticket and bound forwarder identity, rejects
   conflicting program or delivery identities before its first write, and
   accepts exact retries after a crash. CANCEL verifies all ticket receipts
   against HJB1 and removes only matching pending receipts before removing
   the stage; an advanced receipt stops cancellation. The focused fixture
   covers wrong-owner refusal, exact retry, restart recovery, lack of a
   watcher-visible spool, and cancellation cleanup. This is a reversible
   preparation step, not a completed import: no source KILL, cleanup,
   revocation, ELF activation, execution lease, or import ACK is published.
   All 40 sanitized native daemon suites pass under
   `journal-pending-native/`; development `-j16 buildworld` passes for
   amd64, arm64/aarch64, and riscv/riscv64 in the
   `journal-pending-*-buildworld.log` files.
   Startup now audits every reserved-ticket HTD5 source-delivery receipt
   against the exact HJB1 stage and its bound destination identity. A partial
   pending set remains recoverable; an orphan, altered, advanced, or
   version-1-backed receipt prevents daemon recovery. CANCEL likewise
   refuses an advanced receipt while retaining HJB1. The fixture covers
   restart acceptance, advanced-phase rejection, legacy-stage mismatch,
   and cancellation refusal. All 40 sanitized daemon suites pass under
   `journal-pending-audit-native/`. Development
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `journal-pending-audit-*-buildworld.log` under the validation root.
   A locked, read-only pending-import status now reconciles every mapped
   delivery against the outbound journal and reports absent HJB1, partial
   pending receipts, or a complete pending set. It also returns the verified
   destination KILL and cleanup plan. The importer uses the same rule before
   its first write, including refusal of an extra checksum-valid HTD5 that
   carries the ticket token but is not in HJB1. The fixture covers absent,
   partial, complete, wrong-owner, advanced-phase, and unplanned-record
   states. This is a recovery gate for a future transaction, not an import
   ACK or execution lease. All 40 sanitized daemon suites pass under
   `journal-pending-reconcile-native/`; development `-j16 buildworld` passes
   for amd64, arm64/aarch64, and riscv/riscv64 in the
   `journal-pending-reconcile-*-buildworld.log` files.
   The pending source-journal import now finishes by publishing an HJR1
   private marker only after every exact HTD5 pending receipt has reached
   disk. HJR1 binds the reserved ticket, checksum of the exact HJB1 stage,
   and delivery count. Recovery treats all receipts with no HJR1 as a
   retryable partial import; HJR1 with a missing or changed receipt is
   corruption. Startup audits even a zero-delivery HJR1, and CANCEL removes
   HJR1 before pending receipts and HJB1 so a crash can retry cleanup. The
   fixture covers interrupted marker publication, exact retry, changed
   marker bytes, orphan marker, and cancellation cleanup. HJR1 remains an
   inert completion witness; mutation, import ACK, and execution stay fenced.
   All 40 sanitized daemon suites pass under `journal-ready-native/`;
   development `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `journal-ready-*-buildworld.log` files.
   MUTATE and CLAIM now also reject an orphaned HJR1 if HJB1 is absent.
   The source-journal fixture removes HJB1 while retaining HJR1 and proves
   MUTATE fails without advancing the reserved ticket; restoring the exact
   stage makes startup recovery valid again. This preserves the phase fence
   while the claimed-ticket replay rules are implemented. All 40 sanitized
   daemon suites pass under `journal-phase-fence-native/`; development
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   the `journal-phase-fence-*-buildworld.log` files.
   The claimed-ticket KILL binder now has a foreign HJB1 path. It requires
   the exact HJR1 completion marker and all ticket-bound delivery receipts,
   maps the applied source KILLs to the destination VM lifetime, and writes
   the destination KILL records before reporting success. A retry completes
   a partial KILL prefix. Startup accepts a claimed HJB1 only when HJR1 and
   every mapped receipt remain valid; accepted or terminal exact receipts
   are allowed after promotion. The focused fixture injects a claimed phase
   after staging, checks missing-marker and missing-receipt refusal, then
   verifies KILL publication, retry, and restart recovery. Production
   MUTATE remains fenced, so this path does not yet enable foreign restore.
   All 40 sanitized daemon suites pass under `journal-foreign-kills-native/`;
   development `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `journal-foreign-kills-*-buildworld.log` files.
   Claimed-ticket KILL and cleanup status now read the same validated HJB1
   source cut as the all-KILL binder. The per-KILL binder publishes an exact
   destination KILL before reporting its destination acknowledgment phase.
   A claimed foreign ticket refuses an HJR1 completion marker left behind
   without HJB1, rather than falling back to an empty local source journal.
   Ticket-bound HTD5 alone is not evidence of a foreign cut because a local
   handoff can produce HTD5 too. The source-journal fixture exercises missing
   stage, missing marker, missing receipt, per-KILL retry, and advanced receipt
   recovery. Production foreign MUTATE remains fenced.
   All 40 sanitized native daemon suites pass under
   `journal-claimed-query-final3-native/`; final-source development
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   the `journal-claimed-query-final-*-buildworld.log` files under the
   validation root.
   Destination planning now preserves the original HJB1 delivery records
   instead of rewriting the decoded source cut. Claimed-ticket source
   delivery queries validate HJR1 and the exact receipt set, then report the
   original source phase, revocation, and private payload availability. A
   pending destination HTD5 remains unbound. After an exact advanced
   receipt, lineage verification can use the attested HJB1 source record
   when a foreign host has no local source file; that source cut terminates
   the older-host lineage walk. This does not publish an ELF spool or grant
   an execution lease, and production foreign MUTATE remains fenced.
   The focused source-journal fixture and all 40 sanitized native daemon
   suites pass under `journal-foreign-delivery-native/`; final-source
   development `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `journal-foreign-delivery-*-buildworld.log` files
   under the validation root.
   The claimed-ticket delivery binder now has a foreign HJB1 path. It
   requires the exact mapped HTD5 record and destination owner, an advanced
   accepted or installed receipt, verified destination ELF spool bytes, and
   nonrevoked lineage before returning that binding. It refuses a pending
   receipt, missing spool, or wrong owner without publishing records or
   payloads. The source-journal fixture covers those refusals and an exact
   accepted retry. This is a post-promotion check; it does not promote an
   import or supply the missing execution lease.
   All 40 sanitized daemon suites pass under `journal-foreign-bind-native/`;
   final-source development `-j16 buildworld` passes for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `journal-foreign-bind-*-buildworld.log` files under the validation root.
   Outbound startup now audits imported HSA1 source-release witnesses under
   the handoff lock. It requires configured pinned host keys, a canonical
   token filename and private regular inode, a valid source signature bound
   to this destination key, and agreement with any local ticket's exact
   committed source cut. A pre-reservation witness remains valid without a
   ticket. This audit does not grant an execution lease or lift the foreign
   restore fence.
   The handoff-control fixture checks valid restart and a changed signature;
   all 40 sanitized daemon suites pass under `imported-release-audit-native/`.
   Final-source development `-j16 buildworld` passes for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `imported-release-audit-*-buildworld.log` files under the validation root.
   A VMM-attested destination RESERVE may now adopt a pinned-key HSA1 when
   the source ticket is absent from the local journal. Adoption fsyncs the
   exact signed source cut as a committed local ticket; an interrupted
   adoption can be retried, and RESERVE rechecks the imported proof even on
   an exact reserved-ticket retry. A wrong checkpoint digest or changed
   signature cannot create or reuse the reservation. Foreign MUTATE and
   CLAIM still refuse without a local HSL1 because the source journal import
   and execution lease are incomplete. The handoff-control fixture covers
   wrong-digest refusal, adoption, retry, restart, proof corruption, and the
   mutation fence. Phase-file reading compares the imported HSA1's embedded
   HSL1 source cut when local HSL1 is absent; that read-only check is not a
   signature decision. Startup and reservation independently verify HSA1
   against the pinned host keys. All 40 sanitized daemon suites pass under
   `foreign-release-adopt-native-4/`; development `-j16 buildworld` passes
   for amd64, arm64/aarch64, and riscv/riscv64 in the
   `foreign-release-adopt-*-buildworld.log` files under the validation root.
   The production HANDOFF_IMPORT handler now follows HJB1 staging with the
   private HTD5 pending-receipt import and exact HJR1 completion marker.
   Interrupted receipt prefixes and exact request retries use the same
   importer as the recovery fixtures. The handler still returns
   `EOPNOTSUPP` without an ACK: no transferred ELF spool, KILL, cleanup,
   revocation, or execution lease is activated. Its VMM-attested fixture
   checks the HJM1 request, complete pending status, restart audit, retry,
   and reservation rollback. Bhyve still refuses nonempty transfer before
   it reaches this request. All 40 sanitized daemon suites pass under
   `journal-handler-private-native/`; development `-j16 buildworld` passes
   for amd64, arm64/aarch64, and riscv/riscv64 in the
   `journal-handler-private-*-buildworld.log` files under the validation root.
   Private HJB1 staging, destination planning, pending HTD5/HJR1 import,
   and its recovery status now recheck source release authority under the
   handoff lock. A local ticket requires its exact HSL1; a foreign ticket
   requires the pinned-key HSA1 signature and exact committed source cut.
   The phase reader's checksum-only HSA1 comparison cannot authorize these
   operations. The cross-host handler fixture creates a signed foreign
   release for a journal-bearing transfer, proves that changing the proof
   blocks initial staging and a later HJR1 recovery query, then restores
   the proof and checks import, retry, and rollback. This still creates no
   execution lease or import ACK. All 40 sanitized daemon suites pass under
   `foreign-import-release-gate-native/`; development `-j16 buildworld`
   passes for amd64, arm64/aarch64, and riscv/riscv64 in the
   `foreign-import-release-gate-*-buildworld.log` files under the validation
   root.
   Restore-facing source delivery, KILL, and cleanup queries now recheck
   that release authority before reading a reserved HJB1. The shared
   claimed-ticket source plan and lineage walk do the same before a foreign
   KILL or delivery binder can use HJR1. This closes a checksum-only phase
   read in those paths; it does not enable foreign MUTATE or CLAIM. The
   cross-host fixture changes the HSA1 signature after HJR1 publication and
   checks that all three reserved queries refuse it, then restores the proof
   and verifies the accepted source delivery is visible again. The focused
   claimed-phase fixture repeats the changed-proof check behind HJR1 and
   verifies recovery after restoring the proof. All 40 sanitized daemon
   suites pass under `foreign-claim-release-gate-native/`; the final focused
   handoff-control fixture passes against the same daemon objects.
   Development `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `foreign-claim-release-gate-*-buildworld.log` files
   under the validation root.
   An ordinary host forwarder now refuses to create a new HTD4 pending
   receipt for a program ID already owned by imported HTD5 in the same
   destination VM lifetime. This closes a path that would otherwise mint a
   second delivery identity if transferred ELF bytes were made visible to
   the spool watcher. The handoff-control fixture checks the original and
   a changed source ID against the imported program. All 40 sanitized
   daemon suites pass under `imported-outbound-identity-native-final/`;
   development `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `imported-outbound-identity-*-buildworld.log` files.
   The imported payload remains private in HJB1: this guard does not grant
   an execution lease or publish a watcher-visible spool.
   The HJM1 HANDOFF_IMPORT handler now completes the nested accepted-ingress
   pending import after HJR1. It splits the ticket-bound HTX1, requires the
   nested HCP1 program-image evidence, stages HTB1, then persists mapped
   pending HTD5 ingress receipts and their verified destination ELF spools.
   The watcher leaves those receipts inert. An exact request retry reaches
   the same records; CANCEL removes both the inbound pending prefix and the
   outbound HJR1/HJB1 prefix before releasing the reservation. A combined
   HJM1 attested-handler fixture checks both retries, restart audits, exact
   pending payloads, and cancellation. All 40 sanitized daemon suites pass
   under `hjm1-nested-ingress-native-verified/`; the final restart assertion
   passes in the focused sanitized host-ingress fixture against those daemon
   objects. Development `-j16 buildworld` passes for amd64, arm64/aarch64,
   and riscv/riscv64 in `hjm1-nested-ingress-final-*-buildworld.log`.
   At that stage the handler returned `EOPNOTSUPP` without an import ACK. Accepted
   promotion, a foreign execution lease, and nonempty bhyve restore remain
   open.
   The combined HJM1 path now reserves the exact destination consumer owner
   and program image after importing the nested pending receipts. If that
   consumer is absent, HANDOFF_IMPORT returns `EBUSY` and an exact retry can
   finish the inert owner/cohort/result/promotion-intent sidecars when it
   registers. A changed program digest returns `EPROTO` without accepting
   that owner; restoring the exact image lets the retry continue. The
   attested-handler fixture checks these failures, two exact retries,
   startup audits, durable owner identity, pending-only ELF state, and
   cancellation of both journal prefixes. All 40 sanitized daemon suites
   pass under `hjm1-owners-native/`; development `-j16 buildworld` passes
   for amd64, arm64/aarch64, and riscv/riscv64 in
   `hjm1-owners-*-buildworld.log`. These sidecars are reservation evidence,
   not an execution lease; the handler still refused its ACK at that stage.
   Generic host delivery transitions now recognize a ticket-bound imported
   HTD5 and recheck its exact HTH1 parent, destination identity, signed HSA1
   source cut, and HJB1/HJR1 stage while holding the handoff process lock.
   An HJB1-backed pending receipt cannot be promoted through the ordinary
   `record_delivery` API before the dedicated import transaction grants an
   execution lease; terminal retirement also requires a claimed ticket.
   The handoff-control fixture covers pending and synthetic claimed states,
   unchanged pending status after a refused promotion, a damaged HSA1, and
   cancellation rollback. All 40 sanitized daemon suites pass under
   `imported-receipt-lease-fence-final-native/`; development `-j16
   buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
   `imported-receipt-lease-fence-final-*-buildworld.log`. The lease,
   ticket-bound outbound replay, import ACK, and nonempty restore were open.
   The outbound journal now has a claimed-ticket replay payload reader for
   an exact imported HTD5. It rechecks the HTH1 claim, signed source release,
   complete HJB1/HJR1 plan, exact pending receipt, and transferred ELF digest
   under the handoff lock. It returns bare ELF, removing a validated source-VM
   target envelope so the eventual host forwarder can address the destination
   VM without changing the transferred delivery ID. It does not publish a
   spool or send a frame. The handoff-control fixture checks refusal while
   reserved, exact bare bytes after a synthetic claim, and refusal with a
   damaged HSA1. All 40 sanitized daemon suites pass under
   `claimed-replay-envelope-native/`; development `-j16 buildworld` passes
   for amd64, arm64/aarch64, and riscv/riscv64 in the
   `claimed-replay-envelope-*-buildworld.log` files. Production foreign
   claim, invocation of exact replay, and nonempty restore remain fenced.
   A claimed HTD5 can now be queued for its exact attested destination
   forwarder. The host job re-reads HJB1 at send time, verifies the bare ELF
   digest and forwarder identity, retains the imported delivery ID, sends
   the normal SHA-framed ELF without publishing a watcher-visible spool, and
   advances only that HTD5 through a dedicated ACK transition. An ACK retry
   is idempotent; reserved tickets and damaged HSA1 proof cannot send or
   accept. The rootless handoff-control fixture covers a source-VM target
   envelope, synthetic destination claim, frame bytes and identity, guest
   queue ACK, and the single accepted imported receipt. All 40 sanitized
   daemon suites pass under `claimed-replay-send-final-native-2/`;
   development `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `claimed-replay-send-final-*-buildworld.log`.
   Production HJB1-backed claim, transaction activation, and nonempty bhyve
   restore still need to invoke and recover this path.
   HJM1 HANDOFF_IMPORT now returns a prepared-import ACK after HJR1 has
   fsynced every mapped outbound pending HTD5 and, when nested ingress is
   present, HTB1, mapped inbound pending receipts, verified destination
   spools, and exact consumer-owner sidecars are durable. An absent consumer
   still returns `EBUSY`; a changed image or source proof still returns
   `EPROTO`. Exact ACK retries and CANCEL rollback are covered by the
   handoff-control and combined host-ingress fixtures. The ACK permits bhyve
   to proceed to its still-fenced mutation request; it grants no execution
   lease and cannot release a vCPU. All 40 sanitized daemon suites pass under
   `hjm1-prepared-ack-native/`; development `-j16 buildworld` passes for
   amd64, arm64/aarch64, and riscv/riscv64 in
   `hjm1-prepared-ack-*-buildworld.log`.
   After an attested destination forwarder registers, the control daemon now
   scans its durable pending imported HTD5 receipts and queues exact HJB1
   replay only for a claimed ticket and matching session, owner, VM, and
   epoch. A restart or lost guest queue ACK can therefore rediscover that
   pending work. Repeated admission on the same connection keeps one queued
   job per exact receipt; a changed record with the same delivery identity
   fails closed. The handoff-control fixture covers repeated recovery before
   send and an empty recovery scan after the imported receipt is accepted.
   All 40 sanitized daemon suites pass under
   `claimed-replay-admission-native/`; development `-j16 buildworld` passes
   for amd64, arm64/aarch64, and riscv/riscv64 in
   `claimed-replay-admission-*-buildworld.log`. The fixture reaches claim
   synthetically: production mutation, claim, and nonempty bhyve restore
   remain fenced until saved queue binding and the execution lease form one
   recoverable transaction.
   Protocol 58 gives HANDOFF_BIND_DELIVERY a separate 128-byte request with
   the saved ELF's SHA-256 digest; read-only HANDOFF_DELIVERY retains its
   96-byte wire. Bhyve hashes each complete saved ELF run and sends that
   digest during the paused prestart bind. For a claimed HJB1/HJR1 import,
   the daemon checks the exact destination owner and HTD5, source release,
   transferred ELF bytes, revocation state, and supplied digest before
   advancing that imported receipt from pending to accepted. A changed
   digest leaves it pending; an exact retry of an accepted bind succeeds.
   The source-journal, protocol, handoff-control, bhyve socket, and device
   fixtures cover these boundaries. All 40 sanitized daemon suites and 96
   native port suites pass under `bind-digest-native/` and
   `bind-digest-native-port/`; development `-j16 buildworld` passes for
   amd64, arm64/aarch64, and riscv/riscv64 in
   `bind-digest-*-buildworld.log`. Nested-ingress mutation/claim and nonempty
   restore remain fenced while saved-queue publication and imported receipt
   recovery are made one transaction.
   A journal-only foreign HSA1 ticket with a complete HJB1/HJR1 import and
   exact pending HTD5 receipts can now cross durable MUTATE and CLAIM through
   the production daemon phase handlers. Each phase and exact retry rechecks
   the pinned source release, imported plan, ready witness, and destination
   receipt mapping. Advancing an imported receipt to accepted before CLAIM
   refuses the transition; a nested host-ingress import still refuses MUTATE
   with `EOPNOTSUPP`. The handoff-control, source-journal, and combined
   host-ingress fixtures cover these boundaries, and all 40 sanitized daemon
   suites pass under `journal-phase-hardened-native/`. The production bhyve
   restore still refuses every nonempty transfer before reservation; journal
   promotion is addressed below, while saved-queue publication recovery and
   execution activation remain before that fence can open.
   Imported saved HTD5 binding now checks the complete claimed lineage before
   durably advancing a pending receipt to accepted. The later status check
   remains an exact retry check, but a broken ancestor no longer leaves an
   accepted receipt after a refused first bind. `PROMOTE_IMPORT` now recognizes
   a journal-only claimed HJB1/HJR1 import when no host-ingress stage exists:
   it rechecks the signed source cut, exact destination owner, imported
   receipts, and durable ready witness. Wrong ownership fails, repeated
   promotion succeeds, and pending replay receipts stay pending. The
   handoff-control fixture exercises the real handler; all 40 sanitized
   daemon suites pass under `journal-promotion-native/`. Development
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64
   in `journal-promotion-*-buildworld.log`. This is an
   idempotent promotion check, not an execution lease; nonempty bhyve restore
   and replay completion still remain fenced.
   After the exact REKEY_APPLIED record is durable, ACTIVATE_IMPORT now also
   recognizes a claimed journal-only transfer. It reuses the source-journal
   owner and ready-witness checks and grants no host-ingress program
   activation. The foreign handoff-control fixture rejects activation before
   REKEY_APPLIED, then accepts exact retries after a replayed HTD5 is
   accepted. All 40 sanitized daemon suites pass under
   `journal-activation-native/`, and development `-j16 buildworld` passes
   for amd64, arm64/aarch64, and riscv/riscv64 in
   `journal-activation-*-buildworld.log`. The outer nonempty restore fence
   remains closed while replay readiness and recoverable queue publication
   are addressed below.
   Protocol 59 adds a ticket-bound REPLAY_READY query after destination
   connector admission. The daemon rechecks the claimed journal-only HJB1,
   signed release, owner, ready witness, and every mapped HTD5; it refuses
   readiness while any nonrevoked imported delivery remains pending. Bhyve
   retries a pending reply for a bounded interval after paused ticket/queue
   publication and device resume, but before releasing any guest vCPU. The
   paused VirtIO-DTrace reader cannot accept replay ELF work, so the wait
   must occur after resume while the startup fence still holds.
   Accepted, installed, and terminal receipts satisfy this queue-cut check;
   an exact empty transfer remains an immediate no-op. The foreign control
   fixture covers pending refusal and accepted retries, and the bhyve socket
   fixture covers a NAK followed by a successful retry. All 40 sanitized
   daemon suites pass under `replay-drain-native/`, and all 96 native port
   suites pass under `replay-drain-resume-native-port/`. Development
   `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64
   in `replay-drain-resume-*-buildworld.log`. This barrier does
   not make a failed claimed restore recoverable across a new VM incarnation,
   so the outer nonempty restore fence remains closed. The source cut now
   counts ELF chunks and queued KILL/CLEANUP controls in the authenticated
   journal, adds the paused device queue, and reserves NODE_REKEY plus two
   control slots before PREPARE. It fails with ENOBUFS before source release
   if replay would fill the queue. This intentionally counts saved controls twice when
   they also appear in the journal, so it can refuse some otherwise viable
   checkpoints. A failed claimed restore still needs recovery across a new
   VM incarnation.
   The destination now independently parses the private device image and
   bounds its planned queue plus HJX1 replay before MUTATE. The outer
   nonempty restore fence still makes this path unreachable in production.
   The device now reserves a separate bounded queue allowance for all
   `DTRACED_REPLAY_KILL_MAX` admission KILLs, which can arrive after that
   read-only bound. Ordinary ELF and live controls retain the original 64 MiB
   queue limit, while two total slots remain for guest-applied receipts.
   A new source checkpoint waits until the extra restored-KILL allowance
   drains. The sanitized device fixture checks boundary arithmetic, KILL
   accounting, and receipt behavior at the expanded total limit. All 96
   native port suites pass under `restore-kill-reserve-native-port/`; the
   focused device suite also passes after the final queue-accounting audit.
   A current-source world build for this queue change is still pending.
   The bounded replay timeout remains fail-closed and cannot substitute for
   a recoverable destination transaction. All 40 sanitized daemon suites pass
   under `replay-budget-native-daemon/`, and all 96 native port suites pass
   under `destination-budget-final-native-port/`. Development `-j16 buildworld` passes for
   amd64, arm64/aarch64, and riscv/riscv64 in the
   `destination-budget-*-buildworld.log` files under the validation root.
   Source PREPARE now rebuilds the complete HTX1 member, including HJX1,
   under the handoff locks before comparing its digest with the exported
   ticket. A journal-only transfer therefore fails the explicit nonempty
   restore fence with `EOPNOTSUPP` after an exact digest match; a changed
   journal fails with `EPROTO`. The source-journal-wire fixture also rejects
   a formerly valid empty-transfer ticket after a journal entry is added;
   it and the handoff-control fixture pass this boundary. The amd64
   development `-j16 buildworld` passes in
   `full-source-digest-amd64-buildworld.log`. The most recent full sanitized
   daemon run passed 39 of 40 suites; `host-ingress` hit its 15-second alarm while
   blocked in ZFS `fsync` on `/tmp`. A previously passing binary from
   `replay-budget-native-daemon/` reproduces that timeout under the current
   competing world-build load, so this change does not yet have a clean
   full-daemon result.
   The HJX1 replay budget parser now rejects malformed or unordered KILL
   records and malformed or unordered CLEANUP records before using their
   count for restore planning. A focused sanitized source-journal fixture
   covers rehashed malformed records, and the C transfer-wire fixture passes.
   Version-1 HELLO and
   CAPS_ACCEPT now reject capability bits outside their defined set before
   negotiation, so an unknown HyperTrace claim cannot be silently accepted.
   The current source sends RELEASE before its defunct callback destroys the
   source VM; a HyperTrace destination also needs a durable source-release
   witness before it may run. That ordering must become a recoverable
   handoff transaction, not merely a new frame type. All 32 rootless
   migration session cases pass under `migration-capability-final/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `migration-capability-final-*-buildworld.log` under the
   validation root.
   The existing in-memory device
   blob now rejects unrepresentable member and frame lengths before allocating
   or publishing it. It also stays private until the kernel snapshot session
   releases successfully, so a failed source cut cannot expose the blob to
   migration. Production source and destination entry points now reject a
   HyperTrace VM before pre-copy or destination RAM staging. The deeper blob
   and restore guards remain as backstops. The blob still has no HyperTrace
   ticket, so this is a safe refusal, not migration support. Current-source
   16-job development world builds passed on amd64, arm64/aarch64, and
   riscv/riscv64 in the `migration-early-reject-*-buildworld.log` files.
   The migration frame-header decoder now publishes its output only after
   magic, version, type, flags, and payload-length checks pass. Malformed
   input leaves the prior caller header intact. All 28 rootless migration
   session cases pass under
   `/usr/obj/5BSD-hypertrace-validation/migration-atomic-obj/`; current-source
   `-j16` development world builds passed for amd64, arm64/aarch64, and
   riscv/riscv64 in the `migration-atomic-*-buildworld.log` files under the
   same validation root. This hardens the existing transport but does not
   add the missing HyperTrace ticket or enable live migration.
   The frame receive path now publishes its decoded header only after the
   complete payload passes CRC and sequence checks; a rejected frame leaves
   the prior caller header intact. Both send and receive reject exhaustion
   of the 32-bit sequence space instead of wrapping to zero. All 28 rootless
   migration session cases pass under
   `/usr/obj/5BSD-hypertrace-validation/migration-frame-atomic-*.result`;
   current-source 16-job development world builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `migration-frame-atomic-*-buildworld.log` files under that validation
   root. This does not lift the HyperTrace migration refusal.
   The destination now tracks an in-progress chunked memory generation.
   It refuses a transition to device state, an unchunked continuation, or
   a changed generation identity before the final memory chunk. Streaming
   chunks must use the zero-total form and make progress until their final
   marker. The new rootless fixture exercises the truncated and changed
   sequences; all 29 migration session cases pass under
   `/usr/obj/5BSD-hypertrace-validation/migration-generation-all/`.
   Current-source 16-job development world builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `migration-memory-fence-*-buildworld.log` files under the validation root.
   These checks protect the existing migration protocol; HyperTrace source
   and destination still reject live migration until ticket and journal
   transfer is implemented.
   The source now rejects a pre-copy callback count beyond its fixed scratch
   capacity before moving bytes, and refuses an empty non-final chunk that
   could keep its send loop running without progress. It also checks dirty
   page and stream-offset arithmetic before accumulation. The rootless
   callback fixture and all 30 migration session cases pass under
   `/usr/obj/5BSD-hypertrace-validation/migration-source-contract-all/`;
   current-source 16-job development world builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `migration-source-contract-*-buildworld.log` files under the validation
   root. The HyperTrace migration entry-point refusal remains in force.
   The topology codec and pre-quiesce comparison now reject a memory total
   inconsistent with lowmem plus highmem, including a wrapped 64-bit sum.
   Decode leaves the caller's prior topology intact on either failure. All
   30 rootless migration session cases pass under
   `/usr/obj/5BSD-hypertrace-validation/topology-memory-all/`; current-source
   `-j16` development world builds pass for amd64, arm64/aarch64, and
   riscv/riscv64 in the `topology-memory-*-buildworld.log` files under the
   validation root. The live HyperTrace migration refusal remains in force.
   HELLO and CAPS_ACCEPT decoding now requires zero reserved bytes. The
   source also rejects an accepted capability set that lacks pre-copy,
   contains unknown bits, or claims a capability it did not offer. A focused
   rejection case and all 31 rootless migration session cases pass under
   `/usr/obj/5BSD-hypertrace-validation/migration-caps-all/`; current-source
   `-j16` development world builds pass for amd64, arm64/aarch64, and
   riscv/riscv64 in the `migration-caps-*-buildworld.log` files. These
   handshake checks do not lift the live HyperTrace migration refusal.
   The source now rejects a pre-copy round limit that would wrap its
   32-bit loop counter or final stop-and-copy round. The bhyve control
   command checks the full 64-bit requested value before narrowing it;
   invalid requests leave the source runnable and never start a handshake.
   All 32 rootless migration cases pass under
   `/usr/obj/5BSD-hypertrace-validation/migration-round-limit-all/`, and
   current-source `-j16` development world builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `migration-round-limit-*-buildworld.log` files.
   The production `HANDOFF_EXPORT` handler now returns the same bounded,
   ticket-bound HTX1 built from both ingress and the source HJX1 journal cut.
   The attested fixture checks that a queued CLEANUP appears in the exported
   bytes and that a clean VM still receives an empty transfer. Source COMMIT
   rebuilds that exact cut under the handoff lock and refuses publication if
   a KILL or other journal change invalidates the PREPARE digest. The
   source-journal fixture covers an applied KILL between PREPARE and COMMIT.
   All 40 sanitized daemon component suites pass under
   `journal-export-complete-native-daemon/`; current-source `-j16 buildworld`
   passes for amd64, arm64/aarch64, and riscv/riscv64 in the
   `journal-export-*-buildworld.log` files under the validation root. This
   connects export and closes the identified COMMIT race; source PREPARE and
   bhyve restore still fence nonempty state until destination import and its
   execution lease are complete.
7. **Checkpoint-copy semantics:** Running-source copies are rejected. Define
   distinct source and clone tickets, lifetimes, and revocation ownership.
8. **Cross-host packet provenance:** V2 sidecar tests pass. Host-origin IDs
   now have a disjoint per-boot namespace, guest epochs cannot bypass
   revocation by colliding with the host epoch, and TAP preserves explicit
   empty guest IDs through forwarding. V1-tagged packets crossing into V2
   remain unknown rather than becoming host-origin. VirtIO-net also preserves
   an empty V2 record across guest receive and retransmit. The 49 native port
   suites cover the source-extracted TAP and VirtIO-net decisions. A paused
   source checkpoint now inspects every allocated TX ring, including packed
   and multiqueue rings, and returns EBUSY for queued V2 descriptors. The
   checkpoint-specific ring reader bypasses the normal runtime readiness
   check, which reports empty during checkpoint pause, and treats an
   unreadable or malformed ring as an error. The source-extracted sanitized
   fixture checks drained, queued, and unreadable TX rings; the amd64 -j16
   world builds passed in packet-v2-checkpoint-amd64-buildworld.log and,
   with the restore-side check, guest-regs-amd64-buildworld.log. During a
   real restore, after guest memory and the common VirtIO queue
   state are installed but before backend publication, the same reader
   rejects queued saved V2 descriptors. Preflight cannot inspect ring bytes
   before guest memory is installed. The updated VirtIO-net harness passes
   its private packet-ID snapshot and atomic restore cases, including the
   version-2 compatibility image. Validate provenance transfer, epoch
   retirement, and packet fate across actual host migration and device
   resets. Live proof of the drain boundary and handling of packets outside
   the device queues remain open.
   The save callback also refuses a V2 checkpoint while a TAP backend holds
   a peeked receive record in its private bounce buffer. That record is not
   part of the saved device state; returning EBUSY avoids silently dropping
   it at the cut. The source-extracted checkpoint fixture tests the empty and
   occupied bounce-buffer cases. The bounce-buffer guard alone did not
   inspect packets still queued in the kernel TAP backend.
   The TAP checkpoint check now uses `TAPGV2RXQUEUED` and refuses a
   currently queued kernel packet or a failed queue query. The ioctl reports
   boolean queue occupancy under the queue lock and requires an active V2
   freeze, so a zero-length queued mbuf cannot appear empty. The source-
   extracted fixture covers occupied, empty, and failed queries. The source
   freezes V2 TAP ingress during checkpoint pause.
   The kernel waits for admitted `tap_transmit()` calls to finish before the
   pause succeeds; later enqueues fail until resume or close. The snapshot
   check therefore observes a stable TAP queue cut. Pause failures unwind
   without leaving the TX worker paused. A failed thaw keeps the device
   paused, and a later PCI resume retry reacquires its locks before thawing.
   A concurrent thaw or second freeze now fails while the first freeze waits
   for an admitted enqueue; neither can make that waiting call report a false
   successful cut. The sole TAP queue enqueue path uses `tap_transmit()`.
   The concurrent source-extracted TAP fixture covers an in-flight enqueue,
   competing freeze/thaw, rejection while frozen, and thaw; the VirtIO-net
   ATF case covers failed
   freeze and failed-then-retried thaw. The TAP ioctl now returns its actual
   error instead of silently returning success for failed V2 binding or
   tagging operations. Packet fate through other network backends, device
   reset, and actual host migration still need live qualification.
   V2 backend negotiation now requires both checkpoint receive hooks as well
   as the tagging callback. TAP and its vmnet clone supply the hooks; ngd
   cannot advertise V2. The source-extracted capability fixture exercises
   each missing-hook refusal. This prevents a backend from enabling V2 and
   discovering only at checkpoint time that it has no stable receive cut;
   it does not establish packet fate across a live host migration.
   All 92 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/v2-backend-contract-native-port-final/`;
   the `-j16` amd64 development world build passes in
   `v2-backend-contract-amd64-buildworld.log` under the validation root.
   All 83 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/packet-v2-freeze-final-native-port/`;
   the `snapshot_v2_rx_freeze_retry` ATF case passes against the final
   amd64 world build, and current-source
   `-j16` development world and GENERIC kernel builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the `packet-v2-freeze-final-*` logs
   under the validation root.
   After the competing freeze/thaw guard, all 83 native port suites pass
   under `packet-v2-freeze-race-native-port/`, and current-source `-j16`
   GENERIC kernel builds pass for those same three architectures in the
   `packet-v2-freeze-race-*-buildkernel.log` files. The world builds above
   cover the unchanged userland sources.
   The concurrent freeze fixture now synchronizes on the kernel wait point
   instead of assuming the sender and freezer are scheduled within a fixed
   yield count. It passes again in the later 84-suite native run below.
   All 82 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/packet-v2-kernel-queue-native-port/`.
   Current-source `-j16` development world and GENERIC kernel builds pass
   for amd64, arm64/aarch64, and riscv/riscv64 in the
   `packet-v2-kernel-queue-*-buildworld.log` and
   `packet-v2-kernel-queue-*-buildkernel.log` files under that root.
   All 81 native port suites passed under
   `/usr/obj/5BSD-hypertrace-validation/backend-bounce-native-port/`, and
   current-source `-j16` development world builds passed for amd64,
   arm64/aarch64, and riscv/riscv64 in the `backend-bounce-*-buildworld.log`
   files under that validation root.
   TAP now exposes `netbe:tap-recv-v2` and `netbe:tap-send-v2` probes with the
   complete V2 identifier (including epoch and stamp), alongside the existing
   V1-prefix probes. They require the full V2 identifier to be present in
   the bytes read or passed to a send attempt; they do not imply successful
   external delivery.
   The source-extracted scatter/gather probe fixture and all 81 native port
   suites passed under `/usr/obj/5BSD-hypertrace-validation/v2-tap-probes-native-port/`.
   Current-source `-j16` development world builds passed for amd64,
   arm64/aarch64, and riscv/riscv64 in the `v2-tap-probes-*-buildworld.log`
   files under that validation root.
   The V2 identifier extraction is guarded by the generated probe-enabled
   symbol, so disabled V2 probes do not add a 48-byte copy to every tagged
   packet. The source-extracted fixture checks enabled and disabled probes,
   and all 81 native port suites passed under
   `/usr/obj/5BSD-hypertrace-validation/v2-tap-enabled-native-port/`;
   current-source `-j16` development world builds passed for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `v2-tap-enabled-*-buildworld.log` files under that validation root.
   Both V1 and V2 TAP probes now skip identifier extraction when disabled.
   The no-DTrace TAP object compiles without unresolved DTrace symbols.
   An earlier `WITHOUT_DTRACE=yes` world build found that `libtracecmp`
   was still selected after its DTrace headers were omitted. The library,
   BSDTrace and dtraced daemons, control tools, and their packages and tests
   now follow `MK_DTRACE`. A full amd64 `WITHOUT_DTRACE=yes` world build
   passes in `no-dtrace-final-amd64-buildworld.log`; an enabled amd64 world
   build passes in `dtrace-enabled-selection-amd64-buildworld.log` and
   includes those components. Both logs are under
   `/usr/obj/5BSD-hypertrace-validation/`.
   The final source-extracted probe fixture and all 81 native port suites
   passed under
   `/usr/obj/5BSD-hypertrace-validation/tap-all-probe-guards-native-port/`.
   Current-source `-j16` development world builds passed for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `tap-all-probe-guards-*-buildworld.log` files under that validation root.
   VirtIO-net now stops a receive callback when a malformed backend record
   cannot be discarded or a record advertised by peek cannot be read.
   A disappeared or signal-interrupted record yields to the event loop; a
   persistent backend I/O error disables receive and requests a device reset.
   The receive-length harness covers zero, transient, and permanent failures
   for both malformed record classes and ordinary record reads. This prevents
   a malformed packet from spinning through the callback budget without
   progress.
   The focused `receive_length_bounds` case and related receive/packet-ID
   cases passed. Current-source 16-job development world builds passed for
   amd64, arm64/aarch64, and riscv/riscv64 in the
   `packet-backend-final-*-buildworld.log` files under
   `/usr/obj/5BSD-hypertrace-validation/`.
9. **Guest DTrace semantics and verifier:** Some guest memory operations,
   CTF mapping, virtual probe enable, and a DIF
   transformation verifier remain incomplete.
   An enabling that matched probes from different VMs previously attached
   the second ECB before checking its VM ID, then tried to destroy an
   attached ECB. The VM-ID check now runs before ECB creation or guest
   probe enable. All 97 native port suites pass under
   `vmid-precheck-native-port/`; current-source `-j16` GENERIC kernel builds
   pass on amd64, arm64/aarch64, and riscv/riscv64 in the matching
   `vmid-precheck-*-buildkernel.log` files under the validation root. This
   does not qualify guest execution in a live VM.
   Virtual-probe enable now checks the HyperTrace backend before attaching
   the first ECB, propagates a missing hook or positive/negative backend
   error to the enabling caller, and destroys the unattached ECB on failure.
   The source-extracted `vprobe-enable` regression checks failure without
   attachment, success, a second ECB, and the native provider path. All 98
   native port suites pass under `vprobe-enable-native-port/`; current-source
   `-j16` GENERIC kernel builds pass on amd64, arm64/aarch64, and
   riscv/riscv64 in the matching `vprobe-enable-*-buildkernel.log` files.
   This is component validation; live guest virtual-probe enable remains
   unqualified.
   A mixed-VM enabling now reports `EXDEV` before creating or enabling an
   ECB for the second VM, rather than silently retaining the first VM's
   partial result. The ENABLE ioctl's existing failure rollback removes its
   earlier ECBs. The source-extracted `vprobe-match` callback and
   `enable-ioctl` rollback fixtures pass; all 99 native port suites pass
   under `vprobe-match-native-port/`. Current-source `-j16` GENERIC kernel
   builds pass on amd64, arm64/aarch64, and riscv/riscv64 in the matching
   `vprobe-match-*-buildkernel.log` files. This does not lift the nonempty
   HyperTrace restore fence or establish live guest qualification.
   The returned guest ELF's enabled-probe list now requires strictly
   increasing probe IDs, matching the kernel's `dtrace_enabling_list()`
   output. Duplicate or reordered IDs cannot reach virtual-probe creation;
   a valid two-probe list still verifies. The matching-world
   `vprog-transform` regression passes under `vprog-eprobes-transform/`,
   and current-source `-j16 buildworld` passes for amd64, arm64/aarch64,
   and riscv/riscv64 in `vprog-eprobes-*-buildworld.log` under the validation
   root. This is verifier validation, not live guest execution.
   The DIF verifier's LDGA/LDTA array-range check used impossible
   lower-than-minimum and greater-than-maximum conjunctions, so it accepted
   IDs in the gaps between native, guest, and host array ranges. The host
   array maximum was also below its minimum. The corrected bounds reject
   those gaps and retain the reserved guest/host ranges; a source-extracted
   sanitized fixture checks both opcodes, range edges, and register bounds.
   All 97 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/dif-array-verifier-native-port/`.
   Current-source `-j16` GENERIC kernel builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `dif-array-verifier-*-buildkernel.log` files; `-j16` development world
   builds pass for the same architectures in the matching
   `dif-array-verifier-*-buildworld.log` files under the validation root.
   `DTRACEIOC_ENABLE` now checks the actual matched-description count against
   the caller's buffer before retaining the enabling, returning `E2BIG` for
   a short buffer. Its description-list allocation and free sizes use
   `size_t` and the allocation's byte count. Libdtrace independently rejects
   a negative or over-capacity count from an older driver, cleans up the DOF
   and description buffer on errors, and reports allocation failure instead
   of asserting. The source-extracted `enable-boundary.py` regression covers
   oversized and negative counts, ioctl and allocation failures, a normal
   description, and replacement with an empty result. This closes the
   userland overread and prevents a short-buffer enabling from being retained.
   Failed enables now roll back only the ECB IDs created by that match while
   both DTrace locks are held, before destroying the enabling; pre-existing
   ECBs remain attached. The source-extracted `enable-rollback.py` and
   `enable-ioctl.py` fixtures exercise sparse IDs, buffer exhaustion,
   matching, listing, and retain failures, plus a successful enable.
   Both fixtures pass under AddressSanitizer and UndefinedBehaviorSanitizer;
   current-source GENERIC kernel builds pass for amd64, arm64/aarch64, and
   riscv/riscv64 in `enable-rollback-*-buildkernel.log` under the validation
   object root (amd64's final log includes `-final`).
   The matched-description list now counts occupied probe slots before
   allocating its output array. A sparse VM probe namespace therefore
   allocates one description per actual match instead of one per registered
   slot. The source-extracted sanitized `enable-sparse-list.py` fixture covers
   a 100,000-slot/two-match table, host and guest providers, malformed names,
   allocation failure, and an empty table. Current-source GENERIC kernel
   builds pass for amd64, arm64/aarch64, and riscv/riscv64 in
   `enable-sparse-*-buildkernel.log` under the validation object root.
   A post-retain probe-list `copyout` now holds the enabling in a pending
   state. GO and another ENABLE on the same state refuse that interval,
   while global rematching skips the pending enabling. On a failed copyout
   or late rematch, the ioctl rolls back only its original and late ECB
   ranges, removes the retained enabling, and clears the pending state;
   unrelated ECBs allocated during the unlocked copyout survive. A
   successful copyout catches up probe generations before releasing the
   state. The source-extracted sanitized ioctl fixture injects a failed
   copyout, an interleaved ECB, a concurrent ENABLE, and a failed late match.
   The four focused source-extracted sanitizer fixtures pass, and
   current-source 16-job GENERIC builds pass for amd64, arm64/aarch64,
   and riscv/riscv64 in `enable-copyout-final-*-buildkernel.log` under
   `/usr/obj/5BSD-hypertrace-validation/`. The amd64 development world
   build passes in `enable-copyout-amd64-buildworld.log`. Live guest
   enablement still needs matched-host testing.
   The auxiliary `DTRACEIOC_AUGMENT` and `dtrace_go()` enable paths also
   destroy their DOF and set the libdtrace memory error on description-buffer
   allocation failure. The AddressSanitizer/UndefinedBehaviorSanitizer
   boundary fixture and built-library virtual-program regression pass.
   Development `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64; GENERIC kernel builds pass for the same three targets.
   Logs are `enable-bounds-*-buildworld.log` and
   `enable-bounds-*-buildkernel.log` under
   `/usr/obj/5BSD-hypertrace-validation/`; the final-source world logs
   and the amd64 kernel log include `-final`.
   Guest CTF member relocation now preserves the complete byte offset in
   the DIF integer table instead of wrapping at 64 KiB. It rejects a member
   offset that is not byte aligned, an integer-table index that cannot fit
   the 16-bit SETX operand, and integer bitfield encodings that a byte load
   cannot extract correctly. Failed or unrepresentable CTF sizes now stop
   linking before conversion to the 32-bit return size or rewriting a return
   load. The `ctf-linker-bounds.py` fixture calls the actual built libdtrace
   relocation method and covers a member beyond 64 KiB, an unaligned member,
   a missing typefile, and integer-table index exhaustion. The focused
   fixture, the virtual-program verifier fixture, and the built-library ELF
   suite pass under `ctf-linker-*` validation directories. Full bitfield
   extraction, broader CTF equivalence, and live guest execution remain open.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `ctf-linker-verified-*-buildworld.log` under the same
   validation root.
   Bit-field members of linker-resolved types are now extracted instead of
   refused: the compiler follows the member load with an identity
   extraction (`setx 0; sll; setx 0; srl|sra`), and the linker chooses the
   smallest naturally aligned load of 1, 2, 4 or 8 bytes holding the field,
   the member address and the shift counts from the CTF it links against.
   A bit-field load without that extraction, a field no such load holds,
   and a bit-field address used other than by its load stay refused. The
   linker's usetx-consumer, register/variable reaching-definition and
   tuple-stack walks now visit each basic block once (per entry state)
   instead of once per control-flow path; the per-path walks took time
   exponential in the branches a value lived across, so
   `tcp_state_string[args[3]->tcps_state]` and a clause assigning
   `tcpsinfo_t` never finished linking (dtrace(1) and bsdinstruments spun).
   The pushes that reach a tuple-stack consumer now form one stack. A member
   of an embedded structure (`p->t_inpcb.inp_inc`, tcp.d's `tcps_lport`)
   is typed and relocated with its own member information: the type
   checker looked it up in the type the embedded structure "references"
   (and failed), and, once found, the usetx was relocated to the enclosing
   member's offset. The
   `typing-bitfield.cc` harness in `typing-inference.py` executes linked
   programs against the C++ compiler's layout of a ctfconvert fixture and
   bounds the link time of the tcp.d shapes; evidence is under
   `/usr/obj/5BSD-otel-validation/ctf-*`. The front end's own bit-field
   code for types in the D container (`dt_cg_load()`, `dt_cg_field_get()`,
   `dt_cg_field_set()`) still loads `clp2(bits)` bytes at the field's first
   byte, as upstream FreeBSD does, which misreads a field that crosses a
   byte boundary and can be misaligned; that path is unchanged.
   Member relocation now resolves an absent CTF member before reading its
   type; an absent typefile returns a linking error instead of dereferencing
   it. A member-free load fails closed while a member-free ADD stays
   unchanged, and formatting an empty or long
   diagnostic stays inside the string buffer. The built-libdtrace fixture
   covers these cases under `ctf-member-preflight-fixture/`; the virtual
   program transform and nine built-library ELF cases pass under
   `ctf-member-final-vprog/` and `ctf-member-final-elf/`. Development world
   results are in `ctf-member-final-*-buildworld.log` under the same object
   root.
   A lone `hvtimestamp` DIFO now enables host virtual-time accounting just
   as `vtimestamp` does. Hold and release count both variable IDs, so the
   host-prefixed variable cannot reach its kernel assertion with zero
   references. A source-extracted sanitized fixture covers a lone host
   reference, repeated holds, mixed host/guest references, and balanced
   release. The 84 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/guest-hvtime-final-native-port/`;
   current-source `-j16` GENERIC kernels pass for amd64, arm64/aarch64, and
   riscv/riscv64 in the `guest-hvtime-*-buildkernel.log` files. A DTrace
   runtime regression for `hvtimestamp` is staged for the matched host; it
   cannot run on this build host without `/dev/dtrace/dtrace`.
   Immediate-stack action sizing and per-CPU buffer allocation now share one
   checked product. Zero or oversized frame/string options return `EINVAL`
   before a truncated `int` allocation size can be published. The sanitized
   source-extracted boundary fixture covers valid limits, nonpositive values,
   and overflowing products. All 85 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/guest-immstack-final-native-port/`;
   current-source `-j16` GENERIC kernels pass for amd64, arm64/aarch64, and
   riscv/riscv64 in the `guest-immstack-*-buildkernel.log` files.
   USTACK/JSTACK action creation now reserves the PID slot and checks the
   combined frame and string size before rounding or narrowing the record to
   32 bits. It also refuses a JSTACK string option that would truncate when
   packed into the action argument. This prevents a guest stack record from
   being smaller than the bytes its bounded stack writer can clear and fill.
   The source-extracted ASan/UBSan size fixture covers valid limits, zero and
   negative inputs, frame overflow, and string overflow. All 94 native port
   suites pass under `guest-ustack-size-native-port/`; current-source `-j16`
   GENERIC kernels pass on amd64, arm64/aarch64, and riscv/riscv64 in the
   `guest-ustack-size-*-buildkernel.log` files under the validation root.
   Action admission now also applies the guest walker's 2,048-PC limit to
   virtual USTACK records. It accepts the last supported guest depth,
   refuses the next depth before enabling the action, and preserves the host
   action's independent size limit. The focused source-extracted fixture and
   all 94 native port suites pass under `guest-ustack-admission-native-port/`;
   current-source `-j16` GENERIC builds pass for amd64, arm64/aarch64, and
   riscv/riscv64 in `guest-ustack-admission-*-buildkernel.log` under the
   validation root.
   Kernel STACK action admission now bounds frame bytes before narrowing the
   record to 32 bits or passing an `int` frame limit to the unwinder. This
   closes an overflow that could allocate a smaller record than the requested
   frame count. The source-extracted ASan/UBSan boundary fixture and all 94
   native port suites pass under `guest-stack-size-native-port/` (focused
   fixture under `guest-stack-size/`); current-source `-j16` GENERIC builds
   pass on amd64, arm64/aarch64, and riscv/riscv64 in the
   `guest-stack-size-*-buildkernel.log` files under the validation root.
   Guest kernel `stack()` now has a bounded raw-PC path. The transformed DIF
   hypercall instruction requests at most 64 frames only for clauses that
   contain `stack()`; its resolved frame count is also retained in the host
   action. The guest captures PCs before the hypercall, and the paused VMM
   validates the pointer, count, alignment, and reserved word before the
   host copies from guest memory. Version 5 uses new probe call IDs on amd64,
   arm64, and riscv64 so shorter old argument blocks cannot enter this path.
   The action record tags guest frames with VMID. Libdtrace and
   `bsdinstruments watch` print their raw addresses rather than resolving
   them against host kernel symbols. Guest kernel symbol lookup and exact
   frame accuracy require matched guest/host qualification. Requests above
   64 frames fail admission instead of silently truncating.
   Source-extracted action and formatter fixtures cover valid guest PCs,
   short and malformed envelopes, an absent VM handle, independent host
   stack unwinding, and the guest-symbol lookup fence. The matching-world
   virtual-program fixture checks the generated capture count, default
   resolution, and rejection above 64 frames. All 96 native port suites
   pass under `guest-pcstack-final-native-port/`, and the matching transform
   fixture passes under `guest-pcstack-final-vprog/` in the validation root.
   Final-source `-j16 buildworld` and GENERIC `buildkernel` pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the `guest-pcstack-final-*-buildworld.log`
   and `guest-pcstack-final2-*-buildkernel.log` files there. The guest
   initializes only the requested PC slots before the unwind, so a short
   unwind cannot expose unrelated guest stack bytes and clauses without
   `stack()` avoid that initialization. These tests do
   not measure the guest unwind's probe-frame offset or qualify live VMM
   guest-page copying.
   A host-verified response can still fail guest forwarding generation, for
   example when its `stack()` request exceeds 64 frames. The consumer now
   rewinds the response's verifier DIFO references, destroys the rejected
   program, and returns a failed delivery instead of aborting. The rebuilt
   matching-world verifier fixture checks that rewinding removes rejected
   variable metadata before the next verification. All 96 native port suites
   pass under `transform-reject-native-port/`; the fixture passes under
   `transform-reject-final-vprog/`. Current-source `-j16 buildworld` passes for
   amd64, arm64/aarch64, and riscv/riscv64 in the
   `transform-reject-final-*-buildworld.log` files. The rejection path still needs
   a live consumer/guest delivery test.
   Guest ELF generation now treats temporary-file creation, ELF serialization,
   fsync, rewind, and a rejected unidentified asynchronous send as failed
   deliveries through the same pre-publication cleanup. It closes and unlinks
   partial files, destroys both parsed and generated programs, and rewinds
   verifier references. Identified sends still keep their exact derived result
   for reconnect and replay once publication may have started. The matching
   virtual-program fixture passes under `guest-generation-final-vprog/`;
   current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `guest-generation-final-*-buildworld.log`. These error
   paths still need fault-injected consumer and live guest qualification.
   The consumer now verifies a returned guest ELF against the exact guest
   forwarding program it sent before attaching it as the executable response.
   A missing forwarding program or a changed statement/action is rejected as
   a failed delivery while the accepted source entry remains intact. The
   built-library ELF fixture verifies the complete host-response then
   guest-forwarding sequence in one verifier context and rejects a guest
   response with a changed serialized action argument. Its parser, round-trip,
   and allocation cases pass under `guest-response-verifier-sequence-elf/`.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in `guest-response-verifier-*-buildworld.log`. Live guest
   response verification still needs a matched host/guest test.
   Program-level metadata is also bound. ELF parsing now retains its
   serialized resolver flags, and the program verifier requires the same
   DOF version, resolver flags, and execution mode as the sent program. The
   built-library ELF fixture confirms that a changed serialized resolver
   flag survives parsing and is rejected; the transform fixture rejects each
   changed metadata field. Both pass under `program-metadata-elf/` and
   `program-metadata-vprog/`. Current-source `-j16 buildworld` passes for
   amd64, arm64/aarch64, and riscv/riscv64 in
   `program-metadata-*-buildworld.log` under the validation root.
   The returned guest program's enabled-probe list is now checked before
   `DTRACEIOC_VPROBE_CREATE`. Every concrete provider/module/function/name
   must match a selector in the verified source program; missing list storage,
   zero or out-of-range IDs, empty provider/probe names, nonzero
   guest-reported VMIDs, unterminated names, and a list above the kernel's
   64K-per-VM probe limit are rejected. The check deliberately
   ignores the serialized target field because the attested VM identity, not
   that field, supplies virtual-probe ownership. The matching built-library
   transform fixture covers exact and wildcard matches, the maximum valid
   ID, and unrelated or malformed reports under `guest-eprobe-limits-vprog/`.
   The built-library ELF suite passes under `guest-eprobe-limits-elf/`;
   development `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `guest-eprobe-limits-*-buildworld.log` files.
   This prevents an unverified guest probe name from reaching virtual-probe
   creation, but does not replace matched live guest enablement testing.
   Ordinary scalar DIF loads on a virtual probe now reject an untagged
   host address unless it belongs to that program's DTrace scratch,
   variable storage, or string table. Tagged loads require the active
   guest VM handle and kernel tracing access. This prevents a guest
   program's SETX value from becoming a host kernel read while preserving
   DTrace-owned storage and host-probe loads. The sanitized
   `guest-restricted-load` fixture covers all seven scalar load widths,
   foreign tags, denied access, and permitted scratch reads; all 81 native
   port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/guest-host-load-guard-native-port/`.
   Current-source 16-job GENERIC kernel builds pass for amd64, arm64, and
   riscv64 in the `guest-host-load-guard-*-buildkernel.log` files under
   `/usr/obj/5BSD-hypertrace-validation/`. Live guest load semantics remain
   unqualified.
   Guest `args[index]` now returns zero without a VM pointer tag when the
   index exceeds the ten fields in the fixed HyperTrace argument envelope;
   valid indices retain their guest provenance. The guest-bound host state
   also bounds its five stack-argument cache slots before reading a provider
   argument, so an oversized index cannot overwrite that cache. The source-extracted
   address-sanitized boundary fixture and all 81 native port suites pass
   under `/usr/obj/5BSD-hypertrace-validation/guest-arg-bounds-final-native-port/`.
   Current-source `-j16` GENERIC kernel builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `guest-arg-bounds-final-*-buildkernel.log` files under that validation root.
   All seven DIF user-load opcodes
   now read guest user pages through a separate VMM callback. It enforces
   user page permissions, process privilege, and guest address provenance;
   loaded values retain the guest tag. Host probes continue to read their
   host process and reject a guest-tagged source. Guest BYUREF action capture
   and copyin/copyinto/copyinstr now use the guest user-page callback for
   tagged or untagged guest addresses, require process tracing privilege,
   and reject a foreign address-space tag. The source-extracted sanitized user-load
   fixture covers all seven opcode variants and both address spaces. Other
   guest user-memory operations still need complete semantics. DIF COPYS and
   STB/STH/STW/STX reject guest-tagged store destinations before a host-region
   check can mistake the numeric address for host scratch. The scalar stores
   also reject guest-tagged values because scratch has no pointer-provenance
   shadow; successful STX leaves its host destination register untagged. The
   source-extracted store fixture covers host stores, tagged guest sources and
   destinations, and guest-to-host scratch COPYS. Virtual `copyout()` and
   `copyoutstr()` now write through a bounded guest-user callback after
   destructive-action and process-control authorization. The amd64, arm64,
   and riscv64 VMM callbacks check guest user and write permissions at each
   translation; foreign destination tags fail before any write. The
   source-extracted copyout fixture covers host and guest sources, foreign
   and missing destinations, read/write faults, strings, and address overflow.
   All 75 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/guest-copyout-native-port/`; the
   current-source `-j16` GENERIC kernel and DTrace/VMM module builds pass
   for amd64, arm64/aarch64, and riscv/riscv64 in the
   `guest-copyout-*-buildkernel.log` files. A separate source-extracted
   fixture compiles each architecture's VMM write callback and checks guest
   user-mode selection, page-spanning writes, write-denied second pages,
   translation faults, unsupported paging modes, and address bounds. All 76
   native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/guest-write-pagewalk-native-port/`.
   The guest copyout helper also rejects a source tagged for another VM
   before its active-VM read callback can run, even if a caller skips the
   preceding load check. The sanitized fixture checks that neither guest
   reads nor writes occur in this case. All 82 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/guest-copyout-source-tag-native-port/`;
   current-source `-j16` GENERIC kernel/module builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the `guest-copyout-source-tag-*` logs
   under the validation root.
   These writes still require
   matched live-VM qualification. Virtual probes
   still fail with ILLOP rather than applying `stop`, `raise`, `panic`,
   `breakpoint`, or `chill` to the host process/CPU, or reporting
   host process ancestry, stacks, and symbols as guest state. Guest lock
   inspection also fails closed before a guest pointer can reach FreeBSD's
   host lock-class callbacks. The panic helper itself now rejects a virtual
   probe before claiming the global host panic slot. The source-extracted
   sanitized `guest-panic-action` case exercises guest rejection, host
   destructive-action policy, and host panic claim behavior. Virtual probes
   also bypass the host thread's predicate cache: a false guest predicate
   cannot suppress a later event with different guest context on the same
   bhyve thread. The source-extracted `guest-predicate-cache` case covers
   that scenario, a stale host cache entry, and unchanged host caching. All
   68 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/guest-predicate-full-port/`;
   current-source 16-job development kernel builds pass on amd64,
   arm64/aarch64, and riscv/riscv64 in the
   `guest-predicate-buildkernel-*.log` files. These are compile and
   component results, not live VM qualification.
   Guest `vtimestamp` now comes from the guest thread's virtual-time counter,
   introduced in the version-3 probe ABI and retained in version 5. The
   generated guest forwarding DIFO retains a local `vtimestamp` reference
   only when the source clause
   uses it, so guest context switches maintain that counter; the host never
   substitutes bhyve's thread time. The amd64 probe call number, arm64 HVC
   function ID, and RISC-V experimental extension ID advance with the larger
   envelope so an older caller cannot trigger a longer host copy. The
   matching-world transform fixture covers predicate and action references;
   the generated program also survives an ELF write/read and DOF creation.
   The matching library suite passes seven valid round trips and 79 malformed
   input rejections under `guest-vtime-elf-dof/`, and all 92 native port suites
   pass under `guest-vtime-native-port/` in the validation object root.
   Current-source `-j16` world and GENERIC kernel builds pass for amd64,
   arm64/aarch64, and riscv/riscv64 in the `guest-vtime-*-buildworld.log` and
   `guest-vtime-*-buildkernel.log` files; amd64's final world rebuild is in
   `guest-vtime-amd64-final-buildworld.log`. The version-4 probe ABI also
   carries guest `timestamp` from the probe's
   monotonic clock. A generated guest forwarding DIFO reads `walltimestamp`
   only if the source clause uses it; this sets a presence bit and captures
   the guest wall clock before the hypercall. A virtual host DIFO refuses a
   missing guest wall-clock value instead of substituting host time, while
   `htimestamp` and `hwalltimestamp` retain their host-clock meanings.
   The larger argument block has new amd64 and arm64 probe call numbers and a
   new RISC-V experimental extension ID; older IDs do not dispatch HyperTrace
   probes. The matching-world virtual-program fixture covers predicate,
   action, and combined clock references. The generated program survives ELF
   write/read and DOF creation in `guest-clock-elf-library/`; its suite also
   passes seven valid round trips and 79 malformed-input rejections. All 92
   native port suites pass under `guest-clock-native-port/`, and current-source
   `-j16` world and GENERIC kernel builds pass for amd64, arm64/aarch64, and
   riscv/riscv64 in the `guest-clock-*-buildworld.log` and
   `guest-clock-*-buildkernel.log` files under the validation object root.
   Live guest timing, migration-clock continuity, and other guest equivalents
   still need implementation or qualification. The verifier now rejects
   SLL/SRA/SETX-to-NOP substitutions and incompatible variable kind, CTF
   kind, and reference flags. A failed DIFO verification no longer changes
   metadata in an earlier accepted DIFO. The matching-world transform test
   passes with negative type cases and a failed-verification return-type
   nonmutation case. PUSHTV now preserves concrete CTF/string categories
   while allowing the existing bottom-to-CTF inference, with positive and
   negative transform cases. The ULOAD/UULOAD-to-NOP exception before RET now
   requires the load to feed that RET and identical nonzero host/guest
   by-reference return flags; the
   matching-world test covers accepted and rejected transformations. A
   nonzero source identifier no longer bypasses the entire program-shape
   verifier; unchanged programs pass and an added statement fails. The DIFO
   verifier now rejects undefined return-type kinds, unknown flag bits, and
   nonzero reserved padding while preserving defined return kinds. The ELF
   parser rejects those malformed return fields before CFG/type passes. The
   same kind, flag, and reserved-byte checks now cover variable types in
   both the verifier and ELF parser; the matching-world transform and ELF
   malformed-input suites pass. The ELF parser now checks each statement's
   self reference and each action's serialized statement reference. Shared
   actions remain valid when reachable through the first writer's action
   links; zero or unrelated statement references fail. Serialized printf
   descriptors now carry their conversion names through the ELF string table;
   the parser resolves them against its local conversion dictionary and
   rejects missing or unknown conversions, descriptor-count mismatches, and
   unknown format flags. The parser now also rejects unknown action kinds,
   action tuple counts that would truncate into the runtime's 32-bit field,
   tuple counts on non-aggregation actions, and non-Boolean return flags.
   The program verifier now checks that each action's user argument belongs
   to its statement. It validates DIFOs before changing variable sizes,
   removes newly seen DIFOs from a reused verifier context if a later
   statement fails, and publishes size, VM identity, and copied format data
   only after the whole program passes. Format duplication now retains its
   own prefix pointers and frees partial allocations on failure. The verifier
   now also matches statement stability attributes and aggregation identifier
   name, ID, kind, flags, version, and attributes. A verified guest statement
   uses the host aggregation identifier, including its compiler-private
   auxiliary data, rather than the incomplete identifier parsed from ELF.
   The verifier now proves each statement's action span reaches its declared
   last action without a cycle or a terminal back-edge. This closes a
   self-verification case where `last->next` pointed to the first action and
   skipped action comparison. The matching-world sanitized transform fixture
   rejects both loop forms and still accepts two statements sharing one ECB
   action chain. The updated amd64 libdtrace and arm64/aarch64 and
   riscv/riscv64 worlds pass under `vprog-action-span-*` in the validation
   object root. This is component evidence, not live guest execution.
   The ELF parser now applies the same terminal back-edge rule to serialized
   actions before publishing a parsed program. It permits a terminal link
   into a later statement of a shared ECB but rejects a link into any action
   in the current statement's span. The matching built-library suite covers
   both a one-action terminal self-loop and a multi-action aggregation
   back-edge, plus valid ELF round trips and allocation failures, under
   `elf-terminal-cycle-library/`. Current-source `-j16 buildworld` passes for
   amd64, arm64/aarch64, and riscv/riscv64 in
   `elf-terminal-cycle-*-buildworld.log` under the validation root.
   A parser precheck now verifies the complete serialized successor graph
   before allocating statements. For a reused ECB, each terminal action
   must point to the next statement's first action; the final statement for
   that ECB must have no successor. Missing, foreign, and dangling links
   fail instead of being discarded while rebuilding native action lists.
   The matching built-library suite passes valid shared-ECB round trips and
   71 malformed graph/table cases under `elf-successor-library/`.
   Current-source `-j16 buildworld` passes on amd64, arm64/aarch64, and
   riscv/riscv64 in `elf-successor-*-buildworld.log` under the validation root.
   A guest DIFO can no longer change a concrete host return kind or its
   by-reference flags while leaving the instructions unchanged. A concrete
   host CTF return now also requires the same CTF kind and byte size; a host
   bottom type still permits guest type inference. The matching-world
   `vprog-transform` regression passes with rejected kind, flag, CTF-kind,
   and CTF-size substitutions under
   `/usr/obj/5BSD-hypertrace-validation/ctf-rtype-vprog-final/`.
   The matching-world test also checks its libdtrace object dependency and
   build timestamps against this worktree. Its provenance-checked run passed
   under `/usr/obj/5BSD-hypertrace-validation/ctf-rtype-vprog-provenance/`.
   The 16-job amd64 development world build passed in
   `/usr/obj/5BSD-hypertrace-validation/ctf-rtype-buildworld-cleaned.log`.
   The transformed-DIFO verifier now bounds appended integer-table entries
   by the original USETX relocation count and requires every added index to
   be referenced by one of those relocations. This rejects unused injected
   constants while preserving reused and distinct legitimate SETX indices.
   The matching-world `vprog-transform` suite passes under
   `vprog-inttab-relocations/`; it covers unused, oversized, reused, and
   fully referenced appended tables. This does not yet prove that a guest
   selected the correct CTF member offset for every relocation.
   Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
   riscv/riscv64 in the `vprog-inttab-*-buildworld.log` files under the
   validation root.
   The DTrace receiver now destroys parsed programs rejected for duplicate
   delivery, VM identity conflict, or failed verification; rejected deliveries
   no longer accumulate unaccepted program graphs on the libdtrace handle.
   Guest `execargs` now copies through the VM handle, rejects zero or
   overflowing lengths, terminates the scratch string even when a guest
   supplies no final NUL, and does not publish scratch data after a fault.
   The source-extracted sanitized fixture checks a guest-only pointer,
   overflow, empty length, scratch exhaustion, and a failed copy. Guest
   `execname` and jail-name now copy through guest translation into host
   scratch space and return an untagged host pointer; `execargs` also returns
   its scratch pointer without a guest VM tag. The guest-string fixture checks
   provenance, truncation, scratch exhaustion, a faulted read, and a
   terminator changed between scan and copy. Guest
   immediate-stack printing now rejects a null pointer or negative length
   before its copy, preventing a guest-controlled signed length from turning
   into an unbounded host copy.
   Virtual probe dispatch now returns a failure for a missing probe, a stale
   VM epoch, or a disabled/suspended probe; amd64, Arm64, and RISC-V return
   that failure to their guest hypercall paths. A source-extracted sanitized
   fixture covers these decisions and verifies that the prior VM handle is
   restored after a successful probe firing. The source-extracted batch test
   also checks the guest-visible result after disablement and VM lifetime
   replacement. The native HyperTrace runner and 16-job amd64, arm64, and
   riscv64 GENERIC kernel builds pass with this result contract under
   `/usr/obj/5BSD-hypertrace-validation/probe-result-native/` and the
   `*-probe-result-buildkernel.log` files.
   The host VMM now sets `curcpu` from its vCPU ID on all three architectures,
   so a guest-supplied CPU number cannot mislabel the probe context. The amd64
   source-extracted call fixture checks that override.
   On a virtual probe, host-prefixed PID, parent PID, thread ID, credentials,
   errno, CPU, exec name/args, and jail name/ID now resolve to host state;
   their ordinary counterparts resolve to guest state. The previously absent
   `hjid` and `hjailname` interpreter cases are implemented. A sanitized
   source-extracted fixture checks these paired paths. The exec-argument copy
   helper now takes an explicit address-space handle, so `hexecargs` reads
   bhyve's host argument string while `execargs` reads guest memory.
   `hvmname` now reports the host rather than the guest VM name. The
   source-extracted fixture also distinguishes guest/host VM names and IDs.
   The compiler now maps `hhostid` to its host-specific DIF variable rather
   than the guest host-ID opcode; the fixture checks that mapping.
   Host-prefixed register, stack-depth, and caller variables now remain
   available on virtual probes. Guest `$regs[]` reads architectural values
   from the frozen vCPU through a guarded VMM callback on amd64, arm64, and
   riscv64; unsupported indices and backend failures raise ILLOP. The DIF
   register-to-VMM mapping passes source-extracted sanitized cases for all
   three architectures, and the variable-arm fixture verifies that guest
   registers never fall through to the host trapframe. Returned register
   values retain the guest VM tag, so a pointer-valued register cannot be
   dereferenced as a host address. Guest `$uregs[]` now reads the frozen
   guest thread's saved trapframe through the bounded guest-copy callback;
   matched guest/host layout and live behavior still require qualification.
   Guest stack-depth and caller variables now come from the guest's DIF
   interpreter in the versioned hypercall envelope. The host caller path
   does not pass a guest-supplied address to the host stack walker.
   Guest `memref()` now copies a tagged guest source into the current probe's
   scratch before returning its two-word reference. An untagged guest-probe
   source must already be published scratch. Guest `printm()` accepts only a
   reference and byte range inside that published scratch, then reads those
   bytes as host scratch. Its by-reference path uses that exact byte range,
   rather than the larger DIFO record bound, and clears any guest tag before
   copying; host `printm()` retains its normal load check. A late guest copy
   fault leaves the scratch cursor
   unchanged. Host `memref()` checks aligned scratch capacity before writing,
   `printm()` checks its record size without arithmetic overflow, and
   `memstr()` does not publish scratch output after a guest read fault. The
   updated source-extracted sanitized `guest-memref` fixture covers the guest
   copy through the by-reference action, host load-check retention, scratch
   reuse, foreign tag, forged reference, capacity, and late
   fault cases. All 74 native port suites pass under
   `/usr/obj/5BSD-hypertrace-validation/guest-printm-byref-port/`, and 16-job
   GENERIC kernel/module builds pass for amd64, arm64/aarch64, and
   riscv/riscv64 in the `guest-printm-byref-*-buildkernel.log` files. These
   are component and compile results; live guest memory behavior remains
   unqualified.
   Guest `toupper()` and `tolower()` now stop on faults during either the
   initial string scan or the later character copy, and leave scratch
   unpublished. Zero-length string options fail before their loop bounds
   underflow, and a wrapping pointer cannot read from address zero. The
   source-extracted sanitized `guest-casefold` fixture covers both conversions
   and faults in both passes. All 63 native port suites passed under
   `/usr/obj/5BSD-hypertrace-validation/guest-casefold-final-native-port/`;
   16-job GENERIC kernel and module builds passed on amd64, arm64/aarch64,
   and riscv/riscv64 in the `guest-casefold-*-buildkernel.log` files.
   Guest `json()` now reserves its output from the configured parse limit,
   leaving the selector in a disjoint scratch region even if the guest input
   changes after its length scan. Overflow and wrapping source ranges are
   rejected before pointer arithmetic; faults in either scan, selector copy,
   or parser do not publish a result. The source-extracted sanitized
   `guest-json-scratch` fixture exercises the full-limit write, scratch
   exhaustion, and late faults. All 64 native port suites passed under
   `/usr/obj/5BSD-hypertrace-validation/guest-json-final-native-port/`;
   16-job GENERIC kernel and module builds passed on amd64, arm64/aarch64,
   and riscv/riscv64 in the `guest-json-*-buildkernel.log` files.
   Guest `strjoin()` now checks each byte load before writing scratch or
   publishing a returned pointer. A fault in either input leaves the scratch
   cursor unchanged; the source-extracted sanitized `guest-strjoin` fixture
   covers both late-fault positions and capacity exhaustion. All 65 native
   port suites passed under
   `/usr/obj/5BSD-hypertrace-validation/guest-strjoin-fixed-native-port/`;
   16-job GENERIC kernel and module builds passed on amd64, arm64/aarch64,
   and riscv/riscv64 in the `guest-strjoin-*-buildkernel.log` files.
   The updated guest-register-map and guest-host-stack fixtures pass; all 47
   native port suites pass under guest-regs-final-native-port. The 16-job amd64,
   arm64, and riscv64 GENERIC kernel builds pass in the
   guest-regs-tag-*-buildkernel.log files under the validation object root.
   These do not establish live guest register behavior.
   The updated full native runner passed under
   `/usr/obj/5BSD-hypertrace-validation/host-stack-final/`, and the
   16-job amd64, arm64, and riscv64 GENERIC kernel builds passed in the
   `host-builtins-*-buildkernel.log` files.
   The matching amd64 development world rebuild passed in
   `/usr/obj/5BSD-hypertrace-validation/host-builtins-amd64-buildworld.log`.
   The updated full native runner passed under
   `/usr/obj/5BSD-hypertrace-validation/host-vmname-final/`.
   The full native runner passed under
   `/usr/obj/5BSD-hypertrace-validation/host-vars-native/`, and the final
   16-job amd64, arm64, and riscv64 GENERIC kernel builds passed in the
   `host-vars-*-buildkernel.log` files under
   `/usr/obj/5BSD-hypertrace-validation/` (amd64 uses
   `host-vars-amd64-final-buildkernel.log`).
   Static and dynamic by-reference stores now tag their copied DTrace-owned buffers as host memory. Static stores validate the source before changing the null marker and publish the new value only after a fault-free copy; the source-extracted sanitized fixture covers successful, denied, partial-fault, and null stores. Dynamic by-reference stores validate before variable allocation and stage guest replacements in probe scratch, preserving the old value if a later guest byte faults; insufficient scratch raises `CPU_DTRACE_NOSCRATCH`. The underlying byte and string copies now stop before writing a byte whose guest load faulted, reject wrapping source ranges, and copy guest-to-host bytes forward regardless of numeric address order. Guest by-reference associative keys now use the active probe VM handle, stop hashing on faults, cannot compare equal after a fault, and discard a new dynamic variable if key copy faults before hash publication. Static, thread-local, and associative scalar stores now reject guest-tagged values with `CPU_DTRACE_ILLOP` before changing a value or allocating a dynamic variable. This prevents persistence of a probe-local VM handle and silent loss of guest provenance. Guest scalar pointer persistence still needs a lifetime-safe VM ID and epoch representation plus a teardown audit before it can be supported. Other semantic and type checks still need
   negative security cases.
   Guest by-reference values for thread-local and associative dynamic
   variables now finish copying into probe scratch before the dynamic
   variable lookup or allocation. A late guest read fault therefore leaves
   an existing value intact and cannot publish a new entry. String staging
   clears bytes beyond its NUL before copying them into a host-owned value.
   A newly allocated dynamic-variable chunk is zeroed, including its value
   and provenance handle, before the hash entry becomes visible; allocation
   size checks now reject arithmetic wrap rather than trusting the sum.
   The source-extracted dynamic-variable fixture covers existing and absent
   entries, late faults, scratch exhaustion, failed allocation, and string
   tails. All 61 native port suites passed under
   `/usr/obj/5BSD-hypertrace-validation/dynvar-init-native-port/`;
   16-job GENERIC kernel/module builds passed on amd64, arm64/aarch64, and
   riscv/riscv64 in the `dynvar-init-*-buildkernel.log` files.
   This still needs live guest execution evidence.
10. **Architecture coverage:** The integrated amd64, arm64, and riscv64
    GENERIC kernels and HyperTrace modules built successfully. The arm64 and
    riscv64 kernels also build the VirtIO-DTrace frontend when configured in
    GENERIC. Arm64 now has a versioned VMM query for the five masked ID
    registers it exposes to guests and the guest counter frequency; libvmmapi
    supplies those values to a sorted bhyve checkpoint CPU contract for
    exact destination compatibility comparison. The arm64 GENERIC kernel
    builds, and the otherwise disabled arm64 checkpoint capture source
    passes a direct arm64 cross-compile. Arm64's VMM snapshot callbacks remain
    guarded by `notyet`; its CPU record alone cannot lift that fence.
    The RISC-V VMM now exposes its actual timer timebase through a versioned
    ioctl, using the same fallback and zero-value handling as its virtual
    timer. Bhyve puts that queried frequency into the guest FDT instead of
    hard-coding 1 MHz. This fixes a guest-visible timekeeping mismatch and
    provides one input for the RISC-V CPU contract. Bhyve now captures the
    same guest FDT ISA and MMU strings, queried timer and SSTC values, SBI
    version and implementation, its actual probed SBI extension mask, and the
    VMM HyperTrace SBI extension version. The source-extracted sanitized
    fixture checks both SSTC modes, mismatched timer and extension records,
    and unchanged output on query failure. All 100 native port suites pass
    under `riscv-cpu-contract-sbi-native-port/`; the final focused fixture
    passes under `riscv-cpu-contract-final-focused/`. The capture source passes a direct
    riscv64 cross-compile; the RISC-V world and GENERIC kernel builds pass in
    `riscv-cpu-contract-final-buildworld.log` and
    `riscv-timebase-final-buildkernel.log` under the validation root. RISC-V
    snapshot remains disabled because its VMM has no snapshot callbacks.
    Both new architecture ioctls are now included in libvmmapi's per-machine
    Capsicum allowlist, so a later checkpoint capture can query them after
    bhyve enters capability mode. The arm64 and riscv64 development world
    builds pass in `arm64-cpu-caprights-buildworld.log` and
    `riscv-timebase-caprights-buildworld.log` under the validation root.
    Run the intended guest and
    host paths. On amd64, a failed or disabled probe
    hypercall now sets the DTrace illegal-operation fault instead of silently
    treating the virtual action as successful. The amd64 handler also rejects
    invalid probe and thread IDs before copying the guest argument block;
    its source-extracted sanitized fixture covers that boundary, copy failure,
    rejected dispatch, and successful dispatch. The full native runner passed
    under `/usr/obj/5BSD-hypertrace-validation/amd64-hypercall-native/`, and
    the 16-job amd64 GENERIC build passed in
    `/usr/obj/5BSD-hypertrace-validation/amd64-hypercall-buildkernel.log`.
    A live guest error-path check remains open. Arm64 now intercepts a private
    vendor-hypervisor HVC
    query and probe call after the vCPU freezes, snapshots the same guest
    paging registers used for instruction emulation, validates the EL1 caller,
    copies the fixed argument envelope across held guest pages, and supplies
    VMM identity callbacks. Its guest DIF path probes for bhyve through SMBIOS
    before issuing HVC. This needs matched host/guest qualification; guest
    scalar DIF pointer reads now copy through the frozen VMM's guest-page
    holds. Other guest pointer operations remain incomplete. RISC-V now recognizes an experimental
    HyperTrace SBI extension, advertises it through the SBI base probe, and
    dispatches guest probes after the vCPU has frozen. The handler validates
    the probe ID, copies the fixed argument envelope across held guest pages,
    supplies VM identity callbacks, and returns an SBI status. Guest DIF can
    discover and invoke that extension on RISC-V. The guest entry-probe
    marker was introduced in version 2. Version 3 adds guest thread virtual
    time and uses distinct amd64/arm64 probe calls and a new RISC-V
    experimental SBI extension ID. Version 4 adds guest monotonic and wall
    clocks with another distinct call number on each architecture. Version 5
    adds the bounded raw kernel-PC pointer and count for `stack()`, with a
    fresh probe call number on each architecture. An old
    guest cannot dispatch its
    shorter argument block through the new host handler, and a guest with a
    mismatched query cannot enable the probe call. The source-extracted
    RISC-V fixture checks query mismatch,
    the valid marker, and rejection of a malformed marker before dispatch;
    the 16-job riscv64 GENERIC kernel/module build passes in
    `riscv-version-extension-buildkernel.log`.
    RISC-V's underlying `vmmops_gla2gpa()` now walks VS-stage Sv39/Sv48
    tables through bounded guest-page holds, checks canonical addresses,
    page permissions, superpage alignment, and malformed entries, and
    rejects unsupported modes. Source-extracted, sanitized fixtures cover
    the RISC-V page walk and both Arm64 and RISC-V cross-page envelope copies;
    the 16-job arm64 and riscv64 GENERIC kernel and DTrace module builds pass.
    The Arm64 16 KiB table walk now advances its 4 KiB held page at entry
    512, avoiding an out-of-bounds PTE read. It also rejects noncanonical
    address bits before masking the input width, while honoring a TBI tag.
    A source-extracted AddressSanitizer fixture exercises those boundaries
    and a missing mapping. All 82 native port suites pass under
    `arm64-walker-final-native-port/`; the 16-job
    arm64 GENERIC kernel/module rebuild passed in
    `arm64-walker-final-buildkernel.log` under the validation object root.
    RISC-V scalar DIF pointer reads now use the same bounded guest-page
    copy contract. Bounded raw guest `stack()` capture now builds on both
    architectures, but its frame offset needs live qualification. Guest
    kernel symbol resolution, remaining user-memory operations, and full
    pointer-valued DIF semantics remain unsupported on both architectures.
    Host/guest HVC and SBI probe
    execution still need matched live testing.
11. **Daemon wire ABI and control tool:** Protocol 48 rejects peers using
    earlier layouts. Network frame and cleanup-entry lengths are eight-byte
    little-endian values. The 520-byte message header now has explicit field
    offsets and little-endian integers; receivers reject nonzero reserved
    padding. The 160-byte connection hello now has a fixed little-endian
    layout. Delivery-status and statistics replies now have canonical
    little-endian encoding and reserved-byte checks. The status decoder also
    rejects non-Boolean revoked and replay fields and unknown delivery,
    handoff, and KILL phase bytes. Delivery receipts and
    VM-info records now use fixed little-endian fields. Handoff delivery and
    KILL request payloads now have fixed little-endian fields and reject
    nonzero reserved bytes. The handoff control request now has an explicit
    49-byte layout. The host DTrace consumer's processing ACK now has a
    56-byte little-endian layout with exact delivery identity and reserved-
    byte checks. Each ELF consumer socket now supplies a nonzero random
    session ID for the HCR1 per-consumer receipt ledger. On an identified
    derived ELF frame, the installed-event slot carries the exact parent
    delivery and consumer session; its remaining bytes are zero. Guest ELF and
    target-envelope payloads now use a
    fixed 24-byte little-endian form on disk and on the daemon wire. The
    outbound HDU2 derived-result claim uses a fixed 192-byte little-endian
    record with a checksum and canonical name; startup rejects malformed
    claims. It is a local spool journal, not a migration wire format. The
    local child-launch count and result now have fixed little-endian fields.
    VM-list entries now reject invalid client kinds, missing name terminators,
    and nonzero bytes after the first terminator before `dtrace -M` displays
    them. The header decoder applies the same canonical rule to ELF locations
    and ordinary VM names, while preserving the ELF derived-parent slot's
    binary consumer session.
    Restore admission's bounded KILL manifest uses a little-endian count and
    canonical 32-byte entries; malformed padding or a stale destination
    identity fails admission before device publication.
    The replay-KILL wire decoder now rejects VM IDs outside the fixed
    HyperTrace namespace before returning a parsed record. The standalone
    protocol header keeps that limit local, while daemon compilation checks
    it against the kernel's `HYPERTRACE_MAX_VMS`. The protocol fixture also
    verifies that an invalid VM ID leaves its caller's record unchanged.
    All 36 sanitized daemon and 81 native port suites pass under the
    `replay-vmid-final-native-*` validation directories. Current-source
    `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64 in
    `replay-vmid-final-*-buildworld.log` under the same validation root.
    Consumer processing ACK and execution-report decoders now reject VM IDs
    outside 1 through 1023 before returning a record. The protocol fixture
    covers zero, the highest valid ID, and the first invalid ID in both wire
    forms. All 36 sanitized daemon suites and 81 native port suites passed
    under the `consumer-vmid-native-*` validation directories;
    current-source `-j16` development world builds passed for amd64,
    arm64/aarch64, and riscv/riscv64 in the
    `consumer-vmid-*-buildworld.log` files under that validation root.
    Consumer ACK and execution-report decoding now also requires a nonzero
    delivery ID, program ID, source ID, epoch, and a defined outcome before
    exposing a parsed record. The protocol fixture checks each missing
    field and unchanged output on rejection, including execution-report
    inheritance of the same checks. All 36 sanitized daemon and 81 native
    port suites pass under the `consumer-ack-identity-native-*`
    validation directories; current-source 16-job development world builds
    pass for amd64, arm64/aarch64, and riscv/riscv64 in the
    `consumer-ack-identity-*-buildworld.log` files under
    `/usr/obj/5BSD-hypertrace-validation/`.
    The fixed message-header decoder now also rejects out-of-namespace VM
    IDs in its ELF, KILL, cleanup, and installed-event field groups before
    publishing a parsed header. The protocol fixture covers each group and
    unchanged caller output on rejection. All 36 sanitized daemon suites
    and 81 native port suites pass under the `header-vmid-native-*`
    validation directories; current-source 16-job development world builds
    pass for amd64, arm64/aarch64, and riscv/riscv64 in
    `header-vmid-*-buildworld.log` under
    `/usr/obj/5BSD-hypertrace-validation/`.
    Handoff delivery and KILL decoders now reject zero ticket/digest/source
    identities, zero delivery IDs, invalid delivery scope, and nonpositive or
    init-process KILL PIDs before a malformed record reaches the daemon
    transaction handler. The sanitized protocol fixture checks each rejected
    field while preserving the caller's output object on failure. All 35
    sanitized daemon suites and 70 native port suites pass under the
    `handoff-payload-*` validation directories; current-source 16-job
    development world builds pass on amd64, arm64/aarch64, and riscv/riscv64
    in `handoff-payload-*-buildworld.log`.
    The fixed 49-byte handoff decoder now also rejects unknown operations,
    an empty ticket, and the wrong digest presence for source versus
    destination transitions before exposing a parsed request. The protocol
    fixture covers valid COMMIT and PREPARE forms and each malformed field.
    All 35 sanitized daemon suites and 70 native port suites pass under the
    `handoff-header-*` validation directories; current-source 16-job
    development world builds pass on amd64, arm64/aarch64, and riscv/riscv64
    in `handoff-header-*-buildworld.log`.
    Connection hello identities now require zero bytes after the first NUL,
    so a daemon peer cannot present multiple wire encodings of one name.
    Every native client now requires the daemon's initial hello to have zero
    subscriptions, identity, and session fields as well as the expected kind
    and protocol version; altered hello fields fail before client admission.
    Bhyve now encodes its native header separately from the payload and sizes
    the network frame from the fixed 520-byte wire header; `dtracedctl` uses
    that same fixed length for cleanup and statistics requests.
    `libdtrace` now sends its typed header separately from ELF or KILL payloads
    and computes frame lengths and payload offsets from that fixed wire size;
    it no longer embeds a native C header in the outgoing buffer.
    Header decoding now rejects unknown message types and nonzero fields
    outside each type's allowed field group; an ELF may also carry the
    installed-event group for an authenticated derived parent. That group
    must now be either empty or a complete parent identity with a 16-byte
    consumer session and zero tail. A present ELF program identifier must be
    a canonical NUL-terminated string. The sanitized protocol fixture covers
    empty, complete, and malformed cases. The parent-slot change passed all
    35 native daemon and 44 native port suites under the `wire-parent-*`
    validation directories; the later identifier check passed the focused
    sanitized protocol fixture.
    ELF identity and VM-filter flags now accept only 0 or 1, and identity
    bytes must be zero when the identity-present flag is clear. The child
    launch-result decoder likewise rejects a non-Boolean installed flag and
    now checks the exact launch magic before exposing a parsed result. The
    sanitized protocol fixture rejects a corrupted magic without changing
    its output object.
    This decoder change passed 35 sanitized daemon suites, 44 native port
    suites, and `-j16 buildworld` for amd64, arm64, and riscv64 on 2026-10-16
    (`wire-elfflags-*` logs under `/usr/obj/5BSD-hypertrace-validation`).
    The integrated protocol test covers golden bytes and malformed padding.
    Cross-architecture runtime qualification and a complete wire-ABI audit
    remain open. Statistics requests now require zero cleanup VM ID and epoch
    fields; the selector count remains available. Cleanup messages require
    VM ID and epoch to be either both zero or both present. The daemon rejects
    those fields in administrative cleanup and statistics requests, which
    select VMs by name. The protocol and cleanup-routing fixtures cover the
    malformed and valid forms. The advertised
    `dtracedctl --show-stats` now has a fixed-size local reply for live
    forwarder and delivery counts, with root authorization and name filtering;
    full wire-ABI stabilization remains open.
    Statistics-request decoding now also requires a zero delivery-ID alias
    in the shared header. The daemon ignores that field for statistics, so
    accepting nonzero bytes allowed multiple encodings of one request. The
    protocol fixture checks rejection without changing the caller's decoded
    header. The focused sanitizer fixture, all 36 sanitized native daemon
    component suites, and all 86 native port suites pass under the
    `stats-wire-native-*` validation directories. Current-source 16-job
    development worlds pass for amd64, arm64/aarch64, and riscv/riscv64 in
    `stats-wire-*-buildworld.log` under the same validation root.
    HTX1 validation now rejects the all-zero ticket token that the builder
    already refused, so a caller with an empty token cannot accept a
    separately sealed bundle. The transfer-wire fixture covers that invalid
    form alongside the normal nonzero token. All 86 sanitized native port
    suites and 36 sanitized native daemon component suites pass under
    `transfer-token-native-{port,daemon}/` in the validation object root.
    Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
    riscv/riscv64 in `transfer-token-*-buildworld.log` there.
    Guest ELF envelope parsing now bounds the expected VM-name scan to the
    128-byte attestation name field. A nonterminated fixed-size name fails
    with `EPROTO` instead of allowing `strlen` to read past the caller's
    array. The sanitized protocol fixture covers a valid envelope and the
    full-length unterminated name; all 40 sanitized daemon suites pass under
    `protocol-bounded-name-native-daemon/`. Current-source `-j16 buildworld`
    passes for amd64, arm64/aarch64, and riscv/riscv64 in the
    `protocol-bounded-name-*-buildworld.log` files under the validation root.
12. **Qualification:** Run matched host and guest images on disposable VMs
    with `/dev/vmm`, `/dev/dtrace/dtrace`, and `/dev/dttransport`. Cover tracing,
    restore, migration, recovery, hostile inputs, and latency/loss under load.
    These devices are absent from the current build host, so native builds
    and unit tests alone cannot close this gate.

The latest active-branch native results are under
`/usr/obj/5BSD-hypertrace-validation/srcident-verifier-port/`
and `/usr/obj/5BSD-hypertrace-validation/derived-source-audit-daemon/`
(35 sanitized daemon suites passed).
The HyperTrace vendor/active-daemon runner now keeps its two ABI generations
separate. Its pinned-overlay verification, source-extracted guest-memory
fixtures, nine reproduced vendor regressions, eleven patched checks, active
daemon compile/link, and the job-lifetime, transport, and event suites pass
under `/usr/obj/5BSD-hypertrace-validation/arm64-hvc-guest-string-native-3/`.
The late pre-CLAIM KILL and next-cut barrier regression passed with all 35
sanitized daemon suites under
`/usr/obj/5BSD-hypertrace-validation/preclaim-kill-daemon-fixed/`.
The restored-queue KILL ordering and ELF-continuation regression passed in
the native device suite under
`/usr/obj/5BSD-hypertrace-validation/restore-kill-priority-port/`;
all 43 native port suites passed before the final queue-capacity adjustment,
and the focused device suite passed afterward. The matching development
world build passed with 16 CPUs in
`/usr/obj/5BSD-hypertrace-validation/restore-kill-final-buildworld.log`.
The restore admission manifest and paused-device handoff passed all 43 native
port suites under
`/usr/obj/5BSD-hypertrace-validation/replay-manifest-ready-port/`;
the added READY-fence assertion passed in the focused device suite afterward.
All 35 sanitized daemon suites passed under
`/usr/obj/5BSD-hypertrace-validation/replay-manifest-daemon-pass/`.
The matching 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/replay-manifest-ready-buildworld.log`.
The exact-manifest attachment regression passed all 43 native port suites
under `/usr/obj/5BSD-hypertrace-validation/manifest-retry-port-fixed/`;
its matching 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/manifest-retry-buildworld-fixed.log`.
The destination-identity retry check passed all 43 native port suites under
`/usr/obj/5BSD-hypertrace-validation/manifest-identity-port/`; its matching
16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/manifest-identity-buildworld.log`.
The paused-ticket boundary passed all 43 native port suites under
`/usr/obj/5BSD-hypertrace-validation/paused-ticket-port/`; its matching
16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/paused-ticket-buildworld.log`.
The canonical connection-identity change passed all 35 sanitized native
daemon suites under `/usr/obj/5BSD-hypertrace-validation/canonical-ident-daemon/`;
its matching 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/canonical-ident-buildworld.log`.
The canonical replay-manifest ordering and malformed-order rejection passed all
35 sanitized native daemon suites under
`/usr/obj/5BSD-hypertrace-validation/canonical-replay-daemon/` and all 43
native port suites under
`/usr/obj/5BSD-hypertrace-validation/canonical-replay-port/`. The matching
16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/canonical-replay-incremental-buildworld.log`.
The fixed-header bhyve send API and `dtracedctl` frame sizing passed all 43
native port suites under
`/usr/obj/5BSD-hypertrace-validation/wire-header-api-port-fixed/` and the
16-CPU development world build in
`/usr/obj/5BSD-hypertrace-validation/wire-header-api-buildworld-fixed.log`.
The per-message header field checks passed all 43 native port suites under
`/usr/obj/5BSD-hypertrace-validation/header-groups-port-fixed/` and the
35 sanitized native daemon suites under
`/usr/obj/5BSD-hypertrace-validation/header-groups-daemon/`. The matching
16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/header-groups-buildworld.log`.
The separate `libdtrace` header/payload send path passed all 43 native port
suites under `/usr/obj/5BSD-hypertrace-validation/libdtrace-frame-port/`.
The final exact wire-offset transport assertion passed in
`/usr/obj/5BSD-hypertrace-validation/libdtrace-frame-library-final/`.
The matching 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/libdtrace-frame-buildworld.log`.
The staged destination queue and post-CLAIM publication passed all 43 native
port suites under `/usr/obj/5BSD-hypertrace-validation/restore-stage-port/`.
The final duplicate-stage assertion passed in the focused device executable
`/usr/obj/5BSD-hypertrace-validation/restore-stage-device-final`; the matching
16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/restore-stage-buildworld.log`.
The variable-type verifier and ELF parser checks passed the matching-world
transform and ELF library suites under
`/usr/obj/5BSD-hypertrace-validation/variable-type-vprog/` and
`/usr/obj/5BSD-hypertrace-validation/variable-type-elf/`. The matching
16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/variable-type-buildworld.log`.
The matching 16-CPU development world build passed; its log is
`/usr/obj/5BSD-hypertrace-validation/derived-source-audit-buildworld.log`.
The return-type verifier and parser changes passed the matching-world
transform test under `/usr/obj/5BSD-hypertrace-validation/rtype-parser-vprog/`
and the ELF library suite under
`/usr/obj/5BSD-hypertrace-validation/rtype-parser-elf/`. The matching
16-CPU development world build is logged at
`/usr/obj/5BSD-hypertrace-validation/rtype-parser-buildworld.log`.
The latest journal and hostile-record host-ingress regression passed under
`/usr/obj/5BSD-hypertrace-validation/consumer-receipt-ledger-identity/`.
The indexed HCR1 recovery change passed the rebuilt sanitized daemon and
the multiple-delivery host-ingress regression under
`/usr/obj/5BSD-hypertrace-validation/consumer-index-daemon/`.
The explicit consumer-outcome ledger and lock-cycle correction passed all 35
sanitized daemon suites under
`/usr/obj/5BSD-hypertrace-validation/consumer-lock-verified-daemon/`,
including a host-ingress send that waits for the real frame before ACK and
proves source and revocation locks are available to derived publication. The
final focused host-ingress case also checks legacy HCR1 receipt recovery.
All 53 native port suites passed under
`/usr/obj/5BSD-hypertrace-validation/consumer-outcome-port/`; the matching
amd64 16-job development world build passed in
`/usr/obj/5BSD-hypertrace-validation/consumer-outcome-amd64-buildworld.log`.
The replayed-ACK reconciliation and shared cross-process outcome lock passed
all 35
sanitized daemon suites under
`/usr/obj/5BSD-hypertrace-validation/consumer-outcome-lock-daemon/`;
amd64 and arm64 16-job development world builds passed in the
`consumer-outcome-lock-*-buildworld.log` files under the validation object
root. The riscv64 build is still running and must be checked before treating
that architecture as validated for this change.
The focused exact-session selective replay regression passed under
`/usr/obj/5BSD-hypertrace-validation/consumer-selective-replay-daemon/`.
The derived parent, exact retry, conflicting-payload, restart resolution,
dual-digest and outbound-receipt audit, wrong-source and retained-spool
conflicts, orphan-spool, interrupted-publication, and spool-free
receipt-lineage checks
passed in the latest daemon suite above.
The focused same-session handshake and receiver reconnect tests passed under
`/usr/obj/5BSD-hypertrace-validation/consumer-reconnect-handshake/` and
`/usr/obj/5BSD-hypertrace-validation/consumer-reconnect-test/`.
The pending-ingress and handoff-cut regression checks also passed under
`/usr/obj/5BSD-hypertrace-validation/source-phase-cut/`.
An amd64 development `make -j16 buildworld` of the current experimental
source completed under `/usr/obj/5BSD-hypertrace-validation/active-merged-world-obj/`;
the latest rebuild log is
`/usr/obj/5BSD-hypertrace-validation/derived-hdu2-lineage-buildworld.log`. The
matching-world transform test passed under
`/usr/obj/5BSD-hypertrace-validation/srcident-verifier-test/`.
This is build evidence only. No packages were published or installed and no
live VM was run.
The action-owner and statement-self checks passed six built-library ELF
round trips, 57 malformed graph/table cases, parser-boundary cases, and six
allocation-failure fixtures under
`/usr/obj/5BSD-hypertrace-validation/elf-owner-reachable-library/`. The
matching 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/elf-owner-reachable-buildworld.log`.
All 43 native port suites passed before the final shared-action reachability
adjustment under `/usr/obj/5BSD-hypertrace-validation/elf-owner-port/`;
the built-library suite above covers the final parser change.
The printf-conversion writer and parser passed a 16-CPU development world
build in `/usr/obj/5BSD-hypertrace-validation/printf-conv-buildworld.log`.
The final built-library suite under
`/usr/obj/5BSD-hypertrace-validation/printf-conv-count-library/`
inspected the parsed printf conversion in both normal and checksummed ELF,
and passed 61 malformed graph/table cases plus allocation-failure fixtures.
The matching final 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/printf-conv-count-buildworld.log`.
Format reconstruction now counts and copies into the caller's output bound
instead of sizing a stack buffer from a small fixed estimate; DOF creation
allocates its format scratch on the heap and handles reconstruction failure.
The final built-library suite under
`/usr/obj/5BSD-hypertrace-validation/printf-bounded-dof-library/`
exercised a parsed maximum-width descriptor, a four-byte output buffer with
an untouched canary, and DOF creation from both ordinary and wide printf ELF.
The matching 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/printf-bounded-buildworld.log`.
The restored-device feature check passed all 43 native port suites under
`/usr/obj/5BSD-hypertrace-validation/restore-feature-port/`, including
missing and incomplete negotiated-feature cases. The matching 16-CPU
development world build passed in
`/usr/obj/5BSD-hypertrace-validation/restore-feature-buildworld.log`.
Restore preflight now checks the authenticated source compatibility image for
the same negotiated features before guest memory mutation; queue publication
checks the live restored device again while paused.
That preflight change passed all 43 native port suites under
`/usr/obj/5BSD-hypertrace-validation/restore-preflight-port/` and a 16-CPU
development world build recorded in
`/usr/obj/5BSD-hypertrace-validation/restore-preflight-buildworld.log`.
The receipt-before-rename guest rekey regression passed in the focused
`guest-delivery-rekey` suite, all 35 sanitized daemon component suites passed
under `/usr/obj/5BSD-hypertrace-validation/rekey-prevalidate-daemon/`, and the
matching 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/rekey-prevalidate-buildworld.log`.
Source replayability now rejects guests missing the negotiated restore
features before serializing device bytes. All 43 native port suites passed
under `/usr/obj/5BSD-hypertrace-validation/source-feature-final-port/`, with
the matching 16-CPU development world build in
`/usr/obj/5BSD-hypertrace-validation/source-feature-buildworld.log`.
The action-field parser checks passed the actual built-library suite under
`/usr/obj/5BSD-hypertrace-validation/action-fields-library/` (six valid ELF
round trips and 65 malformed graph/table rejections). The matching 16-CPU
development world build passed in
`/usr/obj/5BSD-hypertrace-validation/action-fields-buildworld.log`.
The final action-field suite under
`/usr/obj/5BSD-hypertrace-validation/action-fields-final-library/` passed
six valid ELF round trips and 66 malformed graph/table rejections; the
matching native 16-CPU world build passed in
`/usr/obj/5BSD-hypertrace-validation/action-fields-final-buildworld.log`.
The same source completed 16-CPU arm64 and riscv64 cross-world builds in
`/usr/obj/5BSD-hypertrace-validation/action-fields-arm64-buildworld.log` and
`/usr/obj/5BSD-hypertrace-validation/action-fields-riscv-buildworld.log`.
These cross-builds establish compilation, not guest or host runtime behavior.
The source-watcher cut regression passed all 35 sanitized daemon component
suites under `/usr/obj/5BSD-hypertrace-validation/source-watcher-cut-final-daemon/`.
It verifies that a prepared source leaves a recovered ingress spool
unmemorized without a pending consumer receipt, and that ABORT permits its
job to be queued. The matching 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/source-watcher-cut-buildworld.log`.
The unattempted consumer-job retirement regression passed all 35 sanitized
daemon suites under
`/usr/obj/5BSD-hypertrace-validation/handoff-queued-retire-daemon/`.
It covers both watcher and startup-recovered pending jobs. The matching
16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/handoff-queued-retire-buildworld.log`.
The deferred-job phase/requeue lock regression passed all 35 sanitized daemon
suites under `/usr/obj/5BSD-hypertrace-validation/native-daemon-current/`;
the matching 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/deferred-handoff-lock-buildworld.log`.
The canonical VM-list and header-field changes passed all 43 native port
suites under
`/usr/obj/5BSD-hypertrace-validation/wire-header-canonical-port/`,
all 35 sanitized daemon suites and the final focused protocol wire cases under
`/usr/obj/5BSD-hypertrace-validation/wire-header-canonical-daemon/`, and
the 16-CPU development world build in
`/usr/obj/5BSD-hypertrace-validation/wire-header-canonical-buildworld.log`.
The program-verifier transaction regression passed against the matching built
library under `/usr/obj/5BSD-hypertrace-validation/verifier-transaction-test/`.
It covers action ownership, late-statement failure without earlier DIFO or
format mutation, context rollback, successful format replacement, and format
prefix ownership. The actual built-library ELF round-trip, malformed-input,
and allocation suites passed under
`/usr/obj/5BSD-hypertrace-validation/verifier-transaction-library/`.
Native, arm64, and riscv64 16-CPU development world builds passed in
`/usr/obj/5BSD-hypertrace-validation/verifier-transaction-buildworld.log`,
`/usr/obj/5BSD-hypertrace-validation/verifier-transaction-arm64-buildworld.log`,
and `/usr/obj/5BSD-hypertrace-validation/verifier-transaction-riscv-buildworld.log`.
The cross-builds do not establish guest runtime behavior.
The aggregation-identifier and statement-attribute verifier regression passed
against the matching built libdtrace under
`/usr/obj/5BSD-hypertrace-validation/aggregation-verifier-test/`.
The actual built-library ELF boundary, round-trip, malformed-input, and
allocation suites passed under
`/usr/obj/5BSD-hypertrace-validation/aggregation-verifier-library/`.
The matching native 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/aggregation-verifier-final-buildworld.log`.
The receiver cleanup passed the focused `cddl/usr.sbin/dtrace` build in
`/usr/obj/5BSD-hypertrace-validation/receiver-cleanup-dtrace-build.log`.
The receiver cleanup with DTrace-handle locking passed the focused executable
build in
`/usr/obj/5BSD-hypertrace-validation/receiver-cleanup-locked-dtrace-build.log`
and the matching 16-CPU development world build in
`/usr/obj/5BSD-hypertrace-validation/receiver-cleanup-buildworld.log`.
The return-flag verifier regression passed against the rebuilt libdtrace in
`/usr/obj/5BSD-hypertrace-validation/return-flags-test/`; the actual
built-library ELF boundary, round-trip, malformed-input, and allocation
suites passed under
`/usr/obj/5BSD-hypertrace-validation/return-flags-library/`.
The matching native 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/return-flags-buildworld.log`.
The status Boolean decoder regression passed all 35 sanitized daemon
component suites under
`/usr/obj/5BSD-hypertrace-validation/status-booleans-daemon/`.
All 43 native port suites passed under
`/usr/obj/5BSD-hypertrace-validation/status-booleans-port/`.
The matching native 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/status-booleans-buildworld.log`.
The protocol-37 status-phase decoder passed all 35 sanitized daemon suites
under `/usr/obj/5BSD-hypertrace-validation/status-phases-daemon/` and all 43
native port suites under
`/usr/obj/5BSD-hypertrace-validation/status-phases-port/`.
The matching native 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/status-phases-buildworld.log`.
The concrete return-kind and by-reference verifier cases passed against the
rebuilt libdtrace under
`/usr/obj/5BSD-hypertrace-validation/return-type-vprog-after-world/`.
The matching native 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/return-type-buildworld.log`.
The matching arm64 16-CPU development world build passed in
`/usr/obj/5BSD-hypertrace-validation/return-type-arm64-buildworld.log`.
Neither cross-build nor rootless verifier test establishes guest runtime
behavior.
The canonical daemon-hello check passed all 35 sanitized native daemon suites
under `/usr/obj/5BSD-hypertrace-validation/server-hello-daemon/` and all 43
native port suites under `/usr/obj/5BSD-hypertrace-validation/server-hello-port/`.
The matching 16-CPU native development world build passed in
`/usr/obj/5BSD-hypertrace-validation/server-hello-buildworld.log`.
Matching arm64 and riscv64 16-CPU development world builds passed in
`/usr/obj/5BSD-hypertrace-validation/server-hello-arm64-buildworld.log` and
`/usr/obj/5BSD-hypertrace-validation/server-hello-riscv-buildworld.log`.
These cross-builds do not establish host/guest wire interoperability.
The amd64 guest-hypercall failure-path change passed the 16-CPU GENERIC
kernel and module build in
`/usr/obj/5BSD-hypertrace-validation/hypercall-result-buildkernel-amd64.log`.
The host-rejected and disabled-hypercall outcomes still need a live guest
runtime check.
The virtual-probe host-context, lock-class, and `vtimestamp` guards passed
16-CPU GENERIC kernel and module builds for amd64, arm64/aarch64, and
riscv/riscv64 in the `guest-context-final-buildkernel-*.log` files under
`/usr/obj/5BSD-hypertrace-validation/`.
The prohibited-action fault behavior still needs a live virtual-probe test.
The migration blob length check passed the 16-CPU amd64 development world
build in `/usr/obj/5BSD-hypertrace-validation/migration-blob-bounds-buildworld-amd64.log`.
The RISC-V VS-stage walker passed the source-extracted sanitized fixture
`python3.12 contrib/hypertrace/tests/riscv-vs-stage-walk.py` and the 16-job
GENERIC kernel/module build in
`/usr/obj/5BSD-hypertrace-validation/riscv-vs-stage-walk-final-buildkernel.log`.
The guest user-memory guards passed the source-extracted sanitized seven-opcode
fixture and the guest builtin fixture, including tagged guest copyin/copyinto,
untagged guest rejection, guest BYUREF rejection before host fetch, and a host
BYUREF read. The 48 native port suites passed with the expanded fixtures under
`/usr/obj/5BSD-hypertrace-validation/native-guest-memory-fixtures/`.
The final amd64, arm64, and riscv/riscv64 16-job GENERIC kernel/module builds
passed in the `guest-memory-final-*-buildkernel.log` files. The expanded
source-extracted guest builtin test also passed under
`/usr/obj/5BSD-hypertrace-validation/guest-builtins-final2/`. These results
do not replace live guest testing.
The DIF store provenance guards passed the source-extracted sanitized
`guest-store.py` fixture, covering all four scalar store widths, guest-tagged
sources and destinations, and COPYS from tagged guest memory into host
scratch. All 49 native port suites passed under
`/usr/obj/5BSD-hypertrace-validation/native-guest-store/`.
The matching 16-job amd64, arm64/aarch64, and riscv/riscv64 GENERIC kernel
and DTrace-module builds passed in the `guest-store-*-buildkernel.log` files
under `/usr/obj/5BSD-hypertrace-validation/`.
The cleanup/statistics field canonicality change passed the focused sanitized
protocol fixture, all 35 native daemon component suites under
`/usr/obj/5BSD-hypertrace-validation/daemon-cleanup-fields-final/`, and all 49
native port suites under
`/usr/obj/5BSD-hypertrace-validation/port-cleanup-fields-final/`.
The guest-variable provenance changes passed sanitized source-extracted static,
thread-local, and associative-variable fixtures, including guest-tagged scalar
rejection before mutation or dynamic-variable allocation. All 51 native port
suites passed under `/usr/obj/5BSD-hypertrace-validation/native-scalar-assoc-final/`.
The final 16-job amd64, arm64/aarch64, and riscv/riscv64 GENERIC kernel and
DTrace-module builds passed in the `scalar-guard-final-*-buildkernel.log` files
under `/usr/obj/5BSD-hypertrace-validation/`. These are build and component
results; guest execution and checkpoint/restore remain unqualified.
The production byte and string copy arms passed a source-extracted ASAN/UBSAN
fixture for guest copies, mid-copy faults, wrapping addresses, and host overlap.
All 52 native port suites passed under
`/usr/obj/5BSD-hypertrace-validation/native-byte-copy-final/`; the 16-job
amd64, arm64/aarch64, and riscv/riscv64 GENERIC kernel/module builds passed in
the `byte-copy-final-*-buildkernel.log` files.
Guest dynamic by-reference replacement now validates before allocation and
uses probe scratch to avoid exposing a faulted partial guest copy. The
source-extracted sanitized fixture covers denied sources, a mid-copy fault,
insufficient scratch, and thread-local/associative paths. The 16-job GENERIC
kernel/module builds passed on amd64, arm64/aarch64, and riscv/riscv64 in the
`dynvar-atomic-final-*-buildkernel.log` files. All 52 native port suites passed
under `/usr/obj/5BSD-hypertrace-validation/native-dynvar-staged-final/`.
This prevents faulted
replacement of existing bytes; concurrent readers still require a separate
publication protocol for full atomic visibility.
The source-extracted sanitized associative-key comparison fixture confirms
that a fault after equal leading bytes cannot match an existing key, and that
an address wrap fails before a read. All 53 native port suites passed under
`/usr/obj/5BSD-hypertrace-validation/native-key-compare-final/`. The 16-job
amd64, arm64/aarch64, and riscv/riscv64 GENERIC kernel/module builds passed in
the `key-compare-final-*-buildkernel.log` files.

The exact-parent consumer replay and completed-receipt spool suppression pass
all 54 sanitized native port suites and 35 sanitized daemon suites under
`/usr/obj/5BSD-hypertrace-validation/consumer-derived-replay-port/` and
`/usr/obj/5BSD-hypertrace-validation/reemit-final-daemon/`. Development
`-j16 buildworld` passes on amd64, arm64/aarch64, and riscv/riscv64 in the
`reemit-*-buildworld.log` files. These checks do not cover a consumer process
crash between ACK and host instrumentation enablement, or transfer of its
journal to another host.

The bounded guest rekey recovery loop passed the source-extracted startup
fixture under `/usr/obj/5BSD-hypertrace-validation/rekey-bounded-final-focused/`,
all 54 native port suites under
`/usr/obj/5BSD-hypertrace-validation/rekey-bounded-final-port/`, and all 35
sanitized native daemon suites under
`/usr/obj/5BSD-hypertrace-validation/rekey-bounded-final-daemon/`.
Current-source `-j16 buildworld` completed for amd64, arm64/aarch64, and
riscv/riscv64 in the `rekey-bounded-final-*-buildworld.log` files under
`/usr/obj/5BSD-hypertrace-validation/`. A restored guest must still prove
the journal and COMMIT retry behavior against the matched host at runtime.

Guest scalar loads now use an architecture VMM callback that translates each
guest page without injecting a guest fault, holds it only during the copy,
and returns an error rather than reading host memory after a guest fault.
This covers amd64, arm64, and riscv64, including scalars that straddle two
guest pages. The source-extracted scalar dispatch and amd64 held-page tests
passed, as did all 56 native port suites under
`/usr/obj/5BSD-hypertrace-validation/guest-scalar-final-native-port-56/`.
Current-source 16-job GENERIC kernel and DTrace/HyperTrace/VMM module builds
passed for amd64, arm64/aarch64, and riscv/riscv64 in the
`guest-scalar-*-buildkernel.log` files (the final arm64 and riscv64 module
refreshes use `guest-scalar-final-*-buildkernel.log`). Live guest pointer
reads and the remaining non-scalar operations still require qualification.
Development `-j16 buildworld` also passed for amd64, arm64/aarch64, and
riscv/riscv64 in the `guest-scalar-*-buildworld.log` files under the same
validation object root.

All seven restricted DIF scalar-load opcodes now authorize tagged guest
addresses against the active guest handle and kernel-read privilege rather
than testing their numeric value against host scratch or string-table ranges.
A stale handle, insufficient privilege, and a zero or wrapping address fail
before any guest read; untagged host loads retain their existing checks.
The source-extracted restricted-load fixture covers each opcode and the
host-address collision case. All 57 native port suites passed under
`/usr/obj/5BSD-hypertrace-validation/guest-restricted-final-native-port/`,
and current-source 16-job amd64, arm64/aarch64, and riscv/riscv64 GENERIC
kernel/module builds passed in the `guest-restricted-*-buildkernel.log` files.
Guest execution still needs matched live testing.

Guest-tagged by-reference values and strings now use the same guest-handle
and kernel-read authorization before any copy. Their numeric address cannot
borrow access to host scratch or a host string table. The source-extracted
by-reference fixture covers the host collision, denial, authorized guest
copy, stale handle, and wrapping address. All 58 native port suites passed
under `/usr/obj/5BSD-hypertrace-validation/guest-authority-final-native-port/`;
current-source 16-job amd64, arm64/aarch64, and riscv/riscv64 GENERIC
kernel/module builds passed in the `guest-authority-*-buildkernel.log` files.
The shared `dtrace_strcanload()` check now enforces that same tag-aware
authorization for its callers.
The expanded source-extracted fixture passed this case, all 58 native port
suites passed under
`/usr/obj/5BSD-hypertrace-validation/guest-authority-string-final-native-port/`,
and current-source 16-job GENERIC kernel/module builds passed on amd64,
arm64/aarch64, and riscv/riscv64 in the
`guest-string-authority-*-buildkernel.log` files.

Guest `uregs[]` now reads the frozen guest thread's saved user-trapframe
pointer and trapframe through bounded VMM guest-page copies, then applies
the architecture's existing `dtrace_getreg()` mapping. Zero and wrapping
addresses or failed copies raise `BADADDR`; a missing guest-copy callback
raises `ILLOP`. The VMM copy bound permits one trapframe on amd64, arm64, and
riscv64 without changing the hypercall envelope. The source-extracted
UREGS fixture covers valid values, invalid indices, and copy failures; the
host-stack fixture checks the DIF variable dispatch. All 60 native port
suites passed under
`/usr/obj/5BSD-hypertrace-validation/guest-uregs-final2-native-port/`,
and current-source 16-job GENERIC kernel/module builds passed on amd64,
arm64/aarch64, and riscv/riscv64 in the `guest-uregs-*-buildkernel.log`
files. Matched guest/host trapframe layout and live UREGS behavior remain
to be qualified.

Guest `caller` and `stackdepth` now come from the guest's own DIF variable
lookups at the forwarding instruction. They travel in the version-2
HyperTrace argument envelope, and the virtual probe returns them without
examining the host hypercall stack. The host `hcaller` and `hstackdepth`
paths remain separate. The source-extracted host-stack fixture checks the
guest values, missing-envelope rejection, and independent host values.
These captures add two guest stack lookups to each forwarded probe; their
exact call-site semantics and cost still need matched live measurement.

Guest `ucaller` now follows the native three-word user-stack convention
from the frozen guest trapframe. On amd64 it reads the return address at
`rbp + 8`, or at `rsp` for an entry probe; arm64 uses `x29 + 8` or the
saved link register; riscv64 uses `s0 - 8` or the saved return register.
The memory read uses the VMM guest-user-page callback, and a missing or
unsupported callback fails closed without reading a host user address.
The guest sends its entry-probe context in the HyperTrace argument envelope;
each of the three VMM hypercall handlers rejects values outside the Boolean
range before dispatch, and DTrace checks again before interpreting frames.
Guest `ustackdepth` now walks guest user pages up to the native 2048-frame limit,
stopping on a zero PC or frame pointer and flagging cyclic or inaccessible
frames. The source-extracted `guest-ucaller` fixture covers both variables'
normal and entry paths, cyclic frames, and callback failures on all three
architectures; the host-stack fixture checks that the `h*` variants remain
independent. All 70 native port suites pass under
`/usr/obj/5BSD-hypertrace-validation/guest-stack-envelope-native-port/`;
current-source 16-job GENERIC kernel/module builds pass on amd64,
arm64/aarch64, and riscv/riscv64 in the
`guest-stack-envelope-*-buildkernel.log` files. The source-extracted amd64
hypercall fixture also verifies that a valid entry marker survives dispatch
and an invalid marker cannot fire a virtual probe.
Live guest stack behavior and matched guest/host frame layout still need
qualification.

Virtual-probe `ustack()` now records the guest PID and user PCs through the
same bounded guest-user callback as `ustackdepth`. Its first slot has a
distinct VMID/PID tag, so the two libdtrace stack formatters print guest
frames as raw PCs and never open a host process that happens to reuse the
guest PID. The source-extracted stack fixture covers all three frame layouts,
entry probes, callback failure, and the tag. A separate extracted formatter
fixture checks both output paths and preserves native host stack lookup.
All 80 sanitized native port suites pass under
`/usr/obj/5BSD-hypertrace-validation/guest-ustack-native-port/`;
current-source `-j16 buildworld` and GENERIC kernel/module builds pass for
amd64, arm64/aarch64, and riscv/riscv64 in the `guest-ustack-final-*` logs
under the same validation root.
Guest symbols and a full epoch-aware user-stack record remain open; this is
raw guest PC capture, not guest symbol resolution or live qualification.

The three VMM guest-copy implementations now stage each bounded envelope,
scalar, or trapframe read and update the destination only after every guest
page translates and can be held. A second-page translation or hold failure
leaves the caller's destination unchanged. Source-extracted, sanitized
amd64, arm64, and riscv64 fixtures cover cross-page success and failure;
all 60 native port suites passed under
`/usr/obj/5BSD-hypertrace-validation/guest-copy-atomic-native-port/`.
Current-source 16-job GENERIC kernel/module builds passed on all three
architectures in `guest-copy-atomic-*-buildkernel.log`. This guarantees
destination integrity on a failed copy, not a simultaneous snapshot of
pages that other guest vCPUs may modify.

Guest DIF `uldsb`, `uldsh`, `uldsw`, `uldub`, `ulduh`, `ulduw`, and `uldx`
now use a separate guest user-page copy callback. The VMM checks user
permissions by walking with CPL 3 on amd64, EL0t on arm64, and a required
`PTE_U` VS-stage mapping on riscv64. Flat/bare paging cannot prove user
ownership and fails closed. The DTrace interpreter requires process tracing
privilege, rejects a foreign guest tag, raises `BADADDR` on a failed user
copy, and tags successful values as guest data so a loaded pointer cannot
be dereferenced in the host address space. The source-extracted interpreter
fixture covers all seven signed and unsigned loads, host preservation,
privilege/provenance rejection, and fault handling. The architecture copy
fixtures cover the user-mode request and its bounded, page-held copy; the
RISC-V VS-stage fixture checks `PTE_U` and bare-stage rejection. All 61
native port suites passed under
`/usr/obj/5BSD-hypertrace-validation/guest-userpages-native-port/`;
current-source 16-job GENERIC kernel/module builds passed on amd64,
arm64/aarch64, and riscv/riscv64 in the
`guest-userpages-*-buildkernel.log` files. Live guest user-page behavior,
including the guest's active page-table mode, remains to be qualified.
Current-source 16-job development world builds also passed for all three
architectures in the `guest-userpages-*-buildworld.log` files.

Guest `copyin`, `copyinto`, `copyinstr`, and BYUREF action capture now use
the same user-page callback as scalar user loads. Tagged guest pointers and
untagged numeric guest addresses are interpreted only in the current guest;
a foreign VM tag or missing process privilege fails before any copy. The
`bcopy` and `copyinto` destinations reject a guest tag before a numeric
address can be mistaken for host scratch. The
host user-memory path is retained for host probes. Bulk copies use bounded
eight-byte reads, while `copyinstr` and string BYUREF read one byte at a
time and stop at NUL without touching the next page. A failed guest read
sets `BADADDR` and does not publish a scratch pointer. The source-extracted
builtin/action fixture covers a NUL at the last byte of a mapped page,
cross-page bulk success and fault, foreign tags, process privilege, and
host-path preservation. It also checks that tagged `bcopy` and `copyinto`
destinations fail without modifying scratch. All 61 native port suites passed under
`/usr/obj/5BSD-hypertrace-validation/guest-usercopy-final-native-port/`; current
source 16-job GENERIC kernel/module builds passed on amd64, arm64/aarch64,
and riscv/riscv64 in the `guest-usercopy-final-*-buildkernel.log` files. Live
guest user-memory behavior and other user-memory operations remain open.

The guest string audit now authorizes tagged strings before their first
length scan in `strstr`, `index`, `rindex`, `substr`, `json`, `toupper`,
`tolower`, `dirname`, `basename`, and the DIF string-tuple push. The
source-extracted builtin fixture covers denied guest strings at unmapped
addresses, including second operands, and verifies that denial occurs
before a guest memory fault. Tagged guest sources in `bcopy`, `memstr`,
`inet_ntop`/`inet_ntoa`/`inet_ntoa6`, and DIF `copys` now use the same
guest-handle and kernel-read authorization as their eventual read. Dynamic
associative-key hashing also checks that authorization before its first
guest-key byte read. The builtin, DIF-store, and string-tuple fixtures cover
guest copy success, privilege denial, stale handles, and denial before the
tuple length scan. All 59 native port suites passed under
`/usr/obj/5BSD-hypertrace-validation/guest-pushtr-final-native-port/`;
current-source 16-job amd64, arm64/aarch64, and riscv/riscv64 GENERIC
kernel/module builds passed in the `guest-tagged-key-*-buildkernel.log` files.
These results establish compilation and source-extracted behavior, not live
guest qualification or completeness of the remaining guest-memory audit.

The guest string interpreter now discards partial results on read faults in
`strlen`, `strchr`/`strrchr`, `strstr`/`index`/`rindex`, `strtok`,
`substr`, `basename`/`dirname`, and `cleanpath`. A fault during `strtok`
also leaves its saved cursor unchanged. These operations check address and
scratch bounds before publishing a result. The `strtoll` parser now stops
at its authorized string limit, checks faults during whitespace, sign,
prefix, and digit reads, and saturates out-of-range values rather than
overflowing signed arithmetic. The source-extracted guest-builtin fixture
covers late faults, a prior `strrchr` match, `strtok` cursor preservation,
bounded parsing, and both signed saturation limits. All 65 native port
suites passed under
`/usr/obj/5BSD-hypertrace-validation/guest-path-final-native-port/`.
Current-source `-j16` GENERIC builds passed on amd64, arm64/aarch64, and
riscv/riscv64 in the `guest-path-final-*-buildkernel.log` files. This is
interpreter validation; matched live host/guest execution is still open.

Guest `inet_ntoa`, `inet_ntoa6`, and `inet_ntop` now discard an IPv4 or IPv6
result when its translated source faults after access checking. `inet_ntop`
also rejects a noncanonical 64-bit address-family value before casting it to
`int`. The source-extracted guest-builtin fixture covers valid IPv4 and IPv6
formatting, cross-page guest read failures, and the invalid family. All 65
native port suites passed under
`/usr/obj/5BSD-hypertrace-validation/guest-inet-native-port/`; current-source
`-j16` GENERIC builds passed on amd64, arm64/aarch64, and riscv/riscv64 in
the `guest-inet-*-buildkernel.log` files. Live guest execution remains open.

Virtual-probe `printm` now fails before dereferencing its untagged two-word
memref, even if a guest program assembled that record in scratch without
calling the already-blocked `memref()` builtin. Virtual-probe `sym`, `mod`,
`usym`, and `umod` also fail rather than resolving a guest address in
the host kernel or process symbol context. Source-extracted action fixtures
verify rejection before a forged `printm` pointer or host process is read,
and preserve the host action paths. All 66 native port suites passed under
`/usr/obj/5BSD-hypertrace-validation/guest-symbol-actions-native-port/`;
current-source `-j16` GENERIC builds passed on amd64, arm64/aarch64, and
riscv/riscv64 in `guest-symbol-actions-*-buildkernel.log`. Guest symbol
resolution remains an implementation gap for gate 9. Virtual-probe `uaddr`
now carries the host-attested VMID, guest-reported PID, and raw guest address
in the existing two-word action record. Both libdtrace consumer paths and the
`%a` printer render that record as a numeric guest VM/PID/address without
looking up host process symbols. Missing guest arguments and denied process
privilege leave the record unpublished; host `uaddr` retains its prior path.
The source-extracted action fixture, all 96 native port suites, and a
formatter check against built amd64 libdtrace passed under the validation
root's `guest-uaddr-*` paths. Current-source `-j16 buildworld` and GENERIC
kernel/module builds also passed for amd64, arm64/aarch64, and riscv/riscv64
in the `guest-uaddr-*-buildworld.log` and `guest-uaddr-*-buildkernel.log`
files. This does not provide guest symbol names or matched live guest
execution.

An imported consumer's HPI1 program announcement now runs its initial
activated-import census once per authenticated connection. An announcement
arriving during ordinary HCR1 admission replay is deferred until that replay
opens; an exact retry after a successful census cannot append duplicate HCR2
jobs. Imported jobs are also keyed by ticket and receipt on each consumer
connection, so an exact activation retry or a race with the HPI1 census
cannot publish the same pending recipient twice. A fresh census keeps keys
only for pending durable results and prunes terminal ones. Imported, ordinary
consumer-replay, and local outbound-replay queues arm their write event while
holding the job-list lock, before publishing jobs; a failed `kevent` leaves
no jobs for a retry to duplicate. The host-ingress and outbound-replay
fixtures cover early and repeated announcements, exact activation retry,
terminal-key pruning, event-arm failure, and successful retry. All 36
sanitized daemon suites pass under
`/usr/obj/5BSD-hypertrace-validation/import-queue-final-native-daemon/`;
current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
riscv/riscv64 in the `import-queue-final-*-buildworld.log` files. The source
accepted-ingress PREPARE and nonempty destination restore fences remain in
force.

The virtual-program hypercall transform now captures high probe arguments
used by predicates and every action DIFO. Direct `arg5` through `arg9` loads
capture their exact slots; computed `args[]`, array-address, and dynamic
translator access capture all five stack slots once per probe. This removes
the old backwards `setx` guess, which read a constant-table index as an
argument value and misread the LDGA variable field when its index register
was nonzero. The source-based transform fixture checks the generated loads,
their deduplication, hypercall placement, and a non-argument array case; it
passes under `/usr/obj/5BSD-hypertrace-validation/high-args-vprog/`.
Current-source `-j16 buildworld` passes for amd64, arm64/aarch64, and
riscv/riscv64 in the `high-args-fixed-amd64-buildworld.log` and
`high-args-final-*-buildworld.log` files. This closes the identified
argument-capture gap in gate 9; other guest DIF semantics and matched live
execution remain open.

A failed restore that has published MUTATE now has a separate, durable reset
path. Protocol 66 adds an attested RESET_MUTATION request from a distinct
replacement VMM. The daemon first proves the old destination epoch retired
and that no capability, execution-start, or rekey-applied witness exists;
it then fsyncs an exact HTH2 reset marker before removing only pending
inbound/outbound import state and returning the ticket to committed. The
normal phase reader refuses a marked ticket. Startup replays a marked
rollback before other handoff audits, including the crash window with both
mutating and committed phase files. Bhyve asks for this reset only after
explicit NAKs to both rebind BEGIN and the read-only destination STATUS;
an uncertain reset reply stops restore and is left for a later exact retry.
The focused restore preflight and 101 native port suites pass under the
validation root's `mutating-reset-restore-preflight-final/` and
`mutating-reset-v3-native-port/` paths. The sanitized native daemon build and
all 40 suites pass under `mutating-reset-v3-native-daemon/`. This is
component evidence, not a live VM recovery claim. Current-source `-j16`
development world builds pass for amd64, arm64/aarch64, and riscv/riscv64
in `mutating-reset-final-*-buildworld.log` under the same validation root.
Nonempty import promotion, foreign execution leases, and matched live
restore remain open.

The nonempty claimed-ticket rebind planner now requires every cleanup named
by the source cut to remain durably queued under the old destination. A
missing old cleanup returns `EPROTO` before HRI1/HRP1 publication instead
of letting the proposed VM acquire cleanup authority without the old
receipt. The handoff-control fixture covers the missing receipt, exact
repair, and subsequent rebind. The sanitized native daemon build and all
40 suites pass under `rebind-cleanup-owner-v2-native-daemon/`; current-source
`-j16` development world builds pass for amd64, arm64/aarch64, and
riscv/riscv64 in `rebind-cleanup-owner-*-buildworld.log` under the validation
root. The atomic nonempty journal-and-owner commit is still unfinished.

HRP1 is now decoded into a typed destination inventory when read, and the
reader re-encodes that inventory to require an exact canonical round trip.
This preserves the proposed delivery, KILL, cleanup, ingress-presence, and
revocation identities for a later crash-recovery transaction without relying
on the publisher's in-memory plan. It rejects invalid HTD5 identities,
out-of-range KILL PIDs, zero cleanup delivery IDs, and duplicate delivery
journal keys even when their record and outer-plan digests have been
recomputed. The handoff-control fixture exercises the malformed cases and
the valid nonempty inventory. All 40 sanitized daemon suites pass under
`rebind-inventory-v2-native-daemon/`; current-source `-j16` development
world builds pass for amd64, arm64/aarch64, and riscv/riscv64 in
`rebind-inventory-*-buildworld.log` under the validation root. This does not
yet publish the nonempty journal or move its execution lease.

The nonempty rebind STAGE and PENDING boundaries now check the current
16,384-record budgets for proposed KILL and queued CLEANUP journals before
publishing HRP1 or pending deliveries. This is a headroom check under the
handoff lock, not a capacity reservation across later operations; the
future commit must check again immediately before its decision marker. The
handoff-control fixture fills the KILL journal, verifies STAGE refuses with
`ENOSPC`, removes those records, and verifies an exact rebind stages. All
40 sanitized daemon suites pass under `rebind-budget-v2-native-daemon/`;
current-source `-j16` development world builds pass for amd64,
arm64/aarch64, and riscv/riscv64 in `rebind-budget-*-buildworld.log` under
the validation root. Nonempty journal publication and owner recovery remain
open.

Guest `ucaller`, `ustackdepth`, and `ustack` now return an empty user context
for virtual probes that report PID 0, before reading a guest trapframe or
user page. This prevents a kernel thread from being labeled with a guest
user stack; guest register reads remain available. The source-extracted
three-architecture fixture checks zero kernel and user reads for PID 0 and
preserves ordinary PID 77 stacks. It passes under
`guest-pid0-userstack-focused/`; all 101 native port suites pass under
`guest-pid0-userstack-native-port/`. Current-source `-j16` GENERIC kernel
and DTrace module builds pass for amd64, arm64/aarch64, and riscv/riscv64
in `guest-pid0-userstack-*-buildkernel.log` under the validation root.
Guest symbol resolution, epoch-aware user-stack records, and matched live
guest execution remain open.

An exact nonempty rebind STAGE retry now accepts its already durable HRP1
inventory after PENDING has published inert destination HTD5 receipts. It
rebuilds the inventory with those receipts allowed, compares the complete
canonical plan, and retains the strict collision check when no HRP1 exists.
The handoff-control regression exercises STAGE after PENDING; all 40
sanitized native daemon suites pass under
`/usr/obj/5BSD-hypertrace-validation/rebind-stage-retry-native-daemon/`.
The amd64, arm64/aarch64, and riscv/riscv64 `-j16 buildworld` checks pass
in the matching `rebind-stage-retry-*-buildworld.log` files.
The nonempty journal-and-owner decision, recovery replay, and execution
lease remain unimplemented. In particular, HJB1 binds the original claimed
destination, so a future claim switch must preserve that source lineage
through a durable commit record before startup can validate it.

Guest user-memory DIF loads and `copyin`, `copyinstr`, `copyinto`, and
`copyout` now reject a virtual probe with PID 0 before any guest user-page
callback. A missing probe argument envelope also fails closed. PID 0 reports
`BADADDR` at the requested user address; an absent envelope reports `ILLOP`.
The source-extracted sanitizer fixtures check that a PID 0 probe performs
no guest user read or write. They pass under the
`guest-pid0-user-memory-{load,copyout,builtins}/` validation directories;
all 101 native port suites pass under `guest-pid0-user-memory-native-port/`.
Current-source `-j16` GENERIC kernel and DTrace module builds pass for
amd64, arm64/aarch64, and riscv/riscv64 in the matching
`guest-pid0-user-memory-*-buildkernel.log` files. This does not establish
guest symbol resolution or matched live VM behavior.

Protocol 67 adds an attested, read-only nonempty rebind preflight after
PENDING. The daemon recomputes the exact HRP1 inventory from the old claimed
source cut, requires every proposed HTD5 to remain pending, checks current
KILL and queued-cleanup headroom, and verifies the old VMM epoch is retired.
A missing receipt, changed plan, or still-live old epoch refuses the request
without moving ownership. Bhyve now invokes this census before its deliberate
`EOPNOTSUPP` nonempty restore fence. The handoff-control, protocol, bhyve
socket, and restore-coordinator fixtures pass in the 40 sanitized daemon and
101 native port suites under the `rebind-nonempty-preflight-*` validation
directories. The amd64, arm64/aarch64, and riscv/riscv64 `-j16 buildworld`
checks pass in the matching logs. HRC2, atomic journal promotion, original
HJB1 lineage across claim replacement, and crash replay remain to be coded.

The daemon wire decoder now refuses KILL and KILL_APPLIED headers with a
reserved or negative PID, a missing or out-of-range VM ID, zero epoch, or
empty source ID before exposing the header to any reader. The protocol
fixture checks each malformed identity without changing the caller's prior
decoded result; bhyve-socket and library-transport fixtures now use valid
KILL identities. All 40 sanitized daemon suites and 101 native port suites
pass under `kill-header-canonical-final-native-daemon/` and
`kill-header-canonical-final2-native-port/` in the validation root. Current
source `-j16 buildworld` passes for amd64, arm64/aarch64, and riscv/riscv64
in the matching `kill-header-canonical-*-buildworld.log` files. This closes
the KILL header identity gap, not the nonempty restore commit or live
host/guest qualification.

The nonempty rebind path now has a fixed HRC2 decision-candidate format.
It binds the original HRI1/claimed HTH2 lineage, the exact HRP1 digest,
and the HJB1 stage digest for a foreign cut; a local cut requires a zero
stage digest. The decoder rejects wrong versions, noncanonical padding,
changed token, malformed HRI1, inconsistent stage presence, and a torn
checksum without changing its output. Read-only nonempty preflight derives
the HJB1 digest from the same validated stage read used to reconstruct
HRP1, encodes the candidate in memory, and round-trips it before returning.
The existing handoff-control fixture exercises this preflight for a nonempty
cut; the protocol fixture checks both local and foreign record encodings.
All 40 sanitized daemon suites pass under `hrc2-format-final-native-daemon/`;
the fixture's journal-heavy 10-second alarm was raised to 30 seconds after
an overloaded run timed out during ordinary fsyncs. The amd64,
arm64/aarch64, and riscv/riscv64 `-j16 buildworld` checks pass in the
`hrc2-format-*-buildworld.log` files. HRC2 is still memory-only:
durable publication, journal replay, owner replacement, and execution
lease remain open, so bhyve's nonempty restore fence stays in place.

HRC2 preflight now uses an independent readback path instead of merely
decoding its freshly encoded candidate. The reader reconstructs the
original claimed HTH2 from HRC2's HRI1, validates the proposed destination
and exact HRP1 bytes on disk, reloads HJB1 and compares its stage digest,
rebuilds the canonical replacement inventory, and requires every proposed
HTD5 to remain pending. It does not take the current claimed filename as
the original source identity. The source-journal fixture now calls the real
nonempty preflight after STAGE and PENDING, covering a positive readback of
the foreign HJB1 cut, HRP1 plan, and pending replacement HTD5. Its focused
ASan/UBSan run passes under `hrc2-owner-lineage-focused-final/`. The 40 sanitized
daemon suites pass under
`hrc2-readback-native-daemon/`. Current-source `-j16 buildworld` passes
for amd64, arm64/aarch64, and riscv/riscv64 in the matching
`hrc2-readback-*-buildworld.log` files. The reader has not yet been used
to replay a durable HRC2 after claim replacement;
journal promotion and execution lease remain fenced.

Guest `copyinstr` and `copyoutstr` now check string addresses as each byte
is touched. A NUL at the highest representable address succeeds without
requiring the unused maximum string range to be addressable; fixed-length
copies still reject an overflowing full range before any guest callback.
The source-extracted guest builtins and copyout fixtures cover the terminal
byte, and all 101 sanitized native port suites pass under
`guest-string-boundary-native-port/`.
Current-source `-j16 buildkernel` passes for amd64, arm64/aarch64, and
riscv/riscv64 in the matching `guest-string-boundary-*-buildkernel.log`
files under the validation root. This checks compilation, not guest runtime
behavior or the remaining guest-memory operations.

The HRC2 readback now checks the on-disk claimed HTH2 and capability
witness against the exact original or proposed destination before returning
its replacement plan. A third owner, missing witness, or changed witness
fails closed, including during an interrupted two-file owner replacement.
The reader leaves all caller outputs unchanged until these checks finish.
It reads those files directly so the check cannot recursively invoke commit
recovery. All 40 sanitized native daemon suites passed under
`hrc2-owner-lineage-native-daemon/` before the final output-ordering change;
the final-source focused source-journal fixture passes under
`hrc2-owner-lineage-focused-final/`. Final-source `-j16 buildworld`
passes for amd64, arm64/aarch64, and riscv/riscv64 in the matching
`hrc2-owner-lineage-final-*-buildworld.log` files. This is a replay prerequisite;
HRC2 publication, journal promotion, startup replay, and execution lease
remain unfinished, and the new negative owner cases still need a focused
fixture.

HRC2 readback is now split at the commit boundary. An immutable snapshot
reader reconstructs the original HTH2, decodes canonical HRP1 inventory,
reloads the exact HJB1 cut when foreign, requires its HJR1 completion
marker, and accepts only the old or proposed owner/capability witness. It
does not require proposed HTD5 receipts to remain pending, so it can be used
after promotion begins. The precommit reader separately rebuilds the plan
from current source journals and requires every proposed receipt to remain
pending before returning. The focused foreign-rebind fixture passes under
`hrc2-snapshot-focused/`; all 40 sanitized daemon suites pass under
`hrc2-snapshot-native-daemon/`. Current-source `-j16 buildworld` passes for
amd64, arm64/aarch64, and riscv/riscv64 in the matching
`hrc2-snapshot-*-buildworld.log` files. The source-journal fixture now
includes the private daemon reader in its test translation unit and checks
HRC2 after a proposed HTD5 advances to accepted, after the capability and
claimed HTH2 are replaced in either valid intermediate order, and after a
third owner is substituted. The immutable snapshot survives the valid
states and rejects the third owner without changing caller outputs; the
precommit reader rejects the advanced receipt. The focused ASan/UBSan case
passes under `hrc2-postpromotion-focused/`, and all 40 sanitized daemon
suites pass under `hrc2-postpromotion-native-daemon/`. No HRC2 decision is
durable yet, and journal
promotion, startup replay, execution lease, and bhyve's nonempty restore
fence remain open.
