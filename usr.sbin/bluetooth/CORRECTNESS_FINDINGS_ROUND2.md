# Bluetooth stack — correctness review, new round (2026-08-21)

## FIXES APPLIED (2026-08-21) — all build clean under `-Werror -Wall -Wextra
## -Wthread-safety`; touched parsers re-fuzzed clean under ASan+UBSan

Criticals: peripheral `bearer_fd`/EATT-fd init; persisted-GATT `value_maxlen`
backing + Execute-Write NULL guard; meshd manager `iv_index` sync (tick +
beacon + DevKey-originate).  Majors: persisted-GATT handle-collision reject;
SMP same-X reflection check (all 4 SC flows, via `smp_validate_public_key`);
SMP one-sided SC-OOB r-value + `have_peer`/`have_local` plumbing + responder
OOB wiring; PRIVACY-off keeps resolution on when reslist non-empty; mesh scan
re-asserted after power-cycle / fail-safe reset; meshctl EVENT-line skip;
meshd app-events peek-before-pop; `bt_devinquiry` `free(*ii)`; mesh ADV-drain
one-PDU-at-a-time pacing (Max_Ext_Adv_Events + Adv Set Terminated); MBW_ADV_MAX
29; all-zero-BlockAck cancel.  Concurrency: SB-handshake seq_cst (F1, all 4
sites); `periph_gatt_db` under `gatt_db_lock` (F2); pairing-worker ATT security
triple under `att_sec_lock` (F3); `local_ids` reset under `conns_lock` (F4);
ATT `SO_SNDTIMEO` (F5).  HCI/GAP: ISO Remove Data Path bitmask; Create-CIS
`con_handle_valid` guard; legacy mesh-burst disable-before-params;
`hci_wait_encryption` Command-Status fast-fail; `adv_kind_to_ext_props` legacy
PDU bit; `IPC_ADV_SET_PARAMS` quiesce/reconfigure/restore; Create-Connection-
Cancel 0x0C treated as success.  bluedctl address-type: daemon-side unique-
address fallback (`blued_conn_by_peer_cmd`).

meshd batch (all independently skeptic-verified CONFIRMED, then fixed):
NB-2 beacon KR phase gate (>=PHASE_2); NB-3 Relay-off honored via
managed_flood_relay; NB-4 Status replies use node default_ttl; NB-5 DevKey
nonce IV = mesh_iv_tx_index (2 sites); NB-11/12 friendship RX/Update IV from
iv_index + LPN IV adoption from Friend Update; NB-16 config-client in-flight
guard; NB-17 NetKey Delete of in-use primary -> Cannot Remove; NB-18 Model Pub
Set AppKeyIndex validation + Publish-TTL fix; NB-19 peer Link Close treated as
provisioner failure; NB-20/21 pending-block overlap in range_used + clean
teardown on commit failure; NB-22 PB-ADV Link Close emitted on success/abort;
NB-23 PB-GATT cancel guarded on doneness; NB-25 SEQ reset on beacon-driven IV
completion; NB-27 Friend Set honored; NB-28 HB Pub Set validate-before-commit;
NB-29 AppKey Delete NetKey/binding checks + clear dangling publications.

meshd batch, second wave (unreleased -> persistence formats changed freely):
NB-6 (per-line SEQ reserve before origination); NB-7 (IV dwell now anchored on
persisted wall-clock via sim wall_now, survives restart); NB-15 (cfg status
poll verb); NB-16 in-flight txn guard; NB-20 (device element count validated at
commit, over-large device refused); NB-26 (friendship RPLs persisted, format
v8); NB-30 (RPR Link Close acked with Link Status); NB-32 (empty GATT
notification ignored, not a link teardown).

Backwards-compat removals (unreleased, no down-level support): dead
ATT_OP_SIGNED_WRITE_CMD / GATT_PROP_AUTH_SIGNED_WRITE aliases; meshd persist
v2-v7 migration collapsed to v8-only (+ devkey_migrated flag removed); mesh
manager v2 read path removed; bond-DB v4 read path removed (v5-only); legacy
absolute bond-secret-file migration removed (safety refusal-to-remint kept);
mesh_rpl_net_receive_ivupd dead iv_update ABI param removed.

Still open (large protocol build-outs; need the mesh hardware/bhyve rig to
validate, unsafe to land blind): NB-13 (friendship security-credential
derivation + routing on TX/RX), NB-14 (multi-node NetKey key-refresh
distribution loop + kr_ack wiring). Lower-value residue: NB-16 echoed-field
validation (opcode-specific; in-flight guard already closes the main hazard),
NB-31 (RPL flush-before-effect vs 500ms debounce), NB-33 (provisioning
error-code conformance nits). HCI/GAP races #3/#5/#11/#15 remain (hardware-
dependent).

Still open (deferred, see notes at end): HCI/GAP races and restructurings
(#3 privacy-toggle scan quiesce, #4 resolving-list capacity, #5 enc send→wait
gap, #10 discoverable param restore, #11 bonded-reconnect LTK race, #13
peripheral pairing window, #14 ext-adv terminal fragment, #15 scan filter
clobber); the meshd finder-only batch (NB-*, HCI/GAP finder items) pending
independent verification; SAR-retransmit frozen-SEQ (needs SAR-TX re-origination
restructure).

---


Correctness-only pass (NOT security) over blued, meshd, bluedctl, meshctl, and
the libmesh/libbluetooth internals they call. BlueZ + the on-disk Core/Mesh
specs are the reference. Every item here is NEW — cross-checked against and
excluded from `CORRECTNESS_FINDINGS.md` and `REVIEW_FINDINGS.md`.

Method: 6 per-subsystem finder agents → independent adversarial verification of
the load-bearing findings → this synthesis. The meshd and HCI/GAP finders ran
their own internal adversarial verification; the SMP/ATT-GATT/daemon-core/CLI
findings below carry an explicit second-reviewer verdict.

Legend: **[V]** = independently verified CONFIRMED; **[V~]** = partially
confirmed (see note); severity is corrected post-verification.

---

## CRITICAL

- **[V] blued peripheral notifications/indications misrouted to fd 0.**
  `blued_peripheral.c` accept path `calloc`s the `att_conn` and sets `fd/mtu/…`
  but never `bearer_fd = -1` (every other constructor — `att_open`,
  `att_open_fd`, the central path at `blued_central.c:1968` — does). `calloc`
  leaves `bearer_fd == 0`; `att_server_send()` (`att_server.c:80`) selects
  `bearer_fd >= 0 ? bearer_fd : fd`, so it `send()`s to **fd 0**. Request
  dispatch masks it (it overwrites/restore-saves `bearer_fd`), but every
  out-of-dispatch server PDU — all client-API notifications/indications
  (`ctl_gatt.c:1857/1862`) and Service Changed (`ctl_gatt.c:1168`,
  `blued_peripheral.c` reconnect) — goes to fd 0. Peripheral notify/indicate is
  dead (ENOTSOCK after daemonize; leaks to the tty in foreground). Fix: set
  `ac->bearer_fd = -1` (and `write_cmd_bearer_fd = -1`, EATT fds) after calloc.

- **[V] Persisted GATT attributes reloaded with full `value_maxlen` but only
  `value_len` bytes of backing.** `ctl_gatt_load_persisted_services`
  (`ctl_gatt.c:1268-1286`) sets `value_maxlen = r->value_maxlen` (≤512) but only
  charges `val_used += vlen` (vlen ≤64), and leaves `value == NULL` when
  `vlen==0`. Write bounds checks trust `value_maxlen`. After ONE restart:
  (a) an empty writable char → `value==NULL, maxlen=512`; Prepare+Execute Write
  memcpy's to NULL at `att_server_dispatch.c:1660` (the execute apply loop lacks
  the `value==NULL` guard `handle_write` has) → remote NULL-deref crash;
  (b) a short-valued char → write ≤maxlen overruns the short arena backing into
  adjacent attributes; (c) `attdb_remove_service` compaction copies
  `max(maxlen,len)` from short backing. (a) is unconditional; (b)/(c) need the
  attr to carry a 1–64B value at save time with large maxlen. Fix: clamp
  `value_maxlen = vlen` on load (or re-back the full maxlen) + NULL-guard the
  execute apply loop.

- **[V] meshd manager `iv_index` frozen at network creation → boot-brick +
  DevKey nonce reuse.** `mgr->iv_index` is written only in `mesh_mgr_create`
  (=0) and the two load paths; nothing updates it when the node IV advances
  (SEQ-exhaustion tick or adopting a peer beacon at n+1). But every
  manager/Config-Client DevKey seal/open uses `mgr->iv_index`
  (`mesh_manager.c:871/890`, `meshd_node.c:853`). After one IV Update:
  (a) persist stores node=n+1, mgr=n; next boot `decode_body`
  (`meshd_persist.c:1196`) sees `mgr->iv_index != mesh_iv_tx_index` → returns
  -1 → `errx(1,"node state corrupt")` — every provisioner that lived through an
  IV Update refuses to boot; (b) pre-restart, DevKey messages seal at IV=n with
  SEQ reset to 0 → CCM device-nonce reuse, and peers derive from n+1 so Config
  traffic fails. Provisioner/manager nodes only. Fix: sync `mgr->iv_index` from
  the node IV on every advance (or read it live).

- **meshd Config Relay-off never honored; every node relays unconditionally.**
  (internally verified, high) `meshd_setup_node` unconditionally
  `mesh_sim_set_df(self,1)` → `managed_flood_relay=1`; `node_recv_net` always
  takes the DF branch, and `mesh_df_forward_decide` falls back to FLOOD purely
  on `managed_flood_relay`, never consulting `relay.enabled`. `mesh_sim_set_relay`
  doesn't touch `managed_flood_relay`, so Config Relay Set = 0 has no effect —
  the node keeps re-flooding while Relay Status reports "off".

- **meshd Config-Server Status replies hardcode TTL 5, ignoring Default TTL.**
  (internally verified, high) `node_deliver_access` (`mesh_sim.c:1281/1341`)
  sends all foundation and model Status replies at literal TTL 5; a Config
  Client >5 hops away on a Default-TTL-20 network sends a request that arrives,
  is processed, but whose Status dies after 5 hops → distant nodes silently
  un-commissionable.

*(The prior meshd finder also reported, internally verified, several further
deterministic criticals/majors: live-beacon KR-phase bug re-introduced
(`meshd_node.c:4157`), nonce-IV mismatch across layers, friendship IV/credential
breakage (NB-11/12/13), NetKey-Delete of the in-use key returns Success
(NB-17), Model-Pub-Set accepts unknown AppKeyIndex (NB-18), provisioning wedges
on peer Link Close / commit failure / transport-fail-before-commit
(NB-19/21/23), Capabilities element-count ignored → unicast overlap (NB-20),
config-client results unobservable + txn aliasing (NB-15/16). See the per-agent
detail; these were not independently re-verified in this synthesis but carry the
finder's own adversarial pass.)*

---

## MAJOR — verified

- **[V] SMP: missing same-X-coordinate public-key check (CVE-2020-26558
  reflection countermeasure).** All four SC flows (`smp_sc.c:405/807/1287/1779`)
  validate on-curve/not-infinity/not-debug-key via `smp_validate_public_key` but
  never compare the peer's X against the local X. Core 6.3 Vol 3 Part H
  §2.3.5.6.1 mandates failing with DHKey Check Failed when the two public keys
  share an X and neither is the debug key. Absence lets an MITM reflect our
  public key in SC Passkey Entry and recover the passkey bit-by-bit across the
  20 commitment rounds (before the DHKey check runs). Fix: constant-time
  `memcmp(peer_pk+1, our_pk+1, 32)` → Pairing Failed on match.

- **[V] SMP: one-sided SC OOB r-value keyed on local import instead of the
  peer's OOB flag.** `smp_sc.c:1042-1049`/`1472-1479` select the f6 r-value from
  `sc->oob->sc != NULL` ("we imported peer OOB") instead of the peer's OOB flag
  `preq[2]`/`pres[2]` ("peer received our OOB"). In the legal asymmetric case
  (peer got our OOB, we got nothing) `r_eb`/`r_ea` is memset to 0 while the peer
  computed its check with our nonzero published random → DHKey Check Failed every
  time. Compounded: `blued_oob_take` (`ctl.c:1374`) only loads `local_random`
  inside `if (e->has_sc)`, and `blued_peripheral.c` never wires `sc.oob` at all
  (so inbound SC-OOB is doubly broken). Distinct from the fixed C1-M2 (opposite
  direction). Fix: gate on the peer OOB flag; load local_random whenever local
  OOB was generated.

- **[V] blued: mesh bearer RX permanently dead after adapter POWER off/on.**
  Mesh passive scan is enabled only on the subscriber 0→1 edge (`mesh_scan_ref`,
  `ctl.c:1037`). `blued_adapter_controller_invalidated` clears
  `mesh_scan_active`; the power-on path (`blued_adapter_init`) never re-asserts
  it while `mesh_subscribers>0`, and `blued_mesh_scan_resume` skips adapters
  with `!mesh_scan_active`. After POWER off/on (or a fail-safe HCI reset) mesh
  RX is dropped forever until an UNSUBSCRIBE→SUBSCRIBE cycle. Fix: re-assert mesh
  scan on power-on when subscribers remain.

- **[V] blued: PRIVACY-off orphans a populated resolving list.**
  `blued_privacy_program` `!on` branch (`blued.c:1387-1394`) disables address
  resolution and returns, leaving a non-empty resolving list with resolution
  off — contradicting the code's own H-H5 policy
  (`blued_reslist_restore_resolution`: `enable = privacy || reslist.count>0`).
  A bonded peer using RPAs can no longer be resolved for auto-reconnect until
  privacy is re-enabled or a RESOLV verb runs. Fix: keep resolution on whenever
  `reslist.count>0`.

- **[V] blued: persisted runtime GATT services replayed with stale absolute
  handles.** `ctl_gatt_load_persisted_services` appends persisted attrs with
  their original absolute handles and only bumps `next_handle` forward — no
  check that `r->handle >= next_handle`, no dup detection, no renumber. If the
  base DB grew between runs (config service added, or a built-in added by an
  upgrade), persisted handles collide with / interleave the base range →
  corrupts find-by-handle, range walks, group-end derivation, and the DB hash.
  Precondition: base handle range changed across runs. Fix: reject/renumber
  persisted attrs whose handle falls below `next_handle`.

- **[V] bluedctl: address type hardcoded public for every per-device command
  except connect/accept-list.** All of read/write/discover/subscribe/pair/
  disconnect/rekey/connparams-update/… call `ble_addr_parse(argv[1], 0, &addr)`
  (type 0). The daemon matches connections by exact `(addr, addr_type)`
  (`conn.c:527`). A peer connected with a random address — most real BLE
  devices — connects fine (connect takes public|random) but can never be
  addressed afterwards → IPC_ERR_NOT_CONN. Fix: accept `[public|random]` on all
  per-device verbs (or track the connected addr_type).

- **[V] meshctl: unsolicited EVENT lines desync interactive mode after
  app-register.** `meshctl_exchange` (`meshctl.c:424`) reads one line and treats
  it as the reply; meshd interleaves async `EVENT …` lines onto the same tx
  stream (`meshd.c:404`, flushed every tick) for any client that registered a
  model. After `app-register`, an EVENT arriving before the next command's
  OK/ERR is misread as that command's reply → permanent off-by-one desync. Fix:
  skip `EVENT ` lines and keep waiting for OK/ERR.

- **[V] meshd: app-events reply overflow destroys popped events.**
  `ctl_app_events` (`meshd_ctl.c:221`) writes `OK events=<total>` up front, then
  destructively pops each event before the fit check; an event that doesn't fit
  the 2048B reply is popped and lost, the function returns -1, and the caller
  (`meshd.c:449`) ignores the return and queues the partial reply with a wrong
  count. Fix: peek-then-pop (or re-queue on overflow); report the count actually
  included.

- **[V~] SMP: LTK Request Reply issued before the LTK Request event.** All
  responder flows (`smp_legacy.c:218`, `smp_sc.c:1523/1951`) fire
  `hci_le_ltk_request_reply` immediately after the last SMP PDU, without waiting
  for the LE LTK Request event (subevent 0x05). Per Core Vol 4 Part E §7.8.25
  the command is only valid in reply to that event → a spec-strict controller
  returns Command Disallowed → the responder aborts an otherwise-good pairing.
  **Partial:** confirmed as a real controller-dependent ordering defect (masked
  by the virtual-HCI test rig); the associated "event handler negative-replies
  during first-time pairing" leg was refuted as an *active* failure — the
  `hci_devreq_mutex` held across `hci_wait_encryption` keeps the event loop from
  consuming the LTK Request, so it's a latent missing-guard, not a live bug.

---

## MAJOR — HCI/GAP (internally verified by the finder, high confidence)

Reported by the HCI/GAP finder, which ran its own adversarial pass ("all 28
survived"). Not independently re-verified in this synthesis; listed for triage.

- Remove ISO Data Path passes the §7.8.109 Setup *enum* to a validator/command
  expecting the §7.8.110 *bitmask* → input path never removed, output removal
  targets the wrong direction (`iso.c:289`).
- Create CIS reads `conn->con_handle` without the `con_handle_valid`/ACTIVE
  guard every other consumer uses → CIS on a stale/zero handle (`iso.c:454`).
- Runtime PRIVACY toggle never quiesces mesh scan / pending create-connection →
  Set Random Address / Set Addr Resolution Enable return Command Disallowed →
  privacy un-enableable while mesh runs (`blued.c:1379+`).
- Resolving-list capacity never read (LE Read Resolving List Size unused); the
  Nth IRK bond over controller/shadow capacity makes blued `err(1)` at startup
  and blocks runtime privacy (`blued.c:1301+`).
- Encryption trigger→`hci_wait_encryption` gap lets the event loop steal the
  one-shot Encryption Change → pairing reported FAILED on an encrypted link.
- `hci_wait_encryption` admits Command Status but never inspects it → a failed
  LE Enable Encryption burns the 5–10s timeout holding the adapter mutex and
  dropping all other events (`hci_misc.c:93`).
- Legacy fallback of `hci_mesh_adv_burst` sets adv params while advertising is
  enabled and never disables → mesh bearer wedges on legacy controllers
  (`hci_adv.c:915`).
- `IPC_ADV_SET_PARAMS` reconfigures the enabled set → Command Disallowed in the
  default peripheral state, mislabeled INVAL (`ctl.c:4316`).
- `adv_kind_to_ext_props` maps legacy-equivalent kinds to non-legacy extended
  properties → adv-data + scan-response combination becomes illegal on the ext
  path (`hci_adv.c:588`).
- Discoverable overlay reprograms set-0 params but the restore path never
  restores them → operator's configured params silently replaced after
  discoverable on→off (`blued.c:2785/2661`).
- Bonded-peripheral reconnect: LTK Request answered with negative reply when the
  event beats the setup thread's handle validation on the legacy Connection
  Complete path (`blued_event.c:396`).
- Create Connection Cancel conflates CONNECTING with "initiating" and treats the
  spec-mandated Command Disallowed as fatal → power-off fails, RPA rotation
  wedges, operator CONNECT can evaporate (`blued.c:1849/3046`).
- Peripheral accepts inbound pairing only in a single 5s post-connect window and
  never for a peer it already has a bond for → ordinary iOS/Android re-pair and
  late-pair flows fail (`blued_peripheral.c:470`).
- Terminal fragment of a fragmented ext advertising report is AD-parsed as a
  fresh AD boundary → fabricated name/UUIDs/mfr attributed to the device
  (`hci_scan.c:930`).
- Synchronous scan narrows the shared HCI socket filter to LE-only and discards
  non-adv LE subevents → Connection/Disconnection/LTK/Encryption events during a
  scan are permanently lost (`hci_scan.c:601/691/711`).

---

## MAJOR — round 2 (libraries + integration seam)

- **libbluetooth: `bt_devinquiry` frees an interior pointer → heap corruption.**
  `hci.c:533,539`: `i` is the `calloc` base but is advanced (`i++`) per copied
  INQUIRY_RESULT response; if a later `bt_devrecv` returns error/short before
  INQUIRY_COMPL, the cleanup calls `free(i)` on `base+k` → UB / heap corruption
  (and leaks the real base) in any process doing device inquiry (`hccontrol
  inquiry`, discovery tooling). Reachable when ≥1 device is found and the
  completion event is late/short. Inherited from upstream FreeBSD but shipping.
  Fix: `free(*ii); *ii = NULL;` on both cleanup paths.

- **blued↔meshd: mesh ADV drain collapses a PDU burst onto one shared adv set.**
  meshd hands the bearer every ready mesh PDU back-to-back (up to 64 PB-ADV
  packets per `meshd_provisioner_drain`; all queued Net PDUs per
  `meshd_drain_tx`), one `IPC_MESH_ADV_SEND` each. blued's `mesh_adv_drain`
  (`ctl.c:1180`) calls `hci_mesh_adv_burst` for every queued frame in a
  synchronous loop; enable-advertising returns on Command Complete without
  airing even one event, and PDUs arrive < one 100ms interval apart, so each
  reprogram preempts the previous PDU. Only the **last** PDU of any back-to-back
  group airs — while meshd counts every one as `tx_frames`. Breaks PB-ADV
  provisioning of any device whose Public Key/data segments (segments 1..N-1
  never sent → reassembly/FCS fails → provisioning stalls) and silently drops
  relayed/originated bursts. Distinct from the known never-terminated-burst
  item. Fix: pace the drain — air one frame for a bounded duration/Max-Ext-Adv-
  Events before advancing (off Adv Set Terminated or a timer).

## MINOR — round 2

- **meshd TX cap (31) exceeds blued's accept ceiling (29).**
  `meshd_bearer_blued.c:36` `MBW_ADV_MAX=31` vs `blued/ctl.h:155`
  `MESH_ADV_PDU_MAX=29`. A 30–31B PDU is accepted locally, framed, sent
  fire-and-forget (reply ignored), and dropped by blued with IPC_ERR_INVAL —
  meshd records it as aired. Latent (conformant mesh PDUs ≤29). Fix: set
  `MBW_ADV_MAX=29`.

- **libmesh SAR: retransmission re-sends segments with the frozen original
  network SEQ.** `mesh_sim.c:255-257` re-enqueues byte-identical cached
  ciphertext on a SAR retransmit without advancing `node->seq`. Per MshPRT
  3.5.3 every transmitted Network PDU (incl. a retransmitted segment) consumes a
  fresh SEQ; only SeqZero/SeqAuth is held constant. A conformant receiver drops
  the byte-for-byte replayed (SRC,SEQ,IVI) at the network cache/RPL before
  reassembly → never re-emits the block-ack → sender retransmits frozen dups to
  exhaustion. Self-heals within this library's own receiver (local delivery not
  gated on the seen verdict), masking the wire non-conformance. Fix: re-encrypt
  each missing segment with `node->seq++` (SeqZero/SegO/SegN unchanged).

- **libmesh SAR: all-zero BlockAck treated as "retransmit all" instead of
  cancel.** `mesh_sim.c:1911-1914`: a Segment Ack with BlockAck==0 leaves
  `blockack` unchanged and requeues every segment. Per MshPRT 3.5.3.4 an
  all-zero BlockAck cancels the segmented transmission (e.g. busy/OBO peer). Fix:
  `if (ack.blockack == 0) s->used = 0;` (cancel) instead of requeue.

## MINOR

Numerous lower-severity conformance/robustness items were reported across all
subsystems (CSF clear-bit not rejected; Read Blob at offset==len returns
Attribute Not Long; SIGHUP reload reverts CLI/persisted/runtime policy;
RESOLV_REMOVE doesn't resolve RPA→identity; ECBFC partial fd-handout hang;
CLOCK_REALTIME pairing-prompt deadlines; persist-format version bump discards
state; discover prints only uuid16; heart-rate/thermometer READ instead of
subscribe; profile-read/scan timeouts exit 0; interactive tokenizer drops >16
tokens; several meshd heartbeat/HB-pub/HB-sub state-mirror and validation gaps;
RPL persistence debounce window; zero-length GATT notify tears down proxy link;
etc.). See the per-agent outputs for the full enumerated list with line refs.

---

## Round 3 — different-dimension review (concurrency / memory-safety / dynamic)

A second review pass along axes the spec-conformance review does not cover:
threading, memory lifetime, and actually building+sanitizing the code.

### Concurrency (NEW — 5 bugs)
- **MAJOR — store-buffering lost-wakeup strands deferred connection teardown.**
  `blued_event.c:1777`/`1131` (disconnect) vs `ctl.c:2484`/`2724` (worker retire).
  The `disconnect_pending` / `att_ops_active` handshake uses release/acquire on
  two distinct atomics; the StoreLoad (Dekker/SB) reordering it must forbid is
  still permitted, so on amd64/aarch64 main can read `att_ops_active` stale
  (defers) while the worker reads `disconnect_pending` stale (doesn't signal) →
  teardown stranded, conn stays ACTIVE with `con_handle_valid` (handle-reuse
  misroute of LTK/Encryption events). The C3-M1 fix corrected program order but
  left the memory order. Fix: seq_cst store+load (or a seq_cst fence) on both
  sides.
- **MAJOR — `periph_gatt_db` read by the peripheral setup worker under the wrong
  lock.** Worker holds only `bond_db_lock` while reading the DB
  (`blued_peripheral.c:730/754/772`); main mutates it under `gatt_db_lock`
  (`ctl_gatt.c:1482` attdb_copy on COMMIT, `blued.c:2939` SET_NAME). Different
  locks → a worker computing/persisting the DB hash can read a half-copied DB →
  torn hash stored in the bond, permanently breaking cache invalidation. Fix:
  take `gatt_db_lock` (nested in `bond_db_lock`) around the reads.
- **MAJOR — central pairing worker writes the ATT security triple without
  `att_sec_lock`.** `blued_central.c:258` (`att_conn_apply_encryption`) is the
  lone writer of `encrypted/authenticated/enc_key_size` not holding the lock;
  a concurrent main-thread Encryption-Change can interleave, and the lock-free
  reader `att_check_security_perms` observes a mixed state → wrong security gate
  on a live link. Fix: hold `att_sec_lock` around the call.
- **MINOR — `local_ids[]`/`controller_epoch` reset without `conns_lock`**
  (`blued.c:2348`): torn epoch / mid-memset read racing a setup worker; mostly
  masked by the epoch check.
- **MINOR — blocking `send()` held across `gatt_db_lock`** (`att_server.c:85`):
  a stalled peer blocks the event-loop thread inside the lock, stalling the
  whole GATT worker pool until the socket drains (priority inversion, not
  deadlock).

The lock hierarchy is otherwise acyclic and verified sound; condvars, refcounts,
the ISO registry, and bond-DB escapes are thread-safe.

### Memory-safety / lifetime
No NEW memory-safety bugs. The wire parsers are uniformly length-gated before
field reads; use-after-free/double-free/leak/overflow all traced clean. Five
latent hardening notes (bounds coupled to an invariant rather than the
destination buffer): `mesh_proxy.c` SAR append margin; `mesh_sim.c:1958`
friend-queue copy vs 16-byte transport; `try_decrypt` `cand[9]` exact fit;
Execute-Write apply re-lookup NULL-check; `smp_bond_import_record` unchecked
`num_report_maps`. `iso.c` transport remains the one uncertified boundary.

### Dynamic (build + sanitizers)
Environment has a working native FreeBSD toolchain. All blued/meshd/libmesh TUs
compile clean under `-Wall -Wextra -Wsign-compare` (one pre-existing dead
variable: `blued_event.c:837` unused `status`). The 23 libFuzzer parsers replay
**clean under ASan+UBSan over a 5248-input corpus** — no OOB/UAF/UB in any
wire-facing parser. `-Werror -Wthread-safety` is enforced by the build.

## Notable VERIFIED-CORRECT areas (no new bug)

SMP crypto byte-order (f4/f5/f6/g2/h6/h7, CTKD salts/keyids), key masking,
KNOB/key-size floors, §3.4 timer, IRK/identity (S-M1/M2), bond DB v4/v5
lifecycle. ATT client bearer selection, MTU exchange clamp, read-path packing
and MTU clamps, prepare/execute per-handle running-length, signed-write CMAC,
db-hash inclusion set, CCCD per-connection + bond persistence. HCI command/event
opcode selection and byte-exact packing, BTSnoop, LE-meta length gates.
Control-socket framing (partial read/write, SCM_RIGHTS single-close), client
lifecycle teardown + (fd,generation) async-reply gating, GATT worker pool
serialization, persist atomic-save/load validation. meshd SEQ block reservation,
main RPL, IV state machine, KR phase persistence, proxy SAR codec, secured
proxy-config PDU. libble framing/reply validation and byte order.
