# Bluetooth Stack — Correctness Bug List

Correctness-focused review (not a security review) of the Bluetooth/BLE/mesh code:
`usr.sbin/bluetooth/{blued,meshd,meshctl,bluedctl,bluectl,vhcitool}`,
`lib/libmesh`, `lib/libble`, `lib/libbluetooth`, `sys/netgraph/bluetooth/drivers/vhci`.

References: `/usr/src/bluetooth-specs/Core_Specification_6_3.txt`, `/tmp/MshPRT_v1.1.html`,
`/tmp/MMDL_v1.1.1.txt`, profile specs in `/tmp`.

Review method: repeated passes with changing focus (general correctness, spec
conformance, concurrency/state machines, arithmetic/endianness, error paths)
until a pass finds nothing new.

Severity: **P1** = wrong behavior likely in normal operation / crash;
**P2** = wrong behavior in realistic edge cases; **P3** = minor / latent.

Status: **FIXED + COMMITTED** — all 143 findings addressed; committed as three
bluetooth-only commits (`351aca0`, `90e475b`, `f7e320b`). Mesh Friend + Low Power Node
roles implemented. Full ATF suite green apart from hardware-only `hci_hw` cases (need a
real controller) and one pre-existing `att_server_edge` case. See the Fix Status Ledger.

## Fix Status Ledger

Fixes are done in waves by disjoint file-group, each verified by building + running the ATF suite
(`tests/usr.sbin/bluetooth/blued/`, ~150 programs) which compiles the whole stack. Nothing here has
ever shipped, so internal IPC / persistence / CLI formats were redesigned freely; only Bluetooth
on-air formats (SMP/ATT/HCI/mesh PDUs) are held fixed.

- **FIXED + test-green — libmesh (findings 1-26, 69-85, 108-109)**: all fixed with fail-before/
  pass-after ATF tests; 654 mesh cases pass (incl. finding-1's previously-failing
  `mesh_iv_beacon_same_index_start`). Findings 4 & 5 were correctly reclassified as doc-only per
  MshPRT §1.3.2 (RFU bits are processed as 0, not rejected).
- **FIXED + test-green — meshd/meshctl (findings 52-55, 71, 73, 77, 80, 106-107, 117, 123;
  completeness 126-127, 130-132)**: 130 meshd cases pass (117/123 verified via
  f117_appkey_rollback / f123_provisioner_begin_rollback).
- **FIXED + test-green — blued HCI/config/persist (40-42, 44, 46-49, 96-99, 124, 143; persistence
  67, 139-141)**, **ATT/GATT/SMP (50-51, 56, 62-64, 104, 110-114)**, **ctl/roles (28, 31, 35-37,
  57, 61, 65-66, 68, 115, 118)**, **libble/CLI/vhci (27, 29, 32, 34, 38-39, 100-103, 105, 125,
  133-134, 142)**. All four agents' owned tests pass. The coordinated security-event/reply IPC
  contract was reconciled by hand (the agents' spec was wrong): the passkey/numcmp reply uses the
  standard typed-security header `[opcode][flags][addr_type@4][addr@5-10][adapter@11][value@12]`
  (sizes 16/13), matching server + client + tests. **ctl_test 57/0, libble_test 25/0,
  ipc_client_test 29/0, privacy_test 8/0** after the fix.
- **FIXED + test-green — blued concurrency/lifetime (Wave 2b): findings 30, 33, 43, 45, 58-60,
  86-95, 116, 119-122**. Root-cause fix: `ctl_clients_lock` is now a recursive mutex (kills the
  ERRORCHECK early-unlock in the whole lock-reacquisition class); new `reslist_lock`/`att_sec_lock`/
  `ctl_att_ops_lock`; central-role teardown frees hogp/att/vhid on APTO/setup-fail/shutdown;
  disconnect made idempotent; new `IPC_ISO_EV_FAILED` event; error-propagation on REKEY/RESOLV/
  ACQUIRE/Service-Changed. Verified: 2610 non-mesh blued cases pass, no regressions.
- **FIXED + test-green — completeness 135, 136, 137, 138, 68(full)**: Filter-Accept-List IPC verbs
  + libble + `accept-list` CLI + persistence; GATT descriptor/include authoring via CLI + config
  parser + peripheral DB apply; runtime GATT-service persistence (`gattsrv` artifact); runtime
  resolving-list IRK persistence (`resolv` artifact); HOGP control-point + multi-instance report-map
  bond persistence (smp_bond v2). ctl_test 60, config_test 29, persist_test 16, bond_migrate 13, all
  green.
- **FIXED + test-green — completeness 128, 129 (deep)**: Remote Provisioning + Directed Forwarding
  fully surfaced through meshd (models, verbs) AND wired onto the live bearer — DF per-hop
  encrypt/relay/reply/confirm and RPR PDU-tunnel + unsolicited reports. meshd_df_test 8, meshd_rpr_test
  9 (incl. live two-node discovery + PDU tunnel). Remaining: genuine 3+ hop OTA across separate
  daemons and a real downstream device need a live multi-node setup (documented in-tree).

**Suite status:** full run = 3253+ passed. The only non-passes are 11 `hci_hw_test` cases (require a
real HCI controller — environment, not regressions) and 1 pre-existing `att_server_edge_test`
(`att_check_read_perm` returns INSUFF_AUTHEN by design at HEAD, unchanged). A mid-run agent
`git stash` reverted the tree once (including the user's unrelated pre-existing work); it was fully
recovered from the stash — see the recovery note in the session.

---

- **Round 1** (broad correctness by component, 7 reviewers): findings 1-55 below.
- **Round 2** (concurrency lens on blued; HOGP/devmgr/GATT-client; ISO/EATT arithmetic; mesh_sim/df/bearer + mesh timers): findings 56-95 below.
- **Round 3** (blued daemon lifecycle/config/hotplug; meshd remaining files; libbluetooth + vhci deep; malformed-input parser lens): findings 96-107 below. Yield dropped sharply — one P2 (bt_devinquiry) + one latent memory bug, rest P3 doc/config nits.
- **Round 4** (SMP pairing state-machine/key-lifecycle; local GATT server DB + advertised content; mesh provisioning/manager state machines & address allocation; cross-component error-propagation/rollback): findings 108-123 below. Rebounded (1 P1 + several P2) because SMP-state-machine and error-handling were previously-untouched behavioral surfaces.
- **Round 5** (spec-constant/opcode-encoding conformance audit; end-to-end IPC/CLI integration): confirmation pass — in progress.

**Convergence:** After 4 rounds / 19 reviewer passes across ~13 distinct lenses, every file in the
new LE+mesh stack has been read in full at least once and re-examined under multiple orthogonal
lenses. The malformed-input (round 3) and local-GATT-DB (round 4) passes came back essentially
clean, indicating those surfaces are solid. Remaining risk is concentrated in the P1/P2 items
below (IV update, Time-model bit packing, friendship livelock, DF routing, several blued
concurrency UAFs, the ctl IPC lock-reacquisition class, the SMP legacy-reconnect P1). Round 5 is
a final confirmation pass; a 6th round would be expected to surface only additional P3s.

---

## Findings

### lib/libmesh — lower layers (net/transport/beacon/IV/KR)

1. **[P2] mesh_iv.c:151-163 — Same-index IV Update "start" regresses the TX IV Index (nonce reuse)**
   In `mesh_iv_recv_beacon`, a beacon with `recv_iv == cur` and the IV Update flag set, received
   in `MESH_IV_NORMAL`, transitions to `MESH_IV_UPDATE_IN_PROGRESS` *without* changing
   `iv_index`. `mesh_iv_tx_index()` (mesh_iv.c:43-44) then returns `iv_index - 1`, so a node that
   was transmitting on index n (and reset SEQ to 0 on entering Normal at n) drops back to
   transmitting on n-1 where its SEQ values were already consumed — (IV, SEQ) nonce reuse. A later
   `(n, flag=0)` beacon then "completes" the update at the same index and triggers a second SEQ
   reset at n. MshPRT §3.11.5 sanctions no such transition (Normal→In Progress shall increment the
   IV Index; Tables 3.84/3.85 have no same-index start). Trigger: an authenticated beacon from a
   laggard node still In Progress toward n (>144 h behind), or any node using the
   mandatory-to-support IV Update test mode (§3.11.5.1). Correct behavior: ignore the flag.

2. **[P3] mesh_iv.c:175-186 — Armed IV Index Recovery ignores (current+1, flag=1) beacons**
   MshPRT Table 3.85 says an armed recovery observing IV = current+1 with flag=1 shall accept the
   IV Index and flag (resetting SEQ if In Progress), and §3.11.6 exempts recovery from the 96-hour
   limits. The code handles `recv_iv == cur+1 && flag` *before* consulting `recovery_active`: in
   In Progress it returns `MESH_IV_NO_CHANGE` unconditionally; in Normal it is dwell-gated. An
   armed node cannot adopt until a flag=0 beacon arrives (up to 96 h lag). Self-heals on the
   completion beacon, hence P3.

3. **[P3] mesh_net.c:321-328 — Decrypt accepts control PDUs with out-of-spec transport length**
   `mesh_net_decrypt` bounds `tlen` with `MESH_NET_MAX_TRANSPORT_PDU` (16) regardless of CTL,
   whereas `mesh_net_valid()` (mesh_net.c:117-123) correctly caps a CTL=1 transport PDU at 12 so
   the whole PDU fits the 29-octet limit of §3.4.4. Also no `inlen <= MESH_NET_MAX_PDU` check, so
   an authenticated control PDU of up to 33 octets decrypts and reaches the transport layer. No
   memory unsafety (buffers hold 16), needs a key-holding sender.

4. **[P3] mesh_beacon.c:316,342-346 (+ mesh_beacon.h:170-171) — Private-beacon parse doesn't
   implement the documented reserved-Flags-bit rejection**
   Function comment and header promise `mesh_private_beacon_parse` rejects beacons whose decrypted
   Flags octet has bits 2-7 set; the code extracts the two defined bits and never tests
   `flags & ~0x03`. Either implement the check or fix the documented contract.

5. **[P3] mesh_key_refresh.h:91-94 — Self-contradictory doc for `mesh_kr_beacon_flag`**
   Comment says the flag is "SET in Phase 2 and Phase 3 … CLEAR otherwise, including Phase 3". The
   implementation (mesh_key_refresh.c:82) returns 1 only in Phase 2, which matches
   §3.11.4.2/3.11.4.3 — the doc misstates wire behavior; code is correct.

*Round 1 clean: mesh_crypto.c, mesh_transport.c, mesh_relay.c, mesh_rpl.c (verified against
MshPRT §3.4/3.5/3.8/3.9/3.10/3.11 incl. CCM parameterization, segment math, BlockAck shifts,
RPL IV-aware comparison).*

### lib/libmesh — access/model layers

6. **[P1] mesh_time_scene.c:27 (encode), :48-50 (decode) — Time Status/Time Set packs Time
   Authority and TAI-UTC Delta in the wrong bit positions**
   MMDL §1.5 field ordering puts Time Authority (1 bit) in bit 0 and TAI-UTC Delta (15 bits) in
   bits 1..15 of the little-endian 16-bit word. The code does
   `packed = tai_utc_delta | (time_authority << 15)` (mirror-wrong in decode), so against a
   compliant peer every Time Status/Time Set decodes with the delta shifted and the authority bit
   read from the delta's LSB. Invisible to round-trip self-tests. (The TAI-UTC Delta Set/Status
   handlers at lines 179-190 are correct because there the delta precedes the padding bit.)

7. **[P2] mesh_generic.c:617-642 — Generic Move Set with computed transition time 0 slams Level
   to ±32767 instead of doing nothing**
   MMDL §3.3.2.2.4: transition time 0 means "shall not initiate any Generic Level state change".
   When the time resolves to 0 ms and delta != 0, the else-branch calls
   `mesh_gen_level_srv_set_present(srv, INT16_MAX/INT16_MIN)` immediately (or after the delay).
   A Move Set without a transition-time field to a server with DTT=0 rails the level.

8. **[P2] mesh_generic.c:347-360, mesh_lighting.c:36-50, mesh_time_scene.c:399-412 — TID window
   anchored at the transaction's first message, never refreshed**
   `expires_ms = now_ms + 6000` is set only when a message is judged new; retransmissions don't
   refresh it. MMDL §3.3.2.2.3 runs the 6 s window from the *previous* same-TID message. Failure:
   a Delta Set slider drag longer than 6 s — at t≈6 s the next same-TID message is misclassified
   as a new transaction, `txn_base` resets to the current level (mesh_generic.c:585-586), and the
   cumulative delta is re-applied on top of itself (level jumps to ~double).

9. **[P2] mesh_lighting.c:110-116, 274-285 (+ CTL 695-719, HSL 1163-1197, xyL 1562-1579) —
   Out-of-range Lightness/Temperature Set dropped instead of clamped**
   MMDL §6.1.2.2.5 requires clamping non-zero out-of-range values to Range Min/Max (same binding
   for CTL Temperature). `lightness_value_valid()` failure makes the handlers return -1: no state
   change, no Status, and for composite CTL/HSL/xyL Sets the entire message including in-range
   components is discarded. (Generic Power Level at mesh_generic.c:796-814 clamps correctly —
   the lightness family is inconsistent with it and the spec.)

10. **[P3] mesh_generic.c:694-713 — Power OnOff RESTORE restores the state saved at the
    *previous* power cycle**
    RESTORE sets present from the stale `srv->last_onoff` (captured at init or the prior cycle)
    and only afterwards stores the pre-cycle value into `last_onoff` — the restored on/off value
    is always one power-cycle behind. Sibling `mesh_gen_power_level_power_cycle` (817-835) is
    correct.

11. **[P3] mesh_sensor.c:294-302 — Sensor Descriptor Get for unknown Property ID returns an
    empty Descriptor Status**
    MMDL §4.2.2 requires echoing the requested Property ID (2-octet status); the loop matches
    nothing and sends `params_len = 0`. The Sensor Get path (305-309) handles this correctly.

12. **[P3] mesh_sensor.c:407-423 with sensor_cadence_encode (257-274) — Accepted Cadence Set can
    be acked with an empty (invalid) Cadence Status**
    For `raw_len >= 16`, trigger_type 0, the status exceeds `MESH_MODEL_REPLY_PARAMS_MAX`;
    encode returns 0 and the SET branch emits a zero-length Cadence Status (spec requires at
    least the Property ID). The GET branch's fallback (387-391) also misreports "no cadence
    configured" for a sensor that has one.

13. **[P3] mesh_lighting.c:95-98 — Actual→Linear conversion uses floor instead of Ceil**
    MMDL §6.1.2.2.1: `Linear = Ceil(65535 * (Actual/65535)^2)`; the integer division truncates.
    Client sets Linear=1 → Actual=255 → Linear Status reads back 0; nearly all Linear Status
    values are one low.

14. **[P3] mesh_lighting.c:650-664, 745-755 — CTL Status reports stale/prohibited Target
    Temperature when only the lightness transition is active**
    `ctl_transition_active(srv, 0)` is true if any of the three transitions is active (a plain
    Light Lightness Set can start the shared lightness one), but target fields are read
    unconditionally from `temperature_transition.target` — status can carry Target CTL
    Temperature 0x0000, a prohibited value (valid 0x0320-0x4E20).

15. **[P3] mesh_lighting.c:313-318 — Light Lightness Default Set wrongly validated against the
    Range and dropped**
    MMDL §6.1.2.4 defines Default as 0x0000-0xFFFF with no Range binding (0 = use Last);
    `lightness_value_valid()` rejects compliant Default Sets silently.

*Round 1 clean: mesh_access.c (opcode codec, virtual-address hash, message cache, transition
math), mesh_cfg_model.c, mesh_cfg_v11.c (SAR bitfields, aggregator, LCD), mesh_health_model.c,
scheduler 80-bit packing, scene register, HSL wrap-around hue ranges.*

### lib/libmesh — friendship, provisioning, proxy, directed forwarding, sim

16. **[P1] mesh_friend.c:868 (with :1039-1042) — Friend Update MD computed from stale queue
    state causes a perpetual MD=1 poll loop**
    `friend_build_update_entry()` sets `up.md = mesh_fq_count(&f->queue) > 0` *before*
    `mesh_fq_poll()` discards the previously delivered head on FSN ack. Steady state after any
    delivery: the queue holds only the already-delivered entry, so every empty-queue Friend
    Update carries MD=1 forever. The LPN FSM reacts to MD=1 with an immediate re-poll
    (mesh_lpn.c:226), so a Friend/LPN pair enters an infinite immediate poll/update loop after
    the first delivered message (battery drain / livelock in normal operation). MD must be
    computed after the ack-discard, excluding the entry being returned.

17. **[P2] mesh_friend.c:915-941 — Any Friend Request destroys an established friendship with a
    different LPN**
    `mesh_friend_fsm_recv_request()` has no state guard: while ESTABLISHED with LPN A, a
    broadcast Friend Request from LPN B that passes the acceptance checks overwrites
    `lpn_addr/lpn_counter/poll_timeout` and re-inits the queue, silently discarding A's queued
    messages with no TERMINATED action. A request from a different `lpn_addr` should be ignored.

18. **[P2] mesh_lpn.c:179-188 — No poll pacing in ESTABLISHED: a due poll re-emitted every tick**
    After `lpn_build_poll()` nothing advances `next_poll_ms` or records an in-flight poll; any
    caller ticking faster than the friend's ReceiveDelay+ReceiveWindow emits back-to-back Friend
    Polls until the Update arrives (poll storm; each duplicate Update then hits bug 19).

19. **[P2] mesh_lpn.c:224,242 — FSN toggles on every received Friend Update/message, including
    duplicates**
    The FSM hard-codes `is_duplicate=0` into `mesh_lpn_on_response()` and keeps no duplicate
    detection. Two copies of the same response toggle FSN twice, so the next Poll carries an
    unchanged FSN; the Friend treats it as "response lost" and resends instead of discarding the
    acked head — the handshake stays desynchronized.

20. **[P2] mesh_provisioner.c:762-875 — PB-ADV link layer ignores Link ID and Link Open UUID**
    `mesh_prov_link_recv()` never compares the parsed `link_id` with `l->link_id` for segments,
    acks, or Link Close (MshPRT §5.2.2 requires ignoring unknown Link IDs), and the LINK_OPEN
    case (787-803) never checks the 16-byte UUID against `l->device_uuid` (§5.3.1.4.1), adopting
    a new link even mid-session. Two concurrent provisioning links nearby corrupt/tear down each
    other's transactions (a foreign Link Close kills a provisioning in progress).

21. **[P2] mesh_df.c:980 — Path Reply matched by `target.range_start` against entries keyed by
    the request's Destination**
    `recv_path_request()` keys the reverse entry `(origin, req.destination)` (:914), but
    `recv_path_reply()` looks up `(path_origin, rep.target.range_start)` — the target's *primary*
    address. Whenever the discovery destination is a secondary element or group address, relays
    drop the reply and the path never establishes. Should match by range coverage (compare
    `mesh_df_discovery_on_reply()`, which uses `range_covers`).

22. **[P2] mesh_sim.c:1430-1431 — Sim Path Target replies with `range_length=1`**
    The target role sets `rep.target.range_length = 1` regardless of which element matched, so
    discovery to a secondary element fails `range_covers()` at the origin too. Should be
    `node->n_elements`.

23. **[P2] mesh_sim.c:1964 — LPN poll toggles FSN even when the Friend's response never arrived**
    `mesh_lpn_on_response()` is called unconditionally after `mesh_sim_run()`. If the response
    was lost (or the queue was empty — the poll handler passes `empty_update = NULL` and sends
    nothing), the next Poll carries a changed FSN which `mesh_fq_poll()` (mesh_friend.c:699-703)
    interprets as an ack — the still-undelivered head is discarded and lost.

24. **[P3] mesh_manager.c:671 — SEQ not persisted; a reloaded manager reuses old sequence
    numbers**
    `mesh_mgr_save/load` deliberately omit `mgr->seq`; after restart under the same IV Index,
    `mesh_mgr_devkey_seal()` re-issues already-used SEQ values, so every node's RPL silently
    discards the manager's Config traffic (and it is nonce reuse). Needs a persisted high-water
    mark or forced IV update.

25. **[P3] mesh_df.c:939,1005,1066-1067 — Path/Echo Reply originated with the incoming request's
    residual TTL**
    A request originated with TTL T arriving over h hops has T−h remaining, but the reply needs
    h hops back; whenever T < 2h+2 the reply dies in transit (relay refuses TTL<2). Replies
    should use a fresh default/max TTL.

26. **[P3] mesh_provisioner.c:406-432 — Device accepts Static/Output/Input OOB Start selections
    it can never authenticate**
    The engine only ever installs the No-OOB AuthValue, yet START validation accepts
    auth_method 1-3 whenever caps advertise them — the exchange then always dies later with
    `PROV_ERR_CONFIRMATION_FAILED` instead of being rejected at Start.

*Round 1 clean: proxy PDU codec/SAR + filter state machine, proxy config crypto, provisioning
PDU codec and derivations (ProvisioningSalt/k5/s2), PB-ADV FCS/segmentation, Friend Clear
LPNCounter window, heartbeat log transforms, remote-provisioning codecs, manager persistence
framing.*

### blued control plane, libble, CLIs, kernel vhci

27. **[P1] bluectl.c:157-226 — bluectl speaks a removed line-based text protocol; every command
    fails or hangs**
    bluectl sends `"SCAN\n"`-style text and waits for `OK/ERROR/END` lines; the daemon speaks
    only length-prefixed binary framing (ctl.c:4793-4868). Single-line commands print binary
    garbage; multi-line commands (`scan`, `list`, `adapters`) block forever. 100% version-skewed
    dead tool.

28. **[P1] ctl.c:397-420 (server) vs ble.c:648-656 (client) — Security events never encode the
    peer address type**
    `ctl_send_security_event()` writes the event code at `body[0..1]` and address at `body+3`
    but never sets `body[2]`, which libble decodes as `addr_type` — every
    PASSKEY_DISPLAY/PASSKEY_INPUT/NUMCMP/KEYPRESS event reports the peer as public. Echoing that
    address back via `ble_passkey_reply()`/`ble_numcmp_reply()` fails the
    `(adapter, addr, addr_type)` lookup (ctl.c:2956-2998) for random-address peers (the common
    case with LE privacy) → pairing prompt can never be answered. The 13-byte event also lacks
    an adapter-index field entirely, so multi-adapter replies can't be routed.

29. **[P1] ble.c:478,586-591,655-656 — libble passes uninitialized `adapter_index` to security
    and GATT-authorize callbacks**
    Stack `ble_addr_t addr` is only partially filled on these paths; `addr.adapter_index` is
    garbage. Apps echoing the callback address into passkey/numcmp replies send garbage
    `payload[11]` — rejected with `IPC_ERR_INVAL` or routed to the wrong adapter. Breaks the
    `bluedctl keyboard` pairing flow (bluedctl.c:1663-1710) nondeterministically.

30. **[P1] blued_event.c:1100-1123 + ctl_conn.c:338-350 + ctl.c:784 + ctl_gatt.c:269 —
    Client-issued DISCONNECT re-acquires `ctl_clients_lock` already held by dispatch**
    The event loop holds `ctl_clients_lock` across `blued_ctl_dispatch()`; DISCONNECT reaches
    `blued_conn_disconnect()`, which relocks the same mutex in
    `blued_ctl_broadcast_conn_event()` and `ctl_gatt_conn_gone()`. With FreeBSD's default
    ERRORCHECK mutex the inner relock returns EDEADLK (ignored) and the inner *unlock releases
    the mutex early* — the rest of dispatch races GATT worker threads sending frames under the
    same lock (txq STAILQ corruption). With a plain mutex it's a hard self-deadlock. Trigger:
    `bluedctl disconnect <addr>` on any active connection.

31. **[P2] bluedctl.c:1458 + ble.c:2433-2451 vs ctl.c:2743-2750 — Wildcard notification
    subscribe emitted by client, unimplemented by server**
    `bluedctl monitor` sends the documented wildcard SUBSCRIBE (all-zero address, handle 0); the
    server rejects handle 0 and can't resolve the zero address. The wildcard-matching code in
    `blued_ctl_notify_value()` (ctl.c:584-590) is unreachable. Monitor's NOTIFY path is dead.

32. **[P2] ble.c:839-878,1155-1174,1244-1316 — Synchronous libble ops bypass the receive buffer
    and desync on buffered partial frames**
    `ble_sync_operation()`/`ble_acquire_typed_gatt()` read directly from the socket without
    checking `ctx->rxlen`; a partial frame left in `rxbuf` by a prior `ble_process()` makes the
    sync read start mid-frame — connection desyncs until reconnect.

33. **[P2] ctl.c:3073-3094 — REKEY runs a full blocking SMP pairing on the dispatch thread**
    `ctl_security_rekey_result()` calls `smp_pair()` (blocking) on the main event-loop thread
    while `ctl_clients_lock` is held. If the rekey needs a passkey/numcmp, the reply can only be
    delivered by the thread blocked inside `smp_pair()` — daemon-wide stall until SMP timeout.
    Every other pairing path runs on a setup thread.

34. **[P2] bluedctl.c:649-663,681-691,702-707,770-790,884-897 — One-shot fire-and-forget
    commands always exit 0, hiding daemon failures**
    write/disconnect/pair/unbond/rekey/advertise/etc. return as soon as the request frame is
    written; the correlated OP_REPLY (which may carry an error) is never awaited in one-shot
    mode. `bluedctl write` against a disconnected device exits 0. Also `subscribe` in one-shot
    mode is a guaranteed no-op (process exit tears the subscription down).

35. **[P3] ctl.c:1683-1724,4716-4787 — HELLO version mismatch not enforced**
    On mismatch the server sets `handshaked=false` but never disconnects, and
    `ctl_process_frame()` never checks `handshaked` before dispatching OP_REQ — the version gate
    (only defense against struct-layout skew, per ipc_proto.h:24-28) is decorative.

36. **[P3] blued_peripheral.c:560-577 — Peripheral setup reads the bond DB without
    `bond_db_lock`**
    Dereferences `pb->has_ltk/is_mitm/key_size` racing `ctl_security_unbond_result()`
    (ctl.c:3029-3071), which `memmove`s entries under the lock — stale/garbage key size can be
    fed to `att_conn_apply_encryption`. Central path does this correctly via
    `hogp_bond_snapshot()`.

37. **[P3] ctl.c:3254-3261 — `IPC_SECURITY_PAIR` never initiates pairing despite documented
    contract**
    Handler only checks a connection exists and returns OK; `ble_pair()` on an unencrypted
    connection reports success with no pairing attempted.

38. **[P3] bluedctl.c:1796-2023 — Help/usage advertise dozens of commands with no handler**
    `services`, `loglevel`, `hogp-*`, `ecbfc-*`, `security`, `io-cap`, `oob-*`, `per-adv-*`,
    `past-*`, `iso-*`, `authorize`, `bond-import`, most `resolv` subcommands, etc. all fall
    through to "unknown or unsupported command".

39. **[P3] sys/netgraph/bluetooth/drivers/vhci/ng_hci_virt.c:246-254 — RX overflow drop-oldest
    can discard an HCI command and stall ng_hci flow control**
    When the 64-deep rxq is full the oldest packet is freed (and ENOBUFS still returned). If the
    dropped packet was an HCI command its Command_Complete never comes, so ng_hci's
    `num_cmd_pkts` credit is never returned — command pipeline stalls until reset. Prefer
    dropping the newest, or never dropping commands.

*Round 1 clean: GAP/bond/ISO/adv IPC record layouts cross-checked both sides, acquire fd-handout
ordering, blued_persist framing, vhci locking/teardown; `ctl_connect_result` error path is not a
double free.*

### blued — HCI core

40. **[P1] hci_conn.c:104-169, hci_misc.c:851-900 et al. (13 wrappers) — Command-Status replies
    never received; the checked status byte is uninitialized stack**
    Wrappers that set `r.event = NG_HCI_EVENT_COMMAND_STATUS` pass `rlen = 1`, but
    `bt_devreq` (lib/libbluetooth/hci.c:292-307) copies the 4-byte command_status event into
    `rparam` only if `rlen >= 4` — otherwise it copies nothing and returns success, so
    `rp.status` is never written. Affected: `hci_le_connection_update`, `hci_le_set_phy`,
    `hci_le_subrate_request`, `hci_le_read_remote_tx_power_level`,
    `hci_le_ext_create_connection`, `hci_le_create_cis`, `hci_le_accept_cis_request`,
    `hci_le_create_big[_test]`, `hci_le_terminate_big`, `hci_le_big_create_sync`,
    `hci_le_request_peer_sca`, `hci_le_periodic_adv_create_sync` — none memset `rp`, so
    `if (rp.status != 0)` reads garbage and nondeterministically reports EIO for accepted
    commands (e.g. `blued_iso_cis_create` then strands the stream in CIG_CONFIGURED and the real
    CIS Established event is ignored). `hci_disconnect` memsets `rp` and therefore *always*
    reports success, masking rejections. Fix: pass a 4-byte `ng_hci_command_status_ep`.

41. **[P1] blued.c:3141-3146 — HCI socket event filter blocks three events the daemon handles**
    The only filter installed admits 0x3E/0x08/0x57. But the daemon: (a) unmasks Encryption
    Change **v2** (0x59) in Event Mask Page 2 (blued.c:1910) and Core 6.3 mandates the
    controller then use v2 — so on v2-capable controllers encryption events are dropped by the
    socket filter and the ATT security gate never opens on bonded reconnects; (b) has a
    Disconnection Complete (0x05) handler whose `iso_on_cis_disconnected` is unreachable — a
    peer-initiated CIS drop leaks the ISO stream; (c) has a dead Encryption Key Refresh (0x30)
    handler.

42. **[P1] hci_adv.c:816-848 + ctl.c:1027-1040 — Mesh TX permanently wedges after the first PDU**
    `hci_mesh_adv_burst` enables the advertising set indefinitely (duration=0, max_events=0) and
    never disables it; the next PDU's Set Extended Advertising Parameters on an enabled set is
    rejected (Command Disallowed per §7.8.53), `mesh_adv_drain` retries forever, the FIFO fills,
    and MESH_ADV_SEND returns BUSY permanently. Also `MESH_ADV_HANDLE` (0x01, hci_util.h:326)
    collides with the peripheral's Coded-PHY set on handle 0x01 (blued.c:3400-3424).

43. **[P2] blued_event.c:182 vs hci_util.c:103 / hci_misc.c:83 — Two unsynchronized readers on
    the same raw HCI socket**
    The main event loop `recv()`s each adapter fd while detached setup threads run `bt_devreq` /
    `hci_wait_encryption` on the same fd (`hci_devreq_mutex` serializes only devreq callers).
    Whichever thread wins steals the other's packet: spurious devreq timeouts, 10 s pairing
    stalls. The threads also swap the socket filter to a narrow set and restore saved copies —
    concurrent save/restore can restore a stale narrow filter, leaving the daemon permanently
    deaf to LE Meta events.

44. **[P2] blued.c:2205-2295 — DISCOVERABLE always fails on extended-advertising controllers
    when set 0 was never configured**
    The enable path issues Set Extended Advertising Data/Enable for handle 0 but never Set
    Extended Advertising Parameters; if `adv_configured` is false the set doesn't exist and the
    data command fails (Unknown Advertising Identifier) — verb always returns -1.

45. **[P2] blued_event.c:1552-1696 — `blued_conn_disconnect` not idempotent for
    central-reconnect; double invocation arms two reconnect timers / two setup threads**
    Only guard is `state == IDLE`; the reconnect path leaves the conn listed as RECONNECTING.
    Two disconnect triggers in one kevent batch overwrite `reconnect_timer` while the first
    ONESHOT timer stays armed (never EV_DELETE'd); both fire, both pass the list-membership
    check, and two setup threads concurrently mutate the same non-refcounted `hogp_device`.

46. **[P3] hci_scan.c:790-871 — Incomplete extended-advertising fragments parsed as standalone
    reports**
    Data_Status 0b01/0b10 fragments are fed straight to `hci_parse_ad_fields` with no
    reassembly; fragments starting mid-AD-structure yield garbage names/UUIDs merged into the
    dedup entry (advertisers with >229-byte extended data).

47. **[P3] blued_internal.h:108-111 / blued.c:69 — Documented 60-second setup timeout is dead
    code**
    `BLUED_SETUP_TIMEOUT_SEC`/`BLUED_KQ_SETUP_TIMEOUT` are declared but no timer is armed and
    the event loop has no dispatch arm for the tag.

48. **[P3] hci_scan.c:62-119 / hci_util.c:51-97 — fd-keyed static slot tables never invalidated
    on adapter close**
    `hci_scan_state[]` and `hci_locks[]` map raw fd numbers with no remove operation; a reused
    fd inherits a stale `own_addr_type`, and after 8 distinct fds the lock table degrades to
    shared hashed mutexes.

49. **[P3] hci_log.c:214-222 — Contradictory length clamp drops instead of truncating**
    For `len > UINT16_MAX` the code warns "truncating" and clamps, but the next check
    `if (len > UINT16_MAX - 4) return;` silently discards the record (and 65532-65535-byte PDUs
    are dropped with no warning). Log-capture-only impact.

*Round 1 clean: hci_scan.c report bounds/offsets vs §7.7.65, blued_le_meta.h subevent decoders,
command encodings in hci_adv/hci_misc/hci_privacy, conn.c refcounting, config.c parsers, iso.c
state machine, connection-update timeout formula.*

### blued — ATT/GATT/SMP

50. **[P2] smp_legacy.c:108,156 — Legacy responder Passkey Entry aborts when the peer sends
    Keypress Notifications**
    The responder's Pairing Confirm is received with `smp_recv_timed`, which does not consume
    Keypress Notifications (opcode 0x0E), unlike every other passkey path (`smp_recv_timed_kp`
    in smp.c:1298, smp_sc.c:459,476,1780,1804). In legacy Passkey Entry (responder displays,
    initiator inputs), the initiator's keypress notification arrives first (Vol 3 Part H
    §3.5.8), the 2-byte read fails `n < 17`, and pairing aborts with EPROTO. Keypress support is
    advertised by default. Fix: use `smp_recv_timed_kp`.

51. **[P3] att_server_dispatch.c:942-944,617 + att.h:165 — Authorize-gated write silently
    truncates and acks values > 512 bytes**
    Deferred-authorization writes are copied into `p->wval` capped at `ATT_PEND_WVAL_MAX` (512),
    but characteristics may register `value_maxlen` up to 517 and MTU-517 Write Requests carry
    up to 514 value octets that passed the maxlen check. On authorize completion only ≤512 bytes
    are stored, yet a success Write Response is returned.

*Round 1 clean: DB-hash reproduces the spec Appendix B test vector; c1/s1/f4/f5/f6/g2/h6/h7/ah
argument orders; signed-write MAC; inclusive ATT handle ranges; MTU clamps across all response
builders; robust-caching gate vs §2.5.2.1; adv_builder budgets; key-distribution ordering.*

### meshd / meshctl

52. **[P2] meshctl.c:65-72,369 vs meshd_ctl.c:337-361 — `app-register`/`app-unregister`/
    `app-watch` omit the required `<element>` argument**
    meshctl documents/sends `app-register <model> [vendor]`; the daemon requires
    `app-register <element> <model> [vendor]`. `meshctl app-watch 0x1000` gets `ERR usage`;
    `app-watch 0x1000 0x1234` registers element=0x1000, model=0x1234 — silently
    misinterpreted.

53. **[P2] meshd.h:326 + meshd.c:454-497 — 256-byte control-socket rx buffer smaller than valid
    commands; long lines drop the connection with no reply**
    `send`/`publish`/`devkey-send` accept access payloads up to 380 octets = 760 hex chars
    (meshctl allows 1024-byte lines), but any line over ~255 bytes makes `meshd_client_read`
    close the client without an `ERR`. Segmented-message payloads over ~118 octets are unusable.

54. **[P2] meshd_node.c:2587-2646,3475 — Configured Heartbeat Publication never transmitted;
    Subscription never counts**
    `h_hb_pub_set`/`h_hb_sub_set` write only the config DB; `mesh_sim_hb_set_pub/sub()` are
    never called anywhere in meshd, so the HB timer stays inactive and `hb_sub_active` stays 0 —
    while Status replies report the config as accepted. Compounding: `meshd_node_tick` gates HB
    publication on `dt_ms >= 1000` where `dt_ms` is the per-tick delta (~10 ms), so periodic
    publish would never run anyway.

55. **[P3] meshd_proxy_gatt.c:26,33-51 — proxy_config_recv key-candidate array sized one short
    (latent stack overflow)**
    `keys[MESH_SIM_MAX_SUBNETS * 2 + 1]` (9 slots) can be fed 2 (self old+new) + 2×4 subnets =
    10 entries. Not reachable via the Config API (NetKeys capped at 4 total) but reachable via
    CRC-valid persisted state with all subnets mid-key-refresh. Should be `* 2 + 2`.

*Round 1 clean: SEQ block reservation, persistence version gates, RPL bind ordering, tx drain
compaction, cfg-client expected-status opcodes, bearer kqueue generation tagging.*

### Round 2 — blued ISO/EATT (arithmetic/bounds lens)

56. **[P2] att.c:554 + every `att_request()` caller (att.c:724,760,819,960,1018,1070,1126,1182,1263,1310,1357,1404) — EATT client responses silently truncated to the fixed-bearer MTU**
    `att_request()` selects an EATT bearer by preference but its `recv(fd, rsp, rsplen, 0)` caps
    `rsplen` at `ac->mtu` (the fixed-channel ATT_MTU from Exchange MTU), not the EATT bearer's
    independently negotiated CoC MTU (default 512). When the peer's fixed MTU is smaller (e.g.
    247, a common constrained default) an EATT Read Response longer than 247 bytes is truncated
    by the SEQPACKET recv with no `MSG_TRUNC` check and parsed as a valid short response —
    `att_read()` returns success with missing bytes. The server side handles this correctly
    (swaps `ac->mtu` to `bearer_mtu`); the client side does not. The receive buffer is already
    65535, only the `rsplen` argument is wrong.

57. **[P3] ctl_iso.c:103-105 — ctl ISO CIG validation rejects spec-legal RTN values 0x10-0x1E**
    `ctl_iso_cig_request_valid` rejects RTN_C_To_P/RTN_P_To_C > 0x0F, but RTN in LE Set CIG
    Parameters is a full octet (blued's own BIG path accepts ≤0x1E at ctl_iso.c:128 and
    hci_misc.c:1060). A CIG request with RTN 0x14 (legal, accepted for a BIG) gets
    IPC_ERR_INVAL. Configuration-only, no corruption.

*Round 2 clean (ISO/EATT lens): iso.c refcounts/bit shifts, ctl_iso.c payload offsets & reply
buffer sizing, ISO HCI encoders vs Core 6.3 ranges, blued_le_meta.h CIS/BIG event layouts,
EATT server path large-MTU heap switch & prepare/execute offset checks, adv_builder guards,
periodic-adv/PAST ranges, ECBFC userland credit balance.*

### Round 2 — blued concurrency / lifetime lens

58. **[P2] ctl.c:1550-1564,628,1590,1645-1649 (+ blued_central.c:1945, att.c:576, blued_event.c:1588) — `ctl_acquires` registry mutated on the main thread while a GATT worker reads it, no lock**
    The comment (ctl.c:1386-1391) claims `ctl_acquires` is "touched only on the main
    event-loop thread". False: `ctl_acquire_route_notify()` iterates the list and `send()`s from
    `hogp_unsolicited()` on a **GATT worker thread** (att.c:576 `unsolicited_cb`) when a
    notification arrives mid-op. Meanwhile the main thread does `LIST_REMOVE+free+close` in
    `ctl_acquire_dispatch()` (EV_EOF) and `ctl_acquire_conn_gone()` (any other peer's disconnect,
    called from `blued_conn_disconnect` where `ctl_clients_lock` is not held). Worker mid-FOREACH
    → use-after-free / list corruption, or `send()` on a closed/reused `daemon_fd`.

59. **[P2] blued_event.c:905-916,1049-1051 (+ conn.c:357-398) — Authenticated Payload Timeout
    tears down a live central connection via `blued_conn_free`, orphaning the ATT fd + kqueue
    registration and leaking the HOGP device**
    The APTO handler (event 0x57) sets `needs_cleanup`; the sweep calls `blued_conn_free(c)`
    directly, not `blued_conn_disconnect()`. For a central connection `att_owned == NULL`, so
    the free path never unregisters `conn->att_fd`, never closes `hogp->vhid_fd`, and never frees
    `hogp`. After APTO on a bonded HOGP link, `dev`/`att_fd`/`vhid_fd` leak **while still
    registered in the kqueue** with `udata` pointing at the freed `conn` — the registration keeps
    firing an event matched to no live conn and never deleted → unbounded "unhandled kqueue
    event" spin / 100% CPU; freed-then-reused `conn` address can alias a later connection. No
    DISCONNECTED event emitted.

60. **[P3] blued_central.c:59-63 + blued_event.c:1051 — every non-reconnect central setup failure
    leaks the `hogp_device`**
    `blued_central_setup_fail()` (non-reconnect) closes `dev->att`/`dev->smp` and frees
    `report_map`, then sets `needs_cleanup`; the sweep runs `blued_conn_free(c)`, which never
    frees `conn->hogp`. Each failed outbound CONNECT without auto-reconnect leaks a full
    `hogp_device`. Same root cause as 59: `blued_conn_free` is not a substitute for the
    central-role teardown `blued_conn_disconnect` performs.

*Round 2 clean (concurrency lens): att_ops_active recv-owner handoff & stale-event guard, conn
refcount across teardown, pairing_lock/cond passkey wait, EATT bearer spinlock/pending
accounting, LTK-request/Encryption-Change conns_lock→bond_db_lock ordering, self-pipe sweep
lockless list walk.*

### Round 2 — blued HOGP / devmgr / GATT-client / persistence lens

*(EATT client-side truncation independently re-confirmed here — same as finding 56.)*

61. **[P2] blued_central.c:1397-1405,1532-1534,955-1001 — `dev->hid_disc` never reset on
    rediscovery; poisoned handle cache saved with a fresh DB hash**
    `hogp_discover()` clears report_map/nreports but not `hid_disc`, and the HID-service
    assignment only fires when HID is the first service or `hid_disc` is still zero. On any
    rediscovery (Service Changed, DB-hash mismatch after peer firmware update, reconnect —
    `dev` survives reconnects) `hid_disc` keeps the OLD layout; `hogp_cache_save()` persists
    stale `report_map_handle`/`hid_info_handle`/`protocol_mode_handle` alongside fresh report
    handles and the freshly-read DB hash. Next reconnect the hash matches, the cache is trusted,
    and the Report Map is read from a wrong handle — vhid gets a bogus HID descriptor.

62. **[P2] ctl.c:500-518 vs att.c:486-487,550-551 — Documented 2-second CTL ATT timeout is dead
    code; blocking ctl GATT ops stall the event loop up to 30 s**
    `ctl_set_att_timeout()` sets `SO_RCVTIMEO` to 2 s, but `att_request()` re-writes RCVTIMEO to
    the remaining-of-30s on every loop iteration, clobbering it. Every ctl READ/WRITE/SUBSCRIBE/
    DISCOVER against an unresponsive peer blocks up to 30 s (per round trip; discovery is many)
    on the thread that also processes HID input for all connections. Only SNDTIMEO keeps the 2 s
    bound.

63. **[P3] att.c:667,683 — `att_exchange_mtu` receives into a 5-byte buffer; concurrent
    unsolicited PDUs truncated to 5 bytes**
    The whole drain loop uses `rsp[5]` as the recv buffer; a notification arriving during the
    MTU exchange (unsolicited handler registered beforehand) reaches `unsolicited_cb` truncated
    to 5 bytes and a bogus 2-byte "report" is written to vhid. Narrow pre-encryption window.

64. **[P3] att.c:581-593,607-619,449-456 — 16-unsolicited-PDU guard permanently kills the primary
    bearer on a legitimate notification burst**
    If ≥16 queued HID notifications drain on the primary bearer while a request awaits its
    response (plausible for a high-rate mouse), `att_request` returns EBADMSG and marks the
    bearer failed forever (`ac->failed` is never cleared) — all later client requests fail with
    EPIPE though the link is healthy.

65. **[P3] blued_central.c:503-504 — Central setup security retry omits
    `ATT_ERR_INSUFF_ENC_KEY_SIZE`**
    Checks only INSUFF_AUTHEN/INSUFF_ENCRYPTION, whereas `ctl_att_needs_security()`
    (ctl_gatt.c:151-158) also treats 0x0C as pairing-worthy. A peer rejecting the bonded key
    size fails setup instead of re-pairing.

66. **[P3] ctl_gatt.c:489-511 — Subscribe path can latch a CCCD belonging to the wrong
    characteristic after a swallowed discovery error**
    When the target char is last in a batch, the nested next-char discovery's error `ret` is not
    checked: `desc_end` falls back to `service.end_handle`, `ret` is overwritten, and the first
    CCCD in the over-wide range (possibly a later characteristic's) is selected and enabled.

67. **[P3] blued.c:2782-2818,2911-2943 + blued_devmgr.c:45-71 — persistence save/load
    asymmetries**
    `discoverable`/`connectable` saved but never restored; v2 settings
    `conn_interval_min/max`/`conn_latency`/`supervision_timeout` never written and never read
    (dead schema). Devcache load consumes `last_seen`/identity/`appearance` but the save path
    never populates them — wiped every restart. `auto_connect` is hardcoded to 1 for every bond
    (blued.c:2924), so the per-device policy field is fictional. gattcache `nattrs`/`attrs[]`
    validated on load but never written. (Bond/CCC round-trip itself is symmetric; only caveat:
    CCCDs saved solely on orderly disconnect, so a crash with an active peripheral connection
    loses the peer's subscription state.)

68. **[P3] blued_central.c:1029,963-979,736-743,1077-1085 — cache-hit reconnects lose HID
    Control Point and multi-instance report maps; report map silently truncated at 4096**
    `hid_ctrl_handle` has no bond-cache field, so the Exit-Suspend write is skipped on every
    cached reconnect. `hogp_cache_save` stores only the first HID instance's `report_map_handle`
    while `dev->reports` spans all instances — a two-HID-service combo device gets a shorter
    descriptor after a cache-hit reconnect. The Read Blob loop stops at the fixed 4096 buffer
    (or when a clipped blob breaks the `len == mtu-1` continuation), attaching a truncated Report
    Map to vhid with no warning.

*Round 2 clean (HOGP/GATT-client lens): gatt.c discovery range-advance/termination,
Find-Info/Read-By-Type/Read-By-Group response validation, prepared/long-write chunking,
notification routing & shared-CCCD subscribe state machine, blued_devmgr bounds/dedup/backoff,
blued_persist framing/CRC.*

### Round 2 — mesh timers / units lens

69. **[P1] meshd_cfgclient.c:74 + meshd.h:812-813 + mesh_manager.c:1825,1875-1890 — Config Client
    retry interval passed in "ticks" but consumed in milliseconds: every remote transaction times
    out in ~40 ms**
    `MESHD_CFG_RETRY_TICKS` (6) is passed as the `interval` of `mesh_mgr_txn_begin()`, which arms
    `deadline = now + interval` in the clock's units — CLOCK_MONOTONIC **milliseconds** — so the
    retry interval is 6 ms. `meshd_cfg_client_tick()` runs every ~10 ms main-loop pass, so
    attempts 2-4 fire on consecutive ticks and the 5th hits `attempts >= MESHD_CFG_MAX_ATTEMPTS`
    → TIMEOUT ~40 ms after send. A real OTA (often segmented) Config Status arrives far later
    and is discarded (state no longer WAITING). Every `cfg *` verb against a non-loopback node
    burns 4 SEQs and reports TIMEOUT.

70. **[P2] mesh_sim.c:1684-1689 (access), :1757-1762 (control) — SeqAuth reconstructed as
    `SEQ − SegO` instead of from SeqZero; spec-compliant retransmitted/interleaved segments
    dropped**
    The RX path computes `seqauth = pdu.seq - lower.sego` and rejects when
    `(seqauth & 0x1fff) != seqzero`. That only holds if every segment used strictly consecutive
    SEQs from SeqAuth. MshPRT §3.5.3.1 derives SeqAuth from SeqZero (`(seq & ~0x1FFF) | seqzero`,
    −0x2000 if above SEQ) precisely because retransmitted/interleaved segments carry any SEQ in
    [SeqAuth, SeqAuth+8191]. Against a compliant peer, any segmented message that loses a segment
    can never complete (recovery retransmissions are dropped). This is meshd's real RX path
    (meshd_node.c:598).

71. **[P2] meshd_persist.c:306,664 + meshd_node.c:3463-3468 + mesh_iv.c:74-81 — IV dwell
    timestamp persisted from CLOCK_MONOTONIC survives host reboots; 96-hour gate wedges (or
    trivially passes) across boots**
    `iv.entered_time` is persisted/restored raw, but the clock is CLOCK_MONOTONIC (since host
    boot). After reboot the restored timestamp is far ahead of the new clock, so
    `mesh_iv_dwell_elapsed()` returns 0 and all dwell-gated transitions are blocked until this
    boot's uptime exceeds the old value + 96 h — the node is left a full IV index behind. Inverse:
    a fresh node gets `entered_time = 0` and passes the gate immediately on a host up >96 h. Fix:
    persist remaining dwell or clamp `entered_time` to `now` at load.

72. **[P2] mesh_provisioner.c:762-875 (esp. `(void)now;` at :853) — none of the three mandatory
    60-second provisioning timers exist; a silent peer hangs the link forever**
    MshPRT §5.3.1.4.1/5.4.4 require a 60 s link-establishment timer, a 60 s link timer (no PDU
    received), and a ≥60 s protocol timer. The PB-ADV link layer keeps no last-RX timestamp
    (discards its `now`), and supervision runs only while this side has a transaction in flight;
    the device role has no timer at all. A peer that acks then goes silent keeps the link open
    indefinitely. (meshd's PB-GATT side does implement the 60 s protocol timer — inconsistent.)

73. **[P2] meshd_node.c:3830 + mesh_provisioner.c:713-714 — a failed OTA provisioning attempt
    permanently wedges provisioning and leaks the reserved unicast address**
    When the PB-ADV retry budget is exhausted (or a peer stalls), `mesh_prov_link_poll()` returns
    −1 forever (FAILED) and the drain stops. No path clears
    `provisioner_active`/`prov_target_active` or calls `mesh_mgr_provision_abort()` on failure
    (only success commit / PB-GATT close do). Since `meshd_provision_ota_begin()` rejects while
    `prov_target_active` is set, a single unanswered `provision-ota` (target off/out of range)
    makes all subsequent OTA *and* PB-GATT provisioning fail until restart, and the reserved
    address block is never released.

74. **[P3] mesh_heartbeat.c:460-525 — Heartbeat Subscription Period never counted down;
    heartbeats processed forever and Sub Status reports the configured, not remaining, PeriodLog**
    MshPRT §4.2.19.4 defines the Subscription Period as the *remaining* duration.
    `mesh_hb_sub_apply()` stores `period_log` with no countdown, `mesh_hb_sub_receive()` never
    checks expiry, and the snapshot echoes the original. One Sub Set with PeriodLog 0x01 counts
    heartbeats indefinitely. (Distinct from finding 54, which is meshd not wiring the setters;
    this is the library engine.)

75. **[P3] mesh_friend.c:982-1013,1029-1037 — Friend FSM has no 1-second Offer-to-first-Poll
    timeout; ESTABLISHING never expires**
    MshPRT §3.6.6.3.1: friendship is established only if a Friend Poll arrives within 1 s of the
    Friend Offer. The FSM supervises only the OFFERING delay and the ESTABLISHED PollTimeout, so
    a first Poll arriving arbitrarily late (or replayed) "establishes" a friendship the LPN
    abandoned, holding the queue the whole time. (Complements finding 17.)

*Round 2 clean (timers/units lens): mesh_access transition/TT step math, transport seqzero/
BlockAck packing, friend PollTimeout/Offer-delay/MinQueueSize math, lpn wrap-safe expiry,
IV 96 h constant & 42-index lookahead, df lifetime table vs Table 4.58, heartbeat log
transforms, relay timing, meshd publication timers, proxy/PB-GATT 20 s/60 s timers, bearer
reconnect backoff, persist debounce.*

### Round 2 — mesh_sim / mesh_df / meshd bearer routing lens

76. **[P1] mesh_df.c:792-806 + mesh_sim.c:1579-1600 — `mesh_df_forward_decide()` returns DIRECTED
    for half-installed entries; sim then unicasts the PDU to node index 0 (blackhole)**
    `mesh_df_table_lookup()`/`forward_decide()` never check the bearer for the needed direction
    is valid (`MESH_DF_BEARER_NONE == 0`), unlike `recv_path_echo_request()` which does. Every
    DF relay that hears a Path Request flood installs a reverse-only entry with
    `bearer_toward_target = 0` (lives the full 12 min–10 day lifetime); when a later PDU for that
    destination reaches such a relay the sim takes the DIRECTED branch, reads bearer 0, and calls
    `enqueue_net_to(to_node=0)` — bearer 0 is simultaneously "no bearer" and node index 0, so the
    PDU is delivered only to node 0 instead of flooded. Worst after an unanswered discovery
    (entries persist, all traffic to that target through DF relays silently misdelivered).

77. **[P1] meshd_bearer_blued.c:1811-1815 — `memmove()` size underflow (crash) when the socket is
    closed while a frame is being processed**
    `meshd_blued_pump_rx()` frame processing can synchronously close the connection (resetting
    `bc->rxn = 0`) — e.g. a NOTIFY event → pbgatt drain → send() fails EPIPE → transport-failed →
    close. Control then reaches `frame_done:` where
    `memmove(bc->rx, bc->rx + framelen, bc->rxn - framelen)` computes `0 - framelen` as `size_t`
    → ~SIZE_MAX-byte memmove → segfault. The `if (bc->fd < 0) return` guard sits *after* the
    memmove; it must precede it.

78. **[P2] mesh_sim.c:844-849,889-904,1725,1786 — friendship credential used to secure *all*
    control TX, including Segment Acks to third parties**
    Once `have_friend_cred` is set, `node_tx_control()` secures *every* control PDU with the
    friendship credential, not just Friend Poll/queue traffic. A third node A's segmented message
    to Friend F gets Segment Acks secured under the friendship NID/keys that A can't decrypt — A
    retransmits until SAR retries are exhausted. Friendship material is only for Friend↔LPN
    (MshPRT §3.6.6.2).

79. **[P2] mesh_df.c:914-916 — relays install Forwarding Table entries with their *local*
    lifetime, ignoring the Path Request's `Path_Lifetime`**
    `recv_path_request()` parses `req.lifetime` but passes `mesh_df_lifetime_ms[node->lifetime]`
    to `mesh_df_table_add()`. MshPRT §3.6.6.5.1 requires using the received Path_Lifetime. An
    origin configured for 24 h gets intermediate hops that expire after their local default
    (~12 min), severing the path mid-life. The sim's parallel handler uses `req.lifetime`
    (mesh_sim.c:1415) — the two disagree.

80. **[P2] meshd_bearer_blued.c:830-842 — one failing proxy link aborts the ADV broadcast of a
    mesh PDU**
    For NET/BEACON PDUs `meshd_blued_tx` pushes to every subscribed GATT proxy link and returns
    −1 on the *first* `mbw_proxy_tx()` failure — before trying the remaining links and before
    the PDU is queued for `IPC_MESH_ADV_SEND`. A single stalled proxy client (ENOBUFS) drops the
    PDU from the radio bearer network-wide, contradicting the file's own "fail only its owning
    link" design.

81. **[P3] mesh_sim.c:1725,1786 — Segment Acks sent for group/virtual-addressed segmented
    messages**
    `send_seg_ack()` is gated only on the ack destination (always unicast), never on the received
    DST being a unicast of this node. MshPRT §3.5.3.4 forbids acking group/virtual segmented
    messages; the sender side agrees (`sar_tx_record()` refuses group-DST). Every subscriber
    emits acks nobody consumes.

82. **[P3] mesh_sim.c:1725-1726,1786-1787 — Segment Ack TTL echoes the residual received TTL**
    Acks are sent with `pdu.ttl` (already-decremented) instead of a default TTL; on asymmetric
    routes/small TTLs the ack expires before reaching the SAR origin, forcing needless
    retransmission cycles.

83. **[P3] mesh_df.c:1106-1133 — Path Echo Reply matched against the wrong table entry when two
    paths share an endpoint**
    The match loop takes the first entry whose origin or target equals the echoed destination,
    ignoring which path the reply traverses. A node that both originates a path to T and relays
    (O2, T) refreshes the wrong entry and forwards O2's echo reply toward the target (wrong
    direction); O2's echo times out and a healthy path is torn down.

84. **[P3] mesh_df.c:956-957 — re-flooded Path Request readdressed from the all-DF group to the
    unicast destination, and SRC not re-originated**
    The relay role emits the forwarded request with `dst = req.destination` instead of the
    all-directed-forwarding-nodes group (0xFFFB); a conformant downstream receiver filters on
    network DST and discards it. Latent: currently only mesh_sim.c uses the DF library and
    bypasses this function.

85. **[P3] mesh_sim.c:705-712,1893-1894 — proxy GATT-in PDU never processed by the proxy node
    itself**
    `mesh_sim_proxy_gatt_in()` reinjects with `tx_node = proxy->index`, and `mesh_sim_step()`
    skips delivery to `tx_node`, so a Network PDU whose DST is the proxy node (or a subscribed
    group) is retransmitted onto the bearer but never delivered locally — MshPRT §6.7 requires
    the Proxy Server to also hand the PDU to its own network layer.

*Round 2 clean (routing lens): try_decrypt candidate sizing, reassembly bounds (384 vs 380),
SeqAuth underflow/13-bit checks, RPL advance on SAR completion, friend-queue dedup,
forwarding-number serial arithmetic, bearer AD-type mapping & event bounds, mbw reserve
accounting.*

### Round 2 — blued concurrency lens (deep pass)

*(This pass re-derived the `ctl_acquires` registry race already recorded as finding 58; the
following are the additional, distinct findings.)*

86. **[P1] blued_event.c:1552,1681-1691 + blued_peripheral.c:216 + blued.c:2063-2068 +
    blued_event.c:1383 — `blued_conn_disconnect` on a CONNECTING conn tears down/frees state
    under a live setup thread (UAF)**
    `blued_conn_disconnect` guards only IDLE and `att_ops_active`; nothing stops it running while
    a detached setup thread owns the conn. Callers that hit CONNECTING conns lack the guard the
    DISCONNECT verb has (ctl_conn.c:340-343): duplicate peripheral accept, adapter loss, POWER-off
    → `blued_adapter_controller_invalidated`, and the 30 s indication timeout armed by the
    peripheral setup thread itself. For a central conn it does `att_close` + `free(conn->hogp)`
    while `blued_conn_setup_central_impl` is still dereferencing `dev` (seconds of blocking
    discovery/pairing) — `hogp_device` has no refcount → use-after-free. Trigger: unplug the
    controller (or POWER off, or same-peer duplicate-accept) mid-pairing.

87. **[P2] iso.c:1012 → ctl.c:477-488,318-342 — `blued_ctl_send_fd` mutates a client's txq
    without `ctl_clients_lock`**
    `iso_on_cis_established` (main thread) calls `blued_ctl_send_fd`, which STAILQ_INSERT_TAILs
    on `client->txq` + flush with no lock, while a GATT worker concurrently appends frames to the
    *same* client's txq under the lock (`ctl_gatt_job_send`, `blued_ctl_notify_value`). A client
    with a pre-registered CIS acquire plus GATT traffic → concurrent STAILQ insert → list
    corruption/crash/lost frames. Every other txq writer takes the lock; this is the one hole.

88. **[P2] ctl.c:1732 → ctl_conn.c:173; ctl.c:4449 → blued.c:2063-2068 → ctl_gatt.c:269/ctl.c:784
    — more dispatch paths re-acquire `ctl_clients_lock` already held by dispatch (same class as
    finding 30, different sites)**
    STATUS verb: dispatch (lock held) → `ctl_send_status_reply` → `ctl_status_snapshot` relocks
    `ctl_clients_lock`. POWER-off verb: → `blued_adapter_set_power` →
    `blued_adapter_controller_invalidated` → `blued_conn_disconnect` → `ctl_gatt_conn_gone` /
    `blued_ctl_broadcast_conn_event`, both relocking. With FreeBSD's ERRORCHECK-default mutex the
    relock returns EDEADLK (ignored) and the inner unlock releases the lock early, destroying the
    dispatch critical section. A systematic sweep of everything reachable from
    `ctl_process_frame` is warranted.

89. **[P2] blued_central.c:602-611,666-667,1736 — vhid fd registered in kqueue before connection
    handoff; failure path leaks a registered fd → event-loop spin**
    The central setup thread registers `dev->vhid_fd` well before the conn is handed off, but the
    conn is already on `blued_g.conns`, so main's handler calls
    `hogp_handle_vhid_output → att_write_cmd` concurrently with the setup thread still operating
    on the same `att_conn` (att_open_eatt, or att_close on setup failure → write to a
    closed/reused fd). Trigger: kernel emits the initial LED output report right after
    VHID_ATTACH. On the needs_cleanup failure path nothing deregisters/closes vhid_fd, so a
    leaked readable vhid fd stays registered forever → 100% CPU livelock.

90. **[P2] ctl_gatt.c:171,199,348,744 + ctl.c:1608 — GATT worker jobs re-resolve the connection
    by address, bypassing the ref/att_ops_active taken at admission**
    `ctl_gatt_job_start` refs `conn` and bumps `att_ops_active`, but the run-time functions
    re-look up by peer address. Duplicate-accept can put a *second* conn for the same peer on the
    list while the first's teardown is deferred; the lookup returns the new conn, on which the
    worker does blocking ATT I/O with `att_ops_active==0` and no reference — both the event loop
    and the worker `recv()` the same ATT fd (the stolen-response bug the ownership scheme
    prevents), and the unreferenced conn can be freed mid-op → UAF. Fix: operate on `job->conn`.

91. **[P3] ctl.c:2402-2404,2596-2599 — `att_ops_active` transition and its EV_DISABLE/EV_ENABLE
    side effect are not atomic as a pair**
    Worker decrements 1→0, is preempted before EV_ENABLE; main admits a new job (0→1) and applies
    EV_DISABLE; worker resumes and applies EV_ENABLE → filter left enabled during the new job.
    The recv-guard prevents data theft, but the handler refuses the level-triggered readable
    event → event loop spins until the worker drains the fd. Transient CPU burn.

92. **[P2] blued.c:1649/1660/1680 + blued_devmgr.c:169-205 vs ctl.c:3064/3176/3206/3213 —
    `adapter->reslist` resolving-list shadow mutated from two threads with no lock**
    Setup threads mutate it after pairing (`blued_reslist_sync_remove/add` do
    count++/memmove/count-- with no internal locking); the dispatch thread mutates the same
    struct via RESOLV_ADD/REMOVE/CLEAR and UNBOND. Pairing completing on a setup thread while the
    operator runs UNBOND/RESOLV → racing memmove/count (two removes double-decrement) corrupts
    the shadow, diverging the host mirror from the controller resolving list. (Distinct from the
    shared-hci_fd finding 43.)

93. **[P2] blued.c:4088-4124,4069,4110-4113 — central-mode shutdown frees `conn->hogp` before
    stopping the GATT workers**
    Shutdown does `free(sc->hogp)` + `blued_conn_free` before
    `blued_ctl_cleanup → ctl_gatt_workers_stop`, and the spin-wait waits only on setup workers,
    not GATT workers. A worker mid-job using `conn->att == &hogp->att` (protected only by the
    conn refcount, which doesn't cover `hogp`) → use-after-free when SIGTERM arrives during an
    in-flight client GATT operation.

94. **[P2] blued.c:665-671,730-736 vs ctl.c:2968,2989 — passkey/numcmp reply can arrive before
    the waiter arms the reply slot (lost reply)**
    `passkey_display` emits the PASSKEY_INPUT event *before* taking `pairing_lock` and setting
    `passkey_reply_status = 0`; the replier only accepts when status==0. An automated agent's
    immediate reply in that window is rejected NOT_FOUND, the setup thread then blocks the full
    30 s timedwait, and pairing fails despite a timely answer. (The condvar predicate loops
    themselves are correct.)

95. **[P2] blued_event.c:788-861,873-884 + ctl_gatt.c:132-141 + blued_central.c:587,644-652 —
    `conn->att` internals written concurrently under a read lock or no lock**
    Main writes ATT security state and closes EATT bearers holding only the conns **rd**lock (no
    exclusion): encryption-change handlers write `encrypted/authenticated/enc_key_size` and call
    `att_close_eatt`. Concurrent writers: worker `ctl_elevate_security` (no lock) and the setup
    thread's `att_open_eatt` on the same `att_conn`. Encryption-failure event on main →
    `att_close_eatt` while the setup thread appends bearers → double-close / torn eatt array / fd
    leak. Also `blued_eatt_accept` (blued_peripheral.c:1130) attaches a bearer with no
    `att_ops_active` gate (unlike the EATT_OPEN verb).

*Round 2 clean (concurrency deep pass): hci_conn.c wrappers, ctl_iso.c main-thread dispatch,
iso.c iso_lock/refcounts, conn.c refcounting & timer deletion; blued_devmgr helpers correct in
isolation (defect is in callers, finding 92).*

### Round 3 — blued daemon lifecycle / config / hotplug lens

96. **[P3] blued.c:936,2686 (arrays) vs blued.c:1757-1832 + conn.c:598-610 (unbounded enum) —
    stack buffer overflow with more than 8 HCI controllers**
    Adapter auto-enumeration inserts one adapter per connected HCI node with no
    `BLUED_MAX_ADAPTERS` cap and assigns unbounded indices, but `blued_set_rpa_timeout` and the
    SIGHUP privacy-transition in `blued_reload_config` declare
    `struct blued_adapter *changed[BLUED_MAX_ADAPTERS]` (=8) and fill it inside an unbounded
    `LIST_FOREACH`. On a host with 9+ controllers a runtime RPA-timeout change or SIGHUP privacy
    toggle writes past the 8-slot stack array. Latent (few systems have that many radios) but a
    real unbounded write.

97. **[P3] config.c:400-403 + config.h:87 — `auto_connect_max_tries` parsed, clamped, documented,
    but never applied**
    No consumer reads the field (grep-confirmed): not the auto-connect spawn path
    (blued.c:3802-3827), reconnect timer (blued_event.c:1463-1533), or blued_central.c. An
    operator setting `auto_connect_max_tries = 1` still gets indefinite reconnection (bounded
    only by the backoff). Silent no-op knob.

98. **[P3] blued.c:2606-2764 — `privacy_mode` change silently ignored on SIGHUP with no
    diagnostic**
    `blued_reload_config` parses `privacy_mode` into `newcfg` but never compares/applies it and,
    unlike every other restart-required key, emits no "restart required" line. An operator
    switching `device`→`network` gets no signal the edit was dropped.

99. **[P3] config.h:35-36 + blued.conf.sample:49-50 — `key_dist` default doc contradicts the
    actual mask**
    The default `0x0b` is documented as "LTK + IRK + CSRK" / `"enc,id,sign"`, but per smp.h:84-87
    `0x0b = ENC|ID|LINK` — it contains the LINK key and *not* CSRK. Code is internally consistent
    (matches smp.c:185-188); only the header comment and sample config are wrong, which will
    mislead `key_dist` tuning.

*Round 3 clean (lifecycle lens): signal handling (SIG_IGN + EVFILT_SIGNAL, no async-safety
hazard), daemonization/pidfile ordering, adapter-enum error paths (fd/calloc cleanup),
security-option propagation to central & peripheral SMP, socket broker fd passing, Capsicum fd
limiting. Minor: `blued_adapter_lost` leaves periph/eatt listen fds registered until shutdown
(benign, reclaimed at exit).*

### Round 3 — libbluetooth / vhci deep lens

100. **[P2] lib/libbluetooth/hci.c:533-543 — `bt_devinquiry` drops ~half of multi-response
     inquiry results**
     The copy loop decrements `num_rsp` inside the body while `num_rsp` is also part of the loop
     bound: `for (n = 0; n < MIN(count, num_rsp); n++) { ...; num_rsp--; }`. Since `n` counts up
     and `num_rsp` counts down each iteration, bound and index converge twice as fast: an
     INQUIRY_RESULT with 8 responses copies only 4 and `bt_devinquiry()` returns 4, silently
     discarding the rest. Upstream FreeBSD decrements *after* the loop (`num_rsp -= n`). Wrong in
     normal operation whenever a controller reports 2+ devices in one result event. (Under-count,
     not an overflow.)

101. **[P3] lib/libbluetooth/bluetooth.c:265-272 — `bt_endprotoent()` ignores `proto_stayopen`**
     `bt_endhostent()` honors `host_stayopen` but `bt_endprotoent()` unconditionally `fclose`s
     `protof`, so `bt_setprotoent(1)` has no effect — the protocols file is reopened every
     `bt_getprotoent()` cycle. Results correct; stayopen contract broken, asymmetric with the
     host path.

102. **[P3] sys/netgraph/bluetooth/drivers/vhci/ng_hci_virt.c:571-578,142-165 — node bare-pointer
     UAF/double-unref race between VHCI_DESTROY/unload and external `ngctl shutdown vhciN`**
     `sc->node` holds only the create-time reference (no extra `NG_NODE_REF`). `vhci_teardown()`
     reads and clears `sc->node` under the mutex, unlocks, then calls `NG_NODE_REALLY_DIE` +
     `ng_rmnode_self`. An `ngctl shutdown vhciN` in that window runs `ng_hci_virt_shutdown()` →
     `NG_NODE_UNREF` and frees the node; teardown then dereferences freed memory. Narrow
     (deliberate concurrent external shutdown), fix is to hold an explicit ref for `sc->node`.

103. **[P3] ng_hci_virt.c:142-165 — external `ngctl shutdown vhciN` leaks the cdev and softc
     slot**
     `ng_hci_virt_shutdown()` clears `sc->node`/`sc->hook` but never removes `sc` from
     `vhci_units[]` nor `destroy_dev(sc->cdev)`. `/dev/vhciN` and the slot persist as a defunct
     instance; repeated external shutdowns without matching destroys exhaust the 16 unit slots
     (ENOSPC).

*Round 3 clean (libbluetooth/vhci lens): bt_devreq event-match & rparam length guards (unsigned
promotion rejects short events), COMMAND_STATUS/COMPL dispatch, byte-order compares, bt_aton/
ntoa, timeout/EINTR loops, host/proto file parsing bounds; vhci rcvdata mbuf freeing,
send_upstream hook ref dance, dev_read/write/poll blocking & partial-read handling, teardown
dying/destroy_dev drain, create/destroy EBUSY gating.*

### Round 3 — malformed / hostile wire-input lens

104. **[P3] att_server_dispatch.c:313-314,331-333 + att_server.c:96-99 — read of uninitialized
     stack `uuid128` on `ATT_READ_BY_TYPE_REQ` with Attribute Type 0x0000**
     A 7-byte `ATT_READ_BY_TYPE_REQ` with a valid 2-octet Attribute Type whose value is `0x0000`
     passes the length gate; `att_extract_uuid(pdu+5, 2, …)` sets only `uuid16` and leaves
     `uuid128` untouched. Since `uuid16 == 0`, `use_uuid128 = true` and the loop runs
     `memcmp(a->uuid128, uuid128, 16)` against the uninitialized stack buffer. In-bounds read (no
     crash) but 128-bit attributes may spuriously match/mismatch. Root cause: using `uuid16 == 0`
     as the "type was 128-bit" sentinel; a real 0x0000 2-octet type should be rejected as Invalid
     PDU (the sibling group-type handler does). MSAN/valgrind would flag it.

105. **[P3] lib/libble/ble.c:1140-1144 — SCM_RIGHTS descriptor extracted without validating
     `cmsg_len`**
     `ble_recv_fd` matches `SOL_SOCKET`/`SCM_RIGHTS` and does `memcpy(out_fd, CMSG_DATA(cmsg), 4)`
     with no `cmsg_len >= CMSG_LEN(sizeof(int))` check. A daemon peer sending an SCM_RIGHTS
     message with zero descriptors makes `*out_fd` a garbage integer that may alias an unrelated
     open descriptor. Not OOB (`cbuf` is `CMSG_SPACE(sizeof(int))`); requires a hostile/buggy
     daemon on the trusted fd-passing socket. Reachable via `ble_acquire_*`.

*Round 3 clean (malformed-input lens — strong result): blued HCI event/adv-report parsers
(envelope `n == buf[2]+3`, exact subevent gates, zero-adlen rejection), ATT/GATT server & client
element-list parsers (no underflow, non-zero/whitelisted/divisible per-element length), SMP
(MSG_TRUNC + exact/min length gates, signed `ssize_t` throughout), libmesh net/transport/access/
proxy/beacon/provision/cfg/df decoders (all length-check before field reads, bounded reassembly,
guaranteed loop advance), libble framing. No P1/P2 over-read/underflow/length-trust found beyond
the known set.*

### Round 3 — meshd remaining files (protocol lens)

106. **[P3] meshd_node.c:2726-2727,2746,2767,2791 — Health Fault Get/Test/Clear ignore the
     request's Company ID (wrong echo, and replies where it must stay silent)**
     All three handlers parse `company` but never use it; `meshd_fault_snapshot` hardcodes
     `fs->company_id = nd->health.company_id` and copies the node's own fault array. MshPRT
     §4.4.3.2.2 requires echoing the incoming Company ID and *ignoring* (no reply) any
     Fault Get/Test/Clear whose CID identifies no Health Fault state on the node. A Health Client
     sending Fault Get with CID 0xFFFF gets a spurious Fault Status carrying the node's own CID
     instead of silence. Works only when the client happens to use the node's CID.

107. **[P3] meshd_config.c:260 — `device_key` excluded from the "readable by others"
     credential-store guard**
     `meshd_config_load` rejects a group/world-readable config only when `have_netkey ||
     have_appkey`, but `device_key` sets a third long-term secret (`have_device_key`) and is
     omitted, so a `meshd.conf` supplying only `device_key` at mode 0644 loads without the
     intended EPERM rejection. `have_device_key` should be part of the same condition.

*Round 3 clean (meshd protocol lens): meshd_models CTL/level/scene mappings, meshd_cfgclient
status-opcode selection & SEQ accounting, meshd_pbgatt segmentation/timeout framing,
meshd_proxy_gatt session matching/SAR, meshd_persist encode/decode symmetry & version gates,
meshd_node opcode→handler routing/model lookup/subscription/KR phase machine.*

### Round 4 — mesh provisioning / manager state-machine & address lens

108. **[P2] mesh_provision.c:210,316 — `prov_caps_valid` wrongly requires the HMAC-SHA256
     algorithm bit, rejecting spec-legal CMAC-only devices**
     The validator returns invalid whenever `(algorithms & MESH_PROV_ALGO_BIT_P256_HMAC) == 0`,
     mandating algorithm 0x01. Per MshPRT Table 5.21 / §5.4.1.4 a Provisionee may advertise only
     `BTM_ECDH_P256_CMAC_AES128_AES_CCM` (bit 0) — the spec even presupposes CMAC-only devices
     ("shall not use CMAC if another algorithm is supported"). Since `mesh_prov_caps_parse` calls
     this on the receive path and returns -1, a provisioner receiving a legitimate CMAC-only
     (e.g. Mesh 1.0) device's Capabilities aborts provisioning outright. Asymmetric with
     `prov_start_valid` (line 232), which accepts algorithm 0x00.

109. **[P3] mesh_provision.c:908-958 — ProvisioningSalt/SessionKey/DeviceKey primitives can't
     express the HMAC (0x01) algorithm sizes**
     The module implements the full algorithm-0x01 confirmation path (32-octet s2 salt, HMAC
     confirmation), but `mesh_prov_provisioning_salt` is hardcoded to 16-octet
     conf_salt/rand_prov/rand_dev (48-octet s1 input). For algorithm 0x01 the spec (§5.4.2.5)
     uses a 32-octet ConfirmationSalt and 32-octet randoms (96-octet input). Any HMAC-algorithm
     provisioning reaching these functions derives SessionKey/Nonce/DevKey from a truncated,
     wrong salt. P3 only because the FSM caller lives in mesh_provisioner.c; the primitive set is
     internally inconsistent for a mode the module otherwise fully implements.

*Round 4 clean: mesh_manager.c address allocation (32-bit no-wrap block math, 0x8000 sentinel,
contiguous multi-element blocks, half-open find_by_addr, symmetric CRC framing),
mesh_remote_prov.c PDU-number sequencing/link-state/scan filtering, provisioning ECDH peer-key
validation (rejects off-curve/infinity), 145-octet confirmation-input assembly, session-nonce.*

### Round 4 — SMP pairing state-machine / key-lifecycle lens

110. **[P1] smp_legacy.c:255-264,330 + smp_keys.c:335-340; surfaces at blued_event.c:423-436 —
     legacy responder overwrites its OWN distributed LTK/EDIV/Rand with the initiator's, breaking
     peripheral reconnection**
     In `smp_respond_legacy()` the peripheral generates and stores its own LTK/EDIV/Rand in
     `bond`, then calls `smp_receive_peer_keys(..., pres[5], false)`. When the initiator
     distributes EncKey (the default), `smp_receive_peer_keys` overwrites `pending.ltk/ediv/rand`
     with the *initiator's* Encryption Information / Central Identification and `*bond = pending`
     — so the peripheral persists the initiator's key material instead of its own. On reconnect
     the central sends the peripheral's distributed EDIV/Rand, but the LTK-request handler
     compares against `bond->ediv/rand` (now the initiator's) → always "mismatch" → negative
     reply. Every reconnection to a bonded LE-legacy peripheral fails, including blued↔blued. The
     central side is correct (stores only the peer's keys).

111. **[P2] smp_keys.c:429-433,390-407 — no bond-overwrite downgrade protection: a weaker
     re-pairing silently replaces a stronger stored bond**
     `smp_bond_db_store()` matches by `(addr_type, addr)` and unconditionally
     `smp_bond_copy_keys()`, overwriting ltk/is_sc/is_mitm/key_size/link_key with the new
     pairing's values, with no old-vs-new security-level comparison. An already-bonded peer
     (default bondable) that re-pairs can downgrade a stored SC/MITM bond to LE-legacy Just Works
     (possibly 7-octet key); an SC-Just-Works re-pair also copies `has_link_key=false`/zeroed
     link_key over a previously CTKD-derived authenticated BR/EDR link key, destroying the
     cross-transport bond. Core Spec Vol 3 Part H §2.4.2.4 requires a stronger key not be
     replaced by a weaker one.

112. **[P3] smp_keys.c:305-332 — cumulative §3.4 pairing deadline not enforced during
     key-distribution receive**
     `smp_receive_peer_keys()` sets a fresh 5 s `SO_RCVTIMEO` and reads each key PDU with raw
     `smp_log_recv()` instead of the timeout-aware `smp_recv_timed()`; the authoritative 30 s
     `smp_pairing_timed_out` deadline is never checked in this loop, so a peer answering each of
     up to 5 key PDUs just under 5 s can extend key distribution to ~25 s beyond budget. Bounded
     by the per-PDU timeout — latent robustness gap.

*Round 4 clean (SMP state-machine lens): IO-capability→method tables vs Core 6.3 Table 2.8
(legacy + SC, all NumCmp/JustWorks cells), passkey display/input role dispatch, EncKey
suppression under SC, responder-first key-dist ordering, CTKD H6/H7 direction & CT2/is_mitm/
bonding gating, identity-address mapping & RPA bond lookup, SC confirm-commitment ordering.*

### Round 4 — local GATT server DB / advertised-content lens

113. **[P3] att_server.c:283-294,336-347 — writable characteristic created with an empty initial
     value is permanently unwritable**
     `value_maxlen` is set only inside `if (len > 0)`. A characteristic declared WRITE/
     WRITE_ENCRYPT with `initial_value_len == 0` (a legal config/app definition) gets
     `value == NULL`, `value_maxlen == 0`, so every client write is rejected with
     INVALID_ATTR_LEN (att_server_dispatch.c:901). A `char { properties write; }` with no `value`
     in blued.conf is dead-on-arrival; the built-in Custom characteristic (1-byte init) likewise
     can never hold more than 1 octet.

114. **[P3] att_server_notify.c:115-136 — `att_send_indication` never arms its own confirmation
     timer (fragile contract)**
     On success it sets `ind_pending = true` but does not arm the mandatory 30 s confirmation
     timer, relying on every caller to do so. If any caller forgets, `ind_pending` stays set
     forever and all future indications on that bearer return EBUSY, wedging Service Changed. Both
     production callers currently arm it — latent (the comment marks it DEFERRED).

115. **[P3] blued_peripheral.c:821-823 — Central Address Resolution hard-coded to 0x01
     (Supported)**
     The GAP Central Address Resolution characteristic (0x2AA6) is always built with 0x01
     regardless of whether LL Privacy/address resolution is actually enabled on the adapter,
     telling a peer it may use RPAs and expect resolution. Likely accurate (blued ships
     hci_privacy.c) but static rather than derived from adapter capability.

*Round 4 clean (local-GATT-DB lens — strong result): handle assignment/ordering (value ==
decl+1, CCCD placement, strictly increasing, sorted binary-search), service grouping end-handle,
all mandatory characteristics & property bits (Service Changed INDICATE-only, CSF READ|WRITE,
Database Hash READ, SSF READ, Appearance 2-octet LE), Database Hash computation vs Vol 3 Part G
§7.3.1, hash-recompute + Service Changed on DB change, robust-caching gate vs Fig 2.6/2.7,
per-client CCCD state, adv_builder AD-type constants (no production callers; live path
`ble_build_adv_data_flags`). No P1/P2 found.*

### Round 4 — error-propagation / partial-failure / rollback lens

116. **[P2] iso.c:977-989,993-1003 — CIS establishment failure is never reported to the
     requesting client**
     `iso_on_cis_established`'s docstring promises to "report the loss so the requester does not
     wait forever," but the `status != 0` branch (and the identical `paths_up == 0` branch) only
     unlinks/unrefs the stream and removes the orphaned CIG — no control event. The ISO event
     vocabulary is only `IPC_ISO_EV_CIS_REQUEST`/`IPC_ISO_EV_ESTABLISHED` (both success-side), so
     a client that issued `ISO_CIS_CREATE` (holding `requesting_client_fd` for the fd handout, or
     an ESTABLISHED subscriber) waits indefinitely on every peer-reject / setup-timeout.

117. **[P2] meshd_node.c:1975-1981 (h_appkey_add) — AppKey DB entry committed before the crypto
     layer accepts it; on sim failure the node reports failure but keeps the key**
     The persistent DB entry is committed first (`e->valid=1`, key copied), then
     `mesh_sim_add_appkey` is attempted; on failure `status` is set to INSUFFICIENT_RESOURCES but
     the DB entry is not rolled back. The client gets an AppKey Status failure while
     `db.appkeys[]` records (and persists) the key as valid — AppKey Get lists it, but model
     traffic bound to it can't be decrypted. DB diverges from crypto.

118. **[P2] blued_central.c:536,965-979 — cache-hit reconnect overwrites the persistent GATT
     handle cache with zeroed metadata handles** *(related to finding 61; distinct mechanism)*
     `blued_conn_setup_central_impl` unconditionally calls `hogp_cache_save(dev,&bond)` on both
     paths, but `hogp_cache_save` derives the metadata handles from `dev->hid_disc`, which the
     cache-hit restore path never populates. A normal reconnect of a bonded, hash-matching device
     has `hid_disc.nchars==0`, so the save zeroes `report_map_handle` etc.; the *next* connect
     sees `report_map_handle==0`, skips the Report Map read, and discards the cache (ENOENT). The
     cache works only every other reconnect and the bond is churned each time (self-heals via
     rediscovery).

119. **[P3] blued_central.c:215-234 (consumed at ctl.c REKEY) — REKEY reports success when
     post-pairing encryption times out, leaving the ATT gate closed and the resolving list
     un-reprogrammed**
     After `smp_pair()` succeeds, a `hci_wait_encryption` timeout `return (0)`s, skipping
     `att_conn_apply_encryption` and the `blued_reslist_sync_remove/add` reprogramming of the
     rotated IRK. REKEY maps 0 to `IPC_ERR_NONE`, so the operator is told rekey succeeded though
     the security gate never reopened and the controller resolving-list entry holds the stale IRK.
     Self-corrects on reconnect.

120. **[P3] blued_peripheral.c:669-674 — server db_hash advanced even when the Service Changed
     indication send fails, stranding a stale client cache**
     On a bonded-peripheral reconnect with a changed DB hash, `gatt_send_service_changed()` (which
     only logs an `att_send_indication < 0`) is called and then `bond->db_hash` is unconditionally
     advanced and committed. If the indication actually failed, the next reconnect sees a matching
     hash, never resends Service Changed, and the peer keeps using stale cached handles.

121. **[P3] ctl.c:1504-1516,2939 — ACQUIRE can send a success OP_REPLY then a second OP_ERROR for
     the same request (double reply, fd never delivered)**
     `ctl_acquire_create` sends the success OP_REPLY (MTU handout) at :1504; if the subsequent
     SCM_RIGHTS fd handout fails it returns -1, which the dispatcher maps to a second
     `ctl_send_op_error` for the same request id. The client gets success-then-error and never the
     promised fd, desyncing a client that expects the SCM_RIGHTS message next.

122. **[P3] ctl.c:3204 (RESOLV_ADD) — `hci_le_set_privacy_mode()` return ignored; failed step
     reported as success**
     After a successful `hci_le_add_dev_resolving_list()`, the follow-up
     `hci_le_set_privacy_mode()` return is discarded and the entry is recorded with
     `IPC_ERR_NONE`. If Set Privacy Mode is rejected, the peer is in the resolving list with the
     wrong privacy mode while the client is told it is fully configured.

123. **[P3] meshd_node.c:3663-3665 (meshd_provisioner_begin) — provisioner marked active before
     the link opens; on open failure the flag sticks and the session leaks**
     `provisioner_active = 1` is set, then `mesh_prov_link_open(...)` is returned directly. If it
     fails, the caller sees failure but `provisioner_active` stays 1 and `prov_sess` is never
     freed, blocking later provisioning. Latent.

*Round 4 clean (error-propagation lens): hci_conn.c HCI wrappers (status checks, fd close on
failure), ctl_gatt.c GATT-DB add/subscribe rollback (mark/rollback txn, remote CCCD rollback),
iso.c CIG/BIG multi-step rollback (only gap is the missing notification, finding 116),
meshd_persist.c atomic save (mkstemp→write→fsync→rename→dir-fsync) & decode-into-temp load,
mesh_key_refresh.c phase machine, mesh_manager.c PDU builders.*

### Round 5 — spec-constant / opcode / encoding conformance audit

124. **[P2] blued_le_meta.h:229,362 — Advertiser_PHY = LE 2M (0x02) rejected as malformed in two
     LE Meta decoders**
     LE Periodic Advertising Sync Established (subevent 0x0E, guard `p[11] != 0x01 && p[11] !=
     0x03`) and PAST Received (subevent 0x18, guard `p[15] != 0x01 && p[15] != 0x03`) both treat
     Advertiser_PHY 0x02 as malformed and return -1. Core 6.3 §7.7.65.14/.24 define
     `0x01=1M, 0x02=2M, 0x03=Coded`. Since the guard fires only on a *successful* sync
     (`p[0]==0`), a genuine sync/PAST from an advertiser whose periodic train uses the LE 2M PHY
     is silently dropped and never reported to the app. Fix: `p[11] < 0x01 || p[11] > 0x03` (and
     likewise `p[15]`).

*Round 5 clean (constants audit — comprehensive, on record): hci_util.h LE feature/event-mask
bits & adv-type/property/own-addr/AD-flags constants; blued_le_meta.h all subevent codes & field
ranges (only the 2M defect above); att.h ATT opcodes/error codes/GATT UUIDs/EATT PSM/MTU; smp.h
SMP opcodes/IO-caps/AuthReq/key-dist/failure-reasons/RPA masks; ble_util.h Base UUID; HCI OCFs
(full LE block) & event codes via NG_HCI macros; HOGP/GATT/DIS/Battery/GAP UUIDs & AD types;
libmesh SIG model IDs, access opcodes, address boundaries, virtual-addr mask, company 0xFFFF, 18
Config status codes. One mismatch total.*

### Round 5 — end-to-end IPC / CLI integration

125. **[P2] bluedctl.c:656-657 + ble.c:3208-3219 vs ctl.c:3254-3261,2948-2953 — `bluedctl pair
     <addr>` maps to a connection-existence probe, not pairing or bond-status**
     The CLI encodes `IPC_SECURITY_PAIR` fire-and-forget; the daemon handler only returns
     `ctl_security_conn(...) != NULL ? IPC_ERR_NONE : IPC_ERR_NOT_CONN` (a `blued_conn_by_peer`
     lookup) — it starts no SMP pairing and returns no bond info. `bluedctl pair AA:...:FF`
     performs no pairing, reports no bond status, prints nothing, and exits 0 regardless. Help
     text documents it as "Report/Check bond status." No-op relative to its documented purpose.
     (Distinct from finding 37, which is the daemon-side contract; this is the CLI-to-verb
     semantic mismatch. Two minor meshctl doc-only gaps also noted: `provision-gatt` verb sketch
     omits optional `[public|random] [adapter=N]`; `key-refresh begin`/`network` need an
     undocumented `<newkey-hex>` arg.)

*Round 5 clean (IPC/CLI integration — comprehensive, both sides traced byte-for-byte): all GAP
(connect/disconnect/set-phy/set-data-len/connparams/scan/list + events), CTL (power/privacy/
pairable/advertise/discoverable/set-mtu/gatt-begin-commit-rollback/status/adapters), GATT (read/
write/subscribe/set-value/add-service/add-char/remove + events), SECURITY (passkey/confirm/unbond/
rekey/bonds/resolv/bond-export-import), ADV, L2CAP (eatt-open/close) framing/offsets/endianness
match; meshctl positional verb args all match meshd_ctl parser. IPC tightness comes from shared
ipc_proto.h encode/decode helpers.*

---

## Bluetooth review — COMPLETE (converged)

5 rounds / 21 reviewer passes / ~15 distinct lenses. **125 findings**: see per-round sections.
Round 5 (constants audit + IPC/CLI integration) surfaced only 2 new P2s and otherwise validated
large surfaces as correct — the review has converged. A 6th round would be expected to yield only
additional P3s.

**Severity tally:** P1 = 8 (findings 6, 16, 27, 28, 29, 30, 40, 41, 42, 86, 110 — several of the
"P1" bullets are grouped; see sections), P2 ≈ 45, remainder P3.

**Highest-priority fixes (P1):**
- **6** Time model bit-packing wrong on the wire (mesh_time_scene.c)
- **16** Friend Update MD perpetual-poll livelock (mesh_friend.c)
- **27** bluectl entirely dead (text vs binary protocol)
- **28/29** security-event addr_type / libble uninitialized adapter_index → pairing prompts unanswerable
- **30/86/88** ctl_clients_lock reacquired under dispatch (ERRORCHECK early-unlock) — a whole class
- **40** uninitialized Command-Status reads (13 HCI wrappers)
- **41** HCI event filter drops Encryption Change v2 / Disconnection Complete / Key Refresh
- **42** mesh TX permanently wedges after first PDU (adv set never disabled + handle collision)
- **110** SMP legacy responder persists initiator's LTK → every LE-legacy peripheral reconnect fails

---

## Completeness Round — product/feature gaps (added later)

Gap analysis: features declared/documented/library-supported but not wired end-to-end, distinct
from the 125 correctness findings above. Verified on both the declaration/doc side and the
missing-implementation side.

### meshd / meshctl / libmesh

126. **[P2] Config Client cannot send SAR / Private Beacon / Private Proxy / Private Node Identity
     / Large Composition Data** — libmesh declares the full builder set
     (mesh_manager.h:665-733) and meshd's Config *Server* answers every one
     (meshd_node.c:2814-3087), but the Config *Client* dispatcher
     (meshd_cfgclient.c:283-748) calls none of these builders and meshctl exposes no sub-verb. A
     manager can configure these states on itself but on no roster node.
127. **[P2] `provision-scan` is a no-op** — documented (meshd.8:247, meshctl.8:65) with libmesh
     support (`mesh_unprov_beacon_parse`), but the bearer only parses secure beacons; the ctl
     handler just prints `OK scan active=...`. No unprovisioned-beacon parse, no discovered-device
     cache, no results verb — an operator can never learn a nearby device UUID via meshd.
128. **[P2] Remote Provisioning fully in libmesh (mesh_remote_prov.c, 36 KB) but entirely
     unsurfaced by meshd** — no `mesh_rp_*` reference anywhere under usr.sbin/bluetooth, no RPR
     model, no verb. A v1.1 baseline management capability (present in BlueZ) is unusable.
129. **[P3] Directed Forwarding fully in libmesh (mesh_df.c, 49 KB) but never registered/exposed**
     — no DF model registered, no DF Config Client verb. (Relates to the DF *correctness* findings
     21-25/76-84 which are all reachable only via mesh_sim, not the product.)
130. **[P3] LPN role integration layer is dead code with no honest disclosure** — `meshd_lpn_*`
     (meshd_node.c:3595-3636) never called; `features` verb hardcodes LowPower=false. Unlike
     Friend (disclosed unsupported at meshd.8:383), the LPN role ships a full dead FSM layer with
     no "unsupported" note.
131. **[P3] `device_uuid` config knob is dead; meshd never advertises an Unprovisioned Device
     Beacon** — parsed (meshd_config.c:116) but never read after; `mesh_unprov_beacon_build` is
     never called. An unprovisioned meshd node cannot be discovered/provisioned over PB-ADV.
132. **[P3] meshd.8 omits the entire `cfg` Config Client family, `key-refresh`, and `node-reset`**
     from its command reference though all are implemented — the daemon's whole manager-to-node
     control surface is undocumented in the daemon man page (appears only in meshctl.8).

### blued / bluedctl / libble

133. **[P1] Extended advertising-set CLI commands documented + fully implemented but have NO CLI
     dispatch** — `adv-set-create/params/data/enable/remove` are in bluedctl.8:228 and cmd_help[],
     backed by libble (ble.h:802) and the daemon (ctl.c:3689, IPC_ADV_SET_*), but bluedctl.c has
     zero `adv-set-*` dispatch and never calls any `ble_adv_set_*` → they fall through to "unknown
     or unsupported command". The entire operator-facing extended/multi-advertising-set surface is
     dead from the only CLI.
134. **[P1] `path-loss` command documented + fully wired but has NO CLI dispatch** — bluedctl.8:308,
     help, libble `ble_path_loss_reporting` (ble.c:4073), server ctl.c:2059; no `path-loss`
     dispatch in bluedctl.c.
135. **[P2] Filter Accept List has no operator management surface** — scan-with-accept-list is
     public (IPC_GAP_SCAN_F_ACCEPT_LIST) but the only population is the bond-driven auto-loader and
     the only removal is on unbond; no accept-list verb, no CLI. An operator cannot add a
     non-bonded peer, inspect, or clear it.
136. **[P2] GATT descriptors (non-CCCD) and included services cannot be authored by an operator**
     — `ble_add_include`/`ble_add_descriptor` (ble.h:630) + handlers (ctl.c:2828) exist, but no
     bluedctl subcommand and no config-file keyword (UCL parser handles only service/
     characteristic). Only a program linking libble can add them.
137. **[P2] Runtime-added local GATT services (`add-service`) are not persisted** — the live
     `periph_gatt_db` is only ever rebuilt from config/hardcoded services; `blued_persist_flush`
     never serializes the server DB (persisted `gattcache` is the client-side discovered DB).
     Runtime services vanish on restart.
138. **[P2] Runtime resolving-list IRK entries (non-bonded) are never persisted or reprogrammed**
     — `IPC_SECURITY_RESOLV_ADD` programs the controller and keeps only an addr shadow;
     `load_resolving_list` rebuilds solely from bonds with `has_irk`. A runtime entry for a
     non-bonded address is lost on restart.
139. **[P2] Extended advertising sets and periodic-advertising state are not persisted or resumed**
     — ext sets tracked in `ext_adv_sets[]` but persist writes exactly one record hardcoded to
     handle=0 (despite MAX_ADV_SETS==4); periodic-adv params are force-cleared on adapter init with
     no persist/resume — asymmetric with legacy advertising, which IS resumed.
140. **[P2] No settable default connection parameters or preferred ATT MTU across restart** —
     CONNECT falls back to hardcoded `6,12,4,500`; no config field / default-params verb / PPCP
     characteristic. Preferred MTU has no field in `blued_persist_settings` and reverts after
     restart.
141. **[P3] Advertising/scan-response payload persist fields are dead** — the record reserves
     `adv_data[31]`/`scan_rsp[31]` but flush fills only handle/enabled/props/interval and restore
     reads only props/intervals; the advertised payload is always persisted as zeros and never
     reapplied. (Distinct from finding 67.)
142. **[P3] bluedctl help/usage inconsistent with dispatch (both directions)** — `set-adv-params`
     is in help + libble-backed but has no dispatch and is absent from the man page (stranded
     feature); `adv-struct` has neither dispatch nor libble backing (phantom). Inversely,
     working commands `eatt-open`/`eatt-close` and profile shortcuts (battery/devinfo/heart-rate/
     thermometer/time/find) are missing from `cmd_help[]` so `bluedctl help <cmd>` says "no such
     command". (Distinct from finding 38.)
143. **[P3] Host-feature and controller-wide default-PHY controls are dead/unexposed** —
     `hci_le_set_host_feature()` has zero callers (CIS/subrating host-support bits can never be
     toggled); `hci_le_set_default_phy()` is only called with hardcoded "no preference" at init —
     no controller-wide default-PHY policy reaches operators.

*Verified NOT gaps: all ipc_proto.h opcodes have server handlers and ble.c has no stubs; local
model registration for Generic/Sensor/Scene/Scheduler/Time/Lighting/LC is complete; Config Client
sub-verbs listed in meshctl help are all wired; meshd_persist encode_body is thorough (keys, SEQ
high-water, IV+phase, netkeys w/ KR, appkeys, bindings/subs/pub, RPL, roster); register-agent/
io-cap/bondable/pairable fully wired; adapter name IS persisted; SIGHUP applies every
man-page-reloadable setting.*

---

## Completeness Round — summary (Bluetooth)

18 product-completeness gaps (126-143) on top of the 125 correctness findings. Theme: **libmesh
and libble implement substantially more than the daemons/CLIs expose** — Remote Provisioning,
Directed Forwarding, the Private/SAR/LCD Config Client subset, LPN role, and extended/periodic
advertising all have full library support that no operator surface reaches. Two P1s are documented,
fully-plumbed CLI commands (`adv-set-*`, `path-loss`) that simply have no dispatch arm. A recurring
persistence theme: runtime-added GATT services, resolving-list IRKs, ext/periodic adv state, adv
payloads, and preferred MTU/conn-params are not persisted across restart. These match the project's
own "spec-conformance ≠ product-complete" and "operator-API parity" concerns.

- **FIXED + test-green — mesh Friend and Low Power Node roles** (previously reported "unsupported"
  under finding 130): the libmesh Friend/LPN engines are now driven end-to-end over the meshd
  network bearer — friendship establishment (Request/Offer/Poll/Update), friend queue + PollTimeout,
  LPN poll cadence; `friend`/`low_power` config keys and `friend`/`low-power` verbs; the `features`
  reply and Config Friend Server report the real state. Two-node establish-and-deliver test added.
  Remaining (documented): unsegmented delivery only, managed-flooding credential (not strict
  friendship k2), and a true over-the-radio multi-daemon run.

### Committed
- `351aca0` — correctness + completeness fixes across the LE and mesh stack (Wave 1 + 2a).
- `90e475b` — concurrency hardening, DF/RPR bearer, remaining completeness (Wave 2b + 128/129 deep
  + 135-138/68).
- `f7e320b` — mesh Friend and Low Power Node roles.
All three are bluetooth-only; the user's unrelated in-tree work was left uncommitted.
