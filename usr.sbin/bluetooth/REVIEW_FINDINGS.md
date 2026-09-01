# Bluetooth stack — adversarial conformance & correctness review

Tracking document for the multi-agent review of `blued`, `meshd`, `bluedctl`,
`meshctl`, `libmesh`, and `libbluetooth`, run against the on-disk specs
(Core 6.3 extracts under `/tmp/core63-*`, `/tmp/MshPRT_v1.1.html`,
`/tmp/MMDL_v1.1.txt`, profile specs).

Each finding has a stable ID, a severity, the exact code location, the defect,
a concrete failure scenario, and the intended fix. Check the box when fixed.

**Severity key:** CRITICAL = key/encryption bypass or memory-safety; MAJOR =
security-relevant missing validation or interop break; MINOR = conformance /
hardening polish; INFO = design note.

**Review streams:**
1. blued SMP / pairing / keys — ✅ complete
2. blued ATT / GATT server — ✅ complete
3. blued HCI / GAP core — ✅ complete
4. libmesh crypto / net / transport / provisioning — ✅ complete
5. libmesh models / features — ✅ complete
6. Control plane (meshd, CLIs, sockets, persistence, libbluetooth) — ✅ complete

---

## Stream 1 — blued SMP / pairing / security

Crypto toolbox was **vector-executed against Core 6.3 Appendix D — 18/18 pass**.
Everything below is missing-validation / conformance, not a crypto error.

### MAJOR

- [x] **S-M1 — All-zero peer IRK accepted and used for RPA resolution (identity-resolution bypass)** ✅ FIXED (has_irk=false on zero IRK + guards in smp_rpa_matches/smp_find_bond)
  - Location: `blued/smp_keys.c:353-356` (sets `has_irk=true` unconditionally on Identity Information PDU); consumed `smp_keys.c:872-879`, `894-930`; programmed to controller resolving list `blued.c:1270-1276`.
  - Spec: Core Vol 4 Part E §7.8.38 — all-zero IRK means "device has no IRK" and must never resolve.
  - Scenario: peer bonds distributing IRK=0; any third party picks arbitrary `prand`, computes `hash = ah(0, prand)`, connects from `hash||prand`; `smp_find_bond` resolves it to that bond and on LE LTK Request returns that bond's LTK.
  - Fix: reject/skip all-zero IRK on receipt, in `smp_rpa_matches`, and before resolving-list programming.

- [x] **S-M2 — Identity-address bond hijack: distributed identity address not bound to resolving IRK nor checked against existing bonds** ✅ FIXED (RPA must resolve under distributed IRK + IRK-continuity refuses cross-bond overwrite). Residual: all-zero-IRK + claimed-address-matching-no-bond still bounded only by downgrade guard — full closure would need refusing identity-address≠connection-address, risking legit public-address distribution.
  - Location: `blued/smp_keys.c:357-361,370` (overwrites bond `addr/addr_type` with peer-claimed address); `smp_bond_db_store` `smp_keys.c:466-511` matches by `addr_type+addr` only, guarded solely by `smp_bond_is_downgrade` (SC/MITM/key-size), not IRK/identity continuity.
  - Scenario: attacker pairing at equal-or-greater security distributes a *victim's* identity address, overwriting the victim's stored bond → victim lockout (DoS) + attacker occupies identity/resolving-list slot.
  - Fix: verify the claimed identity resolves under the just-distributed IRK; refuse to overwrite a bond whose IRK differs.

### S-M3 — now FIXED (BlueZ/Linux convention implemented)

- [x] **S-M3 — ATT Signed Write CMAC convention diverged from BlueZ/Linux (signed-write interop break)** ✅ FIXED. Root-caused from BlueZ `bt_crypto_sign_att` + Linux `net/bluetooth/smp.c aes_cmac`: the correct convention reverses BOTH the CSRK and the *entire* `att-data||SignCounter_le32` message into MSB order for RFC-4493 CMAC, then reverses the 128-bit MAC back and takes its low 8 octets. The old code did neither the message-swap nor the output-reversal. **Note:** the agent's stubbed `SMP_SIGNWRITE_BLUEZ_BYTEORDER` flag was itself incomplete (swapped the message but NOT the output) — enabling it would have been a *different* wrong answer, which is exactly why "just flip it" was unsafe. Fixed in `smp_crypto.c smp_verify_signature` (build flag removed); test oracle `reference_signature` reimplemented independently to the same convention; test peer `btpeer.c` generator updated to match.
  - ⚠️ **Residual (honest):** the in-repo tests are self-consistent by construction (generator + verifier share the convention), so their passing proves internal consistency, NOT interop. Final confirmation still wants a smoke test against a real Android/Linux/BlueZ central issuing a signed write — but the code now matches the documented reference-stack algorithm rather than a local interpretation.
  - Location: `blued/smp_crypto.c:580-623` (`smp_verify_signature`).
  - Verified in code: swaps the CSRK but CMACs the message stream **unswapped**, compares MAC bytes [8..15]. BlueZ (`shared/crypto.c`) and Linux kernel byte-reverse the whole `msg||counter_le` buffer before CMAC and transmit MSB 8 octets LSB-first.
  - Caveat: **no official Signed Write test vector on disk**; in-tree test `smp_crypto_test.c:213` + PDU oracle were derived from this same interpretation, so the passing test is self-referential and cannot confirm interop.
  - Action before fixing: validate against a BlueZ-generated signature or SIG sample data. If confirmed, byte-reverse the message buffer before CMAC.
  - ⚠️ STATUS: behavior INTENTIONALLY unchanged. Block comment + `TODO(S-M3)` added; `#ifdef SMP_SIGNWRITE_BLUEZ_BYTEORDER` selects the byte-reversed variant, default OFF. **Needs a BlueZ capture to decide.**

### MINOR (conformance / hardening — none bypass encryption or leak keys)

- [x] **S-m4 — SC reconnect LTK reply doesn't enforce EDIV=0 / Rand=0** ✅ FIXED (blued_event.c: SC bonds require EDIV=0/Rand=0 else negative reply)
- [x] **S-m5 — Initiator trusts responder RespKeyDist without intersecting its own request** ✅ FIXED (preq[6]&pres[6] at all 3 initiator sites) — `blued/smp.c:1428`, `smp_sc.c:612,1111`. Uses `pres[6]` verbatim instead of `preq[6] & pres[6]`; hostile responder makes central store key material it never requested. Responder path correctly AND-masks (`smp.c:1704-1717`). Vol 3 Part H §3.6.1.
- [x] **S-m6 — Out-of-range Max Encryption Key Size rejected with wrong reason code** ✅ FIXED (0x06 ENCRYPTION_KEY_SIZE) — `blued/smp.c:1037-1043,1757-1764` returns `INVALID_PARAMETERS` (0x0a) instead of `ENCRYPTION_KEY_SIZE` (0x06). Fails closed; interop nicety.
- [x] **S-m7 — Inbound Keypress Notifications accepted without negotiation** ✅ FIXED fully (added `sc->kp_negotiated` = preq[3]&pres[3] both-sides KEYPRESS bit, set at both pairing sites, inbound gate now checks it) — `blued/smp.c:253-294`. `kp_notify` gates only outbound; inbound 0x0E fires `keypress_cb` even if unnegotiated. Bounded, no state effect. Vol 3 Part H §3.5.8.
- [x] **S-m8 — Reserved IO-cap / OOB-flag values not rejected on Just-Works path** ✅ FIXED (range-validate io/oob before model selection, both roles) — `blued/smp.c:1104-1109,1820-1825`. `smp_select_model` (rejects `io>4`) only called when MITM set. No memory-safety impact.
- [x] **S-m9 — `att_conn_apply_encryption` sets `authenticated` but never clears it** ✅ FIXED (`ac->authenticated = mitm;` unconditional) — `blued/att_server.c:739-741`. Non-idempotent on reused `att_conn`; fresh connections are zeroed, so impact limited.
- [x] **S-m10 — `smp_swap_buf` comment claims in-place support but corrupts on `dst==src`** ✅ FIXED (both-ends swap, truly in-place-safe) — `blued/smp_crypto.c:205-213`. Latent; all 40+ call sites use distinct buffers.
- [x] **S-m11 — Compile-gated key hexdump** ✅ FIXED (confirmed BLUED_DEBUG_KEYS undefined everywhere; added #error guard for release builds) — `blued/smp.c:1364-1367`, several `smp_sc.c` sites. Only under `#ifdef BLUED_DEBUG_KEYS && verbose>=3`. Ensure kept out of release builds.

### INFO
- **S-i1** — MITM/SC AuthReq bits are requests, not guarantees; an unauthenticated Just Works bond still forms unless operator raises `min_pairing_security`. Matches documented two-knob design; operators shouldn't assume `mitm=true` alone rejects Just Works.

### Verified CLEAN (stream 1)
Crypto toolbox (c1/s1/f4/f5/f6/g2/h6/h7/AES-CMAC/E/ah — 18/18 official vectors, CTKD D.9/D.10 both CT2 values); pairing state machine (out-of-order/injected/duplicate PDU rejection, method-selection Table 2.8 both roles, SC passkey commit ordering, numeric-comparison gating, 30s timeout, key zeroization); key sizes/KNOB (min(local,peer), <7 reject, SC<16 reject, floor 16, MS-octet masking); key distribution phase-3 ordering + mask enforcement + gated-after-encryption; CTKD gating (SC+MITM only, LinkKey bit, CT2→h7); privacy (RPA gen, marker checks, constant-time compare, fail-closed LTK neg-reply); encryption events (open only on real key material, fail-closed to key size 7); persistence (AES-256-GCM, fresh salt+IV per save, 0600 secret, O_EXCL/O_NOFOLLOW/uid-check/atomic rename, GCM-tag validated load); randomness (arc4random throughout, fresh nonce per SC passkey round).
- Note: the `resolv` artifact stores peer IRKs with CRC32/0600 only (no encryption); acceptable at owner-only perms but the file header's "non-secret" claim is slightly overstated.

---

## Stream 2 — blued ATT / GATT server

Five dimensions audited end-to-end; every load-bearing finding re-verified by an independent adversarial skeptic re-reading the full code path. **No memory-safety defects found** — exposure is in the access-control layer.

### HIGH

- [x] **A-F1 — Per-access authorization (and dynamic-value sourcing) bypassed on 4+ read paths and queued writes** ✅ FIXED (att_check_inline_read denies app-backed values on aggregate paths → client falls back to deferring plain Read; execute-write now fires owner notify)
  - Location: `blued/att_server_dispatch.c` — `handle_read_by_type:382`, `handle_read_multiple:1578`, `handle_read_multiple_variable:1653`, `handle_find_by_type_value:1483`, `handle_execute_write` commit `:1400`. Perm helpers `att_server.c:653-700` inspect only `a->perms`, never `a->flags`/`a->owner_fd`.
  - `ATT_ATTR_F_AUTHORIZE`/`ATT_ATTR_F_DYNAMIC` honored only in `handle_read`/`handle_read_blob`/`handle_write`. Flags are set on the characteristic **value** attribute (`ctl_gatt.c:1507-1511`) — directly selectable by Read By Type (UUID), Read Multiple (handle), and Prepare+Execute Write.
  - Scenario: app registers an AUTHORIZE value (no encryption perms) to vet each access out-of-line; attacker uses `ATT_READ_BY_TYPE_REQ`/`ATT_READ_MULTIPLE_REQ` → gets stored value with no app round-trip. Execute Write commits to an AUTHORIZE attribute with no approval and never fires `blued_ctl_notify_write`. DYNAMIC paths return stale `val_store`.
  - Spec: Core Vol 3 Part G §8.2; Part F §3.4.6. **CONFIRMED.**
- [x] **A-F2 — CCCD always plaintext-writable; notification/indication delivery never checks link security** ✅ FIXED (parent-security check on every CCCD write incl. config-driven; delivery gated in ctl_gatt_notify_result via new exported `att_check_security_perms`). ⚠️ CROSS-FILE RESIDUAL: other `att_send_notification/indication` callers in `blued_peripheral.c` (blued-core agent's file) need the same gate — handle in integration.
  - Location: `blued/att_server.c` `attdb_add_cccd:400-401` (hardcodes `perms=READ|WRITE`); write handler `att_server_dispatch.c:982-1047`; delivery `att_server_notify.c:38-155`, `ctl_gatt.c:1656-1708`.
  - CCCD perms hardcoded plaintext regardless of parent security; write handler checks only CCCD plaintext perms + parent NOTIFY/INDICATE property bits, never parent encryption/authentication perms; delivery gates only on `ctl_cccd_enabled`, never `ac->encrypted`/`ac->authenticated`.
  - Scenario: characteristic value is `ATT_PERM_READ_ENCRYPT` (direct read rejected); unbonded plaintext peer writes 0x0001 to the CCCD; app notifies → protected value pushed over plaintext link. Confidentiality bypass.
  - Spec: Core Vol 3 Part G §3.3.3.3 / §10.3.1.1. **CONFIRMED.**

### MEDIUM

- [x] **A-F3 — CCCD read returns stale 0x0000 on every path except plain Read Request** ✅ FIXED (att_read_value helper sources per-conn ac->cccds[] on all read paths) — `blued/att_server_dispatch.c`: only `handle_read:755-767` special-cases `GATT_UUID_CCCD` (per-conn `ac->cccds[]`); `handle_read_by_type:382`, `handle_read_blob:875`, `handle_read_multiple:1578`, `handle_read_multiple_variable:1653` copy shared `a->value` (init `{0,0}`, never updated on CCCD write). Client reading CCCD via Read By Type/Blob sees 0x0000 while notifications flow. Spec §3.3.3.3. **CONFIRMED.**
- [x] **A-F4 — GATT client treats reserved 0x00 Error Response code as success** ✅ FIXED (0x00 remapped to ATT_ERR_UNLIKELY_ERROR) — `blued/att.c:689-699`: `att_request` copies `ae.code=rsp[4]` validating only `n==5` + echoed opcode, no 0x01..0xFF check; wrappers return `errno==EPROTO ? ae.code : -1`, callers treat 0 as success (`ctl_gatt.c:199,225-230`). Hostile server sends `[0x01,<op>,h,h,0x00]` → daemon records empty read / false-"subscribed". Spec Vol 3 Part F §3.4.1.1 Table 3.4. **CONFIRMED, reachable.**

### LOW / conformance

- [x] **A-F5 — Find By Type Value returns Error Response for a protected attribute instead of silently skipping** ✅ FIXED (value-match first, perm-fail→continue; Read By Type left as error+break) — `blued/att_server_dispatch.c:1470-1480`. Perm-fail on first match returns `ATT_ERROR_RSP` with handle + security code (leaks handle + exact security level); later match `break`s (truncates discovery); perm check runs before value `memcmp:1483`. **PARTIAL** — code confirmed; silent-skip rule is standard §3.4.3.x but not quotable from on-disk extracts. Same error/break is spec-correct for Read By Type, so defensible-but-wrong here.
- [x] **A-F6 — Robustness/conformance cluster (LOW):** ✅ FIXED (all 7: HVN/HVI/Multi-HVN no Error Resp; client MTU→517; over-MTU reject + verbatim prepare echo; ctl_gatt 512 ceiling; 0x2900 hash recompute; HOGP all Protocol Mode chars; adv_builder overflow-safe)
  - Error Response emitted for received HVN(0x1B)/HVI(0x1D)/Multi-HVN(0x23) — command-flag guard checks only bit-6 opcodes, these have bit 6 clear — `att_server_dispatch.c:1947-1954`.
  - Client Exchange-MTU clamps to 65535 not 517 (`ATT_UNENHANCED_MAX_MTU`) — `att.c:759-763`. Not attacker-reachable.
  - Over-MTU request PDUs not rejected; Prepare Write echoes truncated value while queuing full value (§3.4.6.2) — `att_server_dispatch.c:1165-1179`. No memory unsafety.
  - `ctl_gatt` value-length ceiling is 517 not 512 max — `ctl_gatt.c:215,1400,1483,1610,1665,1747`. Local client only.
  - `set_value` on Char Extended Properties (0x2900) mutates hash-covered value without recomputing DB hash — `ctl_gatt.c:1393-1411`. Desyncs Robust Caching.
  - `hogp_enter_boot_protocol` writes Boot mode to only first Protocol Mode char — `hogp_boot.c:29-37`. Composite dual-HID leaves 2nd service in Report mode (HOGP v1.1 §4.11).
  - adv_builder integer-overflow in size guards (`n+2`/`n*16` on size_t) — **test-only, no production caller**; latent.

### Refuted / downgraded
- **Min-key-size fail-open when `enc_key_size==0`** (`att_server.c:664-666,690-692`) — **REFUTED as exploitable**: all four callers floor `link_key_size` to ≥7/16 (`blued_peripheral.c:601`, `blued_central.c:239,491`, `blued_event.c:855`), so it's never 0 while encrypted. Keep as latent-fragility note only.

### Verified CLEAN (stream 2)
PDU length/underflow safety (every opcode enforces exact/min length before field reads, all `len-N` guarded, no size_t underflow/over-read/attacker-driven alloc); Read Blob/Prepare/Execute offset arithmetic (Invalid Offset before Attr-Not-Long, overflow guarded + re-validated against `value_maxlen`); MTU exchange (offer 517, min() with 23 floor, once-only, refused on EATT, client EALREADY); Find Info/Read By Type/Group Type/Find By Type Value response construction (format-byte correctness, no mixing, uniform-length stop, MTU-budget truncation, handle-range validation, group-type restriction); Prepare/Execute queue (per-conn, bounded 16 count/4096 bytes → Queue Full, validate-all-before-apply atomicity, cleared on commit/cancel/disconnect); Error Response construction (Write Command + Signed Write suppress errors, Signed Write verifies CSRK + replay counter); **Database Hash/AES-CMAC** (`att_server_hash.c` — all-zero key, correct 10 hashed types w/ correct value-inclusion, LE order, **independently reproduced Core Appendix B KAT `F1CA2D48ECF58BAC8A8830BBB9FBA990`**, recompute on every structural change); indication flow control (single outstanding, EBUSY, 30 s teardown, MTU−3 truncation, Multi-HVN CSF-gated); cross-connection isolation (prep queue/CCCDs/deferred access/security state all in `struct att_conn`, reset at setup, per-bond CCCD persistence bounded); `gatt.c` client discovery parsing (entry-length allow-lists, `len%entry_len` framing, nonzero entry_len, monotonic/in-range/non-overlap handle validation).

---

## Integration follow-ups (cross-file, done during consolidation)

These arose because agents edited disjoint files but some fixes changed shared headers/APIs consumed by other agents' files:

- [x] **A-F2 peripheral path** — `blued_peripheral.c` `gatt_send_service_changed` now gates `att_send_indication` on `att_check_security_perms` (blued-core agent, via coordinator hand-off). A-F2 airtight on both delivery paths.
- [x] **P-M14 health-struct break** — `mesh_health_model.h` field split broke `meshd_node.c:2813` (`meshd_fault_snapshot`). Fixed to use `registered_faults`/`n_registered_faults` (Fault Status reports Registered). Caught by the build sweep.
- [x] **P-H7 Friend Clear wiring** — `meshd_friend_emit` now handles the new `MESH_FRIEND_ACT_SEND_CLEAR` (sends to `out->addr` = previous Friend, TTL 0x7F) + sets `mesh_fq_entry.segmented` on unreassembled segments (meshd agent).
- [x] **Test updates** — `mesh_manager_test.c seq_persist` (exact-eq → `>=` for SEQ reserve); `mesh_friend_test.c friend_enqueue_while_establishing` (rewritten to spec-correct establishing-Update-then-data flow).
- [x] **Test API reconciliation** — build sweep caught 10 test files using old signatures. Fixed across 7 files + `test_common.h` mocks (`hci_le_set_ext_adv_data` uint8→uint16 H-M6; `hci_get_con_handle` +addr_type H-L3; health field split P-M14; **plus a 4th change the agent found**: `ctl_scan_result` gained `duration_sec` from C-M1 — 9 call sites fixed). All 10 now compile clean.

## Build verification (in-session, `cc -fsyntax-only`)

Environment: session runs under Linuxulator/GNU userland; ATF/libatf not installed, so ATF test **binaries** can't be linked/run here — the authoritative `make` + `kyua test` gate is the native FreeBSD host. Source-level verification done in-session:
- **47 libmesh/blued/meshd `.c` files: 0 real compile errors** (4 additionally need generated headers `ipc_proto.h`/`vhid.h` — confirmed clean with those `-I` paths).
- **All modified + all 10 originally-broken test `.c` files: 0 real compile errors.**
- Cross-TU header/consumer mismatches from concurrent editing were caught by the sweep and fixed (health struct in meshd_node.c; 4 API changes in tests).
- **Remaining gate on host:** full `make` (with generated headers) + run the ATF suites (`mesh_*_test`, `att_test`, `smp_crypto_test`, `ctl_test`, `hci_*_test`, `meshd_*_test`) to exercise the fixes at runtime.

## Consolidated priority (all 6 streams complete)

**Fix-first batch (memory safety / remote crash / auth bypass):**
1. `C-C1` — meshd restart dangling pointers (deterministic corruption) — CRITICAL
2. `H-H1`, `H-H2` — remotely-triggerable UAF on link drop during pairing / APTO-vs-GATT-worker — HIGH
3. `H-H4` — HCI fd race (contradicts codebase's own finding-43 fix) — HIGH
4. `H-H3` — systemic uninitialized `rp` reads (~100 sites) — HIGH
5. `A-F1`, `A-F2` — GATT authorization bypass + CCCD/notify security bypass — HIGH
6. `S-M1`, `S-M2` — SMP all-zero IRK + identity-address bond hijack — MAJOR

**Second batch (conformance/interop correctness):**
- `M-F1` (mesh pubkey-equality), `P-H4`/`P-H5` (mesh bindings/DTT), `P-H6`+`P-C1a` (paired endianness fix), `H-M1`–`H-M7` (GAP conformance), `A-F3`/`A-F4` (GATT robustness), `S-m4`–`S-m6`.

**Feature-level decision (not a patch):**
- `P-C1` — Directed Forwarding is non-interoperable end-to-end. Recommend **gating/disabling DF** rather than patching in this pass; it needs a rebuild against the real §3.6.8 message tables.

**Deferred pending external validation:**
- `S-M3` — signed-write CMAC byte-order — needs a BlueZ capture before touching.

**Privacy batch:** `H-H5`, `H-H6`, `H-H7` (peer-RPA resolution + RPA rotation defeated by mesh scan).

**Leaks/hardening:** `C-m2` (EVP_PKEY leak), `C-m3`, `C-m4`, `P-H8` (manager SEQ nonce reuse), mesh `M-L1`–`M-L7`.

## Stream 3 — blued HCI / GAP core

Every high/medium finding independently re-verified (thread-of-execution + spec text) as CONFIRMED. Reference: Core 6.3 Vol 4 Part E.

### CRITICAL / HIGH

- [x] **H-H1 — Use-after-free: pairing worker vs. disconnect** ✅ FIXED (pairing worker brackets blued_conn_att_ops_begin/end → teardown+free(hogp) defers until worker exits; reconnect can't spawn on freed dev) — `blued/blued_central.c:263-288`, teardown `blued_event.c:1638-1648`. PAIR/REKEY worker is a detached pthread holding only a conn refcount (does not cover non-refcounted `conn->hogp`); never sets `att_ops_active`/`CONNECTING`, so none of `blued_conn_disconnect`'s deferral guards (`blued_event.c:1664-1695`) apply. Remote drops link during `smp_pair()` (≤30 s) → main thread `blued_conn_central_teardown` → `smp_close(&dev->smp)` + `free(dev)` while worker still derefs `dev->smp`/`dev->att`. UAF + concurrent SMP-fd close. `reconnect=true` can spawn a second thread on the freed `dev`. **Remotely triggerable.**
- [x] **H-H2 — Use-after-free: APTO cleanup sweep vs. GATT worker** ✅ FIXED (sweep sets disconnect_pending then checks att_ops_active, defers like EV_EOF; set-then-check avoids lost wakeup) — `blued/blued_event.c:937-944`, sweep `1064-1086`. Auth-Payload-Timeout sets `needs_cleanup` unconditionally; sweep branch frees **without** the `att_ops_active` check the normal EV_EOF path has (`blued_event.c:1691`). GATT worker mid-ATT reads `job->conn->att->mtu` (`ctl.c:2575`); APTO fires at 30 s → sweep frees `dev` under worker → UAF. Fix: add the symmetric `att_ops_active` guard.
- [x] **H-H3 — Uninitialized return-parameter read on short/empty Command Complete (systemic, ~100 sites)** ✅ FIXED (libbluetooth bt_devreq zero-fills rparam before recv; key callers add memset + rlen<sizeof reject). Note: some status-only hci_scan.c callers rely on the systemic zero-fill rather than per-call length checks — flagged, lower value) — `blued/hci_misc.c`, `hci_privacy.c`, `hci_scan.c`, `hci_adv.c`, `hci_util.c`. `bt_devreq` (`lib/libbluetooth/hci.c:283-288,324-332`) copies rparams only `if (r->rlen >= n)` and returns success even for an empty CC, never zero-filling `rparam`; no blued caller memsets `rp`. Verified reads of stack garbage: `hci_get_bdaddr` (`hci_util.c:246,262,267`), `hci_le_read_local_features` (`hci_misc.c:381,392,399` — garbage feature bits drive gating), `hci_reset` (`hci_misc.c:235,246`). Garbage `status==0` accepted as success. Fix: `memset(&rp,0,sizeof rp)` before each call + validate `r.rlen` after.
- [x] **H-H4 — `hci_wait_encryption` races the event loop on the shared HCI fd** ✅ FIXED (takes hci_devreq_mutex around filter swap + recv; event loop trylock backs off, no deadlock) — `blued/hci_misc.c:51-151` (esp. `:65,:83`). Runs on detached worker threads (`blued_central.c:320,479`, `blued_peripheral.c:406,562`) doing raw `bt_devrecv` on `adp->hci_fd` — the fd the main loop drains — **without** `hci_devreq_mutex`. The "finding 43" trylock (`blued_event.c:201`) only excludes lock-holding callers; this holds no lock, so both threads `recv()` and steal each other's Encryption Change / LTK Request / Disconnection Complete → pairing stalls, missed disconnects, encryption desync. **Contradicts the codebase's own finding-43 fix.**
- [x] **H-H5 — Peer-RPA resolution gated on *local* privacy config** ✅ FIXED (program peer IRKs + enable resolution whenever any IRK exists, independent of local privacy; local-RPA stays privacy-gated) — `blued/blued.c:1243-1249,1931`, `ctl.c:3450-3451`. Resolution enabled as `blued_cfg.privacy ? 1 : 0`; with privacy off (default) `load_resolving_list` clears the list and returns. But resolving a peer's RPA is orthogonal to hiding blued's own address. Auto-reconnect connects directly to stored identity address (`blued_central.c:353-356`) with no scan-then-resolve fallback → a bonded peripheral advertising with RPAs is unreachable after restart with privacy off; runtime IRKs wiped on restart.
- [x] **H-H6 — RPA rotation never stops scanning/initiating; RPA becomes fixed** ✅ FIXED (quiesce mesh scan + cancel create-connection before set_random_address, resume after) — `blued/blued.c:1728-1835`. `blued_adapter_rotate_rpa` disables only advertising before `hci_le_set_random_address`; §7.8.4 returns Command Disallowed (0x0C) if scanning/initiating enabled. Mesh bearer keeps passive scan on indefinitely (`ctl.c:963-1008`), so every rotation fails after ≤5 retries and the "resolvable private" address never rotates — fixed random address broadcast forever, defeating privacy.
- [x] **H-H7 — Resolving-list mutations issued without quiescing adv/scan; toggle return ignored** ✅ FIXED (blued_reslist_quiesce_begin/end around mutations; every return checked; genuine Add failure rolls back shadow + surfaced) — `blued/blued.c:1923-1931,1959-1961`, `ctl.c:3442-3511`. §7.8.38/§7.8.44 disallow these while adv/scan enabled or connection pending. `blued_reslist_sync_add` runs after central pairing while mesh scan / peripheral adv may be on; disable-resolution return ignored, Add fails 0x0C, shadow rolled back, peer IRK silently never reaches controller (LOG only) — reported as success.

### MEDIUM

- [x] **H-M1 — Stale connection handle survives reconnect backoff (handle-reuse aliasing)** ✅ FIXED (reconnect branch clears con_handle_valid + NULLs conn->att) — `blued/blued_event.c:1766-1809`. Reconnect branch never clears `con_handle_valid`/`con_handle` (cleared only when timer fires, `conn.c:112`). Enc Change / Key Refresh / APTO match on `con_handle_valid && con_handle==handle` with no epoch check → events land on dead conn, or wrong conn if controller reuses the handle first (first-match `LIST_FOREACH`). Fix: clear `con_handle_valid` + NULL `conn->att` in reconnect branch.
- [x] **H-M2 — LE Advertising Set Terminated event (0x12) unmasked but never handled** ✅ FIXED (0x12 handled, clears ext_adv_sets[].enabled/adv_enabled) — `blued/hci_misc.c:460`; no case in `blued_event.c`/`blued_le_meta.h`. Connectable ext set auto-terminates on connection → blued keeps `set->enabled==true`; RPA-rotation/privacy paths (`blued.c:1655-1658,1803,1815`) act on stale state, resurrecting a terminated set.
- [x] **H-M3 — IPC adv-set handle allocation collides with mesh bearer set 0x02** ✅ FIXED (IPC alloc skips MESH_ADV_HANDLE) — `blued/ctl.c:4229-4241`, `hci_util.h:331`, `hci_adv.c:826-847`. Alloc loop excludes only `ext_adv_sets[]`/`ctl_adv_sets[]`; `MESH_ADV_HANDLE 0x02` programmed directly and never registered, so `IPC_ADV_SET_CREATE` hands 0x02 to a client; next mesh burst force-disables/reparameterizes/re-enables handle 2 — cross-tenant clobber.
- [x] **H-M4 — Extended directed-high maps to a spec-illegal event-properties value** ✅ FIXED (host-side EINVAL for high-duty-directed without legacy bit) — `blued/hci_adv.c:572-591`. `HCI_ADV_CONN_DIR_HIGH` → 0x000D with legacy bit clear; §7.8.53 forbids high-duty directed (bit 3) with extended PDUs (bit 4=0). No host pre-validation → directed-high in AUTO/EXTENDED always fails Invalid HCI Command Parameters.
- [x] **H-M5 — RESOLV_ADD stores an RPA as Peer_Identity_Address** ✅ FIXED (programs resolved bond->addr/addr_type) — `blued/ctl.c:3455-3477`. IRK-resolves the supplied RPA via `smp_find_bond` (proving it's not the identity) but programs `hci_le_add_dev_resolving_list` with the supplied RPA instead of `bond->addr`/`addr_type`; §7.8.38 field is Peer_Identity_Address → entry garbage after next rotation.
- [x] **H-M6 — No extended advertising data fragmentation** ✅ FIXED (uint16 length, fragments >251 via Op 0x01/0x00/0x02; IPC single-frame ≤255 documented limit) — `blued/hci_adv.c:678-720`, `ctl.c:4288-4305`, `blued.c:2279-2291`. Encoder hardcodes Operation 0x03, `uint8_t` length ≤251; IPC framing single-frame. Max_Advertising_Data_Length (≤1650) read but only logged. BlueZ/NimBLE parity gap (both fragment via Op 0x00/0x01/0x02).
- [x] **H-M7 — GATT jobs admitted against a still-CONNECTING central conn** ✅ FIXED (ctl_gatt_resolve_conn also requires BLUED_CONN_ACTIVE) — `blued/ctl.c:2435-2467`. `ctl_gatt_resolve_conn` gates only on `conn->att != NULL`, which the setup thread publishes (`blued_central.c:648-649`) before ACTIVE (line 721) while still doing blocking setup → GATT READ/WRITE races the setup thread on one ATT socket. Other paths (`ctl_gatt.c:1053`) check ACTIVE; this should too.

### LOW / INFO — ✅ all fixed except H-L5 (see below)

- [x] **H-L1** — Anonymous ext adverts (addr_type 0xFF) consume dedup slots then dropped/mislabeled "public 00:00…" — `blued/hci_scan.c:1318-1327`.
- [x] **H-L2** — NO_DEDUP now honored in legacy+ext loops; scan_result_merge de-duplicates UUIDs. ✅
- [x] **H-L3** — `hci_get_con_handle` gained addr_type param, matches LE link_type with safe fallback; 3 callers+header updated. ✅
- [x] **H-L4** — peripheral inbound-pairing now calls reslist sync_remove+_add for peer IRK. ✅
- [~] **H-L5** — ✅ interval truncation FIXED (persist v2: interval_min/max widened uint16→uint32/24-bit, casts removed, apply-path locals widened). ⚠️ Multi-record ext-set restore (re-creating persisted extended sets 1..n at adapter init with their own props/interval/data) documented as a scoped deferral in `blued.c` — feature-sized init plumbing, not a rush-fix. Primary set + real props now restored.
- [x] **H-L6** — `setup_worker_counted` bool → underflow-guarded `setup_worker_count` counter. ✅
- [x] **H-L7** — `blued_le_handle_valid()` added to CIS Established/Request + per-BIS BIG handles. ✅
- [x] **H-L8** — CONNECTING disconnect routes through blued_conn_disconnect (latches disconnect_pending), no BUSY. ✅

### Verified CLEAN (stream 3)
HCI event parsing/memory safety (main dispatch validates `n==buf[2]+3`; legacy arms require exact `n==`; LE Meta validates `len==3+pkt[2]` then per-subevent exact-equality bounds; adv-report loops + AD walker bounded; periodic_syncs bitmap in-bounds; ISO/BIG consumers use list searches — no OOB/underflow/unvalidated cast); Num_HCI_Command_Packets flow control (delegated to kernel ng_hci, correct opcode match + Status/Complete selection); ISO/CIG/BIG parameter validation (range-checks throughout, 294-byte CIG buffer, clamped handle counts, re-validate num_bis before copy, sound refcount/linked lifetime); refcount pairing/double-disconnect/sweep (balanced ref/unref incl. pthread_create failure, stale-event guards, `LIST_FOREACH_SAFE`); dedup keying by (address, address_type) everywhere; legacy 31-byte caps; ext-vs-legacy transport pinning; primary-set enable/disable rollback; hci_privacy ranges.

## Stream 4 — libmesh crypto / net / transport / provisioning

Crypto layer **compiled and vector-executed against MshPRT §8 sample data — every
vector passed byte-exact** (s1, k1–k5, nonces, Network PDU encrypt+obfuscate,
device/virtual-address AAD, Secure Network + Mesh Private beacons), with
tampered-MIC / wrong-AAD / tampered-beacon / empty-ciphertext forgery all rejected.

### MEDIUM

- [x] **M-F1 — Missing public-key-equality check in provisioning** ✅ FIXED (reflection memcmp in shared `sess_derive_confirmation`, covers both roles)
  - Location: `libmesh/mesh_provisioner.c:305-311` (provisioner) & `:433-439` (device) → `mesh_provision.c:676-708`.
  - Spec: MshPRT §5.4.3.1 — provisioning must *fail* when a public key equal to the own public key is received. Peer key is validated on-curve / not-infinity but never compared to the node's own public key, so reflection of the initiator's own key is not rejected.
  - Impact: bounded (engine is No-OOB-only) but a clear conformance gap.
  - Fix: `memcmp(peer_pub, our_pub, 64)==0 → sess_fail(Invalid Format)` in both handlers.

### LOW — crypto API hardening (not reachable from in-tree callers)

- [x] **M-L1 — `size_t→(int)` truncation of `plen`/`aadlen`/`clen` in exported CCM API** ✅ FIXED (>INT_MAX guards) — `libmesh/mesh_crypto.c:436-441,497-506`. A future caller >INT_MAX passes a negative length to OpenSSL. Add magnitude guards.
- [x] **M-L2 — bad-`miclen` early `return(-1)` skips promised output zeroization** ✅ FIXED — `libmesh/mesh_crypto.c:411-412,476-477` vs header contract `mesh_crypto.h:17-19`. Zero `plain`/`cipher` first.
- [x] **M-L3 — `mesh_k2` accepts `plen==0`** ✅ FIXED — `libmesh/mesh_crypto.c:280`. MshPRT §3.9.2.8 requires P ≥ 1 octet; empty-P silently derives non-interoperable keys. Reject `plen==0`.
- [x] **M-L4 — `mesh_aes_cmac` (hence `mesh_s1`/`mesh_k1`) passes `NULL`+nonzero-len into OpenSSL (UB)** ✅ FIXED (mirrored hmac guard) — `libmesh/mesh_crypto.c:105`. `mesh_hmac_sha256:144-147` already guards; mirror it.
- [x] **M-L5 — `warnx()` on OpenSSL failures writes to linking process stderr** ✅ FIXED (MESH_CRYPTO_DEBUG-gated macro) — `libmesh/mesh_crypto.c`. No secrets (MIC-mismatch path stays silent — no oracle). Consider a quiet/debug hook.

### LOW — network / replay API surface & message cache

- [x] **M-L6 — `mesh_rpl_net_receive` takes a single `iv_index`, no IV−1 retry** ✅ FIXED (added `mesh_rpl_net_receive_ivupd` two-candidate wrapper) — `libmesh/mesh_rpl.c:104-118`. A consumer using it directly (not the sim's two-candidate loop at `mesh_sim.c:1138-1146`) drops traffic still on IV−1 during the ≥96h transition. Availability/interop only. Add a doc note or two-candidate wrapper.
- [~] **M-L7 — deprecated `mesh_net_rpl_check` ignores IV Index** ⚠️ ANNOTATED not removed (live caller in `tests/.../mesh_net_test.c`, not owned); marked deprecated, directs to IV-aware path — `libmesh/mesh_net.c:423-452`. DoS direction only (old-IV replays can't decrypt under new IV); real `mesh_rpl.c` is IV-aware. Residual risk = primitive stays exported. Consider removing/annotating.
- [x] **M-N1 — sim message cache keyed on (SRC,SEQ) without IV Index** ✅ FIXED (added iv_index to nmc key) — `libmesh/mesh_sim.c` `nmc_seen_record`. Can suppress at most one relay/proxy-forward across an IV change; **no replay admitted** (IV-aware RPL governs delivery). Dedup-only, informational.

### INFO
- **M-i1** — No-OOB-only provisioning: provisioner hard-codes `auth_method=0` / zero AuthValue (`mesh_provisioner.c:283-291`); no active-MITM protection, though it correctly rejects devices mandating OOB. By design.

### Verified CLEAN (stream 4)
All crypto primitives byte-exact vs §8 vectors (s1/s2/k1–k5, all four nonces, AES-CCM ordering + constant-time tag compare + output-zero-on-failure, PECB obfuscation, Label-UUID AAD, Secure Network + Mesh Private beacons); key hygiene (`explicit_bzero`, EVP freed on all paths, no secret-dependent branches); network layer (NID+IVI match, CTL-dependent NetMIC/transport bounds, SRC-unicast/DST≠0 post-decrypt, relay TTL≥2+decrement+gates); RPL (per-SRC (IV,SEQ) strict-newer, fail-closed when full, authenticate-before-record, never reset on IV update); IV state machine (96h dwell, never-lower, 42-index lookahead, >+1 requires recovery, TX uses IV−1 during update, no nonce reuse); key refresh (phase table, advance-only, revoke at Phase 3); transport/SAR (SeqAuth reconstruction, per-transaction RPL, SegO/SegN bounds ≤384 no overflow, ack-to-local-unicast, 10s discard, bounded reassembly); provisioning crypto (off-curve/infinity reject, ConfirmationInputs order, salts, MIC-8-before-unpack, confirm-before-random); PB-ADV/PB-GATT SAR (FCS, bounds, Link-ID filtering, retransmit-ack suppression).

## Stream 5 — libmesh models / features

Reference: MshPRT / MMDL v1.1. Access-layer codec confirmed directly (dedicated sub-reviewer did not return, but `mesh_access.c` was read and verified independently — no coverage gap).

### CRITICAL — Directed Forwarding is non-interoperable (`libmesh/mesh_df.c`)

Wire formats/forwarding model built from a paraphrase, not the message tables. Round-trip self-tests pass; interop with any conformant node fails.

**✅ WIRE FORMATS FIXED (P-C1a–d), ⚠️ Forwarding Table message set (0x8081–0x808F) remains UNIMPLEMENTED — documented, not fabricated.** Two spec-driven corrections to the original fix text, both accepted as correct: (1) Echo Request/Reply re-originate at **TTL 0x7F unicast** (Tables 3.53/3.54), not TTL-0-group as I'd written; (2) forwarded PATH_REPLY lacks the stored `Next_Toward_Path_Origin` unicast so it re-originates to the DF group at TTL 0 routed via the reverse bearer (documented limitation). **Remaining feature gap: the remotely-managed paged Forwarding Table + DF/Proxy capabilities messages — a larger build, flagged in `mesh_df.h`.**

- [x] **P-C1a — Unicast Address Range: LengthPresent in wrong bit** ✅ FIXED (MSB bit15, RangeStart low-15 unshifted, BE) — `mesh_df.c:90-95` (build), `:112-115` (parse) emit `be16(range_start<<1 | LP)`. DF control PDUs are big-endian transport-control; MshPRT §3.4.2.2.1 Table 3.6 (worked example primary 0x1234 + 5 → `0x92 0x34 0x06`) puts LengthPresent in the **MSB** and RangeStart in low 15 bits **unshifted**. Mis-frames every PATH_REQUEST/PATH_REPLY/DEPENDENT_NODE_UPDATE range.
- [x] **P-C1b — PATH_REPLY layout wrong three ways** ✅ FIXED (Unicast_Destination/OBO/Confirmation at 7/6/5, Path_Origin before FN, conditional ranges per C.1/C.2) — `mesh_df.c:232-236`/`263-266`: omits `Unicast_Destination` flag; puts OBO/Confirmation at bits 7/6 (Table 3.52 = Unicast_Destination/OBO/Confirmation at 7/6/5); emits Forwarding_Number before Path_Origin (spec: Path_Origin then FN); always emits target range though C.1 makes it conditional on Unicast_Destination. Establishment never completes.
- [x] **P-C1c — DF control messages TTL-relayed instead of re-originated at TTL 0** ✅ FIXED (re-originate; PATH_REQ/PATH_REPLY/CONFIRMATION/DEP_UPDATE → TTL 0 to 0xFFFB; Echo → TTL 0x7F unicast per spec) — `mesh_df.c:961,1044,1077,1121,1188,1253` gate on `mesh_net_relay(ttl,…)` (needs TTL≥2, decrements). §3.6.8.2.x requires each hop to *re-originate* with `DST=all-directed-forwarding-nodes`, `TTL=0`; originated PATH_REPLY even uses `MESH_DF_DEFAULT_TTL` (0x7F). Conformant peer's TTL-0 PATH_REQUEST consumed without propagation → multi-hop discovery never completes.
- [x] **P-C1d — Supporting DF defects (HIGH/MED, all verified)** ✅ FIXED (8-bit metric saturating, DEP_UPDATE Type→bit7, better-metric lane forms, correct SRC/DST, virtual/group dests allowed, 0xFF DoNotProcess preserved) — metric treated as 7-bit not 8-bit (`:164,198`); DEPENDENT_NODE_UPDATE Type bit at bit 0 not 7 (`:370,390`); same-FN-better-metric PATH_REQUEST discarded so lanes never form (`:917-921`, contra §3.6.8.2.2 "not less than"); forwarded PATH_CONFIRMATION/DEPENDENT_UPDATE/PATH_REPLY use wrong network SRC/DST (`:1046,1079,1255`); virtual/group destinations rejected (`:155-157,336,414,685`); no Path Request/Reply delay timers; directed-vs-flooding credential selection not modeled (`mesh_df.h:492`); **entire Forwarding Table / capability config message set absent** (codecs jump 0x8080→0x8090); DIRECTED_CONTROL_SET "Do Not Process" 0xFF crushed by 1-bit mask (`:1428-1432`).

### HIGH — model behavior / state-binding defects

- [x] **P-H4 — Generic→lighting upward state bindings entirely missing** ✅ FIXED (bound_sink hook: OnOff→Lightness, Level→Lightness/CTL-Temp/HSL, in_bind guard prevents reverse re-trigger; corrected to Default-first per 6.1.2.2.3) — `libmesh/mesh_lighting.c`, `mesh_generic.c`. Only downward bindings exist (Lightness→OnOff/Level `mesh_lighting.c:111-119`, Temp→Level `:612-619`, Hue/Sat→Level `:1117-1127`); nothing maps Generic OnOff/Level Set *up* into Lightness/CTL/HSL (MMDL 6.1.2.2.2/.3). A Generic OnOff Set 0x01 to a light element does not turn the light on — the canonical path is dead.
- [x] **P-H5 — Transition Time steps 0x3F rejected instead of DTT fallback** ✅ FIXED at decoder level (gen_effective_transition maps 0x3F→DTT; decoders no longer drop). Deliberately did NOT relax `mesh_transition_time_valid` — 0x3F is Prohibited for the DTT *state* (MMDL 3.1.3.2), relaxing would add 2 bugs. Correct call. — `libmesh/mesh_access.c:418-421` (`mesh_transition_time_valid` fails 0x3F) + every Generic Set decoder (`mesh_generic.c:113-115,206,249,292,928`) drops the message. MMDL 3.2.9.3: steps==0x3F → use Default Transition Time (instantaneous if unsupported). Acknowledged Set silently ignored, no Status. `mesh_lighting.c:74-82` gets this right — files disagree.
- [x] **P-H6 — Config Heartbeat Subscription address-range mirror-bug** ✅ FIXED (access-layer `(RangeStart<<1)|LP` LE, build+parse) — `libmesh/mesh_cfg_v11.c:250-282` packs RangeStart low-15/LP bit-15 little-endian. These are access-layer (little-endian) messages, so LengthPresent must be **bit 0**, RangeStart bits 1-15: `(start<<1)|LP`. `mesh_cfg_v11.c` and `mesh_df.c` each implemented the *other* layer's convention — both wrong, **opposite fixes**. Affects SOLICITATION_PDU_RPL_ITEMS_CLEAR/STATUS.
- [x] **P-H7 — Friendship procedure gaps** ✅ FIXED (establishing Poll→Friend Update; initiator Friend Clear procedure w/ repeat+deadline timers; termination flushes queue; segmented-enqueue gate). ⚠️ needs meshd to handle new `MESH_FRIEND_ACT_SEND_CLEAR` (integration item #2 below) + set `mesh_fq_entry.segmented` — `libmesh/mesh_friend.c`, `mesh_lpn.c` (codecs/queue/credentials CLEAN; procedure-level deviates, confidence medium): establishing Poll answered with queued **data** PDU not the mandatory **Friend Update** (`mesh_friend.c:1094`, enqueue-during-establishment `:1189-1198`) — own LPN establishes only on Friend Update (`mesh_lpn.c:261`) → deadlock + message loss; initiator-side **Friend Clear procedure entirely missing** (`prev_addr` parsed never acted on, `recv_clear` rejects Clear Confirms `:1155`, LPN never populates PreviousAddress) → migrated-away friendships never torn down; no §3.5.5 security-update/segmented gating into Friend Queue; termination doesn't discard queue entries.
- [x] **P-H8 — Manager: persisted SEQ allows nonce reuse after crash** ✅ FIXED (persist seq+RESERVE(100), resume ahead; persist format v2→v3). ⚠️ test `seq_persist` asserts exact-equality, needs `>=` (integration item #1) — `libmesh/mesh_manager.c:434-441`/`679-681` persist/reload `seq` with no reserved margin; any `devkey_seal` (`:818-842`) after last save replays same (IV,SEQ,SRC) after reload (contra §3.4.4.5) → AES-CCM nonce reuse. Confidence high. Fix: reserve-block on persist.

### MEDIUM

- [x] **P-M9 — Scene Current Scene not zeroed during transition** ✅ FIXED (current_scene=0 during timed Recall, restored on completion) — `libmesh/mesh_time_scene.c:474-478` leaves `current_scene` intact; `scene_status_reply:392-393` reports it. MMDL 5.1.3.2.1: during transition Current Scene shall be 0x0000.
- [x] **P-M10 — Heartbeat Subscription CountLog/PeriodLog wrong rounding** ✅ FIXED (floor helpers for subscription; publication keeps ceil) — `libmesh/mesh_heartbeat.c:48-63`,`475-487` apply Publication's *ceil* rule; Subscription uses Table 4.1 *floor* rule (§4.1.2). Used `:581-582` → subscription Status over-reports by one for non-power-of-2.
- [x] **P-M11 — Heartbeat Subscription Status reports MinHops=0x7F when disabled** ✅ FIXED (Min=Max=0x00 when unassigned) — `libmesh/mesh_heartbeat.c:502` sets `min_hops=0x7F`, forwarded `:583`. §4.4.1.2.16: when Source/Dest unassigned, Min/MaxHops shall be 0x00.
- [x] **P-M12 — Lightness/Power "Last" corrupted by per-tick sampling** ✅ FIXED (latch Last only when actual≠0 && !transition.active) — `libmesh/mesh_lighting.c:165-167`, `mesh_generic.c:816-817` latch `last=actual` every sample; MMDL 6.1.2.3: Last stores last non-zero from a *completed* change. Fade-to-off leaves `last`≈1 → later On restores near-zero.
- [x] **P-M13 — Prohibited values answered instead of ignored** ✅ FIXED (Power Range 0x0000, Health FastPeriodDivisor 16-255, Sensor property 0x0000 all ignored) — Generic Power Range Set min/max 0x0000 replies + persists (`mesh_generic.c:970-975`); Health Period Set accepts FastPeriodDivisor 16-255 (`mesh_health_model.c:258-264`); Sensor Column/Series Get accepts property 0x0000/malformed len (`mesh_sensor.c:342-354`). MMDL 1.3.3: Prohibited shall be ignored, not responded to. (Lightness Range Set does it right — inconsistent.)
- [x] **P-M14 — Health Server conflates Current Fault and Registered Fault** ✅ FIXED (split current_faults[]/registered_faults[]; Fault Clear touches only registered) — single `faults[]` (`libmesh/mesh_health_model.h:115`); `clear_faults` wipes both. §4.2.16.2: Registered Fault persists across Current-fault clearing; Fault Clear touches only registered array.
- [x] **P-M15 — Manager AppKey Update cannot carry a new key** ✅ FIXED (staged appkey_new distributed on Update, persisted v3) — `libmesh/mesh_manager.c:1031-1044` re-sends current `appkey`; KR Phase-1 AppKey Update must distribute a *new* key (conformant nodes reject same-key with Cannot Update). NetKey Update path correct (`:939-951`).
- [x] **P-M16 — Proxy 1.1 gaps** ✅ FIXED (Private Network/Node Identity adv 0x02/0x03; Directed Proxy Capabilities Status + Control parse; 20s SAR reassembly timeout; filter Add ignores 0x0000) — Private Network/Node Identity advertising types absent (`libmesh/mesh_proxy.c:777-839`) though manager can enable those states; Directed Proxy config rejected (`:506`); no 20 s SAR reassembly timeout (`mesh_proxy.h:209`); unassigned address not ignored on filter Add (`:344-360`).

### LOW (selected)
- [x] **P-L (models subset)** ✅ FIXED — Time Status TAI=0 omission rule; Scene capture-failure status; lighting setters clamp not reject; Light LC documented codec-only. ⏳ LPN items (TransactionNumber 0x00, duplicate-response PDU identity, >1.1s Friend Request spacing) belong to mesh-friend/mgr agent (still running).

### Verified CLEAN (stream 5)
Access-layer opcode codec (1/2/3-byte, 0x7F RFU rejected, vendor CID LE, bounds, `vtad` virtual hash); config model codecs (12-bit key-index pack, model-ID lengths, composition page 0, all msg lengths/status, subscription group-only validation, publication virtual split, SAR/private-beacon/LCD/aggregator — except the address-range item; **note netkey/appkey state rules live in `meshd_node.c`, out of this file set**); generic/lighting math (Delta TID transaction, Move rails, DTT 2-bit encoding, Linear=Ceil(Actual²/65535)/Actual=√ binding, range clamp preserving zero, HSL hue-wrap); sensor/time/scene (MPID Format A/B incl 0x7F, descriptor packing, cadence, Time 40-bit TAI + biases, Scheduler 80-bit, scene status codes + 0x0000 reject); friendship codecs (nine opcodes, Criteria layout, ranges, Offer Delay formula, k2 credential input, FSN handshake, queue enqueue filter, LPNCounter); proxy/relay (Proxy PDU SAR + types, filter default accept, secured proxy-config PDU, Network-ID + Node-Identity adv; **Relay fully clean** — gates, retransmit count+1, interval=(steps+1)×10 ms); manager core (unicast allocator, roster, DevKey seal/open, txn correlation — except SEQ margin P-H8).

## Stream 6 — Control plane (meshd, CLIs, sockets, persistence, libbluetooth)

### CRITICAL

- [x] **C-C1 — `meshd_persist_load` struct-copy dangles self-referential pointers (use-after-scope on every restart-with-state)** ✅ FIXED (node_rehome_sim rebases rpl.entries + elems[].models/subs/labels + friend_rpl[].entries; meshd_sync_subscriptions now called after copy)
  - Location: `meshd/meshd_persist.c:1324` decodes into stack local `struct meshd_node tmp`, then `*nd = tmp;` (`:1431`) memberwise-copies into the live node; `node_rehome_sim(nd, self_index)` (`meshd/meshd_node.c:256-270`, called `:1432`) rebases only `sim.nodes[i].sim`, `self`, and `self->devkey_{rx,client}_arg`.
  - `struct mesh_node` embeds its own backing arrays; setup (run against `tmp` in `decode_body`) plants pointers *into `tmp`*, left pointing at the dead stack frame. Not repaired by `node_rehome_sim`:
    - `self->elems[ei].models` (set once `mesh_sim.c:302`, read every delivery `mesh_sim.c:1331`)
    - `self->rpl.entries` → `rpl_store` (RPL check **writes** through it every received PDU)
    - `self->elems[ei].subs` / `.labels` → `elem_subs`/`elem_labels`
    - sim model config views into `nd->db`: `meshd_sync_subscriptions()` (`meshd_node.c:1492-1498`) not re-run after copy
    - `friend_rpl[i].entries` → `friend_rpl_store[i]` (`meshd_node.c:397-399`, read/written `meshd_node.c:4868`)
  - Scenario: any daemon restart with a state file (normal case, `meshd.c:609` case 0) runs its entire RX path (model dispatch, subscription resolution, RPL updates) through pointers into a freed stack frame → mis-dispatch + RPL/friend-RPL writes scribble on whatever now occupies that stack. Passes light validation; deterministic corruption in sustained operation.
  - Fix: extend `node_rehome_sim` to rebase `elems[].models/subs/labels`, `rpl.entries`, `friend_rpl[].entries` to `nd`, and re-run `meshd_sync_subscriptions(nd)` after the copy. (`nd->app` and `mesh_model.user/.ops` are safe — heap `meshd_app_models` carried by pointer.)

### MAJOR

- [x] **C-M1 — Unprivileged, unrate-limited synchronous `SCAN` freezes the whole blued event loop (~5 s/call)** ✅ FIXED via sanctioned fallback (wired the dead rate-limiter onto SCAN + capped sync duration 3s/1–5s). Full worker-pool migration deliberately deferred (needs thread-safe result streaming off GATT pool)
  - Location: `blued/ctl.c:2017-2021` exempts `IPC_GAP_SCAN` (+ `GET_CONNECTIONS`) from the privilege gate; control socket is `chmod 0660` (`ctl.c:5360`) so any owner **or group** member can call it. SCAN runs synchronously on the main kqueue thread: `blued_event.c:1165` → `ctl_conn.c:109-116` → `hci_scan.c:641-654` busy-receives until the 5 s deadline.
  - The intended guard is **dead code**: `CTL_BLOCKING_LIMIT`/`CTL_BLOCKING_WINDOW` (`ctl.c:628-629`) and `blocking_count`/`blocking_window` (`blued.h:326-327`) are referenced in no `.c` file (grep-confirmed). DISCOVER/READ/WRITE/HOGP were moved to the GATT worker pool; SCAN was left synchronous.
  - Scenario: a group member looping `SCAN` stalls the daemon in ~5 s bursts indefinitely (no other client, HCI event, connection I/O, or timer serviced).
  - Fix: dispatch SCAN to the worker pool, or wire up the existing limiter.

### MINOR

- [x] **C-m1 — blued listener can busy-spin under fd exhaustion** ✅ FIXED (EMFILE/ENFILE disables listener + one-shot retry timer) — `blued/ctl.c:5483-5486`. One `accept4()`, level-triggered listener (`ctl.c:5375`); on `EMFILE`/`ENFILE` the readable event persists → 100% CPU until an fd frees. Bounded (clients capped at `BLUED_MAX_CTL`). Fix: on `EMFILE`/`ENFILE` briefly `EV_DISABLE` the listener.
- [x] **C-m2 — EVP_PKEY leak per successful PB-ADV OTA provisioning** ✅ FIXED (free session on PB-ADV success path) — `meshd/meshd_node.c:5274-5292`. `meshd_provision_ota_commit` frees the session only on the PB-GATT path; PB-ADV never calls `mesh_prov_session_free(&nd->prov_sess)`, and the next init `memset`s it (wiping `kp.pkey` without freeing). One heap EVP_PKEY leaks per device provisioned over PB-ADV. Abort path (`:5307`) is correct.
- [x] **C-m3 — `meshd_drain_tx` retains outbound PDUs on a down/NULL bearer, contrary to contract** ✅ FIXED (drop-on-down, removed ring re-compaction) — `meshd/meshd_node.c:561-571` vs contract `meshd.h:150-152` (NULL bearer/`tx()` should **drop**). Re-compacts every valid entry back into the 256-slot sim TX ring, including when `tx()` returns -1 (blued reconnect window). Ring fills → originations fail until reconnect, then 256 stale PDUs (old SEQs) burst onto air. Fix: drop when bearer absent/down, or bound retention.
- [x] **C-m4 — Unbounded aggregator recursion** ✅ FIXED (aggregator item may not be an aggregator); K1 CLI confirmed already-safe, no change — `meshd/meshd_node.c:3223-3259,4002-4011`. `h_aggregator_seq` ↔ `meshd_foundation_recv` mutually recursive, no nesting limit; ~3.6 KB stack/frame, ~75 levels ≈ 280 KB. DevKey-authenticated (not a default-stack crash). Fix: reject "aggregator item may not be an aggregator".

### Verified CLEAN (stream 6)
blued control-socket framing/privilege (`plen>IPC_MAX_PAYLOAD` rejected, exact rxbuf sizing, per-verb re-validation, non-blocking writes + 64 KB txq cap, fd-passing ownership, `getpeereid` privilege tiers, GATT worker fd+generation tokens, stale-socket refusal); meshd control surface (getpeereid root-or-owner, `chmod 0600`, length-checked buffers, truncation-checked snprintf); persistence framing (atomic temp+fsync+rename+dir-fsync, `mkostempsat`, `fchmod 0600`/`0700`, `O_NOFOLLOW`+fstat uid/mode checks, CRC32, size/count cross-checks, clamps — only defect is C-C1 post-decode copy); meshd lifecycle (flag-only signal handler, flock+dir-check+live-probe before unlink, kqueue generation tagging, no teardown UAF); meshd↔blued bearer (length-validated framing, backoff reconnect, `ENOBUFS` backpressure, write-slot generation guards); config parse (over-long-line reject, `strtoul` checked, unknown-key reject, key-file perm refusal); node/cfgclient/models (codec bounds, reply-size guards, swap-then-break table mutation, underflow-guarded offset math, Config Client by-value txn + address re-resolve); CLIs (`join_args` snprintf guard, range-checked parsers, partial-write loops); libbluetooth (`bt_aton` bounded, `bt_devrecv`/`bt_devreq` length validation, `bt_devinquiry` signed-arithmetic count bound, fd close on all error paths).
