# Bluetooth interoperability comparison: 5BSD against BlueZ, Zephyr and NimBLE

An external-reference sweep of the 5BSD Bluetooth stack. Earlier review rounds
compared this code against itself and converged; a narrow comparison against
BlueZ then found three real divergences in an afternoon. This is the broad
version of that comparison, across five areas, against three independent
implementations plus the Linux kernel.

Nothing in this document was changed in the code when it was written; it is
reconnaissance. Two findings have since been fixed and are marked FIXED in
place: F2.1 (No-Bonding key distribution) and F3.2 (Table 10.2 error
selection). Everything else stands as reported.

## Reference implementations obtained

| Stack | Source | Snapshot commit | Role |
| --- | --- | --- | --- |
| BlueZ 5.87 | `git.kernel.org/pub/scm/bluetooth/bluez.git` | `92305dc06ab8a6d89af2dae1d725cc4d51462ad1` | the dominant Linux peer; also the mesh reference |
| Linux kernel SMP | `net/bluetooth/smp.c` | snapshot `smp_kernel.c` | BlueZ's SMP lives in the kernel, not in userspace |
| Zephyr | `github.com/zephyrproject-rtos/zephyr` | `2665fcca3cced3aefb7202d6289991d8cc1dfcac` | PTS-qualified; where it differs from BlueZ it usually tracks the qualification tests |
| Apache NimBLE | `github.com/apache/mynewt-nimble` | `1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845` | a third independent reading of the same specifications |

Adjudicating text: `/usr/src/bluetooth-specs/Core_Specification_6_3.txt`.
Mesh has no specification in tree; see section 5 for what was used instead.

## Classification key

- **OURS-WRONG** — the spec, or the unanimous practice of the references,
  contradicts us.
- **OURS-RIGHT-OTHERS-DIFFER** — we match the spec and at least one reference
  does not. Recorded so nobody "fixes" us towards the reference.
- **ECOSYSTEM-SPLIT** — the references disagree and the spec does not settle
  it. Needs a product decision, not a patch.
- **AGREE** — checked, no divergence. Recorded so the ground is not re-ploughed.

---

## Ranked findings

Ranked by interoperability impact against a real peer — a Linux central, an
Android or iOS phone — ahead of theoretical conformance.

| # | Area | Finding | Class | Impact |
| --- | --- | --- | --- | --- |
| 1 | ATT errors | Read Blob returns Attribute Not Long where a zero-length response is mandated | OURS-WRONG | reads fail against BlueZ/Android clients |
| 2 | Wire/SMP | on-demand security elevation feeds SMP the identity address, not the on-air address | OURS-WRONG | all pairing fails when privacy is on |
| 3 | ATT errors | unencrypted-link error selection keys on permission bits, not on LTK presence | OURS-WRONG | wrong recovery action by the peer, both directions |
| 4 | Pairing | a No-Bonding pairing still distributes our IRK and CSRK | OURS-WRONG | permanent trackability; privacy defeated |
| 5 | State machine | plaintext notifications/indications accepted before reconnect security is met | OURS-WRONG | spoofable data, cache poisoning |
| 6 | HCI/GAP | peripheral connection-parameter update is a dead end | OURS-WRONG | stuck at the central's interval for the life of the link |
| 7 | State machine | ATT transaction timeout only half-kills the bearer | OURS-WRONG | keeps talking on a dead bearer |
| 8 | Pairing | Pairing Response is sent before the request is validated | OURS-WRONG | out-of-sequence failures; PTS failures |
| 9 | HCI/GAP | extended advertising reports are never reassembled | OURS-WRONG (gap) | BT5 peers appear nameless |
| 10 | State machine | a second Exchange MTU Request is answered Request Not Supported | OURS-WRONG | permanent throughput collapse to 23 octets |
| 11 | HCI/GAP | `ng_l2cap` accepts an illegally short supervision timeout (off by 2x) | OURS-WRONG | peer told "accepted", update never happens |
| 12 | State machine | one malformed ATT PDU tears down the ACL | OURS-DIFFER | remote denial of service |
| 13 | ATT errors | write to an attribute with no backing store returns 0x0D | OURS-WRONG | client retries lengths forever |
| 14 | Pairing | MITM-required enforcement driven by a different knob than the advertised bit | OURS-WRONG | misconfiguration silently yields unauthenticated bonds |

Mesh is ranked separately below, because it has a different reference basis and
a different peer population; on its own scale the top three would outrank
everything above.

| # | Finding | Class | Impact |
| --- | --- | --- | --- |
| M1 | IV Index Recovery is dead code | OURS-WRONG | a node off the air across an IV update is permanently dead on the network |
| M2 | provisioning is always unauthenticated; no OOB method is reachable | OURS-WRONG | MITM can learn the NetKey; cannot provision or be provisioned by OOB peers |
| M3 | no anti-reflection check on Provisioning Confirmation/Random | OURS-WRONG | CVE-2020-26560-class impersonation, latent behind M2 |
| M4 | segmented delivery to or from an LPN behind a Friend cannot work | OURS-WRONG | friendship is a black hole for anything non-trivial |
| M5 | SAR retransmission reuses the same network SEQ | OURS-WRONG | retransmission is a no-op past one hop |
| M6 | replay list committed before authentication, and never aged | OURS-WRONG | one lossy segmented message becomes permanently undeliverable |
| M8 | Node Reset does not erase persisted state | OURS-WRONG | a "removed" node rejoins with the same keys after reboot |
| M7 | a segment ack is sent for every segment | OURS-WRONG | congestion collapse; burns the sequence space ~30x |
| M9 | Key Refresh promotes AppKeys at Phase 2 | OURS-WRONG | traffic loss during refresh; code admits it, doc denies it |
| M10 | fifteen foundation-model divergences | OURS-WRONG | silent mis-provisioning by a real Config Client |

---

## 1. Wire representation and byte order

The two previously confirmed bugs lived here, so this area was swept
exhaustively: every SMP crypto primitive, every key-distribution PDU, every
integer-typed characteristic, and the hand-built HCI fields.

**The headline: the SMP crypto toolbox is correct, and 5BSD uses the majority
idiom.** `e`, `c1`, `s1`, `ah`, `f4`, `f5`, `f6`, `g2`, `h6` and `h7` were
compared argument by argument against all four references. 5BSD builds each
CMAC message in forward spec order with per-field swaps
(`smp_crypto.c:387-526`), which is exactly what Zephyr
(`subsys/bluetooth/crypto/bt_crypto.c:19,56,117,160`) and NimBLE
(`nimble/host/src/ble_sm_alg.c:217,262,330,378`) do; BlueZ and Linux instead
hold everything LSB-first and reverse the whole buffer once
(`bluez/src/shared/crypto.c:619`, `smp_kernel.c:164`). The two shapes are
mathematically identical and were verified to produce the same bytes. The f5
SALT orientation, the g2 truncation and `mod 1000000` reduction (both call
sites, `smp_sc.c:1049` and `:1543`), the public-key coordinate reversal, the
debug-key constant, the A1/A2 address packing, the f6 IOcap ordering, the
legacy `s1` argument order and the Database Hash *input* construction all
match. Details in the audit notes; the point is that this ground is now
covered by an external check rather than by our own oracles.

### F1.1 — Security elevation passes the identity address to SMP [OURS-WRONG, HIGH]

`ctl_gatt.c:112-115` calls `smp_open()` with `conn->adapter->addr` — the
adapter's permanent identity address — as the local address, and a hard-coded
local address type of `0`.

```c
ret = smp_open(&sc, (const uint8_t *)&conn->dst,
    conn->addr_type, (const uint8_t *)&conn->adapter->addr, 0,
    conn->adapter->hci_fd, conn->con_handle, blued_g.bond_db);
```

Those arguments are `local_addr` / `local_addr_type` (`smp.c:819-821`). They
reach `sc->local_addr` (`smp.c:831-833`), and from there `smp_pack_addr()`
(`smp_sc.c:328,778,1344,1859`) puts them into **A1 for f5 and f6**, and into
`iat`/`ia` for legacy `c1` (`smp.c:962,1381,1440`).

Two independent errors: the wrong address (with LL privacy the on-air local
address is an RPA, not the identity address), and an invalid type value —
`0` is not a valid internal `BDADDR_LE_*` code, so `smp_pack_addr()`
(`smp_sc.c:92-100`) maps it to public even for a static-random identity
address, which is wrong even with privacy off.

Spec, Vol 3 Part H §2.2.7/§2.2.8 (text lines 76390-76400): A1 and A2 are the
device addresses used to establish the connection, the type carried as the
least significant bit of the most significant octet.

All three references use the over-the-air connection addresses: Linux
`sc_dhkey_check()` (`smp_kernel.c:1420-1423`) and `sc_mackey_and_ltk()`
(`:1410`) use `hcon->init_addr`/`resp_addr`; Zephyr passes
`conn->le.init_addr`/`resp_addr` (`host/smp.c:3651,3696`); NimBLE passes the
connection's `our_ota_addr`/`peer_ota_addr`.

**Our own other two call sites are already correct** — `blued_central.c:161-169`
deliberately resolves the on-air local address first, and
`blued_peripheral.c:630-632` passes `conn->local_addr`. Only the control-plane
elevation path skips it.

Consequence: with privacy enabled, any GATT operation that hits Insufficient
Authentication and triggers on-demand elevation runs a pairing whose DHKey
Check is computed over the wrong A1. The peer answers Pairing Failed (DHKey
Check Failed), or Confirm Value Failed on legacy. Reproducible on every
privacy-enabled deployment, and it looks like a peer bug because the local
side just returns false.

Action: use the same three lines `blued_central.c:161-166` already uses, and
never hard-code the address type.

### F1.2 — `smp_h6()`/`smp_h7()` take the opposite argument convention to all four references [LATENT]

`smp_crypto.c:538,563` pass `keyid` and `salt` **unswapped** to a raw CMAC, so
they require MSB-first constants. BlueZ (`crypto.c:715`), Linux
(`smp_kernel.c:321,336`) and Zephyr (`bt_crypto.c:192,216`) all take LSB-first
and swap internally. Every current 5BSD caller supplies the correct MSB-first
constants (`smp_keys.c:1171-1176,1239-1247`, verified against Core 6.3 lines
77646-77670), so cross-transport key derivation is right today. The hazard is
that a future caller copying a constant from Linux or Zephyr — the obvious
thing to do — silently breaks CTKD. Classification AGREE on the wire,
but worth renaming the parameters `keyid_be`/`salt_be`.

### F1.3 — Missing `h8`, and three absent GAP characteristics [GAP, not a defect]

Zephyr implements `bt_crypto_h8()` (`bt_crypto.c:240`); we have no `h8`.
Peripheral Preferred Connection Parameters (0x2A04) and Resolvable Private
Address Only (0x2AC9) are absent from our GATT database entirely, and
Appearance (0x2A01) is hardcoded to `{0x00,0x00}` with no way to set it.
None of these is a byte-order defect — they are new wire surfaces that must
use `put_le16` when they are added. NimBLE's `ble_svc_gap.c:189-193` is the
model.

### F1.4 — Host-order log of the LE features bitmap [LOW]

`blued_event.c:791-797` `memcpy`s the 8-octet little-endian LE_Features field
into a `uint64_t` and logs it without `le64toh()`. The sibling reader at
`hci_misc.c:548` does it correctly. Cosmetic on our architectures; the value
is never used for a decision. (It *should* be — see F6.2.)

### F1.5 — Comment rot found while checking justifications

Per the standing instruction to treat justifications as suspect, three were
checked and two are inaccurate:

- `gatt.h:110` claims "only the four wire boundaries convert" the Database
  Hash. There are exactly **two** conversion call sites in tree
  (`gatt.c:178`, `blued_peripheral.c:1609`), and `blued_peripheral.c:1577`
  labels itself "Wire site 1 of 4". The rest of that comment's claims about
  BlueZ and Zephyr were independently verified true.
- `smp_sc.c:811-813` documents variables `pka_be`/`pkb_be` that do not exist
  (only `pka_le`/`pkb_le` are declared, at `:815`) and cites "Appendix D".
- `smp_crypto.c:607-624`, the signed-write truncation justification, is
  **accurate**, including its own caveat that mainline Linux `smp.c` contains
  no ATT signing code so only BlueZ can be cited. This was the comment
  corrected in `e20520bfb2c`; the correction holds up.

---

## 2. Key distribution and pairing rules

The already-known Secure Connections key-distribution finding is recorded in
`tests/usr.sbin/bluetooth/blued/spec_extref_smp_keydist.h` and is not
re-reported. The sweep looked for the same *class* of error elsewhere and
found one, plus several enforcement-ordering problems.

**First, what is right**, because it is a lot and it is load-bearing: the
IO-capability to method mapping is correct in all 50 cells for both legacy and
Secure Connections, and the passkey display/input direction is correct in all
12 Passkey Entry cells for both roles, including the two counter-intuitive
legacy ones. The OOB rules (legacy requires both sides, SC requires either)
and their precedence over MITM are right. Key-distribution AND-ing and
per-role mask selection match Linux line for line, including the legacy
LinkKey strip and the four-field CTKD gate. Distribution order (Peripheral
first) is right in all five flows. Key-size negotiation and LTK masking match
Linux and the §2.3.4 worked example. The 30-second pairing timer is armed
once, is not reset by Phase 2, survives a keypress flood, and force-disconnects
without emitting a PDU. **Secure Connections public-key validation is
complete** — debug-key detection, on-curve check, point-at-infinity, and the
CVE-2020-26558 reflection check, on all four receive sites. There is no
invalid-curve exposure.

### F2.1 — A No-Bonding pairing still distributes our IRK and CSRK [OURS-WRONG, HIGH, security]

**FIXED.** `smp.c` now zeroes both key-distribution octets when the Bonding
flag is clear — on the initiator from its own AuthReq, on the responder from
the AND of both. Pinned by `test_smp_pair_no_bonding_distributes_no_keys` and
`test_smp_respond_no_bonding_distributes_no_keys` in `smp_pairing_test.c`,
which assert the transmitted octets and the absence of any key PDU.

`sc->bondable` drives only the AuthReq Bonding bit (`smp.c:211`). The
key-distribution masks come from an unrelated configuration knob
(`blued_central.c:196-197`, `blued_peripheral.c:652-653`, default
`ENC|ID|SIGN|LINK`), and nothing clears them when bonding was not requested.
We therefore advertise IdKey and SignKey and actually transmit Identity
Information and Signing Information (`smp_keys.c:271-323`,
`smp_legacy.c:298-340`, `smp_sc.c:1658-1699,2125-2166`). The bonding flags are
consulted only when deciding whether to *persist*.

Linux zeroes both masks in `build_pairing_cmd()` (`smp_kernel.c:636-643`).
Zephyr sets `smp->local_dist = 0; smp->remote_dist = 0`
(`host/smp.c:3480-3488`). Spec §3.6.1: "If EncKey and IdKey are set to zero
... no keys shall be distributed."

Consequence is worse than a conformance miss. The local IRK is the single
per-adapter key behind every RPA this host ever advertises. Handing it to a
device we explicitly declined to bond with makes the host permanently
trackable by that device — precisely the linkability that LE privacy exists to
prevent.

### F2.2 — The responder sends Pairing Response before validating the request [OURS-WRONG]

`smp_respond()` transmits at `smp.c:1904`. Key-size range and negotiation
(`:1934-1975`), SC-only (`:1977-1985`), reserved IO-capability and OOB values
(`:2010-2018`), invalid model (`:2035-2043`) and the security floor
(`:2052-2070`) are all checked *after* that, each emitting a Pairing Failed on
a link where we have already committed to a Response. All three references
compute the reason and return it *instead of* the Response — Linux
`smp_cmd_pairing_req()` validates at `smp_kernel.c:1795-1811` and sends only
at `:1818`. (`reject_pairing` is correctly checked first, at `smp.c:1772`.)

A peer that pipelines Phase 2 behind the Response sees an out-of-sequence
failure and may report the wrong reason. The fix is a hoist.

### F2.3 — MITM enforcement is driven by a different knob than the advertised bit [OURS-WRONG]

Spec §2.3.5.1 (line 76874) makes it a "shall": if MITM protection is required
and the selected method is Just Works, pairing fails with Authentication
Requirements (0x03). Our only implementation of that rule is
`smp_policy_permits()` (`smp.c:1226`, called at `:2057`), driven by
`min_pairing_security`; the MITM bit we put on the wire comes from an
independent `mitm` key. The defaults are correct and match Linux, but
`mitm=true` with `min_pairing_security="enc"` advertises "MITM required" and
then silently completes an unauthenticated Just Works bond. Linux derives the
check from the same AuthReq it sent (`smp_kernel.c:1795-1806,1959-1967`), as do
Zephyr (`remote_sec_level_reachable`) and NimBLE
(`ble_sm_verify_auth_requirements`).

### F2.4 — SC-only does not imply authenticated [OURS-WRONG]

`sc_only` rejects a non-SC peer but does not raise the security floor, so SC
Just Works completes under `sc_only`. Vol 3 Part C §10.2.4 requires security
level 4. Zephyr and NimBLE both force level 4 when SC-only is set.

### F2.5 — 16-octet key demanded for all SC pairing [OURS-RIGHT-OTHERS-DIFFER / too strict]

We require 16 octets for every Secure Connections pairing (`smp.c:1106,1956`),
citing erratum 11838. The 128-bit requirement belongs to security level 4 and
SC-Only mode (Vol 3 Part C §10.2.4), not to SC in general. Linux gates it on
`BT_SECURITY_FIPS`, Zephyr on level 4, NimBLE on `BLE_SM_SC_ONLY`. This is a
deliberate deviation whose justification is *narrower than the code* — the
erratum is real but does not reach the general case. It causes a hard pairing
failure against any SC peer offering less than 16, which is rare in the field
and standard in PTS.

### F2.6 — Lower-ranked

Bonding_Flags is a two-bit field with 0b1x reserved; we treat it as one bit and
never mask reserved AuthReq bits on receive (Linux masks with
`AUTH_REQ_MASK`). And `SMP_ERR_KEY_REJECTED` (0x0F) is defined but never sent:
the identity-hijack and bond-downgrade rejections reach the peer as Invalid
Parameters, so it retries the identical exchange.

### An ecosystem note

Zephyr refuses *legacy* Passkey Entry whenever authentication is required, on
the grounds that a 20-bit TK is not real MITM protection. We and Linux both
count it as authenticated. **ECOSYSTEM-SPLIT** — a policy decision, not a bug.

---

## 3. ATT error-code selection

The conformance audit ranks this the top uncovered area. It earns the ranking.

### F3.1 — Read Blob returns Attribute Not Long where the spec mandates a zero-length response [OURS-WRONG, HIGHEST interop impact]

`att_server_dispatch.c:1057-1068`:

```c
if (offset > full_len) -> ATT_ERR_INVALID_OFFSET;          /* correct */
if (offset > 0 && full_len > 0 && full_len <= ac->mtu - 1)
        -> ATT_ERR_ATTR_NOT_LONG;   /* fires even when offset == full_len */
```

**No reference stack ever emits 0x0B.** BlueZ delegates offsets to the db layer
and only produces 0x07. Zephyr's `bt_gatt_attr_read()`
(`host/gatt.c:1769-1784`) returns 0x07 for `offset > value_len` and a
zero-length response for `offset == value_len`. NimBLE has no occurrence of
the code at all.

Spec Vol 3 Part F §3.4.4.5 makes 0x0B a *may*, conditioned on a fixed-length
attribute, and then: "If the value offset ... is equal to the length of the
attribute value, then the length of the part attribute value in the response
**shall** be zero." Our `struct att_attr` has no fixed-length concept, so any
short value trips the branch.

Consequence, concretely: BlueZ's own client `read_long_cb()`
(`src/shared/gatt-client.c:3008-3060`) keeps issuing blobs while
`length >= mtu-1`, so for a characteristic exactly `MTU-1` octets long it
issues a blob at `offset == full_len`. We answer 0x0B; the client takes the
error branch, sets `success = false`, and **discards data it had already
completely collected**. `bluetoothctl` and D-Bus `ReadValue` fail outright on
any 22-octet characteristic at the default MTU. Android's loop behaves the
same way.

Action: delete the branch. It is a one-branch change and it is the single
highest-value fix in this document.

### F3.2 — On an unencrypted link the error must key on LTK presence, not on permission bits [OURS-WRONG]

**FIXED.** `struct att_conn` carries `has_peer_key`, set from the daemon's
bond resolution at link setup and after pairing and cleared by
`att_server_reset()`; `att_check_read_perm()`, `att_check_write_perm()` and
`att_check_security_perms()` select from it. Pinned against
`spec_extref_att_error_selection.h` by `test_se_err_unencrypted_table_10_2`
and `test_se_err_encrypted_table_10_2` in `att_server_edge_test.c`. This is a
deliberate divergence from BlueZ, recorded as such in the code.

`att_server.c:737-781` and `:789-807` choose the error purely from the
attribute's permission bits: authentication-required yields 0x05,
encryption-required yields 0x0F. Bond state is never consulted;
`att_conn_apply_encryption()` (`:853`) only records state after encryption is
already on.

Spec Vol 3 Part C §10.3.1.1 and **Table 10.2** settle it: in the entire
*Unencrypted* block, all three access requirements yield **Insufficient
Authentication (0x05)** in the "No LTK, no STK" column and **Insufficient
Encryption (0x0F)** in all three LTK-present columns. The MITM distinction only
selects 0x05 inside the *Encrypted* block.

Zephyr (`host/gatt.c:3211-3221`) and NimBLE (`ble_att_svr.c:303-322`) both
implement exactly this; NimBLE even does a persistent-store LTK lookup to pick
the code. **BlueZ shares our defect** — which is why comparing only against
BlueZ would have missed this, and why Zephyr was worth fetching.

We are wrong in both directions. An unbonded peer touching an
encryption-required attribute gets 0x0F and is sent down a re-encryption path
that cannot succeed, instead of pairing. A bonded-but-unauthenticated peer
touching a MITM attribute after a dropped link gets 0x05 and re-pairs, instead
of cheaply re-encrypting. Fixing it requires plumbing bond/LTK presence into
`struct att_conn`.

### F3.3 — Write to an attribute with no backing store [OURS-WRONG]

`att_server_dispatch.c:1129` and `:817` conflate `a->value == NULL` with a
length error and return 0x0D. Our *own* Prepare Write path at `:1424-1437`
returns 0x03 and carries a comment explaining that "length is not the issue and
Invalid Attribute Value Length would be the wrong code" — the two paths
disagree with each other, and the one with the reasoning is the right one.
Zephyr's `bt_gatt_check_perm()` (`host/gatt.c:3180-3183`) makes "permission bit
set but no handler" explicitly Write Not Permitted. Returning 0x0D makes a
central retry with different lengths forever.

### F3.4 — Read By Group Type checks the group type before the handle range [OURS-WRONG, minor]

For 128-bit type UUIDs, `att_server_dispatch.c:319` (Unsupported Group Type)
runs before the range check at `:325`; the 16-bit path at `:331` gets the order
right. All three references check the range first (BlueZ `:292-312`, Zephyr
`host/att.c:2086-2104`, NimBLE `:2094-2114`), matching the prose order of
§3.4.4.9. Robustness/PTS only.

### F3.5 — Prepare Write validates too early [OURS-WRONG, minor]

We emit 0x0D and 0x07 at Prepare time, which the Note in §3.4.6.1 reserves for
Execute time; the 0x0D case (`vlen > 512`, reachable at EATT MTUs) is really a
queue-capacity failure and should be 0x09. Zephyr and NimBLE validate only at
Execute. BlueZ diverges the same way we do.

### F3.6 — We are right and Zephyr is not [OURS-RIGHT-OTHERS-DIFFER]

For Read By Type and Read By Group Type permission failures we report the
*offending* attribute handle (`att_server_dispatch.c:490-497,350-360`),
matching §3.4.4.1/§3.4.4.9 and BlueZ and NimBLE. Zephyr is non-conformant:
`att_read_type_rsp()` (`host/att.c:1592-1600`) sends `start_handle`, and
`read_group_cb` carries a literal `/* TODO: Handle read errors */` and simply
stops. Worth a regression test so that nobody later "aligns with Zephyr".

### F3.7 — Two more bad citations, one good one

- **BAD**: `att_server.c:748-751` and `:772-773` cite Vol 3 Part F §3.2.5 for
  the authentication-before-encryption precedence. §3.2.5 states the two rules
  independently and never addresses precedence or the unencrypted case. Vol 3
  Part C Table 10.2 governs, and contradicts the behaviour. This is a third
  instance of the pattern.
- **BAD**: `att_server_dispatch.c:1046-1056` asserts that "offset == length is
  valid and yields a zero-length response" — and the code immediately below it
  returns 0x0B for exactly that case (F3.1).
- **GOOD**: the robust-caching carve-outs at `:2297-2325` were verified against
  Table 3.43 and §2.5.2.1; the three PDUs that must not be answered with 0x12
  are exactly Find Information, Find By Type Value and Read By Group Type, as
  claimed. The Database Hash Read-By-Type citation at `:561-567` and the Read
  Multiple Variable rule at `:2192-2198` also check out.

### Verified correct

Execute Write validation (validate-all-then-apply, queue cleared, offending
handle, running-length offset check) is spec-exact. Read Multiple and Read
Multiple Variable error handling and truncation. Find Information
handle-in-error. Find By Type Value skipping unreadable matches. Client
Supported Features 0x13-on-bit-clear. Request Not Supported dispatch.

---

## 4. State machines

### F4.1 — Plaintext notifications and indications are accepted before reconnect security is met [OURS-WRONG, HIGH]

`blued_central.c:2286 hogp_unsolicited()` hands HVN and HVI to control-plane
subscribers with no encryption or authentication check. The unsolicited handler
is installed at `blued_central.c:452` and MTU exchange happens at `:529`, both
*before* `smp_encrypt_with_ltk()`. Worse, an unencrypted Service Changed
indication clears `bond->has_handle_cache` and `has_db_hash`, so an attacker
can flush the cache of a bonded connection from an unauthenticated position.

Spec Vol 3 Part C §10.3.2.2 requires ignoring such notifications and
confirming-then-discarding such indications. Zephyr implements exactly this in
`check_subscribe_security_level()` (`host/gatt.c:3631`, called at `:3661`).

### F4.2 — The 30-second transaction timeout only half-kills the bearer [OURS-WRONG]

`att.c:633 att_bearer_fail()` sets `ac->failed`, which is read only by the two
bearer selectors in `att.c`. `att_server_send()` (`att_server.c:76-86`) and
`att_server_handle()` never check it, and the socket is never shut down — so we
keep answering requests and emitting notifications on a bearer that §3.3.3
declares unusable: "no further ATT requests ... shall be sent over this ATT
Bearer." BlueZ's `timeout_cb()` (`src/shared/att.c:478-511`) calls
`io_shutdown()`; Zephyr's `att_timeout()` (`host/att.c:3219`) calls
`att_disconnect()`. Our *indication* timer does disconnect
(`blued_event.c:2107-2135`), so that half is right.

### F4.3 — No sequential-transaction enforcement in the server [OURS-WRONG]

There is no `in_req` state. The only busy check is inside `att_begin_defer()`
(`att_server_dispatch.c:678`), so it covers only a second *deferrable* request.
A synchronous request arriving while a deferred read is outstanding is answered
immediately — two responses in flight on one bearer. BlueZ disconnects the
bearer for any second request (`src/shared/att.c:1112-1125`). Zephyr and NimBLE
are fully synchronous, so the case cannot arise for them; our asynchronous
deferral makes this uniquely ours to get wrong.

### F4.4 — A second Exchange MTU Request is answered Request Not Supported [OURS-WRONG]

`att_server_dispatch.c:186`. Vol 3 Part G §4.3.1 says a peer that receives 0x06
for this opcode "shall use the default MTU" — 23 octets. So a re-request, which
some stacks issue after a reconnect, converts into a permanent throughput
collapse for the life of the connection. None of BlueZ, Zephyr or NimBLE keeps
once-per-connection server state; all simply re-negotiate. Aggravated by
`mtu_exchanged` being shared with our own client-side exchange (`att.c:1024`).

### F4.5 — One malformed ATT PDU tears down the ACL [OURS-DIFFER, remote DoS]

`att_recv_record()` maps `MSG_TRUNC` to `EMSGSIZE`, and `blued_event.c:1975`
treats `nr <= 0` as a closed socket and calls `blued_conn_disconnect()`. So a
single over-long ATT PDU — or a zero-length record, which is indistinguishable
from EOF here — drops the ACL. All three references drop the PDU and keep the
link.

### F4.6 — `ac->pending` is per-connection, not per-bearer [OURS-WRONG]

A slow application read on one EATT bearer answers every deferrable request on
bearers 2..5 with Unlikely Error for up to 30 seconds. BlueZ's `in_req` is per
`bt_att_chan`.

### F4.7 — Robust caching gaps

We never suppress notifications and indications to a change-unaware client,
which §2.5.2.1 requires and Zephyr enforces at `host/gatt.c:2461,2625,2959`.
The Database Hash read sets `change_aware` immediately rather than latching
until the next request. `out_of_sync_sent` is per-connection despite a comment
claiming it is per bearer — a fourth inaccurate comment. Zephyr's
`bt_gatt_change_aware()` (`host/gatt.c:6055-6104`) is the spec-exact model.

### F4.8 — Lower-ranked

A stray Confirmation unconditionally clears `ind_pending`
(`att_server_dispatch.c:2501`), so a forged confirmation unlocks the indication
slot; BlueZ and Zephyr disconnect, NimBLE ignores. Indications are refused
`EBUSY` rather than queued (BlueZ and Zephyr queue). A sub-23 Client Rx MTU is
clamped rather than rejected (Zephyr rejects; BlueZ and NimBLE clamp —
**ECOSYSTEM-SPLIT**).

### Verified correct

Prepare-queue lifetime and per-client scoping; an invalid Prepare leaves the
queue intact; client-side Prepare echo validation and Execute-Cancel; Read Blob
offset ordering (0x07 before 0x0B); Read Multiple Variable full-Length
semantics; unknown-opcode discrimination via the 0x40 bit; the initial
change-aware state; and client-side one-outstanding-request enforcement. There
is **no divergent ATT-layer retry or backoff in either direction** — our single
security-elevation retry (`ctl_gatt.c:171-219`, `blued_central.c:631-646`)
matches BlueZ's `op->retry` and Zephyr's `req->retrying`.

---

## 5. Mesh

Mesh has no specification in this tree, so the reference basis is different:
BlueZ's `mesh/` subtree and Zephyr's `subsys/bluetooth/mesh/`, plus BlueZ's
`unit/test-mesh-crypto.c`, whose vectors carry their own "Mesh Profile v1.0.1
Sample data" section citations and are the closest thing to spec text
available. Where the two references agree, that is treated as the
specification.

**The wire formats are in excellent shape, and this is worth saying plainly
before the rest.** Verified octet by octet against both references: the
13-octet network nonce; the PECB and Privacy Random obfuscation construction;
all four nonce types with ASZMIC at bit 7; k1 through k5; the virtual-address
`s1("vtad")` derivation; the friendship k2 P-input; the SeqZero to SeqAuth
reconstruction (our two-branch form is provably identical to Zephyr's mask
arithmetic); Composition Data Page 0; the heartbeat log encodings; and the
provisioning derivations for both algorithms. Twenty of the known-answer
vectors in `mesh_crypto_test.c` match BlueZ's `test-mesh-crypto.c`
byte for byte. Sequence-number persistence uses forward reservation, which is
as good as or better than either reference.

### The systemic finding: implemented, unit-tested, never called

What is broken is almost entirely the layer above the wire format —
**procedures that exist as library functions, are covered by green tests, and
are never called by the daemon.** Four independent instances turned up in four
different subsystems, which prompted a mechanical sweep: of 883 non-static
functions in `lib/libmesh`, **203 have no production caller anywhere in the
tree, and 45 of those are in core-protocol files.** A meaningful share of the
203 is legitimate library symmetry — parse counterparts, client-model APIs —
but the 45 are mandatory procedures, not conveniences.

The ATF suite is green throughout because it calls the library directly. Unit
coverage is actively certifying code the daemon never reaches.

The dead core-protocol entry points include `mesh_iv_recovery_begin`,
`mesh_rpl_reset`, `mesh_rpl_net_receive_ivupd`, `mesh_private_beacon_build`
and `_parse`, the entire `mesh_prov_auth_*` AuthValue family (all four
methods), the LPN and Friend FSM entry points, `mesh_access_dispatch`, the
message-cache init and check, and three proxy advertisement builders.

Suggested action, ahead of any individual fix: add a mechanical check that
every symbol exported by libmesh's `Version.map` has at least one caller
outside `tests/`, and stop treating "the library function exists and is
tested" as evidence that a feature ships.

### M1 — IV Index Recovery is dead code [OURS-WRONG, CRITICAL]

`mesh_iv_recv_beacon()` adopts a higher IV Index only when
`st->recovery_active` is set (`lib/libmesh/mesh_iv.c:178-185,206-212`), and
`mesh_iv_recovery_begin()` (`mesh_iv.c:114-122`) is called from nothing except
`mesh_iv_test.c`. So `recovery_active` is permanently zero in the daemon, and:
a beacon at `cur+1` with the IV Update flag clear is rejected
(`mesh_iv.c:197`); a beacon at `cur+2 .. cur+42` is rejected (`:206`).

BlueZ's `update_iv_ivu_state()` (`mesh/net.c:2695-2782`) accepts any IV index
in `[cur, cur+42]`, resets the sequence number (`:2757`) and prunes the RPL
(`:2761`), with no arming step; the only brake is the 96-hour
`IV_UPD_NORMAL_HOLD`. Zephyr's `bt_mesh_net_iv_update()`
(`mesh/net.c:314-356`) fires the recovery branch automatically, sets
`ivi_was_recovered`, calls `bt_mesh_rpl_clear()` and zeroes the sequence
number, restricted only by the 192-hour rule (`:331-335`).

Consequence: a node that is powered off, out of range, or asleep across a
network IV Update permanently desynchronises. It accepts only `{iv, iv-1}`
(`mesh_sim.c:1197-1204`), so every PDU from the rest of the network fails
NetMIC and the node is silently dead — and unrecoverable without
re-provisioning. This also breaks the ordinary case of a node that was briefly
off the air: the beacon carries `cur+1` with the flag clear, and we reject it.

### M2 — Provisioning is always unauthenticated [OURS-WRONG, HIGH, security]

`mesh_provisioner.c:194,215` install a zero AuthValue in both roles and never
change it. The provisioner builds Provisioning Start from a zeroed struct
(`:288-297`), so the authentication method, action and size are always zero
regardless of what the device advertised; the device role hard-rejects any
Start with `auth_method != 0` (`:436-437`), and `prov_caps_valid()`
(`mesh_provision.c:226-231`) rejects a Capabilities PDU that requires OOB.
`PROV_INPUT_COMPLETE` is handled in neither role's switch and falls to the
Unexpected-PDU default (`:378,535`).

BlueZ's `int_prov_start_auth()` (`mesh/prov-initiator.c:617-652`) intersects
the two capability sets and prefers Static, then Output, then Input. Zephyr's
`bt_mesh_prov_auth()` implements all four methods, and
`prov_check_method()` (`mesh/provisioner.c:148-207`) validates the choice
against the device's Capabilities.

Consequence, three ways: every provisioning we perform is unauthenticated, so
any MITM in range can insert itself and learn the NetKey and DevKey we hand
over; we cannot provision any device that requires OOB, which is most
commercial lighting and lock hardware; and a BlueZ or phone provisioner that
selects Static OOB against our device role gets Invalid PDU and cannot
provision us at all.

The packing helpers this needs already exist and match Zephyr byte for byte —
they are simply never called (the dead-code pattern again).

### M3 — No anti-reflection check on Provisioning Confirmation or Random [OURS-WRONG, HIGH, security]

`mesh_provisioner.c:329-341` stores the peer's Confirmation with no comparison
against our own, and `:344-356` does the same for Random; the device path is
identical at `:471-489,491-505`. Only the identical-public-key case is
rejected (`:80-86`).

BlueZ rejects both explicitly — `prov-initiator.c:772-776` ("Disallow echoed
values") and `:786-790` ("Disallow matching random values"), with the acceptor
mirroring at `prov-acceptor.c:371-373,603-607`. Zephyr does the same at
`provisioner.c:677-682,638-642` and `provisionee.c:426-431`.

This is the CVE-2020-26560 class of provisioning impersonation: a rogue device
that mirrors our Confirmation and then our Random passes our verification
unchanged. It is currently masked only because M2 forces the AuthValue to
zero; it becomes an outright authentication bypass the moment OOB lands. Fix
M3 *before* fixing M2, or fix them together.

### M4 — Segmented delivery to or from an LPN behind a Friend cannot work [OURS-WRONG, HIGH]

Two halves, both broken:

Our segment-ack matcher requires `s->dst == pdu.src` (`mesh_sim.c:1983-1990`),
so an on-behalf-of ack from a Friend's own unicast address never matches; the
`obo` bit is parsed (`mesh_transport.c:502`) and then never read. We also never
*set* it — `send_seg_ack()` (`mesh_sim.c:963-973`) memsets the struct and never
sets `obo`. Zephyr's `seg_tx_lookup()` (`mesh/transport.c:816-841`)
deliberately accepts an ack from a different address when OBO is set; BlueZ
matches on SeqZero alone (`mesh/net.c:1571`) and generates OBO in
`send_net_ack()` when the source is a friended LPN.

And our Friend Queue drops everything interesting: `meshd_node.c:6289` gates
enqueue on `np.ctl == 0`, and `mesh_friend.c:661-666` drops any entry whose
`segmented` flag is set, with no SAR path to re-present a reassembled message.
BlueZ stores per-segment and explicitly forwards Segment Acknowledgment from
the queue (`mesh/friend.c:363-378,502-517`); Zephyr's
`bt_mesh_friend_enqueue_rx()` (`mesh/friend.c:1740-1790`) takes a `seg_count`
and enqueues each segment.

Consequence: a Zephyr or BlueZ LPN that friends with us loses every message
longer than 11 access octets — Composition Data Status, most Config statuses,
anything acknowledged — and never receives a Segment Acknowledgment, so its own
segmented transmissions never complete either. Friendship establishes and then
behaves as a black hole for anything non-trivial.

Note that the simulator hides this: `mesh_sim.c:1730-1751` enqueues *without*
the ctl gate and *without* the segmented flag, so every sim-based friendship
test exercises a path the daemon does not have.

### M5 — SAR retransmission is a no-op past one hop [OURS-WRONG, HIGH]

`sar_tx_record()` (`mesh_sim.c:244-270`) snapshots the already-encrypted
network PDUs, and `sar_tx_requeue_missing()` (`:272-291`) re-queues those
byte-identical PDUs. The network sequence number is therefore identical on
every retransmission.

Zephyr rebuilds each segment from stored plaintext and assigns a fresh sequence
number on every transmission (`mesh/transport.c:342-352,414`,
`mesh/net.c:505`). BlueZ is explicit about it — `mesh/net.c:3122-3125`:
`if (msg->segmented) { /* Send each segment on unique seq_num */ seq_num =
mesh_net_next_seq_num(net); }`.

Every relay keeps a network message cache keyed on (SRC, SEQ, IVI) — **ours
does too**, at `mesh_sim.c:1638`, used to suppress relaying at `:1668,1713`. A
retransmitted segment with the same SEQ is therefore a cache hit at every
relay and is never forwarded. SAR retransmission works only on a direct
one-hop link and is a complete no-op in any multi-hop network — which is
exactly the case where segments get lost. This is what the 13-bit SeqZero
field exists to make possible.

### M6 — The replay list is committed before authentication, and never aged [OURS-WRONG, HIGH]

`mesh_rpl_check()` updates the entry in place at the moment of the check
(`mesh_rpl.c:85-99`); there is no peek/commit split. On receive, the check
happens at lower-transport time, and for a segmented message it commits at the
SeqAuth when the SAR session is *created*, on the first segment
(`mesh_sim.c:1811-1816`; control at `:1918-1921`).

BlueZ checks, delivers via `mesh_model_rx()`, and only then calls
`msg_add_replay_cache()` (`mesh/net.c:1772-1783`), with the comment "If message
has been handled by us, add to RPL". Zephyr's `bt_mesh_rpl_check()` returns the
slot without committing, and the comment at `mesh/rpl.c:104-108` says this
exists precisely "to prevent storing data in RPL that has been rejected by
upper logic ... and for receiving the segmented messages";
`bt_mesh_rpl_update()` is called only on success
(`mesh/transport.c:1057-1061,1599-1607`).

Reproducible consequence: a peer sends a segmented message with SeqAuth S. We
take segment 0, commit RPL = (iv, S), never receive the rest, and reap the
session at the discard deadline. The peer retransmits the same SeqAuth —
SeqZero is invariant across SAR retransmission — we check, `S > S` is false, we
score it a replay, drop it, and send no ack. The sender exhausts its
retransmissions and gives up. **The message is undeliverable forever.** With a
phone provisioner this bricks any long Config message after a single lossy
attempt.

Separately the RPL is never aged or reclaimed — `mesh_rpl_reset()` is one of
the dead exports — behind a hard 16-peer ceiling that persists across reboot,
so the list fills permanently.

### M7 — A segment ack is emitted for every received segment [OURS-WRONG, MEDIUM-HIGH]

`mesh_sim.c:1863-1866` (access) and `:1956-1959` (control) call
`send_seg_ack()` unconditionally after every accepted segment, and again for
every duplicate or late segment (`:1839-1843,1936-1939`). There is no
acknowledgment timer anywhere in the tree. Zephyr uses an `ACK_DELAY(seg_n)`
timer (`mesh/transport.c:51-53,1535-1538`) and cancels it to send a single full
ack on completion; BlueZ sends a partial ack only when the just-received
segment is the largest outstanding one (`mesh/net.c:2044-2057`).

A 32-segment message provokes 32 ack PDUs instead of one or two. Each consumes
a sequence number and is relayed network-wide, so this burns the 24-bit
sequence space roughly thirty times faster than peers and doubles SAR airtime —
a self-inflicted congestion collapse on a busy mesh.

### M8 — Node Reset does not erase persisted state [OURS-WRONG, HIGH]

`h_node_reset()` (`meshd_node.c:1996-2031`) clears the in-memory database, the
provisioned flag, heartbeat publication and friendship roles, but never touches
`nd->persist` and never clears the node's key material. After a restart,
`meshd_persist_load()` restores the node fully provisioned with the same keys
and unicast address — the reset is undone. BlueZ calls `node_remove()` →
`mesh_config_destroy_nvm()` (`mesh/node.c:314-324`); Zephyr calls
`bt_mesh_reset()` (`mesh/cfg_srv.c:2048-2051`).

A provisioner "removes" the node; the node reboots and rejoins with keys it was
supposed to have forgotten, at a unicast address that may since have been
reassigned. Both references also send the Status *before* tearing down; we
mutate first, which happens to work only because the reply path uses state the
handler leaves intact — state the reset should have cleared.

### M9 — Key Refresh promotes AppKeys at Phase 2 instead of Phase 3 [OURS-WRONG, MEDIUM-HIGH]

`meshd_appkeys_kr_promote()` (`meshd_node.c:2047-2060,2098`) overwrites AppKeys
at Phase 2, so the old AppKey stops decrypting received traffic while peers are
still legitimately using it. **The code comment admits this verbatim**
(`meshd_node.c:2035-2045`): "the old AppKey stops decrypting RX at this
promotion (Phase 2) instead of at the Phase 3 settle; per Section 3.11.4 the
old AppKey should remain an RX candidate until Phase 3." An honest limitation
note — but it is recorded as a known limitation in the code and as a *verified
correct property* in the review document (see M12).

### M10 — Foundation model divergences [OURS-WRONG, mostly MEDIUM]

Fifteen were found; the ones that reach a real Config Client:

- **Model Publication Status echoes the requested parameters on failure**
  (`meshd_node.c:2909,2965`, `mesh_cfg_model.c:884-899`). Both references zero
  the seven publication octets when status is not success — BlueZ
  `mesh/cfgmod-server.c:133-134`, Zephyr `mesh/cfg_srv.c:665-668`. nRF Mesh and
  any client that caches the Status believes the publication was configured
  when the node rejected it. Silent mis-provisioning.
- **The Configuration Server model itself accepts subscription and publication
  configuration** (`meshd_node.c:2703-2728,2769-2799,2867-2911`). Both
  references reject; BlueZ returns 0x08 Not-a-Subscribe-Model and 0x07 Invalid
  Publish Parameters (`mesh/model.c:1412` and neighbours), Zephyr returns
  0x07/0x05. Both of our correct status codes are *defined* in
  `mesh_cfg_model.h:137-138` and returned nowhere in the tree. AppKey Bind on
  model 0x0000 *is* correctly rejected, so the check exists — it is just not
  applied to sub/pub.
- Heartbeat Publication Set accepts a virtual destination; Heartbeat
  Subscription Set with PeriodLog 0 is mishandled; prohibited PublishTTL values
  0x80..0xFE are accepted; Model Publication Set does not require the AppKey to
  be bound; Composition Data Get ignores the requested Page; Health Fault
  Get/Clear/Test are silently unimplemented; the Attention Timer never counts
  down; the Health Fast Period Divisor is stored and never applied.

### M11 — Secure Network Beacon and IV state, lower-ranked

Beacons on a *secondary* subnet drive the node's IV index; leaving IV Update In
Progress is not deferred while a segmented transmission is outstanding; an IV
jump does not reset the sequence number or clear the RPL; and the Mesh Private
Beacon is implemented, correct, and never sent or received — the Private Beacon
Server state is exposed and persisted, so a provisioner enabling privacy gets
Success and no behaviour.

### M12 — The mesh self-assessment asserts properties the code does not have [DOC, HIGH]

`usr.sbin/bluetooth/REVIEW_FINDINGS.md:228` is a summary line of verified
properties. Three of its claims are contradicted by the code:

1. "RPL ... authenticate-before-record, never reset on IV update" — presented
   as a correctness property. Authenticate-before-record is the opposite of
   what the code does (M6). And "never reset on IV update" is the defect, not
   the feature: Zephyr ages the RPL on every IV update
   (`mesh/rpl.c:212-250`) and wipes it on recovery (`mesh/net.c:352`)
   precisely so slots are freed and stale pairs cannot block a peer forever.
2. "IV state machine ... >+1 requires recovery" — true as written, but it
   describes a gate whose only key does not exist (M1).
3. "key refresh ... revoke at Phase 3" — the code does Phase 2 and says so
   (M9).

Two entries at `REVIEW_FINDINGS.md:220-221` are closed out as FIXED and
ANNOTATED on functions with zero production callers — the fixes landed in dead
code. Anyone auditing mesh from this document concludes the replay, IV and key
refresh layer is done. This is the same failure mode as the code comments in
sections 1 through 4, at document scale.

### M13 — Mesh oracle traceability

- `tests/usr.sbin/bluetooth/blued/spec_extref_mesh_vectors.h` — 870 lines,
  carefully provenance-stamped to BlueZ with per-value citations and honest GAP
  markers — **is included by nothing.** The one anti-drift gate mesh has is
  wired to no test.
- Twenty-one `spec_mesh_*_oracles.h` headers cite MshPRT v1.1 and MshMDL
  v1.1.1, neither of which is in `/usr/src/bluetooth-specs`. Those citations
  cannot be checked by anyone reading this tree. Spot-checks found them
  correct — the friendship control opcodes match Zephyr's
  `mesh/transport.h:21-31` exactly — but correct by the author's care, not by
  construction. Where BlueZ or Zephyr also defines a constant, the citation
  should name that file and line too.
- `spec_mesh_beacon_oracles.h` mixes a genuinely external Secure Network Beacon
  vector with a **self-computed** Private Beacon one, assembled from a BlueZ
  random paired with a different section's netkey and different flags — while
  BlueZ ships two complete, unused Private Beacon vectors that could have been
  transcribed directly.
- **Directed Forwarding has no external reference of any kind.** `mesh_df.c` is
  1995 lines, `mesh_df.h` 737, plus the DF paths in `mesh_sim.c:1480-1615`.
  Neither reference implements DF: Zephyr's transport control opcode table
  stops at `TRANS_CTL_OP_HEARTBEAT` 0x0a, and BlueZ has nothing. Every DF
  constant rests on a citation to a document nobody in this tree can open.
  Worse, Zephyr *does* implement Solicitation — but as a Proxy Solicitation PDU
  with its own nonce type 0x04 (`mesh/crypto.c:308-326`), not as transport
  control opcode 0x11 the way `spec_mesh_df_oracles.h:17` asserts. That is at
  minimum a naming collision and possibly a real encoding error. DF should be
  ranked UNVERIFIED in any risk register; the only realistic gate is an interop
  test against a commercial DF-capable node, or obtaining MshPRT v1.1.

### Mesh: verified correct

Beyond the wire formats listed at the top: the relay predicate, network message
cache and local-origin drop; Relay Retransmit encoding; IVI-bit and IV +/-1
receive resolution; virtual-address derivation and address classification;
address-type validation; the friendship k2 P-input; and public-key validation
plus the Friend Clear replay window, which are **stricter than both
references** (OURS-RIGHT-OTHERS-DIFFER).

---

## 6. Everything else: HCI, GAP, advertising, privacy, ISO

### F6.1 — `ng_l2cap` accepts an illegally short supervision timeout [OURS-WRONG]

`sys/netgraph/bluetooth/l2cap/ng_l2cap_evnt.c:719-733` rejects a Connection
Parameter Update Request only when `timeout * 8 <= (1 + latency) * interval_max`.
Its own comment derives the constant as `10 / (1.25 * 2)`, which is **4, not
8** — the comment contradicts the code it justifies. This is a fifth bad
justification, and the only one found in the kernel.

Spec (text lines 140256-140259): the timeout must be larger than
`(1 + latency) x connInterval x 2`. Zephyr uses `*4`
(`host/hci_core.c:2058-2062`) — and so does **blued's own copy**
(`hci_conn.c:138-141`), which is correct. The kernel is the odd one out.

Consequence: an illegal parameter set is answered `UPDATE_PARAM_ACCEPT` and
forwarded to HCI LE Connection Update (`ng_l2cap_evnt.c:738-741`), where the
link layer rejects it. The peer has been told "accepted" and never receives an
`LL_CONNECTION_UPDATE_IND`.

### F6.2 — The peripheral connection-parameter update is a dead end [OURS-WRONG, highest impact in this section]

Three compounding problems:

- `hci_conn.c:262-286` gates the HCI path on **local** features only. Zephyr
  requires local *and* remote (`host/conn.c:2188-2190`). We do read the remote
  features — LE Meta 0x04 — but `blued_event.c:787-799` only logs the eight
  octets and discards them.
- `blued_event.c:753` handles LE Connection Update Complete only when
  `buf[4] == 0`. Status `0x1A` (Unsupported Remote Feature) falls through
  silently. Zephyr catches exactly that status and falls back to L2CAP
  (`host/hci_core.c:2153-2165`).
- **The comment declining to implement the L2CAP fallback is false.** It claims
  `ng_l2cap` "does not expose the LE signaling channel to user-space sockets."
  CID 0x0005 *is* dispatched (`ng_l2cap_evnt.c:320`), inbound requests and
  responses are both handled (`:671`, `:756`), and both PDUs are defined
  (`ng_l2cap.h:315,324`). What is actually missing is an *originator*: no
  `NGM_L2CAP_*` opcode exists for it and the transmit arm is a stub —
  `ng_l2cap_cmds.c:617-621`, `case NG_L2CAP_CMD_PARAM_UPDATE_REQUEST: /* TBD
  -- for now, clean up the unsent command */`. Sixth bad justification, and the
  substantive one: the conclusion happens to be right but the stated reason is
  wrong, which would send whoever picks this up looking in the wrong file.

Net effect: a 5BSD peripheral talking to any central whose controller lacks LE
feature bit 1 can never move off the central's connection interval, for the
life of the link.

### F6.3 — No `TGAP(conn_pause_peripheral)` grace before the parameter update [OURS-WRONG]

`blued_peripheral.c:1283-1294` sends the update synchronously in the setup
thread, concurrent with SMP and GATT discovery. Vol 3 Part C §9.3.12.2 (line
65931) says the peripheral should not do this within
`TGAP(conn_pause_peripheral)` = 5 s (line 68321). Zephyr implements it as a
5000 ms timer with an explicit spec citation in `Kconfig:792-806`, plus
`BT_CONN_PARAM_RETRY_COUNT = 3`. We are single-shot and only warn at
verbosity >= 2, so one ignored request — the typical iOS and Android behaviour
inside the pause window — leaves the link stuck forever.

### F6.4 — Extended advertising reports are never reassembled [OURS-WRONG, functional gap]

`hci_scan.c:1099-1160` refuses to AD-parse fragments *and* their terminal tail;
the comment says outright that "reassembly of >229-byte payloads is not
attempted." The suppression itself is correct and well reasoned — a
continuation tail does not start on an AD-structure boundary — but nothing
replaces it. Zephyr has a full reassembler keyed on (address, SID)
(`host/scan.c:70,90,127,96-108,888-951`), which is the same key our
`ext_frag_mark()` already computes. Consequence: Bluetooth 5 peers with more
than one report's worth of advertising data appear with no name, no service
UUIDs and no manufacturer ID — silently, so it reads to a user as "that device
doesn't advertise a name."

### F6.5 — RSSI 0x7F treated as a real +127 dBm [OURS-WRONG]

`hci_scan.c:1048-1057` correctly validates 0x7F as the "not available"
sentinel and then stores it verbatim (`:1087`); the legacy path (`:1589`) does
not check at all. It is then compared as a magnitude in the proximity filter
(`hci_scan.c:550`). BlueZ names it `HCI_RSSI_INVALID` (`src/adapter.c:86`) and
uses it to *disable* filtering (`:2270-2306`). So a report carrying "no RSSI"
scores as the strongest device in range and passes every `rssi_min` filter.

### F6.6 — `Fragment_Preference` and the enabled-set restriction [LATENT]

`hci_adv.c:744-757` hard-codes `Fragment_Preference = 0x01` even on the host's
own fragment train; Zephyr picks per case (`host/adv.c:577,608`). Separately,
§7.8.54 requires Command Disallowed for a non-0x03/0x04 operation on an enabled
set; we do not check, so a fragmented update on a running set fails on the
first fragment *after* Operation 0x01 has already discarded the controller's
existing data, leaving the set advertising nothing. Zephyr guards this at
`host/adv.c:640-647`. Only reachable today at lengths 252-255.

### Scope answers rather than findings

**LE ISO is not comparable**: our ISO is control-plane only and hands the data
socket to the client (`ISO_ST_HANDED_OFF`), so there is no ISO data header in
our code at all. That is a product gap, not a conformance one. **HCI flow
control is not comparable**: every command goes through the synchronous
`bt_devreq` ioctl, so `Num_HCI_Command_Packets` accounting lives entirely in
`sys/netgraph/bluetooth/hci/ng_hci_cmds.c:203,322`. And the ISO data header
packing (PSN, SDU length, PB, TS) lives in
`sys/netgraph/bluetooth/socket/ng_btsocket_iso.c`, which was out of scope here
and deserves its own audit.

Two things are notably better than a naive implementation and should not be
"simplified" by a future cleanup: the RPA-rotation quiescing in
`blued_adapter_rotate_rpa()` (it disables advertising, suspends the mesh
scanner and cancels initiation before `LE_Set_Random_Address`), and the
anonymous-advertiser handling in the extended advertising report parser.

---

## 7. What the pattern says

**Justifications are where the defects are.** Counting only what this sweep
opened and checked: `att_server.c:748-751` cites Vol 3 Part F §3.2.5 for a
precedence rule that section does not state and that Vol 3 Part C Table 10.2
contradicts; `att_server_dispatch.c:1046-1056` states the zero-length rule
correctly and is immediately followed by code that violates it;
`ng_l2cap_evnt.c:719-733` derives a constant its own arithmetic disproves; the
comment declining the L2CAP parameter-update fallback names a limitation the
kernel does not have, while the real blocker sits in a different file;
`gatt.h:110` miscounts its own conversion sites; and a comment on the ATT
robust-caching state calls a per-connection variable per-bearer. Add the two
corrected in `e20520bfb2c`, and it is six.

Each was written to justify a deviation, and in each case the deviation is
where the defect is. That is not a coincidence: a comment gets written at
exactly the moment someone decides not to do the obvious thing, which is also
the moment they are most likely to be wrong. The rule this suggests is simple
and mechanical — when a comment cites a source, open the source.

**At document scale, the same thing.** `REVIEW_FINDINGS.md:228` asserts three
mesh correctness properties the code does not have (M12), and closes two
findings as fixed in functions that have no production caller. A review
document is not coverage.

**BlueZ alone is not a sufficient reference.** F3.2 — the error-selection
defect our own conformance audit ranks first — is a defect BlueZ *shares*. It
was visible only because Zephyr and NimBLE were read alongside. Where the three
disagree, Zephyr's PTS qualification is the tiebreaker worth trusting, and
where BlueZ and Zephyr agree, that is as close to settled as this ecosystem
gets. Two findings in this document (F3.6, and the mesh public-key and Friend
Clear checks) are cases where we are *stricter* than a reference; those are
worth regression tests specifically so nobody later "aligns" us with the
reference and regresses us.

**And for mesh, the reference has to be the daemon, not the library.** The
mesh section's largest finding is not any single protocol error — it is that
203 exported libmesh functions have no production caller, 45 of them in
core-protocol files, while the unit suite is green because it calls them
directly. Every one of the four subsystems examined had at least one mandatory
procedure that exists, is tested, and never runs. A test that reaches a
function the product cannot reach is worse than no test, because it reads as
coverage.

## 8. Files

Created by this sweep:

- `docs/bluetooth-interop-comparison.md` — this document.
- `tests/usr.sbin/bluetooth/blued/spec_extref_att_error_selection.h` — Vol 3
  Part C Table 10.2 transcribed in full as two indexed tables, with the
  governing §10.3.1 text quoted verbatim, plus which references implement it.
  This is the oracle for the top-ranked item of the conformance gap list.
- `tests/usr.sbin/bluetooth/blued/spec_extref_att_read_blob.h` — the
  §3.4.4.5 outcome rule as a function of offset and length, the "may" versus
  "shall" distinction that settles it, and the record that no reference stack
  emits 0x0B. Includes the BlueZ client loop's trigger case as a worked
  example.
- `tests/usr.sbin/bluetooth/blued/spec_extref_smp_addr_binding.h` — the
  §2.3.5.5 "device addresses used during connection setup" rule and the
  address-type bit, with all three references' on-air address fields cited.
- `tests/usr.sbin/bluetooth/blued/spec_extref_mesh_iv_recovery.h` — the IV
  Index Recovery window and side effects, built to the same contract as
  `spec_extref_mesh_vectors.h`: sourced from BlueZ and Zephyr, with Zephyr's
  own verbatim MshPRT v1.1 citation reproduced and labelled as Zephyr's
  citation rather than as our reading of a document this tree does not have.

All four compile standalone and follow the existing headers' conventions: every
value traceable to a named external source, nothing derived by running our own
code.

Note, from M13, that the existing `spec_extref_mesh_vectors.h` is included by
no test. The four headers added here will be equally inert until something
consumes them; wiring them up is the natural next step and requires a change to
the tests Makefile, which was out of scope for this pass.

## 9. Suggested order of work

Not a plan, just the order the evidence supports:

1. **F3.1** (Read Blob) — one branch, and it unbreaks reads from BlueZ and
   Android clients today.
2. **F1.1** (SMP address binding) — three lines that already exist in two other
   call sites; unbreaks all pairing on privacy-enabled deployments.
3. **F2.1** (No-Bonding key distribution) — a privacy defeat, and small.
4. **M1, M3, M6** (mesh IV recovery, provisioning reflection, RPL commit point)
   — each is a "the network stops working" or "the security property is
   absent" class of defect.
5. **F3.2** (Table 10.2 error selection) — larger, needs bond state plumbed
   into `struct att_conn`, but it is the top conformance gap and now has an
   oracle.
6. The mechanical libmesh dead-export check, before any further mesh feature
   work, because it changes what "done" means for everything after it.
