# Bluetooth Mesh: 5BSD against BlueZ, Zephyr and NimBLE

The fifth external-reference sweep, and the first with the mesh specifications
actually in the tree. The earlier sweeps covered ATT/SMP/GAP
(`bluetooth-interop-comparison.md`), the HCI controller interface
(`bluetooth-interop-hci.md`), HID over GATT (`bluetooth-interop-hogp.md`) and
L2CAP/EATT/ISO (`bluetooth-interop-l2cap-iso.md`). Each found real
interoperability defects, several of which three prior rounds of reviewing our
own code had not surfaced. Conformance tracing puts Mesh Model at 0.7% covered
and Mesh Protocol at 8.3% — the lowest in the stack, and the largest area not
yet swept this way.

Nothing in `lib/`, `usr.sbin/` or `sys/` was changed while this was written; it
is reconnaissance. No existing test was modified.

## Scope

Five areas, in the order the ranked gap analysis expected value from them:

1. The foundation models — the Configuration Server message-handling matrix.
2. The access layer — opcode encoding, application key selection, virtual
   addresses and label UUIDs, dispatch into models.
3. The upper and lower transport layers — segmentation and reassembly, block
   acknowledgement, segment-acknowledgement timing, the Friend queue.
4. The network layer — nonces, obfuscation, the NID, relay and forwarding.
5. Key Refresh, IV Update and replay protection.

Provisioning is **deliberately out of scope**. A separate effort was adding
certificate-based provisioning and provisioning-records transfer to
`mesh_provision.c`, `mesh_provisioner.c` and `mesh_remote_prov.c` while this
was written, and those files were not read.

## What changed since the last mesh reading

The mesh section of `bluetooth-interop-comparison.md` opened by noting that
"Mesh has no specification in this tree, so the reference basis is different"
— it adjudicated entirely from BlueZ and Zephyr source. Two of the existing
oracle headers, `spec_extref_mesh_vectors.h` and
`spec_extref_mesh_iv_recovery.h`, open with the same disclaimer and an explicit
anti-drift contract built around not having the document.

That constraint is gone. `/usr/src/bluetooth-specs/` now holds
`MshPRT_v1.1.1.txt` (Mesh Protocol, 48224 lines) and `MshMDL_v1.1.1.txt` (Mesh
Model, 23683 lines), and everything below is adjudicated against the
specification text directly, with the reference implementations used to
establish what the ecosystem actually does rather than to stand in for the
document.

**One structural fact about the 1.1 specifications is worth stating up front,
because getting it wrong wastes a day.** In Mesh 1.1 the foundation models were
moved *out* of the Model specification and *into* the Protocol specification.
The Configuration Server model is **MshPRT §4.4.1**; the configuration messages
are §4.3.2; the status code table is §4.3.14 / Table 4.308. `MshMDL_v1.1.1.txt`
contains only the generic, sensor, time/scene and lighting models and defines
none of it — `grep -ni netkey MshMDL_v1.1.1.txt` returns nothing. Several of
our own code comments still cite `MshMDL` for foundation-model behaviour; they
are all stale (see "Comment audit" below).

## Reference implementations obtained

| Stack | Source | Snapshot commit | Role |
| --- | --- | --- | --- |
| BlueZ 5.87 | `git.kernel.org/pub/scm/bluetooth/bluez.git` | `92305dc06ab8a6d89af2dae1d725cc4d51462ad1` | the dominant Linux peer; `mesh/` is a full userspace stack |
| Zephyr | `github.com/zephyrproject-rtos/zephyr` | `2665fcca3cced3aefb7202d6289991d8cc1dfcac` | PTS-qualified; the most complete Mesh 1.1 implementation available |
| Apache NimBLE | `github.com/apache/mynewt-nimble` | `1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845` | a third reading, but see the caveat below |

Adjudicating text: `/usr/src/bluetooth-specs/MshPRT_v1.1.1.txt` and
`MshMDL_v1.1.1.txt`.

### What each reference actually implements — verified, not assumed

The Subnet Bridge experience from the previous sweep — where BlueZ turned out
to have nothing at all, and that changed how the reading had to be done —
applies here repeatedly. The inventory was established by reading the trees
before any comparison was made:

| Feature | BlueZ 5.87 | Zephyr | NimBLE |
| --- | --- | --- | --- |
| Configuration Server | yes (`mesh/cfgmod-server.c`) | yes (`cfg_srv.c`) | yes (`cfg_srv.c`) |
| Node Identity **Set** | **no** — falls through to Get | yes | yes |
| Subnet Bridge | **no** (zero files match "bridge") | yes (`brg_cfg_srv.c`, `brg_cfg_cli.c`) | **no** |
| Directed Forwarding | **no** | **no** | **no** |
| SAR Configuration (Mesh 1.1) | **no** — SAR is 1.0-shaped, in `mesh/net.c` | yes (`sar_cfg*.c`) | **no** |
| Virtual address module | in `mesh/model.c` | yes, dedicated (`va.c`, `va.h`) | thin, no `va.c` |
| Mesh Private Beacon | yes (`prvbeac-server.c`) | yes (`priv_beacon_srv.c`) | **no** |
| Solicitation PDU / On-Demand Proxy | **no** | yes (`solicitation.c`) | **no** |
| Opcodes Aggregator | **no** | yes (`op_agg*.c`) | **no** |
| Remote Provisioning | yes (`remprv-server.c`) | yes (`rpr_srv.c`) | **no** |

Three consequences shape the whole document:

- **For Directed Forwarding there is no reference implementation anywhere.**
  Our `mesh_df.c` is 1995 lines of a feature none of BlueZ, Zephyr or NimBLE
  has attempted. Every DF finding below is adjudicated from specification text
  alone, and is labelled as such.
- **For Subnet Bridge, Zephyr is the only reference.** Our implementation is
  the more complete of the two remaining stacks that have one.
- **NimBLE's mesh is Mesh 1.0-era throughout**, and its access-layer
  `get_opcode()` is character-for-character identical to Zephyr's, comment
  included. It is a common ancestor, not an independent reading, and is
  weighted as one reference with Zephyr wherever the two agree by descent.

### A note on line numbers

Citations into `lib/libmesh/mesh_sim.c` and
`usr.sbin/bluetooth/meshd/meshd_node.c` were taken while the concurrent
provisioning work was editing both files. The *behaviours* described are
current; the line numbers in those two files specifically may have drifted by
the time this is read. Every other cited file was untouched during the sweep.

### An architectural fact that decides whether these are shipping bugs

`meshd_node.c` has no segmentation, reassembly or network-layer engine of its
own. It calls `mesh_sim_send_access*()` / `mesh_sim_send_upper()` and receives
through `mesh_sim_node_recv*()`. Despite the name, **`mesh_sim.c` is the
production transport and network engine**, not a test harness. A defect found
in `mesh_sim.c` is a shipping defect.

## Classification key

Same as the previous documents.

- **OURS-WRONG** — the spec, or the unanimous practice of the references,
  contradicts us.
- **OURS-RIGHT-OTHERS-DIFFER** — we match the spec and at least one reference
  does not. Recorded so nobody "fixes" us towards the reference.
- **ECOSYSTEM-SPLIT** — the references disagree and the spec does not settle it.
- **SPEC-ONLY** — no reference implements the feature; adjudicated from the
  document alone.
- **AGREE** — checked, no divergence.

---

## Ranked findings

Ranked by what actually happens against a phone provisioner or a commercial
mesh node, not by theoretical conformance.

| # | Area | Finding | Class | Impact |
| --- | --- | --- | --- | --- |
| 1 | Network | a PDU received under friendship credentials is relayed under those same credentials instead of managed flooding | OURS-WRONG | every message a Low Power node sends is relayed encrypted under a key only its Friend holds; **LPN uplink traffic never reaches the network** |
| 2 | Transport | a Segment Acknowledgment carrying OBO=1 is rejected because the matcher requires `stored_dst == ack_src` | OURS-WRONG | **no segmented message we send to any LPN ever completes**; the ack comes from the Friend's address |
| 3 | Access | the model AppKey-binding check is skipped entirely for any model with no Config-installed binding list | OURS-WRONG (security) | on a keyed-but-unconfigured node, any holder of any AppKey can drive every model on the element |
| 4 | Key refresh | the AppKey old/new pair does not exist; the new key overwrites the old at Phase 2 | OURS-WRONG | application traffic is silently undecryptable for the whole of Phase 2 in every mixed-progress key refresh |
| 5 | Key refresh | a Friend Update drives the Key Refresh phase machine with no "authenticated under the new key" gate | OURS-WRONG (security) | the first Friend Update after a NetKey Update collapses an LPN to Phase 3 and revokes a key the network is still using |
| 6 | Access | virtual-address dispatch matches on the 14-bit hash after correctly proving which Label UUID authenticated | OURS-WRONG (security) | two colliding labels deliver to the wrong model; the collision is 2^-14 per pair and an attacker can simply search for one |
| 7 | Network | friendship-credential PDUs are dropped when the Relay feature is disabled | OURS-WRONG | a Friend with Relay off — a normal, legal configuration — black-holes its LPN |
| 8 | Network | fixed group destination addresses are never matched on receive | OURS-WRONG | a Friend Request (DST = all-friends) is not delivered by the network layer; all-relays and all-proxies are unreachable |
| 9 | Access | group and virtual delivery reaches every model on an element once any one model there subscribes | OURS-WRONG | a group Set aimed at one model fires OnOff, Level and Lightness together on the primary element |
| 10 | IV update | ordinary beacon-driven IV Update is misrouted through IV Index Recovery | OURS-WRONG (security) | bypasses the 96-hour dwell that protects against IV runaway, and burns the once-per-192-hours recovery credit on every routine update |
| 11 | Transport | the Friend Queue excludes all Control PDUs and permanently drops segmented messages | OURS-WRONG | our LPN can never receive a segmented message or a Segment Ack for its own outbound transfers |
| 12 | Transport | a Segment Acknowledgment is emitted per received segment; no SAR Acknowledgment timer exists | OURS-WRONG | a 32-segment transfer produces 32 acks instead of one or two — the classic ack storm that kills large transfers |
| 13 | Transport | a Low Power node sends Segment Acknowledgment messages | OURS-WRONG | races its own Friend's OBO ack and burns the radio time an LPN exists to save |
| 14 | Transport | OBO is never set when acknowledging as a Friend | OURS-WRONG | the mirror image of #2: a conformant peer rejects our Friend's ack |
| 15 | Config / pub | Model Publication Status echoes the requested parameters on failure instead of zeroing them | OURS-WRONG | unanimous across all three references and explicit in the spec; every negative publication test misreports |
| 16 | Config / HB | Heartbeat Publication CountLog 0x11 decodes to 0xFFFF, so a Set of 0x11 answers 0xFF | OURS-WRONG | a bounded 65534-message heartbeat becomes an unbounded one, visible in the very next Status |
| 17 | Transport | no multicast SAR retransmission — a segmented message to a group is sent exactly once | OURS-WRONG | single-shot large payloads on an unreliable advertising bearer; silent loss |
| 18 | Network | directed security material `k2(NetKey, 0x02)` is never derived; DF traffic uses flooding credentials | OURS-WRONG, SPEC-ONLY | our Directed Forwarding interoperates only with itself |
| 19 | Config / pub | publication AppKeyIndex is validated node-wide and never against the model's own bindings | OURS-WRONG | set-publication-before-bind returns Success and then never publishes |
| 20 | Config / keys | NetKey Delete refuses to remove the primary subnet even when a different subnet secured the request | OURS-WRONG | blocks a legitimate multi-subnet retirement flow no other stack refuses |
| 21 | Config / keys | AppKey Add rebind answers Invalid Binding (0x11) where spec and all three references say Invalid NetKey Index (0x04) | OURS-WRONG | wrong status on a PTS-checked cell |
| 22 | Config / keys | NetKey Update answers Success in Phase 2, and for a key equal to the current key | OURS-WRONG | a Configuration Manager gets a false Success on a key it did not distribute |
| 23 | Transport | an older SeqAuth from a source opens a fresh reassembly instead of being ignored; multiple concurrent reassemblies per source are allowed | OURS-WRONG | resource exhaustion from one replaying peer; a stale partial transaction can be resurrected |
| 24 | Config / HB | Heartbeat Publication Status on failure reports the stored state rather than the incoming message | OURS-WRONG | the exact opposite of the Model Publication rule — we have both backwards |
| 25 | Transport | "Message Rejected" never emits BlockAck = 0, though we honour it on receive | OURS-WRONG | out of reassembly slots, the peer burns its whole retransmission budget instead of aborting |
| 26 | IV update | a beacon authenticated on a secondary subnet can advance the primary IV Index | OURS-WRONG (security) | a lower-trust guest subnet key can drive a whole-network resource |
| 27 | IV update | the LPN Friend-Update path bypasses the recovery wrapper entirely | OURS-WRONG | the one class of device the spec designates as the recovery path is the one that cannot recover |
| 28 | IV update | the transition out of IV Update is not deferred while a segmented transmission is unacknowledged | OURS-WRONG | any large transfer straddling the boundary has its SeqAuth invalidated mid-flight |
| 29 | Config / keys | Node Reset does not erase key material | OURS-WRONG (security hygiene) | defeats the purpose of retiring a compromised or resold node |
| 30 | Key refresh | friendship credentials are re-derived only at finalize, not at the Phase 1→2 transition | OURS-WRONG | friendship breaks for the duration of Phase 2 |
| 31 | Config / HB | Heartbeat Publication Get/Set does not zero the other fields when Destination is unassigned | OURS-WRONG | stale PeriodLog/TTL/Features read back for a disabled publication |
| 32 | Config / keys | Node Identity and Private Node Identity can both be Enabled at once | OURS-WRONG (privacy) | defeats Private Node Identity; a PTS PRB cell |
| 33 | Config / pub | Publish TTL 0x80–0xFE is accepted, stored and echoed | OURS-WRONG | we put a Prohibited value on the wire in our own Status |
| 34 | Config | status codes 0x07 "Invalid Publish Parameters" and 0x08 "Not a Subscribe Model" are never emitted | OURS-WRONG | Config Model Subscription Add against the Configuration Server model itself returns Success |
| 35 | Config / keys | NetKey Delete does not disable a Heartbeat Publication bound to the deleted subnet | OURS-WRONG | dangling state; heartbeats continue on the wrong subnet |
| 36 | Config | status codes 0x12–0x15 are undefined while the Directed Forwarding messages that need them are implemented | OURS-WRONG (gap) | the DF Config Server cannot report its spec-mandated errors |
| 37 | Network | the proxy solicitation nonce (0x04) and the Solicitation PDU do not exist, but the Solicitation PDU RPL Config Server does | OURS-WRONG (half-feature) | On-Demand Private GATT Proxy cannot be woken |
| 38 | Config | Key Refresh Phase Set always answers Success, including for transitions Table 4.31 does not define | OURS-WRONG | a Configuration Manager sequencing on the Status believes a phase advanced that did not |
| 39 | Replay | the RPL holds 16 entries with no eviction policy | OURS-WRONG (capacity) | source #17 is blackholed permanently, with no recovery short of reboot |
| 40 | Transport | transmission is not cancelled at SeqAuth + 8192; two concurrent segmented transactions to one destination are allowed; two of the four ack-validity conditions are unchecked | OURS-WRONG (minor) | correctness holes at sequence-number churn |
| 41 | Config / DF | PATH_ECHO_INTERVAL 0xFF "no change" is stored as the state; Wanted Lanes 0x00 and prohibited two-way-path bits are accepted | OURS-WRONG, SPEC-ONLY | DF configuration state diverges from what a client set |
| 42 | Network | the Network Message Cache is not keyed on the NetKey index | OURS-WRONG (minor) | spec says "should"; ours substitutes IV Index, a different superset |
| 43 | Access | the access PDU parser bounds the parameters at 379 but not the total PDU at 380 | OURS-WRONG (strictness) | no memory-safety issue; the build side is correct, the parse side is lax |
| 44 | Network | `try_decrypt()`'s candidate array has exactly zero slack and is safe only by an unrelated `- 1` in a different expression | OURS-WRONG (latent) | relaxing a plausible-looking off-by-one overflows a stack array in the receive path |

### Ecosystem splits and places we are right

| # | Area | Finding | Class |
| --- | --- | --- | --- |
| S1 | Transport | Mesh 1.0 fixed SAR timing (BlueZ, NimBLE) vs Mesh 1.1 configurable SAR states (Zephyr). We ship the 1.1 *config model* over less-than-1.0 behaviour — the one combination the spec rules out | ECOSYSTEM-SPLIT, needs a product decision |
| S2 | Access | all-nodes delivery to every element (ours, and the spec's own Figure 3.72) vs primary element only (BlueZ and Zephyr) | ECOSYSTEM-SPLIT |
| S3 | Access | the 3-octet vendor opcode's numeric representation: little-endian CID (ours, Zephyr, NimBLE) vs byte-swapped CID (BlueZ). **The wire form is identical**; only the model-table constant differs | ECOSYSTEM-SPLIT — ours matches the spec's worked example byte for byte |
| S4 | Config / HB | Heartbeat Subscription MinHops after a disabling Set: 0x00 (ours) vs 0x7F (Zephyr, tuned to a named PTS case) vs collected value (BlueZ) | ECOSYSTEM-SPLIT — Zephyr's is the literal reading |
| S5 | Config | a Prohibited subscription Address: status 0x01 (ours, Zephyr) vs silent drop (BlueZ) | ECOSYSTEM-SPLIT — ours is the majority |
| S6 | Config / keys | AppKey Update with a different key already staged: 0x0B (ours) / 0x06 (Zephyr) / silent overwrite + Success (BlueZ) | ECOSYSTEM-SPLIT |
| R1 | Config / keys | the NetKey Delete securing-key rule — **BlueZ has no such check at all** and will delete the key that secured the request | OURS-RIGHT-OTHERS-DIFFER |
| R2 | Config / keys | the per-subnet 60-second Node Identity timer. BlueZ has no Node Identity Set whatsoever | OURS-RIGHT-OTHERS-DIFFER |
| R3 | Access | AppKey candidate selection filters on NetKey index as well as AID. BlueZ omits the NetKey filter | OURS-RIGHT-OTHERS-DIFFER |
| R4 | Config / keys | AppKey Add rolls back on crypto failure, so AppKey Get never lists a key the transport cannot use. No reference does this | OURS-RIGHT-OTHERS-DIFFER |
| R5 | Network | the Mesh Private beacon is implemented as one AES-CCM call, provably identical to the spec's hand-rolled B0/C0/C1 construction and cleaner than Zephyr's | OURS-RIGHT-OTHERS-DIFFER |
| R6 | Config | our Subnet Bridge is the most complete of the two stacks that have one, and matches Zephyr field for field | OURS-RIGHT-OTHERS-DIFFER |
| R7 | Network | the 29-octet PDU cap is enforced asymmetrically (12 control / 16 access), which prevents an overflow a symmetric cap would allow | OURS-RIGHT-OTHERS-DIFFER |

---

## 1. The network layer

The crypto primitives are **bit-exact against the specification's own sample
data**. `mesh_net.c`, `mesh_crypto.c`, `mesh_beacon.c` and `mesh_proxy.c` were
compiled standalone and reproduced the MshPRT §8 vectors exactly: Network PDU
#1, the Secure Network beacon of §8.4.4, the Mesh Private beacon of §8.4.6.1
and the proxy configuration message of §8.9.1. The k2 split from NetKey
`7dd7…c3d6` produced NID `68`, EncryptionKey `0953fa93e7caac9638f58820220a398e`
and PrivacyKey `8b84eedec100067d670971dd2aa700cf`, all three matching the
specification. The network nonce produced `00800000011201000012345678` and the
PECB `6ca487507564`, both matching.

Every network-layer defect below is in *forwarding and credential-selection
policy*, not in the primitives.

### 1.1 Relaying under friendship credentials — OURS-WRONG, #1

`mesh_sim.c`'s `try_decrypt()` returns the encryption key, privacy key and NID
of whichever credential authenticated the PDU, including the friendship
credential. The relay path then re-secures the outgoing copy with *those same*
credentials.

All three references rewrite the NID and re-encrypt with the managed flooding
credential. BlueZ says so in a comment — "If packet was encrypted with
friendship credentials, relay it using flooding credentials". Zephyr masks the
NID octet and substitutes the subnet's transmit credential. NimBLE does the
same.

MshPRT §3.6.6.2, .txt lines 6446-6448:

> OutMsg1 is sent secured using the friend security material and therefore only
> the Friend node will receive and relay this message. **When the Friend node
> relays OutMsg1, the message will be retransmitted using the managed flooding
> security credentials.**

And structurally: §3.4.6.3's Outbound Security Material column (.txt lines
4177-4182) offers exactly two values, "flooding" and "directed". There is no
row of Table 3.14 whose outbound material is friendship.

The consequence is total and silent. Every message an LPN sends reaches its
Friend, is relayed, and is then undecryptable by every other node in the
network, because only the Friend and that one LPN hold the friendship material.
It is invisible without a real Low Power node in the test.

### 1.2 Friendship PDUs dropped when Relay is off — OURS-WRONG, #7

The relay branch is gated on `node->is_relay`, and `mesh_relay_decide()`
returns 0 when the relay feature is disabled. There is no friendship exemption.

Zephyr's relay-disabled early return is explicitly `... && !rx->friend_cred &&
!bridge`, and its send condition is `relay_to_adv(...) || rx->friend_cred ||
bridge`. BlueZ returns `RELAY_ALWAYS` for friendship-credential PDUs with the
comment "Messages that are encrypted with friendship credentials should
*always* be relayed". NimBLE matches Zephyr.

Friend and Relay are independent features. A Friend node with Relay disabled is
a normal configuration, and today it black-holes its LPN's outbound traffic
entirely.

**One caution when fixing this.** BlueZ places its friendship exemption
*before* the `net_ttl < 0x02` check, so a friendship PDU with TTL 0 or 1
reaches a `ttl - 1` that underflows to 0xFF. Zephyr places the exemption after
the TTL gate. Follow Zephyr.

### 1.3 Fixed group addresses never matched on receive — OURS-WRONG, #8

`addressed_here()` accepts only `MESH_ADDR_ALL_NODES` (0xFFFF), a local unicast
address, or a model subscription. There is no constant for `all-relays`,
`all-friends`, `all-proxies` or `all-directed-forwarding-nodes` anywhere in
`lib/libmesh`.

Zephyr has `bt_mesh_fixed_group_match()` and calls it in the receive path.
BlueZ carries the addresses in `mesh-defs.h` and gates each on the
corresponding feature.

MshPRT §3.6.4.2, .txt lines 5435-5441:

> Upon receiving an Upper Transport Control PDU, the destination address of the
> PDU shall be checked. The PDU shall be processed according to the Transport
> Control opcode ... if one of the following conditions is met:
> • The destination address matches a unicast address of an element of the node
> • The destination address matches a fixed group destination address specified
>   in Table 3.28 and the corresponding condition (if any) is satisfied

Table 3.28 pairs each address with the feature that must be enabled:
all-directed-forwarding-nodes with DF, all-proxies with Proxy, all-friends with
Friend, all-relays with Relay, and all-nodes with no condition.

A Friend Request is addressed to all-friends, so today it cannot arrive through
the normal receive path. `meshd_node.c` papers over this with
`meshd_friendship_control_rx()`, which decrypts straight off the bearer — but
that bypass duplicates the entire credential-and-IV candidate loop, does not
consult the network message cache, and covers neither all-relays nor
all-proxies. Fixing `addressed_here()` would let both parallel decrypt loops in
`meshd_node.c` be deleted.

### 1.4 Directed security material never derived — OURS-WRONG, SPEC-ONLY, #18

`mesh_sim.c` contains exactly one k2 P input, `{ 0x00 }`. The friendship P
input is built correctly in `mesh_friend.c`. There is no `{ 0x02 }` anywhere.
DF forwarding and DF transmission both reuse the flooding credential that
decrypted the inbound PDU. A comment in `mesh_sim.c` admits it: "the directed
outbound rows (path bearers, directed credentials) are not implemented."

MshPRT §3.9.6.3.1, .txt lines 10264-10266:

> The directed security material is derived from the directed security
> credentials using the following formula:
> NID || EncryptionKey || PrivacyKey=k2(NetKey, 0x02)
> For Network PDUs that are transmitted according to directed forwarding
> functionality, the directed security material is used.

No reference implements DF, so there is no ecosystem cross-check. Our
path-forwarded PDUs carry the flooding NID; a conformant DF peer will select
the wrong credential, and we cannot decrypt its directed traffic. Given that
`mesh_df.c` is otherwise 1995 lines of serious work, this is the single
load-bearing gap in it.

### 1.5 Proxy solicitation — OURS-WRONG, #37

`mesh_crypto.c` defines nonce builders for types 0x00, 0x01, 0x02 and 0x03.
There is no 0x04, no solicitation nonce, and no Mesh Proxy Solicitation service
UUID 0x1859 anywhere. Yet `mesh_cfg_v11.c` implements the Solicitation PDU RPL
Configuration Server and `meshd_node.c` clears solicitation RPL ranges — the
management surface for a PDU we cannot produce or verify.

Zephyr has `create_proxy_sol_nonce()` and `solicitation.c`. BlueZ and NimBLE
have neither, so this is a half-feature rather than a conformance failure — but
it is a visible one.

**A trap for whoever implements it**, from Table 3.74 (.txt lines 10094-10134):
the proxy solicitation nonce is `0x04 || 0x00 || SSEQ(3) || SSRC(2) || six
octets of zero`. It carries **no IV Index**, unlike the otherwise
identically-shaped proxy nonce, and the specification says why at .txt line
34639: "The IV Index is not used to secure the Solicitation PDU." Copying
`mesh_proxy_nonce()` and changing the type octet produces a wrong nonce.

### 1.6 Smaller network-layer items

**Network Message Cache key (#42).** Ours is `(src, seq, iv_index)`. MshPRT
§3.4.6.5 .txt lines 4283-4285: "Values for the SRC, SEQ fields, **and index of
the NetKey used for decrypting PDU contents** should be stored in a cache
entry." Zephyr uses `(src, seq, net_idx)`; BlueZ `(src, seq, cookie)`; NimBLE
`(src, seq)`. Ours substitutes IV Index for NetKey index — a different
superset, better across IV changes and worse across subnets. The sentence is a
"should", so this is a nit; `try_decrypt` already returns the NetKey index, so
adding it is nearly free.

**Candidate array slack (#44).** `try_decrypt()`'s candidate array is sized
`MESH_SIM_MAX_SUBNETS * 2 + 1` = 9. The worst-case fill is 2 (primary Key
Refresh old+new) + 1 (friendship) + 2 × subnets, and it is safe *only* because
an unrelated cap elsewhere limits subnets to `MESH_SIM_MAX_SUBNETS - 1` = 3,
giving exactly 9. The bound and the guard are written in terms of different
expressions, and that `- 1` reads exactly like an off-by-one somebody will
"correct". Size it `+ 3`, or bound the loop.

**Dead branch.** A TTL range check tests `ttl > 0x7f` on a value that is 7-bit
by construction. `mesh_net_rpl_check()` is documented as deprecated, is not
IV-aware, and is still exported.

### 1.7 Network layer — verified in agreement

- **Network nonce** `0x00 || CTL|TTL || SEQ(3) || SRC(2) || 0x0000 || IV(4)`,
  all big-endian, matching BlueZ, Zephyr, NimBLE and Table 3.67, and byte-exact
  against the spec's own vector.
- **Application and device nonces**, with ASZMIC in bit 7 of octet 1, and the
  DST/TTL asymmetry of .txt lines 9887-9893 respected — TTL is in the network
  nonce and not the others, which is what lets a relay decrement it.
- **Proxy nonce 0x03**, byte-exact against the spec's vector.
- **Obfuscation** in both directions, using the *encrypted* payload as the
  Privacy Random on send and on receive, matching the four formulas at .txt
  lines 10482-10494 verbatim.
- **k2 output split**: NID from the low 7 bits, then 16 + 16 octets, with P
  appended every round.
- **Multiple subnets sharing a NID**: every matching credential is tried until
  one authenticates. .txt lines 3752-3756 require exactly this, and the NID is
  explicitly only "an indication" (.txt lines 10229-10232).
- **Friendship credential P input** `0x01 || LPNAddress || FriendAddress ||
  LPNCounter || FriendCounter`, all big-endian.
- **IV candidate set** `{current, current-1}` with the IVI bit cross-check.
- **Relay TTL rules**: TTL ≥ 2 to relay, decrement by one, never relay to a
  local unicast, cache suppression, and the relayed PDU keeps the received IV
  Index (.txt lines 4026-4029).
- **Own-SRC drop**, and **delivery independent of the relay decision** — a
  group PDU is both delivered and relayed.
- **Network Transmit versus Relay Retransmit** applied to originated and
  relayed traffic respectively, with `(steps+1) × 10 ms`.
- **Secure Network beacon**: BeaconKey from k1 with the "nkbk" salt, NetworkID
  from k3, the 8-octet AuthValue over Flags ‖ NetworkID ‖ IV Index, and the
  flags octet authenticated **as received** before RFU bits are masked
  semantically — which is subtly better than masking first, since masking first
  would let an attacker flip RFU bits without breaking the MAC.
- **Mesh Private beacon** implemented as a single AES-CCM call, provably
  identical to the spec's B0/C0/C1 construction (CCM flags 0x19 means Adata=0,
  M=8, L=2) and byte-exact against the spec's vector.
- **Subnet Bridge re-secures onto the target subnet's credential** — the very
  pattern that finding #1 is missing on the friendship path.
- **Proxy Configuration PDU** forces CTL=1 / TTL=0 / DST=0x0000 and rejects
  anything else on receive.
- **Endianness** everywhere on the wire, proven by four byte-exact vector
  reproductions rather than by inspection.

One thing checked and cleared, recorded so nobody re-derives it: BlueZ's
message cache compares a field named `mic`, which looks like a violation of
"a node shall not consider the NetMIC field value". It is not — the field is
populated from TTL-invariant material in both the control and access cases.

---

## 2. The transport layers

### 2.1 The OBO pair — OURS-WRONG, #2 and #14

These are one defect seen from two sides, and together they mean a 5BSD node
and any Low Power node cannot exchange a segmented message in either direction.

**Receiving an ack (#2).** The segment-ack matcher requires
`s->dst == pdu.src`. The parsed `obo` field is never consulted. An ack from a
Friend has the Friend's source address, not the LPN's, so it is dropped and we
retransmit every segment until the retry budget is exhausted.

MshPRT Table 3.24 "Conditions to validate a segment acknowledgment message",
.txt line 4898:

> Either the source address of the Segment Acknowledgment message matches the
> destination address value stored by the lower transport layer, **or the value
> of the OBO field of the Segment Acknowledgment message is 1.**

Zephyr's `seg_tx_lookup(seq_zero, obo, addr)` latches `tx->ack_src` on the
first OBO ack; NimBLE is the same. BlueZ matches on SeqZero alone and carries a
literal `TODO` about checking OBO — i.e. BlueZ is loose but working, and we are
strict and broken.

**Sending an ack (#14).** `send_seg_ack()` memsets the structure and never sets
`obo` on any path. There is in any case no Friend-side reassembly to set it
from (see #11).

MshPRT .txt lines 4882-4884:

> The OBO field shall be set to 0 by a node that is directly addressed by the
> received message and shall be set to 1 by a Friend node that is
> acknowledging this message on behalf of a Low Power node.

and .txt line 5154:

> If the device is acting as a Friend node for a Low Power node, then it shall
> reassemble segmented messages destined for the Low Power node and act as
> described, except that it shall set the OBO field to 1.

Zephyr sets `rx->obo = net_rx->friend_match` and sources the ack from the
primary address. BlueZ sets the OBO bit unconditionally in `send_frnd_ack()`.

This pair was reported in the previous sweep and both halves are still present.

### 2.2 A Low Power node sends acknowledgments — OURS-WRONG, #13

The only guard on the ack path is "is this destination one of my unicast
addresses". `node->is_lpn` is consulted only for a radio-asleep check.
`mesh_lpn.c` has no SAR logic at all; §3.5.3.5 is unimplemented.

MshPRT .txt line 4747:

> When the Low Power node feature is in use, reassembly is performed by a
> Friend node and the Low Power node does not send any Segment Acknowledgment
> messages.

Zephyr gates both the ack timer and `send_ack()` itself on
`!bt_mesh_lpn_established()`.

An LPN that acks directly races its own Friend's OBO ack — and since Zephyr
latches `ack_src` on the first OBO ack it sees, the originator's binding
becomes whichever arrived first.

### 2.3 No SAR Acknowledgment timer — OURS-WRONG, #12, and ECOSYSTEM-SPLIT S1

An acknowledgment is emitted synchronously for every accepted segment. There is
no delay, no SAR Segments Threshold, no SAR Acknowledgment Retransmissions
Count and no SAR Receiver Segment Interval Step. `meshd_sar_apply()` passes
three values into the engine; of the entire SAR Receiver composite state only
the discard timeout arrives. The other four receiver states are accepted over
the air, echoed in Status messages and persisted to disk — and wired to
nothing.

The correct timer, MshPRT §3.5.3.4 .txt line 5027:

> [min(SegN + 0.5, acknowledgment delay increment) * segment reception interval]

With the specification defaults that saturates: SegN 1 gives 90 ms, SegN 2
gives 150 ms, and SegN 31 also gives 150 ms. Past a small SegN the delay stops
growing, so a 32-segment transfer produces on the order of one acknowledgment.
Ours produces thirty-two. On a busy mesh that is the classic ack storm that
makes large transfers — firmware blobs, big Config lists — fail against real
hardware.

Two further rules are unimplemented: the retransmission of acknowledgments when
SegN exceeds the SAR Segments Threshold (.txt line 5138), and the rate limit on
re-acking an already-complete SeqAuth (.txt line 5053).

**This is also the ecosystem split.** Zephyr implements the Mesh 1.1
configurable SAR states in `sar_cfg*.c`. BlueZ 5.87 and NimBLE are Mesh 1.0-era
with fixed timing — BlueZ acknowledges only when the arriving segment is the
largest outstanding one, plus a flat 2-second inter-segment timeout; NimBLE
uses `150 + 50×TTL` ms. We have the 1.1 configuration *model* over behaviour
that is weaker than either 1.0 implementation.

That specific combination is the one the specification rules out. MshPRT .txt
line 15029 (and identically for the transmitter at line 14915):

> The node shall implement the SAR Receiver independently of the presence of
> the SAR Configuration Server model.

The states are mandatory; only the model that lets a provisioner change them is
optional. **This one needs a product decision**: either implement the 1.1 SAR
states properly, or withdraw the SAR Configuration Server so a provisioner is
not lied to. Shipping both as they stand is the worst of the three options.

### 2.4 The Friend Queue — OURS-WRONG, #11

Three separate problems in one mechanism.

- **Control PDUs are excluded.** Both engines gate enqueue on `ctl == 0`, so no
  Transport Control PDU is ever queued for an LPN. That includes Segment
  Acknowledgment messages destined for the LPN's own outbound transfers.
- **Segmented messages are permanently undeliverable.** One path sets a
  `segmented` flag from the transport header, and the Friend layer drops any
  entry with it set. No caller anywhere presents a *reassembled* segmented
  message, so the drop is unconditional.
- **The other engine has the inverse bug**: it never sets the flag, so raw
  individual segments are queued and shipped to the LPN as if each were a whole
  message.

MshPRT .txt line 5237:

> The Friend Queue stores **Lower Transport PDUs** for a Low Power node. No
> field of the Lower Transport PDU shall be changed... The **CTL**, TTL, SEQ,
> SRC, and DST fields shall be stored

.txt line 5251:

> If the message is a Segmented Access message or a Segmented Control message,
> then the message shall only be stored into the Friend Queue **after** the
> complete Upper Transport PDU has been successfully reassembled and the Friend
> node has acknowledged the reception of all segments.

.txt line 5263 adds a Segment-Ack de-duplication rule for the queue that is
moot for us, since no Segment Ack ever reaches it.

Zephyr's `bt_mesh_friend_enqueue_rx()` takes every matching PDU regardless of
CTL, types each as PARTIAL or COMPLETE, and does the reassembly Friend-side.
BlueZ reassembles in `friend_seg_rxed()` and enqueues only after sending the
full OBO ack.

### 2.5 No multicast retransmission — OURS-WRONG, #17

`sar_tx_record()` refuses to track a transaction whose destination is not
unicast, so segments of a group-addressed or virtual-addressed segmented
message are transmitted exactly once. The SAR Multicast Retransmissions Count
and Interval Step states are unimplemented.

MshPRT .txt line 4795 requires the transmitter to store the destination, the
SeqAuth and a remaining-retransmissions count for a multicast transaction, and
.txt line 4952 requires the whole set of segments to be repeated when the
multicast timer expires. Zephyr and NimBLE both make the retransmit count and
timeout destination-dependent.

There is no acknowledgment for a multicast transaction, so the retransmission
count is the *only* reliability mechanism it has. Without it, every large scene
or lighting payload to a group is a single shot on an unreliable advertising
bearer.

### 2.6 Reassembly session management — OURS-WRONG, #23

`reasm_session()` keys on `(src, seqauth, iv, ctl)` across a fixed slot array
and hands back a free slot for *any* SeqAuth, older or newer. There is no
comparison against a stored Sequence Authentication value, so a stale or
replayed older-SeqAuth segment opens a fresh session; the only backstop is the
replay list.

BlueZ keeps exactly one reassembly per remote and compares explicitly —
`newer = seqAuth > sar_in->seqAuth`, cancelling the old one or ignoring the new
one. Zephyr does the same and additionally checks the RPL.

MshPRT Table 3.25 makes a lower SeqAuth for an unreceived message a "SeqAuth
Error", and .txt line 5048 says "the lower transport layer shall ignore the
message". .txt lines 5016-5019 require that a new reassembly for the same
(source, destination) *discard* any pending one rather than run alongside it.

### 2.7 Rejection is silent — OURS-WRONG, #25

We honour BlockAck = 0 correctly on receive, treating it as "abandon" rather
than "resend everything". We never *send* it: running out of reassembly slots
returns silently.

MshPRT .txt line 4993:

> When the Processing Result is Message Rejected and the message is destined to
> a unicast address, the lower transport layer shall respond with a Segment
> Acknowledgment message with the AckedSegments field set to 0x00000000.

Zephyr sends it in three out-of-resource cases: SDU too large, no Friend Queue
space, assembled length too large. Ours makes the peer burn its full
retransmission budget — and seconds of air time — before giving up.

### 2.8 Retransmission timing — OURS-WRONG, #40 and related

The unicast retransmission interval is a single flat value with no TTL term,
and there is no separate "without progress" budget.

MshPRT .txt line 4828 gives the interval as

> [unicast retransmissions interval step + unicast retransmissions interval
>  increment * (TTL − 1)]

With the specification defaults and a 5-hop TTL that is 400 ms, twice the flat
200 ms. .txt line 4873 requires the no-progress budget to be *reset* whenever a
retransmission newly acknowledges a segment, and decremented otherwise —
Zephyr keeps `attempts_left` and `attempts_left_without_progress` separately
and terminates on either. Multi-hop transfers to distant nodes therefore retry
too fast and abandon too early.

Three smaller holes in the same area:

- Transmission is not cancelled when SEQ reaches SeqAuth + 8192 (.txt line
  4732), which the 13-bit SeqZero field makes mandatory.
- Two concurrent segmented transactions to the same destination are allowed;
  .txt line 4767 forbids it.
- Two of the four Table 3.24 acknowledgment-validity conditions are unchecked:
  "at least one unacknowledged segment that the AckedSegments field reports as
  delivered", and "secured using the same NetKey".

### 2.9 A hardcoded ack TTL, and a comment that invents a rule

Segment acknowledgments go out with a fixed default TTL of 5. The comment above
that code claims MshPRT §3.5.3.4 requires "a fresh default TTL rather than the
residual (already decremented) received TTL". §3.5.3.4 says no such thing. What
it does say, at .txt line 4570, is the opposite lean:

> If the received segments were sent with the TTL field set to 0, it is
> recommended that the corresponding Segment Acknowledgment message is sent
> with the TTL field set to 0.

Zephyr passes the sender's TTL through, so a TTL-0 segment gets a TTL-0 ack.
BlueZ uses a default, as we do. It is only a "recommended", so this is low
impact — but a strictly single-hop exchange with a phone currently has its acks
relayed five hops across the whole mesh.

### 2.10 Transport — verified in agreement

- The 4-octet segmented header bit layout, bit-identical to Zephyr's unpack and
  to Tables 3.19 and 3.23.
- 12-octet access and 8-octet control segment payloads, with non-final segments
  required to be exactly full.
- SegO > SegN rejected; 32 segments maximum.
- SeqZero as the low 13 bits of SeqAuth, with the 0x2000 borrow on
  reconstruction — verified against both of the specification's own worked
  examples at .txt lines 4725-4730.
- The sequence number incremented per segment on first transmission *and* on
  retransmission, which is what stops the relay message cache from eating
  retransmissions.
- Invariant header fields enforced across a reassembly session.
- Duplicate segments accepted idempotently without touching the buffer.
- No acknowledgment to a group or virtual destination.
- Re-acknowledgment of a completed SeqAuth without re-delivery.
- BlockAck bits above SegN masked on receipt.
- The SAR Discard timer, defaulting to the specification's 10 seconds.
- Ack DST set to the SRC of the received segments.
- Friend Queue TTL ≥ 2 gating, TTL decremented on store, the LPN's own source
  excluded, de-duplication on (IV, SEQ, SRC), oldest-first eviction that spares
  Friend Updates, and Friend Poll returning the oldest entry with a synthesized
  Friend Update on an empty queue.
- Friendship credentials used for Friend→LPN delivery and explicitly *not* used
  for third-party Segment Acks — which is the correct instinct, and makes the
  network-layer relay defect (#1) all the more striking.
- Queued entries re-secured at the enqueue-time IV Index, which is slightly
  better than BlueZ, which re-stamps with the live index.

---

## 3. The access layer

### 3.1 Virtual addresses: authenticated by label, dispatched by hash — OURS-WRONG, #6

The receive path does the hard part correctly: it tries each subscribed Label
UUID as the CCM additional data until the MIC verifies, exactly as BlueZ and
Zephyr do. It then **discards the winning label** and dispatches on the 16-bit
address, re-deriving `mesh_virtual_addr(label)` and comparing hashes. The
receive-context structure has no field for the label at all.

MshPRT §3.4.2.3, .txt lines 3341-3343:

> The virtual address is a 16-bit value that has bit 15 set to 1, bit 14 set to
> 0, and bits 13 to 0 set to the value of a hash. This hash is a derivation of
> the Label UUID such that **each hash represents many Label UUIDs**.

and .txt lines 3349-3351:

> When an Access message is received to a virtual address that has a matching
> hash, **each corresponding Label UUID** is used by the upper transport layer
> as additional data as part of the authentication of the message until a match
> is found.

Zephyr records the winning UUID on the receive context and resolves the
destination with `bt_mesh_model_find_uuid()` — an exact label match. BlueZ's
`virt_packet_decrypt()` returns the matching `struct mesh_virtual *` and
`forward_model()` matches subscriptions against that object.

The specification's own collision note (.txt lines 3374-3376) bounds at 2^-46
the chance that two labels produce both a matching hash *and* a passing 32-bit
MIC. That is a bound on the *combined* event. The hash collision alone is
2^-14 per pair — routine in a large deployment, and trivially forced by an
adversary who searches for a Label UUID hashing onto an address already in use.
The MIC is what makes a collision harmless, and the MIC only helps if the label
that passed it is the label used to route.

### 3.2 The AppKey binding check fails open — OURS-WRONG, #3

The check is guarded by a `bindings_configured` flag, and when that flag is
zero the check is skipped entirely and the handler runs. The flag is set only
for models that have a database entry — so on a freshly provisioned node with
an AppKey added but no Model App Bind yet, it is zero on **every** model. The
same fail-open is duplicated on the application-surface matcher.

Zephyr calls `bt_mesh_model_has_key()` unconditionally and answers
`ACCESS_STATUS_WRONG_KEY`. BlueZ's check is likewise unconditional.

MshPRT .txt lines 2584-2586:

> The granularity of access layer security is on a per-model basis. Each model
> defines whether a device key, a set of application keys, or both can be bound
> to the model. The bound keys encrypt and authenticate a message for the model
> to process...

and Figure 3.72's flow: "Has the Model a matching AppKey bound?" → "No" → "Drop
the Message".

On a keyed-but-unconfigured node, any holder of any AppKey can drive Generic
OnOff Set, Light Lightness Set, Scene Recall and everything else on models
nobody bound that key to. Combined with #9 the reach is every model on the
element.

### 3.3 Subscription matching is per-element, not per-model — OURS-WRONG, #9

The per-model subscription check has the same "unconfigured means yes" escape,
and element addressing consults an element-level union of subscriptions
populated from *any* model on that element. So once one model subscribes to
group G, every other model on the element receives G too. There is also a
blanket bypass for 0xFFFF.

MshPRT .txt line 3396:

> A Network PDU sent to a group address shall be delivered to all the instances
> of **models that subscribe** to this group address.

Zephyr requires `bt_mesh_model_find_group()` per model. BlueZ searches each
model's own subscription queue.

The practical result is cross-model state corruption on the common multi-model
primary element — OnOff Server, Level Server, Lightness Server and the Setup
Server all firing on a group Set aimed at one of them.

### 3.4 One key per AppKey index — OURS-WRONG, #4

The application key structure holds a single 16-octet key and one AID, so the
receive selection loop can only ever try one key per index. The daemon stages
an updated key in its own database but pushes it into the engine only at the
Phase 2 promotion, which *overwrites* the old one.

MshPRT .txt lines 11290-11291 (Phase 1) and 11331-11333 (Phase 2) both require
receiving on old **and** new. BlueZ tries `old_key` then `new_key` for every
AppKey whose AID matches; Zephyr keeps `keys[0]` and `keys[1]` and selects on
which NetKey credential decrypted the network layer.

This is the access-layer face of finding #4 in the ranked table; the
configuration-layer face is in §4.3.

### 3.5 Access layer — the vendor opcode split, and why we are right

Our encoder writes the 3-octet vendor opcode's company identifier
little-endian; our decoder reads it back the same way. That produces exactly
the specification's worked example (MshPRT .txt lines 8873-8874):

> For example, when the manufacturer-specific opcode is equal to 0x23 and the
> company identifier is equal to 0x0136, then the 3-octet opcode is equal to
> 0xE3 0x36 0x01.

Zephyr and NimBLE agree, with the comment "Using LE for the CID since the model
layer is defined as little-endian in the mesh spec". BlueZ uses a big-endian
16-bit read and write on the same two octets.

**This is an internal-representation split, not a wire split, and it is worth
being precise about because BlueZ looks buggy and is not.** BlueZ's 32-bit
opcode key holds the CID octets in *wire* order (0xE33601); ours and Zephyr's
hold the CID as a *number* (0xE30136). Both round-trip their own encode/decode
pair and both put the same three octets on the wire. What differs is the
constant a model table has to be written with. A stack that borrows model-table
constants from one project while decoding like the other silently fails to
dispatch every vendor opcode. In BlueZ's case the vendor branch is effectively
dead code — the only callers are SIG opcodes from `cfgmod-server.c`.

Do not "fix" ours toward BlueZ.

### 3.6 The all-nodes split — ECOSYSTEM-SPLIT, S2

We deliver an all-nodes message to every element and every model. Zephyr
delivers to the primary element unless a non-primary element explicitly
subscribes, with the comment "All models on the primary element should receive
the message". BlueZ breaks out of the element loop after the first.

The specification is genuinely ambiguous. Figure 3.72 reads "Is DST Broadcast?
Yes → Deliver to All Elements", which is ours. But .txt lines 2233-2235 say the
fixed group addresses "address a subset of all **primary elements** of nodes".

On multi-element nodes ours produces N× dispatch where the references produce
1×, which shows up as duplicate status replies against certified stacks. Worth
noting too that we special-case only 0xFFFF; 0xFFFC, 0xFFFD and 0xFFFE fall
through to the group-subscription path and therefore get the *opposite*
treatment. That internal inconsistency is worth resolving regardless of which
side of the split we land on.

### 3.7 Smaller access-layer items

**PDU length bound (#43).** The parser caps the parameters at 379 but not the
total at 380, so a 3-octet-opcode PDU of 382 octets parses. The build side is
correct. MshPRT .txt lines 8800-8803 give 379 / 378 / 377 for the three opcode
forms. No memory-safety issue; a strictness gap.

**64-bit TransMIC.** `mesh_upper_encrypt()` permits an access length of 380
regardless of SZMIC, where a 64-bit MIC caps it at 376. Currently unreachable
because every transmit path hard-codes SZMIC = 0 — **we never emit a 64-bit
TransMIC at all**, which both BlueZ and Zephyr support. Worth recording as an
unimplemented option; if it is ever enabled, tighten that bound first.

**SIG models and 3-octet opcodes.** Zephyr explicitly short-circuits SIG model
lookup for 3-octet opcodes, with the comment "SIG models cannot contain 3-byte
opcodes". We compare numeric opcodes only. Harmless in practice, since the CID
is baked into the numeric value, but there is no structural guard.

**A stale comment.** `mesh_access.h` says "big-endian on the wire for
multi-octet SIG opcodes" while §3.7.1 says all multi-octet numeric values in
this layer are little-endian. The *code* is right — opcodes are an octet array,
not a numeric value, and the 2-octet form is big-endian on the wire in all
three references — but the comment invites a wrong "fix".

### 3.8 Access layer — verified in agreement

- **Virtual address derivation**: `s1("vtad")` salt, AES-CMAC over the label,
  `0x8000 | (be16(hash[14..15]) & 0x3FFF)`, byte-identical to Zephyr.
- **Label-collision resolution at the upper transport** — the authentication
  half of #6 is correct; only the dispatch half is broken.
- **Opcode length classification, the 0x7F reserved value, and truncation
  rejection** — identical to all three references and to Table 3.63.
- **AID and AKF packing**, with `aid > 0x3f` rejected on build, and the receive
  loop trying **all** matching keys rather than the first.
- **The NetKey-index filter on AppKey candidates** — ours and Zephyr's; BlueZ
  omits it, and MshPRT .txt lines 2581-2582 ("An application key can only be
  used with a single network key on a node") supports the stricter reading.
- **Device-key messages restricted to a unicast destination**, matching Table
  3.10 and Zephyr's explicit citation of it.
- **Local-then-remote device-key trial order** — Zephyr reverses it for
  provisioner reasons; both are conformant since the MIC arbitrates.
- **The unsegmented/segmented decision at 15 octets**, and the structural
  enforcement that an unsegmented access message always uses a 32-bit TransMIC
  (Table 3.18's "as if the SZMIC field has the value 0").
- **Maximum access payload of 380**, with 379 / 378 / 377 for the three opcode
  forms on the build side.
- **Model identifier encoding**: 2 octets for SIG, 4 for vendor with the
  Company Identifier first, both little-endian, and any other length rejected.
- **Dispatch to all matching models rather than stopping at the first.** This
  is the spec reading and matches BlueZ. Zephyr stops at the first model in an
  element carrying the opcode — a Zephyr simplification, not something to copy.

---

## 4. The Configuration Server

### 4.1 Key management

**AppKey revoked at Phase 2 (#4).** The promotion at the Phase 1→2 transition
copies the new key over the old and clears the staged flag. MshPRT .txt lines
11245-11248: "The nodes will therefore start to transmit using the new key, Key
A2, but will **also receive from the old and new keys**. Finally, Phase 3
(Revoke Old Keys) will revoke the old keys." Zephyr revokes only on
`BT_MESH_KEY_REVOKED`, i.e. Phase 3. The code carries an honest "Known
limitation" comment naming exactly this. During Phase 2 — which a Configuration
Manager may hold open for hours while it reaches Low Power nodes — we cannot
decrypt application traffic from any peer that has not yet advanced.

**NetKey Delete over-restriction (#20).** We refuse to delete a NetKey if it is
either the one that secured the request *or* the primary. The specification's
only deletion prohibition, .txt line 24107: "A NetKey shall not be deleted from
the NetKey List using a message secured with this NetKey." Zephyr and NimBLE
check only `ctx->net_idx == del_idx`. Note that check *automatically* satisfies
the "at least one NetKey" rule, since a Config message must be secured with a
key in the list. The extra primary-key test is justified in a comment by an
internal engine limitation, which is an implementation constraint surfaced as a
protocol error. Adding a second subnet and retiring the original over the new
one is a supported flow; no other stack refuses it.

**AppKey Add rebind status (#21).** We answer Invalid Binding (0x11). Table
4.317 at .txt lines 24146-24147: "The key identified by the AppKeyIndex is
already bound to a different NetKeyIndex for a Config AppKey Add message →
Invalid NetKey Index". BlueZ, Zephyr and NimBLE all answer 0x04. Note 0x11's
own row is explicitly scoped "for a Config AppKey **Update** message" — and our
Update path uses it correctly. Only Add is wrong.

**NetKey Update legality (#22).** Our phase test is a proxy — "do I have a
staged key?" — and a staged key persists into Phase 2. So NetKey Update in
Phase 2 carrying the staged key returns Success, and NetKey Update carrying the
*current* key returns Success in every phase. MshPRT .txt lines 11257-11267
give two conditions, each a conjunction of a phase test and a key-value test,
and end "Otherwise, the Config NetKey Update message shall generate an error."
Zephyr switches on the phase explicitly; BlueZ guards its shortcut on
`kr_phase == PHASE_ONE`. (BlueZ has its own bug here: it never compares against
the current key in Phase 0, so a re-sent identical key starts a Key Refresh.)

**Node Reset (#29).** The handler marks the node unprovisioned and clears the
in-memory database but never touches the engine state holding the NetKey,
subnet keys, AppKeys and DevKey. §3.11.7 requires deletion of all stored
security credentials, all security material, the device key and the
provisioning data.

One thing our design gets right and a naive fix would break: our reply builder
fills a caller-owned buffer and the sealing happens afterward, so we do not
lose the ability to send the Status. Both references solve the same ordering
with an explicit deferral — BlueZ with an idle callback whose comment reads
"Delay node removal to give it a chance to send the status", Zephyr with a
`reset_send_end` work item. **If this is fixed, adopt that deferral** or the
Status response breaks.

**Node Identity and Private Node Identity (#32).** The two Set handlers are
independent; both states can be Enabled at once. MshPRT §4.2.46.1, .txt lines
14865-14872: "If the value of the Node Identity state of the node for **any**
subnet is Enabled..., then the value of the Private Node Identity state shall
be Disabled for **each known subnet**." Zephyr implements both directions and
masks both Gets. BlueZ implements no Node Identity Set at all — its handler
falls through to Get with the comment "Currently setting node identity not
supported" — so it is not a reference here.

**Heartbeat publication not disabled on NetKey Delete (#35).** The cascade
clears bound AppKeys, model bindings, model publications, the bridging table
and DF state — four of the five bullets at .txt lines 24076-24093 — but not the
heartbeat publication. .txt lines 24080-24081: "When NetKey used in Heartbeat
Publication is deleted as a result of the processing of the Config NetKey
Delete message, the Publication for the appropriate NetKey shall be disabled."
BlueZ does it explicitly; Zephyr does it lazily by looking the subnet up and
finding it gone. Worse for us, the publication setter takes no NetKey index at
all, so we keep publishing on the primary credential while Get reports an index
that no longer exists.

**Status codes 0x12–0x15 undefined (#36).** Table 4.308 gained Invalid Path
Entry, Cannot Get, Obsolete Information and Invalid Bearer in Mesh 1.1. We
define none of them, and yet we implement the Directed Forwarding Config Server
messages that the specification requires them for — Invalid Bearer for
Forwarding Table Add, Invalid Path Entry for fixed-path delete and get,
Obsolete Information for the Forwarding Table Update Identifier. BlueZ and
Zephyr also stop at 0x11, but neither implements DF, so neither needs them.

**Codes defined and never returned.** Storage Failure (0x09), Temporarily
Unable to Change State (0x0E), Cannot Set (0x0F) and Cannot Bind (0x0D) are
never returned anywhere. The one the specification actually demands is 0x0E, at
Table 4.319 .txt lines 24289-24290: "The node cannot start advertising with
Node Identity since the maximum number of parallel advertising is reached →
Temporarily Unable to Change State". Zephyr does not produce it either. Low
impact.

**Node Identity 0x02 "Not Supported" is never reported.** Per §4.2.13 a node
without the functionality "shall" report it. Latent today, since meshd always
has the capability, but wrong if it is ever built without proxy support. Note
Zephyr returns *Success* with identity 0x02 rather than Feature Not Supported,
and says so in a comment.

### 4.2 Publication, subscription, heartbeat and relay

**Model Publication Status on error (#15).** We build the Status from the
requested parameters unconditionally. MshPRT .txt lines 23830-23833: "...
setting the ElementAddress and ModelIdentifier fields to the corresponding
fields of the incoming message, setting the Status field to a status code...,
and **setting all other fields to 0x00**." All three references zero the
7-octet tail. A provisioner keying off the echoed address believes the
publication was partially committed.

**Publication with PublishAddress 0x0000 (#31, publication half).** We store
the incoming struct verbatim and merely record that no publication is active,
so AppKeyIndex, CredentialFlag, TTL, Period and Retransmit survive and are
echoed. .txt lines 23740-23743 require all six to be set to 0x00. Zephyr
explicitly zeroes them and cancels the timer; BlueZ frees the publication
outright (though it leaves two fields echoed — a smaller version of our bug).

**Publication AppKeyIndex checked node-wide only (#19).** We check that the key
exists on the node. Table 4.313 at .txt lines 23755-23756: "The AppKey
identified by AppKeyIndex is not known to the node **or is not bound to the
model** identified by the ModelIdentifier — Invalid AppKey Index". Both
references check both halves. Setting publication before binding therefore
returns Success and then never publishes — which is precisely the failure the
code's own NB-18 comment claims to have closed. It closed half of it.

**Publish TTL 0x80–0xFE accepted (#33).** No TTL validation on any publication
path; at publish time the value is silently masked to 7 bits. Table 4.22 makes
0x80–0xFE Prohibited and 0xFF "Use Default TTL". Zephyr drops the message;
BlueZ is as lax as we are, so this is a split with Zephyr on the strict side —
but we then *echo* the Prohibited value back in our own Status, which is a wire
violation regardless.

**Heartbeat CountLog 0x11 (#16).** The decoder maps any CountLog ≥ 0x11 to
0xFFFF, and the encoder maps 0xFFFF back to 0xFF. So a Config Heartbeat
Publication Set carrying CountLog 0x11 produces a Status carrying **0xFF** —
"publish indefinitely" instead of "65534 messages" — and arms the timer with
65535 rather than 65534. The same `>= 0x11` also swallows the Prohibited
0x12–0xFE range.

Table 4.323 at .txt lines 24401-24409 is unambiguous: `0x00 → 0x0000`,
`0x01–0x10 → 2^(n-1)`, `0x11 → 0xFFFE`, `0x12–0xFE` Prohibited, `0xFF →
0xFFFF`. Zephyr implements both directions of that special case explicitly.
The fix is one line, and our own ceiling encoder already maps 0xFFFE back to
0x11 correctly.

**Heartbeat Publication Status on failure (#24).** We report the stored
publication. .txt lines 24369-24373 require the Status to echo the *incoming*
message's Destination, CountLog, PeriodLog and TTL. Both references echo. Note
this is the **opposite** of the Model Publication rule in #15 — the spec zeroes
for one and echoes for the other, and we have both backwards.

**Heartbeat Publication Get with unassigned Destination (#31).** .txt lines
24354-24357 require CountLog, PeriodLog, TTL and Features zeroed and
NetKeyIndex 0x0000. Zephyr does; we return the stored values.

**Publication and subscription capability (#34).** Status codes 0x07 "Invalid
Publish Parameters" and 0x08 "Not a Subscribe Model" exist as constants and are
never emitted. We have no notion of whether a model *supports* publication or
subscription — only whether one is currently configured. BlueZ implements both
checks at eight call sites; Zephyr emits 0x07 but has no 0x08 either.

The concrete consequence: the Configuration Server model itself is registered
and reachable by model lookup, so a Config Model Subscription Add or Config
Model Publication Set targeting model 0x0000 returns **Success** and mutates
state on a model that has neither capability.

**Key Refresh Phase Set always answers Success (#38).** The status is set
before dispatch and the dispatch return value is discarded, so a transition
Table 4.31 does not define — 0x02 from Phase 0 — yields Success with an
unchanged phase. The underlying state guards are correct, so this is a
status-code defect, not state corruption. Zephyr keeps an explicit
valid-transition table and answers Cannot Update; BlueZ sends nothing at all.
Since a Configuration Manager sequences the whole procedure off these replies,
a false Success is worse than an error.

**Directed Forwarding configuration (#41), SPEC-ONLY.** The Path Echo Interval
handler stores 0xFF — the "no change" sentinel — as the state, and builds the
Status from the request rather than the resulting state. .txt lines 28085-28091
require the state to be left alone for 0xFF and the Status to carry the current
state. Prohibited ranges (0x64–0xFE for the interval, 0x00 for Wanted Lanes,
the seven reserved bits of two-way path) are accepted and stored. No reference
implements DF, so these are adjudicated from the document alone.

### 4.3 Configuration Server — verified in agreement

The agreement list here is long, and several items on it are things
implementations routinely get wrong.

**Keys.** NetKey Add idempotency in all three cases, with a constant-time
comparison that is better than everyone's `memcmp`. NetKey Update on an unknown
index. NetKey Delete of a non-existent index returning Success, per the
specification's own note that "the result of deleting a key that does not exist
in the NetKey List is the same as if the key was deleted". The NetKey Delete
cascade over AppKeys, bindings, publications and — ahead of both references —
the bridging table. AppKey Delete of a non-existent key returning Success.
AppKey Delete disabling publications bound to the deleted key. AppKey Get's
error response carrying a zero-length list. NetKey List carrying no Status
field. Key Refresh Phase Get and Set on an unknown index returning Phase 0x00
alongside the error — easy to get wrong, and we did not. Node Identity Get
likewise. Node Identity as per-subnet state. Node Reset Status carrying no
parameters. The 12-bit key index range checks and the packed 3-octet pair
encoding. Exact length validation on every message.

Three cells of the four-cell Key Refresh transition matrix are correct, and
Phase 3 is verified to be unobservable on the wire — every path that can reach
it immediately finalizes to Phase 0, so a Status can only ever carry 0x00,
0x01 or 0x02. That was verified by tracing the callers rather than assumed.

Prohibited parameter values are *dropped, not answered*, exactly as §3.7.3.4
requires and identically to both references. A useful consequence, verified
rather than guessed: several `else` branches in the handlers are unreachable
dead code rather than live divergences.

**Publication and subscription.** Every opcode we define was cross-checked
against `Assigned_Numbers.html` and all are correct. The AppKeyIndex +
CredentialFlag + RFU packing. The publish retransmit interval as
`(steps+1) × 50 ms` — correctly *distinct* from the `× 10 ms` used for Relay
Retransmit and Network Transmit, which is a classic confusion. The 6-bit
steps + 2-bit resolution publish period. Group-only subscription with 0xFFFF
refused. Insufficient Resources on a full list. Delete All reporting address
0x0000. The virtual variants reporting the derived address on both success and
error. Both list-packing formats.

**Heartbeat.** Publication CountLog uses the **ceiling** transform and
subscription Count and Period use the **floor** transform of Table 4.1 — two
different functions, correctly kept apart, and the ceiling verified against the
specification's own worked example of 0x0579 → 0x0C. Publication Status reports
the *remaining* count but the *configured* period; subscription Status reports
the *remaining* period. All three match both references.

**Relay.** Prohibited Set values dropped. Status permitted to carry 0x02 "not
supported" while Set is not. The count and interval-steps arithmetic.

**Subnet Bridge.** All twelve opcodes handled, with field-for-field agreement
with Zephyr on every message: the Directions + packed NetKeyIndex pair +
address encoding, the 1-octet Start Index for Bridged Subnets Get versus the
2-octet one for Bridging Table Get, the 5-octet table entries, entry validation
(directions 0x01/0x02 only, differing NetKey indexes, differing addresses,
Addr1 unicast, the one-way and two-way constraints on Addr2), the four-way
wildcard match on Remove, de-duplication and zero-based offsetting on Bridged
Subnets, and the conditional list body on a non-Success Bridging Table List.
Only Invalid NetKey Index and Insufficient Resources produce status codes, per
Tables 4.359 and 4.360; everything else drops. This is the most complete subnet
bridge of the two stacks that have one.

**Directed Forwarding message structures** (spec-only): all seven message
lengths match their tables, the 12-bit NetKeyIndex encoding is right, and
error-path field echoing on Set and zeroing on Get both match §4.4.7.4.5–.7.

---

## 5. Key Refresh, IV Update and replay protection

### 5.1 Two previously reported defects are fixed

Both findings from the earlier sweep were re-verified against the current tree.

**`mesh_iv_recovery_begin()` had no production caller.** Resolved. An arming
site now exists on the real beacon path, `recovery_active` is no longer
permanently zero, and a beacon at current+2 through current+42 is accepted. The
pending sequence-number reset is consumed correctly and the persisted sequence
block is re-reserved. *But the fix over-fires — see #10.*

**`mesh_rpl_check()` was check-and-commit in one.** Resolved. A non-mutating
scan now backs a peek/commit pair, and the production receive paths peek first
and commit only after delivery. `mesh_rpl_check()` survives only where
authentication is complete at check time — segmented-control completion,
unsegmented control, proxy configuration and friendship control — which is
exactly BlueZ's and Zephyr's rule.

### 5.2 IV Index Recovery over-fires — OURS-WRONG, #10

Recovery is armed on **any** received IV Index greater than the current one,
and the recovery branch is tested *before* the ordinary flag rules. So the
everyday case — state Normal, index exactly one ahead, flag set — takes the
recovery path, which re-anchors the dwell timestamp and marks recovery as
consumed, **skipping the 96-hour dwell gate** the ordinary branch would have
applied.

Table 3.86 (.txt lines 11577-11600) has four rows, and the first is precisely
this everyday case: Normal, current+1, flag 1, "Accept IV Index and IV Update
flag" — and it is the only row that does *not* reset the sequence number.
Zephyr treats current+1 as recovery only when an update is already in progress
or the flag is clear; NimBLE is identical; BlueZ reaches the same result
through a hold state.

Two consequences, both bad:

- The 96-hour dwell that .txt line 11445 establishes is defeated for the
  beacon-driven path. That dwell is the whole mechanism §3.11.6 describes for
  protecting the IV Index against runaway: "Secure Network beacons containing
  out of order or bumped ahead values of IV Index are ignored by nodes that
  follow the IV Update procedure." One misconfigured or hostile beaconing node
  can now drag us up an index per beacon interval.
- Every ordinary IV Update consumes the recovery credit, and .txt lines
  11611-11612 make that credit scarce: "once it happens, the node is not
  allowed to accept an out of order value for the IV Index again for at least
  192 hours." A node that goes off-air within 192 hours of any normal update
  cannot rejoin and needs reprovisioning.

The fix is to gate the arming on Zephyr's predicate: recovery when the index is
more than one ahead, or exactly one ahead with an update already in progress or
the flag clear.

### 5.3 A Friend Update revokes the old key — OURS-WRONG, #5

The Friend Update handler drives the Key Refresh phase machine with the flag it
carries, unconditionally. The Friend Update was decrypted with *any* of the old
key, the new key or the friendship credential — and the friendship credential
is derived from the old NetKey during Key Refresh. Nothing records which one
authenticated it.

In Phase 1 a flag of 0 means "transition to Phase 3", and a Friend in Phase 1
emits exactly that. So the very first Friend Update an LPN receives after being
given a new key collapses it to Phase 3, revokes the old key, and drops it off
a network still transmitting on that key.

MshPRT .txt lines 11307-11309:

> Upon receiving a Secure Network beacon or a Mesh Private beacon with the Key
> Refresh Flag set to 0 **using the new NetKey** in Phase 1, the node shall
> immediately transition to Phase 3, which effectively skips Phase 2.

and .txt lines 6807-6809 make a Friend Update equivalent to a beacon for these
purposes. Zephyr passes `rx->new_key` through to its phase update and returns
immediately when it is false.

**Our own beacon path gets this right** — it drives the phase machine only
inside the new-NetKey branch. The LPN path is the outlier, which makes this a
narrow fix.

### 5.4 The LPN cannot recover a missed IV Update — OURS-WRONG, #27

The Friend Update handler calls the raw beacon-receive function directly rather
than the wrapper that arms recovery. So there is no recovery arming, no pending
sequence reset and no RPL flush on that path: an index one ahead with a clear
flag is rejected, and current+2 through +42 is rejected.

Zephyr routes Friend Updates through the identical function it uses for
beacons, recovery branch and all.

The irony is exact. MshPRT .txt lines 11614-11618 name the Low Power node as
*the* designated mechanism for a device that sleeps through an IV Update:

> a device that stays away from the mesh network for extended periods (for
> example, a battery-powered doorbell button) either should be configured as a
> Low Power node so that it receives IV Index updates from a Friend node ... or
> should have the Proxy Client role

The one path the specification points at is the one path in our tree that
cannot recover.

### 5.5 A secondary subnet can drive the primary IV Index — OURS-WRONG, #26

The subnet loop passes a "is primary" flag that suppresses only recovery
*arming*. The ordinary IV receive still runs, so a secondary-subnet beacon at
current+1 with the flag set moves the node's IV Index.

MshPRT .txt lines 11439-11441:

> If this node is a member of a primary subnet and receives a Secure Network
> beacon or a Mesh Private beacon on a secondary subnet with an IV Index
> greater than the last known IV Index of the primary subnet, the Secure
> Network beacon or the Mesh Private beacon shall be ignored.

BlueZ implements the guard and quotes the paragraph in a comment; Zephyr is
stricter still and ignores IV initiation from any non-primary subnet outright.

A node holding only a secondary NetKey — a guest-access subnet, per §3.11.2 —
can advance a whole-network resource. Combined with #10 that is an IV-runaway
path originating from a deliberately lower-trust key.

### 5.6 IV Update completion is not deferred — OURS-WRONG, #28

Completion checks only the dwell, and the tick completes unconditionally and
zeroes the sequence number.

MshPRT .txt lines 11505-11512:

> A node shall defer state change from IV Update in Progress to Normal
> Operation ... when the node has transmitted a Segmented Access message or a
> Segmented Control message without receiving the corresponding Segment
> Acknowledgment messages. The deferred change of the state shall be executed
> when the appropriate Segment Acknowledgment message is received or the
> timeout for the delivery of this message is reached.
>
> Note: This requirement is necessary because upon completing the IV Update
> procedure the sequence number is reset to 0x000000 and the SeqAuth value
> would not be valid.

Zephyr sets a pending flag when a transmission is in progress; BlueZ refuses to
leave the state while its outbound SAR queue is non-empty. Any segmented
transfer straddling the boundary has its SeqAuth invalidated mid-flight, which
bites exactly the large payloads — Config, BLOB, Large Composition Data —
against a phone.

### 5.7 Friendship credentials across Phase 2 — OURS-WRONG, #30

Friendship credentials are re-derived at finalize, but nothing re-derives them
at the Phase 1→2 transition. For the whole of Phase 2 the node transmits
network PDUs under the new key while securing friendship PDUs under a
credential derived from the old one. Zephyr derives friendship credentials per
subnet key slot, so they follow the transmit key across the boundary.
Friendship — Poll, Update and queued delivery — breaks for the duration of
Phase 2 against a conformant peer.

### 5.8 Replay protection capacity — OURS-WRONG, #39

The list holds 16 entries, is never pruned, and correctly fails closed when
full — .txt lines 10614-10615: "If a node does not have enough resources to
perform replay protection for a given source address, then the node shall
discard the message immediately upon reception."

Fail-closed is right. The *capacity* is the problem: after sixteen distinct
unicast sources, source number seventeen — a phone joining an established
network, for instance — is blackholed permanently with no recovery short of a
reboot. BlueZ evicts entries more than one IV epoch stale to make room. Zephyr
does what we do, but its capacity is a configuration knob typically well above
16. Our value is what we advertise as CRPL in Composition Data page 0, so a
Configuration Manager can *see* the limit; nothing recovers a node that reaches
it.

### 5.9 Smaller items

**Segmented commit stores SeqAuth + SegN** rather than the SEQ of the last
segment actually received. Table 3.75 asks for "the SEQ field of the incoming
last segment"; with retransmissions the true value can exceed SeqAuth + SegN.
The error direction is conservative — it never rejects a legitimate later
message — so there is no interop break, only a slightly narrowed replay window.

**Beacons under the old key in Phase 2** are still processed for IV state.
.txt lines 11332-11334 say a node in Phase 2 "shall only receive Secure Network
beacons or Mesh Private beacons secured using the new NetKey". Zephyr does the
same as we do, so this is an ecosystem split — but it partly undermines the
forced-exclusion property of §3.11.4: a node deliberately excluded from a
refresh still holds the old key and can drive our IV state machine through
Phase 2.

**`mesh_iv_rx_accept()` is dead code** — declared, defined, and called from
nowhere. The real receive-index selection is open-coded as `{current,
current-1}` in four places, all of them correct. The unused predicate is a
maintenance trap because it *looks* like the policy.

### 5.10 Key refresh, IV and replay — verified in agreement

- Per-phase key selection: transmit old/old/new/new, receive both keys in
  Phases 1 and 2, new only in Phase 3, applied consistently on both transmit
  and receive. The phase machine itself is the same as Zephyr's, transition for
  transition.
- Phase 3 promotes and returns to Phase 0 immediately.
- Table 3.85 index and state arithmetic, and the receive-index set in both
  states.
- Normal → In Progress increments the IV Index.
- A same-index beacon with the flag set is ignored — identical to Zephyr's
  "Discard [iv, false] → [iv, true]".
- Beacons below the current index or above current+42 rejected, with the same
  bounds in all three references.
- Sequence number reset on completing the update, on all three completion
  paths, including re-reservation of the persisted block.
- The sequence-number trigger for initiating an update, at the same value both
  references use.
- The 192-hour minimum between starts holds transitively from the two 96-hour
  dwells — *except* where #10 bypasses it.
- **The 96-hour dwell survives a restart.** It is anchored to a real-time
  timestamp, persisted, and clamped against a forward-jumped clock. This is
  better than Zephyr, which counts hours in RAM.
- Table 3.86's four rows encode the right sequence-reset behaviour; it is the
  routing *into* the table that is wrong (#10), not the table.
- The 96-hour limits are correctly waived after a completed recovery.
- RPL entry contents and ordering: source, IV Index and SEQ, with a higher IV
  always newer and strictly-greater SEQ within an epoch.
- RPL entries added only after authentication, and committed only after
  delivery.
- Source and SEQ field validation, failing closed.
- RPL cleared on a recovery jump.
- **RPL persisted across power cycle**, main list and all friendship lists.
- A separate Subnet Bridge RPL, bound unconditionally.
- Proxy configuration messages replay-checked against the same list.
- Replay evaluated once per segmented transaction at its SeqAuth, so
  out-of-order segments are not scored against each other.
- The **beacon transmit path is correct end to end**: flags taken from adopted
  state, the new NetKey selected only from Phase 2 (correctly avoiding the
  Phase-1 new-key-with-clear-flag combination that would signal Phase 3), and
  the AuthValue recomputed over the emitted flags.

---

## Comment audit

The brief asked for existing comments to be treated as suspect, on the grounds
that this stack has had many comments found citing a source that contradicts
them. That held up: **eleven** were checked and found wrong or misleading.
Three of them mark real defects; the rest are stale citations that will
misdirect the next reader.

| Location | Comment claims | Actual |
| --- | --- | --- |
| `mesh_transport.c` header, `mesh_transport.h` | §3.6.5.1 for Upper Transport Access PDU encryption | §3.6.5.1 is **Friend Poll**. The right sections are 3.6.2 / 3.6.4.1 |
| `mesh_transport.c`, `mesh_transport.h` | §3.5.3.3 for the Segment Acknowledgment message format | §3.5.3.3 is *Segmentation behavior*; the format is **§3.5.2.3.1** |
| `meshd_node.c` (SAR) | "MshPRT 4.2.29 / 4.2.30" for the SAR Transmitter/Receiver states | those are **Forwarding Table** and **Wanted Lanes**. SAR is **4.2.48 / 4.2.49** |
| `mesh_sim.c` (ack TTL) | "§3.5.3.4: send the ack with a fresh default TTL rather than the residual received TTL" | §3.5.3.4 says no such thing, and .txt line 4570 leans the other way. **Marks a real defect** |
| `meshd_node.c` (NetKey Delete) | "MshPRT 4.3.2.32: the NetKey that secured this message must not be removed" | 4.3.2.32 is **NetKey Update**. The rule is §4.4.1.2.9, .txt line 24107 |
| `meshd_node.c` (AppKey Add / Update) | "MshMDL 4.3.2.38" | MshMDL has no Config Server. It is **MshPRT** 4.3.2.38 |
| `meshd_node.c` (HB publication disable) | "MshMDL 4.2.18.1" | foundation states are **MshPRT** §4.2.18 / 4.2.19 |
| `meshd_node.c` (LPN PollTimeout) | "MshMDL 4.4.1" | **MshPRT** §4.4.1 |
| `mesh_df.h` (repeatedly) | "Directed Forwarding Configuration model (MshMDL_v1.1 Section 4.4.2)" | wrong document and wrong section: **MshPRT §4.4.7**, messages §4.3.5 |
| `meshd_node.c` NB-18 | claims the unknown-AppKeyIndex hole is closed | closes only the "unknown to node" half, not the "not bound to the model" half. **Marks a real defect** (#19) |
| `mesh_heartbeat.c` P-M11 | cites §4.4.1.2.16 for zeroing MinHops/MaxHops | that rule is stated only for the **Get** response; applying it to Set is the divergence in S4. **Marks a real divergence** |

Comments that were checked and **hold up**: the §7.2.2.2.3 citation for the
60-second Node Identity timer (exact, including the value); §7.2.2.2.5 for
private node identity; §4.2.42.1 for bridging-table removal, whose quoted text
matches the specification word for word; the phase/key-selection table in
`mesh_key_refresh.h`, which matches §3.11.4 exactly including the note that
Phase 3 is transient; the "Known limitation" comment on AppKey promotion, which
is honest and accurate about being finding #4; and the element-address and
non-virtual-subscription citations in `mesh_cfg_model.c`.

## Reference headers created

Seven new oracle headers under `tests/usr.sbin/bluetooth/blued/`, following the
existing `spec_extref_*.h` conventions: every value traceable to a named
external source, nothing derived by running our own code, each compiling
standalone and all seven co-existing in one translation unit alongside the two
pre-existing mesh headers.

| Header | Pins |
| --- | --- |
| `spec_extref_mesh_cfg_status_codes.h` | Table 4.308 in full (0x00–0x15), the separate Opcodes Aggregator table 4.309, the Mesh 1.0 / 1.1 boundary, and which reference defines what |
| `spec_extref_mesh_opcode.h` | Table 3.63, the 0x7F reserved value, the specification's worked vendor-opcode example `0xE3 0x36 0x01`, and the per-form parameter limits |
| `spec_extref_mesh_sar.h` | all twelve Mesh 1.1 SAR states with formulas and defaults, the acknowledgment-timer arithmetic in exact integer form, Table 3.24's four validity conditions, and both SeqAuth worked examples |
| `spec_extref_mesh_virtual_addr.h` | the `vtad` derivation, the dispatch-by-label rule, Table 3.8 fixed group addresses, and Tables 3.9 and 3.10 transcribed cell by cell |
| `spec_extref_mesh_heartbeat.h` | Table 4.1's floor transform, the publication ceiling transform, Table 4.323 including the 0x11 → 0xFFFE special case, and the zero-versus-echo reporting rules |
| `spec_extref_mesh_net_credentials.h` | the three k2 credential families, the inbound-to-outbound credential rule, Table 3.28, the message-cache rules, and all five nonce layouts |
| `spec_extref_mesh_kr_iv.h` | per-phase key usage, the transition triggers with the "authenticated under the new key" clause, the 96/192-hour limits, and Table 3.86 |

Two of these deliberately supersede parts of the older mesh headers.
`spec_extref_mesh_vectors.h` and `spec_extref_mesh_iv_recovery.h` both open by
stating that the tree contains no mesh specification and fall back to quoting
Zephyr's in-code citations. That is no longer true, and the new headers quote
the document. The old ones are not wrong — they are a second-hand reading of
the same text — and are left in place because existing tests include them.

## What to fix first

If only three things are fixed, they should be #1, #2 and #3. The first two
together mean a 5BSD node cannot exchange a segmented message with any Low
Power node in either direction, and cannot forward an LPN's traffic to anyone
— which is most of what a mesh network is for, and none of it is visible
without a real LPN in the test rig. The third is a straightforward
authorization bypass that is live on every node between provisioning and the
first Model App Bind.

After those, #4 and #5 are the pair that make a Key Refresh — the procedure the
whole security model rests on — unsafe to run on a live network.
