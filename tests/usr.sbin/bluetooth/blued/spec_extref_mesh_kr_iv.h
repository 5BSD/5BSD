/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * EXTERNAL REFERENCE ORACLE: Bluetooth Mesh Key Refresh and IV Update --
 * per-phase key usage, the phase transition triggers, the IV Update timing
 * limits, and Table 3.86 (IV Index Recovery actions).
 *
 * Hand-written.  Every constant and every claim below is traceable to a named
 * external source; nothing here was derived from any file under
 * /usr/src/lib/libmesh or /usr/src/usr.sbin/bluetooth, and no value was
 * produced by running 5BSD code.
 *
 * RELATIONSHIP TO spec_extref_mesh_iv_recovery.h
 * ==============================================
 * That header opens by stating that /usr/src/bluetooth-specs contains no Mesh
 * specification and falls back to quoting Zephyr's in-code citation of
 * MshPRT v1.1.  That constraint no longer holds -- MshPRT_v1.1.1.txt is in the
 * tree.  This header quotes the specification directly and is the one to
 * prefer where the two overlap.  The older header is not wrong; it is a
 * second-hand reading of the same text and is retained because existing tests
 * include it.
 *
 * SOURCES
 * =======
 * SPEC: /usr/src/bluetooth-specs/MshPRT_v1.1.1.txt.  Line numbers below are
 *   lines of that .txt file.
 *     Section 3.11.4  Key Refresh procedure ........ lines 11230-11375
 *     Section 3.11.5  IV Update procedure .......... lines 11400-11520
 *     Section 3.11.6  IV Index Recovery, Table 3.86  lines 11570-11620
 *     Section 3.11.7  Node Removal procedure ....... lines 11620+
 *
 * REFERENCE IMPLEMENTATIONS
 * =========================
 * ZEPHYR (2665fcca3cced3aefb7202d6289991d8cc1dfcac): subsys/bluetooth/mesh/
 *   net.c (bt_mesh_net_iv_update), subnet.c (the phase machine and the
 *   Config-side transition table), beacon.c, rpl.c.  PTS-qualified.
 * BLUEZ 5.87 (92305dc06ab8a6d89af2dae1d725cc4d51462ad1): mesh/net.c
 *   (update_iv_ivu_state, process_beacon), net-keys.c, rpl.c.
 * APACHE NIMBLE: nimble/host/mesh/src/net.c, rpl.c -- Mesh 1.0-era, but the
 *   IV Update and Key Refresh procedures did not change in 1.1.
 */

#ifndef SPEC_EXTREF_MESH_KR_IV_H
#define SPEC_EXTREF_MESH_KR_IV_H

#include <stdint.h>

/*
 * ---------------------------------------------------------------------------
 * KEY REFRESH: per-phase key usage.
 *
 * Section 3.11.4, .txt lines 11244-11252, verbatim -- the whole procedure in
 * one paragraph, and the authority for the table below:
 *   "As illustrated in Figure 3.67, nodes in normal operation only know a
 *    single key, Key A1. This key is used for transmitting and receiving
 *    packets. When Phase 1 (Key Distribution) is performed, each node will
 *    receive a new key that is stored in the same key index. The nodes will
 *    continue to transmit using the old key, Key A1, but will additionally
 *    receive using the new key, Key A2. Once all nodes have been informed of
 *    the new key, Phase 2 (Use New Keys) can start. This sends a signal around
 *    the network that the new key should now be used. The nodes will therefore
 *    start to transmit using the new key, Key A2, but will also receive from
 *    the old and new keys. Finally, Phase 3 (Revoke Old Keys) will revoke the
 *    old keys meaning that nodes will only transmit and receive using a single
 *    key, Key A2. After the old keys have been revoked, the nodes are back to
 *    normal operation."
 *
 * Rendered as a table:
 *
 *   Phase        Transmit with     Receive with
 *   -----------  ----------------  ---------------------
 *   0 (normal)   old               old
 *   1            OLD               old AND new
 *   2            NEW               old AND new
 *   3            new               new  (old revoked)
 *
 * The two cells that matter, and that an implementation which keeps only one
 * key slot per index cannot express:
 *   - Phase 1 transmits with the OLD key while receiving with BOTH.
 *   - Phase 2 transmits with the NEW key while STILL receiving with BOTH.
 * Revoking the old key at the entry to Phase 2, rather than at Phase 3, makes
 * a node deaf to every peer that has not yet advanced -- for the entire
 * duration of Phase 2, which a Configuration Manager may deliberately hold
 * open for hours while it reaches Low Power nodes.
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_KR_PHASE_0			0x00u	/* Normal */
#define	SPEC_EXTREF_MESH_KR_PHASE_1			0x01u	/* Key Distribution */
#define	SPEC_EXTREF_MESH_KR_PHASE_2			0x02u	/* Use New Keys */
#define	SPEC_EXTREF_MESH_KR_PHASE_3			0x03u	/* Revoke Old Keys */

/* Transmit key per phase: 0 = old, 1 = new. */
#define	SPEC_EXTREF_MESH_KR_TX_USES_NEW(phase)				\
	((phase) >= SPEC_EXTREF_MESH_KR_PHASE_2)
/* Receive: both keys are accepted in Phase 1 and Phase 2 only. */
#define	SPEC_EXTREF_MESH_KR_RX_ACCEPTS_OLD(phase)			\
	((phase) <= SPEC_EXTREF_MESH_KR_PHASE_2)
#define	SPEC_EXTREF_MESH_KR_RX_ACCEPTS_NEW(phase)			\
	((phase) >= SPEC_EXTREF_MESH_KR_PHASE_1)
/* The old key is destroyed at Phase 3, never earlier. */
#define	SPEC_EXTREF_MESH_KR_OLD_KEY_REVOKED_AT_PHASE	SPEC_EXTREF_MESH_KR_PHASE_3

/*
 * Phase 2 beacon restriction, .txt lines 11331-11334, verbatim:
 *   "When in Phase 2, the node shall only transmit messages and Secure Network
 *    beacons or Mesh Private beacons using the new keys, shall receive
 *    messages using the old keys and the new keys, and shall only receive
 *    Secure Network beacons or Mesh Private beacons secured using the new
 *    NetKey."
 * Note the asymmetry within one sentence: MESSAGES are accepted under both
 * keys in Phase 2, but BEACONS only under the new key.
 */
#define	SPEC_EXTREF_MESH_KR_PHASE2_BEACON_NEW_KEY_ONLY	1
#define	SPEC_EXTREF_MESH_KR_PHASE2_MSG_BOTH_KEYS	1

/*
 * ---------------------------------------------------------------------------
 * KEY REFRESH: transition triggers.
 *
 * Phase 1 -> Phase 3 directly, .txt lines 11307-11309, verbatim:
 *   "Upon receiving a Secure Network beacon or a Mesh Private beacon with the
 *    Key Refresh Flag set to 0 using the new NetKey in Phase 1, the node shall
 *    immediately transition to Phase 3, which effectively skips Phase 2."
 *
 * Read "using the new NetKey" as the load-bearing clause.  A KR=0 beacon
 * authenticated under the OLD key in Phase 1 is simply the ordinary state of
 * the world -- the network has not advanced yet -- and must NOT drive a
 * transition.  A node that acts on the flag without recording which key
 * authenticated the beacon collapses to Phase 3 on the first beacon it hears
 * after being given a new key, revoking a key the rest of the network is
 * still using.
 *
 * The same clause governs the Friend Update path.  .txt lines 6807-6809
 * (Section 3.6.6.4) make a Friend Update equivalent to a beacon for these
 * purposes, so the "which key authenticated it" test applies there too -- and
 * a Friend Update may legitimately arrive under FRIENDSHIP credentials, which
 * are derived from the old NetKey during Phase 1.
 *
 * Phase 2 entry, .txt lines 11329-11331, verbatim:
 *   "Upon receiving a Secure Network beacon or a Mesh Private beacon or a
 *    Friend Update message with the Key Refresh Flag set to 1, or a Config Key
 *    Refresh Phase Set message with the Phase parameter set to 0x02, the node
 *    shall set the Key Refresh Phase for this NetKey to Phase 2."
 *
 * Phase 3, .txt lines 11360-11369, verbatim:
 *   "Upon receiving a Secure Network beacon or a Mesh Private beacon or a
 *    Friend Update message with the Key Refresh Flag set to 0 or a Config Key
 *    Refresh Phase Set message with the Transition parameter set to 0x03, the
 *    node shall revoke the old keys ... It shall ignore Secure Network
 *    beacons, Mesh Private beacons, and Friend Update messages secured using
 *    the new NetKey with the Key Refresh Flag set to 1. After old keys are
 *    revoked, the Key Refresh state will be 0."
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_KR_TRANSITION_REQUIRES_NEW_KEY_AUTH	1
#define	SPEC_EXTREF_MESH_KR_FRIEND_UPDATE_ACTS_AS_BEACON	1
#define	SPEC_EXTREF_MESH_KR_PHASE3_SETTLES_TO_PHASE_0		1
/* Phase 3 is transient: it is never observable in a Config KRP Status. */
#define	SPEC_EXTREF_MESH_KR_PHASE_STATE_PROHIBITED_MIN		0x03u

/*
 * Config Key Refresh Phase Set: the legal Transition values and the legal
 * (starting phase -> transition) pairs, Table 4.31.  Only these five pairs are
 * defined; "All other transition values are Prohibited."
 *
 *   phase 0x00 + transition 0x03  (no state change)
 *   phase 0x01 + transition 0x02  -> Phase 2
 *   phase 0x01 + transition 0x03  -> Phase 3 (then 0)
 *   phase 0x02 + transition 0x02  (no state change)
 *   phase 0x02 + transition 0x03  -> Phase 3 (then 0)
 *
 * Note there is no (phase 0x00 + transition 0x02) row.  A Configuration
 * Manager sending that has sent a Prohibited parameter combination and must
 * not be answered with Success.
 */
#define	SPEC_EXTREF_MESH_KRP_TRANSITION_TO_PHASE_2	0x02u
#define	SPEC_EXTREF_MESH_KRP_TRANSITION_TO_PHASE_3	0x03u
#define	SPEC_EXTREF_MESH_KRP_TRANSITION_VALID(phase, tr)		\
	(((phase) == 0x00u && (tr) == 0x03u) ||				\
	 ((phase) == 0x01u && ((tr) == 0x02u || (tr) == 0x03u)) ||	\
	 ((phase) == 0x02u && ((tr) == 0x02u || (tr) == 0x03u)))

/*
 * Processing a Config NetKey Update, .txt lines 11257-11267, verbatim:
 *   "The node shall successfully process a Config NetKey Update message for a
 *    valid NetKeyIndex if one of the following conditions is met:
 *    - The Key Refresh procedure has not been started and the received NetKey
 *      value is different from the current NetKey value.
 *    - The Key Refresh procedure is in Phase 1 and the received NetKey value
 *      is the same as the new NetKey value.
 *    Otherwise, the Config NetKey Update message shall generate an error."
 *
 * Both conditions are conjunctions of a PHASE test and a KEY-VALUE test.
 * Neither can be inferred from "do I have a staged key?" alone, because a
 * staged key persists into Phase 2.
 */
#define	SPEC_EXTREF_MESH_NETKEY_UPDATE_OK_PHASE0_DIFFERENT_KEY	1
#define	SPEC_EXTREF_MESH_NETKEY_UPDATE_OK_PHASE1_SAME_NEW_KEY	1
#define	SPEC_EXTREF_MESH_NETKEY_UPDATE_ERROR_OTHERWISE		1

/*
 * ---------------------------------------------------------------------------
 * IV UPDATE: timing limits, Section 3.11.5.
 *
 * .txt line 11443, verbatim:
 *   "A node shall not start an IV Update procedure more often than once every
 *    192 hours."
 * .txt lines 11445-11447, verbatim:
 *   "After 96 hours of operating in Normal Operation, a node may initiate the
 *    IV Update procedure by transitioning to the IV Update in Progress state.
 *    When a node transitions from the Normal Operation state to the IV Update
 *    in Progress state, the IV Index on the node shall be incremented by one."
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_IV_MIN_DWELL_HOURS		96u
#define	SPEC_EXTREF_MESH_IV_MIN_BETWEEN_STARTS_HOURS	192u
#define	SPEC_EXTREF_MESH_IV_STATE_NORMAL		0u
#define	SPEC_EXTREF_MESH_IV_STATE_IN_PROGRESS		1u
#define	SPEC_EXTREF_MESH_IV_INDEX_INCREMENTS_ON_START	1
#define	SPEC_EXTREF_MESH_IV_SEQ_RESET_ON_COMPLETE	1

/*
 * The deferral rule, .txt lines 11505-11512, verbatim -- easy to miss and it
 * has no analogue anywhere else in the protocol:
 *   "A node shall defer state change from IV Update in Progress to Normal
 *    Operation, as defined by this procedure, when the node has transmitted a
 *    Segmented Access message or a Segmented Control message without receiving
 *    the corresponding Segment Acknowledgment messages. The deferred change of
 *    the state shall be executed when the appropriate Segment Acknowledgment
 *    message is received or the timeout for the delivery of this message is
 *    reached."
 *   "Note: This requirement is necessary because upon completing the IV Update
 *    procedure the sequence number is reset to 0x000000 and the SeqAuth value
 *    would not be valid."
 */
#define	SPEC_EXTREF_MESH_IV_DEFER_COMPLETE_WHILE_SEG_TX_OUTSTANDING	1

/*
 * Beacon acceptance window, .txt lines 11425-11427, verbatim:
 *   "If a node in Normal Operation receives a Secure Network beacon or a Mesh
 *    Private beacon with an IV index less than the last known IV Index or
 *    greater than the last known IV Index + 42, the Secure Network beacon or
 *    the Mesh Private beacon shall be ignored."
 * The specification's own note explains the 42: it is 48 weeks of absence.
 */
#define	SPEC_EXTREF_MESH_IV_RECOVERY_MAX_AHEAD		42u

/*
 * Secondary-subnet restriction, .txt lines 11439-11441, verbatim:
 *   "If this node is a member of a primary subnet and receives a Secure
 *    Network beacon or a Mesh Private beacon on a secondary subnet with an IV
 *    Index greater than the last known IV Index of the primary subnet, the
 *    Secure Network beacon or the Mesh Private beacon shall be ignored."
 *
 * The IV Index is a whole-network resource; only the primary subnet may
 * advance it.  Without this check, a node holding a lower-trust secondary
 * NetKey (a guest subnet, for instance) can drive the primary IV Index.
 */
#define	SPEC_EXTREF_MESH_IV_SECONDARY_SUBNET_CANNOT_ADVANCE	1

/*
 * ---------------------------------------------------------------------------
 * TABLE 3.86 "Possible actions for the IV Index Recovery procedure",
 * Section 3.11.6, .txt lines 11577-11600, transcribed in full.
 *
 *   State        Observed IV Index         Flag    Action
 *   -----------  ------------------------  ------  --------------------------
 *   Normal       Current + 1               1       Accept index and flag
 *   Normal       Current + 1               0       Accept index and flag, AND
 *                                                  reset sequence numbers to
 *                                                  0x000000
 *   In Progress  Current + 1               0 or 1  Accept, AND reset seq
 *   Normal or    Current + 2 .. + 42       0 or 1  Accept, AND reset seq
 *   In Progress
 *
 * Row 1 is the ONLY row that does not reset the sequence number.  It is also
 * the ordinary, everyday case -- a node in Normal Operation hearing that the
 * network has begun an IV Update.  Routing that everyday case through the
 * recovery machinery is not merely inelegant: recovery is rate-limited to once
 * per 192 hours, so spending the recovery credit on every routine IV Update
 * leaves the node unable to recover a genuinely missed one.
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_IV_T386_NORMAL_P1_FLAG1_RESETS_SEQ	0
#define	SPEC_EXTREF_MESH_IV_T386_NORMAL_P1_FLAG0_RESETS_SEQ	1
#define	SPEC_EXTREF_MESH_IV_T386_INPROG_P1_RESETS_SEQ		1
#define	SPEC_EXTREF_MESH_IV_T386_AHEAD_2_TO_42_RESETS_SEQ	1

/*
 * Which observations constitute RECOVERY (as opposed to ordinary IV Update
 * tracking).  Derived from Table 3.86 read together with the ordinary
 * procedure in Section 3.11.5: an index more than one ahead is always
 * recovery; an index exactly one ahead is recovery only when the ordinary
 * rules cannot explain it -- i.e. when an update is already in progress, or
 * when the flag says Normal Operation.
 */
#define	SPEC_EXTREF_MESH_IV_IS_RECOVERY(state, delta, flag)		\
	((delta) > 1u ||						\
	 ((delta) == 1u && ((state) == SPEC_EXTREF_MESH_IV_STATE_IN_PROGRESS \
	  || (flag) == 0u)))

/*
 * .txt lines 11603-11604, verbatim:
 *   "After the IV Index Recovery procedure completes, the 96-hour time limits
 *    for changing the IV Update procedure state, as defined in the IV Update
 *    procedure, shall not apply."
 * and .txt lines 11611-11612, verbatim -- the rate limit that makes the
 * recovery credit scarce:
 *   "once it happens, the node is not allowed to accept an out of order value
 *    for the IV Index again for at least 192 hours."
 */
#define	SPEC_EXTREF_MESH_IV_RECOVERY_WAIVES_96H_LIMITS	1
#define	SPEC_EXTREF_MESH_IV_RECOVERY_LOCKOUT_HOURS	192u

/*
 * .txt lines 11614-11619, verbatim -- the specification's own answer to
 * "what about a node that sleeps for months":
 *   "Because of the infrequency with which IV Index Recovery is performed on a
 *    node, a device that stays away from the mesh network for extended periods
 *    (for example, a battery-powered doorbell button) either should be
 *    configured as a Low Power node so that it receives IV Index updates from
 *    a Friend node (see Section 3.6.6.4) or should have the Proxy Client role
 *    (see Section 6.2) so that it receives IV Index updates from a Proxy
 *    Server when it reconnects with the mesh network."
 *
 * The Low Power node is the designated recovery path.  An implementation whose
 * LPN Friend-Update handler bypasses the recovery logic has disabled recovery
 * precisely on the class of device the specification names.
 */
#define	SPEC_EXTREF_MESH_IV_LPN_IS_THE_RECOVERY_PATH	1

/*
 * Secure Network beacon Flags octet: bit 0 Key Refresh, bit 1 IV Update.
 * Remaining bits RFU and, per Section 1.3.2, must be authenticated as
 * received rather than masked before the AuthValue is checked.
 */
#define	SPEC_EXTREF_MESH_BEACON_FLAG_KEY_REFRESH	0x01u
#define	SPEC_EXTREF_MESH_BEACON_FLAG_IV_UPDATE		0x02u
#define	SPEC_EXTREF_MESH_BEACON_FLAGS_RFU_MASK		0xFCu
#define	SPEC_EXTREF_MESH_BEACON_AUTH_BEFORE_MASKING	1

/*
 * ---------------------------------------------------------------------------
 * NODE REMOVAL, Section 3.11.7.  Pinned here because the Config Node Reset
 * message is what triggers it and the obligation is easy to under-implement as
 * "mark the node unprovisioned".
 *
 * The node must delete all stored security credentials and security material,
 * the device key, and the provisioning data, and become an unprovisioned
 * device.  Both BlueZ and Zephyr defer the destruction until after the Config
 * Node Reset Status has been sent, because the Status must itself be secured
 * with the device key that is about to be destroyed.
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_NODE_RESET_ERASES_KEY_MATERIAL	1
#define	SPEC_EXTREF_MESH_NODE_RESET_STATUS_BEFORE_ERASE	1

/*
 * ---------------------------------------------------------------------------
 * REPLAY PROTECTION, Section 3.11.6 preamble and Table 3.75.
 * An RPL entry stores the SRC, the IV Index and the SEQ (the SeqAuth for a
 * segmented message).  The check must not commit before the message has been
 * authenticated and delivered; and when the list is full and the source is
 * unknown, the message is DISCARDED -- the list never silently forgets an
 * entry in order to admit a new sender.
 *
 * .txt lines 10614-10615, verbatim:
 *   "If a node does not have enough resources to perform replay protection for
 *    a given source address, then the node shall discard the message
 *    immediately upon reception."
 *
 * That is fail-closed, and it makes the LIST CAPACITY a functional parameter,
 * not an implementation detail: once the list is full, every new peer is
 * permanently unreachable.  The capacity is advertised as CRPL in Composition
 * Data page 0, so a Configuration Manager can see it -- but nothing recovers a
 * node that has run out.
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_RPL_STORES_SRC			1
#define	SPEC_EXTREF_MESH_RPL_STORES_IV_INDEX		1
#define	SPEC_EXTREF_MESH_RPL_STORES_SEQ_OR_SEQAUTH	1
#define	SPEC_EXTREF_MESH_RPL_FULL_IS_FAIL_CLOSED	1
#define	SPEC_EXTREF_MESH_RPL_COMMIT_AFTER_DELIVERY	1
#define	SPEC_EXTREF_MESH_RPL_PERSISTS_ACROSS_REBOOT	1

#endif /* SPEC_EXTREF_MESH_KR_IV_H */
