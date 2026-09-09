/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * EXTERNAL REFERENCE ORACLE: Bluetooth Mesh network-layer security material
 * selection -- the three k2 credential families, the inbound-to-outbound
 * credential rule for relayed PDUs, the fixed group destination conditions of
 * Table 3.28, and the Network Message Cache rules.
 *
 * Hand-written.  Every constant and every claim below is traceable to a named
 * external source; nothing here was derived from any file under
 * /usr/src/lib/libmesh or /usr/src/usr.sbin/bluetooth, and no value was
 * produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ======================
 * A mesh node holds THREE different sets of network security material derived
 * from the same NetKey, distinguished only by the k2 P input.  Which one it
 * uses is not a property of the key, it is a property of the transmission.  In
 * particular, the credential a PDU arrived under does NOT determine the
 * credential it is relayed under -- a friendship-secured PDU must be relayed
 * under managed flooding material, and a directed-forwarding PDU must be
 * transmitted under directed material.
 *
 * A relay that simply re-secures with whatever credential decrypted the PDU
 * looks correct in every single-subnet test, and quietly makes a Friend node
 * unable to forward its Low Power node's traffic to anyone else -- because
 * only the Friend and that one LPN hold the friendship material.  This header
 * pins the rule that catches it.
 *
 * SOURCES
 * =======
 * SPEC: /usr/src/bluetooth-specs/MshPRT_v1.1.1.txt.  Line numbers below are
 *   lines of that .txt file.
 *     Section 3.4.6.3  Relaying, Table 3.14/3.15 ......... lines 3760-4185
 *     Section 3.4.6.5  Network Message Cache ............. lines 4270-4290
 *     Section 3.6.4.2  Fixed group destinations, Tbl 3.28  lines 5435-5455
 *     Section 3.6.6.2  Friendship security material ...... lines 6400-6450
 *     Section 3.9.6.3.1 k2 credential derivation ......... lines 10225-10270
 *
 * REFERENCE IMPLEMENTATIONS
 * =========================
 * ZEPHYR (2665fcca3cced3aefb7202d6289991d8cc1dfcac): subsys/bluetooth/mesh/
 *   net.c, subnet.c, friend.c, cfg.c.  Zephyr rewrites the NID and re-encrypts
 *   with the flooding credential when relaying a friendship-secured PDU, and
 *   implements bt_mesh_fixed_group_match() for Table 3.28.
 * BLUEZ 5.87 (92305dc06ab8a6d89af2dae1d725cc4d51462ad1): mesh/net.c carries
 *   the same rule with an explicit comment ("If packet was encrypted with
 *   friendship credentials, relay it using flooding credentials").
 * APACHE NIMBLE: nimble/host/mesh/src/net.c, same structure as Zephyr.
 *
 * NEITHER BlueZ NOR Zephyr NOR NimBLE implements Directed Forwarding at all.
 * The directed security material below is therefore adjudicated from the
 * specification text alone, with no cross-check available from any reference.
 * Stated explicitly so that a future reader does not mistake the absence of a
 * reference citation for an oversight.
 */

#ifndef SPEC_EXTREF_MESH_NET_CREDENTIALS_H
#define SPEC_EXTREF_MESH_NET_CREDENTIALS_H

#include <stdint.h>

/*
 * ---------------------------------------------------------------------------
 * The three k2 credential families, Section 3.9.6.3.1.
 *
 * .txt lines 10225-10228, verbatim:
 *   "Each Network PDU is secured using security material that is composed of
 *    the NID, the EncryptionKey, and the PrivacyKey.
 *    The NID is a 7-bit value that identifies the security material that is
 *    used to secure this Network PDU."
 *
 * .txt lines 10237-10239, verbatim:
 *   "The managed flooding security material is derived from the managed
 *    flooding security credentials using the following formula:
 *    NID || EncryptionKey || PrivacyKey=k2(NetKey, 0x00)"
 *
 * .txt lines 10241-10245, verbatim:
 *   "The friendship security material is derived from the friendship security
 *    credentials using the following formula:
 *    NID || EncryptionKey || PrivacyKey=k2(NetKey, 0x01 || LPNAddress ||
 *    FriendAddress || LPNCounter || FriendCounter)"
 *
 * .txt lines 10264-10266, verbatim:
 *   "The directed security material is derived from the directed security
 *    credentials using the following formula:
 *    NID || EncryptionKey || PrivacyKey=k2(NetKey, 0x02)
 *    For Network PDUs that are transmitted according to directed forwarding
 *    functionality, the directed security material is used."
 * ---------------------------------------------------------------------------
 */

/* The k2 P input, first octet, identifies the family. */
#define	SPEC_EXTREF_MESH_K2_P_FLOODING			0x00u
#define	SPEC_EXTREF_MESH_K2_P_FRIENDSHIP		0x01u
#define	SPEC_EXTREF_MESH_K2_P_DIRECTED			0x02u

/* Flooding and directed P inputs are exactly one octet.  The friendship P
 * input is 0x01 followed by two 16-bit addresses and two 16-bit counters, all
 * big-endian: 1 + 2 + 2 + 2 + 2 = 9 octets. */
#define	SPEC_EXTREF_MESH_K2_P_LEN_FLOODING		1u
#define	SPEC_EXTREF_MESH_K2_P_LEN_DIRECTED		1u
#define	SPEC_EXTREF_MESH_K2_P_LEN_FRIENDSHIP		9u

/* Byte offsets within the 9-octet friendship P input. */
#define	SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_TAG		0u
#define	SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_LPN_ADDR	1u
#define	SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_FRIEND_ADDR	3u
#define	SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_LPN_COUNTER	5u
#define	SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_FRIEND_COUNTER	7u

/*
 * .txt lines 10247-10254 define where each value comes from, and it is worth
 * pinning because taking them from the wrong message produces a credential
 * that both ends agree on only by luck:
 *   "The LPNAddress value is the unicast address set as source address in the
 *    Friend Request message that set up the friendship."
 *   "The FriendAddress value is the unicast address set as source address in
 *    the Friend Offer message that set up the friendship."
 *   "The LPNCounter value is the value from the LPNCounter field of the Friend
 *    Request message that set up the friendship."
 *   "The FriendCounter is the value from the FriendCounter field of the Friend
 *    Offer message that set up the friendship."
 */

/*
 * The k2 output split, Section 3.9.6.3.1: NID is the low 7 bits of the FIRST
 * octet of T1 (i.e. the derived output's first octet masked with 0x7F), then
 * 16 octets of EncryptionKey and 16 octets of PrivacyKey.
 */
#define	SPEC_EXTREF_MESH_NID_MASK			0x7Fu
#define	SPEC_EXTREF_MESH_ENCRYPTION_KEY_OCTETS		16u
#define	SPEC_EXTREF_MESH_PRIVACY_KEY_OCTETS		16u

/*
 * ---------------------------------------------------------------------------
 * OUTBOUND SECURITY MATERIAL FOR A RETRANSMITTED PDU, Section 3.4.6.3.
 *
 * .txt lines 4177-4182, verbatim -- the Outbound Security Material column of
 * Table 3.14:
 *   "Outbound Security Material. The entries in the Outbound Security Material
 *    column of Table 3.14 identify the type of security material used to
 *    secure the retransmitted Network PDU:
 *    - flooding: The retransmitted Network PDU shall be secured using managed
 *      flooding security material.
 *    - directed: The retransmitted Network PDU shall be secured using directed
 *      security material."
 *
 * Note what is NOT in that list: "friendship".  There is no row of Table 3.14
 * whose outbound security material is friendship.  Friendship material is used
 * only on the direct Friend<->LPN link, never for a relayed PDU.
 *
 * And the prose that says so directly, Section 3.6.6.2, .txt lines 6446-6448,
 * verbatim:
 *   "OutMsg1 is sent secured using the friend security material and therefore
 *    only the Friend node will receive and relay this message. When the Friend
 *    node relays OutMsg1, the message will be retransmitted using the managed
 *    flooding security credentials."
 *
 * Two obligations follow, pinned separately because an implementation can meet
 * the first and miss the second: the payload must be re-encrypted under the
 * flooding EncryptionKey, AND the NID octet on the wire must be rewritten to
 * the flooding NID.
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_RELAY_OUT_CRED_IS_NEVER_FRIENDSHIP	1
#define	SPEC_EXTREF_MESH_RELAY_FRIENDSHIP_IN_FLOODING_OUT	1
#define	SPEC_EXTREF_MESH_RELAY_MUST_REWRITE_NID			1
#define	SPEC_EXTREF_MESH_DIRECTED_FWD_USES_DIRECTED_MATERIAL	1

/*
 * The same shape applies to a Subnet Bridge: a bridged PDU crosses onto a
 * DIFFERENT subnet and must be secured with that subnet's material, not the
 * inbound one.  Zephyr is the only reference implementing subnet bridging.
 */
#define	SPEC_EXTREF_MESH_BRIDGE_RESECURES_ON_TARGET_SUBNET	1

/*
 * .txt lines 4026-4029, verbatim -- what a relayed PDU must and must not
 * change:
 *   "The IV Index used when retransmitting the Network PDU shall be the same
 *    IV Index as in the received Network PDU."
 *   "The TTL field value of the retransmitted Network PDU shall be equal to
 *    the TTL field value of the received Network PDU decremented by 1."
 * The SEQ and SRC of a relayed PDU are likewise unchanged -- a relay does not
 * consume its own sequence number space.
 */
#define	SPEC_EXTREF_MESH_RELAY_KEEPS_IV_INDEX		1
#define	SPEC_EXTREF_MESH_RELAY_DECREMENTS_TTL_BY_1	1
#define	SPEC_EXTREF_MESH_RELAY_MIN_TTL			2u

/*
 * ---------------------------------------------------------------------------
 * Table 3.28 "Fixed group destination addresses and conditions",
 * Section 3.6.4.2, .txt lines 5443-5455, transcribed in full.
 *
 * The governing sentence, .txt lines 5435-5441, verbatim:
 *   "Upon receiving an Upper Transport Control PDU, the destination address of
 *    the PDU shall be checked. The PDU shall be processed according to the
 *    Transport Control opcode ... if one of the following conditions is met:
 *    - The destination address matches a unicast address of an element of the
 *      node
 *    - The destination address matches a fixed group destination address
 *      specified in Table 3.28 and the corresponding condition (if any) is
 *      satisfied"
 *
 * Table 3.28 itself:
 *   all-directed-forwarding-nodes  ... Directed forwarding functionality is enabled
 *   all-proxies .................... Proxy functionality is enabled
 *   all-friends .................... Friend functionality is enabled
 *   all-relays ..................... Relay functionality is enabled
 *   all-nodes ...................... (no condition)
 *
 * The all-friends row is the load-bearing one: a Friend Request is addressed
 * to all-friends, so a node that does not match fixed group addresses at the
 * network layer cannot receive a Friend Request through its normal receive
 * path at all.
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_FIXED_GROUP_ALL_DF_NODES	0xFFFBu
#define	SPEC_EXTREF_MESH_FIXED_GROUP_ALL_PROXIES	0xFFFCu
#define	SPEC_EXTREF_MESH_FIXED_GROUP_ALL_FRIENDS	0xFFFDu
#define	SPEC_EXTREF_MESH_FIXED_GROUP_ALL_RELAYS		0xFFFEu
#define	SPEC_EXTREF_MESH_FIXED_GROUP_ALL_NODES		0xFFFFu

/* Feature bit that must be enabled for each conditioned address. */
#define	SPEC_EXTREF_MESH_FG_COND_DF_ENABLED		1
#define	SPEC_EXTREF_MESH_FG_COND_PROXY_ENABLED		1
#define	SPEC_EXTREF_MESH_FG_COND_FRIEND_ENABLED		1
#define	SPEC_EXTREF_MESH_FG_COND_RELAY_ENABLED		1
#define	SPEC_EXTREF_MESH_FG_COND_ALL_NODES_NONE		0

/*
 * ---------------------------------------------------------------------------
 * Network Message Cache, Section 3.4.6.5.
 *
 * .txt lines 4270-4272 (the cache key), and the two exclusions that follow,
 * verbatim:
 *   "Because the TTL field value is decremented when a Network PDU is relayed,
 *    a node shall not consider the TTL field value when determining whether
 *    the Network PDU already has a corresponding cache entry."
 *   "Also, because the NetMIC field value is derived using the TTL field
 *    value, a node shall not consider the NetMIC field value when determining
 *    whether the Network PDU already has a corresponding cache entry."
 *
 * The recommended key, .txt lines 4283-4285, verbatim:
 *   "Values for the SRC, SEQ fields, and index of the NetKey used for
 *    decrypting PDU contents should be stored in a cache entry."
 *
 * Eviction and size, .txt lines 4278-4288, verbatim:
 *   "When the Network Message Cache is full and an entry for an incoming new
 *    Network PDU needs to be cached, an entry for the incoming new Network PDU
 *    shall replace the entry for the oldest Network PDU that is already in the
 *    Network Message Cache."
 *   "The Network Message Cache shall be able to store entries for at least two
 *    Network PDUs, although it is highly recommended to have a Network Message
 *    Cache size appropriate to the anticipated network density."
 *
 * Note the cache-key sentence is a "should", while the two exclusions are
 * "shall".  Keying on something other than the NetKey index is permitted;
 * keying on the TTL or the NetMIC is not, and either would defeat the cache
 * entirely because both change on every relay hop.
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_NMC_KEY_INCLUDES_SRC		1
#define	SPEC_EXTREF_MESH_NMC_KEY_INCLUDES_SEQ		1
#define	SPEC_EXTREF_MESH_NMC_KEY_SHOULD_INCLUDE_NETKEY_IDX	1
#define	SPEC_EXTREF_MESH_NMC_KEY_MUST_NOT_INCLUDE_TTL	1
#define	SPEC_EXTREF_MESH_NMC_KEY_MUST_NOT_INCLUDE_NETMIC	1
#define	SPEC_EXTREF_MESH_NMC_EVICTS_OLDEST		1
#define	SPEC_EXTREF_MESH_NMC_MIN_ENTRIES		2u

/*
 * ---------------------------------------------------------------------------
 * Multiple subnets sharing a NID.  Section 3.4.4.1's note, .txt lines
 * 10229-10232, verbatim:
 *   "There are up to 2^121 possible keys for each NID; therefore, the NID
 *    value can only provide an indication of the security material that has
 *    been used to secure this Network PDU."
 *
 * A NID match is a HINT, never a selection.  Every credential whose NID
 * matches must be tried until one authenticates, and failure to authenticate
 * under one is not grounds to drop the PDU.
 * ---------------------------------------------------------------------------
 */
#define	SPEC_EXTREF_MESH_NID_IS_A_HINT_NOT_A_SELECTOR	1
#define	SPEC_EXTREF_MESH_TRY_ALL_MATCHING_NID_CREDENTIALS	1

/*
 * Nonce types, Table 3.66, .txt lines 9861-9885 -- pinned here because
 * credential selection and nonce selection are the same decision made twice
 * and must agree.
 *   0x00 Network nonce            (EncryptionKey; network auth/encryption)
 *   0x01 Application nonce        (application key; upper transport)
 *   0x02 Device nonce             (device key; upper transport)
 *   0x03 Proxy nonce              (EncryptionKey; proxy configuration)
 *   0x04 Proxy solicitation nonce (EncryptionKey; Solicitation PDU)
 *   0x05-0xFF RFU
 */
#define	SPEC_EXTREF_MESH_NONCE_TYPE_NETWORK		0x00u
#define	SPEC_EXTREF_MESH_NONCE_TYPE_APPLICATION		0x01u
#define	SPEC_EXTREF_MESH_NONCE_TYPE_DEVICE		0x02u
#define	SPEC_EXTREF_MESH_NONCE_TYPE_PROXY		0x03u
#define	SPEC_EXTREF_MESH_NONCE_TYPE_PROXY_SOLICITATION	0x04u
#define	SPEC_EXTREF_MESH_NONCE_OCTETS			13u

/*
 * Nonce field layouts, Tables 3.67 / 3.69 / 3.71 / 3.73 / 3.74.  All fields
 * big-endian.  Offsets are octet offsets into the 13-octet nonce.
 *
 * Network nonce (0x00):        type(1) CTL|TTL(1) SEQ(3) SRC(2) pad 0x0000(2) IVIndex(4)
 * Application/Device (0x01/2): type(1) ASZMIC|pad(1) SEQ(3) SRC(2) DST(2) IVIndex(4)
 * Proxy nonce (0x03):          type(1) pad 0x00(1) SEQ(3) SRC(2) pad 0x0000(2) IVIndex(4)
 * Proxy solicitation (0x04):   type(1) pad 0x00(1) SSEQ(3) SSRC(2) pad(6)  -- NO IV Index
 *
 * The last one is the trap: the proxy solicitation nonce has a SIX-octet
 * trailing pad and carries no IV Index at all, unlike the otherwise
 * identically shaped proxy nonce.  The specification states the reason
 * outright at .txt line ~34639: "The IV Index is not used to secure the
 * Solicitation PDU."
 *
 * Two other facts stated at .txt lines 9887-9893, verbatim:
 *   "The TTL field value is used within the network nonce but not within the
 *    application nonce, device nonce, or proxy nonce."
 *   "The DST field value is used within the application nonce and device nonce
 *    but not in the network nonce."
 * That asymmetry is what lets a relay decrement the TTL without invalidating
 * the upper transport MIC.
 */
#define	SPEC_EXTREF_MESH_NONCE_OFF_TYPE			0u
#define	SPEC_EXTREF_MESH_NONCE_OFF_SECOND_OCTET		1u
#define	SPEC_EXTREF_MESH_NONCE_OFF_SEQ			2u
#define	SPEC_EXTREF_MESH_NONCE_OFF_SRC			5u
#define	SPEC_EXTREF_MESH_NONCE_OFF_PAD_OR_DST		7u
#define	SPEC_EXTREF_MESH_NONCE_OFF_IV_INDEX		9u
#define	SPEC_EXTREF_MESH_NONCE_ASZMIC_BIT		0x80u	/* bit 7 of octet 1 */
#define	SPEC_EXTREF_MESH_SOL_NONCE_PAD_OCTETS		6u
#define	SPEC_EXTREF_MESH_SOL_NONCE_HAS_IV_INDEX		0

/*
 * Network layer obfuscation, Section 3.9.7.3, .txt lines 10482-10488,
 * reproduced verbatim:
 *   "Privacy Random=(EncDST || EncTransportPDU || NetMIC)[0-6]"
 *   "Privacy Plaintext=0x0000000000 || IV Index || Privacy Random"
 *   "PECB=e (PrivacyKey, Privacy Plaintext)"
 *   "ObfuscatedData=(CTL || TTL || SEQ || SRC) PECB[0-5]"   [XOR]
 * and .txt lines 10490-10494 give the identical Privacy Random and Privacy
 * Plaintext construction for the reverse direction -- i.e. the ENCRYPTED
 * payload is the Privacy Random on BOTH send and receive.
 */
#define	SPEC_EXTREF_MESH_PRIVACY_RANDOM_OCTETS		7u
#define	SPEC_EXTREF_MESH_PRIVACY_PLAINTEXT_ZERO_PAD	5u
#define	SPEC_EXTREF_MESH_PECB_USED_OCTETS		6u
#define	SPEC_EXTREF_MESH_OBFUSCATED_HEADER_OCTETS	6u

#endif /* SPEC_EXTREF_MESH_NET_CREDENTIALS_H */
