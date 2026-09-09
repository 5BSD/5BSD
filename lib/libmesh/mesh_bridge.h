/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Subnet Bridge (MshPRT_v1.1.1 Sections 3.4.6.3, 3.9.8,
 * 4.2.41-4.2.43, 4.3.11 and 4.4.9).
 *
 * A Subnet Bridge is a node that retransmits a Network PDU it received on one
 * subnet onto a DIFFERENT subnet, re-securing it with that subnet's network
 * credentials.  Three states govern it:
 *
 *   Subnet Bridge      (Section 4.2.41) 0x00 disabled / 0x01 enabled, default
 *                      disabled; 0x02-0xFF prohibited.
 *   Bridging Table     (Section 4.2.42) a list of entries, each pairing two
 *                      NetKey Indexes with two addresses and the directions
 *                      in which traffic between them may cross.
 *   Bridging Table Size (Section 4.2.43) a 2-octet maximum entry count that
 *                      "shall be at least 16".
 *
 * Forwarding rule (Section 3.4.6.3).  For a given Bridging Table state entry
 * the Network PDU is retransmitted using the NetKey identified by
 * NetKeyIndex2 when SRC == Address1, DST == Address2 and the PDU was secured
 * with NetKeyIndex1; and using the NetKey identified by NetKeyIndex1 when
 * SRC == Address2, DST == Address1, the PDU was secured with NetKeyIndex2 and
 * the entry's Directions value is 0x02.  The IV Index is unchanged and the TTL
 * is decremented by one, exactly as for a relay: a bridge re-secures a PDU, it
 * does not originate one, so SRC and SEQ are carried across untouched.
 *
 * Replay (Section 3.9.8).  "A Subnet Bridge node shall implement replay
 * protection for all Access and Transport Control messages that are sent to
 * bridged subnets [and] shall maintain the most recent IVISeq value for each
 * source address authorized to send messages to bridged subnets."  That is a
 * list distinct from the node's own replay protection list, which covers only
 * messages addressed to the node; mesh_rpl.h supplies its mechanics and the
 * network layer owns the storage.
 *
 * This module is the pure state + codec half: the Bridging Table container and
 * its operations, the forwarding decision, and the wire codec for the twelve
 * Bridge messages of Section 4.3.11.  No crypto, no I/O, no globals.  Every
 * codec returns 0 on success and -1 on failure with the output zeroed.
 *
 * Bridge messages "shall be encrypted and authenticated using the DevKey of
 * the Subnet Bridge node" (Section 4.3.11), and the access-layer security on
 * the Bridge Configuration Server model "shall use the device key"
 * (Section 4.4.9.1); enforcing that is the caller's job, not this codec's.
 */

#ifndef _MESH_BRIDGE_H_
#define _MESH_BRIDGE_H_

#include <stddef.h>
#include <stdint.h>

/* ----------------------------------------------------------------
 * Opcodes.  Bluetooth Assigned Numbers, cross-checked against the
 * verbatim Access message octets of MshPRT_v1.1.1 Section 8.12.
 * ---------------------------------------------------------------- */
#define	MESH_BRIDGE_OP_SUBNET_BRIDGE_GET	0x80B1
#define	MESH_BRIDGE_OP_SUBNET_BRIDGE_SET	0x80B2
#define	MESH_BRIDGE_OP_SUBNET_BRIDGE_STATUS	0x80B3
#define	MESH_BRIDGE_OP_TABLE_ADD		0x80B4
#define	MESH_BRIDGE_OP_TABLE_REMOVE		0x80B5
#define	MESH_BRIDGE_OP_TABLE_STATUS		0x80B6
#define	MESH_BRIDGE_OP_SUBNETS_GET		0x80B7
#define	MESH_BRIDGE_OP_SUBNETS_LIST		0x80B8
#define	MESH_BRIDGE_OP_TABLE_GET		0x80B9
#define	MESH_BRIDGE_OP_TABLE_LIST		0x80BA
#define	MESH_BRIDGE_OP_TABLE_SIZE_GET		0x80BB
#define	MESH_BRIDGE_OP_TABLE_SIZE_STATUS	0x80BC

/* SIG Model ID (Bluetooth Assigned Numbers, Mesh model identifiers). */
#define	MESH_MODEL_BRIDGE_CFG_SRV		0x0008
#define	MESH_MODEL_BRIDGE_CFG_CLI		0x0009

/* Subnet Bridge state values (Section 4.2.41, Table 4.69). */
#define	MESH_BRIDGE_DISABLED			0x00
#define	MESH_BRIDGE_ENABLED			0x01

/*
 * Directions field values (Section 4.2.42, Table 4.71).  0x00 and 0x03-0xFF
 * are prohibited in a Bridging Table state entry and in BRIDGING_TABLE_ADD;
 * 0x00 is however a legal Current_Directions value in BRIDGING_TABLE_STATUS
 * ("bridging is not allowed", Table 4.289) and is what a successful
 * BRIDGING_TABLE_REMOVE reports (Section 4.4.9.2.2).
 */
#define	MESH_BRIDGE_DIR_NONE			0x00
#define	MESH_BRIDGE_DIR_ONE_WAY			0x01
#define	MESH_BRIDGE_DIR_TWO_WAY			0x02

/*
 * Filter field values for BRIDGED_SUBNETS_GET / _LIST (Section 4.3.11.7,
 * Table 4.291).  Two bits.
 */
#define	MESH_BRIDGE_FILTER_ALL			0x00
#define	MESH_BRIDGE_FILTER_NETKEY1		0x01
#define	MESH_BRIDGE_FILTER_NETKEY2		0x02
#define	MESH_BRIDGE_FILTER_EITHER		0x03

/*
 * Bridging Table Size (Section 4.2.43): "shall be at least 16".  The state is
 * reported as a 2-octet value, so the constant is the reported size as well as
 * the capacity of the container below.
 */
#define	MESH_BRIDGE_TABLE_SIZE			16

/* One Bridging Table state entry (Section 4.2.42, Table 4.70). */
struct mesh_bridge_entry {
	uint8_t		directions;	/* Table 4.71 */
	uint16_t	net_idx1;	/* 12 bits */
	uint16_t	net_idx2;	/* 12 bits */
	uint16_t	addr1;
	uint16_t	addr2;
};

/*
 * The Bridging Table state.  "There is a single instance of a Bridging Table
 * state for a Subnet Bridge node" (Section 4.2.42), so one of these lives on
 * the node.  Entries keep insertion order, which is the order
 * BRIDGING_TABLE_LIST and BRIDGED_SUBNETS_LIST report and index with their
 * Start_Index fields.
 */
struct mesh_bridging_table {
	struct mesh_bridge_entry	entries[MESH_BRIDGE_TABLE_SIZE];
	size_t				n;
};

/* ----------------------------------------------------------------
 * State operations.
 * ---------------------------------------------------------------- */

/*
 * Validate the field values of a BRIDGING_TABLE_ADD entry against
 * Section 4.3.11.4: the two NetKey Indexes differ and fit 12 bits, the two
 * addresses differ, Address1 is a unicast address, Directions is 0x01 or
 * 0x02, Address2 is neither the unassigned address nor the all-nodes fixed
 * group address when Directions is 0x01, and Address2 is a unicast address
 * when Directions is 0x02.  Returns 1 when acceptable, 0 otherwise.
 */
int	mesh_bridge_entry_valid(const struct mesh_bridge_entry *e);

/*
 * Add or update an entry (Section 4.4.9.2.2).  An entry whose NetKeyIndex1,
 * NetKeyIndex2, Address1 and Address2 all match has its Directions field
 * overwritten; otherwise a new entry is appended.  Returns 0 on success and
 * -1 when the table is full (the Insufficient Resources error condition of
 * Table 4.359).
 */
int	mesh_bridge_table_add(struct mesh_bridging_table *t,
	    const struct mesh_bridge_entry *e);

/*
 * Remove entries (Section 4.4.9.2.2).  An entry is removed when its
 * NetKeyIndex1 and NetKeyIndex2 match and each of Address1 / Address2 either
 * matches the corresponding argument or the argument is the unassigned
 * address (a wildcard).  Returns the number of entries removed.
 */
size_t	mesh_bridge_table_remove(struct mesh_bridging_table *t,
	    uint16_t net_idx1, uint16_t net_idx2, uint16_t addr1,
	    uint16_t addr2);

/*
 * Binding with the NetKey List state (Section 4.2.42.1): when a NetKey is
 * deleted, every entry naming its NetKey Index in either position is removed.
 * Returns the number of entries removed.
 */
size_t	mesh_bridge_table_remove_netkey(struct mesh_bridging_table *t,
	    uint16_t net_idx);

/*
 * Forwarding decision (Section 3.4.6.3).  Given a received Network PDU's SRC,
 * DST and the NetKey Index of the subnet that secured it, decide whether the
 * PDU is to be bridged and, if so, under which NetKey Index it must be
 * retransmitted.  Returns 1 and sets *out_net_idx when a Bridging Table state
 * entry authorises the crossing, 0 otherwise.  The first matching entry wins;
 * duplicate pairs with conflicting Directions cannot both authorise the same
 * (SRC, DST, subnet) triple, so the order is immaterial to the verdict.
 */
int	mesh_bridge_forward_net_idx(const struct mesh_bridging_table *t,
	    uint16_t src, uint16_t dst, uint16_t rx_net_idx,
	    uint16_t *out_net_idx);

/* ----------------------------------------------------------------
 * Message codec (Section 4.3.11).  Each _build() emits the complete Access
 * PDU (opcode plus parameters) and each _parse() consumes one.
 * ---------------------------------------------------------------- */

/*
 * SUBNET_BRIDGE_SET (Table 4.284) and SUBNET_BRIDGE_STATUS (Table 4.285):
 * opcode plus a one-octet state.  The builder rejects a prohibited state
 * value (0x02-0xFF); so does the parser, which is what makes a
 * SUBNET_BRIDGE_SET carrying a prohibited value fail rather than latch.
 */
int	mesh_bridge_subnet_build(uint32_t opcode, uint8_t state, uint8_t *out,
	    size_t *outlen);
int	mesh_bridge_subnet_parse(const uint8_t *in, size_t inlen,
	    uint8_t *state);

/*
 * BRIDGING_TABLE_ADD (Table 4.286): Directions, the packed NetKey Index pair
 * and the two addresses.  The parser fills every field and does NOT apply
 * Section 4.3.11.4's value rules; mesh_bridge_entry_valid() does, so a server
 * can answer a malformed-but-parseable message with the right Status.
 */
int	mesh_bridge_table_add_build(const struct mesh_bridge_entry *e,
	    uint8_t *out, size_t *outlen);
int	mesh_bridge_table_add_parse(const uint8_t *in, size_t inlen,
	    struct mesh_bridge_entry *e);

/*
 * BRIDGING_TABLE_REMOVE (Table 4.287): the packed NetKey Index pair and the
 * two addresses, no Directions field.
 */
int	mesh_bridge_table_remove_build(uint16_t net_idx1, uint16_t net_idx2,
	    uint16_t addr1, uint16_t addr2, uint8_t *out, size_t *outlen);
int	mesh_bridge_table_remove_parse(const uint8_t *in, size_t inlen,
	    uint16_t *net_idx1, uint16_t *net_idx2, uint16_t *addr1,
	    uint16_t *addr2);

/* BRIDGING_TABLE_STATUS (Table 4.288). */
struct mesh_bridge_table_status {
	uint8_t		status;			/* Section 4.3.14 status code */
	uint8_t		current_directions;	/* Table 4.289 */
	uint16_t	net_idx1;
	uint16_t	net_idx2;
	uint16_t	addr1;
	uint16_t	addr2;
};

int	mesh_bridge_table_status_build(const struct mesh_bridge_table_status *s,
	    uint8_t *out, size_t *outlen);
int	mesh_bridge_table_status_parse(const uint8_t *in, size_t inlen,
	    struct mesh_bridge_table_status *s);

/*
 * BRIDGED_SUBNETS_GET (Table 4.290) and BRIDGED_SUBNETS_LIST (Table 4.292).
 * The first octet packs Filter in bits 1:0, two prohibited bits and the low
 * nibble of NetKeyIndex in bits 7:4; the second octet holds NetKeyIndex bits
 * 11:4.  The list body is N entries of a 12/12-bit NetKey Index pair
 * (Table 4.293), so 3 octets each.
 */
struct mesh_bridge_subnets_pair {
	uint16_t	net_idx1;
	uint16_t	net_idx2;
};

int	mesh_bridged_subnets_get_build(uint8_t filter, uint16_t net_idx,
	    uint8_t start_index, uint8_t *out, size_t *outlen);
int	mesh_bridged_subnets_get_parse(const uint8_t *in, size_t inlen,
	    uint8_t *filter, uint16_t *net_idx, uint8_t *start_index);
int	mesh_bridged_subnets_list_build(uint8_t filter, uint16_t net_idx,
	    uint8_t start_index, const struct mesh_bridge_subnets_pair *pairs,
	    size_t n_pairs, uint8_t *out, size_t *outlen);
int	mesh_bridged_subnets_list_parse(const uint8_t *in, size_t inlen,
	    uint8_t *filter, uint16_t *net_idx, uint8_t *start_index,
	    struct mesh_bridge_subnets_pair *pairs, size_t max_pairs,
	    size_t *n_pairs);

/*
 * Extract the filtered, de-duplicated set of NetKey Index pairs a
 * BRIDGED_SUBNETS_LIST must report (Section 4.4.9.2.2).  Entries are visited
 * in Bridging Table order, the Filter field of Table 4.291 selects them, and
 * the result starts at start_index counting filtered pairs from zero.  Returns
 * the number of pairs written to pairs[].
 */
size_t	mesh_bridge_subnets_filter(const struct mesh_bridging_table *t,
	    uint8_t filter, uint16_t net_idx, uint8_t start_index,
	    struct mesh_bridge_subnets_pair *pairs, size_t max_pairs);

/*
 * BRIDGING_TABLE_GET (Table 4.294) and BRIDGING_TABLE_LIST (Table 4.295).
 * Start_Index is 2 octets here, not 1.  The list body is N entries of
 * Address1, Address2, Directions (Table 4.296), so 5 octets each.
 */
struct mesh_bridge_addr_entry {
	uint16_t	addr1;
	uint16_t	addr2;
	uint8_t		directions;
};

int	mesh_bridging_table_get_build(uint16_t net_idx1, uint16_t net_idx2,
	    uint16_t start_index, uint8_t *out, size_t *outlen);
int	mesh_bridging_table_get_parse(const uint8_t *in, size_t inlen,
	    uint16_t *net_idx1, uint16_t *net_idx2, uint16_t *start_index);
int	mesh_bridging_table_list_build(uint8_t status, uint16_t net_idx1,
	    uint16_t net_idx2, uint16_t start_index,
	    const struct mesh_bridge_addr_entry *addrs, size_t n_addrs,
	    uint8_t *out, size_t *outlen);
int	mesh_bridging_table_list_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, uint16_t *net_idx1, uint16_t *net_idx2,
	    uint16_t *start_index, struct mesh_bridge_addr_entry *addrs,
	    size_t max_addrs, size_t *n_addrs);

/*
 * Extract the Bridged_Addresses_List a BRIDGING_TABLE_LIST must report
 * (Section 4.4.9.2.2): the Bridging Table state entries associated with the
 * (NetKeyIndex1, NetKeyIndex2) pair, starting at start_index counting
 * filtered entries from zero.  Returns the number written.
 */
size_t	mesh_bridging_table_filter(const struct mesh_bridging_table *t,
	    uint16_t net_idx1, uint16_t net_idx2, uint16_t start_index,
	    struct mesh_bridge_addr_entry *addrs, size_t max_addrs);

/* BRIDGING_TABLE_SIZE_STATUS (Table 4.298): a 2-octet size, little-endian. */
int	mesh_bridge_table_size_status_build(uint16_t size, uint8_t *out,
	    size_t *outlen);
int	mesh_bridge_table_size_status_parse(const uint8_t *in, size_t inlen,
	    uint16_t *size);

#endif /* _MESH_BRIDGE_H_ */
