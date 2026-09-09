/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the meshd Subnet Bridge wiring (MshPRT_v1.1.1 Sections 3.4.6.3,
 * 3.9.8, 4.2.41-4.2.43, 4.3.11 and 4.4.9).
 *
 * Every case drives a meshd ENTRY POINT, never a libmesh function directly:
 *
 *   meshd_foundation_recv()  the Bridge Configuration Server's message
 *                            dispatch - the same entry a DevKey-sealed Bridge
 *                            message reaches over the air;
 *   meshd_ctl_exec_client()  the "bridge" control verbs meshctl(8) sends;
 *   meshd_bearer_rx()        a secured Network PDU arriving from the bearer,
 *                            which is where the forwarding behaviour lives;
 *   meshd_persist_save/load  the on-disk state round trip.
 *
 * Expected values are taken from the specification text, and the wire vectors
 * from the verbatim "Access message" octets of MshPRT_v1.1.1 Section 8.12
 * ("Subnet bridging sample data").  BlueZ 5.87's mesh/ subtree contains no
 * Subnet Bridge implementation at all - not a single occurrence of "bridge" -
 * so there is no second implementation to cross-check against and the
 * specification text is the only adjudicator.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mesh_test_heap.h"
#include "meshd.h"
#include "meshd_persist.h"
#include "mesh_bridge.h"
#include "mesh_cfg_model.h"
#include "mesh_transport.h"

/* ================================================================
 * Fixtures.
 * ================================================================ */

#define	BR_NETKEY_A	0x33	/* subnet 0 (the bridge's primary) */
#define	BR_NETKEY_B	0x44	/* subnet 1 (the bridged-to subnet) */
#define	BR_APPKEY	0x55	/* one AppKey, same octets on both subnets */

static void
br_provision(struct meshd_node *nd, struct meshd_config *cfg, uint16_t addr,
    uint8_t netkey_fill, uint16_t net_idx)
{

	meshd_config_defaults(cfg);
	memset(cfg->netkey, netkey_fill, 16);
	cfg->have_netkey = 1;
	memset(cfg->appkey, BR_APPKEY, 16);
	cfg->have_appkey = 1;
	cfg->netkey_index = net_idx;
	cfg->appkey_index = 0;
	cfg->unicast_addr = addr;
	cfg->iv_index = 0;
	cfg->default_ttl = 7;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, cfg));
}

/*
 * Run one Access PDU through the node's own foundation-model dispatch, which
 * is where the Bridge Configuration Server's handlers hang.  Returns
 * meshd_foundation_recv()'s value: 1 when a Status was produced.
 */
static int
br_recv(struct meshd_node *nd, const uint8_t *req, size_t req_len, uint8_t *st,
    size_t *st_len)
{

	*st_len = 0;
	return (meshd_foundation_recv(nd, req, req_len, st,
	    MESH_ACCESS_PAYLOAD_MAX, st_len));
}

/* Give the node a second subnet through the Config Server's NetKey Add. */
static void
br_add_netkey(struct meshd_node *nd, uint16_t net_idx, uint8_t fill)
{
	struct mesh_cfg_netkey nk;
	uint8_t req[64], st[MESH_ACCESS_PAYLOAD_MAX];
	uint16_t got_idx;
	uint8_t status;
	size_t req_len, st_len;

	memset(&nk, 0, sizeof(nk));
	nk.net_idx = net_idx;
	memset(nk.key, fill, sizeof(nk.key));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD, &nk,
	    req, &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(st, st_len, &status,
	    &got_idx));
	ATF_REQUIRE_EQ(MESH_CFG_SUCCESS, status);
	ATF_REQUIRE_EQ(net_idx, got_idx);
}

/* BRIDGING_TABLE_ADD through the server; returns the parsed Status. */
static void
br_table_add(struct meshd_node *nd, uint8_t dir, uint16_t n1, uint16_t n2,
    uint16_t a1, uint16_t a2, struct mesh_bridge_table_status *out)
{
	struct mesh_bridge_entry e;
	uint8_t req[64], st[MESH_ACCESS_PAYLOAD_MAX];
	size_t req_len, st_len;

	memset(&e, 0, sizeof(e));
	e.directions = dir;
	e.net_idx1 = n1;
	e.net_idx2 = n2;
	e.addr1 = a1;
	e.addr2 = a2;
	ATF_REQUIRE_EQ(0, mesh_bridge_table_add_build(&e, req, &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_bridge_table_status_parse(st, st_len, out));
}

/* Enable subnet bridge functionality through SUBNET_BRIDGE_SET. */
static void
br_enable(struct meshd_node *nd, uint8_t state)
{
	uint8_t req[8], st[MESH_ACCESS_PAYLOAD_MAX], got;
	size_t req_len, st_len;

	ATF_REQUIRE_EQ(0, mesh_bridge_subnet_build(
	    MESH_BRIDGE_OP_SUBNET_BRIDGE_SET, state, req, &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_bridge_subnet_parse(st, st_len, &got));
	ATF_REQUIRE_EQ(state, got);
}

static int
br_verb(struct meshd_node *nd, int argc, const char **argv, char *reply,
    size_t reply_max)
{
	char *av[8];
	int i;

	ATF_REQUIRE(argc <= (int)nitems(av));
	for (i = 0; i < argc; i++)
		av[i] = (char *)(uintptr_t)argv[i];
	return (meshd_ctl_exec_client(nd, NULL, argc, av, reply, reply_max));
}

/* ================================================================
 * Capture-and-pump bearer (mirrors meshd_friendship_test.c).
 * ================================================================ */
#define	BR_MAXCAP	32
static struct br_capframe {
	uint8_t			buf[64];
	size_t			len;
	enum meshd_pdu_class	cls;
} g_cap[BR_MAXCAP];
static size_t g_ncap;

static int
br_cap_tx(void *arg, enum meshd_pdu_class cls, const uint8_t *pdu, size_t len)
{

	(void)arg;
	if (g_ncap < BR_MAXCAP && len <= sizeof(g_cap[0].buf)) {
		memcpy(g_cap[g_ncap].buf, pdu, len);
		g_cap[g_ncap].len = len;
		g_cap[g_ncap].cls = cls;
		g_ncap++;
	}
	return (0);
}

/*
 * Deliver every captured Network PDU to `to` and return the number `to`
 * delivered to a model.  The capture buffer is snapshotted first, so PDUs the
 * receiving node itself transmits (a relay, or a bridged copy) accumulate for
 * the next pump instead of being consumed by this one.
 */
static int
br_pump(struct meshd_node *to)
{
	struct br_capframe snap[BR_MAXCAP];
	size_t n, i;
	int delivered = 0;

	n = g_ncap;
	memcpy(snap, g_cap, n * sizeof(snap[0]));
	g_ncap = 0;
	for (i = 0; i < n; i++)
		if (snap[i].cls == MESHD_PDU_NET &&
		    meshd_bearer_rx(to, snap[i].buf, snap[i].len) == 1)
			delivered++;
	return (delivered);
}

/* ================================================================
 * 4.2.41 Subnet Bridge state: Get / Set / Status, and the engine sync.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_subnet_state);
ATF_TC_BODY(bridge_subnet_state, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	uint8_t req[8], st[MESH_ACCESS_PAYLOAD_MAX], state;
	size_t req_len, st_len;

	br_provision(nd, &cfg, 0x0100, BR_NETKEY_A, 0);

	/*
	 * Section 4.2.41: "The default value of the Subnet Bridge state shall
	 * be 0x00."  SUBNET_BRIDGE_GET is a bare opcode (Table 4.283).
	 */
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    MESH_BRIDGE_OP_SUBNET_BRIDGE_GET, NULL, 0, req, &req_len));
	ATF_CHECK_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_bridge_subnet_parse(st, st_len, &state));
	ATF_CHECK_EQ(MESH_BRIDGE_DISABLED, state);
	ATF_CHECK_EQ(0, nd->self->bridge_enabled);

	/*
	 * Section 8.12.3: the SUBNET_BRIDGE_STATUS Access message for the
	 * enabled state is exactly 80 b3 01.
	 */
	br_enable(nd, MESH_BRIDGE_ENABLED);
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    MESH_BRIDGE_OP_SUBNET_BRIDGE_GET, NULL, 0, req, &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(3u, st_len);
	ATF_CHECK_EQ(0x80, st[0]);
	ATF_CHECK_EQ(0xb3, st[1]);
	ATF_CHECK_EQ(0x01, st[2]);

	/* Section 4.4.9.2.1 + the engine sync: the state reaches the node. */
	ATF_CHECK_EQ(MESH_BRIDGE_ENABLED, nd->db.subnet_bridge);
	ATF_CHECK_EQ(1, nd->self->bridge_enabled);

	/*
	 * Table 4.69: 0x02-0xFF are prohibited.  A SUBNET_BRIDGE_SET carrying
	 * one is not answered and must not latch.
	 */
	req[0] = 0x80;
	req[1] = 0xb2;
	req[2] = 0x02;
	ATF_CHECK_EQ(-1, br_recv(nd, req, 3, st, &st_len));
	ATF_CHECK_EQ(MESH_BRIDGE_ENABLED, nd->db.subnet_bridge);

	/* Disabling propagates too. */
	br_enable(nd, MESH_BRIDGE_DISABLED);
	ATF_CHECK_EQ(0, nd->self->bridge_enabled);
}

/* ================================================================
 * 4.3.11.4 / 4.4.9.2.2 BRIDGING_TABLE_ADD, including both error conditions
 * of Table 4.359 and the Section 8.12.4 wire vector.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_table_add);
ATF_TC_BODY(bridge_table_add, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct mesh_bridge_table_status s;
	struct mesh_bridge_entry e;
	uint8_t req[64], st[MESH_ACCESS_PAYLOAD_MAX];
	size_t req_len, st_len, i;

	br_provision(nd, &cfg, 0x0100, BR_NETKEY_A, 0);
	br_add_netkey(nd, 1, BR_NETKEY_B);

	/*
	 * Section 8.12.4: Directions 0x02, NetKeyIndex1 0x123, NetKeyIndex2
	 * 0x456, Address1 0x0aaa, Address2 0x0bbb encodes as
	 * 80 b4 02 23 61 45 aa 0a bb 0b.  Neither NetKey Index is known to this
	 * node, so Table 4.359's "Either NetKeyIndex1 or NetKeyIndex2 is not
	 * known" applies: Invalid NetKey Index, with Current_Directions set to
	 * the received Directions and every other field echoed.
	 */
	memset(&e, 0, sizeof(e));
	e.directions = MESH_BRIDGE_DIR_TWO_WAY;
	e.net_idx1 = 0x123;
	e.net_idx2 = 0x456;
	e.addr1 = 0x0aaa;
	e.addr2 = 0x0bbb;
	ATF_REQUIRE_EQ(0, mesh_bridge_table_add_build(&e, req, &req_len));
	ATF_REQUIRE_EQ(10u, req_len);
	{
		static const uint8_t want[10] = {
			0x80, 0xb4, 0x02, 0x23, 0x61, 0x45,
			0xaa, 0x0a, 0xbb, 0x0b
		};
		ATF_CHECK_EQ(0, memcmp(req, want, sizeof(want)));
	}
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_bridge_table_status_parse(st, st_len, &s));
	ATF_CHECK_EQ(MESH_CFG_INVALID_NETKEY_INDEX, s.status);
	ATF_CHECK_EQ(MESH_BRIDGE_DIR_TWO_WAY, s.current_directions);
	ATF_CHECK_EQ(0x123, s.net_idx1);
	ATF_CHECK_EQ(0x456, s.net_idx2);
	ATF_CHECK_EQ(0x0aaa, s.addr1);
	ATF_CHECK_EQ(0x0bbb, s.addr2);
	ATF_CHECK_EQ(0u, nd->db.bridging.n);

	/* Both NetKey Indexes known: Success, entry added, engine synced. */
	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0001, 0x0201, &s);
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, s.status);
	ATF_CHECK_EQ(MESH_BRIDGE_DIR_TWO_WAY, s.current_directions);
	ATF_CHECK_EQ(1u, nd->db.bridging.n);
	ATF_CHECK_EQ(1u, nd->self->bridge_table.n);
	ATF_CHECK_EQ(0x0201, nd->self->bridge_table.entries[0].addr2);

	/*
	 * Section 4.4.9.2.2: an entry whose NetKeyIndex1, NetKeyIndex2,
	 * Address1 and Address2 all match is UPDATED in place - the Directions
	 * field is overwritten and no second entry appears.
	 */
	br_table_add(nd, MESH_BRIDGE_DIR_ONE_WAY, 0, 1, 0x0001, 0x0201, &s);
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, s.status);
	ATF_CHECK_EQ(1u, nd->db.bridging.n);
	ATF_CHECK_EQ(MESH_BRIDGE_DIR_ONE_WAY,
	    nd->db.bridging.entries[0].directions);
	ATF_CHECK_EQ(MESH_BRIDGE_DIR_ONE_WAY,
	    nd->self->bridge_table.entries[0].directions);

	/*
	 * Table 4.359 "There is not sufficient memory to add a Bridging Table
	 * state entry" -> Insufficient Resources.  Section 4.2.43 requires the
	 * Bridging Table Size state to be at least 16, so filling it takes at
	 * least 16 distinct entries.
	 */
	ATF_REQUIRE(MESH_BRIDGE_TABLE_SIZE >= 16);
	for (i = nd->db.bridging.n; i < MESH_BRIDGE_TABLE_SIZE; i++) {
		br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 1,
		    (uint16_t)(0x0300 + i), 0x0201, &s);
		ATF_REQUIRE_EQ(MESH_CFG_SUCCESS, s.status);
	}
	ATF_CHECK_EQ((size_t)MESH_BRIDGE_TABLE_SIZE, nd->db.bridging.n);
	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0400, 0x0201, &s);
	ATF_CHECK_EQ(MESH_CFG_INSUFFICIENT_RESOURCES, s.status);
	ATF_CHECK_EQ(MESH_BRIDGE_DIR_TWO_WAY, s.current_directions);
	ATF_CHECK_EQ((size_t)MESH_BRIDGE_TABLE_SIZE, nd->db.bridging.n);
}

/* ================================================================
 * 4.3.11.4 prohibited field values.  Table 4.359 defines no Status Code for
 * them, so the message is ignored - and nothing is added.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_table_add_prohibited);
ATF_TC_BODY(bridge_table_add_prohibited, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct mesh_bridge_entry e;
	uint8_t req[64], st[MESH_ACCESS_PAYLOAD_MAX];
	size_t req_len, st_len;

	br_provision(nd, &cfg, 0x0100, BR_NETKEY_A, 0);
	br_add_netkey(nd, 1, BR_NETKEY_B);

#define	TRY(dirs, n1, n2, a1, a2)					\
	do {								\
		memset(&e, 0, sizeof(e));				\
		e.directions = (dirs);					\
		e.net_idx1 = (n1);					\
		e.net_idx2 = (n2);					\
		e.addr1 = (a1);						\
		e.addr2 = (a2);						\
		ATF_REQUIRE_EQ(0, mesh_bridge_table_add_build(&e, req,	\
		    &req_len));						\
		ATF_CHECK_EQ(-1, br_recv(nd, req, req_len, st, &st_len));\
		ATF_CHECK_EQ(0u, nd->db.bridging.n);			\
	} while (0)

	/* Table 4.71: Directions 0x00 and 0x03-0xFF are prohibited. */
	TRY(0x00, 0, 1, 0x0001, 0x0201);
	TRY(0x03, 0, 1, 0x0001, 0x0201);
	/* "The NetKeyIndex1 and NetKeyIndex2 fields shall have different values." */
	TRY(MESH_BRIDGE_DIR_TWO_WAY, 1, 1, 0x0001, 0x0201);
	/* "The Address1 and Address2 fields shall have different values." */
	TRY(MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0001, 0x0001);
	/* "The Address1 field value shall be a unicast address." */
	TRY(MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0xC001, 0x0201);
	TRY(MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0000, 0x0201);
	/*
	 * "If the Directions field value is 0x01, the unassigned address and
	 * the all-nodes fixed group address are prohibited values for the
	 * Address2 field."
	 */
	TRY(MESH_BRIDGE_DIR_ONE_WAY, 0, 1, 0x0001, 0x0000);
	TRY(MESH_BRIDGE_DIR_ONE_WAY, 0, 1, 0x0001, 0xFFFF);
	/*
	 * "If the Directions field value is 0x02, then the Address2 field value
	 * shall be a unicast address."
	 */
	TRY(MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0001, 0xC000);
#undef	TRY

	/* A group Address2 IS legal with Directions 0x01 (only 0x02 forbids it). */
	memset(&e, 0, sizeof(e));
	e.directions = MESH_BRIDGE_DIR_ONE_WAY;
	e.net_idx1 = 0;
	e.net_idx2 = 1;
	e.addr1 = 0x0001;
	e.addr2 = 0xC000;
	ATF_REQUIRE_EQ(0, mesh_bridge_table_add_build(&e, req, &req_len));
	ATF_CHECK_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_CHECK_EQ(1u, nd->db.bridging.n);
}

/* ================================================================
 * 4.3.11.5 / 4.4.9.2.2 BRIDGING_TABLE_REMOVE, including the three wildcard
 * forms and the Current_Directions == 0x00 requirement.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_table_remove);
ATF_TC_BODY(bridge_table_remove, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct mesh_bridge_table_status s;
	uint8_t req[64], st[MESH_ACCESS_PAYLOAD_MAX];
	size_t req_len, st_len;

	br_provision(nd, &cfg, 0x0100, BR_NETKEY_A, 0);
	br_add_netkey(nd, 1, BR_NETKEY_B);

	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0001, 0x0201, &s);
	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0001, 0x0202, &s);
	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0002, 0x0201, &s);
	ATF_REQUIRE_EQ(3u, nd->db.bridging.n);

	/* Exact match removes exactly one, and reports Current_Directions 0x00. */
	ATF_REQUIRE_EQ(0, mesh_bridge_table_remove_build(0, 1, 0x0001, 0x0201,
	    req, &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_bridge_table_status_parse(st, st_len, &s));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, s.status);
	ATF_CHECK_EQ(MESH_BRIDGE_DIR_NONE, s.current_directions);
	ATF_CHECK_EQ(0x0001, s.addr1);
	ATF_CHECK_EQ(0x0201, s.addr2);
	ATF_CHECK_EQ(2u, nd->db.bridging.n);
	ATF_CHECK_EQ(2u, nd->self->bridge_table.n);

	/*
	 * "The values of the NetKeyIndex1, NetKeyIndex2, and Address1 fields in
	 * the entry match ... and the Address2 field value in the message is
	 * the unassigned address": removes 0x0001 -> 0x0202.
	 */
	ATF_REQUIRE_EQ(0, mesh_bridge_table_remove_build(0, 1, 0x0001, 0x0000,
	    req, &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_bridge_table_status_parse(st, st_len, &s));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, s.status);
	ATF_CHECK_EQ(1u, nd->db.bridging.n);
	ATF_CHECK_EQ(0x0002, nd->db.bridging.entries[0].addr1);

	/* Both addresses unassigned: removes every entry for the subnet pair. */
	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0003, 0x0203, &s);
	ATF_REQUIRE_EQ(2u, nd->db.bridging.n);
	ATF_REQUIRE_EQ(0, mesh_bridge_table_remove_build(0, 1, 0x0000, 0x0000,
	    req, &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_bridge_table_status_parse(st, st_len, &s));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, s.status);
	ATF_CHECK_EQ(0u, nd->db.bridging.n);
	ATF_CHECK_EQ(0u, nd->self->bridge_table.n);

	/* Table 4.360: an unknown NetKey Index -> Invalid NetKey Index. */
	ATF_REQUIRE_EQ(0, mesh_bridge_table_remove_build(0, 9, 0x0001, 0x0201,
	    req, &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_bridge_table_status_parse(st, st_len, &s));
	ATF_CHECK_EQ(MESH_CFG_INVALID_NETKEY_INDEX, s.status);
	ATF_CHECK_EQ(MESH_BRIDGE_DIR_NONE, s.current_directions);

	/*
	 * Section 4.3.11.5: "The Address1 field value shall be the unassigned
	 * address or a unicast address" and "The Address2 field value shall not
	 * be the all-nodes fixed group address."  Both are ignored, not
	 * answered.
	 */
	ATF_REQUIRE_EQ(0, mesh_bridge_table_remove_build(0, 1, 0xC001, 0x0201,
	    req, &req_len));
	ATF_CHECK_EQ(-1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_bridge_table_remove_build(0, 1, 0x0001, 0xFFFF,
	    req, &req_len));
	ATF_CHECK_EQ(-1, br_recv(nd, req, req_len, st, &st_len));
}

/* ================================================================
 * 4.3.11.7 / 4.3.11.8 BRIDGED_SUBNETS_GET -> BRIDGED_SUBNETS_LIST: the four
 * Filter values of Table 4.291, uniqueness, and Start_Index.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_subnets_list);
ATF_TC_BODY(bridge_subnets_list, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct mesh_bridge_table_status s;
	struct mesh_bridge_subnets_pair pairs[MESH_BRIDGE_TABLE_SIZE];
	uint8_t req[64], st[MESH_ACCESS_PAYLOAD_MAX];
	uint8_t filter, start;
	uint16_t netidx;
	size_t req_len, st_len, n;

	br_provision(nd, &cfg, 0x0100, BR_NETKEY_A, 0);
	br_add_netkey(nd, 1, BR_NETKEY_B);
	br_add_netkey(nd, 2, 0x66);

	/* Two entries share (0,1) - the pair must be reported once. */
	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0001, 0x0201, &s);
	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0002, 0x0202, &s);
	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 2, 0x0003, 0x0303, &s);
	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 2, 1, 0x0304, 0x0204, &s);
	ATF_REQUIRE_EQ(4u, nd->db.bridging.n);

#define	SUBNETS(f, ni, si)						\
	do {								\
		ATF_REQUIRE_EQ(0, mesh_bridged_subnets_get_build((f),	\
		    (ni), (si), req, &req_len));			\
		ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st,		\
		    &st_len));						\
		ATF_REQUIRE_EQ(0, mesh_bridged_subnets_list_parse(st,	\
		    st_len, &filter, &netidx, &start, pairs,		\
		    nitems(pairs), &n));				\
		ATF_CHECK_EQ((f), filter);				\
		ATF_CHECK_EQ((ni), netidx);				\
		ATF_CHECK_EQ((si), start);				\
	} while (0)

	/* 0b00: "Report all pairs of NetKey Indexes", de-duplicated. */
	SUBNETS(MESH_BRIDGE_FILTER_ALL, 0, 0);
	ATF_CHECK_EQ(3u, n);
	ATF_CHECK_EQ(0, pairs[0].net_idx1);
	ATF_CHECK_EQ(1, pairs[0].net_idx2);
	ATF_CHECK_EQ(0, pairs[1].net_idx1);
	ATF_CHECK_EQ(2, pairs[1].net_idx2);
	ATF_CHECK_EQ(2, pairs[2].net_idx1);
	ATF_CHECK_EQ(1, pairs[2].net_idx2);

	/* 0b01: NetKeyIndex1 matches the NetKeyIndex field. */
	SUBNETS(MESH_BRIDGE_FILTER_NETKEY1, 2, 0);
	ATF_CHECK_EQ(1u, n);
	ATF_CHECK_EQ(2, pairs[0].net_idx1);
	ATF_CHECK_EQ(1, pairs[0].net_idx2);

	/* 0b10: NetKeyIndex2 matches. */
	SUBNETS(MESH_BRIDGE_FILTER_NETKEY2, 1, 0);
	ATF_CHECK_EQ(2u, n);
	ATF_CHECK_EQ(0, pairs[0].net_idx1);
	ATF_CHECK_EQ(2, pairs[1].net_idx1);

	/* 0b11: either position matches. */
	SUBNETS(MESH_BRIDGE_FILTER_EITHER, 2, 0);
	ATF_CHECK_EQ(2u, n);

	/*
	 * Start_Index counts FILTERED pairs from zero (Section 4.4.9.2.2), so
	 * start 1 over the unfiltered set drops the first pair only.
	 */
	SUBNETS(MESH_BRIDGE_FILTER_ALL, 0, 1);
	ATF_CHECK_EQ(2u, n);
	ATF_CHECK_EQ(0, pairs[0].net_idx1);
	ATF_CHECK_EQ(2, pairs[0].net_idx2);

	/* A start beyond the filtered set yields an empty (but valid) list. */
	SUBNETS(MESH_BRIDGE_FILTER_ALL, 0, 9);
	ATF_CHECK_EQ(0u, n);
	ATF_CHECK_EQ(5u, st_len);	/* opcode + filter/netidx + start */
#undef	SUBNETS

	/*
	 * Table 4.290 has a 2-bit Prohibited field; a message setting it is
	 * malformed and is not answered.
	 */
	req[0] = 0x80;
	req[1] = 0xb7;
	req[2] = 0x04;			/* Prohibited bits set */
	req[3] = 0x00;
	req[4] = 0x00;
	ATF_CHECK_EQ(-1, br_recv(nd, req, 5, st, &st_len));
}

/* ================================================================
 * 4.3.11.9 / 4.3.11.10 BRIDGING_TABLE_GET -> BRIDGING_TABLE_LIST.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_table_list);
ATF_TC_BODY(bridge_table_list, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct mesh_bridge_table_status s;
	struct mesh_bridge_addr_entry addrs[MESH_BRIDGE_TABLE_SIZE];
	uint8_t req[64], st[MESH_ACCESS_PAYLOAD_MAX], status;
	uint16_t n1, n2, start;
	size_t req_len, st_len, n;

	br_provision(nd, &cfg, 0x0100, BR_NETKEY_A, 0);
	br_add_netkey(nd, 1, BR_NETKEY_B);
	br_add_netkey(nd, 2, 0x66);

	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0aaa, 0x0bbb, &s);
	br_table_add(nd, MESH_BRIDGE_DIR_ONE_WAY, 0, 1, 0x0aaa, 0x0ccc, &s);
	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 2, 0x0ddd, 0x0ccc, &s);

	/* Only the entries of the requested subnet pair are reported. */
	ATF_REQUIRE_EQ(0, mesh_bridging_table_get_build(0, 1, 0, req,
	    &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_bridging_table_list_parse(st, st_len, &status,
	    &n1, &n2, &start, addrs, nitems(addrs), &n));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(0, n1);
	ATF_CHECK_EQ(1, n2);
	ATF_CHECK_EQ(0, start);
	ATF_CHECK_EQ(2u, n);
	/* Table 4.296: Address1, Address2, Directions. */
	ATF_CHECK_EQ(0x0aaa, addrs[0].addr1);
	ATF_CHECK_EQ(0x0bbb, addrs[0].addr2);
	ATF_CHECK_EQ(MESH_BRIDGE_DIR_TWO_WAY, addrs[0].directions);
	ATF_CHECK_EQ(0x0ccc, addrs[1].addr2);
	ATF_CHECK_EQ(MESH_BRIDGE_DIR_ONE_WAY, addrs[1].directions);

	/* Start_Index is zero-based over the FILTERED entries. */
	ATF_REQUIRE_EQ(0, mesh_bridging_table_get_build(0, 1, 1, req,
	    &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_bridging_table_list_parse(st, st_len, &status,
	    &n1, &n2, &start, addrs, nitems(addrs), &n));
	ATF_CHECK_EQ(1, start);
	ATF_CHECK_EQ(1u, n);
	ATF_CHECK_EQ(0x0ccc, addrs[0].addr2);

	/*
	 * Table 4.360 applies to BRIDGING_TABLE_GET: an unknown NetKey Index
	 * gives Invalid NetKey Index, and "the Bridged_Addresses_List field
	 * value shall be empty" (Section 4.4.9.2.2).
	 */
	ATF_REQUIRE_EQ(0, mesh_bridging_table_get_build(0, 9, 0, req,
	    &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_bridging_table_list_parse(st, st_len, &status,
	    &n1, &n2, &start, addrs, nitems(addrs), &n));
	ATF_CHECK_EQ(MESH_CFG_INVALID_NETKEY_INDEX, status);
	ATF_CHECK_EQ(0u, n);
	ATF_CHECK_EQ(8u, st_len);	/* opcode(2) status(1) pair(3) start(2) */
}

/* ================================================================
 * 4.2.43 / 4.3.11.11 Bridging Table Size.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_table_size);
ATF_TC_BODY(bridge_table_size, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	uint8_t req[8], st[MESH_ACCESS_PAYLOAD_MAX];
	uint16_t size;
	size_t req_len, st_len;

	br_provision(nd, &cfg, 0x0100, BR_NETKEY_A, 0);

	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_BRIDGE_OP_TABLE_SIZE_GET,
	    NULL, 0, req, &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_bridge_table_size_status_parse(st, st_len,
	    &size));
	/* Section 4.2.43: "shall be at least 16". */
	ATF_CHECK(size >= 16);
	ATF_CHECK_EQ((uint16_t)MESH_BRIDGE_TABLE_SIZE, size);
	/* Table 4.298: a 2-octet little-endian size. */
	ATF_REQUIRE_EQ(4u, st_len);
	ATF_CHECK_EQ(0x80, st[0]);
	ATF_CHECK_EQ(0xbc, st[1]);
	ATF_CHECK_EQ((uint8_t)(size & 0xff), st[2]);
	ATF_CHECK_EQ((uint8_t)(size >> 8), st[3]);
}

/* ================================================================
 * 4.2.42.1 Binding with the NetKey List state.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_netkey_delete_binding);
ATF_TC_BODY(bridge_netkey_delete_binding, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct mesh_bridge_table_status s;
	uint8_t req[64], st[MESH_ACCESS_PAYLOAD_MAX], status;
	uint16_t net_idx;
	size_t req_len, st_len;

	br_provision(nd, &cfg, 0x0100, BR_NETKEY_A, 0);
	br_add_netkey(nd, 1, BR_NETKEY_B);
	br_add_netkey(nd, 2, 0x66);
	br_enable(nd, MESH_BRIDGE_ENABLED);

	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0001, 0x0201, &s);
	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 0, 2, 0x0002, 0x0302, &s);
	br_table_add(nd, MESH_BRIDGE_DIR_TWO_WAY, 2, 1, 0x0303, 0x0203, &s);
	ATF_REQUIRE_EQ(3u, nd->db.bridging.n);

	/*
	 * Section 4.2.42.1: deleting NetKey 2 removes every Bridging Table
	 * entry naming it in EITHER position - here two of the three - and the
	 * network engine's copy follows.
	 */
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_delete_build(2, req, &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(st, st_len, &status,
	    &net_idx));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(1u, nd->db.bridging.n);
	ATF_CHECK_EQ(0, nd->db.bridging.entries[0].net_idx1);
	ATF_CHECK_EQ(1, nd->db.bridging.entries[0].net_idx2);
	ATF_CHECK_EQ(1u, nd->self->bridge_table.n);
	ATF_CHECK_EQ(1, nd->self->bridge_table.entries[0].net_idx2);
}

/* ================================================================
 * 4.4.9.1 model registration and its device-key access-layer security.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_model_registration);
ATF_TC_BODY(bridge_model_registration, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct mesh_cfg_comp_status cs;
	struct mesh_cfg_comp_page0 page;
	uint8_t req[64], st[MESH_ACCESS_PAYLOAD_MAX];
	size_t req_len, st_len, i;
	int found = 0, primary_only = 1, registered = 0;

	br_provision(nd, &cfg, 0x0100, BR_NETKEY_A, 0);

	/*
	 * Composition Data Page 0 must advertise SIG model 0x0008, or no
	 * Configuration Client can discover that this node is a Subnet Bridge.
	 */
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_get_build(0, req, &req_len));
	ATF_REQUIRE_EQ(1, br_recv(nd, req, req_len, st, &st_len));
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_status_parse(st, st_len, &cs));
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_page0_decode(cs.data, cs.data_len,
	    &page));
	for (i = 0; i < page.elements[0].n_sig; i++)
		if (page.elements[0].sig_models[i] == MESH_MODEL_BRIDGE_CFG_SRV)
			found = 1;
	ATF_CHECK_EQ(1, found);

	/*
	 * Section 4.4.9.1: the model "shall be supported on the primary element
	 * and shall not be supported by any secondary elements".
	 */
	for (i = 1; i < page.n_elements; i++) {
		size_t j;

		for (j = 0; j < page.elements[i].n_sig; j++)
			if (page.elements[i].sig_models[j] ==
			    MESH_MODEL_BRIDGE_CFG_SRV)
				primary_only = 0;
	}
	ATF_CHECK_EQ(1, primary_only);

	/* The model is registered with the access layer on element 0. */
	for (i = 0; i < nd->self->elems[0].n_models; i++)
		if (nd->self->elems[0].models[i].model_id ==
		    MESH_MODEL_BRIDGE_CFG_SRV)
			registered = 1;
	ATF_CHECK_EQ(1, registered);
}

/* ================================================================
 * 4.4.9.1 / 4.3.11: an AppKey-secured Bridge message is refused.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_appkey_refused);
ATF_TC_BODY(bridge_appkey_refused, tc)
{
	MESH_HEAP(struct meshd_node, brg);
	MESH_HEAP(struct meshd_node, peer);
	struct meshd_config bcfg, pcfg;
	struct meshd_bearer bbear = { .tx = br_cap_tx };
	struct meshd_bearer pbear = { .tx = br_cap_tx };
	struct mesh_cfg_model_app bind;
	uint8_t req[64], st[MESH_ACCESS_PAYLOAD_MAX], set[8];
	size_t req_len, st_len, set_len;

	br_provision(brg, &bcfg, 0x0100, BR_NETKEY_A, 0);
	br_provision(peer, &pcfg, 0x0001, BR_NETKEY_A, 0);
	meshd_set_bearer(brg, &bbear);
	meshd_set_bearer(peer, &pbear);

	/*
	 * Bind the shared AppKey to the Bridge Configuration Server model.  A
	 * Config Client can do this - nothing in the Configuration Server
	 * refuses it - which is exactly why the model itself has to enforce
	 * Section 4.4.9.1's device-key rule.
	 */
	memset(&bind, 0, sizeof(bind));
	bind.elem_addr = 0x0100;
	bind.app_idx = 0;
	bind.model.vendor = 0;
	bind.model.model_id = MESH_MODEL_BRIDGE_CFG_SRV;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &bind, req, &req_len));
	ATF_REQUIRE_EQ(1, br_recv(brg, req, req_len, st, &st_len));

	/* An AppKey-secured SUBNET_BRIDGE_SET(enable) from the peer. */
	ATF_REQUIRE_EQ(0, mesh_bridge_subnet_build(
	    MESH_BRIDGE_OP_SUBNET_BRIDGE_SET, MESH_BRIDGE_ENABLED, set,
	    &set_len));
	g_ncap = 0;
	ATF_REQUIRE_EQ(0, meshd_send_access_raw(peer, 0x0100, set, set_len));
	ATF_REQUIRE(g_ncap >= 1);
	(void)br_pump(brg);

	/*
	 * It reached the registered model (the refusal counter moved) and it
	 * did NOT take effect: the Subnet Bridge state is still disabled.
	 */
	ATF_CHECK_EQ(1u, brg->bridge_appkey_refused);
	ATF_CHECK_EQ(MESH_BRIDGE_DISABLED, brg->db.subnet_bridge);
	ATF_CHECK_EQ(0, brg->self->bridge_enabled);
}

/* ================================================================
 * The meshctl "bridge" control verbs.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_verbs);
ATF_TC_BODY(bridge_verbs, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	char reply[2048];
	const char *av[7];

	br_provision(nd, &cfg, 0x0100, BR_NETKEY_A, 0);
	br_add_netkey(nd, 1, BR_NETKEY_B);

	/* bridge / bridge status. */
	av[0] = "bridge";
	ATF_CHECK_EQ(0, br_verb(nd, 1, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "OK bridge off") != NULL);

	/* bridge on -> the state reaches the network engine. */
	av[1] = "on";
	ATF_CHECK_EQ(0, br_verb(nd, 2, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "OK bridge on") != NULL);
	ATF_CHECK_EQ(MESH_BRIDGE_ENABLED, nd->db.subnet_bridge);
	ATF_CHECK_EQ(1, nd->self->bridge_enabled);

	/* bridge add. */
	av[1] = "add";
	av[2] = "0";
	av[3] = "1";
	av[4] = "0x0001";
	av[5] = "0x0201";
	av[6] = "2";
	ATF_CHECK_EQ(0, br_verb(nd, 7, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "OK bridge add") != NULL);
	ATF_CHECK(strstr(reply, "entries=1") != NULL);
	ATF_CHECK_EQ(1u, nd->self->bridge_table.n);

	/* An unknown NetKey Index surfaces the server's Status Code. */
	av[3] = "9";
	ATF_CHECK_EQ(-1, br_verb(nd, 7, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "invalid-netkey-index") != NULL);
	av[3] = "1";

	/* A prohibited Directions value is diagnosed, not silently dropped. */
	av[6] = "0";
	ATF_CHECK_EQ(-1, br_verb(nd, 7, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "prohibited field values") != NULL);
	av[6] = "2";

	/* bridge list. */
	av[1] = "list";
	av[2] = "0";
	av[3] = "1";
	ATF_CHECK_EQ(0, br_verb(nd, 4, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "count=1") != NULL);
	ATF_CHECK(strstr(reply, "0001,0201,2") != NULL);

	/* bridge subnets. */
	av[1] = "subnets";
	ATF_CHECK_EQ(0, br_verb(nd, 2, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "count=1") != NULL);
	ATF_CHECK(strstr(reply, "000,001") != NULL);

	/* bridge size. */
	av[1] = "size";
	ATF_CHECK_EQ(0, br_verb(nd, 2, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "OK bridge size 16") != NULL);

	/* bridge stats. */
	av[1] = "stats";
	ATF_CHECK_EQ(0, br_verb(nd, 2, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "forwarded=0") != NULL);

	/* bridge remove. */
	av[1] = "remove";
	av[2] = "0";
	av[3] = "1";
	av[4] = "0";
	av[5] = "0";
	ATF_CHECK_EQ(0, br_verb(nd, 6, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "removed=1") != NULL);
	ATF_CHECK_EQ(0u, nd->self->bridge_table.n);

	/* bridge off. */
	av[1] = "off";
	ATF_CHECK_EQ(0, br_verb(nd, 2, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(0, nd->self->bridge_enabled);

	/* Usage errors. */
	av[1] = "bogus";
	ATF_CHECK_EQ(-1, br_verb(nd, 2, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "ERR usage: bridge") != NULL);
	av[1] = "add";
	ATF_CHECK_EQ(-1, br_verb(nd, 2, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "ERR usage: bridge add") != NULL);
}

/* ================================================================
 * Persistence: the states survive a restart (store version 13).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_persist);
ATF_TC_BODY(bridge_persist, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_config acfg, bcfg;
	struct meshd_persist ps;
	struct mesh_bridge_table_status s;
	const char *path = "meshd_bridge.state";
	FILE *f;
	uint8_t ver[2];

	(void)unlink(path);
	br_provision(a, &acfg, 0x0100, BR_NETKEY_A, 0);
	br_add_netkey(a, 1, BR_NETKEY_B);
	br_enable(a, MESH_BRIDGE_ENABLED);
	br_table_add(a, MESH_BRIDGE_DIR_TWO_WAY, 0, 1, 0x0001, 0x0201, &s);
	br_table_add(a, MESH_BRIDGE_DIR_ONE_WAY, 0, 1, 0x0002, 0x0202, &s);
	ATF_REQUIRE_EQ(MESH_CFG_SUCCESS, s.status);

	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, a));

	/* The store carries the bumped format version. */
	f = fopen(path, "rb");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE_EQ(0, fseek(f, 8, SEEK_SET));
	ATF_REQUIRE_EQ(2u, fread(ver, 1, sizeof(ver), f));
	ATF_REQUIRE_EQ(0, fclose(f));
	ATF_CHECK_EQ(13u, (uint16_t)(ver[0] | ((uint16_t)ver[1] << 8)));

	/* Restart: both states come back, and reach the network engine. */
	br_provision(b, &bcfg, 0x0100, BR_NETKEY_A, 0);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, b));
	ATF_CHECK_EQ(MESH_BRIDGE_ENABLED, b->db.subnet_bridge);
	ATF_CHECK_EQ(1, b->self->bridge_enabled);
	ATF_REQUIRE_EQ(2u, b->db.bridging.n);
	ATF_CHECK_EQ(0x0001, b->db.bridging.entries[0].addr1);
	ATF_CHECK_EQ(0x0201, b->db.bridging.entries[0].addr2);
	ATF_CHECK_EQ(MESH_BRIDGE_DIR_TWO_WAY,
	    b->db.bridging.entries[0].directions);
	ATF_CHECK_EQ(MESH_BRIDGE_DIR_ONE_WAY,
	    b->db.bridging.entries[1].directions);
	ATF_CHECK_EQ(2u, b->self->bridge_table.n);
	ATF_CHECK_EQ(0x0202, b->self->bridge_table.entries[1].addr2);

	(void)unlink(path);
}

/* ================================================================
 * 3.4.6.3 forwarding: a real crossing between two subnets.
 *
 * sender (subnet A, 0x0001) -> bridge (0x0100, subnets A and B)
 *                           -> receiver (subnet B, 0x0201)
 *
 * The receiver holds NetKey B as its PRIMARY subnet, so it can only ever
 * authenticate a Network PDU secured with B: a message that reaches it at all
 * proves the bridge re-secured the PDU under the other subnet's credentials.
 * ================================================================ */
static void
bridge_topology(struct meshd_node *snd, struct meshd_config *scfg,
    struct meshd_node *brg, struct meshd_config *bcfg,
    struct meshd_node *rcv, struct meshd_config *rcfg, uint8_t directions)
{
	struct mesh_bridge_table_status s;

	br_provision(snd, scfg, 0x0001, BR_NETKEY_A, 0);
	br_provision(brg, bcfg, 0x0100, BR_NETKEY_A, 0);
	/* The receiver's primary subnet IS the bridged-to subnet (index 1). */
	br_provision(rcv, rcfg, 0x0201, BR_NETKEY_B, 1);

	br_add_netkey(brg, 1, BR_NETKEY_B);
	br_enable(brg, MESH_BRIDGE_ENABLED);
	br_table_add(brg, directions, 0, 1, 0x0001, 0x0201, &s);
	ATF_REQUIRE_EQ(MESH_CFG_SUCCESS, s.status);
}

ATF_TC_WITHOUT_HEAD(bridge_forwards_across_subnets);
ATF_TC_BODY(bridge_forwards_across_subnets, tc)
{
	MESH_HEAP(struct meshd_node, snd);
	MESH_HEAP(struct meshd_node, brg);
	MESH_HEAP(struct meshd_node, rcv);
	struct meshd_config scfg, bcfg, rcfg;
	struct meshd_bearer sb = { .tx = br_cap_tx };
	struct meshd_bearer bb = { .tx = br_cap_tx };
	struct meshd_bearer rb = { .tx = br_cap_tx };
	uint32_t seq_before;

	bridge_topology(snd, &scfg, brg, &bcfg, rcv, &rcfg,
	    MESH_BRIDGE_DIR_TWO_WAY);
	meshd_set_bearer(snd, &sb);
	meshd_set_bearer(brg, &bb);
	meshd_set_bearer(rcv, &rb);

	/*
	 * The receiver cannot hear the sender directly (different subnet):
	 * feeding it the sender's own PDU delivers nothing.
	 */
	g_ncap = 0;
	seq_before = meshd_node_seq(snd);
	ATF_REQUIRE_EQ(0, meshd_send_onoff(snd, 0x0201, MESH_GEN_ON, 0));
	ATF_REQUIRE(g_ncap >= 1);
	{
		struct br_capframe snap[BR_MAXCAP];
		size_t n = g_ncap, i;

		memcpy(snap, g_cap, n * sizeof(snap[0]));
		for (i = 0; i < n; i++)
			ATF_CHECK(meshd_bearer_rx(rcv, snap[i].buf,
			    snap[i].len) != 1);
	}
	ATF_CHECK_EQ(MESH_GEN_OFF, rcv->app->onoff.present);

	/* Through the bridge, the very same PDUs cross and are delivered. */
	ATF_REQUIRE_EQ(0, br_pump(brg));	/* not addressed to the bridge */
	ATF_CHECK_EQ(1u, brg->self->bridge_fwd_count);
	ATF_REQUIRE(g_ncap >= 1);
	ATF_CHECK_EQ(1, br_pump(rcv));
	ATF_CHECK_EQ(MESH_GEN_ON, rcv->app->onoff.present);

	/*
	 * Section 3.4.6.3: a bridge re-secures, it does not originate.  The
	 * bridge's own sequence number is untouched by the crossing, and the
	 * receiver saw the ORIGINATOR's address, not the bridge's.
	 */
	ATF_CHECK_EQ(0x0001, rcv->self->rx.src);
	ATF_CHECK_EQ(seq_before + 1, meshd_node_seq(snd));

	/*
	 * "The TTL field value of the retransmitted Network PDU shall be equal
	 * to the TTL field value of the received Network PDU decremented by 1."
	 * The sender originated at Default TTL 7.
	 */
	ATF_CHECK_EQ(6, rcv->self->rx.ttl);
}

/* ================================================================
 * 4.2.41: with the Subnet Bridge state disabled, nothing crosses.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_disabled_does_not_forward);
ATF_TC_BODY(bridge_disabled_does_not_forward, tc)
{
	MESH_HEAP(struct meshd_node, snd);
	MESH_HEAP(struct meshd_node, brg);
	MESH_HEAP(struct meshd_node, rcv);
	struct meshd_config scfg, bcfg, rcfg;
	struct meshd_bearer sb = { .tx = br_cap_tx };
	struct meshd_bearer bb = { .tx = br_cap_tx };
	struct meshd_bearer rb = { .tx = br_cap_tx };

	bridge_topology(snd, &scfg, brg, &bcfg, rcv, &rcfg,
	    MESH_BRIDGE_DIR_TWO_WAY);
	meshd_set_bearer(snd, &sb);
	meshd_set_bearer(brg, &bb);
	meshd_set_bearer(rcv, &rb);

	/* The Bridging Table is configured; only the Subnet Bridge state is off. */
	br_enable(brg, MESH_BRIDGE_DISABLED);
	ATF_REQUIRE_EQ(1u, brg->self->bridge_table.n);

	g_ncap = 0;
	ATF_REQUIRE_EQ(0, meshd_send_onoff(snd, 0x0201, MESH_GEN_ON, 0));
	ATF_REQUIRE_EQ(0, br_pump(brg));
	ATF_CHECK_EQ(0u, brg->self->bridge_fwd_count);
	ATF_CHECK_EQ(0, br_pump(rcv));
	ATF_CHECK_EQ(MESH_GEN_OFF, rcv->app->onoff.present);
}

/* ================================================================
 * Table 4.71 Directions 0x01: "Bridging is allowed only for messages with
 * Address1 as the source address and Address2 as the destination address."
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_direction_one_way);
ATF_TC_BODY(bridge_direction_one_way, tc)
{
	MESH_HEAP(struct meshd_node, snd);
	MESH_HEAP(struct meshd_node, brg);
	MESH_HEAP(struct meshd_node, rcv);
	struct meshd_config scfg, bcfg, rcfg;
	struct meshd_bearer sb = { .tx = br_cap_tx };
	struct meshd_bearer bb = { .tx = br_cap_tx };
	struct meshd_bearer rb = { .tx = br_cap_tx };

	bridge_topology(snd, &scfg, brg, &bcfg, rcv, &rcfg,
	    MESH_BRIDGE_DIR_ONE_WAY);
	meshd_set_bearer(snd, &sb);
	meshd_set_bearer(brg, &bb);
	meshd_set_bearer(rcv, &rb);

	/* Address1 -> Address2 crosses. */
	g_ncap = 0;
	ATF_REQUIRE_EQ(0, meshd_send_onoff(snd, 0x0201, MESH_GEN_ON, 0));
	ATF_REQUIRE_EQ(0, br_pump(brg));
	ATF_CHECK_EQ(1u, brg->self->bridge_fwd_count);
	ATF_CHECK_EQ(1, br_pump(rcv));

	/*
	 * Address2 -> Address1 does NOT: the reverse direction requires
	 * Directions 0x02 (Section 3.4.6.3, fourth bullet).
	 */
	g_ncap = 0;
	ATF_REQUIRE_EQ(0, meshd_send_onoff(rcv, 0x0001, MESH_GEN_ON, 0));
	ATF_REQUIRE(g_ncap >= 1);
	ATF_REQUIRE_EQ(0, br_pump(brg));
	ATF_CHECK_EQ(1u, brg->self->bridge_fwd_count);	/* unchanged */
	ATF_CHECK_EQ(0, br_pump(snd));
	ATF_CHECK_EQ(MESH_GEN_OFF, snd->app->onoff.present);
}

/* ================================================================
 * 3.9.8: the Subnet Bridge's own replay protection for bridged traffic.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bridge_replay_protection);
ATF_TC_BODY(bridge_replay_protection, tc)
{
	MESH_HEAP(struct meshd_node, snd);
	MESH_HEAP(struct meshd_node, brg);
	MESH_HEAP(struct meshd_node, rcv);
	struct meshd_config scfg, bcfg, rcfg;
	struct meshd_bearer sb = { .tx = br_cap_tx };
	struct meshd_bearer bb = { .tx = br_cap_tx };
	struct meshd_bearer rb = { .tx = br_cap_tx };
	struct br_capframe replay;

	bridge_topology(snd, &scfg, brg, &bcfg, rcv, &rcfg,
	    MESH_BRIDGE_DIR_TWO_WAY);
	meshd_set_bearer(snd, &sb);
	meshd_set_bearer(brg, &bb);
	meshd_set_bearer(rcv, &rb);

	g_ncap = 0;
	ATF_REQUIRE_EQ(0, meshd_send_onoff(snd, 0x0201, MESH_GEN_ON, 0));
	ATF_REQUIRE(g_ncap >= 1);
	replay = g_cap[0];			/* keep a copy to replay */
	ATF_REQUIRE_EQ(0, br_pump(brg));
	ATF_CHECK_EQ(1u, brg->self->bridge_fwd_count);
	ATF_CHECK_EQ(0u, brg->self->bridge_replay_drops);

	/*
	 * "Messages received by the Subnet Bridge node with the IVISeq value
	 * less than or equal to the last stored value from that source address
	 * shall be discarded immediately upon reception."
	 *
	 * The network message cache would also suppress an immediate repeat, so
	 * clear it first: this must be the REPLAY list's decision, taken from
	 * the stored IVISeq, not incidental duplicate suppression.
	 */
	g_ncap = 0;
	brg->self->nmc_next = 0;
	memset(brg->self->nmc, 0, sizeof(brg->self->nmc));
	ATF_REQUIRE_EQ(0, meshd_bearer_rx(brg, replay.buf, replay.len));
	ATF_CHECK_EQ(1u, brg->self->bridge_fwd_count);	/* not forwarded again */
	ATF_CHECK_EQ(1u, brg->self->bridge_replay_drops);

	/*
	 * The bridge replay list is SEPARATE from the node's own replay
	 * protection list: bridged traffic must not consume the entry that
	 * protects messages addressed to the bridge itself.  Nothing was ever
	 * addressed to the bridge, so its own list is still empty.
	 */
	{
		size_t i;
		int own = 0, bridged = 0;

		for (i = 0; i < MESH_SIM_RPL_SIZE; i++) {
			if (brg->self->rpl_store[i].valid)
				own++;
			if (brg->self->bridge_rpl_store[i].valid)
				bridged++;
		}
		ATF_CHECK_EQ(0, own);
		ATF_CHECK_EQ(1, bridged);
	}

	/* A NEWER sequence number from the same source still crosses. */
	g_ncap = 0;
	ATF_REQUIRE_EQ(0, meshd_send_onoff(snd, 0x0201, MESH_GEN_OFF, 0));
	ATF_REQUIRE_EQ(0, br_pump(brg));
	ATF_CHECK_EQ(2u, brg->self->bridge_fwd_count);
	ATF_CHECK_EQ(1u, brg->self->bridge_replay_drops);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, bridge_subnet_state);
	ATF_TP_ADD_TC(tp, bridge_table_add);
	ATF_TP_ADD_TC(tp, bridge_table_add_prohibited);
	ATF_TP_ADD_TC(tp, bridge_table_remove);
	ATF_TP_ADD_TC(tp, bridge_subnets_list);
	ATF_TP_ADD_TC(tp, bridge_table_list);
	ATF_TP_ADD_TC(tp, bridge_table_size);
	ATF_TP_ADD_TC(tp, bridge_netkey_delete_binding);
	ATF_TP_ADD_TC(tp, bridge_model_registration);
	ATF_TP_ADD_TC(tp, bridge_appkey_refused);
	ATF_TP_ADD_TC(tp, bridge_verbs);
	ATF_TP_ADD_TC(tp, bridge_persist);
	ATF_TP_ADD_TC(tp, bridge_forwards_across_subnets);
	ATF_TP_ADD_TC(tp, bridge_disabled_does_not_forward);
	ATF_TP_ADD_TC(tp, bridge_direction_one_way);
	ATF_TP_ADD_TC(tp, bridge_replay_protection);

	return (atf_no_error());
}
