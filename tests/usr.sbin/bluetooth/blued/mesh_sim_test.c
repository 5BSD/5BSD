/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * End-to-end ATF tests for the Bluetooth Mesh multi-node simulator
 * (mesh_sim.[ch]) driving the Generic application models (mesh_generic.[ch])
 * over the full receive pipeline: network deobfuscate/decrypt, relay,
 * Friend Queue, RPL, SAR reassembly, upper-transport AppKey decrypt and
 * access-layer model dispatch.
 *
 * The scenarios are the mesh analogue of the btpeer / hci_emulator sim-air:
 *
 *   (a) one-hop Generic OnOff Set -> server flips -> Status returned;
 *   (b) two-hop delivery through a Relay (TTL decrement) with the duplicate
 *       from a second relay blocked by the RPL;
 *   (c) group (subscription) delivery to multiple servers;
 *   (d) Friend/LPN: a message queued at the Friend is delivered when the LPN
 *       polls;
 *   (e) IV-Update and Key-Refresh propagating via Secure Network beacons;
 *   (f) replay: a re-injected secured PDU is dropped by the RPL.
 *
 * Security material is the MshPRT_v1.1 Section 8 canonical NetKey / AppKey;
 * the exact secured bytes are produced by the already-KAT-verified Phase 1-8
 * modules, so these tests assert spec OUTCOMES (state, delivered opcode +
 * parameters, TTL/relay/RPL behaviour) rather than re-deriving ciphertext.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_test_heap.h"
#include "mesh_sim.h"
#include "mesh_generic.h"
#include "mesh_crypto.h"
#include "mesh_transport.h"
#include "mesh_friend.h"
#include "mesh_df.h"
#include "mesh_heartbeat.h"
#include "mesh_cfg_model.h"
#include "mesh_provisioner.h"

static const uint8_t NETKEY[16] = {
	0x7d, 0xd7, 0x36, 0x4c, 0xd8, 0x42, 0xad, 0x18,
	0xc1, 0x7c, 0x2b, 0x82, 0x0c, 0x84, 0xc3, 0xd6
};
static const uint8_t NETKEY2[16] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};
static const uint8_t APPKEY[16] = {
	0x63, 0x96, 0x47, 0x71, 0x73, 0x4f, 0xbd, 0x76,
	0xe3, 0xb4, 0x05, 0x19, 0xd1, 0xd9, 0x4a, 0x48
};

static const uint8_t DEVKEY[16] = {
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static int devkey_server_seen, devkey_client_seen;

static int
devkey_server_rx(void *arg, uint16_t src, uint16_t dst,
    const uint8_t *access, size_t access_len, uint8_t *reply,
    size_t *reply_len)
{
	struct mesh_access_pdu ap;
	uint8_t ttl = 7;

	(void)arg; (void)src; (void)dst;
	if (mesh_access_pdu_parse(access, access_len, &ap) != 0 ||
	    ap.opcode != MESH_CFG_OP_DEFAULT_TTL_GET)
		return (-1);
	devkey_server_seen++;
	return (mesh_access_pdu_build(MESH_CFG_OP_DEFAULT_TTL_STATUS, &ttl, 1,
	    reply, reply_len) == 0 ? 1 : -1);
}

static int
devkey_lookup(void *arg, uint16_t src, uint8_t key[16])
{

	(void)arg; (void)src;
	memcpy(key, DEVKEY, 16);
	return (0);
}

static int
devkey_client_rx(void *arg, uint32_t seq, uint16_t src, uint16_t dst,
    const uint8_t *upper, size_t upper_len)
{

	(void)arg; (void)seq; (void)src; (void)dst; (void)upper; (void)upper_len;
	devkey_client_seen++;
	return (1);
}

#define	IV0	0x12345678u

/*
 * Encrypt a Network PDU with the given subnet NetKey (managed-flooding
 * credential) and inject it onto the medium as if transmitted by no existing
 * node (tx_node -1 => delivered to every node).  Used to craft control PDUs
 * the simulator itself never originates.
 */
static void
inject_pdu(struct mesh_sim *sim, const uint8_t netkey[16], uint8_t ctl,
    uint16_t src, uint16_t dst, uint32_t seq, const uint8_t *transport,
    size_t tlen)
{
	uint8_t nid, enc[16], priv[16], p = 0x00;
	struct mesh_net_pdu np;
	uint8_t out[MESH_NET_MAX_PDU];
	size_t ol;

	ATF_REQUIRE_EQ(0, mesh_k2(netkey, &p, 1, &nid, enc, priv));
	memset(&np, 0, sizeof(np));
	np.nid = nid;
	np.ctl = ctl;
	np.ttl = 1;
	np.seq = seq;
	np.src = src;
	np.dst = dst;
	memcpy(np.transport, transport, tlen);
	np.transport_len = tlen;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(enc, priv, nid, 0, &np, out, &ol));
	ATF_REQUIRE_EQ(0, mesh_sim_reinject(sim, -1, out, ol));
}

/* ================================================================
 * (a) One-hop OnOff Set: state flips, Status returns, wire bytes.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(onoff_one_hop);
ATF_TC_BODY(onoff_one_hop, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *s;
	struct mesh_gen_onoff_cli cli;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;
	static const uint8_t exp_params[] = { 0x01, 0x01 };	/* onoff=1 tid=1 */

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, IV0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	s = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE(c != NULL && s != NULL);
	mesh_gen_onoff_cli_init(&cli);
	mesh_gen_onoff_srv_init(&srv, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(c, 0, mesh_gen_onoff_cli_model(&cli)));
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(s, 0, mesh_gen_onoff_srv_model(&srv)));

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&set, 1, pdu, &plen));
	/* On-wire Access PDU = opcode 0x8202 || onoff || tid. */
	ATF_CHECK_EQ(0x82, pdu[0]);
	ATF_CHECK_EQ(0x02, pdu[1]);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0002,
	    MESH_OP_GEN_ONOFF_SET, pdu + 2, plen - 2, 5));
	ATF_CHECK_EQ(1u, mesh_sim_pending(sim));

	ATF_CHECK(mesh_sim_run(sim, 10) >= 2);

	ATF_CHECK_EQ_MSG(1, srv.present, "server OnOff flipped to 1");
	/* Server saw the exact on-wire access opcode + parameters. */
	ATF_CHECK_EQ(MESH_OP_GEN_ONOFF_SET, s->rx.opcode);
	ATF_CHECK_EQ(2u, s->rx.params_len);
	ATF_CHECK_EQ(0, memcmp(s->rx.params, exp_params, 2));
	/* Status returned to the client. */
	ATF_CHECK_EQ(1, cli.have_status);
	ATF_CHECK_EQ(1, cli.last.present);
	ATF_CHECK_EQ(MESH_OP_GEN_ONOFF_STATUS, c->rx.opcode);
	/* Both nodes advanced their SEQ. */
	ATF_CHECK(mesh_sim_node_seq(c) >= 1);
	ATF_CHECK(mesh_sim_node_seq(s) >= 1);
}

/* ================================================================
 * Generic Level Set/Get and Delta end to end.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(level_and_delta_e2e);
ATF_TC_BODY(level_and_delta_e2e, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *s;
	struct mesh_gen_level_cli cli;
	struct mesh_gen_level_srv srv;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	s = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_gen_level_cli_init(&cli);
	mesh_gen_level_srv_init(&srv, 0);
	mesh_sim_add_model(c, 0, mesh_gen_level_cli_model(&cli));
	mesh_sim_add_model(s, 0, mesh_gen_level_srv_model(&srv));

	{
		struct mesh_gen_level_set set = { 4660, 1, 0, 0, 0 };
		ATF_REQUIRE_EQ(0, mesh_gen_level_cli_set(&set, 1, pdu, &plen));
	}
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0002,
	    MESH_OP_GEN_LEVEL_SET, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ(4660, srv.present);
	ATF_CHECK_EQ(1, cli.have_status);
	ATF_CHECK_EQ(4660, cli.last.present);

	/* Delta Set +100 -> 4760. */
	{
		struct mesh_gen_delta_set d = { 100, 2, 0, 0, 0 };
		ATF_REQUIRE_EQ(0, mesh_gen_delta_cli_set(&d, 0, pdu, &plen));
	}
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0002,
	    MESH_OP_GEN_DELTA_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ(4760, srv.present);

	/* Get reflects the new level. */
	ATF_REQUIRE_EQ(0, mesh_gen_level_cli_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0002,
	    MESH_OP_GEN_LEVEL_GET, NULL, 0, 5));
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ(4760, cli.last.present);
}

/* ================================================================
 * (b) Two-hop delivery via a Relay; (b') duplicate blocked by RPL.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(multihop_two_hop);
ATF_TC_BODY(multihop_two_hop, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *r, *s;
	struct mesh_gen_onoff_cli cli;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	r = mesh_sim_add_node(sim, 0x0002, 1);
	s = mesh_sim_add_node(sim, 0x0003, 1);
	mesh_gen_onoff_cli_init(&cli);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(c, 0, mesh_gen_onoff_cli_model(&cli));
	mesh_sim_add_model(s, 0, mesh_gen_onoff_srv_model(&srv));
	mesh_sim_set_relay(r, 1);
	/* Line topology C -- R -- S: C cannot reach S directly. */
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, c, r));
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, r, s));

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 1, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0003,
	    MESH_OP_GEN_ONOFF_SET, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 16);

	ATF_CHECK_EQ_MSG(1, srv.present, "server two hops away flipped");
	ATF_CHECK(r->relay_count > 0);			/* the relay forwarded */
	ATF_CHECK_EQ_MSG(1u, s->rx.count, "server received exactly once");
	/* Status travelled back two hops. */
	ATF_CHECK_EQ(1, cli.have_status);
	ATF_CHECK_EQ(1, cli.last.present);
}

ATF_TC_WITHOUT_HEAD(multihop_rpl_dedup);
ATF_TC_BODY(multihop_rpl_dedup, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *r1, *r2, *s;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	r1 = mesh_sim_add_node(sim, 0x0002, 1);
	r2 = mesh_sim_add_node(sim, 0x0003, 1);
	s = mesh_sim_add_node(sim, 0x0004, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(s, 0, mesh_gen_onoff_srv_model(&srv));
	mesh_sim_set_relay(r1, 1);
	mesh_sim_set_relay(r2, 1);
	/* Diamond: C reaches S through both R1 and R2. */
	mesh_sim_link(sim, c, r1);
	mesh_sim_link(sim, c, r2);
	mesh_sim_link(sim, r1, s);
	mesh_sim_link(sim, r2, s);

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);	/* unacknowledged */
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0004,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 16);

	ATF_CHECK_EQ(1, srv.present);
	ATF_CHECK_EQ_MSG(1u, s->rx.count,
	    "the two relay copies collapse to one delivery (RPL)");
}

/* ================================================================
 * (c) Group (subscription) delivery to multiple servers.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(group_delivery);
ATF_TC_BODY(group_delivery, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *s1, *s2, *s3;
	struct mesh_gen_onoff_srv a, b, d;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	s1 = mesh_sim_add_node(sim, 0x0010, 1);
	s2 = mesh_sim_add_node(sim, 0x0011, 1);
	s3 = mesh_sim_add_node(sim, 0x0012, 1);	/* not subscribed */
	mesh_gen_onoff_srv_init(&a, 0);
	mesh_gen_onoff_srv_init(&b, 0);
	mesh_gen_onoff_srv_init(&d, 0);
	mesh_sim_add_model(s1, 0, mesh_gen_onoff_srv_model(&a));
	mesh_sim_add_model(s2, 0, mesh_gen_onoff_srv_model(&b));
	mesh_sim_add_model(s3, 0, mesh_gen_onoff_srv_model(&d));
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe(s1, 0xC000));
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe(s2, 0xC000));

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0xC000,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 10);

	ATF_CHECK_EQ_MSG(1, a.present, "subscribed server 1 got the group message");
	ATF_CHECK_EQ_MSG(1, b.present, "subscribed server 2 got the group message");
	ATF_CHECK_EQ_MSG(0, d.present, "non-subscribed server ignored it");
	(void)s3;
}

/* ================================================================
 * (d) Friend / Low Power node: queue then poll.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friend_lpn_poll);
ATF_TC_BODY(friend_lpn_poll, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *f, *l;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	f = mesh_sim_add_node(sim, 0x0002, 1);
	l = mesh_sim_add_node(sim, 0x0005, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(l, 0, mesh_gen_onoff_srv_model(&srv));
	mesh_sim_set_relay(f, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, 0x0005, 1, 8));
	ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(l, 0x0002, 0x0000a0));
	ATF_REQUIRE_EQ(0, mesh_sim_establish_friendship(sim, f, l, 0, 0, 0));
	/* C -- F -- L; the LPN is only reachable through its Friend. */
	mesh_sim_link(sim, c, f);
	mesh_sim_link(sim, f, l);

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 7;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0005,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 10);

	/* LPN asleep: nothing delivered yet, but queued at the Friend. */
	ATF_CHECK_EQ_MSG(0, srv.present, "LPN asleep, not yet applied");
	ATF_CHECK_EQ(1u, mesh_fq_count(&f->fq));

	/* Poll: the Friend delivers the queued message. */
	ATF_CHECK_EQ(1, mesh_sim_lpn_poll(sim, l));
	ATF_CHECK_EQ_MSG(1, srv.present, "queued message applied after poll");

	/* A second poll with an empty queue delivers nothing. */
	ATF_CHECK_EQ(0, mesh_sim_lpn_poll(sim, l));
}

/* ================================================================
 * (e) IV Update and Key Refresh via Secure Network beacons.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(iv_update_propagate);
ATF_TC_BODY(iv_update_propagate, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *b;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 5));
	a = mesh_sim_add_node(sim, 0x0001, 1);
	b = mesh_sim_add_node(sim, 0x0002, 1);

	/* Dwell not yet elapsed: local begin is rejected. */
	ATF_CHECK_EQ(-1, mesh_sim_begin_iv_update(a));

	mesh_sim_advance(sim, 96UL * 3600UL + 10);
	ATF_REQUIRE_EQ(0, mesh_sim_begin_iv_update(a));
	ATF_CHECK_EQ(6u, mesh_sim_node_iv(a));

	/* Beacon carries IV Index 6 + update flag; B adopts it. */
	ATF_REQUIRE_EQ(0, mesh_sim_send_beacon(sim, a, 0));
	ATF_CHECK_EQ_MSG(6u, mesh_sim_node_iv(b), "B adopted the new IV Index");

	/* Complete the update on both after another dwell. */
	mesh_sim_advance(sim, 96UL * 3600UL + 10);
	ATF_REQUIRE_EQ(0, mesh_sim_complete_iv_update(a));
	ATF_REQUIRE_EQ(0, mesh_sim_send_beacon(sim, a, 0));
	ATF_CHECK_EQ(6u, mesh_sim_node_iv(b));
}

ATF_TC_WITHOUT_HEAD(key_refresh_propagate);
ATF_TC_BODY(key_refresh_propagate, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *x, *y;
	struct mesh_gen_onoff_cli cli;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	x = mesh_sim_add_node(sim, 0x0001, 1);
	y = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_gen_onoff_cli_init(&cli);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(x, 0, mesh_gen_onoff_cli_model(&cli));
	mesh_sim_add_model(y, 0, mesh_gen_onoff_srv_model(&srv));

	/* Distribute the new key (Phase 1) to both nodes. */
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(x, NETKEY2));
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(y, NETKEY2));
	ATF_CHECK_EQ(MESH_KR_PHASE_1, mesh_sim_node_kr_phase(x));

	/* X advances to Phase 2 and beacons; Y follows. */
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(x));
	ATF_CHECK_EQ(MESH_KR_PHASE_2, mesh_sim_node_kr_phase(x));
	ATF_REQUIRE_EQ(0, mesh_sim_send_beacon(sim, x, 0));
	ATF_CHECK_EQ_MSG(MESH_KR_PHASE_2, mesh_sim_node_kr_phase(y),
	    "Y advanced to Phase 2 from the new-key beacon");

	/* Traffic now flows under the NEW key material (TX new, RX new). */
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(y));	/* Y also TX new */
	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 1, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, x, 0x0002,
	    MESH_OP_GEN_ONOFF_SET, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ_MSG(1, srv.present, "message delivered under refreshed key");
	ATF_CHECK_EQ(1, cli.have_status);
}

/* ================================================================
 * (f) Replay: a re-injected secured PDU is dropped by the RPL.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(replay_dropped);
ATF_TC_BODY(replay_dropped, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *b;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8], wire[MESH_NET_MAX_PDU];
	size_t plen, wlen;
	uint32_t c1;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);
	b = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(b, 0, mesh_gen_onoff_srv_model(&srv));

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	/* Capture the secured wire PDU before it is consumed. */
	ATF_REQUIRE_EQ(1u, mesh_sim_pending(sim));
	wlen = sim->tx[0].len;
	memcpy(wire, sim->tx[0].bytes, wlen);

	mesh_sim_run(sim, 5);
	c1 = b->rx.count;
	ATF_CHECK_EQ(1u, c1);
	ATF_CHECK_EQ(1, srv.present);

	/* Re-inject the identical secured PDU: RPL rejects the delivery. */
	ATF_REQUIRE_EQ(0, mesh_sim_reinject(sim, 0, wire, wlen));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(c1, b->rx.count, "replayed PDU dropped by the RPL");
}

/* ================================================================
 * Segmentation + reassembly of a large access message end to end.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(segmented_reassembly);
ATF_TC_BODY(segmented_reassembly, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *b;
	uint8_t params[40];
	size_t i;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);
	b = mesh_sim_add_node(sim, 0x0002, 1);
	for (i = 0; i < sizeof(params); i++)
		params[i] = (uint8_t)(i + 1);

	/* Opcode 0x8299 is unhandled by any model, but the transport +
	 * reassembly path must still reconstruct the full access PDU. */
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0002, 0x8299,
	    params, sizeof(params), 5));
	ATF_CHECK(mesh_sim_pending(sim) >= 2);		/* multiple segments */
	/*
	 * Deliver the transaction in reverse Network SEQ order.  Replay
	 * protection is transaction-scoped for segmented messages: seeing SegN
	 * first must not cause the lower-numbered segments to be discarded.
	 */
	for (i = 0; i < sim->n_tx / 2; i++) {
		struct mesh_sim_tx tmp = sim->tx[i];

		sim->tx[i] = sim->tx[sim->n_tx - 1 - i];
		sim->tx[sim->n_tx - 1 - i] = tmp;
	}
	mesh_sim_run(sim, 10);

	ATF_CHECK_EQ_MSG(1u, b->rx.count, "reassembled message delivered once");
	ATF_CHECK_EQ(0x8299u, b->rx.opcode);
	ATF_CHECK_EQ(sizeof(params), b->rx.params_len);
	ATF_CHECK_EQ(0, memcmp(b->rx.params, params, sizeof(params)));
}

/* ================================================================
 * Traffic during an in-progress IV Update exercises the IV candidate
 * decrypt path (TX with old index, RX accepts old or new).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(traffic_during_iv_update);
ATF_TC_BODY(traffic_during_iv_update, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *b;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 5));
	a = mesh_sim_add_node(sim, 0x0001, 1);
	b = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(b, 0, mesh_gen_onoff_srv_model(&srv));

	mesh_sim_advance(sim, 96UL * 3600UL + 10);
	ATF_REQUIRE_EQ(0, mesh_sim_begin_iv_update(a));
	ATF_REQUIRE_EQ(0, mesh_sim_begin_iv_update(b));
	/* Both are in Update In Progress: A transmits with the old index. */

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 8);
	ATF_CHECK_EQ_MSG(1, srv.present,
	    "message accepted on an IV candidate during update");
}

/* ================================================================
 * Robustness: garbage on the medium, and undeliverable messages.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(robustness);
ATF_TC_BODY(robustness, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *b;
	struct mesh_gen_onoff_srv srv;
	uint8_t garbage[20];
	uint8_t pdu[8];
	size_t plen, i;
	struct mesh_gen_onoff_set set;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);
	b = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(b, 0, mesh_gen_onoff_srv_model(&srv));

	/* Undecryptable garbage is silently dropped (no crash, no delivery). */
	for (i = 0; i < sizeof(garbage); i++)
		garbage[i] = (uint8_t)(0xa5 ^ i);
	ATF_REQUIRE_EQ(0, mesh_sim_reinject(sim, 0, garbage, sizeof(garbage)));
	mesh_sim_run(sim, 3);
	ATF_CHECK_EQ(0u, b->rx.count);

	/* Message to an unpopulated unicast address is decrypted but not
	 * delivered to any model (no such element on B). */
	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x00ff,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 3);
	ATF_CHECK_EQ_MSG(0u, b->rx.count, "message for a foreign address ignored");
	ATF_CHECK_EQ(0, srv.present);
}

/* ================================================================
 * API argument validation + resource limits.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(api_limits);
ATF_TC_BODY(api_limits, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *n, *m;
	struct mesh_gen_onoff_srv srv;
	struct mesh_sim_prov pv;
	uint8_t key[16], label[MESH_LABEL_UUID_LEN], junk[4] = { 0 };
	uint8_t proxy_msg[16], secured[64], uuid[16] = { 0 };
	uint16_t proxy_addr = 0xc123;
	size_t proxy_msglen, secured_len;
	int i;

	ATF_CHECK_EQ(-1, mesh_sim_init(NULL, NETKEY, APPKEY, 0));
	ATF_CHECK_EQ(-1, mesh_sim_init(sim, NULL, APPKEY, 0));
	ATF_CHECK_EQ(-1, mesh_sim_init(sim, NETKEY, NULL, 0));
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));

	/* Bad element counts + NULL sim-> */
	ATF_CHECK(mesh_sim_add_node(NULL, 0x0001, 1) == NULL);
	ATF_CHECK(mesh_sim_add_node(sim, 0x0001, 0) == NULL);
	ATF_CHECK(mesh_sim_add_node(sim, 0x0001, MESH_SIM_MAX_ELEMS + 1) == NULL);

	n = mesh_sim_add_node(sim, 0x0001, 1);
	ATF_REQUIRE(n != NULL);
	mesh_gen_onoff_srv_init(&srv, 0);

	/* Model table overflow + bad element index. */
	for (i = 0; i < MESH_SIM_MAX_MODELS; i++)
		ATF_REQUIRE_EQ(0, mesh_sim_add_model(n, 0,
		    mesh_gen_onoff_srv_model(&srv)));
	ATF_CHECK_EQ(-1, mesh_sim_add_model(n, 0,
	    mesh_gen_onoff_srv_model(&srv)));
	ATF_CHECK_EQ(-1, mesh_sim_add_model(n, 9,
	    mesh_gen_onoff_srv_model(&srv)));
	ATF_CHECK_EQ(-1, mesh_sim_add_model(NULL, 0,
	    mesh_gen_onoff_srv_model(&srv)));

	/* Subscription list overflow. */
	for (i = 0; i < MESH_SIM_MAX_SUBS; i++)
		ATF_REQUIRE_EQ(0, mesh_sim_subscribe(n, (uint16_t)(0xC000 + i)));
	ATF_CHECK_EQ(-1, mesh_sim_subscribe(n, 0xC0FF));
	ATF_CHECK_EQ(-1, mesh_sim_subscribe(NULL, 0xC000));
	ATF_CHECK_EQ(-1, mesh_sim_subscribe_element(NULL, 0, 0xC000));
	ATF_CHECK_EQ(-1, mesh_sim_subscribe_element(n, 1, 0xC000));
	/* The element list is full from mesh_sim_subscribe() above. */
	ATF_CHECK_EQ(-1, mesh_sim_subscribe_element(n, 0, 0xBFFF));
	mesh_sim_clear_subscriptions(NULL, 0);
	mesh_sim_clear_subscriptions(n, 1);
	mesh_sim_clear_subscriptions(n, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe_element(n, 0, 0xC123));
	ATF_CHECK_EQ(0, mesh_sim_subscribe_element(n, 0, 0xC123));

	memset(label, 0x5a, sizeof(label));
	ATF_CHECK_EQ(-1, mesh_sim_subscribe_virtual_element(NULL, 0, label));
	ATF_CHECK_EQ(-1, mesh_sim_subscribe_virtual_element(n, 0, NULL));
	ATF_CHECK_EQ(-1, mesh_sim_subscribe_virtual_element(n, 1, label));
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe_virtual_element(n, 0, label));
	ATF_CHECK_EQ(0, mesh_sim_subscribe_virtual_element(n, 0, label));

	/* Device-key server/client registration validates every required input. */
	memset(key, 0x33, sizeof(key));
	ATF_CHECK_EQ(-1, mesh_sim_set_devkey(NULL, key, devkey_server_rx, NULL));
	ATF_CHECK_EQ(-1, mesh_sim_set_devkey(n, NULL, devkey_server_rx, NULL));
	ATF_REQUIRE_EQ(0, mesh_sim_set_devkey(n, key, devkey_server_rx, NULL));
	ATF_CHECK_EQ(-1, mesh_sim_set_devkey_client(NULL, devkey_lookup,
	    devkey_client_rx, NULL));
	ATF_CHECK_EQ(-1, mesh_sim_set_devkey_client(n, NULL,
	    devkey_client_rx, NULL));
	ATF_CHECK_EQ(-1, mesh_sim_set_devkey_client(n, devkey_lookup,
	    NULL, NULL));
	ATF_REQUIRE_EQ(0, mesh_sim_set_devkey_client(n, devkey_lookup,
	    devkey_client_rx, NULL));

	/* Link + friend/lpn argument checks (each NULL operand). */
	m = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_CHECK_EQ(-1, mesh_sim_link(sim, n, n));
	ATF_CHECK_EQ(-1, mesh_sim_link(NULL, n, m));
	ATF_CHECK_EQ(-1, mesh_sim_link(sim, NULL, m));
	ATF_CHECK_EQ(-1, mesh_sim_link(sim, n, NULL));
	ATF_CHECK_EQ(0, mesh_sim_link(sim, n, m));
	ATF_CHECK_EQ(-1, mesh_sim_set_friend(NULL, 0x0005, 1, 4));
	ATF_CHECK_EQ(-1, mesh_sim_set_friend(n, 0x0005, 0, 4));
	ATF_CHECK_EQ(-1, mesh_sim_set_lpn(NULL, 0x0002, 0xa0));
	/* PollTimeout below the valid minimum is rejected. */
	ATF_CHECK_EQ(-1, mesh_sim_set_lpn(n, 0x0002, 0));
	mesh_sim_set_relay(NULL, 1);
	ATF_CHECK_EQ(-1, mesh_sim_establish_friendship(NULL, n, m, 0, 1, 1));
	ATF_CHECK_EQ(-1, mesh_sim_establish_friendship(sim, NULL, m, 0, 1, 1));
	ATF_CHECK_EQ(-1, mesh_sim_establish_friendship(sim, n, NULL, 0, 1, 1));
	ATF_CHECK_EQ(-1, mesh_sim_establish_friendship(sim, n, m, 0, 1, 1));

	/* Subnet/AppKey CRUD, including idempotence and cross-binding guards. */
	ATF_CHECK_EQ(-1, mesh_sim_add_subnet(NULL, 1, key));
	ATF_CHECK_EQ(-1, mesh_sim_add_subnet(n, 1, NULL));
	ATF_CHECK_EQ(-1, mesh_sim_add_subnet(n, 0x1000, key));
	ATF_CHECK_EQ(0, mesh_sim_add_subnet(n, 0, NETKEY));
	ATF_CHECK_EQ(-1, mesh_sim_add_subnet(n, 0, key));
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(n, 1, key));
	ATF_CHECK_EQ(0, mesh_sim_add_subnet(n, 1, key));
	key[0] ^= 1;
	ATF_CHECK_EQ(-1, mesh_sim_add_subnet(n, 1, key));
	key[0] ^= 1;
	ATF_CHECK_EQ(-1, mesh_sim_add_appkey(NULL, 1, 1, key));
	ATF_CHECK_EQ(-1, mesh_sim_add_appkey(n, 1, 1, NULL));
	ATF_CHECK_EQ(-1, mesh_sim_add_appkey(n, 2, 1, key));
	ATF_REQUIRE_EQ(0, mesh_sim_add_appkey(n, 1, 1, key));
	ATF_CHECK_EQ(0, mesh_sim_add_appkey(n, 1, 1, APPKEY));
	ATF_CHECK_EQ(-1, mesh_sim_add_appkey(n, 0, 1, APPKEY));
	ATF_CHECK_EQ(-1, mesh_sim_remove_appkey(NULL, 1));
	ATF_CHECK_EQ(-1, mesh_sim_remove_appkey(n, 0x0fff));
	ATF_CHECK_EQ(0, mesh_sim_remove_appkey(n, 1));
	ATF_CHECK_EQ(-1, mesh_sim_remove_subnet(NULL, 1));
	ATF_CHECK_EQ(-1, mesh_sim_remove_subnet(n, 0));
	ATF_CHECK_EQ(-1, mesh_sim_remove_subnet(n, 2));
	ATF_CHECK_EQ(0, mesh_sim_remove_subnet(n, 1));

	/* Proxy bearer API guards are independent of cryptographic vectors. */
	mesh_sim_set_proxy(NULL);
	ATF_CHECK_EQ(-1, mesh_sim_proxy_apply_config(NULL, junk, sizeof(junk)));
	ATF_CHECK_EQ(-1, mesh_sim_proxy_apply_config(n, NULL, sizeof(junk)));
	ATF_CHECK_EQ(-1, mesh_sim_proxy_apply_config(n, junk, sizeof(junk)));
	mesh_sim_set_proxy(n);
	ATF_CHECK_EQ(-1, mesh_sim_proxy_apply_config(n, junk, sizeof(junk)));
	/* Exercise the secured Remove Addresses configuration arm. */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_addr_build(MESH_PROXY_OP_REMOVE_ADDR,
	    &proxy_addr, 1, proxy_msg, sizeof(proxy_msg), &proxy_msglen));
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_encrypt(n->enckey, n->privkey, n->nid,
	    n->iv.iv_index, 1, n->addr, proxy_msg, proxy_msglen, secured,
	    &secured_len));
	ATF_CHECK_EQ(0, mesh_sim_proxy_apply_config(n, secured, secured_len));
	ATF_CHECK_EQ(-1, mesh_sim_proxy_gatt_in(NULL, n, junk, sizeof(junk)));
	ATF_CHECK_EQ(-1, mesh_sim_proxy_gatt_in(sim, NULL, junk, sizeof(junk)));
	ATF_CHECK_EQ(-1, mesh_sim_proxy_gatt_in(sim, n, NULL, sizeof(junk)));
	ATF_CHECK_EQ(-1, mesh_sim_proxy_gatt_in(sim, n, junk, 0));

	/* Explicit-key and pre-encrypted transport entry-point guards. */
	ATF_CHECK_EQ(-1, mesh_sim_send_upper(NULL, n, 2, 0, junk,
	    sizeof(junk), 1, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_upper(sim, NULL, 2, 0, junk,
	    sizeof(junk), 1, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_upper(sim, n, 2, 0, NULL,
	    sizeof(junk), 1, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_upper(sim, n, 2, 0, junk,
	    0, 1, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_upper(sim, n, 2, 0, junk,
	    MESH_UPPER_MAX + 1, 1, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_access_key(sim, NULL, 0, 0, 2,
	    0x8201, NULL, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_access_key_from(NULL, n, n->addr,
	    0, 0, 2, 0x8201, NULL, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_access_key_from(sim, n, n->addr - 1,
	    0, 0, 2, 0x8201, NULL, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_access_key_from(sim, n, n->addr + 1,
	    0, 0, 2, 0x8201, NULL, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_access_key_from(sim, n, n->addr,
	    0, 0x0fff, 2, 0x8201, NULL, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_access_key_from_virtual(NULL, n, n->addr,
	    0, 0, label, 0x8201, NULL, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_access_key_from_virtual(sim, NULL, 0,
	    0, 0, label, 0x8201, NULL, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_access_key_from_virtual(sim, n, n->addr,
	    0, 0, NULL, 0x8201, NULL, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_access_key_from_virtual(sim, n, n->addr,
	    0, 0x0fff, label, 0x8201, NULL, 0, 5));

	/* Secondary Key Refresh and feature helper validation. */
	ATF_CHECK_EQ(-1, mesh_sim_subnet_key_refresh_begin(NULL, 1, NETKEY2));
	ATF_CHECK_EQ(-1, mesh_sim_subnet_key_refresh_begin(n, 1, NULL));
	ATF_CHECK_EQ(-1, mesh_sim_subnet_key_refresh_begin(n, 1, NETKEY2));
	ATF_CHECK_EQ(-1, mesh_sim_subnet_key_refresh_advance(NULL, 1));
	ATF_CHECK_EQ(-1, mesh_sim_subnet_key_refresh_advance(n, 1));
	ATF_CHECK_EQ(-1, mesh_sim_subnet_key_refresh_finalize(NULL, 1));
	ATF_CHECK_EQ(-1, mesh_sim_subnet_key_refresh_finalize(n, 1));
	ATF_CHECK_EQ(-1, mesh_sim_subnet_kr_phase(NULL, 1));
	ATF_CHECK_EQ(-1, mesh_sim_subnet_kr_phase(n, 1));
	mesh_sim_set_df(NULL, 1);
	ATF_CHECK_EQ(-1, mesh_sim_df_discover(NULL, n, 2, 0));
	ATF_CHECK_EQ(-1, mesh_sim_df_discover(sim, NULL, 2, 0));
	ATF_CHECK_EQ(-1, mesh_sim_df_discover(sim, n, 2, 0));
	mesh_sim_df_expire(NULL);
	mesh_sim_hb_set_pub(NULL, 0, 0, 0, 0, 0, 0);
	mesh_sim_hb_set_sub(NULL, 0, 0, 0);
	ATF_CHECK_EQ(-1, mesh_sim_hb_feature_change(NULL, n, 0));
	ATF_CHECK_EQ(-1, mesh_sim_hb_feature_change(sim, NULL, 0));
	ATF_CHECK_EQ(-1, mesh_sim_hb_publish_periodic(NULL, n, 1));
	ATF_CHECK_EQ(-1, mesh_sim_hb_publish_periodic(sim, NULL, 1));
	/* A triggered publication with no destination reaches publish rejection. */
	mesh_sim_hb_set_pub(n, 0, 1, 1, 5, MESH_HB_FEATURE_RELAY,
	    0);
	ATF_CHECK_EQ(0, mesh_sim_hb_feature_change(sim, n,
	    MESH_HB_FEATURE_RELAY));

	/* PB-ADV public lifecycle guards and incomplete-session result. */
	memset(&pv, 0, sizeof(pv));
	ATF_CHECK_EQ(-1, mesh_sim_provision_begin(NULL, &pv, uuid, 7, 1));
	ATF_CHECK_EQ(-1, mesh_sim_provision_begin(sim, NULL, uuid, 7, 1));
	ATF_CHECK_EQ(-1, mesh_sim_provision_begin(sim, &pv, NULL, 7, 1));
	ATF_CHECK_EQ(-1, mesh_sim_provision_begin(sim, &pv, uuid, 7, 0));
	ATF_CHECK_EQ(-1, mesh_sim_provision_run(NULL, &pv, 1));
	ATF_CHECK_EQ(-1, mesh_sim_provision_run(sim, NULL, 1));
	ATF_CHECK_EQ(-1, mesh_sim_provision_run(sim, &pv, 0));
	ATF_CHECK(mesh_sim_provision_commit(NULL, &pv) == NULL);
	ATF_CHECK(mesh_sim_provision_commit(sim, NULL) == NULL);
	ATF_CHECK(mesh_sim_provision_commit(sim, &pv) == NULL);
	ATF_CHECK(mesh_sim_prov_devkey(NULL, 0) == NULL);
	ATF_CHECK(mesh_sim_prov_devkey(&pv, -1) == NULL);
	ATF_CHECK(mesh_sim_prov_devkey(&pv, 2) == NULL);

	/* Send / step / reinject argument checks (each NULL / bad operand). */
	ATF_CHECK_EQ(-1, mesh_sim_send_access(NULL, n, 0x0002, 0x8201,
	    NULL, 0, 5));
	ATF_CHECK_EQ(-1, mesh_sim_send_access(sim, NULL, 0x0002, 0x8201,
	    NULL, 0, 5));
	ATF_CHECK_EQ(0, mesh_sim_step(NULL));
	ATF_CHECK_EQ(0, mesh_sim_step(sim));		/* nothing pending */
	ATF_CHECK_EQ(-1, mesh_sim_reinject(NULL, 0, (const uint8_t *)"xxxx", 4));
	ATF_CHECK_EQ(-1, mesh_sim_reinject(sim, 0, NULL, 4));
	ATF_CHECK_EQ(-1, mesh_sim_reinject(sim, 0, (const uint8_t *)"x", 0));
	{
		uint8_t big[MESH_NET_MAX_PDU + 4];
		memset(big, 0, sizeof(big));
		ATF_CHECK_EQ(-1, mesh_sim_reinject(sim, 0, big, sizeof(big)));
	}

	/* LPN poll argument checks. */
	ATF_CHECK_EQ(-1, mesh_sim_lpn_poll(NULL, n));
	ATF_CHECK_EQ(-1, mesh_sim_lpn_poll(sim, NULL));
	ATF_CHECK_EQ(-1, mesh_sim_lpn_poll(sim, n));	/* n is not an LPN */

	/* Accessors. */
	ATF_CHECK(mesh_sim_node_at(NULL, 0x0001) == NULL);
	ATF_CHECK(mesh_sim_node_at(sim, 0x0001) == n);
	ATF_CHECK(mesh_sim_node_at(sim, 0x9999) == NULL);
	ATF_CHECK_EQ(0u, mesh_sim_node_seq(NULL));
	ATF_CHECK_EQ(0u, mesh_sim_node_iv(NULL));
	ATF_CHECK_EQ(-1, mesh_sim_node_kr_phase(NULL));
	ATF_CHECK_EQ(0u, mesh_sim_pending(NULL));

	/* Node-table overflow: fill to capacity then fail. */
	while (sim->n_nodes < MESH_SIM_MAX_NODES)
		ATF_REQUIRE(mesh_sim_add_node(sim,
		    (uint16_t)(0x1000 + sim->n_nodes), 1) != NULL);
	ATF_CHECK(mesh_sim_add_node(sim, 0x2000, 1) == NULL);

	/* IV / Key Refresh argument checks (each NULL / bad operand). */
	ATF_CHECK_EQ(-1, mesh_sim_begin_iv_update(NULL));
	ATF_CHECK_EQ(-1, mesh_sim_complete_iv_update(NULL));
	ATF_CHECK_EQ(-1, mesh_sim_key_refresh_advance(NULL));
	ATF_CHECK_EQ(-1, mesh_sim_key_refresh_advance(n));	/* no new key */
	ATF_CHECK_EQ(-1, mesh_sim_begin_key_refresh(NULL, NETKEY2));
	ATF_CHECK_EQ(-1, mesh_sim_begin_key_refresh(n, NULL));
	ATF_CHECK_EQ(-1, mesh_sim_send_beacon(NULL, n, 0));
	ATF_CHECK_EQ(-1, mesh_sim_send_beacon(sim, NULL, 0));
	ATF_CHECK_EQ(0, mesh_sim_run(NULL, 5));
}

/* ================================================================
 * Additional reachable-branch coverage: all-nodes address, old-key TX
 * during Key Refresh Phase 1, multi-entry subscription, IV/KR error
 * returns, and medium saturation.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(misc_branches);
ATF_TC_BODY(misc_branches, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *s;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;
	int i;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	s = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(s, 0, mesh_gen_onoff_srv_model(&srv));

	/* All-nodes (0xFFFF) delivery. */
	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, MESH_ADDR_ALL_NODES,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(1, srv.present, "all-nodes address delivered");

	/* Multi-entry subscription: the matching group is the second entry. */
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe(s, 0xC001));
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe(s, 0xC000));
	set.onoff = 0;
	set.tid = 2;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0xC000,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ(0, srv.present);

	/* TX with the OLD key while in Key Refresh Phase 1 (not yet advanced). */
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(c, NETKEY2));
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(s, NETKEY2));
	/* A second begin is rejected (already refreshing). */
	ATF_CHECK_EQ(-1, mesh_sim_begin_key_refresh(c, NETKEY2));
	set.onoff = 1;
	set.tid = 3;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(1, srv.present, "Phase 1 traffic flows under the old key");

	/* IV Update completion in the wrong state is rejected. */
	ATF_CHECK_EQ(-1, mesh_sim_complete_iv_update(c));

	/* Medium saturation: fill the pending queue, then a send fails. */
	{
		MESH_HEAP(struct mesh_sim, sim2);
		struct mesh_node *a;
		int rc = 0;

		ATF_REQUIRE_EQ(0, mesh_sim_init(sim2, NETKEY, APPKEY, 0));
		a = mesh_sim_add_node(sim2, 0x0001, 1);
		(void)mesh_sim_add_node(sim2, 0x0002, 1);
		for (i = 0; i < MESH_SIM_MAX_TX + 4; i++) {
			rc = mesh_sim_send_access(sim2, a, 0x0002, 0x8201,
			    NULL, 0, 5);
			if (rc != 0)
				break;
		}
		ATF_CHECK_EQ_MSG(-1, rc, "send fails once the medium is full");
		/* Reinject also fails when the medium is full. */
		ATF_CHECK_EQ(-1, mesh_sim_reinject(sim2, 0, pdu, 4));
	}
}

/* ================================================================
 * More end-to-end scenarios.
 * ================================================================ */

/* Set Unacknowledged flips the server but returns no Status. */
ATF_TC_WITHOUT_HEAD(onoff_set_unack);
ATF_TC_BODY(onoff_set_unack, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *s;
	struct mesh_gen_onoff_cli cli;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	s = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_gen_onoff_cli_init(&cli);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(c, 0, mesh_gen_onoff_cli_model(&cli));
	mesh_sim_add_model(s, 0, mesh_gen_onoff_srv_model(&srv));

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 8);
	ATF_CHECK_EQ(1, srv.present);
	ATF_CHECK_EQ_MSG(0, cli.have_status, "Set Unacknowledged yields no Status");
}

/* Generic OnOff Get returns the current Present state. */
ATF_TC_WITHOUT_HEAD(onoff_get_e2e);
ATF_TC_BODY(onoff_get_e2e, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *s;
	struct mesh_gen_onoff_cli cli;
	struct mesh_gen_onoff_srv srv;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	s = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_gen_onoff_cli_init(&cli);
	mesh_gen_onoff_srv_init(&srv, 1);		/* preset ON */
	mesh_sim_add_model(c, 0, mesh_gen_onoff_cli_model(&cli));
	mesh_sim_add_model(s, 0, mesh_gen_onoff_srv_model(&srv));

	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0002,
	    MESH_OP_GEN_ONOFF_GET, NULL, 0, 5));
	mesh_sim_run(sim, 8);
	ATF_CHECK_EQ(1, cli.have_status);
	ATF_CHECK_EQ(1, cli.last.present);
}

/*
 * Finding 7: a Generic Move Set whose transition time resolves to 0 (no
 * Transition Time field, DTT=0) makes NO Generic Level state change (MMDL
 * Section 3.3.2.2.4); it must not rail the Level to the bound.
 */
ATF_TC_WITHOUT_HEAD(level_move_e2e);
ATF_TC_BODY(level_move_e2e, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *s;
	struct mesh_gen_level_srv srv;
	struct mesh_gen_move_set m;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	s = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_gen_level_srv_init(&srv, 0);
	mesh_sim_add_model(s, 0, mesh_gen_level_srv_model(&srv));

	memset(&m, 0, sizeof(m));
	m.delta = 100;
	m.tid = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_move_cli_set(&m, 0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0002,
	    MESH_OP_GEN_MOVE_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 8);
	ATF_CHECK_EQ_MSG(0, srv.present,
	    "Move with transition time 0 must not change the Level");
}

/* Two Delta Sets sharing a TID form one transaction (single application). */
ATF_TC_WITHOUT_HEAD(delta_transaction_e2e);
ATF_TC_BODY(delta_transaction_e2e, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *s;
	struct mesh_gen_level_srv srv;
	struct mesh_gen_delta_set d;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	s = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_gen_level_srv_init(&srv, 1000);
	mesh_sim_add_model(s, 0, mesh_gen_level_srv_model(&srv));

	memset(&d, 0, sizeof(d));
	d.delta = 200;
	d.tid = 5;
	ATF_REQUIRE_EQ(0, mesh_gen_delta_cli_set(&d, 0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0002,
	    MESH_OP_GEN_DELTA_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 8);
	ATF_CHECK_EQ(1200, srv.present);
	/* Same TID again: re-applies from the transaction base (still 1200). */
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0002,
	    MESH_OP_GEN_DELTA_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 8);
	ATF_CHECK_EQ_MSG(1200, srv.present, "same-TID Delta does not accumulate");
}

/* A message with TTL=1 is not relayed, so a two-hop destination misses it. */
ATF_TC_WITHOUT_HEAD(relay_ttl_limit);
ATF_TC_BODY(relay_ttl_limit, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *r, *s;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	r = mesh_sim_add_node(sim, 0x0002, 1);
	s = mesh_sim_add_node(sim, 0x0003, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(s, 0, mesh_gen_onoff_srv_model(&srv));
	mesh_sim_set_relay(r, 1);
	mesh_sim_link(sim, c, r);
	mesh_sim_link(sim, r, s);

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0003,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 1));	/* TTL 1 */
	mesh_sim_run(sim, 8);
	ATF_CHECK_EQ_MSG(0u, r->relay_count, "TTL 1 is not relayable");
	ATF_CHECK_EQ_MSG(0, srv.present, "two-hop destination never reached");
}

/* Two queued messages are delivered over two consecutive LPN polls. */
ATF_TC_WITHOUT_HEAD(friend_multi_message);
ATF_TC_BODY(friend_multi_message, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *f, *l;
	struct mesh_gen_level_srv srv;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	f = mesh_sim_add_node(sim, 0x0002, 1);
	l = mesh_sim_add_node(sim, 0x0005, 1);
	mesh_gen_level_srv_init(&srv, 0);
	mesh_sim_add_model(l, 0, mesh_gen_level_srv_model(&srv));
	mesh_sim_set_relay(f, 1);
	mesh_sim_set_friend(f, 0x0005, 1, 8);
	mesh_sim_set_lpn(l, 0x0002, 0x0000a0);
	ATF_REQUIRE_EQ(0, mesh_sim_establish_friendship(sim, f, l, 0, 0, 0));
	mesh_sim_link(sim, c, f);
	mesh_sim_link(sim, f, l);

	{
		struct mesh_gen_level_set s1 = { 111, 1, 0, 0, 0 };
		struct mesh_gen_level_set s2 = { 222, 2, 0, 0, 0 };

		mesh_gen_level_cli_set(&s1, 0, pdu, &plen);
		ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0005,
		    MESH_OP_GEN_LEVEL_SET_UNACK, pdu + 2, plen - 2, 5));
		mesh_sim_run(sim, 5);
		mesh_gen_level_cli_set(&s2, 0, pdu, &plen);
		ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0005,
		    MESH_OP_GEN_LEVEL_SET_UNACK, pdu + 2, plen - 2, 5));
		mesh_sim_run(sim, 5);
	}
	ATF_CHECK_EQ(2u, mesh_fq_count(&f->fq));

	ATF_CHECK_EQ(1, mesh_sim_lpn_poll(sim, l));
	ATF_CHECK_EQ(111, srv.present);
	ATF_CHECK_EQ(1, mesh_sim_lpn_poll(sim, l));
	ATF_CHECK_EQ_MSG(222, srv.present, "second poll delivers the second message");
}

/* A unicast to a specific element reaches only that element's model. */
ATF_TC_WITHOUT_HEAD(multi_element_addressing);
ATF_TC_BODY(multi_element_addressing, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *s;
	struct mesh_gen_onoff_srv e0, e1;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	s = mesh_sim_add_node(sim, 0x0002, 2);
	mesh_gen_onoff_srv_init(&e0, 0);
	mesh_gen_onoff_srv_init(&e1, 0);
	mesh_sim_add_model(s, 0, mesh_gen_onoff_srv_model(&e0));
	mesh_sim_add_model(s, 1, mesh_gen_onoff_srv_model(&e1));

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	/* Address element 2 (0x0003) only. */
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0003,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(0, e0.present, "element 1 unaffected");
	ATF_CHECK_EQ_MSG(1, e1.present, "element 2 addressed");
}

/* A completed node accepts old-index traffic, then both use the new index. */
ATF_TC_WITHOUT_HEAD(iv_complete_and_traffic);
ATF_TC_BODY(iv_complete_and_traffic, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *b;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 5));
	a = mesh_sim_add_node(sim, 0x0001, 1);
	b = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(b, 0, mesh_gen_onoff_srv_model(&srv));

	mesh_sim_advance(sim, 96UL * 3600UL + 10);
	ATF_REQUIRE_EQ(0, mesh_sim_begin_iv_update(a));
	ATF_REQUIRE_EQ(0, mesh_sim_begin_iv_update(b));
	mesh_sim_advance(sim, 96UL * 3600UL + 10);
	ATF_REQUIRE_EQ(0, mesh_sim_complete_iv_update(b));
	ATF_CHECK_EQ(6u, mesh_sim_node_iv(b));

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(1, srv.present,
	    "Normal node accepts current-1 from peer still updating");

	ATF_REQUIRE_EQ(0, mesh_sim_complete_iv_update(a));
	set.onoff = 0;
	set.tid = 2;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(0, srv.present,
	    "traffic flows on current IV Index after both complete");
}

/* ================================================================
 * Deep branch coverage: relay toggles, multi-element addressing, an
 * authenticated-but-corrupt PDU, Friend subscription vs non-LPN filtering,
 * bounded run(), clock guard, and a mixed-key beacon audience.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_branches);
ATF_TC_BODY(deep_branches, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *s;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8], wire[MESH_NET_MAX_PDU];
	size_t plen, wlen;

	/* set_relay: NULL node and the disabled (enabled == 0) arm. */
	mesh_sim_set_relay(NULL, 1);
	mesh_sim_advance(NULL, 1);			/* clock NULL guard */

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	s = mesh_sim_add_node(sim, 0x0002, 2);		/* two elements */
	mesh_sim_set_relay(s, 0);			/* enabled == 0 arm */
	mesh_gen_onoff_srv_init(&srv, 0);
	/* Model lives on the SECOND element; a unicast to the FIRST element
	 * still iterates the second element's non-subscribed address. */
	mesh_sim_add_model(s, 1, mesh_gen_onoff_srv_model(&srv));

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0003,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ(1, srv.present);

	/* Unhandled opcode on an addressed element: reassembled/delivered to
	 * the access layer but no model handles it (op == NULL arm). */
	ATF_REQUIRE_EQ(0, mesh_gen_level_cli_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0003,
	    MESH_OP_GEN_LEVEL_GET, NULL, 0, 5));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(MESH_OP_GEN_LEVEL_GET, s->rx.opcode,
	    "unhandled opcode still reached the access layer");

	/* An invalid opcode makes the originator's Access PDU build fail. */
	ATF_CHECK_EQ(-1, mesh_sim_send_access(sim, c, 0x0003, 0x7f,
	    NULL, 0, 5));

	/* Bounded run(): an acknowledged Set needs two rounds; capping at one
	 * step leaves the Status reply pending (run stops at max_steps). */
	mesh_gen_onoff_srv_init(&srv, 0);
	set.onoff = 1;
	set.tid = 2;
	mesh_gen_onoff_cli_set(&set, 1, pdu, &plen);	/* acknowledged */
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0003,
	    MESH_OP_GEN_ONOFF_SET, pdu + 2, plen - 2, 5));
	ATF_CHECK_EQ_MSG(1, mesh_sim_run(sim, 1), "run stops at max_steps");
	ATF_CHECK(mesh_sim_pending(sim) > 0);		/* reply still queued */
	mesh_sim_run(sim, 5);

	/* Capture a valid wire PDU, corrupt an encrypted octet (leaving the
	 * NID intact): it authenticates the NID but fails the NetMIC, so it is
	 * dropped without delivery. */
	{
		MESH_HEAP(struct mesh_sim, sim2);
		struct mesh_node *a, *b;
		struct mesh_gen_onoff_srv bs;

		ATF_REQUIRE_EQ(0, mesh_sim_init(sim2, NETKEY, APPKEY, 0));
		a = mesh_sim_add_node(sim2, 0x0001, 1);
		b = mesh_sim_add_node(sim2, 0x0002, 1);
		mesh_gen_onoff_srv_init(&bs, 0);
		mesh_sim_add_model(b, 0, mesh_gen_onoff_srv_model(&bs));
		set.onoff = 1;
		set.tid = 1;
		mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
		ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim2, a, 0x0002,
		    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
		wlen = sim2->tx[0].len;
		(void)wire;
		/* Corrupt an encrypted octet of the pending PDU in place: the
		 * NID still matches but the NetMIC fails, so B drops it. */
		sim2->tx[0].bytes[wlen - 3] ^= 0xff;
		mesh_sim_run(sim2, 5);
		ATF_CHECK_EQ_MSG(0u, b->rx.count,
		    "corrupt PDU fails the NetMIC and is dropped");
		/* A wrong-NID PDU is rejected at the NID gate (no new key). */
		{
			uint8_t bad[16];
			memset(bad, 0, sizeof(bad));	/* octet0 NID = 0 */
			ATF_REQUIRE_EQ(0, mesh_sim_reinject(sim2, 0, bad,
			    sizeof(bad)));
			mesh_sim_run(sim2, 2);
			ATF_CHECK_EQ(0u, b->rx.count);
		}
	}

	/* Friend queue filter: subscribed address is stored, a non-LPN
	 * address is not. */
	{
		MESH_HEAP(struct mesh_sim, sim3);
		struct mesh_node *cc, *ff;

		ATF_REQUIRE_EQ(0, mesh_sim_init(sim3, NETKEY, APPKEY, 0));
		cc = mesh_sim_add_node(sim3, 0x0001, 1);
		ff = mesh_sim_add_node(sim3, 0x0002, 1);
		(void)mesh_sim_add_node(sim3, 0x0005, 1);	/* LPN slot */
		ATF_REQUIRE_EQ(0, mesh_sim_set_friend(ff, 0x0005, 1, 8));
		ATF_REQUIRE_EQ(1, mesh_friend_sub_add(&ff->fq.sub, 0x0006));
		mesh_sim_link(sim3, cc, ff);

		/* Subscribed group address 0x0006: stored (out of LPN range). */
		set.onoff = 1;
		set.tid = 1;
		mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
		ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim3, cc, 0x0006,
		    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
		mesh_sim_run(sim3, 5);
		ATF_CHECK_EQ_MSG(1u, mesh_fq_count(&ff->fq),
		    "subscribed address queued for the LPN");

		/* Address 0x0009 (above the LPN range) and 0x0003 (below it):
		 * neither is for the LPN, so neither is queued. */
		set.tid = 2;
		mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
		ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim3, cc, 0x0009,
		    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
		set.tid = 3;
		mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
		ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim3, cc, 0x0003,
		    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
		mesh_sim_run(sim3, 5);
		ATF_CHECK_EQ_MSG(1u, mesh_fq_count(&ff->fq),
		    "non-LPN addresses not queued");
	}

	/* Beacon audience with a node that lacks the new key. */
	{
		MESH_HEAP(struct mesh_sim, sim4);
		struct mesh_node *x, *y, *z;

		ATF_REQUIRE_EQ(0, mesh_sim_init(sim4, NETKEY, APPKEY, 0));
		x = mesh_sim_add_node(sim4, 0x0001, 1);
		y = mesh_sim_add_node(sim4, 0x0002, 1);
		z = mesh_sim_add_node(sim4, 0x0003, 1);	/* no new key */
		ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(x, NETKEY2));
		ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(y, NETKEY2));
		ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(x));
		ATF_REQUIRE_EQ(0, mesh_sim_send_beacon(sim4, x, 0));
		ATF_CHECK_EQ(MESH_KR_PHASE_2, mesh_sim_node_kr_phase(y));
		ATF_CHECK_EQ_MSG(MESH_KR_PHASE_NORMAL, mesh_sim_node_kr_phase(z),
		    "node without the new key ignores the new-key beacon");
	}
}

/* ================================================================
 * Key Refresh Phase 3 revocation and the resulting one-way key gates.
 * Sections 3.11.4.1 and 3.11.4.3 require a new-key KR=0 beacon to enter
 * Phase 3 (even directly from Phase 1), revoke the old key, and return to
 * Normal Operation.  The simulator performs that key promotion atomically.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(key_refresh_phase3);
ATF_TC_BODY(key_refresh_phase3, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *x, *y, *z, *w;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	x = mesh_sim_add_node(sim, 0x0001, 1);
	y = mesh_sim_add_node(sim, 0x0002, 1);
	z = mesh_sim_add_node(sim, 0x0003, 1);
	w = mesh_sim_add_node(sim, 0x0004, 1);		/* new key = old NETKEY */
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(y, 0, mesh_gen_onoff_srv_model(&srv));

	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(x, NETKEY2));
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(y, NETKEY2));
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(z, NETKEY2));
	/* W's "new" key is the original NetKey: a NETKEY2 beacon will fail W's
	 * new-key authentication (exercises the parse-failed arm). */
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(w, NETKEY));
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(y));	/* Y -> Phase 2 */
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(z));	/* Z -> Phase 2 */

	/* X (Phase 1) beacons the new key with KR=0.  Phase-2 Y/Z enter
	 * Phase 3, revoke/promote atomically, and return to state 0. */
	ATF_REQUIRE_EQ(0, mesh_sim_send_beacon(sim, x, 0));
	ATF_CHECK_EQ(MESH_KR_PHASE_NORMAL, mesh_sim_node_kr_phase(y));
	ATF_CHECK_EQ(MESH_KR_PHASE_NORMAL, mesh_sim_node_kr_phase(z));

	/* Both settled nodes now use the promoted new key. */
	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, z, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(1, srv.present, "settled nodes accept the new key");

	/* W still transmits using the revoked old key; its valid access message
	 * must no longer reach Y. */
	set.onoff = 0;
	set.tid = 2;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, w, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(1, srv.present, "settled node rejects the old key");

	/* Y's own state-0 beacon uses the promoted key with KR=0. */
	ATF_REQUIRE_EQ(0, mesh_sim_send_beacon(sim, y, 0));
}

/* ================================================================
 * Crafted control-PDU injection: the Friend-Poll control handler's guard
 * conjuncts (opcode == Poll, node is Friend, source is the LPN).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(control_injection);
ATF_TC_BODY(control_injection, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *f, *p;
	struct mesh_friend_poll poll;
	struct mesh_seg_ack ack;
	uint8_t lt[MESH_FRIEND_POLL_LEN], sack[MESH_SEG_ACK_LEN];
	size_t ltl, sackl;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	f = mesh_sim_add_node(sim, 0x0002, 1);
	p = mesh_sim_add_node(sim, 0x0003, 1);		/* plain (non-Friend) */
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, 0x0005, 1, 8));

	poll.fsn = 0;
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, lt, &ltl));

	/* A Friend Poll to the Friend but from a NON-LPN source: the opcode
	 * and is-Friend conjuncts hold, the src == LPN conjunct fails. */
	inject_pdu(sim, NETKEY, 1, 0x00cc, 0x0002, 10, lt, ltl);
	mesh_sim_run(sim, 3);

	/* A NON-Poll control PDU (Segment Ack, opcode 0x00) to the Friend:
	 * the opcode conjunct fails. */
	memset(&ack, 0, sizeof(ack));
	ack.seqzero = 1;
	ATF_REQUIRE_EQ(0, mesh_seg_ack_build(&ack, sack, &sackl));
	inject_pdu(sim, NETKEY, 1, 0x00cc, 0x0002, 11, sack, sackl);
	mesh_sim_run(sim, 3);

	/* A Friend Poll addressed to a NON-Friend node: the is-Friend conjunct
	 * fails. */
	inject_pdu(sim, NETKEY, 1, 0x00cc, 0x0003, 12, lt, ltl);
	mesh_sim_run(sim, 3);

	/* Nothing crashed and no message was queued at the Friend. */
	ATF_CHECK_EQ(0u, mesh_fq_count(&f->fq));
	(void)p;
}

/* ================================================================
 * Provisioning end to end (MshPRT_v1.1 Section 5): a Provisioner runs the
 * PB-ADV exchange to an unprovisioned device over the virtual bearer; both
 * reach the same DevKey and the joined node participates in network traffic.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(provisioning_e2e);
ATF_TC_BODY(provisioning_e2e, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_sim_prov pv;
	struct mesh_node *prov, *joined;
	struct mesh_gen_onoff_cli cli;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t uuid[16];
	uint8_t pdu[8];
	size_t plen;

	memset(uuid, 0x5a, sizeof(uuid));
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, IV0));

	/* An already-provisioned node that will drive traffic to the newcomer. */
	prov = mesh_sim_add_node(sim, 0x0001, 1);
	ATF_REQUIRE(prov != NULL);
	mesh_gen_onoff_cli_init(&cli);
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(prov, 0,
	    mesh_gen_onoff_cli_model(&cli)));

	/* Provision a device onto unicast 0x0007 over PB-ADV. */
	ATF_REQUIRE_EQ(0, mesh_sim_provision_begin(sim, &pv, uuid, 0x0007, 1));
	ATF_REQUIRE_EQ(0, mesh_sim_provision_run(sim, &pv, 64));

	/* Both sides derived the SAME DevKey (Section 5.4.2.5). */
	ATF_CHECK_EQ_MSG(0, memcmp(mesh_sim_prov_devkey(&pv, 0),
	    mesh_sim_prov_devkey(&pv, 1), 16), "Provisioner and Device DevKey");

	/* The device joins the network at its assigned unicast. */
	joined = mesh_sim_provision_commit(sim, &pv);
	ATF_REQUIRE(joined != NULL);
	ATF_CHECK_EQ(0x0007, joined->addr);
	mesh_gen_onoff_srv_init(&srv, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(joined, 0,
	    mesh_gen_onoff_srv_model(&srv)));

	/* The freshly provisioned node participates in network traffic. */
	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&set, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, prov, 0x0007,
	    MESH_OP_GEN_ONOFF_SET, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ_MSG(1, srv.present, "provisioned node applied the message");
	ATF_CHECK_EQ_MSG(1, cli.have_status, "and answered with a Status");

	mesh_prov_session_free(&pv.sess[0]);
	mesh_prov_session_free(&pv.sess[1]);
}

/* ================================================================
 * Directed Forwarding (MshPRT_v1.1 Section 3.6.6): a path is discovered along
 * a line and a message then follows the directed path (bypassing an off-path
 * neighbour that managed flooding would reach); the path expires and directed
 * routing yields back to flooding until re-discovery.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(directed_forwarding_e2e);
ATF_TC_BODY(directed_forwarding_e2e, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *b, *c, *d, *e;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;
	uint32_t e_relay_after_disc;
	uint64_t now_ms;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);		/* Path Origin */
	b = mesh_sim_add_node(sim, 0x0002, 1);
	c = mesh_sim_add_node(sim, 0x0003, 1);
	d = mesh_sim_add_node(sim, 0x0004, 1);		/* Path Target */
	e = mesh_sim_add_node(sim, 0x0005, 1);		/* off-path witness */
	mesh_gen_onoff_srv_init(&srv, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(d, 0, mesh_gen_onoff_srv_model(&srv)));

	mesh_sim_set_df(a, 1);
	mesh_sim_set_df(b, 1);
	mesh_sim_set_df(c, 1);
	mesh_sim_set_df(d, 1);
	mesh_sim_set_df(e, 1);

	/* Line A-B-C-D; E hangs off B (only reachable by flooding through B). */
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, a, b));
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, b, c));
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, c, d));
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, b, e));

	/* Before discovery a message from A to D is managed-flooded: the
	 * off-path node E hears (and re-broadcasts) it. */
	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0004,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 16);
	ATF_CHECK_EQ_MSG(1, srv.present, "flooded message reached the target");
	ATF_CHECK_MSG(e->relay_count > 0, "off-path E re-broadcast the flood");

	/* Discover a directed path A -> D (Path Request / Reply / Confirmation). */
	ATF_REQUIRE_EQ(0, mesh_sim_df_discover(sim, a, 0x0004,
	    MESH_DF_LIFETIME_12_MIN));
	now_ms = (uint64_t)sim->now * 1000ULL;
	ATF_CHECK_MSG(mesh_df_table_lookup(&b->df_table, 0x0001, 0x0004,
	    now_ms) != NULL, "B installed a forwarding entry for A->D");
	ATF_CHECK_MSG(mesh_df_table_lookup(&c->df_table, 0x0001, 0x0004,
	    now_ms) != NULL, "C installed a forwarding entry for A->D");

	/* Now a message from A to D follows the DIRECTED path: E is bypassed. */
	e_relay_after_disc = e->relay_count;
	b->df_directed_fwd = 0;
	c->df_directed_fwd = 0;
	mesh_gen_onoff_srv_init(&srv, 0);
	set.tid = 2;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0004,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 16);
	ATF_CHECK_EQ_MSG(1, srv.present, "directed message reached the target");
	ATF_CHECK_MSG(b->df_directed_fwd > 0, "B forwarded along the path");
	ATF_CHECK_MSG(c->df_directed_fwd > 0, "C forwarded along the path");
	ATF_CHECK_EQ_MSG(e_relay_after_disc, e->relay_count,
	    "off-path E never saw the directed message");

	/* Expire the path: the forwarding entries lapse (Section 3.6.6.5). */
	mesh_sim_advance(sim, 12UL * 60UL + 5);		/* > 12 minutes */
	mesh_sim_df_expire(sim);
	now_ms = (uint64_t)sim->now * 1000ULL;
	ATF_CHECK_MSG(mesh_df_table_lookup(&b->df_table, 0x0001, 0x0004,
	    now_ms) == NULL, "B's path expired");

	/* With no path, A->D falls back to flooding: E hears it again. */
	e_relay_after_disc = e->relay_count;
	mesh_gen_onoff_srv_init(&srv, 0);
	set.tid = 3;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0004,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 16);
	ATF_CHECK_EQ_MSG(1, srv.present, "flood after expiry reached the target");
	ATF_CHECK_MSG(e->relay_count > e_relay_after_disc,
	    "after expiry the message floods through E again");

	/* Re-discovery re-establishes the directed path. */
	ATF_REQUIRE_EQ(0, mesh_sim_df_discover(sim, a, 0x0004,
	    MESH_DF_LIFETIME_12_MIN));
	now_ms = (uint64_t)sim->now * 1000ULL;
	ATF_CHECK_MSG(mesh_df_table_lookup(&b->df_table, 0x0001, 0x0004,
	    now_ms) != NULL, "path re-discovered");
}

/* ================================================================
 * Heartbeat propagation (MshPRT_v1.1 Section 3.6.5.4, MshMDL_v1.1 4.4.1): a
 * publisher emits feature-change and periodic Heartbeats; a subscriber two
 * hops away counts them and its min/max hops reflect the topology distance.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(heartbeat_e2e);
ATF_TC_BODY(heartbeat_e2e, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *pub, *r, *sub;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	pub = mesh_sim_add_node(sim, 0x0001, 1);
	r = mesh_sim_add_node(sim, 0x0002, 1);
	sub = mesh_sim_add_node(sim, 0x0003, 1);
	mesh_sim_set_relay(r, 1);

	/* Line pub - r - sub: the subscriber is two hops (one relay) away. */
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, pub, r));
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, r, sub));

	/*
	 * Publish to group 0xC000 with InitTTL 5, triggering on a Friend feature
	 * change, and a 1-second period with a count of two publications.
	 */
	mesh_sim_hb_set_pub(pub, 0xC000, 0x02 /* count 2 */, 0x01 /* 1 s */, 5,
	    MESH_HB_FEATURE_FRIEND, MESH_HB_FEATURE_FRIEND);
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe(sub, 0xC000));
	mesh_sim_hb_set_sub(sub, 0x0001, 0xC000, 0x07);

	/* Feature change (Friend cleared) publishes a triggered Heartbeat. */
	ATF_CHECK_EQ_MSG(1, mesh_sim_hb_feature_change(sim, pub, 0),
	    "feature-change Heartbeat published");
	mesh_sim_run(sim, 8);
	ATF_CHECK_EQ_MSG(1u, (unsigned)sub->hb_sub.count,
	    "subscriber counted the Heartbeat");
	/* hops = InitTTL - RxTTL + 1 = 5 - 4 + 1 = 2, matching the topology. */
	ATF_CHECK_EQ_MSG(2, sub->hb_sub.min_hops, "min hops = topology distance");
	ATF_CHECK_EQ_MSG(2, sub->hb_sub.max_hops, "max hops = topology distance");

	/*
	 * MshPRT §3.6.7.2: the first periodic Heartbeat is published as soon
	 * as possible after configuration, independently of the triggered one.
	 */
	ATF_CHECK_EQ(1, mesh_sim_hb_publish_periodic(sim, pub, 0));
	mesh_sim_run(sim, 8);
	ATF_CHECK_EQ_MSG(2u, (unsigned)sub->hb_sub.count,
	    "subscriber counted the immediate periodic Heartbeat");

	/* CountLog 0x02 represents two periodic publications; the next is due
	 * after PeriodLog 0x01 decodes to one second. */
	mesh_sim_advance(sim, 1);
	ATF_CHECK_EQ(1, mesh_sim_hb_publish_periodic(sim, pub, 1));
	mesh_sim_run(sim, 8);
	ATF_CHECK_EQ_MSG(3u, (unsigned)sub->hb_sub.count,
	    "subscriber counted triggered plus both periodic Heartbeats");
	ATF_CHECK_EQ(2, sub->hb_sub.min_hops);
	ATF_CHECK_EQ(2, sub->hb_sub.max_hops);
}

ATF_TC_WITHOUT_HEAD(subsecond_transition_clock);
ATF_TC_BODY(subsecond_transition_clock, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *client, *server;
	struct mesh_gen_level_srv srv;
	struct mesh_gen_level_set set = { 10000, 1, 1, 0x0a, 0 };
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	client = mesh_sim_add_node(sim, 0x0001, 1);
	server = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE(client != NULL && server != NULL);
	mesh_gen_level_srv_init(&srv, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(server, 0,
	    mesh_gen_level_srv_model(&srv)));
	ATF_REQUIRE_EQ(0, mesh_gen_level_set_encode(&set, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, client, 0x0002,
	    MESH_OP_GEN_LEVEL_SET_UNACK, pdu, plen, 5));
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ(0, srv.present);

	mesh_sim_advance_ms(sim, 500);
	ATF_CHECK_EQ(5000, srv.present);
	ATF_CHECK_EQ(0, sim->now);
	ATF_CHECK_EQ(500, sim->now_ms);

	mesh_sim_advance_ms(sim, 500);
	ATF_CHECK_EQ(10000, srv.present);
	ATF_CHECK_EQ(1, sim->now);
	ATF_CHECK_EQ(1000, sim->now_ms);
}

ATF_TC_WITHOUT_HEAD(virtual_address_aad_delivery);
ATF_TC_BODY(virtual_address_aad_delivery, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *client, *server;
	struct mesh_gen_onoff_srv srv, unsubscribed;
	static const uint8_t label[MESH_LABEL_UUID_LEN] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	uint8_t params[2] = { MESH_GEN_ON, 1 };
	uint16_t va;
	uint16_t app_idx = 0;
	int is_va = 1;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, IV0));
	client = mesh_sim_add_node(sim, 0x0001, 1);
	server = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE(client != NULL && server != NULL);
	mesh_gen_onoff_srv_init(&srv, MESH_GEN_OFF);
	mesh_gen_onoff_srv_init(&unsubscribed, MESH_GEN_OFF);
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(server, 0,
	    mesh_gen_onoff_srv_model(&srv)));
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(server, 0,
	    mesh_gen_onoff_srv_model(&unsubscribed)));
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe_virtual_element(server, 0, label));
	ATF_REQUIRE_EQ(0, mesh_virtual_addr(label, &va));
	server->models[0][0].subs = &va;
	server->models[0][0].labels = &label;
	server->models[0][0].sub_is_va = &is_va;
	server->models[0][0].n_subs = 1;
	server->models[0][0].subscriptions_configured = 1;
	server->models[0][0].app_idx = &app_idx;
	server->models[0][0].n_app = 1;
	server->models[0][0].bindings_configured = 1;
	server->models[0][1].subscriptions_configured = 1;
	server->models[0][1].bindings_configured = 1;
	ATF_CHECK(mesh_access_elem_addressed(&server->elems[0], va));
	ATF_CHECK_EQ(-1, mesh_sim_send_access(sim, client, va,
	    MESH_OP_GEN_ONOFF_SET_UNACK, params, sizeof(params), 5));

	ATF_REQUIRE_EQ(0, mesh_sim_send_access_key_from_virtual(sim, client,
	    client->addr, 0, 0, label, MESH_OP_GEN_ONOFF_SET_UNACK,
	    params, sizeof(params), 5));
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ(MESH_GEN_ON, srv.present);
	ATF_CHECK_EQ(MESH_GEN_OFF, unsubscribed.present);
	ATF_CHECK_EQ(va, server->rx.dst);
	ATF_CHECK_EQ(MESH_OP_GEN_ONOFF_SET_UNACK, server->rx.opcode);
}

ATF_TC_WITHOUT_HEAD(devkey_foundation_roundtrip);
ATF_TC_BODY(devkey_foundation_roundtrip, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *client, *server;
	uint8_t access[8], upper[MESH_UPPER_MAX], client_key[16] = { 0 };
	size_t access_len, upper_len;
	uint32_t seq;
	int n;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, IV0));
	client = mesh_sim_add_node(sim, 0x0001, 1);
	server = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE(client != NULL && server != NULL);
	ATF_REQUIRE_EQ(0, mesh_sim_set_devkey(server, DEVKEY,
	    devkey_server_rx, NULL));
	ATF_REQUIRE_EQ(0, mesh_sim_set_devkey(client, client_key,
	    devkey_server_rx, NULL));
	ATF_REQUIRE_EQ(0, mesh_sim_set_devkey_client(client, devkey_lookup,
	    devkey_client_rx, NULL));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_CFG_OP_DEFAULT_TTL_GET,
	    NULL, 0, access, &access_len));
	seq = client->seq;
	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(DEVKEY, 0, 0, seq, client->addr,
	    server->addr, IV0, NULL, access, access_len, upper, &upper_len));
	n = mesh_sim_send_upper(sim, client, server->addr, seq, upper, upper_len,
	    0, 0, 5);
	ATF_REQUIRE(n > 0);
	client->seq += (uint32_t)n;
	devkey_server_seen = devkey_client_seen = 0;
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ(1, devkey_server_seen);
	ATF_CHECK_EQ(1, devkey_client_seen);
	ATF_CHECK_EQ(MESH_CFG_OP_DEFAULT_TTL_STATUS, client->rx.opcode);
}

ATF_TC_WITHOUT_HEAD(secondary_subnet_key_lifecycle);
ATF_TC_BODY(secondary_subnet_key_lifecycle, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *client, *server;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t newkey[16], pdu[8];
	size_t plen;

	memset(newkey, 0x77, sizeof(newkey));
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, IV0));
	client = mesh_sim_add_node(sim, 0x0001, 1);
	server = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE(client != NULL);
	ATF_REQUIRE(server != NULL);
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(client, 1, NETKEY2));
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(server, 1, NETKEY2));
	ATF_REQUIRE_EQ(0, mesh_sim_add_appkey(client, 1, 1, APPKEY));
	ATF_REQUIRE_EQ(0, mesh_sim_add_appkey(server, 1, 1, APPKEY));
	mesh_gen_onoff_srv_init(&srv, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(server, 0,
	    mesh_gen_onoff_srv_model(&srv)));

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&set, 0, pdu, &plen));
	ATF_REQUIRE(mesh_sim_send_access_key(sim, client, 1, 1, server->addr,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5) >= 0);
	ATF_CHECK(mesh_sim_run(sim, 10) > 0);
	ATF_CHECK_EQ(srv.present, 1);

	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_begin(client, 1, newkey));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_begin(server, 1, newkey));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_advance(client, 1));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_advance(server, 1));
	ATF_CHECK_EQ(mesh_sim_subnet_kr_phase(client, 1), MESH_KR_PHASE_2);
	set.onoff = 0;
	set.tid++;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&set, 0, pdu, &plen));
	ATF_REQUIRE(mesh_sim_send_access_key_from(sim, client, client->addr,
	    1, 1, server->addr, MESH_OP_GEN_ONOFF_SET_UNACK,
	    pdu + 2, plen - 2, 5) >= 0);
	ATF_CHECK(mesh_sim_run(sim, 10) > 0);
	ATF_CHECK_EQ(srv.present, 0);

	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_finalize(client, 1));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_finalize(server, 1));
	ATF_CHECK_EQ(mesh_sim_subnet_kr_phase(client, 1), MESH_KR_PHASE_NORMAL);
	ATF_CHECK_EQ(client->subnets[0].have_new_key, 0);
	ATF_CHECK(memcmp(client->subnets[0].netkey, newkey, 16) == 0);
	ATF_CHECK_EQ(-1, mesh_sim_subnet_key_refresh_finalize(client, 1));
}

ATF_TC_WITHOUT_HEAD(sequence_exhaustion_is_atomic);
ATF_TC_BODY(sequence_exhaustion_is_atomic, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *src, *dst;
	uint8_t params[32];

	memset(params, 0x5a, sizeof(params));
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, IV0));
	src = mesh_sim_add_node(sim, 0x0001, 1);
	dst = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE(src != NULL && dst != NULL);

	/* This access message needs multiple Network PDUs, but only one SEQ
	 * remains.  Reject it before placing any segment on the medium. */
	src->seq = MESH_IV_SEQ_MAX;
	ATF_CHECK_EQ(-1, mesh_sim_send_access(sim, src, dst->addr, 0x01,
	    params, sizeof(params), 5));
	ATF_CHECK_EQ(sim->n_tx, 0u);
	ATF_CHECK_EQ(src->seq, MESH_IV_SEQ_MAX);

	/* A single-PDU message may consume the final value exactly once. */
	ATF_CHECK_EQ(0, mesh_sim_send_access(sim, src, dst->addr, 0x01,
	    NULL, 0, 5));
	ATF_CHECK_EQ(src->seq, MESH_IV_SEQ_MAX + 1u);
	ATF_CHECK_EQ(-1, mesh_sim_send_access(sim, src, dst->addr, 0x01,
	    NULL, 0, 5));
}

/* ================================================================
 * Finding 76: a half-installed Forwarding Table entry carries
 * MESH_DF_BEARER_NONE (0) for the required direction.  Bearer 0 aliases node
 * index 0, so the directed path must NOT be taken - the PDU falls back to
 * managed flooding and still reaches the target rather than being blackholed
 * to node 0.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(df_half_installed_entry_floods);
ATF_TC_BODY(df_half_installed_entry_floods, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *b, *d;		/* index 0 == a */
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);		/* node index 0 */
	b = mesh_sim_add_node(sim, 0x0002, 1);
	d = mesh_sim_add_node(sim, 0x0004, 1);
	ATF_REQUIRE(a != NULL && b != NULL && d != NULL);
	mesh_gen_onoff_srv_init(&srv, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(d, 0, mesh_gen_onoff_srv_model(&srv)));

	/* B routes with Directed Forwarding + managed-flooding fallback. */
	mesh_sim_set_df(b, 1);
	/* A -- B -- D: the target is reachable only through B. */
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, a, b));
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, b, d));

	/*
	 * Install a half-installed entry for A->D at B: the bearer toward the
	 * target is MESH_DF_BEARER_NONE (0).  A message A->D selects that bearer;
	 * without the guard the sim would unicast to node index 0 (A) and drop
	 * the PDU, never reaching D.
	 */
	ATF_REQUIRE(mesh_df_table_add(&b->df_table, 0x0001, 0x0004, 0,
	    1 /* bearer_toward_origin */, MESH_DF_BEARER_NONE /* toward target */,
	    720000, 0) != NULL);

	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0004,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 16);

	ATF_CHECK_EQ_MSG(1, srv.present,
	    "PDU flooded to D instead of being blackholed to node 0");
}

/* ================================================================
 * Finding 22: a Path Reply from a Path Target advertises range_length equal to
 * its element count, so discovery to a secondary element address is covered by
 * range_covers() at the origin and the path establishes.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(df_reply_covers_secondary_element);
ATF_TC_BODY(df_reply_covers_secondary_element, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *d;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);		/* Path Origin */
	d = mesh_sim_add_node(sim, 0x0004, 2);		/* Target: elems 4,5 */
	ATF_REQUIRE(a != NULL && d != NULL);

	mesh_sim_set_df(a, 1);
	mesh_sim_set_df(d, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, a, d));

	/*
	 * Discover a path to the Target's SECONDARY element (0x0005).  The Reply
	 * ranges from the Target's primary address; only a range_length equal to
	 * the element count covers 0x0005, so the origin accepts the reply and the
	 * discovery reaches MESH_DF_DISC_ESTABLISHED (mesh_sim_df_discover == 0).
	 */
	ATF_CHECK_EQ_MSG(0, mesh_sim_df_discover(sim, a, 0x0005,
	    MESH_DF_LIFETIME_12_MIN),
	    "path to a secondary element established");
}

/* ================================================================
 * Finding 23: after an LPN Poll whose response was empty/lost, the Friend
 * Sequence Number must NOT toggle; otherwise the next Poll's changed FSN is
 * misread by the Friend as an ack and the still-undelivered head is dropped.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(lpn_poll_lost_response_preserves_fsn);
ATF_TC_BODY(lpn_poll_lost_response_preserves_fsn, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *f, *l;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	f = mesh_sim_add_node(sim, 0x0002, 1);
	l = mesh_sim_add_node(sim, 0x0005, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(l, 0, mesh_gen_onoff_srv_model(&srv));
	mesh_sim_set_relay(f, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, 0x0005, 1, 8));
	ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(l, 0x0002, 0x0000a0));
	ATF_REQUIRE_EQ(0, mesh_sim_establish_friendship(sim, f, l, 0, 0, 0));
	mesh_sim_link(sim, c, f);
	mesh_sim_link(sim, f, l);

	/* First Poll with an EMPTY queue: the Friend answers nothing. */
	ATF_CHECK_EQ(0, mesh_sim_lpn_poll(sim, l));

	/* Now a message is queued at the Friend for the LPN. */
	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 7;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0005,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 10);
	ATF_REQUIRE_EQ(1u, mesh_fq_count(&f->fq));

	/*
	 * The next Poll must still carry the unchanged FSN so the Friend delivers
	 * the queued head.  If the empty first Poll had toggled the FSN, this Poll
	 * would look like an ack and the head would be discarded undelivered.
	 */
	ATF_CHECK_EQ_MSG(1, mesh_sim_lpn_poll(sim, l),
	    "queued head delivered, not dropped by a spurious FSN toggle");
	ATF_CHECK_EQ(1, srv.present);
}

/* ================================================================
 * Finding 70: SeqAuth is derived from SeqZero, not (SEQ - SegO).  A compliant
 * peer may (re)transmit a segment with any SEQ in [SeqAuth, SeqAuth+8191]; such
 * a segment must still reassemble.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(segmented_seqauth_from_seqzero);
ATF_TC_BODY(segmented_seqauth_from_seqzero, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *b;
	uint8_t params[13], access[MESH_ACCESS_PAYLOAD_MAX];
	uint8_t upper[MESH_UPPER_MAX], aid;
	struct mesh_seg seg[MESH_SEG_MAX];
	size_t access_len, upper_len, nseg, i;
	const uint32_t seq0 = 0x000100;		/* SeqAuth; SeqZero = 0x100 */
	const uint32_t seq1 = 0x000105;		/* SegO 1 retransmitted later */

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	b = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE(b != NULL);
	ATF_REQUIRE_EQ(0, mesh_k4(APPKEY, &aid));

	for (i = 0; i < sizeof(params); i++)
		params[i] = (uint8_t)(0xA0 + i);
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(0x8299, params, sizeof(params),
	    access, &access_len));
	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(APPKEY, 1, 0, seq0, 0x0001, 0x0002,
	    0, NULL, access, access_len, upper, &upper_len));
	ATF_REQUIRE_EQ(0, mesh_sar_segment(1, aid, 0, (uint16_t)(seq0 & 0x1fff),
	    upper, upper_len, seg, MESH_SEG_MAX, &nseg));
	ATF_REQUIRE_EQ(2u, nseg);

	/*
	 * Deliver SegO 0 with SEQ=SeqAuth, then SegO 1 with a LATER SEQ (as if
	 * three unrelated messages were sent between the original and its
	 * retransmission).  (SEQ - SegO) no longer equals SeqAuth, so the buggy
	 * derivation rejects SegO 1 and the message never completes.
	 */
	inject_pdu(sim, NETKEY, 0, 0x0001, 0x0002, seq0, seg[0].bytes,
	    seg[0].len);
	inject_pdu(sim, NETKEY, 0, 0x0001, 0x0002, seq1, seg[1].bytes,
	    seg[1].len);
	mesh_sim_run(sim, 10);

	ATF_CHECK_EQ_MSG(1u, b->rx.count,
	    "segment with a non-consecutive SEQ still reassembled");
	ATF_CHECK_EQ(0x8299u, b->rx.opcode);
	ATF_CHECK_EQ(sizeof(params), b->rx.params_len);
	ATF_CHECK_EQ(0, memcmp(b->rx.params, params, sizeof(params)));
}

/* ================================================================
 * Finding 78: a Friend node must secure a Segment Ack to a THIRD party with the
 * normal network credential, not the friendship credential (which the third
 * party cannot decrypt).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(segack_third_party_net_credential);
ATF_TC_BODY(segack_third_party_net_credential, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *t, *f, *l;
	uint8_t params[20];
	size_t i;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	t = mesh_sim_add_node(sim, 0x0001, 1);		/* third-party SAR origin */
	f = mesh_sim_add_node(sim, 0x0002, 1);		/* Friend (has friend cred) */
	l = mesh_sim_add_node(sim, 0x0005, 1);		/* LPN */
	ATF_REQUIRE(t != NULL && f != NULL && l != NULL);
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, 0x0005, 1, 8));
	ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(l, 0x0002, 0x0000a0));
	ATF_REQUIRE_EQ(0, mesh_sim_establish_friendship(sim, f, l, 0, 0, 0));

	for (i = 0; i < sizeof(params); i++)
		params[i] = (uint8_t)(i + 1);

	/* T sends a segmented message to the Friend's own unicast address. */
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, t, 0x0002, 0x8299,
	    params, sizeof(params), 5));
	mesh_sim_run(sim, 20);

	/*
	 * The Friend acks with the normal network credential, so T decrypts the
	 * ack and completes its SAR transaction (the outbound session is freed).
	 * A friendship-credential ack could not be decrypted by T, leaving the
	 * session pending forever.
	 */
	ATF_CHECK_EQ_MSG(0, t->sar_tx[0].used,
	    "third party received and processed the Segment Ack");
}

/* ================================================================
 * Finding 81: a Segment Ack is sent only when the received DST is a unicast
 * address of this node.  Group/virtual-addressed segmented messages are never
 * acknowledged (MshPRT_v1.1 3.5.3.4).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(segack_suppressed_for_group_dst);
ATF_TC_BODY(segack_suppressed_for_group_dst, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *b;
	uint8_t params[20];
	size_t i;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);
	b = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE(a != NULL && b != NULL);
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe(b, 0xC000));

	for (i = 0; i < sizeof(params); i++)
		params[i] = (uint8_t)(i + 1);

	/* Segmented message to a GROUP address B subscribes to. */
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0xC000, 0x8299,
	    params, sizeof(params), 5));
	mesh_sim_run(sim, 20);

	/*
	 * B reassembled the group message but must NOT emit a Segment Ack, so it
	 * originated no control PDU and its SEQ never advanced.
	 */
	ATF_CHECK_EQ_MSG(0u, mesh_sim_node_seq(b),
	    "no Segment Ack originated for a group-addressed segmented message");
}

/* ================================================================
 * Finding 82: a Segment Ack is sent with a fresh default TTL, not the residual
 * (already decremented) received TTL, so it can traverse the same number of
 * hops back to the SAR origin.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(segack_uses_default_ttl_multihop);
ATF_TC_BODY(segack_uses_default_ttl_multihop, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *r1, *r2, *b;
	uint8_t params[20];
	size_t i;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);		/* SAR origin */
	r1 = mesh_sim_add_node(sim, 0x0002, 1);
	r2 = mesh_sim_add_node(sim, 0x0003, 1);
	b = mesh_sim_add_node(sim, 0x0004, 1);		/* reassembler */
	ATF_REQUIRE(a != NULL && r1 != NULL && r2 != NULL && b != NULL);
	mesh_sim_set_relay(r1, 1);
	mesh_sim_set_relay(r2, 1);
	/* A -- R1 -- R2 -- B: three hops each direction. */
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, a, r1));
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, r1, r2));
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, r2, b));

	for (i = 0; i < sizeof(params); i++)
		params[i] = (uint8_t)(i + 1);

	/*
	 * Send with a small initial TTL (3) so the segments arrive at B with a
	 * residual TTL of 1.  A residual-TTL ack could not be relayed back; only a
	 * fresh default TTL lets the ack reach A and complete its SAR session.
	 */
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0004, 0x8299,
	    params, sizeof(params), 3));
	mesh_sim_run(sim, 40);

	ATF_CHECK_EQ_MSG(1u, b->rx.count, "segmented message reached B");
	ATF_CHECK_EQ_MSG(0, a->sar_tx[0].used,
	    "the Segment Ack reached the origin three hops back");
}

/* ================================================================
 * Finding 85: a Proxy Server hands a PDU received over its GATT bearer to its
 * own network layer as well as relaying it, so a PDU addressed to the proxy is
 * delivered locally (MshPRT_v1.1 6.7).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_gatt_in_local_delivery);
ATF_TC_BODY(proxy_gatt_in_local_delivery, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *p;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8], wire[MESH_NET_MAX_PDU];
	size_t plen, wlen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	p = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE(c != NULL && p != NULL);
	mesh_gen_onoff_srv_init(&srv, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(p, 0, mesh_gen_onoff_srv_model(&srv)));
	mesh_sim_set_proxy(p);

	/* Craft a secured PDU addressed to the proxy's own unicast address. */
	memset(&set, 0, sizeof(set));
	set.onoff = 1;
	set.tid = 1;
	mesh_gen_onoff_cli_set(&set, 0, pdu, &plen);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	ATF_REQUIRE_EQ(1u, mesh_sim_pending(sim));
	wlen = sim->tx[0].len;
	memcpy(wire, sim->tx[0].bytes, wlen);
	sim->n_tx = 0;			/* do not deliver over the shared medium */

	/* Hand the PDU in over the proxy's GATT bearer. */
	ATF_REQUIRE_EQ(0, mesh_sim_proxy_gatt_in(sim, p, wire, wlen));
	mesh_sim_run(sim, 10);

	ATF_CHECK_EQ_MSG(1, srv.present,
	    "proxy delivered the GATT-received PDU to its own network layer");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, onoff_one_hop);
	ATF_TP_ADD_TC(tp, level_and_delta_e2e);
	ATF_TP_ADD_TC(tp, multihop_two_hop);
	ATF_TP_ADD_TC(tp, multihop_rpl_dedup);
	ATF_TP_ADD_TC(tp, group_delivery);
	ATF_TP_ADD_TC(tp, friend_lpn_poll);
	ATF_TP_ADD_TC(tp, iv_update_propagate);
	ATF_TP_ADD_TC(tp, key_refresh_propagate);
	ATF_TP_ADD_TC(tp, replay_dropped);
	ATF_TP_ADD_TC(tp, segmented_reassembly);
	ATF_TP_ADD_TC(tp, traffic_during_iv_update);
	ATF_TP_ADD_TC(tp, onoff_set_unack);
	ATF_TP_ADD_TC(tp, onoff_get_e2e);
	ATF_TP_ADD_TC(tp, level_move_e2e);
	ATF_TP_ADD_TC(tp, delta_transaction_e2e);
	ATF_TP_ADD_TC(tp, relay_ttl_limit);
	ATF_TP_ADD_TC(tp, friend_multi_message);
	ATF_TP_ADD_TC(tp, multi_element_addressing);
	ATF_TP_ADD_TC(tp, iv_complete_and_traffic);
	ATF_TP_ADD_TC(tp, robustness);
	ATF_TP_ADD_TC(tp, misc_branches);
	ATF_TP_ADD_TC(tp, deep_branches);
	ATF_TP_ADD_TC(tp, key_refresh_phase3);
	ATF_TP_ADD_TC(tp, control_injection);
	ATF_TP_ADD_TC(tp, provisioning_e2e);
	ATF_TP_ADD_TC(tp, directed_forwarding_e2e);
	ATF_TP_ADD_TC(tp, heartbeat_e2e);
	ATF_TP_ADD_TC(tp, subsecond_transition_clock);
	ATF_TP_ADD_TC(tp, virtual_address_aad_delivery);
	ATF_TP_ADD_TC(tp, devkey_foundation_roundtrip);
	ATF_TP_ADD_TC(tp, api_limits);
	ATF_TP_ADD_TC(tp, secondary_subnet_key_lifecycle);
	ATF_TP_ADD_TC(tp, sequence_exhaustion_is_atomic);
	ATF_TP_ADD_TC(tp, df_half_installed_entry_floods);
	ATF_TP_ADD_TC(tp, df_reply_covers_secondary_element);
	ATF_TP_ADD_TC(tp, lpn_poll_lost_response_preserves_fsn);
	ATF_TP_ADD_TC(tp, segmented_seqauth_from_seqzero);
	ATF_TP_ADD_TC(tp, segack_third_party_net_credential);
	ATF_TP_ADD_TC(tp, segack_suppressed_for_group_dst);
	ATF_TP_ADD_TC(tp, segack_uses_default_ttl_multihop);
	ATF_TP_ADD_TC(tp, proxy_gatt_in_local_delivery);

	return (atf_no_error());
}
