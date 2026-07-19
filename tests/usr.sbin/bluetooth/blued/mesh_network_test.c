/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * MULTI-NODE Bluetooth Mesh NETWORK tests, driving the Phase 1-8 libmesh
 * engine through the in-process network simulator (mesh_sim.[ch]).  Where the
 * mesh_sim_test scenarios prove the receive PIPELINE at 1-3 nodes, these prove
 * the stack's NETWORK-LEVEL behaviour across many nodes:
 *
 *   1. RELAY across >=4 nodes: per-hop TTL decrement, TTL exhaustion, and the
 *      Relay-feature gate (MshPRT_v1.1 Section 3.4.6.3 / 3.6.4).
 *   2. REPLAY protection network-wide: per-source RPL over a relayed path, and
 *      the SEQ ordering rule (Section 3.8.8).
 *   3. FRIENDSHIP / LPN: the Friend Queue + Poll delivery secured with the
 *      distinct FRIENDSHIP credential / friend NID (Section 3.6.6.2 / 3.6.6.4).
 *   4. PROXY: the proxy filter (accept/reject list), secured proxy
 *      configuration PDUs, and the GATT<->adv bridge (Section 6).
 *   5. IV Update propagation via Secure Network beacons (Section 3.10.5).
 *   6. KEY REFRESH phase propagation via beacons (Section 3.11.4).
 *   7. Multiple SUBNETS: NID-based routing - a subnet-B message is not
 *      decryptable by subnet-A-only nodes (Section 3.4.6.3).
 *   8. GROUP addressing publish/subscribe reaching all subscribers across
 *      hops and no one else (Section 3.4.2 / 4.2.4).
 *
 * Security material is the MshPRT_v1.1 Section 8 canonical NetKey/AppKey; the
 * exact secured bytes come from the KAT-verified engine, so the tests assert
 * spec OUTCOMES (delivered opcode/params, decremented TTL, RPL/filter/phase
 * behaviour, the friend NID being distinct from the managed-flooding NID)
 * rather than re-deriving ciphertext.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_test_heap.h"
#include "mesh_sim.h"
#include "mesh_generic.h"
#include "mesh_crypto.h"
#include "mesh_friend.h"
#include "mesh_net.h"
#include "mesh_proxy.h"
#include "spec_mesh_network_integration_oracles.h"

static const uint8_t NETKEY[16] = {
	BT_MNET_SAMPLE_NETKEY_BYTES
};
static const uint8_t NETKEY_B[16] = {
	BT_MNET_FIXTURE_NETKEY_B_BYTES
};
static const uint8_t NETKEY_C[16] = {
	BT_MNET_FIXTURE_NETKEY_C_BYTES
};
static const uint8_t APPKEY[16] = {
	BT_MNET_SAMPLE_APPKEY_BYTES
};
static const uint8_t APPKEY_B[16] = {
	BT_MNET_FIXTURE_APPKEY_B_BYTES
};

#define	IV0		BT_MNET_SAMPLE_IV_INDEX
#define	DWELL_SECS	(BT_MNET_IV_DWELL_SECONDS + 10u)
#define	GROUP_A		BT_MNET_GROUP_MIN
#define	GROUP_B		BT_MNET_GROUP_NEXT

/* Originate an unacknowledged Generic OnOff Set (no Status reply generated). */
static void
onoff_send(struct mesh_sim *sim, struct mesh_node *src, uint16_t dst,
    uint8_t onoff, uint8_t tid, uint8_t ttl)
{
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	memset(&set, 0, sizeof(set));
	set.onoff = onoff;
	set.tid = tid;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&set, 0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, src, dst,
	    BT_MNET_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, ttl));
}

/* Same, but originate on the node's SECONDARY subnet. */
static void
onoff_send_subnet(struct mesh_sim *sim, struct mesh_node *src, uint16_t dst,
    uint8_t onoff, uint8_t tid, uint8_t ttl)
{
	struct mesh_gen_onoff_set set;
	uint8_t pdu[8];
	size_t plen;

	memset(&set, 0, sizeof(set));
	set.onoff = onoff;
	set.tid = tid;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&set, 0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_sim_send_access_key(sim, src, 1, 1, dst,
	    BT_MNET_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, ttl));
}

/*
 * Craft a fully secured Network PDU with an explicit (netkey, ctl, src, dst,
 * seq, transport) - used to inject replays and hand-built control/proxy PDUs
 * onto the medium.  Returns the wire length; the bytes are written to out.
 */
static size_t
build_net_pdu(const uint8_t netkey[16], uint8_t ctl, uint16_t src, uint16_t dst,
    uint32_t seq, uint8_t ttl, const uint8_t *transport, size_t tlen,
    uint8_t *out)
{
	uint8_t nid, enc[16], priv[16], p = 0x00;
	struct mesh_net_pdu np;
	size_t ol;

	ATF_REQUIRE_EQ(0, mesh_k2(netkey, &p, 1, &nid, enc, priv));
	memset(&np, 0, sizeof(np));
	np.nid = nid;
	np.ctl = ctl;
	np.ttl = ttl;
	np.seq = seq;
	np.src = src;
	np.dst = dst;
	memcpy(np.transport, transport, tlen);
	np.transport_len = tlen;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(enc, priv, nid, IV0, &np, out, &ol));
	return (ol);
}

/* Managed-flooding (subnet) 7-bit NID for a NetKey. */
static uint8_t
subnet_nid(const uint8_t netkey[16])
{
	uint8_t nid, enc[16], priv[16], p = 0x00;

	ATF_REQUIRE_EQ(0, mesh_k2(netkey, &p, 1, &nid, enc, priv));
	return (nid);
}

/* ================================================================
 * 1. RELAY across a 5-node line: per-hop TTL decrement.
 *    S(1) -- R1(2) -- R2(3) -- R3(4) -- D(5); S cannot reach D directly.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(relay_five_node_ttl_decrement);
ATF_TC_BODY(relay_five_node_ttl_decrement, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *s, *r1, *r2, *r3, *d;
	struct mesh_gen_onoff_srv srv;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	s = mesh_sim_add_node(sim, 0x0001, 1);
	r1 = mesh_sim_add_node(sim, 0x0002, 1);
	r2 = mesh_sim_add_node(sim, 0x0003, 1);
	r3 = mesh_sim_add_node(sim, 0x0004, 1);
	d = mesh_sim_add_node(sim, 0x0005, 1);
	ATF_REQUIRE(s && r1 && r2 && r3 && d);
	mesh_gen_onoff_srv_init(&srv, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(d, 0, mesh_gen_onoff_srv_model(&srv)));
	mesh_sim_set_relay(r1, 1);
	mesh_sim_set_relay(r2, 1);
	mesh_sim_set_relay(r3, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, s, r1));
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, r1, r2));
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, r2, r3));
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, r3, d));

	/* Initial TTL 5; three relay hops -> D sees TTL 5-3 = 2. */
	onoff_send(sim, s, 0x0005, 1, 1, 5);
	mesh_sim_run(sim, 20);

	ATF_CHECK_EQ_MSG(1, srv.present, "server four hops away flipped");
	ATF_CHECK_EQ_MSG(1u, d->rx.count, "delivered exactly once");
	ATF_CHECK_EQ_MSG(2u, d->rx.ttl,
	    "TTL decremented once per relay: 5 - 3 hops = 2");
	ATF_CHECK(r1->relay_count > 0);
	ATF_CHECK(r2->relay_count > 0);
	ATF_CHECK(r3->relay_count > 0);
}

/* TTL exhaustion: an initial TTL too small to survive the relay chain. */
ATF_TC_WITHOUT_HEAD(relay_ttl_exhausted);
ATF_TC_BODY(relay_ttl_exhausted, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *s, *r1, *r2, *r3, *d;
	struct mesh_gen_onoff_srv srv;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	s = mesh_sim_add_node(sim, 0x0001, 1);
	r1 = mesh_sim_add_node(sim, 0x0002, 1);
	r2 = mesh_sim_add_node(sim, 0x0003, 1);
	r3 = mesh_sim_add_node(sim, 0x0004, 1);
	d = mesh_sim_add_node(sim, 0x0005, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(d, 0, mesh_gen_onoff_srv_model(&srv));
	mesh_sim_set_relay(r1, 1);
	mesh_sim_set_relay(r2, 1);
	mesh_sim_set_relay(r3, 1);
	mesh_sim_link(sim, s, r1);
	mesh_sim_link(sim, r1, r2);
	mesh_sim_link(sim, r2, r3);
	mesh_sim_link(sim, r3, d);

	/*
	 * TTL 3: R1 relays 2, R2 relays 1, R3 sees TTL 1 (< 2) and must NOT
	 * relay (Section 3.4.6.3), so the PDU never reaches D.
	 */
	onoff_send(sim, s, 0x0005, 1, 1, 3);
	mesh_sim_run(sim, 20);

	ATF_CHECK_EQ_MSG(0u, d->rx.count, "TTL exhausted before reaching D");
	ATF_CHECK_EQ(0, srv.present);
	ATF_CHECK(r1->relay_count > 0);		/* the first hops still relayed */
	ATF_CHECK_EQ_MSG(0u, r3->relay_count, "R3 saw TTL 1 and did not relay");
}

/* The Relay-feature gate: disabling a middle relay breaks reachability. */
ATF_TC_WITHOUT_HEAD(relay_disabled_breaks_path);
ATF_TC_BODY(relay_disabled_breaks_path, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *s, *r1, *r2, *r3, *d;
	struct mesh_gen_onoff_srv srv;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	s = mesh_sim_add_node(sim, 0x0001, 1);
	r1 = mesh_sim_add_node(sim, 0x0002, 1);
	r2 = mesh_sim_add_node(sim, 0x0003, 1);
	r3 = mesh_sim_add_node(sim, 0x0004, 1);
	d = mesh_sim_add_node(sim, 0x0005, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(d, 0, mesh_gen_onoff_srv_model(&srv));
	mesh_sim_set_relay(r1, 1);
	mesh_sim_set_relay(r2, 0);		/* R2 Relay feature OFF */
	mesh_sim_set_relay(r3, 1);
	mesh_sim_link(sim, s, r1);
	mesh_sim_link(sim, r1, r2);
	mesh_sim_link(sim, r2, r3);
	mesh_sim_link(sim, r3, d);

	onoff_send(sim, s, 0x0005, 1, 1, 5);
	mesh_sim_run(sim, 20);

	ATF_CHECK_EQ_MSG(0u, d->rx.count, "path broken at the non-relay node");
	ATF_CHECK_EQ_MSG(0u, r2->relay_count, "R2 relay feature disabled");
}

/* ================================================================
 * 2. REPLAY protection network-wide.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(replay_over_relayed_path);
ATF_TC_BODY(replay_over_relayed_path, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *r, *s;
	struct mesh_gen_onoff_srv srv;
	uint8_t wire[MESH_NET_MAX_PDU];
	size_t wlen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	r = mesh_sim_add_node(sim, 0x0002, 1);
	s = mesh_sim_add_node(sim, 0x0003, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(s, 0, mesh_gen_onoff_srv_model(&srv));
	mesh_sim_set_relay(r, 1);
	mesh_sim_link(sim, c, r);
	mesh_sim_link(sim, r, s);

	onoff_send(sim, c, 0x0003, 1, 1, 5);
	/* Snapshot the secured wire PDU C put on the medium. */
	ATF_REQUIRE_EQ(1u, mesh_sim_pending(sim));
	wlen = sim->tx[0].len;
	memcpy(wire, sim->tx[0].bytes, wlen);
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ_MSG(1u, s->rx.count, "delivered once across the relay");

	/* Re-inject the identical PDU as if from C: the RPL rejects it at S. */
	ATF_REQUIRE_EQ(0, mesh_sim_reinject(sim, c->index, wire, wlen));
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ_MSG(1u, s->rx.count, "replayed PDU dropped by S's RPL");
}

/*
 * Per-source SEQ ordering (Section 3.9.8): a fresh higher SEQ is accepted, an
 * equal-or-lower SEQ from the same SRC is rejected as a replay.  Craft the
 * PDUs directly so we control the SEQ.
 */
ATF_TC_WITHOUT_HEAD(replay_seq_ordering);
ATF_TC_BODY(replay_seq_ordering, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *b;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t apdu[8], upper[32], lt[32], wire[MESH_NET_MAX_PDU];
	struct mesh_lower lower;
	size_t plen, upper_len, lt_len, wlen;
	uint8_t aid;
	uint32_t seq;

	/* Sim IV Index matches the IV0 the crafted PDUs are secured under. */
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, IV0));
	a = mesh_sim_add_node(sim, 0x0001, 1);		/* nominal SRC of the PDUs */
	b = mesh_sim_add_node(sim, 0x0002, 1);
	(void)a;
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(b, 0, mesh_gen_onoff_srv_model(&srv));
	ATF_REQUIRE_EQ(0, mesh_k4(APPKEY, &aid));

	/* The client encoding IS the access PDU (opcode||params); vary SEQ. */
	memset(&set, 0, sizeof(set));
	set.onoff = BT_MNET_GENERIC_ONOFF_ON;
	set.tid = 9;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&set, 0, apdu, &plen));

	/* helper builds wire for a given SEQ using SRC=0x0001. */
#define	CRAFT(seqv)	do {						\
	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(APPKEY, 1, 0, (seqv), 0x0001,	\
	    0x0002, IV0, NULL, apdu, plen, upper, &upper_len));		\
	memset(&lower, 0, sizeof(lower));				\
	lower.seg = 0; lower.ctl = 0; lower.akf = 1; lower.aid = aid;	\
	memcpy(lower.data, upper, upper_len); lower.data_len = upper_len; \
	ATF_REQUIRE_EQ(0, mesh_lower_build(&lower, lt, &lt_len));	\
	wlen = build_net_pdu(NETKEY, 0, 0x0001, 0x0002, (seqv), 5, lt,	\
	    lt_len, wire);						\
} while (0)

	/* SEQ 10 accepted. */
	seq = 10;
	CRAFT(seq);
	ATF_REQUIRE_EQ(0, mesh_sim_reinject(sim, -1, wire, wlen));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(1u, b->rx.count, "fresh SEQ 10 accepted");

	/* SEQ 9 (< stored 10) rejected. */
	CRAFT(9u);
	ATF_REQUIRE_EQ(0, mesh_sim_reinject(sim, -1, wire, wlen));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(1u, b->rx.count, "lower SEQ 9 rejected by the RPL");

	/* SEQ 10 again (== stored) rejected. */
	CRAFT(10u);
	ATF_REQUIRE_EQ(0, mesh_sim_reinject(sim, -1, wire, wlen));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(1u, b->rx.count, "equal SEQ 10 rejected by the RPL");

	/* SEQ 11 (> stored) accepted. */
	CRAFT(11u);
	ATF_REQUIRE_EQ(0, mesh_sim_reinject(sim, -1, wire, wlen));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(2u, b->rx.count, "higher SEQ 11 accepted");
#undef CRAFT
}

/* ================================================================
 * 3. FRIENDSHIP / LPN with the distinct friendship credential.
 *
 *    C(1) -- F(2) -- L(5); a subnet-only relay E(6) hears ONLY F's
 *    transmissions.  When the friendship credential is used, E cannot decrypt
 *    (different NID / NetMIC) and does not relay the delivery; with the plain
 *    subnet credential it does.  That contrast proves the friend NID is on the
 *    wire.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friend_delivery_uses_friend_credential);
ATF_TC_BODY(friend_delivery_uses_friend_credential, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *f, *l, *e;
	struct mesh_gen_onoff_srv srv;
	uint8_t exp_nid[1], exp_enc[16], exp_priv[16];

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	f = mesh_sim_add_node(sim, 0x0002, 1);
	l = mesh_sim_add_node(sim, 0x0005, 1);
	e = mesh_sim_add_node(sim, 0x0006, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(l, 0, mesh_gen_onoff_srv_model(&srv));
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, 0x0005, 1, 8));
	ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(l, 0x0002,
	    BT_MNET_POLL_TIMEOUT_SAMPLE));
	mesh_sim_set_relay(e, 1);		/* subnet-only eavesdropper relay */
	mesh_sim_link(sim, c, f);
	mesh_sim_link(sim, f, l);
	mesh_sim_link(sim, f, e);

	/* Establish friendship (LPNCounter 0, FriendCounter 0). */
	ATF_REQUIRE_EQ(0, mesh_sim_establish_friendship(sim, f, l, 0, 0, 0));

	/* The friendship NID matches the spec derivation and is distinct from
	 * the managed-flooding NID (Section 3.6.6.2). */
	ATF_REQUIRE_EQ(0, mesh_friend_credentials(NETKEY, 0x0005, 0x0002, 0, 0,
	    exp_nid, exp_enc, exp_priv));
	ATF_CHECK_EQ_MSG(exp_nid[0], f->friend_nid,
	    "friend NID equals the k2 friendship-P derivation");
	ATF_CHECK(f->friend_nid == l->friend_nid);
	ATF_CHECK_MSG(f->friend_nid != subnet_nid(NETKEY),
	    "friendship credential is distinct from managed-flooding");

	/* C sends to the (sleeping) LPN; F queues it. */
	onoff_send(sim, c, 0x0005, 1, 7, 5);
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ_MSG(0, srv.present, "LPN asleep, not applied");
	ATF_CHECK_EQ_MSG(1u, mesh_fq_count(&f->fq), "queued at the Friend");

	/* Poll: the Friend delivers, secured with the friend credential. */
	ATF_CHECK_EQ(1, mesh_sim_lpn_poll(sim, l));
	ATF_CHECK_EQ_MSG(BT_MNET_GENERIC_ONOFF_ON, srv.present,
	    "queued message applied after Poll");
	ATF_CHECK_EQ_MSG(0u, e->relay_count,
	    "subnet-only relay could not decrypt the friend-secured delivery");

	/*
	 * The single-bit FSN handshake (Section 3.6.6.4.2): the delivered head
	 * is still queued until the NEXT Poll (with the toggled FSN)
	 * acknowledges it.  The second Poll drains it and finds nothing new.
	 */
	ATF_CHECK_EQ_MSG(1u, mesh_fq_count(&f->fq), "head held pending FSN ack");
	ATF_CHECK_EQ(0, mesh_sim_lpn_poll(sim, l));
	ATF_CHECK_EQ_MSG(0u, mesh_fq_count(&f->fq), "queue drained after FSN ack");
}

/*
 * MshPRT §§3.6.6.2 and 3.6.6.4.2: Friend Poll and queued delivery use
 * friendship security material.  Merely configuring the simulator roles must
 * not create a managed-flooding fallback before establishment.
 */
ATF_TC_WITHOUT_HEAD(friend_poll_requires_established_credential);
ATF_TC_BODY(friend_poll_requires_established_credential, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *f, *l, *e;
	struct mesh_gen_onoff_srv srv;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	f = mesh_sim_add_node(sim, 0x0002, 1);
	l = mesh_sim_add_node(sim, 0x0005, 1);
	e = mesh_sim_add_node(sim, 0x0006, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(l, 0, mesh_gen_onoff_srv_model(&srv));
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, 0x0005, 1, 8));
	ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(l, 0x0002,
	    BT_MNET_POLL_TIMEOUT_SAMPLE));
	mesh_sim_set_relay(e, 1);
	mesh_sim_link(sim, c, f);
	mesh_sim_link(sim, f, l);
	mesh_sim_link(sim, f, e);
	/* Deliberately omit mesh_sim_establish_friendship(). */

	onoff_send(sim, c, 0x0005, 1, 7, 5);
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ_MSG(1u, mesh_fq_count(&f->fq), "queued at the Friend");

	ATF_CHECK_EQ(-1, mesh_sim_lpn_poll(sim, l));
	ATF_CHECK_EQ_MSG(BT_MNET_GENERIC_ONOFF_OFF, srv.present,
	    "no delivery occurs before friendship establishment");
	ATF_CHECK_EQ_MSG(0u, e->relay_count,
	    "no managed-flooding fallback leaks the queued message");
	ATF_CHECK_EQ_MSG(1u, mesh_fq_count(&f->fq),
	    "queued message remains pending establishment");
}

/* Friendship-lost timeout predicate (Section 3.6.6.4.2). */
ATF_TC_WITHOUT_HEAD(friend_poll_timeout);
ATF_TC_BODY(friend_poll_timeout, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *f, *l;
	uint64_t poll_ms;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	f = mesh_sim_add_node(sim, 0x0002, 1);
	l = mesh_sim_add_node(sim, 0x0005, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, 0x0005, 1, 8));
	ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(l, 0x0002,
	    BT_MNET_POLL_TIMEOUT_SAMPLE));
	ATF_REQUIRE_EQ(0, mesh_sim_establish_friendship(sim, f, l, 0, 0, 0));

	/* PollTimeout 0xA0 units of 100 ms = 16000 ms. */
	poll_ms = mesh_lpn_poll_timeout_ms(&l->lpn);
	ATF_CHECK_EQ(BT_MNET_POLL_TIMEOUT_SAMPLE *
	    BT_MNET_POLL_TIMEOUT_STEP_MS, (uint32_t)poll_ms);
	/* Just under the timeout: friendship still holds; at/after: lost. */
	ATF_CHECK_EQ(0, mesh_lpn_friendship_lost(&l->lpn, poll_ms - 1));
	ATF_CHECK_EQ(1, mesh_lpn_friendship_lost(&l->lpn, poll_ms));
}

/* ================================================================
 * 4. PROXY: filter accept/reject list, secured config PDUs, GATT<->adv bridge.
 * ================================================================ */

/* Build a secured Proxy Configuration Network PDU carrying a plaintext cfg. */
static size_t
build_proxy_cfg(const uint8_t netkey[16], uint16_t src, uint32_t seq,
    const uint8_t *msg, size_t msglen, uint8_t *out)
{
	uint8_t nid, enc[16], priv[16], p = 0x00;
	size_t ol;

	ATF_REQUIRE_EQ(0, mesh_k2(netkey, &p, 1, &nid, enc, priv));
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_encrypt(enc, priv, nid, IV0, seq, src,
	    msg, msglen, out, &ol));
	return (ol);
}

ATF_TC_WITHOUT_HEAD(proxy_filter_accept_and_reject);
ATF_TC_BODY(proxy_filter_accept_and_reject, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *p;
	uint8_t msg[16], secured[64];
	size_t mlen, slen;
	uint16_t addr;
	uint32_t base;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, IV0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	p = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_sim_set_proxy(p);
	mesh_sim_link(sim, c, p);

	/* Default filter is an empty accept-list: nothing is forwarded. */
	onoff_send(sim, c, GROUP_A, 1, 1, 5);
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(0u, p->proxy_fwd_count,
	    "empty accept-list forwards nothing");

	/* Secured "Add GROUP_A to the accept list" config PDU. */
	addr = GROUP_A;
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_addr_build(BT_MNET_PROXY_OP_ADD_ADDR,
	    &addr, 1, msg, sizeof(msg), &mlen));
	slen = build_proxy_cfg(NETKEY, 0x0001, 100, msg, mlen, secured);
	ATF_REQUIRE_EQ(0, mesh_sim_proxy_apply_config(p, secured, slen));

	/* GROUP_A now forwarded; GROUP_B (not listed) is not. */
	base = p->proxy_fwd_count;
	onoff_send(sim, c, GROUP_A, 1, 2, 5);
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(base + 1, p->proxy_fwd_count, "accept-listed forwarded");
	ATF_CHECK_EQ(GROUP_A, p->proxy_last_fwd_dst);

	onoff_send(sim, c, GROUP_B, 0, 3, 5);
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(base + 1, p->proxy_fwd_count,
	    "non-accept-listed address not forwarded");

	/* Switch to a reject-list filter (clears the list): GROUP_B now passes. */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_set_filter_build(
	    BT_MNET_PROXY_FILTER_REJECT,
	    msg, sizeof(msg), &mlen));
	slen = build_proxy_cfg(NETKEY, 0x0001, 101, msg, mlen, secured);
	ATF_REQUIRE_EQ(0, mesh_sim_proxy_apply_config(p, secured, slen));
	/* Reject GROUP_A only. */
	addr = GROUP_A;
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_addr_build(BT_MNET_PROXY_OP_ADD_ADDR,
	    &addr, 1, msg, sizeof(msg), &mlen));
	slen = build_proxy_cfg(NETKEY, 0x0001, 102, msg, mlen, secured);
	ATF_REQUIRE_EQ(0, mesh_sim_proxy_apply_config(p, secured, slen));

	base = p->proxy_fwd_count;
	onoff_send(sim, c, GROUP_B, 1, 4, 5);		/* not rejected -> passes */
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(base + 1, p->proxy_fwd_count,
	    "reject-list forwards a non-listed address");
	onoff_send(sim, c, GROUP_A, 1, 5, 5);		/* rejected -> blocked */
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(base + 1, p->proxy_fwd_count,
	    "reject-listed address blocked");
}

/* GATT->adv bridge: a GATT client's Network PDU is retransmitted by the proxy. */
ATF_TC_WITHOUT_HEAD(proxy_gatt_to_adv_bridge);
ATF_TC_BODY(proxy_gatt_to_adv_bridge, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *p, *s;
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_set set;
	uint8_t apdu[8], upper[32], lt[32], wire[MESH_NET_MAX_PDU];
	struct mesh_lower lower;
	size_t plen, upper_len, lt_len, wlen;
	uint8_t aid;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, IV0));
	p = mesh_sim_add_node(sim, 0x0002, 1);
	s = mesh_sim_add_node(sim, 0x0003, 1);
	mesh_sim_set_proxy(p);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(s, 0, mesh_gen_onoff_srv_model(&srv));
	mesh_sim_link(sim, p, s);		/* proxy bridges onto the adv link */
	ATF_REQUIRE_EQ(0, mesh_k4(APPKEY, &aid));

	/* Craft a secured Network PDU (as a GATT client would hand the proxy),
	 * SRC 0x00AA, DST S, carrying a Generic OnOff Set (the client encoding
	 * is already the access PDU opcode||params). */
	memset(&set, 0, sizeof(set));
	set.onoff = BT_MNET_GENERIC_ONOFF_ON;
	set.tid = 3;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&set, 0, apdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(APPKEY, 1, 0, 7, 0x00AA, 0x0003,
	    IV0, NULL, apdu, plen, upper, &upper_len));
	memset(&lower, 0, sizeof(lower));
	lower.seg = 0; lower.ctl = 0; lower.akf = 1; lower.aid = aid;
	memcpy(lower.data, upper, upper_len);
	lower.data_len = upper_len;
	ATF_REQUIRE_EQ(0, mesh_lower_build(&lower, lt, &lt_len));
	wlen = build_net_pdu(NETKEY, 0, 0x00AA, 0x0003, 7, 5, lt, lt_len, wire);

	ATF_REQUIRE_EQ(0, mesh_sim_proxy_gatt_in(sim, p, wire, wlen));
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ_MSG(BT_MNET_GENERIC_ONOFF_ON, srv.present,
	    "GATT-in PDU bridged onto the adv bearer");
	ATF_CHECK_EQ_MSG(1u, s->rx.count, "server received the bridged message");
}

/* ================================================================
 * 5. IV Update propagation across a 4-node network via beacons.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(iv_update_network_propagation);
ATF_TC_BODY(iv_update_network_propagation, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *n[4];
	int i;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 5));
	for (i = 0; i < 4; i++)
		n[i] = mesh_sim_add_node(sim, (uint16_t)(0x0001 + i), 1);

	/* Dwell not elapsed: begin is rejected. */
	ATF_CHECK_EQ(-1, mesh_sim_begin_iv_update(n[0]));
	mesh_sim_advance(sim, DWELL_SECS);
	ATF_REQUIRE_EQ(0, mesh_sim_begin_iv_update(n[0]));
	ATF_CHECK_EQ(6u, mesh_sim_node_iv(n[0]));

	/* One beacon from n[0]; every other node adopts IV Index 6. */
	ATF_REQUIRE_EQ(0, mesh_sim_send_beacon(sim, n[0], 0));
	for (i = 1; i < 4; i++)
		ATF_CHECK_EQ_MSG(6u, mesh_sim_node_iv(n[i]),
		    "node adopted the new IV Index from the beacon");

	/* Complete the update network-wide after another dwell. */
	mesh_sim_advance(sim, DWELL_SECS);
	ATF_REQUIRE_EQ(0, mesh_sim_complete_iv_update(n[0]));
	ATF_REQUIRE_EQ(0, mesh_sim_send_beacon(sim, n[0], 0));
	for (i = 0; i < 4; i++)
		ATF_CHECK_EQ(6u, mesh_sim_node_iv(n[i]));
}

/* ================================================================
 * 6. Key Refresh phase propagation across a 4-node network + traffic.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(key_refresh_network_propagation);
ATF_TC_BODY(key_refresh_network_propagation, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *n[4];
	struct mesh_gen_onoff_srv srv;
	int i;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	for (i = 0; i < 4; i++)
		n[i] = mesh_sim_add_node(sim, (uint16_t)(0x0001 + i), 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(n[3], 0, mesh_gen_onoff_srv_model(&srv));

	/* Distribute the new key to all nodes (Phase 0 -> 1). */
	for (i = 0; i < 4; i++)
		ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(n[i], NETKEY_B));
	for (i = 0; i < 4; i++)
		ATF_CHECK_EQ(BT_MNET_KR_PHASE_1, mesh_sim_node_kr_phase(n[i]));

	/* n[0] advances to Phase 2 and beacons; the rest follow. */
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(n[0]));
	ATF_REQUIRE_EQ(0, mesh_sim_send_beacon(sim, n[0], 0));
	for (i = 1; i < 4; i++)
		ATF_CHECK_EQ_MSG(BT_MNET_KR_PHASE_2,
		    mesh_sim_node_kr_phase(n[i]),
		    "node advanced to Phase 2 from the new-key beacon");

	/* All now TX with the new key; traffic flows under refreshed material. */
	for (i = 1; i < 4; i++)
		ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(n[i]));
	onoff_send(sim, n[0], 0x0004, 1, 1, 5);
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ_MSG(1, srv.present, "delivered under the refreshed NetKey");
}

/* NID (low 7 bits of octet 0) of the most recently queued Network PDU. */
static uint8_t
last_tx_nid(const struct mesh_sim *sim)
{

	ATF_REQUIRE(sim->n_tx > 0);
	return (sim->tx[sim->n_tx - 1].bytes[0] & BT_MNET_NID_MASK);
}

/* ================================================================
 * 6b. Key Refresh dual-key transmit: Phase 1 transmits with the OLD key's NID,
 *     Phase 2 with the NEW key's NID, and receptions decode under both keys
 *     (MshPRT_v1.1 Sections 3.11.4.1-3.11.4.2 key-selection rules).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(key_refresh_tx_nid_by_phase);
ATF_TC_BODY(key_refresh_tx_nid_by_phase, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *n0, *n1;
	struct mesh_gen_onoff_srv srv;
	uint8_t old_nid, new_nid, enc[16], priv[16], p = 0x00;

	ATF_REQUIRE_EQ(0, mesh_k2(NETKEY, &p, 1, &old_nid, enc, priv));
	ATF_REQUIRE_EQ(0, mesh_k2(NETKEY_B, &p, 1, &new_nid, enc, priv));

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	n0 = mesh_sim_add_node(sim, 0x0001, 1);
	n1 = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(n1, 0, mesh_gen_onoff_srv_model(&srv));

	/* Both hold both keys (Phase 1). */
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(n0, NETKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(n1, NETKEY_B));

	/* Phase 1: transmit with the OLD key; n1 (holding both) still decodes. */
	onoff_send(sim, n0, 0x0002, 1, 1, 5);
	ATF_CHECK_EQ_MSG(old_nid, last_tx_nid(sim), "Phase 1 TX uses the old NID");
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ_MSG(1, srv.present, "Phase 1 delivered under the old key");
	srv.present = 0;

	/* Phase 2: both transmit with the NEW key. */
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(n0));
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(n1));
	onoff_send(sim, n0, 0x0002, 1, 2, 5);
	ATF_CHECK_EQ_MSG(new_nid, last_tx_nid(sim), "Phase 2 TX uses the new NID");
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ_MSG(1, srv.present, "Phase 2 delivered under the new key");
}

/* ================================================================
 * 6c. Key Refresh SETTLE revokes the old key (security-critical).  After the
 *     local finalize operation completes revocation, it promotes the new key
 *     as the sole current
 *     key: a settled node transmits/accepts ONLY the new key and REJECTS traffic
 *     still secured with the (revoked) old key (MshPRT_v1.1 Section 3.11.4.3).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(key_refresh_settle_revokes_old_key);
ATF_TC_BODY(key_refresh_settle_revokes_old_key, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *n0, *n1, *stale;
	struct mesh_gen_onoff_srv srv;
	uint8_t new_nid, enc[16], priv[16], p = 0x00;

	ATF_REQUIRE_EQ(0, mesh_k2(NETKEY_B, &p, 1, &new_nid, enc, priv));

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	n0 = mesh_sim_add_node(sim, 0x0001, 1);
	n1 = mesh_sim_add_node(sim, 0x0002, 1);
	stale = mesh_sim_add_node(sim, 0x0003, 1);	/* never refreshed */
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(n1, 0, mesh_gen_onoff_srv_model(&srv));

	/* Refresh n0 and n1 through the full cycle to the Phase 3 settle. */
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(n0, NETKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(n1, NETKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(n0));
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(n1));
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_finalize(n0));
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_finalize(n1));

	/* The new key is now the sole current key; the old key is gone. */
	ATF_CHECK_EQ(BT_MNET_KR_NORMAL, mesh_sim_node_kr_phase(n0));
	ATF_CHECK_EQ(0, n0->have_new_key);
	ATF_CHECK_EQ_MSG(0, memcmp(n0->netkey, NETKEY_B, 16),
	    "new key promoted to sole current key");
	ATF_CHECK_EQ_MSG(new_nid, n0->nid, "TX now uses the new key's NID");

	/*
	 * A node still on the OLD key (never given the new one) is partitioned:
	 * its old-key-secured traffic is rejected by the settled node.
	 */
	onoff_send(sim, stale, 0x0002, 1, 1, 5);
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ_MSG(0, srv.present,
	    "settled node REJECTS traffic secured with the revoked old key");

	/* New-key traffic from a settled peer is accepted. */
	onoff_send(sim, n0, 0x0002, 1, 2, 5);
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ_MSG(1, srv.present,
	    "settled node accepts traffic under the promoted new key");
}

/* ================================================================
 * 6d. A beacon-driven settle also promotes: a node walked 1->2->3->0 purely by
 *     received Secure Network beacons ends on the new key with the old revoked.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(key_refresh_beacon_settle_promotes);
ATF_TC_BODY(key_refresh_beacon_settle_promotes, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *driver, *rx;
	uint8_t new_nid, enc[16], priv[16], p = 0x00;

	ATF_REQUIRE_EQ(0, mesh_k2(NETKEY_B, &p, 1, &new_nid, enc, priv));

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	driver = mesh_sim_add_node(sim, 0x0001, 1);
	rx = mesh_sim_add_node(sim, 0x0002, 1);

	/* Both hold both keys (Phase 1). */
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(driver, NETKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(rx, NETKEY_B));

	/* driver -> Phase 2, beacons flag=1: rx advances 1 -> 2. */
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(driver));
	ATF_REQUIRE_EQ(0, mesh_sim_send_beacon(sim, driver, 0));
	ATF_CHECK_EQ(BT_MNET_KR_PHASE_2, mesh_sim_node_kr_phase(rx));

	/* driver settles (finalize -> flag=0 beacon): rx 2 -> 3 -> 0 + promote. */
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_finalize(driver));
	ATF_REQUIRE_EQ(0, mesh_sim_send_beacon(sim, driver, 0));	/* 2 -> 3 */
	ATF_REQUIRE_EQ(0, mesh_sim_send_beacon(sim, driver, 0));	/* 3 -> 0, promote */
	ATF_CHECK_EQ(BT_MNET_KR_NORMAL, mesh_sim_node_kr_phase(rx));
	ATF_CHECK_EQ(0, rx->have_new_key);
	ATF_CHECK_EQ_MSG(0, memcmp(rx->netkey, NETKEY_B, 16),
	    "beacon-driven settle promoted the new key");
	ATF_CHECK_EQ(new_nid, rx->nid);
}

/* ================================================================
 * 6e. Key Refresh re-derives the friendship credential from the promoted key
 *     (MshPRT_v1.1 Section 3.6.6.2: friendship security is bound to the NetKey).
 *     Without this the LPN link silently breaks after a refresh.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(key_refresh_rederives_friend_credential);
ATF_TC_BODY(key_refresh_rederives_friend_credential, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *f, *l;
	uint8_t old_nid, old_enc[16];
	uint8_t exp_nid[1], exp_enc[16], exp_priv[16];

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	f = mesh_sim_add_node(sim, 0x0001, 1);
	l = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, l->addr, 1, 8));
	ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(l, f->addr, 100));
	ATF_REQUIRE_EQ(0, mesh_sim_establish_friendship(sim, f, l, 0, 1, 2));

	old_nid = f->friend_nid;
	memcpy(old_enc, f->friend_enckey, 16);

	/* The credential the Friend/LPN must hold after promoting to the new key. */
	ATF_REQUIRE_EQ(0, mesh_friend_credentials(NETKEY_B, l->addr, f->addr, 1, 2,
	    exp_nid, exp_enc, exp_priv));

	/* Full refresh + settle on both endpoints. */
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(f, NETKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(l, NETKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(f));
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(l));
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_finalize(f));
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_finalize(l));

	/* Both endpoints re-derived the friendship credential from the new key. */
	ATF_CHECK_EQ(exp_nid[0], f->friend_nid);
	ATF_CHECK_EQ_MSG(0, memcmp(f->friend_enckey, exp_enc, 16),
	    "Friend re-derived the friendship key from the promoted NetKey");
	ATF_CHECK_EQ(exp_nid[0], l->friend_nid);
	ATF_CHECK_EQ(0, memcmp(l->friend_enckey, exp_enc, 16));
	/* The credential actually changed (was bound to the old key). */
	ATF_CHECK_MSG(memcmp(exp_enc, old_enc, 16) != 0,
	    "the friendship key is different under the new NetKey");
	(void)old_nid;
}

/* ================================================================
 * 7. Multiple subnets: NID-based routing.  A subnet-B message is decodable
 *    only by subnet-B members; subnet-A-only nodes cannot decrypt it.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(multi_subnet_nid_routing);
ATF_TC_BODY(multi_subnet_nid_routing, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *x, *y, *z;
	struct mesh_gen_onoff_srv sy, sz;

	/* Subnet A is the sim's primary NetKey; subnet B is NETKEY_B added to
	 * the dual-homed nodes X and Z.  Y is subnet-A-only. */
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);			/* subnet A only */
	x = mesh_sim_add_node(sim, 0x0003, 1);			/* dual A+B */
	y = mesh_sim_add_node(sim, 0x0004, 1);			/* subnet A only */
	z = mesh_sim_add_node(sim, 0x0005, 1);			/* dual A+B */
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(x, 1, NETKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_add_appkey(x, 1, 1, APPKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(z, 1, NETKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_add_appkey(z, 1, 1, APPKEY_B));
	mesh_gen_onoff_srv_init(&sy, 0);
	mesh_gen_onoff_srv_init(&sz, 0);
	mesh_sim_add_model(y, 0, mesh_gen_onoff_srv_model(&sy));
	mesh_sim_add_model(z, 0, mesh_gen_onoff_srv_model(&sz));
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe(y, GROUP_A));
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe(z, GROUP_A));

	/* X publishes to GROUP_A on subnet B: only Z (a subnet-B member)
	 * decrypts; Y (subnet A only) cannot. */
	onoff_send_subnet(sim, x, GROUP_A, 1, 1, 5);
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ_MSG(1, sz.present, "subnet-B member decoded the message");
	ATF_CHECK_EQ_MSG(0, sy.present,
	    "subnet-A-only node could not decrypt the subnet-B message");

	/* A publishes to GROUP_A on subnet A: Y (a subnet-A member) decodes it. */
	onoff_send(sim, a, GROUP_A, 1, 2, 5);
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ_MSG(1, sy.present, "subnet-A member decoded the subnet-A message");
}

ATF_TC_WITHOUT_HEAD(multiple_appkeys_same_subnet);
ATF_TC_BODY(multiple_appkeys_same_subnet, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *client, *server;
	struct mesh_gen_onoff_srv state;
	struct mesh_gen_onoff_set set = { 1, 7, 0, 0, 0 };
	uint8_t pdu[8];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	client = mesh_sim_add_node(sim, 0x0001, 1);
	server = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE(client != NULL && server != NULL);
	ATF_REQUIRE_EQ(0, mesh_sim_add_appkey(client, 0, 2, APPKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_add_appkey(server, 0, 2, APPKEY_B));
	mesh_gen_onoff_srv_init(&state, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(server, 0,
	    mesh_gen_onoff_srv_model(&state)));
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&set, 0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_sim_send_access_key(sim, client, 0, 2, 0x0002,
	    BT_MNET_OP_GEN_ONOFF_SET_UNACK, pdu + 2, plen - 2, 5));
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ(1, state.present);
	ATF_CHECK_EQ(2, client->n_appkeys);
	ATF_CHECK_EQ(2, server->n_appkeys);
}

ATF_TC_WITHOUT_HEAD(secondary_subnet_key_refresh);
ATF_TC_BODY(secondary_subnet_key_refresh, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *client, *server, *old_peer;
	struct mesh_gen_onoff_srv refreshed, stale;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	client = mesh_sim_add_node(sim, 0x0001, 1);
	server = mesh_sim_add_node(sim, 0x0002, 1);
	old_peer = mesh_sim_add_node(sim, 0x0003, 1);
	ATF_REQUIRE(client != NULL && server != NULL && old_peer != NULL);
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(client, 1, NETKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(server, 1, NETKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(old_peer, 1, NETKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_add_appkey(client, 1, 1, APPKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_add_appkey(server, 1, 1, APPKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_add_appkey(old_peer, 1, 1, APPKEY_B));
	mesh_gen_onoff_srv_init(&refreshed, 0);
	mesh_gen_onoff_srv_init(&stale, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(server, 0,
	    mesh_gen_onoff_srv_model(&refreshed)));
	ATF_REQUIRE_EQ(0, mesh_sim_add_model(old_peer, 0,
	    mesh_gen_onoff_srv_model(&stale)));
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe(server, GROUP_A));
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe(old_peer, GROUP_A));

	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_begin(client, 1,
	    NETKEY_C));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_begin(server, 1,
	    NETKEY_C));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_advance(client, 1));
	ATF_CHECK_EQ(BT_MNET_KR_PHASE_2,
	    mesh_sim_subnet_kr_phase(client, 1));
	ATF_REQUIRE_EQ(0, mesh_sim_send_beacon(sim, client, 1));
	ATF_CHECK_EQ_MSG(BT_MNET_KR_PHASE_2,
	    mesh_sim_subnet_kr_phase(server, 1),
	    "secondary-subnet beacon advanced the matching subnet");
	ATF_CHECK_EQ_MSG(BT_MNET_KR_NORMAL,
	    mesh_sim_subnet_kr_phase(old_peer, 1),
	    "a peer without the distributed key ignored the refresh beacon");
	onoff_send_subnet(sim, client, GROUP_A, 1, 9, 5);
	mesh_sim_run(sim, 10);
	ATF_CHECK_EQ(1, refreshed.present);
	ATF_CHECK_EQ_MSG(0, stale.present,
	    "old-key-only member rejected Phase-2 secondary-subnet traffic");

	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_finalize(client, 1));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_finalize(server, 1));
	ATF_CHECK_EQ(BT_MNET_KR_NORMAL,
	    mesh_sim_subnet_kr_phase(server, 1));
}

ATF_TC_WITHOUT_HEAD(secondary_subnet_friendship);
ATF_TC_BODY(secondary_subnet_friendship, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *friend, *lpn;
	uint8_t old_enc[16], exp_nid[1], exp_enc[16], exp_priv[16];

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	friend = mesh_sim_add_node(sim, 0x0001, 1);
	lpn = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE(friend != NULL && lpn != NULL);
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(friend, 1, NETKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(lpn, 1, NETKEY_B));
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(friend, lpn->addr, 1, 8));
	ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(lpn, friend->addr, 100));
	ATF_REQUIRE_EQ(0, mesh_sim_establish_friendship(sim, friend, lpn, 1,
	    3, 4));
	ATF_REQUIRE_EQ(0, mesh_friend_credentials(NETKEY_B, lpn->addr,
	    friend->addr, 3, 4, exp_nid, exp_enc, exp_priv));
	ATF_CHECK_EQ(1, friend->friend_net_idx);
	ATF_CHECK_EQ(1, lpn->friend_net_idx);
	ATF_CHECK_EQ(exp_nid[0], friend->friend_nid);
	ATF_CHECK_EQ(0, memcmp(exp_enc, friend->friend_enckey, 16));
	memcpy(old_enc, friend->friend_enckey, sizeof(old_enc));

	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_begin(friend, 1,
	    NETKEY_C));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_begin(lpn, 1, NETKEY_C));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_advance(friend, 1));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_advance(lpn, 1));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_finalize(friend, 1));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_finalize(lpn, 1));
	ATF_REQUIRE_EQ(0, mesh_friend_credentials(NETKEY_C, lpn->addr,
	    friend->addr, 3, 4, exp_nid, exp_enc, exp_priv));
	ATF_CHECK_EQ(exp_nid[0], friend->friend_nid);
	ATF_CHECK_EQ(0, memcmp(exp_enc, friend->friend_enckey, 16));
	ATF_CHECK(memcmp(old_enc, friend->friend_enckey, 16) != 0);
}

/* ================================================================
 * 8. GROUP publish/subscribe reaches every subscriber across a relay hop and
 *    no one else.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(group_pubsub_across_relay);
ATF_TC_BODY(group_pubsub_across_relay, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *c, *r, *s1, *s2, *s3;
	struct mesh_gen_onoff_srv a1, a2, a3;

	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	c = mesh_sim_add_node(sim, 0x0001, 1);
	r = mesh_sim_add_node(sim, 0x0002, 1);
	s1 = mesh_sim_add_node(sim, 0x0010, 1);
	s2 = mesh_sim_add_node(sim, 0x0011, 1);
	s3 = mesh_sim_add_node(sim, 0x0012, 1);	/* not subscribed */
	mesh_gen_onoff_srv_init(&a1, 0);
	mesh_gen_onoff_srv_init(&a2, 0);
	mesh_gen_onoff_srv_init(&a3, 0);
	mesh_sim_add_model(s1, 0, mesh_gen_onoff_srv_model(&a1));
	mesh_sim_add_model(s2, 0, mesh_gen_onoff_srv_model(&a2));
	mesh_sim_add_model(s3, 0, mesh_gen_onoff_srv_model(&a3));
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe(s1, GROUP_A));
	ATF_REQUIRE_EQ(0, mesh_sim_subscribe(s2, GROUP_A));
	mesh_sim_set_relay(r, 1);
	/* C reaches the servers only through the relay R. */
	mesh_sim_link(sim, c, r);
	mesh_sim_link(sim, r, s1);
	mesh_sim_link(sim, r, s2);
	mesh_sim_link(sim, r, s3);

	onoff_send(sim, c, GROUP_A, 1, 1, 5);
	mesh_sim_run(sim, 16);

	ATF_CHECK_EQ_MSG(1, a1.present, "subscribed server 1 (a hop away) got it");
	ATF_CHECK_EQ_MSG(1, a2.present, "subscribed server 2 (a hop away) got it");
	ATF_CHECK_EQ_MSG(0, a3.present, "non-subscribed server ignored it");
	ATF_CHECK(r->relay_count > 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, relay_five_node_ttl_decrement);
	ATF_TP_ADD_TC(tp, relay_ttl_exhausted);
	ATF_TP_ADD_TC(tp, relay_disabled_breaks_path);
	ATF_TP_ADD_TC(tp, replay_over_relayed_path);
	ATF_TP_ADD_TC(tp, replay_seq_ordering);
	ATF_TP_ADD_TC(tp, friend_delivery_uses_friend_credential);
	ATF_TP_ADD_TC(tp, friend_poll_requires_established_credential);
	ATF_TP_ADD_TC(tp, friend_poll_timeout);
	ATF_TP_ADD_TC(tp, proxy_filter_accept_and_reject);
	ATF_TP_ADD_TC(tp, proxy_gatt_to_adv_bridge);
	ATF_TP_ADD_TC(tp, iv_update_network_propagation);
	ATF_TP_ADD_TC(tp, key_refresh_network_propagation);
	ATF_TP_ADD_TC(tp, key_refresh_tx_nid_by_phase);
	ATF_TP_ADD_TC(tp, key_refresh_settle_revokes_old_key);
	ATF_TP_ADD_TC(tp, key_refresh_beacon_settle_promotes);
	ATF_TP_ADD_TC(tp, key_refresh_rederives_friend_credential);
	ATF_TP_ADD_TC(tp, multi_subnet_nid_routing);
	ATF_TP_ADD_TC(tp, multiple_appkeys_same_subnet);
	ATF_TP_ADD_TC(tp, secondary_subnet_key_refresh);
	ATF_TP_ADD_TC(tp, secondary_subnet_friendship);
	ATF_TP_ADD_TC(tp, group_pubsub_across_relay);

	return (atf_no_error());
}
