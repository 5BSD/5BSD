/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Fault-injection ATF tests for the Bluetooth Mesh simulator (mesh_sim.c).
 *
 * mesh_sim.c calls into the Phase 1-8 libmesh primitives (mesh_net_encrypt,
 * mesh_upper_encrypt, mesh_lower_build/parse, mesh_sar_segment, the SAR
 * reassembler, k2/k4, the beacon and friendship builders/parsers, ...).  On
 * the valid, bounded inputs the simulator constructs, those primitives never
 * fail, so the defensive "!= 0 -> bail out" arms guarding each call are
 * unreachable by ordinary traffic.  This test makes them reachable with the
 * --wrap linker seam: each __wrap_<sym> forwards to __real_<sym> unless it has
 * been ARMED, in which case it fails the next call exactly once.  Driving a
 * normal sim operation with one primitive armed exercises the matching
 * error-handling branch in mesh_sim.c.
 *
 * This mirrors the smp_fault_test / libble_fault_test --wrap seams.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_test_heap.h"
#include "mesh_sim.h"
#include "mesh_generic.h"
#include "mesh_transport.h"
#include "mesh_beacon.h"
#include "mesh_friend.h"

/* ---- __real declarations for the wrapped primitives. ---- */
int __real_mesh_net_encrypt(const uint8_t[16], const uint8_t[16], uint8_t,
    uint32_t, const struct mesh_net_pdu *, uint8_t *, size_t *);
int __real_mesh_upper_encrypt(const uint8_t[16], int, int, uint32_t, uint16_t,
    uint16_t, uint32_t, const uint8_t *, const uint8_t *, size_t, uint8_t *,
    size_t *);
int __real_mesh_upper_decrypt(const uint8_t[16], int, int, uint32_t, uint16_t,
    uint16_t, uint32_t, const uint8_t *, const uint8_t *, size_t, uint8_t *,
    size_t *);
int __real_mesh_lower_build(const struct mesh_lower *, uint8_t *, size_t *);
int __real_mesh_lower_parse(int, const uint8_t *, size_t, struct mesh_lower *);
int __real_mesh_sar_segment(int, uint8_t, int, uint16_t, const uint8_t *,
    size_t, struct mesh_seg *, size_t, size_t *);
int __real_mesh_reasm_input(struct mesh_reasm *, uint16_t, const uint8_t *,
    size_t);
int __real_mesh_reasm_get(const struct mesh_reasm *, uint8_t *, size_t *);
int __real_mesh_access_pdu_parse(const uint8_t *, size_t,
    struct mesh_access_pdu *);
int __real_mesh_k2(const uint8_t[16], const uint8_t *, size_t, uint8_t[1],
    uint8_t[16], uint8_t[16]);
int __real_mesh_k4(const uint8_t[16], uint8_t[1]);
int __real_mesh_secure_beacon_build(const uint8_t[16], uint8_t, uint8_t,
    uint32_t, uint8_t *, size_t *);
int __real_mesh_friend_poll_build(const struct mesh_friend_poll *, uint8_t *,
    size_t *);
int __real_mesh_friend_poll_parse(const uint8_t *, size_t,
    struct mesh_friend_poll *);
int __real_mesh_kr_beacon(struct mesh_key_refresh *, int);
int __real_mesh_friend_credentials(const uint8_t[16], uint16_t, uint16_t,
    uint16_t, uint16_t, uint8_t[1], uint8_t[16], uint8_t[16]);
int __real_mesh_df_discovery_start(struct mesh_df_discovery *, uint16_t,
    uint16_t, uint8_t, uint8_t, uint8_t, uint8_t, int, uint64_t, uint64_t,
    struct mesh_df_path_request *);
int __real_mesh_df_path_request_build(const struct mesh_df_path_request *,
    uint8_t *, size_t *);
int __real_mesh_hb_msg_build(const struct mesh_hb_msg *, uint8_t *, size_t *);

/* ---- arm state: one-shot flags + an Nth-call countdown for net_encrypt. ---- */
static struct {
	int upper_encrypt;
	int upper_decrypt;
	int lower_build;
	int lower_parse;
	int sar_segment;
	int reasm_input;
	int reasm_get;
	int pdu_parse;
	int k4;
	int beacon_build;
	int poll_build;
	int poll_parse;
	int kr_beacon;
	int df_start;
	int df_request_build;
	int hb_build;
	int force_akf0;		/* lower_parse post-processing: force akf=0 */
	/* net_encrypt / k2 use a call counter so a specific call can fail. */
	int net_calls, net_fail_at;
	int k2_calls, k2_fail_at;
	int friend_calls, friend_fail_at;
} F;

static void
fault_reset(void)
{

	memset(&F, 0, sizeof(F));
}

#define ONESHOT(field) (F.field ? (F.field = 0, 1) : 0)

int
__wrap_mesh_net_encrypt(const uint8_t ek[16], const uint8_t pk[16], uint8_t nid,
    uint32_t iv, const struct mesh_net_pdu *in, uint8_t *out, size_t *outlen)
{

	F.net_calls++;
	if (F.net_fail_at != 0 && F.net_calls == F.net_fail_at)
		return (-1);
	return (__real_mesh_net_encrypt(ek, pk, nid, iv, in, out, outlen));
}

int
__wrap_mesh_k2(const uint8_t nk[16], const uint8_t *p, size_t pl,
    uint8_t nidp[1], uint8_t ek[16], uint8_t pkk[16])
{

	F.k2_calls++;
	if (F.k2_fail_at != 0 && F.k2_calls == F.k2_fail_at)
		return (-1);
	return (__real_mesh_k2(nk, p, pl, nidp, ek, pkk));
}

int
__wrap_mesh_k4(const uint8_t ak[16], uint8_t aid[1])
{

	if (ONESHOT(k4))
		return (-1);
	return (__real_mesh_k4(ak, aid));
}

int
__wrap_mesh_upper_encrypt(const uint8_t k[16], int akf, int szmic, uint32_t seq,
    uint16_t src, uint16_t dst, uint32_t iv, const uint8_t *lbl,
    const uint8_t *acc, size_t alen, uint8_t *out, size_t *outlen)
{

	if (ONESHOT(upper_encrypt))
		return (-1);
	return (__real_mesh_upper_encrypt(k, akf, szmic, seq, src, dst, iv, lbl,
	    acc, alen, out, outlen));
}

int
__wrap_mesh_upper_decrypt(const uint8_t k[16], int akf, int szmic, uint32_t seq,
    uint16_t src, uint16_t dst, uint32_t iv, const uint8_t *lbl,
    const uint8_t *up, size_t ulen, uint8_t *acc, size_t *alen)
{

	if (ONESHOT(upper_decrypt))
		return (-1);
	return (__real_mesh_upper_decrypt(k, akf, szmic, seq, src, dst, iv, lbl,
	    up, ulen, acc, alen));
}

int
__wrap_mesh_lower_build(const struct mesh_lower *in, uint8_t *out, size_t *ol)
{

	if (ONESHOT(lower_build))
		return (-1);
	return (__real_mesh_lower_build(in, out, ol));
}

int
__wrap_mesh_lower_parse(int ctl, const uint8_t *in, size_t inlen,
    struct mesh_lower *out)
{
	int rc = __real_mesh_lower_parse(ctl, in, inlen, out);

	if (rc == 0 && ONESHOT(force_akf0))
		out->akf = 0;			/* drive the akf != 1 arm */
	if (ONESHOT(lower_parse))
		return (-1);
	return (rc);
}

int
__wrap_mesh_sar_segment(int akf, uint8_t aid, int szmic, uint16_t sz,
    const uint8_t *up, size_t ul, struct mesh_seg *out, size_t max, size_t *ns)
{

	if (ONESHOT(sar_segment))
		return (-1);
	return (__real_mesh_sar_segment(akf, aid, szmic, sz, up, ul, out, max,
	    ns));
}

int
__wrap_mesh_reasm_input(struct mesh_reasm *r, uint16_t src, const uint8_t *lt,
    size_t ltl)
{

	if (ONESHOT(reasm_input))
		return (-1);
	return (__real_mesh_reasm_input(r, src, lt, ltl));
}

int
__wrap_mesh_reasm_get(const struct mesh_reasm *r, uint8_t *up, size_t *ul)
{

	if (ONESHOT(reasm_get))
		return (-1);
	return (__real_mesh_reasm_get(r, up, ul));
}

int
__wrap_mesh_access_pdu_parse(const uint8_t *in, size_t inlen,
    struct mesh_access_pdu *out)
{

	if (ONESHOT(pdu_parse))
		return (-1);
	return (__real_mesh_access_pdu_parse(in, inlen, out));
}

int
__wrap_mesh_secure_beacon_build(const uint8_t nk[16], uint8_t kr, uint8_t ivu,
    uint32_t iv, uint8_t *out, size_t *ol)
{

	if (ONESHOT(beacon_build))
		return (-1);
	return (__real_mesh_secure_beacon_build(nk, kr, ivu, iv, out, ol));
}

int
__wrap_mesh_friend_poll_build(const struct mesh_friend_poll *in, uint8_t *out,
    size_t *ol)
{

	if (ONESHOT(poll_build))
		return (-1);
	return (__real_mesh_friend_poll_build(in, out, ol));
}

int
__wrap_mesh_friend_poll_parse(const uint8_t *in, size_t inlen,
    struct mesh_friend_poll *out)
{

	if (ONESHOT(poll_parse))
		return (-1);
	return (__real_mesh_friend_poll_parse(in, inlen, out));
}

int
__wrap_mesh_kr_beacon(struct mesh_key_refresh *st, int flag)
{

	if (ONESHOT(kr_beacon))
		return (-1);
	return (__real_mesh_kr_beacon(st, flag));
}

int
__wrap_mesh_friend_credentials(const uint8_t key[16], uint16_t lpn,
    uint16_t friend, uint16_t lc, uint16_t fc, uint8_t nid[1],
    uint8_t enc[16], uint8_t priv[16])
{

	F.friend_calls++;
	if (F.friend_fail_at != 0 && F.friend_calls == F.friend_fail_at)
		return (-1);
	return (__real_mesh_friend_credentials(key, lpn, friend, lc, fc, nid,
	    enc, priv));
}

int
__wrap_mesh_df_discovery_start(struct mesh_df_discovery *d, uint16_t origin,
    uint16_t target, uint8_t fn, uint8_t metric, uint8_t lifetime,
    uint8_t lanes, int two_way, uint64_t timeout, uint64_t now,
    struct mesh_df_path_request *req)
{

	if (ONESHOT(df_start))
		return (-1);
	return (__real_mesh_df_discovery_start(d, origin, target, fn, metric,
	    lifetime, lanes, two_way, timeout, now, req));
}

int
__wrap_mesh_df_path_request_build(const struct mesh_df_path_request *req,
    uint8_t *out, size_t *outlen)
{

	if (ONESHOT(df_request_build))
		return (-1);
	return (__real_mesh_df_path_request_build(req, out, outlen));
}

int
__wrap_mesh_hb_msg_build(const struct mesh_hb_msg *msg, uint8_t *out,
    size_t *outlen)
{

	if (ONESHOT(hb_build))
		return (-1);
	return (__real_mesh_hb_msg_build(msg, out, outlen));
}

/* ---- shared key material. ---- */
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

/* Build an unacknowledged OnOff Set access PDU parameter block. */
static size_t
onoff_params(uint8_t *p, uint8_t onoff, uint8_t tid)
{
	struct mesh_gen_onoff_set s;
	uint8_t out[8];
	size_t len;

	memset(&s, 0, sizeof(s));
	s.onoff = onoff;
	s.tid = tid;
	(void)mesh_gen_onoff_set_encode(&s, out, &len);
	memcpy(p, out, len);
	return (len);
}

/* ================================================================
 * Setup-time primitive faults (add_node, key refresh key derivation).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_setup);
ATF_TC_BODY(fault_setup, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *n, *f, *l;
	uint8_t label[16] = { 0x5a };

	/* k2 failure aborts add_node. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	F.k2_fail_at = 1;
	ATF_CHECK(mesh_sim_add_node(sim, 0x0001, 1) == NULL);

	/* k4 failure aborts add_node (k2 succeeds first). */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	F.k4 = 1;
	ATF_CHECK(mesh_sim_add_node(sim, 0x0001, 1) == NULL);

	/* k2 failure on the new key aborts begin_key_refresh. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	n = mesh_sim_add_node(sim, 0x0001, 1);	/* k2 call #1 (node) */
	ATF_REQUIRE(n != NULL);
	F.k2_fail_at = 2;			/* fail the new-key derivation */
	ATF_CHECK_EQ(-1, mesh_sim_begin_key_refresh(n, NETKEY2));

	/* kr_beacon failure aborts key_refresh_advance. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	n = mesh_sim_add_node(sim, 0x0001, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(n, NETKEY2));
	F.kr_beacon = 1;
	ATF_CHECK_EQ(-1, mesh_sim_key_refresh_advance(n));

	/* secure_beacon_build failure aborts send_beacon. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	n = mesh_sim_add_node(sim, 0x0001, 1);
	(void)mesh_sim_add_node(sim, 0x0002, 1);
	F.beacon_build = 1;
	ATF_CHECK_EQ(-1, mesh_sim_send_beacon(sim, n, 0));

	/* Secondary-subnet refresh propagates K2 and phase-transition failures. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	n = mesh_sim_add_node(sim, 0x0001, 1);
	ATF_REQUIRE(n != NULL);
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(n, 1, NETKEY2));
	F.k2_fail_at = F.k2_calls + 1;
	ATF_CHECK_EQ(-1, mesh_sim_subnet_key_refresh_begin(n, 1, APPKEY));
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_begin(n, 1, APPKEY));
	F.kr_beacon = 1;
	ATF_CHECK_EQ(-1, mesh_sim_subnet_key_refresh_advance(n, 1));

	/* Fixed-capacity registries fail closed and subnet removal also removes
	 * every AppKey that depends on that subnet. */
	n->elem_n_labels[0] = MESH_SIM_MAX_SUBS;
	ATF_CHECK_EQ(-1, mesh_sim_subscribe_virtual_element(n, 0, label));
	n->n_subnets = MESH_SIM_MAX_SUBNETS - 1;
	ATF_CHECK_EQ(-1, mesh_sim_add_subnet(n, 9, NETKEY2));
	n->n_appkeys = MESH_SIM_MAX_APPKEYS;
	ATF_CHECK_EQ(-1, mesh_sim_add_appkey(n, 0, 9, APPKEY));

	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	n = mesh_sim_add_node(sim, 0x0001, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(n, 1, NETKEY2));
	ATF_REQUIRE_EQ(0, mesh_sim_add_appkey(n, 1, 9, APPKEY));
	ATF_CHECK_EQ(0, mesh_sim_remove_subnet(n, 1));
	ATF_CHECK_EQ(1u, n->n_appkeys); /* primary AppKey remains */

	/* Friendship establishment rejects a subnet absent at either endpoint
	 * and rejects endpoints holding different keys for the same NetKey index. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	f = mesh_sim_add_node(sim, 0x0002, 1);
	l = mesh_sim_add_node(sim, 0x0005, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, l->addr, 1, 8));
	ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(l, f->addr, 0x0000a0));
	ATF_CHECK_EQ(-1, mesh_sim_establish_friendship(sim, f, l, 1, 1, 2));
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(f, 1, NETKEY2));
	ATF_CHECK_EQ(-1, mesh_sim_establish_friendship(sim, f, l, 1, 1, 2));
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(l, 1, APPKEY));
	ATF_CHECK_EQ(-1, mesh_sim_establish_friendship(sim, f, l, 1, 1, 2));
}

/* ================================================================
 * Transmit-path primitive faults (originate + control TX).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_tx);
ATF_TC_BODY(fault_tx, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *l, *f;
	uint8_t p[8], big[40];
	size_t plen, i;

	plen = onoff_params(p, 1, 1);

	/* upper_encrypt failure. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);
	(void)mesh_sim_add_node(sim, 0x0002, 1);
	F.upper_encrypt = 1;
	ATF_CHECK_EQ(-1, mesh_sim_send_access(sim, a, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, p, plen, 5));

	/* lower_build failure (unsegmented path). */
	F.lower_build = 1;
	ATF_CHECK_EQ(-1, mesh_sim_send_access(sim, a, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, p, plen, 5));

	/* net_encrypt failure (unsegmented enqueue). */
	F.net_fail_at = F.net_calls + 1;
	ATF_CHECK_EQ(-1, mesh_sim_send_access(sim, a, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, p, plen, 5));

	/* Segmented path: sar_segment failure. */
	for (i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)i;
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);
	(void)mesh_sim_add_node(sim, 0x0002, 1);
	F.sar_segment = 1;
	ATF_CHECK_EQ(-1, mesh_sim_send_access(sim, a, 0x0002, 0x8299,
	    big, sizeof(big), 5));

	/* Segmented path: net_encrypt failure inside the segment loop. */
	F.net_calls = 0;
	F.net_fail_at = 1;
	ATF_CHECK_EQ(-1, mesh_sim_send_access(sim, a, 0x0002, 0x8299,
	    big, sizeof(big), 5));

	/* The public pre-sealed Upper Transport seam has its own unsegmented and
	 * segmented lower/network error propagation. */
	F.lower_build = 1;
	ATF_CHECK_EQ(-1, mesh_sim_send_upper(sim, a, 0x0002, a->seq, p, plen,
	    1, a->appkeys[0].aid, 5));
	F.net_fail_at = F.net_calls + 1;
	ATF_CHECK_EQ(-1, mesh_sim_send_upper(sim, a, 0x0002, a->seq, p, plen,
	    1, a->appkeys[0].aid, 5));
	F.sar_segment = 1;
	ATF_CHECK_EQ(-1, mesh_sim_send_upper(sim, a, 0x0002, a->seq, big,
	    sizeof(big), 1, a->appkeys[0].aid, 5));
	F.net_fail_at = F.net_calls + 1;
	ATF_CHECK_EQ(-1, mesh_sim_send_upper(sim, a, 0x0002, a->seq, big,
	    sizeof(big), 1, a->appkeys[0].aid, 5));

	/* Phase 2 selects the newly derived primary credential for ordinary and
	 * virtual-address access traffic. */
	{
		uint8_t label[16] = { 0x33 };

		fault_reset();
		ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(a, NETKEY2));
		ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(a));
		ATF_CHECK_EQ(0, mesh_sim_send_access_key(sim, a, 0, 0, 0xc001,
		    MESH_OP_GEN_ONOFF_SET_UNACK, p, plen, 5));
		ATF_CHECK_EQ(0, mesh_sim_send_access_key_from_virtual(sim, a,
		    a->addr, 0, 0, label, MESH_OP_GEN_ONOFF_SET_UNACK, p, plen, 5));
	}

	/* Control TX failure: net_encrypt fails inside the LPN Friend Poll. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	f = mesh_sim_add_node(sim, 0x0002, 1);
	l = mesh_sim_add_node(sim, 0x0005, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, 0x0005, 1, 8));
	ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(l, 0x0002, 0x0000a0));
	F.net_calls = 0;
	F.net_fail_at = 1;			/* the Poll's own net_encrypt */
	ATF_CHECK_EQ(-1, mesh_sim_lpn_poll(sim, l));

	/* Friend Poll build failure aborts the poll. */
	fault_reset();
	F.poll_build = 1;
	ATF_CHECK_EQ(-1, mesh_sim_lpn_poll(sim, l));

	/* Relay re-broadcast whose enqueue (net_encrypt) fails: the relay
	 * count is not incremented (the "enqueue succeeded" arm is not taken). */
	{
		MESH_HEAP(struct mesh_sim, rsim);
		struct mesh_node *cc, *rr;

		fault_reset();
		ATF_REQUIRE_EQ(0, mesh_sim_init(rsim, NETKEY, APPKEY, 0));
		cc = mesh_sim_add_node(rsim, 0x0001, 1);
		rr = mesh_sim_add_node(rsim, 0x0002, 1);
		(void)mesh_sim_add_node(rsim, 0x0003, 1);
		mesh_sim_set_relay(rr, 1);
		mesh_sim_link(rsim, cc, rr);
		mesh_sim_link(rsim, rr, mesh_sim_node_at(rsim, 0x0003));
		ATF_REQUIRE_EQ(0, mesh_sim_send_access(rsim, cc, 0x0003,
		    MESH_OP_GEN_ONOFF_SET_UNACK, p, plen, 5));
		/* Call #1 was the originator's send; fail the relay's encrypt. */
		F.net_fail_at = F.net_calls + 1;
		mesh_sim_run(rsim, 6);
		ATF_CHECK_EQ_MSG(0u, rr->relay_count,
		    "relay enqueue failure leaves the relay count at zero");
	}
}

/* ================================================================
 * Receive-path primitive faults (delivery + reassembly + control).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_rx);
ATF_TC_BODY(fault_rx, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *a, *b;
	struct mesh_gen_onoff_srv srv;
	uint8_t p[8], big[40];
	size_t plen, i;

	plen = onoff_params(p, 1, 1);

	/* Each of these arms the receiver's primitive so the delivered PDU is
	 * silently dropped; the server therefore never updates. */

	/* lower_parse failure. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);
	b = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_gen_onoff_srv_init(&srv, 0);
	mesh_sim_add_model(b, 0, mesh_gen_onoff_srv_model(&srv));
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, p, plen, 5));
	F.lower_parse = 1;
	mesh_sim_run(sim, 3);
	ATF_CHECK_EQ(0, srv.present);

	/* akf != 1 arm: force the reassembled/parsed lower PDU to look like a
	 * device-key message, which this sim does not deliver. */
	mesh_gen_onoff_srv_init(&srv, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, p, plen, 5));
	F.force_akf0 = 1;
	mesh_sim_run(sim, 3);
	ATF_CHECK_EQ(0, srv.present);

	/* upper_decrypt failure. */
	mesh_gen_onoff_srv_init(&srv, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, p, plen, 5));
	F.upper_decrypt = 1;
	mesh_sim_run(sim, 3);
	ATF_CHECK_EQ(0, srv.present);

	/* access_pdu_parse failure (after a good upper decrypt). */
	mesh_gen_onoff_srv_init(&srv, 0);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0002,
	    MESH_OP_GEN_ONOFF_SET_UNACK, p, plen, 5));
	F.pdu_parse = 1;
	mesh_sim_run(sim, 3);
	ATF_CHECK_EQ(0, srv.present);

	/* Segmented reassembly: reasm_input error. */
	for (i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)i;
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);
	b = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0002, 0x8299,
	    big, sizeof(big), 5));
	F.reasm_input = 1;
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ(0u, b->rx.count);

	/* Segmented reassembly: reasm_get failure on completion. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);
	b = mesh_sim_add_node(sim, 0x0002, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, a, 0x0002, 0x8299,
	    big, sizeof(big), 5));
	F.reasm_get = 1;
	mesh_sim_run(sim, 5);
	ATF_CHECK_EQ(0u, b->rx.count);

	/* Friend Poll parse failure on the Friend side. */
	{
		struct mesh_node *c, *f, *l;
		int rc;

		fault_reset();
		ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
		c = mesh_sim_add_node(sim, 0x0001, 1);
		f = mesh_sim_add_node(sim, 0x0002, 1);
		l = mesh_sim_add_node(sim, 0x0005, 1);
		mesh_gen_onoff_srv_init(&srv, 0);
		mesh_sim_add_model(l, 0, mesh_gen_onoff_srv_model(&srv));
		ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, 0x0005, 1, 8));
		ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(l, 0x0002, 0x0000a0));
		/* Mesh Protocol 1.1 §3.6.6.2: Poll uses friendship credentials. */
		ATF_REQUIRE_EQ(0,
		    mesh_sim_establish_friendship(sim, f, l, 0, 0, 0));
		/* A client queues a message for the sleeping LPN at the Friend. */
		ATF_REQUIRE_EQ(0, mesh_sim_send_access(sim, c, 0x0005,
		    MESH_OP_GEN_ONOFF_SET_UNACK, p, plen, 5));
		mesh_sim_run(sim, 5);
		ATF_REQUIRE_EQ(1u, mesh_fq_count(&f->fq));
		/* Poll with the Friend's poll parse armed to fail. */
		F.poll_parse = 1;
		rc = mesh_sim_lpn_poll(sim, l);
		ATF_CHECK_EQ_MSG(0, rc, "poll parse failure returned %d", rc);
	}
}

/* Higher-level security, directed-forwarding, and Heartbeat fault contracts. */
ATF_TC_WITHOUT_HEAD(fault_feature_primitives);
ATF_TC_BODY(fault_feature_primitives, tc)
{
	MESH_HEAP(struct mesh_sim, sim);
	struct mesh_node *f, *l, *a, *b;
	int rc;

	/* Either endpoint's friendship-credential derivation may fail. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	f = mesh_sim_add_node(sim, 0x0002, 1);
	l = mesh_sim_add_node(sim, 0x0005, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, l->addr, 1, 8));
	ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(l, f->addr, 0x0000a0));
	F.friend_fail_at = 1;
	ATF_CHECK_EQ(-1, mesh_sim_establish_friendship(sim, f, l, 0, 1, 2));

	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	f = mesh_sim_add_node(sim, 0x0002, 1);
	l = mesh_sim_add_node(sim, 0x0005, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, l->addr, 1, 8));
	ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(l, f->addr, 0x0000a0));
	F.friend_fail_at = 2;
	ATF_CHECK_EQ(-1, mesh_sim_establish_friendship(sim, f, l, 0, 1, 2));

	/* Promotion must propagate a friendship re-derivation failure. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	f = mesh_sim_add_node(sim, 0x0002, 1);
	l = mesh_sim_add_node(sim, 0x0005, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_set_friend(f, l->addr, 1, 8));
	ATF_REQUIRE_EQ(0, mesh_sim_set_lpn(l, f->addr, 0x0000a0));
	ATF_REQUIRE_EQ(0, mesh_sim_establish_friendship(sim, f, l, 0, 1, 2));
	ATF_REQUIRE_EQ(0, mesh_sim_begin_key_refresh(f, NETKEY2));
	ATF_REQUIRE_EQ(0, mesh_sim_key_refresh_advance(f));
	F.friend_fail_at = F.friend_calls + 1;
	ATF_CHECK_EQ(-1, mesh_sim_key_refresh_finalize(f));

	/* Directed-path setup and request encoding failures stop discovery. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_sim_init(sim, NETKEY, APPKEY, 0));
	a = mesh_sim_add_node(sim, 0x0001, 1);
	b = mesh_sim_add_node(sim, 0x0002, 1);
	mesh_sim_set_df(a, 1);
	mesh_sim_set_df(b, 1);
	ATF_REQUIRE_EQ(0, mesh_sim_link(sim, a, b));
	F.df_start = 1;
	ATF_CHECK_EQ(-1, mesh_sim_df_discover(sim, a, b->addr, 0));
	F.df_request_build = 1;
	ATF_CHECK_EQ(-1, mesh_sim_df_discover(sim, a, b->addr, 0));

	/* Both triggered and periodic publication absorb a builder failure. */
	mesh_sim_hb_set_pub(a, 0xc000, 2, 1, 5,
	    MESH_HB_FEATURE_FRIEND, MESH_HB_FEATURE_FRIEND);
	F.hb_build = 1;
	ATF_CHECK_EQ(-1, mesh_sim_hb_feature_change(sim, a, 0));
	mesh_sim_hb_set_pub(a, 0xc000, 2, 1, 5, 0, 0);
	F.hb_build = 1;
	/* The timer starts with its first publication immediately due (§3.6.7.2). */
	rc = mesh_sim_hb_publish_periodic(sim, a, 0);
	ATF_CHECK_EQ_MSG(0, rc, "failed immediate publication returned %d", rc);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fault_setup);
	ATF_TP_ADD_TC(tp, fault_tx);
	ATF_TP_ADD_TC(tp, fault_rx);
	ATF_TP_ADD_TC(tp, fault_feature_primitives);

	return (atf_no_error());
}
