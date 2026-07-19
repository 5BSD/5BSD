/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Fault-injection tests for the meshd(8) node daemon.  meshd's own logic
 * contains defensive error arms that check the return of libblemesh calls
 * which cannot fail on valid input (a full sim table, an encode of a
 * well-formed struct, ...).  These arms are unreachable by data alone, so we
 * reach them the same way mesh_sim_fault_test does: the linker --wrap facility
 * intercepts the relevant libblemesh entry points and, when a per-function
 * toggle is armed, returns the failure the arm is written to handle.
 *
 * Each toggle is armed immediately before the meshd call under test and
 * cleared immediately after, so the surrounding test scaffolding (which builds
 * its input PDUs with the same codecs) runs against the real implementations.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_test_heap.h"
#include "meshd.h"

/* ---- wrap toggles ---- */
static int f_sim_init;
static int f_add_node;
static uint16_t f_add_model_id;		/* fail add_model for this model id */
static int f_reinject;
static int f_send_access;
static int f_onoff_encode;
static int f_level_encode;
static int f_data_unpack;
static int f_page0_encode;
static int f_comp_status;
static int f_u8_build;
static int f_u8_parse;
static int f_comp_get_parse;
static int f_node_reset_build;
static int f_att_build;
static int f_att_parse;
static int f_fault_get_parse;
static int f_fault_status_build;

/* ---- real symbols ---- */
int __real_mesh_sim_init(struct mesh_sim *, const uint8_t *, const uint8_t *,
    uint32_t);
struct mesh_node *__real_mesh_sim_add_node(struct mesh_sim *, uint16_t, uint8_t);
int __real_mesh_sim_add_model(struct mesh_node *, uint8_t, struct mesh_model);
int __real_mesh_sim_reinject(struct mesh_sim *, int, const uint8_t *, size_t);
int __real_mesh_sim_send_access(struct mesh_sim *, struct mesh_node *, uint16_t,
    uint32_t, const uint8_t *, size_t, uint8_t);
int __real_mesh_gen_onoff_set_encode(const struct mesh_gen_onoff_set *,
    uint8_t *, size_t *);
int __real_mesh_gen_level_set_encode(const struct mesh_gen_level_set *,
    uint8_t *, size_t *);
int __real_mesh_prov_data_unpack(const uint8_t *, struct mesh_prov_data *);
int __real_mesh_cfg_comp_page0_encode(const struct mesh_cfg_comp_page0 *,
    uint8_t *, size_t *);
int __real_mesh_cfg_comp_status_build(const struct mesh_cfg_comp_status *,
    uint8_t *, size_t *);
int __real_mesh_cfg_u8_state_build(uint32_t, uint8_t, uint8_t *, size_t *);
int __real_mesh_cfg_u8_state_parse(const uint8_t *, size_t, uint32_t *,
    uint8_t *);
int __real_mesh_cfg_comp_get_parse(const uint8_t *, size_t, uint8_t *);
int __real_mesh_cfg_node_reset_status_build(uint8_t *, size_t *);
int __real_mesh_hlt_attention_build(uint32_t, uint8_t, uint8_t *, size_t *);
int __real_mesh_hlt_attention_parse(const uint8_t *, size_t, uint32_t *,
    uint8_t *);
int __real_mesh_hlt_fault_get_parse(const uint8_t *, size_t, uint16_t *);
int __real_mesh_hlt_fault_status_build(const struct mesh_hlt_fault_status *,
    uint8_t *, size_t *);

/* ---- wrappers ---- */
int
__wrap_mesh_sim_init(struct mesh_sim *s, const uint8_t *nk, const uint8_t *ak,
    uint32_t iv)
{
	if (f_sim_init)
		return (-1);
	return (__real_mesh_sim_init(s, nk, ak, iv));
}
struct mesh_node *
__wrap_mesh_sim_add_node(struct mesh_sim *s, uint16_t a, uint8_t n)
{
	if (f_add_node)
		return (NULL);
	return (__real_mesh_sim_add_node(s, a, n));
}
int
__wrap_mesh_sim_add_model(struct mesh_node *n, uint8_t e, struct mesh_model m)
{
	if (f_add_model_id != 0 && m.model_id == f_add_model_id)
		return (-1);
	return (__real_mesh_sim_add_model(n, e, m));
}
int
__wrap_mesh_sim_reinject(struct mesh_sim *s, int t, const uint8_t *b, size_t l)
{
	if (f_reinject)
		return (-1);
	return (__real_mesh_sim_reinject(s, t, b, l));
}
int
__wrap_mesh_sim_send_access(struct mesh_sim *s, struct mesh_node *n, uint16_t d,
    uint32_t op, const uint8_t *p, size_t pl, uint8_t ttl)
{
	if (f_send_access)
		return (-1);
	return (__real_mesh_sim_send_access(s, n, d, op, p, pl, ttl));
}
int
__wrap_mesh_gen_onoff_set_encode(const struct mesh_gen_onoff_set *in,
    uint8_t *o, size_t *ol)
{
	if (f_onoff_encode)
		return (-1);
	return (__real_mesh_gen_onoff_set_encode(in, o, ol));
}
int
__wrap_mesh_gen_level_set_encode(const struct mesh_gen_level_set *in,
    uint8_t *o, size_t *ol)
{
	if (f_level_encode)
		return (-1);
	return (__real_mesh_gen_level_set_encode(in, o, ol));
}
int
__wrap_mesh_prov_data_unpack(const uint8_t *in, struct mesh_prov_data *out)
{
	if (f_data_unpack)
		return (-1);
	return (__real_mesh_prov_data_unpack(in, out));
}
int
__wrap_mesh_cfg_comp_page0_encode(const struct mesh_cfg_comp_page0 *in,
    uint8_t *o, size_t *ol)
{
	if (f_page0_encode)
		return (-1);
	return (__real_mesh_cfg_comp_page0_encode(in, o, ol));
}
int
__wrap_mesh_cfg_comp_status_build(const struct mesh_cfg_comp_status *in,
    uint8_t *o, size_t *ol)
{
	if (f_comp_status)
		return (-1);
	return (__real_mesh_cfg_comp_status_build(in, o, ol));
}
int
__wrap_mesh_cfg_u8_state_build(uint32_t op, uint8_t v, uint8_t *o, size_t *ol)
{
	if (f_u8_build)
		return (-1);
	return (__real_mesh_cfg_u8_state_build(op, v, o, ol));
}
int
__wrap_mesh_cfg_u8_state_parse(const uint8_t *in, size_t l, uint32_t *op,
    uint8_t *v)
{
	if (f_u8_parse)
		return (-1);
	return (__real_mesh_cfg_u8_state_parse(in, l, op, v));
}
int
__wrap_mesh_cfg_comp_get_parse(const uint8_t *in, size_t l, uint8_t *pg)
{
	if (f_comp_get_parse)
		return (-1);
	return (__real_mesh_cfg_comp_get_parse(in, l, pg));
}
int
__wrap_mesh_cfg_node_reset_status_build(uint8_t *o, size_t *ol)
{
	if (f_node_reset_build)
		return (-1);
	return (__real_mesh_cfg_node_reset_status_build(o, ol));
}
int
__wrap_mesh_hlt_attention_build(uint32_t op, uint8_t a, uint8_t *o, size_t *ol)
{
	if (f_att_build)
		return (-1);
	return (__real_mesh_hlt_attention_build(op, a, o, ol));
}
int
__wrap_mesh_hlt_attention_parse(const uint8_t *in, size_t l, uint32_t *op,
    uint8_t *a)
{
	if (f_att_parse)
		return (-1);
	return (__real_mesh_hlt_attention_parse(in, l, op, a));
}
int
__wrap_mesh_hlt_fault_get_parse(const uint8_t *in, size_t l, uint16_t *c)
{
	if (f_fault_get_parse)
		return (-1);
	return (__real_mesh_hlt_fault_get_parse(in, l, c));
}
int
__wrap_mesh_hlt_fault_status_build(const struct mesh_hlt_fault_status *in,
    uint8_t *o, size_t *ol)
{
	if (f_fault_status_build)
		return (-1);
	return (__real_mesh_hlt_fault_status_build(in, o, ol));
}

static const uint8_t k_netkey[16] = { 1, 2, 3, 4, 5, 6, 7, 8,
	9, 10, 11, 12, 13, 14, 15, 16 };
static const uint8_t k_appkey[16] = { 16, 15, 14, 13, 12, 11, 10, 9,
	8, 7, 6, 5, 4, 3, 2, 1 };

static void
base_config(struct meshd_config *cfg)
{

	meshd_config_defaults(cfg);
	memcpy(cfg->netkey, k_netkey, 16);
	memcpy(cfg->appkey, k_appkey, 16);
	cfg->have_netkey = 1;
	cfg->have_appkey = 1;
	cfg->unicast_addr = 0x0001;
}

/* ================================================================
 * Setup-path failures (meshd_setup_node via node_init).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(setup_failures);
ATF_TC_BODY(setup_failures, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);

	base_config(&cfg);
	f_sim_init = 1;
	ATF_CHECK_EQ(-1, meshd_node_init(nd, &cfg));
	f_sim_init = 0;

	f_add_node = 1;
	ATF_CHECK_EQ(-1, meshd_node_init(nd, &cfg));
	f_add_node = 0;

	f_add_model_id = MESH_MODEL_GEN_ONOFF_SRV;	/* first add_model */
	ATF_CHECK_EQ(-1, meshd_node_init(nd, &cfg));
	f_add_model_id = MESH_MODEL_GEN_LEVEL_SRV;	/* second add_model */
	ATF_CHECK_EQ(-1, meshd_node_init(nd, &cfg));
	f_add_model_id = 0;
}

/* Provision-path failure through the shared setup helper. */
ATF_TC_WITHOUT_HEAD(provision_setup_failure);
ATF_TC_BODY(provision_setup_failure, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_prov_data pd;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	memset(&pd, 0, sizeof(pd));
	memcpy(pd.netkey, k_netkey, 16);
	pd.unicast_addr = 0x0004;

	f_add_node = 1;
	ATF_CHECK_EQ(-1, meshd_provision_local(nd, &pd));
	f_add_node = 0;
}

/* mesh_prov_data_unpack failure after a good decrypt. */
ATF_TC_WITHOUT_HEAD(provision_unpack_failure);
ATF_TC_BODY(provision_unpack_failure, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_prov_data pd;
	uint8_t skey[16], snonce[13], data[25], enc[25], mic[8];
	size_t i;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	for (i = 0; i < 16; i++)
		skey[i] = (uint8_t)i;
	for (i = 0; i < 13; i++)
		snonce[i] = (uint8_t)(i + 1);
	memset(&pd, 0, sizeof(pd));
	memcpy(pd.netkey, k_netkey, 16);
	pd.unicast_addr = 0x0004;
	mesh_prov_data_pack(&pd, data);
	ATF_REQUIRE_EQ(0, mesh_prov_data_encrypt(skey, snonce, data, enc, mic));

	f_data_unpack = 1;
	ATF_CHECK_EQ(-1, meshd_provision_recv_data(nd, skey, snonce, enc, mic));
	f_data_unpack = 0;
}

/* ================================================================
 * Send / receive path failures.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(send_failures);
ATF_TC_BODY(send_failures, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	f_onoff_encode = 1;
	ATF_CHECK_EQ(-1, meshd_send_onoff(nd, 0x0002, 1, 1));
	f_onoff_encode = 0;

	f_level_encode = 1;
	ATF_CHECK_EQ(-1, meshd_send_level(nd, 0x0002, 5, 1));
	f_level_encode = 0;

	/* Originate helper: send_access failure arm. */
	f_send_access = 1;
	ATF_CHECK_EQ(-1, meshd_send_onoff(nd, 0x0002, 1, 1));
	ATF_CHECK_EQ(-1, meshd_send_level(nd, 0x0002, 5, 1));
	f_send_access = 0;
}

ATF_TC_WITHOUT_HEAD(reinject_failure);
ATF_TC_BODY(reinject_failure, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t pdu[29];

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	memset(pdu, 0x11, sizeof(pdu));

	f_reinject = 1;
	ATF_CHECK_EQ(-1, meshd_bearer_rx(nd, pdu, sizeof(pdu)));
	f_reinject = 0;
}

/* ================================================================
 * Foundation-model reply-build / parse failures.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(foundation_failures);
ATF_TC_BODY(foundation_failures, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t msg[64], reply[512];
	size_t mlen, rlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Default TTL Get: reply u8_state_build failure. */
	ATF_REQUIRE_EQ(0, mesh_cfg_empty_build(MESH_CFG_OP_DEFAULT_TTL_GET,
	    msg, &mlen));
	f_u8_build = 1;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	f_u8_build = 0;

	/* Default TTL Set: parse failure. */
	ATF_REQUIRE_EQ(0, mesh_cfg_u8_state_build(MESH_CFG_OP_DEFAULT_TTL_SET,
	    9, msg, &mlen));
	f_u8_parse = 1;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	f_u8_parse = 0;
	/* Default TTL Set: reply build failure (after a good parse). */
	f_u8_build = 1;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	f_u8_build = 0;

	/* Composition Data Get: get-parse, page0-encode, status-build arms. */
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_get_build(0, msg, &mlen));
	f_comp_get_parse = 1;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	f_comp_get_parse = 0;
	f_page0_encode = 1;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	f_page0_encode = 0;
	f_comp_status = 1;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	f_comp_status = 0;

	/* Node Reset: status-build failure. */
	ATF_REQUIRE_EQ(0, mesh_cfg_node_reset_build(msg, &mlen));
	f_node_reset_build = 1;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	f_node_reset_build = 0;

	/* Health Attention Get: build failure. */
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_build(MESH_HLT_OP_ATTENTION_GET,
	    0, msg, &mlen));
	f_att_build = 1;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	f_att_build = 0;

	/* Health Attention Set: parse failure, then reply-build failure. */
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_build(MESH_HLT_OP_ATTENTION_SET,
	    3, msg, &mlen));
	f_att_parse = 1;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	f_att_parse = 0;
	f_att_build = 1;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	f_att_build = 0;

	/* Health Fault Get: get-parse failure, then status-build failure. */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_get_build(nd->health.company_id,
	    msg, &mlen));
	f_fault_get_parse = 1;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	f_fault_get_parse = 0;
	f_fault_status_build = 1;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	f_fault_status_build = 0;

	/* Health Fault Get: the n_faults overflow guard. */
	nd->health.n_faults = MESH_HLT_MAX_FAULTS + 1;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	nd->health.n_faults = 0;
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, setup_failures);
	ATF_TP_ADD_TC(tp, provision_setup_failure);
	ATF_TP_ADD_TC(tp, provision_unpack_failure);
	ATF_TP_ADD_TC(tp, send_failures);
	ATF_TP_ADD_TC(tp, reinject_failure);
	ATF_TP_ADD_TC(tp, foundation_failures);

	return (atf_no_error());
}
