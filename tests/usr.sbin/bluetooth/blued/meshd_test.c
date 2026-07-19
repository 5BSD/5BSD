/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the meshd(8) node daemon logic (meshd_node.c, meshd_config.c,
 * meshd_ctl.c) built on libblemesh.  These exercise the daemon's own glue -
 * configuration parsing, node/model setup, the bearer receive/transmit seam,
 * provisioning, foundation-model message processing and the control surface -
 * to the branch level, including every error arm reachable without fault
 * injection (the remaining defensive library-failure arms are covered by
 * meshd_fault_test.c).
 *
 * The receive path is driven with real secured Network PDUs produced by a
 * second, key-matched mesh_sim(3) node, so the full deobfuscate / decrypt /
 * dispatch pipeline runs end to end.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <stdbool.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mesh_test_heap.h"
#include "mesh_crypto.h"
#include "meshd.h"
#include "mesh_beacon.h"
#ifdef MESHD_WITH_PROBE_TAP
#include "blued_probe_tap.h"
#endif

int ptap_meshd_node_handler_guard_sweep(struct meshd_node *);
int ptap_meshd_node_internal_state_sweep(struct meshd_node *);

/* Deterministic test keys. */
static const uint8_t g_netkey[16] = {
	0x7d, 0xd7, 0x36, 0x4c, 0xd8, 0x42, 0xad, 0x18,
	0xc1, 0x7c, 0x2b, 0x82, 0x0c, 0x84, 0xc3, 0xd6
};
static const uint8_t g_appkey[16] = {
	0x63, 0x96, 0x47, 0x71, 0x73, 0x4f, 0xbd, 0x76,
	0xe3, 0xb4, 0x05, 0x19, 0xd1, 0xd9, 0x4a, 0x48
};

/* Decode an even-length hex string into out (writing exactly len octets). */
static void
hex_bytes(uint8_t *out, const char *hex, size_t len)
{
	size_t i;
	unsigned int b;

	for (i = 0; i < len; i++) {
		sscanf(hex + 2 * i, "%02x", &b);
		out[i] = (uint8_t)b;
	}
}

static void
base_config(struct meshd_config *cfg)
{

	meshd_config_defaults(cfg);
	memcpy(cfg->netkey, g_netkey, 16);
	memcpy(cfg->appkey, g_appkey, 16);
	cfg->have_netkey = 1;
	cfg->have_appkey = 1;
	cfg->unicast_addr = 0x0001;
	cfg->iv_index = 0;
	cfg->default_ttl = 7;
}

static const uint16_t meshd_expected_sig_models[] = {
	0x0000,				/* Configuration Server */
	0x0002,				/* Health Server */
	MESH_MODEL_GEN_ONOFF_SRV,
	MESH_MODEL_GEN_LEVEL_SRV,
	MESH_MODEL_LIGHT_LIGHTNESS_SRV,
	MESH_MODEL_LIGHT_LIGHTNESS_SETUP_SRV,
	MESH_MODEL_LIGHT_CTL_SRV,
	MESH_MODEL_LIGHT_CTL_SETUP_SRV,
	MESH_MODEL_LIGHT_HSL_SRV,
	MESH_MODEL_LIGHT_HSL_SETUP_SRV,
	MESH_MODEL_LIGHT_XYL_SRV,
	MESH_MODEL_LIGHT_XYL_SETUP_SRV,
	MESH_MODEL_LIGHT_LC_SRV,
	MESH_MODEL_LIGHT_LC_SETUP_SRV,
	MESH_MODEL_GEN_DTT_SRV,
	MESH_MODEL_GEN_POWER_ONOFF_SRV,
	MESH_MODEL_GEN_POWER_ONOFF_SETUP_SRV,
	MESH_MODEL_GEN_POWER_LEVEL_SRV,
	MESH_MODEL_GEN_POWER_LEVEL_SETUP_SRV,
	MESH_MODEL_GEN_BATTERY_SRV,
	MESH_MODEL_GEN_LOCATION_SRV,
	MESH_MODEL_GEN_LOCATION_SETUP_SRV,
	MESH_MODEL_SENSOR_SRV,
	MESH_MODEL_SENSOR_SETUP_SRV,
	MESH_MODEL_TIME_SRV,
	MESH_MODEL_TIME_SETUP_SRV,
	MESH_MODEL_SCENE_SRV,
	MESH_MODEL_SCENE_SETUP_SRV,
	MESH_MODEL_SCHEDULER_SRV,
	MESH_MODEL_SCHEDULER_SETUP_SRV,
};

static bool
meshd_db_has_model(const struct meshd_node *nd, uint16_t model_id)
{
	size_t i;

	for (i = 0; i < nd->db.n_models; i++) {
		if (nd->db.models[i].valid && !nd->db.models[i].id.vendor &&
		    nd->db.models[i].id.model_id == model_id)
			return (true);
	}
	return (false);
}

static bool
meshd_db_has_model_at(const struct meshd_node *nd, uint16_t elem_addr,
    uint16_t model_id)
{
	size_t i;

	for (i = 0; i < nd->db.n_models; i++) {
		if (nd->db.models[i].valid &&
		    nd->db.models[i].elem_addr == elem_addr &&
		    !nd->db.models[i].id.vendor &&
		    nd->db.models[i].id.model_id == model_id)
			return (true);
	}
	return (false);
}

static int
bind_model_to_primary_appkey(struct meshd_node *nd, uint16_t elem_addr,
    const struct mesh_cfg_model_id *id)
{
	size_t i;

	for (i = 0; i < nd->db.n_models; i++) {
		struct meshd_model_entry *m = &nd->db.models[i];

		if (!m->valid || m->elem_addr != elem_addr ||
		    m->id.model_id != id->model_id || m->id.vendor != id->vendor ||
		    (id->vendor && m->id.company_id != id->company_id))
			continue;
		m->app_idx[0] = nd->appkey_index;
		m->n_app = 1;
		meshd_sync_subscriptions(nd);
		return (0);
	}
	return (-1);
}

static bool
comp_has_model(const struct mesh_cfg_comp_page0 *comp, uint16_t model_id)
{
	size_t ei, i;

	if (comp->n_elements == 0)
		return (false);
	for (ei = 0; ei < comp->n_elements; ei++) {
		for (i = 0; i < comp->elements[ei].n_sig; i++) {
			if (comp->elements[ei].sig_models[i] == model_id)
				return (true);
		}
	}
	return (false);
}

/* Build a secured Network PDU from a key-matched peer addressed to dst. */
static int
peer_access_pdu_seq(uint16_t src, uint16_t dst, uint32_t seq,
    uint32_t opcode, const uint8_t *params, size_t params_len, uint8_t *out,
    size_t *outlen)
{
	MESH_HEAP(struct mesh_sim, peer);
	struct mesh_node *nodeb;

	if (mesh_sim_init(peer, g_netkey, g_appkey, 0) != 0)
		return (-1);
	nodeb = mesh_sim_add_node(peer, src, 1);
	if (nodeb == NULL)
		return (-1);
	nodeb->seq = seq;
	if (mesh_sim_send_access(peer, nodeb, dst, opcode, params, params_len,
	    4) != 0 || peer->n_tx == 0 || !peer->tx[0].valid)
		return (-1);
	memcpy(out, peer->tx[0].bytes, peer->tx[0].len);
	*outlen = peer->tx[0].len;
	return (0);
}

static int
peer_onoff_pdu_seq(uint16_t src, uint16_t dst, uint8_t onoff, uint32_t seq,
    uint8_t *out, size_t *outlen)
{
	MESH_HEAP(struct mesh_sim, peer);
	struct mesh_node *nodeb;
	struct mesh_gen_onoff_set set;
	uint8_t params[MESH_GEN_PARAMS_MAX];
	size_t plen;

	if (mesh_sim_init(peer, g_netkey, g_appkey, 0) != 0)
		return (-1);
	nodeb = mesh_sim_add_node(peer, src, 1);
	if (nodeb == NULL)
		return (-1);
	nodeb->seq = seq;
	memset(&set, 0, sizeof(set));
	set.onoff = onoff;
	set.tid = (uint8_t)src;
	if (mesh_gen_onoff_set_encode(&set, params, &plen) != 0)
		return (-1);
	if (mesh_sim_send_access(peer, nodeb, dst, MESH_OP_GEN_ONOFF_SET,
	    params, plen, 4) != 0)
		return (-1);
	if (peer->n_tx == 0 || !peer->tx[0].valid)
		return (-1);
	memcpy(out, peer->tx[0].bytes, peer->tx[0].len);
	*outlen = peer->tx[0].len;
	return (0);
}

static int
peer_onoff_pdu(uint16_t src, uint16_t dst, uint8_t onoff, uint8_t *out,
    size_t *outlen)
{
	return (peer_onoff_pdu_seq(src, dst, onoff, 0, out, outlen));
}

/* ================================================================
 * Configuration parser.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(config_hexdecode);
ATF_TC_BODY(config_hexdecode, tc)
{
	uint8_t buf[4];

	ATF_CHECK_EQ(0, meshd_hexdecode("00ff10AB", buf, 4));
	ATF_CHECK_EQ(0x00, buf[0]);
	ATF_CHECK_EQ(0xff, buf[1]);
	ATF_CHECK_EQ(0xAB, buf[3]);
	/* Wrong length, bad chars, NULLs. */
	ATF_CHECK_EQ(-1, meshd_hexdecode("00ff10", buf, 4));
	ATF_CHECK_EQ(-1, meshd_hexdecode("00ffg0ab", buf, 4));
	ATF_CHECK_EQ(-1, meshd_hexdecode("0Xff10ab", buf, 4));
	ATF_CHECK_EQ(-1, meshd_hexdecode(NULL, buf, 4));
	ATF_CHECK_EQ(-1, meshd_hexdecode("00", NULL, 1));
	/* Characters below '0' and between '9' and 'A' exercise every hexval arm. */
	ATF_CHECK_EQ(-1, meshd_hexdecode("0/", buf, 1));	/* '/' < '0' */
	ATF_CHECK_EQ(-1, meshd_hexdecode(":0", buf, 1));	/* ':' in ('9','A') */
}

ATF_TC_WITHOUT_HEAD(config_parse_lines);
ATF_TC_BODY(config_parse_lines, tc)
{
	struct meshd_config cfg;

	meshd_config_defaults(&cfg);

	/* Ignored lines. */
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, ""));
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "   \t"));
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "# comment"));
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "\n"));

	/* Every recognised key, success path. */
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg,
	    "device_uuid 00112233445566778899aabbccddeeff"));
	ATF_CHECK(cfg.have_uuid);
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "company_id 0x1234"));
	ATF_CHECK_EQ(0x1234, cfg.company_id);
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "product_id 42"));
	ATF_CHECK_EQ(42, cfg.product_id);
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "version_id 7"));
	ATF_CHECK_EQ(7, cfg.version_id);
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg,
	    "netkey 7dd7364cd842ad18c17c2b820c84c3d6"));
	ATF_CHECK(cfg.have_netkey);
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg,
	    "appkey 63964771734fbd76e3b40519d1d94a48"));
	ATF_CHECK(cfg.have_appkey);
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "netkey_index 5"));
	ATF_CHECK_EQ(5, cfg.netkey_index);
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "appkey_index 0x10"));
	ATF_CHECK_EQ(16, cfg.appkey_index);
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "iv_index 42"));
	ATF_CHECK_EQ(42, cfg.iv_index);
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "unicast_addr 0x0007"));
	ATF_CHECK_EQ(7, cfg.unicast_addr);
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "default_ttl 5"));
	ATF_CHECK_EQ(5, cfg.default_ttl);
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "relay 1"));
	ATF_CHECK(cfg.features & MESH_CFG_FEATURE_RELAY);
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "relay 0"));
	ATF_CHECK(!(cfg.features & MESH_CFG_FEATURE_RELAY));
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "proxy 1"));
	ATF_CHECK(cfg.features & MESH_CFG_FEATURE_PROXY);
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "proxy 0"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "friend 1"));
	ATF_CHECK(!(cfg.features & MESH_CFG_FEATURE_FRIEND));
	ATF_CHECK_EQ(0, meshd_config_parse_line(&cfg, "friend 0"));
}

ATF_TC_WITHOUT_HEAD(config_parse_errors);
ATF_TC_BODY(config_parse_errors, tc)
{
	struct meshd_config cfg;

	meshd_config_defaults(&cfg);

	ATF_CHECK_EQ(-1, meshd_config_parse_line(NULL, "x y"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, NULL));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "netkey_only_key"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "bogus 1"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "device_uuid zz"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "company_id 65536"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "product_id nope"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "version_id 65536"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "netkey short"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "appkey short"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "netkey_index 4096"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "appkey_index 99999"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "iv_index notanumber"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "unicast_addr 0x1FFFF"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "default_ttl 200"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "relay 2"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "proxy 5"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "friend 9"));
	/* trailing garbage after a valid number */
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "iv_index 12abc"));
	/* Non-numeric values exercise the parse-failure operand of each key. */
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "netkey_index zz"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "appkey_index zz"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "unicast_addr zz"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "default_ttl zz"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "relay zz"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "proxy zz"));
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "friend zz"));
	/* A value above 32 bits (v > 0xFFFFFFFF) and a strtoul overflow (ERANGE). */
	ATF_CHECK_EQ(-1, meshd_config_parse_line(&cfg, "iv_index 0x1FFFFFFFF"));
	ATF_CHECK_EQ(-1,
	    meshd_config_parse_line(&cfg, "iv_index 0xFFFFFFFFFFFFFFFFF"));
}

ATF_TC_WITHOUT_HEAD(config_validate);
ATF_TC_BODY(config_validate, tc)
{
	struct meshd_config cfg;

	base_config(&cfg);
	ATF_CHECK_EQ(0, meshd_config_validate(&cfg));

	ATF_CHECK_EQ(-1, meshd_config_validate(NULL));
	base_config(&cfg);
	cfg.unicast_addr = 0x0000;
	ATF_CHECK_EQ(-1, meshd_config_validate(&cfg));
	base_config(&cfg);
	cfg.unicast_addr = 0x8000;
	ATF_CHECK_EQ(-1, meshd_config_validate(&cfg));
	base_config(&cfg);
	cfg.default_ttl = 1;
	ATF_CHECK_EQ(-1, meshd_config_validate(&cfg));
	base_config(&cfg);
	cfg.default_ttl = 200;
	ATF_CHECK_EQ(-1, meshd_config_validate(&cfg));
	base_config(&cfg);
	cfg.netkey_index = 0x1000;
	ATF_CHECK_EQ(-1, meshd_config_validate(&cfg));
	base_config(&cfg);
	cfg.appkey_index = 0x1000;
	ATF_CHECK_EQ(-1, meshd_config_validate(&cfg));
}

ATF_TC_WITHOUT_HEAD(config_load_file);
ATF_TC_BODY(config_load_file, tc)
{
	struct meshd_config cfg;
	FILE *fp;
	const char *tmpdir;
	char dir[PATH_MAX], good[PATH_MAX], bad[PATH_MAX], inval[PATH_MAX];
	char overlong[PATH_MAX];

	/*
	 * Write fixtures into a private temp directory (absolute paths), not
	 * the current working directory: run standalone (outside kyua) these
	 * would otherwise land in — and pollute — the source tree.
	 */
	tmpdir = getenv("TMPDIR");
	snprintf(dir, sizeof(dir), "%s/meshd-cfgtest.XXXXXX",
	    (tmpdir != NULL && tmpdir[0] != '\0') ? tmpdir : "/tmp");
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	snprintf(good, sizeof(good), "%s/good.conf", dir);
	snprintf(bad, sizeof(bad), "%s/bad.conf", dir);
	snprintf(inval, sizeof(inval), "%s/inval.conf", dir);
	snprintf(overlong, sizeof(overlong), "%s/overlong.conf", dir);

	/* Missing file / NULL arguments. */
	ATF_CHECK_EQ(-1, meshd_config_load(&cfg, "/nonexistent/meshd.conf"));
	ATF_CHECK_EQ(-1, meshd_config_load(NULL, "x"));
	ATF_CHECK_EQ(-1, meshd_config_load(&cfg, NULL));

	/* A good file. */
	fp = fopen(good, "w");
	ATF_REQUIRE(fp != NULL);
	fprintf(fp, "# sample\nnetkey 7dd7364cd842ad18c17c2b820c84c3d6\n"
	    "appkey 63964771734fbd76e3b40519d1d94a48\n"
	    "unicast_addr 0x0003\ndefault_ttl 7\nrelay 1\n");
	fclose(fp);
	ATF_REQUIRE_EQ(0, chmod(good, 0600));
	ATF_CHECK_EQ(0, meshd_config_load(&cfg, good));
	ATF_CHECK_EQ(0x0003, cfg.unicast_addr);
	ATF_REQUIRE_EQ(0, chmod(good, 0644));
	ATF_CHECK_EQ_MSG(-1, meshd_config_load(&cfg, good),
	    "configuration containing Mesh keys must not be group/world readable");
	ATF_REQUIRE_EQ(0, chmod(good, 0600));

	/* A file with a bad line. */
	fp = fopen(bad, "w");
	ATF_REQUIRE(fp != NULL);
	fprintf(fp, "unicast_addr notanaddr\n");
	fclose(fp);
	ATF_CHECK_EQ(-1, meshd_config_load(&cfg, bad));

	/* A file that parses but fails validation. */
	fp = fopen(inval, "w");
	ATF_REQUIRE(fp != NULL);
	fprintf(fp, "unicast_addr 0x9000\n");
	fclose(fp);
	ATF_CHECK_EQ(-1, meshd_config_load(&cfg, inval));

	/* Never parse a truncated prefix of an oversized physical line. */
	fp = fopen(overlong, "w");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE_EQ(0, fputs("relay 1 #", fp) < 0);
	for (size_t i = 0; i < 300; i++)
		ATF_REQUIRE_EQ(0, fputc('x', fp) == EOF);
	ATF_REQUIRE_EQ(0, fputc('\n', fp) == EOF);
	ATF_REQUIRE_EQ(0, fclose(fp));
	ATF_CHECK_EQ(-1, meshd_config_load(&cfg, overlong));

	/* Best-effort cleanup — never fail the test on teardown. */
	(void)unlink(good);
	(void)unlink(bad);
	(void)unlink(inval);
	(void)unlink(overlong);
	(void)rmdir(dir);
}

/* ================================================================
 * Node init / accessors.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(node_init);
ATF_TC_BODY(node_init, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);

	base_config(&cfg);
	ATF_CHECK_EQ(-1, meshd_node_init(NULL, &cfg));
	ATF_CHECK_EQ(-1, meshd_node_init(nd, NULL));

	base_config(&cfg);
	cfg.unicast_addr = 0x0000;
	ATF_CHECK_EQ(-1, meshd_node_init(nd, &cfg));

	/* Provisioned node with all features. */
	base_config(&cfg);
	cfg.features = MESH_CFG_FEATURE_RELAY | MESH_CFG_FEATURE_PROXY |
	    MESH_CFG_FEATURE_FRIEND;
	ATF_CHECK_EQ(0, meshd_node_init(nd, &cfg));
	ATF_CHECK_EQ(1, nd->provisioned);
	ATF_CHECK_EQ(0x0001, meshd_node_addr(nd));
	ATF_CHECK_EQ(0, meshd_node_seq(nd));
	ATF_CHECK_EQ(0, meshd_node_iv(nd));
	ATF_CHECK_EQ(MESH_GEN_OFF, meshd_node_onoff(nd));
	ATF_CHECK_EQ(INT16_MIN, meshd_node_level(nd));
	ATF_CHECK_EQ(1, nd->cfg.relay);
	ATF_CHECK_EQ(1, nd->cfg.gatt_proxy);
	ATF_CHECK_EQ(2, nd->cfg.friend);
	ATF_CHECK_EQ(0, nd->friend_enabled);

	/* Unprovisioned node (no netkey). */
	base_config(&cfg);
	cfg.have_netkey = 0;
	ATF_CHECK_EQ(0, meshd_node_init(nd, &cfg));
	ATF_CHECK_EQ(0, nd->provisioned);

	ATF_CHECK_EQ(1, meshd_addr_is_unicast(0x0001));
	ATF_CHECK_EQ(1, meshd_addr_is_unicast(0x7fff));
	ATF_CHECK_EQ(0, meshd_addr_is_unicast(0x0000));
	ATF_CHECK_EQ(0, meshd_addr_is_unicast(0x8000));
}

/* ================================================================
 * Bearer receive / transmit seam.
 * ================================================================ */
static int g_tx_count;
static int g_tx_fail;
static uint8_t g_last_tx[64];
static size_t g_last_tx_len;
static int g_proxy_tx_count;
static char g_proxy_tx_addr[18];
static uint8_t g_proxy_tx_type;
static uint8_t g_proxy_tx[64];
static size_t g_proxy_tx_len;
static int g_proxy_open_status;
static int g_proxy_open_calls;
static int g_proxy_close_calls;
static uint8_t g_proxy_close_addr_type;
static uint8_t g_proxy_adapter_index;

static int
capture_proxy_open(void *arg __unused, const char *addr,
    uint8_t addr_type __unused, uint8_t adapter_index)
{

	if (addr == NULL)
		return (-1);
	g_proxy_open_calls++;
	g_proxy_adapter_index = adapter_index;
	return (g_proxy_open_status);
}

static int
capture_proxy_close(void *arg __unused, const char *addr __unused,
    uint8_t addr_type, uint8_t adapter_index)
{

	g_proxy_close_calls++;
	g_proxy_close_addr_type = addr_type;
	g_proxy_adapter_index = adapter_index;
	return (0);
}

static enum meshd_pdu_class g_last_tx_cls;

static int
capture_tx(void *arg, enum meshd_pdu_class cls, const uint8_t *pdu, size_t len)
{

	(void)arg;
	g_tx_count++;
	g_last_tx_cls = cls;
	memcpy(g_last_tx, pdu, len > sizeof(g_last_tx) ? sizeof(g_last_tx) : len);
	g_last_tx_len = len;
	return (g_tx_fail ? -1 : 0);
}

static int
capture_proxy_tx(void *arg, const char *addr, uint8_t addr_type,
    uint8_t adapter_index, uint8_t type,
    const uint8_t *pdu, size_t len)
{

	(void)arg;
	(void)addr_type;
	g_proxy_adapter_index = adapter_index;
	if (addr == NULL || pdu == NULL || len > sizeof(g_proxy_tx))
		return (-1);
	g_proxy_tx_count++;
	strlcpy(g_proxy_tx_addr, addr, sizeof(g_proxy_tx_addr));
	g_proxy_tx_type = type;
	memcpy(g_proxy_tx, pdu, len);
	g_proxy_tx_len = len;
	return (0);
}

ATF_TC_WITHOUT_HEAD(bearer_rx_and_tx);
ATF_TC_BODY(bearer_rx_and_tx, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .tx = capture_tx, .arg = NULL };
	uint8_t pdu[64];
	size_t len;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);

	/* Error arms. */
	ATF_CHECK_EQ(-1, meshd_bearer_rx(NULL, pdu, 1));
	ATF_CHECK_EQ(-1, meshd_bearer_rx(nd, NULL, 1));
	ATF_CHECK_EQ(-1, meshd_bearer_rx(nd, pdu, 0));

	/* Deliver a real OnOff Set from a key-matched peer -> ON. */
	ATF_REQUIRE_EQ(0, peer_onoff_pdu(0x0102, 0x0001, MESH_GEN_ON, pdu, &len));
	g_tx_count = 0;
	g_tx_fail = 0;
	ATF_CHECK_EQ(1, meshd_bearer_rx(nd, pdu, len));
	ATF_CHECK_EQ(MESH_GEN_ON, meshd_node_onoff(nd));
	ATF_CHECK_EQ(1, nd->rx_delivered);
	/* An acknowledged Set to our unicast yields a Status reply on the bearer. */
	ATF_CHECK(nd->tx_frames > 0);
	ATF_CHECK(g_tx_count > 0);
	/* A Network PDU reply carries the Net PDU (0x2A) class to the bearer. */
	ATF_CHECK_EQ(MESHD_PDU_NET, g_last_tx_cls);

	/* A PDU we do not decode (foreign src already seen or garbage): no rx. */
	memset(pdu, 0xAB, sizeof(pdu));
	ATF_CHECK_EQ(0, meshd_bearer_rx(nd, pdu, 29));

	/* Bearer transmit failure is counted. */
	ATF_REQUIRE_EQ(0, peer_onoff_pdu(0x0103, 0x0001, MESH_GEN_OFF, pdu, &len));
	g_tx_fail = 1;
	ATF_CHECK_EQ(1, meshd_bearer_rx(nd, pdu, len));
	ATF_CHECK(nd->tx_errors > 0);

	/* Unprovisioned node refuses receive. */
	nd->provisioned = 0;
	ATF_CHECK_EQ(-1, meshd_bearer_rx(nd, pdu, len));
}

ATF_TC_WITHOUT_HEAD(gatt_proxy_network_rx);
ATF_TC_BODY(gatt_proxy_network_rx, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .proxy_tx = capture_proxy_tx };
	struct mesh_proxy_seg segs[4];
	struct mesh_proxy_cfg parsed;
	uint8_t net[64], cfgmsg[8], secured[64], plain[16];
	uint8_t nid, enc[16], priv[16], k2p = 0;
	uint16_t filter_addrs[] = { 0xc001, 0xc123 };
	uint32_t seq;
	uint16_t src;
	size_t i, netlen, nseg, cfglen, secured_len, plain_len;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);
	ATF_CHECK_EQ(-1, meshd_proxy_gatt_begin(NULL,
	    "00:11:22:33:44:55", 0, MESHD_ADAPTER_DEFAULT, 23));
	ATF_CHECK_EQ(-1, meshd_proxy_gatt_begin(nd,
	    "00:11:22:33:44:55", 0, MESHD_ADAPTER_DEFAULT, 22));
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_begin(nd,
	    "00:11:22:33:44:55", 0, MESHD_ADAPTER_DEFAULT, 23));
	ATF_CHECK_EQ(-1, meshd_proxy_gatt_begin(nd,
	    "00:11:22:33:44:55", 0, MESHD_ADAPTER_DEFAULT, 23));
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_begin(nd,
	    "00:11:22:33:44:66", 0, MESHD_ADAPTER_DEFAULT, 23));
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_begin(nd,
	    "00:11:22:33:44:55", 0, 7, 23));
	ATF_CHECK_EQ(7, nd->proxy_gatt[2].adapter_index);
	/* Discovery canonicalizes the default selector without duplicating it. */
	ATF_CHECK_EQ(-1, meshd_proxy_gatt_resolve_adapter(NULL,
	    "00:11:22:33:44:66", 0, MESHD_ADAPTER_DEFAULT, 2));
	ATF_CHECK_EQ(-1, meshd_proxy_gatt_resolve_adapter(nd,
	    "00:11:22:33:44:66", 0, MESHD_ADAPTER_DEFAULT,
	    MESHD_ADAPTER_DEFAULT));
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_resolve_adapter(nd,
	    "00:11:22:33:44:66", 0, MESHD_ADAPTER_DEFAULT, 2));
	ATF_CHECK_EQ(2, nd->proxy_gatt[1].adapter_index);
	ATF_CHECK_EQ(-1, meshd_proxy_gatt_resolve_adapter(nd,
	    "00:11:22:33:44:55", 0, MESHD_ADAPTER_DEFAULT, 7));
	ATF_CHECK_EQ(MESHD_ADAPTER_DEFAULT,
	    nd->proxy_gatt[0].adapter_index);
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_begin(nd,
	    "00:11:22:33:44:88", 0, MESHD_ADAPTER_DEFAULT, 23));
	ATF_CHECK_EQ(-1, meshd_proxy_gatt_begin(nd,
	    "00:11:22:33:44:99", 0, MESHD_ADAPTER_DEFAULT, 23));
	ATF_REQUIRE_EQ(0, peer_onoff_pdu(0x0102, 0x0001, MESH_GEN_ON,
	    net, &netlen));
	ATF_REQUIRE_EQ(0, mesh_proxy_segment(MESH_PROXY_TYPE_NETWORK, net,
	    netlen, 20, segs, nitems(segs), &nseg));
	ATF_REQUIRE(nseg > 1);
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_recv(nd, "00:11:22:33:44:55",
	    0, MESHD_ADAPTER_DEFAULT, segs[0].bytes, segs[0].len, 1000));
	for (i = 0; i < nseg; i++)
		ATF_REQUIRE_MSG(meshd_proxy_gatt_recv(nd, "00:11:22:33:44:66",
		    0, 2, segs[i].bytes, segs[i].len,
		    1000 + i) >= 0,
		    "second proxy segment %zu rejected", i);
	for (i = 1; i < nseg; i++)
		ATF_REQUIRE_MSG(meshd_proxy_gatt_recv(nd, "00:11:22:33:44:55",
		    0, MESHD_ADAPTER_DEFAULT, segs[i].bytes, segs[i].len,
		    1000 + i) >= 0,
		    "first proxy segment %zu rejected", i);
	ATF_CHECK_EQ(MESH_GEN_ON, meshd_node_onoff(nd));
	ATF_CHECK_EQ(1, nd->rx_delivered);

	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_filter_status_build(
	    MESH_PROXY_FILTER_ACCEPT, 3, cfgmsg, sizeof(cfgmsg), &cfglen));
	ATF_REQUIRE_EQ(0, mesh_proxy_segment(MESH_PROXY_TYPE_CONFIG, cfgmsg,
	    cfglen, 20, segs, nitems(segs), &nseg));
	ATF_REQUIRE_EQ(1, nseg);
	ATF_CHECK_EQ_MSG(0, meshd_proxy_gatt_recv(nd,
	    "00:11:22:33:44:55", 0, MESHD_ADAPTER_DEFAULT, segs[0].bytes,
	    segs[0].len, 2000),
	    "plaintext Proxy Configuration must be rejected");
	ATF_REQUIRE_EQ(0, mesh_k2(g_netkey, &k2p, 1, &nid, enc, priv));
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_encrypt(enc, priv, nid, cfg.iv_index,
	    7, 0x0120, cfgmsg, cfglen, secured, &secured_len));
	ATF_REQUIRE_EQ(0, mesh_proxy_segment(MESH_PROXY_TYPE_CONFIG, secured,
	    secured_len, 20, segs, nitems(segs), &nseg));
	for (i = 0; i < nseg; i++)
		ATF_REQUIRE(meshd_proxy_gatt_recv(nd, "00:11:22:33:44:55",
		    0, MESHD_ADAPTER_DEFAULT, segs[i].bytes,
		    segs[i].len, 2000 + i) >= 0);
	ATF_CHECK(nd->proxy_gatt[0].have_filter_status);
	ATF_CHECK_EQ(MESH_PROXY_FILTER_ACCEPT, nd->proxy_gatt[0].filter_type);
	ATF_CHECK_EQ(3, nd->proxy_gatt[0].filter_size);

	/* Outbound filter controls are secured and address-scoped. */
	g_proxy_tx_count = 0;
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_set_filter(nd,
	    "00:11:22:33:44:66", 0, MESHD_ADAPTER_DEFAULT, cfg.netkey_index,
	    MESH_PROXY_FILTER_REJECT));
	ATF_CHECK_EQ(1, g_proxy_tx_count);
	/* The default selector must transmit on the session's resolved adapter. */
	ATF_CHECK_EQ(2, g_proxy_adapter_index);
	ATF_CHECK_STREQ("00:11:22:33:44:66", g_proxy_tx_addr);
	ATF_CHECK_EQ(MESH_PROXY_TYPE_CONFIG, g_proxy_tx_type);
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_decrypt(enc, priv, nid, cfg.iv_index,
	    g_proxy_tx, g_proxy_tx_len, &seq, &src, plain, sizeof(plain),
	    &plain_len));
	ATF_CHECK_EQ(nd->addr, src);
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_parse(plain, plain_len, &parsed));
	ATF_CHECK_EQ(MESH_PROXY_OP_SET_FILTER_TYPE, parsed.opcode);
	ATF_CHECK_EQ(MESH_PROXY_FILTER_REJECT, parsed.filter_type);

	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_update_filter(nd,
	    "00:11:22:33:44:66", 0, 2, cfg.netkey_index,
	    MESH_PROXY_OP_ADD_ADDR, filter_addrs, nitems(filter_addrs)));
	ATF_CHECK_EQ(2, g_proxy_tx_count);
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_decrypt(enc, priv, nid, cfg.iv_index,
	    g_proxy_tx, g_proxy_tx_len, &seq, &src, plain, sizeof(plain),
	    &plain_len));
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_parse(plain, plain_len, &parsed));
	ATF_CHECK_EQ(MESH_PROXY_OP_ADD_ADDR, parsed.opcode);
	ATF_CHECK_EQ(nitems(filter_addrs), parsed.naddr);
	ATF_CHECK_EQ(filter_addrs[0], parsed.addrs[0]);
	ATF_CHECK_EQ(filter_addrs[1], parsed.addrs[1]);
	meshd_proxy_gatt_cancel(nd, "00:11:22:33:44:55", 0,
	    MESHD_ADAPTER_DEFAULT);
	ATF_CHECK(!nd->proxy_gatt[0].active);
	ATF_CHECK(nd->proxy_gatt[1].active);
	meshd_proxy_gatt_cancel(nd, NULL, 0, MESHD_ADAPTER_DEFAULT);
	for (i = 0; i < MESHD_MAX_PROXY_GATT; i++)
		ATF_CHECK(!nd->proxy_gatt[i].active);
}

ATF_TC_WITHOUT_HEAD(gatt_proxy_connect_lifecycle);
ATF_TC_BODY(gatt_proxy_connect_lifecycle, tc)
{
	struct meshd_config cfg;
	struct meshd_bearer bearer = {
		.proxy_open = capture_proxy_open,
		.proxy_close = capture_proxy_close,
	};
	MESH_HEAP(struct meshd_node, nd);
	const char *addr = "00:11:22:33:44:55";
	uint8_t first[] = { (MESH_PROXY_SAR_FIRST << 6) |
	    MESH_PROXY_TYPE_NETWORK,
	    0x01 };

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	g_proxy_open_calls = 0;
	g_proxy_open_status = 0;
	ATF_CHECK_EQ(-1, meshd_proxy_gatt_connect(NULL, addr, 0,
	    MESHD_ADAPTER_DEFAULT));
	ATF_CHECK_EQ(-1, meshd_proxy_gatt_connect(nd, NULL, 0,
	    MESHD_ADAPTER_DEFAULT));
	ATF_CHECK_EQ(-1, meshd_proxy_gatt_connect(nd, addr, 0,
	    MESHD_ADAPTER_DEFAULT));
	meshd_set_bearer(nd, &bearer);
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_connect(nd, addr, 0,
	    MESHD_ADAPTER_DEFAULT));
	ATF_CHECK_EQ(1, g_proxy_open_calls);
	ATF_CHECK(nd->proxy_gatt[0].active);
	ATF_CHECK_EQ(-1, meshd_proxy_gatt_connect(nd, addr, 0,
	    MESHD_ADAPTER_DEFAULT));
	/* Address type is part of the Core identity, so both may coexist. */
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_connect(nd, addr, 1,
	    MESHD_ADAPTER_DEFAULT));
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_set_mtu(nd, addr, 0,
	    MESHD_ADAPTER_DEFAULT, 247));
	ATF_CHECK_EQ(247, nd->proxy_gatt[0].mtu);
	ATF_CHECK_EQ(23, nd->proxy_gatt[1].mtu);

	/* An unfinished SAR transfer forces link close after 20 seconds. */
	g_proxy_close_calls = 0;
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_recv(nd, addr, 1,
	    MESHD_ADAPTER_DEFAULT, first,
	    sizeof(first), 1000));
	ATF_CHECK_EQ(1000, nd->proxy_gatt[1].rx_started_ms);
	meshd_gatt_tick(nd, 1000 + MESHD_PROXY_SAR_TIMEOUT_MS - 1);
	ATF_CHECK_EQ(0, g_proxy_close_calls);
	meshd_gatt_tick(nd, 1000 + MESHD_PROXY_SAR_TIMEOUT_MS);
	ATF_CHECK_EQ(1, g_proxy_close_calls);
	ATF_CHECK_EQ(1, g_proxy_close_addr_type);
	ATF_CHECK(nd->proxy_gatt[0].active);
	ATF_CHECK(!nd->proxy_gatt[1].active);
	meshd_proxy_gatt_cancel(nd, NULL, 0, MESHD_ADAPTER_DEFAULT);
	g_proxy_open_status = -1;
	ATF_CHECK_EQ(-1, meshd_proxy_gatt_connect(nd, addr, 0,
	    MESHD_ADAPTER_DEFAULT));
	ATF_CHECK_EQ(3, g_proxy_open_calls);
	ATF_CHECK(!nd->proxy_gatt[0].active);
	meshd_node_fini(nd);
}

ATF_TC_WITHOUT_HEAD(model_publication_scheduler);
ATF_TC_BODY(model_publication_scheduler, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .tx = capture_tx };
	struct meshd_model_entry *model = NULL;
	uint8_t access[8], status = 1;
	uint8_t net[64];
	size_t i, access_len;
	size_t netlen;
	int changed;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);
	nd->db.appkeys[0].valid = 1;
	nd->db.appkeys[0].net_idx = cfg.netkey_index;
	nd->db.appkeys[0].app_idx = cfg.appkey_index;
	memcpy(nd->db.appkeys[0].key, cfg.appkey, 16);
	for (i = 0; i < nd->db.n_models; i++)
		if (nd->db.models[i].id.model_id == MESH_MODEL_GEN_ONOFF_SRV)
			model = &nd->db.models[i];
	ATF_REQUIRE(model != NULL);
	model->has_pub = 1;
	model->pub.pub_addr = 0xc001;
	model->pub.app_idx = cfg.appkey_index;
	model->pub.ttl = 5;
	model->pub.period = 0x01;	/* 100 ms */
	model->pub.retransmit = 0x01;	/* one retransmission at 50 ms */
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_GEN_ONOFF_STATUS,
	    &status, 1, access, &access_len));
	g_tx_count = 0;
	ATF_REQUIRE_EQ(0, meshd_publish_raw(nd, nd->addr,
	    MESH_MODEL_GEN_ONOFF_SRV, 0,
	    access, access_len));
	ATF_CHECK_EQ(1, g_tx_count);
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 50, &changed));
	ATF_CHECK_EQ(2, g_tx_count);
	nd->app->onoff.present = MESH_GEN_OFF;
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 100, &changed));
	ATF_CHECK_EQ(3, g_tx_count);
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(model->pub_access,
	    model->pub_access_len, &(struct mesh_access_pdu){0}));
	ATF_CHECK_EQ(MESH_GEN_OFF,
	    model->pub_access[model->pub_access_len - 1]);

	/* An actual model-state change publishes immediately. */
	g_tx_count = 0;
	ATF_REQUIRE_EQ(0, peer_onoff_pdu(0x0102, nd->addr, MESH_GEN_ON,
	    net, &netlen));
	ATF_REQUIRE_EQ(1, meshd_bearer_rx(nd, net, netlen));
	ATF_CHECK_EQ_MSG(2, g_tx_count,
	    "acknowledged Status and state-change publication were transmitted");
	ATF_CHECK_EQ(MESH_GEN_ON,
	    model->pub_access[model->pub_access_len - 1]);

	/* A model without a Get opcode publishes its caller-supplied cache. */
	model->pub_get_opcode = 0;
	model->next_pub_ms = 0;
	model->pub.period = 0x41;	/* one second: period unit 1 */
	g_tx_count = 0;
	ATF_REQUIRE_EQ(0, meshd_publish_raw(nd, nd->addr,
	    MESH_MODEL_GEN_ONOFF_SRV, 0, access, access_len));
	ATF_CHECK_EQ(1, g_tx_count);
	ATF_CHECK(model->next_pub_ms != 0);

	/* Virtual publication resolves the label UUID and uses the AppKey. */
	model->pub_is_va = 1;
	memset(model->pub_label, 0x5a, sizeof(model->pub_label));
	ATF_REQUIRE_EQ(0, mesh_virtual_addr(model->pub_label,
	    &model->pub.pub_addr));
	ATF_REQUIRE_EQ(0, meshd_publish_raw(nd, nd->addr,
	    MESH_MODEL_GEN_ONOFF_SRV, 0, access, access_len));
	ATF_CHECK_EQ(2, g_tx_count);
	model->pub_is_va = 0;
	model->pub.pub_addr = 0xc001;

	/* A failed retransmission is canceled instead of retried forever. */
	model->pub_access[0] = 0x7f;	/* invalid/reserved access opcode */
	model->pub_access_len = 1;
	model->retransmit_left = 2;
	model->next_retransmit_ms = 1000;
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 1000, &changed));
	ATF_CHECK_EQ(0, model->retransmit_left);

	/* A valid cached PDU with a missing AppKey fails the same way. */
	memcpy(model->pub_access, access, access_len);
	model->pub_access_len = access_len;
	model->pub.app_idx = 0x0ffe;
	model->retransmit_left = 1;
	model->next_retransmit_ms = 1100;
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 1100, &changed));
	ATF_CHECK_EQ(0, model->retransmit_left);
	model->pub.app_idx = cfg.appkey_index;

	/* Exercise disabled periods, every encoded unit, and catch-up. */
	model->pub.period = 0;
	model->next_pub_ms = 0;
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 1200, &changed));
	ATF_CHECK_EQ(0, model->next_pub_ms);
	model->pub.period = 0x81;	/* ten seconds */
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 1300, &changed));
	ATF_CHECK_EQ(11300, model->next_pub_ms);
	model->pub.period = 0xc1;	/* ten minutes */
	model->next_pub_ms = 1;
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 1800001, &changed));
	ATF_CHECK(model->next_pub_ms > 1800001);
}

ATF_TC_WITHOUT_HEAD(app_surface_receives_access_events);
ATF_TC_BODY(app_surface_receives_access_events, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_app_client *cl;
	struct meshd_app_event ev;
	struct mesh_cfg_model_id id;
	char reply[512];
	char *av[4];
	uint8_t pdu[64];
	size_t len;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	cl = &nd->app_clients[0];
	meshd_app_client_init(cl, 100);
	memset(&id, 0, sizeof(id));
	id.model_id = MESH_MODEL_GEN_ONOFF_SRV;

	/* Exercise every control-surface validation arm before registration. */
	av[0] = __DECONST(char *, "app-register-opcode");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 1, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "app-register");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 1, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "app-unregister");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 1, av, reply,
	    sizeof(reply)));
	av[1] = __DECONST(char *, "0x0001");
	av[2] = __DECONST(char *, "0x7ffe");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 3, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "app-events");
	av[1] = __DECONST(char *, "invalid");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)));
	av[1] = __DECONST(char *, "1");
	av[2] = __DECONST(char *, "extra");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 3, av, reply,
	    sizeof(reply)));
	av[1] = __DECONST(char *, "0");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 1, av, reply, 1));

	ATF_CHECK_EQ(0, meshd_app_client_event_count(cl));
	ATF_CHECK_EQ(0, meshd_app_client_event_pop(cl, &ev));
	ATF_REQUIRE_EQ(0, peer_onoff_pdu(0x0102, 0x0001, MESH_GEN_ON,
	    pdu, &len));
	ATF_REQUIRE_EQ(1, meshd_bearer_rx(nd, pdu, len));
	ATF_CHECK_EQ(0, meshd_app_client_event_count(cl));

	id.model_id = 0x1234;
	ATF_REQUIRE_EQ(0, meshd_app_client_register_opcode(nd, cl,
	    meshd_node_addr(nd), &id, MESH_OP_GEN_ONOFF_SET));
	ATF_REQUIRE_EQ(0, bind_model_to_primary_appkey(nd,
	    meshd_node_addr(nd), &id));
	ATF_REQUIRE_EQ(0, peer_onoff_pdu(0x0103, 0x0001, MESH_GEN_OFF,
	    pdu, &len));
	ATF_REQUIRE_EQ(1, meshd_bearer_rx(nd, pdu, len));
	ATF_REQUIRE_EQ(1, meshd_app_client_event_count(cl));
	ATF_REQUIRE_EQ(1, meshd_app_client_event_pop(cl, &ev));
	ATF_CHECK_EQ(0x1234, ev.id.model_id);
	ATF_CHECK_EQ(MESH_OP_GEN_ONOFF_SET, ev.opcode);
	ATF_REQUIRE_EQ(0, meshd_app_client_unregister_model(cl,
	    meshd_node_addr(nd), &id));

	av[0] = __DECONST(char *, "app-register");
	av[1] = __DECONST(char *, "0x1000");
	ATF_CHECK(meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)) <= 0);
	ATF_CHECK_MSG(strstr(reply, "app session required") != NULL, "%s",
	    reply);

	av[0] = __DECONST(char *, "app-events");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "app session required") != NULL, "%s",
	    reply);

	av[0] = __DECONST(char *, "app-unregister");
	av[1] = __DECONST(char *, "0x1000");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "app session required") != NULL, "%s",
	    reply);

	id.model_id = MESH_MODEL_GEN_ONOFF_SRV;
	ATF_REQUIRE_EQ(0, meshd_app_client_register_model(nd, cl,
	    meshd_node_addr(nd), &id));
	ATF_REQUIRE_EQ(0, bind_model_to_primary_appkey(nd,
	    meshd_node_addr(nd), &id));
	ATF_CHECK(meshd_db_has_model(nd, MESH_MODEL_GEN_ONOFF_SRV));
	ATF_REQUIRE_EQ(0, peer_onoff_pdu(0x0104, 0x0001, MESH_GEN_OFF,
	    pdu, &len));
	ATF_REQUIRE_EQ(1, meshd_bearer_rx(nd, pdu, len));
	ATF_REQUIRE_EQ(1, meshd_app_client_event_count(cl));
	ATF_REQUIRE_EQ(1, meshd_app_client_event_pop(cl, &ev));
	ATF_CHECK_EQ(0x0104, ev.src);
	ATF_CHECK_EQ(0x0001, ev.dst);
	ATF_CHECK_EQ(meshd_node_addr(nd), ev.elem_addr);
	ATF_CHECK_EQ(MESH_MODEL_GEN_ONOFF_SRV, ev.id.model_id);
	ATF_CHECK_EQ(MESH_OP_GEN_ONOFF_SET, ev.opcode);
	ATF_CHECK(ev.params_len > 0);
	ATF_CHECK_EQ(0, meshd_app_client_event_count(cl));
	ATF_REQUIRE_EQ(0, meshd_app_client_unregister_model(cl,
	    meshd_node_addr(nd), &id));

	av[0] = __DECONST(char *, "app-register");
	av[1] = __DECONST(char *, "0x0001");
	av[2] = __DECONST(char *, "0x1000");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, cl, 3, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "OK app-register") != NULL, "%s", reply);
	ATF_CHECK(meshd_db_has_model(nd, MESH_MODEL_GEN_ONOFF_SRV));
	av[1] = __DECONST(char *, "0x7fff");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 3, av, reply,
	    sizeof(reply)));
	av[1] = __DECONST(char *, "0x0001");

	ATF_REQUIRE_EQ(0, peer_onoff_pdu(0x0006, 0x0001, MESH_GEN_ON,
	    pdu, &len));
	ATF_REQUIRE_EQ(1, meshd_bearer_rx(nd, pdu, len));
	av[0] = __DECONST(char *, "app-events");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 1, av, reply, 32));
	ATF_REQUIRE_EQ(0, peer_onoff_pdu(0x0005, 0x0001, MESH_GEN_ON,
	    pdu, &len));
	ATF_REQUIRE_EQ(1, meshd_bearer_rx(nd, pdu, len));
	av[0] = __DECONST(char *, "app-events");
	av[1] = __DECONST(char *, "1");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "OK events=1") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "model=0x1000") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "src=0x0005") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "opcode=0x008202") != NULL, "%s", reply);

	av[0] = __DECONST(char *, "app-unregister");
	av[1] = __DECONST(char *, "0x0001");
	av[2] = __DECONST(char *, "0x1000");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, cl, 3, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "OK app-unregister") != NULL, "%s", reply);
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 3, av, reply,
	    sizeof(reply)));
	meshd_app_client_fini(cl);
}

ATF_TC_WITHOUT_HEAD(app_opcode_command_and_ownership);
ATF_TC_BODY(app_opcode_command_and_ownership, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_app_client *cl;
	struct meshd_app_event ev;
	struct mesh_cfg_model_id id = { .model_id = 0x1234 };
	char reply[512];
	char *av[12];
	uint8_t net[64], param = 0x5a;
	size_t len;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Network-manager verbs must fail cleanly before create-network. */
	av[0] = __DECONST(char *, "key-refresh");
	av[1] = __DECONST(char *, "network-status");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	av[1] = __DECONST(char *, "network");
	av[2] = __DECONST(char *, "ffeeddccbbaa99887766554433221100");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "provision-scan");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "provision");
	av[1] = __DECONST(char *, "00112233445566778899aabbccddeeff");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));

	/* Signed parsers reject empty and out-of-range values. */
	av[0] = __DECONST(char *, "level");
	av[1] = __DECONST(char *, "1"); av[2] = __DECONST(char *, "");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "location-global");
	av[1] = __DECONST(char *, "2147483648");
	av[2] = __DECONST(char *, "0"); av[3] = __DECONST(char *, "0");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 4, av, reply,
	    sizeof(reply)));
	cl = &nd->app_clients[0];
	meshd_app_client_init(cl, 103);
	av[0] = __DECONST(char *, "app-register-opcode");
	av[1] = __DECONST(char *, "0x0001");
	av[2] = __DECONST(char *, "0x1234");
	av[3] = __DECONST(char *, "0xbf01");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl, 4, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "OK app-register-opcode") != NULL,
	    "%s", reply);
	ATF_REQUIRE_EQ(0, bind_model_to_primary_appkey(nd, nd->addr, &id));
	ATF_REQUIRE_EQ(0, peer_access_pdu_seq(0x0110, nd->addr, 0, 0xbf01,
	    &param, 1, net, &len));
	ATF_REQUIRE_EQ(1, meshd_bearer_rx(nd, net, len));
	ATF_REQUIRE_EQ(1, meshd_app_client_event_pop(cl, &ev));
	ATF_CHECK_EQ(0x1234, ev.id.model_id);
	ATF_CHECK_EQ(0xbf01, ev.opcode);
	ATF_CHECK_EQ(1, ev.params_len);
	ATF_CHECK_EQ(param, ev.params[0]);

	/* Reserved and model/company-mismatched opcodes are rejected. */
	av[3] = __DECONST(char *, "0x7f");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 4, av, reply,
	    sizeof(reply)));
	av[2] = __DECONST(char *, "0x5678");
	av[3] = __DECONST(char *, "0xc11234");
	av[4] = __DECONST(char *, "0x1234");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl, 5, av, reply,
	    sizeof(reply)));
	av[4] = __DECONST(char *, "0x4321");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 5, av, reply,
	    sizeof(reply)));
	meshd_app_client_fini(cl);
}

ATF_TC_WITHOUT_HEAD(app_client_queues_are_per_connection);
ATF_TC_BODY(app_client_queues_are_per_connection, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_app_client *c1, *c2;
	struct meshd_app_event ev;
	struct mesh_cfg_model_id onoff = {
	    .model_id = MESH_MODEL_GEN_ONOFF_SRV
	};
	char reply[512];
	char *av[4];
	uint8_t pdu[64];
	size_t len;

#ifdef MESHD_WITH_PROBE_TAP
	probe_tap_reset();
#endif
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	c1 = &nd->app_clients[0];
	c2 = &nd->app_clients[1];
	meshd_app_client_init(c1, 101);
	meshd_app_client_init(c2, 102);

	av[0] = __DECONST(char *, "app-register");
	av[1] = __DECONST(char *, "0x0001");
	av[2] = __DECONST(char *, "0x1000");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, c1, 3, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "OK app-register") != NULL, "%s", reply);

	av[2] = __DECONST(char *, "0x1234");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, c2, 3, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "OK app-register") != NULL, "%s", reply);
	ATF_REQUIRE_EQ(0, bind_model_to_primary_appkey(nd, nd->addr, &onoff));

	ATF_REQUIRE_EQ(0, peer_onoff_pdu(0x0006, 0x0001, MESH_GEN_ON,
	    pdu, &len));
	ATF_REQUIRE_EQ(1, meshd_bearer_rx(nd, pdu, len));

	ATF_CHECK_EQ(0, meshd_app_client_event_count(c2));
	ATF_REQUIRE_EQ(1, meshd_app_client_event_count(c1));
	ATF_CHECK_EQ(0, meshd_app_client_event_count(c2));
	ATF_REQUIRE_EQ(1, meshd_app_client_event_pop(c1, &ev));
	ATF_CHECK_EQ(101, c1->fd);
	ATF_CHECK_EQ(0x0006, ev.src);
	ATF_CHECK_EQ(MESH_MODEL_GEN_ONOFF_SRV, ev.id.model_id);
	ATF_CHECK_EQ(MESH_OP_GEN_ONOFF_SET, ev.opcode);

	ATF_REQUIRE_EQ(0, peer_onoff_pdu(0x0007, 0x0001, MESH_GEN_OFF,
	    pdu, &len));
	ATF_REQUIRE_EQ(1, meshd_bearer_rx(nd, pdu, len));
	av[0] = __DECONST(char *, "app-events");
	av[1] = __DECONST(char *, "1");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, c1, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "OK events=1") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "src=0x0007") != NULL, "%s", reply);
	ATF_CHECK_EQ(0, meshd_app_client_event_count(c1));

#ifdef MESHD_WITH_PROBE_TAP
	ATF_CHECK(probe_tap_find("meshd:app:connect", 0) <
	    probe_tap_count());
	ATF_CHECK(probe_tap_find("meshd:app:register", 0) <
	    probe_tap_count());
	ATF_CHECK(probe_tap_find("meshd:app:event:queue", 0) <
	    probe_tap_count());
#endif
	meshd_app_client_fini(c1);
	meshd_app_client_fini(c2);
#ifdef MESHD_WITH_PROBE_TAP
	ATF_CHECK(probe_tap_find("meshd:app:disconnect", 0) <
	    probe_tap_count());
#endif
}

ATF_TC_WITHOUT_HEAD(app_client_multi_connection_stress);
ATF_TC_BODY(app_client_multi_connection_stress, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_model_id id = {
	    .model_id = MESH_MODEL_GEN_ONOFF_SRV
	};
	struct meshd_app_event ev;
	uint8_t pdu[64];
	size_t i, j, len;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	for (i = 0; i < MESHD_MAX_APP_CLIENTS; i++) {
		meshd_app_client_init(&nd->app_clients[i], 200 + (int)i);
		ATF_REQUIRE_EQ(0, meshd_app_client_register_model(nd,
		    &nd->app_clients[i], nd->addr, &id));
	}
	ATF_REQUIRE_EQ(0, bind_model_to_primary_appkey(nd, nd->addr, &id));
	for (j = 0; j < MESHD_APP_EVENT_MAX + 8; j++) {
		ATF_REQUIRE_EQ(0, peer_onoff_pdu_seq(0x0100, nd->addr,
		    (uint8_t)(j & 1), (uint32_t)j, pdu, &len));
		ATF_REQUIRE_EQ(1, meshd_bearer_rx(nd, pdu, len));
	}
	for (i = 0; i < MESHD_MAX_APP_CLIENTS; i++) {
		struct meshd_app_client *client = &nd->app_clients[i];

		ATF_CHECK_EQ_MSG(MESHD_APP_EVENT_MAX,
		    meshd_app_client_event_count(client),
		    "client %zu queued %zu events", i,
		    meshd_app_client_event_count(client));
		ATF_CHECK_EQ_MSG(8, meshd_app_client_event_dropped(client),
		    "client %zu dropped %u events", i,
		    meshd_app_client_event_dropped(client));
		for (j = 0; j < MESHD_APP_EVENT_MAX; j++)
			ATF_REQUIRE_EQ(1, meshd_app_client_event_pop(client, &ev));
		ATF_CHECK_EQ(0, meshd_app_client_event_count(client));
		meshd_app_client_fini(client);
	}
}

ATF_TC_WITHOUT_HEAD(bearer_drop_without_sink);
ATF_TC_BODY(bearer_drop_without_sink, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t pdu[64];
	size_t len;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	/* No bearer attached: retain replies until a bearer can accept them. */
	ATF_REQUIRE_EQ(0, peer_onoff_pdu(0x0102, 0x0001, MESH_GEN_ON, pdu, &len));
	ATF_CHECK_EQ(1, meshd_bearer_rx(nd, pdu, len));
	ATF_CHECK_EQ(0, nd->tx_frames);
	ATF_CHECK(nd->sim.n_tx > 0);

	/* A NULL-tx bearer also retains queued PDUs. */
	struct meshd_bearer nulltx = { .tx = NULL, .arg = NULL };
	meshd_set_bearer(nd, &nulltx);
	meshd_set_bearer(NULL, &nulltx);		/* no-op guard */
	ATF_REQUIRE_EQ(0, peer_onoff_pdu(0x0104, 0x0001, MESH_GEN_OFF, pdu, &len));
	ATF_CHECK_EQ(1, meshd_bearer_rx(nd, pdu, len));
	ATF_CHECK(nd->sim.n_tx > 0);

	/* Attaching a working bearer drains the retained queue exactly once. */
	{
		struct meshd_bearer bearer = { .tx = capture_tx, .arg = NULL };

		g_tx_count = 0;
		g_tx_fail = 0;
		meshd_set_bearer(nd, &bearer);
		meshd_drain_tx(nd);
		ATF_CHECK(g_tx_count > 0);
		ATF_CHECK_EQ(0, nd->sim.n_tx);
	}
}

/* ================================================================
 * Secure Network beacon pump: the tick loop emits a beacon carrying the Key
 * Refresh Flag for the current phase, secured with the phase-selected key
 * (MshPRT_v1.1 Sections 3.10.3 and 3.11.4).  A receiving node advances its phase
 * from that flag (meshd_beacon_rx).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(beacon_pump_kr_flag);
ATF_TC_BODY(beacon_pump_kr_flag, tc)
{
	static const uint8_t newkey[16] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0
	};
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .tx = capture_tx, .arg = NULL };
	struct mesh_secure_beacon sb;
	int changed;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);
	nd->cfg.beacon = 1;			/* Secure Network Beacon enabled */

	/* Phase 0: the beacon authenticates under the current key, flag clear. */
	g_tx_count = 0;
	g_tx_fail = 0;
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 100000, &changed));
	ATF_CHECK(g_tx_count > 0);
	/* The beacon pump tags its frames with the beacon (0x2B) class. */
	ATF_CHECK_EQ(MESHD_PDU_BEACON, g_last_tx_cls);
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_parse(g_netkey, g_last_tx,
	    g_last_tx_len, &sb));
	ATF_CHECK_EQ(0, sb.key_refresh);

	/* Advance the refresh to Phase 2. */
	ATF_REQUIRE_EQ(0, meshd_kr_begin(nd, newkey));
	ATF_REQUIRE_EQ(0, meshd_kr_advance(nd));

	/* Next cadence tick: the beacon is now secured with the NEW key, flag SET. */
	g_tx_count = 0;
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd,
	    (100 + MESHD_BEACON_INTERVAL) * 1000ULL,
	    &changed));
	ATF_CHECK(g_tx_count > 0);
	ATF_CHECK_MSG(mesh_secure_beacon_parse(g_netkey, g_last_tx,
	    g_last_tx_len, &sb) != 0,
	    "Phase 2 beacon no longer authenticates under the old key");
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_parse(newkey, g_last_tx,
	    g_last_tx_len, &sb));
	ATF_CHECK_EQ_MSG(1, sb.key_refresh,
	    "beacon Key Refresh Flag matches Phase 2");
}

ATF_TC_WITHOUT_HEAD(beacon_pump_all_subnets);
ATF_TC_BODY(beacon_pump_all_subnets, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .tx = capture_tx };
	struct meshd_netkey_entry *secondary = &nd->db.netkeys[1];
	struct mesh_secure_beacon sb;
	int changed;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);
	memset(secondary, 0, sizeof(*secondary));
	secondary->valid = 1;
	secondary->net_idx = 1;
	memcpy(secondary->key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(nd->self, 1, g_appkey));
	nd->cfg.beacon = 1;
	g_tx_count = 0;
	g_tx_fail = 0;
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 100000, &changed));
	ATF_CHECK_EQ_MSG(2, g_tx_count,
	    "one Secure Network beacon was emitted per configured subnet");
	ATF_CHECK_EQ(MESHD_PDU_BEACON, g_last_tx_cls);
	ATF_CHECK(mesh_secure_beacon_parse(g_netkey, g_last_tx,
	    g_last_tx_len, &sb) != 0);
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_parse(g_appkey, g_last_tx,
	    g_last_tx_len, &sb));
}

ATF_TC_WITHOUT_HEAD(beacon_receive_matrix);
ATF_TC_BODY(beacon_receive_matrix, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, sender);
	MESH_HEAP(struct meshd_node, receiver);
	struct meshd_bearer bearer = { .tx = capture_tx };
	int changed;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(sender, &cfg));
	ATF_REQUIRE_EQ(0, meshd_node_init(receiver, &cfg));
	meshd_set_bearer(sender, &bearer);
	sender->cfg.beacon = 1;
	g_tx_count = 0;
	ATF_REQUIRE_EQ(0, meshd_node_tick(sender, 100000, &changed));
	ATF_REQUIRE(g_tx_count > 0);
	ATF_CHECK_EQ(-1, meshd_beacon_rx(NULL, g_last_tx, g_last_tx_len));
	ATF_CHECK_EQ(-1, meshd_beacon_rx(receiver, NULL, g_last_tx_len));
	ATF_CHECK_EQ(0, meshd_beacon_rx(receiver, g_last_tx, 1));
	ATF_CHECK_EQ(1, meshd_beacon_rx(receiver, g_last_tx, g_last_tx_len));
	ATF_CHECK_EQ(0, receiver->db.netkeys[0].kr_phase);
	receiver->db.netkeys[0].has_new_key = 1;
	memset(receiver->db.netkeys[0].new_key, 0xa5,
	    sizeof(receiver->db.netkeys[0].new_key));
	ATF_CHECK_EQ(1, meshd_beacon_rx(receiver, g_last_tx, g_last_tx_len));
	ATF_CHECK_EQ(0, receiver->db.netkeys[0].has_new_key);
	ATF_CHECK_EQ(0, memcmp(receiver->db.netkeys[0].key, g_netkey, 16));

	/* A beacon authenticated for an unknown subnet is ignored. */
	g_last_tx[1] ^= 0x80;
	ATF_CHECK_EQ(0, meshd_beacon_rx(receiver, g_last_tx, g_last_tx_len));
}

/* ================================================================
 * Originating messages.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(send_onoff_level);
ATF_TC_BODY(send_onoff_level, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_app_client app_client;
	struct meshd_app_event event;
	struct mesh_gen_battery_status battery;
	struct mesh_gen_location_global global;
	struct mesh_gen_location_local local;
	uint8_t access[MESH_ACCESS_PAYLOAD_MAX];
	size_t access_len;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	ATF_CHECK_EQ(-1, meshd_send_onoff(NULL, 0x0002, 1, 1));
	ATF_CHECK_EQ(-1, meshd_send_onoff(nd, 0x0000, 1, 1));
	ATF_CHECK_EQ(0, meshd_send_onoff(nd, 0x0002, 1, 1));
	ATF_CHECK_EQ(0, meshd_send_onoff(nd, 0x0002, 0, 0));	/* unack */
	ATF_CHECK(meshd_node_seq(nd) > 0);

	ATF_CHECK_EQ(-1, meshd_send_level(NULL, 0x0002, 1, 1));
	ATF_CHECK_EQ(-1, meshd_send_level(nd, 0x0000, 1, 1));
	ATF_CHECK_EQ(0, meshd_send_level(nd, 0x0002, 100, 1));
	ATF_CHECK_EQ(0, meshd_send_level(nd, 0x0002, -100, 0));	/* unack */

	/* Exercise every Generic Power and transition originating wrapper. */
	ATF_CHECK_EQ(-1, meshd_send_power_onoff(NULL, 2, 0, 1));
	ATF_CHECK_EQ(-1, meshd_send_power_onoff(nd, 0, 0, 1));
	ATF_CHECK_EQ(-1, meshd_send_power_onoff(nd, 2, 3, 1));
	ATF_CHECK_EQ(0, meshd_send_power_onoff(nd, 2, 2, 1));
	ATF_CHECK_EQ(0, meshd_send_power_onoff(nd, 2, 0, 0));
	ATF_CHECK_EQ(-1, meshd_send_dtt(NULL, 2, 0, 1));
	ATF_CHECK_EQ(-1, meshd_send_dtt(nd, 0, 0, 1));
	ATF_CHECK_EQ(-1, meshd_send_dtt(nd, 2, 0x3f, 1));
	ATF_CHECK_EQ(0, meshd_send_dtt(nd, 2, 0x41, 1));
	ATF_CHECK_EQ(0, meshd_send_dtt(nd, 2, 0, 0));
	ATF_CHECK_EQ(-1, meshd_send_power_level(NULL, 2, 1, 1));
	ATF_CHECK_EQ(-1, meshd_send_power_level(nd, 0, 1, 1));
	ATF_CHECK_EQ(0, meshd_send_power_level(nd, 2, 0x1234, 1));
	ATF_CHECK_EQ(0, meshd_send_power_level(nd, 2, 0x5678, 0));
	ATF_CHECK_EQ(-1, meshd_send_power_default(NULL, 2, 1, 1));
	ATF_CHECK_EQ(-1, meshd_send_power_default(nd, 0, 1, 1));
	ATF_CHECK_EQ(0, meshd_send_power_default(nd, 2, 0x1234, 1));
	ATF_CHECK_EQ(0, meshd_send_power_default(nd, 2, 0x5678, 0));
	ATF_CHECK_EQ(-1, meshd_send_power_range(NULL, 2, 1, 2, 1));
	ATF_CHECK_EQ(-1, meshd_send_power_range(nd, 0, 1, 2, 1));
	ATF_CHECK_EQ(-1, meshd_send_power_range(nd, 2, 0, 2, 1));
	ATF_CHECK_EQ(-1, meshd_send_power_range(nd, 2, 2, 0, 1));
	ATF_CHECK_EQ(-1, meshd_send_power_range(nd, 2, 3, 2, 1));
	ATF_CHECK_EQ(0, meshd_send_power_range(nd, 2, 1, 2, 1));
	ATF_CHECK_EQ(0, meshd_send_power_range(nd, 2, 2, 3, 0));

	/* Raw access validation and successful parsed access origination. */
	ATF_CHECK_EQ(-1, meshd_send_access_raw(NULL, 2, access, 1));
	ATF_CHECK_EQ(-1, meshd_send_access_raw(nd, 0, access, 1));
	ATF_CHECK_EQ(-1, meshd_send_access_raw(nd, 2, NULL, 1));
	ATF_CHECK_EQ(-1, meshd_send_access_raw(nd, 2, access, 0));
	access[0] = 0x7f;
	ATF_CHECK_EQ(-1, meshd_send_access_raw(nd, 2, access, 1));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_GEN_ONOFF_GET, NULL, 0,
	    access, &access_len));
	ATF_CHECK_EQ(0, meshd_send_access_raw(nd, 2, access, access_len));
	ATF_CHECK_EQ(-1, meshd_send_devkey_raw(nd, 2, 0, 0, access,
	    access_len));
	ATF_CHECK_EQ(-1, meshd_publish_raw(NULL, 1, MESH_MODEL_GEN_ONOFF_SRV, 0,
	    access, access_len));
	ATF_CHECK_EQ(-1, meshd_publish_raw(nd, 1, MESH_MODEL_GEN_ONOFF_SRV, 0,
	    NULL, access_len));

	/* Application state setters and client queue null/inactive contracts. */
	memset(&battery, 0, sizeof(battery));
	/* Mesh Model 1.1.1 Tables 3.12-3.15: all fields unknown. */
	battery.flags = 0xff;
	memset(&global, 0, sizeof(global));
	memset(&local, 0, sizeof(local));
	ATF_CHECK_EQ(-1, meshd_set_battery(NULL, &battery));
	ATF_CHECK_EQ(-1, meshd_set_battery(nd, NULL));
	ATF_CHECK_EQ(0, meshd_set_battery(nd, &battery));
	ATF_CHECK_EQ(-1, meshd_set_location_global(NULL, &global));
	ATF_CHECK_EQ(-1, meshd_set_location_global(nd, NULL));
	ATF_CHECK_EQ(0, meshd_set_location_global(nd, &global));
	ATF_CHECK_EQ(-1, meshd_set_location_local(NULL, &local));
	ATF_CHECK_EQ(-1, meshd_set_location_local(nd, NULL));
	ATF_CHECK_EQ(0, meshd_set_location_local(nd, &local));
	meshd_app_client_init(NULL, 1);
	memset(&app_client, 0, sizeof(app_client));
	ATF_CHECK_EQ(0, meshd_app_client_event_count(NULL));
	ATF_CHECK_EQ(0, meshd_app_client_event_count(&app_client));
	ATF_CHECK_EQ(0, meshd_app_client_event_dropped(NULL));
	ATF_CHECK_EQ(0, meshd_app_client_event_pop(NULL, &event));
	ATF_CHECK_EQ(0, meshd_app_client_event_pop(&app_client, &event));
	meshd_app_client_fini(NULL);
	meshd_node_fini(NULL);

	/* Unprovisioned node refuses to originate. */
	nd->provisioned = 0;
	ATF_CHECK_EQ(-1, meshd_send_onoff(nd, 0x0002, 1, 1));
	ATF_CHECK_EQ(-1, meshd_send_level(nd, 0x0002, 1, 1));
}

/* ================================================================
 * Provisioning.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(provision_local);
ATF_TC_BODY(provision_local, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_prov_data pd;

	base_config(&cfg);
	cfg.have_netkey = 0;			/* start unprovisioned */
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	ATF_CHECK_EQ(0, nd->provisioned);

	memset(&pd, 0, sizeof(pd));
	ATF_CHECK_EQ(-1, meshd_provision_local(NULL, &pd));
	ATF_CHECK_EQ(-1, meshd_provision_local(nd, NULL));

	memcpy(pd.netkey, g_netkey, 16);
	pd.iv_index = 3;
	pd.unicast_addr = 0x0000;		/* invalid */
	ATF_CHECK_EQ(-1, meshd_provision_local(nd, &pd));

	pd.unicast_addr = 0x0005;
	ATF_CHECK_EQ(0, meshd_provision_local(nd, &pd));
	ATF_CHECK_EQ(1, nd->provisioned);
	ATF_CHECK_EQ(0x0005, meshd_node_addr(nd));
	ATF_CHECK_EQ(3, meshd_node_iv(nd));
}

ATF_TC_WITHOUT_HEAD(provision_recv_data);
ATF_TC_BODY(provision_recv_data, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_prov_data pd;
	uint8_t skey[16], snonce[13], data[25], enc[25], mic[8];
	size_t i;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	for (i = 0; i < sizeof(skey); i++)
		skey[i] = (uint8_t)(i + 1);
	for (i = 0; i < sizeof(snonce); i++)
		snonce[i] = (uint8_t)(0x20 + i);

	memset(&pd, 0, sizeof(pd));
	memcpy(pd.netkey, g_netkey, 16);
	pd.netkey_index = 0;
	pd.flags = 0;
	pd.iv_index = 7;
	pd.unicast_addr = 0x0009;
	mesh_prov_data_pack(&pd, data);
	ATF_REQUIRE_EQ(0, mesh_prov_data_encrypt(skey, snonce, data, enc, mic));

	/* NULL arms. */
	ATF_CHECK_EQ(-1, meshd_provision_recv_data(NULL, skey, snonce, enc, mic));
	ATF_CHECK_EQ(-1, meshd_provision_recv_data(nd, NULL, snonce, enc, mic));
	ATF_CHECK_EQ(-1, meshd_provision_recv_data(nd, skey, NULL, enc, mic));
	ATF_CHECK_EQ(-1, meshd_provision_recv_data(nd, skey, snonce, NULL, mic));
	ATF_CHECK_EQ(-1, meshd_provision_recv_data(nd, skey, snonce, enc, NULL));

	/* Corrupt MIC -> decrypt failure. */
	{
		uint8_t badmic[8];
		memcpy(badmic, mic, 8);
		badmic[0] ^= 0xff;
		ATF_CHECK_EQ(-1, meshd_provision_recv_data(nd, skey, snonce,
		    enc, badmic));
	}

	/* Success -> installed. */
	ATF_CHECK_EQ(0, meshd_provision_recv_data(nd, skey, snonce, enc, mic));
	ATF_CHECK_EQ(0x0009, meshd_node_addr(nd));
	ATF_CHECK_EQ(7, meshd_node_iv(nd));
}

/* ================================================================
 * Foundation-model message processing.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(foundation_recv);
ATF_TC_BODY(foundation_recv, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t msg[64], reply[512];
	size_t mlen, rlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* NULL / malformed arms. */
	ATF_CHECK_EQ(-1, meshd_foundation_recv(NULL, msg, 1, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, NULL, 1, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, 0, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, 1, NULL,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, 1, reply,
	    sizeof(reply), NULL));
	msg[0] = 0x7f;				/* reserved 1-octet opcode */
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, 1, reply,
	    sizeof(reply), &rlen));

	/* Config Default TTL Get -> status. */
	ATF_REQUIRE_EQ(0, mesh_cfg_empty_build(MESH_CFG_OP_DEFAULT_TTL_GET,
	    msg, &mlen));
	ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK(rlen > 0);

	/* Config Default TTL Set (valid) -> status, state updated. */
	ATF_REQUIRE_EQ(0, mesh_cfg_u8_state_build(MESH_CFG_OP_DEFAULT_TTL_SET,
	    10, msg, &mlen));
	ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(10, nd->cfg.default_ttl);

	/* Config Default TTL Set (invalid TTL == 1) -> error. */
	ATF_REQUIRE_EQ(0, mesh_cfg_u8_state_build(MESH_CFG_OP_DEFAULT_TTL_SET,
	    1, msg, &mlen));
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));

	/* Config Composition Data Get page 0 -> status. */
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_get_build(0, msg, &mlen));
	ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK(rlen > 0);

	/* Config Node Reset -> status, node unprovisioned. */
	ATF_REQUIRE_EQ(0, mesh_cfg_node_reset_build(msg, &mlen));
	ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(0, nd->provisioned);

	/* Health Attention Get / Set. */
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_build(MESH_HLT_OP_ATTENTION_GET,
	    0, msg, &mlen));
	ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_build(MESH_HLT_OP_ATTENTION_SET,
	    12, msg, &mlen));
	ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(12, nd->health.attention);

	/* Health Fault Get (with a registered fault). */
	ATF_REQUIRE_EQ(0, mesh_hlt_server_add_fault(&nd->health, 0x11));
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_get_build(nd->health.company_id,
	    msg, &mlen));
	ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK(rlen > 0);

	/* An unhandled opcode (Generic OnOff Get) -> error. */
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_get(msg, &mlen));
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
}

/* A too-small reply buffer must be rejected, not overrun. */
ATF_TC_WITHOUT_HEAD(foundation_reply_overflow);
ATF_TC_BODY(foundation_reply_overflow, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t msg[64], tiny[2];
	size_t mlen, rlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Composition Data Status is far larger than 2 octets. */
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_get_build(0, msg, &mlen));
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, tiny,
	    sizeof(tiny), &rlen));
	/* TTL status (3 octets) also overflows a 2-octet buffer. */
	ATF_REQUIRE_EQ(0, mesh_cfg_empty_build(MESH_CFG_OP_DEFAULT_TTL_GET,
	    msg, &mlen));
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen, tiny,
	    sizeof(tiny), &rlen));
}

ATF_TC_WITHOUT_HEAD(foundation_feature_handler_matrix);
ATF_TC_BODY(foundation_feature_handler_matrix, tc)
{
	static const uint32_t empty_gets[] = {
		MESH_CFG_OP_BEACON_GET, MESH_CFG_OP_FRIEND_GET,
		MESH_CFG_OP_GATT_PROXY_GET, MESH_CFG_OP_RELAY_GET,
		MESH_CFG_OP_NET_TRANSMIT_GET, MESH_CFG_OP_NETKEY_GET,
		MESH_HLT_OP_PERIOD_GET
	};
	static const struct {
		uint32_t opcode;
		uint8_t params[2];
		size_t len;
	} sets[] = {
		{ MESH_CFG_OP_BEACON_SET, { 1 }, 1 },
		{ MESH_CFG_OP_FRIEND_SET, { 1 }, 1 },
		{ MESH_CFG_OP_GATT_PROXY_SET, { 1 }, 1 },
		{ MESH_CFG_OP_RELAY_SET, { 1, 0x09 }, 2 },
		{ MESH_CFG_OP_NET_TRANSMIT_SET, { 0x11 }, 1 },
		{ MESH_HLT_OP_PERIOD_SET, { 3 }, 1 },
	};
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t msg[64], reply[512], index[2];
	size_t mlen, rlen;

	base_config(&cfg);
	cfg.features = MESH_CFG_FEATURE_RELAY | MESH_CFG_FEATURE_PROXY |
	    MESH_CFG_FEATURE_FRIEND;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	for (size_t i = 0; i < nitems(empty_gets); i++) {
		ATF_REQUIRE_EQ(0, mesh_access_pdu_build(empty_gets[i], NULL, 0,
		    msg, &mlen));
		ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
		    sizeof(reply), &rlen));
		ATF_CHECK(rlen > 0);
	}
	for (size_t i = 0; i < nitems(sets); i++) {
		ATF_REQUIRE_EQ(0, mesh_access_pdu_build(sets[i].opcode,
		    sets[i].params, sets[i].len, msg, &mlen));
		ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
		    sizeof(reply), &rlen));
	}

	/* Subnet-indexed getters exercise their packed 12-bit validation. */
	index[0] = cfg.netkey_index & 0xff;
	index[1] = cfg.netkey_index >> 8;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_CFG_OP_APPKEY_GET, index,
	    sizeof(index), msg, &mlen));
	ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    MESH_CFG_OP_KEY_REFRESH_PHASE_GET, index, sizeof(index), msg,
	    &mlen));
	ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_CFG_OP_NODE_IDENTITY_GET,
	    index, sizeof(index), msg, &mlen));
	ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	meshd_node_fini(nd);
}

ATF_TC_WITHOUT_HEAD(foundation_key_lifecycle);
ATF_TC_BODY(foundation_key_lifecycle, tc)
{
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_netkey nk;
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t msg[64], reply[64], status;
	uint16_t net_idx, app_idx;
	size_t mlen, rlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Add a secondary subnet, then verify idempotence and conflict status. */
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 1;
	memset(nk.key, 0x31, sizeof(nk.key));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD,
	    &nk, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(reply, rlen, &status,
	    &net_idx));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(1, net_idx);
	ATF_CHECK_EQ(0, mesh_sim_subnet_kr_phase(nd->self, 1));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	nk.key[0] ^= 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD,
	    &nk, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(reply, rlen, &status,
	    &net_idx));
	ATF_CHECK_EQ(MESH_CFG_KEY_INDEX_ALREADY_STORED, status);

	/* Update enters KR phase 1; replaying the same update is harmless. */
	memset(nk.key, 0x42, sizeof(nk.key));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(1, mesh_sim_subnet_kr_phase(nd->self, 1));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	nk.key[0] ^= 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(reply, rlen, &status,
	    &net_idx));
	ATF_CHECK_EQ(MESH_CFG_CANNOT_UPDATE, status);
	nk.net_idx = 9;
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(reply, rlen, &status,
	    &net_idx));
	ATF_CHECK_EQ(MESH_CFG_INVALID_NETKEY_INDEX, status);

	/* Add/update/delete an AppKey bound to the secondary subnet. */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 1;
	ak.app_idx = 2;
	memset(ak.key, 0x53, sizeof(ak.key));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD,
	    &ak, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_parse(reply, rlen, &status,
	    &net_idx, &app_idx));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ak.key[0] ^= 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD,
	    &ak, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_parse(reply, rlen, &status,
	    &net_idx, &app_idx));
	ATF_CHECK_EQ(MESH_CFG_KEY_INDEX_ALREADY_STORED, status);
	memset(ak.key, 0x64, sizeof(ak.key));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_UPDATE,
	    &ak, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ak.net_idx = 9;
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD,
	    &ak, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_parse(reply, rlen, &status,
	    &net_idx, &app_idx));
	ATF_CHECK_EQ(MESH_CFG_INVALID_NETKEY_INDEX, status);

	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_delete_build(1, 2, msg, &mlen));
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen - 1, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_delete_build(1, msg, &mlen));
	ATF_CHECK_EQ(-1, meshd_foundation_recv(nd, msg, mlen - 1, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(-1, mesh_sim_subnet_kr_phase(nd->self, 1));
	/* Deleting a missing key is specified to succeed idempotently. */
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	meshd_node_fini(nd);
}

/* Composition Data on a fully featured node, and the drain skip-invalid arm. */
ATF_TC_WITHOUT_HEAD(featured_comp_and_drain);
ATF_TC_BODY(featured_comp_and_drain, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t msg[64], reply[512];
	size_t mlen, rlen;

	base_config(&cfg);
	cfg.features = MESH_CFG_FEATURE_RELAY | MESH_CFG_FEATURE_PROXY |
	    MESH_CFG_FEATURE_FRIEND;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Composition omits Friend until its FSM is connected to the bearer. */
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_get_build(0, msg, &mlen));
	ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));

	/* Seed an invalid transmit slot: the drain loop must skip it. */
	nd->sim.n_tx = 1;
	nd->sim.tx[0].valid = 0;
	ATF_CHECK_EQ(0, meshd_send_onoff(nd, 0x0002, 1, 0));
}

ATF_TC_WITHOUT_HEAD(composition_registers_all_app_model_families);
ATF_TC_BODY(composition_registers_all_app_model_families, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_comp_status st;
	struct mesh_cfg_comp_page0 comp;
	uint8_t msg[64], reply[512];
	size_t mlen, rlen, i;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	ATF_REQUIRE_EQ(nitems(meshd_expected_sig_models) + 6, nd->db.n_models);
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_get_build(0, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_status_parse(reply, rlen, &st));
	ATF_REQUIRE_EQ(0, mesh_cfg_comp_page0_decode(st.data, st.data_len,
	    &comp));
	ATF_REQUIRE_EQ(4, comp.n_elements);
	ATF_REQUIRE_EQ(nitems(meshd_expected_sig_models),
	    comp.elements[0].n_sig);

	for (i = 0; i < nitems(meshd_expected_sig_models); i++) {
		uint16_t model_id = meshd_expected_sig_models[i];

		ATF_CHECK_MSG(comp_has_model(&comp, model_id),
		    "model 0x%04x missing from Composition Data", model_id);
		ATF_CHECK_MSG(meshd_db_has_model(nd, model_id),
		    "model 0x%04x missing from config database", model_id);
	}
	ATF_REQUIRE_EQ(2, comp.elements[1].n_sig);
	ATF_CHECK_EQ(MESH_MODEL_GEN_LEVEL_SRV,
	    comp.elements[1].sig_models[0]);
	ATF_CHECK_EQ(MESH_MODEL_LIGHT_CTL_TEMP_SRV,
	    comp.elements[1].sig_models[1]);
	ATF_REQUIRE_EQ(2, comp.elements[2].n_sig);
	ATF_CHECK_EQ(MESH_MODEL_GEN_LEVEL_SRV,
	    comp.elements[2].sig_models[0]);
	ATF_CHECK_EQ(MESH_MODEL_LIGHT_HSL_HUE_SRV,
	    comp.elements[2].sig_models[1]);
	ATF_REQUIRE_EQ(2, comp.elements[3].n_sig);
	ATF_CHECK_EQ(MESH_MODEL_GEN_LEVEL_SRV,
	    comp.elements[3].sig_models[0]);
	ATF_CHECK_EQ(MESH_MODEL_LIGHT_HSL_SAT_SRV,
	    comp.elements[3].sig_models[1]);
	ATF_CHECK(meshd_db_has_model_at(nd, nd->addr + 1,
	    MESH_MODEL_LIGHT_CTL_TEMP_SRV));
	ATF_CHECK(meshd_db_has_model_at(nd, nd->addr + 2,
	    MESH_MODEL_LIGHT_HSL_HUE_SRV));
	ATF_CHECK(meshd_db_has_model_at(nd, nd->addr + 3,
	    MESH_MODEL_LIGHT_HSL_SAT_SRV));

	/* Extended component models bind bidirectionally to Generic Level. */
	mesh_gen_level_srv_set_present(&nd->app->hue_level, 1234);
	ATF_CHECK_EQ(34002, nd->app->hsl.hue);
	mesh_gen_level_srv_set_present(&nd->app->sat_level, -1234);
	ATF_CHECK_EQ(31534, nd->app->hsl.saturation);
	ATF_REQUIRE_EQ(0, mesh_light_hsl_set(&nd->app->hsl, 1000, 40000,
	    50000));
	ATF_CHECK_EQ(7232, nd->app->hue_level.present);
	ATF_CHECK_EQ(17232, nd->app->sat_level.present);
	mesh_gen_level_srv_set_present(&nd->app->ctl_level, INT16_MIN);
	ATF_CHECK_EQ(nd->app->ctl.range_min, nd->app->ctl.temperature);
	mesh_gen_level_srv_set_present(&nd->app->ctl_level, INT16_MAX);
	ATF_CHECK_EQ(nd->app->ctl.range_max, nd->app->ctl.temperature);
}

/* ================================================================
 * Control surface.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ctl_tokenize);
ATF_TC_BODY(ctl_tokenize, tc)
{
	char line[64];
	char *argv[4];

	ATF_CHECK_EQ(0, meshd_ctl_tokenize(NULL, argv, 4));
	ATF_CHECK_EQ(0, meshd_ctl_tokenize(line, NULL, 4));
	strcpy(line, "a b");
	ATF_CHECK_EQ(0, meshd_ctl_tokenize(line, argv, 0));

	strcpy(line, "   ");
	ATF_CHECK_EQ(0, meshd_ctl_tokenize(line, argv, 4));

	strcpy(line, "  onoff  2  1 \n");
	ATF_CHECK_EQ(3, meshd_ctl_tokenize(line, argv, 4));
	ATF_CHECK_STREQ("onoff", argv[0]);
	ATF_CHECK_STREQ("2", argv[1]);
	ATF_CHECK_STREQ("1", argv[2]);

	/* More tokens than the array holds: stop at max. */
	strcpy(line, "a b c d e");
	ATF_CHECK_EQ(4, meshd_ctl_tokenize(line, argv, 4));

	/* Tab and carriage-return delimiters, leading and between tokens. */
	strcpy(line, "\tonoff\r");
	ATF_CHECK_EQ(1, meshd_ctl_tokenize(line, argv, 4));
	ATF_CHECK_STREQ("onoff", argv[0]);
	strcpy(line, "a\tb");
	ATF_CHECK_EQ(2, meshd_ctl_tokenize(line, argv, 4));

	/* A single token with no trailing delimiter (ends at NUL). */
	strcpy(line, "ab");
	ATF_CHECK_EQ(1, meshd_ctl_tokenize(line, argv, 4));
	ATF_CHECK_STREQ("ab", argv[0]);

	/* A token terminated by a newline. */
	strcpy(line, "cmd\narg");
	ATF_CHECK_EQ(2, meshd_ctl_tokenize(line, argv, 4));
	ATF_CHECK_STREQ("cmd", argv[0]);
}

ATF_TC_WITHOUT_HEAD(ctl_exec);
ATF_TC_BODY(ctl_exec, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	char reply[2048];
	char *av[12];

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Guard arms: every operand of the entry check. */
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(NULL, NULL, 1, av, reply, sizeof(reply)));
	av[0] = (char *)"status";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, NULL, reply, sizeof(reply)));
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, NULL, sizeof(reply)));
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply, 0));
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 0, av, reply, sizeof(reply)));

	/* status */
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));
	ATF_CHECK(strncmp(reply, "OK", 2) == 0);

	/* Node-management inventory mirrors Composition Data / config DB safely. */
	av[0] = (char *)"models";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "OK models=36") != NULL, "reply=%s", reply);
	ATF_CHECK(strstr(reply, "elem=0x0004 sig:0x130b") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x0000") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x0002") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1000 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1002 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1006 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1007 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1004 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1009 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x100a apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x100c apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x100e apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x100f apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1100 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1101 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1200 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1201 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1203 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1204 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1206 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1207 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1300 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1301 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1303 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1304 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1307 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x1308 apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x130a apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x130b apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x130c apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "sig:0x130d apps=0 subs=0 pub=0") != NULL);
	ATF_CHECK(strstr(reply, "netkey") == NULL);
	ATF_CHECK(strstr(reply, "appkey") == NULL);
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));

	/* A commissioned model reports only non-secret configuration cardinality. */
	nd->db.models[2].app_idx[0] = 0x001;
	nd->db.models[2].n_app = 1;
	nd->db.models[2].subs[0] = 0xc001;
	nd->db.models[2].n_subs = 1;
	nd->db.models[2].has_pub = 1;
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "sig:0x1000 apps=1 subs=1 pub=1") != NULL);
	ATF_CHECK(strstr(reply, "0xc001") == NULL);

	/* onoff: usage, bad arg, send failure (dst 0), success. */
	av[0] = (char *)"onoff";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));
	av[1] = (char *)"xx"; av[2] = (char *)"1";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"0"; av[2] = (char *)"1";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	/* second-operand bad arg (valid dst, bad value). */
	av[1] = (char *)"2"; av[2] = (char *)"xx";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	/* value out of range (b > max). */
	av[1] = (char *)"2"; av[2] = (char *)"9";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	/* argument that overflows strtoul (errno == ERANGE). */
	av[1] = (char *)"0xFFFFFFFFFFFFFFFFF"; av[2] = (char *)"1";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"2"; av[2] = (char *)"1";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));

	/* Generic Power OnOff: range validation and acknowledged send. */
	av[0] = (char *)"power-onoff";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));
	av[1] = (char *)"2"; av[2] = (char *)"3";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"0"; av[2] = (char *)"2";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"2"; av[2] = (char *)"2";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "OK power-onoff") != NULL);

	av[0] = (char *)"transition";
	av[1] = (char *)"2"; av[2] = (char *)"0x3f";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"0"; av[2] = (char *)"0x0a";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"2"; av[2] = (char *)"0x0a";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "OK transition") != NULL);

	av[0] = (char *)"power-level";
	av[1] = (char *)"2"; av[2] = (char *)"500";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "OK power-level") != NULL);
	av[0] = (char *)"power-default";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[0] = (char *)"power-range";
	av[1] = (char *)"2"; av[2] = (char *)"100";
	av[3] = (char *)"1000";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 4, av, reply, sizeof(reply)));
	av[2] = (char *)"0";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 4, av, reply, sizeof(reply)));

	av[0] = (char *)"battery-state";
	av[1] = (char *)"85"; av[2] = (char *)"100";
	/* Serviceability=01; Charging/Indicator/Presence=10. */
	av[3] = (char *)"50"; av[4] = (char *)"0x6a";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 5, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(85, nd->app->battery.state.level);
	/* Serviceability 0b00 is Reserved for Future Use. */
	av[4] = (char *)"0x2a";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 5, av, reply,
	    sizeof(reply)));
	av[4] = (char *)"0x6a";
	av[1] = (char *)"101";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 5, av, reply, sizeof(reply)));

	av[0] = (char *)"location-global";
	av[1] = (char *)"-123456"; av[2] = (char *)"654321";
	av[3] = (char *)"42";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 4, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(-123456, nd->app->location.global.latitude);
	av[3] = (char *)"40000";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 4, av, reply, sizeof(reply)));
	av[0] = (char *)"location-local";
	av[1] = (char *)"-10"; av[2] = (char *)"20";
	av[3] = (char *)"3"; av[4] = (char *)"7";
	av[5] = (char *)"0x1234";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 6, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(-10, nd->app->location.local.north);

	av[0] = (char *)"sensor-set"; av[1] = (char *)"0x004f";
	av[2] = (char *)"1122";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(1u, nd->app->sensor.n_entries);
	av[0] = (char *)"sensor-setting"; av[1] = (char *)"0x004f";
	av[2] = (char *)"0x1234"; av[3] = (char *)"3"; av[4] = (char *)"09";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 5, av, reply, sizeof(reply)));
	av[0] = (char *)"sensor-column"; av[1] = (char *)"0x004f";
	av[2] = (char *)"07"; av[3] = (char *)"0708";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 4, av, reply, sizeof(reply)));
	av[0] = (char *)"sensor-cadence"; av[1] = (char *)"0x004f";
	av[2] = (char *)"2"; av[3] = (char *)"0"; av[4] = (char *)"0100";
	av[5] = (char *)"0200"; av[6] = (char *)"3"; av[7] = (char *)"0400";
	av[8] = (char *)"0500";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 9, av, reply, sizeof(reply)));
	av[0] = (char *)"time-set"; av[1] = (char *)"100";
	av[2] = (char *)"1"; av[3] = (char *)"2"; av[4] = (char *)"1";
	av[5] = (char *)"0x1234"; av[6] = (char *)"0x40";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 7, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(100u, nd->app->time.time.tai_seconds);
	av[0] = (char *)"time-role"; av[1] = (char *)"2";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	av[1] = (char *)"4";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	av[0] = (char *)"time-zone"; av[1] = (char *)"0x44";
	av[2] = (char *)"100";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(0x44, nd->app->time.time.time_zone_offset);
	av[0] = (char *)"time-delta"; av[1] = (char *)"0x1235";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(0x1235, nd->app->time.time.tai_utc_delta);
	mesh_gen_power_level_set_actual(&nd->app->power_level, 100);
	nd->app->onoff.present = MESH_GEN_ON;
	av[0] = (char *)"scene-store"; av[1] = (char *)"0x1234";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(1u, nd->app->scene.n_scenes);
	nd->app->onoff.present = MESH_GEN_OFF;
	av[0] = (char *)"scene-recall";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(MESH_GEN_ON, nd->app->onoff.present);
	av[0] = (char *)"ctl-state"; av[1] = (char *)"600";
	av[2] = (char *)"3000"; av[3] = (char *)"-10";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 4, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(3000, nd->app->ctl.temperature);
	av[0] = (char *)"hsl-state"; av[1] = (char *)"700";
	av[2] = (char *)"2000"; av[3] = (char *)"3000";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 4, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(2000, nd->app->hsl.hue);
	av[0] = (char *)"xyl-state"; av[1] = (char *)"800";
	av[2] = (char *)"2500"; av[3] = (char *)"3500";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 4, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(2500, nd->app->xyl.x);
	ATF_CHECK_EQ(3500, nd->app->xyl.y);
	nd->app->lightness.last = 900;
	av[0] = (char *)"lc-mode"; av[1] = (char *)"1";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(1, nd->app->lc.mode);
	av[0] = (char *)"lc-om"; av[1] = (char *)"1";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(1, nd->app->lc.occupancy_mode);
	av[0] = (char *)"lc-light-onoff"; av[1] = (char *)"1";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(1, nd->app->lc.light_onoff);
	ATF_CHECK_EQ(900, nd->app->lightness.actual);
	av[0] = (char *)"lc-property"; av[1] = (char *)"0x002e";
	av[2] = (char *)"3412";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(1u, nd->app->lc.n_properties);
	ATF_CHECK_EQ(0x002e, nd->app->lc.properties[0].id);
	ATF_CHECK_EQ(2u, nd->app->lc.properties[0].len);
	av[2] = (char *)"0011223344";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[0] = (char *)"scheduler-set"; av[1] = (char *)"3";
	av[2] = (char *)"100"; av[3] = (char *)"0x80"; av[4] = (char *)"13";
	av[5] = (char *)"7"; av[6] = (char *)"30"; av[7] = (char *)"0";
	av[8] = (char *)"0x7f"; av[9] = (char *)"2"; av[10] = (char *)"0";
	av[11] = (char *)"10";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 12, av, reply, sizeof(reply)));
	ATF_CHECK((nd->app->scheduler.defined & (1u << 3)) != 0);
	av[9] = (char *)"15"; av[11] = (char *)"0";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 12, av, reply, sizeof(reply)));
	ATF_CHECK((nd->app->scheduler.defined & (1u << 3)) == 0);
	av[0] = (char *)"lightness-range"; av[1] = (char *)"100";
	av[2] = (char *)"1000";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[0] = (char *)"lightness-state"; av[1] = (char *)"500";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(500, nd->app->lightness.actual);
	ATF_CHECK_EQ(MESH_GEN_ON, nd->app->onoff.present);

	/* level: usage, bad arg, send failure, success. */
	av[0] = (char *)"level";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));
	av[1] = (char *)"zz"; av[2] = (char *)"5";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"0"; av[2] = (char *)"5";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"2"; av[2] = (char *)"-5";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	/* Reject malformed and out-of-range Levels rather than narrowing them. */
	av[1] = (char *)"2"; av[2] = (char *)"12oops";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"2"; av[2] = (char *)"32768";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"2"; av[2] = (char *)"-32769";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));

	/* ttl: usage, bad-parse arg, invalid, success. */
	av[0] = (char *)"ttl";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));
	av[1] = (char *)"zz";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	av[1] = (char *)"1";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	av[1] = (char *)"9";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));

	/* attention: usage, bad-parse arg, success. */
	av[0] = (char *)"attention";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));
	av[1] = (char *)"zz";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	av[1] = (char *)"5";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));

	/* provision-local: usage, bad arg, failure (addr 0), success. */
	av[0] = (char *)"provision-local";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));
	av[1] = (char *)"qq"; av[2] = (char *)"0";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	/* valid addr, bad iv (second-operand parse failure). */
	av[1] = (char *)"6"; av[2] = (char *)"xx";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"0"; av[2] = (char *)"0";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"0x0006"; av[2] = (char *)"2";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(0x0006, meshd_node_addr(nd));

	/* key-refresh: status, begin (Phase 1), advance (2), finish (0). */
	av[0] = (char *)"key-refresh";
	av[1] = (char *)"status";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "phase=0") != NULL);
	av[1] = (char *)"begin";
	av[2] = (char *)"a1a2a3a4a5a6a7a8a9aaabacadaeafb0";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "phase=1") != NULL);
	/* A second begin mid-refresh is rejected. */
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"advance";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "phase=2") != NULL);
	av[1] = (char *)"finish";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "phase=0") != NULL);
	/* bad hex + unknown sub-verb. */
	av[1] = (char *)"begin"; av[2] = (char *)"nothex";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	av[1] = (char *)"bogus";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 2, av, reply, sizeof(reply)));

	/* reset */
	av[0] = (char *)"reset";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));
	ATF_CHECK_EQ(0, nd->provisioned);
	av[0] = (char *)"leave";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));
	av[0] = (char *)"attach";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));

	/* unknown */
	av[0] = (char *)"frobnicate";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));
}

static char pbgatt_open_addr[18];
static uint8_t pbgatt_open_addr_type;
static uint8_t pbgatt_open_adapter_index;

static int
capture_pbgatt_open(void *arg __unused, const char *addr,
    uint8_t addr_type, uint8_t adapter_index)
{

	strlcpy(pbgatt_open_addr, addr, sizeof(pbgatt_open_addr));
	pbgatt_open_addr_type = addr_type;
	pbgatt_open_adapter_index = adapter_index;
	return (0);
}

ATF_TC_WITHOUT_HEAD(ctl_provision_gatt);
ATF_TC_BODY(ctl_provision_gatt, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = {
		.pbgatt_open = capture_pbgatt_open,
	};
	char reply[256];
	char *av[6];

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);
	av[0] = (char *)"create-network";
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply, sizeof(reply)));

	av[0] = (char *)"provision-gatt";
	av[1] = (char *)"11:22:33:44:55:66";
	av[2] = (char *)"random";
	av[3] = (char *)"adapter=7";
	av[4] = (char *)"0102030405060708090a0b0c0d0e0f10";
	av[5] = (char *)"1";
	pbgatt_open_addr[0] = '\0';
	pbgatt_open_addr_type = 0;
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, NULL, 6, av, reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "OK PB-GATT") != NULL);
	ATF_CHECK_STREQ("11:22:33:44:55:66", pbgatt_open_addr);
	ATF_CHECK_EQ(1, pbgatt_open_addr_type);
	ATF_CHECK_EQ(7, pbgatt_open_adapter_index);
	ATF_CHECK_EQ(7, nd->pbgatt.adapter_index);
	ATF_CHECK(nd->pbgatt.active);
	ATF_CHECK(nd->prov_target_active);
	/* A second concurrent provisioning attempt is rejected. */
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 6, av, reply, sizeof(reply)));

	mesh_prov_session_free(&nd->prov_sess);
	nd->pbgatt.active = 0;
	meshd_node_fini(nd);
}

ATF_TC_WITHOUT_HEAD(ctl_extended_mesh_command_matrix);
ATF_TC_BODY(ctl_extended_mesh_command_matrix, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	char reply[2048];
	char *av[12];
	static const char *const needs_arguments[] = {
		"power-level", "power-default", "battery-state",
		"location-local", "sensor-set", "sensor-setting",
		"sensor-column", "sensor-cadence", "time-set", "time-zone",
		"time-delta", "scene-store", "scene-recall", "scene-delete",
		"scheduler-set", "lightness-state", "lightness-default",
		"lightness-range", "ctl-state", "hsl-state", "xyl-state",
		"lc-mode", "lc-om", "lc-light-onoff", "delete-remote-node",
		"publish", "provision", "provision-gatt", "proxy-gatt",
		"proxy-gatt-close", "proxy-filter-add", "proxy-filter-remove",
	};
	size_t i;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Each verb must reject a missing operand with its documented usage. */
	for (i = 0; i < nitems(needs_arguments); i++) {
		av[0] = __DECONST(char *, needs_arguments[i]);
		ATF_CHECK_EQ_MSG(-1, meshd_ctl_exec_client(nd, NULL, 1, av,
		    reply, sizeof(reply)), "verb=%s reply=%s", needs_arguments[i],
		    reply);
		ATF_CHECK_MSG(strncmp(reply, "ERR", 3) == 0,
		    "verb=%s reply=%s", needs_arguments[i], reply);
	}

	/* Previously untouched local lighting/scene control verbs. */
	av[0] = __DECONST(char *, "lightness-default");
	av[1] = __DECONST(char *, "750");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "ctl-range");
	av[1] = __DECONST(char *, "800"); av[2] = __DECONST(char *, "20000");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply,
	    sizeof(reply)));
	av[1] = __DECONST(char *, "20000"); av[2] = __DECONST(char *, "800");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "hsl-range");
	av[1] = __DECONST(char *, "1"); av[2] = __DECONST(char *, "60000");
	av[3] = __DECONST(char *, "2"); av[4] = __DECONST(char *, "50000");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 5, av, reply,
	    sizeof(reply)));
	av[1] = __DECONST(char *, "2"); av[2] = __DECONST(char *, "1");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 5, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "xyl-range");
	av[1] = __DECONST(char *, "1"); av[2] = __DECONST(char *, "60000");
	av[3] = __DECONST(char *, "2"); av[4] = __DECONST(char *, "50000");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 5, av, reply,
	    sizeof(reply)));
	av[3] = __DECONST(char *, "9"); av[4] = __DECONST(char *, "3");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 5, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "scene-store"); av[1] = __DECONST(char *, "9");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "scene-delete");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK(meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)) <= 0);

	/* Manager lifecycle and roster operations. */
	av[0] = __DECONST(char *, "list-nodes");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "create-network");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "list-nodes");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "features");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "import-remote-node");
	av[1] = __DECONST(char *, "0x0100"); av[2] = __DECONST(char *, "2");
	av[3] = __DECONST(char *, "00112233445566778899aabbccddeeff");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 4, av, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 4, av, reply,
	    sizeof(reply)));
	av[2] = __DECONST(char *, "0");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 4, av, reply,
	    sizeof(reply)));
	av[2] = __DECONST(char *, "2");
	av[0] = __DECONST(char *, "list-nodes");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "[0x0100/2]") != NULL, "%s", reply);

	/* Fill the bounded sensor registry, then exercise cadence validation. */
	for (i = 1; i <= MESH_SENSOR_MAX_PROPERTIES + 1; i++) {
		char property[16];

		snprintf(property, sizeof(property), "%zu", i);
		av[0] = __DECONST(char *, "sensor-set");
		av[1] = property; av[2] = __DECONST(char *, "01");
		ATF_CHECK_EQ(i <= MESH_SENSOR_MAX_PROPERTIES ? 0 : -1,
		    meshd_ctl_exec_client(nd, NULL, 3, av, reply, sizeof(reply)));
	}
	av[0] = __DECONST(char *, "sensor-set");
	av[1] = __DECONST(char *, "1"); av[2] = __DECONST(char *, "01");
	av[3] = __DECONST(char *, "0"); av[4] = __DECONST(char *, "4096");
	av[5] = __DECONST(char *, "0"); av[6] = __DECONST(char *, "0");
	av[7] = __DECONST(char *, "0");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 8, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "sensor-cadence");
	av[1] = __DECONST(char *, "1"); av[2] = __DECONST(char *, "0");
	av[3] = __DECONST(char *, "0"); av[4] = __DECONST(char *, "0000");
	av[5] = __DECONST(char *, "00"); av[6] = __DECONST(char *, "0");
	av[7] = __DECONST(char *, "00"); av[8] = __DECONST(char *, "00");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 9, av, reply,
	    sizeof(reply)));

	/* Parsed scheduler fields can still form a semantically invalid action. */
	{
		char *sched[] = { __DECONST(char *, "scheduler-set"),
		    __DECONST(char *, "0"), __DECONST(char *, "100"),
		    __DECONST(char *, "1"), __DECONST(char *, "1"),
		    __DECONST(char *, "1"), __DECONST(char *, "1"),
		    __DECONST(char *, "1"), __DECONST(char *, "1"),
		    __DECONST(char *, "3"), __DECONST(char *, "0"),
		    __DECONST(char *, "0") };

		ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, nitems(sched),
		    sched, reply, sizeof(reply)));
	}

	/* Raw application, DevKey, and publication paths (including failures). */
	av[0] = __DECONST(char *, "send"); av[1] = __DECONST(char *, "0x0100");
	av[2] = __DECONST(char *, "0"); av[3] = __DECONST(char *, "820201");
	ATF_CHECK(meshd_ctl_exec_client(nd, NULL, 4, av, reply,
	    sizeof(reply)) <= 0);
	av[2] = __DECONST(char *, "4096");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 4, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "devkey-send");
	av[1] = __DECONST(char *, "0x0100"); av[2] = __DECONST(char *, "remote");
	av[3] = __DECONST(char *, "0"); av[4] = __DECONST(char *, "8008");
	ATF_CHECK(meshd_ctl_exec_client(nd, NULL, 5, av, reply,
	    sizeof(reply)) <= 0);
	av[2] = __DECONST(char *, "invalid");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 5, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "publish"); av[1] = __DECONST(char *, "1");
	av[2] = __DECONST(char *, "0x1000"); av[3] = __DECONST(char *, "820201");
	ATF_CHECK(meshd_ctl_exec_client(nd, NULL, 4, av, reply,
	    sizeof(reply)) <= 0);
	av[3] = __DECONST(char *, "0x1234"); av[4] = __DECONST(char *, "820201");
	ATF_CHECK(meshd_ctl_exec_client(nd, NULL, 5, av, reply,
	    sizeof(reply)) <= 0);

	/* Network refresh and provisioning/proxy validation surfaces. */
	av[0] = __DECONST(char *, "key-refresh");
	av[1] = __DECONST(char *, "network-status");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	av[1] = __DECONST(char *, "network");
	av[2] = __DECONST(char *, "ffeeddccbbaa99887766554433221100");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "provision-scan");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "provision");
	av[1] = __DECONST(char *, "bad");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	av[1] = __DECONST(char *, "00112233445566778899aabbccddeeff");
	av[2] = __DECONST(char *, "0");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "proxy-gatt"); av[1] = __DECONST(char *, "bad");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "proxy-filter-set");
	av[1] = __DECONST(char *, "bad"); av[2] = __DECONST(char *, "0");
	av[3] = __DECONST(char *, "invalid");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 4, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "proxy-filter-add");
	av[3] = __DECONST(char *, "0");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 4, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "provision-status");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));

	av[0] = __DECONST(char *, "delete-remote-node");
	av[1] = __DECONST(char *, "0x0100"); av[2] = __DECONST(char *, "2");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 3, av, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 3, av, reply,
	    sizeof(reply)));
	meshd_node_fini(nd);
}

/* ================================================================
 * Role driving through the daemon (MshPRT_v1.1 Section 3.6.5 / Section 5).
 * ================================================================ */

/* The daemon drives the Friend role: Request -> Offer -> Poll -> establish. */
ATF_TC_WITHOUT_HEAD(role_friend);
ATF_TC_BODY(role_friend, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_friend_out out;
	struct mesh_friend_request req;
	struct mesh_friend_poll poll;
	uint8_t rpdu[MESH_FRIEND_REQUEST_LEN], ppdu[MESH_FRIEND_POLL_LEN];
	size_t rlen, plen;
	uint64_t now = 0;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	ATF_REQUIRE_EQ(0, meshd_friend_enable(nd, 20, 8, 4, -90, 4));

	memset(&req, 0, sizeof(req));
	req.min_queue_size_log = 1;
	req.recv_delay = 100;
	req.poll_timeout = 100;
	req.num_elements = 1;
	req.lpn_counter = 1;
	ATF_REQUIRE_EQ(0, mesh_friend_request_build(&req, rpdu, &rlen));

	/* Friend Request from LPN 0x1201 (the message SRC). */
	ATF_REQUIRE_EQ(0, meshd_friend_input(nd, 0x1201, rpdu, rlen, -60, 0, 0,
	    0, now, &out));
	now = 300;
	ATF_REQUIRE_EQ(0, meshd_friend_tick(nd, now, &out));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_CONTROL, out.action);
	ATF_CHECK_EQ(MESH_FRIEND_OP_OFFER, out.pdu[0] & 0x7f);

	memset(&poll, 0, sizeof(poll));
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, ppdu, &plen));
	ATF_CHECK_EQ(1, meshd_friend_input(nd, 0x1201, ppdu, plen, 0, 0, 0, 0,
	    now, &out));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_MSG, out.action);
	ATF_CHECK(mesh_friend_fsm_established(&nd->friend_fsm));
}

/* The daemon drives the LPN role: Request -> Offer -> Poll -> establish. */
ATF_TC_WITHOUT_HEAD(role_lpn);
ATF_TC_BODY(role_lpn, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_lpn_out out;
	struct mesh_friend_offer offer;
	struct mesh_friend_update up;
	uint8_t opdu[MESH_FRIEND_OFFER_LEN], updu[MESH_FRIEND_UPDATE_LEN];
	size_t olen, ulen;
	uint64_t now = 0;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	ATF_REQUIRE_EQ(0, meshd_lpn_enable(nd, 0, 0, 1, 100, 100, 1000, 5000,
	    now, &out));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_REQUEST, out.action);

	memset(&offer, 0, sizeof(offer));
	offer.recv_window = 20;
	offer.queue_size = 8;
	offer.sub_list_size = 4;
	offer.rssi = -50;
	offer.friend_counter = 1;
	ATF_REQUIRE_EQ(0, mesh_friend_offer_build(&offer, opdu, &olen));
	ATF_CHECK_EQ(1, meshd_lpn_recv_offer(nd, opdu, olen, 0x2345, now));

	now = 1000;
	ATF_REQUIRE_EQ(0, meshd_lpn_tick(nd, now, &out));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_POLL, out.action);
	ATF_CHECK_EQ(0x2345, out.friend_addr);

	memset(&up, 0, sizeof(up));
	up.iv_index = 0x1000;
	ATF_REQUIRE_EQ(0, mesh_friend_update_build(&up, updu, &ulen));
	ATF_CHECK_EQ(1, meshd_lpn_recv_update(nd, updu, ulen, now, &out));
	ATF_CHECK_EQ(MESH_LPN_ACT_ESTABLISHED, out.action);
	ATF_CHECK(mesh_lpn_fsm_established(&nd->lpn_fsm));
}

/*
 * The daemon acts as a Provisioner and provisions a simulated device end to end
 * over the PB-ADV bearer: both sides finish holding the same DevKey.
 */
ATF_TC_WITHOUT_HEAD(role_provisioner);
ATF_TC_BODY(role_provisioner, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_prov_link dl;
	struct mesh_prov_session ds;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	uint8_t uuid[16];
	uint8_t raw[25];
	uint8_t pkt[MESH_PBADV_PKT_MAX];
	uint8_t dev_ack[MESH_PBADV_PKT_MAX];
	uint8_t rpdu[MESH_PROV_PDU_MAX];
	size_t len, rlen, dev_ack_len;
	int have_pdu, have_ack, dev_ack_pending;
	uint64_t now = 0;
	int i;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	memset(uuid, 0x42, sizeof(uuid));
	hex_bytes(raw, "efb2255e6422d330088e09bb015ed707056700010203040b0c", 25);
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));

	/* Simulated device: link + session. */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	mesh_prov_link_init_device(&dl, uuid, 100000, 3);
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&ds, NULL, NULL, &caps));
	dev_ack_pending = 0;

	/* Daemon begins provisioning: the Link Open reaches the device. */
	ATF_REQUIRE_EQ(0, meshd_provisioner_begin(nd, uuid, 0x11223344, NULL,
	    NULL, 0x00, &pdata, 100000, 3, now, pkt, &len));
	have_ack = have_pdu = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, len, now, rpdu, &rlen,
	    &have_pdu, dev_ack, &dev_ack_len, &have_ack));
	if (have_ack)
		dev_ack_pending = 1;

	/* Pump both bearers to quiescence (no packet loss). */
	for (i = 0; i < 400; i++) {
		if (meshd_provisioner_poll(nd, now, pkt, &len) == 1) {
			have_ack = have_pdu = 0;
			ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, len, now,
			    rpdu, &rlen, &have_pdu, dev_ack, &dev_ack_len,
			    &have_ack));
			if (have_ack)
				dev_ack_pending = 1;
			if (have_pdu)
				(void)mesh_prov_session_recv(&ds, rpdu, rlen);
			continue;
		}
		/* Device side: emit ack, then drive its session over the link. */
		if (dev_ack_pending) {
			ATF_REQUIRE_EQ(0, meshd_provisioner_recv(nd, dev_ack,
			    dev_ack_len, now));
			dev_ack_pending = 0;
			continue;
		}
		{
			int rc = mesh_prov_link_poll(&dl, now, pkt, &len);
			if (rc == 1) {
				ATF_REQUIRE_EQ(0, meshd_provisioner_recv(nd, pkt,
				    len, now));
				continue;
			}
			if (mesh_prov_link_idle(&dl)) {
				uint8_t spdu[MESH_PROV_PDU_MAX];
				size_t slen;
				if (mesh_prov_session_poll(&ds, spdu, &slen) == 1) {
					ATF_REQUIRE_EQ(0, mesh_prov_link_send(&dl,
					    spdu, slen, now));
					continue;
				}
			}
		}
		if (meshd_provisioner_done(nd) && mesh_prov_session_done(&ds))
			break;
	}

	ATF_CHECK(meshd_provisioner_done(nd));
	ATF_CHECK(mesh_prov_session_done(&ds));
	/* Both sides derived the same DevKey. */
	ATF_CHECK_EQ_MSG(0, memcmp(nd->prov_sess.devkey,
	    mesh_prov_session_devkey(&ds), 16), "provisioner/device DevKey match");

	mesh_prov_session_free(&nd->prov_sess);
	mesh_prov_session_free(&ds);
}

/*
 * Provision a peer end to end over PB-GATT at the default ATT MTU.  Both
 * directions pass through Proxy-PDU segmentation/reassembly; the 65-octet
 * Public Key PDU therefore exercises a multi-notification exchange.
 */
static int g_pbgatt_close_calls;
static int g_pbgatt_timeout_calls;
static int g_pbgatt_timeout_result;
static uint8_t g_pbgatt_timeout_wire[MESH_PROXY_MAX_PDU];
static size_t g_pbgatt_timeout_wire_len;

static int
capture_pbgatt_close(void *arg __unused)
{

	g_pbgatt_close_calls++;
	return (0);
}

static int
capture_pbgatt_timeout(void *arg)
{
	struct meshd_node *nd = arg;

	g_pbgatt_timeout_calls++;
	if (g_pbgatt_timeout_result != 0)
		return (g_pbgatt_timeout_result);
	return (meshd_pbgatt_poll(nd, nd->pbgatt.timeout_started_ms,
	    g_pbgatt_timeout_wire, sizeof(g_pbgatt_timeout_wire),
	    &g_pbgatt_timeout_wire_len) == 1 ? 0 : -1);
}

ATF_TC_WITHOUT_HEAD(role_provisioner_pbgatt);
ATF_TC_BODY(role_provisioner_pbgatt, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = {
		.pbgatt_close = capture_pbgatt_close,
		.pbgatt_timeout = capture_pbgatt_timeout,
	};
	struct mesh_prov_session ds;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	struct mesh_pbgatt_reasm device_rx;
	struct mesh_proxy_pdu segs[MESHD_PBGATT_MAX_SEGS];
	uint8_t raw[25], proxy[64], prov[MESH_PROV_PDU_MAX], rfu[] = { 0x04 };
	uint8_t bad_state[] = { MESH_PROXY_TYPE_PROVISIONING, 0x00, 0x00 };
	uint8_t uuid[16] = { 1 };
	uint8_t first[] = { (MESH_PROXY_SAR_FIRST << 6) |
	    MESH_PROXY_TYPE_PROVISIONING, 0x00 };
	size_t proxy_len, prov_len, nseg, i;
	int step, rc;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	hex_bytes(raw, "efb2255e6422d330088e09bb015ed707056700010203040b0c",
	    sizeof(raw));
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&ds, NULL, NULL, &caps));
	mesh_pbgatt_reasm_init(&device_rx);
	bearer.arg = nd;
	meshd_set_bearer(nd, &bearer);

	ATF_CHECK_EQ(-1, meshd_pbgatt_begin(nd, 22, NULL, NULL, 0, &pdata));
	ATF_REQUIRE_EQ(0, meshd_pbgatt_begin(nd, 23, NULL, NULL, 0, &pdata));
	ATF_REQUIRE_EQ(0, meshd_pbgatt_set_mtu(nd, 247));
	ATF_CHECK_EQ(247, nd->pbgatt.mtu);
	/* Recommended MTU 69 and larger must respect the fixed segment buffer. */
	ATF_REQUIRE_EQ(0, meshd_pbgatt_set_mtu(nd, 69));
	/* The link-open timer starts only after the CCCD subscription succeeds. */
	meshd_gatt_tick(nd, MESHD_PBGATT_PROTOCOL_TIMEOUT_MS + 1000);
	ATF_CHECK(nd->pbgatt.active);
	ATF_REQUIRE_EQ(0, meshd_pbgatt_link_open(nd, 1000));
	meshd_gatt_tick(nd, 1000 + MESHD_PBGATT_PROTOCOL_TIMEOUT_MS - 1);
	ATF_CHECK(nd->pbgatt.active);
	g_pbgatt_close_calls = 0;
	g_pbgatt_timeout_calls = 0;
	g_pbgatt_timeout_result = 0;
	g_pbgatt_timeout_wire_len = 0;
	meshd_gatt_tick(nd, 1000 + MESHD_PBGATT_PROTOCOL_TIMEOUT_MS);
	ATF_CHECK(nd->pbgatt.active);
	ATF_CHECK(nd->pbgatt.timeout_closing);
	ATF_CHECK_EQ(1, g_pbgatt_timeout_calls);
	ATF_REQUIRE_EQ(3, g_pbgatt_timeout_wire_len);
	ATF_CHECK_EQ(MESH_PROXY_TYPE_PROVISIONING, g_pbgatt_timeout_wire[0]);
	ATF_CHECK_EQ(MESH_PROV_FAILED, g_pbgatt_timeout_wire[1]);
	ATF_CHECK_EQ(MESHD_PROV_ERR_UNEXPECTED_ERROR,
	    g_pbgatt_timeout_wire[2]);
	ATF_CHECK_EQ(0, g_pbgatt_close_calls);
	meshd_gatt_tick(nd, 1000 + MESHD_PBGATT_PROTOCOL_TIMEOUT_MS +
	    MESHD_PBGATT_FAILED_CLOSE_TIMEOUT_MS - 1);
	ATF_CHECK(nd->pbgatt.active);
	meshd_gatt_tick(nd, 1000 + MESHD_PBGATT_PROTOCOL_TIMEOUT_MS +
	    MESHD_PBGATT_FAILED_CLOSE_TIMEOUT_MS);
	ATF_CHECK(!nd->pbgatt.active);
	ATF_CHECK_EQ(1, g_pbgatt_close_calls);
	ATF_REQUIRE_EQ(0, meshd_pbgatt_begin(nd, 69, NULL, NULL, 0, &pdata));
	ATF_REQUIRE_EQ(0, meshd_pbgatt_link_open(nd, 70000));
	/* Sending a complete PDU restarts the session-long protocol timer. */
	ATF_REQUIRE_EQ(1, meshd_pbgatt_poll(nd, 71000, proxy, sizeof(proxy),
	    &proxy_len));
	ATF_CHECK_EQ(71000, nd->pbgatt.protocol_started_ms);
	meshd_gatt_tick(nd, 71000 + MESHD_PBGATT_PROTOCOL_TIMEOUT_MS - 1);
	ATF_CHECK(nd->pbgatt.active);
	g_pbgatt_timeout_result = -1;
	meshd_gatt_tick(nd, 71000 + MESHD_PBGATT_PROTOCOL_TIMEOUT_MS);
	ATF_CHECK(!nd->pbgatt.active);
	g_pbgatt_timeout_result = 0;
	ATF_REQUIRE_EQ(0, meshd_pbgatt_begin(nd, 69, NULL, NULL, 0, &pdata));
	ATF_REQUIRE_EQ(0, meshd_pbgatt_link_open(nd, 140000));
	ATF_CHECK_EQ(0, meshd_pbgatt_recv(nd, rfu, sizeof(rfu), 140000));
	ATF_CHECK(nd->pbgatt.protocol_timer);
	/* Receive-event time, not the potentially stale node tick, starts SAR. */
	ATF_REQUIRE_EQ(0, meshd_pbgatt_recv(nd, first, sizeof(first), 141234));
	ATF_CHECK(nd->pbgatt.rx_started);
	ATF_CHECK_EQ(141234, nd->pbgatt.rx_started_ms);
	meshd_pbgatt_cancel(nd);
	/* A complete out-of-sequence Provisioning PDU is bearer-fatal. */
	ATF_REQUIRE_EQ(0, meshd_pbgatt_begin(nd, 69, NULL, NULL, 0, &pdata));
	ATF_REQUIRE_EQ(0, meshd_pbgatt_link_open(nd, 141500));
	ATF_CHECK_EQ(-1, meshd_pbgatt_recv(nd, bad_state,
	    sizeof(bad_state), 141600));
	meshd_pbgatt_cancel(nd);
	nd->mgr = calloc(1, sizeof(*nd->mgr));
	ATF_REQUIRE(nd->mgr != NULL);
	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(nd->mgr, NULL, NULL));
	ATF_REQUIRE_EQ(0, mesh_mgr_provision_prepare(nd->mgr, uuid, 1,
	    &pdata));
	nd->mgr_active = 1;
	nd->prov_target_active = 1;
	ATF_REQUIRE_EQ(0, meshd_pbgatt_begin(nd, 69, NULL, NULL, 0, &pdata));
	ATF_REQUIRE_EQ(0, meshd_pbgatt_link_open(nd, 72000));

	for (step = 0; step < 400; step++) {
		/* Provisioner Data In writes -> device provisioning session. */
		while ((rc = meshd_pbgatt_poll(nd, 72000 + step, proxy, sizeof(proxy),
		    &proxy_len)) == 1) {
			ATF_CHECK_MSG(proxy_len <= 66, "ATT value exceeds MTU: %zu",
			    proxy_len);
			rc = mesh_pbgatt_reasm_input(&device_rx, proxy, proxy_len,
			    prov, sizeof(prov), &prov_len);
			ATF_REQUIRE_MSG(rc >= 0, "device SAR rejected segment");
			if (rc == 1)
				ATF_REQUIRE_EQ(0,
				    mesh_prov_session_recv(&ds, prov, prov_len));
		}
		ATF_REQUIRE_MSG(rc == 0, "provisioner poll failed");

		/* Device Data Out notifications -> meshd provisioner session. */
		if (mesh_prov_session_poll(&ds, prov, &prov_len) == 1) {
			ATF_REQUIRE_EQ(0, mesh_pbgatt_segment(
			    MESH_PROXY_TYPE_PROVISIONING, prov, prov_len, 19,
			    segs, MESHD_PBGATT_MAX_SEGS, &nseg));
			for (i = 0; i < nseg; i++)
				ATF_REQUIRE_MSG(meshd_pbgatt_recv(nd, segs[i].bytes,
				    segs[i].len, 72000 + step) >= 0,
				    "meshd SAR rejected segment");
		}
		if (meshd_pbgatt_done(nd) && mesh_prov_session_done(&ds))
			break;
	}

	ATF_CHECK_MSG(meshd_pbgatt_done(nd), "provisioner did not complete");
	ATF_CHECK_MSG(mesh_prov_session_done(&ds), "device did not complete");
	ATF_CHECK(nd->pbgatt.protocol_timer);
	ATF_CHECK_EQ_MSG(0, memcmp(nd->prov_sess.devkey,
	    mesh_prov_session_devkey(&ds), 16), "PB-GATT DevKey mismatch");
	ATF_CHECK_EQ(-1, meshd_pbgatt_recv(nd, proxy, 67, 71000));
	g_pbgatt_close_calls = 0;
	ATF_REQUIRE(meshd_provision_ota_commit(nd, 0x1234) != NULL);
	ATF_CHECK_EQ(1, g_pbgatt_close_calls);
	ATF_CHECK(!nd->pbgatt.active);
	ATF_CHECK(!nd->prov_target_active);
	ATF_CHECK_EQ(1, mesh_mgr_node_count(nd->mgr));

	mesh_prov_session_free(&ds);
	meshd_node_fini(nd);
}

ATF_TC_WITHOUT_HEAD(foundation_handler_guard_sweep);
ATF_TC_BODY(foundation_handler_guard_sweep, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	ATF_CHECK(ptap_meshd_node_handler_guard_sweep(nd) > 70);
	meshd_node_fini(nd);
}

ATF_TC_WITHOUT_HEAD(node_internal_state_sweep);
ATF_TC_BODY(node_internal_state_sweep, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	ATF_CHECK_EQ(0, ptap_meshd_node_internal_state_sweep(nd));
	meshd_node_fini(nd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, role_friend);
	ATF_TP_ADD_TC(tp, role_lpn);
	ATF_TP_ADD_TC(tp, role_provisioner);
	ATF_TP_ADD_TC(tp, role_provisioner_pbgatt);

	ATF_TP_ADD_TC(tp, config_hexdecode);
	ATF_TP_ADD_TC(tp, config_parse_lines);
	ATF_TP_ADD_TC(tp, config_parse_errors);
	ATF_TP_ADD_TC(tp, config_validate);
	ATF_TP_ADD_TC(tp, config_load_file);
	ATF_TP_ADD_TC(tp, node_init);
	ATF_TP_ADD_TC(tp, bearer_rx_and_tx);
	ATF_TP_ADD_TC(tp, gatt_proxy_network_rx);
	ATF_TP_ADD_TC(tp, gatt_proxy_connect_lifecycle);
	ATF_TP_ADD_TC(tp, model_publication_scheduler);
	ATF_TP_ADD_TC(tp, app_surface_receives_access_events);
	ATF_TP_ADD_TC(tp, app_opcode_command_and_ownership);
	ATF_TP_ADD_TC(tp, app_client_queues_are_per_connection);
	ATF_TP_ADD_TC(tp, app_client_multi_connection_stress);
	ATF_TP_ADD_TC(tp, bearer_drop_without_sink);
	ATF_TP_ADD_TC(tp, beacon_pump_kr_flag);
	ATF_TP_ADD_TC(tp, beacon_pump_all_subnets);
	ATF_TP_ADD_TC(tp, beacon_receive_matrix);
	ATF_TP_ADD_TC(tp, send_onoff_level);
	ATF_TP_ADD_TC(tp, provision_local);
	ATF_TP_ADD_TC(tp, provision_recv_data);
	ATF_TP_ADD_TC(tp, foundation_recv);
	ATF_TP_ADD_TC(tp, foundation_reply_overflow);
	ATF_TP_ADD_TC(tp, foundation_feature_handler_matrix);
	ATF_TP_ADD_TC(tp, foundation_handler_guard_sweep);
	ATF_TP_ADD_TC(tp, node_internal_state_sweep);
	ATF_TP_ADD_TC(tp, foundation_key_lifecycle);
	ATF_TP_ADD_TC(tp, featured_comp_and_drain);
	ATF_TP_ADD_TC(tp, composition_registers_all_app_model_families);
	ATF_TP_ADD_TC(tp, ctl_tokenize);
	ATF_TP_ADD_TC(tp, ctl_exec);
	ATF_TP_ADD_TC(tp, ctl_provision_gatt);
	ATF_TP_ADD_TC(tp, ctl_extended_mesh_command_matrix);

	return (atf_no_error());
}
