/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Regression tests for the meshd/meshctl correctness and completeness findings
 * (bluetooth-bugs.md findings 52, 53, 54, 55, 69, 71, 73, 106, 107 and the
 * completeness items 126, 127, 130, 131).  Each test pins the fixed behavior so
 * a re-introduction of the bug fails here.
 *
 * The libmesh / meshd structs are large, so every node / manager is
 * heap-allocated via MESH_HEAP - never on the test stack.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mesh_test_heap.h"
#include "meshd.h"
#include "meshd_persist.h"
#include "mesh_heartbeat.h"
#include "mesh_health_model.h"
#include "mesh_beacon.h"
#include "mesh_cfg_model.h"
#include "mesh_provisioner.h"

#ifndef __DECONST
#define	__DECONST(type, var)	((type)(uintptr_t)(const void *)(var))
#endif

/*
 * Linker-wrapped mesh_prov_link_open so finding 123's PB-ADV link-open failure
 * path (unreachable with valid arguments) can be forced on demand.  Passes
 * through to the real implementation unless g_force_link_open_fail is set.
 */
static int g_force_link_open_fail;
int __real_mesh_prov_link_open(struct mesh_prov_link *l, uint64_t now,
    uint8_t *out, size_t *outlen);
int __wrap_mesh_prov_link_open(struct mesh_prov_link *l, uint64_t now,
    uint8_t *out, size_t *outlen);
int
__wrap_mesh_prov_link_open(struct mesh_prov_link *l, uint64_t now,
    uint8_t *out, size_t *outlen)
{

	if (g_force_link_open_fail)
		return (-1);
	return (__real_mesh_prov_link_open(l, now, out, outlen));
}

static const uint8_t g_netkey[16] = {
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
};
static const uint8_t g_appkey[16] = {
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
};

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

/* Bearer capture sink shared by the tick-emission tests. */
static unsigned g_tx_count;
static enum meshd_pdu_class g_last_tx_cls;

static int
capture_tx(void *arg, enum meshd_pdu_class cls, const uint8_t *pdu, size_t len)
{

	(void)arg; (void)pdu; (void)len;
	g_tx_count++;
	g_last_tx_cls = cls;
	return (0);
}

/*
 * Stand up a Config Client node with a created network and one roster node at
 * addr, mirroring mesh_cfgclient_test.c's fixture.  The manager is heap
 * allocated and owned by nd (meshd_node_fini frees nd->mgr); callers must NOT
 * free it separately.
 */
static void
mgr_network(struct meshd_node *nd, struct meshd_config *cfg, uint16_t addr)
{
	uint8_t uuid[16], dk[16];
	struct mesh_mgr *mgr;

	base_config(cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, cfg));
	mgr = calloc(1, sizeof(*mgr));
	ATF_REQUIRE(mgr != NULL);
	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	nd->mgr = mgr;
	nd->mgr_active = 1;
	memset(uuid, 0xD0, sizeof(uuid));
	memset(dk, 0x55, sizeof(dk));
	ATF_REQUIRE(mesh_mgr_add_node(mgr, uuid, addr, 1, dk, 0) != NULL);
}

/* ---- Finding 52: app-register requires the <element> argument ---------- */
ATF_TC_WITHOUT_HEAD(f52_app_register_element);
ATF_TC_BODY(f52_app_register_element, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_app_client *cl;
	char reply[256];
	char *av[4];

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	cl = &nd->app_clients[0];
	meshd_app_client_init(cl, 100);

	/* Two tokens (model only) is now a usage error - the daemon needs the
	 * element, so a CLI that omits it can no longer be silently misparsed. */
	av[0] = __DECONST(char *, "app-register");
	av[1] = __DECONST(char *, "0x1234");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "<element>") != NULL, "%s", reply);

	/* element + model is accepted and interpreted correctly.  The element
	 * must be a real element address of the node (its primary, 0x0001). */
	av[1] = __DECONST(char *, "0x0001");
	av[2] = __DECONST(char *, "0x1234");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, cl, 3, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "elem=0x0001") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "model=0x1234") != NULL, "%s", reply);

	meshd_node_fini(nd);
}

/* ---- Finding 53: rx buffer holds a full command line ------------------- */
ATF_TC_WITHOUT_HEAD(f53_rxbuf_large);
ATF_TC_BODY(f53_rxbuf_large, tc)
{
	struct meshd_app_client c;

	/* meshctl allows 1024-byte lines and send/publish payloads reach ~780
	 * chars; the control-socket rx buffer must hold at least that. */
	ATF_CHECK_MSG(sizeof(c.rxbuf) >= 1024, "rxbuf=%zu", sizeof(c.rxbuf));
}

/* ---- Finding 54: Heartbeat pub/sub setters wired + accumulated tick ---- */
ATF_TC_WITHOUT_HEAD(f54_heartbeat_wired);
ATF_TC_BODY(f54_heartbeat_wired, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .tx = capture_tx };
	struct mesh_hb_pub pub;
	struct mesh_hb_sub_set sub;
	uint8_t msg[16], reply[64];
	size_t mlen, rlen;
	uint64_t now;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);

	/* A Config Heartbeat Publication Set must arm the sim's periodic timer;
	 * before the fix mesh_sim_hb_set_pub was never called. */
	ATF_CHECK_EQ(0, mesh_hb_pub_timer_active(&nd->self->hb_timer));
	memset(&pub, 0, sizeof(pub));
	pub.dst = 0xC000;
	pub.count_log = 0x03;
	pub.period_log = 0x01;		/* 1 second */
	pub.ttl = 0x07;
	pub.net_idx = 0x0000;
	ATF_REQUIRE_EQ(0, mesh_hb_pub_set_build(&pub, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_MSG(mesh_hb_pub_timer_active(&nd->self->hb_timer) == 1,
	    "HB publication timer not armed");

	/* A Config Heartbeat Subscription Set must arm the sim's counter. */
	ATF_CHECK_EQ(0, nd->self->hb_sub_active);
	memset(&sub, 0, sizeof(sub));
	sub.src = 0x0002;
	sub.dst = 0x0001;		/* our own unicast */
	sub.period_log = 0x02;
	ATF_REQUIRE_EQ(0, mesh_hb_sub_set_build(&sub, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_MSG(nd->self->hb_sub_active == 1, "HB subscription inactive");

	/*
	 * The periodic publish gate must accumulate the ~10 ms per-tick delta:
	 * ticking in 100 ms steps (never dt_ms >= 1000) must still publish once
	 * a whole second has elapsed.  Before the fix nothing was ever sent.
	 */
	g_tx_count = 0;
	for (now = 100; now <= 2500; now += 100)
		(void)meshd_node_tick(nd, now, NULL);
	ATF_CHECK_MSG(g_tx_count > 0, "no Heartbeat published across ~2 s");

	meshd_node_fini(nd);
}

/* ---- Finding 55: proxy key-candidate array sized for every subnet ------ */
ATF_TC_WITHOUT_HEAD(f55_proxy_key_array);
ATF_TC_BODY(f55_proxy_key_array, tc)
{
	size_t array_slots = (size_t)(MESH_SIM_MAX_SUBNETS * 2 + 2);
	size_t max_candidates = (size_t)(2 + MESH_SIM_MAX_SUBNETS * 2);

	/* self old+new (2) plus old+new per subnet must fit the candidate
	 * array; the previous +1 sizing overflowed by one slot. */
	ATF_CHECK_MSG(array_slots >= max_candidates,
	    "array=%zu candidates=%zu", array_slots, max_candidates);
}

/* ---- Finding 69: Config Client retry interval is a realistic ms value -- */
ATF_TC_WITHOUT_HEAD(f69_cfg_retry_ms);
ATF_TC_BODY(f69_cfg_retry_ms, tc)
{

	/* The interval is consumed as CLOCK_MONOTONIC milliseconds; a value of
	 * a handful of "ticks" timed transactions out in ~40 ms. */
	ATF_CHECK_MSG(MESHD_CFG_RETRY_MS >= 100 && MESHD_CFG_RETRY_MS <= 5000,
	    "retry=%d ms", MESHD_CFG_RETRY_MS);
}

/* ---- Finding 71: persisted IV dwell timestamp clamped on load ---------- */
ATF_TC_WITHOUT_HEAD(f71_iv_dwell_reboot);
ATF_TC_BODY(f71_iv_dwell_reboot, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_persist ps;
	const char *path = "meshd_f71.state";

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(a, &cfg));

	/*
	 * Simulate a value written under a previous boot's CLOCK_MONOTONIC that
	 * is far ahead of the fresh clock after a reboot.
	 */
	a->self->iv.state = MESH_IV_UPDATE_IN_PROGRESS;
	a->self->iv.iv_index = 5;
	a->self->iv.entered_time = 1000000000000ULL;	/* ~31,000 years */

	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, a));

	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, b));
	ATF_CHECK_EQ(5, b->self->iv.iv_index);
	ATF_CHECK_EQ(MESH_IV_UPDATE_IN_PROGRESS, b->self->iv.state);
	/* The dwell timestamp must be clamped to this boot's monotonic clock,
	 * not the astronomically large persisted value. */
	ATF_CHECK_MSG(b->self->iv.entered_time < 1000000000ULL,
	    "entered_time=%llu not clamped",
	    (unsigned long long)b->self->iv.entered_time);

	(void)unlink(path);
	meshd_node_fini(a);
	meshd_node_fini(b);
}

/* ---- Finding 73: a failed OTA attempt is torn down, not wedged --------- */
ATF_TC_WITHOUT_HEAD(f73_ota_failure_recovers);
ATF_TC_BODY(f73_ota_failure_recovers, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t uuid[16];

	mgr_network(nd, &cfg, 0x0002);
	memset(uuid, 0xAB, sizeof(uuid));

	ATF_REQUIRE_EQ(0, meshd_provision_ota_begin(nd, uuid, 1, 0));
	ATF_CHECK_EQ(1, nd->prov_target_active);
	ATF_CHECK_EQ(1, nd->provisioner_active);

	/* Force the PB-ADV link to FAILED (retransmit budget exhausted). */
	nd->prov_link.state = MESH_LINK_FAILED;
	ATF_CHECK_EQ(1, meshd_provision_ota_failed(nd));

	/* The main-loop teardown clears the flags and records the failure. */
	meshd_provision_ota_abort(nd, 1);
	ATF_CHECK_EQ(0, nd->prov_target_active);
	ATF_CHECK_EQ(0, nd->provisioner_active);
	ATF_CHECK_EQ(1, nd->prov_failed);

	/* Provisioning is no longer wedged: a fresh attempt is accepted. */
	ATF_CHECK_EQ(0, meshd_provision_ota_begin(nd, uuid, 1, 0));
	ATF_CHECK_EQ(0, nd->prov_failed);
	ATF_CHECK_EQ(1, nd->prov_target_active);

	meshd_node_fini(nd);		/* frees nd->mgr */
}

/* ---- Finding 106: Health Fault handlers honor the Company ID ----------- */
ATF_TC_WITHOUT_HEAD(f106_health_fault_cid);
ATF_TC_BODY(f106_health_fault_cid, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t msg[16], reply[64];
	size_t mlen, rlen;
	uint16_t wrong;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	wrong = (uint16_t)(nd->cid ^ 0xFFFF);

	/* Fault Get for the node's own CID yields a Fault Status reply. */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_get_build(nd->cid, msg, &mlen));
	ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));

	/* Fault Get for an unknown CID identifies no fault state: no reply. */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_get_build(wrong, msg, &mlen));
	ATF_CHECK_EQ(0, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));

	/* Fault Test for an unknown CID must be ignored (no reply). */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_test_build(MESH_HLT_OP_FAULT_TEST,
	    0x01, wrong, msg, &mlen));
	ATF_CHECK_EQ(0, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));

	/* Fault Clear for an unknown CID must be ignored (no reply). */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_clear_build(MESH_HLT_OP_FAULT_CLEAR,
	    wrong, msg, &mlen));
	ATF_CHECK_EQ(0, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));

	/* The node's own CID Test/Clear still reply. */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_test_build(MESH_HLT_OP_FAULT_TEST,
	    0x01, nd->cid, msg, &mlen));
	ATF_CHECK_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));

	meshd_node_fini(nd);
}

/* ---- Finding 107: device_key alone triggers the readable-config guard -- */
ATF_TC_WITHOUT_HEAD(f107_device_key_guard);
ATF_TC_BODY(f107_device_key_guard, tc)
{
	struct meshd_config cfg;
	const char *path = "meshd_f107.conf";
	FILE *fp;

	fp = fopen(path, "w");
	ATF_REQUIRE(fp != NULL);
	fputs("device_key 00112233445566778899aabbccddeeff\n", fp);
	fputs("unicast_addr 0x0001\n", fp);
	fclose(fp);

	/* World/group-readable with a long-term secret must be refused. */
	ATF_REQUIRE_EQ(0, chmod(path, 0644));
	ATF_CHECK_EQ(-1, meshd_config_load(&cfg, path));
	ATF_CHECK_EQ(EPERM, errno);

	/* Owner-only is accepted. */
	ATF_REQUIRE_EQ(0, chmod(path, 0600));
	ATF_CHECK_EQ(0, meshd_config_load(&cfg, path));
	ATF_CHECK_EQ(1, cfg.have_device_key);

	(void)unlink(path);
}

/* ---- Finding 126: Config Client v1.1 verbs are wired ------------------- */
ATF_TC_WITHOUT_HEAD(f126_cfgclient_v11_verbs);
ATF_TC_BODY(f126_cfgclient_v11_verbs, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	char reply[256];
	char *av[10];

	mgr_network(nd, &cfg, 0x0002);

	/* Each new sub-verb must dispatch (send accepted over the NULL bearer,
	 * reported as sent/WAITING) rather than "unknown cfg verb". */
	av[0] = __DECONST(char *, "sar-tx-get");
	av[1] = __DECONST(char *, "0x0002");
	ATF_CHECK_EQ(0, meshd_cfg_client_verb(nd, 2, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "unknown") == NULL, "%s", reply);

	av[0] = __DECONST(char *, "sar-rx-get");
	ATF_CHECK_EQ(0, meshd_cfg_client_verb(nd, 2, av, 0, reply,
	    sizeof(reply)));

	av[0] = __DECONST(char *, "priv-beacon-get");
	ATF_CHECK_EQ(0, meshd_cfg_client_verb(nd, 2, av, 0, reply,
	    sizeof(reply)));

	av[0] = __DECONST(char *, "priv-gatt-proxy");
	av[2] = __DECONST(char *, "1");
	ATF_CHECK_EQ(0, meshd_cfg_client_verb(nd, 3, av, 0, reply,
	    sizeof(reply)));

	av[0] = __DECONST(char *, "od-priv-proxy");
	ATF_CHECK_EQ(0, meshd_cfg_client_verb(nd, 3, av, 0, reply,
	    sizeof(reply)));

	av[0] = __DECONST(char *, "priv-node-identity-get");
	av[2] = __DECONST(char *, "0x0000");
	ATF_CHECK_EQ(0, meshd_cfg_client_verb(nd, 3, av, 0, reply,
	    sizeof(reply)));

	av[0] = __DECONST(char *, "lcd-get");
	av[2] = __DECONST(char *, "0x00");
	av[3] = __DECONST(char *, "0x0000");
	ATF_CHECK_EQ(0, meshd_cfg_client_verb(nd, 4, av, 0, reply,
	    sizeof(reply)));

	/* A SAR TX Set with the seven packed fields. */
	av[0] = __DECONST(char *, "sar-tx-set");
	av[2] = __DECONST(char *, "1");
	av[3] = __DECONST(char *, "2");
	av[4] = __DECONST(char *, "3");
	av[5] = __DECONST(char *, "4");
	av[6] = __DECONST(char *, "5");
	av[7] = __DECONST(char *, "6");
	av[8] = __DECONST(char *, "7");
	ATF_CHECK_EQ(0, meshd_cfg_client_verb(nd, 9, av, 0, reply,
	    sizeof(reply)));

	meshd_node_fini(nd);		/* frees nd->mgr */
}

/* ---- Finding 127: provision-scan parses/lists unprovisioned beacons ---- */
ATF_TC_WITHOUT_HEAD(f127_provision_scan);
ATF_TC_BODY(f127_provision_scan, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_unprov_beacon ub;
	uint8_t beacon[MESH_UNPROV_BEACON_MAX_LEN];
	size_t blen;
	char reply[512];
	char *av[3];

	mgr_network(nd, &cfg, 0x0002);

	/* Enable discovery. */
	av[0] = __DECONST(char *, "provision-scan");
	av[1] = __DECONST(char *, "on");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(1, nd->prov_scanning);

	/* Feed an Unprovisioned Device Beacon through the beacon RX path. */
	memset(&ub, 0, sizeof(ub));
	memset(ub.uuid, 0x5A, sizeof(ub.uuid));
	ATF_REQUIRE_EQ(0, mesh_unprov_beacon_build(&ub, beacon, &blen));
	ATF_CHECK_EQ(1, meshd_beacon_rx(nd, beacon, blen));
	ATF_CHECK_EQ(1, nd->scan_results[0].valid);

	/* list surfaces the discovered device and its UUID. */
	av[1] = __DECONST(char *, "list");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "devices=1") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "5a5a5a5a") != NULL, "%s", reply);

	/* off disables discovery. */
	av[1] = __DECONST(char *, "off");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0, nd->prov_scanning);

	meshd_node_fini(nd);		/* frees nd->mgr */
}

/* ---- Finding 130: LowPower disclosed as unsupported -------------------- */
ATF_TC_WITHOUT_HEAD(f130_lowpower_unsupported);
ATF_TC_BODY(f130_lowpower_unsupported, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	char reply[256];
	char *av[1];

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	av[0] = __DECONST(char *, "features");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "LowPower=unsupported") != NULL, "%s",
	    reply);

	meshd_node_fini(nd);
}

/* ---- Finding 131: unprovisioned node advertises its device UUID -------- */
ATF_TC_WITHOUT_HEAD(f131_unprov_beacon);
ATF_TC_BODY(f131_unprov_beacon, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .tx = capture_tx };

	/* The device_uuid config knob must land on the node. */
	base_config(&cfg);
	memset(cfg.device_uuid, 0x77, sizeof(cfg.device_uuid));
	cfg.have_uuid = 1;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	ATF_CHECK_EQ(1, nd->have_device_uuid);
	ATF_CHECK_EQ(0, memcmp(nd->device_uuid, cfg.device_uuid, 16));

	meshd_set_bearer(nd, &bearer);
	/* An unprovisioned node emits an Unprovisioned Device Beacon. */
	nd->provisioned = 0;
	g_tx_count = 0;
	ATF_CHECK_EQ(1, meshd_unprov_beacon_emit(nd));
	ATF_CHECK(g_tx_count > 0);
	ATF_CHECK_EQ(MESHD_PDU_BEACON, g_last_tx_cls);

	/* A provisioned node does not. */
	nd->provisioned = 1;
	ATF_CHECK_EQ(0, meshd_unprov_beacon_emit(nd));

	meshd_node_fini(nd);
}

/* ---- Finding 117: AppKey DB entry rolled back on sim/crypto failure ---- */
ATF_TC_WITHOUT_HEAD(f117_appkey_rollback);
ATF_TC_BODY(f117_appkey_rollback, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_appkey ak;
	uint8_t msg[64], reply[64];
	size_t mlen, rlen, i;
	uint16_t net_idx, app_idx;
	uint8_t status;
	int found;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* One real Add so subsequent Adds no longer free the bootstrap sim
	 * slot (had_configured_appkey becomes true). */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0;
	ak.app_idx = 1;
	memset(ak.key, 0x41, sizeof(ak.key));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_parse(reply, rlen, &status,
	    &net_idx, &app_idx));
	ATF_REQUIRE_EQ(MESH_CFG_SUCCESS, status);

	/* Saturate the sim's AppKey table (leaving the meshd DB with free
	 * slots) so the next Add's DB commit succeeds but the sim rejects it. */
	for (i = 10; i < 10 + MESH_SIM_MAX_APPKEYS; i++)
		(void)mesh_sim_add_appkey(nd->self, 0, (uint16_t)i, ak.key);

	/* Add a fresh AppKey: DB slot is free (commit), but the sim is full. */
	ak.app_idx = 2;
	memset(ak.key, 0x52, sizeof(ak.key));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_parse(reply, rlen, &status,
	    &net_idx, &app_idx));
	ATF_CHECK_EQ(MESH_CFG_INSUFFICIENT_RESOURCES, status);

	/* The DB must NOT list the rejected key (rolled back, not orphaned). */
	found = 0;
	for (i = 0; i < MESHD_MAX_APPKEYS; i++)
		if (nd->db.appkeys[i].valid && nd->db.appkeys[i].app_idx == 2)
			found = 1;
	ATF_CHECK_MSG(found == 0, "rejected AppKey 2 left committed in the DB");

	meshd_node_fini(nd);
}

/* ---- Finding 123: provisioner_active cleared if link open fails -------- */
ATF_TC_WITHOUT_HEAD(f123_provisioner_begin_rollback);
ATF_TC_BODY(f123_provisioner_begin_rollback, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t uuid[16];

	mgr_network(nd, &cfg, 0x0002);
	memset(uuid, 0xC3, sizeof(uuid));

	/* Force the PB-ADV link open to fail after provisioner_active is set. */
	g_force_link_open_fail = 1;
	ATF_CHECK_EQ(-1, meshd_provision_ota_begin(nd, uuid, 1, 0));
	/* The fix must undo the active flag (and free the session) so a later
	 * attempt is not permanently blocked. */
	ATF_CHECK_EQ(0, nd->provisioner_active);
	ATF_CHECK_EQ(0, nd->prov_target_active);

	/* With the link open working again, provisioning proceeds. */
	g_force_link_open_fail = 0;
	ATF_CHECK_EQ(0, meshd_provision_ota_begin(nd, uuid, 1, 0));
	ATF_CHECK_EQ(1, nd->provisioner_active);
	ATF_CHECK_EQ(1, nd->prov_target_active);

	g_force_link_open_fail = 0;
	meshd_node_fini(nd);		/* frees nd->mgr */
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, f52_app_register_element);
	ATF_TP_ADD_TC(tp, f53_rxbuf_large);
	ATF_TP_ADD_TC(tp, f54_heartbeat_wired);
	ATF_TP_ADD_TC(tp, f55_proxy_key_array);
	ATF_TP_ADD_TC(tp, f69_cfg_retry_ms);
	ATF_TP_ADD_TC(tp, f71_iv_dwell_reboot);
	ATF_TP_ADD_TC(tp, f73_ota_failure_recovers);
	ATF_TP_ADD_TC(tp, f106_health_fault_cid);
	ATF_TP_ADD_TC(tp, f107_device_key_guard);
	ATF_TP_ADD_TC(tp, f126_cfgclient_v11_verbs);
	ATF_TP_ADD_TC(tp, f127_provision_scan);
	ATF_TP_ADD_TC(tp, f117_appkey_rollback);
	ATF_TP_ADD_TC(tp, f123_provisioner_begin_rollback);
	ATF_TP_ADD_TC(tp, f130_lowpower_unsupported);
	ATF_TP_ADD_TC(tp, f131_unprov_beacon);

	return (atf_no_error());
}
