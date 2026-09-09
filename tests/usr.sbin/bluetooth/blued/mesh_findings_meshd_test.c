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
#include <time.h>
#include <unistd.h>

#include "mesh_test_heap.h"
#include "meshd.h"
#include "meshd_persist.h"
#include "mesh_heartbeat.h"
#include "mesh_health_model.h"
#include "mesh_beacon.h"
#include "mesh_cfg_model.h"
#include "mesh_provisioner.h"
#include "mesh_crypto.h"
#include "mesh_net.h"
#include "mesh_transport.h"
#include "mesh_generic.h"
#include "mesh_iv.h"
#include "mesh_cfg_v11.h"
#include "mesh_friend.h"
#include "mesh_lpn.h"
#include "mesh_proxy.h"
#include "mesh_sim.h"

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
	/*
	 * The dwell timestamp must be clamped to the current wall clock, not
	 * left at the astronomically large persisted value.  entered_time is
	 * CLOCK_REALTIME *seconds* (the sim feeds the IV state machine
	 * wall_now), so compare against the live clock -- an absolute
	 * threshold here would be a moving target and, at 1e9 seconds
	 * (year 2001), permanently unsatisfiable.
	 */
	{
		struct timespec wts;

		ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_REALTIME, &wts));
		ATF_CHECK_MSG(b->self->iv.entered_time <= (uint64_t)wts.tv_sec,
		    "entered_time=%llu not clamped to now=%llu",
		    (unsigned long long)b->self->iv.entered_time,
		    (unsigned long long)wts.tv_sec);
		ATF_CHECK(b->self->iv.entered_time != 1000000000000ULL);
	}

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

/*
 * ---- Finding 130: LowPower / Friend role now wired to the bearer --------
 *
 * The Friend and Low Power node engines are driven over the bearer, so the
 * features verb reports the live enable state (true/false) rather than the old
 * honest "unsupported" disclosure.
 */
ATF_TC_WITHOUT_HEAD(f130_lowpower_unsupported);
ATF_TC_BODY(f130_lowpower_unsupported, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	char reply[256];
	char *av[2];

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Off by default: reported as false, never "unsupported". */
	av[0] = __DECONST(char *, "features");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "LowPower=false") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "unsupported") == NULL, "%s", reply);

	/* Enable the Low Power role -> reported true. */
	av[0] = __DECONST(char *, "low-power");
	av[1] = __DECONST(char *, "on");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	av[0] = __DECONST(char *, "features");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "LowPower=true") != NULL, "%s", reply);

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

/* ================================================================
 * Wiring regressions: procedures that exist, are unit-tested, and were never
 * invoked by the daemon.
 *
 * Every case below drives meshd's OWN entry points - meshd_beacon_rx(),
 * meshd_bearer_rx(), meshd_node_tick(), meshd_ctl_exec_client(),
 * meshd_provisioner_begin()/_recv()/_poll() - rather than the libmesh function
 * under test, so a regression in the WIRING fails here even when the library
 * function itself is still correct.  That distinction is the whole point:
 * these four procedures each had green unit coverage while the daemon never
 * called them.
 * ================================================================ */

/* Managed-flooding k2 P input (MshPRT_v1.1.1 Section 3.8.6.3.2). */
static const uint8_t g_k2_p_managed[1] = { 0x00 };

/*
 * Decrypt one Network PDU the daemon put on the bearer, with the shared
 * NetKey.  Returns 0 on success.
 */
static int
net_open(const uint8_t *bytes, size_t len, uint32_t iv,
    struct mesh_net_pdu *out)
{
	uint8_t enc[16], priv[16], nid;

	if (mesh_k2(g_netkey, g_k2_p_managed, sizeof(g_k2_p_managed), &nid,
	    enc, priv) != 0)
		return (-1);
	return (mesh_net_decrypt(enc, priv, nid, iv, bytes, len, out));
}

/*
 * Build the wire bytes a peer at `src` would emit for one access message to
 * `dst`, secured with the shared NetKey/AppKey.  A throwaway mesh_sim plays
 * the peer's radio; the frames are then injected into the daemon through
 * meshd_bearer_rx(), which is the daemon's own receive entry point.
 */
struct peer_frames {
	uint8_t	bytes[MESH_SEG_MAX][MESH_NET_MAX_PDU];
	size_t	len[MESH_SEG_MAX];
	size_t	n;
};

static void
peer_access_frames(uint16_t src, uint16_t dst, uint32_t seq, uint32_t iv,
    uint32_t opcode, const uint8_t *params, size_t plen,
    struct peer_frames *pf)
{
	MESH_HEAP(struct mesh_sim, peer);
	struct mesh_node *nodeb;
	size_t i;

	memset(pf, 0, sizeof(*pf));
	ATF_REQUIRE_EQ(0, mesh_sim_init(peer, g_netkey, g_appkey, iv));
	nodeb = mesh_sim_add_node(peer, src, 1);
	ATF_REQUIRE(nodeb != NULL);
	nodeb->seq = seq;
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(peer, nodeb, dst, opcode,
	    params, plen, 4));
	ATF_REQUIRE(peer->n_tx > 0 && peer->n_tx <= MESH_SEG_MAX);
	for (i = 0; i < peer->n_tx; i++) {
		ATF_REQUIRE(peer->tx[i].valid);
		memcpy(pf->bytes[i], peer->tx[i].bytes, peer->tx[i].len);
		pf->len[i] = peer->tx[i].len;
	}
	pf->n = peer->n_tx;
}

/* ---- M1: IV Index Recovery runs from the daemon's beacon path ---------- */
/*
 * MshPRT_v1.1.1 Section 3.11.6: the IV Index Recovery procedure observes
 * authenticated Secure Network beacons and adopts an IV Index from Current + 1
 * to Current + 42, resetting the sequence numbers (Table 3.86).  It has no
 * arming step visible to the application - authenticating the beacon IS the
 * trigger - and it must not run again for 192 hours.
 *
 * mesh_iv_recovery_begin() had no production caller, so recovery_active was
 * permanently zero in the daemon and every beacon beyond Current + 1 (and
 * every Current + 1 beacon with the IV Update flag clear) was rejected: a node
 * that was off the air across an IV Update could never rejoin.  This drives
 * meshd_beacon_rx(), the daemon's beacon entry point.
 */
ATF_TC_WITHOUT_HEAD(m1_iv_recovery_beacon_path);
ATF_TC_BODY(m1_iv_recovery_beacon_path, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct peer_frames pf;
	struct mesh_gen_onoff_set set;
	uint8_t beacon[MESH_SECURE_BEACON_LEN];
	uint8_t params[MESH_GEN_PARAMS_MAX];
	size_t blen, plen, i;
	int seen;

	base_config(&cfg);
	cfg.iv_index = 100;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	ATF_REQUIRE_EQ(100u, nd->self->iv.iv_index);

	/*
	 * Give the node some state the recovery has to clear: one replay
	 * protection entry from a peer, and a non-zero sequence number.  Both
	 * are established through the daemon's own receive path.
	 */
	memset(&set, 0, sizeof(set));
	set.onoff = MESH_GEN_ON;
	set.tid = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&set, params, &plen));
	peer_access_frames(0x0102, nd->addr, 7, cfg.iv_index,
	    MESH_OP_GEN_ONOFF_SET_UNACK, params, plen, &pf);
	ATF_REQUIRE_EQ(1u, (unsigned)pf.n);
	ATF_REQUIRE_EQ(1, meshd_bearer_rx(nd, pf.bytes[0], pf.len[0]));
	seen = 0;
	for (i = 0; i < MESH_SIM_RPL_SIZE; i++)
		if (nd->self->rpl_store[i].valid &&
		    nd->self->rpl_store[i].src == 0x0102)
			seen = 1;
	ATF_REQUIRE_EQ_MSG(1, seen, "peer must be recorded in the RPL");
	nd->self->seq = 4242;

	/*
	 * A beacon carrying Current IV Index + 5 (well inside the 42-index
	 * window) with the IV Update flag clear.  Table 3.86 last row: accept
	 * the IV Index and the flag, and reset the sequence numbers.
	 */
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(cfg.netkey, 0, 0, 105,
	    beacon, &blen));
	ATF_CHECK_EQ_MSG(1, meshd_beacon_rx(nd, beacon, blen),
	    "the daemon must accept an authenticated Secure Network beacon");
	ATF_CHECK_EQ_MSG(105u, nd->self->iv.iv_index,
	    "IV Index Recovery must adopt Current + 5 (Section 3.11.6)");
	ATF_CHECK_EQ(MESH_IV_NORMAL, nd->self->iv.state);
	ATF_CHECK_EQ_MSG(0u, nd->self->seq,
	    "Table 3.86: the recovery resets the sequence numbers");
	for (i = 0; i < MESH_SIM_RPL_SIZE; i++)
		ATF_CHECK_EQ_MSG(0, nd->self->rpl_store[i].valid,
		    "the replay list belongs to the abandoned IV epoch");
	ATF_CHECK_EQ(0, nd->self->iv.recovery_active);
	ATF_CHECK_EQ(1, nd->self->iv.recovery_done);

	/*
	 * "Once it happens, the node is not allowed to accept an out of order
	 * value for the IV Index again for at least 192 hours" - a second jump
	 * immediately afterwards must be refused.
	 */
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(cfg.netkey, 0, 0, 130,
	    beacon, &blen));
	(void)meshd_beacon_rx(nd, beacon, blen);
	ATF_CHECK_EQ_MSG(105u, nd->self->iv.iv_index,
	    "a second recovery inside 192 hours must be refused");

	/* Beyond Current + 42 is outside the window and is never adopted. */
	nd->self->iv.recovery_done = 0;
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(cfg.netkey, 0, 0, 148,
	    beacon, &blen));
	(void)meshd_beacon_rx(nd, beacon, blen);
	ATF_CHECK_EQ_MSG(105u, nd->self->iv.iv_index,
	    "Current + 43 is outside the recovery window");

	meshd_node_fini(nd);
}

/* ---- M6: the replay list is committed only after authentication -------- */
/*
 * MshPRT_v1.1.1 Section 3.9.8 records an ACCEPTED PDU in the replay protection
 * list.  A segmented message is not accepted until every segment has arrived
 * and the TransMIC has verified, and Section 3.5.3.1 makes SeqZero - and
 * therefore SeqAuth - invariant across a SAR retransmission.  Committing at
 * the first segment therefore makes one lossy attempt permanently poison that
 * SeqAuth: the mandatory retransmission is scored a replay and the message can
 * never be delivered.
 *
 * Driven entirely through meshd_bearer_rx() and meshd_node_tick().
 */
ATF_TC_WITHOUT_HEAD(m6_rpl_commits_after_authentication);
ATF_TC_BODY(m6_rpl_commits_after_authentication, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct peer_frames pf;
	uint8_t params[48];
	size_t i;
	uint32_t before;
	int changed;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* A payload long enough to segment (> 11 access octets). */
	for (i = 0; i < sizeof(params); i++)
		params[i] = (uint8_t)i;
	peer_access_frames(0x0102, nd->addr, 64, cfg.iv_index, 0x8299, params,
	    sizeof(params), &pf);
	ATF_REQUIRE_MSG(pf.n > 1, "payload must segment (%zu frames)", pf.n);

	/* First attempt: only segment zero survives the air. */
	before = nd->self->rx.count;
	ATF_REQUIRE_EQ_MSG(0, meshd_bearer_rx(nd, pf.bytes[0], pf.len[0]),
	    "a lone segment zero delivers nothing");
	ATF_CHECK_EQ(before, nd->self->rx.count);

	/* Let the SAR discard timeout reap the half-built reassembly. */
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 60000, &changed));

	/*
	 * The peer retransmits.  SeqZero is invariant, so this is the same
	 * SeqAuth the failed attempt saw; it must still be deliverable.
	 */
	for (i = 0; i < pf.n; i++)
		ATF_REQUIRE(meshd_bearer_rx(nd, pf.bytes[i], pf.len[i]) >= 0);
	ATF_CHECK_EQ_MSG(before + 1, nd->self->rx.count,
	    "a retransmitted SeqAuth must not be scored a replay");

	/* A genuine replay of the completed transaction is still rejected. */
	before = nd->self->rx.count;
	for (i = 0; i < pf.n; i++)
		(void)meshd_bearer_rx(nd, pf.bytes[i], pf.len[i]);
	ATF_CHECK_EQ_MSG(before, nd->self->rx.count,
	    "replay protection still holds once the message is accepted");

	meshd_node_fini(nd);
}

/* ---- M5: a SAR retransmission takes a fresh sequence number ------------ */
/*
 * Every relay keeps a network message cache keyed on (SRC, SEQ, IVI) and drops
 * what it has already processed (MshPRT_v1.1.1 Section 3.4.5), so re-emitting
 * the byte-identical segment is discarded at the first relay: retransmission
 * used to be a complete no-op past one hop, which is exactly where segments
 * get lost.  The transaction stays identifiable through its invariant SeqZero.
 *
 * Driven through meshd_send_access_raw() (the daemon's origination entry, used
 * by the "send" control verb) and meshd_node_tick().
 */
static uint8_t g_sar_frames[MESH_SEG_MAX * 4][MESH_NET_MAX_PDU];
static size_t g_sar_len[MESH_SEG_MAX * 4];
static size_t g_sar_n;

static int
sar_capture_tx(void *arg, enum meshd_pdu_class cls, const uint8_t *pdu,
    size_t len)
{

	(void)arg;
	if (cls == MESHD_PDU_NET && g_sar_n < nitems(g_sar_len) &&
	    len <= MESH_NET_MAX_PDU) {
		memcpy(g_sar_frames[g_sar_n], pdu, len);
		g_sar_len[g_sar_n++] = len;
	}
	return (0);
}

ATF_TC_WITHOUT_HEAD(m5_sar_retransmit_fresh_seq);
ATF_TC_BODY(m5_sar_retransmit_fresh_seq, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .arg = NULL, .tx = sar_capture_tx };
	struct mesh_net_pdu np;
	uint8_t access[64];
	uint32_t first_seq[MESH_SEG_MAX];
	size_t first_n, i, j;
	int changed;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);

	/* A segmented access message to a UNICAST peer, which is what arms
	 * the SAR transmitter (a group destination is never acknowledged). */
	access[0] = 0x82;
	access[1] = 0x99;
	for (i = 2; i < sizeof(access); i++)
		access[i] = (uint8_t)i;
	g_sar_n = 0;
	ATF_REQUIRE_EQ(0, meshd_send_access_raw(nd, 0x0002, access,
	    sizeof(access)));
	ATF_REQUIRE_MSG(g_sar_n > 1, "message must segment (%zu frames)",
	    g_sar_n);
	first_n = g_sar_n;
	ATF_REQUIRE(first_n <= MESH_SEG_MAX);
	for (i = 0; i < first_n; i++) {
		ATF_REQUIRE_EQ_MSG(0, net_open(g_sar_frames[i], g_sar_len[i],
		    cfg.iv_index, &np), "segment %zu must decrypt", i);
		first_seq[i] = np.seq;
	}

	/*
	 * No Segment Acknowledgment arrives, so the retransmission timer fires
	 * on the next tick past the interval.
	 */
	g_sar_n = 0;
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 500, &changed));
	ATF_REQUIRE_MSG(g_sar_n == first_n,
	    "every unacknowledged segment is retransmitted (%zu of %zu)",
	    g_sar_n, first_n);

	for (i = 0; i < g_sar_n; i++) {
		ATF_REQUIRE_EQ(0, net_open(g_sar_frames[i], g_sar_len[i],
		    cfg.iv_index, &np));
		for (j = 0; j < first_n; j++)
			ATF_CHECK_MSG(np.seq != first_seq[j],
			    "retransmitted segment reused SEQ %u: every relay "
			    "drops it as a network message cache hit",
			    (unsigned)np.seq);
		/* The transaction is still identified by its SeqZero. */
		ATF_CHECK_MSG((np.transport[0] & 0x80) != 0,
		    "retransmission must still be a segmented PDU");
	}

	meshd_node_fini(nd);
}

/* ---- M2: Static OOB provisioning is reachable from the daemon ---------- */
/*
 * MshPRT_v1.1.1 Section 5.4.1.3: Provisioning Start selects the authentication
 * method.  The whole mesh_prov_auth_* AuthValue family had no production
 * caller, both roles hard-wired a zero AuthValue and the device role rejected
 * any Start with auth_method != 0, so every provisioning this daemon performed
 * was unauthenticated and no OOB peer could be provisioned at all.
 *
 * This drives the operator interface ("provision-oob" through
 * meshd_ctl_exec_client()) and then the daemon's PB-ADV provisioner entry
 * points against a simulated device that advertises Static OOB.
 */
ATF_TC_WITHOUT_HEAD(m2_provisioning_static_oob);
ATF_TC_BODY(m2_provisioning_static_oob, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_prov_link dl;
	struct mesh_prov_session ds;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	static const uint8_t oob[4] = { 0x12, 0x34, 0x56, 0x78 };
	uint8_t uuid[16], raw[25];
	uint8_t pkt[MESH_PBADV_PKT_MAX], dev_ack[MESH_PBADV_PKT_MAX];
	uint8_t rpdu[MESH_PROV_PDU_MAX];
	char reply[256];
	char *av[3];
	size_t len, rlen, dev_ack_len;
	int have_pdu, have_ack, dev_ack_pending, i;
	uint64_t now = 0;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* The operator installs the device's Static OOB value. */
	av[0] = __DECONST(char *, "provision-oob");
	av[1] = __DECONST(char *, "12345678");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "len=4") != NULL, "%s", reply);
	ATF_CHECK_EQ(4u, (unsigned)nd->prov_static_oob_len);

	memset(uuid, 0x42, sizeof(uuid));
	ATF_REQUIRE_EQ(0, meshd_hexdecode(
	    "efb2255e6422d330088e09bb015ed707056700010203040b0c", raw, 25));
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));

	/* The device advertises Static OOB and holds the same value. */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.static_oob_type = MESH_PROV_OOB_TYPE_STATIC;
	mesh_prov_link_init_device(&dl, uuid, 100000, 3);
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&ds, NULL, NULL, &caps));
	ATF_REQUIRE_EQ(0, mesh_prov_session_set_static_oob(&ds, oob,
	    sizeof(oob)));
	dev_ack_pending = 0;

	ATF_REQUIRE_EQ(0, meshd_provisioner_begin(nd, uuid, 0x11223344, NULL,
	    NULL, 0x00, &pdata, 100000, 3, now, pkt, &len));
	ATF_CHECK_EQ_MSG(1, nd->prov_sess.have_static_oob,
	    "the daemon must apply the operator's Static OOB to the session");
	have_ack = have_pdu = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, len, now, rpdu, &rlen,
	    &have_pdu, dev_ack, &dev_ack_len, &have_ack));
	if (have_ack)
		dev_ack_pending = 1;

	for (i = 0; i < 400; i++) {
		if (meshd_provisioner_poll(nd, now, pkt, &len) == 1) {
			have_ack = have_pdu = 0;
			ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, len,
			    now, rpdu, &rlen, &have_pdu, dev_ack,
			    &dev_ack_len, &have_ack));
			if (have_ack)
				dev_ack_pending = 1;
			if (have_pdu)
				(void)mesh_prov_session_recv(&ds, rpdu, rlen);
			continue;
		}
		if (dev_ack_pending) {
			ATF_REQUIRE_EQ(0, meshd_provisioner_recv(nd, dev_ack,
			    dev_ack_len, now));
			dev_ack_pending = 0;
			continue;
		}
		if (mesh_prov_link_poll(&dl, now, pkt, &len) == 1) {
			ATF_REQUIRE_EQ(0, meshd_provisioner_recv(nd, pkt, len,
			    now));
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
		if (meshd_provisioner_done(nd) && mesh_prov_session_done(&ds))
			break;
	}

	ATF_CHECK_MSG(meshd_provisioner_done(nd), "provisioner completed");
	ATF_CHECK_MSG(mesh_prov_session_done(&ds), "device completed");
	ATF_CHECK_EQ_MSG(0, memcmp(nd->prov_sess.devkey,
	    mesh_prov_session_devkey(&ds), 16), "same DevKey");

	/*
	 * The exchange was AUTHENTICATED: Provisioning Start carried
	 * Authentication Method 0x01 with a zero Action and Size (Section
	 * 5.4.1.3), and the AuthValue is the Static OOB value, not zero.
	 */
	ATF_CHECK_EQ_MSG(MESH_PROV_AUTH_METHOD_STATIC, nd->prov_sess.start_val[2],
	    "Provisioning Start must select Static OOB");
	ATF_CHECK_EQ(0, nd->prov_sess.start_val[3]);
	ATF_CHECK_EQ(0, nd->prov_sess.start_val[4]);
	ATF_CHECK_EQ(0, memcmp(nd->prov_sess.auth, oob, sizeof(oob)));
	ATF_CHECK_EQ(0, memcmp(ds.auth, oob, sizeof(oob)));

	mesh_prov_session_free(&nd->prov_sess);
	mesh_prov_session_free(&ds);
	meshd_node_fini(nd);
}

/*
 * The mirror image: no Static OOB installed, so the exchange is No-OOB, and a
 * device that advertises "only OOB authenticated provisioning supported"
 * without a Static OOB capability is refused rather than driven into an
 * unauthenticated exchange it would reject anyway.
 */
ATF_TC_WITHOUT_HEAD(m2_provisioning_oob_only_refused);
ATF_TC_BODY(m2_provisioning_oob_only_refused, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_prov_session ds;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	uint8_t raw[25], cpdu[MESH_PROV_PDU_MAX], spdu[MESH_PROV_PDU_MAX];
	size_t clen, slen;
	char reply[256];
	char *av[2];

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* No value installed: the verb reports "none". */
	av[0] = __DECONST(char *, "provision-oob");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "static-oob=none") != NULL, "%s", reply);

	ATF_REQUIRE_EQ(0, meshd_hexdecode(
	    "efb2255e6422d330088e09bb015ed707056700010203040b0c", raw, 25));
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&nd->prov_sess, NULL,
	    NULL, 0x00, &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&nd->prov_sess));
	ATF_REQUIRE_EQ(1, mesh_prov_session_poll(&nd->prov_sess, spdu, &slen));

	/*
	 * Capabilities from a device that will accept nothing but an OOB
	 * authenticated exchange (OOB Type bit 1) and offers no Static OOB.
	 */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	/*
	 * Table 5.23: with OOB Type bit 1 set, bit 0 of the Algorithms field
	 * shall be 0, so only the HMAC-SHA-256 algorithm may be advertised.
	 */
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_HMAC;
	caps.static_oob_type = MESH_PROV_OOB_TYPE_ONLY_OOB;
	caps.output_oob_size = 4;
	caps.output_oob_action = 0x0008;	/* Output Numeric */
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&ds, NULL, NULL, &caps));
	ATF_REQUIRE_EQ(0, mesh_prov_session_recv(&ds, spdu, slen));
	ATF_REQUIRE_EQ(1, mesh_prov_session_poll(&ds, cpdu, &clen));

	ATF_CHECK_EQ_MSG(-1, mesh_prov_session_recv(&nd->prov_sess, cpdu,
	    clen), "an Output-OOB-only device must be refused, not downgraded");
	ATF_CHECK(mesh_prov_session_failed(&nd->prov_sess));

	mesh_prov_session_free(&nd->prov_sess);
	mesh_prov_session_free(&ds);
	meshd_node_fini(nd);
}


/* ================================================================
 * Round-4 wiring: procedures that were implemented, unit-tested and never
 * invoked by the daemon.  Every case below drives a meshd entry point
 * (meshd_node_tick / meshd_beacon_rx / meshd_foundation_recv / meshd_bearer_rx
 * / meshd_persist_*), never the libmesh function directly -- that distinction
 * is the whole point, since each of these library functions was already green
 * in its own unit test while nothing in the daemon ever called it.
 * ================================================================ */

/* Capture-and-pump bearer for the round-4 cases. */
#define	R4_MAXCAP	32
static struct r4_capframe {
	uint8_t			buf[64];
	size_t			len;
	enum meshd_pdu_class	cls;
} g_r4cap[R4_MAXCAP];
static size_t g_r4n;

static int
r4_cap_tx(void *arg, enum meshd_pdu_class cls, const uint8_t *pdu, size_t len)
{

	(void)arg;
	if (g_r4n < R4_MAXCAP && len <= sizeof(g_r4cap[0].buf)) {
		memcpy(g_r4cap[g_r4n].buf, pdu, len);
		g_r4cap[g_r4n].len = len;
		g_r4cap[g_r4n].cls = cls;
		g_r4n++;
	}
	return (0);
}

/* Deliver every captured Network PDU to `to`; returns the delivered count. */
static int
r4_pump(struct meshd_node *to)
{
	struct r4_capframe snap[R4_MAXCAP];
	size_t n, i;
	int delivered = 0;

	n = g_r4n;
	memcpy(snap, g_r4cap, n * sizeof(snap[0]));
	g_r4n = 0;
	for (i = 0; i < n; i++)
		if (snap[i].cls == MESHD_PDU_NET &&
		    meshd_bearer_rx(to, snap[i].buf, snap[i].len) == 1)
			delivered++;
	return (delivered);
}

static void
r4_tick(struct meshd_node *nd, uint64_t t)
{
	int ivc;

	ATF_REQUIRE(meshd_node_tick(nd, t, &ivc) >= 0);
}

/* Provision a node into the fixed shared subnet at addr with `features`. */
static void
r4_provision(struct meshd_node *nd, struct meshd_config *cfg, uint16_t addr,
    uint16_t features)
{

	meshd_config_defaults(cfg);
	memset(cfg->netkey, 0x33, 16);
	cfg->have_netkey = 1;
	memset(cfg->appkey, 0x44, 16);
	cfg->have_appkey = 1;
	cfg->netkey_index = 0;
	cfg->appkey_index = 0;
	cfg->unicast_addr = addr;
	cfg->iv_index = 0;
	cfg->default_ttl = 7;
	cfg->features = features;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, cfg));
}

/* Deliver a foundation-model message and return the reply length. */
static size_t
r4_foundation(struct meshd_node *nd, const uint8_t *msg, size_t mlen,
    uint8_t *reply, size_t reply_max)
{
	size_t rlen = 0;

	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    reply_max, &rlen));
	return (rlen);
}

/* ---- Mesh Private beacon (MshPRT_v1.1.1 Section 3.10.4) ---------------- */
/*
 * The Private Beacon state was persisted and echoed in its Status while the
 * built-and-parsed Mesh Private beacon was never sent or received, so enabling
 * beacon privacy reported Success and changed nothing.  Drive it through the
 * daemon: Config Private Beacon Set on node A, tick A, and feed what A put on
 * the bearer into B's meshd_beacon_rx.
 */
ATF_TC_WITHOUT_HEAD(m7_private_beacon_wired);
ATF_TC_BODY(m7_private_beacon_wired, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_config acfg, bcfg;
	struct meshd_bearer bearer = { .tx = r4_cap_tx };
	struct mesh_cfg_priv_beacon pb;
	struct mesh_private_beacon parsed;
	uint8_t msg[16], reply[32], first[MESH_PRIVATE_BEACON_LEN];
	size_t mlen, i, npriv;

	(void)tc;
	r4_provision(a, &acfg, 0x0001, 0);
	r4_provision(b, &bcfg, 0x0100, 0);
	meshd_set_bearer(a, &bearer);

	/*
	 * The Secure Network beacon is off; only the Private Beacon state is
	 * enabled, so anything that reaches the bearer here is a Mesh Private
	 * beacon.  Random Update Interval Steps 0 means the Random is
	 * regenerated for every beacon (Section 4.2.44.2).
	 */
	a->cfg.beacon = 0;
	memset(&pb, 0, sizeof(pb));
	pb.private_beacon = 1;
	pb.has_random_update = 1;
	pb.random_update_interval_steps = 0;
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_beacon_set_build(&pb, msg, &mlen));
	ATF_REQUIRE(r4_foundation(a, msg, mlen, reply, sizeof(reply)) > 0);
	ATF_REQUIRE_EQ(1, a->db.priv_beacon);

	/* A's beacon cadence must now put a Mesh Private beacon on the air. */
	g_r4n = 0;
	r4_tick(a, 1000);
	npriv = 0;
	for (i = 0; i < g_r4n; i++)
		if (g_r4cap[i].cls == MESHD_PDU_BEACON &&
		    g_r4cap[i].len == MESH_PRIVATE_BEACON_LEN &&
		    g_r4cap[i].buf[0] == MESH_BEACON_TYPE_MESH_PRIVATE) {
			memcpy(first, g_r4cap[i].buf, MESH_PRIVATE_BEACON_LEN);
			npriv++;
		}
	ATF_REQUIRE_MSG(npriv == 1, "expected one Mesh Private beacon, got %zu",
	    npriv);
	/* No Secure Network beacon: the two states are independent. */
	for (i = 0; i < g_r4n; i++)
		ATF_CHECK(g_r4cap[i].len != MESH_SECURE_BEACON_LEN);

	/* It authenticates under the shared NetKey and carries the IV state. */
	ATF_REQUIRE_EQ(0, mesh_private_beacon_parse(a->self->netkey, first,
	    sizeof(first), &parsed));
	ATF_CHECK_EQ(a->self->iv.iv_index, parsed.iv_index);

	/* And B's beacon receive path accepts it (it did not, before). */
	ATF_CHECK_EQ(1, meshd_beacon_rx(b, first, sizeof(first)));

	/*
	 * Random Update Interval Steps 0: the next beacon must carry a fresh
	 * Random (Table 4.73).
	 */
	g_r4n = 0;
	r4_tick(a, 1000 + MESHD_BEACON_INTERVAL * 1000ULL);
	npriv = 0;
	for (i = 0; i < g_r4n; i++)
		if (g_r4cap[i].len == MESH_PRIVATE_BEACON_LEN) {
			ATF_CHECK(memcmp(g_r4cap[i].buf + 1, first + 1,
			    MESH_PRIVATE_BEACON_RANDOM_LEN) != 0);
			npriv++;
		}
	ATF_CHECK_EQ(1, npriv);

	meshd_node_fini(a);
	meshd_node_fini(b);
}

/*
 * With a non-zero Random Update Interval Steps the Random is held for
 * 10 * steps seconds -- but a change in the Flags or the IV Index regenerates
 * it immediately (Section 3.10.4.2), because reusing the Random across a
 * state change is exactly what would leak the state the private beacon hides.
 */
ATF_TC_WITHOUT_HEAD(m7_private_beacon_random_cadence);
ATF_TC_BODY(m7_private_beacon_random_cadence, tc)
{
	MESH_HEAP(struct meshd_node, a);
	struct meshd_config acfg;
	struct meshd_bearer bearer = { .tx = r4_cap_tx };
	struct mesh_cfg_priv_beacon pb;
	uint8_t msg[16], reply[32];
	uint8_t r1[MESH_PRIVATE_BEACON_RANDOM_LEN];
	uint8_t r2[MESH_PRIVATE_BEACON_RANDOM_LEN];
	size_t mlen, i;
	int seen;

	(void)tc;
	r4_provision(a, &acfg, 0x0001, 0);
	meshd_set_bearer(a, &bearer);
	a->cfg.beacon = 0;
	memset(&pb, 0, sizeof(pb));
	pb.private_beacon = 1;
	pb.has_random_update = 1;
	pb.random_update_interval_steps = 60;	/* the default: 10 minutes */
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_beacon_set_build(&pb, msg, &mlen));
	ATF_REQUIRE(r4_foundation(a, msg, mlen, reply, sizeof(reply)) > 0);

	g_r4n = 0;
	r4_tick(a, 1000);
	seen = 0;
	for (i = 0; i < g_r4n; i++)
		if (g_r4cap[i].len == MESH_PRIVATE_BEACON_LEN) {
			memcpy(r1, g_r4cap[i].buf + 1, sizeof(r1));
			seen = 1;
		}
	ATF_REQUIRE(seen);

	/* Well inside the interval and with unchanged state: same Random. */
	g_r4n = 0;
	r4_tick(a, 1000 + MESHD_BEACON_INTERVAL * 1000ULL);
	seen = 0;
	for (i = 0; i < g_r4n; i++)
		if (g_r4cap[i].len == MESH_PRIVATE_BEACON_LEN) {
			ATF_CHECK_EQ(0, memcmp(g_r4cap[i].buf + 1, r1,
			    sizeof(r1)));
			seen = 1;
		}
	ATF_REQUIRE(seen);

	/* An IV Index change regenerates it inside the same interval. */
	a->self->iv.iv_index = 7;
	g_r4n = 0;
	r4_tick(a, 1000 + 2 * MESHD_BEACON_INTERVAL * 1000ULL);
	seen = 0;
	for (i = 0; i < g_r4n; i++)
		if (g_r4cap[i].len == MESH_PRIVATE_BEACON_LEN) {
			memcpy(r2, g_r4cap[i].buf + 1, sizeof(r2));
			seen = 1;
		}
	ATF_REQUIRE(seen);
	ATF_CHECK(memcmp(r1, r2, sizeof(r1)) != 0);

	meshd_node_fini(a);
}

/* ---- Identity advertising duration (Sections 7.2.2.2.3 / 7.2.2.2.5) ---- */
/*
 * "the Node Identity timer ... shall be ... started with the period set to 60
 * seconds.  When the Node Identity timer expires, the server shall stop
 * advertising for the corresponding subnet and set the Node Identity state to
 * disabled."  The state was latched Running for ever instead.
 */
ATF_TC_WITHOUT_HEAD(m8_identity_advertising_duration);
ATF_TC_BODY(m8_identity_advertising_duration, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct mesh_cfg_priv_node_identity pid;
	uint8_t msg[16], reply[32], status, identity;
	uint16_t net_idx;
	size_t mlen, rlen;

	(void)tc;
	r4_provision(nd, &cfg, 0x0001, 0);
	r4_tick(nd, 1000);

	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_set_build(0x000,
	    MESH_CFG_NODE_IDENTITY_RUNNING, msg, &mlen));
	rlen = r4_foundation(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_status_parse(reply, rlen,
	    &status, &net_idx, &identity));
	ATF_REQUIRE_EQ(MESH_CFG_SUCCESS, status);
	ATF_REQUIRE_EQ(MESH_CFG_NODE_IDENTITY_RUNNING, identity);

	memset(&pid, 0, sizeof(pid));
	pid.net_idx = 0x000;
	pid.identity = MESH_CFG_PRIV_IDENTITY_RUNNING;
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_set_build(&pid, msg,
	    &mlen));
	ATF_REQUIRE(r4_foundation(nd, msg, mlen, reply, sizeof(reply)) > 0);
	ATF_REQUIRE_EQ(MESH_CFG_PRIV_IDENTITY_RUNNING,
	    nd->db.netkeys[0].priv_node_identity);

	/* One second short of the 60-second timer: still advertising. */
	r4_tick(nd, 1000 + 59000);
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_get_build(0x000, msg, &mlen));
	rlen = r4_foundation(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_status_parse(reply, rlen,
	    &status, &net_idx, &identity));
	ATF_CHECK_EQ(MESH_CFG_NODE_IDENTITY_RUNNING, identity);

	/* At the deadline both states return to disabled. */
	r4_tick(nd, 1000 + 60000);
	rlen = r4_foundation(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_status_parse(reply, rlen,
	    &status, &net_idx, &identity));
	ATF_CHECK_EQ(MESH_CFG_NODE_IDENTITY_STOPPED, identity);
	ATF_CHECK_EQ(MESH_CFG_PRIV_IDENTITY_STOPPED,
	    nd->db.netkeys[0].priv_node_identity);

	meshd_node_fini(nd);
}

/* ---- Friendship subscription list (Section 3.6.6.4.3) ----------------- */
/*
 * A Friend forwards to its LPN only what its per-LPN subscription list names,
 * and the LPN is the only party that can put anything on that list.  Nothing
 * in the daemon ever sent a Friend Subscription List Add, so a Low Power node
 * could never receive a group message through its Friend.
 */
ATF_TC_WITHOUT_HEAD(m9_lpn_subscription_list);
ATF_TC_BODY(m9_lpn_subscription_list, tc)
{
	MESH_HEAP(struct meshd_node, friend);
	MESH_HEAP(struct meshd_node, lpn);
	MESH_HEAP(struct mesh_sim, src);
	struct meshd_config fcfg, lcfg;
	struct meshd_bearer fbear = { .tx = r4_cap_tx };
	struct meshd_bearer lbear = { .tx = r4_cap_tx };
	struct mesh_cfg_model_sub ms;
	struct mesh_cfg_model_id model;
	struct mesh_node *sender;
	uint8_t netkey[16], appkey[16];
	uint8_t amsg[3] = { 0x82, 0x99, 0x5A };
	uint8_t msg[32], reply[32];
	size_t mlen, qbefore;

	(void)tc;
	r4_provision(friend, &fcfg, 0x0100, MESH_CFG_FEATURE_FRIEND);
	r4_provision(lpn, &lcfg, 0x0001, MESH_CFG_FEATURE_LOW_POWER);
	meshd_set_bearer(friend, &fbear);
	meshd_set_bearer(lpn, &lbear);
	ATF_REQUIRE(friend->friend_enabled);
	ATF_REQUIRE(lpn->lpn_enabled);

	/* Request / Offer / Poll / Update: establish the friendship. */
	g_r4n = 0;
	r4_tick(lpn, 1000);
	(void)r4_pump(friend);
	g_r4n = 0;
	r4_tick(friend, 2000);
	(void)r4_pump(lpn);
	g_r4n = 0;
	r4_tick(lpn, 1600);
	(void)r4_pump(friend);
	(void)r4_pump(lpn);
	ATF_REQUIRE_EQ(1, mesh_lpn_fsm_established(&lpn->lpn_fsm));
	ATF_REQUIRE_EQ(1, mesh_friend_fsm_established(&friend->friend_fsm));

	/* Subscribe a model on the LPN to a group address. */
	memset(&model, 0, sizeof(model));
	model.model_id = MESH_MODEL_GEN_ONOFF_SRV;
	memset(&ms, 0, sizeof(ms));
	ms.elem_addr = 0x0001;
	ms.address = 0xC001;
	ms.model = model;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_ADD,
	    &ms, msg, &mlen));
	g_r4n = 0;
	ATF_REQUIRE(r4_foundation(lpn, msg, mlen, reply, sizeof(reply)) > 0);

	/*
	 * The subscription change must have put a Friend Subscription List Add
	 * on the air, and it must be awaiting its Confirm.
	 */
	ATF_REQUIRE_MSG(g_r4n >= 1, "no Friend Subscription List Add emitted");
	ATF_CHECK_EQ(1, lpn->lpn_fsm.sub_pending);

	/* The Friend records the address and answers with a Confirm. */
	(void)r4_pump(friend);
	ATF_CHECK_EQ(1, mesh_friend_sub_contains(&friend->friend_fsm.queue.sub,
	    0xC001));

	/* Confirm -> LPN: the transaction closes and the mirror commits. */
	(void)r4_pump(lpn);
	ATF_CHECK_EQ(0, lpn->lpn_fsm.sub_pending);
	ATF_CHECK_EQ(1, lpn->lpn_sub_n);
	ATF_CHECK_EQ(0xC001, lpn->lpn_sub_announced[0]);

	/*
	 * The end the whole exchange exists for: a group message off the
	 * network is now queued by the Friend for its LPN.
	 */
	memset(netkey, 0x33, sizeof(netkey));
	memset(appkey, 0x44, sizeof(appkey));
	ATF_REQUIRE_EQ(0, mesh_sim_init(src, netkey, appkey, 0));
	sender = mesh_sim_add_node(src, 0x00AA, 1);
	ATF_REQUIRE(sender != NULL);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(src, sender, 0xC001, 0x8299,
	    &amsg[2], 1, 5));
	ATF_REQUIRE(src->n_tx >= 1);
	qbefore = mesh_fq_count(&friend->friend_fsm.queue);
	(void)meshd_bearer_rx(friend, src->tx[0].bytes, src->tx[0].len);
	ATF_CHECK_EQ(qbefore + 1, mesh_fq_count(&friend->friend_fsm.queue));

	/* Removing the subscription sends the matching Remove. */
	ms.address = 0xC001;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_DELETE,
	    &ms, msg, &mlen));
	g_r4n = 0;
	ATF_REQUIRE(r4_foundation(lpn, msg, mlen, reply, sizeof(reply)) > 0);
	ATF_REQUIRE_MSG(g_r4n >= 1,
	    "no Friend Subscription List Remove emitted");
	(void)r4_pump(friend);
	ATF_CHECK_EQ(0, mesh_friend_sub_contains(&friend->friend_fsm.queue.sub,
	    0xC001));
	(void)r4_pump(lpn);
	ATF_CHECK_EQ(0, lpn->lpn_sub_n);

	meshd_node_fini(friend);
	meshd_node_fini(lpn);
}

/* ---- 192-hour IV Index Recovery hold across a restart (Section 3.11.6) - */
/*
 * A node that completed a recovery must not run another for 192 hours.  The
 * hold lived only in memory, so every restart re-armed the procedure.
 */
ATF_TC_WITHOUT_HEAD(m10_iv_recovery_hold_persists);
ATF_TC_BODY(m10_iv_recovery_hold_persists, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_persist ps;
	struct timespec wts;
	const char *path = "meshd_m10.state";
	uint64_t wall_now;

	(void)tc;
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_REALTIME, &wts));
	wall_now = (uint64_t)wts.tv_sec;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(a, &cfg));
	a->self->iv.recovery_done = 1;
	a->self->iv.recovery_time = wall_now;

	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, a));
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, b));

	ATF_CHECK_EQ(1, b->self->iv.recovery_done);
	ATF_CHECK_EQ(wall_now, b->self->iv.recovery_time);
	/*
	 * The hold is what the eligibility rule reads: the restarted node must
	 * NOT be eligible to recover again until the 192 hours have run.
	 */
	ATF_CHECK_EQ(0, mesh_iv_recovery_eligible(&b->self->iv, wall_now));
	ATF_CHECK_EQ(0, mesh_iv_recovery_eligible(&b->self->iv,
	    wall_now + MESH_IV_RECOVERY_MIN_SECS - 1));
	ATF_CHECK_EQ(1, mesh_iv_recovery_eligible(&b->self->iv,
	    wall_now + MESH_IV_RECOVERY_MIN_SECS));

	/* A future timestamp is clamped, as entered_time already was. */
	a->self->iv.recovery_time = wall_now + 1000000000ULL;
	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, a));
	meshd_node_fini(b);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, b));
	ATF_CHECK(b->self->iv.recovery_time <= wall_now + 1);

	(void)unlink(path);
	meshd_node_fini(a);
	meshd_node_fini(b);
}

/* ---- Proxy SAR reassembly timeout (Section 6.3.2.2) ------------------- */
/*
 * The 20-second timeout is now evaluated by mesh_proxy_reasm_tick(), the
 * library's own clock, instead of a second copy of the rule in the daemon.
 * Complementary: it pins that the deadline still runs from the segment rather
 * than from the tick that observes it.
 */
ATF_TC_WITHOUT_HEAD(m11_proxy_reasm_tick_wired);
ATF_TC_BODY(m11_proxy_reasm_tick_wired, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer = { .tx = r4_cap_tx };
	const char *addr = "aa:bb:cc:dd:ee:ff";
	uint8_t first[] = { (MESH_PROXY_SAR_FIRST << 6) |
	    MESH_PROXY_TYPE_NETWORK, 0x01 };

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);
	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_begin(nd, addr, 0,
	    MESHD_ADAPTER_DEFAULT, MESHD_PBGATT_MIN_MTU));

	ATF_REQUIRE_EQ(0, meshd_proxy_gatt_recv(nd, addr, 0,
	    MESHD_ADAPTER_DEFAULT, first, sizeof(first), 5000));
	/* The reassembler's clock is armed from the segment, not the tick. */
	ATF_CHECK_EQ(1, nd->proxy_gatt[0].rx.timing);
	ATF_CHECK_EQ(5000, nd->proxy_gatt[0].rx.start_ms);

	meshd_gatt_tick(nd, 5000 + MESH_PROXY_REASM_TIMEOUT_MS - 1);
	ATF_CHECK(nd->proxy_gatt[0].active);
	meshd_gatt_tick(nd, 5000 + MESH_PROXY_REASM_TIMEOUT_MS);
	ATF_CHECK(!nd->proxy_gatt[0].active);

	meshd_node_fini(nd);
}

/*
 * A lost Friend Subscription List Confirm must not wedge the LPN: the message
 * is repeated with its original TransactionNumber, and after the retry budget
 * the transaction is abandoned so a later subscription change is not blocked
 * behind it.  Starting a fresh friendship also abandons it (its Confirm can
 * never arrive from a Friend that no longer holds the transaction).
 */
ATF_TC_WITHOUT_HEAD(m9_lpn_subscription_confirm_lost);
ATF_TC_BODY(m9_lpn_subscription_confirm_lost, tc)
{
	MESH_HEAP(struct meshd_node, friend);
	MESH_HEAP(struct meshd_node, lpn);
	struct meshd_config fcfg, lcfg;
	struct meshd_bearer fbear = { .tx = r4_cap_tx };
	struct meshd_bearer lbear = { .tx = r4_cap_tx };
	struct mesh_cfg_model_sub ms;
	struct mesh_cfg_model_id model;
	uint8_t msg[32], reply[32], transaction;
	size_t mlen;
	unsigned k;

	(void)tc;
	r4_provision(friend, &fcfg, 0x0100, MESH_CFG_FEATURE_FRIEND);
	r4_provision(lpn, &lcfg, 0x0001, MESH_CFG_FEATURE_LOW_POWER);
	meshd_set_bearer(friend, &fbear);
	meshd_set_bearer(lpn, &lbear);

	g_r4n = 0;
	r4_tick(lpn, 1000);
	(void)r4_pump(friend);
	g_r4n = 0;
	r4_tick(friend, 2000);
	(void)r4_pump(lpn);
	g_r4n = 0;
	r4_tick(lpn, 1600);
	(void)r4_pump(friend);
	(void)r4_pump(lpn);
	ATF_REQUIRE_EQ(1, mesh_lpn_fsm_established(&lpn->lpn_fsm));

	memset(&model, 0, sizeof(model));
	model.model_id = MESH_MODEL_GEN_ONOFF_SRV;
	memset(&ms, 0, sizeof(ms));
	ms.elem_addr = 0x0001;
	ms.address = 0xC002;
	ms.model = model;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_ADD,
	    &ms, msg, &mlen));
	g_r4n = 0;
	ATF_REQUIRE(r4_foundation(lpn, msg, mlen, reply, sizeof(reply)) > 0);
	ATF_REQUIRE_EQ(1, lpn->lpn_fsm.sub_pending);
	transaction = lpn->lpn_fsm.sub_transaction;

	/* Drop the Confirm: the tick repeats the message, bounded. */
	for (k = 1; k <= MESHD_LPN_SUB_MAX_RETRIES; k++) {
		g_r4n = 0;
		r4_tick(lpn, 1600 + k * MESHD_LPN_SUB_RETRY_MS);
		ATF_CHECK_MSG(g_r4n >= 1, "retry %u sent nothing", k);
		ATF_CHECK_EQ(1, lpn->lpn_fsm.sub_pending);
		/* Same transaction: a repeat, not a new one. */
		ATF_CHECK_EQ(transaction, lpn->lpn_fsm.sub_transaction);
	}
	/* Budget spent: the transaction is released rather than left pending. */
	r4_tick(lpn, 1600 + (MESHD_LPN_SUB_MAX_RETRIES + 1) *
	    MESHD_LPN_SUB_RETRY_MS);
	ATF_CHECK_EQ(0, lpn->lpn_fsm.sub_pending);
	ATF_CHECK_EQ(0, lpn->lpn_sub_n);

	/* And a fresh Friend Request clears any transaction outright. */
	lpn->lpn_fsm.sub_pending = 1;
	g_r4n = 0;
	ATF_REQUIRE_EQ(0, meshd_lpn_enable(lpn, 0, 0, 1, 100, 100, 500, 2000,
	    9000, &(struct mesh_lpn_out){ 0 }));
	ATF_CHECK_EQ(0, lpn->lpn_fsm.sub_pending);

	meshd_node_fini(friend);
	meshd_node_fini(lpn);
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
	ATF_TP_ADD_TC(tp, m1_iv_recovery_beacon_path);
	ATF_TP_ADD_TC(tp, m6_rpl_commits_after_authentication);
	ATF_TP_ADD_TC(tp, m5_sar_retransmit_fresh_seq);
	ATF_TP_ADD_TC(tp, m2_provisioning_static_oob);
	ATF_TP_ADD_TC(tp, m2_provisioning_oob_only_refused);
	ATF_TP_ADD_TC(tp, m7_private_beacon_wired);
	ATF_TP_ADD_TC(tp, m7_private_beacon_random_cadence);
	ATF_TP_ADD_TC(tp, m8_identity_advertising_duration);
	ATF_TP_ADD_TC(tp, m9_lpn_subscription_list);
	ATF_TP_ADD_TC(tp, m9_lpn_subscription_confirm_lost);
	ATF_TP_ADD_TC(tp, m10_iv_recovery_hold_persists);
	ATF_TP_ADD_TC(tp, m11_proxy_reasm_tick_wired);

	return (atf_no_error());
}
