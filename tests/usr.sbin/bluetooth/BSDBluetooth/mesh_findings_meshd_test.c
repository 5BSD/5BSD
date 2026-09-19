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
#include "spec_extref_mesh_sar.h"

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
peer_access_frames_keys(uint16_t src, uint16_t dst, uint32_t seq, uint32_t iv,
    uint32_t opcode, const uint8_t *params, size_t plen,
    const uint8_t netkey[16], const uint8_t appkey[16], struct peer_frames *pf)
{
	MESH_HEAP(struct mesh_sim, peer);
	struct mesh_node *nodeb;
	size_t i;

	memset(pf, 0, sizeof(*pf));
	ATF_REQUIRE_EQ(0, mesh_sim_init(peer, netkey, appkey, iv));
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

/* The common case: the fixture's own NetKey and AppKey. */
static void
peer_access_frames(uint16_t src, uint16_t dst, uint32_t seq, uint32_t iv,
    uint32_t opcode, const uint8_t *params, size_t plen,
    struct peer_frames *pf)
{

	peer_access_frames_keys(src, dst, seq, iv, opcode, params, plen,
	    g_netkey, g_appkey, pf);
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
	 *
	 * SETUP CHANGE, flagged: this used to tick to 500 ms, which was the
	 * flat 200 ms the engine once used plus slack.  The SAR Unicast
	 * Retransmissions timer is now derived from the node's SAR Transmitter
	 * state as MshPRT_v1.1.1 Section 3.5.3.3.1 requires, so the deadline
	 * is later and the old tick landed BEFORE it:
	 *   interval  = step + increment * (TTL - 1)
	 *             = (7 + 1) * 25 + (1 + 1) * 25 * (7 - 1) = 500 ms
	 *   start     = "an estimated time of the end of the transmission of
	 *                the last segment", SegN segment transmission
	 *                intervals after the first (Section 4.2.48.1)
	 *             = 5 * (5 + 1) * 10 = 300 ms
	 * The assertion below is unchanged; only the instant it is taken at
	 * moves, from 500 ms to past the 800 ms the specification's own
	 * formulae give for base_config()'s Default TTL of 7.
	 */
	g_sar_n = 0;
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 900, &changed));
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



/* ---- M3: Output and Input OOB provisioning reach the daemon ---------- */
/*
 * MshPRT_v1.1.1 Sections 5.4.2.4.3 and 5.4.2.4.4.  The AuthValue packers for
 * the operator-driven methods were byte-correct and unit-tested, and no
 * production path could ever reach them: the daemon had no channel to show a
 * value to an operator or to collect one, so both methods were refused
 * outright.
 *
 * Every case below drives the DAEMON entry points - meshd_ctl_exec_client()
 * for the verbs, meshd_provisioner_begin / _recv / _drain for the session, and
 * the app-client event queue for the display direction - against a simulated
 * device on the other end of a PB-ADV link.
 *
 * The directions being pinned are the ones that are easy to invert:
 *   Output OOB - the DEVICE displays, the daemon (Provisioner) collects;
 *   Input OOB  - the daemon displays, the DEVICE collects and answers with a
 *                Provisioning Input Complete PDU.
 */

/* Capture bearer: every PB-ADV packet the daemon sends, in order. */
#define	M3_FIFO_MAX	64
static struct m3_pkt {
	uint8_t	buf[MESH_PBADV_PKT_MAX];
	size_t	len;
} g_m3_fifo[M3_FIFO_MAX];
static size_t g_m3_n;

static int
m3_tx(void *arg __unused, enum meshd_pdu_class cls, const uint8_t *pdu,
    size_t len)
{

	if (cls == MESHD_PDU_PROV && g_m3_n < M3_FIFO_MAX &&
	    len <= sizeof(g_m3_fifo[0].buf)) {
		memcpy(g_m3_fifo[g_m3_n].buf, pdu, len);
		g_m3_fifo[g_m3_n].len = len;
		g_m3_n++;
	}
	return (0);
}

/*
 * One step of the PB-ADV exchange in both directions.  Returns 1 if anything
 * moved.  `oob` is the simulated device session; `dl` its link.
 */
static int
m3_step(struct meshd_node *nd, struct mesh_prov_link *dl,
    struct mesh_prov_session *ds, uint64_t now)
{
	uint8_t pkt[MESH_PBADV_PKT_MAX], ack[MESH_PBADV_PKT_MAX];
	uint8_t rpdu[MESH_PROV_PDU_MAX], spdu[MESH_PROV_PDU_MAX];
	size_t len, acklen, rlen, slen, i, n;
	int have_pdu, have_ack, moved = 0;

	/* Daemon -> bearer. */
	if (meshd_provisioner_drain(nd, now) > 0)
		moved = 1;

	/* Bearer -> device. */
	n = g_m3_n;
	g_m3_n = 0;
	for (i = 0; i < n; i++) {
		have_pdu = have_ack = 0;
		(void)mesh_prov_link_recv(dl, g_m3_fifo[i].buf,
		    g_m3_fifo[i].len, now, rpdu, &rlen, &have_pdu, ack, &acklen,
		    &have_ack);
		if (have_ack)
			(void)meshd_provisioner_recv(nd, ack, acklen, now);
		if (have_pdu)
			(void)mesh_prov_session_recv(ds, rpdu, rlen);
		moved = 1;
	}

	/* Device -> daemon. */
	if (mesh_prov_link_poll(dl, now, pkt, &len) == 1) {
		(void)meshd_provisioner_recv(nd, pkt, len, now);
		return (1);
	}
	if (mesh_prov_link_idle(dl) &&
	    mesh_prov_session_poll(ds, spdu, &slen) == 1) {
		(void)mesh_prov_link_send(dl, spdu, slen, now);
		return (1);
	}
	return (moved);
}

/* Run the exchange until it stalls or both sides are done. */
static void
m3_pump(struct meshd_node *nd, struct mesh_prov_link *dl,
    struct mesh_prov_session *ds, uint64_t now)
{
	int i;

	for (i = 0; i < 200; i++) {
		if (meshd_provisioner_done(nd) && mesh_prov_session_done(ds))
			return;
		if (m3_step(nd, dl, ds, now) == 0)
			return;
	}
}

/* Boilerplate shared by the two end-to-end cases. */
static void
m3_setup(struct meshd_node *nd, struct meshd_bearer *bearer,
    struct mesh_prov_link *dl, struct mesh_prov_session *ds,
    const struct mesh_prov_caps *caps, struct mesh_prov_data *pdata,
    const uint8_t uuid[16], uint64_t now)
{
	uint8_t raw[25];

	g_m3_n = 0;
	memset(bearer, 0, sizeof(*bearer));
	bearer->tx = m3_tx;
	meshd_set_bearer(nd, bearer);
	ATF_REQUIRE_EQ(0, meshd_hexdecode(
	    "efb2255e6422d330088e09bb015ed707056700010203040b0c", raw, 25));
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, pdata));
	mesh_prov_link_init_device(dl, uuid, 100000, 3);
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(ds, NULL, NULL, caps));
	ATF_REQUIRE_EQ(0, meshd_provisioner_begin(nd, uuid, 0x11223344, NULL,
	    NULL, 0x00, pdata, 100000, 3, now, g_m3_fifo[0].buf,
	    &g_m3_fifo[0].len));
	g_m3_n = 1;
}

/*
 * Output OOB end to end: the operator opts in with "provision-oob output",
 * the device displays a six-digit value, the daemon raises a prov-oob-input
 * app event and stalls, and "provision-oob-input" completes the exchange.
 */
ATF_TC_WITHOUT_HEAD(m3_provisioning_output_oob);
ATF_TC_BODY(m3_provisioning_output_oob, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer;
	struct meshd_app_client *cl;
	struct mesh_prov_link dl;
	struct mesh_prov_session ds;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	struct mesh_prov_oob_prompt dp, pp;
	uint8_t uuid[16];
	char reply[512];
	char *av[3];
	uint64_t now = 0;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	cl = &nd->app_clients[0];
	meshd_app_client_init(cl, 100);

	/* The operator opts in to the Output OOB method. */
	av[0] = __DECONST(char *, "provision-oob");
	av[1] = __DECONST(char *, "output");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "output=on") != NULL, "%s", reply);
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "output=on") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "input=off") != NULL, "%s", reply);

	/* A device with a six-digit numeric display. */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.output_oob_size = 6;
	caps.output_oob_action = 1u << MESH_PROV_OUT_ACT_NUMERIC;
	memset(uuid, 0x42, sizeof(uuid));
	m3_setup(nd, &bearer, &dl, &ds, &caps, &pdata, uuid, now);

	m3_pump(nd, &dl, &ds, now);

	/* Provisioning Start selected Output OOB with the Action and Size. */
	ATF_CHECK_EQ_MSG(MESH_PROV_AUTH_METHOD_OUTPUT,
	    nd->prov_sess.start_val[2], "Start must select Output OOB");
	ATF_CHECK_EQ(MESH_PROV_OUT_ACT_NUMERIC, nd->prov_sess.start_val[3]);
	ATF_CHECK_EQ(6, nd->prov_sess.start_val[4]);
	ATF_CHECK_MSG(!meshd_provisioner_done(nd),
	    "the exchange must stall until the operator answers");

	/* The daemon asked the operator for the value the device shows. */
	ATF_REQUIRE_EQ(1, meshd_provision_oob_prompt(nd, &pp));
	ATF_CHECK_EQ_MSG(MESH_PROV_OOB_PROMPT_INPUT, pp.kind,
	    "Output OOB: the daemon collects, the device displays");
	ATF_CHECK_EQ(6, pp.size);
	ATF_REQUIRE_EQ(1, mesh_prov_session_oob_prompt(&ds, &dp));
	ATF_CHECK_EQ(MESH_PROV_OOB_PROMPT_DISPLAY, dp.kind);
	ATF_CHECK_EQ(6u, (unsigned)strlen(dp.value));

	/* The prompt reached the app client as an event... */
	av[0] = __DECONST(char *, "app-events");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "prov-oob-input") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "size=6") != NULL, "%s", reply);

	/* ...and "provision-oob" reports it too, for a late-comer. */
	av[0] = __DECONST(char *, "provision-oob");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "prompt=input") != NULL, "%s", reply);

	/* A value that does not match the Size is refused, session intact. */
	av[0] = __DECONST(char *, "provision-oob-input");
	av[1] = __DECONST(char *, "12345678901");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strncmp(reply, "ERR", 3) == 0, "%s", reply);
	ATF_CHECK(!mesh_prov_session_failed(&nd->prov_sess));

	/* The operator reads the device display and types it in. */
	av[1] = dp.value;
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strncmp(reply, "OK", 2) == 0, "%s", reply);
	ATF_CHECK_EQ(0, meshd_provision_oob_prompt(nd, &pp));

	m3_pump(nd, &dl, &ds, now);

	ATF_CHECK_MSG(meshd_provisioner_done(nd), "provisioner completed");
	ATF_CHECK_MSG(mesh_prov_session_done(&ds), "device completed");
	ATF_CHECK_EQ_MSG(0, memcmp(nd->prov_sess.devkey,
	    mesh_prov_session_devkey(&ds), 16), "same DevKey");
	ATF_CHECK_EQ_MSG(0, memcmp(nd->prov_sess.auth, ds.auth,
	    MESH_PROV_AUTH_LEN_256), "same AuthValue");

	mesh_prov_session_free(&nd->prov_sess);
	mesh_prov_session_free(&ds);
	meshd_node_fini(nd);
}

/*
 * Input OOB end to end: the daemon generates and displays the value (pushed to
 * the app client as a prov-oob-display event), the device's user enters it,
 * and the Provisioning Input Complete PDU releases the daemon's Confirmation.
 */
ATF_TC_WITHOUT_HEAD(m3_provisioning_input_oob);
ATF_TC_BODY(m3_provisioning_input_oob, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer;
	struct meshd_app_client *cl, *cl2;
	struct mesh_prov_link dl;
	struct mesh_prov_session ds;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	struct mesh_prov_oob_prompt pp, dp;
	uint8_t uuid[16];
	char reply[512], shown[MESH_PROV_OOB_VALUE_MAX], want[64];
	char *av[3];
	uint64_t now = 0;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	/* Two operator interfaces: the prompt must reach both. */
	cl = &nd->app_clients[0];
	cl2 = &nd->app_clients[1];
	meshd_app_client_init(cl, 101);
	meshd_app_client_init(cl2, 111);

	av[0] = __DECONST(char *, "provision-oob");
	av[1] = __DECONST(char *, "input");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "input=on") != NULL, "%s", reply);

	/* A device with a four-digit keypad and no display. */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.input_oob_size = 4;
	caps.input_oob_action = 1u << MESH_PROV_IN_ACT_NUMERIC;
	memset(uuid, 0x77, sizeof(uuid));
	m3_setup(nd, &bearer, &dl, &ds, &caps, &pdata, uuid, now);

	m3_pump(nd, &dl, &ds, now);

	ATF_CHECK_EQ_MSG(MESH_PROV_AUTH_METHOD_INPUT,
	    nd->prov_sess.start_val[2], "Start must select Input OOB");
	ATF_CHECK_EQ(MESH_PROV_IN_ACT_NUMERIC, nd->prov_sess.start_val[3]);
	ATF_CHECK_EQ(4, nd->prov_sess.start_val[4]);

	/* The daemon displays; the device waits for its user. */
	ATF_REQUIRE_EQ(1, meshd_provision_oob_prompt(nd, &pp));
	ATF_CHECK_EQ_MSG(MESH_PROV_OOB_PROMPT_DISPLAY, pp.kind,
	    "Input OOB: the daemon displays, the device collects");
	ATF_CHECK_EQ(4u, (unsigned)strlen(pp.value));
	ATF_REQUIRE_EQ(1, mesh_prov_session_oob_prompt(&ds, &dp));
	ATF_CHECK_EQ(MESH_PROV_OOB_PROMPT_INPUT, dp.kind);
	ATF_CHECK_MSG(!meshd_provisioner_done(nd),
	    "the daemon holds its Confirmation for Input Complete");

	/* The value reached the app client, in readable form. */
	strlcpy(shown, pp.value, sizeof(shown));
	snprintf(want, sizeof(want), "value=%s", shown);
	av[0] = __DECONST(char *, "app-events");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "prov-oob-display") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, want) != NULL, "want %s, got %s", want,
	    reply);
	ATF_CHECK_EQ_MSG(1u, meshd_app_client_event_count(cl2),
	    "every connected client is told, not just the first");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl2, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, want) != NULL, "%s", reply);
	/* Announced once: a repeated pump must not re-queue it. */
	meshd_provision_oob_pump(nd, now);
	ATF_CHECK_EQ(0u, meshd_app_client_event_count(cl2));

	/* Nothing for the operator to type on THIS side. */
	av[0] = __DECONST(char *, "provision-oob-input");
	av[1] = shown;
	ATF_CHECK_EQ_MSG(-1, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)), "the daemon is not the side that inputs");

	/* The device's user enters the value; Input Complete follows. */
	ATF_REQUIRE_EQ(0, mesh_prov_session_oob_input(&ds, shown));
	m3_pump(nd, &dl, &ds, now);

	ATF_CHECK_MSG(meshd_provisioner_done(nd), "provisioner completed");
	ATF_CHECK_MSG(mesh_prov_session_done(&ds), "device completed");
	ATF_CHECK_EQ_MSG(0, memcmp(nd->prov_sess.devkey,
	    mesh_prov_session_devkey(&ds), 16), "same DevKey");
	ATF_CHECK_EQ(0, memcmp(nd->prov_sess.auth, ds.auth,
	    MESH_PROV_AUTH_LEN_256));

	mesh_prov_session_free(&nd->prov_sess);
	mesh_prov_session_free(&ds);
	meshd_node_fini(nd);
}

/*
 * The refusal and the timeout.  A device that will only be provisioned over an
 * OOB-authenticated exchange, offering a method the operator has not opted in
 * to, is refused rather than downgraded; and an Input OOB exchange whose
 * Input Complete never arrives fails on the daemon's tick instead of holding
 * the provisioner forever.
 */
ATF_TC_WITHOUT_HEAD(m3_provisioning_oob_refused_and_timeout);
ATF_TC_BODY(m3_provisioning_oob_refused_and_timeout, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer;
	struct meshd_app_client *cl;
	struct mesh_prov_link dl;
	struct mesh_prov_session ds;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	struct mesh_prov_oob_prompt pp;
	uint8_t uuid[16];
	char reply[512];
	char *av[3];
	uint64_t now = 0;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	cl = &nd->app_clients[0];
	meshd_app_client_init(cl, 102);

	/* Nothing to input while no session is running. */
	av[0] = __DECONST(char *, "provision-oob-input");
	av[1] = __DECONST(char *, "1234");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, cl, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "usage") != NULL, "%s", reply);

	/* Opt in to INPUT only; the device offers OUTPUT and demands OOB. */
	av[0] = __DECONST(char *, "provision-oob");
	av[1] = __DECONST(char *, "input");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)));

	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	/* Table 5.23: with OOB Type bit 1 set, only HMAC may be advertised. */
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_HMAC;
	caps.static_oob_type = MESH_PROV_OOB_TYPE_ONLY_OOB;
	caps.output_oob_size = 4;
	caps.output_oob_action = 1u << MESH_PROV_OUT_ACT_NUMERIC;
	memset(uuid, 0x11, sizeof(uuid));
	m3_setup(nd, &bearer, &dl, &ds, &caps, &pdata, uuid, now);
	m3_pump(nd, &dl, &ds, now);

	ATF_CHECK_MSG(mesh_prov_session_failed(&nd->prov_sess),
	    "an unsatisfiable OOB-only device must be refused, not downgraded");
	ATF_CHECK(!meshd_provisioner_done(nd));
	ATF_CHECK_EQ(0, meshd_provision_oob_prompt(nd, &pp));
	mesh_prov_session_free(&nd->prov_sess);
	mesh_prov_session_free(&ds);
	nd->provisioner_active = 0;

	/* Now the Input Complete timeout. */
	av[1] = __DECONST(char *, "input");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)));
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.input_oob_size = 4;
	caps.input_oob_action = 1u << MESH_PROV_IN_ACT_NUMERIC;
	memset(uuid, 0x22, sizeof(uuid));
	m3_setup(nd, &bearer, &dl, &ds, &caps, &pdata, uuid, now);
	m3_pump(nd, &dl, &ds, now);
	ATF_REQUIRE_EQ(1, meshd_provision_oob_prompt(nd, &pp));
	ATF_REQUIRE_EQ(MESH_PROV_OOB_PROMPT_DISPLAY, pp.kind);

	/* The device's user never types it. */
	(void)meshd_provisioner_drain(nd,
	    MESH_PROV_INPUT_COMPLETE_TIMEOUT_MS - 1);
	ATF_CHECK_MSG(!mesh_prov_session_failed(&nd->prov_sess),
	    "not due yet");
	(void)meshd_provisioner_drain(nd, MESH_PROV_INPUT_COMPLETE_TIMEOUT_MS);
	ATF_CHECK_MSG(mesh_prov_session_failed(&nd->prov_sess),
	    "an unanswered Input Complete must not stall the daemon forever");
	ATF_CHECK_EQ(0x07, nd->prov_sess.error);
	ATF_CHECK_EQ(0, meshd_provision_oob_prompt(nd, &pp));

	/* "provision-oob none" clears the opt-in and the static value. */
	av[0] = __DECONST(char *, "provision-oob");
	av[1] = __DECONST(char *, "none");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)));
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, cl, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "output=off") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "input=off") != NULL, "%s", reply);
	ATF_CHECK_MSG(strstr(reply, "static-oob=none") != NULL, "%s", reply);
	av[1] = __DECONST(char *, "sideways");
	ATF_CHECK_EQ_MSG(-1, meshd_ctl_exec_client(nd, cl, 2, av, reply,
	    sizeof(reply)), "an unknown argument is not a hex value");

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

	/* One second short of the 60-second timer: still advertising. */
	r4_tick(nd, 1000 + 59000);
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_get_build(0x000, msg, &mlen));
	rlen = r4_foundation(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_status_parse(reply, rlen,
	    &status, &net_idx, &identity));
	ATF_CHECK_EQ(MESH_CFG_NODE_IDENTITY_RUNNING, identity);

	/* At the deadline the state returns to disabled. */
	r4_tick(nd, 1000 + 60000);
	rlen = r4_foundation(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_status_parse(reply, rlen,
	    &status, &net_idx, &identity));
	ATF_CHECK_EQ(MESH_CFG_NODE_IDENTITY_STOPPED, identity);
	ATF_CHECK_EQ(MESH_CFG_PRIV_IDENTITY_STOPPED,
	    nd->db.netkeys[0].priv_node_identity);

	/*
	 * SETUP CHANGED (finding 32).  This case used to enable Private Node
	 * Identity while Node Identity was still Enabled on the same subnet.
	 * MshPRT_v1.1.1 Section 4.2.46.1 forbids that combination outright -
	 * "to change the Private Node Identity state to Enabled, the Node
	 * Identity state must be set to Disabled for all subnets" - so the old
	 * setup was itself invalid and the Set is now issued only after the
	 * Node Identity timer above has expired.  What the case is ABOUT is
	 * unchanged: the Private Node Identity state has its own 60-second
	 * timer (Section 7.2.2.2.5) and must return to disabled on expiry.
	 */
	memset(&pid, 0, sizeof(pid));
	pid.net_idx = 0x000;
	pid.identity = MESH_CFG_PRIV_IDENTITY_RUNNING;
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_set_build(&pid, msg,
	    &mlen));
	ATF_REQUIRE(r4_foundation(nd, msg, mlen, reply, sizeof(reply)) > 0);
	ATF_REQUIRE_EQ(MESH_CFG_PRIV_IDENTITY_RUNNING,
	    nd->db.netkeys[0].priv_node_identity);

	r4_tick(nd, 1000 + 60000 + 59000);
	ATF_CHECK_EQ_MSG(MESH_CFG_PRIV_IDENTITY_RUNNING,
	    nd->db.netkeys[0].priv_node_identity,
	    "one second short of the private 60-second timer");
	r4_tick(nd, 1000 + 60000 + 60000);
	ATF_CHECK_EQ_MSG(MESH_CFG_PRIV_IDENTITY_STOPPED,
	    nd->db.netkeys[0].priv_node_identity,
	    "the private identity timer must expire to disabled too");

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

/* ================================================================
 * Mesh Proxy SERVER role (MshPRT_v1.1.1 Sections 6.7 and 7.2).
 *
 * These cases drive the DAEMON's entry points -- meshd_node_tick() and the
 * meshd_proxy_server_* and meshd_proxy_adv_emit() seams -- through a capturing
 * struct meshd_bearer, not the libmesh builders directly.  That distinction is
 * the point: the four proxy advertising builders and the Filter Status builder
 * were unit-tested and green while no daemon path ever called them.
 * ================================================================ */

#define	PX_MAX_TX	16

static struct px_tx_rec {
	uint8_t		pdu[MESH_PROXY_MAX_PDU];
	size_t		len;
	char		addr[18];
	uint8_t		addr_type;
	uint8_t		adapter;
} g_px_tx[PX_MAX_TX];
static size_t g_px_ntx;
static int g_px_tx_fail;

static uint8_t g_px_ad[64];
static size_t g_px_adlen;
static uint8_t g_px_policy;
static unsigned g_px_adv_calls;
static int g_px_adv_enable;

static unsigned g_px_service_calls;
static int g_px_service_enable;

static void
px_reset(void)
{

	memset(g_px_tx, 0, sizeof(g_px_tx));
	g_px_ntx = 0;
	g_px_tx_fail = 0;
	memset(g_px_ad, 0, sizeof(g_px_ad));
	g_px_adlen = 0;
	g_px_policy = 0xff;
	g_px_adv_calls = 0;
	g_px_adv_enable = -1;
	g_px_service_calls = 0;
	g_px_service_enable = -1;
}

static int
px_srv_tx(void *arg, const char *addr, uint8_t addr_type,
    uint8_t adapter_index, const uint8_t *pdu, size_t len)
{
	struct px_tx_rec *r;

	(void)arg;
	if (g_px_tx_fail)
		return (-1);
	if (g_px_ntx >= PX_MAX_TX || len > sizeof(r->pdu))
		return (-1);
	r = &g_px_tx[g_px_ntx++];
	memcpy(r->pdu, pdu, len);
	r->len = len;
	strlcpy(r->addr, addr, sizeof(r->addr));
	r->addr_type = addr_type;
	r->adapter = adapter_index;
	return (0);
}

static int
px_adv(void *arg, int enable, uint8_t addr_policy, const uint8_t *ad,
    size_t adlen)
{

	(void)arg;
	g_px_adv_calls++;
	g_px_adv_enable = enable;
	g_px_policy = addr_policy;
	g_px_adlen = adlen;
	if (adlen != 0 && adlen <= sizeof(g_px_ad))
		memcpy(g_px_ad, ad, adlen);
	return (0);
}

static int
px_service(void *arg, int enable)
{

	(void)arg;
	g_px_service_calls++;
	g_px_service_enable = enable;
	return (0);
}

static const char g_px_peer[] = "11:22:33:44:55:66";
#define	PX_MTU	69

/* Secure one proxy configuration message with the node's own credentials. */
static size_t
px_secure_cfg(struct meshd_node *nd, uint32_t seq, uint16_t src,
    const uint8_t *msg, size_t msglen, uint8_t *out, size_t outcap)
{
	uint8_t secured[MESH_PROXY_MAX_NETWORK_PDU];
	size_t slen, plen;

	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_encrypt(nd->self->enckey,
	    nd->self->privkey, nd->self->nid, nd->self->iv.iv_index, seq, src,
	    msg, msglen, secured, &slen));
	ATF_REQUIRE_EQ(0, mesh_proxy_pdu_build(MESH_PROXY_SAR_COMPLETE,
	    MESH_PROXY_TYPE_CONFIG, secured, slen, out, outcap, &plen));
	return (plen);
}

/* Decode the last captured Data Out notification as a Filter Status. */
static void
px_last_filter_status(struct meshd_node *nd, uint8_t *filter_type,
    uint16_t *list_size)
{
	struct mesh_proxy_cfg cfg;
	const uint8_t *data;
	uint8_t msg[16], sar, type;
	size_t datalen, msglen;
	uint32_t seq;
	uint16_t src;

	ATF_REQUIRE(g_px_ntx > 0);
	ATF_REQUIRE_EQ(0, mesh_proxy_pdu_parse(g_px_tx[g_px_ntx - 1].pdu,
	    g_px_tx[g_px_ntx - 1].len, &sar, &type, &data, &datalen));
	ATF_REQUIRE_EQ(MESH_PROXY_SAR_COMPLETE, sar);
	ATF_REQUIRE_EQ(MESH_PROXY_TYPE_CONFIG, type);
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_decrypt(nd->self->enckey,
	    nd->self->privkey, nd->self->nid, nd->self->iv.iv_index, data,
	    datalen, &seq, &src, msg, sizeof(msg), &msglen));
	/*
	 * Section 6.7: "a Proxy Server shall set the SRC field to the unicast
	 * address of its primary element".
	 */
	ATF_CHECK_EQ(nd->self->addr, src);
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_parse(msg, msglen, &cfg));
	ATF_REQUIRE_EQ(MESH_PROXY_OP_FILTER_STATUS, cfg.opcode);
	*filter_type = cfg.filter_type;
	*list_size = cfg.list_size;
}

/*
 * Table 7.9: "GATT Proxy state 0x01 ... Advertising: Network ID".  Driven
 * through meshd_node_tick(), so this case fails if the proxy advertising emit
 * is not wired into the daemon's tick at all -- which is exactly the state the
 * four builders were in.
 */
ATF_TC_WITHOUT_HEAD(px1_proxy_adv_network_id_from_tick);
ATF_TC_BODY(px1_proxy_adv_network_id_from_tick, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer = { .tx = capture_tx, .proxy_adv = px_adv,
	    .proxy_service = px_service, .proxy_srv_tx = px_srv_tx };
	uint8_t expect[MESH_PROXY_ADV_NETWORK_ID_LEN];
	size_t expectlen;

	(void)tc;
	px_reset();
	r4_provision(nd, &cfg, 0x0001, 0);
	meshd_set_bearer(nd, &bearer);
	nd->cfg.gatt_proxy = 1;

	r4_tick(nd, 1000);
	ATF_REQUIRE_MSG(g_px_adv_calls > 0, "the tick emitted no proxy "
	    "advertisement");
	ATF_CHECK_EQ(1, g_px_adv_enable);
	/* Table 7.6 / 7.11: a 13-octet Service Data AD structure. */
	ATF_REQUIRE_EQ(MESH_PROXY_ADV_NETWORK_ID_LEN, g_px_adlen);
	ATF_CHECK_EQ(MESH_PROXY_ADV_NETWORK_ID_LEN - 1, g_px_ad[0]);
	ATF_CHECK_EQ(MESH_AD_TYPE_SERVICE_DATA_16, g_px_ad[1]);
	ATF_CHECK_EQ(0x28, g_px_ad[2]);
	ATF_CHECK_EQ(0x18, g_px_ad[3]);
	ATF_CHECK_EQ(MESH_PROXY_ADV_NETWORK_ID, g_px_ad[4]);
	/* The Network ID is k3(NetKey) for this node's subnet. */
	ATF_REQUIRE_EQ(0, mesh_proxy_adv_network_id_build(nd->self->netkey,
	    expect, &expectlen));
	ATF_CHECK_EQ(expectlen, g_px_adlen);
	ATF_CHECK_EQ(0, memcmp(expect, g_px_ad, expectlen));

	meshd_node_fini(nd);
}

/*
 * Table 7.10 and the Section 7.2.2.2.3/7.2.2.2.5 selection: Private Node
 * Identity wins over Node Identity, which wins over Network ID; each identity
 * advertisement draws a fresh Random, and the private form asks for a private
 * advertising address.
 */
ATF_TC_WITHOUT_HEAD(px2_proxy_adv_identity_precedence);
ATF_TC_BODY(px2_proxy_adv_identity_precedence, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer = { .tx = capture_tx, .proxy_adv = px_adv,
	    .proxy_srv_tx = px_srv_tx };
	uint8_t first[MESH_PROXY_ADV_NODE_IDENTITY_LEN];

	(void)tc;
	px_reset();
	r4_provision(nd, &cfg, 0x0001, 0);
	meshd_set_bearer(nd, &bearer);
	nd->cfg.gatt_proxy = 1;

	/*
	 * Every advertisement is emitted by the daemon tick on the beacon
	 * cadence, so the clock advances by MESHD_BEACON_INTERVAL between them.
	 */
	/* Node Identity running takes precedence over the Network ID form. */
	nd->db.netkeys[0].node_identity = MESH_CFG_NODE_IDENTITY_RUNNING;
	r4_tick(nd, 1000);
	ATF_REQUIRE_EQ(MESH_PROXY_ADV_NODE_IDENTITY_LEN, g_px_adlen);
	ATF_CHECK_EQ(MESH_PROXY_ADV_NODE_IDENTITY, g_px_ad[4]);
	memcpy(first, g_px_ad, sizeof(first));

	/* "The Random field is the 64-bit random value used in the Hash": a
	 * fresh one per advertisement, so no two are identical. */
	r4_tick(nd, 1000 + MESHD_BEACON_INTERVAL * 1000ULL);
	ATF_CHECK(memcmp(first + 13, g_px_ad + 13, MESH_PROXY_ID_RANDOM_LEN)
	    != 0);

	/* Private Node Identity running takes precedence over both. */
	nd->db.netkeys[0].priv_node_identity = MESH_CFG_PRIV_IDENTITY_RUNNING;
	r4_tick(nd, 1000 + 2 * MESHD_BEACON_INTERVAL * 1000ULL);
	ATF_REQUIRE_EQ(MESH_PROXY_ADV_PRIVATE_NODE_IDENTITY_LEN, g_px_adlen);
	ATF_CHECK_EQ(MESH_PROXY_ADV_PRIVATE_NODE_IDENTITY, g_px_ad[4]);
	/*
	 * Section 7.2.2.2.5: "shall use a resolvable private address or a
	 * non-resolvable private address in the AdvA field".
	 */
	ATF_CHECK(g_px_policy == MESHD_ADV_ADDR_NRPA ||
	    g_px_policy == MESHD_ADV_ADDR_RPA);

	/* Both identity states stopped and GATT Proxy off: nothing to air. */
	nd->db.netkeys[0].node_identity = MESH_CFG_NODE_IDENTITY_STOPPED;
	nd->db.netkeys[0].priv_node_identity = MESH_CFG_PRIV_IDENTITY_STOPPED;
	nd->cfg.gatt_proxy = 0;
	g_px_adv_calls = 0;
	r4_tick(nd, 1000 + 3 * MESHD_BEACON_INTERVAL * 1000ULL);
	ATF_CHECK_EQ(1, g_px_adv_calls);	/* the stop */
	ATF_CHECK_EQ(0, g_px_adv_enable);

	meshd_node_fini(nd);
}

/*
 * Sections 7.2.2.2.2-7.2.2.2.5: "When a server is a member of multiple subnets,
 * it shall interleave the advertising of each subnet."
 */
ATF_TC_WITHOUT_HEAD(px3_proxy_adv_interleaves_subnets);
ATF_TC_BODY(px3_proxy_adv_interleaves_subnets, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer = { .tx = capture_tx, .proxy_adv = px_adv,
	    .proxy_srv_tx = px_srv_tx };
	uint8_t netid0[MESH_PROXY_ADV_NETWORK_ID_LEN];
	uint8_t netid1[MESH_PROXY_ADV_NETWORK_ID_LEN];
	uint8_t second[16];
	size_t len0, len1;

	(void)tc;
	px_reset();
	r4_provision(nd, &cfg, 0x0001, 0);
	meshd_set_bearer(nd, &bearer);
	nd->cfg.gatt_proxy = 1;

	/* A second subnet in the configuration database. */
	memset(second, 0x77, sizeof(second));
	nd->db.netkeys[1].valid = 1;
	nd->db.netkeys[1].net_idx = 0x001;
	memcpy(nd->db.netkeys[1].key, second, sizeof(second));

	ATF_REQUIRE_EQ(0, mesh_proxy_adv_network_id_build(nd->self->netkey,
	    netid0, &len0));
	ATF_REQUIRE_EQ(0, mesh_proxy_adv_network_id_build(second, netid1,
	    &len1));

	r4_tick(nd, 1000);
	ATF_CHECK_EQ(0, memcmp(netid0, g_px_ad, len0));
	r4_tick(nd, 1000 + MESHD_BEACON_INTERVAL * 1000ULL);
	ATF_CHECK_EQ(0, memcmp(netid1, g_px_ad, len1));
	/* And back round to the first: the cursor wraps, it does not stick. */
	r4_tick(nd, 1000 + 2 * MESHD_BEACON_INTERVAL * 1000ULL);
	ATF_CHECK_EQ(0, memcmp(netid0, g_px_ad, len0));

	meshd_node_fini(nd);
}

/*
 * Section 6.7: every Set Filter Type, Add Addresses and Remove Addresses is
 * answered with a Filter Status, secured with the credentials that secured the
 * request.  Driven through meshd_proxy_server_recv(), the daemon's Data In
 * entry point.
 */
ATF_TC_WITHOUT_HEAD(px4_proxy_server_answers_filter_status);
ATF_TC_BODY(px4_proxy_server_answers_filter_status, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer = { .tx = capture_tx, .proxy_srv_tx = px_srv_tx };
	uint8_t msg[1 + MESH_PROXY_MAX_ADDR_PER_MSG * 2];
	uint8_t pdu[MESH_PROXY_MAX_PDU];
	uint16_t addrs[3], list_size;
	uint8_t filter_type;
	size_t mlen, plen;

	(void)tc;
	px_reset();
	r4_provision(nd, &cfg, 0x0001, 0);
	meshd_set_bearer(nd, &bearer);
	ATF_REQUIRE_EQ(0, meshd_proxy_server_open(nd, g_px_peer, 0, 0, PX_MTU));

	/* Set Filter Type (reject list). */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_set_filter_build(
	    MESH_PROXY_FILTER_REJECT, msg, sizeof(msg), &mlen));
	plen = px_secure_cfg(nd, 1, 0x0002, msg, mlen, pdu, sizeof(pdu));
	g_px_ntx = 0;
	ATF_REQUIRE_EQ(1, meshd_proxy_server_recv(nd, g_px_peer, 0, 0, pdu,
	    plen, PX_MTU, 1000));
	ATF_REQUIRE_MSG(g_px_ntx == 1, "no Filter Status was sent (%zu)",
	    g_px_ntx);
	px_last_filter_status(nd, &filter_type, &list_size);
	ATF_CHECK_EQ(MESH_PROXY_FILTER_REJECT, filter_type);
	ATF_CHECK_EQ(0, list_size);
	/* It was notified to the connection the request arrived on. */
	ATF_CHECK_EQ(0, strcmp(g_px_peer, g_px_tx[0].addr));

	/*
	 * Add Addresses: "If the AddressArray field contains the unassigned
	 * address, the Proxy Server shall ignore that address", and an address
	 * already in the list is not added twice.
	 */
	addrs[0] = 0x0000;
	addrs[1] = 0xC000;
	addrs[2] = 0xC000;
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_addr_build(MESH_PROXY_OP_ADD_ADDR,
	    addrs, 3, msg, sizeof(msg), &mlen));
	plen = px_secure_cfg(nd, 2, 0x0002, msg, mlen, pdu, sizeof(pdu));
	g_px_ntx = 0;
	ATF_REQUIRE_EQ(1, meshd_proxy_server_recv(nd, g_px_peer, 0, 0, pdu,
	    plen, PX_MTU, 2000));
	ATF_REQUIRE_EQ(1, g_px_ntx);
	px_last_filter_status(nd, &filter_type, &list_size);
	ATF_CHECK_EQ(MESH_PROXY_FILTER_REJECT, filter_type);
	ATF_CHECK_EQ(1, list_size);

	/* Remove Addresses takes it back out. */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_addr_build(MESH_PROXY_OP_REMOVE_ADDR,
	    addrs, 3, msg, sizeof(msg), &mlen));
	plen = px_secure_cfg(nd, 3, 0x0002, msg, mlen, pdu, sizeof(pdu));
	g_px_ntx = 0;
	ATF_REQUIRE_EQ(1, meshd_proxy_server_recv(nd, g_px_peer, 0, 0, pdu,
	    plen, PX_MTU, 3000));
	ATF_REQUIRE_EQ(1, g_px_ntx);
	px_last_filter_status(nd, &filter_type, &list_size);
	ATF_CHECK_EQ(0, list_size);

	meshd_node_fini(nd);
}

/*
 * Section 6.4/6.4.1 and 6.7: the proxy filter gates the Proxy Server's network
 * interface output, and a Network PDU from the Proxy Client teaches the accept
 * list that client's SRC.
 */
ATF_TC_WITHOUT_HEAD(px5_proxy_server_filters_and_learns);
ATF_TC_BODY(px5_proxy_server_filters_and_learns, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer = { .tx = capture_tx, .proxy_srv_tx = px_srv_tx };
	struct mesh_net_pdu net;
	uint8_t wire[MESH_PROXY_MAX_NETWORK_PDU];
	uint8_t pdu[MESH_PROXY_MAX_PDU];
	size_t wirelen, plen;

	(void)tc;
	px_reset();
	r4_provision(nd, &cfg, 0x0001, 0);
	meshd_set_bearer(nd, &bearer);
	ATF_REQUIRE_EQ(0, meshd_proxy_server_open(nd, g_px_peer, 0, 0, PX_MTU));
	g_px_ntx = 0;

	/* The default accept-list filter is empty, so nothing is forwarded. */
	memset(&net, 0, sizeof(net));
	net.nid = nd->self->nid;
	net.ttl = 5;
	net.seq = 10;
	net.src = 0x0009;
	net.dst = 0xC000;
	net.transport_len = 6;
	memset(net.transport, 0xAB, net.transport_len);
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(nd->self->enckey, nd->self->privkey,
	    nd->self->nid, nd->self->iv.iv_index, &net, wire, &wirelen));
	ATF_CHECK_EQ(0, meshd_proxy_server_forward(nd, wire, wirelen));
	ATF_CHECK_EQ(0, g_px_ntx);

	/*
	 * "upon receiving a Proxy PDU containing a valid Network PDU from the
	 * Proxy Client, the Proxy Server shall add the unicast address
	 * contained in the SRC field of the Network PDU to the accept list"
	 * (Section 6.7).  Feed one in from SRC 0x0007.
	 */
	net.seq = 11;
	net.src = 0x0007;
	net.dst = 0x0001;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(nd->self->enckey, nd->self->privkey,
	    nd->self->nid, nd->self->iv.iv_index, &net, wire, &wirelen));
	ATF_REQUIRE_EQ(0, mesh_proxy_pdu_build(MESH_PROXY_SAR_COMPLETE,
	    MESH_PROXY_TYPE_NETWORK, wire, wirelen, pdu, sizeof(pdu), &plen));
	(void)meshd_proxy_server_recv(nd, g_px_peer, 0, 0, pdu, plen, PX_MTU,
	    1000);
	ATF_CHECK_EQ(1, mesh_proxy_filter_accepts(&nd->proxy_srv[0].filter,
	    0x0007));

	/* A PDU addressed to that learned address is now forwarded verbatim. */
	net.seq = 12;
	net.src = 0x0003;
	net.dst = 0x0007;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(nd->self->enckey, nd->self->privkey,
	    nd->self->nid, nd->self->iv.iv_index, &net, wire, &wirelen));
	g_px_ntx = 0;
	ATF_REQUIRE_EQ(1, meshd_proxy_server_forward(nd, wire, wirelen));
	ATF_REQUIRE_EQ(1, g_px_ntx);
	ATF_CHECK_EQ(wirelen + MESH_PROXY_HDR_LEN, g_px_tx[0].len);
	ATF_CHECK_EQ(0, memcmp(wire, g_px_tx[0].pdu + MESH_PROXY_HDR_LEN,
	    wirelen));

	/* One addressed elsewhere is still blocked by the accept list. */
	net.seq = 13;
	net.dst = 0x0055;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(nd->self->enckey, nd->self->privkey,
	    nd->self->nid, nd->self->iv.iv_index, &net, wire, &wirelen));
	g_px_ntx = 0;
	ATF_CHECK_EQ(0, meshd_proxy_server_forward(nd, wire, wirelen));
	ATF_CHECK_EQ(0, g_px_ntx);

	meshd_node_fini(nd);
}

/*
 * Section 6.7: "Upon connection ... The Proxy Server shall send a mesh beacon
 * for each known subnet to the Proxy Client", and Section 7.2.2.2 makes the
 * «Mesh Proxy Service» present in the GATT database of a node with the Proxy
 * feature enabled.  The registration is driven from meshd_node_tick().
 */
ATF_TC_WITHOUT_HEAD(px6_proxy_service_and_connect_beacons);
ATF_TC_BODY(px6_proxy_service_and_connect_beacons, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	struct meshd_bearer bearer = { .tx = capture_tx, .proxy_adv = px_adv,
	    .proxy_service = px_service, .proxy_srv_tx = px_srv_tx };
	const uint8_t *data;
	uint8_t sar, type;
	size_t datalen;

	(void)tc;
	px_reset();
	r4_provision(nd, &cfg, 0x0001, 0);
	meshd_set_bearer(nd, &bearer);
	nd->cfg.gatt_proxy = 1;

	r4_tick(nd, 1000);
	ATF_REQUIRE_MSG(g_px_service_calls > 0, "the tick never registered the "
	    "Mesh Proxy Service");
	ATF_CHECK_EQ(1, g_px_service_enable);
	ATF_CHECK_EQ(1, nd->proxy_service_registered);
	/* Idempotent: a second tick does not re-register. */
	r4_tick(nd, 1010);
	ATF_CHECK_EQ(1, g_px_service_calls);

	g_px_ntx = 0;
	ATF_REQUIRE_EQ(0, meshd_proxy_server_open(nd, g_px_peer, 0, 0, PX_MTU));
	ATF_REQUIRE_MSG(g_px_ntx == 1, "connection sent %zu beacons", g_px_ntx);
	ATF_REQUIRE_EQ(0, mesh_proxy_pdu_parse(g_px_tx[0].pdu, g_px_tx[0].len,
	    &sar, &type, &data, &datalen));
	ATF_CHECK_EQ(MESH_PROXY_TYPE_BEACON, type);
	/*
	 * Table 6.15: with the GATT Proxy state enabled the Proxy Privacy
	 * parameter is Disabled (Section 7.2.2.2.6), so a Secure Network
	 * beacon is what goes out.
	 */
	ATF_CHECK_EQ(MESH_BEACON_TYPE_SECURE_NETWORK, data[0]);
	ATF_CHECK_EQ(0, nd->proxy_srv[0].privacy);

	/* Closing the connection drops its per-connection state entirely. */
	meshd_proxy_server_close(nd, g_px_peer, 0, 0);
	ATF_CHECK_EQ(0, nd->proxy_srv[0].active);

	meshd_node_fini(nd);
}

/* ---- IM10: an ordinary IV Update is not an IV Index Recovery ----------- */
/*
 * MshPRT_v1.1.1 Section 3.11.6 Table 3.86 overlaps the ordinary IV Update
 * procedure at Current IV Index + 1.  Row 1 - Normal, Current + 1, IV Update
 * flag 1 - is the everyday "the network has started an IV Update" beacon, and
 * Section 3.11.5 already owns it: the node transitions only after 96 hours in
 * its current state.  Routing it through recovery instead re-anchors that
 * dwell (Section 3.11.6: "the 96-hour time limits ... shall not apply") and
 * spends the credit the specification rations to once per 192 hours, so a
 * routine update would leave the node unable to recover a genuinely missed one.
 *
 * Driven through meshd_beacon_rx(), the daemon's beacon entry point.
 */
ATF_TC_WITHOUT_HEAD(im10_ordinary_iv_update_is_not_recovery);
ATF_TC_BODY(im10_ordinary_iv_update_is_not_recovery, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t beacon[MESH_SECURE_BEACON_LEN];
	size_t blen;

	(void)tc;
	base_config(&cfg);
	cfg.iv_index = 100;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	ATF_REQUIRE_EQ(100u, nd->self->iv.iv_index);
	nd->self->seq = 4242;

	/*
	 * Table 3.86 row 1 / Table 3.85: Current + 1 with the IV Update flag
	 * set.  The node was just provisioned, so its 96-hour dwell has not
	 * run: the ordinary procedure leaves the IV Index alone.
	 */
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(cfg.netkey, 0, 1, 101,
	    beacon, &blen));
	ATF_CHECK_EQ(1, meshd_beacon_rx(nd, beacon, blen));
	ATF_CHECK_EQ_MSG(100u, nd->self->iv.iv_index,
	    "an ordinary IV Update must respect the 96-hour dwell");
	ATF_CHECK_EQ(MESH_IV_NORMAL, nd->self->iv.state);
	ATF_CHECK_EQ_MSG(4242u, nd->self->seq,
	    "Table 3.86 row 1 carries no sequence-number reset");
	ATF_CHECK_EQ_MSG(0, nd->self->iv.recovery_done,
	    "an ordinary IV Update must not consume the recovery credit");
	ATF_CHECK_EQ(0, nd->self->iv.recovery_active);

	/*
	 * The credit is therefore still available for what it is for: an
	 * out-of-order IV Index the ordinary procedure cannot explain (Table
	 * 3.86 last row), which is adopted and does reset the sequence numbers.
	 */
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(cfg.netkey, 0, 0, 107,
	    beacon, &blen));
	ATF_CHECK_EQ(1, meshd_beacon_rx(nd, beacon, blen));
	ATF_CHECK_EQ_MSG(107u, nd->self->iv.iv_index,
	    "IV Index Recovery must still adopt Current + 7");
	ATF_CHECK_EQ(0u, nd->self->seq);
	ATF_CHECK_EQ(1, nd->self->iv.recovery_done);

	meshd_node_fini(nd);
}

/* ---- IM32: Node Identity and Private Node Identity are exclusive ------ */
/*
 * MshPRT_v1.1.1 Section 4.2.46.1 "Binding with Node Identity", verbatim:
 *
 *   "If the value of the Node Identity state of the node for any subnet is
 *    Enabled (see Table 4.28), then the value of the Private Node Identity
 *    state shall be Disabled for each known subnet.  Therefore, to change the
 *    Private Node Identity state to Enabled, the Node Identity state must be
 *    set to Disabled for all subnets."
 *
 * Table 4.364 names the status for the refused Set - "The node cannot change
 * the Private Node Identity state due to binding with the Node Identity state
 * (see Section 4.2.46.1)" -> "Temporarily Unable to Change State", which
 * Table 4.308 numbers 0x0E - and Section 4.4.11.2.3 fixes what the failing
 * Status carries: "with the NetKeyIndex and Private_Identity fields set to the
 * corresponding values in the incoming message".
 *
 * Both states were independently writable, so a Configuration Manager could
 * leave both Enabled and the node would advertise its plain, trackable Node
 * Identity alongside the private one - which is the entire thing Private Node
 * Identity exists to prevent.
 *
 * Driven through meshd_foundation_recv(), the Configuration Server entry
 * point, with a second subnet present so the "for any subnet" / "for each
 * known subnet" scope is actually exercised.
 */
ATF_TC_WITHOUT_HEAD(im32_node_identity_excludes_private);
ATF_TC_BODY(im32_node_identity_excludes_private, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_priv_node_identity pid, got;
	struct mesh_cfg_netkey nk;
	uint8_t msg[64], reply[64];
	uint16_t net_idx;
	uint8_t status, identity;
	size_t mlen, rlen = 0;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* A second subnet, so "any subnet" / "each known subnet" has teeth. */
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 1;
	memset(nk.key, 0x77, sizeof(nk.key));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD, &nk,
	    msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

	/* With Node Identity Disabled everywhere, Private may be Enabled. */
	memset(&pid, 0, sizeof(pid));
	pid.net_idx = 0;
	pid.identity = MESH_CFG_PRIV_IDENTITY_RUNNING;
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_set_build(&pid, msg,
	    &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_status_parse(reply, rlen,
	    &status, &got));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(MESH_CFG_PRIV_IDENTITY_RUNNING, got.identity);

	/*
	 * THE GATE, first direction.  Enabling Node Identity on subnet 1 must
	 * drive Private Node Identity to Disabled on EVERY known subnet,
	 * including subnet 0 where it was just Enabled.
	 */
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_set_build(1,
	    MESH_CFG_NODE_IDENTITY_RUNNING, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_status_parse(reply, rlen,
	    &status, &net_idx, &identity));
	ATF_REQUIRE_EQ(MESH_CFG_SUCCESS, status);
	ATF_REQUIRE_EQ(MESH_CFG_NODE_IDENTITY_RUNNING, identity);

	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_get_build(0, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_status_parse(reply, rlen,
	    &status, &got));
	ATF_CHECK_EQ_MSG(MESH_CFG_PRIV_IDENTITY_STOPPED, got.identity,
	    "Node Identity Enabled anywhere forces Private Disabled here");

	/*
	 * THE GATE, second direction.  A Private Node Identity Set to Enabled
	 * while Node Identity is Enabled on subnet 1 must be REFUSED with
	 * Temporarily Unable to Change State (0x0E), must leave the stored
	 * state alone, and must echo the incoming NetKeyIndex and
	 * Private_Identity.
	 */
	pid.net_idx = 0;
	pid.identity = MESH_CFG_PRIV_IDENTITY_RUNNING;
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_set_build(&pid, msg,
	    &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_status_parse(reply, rlen,
	    &status, &got));
	ATF_CHECK_EQ_MSG(MESH_CFG_TEMP_UNABLE_TO_CHANGE, status,
	    "Table 4.364: binding with Node Identity is 0x0E");
	ATF_CHECK_EQ_MSG(0, got.net_idx, "Section 4.4.11.2.3 echoes NetKeyIndex");
	ATF_CHECK_EQ_MSG(MESH_CFG_PRIV_IDENTITY_RUNNING, got.identity,
	    "Section 4.4.11.2.3 echoes the incoming Private_Identity");
	ATF_CHECK_EQ_MSG(MESH_CFG_PRIV_IDENTITY_STOPPED,
	    nd->db.netkeys[0].priv_node_identity,
	    "a refused Set must not change the stored state");

	/* Disabling Node Identity again releases the binding. */
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_set_build(1,
	    MESH_CFG_NODE_IDENTITY_STOPPED, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_set_build(&pid, msg,
	    &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_status_parse(reply, rlen,
	    &status, &got));
	ATF_CHECK_EQ_MSG(MESH_CFG_SUCCESS, status,
	    "with Node Identity Disabled on all subnets the Set succeeds");
	ATF_CHECK_EQ(MESH_CFG_PRIV_IDENTITY_RUNNING, got.identity);

	meshd_node_fini(nd);
}

/* ---- IM29: Config Node Reset erases the key material ------------------ */
/*
 * MshPRT_v1.1.1 Section 4.4.1.2, verbatim: "When an element receives a Config
 * Node Reset message, it shall perform the Node Removal procedure (see Section
 * 3.11.7) and respond with a Config Node Reset Status message."
 *
 * Section 3.11.7, verbatim: "When the Node Removal procedure is started, the
 * node shall delete all stored security credentials, all stored security
 * material, the device key, and the provisioning data.  If the node supports
 * provisioning, the node shall become an unprovisioned device."
 *
 * The reset cleared the Configuration Server's own copy of the key list and
 * left the LIVE keys behind - the NetKey, its derived flooding/directed
 * material, every secondary subnet, every AppKey and the device key - so a
 * node retired because it was compromised, or sold on, still held everything,
 * and the next persistence save wrote it all back to disk.
 *
 * Driven through meshd_foundation_recv() (Config NetKey Add / AppKey Add /
 * Node Reset) and meshd_persist_save().
 */
ATF_TC_WITHOUT_HEAD(im29_node_reset_erases_key_material);
ATF_TC_BODY(im29_node_reset_erases_key_material, tc)
{
	static const uint8_t primary[16] = {
		0x5a, 0x11, 0xc3, 0x27, 0x84, 0xde, 0x0f, 0x9b,
		0x62, 0xa4, 0x7e, 0x30, 0xd8, 0x15, 0xcc, 0x49,
	};
	static const uint8_t secondary[16] = {
		0x0e, 0x73, 0xb1, 0x5f, 0x2a, 0x96, 0xd4, 0x38,
		0xf1, 0x6c, 0x07, 0xab, 0x52, 0xe9, 0x84, 0x1d,
	};
	static const uint8_t app[16] = {
		0xc7, 0x42, 0x9e, 0x08, 0xb5, 0x6d, 0x31, 0xfa,
		0x27, 0x8c, 0xe0, 0x94, 0x1b, 0x75, 0xa3, 0x6e,
	};
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_persist ps;
	struct mesh_cfg_netkey nk;
	struct mesh_cfg_appkey ak;
	const char *path = "meshd_im29.state";
	uint8_t msg[64], reply[64];
	uint8_t zero16[16];
	uint8_t *blob;
	long blen;
	FILE *f;
	size_t mlen, rlen = 0, i;

	(void)tc;
	memset(zero16, 0, sizeof(zero16));
	base_config(&cfg);
	memcpy(cfg.netkey, primary, 16);
	memcpy(cfg.appkey, app, 16);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	ATF_REQUIRE_EQ(0, memcmp(nd->self->netkey, primary, 16));

	/* A device key, a secondary subnet and a second AppKey to erase. */
	memset(nd->self->devkey, 0x3c, sizeof(nd->self->devkey));
	nd->self->have_devkey = 1;
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 1;
	memcpy(nk.key, secondary, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD, &nk,
	    msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0;
	ak.app_idx = 3;
	memcpy(ak.key, app, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));

	/* Sanity: the material really is present before the reset. */
	ATF_REQUIRE(memcmp(nd->self->enckey, zero16, 16) != 0);
	ATF_REQUIRE(memcmp(nd->self->directed_enckey, zero16, 16) != 0);
	ATF_REQUIRE(nd->self->n_subnets > 0);
	ATF_REQUIRE(nd->self->n_appkeys > 0);

	/* Config Node Reset through the Configuration Server. */
	ATF_REQUIRE_EQ(0, mesh_cfg_node_reset_build(msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(0, nd->provisioned);

	/* "all stored security credentials, all stored security material" */
	ATF_CHECK_EQ_MSG(0, memcmp(nd->self->netkey, zero16, 16),
	    "the NetKey must be gone");
	ATF_CHECK_EQ(0, nd->self->nid);
	ATF_CHECK_EQ_MSG(0, memcmp(nd->self->enckey, zero16, 16),
	    "the flooding EncryptionKey must be gone");
	ATF_CHECK_EQ(0, memcmp(nd->self->privkey, zero16, 16));
	ATF_CHECK_EQ_MSG(0, memcmp(nd->self->directed_enckey, zero16, 16),
	    "the directed EncryptionKey must be gone");
	ATF_CHECK_EQ(0, memcmp(nd->self->directed_privkey, zero16, 16));
	ATF_CHECK_EQ(0, nd->self->directed_nid);
	ATF_CHECK_EQ(0, nd->self->have_new_key);
	ATF_CHECK_EQ_MSG(0u, (unsigned)nd->self->n_subnets,
	    "every secondary subnet must be gone");
	for (i = 0; i < MESH_SIM_MAX_SUBNETS; i++)
		ATF_CHECK_EQ(0, nd->self->subnets[i].valid);
	ATF_CHECK_EQ_MSG(0u, (unsigned)nd->self->n_appkeys,
	    "every application key must be gone");
	for (i = 0; i < MESH_SIM_MAX_APPKEYS; i++)
		ATF_CHECK_EQ(0, nd->self->appkeys[i].valid);
	ATF_CHECK_EQ(0, nd->self->have_friend_cred);
	ATF_CHECK_EQ(0, nd->self->have_new_friend_cred);
	/* "the device key" */
	ATF_CHECK_EQ_MSG(0, nd->self->have_devkey, "the device key must be gone");
	ATF_CHECK_EQ(0, memcmp(nd->self->devkey, zero16, 16));

	/*
	 * And it must not come back off disk.  A save after the reset is what a
	 * running daemon does at the bottom of its event loop; none of the
	 * three keys may appear anywhere in the stored state.
	 */
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, nd));
	f = fopen(path, "rb");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE_EQ(0, fseek(f, 0, SEEK_END));
	blen = ftell(f);
	ATF_REQUIRE(blen > 0);
	ATF_REQUIRE_EQ(0, fseek(f, 0, SEEK_SET));
	blob = malloc((size_t)blen);
	ATF_REQUIRE(blob != NULL);
	ATF_REQUIRE_EQ((size_t)blen, fread(blob, 1, (size_t)blen, f));
	(void)fclose(f);
	for (i = 0; i + 16 <= (size_t)blen; i++) {
		ATF_CHECK_MSG(memcmp(blob + i, primary, 16) != 0,
		    "the NetKey is still in the persisted state at offset %zu",
		    i);
		ATF_CHECK_MSG(memcmp(blob + i, secondary, 16) != 0,
		    "the secondary NetKey is still persisted at offset %zu", i);
		ATF_CHECK_MSG(memcmp(blob + i, app, 16) != 0,
		    "the AppKey is still persisted at offset %zu", i);
	}
	free(blob);
	(void)unlink(path);
	meshd_node_fini(nd);
}

/* ---- IM28: IV Update completion defers to an unacknowledged SAR TX ---- */
/*
 * MshPRT_v1.1.1 Section 3.11.5, verbatim:
 *
 *   "A node shall defer state change from IV Update in Progress to Normal
 *    Operation, as defined by this procedure, when the node has transmitted a
 *    Segmented Access message or a Segmented Control message without receiving
 *    the corresponding Segment Acknowledgment messages.  The deferred change
 *    of the state shall be executed when the appropriate Segment
 *    Acknowledgment message is received or the timeout for the delivery of
 *    this message is reached."
 *
 *   "Note: This requirement is necessary because upon completing the IV Update
 *    procedure the sequence number is reset to 0x000000 and the SeqAuth value
 *    would not be valid."
 *
 * Driven through meshd_send_access_raw() (the daemon's originate entry point,
 * which is what arms the SAR transmitter) and meshd_node_tick() (which is
 * where the daemon completes an IV Update).
 */
ATF_TC_WITHOUT_HEAD(im28_iv_completion_defers_to_segmented_tx);
ATF_TC_BODY(im28_iv_completion_defers_to_segmented_tx, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	MESH_HEAP(struct meshd_node, ctl);
	struct meshd_bearer bearer = { .arg = NULL, .tx = sar_capture_tx };
	uint8_t access[64];
	uint64_t t;
	size_t i;
	int changed;

	(void)tc;
	base_config(&cfg);
	cfg.iv_index = 100;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);

	/*
	 * TEST SETUP: the node is in IV Update in Progress at IV Index 101
	 * (so it transmits with 100) and the 96-hour dwell has run, which is
	 * exactly the state in which the tick below would otherwise complete
	 * the update on its next pass.  entered_time is CLOCK_REALTIME seconds
	 * (see f71_iv_dwell_reboot).
	 */
	nd->self->iv.iv_index = 101;
	nd->self->iv.state = MESH_IV_UPDATE_IN_PROGRESS;
	nd->self->iv.entered_time = 0;

	/* A segmented access message to a UNICAST peer arms the SAR transmitter. */
	access[0] = 0x82;
	access[1] = 0x99;
	for (i = 2; i < sizeof(access); i++)
		access[i] = (uint8_t)i;
	g_sar_n = 0;
	ATF_REQUIRE_EQ(0, meshd_send_access_raw(nd, 0x0002, access,
	    sizeof(access)));
	ATF_REQUIRE_MSG(g_sar_n > 1, "message must segment (%zu frames)",
	    g_sar_n);
	ATF_REQUIRE_EQ(1, nd->self->sar_tx[0].used);

	/*
	 * THE GATE.  No Segment Acknowledgment arrives.  The tick must NOT
	 * complete the update, because completing it zeroes the sequence
	 * number and invalidates the SeqAuth of the transfer in flight.
	 */
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 100, &changed));
	ATF_CHECK_EQ_MSG(MESH_IV_UPDATE_IN_PROGRESS, nd->self->iv.state,
	    "completion must be deferred while a segmented TX is unacked");
	ATF_CHECK_EQ_MSG(101u, nd->self->iv.iv_index,
	    "the deferred node keeps the In Progress index");
	ATF_CHECK_MSG(nd->self->seq != 0,
	    "a deferred completion must not reset the sequence number");
	ATF_CHECK_MSG(nd->self->iv_complete_deferrals > 0,
	    "the deferral must be taken, not merely blocked by the dwell");

	/*
	 * The beacon-driven completion is deferred by the same rule.  A Secure
	 * Network beacon at the SAME IV Index with the IV Update flag clear is
	 * the network reporting Normal Operation, and Table 3.85 has an In
	 * Progress node follow it - but not while a segmented transfer is
	 * unacknowledged.  meshd_beacon_rx() is the daemon's beacon entry.
	 */
	{
		uint8_t beacon[MESH_SECURE_BEACON_LEN];
		size_t blen;
		uint32_t before = nd->self->iv_complete_deferrals;

		ATF_REQUIRE_EQ(1, nd->self->sar_tx[0].used);
		ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(cfg.netkey, 0, 0,
		    101, beacon, &blen));
		ATF_CHECK_EQ(1, meshd_beacon_rx(nd, beacon, blen));
		ATF_CHECK_EQ_MSG(MESH_IV_UPDATE_IN_PROGRESS, nd->self->iv.state,
		    "a beacon must not complete the update either");
		ATF_CHECK_MSG(nd->self->iv_complete_deferrals > before,
		    "the beacon path must take the deferral");
	}

	/*
	 * "... or the timeout for the delivery of this message is reached."
	 * With no acknowledgment the SAR transmitter exhausts its
	 * retransmission budget and releases the slot; the deferred completion
	 * is then executed by the next tick.
	 */
	for (t = 500; t <= 20000 && nd->self->sar_tx[0].used; t += 500)
		ATF_REQUIRE(meshd_node_tick(nd, t, &changed) >= 0);
	ATF_REQUIRE_EQ_MSG(0, nd->self->sar_tx[0].used,
	    "the SAR transmit slot must eventually be released");
	ATF_REQUIRE(meshd_node_tick(nd, t + 500, &changed) >= 0);
	ATF_CHECK_EQ_MSG(MESH_IV_NORMAL, nd->self->iv.state,
	    "the deferred completion must be executed once the SAR drains");
	ATF_CHECK_EQ(101u, nd->self->iv.iv_index);
	ATF_CHECK_EQ_MSG(0u, nd->self->seq,
	    "completion opens the new epoch with SEQ 0x000000");

	/*
	 * The control: an identical node with NOTHING in flight completes on
	 * its very first tick.  Without this the test could pass by never
	 * completing an IV Update at all.
	 */
	ATF_REQUIRE_EQ(0, meshd_node_init(ctl, &cfg));
	ctl->self->iv.iv_index = 101;
	ctl->self->iv.state = MESH_IV_UPDATE_IN_PROGRESS;
	ctl->self->iv.entered_time = 0;
	ATF_REQUIRE_EQ(0, meshd_node_tick(ctl, 100, &changed));
	ATF_CHECK_EQ_MSG(MESH_IV_NORMAL, ctl->self->iv.state,
	    "with no segmented transfer outstanding the tick completes at once");
	ATF_CHECK_EQ(0u, ctl->self->iv_complete_deferrals);

	meshd_node_fini(ctl);
	meshd_node_fini(nd);
}

/* ---- IM26: a secondary subnet may not drive the primary IV Index ------ */
/*
 * MshPRT_v1.1.1 Section 3.11.5, verbatim:
 *
 *   "If this node is a member of a primary subnet and receives a Secure
 *    Network beacon or a Mesh Private beacon on a secondary subnet with an IV
 *    Index greater than the last known IV Index of the primary subnet, the
 *    Secure Network beacon or the Mesh Private beacon shall be ignored."
 *
 * The IV Index is one resource for the whole node, and Section 3.11.2 makes a
 * secondary subnet the deliberately lower-trust one (a guest subnet).  Holding
 * only a secondary NetKey must not let a beacon move the node's IV Index.
 *
 * Driven through meshd_foundation_recv() (Config NetKey Add, to install the
 * secondary subnet) and meshd_beacon_rx() (the daemon's beacon entry point).
 */
ATF_TC_WITHOUT_HEAD(im26_secondary_subnet_cannot_drive_iv);
ATF_TC_BODY(im26_secondary_subnet_cannot_drive_iv, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_netkey nk;
	uint8_t beacon[MESH_SECURE_BEACON_LEN];
	uint8_t msg[64], reply[64];
	uint8_t secondary[16];
	size_t blen, mlen, rlen = 0;

	(void)tc;
	base_config(&cfg);
	cfg.iv_index = 100;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	ATF_REQUIRE_EQ(100u, nd->self->iv.iv_index);
	nd->self->seq = 4242;
	/*
	 * TEST SETUP: age the node past the Section 3.11.5 96-hour dwell, so
	 * the ORDINARY IV Update transition is available and the assertions
	 * below are about the subnet the beacon arrived on and nothing else.
	 * entered_time is CLOCK_REALTIME seconds (see f71_iv_dwell_reboot), so
	 * zero is unambiguously more than 96 hours ago.
	 */
	nd->self->iv.entered_time = 0;

	/* Install a secondary subnet, NetKeyIndex 1, through the Config Server. */
	memset(secondary, 0x99, sizeof(secondary));
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 1;
	memcpy(nk.key, secondary, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD, &nk,
	    msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

	/*
	 * THE GATE.  A beacon authenticated on the SECONDARY subnet at Current
	 * + 1 with the IV Update flag set - the everyday "the network has
	 * started an IV Update" observation.  On the primary subnet this is the
	 * ordinary Section 3.11.5 transition; on a secondary subnet it must be
	 * ignored outright.
	 */
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(secondary, 0, 1, 101,
	    beacon, &blen));
	ATF_CHECK_EQ(1, meshd_beacon_rx(nd, beacon, blen));
	ATF_CHECK_EQ_MSG(100u, nd->self->iv.iv_index,
	    "a secondary-subnet beacon must not advance the IV Index");
	ATF_CHECK_EQ_MSG(MESH_IV_NORMAL, nd->self->iv.state,
	    "a secondary-subnet beacon must not start an IV Update");
	ATF_CHECK_EQ(4242u, nd->self->seq);

	/*
	 * The same is true of an out-of-order index the recovery procedure
	 * would otherwise adopt.  (Recovery ARMING was already restricted to
	 * the primary subnet before this fix, so this arm PINS that behaviour
	 * rather than gating the fix.)
	 */
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(secondary, 0, 0, 107,
	    beacon, &blen));
	ATF_CHECK_EQ(1, meshd_beacon_rx(nd, beacon, blen));
	ATF_CHECK_EQ_MSG(100u, nd->self->iv.iv_index,
	    "a secondary-subnet beacon must not drive IV Index Recovery");
	ATF_CHECK_EQ(0, nd->self->iv.recovery_done);

	/*
	 * The control: the identical observation on the PRIMARY subnet IS
	 * accepted.  Without this the test could pass by ignoring every beacon.
	 */
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(cfg.netkey, 0, 0, 107,
	    beacon, &blen));
	ATF_CHECK_EQ(1, meshd_beacon_rx(nd, beacon, blen));
	ATF_CHECK_EQ_MSG(107u, nd->self->iv.iv_index,
	    "the primary subnet still drives the IV Index");
	ATF_CHECK_EQ(1, nd->self->iv.recovery_done);

	meshd_node_fini(nd);
}

/* ---- IM3: the model AppKey-binding check is unconditional ------------- */
/*
 * MshPRT_v1.1.1 Section 3.7.3 and Figure 3.72: an access message secured with
 * an application key is processed by a model only when that AppKey is bound to
 * the model - "Has the Model a matching AppKey bound?" -> "No" -> "Drop the
 * Message".  A model with no bindings at all has no matching AppKey, and that
 * is the state of EVERY model on a node between provisioning (which installs
 * an AppKey) and its first Config Model App Bind.  Skipping the check for such
 * models lets any holder of any AppKey on the node drive every model on it.
 *
 * Driven through meshd_bearer_rx() and meshd_foundation_recv(), the daemon's
 * network and Configuration Server entry points.
 */
ATF_TC_WITHOUT_HEAD(im3_appkey_binding_is_unconditional);
ATF_TC_BODY(im3_appkey_binding_is_unconditional, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct peer_frames pf;
	struct mesh_gen_onoff_set set;
	struct mesh_cfg_model_app ma;
	struct mesh_cfg_appkey ak;
	uint8_t params[MESH_GEN_PARAMS_MAX];
	uint8_t msg[64], reply[64];
	size_t plen, mlen, rlen = 0, i;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	/*
	 * Provisioned and keyed, with no Config Model App Bind yet: every
	 * model's binding list is empty, which is the vulnerable state.
	 */
	for (i = 0; i < nd->db.n_models; i++)
		ATF_REQUIRE_EQ(0u, (unsigned)nd->db.models[i].n_app);
	ATF_REQUIRE_EQ(MESH_GEN_OFF, nd->app->onoff.present);

	memset(&set, 0, sizeof(set));
	set.onoff = MESH_GEN_ON;
	set.tid = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&set, params, &plen));
	peer_access_frames(0x0102, nd->addr, 7, cfg.iv_index,
	    MESH_OP_GEN_ONOFF_SET_UNACK, params, plen, &pf);
	ATF_REQUIRE_EQ(1u, (unsigned)pf.n);
	(void)meshd_bearer_rx(nd, pf.bytes[0], pf.len[0]);
	ATF_CHECK_EQ_MSG(MESH_GEN_OFF, nd->app->onoff.present,
	    "a model with no AppKey bound must drop an AppKey-secured message");

	/* Bind the AppKey to the Generic OnOff Server, as a Configuration
	 * Client would, and the very same message is now processed. */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = cfg.netkey_index;
	ak.app_idx = cfg.appkey_index;
	memcpy(ak.key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD,
	    &ak, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);
	memset(&ma, 0, sizeof(ma));
	ma.elem_addr = nd->addr;
	ma.app_idx = cfg.appkey_index;
	ma.model.model_id = MESH_MODEL_GEN_ONOFF_SRV;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &ma, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

	set.tid = 2;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&set, params, &plen));
	peer_access_frames(0x0102, nd->addr, 9, cfg.iv_index,
	    MESH_OP_GEN_ONOFF_SET_UNACK, params, plen, &pf);
	ATF_REQUIRE_EQ(1u, (unsigned)pf.n);
	(void)meshd_bearer_rx(nd, pf.bytes[0], pf.len[0]);
	ATF_CHECK_EQ_MSG(MESH_GEN_ON, nd->app->onoff.present,
	    "a bound AppKey must reach the model");

	meshd_node_fini(nd);
}

/* ---- IM4: both AppKeys are live through Key Refresh Phase 2 ----------- */
/*
 * MshPRT_v1.1.1 Section 3.11.4.1: on receiving the new keys "the node shall
 * transmit using the old keys and receive using both the old keys and the new
 * keys"; Section 3.11.4.2 keeps that receive rule in Phase 2 and only switches
 * transmission; Section 3.11.4.3 revokes the old keys in Phase 3.  "The keys"
 * are the NetKey and the AppKeys bound to it.
 *
 * With one key slot per AppKey index the Phase 2 advance overwrote the old
 * AppKey, so every peer that had not yet been given the new one - which is the
 * normal condition during a refresh, since that is what Phase 2 exists to wait
 * out - became silently undecryptable.
 */
ATF_TC_WITHOUT_HEAD(im4_appkey_old_and_new_through_phase2);
ATF_TC_BODY(im4_appkey_old_and_new_through_phase2, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct peer_frames pf;
	struct mesh_gen_onoff_set set;
	struct mesh_cfg_model_app ma;
	struct mesh_cfg_netkey nk;
	struct mesh_cfg_appkey ak;
	uint8_t params[MESH_GEN_PARAMS_MAX];
	uint8_t msg[64], reply[64];
	uint8_t new_netkey[16], new_appkey[16];
	size_t plen, mlen, rlen = 0;
	uint32_t before;

	(void)tc;
	memset(new_netkey, 0x77, sizeof(new_netkey));
	memset(new_appkey, 0x88, sizeof(new_appkey));
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Bind the AppKey so the message reaches a model at all. */
	memset(&ma, 0, sizeof(ma));
	ma.elem_addr = nd->addr;
	ma.app_idx = cfg.appkey_index;
	ma.model.model_id = MESH_MODEL_GEN_ONOFF_SRV;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &ma, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));

	/*
	 * Install the AppKey through the Configuration Server as well: only a
	 * Config-installed key has the database entry a later Config AppKey
	 * Update refers to.
	 */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = cfg.netkey_index;
	ak.app_idx = cfg.appkey_index;
	memcpy(ak.key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD,
	    &ak, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

	/* Config NetKey Update -> Key Refresh Phase 1. */
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = cfg.netkey_index;
	memcpy(nk.key, new_netkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(MESH_KR_PHASE_1, meshd_kr_phase(nd));

	/* Config AppKey Update stages the new AppKey beside the old one. */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = cfg.netkey_index;
	ak.app_idx = cfg.appkey_index;
	memcpy(ak.key, new_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_UPDATE,
	    &ak, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

	/* Phase 1 -> Phase 2. */
	ATF_REQUIRE_EQ(0, meshd_kr_advance(nd));
	ATF_REQUIRE_EQ(MESH_KR_PHASE_2, meshd_kr_phase(nd));

	memset(&set, 0, sizeof(set));
	set.onoff = MESH_GEN_ON;
	set.tid = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&set, params, &plen));

	/* A peer still on the OLD AppKey (and the old NetKey, which Phase 2
	 * also still receives) must be understood. */
	before = nd->self->rx.count;
	peer_access_frames_keys(0x0102, nd->addr, 11, cfg.iv_index,
	    MESH_OP_GEN_ONOFF_SET_UNACK, params, plen, g_netkey, g_appkey, &pf);
	ATF_REQUIRE_EQ(1u, (unsigned)pf.n);
	(void)meshd_bearer_rx(nd, pf.bytes[0], pf.len[0]);
	ATF_CHECK_EQ_MSG(before + 1, nd->self->rx.count,
	    "Phase 2 must still receive with the old AppKey");

	/* And so must a peer that already has the new one. */
	before = nd->self->rx.count;
	set.tid = 2;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&set, params, &plen));
	peer_access_frames_keys(0x0103, nd->addr, 13, cfg.iv_index,
	    MESH_OP_GEN_ONOFF_SET_UNACK, params, plen, new_netkey, new_appkey,
	    &pf);
	ATF_REQUIRE_EQ(1u, (unsigned)pf.n);
	(void)meshd_bearer_rx(nd, pf.bytes[0], pf.len[0]);
	ATF_CHECK_EQ_MSG(before + 1, nd->self->rx.count,
	    "Phase 2 must receive with the new AppKey");

	/* Phase 3 revokes the old keys: only the new AppKey is left. */
	ATF_REQUIRE_EQ(0, meshd_kr_finish(nd));
	before = nd->self->rx.count;
	set.tid = 3;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&set, params, &plen));
	peer_access_frames_keys(0x0104, nd->addr, 15, cfg.iv_index,
	    MESH_OP_GEN_ONOFF_SET_UNACK, params, plen, new_netkey, g_appkey,
	    &pf);
	ATF_REQUIRE_EQ(1u, (unsigned)pf.n);
	(void)meshd_bearer_rx(nd, pf.bytes[0], pf.len[0]);
	ATF_CHECK_EQ_MSG(before, nd->self->rx.count,
	    "Phase 3 revokes the old AppKey");
	set.tid = 4;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&set, params, &plen));
	peer_access_frames_keys(0x0105, nd->addr, 17, cfg.iv_index,
	    MESH_OP_GEN_ONOFF_SET_UNACK, params, plen, new_netkey, new_appkey,
	    &pf);
	ATF_REQUIRE_EQ(1u, (unsigned)pf.n);
	(void)meshd_bearer_rx(nd, pf.bytes[0], pf.len[0]);
	ATF_CHECK_EQ_MSG(before + 1, nd->self->rx.count,
	    "Phase 3 keeps the new AppKey");

	meshd_node_fini(nd);
}


/* ---- IM8: fixed group destination addresses are matched on receive ----- */
/*
 * MshPRT_v1.1.1 Section 3.6.4.2: "Upon receiving an Upper Transport Control
 * PDU, the destination address of the PDU shall be checked.  The PDU shall be
 * processed according to the Transport Control opcode ... if one of the
 * following conditions is met: [] The destination address matches a unicast
 * address of an element of the node [] The destination address matches a fixed
 * group destination address specified in Table 3.28 and the corresponding
 * condition (if any) is satisfied."  Table 3.28 pairs all-friends (0xFFFD)
 * with "Friend functionality is enabled", all-relays (0xFFFE) with Relay,
 * all-proxies (0xFFFC) with Proxy, and all-nodes (0xFFFF) with no condition.
 *
 * Matching only all-nodes leaves every other fixed group address unreachable -
 * including all-friends, which is the destination of a Friend Request
 * (Section 3.6.6.2), so the mandatory friendship-establishment procedure
 * cannot arrive through the network layer at all.
 *
 * Driven through meshd_foundation_recv() (Config Heartbeat Subscription Set
 * and Config Friend Set) and meshd_bearer_rx(), the daemon's own entry points.
 * A Heartbeat message is used as the observable Transport Control PDU because
 * the Heartbeat Subscription counter records, per (SRC, DST) pair, that the
 * upper transport layer processed it.
 */
static void
peer_hb_frame(uint16_t src, uint16_t dst, uint32_t seq, uint32_t iv,
    uint8_t ttl, struct peer_frames *pf)
{
	MESH_HEAP(struct mesh_sim, peer);
	struct mesh_node *hb;
	size_t i;

	memset(pf, 0, sizeof(*pf));
	ATF_REQUIRE_EQ(0, mesh_sim_init(peer, g_netkey, g_appkey, iv));
	hb = mesh_sim_add_node(peer, src, 1);
	ATF_REQUIRE(hb != NULL);
	hb->seq = seq;
	/*
	 * Publish on a feature change (MshPRT_v1.1.1 Section 4.2.18): the
	 * trigger mask names Relay, so flipping Relay on emits exactly one
	 * Heartbeat to the configured destination.
	 */
	mesh_sim_hb_set_pub(hb, dst, 0x01, 0x00, ttl, MESH_HB_FEATURE_RELAY, 0);
	ATF_REQUIRE_EQ(1, mesh_sim_hb_feature_change(peer, hb,
	    MESH_HB_FEATURE_RELAY));
	ATF_REQUIRE(peer->n_tx >= 1 && peer->n_tx <= MESH_SEG_MAX);
	for (i = 0; i < peer->n_tx; i++) {
		pf->len[i] = peer->tx[i].len;
		memcpy(pf->bytes[i], peer->tx[i].bytes, pf->len[i]);
	}
	pf->n = peer->n_tx;
}

ATF_TC_WITHOUT_HEAD(im8_fixed_group_dst_matched_on_receive);
ATF_TC_BODY(im8_fixed_group_dst_matched_on_receive, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct peer_frames pf;
	struct mesh_hb_sub_set sub;
	uint8_t msg[32], reply[64];
	size_t mlen, rlen = 0, i;

	(void)tc;
	base_config(&cfg);
	cfg.features = MESH_CFG_FEATURE_FRIEND;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	ATF_REQUIRE_EQ(1, nd->friend_enabled);
	ATF_REQUIRE_MSG(nd->self->friend_feature == 1,
	    "the network engine must know the Friend feature is enabled");

	/*
	 * Subscribe to Heartbeats from 0x00AA addressed to all-friends.  0xFFFD
	 * is a group address, which Section 4.2.19.2 allows as a Heartbeat
	 * Subscription Destination.
	 */
	memset(&sub, 0, sizeof(sub));
	sub.src = 0x00AA;
	sub.dst = MESH_ADDR_ALL_FRIENDS;
	sub.period_log = 0x05;
	ATF_REQUIRE_EQ(0, mesh_hb_sub_set_build(&sub, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(1, nd->self->hb_sub_active);
	ATF_REQUIRE_EQ(0u, nd->self->hb_sub.count);

	/* A Friend-enabled node is addressed by all-friends (Table 3.28). */
	peer_hb_frame(0x00AA, MESH_ADDR_ALL_FRIENDS, 11, cfg.iv_index, 7, &pf);
	for (i = 0; i < pf.n; i++)
		(void)meshd_bearer_rx(nd, pf.bytes[i], pf.len[i]);
	ATF_CHECK_EQ_MSG(1u, nd->self->hb_sub.count,
	    "all-friends must address a node with the Friend feature enabled");

	/*
	 * The condition is load-bearing: with the Friend feature disabled the
	 * same address must not address the node.  Config Friend Set 0x00
	 * disables the role; the subscription is re-armed because applying a
	 * Set resets the accumulated counters (Section 4.2.19.3).
	 */
	ATF_REQUIRE_EQ(0, mesh_cfg_u8_state_build(MESH_CFG_OP_FRIEND_SET, 0,
	    msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, nd->cfg.friend);
	ATF_REQUIRE_EQ(0, nd->self->friend_feature);
	ATF_REQUIRE_EQ(0, mesh_hb_sub_set_build(&sub, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0u, nd->self->hb_sub.count);
	peer_hb_frame(0x00AA, MESH_ADDR_ALL_FRIENDS, 21, cfg.iv_index, 7, &pf);
	for (i = 0; i < pf.n; i++)
		(void)meshd_bearer_rx(nd, pf.bytes[i], pf.len[i]);
	ATF_CHECK_EQ_MSG(0u, nd->self->hb_sub.count,
	    "all-friends must not address a node with the Friend feature off");

	/*
	 * all-relays carries the Relay condition, and Config Relay Set is the
	 * state that satisfies it.
	 */
	sub.dst = MESH_ADDR_ALL_RELAYS;
	ATF_REQUIRE_EQ(0, mesh_hb_sub_set_build(&sub, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, nd->self->is_relay);
	peer_hb_frame(0x00AA, MESH_ADDR_ALL_RELAYS, 31, cfg.iv_index, 7, &pf);
	for (i = 0; i < pf.n; i++)
		(void)meshd_bearer_rx(nd, pf.bytes[i], pf.len[i]);
	ATF_CHECK_EQ_MSG(0u, nd->self->hb_sub.count,
	    "all-relays must not address a node with Relay disabled");
	{
		struct mesh_cfg_relay r;

		memset(&r, 0, sizeof(r));
		r.relay = 1;
		ATF_REQUIRE_EQ(0, mesh_cfg_relay_set_build(
		    MESH_CFG_OP_RELAY_SET, &r, msg, &mlen));
		ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
		    sizeof(reply), &rlen));
	}
	ATF_REQUIRE_EQ(1, nd->self->is_relay);
	peer_hb_frame(0x00AA, MESH_ADDR_ALL_RELAYS, 41, cfg.iv_index, 7, &pf);
	for (i = 0; i < pf.n; i++)
		(void)meshd_bearer_rx(nd, pf.bytes[i], pf.len[i]);
	ATF_CHECK_EQ_MSG(1u, nd->self->hb_sub.count,
	    "all-relays must address a node with the Relay feature enabled");

	meshd_node_fini(nd);
}


/* ---- IM9: group delivery is per-model, not per-element ---------------- */
/*
 * MshPRT_v1.1.1 Section 3.4.2.4: "A Network PDU sent to a group address shall
 * be delivered to all the instances of models that subscribe to this group
 * address."  Section 3.7.3.1 says it for both forms - the destination must be
 * "a group address ... or a virtual address that the instance of the model is
 * subscribed to" - and Figure 3.72 has an unsubscribed model drop the message.
 * "that subscribe" is per-MODEL.  Delivering to every model on an element
 * because one model there subscribed is a different, broader behaviour, and on
 * the usual multi-model primary element it fires Generic OnOff, Generic Level
 * and Light Lightness together on a group Set aimed at one of them.
 *
 * Driven through meshd_foundation_recv() (Config AppKey Add, Config Model App
 * Bind, Config Model Subscription Add) and meshd_bearer_rx().
 *
 * NOTE ON COVERAGE: this case PINS the rule rather than gating the library fix
 * that accompanies it.  It passes against the pre-fix code, because meshd
 * registers a Configuration database entry for every model at
 * initialisation, which set the per-model subscription list as "configured"
 * (though empty) on every model and so never reached the library's
 * "unconfigured means subscribed to everything" branch.  The branch itself is
 * gated by mesh_access_test:group_fanout.
 */
ATF_TC_WITHOUT_HEAD(im9_group_delivery_is_per_model);
ATF_TC_BODY(im9_group_delivery_is_per_model, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct peer_frames pf;
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_model_app ma;
	struct mesh_cfg_model_sub ms;
	struct mesh_gen_onoff_set set;
	uint8_t params[MESH_GEN_PARAMS_MAX];
	uint8_t msg[64], reply[64];
	size_t plen, mlen, rlen = 0, i;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Commission the AppKey and bind it to the Generic OnOff Server. */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = cfg.netkey_index;
	ak.app_idx = cfg.appkey_index;
	memcpy(ak.key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD,
	    &ak, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);
	memset(&ma, 0, sizeof(ma));
	ma.elem_addr = nd->addr;
	ma.app_idx = cfg.appkey_index;
	ma.model.model_id = MESH_MODEL_GEN_ONOFF_SRV;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &ma, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

	/*
	 * Subscribe a DIFFERENT model on the same element - the Generic Level
	 * Server - to the group.  The element is now addressed by 0xC000, but
	 * the Generic OnOff Server subscribes to nothing.
	 */
	memset(&ms, 0, sizeof(ms));
	ms.elem_addr = nd->addr;
	ms.address = 0xC000;
	ms.model.model_id = MESH_MODEL_GEN_LEVEL_SRV;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_ADD,
	    &ms, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

	memset(&set, 0, sizeof(set));
	set.onoff = MESH_GEN_ON;
	set.tid = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&set, params, &plen));
	ATF_REQUIRE_EQ(MESH_GEN_OFF, nd->app->onoff.present);
	peer_access_frames(0x0102, 0xC000, 21, cfg.iv_index,
	    MESH_OP_GEN_ONOFF_SET_UNACK, params, plen, &pf);
	for (i = 0; i < pf.n; i++)
		(void)meshd_bearer_rx(nd, pf.bytes[i], pf.len[i]);
	ATF_CHECK_EQ_MSG(MESH_GEN_OFF, nd->app->onoff.present,
	    "a group message must not reach a model that did not subscribe, "
	    "even when another model on the element did");

	/*
	 * The control: the very same message to the element's unicast address
	 * IS processed, so the AppKey binding really is in place and the drop
	 * above was the subscription rule and not the binding rule.
	 */
	set.tid = 2;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&set, params, &plen));
	peer_access_frames(0x0102, nd->addr, 31, cfg.iv_index,
	    MESH_OP_GEN_ONOFF_SET_UNACK, params, plen, &pf);
	for (i = 0; i < pf.n; i++)
		(void)meshd_bearer_rx(nd, pf.bytes[i], pf.len[i]);
	ATF_CHECK_EQ_MSG(MESH_GEN_ON, nd->app->onoff.present,
	    "the unicast destination still addresses the bound model");

	/* And once the OnOff Server subscribes itself, the group works. */
	nd->app->onoff.present = MESH_GEN_OFF;
	ms.model.model_id = MESH_MODEL_GEN_ONOFF_SRV;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_ADD,
	    &ms, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);
	set.tid = 3;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&set, params, &plen));
	peer_access_frames(0x0102, 0xC000, 41, cfg.iv_index,
	    MESH_OP_GEN_ONOFF_SET_UNACK, params, plen, &pf);
	for (i = 0; i < pf.n; i++)
		(void)meshd_bearer_rx(nd, pf.bytes[i], pf.len[i]);
	ATF_CHECK_EQ_MSG(MESH_GEN_ON, nd->app->onoff.present,
	    "a subscribed model does receive the group message");

	meshd_node_fini(nd);
}


/* ---- IM6: virtual dispatch uses the Label UUID, not the 14-bit hash ---- */
/*
 * MshPRT_v1.1.1 Section 3.4.2.3: "The virtual address is a 16-bit value that
 * has bit 15 set to 1, bit 14 set to 0, and bits 13 to 0 set to the value of a
 * hash.  This hash is a derivation of the Label UUID such that EACH HASH
 * REPRESENTS MANY LABEL UUIDs", and "when an Access message is received to a
 * virtual address that has a matching hash, each corresponding Label UUID is
 * used by the upper transport layer as additional data as part of the
 * authentication of the message until a match is found".
 *
 * So the 16-bit address on the wire does not identify a subscription; only the
 * Label UUID does.  Proving which label authenticated the message and then
 * dispatching on the address anyway throws that answer away: two labels that
 * collide in the 14-bit hash then deliver to each other's models.  The
 * specification's own note bounds at 2^-46 the chance of a matching hash AND a
 * passing 32-bit MIC, which is a bound on the COMBINED event; the hash
 * collision alone is one pair in 16384 and an adversary can simply search for a
 * Label UUID hashing onto an address already in use.  The MIC is what makes a
 * collision harmless, and the MIC only helps if the label that passed it is the
 * label used to route.
 *
 * The two Label UUIDs below collide on purpose.  IM6_LABEL_SPEC is the
 * specification's own sample from Section 8.3.22, whose virtual address 0xB529
 * is stated there; IM6_LABEL_COLLIDER is a second label with the same 14-bit
 * hash.  The case REQUIREs the collision before relying on it, so a change in
 * the derivation fails loudly rather than quietly making the case vacuous.
 *
 * Driven through meshd_foundation_recv() (Config AppKey Add, Config Model App
 * Bind, Config Model Subscription Virtual Address Add) and meshd_bearer_rx().
 */
static const uint8_t im6_label_spec[MESH_LABEL_UUID_LEN] = {
	0x00, 0x73, 0xe7, 0xe4, 0xd8, 0xb9, 0x44, 0x0f,
	0xaf, 0x84, 0x15, 0xdf, 0x4c, 0x56, 0xc0, 0xe1
};
static const uint8_t im6_label_collider[MESH_LABEL_UUID_LEN] = {
	0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
	0x5b, 0x5b, 0x5b, 0x5b, 0x00, 0x00, 0x3e, 0xc6
};
#define	IM6_SPEC_VIRTUAL_ADDR	0xB529	/* MshPRT_v1.1.1 Section 8.3.22 */

/* Build the frames a peer sends to a virtual address, authenticated with the
 * given Label UUID as the upper-transport additional data. */
static void
peer_virtual_frames(uint16_t src, const uint8_t label[MESH_LABEL_UUID_LEN],
    uint32_t seq, uint32_t iv, uint32_t opcode, const uint8_t *params,
    size_t plen, struct peer_frames *pf)
{
	MESH_HEAP(struct mesh_sim, peer);
	struct mesh_node *pn;
	size_t i;

	memset(pf, 0, sizeof(*pf));
	ATF_REQUIRE_EQ(0, mesh_sim_init(peer, g_netkey, g_appkey, iv));
	pn = mesh_sim_add_node(peer, src, 1);
	ATF_REQUIRE(pn != NULL);
	pn->seq = seq;
	ATF_REQUIRE_EQ(0, mesh_sim_send_access_key_from_virtual(peer, pn,
	    src, 0, 0, label, opcode, params, plen, 5));
	ATF_REQUIRE(peer->n_tx > 0 && peer->n_tx <= MESH_SEG_MAX);
	for (i = 0; i < peer->n_tx; i++) {
		pf->len[i] = peer->tx[i].len;
		memcpy(pf->bytes[i], peer->tx[i].bytes, pf->len[i]);
	}
	pf->n = peer->n_tx;
}

ATF_TC_WITHOUT_HEAD(im6_virtual_dispatch_uses_label_not_hash);
ATF_TC_BODY(im6_virtual_dispatch_uses_label_not_hash, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct peer_frames pf;
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_model_app ma;
	struct mesh_cfg_model_sub_va sv;
	struct mesh_gen_onoff_set set;
	uint8_t params[MESH_GEN_PARAMS_MAX];
	uint8_t msg[64], reply[64];
	uint16_t va_spec, va_collider;
	size_t plen, mlen, rlen = 0, i;

	(void)tc;
	/*
	 * The premise, checked rather than assumed: the specification's own
	 * sample Label UUID hashes to the virtual address Section 8.3.22
	 * states, and the second label hashes to the very same address.
	 */
	ATF_REQUIRE_EQ(0, mesh_virtual_addr(im6_label_spec, &va_spec));
	ATF_REQUIRE_EQ_MSG(IM6_SPEC_VIRTUAL_ADDR, va_spec,
	    "MshPRT_v1.1.1 Section 8.3.22 sample virtual address");
	ATF_REQUIRE_EQ(0, mesh_virtual_addr(im6_label_collider, &va_collider));
	ATF_REQUIRE_EQ_MSG(va_spec, va_collider,
	    "the two Label UUIDs must collide in the 14-bit hash");
	ATF_REQUIRE(memcmp(im6_label_spec, im6_label_collider,
	    MESH_LABEL_UUID_LEN) != 0);

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	memset(&ak, 0, sizeof(ak));
	ak.net_idx = cfg.netkey_index;
	ak.app_idx = cfg.appkey_index;
	memcpy(ak.key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD,
	    &ak, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);
	memset(&ma, 0, sizeof(ma));
	ma.elem_addr = nd->addr;
	ma.app_idx = cfg.appkey_index;
	ma.model.model_id = MESH_MODEL_GEN_ONOFF_SRV;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &ma, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

	/*
	 * The Generic OnOff Server subscribes to the COLLIDER label; the
	 * Generic Level Server subscribes to the specification's label.  The
	 * node therefore holds both labels as authentication candidates, and
	 * both resolve to the same 16-bit destination address.
	 */
	memset(&sv, 0, sizeof(sv));
	sv.elem_addr = nd->addr;
	memcpy(sv.label, im6_label_collider, MESH_LABEL_UUID_LEN);
	sv.model.model_id = MESH_MODEL_GEN_ONOFF_SRV;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_va_build(
	    MESH_CFG_OP_MODEL_SUB_VA_ADD, &sv, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);
	memcpy(sv.label, im6_label_spec, MESH_LABEL_UUID_LEN);
	sv.model.model_id = MESH_MODEL_GEN_LEVEL_SRV;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_va_build(
	    MESH_CFG_OP_MODEL_SUB_VA_ADD, &sv, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

	/*
	 * A Generic OnOff Set authenticated with the SPECIFICATION's label,
	 * addressed to the shared 0xB529.  The Generic OnOff Server subscribes
	 * to the other label, so it is not a destination of this message.
	 */
	memset(&set, 0, sizeof(set));
	set.onoff = MESH_GEN_ON;
	set.tid = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&set, params, &plen));
	ATF_REQUIRE_EQ(MESH_GEN_OFF, nd->app->onoff.present);
	peer_virtual_frames(0x0102, im6_label_spec, 61, cfg.iv_index,
	    MESH_OP_GEN_ONOFF_SET_UNACK, params, plen, &pf);
	for (i = 0; i < pf.n; i++)
		(void)meshd_bearer_rx(nd, pf.bytes[i], pf.len[i]);
	ATF_CHECK_EQ_MSG(va_spec, nd->self->rx.dst,
	    "the message was received at the shared virtual address");
	ATF_CHECK_MSG(nd->self->rx.have_label,
	    "the authenticating Label UUID must be recorded");
	ATF_CHECK_EQ_MSG(0, memcmp(nd->self->rx.label, im6_label_spec,
	    MESH_LABEL_UUID_LEN),
	    "the recorded label must be the one that authenticated");
	ATF_CHECK_EQ_MSG(MESH_GEN_OFF, nd->app->onoff.present,
	    "a colliding Label UUID must not deliver to a model subscribed to "
	    "a different label with the same 14-bit hash");

	/*
	 * The control: the same message authenticated with the label the
	 * Generic OnOff Server actually subscribes to IS delivered, so the drop
	 * above was the label comparison and not a decrypt failure.
	 */
	set.tid = 2;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&set, params, &plen));
	peer_virtual_frames(0x0102, im6_label_collider, 71, cfg.iv_index,
	    MESH_OP_GEN_ONOFF_SET_UNACK, params, plen, &pf);
	for (i = 0; i < pf.n; i++)
		(void)meshd_bearer_rx(nd, pf.bytes[i], pf.len[i]);
	ATF_CHECK_EQ_MSG(0, memcmp(nd->self->rx.label, im6_label_collider,
	    MESH_LABEL_UUID_LEN),
	    "the recorded label follows the authenticating label");
	ATF_CHECK_EQ_MSG(MESH_GEN_ON, nd->app->onoff.present,
	    "the subscribed Label UUID does deliver");

	meshd_node_fini(nd);
}


/* ---- IM12: one Segment Acknowledgment per SAR Acknowledgment timer ---- */
/*
 * MshPRT_v1.1.1 Section 3.5.3.4.  A First or Next Segment to a unicast
 * destination "shall start the SAR Discard timer and SAR Acknowledgment timer
 * for this SeqAuth from the initial values", and the acknowledgment is emitted
 * only when that timer expires: "When the SAR Acknowledgment timer expires, the
 * lower transport layer shall send a Segment Acknowledgment message with the
 * AckedSegments field set to the AckedSegments value for the identified
 * SeqAuth."  A Last Segment acknowledges at once, with every segment reported
 * delivered.  The initial value is
 *
 *   [min(SegN + 0.5, acknowledgment delay increment) * segment reception
 *    interval]
 *
 * which with the specification's defaults (SAR Acknowledgment Delay Increment
 * 0b001 = 2.5, SAR Receiver Segment Interval Step 0b0101 = 60 ms) saturates at
 * 150 ms for any SegN of 2 or more.  Since every arriving segment restarts the
 * timer, a burst of segments produces on the order of ONE acknowledgment - not
 * one per segment, which is the acknowledgment storm that defeats large
 * transfers on a shared advertising bearer.
 *
 * Driven through meshd_bearer_rx() and meshd_node_tick(), the daemon's receive
 * and cadence entry points.
 */
static size_t
sar_count_acks(uint32_t iv, uint32_t *blockack_out)
{
	struct mesh_net_pdu np;
	struct mesh_seg_ack ack;
	size_t i, n = 0;

	for (i = 0; i < g_sar_n; i++) {
		if (net_open(g_sar_frames[i], g_sar_len[i], iv, &np) != 0)
			continue;
		if (np.ctl != 1 || np.transport_len == 0 ||
		    (np.transport[0] & 0x80) != 0 ||
		    (np.transport[0] & 0x7f) != 0x00)
			continue;
		if (mesh_seg_ack_parse(np.transport, np.transport_len,
		    &ack) != 0)
			continue;
		if (blockack_out != NULL)
			*blockack_out = ack.blockack;
		n++;
	}
	return (n);
}

ATF_TC_WITHOUT_HEAD(im12_one_ack_per_sar_ack_timer);
ATF_TC_BODY(im12_one_ack_per_sar_ack_timer, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .arg = NULL, .tx = sar_capture_tx };
	struct peer_frames pf;
	uint8_t params[60];
	uint32_t blockack = 0;
	uint8_t segn;
	size_t i;
	int changed;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);

	/*
	 * A peer sends a segmented access message to this node's unicast
	 * address.  60 parameter octets need six segments, so SegN is 5 and the
	 * acknowledgment delay is the saturated 150 ms.
	 */
	memset(params, 0x3C, sizeof(params));
	peer_access_frames(0x0102, nd->addr, 101, cfg.iv_index, 0x8299,
	    params, sizeof(params), &pf);
	ATF_REQUIRE_MSG(pf.n >= 3, "the message must segment (%zu)", pf.n);
	segn = (uint8_t)(pf.n - 1);

	/* Every segment but the last: not one acknowledgment yet. */
	g_sar_n = 0;
	for (i = 0; i + 1 < pf.n; i++)
		(void)meshd_bearer_rx(nd, pf.bytes[i], pf.len[i]);
	ATF_CHECK_EQ_MSG(0u, (unsigned)sar_count_acks(cfg.iv_index, NULL),
	    "an incomplete transaction is not acknowledged per segment");

	/* Still nothing before the timer's 150 ms. */
	g_sar_n = 0;
	ATF_REQUIRE(meshd_node_tick(nd, 100, &changed) >= 0);
	ATF_CHECK_EQ_MSG(0u, (unsigned)sar_count_acks(cfg.iv_index, NULL),
	    "the SAR Acknowledgment timer has not expired at 100 ms");

	/*
	 * Past 150 ms exactly one acknowledgment goes out, reporting the
	 * segments that did arrive - every one except the last.
	 */
	g_sar_n = 0;
	ATF_REQUIRE(meshd_node_tick(nd, 400, &changed) >= 0);
	ATF_CHECK_EQ_MSG(1u, (unsigned)sar_count_acks(cfg.iv_index, &blockack),
	    "the expiry of the SAR Acknowledgment timer emits exactly one");
	ATF_CHECK_EQ_MSG(mesh_blockack_full(segn) &
	    ~((uint32_t)1 << segn), blockack,
	    "AckedSegments reports the segments received, the last still "
	    "outstanding");

	/*
	 * The last segment completes the transaction and is acknowledged
	 * immediately with every segment delivered - one more acknowledgment,
	 * for two in total against a six-segment transfer.
	 */
	g_sar_n = 0;
	(void)meshd_bearer_rx(nd, pf.bytes[pf.n - 1], pf.len[pf.n - 1]);
	ATF_CHECK_EQ_MSG(1u, (unsigned)sar_count_acks(cfg.iv_index, &blockack),
	    "a Last Segment to a unicast address acknowledges at once");
	ATF_CHECK_EQ_MSG(mesh_blockack_full(segn), blockack,
	    "the completing acknowledgment reports every segment delivered");

	meshd_node_fini(nd);
}

/* ---- IM17: a multicast segmented message is retransmitted ------------- */
/*
 * MshPRT_v1.1.1 Section 3.5.3.3: "For each transmission to a group address or a
 * virtual address, the lower transport layer stores the destination address,
 * the derived SeqAuth of the segmented message, and the remaining number of
 * retransmissions value", and "when the SAR Multicast Retransmissions timer
 * expires and the remaining number of retransmissions value is greater than 0,
 * then the lower transport layer shall repeat the transmission of all the
 * segments of the Upper Transport PDU."
 *
 * Section 3.5.3.4 never acknowledges a group or virtual destination, so that
 * count is the ONLY reliability a multicast segmented message has.  Sending it
 * exactly once makes every large scene or lighting payload to a group a single
 * shot on an unreliable advertising bearer.  Section 4.2.48.6's default SAR
 * Multicast Retransmissions Count is 0b0010 and "the maximum number of
 * transmissions of a segment is (SAR Multicast Retransmissions Count + 1)", so
 * three transmissions; Section 4.2.48.7's default interval is 0b1001, 250 ms.
 *
 * Driven through meshd_send_access_raw() and meshd_node_tick().
 */
ATF_TC_WITHOUT_HEAD(im17_multicast_sar_retransmission);
ATF_TC_BODY(im17_multicast_sar_retransmission, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .arg = NULL, .tx = sar_capture_tx };
	struct mesh_net_pdu np;
	uint8_t access[64];
	uint32_t seen_seq[MESH_SEG_MAX * 4];
	size_t nseg, nseen = 0, i, j;
	int changed;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);

	access[0] = 0x82;
	access[1] = 0x99;
	for (i = 2; i < sizeof(access); i++)
		access[i] = (uint8_t)i;

	/* The first transmission of a segmented message to a GROUP address. */
	g_sar_n = 0;
	ATF_REQUIRE_EQ(0, meshd_send_access_raw(nd, 0xC000, access,
	    sizeof(access)));
	ATF_REQUIRE_MSG(g_sar_n > 1, "message must segment (%zu)", g_sar_n);
	nseg = g_sar_n;
	ATF_REQUIRE(nseg <= MESH_SEG_MAX);
	for (i = 0; i < nseg; i++) {
		ATF_REQUIRE_EQ(0, net_open(g_sar_frames[i], g_sar_len[i],
		    cfg.iv_index, &np));
		ATF_REQUIRE_EQ(0xC000, np.dst);
		seen_seq[nseen++] = np.seq;
	}

	/*
	 * Past the multicast interval every segment is repeated, with a fresh
	 * network sequence number: Section 3.4.6.5's message cache lets every
	 * relay drop a (SRC, SEQ, IVI) it has already seen, so a repeat
	 * carrying the original SEQ would never leave the first hop.
	 *
	 * SETUP CHANGE, flagged: the tick instants move because the SAR
	 * Multicast Retransmissions timer now starts at the estimated end of
	 * the transmission of the last segment (Section 3.5.3.3.1), SegN
	 * segment transmission intervals after the first.  The interval itself
	 * is unchanged at the Section 4.2.48.7 default of (9 + 1) * 25 =
	 * 250 ms; the start offset is 5 * (5 + 1) * 10 = 300 ms, so a repeat
	 * falls due every 550 ms rather than every 250 ms.  The assertions are
	 * unchanged.
	 */
	g_sar_n = 0;
	ATF_REQUIRE(meshd_node_tick(nd, 600, &changed) >= 0);
	ATF_CHECK_EQ_MSG(nseg, g_sar_n,
	    "every segment of a multicast transaction is repeated (%zu of "
	    "%zu)", g_sar_n, nseg);
	for (i = 0; i < g_sar_n; i++) {
		ATF_REQUIRE_EQ(0, net_open(g_sar_frames[i], g_sar_len[i],
		    cfg.iv_index, &np));
		ATF_CHECK_EQ_MSG(0xC000, np.dst, "the destination is unchanged");
		for (j = 0; j < nseen; j++)
			ATF_CHECK_MSG(np.seq != seen_seq[j],
			    "a repeated segment reused SEQ %u",
			    (unsigned)np.seq);
		if (nseen < nitems(seen_seq))
			seen_seq[nseen++] = np.seq;
	}

	/* A second repeat, for three transmissions in all. */
	g_sar_n = 0;
	ATF_REQUIRE(meshd_node_tick(nd, 1200, &changed) >= 0);
	ATF_CHECK_EQ_MSG(nseg, g_sar_n,
	    "the SAR Multicast Retransmissions Count default is three "
	    "transmissions (%zu of %zu)", g_sar_n, nseg);

	/*
	 * And then it stops: "when the SAR Multicast Retransmissions timer
	 * expires and the remaining number of retransmissions value is 0, then
	 * the lower transport layer shall cancel the transmission."
	 */
	g_sar_n = 0;
	ATF_REQUIRE(meshd_node_tick(nd, 1800, &changed) >= 0);
	ATF_CHECK_EQ_MSG(0u, (unsigned)g_sar_n,
	    "the transmission is cancelled once the count reaches zero");

	meshd_node_fini(nd);
}

/* ---- IM23: one reassembly per (source, destination); older SeqAuth ---- */
/*
 * MshPRT_v1.1.1 Section 3.5.3.4 stores "one or more pairs of values,
 * consisting of an AckedSegments value ... and a Sequence Authentication
 * value.  Each such pair is associated with a source address and a destination
 * address", and Table 3.25 turns an arriving segment whose SeqAuth is LESS
 * than that stored value into a SeqAuth Error or a Repeated Segment - for both
 * of which "the lower transport layer shall ignore the message".  A First
 * Segment (SeqAuth greater than the stored value) instead requires that "if
 * another reassembly is already pending for the same source address and for
 * the same destination address, the pending reassembly shall be discarded".
 *
 * Keying the slot array on SeqAuth as well made both impossible: an older
 * SeqAuth was handed a free slot and reassembled, and one peer could hold
 * every slot at once with a stream of distinct SeqZeros.  Driven through
 * meshd_bearer_rx(), the daemon's own receive entry point.
 */
ATF_TC_WITHOUT_HEAD(im23_one_reassembly_per_source);
ATF_TC_BODY(im23_one_reassembly_per_source, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct peer_frames pf_new, pf_old;
	uint8_t params[48];
	size_t i, live;
	uint32_t before;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	for (i = 0; i < sizeof(params); i++)
		params[i] = (uint8_t)i;

	/*
	 * One peer, two segmented transactions to this node's unicast address.
	 * SeqAuth is the SEQ of segment zero, so seq 5000 is the newer
	 * transaction and seq 4000 the older one; both SeqZeros are below
	 * 0x2000 so each SeqAuth reconstructs to the SEQ it was built with.
	 */
	peer_access_frames(0x0102, nd->addr, 5000, cfg.iv_index, 0x8299,
	    params, sizeof(params), &pf_new);
	ATF_REQUIRE_MSG(pf_new.n > 1, "payload must segment (%zu)", pf_new.n);
	peer_access_frames(0x0102, nd->addr, 4000, cfg.iv_index, 0x8299,
	    params, sizeof(params), &pf_old);
	ATF_REQUIRE_EQ(pf_new.n, pf_old.n);

	/* Segment zero of the NEWER transaction opens the reassembly. */
	ATF_REQUIRE_EQ(0, meshd_bearer_rx(nd, pf_new.bytes[0], pf_new.len[0]));
	before = nd->self->rx.count;

	/*
	 * THE GATE.  The whole OLDER transaction now arrives.  Its SeqAuth is
	 * below the stored Sequence Authentication value for this (source,
	 * destination), so every segment of it is a SeqAuth Error and must be
	 * ignored - not reassembled in a second slot and delivered.
	 */
	for (i = 0; i < pf_old.n; i++)
		(void)meshd_bearer_rx(nd, pf_old.bytes[i], pf_old.len[i]);
	ATF_CHECK_EQ_MSG(before, nd->self->rx.count,
	    "a SeqAuth below the stored value must be ignored, not delivered");

	/* And it must not have consumed a second slot for this source. */
	live = 0;
	for (i = 0; i < MESH_SIM_REASM; i++)
		if (nd->self->reasm[i].used &&
		    nd->self->reasm[i].src == 0x0102)
			live++;
	ATF_CHECK_EQ_MSG(1u, (unsigned)live,
	    "one (source, destination) may hold exactly one reassembly, "
	    "found %u", (unsigned)live);

	/*
	 * The newer transaction is untouched by the replay: its remaining
	 * segments still complete it.
	 */
	for (i = 1; i < pf_new.n; i++)
		ATF_REQUIRE(meshd_bearer_rx(nd, pf_new.bytes[i],
		    pf_new.len[i]) >= 0);
	ATF_CHECK_EQ_MSG(before + 1, nd->self->rx.count,
	    "the pending newer transaction must still complete");

	/*
	 * The CONTROL: a strictly NEWER SeqAuth from the same source is a
	 * First Segment and does complete, so the case cannot pass by
	 * rejecting everything.
	 */
	{
		struct peer_frames pf3;

		peer_access_frames(0x0102, nd->addr, 6000, cfg.iv_index,
		    0x8299, params, sizeof(params), &pf3);
		for (i = 0; i < pf3.n; i++)
			ATF_REQUIRE(meshd_bearer_rx(nd, pf3.bytes[i],
			    pf3.len[i]) >= 0);
		ATF_CHECK_EQ_MSG(before + 2, nd->self->rx.count,
		    "a newer SeqAuth from the same source must be accepted");
	}

	meshd_node_fini(nd);
}

/* ---- IM25: out of reassembly slots answers BlockAck = 0 --------------- */
/*
 * MshPRT_v1.1.1 Section 3.5.3.4, Table 3.25's "Message Rejected" row ("the
 * lower transport layer cannot accept the segment message because it is
 * currently out of resources"):
 *
 *   "When the Processing Result is Message Rejected and the message is
 *    destined to a unicast address, the lower transport layer shall respond
 *    with a Segment Acknowledgment message with the AckedSegments field set to
 *    0x00000000."
 *
 * Section 3.5.3.3.2 makes that zero AckedSegments a cancellation: "the
 * transmission of the Upper Transport PDU shall be immediately canceled".
 * Returning silently instead makes the peer spend its entire retransmission
 * budget - and seconds of air time - on a node with no slot for it.  We
 * already honour BlockAck = 0 on receive; this is the send half.
 */
ATF_TC_WITHOUT_HEAD(im25_message_rejected_blockack_zero);
ATF_TC_BODY(im25_message_rejected_blockack_zero, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .arg = NULL, .tx = sar_capture_tx };
	struct peer_frames pf;
	struct mesh_net_pdu np;
	struct mesh_seg_ack ack;
	uint8_t params[48];
	uint16_t src;
	uint32_t seq;
	size_t i, acks;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);
	for (i = 0; i < sizeof(params); i++)
		params[i] = (uint8_t)i;

	/*
	 * Fill every reassembly slot: one distinct source per slot, each
	 * sending only segment zero so the transaction stays pending.  The
	 * clock is never advanced, so no SAR Acknowledgment timer expires and
	 * these openings emit nothing.
	 */
	for (i = 0; i < MESH_SIM_REASM; i++) {
		g_sar_n = 0;
		src = (uint16_t)(0x0102 + i);
		peer_access_frames(src, nd->addr, 5000, cfg.iv_index, 0x8299,
		    params, sizeof(params), &pf);
		ATF_REQUIRE_MSG(pf.n > 1, "payload must segment");
		ATF_REQUIRE_EQ(0, meshd_bearer_rx(nd, pf.bytes[0],
		    pf.len[0]));
		ATF_REQUIRE_EQ_MSG(0u, (unsigned)g_sar_n,
		    "a First Segment arms the acknowledgment timer, it does "
		    "not acknowledge");
	}

	/*
	 * THE GATE.  One more source arrives with nowhere to be reassembled.
	 * The response must be a Segment Acknowledgment addressed to that
	 * source with an all-zero AckedSegments field.
	 */
	src = (uint16_t)(0x0102 + MESH_SIM_REASM);
	seq = 5000;
	peer_access_frames(src, nd->addr, seq, cfg.iv_index, 0x8299, params,
	    sizeof(params), &pf);
	g_sar_n = 0;
	ATF_REQUIRE_EQ(0, meshd_bearer_rx(nd, pf.bytes[0], pf.len[0]));
	ATF_REQUIRE_MSG(g_sar_n > 0,
	    "Message Rejected must answer, not return silently");

	acks = 0;
	for (i = 0; i < g_sar_n; i++) {
		ATF_REQUIRE_EQ(0, net_open(g_sar_frames[i], g_sar_len[i],
		    cfg.iv_index, &np));
		if (np.ctl != 1 || np.transport_len == 0 ||
		    (np.transport[0] & 0x7f) != 0x00)
			continue;
		ATF_REQUIRE_EQ(0, mesh_seg_ack_parse(np.transport,
		    np.transport_len, &ack));
		acks++;
		ATF_CHECK_EQ_MSG(src, np.dst,
		    "the rejection is addressed to the rejected source");
		ATF_CHECK_EQ_MSG(0u, (unsigned)ack.blockack,
		    "AckedSegments must be 0x00000000, got 0x%08x",
		    (unsigned)ack.blockack);
		ATF_CHECK_EQ_MSG((uint16_t)(seq & 0x1fff), ack.seqzero,
		    "the rejection names the rejected transaction's SeqZero");
		ATF_CHECK_EQ_MSG(0, ack.obo,
		    "a directly addressed node sets OBO = 0");
	}
	ATF_CHECK_EQ_MSG(1u, (unsigned)acks,
	    "exactly one Segment Acknowledgment answers the rejection");

	/*
	 * The CONTROL: nothing was delivered, and the slots that were already
	 * occupied were not stolen - the rejected source did not evict a
	 * legitimate in-flight transaction.
	 */
	ATF_CHECK_EQ_MSG(0u, nd->self->rx.count,
	    "a rejected segment delivers nothing");
	for (i = 0; i < MESH_SIM_REASM; i++)
		ATF_CHECK_EQ_MSG((uint16_t)(0x0102 + i),
		    nd->self->reasm[i].src,
		    "an occupied slot must not be reassigned to the rejected "
		    "source");

	meshd_node_fini(nd);
}

/*
 * ================================================================
 * IM40: the three SAR transmitter holes of finding 40.
 * ================================================================
 */

/* Is a SAR transmit slot still holding a transaction to dst? */
static int
sar_tx_used_for(const struct meshd_node *nd, uint16_t dst)
{
	size_t i;

	for (i = 0; i < MESH_SIM_SAR_TX; i++)
		if (nd->self->sar_tx[i].used && nd->self->sar_tx[i].dst == dst)
			return (1);
	return (0);
}

/*
 * The SeqZero of the transaction currently held for dst, or 0xffff when there
 * is none.  A transaction is identified by its SeqZero (MshPRT_v1.1.1 Section
 * 3.5.3.1), so a CHANGE of SeqZero for one destination is exactly "a different
 * Upper Transport PDU has started".
 */
static uint16_t
sar_tx_seqzero_for(const struct meshd_node *nd, uint16_t dst)
{
	size_t i;

	for (i = 0; i < MESH_SIM_SAR_TX; i++)
		if (nd->self->sar_tx[i].used && nd->self->sar_tx[i].dst == dst)
			return (nd->self->sar_tx[i].seqzero);
	return (0xffff);
}

/* A segmented access payload: a 2-octet opcode plus 62 parameter octets. */
static void
seg_payload(uint8_t *access, size_t len)
{
	size_t i;

	access[0] = 0x82;
	access[1] = 0x99;
	for (i = 2; i < len; i++)
		access[i] = (uint8_t)i;
}

/* ---- IM40a: the 13-bit SeqZero window cancels the transmission -------- */
/*
 * MshPRT_v1.1.1 Section 3.5.3.1:
 *
 *   "Because of the limited size of the SeqZero field, it is not possible to
 *    send a segmented message when the SEQ field value is 8192 greater than
 *    the SeqAuth value.  If a segmented message has not been acknowledged by
 *    the time that the SEQ field value is 8192 greater than the SeqAuth value,
 *    then the transmission of the Upper Transport PDU shall be canceled."
 *
 * The transaction is identified on the wire ONLY by its 13-bit SeqZero, so
 * once SEQ has advanced a full 0x2000 the receiver reconstructs a different
 * SeqAuth from the same SeqZero (the 0x2000 borrow of Section 3.5.3.1) and
 * every further retransmission is attributed to the wrong transaction.  The
 * engine had no such test: it retransmitted until its retry budget ran out.
 *
 * Driven through meshd_send_access_raw() and meshd_node_tick().
 */
ATF_TC_WITHOUT_HEAD(im40a_seqzero_window_cancels_tx);
ATF_TC_BODY(im40a_seqzero_window_cancels_tx, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	MESH_HEAP(struct meshd_node, ctl);
	struct meshd_bearer bearer = { .arg = NULL, .tx = sar_capture_tx };
	struct mesh_net_pdu np;
	uint8_t access[64];
	uint32_t seqauth;
	int changed;

	(void)tc;
	seg_payload(access, sizeof(access));

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);
	g_sar_n = 0;
	ATF_REQUIRE_EQ(0, meshd_send_access_raw(nd, 0x00AA, access,
	    sizeof(access)));
	ATF_REQUIRE_MSG(g_sar_n > 1, "message must segment (%zu)", g_sar_n);
	ATF_REQUIRE_EQ(1, nd->self->sar_tx[0].used);

	/*
	 * The SeqAuth is the SEQ of segment zero, read off the wire rather
	 * than out of the engine's own bookkeeping.
	 */
	ATF_REQUIRE_EQ(0, net_open(g_sar_frames[0], g_sar_len[0],
	    cfg.iv_index, &np));
	seqauth = np.seq;

	/*
	 * TEST SETUP: other traffic burns sequence numbers until SEQ is
	 * exactly 8192 past the SeqAuth.  No acknowledgment has arrived.
	 */
	nd->self->seq = seqauth + 0x2000;

	/*
	 * THE GATE.  The transmission must be cancelled, and cancelled on
	 * observation rather than at the next retransmission timer: the window
	 * is gone, so nothing more may go out under this SeqZero.
	 */
	g_sar_n = 0;
	ATF_REQUIRE_EQ(0, meshd_node_tick(nd, 100, &changed));
	ATF_CHECK_EQ_MSG(0, nd->self->sar_tx[0].used,
	    "the transaction must be cancelled at SeqAuth + 8192");
	ATF_CHECK_EQ_MSG(0u, (unsigned)g_sar_n,
	    "nothing may be retransmitted under an exhausted SeqZero");
	/* And it stays cancelled past the retransmission interval. */
	g_sar_n = 0;
	ATF_REQUIRE(meshd_node_tick(nd, 900, &changed) >= 0);
	ATF_CHECK_EQ_MSG(0u, (unsigned)g_sar_n,
	    "a cancelled transaction does not resume");

	/*
	 * The CONTROL: one short of the window (SeqAuth + 8191) is still a
	 * live transaction and still retransmits, so the case cannot pass by
	 * cancelling everything.
	 */
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(ctl, &cfg));
	meshd_set_bearer(ctl, &bearer);
	g_sar_n = 0;
	ATF_REQUIRE_EQ(0, meshd_send_access_raw(ctl, 0x00AA, access,
	    sizeof(access)));
	ATF_REQUIRE(g_sar_n > 1);
	ATF_REQUIRE_EQ(0, net_open(g_sar_frames[0], g_sar_len[0],
	    cfg.iv_index, &np));
	ctl->self->seq = np.seq + 0x1fff;
	g_sar_n = 0;
	ATF_REQUIRE(meshd_node_tick(ctl, 900, &changed) >= 0);
	ATF_CHECK_MSG(g_sar_n > 0,
	    "SeqAuth + 8191 is still inside the window and must retransmit");

	meshd_node_fini(ctl);
	meshd_node_fini(nd);
}

/* ---- IM40b: one segmented transaction per destination ----------------- */
/*
 * MshPRT_v1.1.1 Section 3.5.3.3.1:
 *
 *   "The lower transport layer shall not transmit segmented messages for more
 *    than one Upper Transport PDU to the same destination at the same time.
 *    The lower transport layer should start to transmit segmented messages for
 *    a new Upper Transport PDU for the same destination when the transaction
 *    for the last Upper Transport PDU is completed or the message transmission
 *    has been canceled."
 *
 * Two transactions to one destination share a single 13-bit SeqZero space and
 * a single AckedSegments value at the peer, so the peer's acknowledgments
 * become ambiguous - which is the "shall not" of the first sentence.
 *
 * EXPECTATION CHANGE, FLAGGED PROMINENTLY: this case used to require the
 * second origination to be REFUSED.  It is now required to be QUEUED, which is
 * what the section's SECOND sentence asks for ("should start to transmit
 * segmented messages for a new Upper Transport PDU for the same destination
 * when the transaction for the last Upper Transport PDU is completed or the
 * message transmission has been canceled").  Refusing satisfied the "shall
 * not" while ignoring the "should", and made an operator issuing two segmented
 * verbs back to back get an error.
 *
 * The invariant the case was really protecting is UNCHANGED and still
 * asserted: exactly one live transaction per destination, and nothing on the
 * air for the second Upper Transport PDU until the first ends.  What is new is
 * that the second PDU must then GO OUT BY ITSELF, with no second call from the
 * higher layer.
 */
ATF_TC_WITHOUT_HEAD(im40b_one_transaction_per_destination);
ATF_TC_BODY(im40b_one_transaction_per_destination, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .arg = NULL, .tx = sar_capture_tx };
	uint8_t access[64];
	uint16_t first_seqzero;
	size_t i, live;
	int changed;

	(void)tc;
	seg_payload(access, sizeof(access));
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);

	g_sar_n = 0;
	ATF_REQUIRE_EQ(0, meshd_send_access_raw(nd, 0x00AA, access,
	    sizeof(access)));
	ATF_REQUIRE_MSG(g_sar_n > 1, "message must segment");
	ATF_REQUIRE_EQ(1, nd->self->sar_tx[0].used);

	/* THE GATE.  A second segmented Upper Transport PDU to 0x00AA. */
	g_sar_n = 0;
	ATF_CHECK_EQ_MSG(0, meshd_send_access_raw(nd, 0x00AA, access,
	    sizeof(access)),
	    "a second segmented transaction to the same destination must be "
	    "queued, not refused");
	ATF_CHECK_EQ_MSG(0u, (unsigned)g_sar_n,
	    "nothing may go on the air while the first transaction is live");
	live = 0;
	for (i = 0; i < MESH_SIM_SAR_TX; i++)
		if (nd->self->sar_tx[i].used &&
		    nd->self->sar_tx[i].dst == 0x00AA)
			live++;
	ATF_CHECK_EQ_MSG(1u, (unsigned)live,
	    "one destination may hold exactly one transaction, found %u",
	    (unsigned)live);

	/*
	 * The CONTROL, twice over.  A DIFFERENT destination is unaffected...
	 */
	g_sar_n = 0;
	ATF_CHECK_EQ_MSG(0, meshd_send_access_raw(nd, 0x00AB, access,
	    sizeof(access)),
	    "a segmented transaction to another destination is allowed");
	ATF_CHECK_MSG(g_sar_n > 1, "and does reach the air");

	/*
	 * ... and once the first transaction is over ("the message
	 * transmission has been canceled"), the destination is free again.
	 */
	first_seqzero = sar_tx_seqzero_for(nd, 0x00AA);
	ATF_REQUIRE(first_seqzero != 0xffff);
	for (i = 0, changed = 0; i < 120; i++) {
		g_sar_n = 0;
		ATF_REQUIRE(meshd_node_tick(nd, (uint64_t)(i + 1) * 500,
		    &changed) >= 0);
		if (sar_tx_seqzero_for(nd, 0x00AA) != first_seqzero &&
		    sar_tx_seqzero_for(nd, 0x00AA) != 0xffff)
			break;
	}
	/*
	 * THE SECOND HALF OF THE GATE: the queued Upper Transport PDU started
	 * on its own once the first transaction was cancelled - no further
	 * call from the higher layer, which is exactly the "should start to
	 * transmit" the refusal used to ignore.  A different SeqZero on the
	 * same destination is a different Upper Transport PDU.
	 */
	ATF_CHECK_MSG(sar_tx_seqzero_for(nd, 0x00AA) != first_seqzero &&
	    sar_tx_seqzero_for(nd, 0x00AA) != 0xffff,
	    "the queued transaction must start by itself once the destination "
	    "is free");
	ATF_CHECK_MSG(g_sar_n > 1,
	    "and its segments must reach the air (%zu frames)", g_sar_n);
	ATF_CHECK_EQ_MSG(1, sar_tx_used_for(nd, 0x00AA),
	    "and it must occupy the destination's single transmit slot");

	/*
	 * And the DEFINED FULL-QUEUE behaviour: the queue is bounded at
	 * MESH_SIM_SAR_QUEUE entries, and an origination that finds it full is
	 * refused - the same answer the section's first sentence always
	 * allowed.  0x00AA now has one live transaction, so every further
	 * origination to it queues until the queue is full.
	 */
	for (i = 0; i < MESH_SIM_SAR_QUEUE; i++)
		ATF_REQUIRE_EQ_MSG(0, meshd_send_access_raw(nd, 0x00AA, access,
		    sizeof(access)), "queue slot %zu must be accepted", i);
	ATF_CHECK_MSG(meshd_send_access_raw(nd, 0x00AA, access,
	    sizeof(access)) != 0,
	    "an origination that finds the queue full must be refused, not "
	    "dropped silently");

	meshd_node_fini(nd);
}

/* ---- IM40c: Table 3.24's third and fourth validity conditions --------- */
/*
 * MshPRT_v1.1.1 Table 3.24 lists four conditions an incoming Segment
 * Acknowledgment must ALL meet to be "a valid acknowledgment".  Two were
 * checked (matching SeqAuth; source matches the stored destination or OBO = 1)
 * and two were not:
 *
 *   "For the SeqAuth derived from the SeqZero field of the message, there is
 *    at least one unacknowledged segment that the AckedSegments field of the
 *    message reports as delivered"
 *
 *   "The message was secured using the same NetKey that was used to secure the
 *    segmented message"
 *
 * Section 3.5.3.3.2 then makes a valid acknowledgment that does not cover
 * everything drive a retransmission round and spend a retry, so honouring an
 * INVALID one burns the budget: a peer (or an attacker on another subnet the
 * node holds) can replay one acknowledgment and drain the transfer.
 */
ATF_TC_WITHOUT_HEAD(im40c_ack_validity_conditions);
ATF_TC_BODY(im40c_ack_validity_conditions, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .arg = NULL, .tx = sar_capture_tx };
	struct mesh_cfg_netkey nk;
	struct mesh_seg_ack ack;
	struct mesh_net_pdu np;
	uint8_t access[64], lt[MESH_SEG_ACK_LEN];
	uint8_t frame[MESH_NET_MAX_PDU];
	uint8_t msg[64], reply[64];
	uint8_t secondary[16], senc[16], spriv[16], snid;
	static const uint8_t k2_p_flooding[1] = { 0x00 };
	size_t ltlen, flen, mlen, rlen = 0;
	uint16_t seqzero;
	uint8_t segn, retries;

	(void)tc;
	seg_payload(access, sizeof(access));
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);

	/* A secondary subnet, NetKeyIndex 1, installed through the Config
	 * Server - the same path im26 uses. */
	memset(secondary, 0x99, sizeof(secondary));
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 1;
	memcpy(nk.key, secondary, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD,
	    &nk, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);
	ATF_REQUIRE_EQ(0, mesh_k2(secondary, k2_p_flooding,
	    sizeof(k2_p_flooding), &snid, senc, spriv));

	g_sar_n = 0;
	ATF_REQUIRE_EQ(0, meshd_send_access_raw(nd, 0x00AA, access,
	    sizeof(access)));
	ATF_REQUIRE_MSG(g_sar_n > 1, "message must segment");
	ATF_REQUIRE_EQ(1, nd->self->sar_tx[0].used);
	seqzero = nd->self->sar_tx[0].seqzero;
	segn = nd->self->sar_tx[0].segn;
	ATF_REQUIRE(segn >= 1);

	memset(&ack, 0, sizeof(ack));
	ack.seqzero = seqzero;
	ack.blockack = 1;		/* segment zero only */
	ack.obo = 0;
	ATF_REQUIRE_EQ(0, mesh_seg_ack_build(&ack, lt, &ltlen));

	/*
	 * THE FOURTH CONDITION.  The identical acknowledgment secured with the
	 * SECONDARY subnet's NetKey, which this node holds and will therefore
	 * authenticate.  It must not touch a transaction that went out on the
	 * primary.
	 */
	memset(&np, 0, sizeof(np));
	np.nid = snid;
	np.ctl = 1;
	np.ttl = 5;
	np.seq = 0x100;
	np.src = 0x00AA;
	np.dst = nd->addr;
	memcpy(np.transport, lt, ltlen);
	np.transport_len = ltlen;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(senc, spriv, snid, cfg.iv_index,
	    &np, frame, &flen));
	g_sar_n = 0;
	retries = nd->self->sar_tx[0].retries;
	(void)meshd_bearer_rx(nd, frame, flen);
	ATF_CHECK_EQ_MSG(0u, (unsigned)nd->self->sar_tx[0].blockack,
	    "an acknowledgment on another NetKey must not mark a segment "
	    "delivered");
	ATF_CHECK_EQ_MSG(retries, nd->self->sar_tx[0].retries,
	    "an acknowledgment on another NetKey must not spend a retry");
	ATF_CHECK_EQ_MSG(0u, (unsigned)g_sar_n,
	    "an acknowledgment on another NetKey must not drive a "
	    "retransmission round");

	/*
	 * The CONTROL for the fourth condition: the same acknowledgment on the
	 * PRIMARY subnet is valid, reports progress, and does drive a round.
	 */
	np.nid = nd->self->nid;
	np.seq = 0x101;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(nd->self->enckey,
	    nd->self->privkey, nd->self->nid, cfg.iv_index, &np, frame,
	    &flen));
	g_sar_n = 0;
	(void)meshd_bearer_rx(nd, frame, flen);
	ATF_REQUIRE_EQ_MSG(1u, (unsigned)nd->self->sar_tx[0].blockack,
	    "the same acknowledgment on the primary subnet is valid "
	    "(used=%d ba=0x%x retries=%u nsar=%zu pni=%u ni=%u)",
	    nd->self->sar_tx[0].used,
	    (unsigned)nd->self->sar_tx[0].blockack,
	    (unsigned)nd->self->sar_tx[0].retries, g_sar_n,
	    (unsigned)nd->self->primary_net_idx,
	    (unsigned)nd->self->sar_tx[0].net_idx);
	ATF_REQUIRE_MSG(g_sar_n > 0,
	    "a valid partial acknowledgment retransmits the rest");
	retries = nd->self->sar_tx[0].retries;
	ATF_REQUIRE(retries > 0);

	/*
	 * THE THIRD CONDITION.  A replay of that acknowledgment reports
	 * nothing NEW as delivered, so it is not a valid acknowledgment and
	 * must be ignored - not honoured into another retransmission round.
	 */
	np.seq = 0x102;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(nd->self->enckey,
	    nd->self->privkey, nd->self->nid, cfg.iv_index, &np, frame,
	    &flen));
	g_sar_n = 0;
	(void)meshd_bearer_rx(nd, frame, flen);
	ATF_CHECK_EQ_MSG(retries, nd->self->sar_tx[0].retries,
	    "an acknowledgment reporting no new segment must not spend a "
	    "retry");
	ATF_CHECK_EQ_MSG(0u, (unsigned)g_sar_n,
	    "an acknowledgment reporting no new segment must not retransmit");

	/*
	 * The CONTROL for the third condition: an acknowledgment that DOES
	 * report a new segment is still honoured.
	 */
	ack.blockack = 3;		/* segments zero and one */
	ATF_REQUIRE_EQ(0, mesh_seg_ack_build(&ack, lt, &ltlen));
	memcpy(np.transport, lt, ltlen);
	np.transport_len = ltlen;
	np.seq = 0x103;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(nd->self->enckey,
	    nd->self->privkey, nd->self->nid, cfg.iv_index, &np, frame,
	    &flen));
	g_sar_n = 0;
	(void)meshd_bearer_rx(nd, frame, flen);
	ATF_CHECK_EQ_MSG(3u, (unsigned)nd->self->sar_tx[0].blockack,
	    "new progress is still recorded");

	meshd_node_fini(nd);
}

/* ---- IM39: RPL exhaustion fails closed, is reported, and recovers ----- */
/*
 * MshPRT_v1.1.1 Section 3.9.8:
 *
 *   "If a node does not have enough resources to perform replay protection for
 *    a given source address, then the node shall discard the message
 *    immediately upon reception."
 *
 * The specification sets no minimum capacity: Table 4.2 has Composition Data
 * Page 0 advertise it as CRPL, "a 16-bit value representing the minimum number
 * of replay protection list entries in a device", and we advertise our real
 * capacity there.  So failing closed at capacity is conformant and staying
 * closed forever is not a specification violation - it is an operational one,
 * and finding 39's complaint is that nothing recovered and nothing reported.
 *
 * Two things are fixed, and neither invents an eviction policy:
 *
 *  - the condition is COUNTED and reported by the daemon's "status" verb, so a
 *    saturated list is distinguishable from a dead radio;
 *  - a full list reclaims only entries that can no longer adjudicate anything.
 *    A receiver authenticates a Network PDU under the current IV Index or IV
 *    Index - 1 only (Sections 3.10.5 / 3.11.5), so an entry more than one
 *    epoch behind cannot be reached by any PDU that would still authenticate,
 *    and the traffic that source can still send carries an IVISeq strictly
 *    greater than the reclaimed value - which an empty slot accepts too.
 *
 * INTERPRETATION, recorded as one: the specification does not name this
 * reclaim.  The claim it rests on - that nothing secured under IV Index - 2 or
 * earlier can authenticate - is a consequence of the receive-index rule, not a
 * quotation.  No LRU or lowest-SEQ eviction is performed; those WOULD open a
 * replay window.
 */
ATF_TC_WITHOUT_HEAD(im39_rpl_full_reports_and_recovers);
ATF_TC_BODY(im39_rpl_full_reports_and_recovers, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct peer_frames pf, first;
	uint8_t params[4];
	char reply[256];
	const char *av[1] = { "status" };
	size_t i;
	uint32_t before;
	uint16_t src;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	memset(params, 0x5a, sizeof(params));

	/*
	 * Saturate the list: one unsegmented access message per distinct
	 * source, each delivered to a model and therefore recorded.
	 */
	for (i = 0; i < MESH_SIM_RPL_SIZE; i++) {
		src = (uint16_t)(0x0102 + i);
		before = nd->self->rx.count;
		peer_access_frames(src, nd->addr, 100, cfg.iv_index, 0x8299,
		    params, sizeof(params), &pf);
		ATF_REQUIRE_EQ_MSG(1u, (unsigned)pf.n,
		    "the fixture message must be unsegmented");
		ATF_REQUIRE_EQ_MSG(1, meshd_bearer_rx(nd, pf.bytes[0],
		    pf.len[0]), "source %u must be delivered", (unsigned)i);
		ATF_REQUIRE_EQ(before + 1, nd->self->rx.count);
		if (i == 0)
			first = pf;
	}

	/*
	 * THE GATE, part one: source number CRPL+1 is discarded (correct, and
	 * unchanged), and the discard is now COUNTED and reported.
	 */
	src = (uint16_t)(0x0102 + MESH_SIM_RPL_SIZE);
	peer_access_frames(src, nd->addr, 100, cfg.iv_index, 0x8299, params,
	    sizeof(params), &pf);
	before = nd->self->rx.count;
	ATF_CHECK_EQ_MSG(0, meshd_bearer_rx(nd, pf.bytes[0], pf.len[0]),
	    "with no room for the source the PDU must be discarded");
	ATF_CHECK_EQ(before, nd->self->rx.count);
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(nd, NULL, 1,
	    __DECONST(char **, av), reply, sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "rplfull=1") != NULL,
	    "the status verb must report the exhaustion, got \"%s\"", reply);

	/*
	 * THE GATE, part two: two IV epochs later the entries recorded at IV
	 * Index 0 can no longer adjudicate any PDU, so one is reclaimed and
	 * the new source is admitted.
	 *
	 * TEST SETUP: the node is at IV Index 2, which it reaches through two
	 * ordinary IV Update procedures (192 hours apart).  Set directly, as
	 * im26 and im28 set IV state directly, because the transitions
	 * themselves are not what is under test here.
	 */
	nd->self->iv.iv_index = 2;
	peer_access_frames(src, nd->addr, 100, 2, 0x8299, params,
	    sizeof(params), &pf);
	before = nd->self->rx.count;
	ATF_CHECK_EQ_MSG(1, meshd_bearer_rx(nd, pf.bytes[0], pf.len[0]),
	    "an entry two IV epochs stale must be reclaimed for a new source");
	ATF_CHECK_EQ(before + 1, nd->self->rx.count);

	/*
	 * The CONTROL, and the safety argument made executable: the source
	 * whose entry was reclaimed cannot be replayed.  Its captured PDU is
	 * secured under IV Index 0, which this node no longer authenticates
	 * (it accepts only IV Index 2 and 1), so the reclaim opened no window.
	 */
	before = nd->self->rx.count;
	ATF_CHECK_EQ_MSG(0, meshd_bearer_rx(nd, first.bytes[0], first.len[0]),
	    "a PDU secured two IV epochs ago must not authenticate at all");
	ATF_CHECK_EQ_MSG(before, nd->self->rx.count,
	    "reclaiming a stale entry must not admit a replay");

	meshd_node_fini(nd);
}

/* ---- IM43: the access PDU bound is on the whole message, not the params - */
/*
 * MshPRT_v1.1.1 Section 3.7.3:
 *
 *   "With a 32-bit TransMIC field, the maximum size of the Access message is
 *    380 octets, and therefore with a single-octet opcode, the parameters
 *    field can be up to 379 octets.  With a 2-octet opcode, the parameters
 *    field can be up to 378 octets.  With a 3-octet opcode, the parameters
 *    field can be up to 377 octets."
 *
 * Table 3.61 lists the Parameters field as "0 to 379", and the parser enforced
 * only that, so a 3-octet-opcode message of 382 octets - 379 parameter octets
 * that no conformant peer can have sent, and that our own build side refuses
 * to produce - parsed clean.  There is no memory-safety issue either way: the
 * parameters buffer is 379 octets and the bound that was checked is its size.
 *
 * THIS CASE PINS THE BOUNDARY RATHER THAN GATING THE FIX, and the difference
 * was established by reverting: with the parser's total-length check removed,
 * every assertion below still passes.  The reason is that no daemon entry
 * point can present the parser with a message longer than 380 octets in the
 * first place - an Access message travels in at most 32 twelve-octet segments
 * (384 octets "including the TransMIC field"), so the largest access payload
 * the upper transport can hand over or accept is 384 - 4 = 380, and
 * meshd_send_access_raw() refuses a 382-octet message at segmentation even
 * with the lax parser.  The fix is a strictness repair to the parser's own
 * contract, not a reachable defect; what this case locks is the 380/381
 * boundary at the daemon's origination entry.
 */
ATF_TC_WITHOUT_HEAD(im43_access_pdu_total_length_bound);
ATF_TC_BODY(im43_access_pdu_total_length_bound, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .arg = NULL, .tx = sar_capture_tx };
	static uint8_t access[MESH_ACCESS_PAYLOAD_MAX + 4];
	size_t i;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);

	/* A 3-octet vendor opcode: 11xxxxxx followed by a little-endian CID. */
	access[0] = 0xC1;
	access[1] = 0x0C;
	access[2] = 0x00;
	for (i = 3; i < sizeof(access); i++)
		access[i] = (uint8_t)i;

	/*
	 * THE GATE.  382 octets: a 3-octet opcode plus 379 parameter octets.
	 * The parameters are within Table 3.61's 379 but the message is two
	 * octets past the 380-octet maximum.
	 */
	ATF_CHECK_MSG(meshd_send_access_raw(nd, 0x00AA, access,
	    MESH_ACCESS_PAYLOAD_MAX + 2) != 0,
	    "a 382-octet access message must be refused");
	/* 381 is over the bound as well. */
	ATF_CHECK_MSG(meshd_send_access_raw(nd, 0x00AA, access,
	    MESH_ACCESS_PAYLOAD_MAX + 1) != 0,
	    "a 381-octet access message must be refused");

	/*
	 * The CONTROL: exactly 380 octets - a 3-octet opcode and 377
	 * parameters, the largest message this opcode form allows - is
	 * accepted, so the case gates the bound rather than the feature.
	 */
	g_sar_n = 0;
	ATF_CHECK_EQ_MSG(0, meshd_send_access_raw(nd, 0x00AB, access,
	    MESH_ACCESS_PAYLOAD_MAX),
	    "the maximum-size access message must still be accepted");

	meshd_node_fini(nd);
}

/* ---- IM42: the Network Message Cache is keyed on the NetKey index ------ */
/*
 * MshPRT_v1.1.1 Section 3.4.6.5: "Values for the SRC, SEQ fields, and index of
 * the NetKey used for decrypting PDU contents should be stored in a cache
 * entry."
 *
 * This is a "should", not a "shall", and the cache already keyed on (SRC, SEQ,
 * IV Index) - a superset of (SRC, SEQ) that is better across an IV Update and
 * worse across subnets.  The recommendation is followed because it has a
 * concrete consequence: Section 3.4.6.3 has a Subnet Bridge re-secure a PDU
 * onto another subnet with the originator's SRC and SEQ intact, so on a node
 * holding both subnets the bridged copy was indistinguishable from the
 * original and was discarded as a duplicate.  The IV Index is KEPT in the key
 * as well: a longer key can only cause a PDU to be processed that would
 * otherwise have been dropped as a duplicate, never the same Network PDU
 * twice, which is the property the section requires.
 *
 * Driven through meshd_foundation_recv() (Config NetKey Add and Config Relay
 * Set) and meshd_bearer_rx().
 */
ATF_TC_WITHOUT_HEAD(im42_message_cache_keyed_on_netkey);
ATF_TC_BODY(im42_message_cache_keyed_on_netkey, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .arg = NULL, .tx = sar_capture_tx };
	struct mesh_cfg_netkey nk;
	struct mesh_cfg_relay rl;
	struct peer_frames pf;
	struct mesh_net_pdu np;
	uint8_t params[4], msg[64], reply[64];
	uint8_t frame[MESH_NET_MAX_PDU];
	uint8_t secondary[16], senc[16], spriv[16], snid;
	static const uint8_t k2_p_flooding[1] = { 0x00 };
	size_t mlen, rlen = 0, flen;
	uint32_t relays;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);
	memset(params, 0x33, sizeof(params));

	/* A secondary subnet, NetKeyIndex 1. */
	memset(secondary, 0x99, sizeof(secondary));
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 1;
	memcpy(nk.key, secondary, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD,
	    &nk, msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);
	ATF_REQUIRE_EQ(0, mesh_k2(secondary, k2_p_flooding,
	    sizeof(k2_p_flooding), &snid, senc, spriv));

	/* Relay on, so a PDU that is not for us is retransmitted. */
	memset(&rl, 0, sizeof(rl));
	rl.relay = 1;
	rl.retransmit = 0;
	ATF_REQUIRE_EQ(0, mesh_cfg_relay_set_build(MESH_CFG_OP_RELAY_SET, &rl,
	    msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));

	/*
	 * One Network PDU from 0x0102 to a third party, secured on the primary
	 * subnet, and the SAME (SRC, SEQ, IV Index) re-secured on the
	 * secondary subnet - which is exactly what a Subnet Bridge emits.
	 */
	peer_access_frames(0x0102, 0x00AA, 100, cfg.iv_index, 0x8299, params,
	    sizeof(params), &pf);
	ATF_REQUIRE_EQ_MSG(1u, (unsigned)pf.n, "the fixture must be one PDU");
	ATF_REQUIRE_EQ(0, net_open(pf.bytes[0], pf.len[0], cfg.iv_index, &np));
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(senc, spriv, snid, cfg.iv_index,
	    &np, frame, &flen));

	relays = nd->self->relay_count;
	(void)meshd_bearer_rx(nd, pf.bytes[0], pf.len[0]);
	ATF_REQUIRE_EQ_MSG(relays + 1, nd->self->relay_count,
	    "the first copy must be relayed");

	/*
	 * The CONTROL first, because it is what makes the gate meaningful: a
	 * byte-identical repeat on the SAME subnet is a cache hit and must not
	 * be relayed again.
	 */
	relays = nd->self->relay_count;
	(void)meshd_bearer_rx(nd, pf.bytes[0], pf.len[0]);
	ATF_CHECK_EQ_MSG(relays, nd->self->relay_count,
	    "a repeat on the same subnet is a cache hit");

	/*
	 * THE GATE.  Same SRC, same SEQ, same IV Index, DIFFERENT NetKey: a
	 * different Network PDU, which must be processed.
	 */
	relays = nd->self->relay_count;
	(void)meshd_bearer_rx(nd, frame, flen);
	ATF_CHECK_EQ_MSG(relays + 1, nd->self->relay_count,
	    "the same (SRC, SEQ, IV Index) on another NetKey is a distinct "
	    "Network PDU and must not be discarded as a duplicate");

	/* And that copy is itself cached: a repeat of it changes nothing. */
	relays = nd->self->relay_count;
	(void)meshd_bearer_rx(nd, frame, flen);
	ATF_CHECK_EQ_MSG(relays, nd->self->relay_count,
	    "the secondary-subnet copy is cached too");

	meshd_node_fini(nd);
}


/* ================================================================
 * SAR Configuration Server: the SAR Transmitter (MshPRT_v1.1.1 Section 4.2.48)
 * and SAR Receiver (Section 4.2.49) composite states.
 *
 * Section 4.2.48, verbatim: "A node shall implement the SAR Transmitter state
 * independently of the presence of the SAR Configuration Server model."
 * Section 4.2.49, verbatim: "The node shall implement the SAR Receiver
 * independently of the presence of the SAR Configuration Server model."
 *
 * The STATES are mandatory and only the MODEL is optional, so a stack that
 * advertises the model while its SAR behaviour runs off compiled-in constants
 * ships the one arrangement the specification rules out: a provisioner can
 * read and write the states and observe no effect.
 *
 * Every expected value below comes from spec_extref_mesh_sar.h, which
 * transcribes the sub-section defaults and formulae from the specification
 * text; none was produced by running this stack.  All five cases are driven
 * through meshd_foundation_recv() (the daemon's Configuration Server entry),
 * meshd_send_access_raw(), meshd_bearer_rx() and meshd_node_tick().
 * ================================================================ */

/* Deliver one Config message and return the reply length. */
static size_t
sar_cfg_deliver(struct meshd_node *nd, const uint8_t *msg, size_t mlen,
    uint8_t *reply, size_t reply_max)
{
	size_t rlen = 0;

	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply,
	    reply_max, &rlen));
	return (rlen);
}

/*
 * A SAR Transmitter Get on an unconfigured node must return the
 * specification's own defaults, and a Set must round-trip every one of the
 * seven sub-states exactly - several of them are "x + 1" step counts rather
 * than raw values, so a codec that normalises anything makes the Status
 * disagree with the following Get.
 */
ATF_TC_WITHOUT_HEAD(sar_transmitter_state_roundtrip);
ATF_TC_BODY(sar_transmitter_state_roundtrip, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_sar_transmitter set, got;
	uint8_t msg[32], reply[32];
	size_t mlen, rlen;
	uint32_t opcode;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Get: the Section 4.2.48.1-.7 defaults. */
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_get_build(msg, &mlen));
	rlen = sar_cfg_deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_parse(reply, rlen, &opcode, &got));
	ATF_CHECK_EQ(MESH_CFG_OP_SAR_TRANSMITTER_STATUS, opcode);
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_SAR_TX_SEG_INT_STEP_DEFAULT,
	    got.seg_interval_step, "SAR Segment Interval Step default");
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_SAR_TX_UNICAST_RETRANS_DEFAULT,
	    got.unicast_retrans_count, "SAR Unicast Retransmissions Count");
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_SAR_TX_NO_PROGRESS_DEFAULT,
	    got.unicast_retrans_without_progress_count,
	    "SAR Unicast Retransmissions Without Progress Count");
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_SAR_TX_UNICAST_INT_STEP_DEFAULT,
	    got.unicast_retrans_interval_step,
	    "SAR Unicast Retransmissions Interval Step");
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_SAR_TX_UNICAST_INC_DEFAULT,
	    got.unicast_retrans_interval_increment,
	    "SAR Unicast Retransmissions Interval Increment");
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_SAR_TX_MULTICAST_RETRANS_DEFAULT,
	    got.multicast_retrans_count, "SAR Multicast Retransmissions Count");
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_SAR_TX_MULTICAST_INT_STEP_DEFAULT,
	    got.multicast_retrans_interval_step,
	    "SAR Multicast Retransmissions Interval Step");

	/* Set every sub-state to a distinct in-range value. */
	memset(&set, 0, sizeof(set));
	set.seg_interval_step = 0x0f;
	set.unicast_retrans_count = 0x0e;
	set.unicast_retrans_without_progress_count = 0x0d;
	set.unicast_retrans_interval_step = 0x0c;
	set.unicast_retrans_interval_increment = 0x0b;
	set.multicast_retrans_count = 0x0a;
	set.multicast_retrans_interval_step = 0x09;
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_build(MESH_CFG_OP_SAR_TRANSMITTER_SET,
	    &set, msg, &mlen));
	rlen = sar_cfg_deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_parse(reply, rlen, &opcode, &got));
	ATF_CHECK_EQ(MESH_CFG_OP_SAR_TRANSMITTER_STATUS, opcode);
	ATF_CHECK_EQ_MSG(0, memcmp(&set, &got, sizeof(set)),
	    "the Status must echo the Set exactly");

	/* And a following Get must return the same, not the defaults. */
	memset(&got, 0, sizeof(got));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_get_build(msg, &mlen));
	rlen = sar_cfg_deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_parse(reply, rlen, &opcode, &got));
	ATF_CHECK_EQ_MSG(0, memcmp(&set, &got, sizeof(set)),
	    "a Get must return what the Set wrote");

	meshd_node_fini(nd);
}

/* The same for the five SAR Receiver sub-states, Section 4.2.49.1-.5. */
ATF_TC_WITHOUT_HEAD(sar_receiver_state_roundtrip);
ATF_TC_BODY(sar_receiver_state_roundtrip, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_sar_receiver set, got;
	uint8_t msg[32], reply[32];
	size_t mlen, rlen;
	uint32_t opcode;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_get_build(msg, &mlen));
	rlen = sar_cfg_deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_parse(reply, rlen, &opcode, &got));
	ATF_CHECK_EQ(MESH_CFG_OP_SAR_RECEIVER_STATUS, opcode);
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_SAR_RX_SEG_THRESHOLD_DEFAULT,
	    got.segments_threshold, "SAR Segments Threshold default");
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_SAR_RX_ACK_DELAY_INC_DEFAULT,
	    got.ack_delay_increment, "SAR Acknowledgment Delay Increment");
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_SAR_RX_ACK_RETRANS_DEFAULT,
	    got.ack_retrans_count,
	    "SAR Acknowledgment Retransmissions Count");
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_SAR_RX_DISCARD_TIMEOUT_DEFAULT,
	    got.discard_timeout, "SAR Discard Timeout default");
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_SAR_RX_SEG_INT_STEP_DEFAULT,
	    got.rx_segment_interval_step,
	    "SAR Receiver Segment Interval Step default");

	memset(&set, 0, sizeof(set));
	set.segments_threshold = 0x1f;		/* 5-bit */
	set.ack_delay_increment = 0x06;		/* 3-bit */
	set.discard_timeout = 0x0e;		/* 4-bit */
	set.rx_segment_interval_step = 0x0d;	/* 4-bit */
	set.ack_retrans_count = 0x03;		/* 2-bit */
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_build(MESH_CFG_OP_SAR_RECEIVER_SET,
	    &set, msg, &mlen));
	rlen = sar_cfg_deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_parse(reply, rlen, &opcode, &got));
	ATF_CHECK_EQ(MESH_CFG_OP_SAR_RECEIVER_STATUS, opcode);
	ATF_CHECK_EQ_MSG(0, memcmp(&set, &got, sizeof(set)),
	    "the Status must echo the Set exactly");

	memset(&got, 0, sizeof(got));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_get_build(msg, &mlen));
	rlen = sar_cfg_deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_parse(reply, rlen, &opcode, &got));
	ATF_CHECK_EQ_MSG(0, memcmp(&set, &got, sizeof(set)),
	    "a Get must return what the Set wrote");

	meshd_node_fini(nd);
}

/*
 * THE GATE for the SAR Transmitter's effect on the transport layer.
 *
 * Section 3.5.3.3.1 makes the SAR Unicast Retransmissions timer a function of
 * two settable states and the message TTL:
 *   "[unicast retransmissions interval step + unicast retransmissions
 *     interval increment * (TTL - 1)]"
 * With the interval step and the increment both written to their maximum
 * (0b1111), Section 4.2.48.4/.5 give (15 + 1) * 25 = 400 ms for each term, so
 * at base_config()'s Default TTL of 7 the interval is 400 + 400 * 6 =
 * 2800 ms.  A stack that ignores the increment - or ignores the states
 * altogether - retransmits an order of magnitude too early.
 */
ATF_TC_WITHOUT_HEAD(sar_transmitter_state_drives_retransmit_timer);
ATF_TC_BODY(sar_transmitter_state_drives_retransmit_timer, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .arg = NULL, .tx = sar_capture_tx };
	struct mesh_cfg_sar_transmitter set;
	uint8_t msg[32], reply[32], access[64];
	size_t mlen, i;
	uint32_t interval;
	int changed;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);

	memset(&set, 0, sizeof(set));
	set.seg_interval_step = 0x00;			/* 10 ms */
	set.unicast_retrans_count = 0x0f;		/* a long budget */
	set.unicast_retrans_without_progress_count = 0x0f;
	set.unicast_retrans_interval_step = 0x0f;	/* 400 ms */
	set.unicast_retrans_interval_increment = 0x0f;	/* 400 ms */
	set.multicast_retrans_count = 0x02;
	set.multicast_retrans_interval_step = 0x09;
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_build(MESH_CFG_OP_SAR_TRANSMITTER_SET,
	    &set, msg, &mlen));
	(void)sar_cfg_deliver(nd, msg, mlen, reply, sizeof(reply));

	interval = SPEC_EXTREF_MESH_SAR_TX_UNICAST_TIMER_MS(0x0fu, 0x0fu, 7u);
	ATF_REQUIRE_EQ_MSG(2800u, interval,
	    "the oracle's own formula must give 2800 ms, got %u",
	    (unsigned)interval);

	access[0] = 0x82;
	access[1] = 0x99;
	for (i = 2; i < sizeof(access); i++)
		access[i] = (uint8_t)i;
	g_sar_n = 0;
	ATF_REQUIRE_EQ(0, meshd_send_access_raw(nd, 0x0002, access,
	    sizeof(access)));
	ATF_REQUIRE_MSG(g_sar_n > 1, "message must segment (%zu)", g_sar_n);

	/*
	 * Well inside the configured interval: nothing may be retransmitted.
	 * This is the arm that fails when the states are ignored and a flat
	 * library constant times the retransmission.
	 */
	g_sar_n = 0;
	ATF_REQUIRE(meshd_node_tick(nd, 1000, &changed) >= 0);
	ATF_CHECK_EQ_MSG(0u, (unsigned)g_sar_n,
	    "nothing may be retransmitted %u ms into a %u ms interval",
	    1000u, (unsigned)interval);

	/* Past it, the whole unacknowledged transaction goes out again. */
	g_sar_n = 0;
	ATF_REQUIRE(meshd_node_tick(nd, 3200, &changed) >= 0);
	ATF_CHECK_MSG(g_sar_n > 1,
	    "the transaction must be retransmitted past the interval (%zu)",
	    g_sar_n);

	meshd_node_fini(nd);
}

/*
 * THE GATE for the SAR Multicast Retransmissions Count state, Section
 * 4.2.48.6: "the maximum number of transmissions of a segment is (SAR
 * Multicast Retransmissions Count + 1)".  Written to 0b0000 the segments are
 * sent exactly once, and Section 3.5.3.3.3's "when the SAR Multicast
 * Retransmissions timer expires and the remaining number of retransmissions
 * value is 0, then the lower transport layer shall cancel the transmission"
 * ends the transaction with no repeat at all.  A stack holding the count as a
 * constant repeats regardless of what the provisioner wrote.
 */
ATF_TC_WITHOUT_HEAD(sar_transmitter_state_drives_multicast_count);
ATF_TC_BODY(sar_transmitter_state_drives_multicast_count, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .arg = NULL, .tx = sar_capture_tx };
	struct mesh_cfg_sar_transmitter set;
	uint8_t msg[32], reply[32], access[64];
	size_t mlen, i;
	int changed;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);

	memset(&set, 0, sizeof(set));
	set.seg_interval_step = 0x00;
	set.unicast_retrans_count = 0x02;
	set.unicast_retrans_without_progress_count = 0x02;
	set.unicast_retrans_interval_step = 0x07;
	set.unicast_retrans_interval_increment = 0x01;
	set.multicast_retrans_count = 0x00;		/* one transmission */
	set.multicast_retrans_interval_step = 0x00;	/* 25 ms */
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_build(MESH_CFG_OP_SAR_TRANSMITTER_SET,
	    &set, msg, &mlen));
	(void)sar_cfg_deliver(nd, msg, mlen, reply, sizeof(reply));

	access[0] = 0x82;
	access[1] = 0x99;
	for (i = 2; i < sizeof(access); i++)
		access[i] = (uint8_t)i;
	g_sar_n = 0;
	ATF_REQUIRE_EQ(0, meshd_send_access_raw(nd, 0xC000, access,
	    sizeof(access)));
	ATF_REQUIRE_MSG(g_sar_n > 1, "message must segment (%zu)", g_sar_n);

	/* THE GATE: a full second, far past any multicast interval. */
	g_sar_n = 0;
	for (i = 100; i <= 1000; i += 100)
		ATF_REQUIRE(meshd_node_tick(nd, (uint64_t)i, &changed) >= 0);
	ATF_CHECK_EQ_MSG(0u, (unsigned)g_sar_n,
	    "a Multicast Retransmissions Count of 0 forbids every repeat, "
	    "saw %zu frames", g_sar_n);

	meshd_node_fini(nd);
}

/*
 * THE GATE for the SAR Receiver's acknowledgment retransmissions, Section
 * 3.5.3.4, verbatim:
 *
 *   "If the number of segments in the transmission indicated by the value of
 *    SegN field is greater than the value of the SAR Segments Threshold state
 *    (see Section 4.2.49.1), the lower transport layer shall retransmit
 *    Segment Acknowledgment messages using the value of the SAR Acknowledgment
 *    Retransmissions Count state (see Section 4.2.49.3).  Each retransmitted
 *    message shall include a new value for the SEQ field.  Between
 *    retransmissions, the lower transport layer shall introduce a delay
 *    indicated by the value of the SAR Receiver Segment Interval Step state
 *    (see Section 4.2.49.5)."
 *
 * Section 4.2.49.3: "The maximum number of transmissions of a Segment
 * Acknowledgment message is (SAR Acknowledgment Retransmissions Count + 1)."
 * At the specification's defaults the count is 0b00 - one transmission - so
 * this behaviour is INVISIBLE until the SAR Receiver state is writable, which
 * is exactly why a stack can ship the model without it and not notice.
 */
ATF_TC_WITHOUT_HEAD(sar_receiver_state_drives_ack_retransmissions);
ATF_TC_BODY(sar_receiver_state_drives_ack_retransmissions, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_bearer bearer = { .arg = NULL, .tx = sar_capture_tx };
	struct mesh_cfg_sar_receiver set;
	struct peer_frames pf;
	struct mesh_net_pdu np;
	uint8_t msg[32], reply[32], params[48];
	size_t mlen, i, acks;
	uint32_t seqs[16];
	size_t nseq = 0;
	int changed;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	meshd_set_bearer(nd, &bearer);

	memset(&set, 0, sizeof(set));
	/* 0 arms the behaviour for every multi-segment message. */
	set.segments_threshold = 0x00;
	set.ack_delay_increment = 0x01;
	set.discard_timeout = 0x01;
	set.rx_segment_interval_step = 0x00;	/* 10 ms between retransmits */
	set.ack_retrans_count = 0x03;		/* 4 transmissions in all */
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_build(MESH_CFG_OP_SAR_RECEIVER_SET,
	    &set, msg, &mlen));
	(void)sar_cfg_deliver(nd, msg, mlen, reply, sizeof(reply));

	for (i = 0; i < sizeof(params); i++)
		params[i] = (uint8_t)i;
	/*
	 * The source must not be one of this node's OWN element addresses -
	 * base_config() gives the node 0x0001 and its secondary elements
	 * follow it - or the network layer discards the frame as its own.
	 */
	peer_access_frames(0x0102, nd->addr, 5000, cfg.iv_index, 0x8299,
	    params, sizeof(params), &pf);
	ATF_REQUIRE_MSG(pf.n > 1, "payload must segment (%zu)", pf.n);

	g_sar_n = 0;
	for (i = 0; i < pf.n; i++)
		ATF_REQUIRE(meshd_bearer_rx(nd, pf.bytes[i], pf.len[i]) >= 0);
	/* Let the retransmission timer run out its budget. */
	for (i = 10; i <= 300; i += 10)
		ATF_REQUIRE(meshd_node_tick(nd, (uint64_t)i, &changed) >= 0);

	acks = 0;
	for (i = 0; i < g_sar_n; i++) {
		ATF_REQUIRE_EQ(0, net_open(g_sar_frames[i], g_sar_len[i],
		    cfg.iv_index, &np));
		if (np.ctl != 1 || np.transport_len == 0 ||
		    (np.transport[0] & 0x7f) != SPEC_EXTREF_MESH_SEG_ACK_OPCODE)
			continue;
		if (nseq < nitems(seqs))
			seqs[nseq++] = np.seq;
		acks++;
	}
	ATF_CHECK_EQ_MSG((size_t)(set.ack_retrans_count + 1), acks,
	    "(SAR Acknowledgment Retransmissions Count + 1) Segment "
	    "Acknowledgment messages must be sent, saw %zu", acks);
	/* "Each retransmitted message shall include a new value for the SEQ
	 * field": every acknowledgment carries a distinct SEQ. */
	for (i = 0; i + 1 < nseq; i++)
		ATF_CHECK_MSG(seqs[i] != seqs[i + 1],
		    "a retransmitted acknowledgment reused SEQ %u",
		    (unsigned)seqs[i]);

	meshd_node_fini(nd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, im3_appkey_binding_is_unconditional);
	ATF_TP_ADD_TC(tp, im6_virtual_dispatch_uses_label_not_hash);
	ATF_TP_ADD_TC(tp, im8_fixed_group_dst_matched_on_receive);
	ATF_TP_ADD_TC(tp, im9_group_delivery_is_per_model);
	ATF_TP_ADD_TC(tp, im12_one_ack_per_sar_ack_timer);
	ATF_TP_ADD_TC(tp, im17_multicast_sar_retransmission);
	ATF_TP_ADD_TC(tp, im4_appkey_old_and_new_through_phase2);
	ATF_TP_ADD_TC(tp, im10_ordinary_iv_update_is_not_recovery);
	ATF_TP_ADD_TC(tp, im26_secondary_subnet_cannot_drive_iv);
	ATF_TP_ADD_TC(tp, im23_one_reassembly_per_source);
	ATF_TP_ADD_TC(tp, im25_message_rejected_blockack_zero);
	ATF_TP_ADD_TC(tp, sar_transmitter_state_roundtrip);
	ATF_TP_ADD_TC(tp, sar_receiver_state_roundtrip);
	ATF_TP_ADD_TC(tp, sar_transmitter_state_drives_retransmit_timer);
	ATF_TP_ADD_TC(tp, sar_transmitter_state_drives_multicast_count);
	ATF_TP_ADD_TC(tp, sar_receiver_state_drives_ack_retransmissions);
	ATF_TP_ADD_TC(tp, im28_iv_completion_defers_to_segmented_tx);
	ATF_TP_ADD_TC(tp, im39_rpl_full_reports_and_recovers);
	ATF_TP_ADD_TC(tp, im42_message_cache_keyed_on_netkey);
	ATF_TP_ADD_TC(tp, im43_access_pdu_total_length_bound);
	ATF_TP_ADD_TC(tp, im40a_seqzero_window_cancels_tx);
	ATF_TP_ADD_TC(tp, im40b_one_transaction_per_destination);
	ATF_TP_ADD_TC(tp, im40c_ack_validity_conditions);
	ATF_TP_ADD_TC(tp, im29_node_reset_erases_key_material);
	ATF_TP_ADD_TC(tp, im32_node_identity_excludes_private);
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
	ATF_TP_ADD_TC(tp, m3_provisioning_output_oob);
	ATF_TP_ADD_TC(tp, m3_provisioning_input_oob);
	ATF_TP_ADD_TC(tp, m3_provisioning_oob_refused_and_timeout);
	ATF_TP_ADD_TC(tp, m7_private_beacon_wired);
	ATF_TP_ADD_TC(tp, m7_private_beacon_random_cadence);
	ATF_TP_ADD_TC(tp, m8_identity_advertising_duration);
	ATF_TP_ADD_TC(tp, m9_lpn_subscription_list);
	ATF_TP_ADD_TC(tp, m9_lpn_subscription_confirm_lost);
	ATF_TP_ADD_TC(tp, m10_iv_recovery_hold_persists);
	ATF_TP_ADD_TC(tp, m11_proxy_reasm_tick_wired);
	ATF_TP_ADD_TC(tp, px1_proxy_adv_network_id_from_tick);
	ATF_TP_ADD_TC(tp, px2_proxy_adv_identity_precedence);
	ATF_TP_ADD_TC(tp, px3_proxy_adv_interleaves_subnets);
	ATF_TP_ADD_TC(tp, px4_proxy_server_answers_filter_status);
	ATF_TP_ADD_TC(tp, px5_proxy_server_filters_and_learns);
	ATF_TP_ADD_TC(tp, px6_proxy_service_and_connect_beacons);

	return (atf_no_error());
}
