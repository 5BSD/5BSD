/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the meshd(8) persistent node-state store (meshd_persist.c) and
 * the clock tick that advances the time-driven state machines (meshd_node_tick).
 *
 * The security assertions are:
 *
 *   - SEQ CANNOT REGRESS across a restart/crash.  Sequence numbers are handed
 *     out from a reserved block whose high-water is persisted ahead of use; a
 *     reload resumes the live SEQ at that high-water, strictly above any SEQ the
 *     node could have used before the crash (MshPRT_v1.1 Section 3.8.4).
 *
 *   - THE REPLAY PROTECTION LIST SURVIVES A RESTART: a (src, seq) accepted
 *     before the crash is rejected as a replay after the reload (Section 3.8.8).
 *
 * plus keys/IV/config round-trip, CRC / version gating, and a mock-clock tick
 * that fires an IV Update timer at the expected `now` (Section 3.10.5).
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "mesh_test_heap.h"
#include "meshd.h"
#include "meshd_persist.h"
#include "mesh_crypto.h"

int ptap_meshd_persist_decode_sweep(const struct meshd_node *);

static const uint8_t g_newkey[16] = {
	0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
	0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0
};

/* Locate a subnet db entry by NetKey index. */
static struct meshd_netkey_entry *
db_netkey(struct meshd_node *nd, uint16_t net_idx)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_NETKEYS; i++) {
		if (nd->db.netkeys[i].valid &&
		    nd->db.netkeys[i].net_idx == net_idx)
			return (&nd->db.netkeys[i]);
	}
	return (NULL);
}

static const uint8_t g_netkey[16] = {
	0x7d, 0xd7, 0x36, 0x4c, 0xd8, 0x42, 0xad, 0x18,
	0xc1, 0x7c, 0x2b, 0x82, 0x0c, 0x84, 0xc3, 0xd6
};
static const uint8_t g_appkey[16] = {
	0x63, 0x96, 0x47, 0x71, 0x73, 0x4f, 0xbd, 0x76,
	0xe3, 0xb4, 0x05, 0x19, 0xd1, 0xd9, 0x4a, 0x48
};

static void
base_config(struct meshd_config *cfg)
{

	meshd_config_defaults(cfg);
	memcpy(cfg->netkey, g_netkey, 16);
	memcpy(cfg->appkey, g_appkey, 16);
	cfg->have_netkey = 1;
	cfg->have_appkey = 1;
	cfg->unicast_addr = 0x0100;
	cfg->iv_index = 0;
	cfg->default_ttl = 7;
}

static void
fresh_node(struct meshd_node *nd)
{
	struct meshd_config cfg;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
}

static void
store_set_version(const char *path, uint16_t version)
{
	FILE *f;
	uint8_t b[2];

	b[0] = (uint8_t)(version & 0xff);
	b[1] = (uint8_t)((version >> 8) & 0xff);
	f = fopen(path, "r+b");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE_EQ(0, fseek(f, 8, SEEK_SET));
	ATF_REQUIRE_EQ(2, fwrite(b, 1, sizeof(b), f));
	ATF_REQUIRE_EQ(0, fclose(f));
}

static void
save_fresh_store(struct meshd_persist *ps, struct meshd_node *nd,
    const char *path)
{

	(void)unlink(path);
	fresh_node(nd);
	meshd_persist_init(ps, path, 100);
	ATF_REQUIRE_EQ(1, meshd_persist_load(ps, nd));
	ATF_REQUIRE_EQ(1, meshd_persist_seq_reserve(ps, nd));
}

/* ================================================================
 * SEQ block reservation: the SEQ-no-regress security assertion.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(seq_block_no_regress);
ATF_TC_BODY(seq_block_no_regress, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_persist ps;
	const char *path = "meshd_seq.state";
	uint32_t last_used;

	fresh_node(a);
	meshd_persist_init(&ps, path, 100);

	/* No store yet: load reports a fresh node, and we reserve the first block. */
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));
	ATF_REQUIRE_EQ(1, meshd_persist_seq_reserve(&ps, a));
	ATF_CHECK_EQ(100u, ps.reserved);	/* live 0 + block */

	/*
	 * Consume SEQ up to just below the reserved high-water WITHOUT
	 * re-reserving - this models a crash mid-block.  The highest SEQ the node
	 * could have handed out is last_used; every one is strictly below the
	 * persisted high-water.
	 */
	a->self->seq = 99;
	last_used = a->self->seq;
	ATF_REQUIRE(last_used < ps.reserved);

	/* Crash + restart: a brand-new node loads the persisted state. */
	fresh_node(b);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, b));

	/* SECURITY: the resumed SEQ is strictly above any SEQ used before. */
	ATF_CHECK(meshd_node_seq(b) > last_used);
	ATF_CHECK_EQ(100u, meshd_node_seq(b));

	/* And the next block was reserved ahead again (crash-after-boot safe). */
	ATF_CHECK(ps.reserved >= meshd_node_seq(b) + MESHD_PERSIST_SEQ_GUARD);

	/* Repeated reload never regresses: each boot resumes >= the last. */
	a->self->seq = meshd_node_seq(b) + 50;
	ATF_REQUIRE(meshd_persist_seq_reserve(&ps, b) >= 0);
	{
		MESH_HEAP(struct meshd_node, c);
		uint32_t before = ps.reserved;

		fresh_node(c);
		ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, c));
		ATF_CHECK_EQ(before, meshd_node_seq(c));
	}

	(void)unlink(path);
}

/*
 * The reserve-ahead invariant holds directly: after any seq_reserve the
 * persisted high-water stays at least GUARD above the live SEQ, so the live
 * SEQ can never reach (let alone hand out at) an un-persisted value.
 */
ATF_TC_WITHOUT_HEAD(seq_reserve_ahead_invariant);
ATF_TC_BODY(seq_reserve_ahead_invariant, tc)
{
	MESH_HEAP(struct meshd_node, a);
	struct meshd_persist ps;
	const char *path = "meshd_seqinv.state";
	uint32_t s;

	fresh_node(a);
	meshd_persist_init(&ps, path, 256);
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));

	for (s = 0; s < 2000; s += 30) {
		a->self->seq = s;
		ATF_REQUIRE(meshd_persist_seq_reserve(&ps, a) >= 0);
		/* Reserved always strictly ahead of the live SEQ. */
		ATF_CHECK(ps.reserved > a->self->seq);
		ATF_CHECK(ps.reserved >= a->self->seq + MESHD_PERSIST_SEQ_GUARD);
	}

	(void)unlink(path);
}

/* ================================================================
 * SEQ reservation is IV-epoch aware: a beacon-driven IV Index change (which
 * resets the live SEQ to 0 without the tick observing it) must invalidate the
 * carried-over high-water and force an immediate re-reserve for the new epoch.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(seq_reserve_iv_epoch);
ATF_TC_BODY(seq_reserve_iv_epoch, tc)
{
	MESH_HEAP(struct meshd_node, a);
	struct meshd_persist ps;
	const char *path = "meshd_seqepoch.state";

	fresh_node(a);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));
	ATF_REQUIRE_EQ(1, meshd_persist_seq_reserve(&ps, a));
	ATF_CHECK_EQ(100u, ps.reserved);

	/* Ample headroom within the epoch: no re-reserve. */
	a->self->seq = 10;
	ATF_CHECK_EQ(0, meshd_persist_seq_reserve(&ps, a));

	/*
	 * Beacon-driven IV completion: new TX IV Index, live SEQ back to 0.
	 * The old high-water (100 >= 0 + GUARD) would look like headroom, but
	 * it belongs to the previous epoch: a fresh block MUST be persisted.
	 */
	a->self->iv.iv_index++;
	a->self->seq = 0;
	ATF_CHECK_EQ(1, meshd_persist_seq_reserve(&ps, a));
	ATF_CHECK_EQ(100u, ps.reserved);
	ATF_CHECK_EQ(mesh_iv_tx_index(&a->self->iv), ps.reserved_txiv);

	(void)unlink(path);
}

/* ================================================================
 * The SEQ epoch is the TX IV Index, not the beacon IV Index: when the IV
 * Update COMPLETES (Update In Progress -> Normal) the iv_index field does not
 * change, yet the TX index moves from iv_index-1 to iv_index and the live SEQ
 * resets to 0 - a fresh block MUST be persisted for the new epoch.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(seq_reserve_iv_completion);
ATF_TC_BODY(seq_reserve_iv_completion, tc)
{
	MESH_HEAP(struct meshd_node, a);
	struct meshd_persist ps;
	const char *path = "meshd_seqcompl.state";

	fresh_node(a);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));

	/* Network enters IV Update: beacon index 1, TX stays on index 0. */
	a->self->iv.iv_index = 1;
	a->self->iv.state = MESH_IV_UPDATE_IN_PROGRESS;
	ATF_REQUIRE_EQ(0u, mesh_iv_tx_index(&a->self->iv));
	a->self->seq = 10;
	ATF_REQUIRE_EQ(1, meshd_persist_seq_reserve(&ps, a));
	ATF_CHECK_EQ(0u, ps.reserved_txiv);

	/* Ample headroom within the epoch: no re-reserve. */
	ATF_CHECK_EQ(0, meshd_persist_seq_reserve(&ps, a));

	/*
	 * Completion: iv_index is UNCHANGED, only the state machine moves
	 * back to Normal - the TX index advances 0 -> 1 and SEQ resets.
	 * The carried-over high-water belongs to epoch 0: a fresh block
	 * covering epoch 1 must be persisted immediately.
	 */
	a->self->iv.state = MESH_IV_NORMAL;
	a->self->seq = 0;
	ATF_REQUIRE_EQ(1u, mesh_iv_tx_index(&a->self->iv));
	ATF_CHECK_EQ(1, meshd_persist_seq_reserve(&ps, a));
	ATF_CHECK_EQ(100u, ps.reserved);
	ATF_CHECK_EQ(1u, ps.reserved_txiv);

	(void)unlink(path);
}

/* ================================================================
 * provision-local floors the re-seeded node's SEQ at the persisted
 * reservation: even a reset + reprovision with the same key/IV cannot hand
 * out an already-used (IV,SRC,SEQ).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(provision_local_seq_floor);
ATF_TC_BODY(provision_local_seq_floor, tc)
{
	MESH_HEAP(struct meshd_node, a);
	struct meshd_persist ps;
	const char *path = "meshd_seqfloor.state";
	char reply[256];
	char *av[3];
	uint32_t floor_mark;

	fresh_node(a);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));
	a->persist = &ps;
	a->self->seq = 42;			/* SEQs already spent */
	ATF_REQUIRE(meshd_persist_seq_reserve(&ps, a) >= 0);
	floor_mark = ps.reserved;
	ATF_REQUIRE(floor_mark > 42);

	/* provision-local on a live node is refused: reset is required. */
	av[0] = __DECONST(char *, "provision-local");
	av[1] = __DECONST(char *, "0x0100");
	av[2] = __DECONST(char *, "0");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(a, NULL, 3, av, reply,
	    sizeof(reply)));
	ATF_CHECK(strstr(reply, "already provisioned") != NULL);

	av[0] = __DECONST(char *, "reset");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(a, NULL, 1, av, reply,
	    sizeof(reply)));

	/* Same address, same IV: the fresh SEQ must resume AT the old mark. */
	av[0] = __DECONST(char *, "provision-local");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(a, NULL, 3, av, reply,
	    sizeof(reply)));
	ATF_CHECK(a->self->seq >= floor_mark);
	/* And the next block is already persisted ahead of the floored SEQ. */
	ATF_CHECK(ps.reserved >= a->self->seq + MESHD_PERSIST_SEQ_GUARD);

	(void)unlink(path);
}

/* ================================================================
 * Round-2 fix: the SEQ floor is IV-epoch-aware.  provision-local at a TX IV
 * Index BELOW the persisted reservation's epoch is refused outright (the
 * store no longer covers that epoch's spent SEQ space); an equal index keeps
 * the floor; a strictly higher index opens a fresh epoch (SEQ 0) and still
 * re-reserves.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(provision_local_iv_epoch);
ATF_TC_BODY(provision_local_iv_epoch, tc)
{
	MESH_HEAP(struct meshd_node, a);
	struct meshd_persist ps;
	const char *path = "meshd_seqepoch.state";
	char reply[256];
	char *av[3];
	uint32_t floor_mark;

	fresh_node(a);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));
	a->persist = &ps;

	/* SEQs spent in epoch (TX IV Index) 5. */
	a->self->iv.iv_index = 5;
	a->self->seq = 42;
	ATF_REQUIRE(meshd_persist_seq_reserve(&ps, a) >= 0);
	ATF_REQUIRE_EQ(5u, ps.reserved_txiv);
	floor_mark = ps.reserved;

	av[0] = __DECONST(char *, "reset");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(a, NULL, 1, av, reply,
	    sizeof(reply)));

	/* Lower IV than the reserved epoch: refused, node stays down. */
	av[0] = __DECONST(char *, "provision-local");
	av[1] = __DECONST(char *, "0x0100");
	av[2] = __DECONST(char *, "4");
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(a, NULL, 3, av, reply,
	    sizeof(reply)));
	ATF_CHECK(strstr(reply, "below persisted SEQ epoch") != NULL);
	ATF_CHECK_EQ(0, a->provisioned);

	/* Equal IV: allowed, and the SEQ floor still applies. */
	av[2] = __DECONST(char *, "5");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(a, NULL, 3, av, reply,
	    sizeof(reply)));
	ATF_CHECK(a->self->seq >= floor_mark);

	av[0] = __DECONST(char *, "reset");
	ATF_REQUIRE_EQ(0, meshd_ctl_exec_client(a, NULL, 1, av, reply,
	    sizeof(reply)));

	/* Higher IV: a fresh epoch, SEQ 0 is safe, new block reserved. */
	av[0] = __DECONST(char *, "provision-local");
	av[2] = __DECONST(char *, "6");
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(a, NULL, 3, av, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0u, a->self->seq);
	ATF_CHECK_EQ(6u, ps.reserved_txiv);
	ATF_CHECK(ps.reserved >= a->self->seq + MESHD_PERSIST_SEQ_GUARD);

	(void)unlink(path);
}

/* ================================================================
 * appkey_index and a staged Config AppKey Update key survive a restart.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(appkey_index_and_staged_key_roundtrip);
ATF_TC_BODY(appkey_index_and_staged_key_roundtrip, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_persist ps;
	const char *path = "meshd_akidx.state";
	uint8_t staged[16];

	fresh_node(a);
	a->appkey_index = 0x003;
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));

	/* A configured AppKey with a staged (KR Phase 1) update key. */
	a->db.appkeys[0].valid = 1;
	a->db.appkeys[0].app_idx = 0x001;
	a->db.appkeys[0].net_idx = 0x000;
	memcpy(a->db.appkeys[0].key, g_appkey, 16);
	memset(staged, 0x5a, sizeof(staged));
	memcpy(a->db.appkeys[0].new_key, staged, 16);
	a->db.appkeys[0].has_new_key = 1;
	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, a));

	fresh_node(b);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, b));

	/* The bootstrap AppKey index is restored, not reset to 0. */
	ATF_CHECK_EQ(0x003, b->appkey_index);
	/* The staged key is held again, distinct from the live key. */
	ATF_CHECK_EQ(1, b->db.appkeys[0].valid);
	ATF_CHECK_EQ(1, b->db.appkeys[0].has_new_key);
	ATF_CHECK_EQ(0, memcmp(b->db.appkeys[0].key, g_appkey, 16));
	ATF_CHECK_EQ(0, memcmp(b->db.appkeys[0].new_key, staged, 16));

	(void)unlink(path);
}

/* ================================================================
 * RPL survives restart: the replay-rejection security assertion.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(rpl_survives_restart);
ATF_TC_BODY(rpl_survives_restart, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_persist ps;
	const char *path = "meshd_rpl.state";
	const uint16_t src = 0x0005;
	const uint32_t iv = 0;
	const uint32_t seq = 0x001234;

	fresh_node(a);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));

	/* Accept a PDU from src at (iv, seq): the RPL records it (returns 1). */
	ATF_REQUIRE_EQ(1, mesh_rpl_check(&a->self->rpl, src, iv, seq));
	/* Immediately replayed: rejected (returns 0). */
	ATF_REQUIRE_EQ(0, mesh_rpl_check(&a->self->rpl, src, iv, seq));

	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, a));

	/* Crash + restart. */
	fresh_node(b);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, b));

	/* SECURITY: the replay is STILL rejected after the reload. */
	ATF_CHECK_EQ(0, mesh_rpl_check(&b->self->rpl, src, iv, seq));
	/* A strictly newer SEQ from the same source is accepted. */
	ATF_CHECK_EQ(1, mesh_rpl_check(&b->self->rpl, src, iv, seq + 1));

	(void)unlink(path);
}

/* ================================================================
 * Keys / IV / model configuration round-trip.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(node_state_roundtrip);
ATF_TC_BODY(node_state_roundtrip, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_persist ps;
	const char *path = "meshd_state.state";

	fresh_node(a);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));

	/* Mutate runtime state: an added AppKey, a model binding/sub/pub, IV phase. */
	a->db.appkeys[0].valid = 1;
	a->db.appkeys[0].app_idx = 0x001;
	a->db.appkeys[0].net_idx = 0x000;
	memcpy(a->db.appkeys[0].key, g_appkey, 16);

	a->db.models[0].n_app = 1;
	a->db.models[0].app_idx[0] = 0x001;
	a->db.models[0].n_subs = 1;
	a->db.models[0].subs[0] = 0xC000;
	a->db.models[0].sub_is_va[0] = 0;
	a->db.models[0].has_pub = 1;
	a->db.models[0].pub.pub_addr = 0xC001;
	a->db.models[0].pub.app_idx = 0x001;
	a->db.models[0].pub.ttl = 5;

	a->self->iv.iv_index = 3;
	a->self->iv.state = MESH_IV_UPDATE_IN_PROGRESS;
	/*
	 * A far-future dwell timestamp (as a persisted value would look on a host
	 * whose wall clock has since regressed): the loader must clamp it down to
	 * the current wall clock so no dwell-gated IV transition is wedged until
	 * real time catches up (finding 71 / NB-7).
	 */
	a->self->iv.entered_time = 4000000000000ULL;
	a->self->seq = 42;
	a->app->onoff.present = MESH_GEN_ON;
	a->app->level.present = (int16_t)(500 - 32768);
	a->app->dtt.transition_time = 0x41;
	a->app->power_onoff.on_power_up = MESH_GEN_ONPOWERUP_DEFAULT;
	a->app->power_onoff.last_onoff = MESH_GEN_ON;
	a->app->power_level.actual = 500;
	a->app->power_level.last = 700;
	a->app->power_level.default_power = 600;
	a->app->power_level.range_min = 100;
	a->app->power_level.range_max = 1000;
	a->app->location.global.latitude = -123456;
	a->app->location.global.longitude = 654321;
	a->app->location.global.altitude = 42;
	a->app->location.local.north = -10;
	a->app->location.local.east = 20;
	a->app->location.local.altitude = 3;
	a->app->location.local.floor = 7;
	a->app->location.local.uncertainty = 0x1234;
	a->app->time.time.tai_seconds = UINT64_C(0x0102030405);
	a->app->time.time.subsecond = 6;
	a->app->time.time.uncertainty = 7;
	a->app->time.time.tai_utc_delta = 0x1234;
	a->app->time.time.time_authority = 1;
	a->app->time.time.time_zone_offset = 0x40;
	a->app->time.role = 2;
	a->app->time.new_zone_offset = 0x44;
	a->app->time.zone_change = 200;
	a->app->time.new_tai_utc_delta = 0x1235;
	a->app->time.delta_change = 300;
	a->app->lightness.actual = 500;
	a->app->lightness.last = 500;
	a->app->lightness.default_lightness = 300;
	a->app->lightness.range_min = 100;
	a->app->lightness.range_max = 1000;
	a->app->ctl.temperature = 3000;
	a->app->ctl.delta_uv = -10;
	a->app->ctl.default_lightness = 500;
	a->app->ctl.default_temperature = 3500;
	a->app->ctl.default_delta_uv = 20;
	a->app->ctl.range_min = 1000;
	a->app->ctl.range_max = 5000;
	a->app->hsl.hue = 2000; a->app->hsl.saturation = 3000;
	a->app->hsl.default_lightness = 500; a->app->hsl.default_hue = 2100;
	a->app->hsl.default_saturation = 3100; a->app->hsl.hue_min = 100;
	a->app->hsl.hue_max = 5000; a->app->hsl.saturation_min = 200;
	a->app->hsl.saturation_max = 6000;
	a->app->xyl.x = 2000; a->app->xyl.y = 3000;
	a->app->xyl.default_lightness = 500; a->app->xyl.default_x = 2100;
	a->app->xyl.default_y = 3100; a->app->xyl.x_min = 100;
	a->app->xyl.x_max = 5000; a->app->xyl.y_min = 200;
	a->app->xyl.y_max = 6000;
	a->app->lc.mode = 1; a->app->lc.occupancy_mode = 1;
	a->app->lc.light_onoff = 1;
	{
		uint8_t lc_prop[] = { 0x34, 0x12 };
		ATF_REQUIRE_EQ(0, mesh_light_lc_property_set(&a->app->lc, 0x002e,
		    lc_prop, sizeof(lc_prop)));
	}
	ATF_REQUIRE_EQ(0, mesh_scene_srv_store(&a->app->scene, 0x1234));
	{
		struct mesh_scheduler_action action;
		memset(&action, 0, sizeof(action)); action.index = 3; action.year = 0x64;
		action.months = 0x80; action.day = 13; action.hour = 7;
		action.minute = 30; action.days_of_week = 0x7f; action.action = 2;
		action.scene_number = 10;
		a->app->scheduler.entries[3] = action;
		a->app->scheduler.defined = 1u << 3;
	}
	{
		struct mesh_sensor_descriptor d = { 0x004f, 1, 2, 3, 4, 5 };
		struct mesh_sensor_cadence cadence;
		struct mesh_sensor_setting setting;
		struct mesh_sensor_column column;
		uint8_t raw[] = { 0x11, 0x22 };
		ATF_REQUIRE_EQ(0, mesh_sensor_srv_set(&a->app->sensor, &d, raw, 2));
		memset(&cadence, 0, sizeof(cadence)); cadence.fast_period_divisor = 2;
		cadence.delta_down[0] = 1; cadence.delta_up[0] = 2;
		ATF_REQUIRE_EQ(0, mesh_sensor_srv_set_cadence(&a->app->sensor, 0x004f,
		    &cadence));
		memset(&setting, 0, sizeof(setting)); setting.property_id = 0x1234;
		setting.access = 3; setting.raw[0] = 9; setting.raw_len = 1;
		ATF_REQUIRE_EQ(0, mesh_sensor_srv_set_setting(&a->app->sensor, 0x004f,
		    &setting));
		memset(&column, 0, sizeof(column)); column.key[0] = 7;
		column.key_len = 1; column.raw[0] = 7; column.raw_len = 1;
		ATF_REQUIRE_EQ(0, mesh_sensor_srv_set_column(&a->app->sensor, 0x004f,
		    &column));
	}

	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, a));

	fresh_node(b);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, b));

	/* Address, primary keys and their derived credentials. */
	ATF_CHECK_EQ(0x0100, meshd_node_addr(b));
	ATF_CHECK_EQ(0, memcmp(b->self->netkey, g_netkey, 16));
	ATF_CHECK_EQ(0, memcmp(b->self->appkeys[0].key, g_appkey, 16));

	/* IV Index / phase. */
	ATF_CHECK_EQ(3u, meshd_node_iv(b));
	ATF_CHECK_EQ(MESH_IV_UPDATE_IN_PROGRESS, b->self->iv.state);
	/* The dwell timestamp is clamped down to the current wall clock, not the
	 * astronomically large persisted value (finding 71 / NB-7): it is no
	 * longer the stored far-future value and is not ahead of "now". */
	ATF_CHECK(b->self->iv.entered_time < 4000000000000ULL);
	ATF_CHECK(b->self->iv.entered_time <= (uint64_t)time(NULL));

	/* AppKey + model config. */
	ATF_CHECK_EQ(1, b->db.appkeys[0].valid);
	ATF_CHECK_EQ(0x001, b->db.appkeys[0].app_idx);
	ATF_CHECK_EQ(0, memcmp(b->db.appkeys[0].key, g_appkey, 16));
	ATF_CHECK_EQ(1u, (unsigned)b->db.models[0].n_app);
	ATF_CHECK_EQ(0x001, b->db.models[0].app_idx[0]);
	ATF_CHECK_EQ(1u, (unsigned)b->db.models[0].n_subs);
	ATF_CHECK_EQ(0xC000, b->db.models[0].subs[0]);
	ATF_CHECK_EQ(1, b->db.models[0].has_pub);
	ATF_CHECK_EQ(0xC001, b->db.models[0].pub.pub_addr);
	ATF_CHECK_EQ(0x0100, b->db.models[0].elem_addr);
	/*
	 * The first secondary-element (0x0101) model entry, located by
	 * searching rather than by a fixed index: the primary element's model
	 * inventory grows whenever a model is added to the node, and a magic
	 * index turns that into an unrelated test failure.
	 */
	{
		size_t mi;

		for (mi = 0; mi < b->db.n_models; mi++)
			if (b->db.models[mi].valid &&
			    b->db.models[mi].elem_addr == 0x0101)
				break;
		ATF_REQUIRE(mi + 1 < b->db.n_models);
		ATF_CHECK_EQ(0x0101, b->db.models[mi].elem_addr);
		ATF_CHECK_EQ(MESH_MODEL_LIGHT_CTL_TEMP_SRV,
		    b->db.models[mi + 1].id.model_id);
	}

	/* Nonvolatile application-model state (current internal schema). */
	ATF_CHECK_EQ(MESH_GEN_ON, b->app->onoff.present);
	ATF_CHECK_EQ((int16_t)(500 - 32768), b->app->level.present);
	ATF_CHECK_EQ(0x41, b->app->dtt.transition_time);
	ATF_CHECK_EQ(MESH_GEN_ONPOWERUP_DEFAULT,
	    b->app->power_onoff.on_power_up);
	ATF_CHECK_EQ(MESH_GEN_ON, b->app->power_onoff.last_onoff);
	ATF_CHECK_EQ(500, b->app->power_level.actual);
	ATF_CHECK_EQ(700, b->app->power_level.last);
	ATF_CHECK_EQ(600, b->app->power_level.default_power);
	ATF_CHECK_EQ(100, b->app->power_level.range_min);
	ATF_CHECK_EQ(1000, b->app->power_level.range_max);
	ATF_CHECK_EQ(-123456, b->app->location.global.latitude);
	ATF_CHECK_EQ(654321, b->app->location.global.longitude);
	ATF_CHECK_EQ(-10, b->app->location.local.north);
	ATF_CHECK_EQ(7, b->app->location.local.floor);
	ATF_CHECK_EQ(0x1234, b->app->location.local.uncertainty);
	ATF_CHECK_EQ(1u, b->app->sensor.n_entries);
	ATF_CHECK_EQ(0x004f,
	    b->app->sensor.entries[0].descriptor.property_id);
	ATF_CHECK_EQ(1, b->app->sensor.entries[0].cadence.valid);
	ATF_CHECK_EQ(1u, b->app->sensor.entries[0].n_settings);
	ATF_CHECK_EQ(1u, b->app->sensor.entries[0].n_columns);
	ATF_CHECK_EQ(UINT64_C(0x0102030405), b->app->time.time.tai_seconds);
	ATF_CHECK_EQ(0x1234, b->app->time.time.tai_utc_delta);
	ATF_CHECK_EQ(2, b->app->time.role);
	ATF_CHECK_EQ(0x44, b->app->time.new_zone_offset);
	ATF_CHECK_EQ(200u, b->app->time.zone_change);
	ATF_CHECK_EQ(0x1235, b->app->time.new_tai_utc_delta);
	ATF_CHECK_EQ(300u, b->app->time.delta_change);
	ATF_CHECK_EQ(500, b->app->lightness.actual);
	ATF_CHECK_EQ(500, b->app->lightness.last);
	ATF_CHECK_EQ(300, b->app->lightness.default_lightness);
	ATF_CHECK_EQ(100, b->app->lightness.range_min);
	ATF_CHECK_EQ(1000, b->app->lightness.range_max);
	ATF_CHECK_EQ(3000, b->app->ctl.temperature);
	ATF_CHECK_EQ(-10, b->app->ctl.delta_uv);
	ATF_CHECK_EQ(3500, b->app->ctl.default_temperature);
	ATF_CHECK_EQ(1000, b->app->ctl.range_min);
	ATF_CHECK_EQ(5000, b->app->ctl.range_max);
	ATF_CHECK_EQ(2000, b->app->hsl.hue);
	ATF_CHECK_EQ(3000, b->app->hsl.saturation);
	ATF_CHECK_EQ(100, b->app->hsl.hue_min);
	ATF_CHECK_EQ(6000, b->app->hsl.saturation_max);
	ATF_CHECK_EQ(2000, b->app->xyl.x);
	ATF_CHECK_EQ(3000, b->app->xyl.y);
	ATF_CHECK_EQ(100, b->app->xyl.x_min);
	ATF_CHECK_EQ(6000, b->app->xyl.y_max);
	ATF_CHECK_EQ(1, b->app->lc.mode);
	ATF_CHECK_EQ(1, b->app->lc.occupancy_mode);
	ATF_CHECK_EQ(1, b->app->lc.light_onoff);
	ATF_CHECK_EQ(1u, b->app->lc.n_properties);
	ATF_CHECK_EQ(0x002e, b->app->lc.properties[0].id);
	ATF_CHECK_EQ(2u, b->app->lc.properties[0].len);
	ATF_CHECK_EQ(0x34, b->app->lc.properties[0].value[0]);
	ATF_CHECK_EQ(0x12, b->app->lc.properties[0].value[1]);
	ATF_CHECK_EQ(1u, b->app->scene.n_scenes);
	ATF_CHECK_EQ(0x1234, b->app->scene.current_scene);
	ATF_CHECK((b->app->scheduler.defined & (1u << 3)) != 0);
	ATF_CHECK_EQ(10, b->app->scheduler.entries[3].scene_number);
	ATF_CHECK_EQ(5, b->db.models[0].pub.ttl);

	(void)unlink(path);
}

/* ================================================================
 * Key Refresh survives a mid-refresh restart (security-critical): the store
 * carries BOTH keys + the phase, so a node that crashes between NetKey Update
 * and the finish resumes in the correct phase with the new key intact - it does
 * not lose the new key or revert to the old (MshPRT_v1.1 Section 3.11.4).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(key_refresh_survives_restart);
ATF_TC_BODY(key_refresh_survives_restart, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	MESH_HEAP(struct meshd_node, c);
	struct meshd_persist ps;
	struct meshd_netkey_entry *e;
	const char *path = "meshd_kr.state";
	uint8_t new_nid, enc[16], priv[16], p = 0x00;

	fresh_node(a);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));

	/* Enter Phase 1 (NetKey Update) and persist mid-refresh. */
	ATF_REQUIRE_EQ(0, meshd_kr_begin(a, g_newkey));
	ATF_REQUIRE_EQ(MESH_CFG_KR_PHASE_1, meshd_kr_phase(a));
	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, a));

	/* Crash + restart: Phase 1 and BOTH keys must come back. */
	fresh_node(b);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, b));
	ATF_CHECK_EQ(MESH_CFG_KR_PHASE_1, meshd_kr_phase(b));
	ATF_CHECK_EQ(1, b->self->have_new_key);
	e = db_netkey(b, b->netkey_index);
	ATF_REQUIRE(e != NULL);
	ATF_CHECK_EQ(1, e->has_new_key);
	ATF_CHECK_EQ(0, memcmp(e->key, g_netkey, 16));		/* old key kept */
	ATF_CHECK_EQ(0, memcmp(e->new_key, g_newkey, 16));	/* new key kept */
	/* Phase 1 still transmits with the OLD key. */
	ATF_CHECK_EQ(0, memcmp(b->self->netkey, g_netkey, 16));
	ATF_CHECK_EQ(MESH_KR_KEY_OLD, mesh_kr_tx_key(&b->self->kr));

	/* Advance to Phase 2 and persist; a restart must resume TX on the new key. */
	ATF_REQUIRE_EQ(0, meshd_kr_advance(a));
	ATF_REQUIRE_EQ(MESH_CFG_KR_PHASE_2, meshd_kr_phase(a));
	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, a));

	fresh_node(c);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, c));
	ATF_CHECK_EQ(MESH_CFG_KR_PHASE_2, meshd_kr_phase(c));
	ATF_CHECK_EQ(1, c->self->have_new_key);
	ATF_CHECK_EQ_MSG(MESH_KR_KEY_NEW, mesh_kr_tx_key(&c->self->kr),
	    "a Phase-2 node resumes transmitting on the new key after reload");
	ATF_REQUIRE_EQ(0, mesh_k2(g_newkey, &p, 1, &new_nid, enc, priv));
	ATF_CHECK_EQ(new_nid, c->self->new_nid);

	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(secondary_key_refresh_survives_restart);
ATF_TC_BODY(secondary_key_refresh_survives_restart, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_persist ps;
	struct meshd_netkey_entry *e;
	struct mesh_sim_subnet_key *subnet = NULL;
	const char *path = "meshd_secondary_kr.state";
	size_t i;

	fresh_node(a);
	e = &a->db.netkeys[1];
	memset(e, 0, sizeof(*e));
	e->valid = 1;
	e->net_idx = 1;
	memcpy(e->key, g_appkey, 16);
	e->kr_phase = MESH_CFG_KR_PHASE_2;
	e->has_new_key = 1;
	memcpy(e->new_key, g_newkey, 16);
	ATF_REQUIRE_EQ(0, mesh_sim_add_subnet(a->self, 1, g_appkey));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_begin(a->self, 1,
	    g_newkey));
	ATF_REQUIRE_EQ(0, mesh_sim_subnet_key_refresh_advance(a->self, 1));
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, a));

	fresh_node(b);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, b));
	e = db_netkey(b, 1);
	ATF_REQUIRE(e != NULL);
	ATF_CHECK_EQ(MESH_CFG_KR_PHASE_2, e->kr_phase);
	ATF_CHECK_EQ(1, e->has_new_key);
	ATF_CHECK_EQ(0, memcmp(g_appkey, e->key, 16));
	ATF_CHECK_EQ(0, memcmp(g_newkey, e->new_key, 16));
	for (i = 0; i < b->self->n_subnets; i++)
		if (b->self->subnets[i].valid &&
		    b->self->subnets[i].net_idx == 1)
			subnet = &b->self->subnets[i];
	ATF_REQUIRE(subnet != NULL);
	ATF_CHECK_EQ(MESH_KR_PHASE_2, mesh_kr_phase(&subnet->kr));
	ATF_CHECK_EQ(MESH_KR_KEY_NEW, mesh_kr_tx_key(&subnet->kr));
	ATF_CHECK_EQ(1, subnet->have_new_key);
	ATF_CHECK_EQ(0, memcmp(g_newkey, subnet->new_netkey, 16));

	(void)unlink(path);
}

/* ================================================================
 * CRC / version gating and missing-store handling.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(store_integrity_gating);
ATF_TC_BODY(store_integrity_gating, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_persist ps;
	const char *path = "meshd_gate.state";
	FILE *f;
	long sz;
	uint8_t byte;

	fresh_node(a);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));
	ATF_REQUIRE_EQ(1, meshd_persist_seq_reserve(&ps, a));

	/* Current stores load cleanly. */
	fresh_node(b);
	meshd_persist_init(&ps, path, 100);
	ATF_CHECK_EQ(0, meshd_persist_load(&ps, b));

	/* Schema version 0 and future versions are never trusted. */
	save_fresh_store(&ps, a, path);
	store_set_version(path, 0);
	fresh_node(b);
	meshd_persist_init(&ps, path, 100);
	ATF_CHECK_EQ(-1, meshd_persist_load(&ps, b));

	save_fresh_store(&ps, a, path);
	store_set_version(path, 0xffff);
	fresh_node(b);
	meshd_persist_init(&ps, path, 100);
	ATF_CHECK_EQ(-1, meshd_persist_load(&ps, b));

	save_fresh_store(&ps, a, path);

	/* Corrupt one payload byte: the CRC must fail the load. */
	f = fopen(path, "r+b");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE_EQ(0, fseek(f, 0, SEEK_END));
	sz = ftell(f);
	ATF_REQUIRE(sz > 4);
	ATF_REQUIRE_EQ(0, fseek(f, sz - 1, SEEK_SET));
	ATF_REQUIRE_EQ(1, fread(&byte, 1, 1, f));
	byte ^= 0xFF;
	ATF_REQUIRE_EQ(0, fseek(f, sz - 1, SEEK_SET));
	ATF_REQUIRE_EQ(1, fwrite(&byte, 1, 1, f));
	ATF_REQUIRE_EQ(0, fclose(f));

	fresh_node(b);
	meshd_persist_init(&ps, path, 100);
	ATF_CHECK_EQ(-1, meshd_persist_load(&ps, b));

	/* Bad magic is rejected too. */
	f = fopen(path, "r+b");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE_EQ(0, fseek(f, 0, SEEK_SET));
	byte = 'X';
	ATF_REQUIRE_EQ(1, fwrite(&byte, 1, 1, f));
	ATF_REQUIRE_EQ(0, fclose(f));
	ATF_CHECK_EQ(-1, meshd_persist_load(&ps, b));

	/* Removing the store makes load report a fresh node. */
	ATF_REQUIRE_EQ(0, unlink(path));
	ATF_CHECK_EQ(1, meshd_persist_load(&ps, b));

	/* A symlink/open-policy failure is corruption, never a fresh identity. */
	ATF_REQUIRE_EQ(0, symlink("meshd_gate.target", path));
	ATF_CHECK_EQ(-1, meshd_persist_load(&ps, b));
	ATF_REQUIRE_EQ(0, unlink(path));
}

/* ================================================================
 * Clock tick advances the IV Update state machine at the expected `now`.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(clock_tick_drives_iv_update);
ATF_TC_BODY(clock_tick_drives_iv_update, tc)
{
	MESH_HEAP(struct meshd_node, a);
	/*
	 * The IV Update 96-hour dwell is measured against the wall clock
	 * (CLOCK_REALTIME seconds), which meshd_node_tick seeds into the sim so
	 * time-in-state survives a daemon restart even though the tick's own
	 * now_ms is the monotonic clock (Sections 3.10.5 / 3.11.5).  We drive
	 * the transitions by positioning the state machine's entered_time
	 * relative to that wall clock, not by the synthetic tick now_ms.
	 */
	const uint64_t far_future = (uint64_t)1 << 40;	/* > any real wall time */
	int iv_changed;

	fresh_node(a);
	a->self->seq = MESH_IV_SEQ_TRIGGER;	/* SEQ exhausted: update is due */

	/* Entered_time in the future: the wall clock cannot have dwelled yet,
	 * so no transition occurs however far the tick's now_ms is advanced. */
	mesh_iv_init(&a->self->iv, 0, far_future);
	ATF_REQUIRE_EQ(0, meshd_node_tick(a,
	    MESH_IV_MIN_DWELL_SECS * 1000ULL / 2, &iv_changed));
	ATF_CHECK_EQ(0u, meshd_node_iv(a));
	ATF_CHECK_EQ(MESH_IV_NORMAL, a->self->iv.state);
	ATF_CHECK_EQ(0, iv_changed);

	/* Entered_time in the past: the dwell is satisfied, so the update
	 * BEGINS (index n -> n+1, In Progress). */
	mesh_iv_init(&a->self->iv, 0, 0);
	ATF_REQUIRE_EQ(0, meshd_node_tick(a,
	    MESH_IV_MIN_DWELL_SECS * 1000ULL, &iv_changed));
	ATF_CHECK_EQ(1u, meshd_node_iv(a));
	ATF_CHECK_EQ(MESH_IV_UPDATE_IN_PROGRESS, a->self->iv.state);
	ATF_CHECK_EQ(1, iv_changed);

	/* A full dwell later the update COMPLETES: back to Normal, SEQ reset. */
	a->self->iv.entered_time = 0;
	ATF_REQUIRE_EQ(0, meshd_node_tick(a,
	    2 * MESH_IV_MIN_DWELL_SECS * 1000ULL, &iv_changed));
	ATF_CHECK_EQ(MESH_IV_NORMAL, a->self->iv.state);
	ATF_CHECK_EQ(1u, meshd_node_iv(a));
	ATF_CHECK_EQ(0u, meshd_node_seq(a));
	ATF_CHECK_EQ(1, iv_changed);
}

ATF_TC_WITHOUT_HEAD(transition_snapshot_restores_steady);
ATF_TC_BODY(transition_snapshot_restores_steady, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_persist ps;
	const char *path = "meshd_transition.state";
	int changed;

	(void)unlink(path);
	fresh_node(a);
	ATF_REQUIRE_EQ(0,
	    mesh_light_lightness_set_actual(&a->app->lightness, 32768));
	mesh_transition_start_ms(&a->app->lightness.transition, 32768, 33768,
	    1000, 0, 0);
	a->sim.now_ms = 500;
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, a));
	ATF_CHECK_EQ(500, a->app->level.present);

	fresh_node(b);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, b));
	ATF_CHECK_EQ(500, b->app->level.present);
	ATF_CHECK_EQ(33268, b->app->lightness.actual);
	ATF_CHECK(!b->app->lightness.transition.active);
	ATF_REQUIRE_EQ(0, meshd_node_tick(b, 5000, &changed));
	ATF_CHECK_EQ(500, b->app->level.present);
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(dirty_debounce_and_binding_reload);
ATF_TC_BODY(dirty_debounce_and_binding_reload, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_persist ps;
	const char *path = "meshd_dirty.state";

	(void)unlink(path);
	fresh_node(a);
	mesh_gen_level_srv_set_present(&a->app->level, 1234);
	a->app->ctl.temperature = 3000;
	a->app->hsl.hue = 4000;
	a->app->hsl.saturation = 5000;
	meshd_persist_init(&ps, path, 100);
	meshd_persist_mark_dirty(&ps, 1000);
	ATF_CHECK_EQ(0, meshd_persist_flush(&ps, a, 1200, 0));
	ATF_CHECK_EQ(-1, access(path, F_OK));
	ATF_REQUIRE_EQ(1, meshd_persist_flush(&ps, a, 1500, 0));
	ATF_CHECK_EQ(0, ps.dirty);

	fresh_node(b);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, b));
	ATF_CHECK_EQ(1234, b->app->level.present);
	ATF_CHECK_EQ((uint16_t)(1234 + 32768), b->app->lightness.actual);
	ATF_CHECK_EQ(b->app->lightness.actual, b->app->power_level.actual);
	ATF_CHECK_EQ(MESH_GEN_ON, b->app->onoff.present);
	ATF_CHECK_EQ((int16_t)((((uint32_t)3000 - 0x0320) * 65535 +
	    (0x4e20 - 0x0320) / 2) / (0x4e20 - 0x0320) - 32768),
	    b->app->ctl_level.present);
	ATF_CHECK_EQ((int16_t)(4000 - 32768), b->app->hue_level.present);
	ATF_CHECK_EQ((int16_t)(5000 - 32768), b->app->sat_level.present);
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(device_key_and_manager_atomic_roundtrip);
ATF_TC_BODY(device_key_and_manager_atomic_roundtrip, tc)
{
	static const uint8_t uuid[16] = {
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
	};
	static const uint8_t remote_devkey[16] = {
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
	};
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_persist ps;
	const struct mesh_mgr_node *remote;
	const char *path = "meshd_atomic_manager.state";
	uint8_t saved_devkey[16];

	(void)unlink(path);
	fresh_node(a);
	memcpy(saved_devkey, a->local_devkey, sizeof(saved_devkey));
	a->mgr = calloc(1, sizeof(*a->mgr));
	ATF_REQUIRE(a->mgr != NULL);
	memcpy(a->mgr->netkey, a->self->netkey, 16);
	memcpy(a->mgr->appkey, g_appkey, 16);
	memcpy(a->mgr->self_devkey, a->local_devkey, 16);
	a->mgr->netkey_index = a->netkey_index;
	a->mgr->appkey_index = a->appkey_index;
	a->mgr->iv_index = mesh_iv_tx_index(&a->self->iv);
	a->mgr->self_addr = a->self->addr;
	a->mgr->self_elements = a->self->n_elements;
	a->mgr->next_unicast = 0x0200;
	ATF_REQUIRE(mesh_mgr_add_node(a->mgr, uuid, 0x0200, 2,
	    remote_devkey, 12345) != NULL);
	a->mgr_active = 1;

	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, a));

	/* The node store alone is the commit record; no manager mirror is needed. */
	fresh_node(b);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, b));
	ATF_CHECK_EQ(0, memcmp(saved_devkey, b->local_devkey, 16));
	ATF_REQUIRE_EQ(1, b->mgr_active);
	ATF_REQUIRE(b->mgr != NULL);
	ATF_CHECK_EQ(meshd_node_seq(b), b->mgr->seq);
	ATF_CHECK_EQ(0, memcmp(b->self->netkey, b->mgr->netkey, 16));
	ATF_CHECK_EQ(0, memcmp(b->local_devkey, b->mgr->self_devkey, 16));
	remote = mesh_mgr_node_at(b->mgr, 0);
	ATF_REQUIRE(remote != NULL);
	ATF_CHECK_EQ(0x0200, remote->addr);
	ATF_CHECK_EQ(0, memcmp(remote_devkey, remote->devkey, 16));
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(write_error_retry_and_forced_flush);
ATF_TC_BODY(write_error_retry_and_forced_flush, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_persist ps;
	char dir[] = "meshd-retry.XXXXXX";
	char path[PATH_MAX];

	if (geteuid() == 0)
		atf_tc_skip("root bypasses directory write permissions");
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	snprintf(path, sizeof(path), "%s/node.state", dir);
	fresh_node(nd);
	meshd_persist_init(&ps, path, 100);
	meshd_persist_mark_dirty(&ps, 100);
	ATF_REQUIRE_EQ(0, chmod(dir, 0500));
	ATF_CHECK_EQ(-1, meshd_persist_flush(&ps, nd, 100, 1));
	ATF_CHECK_EQ(1, ps.dirty);
	ATF_CHECK_EQ(1, ps.write_errors);
	ATF_CHECK(ps.last_errno != 0);
	ATF_CHECK_EQ(100 + MESHD_PERSIST_RETRY_MS, ps.due_ms);
	ATF_REQUIRE_EQ(0, chmod(dir, 0700));
	ATF_CHECK_EQ(0, meshd_persist_flush(&ps, nd,
	    ps.due_ms - 1, 0));
	ATF_CHECK_EQ(1, meshd_persist_flush(&ps, nd, ps.due_ms, 0));
	ATF_CHECK_EQ(0, ps.dirty);
	ATF_CHECK_EQ(0, ps.last_errno);

	/* Force bypasses the normal debounce deadline. */
	meshd_persist_mark_dirty(&ps, 10000);
	ATF_CHECK_EQ(1, meshd_persist_flush(&ps, nd, 10000, 1));
	ATF_CHECK_EQ(0, ps.dirty);
	(void)unlink(path);
	(void)rmdir(dir);
}

ATF_TC_WITHOUT_HEAD(decoder_validation_sweep);
ATF_TC_BODY(decoder_validation_sweep, tc)
{
	MESH_HEAP(struct meshd_node, nd);

	(void)tc;
	fresh_node(nd);
	ATF_CHECK(ptap_meshd_persist_decode_sweep(nd) >= 0);
	meshd_node_fini(nd);
}

/* ================================================================
 * Round-3 finding 1: a FAILED SEQ reservation must not leave a zero
 * high-water behind for the live IV epoch.
 *
 * meshd.c's main loop used to pre-zero ps.reserved before every
 * meshd_persist_seq_reserve() call.  On a save failure seq_reserve restores
 * the value it found - which the loop had just zeroed - and the flush right
 * after it (and the shutdown force-flush) then committed a high-water of 0 for
 * the LIVE epoch, so a restart re-aired SEQ 1,2,3 under the same NetKey and IV
 * Index.  This pins the invariant the pre-zeroing broke: a failed reservation
 * leaves the previous high-water intact, and a subsequent successful save
 * never writes a mark below the live SEQ.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(reserve_failure_keeps_high_water);
ATF_TC_BODY(reserve_failure_keeps_high_water, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_persist ps, ps2;
	char dir[] = "meshd-reserve.XXXXXX";
	char path[PATH_MAX];
	uint32_t good_hw, good_txiv;

	(void)tc;
	if (geteuid() == 0)
		atf_tc_skip("root bypasses directory write permissions");
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	snprintf(path, sizeof(path), "%s/node.state", dir);

	fresh_node(a);
	meshd_persist_init(&ps, path, 256);
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));
	ATF_REQUIRE_EQ(1, meshd_persist_seq_reserve(&ps, a));
	good_hw = ps.reserved;
	good_txiv = ps.reserved_txiv;
	ATF_REQUIRE(good_hw != 0);

	/* Burn past the guard so the next call must actually persist. */
	a->self->seq = good_hw - 1;

	/* Make the store unwritable: the reservation fails. */
	ATF_REQUIRE_EQ(0, chmod(dir, 0500));
	ATF_CHECK_EQ(-1, meshd_persist_seq_reserve(&ps, a));
	/* The previous high-water is restored, NOT zeroed. */
	ATF_CHECK_EQ(good_hw, ps.reserved);
	ATF_CHECK_EQ(good_txiv, ps.reserved_txiv);

	/* A flush attempted in that state also fails and stays dirty. */
	meshd_persist_mark_dirty(&ps, 100);
	ATF_CHECK_EQ(-1, meshd_persist_flush(&ps, a, 100, 1));
	ATF_CHECK_EQ(1, ps.dirty);
	ATF_REQUIRE_EQ(0, chmod(dir, 0700));

	/* Once writable again the committed mark still leads the live SEQ. */
	ATF_REQUIRE(meshd_persist_seq_reserve(&ps, a) >= 0);
	ATF_CHECK(ps.reserved >= a->self->seq + MESHD_PERSIST_SEQ_GUARD);
	/* seq_reserve() already saved, so the flush is a clean no-op. */
	ATF_REQUIRE(meshd_persist_flush(&ps, a, 200, 1) >= 0);

	/* A restart resumes at or above the last SEQ ever used. */
	fresh_node(b);
	meshd_persist_init(&ps2, path, 256);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps2, b));
	ATF_CHECK(b->self->seq >= good_hw);
	ATF_CHECK(ps2.reserved != 0);

	meshd_node_fini(a);
	meshd_node_fini(b);
	(void)unlink(path);
	(void)rmdir(dir);
}

/* ================================================================
 * Round-3 finding 5: the config-derived Device UUID must survive a restart.
 *
 * device_uuid/have_device_uuid are not in the store and were not carried
 * across meshd_persist_load()'s `*nd = tmp` copy, so after the first restart
 * the node could never emit an Unprovisioned Device Beacon again and was
 * permanently un-provisionable.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(device_uuid_survives_restart);
ATF_TC_BODY(device_uuid_survives_restart, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_config cfg;
	struct meshd_persist ps, ps2;
	const char *path = "meshd_uuid.state";
	uint8_t uuid[16];
	size_t i;

	(void)tc;
	for (i = 0; i < sizeof(uuid); i++)
		uuid[i] = (uint8_t)(0x40 + i);

	base_config(&cfg);
	memcpy(cfg.device_uuid, uuid, sizeof(uuid));
	cfg.have_uuid = 1;
	ATF_REQUIRE_EQ(0, meshd_node_init(a, &cfg));
	ATF_CHECK_EQ(1, a->have_device_uuid);

	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));
	ATF_REQUIRE_EQ(1, meshd_persist_seq_reserve(&ps, a));

	/* Restart: init from the same config, then reload the store. */
	ATF_REQUIRE_EQ(0, meshd_node_init(b, &cfg));
	meshd_persist_init(&ps2, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps2, b));
	ATF_CHECK_EQ(1, b->have_device_uuid);
	ATF_CHECK_EQ(0, memcmp(b->device_uuid, uuid, sizeof(uuid)));

	meshd_node_fini(a);
	meshd_node_fini(b);
	(void)unlink(path);
}

/* ================================================================
 * Round-3 findings 9 + 14 (persist version 10 -> 11): the per-subnet Directed
 * Forwarding sub-states and the Mesh 1.1 Configuration Server states are now
 * serialized.  All of them were previously set, echoed in their Status and
 * then silently forgotten across a restart.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(v11_states_roundtrip);
ATF_TC_BODY(v11_states_roundtrip, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_persist ps, ps2;
	struct meshd_netkey_entry *nk;
	const char *path = "meshd_v11.state";

	(void)tc;
	fresh_node(a);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(1, meshd_persist_load(&ps, a));

	nk = db_netkey(a, 0x000);
	ATF_REQUIRE(nk != NULL);
	nk->df.control.directed_forwarding = 1;
	nk->df.control.directed_relay = 0;
	nk->df.control.directed_proxy = 1;
	nk->df.control.directed_proxy_use_directed_default = 1;
	nk->df.control.directed_friend = 0;
	nk->df.metric.metric_type = MESH_DF_METRIC_NODE_COUNT;
	nk->df.metric.lifetime = MESH_DF_LIFETIME_24_HOUR;
	nk->df.lanes.wanted_lanes = 3;
	nk->df.two_way.two_way_path = 1;
	nk->df.echo.unicast_echo_interval = 0x14;
	nk->df.echo.multicast_echo_interval = 0x28;

	a->df.net_transmit.count = 2;
	a->df.net_transmit.interval_steps = 5;
	a->df.relay_retransmit.count = 1;
	a->df.relay_retransmit.interval_steps = 9;

	a->db.sar_tx.seg_interval_step = 6;
	a->db.sar_tx.unicast_retrans_count = 5;
	a->db.sar_tx.unicast_retrans_without_progress_count = 4;
	a->db.sar_tx.unicast_retrans_interval_step = 3;
	a->db.sar_tx.unicast_retrans_interval_increment = 2;
	a->db.sar_tx.multicast_retrans_count = 1;
	a->db.sar_tx.multicast_retrans_interval_step = 7;
	a->db.sar_rx.segments_threshold = 9;
	a->db.sar_rx.ack_delay_increment = 3;
	a->db.sar_rx.discard_timeout = 5;
	a->db.sar_rx.rx_segment_interval_step = 4;
	a->db.sar_rx.ack_retrans_count = 2;
	a->db.od_priv_proxy = 0x0a;
	a->db.priv_beacon = 1;
	a->db.priv_beacon_random_steps = 0x1e;
	a->db.priv_gatt_proxy = 1;
	a->db.sol_pdu_rpl_last.range_start = 0x0102;
	a->db.sol_pdu_rpl_last.range_length = 4;

	meshd_persist_mark_dirty(&ps, 100);
	ATF_REQUIRE_EQ(1, meshd_persist_flush(&ps, a, 100, 1));

	fresh_node(b);
	meshd_persist_init(&ps2, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps2, b));

	nk = db_netkey(b, 0x000);
	ATF_REQUIRE(nk != NULL);
	ATF_CHECK_EQ(1, nk->df.control.directed_forwarding);
	ATF_CHECK_EQ(0, nk->df.control.directed_relay);
	ATF_CHECK_EQ(1, nk->df.control.directed_proxy);
	ATF_CHECK_EQ(1, nk->df.control.directed_proxy_use_directed_default);
	ATF_CHECK_EQ(0, nk->df.control.directed_friend);
	ATF_CHECK_EQ(0x000, nk->df.control.net_idx);
	ATF_CHECK_EQ(MESH_DF_LIFETIME_24_HOUR, nk->df.metric.lifetime);
	ATF_CHECK_EQ(3, nk->df.lanes.wanted_lanes);
	ATF_CHECK_EQ(1, nk->df.two_way.two_way_path);
	ATF_CHECK_EQ(0x14, nk->df.echo.unicast_echo_interval);
	ATF_CHECK_EQ(0x28, nk->df.echo.multicast_echo_interval);
	/* The engine is re-derived from the restored per-subnet control. */
	ATF_CHECK_EQ(1, b->self->df_enabled);
	ATF_CHECK_EQ(0, b->self->df_feat.directed_relay);
	ATF_CHECK_EQ(1, b->self->df_feat.directed_proxy);

	ATF_CHECK_EQ(2, b->df.net_transmit.count);
	ATF_CHECK_EQ(5, b->df.net_transmit.interval_steps);
	ATF_CHECK_EQ(1, b->df.relay_retransmit.count);
	ATF_CHECK_EQ(9, b->df.relay_retransmit.interval_steps);

	ATF_CHECK_EQ(6, b->db.sar_tx.seg_interval_step);
	ATF_CHECK_EQ(5, b->db.sar_tx.unicast_retrans_count);
	ATF_CHECK_EQ(4, b->db.sar_tx.unicast_retrans_without_progress_count);
	ATF_CHECK_EQ(3, b->db.sar_tx.unicast_retrans_interval_step);
	ATF_CHECK_EQ(2, b->db.sar_tx.unicast_retrans_interval_increment);
	ATF_CHECK_EQ(1, b->db.sar_tx.multicast_retrans_count);
	ATF_CHECK_EQ(7, b->db.sar_tx.multicast_retrans_interval_step);
	ATF_CHECK_EQ(9, b->db.sar_rx.segments_threshold);
	ATF_CHECK_EQ(3, b->db.sar_rx.ack_delay_increment);
	ATF_CHECK_EQ(5, b->db.sar_rx.discard_timeout);
	ATF_CHECK_EQ(4, b->db.sar_rx.rx_segment_interval_step);
	ATF_CHECK_EQ(2, b->db.sar_rx.ack_retrans_count);
	ATF_CHECK_EQ(0x0a, b->db.od_priv_proxy);
	ATF_CHECK_EQ(1, b->db.priv_beacon);
	ATF_CHECK_EQ(0x1e, b->db.priv_beacon_random_steps);
	ATF_CHECK_EQ(1, b->db.priv_gatt_proxy);
	ATF_CHECK_EQ(0x0102, b->db.sol_pdu_rpl_last.range_start);
	ATF_CHECK_EQ(4, b->db.sol_pdu_rpl_last.range_length);
	/*
	 * The restored SAR states drive the engine's real SAR timing.
	 *
	 * EXPECTATION CHANGE, flagged: this used to assert three DERIVED
	 * millisecond values (sar_retrans_ms / sar_retries / sar_discard_ms),
	 * which were all the engine kept.  The engine now holds the SAR
	 * Transmitter and SAR Receiver composite states in their wire encoding
	 * (MshPRT_v1.1.1 Sections 4.2.48 / 4.2.49), because a Get must return
	 * exactly what a Set wrote, and derives every timer from them.  The
	 * assertion is therefore restated over all twelve sub-states rather
	 * than three derived numbers - strictly stronger, and it still checks
	 * exactly what it checked before: that a restore reaches the engine.
	 */
	ATF_CHECK_EQ(6, b->self->sar_tx_state.seg_interval_step);
	ATF_CHECK_EQ(5, b->self->sar_tx_state.unicast_retrans_count);
	ATF_CHECK_EQ(4,
	    b->self->sar_tx_state.unicast_retrans_without_progress_count);
	ATF_CHECK_EQ(3, b->self->sar_tx_state.unicast_retrans_interval_step);
	ATF_CHECK_EQ(2,
	    b->self->sar_tx_state.unicast_retrans_interval_increment);
	ATF_CHECK_EQ(1, b->self->sar_tx_state.multicast_retrans_count);
	ATF_CHECK_EQ(7, b->self->sar_tx_state.multicast_retrans_interval_step);
	ATF_CHECK_EQ(9, b->self->sar_rx_state.segments_threshold);
	ATF_CHECK_EQ(3, b->self->sar_rx_state.ack_delay_increment);
	ATF_CHECK_EQ(5, b->self->sar_rx_state.discard_timeout);
	ATF_CHECK_EQ(4, b->self->sar_rx_state.rx_segment_interval_step);
	ATF_CHECK_EQ(2, b->self->sar_rx_state.ack_retrans_count);

	meshd_node_fini(a);
	meshd_node_fini(b);
	(void)unlink(path);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, seq_block_no_regress);
	ATF_TP_ADD_TC(tp, seq_reserve_ahead_invariant);
	ATF_TP_ADD_TC(tp, seq_reserve_iv_epoch);
	ATF_TP_ADD_TC(tp, seq_reserve_iv_completion);
	ATF_TP_ADD_TC(tp, provision_local_seq_floor);
	ATF_TP_ADD_TC(tp, provision_local_iv_epoch);
	ATF_TP_ADD_TC(tp, appkey_index_and_staged_key_roundtrip);
	ATF_TP_ADD_TC(tp, rpl_survives_restart);
	ATF_TP_ADD_TC(tp, node_state_roundtrip);
	ATF_TP_ADD_TC(tp, key_refresh_survives_restart);
	ATF_TP_ADD_TC(tp, secondary_key_refresh_survives_restart);
	ATF_TP_ADD_TC(tp, store_integrity_gating);
	ATF_TP_ADD_TC(tp, clock_tick_drives_iv_update);
	ATF_TP_ADD_TC(tp, transition_snapshot_restores_steady);
	ATF_TP_ADD_TC(tp, dirty_debounce_and_binding_reload);
	ATF_TP_ADD_TC(tp, device_key_and_manager_atomic_roundtrip);
	ATF_TP_ADD_TC(tp, write_error_retry_and_forced_flush);
	ATF_TP_ADD_TC(tp, decoder_validation_sweep);
	ATF_TP_ADD_TC(tp, reserve_failure_keeps_high_water);
	ATF_TP_ADD_TC(tp, device_uuid_survives_restart);
	ATF_TP_ADD_TC(tp, v11_states_roundtrip);

	return (atf_no_error());
}
