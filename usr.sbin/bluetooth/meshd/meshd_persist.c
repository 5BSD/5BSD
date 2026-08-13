/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * meshd persistent node-state store.  See meshd_persist.h for the store role,
 * the SEQ block-reservation scheme and the spec citations (MshPRT_v1.1 Sections
 * 3.8.4, 3.8.8, 3.10.5).
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rand.h>

#include "meshd.h"
#include "meshd_persist.h"

#define	MESHD_PERSIST_MAGIC	"MSHNODE\1"	/* 8 octets */
#define	MESHD_PERSIST_MAGIC_LEN	8
#define	MESHD_PERSIST_VERSION	6
#define	MESHD_PERSIST_HDR_LEN	20		/* magic..crc32 inclusive */

/* Version 6 on-disk feature octet; these are store fields, not wire bits. */
#define MESHD_PERSIST_FEAT_RELAY	0x01
#define MESHD_PERSIST_FEAT_PROXY	0x02
#define MESHD_PERSIST_FEAT_FRIEND	0x04
#define MESHD_PERSIST_FEAT_BEACON	0x08

/*
 * Comfortably bounds the fixed node header + every counted section.  The model
 * table alone can exceed 8 KiB when all bindings, subscriptions and virtual
 * labels are present, so keep enough headroom for the full current schema.
 */
#define	MESHD_PERSIST_BODY_MAX	65536

static int fsync_parent_dir(const char *path);

static int
persist_unicast_block_valid(uint16_t addr, uint8_t elements)
{
	uint32_t end;

	end = (uint32_t)addr + elements;
	return (meshd_addr_is_unicast(addr) && elements != 0 &&
	    end <= 0x8000u);
}

static int
persist_blocks_overlap(uint16_t a, uint8_t an, uint16_t b, uint8_t bn)
{

	return ((uint32_t)a < (uint32_t)b + bn &&
	    (uint32_t)b < (uint32_t)a + an);
}

/* ================================================================
 * CRC32 (IEEE 802.3, reflected polynomial 0xEDB88320) and framed I/O,
 * matching the mesh_manager / blued_persist store format.
 * ================================================================ */

static uint32_t
persist_crc32(uint32_t crc, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t i;
	int k;

	crc = ~crc;
	for (i = 0; i < len; i++) {
		crc ^= p[i];
		for (k = 0; k < 8; k++)
			crc = (crc >> 1) ^ (0xEDB88320u & (~(crc & 1) + 1));
	}
	return (~crc);
}

static int
write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t off = 0;
	ssize_t n;

	while (off < len) {
		n = write(fd, p + off, len - off);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return (-1);
		off += (size_t)n;
	}
	return (0);
}

static int
read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t off = 0;
	ssize_t n;

	while (off < len) {
		n = read(fd, p + off, len - off);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return (-1);
		off += (size_t)n;
	}
	return (0);
}

/* ----------------------------------------------------------------
 * Bounded little-endian cursor.  A writer that overflows sets err; a reader
 * that underruns sets err.  Every accessor checks err first, so a single test
 * after a run of calls detects any fault.
 * ---------------------------------------------------------------- */
struct cur {
	uint8_t		*buf;
	const uint8_t	*rbuf;
	size_t		 len;	/* capacity (writer) or available (reader) */
	size_t		 off;
	int		 err;
};

static void
put_bytes(struct cur *c, const void *v, size_t n)
{

	if (c->err || c->off + n > c->len) {
		c->err = 1;
		return;
	}
	memcpy(c->buf + c->off, v, n);
	c->off += n;
}

static void
put_u8(struct cur *c, uint8_t v)
{

	put_bytes(c, &v, 1);
}

static void
put_u16(struct cur *c, uint16_t v)
{
	uint8_t b[2];

	le16enc(b, v);
	put_bytes(c, b, 2);
}

static void
put_u32(struct cur *c, uint32_t v)
{
	uint8_t b[4];

	le32enc(b, v);
	put_bytes(c, b, 4);
}

static void
put_u64(struct cur *c, uint64_t v)
{
	uint8_t b[8];

	le64enc(b, v);
	put_bytes(c, b, 8);
}

static void
get_bytes(struct cur *c, void *v, size_t n)
{

	if (c->err || c->off + n > c->len) {
		c->err = 1;
		memset(v, 0, n);
		return;
	}
	memcpy(v, c->rbuf + c->off, n);
	c->off += n;
}

static uint8_t
get_u8(struct cur *c)
{
	uint8_t v;

	get_bytes(c, &v, 1);
	return (v);
}

static uint16_t
get_u16(struct cur *c)
{
	uint8_t b[2];

	get_bytes(c, b, 2);
	return (le16dec(b));
}

static uint32_t
get_u32(struct cur *c)
{
	uint8_t b[4];

	get_bytes(c, b, 4);
	return (le32dec(b));
}

static uint64_t
get_u64(struct cur *c)
{
	uint8_t b[8];

	get_bytes(c, b, 8);
	return (le64dec(b));
}

static int
persist_version_supported(uint16_t version)
{

	return (version >= 2 && version <= MESHD_PERSIST_VERSION);
}

static void
node_decode_init(struct meshd_node *nd)
{

	memset(nd, 0, sizeof(*nd));
	nd->cid = MESHD_DEFAULT_CID;
	nd->pid = MESHD_DEFAULT_PID;
	nd->vid = MESHD_DEFAULT_VID;
	mesh_cfg_server_init(&nd->cfg);
	mesh_hlt_server_init(&nd->health, nd->cid);
}

static void
node_rehome_sim(struct meshd_node *nd, int self_index)
{
	int i;

	for (i = 0; i < nd->sim.n_nodes; i++)
		nd->sim.nodes[i].sim = &nd->sim;
	if (self_index >= 0 && self_index < nd->sim.n_nodes)
		nd->self = &nd->sim.nodes[self_index];
	else
		nd->self = NULL;
	if (nd->self != NULL) {
		nd->self->devkey_rx_arg = nd;
		nd->self->devkey_client_arg = nd;
	}
}

/* ================================================================
 * Body encode / decode.
 * ================================================================ */

/* Encode the node runtime state into *c using ps->reserved as the SEQ mark. */
static void
encode_body(struct cur *c, const struct meshd_persist *ps,
    const struct meshd_node *nd)
{
	const struct mesh_node *self = nd->self;
	uint8_t features;
	size_t i, j, nvalid;

	/* Fixed node header. */
	put_u16(c, nd->addr);
	put_u16(c, nd->netkey_index);
	put_u8(c, (uint8_t)(nd->provisioned ? 1 : 0));
	put_u8(c, nd->cfg.default_ttl);
	features = 0;
	if (nd->cfg.relay == 1)
		features |= MESHD_PERSIST_FEAT_RELAY;
	if (nd->cfg.gatt_proxy == 1)
		features |= MESHD_PERSIST_FEAT_PROXY;
	if (nd->cfg.friend == 1)
		features |= MESHD_PERSIST_FEAT_FRIEND;
	if (nd->cfg.beacon == 1)
		features |= MESHD_PERSIST_FEAT_BEACON;
	put_u8(c, features);
	put_u16(c, nd->cid);
	put_u16(c, nd->pid);
	put_u16(c, nd->vid);

	/* SEQ high-water (the reservation mark) + IV Index / phase. */
	put_u32(c, ps->reserved);
	put_u32(c, self->iv.iv_index);
	put_u8(c, (uint8_t)self->iv.state);
	put_u64(c, self->iv.entered_time);

	put_u8(c, nd->db.net_transmit);
	put_u8(c, nd->cfg.relay_retransmit);
	put_u32(c, nd->db.lpn_poll_timeout);
	put_bytes(c, self->netkey, 16);
	put_bytes(c, self->appkeys[0].key, 16);
	put_bytes(c, nd->local_devkey, sizeof(nd->local_devkey));

	/* Heartbeat publication state. */
	put_u16(c, nd->db.hb_pub.dst);
	put_u8(c, nd->db.hb_pub.count_log);
	put_u8(c, nd->db.hb_pub.period_log);
	put_u8(c, nd->db.hb_pub.ttl);
	put_u16(c, nd->db.hb_pub.features);
	put_u16(c, nd->db.hb_pub.net_idx);

	/* Subnets (NetKey list). */
	nvalid = 0;
	for (i = 0; i < MESHD_MAX_NETKEYS; i++)
		if (nd->db.netkeys[i].valid)
			nvalid++;
	put_u16(c, (uint16_t)nvalid);
	for (i = 0; i < MESHD_MAX_NETKEYS; i++) {
		const struct meshd_netkey_entry *nk = &nd->db.netkeys[i];

		if (!nk->valid)
			continue;
		put_u16(c, nk->net_idx);
		put_bytes(c, nk->key, 16);
		put_u8(c, nk->node_identity);
		/* Key Refresh phase + the held new key (both keys, mid-refresh). */
		put_u8(c, nk->kr_phase);
		put_u8(c, (uint8_t)(nk->has_new_key ? 1 : 0));
		if (nk->has_new_key)
			put_bytes(c, nk->new_key, 16);
	}

	/* Application keys. */
	nvalid = 0;
	for (i = 0; i < MESHD_MAX_APPKEYS; i++)
		if (nd->db.appkeys[i].valid)
			nvalid++;
	put_u16(c, (uint16_t)nvalid);
	for (i = 0; i < MESHD_MAX_APPKEYS; i++) {
		const struct meshd_appkey_entry *ak = &nd->db.appkeys[i];

		if (!ak->valid)
			continue;
		put_u16(c, ak->app_idx);
		put_u16(c, ak->net_idx);
		put_bytes(c, ak->key, 16);
	}

	/* Per-model configuration: bindings, subscriptions, publication. */
	put_u16(c, (uint16_t)nd->db.n_models);
	for (i = 0; i < nd->db.n_models; i++) {
		const struct meshd_model_entry *m = &nd->db.models[i];

		put_u16(c, m->elem_addr);
		put_u16(c, m->id.model_id);
		put_u16(c, m->id.company_id);
		put_u8(c, (uint8_t)(m->id.vendor ? 1 : 0));
		put_u8(c, (uint8_t)m->n_app);
		for (j = 0; j < m->n_app; j++)
			put_u16(c, m->app_idx[j]);
		put_u8(c, (uint8_t)m->n_subs);
		for (j = 0; j < m->n_subs; j++) {
			put_u16(c, m->subs[j]);
			put_u8(c, (uint8_t)(m->sub_is_va[j] ? 1 : 0));
			put_bytes(c, m->sub_label[j], MESH_LABEL_UUID_LEN);
		}
		put_u8(c, (uint8_t)(m->has_pub ? 1 : 0));
		put_u16(c, m->pub.pub_addr);
		put_u16(c, m->pub.app_idx);
		put_u8(c, m->pub.cred_flag);
		put_u8(c, m->pub.ttl);
		put_u8(c, m->pub.period);
		put_u8(c, m->pub.retransmit);
		put_u8(c, (uint8_t)(m->pub_is_va ? 1 : 0));
		put_bytes(c, m->pub_label, MESH_LABEL_UUID_LEN);
	}

	/* Replay Protection List (per-source last IV Index + SEQ). */
	nvalid = 0;
	for (i = 0; i < MESH_SIM_RPL_SIZE; i++)
		if (self->rpl_store[i].valid)
			nvalid++;
	put_u16(c, (uint16_t)nvalid);
	for (i = 0; i < MESH_SIM_RPL_SIZE; i++) {
		const struct mesh_rpl_entry *e = &self->rpl_store[i];

		if (!e->valid)
			continue;
		put_u16(c, e->src);
		put_u32(c, e->iv_index);
		put_u32(c, e->seq);
	}

	/* Nonvolatile application-model states. */
	put_u8(c, nd->app != NULL ? nd->app->onoff.present : MESH_GEN_OFF);
	put_u16(c, nd->app != NULL ? (uint16_t)nd->app->level.present : 0);
	put_u8(c, nd->app != NULL ? nd->app->dtt.transition_time : 0);
	put_u8(c, nd->app != NULL ? nd->app->power_onoff.on_power_up :
	    MESH_GEN_ONPOWERUP_RESTORE);
	put_u8(c, nd->app != NULL ? nd->app->power_onoff.last_onoff : MESH_GEN_OFF);
	/* Generic Power Level nonvolatile Actual/Last/Default/Range. */
	put_u16(c, nd->app != NULL ? nd->app->power_level.actual : 0);
	put_u16(c, nd->app != NULL ? nd->app->power_level.last : UINT16_MAX);
	put_u16(c, nd->app != NULL ? nd->app->power_level.default_power : 0);
	put_u16(c, nd->app != NULL ? nd->app->power_level.range_min : 1);
	put_u16(c, nd->app != NULL ? nd->app->power_level.range_max : UINT16_MAX);
	put_u8(c, nd->app != NULL ? nd->app->power_level.range_status : 0);
	/* Generic Location Global and Local state. */
	put_u32(c, nd->app != NULL ? (uint32_t)nd->app->location.global.latitude :
	    (uint32_t)INT32_MIN);
	put_u32(c, nd->app != NULL ? (uint32_t)nd->app->location.global.longitude :
	    (uint32_t)INT32_MIN);
	put_u16(c, nd->app != NULL ? (uint16_t)nd->app->location.global.altitude :
	    (uint16_t)INT16_MAX);
	put_u16(c, nd->app != NULL ? (uint16_t)nd->app->location.local.north :
	    (uint16_t)INT16_MIN);
	put_u16(c, nd->app != NULL ? (uint16_t)nd->app->location.local.east :
	    (uint16_t)INT16_MIN);
	put_u16(c, nd->app != NULL ? (uint16_t)nd->app->location.local.altitude :
	    (uint16_t)INT16_MAX);
	put_u8(c, nd->app != NULL ? nd->app->location.local.floor : 0xff);
	put_u16(c, nd->app != NULL ? nd->app->location.local.uncertainty : 0);

	/* Sensor registry, including nonvolatile cadence/settings and series. */
	put_u8(c, nd->app != NULL ? (uint8_t)nd->app->sensor.n_entries : 0);
	if (nd->app != NULL) for (i = 0; i < nd->app->sensor.n_entries; i++) {
		const struct mesh_sensor_entry *e = &nd->app->sensor.entries[i];
		uint8_t descriptor[8];
		(void)mesh_sensor_descriptor_encode(&e->descriptor, descriptor);
		put_bytes(c, descriptor, sizeof(descriptor));
		put_u8(c, (uint8_t)e->value.raw_len);
		put_bytes(c, e->value.raw, e->value.raw_len);
		put_u8(c, e->cadence.valid ? 1 : 0);
		if (e->cadence.valid) {
			size_t delta_len = e->cadence.trigger_type ? 2 : e->value.raw_len;
			put_u8(c, e->cadence.fast_period_divisor);
			put_u8(c, e->cadence.trigger_type);
			put_bytes(c, e->cadence.delta_down, delta_len);
			put_bytes(c, e->cadence.delta_up, delta_len);
			put_u8(c, e->cadence.min_interval);
			put_bytes(c, e->cadence.fast_low, e->value.raw_len);
			put_bytes(c, e->cadence.fast_high, e->value.raw_len);
		}
		put_u8(c, (uint8_t)e->n_settings);
		for (j = 0; j < e->n_settings; j++) {
			put_u16(c, e->settings[j].property_id);
			put_u8(c, e->settings[j].access);
			put_u8(c, (uint8_t)e->settings[j].raw_len);
			put_bytes(c, e->settings[j].raw, e->settings[j].raw_len);
		}
		put_u8(c, (uint8_t)e->n_columns);
		for (j = 0; j < e->n_columns; j++) {
			put_u8(c, (uint8_t)e->columns[j].key_len);
			put_bytes(c, e->columns[j].key, e->columns[j].key_len);
			put_u8(c, (uint8_t)e->columns[j].raw_len);
			put_bytes(c, e->columns[j].raw, e->columns[j].raw_len);
		}
	}

	/* Time state and pending zone/TAI-UTC changes. */
	{
		uint8_t wire[10], tai[5];
		struct mesh_time_state zero;
		const struct mesh_time_srv *time;
		uint64_t v;
		memset(&zero, 0, sizeof(zero)); zero.time_zone_offset = 0x40;
		time = nd->app != NULL ? &nd->app->time : NULL;
		(void)mesh_time_state_encode(time != NULL ? &time->time : &zero, wire);
		put_bytes(c, wire, sizeof(wire));
		put_u8(c, time != NULL ? time->role : 0);
		put_u8(c, time != NULL ? time->new_zone_offset : 0x40);
		v = time != NULL ? time->zone_change : 0;
		for (i = 0; i < sizeof(tai); i++) tai[i] = v >> (8 * i);
		put_bytes(c, tai, sizeof(tai));
		put_u16(c, time != NULL ? time->new_tai_utc_delta : 0);
		v = time != NULL ? time->delta_change : 0;
		for (i = 0; i < sizeof(tai); i++) tai[i] = v >> (8 * i);
		put_bytes(c, tai, sizeof(tai));
	}
	/* Light Lightness Actual/Last/Default/Range state. */
	put_u16(c, nd->app != NULL ? nd->app->lightness.actual : 0);
	put_u16(c, nd->app != NULL ? nd->app->lightness.last : UINT16_MAX);
	put_u16(c, nd->app != NULL ? nd->app->lightness.default_lightness : 0);
	put_u16(c, nd->app != NULL ? nd->app->lightness.range_min : 1);
	put_u16(c, nd->app != NULL ? nd->app->lightness.range_max : UINT16_MAX);
	put_u8(c, nd->app != NULL ? nd->app->lightness.range_status : 0);
	/* Light CTL current/default/temperature-range state. */
	put_u16(c, nd->app != NULL ? nd->app->ctl.temperature : 0x0320);
	put_u16(c, nd->app != NULL ? (uint16_t)nd->app->ctl.delta_uv : 0);
	put_u16(c, nd->app != NULL ? nd->app->ctl.default_lightness : 0);
	put_u16(c, nd->app != NULL ? nd->app->ctl.default_temperature : 0x0320);
	put_u16(c, nd->app != NULL ? (uint16_t)nd->app->ctl.default_delta_uv : 0);
	put_u16(c, nd->app != NULL ? nd->app->ctl.range_min : 0x0320);
	put_u16(c, nd->app != NULL ? nd->app->ctl.range_max : 0x4e20);
	put_u8(c, nd->app != NULL ? nd->app->ctl.range_status : 0);
	/* Light HSL current/default/range state. */
	put_u16(c, nd->app != NULL ? nd->app->hsl.hue : 0);
	put_u16(c, nd->app != NULL ? nd->app->hsl.saturation : 0);
	put_u16(c, nd->app != NULL ? nd->app->hsl.default_lightness : 0);
	put_u16(c, nd->app != NULL ? nd->app->hsl.default_hue : 0);
	put_u16(c, nd->app != NULL ? nd->app->hsl.default_saturation : 0);
	put_u16(c, nd->app != NULL ? nd->app->hsl.hue_min : 0);
	put_u16(c, nd->app != NULL ? nd->app->hsl.hue_max : UINT16_MAX);
	put_u16(c, nd->app != NULL ? nd->app->hsl.saturation_min : 0);
	put_u16(c, nd->app != NULL ? nd->app->hsl.saturation_max : UINT16_MAX);
	put_u8(c, nd->app != NULL ? nd->app->hsl.range_status : 0);
	/* Light xyL current/default/range state. */
	put_u16(c, nd->app != NULL ? nd->app->xyl.x : 0);
	put_u16(c, nd->app != NULL ? nd->app->xyl.y : 0);
	put_u16(c, nd->app != NULL ? nd->app->xyl.default_lightness : 0);
	put_u16(c, nd->app != NULL ? nd->app->xyl.default_x : 0);
	put_u16(c, nd->app != NULL ? nd->app->xyl.default_y : 0);
	put_u16(c, nd->app != NULL ? nd->app->xyl.x_min : 0);
	put_u16(c, nd->app != NULL ? nd->app->xyl.x_max : UINT16_MAX);
	put_u16(c, nd->app != NULL ? nd->app->xyl.y_min : 0);
	put_u16(c, nd->app != NULL ? nd->app->xyl.y_max : UINT16_MAX);
	put_u8(c, nd->app != NULL ? nd->app->xyl.range_status : 0);
	/* Light LC mode/onoff state and setup properties. */
	put_u8(c, nd->app != NULL ? nd->app->lc.mode : 0);
	put_u8(c, nd->app != NULL ? nd->app->lc.occupancy_mode : 0);
	put_u8(c, nd->app != NULL ? nd->app->lc.light_onoff : 0);
	put_u8(c, nd->app != NULL ? (uint8_t)nd->app->lc.n_properties : 0);
	if (nd->app != NULL) for (i = 0; i < nd->app->lc.n_properties; i++) {
		put_u16(c, nd->app->lc.properties[i].id);
		put_u8(c, nd->app->lc.properties[i].len);
		put_bytes(c, nd->app->lc.properties[i].value,
		    nd->app->lc.properties[i].len);
	}
	/* Scene snapshots and the complete Scheduler register. */
	put_u8(c, nd->app != NULL ? (uint8_t)nd->app->scene.n_scenes : 0);
	if (nd->app != NULL) for (i = 0; i < nd->app->scene.n_scenes; i++) {
		const struct mesh_scene_entry *entry = &nd->app->scene.scenes[i];
		put_u16(c, entry->number);
		put_u8(c, (uint8_t)entry->data_len);
		put_bytes(c, entry->data, entry->data_len);
	}
	put_u16(c, nd->app != NULL ? nd->app->scene.current_scene : 0);
	put_u16(c, nd->app != NULL ? nd->app->scene.target_scene : 0);
	put_u16(c, nd->app != NULL ? nd->app->scheduler.defined : 0);
	if (nd->app != NULL) for (i = 0; i < MESH_SCHEDULER_MAX; i++) {
		uint8_t action[10];
		if ((nd->app->scheduler.defined & (1u << i)) == 0)
			continue;
		(void)mesh_scheduler_action_encode(&nd->app->scheduler.entries[i], action);
		put_bytes(c, action, sizeof(action));
	}

	/* Manager state is embedded so node identity + roster commit atomically. */
	put_u8(c, (uint8_t)(nd->mgr_active && nd->mgr != NULL));
	if (nd->mgr_active && nd->mgr != NULL) {
		const struct mesh_mgr *mgr = nd->mgr;

		put_bytes(c, mgr->netkey, 16);
		put_bytes(c, mgr->appkey, 16);
		put_bytes(c, mgr->self_devkey, 16);
		put_u16(c, mgr->netkey_index);
		put_u16(c, mgr->appkey_index);
		put_u32(c, mgr->iv_index);
		put_u8(c, mgr->flags);
		put_u16(c, mgr->self_addr);
		put_u8(c, mgr->self_elements);
		put_u16(c, mgr->next_unicast);
		put_u16(c, (uint16_t)mgr->n_nodes);
		for (i = 0; i < mgr->n_nodes; i++) {
			const struct mesh_mgr_node *mn = &mgr->nodes[i];

			put_bytes(c, mn->uuid, 16);
			put_bytes(c, mn->devkey, 16);
			put_u16(c, mn->addr);
			put_u8(c, mn->num_elements);
			put_u64(c, mn->prov_time);
			put_u8(c, mn->kr_state);
		}
	}
}

/*
 * Decode the body into nd.  The keys / address / IV Index are applied by
 * rebuilding the node (meshd_node_restore) so its network credentials
 * re-derive; the remaining runtime state is overlaid onto the rebuilt node.
 * Sets *out_hw to the persisted SEQ high-water.  Returns 0, -1 on underrun.
 */
static int
decode_body(struct cur *c, struct meshd_node *nd, uint16_t version,
    uint32_t *out_hw)
{
	uint8_t netkey[16], appkey[16];
	uint16_t addr, netkey_index, cid, pid, vid;
	uint32_t seq_hw, iv_index, lpn_poll;
	uint8_t provisioned, default_ttl, features, iv_state, net_transmit;
	uint8_t relay_retransmit;
	uint64_t iv_entered;
	struct mesh_hb_pub hb_pub;
	uint16_t n_netkeys, n_appkeys, n_models, n_rpl;
	size_t i, j;

	addr = get_u16(c);
	netkey_index = get_u16(c);
	provisioned = get_u8(c);
	default_ttl = get_u8(c);
	features = get_u8(c);
	cid = get_u16(c);
	pid = get_u16(c);
	vid = get_u16(c);
	seq_hw = get_u32(c);
	iv_index = get_u32(c);
	iv_state = get_u8(c);
	iv_entered = get_u64(c);
	net_transmit = get_u8(c);
	relay_retransmit = version >= 6 ? get_u8(c) : 0;
	lpn_poll = get_u32(c);
	get_bytes(c, netkey, 16);
	get_bytes(c, appkey, 16);
	if (version >= 4)
		get_bytes(c, nd->local_devkey, sizeof(nd->local_devkey));
	else {
		if (RAND_bytes(nd->local_devkey, sizeof(nd->local_devkey)) != 1)
			return (-1);
		nd->devkey_migrated = 1;
	}
	nd->have_local_devkey = 1;

	memset(&hb_pub, 0, sizeof(hb_pub));
	hb_pub.dst = get_u16(c);
	hb_pub.count_log = get_u8(c);
	hb_pub.period_log = get_u8(c);
	hb_pub.ttl = get_u8(c);
	hb_pub.features = get_u16(c);
	hb_pub.net_idx = get_u16(c);

	if (c->err)
		return (-1);

	/* Rebuild the node from the restored keys (re-derives credentials). */
	nd->netkey_index = netkey_index;
	nd->cid = cid;
	nd->pid = pid;
	nd->vid = vid;
	if (meshd_node_restore(nd, netkey, appkey, iv_index, addr) != 0)
		return (-1);
	nd->provisioned = provisioned ? 1 : 0;
	nd->cfg.default_ttl = default_ttl;
	nd->cfg.relay = (features & MESHD_PERSIST_FEAT_RELAY) ? 1 : 0;
	nd->cfg.gatt_proxy = (features & MESHD_PERSIST_FEAT_PROXY) ? 1 : 0;
	/* Friend is not exposed until its FSM is wired to the real bearer. */
	nd->cfg.friend = 2;
	nd->friend_enabled = 0;
	nd->cfg.beacon = (features & MESHD_PERSIST_FEAT_BEACON) ? 1 : 0;

	/* Restore the IV Update phase (meshd_node_restore left it Normal). */
	nd->self->iv.iv_index = iv_index;
	nd->self->iv.state = iv_state;
	/*
	 * entered_time is a CLOCK_MONOTONIC-seconds timestamp used to gate the
	 * 96-hour IV Update dwell.  That clock resets on every host reboot, so a
	 * raw restored value is meaningless against this boot's clock: a value
	 * far in the future wedges every dwell-gated transition, and a fresh
	 * node's 0 passes the gate trivially once uptime exceeds 96 h.  Restart
	 * the dwell from the current monotonic time so the gate is enforced
	 * relative to a clock that actually exists this boot (finding 71).
	 */
	{
		struct timespec ts;

		(void)iv_entered;
		nd->self->iv.entered_time =
		    (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) ?
		    (uint64_t)ts.tv_sec : 0;
	}

	nd->db.net_transmit = net_transmit;
	nd->cfg.relay_retransmit = relay_retransmit;
	nd->db.lpn_poll_timeout = lpn_poll;
	nd->db.hb_pub = hb_pub;
	mesh_sim_set_relay(nd->self, nd->cfg.relay == 1);
	mesh_relay_unpack(nd->db.net_transmit,
	    &nd->self->relay.net_tx_count, &nd->self->relay.net_tx_steps);
	mesh_relay_unpack(nd->cfg.relay_retransmit,
	    &nd->self->relay.relay_rx_count, &nd->self->relay.relay_rx_steps);

	/* Subnets. */
	n_netkeys = get_u16(c);
	if (n_netkeys > MESHD_MAX_NETKEYS)
		return (-1);
	for (i = 0; i < MESHD_MAX_NETKEYS; i++)
		nd->db.netkeys[i].valid = 0;
	for (i = 0; i < n_netkeys; i++) {
		struct meshd_netkey_entry *nk = &nd->db.netkeys[i];

		nk->valid = 1;
		nk->net_idx = get_u16(c);
		get_bytes(c, nk->key, 16);
		nk->node_identity = get_u8(c);
		nk->priv_node_identity = MESH_CFG_PRIV_IDENTITY_STOPPED;
		nk->kr_phase = MESH_CFG_KR_PHASE_0;
		nk->has_new_key = 0;
		nk->kr_phase = get_u8(c);
		nk->has_new_key = get_u8(c) ? 1 : 0;
		if (nk->has_new_key)
			get_bytes(c, nk->new_key, 16);
		if (nk->net_idx != nd->netkey_index &&
		    mesh_sim_add_subnet(nd->self, nk->net_idx, nk->key) != 0)
			return (-1);
		/* Restore both credentials and the transmitted-key phase. */
		if (nk->has_new_key) {
			if (mesh_sim_subnet_key_refresh_begin(nd->self, nk->net_idx,
			    nk->new_key) != 0)
				return (-1);
			if (nk->kr_phase == MESH_CFG_KR_PHASE_2)
				(void)mesh_sim_subnet_key_refresh_advance(nd->self,
				    nk->net_idx);
		}
	}

	/* Application keys. */
	n_appkeys = get_u16(c);
	if (n_appkeys > MESHD_MAX_APPKEYS)
		return (-1);
	if (n_appkeys != 0 && nd->self->n_appkeys != 0)
		(void)mesh_sim_remove_appkey(nd->self,
		    nd->self->appkeys[0].app_idx);
	for (i = 0; i < MESHD_MAX_APPKEYS; i++)
		nd->db.appkeys[i].valid = 0;
	for (i = 0; i < n_appkeys; i++) {
		struct meshd_appkey_entry *ak = &nd->db.appkeys[i];

		ak->valid = 1;
		ak->app_idx = get_u16(c);
		ak->net_idx = get_u16(c);
		get_bytes(c, ak->key, 16);
		if (mesh_sim_add_appkey(nd->self, ak->net_idx, ak->app_idx,
		    ak->key) != 0)
			return (-1);
	}

	/* Per-model configuration. */
	n_models = get_u16(c);
	if (n_models > MESHD_MAX_MODELS)
		return (-1);
	for (i = 0; i < n_models; i++) {
		struct meshd_model_entry *m = &nd->db.models[i];
		uint8_t na, ns, has_pub;

		m->elem_addr = get_u16(c);
		if (m->elem_addr < nd->addr || (uint32_t)m->elem_addr >=
		    (uint32_t)nd->addr + nd->self->n_elements)
			return (-1);
		m->id.model_id = get_u16(c);
		m->id.company_id = get_u16(c);
		m->id.vendor = get_u8(c) ? 1 : 0;
		m->valid = 1;
		na = get_u8(c);
		if (na > MESHD_MAX_BINDINGS)
			return (-1);
		m->n_app = na;
		for (j = 0; j < na; j++)
			m->app_idx[j] = get_u16(c);
		ns = get_u8(c);
		if (ns > MESHD_MAX_SUBS)
			return (-1);
		m->n_subs = ns;
		for (j = 0; j < ns; j++) {
			m->subs[j] = get_u16(c);
			m->sub_is_va[j] = get_u8(c) ? 1 : 0;
			get_bytes(c, m->sub_label[j], MESH_LABEL_UUID_LEN);
		}
		has_pub = get_u8(c);
		m->has_pub = has_pub ? 1 : 0;
		m->pub.elem_addr = m->elem_addr;
		m->pub.pub_addr = get_u16(c);
		m->pub.app_idx = get_u16(c);
		m->pub.cred_flag = get_u8(c);
		m->pub.ttl = get_u8(c);
		m->pub.period = get_u8(c);
		m->pub.retransmit = get_u8(c);
		if (version >= 3) {
			m->pub_is_va = get_u8(c) ? 1 : 0;
			get_bytes(c, m->pub_label, MESH_LABEL_UUID_LEN);
		}
		if (m->pub_is_va) {
			uint16_t va;

			if (!m->has_pub ||
			    mesh_virtual_addr(m->pub_label, &va) != 0 ||
			    va != m->pub.pub_addr)
				return (-1);
		}
		m->pub.model = m->id;
	}
	if (n_models > nd->db.n_models)
		nd->db.n_models = n_models;
	meshd_sync_subscriptions(nd);

	/*
	 * Replay Protection List.  Bind the RPL to its storage FIRST -
	 * mesh_rpl_init() zeroes the backing store - then populate the restored
	 * entries, so the reload cannot wipe them.
	 */
	n_rpl = get_u16(c);
	if (n_rpl > MESH_SIM_RPL_SIZE)
		return (-1);
	mesh_rpl_init(&nd->self->rpl, nd->self->rpl_store, MESH_SIM_RPL_SIZE);
	for (i = 0; i < n_rpl; i++) {
		struct mesh_rpl_entry *e = &nd->self->rpl_store[i];

		e->src = get_u16(c);
		e->iv_index = get_u32(c);
		e->seq = get_u32(c);
		e->valid = 1;
	}

	{
		uint8_t onoff, dtt, on_power_up, last_onoff;
		int16_t level;

		onoff = get_u8(c);
		level = (int16_t)get_u16(c);
		dtt = get_u8(c);
		on_power_up = get_u8(c);
		last_onoff = get_u8(c);
		if (onoff > MESH_GEN_ON || !mesh_gen_transition_time_valid(dtt) ||
		    on_power_up > MESH_GEN_ONPOWERUP_RESTORE ||
		    last_onoff > MESH_GEN_ON || nd->app == NULL)
			return (-1);
		mesh_gen_onoff_srv_set_present(&nd->app->onoff, onoff);
		mesh_gen_level_srv_set_present(&nd->app->level, level);
		nd->app->dtt.transition_time = dtt;
		nd->app->power_onoff.on_power_up = on_power_up;
		nd->app->power_onoff.last_onoff = last_onoff;
	}
	{
		struct mesh_gen_power_level_srv *power = &nd->app->power_level;
		uint16_t stored_last;

		power->actual = get_u16(c);
		power->last = get_u16(c);
		power->default_power = get_u16(c);
		power->range_min = get_u16(c);
		power->range_max = get_u16(c);
		power->range_status = get_u8(c);
		if (power->last == 0 || power->range_min == 0 ||
		    power->range_max < power->range_min || power->range_status > 2)
			return (-1);
		stored_last = power->last;
		mesh_gen_power_level_set_actual(power, power->actual);
		power->last = stored_last;
	}
	{
		nd->app->location.global.latitude = (int32_t)get_u32(c);
		nd->app->location.global.longitude = (int32_t)get_u32(c);
		nd->app->location.global.altitude = (int16_t)get_u16(c);
		nd->app->location.local.north = (int16_t)get_u16(c);
		nd->app->location.local.east = (int16_t)get_u16(c);
		nd->app->location.local.altitude = (int16_t)get_u16(c);
		nd->app->location.local.floor = get_u8(c);
		nd->app->location.local.uncertainty = get_u16(c);
	}
	{
		uint8_t count = get_u8(c);
		if (count > MESH_SENSOR_MAX_PROPERTIES) return (-1);
		mesh_sensor_srv_init(&nd->app->sensor);
		for (i = 0; i < count; i++) {
			struct mesh_sensor_descriptor d;
			struct mesh_sensor_cadence cadence;
			struct mesh_sensor_setting setting;
			struct mesh_sensor_column column;
			uint8_t descriptor[8], raw[MESH_SENSOR_RAW_MAX];
			uint8_t rawlen, valid, nsettings, ncolumns;

			get_bytes(c, descriptor, sizeof(descriptor));
			if (mesh_sensor_descriptor_decode(descriptor, sizeof(descriptor), &d) != 0)
				return (-1);
			rawlen = get_u8(c);
			if (rawlen == 0 || rawlen > MESH_SENSOR_RAW_MAX) return (-1);
			get_bytes(c, raw, rawlen);
			if (mesh_sensor_srv_set(&nd->app->sensor, &d, raw, rawlen) != 0)
				return (-1);
			valid = get_u8(c);
			if (valid > 1) return (-1);
			if (valid) {
				size_t delta_len;
				memset(&cadence, 0, sizeof(cadence)); cadence.valid = 1;
				cadence.fast_period_divisor = get_u8(c);
				cadence.trigger_type = get_u8(c);
				if (cadence.trigger_type > 1) return (-1);
				delta_len = cadence.trigger_type ? 2 : rawlen;
				get_bytes(c, cadence.delta_down, delta_len);
				get_bytes(c, cadence.delta_up, delta_len);
				cadence.min_interval = get_u8(c);
				get_bytes(c, cadence.fast_low, rawlen);
				get_bytes(c, cadence.fast_high, rawlen);
				if (mesh_sensor_srv_set_cadence(&nd->app->sensor, d.property_id,
				    &cadence) != 0) return (-1);
			}
			nsettings = get_u8(c);
			if (nsettings > MESH_SENSOR_MAX_SETTINGS) return (-1);
			for (j = 0; j < nsettings; j++) {
				memset(&setting, 0, sizeof(setting));
				setting.property_id = get_u16(c); setting.access = get_u8(c);
				setting.raw_len = get_u8(c);
				if (setting.raw_len > MESH_SENSOR_RAW_MAX) return (-1);
				get_bytes(c, setting.raw, setting.raw_len);
				if (mesh_sensor_srv_set_setting(&nd->app->sensor, d.property_id,
				    &setting) != 0) return (-1);
			}
			ncolumns = get_u8(c);
			if (ncolumns > MESH_SENSOR_MAX_COLUMNS) return (-1);
			for (j = 0; j < ncolumns; j++) {
				memset(&column, 0, sizeof(column)); column.key_len = get_u8(c);
				if (column.key_len == 0 || column.key_len > MESH_SENSOR_RAW_MAX)
					return (-1);
				get_bytes(c, column.key, column.key_len);
				column.raw_len = get_u8(c);
				if (column.raw_len == 0 || column.raw_len > MESH_SENSOR_RAW_MAX)
					return (-1);
				get_bytes(c, column.raw, column.raw_len);
				if (mesh_sensor_srv_set_column(&nd->app->sensor, d.property_id,
				    &column) != 0) return (-1);
			}
		}
	}
	{
		uint8_t wire[10], tai[5];
		uint64_t value;
		get_bytes(c, wire, sizeof(wire));
		if (mesh_time_state_decode(wire, sizeof(wire), &nd->app->time.time) != 0)
			return (-1);
		nd->app->time.role = get_u8(c);
		nd->app->time.new_zone_offset = get_u8(c);
		get_bytes(c, tai, sizeof(tai)); value = 0;
		for (i = 0; i < sizeof(tai); i++) value |= (uint64_t)tai[i] << (8 * i);
		nd->app->time.zone_change = value;
		nd->app->time.new_tai_utc_delta = get_u16(c);
		get_bytes(c, tai, sizeof(tai)); value = 0;
		for (i = 0; i < sizeof(tai); i++) value |= (uint64_t)tai[i] << (8 * i);
		nd->app->time.delta_change = value;
		if (nd->app->time.role > 3 ||
		    nd->app->time.new_tai_utc_delta > 0x7fff)
			return (-1);
	}
	{
		struct mesh_light_lightness_srv *lightness = &nd->app->lightness;
		uint16_t last;
		lightness->actual = get_u16(c); last = get_u16(c);
		lightness->default_lightness = get_u16(c);
		lightness->range_min = get_u16(c); lightness->range_max = get_u16(c);
		lightness->range_status = get_u8(c);
		if (last == 0 || lightness->range_min == 0 ||
		    lightness->range_max < lightness->range_min ||
		    lightness->range_status > 2 ||
		    mesh_light_lightness_set_actual(lightness, lightness->actual) != 0)
			return (-1);
		lightness->last = last;
	}
	{
		struct mesh_light_ctl_srv *ctl = &nd->app->ctl;
		ctl->temperature = get_u16(c); ctl->delta_uv = (int16_t)get_u16(c);
		ctl->default_lightness = get_u16(c);
		ctl->default_temperature = get_u16(c);
		ctl->default_delta_uv = (int16_t)get_u16(c);
		ctl->range_min = get_u16(c); ctl->range_max = get_u16(c);
		ctl->range_status = get_u8(c);
		if (ctl->range_min < 0x0320 || ctl->range_max > 0x4e20 ||
		    ctl->range_min > ctl->range_max ||
		    ctl->temperature < ctl->range_min || ctl->temperature > ctl->range_max ||
		    ctl->default_temperature < ctl->range_min ||
		    ctl->default_temperature > ctl->range_max || ctl->range_status > 2)
			return (-1);
		{
			uint32_t span = (uint32_t)ctl->range_max - ctl->range_min;
			uint32_t offset = (uint32_t)ctl->temperature - ctl->range_min;
			int16_t level = ctl->temperature <= ctl->range_min ? INT16_MIN :
			    (ctl->temperature >= ctl->range_max ? INT16_MAX :
			    (int16_t)((offset * UINT32_C(65535) + span / 2) / span -
			    UINT32_C(32768)));

			mesh_gen_level_srv_set_present(&nd->app->ctl_level, level);
		}
	}
	{
		struct mesh_light_hsl_srv *hsl = &nd->app->hsl;
		hsl->hue = get_u16(c); hsl->saturation = get_u16(c);
		hsl->default_lightness = get_u16(c); hsl->default_hue = get_u16(c);
		hsl->default_saturation = get_u16(c); hsl->hue_min = get_u16(c);
		hsl->hue_max = get_u16(c); hsl->saturation_min = get_u16(c);
		hsl->saturation_max = get_u16(c); hsl->range_status = get_u8(c);
		if (hsl->hue_min > hsl->hue_max ||
		    hsl->saturation_min > hsl->saturation_max ||
		    hsl->hue < hsl->hue_min || hsl->hue > hsl->hue_max ||
		    hsl->saturation < hsl->saturation_min ||
		    hsl->saturation > hsl->saturation_max || hsl->range_status > 2)
			return (-1);
		mesh_gen_level_srv_set_present(&nd->app->hue_level,
		    (int16_t)((int32_t)hsl->hue - 32768));
		mesh_gen_level_srv_set_present(&nd->app->sat_level,
		    (int16_t)((int32_t)hsl->saturation - 32768));
	}
	{
		struct mesh_light_xyl_srv *xyl = &nd->app->xyl;
		xyl->x = get_u16(c); xyl->y = get_u16(c);
		xyl->default_lightness = get_u16(c); xyl->default_x = get_u16(c);
		xyl->default_y = get_u16(c); xyl->x_min = get_u16(c);
		xyl->x_max = get_u16(c); xyl->y_min = get_u16(c);
		xyl->y_max = get_u16(c); xyl->range_status = get_u8(c);
		if (xyl->x_min > xyl->x_max || xyl->y_min > xyl->y_max ||
		    xyl->x < xyl->x_min || xyl->x > xyl->x_max ||
		    xyl->y < xyl->y_min || xyl->y > xyl->y_max ||
		    xyl->range_status > 2)
			return (-1);
	}
	{
		struct mesh_light_lc_srv *lc = &nd->app->lc;
		uint8_t count;

		lc->mode = get_u8(c);
		lc->occupancy_mode = get_u8(c);
		lc->light_onoff = get_u8(c);
		count = get_u8(c);
		if (lc->mode > 1 || lc->occupancy_mode > 1 ||
		    lc->light_onoff > 1 || count > MESH_LIGHT_LC_MAX_PROPERTIES)
			return (-1);
		lc->n_properties = 0;
		for (i = 0; i < count; i++) {
			uint16_t id = get_u16(c);
			uint8_t len = get_u8(c);
			uint8_t value[MESH_LIGHT_LC_PROPERTY_VALUE_MAX];

			if (id == 0 || len > sizeof(value))
				return (-1);
			get_bytes(c, value, len);
			if (c->err ||
			    mesh_light_lc_property_set(lc, id, value, len) != 0)
				return (-1);
		}
		if (mesh_light_lc_set(lc, lc->mode, lc->light_onoff) != 0)
			return (-1);
	}
	{
		uint8_t count = get_u8(c);
		if (count > MESH_SCENE_MAX) return (-1);
		for (i = 0; i < count; i++) {
			struct mesh_scene_entry *entry = &nd->app->scene.scenes[i];
			entry->number = get_u16(c); entry->data_len = get_u8(c);
			if (entry->number == 0 || entry->data_len > MESH_SCENE_DATA_MAX)
				return (-1);
			get_bytes(c, entry->data, entry->data_len);
			if (i != 0 && nd->app->scene.scenes[i - 1].number >= entry->number)
				return (-1);
		}
		nd->app->scene.n_scenes = count;
		nd->app->scene.current_scene = get_u16(c);
		nd->app->scene.target_scene = get_u16(c);
		nd->app->scheduler.defined = get_u16(c);
		for (i = 0; i < MESH_SCHEDULER_MAX; i++) {
			uint8_t action[10];
			if ((nd->app->scheduler.defined & (1u << i)) == 0)
				continue;
			get_bytes(c, action, sizeof(action));
			if (mesh_scheduler_action_decode(action, sizeof(action),
			    &nd->app->scheduler.entries[i]) != 0 ||
			    nd->app->scheduler.entries[i].index != i)
				return (-1);
		}
	}

	if (version >= 5) {
		uint8_t active = get_u8(c);

		if (active > 1)
			return (-1);
		if (active) {
			struct mesh_mgr *mgr = calloc(1, sizeof(*mgr));
			uint16_t count;

			if (mgr == NULL)
				return (-1);
			get_bytes(c, mgr->netkey, 16);
			get_bytes(c, mgr->appkey, 16);
			get_bytes(c, mgr->self_devkey, 16);
			mgr->netkey_index = get_u16(c);
			mgr->appkey_index = get_u16(c);
			mgr->iv_index = get_u32(c);
			mgr->flags = get_u8(c);
			mgr->self_addr = get_u16(c);
			mgr->self_elements = get_u8(c);
			mgr->next_unicast = get_u16(c);
			count = get_u16(c);
			if (count > MESH_MGR_MAX_NODES ||
			    mgr->netkey_index > 0x0fff ||
			    mgr->appkey_index > 0x0fff ||
			    !persist_unicast_block_valid(mgr->self_addr,
			    mgr->self_elements) || mgr->next_unicast == 0 ||
			    mgr->next_unicast > 0x8000) {
				free(mgr);
				return (-1);
			}
			for (i = 0; i < count; i++) {
				struct mesh_mgr_node *mn = &mgr->nodes[i];

				get_bytes(c, mn->uuid, 16);
				get_bytes(c, mn->devkey, 16);
				mn->addr = get_u16(c);
				mn->num_elements = get_u8(c);
				mn->prov_time = get_u64(c);
				mn->kr_state = get_u8(c);
				if (!persist_unicast_block_valid(mn->addr,
				    mn->num_elements) ||
				    persist_blocks_overlap(mn->addr, mn->num_elements,
				    mgr->self_addr, mgr->self_elements) ||
				    mn->kr_state > MESH_MGR_KR_ACKED ||
				    mgr->next_unicast < (uint32_t)mn->addr +
				    mn->num_elements) {
					free(mgr);
					return (-1);
				}
				for (j = 0; j < i; j++)
					if (persist_blocks_overlap(mn->addr,
					    mn->num_elements, mgr->nodes[j].addr,
					    mgr->nodes[j].num_elements)) {
						free(mgr);
						return (-1);
					}
			}
			mgr->n_nodes = count;
			mgr->seq = nd->self->seq;
			if (c->err || mgr->self_addr != nd->addr ||
			    mgr->self_elements != nd->self->n_elements ||
			    mgr->netkey_index != nd->netkey_index ||
			    mgr->appkey_index != nd->appkey_index ||
			    mgr->iv_index != mesh_iv_tx_index(&nd->self->iv) ||
			    timingsafe_bcmp(mgr->self_devkey, nd->local_devkey, 16) != 0 ||
			    timingsafe_bcmp(mgr->netkey, nd->self->netkey, 16) != 0 ||
			    timingsafe_bcmp(mgr->appkey, appkey, 16) != 0) {
				free(mgr);
				return (-1);
			}
			nd->mgr = mgr;
			nd->mgr_active = 1;
		}
	}

	if (c->err)
		return (-1);
	*out_hw = seq_hw;
	return (0);
}

/* ================================================================
 * Public interface.
 * ================================================================ */

void
meshd_persist_init(struct meshd_persist *ps, const char *path, uint32_t block)
{

	if (ps == NULL)
		return;
	memset(ps, 0, sizeof(*ps));
	if (path != NULL)
		strlcpy(ps->path, path, sizeof(ps->path));
	ps->block = (block != 0) ? block : MESHD_PERSIST_SEQ_BLOCK;
	ps->reserved = 0;
}

int
meshd_persist_save(struct meshd_persist *ps, struct meshd_node *nd)
{
	uint8_t *frame;
	char tmp[PATH_MAX];
	struct cur c;
	uint32_t crc;
	size_t body_len, frame_len;
	uint16_t n_rpl;
	size_t i;
	int fd, rc;

	if (ps == NULL || nd == NULL || nd->self == NULL || ps->path[0] == '\0')
		return (-1);
	/* Save a current snapshot; transition timers intentionally do not resume. */
	mesh_access_tick(nd->self->elems, nd->self->n_elements, nd->sim.now_ms);
	frame = malloc(MESHD_PERSIST_HDR_LEN + MESHD_PERSIST_BODY_MAX);
	if (frame == NULL)
		return (-1);

	/* Body immediately after the header. */
	memset(&c, 0, sizeof(c));
	c.buf = frame + MESHD_PERSIST_HDR_LEN;
	c.len = MESHD_PERSIST_BODY_MAX;
	encode_body(&c, ps, nd);
	if (c.err) {
		free(frame);
		return (-1);
	}
	body_len = c.off;

	/* RPL count carried in the header count field (informational). */
	n_rpl = 0;
	for (i = 0; i < MESH_SIM_RPL_SIZE; i++)
		if (nd->self->rpl_store[i].valid)
			n_rpl++;

	/* Header: magic, version, flags, count, reserved, crc (filled last). */
	memset(&c, 0, sizeof(c));
	c.buf = frame;
	c.len = MESHD_PERSIST_HDR_LEN;
	put_bytes(&c, MESHD_PERSIST_MAGIC, MESHD_PERSIST_MAGIC_LEN);
	put_u16(&c, MESHD_PERSIST_VERSION);
	put_u16(&c, 0);				/* flags */
	put_u16(&c, n_rpl);			/* count */
	put_u16(&c, 0);				/* reserved */
	if (c.err) {
		free(frame);
		return (-1);
	}
	memset(frame + MESHD_PERSIST_HDR_LEN - 4, 0, 4);	/* crc = 0 for calc */

	frame_len = MESHD_PERSIST_HDR_LEN + body_len;
	crc = persist_crc32(0, frame, frame_len);
	le32enc(frame + MESHD_PERSIST_HDR_LEN - 4, crc);

	/* Atomic replace: write temp, fsync, rename over the target. */
	if ((size_t)snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", ps->path) >=
	    sizeof(tmp)) {
		free(frame);
		return (-1);
	}
	fd = mkstemp(tmp);
	if (fd < 0) {
		free(frame);
		return (-1);
	}
	if (fchmod(fd, 0600) != 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
		(void)close(fd);
		(void)unlink(tmp);
		free(frame);
		return (-1);
	}
	rc = write_all(fd, frame, frame_len);
	free(frame);
	if (rc == 0)
		rc = fsync(fd);
	if (close(fd) != 0)
		rc = -1;
	if (rc == 0 && rename(tmp, ps->path) != 0)
		rc = -1;
	if (rc == 0 && fsync_parent_dir(ps->path) != 0)
		rc = -1;
	if (rc != 0)
		(void)unlink(tmp);
	else {
		ps->dirty = 0;
		ps->due_ms = 0;
		ps->last_errno = 0;
	}
	return (rc);
}

void
meshd_persist_mark_dirty(struct meshd_persist *ps, uint64_t now_ms)
{

	if (ps == NULL)
		return;
	if (!ps->dirty)
		ps->due_ms = now_ms + MESHD_PERSIST_DEBOUNCE_MS;
	ps->dirty = 1;
}

int
meshd_persist_flush(struct meshd_persist *ps, struct meshd_node *nd,
    uint64_t now_ms, int force)
{
	int saved_errno;

	if (ps == NULL || nd == NULL)
		return (-1);
	if (!ps->dirty)
		return (0);
	if (!force && now_ms < ps->due_ms)
		return (0);
	if (meshd_persist_save(ps, nd) == 0)
		return (1);
	saved_errno = errno != 0 ? errno : EIO;
	ps->dirty = 1;
	ps->due_ms = now_ms + MESHD_PERSIST_RETRY_MS;
	ps->write_errors++;
	ps->last_errno = saved_errno;
	errno = saved_errno;
	return (-1);
}

int
meshd_persist_load(struct meshd_persist *ps, struct meshd_node *nd)
{
	uint8_t *frame;
	struct cur c;
	struct mesh_mgr *mgr;
	struct meshd_node tmp;
	struct stat sb;
	uint32_t stored_crc, running, seq_hw;
	uint16_t version;
	size_t body_len;
	ssize_t rn;
	int fd, mgr_active, self_index;
	const struct meshd_bearer *bearer;

	if (ps == NULL || nd == NULL || ps->path[0] == '\0')
		return (-1);
	fd = open(ps->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return (errno == ENOENT ? 1 : -1); /* only absence means fresh */
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0 ||
	    (size_t)sb.st_size < MESHD_PERSIST_HDR_LEN ||
	    (size_t)sb.st_size >
	    MESHD_PERSIST_HDR_LEN + MESHD_PERSIST_BODY_MAX) {
		(void)close(fd);
		return (-1);
	}
	frame = malloc(MESHD_PERSIST_HDR_LEN + MESHD_PERSIST_BODY_MAX);
	if (frame == NULL) {
		(void)close(fd);
		return (-1);
	}
	if (read_all(fd, frame, MESHD_PERSIST_HDR_LEN) != 0) {
		(void)close(fd);
		free(frame);
		return (-1);
	}
	body_len = (size_t)sb.st_size - MESHD_PERSIST_HDR_LEN;
	rn = 0;
	if (body_len > 0 &&
	    read_all(fd, frame + MESHD_PERSIST_HDR_LEN, body_len) != 0)
		rn = -1;
	(void)close(fd);
	if (rn != 0) {
		free(frame);
		return (-1);
	}

	if (memcmp(frame, MESHD_PERSIST_MAGIC, MESHD_PERSIST_MAGIC_LEN) != 0) {
		free(frame);
		return (-1);
	}
	memset(&c, 0, sizeof(c));
	c.rbuf = frame + MESHD_PERSIST_MAGIC_LEN;
	c.len = MESHD_PERSIST_HDR_LEN - MESHD_PERSIST_MAGIC_LEN;
	version = get_u16(&c);
	(void)get_u16(&c);			/* flags */
	(void)get_u16(&c);			/* count */
	if (!persist_version_supported(version)) {
		free(frame);
		return (-1);
	}

	/* CRC over the whole frame with the crc field taken as zero. */
	stored_crc = le32dec(frame + MESHD_PERSIST_HDR_LEN - 4);
	memset(frame + MESHD_PERSIST_HDR_LEN - 4, 0, 4);
	running = persist_crc32(0, frame, MESHD_PERSIST_HDR_LEN + body_len);
	if (running != stored_crc) {
		free(frame);
		return (-1);
	}

	/* Decode the body onto the node. */
	node_decode_init(&tmp);
	memset(&c, 0, sizeof(c));
	c.rbuf = frame + MESHD_PERSIST_HDR_LEN;
	c.len = body_len;
	if (decode_body(&c, &tmp, version, &seq_hw) != 0) {
		meshd_node_fini(&tmp);
		free(frame);
		return (-1);
	}
	free(frame);

	/*
	 * Resume the live SEQ at the persisted high-water: it is >= the last SEQ
	 * ever used (the block was reserved ahead), so SEQ cannot regress.  Then
	 * reserve the next block so a crash immediately after boot still resumes
	 * higher.
	 */
	tmp.self->seq = seq_hw;
	if (tmp.mgr_active)
		tmp.mgr->seq = seq_hw;
	ps->reserved = seq_hw;
	if (meshd_persist_seq_reserve(ps, &tmp) < 0) {
		meshd_node_fini(&tmp);
		return (-1);
	}
	bearer = nd->bearer;
	mgr = tmp.mgr_active ? NULL : nd->mgr;
	mgr_active = tmp.mgr_active ? 0 : nd->mgr_active;
	if (!tmp.mgr_active) {
		nd->mgr = NULL;
		nd->mgr_active = 0;
	}
	meshd_node_fini(nd);
	tmp.bearer = bearer;
	if (!tmp.mgr_active) {
		tmp.mgr = mgr;
		tmp.mgr_active = mgr_active;
	}
	self_index = tmp.self != NULL ? tmp.self->index : -1;
	*nd = tmp;
	node_rehome_sim(nd, self_index);
	return (0);
}

/* fsync the directory containing path so a preceding rename() is durable. */
static int
fsync_parent_dir(const char *path)
{
	char dir[PATH_MAX];
	const char *slash;
	int dfd;

	slash = strrchr(path, '/');
	if (slash == NULL) {
		dir[0] = '.';
		dir[1] = '\0';
	} else if (slash == path) {
		dir[0] = '/';
		dir[1] = '\0';
	} else {
		size_t n = (size_t)(slash - path);

		if (n >= sizeof(dir))
			return (-1);
		memcpy(dir, path, n);
		dir[n] = '\0';
	}
	dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0)
		return (-1);
	if (fsync(dfd) != 0) {
		(void)close(dfd);
		return (-1);
	}
	return (close(dfd));
}

int
meshd_persist_mgr_save(const char *path, const struct mesh_mgr *mgr)
{
	char tmp[PATH_MAX];

	if (path == NULL || mgr == NULL || path[0] == '\0')
		return (-1);
	if ((size_t)snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path) >= sizeof(tmp))
		return (-1);
	{
		int fd = mkstemp(tmp);

		if (fd < 0)
			return (-1);
		if (fchmod(fd, 0600) != 0 || close(fd) != 0) {
			(void)unlink(tmp);
			return (-1);
		}
	}
	/* mesh_mgr_save writes + fsyncs the file; add atomic rename + dir fsync. */
	if (mesh_mgr_save(mgr, tmp) != 0) {
		(void)unlink(tmp);
		return (-1);
	}
	if (rename(tmp, path) != 0) {
		(void)unlink(tmp);
		return (-1);
	}
	return (fsync_parent_dir(path));
}

int
meshd_persist_mgr_load(const char *path, struct mesh_mgr *mgr)
{
	struct stat sb;

	if (path == NULL || mgr == NULL)
		return (-1);
	if (lstat(path, &sb) != 0)
		return (errno == ENOENT ? 1 : -1);
	if (!S_ISREG(sb.st_mode) || sb.st_uid != geteuid() ||
	    (sb.st_mode & 077) != 0)
		return (-1);
	return (mesh_mgr_load(mgr, path) == 0 ? 0 : -1);
}

int
meshd_persist_seq_reserve(struct meshd_persist *ps, struct meshd_node *nd)
{
	uint32_t live, old_reserved;
	uint64_t next;

	if (ps == NULL || nd == NULL || nd->self == NULL)
		return (-1);

	live = nd->self->seq;
	/*
	 * Reserve-ahead invariant: the persisted high-water must stay at least
	 * GUARD above the live SEQ.  GUARD dwarfs the few SEQ values a single
	 * meshd operation consumes between calls, so the live SEQ can never reach
	 * (and thus never hand out at or above) the persisted high-water before a
	 * higher one is on disk - which is what makes SEQ non-regressing across a
	 * crash.
	 */
	if (ps->reserved != 0 && ps->reserved >= live + MESHD_PERSIST_SEQ_GUARD)
		return (0);

	next = (uint64_t)live + ps->block;
	if (next > MESH_IV_SEQ_MAX)
		next = MESH_IV_SEQ_MAX;		/* IV Update must intervene */
	old_reserved = ps->reserved;
	ps->reserved = (uint32_t)next;
	if (meshd_persist_save(ps, nd) != 0) {
		ps->reserved = old_reserved;
		ps->dirty = 1;
		return (-1);
	}
	return (1);
}
