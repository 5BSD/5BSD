/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * meshd node core: the provisionable node, its key material, model
 * registration, the bearer receive/transmit seam and the foundation-model
 * (Configuration / Health) message processing.  Pure logic, no I/O; the
 * mesh_sim(3) engine from libblemesh does the network/transport/access work.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/rand.h>

#include "meshd.h"
#include "meshd_probes.h"
#include "mesh_transport.h"
#include "mesh_beacon.h"

static uint16_t meshd_features(const struct meshd_node *nd);
static int meshd_model_id_eq(const struct mesh_cfg_model_id *a,
    const struct mesh_cfg_model_id *b);
static const struct meshd_app_reg *meshd_app_match_rx(
    const struct meshd_node *nd, const struct meshd_app_surface *apps);
static void meshd_app_queue_rx(struct meshd_node *nd);
static int meshd_app_surface_register(struct meshd_app_surface *apps,
    uint16_t elem_addr, const struct mesh_cfg_model_id *id, int has_opcode,
    uint32_t opcode);
static int meshd_app_surface_unregister(struct meshd_app_surface *apps,
    uint16_t elem_addr, const struct mesh_cfg_model_id *id);
static size_t meshd_app_surface_event_count(const struct meshd_app_surface *apps);
static uint32_t meshd_app_surface_event_dropped(
    const struct meshd_app_surface *apps);
static int meshd_app_surface_event_pop(struct meshd_app_surface *apps,
    struct meshd_app_event *ev);
static void meshd_app_surface_queue_rx(struct meshd_app_surface *apps,
    const struct mesh_sim_rx *rx, const struct meshd_app_reg *reg, int fd);
static struct meshd_model_entry *meshd_find_or_add_model(struct meshd_node *nd,
    uint16_t elem_addr, const struct mesh_cfg_model_id *id);
static int meshd_devkey_rx(void *, uint16_t, uint16_t, uint16_t,
    const uint8_t *, size_t, uint8_t *, size_t *);
static int meshd_remote_devkey(void *, uint16_t, uint8_t[16]);
static int meshd_remote_devkey_rx(void *, uint32_t, uint16_t, uint16_t,
    const uint8_t *, size_t);
static struct meshd_appkey_entry *meshd_find_appkey(struct meshd_node *,
    uint16_t);
static void meshd_df_rpr_init(struct meshd_node *nd);
static int meshd_friendship_control_rx(struct meshd_node *, const uint8_t *,
    size_t);
static void meshd_friendship_access_queue_rx(struct meshd_node *,
    const uint8_t *, size_t);
static void meshd_friend_emit(struct meshd_node *nd, uint16_t dst,
    struct mesh_friend_out *out);
static void meshd_lpn_emit(struct meshd_node *nd, struct mesh_lpn_out *out);

/*
 * Keep the manager's IV Index in lock-step with the node's transmit IV Index.
 *
 * The manager (Config Client / DevKey) copy is seeded once at network creation
 * and load, but the node's IV advances independently via the tick-driven IV
 * Update procedure and via adopting a peer's Secure Network beacon.  Every
 * DevKey seal/open reads mgr->iv_index, and the persist consistency check
 * requires mgr->iv_index == mesh_iv_tx_index(node) at load, so a stale manager
 * copy causes (a) errx("node state corrupt") on the next boot after an IV
 * Update and (b) CCM device-nonce reuse when the SEQ epoch resets while the
 * manager still seals at the old index.  Call this at every point the node IV
 * can change and before any manager-originated DevKey traffic.
 */
static void
meshd_sync_mgr_iv(struct meshd_node *nd)
{
	if (nd != NULL && nd->mgr_active && nd->mgr != NULL && nd->self != NULL)
		nd->mgr->iv_index = mesh_iv_tx_index(&nd->self->iv);
}

static uint64_t
meshd_pub_period_ms(uint8_t period)
{
	static const uint32_t unit_ms[] = { 100, 1000, 10000, 600000 };

	return ((uint64_t)(period & 0x3f) * unit_ms[period >> 6]);
}

static uint32_t
meshd_model_pub_get(uint16_t model_id)
{

	switch (model_id) {
	case MESH_MODEL_GEN_ONOFF_SRV:
		return (MESH_OP_GEN_ONOFF_GET);
	case MESH_MODEL_GEN_LEVEL_SRV:
		return (MESH_OP_GEN_LEVEL_GET);
	case MESH_MODEL_GEN_DTT_SRV:
		return (MESH_OP_GEN_DTT_GET);
	case MESH_MODEL_GEN_POWER_ONOFF_SRV:
		return (MESH_OP_GEN_ONPOWERUP_GET);
	case MESH_MODEL_GEN_POWER_LEVEL_SRV:
		return (MESH_OP_GEN_POWER_LEVEL_GET);
	case MESH_MODEL_GEN_BATTERY_SRV:
		return (MESH_OP_GEN_BATTERY_GET);
	case MESH_MODEL_GEN_LOCATION_SRV:
		return (MESH_OP_GEN_LOCATION_GLOBAL_GET);
	case MESH_MODEL_LIGHT_LIGHTNESS_SRV:
		return (MESH_OP_LIGHT_LIGHTNESS_GET);
	case MESH_MODEL_LIGHT_CTL_SRV:
		return (MESH_OP_LIGHT_CTL_GET);
	case MESH_MODEL_LIGHT_CTL_TEMP_SRV:
		return (MESH_OP_LIGHT_CTL_TEMPERATURE_GET);
	case MESH_MODEL_LIGHT_HSL_SRV:
		return (MESH_OP_LIGHT_HSL_GET);
	case MESH_MODEL_LIGHT_HSL_HUE_SRV:
		return (MESH_OP_LIGHT_HSL_HUE_GET);
	case MESH_MODEL_LIGHT_HSL_SAT_SRV:
		return (MESH_OP_LIGHT_HSL_SATURATION_GET);
	case MESH_MODEL_LIGHT_XYL_SRV:
		return (MESH_OP_LIGHT_XYL_GET);
	case MESH_MODEL_LIGHT_LC_SRV:
		return (MESH_OP_LIGHT_LC_LIGHT_ONOFF_GET);
	case MESH_MODEL_SENSOR_SRV:
		return (MESH_OP_SENSOR_GET);
	case MESH_MODEL_TIME_SRV:
		return (MESH_OP_TIME_GET);
	case MESH_MODEL_SCENE_SRV:
		return (MESH_OP_SCENE_GET);
	case MESH_MODEL_SCHEDULER_SRV:
		return (MESH_OP_SCHEDULER_GET);
	default:
		return (0);
	}
}

static int
meshd_model_refresh_publication(struct meshd_node *nd,
    struct meshd_model_entry *m)
{
	struct mesh_model_reply reply;
	uint8_t get[MESH_ACCESS_OPCODE_MAX_LEN];
	size_t getlen;

	if (m->pub_get_opcode == 0)
		return (m->pub_access_len != 0 ? 0 : -1);
	if (mesh_access_pdu_build(m->pub_get_opcode, NULL, 0, get, &getlen) != 0)
		return (-1);
	memset(&reply, 0, sizeof(reply));
	if (mesh_access_dispatch_at(nd->self->elems, nd->self->n_elements,
	    nd->addr, m->elem_addr, get, getlen, &reply, nd->sim.now_ms) != 0 ||
	    !reply.have_reply || mesh_access_pdu_build(reply.opcode, reply.params,
	    reply.params_len, m->pub_access, &m->pub_access_len) != 0)
		return (-1);
	return (0);
}

static int
meshd_model_publication_digest(struct meshd_node *nd,
    struct meshd_model_entry *m, uint64_t *digest)
{
	uint64_t h = UINT64_C(1469598103934665603);
	size_t i;

	if (!m->valid || !m->has_pub || m->pub_get_opcode == 0 ||
	    meshd_model_refresh_publication(nd, m) != 0)
		return (-1);
	for (i = 0; i < m->pub_access_len; i++) {
		h ^= m->pub_access[i];
		h *= UINT64_C(1099511628211);
	}
	h ^= m->pub_access_len;
	*digest = h;
	return (0);
}

static int
meshd_model_publish(struct meshd_node *nd, struct meshd_model_entry *m,
    int arm_retransmit)
{
	struct meshd_appkey_entry *appkey;
	struct mesh_access_pdu ap;
	uint8_t ttl;

	if (meshd_model_refresh_publication(nd, m) != 0 ||
	    m->pub.pub_addr == MESH_ADDR_UNASSIGNED ||
	    mesh_access_pdu_parse(m->pub_access, m->pub_access_len, &ap) != 0)
		return (-1);
	appkey = meshd_find_appkey(nd, m->pub.app_idx);
	if (appkey == NULL)
		return (-1);
	/*
	 * Publish TTL (MshMDL): 0x00-0x7F is the TTL to use, 0xFF means "use
	 * the node's Default TTL".  Do NOT route it through
	 * mesh_cfg_default_ttl_valid, which rejects 0x01 as a Default-TTL value
	 * and would silently replace a legitimate Publish TTL of 1 with the
	 * Default TTL (NB-18).
	 */
	ttl = (m->pub.ttl == 0xFF) ? nd->cfg.default_ttl : (m->pub.ttl & 0x7F);
	if (m->pub_is_va) {
		if (mesh_sim_send_access_key_from_virtual(&nd->sim, nd->self,
		    m->elem_addr, appkey->net_idx, appkey->app_idx, m->pub_label,
		    ap.opcode, ap.params, ap.params_len, ttl) != 0)
			return (-1);
	} else if (mesh_sim_send_access_key_from(&nd->sim, nd->self,
	    m->elem_addr, appkey->net_idx, appkey->app_idx, m->pub.pub_addr,
	    ap.opcode, ap.params, ap.params_len, ttl) != 0)
		return (-1);
	meshd_drain_tx(nd);
	if (arm_retransmit) {
		m->retransmit_left = m->pub.retransmit & 0x07;
		m->next_retransmit_ms = nd->sim.now_ms +
		    (uint64_t)(((m->pub.retransmit >> 3) & 0x1f) + 1) * 50;
	}
	return (0);
}

static void
meshd_publication_tick(struct meshd_node *nd, uint64_t now_ms)
{
	size_t i;

	for (i = 0; i < nd->db.n_models; i++) {
		struct meshd_model_entry *m = &nd->db.models[i];
		uint64_t period_ms;

		if (!m->valid || !m->has_pub ||
		    (m->pub_get_opcode == 0 && m->pub_access_len == 0))
			continue;
		while (m->retransmit_left != 0 &&
		    now_ms >= m->next_retransmit_ms) {
			if (meshd_model_publish(nd, m, 0) != 0) {
				m->retransmit_left = 0;
				break;
			}
			m->retransmit_left--;
			m->next_retransmit_ms +=
			    (uint64_t)(((m->pub.retransmit >> 3) & 0x1f) + 1) * 50;
		}
		period_ms = meshd_pub_period_ms(m->pub.period);
		if (period_ms == 0)
			continue;
		if (m->next_pub_ms == 0)
			m->next_pub_ms = now_ms + period_ms;
		if (now_ms >= m->next_pub_ms) {
			(void)meshd_model_publish(nd, m, 1);
			do {
				m->next_pub_ms += period_ms;
			} while (m->next_pub_ms <= now_ms);
		}
	}
}

/* Primary-element SIG model inventory. */
static const uint16_t meshd_primary_sig_models[] = {
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

static const uint16_t meshd_ctl_temp_sig_models[] = {
	MESH_MODEL_GEN_LEVEL_SRV,
	MESH_MODEL_LIGHT_CTL_TEMP_SRV,
};

static const uint16_t meshd_hsl_hue_sig_models[] = {
	MESH_MODEL_GEN_LEVEL_SRV,
	MESH_MODEL_LIGHT_HSL_HUE_SRV,
};

static const uint16_t meshd_hsl_sat_sig_models[] = {
	MESH_MODEL_GEN_LEVEL_SRV,
	MESH_MODEL_LIGHT_HSL_SAT_SRV,
};

struct meshd_element_models {
	const uint16_t *models;
	size_t n_models;
};

static const struct meshd_element_models meshd_elements[] = {
	{ meshd_primary_sig_models, nitems(meshd_primary_sig_models) },
	{ meshd_ctl_temp_sig_models, nitems(meshd_ctl_temp_sig_models) },
	{ meshd_hsl_hue_sig_models, nitems(meshd_hsl_hue_sig_models) },
	{ meshd_hsl_sat_sig_models, nitems(meshd_hsl_sat_sig_models) },
};

static void
meshd_comp_fill(struct mesh_cfg_comp_page0 *page,
    const struct meshd_node *nd)
{
	struct mesh_cfg_comp_element *el;
	size_t ei, n;

	memset(page, 0, sizeof(*page));
	page->cid = nd->cid;
	page->pid = nd->pid;
	page->vid = nd->vid;
	page->crpl = MESH_SIM_RPL_SIZE;
	page->features = meshd_features(nd);
	page->n_elements = nitems(meshd_elements);
	for (ei = 0; ei < nitems(meshd_elements); ei++) {
		el = &page->elements[ei];
		el->loc = 0x0000;
		n = meshd_elements[ei].n_models;
		if (n > nitems(el->sig_models))
			n = nitems(el->sig_models);
		memcpy(el->sig_models, meshd_elements[ei].models,
		    n * sizeof(el->sig_models[0]));
		el->n_sig = n;
	}
}

/*
 * Register the advertised model inventory on every element.  Composition Data
 * and the Configuration Server database are generated from meshd_elements so
 * they cannot disagree about a model's element address.
 */
static void
meshd_db_register_models(struct meshd_node *nd)
{
	struct meshd_cfg_db *db = &nd->db;
	size_t ei, i;

	db->n_models = 0;
	for (ei = 0; ei < nitems(meshd_elements); ei++) {
		for (i = 0; i < meshd_elements[ei].n_models &&
		    db->n_models < MESHD_MAX_MODELS; i++) {
			struct meshd_model_entry *m =
			    &db->models[db->n_models++];

			memset(m, 0, sizeof(*m));
			m->valid = 1;
			m->elem_addr = nd->addr + (uint16_t)ei;
			m->id.model_id = meshd_elements[ei].models[i];
			m->pub_get_opcode = meshd_model_pub_get(m->id.model_id);
		}
	}
}

/*
 * Initialise the config database from provisioning data: register the models
 * and seed the primary subnet (the provisioning NetKey) so the AppKey Add /
 * Model Bind commissioning sequence has a NetKey to bind against.
 */
static void
meshd_db_init(struct meshd_node *nd, const uint8_t netkey[16], uint16_t net_idx)
{

	memset(&nd->db, 0, sizeof(nd->db));
	meshd_db_register_models(nd);
	nd->db.netkeys[0].valid = 1;
	nd->db.netkeys[0].net_idx = net_idx;
	memcpy(nd->db.netkeys[0].key, netkey, 16);
	nd->db.netkeys[0].kr_phase = MESH_CFG_KR_PHASE_0;
	nd->db.netkeys[0].node_identity = MESH_CFG_NODE_IDENTITY_STOPPED;
	nd->db.netkeys[0].priv_node_identity = MESH_CFG_PRIV_IDENTITY_STOPPED;
}

int
meshd_addr_is_unicast(uint16_t addr)
{

	return (addr >= MESHD_UNICAST_MIN && addr <= MESHD_UNICAST_MAX);
}

/*
 * (Re)build the sim, the local node and its models from a key set.  Shared by
 * initialisation and (re)provisioning.  Returns 0 on success, -1 on failure.
 */
static int
meshd_setup_node(struct meshd_node *nd, const uint8_t netkey[16],
    const uint8_t appkey[16], uint32_t iv_index, uint16_t addr)
{
	struct mesh_node *node;

	if (mesh_sim_init(&nd->sim, netkey, appkey, iv_index) != 0)
		return (-1);
	/*
	 * Seed the wall-clock anchor BEFORE creating the node so its IV Update
	 * dwell anchor (entered_time) is stamped in the CLOCK_REALTIME domain
	 * the dwell check uses.  Otherwise a freshly provisioned node anchors
	 * entered_time at 0 (monotonic), and the first tick's wall_now (~1.7e9)
	 * makes mesh_iv_dwell_elapsed() trivially true -- letting the node skip
	 * the MshPRT 96-hour IV Update dwell exactly once after provisioning.
	 */
	{
		struct timespec wts;

		if (clock_gettime(CLOCK_REALTIME, &wts) == 0)
			nd->sim.wall_now = (uint64_t)wts.tv_sec;
	}
	node = mesh_sim_add_node(&nd->sim, addr, nitems(meshd_elements));
	if (node == NULL)
		return (-1);
	node->primary_net_idx = nd->netkey_index;
	node->appkeys[0].net_idx = nd->netkey_index;
	node->appkeys[0].app_idx = nd->appkey_index;

	/* Initialise and register every application model on its element. */
	if (meshd_models_register_all(nd, node) != 0)
		return (-1);

	nd->addr = addr;
	nd->self = node;
	for (size_t i = 0; i < nitems(nd->friend_rpl); i++)
		mesh_rpl_init(&nd->friend_rpl[i], nd->friend_rpl_store[i],
		    nitems(nd->friend_rpl_store[i]));
	if (nd->have_local_devkey && mesh_sim_set_devkey(node,
	    nd->local_devkey, meshd_devkey_rx, nd) != 0)
		return (-1);
	if (mesh_sim_set_devkey_client(node, meshd_remote_devkey,
	    meshd_remote_devkey_rx, nd) != 0)
		return (-1);

	/* Seed the config database: models + the provisioning (primary) subnet. */
	meshd_db_init(nd, netkey, nd->netkey_index);

	/* Directed Forwarding + Remote Provisioning model state (128/129). */
	meshd_df_rpr_init(nd);
	return (0);
}

int
meshd_node_init(struct meshd_node *nd, const struct meshd_config *cfg)
{

	if (nd == NULL || cfg == NULL)
		return (-1);
	if (!meshd_addr_is_unicast(cfg->unicast_addr))
		return (-1);

	memset(nd, 0, sizeof(*nd));
	nd->cid = cfg->company_id;
	nd->pid = cfg->product_id;
	nd->vid = cfg->version_id;
	nd->netkey_index = cfg->netkey_index;
	nd->appkey_index = cfg->appkey_index;
	if (cfg->have_device_key)
		memcpy(nd->local_devkey, cfg->device_key,
		    sizeof(nd->local_devkey));
	else if (RAND_bytes(nd->local_devkey, sizeof(nd->local_devkey)) != 1)
		return (-1);
	nd->have_local_devkey = 1;
	if (cfg->have_uuid) {
		memcpy(nd->device_uuid, cfg->device_uuid,
		    sizeof(nd->device_uuid));
		nd->have_device_uuid = 1;
	}

	mesh_cfg_server_init(&nd->cfg);
	mesh_hlt_server_init(&nd->health, nd->cid);

	nd->cfg.default_ttl = cfg->default_ttl;
	if (nd->self != NULL)
		nd->self->default_ttl = cfg->default_ttl;
	if (cfg->features & MESH_CFG_FEATURE_RELAY)
		nd->cfg.relay = 1;
	if (cfg->features & MESH_CFG_FEATURE_PROXY)
		nd->cfg.gatt_proxy = 1;
	/*
	 * Friendship roles (MshPRT_v1.1 Section 3.6.5 / 3.6.6).  The Friend and
	 * Low Power node engines are now driven over the bearer: meshd_bearer_rx
	 * routes inbound friendship control PDUs (identified by their Transport
	 * Control opcode) to the engines, and the node tick drives the LPN poll
	 * cadence and the Friend Offer / PollTimeout timers.  The Config Server
	 * Friend state reflects whether the Friend role is enabled.
	 */
	nd->cfg.friend = (cfg->features & MESH_CFG_FEATURE_FRIEND) ? 1 : 0;

	if (meshd_setup_node(nd, cfg->netkey, cfg->appkey, cfg->iv_index,
	    cfg->unicast_addr) != 0)
		return (-1);
	mesh_sim_set_relay(nd->self, nd->cfg.relay == 1);
	if (cfg->features & MESH_CFG_FEATURE_FRIEND)
		(void)meshd_friend_role_enable(nd);
	if (cfg->features & MESH_CFG_FEATURE_LOW_POWER)
		(void)meshd_lpn_role_enable(nd);

	/* A node whose provisioning data was supplied comes up provisioned. */
	nd->provisioned = cfg->have_netkey ? 1 : 0;
	return (0);
}

static int
meshd_devkey_rx(void *arg, uint16_t src, uint16_t dst, uint16_t net_idx,
    const uint8_t *access, size_t access_len, uint8_t *reply,
    size_t *reply_len)
{
	struct meshd_node *nd = arg;
	struct mesh_access_pdu ap;

	if (nd == NULL || dst != nd->addr)
		return (-1);
	/*
	 * Record the subnet that secured this config message so the config
	 * server (h_netkey_delete) can refuse to remove the NetKey that secured
	 * it (MshPRT 4.3.2.32).  Dispatch is synchronous below, so a per-node
	 * scratch field is sufficient in this single-threaded daemon.
	 */
	nd->rx_secure_net_idx = net_idx;
	/*
	 * Remember the RPR Client's unicast so the Server can later address it
	 * with unsolicited Scan/Link/PDU Reports (finding 128).
	 */
	if (mesh_access_pdu_parse(access, access_len, &ap) == 0 &&
	    ap.opcode >= MESH_RP_OP_SCAN_CAPABILITIES_GET &&
	    ap.opcode <= MESH_RP_OP_PDU_REPORT)
		nd->rpr.client_addr = src;
	return (meshd_foundation_recv(nd, access, access_len, reply,
	    MESH_ACCESS_PAYLOAD_MAX, reply_len));
}

static int
meshd_remote_devkey(void *arg, uint16_t src, uint8_t key[16])
{
	struct meshd_node *nd = arg;
	struct mesh_mgr_node *node;

	if (nd == NULL || key == NULL || !nd->mgr_active || nd->mgr == NULL)
		return (-1);
	node = mesh_mgr_find_by_addr(nd->mgr, src);
	if (node == NULL)
		return (-1);
	memcpy(key, node->devkey, 16);
	return (0);
}

static int
meshd_remote_devkey_rx(void *arg, uint32_t seq, uint16_t src, uint16_t dst,
    const uint8_t *upper, size_t upper_len)
{
	int r;

	/*
	 * A DevKey-sealed message from a roster node is first offered to the
	 * in-flight Config/DF/RPR Client transaction (Status correlation); if
	 * that does not consume it, it may be an unsolicited RPR Report.
	 */
	r = meshd_cfg_client_rx(arg, seq, src, dst, upper, upper_len);
	if (r == 1)
		return (1);
	return (meshd_rpr_client_rx(arg, seq, src, dst, upper, upper_len));
}

void
meshd_node_fini(struct meshd_node *nd)
{

	if (nd == NULL)
		return;
	free(nd->mgr);
	nd->mgr = NULL;
	nd->mgr_active = 0;
	meshd_models_fini(nd);
}

void
meshd_set_bearer(struct meshd_node *nd, const struct meshd_bearer *b)
{

	if (nd != NULL)
		nd->bearer = b;
}

/*
 * Hand every queued outbound Network PDU to the bearer, then clear the sim
 * transmit queue.  Counts frames and transmit errors.
 */
void
meshd_drain_tx(struct meshd_node *nd)
{
	size_t i;

	for (i = 0; i < nd->sim.n_tx; i++) {
		if (!nd->sim.tx[i].valid)
			continue;
		/*
		 * A NULL/absent bearer drops the PDU per the meshd_bearer
		 * contract.  A present bearer that reports a transmit error (the
		 * blued-down reconnect window) also drops rather than retaining
		 * the PDU: re-queuing filled the fixed 256-slot ring, stalled new
		 * originations, then burst stale SEQs onto the air on reconnect
		 * (finding C-m3).
		 */
		if (nd->bearer == NULL || nd->bearer->tx == NULL)
			continue;
		nd->tx_frames++;
		if (nd->bearer->tx(nd->bearer->arg, MESHD_PDU_NET,
		    nd->sim.tx[i].bytes, nd->sim.tx[i].len) != 0)
			nd->tx_errors++;
	}
	nd->sim.n_tx = 0;
}

int
meshd_provision_local(struct meshd_node *nd, const struct mesh_prov_data *pd)
{
	uint8_t appkey[16];

	if (nd == NULL || pd == NULL)
		return (-1);
	if (!meshd_addr_is_unicast(pd->unicast_addr))
		return (-1);

	/* Preserve the configured AppKey across the re-seed. */
	memcpy(appkey, nd->sim.appkey, sizeof(appkey));

	/* meshd_setup_node() re-initialises model state via register_all(). */
	if (meshd_setup_node(nd, pd->netkey, appkey, pd->iv_index,
	    pd->unicast_addr) != 0)
		return (-1);
	nd->provisioned = 1;
	return (0);
}

int
meshd_provision_recv_data(struct meshd_node *nd,
    const uint8_t session_key[16], const uint8_t session_nonce[13],
    const uint8_t enc[25], const uint8_t mic[8])
{
	struct mesh_prov_data pd;
	uint8_t data[25];

	if (nd == NULL || session_key == NULL || session_nonce == NULL ||
	    enc == NULL || mic == NULL)
		return (-1);

	/* Decrypt + MIC-verify the Provisioning Data PDU (real libblemesh). */
	if (mesh_prov_data_decrypt(session_key, session_nonce, enc, mic,
	    data) != 0)
		return (-1);
	if (mesh_prov_data_unpack(data, &pd) != 0)
		return (-1);
	return (meshd_provision_local(nd, &pd));
}

int
meshd_bearer_rx(struct meshd_node *nd, const uint8_t *pdu, size_t len)
{
	uint64_t pub_before[MESHD_MAX_MODELS], pub_after;
	uint8_t pub_valid[MESHD_MAX_MODELS];
	uint32_t before;
	size_t i;

	if (nd == NULL || pdu == NULL || len == 0)
		return (-1);
	if (!nd->provisioned)
		return (-1);
	/* Friendship control is dispatched separately below with its own RPL. */
	before = nd->self->rx.count;
	memset(pub_valid, 0, sizeof(pub_valid));
	for (i = 0; i < nd->db.n_models; i++)
		if (meshd_model_publication_digest(nd, &nd->db.models[i],
		    &pub_before[i]) == 0)
			pub_valid[i] = 1;

	/* Inject onto the medium and run the receive pipeline once. */
	if (mesh_sim_reinject(&nd->sim, MESHD_BEARER_TX_NODE, pdu, len) != 0)
		return (-1);
	(void)mesh_sim_step(&nd->sim);

	/* Any Status reply / relay the node produced is now queued: send it. */
	meshd_drain_tx(nd);

	/*
	 * Friendship (MshPRT_v1.1 Section 3.6.5): decrypt the inbound PDU with
	 * the managed-flooding credential and route any friendship control
	 * message (or a message destined for our LPN) to the Friend/LPN engines,
	 * transmitting the resulting control/queued PDUs over the bearer.  The
	 * sim step above ignores these opcodes, so this is additive.
	 */
	if (nd->friend_enabled || nd->lpn_enabled) {
		(void)meshd_friendship_control_rx(nd, pdu, len);
		meshd_friendship_access_queue_rx(nd, pdu, len);
	}

	/*
	 * An access PDU delivered to us while we are an established LPN is a
	 * Friend Queue delivery answering our outstanding Poll: toggle the LPN
	 * FSN so the next Poll acknowledges this entry and the Friend advances to
	 * the next queued message (without this the Friend resends the queue head
	 * forever; C6-M6).  more_data is set so the LPN re-polls promptly to drain
	 * any remaining entries; an empty-queue Friend Update later resets the
	 * cadence with MD=0.  on_message treats a copy with no Poll outstanding as
	 * a duplicate and leaves the FSN unchanged.
	 */
	if (nd->lpn_enabled && mesh_lpn_fsm_established(&nd->lpn_fsm) &&
	    nd->self->rx.count > before)
		(void)mesh_lpn_fsm_on_message(&nd->lpn_fsm, 1, nd->tick_last);

	if (nd->self->rx.count > before) {
		meshd_app_queue_rx(nd);
		for (i = 0; i < nd->db.n_models; i++)
			if (pub_valid[i] && meshd_model_publication_digest(nd,
			    &nd->db.models[i], &pub_after) == 0 &&
			    pub_after != pub_before[i])
				(void)meshd_model_publish(nd, &nd->db.models[i], 1);
		nd->rx_delivered++;
		return (1);
	}
	return (0);
}

/* Originate an access message from the node and drain it to the bearer. */
static int
meshd_originate(struct meshd_node *nd, uint16_t dst, uint32_t opcode,
    const uint8_t *params, size_t plen)
{

	if (mesh_sim_send_access(&nd->sim, nd->self, dst, opcode, params, plen,
	    nd->cfg.default_ttl) != 0)
		return (-1);
	meshd_drain_tx(nd);
	return (0);
}

int
meshd_send_onoff(struct meshd_node *nd, uint16_t dst, uint8_t onoff, int ack)
{
	struct mesh_gen_onoff_set set;
	uint8_t params[MESH_GEN_PARAMS_MAX];
	size_t plen;
	uint32_t opcode;

	if (nd == NULL || !nd->provisioned)
		return (-1);
	if (dst == 0x0000)
		return (-1);

	memset(&set, 0, sizeof(set));
	set.onoff = onoff ? MESH_GEN_ON : MESH_GEN_OFF;
	set.tid = 0;
	if (mesh_gen_onoff_set_encode(&set, params, &plen) != 0)
		return (-1);
	opcode = ack ? MESH_OP_GEN_ONOFF_SET : MESH_OP_GEN_ONOFF_SET_UNACK;
	return (meshd_originate(nd, dst, opcode, params, plen));
}

int
meshd_send_level(struct meshd_node *nd, uint16_t dst, int16_t level, int ack)
{
	struct mesh_gen_level_set set;
	uint8_t params[MESH_GEN_PARAMS_MAX];
	size_t plen;
	uint32_t opcode;

	if (nd == NULL || !nd->provisioned)
		return (-1);
	if (dst == 0x0000)
		return (-1);

	memset(&set, 0, sizeof(set));
	set.level = level;
	set.tid = 0;
	if (mesh_gen_level_set_encode(&set, params, &plen) != 0)
		return (-1);
	opcode = ack ? MESH_OP_GEN_LEVEL_SET : MESH_OP_GEN_LEVEL_SET_UNACK;
	return (meshd_originate(nd, dst, opcode, params, plen));
}

int
meshd_send_power_onoff(struct meshd_node *nd, uint16_t dst,
    uint8_t on_power_up, int ack)
{
	uint32_t opcode;

	if (nd == NULL || !nd->provisioned || dst == 0x0000 ||
	    on_power_up > MESH_GEN_ONPOWERUP_RESTORE)
		return (-1);
	opcode = ack ? MESH_OP_GEN_ONPOWERUP_SET :
	    MESH_OP_GEN_ONPOWERUP_SET_UNACK;
	return (meshd_originate(nd, dst, opcode, &on_power_up, 1));
}

int
meshd_send_dtt(struct meshd_node *nd, uint16_t dst, uint8_t transition_time,
    int ack)
{
	uint32_t opcode;

	if (nd == NULL || !nd->provisioned || dst == 0x0000 ||
	    !mesh_gen_transition_time_valid(transition_time))
		return (-1);
	opcode = ack ? MESH_OP_GEN_DTT_SET : MESH_OP_GEN_DTT_SET_UNACK;
	return (meshd_originate(nd, dst, opcode, &transition_time, 1));
}

int
meshd_send_power_level(struct meshd_node *nd, uint16_t dst, uint16_t power,
    int ack)
{
	uint8_t p[3] = { (uint8_t)power, (uint8_t)(power >> 8), 0 };

	if (nd == NULL || !nd->provisioned || dst == 0)
		return (-1);
	return (meshd_originate(nd, dst, ack ? MESH_OP_GEN_POWER_LEVEL_SET :
	    MESH_OP_GEN_POWER_LEVEL_SET_UNACK, p, sizeof(p)));
}

int
meshd_send_power_default(struct meshd_node *nd, uint16_t dst, uint16_t power,
    int ack)
{
	uint8_t p[2] = { (uint8_t)power, (uint8_t)(power >> 8) };

	if (nd == NULL || !nd->provisioned || dst == 0)
		return (-1);
	return (meshd_originate(nd, dst, ack ? MESH_OP_GEN_POWER_DEFAULT_SET :
	    MESH_OP_GEN_POWER_DEFAULT_SET_UNACK, p, sizeof(p)));
}

int
meshd_send_power_range(struct meshd_node *nd, uint16_t dst, uint16_t min,
    uint16_t max, int ack)
{
	uint8_t p[4];

	if (nd == NULL || !nd->provisioned || dst == 0 || min == 0 || max == 0 ||
	    max < min)
		return (-1);
	p[0] = (uint8_t)min; p[1] = (uint8_t)(min >> 8);
	p[2] = (uint8_t)max; p[3] = (uint8_t)(max >> 8);
	return (meshd_originate(nd, dst, ack ? MESH_OP_GEN_POWER_RANGE_SET :
	    MESH_OP_GEN_POWER_RANGE_SET_UNACK, p, sizeof(p)));
}

int
meshd_send_access_raw(struct meshd_node *nd, uint16_t dst,
    const uint8_t *access, size_t access_len)
{
	struct mesh_access_pdu ap;

	if (nd == NULL || !nd->provisioned || dst == 0x0000 ||
	    access == NULL || access_len == 0)
		return (-1);
	if (mesh_access_pdu_parse(access, access_len, &ap) != 0)
		return (-1);
	return (meshd_originate(nd, dst, ap.opcode, ap.params, ap.params_len));
}

int
meshd_send_devkey_raw(struct meshd_node *nd, uint16_t dst, int remote,
    uint16_t net_idx, const uint8_t *access, size_t access_len)
{
	struct mesh_mgr_node *node;
	uint8_t upper[MESH_ACCESS_PAYLOAD_MAX + 8];
	size_t upper_len;
	uint32_t seq0;
	int n;

	if (nd == NULL || !nd->provisioned || !nd->mgr_active ||
	    nd->mgr == NULL || nd->self == NULL || dst == 0x0000 ||
	    access == NULL || access_len == 0 ||
	    access_len > MESH_ACCESS_PAYLOAD_MAX)
		return (-1);
	if (net_idx != nd->mgr->netkey_index)
		return (-1);

	seq0 = mesh_sim_node_seq(nd->self);
	nd->mgr->seq = seq0;
	/* Seal under the live transmit IV Index, not the create-time copy. */
	meshd_sync_mgr_iv(nd);
	if (remote) {
		node = mesh_mgr_find_by_addr(nd->mgr, dst);
		if (node == NULL)
			return (-1);
		if (mesh_mgr_devkey_seal(nd->mgr, node, access, access_len,
		    &seq0, upper, &upper_len) != 0)
			return (-1);
	} else {
		if (mesh_upper_encrypt(nd->mgr->self_devkey, 0, 0, seq0,
		    nd->mgr->self_addr, dst, nd->mgr->iv_index, NULL, access,
		    access_len, upper, &upper_len) != 0)
			return (-1);
	}

	n = mesh_sim_send_upper(&nd->sim, nd->self, dst, seq0, upper, upper_len,
	    0, 0, nd->cfg.default_ttl);
	if (n < 0)
		return (-1);
	nd->self->seq = seq0 + (uint32_t)n;
	nd->mgr->seq = nd->self->seq;
	meshd_drain_tx(nd);
	return (0);
}

int
meshd_publish_raw(struct meshd_node *nd, uint16_t elem_addr,
    uint16_t model_id, uint16_t vendor, const uint8_t *access,
    size_t access_len)
{
	struct mesh_cfg_model_id id;
	struct mesh_access_pdu ap;
	size_t i;

	if (nd == NULL || !nd->provisioned || access == NULL || access_len == 0)
		return (-1);
	memset(&id, 0, sizeof(id));
	id.model_id = model_id;
	if (vendor != 0) {
		id.vendor = 1;
		id.company_id = vendor;
	}
	if (mesh_access_pdu_parse(access, access_len, &ap) != 0)
		return (-1);
	for (i = 0; i < nd->db.n_models; i++) {
		struct meshd_model_entry *m = &nd->db.models[i];

		if (!m->valid || !m->has_pub || m->elem_addr != elem_addr)
			continue;
		if (m->id.vendor != id.vendor ||
		    m->id.model_id != id.model_id ||
		    (id.vendor && m->id.company_id != id.company_id))
			continue;
		if (m->pub.pub_addr == 0x0000 || access_len > sizeof(m->pub_access))
			return (-1);
		memcpy(m->pub_access, access, access_len);
		m->pub_access_len = access_len;
		if (m->next_pub_ms == 0 && meshd_pub_period_ms(m->pub.period) != 0)
			m->next_pub_ms = nd->sim.now_ms +
			    meshd_pub_period_ms(m->pub.period);
		return (meshd_model_publish(nd, m, 1));
	}
	return (-1);
}

static int
meshd_app_registered(const struct meshd_app_surface *apps)
{

	return (apps != NULL && apps->n_regs > 0);
}

static const struct meshd_app_reg *
meshd_app_match_rx(const struct meshd_node *nd,
    const struct meshd_app_surface *apps)
{
	const struct mesh_sim_rx *rx;
	size_t ri, ei, mi;

	if (nd == NULL || !meshd_app_registered(apps) || nd->self == NULL ||
	    !nd->self->rx.valid)
		return (NULL);
	rx = &nd->self->rx;
	for (ri = 0; ri < MESHD_MAX_APP_REGS; ri++) {
		const struct meshd_app_reg *r = &apps->regs[ri];

		if (!r->valid)
			continue;
		for (ei = 0; ei < nd->self->n_elements; ei++) {
			const struct mesh_element *el = &nd->self->elems[ei];

			if (el->addr != r->elem_addr)
				continue;
			for (mi = 0; mi < el->n_models; mi++) {
				const struct mesh_model *m = &el->models[mi];
				struct mesh_cfg_model_id mid;
				size_t ai, oi, si;
				int addressed, opcode_match;

				memset(&mid, 0, sizeof(mid));
				mid.model_id = m->model_id;
				if (m->company_id != MESH_COMPANY_SIG) {
					mid.vendor = 1;
					mid.company_id = m->company_id;
				}
				if (!meshd_model_id_eq(&r->id, &mid))
					continue;
				opcode_match = !r->has_opcode ?
				    mesh_model_find_op(m, rx->opcode) != NULL : 0;
				if (r->has_opcode && r->opcode == rx->opcode)
					for (oi = 0; oi < m->n_app_opcodes; oi++)
						if (m->app_opcodes[oi] == rx->opcode) {
							opcode_match = 1;
							break;
						}
				if (!opcode_match)
					continue;
				if (rx->app_idx != UINT16_MAX && m->bindings_configured) {
					for (ai = 0; ai < m->n_app; ai++)
						if (m->app_idx[ai] == rx->app_idx)
							break;
					if (ai == m->n_app)
						continue;
				}
				addressed = mesh_addr_is_unicast(rx->dst) ||
				    !m->subscriptions_configured ||
				    rx->dst == MESH_ADDR_ALL_NODES;
				for (si = 0; !addressed && si < m->n_subs; si++) {
					uint16_t va;

					if (mesh_addr_is_group(rx->dst) &&
					    !m->sub_is_va[si] && m->subs[si] == rx->dst)
						addressed = 1;
					else if (mesh_addr_is_virtual(rx->dst) &&
					    m->sub_is_va[si] &&
					    mesh_virtual_addr(m->labels[si], &va) == 0 &&
					    va == rx->dst)
						addressed = 1;
				}
				if (addressed)
					return (r);
			}
		}
	}
	return (NULL);
}

static void
meshd_app_surface_queue_rx(struct meshd_app_surface *apps,
    const struct mesh_sim_rx *rx, const struct meshd_app_reg *reg, int fd)
{
	struct meshd_app_event *ev;
	size_t pos;

	if (apps == NULL || rx == NULL || reg == NULL)
		return;

	if (apps->ev_count == MESHD_APP_EVENT_MAX) {
		apps->ev_head = (apps->ev_head + 1) % MESHD_APP_EVENT_MAX;
		apps->ev_count--;
		apps->ev_dropped++;
		MESHD_PROBE_APP_EVENT_DROP(fd, apps->ev_dropped);
	}
	pos = (apps->ev_head + apps->ev_count) % MESHD_APP_EVENT_MAX;
	ev = &apps->events[pos];
	ev->elem_addr = reg->elem_addr;
	ev->id = reg->id;
	ev->src = rx->src;
	ev->dst = rx->dst;
	ev->opcode = rx->opcode;
	ev->params_len = rx->params_len;
	if (ev->params_len > sizeof(ev->params))
		ev->params_len = sizeof(ev->params);
	memcpy(ev->params, rx->params, ev->params_len);
	apps->ev_count++;
	MESHD_PROBE_APP_EVENT_QUEUE(fd, rx->opcode, apps->ev_count);
}

static void
meshd_app_queue_rx(struct meshd_node *nd)
{
	const struct meshd_app_reg *reg;
	size_t i;

	if (nd == NULL || nd->self == NULL || !nd->self->rx.valid)
		return;

	for (i = 0; i < MESHD_MAX_APP_CLIENTS; i++) {
		struct meshd_app_client *cl = &nd->app_clients[i];

		if (!cl->active)
			continue;
		reg = meshd_app_match_rx(nd, &cl->apps);
		if (reg != NULL)
			meshd_app_surface_queue_rx(&cl->apps, &nd->self->rx,
			    reg, cl->fd);
	}
}

static int
meshd_app_surface_register(struct meshd_app_surface *apps, uint16_t elem_addr,
    const struct mesh_cfg_model_id *id, int has_opcode, uint32_t opcode)
{
	struct meshd_app_reg *r;
	size_t i;

	if (apps == NULL || id == NULL)
		return (-1);
	for (i = 0; i < MESHD_MAX_APP_REGS; i++) {
		r = &apps->regs[i];
		if (r->valid && r->elem_addr == elem_addr &&
		    meshd_model_id_eq(&r->id, id) &&
		    r->has_opcode == has_opcode &&
		    (!has_opcode || r->opcode == opcode))
			return (0);
	}
	if (apps->n_regs >= MESHD_MAX_APP_REGS)
		return (-1);
	for (i = 0; i < MESHD_MAX_APP_REGS; i++) {
		r = &apps->regs[i];
		if (!r->valid) {
			memset(r, 0, sizeof(*r));
			r->valid = 1;
			r->elem_addr = elem_addr;
			r->id = *id;
			r->has_opcode = has_opcode;
			r->opcode = opcode;
			apps->n_regs++;
			return (0);
		}
	}
	return (-1);
}

static int
meshd_app_surface_unregister(struct meshd_app_surface *apps, uint16_t elem_addr,
    const struct mesh_cfg_model_id *id)
{
	struct meshd_app_reg *r;
	size_t i;
	int removed = 0;

	if (apps == NULL || id == NULL)
		return (-1);
	for (i = 0; i < MESHD_MAX_APP_REGS; i++) {
		r = &apps->regs[i];
		if (r->valid && r->elem_addr == elem_addr &&
		    meshd_model_id_eq(&r->id, id)) {
			memset(r, 0, sizeof(*r));
			apps->n_regs--;
			removed = 1;
		}
	}
	return (removed ? 0 : -1);
}

static size_t
meshd_app_surface_event_count(const struct meshd_app_surface *apps)
{

	return (apps != NULL ? apps->ev_count : 0);
}

static uint32_t
meshd_app_surface_event_dropped(const struct meshd_app_surface *apps)
{

	return (apps != NULL ? apps->ev_dropped : 0);
}

static int
meshd_app_surface_event_pop(struct meshd_app_surface *apps,
    struct meshd_app_event *ev)
{

	if (apps == NULL || ev == NULL || apps->ev_count == 0)
		return (0);
	*ev = apps->events[apps->ev_head];
	apps->ev_head = (apps->ev_head + 1) % MESHD_APP_EVENT_MAX;
	apps->ev_count--;
	return (1);
}

/* Copy the head event WITHOUT removing it, so a caller can check whether the
 * rendered form fits its reply before committing to the destructive pop. */
static int
meshd_app_surface_event_peek(const struct meshd_app_surface *apps,
    struct meshd_app_event *ev)
{

	if (apps == NULL || ev == NULL || apps->ev_count == 0)
		return (0);
	*ev = apps->events[apps->ev_head];
	return (1);
}

void
meshd_app_client_init(struct meshd_app_client *cl, int fd)
{

	if (cl == NULL)
		return;
	memset(cl, 0, sizeof(*cl));
	cl->active = 1;
	cl->fd = fd;
	MESHD_PROBE_APP_CONNECT(fd);
}

void
meshd_app_client_fini(struct meshd_app_client *cl)
{
	int fd;

	if (cl == NULL)
		return;
	fd = cl->fd;
	memset(cl, 0, sizeof(*cl));
	cl->fd = -1;
	MESHD_PROBE_APP_DISCONNECT(fd);
}

static int
meshd_app_client_register(struct meshd_node *nd,
    struct meshd_app_client *cl, uint16_t elem_addr,
    const struct mesh_cfg_model_id *id, int has_opcode, uint32_t opcode)
{
	struct mesh_model runtime;
	size_t ei, mi;

	if (nd == NULL || cl == NULL || !cl->active || id == NULL ||
	    nd->self == NULL || elem_addr < nd->addr ||
	    (uint32_t)elem_addr >= (uint32_t)nd->addr + nd->self->n_elements)
		return (-1);
	if (meshd_find_or_add_model(nd, elem_addr, id) == NULL)
		return (-1);
	ei = (size_t)(elem_addr - nd->addr);
	for (mi = 0; mi < nd->self->elems[ei].n_models; mi++) {
		const struct mesh_model *m = &nd->self->models[ei][mi];
		int vendor = m->company_id != MESH_COMPANY_SIG;

		if (m->model_id == id->model_id && vendor == id->vendor &&
		    (!vendor || m->company_id == id->company_id))
			break;
	}
	if (mi == nd->self->elems[ei].n_models) {
		memset(&runtime, 0, sizeof(runtime));
		runtime.model_id = id->model_id;
		runtime.company_id = id->vendor ? id->company_id : MESH_COMPANY_SIG;
		if (mesh_sim_add_model(nd->self, (uint8_t)ei, runtime) != 0)
			return (-1);
		mi = nd->self->elems[ei].n_models - 1;
	}
	if (has_opcode) {
		struct mesh_model *m = &nd->self->models[ei][mi];

		for (size_t oi = 0; oi < m->n_app_opcodes; oi++)
			if (m->app_opcodes[oi] == opcode)
				goto opcode_present;
		if (m->n_app_opcodes >= MESH_MODEL_MAX_APP_OPCODES)
			return (-1);
		m->app_opcodes[m->n_app_opcodes++] = opcode;
	}
opcode_present:
	meshd_sync_subscriptions(nd);
	if (meshd_app_surface_register(&cl->apps, elem_addr, id, has_opcode,
	    opcode) != 0)
		return (-1);
	MESHD_PROBE_APP_REGISTER(cl->fd, id->model_id,
	    id->vendor ? id->company_id : 0);
	return (0);
}

int
meshd_app_client_register_model(struct meshd_node *nd,
    struct meshd_app_client *cl, uint16_t elem_addr,
    const struct mesh_cfg_model_id *id)
{

	return (meshd_app_client_register(nd, cl, elem_addr, id, 0, 0));
}

int
meshd_app_client_register_opcode(struct meshd_node *nd,
    struct meshd_app_client *cl, uint16_t elem_addr,
    const struct mesh_cfg_model_id *id, uint32_t opcode)
{
	uint8_t access[3];
	struct mesh_access_pdu parsed;
	size_t access_len;

	if (id == NULL ||
	    mesh_access_pdu_build(opcode, NULL, 0, access, &access_len) != 0)
		return (-1);
	if (mesh_access_pdu_parse(access, access_len, &parsed) != 0 ||
	    parsed.vendor != id->vendor ||
	    (id->vendor && parsed.company_id != id->company_id))
		return (-1);
	return (meshd_app_client_register(nd, cl, elem_addr, id, 1, opcode));
}

int
meshd_app_client_unregister_model(struct meshd_app_client *cl,
    uint16_t elem_addr, const struct mesh_cfg_model_id *id)
{

	if (cl == NULL || !cl->active || id == NULL)
		return (-1);
	return (meshd_app_surface_unregister(&cl->apps, elem_addr, id));
}

size_t
meshd_app_client_event_count(const struct meshd_app_client *cl)
{

	return (cl != NULL && cl->active ?
	    meshd_app_surface_event_count(&cl->apps) : 0);
}

uint32_t
meshd_app_client_event_dropped(const struct meshd_app_client *cl)
{

	return (cl != NULL && cl->active ?
	    meshd_app_surface_event_dropped(&cl->apps) : 0);
}

int
meshd_app_client_event_pop(struct meshd_app_client *cl,
    struct meshd_app_event *ev)
{

	return (cl != NULL && cl->active ?
	    meshd_app_surface_event_pop(&cl->apps, ev) : 0);
}

int
meshd_app_client_event_peek(const struct meshd_app_client *cl,
    struct meshd_app_event *ev)
{

	return (cl != NULL && cl->active ?
	    meshd_app_surface_event_peek(&cl->apps, ev) : 0);
}

int
meshd_set_battery(struct meshd_node *nd,
    const struct mesh_gen_battery_status *state)
{
	uint8_t wire[8];

	if (nd == NULL || nd->app == NULL || state == NULL ||
	    mesh_gen_battery_status_encode(state, wire) != 0)
		return (-1);
	nd->app->battery.state = *state;
	return (0);
}

int
meshd_set_location_global(struct meshd_node *nd,
    const struct mesh_gen_location_global *state)
{
	if (nd == NULL || nd->app == NULL || state == NULL) return (-1);
	nd->app->location.global = *state;
	return (0);
}

int
meshd_set_location_local(struct meshd_node *nd,
    const struct mesh_gen_location_local *state)
{
	if (nd == NULL || nd->app == NULL || state == NULL) return (-1);
	nd->app->location.local = *state;
	return (0);
}

/* Derive the Composition Data Page 0 features word from server state. */
static uint16_t
meshd_features(const struct meshd_node *nd)
{
	uint16_t f = 0;

	if (nd->cfg.relay == 1)
		f |= MESH_CFG_FEATURE_RELAY;
	if (nd->cfg.gatt_proxy == 1)
		f |= MESH_CFG_FEATURE_PROXY;
	if (nd->cfg.friend == 1 || nd->friend_enabled)
		f |= MESH_CFG_FEATURE_FRIEND;
	if (nd->lpn_enabled)
		f |= MESH_CFG_FEATURE_LOW_POWER;
	return (f);
}

/* Build this node's Composition Data Page 0 into a Config status reply. */
static int
meshd_build_comp_status(struct meshd_node *nd, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_comp_page0 page;
	struct mesh_cfg_comp_status st;
	uint8_t buf[MESH_ACCESS_PAYLOAD_MAX];
	size_t blen;

	meshd_comp_fill(&page, nd);

	memset(&st, 0, sizeof(st));
	st.page = 0;
	if (mesh_cfg_comp_page0_encode(&page, st.data, &st.data_len) != 0)
		return (-1);
	if (mesh_cfg_comp_status_build(&st, buf, &blen) != 0)
		return (-1);
	if (blen > reply_max)
		return (-1);
	memcpy(reply, buf, blen);
	*reply_len = blen;
	return (1);
}

/* ================================================================
 * Configuration Server dispatch runtime (MshMDL_v1.1 Section 4.4.1;
 * access dispatch MshPRT_v1.1 Section 3.4.2 / 3.7).  A DevKey-encrypted
 * Configuration message is parsed (codecs in mesh_cfg_model.c), the node
 * config database (struct meshd_cfg_db) is mutated, and the mandatory
 * auto-Status is emitted.  Each handler builds its reply into a local buffer
 * and copies it out only when it fits, so a short reply buffer is rejected
 * without an overrun.
 * ================================================================ */

/* Copy a built reply out when it fits; -1 (no overrun) when it does not. */
static int
meshd_emit(const uint8_t *buf, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{

	if (len > reply_max)
		return (-1);
	memcpy(reply, buf, len);
	*reply_len = len;
	return (1);
}

/* Model identifier equality (SIG: model id; vendor: company id + model id). */
static int
meshd_model_id_eq(const struct mesh_cfg_model_id *a,
    const struct mesh_cfg_model_id *b)
{

	if (a->vendor != b->vendor || a->model_id != b->model_id)
		return (0);
	if (a->vendor && a->company_id != b->company_id)
		return (0);
	return (1);
}

static struct meshd_netkey_entry *
meshd_find_netkey(struct meshd_node *nd, uint16_t net_idx)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_NETKEYS; i++) {
		if (nd->db.netkeys[i].valid &&
		    nd->db.netkeys[i].net_idx == net_idx)
			return (&nd->db.netkeys[i]);
	}
	return (NULL);
}

static struct meshd_netkey_entry *
meshd_alloc_netkey(struct meshd_node *nd)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_NETKEYS; i++) {
		if (!nd->db.netkeys[i].valid)
			return (&nd->db.netkeys[i]);
	}
	return (NULL);
}

static struct meshd_appkey_entry *
meshd_find_appkey(struct meshd_node *nd, uint16_t app_idx)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_APPKEYS; i++) {
		if (nd->db.appkeys[i].valid &&
		    nd->db.appkeys[i].app_idx == app_idx)
			return (&nd->db.appkeys[i]);
	}
	return (NULL);
}

static struct meshd_appkey_entry *
meshd_alloc_appkey(struct meshd_node *nd)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_APPKEYS; i++) {
		if (!nd->db.appkeys[i].valid)
			return (&nd->db.appkeys[i]);
	}
	return (NULL);
}

static struct meshd_model_entry *
meshd_find_model(struct meshd_node *nd, uint16_t elem_addr,
    const struct mesh_cfg_model_id *id)
{
	size_t i;

	for (i = 0; i < nd->db.n_models; i++) {
		if (nd->db.models[i].valid &&
		    nd->db.models[i].elem_addr == elem_addr &&
		    meshd_model_id_eq(&nd->db.models[i].id, id))
			return (&nd->db.models[i]);
	}
	return (NULL);
}

static struct meshd_model_entry *
meshd_find_or_add_model(struct meshd_node *nd, uint16_t elem_addr,
    const struct mesh_cfg_model_id *id)
{
	struct meshd_model_entry *m;
	size_t i;

	for (i = 0; i < nd->db.n_models; i++) {
		m = &nd->db.models[i];
		if (m->valid && m->elem_addr == elem_addr &&
		    meshd_model_id_eq(&m->id, id))
			return (m);
	}
	if (nd->db.n_models >= MESHD_MAX_MODELS)
		return (NULL);
	m = &nd->db.models[nd->db.n_models++];
	memset(m, 0, sizeof(*m));
	m->valid = 1;
	m->elem_addr = elem_addr;
	m->id = *id;
	return (m);
}

static int
meshd_element_valid(const struct meshd_node *nd, uint16_t elem_addr)
{

	return (nd != NULL && nd->self != NULL && elem_addr >= nd->addr &&
	    (uint32_t)elem_addr < (uint32_t)nd->addr + nd->self->n_elements);
}

void
meshd_sync_subscriptions(struct meshd_node *nd)
{
	size_t ei, i, j, mi;

	if (nd == NULL || nd->self == NULL)
		return;
	for (ei = 0; ei < nd->self->n_elements; ei++)
		mesh_sim_clear_subscriptions(nd->self, (uint8_t)ei);
	for (ei = 0; ei < nd->self->n_elements; ei++) {
		for (mi = 0; mi < nd->self->elems[ei].n_models; mi++) {
			struct mesh_model *rm = &nd->self->models[ei][mi];

			rm->subs = NULL;
			rm->labels = NULL;
			rm->sub_is_va = NULL;
			rm->n_subs = 0;
			rm->subscriptions_configured = 0;
			rm->app_idx = NULL;
			rm->n_app = 0;
			rm->bindings_configured = 0;
		}
	}
	for (i = 0; i < nd->db.n_models; i++) {
		const struct meshd_model_entry *m = &nd->db.models[i];

		if (!m->valid || !meshd_element_valid(nd, m->elem_addr))
			continue;
		ei = (size_t)(m->elem_addr - nd->addr);
		for (mi = 0; mi < nd->self->elems[ei].n_models; mi++) {
			struct mesh_model *rm = &nd->self->models[ei][mi];
			int vendor = rm->company_id != MESH_COMPANY_SIG;

			if (rm->model_id != m->id.model_id || vendor != m->id.vendor ||
			    (vendor && rm->company_id != m->id.company_id))
				continue;
			rm->subs = m->subs;
			rm->labels = m->sub_label;
			rm->sub_is_va = m->sub_is_va;
			rm->n_subs = m->n_subs;
			rm->subscriptions_configured = 1;
			rm->app_idx = m->app_idx;
			rm->n_app = m->n_app;
			rm->bindings_configured = 1;
		}
		for (j = 0; j < m->n_subs; j++) {
			if (m->sub_is_va[j])
				(void)mesh_sim_subscribe_virtual_element(nd->self,
				    (uint8_t)ei, m->sub_label[j]);
			else
				(void)mesh_sim_subscribe_element(nd->self, (uint8_t)ei,
				    m->subs[j]);
		}
	}
}

/* ---------------- Node-wide state: TTL / Beacon / Proxy / Friend --------- */

static int
h_default_ttl_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint8_t buf[8];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	if (mesh_cfg_u8_state_build(MESH_CFG_OP_DEFAULT_TTL_STATUS,
	    nd->cfg.default_ttl, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_default_ttl_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint32_t op;
	uint8_t v, buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_u8_state_parse(pdu, len, &op, &v) != 0)
		return (-1);
	if (!mesh_cfg_default_ttl_valid(v))
		return (-1);
	nd->cfg.default_ttl = v;
	/* Mirror into the sim node so Config/model Status replies originate at
	 * the configured Default TTL instead of a hardcoded 5 (NB-4). */
	if (nd->self != NULL)
		nd->self->default_ttl = v;
	if (mesh_cfg_u8_state_build(MESH_CFG_OP_DEFAULT_TTL_STATUS, v, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* Beacon / GATT Proxy / Friend share the single-octet state shape. */
static int
meshd_u8_get(uint32_t status_op, uint8_t value, uint8_t *reply,
    size_t reply_max, size_t *reply_len)
{
	uint8_t buf[8];
	size_t blen;

	if (mesh_cfg_u8_state_build(status_op, value, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
meshd_u8_set(uint32_t status_op, uint8_t *state, const uint8_t *pdu, size_t len,
    uint8_t *reply, size_t reply_max, size_t *reply_len)
{
	uint32_t op;
	uint8_t v;

	if (mesh_cfg_u8_state_parse(pdu, len, &op, &v) != 0)
		return (-1);
	if (v > 1)			/* only Off (0) / On (1) are settable */
		return (-1);
	*state = v;
	return (meshd_u8_get(status_op, v, reply, reply_max, reply_len));
}

static int
h_beacon_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{

	(void)ap; (void)pdu; (void)len;
	return (meshd_u8_get(MESH_CFG_OP_BEACON_STATUS, nd->cfg.beacon, reply,
	    reply_max, reply_len));
}

static int
h_beacon_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{

	(void)ap;
	return (meshd_u8_set(MESH_CFG_OP_BEACON_STATUS, &nd->cfg.beacon, pdu,
	    len, reply, reply_max, reply_len));
}

static int
h_gatt_proxy_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{

	(void)ap; (void)pdu; (void)len;
	return (meshd_u8_get(MESH_CFG_OP_GATT_PROXY_STATUS, nd->cfg.gatt_proxy,
	    reply, reply_max, reply_len));
}

static int
h_gatt_proxy_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{

	(void)ap;
	return (meshd_u8_set(MESH_CFG_OP_GATT_PROXY_STATUS, &nd->cfg.gatt_proxy,
	    pdu, len, reply, reply_max, reply_len));
}

static int
h_friend_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{

	(void)ap; (void)pdu; (void)len;
	return (meshd_u8_get(MESH_CFG_OP_FRIEND_STATUS, nd->cfg.friend, reply,
	    reply_max, reply_len));
}

static int
h_friend_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{

	uint32_t op;
	uint8_t v;

	(void)ap;
	if (mesh_cfg_u8_state_parse(pdu, len, &op, &v) != 0 || v > 1)
		return (-1);
	/*
	 * The node supports the Friend feature (the role exists and Composition
	 * advertises it), so honor Friend Set instead of always replying Not
	 * Supported (0x02), which contradicted Friend Get and Composition
	 * (NB-27).  Enable/disable the role and report the resulting state.
	 */
	if (v == 1)
		(void)meshd_friend_role_enable(nd);
	else
		meshd_friend_role_disable(nd);
	return (meshd_u8_get(MESH_CFG_OP_FRIEND_STATUS, nd->cfg.friend, reply,
	    reply_max, reply_len));
}

/* ---------------- Relay + Network Transmit ------------------------------- */

static int
h_relay_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_relay r;
	uint8_t buf[8];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	r.relay = nd->cfg.relay;
	r.retransmit = nd->cfg.relay_retransmit;
	if (mesh_cfg_relay_set_build(MESH_CFG_OP_RELAY_STATUS, &r, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_relay_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_relay r;
	uint32_t op;
	uint8_t buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_relay_set_parse(pdu, len, &op, &r) != 0)
		return (-1);
	nd->cfg.relay = r.relay ? 1 : 0;
	nd->cfg.relay_retransmit = r.retransmit;
	mesh_sim_set_relay(nd->self, nd->cfg.relay);
	mesh_relay_unpack(r.retransmit, &nd->self->relay.relay_rx_count,
	    &nd->self->relay.relay_rx_steps);
	r.relay = nd->cfg.relay;
	if (mesh_cfg_relay_set_build(MESH_CFG_OP_RELAY_STATUS, &r, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_net_transmit_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_net_transmit nt;
	uint8_t buf[8];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	nt.count = (uint8_t)(nd->db.net_transmit & 0x07);
	nt.interval_steps = (uint8_t)((nd->db.net_transmit >> 3) & 0x1f);
	if (mesh_cfg_net_transmit_set_build(MESH_CFG_OP_NET_TRANSMIT_STATUS, &nt,
	    buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_net_transmit_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_net_transmit nt;
	uint32_t op;
	uint8_t buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_net_transmit_set_parse(pdu, len, &op, &nt) != 0)
		return (-1);
	nd->db.net_transmit = (uint8_t)(((nt.interval_steps & 0x1f) << 3) |
	    (nt.count & 0x07));
	nd->self->relay.net_tx_count = nt.count & 0x07;
	nd->self->relay.net_tx_steps = nt.interval_steps & 0x1f;
	if (mesh_cfg_net_transmit_set_build(MESH_CFG_OP_NET_TRANSMIT_STATUS, &nt,
	    buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* ---------------- Composition Data + Node Reset -------------------------- */

static int
h_comp_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint8_t page;

	(void)ap;
	if (mesh_cfg_comp_get_parse(pdu, len, &page) != 0)
		return (-1);
	return (meshd_build_comp_status(nd, reply, reply_max, reply_len));
}

static int
h_node_reset(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint8_t buf[8];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	nd->provisioned = 0;
	memset(&nd->db, 0, sizeof(nd->db));
	meshd_db_register_models(nd);
	if (mesh_cfg_node_reset_status_build(buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* Key Refresh operations, indexed by subnet (MshPRT_v1.1 Section 3.11.4). */

static int
meshd_kr_begin_idx(struct meshd_node *nd, uint16_t net_idx,
    const uint8_t new_key[16])
{
	struct meshd_netkey_entry *e;

	if (nd == NULL || new_key == NULL)
		return (-1);
	e = meshd_find_netkey(nd, net_idx);
	if (e == NULL || e->has_new_key)
		return (-1);
	if (mesh_sim_subnet_key_refresh_begin(nd->self, net_idx, new_key) != 0)
		return (-1);
	memcpy(e->new_key, new_key, 16);
	e->has_new_key = 1;
	e->kr_phase = (uint8_t)mesh_sim_subnet_kr_phase(nd->self, net_idx);
	return (0);
}

static int
meshd_kr_advance_idx(struct meshd_node *nd, uint16_t net_idx)
{
	struct meshd_netkey_entry *e;

	if (nd == NULL)
		return (-1);
	e = meshd_find_netkey(nd, net_idx);
	if (e == NULL || !e->has_new_key ||
	    mesh_sim_subnet_kr_phase(nd->self, net_idx) != MESH_KR_PHASE_1)
		return (-1);
	if (mesh_sim_subnet_key_refresh_advance(nd->self, net_idx) != 0)
		return (-1);
	e->kr_phase = (uint8_t)mesh_sim_subnet_kr_phase(nd->self, net_idx);
	return (0);
}

static int
meshd_kr_finish_idx(struct meshd_node *nd, uint16_t net_idx)
{
	struct meshd_netkey_entry *e;

	if (nd == NULL)
		return (-1);
	e = meshd_find_netkey(nd, net_idx);
	if (e == NULL || !e->has_new_key)
		return (-1);
	if (mesh_sim_subnet_key_refresh_finalize(nd->self, net_idx) != 0)
		return (-1);
	memcpy(e->key, e->new_key, 16);
	e->has_new_key = 0;
	explicit_bzero(e->new_key, sizeof(e->new_key));
	e->kr_phase = (uint8_t)mesh_sim_subnet_kr_phase(nd->self, net_idx);
	return (0);
}

int
meshd_kr_phase(const struct meshd_node *nd)
{

	if (nd == NULL || nd->self == NULL)
		return (-1);
	return (mesh_sim_node_kr_phase(nd->self));
}

/* NetKey Update: distribute new_key and enter Phase 1 (hold BOTH keys). */
int
meshd_kr_begin(struct meshd_node *nd, const uint8_t new_key[16])
{
	return (nd == NULL ? -1 :
	    meshd_kr_begin_idx(nd, nd->netkey_index, new_key));
}

/* KR Phase Transition 2: Phase 1 -> 2 (start transmitting with the new key). */
int
meshd_kr_advance(struct meshd_node *nd)
{
	return (nd == NULL ? -1 :
	    meshd_kr_advance_idx(nd, nd->netkey_index));
}

/* KR Phase Transition 3: revoke the old key, promote the new one, settle. */
int
meshd_kr_finish(struct meshd_node *nd)
{
	return (nd == NULL ? -1 :
	    meshd_kr_finish_idx(nd, nd->netkey_index));
}

/*
 * AppKey Key Refresh Phase-3 completion (C6-H3).  After every node has
 * installed the staged AppKey via Config AppKey Update, promote it to the
 * manager's current key, mint a fresh staged key, and apply the promoted key
 * to the Provisioner's own primary AppKey so the local node uses the current
 * key and the persisted node/mirror copies agree (the restart consistency
 * check compares mgr->appkey against the node's stored primary AppKey).  A
 * subsequent AppKey Update then distributes a genuinely new key, and a fresh
 * node provisioned via AppKey Add receives the current (not revoked) key.
 */
int
meshd_appkey_finalize(struct meshd_node *nd)
{
	struct meshd_appkey_entry *e;
	uint8_t newkey[16];
	int rc = 0;

	if (nd == NULL || !nd->mgr_active || nd->mgr == NULL || nd->self == NULL)
		return (-1);
	if (mesh_mgr_appkey_promote(nd->mgr, newkey) != 0)
		return (-1);
	e = meshd_find_appkey(nd, nd->mgr->appkey_index);
	if (e != NULL) {
		memcpy(e->key, newkey, sizeof(e->key));
		if (mesh_sim_add_appkey(nd->self, e->net_idx, e->app_idx,
		    newkey) != 0)
			rc = -1;
	}
	explicit_bzero(newkey, sizeof(newkey));
	return (rc);
}

/* ---------------- NetKey list ------------------------------------------- */

static int
h_netkey_add(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_netkey in;
	struct meshd_netkey_entry *e;
	uint32_t op;
	uint8_t status, buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_netkey_add_parse(pdu, len, &op, &in) != 0)
		return (-1);
	e = meshd_find_netkey(nd, in.net_idx);
	if (op == MESH_CFG_OP_NETKEY_ADD) {
		if (e != NULL)
			status = (timingsafe_bcmp(e->key, in.key, 16) == 0) ?
			    MESH_CFG_SUCCESS : MESH_CFG_KEY_INDEX_ALREADY_STORED;
		else if ((e = meshd_alloc_netkey(nd)) == NULL)
			status = MESH_CFG_INSUFFICIENT_RESOURCES;
		else {
			e->valid = 1;
			e->net_idx = in.net_idx;
			memcpy(e->key, in.key, 16);
			e->kr_phase = MESH_CFG_KR_PHASE_0;
			e->node_identity = MESH_CFG_NODE_IDENTITY_STOPPED;
			e->priv_node_identity = MESH_CFG_PRIV_IDENTITY_STOPPED;
			if (mesh_sim_add_subnet(nd->self, in.net_idx, in.key) != 0) {
				memset(e, 0, sizeof(*e));
				status = MESH_CFG_INSUFFICIENT_RESOURCES;
			} else
				status = MESH_CFG_SUCCESS;
		}
	} else {			/* NetKey Update (0x8045) */
		/*
		 * MshPRT_v1.1 Section 3.11.4: a NetKey Update distributes the new
		 * key and drives the subnet into Key Refresh Phase 1, holding BOTH
		 * keys.  The old key is NOT overwritten - it stays live for TX until
		 * Phase 2 and for RX until the Phase 3 settle.
		 */
		if (e == NULL)
			status = MESH_CFG_INVALID_NETKEY_INDEX;
		else if (timingsafe_bcmp(e->key, in.key, 16) == 0)
			status = MESH_CFG_SUCCESS;	/* equals current key: no-op */
		else if (e->has_new_key)
			/* Mid-refresh: re-sending the same new key is idempotent,
			 * a different key cannot change the in-flight refresh. */
			status = (timingsafe_bcmp(e->new_key, in.key, 16) == 0) ?
			    MESH_CFG_SUCCESS : MESH_CFG_CANNOT_UPDATE;
		else if (meshd_kr_begin_idx(nd, in.net_idx, in.key) != 0)
			status = MESH_CFG_UNSPECIFIED_ERROR;
		else
			status = MESH_CFG_SUCCESS;
	}
	if (mesh_cfg_netkey_status_build(status, in.net_idx, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_netkey_delete(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct meshd_netkey_entry *e;
	uint16_t net_idx;
	size_t i;
	uint8_t buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_netkey_delete_parse(pdu, len, &net_idx) != 0)
		return (-1);
	/*
	 * MshPRT 4.3.2.32: the NetKey that secured this message (and the last
	 * remaining NetKey) must not be removed.  rx_secure_net_idx is the subnet
	 * that secured this Config message (plumbed from the network decrypt);
	 * refuse to delete it even when it is not the primary.  Deleting the
	 * in-use primary subnet is separately refused because that would wipe its
	 * Config-Server DB entry and bound AppKeys while the node keeps
	 * TX/RX/relaying on it (mesh_sim_remove_subnet is skipped for the
	 * primary) -- a split-brain state.  Respond Cannot Remove and change
	 * nothing (NB-17).
	 */
	if (net_idx == nd->rx_secure_net_idx || net_idx == nd->netkey_index) {
		if (mesh_cfg_netkey_status_build(MESH_CFG_CANNOT_REMOVE, net_idx,
		    buf, &blen) != 0)
			return (-1);
		return (meshd_emit(buf, blen, reply, reply_max, reply_len));
	}
	e = meshd_find_netkey(nd, net_idx);
	if (e != NULL) {
		/* Remove the subnet and every AppKey bound to it. */
		for (i = 0; i < MESHD_MAX_APPKEYS; i++) {
			uint16_t app_idx;
			size_t mi, j;

			if (!nd->db.appkeys[i].valid ||
			    nd->db.appkeys[i].net_idx != net_idx)
				continue;
			app_idx = nd->db.appkeys[i].app_idx;
			(void)mesh_sim_remove_appkey(nd->self, app_idx);
			memset(&nd->db.appkeys[i], 0, sizeof(nd->db.appkeys[i]));
			/*
			 * Clear model bindings and publications that referenced
			 * this AppKey, or they dangle: a stale binding survives
			 * and a publication keeps has_pub=1 with an unresolvable
			 * app_idx, silently failing every publish tick (same
			 * dangling-state class fixed in AppKey Delete, NB-29).
			 */
			for (mi = 0; mi < nd->db.n_models; mi++) {
				struct meshd_model_entry *m = &nd->db.models[mi];

				for (j = 0; j < m->n_app; j++) {
					if (m->app_idx[j] != app_idx)
						continue;
					m->app_idx[j] = m->app_idx[m->n_app - 1];
					m->n_app--;
					break;
				}
				if (m->has_pub && m->pub.app_idx == app_idx) {
					m->has_pub = 0;
					memset(&m->pub, 0, sizeof(m->pub));
				}
			}
		}
		/* net_idx is a non-primary subnet here (primary rejected above). */
		(void)mesh_sim_remove_subnet(nd->self, net_idx);
		meshd_sync_subscriptions(nd);
		memset(e, 0, sizeof(*e));
	}
	if (mesh_cfg_netkey_status_build(MESH_CFG_SUCCESS, net_idx, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_netkey_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint16_t idx[MESHD_MAX_NETKEYS];
	size_t i, n = 0;
	uint8_t buf[MESH_ACCESS_PAYLOAD_MAX];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	for (i = 0; i < MESHD_MAX_NETKEYS; i++) {
		if (nd->db.netkeys[i].valid)
			idx[n++] = nd->db.netkeys[i].net_idx;
	}
	if (mesh_cfg_netkey_list_build(idx, n, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* ---------------- AppKey list ------------------------------------------- */

static int
h_appkey_add(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_appkey in;
	struct meshd_appkey_entry *e, *added = NULL;
	uint32_t op;
	uint8_t status, buf[8];
	size_t blen, i;
	int had_configured_appkey = 0;

	(void)ap;
	if (mesh_cfg_appkey_add_parse(pdu, len, &op, &in) != 0)
		return (-1);
	for (i = 0; i < MESHD_MAX_APPKEYS; i++)
		if (nd->db.appkeys[i].valid)
			had_configured_appkey = 1;
	if (meshd_find_netkey(nd, in.net_idx) == NULL)
		status = MESH_CFG_INVALID_NETKEY_INDEX;
	else {
		e = meshd_find_appkey(nd, in.app_idx);
		if (op == MESH_CFG_OP_APPKEY_ADD) {
			if (e != NULL && e->net_idx != in.net_idx)
				status = MESH_CFG_INVALID_BINDING;
			else if (e != NULL)
				status = (timingsafe_bcmp(e->key, in.key, 16) == 0) ?
				    MESH_CFG_SUCCESS :
				    MESH_CFG_KEY_INDEX_ALREADY_STORED;
			else if ((e = meshd_alloc_appkey(nd)) == NULL)
				status = MESH_CFG_INSUFFICIENT_RESOURCES;
			else {
				e->valid = 1;
				e->app_idx = in.app_idx;
				e->net_idx = in.net_idx;
				memcpy(e->key, in.key, 16);
				status = MESH_CFG_SUCCESS;
				added = e;	/* newly committed: rollback candidate */
			}
		} else {		/* AppKey Update */
			if (e == NULL)
				status = MESH_CFG_INVALID_APPKEY_INDEX;
			else if (e->net_idx != in.net_idx)
				status = MESH_CFG_INVALID_BINDING;
			else {
				memcpy(e->key, in.key, 16);
				status = MESH_CFG_SUCCESS;
			}
		}
	}
	if (status == MESH_CFG_SUCCESS && !had_configured_appkey &&
	    nd->self->n_appkeys != 0)
		(void)mesh_sim_remove_appkey(nd->self,
		    nd->self->appkeys[0].app_idx);
	if (status == MESH_CFG_SUCCESS &&
	    mesh_sim_add_appkey(nd->self, in.net_idx, in.app_idx, in.key) != 0) {
		status = MESH_CFG_INSUFFICIENT_RESOURCES;
		/*
		 * The crypto/sim layer rejected the key.  Roll back the DB entry
		 * we just committed so AppKey Get does not list a key that model
		 * traffic can never be decrypted with (finding 117).  Only a
		 * freshly allocated Add entry is rolled back; an idempotent
		 * re-Add or an Update of a pre-existing entry is left intact.
		 */
		if (added != NULL) {
			explicit_bzero(added->key, sizeof(added->key));
			added->valid = 0;
			added->app_idx = 0;
			added->net_idx = 0;
		}
	}
	if (mesh_cfg_appkey_status_build(status, in.net_idx, in.app_idx, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_appkey_delete(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct meshd_appkey_entry *e;
	uint16_t net_idx, app_idx;
	size_t i, j;
	uint8_t buf[8];
	size_t blen;
	uint8_t status = MESH_CFG_SUCCESS;

	(void)ap;
	if (mesh_cfg_appkey_delete_parse(pdu, len, &net_idx, &app_idx) != 0)
		return (-1);
	/* Unknown NetKeyIndex -> Invalid NetKey Index (NB-29), not Success. */
	if (meshd_find_netkey(nd, net_idx) == NULL)
		status = MESH_CFG_INVALID_NETKEY_INDEX;
	else if ((e = meshd_find_appkey(nd, app_idx)) != NULL &&
	    e->net_idx != net_idx) {
		/* AppKey exists but under a different NetKey -> Invalid Binding. */
		status = MESH_CFG_INVALID_BINDING;
	} else if (e != NULL) {
		/* Drop the key and any per-model binding that referenced it. */
		for (i = 0; i < nd->db.n_models; i++) {
			struct meshd_model_entry *m = &nd->db.models[i];

			for (j = 0; j < m->n_app; j++) {
				if (m->app_idx[j] != app_idx)
					continue;
				m->app_idx[j] = m->app_idx[m->n_app - 1];
				m->n_app--;
				break;
			}
			/*
			 * Also clear any publication bound to the deleted key,
			 * or the model keeps has_pub=1 with a dangling app_idx
			 * and meshd_model_publish silently fails every tick
			 * (NB-29).
			 */
			if (m->has_pub && m->pub.app_idx == app_idx) {
				m->has_pub = 0;
				memset(&m->pub, 0, sizeof(m->pub));
			}
		}
		(void)mesh_sim_remove_appkey(nd->self, app_idx);
		memset(e, 0, sizeof(*e));
		meshd_sync_subscriptions(nd);
	}
	/* Deleting a non-existent AppKey under a known NetKey is Success (no-op). */
	if (mesh_cfg_appkey_status_build(status, net_idx, app_idx, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_appkey_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint16_t net_idx, idx[MESHD_MAX_APPKEYS];
	size_t i, n = 0;
	uint8_t status, buf[MESH_ACCESS_PAYLOAD_MAX];
	size_t blen;

	(void)ap;
	if (mesh_cfg_appkey_get_parse(pdu, len, &net_idx) != 0)
		return (-1);
	if (meshd_find_netkey(nd, net_idx) == NULL)
		status = MESH_CFG_INVALID_NETKEY_INDEX;
	else {
		status = MESH_CFG_SUCCESS;
		for (i = 0; i < MESHD_MAX_APPKEYS; i++) {
			if (nd->db.appkeys[i].valid &&
			    nd->db.appkeys[i].net_idx == net_idx)
				idx[n++] = nd->db.appkeys[i].app_idx;
		}
	}
	if (mesh_cfg_appkey_list_build(status, net_idx, idx, n, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* ---------------- Model AppKey binding ---------------------------------- */

static uint8_t
meshd_do_bind(struct meshd_node *nd, uint32_t op,
    const struct mesh_cfg_model_app *in)
{
	struct meshd_model_entry *m;
	size_t j;

	if (!meshd_element_valid(nd, in->elem_addr))
		return (MESH_CFG_INVALID_ADDRESS);
	if (meshd_find_appkey(nd, in->app_idx) == NULL)
		return (MESH_CFG_INVALID_APPKEY_INDEX);
	m = meshd_find_model(nd, in->elem_addr, &in->model);
	if (m == NULL)
		return (MESH_CFG_INVALID_MODEL);
	/* The Configuration Server model uses the DevKey, not an AppKey. */
	if (!m->id.vendor && m->id.model_id == 0x0000)
		return (MESH_CFG_INVALID_MODEL);
	for (j = 0; j < m->n_app; j++) {
		if (m->app_idx[j] == in->app_idx) {
			if (op == MESH_CFG_OP_MODEL_APP_UNBIND) {
				m->app_idx[j] = m->app_idx[m->n_app - 1];
				m->n_app--;
			}
			return (MESH_CFG_SUCCESS);
		}
	}
	if (op == MESH_CFG_OP_MODEL_APP_UNBIND)
		return (MESH_CFG_SUCCESS);	/* not bound: nothing to remove */
	if (m->n_app >= MESHD_MAX_BINDINGS)
		return (MESH_CFG_INSUFFICIENT_RESOURCES);
	m->app_idx[m->n_app++] = in->app_idx;
	return (MESH_CFG_SUCCESS);
}

static int
h_model_app_bind(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_model_app in;
	uint32_t op;
	uint8_t status, buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_model_app_parse(pdu, len, &op, &in) != 0)
		return (-1);
	status = meshd_do_bind(nd, op, &in);
	if (status == MESH_CFG_SUCCESS)
		meshd_sync_subscriptions(nd);
	if (mesh_cfg_model_app_status_build(status, &in, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_model_app_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_model_id model;
	struct meshd_model_entry *m;
	uint32_t op, list_op;
	uint16_t elem_addr;
	uint8_t status, buf[MESH_ACCESS_PAYLOAD_MAX];
	const uint16_t *idx = NULL;
	size_t n = 0, blen;

	(void)ap;
	if (mesh_cfg_model_app_get_parse(pdu, len, &op, &elem_addr, &model) != 0)
		return (-1);
	list_op = (op == MESH_CFG_OP_VND_MODEL_APP_GET) ?
	    MESH_CFG_OP_VND_MODEL_APP_LIST : MESH_CFG_OP_SIG_MODEL_APP_LIST;
	if (!meshd_element_valid(nd, elem_addr))
		status = MESH_CFG_INVALID_ADDRESS;
	else if ((m = meshd_find_model(nd, elem_addr, &model)) == NULL)
		status = MESH_CFG_INVALID_MODEL;
	else {
		status = MESH_CFG_SUCCESS;
		idx = m->app_idx;
		n = m->n_app;
	}
	if (mesh_cfg_model_app_list_build(list_op, status, elem_addr, &model,
	    idx, n, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* ---------------- Model subscription ------------------------------------ */

/* Add/replace a group address in a model's subscription list. */
static uint8_t
meshd_sub_mutate(struct meshd_model_entry *m, uint32_t op, uint16_t addr,
    const uint8_t *label)
{
	size_t j;

	if (op == MESH_CFG_OP_MODEL_SUB_OVERWRITE ||
	    op == MESH_CFG_OP_MODEL_SUB_VA_OVERWRITE) {
		m->n_subs = 0;			/* replace the whole list */
	}
	if (op == MESH_CFG_OP_MODEL_SUB_DELETE ||
	    op == MESH_CFG_OP_MODEL_SUB_VA_DELETE) {
		for (j = 0; j < m->n_subs; j++) {
			if (m->subs[j] != addr ||
			    ((label != NULL) != (m->sub_is_va[j] != 0)) ||
			    (label != NULL && memcmp(m->sub_label[j], label,
			    MESH_LABEL_UUID_LEN) != 0))
				continue;
			m->subs[j] = m->subs[m->n_subs - 1];
			m->sub_is_va[j] = m->sub_is_va[m->n_subs - 1];
			memcpy(m->sub_label[j], m->sub_label[m->n_subs - 1],
			    MESH_LABEL_UUID_LEN);
			m->n_subs--;
			break;
		}
		return (MESH_CFG_SUCCESS);
	}
	for (j = 0; j < m->n_subs; j++) {
		if (m->subs[j] == addr &&
		    ((label == NULL && !m->sub_is_va[j]) ||
		    (label != NULL && m->sub_is_va[j] &&
		    memcmp(m->sub_label[j], label, MESH_LABEL_UUID_LEN) == 0)))
			return (MESH_CFG_SUCCESS);	/* already present */
	}
	if (m->n_subs >= MESHD_MAX_SUBS)
		return (MESH_CFG_INSUFFICIENT_RESOURCES);
	m->subs[m->n_subs] = addr;
	m->sub_is_va[m->n_subs] = (label != NULL);
	if (label != NULL)
		memcpy(m->sub_label[m->n_subs], label, MESH_LABEL_UUID_LEN);
	else
		memset(m->sub_label[m->n_subs], 0, MESH_LABEL_UUID_LEN);
	m->n_subs++;
	return (MESH_CFG_SUCCESS);
}

static int
h_model_sub(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_model_sub in;
	struct meshd_model_entry *m;
	uint32_t op;
	uint8_t status, buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_model_sub_parse(pdu, len, &op, &in) != 0)
		return (-1);
	if (!meshd_element_valid(nd, in.elem_addr))
		status = MESH_CFG_INVALID_ADDRESS;
	else if (!mesh_addr_is_group(in.address) ||
	    in.address == MESH_ADDR_ALL_NODES)
		status = MESH_CFG_INVALID_ADDRESS;
	else if ((m = meshd_find_model(nd, in.elem_addr, &in.model)) == NULL)
		status = MESH_CFG_INVALID_MODEL;
	else
		status = meshd_sub_mutate(m, op, in.address, NULL);
	if (status == MESH_CFG_SUCCESS)
		meshd_sync_subscriptions(nd);
	if (mesh_cfg_model_sub_status_build(status, &in, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_model_sub_del_all(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_model_sub st;
	struct mesh_cfg_model_id model;
	struct meshd_model_entry *m;
	uint16_t elem_addr;
	uint8_t status, buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_model_sub_del_all_parse(pdu, len, &elem_addr, &model) != 0)
		return (-1);
	if (!meshd_element_valid(nd, elem_addr))
		status = MESH_CFG_INVALID_ADDRESS;
	else if ((m = meshd_find_model(nd, elem_addr, &model)) == NULL)
		status = MESH_CFG_INVALID_MODEL;
	else {
		m->n_subs = 0;
		meshd_sync_subscriptions(nd);
		status = MESH_CFG_SUCCESS;
	}
	memset(&st, 0, sizeof(st));
	st.elem_addr = elem_addr;
	st.address = MESH_ADDR_UNASSIGNED;	/* Delete All reports 0x0000 */
	st.model = model;
	if (mesh_cfg_model_sub_status_build(status, &st, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_model_sub_va(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_model_sub_va in;
	struct mesh_cfg_model_sub st;
	struct meshd_model_entry *m;
	uint32_t op;
	uint16_t va;
	uint8_t status, buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_model_sub_va_parse(pdu, len, &op, &in) != 0)
		return (-1);
	if (mesh_virtual_addr(in.label, &va) != 0)
		return (-1);
	if (!meshd_element_valid(nd, in.elem_addr))
		status = MESH_CFG_INVALID_ADDRESS;
	else if ((m = meshd_find_model(nd, in.elem_addr, &in.model)) == NULL)
		status = MESH_CFG_INVALID_MODEL;
	else
		status = meshd_sub_mutate(m, op, va, in.label);
	if (status == MESH_CFG_SUCCESS)
		meshd_sync_subscriptions(nd);
	memset(&st, 0, sizeof(st));
	st.elem_addr = in.elem_addr;
	st.address = va;			/* derived virtual address */
	st.model = in.model;
	if (mesh_cfg_model_sub_status_build(status, &st, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_model_sub_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_model_id model;
	struct meshd_model_entry *m;
	uint32_t op, list_op;
	uint16_t elem_addr;
	uint8_t status, buf[MESH_ACCESS_PAYLOAD_MAX];
	const uint16_t *addrs = NULL;
	size_t n = 0, blen;

	(void)ap;
	if (mesh_cfg_model_sub_get_parse(pdu, len, &op, &elem_addr, &model) != 0)
		return (-1);
	list_op = (op == MESH_CFG_OP_VND_MODEL_SUB_GET) ?
	    MESH_CFG_OP_VND_MODEL_SUB_LIST : MESH_CFG_OP_SIG_MODEL_SUB_LIST;
	if (!meshd_element_valid(nd, elem_addr))
		status = MESH_CFG_INVALID_ADDRESS;
	else if ((m = meshd_find_model(nd, elem_addr, &model)) == NULL)
		status = MESH_CFG_INVALID_MODEL;
	else {
		status = MESH_CFG_SUCCESS;
		addrs = m->subs;
		n = m->n_subs;
	}
	if (mesh_cfg_model_sub_list_build(list_op, status, elem_addr, &model,
	    addrs, n, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* ---------------- Model publication ------------------------------------- */

static int
h_model_pub_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_model_id model;
	struct mesh_cfg_model_pub pub;
	struct meshd_model_entry *m;
	uint16_t elem_addr;
	uint8_t status, buf[24];
	size_t blen;

	(void)ap;
	if (mesh_cfg_model_pub_get_parse(pdu, len, &elem_addr, &model) != 0)
		return (-1);
	memset(&pub, 0, sizeof(pub));
	pub.elem_addr = elem_addr;
	pub.model = model;
	if (!meshd_element_valid(nd, elem_addr))
		status = MESH_CFG_INVALID_ADDRESS;
	else if ((m = meshd_find_model(nd, elem_addr, &model)) == NULL)
		status = MESH_CFG_INVALID_MODEL;
	else {
		status = MESH_CFG_SUCCESS;
		if (m->has_pub)
			pub = m->pub;
	}
	if (mesh_cfg_model_pub_status_build(status, &pub, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_model_pub_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_model_pub in;
	struct meshd_model_entry *m;
	uint8_t status, buf[24];
	size_t blen;

	(void)ap;
	if (mesh_cfg_model_pub_set_parse(pdu, len, &in) != 0)
		return (-1);
	if (!meshd_element_valid(nd, in.elem_addr))
		status = MESH_CFG_INVALID_ADDRESS;
	else if ((m = meshd_find_model(nd, in.elem_addr, &in.model)) == NULL)
		status = MESH_CFG_INVALID_MODEL;
	else if (in.pub_addr != MESH_ADDR_UNASSIGNED &&
	    meshd_find_appkey(nd, in.app_idx) == NULL) {
		/* Unknown AppKeyIndex -> Invalid AppKey Index, not Success: a
		 * committed pub with an unbound key silently fails every publish
		 * tick with the provisioner believing it succeeded (NB-18). */
		status = MESH_CFG_INVALID_APPKEY_INDEX;
	} else {
		m->pub = in;
		m->pub_is_va = 0;
		memset(m->pub_label, 0, sizeof(m->pub_label));
		m->next_pub_ms = 0;
		m->retransmit_left = 0;
		/* PublishAddress 0x0000 disables the publication. */
		m->has_pub = (in.pub_addr != MESH_ADDR_UNASSIGNED) ? 1 : 0;
		status = MESH_CFG_SUCCESS;
	}
	if (mesh_cfg_model_pub_status_build(status, &in, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_model_pub_va_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_model_pub_va in;
	struct mesh_cfg_model_pub pub;
	struct meshd_model_entry *m;
	uint16_t va;
	uint8_t status, buf[24];
	size_t blen;

	(void)ap;
	if (mesh_cfg_model_pub_va_set_parse(pdu, len, &in) != 0)
		return (-1);
	if (mesh_virtual_addr(in.label, &va) != 0)
		return (-1);
	memset(&pub, 0, sizeof(pub));
	pub.elem_addr = in.elem_addr;
	pub.pub_addr = va;
	pub.app_idx = in.app_idx;
	pub.cred_flag = in.cred_flag;
	pub.ttl = in.ttl;
	pub.period = in.period;
	pub.retransmit = in.retransmit;
	pub.model = in.model;
	if (!meshd_element_valid(nd, in.elem_addr))
		status = MESH_CFG_INVALID_ADDRESS;
	else if ((m = meshd_find_model(nd, in.elem_addr, &in.model)) == NULL)
		status = MESH_CFG_INVALID_MODEL;
	else if (meshd_find_appkey(nd, in.app_idx) == NULL) {
		/* Virtual publish addr is never unassigned, so the AppKeyIndex
		 * must always be valid (NB-18). */
		status = MESH_CFG_INVALID_APPKEY_INDEX;
	} else {
		m->pub = pub;
		m->has_pub = 1;
		m->pub_is_va = 1;
		memcpy(m->pub_label, in.label, sizeof(m->pub_label));
		m->next_pub_ms = 0;
		m->retransmit_left = 0;
		status = MESH_CFG_SUCCESS;
	}
	if (mesh_cfg_model_pub_status_build(status, &pub, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* ---------------- Key Refresh Phase / Node Identity --------------------- */

static int
h_kr_phase_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct meshd_netkey_entry *e;
	uint16_t net_idx;
	uint8_t status, phase, buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_kr_phase_get_parse(pdu, len, &net_idx) != 0)
		return (-1);
	e = meshd_find_netkey(nd, net_idx);
	if (e == NULL) {
		status = MESH_CFG_INVALID_NETKEY_INDEX;
		phase = MESH_CFG_KR_PHASE_0;
	} else {
		status = MESH_CFG_SUCCESS;
		phase = (uint8_t)mesh_sim_subnet_kr_phase(nd->self, net_idx);
	}
	if (mesh_cfg_kr_phase_status_build(status, net_idx, phase, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_kr_phase_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct meshd_netkey_entry *e;
	uint16_t net_idx;
	uint8_t transition, status, phase, buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_kr_phase_set_parse(pdu, len, &net_idx, &transition) != 0)
		return (-1);
	e = meshd_find_netkey(nd, net_idx);
	if (e == NULL) {
		status = MESH_CFG_INVALID_NETKEY_INDEX;
		phase = MESH_CFG_KR_PHASE_0;
	} else {
		/*
		 * Drive the real phase machine on the sim node (Section 3.11.4):
		 * Transition 2 moves Phase 1 -> 2 (start transmitting with the new
		 * key); Transition 3 finishes by revoking the old key and promoting
		 * the new one to the sole current key (finalize).
		 */
		status = MESH_CFG_SUCCESS;
		if (transition == MESH_CFG_KR_TRANSITION_2)
			(void)meshd_kr_advance_idx(nd, net_idx);
		else if (transition == MESH_CFG_KR_TRANSITION_3)
			(void)meshd_kr_finish_idx(nd, net_idx);
		phase = (uint8_t)mesh_sim_subnet_kr_phase(nd->self, net_idx);
	}
	if (mesh_cfg_kr_phase_status_build(status, net_idx, phase, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_node_identity_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct meshd_netkey_entry *e;
	uint16_t net_idx;
	uint8_t status, identity, buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_node_identity_get_parse(pdu, len, &net_idx) != 0)
		return (-1);
	e = meshd_find_netkey(nd, net_idx);
	status = (e != NULL) ? MESH_CFG_SUCCESS : MESH_CFG_INVALID_NETKEY_INDEX;
	identity = (e != NULL) ? e->node_identity :
	    MESH_CFG_NODE_IDENTITY_STOPPED;
	if (mesh_cfg_node_identity_status_build(status, net_idx, identity, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_node_identity_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct meshd_netkey_entry *e;
	uint16_t net_idx;
	uint8_t identity, status, buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_node_identity_set_parse(pdu, len, &net_idx, &identity) != 0)
		return (-1);
	e = meshd_find_netkey(nd, net_idx);
	if (e == NULL)
		status = MESH_CFG_INVALID_NETKEY_INDEX;
	else {
		if (identity == MESH_CFG_NODE_IDENTITY_STOPPED ||
		    identity == MESH_CFG_NODE_IDENTITY_RUNNING)
			e->node_identity = identity;
		status = MESH_CFG_SUCCESS;
		identity = e->node_identity;
	}
	if (mesh_cfg_node_identity_status_build(status, net_idx, identity, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_lpn_polltimeout_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint16_t lpn_addr;
	uint8_t buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_lpn_polltimeout_get_parse(pdu, len, &lpn_addr) != 0)
		return (-1);
	/* No Friend feature / no LPN: PollTimeout is 0 (MshMDL 4.4.1). */
	if (mesh_cfg_lpn_polltimeout_status_build(lpn_addr,
	    nd->db.lpn_poll_timeout, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* ---------------- Heartbeat Publication / Subscription ------------------ */

static int
h_hb_pub_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint8_t buf[16];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	if (mesh_hb_pub_status_build(MESH_CFG_SUCCESS, &nd->db.hb_pub, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_hb_pub_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_hb_pub in;
	uint8_t status, buf[16];
	size_t blen;

	uint8_t scratch[16];
	size_t slen;

	(void)ap;
	if (mesh_hb_pub_set_parse(pdu, len, &in) != 0)
		return (-1);
	/*
	 * Reject prohibited field values (ttl>0x7f, bad count/period log, etc.)
	 * BEFORE committing: mesh_hb_pub_set_parse does no range validation, and
	 * the old code stored `in` and only then discovered the poison when
	 * mesh_hb_pub_status_build failed -- leaving nd->db.hb_pub corrupt so
	 * every later HB Pub Get/Status build failed forever (NB-28).  Packing
	 * to a scratch buffer runs the same range checks without touching state.
	 */
	if (mesh_hb_pub_status_build(MESH_CFG_SUCCESS, &in, scratch, &slen) != 0)
		return (-1);
	if (in.dst != MESH_ADDR_UNASSIGNED &&
	    meshd_find_netkey(nd, in.net_idx) == NULL)
		status = MESH_CFG_INVALID_NETKEY_INDEX;
	else {
		nd->db.hb_pub = in;
		status = MESH_CFG_SUCCESS;
		/*
		 * Load the publication into the sim so the periodic Heartbeat
		 * timer actually arms; without this the config DB records the
		 * publication but nothing is ever transmitted (finding 54).
		 */
		mesh_sim_hb_set_pub(nd->self, in.dst, in.count_log, in.period_log,
		    in.ttl, in.features, meshd_features(nd));
	}
	if (mesh_hb_pub_status_build(status, &nd->db.hb_pub, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_hb_sub_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_hb_sub_status st;
	uint8_t buf[16];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	mesh_hb_sub_snapshot(&nd->db.hb_sub, MESH_CFG_SUCCESS, &st);
	if (mesh_hb_sub_status_build(&st, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_hb_sub_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_hb_sub_set in;
	struct mesh_hb_sub_status st;
	uint8_t status, buf[16];
	size_t blen;

	(void)ap;
	if (mesh_hb_sub_set_parse(pdu, len, &in) != 0)
		return (-1);
	status = (mesh_hb_sub_apply(&nd->db.hb_sub, &in) == 0) ?
	    MESH_CFG_SUCCESS : MESH_CFG_INVALID_ADDRESS;
	if (status == MESH_CFG_SUCCESS)
		/*
		 * Arm the sim's subscription counter; without this hb_sub_active
		 * stays 0 and received Heartbeats are never counted (finding 54).
		 */
		mesh_sim_hb_set_sub(nd->self, in.src, in.dst, in.period_log);
	mesh_hb_sub_snapshot(&nd->db.hb_sub, status, &st);
	if (mesh_hb_sub_status_build(&st, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* ---------------- Health Server ----------------------------------------- */

static int
h_hlt_attention_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint8_t buf[8];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	if (mesh_hlt_attention_build(MESH_HLT_OP_ATTENTION_STATUS,
	    nd->health.attention, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_hlt_attention_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint32_t op;
	uint8_t v, buf[8];
	size_t blen;

	(void)ap;
	if (mesh_hlt_attention_parse(pdu, len, &op, &v) != 0)
		return (-1);
	nd->health.attention = v;
	if (mesh_hlt_attention_build(MESH_HLT_OP_ATTENTION_STATUS, v, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_hlt_period_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint8_t buf[8];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	if (mesh_hlt_period_build(MESH_HLT_OP_PERIOD_STATUS,
	    nd->health.fast_period_divisor, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_hlt_period_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint32_t op;
	uint8_t div, buf[8];
	size_t blen;

	(void)ap;
	if (mesh_hlt_period_parse(pdu, len, &op, &div) != 0)
		return (-1);
	if (div > 15)
		return (-1);
	nd->health.fast_period_divisor = div;
	if (mesh_hlt_period_build(MESH_HLT_OP_PERIOD_STATUS, div, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* Snapshot the registered fault array into a Fault Status structure. */
static int
meshd_fault_snapshot(struct meshd_node *nd, struct mesh_hlt_fault_status *fs)
{

	memset(fs, 0, sizeof(*fs));
	fs->test_id = nd->health.test_id;
	fs->company_id = nd->health.company_id;
	/*
	 * P-M14: Health Fault Status reports the Registered Fault array (which
	 * persists across Current-fault clearing), not the Current faults.
	 */
	if (nd->health.n_registered_faults > MESH_HLT_MAX_FAULTS)
		return (-1);
	memcpy(fs->faults, nd->health.registered_faults,
	    nd->health.n_registered_faults);
	fs->n_faults = nd->health.n_registered_faults;
	return (0);
}

static int
h_hlt_fault_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_hlt_fault_status fs;
	uint16_t company;
	uint8_t buf[MESH_ACCESS_PAYLOAD_MAX];
	size_t blen;

	(void)ap;
	if (mesh_hlt_fault_get_parse(pdu, len, &company) != 0)
		return (-1);
	/*
	 * The node holds Health Fault state only for its own Company ID; a Get
	 * naming any other CID identifies no fault state and MUST be ignored
	 * with no Status (MshPRT_v1.1 Section 4.4.3.2.2, finding 106).  When it
	 * matches, the snapshot echoes that same CID.
	 */
	if (company != nd->health.company_id)
		return (0);
	if (meshd_fault_snapshot(nd, &fs) != 0)
		return (-1);
	if (mesh_hlt_fault_status_build(&fs, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_hlt_fault_clear(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_hlt_fault_status fs;
	uint32_t op;
	uint16_t company;
	uint8_t buf[MESH_ACCESS_PAYLOAD_MAX];
	size_t blen;

	(void)ap;
	if (mesh_hlt_fault_clear_parse(pdu, len, &op, &company) != 0)
		return (-1);
	/* Unknown CID: no fault state to clear, ignore silently (finding 106). */
	if (company != nd->health.company_id)
		return (0);
	mesh_hlt_server_clear_faults(&nd->health);
	if (op == MESH_HLT_OP_FAULT_CLEAR_UNREL)
		return (0);		/* unacknowledged: no Status */
	if (meshd_fault_snapshot(nd, &fs) != 0)
		return (-1);
	if (mesh_hlt_fault_status_build(&fs, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_hlt_fault_test(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_hlt_fault_status fs;
	uint32_t op;
	uint16_t company;
	uint8_t test_id, buf[MESH_ACCESS_PAYLOAD_MAX];
	size_t blen;

	(void)ap;
	if (mesh_hlt_fault_test_parse(pdu, len, &op, &test_id, &company) != 0)
		return (-1);
	/* Unknown CID: no fault state to test, ignore silently (finding 106). */
	if (company != nd->health.company_id)
		return (0);
	nd->health.test_id = test_id;
	if (op == MESH_HLT_OP_FAULT_TEST_UNREL)
		return (0);		/* unacknowledged: no Status */
	if (meshd_fault_snapshot(nd, &fs) != 0)
		return (-1);
	if (mesh_hlt_fault_status_build(&fs, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* ---------------- Mesh 1.1 Configuration models (MshMDL Section 4) ------- */

static int
h_sar_tx_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint8_t buf[16];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	if (mesh_cfg_sar_tx_build(MESH_CFG_OP_SAR_TRANSMITTER_STATUS, &nd->db.sar_tx,
	    buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_sar_tx_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_sar_transmitter tx;
	uint8_t buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_sar_tx_parse(pdu, len, NULL, &tx) != 0)
		return (-1);
	nd->db.sar_tx = tx;
	if (mesh_cfg_sar_tx_build(MESH_CFG_OP_SAR_TRANSMITTER_STATUS, &nd->db.sar_tx,
	    buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_sar_rx_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint8_t buf[16];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	if (mesh_cfg_sar_rx_build(MESH_CFG_OP_SAR_RECEIVER_STATUS, &nd->db.sar_rx,
	    buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_sar_rx_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_sar_receiver rx;
	uint8_t buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_sar_rx_parse(pdu, len, NULL, &rx) != 0)
		return (-1);
	nd->db.sar_rx = rx;
	if (mesh_cfg_sar_rx_build(MESH_CFG_OP_SAR_RECEIVER_STATUS, &nd->db.sar_rx,
	    buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_od_priv_proxy_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint8_t buf[8];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	if (mesh_cfg_od_priv_proxy_build(MESH_CFG_OP_OD_PRIV_PROXY_STATUS,
	    nd->db.od_priv_proxy, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_od_priv_proxy_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint8_t v, buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_od_priv_proxy_parse(pdu, len, NULL, &v) != 0)
		return (-1);
	nd->db.od_priv_proxy = v;
	if (mesh_cfg_od_priv_proxy_build(MESH_CFG_OP_OD_PRIV_PROXY_STATUS,
	    nd->db.od_priv_proxy, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_priv_beacon_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_priv_beacon pb;
	uint8_t buf[8];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	memset(&pb, 0, sizeof(pb));
	pb.private_beacon = nd->db.priv_beacon;
	pb.random_update_interval_steps = nd->db.priv_beacon_random_steps;
	if (mesh_cfg_priv_beacon_status_build(&pb, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_priv_beacon_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_priv_beacon pb;
	uint8_t buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_priv_beacon_set_parse(pdu, len, &pb) != 0)
		return (-1);
	nd->db.priv_beacon = pb.private_beacon ? 1 : 0;
	if (pb.has_random_update)
		nd->db.priv_beacon_random_steps = pb.random_update_interval_steps;
	pb.private_beacon = nd->db.priv_beacon;
	pb.random_update_interval_steps = nd->db.priv_beacon_random_steps;
	if (mesh_cfg_priv_beacon_status_build(&pb, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_priv_gatt_proxy_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint8_t buf[8];
	size_t blen;

	(void)ap; (void)pdu; (void)len;
	if (mesh_cfg_priv_gatt_proxy_build(MESH_CFG_OP_PRIV_GATT_PROXY_STATUS,
	    nd->db.priv_gatt_proxy, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_priv_gatt_proxy_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint8_t v, buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_priv_gatt_proxy_parse(pdu, len, NULL, &v) != 0)
		return (-1);
	if (v > 1)
		return (-1);
	nd->db.priv_gatt_proxy = v;
	if (mesh_cfg_priv_gatt_proxy_build(MESH_CFG_OP_PRIV_GATT_PROXY_STATUS,
	    nd->db.priv_gatt_proxy, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_priv_node_identity_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_priv_node_identity id;
	struct meshd_netkey_entry *e;
	uint16_t net_idx;
	uint8_t status, buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_priv_node_identity_get_parse(pdu, len, &net_idx) != 0)
		return (-1);
	e = meshd_find_netkey(nd, net_idx);
	status = (e != NULL) ? MESH_CFG_SUCCESS : MESH_CFG_INVALID_NETKEY_INDEX;
	memset(&id, 0, sizeof(id));
	id.net_idx = net_idx;
	id.identity = (e != NULL) ? e->priv_node_identity :
	    MESH_CFG_PRIV_IDENTITY_STOPPED;
	if (mesh_cfg_priv_node_identity_status_build(status, &id, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_priv_node_identity_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_priv_node_identity id;
	struct meshd_netkey_entry *e;
	uint8_t status, buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_priv_node_identity_set_parse(pdu, len, &id) != 0)
		return (-1);
	e = meshd_find_netkey(nd, id.net_idx);
	if (e == NULL)
		status = MESH_CFG_INVALID_NETKEY_INDEX;
	else {
		if (id.identity == MESH_CFG_PRIV_IDENTITY_STOPPED ||
		    id.identity == MESH_CFG_PRIV_IDENTITY_RUNNING)
			e->priv_node_identity = id.identity;
		id.identity = e->priv_node_identity;
		status = MESH_CFG_SUCCESS;
	}
	if (mesh_cfg_priv_node_identity_status_build(status, &id, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_sol_pdu_rpl_clear(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_addr_range r;
	uint32_t op;
	uint8_t buf[8];
	size_t blen;

	(void)ap;
	if (mesh_cfg_sol_pdu_rpl_clear_parse(pdu, len, &op, &r) != 0)
		return (-1);
	/* Clear the solicitation RPL entries in the range and record it. */
	nd->db.sol_pdu_rpl_last = r;
	if (op == MESH_CFG_OP_SOL_PDU_RPL_ITEMS_CLEAR_UNACK)
		return (0);		/* unacknowledged: no Status */
	if (mesh_cfg_sol_pdu_rpl_status_build(&r, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* Fill buf with the node's Large Composition Data page blob; -1 on error. */
static int
meshd_lcd_blob(struct meshd_node *nd, uint8_t page, uint8_t *buf, size_t cap,
    size_t *blen)
{
	struct mesh_cfg_comp_page0 comp;

	if (page != 0)
		return (-1);
	meshd_comp_fill(&comp, nd);
	if (mesh_cfg_comp_page0_encode(&comp, buf, blen) != 0)
		return (-1);
	if (*blen > cap)
		return (-1);
	return (0);
}

/* Large Composition Data Get / Models Metadata Get: offset-addressed page. */
static int
h_lcd_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_lcd_get get;
	struct mesh_cfg_lcd_status st;
	uint8_t blob[MESH_CFG_LCD_DATA_MAX];
	uint8_t buf[MESH_ACCESS_PAYLOAD_MAX];
	size_t bloblen, chunk, blen;
	uint32_t op, status_op;

	(void)ap;
	if (mesh_cfg_lcd_get_parse(pdu, len, &op, &get) != 0)
		return (-1);
	memset(&st, 0, sizeof(st));
	st.page = get.page;
	st.offset = get.offset;

	if (op == MESH_CFG_OP_MODELS_METADATA_GET) {
		/* This node advertises no models metadata: an empty page. */
		status_op = MESH_CFG_OP_MODELS_METADATA_STATUS;
		st.total_size = 0;
		st.data_len = 0;
	} else {
		status_op = MESH_CFG_OP_LARGE_COMP_DATA_STATUS;
		if (meshd_lcd_blob(nd, get.page, blob, sizeof(blob),
		    &bloblen) != 0)
			return (-1);
		st.total_size = (uint16_t)bloblen;
		if (get.offset >= bloblen)
			st.data_len = 0;	/* offset past the end: no data */
		else {
			chunk = bloblen - get.offset;
			if (chunk > MESH_CFG_LCD_DATA_MAX)
				chunk = MESH_CFG_LCD_DATA_MAX;
			memcpy(st.data, blob + get.offset, chunk);
			st.data_len = chunk;
		}
	}
	if (mesh_cfg_lcd_status_build(status_op, &st, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/*
 * Opcodes Aggregator Sequence: dispatch each aggregated Access PDU through the
 * foundation-model handler and pack each response as an Aggregator Status item
 * (an empty item for a message handled without a reply).
 */
static int
h_aggregator_seq(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_agg_item items[MESH_CFG_AGG_MAX_ITEMS];
	struct mesh_cfg_agg_item resp[MESH_CFG_AGG_MAX_ITEMS];
	uint8_t respbuf[MESH_CFG_AGG_MAX_ITEMS][160];
	uint8_t buf[MESH_ACCESS_PAYLOAD_MAX];
	uint16_t elem;
	uint8_t status = MESH_CFG_SUCCESS;
	size_t nitems, i, blen;

	(void)ap;
	if (mesh_cfg_agg_seq_parse(pdu, len, &elem, items, MESH_CFG_AGG_MAX_ITEMS,
	    &nitems) != 0)
		return (-1);
	if (elem != nd->addr)
		status = MESH_CFG_INVALID_ADDRESS;

	for (i = 0; i < nitems; i++) {
		struct mesh_access_pdu iap;
		size_t rl = 0;

		resp[i].data = NULL;
		resp[i].len = 0;
		if (status != MESH_CFG_SUCCESS || items[i].len == 0)
			continue;
		/*
		 * An aggregated item may not itself be an Opcodes Aggregator
		 * Sequence: h_aggregator_seq() and meshd_foundation_recv() are
		 * mutually recursive with no depth bound, so a nested aggregator
		 * would let a DevKey peer drive unbounded recursion (finding C-m4).
		 * Reject it as an unhandled item (empty response) without
		 * dispatching.
		 */
		if (mesh_access_pdu_parse(items[i].data, items[i].len, &iap) == 0 &&
		    iap.opcode == MESH_CFG_OP_AGGREGATOR_SEQUENCE)
			continue;
		if (meshd_foundation_recv(nd, items[i].data, items[i].len,
		    respbuf[i], sizeof(respbuf[i]), &rl) == 1) {
			resp[i].data = respbuf[i];
			resp[i].len = rl;
		}
	}
	if (mesh_cfg_agg_status_build(status, elem, resp, nitems, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* ================================================================
 * Directed Forwarding Configuration Server (finding 129, MshMDL_v1.1
 * Section 4.4.3).  Each sub-state answers Get with the stored value and Set by
 * storing the request and echoing a SUCCESS Status, mirroring the node-wide
 * Configuration states above.  A single primary-subnet instance is kept; the
 * request's NetKeyIndex is echoed back.
 * ================================================================ */

static int
h_df_control_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_directed_control c;
	uint16_t net_idx;
	uint8_t buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_directed_control_get_parse(pdu, len, &net_idx) != 0)
		return (-1);
	c = nd->df.control;
	c.net_idx = net_idx;
	if (mesh_cfg_directed_control_status_build(MESH_CFG_STATUS_SUCCESS, &c,
	    buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_df_control_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_directed_control c;
	uint8_t buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_directed_control_set_parse(pdu, len, &c) != 0)
		return (-1);
	nd->df.control = c;
	/* Turning Directed Forwarding on enables the sim node's DF roles. */
	if (c.directed_forwarding)
		meshd_df_enable(nd);
	if (mesh_cfg_directed_control_status_build(MESH_CFG_STATUS_SUCCESS, &c,
	    buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_df_metric_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_path_metric m;
	uint16_t net_idx;
	uint8_t buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_directed_control_get_parse(pdu, len, &net_idx) != 0)
		return (-1);
	m = nd->df.metric;
	m.net_idx = net_idx;
	if (mesh_cfg_path_metric_status_build(MESH_CFG_STATUS_SUCCESS, &m, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_df_metric_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_path_metric m;
	uint8_t buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_path_metric_set_parse(pdu, len, &m) != 0)
		return (-1);
	nd->df.metric = m;
	if (mesh_cfg_path_metric_status_build(MESH_CFG_STATUS_SUCCESS, &m, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_df_lanes_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_wanted_lanes l;
	uint16_t net_idx;
	uint8_t buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_directed_control_get_parse(pdu, len, &net_idx) != 0)
		return (-1);
	l = nd->df.lanes;
	l.net_idx = net_idx;
	if (mesh_cfg_wanted_lanes_status_build(MESH_CFG_STATUS_SUCCESS, &l, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_df_lanes_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_wanted_lanes l;
	uint8_t buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_wanted_lanes_set_parse(pdu, len, &l) != 0)
		return (-1);
	nd->df.lanes = l;
	if (mesh_cfg_wanted_lanes_status_build(MESH_CFG_STATUS_SUCCESS, &l, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_df_two_way_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_two_way_path t;
	uint16_t net_idx;
	uint8_t buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_directed_control_get_parse(pdu, len, &net_idx) != 0)
		return (-1);
	t = nd->df.two_way;
	t.net_idx = net_idx;
	if (mesh_cfg_two_way_path_status_build(MESH_CFG_STATUS_SUCCESS, &t, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_df_two_way_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_two_way_path t;
	uint8_t buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_two_way_path_set_parse(pdu, len, &t) != 0)
		return (-1);
	nd->df.two_way = t;
	if (mesh_cfg_two_way_path_status_build(MESH_CFG_STATUS_SUCCESS, &t, buf,
	    &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_df_echo_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_path_echo_interval e;
	uint16_t net_idx;
	uint8_t buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_directed_control_get_parse(pdu, len, &net_idx) != 0)
		return (-1);
	e = nd->df.echo;
	e.net_idx = net_idx;
	if (mesh_cfg_path_echo_interval_status_build(MESH_CFG_STATUS_SUCCESS, &e,
	    buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_df_echo_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_path_echo_interval e;
	uint8_t buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_path_echo_interval_set_parse(pdu, len, &e) != 0)
		return (-1);
	nd->df.echo = e;
	if (mesh_cfg_path_echo_interval_status_build(MESH_CFG_STATUS_SUCCESS, &e,
	    buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_df_transmit_get(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_transmit t;
	uint32_t status_op;
	uint8_t buf[16];
	size_t blen;

	(void)pdu; (void)len;
	if (ap->opcode == MESH_CFG_OP_DIRECTED_NET_TRANSMIT_GET) {
		t = nd->df.net_transmit;
		status_op = MESH_CFG_OP_DIRECTED_NET_TRANSMIT_STATUS;
	} else {
		t = nd->df.relay_retransmit;
		status_op = MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_STATUS;
	}
	if (mesh_cfg_directed_transmit_build(status_op, &t, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

static int
h_df_transmit_set(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	struct mesh_cfg_transmit t;
	uint32_t op, status_op;
	uint8_t buf[16];
	size_t blen;

	(void)ap;
	if (mesh_cfg_directed_transmit_parse(pdu, len, &op, &t) != 0)
		return (-1);
	if (op == MESH_CFG_OP_DIRECTED_NET_TRANSMIT_SET) {
		nd->df.net_transmit = t;
		status_op = MESH_CFG_OP_DIRECTED_NET_TRANSMIT_STATUS;
	} else if (op == MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_SET) {
		nd->df.relay_retransmit = t;
		status_op = MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_STATUS;
	} else
		return (-1);
	if (mesh_cfg_directed_transmit_build(status_op, &t, buf, &blen) != 0)
		return (-1);
	return (meshd_emit(buf, blen, reply, reply_max, reply_len));
}

/* ================================================================
 * Remote Provisioning Server model (finding 128, MshPRT_v1.1 Section 5.4.4).
 * Answers the synchronous Scan / Link control requests via the scan-server and
 * server-link FSMs.  The PDU-tunnel (PDU Send -> Outbound PDU Report) drives the
 * server-link FSM in a loopback fashion (meshd-as-server has no separate device
 * bearer wired), committing the transfer immediately so the FSM numbering and
 * state transitions are exercised end to end.  Reports (Scan Report, PDU Report,
 * Link Report) are unsolicited server-originated and are produced by the driver
 * helpers, not from this synchronous request path.
 * ================================================================ */
int
meshd_rpr_server_recv(struct meshd_node *nd, const struct mesh_access_pdu *ap,
    const uint8_t *pdu, size_t len, uint8_t *reply, size_t reply_max,
    size_t *reply_len)
{
	uint8_t buf[MESH_RP_MSG_MAX];
	size_t blen;
	uint64_t now;

	if (nd == NULL || ap == NULL || pdu == NULL || reply == NULL ||
	    reply_len == NULL)
		return (-1);
	now = nd->sim.now_ms;
	*reply_len = 0;

	switch (ap->opcode) {
	case MESH_RP_OP_SCAN_CAPABILITIES_GET: {
		struct mesh_rp_scan_caps caps;

		mesh_rp_scan_server_caps(&nd->rpr.scan_server, &caps);
		if (mesh_rp_scan_caps_status_build(&caps, buf, &blen) != 0)
			return (-1);
		return (meshd_emit(buf, blen, reply, reply_max, reply_len));
	}
	case MESH_RP_OP_SCAN_GET: {
		struct mesh_rp_scan_status st;

		mesh_rp_scan_server_status(&nd->rpr.scan_server, now, &st);
		if (mesh_rp_scan_status_build(&st, buf, &blen) != 0)
			return (-1);
		return (meshd_emit(buf, blen, reply, reply_max, reply_len));
	}
	case MESH_RP_OP_SCAN_START: {
		struct mesh_rp_scan_start req;
		struct mesh_rp_scan_status st;

		if (mesh_rp_scan_start_parse(pdu, len, &req) != 0)
			return (-1);
		(void)mesh_rp_scan_server_start(&nd->rpr.scan_server, &req, now,
		    &st);
		if (mesh_rp_scan_status_build(&st, buf, &blen) != 0)
			return (-1);
		return (meshd_emit(buf, blen, reply, reply_max, reply_len));
	}
	case MESH_RP_OP_SCAN_STOP: {
		struct mesh_rp_scan_status st;

		(void)mesh_rp_scan_server_stop(&nd->rpr.scan_server, now, &st);
		if (mesh_rp_scan_status_build(&st, buf, &blen) != 0)
			return (-1);
		return (meshd_emit(buf, blen, reply, reply_max, reply_len));
	}
	case MESH_RP_OP_LINK_GET: {
		struct mesh_rp_link_status st;

		mesh_rp_server_link_status(&nd->rpr.server_link, &st);
		if (mesh_rp_link_status_build(&st, buf, &blen) != 0)
			return (-1);
		return (meshd_emit(buf, blen, reply, reply_max, reply_len));
	}
	case MESH_RP_OP_LINK_OPEN: {
		struct mesh_rp_link_open op;
		struct mesh_rp_link_status st;

		if (mesh_rp_link_open_parse(pdu, len, &op) != 0)
			return (-1);
		(void)mesh_rp_server_link_on_open(&nd->rpr.server_link, &op,
		    &st);
		if (mesh_rp_link_status_build(&st, buf, &blen) != 0)
			return (-1);
		return (meshd_emit(buf, blen, reply, reply_max, reply_len));
	}
	case MESH_RP_OP_LINK_CLOSE: {
		struct mesh_rp_link_report rp;
		struct mesh_rp_link_status st;
		uint8_t reason;

		if (mesh_rp_link_close_parse(pdu, len, &reason) != 0)
			return (-1);
		(void)mesh_rp_server_link_on_close(&nd->rpr.server_link, reason,
		    &rp);
		/*
		 * The acknowledged response to Remote Provisioning Link Close is
		 * a Link Status (MshPRT 4.4.5); Link Report is the SEPARATE
		 * unsolicited state-change report.  Previously this replied with
		 * a Link Report, which a conformant client (expecting Link
		 * Status) ignores (NB-30).
		 */
		mesh_rp_server_link_status(&nd->rpr.server_link, &st);
		if (mesh_rp_link_status_build(&st, buf, &blen) != 0)
			return (-1);
		return (meshd_emit(buf, blen, reply, reply_max, reply_len));
	}
	case MESH_RP_OP_PDU_SEND: {
		struct mesh_rp_pdu_send snd;
		uint8_t prov[MESH_RP_PROV_PDU_MAX];
		size_t plen;
		uint8_t outrep;

		if (mesh_rp_pdu_send_parse(pdu, len, &snd) != 0)
			return (-1);
		/* on_pdu_send returns 0 (new PDU delivered) / 1 (duplicate). */
		if (mesh_rp_server_link_on_pdu_send(&nd->rpr.server_link, &snd,
		    prov, &plen, &outrep) != 0 || plen == 0)
			return (0);		/* duplicate / out of order: no ack */
		/* Loopback: no downstream device bearer -> commit immediately. */
		if (mesh_rp_server_link_pdu_delivered(&nd->rpr.server_link, 1,
		    &outrep, NULL) != 0)
			return (0);
		if (mesh_rp_pdu_outbound_report_build(outrep, buf, &blen) != 0)
			return (-1);
		return (meshd_emit(buf, blen, reply, reply_max, reply_len));
	}
	default:
		return (0);		/* not a synchronous RPR Server request */
	}
}

/*
 * Seal an RPR access message under this node's DevKey and transmit it to dst
 * (the RPR Client) over the bearer - the unsolicited Report emit primitive.
 * The Client opens it with this node's DevKey held in its roster.
 */
static int
meshd_rpr_emit(struct meshd_node *nd, uint16_t dst, const uint8_t *access,
    size_t access_len)
{
	uint8_t upper[MESH_ACCESS_PAYLOAD_MAX + 8];
	size_t ulen;
	uint32_t seq0, iv;
	int n;

	if (nd == NULL || nd->self == NULL || !nd->have_local_devkey ||
	    dst == 0x0000 || access == NULL || access_len == 0 ||
	    access_len > MESH_ACCESS_PAYLOAD_MAX)
		return (-1);
	if (nd->bearer == NULL || nd->bearer->tx == NULL)
		return (-1);
	seq0 = mesh_sim_node_seq(nd->self);
	/*
	 * Device-key nonce IV must match the network-layer securing IV
	 * (mesh_sim_send_upper uses mesh_iv_tx_index), not the raw new index:
	 * during an IV Update mesh_sim_node_iv returns the new index while the
	 * network layer uses the old one, making the message undecryptable
	 * (NB-5).
	 */
	iv = mesh_iv_tx_index(&nd->self->iv);
	if (mesh_upper_encrypt(nd->local_devkey, 0, 0, seq0, nd->addr, dst, iv,
	    NULL, access, access_len, upper, &ulen) != 0)
		return (-1);
	n = mesh_sim_send_upper(&nd->sim, nd->self, dst, seq0, upper, ulen, 0, 0,
	    nd->cfg.default_ttl);
	if (n < 0)
		return (-1);
	nd->self->seq = seq0 + (uint32_t)n;
	meshd_drain_tx(nd);
	return (0);
}

/* Record an inbound Report in the client-side ring for "remote-prov reports". */
static void
meshd_rpr_buffer(struct meshd_node *nd, uint32_t opcode, uint16_t src,
    const uint8_t *data, size_t len)
{
	struct meshd_rpr_report *r;

	r = &nd->rpr.reports[nd->rpr.report_head];
	if (len > sizeof(r->data))
		len = sizeof(r->data);
	r->opcode = opcode;
	r->src = src;
	r->len = len;
	if (len > 0)
		memcpy(r->data, data, len);
	nd->rpr.report_head = (nd->rpr.report_head + 1) % MESHD_RPR_MAX_REPORTS;
	nd->rpr.n_reports++;
}

int
meshd_rpr_server_report_scan(struct meshd_node *nd, const uint8_t uuid[16],
    uint16_t oob, int8_t rssi, uint64_t now)
{
	struct mesh_rp_scan_report rep;
	uint8_t access[MESH_RP_MSG_MAX];
	size_t alen;
	int emit = 0;

	if (nd == NULL || uuid == NULL || nd->rpr.client_addr == 0x0000)
		return (-1);
	if (mesh_rp_scan_server_device_seen(&nd->rpr.scan_server, uuid, oob,
	    rssi, now, &rep, &emit) != 0)
		return (-1);
	if (!emit)
		return (0);
	if (mesh_rp_scan_report_build(&rep, access, &alen) != 0)
		return (-1);
	if (meshd_rpr_emit(nd, nd->rpr.client_addr, access, alen) != 0)
		return (-1);
	return (1);
}

int
meshd_rpr_server_report_bearer(struct meshd_node *nd)
{
	struct mesh_rp_link_report rep;
	uint8_t access[MESH_RP_MSG_MAX];
	size_t alen;

	if (nd == NULL || nd->rpr.client_addr == 0x0000)
		return (-1);
	if (mesh_rp_server_link_bearer_open(&nd->rpr.server_link, &rep) != 0)
		return (0);			/* not OPENING: nothing to report */
	if (mesh_rp_link_report_build(&rep, access, &alen) != 0)
		return (-1);
	if (meshd_rpr_emit(nd, nd->rpr.client_addr, access, alen) != 0)
		return (-1);
	return (1);
}

int
meshd_rpr_server_report_pdu(struct meshd_node *nd, const uint8_t *prov_pdu,
    size_t len)
{
	struct mesh_rp_pdu_report rep;
	uint8_t access[MESH_RP_MSG_MAX];
	size_t alen;

	if (nd == NULL || prov_pdu == NULL || nd->rpr.client_addr == 0x0000)
		return (-1);
	if (mesh_rp_server_link_report_pdu(&nd->rpr.server_link, prov_pdu, len,
	    &rep) != 0)
		return (-1);
	if (mesh_rp_pdu_report_build(&rep, access, &alen) != 0)
		return (-1);
	if (meshd_rpr_emit(nd, nd->rpr.client_addr, access, alen) != 0)
		return (-1);
	return (1);
}

int
meshd_rpr_client_send_pdu(struct meshd_node *nd, const uint8_t *prov_pdu,
    size_t len, uint64_t now)
{
	uint8_t access[MESH_RP_MSG_MAX];
	size_t alen;

	(void)now;
	if (nd == NULL || prov_pdu == NULL)
		return (-1);
	if (!nd->mgr_active || nd->mgr == NULL || nd->rpr.server_addr == 0x0000)
		return (-1);
	if (mesh_rp_client_link_send_pdu(&nd->rpr.client_link, prov_pdu, len,
	    access, &alen) != 0)
		return (-1);
	/*
	 * PDU Send is sealed under the Server's DevKey and transmitted without a
	 * Config-Client transaction: the Server answers with a PDU Outbound
	 * Report which returns unsolicited through meshd_rpr_client_rx.
	 */
	return (meshd_send_devkey_raw(nd, nd->rpr.server_addr, 1,
	    nd->mgr->netkey_index, access, alen));
}

int
meshd_rpr_client_rx(struct meshd_node *nd, uint32_t seq, uint16_t src,
    uint16_t dst, const uint8_t *upper, size_t upper_len)
{
	struct mesh_mgr_node *node;
	struct mesh_access_pdu ap;
	uint8_t plain[MESH_ACCESS_MAX];
	size_t plen;

	if (nd == NULL || upper == NULL)
		return (-1);
	if (!nd->mgr_active || nd->mgr == NULL)
		return (0);
	node = mesh_mgr_find_by_addr(nd->mgr, src);
	if (node == NULL)
		return (0);
	plen = sizeof(plain);
	if (mesh_mgr_devkey_open(nd->mgr, node, seq, src, dst, upper, upper_len,
	    plain, &plen) != 0)
		return (0);
	if (mesh_access_pdu_parse(plain, plen, &ap) != 0)
		return (0);

	switch (ap.opcode) {
	case MESH_RP_OP_SCAN_REPORT: {
		struct mesh_rp_scan_report rep;

		if (mesh_rp_scan_report_parse(plain, plen, &rep) != 0)
			return (0);
		(void)mesh_rp_scan_client_on_report(&nd->rpr.scan_client, &rep);
		meshd_rpr_buffer(nd, ap.opcode, src, rep.uuid, sizeof(rep.uuid));
		return (1);
	}
	case MESH_RP_OP_LINK_REPORT: {
		struct mesh_rp_link_report rep;
		uint8_t d[2];

		if (mesh_rp_link_report_parse(plain, plen, &rep) != 0)
			return (0);
		(void)mesh_rp_client_link_on_report(&nd->rpr.client_link, &rep);
		nd->rpr.client_active =
		    mesh_rp_client_link_is_active(&nd->rpr.client_link);
		d[0] = rep.status;
		d[1] = rep.rp_state;
		meshd_rpr_buffer(nd, ap.opcode, src, d, sizeof(d));
		return (1);
	}
	case MESH_RP_OP_PDU_OUTBOUND_REPORT: {
		uint8_t num;

		if (mesh_rp_pdu_outbound_report_parse(plain, plen, &num) != 0)
			return (0);
		(void)mesh_rp_client_link_on_outbound_report(
		    &nd->rpr.client_link, num);
		meshd_rpr_buffer(nd, ap.opcode, src, &num, 1);
		return (1);
	}
	case MESH_RP_OP_PDU_REPORT: {
		struct mesh_rp_pdu_report rep;
		uint8_t prov[MESH_RP_PROV_PDU_MAX];
		size_t pl = sizeof(prov);

		if (mesh_rp_pdu_report_parse(plain, plen, &rep) != 0)
			return (0);
		if (mesh_rp_client_link_on_pdu_report(&nd->rpr.client_link, &rep,
		    prov, &pl) != 0)
			return (0);
		memcpy(nd->rpr.inbound_pdu, prov, pl);
		nd->rpr.inbound_pdu_len = pl;
		meshd_rpr_buffer(nd, ap.opcode, src, prov, pl);
		return (1);
	}
	default:
		return (0);
	}
}

/* (Re)initialise the DF + RPR model state on (re)provision. */
static void
meshd_df_rpr_init(struct meshd_node *nd)
{

	memset(&nd->df, 0, sizeof(nd->df));
	nd->df.control.net_idx = nd->netkey_index;
	nd->df.metric.net_idx = nd->netkey_index;
	nd->df.metric.metric_type = MESH_DF_METRIC_NODE_COUNT;
	nd->df.metric.lifetime = MESH_DF_LIFETIME_2_HOUR;
	nd->df.lanes.net_idx = nd->netkey_index;
	nd->df.lanes.wanted_lanes = 1;
	nd->df.two_way.net_idx = nd->netkey_index;
	nd->df.echo.net_idx = nd->netkey_index;
	/*
	 * Enable Directed Forwarding on the sim node so the received-PDU path
	 * relays and answers DF transport-control PDUs over the live bearer
	 * (finding 129).  Managed flooding stays available as the fallback.
	 */
	mesh_sim_set_df(nd->self, 1);
	nd->df.enabled = 1;

	memset(&nd->rpr, 0, sizeof(nd->rpr));
	mesh_rp_scan_server_init(&nd->rpr.scan_server, MESH_RP_SCAN_FOUND_MAX, 1);
	mesh_rp_server_link_init(&nd->rpr.server_link);
	mesh_rp_scan_client_init(&nd->rpr.scan_client);
	mesh_rp_client_link_init(&nd->rpr.client_link);
	nd->rpr.client_active = 0;
}

/* ================================================================
 * Opcode -> handler dispatch table (MshMDL Section 4.3.4 / 7.2).
 * ================================================================ */
typedef int (*meshd_cfg_fn)(struct meshd_node *nd,
    const struct mesh_access_pdu *ap, const uint8_t *pdu, size_t len,
    uint8_t *reply, size_t reply_max, size_t *reply_len);

struct meshd_cfg_handler {
	uint32_t	opcode;
	meshd_cfg_fn	fn;
};

static const struct meshd_cfg_handler meshd_cfg_table[] = {
	{ MESH_CFG_OP_COMP_DATA_GET,		h_comp_get },
	{ MESH_CFG_OP_DEFAULT_TTL_GET,		h_default_ttl_get },
	{ MESH_CFG_OP_DEFAULT_TTL_SET,		h_default_ttl_set },
	{ MESH_CFG_OP_BEACON_GET,		h_beacon_get },
	{ MESH_CFG_OP_BEACON_SET,		h_beacon_set },
	{ MESH_CFG_OP_GATT_PROXY_GET,		h_gatt_proxy_get },
	{ MESH_CFG_OP_GATT_PROXY_SET,		h_gatt_proxy_set },
	{ MESH_CFG_OP_FRIEND_GET,		h_friend_get },
	{ MESH_CFG_OP_FRIEND_SET,		h_friend_set },
	{ MESH_CFG_OP_RELAY_GET,		h_relay_get },
	{ MESH_CFG_OP_RELAY_SET,		h_relay_set },
	{ MESH_CFG_OP_NET_TRANSMIT_GET,		h_net_transmit_get },
	{ MESH_CFG_OP_NET_TRANSMIT_SET,		h_net_transmit_set },
	{ MESH_CFG_OP_NODE_RESET,		h_node_reset },
	{ MESH_CFG_OP_NETKEY_ADD,		h_netkey_add },
	{ MESH_CFG_OP_NETKEY_UPDATE,		h_netkey_add },
	{ MESH_CFG_OP_NETKEY_DELETE,		h_netkey_delete },
	{ MESH_CFG_OP_NETKEY_GET,		h_netkey_get },
	{ MESH_CFG_OP_APPKEY_ADD,		h_appkey_add },
	{ MESH_CFG_OP_APPKEY_UPDATE,		h_appkey_add },
	{ MESH_CFG_OP_APPKEY_DELETE,		h_appkey_delete },
	{ MESH_CFG_OP_APPKEY_GET,		h_appkey_get },
	{ MESH_CFG_OP_MODEL_APP_BIND,		h_model_app_bind },
	{ MESH_CFG_OP_MODEL_APP_UNBIND,		h_model_app_bind },
	{ MESH_CFG_OP_SIG_MODEL_APP_GET,	h_model_app_get },
	{ MESH_CFG_OP_VND_MODEL_APP_GET,	h_model_app_get },
	{ MESH_CFG_OP_MODEL_SUB_ADD,		h_model_sub },
	{ MESH_CFG_OP_MODEL_SUB_DELETE,		h_model_sub },
	{ MESH_CFG_OP_MODEL_SUB_OVERWRITE,	h_model_sub },
	{ MESH_CFG_OP_MODEL_SUB_DELETE_ALL,	h_model_sub_del_all },
	{ MESH_CFG_OP_MODEL_SUB_VA_ADD,		h_model_sub_va },
	{ MESH_CFG_OP_MODEL_SUB_VA_DELETE,	h_model_sub_va },
	{ MESH_CFG_OP_MODEL_SUB_VA_OVERWRITE,	h_model_sub_va },
	{ MESH_CFG_OP_SIG_MODEL_SUB_GET,	h_model_sub_get },
	{ MESH_CFG_OP_VND_MODEL_SUB_GET,	h_model_sub_get },
	{ MESH_CFG_OP_MODEL_PUB_GET,		h_model_pub_get },
	{ MESH_CFG_OP_MODEL_PUB_SET,		h_model_pub_set },
	{ MESH_CFG_OP_MODEL_PUB_VA_SET,		h_model_pub_va_set },
	{ MESH_CFG_OP_KEY_REFRESH_PHASE_GET,	h_kr_phase_get },
	{ MESH_CFG_OP_KEY_REFRESH_PHASE_SET,	h_kr_phase_set },
	{ MESH_CFG_OP_NODE_IDENTITY_GET,	h_node_identity_get },
	{ MESH_CFG_OP_NODE_IDENTITY_SET,	h_node_identity_set },
	{ MESH_CFG_OP_LPN_POLLTIMEOUT_GET,	h_lpn_polltimeout_get },
	{ MESH_CFG_OP_HB_PUB_GET,		h_hb_pub_get },
	{ MESH_CFG_OP_HB_PUB_SET,		h_hb_pub_set },
	{ MESH_CFG_OP_HB_SUB_GET,		h_hb_sub_get },
	{ MESH_CFG_OP_HB_SUB_SET,		h_hb_sub_set },
	{ MESH_HLT_OP_ATTENTION_GET,		h_hlt_attention_get },
	{ MESH_HLT_OP_ATTENTION_SET,		h_hlt_attention_set },
	{ MESH_HLT_OP_PERIOD_GET,		h_hlt_period_get },
	{ MESH_HLT_OP_PERIOD_SET,		h_hlt_period_set },
	{ MESH_HLT_OP_FAULT_GET,		h_hlt_fault_get },
	{ MESH_HLT_OP_FAULT_CLEAR,		h_hlt_fault_clear },
	{ MESH_HLT_OP_FAULT_CLEAR_UNREL,	h_hlt_fault_clear },
	{ MESH_HLT_OP_FAULT_TEST,		h_hlt_fault_test },
	{ MESH_HLT_OP_FAULT_TEST_UNREL,		h_hlt_fault_test },
	{ MESH_CFG_OP_SAR_TRANSMITTER_GET,	h_sar_tx_get },
	{ MESH_CFG_OP_SAR_TRANSMITTER_SET,	h_sar_tx_set },
	{ MESH_CFG_OP_SAR_RECEIVER_GET,		h_sar_rx_get },
	{ MESH_CFG_OP_SAR_RECEIVER_SET,		h_sar_rx_set },
	{ MESH_CFG_OP_OD_PRIV_PROXY_GET,	h_od_priv_proxy_get },
	{ MESH_CFG_OP_OD_PRIV_PROXY_SET,	h_od_priv_proxy_set },
	{ MESH_CFG_OP_PRIV_BEACON_GET,		h_priv_beacon_get },
	{ MESH_CFG_OP_PRIV_BEACON_SET,		h_priv_beacon_set },
	{ MESH_CFG_OP_PRIV_GATT_PROXY_GET,	h_priv_gatt_proxy_get },
	{ MESH_CFG_OP_PRIV_GATT_PROXY_SET,	h_priv_gatt_proxy_set },
	{ MESH_CFG_OP_PRIV_NODE_IDENTITY_GET,	h_priv_node_identity_get },
	{ MESH_CFG_OP_PRIV_NODE_IDENTITY_SET,	h_priv_node_identity_set },
	{ MESH_CFG_OP_SOL_PDU_RPL_ITEMS_CLEAR,		h_sol_pdu_rpl_clear },
	{ MESH_CFG_OP_SOL_PDU_RPL_ITEMS_CLEAR_UNACK,	h_sol_pdu_rpl_clear },
	{ MESH_CFG_OP_LARGE_COMP_DATA_GET,	h_lcd_get },
	{ MESH_CFG_OP_MODELS_METADATA_GET,	h_lcd_get },
	{ MESH_CFG_OP_AGGREGATOR_SEQUENCE,	h_aggregator_seq },
	/* Directed Forwarding Configuration Server (finding 129). */
	{ MESH_CFG_OP_DIRECTED_CONTROL_GET,	h_df_control_get },
	{ MESH_CFG_OP_DIRECTED_CONTROL_SET,	h_df_control_set },
	{ MESH_CFG_OP_PATH_METRIC_GET,		h_df_metric_get },
	{ MESH_CFG_OP_PATH_METRIC_SET,		h_df_metric_set },
	{ MESH_CFG_OP_WANTED_LANES_GET,		h_df_lanes_get },
	{ MESH_CFG_OP_WANTED_LANES_SET,		h_df_lanes_set },
	{ MESH_CFG_OP_TWO_WAY_PATH_GET,		h_df_two_way_get },
	{ MESH_CFG_OP_TWO_WAY_PATH_SET,		h_df_two_way_set },
	{ MESH_CFG_OP_PATH_ECHO_INTERVAL_GET,	h_df_echo_get },
	{ MESH_CFG_OP_PATH_ECHO_INTERVAL_SET,	h_df_echo_set },
	{ MESH_CFG_OP_DIRECTED_NET_TRANSMIT_GET, h_df_transmit_get },
	{ MESH_CFG_OP_DIRECTED_NET_TRANSMIT_SET, h_df_transmit_set },
	{ MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_GET, h_df_transmit_get },
	{ MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_SET, h_df_transmit_set },
};

int
meshd_foundation_recv(struct meshd_node *nd, const uint8_t *pdu, size_t len,
    uint8_t *reply, size_t reply_max, size_t *reply_len)
{
	struct mesh_access_pdu ap;
	size_t i;

	if (nd == NULL || pdu == NULL || len == 0 || reply == NULL ||
	    reply_len == NULL)
		return (-1);
	if (mesh_access_pdu_parse(pdu, len, &ap) != 0)
		return (-1);
	*reply_len = 0;

	for (i = 0; i < nitems(meshd_cfg_table); i++) {
		if (meshd_cfg_table[i].opcode == ap.opcode)
			return (meshd_cfg_table[i].fn(nd, &ap, pdu, len, reply,
			    reply_max, reply_len));
	}
	/* Remote Provisioning Server model opcodes (finding 128). */
	if (ap.opcode >= MESH_RP_OP_SCAN_CAPABILITIES_GET &&
	    ap.opcode <= MESH_RP_OP_PDU_REPORT)
		return (meshd_rpr_server_recv(nd, &ap, pdu, len, reply,
		    reply_max, reply_len));
	return (-1);		/* not a handled foundation opcode */
}

uint16_t
meshd_node_addr(const struct meshd_node *nd)
{

	return (nd->addr);
}

uint32_t
meshd_node_seq(const struct meshd_node *nd)
{

	return (mesh_sim_node_seq(nd->self));
}

uint32_t
meshd_node_iv(const struct meshd_node *nd)
{

	return (mesh_sim_node_iv(nd->self));
}

uint8_t
meshd_node_onoff(const struct meshd_node *nd)
{

	return (nd->app != NULL ? nd->app->onoff.present : MESH_GEN_OFF);
}

int16_t
meshd_node_level(const struct meshd_node *nd)
{

	return (nd->app != NULL ? nd->app->level.present : 0);
}

int
meshd_node_restore(struct meshd_node *nd, const uint8_t netkey[16],
    const uint8_t appkey[16], uint32_t iv_index, uint16_t addr)
{

	if (nd == NULL || netkey == NULL || appkey == NULL)
		return (-1);
	if (!meshd_addr_is_unicast(addr))
		return (-1);
	if (meshd_setup_node(nd, netkey, appkey, iv_index, addr) != 0)
		return (-1);
	nd->provisioned = 1;
	return (0);
}

static struct mesh_sim_subnet_key *
meshd_sim_subnet(struct meshd_node *nd, uint16_t net_idx)
{
	size_t i;

	for (i = 0; i < nd->self->n_subnets; i++)
		if (nd->self->subnets[i].valid &&
		    nd->self->subnets[i].net_idx == net_idx)
			return (&nd->self->subnets[i]);
	return (NULL);
}

static int
meshd_beacon_emit_one(struct meshd_node *nd, uint16_t net_idx)
{
	uint8_t beacon[MESH_SECURE_BEACON_LEN];
	const uint8_t *bkey;
	const struct mesh_node *self;
	struct mesh_sim_subnet_key *subnet;
	size_t blen;
	uint8_t kr_flag, iv_update;

	self = nd->self;
	/*
	 * Select the key and Key Refresh Flag for the current phase
	 * (Sections 3.11.4.1-3.11.4.3): once the new key is held (Phase >= 1) the beacon
	 * is secured with it and carries the phase's flag; otherwise the current
	 * key with a clear flag.
	 */
	if (net_idx == self->primary_net_idx) {
		/*
		 * Beacon with the NEW key only from Phase 2 (mesh_kr_beacon_flag
		 * is 1 only in Phase 2).  A Phase-1 node beaconing new-key/KR=0
		 * signals Phase 3 to receivers and revokes the old key mid-
		 * distribution (C4-M2); the sim path already uses >= PHASE_2.
		 */
		if (self->have_new_key &&
		    mesh_kr_phase(&self->kr) >= MESH_KR_PHASE_2) {
			bkey = self->new_netkey;
			kr_flag = (uint8_t)mesh_kr_beacon_flag(&self->kr);
		} else {
			bkey = self->netkey;
			kr_flag = 0;
		}
	} else {
		subnet = meshd_sim_subnet(nd, net_idx);
		if (subnet == NULL)
			return (-1);
		if (subnet->have_new_key &&
		    mesh_kr_phase(&subnet->kr) >= MESH_KR_PHASE_2) {
			bkey = subnet->new_netkey;
			kr_flag = (uint8_t)mesh_kr_beacon_flag(&subnet->kr);
		} else {
			bkey = subnet->netkey;
			kr_flag = 0;
		}
	}
	iv_update = (self->iv.state == MESH_IV_UPDATE_IN_PROGRESS) ? 1 : 0;
	if (mesh_secure_beacon_build(bkey, kr_flag, iv_update,
	    self->iv.iv_index, beacon, &blen) != 0)
		return (0);
	if (nd->bearer == NULL || nd->bearer->tx == NULL)
		return (0);
	nd->tx_frames++;
	if (nd->bearer->tx(nd->bearer->arg, MESHD_PDU_BEACON, beacon, blen) != 0) {
		nd->tx_errors++;
		return (0);
	}
	return (1);
}

int
meshd_beacon_emit(struct meshd_node *nd)
{
	size_t i;
	int emitted, rc;

	if (nd == NULL || nd->self == NULL)
		return (-1);
	emitted = 0;
	for (i = 0; i < MESHD_MAX_NETKEYS; i++) {
		if (!nd->db.netkeys[i].valid)
			continue;
		rc = meshd_beacon_emit_one(nd, nd->db.netkeys[i].net_idx);
		if (rc < 0)
			return (-1);
		emitted += rc;
	}
	nd->beacon_last = nd->sim.now_ms;
	return (emitted);
}

/*
 * Emit one Unprovisioned Device Beacon (Section 3.9.2) carrying this node's
 * configured device UUID, so an unprovisioned meshd node is discoverable and
 * provisionable over PB-ADV.  Only meaningful while the node is unprovisioned
 * and a device_uuid was configured.  Returns 1 if a beacon was sent, 0 if not,
 * -1 on a bad argument.
 */
int
meshd_unprov_beacon_emit(struct meshd_node *nd)
{
	struct mesh_unprov_beacon ub;
	uint8_t beacon[MESH_UNPROV_BEACON_MAX_LEN];
	size_t blen;

	if (nd == NULL)
		return (-1);
	if (nd->provisioned || !nd->have_device_uuid ||
	    nd->bearer == NULL || nd->bearer->tx == NULL)
		return (0);
	memset(&ub, 0, sizeof(ub));
	memcpy(ub.uuid, nd->device_uuid, sizeof(ub.uuid));
	ub.oob = 0;			/* no OOB capabilities advertised */
	if (mesh_unprov_beacon_build(&ub, beacon, &blen) != 0)
		return (0);
	nd->tx_frames++;
	if (nd->bearer->tx(nd->bearer->arg, MESHD_PDU_BEACON, beacon, blen) != 0) {
		nd->tx_errors++;
		return (0);
	}
	nd->unprov_beacon_last = nd->sim.now_ms;
	return (1);
}

/*
 * Enable/disable unprovisioned-device discovery.  Enabling clears any prior
 * results so a fresh scan reflects only currently-heard devices.
 */
void
meshd_provision_scan_set(struct meshd_node *nd, int on)
{

	if (nd == NULL)
		return;
	nd->prov_scanning = on ? 1 : 0;
	if (on)
		memset(nd->scan_results, 0, sizeof(nd->scan_results));
}

/* Record a discovered unprovisioned device (dedup by UUID).  Returns 0/-1. */
int
meshd_provision_scan_add(struct meshd_node *nd, const uint8_t uuid[16],
    uint16_t oob)
{
	size_t i, free_slot = MESHD_MAX_SCAN_RESULTS;

	if (nd == NULL || uuid == NULL)
		return (-1);
	for (i = 0; i < MESHD_MAX_SCAN_RESULTS; i++) {
		if (nd->scan_results[i].valid) {
			if (memcmp(nd->scan_results[i].uuid, uuid, 16) == 0) {
				nd->scan_results[i].oob = oob;
				return (0);	/* refresh existing entry */
			}
		} else if (free_slot == MESHD_MAX_SCAN_RESULTS)
			free_slot = i;
	}
	if (free_slot == MESHD_MAX_SCAN_RESULTS)
		return (-1);		/* cache full */
	memcpy(nd->scan_results[free_slot].uuid, uuid, 16);
	nd->scan_results[free_slot].oob = oob;
	nd->scan_results[free_slot].valid = 1;
	return (0);
}

int
meshd_beacon_rx(struct meshd_node *nd, const uint8_t *pdu, size_t len)
{
	struct meshd_netkey_entry *e;
	struct mesh_sim_subnet_key *subnet;
	uint16_t net_idx;
	uint8_t old_iv_state;

	if (nd == NULL || pdu == NULL || nd->self == NULL)
		return (-1);
	old_iv_state = nd->self->iv.state;
	if (mesh_sim_node_recv_beacon(nd->self, pdu, len, nd->sim.now,
	    &net_idx) == 0) {
		/*
		 * A beacon that completes the IV Update (In-Progress -> Normal)
		 * opens a fresh SEQ epoch: reset SEQ to 0 here, because the tick's
		 * own reset only fires when IT observes the transition, and a
		 * beacon-driven completion runs before the tick sees Normal
		 * (MshPRT 3.11.5, NB-25).
		 */
		if (old_iv_state == MESH_IV_UPDATE_IN_PROGRESS &&
		    nd->self->iv.state == MESH_IV_NORMAL)
			nd->self->seq = 0;
		/* Beacon may have advanced/recovered the node IV Index; keep the
		 * manager copy in step for DevKey traffic and persistence. */
		meshd_sync_mgr_iv(nd);
	} else {
		/*
		 * Not an authenticated Secure Network beacon.  While a discovery
		 * scan is active, try to parse it as an Unprovisioned Device
		 * Beacon and record the device so the operator can list nearby
		 * provisionable devices (finding 127).
		 */
		if (nd->prov_scanning) {
			struct mesh_unprov_beacon ub;

			if (mesh_unprov_beacon_parse(pdu, len, &ub) == 0) {
				meshd_provision_scan_add(nd, ub.uuid, ub.oob);
				return (1);
			}
		}
		return (0);
	}
	/* Mirror the authenticated subnet's phase and any settled key. */
	e = meshd_find_netkey(nd, net_idx);
	if (e != NULL) {
		e->kr_phase = (uint8_t)mesh_sim_subnet_kr_phase(nd->self,
		    net_idx);
		/* A beacon-driven settle promotes and clears the new key. */
		subnet = net_idx == nd->self->primary_net_idx ? NULL :
		    meshd_sim_subnet(nd, net_idx);
		if (((subnet == NULL && !nd->self->have_new_key) ||
		    (subnet != NULL && !subnet->have_new_key)) && e->has_new_key) {
			memcpy(e->key, subnet == NULL ? nd->self->netkey :
			    subnet->netkey, 16);
			e->has_new_key = 0;
			explicit_bzero(e->new_key, sizeof(e->new_key));
		}
	}
	return (1);
}

/*
 * Advance the time-driven state machines (MshMDL_v1.1 Section 4.2.18 periodic
 * Heartbeat, MshPRT_v1.1 Section 3.10.5 IV Update).  The clock is injected by
 * publishing `now` to the sim's virtual clock, which the IV Update dwell timers
 * read; the Heartbeat timer is advanced by the elapsed delta since the previous
 * tick.  While the Beacon state is enabled a Secure Network beacon is emitted at
 * the Section 3.9.3 cadence, carrying the current Key Refresh phase flag.
 */
int
meshd_node_tick(struct meshd_node *nd, uint64_t now_ms, int *iv_changed)
{
	uint32_t old_iv;
	int old_state, hb = 0;
	uint64_t dt_ms;

	if (iv_changed != NULL)
		*iv_changed = 0;
	if (nd == NULL || nd->self == NULL)
		return (-1);

	/* Elapsed milliseconds since the previous tick (0 on the first tick). */
	dt_ms = (nd->tick_last == 0 || now_ms < nd->tick_last) ? 0 :
	    now_ms - nd->tick_last;
	nd->tick_last = now_ms;
	if (now_ms >= nd->sim.now_ms)
		mesh_sim_advance_ms(&nd->sim, now_ms - nd->sim.now_ms);
	else {
		nd->sim.now_ms = now_ms;
		nd->sim.now = now_ms / 1000;
	}
	/*
	 * Feed the sim a wall-clock anchor for the IV Update 96-hour dwell so
	 * time-in-state survives daemon restarts (the monotonic clock resets to
	 * ~0 each boot).  A backward wall-clock step is handled by the dwell's
	 * own now < entered_time guard.
	 */
	{
		struct timespec wts;

		if (clock_gettime(CLOCK_REALTIME, &wts) == 0)
			nd->sim.wall_now = (uint64_t)wts.tv_sec;
	}
	meshd_gatt_tick(nd, now_ms);
	meshd_publication_tick(nd, now_ms);
	if (nd->sim.n_tx != 0)
		meshd_drain_tx(nd);

	/*
	 * Periodic Heartbeat publication onto the bearer (Section 4.2.18).
	 * dt_ms is the per-tick delta (~10 ms); accumulate it and publish for
	 * each whole second that elapses, carrying the sub-second remainder.
	 */
	nd->hb_accum_ms += dt_ms;
	if (nd->hb_accum_ms >= 1000) {
		uint32_t secs = (uint32_t)(nd->hb_accum_ms / 1000);
		int n;

		nd->hb_accum_ms -= (uint64_t)secs * 1000;
		n = mesh_sim_hb_publish_periodic(&nd->sim, nd->self, secs);
		if (n > 0) {
			hb = n;
			meshd_drain_tx(nd);
		}
	}

	/*
	 * IV Update procedure (Section 3.10.5).  Begin an update when the SEQ
	 * space nears exhaustion; complete an in-progress update.  Both are
	 * gated by the 96-hour minimum dwell inside the state machine, so an
	 * out-of-turn call is a harmless no-op.  When an update COMPLETES the
	 * node adopts the new IV Index for transmit and the SEQ resets to 0 for
	 * the fresh epoch.
	 */
	old_iv = nd->self->iv.iv_index;
	old_state = nd->self->iv.state;
	if (mesh_iv_seq_exhausted(nd->self->seq))
		(void)mesh_sim_begin_iv_update(nd->self);
	if (nd->self->iv.state == MESH_IV_UPDATE_IN_PROGRESS)
		(void)mesh_sim_complete_iv_update(nd->self);
	if (old_state == MESH_IV_UPDATE_IN_PROGRESS &&
	    nd->self->iv.state == MESH_IV_NORMAL) {
		/* Update completed: new epoch, SEQ starts over (Section 3.10.5). */
		nd->self->seq = 0;
		if (iv_changed != NULL)
			*iv_changed = 1;
	} else if (old_iv != nd->self->iv.iv_index && iv_changed != NULL) {
		*iv_changed = 1;
	}
	/* Propagate any IV advance into the manager copy before it is used
	 * (DevKey seal) or persisted (load-time consistency check). */
	meshd_sync_mgr_iv(nd);

	/*
	 * Secure Network beacon pump (Section 3.9.3): while the Beacon state is
	 * enabled, emit one beacon per cadence interval.  It carries the Key
	 * Refresh Flag for the current phase, which drives receiving nodes
	 * through the refresh (Section 3.11.4).
	 */
	if (nd->cfg.beacon == 1 &&
	    (nd->beacon_last == 0 || now_ms >= nd->beacon_last +
	    MESHD_BEACON_INTERVAL * 1000ULL))
		(void)meshd_beacon_emit(nd);

	/*
	 * Unprovisioned Device Beacon (Section 3.9.2): while this node is itself
	 * unprovisioned and a device_uuid was configured, advertise it so it can
	 * be discovered and provisioned over PB-ADV (finding 131).
	 */
	if (!nd->provisioned && nd->have_device_uuid &&
	    (nd->unprov_beacon_last == 0 || now_ms >= nd->unprov_beacon_last +
	    MESHD_BEACON_INTERVAL * 1000ULL))
		(void)meshd_unprov_beacon_emit(nd);

	/*
	 * Directed Forwarding (finding 129): age out established Forwarding Table
	 * paths on the sim node and fail a Path Origin discovery whose reply
	 * budget elapsed.  Relay/target processing itself happens on the
	 * received-PDU path (meshd_bearer_rx).
	 */
	if (nd->self->df_enabled) {
		mesh_sim_df_expire(&nd->sim);
		if (nd->self->df_disc.state == MESH_DF_DISC_REQUEST_SENT)
			(void)mesh_df_discovery_timed_out(&nd->self->df_disc,
			    now_ms);
	}

	/*
	 * Remote Provisioning (finding 128): expire the Scan Server's timed scan
	 * and the Client's link-open budget.
	 */
	(void)mesh_rp_scan_server_tick(&nd->rpr.scan_server, now_ms);
	if (nd->rpr.client_active &&
	    mesh_rp_client_link_tick(&nd->rpr.client_link, now_ms))
		nd->rpr.client_active = mesh_rp_client_link_is_active(
		    &nd->rpr.client_link);

	/*
	 * Friendship (MshPRT_v1.1 Section 3.6.5 / 3.6.6).  Drive the Low Power
	 * node cadence (Friend Request on first tick, offer selection, cadence
	 * Polls, re-establishment) and the Friend timers (emit a due Offer,
	 * supervise the PollTimeout), transmitting the resulting control PDUs
	 * over the bearer.
	 */
	if (nd->lpn_enabled) {
		struct mesh_lpn_out lout;

		memset(&lout, 0, sizeof(lout));
		if (nd->lpn_fsm.state == MESH_LPN_ST_IDLE) {
			if (nd->bearer != NULL && nd->bearer->tx != NULL &&
			    mesh_lpn_fsm_start(&nd->lpn_fsm, now_ms, &lout) == 0)
				meshd_lpn_emit(nd, &lout);
		} else if (mesh_lpn_fsm_tick(&nd->lpn_fsm, now_ms, &lout) == 0)
			meshd_lpn_emit(nd, &lout);
	}
	if (nd->friend_enabled) {
		struct mesh_friend_out fout;

		memset(&fout, 0, sizeof(fout));
		if (mesh_friend_fsm_tick(&nd->friend_fsm, now_ms, &fout) == 0)
			meshd_friend_emit(nd, nd->friend_fsm.lpn_addr, &fout);
	}

	return (hb);
}

/* ================================================================
 * Directed Forwarding drive (finding 129, MshPRT_v1.1 Section 3.6.7).
 *
 * The relay / target / Path-Origin reply-and-confirm roles run inside the sim
 * node (enabled by mesh_sim_set_df) and are driven by the received-PDU path:
 * meshd_bearer_rx -> mesh_sim_reinject + mesh_sim_step decrypts an inbound DF
 * transport-control PDU, the sim's DF dispatch relays/answers it onto the tx
 * queue, and meshd_drain_tx flushes those to the bearer.  meshd only has to
 * enable DF, originate the initial Path Request, and expire aged paths.
 * ================================================================ */

void
meshd_df_enable(struct meshd_node *nd)
{

	if (nd == NULL || nd->self == NULL)
		return;
	/*
	 * managed_flood_relay is the DF flood-fallback, but it doubles as the
	 * Relay-feature indicator that mesh_df_forward_decide consults, so it
	 * must track the node's actual Relay state -- NOT be forced to 1.
	 * Enabling Directed Forwarding at runtime must not make a node whose
	 * Relay feature is administratively OFF start relaying via managed
	 * flooding (NB-3; mesh_sim_set_df is the sibling writer that the
	 * mesh_sim_set_relay fix alone did not cover).  At initial setup
	 * mesh_sim_set_relay runs after this and re-establishes the value.
	 */
	mesh_sim_set_df(nd->self, nd->cfg.relay == 1);
	nd->df.enabled = 1;
}

/*
 * MshPRT 3.6.6.2 Table 3.6: which Friend control opcodes are secured with the
 * friendship credential (vs managed flooding).  Poll/Update/Subscription-List
 * Add/Remove/Confirm use the friendship credential; Request/Offer/Clear/Clear
 * Confirm use managed flooding.
 */
static int
friend_op_uses_cred(uint8_t opcode)
{

	switch (opcode) {
	case MESH_FRIEND_OP_POLL:
	case MESH_FRIEND_OP_UPDATE:
	case MESH_FRIEND_OP_SUBLIST_ADD:
	case MESH_FRIEND_OP_SUBLIST_REMOVE:
	case MESH_FRIEND_OP_SUBLIST_CONFIRM:
		return (1);
	default:
		return (0);
	}
}

/*
 * Derive and store this node's friendship security credential (MshPRT
 * 3.6.6.2) from the negotiated LPN/Friend addresses and LPN/Friend counters.
 * Once stored (have_friend_cred), the credential-bound friendship PDUs (Friend
 * Poll/Update/Subscription-List/Confirm and queued messages) are secured with
 * it instead of the managed-flooding credential, so a conformant peer can
 * decrypt them.  Uses the primary subnet NetKey (meshd friendships are on the
 * primary subnet).
 */
static void
meshd_friend_cred_derive(struct meshd_node *nd, uint16_t lpn_addr,
    uint16_t friend_addr, uint16_t lpn_counter, uint16_t friend_counter)
{
	struct mesh_node *self;
	uint8_t nid[1];

	if (nd == NULL || nd->self == NULL)
		return;
	self = nd->self;
	if (mesh_friend_credentials(self->netkey, lpn_addr, friend_addr,
	    lpn_counter, friend_counter, nid, self->friend_enckey,
	    self->friend_privkey) != 0)
		return;
	self->friend_nid = nid[0];
	self->friend_net_idx = self->primary_net_idx;
	self->fc_lpn_addr = lpn_addr;
	self->fc_friend_addr = friend_addr;
	self->fc_lpn_counter = lpn_counter;
	self->fc_friend_counter = friend_counter;
	self->have_friend_cred = 1;
}

static int
meshd_df_send_control(struct meshd_node *nd, uint8_t opcode, uint16_t dst,
    uint8_t ttl, const uint8_t *params, size_t plen, int friend_cred)
{
	const struct mesh_node *self;
	struct mesh_net_pdu np;
	uint8_t frame[64];
	const uint8_t *enc, *priv;
	uint8_t nid;
	size_t flen;
	uint32_t iv;

	if (nd == NULL || nd->self == NULL || nd->bearer == NULL ||
	    nd->bearer->tx == NULL)
		return (-1);
	if (plen + 1 > MESH_NET_MAX_CONTROL_TRANSPORT_PDU)
		return (-1);			/* would need segmentation */
	self = nd->self;
	/*
	 * Credential-bound friendship PDUs use the friendship credential once it
	 * has been established (MshPRT 3.6.6.2 Table 3.6); everything else -- and
	 * friendship PDUs sent before establishment (Request/Offer) -- uses the
	 * managed-flooding credential.
	 */
	if (friend_cred && self->have_friend_cred) {
		nid = self->friend_nid;
		enc = self->friend_enckey;
		priv = self->friend_privkey;
	} else {
		nid = self->nid;
		enc = self->enckey;
		priv = self->privkey;
	}
	iv = mesh_iv_tx_index(&nd->self->iv);
	memset(&np, 0, sizeof(np));
	np.ivi = (uint8_t)(iv & 1);
	np.nid = nid;
	np.ctl = 1;
	np.ttl = ttl;
	np.seq = nd->self->seq;
	np.src = nd->addr;
	np.dst = dst;
	np.transport[0] = (uint8_t)(opcode & 0x7f);
	if (plen > 0)
		memcpy(np.transport + 1, params, plen);
	np.transport_len = plen + 1;
	if (mesh_net_encrypt(enc, priv, nid, iv, &np, frame, &flen) != 0)
		return (-1);
	nd->self->seq++;
	nd->tx_frames++;
	if (nd->bearer->tx(nd->bearer->arg, MESHD_PDU_NET, frame, flen) != 0) {
		nd->tx_errors++;
		return (-1);
	}
	return (0);
}

int
meshd_df_discover_begin(struct meshd_node *nd, uint16_t target, uint64_t now)
{
	struct mesh_df_path_request req;
	uint8_t params[MESH_ACCESS_PAYLOAD_MAX];
	size_t plen;

	if (nd == NULL || nd->self == NULL || !nd->provisioned)
		return (-1);
	if (nd->bearer == NULL || nd->bearer->tx == NULL)
		return (-1);			/* origination needs a bearer */
	if (!nd->self->df_enabled)
		meshd_df_enable(nd);
	if (nd->self->df_disc.state == MESH_DF_DISC_REQUEST_SENT)
		return (-1);			/* one discovery in flight */

	/*
	 * Arm the sim node's Path Origin FSM so the received-PDU path completes
	 * the Reply/Confirmation exchange, then originate the Path Request onto
	 * the bearer.  (mesh_sim_df_discover would pump the local single-node
	 * medium and consume the frame instead of transmitting it.)
	 */
	if (mesh_df_discovery_start(&nd->self->df_disc, nd->addr, target,
	    nd->self->df_fn, nd->df.metric.metric_type, nd->df.metric.lifetime,
	    nd->df.lanes.wanted_lanes ? nd->df.lanes.wanted_lanes : 1,
	    nd->df.two_way.two_way_path, 30000, now, &req) != 0)
		return (-1);
	nd->self->df_fn = mesh_df_fn_next(nd->self->df_fn);
	if (mesh_df_path_request_build(&req, params, &plen) != 0)
		return (-1);
	if (meshd_df_send_control(nd, MESH_DF_OP_PATH_REQUEST, MESH_ADDR_ALL_DF,
	    5, params, plen, 0) != 0)
		return (-1);
	return (0);
}

/* ================================================================
 * Friendship roles (MshPRT_v1.1 Section 3.6.5).
 * ================================================================ */

int
meshd_friend_enable(struct meshd_node *nd, uint8_t recv_window,
    uint8_t queue_size, uint8_t sub_list_size, int8_t min_rssi,
    uint8_t max_queue_size_log)
{

	if (nd == NULL)
		return (-1);
	mesh_friend_fsm_init(&nd->friend_fsm, nd->addr, recv_window, queue_size,
	    sub_list_size, min_rssi, max_queue_size_log);
	nd->friend_enabled = 1;
	return (0);
}

int
meshd_friend_input(struct meshd_node *nd, uint16_t src, const uint8_t *pdu,
    size_t len, int8_t rssi, uint8_t key_refresh, uint8_t iv_update,
    uint32_t iv_index, uint64_t now, struct mesh_friend_out *out)
{
	uint8_t op;

	if (nd == NULL || pdu == NULL || out == NULL || len == 0)
		return (-1);
	if (!nd->friend_enabled)
		return (-1);

	op = pdu[0] & 0x7f;
	switch (op) {
	case MESH_FRIEND_OP_REQUEST:
		/* The LPN's primary element unicast is the message SRC. */
		if (mesh_friend_fsm_recv_request(&nd->friend_fsm, pdu, len, src,
		    rssi, now, out) != 0)
			return (-1);
		return (0);
	case MESH_FRIEND_OP_POLL:
		return (mesh_friend_fsm_recv_poll(&nd->friend_fsm, pdu, len,
		    key_refresh, iv_update, iv_index, now, out));
	case MESH_FRIEND_OP_SUBLIST_ADD:
	case MESH_FRIEND_OP_SUBLIST_REMOVE:
		return (mesh_friend_fsm_recv_sublist(&nd->friend_fsm, pdu, len,
		    now, out));
	case MESH_FRIEND_OP_CLEAR:
	case MESH_FRIEND_OP_CLEAR_CONFIRM: {
		int r = mesh_friend_fsm_recv_clear(&nd->friend_fsm, pdu, len,
		    out);

		/*
		 * A Friend Clear Confirm must be returned to the sender of the
		 * Friend Clear (this Friend, several hops away), NOT to the LPN at
		 * TTL 0.  The library builds the Confirm but cannot know the
		 * sender, so stamp it here so meshd_friend_emit floods it to src
		 * (C6-H4).
		 */
		if (r == 1 && out->action == MESH_FRIEND_ACT_SEND_CONTROL)
			out->addr = src;
		return (r);
	}
	default:
		return (-1);
	}
}

int
meshd_friend_tick(struct meshd_node *nd, uint64_t now, struct mesh_friend_out *out)
{

	if (nd == NULL || out == NULL || !nd->friend_enabled)
		return (-1);
	return (mesh_friend_fsm_tick(&nd->friend_fsm, now, out));
}

int
meshd_friend_enqueue(struct meshd_node *nd, const struct mesh_fq_entry *in)
{

	if (nd == NULL || in == NULL || !nd->friend_enabled)
		return (-1);
	return (mesh_friend_fsm_enqueue(&nd->friend_fsm, in));
}

int
meshd_lpn_enable(struct meshd_node *nd, uint8_t rssi_factor,
    uint8_t rx_window_factor, uint8_t min_queue_size_log, uint8_t recv_delay,
    uint32_t poll_timeout, uint32_t offer_window_ms, uint32_t poll_interval_ms,
    uint64_t now, struct mesh_lpn_out *out)
{

	if (nd == NULL || out == NULL)
		return (-1);
	mesh_lpn_fsm_init(&nd->lpn_fsm, nd->addr, 1, rssi_factor, rx_window_factor,
	    min_queue_size_log, recv_delay, poll_timeout, offer_window_ms,
	    poll_interval_ms);
	nd->lpn_enabled = 1;
	return (mesh_lpn_fsm_start(&nd->lpn_fsm, now, out));
}

int
meshd_lpn_recv_offer(struct meshd_node *nd, const uint8_t *pdu, size_t len,
    uint16_t friend_addr, uint64_t now)
{

	if (nd == NULL || pdu == NULL || !nd->lpn_enabled)
		return (-1);
	return (mesh_lpn_fsm_recv_offer(&nd->lpn_fsm, pdu, len, friend_addr, now));
}

int
meshd_lpn_recv_update(struct meshd_node *nd, const uint8_t *pdu, size_t len,
    uint64_t now, struct mesh_lpn_out *out)
{

	if (nd == NULL || pdu == NULL || out == NULL || !nd->lpn_enabled)
		return (-1);
	return (mesh_lpn_fsm_recv_update(&nd->lpn_fsm, pdu, len, now, out));
}

int
meshd_lpn_tick(struct meshd_node *nd, uint64_t now, struct mesh_lpn_out *out)
{

	if (nd == NULL || out == NULL || !nd->lpn_enabled)
		return (-1);
	return (mesh_lpn_fsm_tick(&nd->lpn_fsm, now, out));
}

/* ================================================================
 * Friendship drive over the bearer (MshPRT_v1.1 Section 3.6.5 / 3.6.6).
 *
 * The Friend and Low Power node engines (mesh_friend.c / mesh_lpn.c) emit a
 * single action per step (a control PDU or a queued message).  These helpers
 * secure each emitted PDU as a managed-flooding Network PDU and hand it to the
 * bearer - the same wire form a peer's mesh_net_decrypt recovers - and route
 * inbound friendship control PDUs (decrypted at meshd_bearer_rx) back to the
 * engines.  Friendship control messages travel single-hop (TTL 0) between the
 * LPN and its Friend.
 * ================================================================ */

/* Fixed all-friends group address (MshPRT_v1.1 Section 3.4.2.4). */
#ifndef	MESH_ADDR_ALL_FRIENDS
#define	MESH_ADDR_ALL_FRIENDS	0xFFFDu
#endif

#define	MESHD_FRIEND_CTL_TTL	0	/* LPN<->Friend is a single hop */
#define	MESHD_FRIEND_RX_RSSI	(-40)	/* synthesised RSSI for a Request */

/* Friend role local Offer parameters + acceptance policy (defaults). */
#define	MESHD_FRIEND_RECV_WINDOW	20	/* our ReceiveWindow, ms */
#define	MESHD_FRIEND_QUEUE_SIZE		8
#define	MESHD_FRIEND_SUBLIST_SIZE	8
#define	MESHD_FRIEND_MIN_RSSI		(-100)	/* accept all but the weakest */
#define	MESHD_FRIEND_MAX_QSIZE_LOG	4	/* serve up to N = 16 */

/* Low Power node Friend Request criteria + cadence (defaults). */
#define	MESHD_LPN_RSSI_FACTOR		0
#define	MESHD_LPN_RXWIN_FACTOR		0
#define	MESHD_LPN_MIN_QSIZE_LOG		1	/* need N >= 2 */
#define	MESHD_LPN_RECV_DELAY_MS		100
#define	MESHD_LPN_POLL_TIMEOUT		100	/* units of 100 ms => 10 s */
#define	MESHD_LPN_OFFER_WINDOW_MS	500
#define	MESHD_LPN_POLL_INTERVAL_MS	2000

/*
 * Network-encrypt a built friendship control PDU (opcode octet + parameters)
 * under the primary subnet's managed-flooding credential and hand it to the
 * bearer.  Reuses meshd_df_send_control, which advances the node SEQ.
 */
static int
meshd_friend_send_control(struct meshd_node *nd, uint16_t dst,
    const uint8_t *pdu, size_t len)
{

	if (nd == NULL || pdu == NULL || len == 0)
		return (-1);
	/*
	 * Per MshPRT 3.6.6.2 Table 3.6 the credential is chosen by opcode:
	 * Friend Poll / Update / Subscription-List Add/Remove/Confirm use the
	 * friendship credential; Friend Request / Offer / Clear / Clear Confirm
	 * use managed flooding (the peer has no friendship credential during the
	 * Request/Offer handshake).
	 */
	return (meshd_df_send_control(nd, (uint8_t)(pdu[0] & 0x7f), dst,
	    MESHD_FRIEND_CTL_TTL, len > 1 ? pdu + 1 : NULL, len - 1,
	    friend_op_uses_cred(pdu[0] & 0x7f)));
}

/*
 * Deliver a Friend Queue entry (a stored Lower Transport PDU) to the LPN.  The
 * entry is re-secured as a managed-flooding Network PDU preserving the original
 * SRC / SEQ / DST and the queue-decremented TTL, so the LPN decrypts and
 * delivers it exactly like any received message.  Only unsegmented deliveries
 * fit a single advertising-bearer frame; a segmented queue entry is dropped.
 */
static int
meshd_friend_send_msg(struct meshd_node *nd, const struct mesh_fq_entry *e)
{
	const struct mesh_node *self;
	struct mesh_net_pdu np;
	uint8_t frame[MESH_NET_MAX_PDU];
	const uint8_t *enc, *priv;
	uint8_t nid;
	size_t flen;
	uint32_t iv;

	if (nd == NULL || e == NULL || nd->self == NULL ||
	    nd->bearer == NULL || nd->bearer->tx == NULL)
		return (-1);
	if (e->pdu_len == 0 || e->pdu_len > MESH_NET_MAX_TRANSPORT_PDU)
		return (-1);			/* unsegmented delivery only */
	self = nd->self;
	/*
	 * Queued messages and the Friend Update are delivered to the LPN with
	 * the friendship credential (MshPRT 3.6.6.2) once it is established.
	 */
	if (self->have_friend_cred) {
		enc = self->friend_enckey;
		priv = self->friend_privkey;
		nid = self->friend_nid;
	} else {
		enc = self->enckey;
		priv = self->privkey;
		nid = self->nid;
	}
	iv = mesh_iv_tx_index(&self->iv);
	memset(&np, 0, sizeof(np));
	np.ivi = (uint8_t)(iv & 1);
	np.nid = nid;
	np.ctl = e->ctl;
	np.ttl = e->ttl;
	/*
	 * A Friend Update is ORIGINATED by the Friend, so it must carry the
	 * Friend's own monotonically-advancing network SEQ (the built entry's
	 * seq is 0).  Every transmission - including a resend of the same empty
	 * -queue Update on a duplicate Poll - advances the SEQ so the LPN's
	 * network RPL accepts each successive Update rather than rejecting it as
	 * a replay (C6-H1).  A stored data entry keeps its original SRC/SEQ so
	 * the LPN sees the message exactly as first sent.
	 */
	np.seq = e->is_update ? nd->self->seq : e->seq;
	np.src = e->src;
	np.dst = e->dst;
	memcpy(np.transport, e->pdu, e->pdu_len);
	np.transport_len = e->pdu_len;
	if (mesh_net_encrypt(enc, priv, nid, iv, &np, frame, &flen) != 0)
		return (-1);
	if (e->is_update)
		nd->self->seq++;	/* consume the SEQ the Update carried */
	nd->tx_frames++;
	if (nd->bearer->tx(nd->bearer->arg, MESHD_PDU_NET, frame, flen) != 0) {
		nd->tx_errors++;
		return (-1);
	}
	return (0);
}

/* Transmit the action a Friend FSM step produced.  dst is our LPN. */
static void
meshd_friend_emit(struct meshd_node *nd, uint16_t dst,
    struct mesh_friend_out *out)
{

	switch (out->action) {
	case MESH_FRIEND_ACT_SEND_CONTROL:
		/*
		 * Most control replies go single-hop to the LPN at TTL 0.  A
		 * Friend Clear Confirm, however, is addressed to the sender of the
		 * Friend Clear (out->addr, possibly several hops away) and must be
		 * flooded with the managed-flooding TTL rather than to the LPN
		 * (C6-H4).
		 */
		if (out->addr != 0 && out->pdu_len > 0)
			(void)meshd_df_send_control(nd,
			    (uint8_t)(out->pdu[0] & 0x7f), out->addr, 0x7f,
			    out->pdu_len > 1 ? out->pdu + 1 : NULL,
			    out->pdu_len - 1, 0);
		else {
			/*
			 * The FriendCounter is finalized when the Offer is built
			 * (not at Request-recv time), so derive the friendship
			 * credential here, as the Offer goes out: both endpoints
			 * now share all four inputs, and the first friend-cred
			 * Poll from the LPN (and our Update reply) can then be
			 * secured/decrypted (NB-13, MshPRT 3.6.6.2).
			 */
			if (out->pdu_len > 0 &&
			    (out->pdu[0] & 0x7f) == MESH_FRIEND_OP_OFFER)
				meshd_friend_cred_derive(nd,
				    nd->friend_fsm.lpn_addr, nd->addr,
				    nd->friend_fsm.lpn_counter,
				    nd->friend_fsm.offer.friend_counter);
			(void)meshd_friend_send_control(nd, dst, out->pdu,
			    out->pdu_len);
		}
		break;
	case MESH_FRIEND_ACT_SEND_MSG:
		(void)meshd_friend_send_msg(nd, &out->msg);
		break;
	case MESH_FRIEND_ACT_SEND_CLEAR:
		/*
		 * A Friend Clear is addressed to the *previous* Friend at
		 * out->addr (not the LPN), which may be several hops away, so it
		 * is flooded with the managed-flooding credential at TTL 0x7F
		 * rather than the single-hop LPN<->Friend TTL (P-H7).
		 */
		if (out->pdu_len > 0)
			(void)meshd_df_send_control(nd,
			    (uint8_t)(out->pdu[0] & 0x7f), out->addr, 0x7f,
			    out->pdu_len > 1 ? out->pdu + 1 : NULL,
			    out->pdu_len - 1, 0);
		break;
	case MESH_FRIEND_ACT_TERMINATED:
		/*
		 * Friendship dropped (PollTimeout): discard the friendship
		 * credential so a stale one is never reused; the next Offer
		 * re-derives it.  Mirrors the LPN clearing it on re-Request.
		 */
		if (nd->self != NULL)
			nd->self->have_friend_cred = 0;
		break;
	default:
		break;
	}
}

/* Transmit the action an LPN FSM step produced. */
static void
meshd_lpn_emit(struct meshd_node *nd, struct mesh_lpn_out *out)
{

	switch (out->action) {
	case MESH_LPN_ACT_SEND_REQUEST:
		/* Starting a new friendship: the previous friendship credential
		 * (if any) is stale, so re-derive it when the next Poll is sent
		 * with the new counters (NB-13). */
		if (nd->self != NULL)
			nd->self->have_friend_cred = 0;
		(void)meshd_friend_send_control(nd, MESH_ADDR_ALL_FRIENDS,
		    out->pdu, out->pdu_len);
		break;
	case MESH_LPN_ACT_SEND_POLL:
	case MESH_LPN_ACT_SEND_SUBLIST:
		/*
		 * The friend is now selected (friend_addr + FriendCounter known),
		 * so derive the friendship credential before the first Poll -- the
		 * LPN secures Poll/Sublist with it (NB-13, MshPRT 3.6.6.2).
		 */
		if (nd->self != NULL && !nd->self->have_friend_cred &&
		    mesh_lpn_fsm_friend(&nd->lpn_fsm) != 0)
			meshd_friend_cred_derive(nd, nd->addr,
			    mesh_lpn_fsm_friend(&nd->lpn_fsm),
			    mesh_lpn_fsm_lpn_counter(&nd->lpn_fsm),
			    mesh_lpn_fsm_friend_counter(&nd->lpn_fsm));
		(void)meshd_friend_send_control(nd, out->friend_addr, out->pdu,
		    out->pdu_len);
		break;
	default:
		break;
	}
}

/*
 * Route an inbound Network PDU to the friendship engines.  The PDU is decrypted
 * with the node's managed-flooding credential (over the current and previous IV
 * Index); a Transport Control friendship message is dispatched by opcode to the
 * Friend engine (Request / Poll / Subscription List / Clear) or the LPN engine
 * (Offer / Update), and any resulting control/queued PDU is transmitted.  An
 * access message destined for our LPN is offered to the Friend Queue.
 */
static int
meshd_friendship_control_rx(struct meshd_node *nd, const uint8_t *pdu,
    size_t len)
{
	struct mesh_lower lower;
	struct mesh_net_pdu np;
	struct {
		uint8_t nid;
		const uint8_t *enckey;
		const uint8_t *privkey;
	} keys[3];
	uint32_t ivc[2], iv, iv_used;
	uint64_t now;
	size_t ki, nkeys, ni, niv;
	uint8_t op, ivu, rpl_slot;
	int ok = 0;

	if (nd->self == NULL)
		return (0);
	/*
	 * Use the network-current IV Index (not mesh_iv_tx_index) for BOTH the
	 * RX decrypt candidates and the empty-queue Friend Update's IV field.
	 * During the node's own IV Update mesh_iv_tx_index returns iv_index-1,
	 * which (a) makes the RX candidates {n-1, n-2} and omit the current
	 * index n -- so friendship traffic secured at n fails to decrypt (NB-12)
	 * -- and (b) puts an illegal (old-index, IVU=1) pair in the Friend
	 * Update, which no LPN can adopt (NB-11).  The Secure Network beacon
	 * carries self->iv.iv_index, so the Update must too.  RX still accepts
	 * {iv_index, iv_index-1}, matching the main try_decrypt path.
	 */
	iv = nd->self->iv.iv_index;
	ivc[0] = iv;
	niv = 1;
	if (iv > 0) {
		ivc[1] = iv - 1;
		niv = 2;
	}
	nkeys = 0;
	if (mesh_kr_rx_accept_old(&nd->self->kr)) {
		keys[nkeys].nid = nd->self->nid;
		keys[nkeys].enckey = nd->self->enckey;
		keys[nkeys].privkey = nd->self->privkey;
		nkeys++;
	}
	if (nd->self->have_new_key && mesh_kr_rx_accept_new(&nd->self->kr)) {
		keys[nkeys].nid = nd->self->new_nid;
		keys[nkeys].enckey = nd->self->new_enckey;
		keys[nkeys].privkey = nd->self->new_privkey;
		nkeys++;
	}
	/*
	 * Friend Poll/Update/Subscription-List/Confirm and queued messages are
	 * secured with the friendship credential (MshPRT 3.6.6.2), not managed
	 * flooding, so add it as a decrypt candidate once established (NB-13).
	 */
	if (nd->self->have_friend_cred) {
		keys[nkeys].nid = nd->self->friend_nid;
		keys[nkeys].enckey = nd->self->friend_enckey;
		keys[nkeys].privkey = nd->self->friend_privkey;
		nkeys++;
	}
	for (ki = 0; ki < nkeys && !ok; ki++)
		for (ni = 0; ni < niv && !ok; ni++)
			if (mesh_net_decrypt(keys[ki].enckey, keys[ki].privkey,
			    keys[ki].nid, ivc[ni], pdu, len, &np) == 0) {
				iv_used = ivc[ni];
				ok = 1;
			}
	if (!ok || np.transport_len == 0)
		return (0);
	if (np.ctl != 1 || mesh_lower_parse(1, np.transport,
	    np.transport_len, &lower) != 0 || lower.seg != 0)
		return (0);
	op = lower.opcode;
	if (!((nd->friend_enabled &&
	    (op == MESH_FRIEND_OP_REQUEST || op == MESH_FRIEND_OP_POLL ||
	    op == MESH_FRIEND_OP_SUBLIST_ADD ||
	    op == MESH_FRIEND_OP_SUBLIST_REMOVE ||
	    op == MESH_FRIEND_OP_CLEAR ||
	    op == MESH_FRIEND_OP_CLEAR_CONFIRM)) ||
	    (nd->lpn_enabled && (op == MESH_FRIEND_OP_OFFER ||
	    op == MESH_FRIEND_OP_UPDATE))))
		return (0);
	switch (op) {
	case MESH_FRIEND_OP_REQUEST:
		rpl_slot = 0;
		break;
	case MESH_FRIEND_OP_POLL:
		rpl_slot = 1;
		break;
	case MESH_FRIEND_OP_SUBLIST_ADD:
		rpl_slot = 2;
		break;
	case MESH_FRIEND_OP_SUBLIST_REMOVE:
		rpl_slot = 3;
		break;
	case MESH_FRIEND_OP_CLEAR:
		rpl_slot = 4;
		break;
	case MESH_FRIEND_OP_OFFER:
		rpl_slot = 5;
		break;
	case MESH_FRIEND_OP_CLEAR_CONFIRM:
		/*
		 * Admit the Friend Clear Confirm so the Friend Clear initiator
		 * stops repeating on the Confirm rather than only at the 2x
		 * PollTimeout deadline (C6-M7).
		 */
		rpl_slot = 7;
		break;
	default: /* MESH_FRIEND_OP_UPDATE */
		rpl_slot = 6;
		break;
	}
	if (mesh_rpl_check(&nd->friend_rpl[rpl_slot], np.src, iv_used,
	    np.seq) != 1)
		return (1);

	now = nd->tick_last;
	ivu = (nd->self->iv.state == MESH_IV_UPDATE_IN_PROGRESS) ? 1 : 0;
	if (nd->friend_enabled &&
	    (op == MESH_FRIEND_OP_REQUEST || op == MESH_FRIEND_OP_POLL ||
	    op == MESH_FRIEND_OP_SUBLIST_ADD ||
	    op == MESH_FRIEND_OP_SUBLIST_REMOVE || op == MESH_FRIEND_OP_CLEAR ||
	    op == MESH_FRIEND_OP_CLEAR_CONFIRM)) {
			struct mesh_friend_out out;

			memset(&out, 0, sizeof(out));
			/*
			 * The empty-queue Friend Update carries the network's
			 * current Key Refresh flag and IV Index (Section 3.6.5.2),
			 * not a hardcoded 0 / the Poll's decrypt IV: LPNs adopt the
			 * IV Index and Key Refresh state solely from these Updates
			 * (C6-M8).
			 */
			if (meshd_friend_input(nd, np.src, np.transport,
			    np.transport_len, MESHD_FRIEND_RX_RSSI,
			    (uint8_t)mesh_kr_beacon_flag(&nd->self->kr), ivu, iv,
			    now, &out) >= 0)
				meshd_friend_emit(nd, nd->friend_fsm.lpn_addr,
				    &out);
	}
	if (nd->lpn_enabled && op == MESH_FRIEND_OP_OFFER)
			(void)meshd_lpn_recv_offer(nd, np.transport,
			    np.transport_len, np.src, now);
	if (nd->lpn_enabled && op == MESH_FRIEND_OP_UPDATE) {
			struct mesh_lpn_out lout;

			memset(&lout, 0, sizeof(lout));
			if (meshd_lpn_recv_update(nd, np.transport,
			    np.transport_len, now, &lout) >= 0) {
				/*
				 * An LPN learns the network IV Index/state ONLY
				 * from Friend Updates.  Feed the learned value
				 * into the node IV state machine (same rules as a
				 * Secure Network beacon); previously nothing
				 * consumed mesh_lpn_fsm_iv_index, so the LPN never
				 * advanced and lost the friendship after the
				 * Friend moved to the new index (NB-11).
				 */
				(void)mesh_iv_recv_beacon(&nd->self->iv,
				    mesh_lpn_fsm_iv_index(&nd->lpn_fsm),
				    nd->lpn_fsm.iv_update,
				    nd->sim.wall_now != 0 ? nd->sim.wall_now :
				    nd->sim.now);
				meshd_sync_mgr_iv(nd);
			}
	}
	return (1);
}

static void
meshd_friendship_access_queue_rx(struct meshd_node *nd, const uint8_t *pdu,
    size_t len)
{
	struct mesh_net_pdu np;
	struct {
		uint8_t nid;
		const uint8_t *enckey;
		const uint8_t *privkey;
	} keys[2];
	uint32_t ivc[2], iv;
	size_t ki, nkeys, ni, niv;
	int ok = 0;

	if (nd->self == NULL || !nd->friend_enabled)
		return;
	/*
	 * Use the network-current IV Index for the RX decrypt candidates
	 * {iv_index, iv_index-1}, NOT mesh_iv_tx_index (which returns iv_index-1
	 * during this node's own IV Update and would omit the current index n).
	 * A peer that has completed its update secures LPN-destined traffic at
	 * n, so the Friend must accept n to queue it -- same NB-12 fix as the
	 * friendship control RX path, which this sibling had missed.
	 */
	iv = nd->self->iv.iv_index;
	ivc[0] = iv;
	niv = 1;
	if (iv > 0) {
		ivc[1] = iv - 1;
		niv = 2;
	}
	/*
	 * During a Key Refresh a message destined for the LPN may be secured
	 * with the new NetKey; try both credentials (mirroring the friendship
	 * control path) so new-key traffic is still queued for the LPN (C6-M9).
	 */
	nkeys = 0;
	if (mesh_kr_rx_accept_old(&nd->self->kr)) {
		keys[nkeys].nid = nd->self->nid;
		keys[nkeys].enckey = nd->self->enckey;
		keys[nkeys].privkey = nd->self->privkey;
		nkeys++;
	}
	if (nd->self->have_new_key && mesh_kr_rx_accept_new(&nd->self->kr)) {
		keys[nkeys].nid = nd->self->new_nid;
		keys[nkeys].enckey = nd->self->new_enckey;
		keys[nkeys].privkey = nd->self->new_privkey;
		nkeys++;
	}
	for (ki = 0; ki < nkeys && !ok; ki++)
		for (ni = 0; ni < niv && !ok; ni++)
			if (mesh_net_decrypt(keys[ki].enckey, keys[ki].privkey,
			    keys[ki].nid, ivc[ni], pdu, len, &np) == 0)
				ok = 1;
	if (!ok || np.transport_len == 0)
		return;
	if (np.ctl == 0 && nd->friend_enabled &&
	    np.transport_len <= MESH_FQ_PDU_MAX) {
		struct mesh_fq_entry e;

		/*
		 * A message off the network destined for our LPN: offer it to
		 * the Friend Queue (Section 3.5.5).  mesh_fq_enqueue applies the
		 * DST / TTL / duplicate filter, so a message for anyone else is
		 * silently dropped here.
		 */
		memset(&e, 0, sizeof(e));
		e.ctl = np.ctl;
		e.ttl = np.ttl;
		e.seq = np.seq;
		e.src = np.src;
		e.dst = np.dst;
		memcpy(e.pdu, np.transport, np.transport_len);
		e.pdu_len = np.transport_len;
		/*
		 * This path enqueues the raw Lower Transport PDU without SAR
		 * reassembly, so an individual segment (SEG bit set in octet 0)
		 * can arrive here.  Flag it so mesh_fq_enqueue applies the §3.5.5
		 * as-yet-unreassembled-segment gate rather than storing it as a
		 * deliverable message (P-H7).
		 */
		e.segmented = (np.transport[0] & 0x80u) ? 1 : 0;
		(void)meshd_friend_enqueue(nd, &e);
	}
}

/*
 * Enable the Friend role: initialise the Friend engine with the local Offer
 * parameters and acceptance policy and reflect the state in the Config Server.
 * The Friend Queue is bound to an LPN when the first Friend Request is accepted.
 */
int
meshd_friend_role_enable(struct meshd_node *nd)
{

	if (nd == NULL || nd->self == NULL)
		return (-1);
	if (meshd_friend_enable(nd, MESHD_FRIEND_RECV_WINDOW,
	    MESHD_FRIEND_QUEUE_SIZE, MESHD_FRIEND_SUBLIST_SIZE,
	    MESHD_FRIEND_MIN_RSSI, MESHD_FRIEND_MAX_QSIZE_LOG) != 0)
		return (-1);
	nd->cfg.friend = 1;
	return (0);
}

/* Disable the Friend role. */
void
meshd_friend_role_disable(struct meshd_node *nd)
{

	if (nd == NULL)
		return;
	nd->friend_enabled = 0;
	if (nd->cfg.friend == 1)
		nd->cfg.friend = 0;
	/*
	 * MshPRT 4.2.14: setting the Friend state to Disabled terminates any
	 * established friendship.  Just clearing friend_enabled leaves the
	 * friendship credential live -- and have_friend_cred is consulted as an
	 * RX decrypt candidate independently of friend_enabled -- so a stale
	 * credential would keep decrypting friendship-secured PDUs after the
	 * role is administratively off.  Drop the credential and reset the Friend
	 * FSM (friendship, message queue, and subscription list) so nothing of
	 * the terminated friendship survives; the LPN discovers the loss via its
	 * PollTimeout.
	 */
	if (nd->self != NULL)
		nd->self->have_friend_cred = 0;
	mesh_friend_fsm_init(&nd->friend_fsm, nd->addr, MESHD_FRIEND_RECV_WINDOW,
	    MESHD_FRIEND_QUEUE_SIZE, MESHD_FRIEND_SUBLIST_SIZE,
	    MESHD_FRIEND_MIN_RSSI, MESHD_FRIEND_MAX_QSIZE_LOG);
}

/*
 * Enable the Low Power node role: initialise the LPN engine with the Friend
 * Request criteria and poll cadence.  The Friend Request is originated on the
 * first node tick once a bearer is attached (mesh_lpn_fsm_start from IDLE), and
 * the cadence Polls / re-establishment run from later ticks.
 */
int
meshd_lpn_role_enable(struct meshd_node *nd)
{
	uint32_t poll_timeout;

	if (nd == NULL || nd->self == NULL)
		return (-1);
	poll_timeout = nd->db.lpn_poll_timeout != 0 ? nd->db.lpn_poll_timeout :
	    MESHD_LPN_POLL_TIMEOUT;
	mesh_lpn_fsm_init(&nd->lpn_fsm, nd->addr, nd->self->n_elements,
	    MESHD_LPN_RSSI_FACTOR, MESHD_LPN_RXWIN_FACTOR,
	    MESHD_LPN_MIN_QSIZE_LOG, MESHD_LPN_RECV_DELAY_MS, poll_timeout,
	    MESHD_LPN_OFFER_WINDOW_MS, MESHD_LPN_POLL_INTERVAL_MS);
	nd->lpn_enabled = 1;
	nd->db.lpn_poll_timeout = poll_timeout;
	return (0);
}

/* Disable the Low Power node role. */
void
meshd_lpn_role_disable(struct meshd_node *nd)
{

	if (nd == NULL)
		return;
	nd->lpn_enabled = 0;
}

/* ================================================================
 * Provisioner role (MshPRT_v1.1 Section 5).
 * ================================================================ */

int
meshd_provisioner_begin(struct meshd_node *nd, const uint8_t device_uuid[16],
    uint32_t link_id, const uint8_t priv[32], const uint8_t random[32],
    uint8_t attention, const struct mesh_prov_data *data,
    uint32_t retry_interval_ms, unsigned max_retries, uint64_t now,
    uint8_t *out, size_t *outlen)
{

	if (nd == NULL || device_uuid == NULL || data == NULL || out == NULL ||
	    outlen == NULL)
		return (-1);
	if (mesh_prov_provisioner_init(&nd->prov_sess, priv, random, attention,
	    data) != 0)
		return (-1);
	if (mesh_prov_session_start(&nd->prov_sess) != 0) {
		mesh_prov_session_free(&nd->prov_sess);
		return (-1);
	}
	mesh_prov_link_init_provisioner(&nd->prov_link, link_id, device_uuid,
	    retry_interval_ms, max_retries);
	nd->provisioner_active = 1;
	nd->prov_ack_pending = 0;
	if (mesh_prov_link_open(&nd->prov_link, now, out, outlen) != 0) {
		/*
		 * The link failed to open: undo the active flag and release the
		 * session, otherwise provisioner_active stays set and blocks
		 * every later provisioning attempt while the session leaks
		 * (finding 123).
		 */
		mesh_prov_session_free(&nd->prov_sess);
		nd->provisioner_active = 0;
		return (-1);
	}
	return (0);
}

int
meshd_provisioner_recv(struct meshd_node *nd, const uint8_t *pkt, size_t len,
    uint64_t now)
{
	uint8_t rpdu[MESH_PROV_PDU_MAX];
	size_t rlen;
	int have_pdu, have_ack;

	if (nd == NULL || pkt == NULL || !nd->provisioner_active)
		return (-1);

	have_pdu = 0;
	have_ack = 0;
	if (mesh_prov_link_recv(&nd->prov_link, pkt, len, now, rpdu, &rlen,
	    &have_pdu, nd->prov_ack, &nd->prov_ack_len, &have_ack) != 0)
		return (-1);
	if (have_ack)
		nd->prov_ack_pending = 1;
	if (have_pdu) {
		/* Feed the reassembled Provisioning PDU to the session. */
		(void)mesh_prov_session_recv(&nd->prov_sess, rpdu, rlen);
	}
	return (0);
}

int
meshd_provisioner_poll(struct meshd_node *nd, uint64_t now, uint8_t *out,
    size_t *outlen)
{
	uint8_t ppdu[MESH_PROV_PDU_MAX];
	size_t plen;
	int rc;

	if (nd == NULL || out == NULL || outlen == NULL || !nd->provisioner_active)
		return (-1);

	/* Transaction Acks take priority so the peer can advance promptly. */
	if (nd->prov_ack_pending) {
		memcpy(out, nd->prov_ack, nd->prov_ack_len);
		*outlen = nd->prov_ack_len;
		nd->prov_ack_pending = 0;
		return (1);
	}

	/* Drain any in-flight link output (Link Open, segments, retransmit). */
	rc = mesh_prov_link_poll(&nd->prov_link, now, out, outlen);
	if (rc != 0)
		return (rc);

	/* Link idle and open: start the next queued Provisioning PDU. */
	if (mesh_prov_link_idle(&nd->prov_link)) {
		rc = mesh_prov_session_poll(&nd->prov_sess, ppdu, &plen);
		if (rc == 1) {
			if (mesh_prov_link_send(&nd->prov_link, ppdu, plen,
			    now) != 0)
				return (-1);
			return (mesh_prov_link_poll(&nd->prov_link, now, out,
			    outlen));
		}
	}
	return (0);
}

int
meshd_provisioner_drain(struct meshd_node *nd, uint64_t now)
{
	uint8_t pkt[MESH_PBADV_PKT_MAX];
	size_t len;
	int n = 0;

	if (nd == NULL || !nd->provisioner_active)
		return (0);

	/*
	 * Hand every ready PB-ADV bearer packet (Link Open, transaction
	 * segments, Acks, retransmits) to the bearer tagged as PB-ADV.  poll()
	 * is timing-gated, so at a fixed `now` it returns 0 once the burst is
	 * drained; the iteration cap is a belt-and-suspenders busy-loop guard.
	 */
	while (n < 64) {
		int rc = meshd_provisioner_poll(nd, now, pkt, &len);

		if (rc != 1)
			break;
		n++;
		nd->tx_frames++;
		if (nd->bearer != NULL && nd->bearer->tx != NULL) {
			if (nd->bearer->tx(nd->bearer->arg, MESHD_PDU_PROV, pkt,
			    len) != 0)
				nd->tx_errors++;
		}
	}
	return (n);
}

int
meshd_provisioner_done(const struct meshd_node *nd)
{

	return (nd != NULL && (nd->provisioner_active || nd->pbgatt.active) &&
	    mesh_prov_session_done(&nd->prov_sess));
}

int
meshd_provisioner_begin_mgr(struct meshd_node *nd, struct mesh_mgr *mgr,
    const uint8_t device_uuid[16], uint8_t num_elements, uint32_t link_id,
    const uint8_t priv[32], const uint8_t random[32], uint8_t attention,
    uint32_t retry_interval_ms, unsigned max_retries, uint64_t now,
    uint8_t *out, size_t *outlen)
{
	struct mesh_prov_data pd;

	if (nd == NULL || mgr == NULL || device_uuid == NULL)
		return (-1);
	/* The manager allocates the address and fills the provisioning data. */
	if (mesh_mgr_provision_prepare(mgr, device_uuid, num_elements, &pd) != 0)
		return (-1);
	if (meshd_provisioner_begin(nd, device_uuid, link_id, priv, random,
	    attention, &pd, retry_interval_ms, max_retries, now, out,
	    outlen) != 0) {
		mesh_mgr_provision_abort(mgr);
		return (-1);
	}
	return (0);
}

struct mesh_mgr_node *
meshd_provisioner_commit_mgr(struct meshd_node *nd, struct mesh_mgr *mgr,
    uint64_t prov_time)
{
	const uint8_t *devkey;

	if (nd == NULL || mgr == NULL || !meshd_provisioner_done(nd))
		return (NULL);
	devkey = mesh_prov_session_devkey(&nd->prov_sess);
	if (devkey == NULL)
		return (NULL);
	return (mesh_mgr_provision_commit(mgr, devkey,
	    mesh_prov_session_num_elements(&nd->prov_sess), prov_time));
}

/*
 * OTA provisioning driver (the operator-facing wrapper of the manager-driven
 * Provisioner seam).  begin reserves an address, opens the PB-ADV link toward an
 * unprovisioned device and emits the initial Link Open to the bearer; the tick
 * loop then pumps the handshake via meshd_provisioner_recv / _drain until
 * meshd_provisioner_done, at which point commit records the node + DevKey.
 */
#define	MESHD_OTA_RETRY_MS	500u
#define	MESHD_OTA_MAX_RETRIES	5u

int
meshd_provision_ota_begin(struct meshd_node *nd, const uint8_t device_uuid[16],
    uint8_t num_elements, uint64_t now)
{
	uint8_t out[MESH_PBADV_PKT_MAX];
	size_t outlen;
	uint32_t link_id;

	if (nd == NULL || device_uuid == NULL || num_elements < 1)
		return (-1);
	if (!nd->mgr_active || nd->mgr == NULL)
		return (-1);
	if (nd->provisioner_active || nd->prov_target_active)
		return (-1);			/* one provisioning at a time */

	/* A per-session Link ID (MshPRT_v1.1 Section 5.3.1): distinct per attempt. */
	link_id = 0x4D455348u ^ (uint32_t)now ^
	    (mesh_sim_node_seq(nd->self) << 1) ^ device_uuid[0];

	if (meshd_provisioner_begin_mgr(nd, nd->mgr, device_uuid, num_elements,
	    link_id, NULL, NULL, 0, MESHD_OTA_RETRY_MS, MESHD_OTA_MAX_RETRIES,
	    now, out, &outlen) != 0)
		return (-1);
	if (nd->bearer != NULL && nd->bearer->tx != NULL)
		(void)nd->bearer->tx(nd->bearer->arg, MESHD_PDU_PROV, out, outlen);

	memcpy(nd->prov_target_uuid, device_uuid, sizeof(nd->prov_target_uuid));
	nd->prov_target_elements = num_elements;
	nd->prov_target_active = 1;
	nd->prov_failed = 0;
	return (0);
}

int
meshd_provision_gatt_begin(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t adapter_index,
    const uint8_t device_uuid[16], uint8_t num_elements)
{
	struct mesh_prov_data pd;

	if (nd == NULL || addr == NULL || strlen(addr) != 17 ||
	    addr_type > MESHD_ADDR_RANDOM || device_uuid == NULL ||
	    num_elements < 1 ||
	    !nd->mgr_active ||
	    nd->mgr == NULL || nd->prov_target_active || nd->provisioner_active ||
	    nd->pbgatt.active || nd->bearer == NULL ||
	    nd->bearer->pbgatt_open == NULL)
		return (-1);
	if (mesh_mgr_provision_prepare(nd->mgr, device_uuid, num_elements,
	    &pd) != 0)
		return (-1);
	/* MTU 23 is always available; discovery may later grow the transport. */
	if (meshd_pbgatt_begin(nd, MESHD_PBGATT_MIN_MTU, NULL, NULL, 0,
	    &pd) != 0) {
		mesh_mgr_provision_abort(nd->mgr);
		return (-1);
	}
	nd->pbgatt.adapter_index = adapter_index;
	if (nd->bearer->pbgatt_open(nd->bearer->arg, addr, addr_type,
	    adapter_index) != 0) {
		if (nd->pbgatt.active) {
			mesh_prov_session_free(&nd->prov_sess);
			memset(&nd->pbgatt, 0, sizeof(nd->pbgatt));
		}
		mesh_mgr_provision_abort(nd->mgr);
		return (-1);
	}
	memcpy(nd->prov_target_uuid, device_uuid, sizeof(nd->prov_target_uuid));
	nd->prov_target_elements = num_elements;
	nd->prov_target_active = 1;
	return (0);
}

/*
 * Emit a PB-ADV Link Close (MshPRT 5.3.1.4.2/.3) so a provisioned device
 * releases the bearer link immediately instead of holding it for its ~60s
 * timeout -- during which it ignores a fresh Link Open (including our own
 * retry) and cannot be re-provisioned (NB-22).  reason: 0=Success, 1=Timeout,
 * 2=Fail.  Only meaningful for an active PB-ADV link we still own.
 */
static void
meshd_prov_send_link_close(struct meshd_node *nd, uint8_t reason)
{
	uint8_t lc[64];
	size_t lclen = sizeof(lc);

	if (nd->bearer == NULL || nd->bearer->tx == NULL)
		return;
	if (nd->prov_link.state == MESH_LINK_CLOSED ||
	    nd->prov_link.state == MESH_LINK_FAILED)
		return;
	if (mesh_prov_link_close(&nd->prov_link, reason, lc, &lclen) == 0)
		(void)nd->bearer->tx(nd->bearer->arg, MESHD_PDU_PROV, lc, lclen);
}

struct mesh_mgr_node *
meshd_provision_ota_commit(struct meshd_node *nd, uint64_t prov_time)
{
	struct mesh_mgr_node *n;

	if (nd == NULL || !nd->prov_target_active)
		return (NULL);
	n = meshd_provisioner_commit_mgr(nd, nd->mgr, prov_time);
	if (n == NULL) {
		/*
		 * The commit consumed the manager's pending reservation, so a
		 * retry can never succeed; without tearing down, the tick would
		 * re-call commit forever with prov_target_active still set and
		 * wedge the provisioner (NB-21).  Abort cleanly instead.
		 */
		meshd_provision_ota_abort(nd, 1);
		return (NULL);
	}
	if (n != NULL) {
		nd->prov_target_active = 0;
		nd->provisioner_active = 0;
		nd->prov_ack_pending = 0;
		nd->prov_failed = 0;
		/*
		 * PB-GATT completes by closing its GATT provisioning link, which
		 * frees the provisioning session.  The PB-ADV path has no link to
		 * close, so free the session here: the next provisioner_init would
		 * otherwise memset it and leak the EVP_PKEY (finding C-m2).
		 */
		if (nd->pbgatt.active)
			meshd_pbgatt_close(nd);
		else {
			/* Close the PB-ADV link with reason Success before freeing
			 * the session so the device releases it now (NB-22). */
			meshd_prov_send_link_close(nd, 0x00);
			mesh_prov_session_free(&nd->prov_sess);
		}
	}
	return (n);
}

int
meshd_provision_ota_failed(const struct meshd_node *nd)
{

	if (nd == NULL || !nd->prov_target_active)
		return (0);
	/*
	 * A peer-initiated bearer Link Close leaves the link in MESH_LINK_CLOSED,
	 * which mesh_prov_link_poll never times out -- so without treating it as
	 * a failure the provisioner stays active forever (ota_begin/gatt_begin
	 * reject, EVP_PKEY leaks) until a daemon restart (NB-19).
	 */
	if (nd->provisioner_active &&
	    (nd->prov_link.state == MESH_LINK_FAILED ||
	    nd->prov_link.state == MESH_LINK_CLOSED ||
	    mesh_prov_session_failed(&nd->prov_sess)))
		return (1);
	return (0);
}

void
meshd_provision_ota_abort(struct meshd_node *nd, int failed)
{

	if (nd == NULL || (!nd->provisioner_active && !nd->prov_target_active))
		return;
	/* Release the manager-reserved unicast address for this target. */
	if (nd->mgr != NULL)
		mesh_mgr_provision_abort(nd->mgr);
	if (nd->provisioner_active) {
		/* Close the PB-ADV link (reason Fail/Success) before freeing so a
		 * conformant device does not hold it for ~60s (NB-22). */
		if (!nd->pbgatt.active)
			meshd_prov_send_link_close(nd, failed ? 0x02 : 0x00);
		mesh_prov_session_free(&nd->prov_sess);
	}
	if (nd->pbgatt.active)
		meshd_pbgatt_close(nd);
	nd->provisioner_active = 0;
	nd->prov_target_active = 0;
	nd->prov_ack_pending = 0;
	nd->prov_failed = failed ? 1 : 0;
}
