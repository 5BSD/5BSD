/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * meshd - a Bluetooth Mesh node daemon built on libblemesh.
 *
 * meshd is a provisionable mesh node: it holds the node's security material
 * (NetKey, AppKey, IV Index, sequence number and Replay Protection List),
 * registers the Generic OnOff / Generic Level application models and the
 * Configuration / Health foundation models, and processes access-layer
 * messages.
 *
 * ENGINE.  The receive/relay/reassemble/dispatch pipeline is libblemesh's
 * mesh_sim(3) network engine driven as a SINGLE-NODE network: the daemon owns
 * one struct mesh_sim holding just this node.  Inbound secured Network PDUs
 * from the bearer are reinjected onto the sim medium and stepped through the
 * full pipeline into the node; outbound PDUs the node originates land on the
 * sim transmit queue and are drained to the bearer.
 *
 * BEARER SEAM.  meshd deliberately does NOT talk to a radio yet.  The bearer
 * is an explicit integration seam (struct meshd_bearer): the real advertising
 * bearer (LE non-connectable advertising / scanning via HCI) and the GATT
 * Proxy bearer (the Mesh Proxy Service on the blued ATT server) plug in here.
 * See meshd.8 BEARER INTEGRATION and the comments on struct meshd_bearer.
 *
 * The daemon logic is pure and testable: the node core (meshd_node.c), the
 * configuration parser (meshd_config.c) and the control surface (meshd_ctl.c)
 * perform no I/O of their own; meshd.c is the thin main()/socket glue.
 */

#ifndef _MESHD_H_
#define _MESHD_H_

#include <stddef.h>
#include <stdint.h>

#include "mesh_sim.h"
#include "mesh_access.h"
#include "mesh_beacon.h"
#include "mesh_cfg_model.h"
#include "mesh_cfg_v11.h"
#include "mesh_bridge.h"
#include "mesh_health_model.h"
#include "mesh_heartbeat.h"
#include "mesh_generic.h"
#include "meshd_models.h"
#include "mesh_prov_cert.h"
#include "mesh_prov_records.h"
#include "mesh_provision.h"
#include "mesh_friend.h"
#include "mesh_lpn.h"
#include "mesh_provisioner.h"
#include "mesh_manager.h"
#include "mesh_df.h"
#include "mesh_remote_prov.h"

/* Mesh unicast address range (MshPRT_v1.1 Section 3.4.2): 0x0001..0x7FFF. */
#define	MESHD_UNICAST_MIN	0x0001u
#define	MESHD_UNICAST_MAX	0x7FFFu

/* Development defaults; deployed nodes should configure their assigned IDs. */
#define	MESHD_DEFAULT_CID	0x05F1u
#define	MESHD_DEFAULT_PID	0x0001u
#define	MESHD_DEFAULT_VID	0x0001u

/* Phantom transmit-node index used when reinjecting a bearer-received PDU:
 * negative, so mesh_sim_step() delivers it to every real node (just ours). */
#define	MESHD_BEARER_TX_NODE	(-1)

/* Secure Network beacon transmit cadence (MshPRT_v1.1 Section 3.9.3), seconds. */
#define	MESHD_BEACON_INTERVAL	10

/*
 * Identity advertising duration (MshPRT_v1.1.1 Sections 7.2.2.2.3 and
 * 7.2.2.2.5): the Node Identity and Private Node Identity timers run for 60
 * seconds from the moment the corresponding state is set to enabled.
 */
#define	MESHD_IDENTITY_ADV_MS	60000ULL

/*
 * Default Random Update Interval Steps (MshPRT_v1.1.1 Table 4.73): 60 steps of
 * 10 seconds, i.e. the Mesh Private beacon Random is regenerated every 10
 * minutes until a Config Private Beacon Set says otherwise.
 */
#define	MESHD_PRIV_BEACON_STEPS_DEFAULT	60

/*
 * Friend Subscription List retransmission: how long to wait for the Friend
 * Subscription List Confirm before repeating the message, and how many times.
 */
#define	MESHD_LPN_SUB_RETRY_MS	2000ULL
#define	MESHD_LPN_SUB_MAX_RETRIES	3

#define	MESHD_MAX_APP_CLIENTS	16

/* Control-socket reply buffer size; shared by meshd.c and meshd_ctl.c. */
#define	MESHD_CTL_REPLY_MAX	2048
#define	MESHD_MAX_PROXY_GATT	4
#define	MESHD_MAX_SCAN_RESULTS	16	/* unprovisioned-device discovery cache */

/* ================================================================
 * Configuration.
 * ================================================================ */

/*
 * Parsed meshd.conf.  Keys and IV/address are the node's provisioning data;
 * the AppKey is bound by a later Config AppKey Add (carried here for the
 * skeleton).  A NUL, all-zero key is treated as "unset".
 */
struct meshd_persist;

struct meshd_config {
	uint8_t		device_uuid[16];
	uint16_t	company_id;
	uint16_t	product_id;
	uint16_t	version_id;
	uint8_t		netkey[16];
	uint16_t	netkey_index;
	uint8_t		appkey[16];
	uint16_t	appkey_index;
	uint8_t		device_key[16];
	uint32_t	iv_index;
	uint16_t	unicast_addr;
	uint8_t		default_ttl;
	uint16_t	features;		/* MESH_CFG_FEATURE_* */
	int		have_netkey;
	int		have_appkey;
	int		have_device_key;
	int		have_uuid;
	char		blued_socket[104];	/* blued control socket path */
};

void	meshd_config_defaults(struct meshd_config *cfg);
/*
 * Parse one "key value" configuration line into cfg.  Blank lines and lines
 * beginning with '#' are ignored.  Returns 0 on success (or an ignored line),
 * -1 on an unknown key or a malformed value.
 */
int	meshd_config_parse_line(struct meshd_config *cfg, const char *line);
/* Validate a fully-parsed config (address range, TTL, required keys). */
int	meshd_config_validate(const struct meshd_config *cfg);
/* Load and parse a config file; returns 0, -1 on open/parse/validate error. */
int	meshd_config_load(struct meshd_config *cfg, const char *path);

/*
 * Decode an even-length hex string into out (writing exactly outlen octets).
 * Returns 0 on success, -1 on a bad character or a length mismatch.
 */
int	meshd_hexdecode(const char *hex, uint8_t *out, size_t outlen);

/* ================================================================
 * Bearer seam.
 * ================================================================ */

/*
 * The AD-type class of an outbound mesh PDU.  meshd's three transmit sites each
 * produce a different mesh advertising AD type; the bearer sink carries this
 * discriminator so it can wrap the PDU in the correct AD structure (the radio
 * bearer, blued, is a dumb pipe and never parses the PDU).  The enum values
 * ARE the wire AD types (MshPRT_v1.1) so the mapping is unambiguous.
 */
enum meshd_pdu_class {
	MESHD_PDU_NET	= 0x2A,	/* Mesh Message / Network PDU (meshd_drain_tx) */
	MESHD_PDU_BEACON = 0x2B,/* Secure Network beacon (meshd_beacon_emit) */
	MESHD_PDU_PROV	= 0x29,	/* PB-ADV provisioning packet (provisioner) */
};

/* Address-type values used by the broker IPC (Bluetooth public/random). */
#define	MESHD_ADDR_PUBLIC	0u
#define	MESHD_ADDR_RANDOM	1u
#define	MESHD_ADAPTER_DEFAULT	0xffu

/*
 * A bearer transmit sink.  meshd hands each outbound mesh PDU to tx() tagged
 * with its AD-type class; the real advertising / GATT-proxy bearer implements
 * it.  tx() returns 0 on success, -1 on a transmit error (which meshd counts
 * but does not treat as fatal).  A NULL bearer or NULL tx() drops outbound PDUs
 * (loopback / test).
 */
struct meshd_bearer {
	int	(*tx)(void *arg, enum meshd_pdu_class cls, const uint8_t *pdu,
		    size_t len);
	int	(*pbgatt_open)(void *arg, const char *addr, uint8_t addr_type,
		    uint8_t adapter_index);
	int	(*proxy_open)(void *arg, const char *addr, uint8_t addr_type,
		    uint8_t adapter_index);
	int	(*pbgatt_close)(void *arg);
	/* Queue the timeout Failed PDU; completion owns the subsequent close. */
	int	(*pbgatt_timeout)(void *arg);
	int	(*proxy_close)(void *arg, const char *addr, uint8_t addr_type,
		    uint8_t adapter_index);
	int	(*proxy_tx)(void *arg, const char *addr, uint8_t addr_type,
	    uint8_t adapter_index, uint8_t type,
	    const uint8_t *pdu, size_t len);
	/*
	 * Proxy SERVER hooks (MshPRT_v1.1.1 Sections 6.7 and 7.2).  The three
	 * above drive the Proxy CLIENT role (this node connecting out to
	 * someone else's Mesh Proxy Service); these drive the server role,
	 * where a Proxy Client connects to us:
	 *
	 *   proxy_service   register/unregister the «Mesh Proxy Service» in the
	 *                   broker's GATT server (Section 7.2.3).
	 *   proxy_srv_tx    send one Proxy PDU to ONE connected Proxy Client as
	 *                   a Mesh Proxy Data Out notification.
	 *   proxy_adv       start/stop connectable proxy advertising carrying a
	 *                   Service Data AD structure under an advertising
	 *                   address policy (Section 7.2.2.2).
	 *
	 * Every one of them is optional: a bearer that does not implement the
	 * server role simply leaves them NULL and the node keeps working as a
	 * Proxy Client and an advertising-bearer node.
	 */
	int	(*proxy_service)(void *arg, int enable);
	int	(*proxy_srv_tx)(void *arg, const char *addr, uint8_t addr_type,
	    uint8_t adapter_index, const uint8_t *pdu, size_t len);
	int	(*proxy_adv)(void *arg, int enable, uint8_t addr_policy,
	    const uint8_t *ad, size_t adlen);
	void	*arg;
};

/*
 * Advertising-address policy passed to proxy_adv (MshPRT_v1.1.1 Sections
 * 7.2.2.2.4/7.2.2.2.5: "shall use a resolvable private address or a
 * non-resolvable private address").  Mirrors the broker's IPC_MESH_ADV_ADDR_*.
 */
#define	MESHD_ADV_ADDR_DEFAULT	0
#define	MESHD_ADV_ADDR_NRPA	1
#define	MESHD_ADV_ADDR_RPA	2

/* PB-GATT uses an ATT value of at least 20 octets at the default MTU 23. */
#define MESHD_PBGATT_MIN_MTU	23
#define MESHD_GATT_MAX_MTU	517
#define MESHD_PBGATT_MAX_SEGS	4
#define MESHD_PROXY_SAR_TIMEOUT_MS	20000ULL
#define MESHD_PBGATT_PROTOCOL_TIMEOUT_MS	60000ULL
#define MESHD_PBGATT_FAILED_CLOSE_TIMEOUT_MS	5000ULL
#define MESHD_PROV_ERR_UNEXPECTED_ERROR	0x07

struct meshd_pbgatt {
	struct mesh_pbgatt_reasm rx;
	struct mesh_proxy_pdu	tx[MESHD_PBGATT_MAX_SEGS];
	size_t			tx_count;
	size_t			tx_next;
	uint16_t		mtu;
	uint64_t		rx_started_ms;
	uint64_t		protocol_started_ms;
	uint64_t		timeout_started_ms;
	uint8_t			adapter_index;
	int			rx_started;
	int			protocol_timer;
	int			timeout_closing;
	int			active;
};

struct meshd_proxy_gatt {
	/*
	 * The reassembler owns the SAR timeout clock (mesh_proxy_reasm_tick);
	 * this structure deliberately keeps no second copy of it.
	 */
	struct mesh_proxy_reasm	rx;
	char			addr[18];
	uint16_t		mtu;
	uint8_t			filter_type;
	uint8_t			addr_type;
	uint8_t			adapter_index;
	uint16_t		filter_size;
	int			have_filter_status;
	int			active;
};

/*
 * Mesh Proxy SERVER per-connection state (MshPRT_v1.1.1 Section 6.7).
 *
 * "When a Proxy Client connects to a Proxy Server, a new instance of the GATT
 * bearer is connected to the network layer via a network interface", and "upon
 * connection, the Proxy Server shall initialize the proxy filter as an accept
 * list filter and the accept list shall be empty".  Both the proxy filter and
 * the SAR reassembly context are therefore per-connection, keyed on the
 * inbound GATT link (peer address + address type + controller).
 */
struct meshd_proxy_server {
	char				addr[18];
	uint8_t				addr_type;
	uint8_t				adapter_index;
	uint16_t			mtu;
	struct mesh_proxy_filter	filter;
	struct mesh_proxy_reasm		rx;
	/*
	 * Proxy Privacy parameter for this connection (Section 6.5), evaluated
	 * once on connection per Section 7.2.2.2.6 and retained for the
	 * lifetime of the connection: it selects Secure Network beacons
	 * (Disabled) or Mesh Private beacons (Enabled) on this link.
	 */
	uint8_t				privacy;
	/*
	 * The Section 6.7 connect-time "mesh beacon for each known subnet"
	 * could not be delivered yet -- typically because the Proxy Client has
	 * not enabled notifications on Mesh Proxy Data Out at the instant the
	 * link came up.  Retried from the tick until it lands or the connection
	 * goes away, so the beacons are not simply lost.
	 */
	int				beacons_pending;
	uint64_t			beacons_retry_ms;
	int				active;
};

#define	MESHD_MAX_PROXY_SERVER	4

/* ================================================================
 * Node configuration database (MshMDL_v1.1 Section 4.2, 4.4.1.1).
 *
 * The Configuration Server mutates this database in response to Configuration
 * Client messages: the NetKey / AppKey lists and their bindings, the per-model
 * AppKey bindings, subscription lists (group and virtual) and publication
 * state, and the node-wide states (Relay, GATT Proxy, Friend, Beacon, Default
 * TTL, Network Transmit, per-subnet Node Identity and Key Refresh Phase,
 * Heartbeat Publication / Subscription and the LPN PollTimeout).
 * ================================================================ */
#define	MESHD_MAX_NETKEYS	4
#define	MESHD_MAX_APPKEYS	8
#define	MESHD_MAX_MODELS	48	/* models across all local elements */
#define	MESHD_MAX_BINDINGS	4	/* AppKey bindings per model */
#define	MESHD_MAX_SUBS		8	/* subscription addresses per model */
#define	MESHD_MAX_APP_REGS	16	/* app-owned element/model registrations */
#define	MESHD_APP_EVENT_MAX	32	/* queued inbound app events */

/* One subnet: a NetKey plus its per-subnet Node Identity / Key Refresh state. */
/*
 * Directed Forwarding Configuration Server sub-states (MshMDL_v1.1 Section
 * 4.4.3).  Every one of these is keyed by NetKeyIndex, so it belongs to the
 * subnet, not to the node: a single node-wide copy let a Set on subnet 1
 * overwrite subnet 0 and made Get answer with the wrong subnet's values.
 * (Directed Network Transmit / Directed Relay Retransmit ARE node-wide and
 * stay on struct meshd_df_state.)
 */
struct meshd_df_subnet {
	struct mesh_cfg_directed_control	control;
	struct mesh_cfg_path_metric		metric;
	struct mesh_cfg_wanted_lanes		lanes;
	struct mesh_cfg_two_way_path		two_way;
	struct mesh_cfg_path_echo_interval	echo;
};

struct meshd_netkey_entry {
	int		valid;
	uint16_t	net_idx;
	uint8_t		key[16];
	struct meshd_df_subnet	df;	/* per-subnet DF Config Server state */
	uint8_t		kr_phase;	/* MESH_CFG_KR_PHASE_*, mirrors the sim */
	int		has_new_key;	/* Key Refresh new NetKey held (Phase 1/2) */
	uint8_t		new_key[16];	/* the distributed new NetKey */
	uint8_t		node_identity;	/* MESH_CFG_NODE_IDENTITY_* */
	uint8_t		priv_node_identity; /* MESH_CFG_PRIV_IDENTITY_* */
	/*
	 * Identity advertising timers (MshPRT_v1.1.1 Sections 7.2.2.2.3 and
	 * 7.2.2.2.5).  Setting the state to enabled starts a 60-second timer for
	 * the subnet; when it expires the server stops advertising for that
	 * subnet and sets the state back to disabled.  Monotonic milliseconds;
	 * 0 means the timer is not running.  Runtime only: an identity
	 * advertisement never survives a restart, and the restore path already
	 * brings both states up STOPPED.
	 */
	uint64_t	identity_deadline_ms;
	uint64_t	priv_identity_deadline_ms;
	/*
	 * Mesh Private beacon transmit state for this subnet (MshPRT_v1.1.1
	 * Section 3.10.4.2).  The Random field is per-subnet and is regenerated
	 * on the Random Update Interval Steps cadence (Section 4.2.44.2) and
	 * whenever the Flags or IV Index differ from the previously transmitted
	 * beacon for the subnet.  Runtime only: nothing here is persisted, since
	 * a restart must draw a fresh Random anyway.
	 */
	uint8_t		pb_random[MESH_PRIVATE_BEACON_RANDOM_LEN];
	uint64_t	pb_random_ms;	/* monotonic ms the Random was drawn */
	uint32_t	pb_last_iv_index;
	uint8_t		pb_last_flags;
	int		have_pb_random;
	int		have_pb_last;
};

/* One AppKey and the NetKey (subnet) it is bound to. */
struct meshd_appkey_entry {
	int		valid;
	uint16_t	app_idx;
	uint16_t	net_idx;
	uint8_t		key[16];
	int		has_new_key;	/* Config AppKey Update staged (KR Phase 1) */
	uint8_t		new_key[16];	/* the staged new AppKey */
};

/* Per-model configuration: AppKey bindings, subscriptions, publication. */
struct meshd_model_entry {
	int				valid;
	uint16_t			elem_addr;
	struct mesh_cfg_model_id	id;
	uint16_t			app_idx[MESHD_MAX_BINDINGS];
	size_t				n_app;
	uint16_t			subs[MESHD_MAX_SUBS];	/* group / virtual addr */
	uint8_t				sub_label[MESHD_MAX_SUBS][MESH_LABEL_UUID_LEN];
	int				sub_is_va[MESHD_MAX_SUBS];
	size_t				n_subs;
	struct mesh_cfg_model_pub	pub;			/* publication state */
	int				has_pub;
	int				pub_is_va;
	uint8_t				pub_label[MESH_LABEL_UUID_LEN];
	uint32_t			pub_get_opcode;	/* 0 for app-owned payloads */
	uint8_t			pub_access[MESH_ACCESS_PAYLOAD_MAX];
	size_t			pub_access_len;
	uint64_t			next_pub_ms;
	uint64_t			next_retransmit_ms;
	uint8_t			retransmit_left;
};

struct meshd_cfg_db {
	struct meshd_netkey_entry	netkeys[MESHD_MAX_NETKEYS];
	struct meshd_appkey_entry	appkeys[MESHD_MAX_APPKEYS];
	struct meshd_model_entry	models[MESHD_MAX_MODELS];
	size_t				n_models;
	uint8_t				net_transmit;	/* packed count/interval */
	struct mesh_hb_pub		hb_pub;
	/*
	 * There is deliberately no Heartbeat Subscription copy here: the only
	 * subscription state that ever counts received Heartbeats is the sim
	 * node's (nd->self->hb_sub, fed by mesh_hb_sub_receive), so a second
	 * copy here could only ever report Count/MinHops/MaxHops that never
	 * move.  h_hb_sub_get/h_hb_sub_set work on nd->self->hb_sub directly.
	 */
	uint32_t			lpn_poll_timeout; /* units of 100 ms */

	/*
	 * Mesh Protocol 1.1 Configuration states (MshMDL_v1.1 Section 4): the
	 * SAR Transmitter / Receiver state, the On-Demand Private GATT Proxy
	 * state, the Private Beacon / Private GATT Proxy states and the last
	 * Solicitation PDU RPL address range cleared.  Per-subnet Private Node
	 * Identity lives on struct meshd_netkey_entry.
	 */
	struct mesh_cfg_sar_transmitter	sar_tx;
	struct mesh_cfg_sar_receiver	sar_rx;
	uint8_t				od_priv_proxy;
	uint8_t				priv_beacon;
	uint8_t				priv_beacon_random_steps;
	uint8_t				priv_gatt_proxy;
	struct mesh_cfg_addr_range	sol_pdu_rpl_last;

	/*
	 * Subnet Bridge (MshPRT_v1.1.1 Sections 4.2.41-4.2.43).  The Bridge
	 * Configuration Server owns the single instance of both states; the
	 * network engine gets a copy through meshd_bridge_sync().  Both are
	 * persisted (the Bridging Table is operator-configured commissioning
	 * state, exactly like the NetKey and model tables beside it).  The
	 * Bridging Table Size state is not stored: it is the fixed capacity
	 * MESH_BRIDGE_TABLE_SIZE of the container, reported as a constant.
	 */
	uint8_t				subnet_bridge;
	struct mesh_bridging_table	bridging;
};

struct meshd_app_reg {
	int				valid;
	struct mesh_cfg_model_id	id;
	uint16_t			elem_addr;
	int				has_opcode;
	uint32_t			opcode;
};

/*
 * App-event kinds.  The queue carries received model messages (ACCESS, the
 * original and default kind) and, since operator-driven OOB provisioning
 * authentication, the two provisioning prompts of MshPRT_v1.1.1 Sections
 * 5.4.2.4.3 / 5.4.2.4.4:
 *
 *   - PROV_OOB_DISPLAY: show `params` (ASCII text, `params_len` characters)
 *     to the operator, who reads it out to the peer's user.  Raised by an
 *     Input OOB exchange, where this side generates the value.
 *   - PROV_OOB_INPUT: the peer is displaying a value of the announced Action
 *     and Size, and the operator must hand it back with "provision-oob-input".
 *     Raised by an Output OOB exchange.
 *
 * Both carry the method / Action / Size in oob_*; the ACCESS fields (element,
 * model, addresses) are zero and the opcode is MESHD_APP_OPCODE_PROV_OOB, so
 * the wire "EVENT" line of an unaware reader stays well formed.
 */
enum meshd_app_event_kind {
	MESHD_APP_EVENT_ACCESS = 0,
	MESHD_APP_EVENT_PROV_OOB_DISPLAY,
	MESHD_APP_EVENT_PROV_OOB_INPUT,
};

/* Reserved pseudo-opcode of the prompt events (not a mesh opcode). */
#define	MESHD_APP_OPCODE_PROV_OOB	0x00fffffeu

struct meshd_app_event {
	enum meshd_app_event_kind kind;
	uint16_t	elem_addr;
	struct mesh_cfg_model_id id;
	uint16_t	src;
	uint16_t	dst;
	uint32_t	opcode;
	uint8_t		params[MESH_ACCESS_PAYLOAD_MAX];
	size_t		params_len;
	uint8_t		oob_method;	/* Table 5.31: 0x02 out / 0x03 in */
	uint8_t		oob_action;	/* Table 5.32 / Table 5.34 */
	uint8_t		oob_size;	/* Table 5.33 / Table 5.35 */
};

struct meshd_app_surface {
	struct meshd_app_reg	regs[MESHD_MAX_APP_REGS];
	size_t			n_regs;
	struct meshd_app_event	events[MESHD_APP_EVENT_MAX];
	size_t			ev_head;
	size_t			ev_count;
	uint32_t		ev_dropped;
};

struct meshd_app_client {
	int			active;
	int			fd;
	/*
	 * Monotonic per-slot generation, bumped by meshd_app_client_init().
	 * App-client kevents carry (slot, generation) rather than a raw slot
	 * pointer, so a stale event for a client closed earlier in the same
	 * kevent batch cannot act on a brand-new client that reused the slot
	 * (and, after close(), the very same descriptor number).
	 */
	uint64_t		generation;
	char			rxbuf[2048];
	size_t			rxlen;
	char			txbuf[2048];
	size_t			txlen;
	size_t			txoff;
	/* Peer sent EOF: drain buffered commands, flush replies, then close. */
	int			eof;
	struct meshd_app_surface apps;
};

/* ================================================================
 * The node.
 * ================================================================ */

/*
 * Directed Forwarding state (finding 129 / MshMDL_v1.1 Section 4.4.3 + MshPRT
 * Section 3.6.7).  Only the NODE-WIDE DF Configuration Server sub-states live
 * here; the per-subnet ones (Directed Control, Path Metric, Wanted Lanes, Two
 * Way Path, Path Echo Interval) are keyed by NetKeyIndex and live on
 * struct meshd_netkey_entry::df.  The relay/target node role (forwarding table
 * + echo) and the Path Origin discovery FSM are driven from the node tick and
 * the "df discover" verb.
 */
struct meshd_df_state {
	struct mesh_cfg_transmit		net_transmit;
	struct mesh_cfg_transmit		relay_retransmit;
	/*
	 * The live relay / target / Path-Origin roles run on the sim node
	 * (mesh_sim_set_df + nd->self->df_table / df_disc), driven by the
	 * received-PDU path (meshd_bearer_rx -> mesh_sim_step -> the sim's DF
	 * transport-control dispatch) and drained to the bearer.  Only the
	 * Configuration Server sub-states above are held here.
	 */
	int					enabled;
};

/*
 * Remote Provisioning state (finding 128 / MshPRT_v1.1 Section 5.4.4).  The
 * Server role (the Remote Provisioning Server model surfaced through the
 * foundation dispatch table) answers Scan / Link / PDU control messages via the
 * scan-server and server-link FSMs.  The Client/manager role (the Remote
 * Provisioning Client model) is driven by the "remote-prov" verbs over the
 * DevKey Config-Client transaction engine.
 */
#define	MESHD_RPR_MAX_REPORTS	8

struct meshd_rpr_state {
	struct mesh_rp_scan_server	scan_server;	/* Server model */
	struct mesh_rp_server_link	server_link;	/* Server model */
	struct mesh_rp_scan_client	scan_client;	/* Client model */
	struct mesh_rp_client_link	client_link;	/* Client model */
	uint16_t			server_addr;	/* remote RPR Server */
	int				client_active;
	/*
	 * Server role: the RPR Client's unicast (recorded from an inbound RPR
	 * request) that unsolicited Scan/Link/PDU Reports are sent back to.
	 */
	uint16_t			client_addr;
	/*
	 * Client role: a ring of unsolicited Reports received from a Server,
	 * surfaced to the operator via "remote-prov reports".  report_head is
	 * the next write slot; n_reports the lifetime count.
	 */
	struct meshd_rpr_report {
		uint32_t	opcode;
		uint16_t	src;
		uint8_t		data[64];
		size_t		len;
	}				reports[MESHD_RPR_MAX_REPORTS];
	size_t				report_head;
	size_t				n_reports;
	/* Client role: last Provisioning PDU tunnelled in via a PDU Report. */
	uint8_t				inbound_pdu[MESH_RP_PROV_PDU_MAX];
	size_t				inbound_pdu_len;
};

/*
 * Friend-side segmented-message reassembly state, one per friendship.  Held
 * segments are stored as Friend Queue entries so that, once the transaction is
 * complete, they can be handed to the queue unchanged (Section 3.5.5: "No
 * field of the Lower Transport PDU shall be changed due to the message being
 * in the Friend Queue").
 */
struct meshd_friend_sar {
	int			active;
	int			ctl;		/* 1 => Segmented Control */
	uint8_t			opcode;		/* Control opcode (ctl only) */
	uint16_t		src;		/* originator */
	uint16_t		dst;		/* LPN element / group */
	uint32_t		seqauth;
	uint32_t		iv_index;
	uint8_t			segn;		/* last segment index */
	uint32_t		blockack;	/* AckedSegments */
	struct mesh_fq_entry	seg[MESH_SEG_MAX];
};

/*
 * Depth of the per-node queue of Configuration verbs waiting for a busy
 * destination (see cfg_queue in struct meshd_node).  Bounded because each
 * entry holds a whole Config PDU.
 */
#define	MESHD_CFG_QUEUE		4

/* One Configuration verb held for a destination with a live SAR transaction. */
struct meshd_cfg_pending {
	uint8_t		req[MESH_ACCESS_MAX];
	size_t		req_len;
	uint16_t	dst;
	uint32_t	expect_status_opcode;
	uint64_t	order;		/* FIFO ticket */
	int		used;
};

struct meshd_node {
	/* mesh_sim is first; all consumers must share its composition limits. */
	struct mesh_sim			sim;
	struct mesh_node		*self;		/* our node in the sim */
	uint16_t			addr;
	uint16_t			netkey_index;	/* primary subnet index */
	uint16_t			appkey_index;	/* bootstrap AppKey index */
	uint16_t			rx_secure_net_idx; /* subnet that secured the
						 * config msg being dispatched
						 * (MshPRT 4.3.2.32) */
	uint8_t			local_devkey[16];
	int				have_local_devkey;

	/*
	 * Device UUID advertised in the Unprovisioned Device Beacon while this
	 * node is itself unprovisioned (from the device_uuid config knob).  When
	 * have_device_uuid is set and the node is unprovisioned, meshd_node_tick
	 * emits the beacon so the node can be discovered/provisioned over PB-ADV.
	 */
	uint8_t			device_uuid[16];
	int				have_device_uuid;
	uint64_t			unprov_beacon_last;

	/*
	 * Unprovisioned-device discovery cache.  While prov_scanning is set,
	 * Unprovisioned Device Beacons received on the bearer are parsed and
	 * their UUIDs recorded here (dedup by UUID) so the operator can list
	 * nearby provisionable devices via the provision-scan verb.
	 */
	int				prov_scanning;
	struct meshd_scan_entry {
		uint8_t		uuid[16];
		uint16_t	oob;
		int		valid;
	}				scan_results[MESHD_MAX_SCAN_RESULTS];

	/*
	 * Application models.  All per-model server/client state lives in one
	 * heap-allocated aggregate (meshd_models.h) reached through this pointer,
	 * so adding a model family is a one-line append to struct meshd_app_models
	 * rather than an edit here.  Allocated in meshd_node_init(), freed in
	 * meshd_node_fini().
	 */
	struct meshd_app_models		*app;

	/* Foundation model state. */
	struct mesh_cfg_server_state	cfg;
	struct mesh_hlt_server_state	health;

	/* Configuration Server database (keys, bindings, subs, node states). */
	struct meshd_cfg_db		db;

	/* App-facing Mesh API surface: one registration/event ring per socket. */
	struct meshd_app_client	app_clients[MESHD_MAX_APP_CLIENTS];

	uint16_t			cid;		/* company id (Composition) */
	uint16_t			pid;
	uint16_t			vid;

	int				provisioned;

	/*
	 * Role engines (MshPRT_v1.1 Section 3.6.5 friendship, Section 5
	 * provisioning).  Each is driven from a caller-supplied millisecond
	 * clock; only one friendship side is active at a time.
	 */
	struct mesh_friend_fsm		friend_fsm;
	int				friend_enabled;
	/* One replay list per friendship-control opcode: a valid Offer and Update
	 * may share a Network SEQ during establishment, but a replay of either
	 * opcode must still be rejected independently. */
	struct mesh_rpl_entry		friend_rpl_store[9][MESH_SIM_RPL_SIZE];
	struct mesh_rpl			friend_rpl[9];
	struct mesh_lpn_fsm		lpn_fsm;
	int				lpn_enabled;
	/*
	 * Friend-side reassembly of one segmented message destined for the Low
	 * Power node (MshPRT_v1.1.1 Sections 3.5.3.4 and 3.5.5).  The Friend
	 * acknowledges the segments on the LPN's behalf (OBO = 1) and holds
	 * them until the complete Upper Transport PDU has arrived, because the
	 * Friend Queue "shall only [store a segmented message] after the
	 * complete Upper Transport PDU has been successfully reassembled and
	 * the Friend node has acknowledged the reception of all segments".
	 */
	struct meshd_friend_sar		friend_sar;
	struct mesh_prov_session	prov_sess;	/* provisioner session */
	struct mesh_prov_link		prov_link;	/* provisioner PB-ADV link */
	int				provisioner_active;
	/*
	 * Static OOB AuthValue for the NEXT provisioning attempt (MshPRT_v1.1.1
	 * Section 5.4.1.3, Authentication Method 0x01).  The operator installs
	 * the device's out-of-band value with the "provision-oob" control verb;
	 * every provisioning entry point (PB-ADV and PB-GATT) applies it to the
	 * session it creates, so an OOB-capable device is provisioned with an
	 * authenticated exchange instead of an unauthenticated one.  Empty
	 * (len 0) means No OOB.
	 */
	uint8_t				prov_static_oob[32];
	size_t				prov_static_oob_len;
	/*
	 * Operator-driven OOB authentication (MshPRT_v1.1.1 Sections 5.4.2.4.3
	 * and 5.4.2.4.4).  prov_oob_allow is the operator's opt-in to driving
	 * Output OOB and/or Input OOB, applied to every session this daemon
	 * creates ("provision-oob output|input|both"); without it the
	 * Provisioner never selects a method that would stall the exchange
	 * waiting for a human.  prov_oob_prompt caches the session's pending
	 * prompt so the operator can still read it with "provision-oob" after
	 * the app-event announcing it has been consumed, and prov_oob_pending
	 * marks it valid.
	 */
	unsigned			prov_oob_allow;
	struct mesh_prov_oob_prompt	prov_oob_prompt;
	int				prov_oob_pending;
	/*
	 * Certificate-based provisioning (MshPRT_v1.1.1 Section 5.5),
	 * Provisioner side.  prov_cert_mode is the operator's opt-in
	 * (MESH_PROV_CERT_MODE_*), prov_cert_policy the trust anchor path and
	 * the additional constraints Section 5.5.1.1 lets a Provisioner
	 * enforce.  Both are applied to every session this daemon creates, on
	 * either provisioning bearer, with the Device UUID of the device being
	 * provisioned filled in at that point -- Section 5.5.1.1.4.6 makes the
	 * Common Name Device UUID check a per-device one.  prov_cert_last is
	 * the verdict of the most recent attempt, kept after the session is
	 * released so "provision-cert" can still report it.
	 */
	unsigned			prov_cert_mode;
	struct mesh_prov_cert_policy	prov_cert_policy;
	char				prov_cert_roots[1024];
	struct mesh_prov_cert_result	prov_cert_last;
	int				prov_cert_have_last;
	/*
	 * Provisionee side: the provisioning records this node serves over the
	 * bearer (Section 5.4.2.6) and the PB-ADV link they are served on.  The
	 * link is a DEVICE-role link keyed on this node's own Device UUID, so
	 * it adopts only a Link Open addressed to this node and never collides
	 * with the Provisioner link above.  invite_seen is the Table 5.49 /
	 * 5.51 condition: a record PDU after a Provisioning Invite PDU in the
	 * same bearer session is an Unexpected PDU.
	 */
	struct {
		struct mesh_prov_record_store	store;
		struct mesh_prov_link		link;
		int				link_ready;
		int				invite_seen;
		uint64_t			lists;
		uint64_t			fragments;
		uint64_t			refused;
	}				prov_records;
	struct meshd_pbgatt		pbgatt;		/* provisioner PB-GATT */
	struct meshd_proxy_gatt		proxy_gatt[MESHD_MAX_PROXY_GATT];
	/* Proxy Server role: connections a Proxy Client made TO this node. */
	struct meshd_proxy_server	proxy_srv[MESHD_MAX_PROXY_SERVER];
	int				proxy_service_registered;
	/*
	 * Proxy advertising interleave cursor and cadence clock (Sections
	 * 7.2.2.2.2/7.2.2.2.3: "it shall interleave the advertising of each
	 * subnet").  proxy_adv_next is an index into the NetKey list; it
	 * advances by one emitted advertisement so consecutive beacon cadences
	 * rotate through the node's subnets.
	 */
	size_t				proxy_adv_next;
	uint64_t			proxy_adv_last;
	int				proxy_adv_on;

	/*
	 * Network-manager role (MshPRT_v1.1 Section 4): the created network's
	 * keys, address pool and node roster.  The roster and address pool make
	 * this object large (hundreds of KB), so it is heap-allocated on demand
	 * by the "create-network" control verb rather than embedded by value,
	 * keeping struct meshd_node small enough to live on the stack.  NULL
	 * until a network is created; mgr_active gates the roster verbs.
	 */
	struct mesh_mgr			*mgr;
	int				mgr_active;
	uint8_t				prov_ack[MESH_PBADV_PKT_MAX];
	size_t				prov_ack_len;
	int				prov_ack_pending;

	/*
	 * Config Client role (MshMDL_v1.1 Section 4.3.4): the in-flight
	 * acknowledged Configuration transaction toward a roster node, sealed
	 * under that node's DevKey and correlated with its Config *Status* reply.
	 * One transaction at a time (the operator drives them sequentially).
	 */
	struct mesh_mgr_txn		cfg_txn;

	/*
	 * Configuration verbs held back because a segmented transaction to the
	 * same destination is already in flight.
	 *
	 * MshPRT_v1.1.1 Section 3.5.3.3.1: the "shall not" forbids two
	 * segmented Upper Transport PDUs to one destination at once, and the
	 * "should" that follows asks for the second to START when the first
	 * "is completed or the message transmission has been canceled".  The
	 * Config Client seals its own Upper Transport PDU under a sequence
	 * number it chooses (mesh_mgr_txn_begin), so the lower transport layer
	 * cannot re-time the transaction on its behalf - the request has to be
	 * held HERE, unsealed, and re-run from the Config PDU when the
	 * destination frees.  That is also what keeps the single cfg_txn slot
	 * from being re-purposed by a verb that has not started yet.
	 *
	 * Bounded: an operator verb that finds the queue full is refused, the
	 * behaviour the section's first sentence always permitted.
	 */
	struct meshd_cfg_pending	cfg_queue[MESHD_CFG_QUEUE];
	uint64_t			cfg_queue_next;
	/*
	 * NetKey Key Refresh distribution (NB-14): the operator's new NetKey and
	 * a flag while it is being pushed to the roster one node at a time.  Each
	 * node's NetKey Update Status advances it to ACKED and triggers the send
	 * to the next DISTRIBUTING node.
	 */
	uint8_t				kr_net_key[16];
	int				kr_distributing;
	/*
	 * Roster addresses whose NetKey Update ended terminally (retry budget
	 * exhausted, or the node left the roster) during the current
	 * distribution round.  The pump skips them so a dead node cannot wedge
	 * the round; they stay DISTRIBUTING in the manager roster, so
	 * "key-refresh network-status" surfaces them as pending.  In-memory
	 * only: a daemon restart retries them.
	 */
	uint16_t			kr_failed[MESH_MGR_MAX_NODES];
	size_t				kr_nfailed;
	/*
	 * Does the single cfg_txn slot currently hold the key-refresh pump's
	 * OWN NetKey Update?  The Config protocol carries no per-request
	 * identifier, so keying the pump's ack/failure handling on
	 * kr_distributing plus the expected opcode alone misattributes an
	 * operator-issued "cfg netkey-update" (same opcode, same slot) that is
	 * answered non-SUCCESS during a live distribution: the pump would mark
	 * an unrelated node failed and skip it for the rest of the round.  Set
	 * only by meshd_kr_send_next(); every other meshd_cfg_client_send()
	 * (i.e. any operator verb re-purposing the slot) clears it.
	 */
	int				kr_txn_owned;

	/*
	 * Directed Forwarding (finding 129) and Remote Provisioning (finding 128)
	 * state.  DF holds the Configuration Server sub-states + relay/origin FSMs;
	 * RPR holds the Server and Client model FSMs.  Both are (re)initialised in
	 * meshd_setup_node() on every (re)provision.
	 */
	struct meshd_df_state		df;
	struct meshd_rpr_state		rpr;

	/*
	 * OTA provisioning: the device UUID and element count of the unprovisioned
	 * device currently being provisioned via meshd_provisioner_begin_mgr, held
	 * so meshd_provisioner_commit_mgr can be issued when the session completes.
	 */
	uint8_t				prov_target_uuid[16];
	uint8_t				prov_target_elements;
	int				prov_target_active;
	/*
	 * Sticky "the last OTA provisioning attempt failed" flag.  A failed
	 * attempt (PB-ADV link FAILED or session error) is torn down eagerly so
	 * the reserved unicast address is released and a new attempt can begin;
	 * this flag preserves the failure for the operator's provision-status
	 * poll.  Cleared when the next attempt starts.
	 */
	int				prov_failed;

	const struct meshd_bearer	*bearer;

	/*
	 * The node's persistent store, when one is attached (meshd.c main;
	 * NULL in the no-persist/test path).  Lets control verbs that re-seed
	 * the node (provision-local) floor the fresh SEQ at the persisted
	 * high-water and re-reserve before returning, so a reset+reprovision
	 * with the same keys/IV cannot reuse (IV,SRC,SEQ) nonces.
	 */
	struct meshd_persist		*persist;

	/*
	 * Monotonic clock (milliseconds) of the last meshd_node_tick;
	 * 0 until the first tick.  Drives the delta fed to the periodic Heartbeat
	 * and IV Update state machines.
	 */
	uint64_t			tick_last;

	/*
	 * Monotonic clock (milliseconds) of the last Secure Network beacon emitted;
	 * 0 until the first is due.  Drives the Section 3.9.3 beacon cadence.
	 */
	uint64_t			beacon_last;

	/*
	 * Fractional-second remainder accumulated toward the next whole second
	 * fed to the periodic Heartbeat publisher.  Ticks arrive every ~10 ms,
	 * so the per-tick delta must be accumulated rather than compared to a
	 * one-second threshold directly.
	 */
	uint64_t			hb_accum_ms;

	/*
	 * Low Power node subscription-list mirror (MshPRT_v1.1.1 Section
	 * 3.6.6.4.3).  A Friend forwards to its LPN only the group and virtual
	 * addresses the LPN has registered with it, so this node's own model
	 * subscriptions have to be pushed to the Friend as Friend Subscription
	 * List Add / Remove.  announced[] is what the Friend has confirmed it
	 * holds; inflight[] is the batch awaiting its Friend Subscription List
	 * Confirm (one transaction at a time, as the TransactionNumber
	 * handshake requires).  Both are cleared when a new friendship starts,
	 * because a new Friend holds nothing for us.
	 */
	uint16_t			lpn_sub_announced[
					    MESH_FRIEND_SUBLIST_ADDR_MAX];
	size_t				lpn_sub_n;
	uint16_t			lpn_sub_inflight[
					    MESH_FRIEND_SUBLIST_ADDR_MAX];
	size_t				lpn_sub_inflight_n;
	int				lpn_sub_inflight_add;
	/*
	 * A lost Friend Subscription List Confirm would otherwise leave the
	 * transaction outstanding for ever, and with it every later
	 * subscription change.  The batch is retransmitted with its original
	 * TransactionNumber (so the Friend treats the repeat as the same
	 * transaction and its Confirm still matches) at this deadline, a
	 * bounded number of times.
	 */
	uint64_t			lpn_sub_retry_ms;
	unsigned			lpn_sub_retries;

	/* Counters (observability / test hooks). */
	uint32_t			rx_delivered;	/* access msgs to models */
	uint32_t			tx_frames;	/* PDUs handed to bearer */
	uint32_t			tx_errors;	/* bearer tx() failures */
	/*
	 * Bridge messages that reached the registered Bridge Configuration
	 * Server model over a bound AppKey and were refused.  MshPRT_v1.1.1
	 * Section 4.4.9.1 requires the model's access-layer security to use the
	 * device key and Section 4.3.11 requires Bridge messages to be sealed
	 * with the DevKey of the Subnet Bridge node, so an AppKey-secured
	 * Bridge message must not take effect.  Counting the refusal (instead
	 * of leaving the model unregistered and the message silently
	 * unroutable) is what makes the model's presence and its security rule
	 * separately observable.
	 */
	uint32_t			bridge_appkey_refused;
};

/*
 * Initialise a node from a validated config: seed the sim with the NetKey /
 * AppKey / IV Index, add the local node at its unicast address, register the
 * Generic OnOff and Level servers, and initialise the Configuration and
 * Health server state.  A node with provisioning keys present in the config
 * comes up already provisioned; otherwise it awaits meshd_provision_*.
 * Returns 0 on success, -1 on a bad argument or sim failure.
 */
int	meshd_node_init(struct meshd_node *nd, const struct meshd_config *cfg);

/*
 * Release resources owned by a node (currently the heap-allocated manager
 * roster).  Safe to call on a zero-initialised or partially-initialised node
 * and idempotent, so it can run on any teardown or error path.
 */
void	meshd_node_fini(struct meshd_node *nd);

/* Attach (or detach, with NULL) the bearer transmit sink. */
void	meshd_set_bearer(struct meshd_node *nd, const struct meshd_bearer *b);

/*
 * Rebuild the node's sim, local node and network credentials from a restored
 * key set - the persistence counterpart of provisioning (the persistent store
 * is authoritative for a node provisioned over the air, which has no keys in its
 * configuration file).  Re-derives the managed-flooding credentials from netkey,
 * installs the AppKey / IV Index / unicast address and marks the node
 * provisioned; model application state is left as the caller restores it.
 * Returns 0 on success, -1 on a bad argument or sim failure.
 */
int	meshd_node_restore(struct meshd_node *nd, const uint8_t netkey[16],
	    const uint8_t appkey[16], uint32_t iv_index, uint16_t addr);

/*
 * Advance the node's time-driven state machines to the monotonic timestamp now
 * (CLOCK_MONOTONIC milliseconds).  Publishes any due periodic Heartbeat
 * (MshMDL_v1.1
 * Section 4.2.18) and drives the IV Update procedure (MshPRT_v1.1 Section
 * 3.10.5): begins an update when SEQ nears exhaustion and the 96-hour dwell has
 * elapsed, and completes an in-progress update once its dwell has elapsed.  On
 * an IV Index change *iv_changed (if non-NULL) is set to 1 so the caller can
 * reset the persisted SEQ high-water for the new IV epoch.  Idempotent for a
 * repeated or non-advancing now.  Returns the number of Heartbeats published
 * (>= 0), -1 on a bad argument.
 */
int	meshd_node_tick(struct meshd_node *nd, uint64_t now_ms, int *iv_changed);

/*
 * Provision the node locally from provisioning data (self-provisioning: no
 * over-the-air exchange).  Validates the unicast address and NetKey, installs
 * them and brings the node up.  When a persistent store is attached the fresh
 * SEQ is floored at the persisted high-water for the same TX IV epoch and the
 * next block is reserved before returning.  Returns 0 on success; -1 on
 * invalid data or a setup failure; -2 if the node is already provisioned
 * (reset first: re-seeding would reuse spent nonces); -3 if the requested TX
 * IV Index is below the persisted SEQ epoch; -4 if the SEQ reservation cannot
 * be persisted (the node is provisioned but MUST NOT originate).
 */
int	meshd_provision_local(struct meshd_node *nd,
	    const struct mesh_prov_data *pd);

/*
 * Provision the node from a received, encrypted Provisioning Data PDU - the
 * final step of the provisioning protocol (MshPRT_v1.1 Section 5.4.2.5), once
 * the SessionKey / SessionNonce have been established by the (bearer-side)
 * handshake.  Decrypts and MIC-verifies via libblemesh, unpacks, validates
 * and installs.  Returns 0, -1 on a MIC failure or invalid data.
 */
int	meshd_provision_recv_data(struct meshd_node *nd,
	    const uint8_t session_key[16], const uint8_t session_nonce[13],
	    const uint8_t enc[25], const uint8_t mic[8]);

/*
 * Deliver a secured Network PDU received from the bearer into the node's
 * receive pipeline.  Runs the sim to quiescence and drains any generated
 * replies/relays back to the bearer.  Returns 1 if an access message reached
 * a model, 0 if none did, -1 on a bad argument or an unprovisioned node.
 */
int	meshd_bearer_rx(struct meshd_node *nd, const uint8_t *pdu, size_t len);

/*
 * Build the node's Secure Network beacon for the primary subnet (MshPRT_v1.1
 * Section 3.9.3) with the Key Refresh Flag and key selected for the current
 * refresh phase (Section 3.11.4), and hand it to the bearer.  Emits at most
 * one beacon and updates the cadence mark.  Returns 1 if a beacon was emitted,
 * 0 if none was (bearer down / build failure), -1 on a bad argument.
 */
int	meshd_beacon_emit(struct meshd_node *nd);
int	meshd_unprov_beacon_emit(struct meshd_node *nd);
void	meshd_provision_scan_set(struct meshd_node *nd, int on);
int	meshd_provision_scan_add(struct meshd_node *nd, const uint8_t uuid[16],
	    uint16_t oob);

/*
 * Deliver a Secure Network beacon received from the bearer to the node: apply
 * the IV-Update accept rules and, when it authenticates under the node's new
 * key, advance the local Key Refresh phase (settling+promoting on the Phase 3
 * transition).  Mirrors the resulting phase into the config database.  Returns
 * 1 if the beacon authenticated, 0 if it did not, -1 on a bad argument.
 */
int	meshd_beacon_rx(struct meshd_node *nd, const uint8_t *pdu, size_t len);

/*
 * Originate a Generic OnOff Set (ack selects acknowledged vs unacknowledged)
 * from this node to dst, securing it with the AppKey and draining it to the
 * bearer.  Returns 0, -1 on failure or an unprovisioned node.
 */
int	meshd_send_onoff(struct meshd_node *nd, uint16_t dst, uint8_t onoff,
	    int ack);
/* Originate a Generic Level Set.  Same contract. */
int	meshd_send_level(struct meshd_node *nd, uint16_t dst, int16_t level,
	    int ack);
int	meshd_send_power_onoff(struct meshd_node *nd, uint16_t dst,
	    uint8_t on_power_up, int ack);
int	meshd_send_dtt(struct meshd_node *nd, uint16_t dst,
	    uint8_t transition_time, int ack);
int	meshd_send_power_level(struct meshd_node *nd, uint16_t dst,
	    uint16_t power, int ack);
int	meshd_send_power_default(struct meshd_node *nd, uint16_t dst,
	    uint16_t power, int ack);
int	meshd_send_power_range(struct meshd_node *nd, uint16_t dst,
	    uint16_t min, uint16_t max, int ack);
int	meshd_send_access_raw(struct meshd_node *nd, uint16_t dst,
	    const uint8_t *access, size_t access_len);
int	meshd_send_devkey_raw(struct meshd_node *nd, uint16_t dst, int remote,
	    uint16_t net_idx, const uint8_t *access, size_t access_len);
int	meshd_publish_raw(struct meshd_node *nd, uint16_t elem_addr,
	    uint16_t model_id, uint16_t vendor, const uint8_t *access,
	    size_t access_len);
void	meshd_sync_subscriptions(struct meshd_node *nd);
void	meshd_app_client_init(struct meshd_app_client *cl, int fd);
void	meshd_app_client_fini(struct meshd_app_client *cl);
int	meshd_app_client_register_model(struct meshd_node *nd,
	    struct meshd_app_client *cl, uint16_t elem_addr,
	    const struct mesh_cfg_model_id *id);
int	meshd_app_client_register_opcode(struct meshd_node *nd,
	    struct meshd_app_client *cl, uint16_t elem_addr,
	    const struct mesh_cfg_model_id *id, uint32_t opcode);
int	meshd_app_client_unregister_model(struct meshd_app_client *cl,
	    uint16_t elem_addr, const struct mesh_cfg_model_id *id);
size_t	meshd_app_client_event_count(const struct meshd_app_client *cl);
uint32_t meshd_app_client_event_dropped(const struct meshd_app_client *cl);
int	meshd_app_client_event_pop(struct meshd_app_client *cl,
	    struct meshd_app_event *ev);
int	meshd_app_client_event_peek(const struct meshd_app_client *cl,
	    struct meshd_app_event *ev);
int	meshd_ctl_exec_client(struct meshd_node *nd, struct meshd_app_client *cl,
	    int argc, char **argv, char *reply, size_t reply_max);
int	meshd_set_battery(struct meshd_node *nd,
	    const struct mesh_gen_battery_status *state);
int	meshd_set_location_global(struct meshd_node *nd,
	    const struct mesh_gen_location_global *state);
int	meshd_set_location_local(struct meshd_node *nd,
	    const struct mesh_gen_location_local *state);

/*
 * Process a received Configuration / Health foundation-model access message
 * (opcode + parameters) addressed to the primary element, updating server
 * state and, when the message is acknowledged, writing the reply Access PDU
 * to the reply buffer.  Returns 1 if a reply was produced, 0 if handled
 * without a reply, -1 if the opcode is not a handled foundation opcode or the
 * message is malformed.  On a reply the length is written to reply_len.
 */
int	meshd_foundation_recv(struct meshd_node *nd, const uint8_t *pdu,
	    size_t len, uint8_t *reply, size_t reply_max, size_t *reply_len);

/* True if addr is a valid unicast address. */
int	meshd_addr_is_unicast(uint16_t addr);

/* ================================================================
 * Key Refresh on the primary subnet (MshPRT_v1.1 Section 3.11.4).  Drive the
 * node's own refresh (Config Server role / operator ctl): begin distributes a
 * new NetKey and enters Phase 1 (holding BOTH keys), advance moves Phase 1 -> 2
 * (transmit with the new key), and finish revokes the old key and promotes the
 * new one to the sole current key.  Each returns 0 on success, -1 if the
 * operation is not legal in the current phase.  meshd_kr_phase returns the
 * current MESH_CFG_KR_PHASE_* value (-1 on a bad argument).
 * ================================================================ */
int	meshd_kr_begin(struct meshd_node *nd, const uint8_t new_key[16]);
int	meshd_kr_advance(struct meshd_node *nd);
int	meshd_kr_finish(struct meshd_node *nd);
int	meshd_kr_phase(const struct meshd_node *nd);

/*
 * AppKey Key Refresh Phase-3 completion: promote the manager's staged AppKey to
 * current, mint a fresh staged key, and apply the promoted key to this node's
 * own primary AppKey.  Returns 0 on success, -1 if no network is active.
 */
int	meshd_appkey_finalize(struct meshd_node *nd);

/* ================================================================
 * Friendship roles (MshPRT_v1.1 Section 3.6.5).
 *
 * The node drives at most one friendship side.  The daemon feeds received
 * friendship control messages (identified by their Transport Control opcode)
 * and periodic ticks to the engine, and transmits the resulting control PDUs
 * over the bearer.  now is the injected millisecond clock.
 * ================================================================ */

/* Enable the Friend role with the local Offer parameters + acceptance policy. */
int	meshd_friend_enable(struct meshd_node *nd, uint8_t recv_window,
	    uint8_t queue_size, uint8_t sub_list_size, int8_t min_rssi,
	    uint8_t max_queue_size_log);

/*
 * Enable/disable the Friend and Low Power node roles with meshd's default
 * parameters and wire them to the bearer-driven receive path and node tick.
 * meshd_friend_role_enable also sets the Config Server Friend state.  The LPN
 * originates its Friend Request on the first tick once a bearer is attached.
 */
int	meshd_friend_role_enable(struct meshd_node *nd);
void	meshd_friend_role_disable(struct meshd_node *nd);
int	meshd_lpn_role_enable(struct meshd_node *nd);
void	meshd_lpn_role_disable(struct meshd_node *nd);

/*
 * Feed a friendship control PDU (opcode octet + parameters) received from src
 * to the Friend engine, routing by opcode: Friend Request (binding src as the
 * LPN), Poll, Subscription List Add/Remove and Clear.  key_refresh/iv_update/
 * iv_index are the node's current security flags used to synthesise a Friend
 * Update on an empty-queue Poll.  Fills out.  Returns the engine result.
 */
int	meshd_friend_input(struct meshd_node *nd, uint16_t src,
	    const uint8_t *pdu, size_t len, int8_t rssi, uint8_t key_refresh,
	    uint8_t iv_update, uint32_t iv_index, uint64_t now,
	    struct mesh_friend_out *out);

/* Advance the Friend engine's timers (emit a due Offer, supervise PollTimeout). */
int	meshd_friend_tick(struct meshd_node *nd, uint64_t now,
	    struct mesh_friend_out *out);

/* Offer a network message to the Friend Queue for the LPN. */
int	meshd_friend_enqueue(struct meshd_node *nd, const struct mesh_fq_entry *in);

/*
 * Enable the Low Power node role and begin establishment: builds a Friend
 * Request (out).  The parameters are the Friend Request criteria + cadence.
 */
int	meshd_lpn_enable(struct meshd_node *nd, uint8_t rssi_factor,
	    uint8_t rx_window_factor, uint8_t min_queue_size_log,
	    uint8_t recv_delay, uint32_t poll_timeout, uint32_t offer_window_ms,
	    uint32_t poll_interval_ms, uint64_t now, struct mesh_lpn_out *out);

/* Feed a received Friend Offer to the LPN engine while it is collecting. */
int	meshd_lpn_recv_offer(struct meshd_node *nd, const uint8_t *pdu,
	    size_t len, uint16_t friend_addr, uint64_t now);

/* Feed a received Friend Update to the LPN engine. */
int	meshd_lpn_recv_update(struct meshd_node *nd, const uint8_t *pdu,
	    size_t len, uint64_t now, struct mesh_lpn_out *out);

/* Advance the LPN engine's timers (select Offer, cadence Poll, re-establish). */
int	meshd_lpn_tick(struct meshd_node *nd, uint64_t now,
	    struct mesh_lpn_out *out);

/* ================================================================
 * Provisioner role (MshPRT_v1.1 Section 5).
 * ================================================================ */

/*
 * Begin acting as a Provisioner toward device_uuid: initialise the provisioning
 * session (priv/random optional fixed values for reproducibility, else
 * generated) and the PB-ADV link, and emit the initial Link Open bearer packet
 * (out/outlen).  data is the provisioning data (NetKey / index / flags / IV /
 * unicast address) to hand the device.  Returns 0, -1 on error.
 */
int	meshd_provisioner_begin(struct meshd_node *nd,
	    const uint8_t device_uuid[16], uint32_t link_id, const uint8_t priv[32],
	    const uint8_t random[32], uint8_t attention,
	    const struct mesh_prov_data *data, uint32_t retry_interval_ms,
	    unsigned max_retries, uint64_t now, uint8_t *out, size_t *outlen);

/*
 * Feed a received PB-ADV packet to the Provisioner link/session: reassembles
 * inbound Provisioning PDUs and drives the session, then segments the session's
 * outbound PDUs back onto the link.  Emitted bearer packets are drained via
 * meshd_provisioner_poll.  Returns 0, -1 on error.
 */
int	meshd_provisioner_recv(struct meshd_node *nd, const uint8_t *pkt,
	    size_t len, uint64_t now);

/*
 * Emit the next outbound Provisioner bearer packet (Link Open retransmit,
 * transaction segment, Transaction Ack or retransmission).  Returns 1 with
 * out/outlen filled, 0 if nothing is due, -1 on error/link failure.
 */
int	meshd_provisioner_poll(struct meshd_node *nd, uint64_t now, uint8_t *out,
	    size_t *outlen);

/*
 * Drain the Provisioner's ready outbound PB-ADV bearer packets to the installed
 * bearer, tagged MESHD_PDU_PROV.  This is the provisioner's transmit site
 * (meshd_provisioner_poll itself only returns one packet to a caller); the
 * daemon calls it after feeding a received PB-ADV packet and on each tick while
 * a session is active.  Bounded (never busy-loops).  Returns the number of
 * packets sent (>= 0).
 */
int	meshd_provisioner_drain(struct meshd_node *nd, uint64_t now);

/*
 * Certificate-based provisioning, Provisioner side (MshPRT_v1.1.1 Section 5.5).
 *
 *   set_cert_mode  installs the operator's opt-in and the trust anchor path
 *                  (roots may be NULL only when mode is 0), plus the optional
 *                  CID/PID the Common Name must carry and match, and the
 *                  certificate-policies requirement of Section 5.5.1.1.4.13.
 *                  Applied to every session this daemon creates afterwards.
 *   cert_result    the verdict of the most recent attempt, or NULL when there
 *                  has not been one.
 *
 * Returns 0, -1 on error.
 */
int	meshd_provision_set_cert_mode(struct meshd_node *nd, unsigned mode,
	    const char *roots, int have_cid_pid, uint16_t cid, uint16_t pid,
	    int require_policies);
const struct mesh_prov_cert_result *meshd_provision_cert_result(
	    const struct meshd_node *nd);

/*
 * Provisionee side: the provisioning record service (MshPRT_v1.1.1 Section
 * 5.4.2.6).  While this node is unprovisioned, has a Device UUID and holds at
 * least one record, it answers Provisioning Records Get and Provisioning
 * Record Request PDUs arriving on the PB-ADV bearer.
 *
 *   record_set     install (replacing) one record's data;
 *   records_clear  drop every record, turning the service off;
 *   records_ids    the stored Record IDs in ascending order;
 *   record_get     one record's data, or NULL;
 *   records_recv   feed one received PB-ADV packet (returns 1 when the service
 *                  is live and consumed it, 0 otherwise);
 *   records_drain  hand every ready service bearer packet to the bearer.
 */
int	meshd_prov_record_set(struct meshd_node *nd, uint16_t id,
	    const uint8_t *data, size_t len);
void	meshd_prov_records_clear(struct meshd_node *nd);
size_t	meshd_prov_records_ids(const struct meshd_node *nd, uint16_t *ids,
	    size_t max);
const uint8_t *meshd_prov_record_get(const struct meshd_node *nd, uint16_t id,
	    size_t *len);
int	meshd_prov_records_recv(struct meshd_node *nd, const uint8_t *pkt,
	    size_t len, uint64_t now);
int	meshd_prov_records_drain(struct meshd_node *nd, uint64_t now);

/*
 * Install (or, with value == NULL / len == 0, clear) the Static OOB
 * authentication value applied to the next provisioning session.  Returns 0,
 * -1 on error.  See struct meshd_node::prov_static_oob.
 */
int	meshd_provision_set_static_oob(struct meshd_node *nd,
	    const uint8_t *value, size_t len);

/*
 * Operator-driven OOB authentication (MshPRT_v1.1.1 Sections 5.4.2.4.3 /
 * 5.4.2.4.4), applied to the next provisioning session:
 *
 *   set_oob_methods  opts in to driving Output OOB and/or Input OOB (the
 *                    MESH_PROV_OOB_ALLOW_* bits, 0 for neither);
 *   oob_prompt       reads the live session's pending operator prompt,
 *                    returning 1 with *out filled, 0 when nothing is pending;
 *   oob_input        hands the session the value the peer displayed, resuming
 *                    the stalled exchange (returns 0, -1 when no input is
 *                    wanted or the value does not fit the Action / Size);
 *   oob_pump         runs the session's Input Complete / operator timeout and
 *                    publishes a newly raised prompt to the app clients as a
 *                    PROV_OOB_DISPLAY / PROV_OOB_INPUT event.  Called from the
 *                    provisioner drain on every tick.
 */
int	meshd_provision_set_oob_methods(struct meshd_node *nd, unsigned allow);
int	meshd_provision_oob_prompt(const struct meshd_node *nd,
	    struct mesh_prov_oob_prompt *out);
int	meshd_provision_oob_input(struct meshd_node *nd, const char *value);
void	meshd_provision_oob_pump(struct meshd_node *nd, uint64_t now);

/*
 * PB-GATT provisioner core.  begin starts the same provisioning session used
 * by PB-ADV without opening a Generic Provisioning link.  poll emits one Mesh
 * Provisioning Proxy PDU suitable for a Write Command to Data In (0x2ADB);
 * recv consumes one Data Out (0x2ADC) notification.  now_ms is the current
 * monotonic time: complete sent and received Provisioning PDUs restart the
 * provisioning protocol timer, while receive fragments use it for SAR timing.
 * mtu is the negotiated ATT MTU and bounds each emitted value to mtu - 3 octets.
 */
int	meshd_pbgatt_begin(struct meshd_node *nd, uint16_t mtu,
	    const uint8_t priv[32], const uint8_t random[32], uint8_t attention,
	    const struct mesh_prov_data *data);
int	meshd_pbgatt_poll(struct meshd_node *nd, uint64_t now_ms,
	    uint8_t *out, size_t outcap, size_t *outlen);
int	meshd_pbgatt_recv(struct meshd_node *nd, const uint8_t *pdu,
	    size_t len, uint64_t now_ms);
int	meshd_pbgatt_recv_mtu(struct meshd_node *nd, const uint8_t *pdu,
	    size_t len, uint16_t bearer_mtu, uint64_t now_ms);
int	meshd_pbgatt_link_open(struct meshd_node *nd, uint64_t now_ms);
int	meshd_pbgatt_set_mtu(struct meshd_node *nd, uint16_t mtu);
int	meshd_pbgatt_timeout(struct meshd_node *nd, uint64_t now_ms);
int	meshd_pbgatt_done(const struct meshd_node *nd);
void	meshd_pbgatt_cancel(struct meshd_node *nd);
void	meshd_pbgatt_close(struct meshd_node *nd);
int	meshd_proxy_gatt_begin(struct meshd_node *nd, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index, uint16_t mtu);
int	meshd_proxy_gatt_recv(struct meshd_node *nd, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index, const uint8_t *pdu, size_t len,
	    uint64_t now_ms);
int	meshd_proxy_gatt_recv_mtu(struct meshd_node *nd, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index, const uint8_t *pdu, size_t len,
	    uint16_t bearer_mtu, uint64_t now_ms);
int	meshd_proxy_gatt_set_mtu(struct meshd_node *nd, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index, uint16_t mtu);
/* Atomically replace a provisional adapter selector after GATT discovery. */
int	meshd_proxy_gatt_resolve_adapter(struct meshd_node *nd,
	    const char *addr, uint8_t addr_type, uint8_t requested_adapter,
	    uint8_t resolved_adapter);
void	meshd_proxy_gatt_cancel(struct meshd_node *nd, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index);
void	meshd_proxy_gatt_close(struct meshd_node *nd, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index);
int	meshd_proxy_gatt_connect(struct meshd_node *nd, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index);
int	meshd_proxy_gatt_set_filter(struct meshd_node *nd, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index, uint16_t net_idx,
	    uint8_t filter_type);
int	meshd_proxy_gatt_update_filter(struct meshd_node *nd, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index, uint16_t net_idx,
	    uint8_t opcode,
	    const uint16_t *addrs, size_t n);
void	meshd_gatt_tick(struct meshd_node *nd, uint64_t now_ms);

/* ================================================================
 * Mesh Proxy Server role (MshPRT_v1.1.1 Sections 6.7 and 7.2).
 * ================================================================ */

/*
 * The Proxy Server role is driven entirely from meshd_gatt_tick(): the
 * «Mesh Proxy Service» registration rule of Section 7.2.2.2, the
 * per-connection SAR timeout of Section 6.3.2.2, and the proxy advertising
 * cadence and subnet interleave of Section 7.2.2.2.  Those three are internal
 * to meshd_proxy_gatt.c; the entry points below are the ones the bearer calls.
 */

/*
 * A Proxy Client connected to / disconnected from this node's Mesh Proxy
 * Service.  Open initialises the connection's proxy filter to an empty accept
 * list, evaluates the Proxy Privacy parameter, and sends one mesh beacon per
 * known subnet, all as required by Section 6.7.
 */
int	meshd_proxy_server_open(struct meshd_node *nd, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index, uint16_t mtu);
void	meshd_proxy_server_close(struct meshd_node *nd, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index);

/*
 * One Mesh Proxy Data In write from a Proxy Client (Section 7.2.3.1): feed it
 * to this connection's reassembler and act on any completed Proxy PDU message.
 * Returns 1 when a message was consumed, 0 when more segments are needed or
 * the message was ignored, -1 when the link must be torn down (Section 6.3.2.2
 * has the receiver disconnect on an illegal SAR sequence).
 */
int	meshd_proxy_server_recv(struct meshd_node *nd, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index, const uint8_t *pdu,
	    size_t len, uint16_t bearer_mtu, uint64_t now_ms);

/*
 * The Proxy Server's network-interface output (Sections 3.4.5 and 6.4): offer
 * one Network PDU to every connected Proxy Client whose proxy filter accepts
 * its destination.  Returns the number of connections it was forwarded to.
 */
int	meshd_proxy_server_forward(struct meshd_node *nd, const uint8_t *pdu,
	    size_t len);


/* True once the Provisioner session has completed successfully. */
int	meshd_provisioner_done(const struct meshd_node *nd);

/*
 * Manager-driven provisioning (MshPRT_v1.1 Section 4).  These bridge the
 * Provisioner role to a mesh_mgr network manager: begin auto-fills the
 * provisioning data (NetKey / IV Index / a freshly allocated unicast address
 * for a device_uuid with num_elements elements) from the manager, and commit
 * records the completed node - its UUID, address, element count and the derived
 * DevKey - into the manager's roster.
 *
 * meshd_provisioner_begin_mgr() has the same bearer contract as
 * meshd_provisioner_begin() (emits the initial Link Open); it returns -1 (and
 * leaves no pending reservation) if the manager cannot allocate an address.
 * meshd_provisioner_commit_mgr() must be called once meshd_provisioner_done()
 * is true; it returns the new roster entry or NULL on failure.
 */
int	meshd_provisioner_begin_mgr(struct meshd_node *nd, struct mesh_mgr *mgr,
	    const uint8_t device_uuid[16], uint8_t num_elements, uint32_t link_id,
	    const uint8_t priv[32], const uint8_t random[32], uint8_t attention,
	    uint32_t retry_interval_ms, unsigned max_retries, uint64_t now,
	    uint8_t *out, size_t *outlen);
struct mesh_mgr_node *meshd_provisioner_commit_mgr(struct meshd_node *nd,
	    struct mesh_mgr *mgr, uint64_t prov_time);

/* Inspection accessors. */
uint16_t	meshd_node_addr(const struct meshd_node *nd);
uint32_t	meshd_node_seq(const struct meshd_node *nd);
uint32_t	meshd_node_iv(const struct meshd_node *nd);
uint8_t		meshd_node_onoff(const struct meshd_node *nd);
int16_t		meshd_node_level(const struct meshd_node *nd);

/*
 * Hand every queued outbound Network PDU to the installed bearer.  Exposed so
 * the Config Client (meshd_cfgclient.c) can flush a sealed Configuration PDU it
 * has queued onto the sim transmit ring.
 */
void	meshd_drain_tx(struct meshd_node *nd);

/* ================================================================
 * Config Client role (MshMDL_v1.1 Section 4.3.4).
 *
 * meshd operates the network it created (create-network / the mgr roster) by
 * sending acknowledged Configuration messages to a provisioned node's primary
 * element, sealed under that node's DevKey, and correlating the returned Config
 * *Status*.  meshd_cfgclient.c bridges the libmesh Config Client PDU builders
 * (mesh_mgr_cfg_*_pdu) and the DevKey transaction engine (mesh_mgr_txn_*) to the
 * daemon's transmit / receive seams.
 * ================================================================ */

/*
 * Retransmit cadence and bounded attempt budget for a Config Client txn.
 * mesh_mgr_txn_begin() arms its deadline in the transaction clock's units,
 * which is CLOCK_MONOTONIC milliseconds here, so the interval must be a real
 * millisecond value (not a small "tick" count).  800 ms per attempt gives a
 * ~3.2 s overall budget, enough for a segmented Config Status from a remote
 * (possibly multi-hop) node to arrive before the transaction times out.
 */
#define	MESHD_CFG_RETRY_MS	800
#define	MESHD_CFG_MAX_ATTEMPTS	4

/*
 * Seal a built Configuration Access PDU (req/req_len) to the roster node whose
 * primary element is dst under its DevKey, register the in-flight transaction
 * (expecting a Status with expect_status_opcode), transmit the sealed PDU over
 * the bearer as a Network PDU, and arm the retransmit timer at now.  If
 * out_upper/out_seq are non-NULL they receive the sealed Upper Transport PDU and
 * the sequence number it was sealed under (the peer needs the seq to decrypt) -
 * used by tests to drive the peer directly.  Returns 0 on success, -1 if there
 * is no active network, no such node, or a seal/transmit failure.
 */
int	meshd_cfg_client_send(struct meshd_node *nd, uint16_t dst,
	    const uint8_t *req, size_t req_len, uint32_t expect_status_opcode,
	    uint64_t now, uint8_t *out_upper, size_t *out_upper_len,
	    uint32_t *out_seq);

/*
 * Feed a received Upper Transport PDU (a candidate Config Status sealed by the
 * node with (seq, src, dst)) to the in-flight transaction.  On a matching Status
 * the transaction completes and its plaintext Status is retained for
 * meshd_cfg_client_status().  Returns 1 if the transaction completed, 0 if the
 * PDU was ignored, -1 on a bad argument.
 */
int	meshd_cfg_client_rx(struct meshd_node *nd, uint32_t seq, uint16_t src,
	    uint16_t dst, const uint8_t *upper, size_t upper_len);
int	meshd_kr_send_next(struct meshd_node *nd, uint64_t now);

/*
 * Advance the in-flight transaction's retransmit timer to now, re-sending the
 * request over the bearer when the retry interval elapses and declaring a
 * timeout once the attempt budget is spent.  Returns 1 if a retransmission was
 * emitted, 0 otherwise, -1 on a bad argument.
 */
int	meshd_cfg_client_tick(struct meshd_node *nd, uint64_t now);

/*
 * Inspect the in-flight transaction: its state (MESH_MGR_TXN_*) and, when
 * complete, a pointer to the recovered Status Access PDU (*status / *status_len).
 * Returns the state; *status may be NULL when no Status is available.
 */
int	meshd_cfg_client_status(const struct meshd_node *nd,
	    const uint8_t **status, size_t *status_len);

/*
 * Execute a "cfg" control sub-verb (argv[0] is the sub-verb, e.g. "appkey-add"):
 * build the Configuration message, send it via meshd_cfg_client_send and, if the
 * transaction has already completed (test / loopback), parse and surface the
 * Status.  now is the injected clock.  Writes a human-readable result to reply.
 * Returns 0 on success, -1 on a bad argument or an operation failure.
 */
int	meshd_cfg_client_verb(struct meshd_node *nd, int argc, char **argv,
	    uint64_t now, char *reply, size_t reply_max);

/* ================================================================
 * OTA provisioning driver (MshPRT_v1.1 Section 5).
 * ================================================================ */

/*
 * Begin provisioning the unprovisioned device device_uuid (num_elements
 * elements) into the created network via the manager: reserves a unicast
 * address, opens the PB-ADV link and emits the initial Link Open to the bearer.
 * Records the target so meshd_provision_ota_commit() can finish it.  now is the
 * injected clock.  Returns 0, -1 if there is no network or on a link failure.
 */
int	meshd_provision_ota_begin(struct meshd_node *nd,
	    const uint8_t device_uuid[16], uint8_t num_elements, uint64_t now);

/*
 * Complete an OTA provisioning once meshd_provisioner_done() is true: record the
 * node (UUID / address / element count / derived DevKey) into the manager
 * roster.  Returns the new roster entry, or NULL if provisioning is not done or
 * on a commit failure.
 */
struct mesh_mgr_node *meshd_provision_ota_commit(struct meshd_node *nd,
	    uint64_t prov_time);
int	meshd_provision_gatt_begin(struct meshd_node *nd, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index,
	    const uint8_t device_uuid[16],
	    uint8_t num_elements);

/*
 * Report whether an in-flight OTA provisioning attempt has failed: the PB-ADV
 * link exhausted its retransmission budget (FAILED) or the provisioning session
 * hit a protocol error.  Returns 1 if failed, 0 otherwise.
 */
int	meshd_provision_ota_failed(const struct meshd_node *nd);

/*
 * Tear down an in-flight (or failed) OTA provisioning attempt: release the
 * manager-reserved unicast address, free the session, and clear the
 * provisioner/target-active flags so a new attempt can begin.  Sets the sticky
 * prov_failed flag when failed is non-zero.  Safe to call when nothing is
 * active.
 */
void	meshd_provision_ota_abort(struct meshd_node *nd, int failed);

/* ================================================================
 * Directed Forwarding (finding 129, MshMDL_v1.1 Section 4.4.3).
 * ================================================================ */

/*
 * Execute a "df" control sub-verb (argv[0] is the sub-verb, e.g. "get"/"set"/
 * "metric"/"lanes"/"two-way"/"echo"/"net-transmit"/"relay-retransmit").  The
 * DF Configuration Client sub-verbs build a Directed-Forwarding Configuration
 * message and drive it over the DevKey Config-Client transaction engine exactly
 * like "cfg"; "discover" drives the local Path Origin discovery FSM.  now is the
 * injected clock.  Returns 0 on success, -1 on a bad argument/operation.
 */
int	meshd_df_client_verb(struct meshd_node *nd, int argc, char **argv,
	    uint64_t now, char *reply, size_t reply_max);

/*
 * Enable Directed Forwarding on the sim node (idempotent): turns on the sim's
 * DF relay/proxy/friend features with managed flooding as the fallback so the
 * node relays and answers Path Request/Reply/Confirmation/Echo received over
 * the bearer.  Called at node setup and when the DF Configuration Server's
 * Directed Forwarding state is turned on.
 */
/*
 * SAR Transmitter / Receiver Configuration Server states (MshPRT 4.2.29 /
 * 4.2.30).  _defaults() seeds the engine-equivalent defaults; _apply() pushes
 * the current states into the network engine's SAR timing.
 */
void	meshd_sar_defaults(struct meshd_node *nd);
void	meshd_sar_apply(struct meshd_node *nd);

void	meshd_df_enable(struct meshd_node *nd);
/* Re-derive the node-wide DF engine from the per-subnet Directed Control. */
void	meshd_df_resync(struct meshd_node *nd);

/*
 * The Health Server as an access-layer model, so AppKey-secured Health
 * messages reach it (the DevKey dispatch table alone left the model
 * unreachable over a bound AppKey).  Registered on element 0.
 */
struct mesh_model	meshd_hlt_srv_model(struct meshd_node *nd);

/*
 * Bridge Configuration Server (MshPRT_v1.1.1 Section 4.4.9) as an access-layer
 * model, registered on the primary element exactly like the Health Server
 * above, so the model is reachable through ordinary access-layer dispatch
 * rather than only through the DevKey foundation table.  Section 4.4.9.1
 * requires the model's access-layer security to use the device key, so the
 * handler enforces that: a Bridge message that arrives under an AppKey is
 * refused there, not by being unreachable.
 */
struct mesh_model	meshd_bridge_srv_model(struct meshd_node *nd);

/*
 * Push the Bridge Configuration Server's Subnet Bridge and Bridging Table
 * states into the network engine (mesh_sim_set_bridge /
 * mesh_sim_set_bridging_table).  Called after every state change so the
 * forwarding behaviour and the configured state never diverge.
 */
void	meshd_bridge_sync(struct meshd_node *nd);


/*
 * Start a Path Origin path discovery toward target on the primary subnet: arms
 * the sim node's discovery FSM (-> REQUEST_SENT), advances the Forwarding
 * Number, network-encrypts the Path Request as a transport-control PDU and
 * transmits it on the bearer.  The Path Reply/Confirmation exchange is completed
 * by the received-PDU path.  Returns 0, -1 on a bad argument, no bearer, or if a
 * discovery is already in flight.
 */
int	meshd_df_discover_begin(struct meshd_node *nd, uint16_t target,
	    uint64_t now);

/* ================================================================
 * Remote Provisioning (finding 128, MshPRT_v1.1 Section 5.4.4).
 * ================================================================ */

/*
 * Execute a "remote-prov" control sub-verb (argv[0] is the sub-verb, e.g.
 * "scan"/"scan-stop"/"caps"/"link-open"/"link-close"/"status").  The client
 * sub-verbs build a Remote Provisioning message and drive it over the DevKey
 * Config-Client transaction engine (the RPR models use the device key); the
 * client scan/link FSMs record the correlated Status.  Returns 0, -1 on error.
 */
int	meshd_rpr_client_verb(struct meshd_node *nd, int argc, char **argv,
	    uint64_t now, char *reply, size_t reply_max);

/*
 * Remote Provisioning Server (the Remote Provisioning Server model): dispatch a
 * received RPR access opcode (MESH_RP_OP_*) to the scan-server / server-link
 * FSMs and build the synchronous Status/Report reply.  Called from the
 * foundation dispatch when the opcode is not a Configuration/Health opcode.
 * Returns 1 with a reply, 0 if no reply is due, -1 if the opcode is not an RPR
 * Server opcode or on a decode error.
 */
int	meshd_rpr_server_recv(struct meshd_node *nd,
	    const struct mesh_access_pdu *ap, const uint8_t *pdu, size_t len,
	    uint8_t *reply, size_t reply_max, size_t *reply_len);

/*
 * Remote Provisioning Server unsolicited Report emitters.  Each drives the
 * server FSM and, if a report is due, seals it under this node's DevKey and
 * transmits it to the recorded RPR Client (nd->rpr.client_addr) over the bearer.
 * A client address must have been recorded (from a prior inbound RPR request).
 * Return 1 if a report was emitted, 0 if none was due, -1 on error.
 *
 *   _report_scan   - offer a discovered device UUID to the scan server.
 *   _report_bearer - the device-side bearer opened (Link Report ACTIVE).
 *   _report_pdu    - the device returned a Provisioning PDU (PDU Report).
 */
int	meshd_rpr_server_report_scan(struct meshd_node *nd,
	    const uint8_t uuid[16], uint16_t oob, int8_t rssi, uint64_t now);
int	meshd_rpr_server_report_bearer(struct meshd_node *nd);
int	meshd_rpr_server_report_pdu(struct meshd_node *nd,
	    const uint8_t *prov_pdu, size_t len);

/*
 * Remote Provisioning Client: tunnel one outbound Provisioning PDU to the
 * Server over the active link (a PDU Send sealed under the Server's DevKey).
 * Returns 0, -1 if the link is not active or on a seal/transmit error.
 */
int	meshd_rpr_client_send_pdu(struct meshd_node *nd, const uint8_t *prov_pdu,
	    size_t len, uint64_t now);

/*
 * Remote Provisioning Client inbound Report path: decode an Upper Transport PDU
 * sealed under a Server's DevKey (src) and, if it carries an unsolicited RPR
 * Report (Scan/Link/PDU/Outbound), drive the matching client FSM, buffer it for
 * "remote-prov reports", and (for a PDU Report) capture the tunnelled
 * Provisioning PDU.  Returns 1 if handled, 0 if not an RPR Report, -1 on error.
 * Called from the remote-DevKey receive seam after the Config Client txn path.
 */
int	meshd_rpr_client_rx(struct meshd_node *nd, uint32_t seq, uint16_t src,
	    uint16_t dst, const uint8_t *upper, size_t upper_len);

/* ================================================================
 * Control surface.
 * ================================================================ */

/*
 * Tokenise a command line in place (whitespace-separated, no quoting) into
 * argv, up to max entries.  Returns the token count (argc), which may be 0.
 */
int	meshd_ctl_tokenize(char *line, char **argv, int max);

#endif /* _MESHD_H_ */
