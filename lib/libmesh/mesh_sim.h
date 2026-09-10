/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh in-process multi-node network SIMULATOR.
 *
 * This is the mesh analogue of the hci_emulator / btpeer "sim-air": a pure,
 * hardware-free, spec-oracle harness that wires the Phase 1-8 libmesh modules
 * (mesh_crypto, mesh_net, mesh_transport, mesh_access, mesh_rpl, mesh_relay,
 * mesh_iv, mesh_key_refresh, mesh_beacon, mesh_friend and the mesh_generic
 * application models) into a running network of nodes that talk to each other
 * over a shared virtual advertising medium.
 *
 * MEDIUM.  mesh_sim holds a queue of transmitted secured Network PDUs.  On
 * mesh_sim_step() every queued transmission is delivered to every node in
 * range (all nodes but the transmitter); each receiving node runs the FULL
 * receive pipeline:
 *
 *   network deobfuscate + decrypt (NID/key candidate match, IV-Index
 *   candidate match)  ->  network message cache (relay-loop dedup)  ->
 *   Relay feature (TTL >= 2 re-broadcast with TTL-1)  ->  Friend Queue
 *   enqueue (store for a sleeping LPN)  ->  addressing (unicast element /
 *   subscribed group / all-nodes)  ->  Replay Protection List  ->  lower
 *   transport parse + SAR reassembly  ->  upper transport AppKey decrypt  ->
 *   access-layer model dispatch (mesh_generic servers/clients).
 *
 * A relay re-broadcasts onto the medium, so a message queued in one step is
 * delivered a hop further in the next: MULTI-HOP delivery emerges from
 * stepping the sim until it goes quiescent (mesh_sim_run).  Secure Network
 * beacons ride a separate beacon medium and drive the IV-Update and
 * Key-Refresh state machines across the network.  A caller-injected virtual
 * clock (seconds) gates the 96-hour IV-Update dwell.
 *
 * The structures are intentionally NOT opaque: tests inspect node state
 * (SEQ, IV Index, Key Refresh phase, the last delivered access message, the
 * OnOff/Level server state reached through the model user pointers) directly.
 *
 * BOUNDED CAPACITIES: each node supports four NetKeys total (the primary plus
 * three additional subnets), eight AppKeys, eight elements and 48 models per
 * element.  Friendship credentials are derived from the explicitly selected
 * subnet.  The virtual clock drives access-model transitions via
 * mesh_access_tick(), including delayed Scene recalls.
 */

#ifndef _MESH_SIM_H_
#define _MESH_SIM_H_

#include <stddef.h>
#include <stdint.h>

#include "mesh_access.h"
#include "mesh_bridge.h"
#include "mesh_df.h"
#include "mesh_friend.h"
#include "mesh_heartbeat.h"
#include "mesh_iv.h"
#include "mesh_key_refresh.h"
#include "mesh_net.h"
#include "mesh_provisioner.h"
#include "mesh_proxy.h"
#include "mesh_relay.h"
#include "mesh_rpl.h"
#include "mesh_transport.h"

#define	MESH_SIM_MAX_NODES	16
#define	MESH_SIM_MAX_ELEMS	8
#define	MESH_SIM_MAX_MODELS	48	/* models per element */
#define	MESH_SIM_MAX_SUBS	384	/* unique subscriptions per element */
#define	MESH_SIM_MAX_SUBNETS	4
#define	MESH_SIM_MAX_APPKEYS	8

struct mesh_sim_subnet_key {
	int		valid;
	uint16_t	net_idx;
	uint8_t		netkey[16];
	uint8_t		nid;
	uint8_t		enckey[16];
	uint8_t		privkey[16];
	int		have_new_key;
	uint8_t		new_netkey[16];
	uint8_t		new_nid;
	uint8_t		new_enckey[16];
	uint8_t		new_privkey[16];
	/*
	 * Directed security material, k2(NetKey, 0x02) (MshPRT_v1.1.1 Section
	 * 3.9.6.3.1).  Derived from the same NetKey as the managed-flooding
	 * material above and held alongside it, because a node that supports
	 * directed forwarding needs BOTH at once: Table 3.14 selects between
	 * them per retransmitted PDU, not per subnet.
	 */
	uint8_t		directed_nid;
	uint8_t		directed_enckey[16];
	uint8_t		directed_privkey[16];
	uint8_t		new_directed_nid;
	uint8_t		new_directed_enckey[16];
	uint8_t		new_directed_privkey[16];
	struct mesh_key_refresh kr;
};

/*
 * One application key index.  MshPRT_v1.1.1 Section 3.11.4: an AppKey follows
 * the Key Refresh phase of the NetKey it is bound to, so the index holds TWO
 * keys for the duration of a refresh - the old one and the one distributed by
 * Config AppKey Update.  Phase 1 transmits with the old key, Phase 2 with the
 * new one, and both phases RECEIVE with either; Phase 3 revokes the old key.
 * A single key slot would make all application traffic undecryptable for
 * whichever side of the refresh the peer had not reached yet.
 */
struct mesh_sim_app_key {
	int		valid;
	uint16_t	net_idx;
	uint16_t	app_idx;
	uint8_t		key[16];
	uint8_t		aid;
	int		have_new_key;	/* a Config AppKey Update is staged */
	uint8_t		new_key[16];
	uint8_t		new_aid;
};
#define	MESH_SIM_RPL_SIZE	16
#define	MESH_SIM_NMC_SIZE	64	/* network message cache slots */
#define	MESH_SIM_REASM		2	/* concurrent reassembly sessions */
#define	MESH_SIM_SAR_TX		4	/* concurrent outbound SAR sessions */
#define	MESH_SIM_MAX_TX		256	/* pending transmissions in the medium */
#define	MESH_SIM_RELAY_TX	256	/* timed Network/Relay retransmissions */
#define	MESH_SIM_RX_MAX		MESH_ACCESS_PAYLOAD_MAX

/*
 * Fixed group destination addresses, MshPRT_v1.1.1 Section 3.4.2.4 Table 3.8.
 *
 * Each of these (all-nodes excepted) is paired by Table 3.28 -- and, for
 * access messages, Table 3.64 -- with the feature that must be enabled for
 * the node to be addressed by it: directed forwarding for
 * all-directed-forwarding-nodes, Proxy for all-proxies, Friend for
 * all-friends, Relay for all-relays.  all-nodes carries no condition.
 */
#define	MESH_ADDR_ALL_DF	0xFFFBu
#define	MESH_ADDR_ALL_PROXIES	0xFFFCu
#define	MESH_ADDR_ALL_FRIENDS	0xFFFDu
#define	MESH_ADDR_ALL_RELAYS	0xFFFEu
#define	MESH_ADDR_ALL_NODES	0xFFFFu

/*
 * One transmitted secured Network PDU on the shared medium.  A broadcast
 * transmission (to_node == -1) is heard by every in-range node; a directed
 * forwarding hop (to_node >= 0) is delivered only to that one adjacent node,
 * which is how the sim distinguishes a directed forward from managed flooding
 * (MshPRT_v1.1 Section 3.6.6).
 */
struct mesh_sim_tx {
	uint8_t		bytes[MESH_NET_MAX_PDU];
	size_t		len;
	int		tx_node;	/* originator index (never re-delivered) */
	int		to_node;	/* directed next hop, or -1 for broadcast */
	int		valid;
};

struct mesh_sim_relay_tx {
	struct mesh_sim_tx	pdu;
	struct mesh_relay_tx	timer;
};

/*
 * Network message cache slot: a (src, seq) processed for relay dedup.
 * M-N1: the IV Index is part of the key so a (src, seq) that recurs across
 * an IV Index change is not mistaken for a duplicate of the earlier epoch.
 */
struct mesh_sim_nmc {
	uint16_t	src;
	uint32_t	seq;
	uint32_t	iv_index;
	/*
	 * MshPRT_v1.1.1 Section 3.4.6.5: "Values for the SRC, SEQ fields, and
	 * index of the NetKey used for decrypting PDU contents should be
	 * stored in a cache entry."  Without it, a Subnet Bridge's re-secured
	 * copy - which keeps the originator's SRC and SEQ and changes only the
	 * NetKey (Section 3.4.6.3) - is indistinguishable from the original
	 * and is discarded as a duplicate.
	 */
	uint16_t	net_idx;
	int		valid;
};

/* One SAR reassembly session plus its captured SeqAuth. */
struct mesh_sim_reasm {
	struct mesh_reasm	r;
	uint32_t		seqauth;	/* SEQ of segment 0 */
	uint32_t		iv_index;
	/*
	 * The (SRC, DST) pair this reassembly belongs to.  MshPRT_v1.1.1
	 * Section 3.5.3.4: "Each such pair [AckedSegments, Sequence
	 * Authentication] is associated with a source address and a
	 * destination address", and a First Segment for a (source,
	 * destination) that already has a reassembly pending DISCARDS the
	 * pending one - so (SRC, DST) is the identity of a session and the
	 * SeqAuth is state WITHIN it, never part of the key.  Keying on
	 * SeqAuth as well let one peer hold every slot with a stream of
	 * distinct SeqZeros.
	 */
	uint16_t		src;
	uint16_t		dst;
	int			szmic;
	int			ctl;
	uint64_t		deadline_ms;	/* SAR Discard timer */
	/*
	 * SAR Acknowledgment timer, MshPRT_v1.1.1 Section 3.5.3.4.  A Segment
	 * Acknowledgment is NOT emitted per arriving segment: a First or Next
	 * Segment to a unicast destination (re)starts this timer, and only its
	 * expiry - or the Last Segment, which acknowledges immediately -
	 * produces one.  Restarting on every segment is what collapses a
	 * 32-segment burst to a single acknowledgment instead of thirty-two.
	 * ack_src / ack_ttl are the DST and TTL that acknowledgment must carry:
	 * "the DST field shall have the same value as the SRC field of the
	 * first received segment of the segmented message".
	 */
	int			ack_armed;
	uint64_t		ack_due_ms;
	uint16_t		ack_src;
	uint8_t			ack_ttl;
	uint16_t		ack_seqzero;
	/*
	 * When the last Segment Acknowledgment for this SeqAuth went out, for
	 * the Most Recent SeqAuth rate limit: "the lower transport layer shall
	 * not send more than one Segment Acknowledgment message for the same
	 * SeqAuth in a period of [acknowledgment delay increment * segment
	 * reception interval] milliseconds" (Section 3.5.3.4).
	 */
	int			acked_once;
	uint64_t		last_ack_ms;
	int			used;
	int			complete;	/* C4-L4: SeqAuth fully reassembled;
					 * retained so a retransmitted segment
					 * is re-acked, not silently dropped. */
};

/* Retransmission state for one locally originated segmented message. */
/*
 * Outstanding segmented transmission (SAR Transmitter, MshPRT_v1.1.1 Section
 * 3.5.3.3).
 *
 * The segments are held as CLEARTEXT Network PDUs, not as the encrypted frames
 * that went on the air.  A retransmission must carry a FRESH network sequence
 * number: every relay keeps a network message cache keyed on (SRC, SEQ, IVI)
 * and drops a PDU it has already seen, so re-emitting the byte-identical frame
 * is a no-op beyond the first hop - exactly the multi-hop case in which
 * segments are lost.  The 13-bit SeqZero in each segment is what keeps the
 * transaction identifiable across the change of SEQ.
 *
 * iv_index is pinned for the lifetime of the transaction: the upper transport
 * TransMIC was computed over (SeqAuth, IV Index), and Section 3.11.5 defers
 * leaving IV Update in Progress precisely so an outstanding segmented message
 * keeps a valid SeqAuth.
 */
struct mesh_sim_sar_tx {
	struct mesh_net_pdu	seg[MESH_SEG_MAX];
	uint32_t		iv_index;
	/*
	 * The full 24-bit SEQ of segment zero.  MshPRT_v1.1.1 Section 3.5.3.1:
	 * "Because of the limited size of the SeqZero field, it is not
	 * possible to send a segmented message when the SEQ field value is
	 * 8192 greater than the SeqAuth value.  If a segmented message has not
	 * been acknowledged by the time that the SEQ field value is 8192
	 * greater than the SeqAuth value, then the transmission of the Upper
	 * Transport PDU shall be canceled."  seqzero alone cannot express that
	 * test, being the low 13 bits of exactly this value.
	 */
	uint32_t		seqauth;
	/*
	 * NetKey index the transaction was secured with.  MshPRT_v1.1.1 Table
	 * 3.24's fourth acknowledgment-validity condition: "The message was
	 * secured using the same NetKey that was used to secure the segmented
	 * message."
	 */
	uint16_t		net_idx;
	uint16_t		dst;
	uint16_t		seqzero;
	uint8_t			segn;
	uint8_t			retries;
	uint32_t		blockack;
	uint64_t		deadline_ms;
	/*
	 * Multicast transactions, MshPRT_v1.1.1 Section 3.5.3.3.  A group or
	 * virtual destination is never acknowledged, so the retransmission
	 * count is the only reliability a multicast segmented message has:
	 * ".txt 4795" has the transmitter store the destination, the SeqAuth
	 * and a remaining-retransmissions count for it, and on each expiry of
	 * the SAR Multicast Retransmissions timer "repeat the transmission of
	 * all the segments of the Upper Transport PDU".  Declining to track
	 * such a transaction at all sends every large scene or lighting payload
	 * to a group exactly once on an unreliable advertising bearer.
	 */
	int			multicast;
	uint8_t			retrans_left;
	int			used;
};

/* Last access message a node fully decoded and dispatched (test hook). */
struct mesh_sim_rx {
	int		valid;
	uint16_t	src;
	uint16_t	dst;
	uint16_t	app_idx;	/* UINT16_MAX for DeviceKey traffic */
	/*
	 * For a virtual destination, the Label UUID that AUTHENTICATED the
	 * message: the candidate whose 16 octets, used as the upper transport's
	 * CCM additional data, made the TransMIC verify (MshPRT_v1.1.1 Section
	 * 3.4.2.3).  have_label is 0 for a unicast or group destination.
	 */
	int		have_label;
	uint8_t		label[MESH_LABEL_UUID_LEN];
	uint32_t	opcode;
	uint8_t		params[MESH_SIM_RX_MAX];
	size_t		params_len;
	uint8_t		ttl;		/* TTL of the delivered Network PDU */
	uint32_t	count;		/* total messages delivered to models */
};

/*
 * DevKey-sealed (config) message delivered to the local node.  The uint16_t
 * after dst is the NetKeyIndex of the subnet that secured the inbound Network
 * PDU -- the config server needs it to honor "do not remove the NetKey that
 * secured this message" (MshPRT 4.3.2.32).
 */
typedef int (*mesh_sim_devkey_rx_fn)(void *, uint16_t, uint16_t, uint16_t,
    const uint8_t *, size_t, uint8_t *, size_t *);
typedef int (*mesh_sim_devkey_lookup_fn)(void *, uint16_t, uint8_t[16]);
typedef int (*mesh_sim_devkey_upper_rx_fn)(void *, uint32_t, uint16_t,
    uint16_t, const uint8_t *, size_t);

/*
 * A node.  Holds its addressing, security material, per-feature state and a
 * model table.  The element/model tables are owned here; model user pointers
 * reference caller-owned model state (e.g. struct mesh_gen_onoff_srv).
 */
struct mesh_node {
	uint16_t		addr;		/* primary element unicast */
	uint8_t			n_elements;
	uint8_t			default_ttl;	/* Config Default TTL for replies/origination */
	struct mesh_element	elems[MESH_SIM_MAX_ELEMS];
	struct mesh_model	models[MESH_SIM_MAX_ELEMS][MESH_SIM_MAX_MODELS];

	uint16_t		elem_subs[MESH_SIM_MAX_ELEMS][MESH_SIM_MAX_SUBS];
	uint16_t		elem_n_subs[MESH_SIM_MAX_ELEMS];
	uint8_t			elem_labels[MESH_SIM_MAX_ELEMS][MESH_SIM_MAX_SUBS]
				    [MESH_LABEL_UUID_LEN];
	uint16_t		elem_n_labels[MESH_SIM_MAX_ELEMS];

	/* Subnet security material (flooding k2 P=0x00, directed k2 P=0x02). */
	uint8_t			netkey[16];
	uint8_t			nid;
	uint8_t			enckey[16];
	uint8_t			privkey[16];
	uint16_t		primary_net_idx;
	int			have_new_key;	/* Key Refresh new material present */
	uint8_t			new_netkey[16];
	uint8_t			new_nid;
	uint8_t			new_enckey[16];
	uint8_t			new_privkey[16];
	/* Directed security material, k2(NetKey, 0x02); see the subnet slot. */
	uint8_t			directed_nid;
	uint8_t			directed_enckey[16];
	uint8_t			directed_privkey[16];
	uint8_t			new_directed_nid;
	uint8_t			new_directed_enckey[16];
	uint8_t			new_directed_privkey[16];
	struct mesh_key_refresh	kr;

	struct mesh_sim_subnet_key subnets[MESH_SIM_MAX_SUBNETS];
	size_t			n_subnets;
	struct mesh_sim_app_key appkeys[MESH_SIM_MAX_APPKEYS];
	size_t			n_appkeys;
	/*
	 * Default model AppKey bindings for a node driven directly through this
	 * API rather than by a Configuration Server: the list of AppKey indexes
	 * the node holds, which mesh_sim_add_model() binds each registered model
	 * to.  A Configuration Server (meshd) replaces every model's binding
	 * list with the one its Config Model App Bind database holds, and only
	 * models still pointing at this array are maintained here, so the two
	 * never interfere.  The access layer's binding check (MshPRT_v1.1.1
	 * Figure 3.72) is unconditional either way.
	 */
	uint16_t		model_app_idx[MESH_SIM_MAX_APPKEYS];
	uint8_t			devkey[16];
	int			have_devkey;
	mesh_sim_devkey_rx_fn	devkey_rx;
	void			*devkey_rx_arg;
	mesh_sim_devkey_lookup_fn devkey_lookup;
	mesh_sim_devkey_upper_rx_fn devkey_upper_rx;
	void			*devkey_client_arg;

	/*
	 * Friendship security credentials (MshPRT_v1.1 Section 3.6.6.2): the k2
	 * friendship-P derivation shared by the Friend and its LPN.  When set,
	 * the Friend<->LPN Poll and the queued-message delivery are secured with
	 * the friendship NID (distinct from the managed-flooding NID) instead of
	 * the subnet credential.
	 */
	int			have_friend_cred;
	uint16_t		friend_net_idx;
	uint8_t			friend_nid;
	uint8_t			friend_enckey[16];
	uint8_t			friend_privkey[16];
	/*
	 * Establishment inputs for the friendship credential (the LPN and
	 * Friend addresses and their counters).  Retained so the credential can
	 * be re-derived from a promoted NetKey when a Key Refresh settles
	 * (MshPRT_v1.1 Section 3.6.4.2: friendship security is bound to the
	 * NetKey).
	 */
	uint16_t		fc_lpn_addr;
	uint16_t		fc_friend_addr;
	uint16_t		fc_lpn_counter;
	uint16_t		fc_friend_counter;
	/*
	 * The friendship credential derived from the subnet's NEW NetKey while
	 * a Key Refresh is in flight.  MshPRT_v1.1.1 Section 3.9.6.3.1 derives
	 * friendship security material from the NetKey, and Section 3.11.4.2
	 * says that in Phase 2 the node "shall only transmit messages ... using
	 * the new keys, shall receive messages using the old keys and the new
	 * keys" - so a refresh needs BOTH friendship credentials live from the
	 * moment the new NetKey arrives, exactly as the managed-flooding pair
	 * above does.  Re-deriving only at Phase 3 leaves friendship - Poll,
	 * Update and queued delivery - broken for the whole of Phase 2.
	 */
	int			have_new_friend_cred;
	uint8_t			new_friend_nid;
	uint8_t			new_friend_enckey[16];
	uint8_t			new_friend_privkey[16];

	/*
	 * Proxy (GATT bearer) role (MshPRT_v1.1 Section 6).  A proxy node holds
	 * a proxy filter and forwards to its GATT client only those Network PDUs
	 * whose DST passes the filter; proxy_fwd_count / proxy_last_fwd_dst
	 * capture that GATT-out direction for inspection.
	 */
	int			is_proxy;
	struct mesh_proxy_filter pfilter;
	uint32_t		proxy_fwd_count;
	uint16_t		proxy_last_fwd_dst;

	struct mesh_iv_state	iv;
	uint32_t		seq;

	struct mesh_rpl_entry	rpl_store[MESH_SIM_RPL_SIZE];
	struct mesh_rpl		rpl;

	struct mesh_relay_config relay;
	int			is_relay;

	/*
	 * Subnet Bridge (MshPRT_v1.1.1 Sections 3.4.6.3, 3.9.8, 4.2.41-4.2.43).
	 * When bridge_enabled, the receive path consults bridge_table to decide
	 * whether a Network PDU crosses to another subnet; a crossing PDU is
	 * re-secured with the destination subnet's network credential and
	 * retransmitted with the same SRC, SEQ and IV Index and TTL - 1.
	 *
	 * bridge_rpl is the SEPARATE replay list Section 3.9.8 requires of a
	 * Subnet Bridge ("shall maintain the most recent IVISeq value for each
	 * source address authorized to send messages to bridged subnets").  It
	 * must not share storage with node->rpl, which protects messages
	 * addressed to this node: a bridged message is never delivered here, so
	 * committing it to node->rpl would let bridged traffic from a peer
	 * suppress that peer's genuine messages to this node, and vice versa.
	 */
	int			bridge_enabled;
	struct mesh_bridging_table bridge_table;
	struct mesh_rpl_entry	bridge_rpl_store[MESH_SIM_RPL_SIZE];
	struct mesh_rpl		bridge_rpl;
	uint32_t		bridge_fwd_count;  /* PDUs crossed to a subnet */
	uint32_t		bridge_replay_drops;

	struct mesh_sim_nmc	nmc[MESH_SIM_NMC_SIZE];
	size_t			nmc_next;

	struct mesh_sim_reasm	reasm[MESH_SIM_REASM];
	struct mesh_sim_sar_tx	sar_tx[MESH_SIM_SAR_TX];

	/*
	 * SAR timing (MshPRT_v1.1.1 Sections 4.2.48 / 4.2.49), applied from the
	 * node's SAR Transmitter / SAR Receiver Configuration Server states via
	 * mesh_sim_set_sar().  Zero means "library default", so a node that was
	 * never configured behaves exactly as before.
	 */
	uint32_t		sar_retrans_ms;	 /* unicast retransmit interval */
	uint32_t		sar_retries;	 /* unicast retransmit budget */
	uint32_t		sar_discard_ms;	 /* RX reassembly discard timeout */

	/*
	 * Friend feature enablement, as distinct from is_friend below.
	 *
	 * is_friend arms THIS engine's Friend Queue for one LPN.  A consumer
	 * that runs its own friendship engine (meshd does) leaves is_friend
	 * clear, but the network layer still has to know the Friend feature is
	 * enabled, because Table 3.28 conditions delivery of the all-friends
	 * fixed group address on exactly that -- and a Friend Request is
	 * addressed to all-friends.  Set through mesh_sim_set_friend_feature().
	 */
	int			friend_feature;

	/* Friend feature: a queue for one LPN. */
	int			is_friend;
	uint16_t		friend_lpn;	/* the LPN this node serves */
	struct mesh_friend_queue fq;

	/* Low Power node feature. */
	int			is_lpn;
	int			awake;		/* radio on (polling) */
	uint16_t		lpn_friend;	/* this LPN's Friend address */
	struct mesh_lpn_state	lpn;

	struct mesh_sim_rx	rx;		/* last delivered access message */
	uint32_t		relay_count;	/* PDUs this node re-broadcast */

	/*
	 * Directed Forwarding (MshPRT_v1.1 Section 3.6.6).  A DF-capable node
	 * keeps a Forwarding Table of established paths and, as a Path Origin,
	 * a discovery state machine.  When df_enabled, the relay decision runs
	 * mesh_df_forward_decide() (directed along a matched path, else the
	 * managed-flooding fallback) instead of the plain Relay feature.
	 */
	int			df_enabled;
	struct mesh_df_fwd_table df_table;
	struct mesh_df_features	df_feat;
	struct mesh_df_discovery df_disc;	/* Path Origin discovery state */
	uint8_t			df_fn;		/* next Forwarding Number to originate */
	uint32_t		df_directed_fwd; /* PDUs forwarded along a path */
	/*
	 * Count of IV Update completions held back by MshPRT_v1.1.1 Section
	 * 3.11.5's deferral rule (an unacknowledged segmented transmission).
	 * Observability only; the deferral itself is a property of the SAR
	 * transmit table, not of this counter.
	 */
	uint32_t		iv_complete_deferrals;

	/*
	 * Heartbeat (MshPRT_v1.1 Section 3.6.5.4, MshMDL_v1.1 Section 4.4.1).
	 * hb_features tracks the node's current feature bitmap; hb_pub/hb_timer
	 * drive periodic and feature-change publication; hb_sub records received
	 * Heartbeats (count and min/max hops) when a subscription is active.
	 */
	uint16_t		hb_features;
	struct mesh_hb_pub	hb_pub;
	struct mesh_hb_pub_timer hb_timer;
	struct mesh_hb_sub	hb_sub;
	int			hb_sub_active;

	struct mesh_sim		*sim;
	int			index;
};

/* The simulator: the node set, the shared media and the virtual clock. */
struct mesh_sim {
	struct mesh_node	nodes[MESH_SIM_MAX_NODES];
	int			n_nodes;

	struct mesh_sim_tx	tx[MESH_SIM_MAX_TX];
	size_t			n_tx;
	struct mesh_sim_relay_tx retransmit[MESH_SIM_RELAY_TX];

	uint8_t			netkey[16];	/* shared subnet NetKey */
	uint8_t			appkey[16];	/* shared AppKey */
	uint32_t		iv_index;

	uint64_t		now;		/* protocol virtual clock, seconds */
	uint64_t		now_ms;		/* access/runtime virtual clock */
	/*
	 * Wall-clock (CLOCK_REALTIME) seconds, used ONLY as the IV Update
	 * 96-hour dwell anchor.  The dwell measures time-in-state and must
	 * survive daemon restarts, so it cannot use the monotonic `now` (which
	 * resets to ~0 each boot).  Defaults to `now` if the host never sets it.
	 */
	uint64_t		wall_now;

	uint32_t		delivered;	/* total node receptions attempted */

	/*
	 * Optional radio topology.  Default (use_topology == 0) is a fully
	 * connected medium: every node hears every transmission.  Once any
	 * link is declared with mesh_sim_link() the medium switches to
	 * explicit adjacency and a transmission reaches only linked nodes,
	 * so genuine multi-hop (relay-only reachability) can be modelled.
	 */
	int			use_topology;
	uint8_t			linked[MESH_SIM_MAX_NODES][MESH_SIM_MAX_NODES];
};

/*
 * A running PB-ADV provisioning exchange over the virtual provisioning bearer
 * (MshPRT_v1.1 Section 5).  Holds the Provisioner and Device protocol sessions
 * and their PB-ADV link/transaction layers, plus a small per-side FIFO of
 * Provisioning PDUs waiting for the link to go idle (a session may enqueue a
 * burst - e.g. Start + Public Key - that the single-transaction link accepts
 * one at a time).  The bearer is lossless, so the built-in retransmission
 * timers never fire; the injected millisecond clock still gates them.
 */
#define	MESH_SIM_PROV_FIFO	4	/* pending Provisioning PDUs per side */

struct mesh_sim_prov {
	struct mesh_prov_session	sess[2];	/* 0 Provisioner, 1 Device */
	struct mesh_prov_link		link[2];
	uint8_t		fifo[2][MESH_SIM_PROV_FIFO][MESH_PROV_PDU_MAX];
	size_t		fifo_len[2][MESH_SIM_PROV_FIFO];
	size_t		fifo_head[2];
	size_t		fifo_tail[2];
	uint64_t	now_ms;
	uint16_t	assigned_addr;
	uint8_t		dev_elements;
	int		done;
	int		failed;
};

/* ----------------------------------------------------------------
 * Setup.
 * ---------------------------------------------------------------- */

/*
 * Initialise a sim with the shared subnet NetKey, AppKey and starting IV
 * Index.  Returns 0 on success, -1 on a NULL argument.
 */
int	mesh_sim_init(struct mesh_sim *sim, const uint8_t netkey[16],
	    const uint8_t appkey[16], uint32_t iv_index);

/*
 * Add a node with primary unicast addr and n_elements consecutive element
 * addresses (addr .. addr+n_elements-1).  Derives the node's network (k2) and
 * application (k4) security material from the shared keys.  Returns the node
 * pointer, or NULL if the table is full or the arguments are invalid.
 */
struct mesh_node *mesh_sim_add_node(struct mesh_sim *sim, uint16_t addr,
	    uint8_t n_elements);

/*
 * Attach a model (from e.g. mesh_gen_onoff_srv_model()) to element elem_index
 * of a node.  Returns 0 on success, -1 on overflow or a bad index.
 */
int	mesh_sim_add_model(struct mesh_node *node, uint8_t elem_index,
	    struct mesh_model model);

/* Subscribe a node to a group address.  Returns 0, or -1 if the list is full. */
int	mesh_sim_subscribe(struct mesh_node *node, uint16_t group);
int	mesh_sim_subscribe_element(struct mesh_node *node, uint8_t elem_index,
	    uint16_t group);
int	mesh_sim_subscribe_virtual_element(struct mesh_node *node,
	    uint8_t elem_index, const uint8_t label[MESH_LABEL_UUID_LEN]);
void	mesh_sim_clear_subscriptions(struct mesh_node *node,
	    uint8_t elem_index);

/*
 * Declare a bidirectional radio link between two nodes.  The first call
 * switches the medium from fully connected to explicit-topology mode, so
 * only linked node pairs hear each other.  Returns 0, -1 on a bad argument.
 */
int	mesh_sim_link(struct mesh_sim *sim, struct mesh_node *a,
	    struct mesh_node *b);

/* Enable the Relay feature on a node (TTL >= 2 re-broadcast). */
void	mesh_sim_set_relay(struct mesh_node *node, int enabled);

/*
 * Subnet Bridge control (MshPRT_v1.1.1 Sections 4.2.41 / 4.2.42).  The Subnet
 * Bridge state gates the forwarding behaviour; the Bridging Table state is
 * copied wholesale from the Bridge Configuration Server's copy, because
 * Section 4.2.42 defines a SINGLE instance of the state per node and the
 * server owns it.  Enabling or disabling the bridge, or replacing the table,
 * clears the bridge replay list: a Bridging Table entry that has been removed
 * or re-pointed no longer authorises the source addresses it used to, so
 * retaining their IVISeq values would only carry stale state forward.
 */
void	mesh_sim_set_bridge(struct mesh_node *node, int enabled);
void	mesh_sim_set_bridging_table(struct mesh_node *node,
	    const struct mesh_bridging_table *t);

/*
 * Record whether the Friend feature is enabled on this node, independently of
 * whether this engine also runs the Friend Queue (mesh_sim_set_friend()).  The
 * network layer needs it for Table 3.28: the all-friends fixed group
 * destination address is addressed to a node only while the Friend feature is
 * enabled, and a Friend Request is addressed to all-friends.
 */
void	mesh_sim_set_friend_feature(struct mesh_node *node, int enabled);

/*
 * Make a node a Friend for the LPN at lpn_addr (lpn_elements elements,
 * queue capacity qcap).  Returns 0, -1 on a bad argument.
 */
int	mesh_sim_set_friend(struct mesh_node *node, uint16_t lpn_addr,
	    uint8_t lpn_elements, size_t qcap);

/* Make a node a Low Power node bound to the Friend at friend_addr. */
int	mesh_sim_set_lpn(struct mesh_node *node, uint16_t friend_addr,
	    uint32_t poll_timeout);

/*
 * Establish friendship security material between an already-configured Friend
 * and LPN (models the outcome of the Friend Request/Offer counter exchange,
 * MshPRT_v1.1 Section 3.6.6.2): both nodes derive the SAME friendship NID /
 * EncryptionKey / PrivacyKey with k2 over
 * 0x01 || LPNAddress || FriendAddress || LPNCounter || FriendCounter, and the
 * LPN friendship is marked established.  Returns 0, -1 on a bad argument or if
 * the pair are not a Friend/LPN.
 */
int	mesh_sim_establish_friendship(struct mesh_sim *sim,
	    struct mesh_node *friend, struct mesh_node *lpn,
	    uint16_t net_idx, uint16_t lpn_counter, uint16_t friend_counter);

/*
 * Add an indexed subnet to a node, deriving
 * its managed-flooding credential.  Returns 0, -1 on a bad argument.
 */
int	mesh_sim_add_subnet(struct mesh_node *node, uint16_t net_idx,
	    const uint8_t netkey[16]);
int	mesh_sim_add_appkey(struct mesh_node *node, uint16_t net_idx,
	    uint16_t app_idx, const uint8_t appkey[16]);
int	mesh_sim_set_devkey(struct mesh_node *node, const uint8_t devkey[16],
	    mesh_sim_devkey_rx_fn rx, void *arg);
int	mesh_sim_set_devkey_client(struct mesh_node *node,
	    mesh_sim_devkey_lookup_fn lookup, mesh_sim_devkey_upper_rx_fn rx,
	    void *arg);
int	mesh_sim_remove_appkey(struct mesh_node *node, uint16_t app_idx);

/*
 * Key Refresh for one application key index (MshPRT_v1.1.1 Section 3.11.4).
 * mesh_sim_appkey_update() stages the key a Config AppKey Update distributed:
 * the old key stays live for transmission until the bound subnet reaches Phase
 * 2 and for reception until the refresh settles.  mesh_sim_appkey_finalize()
 * is the Phase 3 revocation: the staged key becomes the only key.  Both return
 * 0 on success, -1 if the index is unknown (or the staged key is unusable).
 */
int	mesh_sim_appkey_update(struct mesh_node *node, uint16_t net_idx,
	    uint16_t app_idx, const uint8_t new_key[16]);
int	mesh_sim_appkey_finalize(struct mesh_node *node, uint16_t app_idx);
int	mesh_sim_remove_subnet(struct mesh_node *node, uint16_t net_idx);

/*
 * Make a node a Proxy (GATT bearer) node with a default (empty accept-list)
 * proxy filter.
 */
void	mesh_sim_set_proxy(struct mesh_node *node);

/*
 * Apply a secured Proxy Configuration Network PDU (Set Filter Type / Add /
 * Remove Addresses, MshPRT_v1.1 Section 6.6) to a proxy node's filter: the PDU
 * is decrypted with the node's managed-flooding credential under the proxy
 * nonce, parsed, and applied.  Returns 0 on success, -1 on error.
 */
int	mesh_sim_proxy_apply_config(struct mesh_node *node,
	    const uint8_t *secured_pdu, size_t len);

/*
 * GATT-in bridge: a GATT client hands the proxy a fully secured Network PDU,
 * which the proxy retransmits onto the advertising bearer (Section 6.5).
 * Returns 0, -1 on error.
 */
int	mesh_sim_proxy_gatt_in(struct mesh_sim *sim, struct mesh_node *proxy,
	    const uint8_t *net_pdu, size_t len);

/* ----------------------------------------------------------------
 * Traffic.
 * ---------------------------------------------------------------- */

/*
 * Originate an access message from node (primary element) to dst, secured
 * with the node's AppKey and queued onto the medium.  ttl is the initial
 * Time To Live.  Segments automatically if the Upper Transport PDU exceeds a
 * single unsegmented frame.  Returns 0 on success, -1 on failure.
 */
int	mesh_sim_send_access(struct mesh_sim *sim, struct mesh_node *node,
	    uint16_t dst, uint32_t opcode, const uint8_t *params, size_t plen,
	    uint8_t ttl);

/*
 * Like mesh_sim_send_access(), but originate on the node's SECONDARY subnet
 * (secured with netkey2's credential and appkey2).  Requires the node to have
 * an indexed subnet (mesh_sim_add_subnet).  Returns 0, -1 on failure.
 */
int	mesh_sim_send_access_key(struct mesh_sim *sim, struct mesh_node *node,
	    uint16_t net_idx, uint16_t app_idx, uint16_t dst, uint32_t opcode,
	    const uint8_t *params, size_t plen, uint8_t ttl);
int	mesh_sim_send_access_key_from(struct mesh_sim *sim,
	    struct mesh_node *node, uint16_t src, uint16_t net_idx,
	    uint16_t app_idx, uint16_t dst, uint32_t opcode,
	    const uint8_t *params, size_t plen, uint8_t ttl);
int	mesh_sim_send_access_key_from_virtual(struct mesh_sim *sim,
	    struct mesh_node *node, uint16_t src, uint16_t net_idx,
	    uint16_t app_idx, const uint8_t label[MESH_LABEL_UUID_LEN],
	    uint32_t opcode, const uint8_t *params, size_t plen, uint8_t ttl);

/*
 * Originate a PRE-SEALED Upper Transport Access PDU from node to dst.  Unlike
 * mesh_sim_send_access(), the caller has already applied upper-transport
 * encryption (e.g. a Config Client sealing a Configuration message under a
 * node's DevKey, AKF=0); this routine only builds the Lower Transport / Network
 * layers, secures the Network PDU with the node's primary-subnet credential and
 * queues it onto the medium.  akf/aid tag the Lower Transport header; seq0 is
 * the sequence number the upper PDU was sealed under and MUST be the seq used on
 * the wire (so the peer's decrypt nonce matches).  Segments automatically if the
 * upper PDU exceeds one frame, consuming seq0..seq0+nseg-1.  Does NOT advance
 * node->seq - the caller owns the sequence-number space and must advance it by
 * the return value.  Returns the number of Network PDUs (segments) queued (>= 1),
 * -1 on a bad argument or a build failure.
 */
int	mesh_sim_send_upper(struct mesh_sim *sim, struct mesh_node *node,
	    uint16_t dst, uint32_t seq0, const uint8_t *upper, size_t upper_len,
	    int akf, uint8_t aid, uint8_t ttl);

/*
 * Deliver every queued transmission to every other node (one hop).  Relays
 * and Status replies generated during delivery are queued for the NEXT step.
 * Returns the number of transmissions delivered in this step (0 => quiescent).
 */
int	mesh_sim_step(struct mesh_sim *sim);

/*
 * Step until the medium is quiescent or max_steps is reached.  Returns the
 * number of steps run.
 */
int	mesh_sim_run(struct mesh_sim *sim, int max_steps);

/* Re-inject a previously transmitted PDU (attacker replay).  Returns 0/-1. */
int	mesh_sim_reinject(struct mesh_sim *sim, int tx_node,
	    const uint8_t *bytes, size_t len);

/*
 * LPN poll: the LPN sends a Friend Poll to its Friend, the network is run,
 * and any single queued message is delivered back to the (awake) LPN.
 * Returns 1 if a message was delivered, 0 if the queue was empty, -1 on error.
 */
int	mesh_sim_lpn_poll(struct mesh_sim *sim, struct mesh_node *lpn);

/* ----------------------------------------------------------------
 * Beacons, IV Update and Key Refresh.
 * ---------------------------------------------------------------- */

/* Advance the virtual clock by dt seconds. */
void	mesh_sim_advance(struct mesh_sim *sim, uint64_t dt_secs);
void	mesh_sim_advance_ms(struct mesh_sim *sim, uint64_t dt_ms);

/*
 * Broadcast node's Secure Network beacon; every other node processes it
 * (IV-Update accept rules + Key-Refresh phase advance).  Returns 0, -1 on
 * error.
 */
int	mesh_sim_send_beacon(struct mesh_sim *sim, struct mesh_node *node,
	    uint16_t net_idx);

/* Locally begin an IV Update on a node (gated by the 96-hour dwell). */
int	mesh_sim_begin_iv_update(struct mesh_node *node);
/* Locally complete an IV Update on a node (gated by the 96-hour dwell). */
int	mesh_sim_complete_iv_update(struct mesh_node *node);

/*
 * Locally begin a Key Refresh on a node with new_netkey (Phase 0 -> 1),
 * deriving the new network material.  Returns 0, -1 on error.
 */
int	mesh_sim_begin_key_refresh(struct mesh_node *node,
	    const uint8_t new_netkey[16]);
/* Advance a node's own Key Refresh phase (Phase 1 -> 2, using the new key). */
int	mesh_sim_key_refresh_advance(struct mesh_node *node);

/*
 * Settle a Key Refresh (Phase 3 -> 0): promote the new NetKey and its derived
 * managed-flooding credential to the sole current key, re-derive any friendship
 * credential from the promoted key (MshPRT_v1.1 Section 3.6.4.2), reset the
 * phase state machine to Normal and scrub the new-key material.  After this the
 * OLD key is no longer held, so traffic secured with it is rejected - which is
 * the point of the revocation (Section 3.11.4.3).  Returns 0, -1 on error (no new
 * key present).
 */
int	mesh_sim_key_refresh_finalize(struct mesh_node *node);

/* Indexed variants operate on either the primary or an additional subnet. */
int	mesh_sim_subnet_key_refresh_begin(struct mesh_node *node,
	    uint16_t net_idx, const uint8_t new_netkey[16]);
int	mesh_sim_subnet_key_refresh_advance(struct mesh_node *node,
	    uint16_t net_idx);
int	mesh_sim_subnet_key_refresh_finalize(struct mesh_node *node,
	    uint16_t net_idx);
int	mesh_sim_subnet_kr_phase(const struct mesh_node *node,
	    uint16_t net_idx);

/*
 * Process a Secure Network beacon (Section 3.10.3) or a Mesh Private beacon
 * (Section 3.10.4) received by a single node, selected by the Beacon Type
 * octet: authenticate it against each known key, apply the IV-Update accept
 * rules and, when the beacon authenticates under the node's new key, drive the
 * Key Refresh phase from the beacon's Key Refresh Flag (Sections
 * 3.11.4.1-3.11.4.3), then immediately revoking/promoting when Phase 3 is
 * entered.  Both beacons carry the same Flags and IV Index and, per Section
 * 3.10.4.2, drive the same processing.  now is the virtual clock in seconds.
 * Returns 0 on a beacon that authenticated (under any key), -1 otherwise.
 */
int	mesh_sim_node_recv_beacon(struct mesh_node *node, const uint8_t *beacon,
	    size_t len, uint64_t now, uint16_t *net_idx);

/*
 * Drive the IV Update / IV Index Recovery state machines from ONE already
 * authenticated (IV Index, IV Update flag) observation, and apply the two
 * node-level consequences the pure state machine in mesh_iv.c cannot: the
 * sequence-number reset and replay-list flush of Table 3.86, and the Section
 * 3.11.5 rule that a secondary-subnet observation may not carry the node past
 * the primary subnet's last known IV Index.
 *
 * `primary` says whether the observation was authenticated with the PRIMARY
 * subnet's key material.  It is the wrapper mesh_sim_node_recv_beacon() uses
 * for beacons, and it is equally the correct entry point for a Friend Update:
 * MshPRT_v1.1.1 Section 3.6.6.4.2 requires a Low Power node to "process the
 * Flags and IV Index fields using the same rules as if they had been received
 * in a Secure Network beacon", and "the same rules" includes IV Index
 * Recovery - which Section 3.11.6 names the Low Power node as the designated
 * mechanism for.  Calling mesh_iv_recv_beacon() directly from that path skips
 * the arming, the sequence reset and the replay-list flush.
 */
void	mesh_sim_node_iv_beacon(struct mesh_node *node, uint32_t recv_iv,
	    int recv_iv_update, uint64_t now, int primary);

/*
 * Derive and store this node's friendship security material (MshPRT_v1.1.1
 * Section 3.9.6.3.1) for the friendship identified by (net_idx, LPN address,
 * Friend address, LPNCounter, FriendCounter), from BOTH that subnet's current
 * NetKey and, when a Key Refresh has staged one, its new NetKey.  The stored
 * establishment inputs let the pair be re-derived whenever either key changes.
 * Returns 0 on success, -1 when this node does not hold net_idx or the
 * derivation fails (in which case nothing is stored).
 */
int	mesh_sim_friend_cred_derive(struct mesh_node *node, uint16_t net_idx,
	    uint16_t lpn_addr, uint16_t friend_addr, uint16_t lpn_counter,
	    uint16_t friend_counter);

/*
 * Erase every piece of key material this node holds.
 *
 * MshPRT_v1.1.1 Section 3.11.7 (Node Removal procedure), verbatim: "When the
 * Node Removal procedure is started, the node shall delete all stored security
 * credentials, all stored security material, the device key, and the
 * provisioning data.  If the node supports provisioning, the node shall become
 * an unprovisioned device."  Section 4.4.1.2 routes the Config Node Reset
 * message here: "When an element receives a Config Node Reset message, it
 * shall perform the Node Removal procedure (see Section 3.11.7)".
 *
 * Scrubbed: the primary subnet's NetKey and its managed-flooding, directed and
 * Key-Refresh-staged security material; every secondary subnet; every
 * application key (both key slots); the friendship credential pair; and the
 * device key.  The Key Refresh phase machines are re-initialised so no
 * half-finished refresh survives.  Structural identity that is not key
 * material - the element addresses, the model table, the IV Index - is left
 * alone; the surrounding node marks itself unprovisioned.
 */
void	mesh_sim_node_erase_keys(struct mesh_node *node);

/*
 * Friendship security material to TRANSMIT with, selected by the friendship
 * subnet's Key Refresh transmit rule (Section 3.11.4.2: Phase 2 transmits with
 * the new keys).  Returns 0 and fills the out-parameters, or -1 when this node
 * holds no friendship credential.
 */
int	mesh_sim_friend_txsec(const struct mesh_node *node, uint8_t *nid,
	    const uint8_t **enc, const uint8_t **priv);

/* ----------------------------------------------------------------
 * Provisioning (PB-ADV) over the virtual bearer.  MshPRT_v1.1 Section 5.
 * ---------------------------------------------------------------- */

/*
 * Set up a provisioning exchange: a Provisioner hands the sim's subnet NetKey,
 * IV Index and the unicast address assign_addr to an unprovisioned device with
 * dev_elements elements identified by dev_uuid.  Fresh ECDH key pairs and
 * Provisioning Randoms are generated.  Returns 0, -1 on error.
 */
int	mesh_sim_provision_begin(struct mesh_sim *sim, struct mesh_sim_prov *pv,
	    const uint8_t dev_uuid[16], uint16_t assign_addr,
	    uint8_t dev_elements);

/*
 * Pump the PB-ADV bearer (Link Open/Ack, Generic Provisioning transactions and
 * the Section 5.4 Provisioning PDU exchange) until both sessions reach a
 * terminal state or max_iters is exhausted.  Returns 0 when both sides
 * completed and derived the SAME DevKey, -1 otherwise.
 */
int	mesh_sim_provision_run(struct mesh_sim *sim, struct mesh_sim_prov *pv,
	    int max_iters);

/*
 * After a successful run, admit the freshly provisioned device to the network
 * as a sim node at its assigned unicast, deriving the subnet/app credentials
 * from the handed-over NetKey (identical to the sim's shared key).  Returns the
 * new node, or NULL on error.
 */
struct mesh_node *mesh_sim_provision_commit(struct mesh_sim *sim,
	    struct mesh_sim_prov *pv);

/* The DevKey held by the Provisioner (0) or Device (1) side of the exchange. */
const uint8_t	*mesh_sim_prov_devkey(const struct mesh_sim_prov *pv, int side);

/* ----------------------------------------------------------------
 * Directed Forwarding (MshPRT_v1.1 Section 3.6.6).
 * ---------------------------------------------------------------- */

/*
 * Enable Directed Forwarding on a node.  managed_flood is the base managed-
 * flooding Relay fallback (used when no path covers a PDU); the directed
 * relay/proxy/friend features are all enabled.  A DF node routes a Network PDU
 * along an established Forwarding Table path when one matches, else floods.
 */
/*
 * Apply the node's SAR Transmitter / Receiver timing (MshPRT_v1.1.1
 * Sections 4.2.48 / 4.2.49).
 * Any argument of 0 restores the library default for that parameter.
 */
void	mesh_sim_set_sar(struct mesh_node *node, uint32_t retrans_ms,
	    uint32_t retries, uint32_t discard_ms);

void	mesh_sim_set_df(struct mesh_node *node, int managed_flood);

/*
 * Apply a full Directed Forwarding feature set to a node.  enabled == 0 turns
 * the relay/target roles off AND flushes the Forwarding Table (so a node told
 * to stop forwarding cannot keep using established paths); enabled == 1 applies
 * the individual directed relay / proxy / friend feature values, and
 * (re)initialises the Forwarding Table only on a genuine disabled->enabled
 * transition, so re-asserting DF while it is already on preserves the table.
 * mesh_sim_set_df() is the "everything on" shorthand.
 */
void	mesh_sim_set_df_features(struct mesh_node *node, int enabled,
	    int directed_relay, int directed_proxy, int directed_friend,
	    int managed_flood);

/*
 * Run a path discovery from origin to target over the medium: the origin sends
 * a Path Request (flooded, installing reverse Forwarding Table entries at each
 * DF relay), the target answers with a Path Reply that retraces the reverse
 * path installing forward entries, and the origin sends a Path Confirmation
 * (Section 3.6.6.5).  lifetime_sel is a MESH_DF_LIFETIME_* selector.  Returns 0
 * when the origin's discovery reaches the established state, -1 otherwise.
 */
int	mesh_sim_df_discover(struct mesh_sim *sim, struct mesh_node *origin,
	    uint16_t target, uint8_t lifetime_sel);

/* Expire elapsed Forwarding Table entries on every node at the current clock. */
void	mesh_sim_df_expire(struct mesh_sim *sim);

/* ----------------------------------------------------------------
 * Heartbeat (MshPRT_v1.1 Section 3.6.5.4, MshMDL_v1.1 Section 4.4.1).
 * ---------------------------------------------------------------- */

/*
 * Configure a node's Heartbeat publication (destination, CountLog, PeriodLog,
 * publication TTL and the trigger feature mask) and seed its current feature
 * bitmap.  Loads the periodic publication timer.
 */
void	mesh_sim_hb_set_pub(struct mesh_node *node, uint16_t dst,
	    uint8_t count_log, uint8_t period_log, uint8_t ttl,
	    uint16_t trigger_features, uint16_t cur_features);

/*
 * Configure a node's Heartbeat subscription (source, destination, PeriodLog).
 * Returns 0 when the subscription was applied (which includes the disabling
 * forms), -1 when the Set is invalid - in which case any live subscription and
 * its accumulated Count/MinHops/MaxHops are left untouched.
 */
int	mesh_sim_hb_set_sub(struct mesh_node *node, uint16_t src, uint16_t dst,
	    uint8_t period_log);

/*
 * Apply a feature change: update the node's feature bitmap and, when the change
 * touches the publication trigger mask, publish a triggered Heartbeat onto the
 * medium (Section 3.6.5.4).  Returns 1 if a Heartbeat was published, 0 if not,
 * -1 on error.
 */
int	mesh_sim_hb_feature_change(struct mesh_sim *sim, struct mesh_node *node,
	    uint16_t new_features);

/*
 * Advance the node's periodic Heartbeat timer by dt_secs; when a publication
 * period boundary is crossed and publications remain, publish a Heartbeat onto
 * the medium (MshMDL_v1.1 Section 4.2.18).  Returns the number of Heartbeats
 * published (0 or more), -1 on error.
 */
int	mesh_sim_hb_publish_periodic(struct mesh_sim *sim, struct mesh_node *node,
	    uint32_t dt_secs);

/* ----------------------------------------------------------------
 * Inspection accessors.
 * ---------------------------------------------------------------- */

struct mesh_node *mesh_sim_node_at(struct mesh_sim *sim, uint16_t addr);
uint32_t	mesh_sim_node_seq(const struct mesh_node *node);
uint32_t	mesh_sim_node_iv(const struct mesh_node *node);
int		mesh_sim_node_kr_phase(const struct mesh_node *node);
size_t		mesh_sim_pending(const struct mesh_sim *sim);

#endif /* _MESH_SIM_H_ */
