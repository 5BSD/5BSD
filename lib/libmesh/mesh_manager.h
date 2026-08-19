/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh network manager / provisioner application (MshPRT_v1.1
 * Sections 3.4, 3.7, 4; MshMDL_v1.1 Section 4.3).
 *
 * The provisioning protocol (mesh_provisioner.[ch]) carries out the over-the-
 * air exchange that mints a DevKey and hands a device its NetKey / IV Index /
 * unicast address, but it takes those values as caller-supplied inputs and
 * keeps no record of what was provisioned.  This module is the layer above it:
 * the manager that CREATES and OWNS a mesh network and its devices.
 *
 * It provides four things (MshPRT Sections cited per function):
 *
 *   1. Create a network - mint a primary NetKey and AppKey, fix IV Index and
 *      key indexes at 0, and stand up the Provisioner's own node at unicast
 *      0x0001 with its own DevKey (Section 3.7.3 / Section 4).
 *
 *   2. A unicast address allocator - hand out the next free unicast address to
 *      each device, reserving one address per element so a multi-element device
 *      consumes a contiguous block, within the 0x0001..0x7FFF range and with
 *      exhaustion reported rather than a wrapped/colliding address (Section
 *      3.4.2).
 *
 *   3. A provisioned-node roster and DevKey store - the network's node database
 *      keyed by unicast address (with a device-UUID index), holding each node's
 *      element count, DevKey and provisioned-time, with add / lookup / remove /
 *      iterate and a versioned, CRC-checked persistence format.
 *
 *   4. A Config Client - build the foundation Configuration messages that make
 *      a just-provisioned node useful (AppKey Add, Model App Bind, Model
 *      Subscription Add, Model Publication Set), encrypt them to a node under
 *      its DevKey over the upper transport, and recover the Status replies
 *      (Section 3.7.3, MshMDL Section 4.3.4).
 *
 * Pure and hardware-free apart from the RNG used to mint keys (OpenSSL
 * RAND_bytes, matching the rest of libblemesh) and the persistence file I/O.
 * The struct is public so callers may inspect and, for reproducible tests,
 * override the key material after mesh_mgr_create_network().  DevKeys live only
 * inside the roster and are never logged; every function returns 0 on success
 * and -1 on failure (pointer-returning lookups return NULL) unless noted.
 */

#ifndef _MESH_MANAGER_H_
#define _MESH_MANAGER_H_

#include <stddef.h>
#include <stdint.h>

#include "mesh_provision.h"	/* struct mesh_prov_data */
#include "mesh_cfg_model.h"	/* struct mesh_cfg_model_id / status codecs */
#include "mesh_cfg_v11.h"	/* Mesh 1.1 config codecs (SAR, private, LCD) */
#include "mesh_heartbeat.h"	/* struct mesh_hb_pub / mesh_hb_sub_status */
#include "mesh_transport.h"	/* MESH_ACCESS_MAX */

#define	MESH_MGR_KEY_LEN	16
#define	MESH_MGR_UUID_LEN	16

/* Unicast address range (MshPRT_v1.1 Section 3.4.2): 0x0001..0x7FFF. */
#define	MESH_MGR_UNICAST_MIN	0x0001u
#define	MESH_MGR_UNICAST_MAX	0x7FFFu

/* Conventional Provisioner unicast address (MshPRT Section 4). */
#define	MESH_MGR_PROVISIONER_ADDR	0x0001u

/* Roster capacity.  A network of this many nodes fits without allocation. */
#define	MESH_MGR_MAX_NODES	256

/* ================================================================
 * Provisioned-node roster entry (MshPRT_v1.1 Section 4).
 * ================================================================ */
struct mesh_mgr_node {
	uint8_t		uuid[MESH_MGR_UUID_LEN];	/* device UUID */
	uint16_t	addr;		/* primary element unicast address */
	uint8_t		num_elements;	/* consumes addr..addr+num_elements-1 */
	uint8_t		devkey[MESH_MGR_KEY_LEN];	/* per-node device key */
	uint64_t	prov_time;	/* caller-supplied provisioned timestamp */

	/*
	 * Discovered Composition Data Page 0 (MshMDL Section 4.4.1.2.1): the
	 * node's CID/PID/VID/CRPL/features and per-element SIG & vendor model
	 * lists, learned from a Config Composition Data Status.  have_comp is
	 * 0 until a Status has been applied; runtime-only (re-fetchable, not
	 * persisted).
	 */
	int				have_comp;
	struct mesh_cfg_comp_page0	comp;

	/*
	 * Per-node Key Refresh distribution state (MshPRT_v1.1 Section 3.11.4).
	 * A network-wide refresh marks every roster node DISTRIBUTING; a node's
	 * NetKey Update Status moves it to ACKED.  A node still DISTRIBUTING when
	 * the operator advances the phase has MISSED the refresh (its address is
	 * how the operator sees the node that will be partitioned/evicted).
	 */
	uint8_t				kr_state;
};

/* mesh_mgr_node.kr_state values. */
#define	MESH_MGR_KR_IDLE		0
#define	MESH_MGR_KR_DISTRIBUTING	1	/* NetKey Update sent, no Status yet */
#define	MESH_MGR_KR_ACKED		2	/* NetKey Update Status received */

/* ================================================================
 * The manager: one mesh network's security material, address pool and
 * node roster.
 * ================================================================ */
struct mesh_mgr {
	/* Primary subnet and application key (MshPRT Section 3.8). */
	uint8_t		netkey[MESH_MGR_KEY_LEN];
	uint16_t	netkey_index;	/* 12-bit NetKey Index, 0 for the primary */
	uint8_t		appkey[MESH_MGR_KEY_LEN];
	/*
	 * Staged Key Refresh Phase-1 AppKey: the NEW application key distributed
	 * by Config AppKey Update (MshPRT_v1.1 Section 3.11.4).  Distinct from the
	 * current appkey so an AppKey Update never re-sends the in-use key (which
	 * conformant nodes reject with Cannot Update).  Minted at create-network
	 * time and persisted.
	 */
	uint8_t		appkey_new[MESH_MGR_KEY_LEN];
	uint16_t	appkey_index;	/* 12-bit AppKey Index */
	uint32_t	iv_index;
	uint8_t		flags;		/* provisioning data Flags (KR | IV Update) */

	/* The Provisioner's own node (MshPRT Section 4). */
	uint16_t	self_addr;
	uint8_t		self_elements;
	uint8_t		self_devkey[MESH_MGR_KEY_LEN];

	/* Outbound access-message sequence number for Config Client messages. */
	uint32_t	seq;

	/*
	 * Address allocator high-water mark: the lowest unicast address not yet
	 * handed out.  Monotonic, so allocations never collide with a prior one
	 * or with the Provisioner's own element block.
	 */
	uint16_t	next_unicast;

	/* An address reserved by mesh_mgr_provision_prepare() awaiting commit. */
	struct {
		int		active;
		uint8_t		uuid[MESH_MGR_UUID_LEN];
		uint16_t	addr;
		uint8_t		num_elements;
	}		pending;

	struct mesh_mgr_node	nodes[MESH_MGR_MAX_NODES];
	size_t			n_nodes;
};

/* ================================================================
 * MPROV1 - create a network.  MshPRT_v1.1 Section 3.7.3 / Section 4.
 * ================================================================ */

/*
 * Mint a fresh mesh network: generate a random primary NetKey and AppKey, set
 * the IV Index and both key indexes to 0, and establish the Provisioner's own
 * node at unicast 0x0001 (one element) with a random DevKey.  The roster starts
 * empty and the allocator starts just past the Provisioner's element block.
 * out_netkey / out_appkey, if non-NULL, receive copies of the minted keys.
 * Returns 0, -1 on a NULL manager or an RNG failure.
 */
int	mesh_mgr_create_network(struct mesh_mgr *mgr, uint8_t out_netkey[16],
	    uint8_t out_appkey[16]);

/*
 * Override the Provisioner's own node layout before any address is allocated
 * (the default is 0x0001 / 1 element).  addr must be unicast and num_elements
 * >= 1; the allocator's high-water mark is moved to just past the block.  Fails
 * if devices have already been allocated addresses.  Returns 0, -1 on error.
 */
int	mesh_mgr_set_self(struct mesh_mgr *mgr, uint16_t addr,
	    uint8_t num_elements, const uint8_t devkey[16]);

/* ================================================================
 * MPROV2 - unicast address allocator.  MshPRT_v1.1 Section 3.4.2.
 * ================================================================ */

/*
 * Allocate the next free unicast address block for a device with num_elements
 * elements (>= 1), advancing the allocator so the next call is collision-free.
 * The device occupies out_addr .. out_addr+num_elements-1.  Returns 0 and
 * *out_addr on success, -1 if num_elements is 0 or the block would exceed
 * 0x7FFF (address space exhausted).
 */
int	mesh_mgr_alloc_unicast(struct mesh_mgr *mgr, uint8_t num_elements,
	    uint16_t *out_addr);

/* ================================================================
 * MPROV3 - node roster and DevKey store.  MshPRT_v1.1 Section 4.
 * ================================================================ */

/*
 * Record a provisioned node.  addr must be unicast, num_elements >= 1, and the
 * block addr..addr+num_elements-1 must not overlap the Provisioner or any
 * existing node.  The allocator's high-water mark is advanced past the block so
 * a later mesh_mgr_alloc_unicast() cannot collide with a manually added node
 * (e.g. one restored from persistence).  Returns the stored entry, or NULL on a
 * bad argument, an overlap, or a full roster.
 */
struct mesh_mgr_node *mesh_mgr_add_node(struct mesh_mgr *mgr,
	    const uint8_t uuid[16], uint16_t addr, uint8_t num_elements,
	    const uint8_t devkey[16], uint64_t prov_time);

/* Look up a node by any address within its element block, or by device UUID. */
struct mesh_mgr_node *mesh_mgr_find_by_addr(struct mesh_mgr *mgr, uint16_t addr);
struct mesh_mgr_node *mesh_mgr_find_by_uuid(struct mesh_mgr *mgr,
	    const uint8_t uuid[16]);

/*
 * Remove the node whose primary address is addr (not merely an interior
 * element address).  Returns 0, -1 if no such node.  The freed address block is
 * not reused (the allocator stays monotonic).
 */
int	mesh_mgr_remove_node(struct mesh_mgr *mgr, uint16_t addr);

/* Roster iteration. */
size_t	mesh_mgr_node_count(const struct mesh_mgr *mgr);
const struct mesh_mgr_node *mesh_mgr_node_at(const struct mesh_mgr *mgr,
	    size_t i);

/*
 * Persist / restore the manager (network keys, Provisioner node, allocator
 * state and the full roster including DevKeys) as a single versioned,
 * CRC-checked frame.  The file holds secret key material and is written 0600;
 * integrity - not confidentiality - is provided by the CRC, so callers that
 * require at-rest encryption must layer it.  Load rejects a missing, truncated,
 * wrong-magic, unknown-version or CRC-mismatched file, leaving *mgr untouched.
 * Both return 0 on success, -1 on failure.
 */
int	mesh_mgr_save(const struct mesh_mgr *mgr, const char *path);
int	mesh_mgr_load(struct mesh_mgr *mgr, const char *path);

/* ================================================================
 * MPROV3 - provisioning integration seam.
 *
 * Bridges the provisioning protocol (mesh_provisioner.[ch], driven by the
 * meshd Provisioner role) to the manager: the manager fills in the provisioning
 * data handed to the device and records the result once the DevKey is derived.
 * ================================================================ */

/*
 * Reserve an address for a device about to be provisioned and fill the
 * provisioning data to hand it: the primary NetKey, netkey_index, flags, IV
 * Index and the freshly allocated unicast address.  uuid must not already be in
 * the roster and num_elements must be >= 1.  Records the reservation as pending
 * (only one at a time).  Returns 0 and *out_data on success, -1 on error.
 */
int	mesh_mgr_provision_prepare(struct mesh_mgr *mgr, const uint8_t uuid[16],
	    uint8_t num_elements, struct mesh_prov_data *out_data);

/*
 * Commit the pending provisioning once the protocol has derived devkey:
 * records {UUID, reserved address, element count, DevKey, prov_time} into the
 * roster and clears the pending reservation.  Returns the roster entry, or NULL
 * if nothing is pending or the roster is full.
 */
struct mesh_mgr_node *mesh_mgr_provision_commit(struct mesh_mgr *mgr,
	    const uint8_t devkey[16], uint64_t prov_time);

/* Abandon a pending provisioning (the reserved address stays consumed). */
void	mesh_mgr_provision_abort(struct mesh_mgr *mgr);

/* ================================================================
 * MPROV4 - Config Client.  MshMDL_v1.1 Section 4.3.4.
 *
 * Each _pdu() builder emits a plaintext Configuration Access PDU (opcode +
 * parameters) as the CLIENT sends it; mesh_mgr_devkey_seal() encrypts one to a
 * node under its DevKey (AKF=0, 32-bit TransMIC) and mesh_mgr_devkey_open()
 * recovers a reply.  Status replies are parsed by the _status_parse() helpers.
 * ================================================================ */

/*
 * Config AppKey Add (opcode 0x00): bind the manager's primary AppKey to its
 * primary subnet on the target node.  Emits NetKeyIndexAndAppKeyIndex + AppKey.
 */
int	mesh_mgr_cfg_appkey_add_pdu(const struct mesh_mgr *mgr, uint8_t *out,
	    size_t *outlen);

/*
 * Config Model App Bind (opcode 0x803D): bind the manager's primary AppKey to
 * a model on element elem_addr of the target node.
 */
int	mesh_mgr_cfg_model_app_bind_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, const struct mesh_cfg_model_id *model,
	    uint8_t *out, size_t *outlen);

/*
 * Config Model Subscription Add (opcode 0x801B): subscribe a model on
 * elem_addr to the group address sub_addr.
 */
int	mesh_mgr_cfg_model_sub_add_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, uint16_t sub_addr,
	    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen);

/*
 * Config Model Publication Set (opcode 0x03): set a model's publication to
 * pub_addr under the manager's primary AppKey with the given TTL, period and
 * retransmit (packed per MshMDL Section 4.4.1.2).
 */
int	mesh_mgr_cfg_model_pub_set_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, uint16_t pub_addr, uint8_t ttl, uint8_t period,
	    uint8_t retransmit, const struct mesh_cfg_model_id *model,
	    uint8_t *out, size_t *outlen);

/*
 * Encrypt a Configuration Access PDU to node under its DevKey (device nonce,
 * AKF=0, szmic=0) with the manager as source, consuming one sequence number
 * (returned via *out_seq for the peer's decrypt nonce).  Writes the Upper
 * Transport Access PDU (encrypted payload || 32-bit TransMIC).  Returns 0, -1
 * on a NULL argument, an oversize PDU or a crypto failure.
 */
int	mesh_mgr_devkey_seal(struct mesh_mgr *mgr,
	    const struct mesh_mgr_node *node, const uint8_t *access,
	    size_t access_len, uint32_t *out_seq, uint8_t *out_upper,
	    size_t *out_upper_len);

/*
 * Recover a DevKey-encrypted Configuration Access PDU from node - typically a
 * Status reply, sealed by the node with (seq, src=node, dst=self).  Returns 0
 * and the plaintext Access PDU, -1 on a MIC failure or a bad argument.
 */
int	mesh_mgr_devkey_open(const struct mesh_mgr *mgr,
	    const struct mesh_mgr_node *node, uint32_t seq, uint16_t src,
	    uint16_t dst, const uint8_t *upper, size_t upper_len, uint8_t *access,
	    size_t *access_len);

/*
 * Parse Config AppKey Status (0x8003) / Model App Status (0x803E) replies from
 * a recovered Access PDU.  Thin Config-Client wrappers over the mesh_cfg_*
 * status codecs.  Return 0 and the fields, -1 on a malformed or wrong-opcode
 * PDU.
 */
int	mesh_mgr_cfg_appkey_status_parse(const uint8_t *access, size_t len,
	    uint8_t *status, uint16_t *net_idx, uint16_t *app_idx);
int	mesh_mgr_cfg_model_app_status_parse(const uint8_t *access, size_t len,
	    uint8_t *status, struct mesh_cfg_model_app *out);

/* ================================================================
 * Config Client - node discovery (Composition Data).  MshMDL Section
 * 4.3.2.4 / 4.4.1.2.1.
 * ================================================================ */

/*
 * Config Composition Data Get (opcode 0x8008): request one page (page 0 is the
 * element/model layout).  Emits opcode + Page.
 */
int	mesh_mgr_cfg_comp_get_pdu(const struct mesh_mgr *mgr, uint8_t page,
	    uint8_t *out, size_t *outlen);

/*
 * Apply a Config Composition Data Status (opcode 0x02) to a roster node: parse
 * the Status, decode Page 0 and store the discovered CID/PID/VID/CRPL/features
 * and per-element model lists in node->comp (setting node->have_comp) so later
 * configuration targets the node's real model identifiers.  Only page 0 is
 * decoded; a non-zero page is length-gated and stored raw is not attempted -
 * the function reports -1.  Returns 0 on success, -1 on a malformed, wrong-
 * opcode or non-page-0 Status.
 */
int	mesh_mgr_cfg_comp_status_apply(struct mesh_mgr_node *node,
	    const uint8_t *access, size_t len);

/* ================================================================
 * Config Client - key management.  MshMDL Section 4.3.2.
 * ================================================================ */

/*
 * Config NetKey Add (opcode 0x8040): add a subnet key net_idx / key[16] to the
 * node.  Config NetKey Status (0x8044) is parsed by _netkey_status_parse.
 */
int	mesh_mgr_cfg_netkey_add_pdu(const struct mesh_mgr *mgr, uint16_t net_idx,
	    const uint8_t key[16], uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_netkey_status_parse(const uint8_t *access, size_t len,
	    uint8_t *status, uint16_t *net_idx);

/*
 * Config NetKey Update (opcode 0x8045): distribute a new NetKey for subnet
 * net_idx, driving the target node into Key Refresh Phase 1 (MshPRT_v1.1
 * Section 3.11.4).  Config NetKey Delete (opcode 0x8041): remove subnet net_idx
 * (and, during a refresh targeting the old index, abandon it).  Both are
 * answered by a Config NetKey Status (0x8044), parsed by _netkey_status_parse.
 */
int	mesh_mgr_cfg_netkey_update_pdu(const struct mesh_mgr *mgr,
	    uint16_t net_idx, const uint8_t key[16], uint8_t *out,
	    size_t *outlen);
int	mesh_mgr_cfg_netkey_delete_pdu(const struct mesh_mgr *mgr,
	    uint16_t net_idx, uint8_t *out, size_t *outlen);

/*
 * Config Key Refresh Phase Get (0x8015) / Set (0x8016): read or advance the
 * refresh phase of subnet net_idx.  transition is MESH_CFG_KR_TRANSITION_2
 * (Phase 1 -> 2, start using the new key) or MESH_CFG_KR_TRANSITION_3 (finish:
 * revoke the old key, settle to Phase 0).  Both are answered by a Config Key
 * Refresh Phase Status (0x8017), parsed by _kr_phase_status_parse into the
 * status code, NetKey Index and the resulting phase (MESH_CFG_KR_PHASE_*).
 */
int	mesh_mgr_cfg_kr_phase_get_pdu(const struct mesh_mgr *mgr,
	    uint16_t net_idx, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_kr_phase_set_pdu(const struct mesh_mgr *mgr,
	    uint16_t net_idx, uint8_t transition, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_kr_phase_status_parse(const uint8_t *access, size_t len,
	    uint8_t *status, uint16_t *net_idx, uint8_t *phase);

/*
 * Network-wide Key Refresh orchestration state (MshPRT_v1.1 Section 3.11.4).
 * mesh_mgr_kr_begin marks every roster node DISTRIBUTING (the operator then
 * sends each a NetKey Update).  mesh_mgr_kr_ack records a node's NetKey Update
 * Status, moving it to ACKED (returns 0, -1 if no such node).  mesh_mgr_kr_pending
 * counts nodes still DISTRIBUTING - the nodes that have not acknowledged the new
 * key and would be partitioned if the phase is advanced (the eviction signal).
 */
void	mesh_mgr_kr_begin(struct mesh_mgr *mgr);
int	mesh_mgr_kr_ack(struct mesh_mgr *mgr, uint16_t addr);
size_t	mesh_mgr_kr_pending(const struct mesh_mgr *mgr);

/*
 * Config AppKey Update (opcode 0x01) / AppKey Delete (opcode 0x8000) for the
 * manager's primary AppKey on its primary subnet.  AppKey Update distributes
 * the manager's staged Phase-1 AppKey (mgr->appkey_new) - a NEW key, never the
 * in-use one (MshPRT_v1.1 Section 3.11.4).  Both are answered by a Config
 * AppKey Status (0x8003), parsed by _cfg_appkey_status_parse above.
 */
int	mesh_mgr_cfg_appkey_update_pdu(const struct mesh_mgr *mgr, uint8_t *out,
	    size_t *outlen);
int	mesh_mgr_cfg_appkey_delete_pdu(const struct mesh_mgr *mgr, uint8_t *out,
	    size_t *outlen);

/*
 * Config AppKey Get (opcode 0x8001): list the AppKey indexes bound to net_idx.
 * Config AppKey List (0x8002) is parsed by _appkey_list_parse into up to max
 * indexes (*n set to the count).
 */
int	mesh_mgr_cfg_appkey_get_pdu(const struct mesh_mgr *mgr, uint16_t net_idx,
	    uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_appkey_list_parse(const uint8_t *access, size_t len,
	    uint8_t *status, uint16_t *net_idx, uint16_t *app_idx, size_t max,
	    size_t *n);

/* ================================================================
 * Config Client - node-wide state.  MshMDL Section 4.3.2.
 *
 * Beacon (0x8009/0x800A/0x800B), Default TTL (0x800C/0x800D/0x800E), GATT Proxy
 * (0x8012/0x8013/0x8014) and Friend (0x800F/0x8010/0x8011) all carry a single
 * state octet.  get_opcode / set_opcode name the message (see MESH_CFG_OP_*);
 * the shared Status is a single octet parsed by _u8_state_status_parse.
 * ================================================================ */
int	mesh_mgr_cfg_u8_state_get_pdu(const struct mesh_mgr *mgr,
	    uint32_t get_opcode, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_u8_state_set_pdu(const struct mesh_mgr *mgr,
	    uint32_t set_opcode, uint8_t value, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_u8_state_status_parse(const uint8_t *access, size_t len,
	    uint32_t *opcode, uint8_t *value);

/*
 * Config Relay Get (0x8026) / Set (0x8027) / Status (0x8028).  The Status
 * carries Relay (1) + RelayRetransmit (1), no status code.
 */
int	mesh_mgr_cfg_relay_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
	    size_t *outlen);
int	mesh_mgr_cfg_relay_set_pdu(const struct mesh_mgr *mgr, uint8_t relay,
	    uint8_t retransmit, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_relay_status_parse(const uint8_t *access, size_t len,
	    uint8_t *relay, uint8_t *retransmit);

/*
 * Config Network Transmit Get (0x8023) / Set (0x8024) / Status (0x8025).  count
 * is the 3-bit NetworkTransmitCount, interval_steps the 5-bit
 * NetworkTransmitIntervalSteps (transmit interval = (steps+1)*10 ms).
 */
int	mesh_mgr_cfg_net_transmit_get_pdu(const struct mesh_mgr *mgr,
	    uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_net_transmit_set_pdu(const struct mesh_mgr *mgr,
	    uint8_t count, uint8_t interval_steps, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_net_transmit_status_parse(const uint8_t *access, size_t len,
	    uint8_t *count, uint8_t *interval_steps);

/* ================================================================
 * Config Client - binding / subscription removal + Node Reset.  MshMDL
 * Section 4.3.2.
 * ================================================================ */

/* Config Model App Unbind (opcode 0x803F): unbind the primary AppKey. */
int	mesh_mgr_cfg_model_app_unbind_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, const struct mesh_cfg_model_id *model,
	    uint8_t *out, size_t *outlen);

/*
 * Config Model Subscription Delete (0x801C) / Overwrite (0x801E): a model on
 * elem_addr and the group address sub_addr.  Delete All (0x801D) removes every
 * subscription and omits the address.  All are answered by a Config Model
 * Subscription Status (0x801F), parsed by _model_sub_status_parse.
 */
int	mesh_mgr_cfg_model_sub_delete_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, uint16_t sub_addr,
	    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_model_sub_overwrite_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, uint16_t sub_addr,
	    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_model_sub_delete_all_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, const struct mesh_cfg_model_id *model,
	    uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_model_sub_status_parse(const uint8_t *access, size_t len,
	    uint8_t *status, struct mesh_cfg_model_sub *out);

/*
 * Config Node Reset (opcode 0x8049): remove the node from the network.  Node
 * Reset Status (0x804A) carries no parameters; _node_reset_status_parse just
 * validates the opcode.
 */
int	mesh_mgr_cfg_node_reset_pdu(const struct mesh_mgr *mgr, uint8_t *out,
	    size_t *outlen);
int	mesh_mgr_cfg_node_reset_status_parse(const uint8_t *access, size_t len);

/* ================================================================
 * Config Client - virtual-address publication / subscription.  MshMDL
 * Section 4.4.1.2.  A virtual address (0x8000..0xBFFF) is the 14-bit hash
 * of a 16-octet Label UUID (MshPRT_v1.1 Section 3.4.2.3); the node stores
 * the full Label UUID and derives the same address, so group messaging by
 * Label UUID needs only the label on the wire, not the derived address.
 * ================================================================ */

/*
 * Derive the virtual address a Label UUID maps to (0x8000 | 14-bit hash).
 * Thin wrapper over mesh_virtual_addr() so a manager can predict the address
 * a node will subscribe to.  Returns 0 and *va, -1 on a NULL argument or a
 * crypto failure.
 */
int	mesh_mgr_label_to_virtual_addr(const uint8_t label[16], uint16_t *va);

/*
 * Config Model Publication Virtual Address Set (opcode 0x801A): set a model's
 * publication to the virtual address of label[16] under the manager's primary
 * AppKey with the given TTL, period and retransmit (packed per MshMDL Section
 * 4.4.1.2).  Answered by a Config Model Publication Status (0x8019).
 */
int	mesh_mgr_cfg_model_pub_va_set_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, const uint8_t label[16], uint8_t ttl,
	    uint8_t period, uint8_t retransmit,
	    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen);

/*
 * Config Model Subscription Virtual Address Add (0x8020) / Delete (0x8021) /
 * Overwrite (0x8022): a model on elem_addr and the group identified by
 * label[16].  All are answered by a Config Model Subscription Status (0x801F),
 * parsed by _model_sub_status_parse (the Status echoes the derived virtual
 * address, not the Label UUID).
 */
int	mesh_mgr_cfg_model_sub_va_add_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, const uint8_t label[16],
	    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_model_sub_va_delete_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, const uint8_t label[16],
	    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_model_sub_va_overwrite_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, const uint8_t label[16],
	    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen);

/*
 * Config Model Publication Get (opcode 0x8018): read a model's publication.
 * Config Model Publication Status (0x8019) is parsed by _model_pub_status_parse
 * into the status code and the full publication parameters.
 */
int	mesh_mgr_cfg_model_pub_get_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, const struct mesh_cfg_model_id *model,
	    uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_model_pub_status_parse(const uint8_t *access, size_t len,
	    uint8_t *status, struct mesh_cfg_model_pub *out);

/*
 * Config SIG Model Subscription Get (0x8029) / Vendor Model Subscription Get
 * (0x802B): list a model's subscription addresses.  The matching List (0x802A /
 * 0x802C) is parsed by _model_sub_list_parse into up to max group addresses.
 */
int	mesh_mgr_cfg_model_sub_get_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, const struct mesh_cfg_model_id *model,
	    uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_model_sub_list_parse(const uint8_t *access, size_t len,
	    uint8_t *status, uint16_t *elem_addr, struct mesh_cfg_model_id *model,
	    uint16_t *addrs, size_t max, size_t *n);

/*
 * Config SIG Model App Get (0x804B) / Vendor Model App Get (0x804D): list the
 * AppKey indexes bound to a model.  The matching List (0x804C / 0x804E) is
 * parsed by _model_app_list_parse into up to max AppKey indexes.
 */
int	mesh_mgr_cfg_model_app_get_pdu(const struct mesh_mgr *mgr,
	    uint16_t elem_addr, const struct mesh_cfg_model_id *model,
	    uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_model_app_list_parse(const uint8_t *access, size_t len,
	    uint8_t *status, uint16_t *elem_addr, struct mesh_cfg_model_id *model,
	    uint16_t *app_idx, size_t max, size_t *n);

/* ================================================================
 * Config Client - Node Identity and Low Power Node PollTimeout.  MshMDL
 * Section 4.4.1.2.
 * ================================================================ */

/*
 * Config Node Identity Get (0x8046) / Set (0x8047) for subnet net_idx: read or
 * set whether the node advertises with Node Identity for that subnet (identity
 * is MESH_CFG_NODE_IDENTITY_STOPPED/RUNNING).  Both are answered by a Config
 * Node Identity Status (0x8048), parsed by _node_identity_status_parse into the
 * status code, NetKey Index and resulting identity state.
 */
int	mesh_mgr_cfg_node_identity_get_pdu(const struct mesh_mgr *mgr,
	    uint16_t net_idx, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_node_identity_set_pdu(const struct mesh_mgr *mgr,
	    uint16_t net_idx, uint8_t identity, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_node_identity_status_parse(const uint8_t *access, size_t len,
	    uint8_t *status, uint16_t *net_idx, uint8_t *identity);

/*
 * Config Low Power Node PollTimeout Get (0x802D): query the PollTimeout the
 * node (a Friend) holds for the Low Power Node lpn_addr.  The Status (0x802E)
 * is parsed by _lpn_polltimeout_status_parse into the LPN address and the
 * 24-bit PollTimeout (units of 100 ms; 0 means the node is not a Friend of it).
 */
int	mesh_mgr_cfg_lpn_polltimeout_get_pdu(const struct mesh_mgr *mgr,
	    uint16_t lpn_addr, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_lpn_polltimeout_status_parse(const uint8_t *access,
	    size_t len, uint16_t *lpn_addr, uint32_t *poll_timeout);

/* ================================================================
 * Config Client - Heartbeat publication / subscription.  MshMDL Section
 * 4.4.1.2.15..19.  The publication is the Heartbeat a node emits; the
 * subscription is what it counts.  The Status parsers report the full
 * configuration into a caller-owned struct.
 * ================================================================ */

/*
 * Config Heartbeat Publication Get (0x8038): read the node's Heartbeat
 * publication.  Set (0x8039): configure it (dst 0 disables).  Both are answered
 * by a Config Heartbeat Publication Status (0x06), parsed by _hb_pub_status_parse.
 */
int	mesh_mgr_cfg_hb_pub_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
	    size_t *outlen);
int	mesh_mgr_cfg_hb_pub_set_pdu(const struct mesh_mgr *mgr,
	    const struct mesh_hb_pub *pub, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_hb_pub_status_parse(const uint8_t *access, size_t len,
	    uint8_t *status, struct mesh_hb_pub *out);

/*
 * Config Heartbeat Subscription Get (0x803A): read the node's Heartbeat
 * subscription.  Set (0x803B): configure it (src or dst 0 disables).  Both are
 * answered by a Config Heartbeat Subscription Status (0x803C), parsed by
 * _hb_sub_status_parse.
 */
int	mesh_mgr_cfg_hb_sub_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
	    size_t *outlen);
int	mesh_mgr_cfg_hb_sub_set_pdu(const struct mesh_mgr *mgr, uint16_t src,
	    uint16_t dst, uint8_t period_log, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_hb_sub_status_parse(const uint8_t *access, size_t len,
	    struct mesh_hb_sub_status *out);

/* ================================================================
 * Config Client - Mesh Protocol 1.1 node states.  MshMDL Section 4 (the
 * foundation models added in Mesh 1.1).  These reuse the mesh_cfg_v11 codecs
 * from the client direction; all are DevKey-sealed and correlated via the txn
 * state machine like the core Configuration messages.
 * ================================================================ */

/*
 * SAR Transmitter Get (0x806C) / Set (0x806D) and SAR Receiver Get (0x806F) /
 * Set (0x8070): read or configure the node's segmentation-and-reassembly
 * parameters (MshPRT_v1.1 Sections 4.2.29 / 4.2.30).  The Set carries the
 * packed state; both are answered by the matching Status (0x806E / 0x8071),
 * parsed by _sar_tx_status_parse / _sar_rx_status_parse.
 */
int	mesh_mgr_cfg_sar_tx_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
	    size_t *outlen);
int	mesh_mgr_cfg_sar_tx_set_pdu(const struct mesh_mgr *mgr,
	    const struct mesh_cfg_sar_transmitter *in, uint8_t *out,
	    size_t *outlen);
int	mesh_mgr_cfg_sar_tx_status_parse(const uint8_t *access, size_t len,
	    struct mesh_cfg_sar_transmitter *out);
int	mesh_mgr_cfg_sar_rx_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
	    size_t *outlen);
int	mesh_mgr_cfg_sar_rx_set_pdu(const struct mesh_mgr *mgr,
	    const struct mesh_cfg_sar_receiver *in, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_sar_rx_status_parse(const uint8_t *access, size_t len,
	    struct mesh_cfg_sar_receiver *out);

/*
 * On-Demand Private Proxy Get (0x8069) / Set (0x806A): read or set the node's
 * On-Demand Private GATT Proxy state octet.  Answered by a Status (0x806B),
 * parsed by _od_priv_proxy_status_parse.
 */
int	mesh_mgr_cfg_od_priv_proxy_get_pdu(const struct mesh_mgr *mgr,
	    uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_od_priv_proxy_set_pdu(const struct mesh_mgr *mgr,
	    uint8_t value, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_od_priv_proxy_status_parse(const uint8_t *access, size_t len,
	    uint8_t *value);

/*
 * Private Beacon Get (0x8060) / Set (0x8061): read or set the node's Private
 * Beacon state and (Set) an optional Random Update Interval Steps.  Answered by
 * a Status (0x8062), parsed by _priv_beacon_status_parse.
 */
int	mesh_mgr_cfg_priv_beacon_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
	    size_t *outlen);
int	mesh_mgr_cfg_priv_beacon_set_pdu(const struct mesh_mgr *mgr,
	    const struct mesh_cfg_priv_beacon *in, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_priv_beacon_status_parse(const uint8_t *access, size_t len,
	    struct mesh_cfg_priv_beacon *out);

/*
 * Private GATT Proxy Get (0x8063) / Set (0x8064): read or set the node's
 * Private GATT Proxy state octet.  Answered by a Status (0x8065), parsed by
 * _priv_gatt_proxy_status_parse.
 */
int	mesh_mgr_cfg_priv_gatt_proxy_get_pdu(const struct mesh_mgr *mgr,
	    uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_priv_gatt_proxy_set_pdu(const struct mesh_mgr *mgr,
	    uint8_t value, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_priv_gatt_proxy_status_parse(const uint8_t *access,
	    size_t len, uint8_t *value);

/*
 * Private Node Identity Get (0x8066) / Set (0x8067) for subnet net_idx: read or
 * set the node's Private Node Identity state.  Answered by a Status (0x8068),
 * parsed by _priv_node_identity_status_parse.
 */
int	mesh_mgr_cfg_priv_node_identity_get_pdu(const struct mesh_mgr *mgr,
	    uint16_t net_idx, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_priv_node_identity_set_pdu(const struct mesh_mgr *mgr,
	    uint16_t net_idx, uint8_t identity, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_priv_node_identity_status_parse(const uint8_t *access,
	    size_t len, uint8_t *status, struct mesh_cfg_priv_node_identity *out);

/*
 * Large Composition Data Get (0x8074): request a slice of a Composition Data
 * page at Offset (for pages that do not fit a single Configuration message).
 * The Status (0x8075) is parsed by _lcd_status_parse into the page, offset,
 * total size and the returned data slice.
 */
int	mesh_mgr_cfg_lcd_get_pdu(const struct mesh_mgr *mgr, uint8_t page,
	    uint16_t offset, uint8_t *out, size_t *outlen);
int	mesh_mgr_cfg_lcd_status_parse(const uint8_t *access, size_t len,
	    struct mesh_cfg_lcd_status *out);

/* ================================================================
 * Config Client transaction: request -> Status correlation with bounded
 * retransmission over a lossy bearer (MshPRT_v1.1 Section 3.7.3 - acknowledged
 * Configuration messages are retransmitted until the matching Status arrives).
 *
 * The caller drives a mock/real clock: mesh_mgr_txn_begin() seals a request and
 * emits the first transmission; mesh_mgr_txn_rx() feeds a received PDU and
 * completes the transaction when a Status with the expected opcode decrypts;
 * mesh_mgr_txn_tick() advances time, retransmitting when the retry interval
 * elapses and declaring MESH_MGR_TXN_TIMEOUT once the attempt budget is spent.
 * ================================================================ */
enum mesh_mgr_txn_state {
	MESH_MGR_TXN_IDLE = 0,	/* not started / cleared */
	MESH_MGR_TXN_WAITING,	/* request(s) sent, awaiting Status */
	MESH_MGR_TXN_COMPLETE,	/* matching Status received (status[] valid) */
	MESH_MGR_TXN_TIMEOUT	/* attempt budget exhausted without a Status */
};

struct mesh_mgr_txn {
	enum mesh_mgr_txn_state	state;
	uint32_t		expect_opcode;	/* Status opcode we correlate on */
	uint16_t		node_addr;	/* target node primary address */
	uint32_t		last_seq;	/* seq of the most recent seal */
	uint64_t		deadline;	/* retransmit when now >= deadline */
	uint64_t		interval;	/* retransmit interval (clock units) */
	unsigned		attempts;	/* transmissions made (>= 1) */
	unsigned		max_attempts;	/* bounded budget (>= 1) */
	uint8_t			req[MESH_ACCESS_MAX];	/* the request Access PDU */
	size_t			req_len;
	uint8_t			status[MESH_ACCESS_MAX];/* Status Access PDU on done */
	size_t			status_len;
};

/*
 * Begin a transaction: record req (expecting a Status with expect_opcode),
 * seal it to node under its DevKey and emit the first transmission into
 * out_upper, arm the retry timer at now+interval and set state WAITING.
 * max_attempts (>= 1) bounds the total transmissions.  Returns 0 and *out_seq
 * (the seq the peer needs to open this transmission), -1 on a bad argument or
 * a seal failure.
 */
int	mesh_mgr_txn_begin(struct mesh_mgr *mgr, struct mesh_mgr_txn *t,
	    const struct mesh_mgr_node *node, const uint8_t *req, size_t req_len,
	    uint32_t expect_opcode, uint64_t now, uint64_t interval,
	    unsigned max_attempts, uint8_t *out_upper, size_t *out_upper_len,
	    uint32_t *out_seq);

/*
 * Feed a received upper-transport PDU (a candidate Status sealed by the node
 * with (seq, src, dst)).  When the PDU decrypts under the node's DevKey and its
 * opcode equals expect_opcode, copies the recovered Status into t->status, sets
 * state COMPLETE and returns 1.  Returns 0 when the PDU is ignored (transaction
 * not waiting, MIC failure, or a non-matching opcode) and -1 on a bad argument.
 * A PDU arriving after completion is ignored (no double-apply).
 */
int	mesh_mgr_txn_rx(struct mesh_mgr_txn *t, const struct mesh_mgr *mgr,
	    const struct mesh_mgr_node *node, uint32_t seq, uint16_t src,
	    uint16_t dst, const uint8_t *upper, size_t upper_len);

/*
 * Advance the clock to now.  While WAITING and now >= deadline: if the attempt
 * budget remains, re-seal the request (a fresh seq), emit it into out_upper,
 * bump attempts and re-arm the timer, returning 1 and *out_seq; if the budget
 * is spent, set state TIMEOUT and return 0.  Returns 0 with no emission when
 * nothing is due or the transaction is already terminal, -1 on a bad argument.
 */
int	mesh_mgr_txn_tick(struct mesh_mgr *mgr, struct mesh_mgr_txn *t,
	    const struct mesh_mgr_node *node, uint64_t now, uint8_t *out_upper,
	    size_t *out_upper_len, uint32_t *out_seq);

#endif /* _MESH_MANAGER_H_ */
