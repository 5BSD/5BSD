/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Per-stream state machine for LE Isochronous (ISO) channels: CIS (central
 * and peripheral) and BIS (broadcaster source, synchronized sink).
 *
 * The ISO HCI encoders (hci_misc.c) and the LE-meta decoders (blued_event.c)
 * carry the on-wire protocol; this layer adds the live-session bookkeeping
 * that lets an application SET UP and TEAR DOWN a stream and receive its
 * data-path socket fd.  Every create command completes asynchronously via an
 * LE-meta event (CIS Established / Create BIG Complete / BIG Sync Established),
 * so a verb issues the HCI command and returns "creating"; the matching event
 * finds the pending stream by connection handle and advances it, sets up the
 * ISO data path, and readies the fd handout.  This mirrors the daemon's
 * CONNECT -> EVENT CONNECTED discipline for ACL links.
 * This is transport support only: it does not implement LE Audio profiles
 * (BAP, PACS, ASCS), codecs, or audio-session policy.
 *
 * ISO state is LIVE-SESSION-ONLY: it is never persisted.  On daemon or
 * controller restart the streams are simply gone, which is correct -- an ISO
 * stream is an inherently ephemeral radio object.
 *
 * Core Spec 6.x Vol 4 Part E (ISO HCI): §7.8.97-.111, events §7.7.65.25-.30.
 */

#ifndef _BLUED_ISO_H_
#define _BLUED_ISO_H_

#include <sys/queue.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "hci_internal.h"	/* struct hci_cis_param */

struct blued_adapter;
struct blued_ctl_client;

/* Up to this many BIS carried by one BIG (spec allows up to 0x1F). */
#define ISO_MAX_BIS	8

/* Role of an ISO stream: selects the create/teardown path and directions. */
enum iso_role {
	ISO_ROLE_CIS_CENTRAL,	/* we run Create CIS */
	ISO_ROLE_CIS_PERIPHERAL,/* we answer CIS Request (accept/reject) */
	ISO_ROLE_BIS_SOURCE,	/* broadcaster: Create BIG */
	ISO_ROLE_BIS_SINK,	/* synchronized receiver: BIG Create Sync */
};

/*
 * Stream lifecycle.  Advanced by verbs (send HCI) and by the async LE-meta
 * events that complete them.  TEARDOWN/FAILED are terminal; the stream is
 * unlinked and freed once its last reference drops.
 */
enum iso_state {
	ISO_ST_IDLE,		/* allocated, nothing sent */
	ISO_ST_CIG_CONFIGURED,	/* Set CIG Params returned handles (CIS) */
	ISO_ST_REQUESTED,	/* peripheral: CIS Request seen, awaiting accept */
	ISO_ST_CREATING,	/* create command sent, awaiting the LE-meta event */
	ISO_ST_ESTABLISHED,	/* establish event, status 0 */
	ISO_ST_PATHS_UP,	/* ISO data path(s) set up for required dir(s) */
	ISO_ST_HANDED_OFF,	/* data-path socket acquired by a client */
	ISO_ST_TEARDOWN,	/* removing paths / disconnecting / removing group */
	ISO_ST_FAILED,		/* terminal error; cleanup done */
};

/*
 * Audio-transport forward hook (P-AUDIO-XPORT).  The ISO data-path setup
 * (§7.8.109) takes a Controller_Delay and a Codec_ID/config; today's transport
 * pins the Transparent coding format with zero delay.  Carrying these through
 * the establishment seam means a future LE-Audio path changes an argument, not
 * the control flow.  A NULL pointer selects the Transparent/zero-delay default.
 */
struct iso_audio_params {
	uint32_t	controller_delay;	/* 3-octet, §7.8.109 */
	uint8_t		codec_id[5];		/* Codec_ID, §7.8.109 */
};

/*
 * One isochronous stream.  A CIS carries a single connection handle; a BIG
 * carries num_bis handles (one fd handout per BIS index).
 */
struct blued_iso_stream {
	enum iso_role		role;
	enum iso_state		state;
	struct blued_adapter	*adapter;

	uint8_t			cig_id;		/* CIS */
	uint8_t			cis_id;		/* CIS, within the CIG */
	uint16_t		cis_handle;	/* CIS connection handle */
	uint16_t		acl_handle;	/* CIS: peer's ACL handle */

	uint8_t			big_handle;	/* BIS */
	uint16_t		sync_handle;	/* BIS sink: periodic-adv sync */
	uint8_t			requested_num_bis;
	uint8_t			num_bis;
	uint16_t		bis_handles[ISO_MAX_BIS];

	bdaddr_t		peer;		/* CIS peer / BIS source addr */
	uint8_t			peer_type;

	/* Retained config for teardown and the audio QoS derivation (§7). */
	uint32_t		sdu_interval_c, sdu_interval_p;
	uint16_t		max_transport_latency_c, max_transport_latency_p;
	uint16_t		max_sdu_c, max_sdu_p;
	uint8_t			phy, framing, packing, rtn, encryption;
	uint8_t			broadcast_code[16];

	int			paths_up;	/* dir bitmap: 1=Input, 2=Output */
	uint32_t		bis_paths_up;	/* one bit per successfully set-up BIS */

	/*
	 * Client that issued the create verb.  When push_on_establish is set
	 * the data-path fd is pushed to it the moment the stream establishes;
	 * otherwise the client pulls it later with ISO_ACQUIRE.  -1 if none.
	 */
	int			requesting_client_fd;
	bool			push_on_establish;

	bool			linked;		/* still in the registry list */
	atomic_int		refcount;
	LIST_ENTRY(blued_iso_stream) entries;
};

/* ---- Central / CIS verbs ---- */

/*
 * Provision a CIG and register a stream per configured CIS (§7.8.97).  Set CIG
 * Parameters is synchronous: the controller returns the per-CIS connection
 * handles in the Command Complete, so this returns them in out_handles and the
 * streams enter CIG_CONFIGURED.  Returns 0 on success, -1 on failure.
 */
int	blued_iso_cig_create(struct blued_adapter *adp, uint8_t cig_id,
	    uint32_t sdu_interval_c, uint32_t sdu_interval_p, uint8_t sca,
	    uint8_t packing, uint8_t framing, uint16_t lat_c, uint16_t lat_p,
	    const struct hci_cis_param *cises, uint8_t cis_count,
	    uint16_t *out_handles, uint8_t *out_count);

/*
 * Create a CIS on a provisioned CIG (§7.8.99).  Resolves the peer's ACL handle
 * via blued_conn_by_peer and issues LE Create CIS (Command Status only); the
 * stream enters CREATING and completes on the LE CIS Established event.
 * Returns 0 ("creating"), -1 on failure (no such CIG/CIS or peer not
 * connected).
 */
int	blued_iso_cis_create(struct blued_adapter *adp, const bdaddr_t *peer,
	    uint8_t peer_type, uint8_t cig_id, uint8_t cis_id,
	    int requesting_client_fd, bool push_on_establish);

/* Remove a CIG once no CIS references it (§7.8.100).  Returns 0/-1. */
int	blued_iso_cig_remove(struct blued_adapter *adp, uint8_t cig_id);

/* ---- Peripheral / CIS verbs ---- */

/* Accept an incoming CIS Request (§7.8.101).  Stream -> CREATING. */
int	blued_iso_cis_accept(struct blued_adapter *adp, uint16_t cis_handle);

/* Reject an incoming CIS Request (§7.8.102) and free the pending stream. */
int	blued_iso_cis_reject(struct blued_adapter *adp, uint16_t cis_handle,
	    uint8_t reason);

/* ---- Broadcaster / BIS source verbs ---- */

/*
 * Create a BIG on a running extended-adv set (§7.8.103).  Stream -> CREATING,
 * completes on the Create BIG Complete event.  Returns 0/-1.
 */
int	blued_iso_big_create(struct blued_adapter *adp, uint8_t big_handle,
	    uint8_t adv_handle, uint8_t num_bis, uint32_t sdu_interval,
	    uint16_t max_sdu, uint16_t max_transport_latency, uint8_t rtn,
	    uint8_t phy, uint8_t packing, uint8_t framing, uint8_t encryption,
	    const uint8_t broadcast_code[16]);

/* Terminate a broadcast BIG (§7.8.105) and free its streams. */
int	blued_iso_big_terminate(struct blued_adapter *adp, uint8_t big_handle,
	    uint8_t reason);

/* ---- Sync / BIS sink verbs ---- */

/*
 * Synchronize to a broadcast BIG given a periodic-adv sync handle (§7.8.106).
 * Stream -> CREATING, completes on the BIG Sync Established event.
 */
int	blued_iso_big_create_sync(struct blued_adapter *adp, uint8_t big_handle,
	    uint16_t sync_handle, const uint8_t *bis_indices, uint8_t num_bis,
	    uint8_t mse, uint16_t big_sync_timeout, uint8_t encryption,
	    const uint8_t broadcast_code[16]);

/* Stop synchronizing to a BIG (§7.8.107) and free its sink streams. */
int	blued_iso_big_terminate_sync(struct blued_adapter *adp,
	    uint8_t big_handle);

/* ---- fd handout ---- */

/*
 * Open the kernel ISO data-path socket for an established stream handle (CIS
 * connection handle or a BIS handle) and return its fd for handout, or -1 if
 * the handle is unknown or not yet established.  The caller hands the fd to a
 * client with blued_ctl_send_fd and then closes this original.  Marks the
 * stream HANDED_OFF on success.
 */
int	blued_iso_acquire_fd(struct blued_adapter *adp, uint16_t handle);

/*
 * Open the data-path socket for the bis_index'th BIS of an established BIG and
 * return its fd for handout, or -1 if unknown / not yet established.  The
 * client addresses a BIS by (big_handle, index) since it never sees the raw
 * per-BIS connection handles.
 */
int	blued_iso_acquire_bis_fd(struct blued_adapter *adp,
	    uint8_t big_handle, uint8_t bis_index);

/* ---- Teardown ---- */

/*
 * Ordered CIS teardown (reverse of setup): remove ISO data paths -> disconnect
 * the CIS -> remove the CIG if this was its last CIS -> free the stream.
 * Returns 0 on success, -1 if the handle is unknown.
 */
int	blued_iso_cis_teardown(struct blued_adapter *adp,
	    uint16_t cis_handle, uint8_t reason);

/*
 * Best-effort teardown sweep for one adapter (controller loss / shutdown):
 * remove paths and remove CIG / terminate BIG(-sync) for every stream on it,
 * then free them.  Never persists anything.
 */
int	blued_iso_sweep_adapter(struct blued_adapter *adp);
void	blued_iso_reset_adapter(struct blued_adapter *adp);

/* Free every registered stream (test teardown / daemon exit). */
void	blued_iso_reset(void);

/* ---- Async event seams (called from blued_event.c) ---- */

/* LE CIS Established (§7.7.65.25).  status 0 -> paths up + fd ready. */
void	iso_on_cis_established(struct blued_adapter *adp, uint16_t cis_handle,
	    uint8_t status);

/* LE CIS Request (§7.7.65.26): register a peripheral stream, emit an event. */
void	iso_on_cis_request(struct blued_adapter *adp, uint16_t acl_handle,
	    uint16_t cis_handle, uint8_t cig_id, uint8_t cis_id);

/* LE Create BIG Complete (§7.7.65.27): per-BIS Input path. */
void	iso_on_big_complete(struct blued_adapter *adp, uint8_t big_handle,
	    uint8_t status, uint8_t num_bis, const uint8_t *bis_handles_le);

/* LE BIG Sync Established (§7.7.65.29): per-BIS Output path. */
void	iso_on_big_sync_established(struct blued_adapter *adp,
	    uint8_t big_handle, uint8_t status, uint8_t num_bis,
	    const uint8_t *bis_handles_le);

/* HCI Disconnection Complete for a CIS handle: peer loss -> ISO_LOST + free. */
void	iso_on_cis_disconnected(struct blued_adapter *adp, uint16_t cis_handle,
	    uint8_t reason);

/* LE BIG Sync Lost (§7.7.65.30): sink loss -> ISO_LOST + free. */
void	iso_on_big_sync_lost(struct blued_adapter *adp, uint8_t big_handle,
	    uint8_t reason);

/* LE Terminate BIG Complete (§7.7.65.28): broadcaster stopped -> free. */
void	iso_on_big_terminated(struct blued_adapter *adp, uint8_t big_handle,
	    uint8_t reason);

/* ---- Test/inspection helpers ---- */

/* Current state of the stream carrying handle, or -1 if none. */
int	blued_iso_stream_state(struct blued_adapter *adp, uint16_t handle);

/* Number of registered streams. */
int	blued_iso_stream_count(void);

#endif /* _BLUED_ISO_H_ */
