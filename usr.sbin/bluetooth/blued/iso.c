/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * LE Isochronous (ISO) per-stream state machine: CIS (central/peripheral) and
 * BIS (broadcaster source / synchronized sink).  See iso.h for the model.
 *
 * Threading: the registry is driven entirely from the main event-loop thread
 * (ctl verbs and HCI events both run there).  The iso_lock and the per-stream
 * refcount still guard the list and object lifetime so a teardown that races an
 * in-flight completion cannot free a stream out from under it.  Lock ordering:
 * conns_lock is only taken (inside blued_conn_by_peer) BEFORE iso_lock is ever
 * acquired -- iso_lock is never held across a conns_lock acquisition -- so the
 * two cannot deadlock.  Control-event fanout (ctl_clients_lock) is likewise
 * only called with iso_lock released.
 *
 * Core Spec 6.x Vol 4 Part E: §7.8.97-.111, events §7.7.65.25-.30.
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "blued.h"
#include "ble_util.h"
#include "conn.h"
#include "ctl.h"
#include "hci_util.h"
#include "hci_internal.h"
#include "iso.h"

/* Default Disconnect reason: Remote User Terminated Connection (§7.1.6). */
#define ISO_TEARDOWN_REASON	0x13
#define ISO_REJECT_REASON	NG_HCI_ERROR_REJECTED_LIMITED_RESOURCES
#define ISO_STATUS_CANCELLED_BY_HOST	0x44

/* Internal ownership bits for HCI ISO input/output data paths (§7.8.109-.110). */
#define ISO_PATH_INPUT_UP	0x01
#define ISO_PATH_OUTPUT_UP	0x02

static LIST_HEAD(, blued_iso_stream) iso_streams =
    LIST_HEAD_INITIALIZER(iso_streams);
static pthread_mutex_t iso_lock = PTHREAD_MUTEX_INITIALIZER;

/* Little-endian 16-bit read over a raw event byte run. */
static uint16_t
iso_le16(const uint8_t *p)
{

	return ((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* ---- refcount + registry primitives ---- */

static struct blued_iso_stream *
iso_alloc(void)
{
	struct blued_iso_stream *s;

	s = calloc(1, sizeof(*s));
	if (s == NULL)
		return (NULL);
	s->requesting_client_fd = -1;
	atomic_init(&s->refcount, 1);	/* the registry's reference */
	pthread_mutex_lock(&iso_lock);
	LIST_INSERT_HEAD(&iso_streams, s, entries);
	s->linked = true;
	pthread_mutex_unlock(&iso_lock);
	return (s);
}

static void
iso_unref(struct blued_iso_stream *s)
{

	if (s == NULL)
		return;
	if (atomic_fetch_sub(&s->refcount, 1) == 1)
		free(s);
}

/*
 * Detach a stream from the registry and drop the registry's reference.  Safe to
 * call more than once: the first call clears s->linked, later calls no-op, so a
 * teardown racing a peer-loss event cannot double-remove or double-free.
 */
static void
iso_unlink(struct blued_iso_stream *s)
{
	bool did = false;

	pthread_mutex_lock(&iso_lock);
	if (s->linked) {
		LIST_REMOVE(s, entries);
		s->linked = false;
		did = true;
	}
	pthread_mutex_unlock(&iso_lock);
	if (did)
		iso_unref(s);		/* release the registry reference */
}

/*
 * Find a linked stream carrying `handle` (a CIS connection handle or any BIS
 * handle) and return it with an extra reference the caller must iso_unref.
 */
static struct blued_iso_stream *
iso_find_by_handle(struct blued_adapter *adp, uint16_t handle)
{
	struct blued_iso_stream *s, *found = NULL;
	uint8_t i;

	pthread_mutex_lock(&iso_lock);
	LIST_FOREACH(s, &iso_streams, entries) {
		if (s->adapter != adp)
			continue;
		if ((s->role == ISO_ROLE_CIS_CENTRAL ||
		    s->role == ISO_ROLE_CIS_PERIPHERAL) &&
		    s->cis_handle == handle) {
			found = s;
			break;
		}
		for (i = 0; i < s->num_bis; i++) {
			if (s->bis_handles[i] == handle) {
				found = s;
				break;
			}
		}
		if (found != NULL)
			break;
	}
	if (found != NULL)
		atomic_fetch_add(&found->refcount, 1);
	pthread_mutex_unlock(&iso_lock);
	return (found);
}

/* Find a CIS stream by (cig_id, cis_id), returned ref'd. */
static struct blued_iso_stream *
iso_find_cis(struct blued_adapter *adp, uint8_t cig_id, uint8_t cis_id)
{
	struct blued_iso_stream *s;

	pthread_mutex_lock(&iso_lock);
	LIST_FOREACH(s, &iso_streams, entries) {
		if (s->adapter == adp && s->role == ISO_ROLE_CIS_CENTRAL &&
		    s->cig_id == cig_id && s->cis_id == cis_id) {
			atomic_fetch_add(&s->refcount, 1);
			pthread_mutex_unlock(&iso_lock);
			return (s);
		}
	}
	pthread_mutex_unlock(&iso_lock);
	return (NULL);
}

/* Find a BIS stream by big_handle, returned ref'd. */
static struct blued_iso_stream *
iso_find_big(struct blued_adapter *adp, uint8_t big_handle)
{
	struct blued_iso_stream *s;

	pthread_mutex_lock(&iso_lock);
	LIST_FOREACH(s, &iso_streams, entries) {
		if (s->adapter == adp &&
		    (s->role == ISO_ROLE_BIS_SOURCE ||
		    s->role == ISO_ROLE_BIS_SINK) &&
		    s->big_handle == big_handle) {
			atomic_fetch_add(&s->refcount, 1);
			pthread_mutex_unlock(&iso_lock);
			return (s);
		}
	}
	pthread_mutex_unlock(&iso_lock);
	return (NULL);
}

/* Count the Central's linked CIS configurations in one locally owned CIG. */
static int
iso_cig_refs(struct blued_adapter *adp, uint8_t cig_id)
{
	struct blued_iso_stream *s;
	int n = 0;

	pthread_mutex_lock(&iso_lock);
	LIST_FOREACH(s, &iso_streams, entries)
		if (s->adapter == adp && s->role == ISO_ROLE_CIS_CENTRAL &&
		    s->cig_id == cig_id)
			n++;
	pthread_mutex_unlock(&iso_lock);
	return (n);
}

/* ---- ISO data path setup / teardown ---- */

/*
 * Stand up the required ISO data path direction(s) for an established stream
 * (§7.8.109) and record which directions came up so teardown can reverse them.
 * The audio hook (NULL here) selects the Transparent/zero-delay default; when
 * LE-Audio lands it supplies a real Controller_Delay + codec without changing
 * this flow.  Returns the number of directions set up.
 */
static int
iso_setup_paths(struct blued_iso_stream *s, enum hci_iso_stream_kind kind,
    const struct iso_audio_params *audio)
{
	uint16_t handle;
	int up, i;

	(void)audio;	/* Transparent/zero-delay default (§7); hook reserved */

	if (kind == HCI_ISO_STREAM_CIS) {
		up = 0;
		if (hci_le_setup_iso_hci_path(s->adapter->hci_fd,
		    s->cis_handle, HCI_ISO_DIR_INPUT) == 0) {
			up++;
			s->paths_up |= ISO_PATH_INPUT_UP;
		}
		if (hci_le_setup_iso_hci_path(s->adapter->hci_fd,
		    s->cis_handle, HCI_ISO_DIR_OUTPUT) == 0) {
			up++;
			s->paths_up |= ISO_PATH_OUTPUT_UP;
		}
		return (up);
	}

	/* BIS: one path per BIS handle; Input for source, Output for sink. */
	up = 0;
	for (i = 0; i < s->num_bis; i++) {
		handle = s->bis_handles[i];
		if (hci_le_setup_iso_hci_path(s->adapter->hci_fd, handle,
		    kind == HCI_ISO_STREAM_BIS_SOURCE ? HCI_ISO_DIR_INPUT :
		    HCI_ISO_DIR_OUTPUT) == 0) {
			up++;
			s->bis_paths_up |= (uint32_t)1 << i;
		}
	}
	if (up > 0)
		s->paths_up = (kind == HCI_ISO_STREAM_BIS_SOURCE) ?
		    ISO_PATH_INPUT_UP : ISO_PATH_OUTPUT_UP;
	return (up);
}

/* Reverse of iso_setup_paths: remove every data path that is up (best effort). */
static void
iso_remove_paths(struct blued_iso_stream *s)
{
	int fd = s->adapter->hci_fd;
	int i;

	if (s->paths_up == 0)
		return;
	if (s->role == ISO_ROLE_CIS_CENTRAL ||
	    s->role == ISO_ROLE_CIS_PERIPHERAL) {
		if ((s->paths_up & ISO_PATH_INPUT_UP) != 0 &&
		    hci_le_remove_iso_data_path(fd, s->cis_handle,
		    HCI_ISO_DIR_INPUT) == 0)
			s->paths_up &= ~ISO_PATH_INPUT_UP;
		if ((s->paths_up & ISO_PATH_OUTPUT_UP) != 0 &&
		    hci_le_remove_iso_data_path(fd, s->cis_handle,
		    HCI_ISO_DIR_OUTPUT) == 0)
			s->paths_up &= ~ISO_PATH_OUTPUT_UP;
	} else {
		uint8_t dir = (s->role == ISO_ROLE_BIS_SOURCE) ?
		    HCI_ISO_DIR_INPUT : HCI_ISO_DIR_OUTPUT;

		for (i = 0; i < s->num_bis; i++) {
			uint32_t bit = (uint32_t)1 << i;

			if ((s->bis_paths_up & bit) != 0 &&
			    hci_le_remove_iso_data_path(fd, s->bis_handles[i],
			    dir) == 0)
				s->bis_paths_up &= ~bit;
		}
		if (s->bis_paths_up == 0)
			s->paths_up = 0;
	}
}

/* POWER teardown variant: retain every failed path bit so the registry remains
 * an honest description of controller ownership until a successful retry or
 * HCI Reset invalidates the controller state. */
static int
iso_remove_paths_checked(struct blued_iso_stream *s)
{
	int fd = s->adapter->hci_fd;
	int failed = 0;

	if (s->paths_up == 0)
		return (0);
	if (s->role == ISO_ROLE_CIS_CENTRAL ||
	    s->role == ISO_ROLE_CIS_PERIPHERAL) {
		if ((s->paths_up & ISO_PATH_INPUT_UP) != 0) {
			if (hci_le_remove_iso_data_path(fd, s->cis_handle,
			    HCI_ISO_DIR_INPUT) < 0)
				failed = 1;
			else
				s->paths_up &= ~ISO_PATH_INPUT_UP;
		}
		if ((s->paths_up & ISO_PATH_OUTPUT_UP) != 0) {
			if (hci_le_remove_iso_data_path(fd, s->cis_handle,
			    HCI_ISO_DIR_OUTPUT) < 0)
				failed = 1;
			else
				s->paths_up &= ~ISO_PATH_OUTPUT_UP;
		}
	} else {
		uint8_t dir = s->role == ISO_ROLE_BIS_SOURCE ?
		    HCI_ISO_DIR_INPUT : HCI_ISO_DIR_OUTPUT;

		for (uint8_t i = 0; i < s->num_bis; i++) {
			uint32_t bit = (uint32_t)1 << i;

			if ((s->bis_paths_up & bit) == 0)
				continue;
			if (hci_le_remove_iso_data_path(fd, s->bis_handles[i], dir) < 0)
				failed = 1;
			else
				s->bis_paths_up &= ~bit;
		}
		if (s->bis_paths_up == 0)
			s->paths_up = 0;
	}
	return (failed ? -1 : 0);
}

/* ---- Central / CIS verbs ---- */

int
blued_iso_cig_create(struct blued_adapter *adp, uint8_t cig_id,
    uint32_t sdu_interval_c, uint32_t sdu_interval_p, uint8_t sca,
    uint8_t packing, uint8_t framing, uint16_t lat_c, uint16_t lat_p,
    const struct hci_cis_param *cises, uint8_t cis_count,
    uint16_t *out_handles, uint8_t *out_count)
{
	struct blued_iso_stream *created[16];
	uint16_t handles[16];
	uint8_t created_count = 0, got_cig = 0, got_count = 0;
	uint8_t i;

	if (adp == NULL || cises == NULL || cis_count == 0 || cis_count > 16)
		return (-1);
	if (out_count != NULL)
		*out_count = 0;
	if (iso_cig_refs(adp, cig_id) != 0)
		return (-1);

	if (hci_le_setup_cig(adp->hci_fd, cig_id, sdu_interval_c,
	    sdu_interval_p, sca, packing, framing, lat_c, lat_p, cis_count,
	    cises, &got_cig, &got_count, handles) != 0) {
		LOG_ISO(1, "CIG %u: Set CIG Parameters failed", cig_id);
		return (-1);
	}
	if (got_cig != cig_id || got_count != cis_count) {
		LOG_ISO(1, "CIG %u: inconsistent response cig=%u count=%u",
		    cig_id, got_cig, got_count);
		(void)hci_le_remove_cig(adp->hci_fd, cig_id);
		return (-1);
	}

	for (i = 0; i < got_count; i++) {
		struct blued_iso_stream *s = iso_alloc();

		if (s == NULL) {
			while (created_count != 0)
				iso_unlink(created[--created_count]);
			(void)hci_le_remove_cig(adp->hci_fd, cig_id);
			return (-1);
		}
		created[created_count++] = s;
		s->role = ISO_ROLE_CIS_CENTRAL;
		s->state = ISO_ST_CIG_CONFIGURED;
		s->adapter = adp;
		s->cig_id = got_cig;
		s->cis_id = cises[i].cis_id;
		s->cis_handle = handles[i];
		s->sdu_interval_c = sdu_interval_c;
		s->sdu_interval_p = sdu_interval_p;
		s->max_transport_latency_c = lat_c;
		s->max_transport_latency_p = lat_p;
		s->max_sdu_c = cises[i].max_sdu_c_to_p;
		s->max_sdu_p = cises[i].max_sdu_p_to_c;
		s->phy = cises[i].phy_c_to_p;
		s->rtn = cises[i].rtn_c_to_p;
		s->framing = framing;
		s->packing = packing;
		if (out_handles != NULL)
			out_handles[i] = handles[i];
		LOG_ISO(1, "CIG %u CIS %u configured: handle=0x%04x",
		    got_cig, cises[i].cis_id, handles[i]);
	}
	if (out_count != NULL)
		*out_count = got_count;
	return (0);
}

int
blued_iso_cis_create(struct blued_adapter *adp, const bdaddr_t *peer,
    uint8_t peer_type, uint8_t cig_id, uint8_t cis_id,
    int requesting_client_fd, bool push_on_establish)
{
	struct blued_iso_stream *s;
	struct blued_conn *conn;
	uint16_t cis_handle, acl_handle;
	int rc;

	if (adp == NULL || peer == NULL)
		return (-1);

	/*
	 * Resolve the peer's ACL handle first (this takes conns_lock and
	 * releases it) so iso_lock is never held across a conns_lock acquire.
	 */
	conn = blued_conn_by_peer(adp, peer, peer_type);
	if (conn == NULL) {
		LOG_ISO(1, "Create CIS: peer not connected");
		return (-1);
	}
	acl_handle = conn->con_handle;

	s = iso_find_cis(adp, cig_id, cis_id);
	if (s == NULL) {
		LOG_ISO(1, "Create CIS: no configured CIG %u CIS %u",
		    cig_id, cis_id);
		return (-1);
	}
	if (s->state != ISO_ST_CIG_CONFIGURED) {
		iso_unref(s);
		return (-1);
	}
	s->acl_handle = acl_handle;
	memcpy(&s->peer, peer, sizeof(s->peer));
	s->peer_type = peer_type;
	s->requesting_client_fd = requesting_client_fd;
	s->push_on_establish = push_on_establish;
	cis_handle = s->cis_handle;

	rc = hci_le_create_cis(adp->hci_fd, 1, &cis_handle, &acl_handle);
	if (rc != 0) {
		LOG_ISO(1, "Create CIS 0x%04x failed", cis_handle);
		iso_unref(s);
		return (-1);
	}
	s->state = ISO_ST_CREATING;
	LOG_ISO(1, "Create CIS 0x%04x -> creating (acl=0x%04x)",
	    cis_handle, acl_handle);
	iso_unref(s);
	return (0);
}

int
blued_iso_cig_remove(struct blued_adapter *adp, uint8_t cig_id)
{
	struct blued_iso_stream *s;
	bool found = false;

	if (adp == NULL)
		return (-1);
	/* LE Remove CIG is a Central command and is disallowed for an active
	 * CIG.  An inbound Peripheral CIS with the same peer-assigned CIG_ID is
	 * a separate namespace and must never be deleted by this operation. */
	pthread_mutex_lock(&iso_lock);
	LIST_FOREACH(s, &iso_streams, entries) {
		if (s->adapter != adp || s->role != ISO_ROLE_CIS_CENTRAL ||
		    s->cig_id != cig_id)
			continue;
		found = true;
		if (s->state != ISO_ST_CIG_CONFIGURED) {
			pthread_mutex_unlock(&iso_lock);
			return (-1);
		}
	}
	pthread_mutex_unlock(&iso_lock);
	if (!found)
		return (-1);
	if (hci_le_remove_cig(adp->hci_fd, cig_id) != 0)
		return (-1);
	/* Free any CIS streams still parked in CIG_CONFIGURED for this CIG. */
	for (;;) {
		struct blued_iso_stream *victim = NULL;

		pthread_mutex_lock(&iso_lock);
		LIST_FOREACH(s, &iso_streams, entries) {
			if (s->adapter == adp &&
			    s->role == ISO_ROLE_CIS_CENTRAL &&
			    s->cig_id == cig_id) {
				atomic_fetch_add(&s->refcount, 1);
				victim = s;
				break;
			}
		}
		pthread_mutex_unlock(&iso_lock);
		if (victim == NULL)
			break;
		iso_unlink(victim);
		iso_unref(victim);
	}
	LOG_ISO(1, "CIG %u removed", cig_id);
	return (0);
}

/* ---- Peripheral / CIS verbs ---- */

int
blued_iso_cis_accept(struct blued_adapter *adp, uint16_t cis_handle)
{
	struct blued_iso_stream *s;
	int rc;

	if (adp == NULL)
		return (-1);
	s = iso_find_by_handle(adp, cis_handle);
	if (s == NULL || s->role != ISO_ROLE_CIS_PERIPHERAL ||
	    s->state != ISO_ST_REQUESTED) {
		if (s != NULL)
			iso_unref(s);
		return (-1);
	}
	rc = hci_le_accept_cis_request(adp->hci_fd, cis_handle);
	if (rc != 0) {
		iso_unref(s);
		return (-1);
	}
	s->state = ISO_ST_CREATING;
	LOG_ISO(1, "Accept CIS 0x%04x -> creating", cis_handle);
	iso_unref(s);
	return (0);
}

int
blued_iso_cis_reject(struct blued_adapter *adp, uint16_t cis_handle,
    uint8_t reason)
{
	struct blued_iso_stream *s;

	if (adp == NULL)
		return (-1);
	s = iso_find_by_handle(adp, cis_handle);
	if (s == NULL || s->role != ISO_ROLE_CIS_PERIPHERAL ||
	    s->state != ISO_ST_REQUESTED) {
		if (s != NULL)
			iso_unref(s);
		return (-1);
	}
	if (hci_le_reject_cis_request(adp->hci_fd, cis_handle, reason) != 0) {
		iso_unref(s);
		return (-1);
	}
	LOG_ISO(1, "Reject CIS 0x%04x reason=0x%02x", cis_handle, reason);
	iso_unlink(s);
	iso_unref(s);
	return (0);
}

/* ---- Broadcaster / BIS source ---- */

int
blued_iso_big_create(struct blued_adapter *adp, uint8_t big_handle,
    uint8_t adv_handle, uint8_t num_bis, uint32_t sdu_interval,
    uint16_t max_sdu, uint16_t max_transport_latency, uint8_t rtn,
    uint8_t phy, uint8_t packing, uint8_t framing, uint8_t encryption,
    const uint8_t broadcast_code[16])
{
	struct blued_iso_stream *existing, *s;

	if (adp == NULL || num_bis == 0 || num_bis > ISO_MAX_BIS)
		return (-1);
	existing = iso_find_big(adp, big_handle);
	if (existing != NULL) {
		iso_unref(existing);
		return (-1);
	}
	s = iso_alloc();
	if (s == NULL)
		return (-1);
	s->role = ISO_ROLE_BIS_SOURCE;
	s->state = ISO_ST_CREATING;
	s->adapter = adp;
	s->big_handle = big_handle;
	s->requested_num_bis = num_bis;
	/* num_bis / bis_handles are learned from the Create BIG Complete event. */
	s->sdu_interval_c = sdu_interval;
	s->max_transport_latency_c = max_transport_latency;
	s->max_sdu_c = max_sdu;
	s->rtn = rtn;
	s->phy = phy;
	s->packing = packing;
	s->framing = framing;
	s->encryption = encryption;
	if (broadcast_code != NULL)
		memcpy(s->broadcast_code, broadcast_code, 16);

	if (hci_le_create_big(adp->hci_fd, big_handle, adv_handle, num_bis,
	    sdu_interval, max_sdu, max_transport_latency, rtn, phy, packing,
	    framing, encryption, s->broadcast_code) != 0) {
		LOG_ISO(1, "Create BIG %u failed", big_handle);
		iso_unlink(s);
		return (-1);
	}
	LOG_ISO(1, "Create BIG %u -> creating (num_bis=%u)", big_handle,
	    num_bis);
	return (0);
}

int
blued_iso_big_terminate(struct blued_adapter *adp, uint8_t big_handle,
    uint8_t reason)
{
	struct blued_iso_stream *s;
	enum iso_state old_state;

	if (adp == NULL)
		return (-1);
	s = iso_find_big(adp, big_handle);
	if (s == NULL || s->role != ISO_ROLE_BIS_SOURCE) {
		if (s != NULL)
			iso_unref(s);
		return (-1);
	}
	if (s->state == ISO_ST_TEARDOWN) {
		iso_unref(s);
		return (-1);
	}
	old_state = s->state;
	iso_remove_paths(s);
	if (hci_le_terminate_big(adp->hci_fd, big_handle, reason) != 0) {
		s->state = s->paths_up != 0 ? old_state : ISO_ST_ESTABLISHED;
		iso_unref(s);
		return (-1);
	}
	s->state = ISO_ST_TEARDOWN;
	LOG_ISO(1, "Terminate BIG %u", big_handle);
	iso_unref(s);
	return (0);
}

/* ---- Sync / BIS sink ---- */

int
blued_iso_big_create_sync(struct blued_adapter *adp, uint8_t big_handle,
    uint16_t sync_handle, const uint8_t *bis_indices, uint8_t num_bis,
    uint8_t mse, uint16_t big_sync_timeout, uint8_t encryption,
    const uint8_t broadcast_code[16])
{
	struct blued_iso_stream *existing, *s;

	if (adp == NULL || bis_indices == NULL || num_bis == 0 ||
	    num_bis > ISO_MAX_BIS)
		return (-1);
	existing = iso_find_big(adp, big_handle);
	if (existing != NULL) {
		iso_unref(existing);
		return (-1);
	}
	s = iso_alloc();
	if (s == NULL)
		return (-1);
	s->role = ISO_ROLE_BIS_SINK;
	s->state = ISO_ST_CREATING;
	s->adapter = adp;
	s->big_handle = big_handle;
	s->sync_handle = sync_handle;
	s->requested_num_bis = num_bis;
	/* num_bis / bis_handles are learned from the BIG Sync Established event. */
	s->encryption = encryption;
	if (broadcast_code != NULL)
		memcpy(s->broadcast_code, broadcast_code, 16);

	if (hci_le_big_create_sync(adp->hci_fd, big_handle, sync_handle,
	    encryption, s->broadcast_code, mse, big_sync_timeout, num_bis,
	    bis_indices) != 0) {
		LOG_ISO(1, "BIG Create Sync %u failed", big_handle);
		iso_unlink(s);
		return (-1);
	}
	LOG_ISO(1, "BIG Create Sync %u -> creating (sync=0x%04x num_bis=%u)",
	    big_handle, sync_handle, num_bis);
	return (0);
}

int
blued_iso_big_terminate_sync(struct blued_adapter *adp, uint8_t big_handle)
{
	struct blued_iso_stream *s;
	enum iso_state old_state;

	if (adp == NULL)
		return (-1);
	s = iso_find_big(adp, big_handle);
	if (s == NULL || s->role != ISO_ROLE_BIS_SINK) {
		if (s != NULL)
			iso_unref(s);
		return (-1);
	}
	if (s->state == ISO_ST_TEARDOWN) {
		iso_unref(s);
		return (-1);
	}
	old_state = s->state;
	s->state = ISO_ST_TEARDOWN;
	iso_remove_paths(s);
	if (hci_le_big_terminate_sync(adp->hci_fd, big_handle) != 0) {
		s->state = s->paths_up != 0 ? old_state : ISO_ST_ESTABLISHED;
		iso_unref(s);
		return (-1);
	}
	LOG_ISO(1, "BIG Terminate Sync %u", big_handle);
	iso_unlink(s);
	iso_unref(s);
	return (0);
}

/* ---- fd handout ---- */

int
blued_iso_acquire_fd(struct blued_adapter *adp, uint16_t handle)
{
	struct blued_iso_stream *s;
	int fd;

	s = iso_find_by_handle(adp, handle);
	if (s == NULL)
		return (-1);
	if (s->state != ISO_ST_PATHS_UP && s->state != ISO_ST_HANDED_OFF) {
		iso_unref(s);
		return (-1);
	}
	fd = ble_iso_connect((const uint8_t *)&s->adapter->addr,
	    (const uint8_t *)&s->peer, s->peer_type, handle, 0);
	if (fd >= 0)
		s->state = ISO_ST_HANDED_OFF;
	iso_unref(s);
	return (fd);
}

int
blued_iso_acquire_bis_fd(struct blued_adapter *adp, uint8_t big_handle,
    uint8_t bis_index)
{
	struct blued_iso_stream *s;
	int fd;

	s = iso_find_big(adp, big_handle);
	if (s == NULL)
		return (-1);
	if ((s->state != ISO_ST_PATHS_UP && s->state != ISO_ST_HANDED_OFF) ||
	    bis_index >= s->num_bis ||
	    (s->bis_paths_up & ((uint32_t)1 << bis_index)) == 0) {
		iso_unref(s);
		return (-1);
	}
	fd = ble_iso_connect((const uint8_t *)&s->adapter->addr,
	    (const uint8_t *)&s->peer, s->peer_type, s->bis_handles[bis_index],
	    0);
	if (fd >= 0)
		s->state = ISO_ST_HANDED_OFF;
	iso_unref(s);
	return (fd);
}

/* ---- Teardown ---- */

int
blued_iso_cis_teardown(struct blued_adapter *adp, uint16_t cis_handle,
    uint8_t reason)
{
	struct blued_iso_stream *s;

	s = iso_find_by_handle(adp, cis_handle);
	if (s == NULL || (s->role != ISO_ROLE_CIS_CENTRAL &&
	    s->role != ISO_ROLE_CIS_PERIPHERAL)) {
		if (s != NULL)
			iso_unref(s);
		return (-1);
	}
	if (s->state != ISO_ST_ESTABLISHED && s->state != ISO_ST_PATHS_UP &&
	    s->state != ISO_ST_HANDED_OFF && s->state != ISO_ST_TEARDOWN) {
		iso_unref(s);
		return (-1);
	}
	if (s->state == ISO_ST_TEARDOWN) {
		iso_unref(s);
		return (-1);
	}

	/*
	 * Reverse of setup: remove data paths, disconnect the CIS, then unlink
	 * so the peer's later Disconnection Complete finds nothing (no double
	 * free, no spurious ISO_LOST).
	 */
	iso_remove_paths(s);
	if (hci_disconnect(adp->hci_fd, cis_handle, reason) != 0) {
		s->state = ISO_ST_ESTABLISHED;
		iso_unref(s);
		return (-1);
	}
	s->state = ISO_ST_TEARDOWN;
	iso_unref(s);
	LOG_ISO(1, "CIS 0x%04x teardown requested (reason=0x%02x)",
	    cis_handle, reason);
	return (0);
}

int
blued_iso_sweep_adapter(struct blued_adapter *adp)
{
	struct blued_iso_stream *s, *victim;

	for (;;) {
		victim = NULL;
		pthread_mutex_lock(&iso_lock);
		LIST_FOREACH(s, &iso_streams, entries) {
			if (adp == NULL || s->adapter == adp) {
				atomic_fetch_add(&s->refcount, 1);
				victim = s;
				break;
			}
		}
		pthread_mutex_unlock(&iso_lock);
		if (victim == NULL)
			return (0);

		if (iso_remove_paths_checked(victim) < 0) {
			iso_unref(victim);
			return (-1);
		}
		switch (victim->role) {
		case ISO_ROLE_CIS_CENTRAL:
		case ISO_ROLE_CIS_PERIPHERAL:
			if (victim->role == ISO_ROLE_CIS_CENTRAL &&
			    victim->state == ISO_ST_CIG_CONFIGURED) {
				uint8_t cig_id = victim->cig_id;

				if (hci_le_remove_cig(victim->adapter->hci_fd,
				    cig_id) < 0) {
					iso_unref(victim);
					return (-1);
				}
				/* One Remove CIG destroys every configured CIS in it. */
				for (;;) {
					struct blued_iso_stream *member = NULL;

					pthread_mutex_lock(&iso_lock);
					LIST_FOREACH(s, &iso_streams, entries)
						if (s->adapter == victim->adapter &&
						    s->role == ISO_ROLE_CIS_CENTRAL &&
						    s->cig_id == cig_id &&
						    s->state == ISO_ST_CIG_CONFIGURED) {
							atomic_fetch_add(&s->refcount, 1);
							member = s;
							break;
						}
					pthread_mutex_unlock(&iso_lock);
					if (member == NULL)
						break;
					iso_unlink(member);
					iso_unref(member);
				}
				iso_unref(victim);
				continue;
			}
			if (victim->role == ISO_ROLE_CIS_PERIPHERAL &&
			    victim->state == ISO_ST_REQUESTED) {
				if (hci_le_reject_cis_request(
				    victim->adapter->hci_fd,
				    victim->cis_handle, ISO_REJECT_REASON) < 0) {
					iso_unref(victim);
					return (-1);
				}
			} else {
				if (hci_disconnect(victim->adapter->hci_fd,
				    victim->cis_handle, ISO_TEARDOWN_REASON) < 0) {
					iso_unref(victim);
					return (-1);
				}
			}
			break;
		case ISO_ROLE_BIS_SOURCE:
			if (hci_le_terminate_big(victim->adapter->hci_fd,
			    victim->big_handle, ISO_TEARDOWN_REASON) < 0) {
				iso_unref(victim);
				return (-1);
			}
			break;
		case ISO_ROLE_BIS_SINK:
			if (hci_le_big_terminate_sync(victim->adapter->hci_fd,
			    victim->big_handle) < 0) {
				iso_unref(victim);
				return (-1);
			}
			break;
		}
		iso_unlink(victim);
		iso_unref(victim);
	}
}

void
blued_iso_reset(void)
{
	struct blued_iso_stream *s;

	for (;;) {
		pthread_mutex_lock(&iso_lock);
		s = LIST_FIRST(&iso_streams);
		if (s != NULL) {
			LIST_REMOVE(s, entries);
			s->linked = false;
		}
		pthread_mutex_unlock(&iso_lock);
		if (s == NULL)
			break;
		iso_unref(s);
	}
}

void
blued_iso_reset_adapter(struct blued_adapter *adp)
{
	struct blued_iso_stream *s, *victim;

	for (;;) {
		victim = NULL;
		pthread_mutex_lock(&iso_lock);
		LIST_FOREACH(s, &iso_streams, entries)
			if (s->adapter == adp) {
				LIST_REMOVE(s, entries);
				s->linked = false;
				victim = s;
				break;
			}
		pthread_mutex_unlock(&iso_lock);
		if (victim == NULL)
			break;
		iso_unref(victim);
	}
}

/* ---- Async event seams ---- */

/*
 * Advance an established CIS.  On nonzero status the create failed: free the
 * stream, remove its now-orphaned CIG if it was the last CIS, and report the
 * loss so the requester does not wait forever.  On success set up both data-
 * path directions and, if a client pre-registered, push the fd immediately;
 * otherwise emit ISO_ESTABLISHED so it can pull the fd with ISO_ACQUIRE.
 */
void
iso_on_cis_established(struct blued_adapter *adp, uint16_t cis_handle,
    uint8_t status)
{
	struct blued_iso_stream *s;
	int up;

	s = iso_find_by_handle(adp, cis_handle);
	if (s == NULL) {
		LOG_ISO(1, "CIS Established 0x%04x: no matching stream",
		    cis_handle);
		return;
	}
	if (s->state != ISO_ST_CREATING) {
		LOG_ISO(1, "CIS Established 0x%04x in state %d ignored",
		    cis_handle, s->state);
		iso_unref(s);
		return;
	}
	if (status != 0) {
		bool central = s->role == ISO_ROLE_CIS_CENTRAL;
		uint8_t cig_id = s->cig_id;

		LOG_ISO(1, "CIS Established 0x%04x failed status=0x%02x",
		    cis_handle, status);
		s->state = ISO_ST_FAILED;
		iso_unlink(s);
		iso_unref(s);
		if (central && iso_cig_refs(adp, cig_id) == 0)
			(void)hci_le_remove_cig(adp->hci_fd, cig_id);
		return;
	}

	s->state = ISO_ST_ESTABLISHED;
	up = iso_setup_paths(s, HCI_ISO_STREAM_CIS, NULL);
	if (up <= 0) {
		/* The CIS exists in the Controller even though its host data path
		 * failed.  Keep ownership until Disconnection Complete rather than
		 * freeing a live connection handle. */
		LOG_ISO(1, "CIS 0x%04x established but no data path", cis_handle);
		if (hci_disconnect(adp->hci_fd, cis_handle,
		    ISO_TEARDOWN_REASON) == 0)
			s->state = ISO_ST_TEARDOWN;
		iso_unref(s);
		return;
	}
	s->state = ISO_ST_PATHS_UP;
	LOG_ISO(1, "CIS 0x%04x established, paths up", cis_handle);

	if (s->push_on_establish && s->requesting_client_fd >= 0) {
		int fd = ble_iso_connect((const uint8_t *)&s->adapter->addr,
		    (const uint8_t *)&s->peer, s->peer_type, cis_handle, 0);

		if (fd >= 0) {
			blued_ctl_send_fd(s->requesting_client_fd, fd);
			close(fd);
			s->state = ISO_ST_HANDED_OFF;
		}
	}
	blued_ctl_iso_established(s->adapter, &s->peer, s->peer_type,
	    cis_handle, 0);
	iso_unref(s);
}

void
iso_on_cis_request(struct blued_adapter *adp, uint16_t acl_handle,
    uint16_t cis_handle, uint8_t cig_id, uint8_t cis_id)
{
	struct blued_iso_stream *s;
	struct blued_conn *conn;

	/* Ignore a duplicate request for a handle we already track. */
	s = iso_find_by_handle(adp, cis_handle);
	if (s != NULL) {
		(void)hci_le_reject_cis_request(adp->hci_fd, cis_handle,
		    ISO_REJECT_REASON);
		iso_unref(s);
		return;
	}
	s = iso_alloc();
	if (s == NULL) {
		(void)hci_le_reject_cis_request(adp->hci_fd, cis_handle,
		    ISO_REJECT_REASON);
		return;
	}
	s->role = ISO_ROLE_CIS_PERIPHERAL;
	s->state = ISO_ST_REQUESTED;
	s->adapter = adp;
	s->cig_id = cig_id;
	s->cis_id = cis_id;
	s->cis_handle = cis_handle;
	s->acl_handle = acl_handle;

	/* Best-effort peer address from the ACL link, for the fd handout. */
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (conn->adapter == adp && conn->con_handle_valid &&
		    conn->con_handle == acl_handle) {
			memcpy(&s->peer, &conn->dst, sizeof(s->peer));
			s->peer_type = conn->addr_type;
			break;
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);

	LOG_ISO(1, "CIS Request cis=0x%04x cig=%u cis_id=%u -> awaiting accept",
	    cis_handle, cig_id, cis_id);
	blued_ctl_iso_cis_request(s->adapter, &s->peer, s->peer_type, cis_handle,
	    cig_id,
	    cis_id);
}

/* Shared BIS establishment: record handles, set up per-BIS paths, emit event. */
static void
iso_on_big_established(struct blued_adapter *adp, uint8_t big_handle,
    uint8_t status, uint8_t num_bis, const uint8_t *bis_handles_le,
    enum hci_iso_stream_kind kind)
{
	struct blued_iso_stream *s;
	uint8_t i;
	int up;

	s = iso_find_big(adp, big_handle);
	if (s == NULL) {
		LOG_ISO(1, "BIG %u event: no matching stream", big_handle);
		return;
	}
	if (s->state != ISO_ST_CREATING ||
	    (kind == HCI_ISO_STREAM_BIS_SOURCE &&
	    s->role != ISO_ROLE_BIS_SOURCE) ||
	    (kind == HCI_ISO_STREAM_BIS_SINK &&
	    s->role != ISO_ROLE_BIS_SINK)) {
		if (s->state == ISO_ST_TEARDOWN &&
		    status == ISO_STATUS_CANCELLED_BY_HOST) {
			iso_unlink(s);
			iso_unref(s);
			return;
		}
		LOG_ISO(1, "BIG %u completion does not match pending procedure",
		    big_handle);
		iso_unref(s);
		return;
	}
	(void)adp;
	if (status != 0) {
		LOG_ISO(1, "BIG %u establish failed status=0x%02x", big_handle,
		    status);
		s->state = ISO_ST_FAILED;
		iso_unlink(s);
		iso_unref(s);
		return;
	}
	if (num_bis == 0 || num_bis > ISO_MAX_BIS ||
	    num_bis != s->requested_num_bis || bis_handles_le == NULL) {
		LOG_ISO(1, "BIG %u invalid completion count=%u expected=%u",
		    big_handle, num_bis, s->requested_num_bis);
		s->state = ISO_ST_ESTABLISHED;
		if (s->role == ISO_ROLE_BIS_SOURCE) {
			if (hci_le_terminate_big(adp->hci_fd, big_handle,
			    ISO_TEARDOWN_REASON) == 0)
				s->state = ISO_ST_TEARDOWN;
		} else if (hci_le_big_terminate_sync(adp->hci_fd,
		    big_handle) == 0) {
			iso_unlink(s);
		}
		iso_unref(s);
		return;
	}
	s->num_bis = num_bis;
	for (i = 0; i < num_bis; i++)
		s->bis_handles[i] = iso_le16(bis_handles_le + i * 2);
	s->state = ISO_ST_ESTABLISHED;

	up = iso_setup_paths(s, kind, NULL);
	if (up != num_bis) {
		LOG_ISO(1, "BIG %u established but only %d/%u data paths",
		    big_handle, up, num_bis);
		/* A BIG is exposed only when every requested BIS is usable. */
		iso_remove_paths(s);
		s->state = s->paths_up != 0 ? ISO_ST_PATHS_UP : ISO_ST_ESTABLISHED;
		if (s->role == ISO_ROLE_BIS_SOURCE) {
			if (hci_le_terminate_big(adp->hci_fd, big_handle,
			    ISO_TEARDOWN_REASON) == 0)
				s->state = ISO_ST_TEARDOWN;
		} else if (hci_le_big_terminate_sync(adp->hci_fd,
		    big_handle) == 0) {
			iso_unlink(s);
		}
		iso_unref(s);
		return;
	}
	s->state = ISO_ST_PATHS_UP;
	LOG_ISO(1, "BIG %u established, %u BIS path(s) up", big_handle, up);
	iso_unref(s);
}

void
iso_on_big_complete(struct blued_adapter *adp, uint8_t big_handle,
    uint8_t status, uint8_t num_bis, const uint8_t *bis_handles_le)
{

	iso_on_big_established(adp, big_handle, status, num_bis, bis_handles_le,
	    HCI_ISO_STREAM_BIS_SOURCE);
}

void
iso_on_big_sync_established(struct blued_adapter *adp, uint8_t big_handle,
    uint8_t status, uint8_t num_bis, const uint8_t *bis_handles_le)
{

	iso_on_big_established(adp, big_handle, status, num_bis, bis_handles_le,
	    HCI_ISO_STREAM_BIS_SINK);
}

void
iso_on_cis_disconnected(struct blued_adapter *adp, uint16_t cis_handle,
    uint8_t reason)
{
	struct blued_iso_stream *s;
	bool central;
	uint8_t cig_id;

	s = iso_find_by_handle(adp, cis_handle);
	if (s == NULL || (s->role != ISO_ROLE_CIS_CENTRAL &&
	    s->role != ISO_ROLE_CIS_PERIPHERAL)) {
		if (s != NULL)
			iso_unref(s);
		return;		/* not an ISO CIS, or self-initiated teardown */
	}
	cig_id = s->cig_id;
	central = s->role == ISO_ROLE_CIS_CENTRAL;
	/* Peer-initiated: the controller already dropped the paths. */
	s->paths_up = 0;
	iso_unlink(s);
	iso_unref(s);
	if (central && iso_cig_refs(adp, cig_id) == 0)
		(void)hci_le_remove_cig(adp->hci_fd, cig_id);
	LOG_ISO(1, "CIS 0x%04x lost (reason=0x%02x)", cis_handle, reason);
}

void
iso_on_big_sync_lost(struct blued_adapter *adp, uint8_t big_handle,
    uint8_t reason)
{
	struct blued_iso_stream *s;

	s = iso_find_big(adp, big_handle);
	if (s == NULL || s->role != ISO_ROLE_BIS_SINK) {
		if (s != NULL)
			iso_unref(s);
		return;
	}
	s->paths_up = 0;
	iso_unlink(s);
	iso_unref(s);
	LOG_ISO(1, "BIG %u sync lost (reason=0x%02x)", big_handle, reason);
}

void
iso_on_big_terminated(struct blued_adapter *adp, uint8_t big_handle,
    uint8_t reason)
{
	struct blued_iso_stream *s;

	s = iso_find_big(adp, big_handle);
	if (s == NULL || s->role != ISO_ROLE_BIS_SOURCE) {
		if (s != NULL)
			iso_unref(s);
		return;		/* self-initiated terminate already freed it */
	}
	s->paths_up = 0;
	iso_unlink(s);
	iso_unref(s);
	LOG_ISO(1, "BIG %u terminated (reason=0x%02x)", big_handle, reason);
}

/* ---- inspection ---- */

int
blued_iso_stream_state(struct blued_adapter *adp, uint16_t handle)
{
	struct blued_iso_stream *s;
	int st;

	s = iso_find_by_handle(adp, handle);
	if (s == NULL)
		return (-1);
	st = (int)s->state;
	iso_unref(s);
	return (st);
}

int
blued_iso_stream_count(void)
{
	struct blued_iso_stream *s;
	int n = 0;

	pthread_mutex_lock(&iso_lock);
	LIST_FOREACH(s, &iso_streams, entries)
		n++;
	pthread_mutex_unlock(&iso_lock);
	return (n);
}
