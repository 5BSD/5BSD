/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Control-socket verbs for the LE Isochronous (ISO) operator surface: set up
 * and tear down CIS (central and peripheral) and BIS (broadcaster source,
 * synchronized sink) streams, and hand out the data-path socket fd.  The verbs
 * map 1:1 onto the ISO state machine (iso.c); this layer only parses arguments,
 * resolves the target adapter, and formats replies.
 *
 * All ISO verbs mutate controller state, so the daemon's privilege gate has
 * already rejected an unprivileged peer before dispatch reaches here.  The
 * ISO_ACQUIRE* verbs additionally require the fd-passing feature and a
 * non-sandboxed daemon (socket() is unavailable once Capsicum-sandboxed).
 *
 * Core Spec 6.x Vol 4 Part E: §7.8.97-.111.
 */

#include <sys/capsicum.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blued.h"
#include "conn.h"
#include "ctl.h"
#include "ctl_internal.h"
#include "hci_internal.h"
#include "hci_util.h"
#include "iso.h"


















/* Verb table: prefix (with trailing space) -> handler. */
struct iso_verb {
	const char	*prefix;
	size_t		len;
	void		(*fn)(struct blued_ctl_client *, const char *);
};

static bool
ctl_iso_phy_mask_valid(uint8_t phy)
{

	return (phy != 0 && (phy & ~0x07u) == 0);
}

static bool
ctl_iso_broadcast_code_zero(const uint8_t code[16])
{
	uint8_t acc = 0;

	for (uint8_t i = 0; i < 16; i++)
		acc |= code[i];
	return (acc == 0);
}

static bool
ctl_iso_cig_request_valid(const uint8_t *payload, uint8_t count)
{
	uint32_t sdu_c, sdu_p;
	uint16_t lat_c, lat_p;

	sdu_c = ipc_get_le32(payload + 14);
	sdu_p = ipc_get_le32(payload + 18);
	lat_c = ipc_get_le16(payload + 10);
	lat_p = ipc_get_le16(payload + 12);
	if (payload[4] > 0xef || sdu_c < 0x0000ff || sdu_c > 0x0fffff ||
	    sdu_p < 0x0000ff || sdu_p > 0x0fffff || payload[6] > 0x07 ||
	    payload[7] > 0x01 || payload[8] > 0x02 || lat_c < 0x0005 ||
	    lat_c > 0x0fa0 || lat_p < 0x0005 || lat_p > 0x0fa0)
		return (false);
	for (uint8_t i = 0; i < count; i++) {
		const uint8_t *p = payload + IPC_ISO_CIG_REQ_HDR_SIZE +
		    i * IPC_ISO_CIS_PARAM_SIZE;

		if (p[0] > 0xef || !ctl_iso_phy_mask_valid(p[1]) ||
		    !ctl_iso_phy_mask_valid(p[2]) || p[3] > 0x0f ||
		    p[4] > 0x0f || ipc_get_le16(p + 6) > 0x0fff ||
		    ipc_get_le16(p + 8) > 0x0fff)
			return (false);
	}
	return (true);
}

static bool
ctl_iso_big_request_valid(const uint8_t *payload)
{
	uint32_t sdu_interval;
	uint16_t max_sdu, max_latency;
	uint8_t encryption;

	sdu_interval = ipc_get_le32(payload + 14);
	max_sdu = ipc_get_le16(payload + 18);
	max_latency = ipc_get_le16(payload + 20);
	encryption = payload[11];
	return (payload[4] <= 0xef && payload[5] <= 0xef &&
	    payload[6] >= 0x01 && payload[6] <= ISO_MAX_BIS &&
	    sdu_interval >= 0x0000ff && sdu_interval <= 0x0fffff &&
	    max_sdu >= 0x0001 && max_sdu <= 0x0fff &&
	    max_latency >= 0x0005 && max_latency <= 0x0fa0 &&
	    payload[7] <= 0x1e && ctl_iso_phy_mask_valid(payload[8]) &&
	    payload[9] <= 0x01 && payload[10] <= 0x02 && encryption <= 0x01 &&
	    (encryption != 0 || ctl_iso_broadcast_code_zero(payload + 22)));
}

static bool
ctl_iso_big_sync_request_valid(const uint8_t *payload)
{
	uint8_t num_bis, encryption;

	num_bis = payload[5];
	encryption = payload[7];
	if (payload[4] > 0xef || num_bis < 0x01 || num_bis > ISO_MAX_BIS ||
	    encryption > 0x01 || ipc_get_le16(payload + 8) > 0x0eff ||
	    ipc_get_le16(payload + 10) < 0x000a ||
	    ipc_get_le16(payload + 10) > 0x4000 ||
	    payload[6] > 0x1f ||
	    (encryption == 0 && !ctl_iso_broadcast_code_zero(payload + 20)))
		return (false);
	for (uint8_t i = 0; i < num_bis; i++) {
		uint8_t bis = payload[12 + i];

		if (bis < 0x01 || bis > 0x1f ||
		    (i > 0 && bis <= payload[12 + i - 1]))
			return (false);
	}
	return (true);
}


void
ctl_iso_process_typed(struct blued_ctl_client *client, const uint8_t *payload,
    size_t plen)
{
	struct blued_adapter *adp;
	uint16_t opcode, flags;
	uint8_t adapter_index;
	int error = IPC_ERR_NONE;

	if (!client->peer_known || client->peer_uid != 0) {
		ctl_send_op_error(client, IPC_OP_DOMAIN_ISO, IPC_ERR_PERM,
		    "permission denied");
		return;
	}
	if (plen < 4) {
		error = IPC_ERR_PROTO;
		goto out;
	}
	opcode = ipc_get_le16(payload);
	flags = ipc_get_le16(payload + 2);
	adapter_index = (uint8_t)(flags >> IPC_OP_ADAPTER_SHIFT);
	if ((flags & IPC_OP_FLAGS_RESERVED_MASK) != 0 ||
	    adapter_index >= BLUED_MAX_ADAPTERS) {
		error = IPC_ERR_INVAL;
		goto out;
	}
	adp = blued_adapter_by_index_powered(adapter_index);
	if (adp == NULL || !adp->active) {
		error = IPC_ERR_NOT_FOUND;
		goto out;
	}
	switch (opcode) {
	case IPC_ISO_CIG_CREATE: {
		struct hci_cis_param cises[8];
		uint16_t handles[8];
		uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_ISO_CIG_REPLY_SIZE];
		uint8_t count, returned = 0;

		if ((adp->le_features & LE_FEAT_CIS_CENTRAL) == 0) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		if (plen < IPC_ISO_CIG_REQ_HDR_SIZE ||
		    (count = payload[5]) < 1 || count > 8 || payload[9] != 0 ||
		    ipc_get_le16(payload + 22) != 0 || plen !=
		    IPC_ISO_CIG_REQ_HDR_SIZE + count * IPC_ISO_CIS_PARAM_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		if (!ctl_iso_cig_request_valid(payload, count)) {
			error = IPC_ERR_INVAL;
			break;
		}
		memset(cises, 0, sizeof(cises));
		for (uint8_t i = 0; i < count; i++) {
			const uint8_t *p = payload + IPC_ISO_CIG_REQ_HDR_SIZE +
			    i * IPC_ISO_CIS_PARAM_SIZE;

			if (p[5] != 0) {
				error = IPC_ERR_INVAL;
				goto out;
			}
			cises[i].cis_id = p[0];
			cises[i].phy_c_to_p = p[1];
			cises[i].phy_p_to_c = p[2];
			cises[i].rtn_c_to_p = p[3];
			cises[i].rtn_p_to_c = p[4];
			cises[i].max_sdu_c_to_p = ipc_get_le16(p + 6);
			cises[i].max_sdu_p_to_c = ipc_get_le16(p + 8);
		}
		if (blued_iso_cig_create(adp, payload[4],
		    ipc_get_le32(payload + 14), ipc_get_le32(payload + 18),
		    payload[6], payload[7], payload[8],
		    ipc_get_le16(payload + 10), ipc_get_le16(payload + 12), cises,
		    count, handles, &returned) != 0) {
			error = IPC_ERR_IO;
			break;
		}
		memset(reply, 0, sizeof(reply));
		ipc_op_prefix_encode(reply, client->active_request_id, 0, 0);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, opcode);
		reply[IPC_OP_PREFIX_SIZE + 2] = returned;
		for (uint8_t i = 0; i < returned && i < 8; i++)
			ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 4 + i * 2,
			    handles[i]);
		ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_ISO, reply,
		    sizeof(reply));
		return;
	}
	case IPC_ISO_CIS_CREATE: {
		bdaddr_t peer;
		uint8_t addr_type;

		if ((adp->le_features & LE_FEAT_CIS_CENTRAL) == 0) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		if (plen != IPC_ISO_CIS_CREATE_REQ_SIZE ||
		    !ctl_addr_type_from_ipc(payload[4], &addr_type) ||
		    payload[13] > 1 || ipc_get_le16(payload + 14) != 0) {
			error = IPC_ERR_PROTO;
			break;
		}
		memcpy(&peer, payload + 5, sizeof(peer));
		error = blued_iso_cis_create(adp, &peer, addr_type,
		    payload[11], payload[12], payload[13] ? client->fd : -1,
		    payload[13] != 0) != 0 ? IPC_ERR_IO : IPC_ERR_NONE;
		break;
	}
	case IPC_ISO_CIS_TEARDOWN:
	case IPC_ISO_CIG_REMOVE:
	case IPC_ISO_CIS_ACCEPT:
	case IPC_ISO_CIS_REJECT:
	case IPC_ISO_BIG_TERMINATE:
	case IPC_ISO_BIG_SYNC_TERMINATE:
		if (plen != IPC_ISO_SIMPLE_REQ_SIZE) {
			error = IPC_ERR_PROTO;
			break;
		}
		if ((opcode == IPC_ISO_CIG_REMOVE ||
		    opcode == IPC_ISO_BIG_TERMINATE ||
		    opcode == IPC_ISO_BIG_SYNC_TERMINATE) &&
		    payload[4] > 0xEF) {
			error = IPC_ERR_PROTO;
			break;
		}
		if (opcode == IPC_ISO_CIS_TEARDOWN)
			error = blued_iso_cis_teardown(adp,
			    ipc_get_le16(payload + 4),
			    payload[6]) != 0 ? IPC_ERR_NOT_FOUND : IPC_ERR_NONE;
		else if (opcode == IPC_ISO_CIG_REMOVE)
			error = blued_iso_cig_remove(adp, payload[4]) != 0 ?
			    IPC_ERR_IO : IPC_ERR_NONE;
		else if (opcode == IPC_ISO_CIS_ACCEPT)
			error = blued_iso_cis_accept(adp,
			    ipc_get_le16(payload + 4)) != 0 ? IPC_ERR_NOT_FOUND :
			    IPC_ERR_NONE;
		else if (opcode == IPC_ISO_CIS_REJECT)
			error = blued_iso_cis_reject(adp,
			    ipc_get_le16(payload + 4), payload[6]) != 0 ?
			    IPC_ERR_NOT_FOUND : IPC_ERR_NONE;
		else if (opcode == IPC_ISO_BIG_TERMINATE)
			error = blued_iso_big_terminate(adp, payload[4], payload[5]) != 0 ?
			    IPC_ERR_NOT_FOUND : IPC_ERR_NONE;
		else
			error = blued_iso_big_terminate_sync(adp, payload[4]) != 0 ?
			    IPC_ERR_NOT_FOUND : IPC_ERR_NONE;
		break;
	case IPC_ISO_BIG_CREATE:
		if ((adp->le_features & LE_FEAT_ISO_BROADCASTER) == 0) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		if (plen != IPC_ISO_BIG_REQ_SIZE || payload[13] != 0) {
			error = IPC_ERR_PROTO;
			break;
		}
		if (!ctl_iso_big_request_valid(payload)) {
			error = IPC_ERR_INVAL;
			break;
		}
		error = blued_iso_big_create(adp, payload[4], payload[5], payload[6],
		    ipc_get_le32(payload + 14), ipc_get_le16(payload + 18),
		    ipc_get_le16(payload + 20), payload[7], payload[8], payload[9],
		    payload[10], payload[11], payload + 22) != 0 ? IPC_ERR_IO :
		    IPC_ERR_NONE;
		break;
	case IPC_ISO_BIG_SYNC_CREATE:
		if ((adp->le_features & LE_FEAT_ISO_SYNC_RECEIVER) == 0) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		if (plen != IPC_ISO_BIG_SYNC_REQ_SIZE || payload[5] < 1 ||
		    payload[5] > 8 || payload[7] > 1) {
			error = IPC_ERR_PROTO;
			break;
		}
		if (!ctl_iso_big_sync_request_valid(payload)) {
			error = IPC_ERR_INVAL;
			break;
		}
		error = blued_iso_big_create_sync(adp, payload[4],
		    ipc_get_le16(payload + 8), payload + 12, payload[5], payload[6],
		    ipc_get_le16(payload + 10), payload[7], payload + 20) != 0 ?
		    IPC_ERR_IO : IPC_ERR_NONE;
		break;
	case IPC_ISO_ACQUIRE:
	case IPC_ISO_BIS_ACQUIRE:
	case IPC_ISO_CONNECT_ACQUIRE: {
		uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_ISO_ACQUIRE_REPLY_SIZE];
		size_t handout_len;
		int stream_fd;

		if (!client->wants_fdpass || cap_sandboxed()) {
			error = IPC_ERR_PERM;
			break;
		}
		handout_len = IPC_HDR_SIZE + sizeof(reply) + 1;
		if (opcode == IPC_ISO_CONNECT_ACQUIRE) {
			bdaddr_t peer;
			uint8_t addr_type;

			if (plen != IPC_ISO_CONNECT_ACQUIRE_REQ_SIZE ||
			    !ctl_addr_type_from_ipc(payload[4], &addr_type) ||
			    payload[11] != 0 || ipc_get_le16(payload + 14) != 0) {
				error = IPC_ERR_PROTO;
				break;
			}
			if (!ctl_tx_has_room(client, handout_len)) {
				error = IPC_ERR_IO;
				break;
			}
			memcpy(&peer, payload + 5, sizeof(peer));
			stream_fd = ble_iso_connect((const uint8_t *)&adp->addr,
			    (const uint8_t *)&peer, addr_type,
			    ipc_get_le16(payload + 12), 0);
		} else {
			if (plen != IPC_ISO_SIMPLE_REQ_SIZE) {
				error = IPC_ERR_PROTO;
				break;
			}
			if (!ctl_tx_has_room(client, handout_len)) {
				error = IPC_ERR_IO;
				break;
			}
			stream_fd = opcode == IPC_ISO_ACQUIRE ?
			    blued_iso_acquire_fd(adp, ipc_get_le16(payload + 4)) :
			    blued_iso_acquire_bis_fd(adp, payload[4], payload[5]);
		}
		if (stream_fd < 0) {
			error = IPC_ERR_NOT_FOUND;
			break;
		}
		memset(reply, 0, sizeof(reply));
		ipc_op_prefix_encode(reply, client->active_request_id, 0, 0);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, opcode);
		if (ctl_send_frame(client, IPC_T_OP_REPLY, IPC_OP_DOMAIN_ISO,
		    reply, sizeof(reply)) < 0 ||
		    ctl_send_fd_to_client(client, stream_fd) < 0) {
			close(stream_fd);
			error = IPC_ERR_IO;
			goto out;
		}
		close(stream_fd);
		return;
	}
	default:
		error = IPC_ERR_UNKNOWN_CMD;
		break;
	}
out:
	if (error == IPC_ERR_NONE)
		ctl_send_op_ack(client, IPC_OP_DOMAIN_ISO);
	else
		ctl_send_op_error(client, IPC_OP_DOMAIN_ISO, error,
		    error == IPC_ERR_NOT_FOUND ? "ISO resource not found" :
		    error == IPC_ERR_PERM ? "ISO operation not permitted" :
		    error == IPC_ERR_IO ? "ISO operation failed" :
		    "invalid ISO request");
}
