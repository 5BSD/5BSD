/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATT server request dispatcher — handles incoming ATT requests
 * from connected centrals and sends responses.
 *
 * Split from att_server.c for readability.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "att.h"
#include "att_server.h"
#include "att_server_internal.h"
#include "ble_util.h"
#include "blued_probes.h"
#include "ctl.h"
#include "hci_log.h"
#include "smp.h"

/* ----------------------------------------------------------------
 *  Request handlers
 * ---------------------------------------------------------------- */

static int
handle_mtu_req(struct att_conn *ac, const uint8_t *pdu, size_t len)
{
	uint16_t client_mtu, server_mtu;
	uint8_t rsp[3];

	if (len != 3)
		return att_send_error(ac, ATT_OP_MTU_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	client_mtu = get_le16(pdu + 1);

	if (ac->mtu_exchanged) {
		return att_send_error(ac, ATT_OP_MTU_REQ, 0,
		    ATT_ERR_REQ_NOT_SUPPORTED);
	}

	server_mtu = ATT_UNENHANCED_MAX_MTU;

	rsp[0] = ATT_OP_MTU_RSP;
	put_le16(rsp + 1, server_mtu);
	if (att_server_send(ac, rsp, 3) != 3)
		return (-1);

	ac->mtu = client_mtu < server_mtu ? client_mtu : server_mtu;
	if (ac->mtu < ATT_DEFAULT_MTU)
		ac->mtu = ATT_DEFAULT_MTU;

	/* role 1 == server (peer initiated the exchange). */
	BLUED_PROBE_ATT_MTU(1, client_mtu, server_mtu, ac->mtu);
	LOG_ATT(1, "srv: MTU req client=%d, negotiated=%d", client_mtu, ac->mtu);

	ac->mtu_exchanged = true;
	return (0);
}

static int
handle_find_info(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t start, end;
	ATT_RSP_BUF_DECL(ac);
	int pos, format = 0;
	int pos_limit = (int)ac->mtu;
	int ret;

	if (rsp == NULL)
		return att_send_error(ac, ATT_OP_FIND_INFO_REQ, 0,
		    ATT_ERR_INSUFF_RESOURCES);

	if (len != 5) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_FIND_INFO_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}

	start = get_le16(pdu + 1);
	end = get_le16(pdu + 3);

	if (start == 0 || start > end) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_FIND_INFO_REQ, start,
		    ATT_ERR_INVALID_HANDLE);
	}

	rsp[0] = ATT_OP_FIND_INFO_RSP;
	pos = 2; /* skip opcode + format byte */

	for (int i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];

		if (a->handle < start || a->handle > end)
			continue;

		if (a->uuid16 != 0) {
			if (format == 0)
				format = 1; /* 16-bit */
			else if (format != 1)
				break;
			if (pos + 4 > pos_limit)
				break;
			put_le16(rsp + pos, a->handle);
			put_le16(rsp + pos + 2, a->uuid16);
			pos += 4;
		} else {
			if (format == 0)
				format = 2; /* 128-bit */
			else if (format != 2)
				break;
			if (pos + 18 > pos_limit)
				break;
			put_le16(rsp + pos, a->handle);
			memcpy(rsp + pos + 2, a->uuid128, 16);
			pos += 18;
		}
	}

	if (format == 0) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_FIND_INFO_REQ, start,
		    ATT_ERR_ATTR_NOT_FOUND);
	}

	rsp[1] = (uint8_t)format;
	ret = att_server_send(ac, rsp, pos) == pos ? 0 : -1;
	ATT_RSP_BUF_FREE();
	return (ret);
}

static int
handle_read_by_group_type(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t start, end, uuid16;
	uint8_t uuid128_unused[16];
	ATT_RSP_BUF_DECL(ac);
	int pos, entry_len = 0;
	int pos_limit = (int)ac->mtu;
	size_t uuid_len;
	int ret;

	if (rsp == NULL)
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ, 0,
		    ATT_ERR_INSUFF_RESOURCES);

	/*
	 * Attribute Type is a 2- or 16-octet UUID only (Core Spec Vol 3
	 * Part F §3.4.4.9 / §3.4.4.1 Table 3.15); a 4-octet (UUID32) type
	 * field makes the PDU malformed -> Invalid PDU (0x04).
	 */
	if (len != 7 && len != 21) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}

	start = get_le16(pdu + 1);
	end = get_le16(pdu + 3);

	uuid_len = len - 5;
	if (att_extract_uuid(pdu + 5, uuid_len, &uuid16, uuid128_unused) < 0) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}
	if (uuid16 == 0) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ,
		    start, ATT_ERR_UNSUPPORTED_GROUP_TYPE);
	}

	if (start == 0 || start > end) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ,
		    start, ATT_ERR_INVALID_HANDLE);
	}

	if (uuid16 != GATT_UUID_PRIMARY_SERVICE &&
	    uuid16 != GATT_UUID_SECONDARY_SERVICE) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ,
		    start, ATT_ERR_UNSUPPORTED_GROUP_TYPE);
	}

	rsp[0] = ATT_OP_READ_BY_GROUP_TYPE_RSP;
	pos = 2;

	for (int i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];
		uint16_t grp_end;

		if (a->uuid16 != uuid16)
			continue;
		if (a->handle < start || a->handle > end)
			continue;

		{
			int rerr = att_check_read_perm(a, ac);
			if (rerr != 0) {
				if (entry_len == 0) {
					ATT_RSP_BUF_FREE();
					return att_send_error(ac,
					    ATT_OP_READ_BY_GROUP_TYPE_REQ,
					    a->handle, (uint8_t)rerr);
				}
				break;
			}
		}

		if (a->end_group_handle != 0) {
			grp_end = a->end_group_handle;
		} else {
			grp_end = db->attrs[db->count - 1].handle;
			for (int j = i + 1; j < db->count; j++) {
				if (db->attrs[j].uuid16 ==
				    GATT_UUID_PRIMARY_SERVICE ||
				    db->attrs[j].uuid16 ==
				    GATT_UUID_SECONDARY_SERVICE) {
					grp_end = db->attrs[j - 1].handle;
					break;
				}
			}
		}

		uint16_t vlen = a->value_len;
		if (vlen > (uint16_t)pos_limit - 6)
			vlen = (uint16_t)pos_limit - 6;
		if (vlen > 251)
			vlen = 251;

		if (entry_len == 0)
			entry_len = 4 + vlen;
		else if (entry_len != 4 + (int)vlen)
			break;

		if (pos + entry_len > pos_limit)
			break;

		put_le16(rsp + pos, a->handle);
		put_le16(rsp + pos + 2, grp_end);
		memcpy(rsp + pos + 4, a->value, vlen);
		pos += entry_len;
	}

	if (entry_len == 0) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ,
		    start, ATT_ERR_ATTR_NOT_FOUND);
	}

	rsp[1] = (uint8_t)entry_len;
	ret = att_server_send(ac, rsp, pos) == pos ? 0 : -1;
	ATT_RSP_BUF_FREE();
	return (ret);
}

static int
handle_read_by_type(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t start, end, uuid16;
	uint8_t uuid128[16];
	bool use_uuid128 = false;
	ATT_RSP_BUF_DECL(ac);
	int pos, entry_len = 0;
	int pos_limit = (int)ac->mtu;
	size_t uuid_len;
	int ret;

	if (rsp == NULL)
		return att_send_error(ac, ATT_OP_READ_BY_TYPE_REQ, 0,
		    ATT_ERR_INSUFF_RESOURCES);

	/*
	 * Attribute Type is a 2- or 16-octet UUID only (Core Spec Vol 3
	 * Part F §3.4.4.1 Table 3.15); a 4-octet (UUID32) type field makes
	 * the PDU malformed -> Invalid PDU (0x04).
	 */
	if (len != 7 && len != 21) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BY_TYPE_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}

	start = get_le16(pdu + 1);
	end = get_le16(pdu + 3);

	uuid_len = len - 5;
	if (att_extract_uuid(pdu + 5, uuid_len, &uuid16, uuid128) < 0) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BY_TYPE_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}
	if (uuid16 == 0)
		use_uuid128 = true;

	if (start == 0 || start > end) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BY_TYPE_REQ, start,
		    ATT_ERR_INVALID_HANDLE);
	}

	rsp[0] = ATT_OP_READ_BY_TYPE_RSP;
	pos = 2;

	for (int i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];
		uint16_t vlen;

		if (a->handle < start || a->handle > end)
			continue;
		if (use_uuid128) {
			if (a->uuid16 != 0 ||
			    memcmp(a->uuid128, uuid128, 16) != 0)
				continue;
		} else {
			if (a->uuid16 != uuid16)
				continue;
		}

		{
			int rerr = att_check_read_perm(a, ac);
			if (rerr != 0) {
				if (entry_len == 0) {
					ATT_RSP_BUF_FREE();
					return att_send_error(ac,
					    ATT_OP_READ_BY_TYPE_REQ,
					    a->handle, (uint8_t)rerr);
				}
				break;
			}
		}

		vlen = a->value_len;
		if (vlen > (uint16_t)pos_limit - 4)
			vlen = (uint16_t)pos_limit - 4;
		if (vlen > 253)
			vlen = 253;

		if (entry_len == 0)
			entry_len = 2 + vlen;
		else if (entry_len != 2 + (int)vlen)
			break;

		if (pos + entry_len > pos_limit)
			break;

		put_le16(rsp + pos, a->handle);
		memcpy(rsp + pos + 2, a->value, vlen);
		pos += entry_len;
	}

	if (entry_len == 0) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BY_TYPE_REQ, start,
		    ATT_ERR_ATTR_NOT_FOUND);
	}

	/*
	 * GATT Robust Caching (Core Spec Vol 3 Part G §2.5.2.1, §7.3.1): a
	 * change-unaware client becomes change-aware once it reads the Database
	 * Hash (UUID 0x2B2A).  §7.3 mandates that the hash be read using an
	 * ATT_READ_BY_TYPE_REQ, so this transition must be honoured here and not
	 * only on the plain ATT_READ_REQ path (handle_read).
	 */
	if (!use_uuid128 && uuid16 == 0x2B2A) {
		BLUED_PROBE_ATT_ROBUST_TRANSITION(ac->change_aware, 1, 0x2B2A);
		ac->change_aware = true;
	}

	rsp[1] = (uint8_t)entry_len;
	ret = att_server_send(ac, rsp, pos) == pos ? 0 : -1;
	ATT_RSP_BUF_FREE();
	return (ret);
}

/* ----------------------------------------------------------------
 *  Deferred access (dynamic read / per-access authorization)
 *
 *  When a peer accesses an app-backed attribute the response is withheld and
 *  a single pending access is recorded on the bearer; the owning app resolves
 *  it out-of-line.  The bearer captured at defer time is restored around each
 *  out-of-line send so the response reaches the correct L2CAP channel even
 *  though ac->bearer_fd is only transiently valid during dispatch.
 * ---------------------------------------------------------------- */

static bool
pending_req_has_response(uint8_t req_op)
{

	/* Write Command / Signed Write are unacknowledged (Vol 3 Part F §3.4.5). */
	return (req_op != ATT_OP_WRITE_CMD && req_op != ATT_OP_LEGACY_SIGNED_WRITE_CMD);
}

/* Send an ATT error for the deferred request on its captured bearer. */
static int
pending_send_error(struct att_conn *ac, uint8_t code)
{
	struct att_pending *p = &ac->pending;
	int saved = ac->bearer_fd;
	int ret;

	if (!pending_req_has_response(p->req_op))
		return (0);
	ac->bearer_fd = p->bearer_fd;
	ret = att_send_error(ac, p->req_op, p->handle, code);
	ac->bearer_fd = saved;
	return (ret);
}

/*
 * Complete a deferred read on its captured bearer with the supplied value.
 * The app always returns the full attribute value; the server applies the
 * stored Read-Blob offset and clamps to the bearer MTU (Vol 3 Part F
 * §3.4.4.3-5).
 */
static int
pending_send_read(struct att_conn *ac, const uint8_t *value, uint16_t vlen)
{
	struct att_pending *p = &ac->pending;
	uint16_t mtu = p->bearer_mtu ? p->bearer_mtu : ac->mtu;
	uint8_t stackbuf[ATT_PDU_BUF_SIZE];
	uint8_t *rsp;
	uint16_t rlen;
	int saved = ac->bearer_fd;
	int ret;

	if (mtu < ATT_DEFAULT_MTU)
		mtu = ATT_DEFAULT_MTU;

	if (value == NULL && vlen > 0)
		return pending_send_error(ac, ATT_ERR_UNLIKELY_ERROR);

	/* Blob offset past the value length -> Invalid Offset (§3.4.4.5). */
	if (p->req_op == ATT_OP_READ_BLOB_REQ && p->offset > vlen)
		return pending_send_error(ac, ATT_ERR_INVALID_OFFSET);

	rsp = (mtu > sizeof(stackbuf)) ? malloc(mtu) : stackbuf;
	if (rsp == NULL)
		return pending_send_error(ac, ATT_ERR_INSUFF_RESOURCES);

	rsp[0] = (p->req_op == ATT_OP_READ_BLOB_REQ) ?
	    ATT_OP_READ_BLOB_RSP : ATT_OP_READ_RSP;
	rlen = (uint16_t)(vlen - p->offset);
	if ((uint32_t)1 + rlen > mtu)
		rlen = (uint16_t)(mtu - 1);
	if (rlen > 0 && value != NULL)
		memcpy(rsp + 1, value + p->offset, rlen);

	ac->bearer_fd = p->bearer_fd;
	ret = att_server_send(ac, rsp, 1 + rlen) == 1 + rlen ? 0 : -1;
	ac->bearer_fd = saved;

	if (rsp != stackbuf)
		free(rsp);
	return (ret);
}

/*
 * Record a deferred access on the bearer and start the reply deadline.  A
 * second request while one is already deferred violates the sequential
 * transaction rule (Vol 3 Part F §3.3.3); answer it with Unlikely Error and
 * keep the existing pending intact.  Returns 0 when the access was deferred.
 */
static int
att_begin_defer(struct att_conn *ac, uint8_t kind, uint8_t req_op,
    uint16_t handle, uint16_t offset, int owner_fd)
{
	struct att_pending *p = &ac->pending;
	struct timeval now;

	if (p->kind != ATT_PEND_NONE)
		return att_send_error(ac, req_op, handle,
		    ATT_ERR_UNLIKELY_ERROR);

	memset(p, 0, sizeof(*p));
	p->kind = kind;
	p->req_op = req_op;
	p->handle = handle;
	p->offset = offset;
	p->owner_fd = owner_fd;
	p->bearer_fd = ac->bearer_fd;
	p->bearer_mtu = ac->mtu;
	gettimeofday(&now, NULL);
	p->deadline = now;
	p->deadline.tv_sec += ATT_PENDING_TIMEOUT_SEC;
	return (0);
}

bool
att_server_pending_active(const struct att_conn *ac)
{

	return (ac->pending.kind != ATT_PEND_NONE);
}

uint16_t
att_server_pending_handle(const struct att_conn *ac)
{

	return (ac->pending.handle);
}

int
att_server_pending_owner(const struct att_conn *ac)
{

	return (ac->pending.owner_fd);
}

bool
att_server_pending_is_read(const struct att_conn *ac)
{

	return (ac->pending.kind == ATT_PEND_READ);
}

bool
att_server_pending_is_authorize(const struct att_conn *ac)
{

	return (ac->pending.kind == ATT_PEND_AUTH_READ ||
	    ac->pending.kind == ATT_PEND_AUTH_WRITE);
}

void
att_server_pending_clear(struct att_conn *ac)
{

	ac->pending.kind = ATT_PEND_NONE;
}

int
att_server_complete_read(struct att_conn *ac, const uint8_t *value,
    uint16_t len)
{
	int ret;

	if (ac->pending.kind != ATT_PEND_READ)
		return (0);
	ret = pending_send_read(ac, value, len);
	att_server_pending_clear(ac);
	return (ret);
}

int
att_server_reject_read(struct att_conn *ac, uint8_t att_error)
{
	int ret;

	if (ac->pending.kind != ATT_PEND_READ)
		return (0);
	ret = pending_send_error(ac, att_error);
	att_server_pending_clear(ac);
	return (ret);
}

int
att_server_complete_authorize(struct att_conn *ac, struct att_db *db,
    bool allow)
{
	struct att_pending *p = &ac->pending;
	struct att_attr *a;
	uint8_t kind = p->kind;
	int ret;

	if (kind != ATT_PEND_AUTH_READ && kind != ATT_PEND_AUTH_WRITE)
		return (0);

	if (!allow) {
		/*
		 * Denied: Insufficient Authorization (0x08), Core Spec Vol 3
		 * Part F Table 3.4 / Part G §8.2.
		 */
		ret = pending_send_error(ac, ATT_ERR_INSUFF_AUTHOR);
		att_server_pending_clear(ac);
		return (ret);
	}

	a = attdb_find_by_handle(db, p->handle);
	if (a == NULL) {
		/* Attribute removed while the authorization was outstanding. */
		ret = pending_send_error(ac, ATT_ERR_INVALID_HANDLE);
		att_server_pending_clear(ac);
		return (ret);
	}

	if (kind == ATT_PEND_AUTH_WRITE) {
		uint16_t wlen = p->wlen;
		bool with_response = p->with_response;
		int owner_fd = a->owner_fd;

		if (wlen > a->value_maxlen || a->value == NULL) {
			ret = pending_send_error(ac, ATT_ERR_INVALID_ATTR_LEN);
			att_server_pending_clear(ac);
			return (ret);
		}
		memcpy(a->value, p->wval, wlen);
		a->value_len = wlen;
		if (owner_fd >= 0)
			blued_ctl_notify_write(owner_fd, p->handle, p->wval,
			    wlen);
		ret = 0;
		if (with_response) {
			uint8_t rsp = ATT_OP_WRITE_RSP;
			int saved = ac->bearer_fd;

			ac->bearer_fd = p->bearer_fd;
			ret = att_server_send(ac, &rsp, 1) == 1 ? 0 : -1;
			ac->bearer_fd = saved;
		}
		att_server_pending_clear(ac);
		return (ret);
	}

	/*
	 * Authorized read.  If the attribute is also dynamic, re-defer for the
	 * app to supply the live value; otherwise serve the stored value now.
	 */
	if (a->flags & ATT_ATTR_F_DYNAMIC) {
		uint16_t offset = p->offset;
		int owner_fd = a->owner_fd;

		p->kind = ATT_PEND_READ;
		p->deadline.tv_sec += ATT_PENDING_TIMEOUT_SEC;
		blued_ctl_notify_read(owner_fd, p->handle, offset);
		return (0);
	}

	ret = pending_send_read(ac, a->value, a->value_len);
	att_server_pending_clear(ac);
	return (ret);
}

int
att_server_pending_expire(struct att_conn *ac, const struct timeval *now)
{
	struct att_pending *p = &ac->pending;

	if (p->kind == ATT_PEND_NONE)
		return (0);
	if (now->tv_sec < p->deadline.tv_sec ||
	    (now->tv_sec == p->deadline.tv_sec &&
	    now->tv_usec < p->deadline.tv_usec))
		return (0);

	/*
	 * The app did not answer in time.  Fail the request with Unlikely
	 * Error (Vol 3 Part F §3.4.1.1) and release the bearer; an
	 * unacknowledged Write Command simply gets no response.
	 */
	(void)pending_send_error(ac, ATT_ERR_UNLIKELY_ERROR);
	att_server_pending_clear(ac);
	return (1);
}

static int
handle_read(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t handle;
	struct att_attr *a;
	ATT_RSP_BUF_DECL(ac);
	uint16_t rlen;
	int pos_limit = (int)ac->mtu;
	int ret;

	if (rsp == NULL)
		return att_send_error(ac, ATT_OP_READ_REQ, 0,
		    ATT_ERR_INSUFF_RESOURCES);

	if (len != 3) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}

	handle = get_le16(pdu + 1);
	a = attdb_find_by_handle(db, handle);
	if (a == NULL) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_REQ, handle,
		    ATT_ERR_INVALID_HANDLE);
	}
	{
		int rerr = att_check_read_perm(a, ac);
		if (rerr != 0) {
			ATT_RSP_BUF_FREE();
			return att_send_error(ac, ATT_OP_READ_REQ,
			    handle, (uint8_t)rerr);
		}
	}

	/*
	 * App-backed characteristic: withhold the response and ask the owning
	 * app to authorize and/or supply the value.  Authorization is resolved
	 * first; an authorized read of a dynamic attribute then re-defers for
	 * the live value.
	 */
	if (a->owner_fd >= 0 &&
	    (a->flags & (ATT_ATTR_F_AUTHORIZE | ATT_ATTR_F_DYNAMIC))) {
		int rc;

		if (a->flags & ATT_ATTR_F_AUTHORIZE) {
			rc = att_begin_defer(ac, ATT_PEND_AUTH_READ,
			    ATT_OP_READ_REQ, handle, 0, a->owner_fd);
			if (rc == 0)
				blued_ctl_notify_authorize(a->owner_fd, handle,
				    false, ac);
		} else {
			rc = att_begin_defer(ac, ATT_PEND_READ,
			    ATT_OP_READ_REQ, handle, 0, a->owner_fd);
			if (rc == 0)
				blued_ctl_notify_read(a->owner_fd, handle, 0);
		}
		ATT_RSP_BUF_FREE();
		return (rc);
	}

	rsp[0] = ATT_OP_READ_RSP;

	if (a->uuid16 == GATT_UUID_CCCD) {
		uint8_t cccd_val[2] = { 0, 0 };

		for (int ci = 0; ci < ac->cccd_count; ci++) {
			if (ac->cccds[ci].handle == handle) {
				put_le16(cccd_val, ac->cccds[ci].value);
				break;
			}
		}
		rlen = 2;
		if (1 + rlen > (uint16_t)pos_limit)
			rlen = (uint16_t)pos_limit - 1;
		memcpy(rsp + 1, cccd_val, rlen);
	} else {
		rlen = a->value_len;
		if (1 + rlen > (uint16_t)pos_limit)
			rlen = (uint16_t)pos_limit - 1;
		if (rlen > 0 && a->value != NULL)
			memcpy(rsp + 1, a->value, rlen);
	}
	if (a->uuid16 == 0x2B2A) {
		BLUED_PROBE_ATT_ROBUST_TRANSITION(ac->change_aware, 1, 0x2B2A);
		ac->change_aware = true;
	}

	ret = att_server_send(ac, rsp, 1 + rlen) == 1 + rlen ? 0 : -1;
	ATT_RSP_BUF_FREE();
	return (ret);
}

static int
handle_read_blob(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t handle, offset;
	struct att_attr *a;
	ATT_RSP_BUF_DECL(ac);
	uint16_t rlen;
	int pos_limit = (int)ac->mtu;
	int ret;

	if (rsp == NULL)
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, 0,
		    ATT_ERR_INSUFF_RESOURCES);

	if (len != 5) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}

	handle = get_le16(pdu + 1);
	offset = get_le16(pdu + 3);
	a = attdb_find_by_handle(db, handle);
	if (a == NULL) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, handle,
		    ATT_ERR_INVALID_HANDLE);
	}
	{
		int rerr = att_check_read_perm(a, ac);
		if (rerr != 0) {
			ATT_RSP_BUF_FREE();
			return att_send_error(ac, ATT_OP_READ_BLOB_REQ,
			    handle, (uint8_t)rerr);
		}
	}

	/*
	 * App-backed characteristic: defer as for a plain read, carrying the
	 * blob offset.  The offset is validated against the app-supplied value
	 * when the read completes (pending_send_read).
	 */
	if (a->owner_fd >= 0 &&
	    (a->flags & (ATT_ATTR_F_AUTHORIZE | ATT_ATTR_F_DYNAMIC))) {
		int rc;

		if (a->flags & ATT_ATTR_F_AUTHORIZE) {
			rc = att_begin_defer(ac, ATT_PEND_AUTH_READ,
			    ATT_OP_READ_BLOB_REQ, handle, offset, a->owner_fd);
			if (rc == 0)
				blued_ctl_notify_authorize(a->owner_fd, handle,
				    false, ac);
		} else {
			rc = att_begin_defer(ac, ATT_PEND_READ,
			    ATT_OP_READ_BLOB_REQ, handle, offset, a->owner_fd);
			if (rc == 0)
				blued_ctl_notify_read(a->owner_fd, handle,
				    offset);
		}
		ATT_RSP_BUF_FREE();
		return (rc);
	}

	/*
	 * Core Spec Vol 3 Part F §3.4.4.5: if the value offset is greater
	 * than the length of the attribute value an ATT_ERROR_RSP "shall" be
	 * sent with Invalid Offset (0x07).  The Attribute Not Long (0x0B)
	 * response for a short attribute is only a "may", so the mandatory
	 * offset check must be evaluated first (offset == length is valid and
	 * yields a zero-length response).
	 */
	if (offset > a->value_len) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, handle,
		    ATT_ERR_INVALID_OFFSET);
	}

	if (offset > 0 && a->value_len > 0 &&
	    a->value_len <= ac->mtu - 1) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, handle,
		    ATT_ERR_ATTR_NOT_LONG);
	}

	rsp[0] = ATT_OP_READ_BLOB_RSP;
	rlen = a->value_len - offset;
	if (1 + rlen > (uint16_t)pos_limit)
		rlen = (uint16_t)pos_limit - 1;
	if (rlen > 0 && a->value != NULL)
		memcpy(rsp + 1, a->value + offset, rlen);
	ret = att_server_send(ac, rsp, 1 + rlen) == 1 + rlen ? 0 : -1;
	ATT_RSP_BUF_FREE();
	return (ret);
}

static int
handle_write(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len, bool with_response)
{
	uint16_t handle;
	struct att_attr *a;
	uint16_t vlen;
	uint8_t rsp;

	if (len < 3) {
		if (with_response)
			return att_send_error(ac, ATT_OP_WRITE_REQ, 0,
			    ATT_ERR_INVALID_PDU);
		return (0);
	}

	handle = get_le16(pdu + 1);
	vlen = len - 3;
	a = attdb_find_by_handle(db, handle);
	if (a == NULL) {
		if (with_response)
			return att_send_error(ac, ATT_OP_WRITE_REQ, handle,
			    ATT_ERR_INVALID_HANDLE);
		return (0);
	}
	{
		int werr = att_check_write_perm(a, ac);
		if (werr != 0) {
			if (with_response)
				return att_send_error(ac, ATT_OP_WRITE_REQ,
				    handle, (uint8_t)werr);
			return (0);
		}
	}
	if (vlen > a->value_maxlen || a->value == NULL) {
		if (with_response)
			return att_send_error(ac, ATT_OP_WRITE_REQ, handle,
			    ATT_ERR_INVALID_ATTR_LEN);
		return (0);
	}

	/*
	 * A CCCD (UUID 0x2902) is exactly two octets (Core Spec Vol 3 Part G
	 * §3.3.3.3).  A write of any other length (0 or 1 here — 3+ is already
	 * rejected by the value_maxlen guard) must be rejected with Invalid
	 * Attribute Value Length (0x0D); otherwise it would slip past the
	 * two-octet CCCD path into the generic write branch, corrupting the
	 * stored CCCD length and bypassing the notify/indicate permission
	 * checks.
	 */
	if (a->uuid16 == GATT_UUID_CCCD && vlen != 2) {
		if (with_response)
			return att_send_error(ac, ATT_OP_WRITE_REQ, handle,
			    ATT_ERR_INVALID_ATTR_LEN);
		return (0);
	}

	/*
	 * App-backed characteristic with per-access authorization: withhold the
	 * write, retain its payload, and ask the owning app to allow or deny.
	 * The value is applied (and the Write Response, if any, sent) only when
	 * the app allows it.  Length is already validated above, so an allow
	 * cannot then fail on size.
	 */
	if (a->owner_fd >= 0 && (a->flags & ATT_ATTR_F_AUTHORIZE) &&
	    a->uuid16 != GATT_UUID_CCCD) {
		int rc;

		rc = att_begin_defer(ac, ATT_PEND_AUTH_WRITE,
		    with_response ? ATT_OP_WRITE_REQ : ATT_OP_WRITE_CMD,
		    handle, 0, a->owner_fd);
		if (rc == 0) {
			struct att_pending *p = &ac->pending;

			p->with_response = with_response;
			p->wlen = vlen > ATT_PEND_WVAL_MAX ?
			    ATT_PEND_WVAL_MAX : vlen;
			memcpy(p->wval, pdu + 3, p->wlen);
			blued_ctl_notify_authorize(a->owner_fd, handle, true,
			    ac);
		}
		return (rc);
	}

	if (a->uuid16 == GATT_UUID_CCCD && vlen == 2) {
		uint16_t cccd_val = get_le16(pdu + 3);
		int ci;

		cccd_val &= 0x0003;

		{
			uint8_t char_props = 0;
			bool found_decl = false;

			for (int di = 0; di < db->count; di++) {
				if (db->attrs[di].handle >= handle)
					break;
				if (db->attrs[di].uuid16 ==
				    GATT_UUID_CHARACTERISTIC &&
				    db->attrs[di].value != NULL &&
				    db->attrs[di].value_len >= 1) {
					char_props = db->attrs[di].value[0];
					found_decl = true;
				}
			}

			if (found_decl) {
				if ((cccd_val & GATT_CCCD_NOTIFY) &&
				    !(char_props & GATT_PROP_NOTIFY)) {
					if (with_response)
						return att_send_error(ac,
						    ATT_OP_WRITE_REQ, handle,
						    ATT_ERR_VALUE_NOT_ALLOWED);
					return (0);
				}
				if ((cccd_val & GATT_CCCD_INDICATE) &&
				    !(char_props & GATT_PROP_INDICATE)) {
					if (with_response)
						return att_send_error(ac,
						    ATT_OP_WRITE_REQ, handle,
						    ATT_ERR_VALUE_NOT_ALLOWED);
					return (0);
				}
			} else {
				LOG_ATT(1, "srv: CCCD write handle=%04x: "
				    "no parent characteristic declaration", handle);
				if (with_response)
					return att_send_error(ac, ATT_OP_WRITE_REQ,
					    handle, ATT_ERR_UNLIKELY_ERROR);
				return (0);
			}
		}

		for (ci = 0; ci < ac->cccd_count; ci++) {
			if (ac->cccds[ci].handle == handle) {
				ac->cccds[ci].value = cccd_val;
				break;
			}
		}
		if (ci == ac->cccd_count &&
		    ac->cccd_count < ATT_MAX_CCCDS_PER_CONN) {
			ac->cccds[ac->cccd_count].handle = handle;
			ac->cccds[ac->cccd_count].value = cccd_val;
			ac->cccd_count++;
		} else if (ci == ac->cccd_count) {
			if (with_response)
				return att_send_error(ac, ATT_OP_WRITE_REQ,
				    handle, ATT_ERR_INSUFF_RESOURCES);
			return (0);
		}

		/*
		 * CCCD accepted: value's notify/indicate bits are the peer's
		 * subscription decision for this characteristic.
		 */
		BLUED_PROBE_GATT_CCCD_WRITE(handle, cccd_val);
		LOG_ATT(2, "srv: cccd write handle=%04x value=%04x%s",
		    handle, cccd_val, with_response ? "" : " (cmd)");
	} else {
		memcpy(a->value, pdu + 3, vlen);
		a->value_len = vlen;

		if (a->owner_fd >= 0)
			blued_ctl_notify_write(a->owner_fd, handle,
			    pdu + 3, vlen);

		LOG_ATT(2, "srv: write handle=%04x vlen=%d%s", handle, vlen,
		    with_response ? "" : " (cmd)");

		/*
		 * Client Supported Features write (Core Spec Vol 3 Part G §7.2):
		 * bit 0 is the Robust Caching opt-in.  Writing this bit enables
		 * (or clears) the feature but MUST NOT by itself make the client
		 * change-aware.  Per §2.5.2.1 the initial change-awareness is
		 * derived from the trusted relationship and the Database Hash
		 * comparison at connection setup (see blued_peripheral.c): a
		 * bonded client whose cached database is stale starts
		 * change-unaware and only a Database Hash read (or the Fig 2.6 /
		 * 2.7 transitions) clears that state.  Forcing change_aware here
		 * defeated that and let a stale client skip rediscovery.
		 */
		if (a->uuid16 == 0x2B29 && vlen >= 1) {
			ac->robust_caching =
			    (pdu[3] & ATT_CLIENT_FEAT_ROBUST_CACHING) != 0;
			/*
			 * CSF bit 2 opts the client into Multiple Handle Value
			 * Notifications (Core Spec Vol 3 Part G §7.2): the
			 * server may then coalesce multiple notifications into
			 * a single Multiple HVN PDU.
			 */
			ac->multi_notify =
			    (pdu[3] & ATT_CLIENT_FEAT_MULTI_NOTIFY) != 0;
		}
	}

	if (with_response) {
		rsp = ATT_OP_WRITE_RSP;
		return (att_server_send(ac, &rsp, 1) == 1 ? 0 : -1);
	}
	return (0);
}

/* ----------------------------------------------------------------
 *  Prepare/Execute Write queue (per-connection, in struct att_conn)
 * ---------------------------------------------------------------- */

static int
handle_prepare_write(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t handle, offset, vlen;
	struct att_attr *a;
	struct att_prepare_entry *pe;
	struct att_prepare_queue *pq = &ac->prep_queue;
	ATT_RSP_BUF_DECL(ac);
	int rsplen;
	int pos_limit = (int)ac->mtu;
	int ret;

	if (rsp == NULL)
		return att_send_error(ac, ATT_OP_PREPARE_WRITE_REQ, 0,
		    ATT_ERR_INSUFF_RESOURCES);

	if (len < 5) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_PREPARE_WRITE_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}

	handle = get_le16(pdu + 1);
	offset = get_le16(pdu + 3);
	vlen = len - 5;

	a = attdb_find_by_handle(db, handle);
	if (a == NULL) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_PREPARE_WRITE_REQ, handle,
		    ATT_ERR_INVALID_HANDLE);
	}
	{
		int werr = att_check_write_perm(a, ac);
		if (werr != 0) {
			ATT_RSP_BUF_FREE();
			return att_send_error(ac, ATT_OP_PREPARE_WRITE_REQ,
			    handle, (uint8_t)werr);
		}
	}

	if ((uint32_t)offset + (uint32_t)vlen > UINT16_MAX) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_PREPARE_WRITE_REQ, handle,
		    ATT_ERR_INVALID_OFFSET);
	}

	if (pq->count >= ATT_PREPARE_QUEUE_MAX ||
	    pq->total_bytes + vlen > ATT_PREPARE_QUEUE_MAX_BYTES) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_PREPARE_WRITE_REQ, handle,
		    ATT_ERR_PREPARE_QUEUE_FULL);
	}

	if (vlen > sizeof(pq->entries[0].value)) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_PREPARE_WRITE_REQ, handle,
		    ATT_ERR_INVALID_ATTR_LEN);
	}

	pe = &pq->entries[pq->count++];
	pe->handle = handle;
	pe->offset = offset;
	pe->len = vlen;
	memcpy(pe->value, pdu + 5, vlen);
	pq->total_bytes += vlen;

	rsp[0] = ATT_OP_PREPARE_WRITE_RSP;
	put_le16(rsp + 1, handle);
	put_le16(rsp + 3, offset);
	if (5 + (int)vlen > pos_limit)
		vlen = (uint16_t)(pos_limit - 5);
	memcpy(rsp + 5, pdu + 5, vlen);

	rsplen = 5 + vlen;

	LOG_ATT(2, "srv: prepare write handle=%04x offset=%d vlen=%d queued=%d",
	    handle, offset, vlen, pq->count);

	ret = att_server_send(ac, rsp, rsplen) == rsplen ? 0 : -1;
	ATT_RSP_BUF_FREE();
	return (ret);
}

static int
handle_execute_write(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	struct att_prepare_queue *pq = &ac->prep_queue;
	uint8_t flags;
	uint8_t rsp;
	int i;

	if (len != 2)
		return att_send_error(ac, ATT_OP_EXECUTE_WRITE_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	flags = pdu[1];

	if (flags != ATT_EXECUTE_WRITE_CANCEL &&
	    flags != ATT_EXECUTE_WRITE_COMMIT) {
		pq->count = 0;
		pq->total_bytes = 0;
		return att_send_error(ac, ATT_OP_EXECUTE_WRITE_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}

	if (flags == ATT_EXECUTE_WRITE_COMMIT) {
		/* Validate all entries first before applying */
		for (i = 0; i < pq->count; i++) {
			struct att_prepare_entry *pe = &pq->entries[i];
			struct att_attr *a = attdb_find_by_handle(db, pe->handle);
			int werr;

			if (a == NULL) {
				pq->count = 0;
				pq->total_bytes = 0;
				return att_send_error(ac,
				    ATT_OP_EXECUTE_WRITE_REQ,
				    pe->handle, ATT_ERR_INVALID_HANDLE);
			}
			werr = att_check_write_perm(a, ac);
			if (werr != 0) {
				pq->count = 0;
				pq->total_bytes = 0;
				return att_send_error(ac,
				    ATT_OP_EXECUTE_WRITE_REQ,
				    pe->handle, (uint8_t)werr);
			}
			if (pe->offset > a->value_len) {
				pq->count = 0;
				pq->total_bytes = 0;
				return att_send_error(ac,
				    ATT_OP_EXECUTE_WRITE_REQ,
				    pe->handle, ATT_ERR_INVALID_OFFSET);
			}
			if ((uint32_t)pe->offset + (uint32_t)pe->len >
			    a->value_maxlen) {
				pq->count = 0;
				pq->total_bytes = 0;
				return att_send_error(ac,
				    ATT_OP_EXECUTE_WRITE_REQ,
				    pe->handle, ATT_ERR_INVALID_ATTR_LEN);
			}
			if (a->uuid16 == GATT_UUID_CCCD) {
				uint8_t cccd_buf[2] = { 0, 0 };
				uint16_t cccd_val;
				uint8_t char_props = 0;
				bool found_decl = false;
				int ci, di, j;

				/*
				 * CCCDs are two-octet, per-client values.  Compose every
				 * queued fragment for this handle in a temporary value so
				 * validation is atomic and never mutates the shared DB.
				 */
				if ((uint32_t)pe->offset + pe->len > sizeof(cccd_buf)) {
					pq->count = 0;
					pq->total_bytes = 0;
					return att_send_error(ac,
					    ATT_OP_EXECUTE_WRITE_REQ, pe->handle,
					    ATT_ERR_INVALID_ATTR_LEN);
				}
				for (ci = 0; ci < ac->cccd_count; ci++) {
					if (ac->cccds[ci].handle == pe->handle) {
						put_le16(cccd_buf,
						    ac->cccds[ci].value);
						break;
					}
				}
				if (ci == ac->cccd_count &&
				    ac->cccd_count >= ATT_MAX_CCCDS_PER_CONN) {
					pq->count = 0;
					pq->total_bytes = 0;
					return att_send_error(ac,
					    ATT_OP_EXECUTE_WRITE_REQ, pe->handle,
					    ATT_ERR_INSUFF_RESOURCES);
				}
				for (j = 0; j < pq->count; j++) {
					struct att_prepare_entry *frag =
					    &pq->entries[j];

					if (frag->handle != pe->handle)
						continue;
					if ((uint32_t)frag->offset + frag->len >
					    sizeof(cccd_buf)) {
						pq->count = 0;
						pq->total_bytes = 0;
						return att_send_error(ac,
						    ATT_OP_EXECUTE_WRITE_REQ,
						    pe->handle,
						    ATT_ERR_INVALID_ATTR_LEN);
					}
					memcpy(cccd_buf + frag->offset, frag->value,
					    frag->len);
				}
				cccd_val = get_le16(cccd_buf) & 0x0003;

				cccd_val &= 0x0003;

				for (di = 0; di < db->count; di++) {
					if (db->attrs[di].handle >= pe->handle)
						break;
					if (db->attrs[di].uuid16 ==
					    GATT_UUID_CHARACTERISTIC &&
					    db->attrs[di].value != NULL &&
					    db->attrs[di].value_len >= 1) {
						char_props =
						    db->attrs[di].value[0];
						found_decl = true;
					}
				}

				if (found_decl) {
					if ((cccd_val & GATT_CCCD_NOTIFY) &&
					    !(char_props & GATT_PROP_NOTIFY)) {
						pq->count = 0;
						pq->total_bytes = 0;
						return att_send_error(ac,
						    ATT_OP_EXECUTE_WRITE_REQ,
						    pe->handle,
						    ATT_ERR_VALUE_NOT_ALLOWED);
					}
					if ((cccd_val & GATT_CCCD_INDICATE) &&
					    !(char_props &
					    GATT_PROP_INDICATE)) {
						pq->count = 0;
						pq->total_bytes = 0;
						return att_send_error(ac,
						    ATT_OP_EXECUTE_WRITE_REQ,
						    pe->handle,
						    ATT_ERR_VALUE_NOT_ALLOWED);
					}
				} else {
					pq->count = 0;
					pq->total_bytes = 0;
					return att_send_error(ac,
					    ATT_OP_EXECUTE_WRITE_REQ,
					    pe->handle,
					    ATT_ERR_UNLIKELY_ERROR);
				}
			}
		}

		/* Apply all queued writes. */
		for (i = 0; i < pq->count; i++) {
			struct att_prepare_entry *pe = &pq->entries[i];
			struct att_attr *a = attdb_find_by_handle(db, pe->handle);

			if (a->uuid16 == GATT_UUID_CCCD) {
				uint8_t cccd_buf[2] = { 0, 0 };
				uint16_t cccd_val;
				int ci, j;

				/* Apply a fragmented CCCD only once, at its first entry. */
				for (j = 0; j < i; j++) {
					if (pq->entries[j].handle == pe->handle)
						break;
				}
				if (j != i)
					continue;


				for (ci = 0; ci < ac->cccd_count; ci++) {
					if (ac->cccds[ci].handle ==
					    pe->handle) {
						put_le16(cccd_buf,
						    ac->cccds[ci].value);
						break;
					}
				}
				for (j = i; j < pq->count; j++) {
					struct att_prepare_entry *frag =
					    &pq->entries[j];

					if (frag->handle == pe->handle)
						memcpy(cccd_buf + frag->offset,
						    frag->value, frag->len);
				}
				cccd_val = get_le16(cccd_buf) &
				    (GATT_CCCD_NOTIFY | GATT_CCCD_INDICATE);
				if (ci < ac->cccd_count)
					ac->cccds[ci].value = cccd_val;
				if (ci == ac->cccd_count &&
				    ac->cccd_count <
				    ATT_MAX_CCCDS_PER_CONN) {
					ac->cccds[ac->cccd_count].handle =
					    pe->handle;
					ac->cccds[ac->cccd_count].value =
					    cccd_val;
					ac->cccd_count++;
				}
				continue;
			}

			memcpy(a->value + pe->offset, pe->value, pe->len);
			if ((uint32_t)pe->offset + (uint32_t)pe->len >
			    a->value_len)
				a->value_len =
				    (uint16_t)(pe->offset + pe->len);
		}

		LOG_ATT(2, "srv: execute write applied %d entries",
		    pq->count);
	} else {
		LOG_ATT(2, "srv: execute write cancelled %d entries",
		    pq->count);
	}

	pq->count = 0;
	pq->total_bytes = 0;

	rsp = ATT_OP_EXECUTE_WRITE_RSP;
	return (att_server_send(ac, &rsp, 1) == 1 ? 0 : -1);
}

/* ----------------------------------------------------------------
 *  Find By Type Value (Core Spec Vol 3 Part F 3.4.3.3)
 * ---------------------------------------------------------------- */

static int
handle_find_by_type_value(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t start, end, uuid16;
	ATT_RSP_BUF_DECL(ac);
	int pos;
	int pos_limit = (int)ac->mtu;
	int ret;

	if (rsp == NULL)
		return att_send_error(ac, ATT_OP_FIND_BY_TYPE_VALUE_REQ, 0,
		    ATT_ERR_INSUFF_RESOURCES);

	if (len < 7) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_FIND_BY_TYPE_VALUE_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}

	start = get_le16(pdu + 1);
	end = get_le16(pdu + 3);
	uuid16 = get_le16(pdu + 5);

	if (start == 0 || start > end) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_FIND_BY_TYPE_VALUE_REQ,
		    start, ATT_ERR_INVALID_HANDLE);
	}

	const uint8_t *val = pdu + 7;
	size_t vlen = len - 7;

	rsp[0] = ATT_OP_FIND_BY_TYPE_VALUE_RSP;
	pos = 1;

	for (int i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];
		uint16_t grp_end;

		if (a->handle < start || a->handle > end)
			continue;
		if (a->uuid16 != uuid16)
			continue;

		{
			int rerr = att_check_read_perm(a, ac);
			if (rerr != 0) {
				if (pos == 1) {
					ATT_RSP_BUF_FREE();
					return att_send_error(ac,
					    ATT_OP_FIND_BY_TYPE_VALUE_REQ,
					    a->handle, (uint8_t)rerr);
				}
				break;
			}
		}

		if (a->value_len != vlen ||
		    memcmp(a->value, val, vlen) != 0)
			continue;

		if (uuid16 == GATT_UUID_PRIMARY_SERVICE ||
		    uuid16 == GATT_UUID_SECONDARY_SERVICE) {
			if (a->end_group_handle != 0) {
				grp_end = a->end_group_handle;
			} else {
				grp_end = db->attrs[db->count - 1].handle;
				for (int j = i + 1; j < db->count; j++) {
					if (db->attrs[j].uuid16 ==
					    GATT_UUID_PRIMARY_SERVICE ||
					    db->attrs[j].uuid16 ==
					    GATT_UUID_SECONDARY_SERVICE) {
						grp_end =
						    db->attrs[j - 1].handle;
						break;
					}
				}
			}
		} else {
			grp_end = a->handle;
		}

		if (pos + 4 > pos_limit)
			break;

		put_le16(rsp + pos, a->handle);
		put_le16(rsp + pos + 2, grp_end);
		pos += 4;
	}

	if (pos == 1) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_FIND_BY_TYPE_VALUE_REQ,
		    start, ATT_ERR_ATTR_NOT_FOUND);
	}

	ret = att_server_send(ac, rsp, pos) == pos ? 0 : -1;
	ATT_RSP_BUF_FREE();
	return (ret);
}

/* ----------------------------------------------------------------
 *  Read Multiple (Core Spec Vol 3 Part F 3.4.4.7)
 * ---------------------------------------------------------------- */

static int
handle_read_multiple(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	ATT_RSP_BUF_DECL(ac);
	int pos, nhandles;
	int pos_limit = (int)ac->mtu;
	int ret;

	if (rsp == NULL)
		return att_send_error(ac, ATT_OP_READ_MULTIPLE_REQ, 0,
		    ATT_ERR_INSUFF_RESOURCES);

	if (len < 5 || ((len - 1) % 2) != 0) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_MULTIPLE_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}

	nhandles = (len - 1) / 2;

	rsp[0] = ATT_OP_READ_MULTIPLE_RSP;
	pos = 1;

	for (int i = 0; i < nhandles; i++) {
		uint16_t handle = get_le16(pdu + 1 + i * 2);
		struct att_attr *a = attdb_find_by_handle(db, handle);

		if (a == NULL) {
			ATT_RSP_BUF_FREE();
			return att_send_error(ac, ATT_OP_READ_MULTIPLE_REQ,
			    handle, ATT_ERR_INVALID_HANDLE);
		}
		{
			int rerr = att_check_read_perm(a, ac);
			if (rerr != 0) {
				ATT_RSP_BUF_FREE();
				return att_send_error(ac,
				    ATT_OP_READ_MULTIPLE_REQ,
				    handle, (uint8_t)rerr);
			}
		}

		uint16_t avail = a->value_len;
		if (pos + avail > pos_limit)
			avail = pos_limit - pos;
		if (avail > 0 && a->value != NULL)
			memcpy(rsp + pos, a->value, avail);
		else if (avail > 0)
			memset(rsp + pos, 0, avail);
		pos += avail;

		if (pos >= pos_limit)
			break;
	}

	ret = att_server_send(ac, rsp, pos) == pos ? 0 : -1;
	ATT_RSP_BUF_FREE();
	return (ret);
}

static int
handle_read_multiple_variable(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	ATT_RSP_BUF_DECL(ac);
	int pos, nhandles;
	int pos_limit = (int)ac->mtu;
	int ret;

	if (rsp == NULL)
		return att_send_error(ac, ATT_OP_READ_MULTIPLE_VARIABLE_REQ,
		    0, ATT_ERR_INSUFF_RESOURCES);

	if (len < 5 || ((len - 1) % 2) != 0) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_MULTIPLE_VARIABLE_REQ,
		    0, ATT_ERR_INVALID_PDU);
	}

	nhandles = (len - 1) / 2;

	rsp[0] = ATT_OP_READ_MULTIPLE_VARIABLE_RSP;
	pos = 1;

	for (int i = 0; i < nhandles; i++) {
		uint16_t handle = get_le16(pdu + 1 + i * 2);
		struct att_attr *a = attdb_find_by_handle(db, handle);

		if (a == NULL) {
			ATT_RSP_BUF_FREE();
			return att_send_error(ac,
			    ATT_OP_READ_MULTIPLE_VARIABLE_REQ,
			    handle, ATT_ERR_INVALID_HANDLE);
		}
		{
			int rerr = att_check_read_perm(a, ac);
			if (rerr != 0) {
				ATT_RSP_BUF_FREE();
				return att_send_error(ac,
				    ATT_OP_READ_MULTIPLE_VARIABLE_REQ,
				    handle, (uint8_t)rerr);
			}
		}

		uint16_t vlen = a->value_len;
		uint16_t copylen = vlen;
		if (pos + 2 > pos_limit)
			break;
		/*
		 * Vol 3 Part F §3.4.4.12: the Length field is always the FULL
		 * length of the attribute value; only the Value octets may be
		 * truncated to fit the MTU, so the client can still recover the
		 * true length and re-read.  Do NOT clamp the Length field
		 * itself.
		 */
		if (pos + 2 + copylen > pos_limit)
			copylen = pos_limit - pos - 2;

		put_le16(rsp + pos, vlen);
		pos += 2;
		if (copylen > 0 && a->value != NULL)
			memcpy(rsp + pos, a->value, copylen);
		pos += copylen;

		if (pos >= pos_limit)
			break;
	}

	ret = att_server_send(ac, rsp, pos) == pos ? 0 : -1;
	ATT_RSP_BUF_FREE();
	return (ret);
}

/* ----------------------------------------------------------------
 *  Main request dispatcher
 * ---------------------------------------------------------------- */

int
att_server_handle(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len, int bearer_fd, uint16_t bearer_mtu)
{
	int saved_bearer_fd;
	uint16_t saved_bearer_mtu, eff_mtu;
	int ret;

	if (len == 0)
		return (-1);

	saved_bearer_fd = ac->bearer_fd;
	saved_bearer_mtu = ac->bearer_mtu;
	ac->bearer_fd = bearer_fd;
	ac->bearer_mtu = bearer_mtu;

	eff_mtu = ac->mtu;
	if (bearer_fd >= 0 && bearer_mtu > 0)
		ac->mtu = bearer_mtu;
	/*
	 * Clamp up to the minimum ATT MTU (Core Spec Vol 3 Part F §3.2.8):
	 * callers normally initialize the primary bearer to 23, but the
	 * dispatcher must not trust a zeroed/corrupted att_conn because response
	 * length arithmetic below assumes at least one opcode plus payload room.
	 */
	if (ac->mtu < ATT_DEFAULT_MTU)
		ac->mtu = ATT_DEFAULT_MTU;

	BLUED_PROBE_ATT_RECV(pdu[0], (int)len);

	/* Log incoming ATT request PDU */
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004,
		    pdu, len, true);

	LOG_ATT(1, "srv: %s (0x%02x) len=%zu",
	    att_opcode_name(pdu[0]), pdu[0], len);

	/*
	 * Bounded-timeout backstop for a deferred access: any inbound PDU is an
	 * opportunity to expire a pending read/authorize whose app-reply
	 * deadline has passed, releasing the bearer before processing the new
	 * request.
	 */
	if (ac->pending.kind != ATT_PEND_NONE) {
		struct timeval now;

		gettimeofday(&now, NULL);
		att_server_pending_expire(ac, &now);
	}

	/*
	 * GATT Robust Caching (Core Spec Vol 3 Part G Section 2.5.2.1)
	 *
	 * Change-unaware clients get ATT_ERR_DATABASE_OUT_OF_SYNC for
	 * most operations.  Allowed through:
	 * - ATT_EXCHANGE_MTU (always allowed)
	 * - ATT_READ_BY_TYPE_REQ for Include (0x2802) or Characteristic
	 *   (0x2803) with full range 0x0001-0xFFFF
	 * - ATT_READ_REQ for the Database Hash handle (reading it sets
	 *   change_aware via the handler at line ~428)
	 * - ATT_HANDLE_VALUE_CFM
	 * - Commands (bit 6 set) are silently ignored per spec
	 */
	if (ac->robust_caching && !ac->change_aware) {
		bool allowed = false;

		switch (pdu[0]) {
		case ATT_OP_MTU_REQ:
		case ATT_OP_HANDLE_CFM:
			allowed = true;
			break;
		case ATT_OP_FIND_INFO_REQ:
		case ATT_OP_FIND_BY_TYPE_VALUE_REQ:
		case ATT_OP_READ_BY_GROUP_TYPE_REQ:
			/*
			 * Table 3.43 (Vol 3 Part F §3.4.9) and §3.4.4.9 do NOT
			 * list Database Out Of Sync (0x12) as a valid error for
			 * ATT_FIND_INFORMATION_REQ (0x04),
			 * ATT_FIND_BY_TYPE_VALUE_REQ (0x06) or
			 * ATT_READ_BY_GROUP_TYPE_REQ (0x10).  Robust Caching
			 * (§2.5.2.1) only gates handle/handle-list operations
			 * and non-discovery Read-By-Type; these three must
			 * always pass through the change-unaware gate.
			 */
			allowed = true;
			break;
		case ATT_OP_READ_BY_TYPE_REQ:
			/*
			 * §2.5.2.1: the server sends 0x12 for an
			 * ATT_READ_BY_TYPE_REQ only when the Attribute Type is
			 * other than «Include» (0x2802) or «Characteristic»
			 * (0x2803) AND the handle range is other than
			 * 0x0001-0xFFFF.  By De Morgan the request is allowed
			 * when the type is one of those two OR the range is the
			 * full range (an OR, not an AND).
			 */
			if (len == 7 || len == 21) {
				uint16_t sh = get_le16(pdu + 1);
				uint16_t eh = get_le16(pdu + 3);
				uint16_t uuid = (len == 7) ?
				    get_le16(pdu + 5) : 0;

				if ((uuid == 0x2802 || uuid == 0x2803) ||
				    (sh == 0x0001 && eh == 0xFFFF))
					allowed = true;
			}
			break;
		case ATT_OP_READ_REQ:
			/*
			 * Allow reading Database Hash (sets change_aware
			 * on success in the read handler).
			 */
			if (len == 3) {
				uint16_t h = get_le16(pdu + 1);
				struct att_attr *ra;

				ra = attdb_find_by_handle(db, h);
				if (ra != NULL &&
				    ra->uuid16 == 0x2B2A)
					allowed = true;
			}
			break;
		default:
			/* Commands from a change-unaware client are ignored. */
			if (pdu[0] & ATT_OPCODE_COMMAND_FLAG) {
				ret = 0;
				goto done;
			}
			break;
		}
		if (!allowed) {
			if (ac->out_of_sync_sent) {
				/*
				 * Vol 3 Part G §2.5.2.1 Fig 2.7: the Database
				 * Out Of Sync error was already sent once on
				 * this bearer, so receiving another request
				 * transitions the client to change-aware.  The
				 * error is "sent only once per bearer"; fall
				 * through and process this request normally.
				 */
				ac->change_aware = true;
			} else {
				ac->out_of_sync_sent = true;
				/*
				 * Robust Caching: reject a change-unaware
				 * client's request once with Database Out Of
				 * Sync (Vol 3 Part G §2.5.2.1).
				 */
				BLUED_PROBE_ATT_CACHE_OOS(
				    len >= 3 ? get_le16(pdu + 1) : 0);
				ret = att_send_error(ac, pdu[0],
				    len >= 3 ? get_le16(pdu + 1) : 0,
				    ATT_ERR_DATABASE_OUT_OF_SYNC);
				if (bearer_fd >= 0 && bearer_mtu > 0)
					ac->mtu = eff_mtu;
				ac->bearer_fd = saved_bearer_fd;
				ac->bearer_mtu = saved_bearer_mtu;
				return (ret);
			}
		}
	}

	switch (pdu[0]) {
	case ATT_OP_MTU_REQ:
		if (bearer_fd >= 0) {
			ret = att_send_error(ac, ATT_OP_MTU_REQ, 0,
			    ATT_ERR_REQ_NOT_SUPPORTED);
		} else {
			ret = handle_mtu_req(ac, pdu, len);
		}
		break;
	case ATT_OP_FIND_INFO_REQ:
		ret = handle_find_info(ac, db, pdu, len);
		break;
	case ATT_OP_FIND_BY_TYPE_VALUE_REQ:
		ret = handle_find_by_type_value(ac, db, pdu, len);
		break;
	case ATT_OP_READ_BY_GROUP_TYPE_REQ:
		ret = handle_read_by_group_type(ac, db, pdu, len);
		break;
	case ATT_OP_READ_BY_TYPE_REQ:
		ret = handle_read_by_type(ac, db, pdu, len);
		break;
	case ATT_OP_READ_REQ:
		ret = handle_read(ac, db, pdu, len);
		break;
	case ATT_OP_READ_BLOB_REQ:
		ret = handle_read_blob(ac, db, pdu, len);
		break;
	case ATT_OP_READ_MULTIPLE_REQ:
		ret = handle_read_multiple(ac, db, pdu, len);
		break;
	case ATT_OP_READ_MULTIPLE_VARIABLE_REQ:
		ret = handle_read_multiple_variable(ac, db, pdu, len);
		break;
	case ATT_OP_WRITE_REQ:
		ret = handle_write(ac, db, pdu, len, true);
		break;
	case ATT_OP_WRITE_CMD:
		ret = handle_write(ac, db, pdu, len, false);
		break;
	case ATT_OP_LEGACY_SIGNED_WRITE_CMD:
		if (len < 15) {
			LOG_ATT(1, "srv: Signed Write too short (%zu)", len);
			ret = 0;
		} else if (!ac->has_peer_csrk) {
			LOG_ATT(1, "srv: Signed Write dropped -- "
			    "no peer CSRK available");
			ret = 0;
		} else {
			const uint8_t *sig = pdu + len - 12;
			uint32_t counter = get_le32(sig);
			const uint8_t *mac = sig + 4;
			size_t msg_len = len - 12;

			if (smp_verify_signature(ac->peer_csrk, pdu,
			    msg_len, mac, counter)) {
				if (ac->has_peer_sign_counter &&
				    counter <= ac->peer_sign_counter) {
					LOG_ATT(1, "srv: Signed Write "
					    "replay detected "
					    "(counter=%u, last=%u)",
					    counter,
					    ac->peer_sign_counter);
					ret = 0;
					break;
				}
				if (ac->persist_sign_counter != NULL &&
				    ac->persist_sign_counter(ac, counter) != 0) {
					LOG_ATT(1, "srv: Signed Write dropped -- "
					    "counter persistence failed");
					ret = 0;
					break;
				}
				ac->peer_sign_counter = counter;
				ac->has_peer_sign_counter = true;
				LOG_ATT(1, "srv: Signed Write verified "
				    "(counter=%u)", counter);
				ret = handle_write(ac, db, pdu, msg_len,
				    false);
			} else {
				LOG_ATT(1, "srv: Signed Write signature "
				    "verification failed");
				ret = 0;
			}
		}
		break;
	case ATT_OP_PREPARE_WRITE_REQ:
		ret = handle_prepare_write(ac, db, pdu, len);
		break;
	case ATT_OP_EXECUTE_WRITE_REQ:
		ret = handle_execute_write(ac, db, pdu, len);
		break;
	case ATT_OP_HANDLE_CFM:
		/* A confirmation is exactly its opcode; it has no response. */
		if (len != 1) {
			LOG_ATT(1, "srv: malformed indication confirmation len=%zu", len);
			ret = 0;
			break;
		}
		/*
		 * Robust Caching (Vol 3 Part G §2.5.2.1, Fig 2.6): a
		 * change-unaware client using a single ATT bearer becomes
		 * change-aware when it confirms a Handle Value Indication for
		 * the Service Changed characteristic (UUID 0x2A05).
		 */
		if (ac->robust_caching && !ac->change_aware && ac->ind_pending) {
			struct att_attr *ia;

			ia = attdb_find_by_handle(db, ac->ind_handle);
			if (ia != NULL && ia->uuid16 == 0x2A05)
				ac->change_aware = true;
		}
		ac->ind_pending = false;
		LOG_ATT(2, "srv: received indication confirmation");
		ret = 0;
		break;
	default:
		if (pdu[0] & ATT_OPCODE_COMMAND_FLAG) {
			ret = 0;
		} else {
			ret = att_send_error(ac, pdu[0], 0,
			    ATT_ERR_REQ_NOT_SUPPORTED);
		}
		break;
	}

done:
	/* Restore bearer context */
	if (bearer_fd >= 0 && bearer_mtu > 0)
		ac->mtu = eff_mtu;
	ac->bearer_fd = saved_bearer_fd;
	ac->bearer_mtu = saved_bearer_mtu;
	return (ret);
}

/*
 * Reset ATT server state for a connection.
 */
void
att_server_reset(struct att_conn *ac)
{

	ac->prep_queue.count = 0;
	ac->prep_queue.total_bytes = 0;
	ac->cccd_count = 0;
	ac->mtu_exchanged = false;
	/* A fresh connection has no deferred access outstanding. */
	att_server_pending_clear(ac);
}
