/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATT server — attribute database and request dispatcher for BLE
 * peripheral mode.  Handles incoming ATT requests from a connected
 * central and sends responses.
 *
 * Core Spec Vol 3 Part F (Attribute Protocol).
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"

/* ----------------------------------------------------------------
 *  Value storage helper
 * ---------------------------------------------------------------- */

static uint8_t *
val_alloc(struct att_db *db, uint16_t len)
{
	uint8_t *p;

	if (db->val_used + len > db->val_size)
		return (NULL);
	p = db->val_store + db->val_used;
	db->val_used += len;
	return (p);
}

/* ----------------------------------------------------------------
 *  Database construction
 * ---------------------------------------------------------------- */

void
attdb_init(struct att_db *db, struct att_attr *storage, int max,
    uint8_t *val_buf, size_t val_size)
{

	memset(db, 0, sizeof(*db));
	db->attrs = storage;
	db->max = max;
	db->next_handle = 0x0001;
	db->val_store = val_buf;
	db->val_size = val_size;
	memset(storage, 0, max * sizeof(*storage));
}

static struct att_attr *
attdb_alloc(struct att_db *db)
{
	struct att_attr *a;

	if (db->count >= db->max)
		return (NULL);
	a = &db->attrs[db->count++];
	a->handle = db->next_handle++;
	return (a);
}

/*
 * Add a Primary Service declaration (UUID 0x2800).
 * Returns the handle of the service declaration.
 */
uint16_t
attdb_add_service(struct att_db *db, uint16_t uuid16)
{
	struct att_attr *a;
	uint8_t *v;

	a = attdb_alloc(db);
	if (a == NULL)
		return (0);
	a->uuid16 = GATT_UUID_PRIMARY_SERVICE;
	a->perms = ATT_PERM_READ;
	v = val_alloc(db, 2);
	if (v == NULL)
		return (0);
	put_le16(v, uuid16);
	a->value = v;
	a->value_len = 2;
	return (a->handle);
}

/*
 * Add a Characteristic declaration (UUID 0x2803) + value attribute.
 * Returns the value handle.
 */
uint16_t
attdb_add_characteristic(struct att_db *db, uint16_t uuid16,
    uint8_t props, uint8_t perms, const void *value, uint16_t len)
{
	struct att_attr *decl, *val_attr;
	uint8_t *dv, *vv;

	/* Declaration: [properties(1), value_handle(2), uuid(2)] = 5 bytes */
	decl = attdb_alloc(db);
	if (decl == NULL)
		return (0);
	decl->uuid16 = GATT_UUID_CHARACTERISTIC;
	decl->perms = ATT_PERM_READ;
	dv = val_alloc(db, 5);
	if (dv == NULL)
		return (0);
	dv[0] = props;
	put_le16(dv + 1, db->next_handle); /* value handle = next */
	put_le16(dv + 3, uuid16);
	decl->value = dv;
	decl->value_len = 5;

	/* Value attribute */
	val_attr = attdb_alloc(db);
	if (val_attr == NULL)
		return (0);
	val_attr->uuid16 = uuid16;
	val_attr->perms = perms;
	if (len > 0) {
		vv = val_alloc(db, len);
		if (vv == NULL)
			return (0);
		memcpy(vv, value, len);
		val_attr->value = vv;
		val_attr->value_len = len;
		val_attr->value_maxlen = len;
	}
	return (val_attr->handle);
}

/*
 * Add a Client Characteristic Configuration Descriptor (0x2902).
 * 2 bytes, writable, default 0x0000.
 */
uint16_t
attdb_add_cccd(struct att_db *db)
{
	struct att_attr *a;
	uint8_t *v;

	a = attdb_alloc(db);
	if (a == NULL)
		return (0);
	a->uuid16 = GATT_UUID_CCCD;
	a->perms = ATT_PERM_READ | ATT_PERM_WRITE;
	v = val_alloc(db, 2);
	if (v == NULL)
		return (0);
	v[0] = 0;
	v[1] = 0;
	a->value = v;
	a->value_len = 2;
	a->value_maxlen = 2;
	return (a->handle);
}

/* ----------------------------------------------------------------
 *  Lookup helpers
 * ---------------------------------------------------------------- */

static struct att_attr *
attdb_find(struct att_db *db, uint16_t handle)
{
	int lo = 0, hi = db->count - 1;

	/* Handles are sequential, so direct index works */
	for (int i = lo; i <= hi; i++) {
		if (db->attrs[i].handle == handle)
			return (&db->attrs[i]);
	}
	return (NULL);
}

/* ----------------------------------------------------------------
 *  Response senders
 * ---------------------------------------------------------------- */

int
att_send_error(struct att_conn *ac, uint8_t req_op,
    uint16_t handle, uint8_t code)
{
	uint8_t pdu[5];

	pdu[0] = ATT_OP_ERROR_RSP;
	pdu[1] = req_op;
	put_le16(pdu + 2, handle);
	pdu[4] = code;
	return (send(ac->fd, pdu, 5, 0) == 5 ? 0 : -1);
}

int
att_send_notification(struct att_conn *ac, uint16_t handle,
    const void *value, uint16_t len)
{
	uint8_t pdu[ATT_MAX_MTU];
	uint16_t pdulen;

	if (len > ATT_MAX_MTU - 3)
		len = ATT_MAX_MTU - 3;
	pdulen = 3 + len;
	if (pdulen > ac->mtu)
		pdulen = ac->mtu;
	pdu[0] = ATT_OP_HANDLE_NOTIFY;
	put_le16(pdu + 1, handle);
	memcpy(pdu + 3, value, pdulen - 3);
	return (send(ac->fd, pdu, pdulen, 0) == pdulen ? 0 : -1);
}

/* ----------------------------------------------------------------
 *  Request handlers
 * ---------------------------------------------------------------- */

static int
handle_mtu_req(struct att_conn *ac, const uint8_t *pdu, size_t len)
{
	uint16_t client_mtu, server_mtu;
	uint8_t rsp[3];

	if (len < 3)
		return att_send_error(ac, ATT_OP_MTU_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	client_mtu = get_le16(pdu + 1);
	server_mtu = ATT_MAX_MTU;

	rsp[0] = ATT_OP_MTU_RSP;
	put_le16(rsp + 1, server_mtu);
	if (send(ac->fd, rsp, 3, 0) != 3)
		return (-1);

	ac->mtu = client_mtu < server_mtu ? client_mtu : server_mtu;
	if (ac->mtu < ATT_DEFAULT_MTU)
		ac->mtu = ATT_DEFAULT_MTU;

	DBG("ATT srv: MTU req client=%d, negotiated=%d", client_mtu, ac->mtu);

	return (0);
}

static int
handle_find_info(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t start, end;
	uint8_t rsp[ATT_MAX_MTU];
	int pos, format = 0;

	if (len < 5)
		return att_send_error(ac, ATT_OP_FIND_INFO_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	start = get_le16(pdu + 1);
	end = get_le16(pdu + 3);

	if (start == 0 || start > end)
		return att_send_error(ac, ATT_OP_FIND_INFO_REQ, start,
		    ATT_ERR_INVALID_HANDLE);

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
			if (pos + 4 > (int)ac->mtu)
				break;
			put_le16(rsp + pos, a->handle);
			put_le16(rsp + pos + 2, a->uuid16);
			pos += 4;
		} else {
			if (format == 0)
				format = 2; /* 128-bit */
			else if (format != 2)
				break;
			if (pos + 18 > (int)ac->mtu)
				break;
			put_le16(rsp + pos, a->handle);
			memcpy(rsp + pos + 2, a->uuid128, 16);
			pos += 18;
		}
	}

	if (format == 0)
		return att_send_error(ac, ATT_OP_FIND_INFO_REQ, start,
		    ATT_ERR_ATTR_NOT_FOUND);

	rsp[1] = (uint8_t)format;
	return (send(ac->fd, rsp, pos, 0) == pos ? 0 : -1);
}

static int
handle_read_by_group_type(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t start, end, uuid16;
	uint8_t rsp[ATT_MAX_MTU];
	int pos, entry_len = 0;

	/* Accept 7 bytes (16-bit UUID) or 21 bytes (128-bit UUID) */
	if (len != 7 && len != 21)
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	start = get_le16(pdu + 1);
	end = get_le16(pdu + 3);

	/* Extract 16-bit UUID; accept 128-bit Bluetooth Base UUID form */
	if (len == 21) {
		static const uint8_t base_le[12] = {
			0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00,
			0x00, 0x80, 0x00, 0x10, 0x00, 0x00
		};
		if (memcmp(pdu + 5, base_le, 12) != 0 ||
		    pdu[19] != 0x00 || pdu[20] != 0x00)
			return att_send_error(ac,
			    ATT_OP_READ_BY_GROUP_TYPE_REQ,
			    start, ATT_ERR_UNSUPPORTED_GROUP_TYPE);
		uuid16 = get_le16(pdu + 17);
	} else {
		uuid16 = get_le16(pdu + 5);
	}

	if (start == 0 || start > end)
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ,
		    start, ATT_ERR_INVALID_HANDLE);

	/* Only Primary Service (0x2800) is a grouping type */
	if (uuid16 != GATT_UUID_PRIMARY_SERVICE)
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ,
		    start, ATT_ERR_UNSUPPORTED_GROUP_TYPE);

	rsp[0] = ATT_OP_READ_BY_GROUP_TYPE_RSP;
	pos = 2; /* skip opcode + length byte */

	for (int i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];
		uint16_t grp_end;

		if (a->uuid16 != GATT_UUID_PRIMARY_SERVICE)
			continue;
		if (a->handle < start || a->handle > end)
			continue;

		/* Find end of this service group */
		grp_end = 0xFFFF;
		for (int j = i + 1; j < db->count; j++) {
			if (db->attrs[j].uuid16 == GATT_UUID_PRIMARY_SERVICE) {
				grp_end = db->attrs[j - 1].handle;
				break;
			}
		}

		/* Clamp value to min(ATT_MTU-6, 251) per spec §3.4.4.10 */
		uint16_t vlen = a->value_len;
		if (vlen > ac->mtu - 6)
			vlen = ac->mtu - 6;
		if (vlen > 251)
			vlen = 251;

		/* entry: [handle(2), end_group(2), value(vlen)] */
		if (entry_len == 0)
			entry_len = 4 + vlen;
		else if (entry_len != 4 + (int)vlen)
			break;

		if (pos + entry_len > (int)ac->mtu)
			break;

		put_le16(rsp + pos, a->handle);
		put_le16(rsp + pos + 2, grp_end);
		memcpy(rsp + pos + 4, a->value, vlen);
		pos += entry_len;
	}

	if (entry_len == 0)
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ,
		    start, ATT_ERR_ATTR_NOT_FOUND);

	rsp[1] = (uint8_t)entry_len;
	return (send(ac->fd, rsp, pos, 0) == pos ? 0 : -1);
}

static int
handle_read_by_type(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t start, end, uuid16;
	uint8_t rsp[ATT_MAX_MTU];
	int pos, entry_len = 0;

	/* Accept 7 bytes (16-bit UUID) or 21 bytes (128-bit UUID) */
	if (len != 7 && len != 21)
		return att_send_error(ac, ATT_OP_READ_BY_TYPE_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	start = get_le16(pdu + 1);
	end = get_le16(pdu + 3);

	/* Extract 16-bit UUID; accept 128-bit Bluetooth Base UUID form */
	if (len == 21) {
		static const uint8_t base_le[12] = {
			0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00,
			0x00, 0x80, 0x00, 0x10, 0x00, 0x00
		};
		if (memcmp(pdu + 5, base_le, 12) != 0 ||
		    pdu[19] != 0x00 || pdu[20] != 0x00)
			return att_send_error(ac, ATT_OP_READ_BY_TYPE_REQ,
			    start, ATT_ERR_ATTR_NOT_FOUND);
		uuid16 = get_le16(pdu + 17);
	} else {
		uuid16 = get_le16(pdu + 5);
	}

	if (start == 0 || start > end)
		return att_send_error(ac, ATT_OP_READ_BY_TYPE_REQ, start,
		    ATT_ERR_INVALID_HANDLE);

	rsp[0] = ATT_OP_READ_BY_TYPE_RSP;
	pos = 2;

	for (int i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];
		uint16_t vlen;

		if (a->handle < start || a->handle > end)
			continue;
		if (a->uuid16 != uuid16)
			continue;

		/* Check read permission (spec Vol 3 Part F 3.4.4.1) */
		if (!(a->perms & (ATT_PERM_READ | ATT_PERM_READ_ENCRYPT))) {
			if (entry_len == 0) {
				/* First match is unreadable: error */
				return att_send_error(ac,
				    ATT_OP_READ_BY_TYPE_REQ, a->handle,
				    ATT_ERR_READ_NOT_PERMITTED);
			}
			/* Had entries already: return what we have */
			break;
		}

		/* Clamp value to min(ATT_MTU-4, 253) per spec §3.4.4.2 */
		vlen = a->value_len;
		if (vlen > ac->mtu - 4)
			vlen = ac->mtu - 4;
		if (vlen > 253)
			vlen = 253;

		if (entry_len == 0)
			entry_len = 2 + vlen;
		else if (entry_len != 2 + (int)vlen)
			break;

		if (pos + entry_len > (int)ac->mtu)
			break;

		put_le16(rsp + pos, a->handle);
		memcpy(rsp + pos + 2, a->value, vlen);
		pos += entry_len;
	}

	if (entry_len == 0)
		return att_send_error(ac, ATT_OP_READ_BY_TYPE_REQ, start,
		    ATT_ERR_ATTR_NOT_FOUND);

	rsp[1] = (uint8_t)entry_len;
	return (send(ac->fd, rsp, pos, 0) == pos ? 0 : -1);
}

static int
handle_read(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t handle;
	struct att_attr *a;
	uint8_t rsp[ATT_MAX_MTU];
	uint16_t rlen;

	if (len < 3)
		return att_send_error(ac, ATT_OP_READ_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	handle = get_le16(pdu + 1);
	a = attdb_find(db, handle);
	if (a == NULL)
		return att_send_error(ac, ATT_OP_READ_REQ, handle,
		    ATT_ERR_INVALID_HANDLE);
	if (!(a->perms & (ATT_PERM_READ | ATT_PERM_READ_ENCRYPT)))
		return att_send_error(ac, ATT_OP_READ_REQ, handle,
		    ATT_ERR_READ_NOT_PERMITTED);

	rsp[0] = ATT_OP_READ_RSP;
	rlen = a->value_len;
	if (1 + rlen > ac->mtu)
		rlen = ac->mtu - 1;
	memcpy(rsp + 1, a->value, rlen);
	return (send(ac->fd, rsp, 1 + rlen, 0) == 1 + rlen ? 0 : -1);
}

static int
handle_read_blob(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t handle, offset;
	struct att_attr *a;
	uint8_t rsp[ATT_MAX_MTU];
	uint16_t rlen;

	if (len < 5)
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	handle = get_le16(pdu + 1);
	offset = get_le16(pdu + 3);
	a = attdb_find(db, handle);
	if (a == NULL)
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, handle,
		    ATT_ERR_INVALID_HANDLE);
	if (!(a->perms & (ATT_PERM_READ | ATT_PERM_READ_ENCRYPT)))
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, handle,
		    ATT_ERR_READ_NOT_PERMITTED);
	if (offset > a->value_len)
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, handle,
		    ATT_ERR_INVALID_OFFSET);

	rsp[0] = ATT_OP_READ_BLOB_RSP;
	rlen = a->value_len - offset;
	if (1 + rlen > ac->mtu)
		rlen = ac->mtu - 1;
	memcpy(rsp + 1, a->value + offset, rlen);
	return (send(ac->fd, rsp, 1 + rlen, 0) == 1 + rlen ? 0 : -1);
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
		return (0); /* Write Command: silently ignore */
	}

	handle = get_le16(pdu + 1);
	vlen = len - 3;
	a = attdb_find(db, handle);
	if (a == NULL) {
		if (with_response)
			return att_send_error(ac, ATT_OP_WRITE_REQ, handle,
			    ATT_ERR_INVALID_HANDLE);
		return (0);
	}
	if (!(a->perms & (ATT_PERM_WRITE | ATT_PERM_WRITE_ENCRYPT))) {
		if (with_response)
			return att_send_error(ac, ATT_OP_WRITE_REQ, handle,
			    ATT_ERR_WRITE_NOT_PERMITTED);
		return (0);
	}
	if (vlen > a->value_maxlen) {
		if (with_response)
			return att_send_error(ac, ATT_OP_WRITE_REQ, handle,
			    ATT_ERR_INVALID_ATTR_LEN);
		return (0);
	}

	memcpy(a->value, pdu + 3, vlen);
	a->value_len = vlen;

	DBG("ATT srv: write handle=%04x vlen=%d%s", handle, vlen,
	    with_response ? "" : " (cmd)");

	if (with_response) {
		rsp = ATT_OP_WRITE_RSP;
		return (send(ac->fd, &rsp, 1, 0) == 1 ? 0 : -1);
	}
	return (0);
}

/* ----------------------------------------------------------------
 *  Main request dispatcher
 * ---------------------------------------------------------------- */

int
att_server_handle(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{

	if (len == 0)
		return (-1);

	DBG("ATT srv: opcode=%02x len=%zu", pdu[0], len);

	switch (pdu[0]) {
	case ATT_OP_MTU_REQ:
		return handle_mtu_req(ac, pdu, len);
	case ATT_OP_FIND_INFO_REQ:
		return handle_find_info(ac, db, pdu, len);
	case ATT_OP_READ_BY_GROUP_TYPE_REQ:
		return handle_read_by_group_type(ac, db, pdu, len);
	case ATT_OP_READ_BY_TYPE_REQ:
		return handle_read_by_type(ac, db, pdu, len);
	case ATT_OP_READ_REQ:
		return handle_read(ac, db, pdu, len);
	case ATT_OP_READ_BLOB_REQ:
		return handle_read_blob(ac, db, pdu, len);
	case ATT_OP_WRITE_REQ:
		return handle_write(ac, db, pdu, len, true);
	case ATT_OP_WRITE_CMD:
		return handle_write(ac, db, pdu, len, false);
	default:
		return att_send_error(ac, pdu[0], 0,
		    ATT_ERR_REQ_NOT_SUPPORTED);
	}
}
