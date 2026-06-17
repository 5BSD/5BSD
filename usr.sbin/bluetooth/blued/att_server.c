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

#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "blued_probes.h"
#include "hci_log.h"

/* ----------------------------------------------------------------
 *  Logged send helper — logs outgoing ATT PDU to BTSnoop
 * ---------------------------------------------------------------- */

static ssize_t
att_server_send(struct att_conn *ac, const void *buf, size_t len)
{
	BLUED_PROBE_ATT_SEND(((const uint8_t *)buf)[0], (int)len);
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004,
		    buf, (uint16_t)len, false);
	return (send(ac->fd, buf, len, 0));
}

/* ----------------------------------------------------------------
 *  UUID extraction helper
 *
 *  ATT PDUs may carry UUIDs in 16-bit (2 byte), 32-bit (4 byte),
 *  or 128-bit (16 byte) form.  This helper extracts any form and
 *  normalises it: if the UUID is in the Bluetooth Base UUID range
 *  the 16-bit short form is returned in *uuid16_out; otherwise
 *  *uuid16_out is set to 0 and uuid128_out is filled.
 *
 *  Returns 0 on success, -1 if uuid_len is not 2/4/16.
 * ---------------------------------------------------------------- */

static int
att_extract_uuid(const uint8_t *data, size_t uuid_len,
    uint16_t *uuid16_out, uint8_t uuid128_out[16])
{
	switch (uuid_len) {
	case 2:
		*uuid16_out = get_le16(data);
		return (0);
	case 4: {
		/*
		 * 32-bit UUID: if upper 16 bits are zero, collapse to
		 * 16-bit short form.  Otherwise expand to 128-bit
		 * Bluetooth Base UUID.
		 */
		uint32_t u32 = (uint32_t)data[0] |
		    ((uint32_t)data[1] << 8) |
		    ((uint32_t)data[2] << 16) |
		    ((uint32_t)data[3] << 24);
		if ((u32 & 0xFFFF0000) == 0) {
			*uuid16_out = (uint16_t)u32;
		} else {
			*uuid16_out = 0;
			/* Build 128-bit: base[0..11] + u32_le[0..3] */
			memcpy(uuid128_out, bt_base_uuid_le, 12);
			memcpy(uuid128_out + 12, data, 4);
		}
		return (0);
	}
	case 16:
		/*
		 * 128-bit UUID: check if it is a Bluetooth Base UUID
		 * and extract the 16-bit short form if so.
		 */
		if (memcmp(data, bt_base_uuid_le, 12) == 0 &&
		    data[14] == 0x00 && data[15] == 0x00) {
			*uuid16_out = get_le16(data + 12);
		} else {
			*uuid16_out = 0;
			memcpy(uuid128_out, data, 16);
		}
		return (0);
	default:
		return (-1);
	}
}

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
	if (v == NULL) {
		db->count--;
		return (0);
	}
	put_le16(v, uuid16);
	a->value = v;
	a->value_len = 2;
	return (a->handle);
}

/*
 * Add a Primary Service declaration with a 128-bit UUID.
 */
uint16_t
attdb_add_service128(struct att_db *db, const uint8_t uuid128[16])
{
	struct att_attr *a;
	uint8_t *v;

	a = attdb_alloc(db);
	if (a == NULL)
		return (0);
	a->uuid16 = GATT_UUID_PRIMARY_SERVICE;
	a->perms = ATT_PERM_READ;
	v = val_alloc(db, 16);
	if (v == NULL)
		return (0);
	memcpy(v, uuid128, 16);
	a->value = v;
	a->value_len = 16;
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
 * Add a Characteristic declaration + value attribute with a 128-bit UUID.
 * The declaration value is [properties(1), value_handle(2), uuid128(16)] = 19.
 * Returns the value handle.
 */
uint16_t
attdb_add_characteristic128(struct att_db *db, const uint8_t uuid128[16],
    uint8_t props, uint8_t perms, const void *value, uint16_t len)
{
	struct att_attr *decl, *val_attr;
	uint8_t *dv, *vv;

	/* Declaration: [properties(1), value_handle(2), uuid128(16)] = 19 */
	decl = attdb_alloc(db);
	if (decl == NULL)
		return (0);
	decl->uuid16 = GATT_UUID_CHARACTERISTIC;
	decl->perms = ATT_PERM_READ;
	dv = val_alloc(db, 19);
	if (dv == NULL)
		return (0);
	dv[0] = props;
	put_le16(dv + 1, db->next_handle); /* value handle = next */
	memcpy(dv + 3, uuid128, 16);
	decl->value = dv;
	decl->value_len = 19;

	/* Value attribute — uses 128-bit UUID */
	val_attr = attdb_alloc(db);
	if (val_attr == NULL)
		return (0);
	val_attr->uuid16 = 0;
	memcpy(val_attr->uuid128, uuid128, 16);
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

	/* Linear scan over the attribute array */
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

	return (att_server_send(ac, pdu, 5) == 5 ? 0 : -1);
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

	BLUED_PROBE_ATT_SEND(ATT_OP_HANDLE_NOTIFY, (int)pdulen);

	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004, pdu, pdulen, false);

	return (send(ac->fd, pdu, pdulen, 0) == pdulen ? 0 : -1);
}

/*
 * Send Multiple Handle Value Notification (Core Spec Vol 3 Part F 3.4.7.5)
 *
 * BT 5.2 ATT_MULTIPLE_HANDLE_VALUE_NTF (opcode 0x23): packs multiple
 * handle-value tuples into a single PDU.
 * Format: opcode(1) + [handle(2) + length(2) + value(length)]*
 * Total truncated to MTU.
 */
int
att_send_multiple_handle_value_ntf(struct att_conn *ac,
    const uint16_t *handles, const uint8_t **values,
    const uint16_t *lengths, int count)
{
	uint8_t pdu[ATT_MAX_MTU];
	uint16_t pos;
	int i;

	if (count <= 0)
		return (0);

	pdu[0] = ATT_OP_MULTIPLE_HANDLE_VALUE_NTF;
	pos = 1;

	for (i = 0; i < count; i++) {
		/* Each entry: handle(2) + length(2) + value(length) */
		uint32_t entry_len = 4 + (uint32_t)lengths[i];

		if (pos + entry_len > sizeof(pdu))
			break;
		if (pos + entry_len > ac->mtu)
			break;

		put_le16(pdu + pos, handles[i]);
		put_le16(pdu + pos + 2, lengths[i]);
		memcpy(pdu + pos + 4, values[i], lengths[i]);
		pos += entry_len;
	}

	if (i == 0) {
		/* Could not fit even one entry */
		return (0);
	}

	LOG_ATT(2, "srv: multi handle value ntf count=%d/%d len=%d",
	    i, count, pos);

	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004, pdu, pos, false);

	return (send(ac->fd, pdu, pos, 0) == pos ? 0 : -1);
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
	if (att_server_send(ac, rsp, 3) != 3)
		return (-1);

	ac->mtu = client_mtu < server_mtu ? client_mtu : server_mtu;
	if (ac->mtu < ATT_DEFAULT_MTU)
		ac->mtu = ATT_DEFAULT_MTU;

	LOG_ATT(1, "srv: MTU req client=%d, negotiated=%d", client_mtu, ac->mtu);

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
	return (att_server_send(ac, rsp, pos) == pos ? 0 : -1);
}

static int
handle_read_by_group_type(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t start, end, uuid16;
	uint8_t uuid128_unused[16];
	uint8_t rsp[ATT_MAX_MTU];
	int pos, entry_len = 0;
	size_t uuid_len;

	/* Accept 7 (16-bit), 9 (32-bit), or 21 (128-bit UUID) bytes */
	if (len != 7 && len != 9 && len != 21)
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	start = get_le16(pdu + 1);
	end = get_le16(pdu + 3);

	/* Extract UUID; Read By Group Type only supports grouping UUIDs
	 * (Primary Service 0x2800, Secondary Service 0x2801) which are
	 * 16-bit — reject if the UUID is a vendor 128-bit UUID. */
	uuid_len = len - 5;
	if (att_extract_uuid(pdu + 5, uuid_len, &uuid16, uuid128_unused) < 0)
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	if (uuid16 == 0)
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ,
		    start, ATT_ERR_UNSUPPORTED_GROUP_TYPE);

	if (start == 0 || start > end)
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ,
		    start, ATT_ERR_INVALID_HANDLE);

	/* Primary (0x2800) and Secondary (0x2801) are valid grouping types
	 * per Core Spec Vol 3 Part G Section 2.5.3 */
	if (uuid16 != GATT_UUID_PRIMARY_SERVICE &&
	    uuid16 != GATT_UUID_SECONDARY_SERVICE)
		return att_send_error(ac, ATT_OP_READ_BY_GROUP_TYPE_REQ,
		    start, ATT_ERR_UNSUPPORTED_GROUP_TYPE);

	rsp[0] = ATT_OP_READ_BY_GROUP_TYPE_RSP;
	pos = 2; /* skip opcode + length byte */

	for (int i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];
		uint16_t grp_end;

		if (a->uuid16 != uuid16)
			continue;
		if (a->handle < start || a->handle > end)
			continue;

		/* Check read permission (spec Vol 3 Part F §3.4.4.9) */
		if (!(a->perms & (ATT_PERM_READ | ATT_PERM_READ_ENCRYPT))) {
			if (entry_len == 0)
				return att_send_error(ac,
				    ATT_OP_READ_BY_GROUP_TYPE_REQ,
				    a->handle, ATT_ERR_READ_NOT_PERMITTED);
			break;
		}
		if ((a->perms & ATT_PERM_READ_ENCRYPT) &&
		    !(a->perms & ATT_PERM_READ) && !ac->encrypted) {
			if (entry_len == 0)
				return att_send_error(ac,
				    ATT_OP_READ_BY_GROUP_TYPE_REQ,
				    a->handle, ATT_ERR_INSUFF_ENCRYPTION);
			break;
		}

		/* Find end of this service group — ends before the
		 * next service declaration (Primary or Secondary) */
		grp_end = db->attrs[db->count - 1].handle;
		for (int j = i + 1; j < db->count; j++) {
			if (db->attrs[j].uuid16 == GATT_UUID_PRIMARY_SERVICE ||
			    db->attrs[j].uuid16 == GATT_UUID_SECONDARY_SERVICE) {
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
	return (att_server_send(ac, rsp, pos) == pos ? 0 : -1);
}

static int
handle_read_by_type(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint16_t start, end, uuid16;
	uint8_t uuid128[16];
	bool use_uuid128 = false;
	uint8_t rsp[ATT_MAX_MTU];
	int pos, entry_len = 0;
	size_t uuid_len;

	/* Accept 7 (16-bit), 9 (32-bit), or 21 (128-bit UUID) bytes */
	if (len != 7 && len != 9 && len != 21)
		return att_send_error(ac, ATT_OP_READ_BY_TYPE_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	start = get_le16(pdu + 1);
	end = get_le16(pdu + 3);

	/* Extract UUID in any of the three BT UUID forms */
	uuid_len = len - 5;
	if (att_extract_uuid(pdu + 5, uuid_len, &uuid16, uuid128) < 0)
		return att_send_error(ac, ATT_OP_READ_BY_TYPE_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	if (uuid16 == 0)
		use_uuid128 = true;

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
		/* Match by 128-bit vendor UUID or 16-bit UUID */
		if (use_uuid128) {
			if (a->uuid16 != 0 ||
			    memcmp(a->uuid128, uuid128, 16) != 0)
				continue;
		} else {
			if (a->uuid16 != uuid16)
				continue;
		}

		/* Check read permission (spec Vol 3 Part F 3.4.4.1) */
		if (!(a->perms & (ATT_PERM_READ | ATT_PERM_READ_ENCRYPT))) {
			if (entry_len == 0)
				return att_send_error(ac,
				    ATT_OP_READ_BY_TYPE_REQ, a->handle,
				    ATT_ERR_READ_NOT_PERMITTED);
			break;
		}
		if ((a->perms & ATT_PERM_READ_ENCRYPT) &&
		    !(a->perms & ATT_PERM_READ) && !ac->encrypted) {
			if (entry_len == 0)
				return att_send_error(ac,
				    ATT_OP_READ_BY_TYPE_REQ, a->handle,
				    ATT_ERR_INSUFF_ENCRYPTION);
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
	return (att_server_send(ac, rsp, pos) == pos ? 0 : -1);
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
	if ((a->perms & ATT_PERM_READ_ENCRYPT) &&
	    !(a->perms & ATT_PERM_READ) && !ac->encrypted)
		return att_send_error(ac, ATT_OP_READ_REQ, handle,
		    ATT_ERR_INSUFF_ENCRYPTION);

	rsp[0] = ATT_OP_READ_RSP;
	rlen = a->value_len;
	if (1 + rlen > ac->mtu)
		rlen = ac->mtu - 1;
	memcpy(rsp + 1, a->value, rlen);
	return (att_server_send(ac, rsp, 1 + rlen) == 1 + rlen ? 0 : -1);
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
	if ((a->perms & ATT_PERM_READ_ENCRYPT) &&
	    !(a->perms & ATT_PERM_READ) && !ac->encrypted)
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, handle,
		    ATT_ERR_INSUFF_ENCRYPTION);
	if (offset > a->value_len)
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, handle,
		    ATT_ERR_INVALID_OFFSET);

	rsp[0] = ATT_OP_READ_BLOB_RSP;
	rlen = a->value_len - offset;
	if (1 + rlen > ac->mtu)
		rlen = ac->mtu - 1;
	memcpy(rsp + 1, a->value + offset, rlen);
	return (att_server_send(ac, rsp, 1 + rlen) == 1 + rlen ? 0 : -1);
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
	if ((a->perms & ATT_PERM_WRITE_ENCRYPT) &&
	    !(a->perms & ATT_PERM_WRITE) && !ac->encrypted) {
		if (with_response)
			return att_send_error(ac, ATT_OP_WRITE_REQ, handle,
			    ATT_ERR_INSUFF_ENCRYPTION);
		return (0);
	}
	if (vlen > a->value_maxlen) {
		if (with_response)
			return att_send_error(ac, ATT_OP_WRITE_REQ, handle,
			    ATT_ERR_INVALID_ATTR_LEN);
		return (0);
	}

	memcpy(a->value, pdu + 3, vlen);
	/*
	 * Write Request replaces the entire attribute value
	 * (Core Spec Vol 3 Part F §3.4.5.1).  Write Command
	 * also replaces the full value.  The stored length
	 * becomes exactly the written length.
	 */
	a->value_len = vlen;

	LOG_ATT(2, "srv: write handle=%04x vlen=%d%s", handle, vlen,
	    with_response ? "" : " (cmd)");

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
	uint8_t rsp[ATT_MAX_MTU];
	int rsplen;

	if (len < 5)
		return att_send_error(ac, ATT_OP_PREPARE_WRITE_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	handle = get_le16(pdu + 1);
	offset = get_le16(pdu + 3);
	vlen = len - 5;

	a = attdb_find(db, handle);
	if (a == NULL)
		return att_send_error(ac, ATT_OP_PREPARE_WRITE_REQ, handle,
		    ATT_ERR_INVALID_HANDLE);
	if (!(a->perms & (ATT_PERM_WRITE | ATT_PERM_WRITE_ENCRYPT)))
		return att_send_error(ac, ATT_OP_PREPARE_WRITE_REQ, handle,
		    ATT_ERR_WRITE_NOT_PERMITTED);
	if ((a->perms & ATT_PERM_WRITE_ENCRYPT) &&
	    !(a->perms & ATT_PERM_WRITE) && !ac->encrypted)
		return att_send_error(ac, ATT_OP_PREPARE_WRITE_REQ, handle,
		    ATT_ERR_INSUFF_ENCRYPTION);

	if (pq->count >= ATT_PREPARE_QUEUE_MAX)
		return att_send_error(ac, ATT_OP_PREPARE_WRITE_REQ, handle,
		    ATT_ERR_PREPARE_QUEUE_FULL);

	if (vlen > sizeof(pq->entries[0].value))
		return att_send_error(ac, ATT_OP_PREPARE_WRITE_REQ, handle,
		    ATT_ERR_INVALID_ATTR_LEN);

	pe = &pq->entries[pq->count++];
	pe->handle = handle;
	pe->offset = offset;
	pe->len = vlen;
	memcpy(pe->value, pdu + 5, vlen);

	/* Response echoes back the request: handle + offset + value */
	rsp[0] = ATT_OP_PREPARE_WRITE_RSP;
	put_le16(rsp + 1, handle);
	put_le16(rsp + 3, offset);
	memcpy(rsp + 5, pdu + 5, vlen);

	rsplen = 5 + vlen;

	LOG_ATT(2, "srv: prepare write handle=%04x offset=%d vlen=%d queued=%d",
	    handle, offset, vlen, pq->count);

	return (att_server_send(ac, rsp, rsplen) == rsplen ? 0 : -1);
}

static int
handle_execute_write(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	struct att_prepare_queue *pq = &ac->prep_queue;
	uint8_t flags;
	uint8_t rsp;
	int i;

	if (len < 2)
		return att_send_error(ac, ATT_OP_EXECUTE_WRITE_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	flags = pdu[1];

	if (flags == 0x01) {
		/* Validate all entries first before applying */
		for (i = 0; i < pq->count; i++) {
			struct att_prepare_entry *pe = &pq->entries[i];
			struct att_attr *a = attdb_find(db, pe->handle);

			if (a == NULL) {
				pq->count = 0;
				return att_send_error(ac,
				    ATT_OP_EXECUTE_WRITE_REQ,
				    pe->handle, ATT_ERR_INVALID_HANDLE);
			}
			if (pe->offset > a->value_len) {
				pq->count = 0;
				return att_send_error(ac,
				    ATT_OP_EXECUTE_WRITE_REQ,
				    pe->handle, ATT_ERR_INVALID_OFFSET);
			}
			if (pe->offset + pe->len > a->value_maxlen) {
				pq->count = 0;
				return att_send_error(ac,
				    ATT_OP_EXECUTE_WRITE_REQ,
				    pe->handle, ATT_ERR_INVALID_ATTR_LEN);
			}
		}

		/* Apply all queued writes */
		for (i = 0; i < pq->count; i++) {
			struct att_prepare_entry *pe = &pq->entries[i];
			struct att_attr *a = attdb_find(db, pe->handle);

			memcpy(a->value + pe->offset, pe->value, pe->len);
			if (pe->offset + pe->len > a->value_len)
				a->value_len = pe->offset + pe->len;
		}

		LOG_ATT(2, "srv: execute write applied %d entries",
		    pq->count);
	} else {
		LOG_ATT(2, "srv: execute write cancelled %d entries",
		    pq->count);
	}

	pq->count = 0;

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
	uint8_t rsp[ATT_MAX_MTU];
	int pos;

	if (len < 7)
		return att_send_error(ac, ATT_OP_FIND_BY_TYPE_VALUE_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	start = get_le16(pdu + 1);
	end = get_le16(pdu + 3);
	uuid16 = get_le16(pdu + 5);

	if (start == 0 || start > end)
		return att_send_error(ac, ATT_OP_FIND_BY_TYPE_VALUE_REQ,
		    start, ATT_ERR_INVALID_HANDLE);

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

		/* Check read permission (spec Vol 3 Part F §3.4.3.3) */
		if (!(a->perms & (ATT_PERM_READ | ATT_PERM_READ_ENCRYPT))) {
			if (pos == 1)
				return att_send_error(ac,
				    ATT_OP_FIND_BY_TYPE_VALUE_REQ,
				    a->handle, ATT_ERR_READ_NOT_PERMITTED);
			break;
		}
		if ((a->perms & ATT_PERM_READ_ENCRYPT) &&
		    !(a->perms & ATT_PERM_READ) && !ac->encrypted) {
			if (pos == 1)
				return att_send_error(ac,
				    ATT_OP_FIND_BY_TYPE_VALUE_REQ,
				    a->handle, ATT_ERR_INSUFF_ENCRYPTION);
			break;
		}

		if (a->value_len != vlen ||
		    memcmp(a->value, val, vlen) != 0)
			continue;

		/*
		 * For Primary Service (0x2800), group_end_handle is the
		 * last handle before the next service declaration.
		 * For other types, group_end_handle == found_handle.
		 */
		if (uuid16 == GATT_UUID_PRIMARY_SERVICE ||
		    uuid16 == GATT_UUID_SECONDARY_SERVICE) {
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
		} else {
			grp_end = a->handle;
		}

		if (pos + 4 > (int)ac->mtu)
			break;

		put_le16(rsp + pos, a->handle);
		put_le16(rsp + pos + 2, grp_end);
		pos += 4;
	}

	if (pos == 1)
		return att_send_error(ac, ATT_OP_FIND_BY_TYPE_VALUE_REQ,
		    start, ATT_ERR_ATTR_NOT_FOUND);

	return (att_server_send(ac, rsp, pos) == pos ? 0 : -1);
}

/* ----------------------------------------------------------------
 *  Read Multiple (Core Spec Vol 3 Part F 3.4.4.7)
 * ---------------------------------------------------------------- */

static int
handle_read_multiple(struct att_conn *ac, struct att_db *db,
    const uint8_t *pdu, size_t len)
{
	uint8_t rsp[ATT_MAX_MTU];
	int pos, nhandles;

	/* Minimum: opcode(1) + handle(2) + handle(2) = 5 */
	if (len < 5 || ((len - 1) % 2) != 0)
		return att_send_error(ac, ATT_OP_READ_MULTIPLE_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	nhandles = (len - 1) / 2;

	rsp[0] = ATT_OP_READ_MULTIPLE_RSP;
	pos = 1;

	for (int i = 0; i < nhandles; i++) {
		uint16_t handle = get_le16(pdu + 1 + i * 2);
		struct att_attr *a = attdb_find(db, handle);

		if (a == NULL)
			return att_send_error(ac, ATT_OP_READ_MULTIPLE_REQ,
			    handle, ATT_ERR_INVALID_HANDLE);
		if (!(a->perms & (ATT_PERM_READ | ATT_PERM_READ_ENCRYPT)))
			return att_send_error(ac, ATT_OP_READ_MULTIPLE_REQ,
			    handle, ATT_ERR_READ_NOT_PERMITTED);
		if ((a->perms & ATT_PERM_READ_ENCRYPT) &&
		    !(a->perms & ATT_PERM_READ) && !ac->encrypted)
			return att_send_error(ac, ATT_OP_READ_MULTIPLE_REQ,
			    handle, ATT_ERR_INSUFF_ENCRYPTION);

		uint16_t avail = a->value_len;
		if (pos + avail > (int)ac->mtu)
			avail = ac->mtu - pos;
		if (avail > 0)
			memcpy(rsp + pos, a->value, avail);
		pos += avail;

		if (pos >= (int)ac->mtu)
			break;
	}

	return (att_server_send(ac, rsp, pos) == pos ? 0 : -1);
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

	BLUED_PROBE_ATT_RECV(pdu[0], (int)len);

	/* Log incoming ATT request PDU */
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004,
		    pdu, (uint16_t)len, true);

	LOG_ATT(2, "srv: opcode=%02x len=%zu", pdu[0], len);

	switch (pdu[0]) {
	case ATT_OP_MTU_REQ:
		return handle_mtu_req(ac, pdu, len);
	case ATT_OP_FIND_INFO_REQ:
		return handle_find_info(ac, db, pdu, len);
	case ATT_OP_FIND_BY_TYPE_VALUE_REQ:
		return handle_find_by_type_value(ac, db, pdu, len);
	case ATT_OP_READ_BY_GROUP_TYPE_REQ:
		return handle_read_by_group_type(ac, db, pdu, len);
	case ATT_OP_READ_BY_TYPE_REQ:
		return handle_read_by_type(ac, db, pdu, len);
	case ATT_OP_READ_REQ:
		return handle_read(ac, db, pdu, len);
	case ATT_OP_READ_BLOB_REQ:
		return handle_read_blob(ac, db, pdu, len);
	case ATT_OP_READ_MULTIPLE_REQ:
		return handle_read_multiple(ac, db, pdu, len);
	case ATT_OP_WRITE_REQ:
		return handle_write(ac, db, pdu, len, true);
	case ATT_OP_WRITE_CMD:
		return handle_write(ac, db, pdu, len, false);
	case ATT_OP_PREPARE_WRITE_REQ:
		return handle_prepare_write(ac, db, pdu, len);
	case ATT_OP_EXECUTE_WRITE_REQ:
		return handle_execute_write(ac, db, pdu, len);
	default:
		/* Commands (bit 6 set) must be silently ignored,
		 * not answered with an error response (Core Spec
		 * Vol 3 Part F Section 3.3.1 / 3.4.1.1) */
		if (pdu[0] & 0x40)
			return (0);
		return att_send_error(ac, pdu[0], 0,
		    ATT_ERR_REQ_NOT_SUPPORTED);
	}
}

/*
 * Compute the GATT Database Hash.
 * Core Spec Vol 3 Part G §7.3.1
 *
 * The hash covers all attributes of type: Primary Service (0x2800),
 * Secondary Service (0x2801), Include (0x2802), Characteristic (0x2803),
 * and all Characteristic Descriptors.  For each, the hash input is:
 *   Handle(2, little-endian) || UUID(2 or 16, little-endian) || Value
 *
 * The hash is AES-CMAC with an all-zero 128-bit key.
 * Result is 128 bits in little-endian order.
 */
void
attdb_compute_db_hash(struct att_db *db, uint8_t hash[16])
{
	EVP_MAC *cmac_type;
	EVP_MAC_CTX *ctx;
	OSSL_PARAM params[2];
	size_t outlen;
	uint8_t zero_key[16];
	static char cipher_name[] = "AES-128-CBC";

	memset(zero_key, 0, sizeof(zero_key));

	cmac_type = EVP_MAC_fetch(NULL, "CMAC", NULL);
	if (cmac_type == NULL) {
		warnx("attdb_compute_db_hash: EVP_MAC_fetch failed");
		memset(hash, 0, 16);
		return;
	}
	ctx = EVP_MAC_CTX_new(cmac_type);
	if (ctx == NULL) {
		warnx("attdb_compute_db_hash: EVP_MAC_CTX_new failed");
		EVP_MAC_free(cmac_type);
		memset(hash, 0, 16);
		return;
	}
	params[0] = OSSL_PARAM_construct_utf8_string("cipher", cipher_name, 0);
	params[1] = OSSL_PARAM_construct_end();
	EVP_MAC_init(ctx, zero_key, 16, params);

	for (int i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];
		uint8_t handle_le[2];
		uint8_t uuid_le[2];
		int include_value;

		/*
		 * Per Core Spec Vol 3 Part G §7.3.1, the hash input
		 * includes only these attribute types (by their UUID):
		 *   0x2800 Primary Service       — include value
		 *   0x2801 Secondary Service     — include value
		 *   0x2802 Include               — include value
		 *   0x2803 Characteristic Decl   — include value
		 *   0x2900 Char Extended Props   — include value
		 *   0x2901 Char User Description — no value
		 *   0x2902 CCCD                  — no value
		 *   0x2903 SCCD                  — no value
		 *   0x2904 Char Presentation Fmt — no value
		 *   0x2905 Char Aggregate Format — no value
		 * All other types (characteristic values) are excluded.
		 *
		 * NOTE: 128-bit UUID descriptors should be included per
		 * spec but are currently skipped because the struct lacks
		 * a flag to distinguish them from characteristic values.
		 * This is acceptable while the DB contains only standard
		 * 16-bit UUID attribute types.
		 */
		if (a->uuid16 == 0)
			continue;

		switch (a->uuid16) {
		case 0x2800: /* Primary Service */
		case 0x2801: /* Secondary Service */
		case 0x2802: /* Include */
		case 0x2803: /* Characteristic Declaration */
		case 0x2900: /* Char Extended Properties */
			include_value = 1;
			break;
		case 0x2901: /* Char User Description */
		case 0x2902: /* CCCD */
		case 0x2903: /* SCCD */
		case 0x2904: /* Char Presentation Format */
		case 0x2905: /* Char Aggregate Format */
			include_value = 0;
			break;
		default:
			continue; /* not included in hash */
		}

		handle_le[0] = a->handle & 0xFF;
		handle_le[1] = (a->handle >> 8) & 0xFF;
		uuid_le[0] = a->uuid16 & 0xFF;
		uuid_le[1] = (a->uuid16 >> 8) & 0xFF;

		EVP_MAC_update(ctx, handle_le, 2);
		EVP_MAC_update(ctx, uuid_le, 2);
		if (include_value && a->value != NULL && a->value_len > 0)
			EVP_MAC_update(ctx, a->value, a->value_len);
	}

	outlen = 16;
	EVP_MAC_final(ctx, hash, &outlen, 16);
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(cmac_type);

	LOG_ATT(2, "database hash: %02x%02x%02x%02x%02x%02x%02x%02x"
	    "%02x%02x%02x%02x%02x%02x%02x%02x",
	    hash[0], hash[1], hash[2], hash[3],
	    hash[4], hash[5], hash[6], hash[7],
	    hash[8], hash[9], hash[10], hash[11],
	    hash[12], hash[13], hash[14], hash[15]);
}

/*
 * Reset ATT server state for a connection.
 * Clears any stale prepared writes left by a disconnecting client.
 */
void
att_server_reset(struct att_conn *ac)
{

	ac->prep_queue.count = 0;
}
