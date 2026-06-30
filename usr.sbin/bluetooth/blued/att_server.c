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
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "blued_probes.h"
#include "ctl.h"
#include "hci_log.h"
#include "smp.h"

/*
 * Response buffer helpers for EATT large-MTU support.
 * Handlers use a stack buffer for the common case (primary bearer,
 * MTU <= ATT_PDU_BUF_SIZE) and heap-allocate only when the negotiated
 * MTU exceeds the stack buffer size.
 */
#define ATT_RSP_BUF_DECL(ac)						\
	uint8_t rsp_stack_[ATT_PDU_BUF_SIZE];				\
	uint8_t *rsp = (ac)->mtu > ATT_PDU_BUF_SIZE			\
	    ? malloc((ac)->mtu) : rsp_stack_

#define ATT_RSP_BUF_FREE()						\
	do { if (rsp != rsp_stack_) free(rsp); } while (0)

/* ----------------------------------------------------------------
 *  ATT opcode name for logging
 * ---------------------------------------------------------------- */

static const char *
att_opcode_name(uint8_t op)
{
	switch (op) {
	case ATT_OP_MTU_REQ:			return "MTU_REQ";
	case ATT_OP_MTU_RSP:			return "MTU_RSP";
	case ATT_OP_FIND_INFO_REQ:		return "FIND_INFO_REQ";
	case ATT_OP_FIND_INFO_RSP:		return "FIND_INFO_RSP";
	case ATT_OP_FIND_BY_TYPE_VALUE_REQ:	return "FIND_BY_TYPE_REQ";
	case ATT_OP_READ_BY_TYPE_REQ:		return "READ_BY_TYPE_REQ";
	case ATT_OP_READ_BY_TYPE_RSP:		return "READ_BY_TYPE_RSP";
	case ATT_OP_READ_REQ:			return "READ_REQ";
	case ATT_OP_READ_RSP:			return "READ_RSP";
	case ATT_OP_READ_BLOB_REQ:		return "READ_BLOB_REQ";
	case ATT_OP_READ_MULTIPLE_REQ:		return "READ_MULTI_REQ";
	case ATT_OP_READ_MULTIPLE_VARIABLE_REQ:	return "READ_MULTI_VAR_REQ";
	case ATT_OP_READ_BY_GROUP_TYPE_REQ:	return "READ_BY_GRP_REQ";
	case ATT_OP_WRITE_REQ:			return "WRITE_REQ";
	case ATT_OP_WRITE_CMD:			return "WRITE_CMD";
	case ATT_OP_SIGNED_WRITE_CMD:		return "SIGNED_WRITE_CMD";
	case ATT_OP_PREPARE_WRITE_REQ:		return "PREP_WRITE_REQ";
	case ATT_OP_EXECUTE_WRITE_REQ:		return "EXEC_WRITE_REQ";
	case ATT_OP_HANDLE_NOTIFY:		return "NOTIFY";
	case ATT_OP_HANDLE_IND:			return "INDICATE";
	case ATT_OP_HANDLE_CFM:			return "CONFIRM";
	case ATT_OP_ERROR_RSP:			return "ERROR_RSP";
	default:				return "UNKNOWN";
	}
}

/* ----------------------------------------------------------------
 *  Logged send helper — logs outgoing ATT PDU to BTSnoop
 * ---------------------------------------------------------------- */

static ssize_t
att_server_send(struct att_conn *ac, const void *buf, size_t len)
{
	int fd;

	fd = (ac->bearer_fd >= 0) ? ac->bearer_fd : ac->fd;
	BLUED_PROBE_ATT_SEND(((const uint8_t *)buf)[0], (int)len);
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004,
		    buf, (uint16_t)len, false);
	return (send(fd, buf, len, MSG_NOSIGNAL | MSG_EOR));
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
	a->owner_fd = -1;
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
	if (v == NULL) {
		db->count--;
		return (0);
	}
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
	if (dv == NULL) {
		db->count--;
		return (0);
	}
	dv[0] = props;
	put_le16(dv + 1, db->next_handle); /* value handle = next */
	put_le16(dv + 3, uuid16);
	decl->value = dv;
	decl->value_len = 5;

	/* Value attribute */
	val_attr = attdb_alloc(db);
	if (val_attr == NULL) {
		db->count--;	/* roll back declaration */
		return (0);
	}
	val_attr->uuid16 = uuid16;
	val_attr->perms = perms;
	val_attr->is_char_value = true;
	if (len > 0) {
		vv = val_alloc(db, len);
		if (vv == NULL) {
			db->count -= 2;	/* roll back declaration + value */
			return (0);
		}
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
	if (dv == NULL) {
		db->count--;
		return (0);
	}
	dv[0] = props;
	put_le16(dv + 1, db->next_handle); /* value handle = next */
	memcpy(dv + 3, uuid128, 16);
	decl->value = dv;
	decl->value_len = 19;

	/* Value attribute — uses 128-bit UUID */
	val_attr = attdb_alloc(db);
	if (val_attr == NULL) {
		db->count--;	/* roll back declaration */
		return (0);
	}
	val_attr->uuid16 = 0;
	memcpy(val_attr->uuid128, uuid128, 16);
	val_attr->perms = perms;
	val_attr->is_char_value = true;
	if (len > 0) {
		vv = val_alloc(db, len);
		if (vv == NULL) {
			db->count -= 2;	/* roll back declaration + value */
			return (0);
		}
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
	if (v == NULL) {
		db->count--;
		return (0);
	}
	v[0] = 0;
	v[1] = 0;
	a->value = v;
	a->value_len = 2;
	a->value_maxlen = 2;
	return (a->handle);
}

/*
 * Add an Include Declaration (UUID 0x2802).
 * Value: [start_handle(2), end_handle(2), uuid16(2)] = 6 bytes.
 * Returns the handle of the include declaration, or 0 on failure.
 */
uint16_t
attdb_add_include(struct att_db *db, uint16_t svc_handle,
    uint16_t start, uint16_t end, uint16_t uuid16)
{
	struct att_attr *a;
	uint8_t *v;

	a = attdb_alloc(db);
	if (a == NULL)
		return (0);
	a->uuid16 = GATT_UUID_INCLUDE;
	a->perms = ATT_PERM_READ;

	/*
	 * Core Spec Vol 3 Part G Section 3.2: Include Declaration value
	 * is [start_handle(2), end_handle(2), uuid16(2)] for 16-bit UUIDs,
	 * or [start_handle(2), end_handle(2)] for 128-bit UUIDs (uuid16==0).
	 */
	if (uuid16 != 0) {
		v = val_alloc(db, 6);
		if (v == NULL) {
			db->count--;
			return (0);
		}
		put_le16(v, start);
		put_le16(v + 2, end);
		put_le16(v + 4, uuid16);
		a->value = v;
		a->value_len = 6;
	} else {
		v = val_alloc(db, 4);
		if (v == NULL) {
			db->count--;
			return (0);
		}
		put_le16(v, start);
		put_le16(v + 2, end);
		a->value = v;
		a->value_len = 4;
	}

	(void)svc_handle; /* reserved for future validation */
	return (a->handle);
}

/*
 * Add a generic descriptor attribute.
 * Returns the handle of the descriptor, or 0 on failure.
 */
uint16_t
attdb_add_descriptor(struct att_db *db, uint16_t uuid16,
    uint8_t perms, const void *value, uint16_t len)
{
	struct att_attr *a;
	uint8_t *v;

	a = attdb_alloc(db);
	if (a == NULL)
		return (0);
	a->uuid16 = uuid16;
	a->perms = perms;
	if (len > 0) {
		v = val_alloc(db, len);
		if (v == NULL) {
			db->count--;
			return (0);
		}
		memcpy(v, value, len);
		a->value = v;
		a->value_len = len;
		a->value_maxlen = len;
	}
	return (a->handle);
}

/*
 * Remove a service and all its attributes from the database.
 *
 * Finds the service declaration at 'handle', determines the handle
 * range (from this service to the next service declaration or end),
 * removes all attributes in that range by shifting the remaining
 * attributes down.
 *
 * Returns 0 on success, -1 if handle not found or not a service.
 */
int
attdb_remove_service(struct att_db *db, uint16_t handle)
{
	int start_idx, end_idx, nremove, remain;

	/* Find the service declaration by handle */
	start_idx = -1;
	for (int i = 0; i < db->count; i++) {
		if (db->attrs[i].handle == handle) {
			if (db->attrs[i].uuid16 != GATT_UUID_PRIMARY_SERVICE &&
			    db->attrs[i].uuid16 != GATT_UUID_SECONDARY_SERVICE)
				return (-1); /* not a service */
			start_idx = i;
			break;
		}
	}
	if (start_idx < 0)
		return (-1);

	/* Find the end of this service (next service or end of DB) */
	end_idx = db->count;
	for (int i = start_idx + 1; i < db->count; i++) {
		if (db->attrs[i].uuid16 == GATT_UUID_PRIMARY_SERVICE ||
		    db->attrs[i].uuid16 == GATT_UUID_SECONDARY_SERVICE) {
			end_idx = i;
			break;
		}
	}

	/*
	 * Shift remaining attributes down.
	 *
	 * Note: value pointers still reference val_store, which is not
	 * compacted.  This is acceptable because services are rarely
	 * removed and the wasted space is bounded.
	 */
	nremove = end_idx - start_idx;
	remain = db->count - end_idx;
	if (remain > 0)
		memmove(&db->attrs[start_idx], &db->attrs[end_idx],
		    remain * sizeof(db->attrs[0]));
	db->count -= nremove;

	return (0);
}

/* ----------------------------------------------------------------
 *  Lookup helpers
 * ---------------------------------------------------------------- */

static struct att_attr *
attdb_find(struct att_db *db, uint16_t handle)
{
	int lo = 0, hi = db->count - 1;

	while (lo <= hi) {
		int mid = lo + (hi - lo) / 2;
		if (db->attrs[mid].handle == handle)
			return (&db->attrs[mid]);
		if (db->attrs[mid].handle < handle)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return (NULL);
}

/*
 * Public wrapper for attdb_find — used by ctl.c SET_VALUE command.
 */
struct att_attr *
attdb_find_by_handle(struct att_db *db, uint16_t handle)
{

	return (attdb_find(db, handle));
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
	uint8_t pdu_stack[ATT_PDU_BUF_SIZE];
	uint8_t *pdu;
	uint16_t pdulen, maxlen;
	int ret;

	maxlen = ac->mtu > ATT_PDU_BUF_SIZE ? ac->mtu : ATT_PDU_BUF_SIZE;
	pdu = (maxlen > ATT_PDU_BUF_SIZE) ? malloc(maxlen) : pdu_stack;
	if (pdu == NULL)
		return (-1);

	if (len > maxlen - 3)
		len = maxlen - 3;
	pdulen = 3 + len;
	if (pdulen > ac->mtu)
		pdulen = ac->mtu;
	pdu[0] = ATT_OP_HANDLE_NOTIFY;
	put_le16(pdu + 1, handle);
	memcpy(pdu + 3, value, pdulen - 3);

	ret = att_server_send(ac, pdu, pdulen) == pdulen ? 0 : -1;
	if (pdu != pdu_stack)
		free(pdu);
	return (ret);
}

/*
 * Send Handle Value Indication (Core Spec Vol 3 Part F §3.4.7.2).
 *
 * Like a notification but uses opcode 0x1D (ATT_HANDLE_VALUE_IND).
 * The client must reply with ATT_HANDLE_VALUE_CFM (0x1E) to acknowledge.
 *
 * Enforces one-at-a-time: returns -1 with errno=EBUSY if an indication
 * is already pending confirmation.  The caller must arm the 30-second
 * ATT transaction timer via att_ind_arm_timeout() after a successful send.
 */
int
att_send_indication(struct att_conn *ac, uint16_t handle,
    const void *value, uint16_t len)
{
	uint8_t pdu_stack[ATT_PDU_BUF_SIZE];
	uint8_t *pdu;
	uint16_t pdulen, maxlen;

	/* One indication at a time (Core Spec Vol 3 Part F §3.3.2) */
	if (ac->ind_pending) {
		errno = EBUSY;
		return (-1);
	}

	maxlen = ac->mtu > ATT_PDU_BUF_SIZE ? ac->mtu : ATT_PDU_BUF_SIZE;
	pdu = (maxlen > ATT_PDU_BUF_SIZE) ? malloc(maxlen) : pdu_stack;
	if (pdu == NULL)
		return (-1);

	if (len > maxlen - 3)
		len = maxlen - 3;
	pdulen = 3 + len;
	if (pdulen > ac->mtu)
		pdulen = ac->mtu;
	pdu[0] = ATT_OP_HANDLE_IND;
	put_le16(pdu + 1, handle);
	memcpy(pdu + 3, value, pdulen - 3);

	if (att_server_send(ac, pdu, pdulen) != pdulen) {
		if (pdu != pdu_stack)
			free(pdu);
		return (-1);
	}

	if (pdu != pdu_stack)
		free(pdu);
	ac->ind_pending = true;
	return (0);
}

/*
 * Check read permissions against the connection's security level.
 * Returns 0 if allowed, or the ATT error code to send.
 */
int
att_check_read_perm(const struct att_attr *a, const struct att_conn *ac)
{
	uint8_t mks;

	mks = ac->min_key_size ? ac->min_key_size : 16;

	if (!(a->perms & (ATT_PERM_READ | ATT_PERM_READ_ENCRYPT |
	    ATT_PERM_READ_AUTHEN)))
		return (ATT_ERR_READ_NOT_PERMITTED);
	if ((a->perms & ATT_PERM_READ_ENCRYPT) && !ac->encrypted)
		return (ATT_ERR_INSUFF_ENCRYPTION);
	if ((a->perms & ATT_PERM_READ_ENCRYPT) && ac->encrypted &&
	    ac->enc_key_size > 0 && ac->enc_key_size < mks)
		return (ATT_ERR_INSUFF_ENC_KEY_SIZE);
	/*
	 * Authenticated access implies encryption (Core Spec Vol 3
	 * Part F Section 3.2.5).  Check both: a link can never be
	 * authenticated without also being encrypted.
	 */
	if ((a->perms & ATT_PERM_READ_AUTHEN) && !ac->encrypted)
		return (ATT_ERR_INSUFF_ENCRYPTION);
	if ((a->perms & ATT_PERM_READ_AUTHEN) && ac->encrypted &&
	    ac->enc_key_size > 0 && ac->enc_key_size < mks)
		return (ATT_ERR_INSUFF_ENC_KEY_SIZE);
	if ((a->perms & ATT_PERM_READ_AUTHEN) && !ac->authenticated)
		return (ATT_ERR_INSUFF_AUTHEN);
	return (0);
}

/*
 * Check write permissions against the connection's security level.
 * Returns 0 if allowed, or the ATT error code to send.
 */
int
att_check_write_perm(const struct att_attr *a, const struct att_conn *ac)
{
	uint8_t mks;

	mks = ac->min_key_size ? ac->min_key_size : 16;

	if (!(a->perms & (ATT_PERM_WRITE | ATT_PERM_WRITE_ENCRYPT |
	    ATT_PERM_WRITE_AUTHEN)))
		return (ATT_ERR_WRITE_NOT_PERMITTED);
	if ((a->perms & ATT_PERM_WRITE_ENCRYPT) && !ac->encrypted)
		return (ATT_ERR_INSUFF_ENCRYPTION);
	if ((a->perms & ATT_PERM_WRITE_ENCRYPT) && ac->encrypted &&
	    ac->enc_key_size > 0 && ac->enc_key_size < mks)
		return (ATT_ERR_INSUFF_ENC_KEY_SIZE);
	/* Authenticated access implies encryption */
	if ((a->perms & ATT_PERM_WRITE_AUTHEN) && !ac->encrypted)
		return (ATT_ERR_INSUFF_ENCRYPTION);
	if ((a->perms & ATT_PERM_WRITE_AUTHEN) && ac->encrypted &&
	    ac->enc_key_size > 0 && ac->enc_key_size < mks)
		return (ATT_ERR_INSUFF_ENC_KEY_SIZE);
	if ((a->perms & ATT_PERM_WRITE_AUTHEN) && !ac->authenticated)
		return (ATT_ERR_INSUFF_AUTHEN);
	return (0);
}

/*
 * Send Multiple Handle Value Notification (Core Spec Vol 3 Part F 3.4.7.5)
 *
 * BT 5.2 ATT_MULTIPLE_HANDLE_VALUE_NTF (opcode 0x23): packs multiple
 * handle-value tuples into a single PDU.
 * Format: opcode(1) + [handle(2) + length(2) + value(length)]*
 * Total truncated to MTU.
 *
 * Core Spec Vol 3 Part G §4.12.2: the server shall only send this if
 * the client has set bit 2 (Multiple Handle Value Notifications) in the
 * Client Supported Features characteristic (0x2B29).  The caller must
 * verify this before calling.
 */
int
att_send_multiple_handle_value_ntf(struct att_conn *ac,
    const uint16_t *handles, const uint8_t **values,
    const uint16_t *lengths, int count)
{
	uint8_t pdu_stack[ATT_PDU_BUF_SIZE];
	uint8_t *pdu;
	uint16_t pos, maxlen;
	int i, ret;

	if (count <= 0)
		return (0);

	maxlen = ac->mtu > ATT_PDU_BUF_SIZE ? ac->mtu : ATT_PDU_BUF_SIZE;
	pdu = (maxlen > ATT_PDU_BUF_SIZE) ? malloc(maxlen) : pdu_stack;
	if (pdu == NULL)
		return (-1);

	pdu[0] = ATT_OP_MULTIPLE_HANDLE_VALUE_NTF;
	pos = 1;

	for (i = 0; i < count; i++) {
		/* Each entry: handle(2) + length(2) + value(length) */
		uint32_t entry_len = 4 + (uint32_t)lengths[i];

		if (pos + entry_len > maxlen)
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
		if (pdu != pdu_stack)
			free(pdu);
		return (0);
	}

	LOG_ATT(2, "srv: multi handle value ntf count=%d/%d len=%d",
	    i, count, pos);

	ret = att_server_send(ac, pdu, pos) == pos ? 0 : -1;
	if (pdu != pdu_stack)
		free(pdu);
	return (ret);
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

	/*
	 * Core Spec Vol 3 Part F §3.4.2.1: this request shall only
	 * be sent once per connection.  Return an error if already done.
	 */
	if (ac->mtu_exchanged) {
		return att_send_error(ac, ATT_OP_MTU_REQ, 0,
		    ATT_ERR_REQ_NOT_SUPPORTED);
	}

	/*
	 * Advertise the stack PDU buffer size as our MTU for the
	 * unenhanced ATT bearer.  EATT bearers negotiate MTU via
	 * L2CAP CoC parameters, not ATT_EXCHANGE_MTU_REQ.
	 */
	server_mtu = ATT_PDU_BUF_SIZE;

	rsp[0] = ATT_OP_MTU_RSP;
	put_le16(rsp + 1, server_mtu);
	if (att_server_send(ac, rsp, 3) != 3)
		return (-1);

	ac->mtu = client_mtu < server_mtu ? client_mtu : server_mtu;
	if (ac->mtu < ATT_DEFAULT_MTU)
		ac->mtu = ATT_DEFAULT_MTU;

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

	if (len < 5)
		return att_send_error(ac, ATT_OP_FIND_INFO_REQ, 0,
		    ATT_ERR_INVALID_PDU);

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

	/* Accept 7 (16-bit), 9 (32-bit), or 21 (128-bit UUID) bytes */
	if (len != 7 && len != 9 && len != 21) {
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
	pos = 2; /* skip opcode + length byte */

	for (int i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];
		uint16_t grp_end;

		if (a->uuid16 != uuid16)
			continue;
		if (a->handle < start || a->handle > end)
			continue;

		/* Check read permission (spec Vol 3 Part F §3.4.4.9) */
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
		if (vlen > (uint16_t)pos_limit - 6)
			vlen = (uint16_t)pos_limit - 6;
		if (vlen > 251)
			vlen = 251;

		/* entry: [handle(2), end_group(2), value(vlen)] */
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

	if (len != 7 && len != 9 && len != 21) {
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

		/* Clamp value to min(ATT_MTU-4, 253) per spec §3.4.4.2 */
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

	rsp[1] = (uint8_t)entry_len;
	ret = att_server_send(ac, rsp, pos) == pos ? 0 : -1;
	ATT_RSP_BUF_FREE();
	return (ret);
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

	if (len < 3) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}

	handle = get_le16(pdu + 1);
	a = attdb_find(db, handle);
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

	rsp[0] = ATT_OP_READ_RSP;

	/*
	 * CCCD values are per-connection (Core Spec Vol 3 Part G
	 * §3.3.3.3).  Look up the connection-local value; fall back
	 * to the shared attribute value for bonded defaults.
	 */
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
	/*
	 * Robust Caching: reading the Database Hash (0x2B2A)
	 * makes this client change-aware again.
	 */
	if (a->uuid16 == 0x2B2A)
		ac->change_aware = true;

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

	if (len < 5) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}

	handle = get_le16(pdu + 1);
	offset = get_le16(pdu + 3);
	a = attdb_find(db, handle);
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

	if (offset > 0 && a->value_len <= ac->mtu - 1) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, handle,
		    ATT_ERR_ATTR_NOT_LONG);
	}

	if (offset > 0 && offset >= a->value_len) {
		ATT_RSP_BUF_FREE();
		return att_send_error(ac, ATT_OP_READ_BLOB_REQ, handle,
		    ATT_ERR_INVALID_OFFSET);
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
	 * CCCD writes are per-connection (Core Spec Vol 3 Part G
	 * §3.3.3.3).  Store in the connection's CCCD table rather
	 * than the shared attribute value so each client has its
	 * own notification/indication subscription state.  The
	 * shared attribute value is kept as a default for bonded
	 * persistence.
	 */
	if (a->uuid16 == GATT_UUID_CCCD && vlen == 2) {
		uint16_t cccd_val = get_le16(pdu + 3);
		int ci;

		/* Mask RFU bits (Core Spec Vol 3 Part G §3.3.3.3) */
		cccd_val &= 0x0003;

		/*
		 * Validate CCCD bits against the parent characteristic's
		 * properties (Core Spec Vol 3 Part G §3.3.3.3).  The CCCD
		 * follows the characteristic value attribute, which follows
		 * the characteristic declaration (uuid16 == 0x2803).
		 * Search backwards to find the declaration.
		 */
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

		/* Update existing entry or add a new one */
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
			/* CCCD table full — report insufficient resources */
			if (with_response)
				return att_send_error(ac, ATT_OP_WRITE_REQ,
				    handle, ATT_ERR_INSUFF_RESOURCES);
			return (0);
		}

		LOG_ATT(2, "srv: cccd write handle=%04x value=%04x%s",
		    handle, cccd_val, with_response ? "" : " (cmd)");
	} else {
		memcpy(a->value, pdu + 3, vlen);
		/*
		 * Write Request replaces the entire attribute value
		 * (Core Spec Vol 3 Part F §3.4.5.1).  Write Command
		 * also replaces the full value.  The stored length
		 * becomes exactly the written length.
		 */
		a->value_len = vlen;

		/* Notify the ctl client that owns this attribute */
		if (a->owner_fd >= 0)
			blued_ctl_notify_write(a->owner_fd, handle,
			    pdu + 3, vlen);

		LOG_ATT(2, "srv: write handle=%04x vlen=%d%s", handle, vlen,
		    with_response ? "" : " (cmd)");

		/*
		 * Robust Caching: if client writes Client Supported
		 * Features (0x2B29) with bit 0 set, enable per-conn
		 * Robust Caching tracking and mark change-aware.
		 */
		if (a->uuid16 == 0x2B29 && vlen >= 1 &&
		    (pdu[3] & 0x01) != 0) {
			ac->robust_caching = true;
			ac->change_aware = true;
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

	a = attdb_find(db, handle);
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

	/* Response echoes back the request: handle + offset + value */
	rsp[0] = ATT_OP_PREPARE_WRITE_RSP;
	put_le16(rsp + 1, handle);
	put_le16(rsp + 3, offset);
	/* Clamp echoed value to buffer limit */
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

	if (len < 2)
		return att_send_error(ac, ATT_OP_EXECUTE_WRITE_REQ, 0,
		    ATT_ERR_INVALID_PDU);

	flags = pdu[1];

	/* Core Spec Vol 3 Part F §3.4.6.3: flags must be 0x00 or 0x01 */
	if (flags != 0x00 && flags != 0x01) {
		pq->count = 0;
		pq->total_bytes = 0;
		return att_send_error(ac, ATT_OP_EXECUTE_WRITE_REQ, 0,
		    ATT_ERR_INVALID_PDU);
	}

	if (flags == 0x01) {
		/* Validate all entries first before applying */
		for (i = 0; i < pq->count; i++) {
			struct att_prepare_entry *pe = &pq->entries[i];
			struct att_attr *a = attdb_find(db, pe->handle);
			int werr;

			if (a == NULL) {
				pq->count = 0;
				pq->total_bytes = 0;
				return att_send_error(ac,
				    ATT_OP_EXECUTE_WRITE_REQ,
				    pe->handle, ATT_ERR_INVALID_HANDLE);
			}
			/*
			 * Re-check write permissions at execute time
			 * (Core Spec Vol 3 Part F Section 3.4.6.3).
			 * Security level may have changed since prepare.
			 */
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
			/*
			 * Validate CCCD writes: the Prepare/Execute path
			 * must enforce the same property checks as the
			 * direct Write Request path.
			 */
			if (a->uuid16 == GATT_UUID_CCCD &&
			    pe->offset == 0 && pe->len == 2) {
				uint16_t cccd_val = get_le16(pe->value);
				uint8_t char_props = 0;
				bool found_decl = false;
				int di;

				/* Mask RFU bits */
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

		/* Apply all queued writes */
		for (i = 0; i < pq->count; i++) {
			struct att_prepare_entry *pe = &pq->entries[i];
			struct att_attr *a = attdb_find(db, pe->handle);

			/*
			 * CCCD writes are per-connection: update the
			 * connection's CCCD table instead of the shared
			 * attribute value (same as direct Write path).
			 */
			if (a->uuid16 == GATT_UUID_CCCD &&
			    pe->offset == 0 && pe->len == 2) {
				uint16_t cccd_val = get_le16(pe->value);
				int ci;

				/* Mask RFU bits (same as direct Write) */
				cccd_val &= (GATT_CCCD_NOTIFY |
				    GATT_CCCD_INDICATE);

				for (ci = 0; ci < ac->cccd_count; ci++) {
					if (ac->cccds[ci].handle ==
					    pe->handle) {
						ac->cccds[ci].value =
						    cccd_val;
						break;
					}
				}
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

		/* Check read permission (spec Vol 3 Part F §3.4.3.3) */
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

	/* Minimum: opcode(1) + handle(2) + handle(2) = 5 */
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
		struct att_attr *a = attdb_find(db, handle);

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
		pos += avail;

		if (pos >= pos_limit)
			break;
	}

	ret = att_server_send(ac, rsp, pos) == pos ? 0 : -1;
	ATT_RSP_BUF_FREE();
	return (ret);
}

/*
 * Read Multiple Variable Length Request (Core Spec Vol 3 Part F §3.4.4.8).
 * BT 5.1+: like Read Multiple but each value in the response is preceded
 * by a 2-byte length field, allowing variable-length attributes.
 */
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

	/* Minimum: opcode(1) + handle(2) + handle(2) = 5 */
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
		struct att_attr *a = attdb_find(db, handle);

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

		/* Each entry: length(2) + value(length) */
		uint16_t vlen = a->value_len;
		if (pos + 2 > pos_limit)
			break;
		if (pos + 2 + vlen > pos_limit)
			vlen = pos_limit - pos - 2;

		put_le16(rsp + pos, vlen);
		pos += 2;
		if (vlen > 0 && a->value != NULL)
			memcpy(rsp + pos, a->value, vlen);
		pos += vlen;

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

	/*
	 * Set transient bearer context so response helpers send on
	 * the correct bearer.  When bearer_fd == -1, the primary
	 * bearer (ac->fd / ac->mtu) is used.
	 */
	saved_bearer_fd = ac->bearer_fd;
	saved_bearer_mtu = ac->bearer_mtu;
	ac->bearer_fd = bearer_fd;
	ac->bearer_mtu = bearer_mtu;

	/*
	 * Temporarily swap ac->mtu to the bearer's MTU for the
	 * duration of this request so all internal handlers respect
	 * the correct PDU size limit.
	 */
	eff_mtu = ac->mtu;
	if (bearer_fd >= 0 && bearer_mtu > 0)
		ac->mtu = bearer_mtu;

	BLUED_PROBE_ATT_RECV(pdu[0], (int)len);

	/* Log incoming ATT request PDU */
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004,
		    pdu, (uint16_t)len, true);

	LOG_ATT(1, "srv: %s (0x%02x) len=%zu",
	    att_opcode_name(pdu[0]), pdu[0], len);

	/*
	 * GATT Robust Caching (Core Spec Vol 3 Part G §2.5.2.1):
	 * If the client has set the Robust Caching bit and is
	 * change-unaware (DB was modified since last hash read),
	 * reject with DATABASE_OUT_OF_SYNC for most request types.
	 * Exceptions: Exchange MTU, Read (for DB Hash), and
	 * Write (for Client Supported Features) are always allowed.
	 */
	if (ac->robust_caching && !ac->change_aware &&
	    pdu[0] != ATT_OP_MTU_REQ &&
	    pdu[0] != ATT_OP_READ_REQ &&
	    pdu[0] != ATT_OP_READ_BY_TYPE_REQ &&
	    pdu[0] != ATT_OP_WRITE_REQ &&
	    pdu[0] != ATT_OP_WRITE_CMD &&
	    pdu[0] != ATT_OP_HANDLE_CFM) {
		ret = att_send_error(ac, pdu[0],
		    len >= 3 ? get_le16(pdu + 1) : 0,
		    ATT_ERR_DATABASE_OUT_OF_SYNC);
		if (bearer_fd >= 0 && bearer_mtu > 0)
			ac->mtu = eff_mtu;
		ac->bearer_fd = saved_bearer_fd;
		ac->bearer_mtu = saved_bearer_mtu;
		return (ret);
	}

	switch (pdu[0]) {
	case ATT_OP_MTU_REQ:
		/*
		 * Exchange MTU is only valid on the unenhanced ATT bearer.
		 * EATT bearers negotiate MTU via L2CAP CoC parameters.
		 * Core Spec Vol 3 Part G §5.3.
		 */
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
	case ATT_OP_SIGNED_WRITE_CMD:
		/*
		 * Signed Write Command (Core Spec Vol 3 Part F §3.4.5.4).
		 * PDU: opcode(1) + handle(2) + value(N) + signature(12)
		 * Signature = SignCounter(4, LE) + MAC(8).
		 * No error response may be sent for commands.
		 */
		if (len < 15) {
			/* 1 opcode + 2 handle + 12 sig = 15 minimum */
			LOG_ATT(1, "srv: Signed Write too short (%zu)", len);
			ret = 0;
		} else if (!ac->has_peer_csrk) {
			LOG_ATT(1, "srv: Signed Write dropped — "
			    "no peer CSRK available");
			ret = 0;
		} else {
			const uint8_t *sig = pdu + len - 12;
			uint32_t counter = get_le32(sig);
			const uint8_t *mac = sig + 4;
			size_t msg_len = len - 12;

			if (smp_verify_signature(ac->peer_csrk, pdu,
			    msg_len, mac, counter)) {
				/*
				 * Replay protection: counter must be
				 * strictly increasing (Core Spec Vol 3
				 * Part H Section 2.4.5).
				 */
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
		/* Client confirms receipt of our indication — no response */
		ac->ind_pending = false;
		LOG_ATT(2, "srv: received indication confirmation");
		ret = 0;
		break;
	default:
		/*
		 * Commands (bit 6 set) must be silently ignored,
		 * not answered with an error response (Core Spec
		 * Vol 3 Part F Section 3.3.1 / 3.4.1.1).
		 */
		if (pdu[0] & 0x40) {
			ret = 0;
		} else {
			ret = att_send_error(ac, pdu[0], 0,
			    ATT_ERR_REQ_NOT_SUPPORTED);
		}
		break;
	}

	/* Restore bearer context; only restore MTU if we swapped it */
	if (bearer_fd >= 0 && bearer_mtu > 0)
		ac->mtu = eff_mtu;
	ac->bearer_fd = saved_bearer_fd;
	ac->bearer_mtu = saved_bearer_mtu;
	return (ret);
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
	if (!EVP_MAC_init(ctx, zero_key, 16, params)) {
		warnx("attdb_compute_db_hash: EVP_MAC_init failed");
		EVP_MAC_CTX_free(ctx);
		EVP_MAC_free(cmac_type);
		memset(hash, 0, 16);
		return;
	}

	for (int i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];
		uint8_t handle_le[2];
		int include_value;
		const uint8_t *uuid_bytes;
		size_t uuid_len;

		/*
		 * Per Core Spec Vol 3 Part G §7.3.1, the hash input
		 * includes: service declarations (0x2800-0x2802),
		 * characteristic declarations (0x2803), and ALL
		 * characteristic descriptors (both standard 16-bit
		 * and vendor-specific 128-bit UUIDs).
		 *
		 * Characteristic values are excluded.  The is_char_value
		 * flag distinguishes 128-bit UUID descriptors from
		 * 128-bit UUID characteristic values.
		 */

		/* Skip characteristic values (not included in hash) */
		if (a->is_char_value)
			continue;

		/*
		 * Determine whether the attribute value is included
		 * in the hash input.  Per §7.3.1, the value is
		 * included for service declarations (0x2800-0x2802),
		 * characteristic declarations (0x2803), and the
		 * Characteristic Extended Properties descriptor
		 * (0x2900).  All other attributes (descriptors with
		 * any UUID, including vendor-specific 16-bit UUIDs)
		 * contribute handle + UUID only.
		 */
		if (a->uuid16 != 0) {
			uint8_t uuid16_le[2];

			switch (a->uuid16) {
			case 0x2800: /* Primary Service */
			case 0x2801: /* Secondary Service */
			case 0x2802: /* Include */
			case 0x2803: /* Characteristic Declaration */
			case 0x2900: /* Char Extended Properties */
				include_value = 1;
				break;
			default:
				include_value = 0;
				break;
			}
			uuid16_le[0] = a->uuid16 & 0xFF;
			uuid16_le[1] = (a->uuid16 >> 8) & 0xFF;
			uuid_bytes = uuid16_le;
			uuid_len = 2;
		} else {
			/*
			 * 128-bit UUID descriptor (is_char_value is false).
			 * Descriptors are included without their value.
			 */
			include_value = 0;
			uuid_bytes = a->uuid128;
			uuid_len = 16;
		}

		handle_le[0] = a->handle & 0xFF;
		handle_le[1] = (a->handle >> 8) & 0xFF;

		if (!EVP_MAC_update(ctx, handle_le, 2) ||
		    !EVP_MAC_update(ctx, uuid_bytes, uuid_len) ||
		    (include_value && a->value != NULL && a->value_len > 0 &&
		    !EVP_MAC_update(ctx, a->value, a->value_len))) {
			warnx("attdb_compute_db_hash: EVP_MAC_update failed");
			EVP_MAC_CTX_free(ctx);
			EVP_MAC_free(cmac_type);
			memset(hash, 0, 16);
			return;
		}
	}

	outlen = 16;
	if (!EVP_MAC_final(ctx, hash, &outlen, 16)) {
		warnx("attdb_compute_db_hash: EVP_MAC_final failed");
		EVP_MAC_CTX_free(ctx);
		EVP_MAC_free(cmac_type);
		memset(hash, 0, 16);
		return;
	}
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
	ac->prep_queue.total_bytes = 0;
	ac->cccd_count = 0;
	ac->mtu_exchanged = false;
}
