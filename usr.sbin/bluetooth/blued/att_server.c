/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATT server — attribute database management, handle allocation,
 * service/characteristic/descriptor add/remove, and shared helpers.
 *
 * Request dispatch is in att_server_dispatch.c.
 * Notification/indication sending is in att_server_notify.c.
 * Database hash computation is in att_server_hash.c.
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

#include "att.h"
#include "att_server.h"
#include "att_server_internal.h"
#include "ble_util.h"
#include "blued_probes.h"
#include "hci_log.h"

/* ----------------------------------------------------------------
 *  ATT opcode name for logging
 * ---------------------------------------------------------------- */

const char *
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
	case ATT_OP_LEGACY_SIGNED_WRITE_CMD:		return "SIGNED_WRITE_CMD";
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
 *  Logged send helper -- logs outgoing ATT PDU to BTSnoop
 * ---------------------------------------------------------------- */

ssize_t
att_server_send(struct att_conn *ac, const void *buf, size_t len)
{
	int fd;

	fd = (ac->bearer_fd >= 0) ? ac->bearer_fd : ac->fd;
	BLUED_PROBE_ATT_SEND(((const uint8_t *)buf)[0], (int)len);
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004,
		    buf, len, false);
	return (send(fd, buf, len, MSG_NOSIGNAL | MSG_EOR));
}

/* ----------------------------------------------------------------
 *  UUID extraction helper
 * ---------------------------------------------------------------- */

int
att_extract_uuid(const uint8_t *data, size_t uuid_len,
    uint16_t *uuid16_out, uint8_t uuid128_out[16])
{
	switch (uuid_len) {
	case 2:
		*uuid16_out = get_le16(data);
		return (0);
	/*
	 * A 4-octet (32-bit) UUID is not a valid on-wire Attribute Type: the
	 * ATT PDUs that carry a type field (e.g. Read By Type, Read By Group
	 * Type) constrain it to a 2- or 16-octet UUID (Core Spec Vol 3 Part F
	 * §3.4.4.1 Table 3.15).  Reject so the caller returns Invalid PDU
	 * (0x04) rather than silently accepting a UUID32 extension.
	 */
	case 16:
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

/*
 * Reserve value capacity for a writable characteristic declared with an EMPTY
 * initial value.  Without a reserved buffer the attribute is created
 * value==NULL / value_maxlen==0 and every client write is rejected
 * INVALID_ATTR_LEN — permanently unwritable.  Reserve up to the maximum ATT
 * attribute value length (Core Spec Vol 3 Part F §3.2.9) but never more than
 * the value arena can currently supply, so declaring an empty writable
 * attribute never itself fails attribute creation.  On success value/value_len/
 * value_maxlen are set; if the arena is exhausted they are left zero (the
 * attribute stays a readable empty value, as before).
 */
static void
attdb_reserve_empty_writable(struct att_db *db, struct att_attr *a)
{
	size_t avail = db->val_size - db->val_used;
	uint16_t cap = ATT_PEND_WVAL_MAX;
	uint8_t *vv;

	if ((size_t)cap > avail)
		cap = (uint16_t)avail;
	if (cap == 0)
		return;
	vv = val_alloc(db, cap);
	if (vv == NULL)
		return;
	a->value = vv;
	a->value_len = 0;
	a->value_maxlen = cap;
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

/*
 * Snapshot the whole attribute database into another db, preserving the
 * destination's own backing storage.  Attribute value pointers reference the
 * source val_store; they are re-based onto the destination's val_store so the
 * copy is self-contained.  Returns 0 on success, -1 if dst lacks capacity.
 *
 * Used for staged (transactional) GATT-application registration: a scratch db
 * is seeded from the live db, mutated in isolation, then copied back on commit
 * so peers see the whole application appear atomically (the common atomic
 * GATT-application registration semantics).
 */
int
attdb_copy(struct att_db *dst, const struct att_db *src)
{
	int i;

	if (src->count > dst->max || src->val_used > dst->val_size)
		return (-1);

	memcpy(dst->val_store, src->val_store, src->val_used);
	for (i = 0; i < src->count; i++) {
		dst->attrs[i] = src->attrs[i];
		if (src->attrs[i].value != NULL)
			dst->attrs[i].value = dst->val_store +
			    (size_t)(src->attrs[i].value - src->val_store);
	}
	dst->count = src->count;
	dst->next_handle = src->next_handle;
	dst->val_used = src->val_used;
	return (0);
}

static struct att_attr *
attdb_alloc(struct att_db *db)
{
	struct att_attr *a;

	if (db->count >= db->max)
		return (NULL);
	a = &db->attrs[db->count++];
	/* Slots can be reused after service removal or a failed registration. */
	memset(a, 0, sizeof(*a));
	a->handle = db->next_handle++;
	a->owner_fd = -1;
	return (a);
}

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

uint16_t
attdb_add_characteristic(struct att_db *db, uint16_t uuid16,
    uint8_t props, uint8_t perms, const void *value, uint16_t len)
{
	struct att_attr *decl, *val_attr;
	uint8_t *dv, *vv;
	size_t saved_val_used;

	if (value == NULL && len > 0)
		return (0);
	saved_val_used = db->val_used;

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
	put_le16(dv + 1, db->next_handle);
	put_le16(dv + 3, uuid16);
	decl->value = dv;
	decl->value_len = 5;

	val_attr = attdb_alloc(db);
	if (val_attr == NULL) {
		db->count--;
		db->val_used = saved_val_used;
		return (0);
	}
	val_attr->uuid16 = uuid16;
	val_attr->perms = perms;
	val_attr->is_char_value = true;
	if (len > 0) {
		vv = val_alloc(db, len);
		if (vv == NULL) {
			db->count -= 2;
			db->val_used = saved_val_used;
			return (0);
		}
		memcpy(vv, value, len);
		val_attr->value = vv;
		val_attr->value_len = len;
		val_attr->value_maxlen = len;
	} else if (ATT_PERM_IS_WRITABLE(perms)) {
		/*
		 * Writable characteristic declared with an empty initial value
		 * must still reserve capacity, or it is permanently unwritable.
		 */
		attdb_reserve_empty_writable(db, val_attr);
	}
	return (val_attr->handle);
}

uint16_t
attdb_add_characteristic128(struct att_db *db, const uint8_t uuid128[16],
    uint8_t props, uint8_t perms, const void *value, uint16_t len)
{
	struct att_attr *decl, *val_attr;
	uint8_t *dv, *vv;
	size_t saved_val_used;

	if (value == NULL && len > 0)
		return (0);
	saved_val_used = db->val_used;

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
	put_le16(dv + 1, db->next_handle);
	memcpy(dv + 3, uuid128, 16);
	decl->value = dv;
	decl->value_len = 19;

	val_attr = attdb_alloc(db);
	if (val_attr == NULL) {
		db->count--;
		db->val_used = saved_val_used;
		return (0);
	}
	val_attr->uuid16 = 0;
	memcpy(val_attr->uuid128, uuid128, 16);
	val_attr->perms = perms;
	val_attr->is_char_value = true;
	if (len > 0) {
		vv = val_alloc(db, len);
		if (vv == NULL) {
			db->count -= 2;
			db->val_used = saved_val_used;
			return (0);
		}
		memcpy(vv, value, len);
		val_attr->value = vv;
		val_attr->value_len = len;
		val_attr->value_maxlen = len;
	} else if (ATT_PERM_IS_WRITABLE(perms)) {
		/* See attdb_add_characteristic(): empty writable char must
		 * still reserve capacity or it is permanently unwritable. */
		attdb_reserve_empty_writable(db, val_attr);
	}
	return (val_attr->handle);
}

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

	(void)svc_handle;
	return (a->handle);
}

uint16_t
attdb_add_descriptor(struct att_db *db, uint16_t uuid16,
    uint8_t perms, const void *value, uint16_t len)
{
	struct att_attr *a;
	uint8_t *v;

	if (value == NULL && len > 0)
		return (0);

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

uint16_t
attdb_add_descriptor128(struct att_db *db, const uint8_t uuid128[16],
    uint8_t perms, const void *value, uint16_t len)
{
	struct att_attr *a;
	uint8_t *v;

	if (uuid128 == NULL || (value == NULL && len > 0))
		return (0);

	a = attdb_alloc(db);
	if (a == NULL)
		return (0);
	a->uuid16 = 0;
	memcpy(a->uuid128, uuid128, 16);
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

int
attdb_remove_service(struct att_db *db, uint16_t handle)
{
	int start_idx, end_idx, nremove, remain;
	size_t used;

	start_idx = -1;
	for (int i = 0; i < db->count; i++) {
		if (db->attrs[i].handle == handle) {
			if (db->attrs[i].uuid16 != GATT_UUID_PRIMARY_SERVICE &&
			    db->attrs[i].uuid16 != GATT_UUID_SECONDARY_SERVICE)
				return (-1);
			start_idx = i;
			break;
		}
	}
	if (start_idx < 0)
		return (-1);

	end_idx = db->count;
	for (int i = start_idx + 1; i < db->count; i++) {
		if (db->attrs[i].uuid16 == GATT_UUID_PRIMARY_SERVICE ||
		    db->attrs[i].uuid16 == GATT_UUID_SECONDARY_SERVICE) {
			end_idx = i;
			break;
		}
	}

	nremove = end_idx - start_idx;
	remain = db->count - end_idx;
	if (remain > 0)
		memmove(&db->attrs[start_idx], &db->attrs[end_idx],
		    remain * sizeof(db->attrs[0]));
	db->count -= nremove;

	/*
	 * Attribute values live in a fixed arena.  Compact the surviving values
	 * as well as the descriptors; otherwise repeated runtime add/remove
	 * cycles permanently consume val_store and eventually fail registration.
	 */
	used = 0;
	for (int i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];
		size_t capacity;

		if (a->value == NULL)
			continue;
		capacity = a->value_maxlen > a->value_len ?
		    a->value_maxlen : a->value_len;
		memmove(db->val_store + used, a->value, capacity);
		a->value = db->val_store + used;
		used += capacity;
	}
	db->val_used = used;

	if (db->count > 0)
		db->next_handle = db->attrs[db->count - 1].handle + 1;
	else
		db->next_handle = 0x0001;

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

struct att_attr *
attdb_find_by_handle(struct att_db *db, uint16_t handle)
{

	return (attdb_find(db, handle));
}

/*
 * Overwrite a characteristic value in place, addressed by its 16-bit UUID.
 * Used to update built-in values at runtime (e.g. the GAP Device Name, 0x2A00,
 * from the SET_NAME operator verb).  The new value must fit the attribute's
 * reserved capacity (value_maxlen); a longer value is rejected without
 * mutating the database.  Returns 0 on success, -1 if not found or too long.
 */
int
attdb_set_char_value(struct att_db *db, uint16_t uuid16, const void *val,
    uint16_t len)
{
	int i;

	for (i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];

		if (!a->is_char_value || a->uuid16 != uuid16)
			continue;
		if (a->value == NULL || len > a->value_maxlen)
			return (-1);
		memcpy(a->value, val, len);
		a->value_len = len;
		return (0);
	}
	return (-1);
}

/* ----------------------------------------------------------------
 *  Response senders and permission checks
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

	BLUED_PROBE_ATT_ERROR(req_op, handle, code);

	return (att_server_send(ac, pdu, 5) == 5 ? 0 : -1);
}

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
	/* Core 6.3 Vol 3 Part F §3.2.5: authentication-required access
	 * fails with Insufficient Authentication, even if the link is also
	 * currently unencrypted. */
	if ((a->perms & ATT_PERM_READ_AUTHEN) && !ac->authenticated)
		return (ATT_ERR_INSUFF_AUTHEN);
	if ((a->perms & ATT_PERM_READ_AUTHEN) && ac->encrypted &&
	    ac->enc_key_size > 0 && ac->enc_key_size < mks)
		return (ATT_ERR_INSUFF_ENC_KEY_SIZE);
	return (0);
}

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
	/* See the authentication-required error rule above (§3.2.5). */
	if ((a->perms & ATT_PERM_WRITE_AUTHEN) && !ac->authenticated)
		return (ATT_ERR_INSUFF_AUTHEN);
	if ((a->perms & ATT_PERM_WRITE_AUTHEN) && ac->encrypted &&
	    ac->enc_key_size > 0 && ac->enc_key_size < mks)
		return (ATT_ERR_INSUFF_ENC_KEY_SIZE);
	return (0);
}

/*
 * A-F2: evaluate a connection against the encryption/authentication requirement
 * encoded in an arbitrary permission mask, ignoring the plain READ/WRITE
 * "permitted" bits.  Used to make a CCCD (created plaintext READ|WRITE) inherit
 * its parent characteristic's security level (Core Spec Vol 3 Part G §3.3.3.3 /
 * §10.3.1.1) and to gate notification/indication delivery on that same level.
 * Returns 0 if the link satisfies the requirement, else the ATT error code.
 */
int
att_check_security_perms(uint8_t perms, const struct att_conn *ac)
{
	uint8_t mks = ac->min_key_size ? ac->min_key_size : 16;
	bool need_enc = (perms & (ATT_PERM_READ_ENCRYPT |
	    ATT_PERM_WRITE_ENCRYPT)) != 0;
	bool need_auth = (perms & (ATT_PERM_READ_AUTHEN |
	    ATT_PERM_WRITE_AUTHEN)) != 0;

	if (need_auth && !ac->authenticated)
		return (ATT_ERR_INSUFF_AUTHEN);
	if (need_enc && !ac->encrypted)
		return (ATT_ERR_INSUFF_ENCRYPTION);
	if ((need_enc || need_auth) && ac->encrypted &&
	    ac->enc_key_size > 0 && ac->enc_key_size < mks)
		return (ATT_ERR_INSUFF_ENC_KEY_SIZE);
	return (0);
}

/*
 * C2-M6: notification/indication delivery and the CCCD write that enables it
 * both reflect a READ of the characteristic value (the notified payload is
 * read data).  Gating them on the merged read|write security bits is wrong: a
 * plaintext-readable but encrypted-writable Notify characteristic would then
 * refuse an unencrypted client's CCCD write and drop its notifications even
 * though the payload is freely readable.  Evaluate only the READ-side security
 * requirement (Core Spec Vol 3 Part G §3.3.3.3 / §10.3.1.1) by masking off the
 * write-side encryption/authentication bits before the shared check.
 */
int
att_check_security_perms_read(uint8_t perms, const struct att_conn *ac)
{

	return (att_check_security_perms(perms &
	    (ATT_PERM_READ_ENCRYPT | ATT_PERM_READ_AUTHEN), ac));
}

/*
 * Apply an HCI Encryption Change to a connection's ATT security state, gated
 * on real key material.
 *
 * Trust chain (Core Spec Vol 3 Part H §2.1, §2.4.4; Part F §3.2.5): an HCI
 * Encryption Change event only proves the controller enabled link encryption.
 * It does NOT prove that the encryption is bound to an authenticated key
 * negotiated with THIS peer identity -- a spurious or mismatched
 * encryption-enable must not be allowed to open ATT gates.  The ATT layer
 * therefore refuses to honor encryption on the event alone: it opens the gate
 * only when the caller can attest the link is backed by established key
 * material for this peer -- a stored bond LTK (reconnection) or the LTK just
 * distributed by a completed SMP session on this connection (first bonding).
 * With no such key the gate stays closed and protected attributes remain
 * inaccessible, so an attacker who never actually authenticated cannot reach
 * encrypt/authenticate-required attributes by forcing an encryption event.
 *
 * has_key_material: a bond LTK / just-completed SMP LTK backs this link.
 * mitm:             the backing key was established with MITM protection.
 * bond_key_size:    negotiated size 7..16, or 0 if unknown (use link size).
 * link_key_size:    key size reported alongside the encryption event.
 * Returns true if the gate was opened.
 */
bool
att_conn_apply_encryption(struct att_conn *ac, bool has_key_material,
    bool mitm, uint8_t bond_key_size, uint8_t link_key_size)
{

	if (ac == NULL)
		return (false);
	if (!has_key_material)
		return (false);
	ac->encrypted = true;
	if (bond_key_size >= 7 && bond_key_size <= 16)
		ac->enc_key_size = bond_key_size;
	else
		ac->enc_key_size = link_key_size;
	/*
	 * S-m9: set authenticated strictly from the backing key's MITM status.
	 * A prior assignment only ever set it true, so a reused att_conn whose
	 * new link is encrypted but unauthenticated would retain a stale true.
	 * Assigning unconditionally keeps this idempotent.
	 */
	ac->authenticated = mitm;
	return (true);
}
