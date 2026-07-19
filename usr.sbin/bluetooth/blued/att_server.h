/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_ATT_SERVER_H_
#define _BLUED_ATT_SERVER_H_

#include <sys/time.h>

#include <stdbool.h>
#include <stdint.h>

/* Per-connection CCCD state (Core Spec Vol 3 Part G Section 3.3.3.3) */
#define ATT_MAX_CCCDS_PER_CONN		32

struct att_cccd_entry {
	uint16_t	handle;
	uint16_t	value;
};

/* Prepare Write queue limits */
#define ATT_PREPARE_QUEUE_MAX		16
#define ATT_PREPARE_QUEUE_MAX_BYTES	4096	/* total data bytes across all entries */

struct att_prepare_entry {
	uint16_t	handle;
	uint16_t	offset;
	uint16_t	len;
	uint8_t		value[512]; /* max value per prepare (ATT_PDU_BUF_SIZE - 5) */
};

struct att_prepare_queue {
	struct att_prepare_entry entries[ATT_PREPARE_QUEUE_MAX];
	int		count;
	uint32_t	total_bytes;	/* total queued value bytes */
};

/* Attribute permissions */
#define ATT_PERM_READ		0x01
#define ATT_PERM_WRITE		0x02
#define ATT_PERM_READ_ENCRYPT	0x04
#define ATT_PERM_WRITE_ENCRYPT	0x08
#define ATT_PERM_READ_AUTHEN	0x10	/* requires authenticated encryption */
#define ATT_PERM_WRITE_AUTHEN	0x20	/* requires authenticated encryption */

/*
 * Per-attribute application-backing flags (set at ADD_CHAR time).
 *
 * DYNAMIC: the owning app supplies the value on demand for every peer read
 * instead of the server returning a stored value.  The ATT Read/Read-Blob
 * response is withheld until the app replies with the bytes.
 *
 * AUTHORIZE: the owning app authorizes each individual read/write before it
 * is served (Core Spec Vol 3 Part G §8.2 authorization).  A denial yields
 * ATT Insufficient Authorization (0x08).
 */
#define ATT_ATTR_F_DYNAMIC	0x01
#define ATT_ATTR_F_AUTHORIZE	0x02

/*
 * Single attribute in the GATT database.
 */
struct att_attr {
	uint16_t	handle;
	uint16_t	uuid16;		/* 0 if using uuid128 */
	uint8_t		uuid128[16];
	uint8_t		perms;
	uint8_t		flags;		/* ATT_ATTR_F_* app-backing flags */
	bool		is_char_value;	/* true for characteristic value attrs
					 * (excluded from DB hash per §7.3.1) */
	int		owner_fd;	/* ctl client fd that registered this attr,
					 * -1 for config-driven / built-in attrs */
	uint8_t		*value;		/* points into val_store */
	uint16_t	value_len;
	uint16_t	value_maxlen;	/* for writable attrs (e.g. CCCD) */
	uint16_t	end_group_handle; /* for service decls (0x2800/0x2801):
					   * last handle in this service group.
					   * 0 = compute after database assembly. */
};

/*
 * Attribute database.
 */
struct att_db {
	struct att_attr	*attrs;
	int		count;
	int		max;
	uint16_t	next_handle;
	uint8_t		*val_store;	/* backing storage for values */
	size_t		val_used;
	size_t		val_size;
};

struct att_conn;	/* forward decl from att.h */

/* Database construction */
void		attdb_init(struct att_db *db, struct att_attr *storage, int max,
		    uint8_t *val_buf, size_t val_size);
uint16_t	attdb_add_service(struct att_db *db, uint16_t uuid16);
uint16_t	attdb_add_service128(struct att_db *db,
		    const uint8_t uuid128[16]);
uint16_t	attdb_add_characteristic(struct att_db *db, uint16_t uuid16,
		    uint8_t props, uint8_t perms,
		    const void *value, uint16_t len);
uint16_t	attdb_add_characteristic128(struct att_db *db,
		    const uint8_t uuid128[16], uint8_t props, uint8_t perms,
		    const void *value, uint16_t len);
uint16_t	attdb_add_cccd(struct att_db *db);
uint16_t	attdb_add_include(struct att_db *db, uint16_t svc_handle,
		    uint16_t start, uint16_t end, uint16_t uuid16);
uint16_t	attdb_add_descriptor(struct att_db *db, uint16_t uuid16,
		    uint8_t perms, const void *value, uint16_t len);
uint16_t	attdb_add_descriptor128(struct att_db *db,
		    const uint8_t uuid128[16], uint8_t perms,
		    const void *value, uint16_t len);
int		attdb_remove_service(struct att_db *db, uint16_t handle);

/*
 * Snapshot src into dst, keeping dst's own attrs/val_store backing and
 * re-basing value pointers onto it.  Returns 0 on success, -1 if dst is too
 * small.  Backs staged (atomic) GATT-application registration.
 */
int		attdb_copy(struct att_db *dst, const struct att_db *src);

/* Lookup */
struct att_attr	*attdb_find_by_handle(struct att_db *db, uint16_t handle);

/*
 * Overwrite a characteristic value in place by 16-bit UUID (bounded by the
 * attribute's reserved capacity).  Returns 0 on success, -1 if absent or the
 * new value exceeds capacity.
 */
int		attdb_set_char_value(struct att_db *db, uint16_t uuid16,
		    const void *val, uint16_t len);

/* Request handling */
int		att_server_handle(struct att_conn *ac, struct att_db *db,
		    const uint8_t *pdu, size_t len,
		    int bearer_fd, uint16_t bearer_mtu);
void		att_server_reset(struct att_conn *ac);

/*
 * Deferred access — dynamic reads and per-access authorization.
 *
 * When a peer accesses an attribute flagged ATT_ATTR_F_DYNAMIC/AUTHORIZE the
 * dispatcher withholds the ATT response and records a single pending access on
 * the bearer (Core Spec Vol 3 Part F §3.3.3: ATT is a sequential transaction
 * protocol, so at most one request is outstanding per bearer).  The owning app
 * later resolves it out-of-line via these helpers, which complete the response
 * on the bearer captured at defer time and clear the pending state.
 *
 * All are no-ops (returning 0) when no matching pending access is active, so a
 * stale or duplicate reply cannot desynchronise the bearer.
 */
bool		att_server_pending_active(const struct att_conn *ac);
uint16_t	att_server_pending_handle(const struct att_conn *ac);
int		att_server_pending_owner(const struct att_conn *ac);
bool		att_server_pending_is_read(const struct att_conn *ac);
bool		att_server_pending_is_authorize(const struct att_conn *ac);

/* Dynamic read: supply the value, or reject with an ATT error code. */
int		att_server_complete_read(struct att_conn *ac,
		    const uint8_t *value, uint16_t len);
int		att_server_reject_read(struct att_conn *ac, uint8_t att_error);

/* Authorization: allow (serve/apply the deferred access) or deny (0x08). */
int		att_server_complete_authorize(struct att_conn *ac,
		    struct att_db *db, bool allow);

/*
 * Release a pending access without answering the peer — used when the bearer
 * is torn down while a reply is outstanding (no ATT PDU is sent).
 */
void		att_server_pending_clear(struct att_conn *ac);

/*
 * Bounded-timeout backstop: if a pending access has passed its deadline,
 * answer the peer with an ATT error and release it.  Returns 1 if it expired,
 * 0 otherwise.  Pass the current time (CLOCK_REALTIME via gettimeofday, or a
 * test-supplied value).
 */
int		att_server_pending_expire(struct att_conn *ac,
		    const struct timeval *now);

/* Seconds an app has to answer a deferred access (ATT transaction timeout). */
#define ATT_PENDING_TIMEOUT_SEC	30

/* Response senders */
int		att_send_error(struct att_conn *ac, uint8_t req_op,
		    uint16_t handle, uint8_t code);
int		att_send_notification(struct att_conn *ac, uint16_t handle,
		    const void *value, uint16_t len);
int		att_send_indication(struct att_conn *ac, uint16_t handle,
		    const void *value, uint16_t len);
int		att_check_read_perm(const struct att_attr *a,
		    const struct att_conn *ac);
int		att_check_write_perm(const struct att_attr *a,
		    const struct att_conn *ac);
bool		att_conn_apply_encryption(struct att_conn *ac,
		    bool has_key_material, bool mitm, uint8_t bond_key_size,
		    uint8_t link_key_size);
int		att_send_multiple_handle_value_ntf(struct att_conn *ac,
		    const uint16_t *handles, const uint8_t **values,
		    const uint16_t *lengths, int count);
int		att_notify_multi_gated(struct att_conn *ac,
		    const uint16_t *handles, const uint8_t **values,
		    const uint16_t *lengths, int count);

/*
 * Client Supported Features bits (0x2B29; Core Spec Vol 3 Part G §7.2,
 * Table 7.5).
 */
#define ATT_CLIENT_FEAT_ROBUST_CACHING	0x01	/* bit 0 */
#define ATT_CLIENT_FEAT_EATT		0x02	/* bit 1 */
#define ATT_CLIENT_FEAT_MULTI_NOTIFY	0x04	/* bit 2 */

/* GATT Caching — Database Hash (BT 5.1) */
void		attdb_compute_db_hash(struct att_db *db, uint8_t hash[16]);

#endif /* _BLUED_ATT_SERVER_H_ */
