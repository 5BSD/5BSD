/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_ATT_SERVER_H_
#define _BLUED_ATT_SERVER_H_

#include <stdint.h>

/* Prepare Write queue limits */
#define ATT_PREPARE_QUEUE_MAX	16

struct att_prepare_entry {
	uint16_t	handle;
	uint16_t	offset;
	uint16_t	len;
	uint8_t		value[512]; /* max value per prepare (ATT_MAX_MTU - 5) */
};

struct att_prepare_queue {
	struct att_prepare_entry entries[ATT_PREPARE_QUEUE_MAX];
	int		count;
};

/* Attribute permissions */
#define ATT_PERM_READ		0x01
#define ATT_PERM_WRITE		0x02
#define ATT_PERM_READ_ENCRYPT	0x04
#define ATT_PERM_WRITE_ENCRYPT	0x08

/*
 * Single attribute in the GATT database.
 */
struct att_attr {
	uint16_t	handle;
	uint16_t	uuid16;		/* 0 if using uuid128 */
	uint8_t		uuid128[16];
	uint8_t		perms;
	uint8_t		*value;		/* points into val_store */
	uint16_t	value_len;
	uint16_t	value_maxlen;	/* for writable attrs (e.g. CCCD) */
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

/* Request handling */
int		att_server_handle(struct att_conn *ac, struct att_db *db,
		    const uint8_t *pdu, size_t len);
void		att_server_reset(struct att_conn *ac);

/* Response senders */
int		att_send_error(struct att_conn *ac, uint8_t req_op,
		    uint16_t handle, uint8_t code);
int		att_send_notification(struct att_conn *ac, uint16_t handle,
		    const void *value, uint16_t len);
int		att_send_multiple_handle_value_ntf(struct att_conn *ac,
		    const uint16_t *handles, const uint8_t **values,
		    const uint16_t *lengths, int count);

/* GATT Robust Caching (BT 5.1, Core Spec Vol 3 Part G §7.3.1) */
#define ATT_CLIENT_FEAT_ROBUST_CACHING	0x01

/* GATT Caching — Database Hash (BT 5.1) */
void		attdb_compute_db_hash(struct att_db *db, uint8_t hash[16]);

#endif /* _BLUED_ATT_SERVER_H_ */
