/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_ATT_H_
#define _BLUED_ATT_H_

#include <sys/time.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#include "att_server.h"

/*
 * ATT opcode fields (Core Spec Vol 3 Part F Section 3.3.1, Table 3.2):
 * bit 6 is the Command Flag and bits 5-0 are the Method.
 */
#define ATT_OPCODE_COMMAND_FLAG		0x40
#define ATT_OPCODE_METHOD_MASK		0x3F

/* ATT opcodes (Core Spec Vol 3 Part F Section 3.4) */
#define ATT_OP_ERROR_RSP		0x01
#define ATT_OP_MTU_REQ			0x02
#define ATT_OP_MTU_RSP			0x03
#define ATT_OP_FIND_INFO_REQ		0x04
#define ATT_OP_FIND_INFO_RSP		0x05
#define ATT_OP_FIND_BY_TYPE_VALUE_REQ	0x06
#define ATT_OP_FIND_BY_TYPE_VALUE_RSP	0x07
#define ATT_OP_READ_BY_TYPE_REQ		0x08
#define ATT_OP_READ_BY_TYPE_RSP		0x09
#define ATT_OP_READ_REQ			0x0A
#define ATT_OP_READ_RSP			0x0B
#define ATT_OP_READ_BLOB_REQ		0x0C
#define ATT_OP_READ_BLOB_RSP		0x0D
#define ATT_OP_READ_MULTIPLE_REQ	0x0E
#define ATT_OP_READ_MULTIPLE_RSP	0x0F
#define ATT_OP_WRITE_REQ		0x12
#define ATT_OP_WRITE_RSP		0x13
#define ATT_OP_PREPARE_WRITE_REQ	0x16
#define ATT_OP_PREPARE_WRITE_RSP	0x17
#define ATT_OP_EXECUTE_WRITE_REQ	0x18
#define ATT_OP_EXECUTE_WRITE_RSP	0x19
/* Core 6.3 Vol 3 Part F §3.4.6.3, Table 3.35. */
#define ATT_EXECUTE_WRITE_CANCEL	0x00
#define ATT_EXECUTE_WRITE_COMMIT	0x01
/*
 * Core 6.3 Vol 3 Part F Table 3.42 marks 0xD2 "previously used".
 * Retained only for interoperability with peers implementing the removed
 * Authenticated Signed Writes feature (Vol 1 Part E §2.4.2).
 */
#define ATT_OP_LEGACY_SIGNED_WRITE_CMD	0xD2
/* Source compatibility; new code must use the explicitly legacy name. */
#define ATT_OP_SIGNED_WRITE_CMD		ATT_OP_LEGACY_SIGNED_WRITE_CMD
#define ATT_OP_WRITE_CMD		0x52
#define ATT_OP_HANDLE_NOTIFY		0x1B
#define ATT_OP_HANDLE_IND		0x1D
#define ATT_OP_HANDLE_CFM		0x1E
#define ATT_OP_READ_MULTIPLE_VARIABLE_REQ 0x20
#define ATT_OP_READ_MULTIPLE_VARIABLE_RSP 0x21
#define ATT_OP_MULTIPLE_HANDLE_VALUE_NTF 0x23
#define ATT_OP_READ_BY_GROUP_TYPE_REQ	0x10
#define ATT_OP_READ_BY_GROUP_TYPE_RSP	0x11

/* ATT error codes (Core Spec Vol 3 Part F Section 3.4.1.1) */
#define ATT_ERR_INVALID_HANDLE		0x01
#define ATT_ERR_READ_NOT_PERMITTED	0x02
#define ATT_ERR_WRITE_NOT_PERMITTED	0x03
#define ATT_ERR_INVALID_PDU		0x04
#define ATT_ERR_INSUFF_AUTHEN		0x05
#define ATT_ERR_REQ_NOT_SUPPORTED	0x06
#define ATT_ERR_INVALID_OFFSET		0x07
#define ATT_ERR_INSUFF_AUTHOR		0x08
#define ATT_ERR_PREPARE_QUEUE_FULL	0x09
#define ATT_ERR_ATTR_NOT_FOUND		0x0A
#define ATT_ERR_ATTR_NOT_LONG		0x0B
#define ATT_ERR_INSUFF_ENC_KEY_SIZE	0x0C
#define ATT_ERR_INVALID_ATTR_LEN	0x0D
#define ATT_ERR_UNLIKELY_ERROR		0x0E
#define ATT_ERR_INSUFF_ENCRYPTION	0x0F
#define ATT_ERR_UNSUPPORTED_GROUP_TYPE	0x10
#define ATT_ERR_INSUFF_RESOURCES	0x11
#define ATT_ERR_DATABASE_OUT_OF_SYNC	0x12
#define ATT_ERR_VALUE_NOT_ALLOWED	0x13

/* Default and limits */
#define ATT_DEFAULT_MTU			23
/*
 * The LE fixed-CID (unenhanced) ATT bearer is limited to 517 octets.
 * ATT Exchange MTU advertises the largest PDU the endpoint can receive,
 * so this is both the value we offer as a server and the largest value we
 * request as a client on CID 0x0004.
 *
 * An EATT bearer uses a dynamically allocated L2CAP CID instead: its
 * ATT_MTU is the L2CAP MTU negotiated for that bearer (Core Spec Vol 3,
 * Part F §3.2.8; Vol 3, Part G §5.3.1), and can be larger.  Keep the
 * heap receive buffer large enough for that separate path.
 */
#define ATT_UNENHANCED_MAX_MTU		517
#define ATT_MAX_MTU			65535
#define ATT_PDU_BUF_SIZE		ATT_UNENHANCED_MAX_MTU

/* EATT (Enhanced ATT) — Core Spec Vol 3 Part G Section 5.3 */
#define ATT_EATT_PSM			0x0027
#define ATT_MAX_EATT_BEARERS		5
#define ATT_EATT_MIN_MTU		64

/* GATT UUIDs (Core Spec Vol 3 Part G Section 3) */
#define GATT_UUID_PRIMARY_SERVICE	0x2800
#define GATT_UUID_SECONDARY_SERVICE	0x2801
#define GATT_UUID_INCLUDE		0x2802
#define GATT_UUID_CHARACTERISTIC	0x2803
#define GATT_UUID_CCCD			0x2902
#define GATT_UUID_REPORT_REFERENCE	0x2908

/* Characteristic properties (Core 6.3 Vol 3 Part G §3.3.1.1, Table 3.5) */
#define GATT_PROP_BROADCAST		0x01
#define GATT_PROP_READ			0x02
#define GATT_PROP_WRITE_NO_RSP		0x04
#define GATT_PROP_WRITE			0x08
#define GATT_PROP_NOTIFY		0x10
#define GATT_PROP_INDICATE		0x20
/* 0x40 is "Previously used" in Core 6.3; legacy signed-write compatibility. */
#define GATT_PROP_LEGACY_AUTH_SIGNED_WRITE 0x40
#define GATT_PROP_AUTH_SIGNED_WRITE GATT_PROP_LEGACY_AUTH_SIGNED_WRITE
#define GATT_PROP_EXTENDED		0x80

/* CCCD values */
#define GATT_CCCD_NOTIFY		0x0001
#define GATT_CCCD_INDICATE		0x0002

/*
 * EATT bearer state.
 * Each bearer is an independent L2CAP CoC channel on PSM 0x0027,
 * capable of carrying ATT PDUs in parallel with the primary bearer.
 */
struct att_bearer {
	int		fd;		/* L2CAP CoC socket */
	uint16_t	mtu;		/* negotiated MTU for this bearer */
	bool		active;		/* bearer is connected */
	int		pending;	/* 0 or 1: ATT permits one request per bearer */
};

/*
 * Deferred-access state (dynamic read / per-access authorization).
 *
 * kind == ATT_PEND_NONE means no access is deferred.  A single slot is
 * sufficient because ATT is a sequential transaction protocol: at most one
 * request is outstanding on a bearer at a time (Core Spec Vol 3 Part F
 * §3.3.3).  The bearer socket and MTU are captured at defer time so the
 * response can be completed out-of-line after the app replies, even though
 * ac->bearer_fd/mtu are only transiently set during dispatch.
 */
#define ATT_PEND_NONE		0
#define ATT_PEND_READ		1	/* dynamic read: app supplies value */
#define ATT_PEND_AUTH_READ	2	/* authorize a read, then serve */
#define ATT_PEND_AUTH_WRITE	3	/* authorize a write, then apply */

/* Largest deferred write payload retained for a to-be-authorized write. */
#define ATT_PEND_WVAL_MAX	512

struct att_pending {
	uint8_t		kind;		/* ATT_PEND_* */
	uint8_t		req_op;		/* originating ATT opcode */
	bool		with_response;	/* write path: Write Req vs Write Cmd */
	uint16_t	handle;
	uint16_t	offset;		/* Read Blob offset (0 for plain Read) */
	int		owner_fd;	/* ctl client owning the attribute */
	int		bearer_fd;	/* bearer to answer on (-1 = primary) */
	uint16_t	bearer_mtu;	/* effective MTU captured at defer time */
	uint16_t	wlen;		/* deferred write length */
	uint8_t		wval[ATT_PEND_WVAL_MAX];
	struct timeval	deadline;	/* app must reply before this instant */
};

/*
 * ATT connection state.
 */
struct att_conn {
	int		fd;		/* L2CAP ATT socket (primary bearer) */
	uint16_t	mtu;		/* negotiated MTU */
	bool		mtu_exchanged;	/* MTU exchange already done */
	bool		failed;		/* bearer is dead after a transaction
					 * timeout / reset / protocol fault:
					 * no further ATT PDUs may be sent on
					 * this bearer, a new bearer is
					 * required (Core Spec Vol 3 Part F
					 * §3.3.3) */
	uint8_t		*buf;		/* receive buffer */
	atomic_bool	bearer_lock;	/* protects bearer allocation/removal */
	int		primary_pending; /* 0 or 1 outstanding request */
	bool		encrypted;	/* link is encrypted (AES-CCM) */
	bool		authenticated;	/* encryption uses authenticated key (MITM) */
	uint8_t		enc_key_size;	/* negotiated encryption key size (0 = not set) */
	uint8_t		min_key_size;	/* minimum acceptable key size (from config) */
	uint16_t	con_handle;	/* HCI connection handle (for logging) */

	/* GATT Robust Caching (Core Spec Vol 3 Part G §2.5.2.1) */
	bool		robust_caching;	/* client set Robust Caching bit in 0x2B29 */
	bool		multi_notify;	/* client set Multiple Handle Value
					 * Notifications bit (CSF bit 2, 0x2B29;
					 * Core Spec Vol 3 Part G §7.2) */
	bool		change_aware;	/* client has read current DB hash */
	bool		out_of_sync_sent; /* Database Out Of Sync error sent once
					   * on this bearer (Fig 2.7): the next
					   * request makes the client change-aware */

	/* Indication flow control (Core Spec Vol 3 Part F §3.3.2) */
	bool		ind_pending;	/* indication sent, awaiting confirmation */
	uint16_t	ind_handle;	/* value handle of the pending indication */
	uintptr_t	ind_timer;	/* kqueue EVFILT_TIMER ident, 0 if none */

	/* Prepare/Execute Write queue (per-connection) */
	struct att_prepare_queue	prep_queue;

	/* Per-connection CCCD values (Core Spec Vol 3 Part G §3.3.3.3) */
	struct att_cccd_entry	cccds[ATT_MAX_CCCDS_PER_CONN];
	int			cccd_count;

	/* EATT bearers (additional to primary) */
	struct att_bearer	eatt[ATT_MAX_EATT_BEARERS];
	int			eatt_count;	/* number of active EATT bearers */
	/* Deliver unsolicited PDUs consumed while a request awaits its response. */
	void			(*unsolicited_cb)(struct att_conn *, int,
			    const uint8_t *, size_t, void *);
	void			*unsolicited_arg;

	/*
	 * Write Commands whose ordering matters (for example Mesh Proxy SAR
	 * segments) must use one ATT bearer.  Unlike request transactions,
	 * commands have no response that could be used to reconstruct their
	 * order after they are distributed over EATT bearers.  Pin commands to
	 * one bearer until that bearer is removed or the connection is closed.
	 */
	int			write_cmd_bearer_fd;
	bool			write_cmd_bearer_pinned;

	/* Peer CSRK for ATT Signed Write verification */
	uint8_t			peer_csrk[16];
	bool			has_peer_csrk;

	/* Sign counter for replay protection (Core Spec Vol 3 Part H §2.4.5) */
	uint32_t		peer_sign_counter;
	bool			has_peer_sign_counter;
	/*
	 * Optional hook to write an advanced peer sign counter through to
	 * durable bond storage so the replay floor survives reconnection.
	 * The owning layer installs it; it is NULL when the bearer runs
	 * without a bond database.
	 */
	int			(*persist_sign_counter)(struct att_conn *ac,
				    uint32_t counter);

	/*
	 * Transient bearer context for att_server_handle().
	 * Set during request dispatch so response helpers send on the
	 * correct bearer.  -1 / 0 means use the primary bearer (fd/mtu).
	 */
	int			bearer_fd;	/* -1 = use primary */
	uint16_t		bearer_mtu;	/* 0 = use primary mtu */

	/* Deferred access awaiting an app reply (dynamic read / authorize). */
	struct att_pending	pending;
};

/*
 * ATT error response parsed.
 */
struct att_error {
	uint8_t		req_opcode;
	uint16_t	handle;
	uint8_t		code;
};

/* att.c */
int	att_open(struct att_conn *ac, const uint8_t *local_addr,
	    uint8_t own_addr_type, const uint8_t *addr, uint8_t addr_type);
int	att_open_fd(struct att_conn *ac, int fd, const uint8_t *local_addr,
	    uint8_t own_addr_type, const uint8_t *addr, uint8_t addr_type);
void	att_close(struct att_conn *ac);
int	att_exchange_mtu(struct att_conn *ac, uint16_t client_mtu);
int	att_read(struct att_conn *ac, uint16_t handle,
	    void *buf, size_t buflen, size_t *outlen);
int	att_read_blob(struct att_conn *ac, uint16_t handle, uint16_t offset,
	    void *buf, size_t buflen, size_t *outlen);
int	att_write_req(struct att_conn *ac, uint16_t handle,
	    const void *data, size_t len);
int	att_write_cmd(struct att_conn *ac, uint16_t handle,
	    const void *data, size_t len);
int	att_find_info(struct att_conn *ac, uint16_t start, uint16_t end,
	    void *buf, size_t buflen, size_t *outlen);
int	att_read_by_type(struct att_conn *ac, uint16_t start, uint16_t end,
	    uint16_t uuid16, void *buf, size_t buflen, size_t *outlen);
int	att_read_by_type_uuid128(struct att_conn *ac, uint16_t start,
	    uint16_t end, const uint8_t uuid[16], void *buf, size_t buflen,
	    size_t *outlen);
int	att_read_by_group_type(struct att_conn *ac, uint16_t start,
	    uint16_t end, uint16_t uuid16, void *buf, size_t buflen,
	    size_t *outlen);
int	att_find_by_type_value(struct att_conn *ac, uint16_t start,
	    uint16_t end, uint16_t uuid16, const void *value, size_t vlen,
	    void *buf, size_t buflen, size_t *outlen);
int	att_read_multiple(struct att_conn *ac, const uint16_t *handles,
	    int count, void *buf, size_t buflen, size_t *outlen);
int	att_read_multiple_variable(struct att_conn *ac,
	    const uint16_t *handles, int count,
	    void *buf, size_t buflen, size_t *outlen);
int	att_prepare_write(struct att_conn *ac, uint16_t handle,
	    uint16_t offset, const void *data, size_t len);
int	att_execute_write(struct att_conn *ac, uint8_t flags);
int	att_write_long(struct att_conn *ac, uint16_t handle,
	    const void *data, size_t len);
int	att_recv(struct att_conn *ac, void *buf, size_t buflen, size_t *outlen);
int	att_confirm(struct att_conn *ac);
int	att_recv_bearer(struct att_conn *ac, int fd, void *buf,
	    size_t buflen, size_t *outlen);
int	att_confirm_bearer(struct att_conn *ac, int fd);
void	att_set_unsolicited_handler(struct att_conn *ac,
	    void (*cb)(struct att_conn *, int, const uint8_t *, size_t, void *),
	    void *arg);
int	att_open_eatt(struct att_conn *ac, const uint8_t *local_addr,
	    const uint8_t *addr, uint8_t addr_type, int count);
void	att_close_eatt(struct att_conn *ac);
int	att_eatt_select_bearer(struct att_conn *ac);
int	att_eatt_accept(struct att_conn *ac, int listen_fd);
int	att_eatt_add_bearer(struct att_conn *ac, int fd);
void	att_eatt_remove_bearer(struct att_conn *ac, int fd);

#endif /* _BLUED_ATT_H_ */
