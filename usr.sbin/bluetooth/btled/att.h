/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BTLED_ATT_H_
#define _BTLED_ATT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
#define ATT_OP_WRITE_REQ		0x12
#define ATT_OP_WRITE_RSP		0x13
#define ATT_OP_WRITE_CMD		0x52
#define ATT_OP_HANDLE_NOTIFY		0x1B
#define ATT_OP_HANDLE_IND		0x1D
#define ATT_OP_HANDLE_CFM		0x1E
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
#define ATT_MAX_MTU			517

/* EATT (Enhanced ATT) — Core Spec Vol 3 Part G Section 5.3 */
#define ATT_EATT_PSM			0x0027
#define ATT_MAX_EATT_BEARERS		5

/* GATT UUIDs (Core Spec Vol 3 Part G Section 3) */
#define GATT_UUID_PRIMARY_SERVICE	0x2800
#define GATT_UUID_SECONDARY_SERVICE	0x2801
#define GATT_UUID_INCLUDE		0x2802
#define GATT_UUID_CHARACTERISTIC	0x2803
#define GATT_UUID_CCCD			0x2902
#define GATT_UUID_REPORT_REFERENCE	0x2908

/* Characteristic properties (Core Spec Vol 3 Part G Section 3.3.1.1) */
#define GATT_PROP_BROADCAST		0x01
#define GATT_PROP_READ			0x02
#define GATT_PROP_WRITE_NO_RSP		0x04
#define GATT_PROP_WRITE			0x08
#define GATT_PROP_NOTIFY		0x10
#define GATT_PROP_INDICATE		0x20
#define GATT_PROP_AUTH_SIGNED_WRITE	0x40
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
};

/*
 * ATT connection state.
 */
struct att_conn {
	int		fd;		/* L2CAP ATT socket (primary bearer) */
	uint16_t	mtu;		/* negotiated MTU */
	uint8_t		*buf;		/* receive buffer */

	/* EATT bearers (additional to primary) */
	struct att_bearer	eatt[ATT_MAX_EATT_BEARERS];
	int			eatt_count;	/* number of active EATT bearers */
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
int	att_open(struct att_conn *ac, const uint8_t *addr, uint8_t addr_type);
int	att_open_fd(struct att_conn *ac, int fd, const uint8_t *addr,
	    uint8_t addr_type);
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
int	att_read_by_group_type(struct att_conn *ac, uint16_t start,
	    uint16_t end, uint16_t uuid16, void *buf, size_t buflen,
	    size_t *outlen);
int	att_recv(struct att_conn *ac, void *buf, size_t buflen, size_t *outlen);
int	att_confirm(struct att_conn *ac);
int	att_open_eatt(struct att_conn *ac, const uint8_t *addr,
	    uint8_t addr_type, int count);
void	att_close_eatt(struct att_conn *ac);
int	att_eatt_select_bearer(struct att_conn *ac);
int	att_eatt_accept(struct att_conn *ac, int listen_fd);

#endif /* _BTLED_ATT_H_ */
