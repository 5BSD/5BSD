/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libble — BLE client library implementation.
 *
 * Communicates with blued(8) over its Unix domain control socket using the
 * length-prefixed binary IPC protocol (see ipc_proto.h): ble_open() performs
 * the HELLO handshake, then correlated typed operations and events are
 * dispatched to registered callbacks by ble_process().
 */

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "ble.h"
#include "ipc_proto.h"

#define DEFAULT_SOCK	"/var/run/blued.sock"
#define MAX_NOTIFY_SUBS	16
#define HANDSHAKE_TIMEOUT_MS	2000
#define BLE_MAX_PENDING_OPS	64
#define BLE_MAX_TRACKED_CONNECTIONS	64

struct ble_tracked_connection {
	ble_addr_t	addr;
	uint16_t	mtu;
};

/* Per-handle notification subscription */
struct notify_sub {
	uint16_t	handle;
	ble_notify_cb	cb;
	void		*arg;
};

typedef void (*ble_op_reply_cb)(ble_ctx_t *, uint16_t, uint16_t,
    const uint8_t *, size_t, void *);

struct ble_pending_op {
	uint32_t	id;
	uint16_t	domain;
	uint16_t	opcode;
	ble_op_reply_cb	cb;
	void		*arg;
};

struct ble_scan_op {
	ble_scan_cb	cb;
	void		*arg;
};

struct ble_connect_op {
	ble_addr_t	addr;
	ble_connect_cb	cb;
	void		*arg;
};

struct ble_read_op {
	ble_addr_t	addr;
	ble_read_cb	cb;
	void		*arg;
};

struct ble_discover_op {
	ble_addr_t		addr;
	ble_discover_cb		cb;
	void			*arg;
	ble_service_t		svcs[16];
	int			nsvc;
	ble_characteristic_t	chars[64];
	int			nchar;
};

struct ble_ctx {
	int		fd;

	/*
	 * Framed binary protocol state (see ipc_proto.h).  Every context speaks
	 * the length-prefixed binary protocol; ble_handshake() negotiates the
	 * version and features and is run automatically by ble_open().
	 */
	bool		events_ok;	/* server accepted push-events */
	bool		fdpass_ok;	/* server accepted fd-passing */
	uint32_t	next_request_id;
	struct ble_pending_op pending_ops[BLE_MAX_PENDING_OPS];
	size_t		pending_count;
	uint8_t		rxbuf[IPC_HDR_SIZE + IPC_MAX_PAYLOAD];
	size_t		rxlen;

	/* Error state */
	int		last_error;	/* BLE_ERR_* code */
	char		errmsg[128];	/* human-readable description */

	/* Connection state keyed by controller + address type + address. */
	struct ble_tracked_connection connections[BLE_MAX_TRACKED_CONNECTIONS];
	size_t		connection_count;

	/* RSSI cache from last scan */
	ble_addr_t	rssi_addr;
	int8_t		rssi_value;
	bool		rssi_valid;

	/* Persistent callbacks */
	ble_notify_cb		notify_cb;	/* fallback for unmatched handles */
	void			*notify_arg;

	/* Per-handle notification dispatch */
	struct notify_sub	notify_subs[MAX_NOTIFY_SUBS];
	int			num_notify_subs;
	ble_write_req_cb	write_cb;
	void			*write_arg;
	ble_read_req_cb		read_req_cb;	/* EVENT READ (dynamic read) */
	void			*read_req_arg;
	ble_authorize_cb	authorize_cb;	/* EVENT AUTHORIZE */
	void			*authorize_arg;
	ble_passkey_display_cb	passkey_display_cb;
	void			*passkey_display_arg;
	ble_passkey_input_cb	passkey_input_cb;
	void			*passkey_input_arg;
	ble_numcmp_cb		numcmp_cb;
	void			*numcmp_arg;
	ble_keypress_cb		keypress_cb;	/* EVENT KEYPRESS */
	void			*keypress_arg;
	/* Connection-lifecycle push events (EVENT CONNECTED / DISCONNECTED) */
	ble_conn_event_cb	connected_cb;
	void			*connected_arg;
	ble_disconn_event_cb	disconnected_cb;
	void			*disconnected_arg;
	/* ISO (CIS/BIS) lifecycle push events. */
	ble_iso_cis_req_cb	iso_req_cb;
	void			*iso_req_arg;
	ble_iso_est_cb		iso_est_cb;
	void			*iso_est_arg;
	/* Pending handle return for add_service / add_char */
	uint16_t		*pending_handle;

};

static void ble_set_error(ble_ctx_t *, int, const char *);

static bool
ble_addr_equal(const ble_addr_t *a, const ble_addr_t *b)
{

	return (a->addr_type == b->addr_type &&
	    a->adapter_index == b->adapter_index &&
	    memcmp(a->addr, b->addr, sizeof(a->addr)) == 0);
}

static int
ble_connection_index(const ble_ctx_t *ctx, const ble_addr_t *addr)
{
	size_t i;

	for (i = 0; i < ctx->connection_count; i++)
		if (ble_addr_equal(&ctx->connections[i].addr, addr))
			return ((int)i);
	return (-1);
}

static void
ble_connection_upsert(ble_ctx_t *ctx, const ble_addr_t *addr, uint16_t mtu)
{
	int i;

	i = ble_connection_index(ctx, addr);
	if (i >= 0) {
		ctx->connections[i].mtu = mtu;
		return;
	}
	if (ctx->connection_count == BLE_MAX_TRACKED_CONNECTIONS)
		return;
	ctx->connections[ctx->connection_count].addr = *addr;
	ctx->connections[ctx->connection_count].mtu = mtu;
	ctx->connection_count++;
}

static void
ble_connection_remove(ble_ctx_t *ctx, const ble_addr_t *addr)
{
	int i;

	i = ble_connection_index(ctx, addr);
	if (i < 0)
		return;
	ctx->connection_count--;
	if ((size_t)i != ctx->connection_count)
		ctx->connections[i] = ctx->connections[ctx->connection_count];
	memset(&ctx->connections[ctx->connection_count], 0,
	    sizeof(ctx->connections[ctx->connection_count]));
}

/*
 * Send one framed message (header + payload) over a stream socket.
 */
static int
ble_send_frame(ble_ctx_t *ctx, uint16_t type, uint16_t arg,
    const void *payload, size_t plen)
{
	uint8_t hdr[IPC_HDR_SIZE];
	struct iovec iov[2];
	struct iovec *cur;
	struct msghdr msg;
	ssize_t n;
	int iovcnt;

	if (plen > IPC_MAX_PAYLOAD)
		return (-1);
	ipc_hdr_encode(hdr, (uint32_t)plen, type, arg);

	iov[0].iov_base = hdr;
	iov[0].iov_len = IPC_HDR_SIZE;
	iov[1].iov_base = (void *)(uintptr_t)payload;
	iov[1].iov_len = plen;
	cur = iov;
	iovcnt = (plen > 0) ? 2 : 1;

	while (iovcnt > 0) {
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = cur;
		msg.msg_iovlen = iovcnt;

		n = sendmsg(ctx->fd, &msg, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (n == 0) {
			errno = EPIPE;
			return (-1);
		}

		while (iovcnt > 0 && (size_t)n >= cur[0].iov_len) {
			n -= (ssize_t)cur[0].iov_len;
			cur++;
			iovcnt--;
		}
		if (iovcnt > 0 && n > 0) {
			cur[0].iov_base = (char *)cur[0].iov_base + n;
			cur[0].iov_len -= (size_t)n;
		}
	}

	return (0);
}

static int
ble_send_operation(ble_ctx_t *ctx, uint16_t domain, uint16_t opcode,
    const void *body, size_t body_len, ble_op_reply_cb cb, void *cb_arg,
    uint32_t *id_out)
{
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_MAX_PAYLOAD];
	uint32_t request_id;

	if (domain == 0 || body_len > IPC_MAX_PAYLOAD - IPC_OP_PREFIX_SIZE) {
		errno = EINVAL;
		ble_set_error(ctx, BLE_ERR_INVAL, "operation payload too large");
		return (-1);
	}
	if (ctx->pending_count == BLE_MAX_PENDING_OPS) {
		errno = EBUSY;
		ble_set_error(ctx, BLE_ERR_BUSY, "too many pending operations");
		return (-1);
	}
	request_id = ++ctx->next_request_id;
	if (request_id == 0)
		request_id = ++ctx->next_request_id;
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	memcpy(payload + IPC_OP_PREFIX_SIZE, body, body_len);
	if (ble_send_frame(ctx, IPC_T_OP_REQ, domain, payload,
	    IPC_OP_PREFIX_SIZE + body_len) < 0) {
		ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
		return (-1);
	}
	ctx->pending_ops[ctx->pending_count].id = request_id;
	ctx->pending_ops[ctx->pending_count].domain = domain;
	ctx->pending_ops[ctx->pending_count].opcode = opcode;
	ctx->pending_ops[ctx->pending_count].cb = cb;
	ctx->pending_ops[ctx->pending_count].arg = cb_arg;
	ctx->pending_count++;
	if (id_out != NULL)
		*id_out = request_id;
	return (0);
}

static int
ctl_send_typed(ble_ctx_t *ctx, uint16_t opcode, uint16_t flags,
    uint32_t arg0, uint32_t arg1)
{
	uint8_t payload[IPC_CTL_REQ_SIZE];

	ipc_ctl_req_encode(payload, opcode, flags, arg0, arg1);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_CTL, opcode, payload,
	    sizeof(payload), NULL, NULL, NULL));
}

static void
ble_set_error(ble_ctx_t *ctx, int code, const char *msg)
{

	ctx->last_error = code;
	strlcpy(ctx->errmsg, msg, sizeof(ctx->errmsg));
}

static void
ble_clear_error(ble_ctx_t *ctx)
{

	ctx->last_error = BLE_ERR_NONE;
	ctx->errmsg[0] = '\0';
}

const char *
ble_addr_str(const ble_addr_t *addr, char buf[18])
{
	bdaddr_t ba;

	memcpy(&ba, addr->addr, 6);
	bt_ntoa(&ba, buf);
	return (buf);
}

int
ble_addr_parse(const char *text, uint8_t addr_type, ble_addr_t *out)
{
	bdaddr_t addr;

	if (text == NULL || out == NULL || addr_type > 1 ||
	    !bt_aton(text, &addr))
		return (-1);
	memcpy(out->addr, &addr, sizeof(out->addr));
	out->addr_type = addr_type;
	out->adapter_index = 0;
	return (0);
}

static bool
ble_addr_valid(const ble_addr_t *addr)
{

	return (addr != NULL && addr->addr_type <= 1);
}

static int
ble_map_ipc_err(uint16_t code)
{

	switch (code) {
	case IPC_ERR_NONE:
		return (BLE_ERR_NONE);
	case IPC_ERR_INVAL:
	case IPC_ERR_TOOBIG:
		return (BLE_ERR_INVAL);
	case IPC_ERR_NOT_FOUND:
		return (BLE_ERR_NOTFOUND);
	case IPC_ERR_NOT_CONN:
		return (BLE_ERR_NOTCONN);
	case IPC_ERR_BUSY:
		return (BLE_ERR_BUSY);
	case IPC_ERR_PERM:
		return (BLE_ERR_PERM);
	case IPC_ERR_NOMEM:
		return (BLE_ERR_NOMEM);
	case IPC_ERR_PROTO:
		return (BLE_ERR_PROTO);
	case IPC_ERR_GENERIC:
	case IPC_ERR_UNKNOWN_CMD:
	case IPC_ERR_IO:
	default:
		return (BLE_ERR_DAEMON);
	}
}

static void
ble_fail_pending(ble_ctx_t *ctx, int code, uint16_t status, const char *msg)
{
	struct ble_pending_op pending[BLE_MAX_PENDING_OPS];
	size_t count, i;

	ble_set_error(ctx, code, (msg != NULL && *msg != '\0') ?
	    msg : "daemon error");
	count = ctx->pending_count;
	memcpy(pending, ctx->pending_ops, count * sizeof(pending[0]));
	ctx->pending_count = 0;
	for (i = 0; i < count; i++)
		if (pending[i].cb != NULL)
			pending[i].cb(ctx, pending[i].opcode, status,
			    NULL, 0, pending[i].arg);
	ctx->pending_handle = NULL;
}

/* Process one typed frame from the daemon. */
static void
ble_dispatch_frame(ble_ctx_t *ctx, uint16_t type, uint16_t arg,
    const uint8_t *pl, size_t plen)
{
	char line[IPC_MAX_PAYLOAD + 1];
	size_t l;

	l = (plen < IPC_MAX_PAYLOAD) ? plen : IPC_MAX_PAYLOAD;
	memcpy(line, pl, l);
	line[l] = '\0';

	switch (type) {
	case IPC_T_ERROR:
		ble_fail_pending(ctx, ble_map_ipc_err(arg), arg,
		    line[0] != '\0' ? line : NULL);
		break;
	case IPC_T_OP_REPLY: {
		struct ble_pending_op pending;
		uint32_t request_id;
		uint16_t status, flags;
		size_t i;

		if (plen < IPC_OP_PREFIX_SIZE || arg == 0) {
			ble_set_error(ctx, BLE_ERR_PROTO, "malformed operation reply");
			break;
		}
		ipc_op_prefix_decode(pl, &request_id, &status, &flags);
		for (i = 0; i < ctx->pending_count; i++)
			if (ctx->pending_ops[i].id == request_id &&
			    ctx->pending_ops[i].domain == arg)
				break;
		if (request_id == 0 || i == ctx->pending_count) {
			ble_set_error(ctx, BLE_ERR_PROTO,
			    "uncorrelated operation reply");
			break;
		}
		pending = ctx->pending_ops[i];
		memmove(&ctx->pending_ops[i], &ctx->pending_ops[i + 1],
		    (ctx->pending_count - i - 1) * sizeof(ctx->pending_ops[0]));
		ctx->pending_count--;
		if (flags != 0) {
			ble_set_error(ctx, BLE_ERR_PROTO,
			    "unknown operation reply flags");
			if (pending.cb != NULL)
				pending.cb(ctx, pending.opcode, IPC_ERR_PROTO, NULL, 0,
				    pending.arg);
			break;
		}
		if (status != IPC_ERR_NONE) {
			const uint8_t *msg = pl + IPC_OP_PREFIX_SIZE;
			size_t mlen = plen - IPC_OP_PREFIX_SIZE;

			if (mlen >= sizeof(line))
				mlen = sizeof(line) - 1;
			memcpy(line, msg, mlen);
			line[mlen] = '\0';
			ble_set_error(ctx, ble_map_ipc_err(status),
			    mlen != 0 ? line : "operation failed");
		}
		if (pending.cb != NULL)
			pending.cb(ctx, pending.opcode, status,
			    pl + IPC_OP_PREFIX_SIZE, plen - IPC_OP_PREFIX_SIZE,
			    pending.arg);
		break;
	}
	case IPC_T_OP_EVENT: {
		ble_addr_t addr;
		uint32_t request_id;
		uint16_t status, flags, event;
		size_t i;

		if (plen < IPC_OP_PREFIX_SIZE + 2) {
			ble_set_error(ctx, BLE_ERR_PROTO, "malformed operation event");
			break;
		}
		ipc_op_prefix_decode(pl, &request_id, &status, &flags);
		event = ipc_get_le16(pl + IPC_OP_PREFIX_SIZE);
		if (status != 0 || flags != 0) {
			ble_set_error(ctx, BLE_ERR_PROTO, "invalid operation event");
			break;
		}
		if (arg == IPC_OP_DOMAIN_GATT) {
			const uint8_t *body = pl + IPC_OP_PREFIX_SIZE;
			ble_notify_cb cb = NULL;
			void *cbarg = NULL;
			uint16_t handle, value_len, bearer_mtu;
			int si;

			if (request_id != 0) {
				struct ble_discover_op *op;

				for (i = 0; i < ctx->pending_count; i++)
					if (ctx->pending_ops[i].id == request_id &&
					    ctx->pending_ops[i].domain == arg)
						break;
				if (i == ctx->pending_count ||
				    ctx->pending_ops[i].opcode != IPC_GATT_DISCOVER ||
				    plen != IPC_OP_PREFIX_SIZE +
				    IPC_GATT_DISCOVERY_EVENT_SIZE) {
					ble_set_error(ctx, BLE_ERR_PROTO,
					    "malformed GATT discovery event");
					break;
				}
				op = ctx->pending_ops[i].arg;
				if (op == NULL) {
					ble_set_error(ctx, BLE_ERR_PROTO,
					    "discovery state missing");
					break;
				}
				if (event == IPC_GATT_EV_SERVICE &&
				    op->nsvc < 16) {
					ble_service_t *service =
					    &op->svcs[op->nsvc++];

					memset(service, 0, sizeof(*service));
					service->uuid.uuid16 = ipc_get_le16(body + 2);
					memcpy(service->uuid.uuid128, body + 4, 16);
					service->start_handle = ipc_get_le16(body + 20);
					service->end_handle = ipc_get_le16(body + 22);
				} else if (event == IPC_GATT_EV_CHARACTERISTIC &&
				    op->nchar < 64) {
					ble_characteristic_t *characteristic =
					    &op->chars[op->nchar++];

					memset(characteristic, 0,
					    sizeof(*characteristic));
					characteristic->uuid.uuid16 =
					    ipc_get_le16(body + 2);
					memcpy(characteristic->uuid.uuid128, body + 4, 16);
					characteristic->handle = ipc_get_le16(body + 20);
					characteristic->properties = body[22];
				} else if (event != IPC_GATT_EV_SERVICE &&
				    event != IPC_GATT_EV_CHARACTERISTIC) {
					ble_set_error(ctx, BLE_ERR_PROTO,
					    "unknown GATT discovery record");
				}
				break;
			}
			if (event == IPC_GATT_EV_WRITE) {
				if (plen < IPC_OP_PREFIX_SIZE +
				    IPC_GATT_VALUE_EVENT_SIZE ||
				    (value_len = ipc_get_le16(body + 4)) !=
				    plen - IPC_OP_PREFIX_SIZE -
				    IPC_GATT_VALUE_EVENT_SIZE) {
					ble_set_error(ctx, BLE_ERR_PROTO,
					    "malformed GATT write event");
					break;
				}
				if (ctx->write_cb != NULL)
					ctx->write_cb(ipc_get_le16(body + 2),
					    body + IPC_GATT_VALUE_EVENT_SIZE, value_len,
					    ctx->write_arg);
				break;
			}
			if (event == IPC_GATT_EV_READ) {
				if (plen != IPC_OP_PREFIX_SIZE +
				    IPC_GATT_READ_EVENT_SIZE) {
					ble_set_error(ctx, BLE_ERR_PROTO,
					    "malformed GATT read event");
					break;
				}
				if (ctx->read_req_cb != NULL)
					ctx->read_req_cb(ipc_get_le16(body + 2),
					    ipc_get_le16(body + 4), ctx->read_req_arg);
				break;
			}
			if (event == IPC_GATT_EV_AUTHORIZE) {
				if (plen != IPC_OP_PREFIX_SIZE +
				    IPC_GATT_AUTHORIZE_EVENT_SIZE || body[2] > 1 ||
				    body[11] > 1) {
					ble_set_error(ctx, BLE_ERR_PROTO,
					    "malformed GATT authorize event");
					break;
				}
				addr.addr_type = body[2];
				memcpy(addr.addr, body + 3, 6);
				if (ctx->authorize_cb != NULL)
					ctx->authorize_cb(&addr,
					    ipc_get_le16(body + 9), body[11] != 0,
					    ctx->authorize_arg);
				break;
			}

			if (event != IPC_GATT_EV_NOTIFY ||
			    plen < IPC_OP_PREFIX_SIZE + IPC_GATT_NOTIFY_EVENT_SIZE ||
			    body[2] > 1) {
				ble_set_error(ctx, BLE_ERR_PROTO,
				    "malformed GATT notification event");
				break;
			}
			handle = ipc_get_le16(body + 9);
			value_len = ipc_get_le16(body + 11);
			bearer_mtu = ipc_get_le16(body + 14);
			if (plen != IPC_OP_PREFIX_SIZE +
			    IPC_GATT_NOTIFY_EVENT_SIZE + value_len ||
			    bearer_mtu < 23 ||
			    value_len > (uint16_t)(bearer_mtu - 3)) {
				ble_set_error(ctx, BLE_ERR_PROTO,
				    "invalid GATT notification length");
				break;
			}
			addr.addr_type = body[2];
			memcpy(addr.addr, body + 3, 6);
			addr.adapter_index = body[13];
			for (si = 0; si < ctx->num_notify_subs; si++)
				if (ctx->notify_subs[si].handle == handle) {
					cb = ctx->notify_subs[si].cb;
					cbarg = ctx->notify_subs[si].arg;
					break;
				}
			if (cb == NULL) {
				cb = ctx->notify_cb;
				cbarg = ctx->notify_arg;
			}
			if (cb != NULL)
				cb(&addr, handle,
				    body + IPC_GATT_NOTIFY_EVENT_SIZE, value_len, cbarg);
			break;
		}
		if (arg == IPC_OP_DOMAIN_SECURITY) {
			const uint8_t *body = pl + IPC_OP_PREFIX_SIZE;
			uint32_t value;
			size_t event_len;

			if (event == IPC_SECURITY_EV_PASSKEY_INPUT)
				event_len = IPC_SECURITY_INPUT_EVENT_SIZE;
			else if (event == IPC_SECURITY_EV_PASSKEY_DISPLAY ||
			    event == IPC_SECURITY_EV_NUMCMP)
				event_len = IPC_SECURITY_PASSKEY_EVENT_SIZE;
			else if (event == IPC_SECURITY_EV_KEYPRESS)
				event_len = IPC_SECURITY_KEYPRESS_EVENT_SIZE;
			else {
				ble_set_error(ctx, BLE_ERR_PROTO,
				    "unknown security event");
				break;
			}
			if (request_id != 0 ||
			    plen != IPC_OP_PREFIX_SIZE + event_len ||
			    body[2] > 1) {
				ble_set_error(ctx, BLE_ERR_PROTO,
				    "malformed security event");
				break;
			}
			addr.addr_type = body[2];
			memcpy(addr.addr, body + 3, sizeof(addr.addr));
			if (event == IPC_SECURITY_EV_PASSKEY_INPUT) {
				if (ctx->passkey_input_cb != NULL)
					ctx->passkey_input_cb(&addr,
					    ctx->passkey_input_arg);
			} else if ((event == IPC_SECURITY_EV_PASSKEY_DISPLAY ||
			    event == IPC_SECURITY_EV_NUMCMP)) {
				value = ipc_get_le32(body + 9);
				if (value > 999999) {
					ble_set_error(ctx, BLE_ERR_PROTO,
					    "invalid security event value");
					break;
				}
				if (event == IPC_SECURITY_EV_PASSKEY_DISPLAY &&
				    ctx->passkey_display_cb != NULL)
					ctx->passkey_display_cb(&addr, value,
					    ctx->passkey_display_arg);
				else if (event == IPC_SECURITY_EV_NUMCMP &&
				    ctx->numcmp_cb != NULL)
					ctx->numcmp_cb(&addr, value,
					    ctx->numcmp_arg);
			} else if (event == IPC_SECURITY_EV_KEYPRESS) {
				if (ctx->keypress_cb != NULL)
					ctx->keypress_cb(&addr, body[9],
					    ctx->keypress_arg);
			}
			break;
		}
		if (arg == IPC_OP_DOMAIN_ISO) {
			const uint8_t *body = pl + IPC_OP_PREFIX_SIZE;

			if (event != IPC_ISO_EV_CIS_REQUEST &&
			    event != IPC_ISO_EV_ESTABLISHED) {
				ble_set_error(ctx, BLE_ERR_PROTO, "unknown ISO event");
				break;
			}
			if (request_id != 0 ||
			    plen != IPC_OP_PREFIX_SIZE + IPC_ISO_EVENT_SIZE ||
			    body[2] > 1) {
				ble_set_error(ctx, BLE_ERR_PROTO, "malformed ISO event");
				break;
			}
			addr.addr_type = body[2];
			memcpy(addr.addr, body + 3, sizeof(addr.addr));
			addr.adapter_index = body[13];
			if (event == IPC_ISO_EV_CIS_REQUEST) {
				if (ctx->iso_req_cb != NULL)
					ctx->iso_req_cb(&addr, ipc_get_le16(body + 9),
					    body[11], body[12], ctx->iso_req_arg);
			} else if (event == IPC_ISO_EV_ESTABLISHED) {
				if (ctx->iso_est_cb != NULL)
					ctx->iso_est_cb(&addr, ipc_get_le16(body + 9),
					    ipc_get_le16(body + 11), ctx->iso_est_arg);
			}
			break;
		}
		if (arg != IPC_OP_DOMAIN_GAP) {
			ble_set_error(ctx, BLE_ERR_PROTO,
			    "unknown operation event domain");
			break;
		}
			if (request_id != 0) {
				ble_scan_result_t result;
				struct ble_scan_op *op;
			const uint8_t *body = pl + IPC_OP_PREFIX_SIZE;
			uint8_t count, name_len;

			for (i = 0; i < ctx->pending_count; i++)
				if (ctx->pending_ops[i].id == request_id &&
				    ctx->pending_ops[i].domain == arg)
					break;
			if (i == ctx->pending_count ||
			    ctx->pending_ops[i].opcode != IPC_GAP_SCAN ||
			    event != IPC_GAP_EV_SCAN_RESULT ||
			    plen != IPC_OP_PREFIX_SIZE +
			    IPC_GAP_SCAN_RESULT_EVENT_SIZE) {
				ble_set_error(ctx, BLE_ERR_PROTO,
				    "uncorrelated or malformed scan event");
					break;
				}
				op = ctx->pending_ops[i].arg;
				if (op == NULL) {
					ble_set_error(ctx, BLE_ERR_PROTO, "scan state missing");
					break;
				}
			count = body[14];
			name_len = body[15];
			if (body[4] > 1 || count > 8 || name_len > 32) {
				ble_set_error(ctx, BLE_ERR_PROTO,
				    "invalid scan result fields");
				break;
			}
			memset(&result, 0, sizeof(result));
			result.addr.addr_type = body[4];
			memcpy(result.addr.addr, body + 5, 6);
			result.addr.adapter_index = (uint8_t)ipc_get_le16(body + 2);
			result.rssi = (int8_t)body[11];
			result.mfr_id = ipc_get_le16(body + 12);
			result.num_svc_uuids = count;
			for (i = 0; i < count; i++)
				result.svc_uuids[i].uuid16 =
				    ipc_get_le16(body + 16 + i * 2);
			memcpy(result.name, body + 32, name_len);
			result.name[name_len] = '\0';
			ctx->rssi_addr = result.addr;
			ctx->rssi_value = result.rssi;
			ctx->rssi_valid = true;
				if (op->cb != NULL)
					op->cb(&result, op->arg);
			break;
		}
			if (event == IPC_GAP_EV_CONNECTED &&
			    plen == IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECTED_EVENT_SIZE &&
			    pl[IPC_OP_PREFIX_SIZE + 2] <= 1) {
				addr.addr_type = pl[IPC_OP_PREFIX_SIZE + 2];
				memcpy(addr.addr, pl + IPC_OP_PREFIX_SIZE + 3, 6);
				addr.adapter_index = pl[IPC_OP_PREFIX_SIZE + 14];
				ble_connection_upsert(ctx, &addr,
				    ipc_get_le16(pl + IPC_OP_PREFIX_SIZE + 12));
			if (ctx->connected_cb != NULL)
				ctx->connected_cb(&addr,
				    ipc_get_le16(pl + IPC_OP_PREFIX_SIZE + 10),
				    ipc_get_le16(pl + IPC_OP_PREFIX_SIZE + 12),
				    ctx->connected_arg);
			} else if (event == IPC_GAP_EV_DISCONNECTED &&
			    plen == IPC_OP_PREFIX_SIZE +
			    IPC_GAP_DISCONNECTED_EVENT_SIZE &&
			    pl[IPC_OP_PREFIX_SIZE + 2] <= 1) {
				addr.addr_type = pl[IPC_OP_PREFIX_SIZE + 2];
				memcpy(addr.addr, pl + IPC_OP_PREFIX_SIZE + 3, 6);
				addr.adapter_index = pl[IPC_OP_PREFIX_SIZE + 11];
				ble_connection_remove(ctx, &addr);
			if (ctx->disconnected_cb != NULL)
				ctx->disconnected_cb(&addr,
				    ipc_get_le16(pl + IPC_OP_PREFIX_SIZE + 9),
				    ctx->disconnected_arg);
		} else {
			ble_set_error(ctx, BLE_ERR_PROTO,
			    "unknown or malformed GAP event");
		}
		break;
	}
	case IPC_T_HELLO:
	default:
		/* Unexpected post-handshake; ignore. */
		break;
	}
}

/*
 * Blocking read of exactly one frame (used by the handshake).  Returns 0 on
 * success, -1 on timeout/error.
 */
static int
ble_poll_until(int fd, short events, int64_t deadline_ms)
{
	struct pollfd pfd;
	struct timespec ts;
	int64_t now_ms, remain;
	int rc;

	pfd.fd = fd;
	pfd.events = events;
	for (;;) {
		if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
			return (-1);
		now_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
		remain = deadline_ms - now_ms;
		if (remain <= 0)
			return (0);
		if (remain > INT_MAX)
			remain = INT_MAX;
		pfd.revents = 0;
		rc = poll(&pfd, 1, (int)remain);
		if (rc < 0 && errno == EINTR)
			continue;
		if (rc <= 0)
			return (rc);
		return ((pfd.revents & events) != 0 ? 1 : -1);
	}
}

static int
ble_read_one_frame_until(ble_ctx_t *ctx, uint16_t *type, uint16_t *arg,
    uint8_t *payload, size_t *plen, int64_t deadline_ms)
{
	uint8_t hdr[IPC_HDR_SIZE];
	uint32_t need;
	size_t got = 0;

	/* Read the fixed header. */
	while (got < IPC_HDR_SIZE) {
		ssize_t n;

		if (ble_poll_until(ctx->fd, POLLIN, deadline_ms) != 1)
			return (-1);
		n = recv(ctx->fd, hdr + got, IPC_HDR_SIZE - got, 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return (-1);
		got += (size_t)n;
	}
	ipc_hdr_decode(hdr, &need, type, arg);
	if (need > IPC_MAX_PAYLOAD)
		return (-1);

	got = 0;
	while (got < need) {
		ssize_t n;

		if (ble_poll_until(ctx->fd, POLLIN, deadline_ms) != 1)
			return (-1);
		n = recv(ctx->fd, payload + got, need - got, 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return (-1);
		got += (size_t)n;
	}
	*plen = need;
	return (0);
}

static int
ble_read_one_frame(ble_ctx_t *ctx, uint16_t *type, uint16_t *arg,
    uint8_t *payload, size_t *plen, int timeout_ms)
{
	struct timespec ts;
	int64_t deadline_ms;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (-1);
	deadline_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 +
	    timeout_ms;
	return (ble_read_one_frame_until(ctx, type, arg, payload, plen,
	    deadline_ms));
}

int
ble_handshake(ble_ctx_t *ctx)
{
	uint8_t features[IPC_HELLO_FEATURES_SIZE];
	uint8_t payload[IPC_MAX_PAYLOAD + 1];
	uint16_t type, arg;
	uint32_t accepted;
	size_t plen = 0;

	ble_clear_error(ctx);

	ipc_put_le32(features, IPC_FEATURE_EVENTS | IPC_FEATURE_FDPASS);
	if (ble_send_frame(ctx, IPC_T_HELLO, IPC_PROTO_VERSION,
	    features, sizeof(features)) < 0) {
		ble_set_error(ctx, BLE_ERR_SOCKET, "handshake send failed");
		return (-1);
	}

	if (ble_read_one_frame(ctx, &type, &arg, payload, &plen,
	    HANDSHAKE_TIMEOUT_MS) < 0) {
		ble_set_error(ctx, BLE_ERR_TIMEOUT, "handshake timed out");
		return (-1);
	}
	if (type == IPC_T_ERROR) {
		payload[plen] = '\0';
		ble_set_error(ctx, BLE_ERR_PROTO,
		    plen > 0 ? (const char *)payload :
		    "handshake rejected");
		return (-1);
	}
	if (type != IPC_T_HELLO) {
		ble_set_error(ctx, BLE_ERR_PROTO, "bad handshake reply");
		return (-1);
	}
	if (arg != IPC_PROTO_VERSION || plen != IPC_HELLO_FEATURES_SIZE) {
		ble_set_error(ctx, BLE_ERR_PROTO, "protocol version mismatch");
		return (-1);
	}
	accepted = ipc_get_le32(payload);
	if ((accepted & ~IPC_FEATURE_ALL) != 0) {
		ble_set_error(ctx, BLE_ERR_PROTO, "invalid handshake features");
		return (-1);
	}
	ctx->events_ok = (accepted & IPC_FEATURE_EVENTS) != 0;
	ctx->fdpass_ok = (accepted & IPC_FEATURE_FDPASS) != 0;
	return (0);
}

ble_ctx_t *
ble_open(const char *sock_path)
{
	struct sockaddr_un sun;
	ble_ctx_t *ctx;
	int fd;

	if (sock_path == NULL)
		sock_path = DEFAULT_SOCK;
	if (strlen(sock_path) >= sizeof(sun.sun_path)) {
		errno = ENAMETOOLONG;
		return (NULL);
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return (NULL);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	(void)strlcpy(sun.sun_path, sock_path, sizeof(sun.sun_path));

	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(fd);
		return (NULL);
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		close(fd);
		return (NULL);
	}
	ctx->fd = fd;

	/*
	 * Upgrade to the framed binary protocol via the HELLO handshake.  On a
	 * version mismatch, timeout, or I/O error this fails cleanly (never
	 * hangs) and ble_open() reports failure to the caller.
	 */
	if (ble_handshake(ctx) < 0) {
		close(fd);
		free(ctx);
		return (NULL);
	}
	return (ctx);
}

ble_ctx_t *
ble_open_fd(int fd)
{
	ble_ctx_t *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return (NULL);
	ctx->fd = fd;
	return (ctx);
}

void
ble_close(ble_ctx_t *ctx)
{

	if (ctx == NULL)
		return;
	if (ctx->pending_count != 0)
		ble_fail_pending(ctx, BLE_ERR_SOCKET, IPC_ERR_IO,
		    "context closed");
	if (ctx->fd >= 0)
		close(ctx->fd);
	free(ctx);
}

int
ble_fd(ble_ctx_t *ctx)
{

	return (ctx->fd);
}

/*
 * Framed protocol receive path: drain the socket and dispatch every complete
 * length-prefixed frame.
 */
static int
ble_process_framed(ble_ctx_t *ctx)
{
	ssize_t n;
	size_t avail;

	avail = sizeof(ctx->rxbuf) - ctx->rxlen;
	if (avail == 0) {
		/* Desynced: a claimed frame exceeds the buffer.  Reset. */
		ctx->rxlen = 0;
		avail = sizeof(ctx->rxbuf);
	}

	n = recv(ctx->fd, ctx->rxbuf + ctx->rxlen, avail, MSG_DONTWAIT);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return (0);
		ble_set_error(ctx, BLE_ERR_SOCKET, "recv failed");
		return (-1);
	}
	if (n == 0) {
		ble_set_error(ctx, BLE_ERR_SOCKET, "connection closed");
		ctx->connection_count = 0;
		return (-1);
	}
	ctx->rxlen += (size_t)n;

	for (;;) {
		uint32_t plen;
		uint16_t type, arg;

		if (ctx->rxlen < IPC_HDR_SIZE)
			break;
		ipc_hdr_decode(ctx->rxbuf, &plen, &type, &arg);
		if (plen > IPC_MAX_PAYLOAD) {
			ble_set_error(ctx, BLE_ERR_PROTO, "frame too large");
			ctx->rxlen = 0;
			return (-1);
		}
		if (ctx->rxlen < IPC_HDR_SIZE + plen)
			break;	/* wait for the rest of the frame */

		ble_dispatch_frame(ctx, type, arg,
		    ctx->rxbuf + IPC_HDR_SIZE, plen);

		{
			size_t consumed = IPC_HDR_SIZE + plen;
			size_t remain = ctx->rxlen - consumed;

			if (remain > 0)
				memmove(ctx->rxbuf,
				    ctx->rxbuf + consumed, remain);
			ctx->rxlen = remain;
		}
	}
	return (0);
}

int
ble_process(ble_ctx_t *ctx)
{

	return (ble_process_framed(ctx));
}

/*
 * Capability broker (fd-passing)
 */

/*
 * Receive one SCM_RIGHTS descriptor handed by the daemon on the control
 * socket.  blued_ctl_send_fd() sends each fd as a single data byte carrying
 * the ancillary descriptor, so this reads exactly that byte and extracts the
 * fd.  The received fd is already capability-limited (CAP_SEND|CAP_RECV|
 * CAP_EVENT, XFER_ONCE) by the daemon; the client cannot widen or re-pass it.
 */
static int
ble_recv_fd(ble_ctx_t *ctx, int timeout_ms, int *out_fd)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(sizeof(int))];
	char byte;
	struct timespec ts;
	int64_t deadline_ms;
	ssize_t n;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (-1);
	deadline_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 +
	    timeout_ms;
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(cbuf, 0, sizeof(cbuf));
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	for (;;) {
		if (ble_poll_until(ctx->fd, POLLIN, deadline_ms) != 1)
			return (-1);
		msg.msg_controllen = sizeof(cbuf);
		n = recvmsg(ctx->fd, &msg, 0);
		if (n < 0 && errno == EINTR)
			continue;
		break;
	}
	if (n < 1)
		return (-1);

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS)
		return (-1);
	memcpy(out_fd, CMSG_DATA(cmsg), sizeof(int));
	return (0);
}

/*
 * Read the next non-event framed reply.  The broker acquire exchange is a
 * strict request/response, but a client that opted into push-events could see
 * an async EVENT frame interleave; those are skipped so the acquire stays in
 * sync.  Returns 0 with type/arg/payload filled, -1 on timeout/I/O.
 */
static int
ble_acquire_next_frame(ble_ctx_t *ctx, uint16_t *type, uint16_t *arg,
    uint8_t *payload, size_t *plen)
{
	struct timespec ts;
	int64_t deadline_ms;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (-1);
	deadline_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 +
	    HANDSHAKE_TIMEOUT_MS;

	do {
		if (ble_read_one_frame_until(ctx, type, arg, payload, plen,
		    deadline_ms) < 0)
			return (-1);
		if (*type == IPC_T_OP_EVENT)
			ble_dispatch_frame(ctx, *type, *arg, payload, *plen);
	} while (*type == IPC_T_OP_EVENT);
	return (0);
}

static void ble_gatt_req_encode(uint8_t[IPC_GATT_REQ_SIZE], uint16_t,
    const ble_addr_t *, uint16_t);

static int
ble_acquire_typed_gatt(ble_ctx_t *ctx, uint16_t opcode,
    const ble_addr_t *addr, uint16_t handle, int *out_fd, uint16_t *out_mtu)
{
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_GATT_REQ_SIZE];
	uint8_t reply[IPC_MAX_PAYLOAD + 1];
	uint32_t request_id, reply_id;
	uint16_t type, domain, status, flags;
	size_t plen = 0, msglen;
	int fd = -1;

	if (ctx->pending_count != 0) {
		ble_set_error(ctx, BLE_ERR_BUSY,
		    "operation pending during fd acquisition");
		return (-1);
	}
	request_id = ++ctx->next_request_id;
	if (request_id == 0)
		request_id = ++ctx->next_request_id;
	ipc_op_prefix_encode(request, request_id, 0, 0);
	ble_gatt_req_encode(request + IPC_OP_PREFIX_SIZE, opcode, addr, handle);
	if (ble_send_frame(ctx, IPC_T_OP_REQ, IPC_OP_DOMAIN_GATT, request,
	    sizeof(request)) < 0) {
		ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
		return (-1);
	}
	if (ble_acquire_next_frame(ctx, &type, &domain, reply, &plen) < 0) {
		ble_set_error(ctx, BLE_ERR_TIMEOUT, "acquire timed out");
		return (-1);
	}
	if (type != IPC_T_OP_REPLY || domain != IPC_OP_DOMAIN_GATT ||
	    plen < IPC_OP_PREFIX_SIZE) {
		ble_set_error(ctx, BLE_ERR_PROTO, "acquire reply malformed");
		return (-1);
	}
	ipc_op_prefix_decode(reply, &reply_id, &status, &flags);
	if (reply_id != request_id || flags != 0) {
		ble_set_error(ctx, BLE_ERR_PROTO, "acquire reply correlation failed");
		return (-1);
	}
	if (status != IPC_ERR_NONE) {
		msglen = plen - IPC_OP_PREFIX_SIZE;
		if (msglen > IPC_MAX_PAYLOAD)
			msglen = IPC_MAX_PAYLOAD;
		memmove(reply, reply + IPC_OP_PREFIX_SIZE, msglen);
		reply[msglen] = '\0';
		ble_set_error(ctx, ble_map_ipc_err(status),
		    msglen != 0 ? (const char *)reply : "acquire failed");
		return (-1);
	}
	if (plen != IPC_OP_PREFIX_SIZE + IPC_GATT_ACQUIRE_REPLY_SIZE ||
	    ipc_get_le16(reply + IPC_OP_PREFIX_SIZE) != opcode) {
		ble_set_error(ctx, BLE_ERR_PROTO, "acquire metadata malformed");
		return (-1);
	}
	if (ble_recv_fd(ctx, HANDSHAKE_TIMEOUT_MS, &fd) < 0) {
		ble_set_error(ctx, BLE_ERR_PROTO, "fd handout failed");
		return (-1);
	}
	*out_fd = fd;
	if (out_mtu != NULL)
		*out_mtu = ipc_get_le16(reply + IPC_OP_PREFIX_SIZE + 2);
	return (0);
}

static int
ble_sync_operation(ble_ctx_t *ctx, uint16_t domain, uint16_t opcode,
    const void *body, size_t body_len, uint8_t *result, size_t result_size,
    size_t *result_len)
{
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_MAX_PAYLOAD];
	uint8_t reply[IPC_MAX_PAYLOAD + 1];
	uint32_t request_id, reply_id;
	uint16_t type, reply_domain, status, flags;
	size_t plen = 0, len;

	if (domain == 0 || opcode == 0 || body == NULL || body_len < 2 ||
	    ipc_get_le16(body) != opcode) {
		errno = EINVAL;
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid typed operation");
		return (-1);
	}
	if (body_len > IPC_MAX_PAYLOAD - IPC_OP_PREFIX_SIZE) {
		errno = EINVAL;
		ble_set_error(ctx, BLE_ERR_INVAL, "operation payload too large");
		return (-1);
	}
	if (ctx->pending_count != 0) {
		errno = EBUSY;
		ble_set_error(ctx, BLE_ERR_BUSY, "operation already pending");
		return (-1);
	}
	request_id = ++ctx->next_request_id;
	if (request_id == 0)
		request_id = ++ctx->next_request_id;
	ipc_op_prefix_encode(request, request_id, 0, 0);
	memcpy(request + IPC_OP_PREFIX_SIZE, body, body_len);
	if (ble_send_frame(ctx, IPC_T_OP_REQ, domain, request,
	    IPC_OP_PREFIX_SIZE + body_len) < 0) {
		ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
		return (-1);
	}
	if (ble_acquire_next_frame(ctx, &type, &reply_domain, reply, &plen) < 0) {
		ble_set_error(ctx, BLE_ERR_TIMEOUT, "operation timed out");
		return (-1);
	}
	if (type != IPC_T_OP_REPLY || reply_domain != domain ||
	    plen < IPC_OP_PREFIX_SIZE) {
		ble_set_error(ctx, BLE_ERR_PROTO, "operation reply malformed");
		return (-1);
	}
	ipc_op_prefix_decode(reply, &reply_id, &status, &flags);
	/* The request ID identifies the pending operation within its domain. */
	if (reply_id != request_id || flags != 0) {
		ble_set_error(ctx, BLE_ERR_PROTO, "operation reply correlation failed");
		return (-1);
	}
	if (status != IPC_ERR_NONE) {
		len = plen - IPC_OP_PREFIX_SIZE;
		if (len > IPC_MAX_PAYLOAD)
			len = IPC_MAX_PAYLOAD;
		memmove(reply, reply + IPC_OP_PREFIX_SIZE, len);
		reply[len] = '\0';
		ble_set_error(ctx, ble_map_ipc_err(status),
		    len != 0 ? (const char *)reply : "operation failed");
		return (-1);
	}
	len = plen - IPC_OP_PREFIX_SIZE;
	if (len > result_size || (len != 0 && result == NULL)) {
		ble_set_error(ctx, BLE_ERR_PROTO, "operation result too large");
		return (-1);
	}
	if (len != 0)
		memcpy(result, reply + IPC_OP_PREFIX_SIZE, len);
	if (result_len != NULL)
		*result_len = len;
	return (0);
}

static int
ble_acquire_typed_iso_fd(ble_ctx_t *ctx, uint16_t opcode,
    const uint8_t *request, size_t request_len, int *out_fd)
{
	uint8_t reply[IPC_ISO_ACQUIRE_REPLY_SIZE];
	size_t reply_len;
	int fd;

	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_ISO, opcode, request,
	    request_len, reply, sizeof(reply), &reply_len) < 0)
		return (-1);
	if (reply_len != sizeof(reply) || ipc_get_le16(reply) != opcode ||
	    ipc_get_le16(reply + 2) != 0) {
		ble_set_error(ctx, BLE_ERR_PROTO, "invalid ISO acquire reply");
		return (-1);
	}
	if (ble_recv_fd(ctx, HANDSHAKE_TIMEOUT_MS, &fd) < 0) {
		ble_set_error(ctx, BLE_ERR_PROTO, "ISO fd handout failed");
		return (-1);
	}
	*out_fd = fd;
	return (0);
}

/*
 * Acquire a direct L2CAP CoC data socket from the daemon.
 *
 * Negotiates the fd handout for one channel: the returned *out_fd is a
 * connected, capability-scoped socket the caller owns outright (send/recv/poll
 * only).  Requires the fd-passing feature to have been accepted at HELLO and
 * the peer to be privileged (enforced daemon-side).  Returns 0 and stores the
 * fd on success, -1 with ble_errno() set otherwise.
 */
int
ble_acquire_coc(ble_ctx_t *ctx, const ble_addr_t *addr, uint16_t psm,
    int *out_fd)
{
	uint8_t request[IPC_L2CAP_REQ_SIZE] = { 0 };
	uint8_t reply[IPC_L2CAP_ACQUIRE_REPLY_SIZE];
	size_t reply_len;
	int fd = -1;

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || out_fd == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	if (!ctx->fdpass_ok) {
		ble_set_error(ctx, BLE_ERR_PERM, "fd-passing not negotiated");
		return (-1);
	}
	ipc_put_le16(request, IPC_L2CAP_ACQUIRE_COC);
	request[4] = addr->addr_type;
	memcpy(request + 5, addr->addr, sizeof(addr->addr));
	request[11] = 1;
	ipc_put_le16(request + 12, psm);
	request[16] = addr->adapter_index;
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_L2CAP,
	    IPC_L2CAP_ACQUIRE_COC, request, sizeof(request), reply,
	    sizeof(reply), &reply_len) < 0)
		return (-1);
	if (reply_len != sizeof(reply) ||
	    ipc_get_le16(reply) != IPC_L2CAP_ACQUIRE_COC || reply[2] != 1 ||
	    reply[3] != 0) {
		ble_set_error(ctx, BLE_ERR_PROTO, "invalid CoC acquire reply");
		return (-1);
	}
	if (ble_recv_fd(ctx, HANDSHAKE_TIMEOUT_MS, &fd) < 0) {
		ble_set_error(ctx, BLE_ERR_PROTO, "fd handout failed");
		return (-1);
	}
	*out_fd = fd;
	return (0);
}

struct ble_ecbfc_session {
	unsigned count;
	int fds[5];
	uint16_t omtu[5];
};

void
ble_ecbfc_session_close(ble_ecbfc_session_t *s)
{
	unsigned i;

	if (s == NULL)
		return;
	for (i = 0; i < s->count; i++)
		if (s->fds[i] >= 0)
			close(s->fds[i]);
	free(s);
}

int
ble_ecbfc_session_open(ble_ctx_t *ctx, const ble_addr_t *addr, uint16_t psm,
    unsigned count, ble_ecbfc_session_t **out)
{
	ble_ecbfc_session_t *s;
	unsigned i;
	uint8_t request[IPC_L2CAP_REQ_SIZE] = { 0 };
	uint8_t typed_reply[IPC_L2CAP_ACQUIRE_REPLY_SIZE];
	size_t reply_len;

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || out == NULL || count < 1 || count > 5) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid ECBFC session arguments");
		return (-1);
	}
	if (!ctx->fdpass_ok) {
		ble_set_error(ctx, BLE_ERR_PERM, "fd-passing not negotiated");
		return (-1);
	}
	s = calloc(1, sizeof(*s));
	if (s == NULL) {
		ble_set_error(ctx, BLE_ERR_NOMEM, "out of memory");
		return (-1);
	}
	for (i = 0; i < 5; i++)
		s->fds[i] = -1;
	ipc_put_le16(request, IPC_L2CAP_ACQUIRE_COC);
	request[4] = addr->addr_type;
	memcpy(request + 5, addr->addr, sizeof(addr->addr));
	request[11] = (uint8_t)count;
	ipc_put_le16(request + 12, psm);
	request[16] = addr->adapter_index;
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_L2CAP,
	    IPC_L2CAP_ACQUIRE_COC, request, sizeof(request), typed_reply,
	    sizeof(typed_reply), &reply_len) < 0)
		goto fail;
	if (reply_len != sizeof(typed_reply) ||
	    ipc_get_le16(typed_reply) != IPC_L2CAP_ACQUIRE_COC ||
	    typed_reply[2] < 1 || typed_reply[2] > count || typed_reply[3] != 0)
		goto proto_fail;
	s->count = typed_reply[2];
	for (i = 0; i < s->count; i++) {
		s->omtu[i] = ipc_get_le16(typed_reply + 4 + i * 2);
		if (ble_recv_fd(ctx, HANDSHAKE_TIMEOUT_MS, &s->fds[i]) < 0)
			goto proto_fail;
	}
	*out = s;
	return (0);
proto_fail:
	ble_set_error(ctx, BLE_ERR_PROTO, "ECBFC acquire reply malformed");
fail:
	ble_ecbfc_session_close(s);
	return (-1);
}

unsigned
ble_ecbfc_session_count(const ble_ecbfc_session_t *s)
{

	return (s != NULL ? s->count : 0);
}

int
ble_ecbfc_session_fd(const ble_ecbfc_session_t *s, unsigned channel)
{

	return (s != NULL && channel < s->count ? s->fds[channel] : -1);
}

int
ble_ecbfc_session_take_fd(ble_ecbfc_session_t *s, unsigned channel)
{
	int fd;

	if (s == NULL || channel >= s->count)
		return (-1);
	fd = s->fds[channel];
	s->fds[channel] = -1;
	return (fd);
}

uint16_t
ble_ecbfc_session_omtu(const ble_ecbfc_session_t *s, unsigned channel)
{

	return (s != NULL && channel < s->count ? s->omtu[channel] : 0);
}

int
ble_ecbfc_session_reconfigure(ble_ctx_t *ctx, ble_ecbfc_session_t *s,
    uint16_t mtu, uint16_t mps)
{
	struct l2cap_reconfig_param rp;
	unsigned i;

	ble_clear_error(ctx);
	if (s == NULL || mtu < 64 || mps < 64) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid ECBFC reconfiguration");
		return (-1);
	}
	rp.mtu = mtu;
	rp.mps = mps;
	for (i = 0; i < s->count; i++) {
		if (s->fds[i] >= 0 && setsockopt(s->fds[i], SOL_L2CAP,
		    SO_L2CAP_RECONFIG, &rp, sizeof(rp)) != 0) {
			ble_set_error(ctx, BLE_ERR_SOCKET, "ECBFC reconfiguration failed");
			return (-1);
		}
	}
	return (0);
}

/*
 * Acquire a direct ISO (CIS/BIS) data socket for an already-established stream
 * handle.  Same handout semantics and capability scoping as ble_acquire_coc.
 * The stream must already be established (its handle produced by the CIG/CIS/
 * BIG lifecycle, PC3); this only pulls the data-path fd.
 */
int
ble_acquire_iso(ble_ctx_t *ctx, const ble_addr_t *addr, uint16_t cis_handle,
    int *out_fd)
{
	uint8_t request[IPC_ISO_CONNECT_ACQUIRE_REQ_SIZE] = { 0 };

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || out_fd == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	if (!ctx->fdpass_ok) {
		ble_set_error(ctx, BLE_ERR_PERM, "fd-passing not negotiated");
		return (-1);
	}
	ipc_put_le16(request, IPC_ISO_CONNECT_ACQUIRE);
	ipc_put_le16(request + 2,
	    (uint16_t)addr->adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = addr->addr_type;
	memcpy(request + 5, addr->addr, sizeof(addr->addr));
	ipc_put_le16(request + 12, cis_handle);
	return (ble_acquire_typed_iso_fd(ctx, IPC_ISO_CONNECT_ACQUIRE,
	    request, sizeof(request), out_fd));
}

/*
 * Shared body for ACQUIRE_NOTIFY / ACQUIRE_WRITE.  The daemon returns a typed
 * correlated reply and an SCM_RIGHTS descriptor.  Returns 0 with *out_fd (and
 * *out_mtu when non-NULL) set.
 */
static int
ble_acquire_chan(ble_ctx_t *ctx, uint16_t opcode, const ble_addr_t *addr,
    uint16_t handle, int *out_fd, uint16_t *out_mtu)
{
	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || out_fd == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	if (!ctx->fdpass_ok) {
		ble_set_error(ctx, BLE_ERR_PERM, "fd-passing not negotiated");
		return (-1);
	}
	return (ble_acquire_typed_gatt(ctx, opcode, addr, handle, out_fd,
	    out_mtu));
}

int
ble_acquire_notify(ble_ctx_t *ctx, const ble_addr_t *addr, uint16_t handle,
    int *out_fd, uint16_t *out_mtu)
{

	return (ble_acquire_chan(ctx, IPC_GATT_ACQUIRE_NOTIFY, addr, handle, out_fd,
	    out_mtu));
}

int
ble_acquire_write(ble_ctx_t *ctx, const ble_addr_t *addr, uint16_t handle,
    int *out_fd)
{

	return (ble_acquire_chan(ctx, IPC_GATT_ACQUIRE_WRITE, addr, handle, out_fd,
	    NULL));
}

/*
 * LE Isochronous (ISO) operator surface.
 *
 * Each create/teardown verb has one correlated typed reply.  Create operations
 * return once the HCI command is issued; establishment then arrives as a typed
 * event routed to ble_on_iso_established / ble_on_iso_cis_request.
 */

struct ble_iso_stream {
	int	fd;	/* capability-scoped SEQPACKET ISO data socket */
};

int
ble_iso_cig_create(ble_ctx_t *ctx, uint8_t adapter_index,
    const ble_cig_params_t *params,
    uint16_t *out_cis_handles, int max)
{
	int i, n;
	uint8_t request[IPC_ISO_CIG_REQ_HDR_SIZE + 8 * IPC_ISO_CIS_PARAM_SIZE];
	uint8_t typed_reply[IPC_ISO_CIG_REPLY_SIZE];
	size_t reply_len;

	ble_clear_error(ctx);
	if (params == NULL || params->num_cis <= 0 || params->num_cis > 8 ||
	    max < 0 || (max != 0 && out_cis_handles == NULL)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid CIG params");
		return (-1);
	}
	memset(request, 0, sizeof(request));
	ipc_put_le16(request, IPC_ISO_CIG_CREATE);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = params->cig_id;
	request[5] = (uint8_t)params->num_cis;
	request[6] = params->sca;
	request[7] = params->packing;
	request[8] = params->framing;
	ipc_put_le16(request + 10, params->max_transport_latency_c_ms);
	ipc_put_le16(request + 12, params->max_transport_latency_p_ms);
	ipc_put_le32(request + 14, params->sdu_interval_c_us);
	ipc_put_le32(request + 18, params->sdu_interval_p_us);
	for (i = 0; i < params->num_cis; i++) {
		uint8_t *cp = request + IPC_ISO_CIG_REQ_HDR_SIZE +
		    i * IPC_ISO_CIS_PARAM_SIZE;

		cp[0] = params->cis[i].cis_id;
		cp[1] = params->cis[i].phy_c;
		cp[2] = params->cis[i].phy_p;
		cp[3] = params->cis[i].rtn_c;
		cp[4] = params->cis[i].rtn_p;
		ipc_put_le16(cp + 6, params->cis[i].max_sdu_c);
		ipc_put_le16(cp + 8, params->cis[i].max_sdu_p);
	}
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_ISO, IPC_ISO_CIG_CREATE,
	    request, IPC_ISO_CIG_REQ_HDR_SIZE + params->num_cis *
	    IPC_ISO_CIS_PARAM_SIZE, typed_reply, sizeof(typed_reply),
	    &reply_len) < 0)
		return (-1);
	if (reply_len != sizeof(typed_reply) ||
	    ipc_get_le16(typed_reply) != IPC_ISO_CIG_CREATE ||
	    typed_reply[2] > 8 || typed_reply[3] != 0) {
		ble_set_error(ctx, BLE_ERR_PROTO, "invalid CIG reply");
		return (-1);
	}
	n = typed_reply[2] < max ? typed_reply[2] : max;
	for (i = 0; i < n; i++)
		out_cis_handles[i] = ipc_get_le16(typed_reply + 4 + i * 2);
	return (n);
}

int
ble_iso_cis_create(ble_ctx_t *ctx, const ble_addr_t *peer, uint8_t cig_id,
    uint8_t cis_id)
{
	uint8_t request[IPC_ISO_CIS_CREATE_REQ_SIZE] = { 0 };
	size_t reply_len;

	if (!ble_addr_valid(peer)) {
		ble_clear_error(ctx);
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	ipc_put_le16(request, IPC_ISO_CIS_CREATE);
	ipc_put_le16(request + 2,
	    (uint16_t)peer->adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = peer->addr_type;
	memcpy(request + 5, peer->addr, sizeof(peer->addr));
	request[11] = cig_id;
	request[12] = cis_id;
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_ISO,
	    IPC_ISO_CIS_CREATE, request, sizeof(request), NULL, 0, &reply_len));
}

int
ble_iso_cis_teardown(ble_ctx_t *ctx, uint8_t adapter_index,
    uint16_t cis_handle)
{
	uint8_t request[IPC_ISO_SIMPLE_REQ_SIZE] = { 0 };
	size_t reply_len;

	ipc_put_le16(request, IPC_ISO_CIS_TEARDOWN);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	ipc_put_le16(request + 4, cis_handle);
	request[6] = 0x13;
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_ISO,
	    IPC_ISO_CIS_TEARDOWN, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_iso_cig_remove(ble_ctx_t *ctx, uint8_t adapter_index, uint8_t cig_id)
{
	uint8_t request[IPC_ISO_SIMPLE_REQ_SIZE] = { 0 };
	size_t reply_len;

	ipc_put_le16(request, IPC_ISO_CIG_REMOVE);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = cig_id;
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_ISO,
	    IPC_ISO_CIG_REMOVE, request, sizeof(request), NULL, 0, &reply_len));
}

int
ble_iso_cis_accept(ble_ctx_t *ctx, uint8_t adapter_index,
    uint16_t cis_handle)
{
	uint8_t request[IPC_ISO_SIMPLE_REQ_SIZE] = { 0 };
	size_t reply_len;

	ipc_put_le16(request, IPC_ISO_CIS_ACCEPT);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	ipc_put_le16(request + 4, cis_handle);
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_ISO,
	    IPC_ISO_CIS_ACCEPT, request, sizeof(request), NULL, 0, &reply_len));
}

int
ble_iso_cis_reject(ble_ctx_t *ctx, uint8_t adapter_index,
    uint16_t cis_handle, uint8_t reason)
{
	uint8_t request[IPC_ISO_SIMPLE_REQ_SIZE] = { 0 };
	size_t reply_len;

	ipc_put_le16(request, IPC_ISO_CIS_REJECT);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	ipc_put_le16(request + 4, cis_handle);
	request[6] = reason;
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_ISO,
	    IPC_ISO_CIS_REJECT, request, sizeof(request), NULL, 0, &reply_len));
}

int
ble_iso_big_create(ble_ctx_t *ctx, uint8_t adapter_index,
    const ble_big_params_t *params)
{
	uint8_t request[IPC_ISO_BIG_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	if (params == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid BIG params");
		return (-1);
	}
	ipc_put_le16(request, IPC_ISO_BIG_CREATE);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = params->big_handle;
	request[5] = params->adv_handle;
	request[6] = params->num_bis;
	request[7] = params->rtn;
	request[8] = params->phy;
	request[9] = params->packing;
	request[10] = params->framing;
	request[11] = params->encryption ? 1 : 0;
	ipc_put_le32(request + 14, params->sdu_interval_us);
	ipc_put_le16(request + 18, params->max_sdu);
	ipc_put_le16(request + 20, params->max_transport_latency_ms);
	memcpy(request + 22, params->broadcast_code, 16);
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_ISO,
	    IPC_ISO_BIG_CREATE, request, sizeof(request), NULL, 0, &reply_len));
}

int
ble_iso_big_terminate(ble_ctx_t *ctx, uint8_t adapter_index,
    uint8_t big_handle, uint8_t reason)
{
	uint8_t request[IPC_ISO_SIMPLE_REQ_SIZE] = { 0 };
	size_t reply_len;

	ipc_put_le16(request, IPC_ISO_BIG_TERMINATE);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = big_handle;
	request[5] = reason;
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_ISO,
	    IPC_ISO_BIG_TERMINATE, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_iso_big_create_sync(ble_ctx_t *ctx, uint8_t adapter_index,
    uint8_t big_handle,
    uint16_t sync_handle, const uint8_t *bis_indices, int num_bis, uint8_t mse,
    uint16_t timeout, const uint8_t broadcast_code[16])
{
	uint8_t request[IPC_ISO_BIG_SYNC_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	if (bis_indices == NULL || num_bis <= 0 || num_bis > 8) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid BIG sync params");
		return (-1);
	}
	ipc_put_le16(request, IPC_ISO_BIG_SYNC_CREATE);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = big_handle;
	request[5] = (uint8_t)num_bis;
	request[6] = mse;
	request[7] = broadcast_code != NULL ? 1 : 0;
	ipc_put_le16(request + 8, sync_handle);
	ipc_put_le16(request + 10, timeout);
	memcpy(request + 12, bis_indices, (size_t)num_bis);
	if (broadcast_code != NULL)
		memcpy(request + 20, broadcast_code, 16);
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_ISO,
	    IPC_ISO_BIG_SYNC_CREATE, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_iso_big_terminate_sync(ble_ctx_t *ctx, uint8_t adapter_index,
    uint8_t big_handle)
{
	uint8_t request[IPC_ISO_SIMPLE_REQ_SIZE] = { 0 };
	size_t reply_len;

	ipc_put_le16(request, IPC_ISO_BIG_SYNC_TERMINATE);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = big_handle;
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_ISO,
	    IPC_ISO_BIG_SYNC_TERMINATE, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_iso_acquire(ble_ctx_t *ctx, uint8_t adapter_index, uint16_t cis_handle,
    ble_iso_stream_t **out)
{
	uint8_t request[IPC_ISO_SIMPLE_REQ_SIZE] = { 0 };
	ble_iso_stream_t *stream;
	int fd;

	if (out == NULL || !ctx->fdpass_ok) {
		ble_set_error(ctx, out == NULL ? BLE_ERR_INVAL : BLE_ERR_PERM,
		    out == NULL ? "invalid argument" : "fd-passing not negotiated");
		return (-1);
	}
	ipc_put_le16(request, IPC_ISO_ACQUIRE);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	ipc_put_le16(request + 4, cis_handle);
	if (ble_acquire_typed_iso_fd(ctx, IPC_ISO_ACQUIRE, request,
	    sizeof(request), &fd) < 0)
		return (-1);
	stream = calloc(1, sizeof(*stream));
	if (stream == NULL) {
		close(fd);
		ble_set_error(ctx, BLE_ERR_NOMEM, "out of memory");
		return (-1);
	}
	stream->fd = fd;
	*out = stream;
	return (0);
}

int
ble_iso_bis_acquire(ble_ctx_t *ctx, uint8_t adapter_index,
    uint8_t big_handle, uint8_t bis_index, ble_iso_stream_t **out)
{
	uint8_t request[IPC_ISO_SIMPLE_REQ_SIZE] = { 0 };
	ble_iso_stream_t *stream;
	int fd;

	if (out == NULL || !ctx->fdpass_ok) {
		ble_set_error(ctx, out == NULL ? BLE_ERR_INVAL : BLE_ERR_PERM,
		    out == NULL ? "invalid argument" : "fd-passing not negotiated");
		return (-1);
	}
	ipc_put_le16(request, IPC_ISO_BIS_ACQUIRE);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = big_handle;
	request[5] = bis_index;
	if (ble_acquire_typed_iso_fd(ctx, IPC_ISO_BIS_ACQUIRE, request,
	    sizeof(request), &fd) < 0)
		return (-1);
	stream = calloc(1, sizeof(*stream));
	if (stream == NULL) {
		close(fd);
		ble_set_error(ctx, BLE_ERR_NOMEM, "out of memory");
		return (-1);
	}
	stream->fd = fd;
	*out = stream;
	return (0);
}

void
ble_on_iso_established(ble_ctx_t *ctx, ble_iso_est_cb cb, void *arg)
{

	ctx->iso_est_cb = cb;
	ctx->iso_est_arg = arg;
}

void
ble_on_iso_cis_request(ble_ctx_t *ctx, ble_iso_cis_req_cb cb, void *arg)
{

	ctx->iso_req_cb = cb;
	ctx->iso_req_arg = arg;
}

int
ble_iso_fd(ble_iso_stream_t *s)
{

	return (s != NULL ? s->fd : -1);
}

int
ble_iso_send(ble_iso_stream_t *s, const void *sdu, size_t len)
{

	if (s == NULL)
		return (-1);
	return ((int)write(s->fd, sdu, len));
}

int
ble_iso_recv(ble_iso_stream_t *s, void *buf, size_t len)
{

	if (s == NULL)
		return (-1);
	return ((int)read(s->fd, buf, len));
}

void
ble_iso_close(ble_iso_stream_t *s)
{

	if (s == NULL)
		return;
	if (s->fd >= 0)
		close(s->fd);
	free(s);
}

/*
 * Central mode
 */

int
ble_scan(ble_ctx_t *ctx, ble_scan_cb cb, void *arg)
{
	ble_scan_params_t params;

	ble_clear_error(ctx);
	memset(&params, 0, sizeof(params));
	params.rssi_min = BLE_RSSI_ANY;
	return (ble_scan_filtered(ctx, &params, cb, arg));
}

static void
ble_scan_reply(ble_ctx_t *ctx, uint16_t opcode, uint16_t status,
    const uint8_t *payload, size_t payload_len, void *arg)
{
	struct ble_scan_op *op = arg;

	(void)ctx;
	(void)opcode;
	(void)status;
	(void)payload;
	(void)payload_len;
	free(op);
}

int
ble_scan_filtered(ble_ctx_t *ctx, const ble_scan_params_t *params,
    ble_scan_cb cb, void *arg)
{
	uint8_t request[IPC_GAP_SCAN_REQ_SIZE];
	struct ble_scan_op *op;
	uint16_t flags;
	int8_t rssi_min;

	ble_clear_error(ctx);
	if (params == NULL)
		return (ble_scan(ctx, cb, arg));
	/* Interval/window bounds mirror the daemon (Core Spec §7.8.10). */
	if ((params->interval != 0 &&
	    (params->interval < 0x0004 || params->interval > 0x4000)) ||
	    (params->window != 0 &&
	    (params->window < 0x0004 || params->window > 0x4000)) ||
	    (params->interval != 0 && params->window != 0 &&
	    params->window > params->interval)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid scan params");
		return (-1);
	}

	if (params->name_sub[0] != '\0') {
		size_t i;

		/* A name substring may not contain whitespace (token boundary). */
		for (i = 0; params->name_sub[i] != '\0'; i++) {
			unsigned char c = (unsigned char)params->name_sub[i];

			if (c <= ' ' || c == 0x7F) {
				ble_set_error(ctx, BLE_ERR_INVAL,
				    "invalid name filter");
				return (-1);
			}
		}
	}

	op = calloc(1, sizeof(*op));
	if (op == NULL) {
		ble_set_error(ctx, BLE_ERR_NOMEM, "scan state allocation failed");
		return (-1);
	}
	op->cb = cb;
	op->arg = arg;
	memset(request, 0, sizeof(request));
	flags = 0;
	if (params->passive)
		flags |= IPC_GAP_SCAN_F_PASSIVE;
	if (params->accept_list)
		flags |= IPC_GAP_SCAN_F_ACCEPT_LIST;
	if (params->no_dedup)
		flags |= IPC_GAP_SCAN_F_NO_DEDUP;
	ipc_put_le16(request, IPC_GAP_SCAN);
	ipc_put_le16(request + 2, flags);
	ipc_put_le16(request + 4, params->interval);
	ipc_put_le16(request + 6, params->window);
	ipc_put_le16(request + 8, params->uuid16);
	rssi_min = params->rssi_min;
	if (rssi_min == 0 && params->interval == 0 &&
	    params->window == 0 && params->uuid16 == 0 &&
	    params->name_sub[0] == '\0' && !params->passive &&
	    !params->accept_list && !params->no_dedup)
		rssi_min = BLE_RSSI_ANY;
	request[10] = (uint8_t)rssi_min;
	strlcpy((char *)request + 12, params->name_sub, 32);
	if (ble_send_operation(ctx, IPC_OP_DOMAIN_GAP, IPC_GAP_SCAN,
	    request, sizeof(request), ble_scan_reply, op, NULL) < 0) {
		free(op);
		return (-1);
	}
	return (0);
}

int
ble_connect(ble_ctx_t *ctx, const ble_addr_t *addr,
    ble_connect_cb cb, void *arg)
{

	return (ble_connect_params(ctx, addr, NULL, cb, arg));
}

static void
ble_connect_reply(ble_ctx_t *ctx, uint16_t opcode, uint16_t status,
    const uint8_t *payload, size_t payload_len, void *arg)
{
	struct ble_connect_op *op = arg;

	if (op == NULL)
		return;
	if (status == IPC_ERR_NONE && opcode == IPC_GAP_CONNECT_NAME) {
		if (payload_len != IPC_GAP_CONNECT_NAME_REPLY_SIZE ||
		    payload[0] > 1) {
			ble_set_error(ctx, BLE_ERR_PROTO,
			    "malformed CONNECT_NAME reply");
			status = IPC_ERR_PROTO;
		} else {
			op->addr.addr_type = payload[0];
			memcpy(op->addr.addr, payload + 1, 6);
		}
	}
	if (op->cb != NULL)
		op->cb(&op->addr, status == IPC_ERR_NONE ? 0 : -1, op->arg);
	free(op);
}

int
ble_connect_params(ble_ctx_t *ctx, const ble_addr_t *addr,
    const ble_conn_params_t *params, ble_connect_cb cb, void *arg)
{
	uint8_t payload[IPC_GAP_CONNECT_REQ_SIZE];
	struct ble_connect_op *op;
	uint16_t opflags;

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	if (params != NULL) {
		if (params->interval_min < 0x0006 ||
		    params->interval_min > 0x0c80 ||
		    params->interval_max < 0x0006 ||
		    params->interval_max > 0x0c80 ||
		    params->interval_min > params->interval_max ||
		    params->latency > 0x01f3 ||
		    params->timeout < 0x000a ||
		    params->timeout > 0x0c80 ||
		    (uint32_t)params->timeout * 4 <=
		    (uint32_t)params->interval_max *
		    (1 + (uint32_t)params->latency) ||
		    (params->tx_phys & ~0x07) != 0 ||
		    (params->rx_phys & ~0x07) != 0) {
			ble_set_error(ctx, BLE_ERR_INVAL,
			    "invalid connection params");
			return (-1);
		}
	}

	op = calloc(1, sizeof(*op));
	if (op == NULL) {
		ble_set_error(ctx, BLE_ERR_NOMEM, "connect state allocation failed");
		return (-1);
	}
	op->addr = *addr;
	op->cb = cb;
	op->arg = arg;
	opflags = 0;
	ipc_gap_req_encode(payload, IPC_GAP_CONNECT, 0, addr->addr_type,
	    addr->addr, addr->adapter_index);
	memset(payload + 12, 0, sizeof(payload) - 12);
	if (params != NULL) {
		opflags |= IPC_GAP_F_CONN_PARAMS;
		if (params->tx_phys != 0 || params->rx_phys != 0)
			opflags |= IPC_GAP_F_PHY;
		ipc_put_le16(payload + 12, params->interval_min);
		ipc_put_le16(payload + 14, params->interval_max);
		ipc_put_le16(payload + 16, params->latency);
		ipc_put_le16(payload + 18, params->timeout);
		payload[20] = params->tx_phys;
		payload[21] = params->rx_phys;
	}
	ipc_put_le16(payload + 2, opflags);
	if (ble_send_operation(ctx, IPC_OP_DOMAIN_GAP, IPC_GAP_CONNECT,
	    payload, sizeof(payload), ble_connect_reply, op, NULL) == 0)
		return (0);
	ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
	free(op);
	return (-1);
}

int
ble_connect_name(ble_ctx_t *ctx, uint8_t adapter_index, const char *name,
    ble_connect_cb cb, void *arg)
{
	const char *p;
	uint8_t payload[IPC_GAP_CONNECT_NAME_REQ_SIZE];
	struct ble_connect_op *op;

	if (name == NULL || *name == '\0')
		return (-1);
	for (p = name; *p != '\0'; p++) {
		if (*p == '\n' || *p == '\r' || (unsigned char)*p < 0x20)
			return (-1);
	}
	if ((size_t)(p - name) >= 32) {
		ble_set_error(ctx, BLE_ERR_INVAL, "device name too long");
		return (-1);
	}

	ble_clear_error(ctx);
	op = calloc(1, sizeof(*op));
	if (op == NULL) {
		ble_set_error(ctx, BLE_ERR_NOMEM, "connect state allocation failed");
		return (-1);
	}
	op->addr.adapter_index = adapter_index;
	op->cb = cb;
	op->arg = arg;
	memset(payload, 0, sizeof(payload));
	ipc_put_le16(payload, IPC_GAP_CONNECT_NAME);
	ipc_put_le16(payload + 2, (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	strlcpy((char *)payload + 4, name, 32);
	if (ble_send_operation(ctx, IPC_OP_DOMAIN_GAP,
	    IPC_GAP_CONNECT_NAME, payload, sizeof(payload),
	    ble_connect_reply, op, NULL) == 0)
		return (0);
	ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
	free(op);
	return (-1);
}

int
ble_disconnect(ble_ctx_t *ctx, const ble_addr_t *addr)
{
	uint8_t payload[IPC_GAP_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	ipc_gap_req_encode(payload, IPC_GAP_DISCONNECT, 0,
	    addr->addr_type, addr->addr, addr->adapter_index);
	if (ble_send_operation(ctx, IPC_OP_DOMAIN_GAP,
	    IPC_GAP_DISCONNECT, payload, sizeof(payload), NULL, NULL,
	    NULL) == 0)
		return (0);
	ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
	return (-1);
}

static void ble_discover_reply(ble_ctx_t *, uint16_t, uint16_t,
    const uint8_t *, size_t, void *);

int
ble_discover(ble_ctx_t *ctx, const ble_addr_t *addr,
    ble_discover_cb cb, void *arg)
{
	uint8_t payload[IPC_GATT_REQ_SIZE];
	struct ble_discover_op *op;

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	op = calloc(1, sizeof(*op));
	if (op == NULL) {
		ble_set_error(ctx, BLE_ERR_NOMEM, "discovery state allocation failed");
		return (-1);
	}
	op->addr = *addr;
	op->cb = cb;
	op->arg = arg;
	ble_gatt_req_encode(payload, IPC_GATT_DISCOVER, addr, 0);
	if (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_DISCOVER, payload, sizeof(payload),
	    ble_discover_reply, op, NULL) == 0)
		return (0);
	ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
	free(op);
	return (-1);
}

static void
ble_gatt_req_encode(uint8_t payload[IPC_GATT_REQ_SIZE], uint16_t opcode,
    const ble_addr_t *addr, uint16_t handle)
{

	memset(payload, 0, IPC_GATT_REQ_SIZE);
	ipc_put_le16(payload, opcode);
	if (addr != NULL) {
		payload[4] = addr->addr_type;
		memcpy(payload + 5, addr->addr, 6);
		payload[11] = addr->adapter_index;
	}
	ipc_put_le16(payload + 12, handle);
}

static void
ble_gatt_uuid_encode(uint8_t payload[18], const ble_uuid_t *uuid)
{

	ipc_put_le16(payload, uuid->uuid16);
	memcpy(payload + 2, uuid->uuid128, sizeof(uuid->uuid128));
}

static void
ble_gatt_handle_reply(ble_ctx_t *ctx, uint16_t opcode, uint16_t status,
    const uint8_t *payload, size_t payload_len, void *arg)
{
	uint16_t *handle = arg;

	if (status != IPC_ERR_NONE)
		return;
	if (payload_len != IPC_GATT_HANDLE_REPLY_SIZE ||
	    ipc_get_le16(payload) != opcode) {
		ble_set_error(ctx, BLE_ERR_PROTO, "malformed GATT handle reply");
		return;
	}
	if (handle != NULL)
		*handle = ipc_get_le16(payload + 2);
}

static void
ble_discover_reply(ble_ctx_t *ctx, uint16_t opcode, uint16_t status,
    const uint8_t *payload, size_t payload_len, void *arg)
{
	struct ble_discover_op *op = arg;

	(void)ctx;
	(void)opcode;
	(void)payload;
	(void)payload_len;
	if (op == NULL)
		return;
	if (op->cb != NULL)
		op->cb(&op->addr, status == IPC_ERR_NONE ? op->svcs : NULL,
		    status == IPC_ERR_NONE ? op->nsvc : 0,
		    status == IPC_ERR_NONE ? op->chars : NULL,
		    status == IPC_ERR_NONE ? op->nchar : 0, op->arg);
	free(op);
}

static void
ble_read_reply(ble_ctx_t *ctx, uint16_t opcode, uint16_t status,
    const uint8_t *payload, size_t payload_len, void *arg)
{
	struct ble_read_op *op = arg;
	uint16_t handle, value_len;

	(void)opcode;
	if (op == NULL)
		return;
	if (status != IPC_ERR_NONE) {
		if (op->cb != NULL)
			op->cb(&op->addr, 0, NULL, 0, -1, op->arg);
	} else if (payload_len < IPC_GATT_READ_REPLY_SIZE ||
	    ipc_get_le16(payload) != IPC_GATT_READ ||
	    (value_len = ipc_get_le16(payload + 4)) !=
	    payload_len - IPC_GATT_READ_REPLY_SIZE) {
		ble_set_error(ctx, BLE_ERR_PROTO, "malformed GATT read reply");
		if (op->cb != NULL)
			op->cb(&op->addr, 0, NULL, 0, -1, op->arg);
	} else {
		handle = ipc_get_le16(payload + 2);
		if (op->cb != NULL)
			op->cb(&op->addr, handle,
			    payload + IPC_GATT_READ_REPLY_SIZE, value_len, 0, op->arg);
	}
	free(op);
}

int
ble_read(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint16_t handle, ble_read_cb cb, void *arg)
{
	uint8_t payload[IPC_GATT_REQ_SIZE];
	struct ble_read_op *op;

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	op = calloc(1, sizeof(*op));
	if (op == NULL) {
		ble_set_error(ctx, BLE_ERR_NOMEM, "read state allocation failed");
		return (-1);
	}
	op->addr = *addr;
	op->cb = cb;
	op->arg = arg;
	ble_gatt_req_encode(payload, IPC_GATT_READ, addr, handle);
	if (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT, IPC_GATT_READ,
	    payload, sizeof(payload), ble_read_reply, op, NULL) == 0)
		return (0);
	ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
	free(op);
	return (-1);
}

int
ble_write(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint16_t handle, const uint8_t *value, uint16_t len)
{
	uint8_t payload[IPC_GATT_VALUE_REQ_SIZE + 512];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || (value == NULL && len > 0)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	if (len > 512) {
		ble_set_error(ctx, BLE_ERR_INVAL, "value too long");
		return (-1);
	}
	ble_gatt_req_encode(payload, IPC_GATT_WRITE, addr, handle);
	ipc_put_le16(payload + 14, len);
	if (len != 0)
		memcpy(payload + IPC_GATT_VALUE_REQ_SIZE, value, len);
	if (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT, IPC_GATT_WRITE,
	    payload, IPC_GATT_VALUE_REQ_SIZE + len, NULL, NULL, NULL) == 0)
		return (0);
	ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
	return (-1);
}

int
ble_write_no_response(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint16_t handle, const void *value, uint16_t len)
{
	uint8_t payload[IPC_GATT_VALUE_REQ_SIZE + 512];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || (value == NULL && len > 0)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	if (len > 512) {
		ble_set_error(ctx, BLE_ERR_INVAL, "value too long");
		return (-1);
	}
	ble_gatt_req_encode(payload, IPC_GATT_WRITE_CMD, addr, handle);
	ipc_put_le16(payload + 14, len);
	if (len != 0)
		memcpy(payload + IPC_GATT_VALUE_REQ_SIZE, value, len);
	if (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_WRITE_CMD, payload, IPC_GATT_VALUE_REQ_SIZE + len,
	    NULL, NULL, NULL) == 0)
		return (0);
	ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
	return (-1);
}

int
ble_subscribe(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint16_t handle, ble_notify_cb cb, void *arg)
{
	uint8_t payload[IPC_GATT_REQ_SIZE];
	int ret;
	int i;

	/*
	 * A NULL address means "all addresses" — this is how `bluedctl monitor`
	 * arms notification delivery without a specific peer.  Formatting a NULL
	 * address would dereference it inside ble_addr_str() (memcpy of
	 * addr->addr), crashing the instant monitor starts (finding K3).  Route
	 * it to the global fallback callback and emit a wildcard subscribe frame
	 * (the all-zeroes address) rather than touching a NULL pointer.
	 */
	if (addr == NULL) {
		ble_gatt_req_encode(payload, IPC_GATT_SUBSCRIBE, NULL, handle);
		ret = ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
		    IPC_GATT_SUBSCRIBE, payload, sizeof(payload), NULL, NULL,
		    NULL);
		if (ret == 0) {
			ctx->notify_cb = cb;
			ctx->notify_arg = arg;
		}
		return (ret);
	}
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}

	/*
	 * Register per-handle callback.  If a subscription for this handle
	 * already exists, update it in place.  Otherwise add a new entry.
	 * When the per-handle table is full, fall back to setting the global
	 * callback (which applies to all unmatched handles).
	 */
	for (i = 0; i < ctx->num_notify_subs; i++) {
		if (ctx->notify_subs[i].handle == handle) {
			ble_gatt_req_encode(payload, IPC_GATT_SUBSCRIBE, addr,
			    handle);
			ret = ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
			    IPC_GATT_SUBSCRIBE, payload, sizeof(payload), NULL,
			    NULL, NULL);
			if (ret == 0) {
				ctx->notify_subs[i].cb = cb;
				ctx->notify_subs[i].arg = arg;
			}
			return (ret);
		}
	}
	ble_gatt_req_encode(payload, IPC_GATT_SUBSCRIBE, addr, handle);
	ret = ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_SUBSCRIBE, payload, sizeof(payload), NULL, NULL, NULL);
	if (ret != 0)
		return (ret);
	if (ctx->num_notify_subs < MAX_NOTIFY_SUBS) {
		ctx->notify_subs[ctx->num_notify_subs].handle = handle;
		ctx->notify_subs[ctx->num_notify_subs].cb = cb;
		ctx->notify_subs[ctx->num_notify_subs].arg = arg;
		ctx->num_notify_subs++;
	} else {
		/* Table full — fall back to global callback */
		ctx->notify_cb = cb;
		ctx->notify_arg = arg;
	}
	return (0);
}

int
ble_unsubscribe(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint16_t handle)
{
	uint8_t payload[IPC_GATT_REQ_SIZE];
	int found;
	int i;

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	/* Remove per-handle subscription entry if present */
	found = -1;
	for (i = 0; i < ctx->num_notify_subs; i++) {
		if (ctx->notify_subs[i].handle == handle) {
			found = i;
			break;
		}
	}

	ble_gatt_req_encode(payload, IPC_GATT_UNSUBSCRIBE, addr, handle);
	if (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_UNSUBSCRIBE, payload, sizeof(payload), NULL, NULL,
	    NULL) < 0)
		return (-1);
	if (found >= 0)
		ctx->notify_subs[found] =
		    ctx->notify_subs[--ctx->num_notify_subs];
	return (0);
}

/*
 * Peripheral mode
 */

int
ble_add_service(ble_ctx_t *ctx, const ble_uuid_t *uuid,
    uint16_t *out_handle)
{
	uint8_t payload[IPC_GATT_ADD_SERVICE_REQ_SIZE];

	if (uuid == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "uuid is NULL");
		return (-1);
	}
	if (out_handle != NULL)
		*out_handle = 0;
	ble_gatt_req_encode(payload, IPC_GATT_ADD_SERVICE, NULL, 0);
	ble_gatt_uuid_encode(payload + 14, uuid);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_ADD_SERVICE, payload, sizeof(payload),
	    ble_gatt_handle_reply, out_handle, NULL));
}

int
ble_add_char_ex(ble_ctx_t *ctx, uint16_t svc_handle,
    const ble_uuid_t *uuid, uint8_t props, uint8_t perms,
    const uint8_t *value, uint16_t len, uint8_t flags, uint16_t *out_handle)
{
	uint8_t payload[IPC_MAX_PAYLOAD];

	if (uuid == NULL || svc_handle == 0 ||
	    (value == NULL && len != 0) ||
	    len > IPC_MAX_PAYLOAD - IPC_GATT_ADD_CHAR_REQ_SIZE) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid characteristic");
		return (-1);
	}
	if (out_handle != NULL)
		*out_handle = 0;
	ble_gatt_req_encode(payload, IPC_GATT_ADD_CHARACTERISTIC, NULL,
	    svc_handle);
	ble_gatt_uuid_encode(payload + 14, uuid);
	payload[32] = props;
	payload[33] = perms;
	payload[34] = flags;
	payload[35] = 0;
	ipc_put_le16(payload + 36, len);
	if (len != 0)
		memcpy(payload + IPC_GATT_ADD_CHAR_REQ_SIZE, value, len);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_ADD_CHARACTERISTIC, payload,
	    IPC_GATT_ADD_CHAR_REQ_SIZE + len, ble_gatt_handle_reply,
	    out_handle, NULL));
}

int
ble_add_characteristic(ble_ctx_t *ctx, uint16_t svc_handle,
    const ble_uuid_t *uuid, uint8_t props, uint8_t perms,
    const uint8_t *value, uint16_t len, uint16_t *out_handle)
{

	return (ble_add_char_ex(ctx, svc_handle, uuid, props, perms, value,
	    len, 0, out_handle));
}

int
ble_add_include(ble_ctx_t *ctx, uint16_t svc_handle,
    uint16_t included_start, uint16_t included_end, uint16_t uuid16,
    uint16_t *out_handle)
{
	uint8_t payload[IPC_GATT_ADD_INCLUDE_REQ_SIZE];

	if (out_handle != NULL)
		*out_handle = 0;
	if (svc_handle == 0 || included_start == 0 || included_end == 0 ||
	    included_end < included_start) {
		ctx->pending_handle = NULL;
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid include range");
		return (-1);
	}
	ble_gatt_req_encode(payload, IPC_GATT_ADD_INCLUDE, NULL,
	    svc_handle);
	ipc_put_le16(payload + 14, included_start);
	ipc_put_le16(payload + 16, included_end);
	ipc_put_le16(payload + 18, uuid16);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_ADD_INCLUDE, payload, sizeof(payload),
	    ble_gatt_handle_reply, out_handle, NULL));
}

int
ble_add_descriptor(ble_ctx_t *ctx, uint16_t char_handle,
    const ble_uuid_t *uuid, uint8_t perms, const uint8_t *value, uint16_t len,
    uint16_t *out_handle)
{
	uint8_t payload[IPC_MAX_PAYLOAD];

	if (uuid == NULL || char_handle == 0 ||
	    (value == NULL && len != 0) ||
	    len > IPC_MAX_PAYLOAD - IPC_GATT_ADD_DESC_REQ_SIZE) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid descriptor");
		return (-1);
	}
	if (out_handle != NULL)
		*out_handle = 0;
	ble_gatt_req_encode(payload, IPC_GATT_ADD_DESCRIPTOR, NULL,
	    char_handle);
	ble_gatt_uuid_encode(payload + 14, uuid);
	payload[32] = perms;
	payload[33] = 0;
	ipc_put_le16(payload + 34, len);
	if (len != 0)
		memcpy(payload + IPC_GATT_ADD_DESC_REQ_SIZE, value, len);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_ADD_DESCRIPTOR, payload,
	    IPC_GATT_ADD_DESC_REQ_SIZE + len, ble_gatt_handle_reply,
	    out_handle, NULL));
}

int
ble_set_value(ble_ctx_t *ctx, uint16_t handle,
    const uint8_t *value, uint16_t len)
{
	uint8_t payload[IPC_GATT_VALUE_REQ_SIZE + 512];

	if (value == NULL && len > 0) {
		ble_set_error(ctx, BLE_ERR_INVAL, "value is NULL");
		return (-1);
	}
	if (len > 512) {
		ble_set_error(ctx, BLE_ERR_INVAL, "value too long");
		return (-1);
	}
	ble_gatt_req_encode(payload, IPC_GATT_SET_VALUE, NULL, handle);
	ipc_put_le16(payload + 14, len);
	if (len != 0)
		memcpy(payload + IPC_GATT_VALUE_REQ_SIZE, value, len);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_SET_VALUE, payload, IPC_GATT_VALUE_REQ_SIZE + len,
	    NULL, NULL, NULL));
}

int
ble_notify(ble_ctx_t *ctx, uint16_t handle, const uint8_t *value, uint16_t len)
{
	uint8_t payload[IPC_GATT_VALUE_REQ_SIZE + 512];

	if (value == NULL && len > 0) {
		ble_set_error(ctx, BLE_ERR_INVAL, "value is NULL");
		return (-1);
	}
	if (len > 512) {
		ble_set_error(ctx, BLE_ERR_INVAL, "value too long");
		return (-1);
	}
	ble_gatt_req_encode(payload, IPC_GATT_NOTIFY, NULL, handle);
	ipc_put_le16(payload + 14, len);
	if (len != 0)
		memcpy(payload + IPC_GATT_VALUE_REQ_SIZE, value, len);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_NOTIFY, payload, IPC_GATT_VALUE_REQ_SIZE + len,
	    NULL, NULL, NULL));
}

int
ble_indicate(ble_ctx_t *ctx, uint16_t handle, const uint8_t *value,
    uint16_t len)
{
	uint8_t payload[IPC_GATT_VALUE_REQ_SIZE + 512];

	if (value == NULL && len > 0) {
		ble_set_error(ctx, BLE_ERR_INVAL, "value is NULL");
		return (-1);
	}
	if (len > 512) {
		ble_set_error(ctx, BLE_ERR_INVAL, "value too long");
		return (-1);
	}
	ble_gatt_req_encode(payload, IPC_GATT_INDICATE, NULL, handle);
	ipc_put_le16(payload + 14, len);
	if (len != 0)
		memcpy(payload + IPC_GATT_VALUE_REQ_SIZE, value, len);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_INDICATE, payload, IPC_GATT_VALUE_REQ_SIZE + len,
	    NULL, NULL, NULL));
}

int
ble_remove_service(ble_ctx_t *ctx, uint16_t handle)
{
	uint8_t payload[IPC_GATT_REQ_SIZE];

	ble_gatt_req_encode(payload, IPC_GATT_REMOVE_SERVICE, NULL, handle);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_REMOVE_SERVICE, payload, sizeof(payload), NULL, NULL,
	    NULL));
}

int
ble_gatt_begin(ble_ctx_t *ctx)
{

	return (ctl_send_typed(ctx, IPC_CTL_GATT_BEGIN, 0, 0, 0));
}

int
ble_gatt_commit(ble_ctx_t *ctx)
{

	return (ctl_send_typed(ctx, IPC_CTL_GATT_COMMIT, 0, 0, 0));
}

int
ble_gatt_rollback(ble_ctx_t *ctx)
{

	return (ctl_send_typed(ctx, IPC_CTL_GATT_ROLLBACK, 0, 0, 0));
}

void
ble_on_write(ble_ctx_t *ctx, ble_write_req_cb cb, void *arg)
{

	ctx->write_cb = cb;
	ctx->write_arg = arg;
}

void
ble_on_read_request(ble_ctx_t *ctx, ble_read_req_cb cb, void *arg)
{

	ctx->read_req_cb = cb;
	ctx->read_req_arg = arg;
}

void
ble_on_authorize(ble_ctx_t *ctx, ble_authorize_cb cb, void *arg)
{

	ctx->authorize_cb = cb;
	ctx->authorize_arg = arg;
}

int
ble_gatt_read_reply(ble_ctx_t *ctx, uint16_t handle, const uint8_t *value,
    uint16_t len)
{
	uint8_t payload[IPC_GATT_VALUE_REQ_SIZE + 512];

	if (len > 512 || (len != 0 && value == NULL)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "value too long");
		return (-1);
	}
	ble_gatt_req_encode(payload, IPC_GATT_READ_REPLY, NULL, handle);
	ipc_put_le16(payload + 14, len);
	if (len != 0)
		memcpy(payload + IPC_GATT_VALUE_REQ_SIZE, value, len);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_READ_REPLY, payload, IPC_GATT_VALUE_REQ_SIZE + len,
	    NULL, NULL, NULL));
}

int
ble_gatt_read_reject(ble_ctx_t *ctx, uint16_t handle, uint8_t att_error)
{
	uint8_t payload[IPC_GATT_DECISION_REQ_SIZE];

	ble_gatt_req_encode(payload, IPC_GATT_READ_REJECT, NULL, handle);
	payload[14] = att_error;
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_READ_REJECT, payload, sizeof(payload), NULL, NULL,
	    NULL));
}

int
ble_gatt_authorize_reply(ble_ctx_t *ctx, uint16_t handle, bool allow)
{
	uint8_t payload[IPC_GATT_DECISION_REQ_SIZE];

	ble_gatt_req_encode(payload, IPC_GATT_AUTHORIZE_REPLY, NULL, handle);
	payload[14] = allow ? 1 : 0;
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_GATT,
	    IPC_GATT_AUTHORIZE_REPLY, payload, sizeof(payload), NULL, NULL,
	    NULL));
}

/*
 * Pairing
 */

static void
ble_security_req_encode(uint8_t payload[IPC_SECURITY_REQ_SIZE],
    uint16_t opcode, const ble_addr_t *addr)
{

	memset(payload, 0, IPC_SECURITY_REQ_SIZE);
	ipc_put_le16(payload, opcode);
	if (addr != NULL) {
		payload[4] = addr->addr_type;
		memcpy(payload + 5, addr->addr, sizeof(addr->addr));
		payload[11] = addr->adapter_index;
	}
}

int
ble_passkey_reply(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint32_t passkey)
{
	uint8_t payload[IPC_SECURITY_PASSKEY_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || passkey > 999999) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	ble_security_req_encode(payload, IPC_SECURITY_PASSKEY_REPLY, addr);
	ipc_put_le32(payload + 12, passkey);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_PASSKEY_REPLY, payload, sizeof(payload), NULL,
	    NULL, NULL));
}

int
ble_numcmp_reply(ble_ctx_t *ctx, const ble_addr_t *addr, bool accept)
{
	uint8_t payload[IPC_SECURITY_DECISION_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	ble_security_req_encode(payload, IPC_SECURITY_NUMCMP_REPLY, addr);
	payload[12] = accept ? 1 : 0;
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_NUMCMP_REPLY, payload, sizeof(payload), NULL,
	    NULL, NULL));
}

void
ble_on_passkey_display(ble_ctx_t *ctx, ble_passkey_display_cb cb, void *arg)
{

	ctx->passkey_display_cb = cb;
	ctx->passkey_display_arg = arg;
}

void
ble_on_passkey_input(ble_ctx_t *ctx, ble_passkey_input_cb cb, void *arg)
{

	ctx->passkey_input_cb = cb;
	ctx->passkey_input_arg = arg;
}

void
ble_on_numcmp(ble_ctx_t *ctx, ble_numcmp_cb cb, void *arg)
{

	ctx->numcmp_cb = cb;
	ctx->numcmp_arg = arg;
}

void
ble_on_connected(ble_ctx_t *ctx, ble_conn_event_cb cb, void *arg)
{

	ctx->connected_cb = cb;
	ctx->connected_arg = arg;
}

void
ble_on_disconnected(ble_ctx_t *ctx, ble_disconn_event_cb cb, void *arg)
{

	ctx->disconnected_cb = cb;
	ctx->disconnected_arg = arg;
}

/*
 * Peripheral advertising control (finding C10).  Submission is asynchronous;
 * ble_process() consumes the correlated daemon result and updates ble_errno().
 */
int
ble_advertise(ble_ctx_t *ctx, bool enable)
{

	ble_clear_error(ctx);
	if (ctl_send_typed(ctx, IPC_CTL_ADVERTISE, IPC_CTL_F_BOOL,
	    enable ? 1 : 0, 0) < 0) {
		ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
		return (-1);
	}
	return (0);
}

int
ble_set_adv_params(ble_ctx_t *ctx, const ble_adv_params_t *params)
{
	uint8_t payload[IPC_ADV_PARAMS_REQ_SIZE];

	ble_clear_error(ctx);
	if (params == NULL ||
	    params->mode < 0 || params->mode > BLE_ADV_MODE_EXTENDED ||
	    params->type < 0 || params->type > BLE_ADV_TYPE_NONCONN_UND ||
	    params->interval_min > params->interval_max ||
	    params->primary_phy > BLE_PHY_CODED ||
	    params->secondary_phy > BLE_PHY_CODED ||
	    params->primary_phy == BLE_PHY_2M || /* 2M invalid on primary */
	    params->own_addr_type > 3 ||
	    (params->has_peer && params->peer.addr_type > 1) ||
	    params->channel_map > 7) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid advertising params");
		return (-1);
	}
	memset(payload, 0, sizeof(payload));
	ipc_put_le16(payload, IPC_ADV_SET_PARAMS);
	payload[4] = (uint8_t)params->mode;
	payload[5] = (uint8_t)params->type;
	payload[6] = params->channel_map != 0 ? params->channel_map : 0x07;
	payload[7] = params->own_addr_type;
	payload[8] = params->primary_phy != 0 ? params->primary_phy : BLE_PHY_1M;
	payload[9] = params->secondary_phy != 0 ? params->secondary_phy :
	    BLE_PHY_1M;
	payload[10] = (uint8_t)params->tx_power;
	payload[11] = params->has_peer ? 1 : 0;
	if (params->has_peer) {
		payload[12] = params->peer.addr_type;
		memcpy(payload + 13, params->peer.addr, sizeof(params->peer.addr));
	}
	ipc_put_le32(payload + 20, params->interval_min);
	ipc_put_le32(payload + 24, params->interval_max);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_ADV,
	    IPC_ADV_SET_PARAMS, payload, sizeof(payload), NULL, NULL, NULL));
}

int
ble_adapter_power(ble_ctx_t *ctx, int adapter_idx, bool on)
{
	uint16_t flags;
	uint32_t arg1;

	ble_clear_error(ctx);
	flags = IPC_CTL_F_BOOL;
	arg1 = 0;
	if (adapter_idx >= 0) {
		flags |= IPC_CTL_F_ADAPTER;
		arg1 = (uint32_t)adapter_idx;
	}
	if (ctl_send_typed(ctx, IPC_CTL_POWER, flags, on ? 1 : 0, arg1) < 0) {
		ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
		return (-1);
	}
	return (0);
}

int
ble_set_discoverable(ble_ctx_t *ctx, bool enable, unsigned int timeout,
    bool limited)
{
	uint16_t flags;

	ble_clear_error(ctx);
	if (timeout > 3600) {
		ble_set_error(ctx, BLE_ERR_INVAL,
		    "discoverable timeout out of range");
		return (-1);
	}
	flags = IPC_CTL_F_BOOL;
	if (limited)
		flags |= IPC_CTL_F_LIMITED;
	if (ctl_send_typed(ctx, IPC_CTL_DISCOVERABLE, flags,
	    enable ? 1 : 0, timeout) < 0) {
		ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
		return (-1);
	}
	return (0);
}

int
ble_set_pairable(ble_ctx_t *ctx, bool enable)
{

	ble_clear_error(ctx);
	if (ctl_send_typed(ctx, IPC_CTL_PAIRABLE, IPC_CTL_F_BOOL,
	    enable ? 1 : 0, 0) < 0) {
		ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
		return (-1);
	}
	return (0);
}

int
ble_set_name(ble_ctx_t *ctx, const char *name)
{
	const char *p;
	uint8_t payload[IPC_ADV_NAME_REQ_HDR_SIZE + IPC_ADV_NAME_MAX_SIZE];
	size_t len;

	ble_clear_error(ctx);
	if (name == NULL || *name == '\0') {
		ble_set_error(ctx, BLE_ERR_INVAL, "empty name");
		return (-1);
	}
	for (p = name; *p != '\0'; p++) {
		if ((unsigned char)*p < 0x20 || (unsigned char)*p == 0x7F) {
			ble_set_error(ctx, BLE_ERR_INVAL,
			    "name contains control characters");
			return (-1);
		}
	}
	len = strlen(name);
	if (len > IPC_ADV_NAME_MAX_SIZE) {
		ble_set_error(ctx, BLE_ERR_INVAL, "name too long");
		return (-1);
	}
	memset(payload, 0, IPC_ADV_NAME_REQ_HDR_SIZE);
	ipc_put_le16(payload, IPC_ADV_SET_NAME);
	memcpy(payload + IPC_ADV_NAME_REQ_HDR_SIZE, name, len);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_ADV,
	    IPC_ADV_SET_NAME, payload, IPC_ADV_NAME_REQ_HDR_SIZE + len,
	    NULL, NULL, NULL));
}

int
ble_set_adv_data(ble_ctx_t *ctx, const uint8_t *data, uint16_t len)
{
	uint8_t payload[IPC_ADV_DATA_REQ_HDR_SIZE + 31];

	ble_clear_error(ctx);
	if (len > 31 || (len != 0 && data == NULL)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "adv data too long (max 31)");
		return (-1);
	}
	memset(payload, 0, IPC_ADV_DATA_REQ_HDR_SIZE);
	ipc_put_le16(payload, IPC_ADV_SET_DATA);
	ipc_put_le16(payload + 4, len);
	if (len != 0)
		memcpy(payload + IPC_ADV_DATA_REQ_HDR_SIZE, data, len);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_ADV,
	    IPC_ADV_SET_DATA, payload, IPC_ADV_DATA_REQ_HDR_SIZE + len,
	    NULL, NULL, NULL));
}

int
ble_set_scan_response(ble_ctx_t *ctx, const uint8_t *data, uint16_t len)
{
	uint8_t payload[IPC_ADV_DATA_REQ_HDR_SIZE + 31];

	ble_clear_error(ctx);
	if (len > 31 || (len != 0 && data == NULL)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "scan resp too long (max 31)");
		return (-1);
	}
	memset(payload, 0, IPC_ADV_DATA_REQ_HDR_SIZE);
	ipc_put_le16(payload, IPC_ADV_SET_SCAN_RESPONSE);
	ipc_put_le16(payload + 4, len);
	if (len != 0)
		memcpy(payload + IPC_ADV_DATA_REQ_HDR_SIZE, data, len);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_ADV,
	    IPC_ADV_SET_SCAN_RESPONSE, payload,
	    IPC_ADV_DATA_REQ_HDR_SIZE + len, NULL, NULL, NULL));
}

/*
 * Enable or disable LE privacy (Resolvable Private Addresses) at runtime.  The
 * daemon programs the resolving list and switches the own-address type used for
 * advertising/scanning/connecting (Core Spec Vol 6 Part B §6.4).
 */
int
ble_set_privacy(ble_ctx_t *ctx, bool on)
{

	ble_clear_error(ctx);
	if (ctl_send_typed(ctx, IPC_CTL_PRIVACY, IPC_CTL_F_BOOL,
	    on ? 1 : 0, 0) < 0) {
		ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
		return (-1);
	}
	return (0);
}

/*
 * Set the preferred ATT MTU the daemon requests in the Exchange MTU procedure
 * on subsequent connections (Core Spec Vol 3 Part F §3.4.2).  Bounded to
 * [23, 517], the classic ATT PDU range.
 */
int
ble_set_preferred_mtu(ble_ctx_t *ctx, uint16_t mtu)
{

	ble_clear_error(ctx);
	if (mtu < 23 || mtu > 517) {
		ble_set_error(ctx, BLE_ERR_INVAL, "mtu out of range (23-517)");
		return (-1);
	}
	if (ctl_send_typed(ctx, IPC_CTL_SET_MTU, 0, mtu, 0) < 0) {
		ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
		return (-1);
	}
	return (0);
}

/*
 * Error handling
 */

int
ble_errno(ble_ctx_t *ctx)
{

	return (ctx->last_error);
}

const char *
ble_strerror(ble_ctx_t *ctx)
{

	if (ctx->last_error == BLE_ERR_NONE)
		return ("no error");
	if (ctx->errmsg[0] != '\0')
		return (ctx->errmsg);
	switch (ctx->last_error) {
	case BLE_ERR_SOCKET:	return ("socket I/O error");
	case BLE_ERR_PROTO:	return ("protocol parse error");
	case BLE_ERR_BUSY:	return ("operation already in progress");
	case BLE_ERR_NOTCONN:	return ("not connected");
	case BLE_ERR_INVAL:	return ("invalid argument");
	case BLE_ERR_DAEMON:	return ("daemon error");
	case BLE_ERR_NOMEM:	return ("out of memory");
	case BLE_ERR_TIMEOUT:	return ("operation timed out");
	case BLE_ERR_PERM:	return ("permission denied");
	case BLE_ERR_NOTFOUND:	return ("not found");
	default:		return ("unknown error");
	}
}

/*
 * Connection state
 */

bool
ble_is_connected(ble_ctx_t *ctx)
{

	return (ctx != NULL && ctx->connection_count != 0);
}

uint16_t
ble_get_mtu(ble_ctx_t *ctx)
{

	/* The legacy aggregate is unambiguous only for one active connection. */
	return (ctx != NULL && ctx->connection_count == 1 ?
	    ctx->connections[0].mtu : 0);
}

bool
ble_is_peer_connected(ble_ctx_t *ctx, const ble_addr_t *addr)
{

	return (ctx != NULL && addr != NULL &&
	    ble_connection_index(ctx, addr) >= 0);
}

uint16_t
ble_get_peer_mtu(ble_ctx_t *ctx, const ble_addr_t *addr)
{
	int i;

	if (ctx == NULL || addr == NULL)
		return (0);
	i = ble_connection_index(ctx, addr);
	return (i >= 0 ? ctx->connections[i].mtu : 0);
}

/*
 * Pairing / bond management
 */

int
ble_pair(ble_ctx_t *ctx, const ble_addr_t *addr)
{
	uint8_t payload[IPC_SECURITY_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	ble_security_req_encode(payload, IPC_SECURITY_PAIR, addr);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_PAIR, payload, sizeof(payload), NULL, NULL,
	    NULL));
}

/* Map a BLE_IO_* capability to the daemon's REGISTER_AGENT keyword. */
static const char *
ble_io_cap_str(ble_io_cap_t io_cap)
{

	switch (io_cap) {
	case BLE_IO_DISPLAY_ONLY:	return ("DisplayOnly");
	case BLE_IO_DISPLAY_YESNO:	return ("DisplayYesNo");
	case BLE_IO_KEYBOARD_ONLY:	return ("KeyboardOnly");
	case BLE_IO_NO_INPUT_NO_OUTPUT:	return ("NoInputNoOutput");
	case BLE_IO_KEYBOARD_DISPLAY:	return ("KeyboardDisplay");
	}
	return (NULL);
}

int
ble_register_agent(ble_ctx_t *ctx, ble_io_cap_t io_cap)
{
	const char *cap = ble_io_cap_str(io_cap);
	uint8_t payload[IPC_SECURITY_AGENT_REQ_SIZE];

	ble_clear_error(ctx);
	if (cap == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid io capability");
		return (-1);
	}
	ble_security_req_encode(payload, IPC_SECURITY_REGISTER_AGENT, NULL);
	payload[12] = (uint8_t)io_cap;
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_REGISTER_AGENT, payload, sizeof(payload), NULL,
	    NULL, NULL));
}

int
ble_unregister_agent(ble_ctx_t *ctx)
{
	uint8_t payload[IPC_SECURITY_REQ_SIZE];

	ble_security_req_encode(payload, IPC_SECURITY_UNREGISTER_AGENT, NULL);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_UNREGISTER_AGENT, payload, sizeof(payload), NULL,
	    NULL, NULL));
}

int
ble_bond_list(ble_ctx_t *ctx, ble_bond_t *bonds, int max_bonds)
{
	uint8_t request[IPC_SECURITY_REQ_SIZE];
	uint8_t reply[IPC_SECURITY_BOND_REPLY_HDR_SIZE + BLE_MAX_BONDS *
	    IPC_SECURITY_BOND_RECORD_SIZE];
	size_t reply_len;

	ble_clear_error(ctx);
	if (bonds == NULL || max_bonds <= 0) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid arguments");
		return (-1);
	}
	uint16_t count;

	ble_security_req_encode(request, IPC_SECURITY_BOND_LIST, NULL);
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_BOND_LIST, request, sizeof(request), reply,
	    sizeof(reply), &reply_len) < 0)
		return (-1);
	if (reply_len < IPC_SECURITY_BOND_REPLY_HDR_SIZE ||
	    ipc_get_le16(reply) != IPC_SECURITY_BOND_LIST ||
	    (count = ipc_get_le16(reply + 2)) > BLE_MAX_BONDS ||
	    reply_len != IPC_SECURITY_BOND_REPLY_HDR_SIZE + count *
	    IPC_SECURITY_BOND_RECORD_SIZE) {
		ble_set_error(ctx, BLE_ERR_PROTO, "invalid bond snapshot");
		return (-1);
	}
	if (count > (uint16_t)max_bonds)
		count = (uint16_t)max_bonds;
	for (uint16_t i = 0; i < count; i++) {
		const uint8_t *record = reply + IPC_SECURITY_BOND_REPLY_HDR_SIZE +
		    i * IPC_SECURITY_BOND_RECORD_SIZE;
		uint8_t record_flags = record[7];

		if (record[0] > 1 ||
		    (record_flags & ~(IPC_SECURITY_BOND_F_LTK |
		    IPC_SECURITY_BOND_F_IRK | IPC_SECURITY_BOND_F_CSRK |
		    IPC_SECURITY_BOND_F_SC | IPC_SECURITY_BOND_F_LINK_KEY |
		    IPC_SECURITY_BOND_F_MITM)) != 0 ||
		    memchr(record + 8, '\0', 64) == NULL) {
			ble_set_error(ctx, BLE_ERR_PROTO, "invalid bond record");
			return (-1);
		}
		memset(&bonds[i], 0, sizeof(bonds[i]));
		bonds[i].addr.addr_type = record[0];
		memcpy(bonds[i].addr.addr, record + 1, 6);
		bonds[i].has_ltk =
		    (record_flags & IPC_SECURITY_BOND_F_LTK) != 0;
		bonds[i].has_irk =
		    (record_flags & IPC_SECURITY_BOND_F_IRK) != 0;
		bonds[i].has_csrk =
		    (record_flags & IPC_SECURITY_BOND_F_CSRK) != 0;
		bonds[i].is_sc =
		    (record_flags & IPC_SECURITY_BOND_F_SC) != 0;
		bonds[i].has_link_key =
		    (record_flags & IPC_SECURITY_BOND_F_LINK_KEY) != 0;
		strlcpy(bonds[i].name, (const char *)record + 8,
		    sizeof(bonds[i].name));
	}
	return ((int)count);
}

int
ble_connections(ble_ctx_t *ctx, ble_connection_info_t *connections,
    int max_connections)
{
	uint8_t request[IPC_GAP_CONNECTION_REQ_SIZE];
	uint8_t reply[IPC_GAP_CONNECTION_REPLY_HDR_SIZE +
	    IPC_GAP_CONNECTION_MAX * IPC_GAP_CONNECTION_RECORD_SIZE];
	size_t reply_len;
	struct ble_tracked_connection snapshot[BLE_MAX_TRACKED_CONNECTIONS];
	size_t snapshot_count = 0;
	uint16_t count, total_count;

	ble_clear_error(ctx);
	if (connections == NULL || max_connections <= 0) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid arguments");
		return (-1);
	}
	ipc_gap_req_encode(request, IPC_GAP_GET_CONNECTIONS, 0, 0,
	    (const uint8_t[6]){0}, 0);
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_GAP,
	    IPC_GAP_GET_CONNECTIONS, request, sizeof(request), reply,
	    sizeof(reply), &reply_len) < 0)
		return (-1);
	if (reply_len < IPC_GAP_CONNECTION_REPLY_HDR_SIZE ||
	    ipc_get_le16(reply) != IPC_GAP_GET_CONNECTIONS ||
	    (count = ipc_get_le16(reply + 2)) > IPC_GAP_CONNECTION_MAX ||
	    reply_len != IPC_GAP_CONNECTION_REPLY_HDR_SIZE + count *
	    IPC_GAP_CONNECTION_RECORD_SIZE) {
		ble_set_error(ctx, BLE_ERR_PROTO, "invalid connection snapshot");
		return (-1);
	}
	total_count = count;
	for (uint16_t i = 0; i < total_count; i++) {
		const uint8_t *record = reply + IPC_GAP_CONNECTION_REPLY_HDR_SIZE +
		    i * IPC_GAP_CONNECTION_RECORD_SIZE;
		uint8_t record_flags = record[9];
		ble_connection_info_t *out = i < (uint16_t)max_connections ?
		    &connections[i] : NULL;

		if (record[0] > 1 || record[7] > 3 || record[8] > 1 ||
		    (record_flags & ~(IPC_GAP_CONN_F_ENCRYPTED |
		    IPC_GAP_CONN_F_AUTHENTICATED | IPC_GAP_CONN_F_PHY_VALID)) != 0 ||
		    record[10] > 16 ||
		    ((record_flags & IPC_GAP_CONN_F_ENCRYPTED) != 0 &&
		    record[10] < 7) ||
		    ((record_flags & IPC_GAP_CONN_F_AUTHENTICATED) != 0 &&
		    (record_flags & IPC_GAP_CONN_F_ENCRYPTED) == 0) ||
		    ((record_flags & IPC_GAP_CONN_F_PHY_VALID) != 0 &&
		    (record[11] < 1 || record[11] > 3 || record[12] < 1 ||
		    record[12] > 3)) || record[13] >= 8 ||
		    memchr(record + 24, '\0', 64) == NULL) {
			ble_set_error(ctx, BLE_ERR_PROTO,
			    "invalid connection record");
			return (-1);
		}
		if (out == NULL)
			continue;
		memset(out, 0, sizeof(*out));
		out->addr.addr_type = record[0];
		memcpy(out->addr.addr, record + 1, 6);
		out->addr.adapter_index = record[13];
		out->adapter_index = record[13];
		out->state = record[7];
		out->role = record[8];
		out->encrypted =
		    (record_flags & IPC_GAP_CONN_F_ENCRYPTED) != 0;
		out->authenticated =
		    (record_flags & IPC_GAP_CONN_F_AUTHENTICATED) != 0;
		out->key_size = record[10];
		out->phy_valid =
		    (record_flags & IPC_GAP_CONN_F_PHY_VALID) != 0;
		out->tx_phy = record[11];
		out->rx_phy = record[12];
		out->handle = ipc_get_le16(record + 14);
		out->mtu = ipc_get_le16(record + 16);
		out->interval = ipc_get_le16(record + 18);
		out->latency = ipc_get_le16(record + 20);
		out->supervision_timeout = ipc_get_le16(record + 22);
		strlcpy(out->name, (const char *)record + 24,
		    sizeof(out->name));
	}
	count = total_count < (uint16_t)max_connections ? total_count :
	    (uint16_t)max_connections;
	/*
	 * A successful snapshot is authoritative.  Reconcile from every returned
	 * record, including records beyond the caller's output capacity; only ACTIVE
	 * links belong in the convenience connection/MTU cache.  Validation above
	 * completes before publishing, so a malformed/failed snapshot preserves the
	 * last known event-derived state.
	 */
	for (uint16_t i = 0; i < total_count; i++) {
		const uint8_t *record = reply + IPC_GAP_CONNECTION_REPLY_HDR_SIZE +
		    i * IPC_GAP_CONNECTION_RECORD_SIZE;

		if (record[7] != BLE_CONNECTION_ACTIVE)
			continue;
		snapshot[snapshot_count].addr.addr_type = record[0];
		memcpy(snapshot[snapshot_count].addr.addr, record + 1, 6);
		snapshot[snapshot_count].addr.adapter_index = record[13];
		snapshot[snapshot_count].mtu = ipc_get_le16(record + 16);
		snapshot_count++;
	}
	memcpy(ctx->connections, snapshot,
	    snapshot_count * sizeof(snapshot[0]));
	if (snapshot_count < ctx->connection_count)
		memset(&ctx->connections[snapshot_count], 0,
		    (ctx->connection_count - snapshot_count) *
		    sizeof(ctx->connections[0]));
	ctx->connection_count = snapshot_count;
	return ((int)count);
}

int
ble_unbond(ble_ctx_t *ctx, const ble_addr_t *addr)
{
	uint8_t payload[IPC_SECURITY_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	ble_security_req_encode(payload, IPC_SECURITY_UNBOND, addr);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_UNBOND, payload, sizeof(payload), NULL, NULL,
	    NULL));
}

int
ble_rekey(ble_ctx_t *ctx, const ble_addr_t *addr)
{
	uint8_t payload[IPC_SECURITY_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	ble_security_req_encode(payload, IPC_SECURITY_REKEY, addr);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_REKEY, payload, sizeof(payload), NULL, NULL,
	    NULL));
}

/*
 * ============================================================
 * Security / pairing / privacy policy (de-hardcoded surface)
 * ============================================================
 */

struct ble_adv_set {
	ble_ctx_t *ctx;
	uint8_t handle;
};

int
ble_adv_set_create(ble_ctx_t *ctx, ble_adv_set_t **out)
{
	ble_adv_set_t *set;
	unsigned handle;
	uint8_t request[IPC_ADV_SET_CREATE_REQ_SIZE];
	uint8_t reply[IPC_ADV_SET_CREATE_REPLY_SIZE];
	size_t reply_len;

	ble_clear_error(ctx);
	if (out == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid advertising set output");
		return (-1);
	}
	memset(request, 0, sizeof(request));
	ipc_put_le16(request, IPC_ADV_SET_CREATE);
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_ADV,
	    IPC_ADV_SET_CREATE, request, sizeof(request), reply,
	    sizeof(reply), &reply_len) < 0)
		return (-1);
	if (reply_len != sizeof(reply) ||
	    ipc_get_le16(reply) != IPC_ADV_SET_CREATE || reply[2] == 0 ||
	    reply[2] > 0xef || reply[3] != 0) {
		ble_set_error(ctx, BLE_ERR_PROTO,
		    "invalid advertising set reply");
		return (-1);
	}
	handle = reply[2];
	set = calloc(1, sizeof(*set));
	if (set == NULL) {
		uint8_t remove[IPC_ADV_SET_STATE_REQ_SIZE] = { 0 };
		size_t ignored;

		ipc_put_le16(remove, IPC_ADV_SET_HANDLE_REMOVE);
		remove[4] = (uint8_t)handle;
		(void)ble_sync_operation(ctx, IPC_OP_DOMAIN_ADV,
		    IPC_ADV_SET_HANDLE_REMOVE, remove, sizeof(remove), NULL, 0,
		    &ignored);
		ble_set_error(ctx, BLE_ERR_NOMEM, "out of memory");
		return (-1);
	}
	set->ctx = ctx;
	set->handle = (uint8_t)handle;
	*out = set;
	return (0);
}

uint8_t
ble_adv_set_handle(const ble_adv_set_t *set)
{

	return (set != NULL ? set->handle : 0);
}

int
ble_adv_set_params(ble_adv_set_t *set, uint16_t props, uint32_t min,
    uint32_t max, uint8_t primary, uint8_t secondary)
{
	uint8_t request[IPC_ADV_SET_PARAMS_REQ_SIZE];
	size_t reply_len;

	if (set == NULL || min < 0x20 || max > 0xffffff || min > max) {
		if (set != NULL)
			ble_set_error(set->ctx, BLE_ERR_INVAL, "invalid set params");
		return (-1);
	}
	memset(request, 0, sizeof(request));
	ipc_put_le16(request, IPC_ADV_SET_HANDLE_PARAMS);
	request[4] = set->handle;
	request[5] = primary;
	request[6] = secondary;
	ipc_put_le16(request + 8, props);
	ipc_put_le32(request + 12, min);
	ipc_put_le32(request + 16, max);
	return (ble_sync_operation(set->ctx, IPC_OP_DOMAIN_ADV,
	    IPC_ADV_SET_HANDLE_PARAMS, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_adv_set_data(ble_adv_set_t *set, const uint8_t *data, uint8_t len)
{
	uint8_t request[IPC_ADV_SET_DATA_REQ_HDR_SIZE + 251];
	size_t reply_len;

	if (set == NULL || len > 251 || (len != 0 && data == NULL)) {
		if (set != NULL)
			ble_set_error(set->ctx, BLE_ERR_INVAL, "invalid set data");
		return (-1);
	}
	memset(request, 0, IPC_ADV_SET_DATA_REQ_HDR_SIZE);
	ipc_put_le16(request, IPC_ADV_SET_HANDLE_DATA);
	request[4] = set->handle;
	request[5] = len;
	if (len != 0)
		memcpy(request + IPC_ADV_SET_DATA_REQ_HDR_SIZE, data, len);
	return (ble_sync_operation(set->ctx, IPC_OP_DOMAIN_ADV,
	    IPC_ADV_SET_HANDLE_DATA, request,
	    IPC_ADV_SET_DATA_REQ_HDR_SIZE + len, NULL, 0, &reply_len));
}

int
ble_adv_set_enable(ble_adv_set_t *set, bool enable)
{
	uint8_t request[IPC_ADV_SET_STATE_REQ_SIZE] = { 0 };
	size_t reply_len;

	if (set == NULL)
		return (-1);
	ipc_put_le16(request, IPC_ADV_SET_HANDLE_ENABLE);
	request[4] = set->handle;
	request[5] = enable ? 1 : 0;
	return (ble_sync_operation(set->ctx, IPC_OP_DOMAIN_ADV,
	    IPC_ADV_SET_HANDLE_ENABLE, request, sizeof(request), NULL, 0,
	    &reply_len));
}

void
ble_adv_set_close(ble_adv_set_t *set)
{
	uint8_t request[IPC_ADV_SET_STATE_REQ_SIZE] = { 0 };
	size_t reply_len;

	if (set == NULL)
		return;
	ipc_put_le16(request, IPC_ADV_SET_HANDLE_REMOVE);
	request[4] = set->handle;
	(void)ble_sync_operation(set->ctx, IPC_OP_DOMAIN_ADV,
	    IPC_ADV_SET_HANDLE_REMOVE, request, sizeof(request), NULL, 0,
	    &reply_len);
	free(set);
}

int
ble_eatt_open(ble_ctx_t *ctx, const ble_addr_t *addr, unsigned count)
{
	uint8_t request[IPC_L2CAP_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || count < 1 || count > 5) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid EATT arguments");
		return (-1);
	}
	ipc_put_le16(request, IPC_L2CAP_EATT_OPEN);
	request[4] = addr->addr_type;
	memcpy(request + 5, addr->addr, sizeof(addr->addr));
	request[11] = (uint8_t)count;
	request[16] = addr->adapter_index;
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_L2CAP,
	    IPC_L2CAP_EATT_OPEN, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_eatt_close(ble_ctx_t *ctx, const ble_addr_t *addr)
{
	uint8_t request[IPC_L2CAP_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid EATT address");
		return (-1);
	}
	ipc_put_le16(request, IPC_L2CAP_EATT_CLOSE);
	request[4] = addr->addr_type;
	memcpy(request + 5, addr->addr, sizeof(addr->addr));
	request[16] = addr->adapter_index;
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_L2CAP,
	    IPC_L2CAP_EATT_CLOSE, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_adapter_caps(ble_ctx_t *ctx, int adapter_idx, ble_adapter_caps_t *out)
{
	uint8_t req[IPC_CTL_REQ_SIZE];
	uint8_t payload[IPC_ADAPTER_CAPS_REPLY_SIZE];
	uint16_t typed_index;
	uint8_t typed_addr[6], typed_addr_type, typed_powered;
	uint64_t typed_features;
	size_t plen;

	ble_clear_error(ctx);
	if (out == NULL || adapter_idx < 0 || adapter_idx > UINT16_MAX) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid adapter capability query");
		return (-1);
	}
	ipc_ctl_req_encode(req, IPC_CTL_ADAPTER_CAPS, 0,
	    (uint32_t)adapter_idx, 0);
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_CTL, IPC_CTL_ADAPTER_CAPS,
	    req, sizeof(req), payload, sizeof(payload), &plen) < 0)
		return (-1);
	if (plen != IPC_ADAPTER_CAPS_REPLY_SIZE) {
		ble_set_error(ctx, BLE_ERR_PROTO, "bad ADAPTER_CAPS reply");
		return (-1);
	}
	ipc_adapter_caps_reply_decode(payload, &typed_index, out->name,
	    typed_addr, &typed_addr_type, &typed_powered, &typed_features);
	if (typed_index != (uint16_t)adapter_idx ||
	    typed_addr_type > 1 || typed_powered > 1) {
		ble_set_error(ctx, BLE_ERR_PROTO, "bad ADAPTER_CAPS reply");
		return (-1);
	}
	out->name[sizeof(out->name) - 1] = '\0';
	out->index = typed_index;
	memcpy(out->addr.addr, typed_addr, sizeof(out->addr.addr));
	out->addr.addr_type = typed_addr_type;
	out->addr.adapter_index = typed_index;
	out->powered = typed_powered != 0;
	out->le_features = typed_features;
	return (0);
}

int
ble_status(ble_ctx_t *ctx, ble_status_t *out)
{
	uint8_t req[IPC_CTL_REQ_SIZE];
	uint8_t payload[IPC_STATUS_REPLY_SIZE];
	uint16_t flags;
	size_t payload_len;

	ble_clear_error(ctx);
	if (out == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid status output");
		return (-1);
	}
	ipc_ctl_req_encode(req, IPC_CTL_STATUS, 0, 0, 0);
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_CTL, IPC_CTL_STATUS,
	    req, sizeof(req), payload, sizeof(payload), &payload_len) < 0)
		return (-1);
	if (payload_len != IPC_STATUS_REPLY_SIZE) {
		ble_set_error(ctx, BLE_ERR_PROTO, "bad STATUS reply");
		return (-1);
	}
	ipc_status_reply_decode(payload, &out->adapters, &out->connections,
	    &out->clients, &flags);
	if ((flags & ~IPC_STATUS_F_PERIPH_ACTIVE) != 0) {
		ble_set_error(ctx, BLE_ERR_PROTO, "bad STATUS flags");
		return (-1);
	}
	out->peripheral_active = (flags & IPC_STATUS_F_PERIPH_ACTIVE) != 0;
	return (0);
}

int
ble_periodic_adv_params(ble_ctx_t *ctx, uint8_t adapter_index,
    uint16_t interval_min,
    uint16_t interval_max, uint16_t properties)
{
	uint8_t request[IPC_PERIODIC_PARAMS_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	if (interval_min < 0x0006 || interval_min > interval_max ||
	    (properties & ~BLE_PERIODIC_ADV_PROP_INCLUDE_TX_POWER) != 0) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid periodic intervals");
		return (-1);
	}
	ipc_put_le16(request, IPC_PERIODIC_ADV_PARAMS);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	ipc_put_le16(request + 4, interval_min);
	ipc_put_le16(request + 6, interval_max);
	ipc_put_le16(request + 8, properties);
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    IPC_PERIODIC_ADV_PARAMS, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_periodic_adv_data(ble_ctx_t *ctx, uint8_t adapter_index,
    const uint8_t *data, uint8_t len)
{
	uint8_t request[IPC_PERIODIC_DATA_REQ_HDR_SIZE + 252];
	size_t reply_len;

	ble_clear_error(ctx);
	if (data == NULL && len != 0) {
		ble_set_error(ctx, BLE_ERR_INVAL, "missing periodic data");
		return (-1);
	}
	if (len > 252) {
		ble_set_error(ctx, BLE_ERR_INVAL, "periodic data too long");
		return (-1);
	}
	memset(request, 0, IPC_PERIODIC_DATA_REQ_HDR_SIZE);
	ipc_put_le16(request, IPC_PERIODIC_ADV_DATA);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	ipc_put_le16(request + 4, len);
	if (len != 0)
		memcpy(request + IPC_PERIODIC_DATA_REQ_HDR_SIZE, data, len);
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    IPC_PERIODIC_ADV_DATA, request, IPC_PERIODIC_DATA_REQ_HDR_SIZE + len,
	    NULL, 0, &reply_len));
}

int
ble_periodic_adv_enable(ble_ctx_t *ctx, uint8_t adapter_index, bool enable)
{
	uint8_t request[IPC_PERIODIC_STATE_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	ipc_put_le16(request, IPC_PERIODIC_ADV_ENABLE);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = enable ? 1 : 0;
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    IPC_PERIODIC_ADV_ENABLE, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_periodic_sync_create(ble_ctx_t *ctx, const ble_addr_t *addr, uint8_t sid,
    uint16_t skip, uint16_t timeout)
{
	uint8_t request[IPC_PERIODIC_SYNC_CREATE_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || sid > 0x0f || skip > 0x01f3 ||
	    timeout < 0x000a || timeout > 0x4000) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid periodic sync parameters");
		return (-1);
	}
	ipc_put_le16(request, IPC_PERIODIC_SYNC_CREATE);
	ipc_put_le16(request + 2,
	    (uint16_t)addr->adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = addr->addr_type;
	memcpy(request + 5, addr->addr, sizeof(addr->addr));
	request[11] = sid;
	ipc_put_le16(request + 12, skip);
	ipc_put_le16(request + 14, timeout);
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    IPC_PERIODIC_SYNC_CREATE, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_periodic_sync_cancel(ble_ctx_t *ctx, uint8_t adapter_index)
{
	uint8_t request[IPC_PERIODIC_SIMPLE_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	ipc_put_le16(request, IPC_PERIODIC_SYNC_CANCEL);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    IPC_PERIODIC_SYNC_CANCEL, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_periodic_sync_terminate(ble_ctx_t *ctx, uint8_t adapter_index,
    uint16_t sync_handle)
{
	uint8_t request[IPC_PERIODIC_STATE_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	if (sync_handle > 0x0eff) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid periodic sync handle");
		return (-1);
	}
	ipc_put_le16(request, IPC_PERIODIC_SYNC_TERMINATE);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	ipc_put_le16(request + 4, sync_handle);
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    IPC_PERIODIC_SYNC_TERMINATE, request, sizeof(request), NULL, 0,
	    &reply_len));
}

static int
ble_periodic_adv_list_peer(ble_ctx_t *ctx, const ble_addr_t *addr, uint8_t sid,
    bool add)
{
	uint8_t request[IPC_PERIODIC_PEER_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || sid > 0x0f) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid periodic advertiser");
		return (-1);
	}
	ipc_put_le16(request, add ? IPC_PERIODIC_LIST_ADD :
	    IPC_PERIODIC_LIST_REMOVE);
	ipc_put_le16(request + 2,
	    (uint16_t)addr->adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = addr->addr_type;
	memcpy(request + 5, addr->addr, sizeof(addr->addr));
	request[11] = sid;
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    add ? IPC_PERIODIC_LIST_ADD : IPC_PERIODIC_LIST_REMOVE,
	    request, sizeof(request), NULL, 0, &reply_len));
}

int
ble_periodic_adv_list_add(ble_ctx_t *ctx, const ble_addr_t *addr, uint8_t sid)
{
	return (ble_periodic_adv_list_peer(ctx, addr, sid, true));
}

int
ble_periodic_adv_list_remove(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint8_t sid)
{
	return (ble_periodic_adv_list_peer(ctx, addr, sid, false));
}

int
ble_periodic_adv_list_clear(ble_ctx_t *ctx, uint8_t adapter_index)
{
	uint8_t request[IPC_PERIODIC_SIMPLE_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	ipc_put_le16(request, IPC_PERIODIC_LIST_CLEAR);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    IPC_PERIODIC_LIST_CLEAR, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_periodic_adv_list_size(ble_ctx_t *ctx, uint8_t adapter_index,
    uint8_t *size)
{
	uint8_t request[IPC_PERIODIC_SIMPLE_REQ_SIZE] = { 0 };
	uint8_t reply[IPC_PERIODIC_SIZE_REPLY_SIZE];
	size_t reply_len;

	ble_clear_error(ctx);
	if (size == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "missing advertiser-list size output");
		return (-1);
	}
	ipc_put_le16(request, IPC_PERIODIC_LIST_SIZE);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    IPC_PERIODIC_LIST_SIZE, request, sizeof(request), reply,
	    sizeof(reply), &reply_len) < 0)
		return (-1);
	if (reply_len != sizeof(reply) ||
	    ipc_get_le16(reply) != IPC_PERIODIC_LIST_SIZE || reply[3] != 0) {
		ble_set_error(ctx, BLE_ERR_PROTO, "invalid advertiser-list size reply");
		return (-1);
	}
	*size = reply[2];
	return (0);
}

int
ble_past_transfer(ble_ctx_t *ctx, const ble_addr_t *peer,
    uint16_t service_data, uint16_t sync_handle)
{
	uint8_t request[IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	if (!ble_addr_valid(peer) || sync_handle > 0x0eff) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid PAST transfer parameters");
		return (-1);
	}
	ipc_put_le16(request, IPC_PERIODIC_PAST_TRANSFER);
	ipc_put_le16(request + 2,
	    (uint16_t)peer->adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = peer->addr_type;
	memcpy(request + 5, peer->addr, sizeof(peer->addr));
	ipc_put_le16(request + 12, service_data);
	ipc_put_le16(request + 14, sync_handle);
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    IPC_PERIODIC_PAST_TRANSFER, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_past_receive_enable(ble_ctx_t *ctx, uint8_t adapter_index,
    uint16_t sync_handle, bool enable)
{
	uint8_t request[IPC_PERIODIC_STATE_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	if (sync_handle > 0x0eff) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid periodic sync handle");
		return (-1);
	}
	ipc_put_le16(request, IPC_PERIODIC_PAST_RECEIVE);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	ipc_put_le16(request + 4, sync_handle);
	request[6] = enable ? 1 : 0;
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    IPC_PERIODIC_PAST_RECEIVE, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_past_set_info_transfer(ble_ctx_t *ctx, const ble_addr_t *peer,
    uint16_t service_data, uint8_t adv_handle)
{
	uint8_t request[IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	if (!ble_addr_valid(peer) || adv_handle > 0xef) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid PAST set transfer");
		return (-1);
	}
	ipc_put_le16(request, IPC_PERIODIC_PAST_SET_INFO);
	ipc_put_le16(request + 2,
	    (uint16_t)peer->adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = peer->addr_type;
	memcpy(request + 5, peer->addr, sizeof(peer->addr));
	ipc_put_le16(request + 12, service_data);
	request[14] = adv_handle;
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    IPC_PERIODIC_PAST_SET_INFO, request, sizeof(request), NULL, 0,
	    &reply_len));
}

static bool
ble_past_params_valid(uint8_t mode, uint16_t skip, uint16_t timeout)
{
	return (mode <= 3 && skip <= 0x01f3 && timeout >= 0x000a &&
	    timeout <= 0x4000);
}

int
ble_past_params(ble_ctx_t *ctx, const ble_addr_t *peer, uint8_t mode,
    uint16_t skip, uint16_t timeout, uint8_t cte_type)
{
	uint8_t request[IPC_PERIODIC_PAST_PARAMS_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	if (!ble_addr_valid(peer) || !ble_past_params_valid(mode, skip, timeout) ||
	    (cte_type & ~0x17u) != 0) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid PAST parameters");
		return (-1);
	}
	ipc_put_le16(request, IPC_PERIODIC_PAST_PARAMS);
	ipc_put_le16(request + 2,
	    (uint16_t)peer->adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = peer->addr_type;
	memcpy(request + 5, peer->addr, sizeof(peer->addr));
	request[12] = mode;
	request[13] = cte_type;
	ipc_put_le16(request + 14, skip);
	ipc_put_le16(request + 16, timeout);
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    IPC_PERIODIC_PAST_PARAMS, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_past_default_params(ble_ctx_t *ctx, uint8_t adapter_index, uint8_t mode,
    uint16_t skip, uint16_t timeout, uint8_t cte_type)
{
	uint8_t request[IPC_PERIODIC_PAST_DEFAULT_REQ_SIZE] = { 0 };
	size_t reply_len;

	ble_clear_error(ctx);
	if (!ble_past_params_valid(mode, skip, timeout) ||
	    (cte_type & ~0x17u) != 0) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid default PAST parameters");
		return (-1);
	}
	ipc_put_le16(request, IPC_PERIODIC_PAST_DEFAULT_PARAMS);
	ipc_put_le16(request + 2,
	    (uint16_t)adapter_index << IPC_OP_ADAPTER_SHIFT);
	request[4] = mode;
	request[5] = cte_type;
	ipc_put_le16(request + 6, skip);
	ipc_put_le16(request + 8, timeout);
	return (ble_sync_operation(ctx, IPC_OP_DOMAIN_PERIODIC,
	    IPC_PERIODIC_PAST_DEFAULT_PARAMS, request, sizeof(request), NULL, 0,
	    &reply_len));
}

int
ble_path_loss_reporting(ble_ctx_t *ctx, const ble_addr_t *addr, uint8_t low,
    uint8_t low_hysteresis, uint8_t high, uint8_t high_hysteresis,
    uint16_t min_time, bool enable)
{
	uint8_t payload[IPC_GAP_PATH_LOSS_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || low > high ||
	    low_hysteresis > low || high_hysteresis > 0xff - high) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid path loss parameters");
		return (-1);
	}
	ipc_gap_req_encode(payload, IPC_GAP_PATH_LOSS, 0,
	    addr->addr_type, addr->addr, addr->adapter_index);
	payload[12] = low;
	payload[13] = low_hysteresis;
	payload[14] = high;
	payload[15] = high_hysteresis;
	ipc_put_le16(payload + 16, min_time);
	payload[18] = enable ? 1 : 0;
	payload[19] = 0;
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_GAP,
	    IPC_GAP_PATH_LOSS, payload, sizeof(payload), NULL, NULL, NULL));
}

static bool
ble_key_dist_valid(uint8_t key_dist)
{

	return ((key_dist & ~(BLE_KEY_DIST_ENC | BLE_KEY_DIST_ID |
	    BLE_KEY_DIST_SIGN)) == 0);
}

static int
ble_send_security_policy(ble_ctx_t *ctx, uint16_t mask,
    const ble_security_policy_t *pol)
{
	uint8_t payload[IPC_SECURITY_POLICY_REQ_SIZE];

	ble_security_req_encode(payload, IPC_SECURITY_SET_POLICY, NULL);
	ipc_put_le16(payload + 12, mask);
	payload[14] = pol->mitm ? 1 : 0;
	payload[15] = pol->bonding ? 1 : 0;
	payload[16] = (uint8_t)pol->sc_mode;
	payload[17] = pol->keypress ? 1 : 0;
	payload[18] = (uint8_t)pol->io_cap;
	payload[19] = (uint8_t)pol->min_security;
	payload[20] = pol->min_key_size;
	payload[21] = pol->key_dist;
	ipc_put_le16(payload + 22, 0);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_SET_POLICY, payload, sizeof(payload), NULL, NULL,
	    NULL));
}

int
ble_set_security_policy(ble_ctx_t *ctx, const ble_security_policy_t *pol)
{
	ble_clear_error(ctx);
	if (pol == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "null policy");
		return (-1);
	}
	if (pol->io_cap < BLE_IO_DISPLAY_ONLY ||
	    pol->io_cap > BLE_IO_KEYBOARD_DISPLAY) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid io capability");
		return (-1);
	}
	if (pol->sc_mode < BLE_SC_OFF || pol->sc_mode > BLE_SC_ONLY) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid SC mode");
		return (-1);
	}
	if (pol->min_security < BLE_SEC_NONE ||
	    pol->min_security > BLE_SEC_SC) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid security level");
		return (-1);
	}
	if (pol->min_key_size < 7 || pol->min_key_size > 16) {
		ble_set_error(ctx, BLE_ERR_INVAL, "key size out of range");
		return (-1);
	}
	if (!ble_key_dist_valid(pol->key_dist)) {
		ble_set_error(ctx, BLE_ERR_INVAL,
		    "invalid key distribution mask");
		return (-1);
	}
	return (ble_send_security_policy(ctx, IPC_SECURITY_POLICY_F_ALL, pol));
}

int
ble_get_security_policy(ble_ctx_t *ctx, ble_security_policy_t *out)
{
	uint8_t request[IPC_SECURITY_REQ_SIZE];
	uint8_t reply[IPC_SECURITY_POLICY_REPLY_SIZE];
	size_t reply_len;

	ble_clear_error(ctx);
	if (out == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "null out");
		return (-1);
	}
	ble_security_req_encode(request, IPC_SECURITY_GET_POLICY, NULL);
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_GET_POLICY, request, sizeof(request), reply,
	    sizeof(reply), &reply_len) < 0)
		return (-1);
	if (reply_len != sizeof(reply) ||
	    ipc_get_le16(reply) != IPC_SECURITY_GET_POLICY ||
	    reply[2] > 1 || reply[3] > 1 || reply[4] > 2 ||
	    reply[5] > 1 || reply[6] > 4 || reply[7] > 3 ||
	    reply[8] < 7 || reply[8] > 16 ||
	    !ble_key_dist_valid(reply[9]) ||
	    ipc_get_le16(reply + 10) < 1 ||
	    ipc_get_le16(reply + 10) > 3600) {
		ble_set_error(ctx, BLE_ERR_PROTO, "invalid security policy");
		return (-1);
	}
	memset(out, 0, sizeof(*out));
	out->mitm = reply[2] != 0;
	out->bonding = reply[3] != 0;
	out->sc_mode = (ble_sc_mode_t)reply[4];
	out->keypress = reply[5] != 0;
	out->io_cap = (ble_io_cap_t)reply[6];
	out->min_security = (ble_sec_level_t)reply[7];
	out->min_key_size = reply[8];
	out->key_dist = reply[9];
	out->rpa_timeout = ipc_get_le16(reply + 10);
	return (0);
}

int
ble_set_mitm(ble_ctx_t *ctx, bool require_mitm)
{
	ble_security_policy_t pol = { .mitm = require_mitm };

	return (ble_send_security_policy(ctx, IPC_SECURITY_POLICY_F_MITM, &pol));
}

int
ble_set_bondable(ble_ctx_t *ctx, bool bondable)
{
	ble_security_policy_t pol = { .bonding = bondable };

	return (ble_send_security_policy(ctx,
	    IPC_SECURITY_POLICY_F_BONDING, &pol));
}

int
ble_set_sc_mode(ble_ctx_t *ctx, ble_sc_mode_t mode)
{
	ble_security_policy_t pol = { .sc_mode = mode };

	ble_clear_error(ctx);
	if (mode < BLE_SC_OFF || mode > BLE_SC_ONLY) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid SC mode");
		return (-1);
	}
	return (ble_send_security_policy(ctx, IPC_SECURITY_POLICY_F_SC, &pol));
}

int
ble_set_keypress(ble_ctx_t *ctx, bool enable)
{
	ble_security_policy_t pol = { .keypress = enable };

	return (ble_send_security_policy(ctx,
	    IPC_SECURITY_POLICY_F_KEYPRESS, &pol));
}

int
ble_set_io_capability(ble_ctx_t *ctx, ble_io_cap_t io_cap)
{
	ble_security_policy_t pol = { .io_cap = io_cap };

	ble_clear_error(ctx);
	if (io_cap < BLE_IO_DISPLAY_ONLY || io_cap > BLE_IO_KEYBOARD_DISPLAY) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid io capability");
		return (-1);
	}
	return (ble_send_security_policy(ctx,
	    IPC_SECURITY_POLICY_F_IO_CAP, &pol));
}

int
ble_set_min_security(ble_ctx_t *ctx, ble_sec_level_t level)
{
	ble_security_policy_t pol = { .min_security = level };

	ble_clear_error(ctx);
	if (level < BLE_SEC_NONE || level > BLE_SEC_SC) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid security level");
		return (-1);
	}
	return (ble_send_security_policy(ctx,
	    IPC_SECURITY_POLICY_F_MIN_SEC, &pol));
}

int
ble_set_min_key_size(ble_ctx_t *ctx, uint8_t key_size)
{
	ble_security_policy_t pol = { .min_key_size = key_size };

	ble_clear_error(ctx);
	if (key_size < 7 || key_size > 16) {
		ble_set_error(ctx, BLE_ERR_INVAL, "key size out of range");
		return (-1);
	}
	return (ble_send_security_policy(ctx,
	    IPC_SECURITY_POLICY_F_KEY_SIZE, &pol));
}

int
ble_set_key_distribution(ble_ctx_t *ctx, uint8_t key_dist)
{
	ble_security_policy_t pol = { .key_dist = key_dist };

	ble_clear_error(ctx);
	if (!ble_key_dist_valid(key_dist)) {
		ble_set_error(ctx, BLE_ERR_INVAL,
		    "invalid key distribution mask");
		return (-1);
	}
	return (ble_send_security_policy(ctx,
	    IPC_SECURITY_POLICY_F_KEY_DIST, &pol));
}

int
ble_set_rpa_timeout(ble_ctx_t *ctx, unsigned int seconds)
{

	ble_clear_error(ctx);
	if (seconds < 1 || seconds > 3600) {
		ble_set_error(ctx, BLE_ERR_INVAL, "rpa timeout out of range");
		return (-1);
	}
	if (ctl_send_typed(ctx, IPC_CTL_RPA_TIMEOUT, 0, seconds, 0) < 0) {
		ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
		return (-1);
	}
	return (0);
}

int
ble_get_security_info(ble_ctx_t *ctx, const ble_addr_t *addr,
    ble_security_info_t *out)
{
	uint8_t request[IPC_SECURITY_REQ_SIZE];
	uint8_t reply[IPC_SECURITY_INFO_REPLY_SIZE];
	size_t reply_len;

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || out == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "null argument");
		return (-1);
	}
	ble_security_req_encode(request, IPC_SECURITY_GET_INFO, addr);
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_GET_INFO, request, sizeof(request), reply,
	    sizeof(reply), &reply_len) < 0)
		return (-1);
	if (reply_len != sizeof(reply) ||
	    ipc_get_le16(reply) != IPC_SECURITY_GET_INFO || reply[2] > 1 ||
	    reply[9] > 16 || reply[10] < 1 || reply[10] > 4 ||
	    (reply[11] & ~0x0fu) != 0 ||
	    ((reply[11] & IPC_SECURITY_INFO_F_ENCRYPTED) != 0 &&
	    reply[9] < 7) ||
	    ((reply[11] & IPC_SECURITY_INFO_F_ENCRYPTED) == 0 &&
	    reply[10] != 1) ||
	    ((reply[11] & IPC_SECURITY_INFO_F_ENCRYPTED) != 0 &&
	    reply[10] < 2) ||
	    ((reply[11] & IPC_SECURITY_INFO_F_AUTHENTICATED) != 0 &&
	    reply[10] < 3) ||
	    ((reply[11] & IPC_SECURITY_INFO_F_SC) != 0 && reply[10] != 4)) {
		ble_set_error(ctx, BLE_ERR_PROTO, "invalid security info");
		return (-1);
	}
	memset(out, 0, sizeof(*out));
	out->addr.addr_type = reply[2];
	memcpy(out->addr.addr, reply + 3, sizeof(out->addr.addr));
	out->key_size = reply[9];
	out->level = reply[10];
	out->encrypted = (reply[11] & IPC_SECURITY_INFO_F_ENCRYPTED) != 0;
	out->authenticated =
	    (reply[11] & IPC_SECURITY_INFO_F_AUTHENTICATED) != 0;
	out->secure_connections = (reply[11] & IPC_SECURITY_INFO_F_SC) != 0;
	out->bonded = (reply[11] & IPC_SECURITY_INFO_F_BONDED) != 0;
	return (0);
}

/*
 * ============================================================
 * OOB pairing data
 * ============================================================
 */

int
ble_oob_sc_generate(ble_ctx_t *ctx, ble_oob_sc_t *out)
{
	uint8_t request[IPC_SECURITY_REQ_SIZE];
	uint8_t reply[IPC_SECURITY_OOB_REPLY_SIZE];
	size_t reply_len;

	ble_clear_error(ctx);
	if (out == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "null out");
		return (-1);
	}
	ble_security_req_encode(request, IPC_SECURITY_OOB_GENERATE, NULL);
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_OOB_GENERATE, request, sizeof(request), reply,
	    sizeof(reply), &reply_len) < 0)
		return (-1);
	if (reply_len != sizeof(reply) ||
	    ipc_get_le16(reply) != IPC_SECURITY_OOB_GENERATE) {
		ble_set_error(ctx, BLE_ERR_PROTO, "invalid OOB reply");
		return (-1);
	}
	memcpy(out->confirm, reply + 2, sizeof(out->confirm));
	memcpy(out->random, reply + 18, sizeof(out->random));
	memcpy(out->pkx, reply + 34, sizeof(out->pkx));
	return (0);
}

int
ble_oob_inject_sc(ble_ctx_t *ctx, const ble_addr_t *addr,
    const uint8_t confirm[16], const uint8_t random[16])
{
	uint8_t payload[IPC_SECURITY_OOB_SC_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || confirm == NULL || random == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "null argument");
		return (-1);
	}
	ble_security_req_encode(payload, IPC_SECURITY_OOB_INJECT_SC, addr);
	memcpy(payload + 12, confirm, 16);
	memcpy(payload + 28, random, 16);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_OOB_INJECT_SC, payload, sizeof(payload), NULL,
	    NULL, NULL));
}

int
ble_oob_inject_legacy(ble_ctx_t *ctx, const ble_addr_t *addr,
    const uint8_t tk[16])
{
	uint8_t payload[IPC_SECURITY_OOB_LEGACY_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr) || tk == NULL) {
		ble_set_error(ctx, BLE_ERR_INVAL, "null argument");
		return (-1);
	}
	ble_security_req_encode(payload, IPC_SECURITY_OOB_INJECT_LEGACY, addr);
	memcpy(payload + 12, tk, 16);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_OOB_INJECT_LEGACY, payload, sizeof(payload), NULL,
	    NULL, NULL));
}

int
ble_oob_clear(ble_ctx_t *ctx, const ble_addr_t *addr)
{
	uint8_t payload[IPC_SECURITY_OOB_CLEAR_REQ_SIZE];

	ble_clear_error(ctx);
	if (addr != NULL && !ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid address");
		return (-1);
	}
	ble_security_req_encode(payload, IPC_SECURITY_OOB_CLEAR, addr);
	payload[12] = addr == NULL ? IPC_SECURITY_OOB_CLEAR_F_ALL : 0;
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_OOB_CLEAR, payload, sizeof(payload), NULL, NULL,
	    NULL));
}

/*
 * ============================================================
 * LE privacy resolving-list management
 * ============================================================
 */

int
ble_resolv_add(ble_ctx_t *ctx, const ble_addr_t *addr, const uint8_t irk[16])
{
	uint8_t payload[IPC_SECURITY_RESOLV_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "null address");
		return (-1);
	}
	memset(payload, 0, sizeof(payload));
	ble_security_req_encode(payload, IPC_SECURITY_RESOLV_ADD, addr);
	if (irk != NULL) {
		payload[12] = IPC_SECURITY_RESOLV_F_IRK;
		memcpy(payload + 16, irk, 16);
	}
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_RESOLV_ADD, payload, sizeof(payload), NULL, NULL,
	    NULL));
}

int
ble_resolv_remove(ble_ctx_t *ctx, const ble_addr_t *addr)
{
	uint8_t payload[IPC_SECURITY_RESOLV_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "null address");
		return (-1);
	}
	memset(payload, 0, sizeof(payload));
	ble_security_req_encode(payload, IPC_SECURITY_RESOLV_REMOVE, addr);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_RESOLV_REMOVE, payload, sizeof(payload), NULL,
	    NULL, NULL));
}

int
ble_resolv_clear(ble_ctx_t *ctx)
{
	uint8_t payload[IPC_SECURITY_RESOLV_REQ_SIZE];

	ble_clear_error(ctx);
	memset(payload, 0, sizeof(payload));
	ble_security_req_encode(payload, IPC_SECURITY_RESOLV_CLEAR, NULL);
	return (ble_send_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_RESOLV_CLEAR, payload, sizeof(payload), NULL,
	    NULL, NULL));
}

int
ble_resolv_entries(ble_ctx_t *ctx, ble_resolv_entry_t *entries,
    int max_entries)
{
	uint8_t request[IPC_SECURITY_REQ_SIZE];
	uint8_t reply[IPC_SECURITY_RESOLV_REPLY_HDR_SIZE + BLE_MAX_BONDS *
	    IPC_SECURITY_RESOLV_RECORD_SIZE];
	size_t reply_len;
	uint16_t count;

	ble_clear_error(ctx);
	if (entries == NULL || max_entries <= 0) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid arguments");
		return (-1);
	}
	ble_security_req_encode(request, IPC_SECURITY_RESOLV_LIST, NULL);
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_RESOLV_LIST, request, sizeof(request), reply,
	    sizeof(reply), &reply_len) < 0)
		return (-1);
	if (reply_len < IPC_SECURITY_RESOLV_REPLY_HDR_SIZE ||
	    ipc_get_le16(reply) != IPC_SECURITY_RESOLV_LIST ||
	    (count = ipc_get_le16(reply + 2)) > BLE_MAX_BONDS ||
	    reply_len != IPC_SECURITY_RESOLV_REPLY_HDR_SIZE + count *
	    IPC_SECURITY_RESOLV_RECORD_SIZE) {
		ble_set_error(ctx, BLE_ERR_PROTO, "invalid resolving snapshot");
		return (-1);
	}
	if (count > (uint16_t)max_entries)
		count = (uint16_t)max_entries;
	for (uint16_t i = 0; i < count; i++) {
		const uint8_t *record = reply +
		    IPC_SECURITY_RESOLV_REPLY_HDR_SIZE + i *
		    IPC_SECURITY_RESOLV_RECORD_SIZE;

		if (record[0] > 1 ||
		    (record[7] & ~IPC_SECURITY_RESOLV_F_IN_LIST) != 0) {
			ble_set_error(ctx, BLE_ERR_PROTO,
			    "invalid resolving record");
			return (-1);
		}
		entries[i].addr.addr_type = record[0];
		memcpy(entries[i].addr.addr, record + 1, 6);
		entries[i].in_controller =
		    (record[7] & IPC_SECURITY_RESOLV_F_IN_LIST) != 0;
	}
	return ((int)count);
}

void
ble_on_keypress(ble_ctx_t *ctx, ble_keypress_cb cb, void *arg)
{

	ctx->keypress_cb = cb;
	ctx->keypress_arg = arg;
}

/*
 * Bond backup / restore / migration (PC4).
 *
 * The opaque record keeps the daemon's binary export blob.
 */
struct ble_bond_record {
	uint8_t	*data;
	size_t	 len;
};

ble_bond_record_t *
ble_bond_export(ble_ctx_t *ctx, const ble_addr_t *addr)
{
	ble_bond_record_t *rec;
	uint8_t request[IPC_SECURITY_REQ_SIZE];
	uint8_t reply[IPC_MAX_PAYLOAD];
	size_t reply_len, record_len;

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid arguments");
		return (NULL);
	}
	ble_security_req_encode(request, IPC_SECURITY_BOND_EXPORT, addr);
	if (ble_sync_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_BOND_EXPORT, request, sizeof(request), reply,
	    sizeof(reply), &reply_len) < 0)
		return (NULL);
	if (reply_len < IPC_SECURITY_BOND_EXPORT_REPLY_HDR_SIZE ||
	    ipc_get_le16(reply) != IPC_SECURITY_BOND_EXPORT ||
	    (record_len = ipc_get_le16(reply + 2)) == 0 ||
	    reply_len != IPC_SECURITY_BOND_EXPORT_REPLY_HDR_SIZE +
	    record_len || record_len > UINT16_MAX) {
		ble_set_error(ctx, BLE_ERR_PROTO, "invalid bond export");
		explicit_bzero(reply, sizeof(reply));
		return (NULL);
	}
	rec = calloc(1, sizeof(*rec));
	if (rec == NULL || (rec->data = malloc(record_len)) == NULL) {
		ble_bond_record_free(rec);
		explicit_bzero(reply, sizeof(reply));
		ble_set_error(ctx, BLE_ERR_NOMEM, "out of memory");
		return (NULL);
	}
	rec->len = record_len;
	memcpy(rec->data, reply + IPC_SECURITY_BOND_EXPORT_REPLY_HDR_SIZE,
	    record_len);
	explicit_bzero(reply, sizeof(reply));
	return (rec);
}

int
ble_bond_import(ble_ctx_t *ctx, const ble_bond_record_t *rec)
{
	uint8_t *request;
	size_t request_len;
	int rc;

	ble_clear_error(ctx);
	if (rec == NULL || rec->data == NULL || rec->len == 0 ||
	    rec->len > UINT16_MAX) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid record");
		return (-1);
	}
	request_len = IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE + rec->len;
	if (request_len > IPC_MAX_PAYLOAD) {
		ble_set_error(ctx, BLE_ERR_INVAL, "record is too large");
		return (-1);
	}
	request = calloc(1, request_len);
	if (request == NULL) {
		ble_set_error(ctx, BLE_ERR_NOMEM, "out of memory");
		return (-1);
	}
	ipc_put_le16(request, IPC_SECURITY_BOND_IMPORT);
	ipc_put_le16(request + 12, (uint16_t)rec->len);
	memcpy(request + IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE, rec->data,
	    rec->len);
	rc = ble_sync_operation(ctx, IPC_OP_DOMAIN_SECURITY,
	    IPC_SECURITY_BOND_IMPORT, request, request_len, NULL, 0, NULL);
	explicit_bzero(request, request_len);
	free(request);
	return (rc);
}

const void *
ble_bond_record_data(const ble_bond_record_t *rec, size_t *len)
{

	if (len != NULL)
		*len = rec != NULL ? rec->len : 0;
	return (rec != NULL ? rec->data : NULL);
}

ble_bond_record_t *
ble_bond_record_from_data(const void *data, size_t len)
{
	ble_bond_record_t *rec;

	if (data == NULL || len == 0 ||
	    len > IPC_MAX_PAYLOAD - IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE)
		return (NULL);
	rec = calloc(1, sizeof(*rec));
	if (rec == NULL)
		return (NULL);
	rec->data = malloc(len);
	if (rec->data == NULL) {
		free(rec);
		return (NULL);
	}
	memcpy(rec->data, data, len);
	rec->len = len;
	return (rec);
}

void
ble_bond_record_free(ble_bond_record_t *rec)
{

	if (rec == NULL)
		return;
	if (rec->data != NULL) {
		explicit_bzero(rec->data, rec->len);
		free(rec->data);
	}
	free(rec);
}

/*
 * PHY management
 */

int
ble_set_phy(ble_ctx_t *ctx, const ble_addr_t *addr, uint8_t tx_phys,
    uint8_t rx_phys)
{
	uint8_t payload[IPC_GAP_PHY_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	if ((tx_phys & ~0x07) != 0 || (rx_phys & ~0x07) != 0) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid PHY mask");
		return (-1);
	}
	ipc_gap_req_encode(payload, IPC_GAP_SET_PHY, 0, addr->addr_type,
	    addr->addr, addr->adapter_index);
	payload[12] = tx_phys;
	payload[13] = rx_phys;
	if (ble_send_operation(ctx, IPC_OP_DOMAIN_GAP, IPC_GAP_SET_PHY,
	    payload, sizeof(payload), NULL, NULL, NULL) == 0)
		return (0);
	ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
	return (-1);
}

int
ble_set_data_length(ble_ctx_t *ctx, const ble_addr_t *addr, uint16_t tx_octets,
    uint16_t tx_time)
{
	uint8_t payload[IPC_GAP_DATA_LEN_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	if (tx_octets < 0x001B || tx_octets > 0x00FB ||
	    tx_time < 0x0148 || tx_time > 0x4290) {
		ble_set_error(ctx, BLE_ERR_INVAL, "data length out of range");
		return (-1);
	}
	ipc_gap_req_encode(payload, IPC_GAP_SET_DATA_LEN, 0,
	    addr->addr_type, addr->addr, addr->adapter_index);
	ipc_put_le16(payload + 12, tx_octets);
	ipc_put_le16(payload + 14, tx_time);
	if (ble_send_operation(ctx, IPC_OP_DOMAIN_GAP,
	    IPC_GAP_SET_DATA_LEN, payload, sizeof(payload), NULL, NULL,
	    NULL) == 0)
		return (0);
	ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
	return (-1);
}

/*
 * Connection parameters
 */

int
ble_conn_params_update(ble_ctx_t *ctx, const ble_addr_t *addr,
    uint16_t interval_min, uint16_t interval_max, uint16_t latency,
    uint16_t timeout)
{
	uint8_t payload[IPC_GAP_CONN_UPDATE_REQ_SIZE];

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-1);
	}
	if (interval_min < 0x0006 || interval_min > 0x0c80 ||
	    interval_max < 0x0006 || interval_max > 0x0c80 ||
	    interval_min > interval_max || latency > 0x01f3 ||
	    timeout < 0x000a || timeout > 0x0c80 ||
	    (uint32_t)timeout * 4 <=
	    (uint32_t)interval_max * (1 + (uint32_t)latency)) {
		ble_set_error(ctx, BLE_ERR_INVAL,
		    "invalid connection parameters");
		return (-1);
	}
	ipc_gap_req_encode(payload, IPC_GAP_CONN_UPDATE, 0,
	    addr->addr_type, addr->addr, addr->adapter_index);
	ipc_put_le16(payload + 12, interval_min);
	ipc_put_le16(payload + 14, interval_max);
	ipc_put_le16(payload + 16, latency);
	ipc_put_le16(payload + 18, timeout);
	if (ble_send_operation(ctx, IPC_OP_DOMAIN_GAP,
	    IPC_GAP_CONN_UPDATE, payload, sizeof(payload), NULL, NULL,
	    NULL) == 0)
		return (0);
	ble_set_error(ctx, BLE_ERR_SOCKET, "send failed");
	return (-1);
}

int
ble_get_rssi(ble_ctx_t *ctx, const ble_addr_t *addr)
{

	ble_clear_error(ctx);
	if (!ble_addr_valid(addr)) {
		ble_set_error(ctx, BLE_ERR_INVAL, "invalid argument");
		return (-127);
	}
	if (ctx->rssi_valid &&
	    memcmp(ctx->rssi_addr.addr, addr->addr, 6) == 0)
		return (ctx->rssi_value);
	return (-127);
}

/*
 * Convenience — client-side profile helpers.
 *
 * These chain generic GATT operations (DISCOVER + READ/SUBSCRIBE)
 * to provide higher-level profile access without daemon-side
 * profile knowledge.
 */

/*
 * Internal callback for ble_read_battery(): invoked when DISCOVER
 * completes, searches for Battery Level, issues READ.
 */
struct ble_battery_op {
	ble_ctx_t	*ctx;
	ble_read_cb	cb;
	void		*arg;
};

static void
battery_discover_done(const ble_addr_t *addr,
    const ble_service_t *svcs, int nsvc,
    const ble_characteristic_t *chars, int nchar, void *arg)
{
	struct ble_battery_op *op = arg;
	int i;

	(void)svcs;
	(void)nsvc;

	for (i = 0; i < nchar; i++) {
		if (chars[i].uuid.uuid16 == BLE_CHR_BATTERY_LEVEL) {
			if (ble_read(op->ctx, addr, chars[i].handle,
			    op->cb, op->arg) < 0 && op->cb != NULL)
				op->cb(addr, 0, NULL, 0, -1, op->arg);
			free(op);
			return;
		}
	}

	/* Not found — report error */
	if (op->cb != NULL)
		op->cb(addr, 0, NULL, 0, -1, op->arg);
	free(op);
}

int
ble_read_battery(ble_ctx_t *ctx, const ble_addr_t *addr,
    ble_read_cb cb, void *arg)
{
	struct ble_battery_op *op;

	if (ctx == NULL || !ble_addr_valid(addr))
		return (-1);
	op = calloc(1, sizeof(*op));
	if (op == NULL)
		return (-1);
	op->ctx = ctx;
	op->cb = cb;
	op->arg = arg;

	/* Start discovery — battery_discover_done chains the READ */
	if (ble_discover(ctx, addr, battery_discover_done, op) == 0)
		return (0);
	free(op);
	return (-1);
}
