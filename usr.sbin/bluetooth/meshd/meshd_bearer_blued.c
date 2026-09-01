/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * meshd's radio bearer: a small privileged client of blued's mesh-bearer
 * control-socket API.  See meshd_bearer_blued.h for the model.  Both daemons
 * use the shared ipc_proto.h contract for framing and typed payloads.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "meshd_bearer_blued.h"
#include "meshd_persist.h"
#include "ipc_proto.h"

/*
 * Largest mesh AD payload across the three types (Net PDU = 29 octets).  Must
 * match blued's MESH_ADV_PDU_MAX (29): blued rejects a longer payload with
 * IPC_ERR_INVAL, and the ADV_SEND is fire-and-forget, so a 30-31 byte PDU
 * accepted here would be silently dropped by blued while we counted it sent.
 */
#define	MBW_ADV_MAX		29u

/* Reconnect backoff ceiling (seconds); the 1 s tick drives the retry clock. */
#define	MBW_BACKOFF_MAX		30u
#define	MBW_MSEC_PER_SEC	1000u
#define	MBW_HELLO_TIMEOUT_SEC	5

static void mbw_retry_failed(struct meshd_blued *);

static uint64_t
mbw_now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (0);
	return ((uint64_t)ts.tv_sec * MBW_MSEC_PER_SEC +
	    (uint64_t)ts.tv_nsec / 1000000u);
}

static int
mbw_ready(const struct meshd_blued *bc)
{

	return (bc != NULL && bc->fd >= 0 &&
	    (bc->state == MESHD_BLUED_READY ||
	    (bc->state == MESHD_BLUED_DOWN && bc->handshake_deadline == 0)));
}

/* ---- little-endian header encode/decode (host-endian independent) ---- */

static void
mbw_transport_failed(struct meshd_blued *bc, struct meshd_node *nd)
{

	if (bc == NULL)
		return;
	if (nd == NULL)
		nd = bc->node;
	if (nd != NULL) {
		meshd_proxy_gatt_cancel(nd, NULL, 0, 0);
		/*
		 * Do not cancel a PB-GATT provisioning that has already
		 * completed: the pump can process the Complete frame (driving the
		 * session to DONE) and then see transport EOF in the same drain,
		 * before the event-loop tick commits it.  A DONE session needs no
		 * further bearer I/O, so leave it for the tick to commit -- the
		 * two deliberate teardown paths guard this call the same way
		 * (NB-23).
		 */
		if (!meshd_pbgatt_done(nd))
			meshd_pbgatt_cancel(nd);
	}
	meshd_blued_close(bc);
	mbw_retry_failed(bc);
}

static int
mbw_deadline_remaining(const struct timespec *deadline)
{
	struct timespec now;
	int64_t ms;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return (-1);
	ms = (int64_t)(deadline->tv_sec - now.tv_sec) * 1000 +
	    (deadline->tv_nsec - now.tv_nsec + 999999) / 1000000;
	if (ms <= 0) {
		errno = ETIMEDOUT;
		return (-1);
	}
	return ((int)MIN(ms, INT_MAX));
}

static int
mbw_wait_deadline(int fd, short events, const struct timespec *deadline)
{
	struct pollfd pfd;
	int timeout, rc;

	for (;;) {
		timeout = mbw_deadline_remaining(deadline);
		if (timeout < 0)
			return (-1);
		memset(&pfd, 0, sizeof(pfd));
		pfd.fd = fd;
		pfd.events = events;
		rc = poll(&pfd, 1, timeout);
		if (rc > 0) {
			if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 &&
			    (pfd.revents & events) == 0) {
				errno = ECONNRESET;
				return (-1);
			}
			return (0);
		}
		if (rc == 0) {
			errno = ETIMEDOUT;
			return (-1);
		}
		if (errno != EINTR)
			return (-1);
	}
}

/* Write exactly n bytes before one absolute attach deadline. */
static int
mbw_write_all(int fd, const uint8_t *buf, size_t n,
    const struct timespec *deadline)
{
	size_t off = 0;

	while (off < n) {
		ssize_t w = send(fd, buf + off, n - off, MSG_NOSIGNAL);

		if (w > 0) {
			off += (size_t)w;
			continue;
		}
		if (w < 0 && errno == EINTR)
			continue;
		if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			if (mbw_wait_deadline(fd, POLLOUT, deadline) == 0)
				continue;
		}
		return (-1);
	}
	return (0);
}

/* Drain queued complete frames.  EAGAIN leaves the remainder queued. */
int
meshd_blued_flush(struct meshd_blued *bc)
{
	ssize_t w;
	int error = 0;
	uint64_t now;

	if (bc == NULL || bc->fd < 0)
		return (-1);
	now = mbw_now();
	if (bc->state != MESHD_BLUED_READY &&
	    bc->handshake_deadline != 0 && now != 0 &&
	    now >= bc->handshake_deadline) {
		errno = ETIMEDOUT;
		mbw_transport_failed(bc, NULL);
		return (-1);
	}
	if (bc->state == MESHD_BLUED_CONNECTING) {
		socklen_t errorlen = sizeof(error);

		if (getsockopt(bc->fd, SOL_SOCKET, SO_ERROR, &error, &errorlen) != 0 ||
		    error != 0) {
			if (error != 0)
				errno = error;
			mbw_transport_failed(bc, NULL);
			return (-1);
		}
		bc->state = MESHD_BLUED_HELLO;
	}
	while (bc->txoff < bc->txlen) {
		w = send(bc->fd, bc->tx + bc->txoff, bc->txlen - bc->txoff,
		    MSG_NOSIGNAL);
		if (w > 0) {
			bc->txoff += (size_t)w;
			continue;
		}
		if (w < 0 && errno == EINTR)
			continue;
		if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return (0);
		mbw_transport_failed(bc, NULL);
		return (-1);
	}
	bc->txoff = bc->txlen = 0;
	if (mbw_ready(bc) && bc->pbgatt_pending &&
	    !bc->pbgatt_draining && bc->node != NULL)
		(void)meshd_blued_pbgatt_drain(bc, bc->node);
	return (0);
}

int
meshd_blued_wants_write(const struct meshd_blued *bc)
{

	return (bc != NULL && bc->fd >= 0 &&
	    (bc->state == MESHD_BLUED_CONNECTING || bc->txoff < bc->txlen));
}

/* Read exactly n bytes before one absolute attach deadline. */
static int
mbw_read_all(int fd, uint8_t *buf, size_t n,
    const struct timespec *deadline)
{
	size_t off = 0;

	while (off < n) {
		ssize_t r = read(fd, buf + off, n - off);

		if (r > 0) {
			off += (size_t)r;
			continue;
		}
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			if (mbw_wait_deadline(fd, POLLIN, deadline) == 0)
				continue;
		}
		return (-1);		/* error or EOF before n bytes */
	}
	return (0);
}

/* Frame and send one control message.  Returns 0 / -1. */
static int
mbw_send_frame(int fd, uint16_t type, uint16_t arg, const void *payload,
    size_t plen, const struct timespec *deadline)
{
	uint8_t hdr[IPC_HDR_SIZE];

	if (plen > IPC_MAX_PAYLOAD)
		return (-1);
	ipc_hdr_encode(hdr, (uint32_t)plen, type, arg);
	if (mbw_write_all(fd, hdr, sizeof(hdr), deadline) != 0)
		return (-1);
	if (plen != 0 && mbw_write_all(fd, payload, plen, deadline) != 0)
		return (-1);
	return (0);
}

static int
mbw_queue_frame(struct meshd_blued *bc, uint16_t type, uint16_t arg,
    const void *payload, size_t plen)
{
	uint8_t hdr[IPC_HDR_SIZE];
	size_t framelen, pending;

	if (bc == NULL || bc->fd < 0 || plen > IPC_MAX_PAYLOAD)
		return (-1);
	framelen = IPC_HDR_SIZE + plen;
	pending = bc->txlen - bc->txoff;
	if (framelen > sizeof(bc->tx) - pending) {
		errno = ENOBUFS;
		return (-1);
	}
	if (pending != 0 && bc->txoff != 0)
		memmove(bc->tx, bc->tx + bc->txoff, pending);
	bc->txoff = 0;
	bc->txlen = pending;
	ipc_hdr_encode(hdr, (uint32_t)plen, type, arg);
	memcpy(bc->tx + bc->txlen, hdr, sizeof(hdr));
	bc->txlen += sizeof(hdr);
	if (plen != 0) {
		memcpy(bc->tx + bc->txlen, payload, plen);
		bc->txlen += plen;
	}
	if (bc->state == MESHD_BLUED_CONNECTING)
		return (0);
	return (meshd_blued_flush(bc));
}

static int
mbw_send_operation(struct meshd_blued *bc, uint16_t domain,
    const void *body, size_t body_len, uint32_t *request_id)
{
	uint8_t payload[IPC_MAX_PAYLOAD];
	uint32_t id;

	if (!mbw_ready(bc) || body_len > sizeof(payload) -
	    IPC_OP_PREFIX_SIZE)
		return (-1);
	id = ++bc->next_request_id;
	if (id == 0)
		id = ++bc->next_request_id;
	ipc_op_prefix_encode(payload, id, IPC_ERR_NONE, 0);
	memcpy(payload + IPC_OP_PREFIX_SIZE, body, body_len);
	if (mbw_queue_frame(bc, IPC_T_OP_REQ, domain, payload,
	    IPC_OP_PREFIX_SIZE + body_len) != 0)
		return (-1);
	if (request_id != NULL)
		*request_id = id;
	return (0);
}

static int
mbw_reserve_operations(struct meshd_blued *bc, size_t bytes)
{
	size_t pending;

	if (!mbw_ready(bc))
		return (-1);
	pending = bc->txlen - bc->txoff;
	if (bytes > sizeof(bc->tx) - pending) {
		errno = ENOBUFS;
		return (-1);
	}
	return (0);
}

/*
 * Reserve both queue space and correlation records for one complete Proxy
 * message.  A zero request_id denotes a record reserved by the current call
 * but not yet assigned to an operation.  Nothing is changed on failure.
 */
static int
mbw_write_reserve(struct meshd_blued *bc, size_t bytes, uint8_t kind,
    uint8_t proxy_index, size_t count, size_t *slots)
{
	size_t found, i;

	if (bc == NULL || slots == NULL || count == 0 ||
	    (kind != MESHD_BLUED_WRITE_PROXY &&
	    kind != MESHD_BLUED_WRITE_PBGATT) ||
	    mbw_reserve_operations(bc, bytes) != 0)
		return (-1);
	for (found = i = 0; i < MESHD_BLUED_MAX_WRITES && found < count; i++)
		if (bc->writes[i].kind == 0)
			slots[found++] = i;
	if (found != count) {
		errno = ENOBUFS;
		return (-1);
	}
	for (i = 0; i < count; i++) {
		bc->writes[slots[i]].request_id = 0;
		bc->writes[slots[i]].kind = kind;
		bc->writes[slots[i]].proxy_index = proxy_index;
		bc->writes[slots[i]].generation = kind == MESHD_BLUED_WRITE_PBGATT ?
		    bc->pbgatt_generation : 0;
	}
	return (0);
}

static void
mbw_write_release(struct meshd_blued *bc, const size_t *slots, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		memset(&bc->writes[slots[i]], 0, sizeof(bc->writes[slots[i]]));
}

static struct meshd_blued_write *
mbw_write_request(struct meshd_blued *bc, uint32_t request_id)
{
	size_t i;

	if (request_id == 0)
		return (NULL);
	for (i = 0; i < MESHD_BLUED_MAX_WRITES; i++)
		if (bc->writes[i].kind != 0 &&
		    bc->writes[i].request_id == request_id)
			return (&bc->writes[i]);
	return (NULL);
}

static void
mbw_write_clear_owner(struct meshd_blued *bc, uint8_t kind,
    uint8_t proxy_index)
{
	size_t i;

	for (i = 0; i < MESHD_BLUED_MAX_WRITES; i++)
		if (bc->writes[i].kind == kind && (kind != MESHD_BLUED_WRITE_PROXY ||
		    bc->writes[i].proxy_index == proxy_index))
			memset(&bc->writes[i], 0, sizeof(bc->writes[i]));
}

/* ================================================================
 * Connection lifecycle.
 * ================================================================ */

void
meshd_blued_init(struct meshd_blued *bc, const char *sockpath)
{
	if (bc == NULL)
		return;
	memset(bc, 0, sizeof(*bc));
	bc->fd = -1;
	bc->state = MESHD_BLUED_DOWN;
	if (sockpath != NULL &&
	    strlcpy(bc->sockpath, sockpath, sizeof(bc->sockpath)) >=
	    sizeof(bc->sockpath))
		bc->sockpath[0] = '\0';
}

void
meshd_blued_bind_node(struct meshd_blued *bc, struct meshd_node *nd)
{

	if (bc != NULL)
		bc->node = nd;
}

void
meshd_blued_close(struct meshd_blued *bc)
{
	if (bc == NULL)
		return;
	if (bc->fd >= 0)
		(void)close(bc->fd);
	bc->fd = -1;
	bc->state = MESHD_BLUED_DOWN;
	bc->rxn = 0;
	bc->txoff = bc->txlen = 0;
	bc->gatt_addr[0] = '\0';
	bc->gatt_addr_type = 0;
	bc->gatt_adapter_index = IPC_MESH_ADAPTER_DEFAULT;
	bc->gatt_mtu = 0;
	bc->gatt_data_in = 0;
	bc->gatt_data_out = 0;
	bc->gatt_discovering = 0;
	bc->gatt_subscribing = 0;
	bc->gatt_subscribed = 0;
	bc->gatt_in_service = 0;
	bc->gatt_mesh_type = MESHD_GATT_NONE;
	bc->discover_request_id = 0;
	bc->subscribe_request_id = 0;
	bc->handshake_deadline = 0;
	bc->handshake_request_id = 0;
	bc->pbgatt_pending = 0;
	bc->pbgatt_draining = 0;
	memset(bc->proxy, 0, sizeof(bc->proxy));
	memset(bc->peers, 0, sizeof(bc->peers));
	memset(bc->writes, 0, sizeof(bc->writes));
}

int
meshd_blued_fd(const struct meshd_blued *bc)
{
	return (bc != NULL ? bc->fd : -1);
}

uint64_t
meshd_blued_generation(const struct meshd_blued *bc)
{

	return (bc != NULL ? bc->generation : 0);
}

int
meshd_blued_attach(struct meshd_blued *bc, int fd)
{
	uint8_t hdr[IPC_HDR_SIZE];
	uint8_t features[IPC_HELLO_FEATURES_SIZE];
	uint8_t request[IPC_MESH_REQ_SIZE];
	uint8_t payload[IPC_MAX_PAYLOAD];
	uint32_t plen, request_id, reply_id;
	uint16_t status, reply_flags;
	uint16_t type, arg;
	int flags;
	struct timespec deadline;

	if (bc == NULL || bc->fd >= 0 || fd < 0)
		return (-1);

	/*
	 * Handshake (blocking): request mesh capability, validate the HELLO reply,
	 * then subscribe.  Attachment is not complete until the correlated
	 * subscription ACK has arrived; otherwise callers could advertise through
	 * a socket on which inbound mesh reports were never enabled.
	 */
	/* One absolute deadline bounds the complete HELLO + subscription exchange. */
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
		goto fail;
	deadline.tv_sec += MBW_HELLO_TIMEOUT_SEC;
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		goto fail;
	ipc_put_le32(features, IPC_FEATURE_MESH);
	if (mbw_send_frame(fd, IPC_T_HELLO, IPC_PROTO_VERSION,
	    features, sizeof(features), &deadline) != 0)
		goto fail;
	if (mbw_read_all(fd, hdr, sizeof(hdr), &deadline) != 0)
		goto fail;
	ipc_hdr_decode(hdr, &plen, &type, &arg);
	(void)arg;
	if (plen != IPC_HELLO_FEATURES_SIZE)
		goto fail;
	if (mbw_read_all(fd, features, sizeof(features), &deadline) != 0)
		goto fail;
	if (type != IPC_T_HELLO || arg != IPC_PROTO_VERSION)
		goto fail;
	if ((ipc_get_le32(features) &
	    (IPC_FEATURE_MESH | IPC_FEATURE_EVENTS)) !=
	    (IPC_FEATURE_MESH | IPC_FEATURE_EVENTS))
		goto fail;
	memset(request, 0, sizeof(request));
	ipc_put_le16(request, IPC_MESH_SUBSCRIBE);
	request_id = ++bc->next_request_id;
	if (request_id == 0)
		request_id = ++bc->next_request_id;
	ipc_op_prefix_encode(payload, request_id, IPC_ERR_NONE, 0);
	memcpy(payload + IPC_OP_PREFIX_SIZE, request, sizeof(request));
	if (mbw_send_frame(fd, IPC_T_OP_REQ, IPC_OP_DOMAIN_MESH, payload,
	    IPC_OP_PREFIX_SIZE + sizeof(request), &deadline) != 0)
		goto fail;

	/* Events may race the ACK.  Retain them verbatim for the normal pump. */
	for (;;) {
		if (mbw_read_all(fd, hdr, sizeof(hdr), &deadline) != 0)
			goto fail;
		ipc_hdr_decode(hdr, &plen, &type, &arg);
		if (plen > IPC_MAX_PAYLOAD ||
		    mbw_read_all(fd, payload, plen, &deadline) != 0)
			goto fail;
		if (type == IPC_T_OP_EVENT && plen >= IPC_OP_PREFIX_SIZE + 2) {
			ipc_op_prefix_decode(payload, &reply_id, &status,
			    &reply_flags);
			if (status != IPC_ERR_NONE || reply_flags != 0 ||
			    (arg != IPC_OP_DOMAIN_MESH && arg != IPC_OP_DOMAIN_GAP &&
			    arg != IPC_OP_DOMAIN_GATT))
				goto fail;
			if (IPC_HDR_SIZE + plen > sizeof(bc->rx) - bc->rxn)
				goto fail;
			memcpy(bc->rx + bc->rxn, hdr, sizeof(hdr));
			bc->rxn += sizeof(hdr);
			memcpy(bc->rx + bc->rxn, payload, plen);
			bc->rxn += plen;
			continue;
		}
		if (type != IPC_T_OP_REPLY || arg != IPC_OP_DOMAIN_MESH ||
		    plen != IPC_OP_PREFIX_SIZE)
			goto fail;
		ipc_op_prefix_decode(payload, &reply_id, &status, &reply_flags);
		if (reply_id != request_id || status != IPC_ERR_NONE ||
		    reply_flags != 0)
			goto fail;
		break;
	}

	if (++bc->generation == 0)
		++bc->generation;
	bc->fd = fd;
	bc->state = MESHD_BLUED_READY;
	bc->backoff = 0;
	return (0);
fail:
	(void)close(fd);
	bc->fd = -1;
	bc->state = MESHD_BLUED_DOWN;
	bc->rxn = 0;
	bc->txoff = bc->txlen = 0;
	memset(bc->writes, 0, sizeof(bc->writes));
	return (-1);
}

int
meshd_blued_connect(struct meshd_blued *bc)
{
	struct sockaddr_un sun;
	uint8_t features[IPC_HELLO_FEATURES_SIZE];
	int fd, flags, rc;
	uint64_t now;

	if (bc == NULL || bc->fd >= 0 || bc->sockpath[0] == '\0')
		return (-1);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return (-1);
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		(void)close(fd);
		return (-1);
	}
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	(void)strlcpy(sun.sun_path, bc->sockpath, sizeof(sun.sun_path));
	rc = connect(fd, (struct sockaddr *)&sun, sizeof(sun));
	if (rc < 0 && errno != EINPROGRESS) {
		(void)close(fd);
		return (-1);
	}
	now = mbw_now();
	if (now == 0) {
		(void)close(fd);
		return (-1);
	}
	if (++bc->generation == 0)
		++bc->generation;
	bc->fd = fd;
	bc->state = rc == 0 ? MESHD_BLUED_HELLO : MESHD_BLUED_CONNECTING;
	bc->handshake_deadline = now + MBW_HELLO_TIMEOUT_SEC *
	    MBW_MSEC_PER_SEC;
	bc->rxn = 0;
	bc->txoff = bc->txlen = 0;
	ipc_put_le32(features, IPC_FEATURE_MESH);
	if (mbw_queue_frame(bc, IPC_T_HELLO, IPC_PROTO_VERSION, features,
	    sizeof(features)) != 0) {
		meshd_blued_close(bc);
		return (-1);
	}
	return (0);
}

static void
mbw_retry_failed(struct meshd_blued *bc)
{
	uint64_t now;

	if (bc->backoff == 0)
		bc->backoff = 1;
	else if (bc->backoff >= MBW_BACKOFF_MAX / 2)
		bc->backoff = MBW_BACKOFF_MAX;
	else
		bc->backoff *= 2;
	now = mbw_now();
	bc->retry_at = now + (uint64_t)bc->backoff * MBW_MSEC_PER_SEC;
}

int
meshd_blued_maintain(struct meshd_blued *bc, uint64_t now)
{
	uint64_t current;

	if (bc == NULL)
		return (0);
	current = mbw_now();
	if (bc->fd >= 0) {
		if (!mbw_ready(bc) && bc->handshake_deadline != 0 && current != 0 &&
		    current >= bc->handshake_deadline) {
			mbw_transport_failed(bc, NULL);
			return (0);
		}
		if (mbw_ready(bc) && bc->pbgatt_pending &&
		    bc->node != NULL)
			(void)meshd_blued_pbgatt_drain(bc, bc->node);
		return (mbw_ready(bc));
	}
	if (cap_sandboxed())
		return (0);			/* reconnect needs socket/connect */
	if (now < bc->retry_at)
		return (0);			/* backoff window still open */

	if (meshd_blued_connect(bc) == 0)
		return (0);
	if (bc->retry_at <= current)
		mbw_retry_failed(bc);
	return (0);
}

/* ================================================================
 * Transmit sink (struct meshd_bearer.tx).
 * ================================================================ */

static struct meshd_blued_proxy_link *
mbw_proxy_link(struct meshd_blued *bc, const char *addr, uint8_t addr_type,
    uint8_t adapter_index)
{
	size_t i;

	if (bc == NULL || addr == NULL)
		return (NULL);
	for (i = 0; i < MESHD_MAX_PROXY_GATT; i++)
		if (bc->proxy[i].active &&
		    bc->proxy[i].addr_type == addr_type &&
		    bc->proxy[i].session_adapter_index == adapter_index &&
		    strcmp(bc->proxy[i].addr, addr) == 0)
			return (&bc->proxy[i]);
	return (NULL);
}

static struct meshd_blued_peer *
mbw_peer_exact(struct meshd_blued *bc, const bdaddr_t *addr,
    uint8_t addr_type, uint8_t adapter_index)
{
	size_t i;

	for (i = 0; i < MESHD_BLUED_MAX_PEERS; i++)
		if (bc->peers[i].active && bc->peers[i].addr_type == addr_type &&
		    bc->peers[i].adapter_index == adapter_index &&
		    memcmp(bc->peers[i].addr, addr, sizeof(*addr)) == 0)
			return (&bc->peers[i]);
	return (NULL);
}

/* Return the sole adapter carrying this identity, or NULL if absent/ambiguous. */
static struct meshd_blued_peer *
mbw_peer_unique(struct meshd_blued *bc, const bdaddr_t *addr,
    uint8_t addr_type)
{
	struct meshd_blued_peer *match = NULL;
	size_t i;

	for (i = 0; i < MESHD_BLUED_MAX_PEERS; i++) {
		if (!bc->peers[i].active || bc->peers[i].addr_type != addr_type ||
		    memcmp(bc->peers[i].addr, addr, sizeof(*addr)) != 0)
			continue;
		if (match != NULL)
			return (NULL);
		match = &bc->peers[i];
	}
	return (match);
}

static void
mbw_peer_connected(struct meshd_blued *bc, const bdaddr_t *addr,
    uint8_t addr_type, uint8_t adapter_index, uint16_t mtu)
{
	struct meshd_blued_peer *peer;
	size_t i;

	peer = mbw_peer_exact(bc, addr, addr_type, adapter_index);
	if (peer == NULL) {
		for (i = 0; i < MESHD_BLUED_MAX_PEERS; i++)
			if (!bc->peers[i].active) {
				peer = &bc->peers[i];
				break;
			}
	}
	if (peer == NULL)
		return;
	memcpy(peer->addr, addr, sizeof(*addr));
	peer->addr_type = addr_type;
	peer->adapter_index = adapter_index;
	peer->mtu = mtu;
	peer->active = 1;
}

static void
mbw_peer_disconnected(struct meshd_blued *bc, const bdaddr_t *addr,
    uint8_t addr_type, uint8_t adapter_index)
{
	struct meshd_blued_peer *peer;

	peer = mbw_peer_exact(bc, addr, addr_type, adapter_index);
	if (peer != NULL)
		memset(peer, 0, sizeof(*peer));
}

static int
mbw_proxy_tx(struct meshd_blued *bc, struct meshd_blued_proxy_link *link,
    uint8_t type, const uint8_t *msg, size_t msglen)
{
	struct mesh_proxy_seg segs[4];
	uint8_t request[IPC_GATT_VALUE_REQ_SIZE + MESH_PROXY_MAX_PDU];
	bdaddr_t ba;
	size_t i, nseg, slots[4];
	size_t reserve = 0;
	uint32_t request_id;
	uint8_t proxy_index;

	if (link == NULL || !link->subscribed || link->data_in == 0 ||
	    link->mtu < MESHD_PBGATT_MIN_MTU || !bt_aton(link->addr, &ba) ||
	    mesh_proxy_segment(type, msg, msglen,
	    MIN((size_t)link->mtu - 3, (size_t)MESH_PROXY_MAX_PDU), segs,
	    sizeof(segs) / sizeof(segs[0]),
	    &nseg) != 0)
		return (-1);
	for (i = 0; i < nseg; i++)
		reserve += IPC_HDR_SIZE + IPC_OP_PREFIX_SIZE +
		    IPC_GATT_VALUE_REQ_SIZE + segs[i].len;
	proxy_index = (uint8_t)(link - bc->proxy);
	if (mbw_write_reserve(bc, reserve, MESHD_BLUED_WRITE_PROXY,
	    proxy_index, nseg, slots) != 0)
		return (-1);
	for (i = 0; i < nseg; i++) {
		memset(request, 0, IPC_GATT_VALUE_REQ_SIZE);
		ipc_put_le16(request, IPC_GATT_WRITE_CMD);
		request[4] = link->addr_type;
		memcpy(request + 5, &ba, sizeof(ba));
		request[11] = link->adapter_index;
		ipc_put_le16(request + 12, link->data_in);
		ipc_put_le16(request + 14, (uint16_t)segs[i].len);
		memcpy(request + IPC_GATT_VALUE_REQ_SIZE, segs[i].bytes,
		    segs[i].len);
		if (mbw_send_operation(bc, IPC_OP_DOMAIN_GATT, request,
		    IPC_GATT_VALUE_REQ_SIZE + segs[i].len, &request_id) != 0) {
			mbw_write_release(bc, slots + i, nseg - i);
			if (errno != ENOBUFS)
				meshd_blued_close(bc);
			return (-1);
		}
		bc->writes[slots[i]].request_id = request_id;
	}
	return (0);
}

int
meshd_blued_proxy_tx(void *arg, const char *addr, uint8_t addr_type,
    uint8_t adapter_index, uint8_t type, const uint8_t *pdu, size_t len)
{
	struct meshd_blued *bc = arg;

	if (!mbw_ready(bc) || pdu == NULL)
		return (-1);
	return (mbw_proxy_tx(bc, mbw_proxy_link(bc, addr, addr_type,
	    adapter_index), type,
	    pdu, len));
}

int
meshd_blued_tx(void *arg, enum meshd_pdu_class cls, const uint8_t *pdu,
    size_t len)
{
	struct meshd_blued *bc = arg;
	uint8_t request[IPC_MESH_ADV_REQ_HDR_SIZE + MBW_ADV_MAX];
	unsigned adtype;

	if (bc == NULL || pdu == NULL || len == 0)
		return (-1);
	if (!mbw_ready(bc))
		return (-1);			/* bearer down: outbound dropped */
	if (cls == MESHD_PDU_NET || cls == MESHD_PDU_BEACON) {
		size_t i;

		/*
		 * Push to every subscribed GATT proxy link.  A single link's
		 * failure (e.g. a stalled client returning ENOBUFS) must fail
		 * only its owning link, not abort delivery to the remaining
		 * proxy links or the radio ADV bearer below (finding 80).  A
		 * fatal per-link error already tears the link (or the whole
		 * bearer) down inside mbw_proxy_tx; if that dropped the bearer
		 * the ADV send below fails on its own.
		 */
		for (i = 0; i < MESHD_MAX_PROXY_GATT; i++)
			if (bc->proxy[i].active && bc->proxy[i].subscribed &&
			    bc->proxy[i].data_in != 0)
				(void)mbw_proxy_tx(bc, &bc->proxy[i],
				    cls == MESHD_PDU_NET ?
				    MESH_PROXY_TYPE_NETWORK :
				    MESH_PROXY_TYPE_BEACON, pdu, len);
		if (!mbw_ready(bc))
			return (-1);		/* a fatal proxy error closed us */
	}
	if (len > MBW_ADV_MAX)
		return (-1);			/* will not fit a legacy AD field */

	/* Map the PDU class to its wire AD type; reject anything else. */
	switch (cls) {
	case MESHD_PDU_NET:	adtype = 0x2A; break;
	case MESHD_PDU_BEACON:	adtype = 0x2B; break;
	case MESHD_PDU_PROV:	adtype = 0x29; break;
	default:		return (-1);
	}

	ipc_put_le16(request, IPC_MESH_ADV_SEND);
	request[2] = (uint8_t)adtype;
	request[3] = IPC_MESH_ADAPTER_DEFAULT;
	request[4] = (uint8_t)len;
	request[5] = 0;
	memcpy(request + IPC_MESH_ADV_REQ_HDR_SIZE, pdu, len);
	if (mbw_send_operation(bc, IPC_OP_DOMAIN_MESH, request,
	    IPC_MESH_ADV_REQ_HDR_SIZE + len, NULL) != 0) {
		/* Queue exhaustion drops this PDU, but the link is still usable. */
		if (errno != ENOBUFS)
			meshd_blued_close(bc);
		return (-1);
	}
	return (0);
}

int
meshd_blued_pbgatt_bind(struct meshd_blued *bc, const char *addr,
    uint8_t addr_type, uint16_t data_in, uint16_t data_out)
{
	uint8_t request[IPC_GATT_REQ_SIZE];
	bdaddr_t ba;

	if (!mbw_ready(bc) || addr == NULL || strlen(addr) != 17 ||
	    addr_type > MESHD_ADDR_RANDOM || data_in == 0 || data_out == 0 ||
	    !bt_aton(addr, &ba))
		return (-1);
	memset(request, 0, sizeof(request));
	ipc_put_le16(request, IPC_GATT_SUBSCRIBE);
	request[4] = addr_type;
	memcpy(request + 5, &ba, sizeof(ba));
	request[11] = bc->gatt_adapter_index;
	ipc_put_le16(request + 12, data_out);
	if (mbw_send_operation(bc, IPC_OP_DOMAIN_GATT, request,
	    sizeof(request), &bc->subscribe_request_id) != 0)
		return (-1);
	strlcpy(bc->gatt_addr, addr, sizeof(bc->gatt_addr));
	bc->gatt_addr_type = addr_type;
	bc->gatt_data_in = data_in;
	bc->gatt_data_out = data_out;
	bc->gatt_subscribing = 1;
	bc->gatt_subscribed = 0;
	return (0);
}

static int
mbw_pbgatt_discover(struct meshd_blued *bc, const char *addr,
    uint8_t addr_type, uint8_t adapter_index)
{
	uint8_t request[IPC_GATT_REQ_SIZE];
	bdaddr_t ba;
	struct meshd_blued_peer *peer;

	if (!mbw_ready(bc) || addr == NULL || strlen(addr) != 17 ||
	    addr_type > MESHD_ADDR_RANDOM ||
	    adapter_index > MESHD_ADAPTER_DEFAULT || !bt_aton(addr, &ba))
		return (-1);
	memset(request, 0, sizeof(request));
	ipc_put_le16(request, IPC_GATT_DISCOVER);
	request[4] = addr_type;
	memcpy(request + 5, &ba, sizeof(ba));
	peer = adapter_index == MESHD_ADAPTER_DEFAULT ?
	    mbw_peer_unique(bc, &ba, addr_type) :
	    mbw_peer_exact(bc, &ba, addr_type, adapter_index);
	bc->gatt_adapter_index = adapter_index != MESHD_ADAPTER_DEFAULT ?
	    adapter_index : peer != NULL ? peer->adapter_index :
	    IPC_MESH_ADAPTER_DEFAULT;
	bc->gatt_mtu = peer != NULL ? peer->mtu : 0;
	request[11] = bc->gatt_adapter_index;
	if (mbw_send_operation(bc, IPC_OP_DOMAIN_GATT, request,
	    sizeof(request), &bc->discover_request_id) != 0)
		return (-1);
	if (++bc->pbgatt_generation == 0)
		bc->pbgatt_generation++;
	strlcpy(bc->gatt_addr, addr, sizeof(bc->gatt_addr));
	bc->gatt_addr_type = addr_type;
	bc->gatt_data_in = 0;
	bc->gatt_data_out = 0;
	bc->gatt_discovering = 1;
	bc->gatt_subscribing = 0;
	bc->gatt_subscribed = 0;
	bc->subscribe_request_id = 0;
	bc->gatt_in_service = 0;
	bc->gatt_mesh_type = MESHD_GATT_PROVISIONING;
	return (0);
}

int
meshd_blued_pbgatt_discover(struct meshd_blued *bc, const char *addr,
    uint8_t addr_type)
{

	return (mbw_pbgatt_discover(bc, addr, addr_type,
	    MESHD_ADAPTER_DEFAULT));
}

int
meshd_blued_pbgatt_open(void *arg, const char *addr, uint8_t addr_type,
    uint8_t adapter_index)
{

	return (mbw_pbgatt_discover(arg, addr, addr_type, adapter_index));
}

int
meshd_blued_proxy_open(void *arg, const char *addr, uint8_t addr_type,
    uint8_t adapter_index)
{
	struct meshd_blued *bc = arg;
	struct meshd_blued_proxy_link *link;
	uint8_t request[IPC_GATT_REQ_SIZE];
	bdaddr_t ba;
	struct meshd_blued_peer *peer;
	size_t i;

	if (!mbw_ready(bc) || addr == NULL || strlen(addr) != 17 ||
	    addr_type > MESHD_ADDR_RANDOM || !bt_aton(addr, &ba) ||
	    adapter_index > MESHD_ADAPTER_DEFAULT ||
	    mbw_proxy_link(bc, addr, addr_type, adapter_index) != NULL)
		return (-1);
	for (i = 0; i < MESHD_MAX_PROXY_GATT; i++)
		if (!bc->proxy[i].active)
			break;
	if (i == MESHD_MAX_PROXY_GATT)
		return (-1);
	link = &bc->proxy[i];
	memset(link, 0, sizeof(*link));
	link->active = 1;
	link->discovering = 1;
	link->addr_type = addr_type;
	link->session_adapter_index = adapter_index;
	peer = adapter_index == MESHD_ADAPTER_DEFAULT ?
	    mbw_peer_unique(bc, &ba, addr_type) :
	    mbw_peer_exact(bc, &ba, addr_type, adapter_index);
	link->adapter_index = adapter_index != MESHD_ADAPTER_DEFAULT ?
	    adapter_index : peer != NULL ? peer->adapter_index :
	    IPC_MESH_ADAPTER_DEFAULT;
	link->mtu = peer != NULL ? peer->mtu : 0;
	strlcpy(link->addr, addr, sizeof(link->addr));
	memset(request, 0, sizeof(request));
	ipc_put_le16(request, IPC_GATT_DISCOVER);
	request[4] = addr_type;
	memcpy(request + 5, &ba, sizeof(ba));
	request[11] = link->adapter_index;
	if (mbw_send_operation(bc, IPC_OP_DOMAIN_GATT, request,
	    sizeof(request), &link->discover_request_id) != 0) {
		memset(link, 0, sizeof(*link));
		return (-1);
	}
	return (0);
}

int
meshd_blued_pbgatt_drain(struct meshd_blued *bc, struct meshd_node *nd)
{
	uint8_t pdu[MESH_PROXY_MAX_PDU];
	uint8_t request[IPC_GATT_VALUE_REQ_SIZE + sizeof(pdu)];
	bdaddr_t ba;
	size_t len, slots[MESHD_PBGATT_MAX_SEGS], reserved, i;
	uint32_t request_id;
	int sent = 0, rc;

	if (!mbw_ready(bc) || nd == NULL || !bc->gatt_subscribed ||
	    bc->gatt_data_in == 0)
		return (-1);
	if (!bt_aton(bc->gatt_addr, &ba))
		return (-1);
	if (bc->pbgatt_draining)
		return (0);
	bc->pbgatt_draining = 1;
	bc->pbgatt_pending = 0;
	for (;;) {
		/*
		 * poll() may start another provisioning PDU immediately after the
		 * previous one.  Reserve queue bytes and result records before every
		 * such start, then trim the conservative record reservation once the
		 * actual segment count is known.
		 */
		reserved = nd->pbgatt.tx_next == nd->pbgatt.tx_count ?
		    MESHD_PBGATT_MAX_SEGS : nd->pbgatt.tx_count - nd->pbgatt.tx_next;
		if (mbw_write_reserve(bc, reserved *
		    (IPC_HDR_SIZE + IPC_OP_PREFIX_SIZE + IPC_GATT_VALUE_REQ_SIZE +
		    MESH_PROXY_MAX_PDU), MESHD_BLUED_WRITE_PBGATT, 0, reserved,
		    slots) != 0) {
			if (errno == ENOBUFS)
				bc->pbgatt_pending = 1;
			bc->pbgatt_draining = 0;
			return (sent != 0 ? sent : -1);
		}
		rc = meshd_pbgatt_poll(nd, mbw_now(), pdu, sizeof(pdu), &len);
		if (rc != 1) {
			mbw_write_release(bc, slots, reserved);
			if (rc < 0) {
				(void)meshd_blued_pbgatt_close(bc);
				meshd_pbgatt_cancel(nd);
			}
			bc->pbgatt_draining = 0;
			return (rc < 0 ? -1 : sent);
		}
		if (reserved == MESHD_PBGATT_MAX_SEGS) {
			size_t actual = nd->pbgatt.tx_count;

			if (actual < reserved) {
				mbw_write_release(bc, slots + actual,
				    reserved - actual);
				reserved = actual;
			}
		}
		for (i = 0; i < reserved; i++) {
			if (i != 0 &&
			    meshd_pbgatt_poll(nd, mbw_now(), pdu, sizeof(pdu),
			    &len) != 1) {
				mbw_write_release(bc, slots + i, reserved - i);
				(void)meshd_blued_pbgatt_close(bc);
				meshd_pbgatt_cancel(nd);
				bc->pbgatt_draining = 0;
				return (-1);
			}
			memset(request, 0, IPC_GATT_VALUE_REQ_SIZE);
			ipc_put_le16(request, IPC_GATT_WRITE_CMD);
			request[4] = bc->gatt_addr_type;
			memcpy(request + 5, &ba, sizeof(ba));
			request[11] = bc->gatt_adapter_index;
			ipc_put_le16(request + 12, bc->gatt_data_in);
			ipc_put_le16(request + 14, (uint16_t)len);
			memcpy(request + IPC_GATT_VALUE_REQ_SIZE, pdu, len);
			if (mbw_send_operation(bc, IPC_OP_DOMAIN_GATT, request,
			    IPC_GATT_VALUE_REQ_SIZE + len, &request_id) != 0) {
				mbw_write_release(bc, slots + i, reserved - i);
				if (errno != ENOBUFS)
					meshd_blued_close(bc);
				else
					bc->pbgatt_pending = 1;
				if (errno != ENOBUFS)
					meshd_pbgatt_cancel(nd);
				bc->pbgatt_draining = 0;
				return (-1);
			}
			bc->writes[slots[i]].request_id = request_id;
			if (nd->pbgatt.timeout_closing &&
			    nd->pbgatt.tx_next == nd->pbgatt.tx_count)
				bc->writes[slots[i]].terminal = 1;
			sent++;
		}
	}
}

int
meshd_blued_pbgatt_timeout(void *arg)
{
	struct meshd_blued *bc = arg;
	int rc;

	if (bc == NULL || bc->node == NULL || !bc->node->pbgatt.timeout_closing)
		return (-1);
	rc = meshd_blued_pbgatt_drain(bc, bc->node);
	if (rc <= 0) {
		/* A timed-out transaction must never wait indefinitely for queue room. */
		bc->pbgatt_pending = 0;
		return (-1);
	}
	return (0);
}

/* ================================================================
 * Receive pump.
 * ================================================================ */

/*
 * Dispatch one decoded EVENT MESH_ADV to the matching RX seam by AD type.  No
 * mesh crypto crosses the bearer: blued hands us the opaque AD payload and
 * we feed it to the seam that owns that PDU type.  Returns 1 if dispatched.
 */
static int
mbw_dispatch(struct meshd_node *nd, unsigned adtype, const uint8_t *pdu,
    size_t len, uint64_t now)
{
	switch (adtype) {
	case 0x2A:				/* Mesh Message / Network PDU */
		(void)meshd_bearer_rx(nd, pdu, len);
		return (1);
	case 0x2B:				/* Secure Network beacon */
		(void)meshd_beacon_rx(nd, pdu, len);
		return (1);
	case 0x29:				/* PB-ADV provisioning packet */
		(void)meshd_provisioner_recv(nd, pdu, len, now);
		(void)meshd_provisioner_drain(nd, now);
		return (1);
	default:
		return (0);			/* not a mesh AD type: ignore */
	}
}

static struct meshd_blued_proxy_link *
mbw_proxy_request(struct meshd_blued *bc, uint32_t request_id)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_PROXY_GATT; i++)
		if (bc->proxy[i].active && bc->proxy[i].discovering &&
		    bc->proxy[i].discover_request_id == request_id)
			return (&bc->proxy[i]);
	return (NULL);
}

static struct meshd_blued_proxy_link *
mbw_proxy_wire(struct meshd_blued *bc, const bdaddr_t *ba, uint8_t addr_type,
    uint8_t adapter_index, uint16_t handle)
{
	bdaddr_t candidate;
	size_t i;

	for (i = 0; i < MESHD_MAX_PROXY_GATT; i++) {
		if (!bc->proxy[i].active ||
		    (!bc->proxy[i].subscribed && !bc->proxy[i].subscribing) ||
		    bc->proxy[i].addr_type != addr_type ||
		    bc->proxy[i].adapter_index != adapter_index ||
		    bc->proxy[i].data_out != handle ||
		    !bt_aton(bc->proxy[i].addr, &candidate))
			continue;
		if (memcmp(ba, &candidate, sizeof(candidate)) == 0)
			return (&bc->proxy[i]);
	}
	return (NULL);
}

static struct meshd_blued_proxy_link *
mbw_proxy_subscribe_request(struct meshd_blued *bc, uint32_t request_id)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_PROXY_GATT; i++)
		if (bc->proxy[i].active && bc->proxy[i].subscribing &&
		    bc->proxy[i].subscribe_request_id == request_id)
			return (&bc->proxy[i]);
	return (NULL);
}

static int
mbw_proxy_subscribe(struct meshd_blued *bc,
    struct meshd_blued_proxy_link *link)
{
	uint8_t request[IPC_GATT_REQ_SIZE];
	bdaddr_t ba;

	if (link == NULL || link->data_in == 0 || link->data_out == 0 ||
	    !bt_aton(link->addr, &ba))
		return (-1);
	memset(request, 0, sizeof(request));
	ipc_put_le16(request, IPC_GATT_SUBSCRIBE);
	request[4] = link->addr_type;
	memcpy(request + 5, &ba, sizeof(ba));
	request[11] = link->adapter_index;
	ipc_put_le16(request + 12, link->data_out);
	if (mbw_send_operation(bc, IPC_OP_DOMAIN_GATT, request,
	    sizeof(request), &link->subscribe_request_id) != 0)
		return (-1);
	link->subscribing = 1;
	link->subscribed = 0;
	return (0);
}

static int
mbw_gatt_unsubscribe(struct meshd_blued *bc, const char *addr,
    uint8_t addr_type, uint8_t adapter_index, uint16_t handle)
{
	uint8_t request[IPC_GATT_REQ_SIZE];
	bdaddr_t ba;

	if (!mbw_ready(bc) || addr == NULL || handle == 0 ||
	    !bt_aton(addr, &ba))
		return (-1);
	memset(request, 0, sizeof(request));
	ipc_put_le16(request, IPC_GATT_UNSUBSCRIBE);
	request[4] = addr_type;
	memcpy(request + 5, &ba, sizeof(ba));
	request[11] = adapter_index;
	ipc_put_le16(request + 12, handle);
	return (mbw_send_operation(bc, IPC_OP_DOMAIN_GATT, request,
	    sizeof(request), NULL));
}

static int
mbw_peer_disconnect(struct meshd_blued *bc, const char *addr,
    uint8_t addr_type, uint8_t adapter_index)
{
	uint8_t request[IPC_GAP_REQ_SIZE];
	bdaddr_t ba;

	if (!mbw_ready(bc) || addr == NULL || !bt_aton(addr, &ba))
		return (-1);
	ipc_gap_req_encode(request, IPC_GAP_DISCONNECT, 0, addr_type,
	    (const uint8_t *)&ba, adapter_index);
	return (mbw_send_operation(bc, IPC_OP_DOMAIN_GAP, request,
	    sizeof(request), NULL));
}

int
meshd_blued_proxy_close(void *arg, const char *addr, uint8_t addr_type,
    uint8_t adapter_index)
{
	struct meshd_blued *bc = arg;
	struct meshd_blued_proxy_link *link;
	uint8_t proxy_index;
	int error = 0;

	link = mbw_proxy_link(bc, addr, addr_type, adapter_index);
	if (link == NULL || link->addr_type != addr_type)
		return (-1);
	proxy_index = (uint8_t)(link - bc->proxy);
	if (link->subscribed && link->data_out != 0 &&
	    mbw_gatt_unsubscribe(bc, link->addr,
	    link->addr_type, link->adapter_index, link->data_out) != 0)
		error = -1;
	if (mbw_peer_disconnect(bc, link->addr, link->addr_type,
	    link->adapter_index) != 0)
		error = -1;
	mbw_write_clear_owner(bc, MESHD_BLUED_WRITE_PROXY, proxy_index);
	memset(link, 0, sizeof(*link));
	return (error);
}

int
meshd_blued_pbgatt_close(void *arg)
{
	struct meshd_blued *bc = arg;
	int error = 0;

	if (bc == NULL || bc->gatt_addr[0] == '\0')
		return (-1);
	if (bc->gatt_subscribed && bc->gatt_data_out != 0 &&
	    mbw_gatt_unsubscribe(bc, bc->gatt_addr,
	    bc->gatt_addr_type, bc->gatt_adapter_index,
	    bc->gatt_data_out) != 0)
		error = -1;
	if (mbw_peer_disconnect(bc, bc->gatt_addr, bc->gatt_addr_type,
	    bc->gatt_adapter_index) != 0)
		error = -1;
	mbw_write_clear_owner(bc, MESHD_BLUED_WRITE_PBGATT, 0);
	bc->gatt_addr[0] = '\0';
	bc->gatt_adapter_index = IPC_MESH_ADAPTER_DEFAULT;
	bc->gatt_mtu = 0;
	bc->gatt_data_in = bc->gatt_data_out = 0;
	bc->gatt_discovering = 0;
	bc->gatt_subscribing = 0;
	bc->gatt_subscribed = 0;
	bc->subscribe_request_id = 0;
	bc->gatt_mesh_type = MESHD_GATT_NONE;
	bc->pbgatt_pending = 0;
	return (error);
}

/*
 * Parse one EVENT MESH_ADV frame payload ("EVENT MESH_ADV <adtype> <hex>") and
 * dispatch it.  All field extraction is bounded; a malformed payload is ignored
 * (returns 0) rather than trusted.  Returns 1 if an event was dispatched.
 */
static int
mbw_handle_event(struct meshd_blued *bc, struct meshd_node *nd,
    uint16_t domain, const uint8_t *p, size_t plen, uint64_t now)
{
	struct meshd_blued_proxy_link *link;
	uint32_t request_id;
	uint16_t status, flags, event, value_len, bearer_mtu;
	const uint8_t *body;
	bdaddr_t ba;

	if (plen < IPC_OP_PREFIX_SIZE + 2)
		return (0);
	ipc_op_prefix_decode(p, &request_id, &status, &flags);
	if (status != IPC_ERR_NONE || flags != 0)
		return (0);
	body = p + IPC_OP_PREFIX_SIZE;
	event = ipc_get_le16(body);
	if (domain == IPC_OP_DOMAIN_MESH && request_id == 0 &&
	    event == IPC_MESH_EV_ADV && plen >= IPC_OP_PREFIX_SIZE +
	    IPC_MESH_ADV_EVENT_HDR_SIZE && body[3] != 0 &&
	    body[3] <= MBW_ADV_MAX && plen == IPC_OP_PREFIX_SIZE +
	    IPC_MESH_ADV_EVENT_HDR_SIZE + body[3])
		return (mbw_dispatch(nd, body[2],
		    body + IPC_MESH_ADV_EVENT_HDR_SIZE, body[3], now));
	if (domain == IPC_OP_DOMAIN_GAP && request_id == 0 &&
	    event == IPC_GAP_EV_CONNECTED && plen == IPC_OP_PREFIX_SIZE +
	    IPC_GAP_CONNECTED_EVENT_SIZE) {
		memcpy(&ba, body + 3, sizeof(ba));
		mbw_peer_connected(bc, &ba, body[2], body[14],
		    ipc_get_le16(body + 12));
		return (0);
	}
	if (domain == IPC_OP_DOMAIN_GATT && request_id ==
	    bc->discover_request_id && bc->gatt_discovering &&
	    plen == IPC_OP_PREFIX_SIZE + IPC_GATT_DISCOVERY_EVENT_SIZE) {
		if (event == IPC_GATT_EV_SERVICE)
			bc->gatt_in_service = ipc_get_le16(body + 2) == 0x1827;
		else if (event == IPC_GATT_EV_CHARACTERISTIC &&
		    bc->gatt_in_service) {
			if (ipc_get_le16(body + 2) == 0x2adb)
				bc->gatt_data_in = ipc_get_le16(body + 20);
			else if (ipc_get_le16(body + 2) == 0x2adc)
				bc->gatt_data_out = ipc_get_le16(body + 20);
		}
		return (0);
	}
	link = domain == IPC_OP_DOMAIN_GATT ?
	    mbw_proxy_request(bc, request_id) : NULL;
	if (link != NULL && plen == IPC_OP_PREFIX_SIZE +
	    IPC_GATT_DISCOVERY_EVENT_SIZE) {
		if (event == IPC_GATT_EV_SERVICE)
			link->in_service = ipc_get_le16(body + 2) ==
			    MESH_PROXY_SERVICE_UUID;
		else if (event == IPC_GATT_EV_CHARACTERISTIC && link->in_service) {
			if (ipc_get_le16(body + 2) == MESH_PROXY_DATA_IN_UUID)
				link->data_in = ipc_get_le16(body + 20);
			else if (ipc_get_le16(body + 2) == MESH_PROXY_DATA_OUT_UUID)
				link->data_out = ipc_get_le16(body + 20);
		}
		return (0);
	}
	if (domain == IPC_OP_DOMAIN_GATT && request_id == 0 &&
	    event == IPC_GATT_EV_NOTIFY && plen >= IPC_OP_PREFIX_SIZE +
	    IPC_GATT_NOTIFY_EVENT_SIZE) {
		value_len = ipc_get_le16(body + 11);
		bearer_mtu = ipc_get_le16(body + 14);
		if (plen != IPC_OP_PREFIX_SIZE + IPC_GATT_NOTIFY_EVENT_SIZE +
		    value_len || bearer_mtu < MESHD_PBGATT_MIN_MTU ||
		    value_len > (size_t)bearer_mtu - 3)
			return (0);
		memcpy(&ba, body + 3, sizeof(ba));
		link = mbw_proxy_wire(bc, &ba, body[2], body[13],
		    ipc_get_le16(body + 9));
		if (link != NULL) {
			if (meshd_proxy_gatt_recv_mtu(nd, link->addr,
			    link->addr_type, link->session_adapter_index,
			    body + IPC_GATT_NOTIFY_EVENT_SIZE,
			    value_len, bearer_mtu, now) < 0) {
				char addr[sizeof(link->addr)];
				uint8_t addr_type = link->addr_type;
				uint8_t adapter_index = link->session_adapter_index;

				strlcpy(addr, link->addr, sizeof(addr));
				(void)meshd_blued_proxy_close(bc, addr, addr_type,
				    adapter_index);
				meshd_proxy_gatt_cancel(nd, addr, addr_type,
				    adapter_index);
				return (0);
			}
			return (1);
		}
		if ((!bc->gatt_subscribed && !bc->gatt_subscribing) ||
		    body[2] != bc->gatt_addr_type ||
		    body[13] != bc->gatt_adapter_index ||
		    ipc_get_le16(body + 9) != bc->gatt_data_out ||
		    !bt_aton(bc->gatt_addr, &ba) ||
		    memcmp(body + 3, &ba, sizeof(ba)) != 0)
			return (0);
		if (meshd_pbgatt_recv_mtu(nd,
		    body + IPC_GATT_NOTIFY_EVENT_SIZE, value_len,
		    bearer_mtu, now) < 0) {
			(void)meshd_blued_pbgatt_close(bc);
			meshd_pbgatt_cancel(nd);
			return (0);
		}
		(void)meshd_blued_pbgatt_drain(bc, nd);
		return (1);
	}
	if (domain == IPC_OP_DOMAIN_GAP && request_id == 0 &&
	    event == IPC_GAP_EV_DISCONNECTED && plen == IPC_OP_PREFIX_SIZE +
	    IPC_GAP_DISCONNECTED_EVENT_SIZE) {
		size_t i;

		memcpy(&ba, body + 3, sizeof(ba));
		mbw_peer_disconnected(bc, &ba, body[2], body[11]);
		for (i = 0; i < MESHD_MAX_PROXY_GATT; i++) {
			bdaddr_t candidate;

			if (!bc->proxy[i].active || bc->proxy[i].addr_type != body[2] ||
			    bc->proxy[i].adapter_index != body[11] ||
			    !bt_aton(bc->proxy[i].addr, &candidate) ||
			    memcmp(&ba, &candidate, sizeof(ba)) != 0)
				continue;
			if (bc->proxy[i].subscribed)
				(void)mbw_gatt_unsubscribe(bc, bc->proxy[i].addr,
				    bc->proxy[i].addr_type,
				    bc->proxy[i].adapter_index,
				    bc->proxy[i].data_out);
			meshd_proxy_gatt_cancel(nd, bc->proxy[i].addr,
			    bc->proxy[i].addr_type,
			    bc->proxy[i].session_adapter_index);
			mbw_write_clear_owner(bc, MESHD_BLUED_WRITE_PROXY,
			    (uint8_t)i);
			memset(&bc->proxy[i], 0, sizeof(bc->proxy[i]));
			return (0);
		}
		if (bc->gatt_addr_type != body[2] ||
		    bc->gatt_adapter_index != body[11] ||
		    !bt_aton(bc->gatt_addr, &ba) ||
		    memcmp(body + 3, &ba, sizeof(ba)) != 0)
			return (0);
		if (bc->gatt_subscribed)
			(void)mbw_gatt_unsubscribe(bc, bc->gatt_addr,
			    bc->gatt_addr_type, bc->gatt_adapter_index,
			    bc->gatt_data_out);
		bc->gatt_addr[0] = '\0';
		bc->gatt_addr_type = 0;
		bc->gatt_adapter_index = IPC_MESH_ADAPTER_DEFAULT;
		bc->gatt_mtu = 0;
		bc->gatt_data_in = bc->gatt_data_out = 0;
		bc->gatt_discovering = 0;
		bc->gatt_subscribing = 0;
		bc->gatt_subscribed = 0;
		bc->subscribe_request_id = 0;
		mbw_write_clear_owner(bc, MESHD_BLUED_WRITE_PBGATT, 0);
		if (!meshd_pbgatt_done(nd))
			meshd_pbgatt_cancel(nd);
		bc->gatt_mesh_type = MESHD_GATT_NONE;
	}
	return (0);
}

/* Consume a correlated Write Command result and fail only its owning link. */
static int
mbw_handle_write_reply(struct meshd_blued *bc, struct meshd_node *nd,
    uint32_t request_id, uint16_t status, uint16_t flags, size_t plen)
{
	struct meshd_blued_write *write;
	uint8_t kind, proxy_index, terminal;
	uint64_t generation;
	int ok;

	write = mbw_write_request(bc, request_id);
	if (write == NULL)
		return (0);
	kind = write->kind;
	proxy_index = write->proxy_index;
	terminal = write->terminal;
	generation = write->generation;
	memset(write, 0, sizeof(*write));
	/* A delayed reply from an older PB-GATT link must not close its successor. */
	if (kind == MESHD_BLUED_WRITE_PBGATT &&
	    generation != bc->pbgatt_generation)
		return (1);
	ok = status == IPC_ERR_NONE && flags == 0 && plen == IPC_OP_PREFIX_SIZE;
	if (ok && kind == MESHD_BLUED_WRITE_PBGATT && terminal &&
	    nd != NULL && nd->pbgatt.active && nd->pbgatt.timeout_closing) {
		(void)meshd_blued_pbgatt_close(bc);
		meshd_pbgatt_cancel(nd);
		return (1);
	}
	if (ok)
		return (1);

	if (kind == MESHD_BLUED_WRITE_PROXY &&
	    proxy_index < MESHD_MAX_PROXY_GATT &&
	    bc->proxy[proxy_index].active) {
		char addr[sizeof(bc->proxy[proxy_index].addr)];
		uint8_t addr_type = bc->proxy[proxy_index].addr_type;
		uint8_t adapter_index =
		    bc->proxy[proxy_index].session_adapter_index;

		strlcpy(addr, bc->proxy[proxy_index].addr, sizeof(addr));
		(void)meshd_blued_proxy_close(bc, addr, addr_type, adapter_index);
		meshd_proxy_gatt_cancel(nd, addr, addr_type, adapter_index);
	} else if (kind == MESHD_BLUED_WRITE_PBGATT &&
	    bc->gatt_addr[0] != '\0') {
		(void)meshd_blued_pbgatt_close(bc);
		meshd_pbgatt_cancel(nd);
	}
	return (1);
}

/* Advance the production nonblocking HELLO/subscription handshake. */
static int
mbw_handshake_frame(struct meshd_blued *bc, uint16_t type, uint16_t arg,
    const uint8_t *payload, size_t plen)
{
	uint8_t request[IPC_MESH_REQ_SIZE];
	uint8_t op[IPC_OP_PREFIX_SIZE + IPC_MESH_REQ_SIZE];
	uint32_t request_id;
	uint16_t status, flags;

	if (bc->state == MESHD_BLUED_HELLO) {
		if (type != IPC_T_HELLO || arg != IPC_PROTO_VERSION ||
		    plen != IPC_HELLO_FEATURES_SIZE ||
		    (ipc_get_le32(payload) &
		    (IPC_FEATURE_MESH | IPC_FEATURE_EVENTS)) !=
		    (IPC_FEATURE_MESH | IPC_FEATURE_EVENTS))
			return (-1);
		memset(request, 0, sizeof(request));
		ipc_put_le16(request, IPC_MESH_SUBSCRIBE);
		request_id = ++bc->next_request_id;
		if (request_id == 0)
			request_id = ++bc->next_request_id;
		ipc_op_prefix_encode(op, request_id, IPC_ERR_NONE, 0);
		memcpy(op + IPC_OP_PREFIX_SIZE, request, sizeof(request));
		bc->handshake_request_id = request_id;
		bc->state = MESHD_BLUED_SUBSCRIBING;
		if (mbw_queue_frame(bc, IPC_T_OP_REQ, IPC_OP_DOMAIN_MESH, op,
		    sizeof(op)) != 0)
			return (-1);
		return (1);
	}
	if (bc->state != MESHD_BLUED_SUBSCRIBING)
		return (0);
	if (type == IPC_T_OP_EVENT)
		return (0);
	if (type != IPC_T_OP_REPLY || arg != IPC_OP_DOMAIN_MESH ||
	    plen != IPC_OP_PREFIX_SIZE)
		return (-1);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	if (request_id != bc->handshake_request_id || status != IPC_ERR_NONE ||
	    flags != 0)
		return (-1);
	bc->state = MESHD_BLUED_READY;
	bc->handshake_deadline = 0;
	bc->handshake_request_id = 0;
	bc->backoff = 0;
	bc->retry_at = 0;
	return (1);
}

int
meshd_blued_pump_rx(struct meshd_blued *bc, struct meshd_node *nd,
    struct meshd_persist *ps, uint64_t now)
{
	int dispatched = 0;
	int transport_eof = 0;

	if (bc == NULL || nd == NULL)
		return (-1);
	if (bc->fd < 0)
		return (0);
	if (bc->state != MESHD_BLUED_READY &&
	    bc->handshake_deadline != 0 && mbw_now() >=
	    bc->handshake_deadline) {
		errno = ETIMEDOUT;
		mbw_transport_failed(bc, nd);
		return (0);
	}

	/* Drain readable bytes into the reassembly buffer. */
	for (;;) {
		ssize_t r;
		size_t space = sizeof(bc->rx) - bc->rxn;

		if (space == 0)
			break;			/* buffer full; process below */
		r = read(bc->fd, bc->rx + bc->rxn, space);
		if (r > 0) {
			bc->rxn += (size_t)r;
			continue;
		}
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			break;			/* no more data right now */
		/* Preserve and process any complete frames received before EOF. */
		transport_eof = 1;
		break;
	}

	/* Process every complete frame currently buffered. */
	for (;;) {
		uint32_t plen;
		uint16_t type, arg;
		size_t framelen;
		const uint8_t *payload;

		if (bc->rxn < IPC_HDR_SIZE)
			break;
		ipc_hdr_decode(bc->rx, &plen, &type, &arg);
		if (plen > IPC_MAX_PAYLOAD) {
			/* Malformed length: the stream is unusable, resync by drop. */
			mbw_transport_failed(bc, nd);
			return (dispatched);
		}
		framelen = IPC_HDR_SIZE + plen;
		if (bc->rxn < framelen)
			break;			/* wait for the rest of the frame */
		payload = bc->rx + IPC_HDR_SIZE;
		if (bc->state == MESHD_BLUED_HELLO ||
		    bc->state == MESHD_BLUED_SUBSCRIBING) {
			int handshake;

			handshake = mbw_handshake_frame(bc, type, arg, payload, plen);
			if (handshake < 0) {
				mbw_transport_failed(bc, nd);
				return (dispatched);
			}
			if (handshake > 0)
				goto frame_done;
		}
		if (type == IPC_T_OP_EVENT) {
			/*
			 * A single bearer drain can process many inbound frames,
			 * each of which may originate access-layer replies that
			 * advance the live SEQ (a segmented reply consumes up to
			 * MESH_SEG_MAX SEQ, which is within the persist guard
			 * band).  Reserve the persisted SEQ high-water ahead of
			 * this frame's origination here -- the once-per-drain
			 * reserve in the main loop is too coarse and would let
			 * aired PDUs outrun the persisted mark, so a crash could
			 * resume below already-transmitted SEQ under the same IV
			 * (nonce reuse).  If the store cannot be written, stop
			 * draining before originating; the frame stays buffered
			 * and the main loop's reserve then fails and quits.
			 */
			if (ps != NULL && meshd_persist_seq_reserve(ps, nd) < 0)
				break;
			dispatched += mbw_handle_event(bc, nd, arg, payload,
			    plen, now);
		}
		else if (type == IPC_T_OP_REPLY && arg == IPC_OP_DOMAIN_GATT &&
		    plen >= IPC_OP_PREFIX_SIZE) {
			struct meshd_blued_proxy_link *link;
			uint32_t request_id;
			uint16_t status, flags, mtu;
			uint8_t adapter_index;
			int discover_ok;
			char addr[sizeof(bc->gatt_addr)];
			bdaddr_t ba;

			ipc_op_prefix_decode(payload, &request_id, &status, &flags);
			if (mbw_handle_write_reply(bc, nd, request_id, status, flags,
			    plen))
				goto gatt_reply_done;
			/*
			 * A subscription is operational only after its correlated ACK.
			 * In particular, do not transmit PB-GATT Invite or accept Proxy
			 * notifications merely because discovery and the local enqueue
			 * succeeded.
			 */
			link = mbw_proxy_subscribe_request(bc, request_id);
			if (link != NULL) {
				char failed_addr[sizeof(link->addr)];
				uint8_t failed_type = link->addr_type;
				uint8_t failed_adapter = link->session_adapter_index;

				link->subscribing = 0;
				link->subscribe_request_id = 0;
				if (status == IPC_ERR_NONE && flags == 0 &&
				    plen == IPC_OP_PREFIX_SIZE) {
					link->subscribed = 1;
				} else {
					strlcpy(failed_addr, link->addr,
					    sizeof(failed_addr));
					(void)meshd_blued_proxy_close(bc, failed_addr,
					    failed_type, failed_adapter);
					meshd_proxy_gatt_cancel(nd, failed_addr,
					    failed_type, failed_adapter);
				}
				goto gatt_reply_done;
			}
			if (bc->gatt_subscribing &&
			    request_id == bc->subscribe_request_id) {
				bc->gatt_subscribing = 0;
				bc->subscribe_request_id = 0;
				if (status == IPC_ERR_NONE && flags == 0 &&
				    plen == IPC_OP_PREFIX_SIZE &&
				    meshd_pbgatt_link_open(nd, now) == 0) {
					bc->gatt_subscribed = 1;
					(void)meshd_blued_pbgatt_drain(bc, nd);
				} else {
					(void)meshd_blued_pbgatt_close(bc);
					meshd_pbgatt_cancel(nd);
				}
				goto gatt_reply_done;
			}
			discover_ok = status == IPC_ERR_NONE && flags == 0 &&
			    plen == IPC_OP_PREFIX_SIZE + IPC_GATT_DISCOVER_REPLY_SIZE &&
			    ipc_get_le16(payload + IPC_OP_PREFIX_SIZE) ==
			    IPC_GATT_DISCOVER && payload[IPC_OP_PREFIX_SIZE + 3] == 0;
			adapter_index = discover_ok ?
			    payload[IPC_OP_PREFIX_SIZE + 2] : IPC_MESH_ADAPTER_DEFAULT;
			mtu = discover_ok ?
			    ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 4) : 0;
			if (discover_ok && (adapter_index == IPC_MESH_ADAPTER_DEFAULT ||
			    mtu < MESHD_PBGATT_MIN_MTU || mtu > MESHD_GATT_MAX_MTU))
				discover_ok = 0;
			link = mbw_proxy_request(bc, request_id);
			if (link != NULL) {
				uint8_t requested_adapter =
				    link->session_adapter_index;

				link->discovering = 0;
				link->in_service = 0;
				link->discover_request_id = 0;
				if (discover_ok && requested_adapter ==
				    MESHD_ADAPTER_DEFAULT) {
					if (meshd_proxy_gatt_resolve_adapter(nd,
					    link->addr, link->addr_type,
					    requested_adapter, adapter_index) != 0)
						discover_ok = 0;
					else
						link->session_adapter_index = adapter_index;
				}
				if (discover_ok) {
					link->adapter_index = adapter_index;
					link->mtu = mtu;
					(void)meshd_proxy_gatt_set_mtu(nd, link->addr,
					    link->addr_type, link->session_adapter_index,
					    mtu);
					if (bt_aton(link->addr, &ba))
						mbw_peer_connected(bc, &ba, link->addr_type,
						    adapter_index, mtu);
				}
				if (!discover_ok || mbw_proxy_subscribe(bc, link) != 0) {
					char failed_addr[sizeof(link->addr)];
					uint8_t failed_type = link->addr_type;
					uint8_t failed_adapter =
					    link->session_adapter_index;

					strlcpy(failed_addr, link->addr,
					    sizeof(failed_addr));
					(void)meshd_blued_proxy_close(bc, failed_addr,
					    failed_type, failed_adapter);
					meshd_proxy_gatt_cancel(nd, failed_addr,
					    failed_type, failed_adapter);
				}
			} else if (bc->gatt_discovering &&
			    request_id == bc->discover_request_id) {
				bc->gatt_discovering = 0;
				bc->gatt_in_service = 0;
				bc->discover_request_id = 0;
				strlcpy(addr, bc->gatt_addr, sizeof(addr));
				if (discover_ok) {
					bc->gatt_adapter_index = adapter_index;
					bc->gatt_mtu = mtu;
					(void)meshd_pbgatt_set_mtu(nd, mtu);
					if (bt_aton(addr, &ba))
						mbw_peer_connected(bc, &ba,
						    bc->gatt_addr_type, adapter_index, mtu);
				}
				if (discover_ok &&
				    bc->gatt_data_in != 0 &&
				    bc->gatt_data_out != 0) {
					if (meshd_blued_pbgatt_bind(bc, addr,
					    bc->gatt_addr_type,
					    bc->gatt_data_in,
					    bc->gatt_data_out) != 0) {
							(void)meshd_blued_pbgatt_close(bc);
							meshd_pbgatt_cancel(nd);
						}
				} else {
					(void)meshd_blued_pbgatt_close(bc);
					meshd_pbgatt_cancel(nd);
				}
			}
		gatt_reply_done:
			;
		} else if (type == IPC_T_ERROR) {
			size_t i;

			for (i = 0; i < MESHD_MAX_PROXY_GATT; i++)
				if (bc->proxy[i].active &&
				    bc->proxy[i].discovering) {
					(void)mbw_peer_disconnect(bc,
					    bc->proxy[i].addr,
					    bc->proxy[i].addr_type,
					    bc->proxy[i].adapter_index);
					meshd_proxy_gatt_cancel(nd,
					    bc->proxy[i].addr,
					    bc->proxy[i].addr_type,
					    bc->proxy[i].session_adapter_index);
					mbw_write_clear_owner(bc,
					    MESHD_BLUED_WRITE_PROXY, (uint8_t)i);
					memset(&bc->proxy[i], 0,
					    sizeof(bc->proxy[i]));
				}
			if (bc->gatt_discovering) {
				(void)meshd_blued_pbgatt_close(bc);
				bc->gatt_discovering = 0;
				bc->gatt_in_service = 0;
				bc->discover_request_id = 0;
				meshd_pbgatt_cancel(nd);
			}
		}

	frame_done:
		/*
		 * Frame processing can synchronously close the connection (e.g. a
		 * NOTIFY -> proxy drain -> send() EPIPE -> transport-failed ->
		 * close), which resets bc->rxn to 0.  The memmove below would then
		 * compute (0 - framelen) as a size_t and copy ~SIZE_MAX bytes, so
		 * the closed-socket guard MUST precede it (finding 77).
		 */
		if (bc->fd < 0)
			return (dispatched);
		memmove(bc->rx, bc->rx + framelen, bc->rxn - framelen);
		bc->rxn -= framelen;
	}
	if (transport_eof)
		mbw_transport_failed(bc, nd);
	else if (mbw_ready(bc) &&
	    bc->pbgatt_pending)
		(void)meshd_blued_pbgatt_drain(bc, nd);
	return (dispatched);
}
