/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "migration_vsock_relay.h"
#include "vsock_migration_state.h"

#define RELAY_MAGIC 0x31525653U /* SVR1 */
#define RELAY_HEADER_SIZE 16U
#define RELAY_DATA 1U
#define RELAY_FIN 2U
#define RELAY_STREAM_CHUNK (64U * 1024U)
#define RELAY_MAX_DATA VSOCK_MIGRATION_MAX_PEER_BUFFER

struct relay_conn {
	bool local_fin;
	bool remote_fin;
};

struct relay_frame {
	uint8_t *buf;
	size_t have;
	size_t need;
	size_t offset;
	uint32_t index;
	uint32_t kind;
};

static void
relay_frame_reset(struct relay_frame *frame)
{

	frame->have = 0;
	frame->need = RELAY_HEADER_SIZE;
	frame->offset = 0;
	frame->index = 0;
	frame->kind = 0;
}

static bool
relay_frame_ready(const struct relay_frame *frame)
{

	return (frame->have == frame->need && frame->have >=
	    RELAY_HEADER_SIZE);
}

static void
relay_frame_begin(struct relay_frame *frame, uint32_t index,
    uint32_t kind, size_t len)
{

	le32enc(frame->buf, RELAY_MAGIC);
	le32enc(frame->buf + 4, index);
	le32enc(frame->buf + 8, kind);
	le32enc(frame->buf + 12, (uint32_t)len);
	frame->have = RELAY_HEADER_SIZE + len;
	frame->need = frame->have;
	frame->offset = 0;
	frame->index = index;
	frame->kind = kind;
}

static int
relay_recv_network(int fd, struct relay_frame *frame, size_t count)
{
	ssize_t got;
	uint32_t length;

	got = recv(fd, frame->buf + frame->have,
	    frame->need - frame->have, MSG_DONTWAIT);
	if (got == 0)
		return (ECONNRESET);
	if (got < 0)
		return (errno == EAGAIN || errno == EWOULDBLOCK ||
		    errno == EINTR ? 0 : errno);
	frame->have += (size_t)got;
	if (frame->have != RELAY_HEADER_SIZE ||
	    frame->need != RELAY_HEADER_SIZE)
		return (0);
	if (le32dec(frame->buf) != RELAY_MAGIC)
		return (EBADMSG);
	frame->index = le32dec(frame->buf + 4);
	frame->kind = le32dec(frame->buf + 8);
	length = le32dec(frame->buf + 12);
	if (frame->index >= count ||
	    (frame->kind != RELAY_DATA && frame->kind != RELAY_FIN) ||
	    length > RELAY_MAX_DATA ||
	    (frame->kind == RELAY_DATA && length == 0) ||
	    (frame->kind == RELAY_FIN && length != 0))
		return (EBADMSG);
	frame->need = RELAY_HEADER_SIZE + length;
	return (0);
}

static int
relay_send_network(int fd, struct relay_frame *frame)
{
	ssize_t sent;

	sent = send(fd, frame->buf + frame->offset,
	    frame->need - frame->offset, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (sent < 0)
		return (errno == EAGAIN || errno == EWOULDBLOCK ||
		    errno == EINTR ? 0 : errno);
	if (sent == 0)
		return (EPIPE);
	frame->offset += (size_t)sent;
	if (frame->offset == frame->need)
		relay_frame_reset(frame);
	return (0);
}

static int
relay_recv_local(const struct migration_vsock_relay_endpoint *endpoint,
    struct relay_conn *conn, struct relay_frame *frame, uint32_t index)
{
	struct iovec iov;
	struct msghdr msg;
	ssize_t got;
	bool fin;

	fin = false;
	if (endpoint->type == VSOCK_MIGRATION_TYPE_SEQPACKET) {
		memset(&msg, 0, sizeof(msg));
		iov.iov_base = frame->buf + RELAY_HEADER_SIZE;
		iov.iov_len = RELAY_MAX_DATA;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		got = recvmsg(endpoint->fd, &msg, MSG_DONTWAIT);
		if (got >= 0 && (msg.msg_flags & MSG_TRUNC) != 0)
			return (EMSGSIZE);
		if (got == 0) {
			if ((msg.msg_flags & MSG_EOR) != 0)
				return (EPROTO);
			fin = true;
		}
	} else {
		got = recv(endpoint->fd, frame->buf + RELAY_HEADER_SIZE,
		    RELAY_STREAM_CHUNK, MSG_DONTWAIT);
		fin = got == 0;
	}
	if (got < 0)
		return (errno == EAGAIN || errno == EWOULDBLOCK ||
		    errno == EINTR ? 0 : errno);
	if (fin) {
		conn->local_fin = true;
		relay_frame_begin(frame, index, RELAY_FIN, 0);
	} else
		relay_frame_begin(frame, index, RELAY_DATA, (size_t)got);
	return (0);
}

static int
relay_send_local(const struct migration_vsock_relay_endpoint *endpoint,
    struct relay_conn *conn, struct relay_frame *frame)
{
	struct iovec iov;
	struct msghdr msg;
	ssize_t sent;
	size_t length;

	if (frame->kind == RELAY_FIN) {
		if (conn->remote_fin)
			return (EBADMSG);
		if (shutdown(endpoint->fd, SHUT_WR) != 0 && errno != ENOTCONN)
			return (errno);
		conn->remote_fin = true;
		relay_frame_reset(frame);
		return (0);
	}
	if (conn->remote_fin)
		return (EBADMSG);
	length = frame->need - RELAY_HEADER_SIZE;
	if (endpoint->type == VSOCK_MIGRATION_TYPE_SEQPACKET) {
		memset(&msg, 0, sizeof(msg));
		iov.iov_base = frame->buf + RELAY_HEADER_SIZE;
		iov.iov_len = length;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		sent = sendmsg(endpoint->fd, &msg,
		    MSG_DONTWAIT | MSG_NOSIGNAL | MSG_EOR);
		if (sent >= 0 && (size_t)sent != length)
			return (EIO);
	} else {
		if (length == 0)
			return (EBADMSG);
		sent = send(endpoint->fd,
		    frame->buf + RELAY_HEADER_SIZE + frame->offset,
		    length - frame->offset, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (sent == 0)
			return (EPIPE);
	}
	if (sent < 0)
		return (errno == EAGAIN || errno == EWOULDBLOCK ||
		    errno == EINTR ? 0 : errno);
	frame->offset += (size_t)sent;
	if (frame->offset == length)
		relay_frame_reset(frame);
	return (0);
}

int
migration_vsock_relay_run(int stream_fd,
    const struct migration_vsock_relay_endpoint *endpoints, size_t count)
{
	struct relay_conn *connections;
	struct relay_frame incoming, outgoing;
	struct pollfd *pollfds;
	uint8_t *rxbuf, *txbuf;
	bool done;
	int error, ready;

	if (stream_fd < 0 || count > VSOCK_MIGRATION_MAX_CONNS ||
	    (count != 0 && endpoints == NULL))
		return (EINVAL);
	for (size_t i = 0; i < count; i++) {
		if (endpoints[i].fd < 0 ||
		    (endpoints[i].type != VSOCK_MIGRATION_TYPE_STREAM &&
		    endpoints[i].type != VSOCK_MIGRATION_TYPE_SEQPACKET))
			return (EINVAL);
	}
	if (count == 0)
		return (0);
	connections = calloc(count, sizeof(*connections));
	pollfds = calloc(count + 1, sizeof(*pollfds));
	rxbuf = malloc(RELAY_HEADER_SIZE + RELAY_MAX_DATA);
	txbuf = malloc(RELAY_HEADER_SIZE + RELAY_MAX_DATA);
	if (connections == NULL || pollfds == NULL || rxbuf == NULL ||
	    txbuf == NULL) {
		error = ENOMEM;
		goto out;
	}
	memset(&incoming, 0, sizeof(incoming));
	memset(&outgoing, 0, sizeof(outgoing));
	incoming.buf = rxbuf;
	outgoing.buf = txbuf;
	relay_frame_reset(&incoming);
	relay_frame_reset(&outgoing);
	error = 0;
	for (;;) {
		done = true;
		for (size_t i = 0; i < count; i++) {
			if (!connections[i].local_fin ||
			    !connections[i].remote_fin) {
				done = false;
				break;
			}
		}
		if (done && outgoing.have == 0 && incoming.have == 0) {
			error = 0;
			break;
		}
		if (relay_frame_ready(&incoming) &&
		    incoming.kind == RELAY_FIN) {
			error = relay_send_local(&endpoints[incoming.index],
			    &connections[incoming.index], &incoming);
			if (error != 0)
				break;
			continue;
		}
		memset(pollfds, 0, (count + 1) * sizeof(*pollfds));
		pollfds[0].fd = stream_fd;
		if (!relay_frame_ready(&incoming))
			pollfds[0].events |= POLLIN;
		if (outgoing.have != 0)
			pollfds[0].events |= POLLOUT;
		if (pollfds[0].events == 0)
			pollfds[0].fd = -1;
		for (size_t i = 0; i < count; i++) {
			pollfds[i + 1].fd = endpoints[i].fd;
			if (outgoing.have == 0 && !connections[i].local_fin)
				pollfds[i + 1].events |= POLLIN;
			if (relay_frame_ready(&incoming) &&
			    incoming.index == i && incoming.kind == RELAY_DATA)
				pollfds[i + 1].events |= POLLOUT;
			if (pollfds[i + 1].events == 0)
				pollfds[i + 1].fd = -1;
		}
		ready = poll(pollfds, count + 1, -1);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			error = errno;
			break;
		}
		if ((pollfds[0].revents & POLLNVAL) != 0) {
			error = EBADF;
			break;
		}
		for (size_t i = 0; i < count; i++) {
			if ((pollfds[i + 1].revents & POLLNVAL) != 0) {
				error = EBADF;
				goto out;
			}
		}
		if (outgoing.have != 0 &&
		    (pollfds[0].revents & (POLLOUT | POLLERR | POLLHUP)) != 0) {
			error = relay_send_network(stream_fd, &outgoing);
			if (error != 0)
				break;
		}
		if (relay_frame_ready(&incoming) &&
		    incoming.kind == RELAY_DATA &&
		    (pollfds[incoming.index + 1].revents &
		    (POLLOUT | POLLERR | POLLHUP)) != 0) {
			error = relay_send_local(&endpoints[incoming.index],
			    &connections[incoming.index], &incoming);
			if (error != 0)
				break;
		}
		if (!relay_frame_ready(&incoming) &&
		    (pollfds[0].revents & (POLLIN | POLLERR | POLLHUP)) != 0) {
			error = relay_recv_network(stream_fd, &incoming, count);
			if (error != 0)
				break;
		}
		if (outgoing.have == 0) {
			for (size_t i = 0; i < count; i++) {
				if (connections[i].local_fin)
					continue;
				if ((pollfds[i + 1].revents &
				    (POLLIN | POLLERR | POLLHUP | POLLNVAL)) == 0)
					continue;
				error = relay_recv_local(&endpoints[i],
				    &connections[i], &outgoing, (uint32_t)i);
				break;
			}
			if (error != 0)
				break;
		}
	}
out:
	free(txbuf);
	free(rxbuf);
	free(pollfds);
	free(connections);
	return (error);
}
