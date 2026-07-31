/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "io.h"
#include "session.h"

int
networkcmp_io_send(struct networkcmp_session *session,
    const struct networkcmp_inline_request *request,
    struct networkcmp_inline_reply *reply)
{
	struct networkcmp_session_socket *socket;
	ssize_t sent;

	if (session == NULL || request == NULL || reply == NULL ||
	    request->length == 0 || request->length > NETWORKCMP_INLINE_MAX ||
	    request->flags != 0 || request->timeout_ms != 0) {
		errno = EINVAL;
		return (-1);
	}
	socket = networkcmp_session_lookup(session, request->socket);
	if (socket == NULL)
		return (-1);
	sent = send(socket->fd, request + 1, request->length,
	    MSG_DONTWAIT | MSG_NOSIGNAL);
	if (sent == -1)
		return (-1);
	memset(reply, 0, sizeof(*reply));
	reply->length = (uint32_t)sent;
	return (0);
}

int
networkcmp_io_recv(struct networkcmp_session *session,
    const struct networkcmp_inline_request *request,
    struct networkcmp_inline_reply *reply, void *data)
{
	struct networkcmp_session_socket *socket;
	struct msghdr message;
	struct iovec iov;
	ssize_t received;

	if (session == NULL || request == NULL || reply == NULL || data == NULL ||
	    request->length == 0 || request->length > NETWORKCMP_INLINE_MAX ||
	    request->flags != 0 || request->timeout_ms != 0) {
		errno = EINVAL;
		return (-1);
	}
	socket = networkcmp_session_lookup(session, request->socket);
	if (socket == NULL)
		return (-1);
	memset(&message, 0, sizeof(message));
	iov.iov_base = data;
	iov.iov_len = request->length;
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	received = recvmsg(socket->fd, &message, MSG_DONTWAIT);
	if (received == -1)
		return (-1);
	memset(reply, 0, sizeof(*reply));
	/*
	 * Some kernels report a datagram's original length with MSG_TRUNC.
	 * Never let that length expose bytes beyond the initialized buffer.
	 */
	reply->length = (uint32_t)MIN((size_t)received,
	    (size_t)request->length);
	if (received == 0 && socket->type == NETWORKCMP_SOCK_STREAM)
		reply->flags |= NETWORKCMP_IO_F_EOF;
	if ((message.msg_flags & MSG_TRUNC) != 0 ||
	    (size_t)received > request->length)
		reply->flags |= NETWORKCMP_IO_F_TRUNCATED;
	return (0);
}
