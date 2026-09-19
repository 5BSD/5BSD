/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <notify.h>
#include <notify_server.h>

#include "transport.h"

int
internal_send(int fd, const void *data, size_t length,
    enum notify_message_role role)
{
	const struct notify_msg *message;
	ssize_t sent;

	if (data == NULL || length < sizeof(*message)) {
		errno = EINVAL;
		return (-1);
	}
	message = data;
	if (notify_validate_message(message, length, role) == -1)
		return (-1);
	sent = send(fd, data, length, MSG_NOSIGNAL);
	if (sent == -1)
		return (-1);
	if ((size_t)sent != length) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

ssize_t
internal_receive(int fd, void *data, size_t capacity,
    enum notify_message_role role)
{
	struct msghdr message;
	struct iovec iov[2];
	uint8_t overflow;
	ssize_t received;

	if (data == NULL || capacity < sizeof(struct notify_msg)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&message, 0, sizeof(message));
	iov[0].iov_base = data;
	iov[0].iov_len = MIN(capacity, NOTIFY_MAX_MESSAGE);
	iov[1].iov_base = &overflow;
	iov[1].iov_len = sizeof(overflow);
	message.msg_iov = iov;
	message.msg_iovlen = nitems(iov);
	received = recvmsg(fd, &message, 0);
	if (received == -1)
		return (-1);
	if (received == 0) {
		errno = ECONNRESET;
		return (-1);
	}
	if ((size_t)received > iov[0].iov_len ||
	    (message.msg_flags & MSG_TRUNC) != 0) {
		errno = EPROTO;
		return (-1);
	}
	if (notify_validate_message(data, (size_t)received, role) == -1)
		return (-1);
	return (received);
}
