/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <notifycmp.h>

#include "transport.h"

int
internal_send(int fd, const void *data, size_t length,
    enum notifycmp_message_role role)
{
	const struct notifycmp_msg *message;
	ssize_t sent;

	if (data == NULL || length < sizeof(*message)) {
		errno = EINVAL;
		return (-1);
	}
	message = data;
	if (notifycmp_validate_message(message, length, role) == -1)
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
    enum notifycmp_message_role role)
{
	struct msghdr message;
	struct iovec iov[2];
	uint8_t overflow;
	ssize_t received;

	if (data == NULL || capacity < sizeof(struct notifycmp_msg)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&message, 0, sizeof(message));
	iov[0].iov_base = data;
	iov[0].iov_len = MIN(capacity, NOTIFYCMP_MAX_MESSAGE);
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
	if (notifycmp_validate_message(data, (size_t)received, role) == -1)
		return (-1);
	return (received);
}

int
internal_send_fd(int socket, const void *data, size_t length, int fd)
{
	struct msghdr message;
	struct iovec iov;
	union {
		struct cmsghdr header;
		char bytes[CMSG_SPACE(sizeof(int))];
	} control;
	struct cmsghdr *header;
	ssize_t sent;

	if (data == NULL || length == 0 || fd < 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(&message, 0, sizeof(message));
	iov.iov_base = __DECONST(void *, data);
	iov.iov_len = length;
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	header = CMSG_FIRSTHDR(&message);
	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(header), &fd, sizeof(fd));
	sent = sendmsg(socket, &message, MSG_NOSIGNAL);
	if (sent == -1)
		return (-1);
	if ((size_t)sent != length) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

ssize_t
internal_receive_fd(int socket, void *data, size_t capacity, int *fd)
{
	struct msghdr message;
	struct iovec iov;
	union {
		struct cmsghdr header;
		char bytes[CMSG_SPACE(sizeof(int))];
	} control;
	struct cmsghdr *header;
	ssize_t received;

	if (data == NULL || capacity == 0 || fd == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*fd = -1;
	memset(&message, 0, sizeof(message));
	iov.iov_base = data;
	iov.iov_len = capacity;
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	received = recvmsg(socket, &message, MSG_CMSG_CLOEXEC | MSG_TRUNC);
	if (received == -1)
		return (-1);
	header = CMSG_FIRSTHDR(&message);
	if (received == 0 || (size_t)received > capacity ||
	    (message.msg_flags & MSG_CTRUNC) != 0 ||
	    header == NULL || CMSG_NXTHDR(&message, header) != NULL ||
	    header->cmsg_level != SOL_SOCKET ||
	    header->cmsg_type != SCM_RIGHTS ||
	    header->cmsg_len != CMSG_LEN(sizeof(*fd))) {
		if (header != NULL && header->cmsg_level == SOL_SOCKET &&
		    header->cmsg_type == SCM_RIGHTS &&
		    header->cmsg_len >= CMSG_LEN(sizeof(*fd))) {
			memcpy(fd, CMSG_DATA(header), sizeof(*fd));
			close(*fd);
			*fd = -1;
		}
		errno = EPROTO;
		return (-1);
	}
	memcpy(fd, CMSG_DATA(header), sizeof(*fd));
	return (received);
}
