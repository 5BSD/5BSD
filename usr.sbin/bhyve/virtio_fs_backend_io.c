/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_backend_io.h"
#include "virtio_state_range.h"

#define	VFSB_CONTROL_FDS	16U

static int
virtio_fs_backend_path_split(const char *path, char **parentp, char **namep)
{
	char *copy, *slash;

	if (path == NULL || path[0] != '/' || parentp == NULL || namep == NULL)
		return (EINVAL);
	copy = strdup(path);
	if (copy == NULL)
		return (ENOMEM);
	slash = strrchr(copy, '/');
	if (slash == NULL || slash[1] == '\0') {
		free(copy);
		return (EINVAL);
	}
	*namep = strdup(slash + 1);
	if (*namep == NULL) {
		free(copy);
		return (ENOMEM);
	}
	if (slash == copy)
		slash[1] = '\0';
	else
		*slash = '\0';
	*parentp = copy;
	return (0);
}

int
virtio_fs_backend_connect_finish(int fd, uid_t expected_uid,
    gid_t expected_gid)
{
	socklen_t error_len;
	int error;

	error = 0;
	error_len = sizeof(error);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0)
		return (errno);
	if (error_len != sizeof(error))
		return (EPROTO);
	if (error != 0)
		return (error);
	return (virtio_fs_backend_authenticate(fd, expected_uid,
	    expected_gid));
}

int
virtio_fs_backend_connect_start(const char *path, uid_t expected_uid,
    gid_t expected_gid, int *result_fd, bool *connecting)
{
	struct sockaddr_un address;
	char *name, *parent;
	size_t name_len;
	int dfd, error, fd;

	if (result_fd == NULL || connecting == NULL)
		return (EINVAL);
	*result_fd = -1;
	*connecting = false;
	error = virtio_fs_backend_path_split(path, &parent, &name);
	if (error != 0)
		return (error);
	name_len = strlen(name);
	if (name_len == 0 || name_len >= sizeof(address.sun_path)) {
		free(name);
		free(parent);
		return (ENAMETOOLONG);
	}
	dfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	error = errno;
	free(parent);
	if (dfd < 0) {
		free(name);
		return (error);
	}
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		error = errno;
		(void)close(dfd);
		free(name);
		return (error);
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	address.sun_len = (uint8_t)(offsetof(struct sockaddr_un, sun_path) +
	    name_len + 1);
	memcpy(address.sun_path, name, name_len + 1);
	free(name);
	if (connectat(dfd, fd, (struct sockaddr *)&address,
	    address.sun_len) != 0) {
		error = errno;
		(void)close(dfd);
		if (error != EINPROGRESS) {
			(void)close(fd);
			return (error);
		}
		*connecting = true;
	} else {
		(void)close(dfd);
		error = virtio_fs_backend_connect_finish(fd, expected_uid,
		    expected_gid);
		if (error != 0) {
			(void)close(fd);
			return (error);
		}
	}
	*result_fd = fd;
	return (0);
}

static void
virtio_fs_backend_discard_rights(struct msghdr *message)
{
	const unsigned char *end, *start;
	struct cmsghdr *control;
	size_t available, bytes, count, i;
	int *fds;

	end = (const unsigned char *)message->msg_control +
	    message->msg_controllen;
	for (control = CMSG_FIRSTHDR(message); control != NULL;
	    control = CMSG_NXTHDR(message, control)) {
		start = (const unsigned char *)control;
		if (start + sizeof(*control) > end ||
		    control->cmsg_len < CMSG_LEN(0))
			break;
		available = MIN((size_t)(end - start),
		    (size_t)control->cmsg_len);
		if (control->cmsg_level == SOL_SOCKET &&
		    control->cmsg_type == SCM_RIGHTS &&
		    available >= CMSG_LEN(0)) {
			bytes = available - CMSG_LEN(0);
			count = bytes / sizeof(*fds);
			fds = (int *)(void *)CMSG_DATA(control);
			for (i = 0; i < count; i++)
				(void)close(fds[i]);
		}
		if (control->cmsg_len > (size_t)(end - start))
			break;
	}
}

int
virtio_fs_backend_authenticate(int fd, uid_t expected_uid,
    gid_t expected_gid)
{
	struct sockaddr_un peer;
	socklen_t peer_len, type_len;
	gid_t peer_gid;
	uid_t peer_uid;
	int type;

	type_len = sizeof(type);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_len) != 0)
		return (errno);
	if (type_len != sizeof(type) || type != SOCK_SEQPACKET)
		return (EPROTOTYPE);
	peer_len = sizeof(peer);
	if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0)
		return (errno);
	if (peer_len < offsetof(struct sockaddr_un, sun_path) ||
	    peer.sun_family != AF_UNIX)
		return (EAFNOSUPPORT);
	if (getpeereid(fd, &peer_uid, &peer_gid) != 0)
		return (errno);
	if ((expected_uid != (uid_t)-1 && peer_uid != expected_uid) ||
	    (expected_gid != (gid_t)-1 && peer_gid != expected_gid))
		return (EACCES);
	return (0);
}

int
virtio_fs_backend_send_frame(int fd,
    const struct virtio_fs_backend_header *header, const void *payload)
{
	struct iovec vectors[2];
	struct msghdr message;
	uint8_t wire[VIRTIO_FS_BACKEND_HEADER_SIZE];
	size_t total;
	ssize_t sent;
	int error;

	if (header == NULL ||
	    (payload == NULL && header->payload_len != 0))
		return (EINVAL);
	error = virtio_fs_backend_header_encode(header, wire);
	if (error != 0)
		return (error);
	vectors[0].iov_base = wire;
	vectors[0].iov_len = sizeof(wire);
	vectors[1].iov_base = __DECONST(void *, payload);
	vectors[1].iov_len = header->payload_len;
	memset(&message, 0, sizeof(message));
	message.msg_iov = vectors;
	message.msg_iovlen = header->payload_len == 0 ? 1 : 2;
	total = sizeof(wire) + header->payload_len;
	do {
		sent = sendmsg(fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
	} while (sent < 0 && errno == EINTR);
	if (sent < 0)
		return (errno);
	if ((size_t)sent != total)
		return (EIO);
	return (0);
}

int
virtio_fs_backend_receive_frame(int fd,
    struct virtio_fs_backend_header *header, void *payload,
    size_t payload_capacity, size_t *payload_len)
{
	union {
		struct cmsghdr alignment;
		unsigned char bytes[CMSG_SPACE(
		    sizeof(int) * VFSB_CONTROL_FDS)];
	} control_buffer;
	struct virtio_fs_backend_header decoded;
	uint8_t wire[VIRTIO_FS_BACKEND_HEADER_SIZE];
	struct iovec vectors[2];
	struct msghdr message;
	size_t received_payload;
	ssize_t received;
	int error;

	if (header == NULL || payload_len == NULL ||
	    (payload == NULL && payload_capacity != 0) ||
	    payload_capacity > VIRTIO_FS_BACKEND_MAX_FRAME)
		return (EINVAL);
	/*
	 * This is a three-output transaction.  Reject aliases before recvmsg()
	 * consumes the record so a caller can correct the buffers and retry.
	 */
	if (virtio_state_ranges_overlap(header, sizeof(*header), payload,
	    payload_capacity) ||
	    virtio_state_ranges_overlap(header, sizeof(*header), payload_len,
	    sizeof(*payload_len)) ||
	    virtio_state_ranges_overlap(payload, payload_capacity, payload_len,
	    sizeof(*payload_len)))
		return (EINVAL);
	*payload_len = 0;
	vectors[0].iov_base = wire;
	vectors[0].iov_len = sizeof(wire);
	vectors[1].iov_base = payload;
	vectors[1].iov_len = payload_capacity;
	memset(&message, 0, sizeof(message));
	memset(&control_buffer, 0, sizeof(control_buffer));
	message.msg_iov = vectors;
	message.msg_iovlen = payload_capacity == 0 ? 1 : 2;
	message.msg_control = control_buffer.bytes;
	message.msg_controllen = sizeof(control_buffer.bytes);
	do {
		received = recvmsg(fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
	} while (received < 0 && errno == EINTR);
	if (received < 0)
		return (errno);
	if (received == 0)
		return (ECONNRESET);
	if (message.msg_controllen != 0)
		virtio_fs_backend_discard_rights(&message);
	if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
		return (EMSGSIZE);
	if (message.msg_controllen != 0)
		return (EPROTO);
	if ((size_t)received < sizeof(wire))
		return (EPROTO);
	error = virtio_fs_backend_header_decode(wire, sizeof(wire),
	    &decoded);
	if (error != 0)
		return (error);
	if (decoded.payload_len > payload_capacity)
		return (EMSGSIZE);
	received_payload = (size_t)received - sizeof(wire);
	if (decoded.payload_len != received_payload)
		return (EPROTO);
	*header = decoded;
	*payload_len = received_payload;
	return (0);
}
