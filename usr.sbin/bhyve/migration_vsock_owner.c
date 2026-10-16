/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "migration_vsock_owner.h"
#include "vsock_migration_state.h"

#define OWNER_MAGIC 0x314f5356U /* VSO1 */
#define OWNER_PREPARE 1U
#define OWNER_CANCEL 2U
#define OWNER_ACTIVATE 3U
#define OWNER_APPEND 4U
#define OWNER_READY 5U
#define OWNER_HEADER_SIZE 16U
#define OWNER_BATCH_CONNS 128U
#define OWNER_MAX_FDS (OWNER_BATCH_CONNS + 1U)
#define OWNER_MAX_PACKET (OWNER_HEADER_SIZE + \
    OWNER_BATCH_CONNS * sizeof(uint32_t))

static int owner_control = -1;

static void
owner_close_fds(int *fds, size_t count)
{

	for (size_t i = 0; i < count; i++) {
		if (fds[i] >= 0) {
			close(fds[i]);
			fds[i] = -1;
		}
	}
}

static int
owner_limit_received(int *fds, size_t count, bool stream_first)
{
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;

	for (size_t i = 0; i < count; i++) {
		cap_rights_init(&rights, CAP_EVENT, CAP_RECV, CAP_SEND,
		    CAP_SHUTDOWN);
		if (stream_first && i == 0)
			cap_rights_clear(&rights, CAP_SHUTDOWN);
		if (cap_rights_limit(fds[i], &rights) != 0 ||
		    cap_xfer_limit(fds[i], CAP_XFER_NONE) != 0 ||
		    cap_cloexec_limit(fds[i], CAP_CLOEXEC_LOCKED) != 0 ||
		    cap_clofork_limit(fds[i], CAP_CLOFORK_LOCKED) != 0)
			return (errno != 0 ? errno : EIO);
	}
#else
	(void)fds;
	(void)count;
	(void)stream_first;
#endif
	return (0);
}

static int
owner_reply(int fd, uint32_t command, int status)
{
	uint8_t wire[OWNER_HEADER_SIZE];
	ssize_t sent;

	le32enc(wire, OWNER_MAGIC);
	le32enc(wire + 4, command);
	le32enc(wire + 8, (uint32_t)status);
	le32enc(wire + 12, 0);
	sent = send(fd, wire, sizeof(wire), MSG_NOSIGNAL);
	return (sent == sizeof(wire) ? 0 : sent < 0 ? errno : EIO);
}

static int
owner_receive(int fd, uint8_t wire[OWNER_MAX_PACKET], int fds[OWNER_MAX_FDS],
    size_t *fd_count, size_t *wire_len)
{
	char control[CMSG_SPACE(OWNER_MAX_FDS * sizeof(int))];
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	ssize_t got;
	bool malformed;

	*fd_count = 0;
	*wire_len = 0;
	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	iov.iov_base = wire;
	iov.iov_len = OWNER_MAX_PACKET;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	got = recvmsg(fd, &msg, MSG_CMSG_CLOEXEC);
	if (got < 0)
		return (errno == EINTR ? EINTR : errno);
	*wire_len = (size_t)got;
	malformed = false;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		size_t bytes, count;

		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS)
			continue;
		if (cmsg->cmsg_len < CMSG_LEN(0)) {
			malformed = true;
			continue;
		}
		bytes = cmsg->cmsg_len - CMSG_LEN(0);
		count = bytes / sizeof(int);
		if (bytes % sizeof(int) != 0 ||
		    count > OWNER_MAX_FDS - *fd_count) {
			int received;

			for (size_t i = 0; i < count; i++) {
				memcpy(&received, CMSG_DATA(cmsg) + i * sizeof(int),
				    sizeof(received));
				close(received);
			}
			malformed = true;
			continue;
		}
		memcpy(fds + *fd_count, CMSG_DATA(cmsg), bytes);
		*fd_count += count;
	}
	if (malformed || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
		return (EMSGSIZE);
	if (got == 0)
		return (ENOTCONN);
	return (0);
}

static int
owner_child_loop(int fd)
{
	struct migration_vsock_relay_endpoint endpoints[
	    VSOCK_MIGRATION_MAX_CONNS];
	uint8_t wire[OWNER_MAX_PACKET];
	int fds[OWNER_MAX_FDS];
	size_t fd_count, wire_len;
	uint32_t command, count, prepared_count, expected_count, offset;
	bool prepared;
	int error, stream_fd;

	prepared = false;
	prepared_count = 0;
	expected_count = 0;
	stream_fd = -1;
	for (size_t i = 0; i < VSOCK_MIGRATION_MAX_CONNS; i++)
		endpoints[i].fd = -1;
	for (;;) {
		for (size_t i = 0; i < OWNER_MAX_FDS; i++)
			fds[i] = -1;
		error = owner_receive(fd, wire, fds, &fd_count, &wire_len);
		if (error == EINTR)
			continue;
		if (error != 0) {
			owner_close_fds(fds, fd_count);
			break;
		}
		if (wire_len < OWNER_HEADER_SIZE ||
		    le32dec(wire) != OWNER_MAGIC) {
			owner_close_fds(fds, fd_count);
			error = EPROTO;
			break;
		}
		command = le32dec(wire + 4);
		count = le32dec(wire + 8);
		offset = le32dec(wire + 12);
		if (command == OWNER_PREPARE || command == OWNER_APPEND) {
			bool valid_types;

			if (count > OWNER_BATCH_CONNS ||
			    wire_len != OWNER_HEADER_SIZE + count * sizeof(uint32_t) ||
			    fd_count != (size_t)count +
			    (command == OWNER_PREPARE ? 1 : 0) ||
			    (command == OWNER_PREPARE &&
			    (prepared || offset > VSOCK_MIGRATION_MAX_CONNS ||
			    count > offset)) ||
			    (command == OWNER_APPEND &&
			    (!prepared || count == 0 ||
			    offset != prepared_count ||
			    count > expected_count - prepared_count))) {
				owner_close_fds(fds, fd_count);
				if (owner_reply(fd, command, EINVAL) != 0)
					break;
				continue;
			}
			valid_types = true;
			for (uint32_t i = 0; i < count; i++) {
				uint32_t type = le32dec(wire + OWNER_HEADER_SIZE +
				    i * sizeof(uint32_t));
				if (type != VSOCK_MIGRATION_TYPE_STREAM &&
				    type != VSOCK_MIGRATION_TYPE_SEQPACKET) {
					valid_types = false;
					break;
				}
			}
			if (!valid_types) {
				owner_close_fds(fds, fd_count);
				if (owner_reply(fd, command, EINVAL) != 0)
					break;
				continue;
			}
			error = owner_limit_received(fds, fd_count,
			    command == OWNER_PREPARE);
			if (error != 0) {
				owner_close_fds(fds, fd_count);
				if (owner_reply(fd, command, error) != 0)
					break;
				continue;
			}
			for (uint32_t i = 0; i < count; i++) {
				uint32_t slot = command == OWNER_PREPARE ? i :
				    prepared_count + i;

				endpoints[slot].fd = fds[i +
				    (command == OWNER_PREPARE ? 1 : 0)];
				endpoints[slot].type = le32dec(wire +
				    OWNER_HEADER_SIZE + i * sizeof(uint32_t));
			}
			if (command == OWNER_PREPARE) {
				stream_fd = fds[0];
				prepared = true;
				prepared_count = count;
				expected_count = offset;
			} else
				prepared_count += count;
			if (owner_reply(fd, command, 0) != 0)
				break;
			continue;
		}
		owner_close_fds(fds, fd_count);
		if (wire_len != OWNER_HEADER_SIZE || count != 0 || offset != 0) {
			if (owner_reply(fd, command, EINVAL) != 0)
				break;
			continue;
		}
		if (command == OWNER_CANCEL) {
			if (prepared) {
				for (size_t i = 0; i < prepared_count; i++) {
					if (endpoints[i].fd >= 0)
						close(endpoints[i].fd);
					endpoints[i].fd = -1;
				}
				close(stream_fd);
				stream_fd = -1;
				prepared = false;
				prepared_count = 0;
				expected_count = 0;
			}
			if (owner_reply(fd, command, 0) != 0)
				break;
			continue;
		}
		if (command == OWNER_ACTIVATE && prepared &&
		    prepared_count == expected_count) {
			if (owner_reply(fd, command, 0) != 0)
				break;
			return (migration_vsock_relay_run(stream_fd, endpoints,
			    prepared_count));
		}
		if (owner_reply(fd, command, EINVAL) != 0)
			break;
	}
	if (prepared) {
		for (size_t i = 0; i < prepared_count; i++) {
			if (endpoints[i].fd >= 0)
				close(endpoints[i].fd);
		}
		close(stream_fd);
	}
	return (error == ENOTCONN ? 0 : error);
}

int
migration_vsock_owner_start(pid_t *pid_out)
{
	struct timeval timeout = { .tv_sec = 30 };
	uint8_t reply[OWNER_HEADER_SIZE];
	int pair[2];
	pid_t pid;
	ssize_t got;
	int error;

	if (owner_control >= 0)
		return (EALREADY);
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
	    pair) != 0)
		return (errno);
	pid = fork();
	if (pid < 0) {
		error = errno;

		close(pair[0]);
		close(pair[1]);
		return (error);
	}
	if (pid == 0) {
		close(pair[0]);
		if (pair[1] != 3) {
			if (dup2(pair[1], 3) < 0)
				_exit(1);
			close(pair[1]);
		}
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		closefrom(4);
#ifndef WITHOUT_CAPSICUM
		if (cap_enter() != 0)
			_exit(1);
#endif
		if (owner_reply(3, OWNER_READY, 0) != 0)
			_exit(1);
		error = owner_child_loop(3);
		close(3);
		_exit(error == 0 ? 0 : 1);
	}
	close(pair[1]);
	if (setsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &timeout,
	    sizeof(timeout)) != 0) {
		error = errno;
		goto failed;
	}
	got = recv(pair[0], reply, sizeof(reply), 0);
	if (got != sizeof(reply) || le32dec(reply) != OWNER_MAGIC ||
	    le32dec(reply + 4) != OWNER_READY || le32dec(reply + 8) != 0 ||
	    le32dec(reply + 12) != 0) {
		error = got < 0 ? errno : EPROTO;
		goto failed;
	}
	owner_control = pair[0];
	if (pid_out != NULL)
		*pid_out = pid;
	return (0);
failed:
	close(pair[0]);
	while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
		;
	return (error);
}

static int
owner_request(uint32_t command, int stream_fd,
    const struct migration_vsock_relay_endpoint *endpoints, size_t count,
    uint32_t detail)
{
	char control[CMSG_SPACE(OWNER_MAX_FDS * sizeof(int))];
	uint8_t wire[OWNER_MAX_PACKET], reply[OWNER_HEADER_SIZE];
	int fds[OWNER_MAX_FDS];
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	ssize_t sent, got;
	size_t length;

	if (owner_control < 0)
		return (ENXIO);
	if (command == OWNER_PREPARE || command == OWNER_APPEND) {
		if ((command == OWNER_PREPARE && stream_fd < 0) ||
		    (command == OWNER_APPEND && stream_fd >= 0) ||
		    count > OWNER_BATCH_CONNS ||
		    (count != 0 && endpoints == NULL))
			return (EINVAL);
		if (command == OWNER_PREPARE)
			fds[0] = stream_fd;
		for (size_t i = 0; i < count; i++) {
			if (endpoints[i].fd < 0 ||
			    (endpoints[i].type != VSOCK_MIGRATION_TYPE_STREAM &&
			    endpoints[i].type != VSOCK_MIGRATION_TYPE_SEQPACKET))
				return (EINVAL);
			fds[i + (command == OWNER_PREPARE ? 1 : 0)] =
			    endpoints[i].fd;
		}
	} else if (count != 0 || endpoints != NULL || stream_fd >= 0 ||
	    detail != 0)
		return (EINVAL);
	le32enc(wire, OWNER_MAGIC);
	le32enc(wire + 4, command);
	le32enc(wire + 8, (uint32_t)count);
	le32enc(wire + 12, detail);
	length = OWNER_HEADER_SIZE;
	if (command == OWNER_PREPARE || command == OWNER_APPEND) {
		for (size_t i = 0; i < count; i++)
			le32enc(wire + length + i * sizeof(uint32_t),
			    endpoints[i].type);
		length += count * sizeof(uint32_t);
	}
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = wire;
	iov.iov_len = length;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (command == OWNER_PREPARE || command == OWNER_APPEND) {
		size_t fd_count = count +
		    (command == OWNER_PREPARE ? 1 : 0);

		memset(control, 0, sizeof(control));
		msg.msg_control = control;
		msg.msg_controllen = CMSG_SPACE(fd_count * sizeof(int));
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(fd_count * sizeof(int));
		memcpy(CMSG_DATA(cmsg), fds, fd_count * sizeof(int));
	}
	sent = sendmsg(owner_control, &msg, MSG_NOSIGNAL);
	if (sent < 0)
		return (errno);
	if ((size_t)sent != length)
		return (EIO);
	got = recv(owner_control, reply, sizeof(reply), 0);
	if (got < 0)
		return (errno);
	if (got != sizeof(reply) || le32dec(reply) != OWNER_MAGIC ||
	    le32dec(reply + 4) != command || le32dec(reply + 12) != 0)
		return (EPROTO);
	return ((int)le32dec(reply + 8));
}

int
migration_vsock_owner_prepare(int stream_fd,
    const struct migration_vsock_relay_endpoint *endpoints, size_t count)
{
	size_t batch;
	int error, rollback_error;

	if (stream_fd < 0 || count > VSOCK_MIGRATION_MAX_CONNS ||
	    (count != 0 && endpoints == NULL))
		return (EINVAL);
	for (size_t i = 0; i < count; i++) {
		if (endpoints[i].fd < 0 ||
		    (endpoints[i].type != VSOCK_MIGRATION_TYPE_STREAM &&
		    endpoints[i].type != VSOCK_MIGRATION_TYPE_SEQPACKET))
			return (EINVAL);
	}
	if (owner_control < 0)
		return (ENXIO);
	batch = count < OWNER_BATCH_CONNS ? count : OWNER_BATCH_CONNS;
	error = owner_request(OWNER_PREPARE, stream_fd, endpoints, batch,
	    (uint32_t)count);
	if (error != 0)
		goto rollback;
	for (size_t offset = batch; offset < count; offset += batch) {
		batch = count - offset < OWNER_BATCH_CONNS ?
		    count - offset : OWNER_BATCH_CONNS;
		error = owner_request(OWNER_APPEND, -1, endpoints + offset,
		    batch, (uint32_t)offset);
		if (error != 0)
			goto rollback;
	}
	return (0);
rollback:
	/* The request may have arrived even if its acknowledgement did not. */
	rollback_error = migration_vsock_owner_cancel();
	return (rollback_error == 0 ? error : EPROTO);
}

int
migration_vsock_owner_cancel(void)
{

	return (owner_request(OWNER_CANCEL, -1, NULL, 0, 0));
}

int
migration_vsock_owner_activate(void)
{
	int error;

	error = owner_request(OWNER_ACTIVATE, -1, NULL, 0, 0);
	if (error == 0)
		migration_vsock_owner_detach();
	return (error);
}

void
migration_vsock_owner_detach(void)
{

	if (owner_control >= 0)
		close(owner_control);
	owner_control = -1;
}
