/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "session.h"

int
networkcmp_session_init(struct networkcmp_session *session, uint32_t limit)
{
	size_t i;

	if (session == NULL || limit == 0 ||
	    limit > NETWORKCMP_SESSION_MAX_SOCKETS) {
		errno = EINVAL;
		return (-1);
	}
	memset(session, 0, sizeof(*session));
	session->limit = limit;
	for (i = 0; i < nitems(session->sockets); i++)
		session->sockets[i].fd = -1;
	return (0);
}

void
networkcmp_session_destroy(struct networkcmp_session *session)
{
	size_t i;

	for (i = 0; i < session->limit; i++) {
		if (session->sockets[i].fd != -1)
			close(session->sockets[i].fd);
		session->sockets[i].fd = -1;
	}
}

struct networkcmp_session_socket *
networkcmp_session_lookup(struct networkcmp_session *session,
    struct networkcmp_handle handle)
{
	struct networkcmp_session_socket *socket;

	if (handle.handle == 0 || handle.handle > session->limit) {
		errno = EBADF;
		return (NULL);
	}
	socket = &session->sockets[handle.handle - 1];
	if (socket->fd == -1 || socket->generation != handle.generation) {
		errno = ESTALE;
		return (NULL);
	}
	return (socket);
}

int
networkcmp_session_allocate(struct networkcmp_session *session, int fd,
    uint32_t family, uint32_t type, struct networkcmp_handle *handle)
{
	struct networkcmp_session_socket *socket;
	size_t i;

	if (fd < 0 || handle == NULL ||
	    (family != NETWORKCMP_AF_INET4 &&
	    family != NETWORKCMP_AF_INET6) ||
	    (type != NETWORKCMP_SOCK_STREAM &&
	    type != NETWORKCMP_SOCK_DGRAM)) {
		errno = EINVAL;
		return (-1);
	}
	for (i = 0; i < session->limit; i++) {
		socket = &session->sockets[i];
		if (socket->fd != -1)
			continue;
		socket->generation++;
		if (socket->generation == 0)
			socket->generation = 1;
		socket->fd = fd;
		socket->family = family;
		socket->type = type;
		socket->connect_started = false;
		socket->connect_complete = false;
		handle->handle = i + 1;
		handle->generation = socket->generation;
		return (0);
	}
	errno = EMFILE;
	return (-1);
}

int
networkcmp_session_socket(struct networkcmp_session *session,
    const struct networkcmp_socket_request *request,
    struct networkcmp_handle_reply *reply)
{
	int domain, type, fd, error;

	if (session == NULL || request == NULL || reply == NULL ||
	    (request->family != NETWORKCMP_AF_INET4 &&
	    request->family != NETWORKCMP_AF_INET6) ||
	    (request->type != NETWORKCMP_SOCK_STREAM &&
	    request->type != NETWORKCMP_SOCK_DGRAM) ||
	    request->flags != 0 ||
	    (request->protocol != 0 &&
	    !((request->type == NETWORKCMP_SOCK_STREAM &&
	    request->protocol == IPPROTO_TCP) ||
	    (request->type == NETWORKCMP_SOCK_DGRAM &&
	    request->protocol == IPPROTO_UDP)))) {
		errno = EINVAL;
		return (-1);
	}
	domain = request->family == NETWORKCMP_AF_INET4 ? AF_INET : AF_INET6;
	type = request->type == NETWORKCMP_SOCK_STREAM ? SOCK_STREAM : SOCK_DGRAM;
	fd = socket(domain, type | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    (int)request->protocol);
	if (fd == -1)
		return (-1);
	if (networkcmp_session_allocate(session, fd, request->family,
	    request->type, &reply->socket) == -1) {
		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	return (0);
}

int
networkcmp_session_close(struct networkcmp_session *session,
    struct networkcmp_handle handle)
{
	struct networkcmp_session_socket *socket;

	socket = networkcmp_session_lookup(session, handle);
	if (socket == NULL)
		return (-1);
	close(socket->fd);
	socket->fd = -1;
	return (0);
}

int
networkcmp_session_connect_status(struct networkcmp_session *session,
    struct networkcmp_handle handle)
{
	struct networkcmp_session_socket *socket;
	struct pollfd pollfd;
	socklen_t option_length;
	int socket_error;

	socket = networkcmp_session_lookup(session, handle);
	if (socket == NULL)
		return (-1);
	if (socket->type != NETWORKCMP_SOCK_STREAM) {
		errno = EOPNOTSUPP;
		return (-1);
	}
	if (!socket->connect_started) {
		errno = ENOTCONN;
		return (-1);
	}
	if (socket->connect_complete)
		return (0);
	memset(&pollfd, 0, sizeof(pollfd));
	pollfd.fd = socket->fd;
	pollfd.events = POLLOUT;
	if (poll(&pollfd, 1, 0) == -1)
		return (-1);
	if (pollfd.revents == 0) {
		errno = EINPROGRESS;
		return (-1);
	}
	socket_error = 0;
	option_length = sizeof(socket_error);
	if (getsockopt(socket->fd, SOL_SOCKET, SO_ERROR, &socket_error,
	    &option_length) == -1)
		return (-1);
	if (socket_error != 0) {
		errno = socket_error;
		return (-1);
	}
	socket->connect_complete = true;
	return (0);
}

int
networkcmp_session_setopt(struct networkcmp_session *session,
    struct networkcmp_handle handle, uint32_t level, uint32_t option,
    const void *value, size_t value_length)
{
	struct networkcmp_session_socket *socket;
	int setting;

	if (value == NULL || value_length != sizeof(setting)) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(&setting, value, sizeof(setting));
	switch (level) {
	case SOL_SOCKET:
		switch (option) {
		case SO_KEEPALIVE:
		case SO_REUSEADDR:
			if (setting != 0 && setting != 1) {
				errno = EINVAL;
				return (-1);
			}
			break;
		case SO_SNDBUF:
		case SO_RCVBUF:
			if (setting < 4096 || setting > 16 * 1024 * 1024) {
				errno = EINVAL;
				return (-1);
			}
			break;
		default:
			errno = ENOPROTOOPT;
			return (-1);
		}
		break;
	case IPPROTO_TCP:
		if (option != TCP_NODELAY ||
		    (setting != 0 && setting != 1)) {
			errno = option == TCP_NODELAY ? EINVAL : ENOPROTOOPT;
			return (-1);
		}
		break;
	case IPPROTO_IPV6:
		if (option != IPV6_V6ONLY ||
		    (setting != 0 && setting != 1)) {
			errno = option == IPV6_V6ONLY ? EINVAL : ENOPROTOOPT;
			return (-1);
		}
		break;
	default:
		errno = ENOPROTOOPT;
		return (-1);
	}
	socket = networkcmp_session_lookup(session, handle);
	if (socket == NULL)
		return (-1);
	if ((level == IPPROTO_TCP && socket->type != NETWORKCMP_SOCK_STREAM) ||
	    (level == IPPROTO_IPV6 &&
	    socket->family != NETWORKCMP_AF_INET6)) {
		errno = ENOPROTOOPT;
		return (-1);
	}
	return (setsockopt(socket->fd, (int)level, (int)option, &setting,
	    sizeof(setting)));
}
