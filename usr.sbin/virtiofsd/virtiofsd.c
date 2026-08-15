/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_backend_io.h"
#include "virtiofsd_export.h"
#include "virtiofsd_fuse.h"
#include "virtiofsd_server.h"
#include "virtiofsd_session.h"

#define	VIRTIOFSD_DEFAULT_NODES		65536U
#define	VIRTIOFSD_DEFAULT_HANDLES	65536U
#define	VIRTIOFSD_DEFAULT_INFLIGHT	1024U
#define	VIRTIOFSD_DEFAULT_WORKERS	4U
#define	VIRTIOFSD_DEFAULT_MESSAGE	(16U * 1024U * 1024U)
#define	VIRTIOFSD_DEFAULT_PENDING	(256U * 1024U * 1024U)
#define	VIRTIOFSD_IO_BUDGET		64U
/*
 * A backend socket is normally private to one bhyve instance.  Bound the
 * pre-HELLO phase nonetheless: an authenticated peer can otherwise connect
 * and remain silent forever, holding the daemon's only accept loop.
 */
#ifndef VIRTIOFSD_HELLO_TIMEOUT_MS
#define	VIRTIOFSD_HELLO_TIMEOUT_MS	5000
#endif

static int signal_pipe[2] = { -1, -1 };

static void
signal_handler(int signal_number __unused)
{
	uint8_t byte;

	byte = 1;
	if (signal_pipe[1] >= 0)
		(void)write(signal_pipe[1], &byte, sizeof(byte));
}

static uint32_t
parse_u32(const char *value, uint32_t minimum, uint32_t maximum,
    const char *description)
{
	const char *error;
	long long parsed;

	parsed = strtonum(value, minimum, maximum, &error);
	if (error != NULL)
		errx(64, "%s is %s: %s", description, error, value);
	return ((uint32_t)parsed);
}

static bool
pending_limit_valid(uint32_t maximum_message, uint32_t maximum_pending)
{

	return (maximum_message != 0 &&
	    maximum_message <= maximum_pending / 2U);
}

static void
limit_rights(int fd, cap_rights_t *rights, const char *description)
{

	if (cap_rights_limit(fd, rights) != 0)
		err(1, "cap_rights_limit %s", description);
}

static void
sandbox_descriptors(int rootfd, int parentfd, int listener)
{
	cap_rights_t rights;

	/*
	 * Rights inherited by descriptors opened beneath the export must cover
	 * read-only file and directory operation, but never namespace mutation.
	 */
	cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_SEEK, CAP_FSTAT,
	    CAP_FSTATFS, CAP_FCNTL);
	limit_rights(rootfd, &rights, "export");

	/* The parent is retained solely to unlink our owned socket at exit. */
	cap_rights_init(&rights, CAP_UNLINKAT);
	limit_rights(parentfd, &rights, "socket parent");

	/*
	 * Accepted sockets inherit a subset of listener rights.  Include peer
	 * authentication, framed I/O, and poll/kqueue readiness explicitly.
	 */
	cap_rights_init(&rights, CAP_ACCEPT, CAP_EVENT, CAP_GETPEERNAME,
	    CAP_GETSOCKOPT, CAP_READ, CAP_WRITE, CAP_RECV, CAP_SEND);
	limit_rights(listener, &rights, "listener");

	cap_rights_init(&rights, CAP_EVENT, CAP_READ);
	limit_rights(signal_pipe[0], &rights, "signal read pipe");
	cap_rights_init(&rights, CAP_WRITE);
	limit_rights(signal_pipe[1], &rights, "signal write pipe");
}

static void
usage(void)
{

	fprintf(stderr,
	    "usage: virtiofsd -r export -s socket [-U uid] [-G gid]\\n"
	    "                 [-n nodes] [-h handles] [-i inflight]\\n"
	    "                 [-m message-bytes] [-b pending-bytes]\\n"
	    "                 [-w workers]\\n");
	exit(64);
}

static int
socket_parent(const char *path, char **parent, char **name)
{
	char *copy, *slash;

	if (path == NULL || path[0] != '/' || parent == NULL || name == NULL)
		return (EINVAL);
	copy = strdup(path);
	if (copy == NULL)
		return (ENOMEM);
	slash = strrchr(copy, '/');
	if (slash == NULL || slash[1] == '\0' ||
	    strcmp(slash + 1, ".") == 0 || strcmp(slash + 1, "..") == 0) {
		free(copy);
		return (EINVAL);
	}
	*name = strdup(slash + 1);
	if (*name == NULL) {
		free(copy);
		return (ENOMEM);
	}
	if (slash == copy)
		slash[1] = '\0';
	else
		*slash = '\0';
	*parent = copy;
	return (0);
}

static int
listener_create(const char *path, int *parentfd, char **socket_name)
{
	struct sockaddr_un address;
	char *name, *parent;
	size_t length;
	int error, fd;
	bool bound;

	error = socket_parent(path, &parent, &name);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	*parentfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	free(parent);
	if (*parentfd == -1) {
		error = errno;
		free(name);
		errno = error;
		return (-1);
	}
	length = strlen(name);
	if (length >= sizeof(address.sun_path)) {
		(void)close(*parentfd);
		free(name);
		errno = ENAMETOOLONG;
		return (-1);
	}
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		error = errno;
		(void)close(*parentfd);
		free(name);
		errno = error;
		return (-1);
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	address.sun_len = (uint8_t)(offsetof(struct sockaddr_un, sun_path) +
	    length + 1);
	memcpy(address.sun_path, name, length + 1);
	bound = false;
	if (bindat(*parentfd, fd, (struct sockaddr *)&address,
	    address.sun_len) != 0)
		goto fail;
	bound = true;
	if (fchmodat(*parentfd, name, 0600,
	    AT_SYMLINK_NOFOLLOW | AT_RESOLVE_BENEATH) != 0 ||
	    listen(fd, 8) != 0)
		goto fail;
	*socket_name = name;
	return (fd);
fail:
	error = errno;
	(void)close(fd);
	if (bound)
		(void)unlinkat(*parentfd, name, 0);
	(void)close(*parentfd);
	free(name);
	errno = error;
	return (-1);
}

static int
client_run(int client, int rootfd, uid_t expected_uid, gid_t expected_gid,
    uint32_t nodes, uint32_t handles, uint32_t maximum_message,
    uint32_t maximum_inflight, uint32_t maximum_pending,
    unsigned int workers)
{
	struct virtio_fs_backend_header header;
	struct virtiofsd_export *export;
	struct virtiofsd_server *server;
	struct virtiofsd_session *session;
	struct pollfd descriptors[3];
	uint8_t *payload;
	size_t payload_len;
	unsigned int budget;
	int error, result, timeout;
	bool done, hello_seen;

	error = virtio_fs_backend_authenticate(client, expected_uid,
	    expected_gid);
	if (error != 0)
		return (error);
	export = NULL;
	session = NULL;
	server = NULL;
	payload = malloc(maximum_message);
	if (payload == NULL)
		return (ENOMEM);
	error = virtiofsd_export_create(rootfd, nodes, &export);
	if (error != 0)
		goto out;
	error = virtiofsd_session_create(export, handles, maximum_message,
	    &session);
	if (error != 0)
		goto out;
	error = virtiofsd_server_create(session, maximum_message,
	    maximum_inflight, maximum_pending, workers, &server);
	if (error != 0)
		goto out;
	done = false;
	hello_seen = false;
	while (!done) {
		descriptors[0] = (struct pollfd) {
			.fd = client,
			.events = POLLIN |
			    (virtiofsd_server_wants_write(server) ?
			    POLLOUT : 0),
		};
		descriptors[1] = (struct pollfd) {
			.fd = virtiofsd_server_wakeup_fd(server),
			.events = POLLIN,
		};
		descriptors[2] = (struct pollfd) {
			.fd = signal_pipe[0],
			.events = POLLIN,
		};
		/* Do not let a connected but silent peer starve later clients. */
		timeout = hello_seen ? -1 : VIRTIOFSD_HELLO_TIMEOUT_MS;
		do {
			result = poll(descriptors, nitems(descriptors), timeout);
		} while (result < 0 && errno == EINTR);
		if (result == 0) {
			error = ETIMEDOUT;
			break;
		}
		if (result < 0) {
			error = errno;
			break;
		}
		if ((descriptors[2].revents & POLLIN) != 0) {
			error = ECANCELED;
			break;
		}
		if ((descriptors[1].revents & POLLIN) != 0)
			virtiofsd_server_drain_wakeup(server);
		if ((descriptors[0].revents & POLLIN) != 0) {
			for (budget = 0; budget < VIRTIOFSD_IO_BUDGET; budget++) {
				error = virtio_fs_backend_receive_frame(client,
				    &header, payload, maximum_message,
				    &payload_len);
				if (error == EAGAIN || error == EWOULDBLOCK) {
					error = 0;
					break;
				}
				if (error != 0)
					break;
				error = virtiofsd_server_handle(server, &header,
				    payload_len == 0 ? NULL : payload,
				    payload_len);
				if (error != 0)
					break;
				if (header.type == VIRTIO_FS_BACKEND_HELLO)
					hello_seen = true;
			}
			if (error != 0)
				break;
		}
		if ((descriptors[0].revents & (POLLERR | POLLHUP |
		    POLLNVAL)) != 0) {
			error = ECONNRESET;
			break;
		}
		if ((descriptors[0].revents & POLLOUT) != 0 ||
		    descriptors[1].revents != 0) {
			for (budget = 0; budget < VIRTIOFSD_IO_BUDGET; budget++) {
				error = virtiofsd_server_flush_one(server, client);
				if (error == EAGAIN || error == EWOULDBLOCK ||
				    error == ENOENT) {
					error = 0;
					break;
				}
				if (error != 0)
					break;
			}
			if (error != 0)
				break;
		}
		error = virtiofsd_server_error(server);
		if (error != 0)
			break;
		done = virtiofsd_server_closed(server) &&
		    !virtiofsd_server_wants_write(server);
	}
out:
	virtiofsd_server_destroy(server);
	virtiofsd_session_destroy(session);
	virtiofsd_export_destroy(export);
	free(payload);
	return (error);
}

int
main(int argc, char **argv)
{
	struct sigaction action;
	const char *export_path, *socket_path;
	char *socket_name;
	uint32_t handles, maximum_inflight, maximum_message;
	uint32_t maximum_pending, nodes, workers;
	gid_t expected_gid;
	uid_t expected_uid;
	int ch, client, error, listener, parentfd, rootfd;

	export_path = NULL;
	socket_path = NULL;
	nodes = VIRTIOFSD_DEFAULT_NODES;
	handles = VIRTIOFSD_DEFAULT_HANDLES;
	maximum_inflight = VIRTIOFSD_DEFAULT_INFLIGHT;
	maximum_message = VIRTIOFSD_DEFAULT_MESSAGE;
	maximum_pending = VIRTIOFSD_DEFAULT_PENDING;
	workers = VIRTIOFSD_DEFAULT_WORKERS;
	expected_uid = geteuid();
	expected_gid = getegid();
	while ((ch = getopt(argc, argv, "G:U:b:h:i:m:n:r:s:w:")) != -1) {
		switch (ch) {
		case 'G':
			expected_gid = (gid_t)parse_u32(optarg, 0, UINT32_MAX,
			    "gid");
			break;
		case 'U':
			expected_uid = (uid_t)parse_u32(optarg, 0, UINT32_MAX,
			    "uid");
			break;
		case 'b':
			maximum_pending = parse_u32(optarg, 1,
			    VIRTIO_FS_BACKEND_MAX_PENDING_BYTES,
			    "pending bytes");
			break;
		case 'h':
			handles = parse_u32(optarg, 1, UINT32_MAX, "handles");
			break;
		case 'i':
			maximum_inflight = parse_u32(optarg, 1,
			    VIRTIO_FS_BACKEND_MAX_INFLIGHT, "inflight");
			break;
		case 'm':
			maximum_message = parse_u32(optarg,
			    VIRTIOFSD_FUSE_IN_HEADER_SIZE,
			    VIRTIO_FS_BACKEND_MAX_FRAME, "message bytes");
			break;
		case 'n':
			nodes = parse_u32(optarg, 2, UINT32_MAX - 1, "nodes");
			break;
		case 'r':
			export_path = optarg;
			break;
		case 's':
			socket_path = optarg;
			break;
		case 'w':
			workers = parse_u32(optarg, 1,
			    VIRTIO_FS_BACKEND_MAX_INFLIGHT, "workers");
			break;
		default:
			usage();
		}
	}
	if (optind != argc || export_path == NULL || socket_path == NULL ||
	    workers > maximum_inflight ||
	    !pending_limit_valid(maximum_message, maximum_pending))
		usage();
	closefrom(3);
	rootfd = open(export_path, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (rootfd == -1)
		err(1, "open export %s", export_path);
	parentfd = -1;
	socket_name = NULL;
	listener = listener_create(socket_path, &parentfd, &socket_name);
	if (listener == -1)
		err(1, "listen %s", socket_path);
	if (pipe2(signal_pipe, O_CLOEXEC | O_NONBLOCK) != 0)
		err(1, "signal pipe");
	memset(&action, 0, sizeof(action));
	action.sa_handler = signal_handler;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, NULL) != 0 ||
	    sigaction(SIGTERM, &action, NULL) != 0)
		err(1, "sigaction");
	sandbox_descriptors(rootfd, parentfd, listener);
	if (cap_enter() != 0)
		err(1, "cap_enter");

	error = 0;
	for (;;) {
		struct pollfd descriptors[2] = {
			{ .fd = listener, .events = POLLIN },
			{ .fd = signal_pipe[0], .events = POLLIN },
		};
		do {
			ch = poll(descriptors, nitems(descriptors), -1);
		} while (ch < 0 && errno == EINTR);
		if (ch < 0) {
			error = errno;
			break;
		}
		if ((descriptors[1].revents & POLLIN) != 0)
			break;
		if ((descriptors[0].revents & POLLIN) == 0)
			continue;
		client = accept4(listener, NULL, NULL,
		    SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (client == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			error = errno;
			break;
		}
		error = client_run(client, rootfd, expected_uid, expected_gid,
		    nodes, handles, maximum_message, maximum_inflight,
		    maximum_pending, workers);
		(void)close(client);
		if (error == ECANCELED)
			break;
		if (error != 0)
			warnc(error, "backend connection");
		error = 0;
	}
	(void)close(listener);
	(void)unlinkat(parentfd, socket_name, 0);
	(void)close(parentfd);
	(void)close(rootfd);
	(void)close(signal_pipe[0]);
	(void)close(signal_pipe[1]);
	free(socket_name);
	return (error == 0 || error == ECANCELED ? 0 : 1);
}
