/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "virtio_fs_backend.c"
#include "virtio_fs_backend_io.c"
#include "virtio_fs_outbox.c"
#include "virtiofsd_export.c"
#include "virtiofsd_fuse.c"
#include "virtiofsd_handle.c"
#include "virtiofsd_session.c"
#include "virtiofsd_server.c"
#define	main	virtiofsd_program_main
int	virtiofsd_program_main(int, char **);
#include "virtiofsd.c"
#undef main

#define	DOC_FUSE_LOOKUP		1U
#define	DOC_FUSE_OPEN		14U
#define	DOC_FUSE_READ		15U
#define	DOC_FUSE_RELEASE	18U
#define	DOC_FUSE_OPENDIR	27U
#define	DOC_FUSE_READDIR	28U
#define	DOC_FUSE_RELEASEDIR	29U

static void
wait_readable(int fd)
{
	struct pollfd descriptor;
	int result;

	descriptor = (struct pollfd) {
		.fd = fd,
		.events = POLLIN,
	};
	do {
		result = poll(&descriptor, 1, 5000);
	} while (result < 0 && errno == EINTR);
	ATF_REQUIRE_MSG(result == 1 && (descriptor.revents & POLLIN) != 0,
	    "descriptor did not become readable: result=%d events=%#x",
	    result, descriptor.revents);
}

static void
send_hello(int fd)
{
	struct virtio_fs_backend_header header;
	struct virtio_fs_backend_hello offer;
	uint8_t wire[VIRTIO_FS_BACKEND_HELLO_SIZE];

	offer = (struct virtio_fs_backend_hello) {
		.minimum_version = 1,
		.maximum_version = 1,
		.features = VIRTIO_FS_BACKEND_F_CANCEL |
		    VIRTIO_FS_BACKEND_F_FREEZE |
		    VIRTIO_FS_BACKEND_F_STATE_TRANSFER,
		.maximum_message = 4096,
		.maximum_inflight = 8,
		.maximum_pending_bytes = 32768,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_hello_encode(&offer, wire), 0);
	header = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_HELLO,
		.payload_len = sizeof(wire),
		.request_id = 1,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(fd, &header, wire), 0);
}

/*
 * bindat(2) creates the directory entry before listen(2) makes the socket
 * connectable.  EVFILT_VNODE therefore proves that the pathname exists, not
 * that the daemon has completed listener initialization.  Retry only that
 * narrow startup window under one monotonic deadline; all later protocol
 * progress remains readiness-driven.
 */
static int
connect_daemon(const char *path, int *client, bool *connecting)
{
	struct timespec deadline, now, pause;
	int error;

	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &deadline), 0);
	deadline.tv_sec += 5;
	pause = (struct timespec) { .tv_nsec = 1000000 };
	for (;;) {
		error = virtio_fs_backend_connect_start(path, geteuid(),
		    getegid(), client, connecting);
		if (error != ENOENT && error != ECONNREFUSED)
			return (error);
		ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &now), 0);
		if (now.tv_sec > deadline.tv_sec ||
		    (now.tv_sec == deadline.tv_sec &&
		    now.tv_nsec >= deadline.tv_nsec))
			return (error);
		while (nanosleep(&pause, &pause) != 0)
			ATF_REQUIRE_EQ(errno, EINTR);
		pause = (struct timespec) { .tv_nsec = 1000000 };
	}
}

static size_t
round_trip(int fd, uint64_t request_id, const void *request,
    size_t request_len, void *response, size_t response_capacity)
{
	struct virtio_fs_backend_header header;
	size_t response_len;

	header = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_REQUEST,
		.payload_len = (uint32_t)request_len,
		.request_id = request_id,
		.incarnation = 1,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(fd, &header, request), 0);
	wait_readable(fd);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fd, &header, response,
	    response_capacity, &response_len), 0);
	ATF_REQUIRE_EQ(header.type, VIRTIO_FS_BACKEND_RESPONSE);
	ATF_REQUIRE_EQ(header.request_id, request_id);
	ATF_REQUIRE_EQ(header.status, 0);
	return (response_len);
}

static void
fuse_request(uint8_t *wire, size_t length, uint32_t opcode,
    uint64_t unique, uint64_t nodeid)
{

	memset(wire, 0, length);
	le32enc(wire, (uint32_t)length);
	le32enc(wire + 4, opcode);
	le64enc(wire + 8, unique);
	le64enc(wire + 16, nodeid);
	le32enc(wire + 24, 1001);
	le32enc(wire + 28, 1002);
	le32enc(wire + 32, 1003);
}

ATF_TC_WITHOUT_HEAD(pending_limit_validation);
ATF_TC_BODY(pending_limit_validation, tc)
{

	ATF_CHECK(!pending_limit_valid(0, UINT32_MAX));
	ATF_CHECK(pending_limit_valid(1, 2));
	ATF_CHECK(!pending_limit_valid(2, 3));
	ATF_CHECK(pending_limit_valid(UINT32_MAX / 2U, UINT32_MAX - 1U));
	ATF_CHECK(!pending_limit_valid(UINT32_MAX / 2U + 1U, UINT32_MAX));
}

ATF_TC_WITHOUT_HEAD(foreground_daemon_is_sandboxed_event_driven_and_cleans);
ATF_TC_BODY(foreground_daemon_is_sandboxed_event_driven_and_cleans, tc)
{
	struct virtio_fs_backend_header header;
	struct kevent change, event;
	struct timespec timeout;
	uint8_t fuse[80], payload[4096], *state;
	char directory[32], socket_path[96];
	char *arguments[] = {
		__DECONST(char *, "virtiofsd"),
		__DECONST(char *, "-r"), directory,
		__DECONST(char *, "-s"), socket_path,
		__DECONST(char *, "-m"), __DECONST(char *, "4096"),
		__DECONST(char *, "-b"), __DECONST(char *, "32768"),
		__DECONST(char *, "-i"), __DECONST(char *, "8"),
		__DECONST(char *, "-n"), __DECONST(char *, "64"),
		__DECONST(char *, "-h"), __DECONST(char *, "32"),
		__DECONST(char *, "-w"), __DECONST(char *, "2"),
		NULL,
	};
	size_t entry_size, name_len, payload_len, position;
	uint64_t directory_handle, file_handle, nodeid;
	pid_t child;
	int client, directory_fd, error, file_fd, kqueue_fd, status;
	bool connecting, found_file, found_socket;

	strcpy(directory, "/tmp/virtiofsd-daemon.XXXXXX");
	ATF_REQUIRE(mkdtemp(directory) != NULL);
	ATF_REQUIRE(snprintf(socket_path, sizeof(socket_path), "%s/socket",
	    directory) > 0);
	directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(directory_fd >= 0);
	file_fd = openat(directory_fd, "file",
	    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	ATF_REQUIRE(file_fd >= 0);
	ATF_REQUIRE_EQ(write(file_fd, "data", 4), 4);
	ATF_REQUIRE_EQ(close(file_fd), 0);
	kqueue_fd = kqueue();
	ATF_REQUIRE(kqueue_fd >= 0);
	EV_SET(&change, directory_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	    NOTE_WRITE, 0, NULL);
	ATF_REQUIRE_EQ(kevent(kqueue_fd, &change, 1, NULL, 0, NULL), 0);

	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0)
		_exit(virtiofsd_program_main(17, arguments));
	timeout = (struct timespec) { .tv_sec = 5 };
	ATF_REQUIRE_MSG(kevent(kqueue_fd, NULL, 0, &event, 1, &timeout) == 1,
	    "daemon did not create its socket");
	ATF_REQUIRE_EQ(close(kqueue_fd), 0);
	ATF_REQUIRE_EQ(close(directory_fd), 0);

	error = connect_daemon(socket_path, &client, &connecting);
	ATF_REQUIRE_EQ(error, 0);
	if (connecting) {
		struct pollfd descriptor = {
			.fd = client,
			.events = POLLOUT,
		};
		ATF_REQUIRE_EQ(poll(&descriptor, 1, 5000), 1);
		ATF_REQUIRE_EQ(virtio_fs_backend_connect_finish(client,
		    geteuid(), getegid()), 0);
	}
	send_hello(client);
	wait_readable(client);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(client, &header,
	    payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(header.type, VIRTIO_FS_BACKEND_HELLO_REPLY);
	ATF_CHECK_EQ(header.incarnation, 0);
	{
		struct virtio_fs_backend_hello selected;

		ATF_REQUIRE_EQ(virtio_fs_backend_hello_decode(payload,
		    payload_len, &selected), 0);
		ATF_CHECK_EQ(selected.features,
		    VIRTIO_FS_BACKEND_F_CANCEL |
		    VIRTIO_FS_BACKEND_F_FREEZE |
		    VIRTIO_FS_BACKEND_F_STATE_TRANSFER);
	}

	memset(fuse, 0, 56);
	le32enc(fuse, 56);
	le32enc(fuse + 4, VIRTIOFSD_FUSE_INIT);
	le64enc(fuse + 8, 71);
	le64enc(fuse + 16, 1);
	le32enc(fuse + 40, 7);
	le32enc(fuse + 44, 35);
	header = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_REQUEST,
		.payload_len = 56,
		.request_id = 2,
		.incarnation = 1,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(client, &header, fuse), 0);
	wait_readable(client);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(client, &header,
	    payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(header.type, VIRTIO_FS_BACKEND_RESPONSE);
	ATF_CHECK_EQ(header.status, 0);
	ATF_CHECK_EQ(le32dec(payload), payload_len);
	ATF_CHECK_EQ(le64dec(payload + 8), 71);

	fuse_request(fuse, 45, DOC_FUSE_LOOKUP, 72, 1);
	memcpy(fuse + 40, "file", 5);
	payload_len = round_trip(client, 3, fuse, 45, payload,
	    sizeof(payload));
	ATF_REQUIRE_EQ(payload_len, 144);
	nodeid = le64dec(payload + 16);

	fuse_request(fuse, 48, DOC_FUSE_OPEN, 73, nodeid);
	payload_len = round_trip(client, 4, fuse, 48, payload,
	    sizeof(payload));
	ATF_REQUIRE_EQ(payload_len, 32);
	file_handle = le64dec(payload + 16);

	fuse_request(fuse, 80, DOC_FUSE_READ, 74, nodeid);
	le64enc(fuse + 40, file_handle);
	le32enc(fuse + 56, 4);
	payload_len = round_trip(client, 5, fuse, 80, payload,
	    sizeof(payload));
	ATF_REQUIRE_EQ(payload_len, 20);
	ATF_CHECK_EQ(memcmp(payload + 16, "data", 4), 0);

	fuse_request(fuse, 48, DOC_FUSE_OPENDIR, 76, 1);
	ATF_REQUIRE_EQ(round_trip(client, 6, fuse, 48, payload,
	    sizeof(payload)), 32);
	directory_handle = le64dec(payload + 16);
	fuse_request(fuse, 80, DOC_FUSE_READDIR, 77, 1);
	le64enc(fuse + 40, directory_handle);
	le32enc(fuse + 56, 4080);
	payload_len = round_trip(client, 7, fuse, 80, payload,
	    sizeof(payload));
	found_file = false;
	found_socket = false;
	for (position = 16; position < payload_len;
	    position += entry_size) {
		ATF_REQUIRE(payload_len - position >= 24);
		name_len = le32dec(payload + position + 16);
		entry_size = (24 + name_len + 7) & ~(size_t)7;
		ATF_REQUIRE(entry_size <= payload_len - position);
		if (name_len == 4 &&
		    memcmp(payload + position + 24, "file", 4) == 0)
			found_file = true;
		if (name_len == 6 &&
		    memcmp(payload + position + 24, "socket", 6) == 0)
			found_socket = true;
	}
	ATF_CHECK(found_file);
	ATF_CHECK(!found_socket);

	/* Exercise the daemon protocol, not merely the in-process state codec. */
	header = (struct virtio_fs_backend_header) {
		.version = VIRTIO_FS_BACKEND_VERSION,
		.type = VIRTIO_FS_BACKEND_QUIESCE,
		.request_id = VIRTIO_FS_BACKEND_CONTROL_ID_BIT | 10,
		.incarnation = 1,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(client, &header, NULL), 0);
	wait_readable(client);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(client, &header,
	    payload, sizeof(payload), &payload_len), 0);
	ATF_REQUIRE_EQ(header.type, VIRTIO_FS_BACKEND_QUIESCE_REPLY);
	ATF_REQUIRE_EQ(header.status, 0);
	ATF_REQUIRE(payload_len > VIRTIOFSD_SESSION_STATE_SIZE);
	ATF_REQUIRE_EQ(le16dec(payload + 4), VIRTIOFSD_SESSION_STATE_VERSION);
	state = malloc(payload_len);
	ATF_REQUIRE(state != NULL);
	memcpy(state, payload, payload_len);
	header.type = VIRTIO_FS_BACKEND_THAW;
	header.payload_len = (uint32_t)payload_len;
	header.request_id = VIRTIO_FS_BACKEND_CONTROL_ID_BIT | 11;
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(client, &header, state), 0);
	free(state);
	wait_readable(client);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(client, &header,
	    payload, sizeof(payload), &payload_len), 0);
	ATF_REQUIRE_EQ(header.type, VIRTIO_FS_BACKEND_THAW_REPLY);
	ATF_REQUIRE_EQ(header.status, 0);
	ATF_REQUIRE_EQ(payload_len, 0);
	/* Both exact handles remain usable after reconstruction. */
	fuse_request(fuse, 80, DOC_FUSE_READ, 79, nodeid);
	le64enc(fuse + 40, file_handle);
	le32enc(fuse + 56, 4);
	ATF_REQUIRE_EQ(round_trip(client, 12, fuse, 80, payload,
	    sizeof(payload)), 20);
	ATF_CHECK_EQ(memcmp(payload + 16, "data", 4), 0);
	fuse_request(fuse, 80, DOC_FUSE_READDIR, 80, 1);
	le64enc(fuse + 40, directory_handle);
	le32enc(fuse + 56, 4080);
	ATF_CHECK(round_trip(client, 13, fuse, 80, payload,
	    sizeof(payload)) > 16);

	fuse_request(fuse, 64, DOC_FUSE_RELEASE, 81, nodeid);
	le64enc(fuse + 40, file_handle);
	ATF_REQUIRE_EQ(round_trip(client, 14, fuse, 64, payload,
	    sizeof(payload)), 16);
	fuse_request(fuse, 64, DOC_FUSE_RELEASEDIR, 78, 1);
	le64enc(fuse + 40, directory_handle);
	ATF_REQUIRE_EQ(round_trip(client, 15, fuse, 64, payload,
	    sizeof(payload)), 16);

	ATF_REQUIRE_EQ(kill(child, SIGTERM), 0);
	ATF_REQUIRE_EQ(waitpid(child, &status, 0), child);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);
	ATF_REQUIRE_EQ(close(client), 0);
	ATF_CHECK_EQ(access(socket_path, F_OK), -1);
	ATF_CHECK_EQ(errno, ENOENT);
	file_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(file_fd >= 0);
	ATF_REQUIRE_EQ(unlinkat(file_fd, "file", 0), 0);
	ATF_REQUIRE_EQ(close(file_fd), 0);
	ATF_REQUIRE_EQ(rmdir(directory), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, pending_limit_validation);
	ATF_TP_ADD_TC(tp,
	    foreground_daemon_is_sandboxed_event_driven_and_cleans);
	return (atf_no_error());
}
