/*
 * Unix-domain transport tests for the private VFSB protocol.
 */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "virtio_fs_backend.c"
#include "virtio_fs_backend_io.c"

#define	ALIAS_STORAGE_SIZE	128U

static struct virtio_fs_backend_header
request_header(uint32_t payload_len)
{

	return ((struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_REQUEST,
		.payload_len = payload_len,
		.request_id = 7,
		.incarnation = 3,
	});
}

ATF_TC_WITHOUT_HEAD(backend_connect_is_bounded_and_authenticated);
ATF_TC_BODY(backend_connect_is_bounded_and_authenticated, tc)
{
	struct sockaddr_un address;
	struct pollfd pollfd;
	char directory[] = "/tmp/vfsb.XXXXXX";
	char path[sizeof(address.sun_path)];
	char too_long[sizeof(address.sun_path) + 2];
	socklen_t address_len;
	bool connecting;
	int accepted, client, flags, listener;

	ATF_REQUIRE(mkdtemp(directory) != NULL);
	ATF_REQUIRE(snprintf(path, sizeof(path), "%s/backend", directory) > 0);
	listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	ATF_REQUIRE(listener >= 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	ATF_REQUIRE(strlcpy(address.sun_path, path,
	    sizeof(address.sun_path)) < sizeof(address.sun_path));
	address.sun_len = (uint8_t)(offsetof(struct sockaddr_un, sun_path) +
	    strlen(address.sun_path) + 1);
	address_len = address.sun_len;
	ATF_REQUIRE_EQ(bind(listener, (struct sockaddr *)&address,
	    address_len), 0);
	ATF_REQUIRE_EQ(listen(listener, 1), 0);

	ATF_REQUIRE_EQ(virtio_fs_backend_connect_start(path, geteuid(),
	    getegid(), &client, &connecting), 0);
	if (connecting) {
		pollfd = (struct pollfd) {
			.fd = client,
			.events = POLLOUT,
		};
		ATF_REQUIRE_EQ(poll(&pollfd, 1, 1000), 1);
		ATF_REQUIRE_EQ(virtio_fs_backend_connect_finish(client,
		    geteuid(), getegid()), 0);
	}
	accepted = accept(listener, NULL, NULL);
	ATF_REQUIRE(accepted >= 0);
	flags = fcntl(client, F_GETFL);
	ATF_REQUIRE(flags >= 0);
	ATF_CHECK((flags & O_NONBLOCK) != 0);
	flags = fcntl(client, F_GETFD);
	ATF_REQUIRE(flags >= 0);
	ATF_CHECK((flags & FD_CLOEXEC) != 0);
	ATF_REQUIRE_EQ(close(accepted), 0);
	ATF_REQUIRE_EQ(close(client), 0);
	ATF_REQUIRE_EQ(close(listener), 0);
	ATF_REQUIRE_EQ(unlink(path), 0);
	ATF_REQUIRE_EQ(rmdir(directory), 0);

	client = 99;
	connecting = true;
	ATF_CHECK_EQ(virtio_fs_backend_connect_start("relative", geteuid(),
	    getegid(), &client, &connecting), EINVAL);
	ATF_CHECK_EQ(client, -1);
	ATF_CHECK(!connecting);
	memset(too_long, 'a', sizeof(too_long));
	too_long[0] = '/';
	too_long[sizeof(too_long) - 1] = '\0';
	ATF_CHECK_EQ(virtio_fs_backend_connect_start(too_long, geteuid(),
	    getegid(), &client, &connecting), ENAMETOOLONG);
}

ATF_TC_WITHOUT_HEAD(backend_connect_supports_long_parent_path);
ATF_TC_BODY(backend_connect_supports_long_parent_path, tc)
{
	static const char component[] = "parent-directory-component-0000";
	struct sockaddr_un address;
	struct pollfd pollfd;
	char directories[4][MAXPATHLEN];
	char root[] = "/tmp/vfsb-long.XXXXXX";
	char path[MAXPATHLEN];
	socklen_t address_len;
	bool connecting;
	int accepted, client, dfd, listener;
	size_t i;

	ATF_REQUIRE(mkdtemp(root) != NULL);
	ATF_REQUIRE(strlcpy(directories[0], root,
	    sizeof(directories[0])) < sizeof(directories[0]));
	for (i = 1; i < nitems(directories); i++) {
		ATF_REQUIRE(snprintf(directories[i], sizeof(directories[i]),
		    "%s/%s%zu", directories[i - 1], component, i) > 0);
		ATF_REQUIRE_EQ(mkdir(directories[i], 0700), 0);
	}
	ATF_REQUIRE(snprintf(path, sizeof(path), "%s/backend",
	    directories[nitems(directories) - 1]) > 0);
	ATF_REQUIRE(strlen(path) >= sizeof(address.sun_path));

	dfd = open(directories[nitems(directories) - 1],
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(dfd >= 0);
	listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	ATF_REQUIRE(listener >= 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	ATF_REQUIRE(strlcpy(address.sun_path, "backend",
	    sizeof(address.sun_path)) < sizeof(address.sun_path));
	address.sun_len = (uint8_t)(offsetof(struct sockaddr_un, sun_path) +
	    strlen(address.sun_path) + 1);
	address_len = address.sun_len;
	ATF_REQUIRE_EQ(bindat(dfd, listener, (struct sockaddr *)&address,
	    address_len), 0);
	ATF_REQUIRE_EQ(listen(listener, 1), 0);

	ATF_REQUIRE_EQ(virtio_fs_backend_connect_start(path, geteuid(),
	    getegid(), &client, &connecting), 0);
	if (connecting) {
		pollfd = (struct pollfd) {
			.fd = client,
			.events = POLLOUT,
		};
		ATF_REQUIRE_EQ(poll(&pollfd, 1, 1000), 1);
		ATF_REQUIRE_EQ(virtio_fs_backend_connect_finish(client,
		    geteuid(), getegid()), 0);
	}
	accepted = accept(listener, NULL, NULL);
	ATF_REQUIRE(accepted >= 0);
	ATF_REQUIRE_EQ(close(accepted), 0);
	ATF_REQUIRE_EQ(close(client), 0);
	ATF_REQUIRE_EQ(close(listener), 0);
	ATF_REQUIRE_EQ(unlinkat(dfd, "backend", 0), 0);
	ATF_REQUIRE_EQ(close(dfd), 0);
	for (i = nitems(directories); i-- > 1;)
		ATF_REQUIRE_EQ(rmdir(directories[i]), 0);
	ATF_REQUIRE_EQ(rmdir(root), 0);
}

ATF_TC_WITHOUT_HEAD(peer_authentication);
ATF_TC_BODY(peer_authentication, tc)
{
	int sockets[2], stream[2];
	uid_t wrong_uid;

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	ATF_CHECK_EQ(virtio_fs_backend_authenticate(sockets[0], geteuid(),
	    getegid()), 0);
	ATF_CHECK_EQ(virtio_fs_backend_authenticate(sockets[0],
	    (uid_t)-1, (gid_t)-1), 0);
	wrong_uid = geteuid() == 0 ? 1 : 0;
	ATF_CHECK_EQ(virtio_fs_backend_authenticate(sockets[0], wrong_uid,
	    getegid()), EACCES);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, stream), 0);
	ATF_CHECK_EQ(virtio_fs_backend_authenticate(stream[0], geteuid(),
	    getegid()), EPROTOTYPE);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	ATF_REQUIRE_EQ(close(stream[0]), 0);
	ATF_REQUIRE_EQ(close(stream[1]), 0);
}

ATF_TC_WITHOUT_HEAD(frame_round_trip_and_nonblocking);
ATF_TC_BODY(frame_round_trip_and_nonblocking, tc)
{
	struct virtio_fs_backend_header sent, received;
	uint8_t input[] = { 1, 2, 3, 4, 5 };
	uint8_t output[sizeof(input)];
	size_t output_len;
	int sockets[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[1], &received,
	    output, sizeof(output), &output_len), EAGAIN);
	sent = request_header(sizeof(input));
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[0], &sent,
	    input), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &received,
	    output, sizeof(output), &output_len), 0);
	ATF_CHECK_EQ(output_len, sizeof(input));
	ATF_CHECK(memcmp(output, input, sizeof(input)) == 0);
	ATF_CHECK_EQ(received.type, sent.type);
	ATF_CHECK_EQ(received.request_id, sent.request_id);
	ATF_CHECK_EQ(received.incarnation, sent.incarnation);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(truncation_and_bad_frames);
ATF_TC_BODY(truncation_and_bad_frames, tc)
{
	struct virtio_fs_backend_header sent, received;
	uint8_t input[8] = { 0 }, output[4], wire[40];
	struct iovec vector;
	size_t output_len;
	int sockets[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	sent = request_header(sizeof(input));
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[0], &sent,
	    input), 0);
	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[1], &received,
	    output, sizeof(output), &output_len), EMSGSIZE);

	ATF_REQUIRE_EQ(virtio_fs_backend_header_encode(&sent, wire), 0);
	le32enc(wire + 12, 1);	/* Header disagrees with the datagram. */
	vector.iov_base = wire;
	vector.iov_len = sizeof(wire);
	ATF_REQUIRE_EQ(writev(sockets[0], &vector, 1), sizeof(wire));
	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[1], &received,
	    output, sizeof(output), &output_len), EPROTO);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(descriptor_passing_is_rejected);
ATF_TC_BODY(descriptor_passing_is_rejected, tc)
{
	union {
		struct cmsghdr alignment;
		unsigned char bytes[CMSG_SPACE(sizeof(int))];
	} control;
	struct virtio_fs_backend_header sent, received;
	uint8_t output[1], wire[40];
	struct cmsghdr *cmsg;
	struct iovec vector;
	struct msghdr message;
	size_t output_len;
	int descriptor, sockets[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	descriptor = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(descriptor >= 0);
	sent = request_header(0);
	ATF_REQUIRE_EQ(virtio_fs_backend_header_encode(&sent, wire), 0);
	vector.iov_base = wire;
	vector.iov_len = sizeof(wire);
	memset(&control, 0, sizeof(control));
	memset(&message, 0, sizeof(message));
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	cmsg = CMSG_FIRSTHDR(&message);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &descriptor, sizeof(descriptor));
	ATF_REQUIRE_EQ(sendmsg(sockets[0], &message, 0), sizeof(wire));
	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[1], &received,
	    output, sizeof(output), &output_len), EPROTO);
	ATF_REQUIRE_EQ(close(descriptor), 0);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

static unsigned int
open_descriptor_count(void)
{
	unsigned int count;
	int limit;

	count = 0;
	limit = getdtablesize();
	for (int fd = 0; fd < limit; fd++) {
		if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
			count++;
	}
	return (count);
}

ATF_TC_WITHOUT_HEAD(truncated_descriptors_are_closed);
ATF_TC_BODY(truncated_descriptors_are_closed, tc)
{
	union {
		struct cmsghdr alignment;
		unsigned char bytes[CMSG_SPACE(sizeof(int) * 17)];
	} control;
	struct virtio_fs_backend_header sent, received;
	uint8_t output[1], wire[40];
	struct cmsghdr *cmsg;
	struct iovec vector;
	struct msghdr message;
	unsigned int before;
	size_t output_len;
	int descriptor, descriptors[17], sockets[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	descriptor = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(descriptor >= 0);
	for (size_t i = 0; i < nitems(descriptors); i++)
		descriptors[i] = descriptor;
	sent = request_header(0);
	ATF_REQUIRE_EQ(virtio_fs_backend_header_encode(&sent, wire), 0);
	vector.iov_base = wire;
	vector.iov_len = sizeof(wire);
	memset(&control, 0, sizeof(control));
	memset(&message, 0, sizeof(message));
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	cmsg = CMSG_FIRSTHDR(&message);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(descriptors));
	memcpy(CMSG_DATA(cmsg), descriptors, sizeof(descriptors));
	ATF_REQUIRE_EQ(sendmsg(sockets[0], &message, 0), sizeof(wire));
	before = open_descriptor_count();
	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[1], &received,
	    output, sizeof(output), &output_len), EMSGSIZE);
	ATF_CHECK_EQ(open_descriptor_count(), before);
	ATF_REQUIRE_EQ(close(descriptor), 0);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(api_errors_and_peer_close);
ATF_TC_BODY(api_errors_and_peer_close, tc)
{
	struct virtio_fs_backend_header sent, received;
	uint8_t output[1];
	size_t output_len;
	int sockets[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	sent = request_header(1);
	ATF_CHECK_EQ(virtio_fs_backend_send_frame(sockets[0], &sent, NULL),
	    EINVAL);
	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[0], NULL,
	    output, sizeof(output), &output_len), EINVAL);
	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[0], &received,
	    NULL, sizeof(output), &output_len), EINVAL);
	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[0], &received,
	    output, sizeof(output), NULL), EINVAL);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[0], &received,
	    output, sizeof(output), &output_len), ECONNRESET);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
}

ATF_TC_WITHOUT_HEAD(receive_outputs_must_not_alias);
ATF_TC_BODY(receive_outputs_must_not_alias, tc)
{
	union {
		max_align_t alignment;
		uint8_t bytes[ALIAS_STORAGE_SIZE];
	} storage;
	struct virtio_fs_backend_header sent, received;
	uint8_t input[] = { 1, 2, 3, 4 };
	uint8_t output[sizeof(input)];
	size_t output_len;
	int sockets[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	sent = request_header(sizeof(input));
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[0], &sent,
	    input), 0);

	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[1],
	    (struct virtio_fs_backend_header *)(void *)storage.bytes,
	    storage.bytes, sizeof(input), &output_len), EINVAL);
	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[1], &received,
	    storage.bytes, sizeof(input),
	    (size_t *)(void *)storage.bytes), EINVAL);
	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[1],
	    (struct virtio_fs_backend_header *)(void *)storage.bytes,
	    output, sizeof(output),
	    (size_t *)(void *)storage.bytes), EINVAL);

	/*
	 * Alias rejection happens before recvmsg(), so the original record is
	 * still available to a corrected call.
	 */
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &received,
	    output, sizeof(output), &output_len), 0);
	ATF_CHECK_EQ(output_len, sizeof(input));
	ATF_CHECK(memcmp(output, input, sizeof(input)) == 0);
	ATF_CHECK_EQ(received.request_id, sent.request_id);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

/*
 * local(4) SOCK_SEQPACKET shares the stream implementation: records end only
 * at MSG_EOR, so frames sent without it coalesce in the receive buffer.
 */
ATF_TC_WITHOUT_HEAD(back_to_back_frames_keep_boundaries);
ATF_TC_BODY(back_to_back_frames_keep_boundaries, tc)
{
	struct virtio_fs_backend_header received, sent;
	uint8_t first[] = { 1, 2, 3, 4, 5 }, second[] = { 9, 8, 7, 6, 5, 4, 3 };
	uint8_t output[64];
	size_t output_len;
	int sockets[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0,
	    sockets), 0);
	sent = request_header(sizeof(first));
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[0], &sent, first),
	    0);
	sent = request_header(sizeof(second));
	sent.request_id = 8;
	ATF_REQUIRE_EQ(virtio_fs_backend_send_frame(sockets[0], &sent, second),
	    0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &received,
	    output, sizeof(output), &output_len), 0);
	ATF_CHECK_EQ(received.request_id, 7);
	ATF_CHECK_EQ(output_len, sizeof(first));
	ATF_CHECK(memcmp(output, first, sizeof(first)) == 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &received,
	    output, sizeof(output), &output_len), 0);
	ATF_CHECK_EQ(received.request_id, 8);
	ATF_CHECK_EQ(output_len, sizeof(second));
	ATF_CHECK(memcmp(output, second, sizeof(second)) == 0);
	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[1], &received,
	    output, sizeof(output), &output_len), EAGAIN);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

struct large_sender {
	int fd;
	const uint8_t *payload;
	uint32_t length;
	int error;
};

static void *
large_sender_main(void *argument)
{
	struct large_sender *sender = argument;
	struct virtio_fs_backend_header header;
	struct pollfd descriptor;

	header = request_header(sender->length);
	descriptor = (struct pollfd) { .fd = sender->fd, .events = POLLOUT };
	do {
		(void)poll(&descriptor, 1, 5000);
		sender->error = virtio_fs_backend_send_frame(sender->fd, &header,
		    sender->payload);
	} while (sender->error == EAGAIN);
	return (NULL);
}

/*
 * A FUSE_READ reply for a 64 KiB block exceeds the default 64 KiB local
 * socket buffers (net.local.seqpacket.recvspace), so the kernel moves it in
 * pieces: a nonblocking sender sees a short count and the receiver can observe
 * a partial record.  Both ends must finish the frame instead of failing.
 */
ATF_TC_WITHOUT_HEAD(frames_larger_than_socket_buffer_are_reassembled);
ATF_TC_BODY(frames_larger_than_socket_buffer_are_reassembled, tc)
{
	static const uint32_t lengths[] = { 65552, 131088, 1048592 };
	struct virtio_fs_backend_header received;
	struct large_sender sender;
	struct pollfd descriptor;
	pthread_t thread;
	uint8_t *input, *output;
	size_t i, j, output_len;
	int error, sockets[2];

	input = malloc(lengths[nitems(lengths) - 1]);
	output = malloc(lengths[nitems(lengths) - 1]);
	ATF_REQUIRE(input != NULL && output != NULL);
	for (j = 0; j < lengths[nitems(lengths) - 1]; j++)
		input[j] = (uint8_t)(j * 131U + 7U);
	for (i = 0; i < nitems(lengths); i++) {
		ATF_REQUIRE_EQ(socketpair(AF_UNIX,
		    SOCK_SEQPACKET | SOCK_NONBLOCK, 0, sockets), 0);
		sender = (struct large_sender) {
			.fd = sockets[0],
			.payload = input,
			.length = lengths[i],
		};
		ATF_REQUIRE_EQ(pthread_create(&thread, NULL, large_sender_main,
		    &sender), 0);
		do {
			descriptor = (struct pollfd) {
				.fd = sockets[1],
				.events = POLLIN,
			};
			ATF_REQUIRE_EQ(poll(&descriptor, 1, 5000), 1);
			error = virtio_fs_backend_receive_frame(sockets[1],
			    &received, output, lengths[nitems(lengths) - 1],
			    &output_len);
		} while (error == EAGAIN);
		ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
		ATF_CHECK_EQ(sender.error, 0);
		ATF_CHECK_EQ(error, 0);
		ATF_CHECK_EQ(output_len, lengths[i]);
		ATF_CHECK(error != 0 || memcmp(output, input, lengths[i]) == 0);
		ATF_REQUIRE_EQ(close(sockets[0]), 0);
		ATF_REQUIRE_EQ(close(sockets[1]), 0);
	}
	free(output);
	free(input);
}

/* An event-loop callback must return well inside this bound. */
#define	PROMPT_MS	50

static long
elapsed_ms(const struct timespec *start)
{
	struct timespec now;

	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &now), 0);
	return ((now.tv_sec - start->tv_sec) * 1000 +
	    (now.tv_nsec - start->tv_nsec) / 1000000);
}

/*
 * A frame is complete only at the peer's MSG_EOR.  A record that reaches the
 * announced length without it continues into what would be the next frame.
 */
ATF_TC_WITHOUT_HEAD(full_length_without_eor_is_rejected);
ATF_TC_BODY(full_length_without_eor_is_rejected, tc)
{
	struct virtio_fs_backend_header received, sent;
	uint8_t frame[40 + 5], output[16];
	size_t output_len;
	int sockets[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0,
	    sockets), 0);
	sent = request_header(5);
	ATF_REQUIRE_EQ(virtio_fs_backend_header_encode(&sent, frame), 0);
	memset(frame + 40, 0x5a, 5);
	ATF_REQUIRE_EQ(send(sockets[0], frame, sizeof(frame), 0),
	    (ssize_t)sizeof(frame));
	ATF_CHECK_EQ(virtio_fs_backend_receive_frame(sockets[1], &received,
	    output, sizeof(output), &output_len), EPROTO);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

/*
 * The stream functions return EAGAIN for a partly received frame instead of
 * waiting for the rest, and resume where they stopped.
 */
ATF_TC_WITHOUT_HEAD(partial_frame_resumes_without_waiting);
ATF_TC_BODY(partial_frame_resumes_without_waiting, tc)
{
	struct virtio_fs_backend_stream stream;
	struct virtio_fs_backend_header received, sent;
	struct timespec deadline, start;
	uint8_t frame[40 + 16], output[16];
	size_t output_len;
	int sockets[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0,
	    sockets), 0);
	sent = request_header(16);
	ATF_REQUIRE_EQ(virtio_fs_backend_header_encode(&sent, frame), 0);
	for (size_t i = 0; i < 16; i++)
		frame[40 + i] = (uint8_t)(i * 7 + 1);
	virtio_fs_backend_stream_init(&stream);
	ATF_CHECK(!virtio_fs_backend_stream_deadline(&stream, &deadline));

	/* Half the header. */
	ATF_REQUIRE_EQ(send(sockets[0], frame, 20, 0), 20);
	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &start), 0);
	ATF_CHECK_EQ(virtio_fs_backend_stream_receive(&stream, sockets[1],
	    &received, output, sizeof(output), &output_len), EAGAIN);
	ATF_CHECK(elapsed_ms(&start) < PROMPT_MS);
	ATF_CHECK(virtio_fs_backend_stream_deadline(&stream, &deadline));

	/* The rest of the header and part of the payload. */
	ATF_REQUIRE_EQ(send(sockets[0], frame + 20, 30, 0), 30);
	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &start), 0);
	ATF_CHECK_EQ(virtio_fs_backend_stream_receive(&stream, sockets[1],
	    &received, output, sizeof(output), &output_len), EAGAIN);
	ATF_CHECK(elapsed_ms(&start) < PROMPT_MS);

	ATF_REQUIRE_EQ(send(sockets[0], frame + 50, sizeof(frame) - 50,
	    MSG_EOR), (ssize_t)(sizeof(frame) - 50));
	ATF_CHECK_EQ(virtio_fs_backend_stream_receive(&stream, sockets[1],
	    &received, output, sizeof(output), &output_len), 0);
	ATF_CHECK_EQ(output_len, 16);
	ATF_CHECK(memcmp(output, frame + 40, 16) == 0);
	ATF_CHECK_EQ(received.request_id, sent.request_id);
	ATF_CHECK(!virtio_fs_backend_stream_deadline(&stream, &deadline));
	virtio_fs_backend_stream_fini(&stream);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

/*
 * A receive that runs after the progress deadline but finds more of the
 * frame takes it (the header rest, then the payload); one that finds nothing
 * reports ETIMEDOUT.
 */
ATF_TC_WITHOUT_HEAD(late_receive_moves_before_expiring);
ATF_TC_BODY(late_receive_moves_before_expiring, tc)
{
	struct virtio_fs_backend_stream stream;
	struct virtio_fs_backend_header received, sent;
	uint8_t frame[40 + 16], output[16];
	size_t output_len;
	int error, sockets[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0,
	    sockets), 0);
	sent = request_header(16);
	ATF_REQUIRE_EQ(virtio_fs_backend_header_encode(&sent, frame), 0);
	memset(frame + 40, 0x3c, 16);
	virtio_fs_backend_stream_init(&stream);

	ATF_REQUIRE_EQ(send(sockets[0], frame, 20, 0), 20);
	ATF_CHECK_EQ(virtio_fs_backend_stream_receive(&stream, sockets[1],
	    &received, output, sizeof(output), &output_len), EAGAIN);
	ATF_REQUIRE_EQ(send(sockets[0], frame + 20, sizeof(frame) - 20,
	    MSG_EOR), (ssize_t)(sizeof(frame) - 20));
	do {
		stream.receive_deadline = (struct timespec){ 0, 0 };
		error = virtio_fs_backend_stream_receive(&stream, sockets[1],
		    &received, output, sizeof(output), &output_len);
	} while (error == EAGAIN);
	ATF_CHECK_EQ(error, 0);
	ATF_CHECK_EQ(output_len, 16);
	ATF_CHECK(memcmp(output, frame + 40, 16) == 0);

	ATF_REQUIRE_EQ(send(sockets[0], frame, 20, 0), 20);
	ATF_CHECK_EQ(virtio_fs_backend_stream_receive(&stream, sockets[1],
	    &received, output, sizeof(output), &output_len), EAGAIN);
	ATF_CHECK(virtio_fs_backend_stream_receiving(&stream));
	stream.receive_deadline = (struct timespec){ 0, 0 };
	ATF_CHECK_EQ(virtio_fs_backend_stream_receive(&stream, sockets[1],
	    &received, output, sizeof(output), &output_len), ETIMEDOUT);
	ATF_CHECK(!virtio_fs_backend_stream_receiving(&stream));
	virtio_fs_backend_stream_fini(&stream);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

/*
 * A flush that runs after the progress deadline but finds room moves the
 * tail on; one that finds the peer still full reports ETIMEDOUT.
 */
ATF_TC_WITHOUT_HEAD(late_flush_moves_before_expiring);
ATF_TC_BODY(late_flush_moves_before_expiring, tc)
{
	struct virtio_fs_backend_stream stream;
	struct virtio_fs_backend_header sent;
	uint8_t payload[4096], sink[4096 + 40];
	size_t left;
	int size, sockets[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0,
	    sockets), 0);
	size = 64;
	ATF_REQUIRE_EQ(setsockopt(sockets[1], SOL_SOCKET, SO_RCVBUF, &size,
	    sizeof(size)), 0);
	sent = request_header(sizeof(payload));
	memset(payload, 0xa5, sizeof(payload));
	virtio_fs_backend_stream_init(&stream);
	ATF_REQUIRE_EQ(virtio_fs_backend_stream_send(&stream, sockets[0], &sent,
	    payload), 0);
	ATF_REQUIRE(virtio_fs_backend_stream_sending(&stream));

	left = stream.send_len - stream.send_done;
	ATF_REQUIRE(recv(sockets[1], sink, sizeof(sink), MSG_DONTWAIT) > 0);
	stream.send_deadline = (struct timespec){ 0, 0 };
	ATF_CHECK_EQ(virtio_fs_backend_stream_flush(&stream, sockets[0]),
	    EAGAIN);
	ATF_CHECK(stream.send_len - stream.send_done < left);

	stream.send_deadline = (struct timespec){ 0, 0 };
	ATF_CHECK_EQ(virtio_fs_backend_stream_flush(&stream, sockets[0]),
	    ETIMEDOUT);
	virtio_fs_backend_stream_fini(&stream);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

/*
 * Rights attached to a later piece of a frame fail it and are closed.  The
 * kernel would dispose of them silently if the piece were read without a
 * control buffer.
 */
ATF_TC_WITHOUT_HEAD(descriptors_in_a_continuation_fail_the_frame);
ATF_TC_BODY(descriptors_in_a_continuation_fail_the_frame, tc)
{
	union {
		struct cmsghdr alignment;
		unsigned char bytes[CMSG_SPACE(sizeof(int))];
	} control;
	struct virtio_fs_backend_stream stream;
	struct virtio_fs_backend_header received, sent;
	uint8_t output[1], wire[40];
	struct cmsghdr *cmsg;
	struct iovec vector;
	struct msghdr message;
	unsigned int before;
	size_t output_len;
	int descriptor, sockets[2];

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0,
	    sockets), 0);
	descriptor = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(descriptor >= 0);
	sent = request_header(0);
	ATF_REQUIRE_EQ(virtio_fs_backend_header_encode(&sent, wire), 0);
	ATF_REQUIRE_EQ(send(sockets[0], wire, 20, 0), 20);
	virtio_fs_backend_stream_init(&stream);
	ATF_REQUIRE_EQ(virtio_fs_backend_stream_receive(&stream, sockets[1],
	    &received, output, sizeof(output), &output_len), EAGAIN);
	vector.iov_base = wire + 20;
	vector.iov_len = sizeof(wire) - 20;
	memset(&control, 0, sizeof(control));
	memset(&message, 0, sizeof(message));
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	cmsg = CMSG_FIRSTHDR(&message);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &descriptor, sizeof(descriptor));
	ATF_REQUIRE_EQ(sendmsg(sockets[0], &message, MSG_EOR),
	    (ssize_t)(sizeof(wire) - 20));
	ATF_REQUIRE_EQ(close(descriptor), 0);
	before = open_descriptor_count();
	ATF_CHECK_EQ(virtio_fs_backend_stream_receive(&stream, sockets[1],
	    &received, output, sizeof(output), &output_len), EPROTO);
	ATF_CHECK_EQ(open_descriptor_count(), before);
	virtio_fs_backend_stream_fini(&stream);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, api_errors_and_peer_close);
	ATF_TP_ADD_TC(tp, backend_connect_is_bounded_and_authenticated);
	ATF_TP_ADD_TC(tp, backend_connect_supports_long_parent_path);
	ATF_TP_ADD_TC(tp, peer_authentication);
	ATF_TP_ADD_TC(tp, frame_round_trip_and_nonblocking);
	ATF_TP_ADD_TC(tp, truncation_and_bad_frames);
	ATF_TP_ADD_TC(tp, descriptor_passing_is_rejected);
	ATF_TP_ADD_TC(tp, truncated_descriptors_are_closed);
	ATF_TP_ADD_TC(tp, receive_outputs_must_not_alias);
	ATF_TP_ADD_TC(tp, back_to_back_frames_keep_boundaries);
	ATF_TP_ADD_TC(tp, frames_larger_than_socket_buffer_are_reassembled);
	ATF_TP_ADD_TC(tp, full_length_without_eor_is_rejected);
	ATF_TP_ADD_TC(tp, partial_frame_resumes_without_waiting);
	ATF_TP_ADD_TC(tp, late_receive_moves_before_expiring);
	ATF_TP_ADD_TC(tp, late_flush_moves_before_expiring);
	ATF_TP_ADD_TC(tp, descriptors_in_a_continuation_fail_the_frame);
	return (atf_no_error());
}
