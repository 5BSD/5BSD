/*
 * Unix-domain transport tests for the private VFSB protocol.
 */
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, api_errors_and_peer_close);
	ATF_TP_ADD_TC(tp, backend_connect_is_bounded_and_authenticated);
	ATF_TP_ADD_TC(tp, peer_authentication);
	ATF_TP_ADD_TC(tp, frame_round_trip_and_nonblocking);
	ATF_TP_ADD_TC(tp, truncation_and_bad_frames);
	ATF_TP_ADD_TC(tp, descriptor_passing_is_rejected);
	ATF_TP_ADD_TC(tp, truncated_descriptors_are_closed);
	ATF_TP_ADD_TC(tp, receive_outputs_must_not_alias);
	return (atf_no_error());
}
