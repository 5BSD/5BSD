/* Event-driven client tests for the private virtio-fs backend handshake. */
#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "virtio_fs_backend.c"
#include "virtio_fs_backend_io.c"
#include "virtio_fs_backend_client.c"

#define	DOC_PROTOCOL_VERSION	1U
#define	DOC_HELLO_SIZE		20U
#define	DOC_FEATURE_CANCEL	(UINT32_C(1) << 0)
#define	DOC_FEATURE_FREEZE	(UINT32_C(1) << 1)
#define	DOC_MAX_MESSAGE		4096U
#define	DOC_MAX_INFLIGHT	16U
#define	DOC_MAX_PENDING		65536U

static struct virtio_fs_backend_hello
client_offer(void)
{

	return ((struct virtio_fs_backend_hello) {
		.minimum_version = DOC_PROTOCOL_VERSION,
		.maximum_version = DOC_PROTOCOL_VERSION,
		.features = DOC_FEATURE_CANCEL | DOC_FEATURE_FREEZE,
		.maximum_message = DOC_MAX_MESSAGE,
		.maximum_inflight = DOC_MAX_INFLIGHT,
		.maximum_pending_bytes = DOC_MAX_PENDING,
	});
}

static void
receive_hello(int fd, struct virtio_fs_backend_header *header)
{
	uint8_t payload[DOC_HELLO_SIZE];
	size_t payload_len;

	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fd, header, payload,
	    sizeof(payload), &payload_len), 0);
	ATF_REQUIRE_EQ(payload_len, DOC_HELLO_SIZE);
	ATF_CHECK_EQ(le16dec(payload), DOC_PROTOCOL_VERSION);
	ATF_CHECK_EQ(le16dec(payload + 2), DOC_PROTOCOL_VERSION);
	ATF_CHECK_EQ(le32dec(payload + 4),
	    DOC_FEATURE_CANCEL | DOC_FEATURE_FREEZE);
	ATF_CHECK_EQ(le32dec(payload + 8), DOC_MAX_MESSAGE);
	ATF_CHECK_EQ(le32dec(payload + 12), DOC_MAX_INFLIGHT);
	ATF_CHECK_EQ(le32dec(payload + 16), DOC_MAX_PENDING);
}

static void
send_selection(int fd, const struct virtio_fs_backend_header *request,
    int32_t status, uint32_t maximum_inflight)
{
	struct virtio_fs_backend_header reply;
	struct virtio_fs_backend_hello selection;
	uint8_t payload[DOC_HELLO_SIZE];
	int error;

	reply = (struct virtio_fs_backend_header) {
		.version = DOC_PROTOCOL_VERSION,
		.type = VIRTIO_FS_BACKEND_HELLO_REPLY,
		.payload_len = status == 0 ? DOC_HELLO_SIZE : 0,
		.request_id = request->request_id,
		.status = status,
	};
	if (status == 0) {
		selection = client_offer();
		selection.maximum_inflight = maximum_inflight;
		ATF_REQUIRE_EQ(virtio_fs_backend_hello_encode(&selection,
		    payload), 0);
	}
	error = virtio_fs_backend_send_frame(fd, &reply,
	    status == 0 ? payload : NULL);
	ATF_REQUIRE_EQ(error, 0);
}

ATF_TC_WITHOUT_HEAD(event_driven_handshake_and_transfer);
ATF_TC_BODY(event_driven_handshake_and_transfer, tc)
{
	struct virtio_fs_backend_client *client;
	struct virtio_fs_backend_header request;
	struct virtio_fs_backend_hello offer;
	struct virtio_fs_backend_session session;
	int adopted, sockets[2];

	offer = client_offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_client_adopt(sockets[0], geteuid(),
	    getegid(), &offer, &client), 0);
	ATF_CHECK_EQ(virtio_fs_backend_client_fd(client), sockets[0]);
	ATF_CHECK_EQ(virtio_fs_backend_client_events(client),
	    VIRTIO_FS_BACKEND_CLIENT_WRITE);
	ATF_CHECK_EQ(virtio_fs_backend_client_progress(client, false, false),
	    EAGAIN);
	ATF_REQUIRE_EQ(virtio_fs_backend_client_progress(client, false, true),
	    EAGAIN);
	ATF_CHECK_EQ(virtio_fs_backend_client_events(client),
	    VIRTIO_FS_BACKEND_CLIENT_READ);
	receive_hello(sockets[1], &request);
	ATF_CHECK_EQ(request.type, VIRTIO_FS_BACKEND_HELLO);
	ATF_CHECK_EQ(request.request_id, 1);
	ATF_CHECK_EQ(request.incarnation, 0);
	send_selection(sockets[1], &request, 0, 8);
	ATF_REQUIRE_EQ(virtio_fs_backend_client_progress(client, true, false),
	    0);
	ATF_CHECK(virtio_fs_backend_client_active(client));
	ATF_CHECK_EQ(virtio_fs_backend_client_fd(client), sockets[0]);
	ATF_CHECK_EQ(virtio_fs_backend_client_events(client), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_client_take_active(client, &session,
	    &adopted), 0);
	ATF_CHECK_EQ(adopted, sockets[0]);
	ATF_CHECK_EQ(session.phase, VIRTIO_FS_BACKEND_ACTIVE);
	ATF_CHECK_EQ(session.incarnation, 1);
	ATF_CHECK_EQ(session.maximum_inflight, 8);
	ATF_CHECK_EQ(virtio_fs_backend_client_fd(client), -1);
	ATF_CHECK_EQ(virtio_fs_backend_client_take_active(client, &session,
	    &adopted), EBUSY);
	virtio_fs_backend_client_destroy(client);
	ATF_REQUIRE_EQ(close(adopted), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(rejected_and_malformed_handshakes_fail_closed);
ATF_TC_BODY(rejected_and_malformed_handshakes_fail_closed, tc)
{
	struct virtio_fs_backend_client *client;
	struct virtio_fs_backend_header request;
	struct virtio_fs_backend_hello offer;
	int error, sockets[2];

	offer = client_offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_client_adopt(sockets[0], geteuid(),
	    getegid(), &offer, &client), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_client_progress(client, false, true),
	    EAGAIN);
	receive_hello(sockets[1], &request);
	send_selection(sockets[1], &request, -EPERM, 0);
	ATF_CHECK_EQ(virtio_fs_backend_client_progress(client, true, false),
	    ECONNREFUSED);
	ATF_CHECK(!virtio_fs_backend_client_active(client));
	ATF_CHECK_EQ(virtio_fs_backend_client_error(client), ECONNREFUSED);
	ATF_CHECK_EQ(virtio_fs_backend_client_events(client), 0);
	virtio_fs_backend_client_destroy(client);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);

	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK |
	    SOCK_CLOEXEC, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_client_adopt(sockets[0], geteuid(),
	    getegid(), &offer, &client), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_client_progress(client, false, true),
	    EAGAIN);
	receive_hello(sockets[1], &request);
	request.request_id++;
	send_selection(sockets[1], &request, 0, DOC_MAX_INFLIGHT);
	error = virtio_fs_backend_client_progress(client, true, false);
	ATF_CHECK_EQ(error, EPROTO);
	error = virtio_fs_backend_client_error(client);
	ATF_CHECK_EQ(error, EPROTO);
	virtio_fs_backend_client_destroy(client);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(api_and_selection_bounds);
ATF_TC_BODY(api_and_selection_bounds, tc)
{
	struct virtio_fs_backend_client *client;
	struct virtio_fs_backend_header request;
	struct virtio_fs_backend_hello offer;
	int sockets[2];

	offer = client_offer();
	ATF_CHECK_EQ(virtio_fs_backend_client_adopt(-1, geteuid(), getegid(),
	    &offer, &client), EBADF);
	ATF_CHECK_EQ(virtio_fs_backend_client_fd(NULL), -1);
	offer.maximum_message = 0;
	ATF_CHECK_EQ(virtio_fs_backend_client_adopt(-1, geteuid(), getegid(),
	    &offer, &client), EINVAL);
	offer = client_offer();
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK,
	    0, sockets), 0);
	ATF_CHECK_EQ(virtio_fs_backend_client_adopt(sockets[0], geteuid(),
	    getegid() + 1, &offer, &client), EACCES);
	ATF_CHECK(fcntl(sockets[0], F_GETFD) >= 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_client_adopt(sockets[0], geteuid(),
	    getegid(), &offer, &client), 0);
	ATF_CHECK((fcntl(sockets[0], F_GETFD) & FD_CLOEXEC) != 0);
	ATF_CHECK_EQ(virtio_fs_backend_client_take_active(client, NULL,
	    &sockets[0]), EINVAL);
	ATF_REQUIRE_EQ(virtio_fs_backend_client_progress(client, false, true),
	    EAGAIN);
	receive_hello(sockets[1], &request);
	send_selection(sockets[1], &request, 0, DOC_MAX_INFLIGHT + 1);
	ATF_CHECK_EQ(virtio_fs_backend_client_progress(client, true, false),
	    EPROTO);
	virtio_fs_backend_client_destroy(client);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, event_driven_handshake_and_transfer);
	ATF_TP_ADD_TC(tp, rejected_and_malformed_handshakes_fail_closed);
	ATF_TP_ADD_TC(tp, api_and_selection_bounds);
	return (atf_no_error());
}
