/*
 * Bounded, priority-preserving VirtIO filesystem backend outbox tests.
 */
#include <sys/socket.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "virtio_fs_backend.c"
#include "virtio_fs_backend_io.c"
#include "virtio_fs_outbox.c"

#define	DOC_MAX_MESSAGE	64U
#define	DOC_MAX_PENDING	128U

static struct virtio_fs_backend_header
request(uint64_t id, uint32_t length)
{

	return ((struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_REQUEST,
		.payload_len = length,
		.request_id = id,
		.incarnation = 3,
	});
}

ATF_TC_WITHOUT_HEAD(priority_precedes_normal);
ATF_TC_BODY(priority_precedes_normal, tc)
{
	struct virtio_fs_backend_header header, received, sent;
	struct virtio_fs_outbox *outbox;
	uint8_t normal[] = { 1 }, priority[] = { 2 }, output[1];
	size_t output_len;
	int sockets[2];

	ATF_REQUIRE_EQ(virtio_fs_outbox_create(2, 2, DOC_MAX_MESSAGE,
	    DOC_MAX_PENDING, &outbox), 0);
	header = request(1, sizeof(normal));
	ATF_REQUIRE_EQ(virtio_fs_outbox_enqueue(outbox, false, &header,
	    normal), 0);
	header = request(2, sizeof(priority));
	ATF_REQUIRE_EQ(virtio_fs_outbox_enqueue(outbox, true, &header,
	    priority), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_outbox_flush_one(outbox, sockets[0],
	    &sent), 0);
	ATF_CHECK_EQ(sent.request_id, 2);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(sockets[1], &received,
	    output, sizeof(output), &output_len), 0);
	ATF_CHECK_EQ(received.request_id, 2);
	ATF_CHECK_EQ(output[0], 2);
	ATF_REQUIRE_EQ(virtio_fs_outbox_flush_one(outbox, sockets[0],
	    &sent), 0);
	ATF_CHECK_EQ(sent.request_id, 1);
	ATF_CHECK_EQ(virtio_fs_outbox_flush_one(outbox, sockets[0], &sent),
	    ENOENT);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	virtio_fs_outbox_destroy(outbox);
}

ATF_TC_WITHOUT_HEAD(priority_capacity_is_reserved);
ATF_TC_BODY(priority_capacity_is_reserved, tc)
{
	struct virtio_fs_backend_header header;
	struct virtio_fs_outbox *outbox;
	uint8_t payload[DOC_MAX_MESSAGE];

	memset(payload, 0xa5, sizeof(payload));
	ATF_REQUIRE_EQ(virtio_fs_outbox_create(2, 1, DOC_MAX_MESSAGE,
	    DOC_MAX_PENDING, &outbox), 0);
	header = request(1, sizeof(payload));
	ATF_REQUIRE_EQ(virtio_fs_outbox_enqueue(outbox, false, &header,
	    payload), 0);
	header = request(2, 1);
	ATF_CHECK_EQ(virtio_fs_outbox_enqueue(outbox, false, &header,
	    payload), ENOBUFS);
	header = request(3, sizeof(payload));
	ATF_REQUIRE_EQ(virtio_fs_outbox_enqueue(outbox, true, &header,
	    payload), 0);
	ATF_CHECK_EQ(virtio_fs_outbox_count(outbox, false), 1);
	ATF_CHECK_EQ(virtio_fs_outbox_count(outbox, true), 1);
	ATF_CHECK_EQ(virtio_fs_outbox_bytes(outbox), DOC_MAX_PENDING);
	virtio_fs_outbox_destroy(outbox);
}

ATF_TC_WITHOUT_HEAD(send_failure_preserves_frame);
ATF_TC_BODY(send_failure_preserves_frame, tc)
{
	struct virtio_fs_backend_header header, sent;
	struct virtio_fs_outbox *outbox;
	uint8_t payload = 7;
	int sockets[2];

	ATF_REQUIRE_EQ(virtio_fs_outbox_create(1, 1, DOC_MAX_MESSAGE,
	    DOC_MAX_PENDING, &outbox), 0);
	header = request(9, 1);
	ATF_REQUIRE_EQ(virtio_fs_outbox_enqueue(outbox, false, &header,
	    &payload), 0);
	ATF_CHECK_EQ(virtio_fs_outbox_flush_one(outbox, -1, &sent), EBADF);
	ATF_CHECK_EQ(virtio_fs_outbox_count(outbox, false), 1);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_outbox_flush_one(outbox, sockets[0],
	    &sent), 0);
	ATF_CHECK_EQ(sent.request_id, 9);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	virtio_fs_outbox_destroy(outbox);
}

ATF_TC_WITHOUT_HEAD(constructor_and_frame_validation);
ATF_TC_BODY(constructor_and_frame_validation, tc)
{
	struct virtio_fs_backend_header header;
	struct virtio_fs_outbox *outbox;
	uint8_t payload[DOC_MAX_MESSAGE + 1];

	ATF_CHECK_EQ(virtio_fs_outbox_create(1, 1, DOC_MAX_MESSAGE,
	    DOC_MAX_MESSAGE, &outbox), EINVAL);
	ATF_REQUIRE_EQ(virtio_fs_outbox_create(1, 1, DOC_MAX_MESSAGE,
	    DOC_MAX_PENDING, &outbox), 0);
	header = request(1, sizeof(payload));
	ATF_CHECK_EQ(virtio_fs_outbox_enqueue(outbox, false, &header,
	    payload), EMSGSIZE);
	header = request(1, 1);
	ATF_CHECK_EQ(virtio_fs_outbox_enqueue(outbox, false, &header, NULL),
	    EINVAL);
	virtio_fs_outbox_destroy(outbox);
}

ATF_TC_WITHOUT_HEAD(reset_preserves_limits);
ATF_TC_BODY(reset_preserves_limits, tc)
{
	struct virtio_fs_backend_header header;
	struct virtio_fs_outbox *outbox;
	uint8_t payload = 1;

	ATF_REQUIRE_EQ(virtio_fs_outbox_create(1, 1, DOC_MAX_MESSAGE,
	    DOC_MAX_PENDING, &outbox), 0);
	header = request(1, 1);
	ATF_REQUIRE_EQ(virtio_fs_outbox_enqueue(outbox, false, &header,
	    &payload), 0);
	header = request(2, 1);
	ATF_REQUIRE_EQ(virtio_fs_outbox_enqueue(outbox, true, &header,
	    &payload), 0);
	ATF_CHECK_EQ(virtio_fs_outbox_reset(outbox), 2);
	ATF_CHECK_EQ(virtio_fs_outbox_count(outbox, false), 0);
	ATF_CHECK_EQ(virtio_fs_outbox_count(outbox, true), 0);
	header = request(3, 1);
	ATF_REQUIRE_EQ(virtio_fs_outbox_enqueue(outbox, false, &header,
	    &payload), 0);
	ATF_CHECK_EQ(virtio_fs_outbox_reset(outbox), 1);
	virtio_fs_outbox_destroy(outbox);
}

ATF_TC_WITHOUT_HEAD(selective_reset_preserves_other_queues);
ATF_TC_BODY(selective_reset_preserves_other_queues, tc)
{
	struct virtio_fs_backend_header header, sent;
	struct virtio_fs_outbox *outbox;
	uint8_t payload = 1;
	int sockets[2];

	ATF_REQUIRE_EQ(virtio_fs_outbox_create(3, 2, DOC_MAX_MESSAGE,
	    DOC_MAX_PENDING, &outbox), 0);
	for (uint64_t i = 1; i <= 3; i++) {
		header = request(i, 1);
		ATF_REQUIRE_EQ(virtio_fs_outbox_enqueue_on(outbox, i == 2,
		    i == 2 ? 7 : 9, &header, &payload), 0);
	}
	ATF_CHECK_EQ(virtio_fs_outbox_reset_queue(outbox, 9), 2);
	ATF_CHECK_EQ(virtio_fs_outbox_count(outbox, false), 0);
	ATF_CHECK_EQ(virtio_fs_outbox_count(outbox, true), 1);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_outbox_flush_one(outbox, sockets[0],
	    &sent), 0);
	ATF_CHECK_EQ(sent.request_id, 2);
	ATF_CHECK_EQ(virtio_fs_outbox_reset_queue(outbox, 7), 0);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	virtio_fs_outbox_destroy(outbox);
}

ATF_TC_WITHOUT_HEAD(completion_output_must_not_alias_outbox);
ATF_TC_BODY(completion_output_must_not_alias_outbox, tc)
{
	struct virtio_fs_backend_header header, sent;
	struct virtio_fs_outbox *outbox;
	uint8_t payload = 1;
	int sockets[2];

	ATF_REQUIRE_EQ(virtio_fs_outbox_create(1, 1, DOC_MAX_MESSAGE,
	    DOC_MAX_PENDING, &outbox), 0);
	header = request(1, sizeof(payload));
	ATF_REQUIRE_EQ(virtio_fs_outbox_enqueue(outbox, false, &header,
	    &payload), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	ATF_CHECK_EQ(virtio_fs_outbox_flush_one(outbox, sockets[0],
	    (struct virtio_fs_backend_header *)(void *)outbox), EINVAL);
	ATF_CHECK_EQ(virtio_fs_outbox_count(outbox, false), 1);
	ATF_REQUIRE_EQ(virtio_fs_outbox_flush_one(outbox, sockets[0],
	    &sent), 0);
	ATF_CHECK_EQ(sent.request_id, 1);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	virtio_fs_outbox_destroy(outbox);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, completion_output_must_not_alias_outbox);
	ATF_TP_ADD_TC(tp, priority_precedes_normal);
	ATF_TP_ADD_TC(tp, priority_capacity_is_reserved);
	ATF_TP_ADD_TC(tp, send_failure_preserves_frame);
	ATF_TP_ADD_TC(tp, constructor_and_frame_validation);
	ATF_TP_ADD_TC(tp, reset_preserves_limits);
	ATF_TP_ADD_TC(tp, selective_reset_preserves_other_queues);
	return (atf_no_error());
}
