/*
 * Queue-to-backend ownership tests for the unadvertised VirtIO filesystem.
 */
#include <sys/endian.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_fs_host.c"
#include "virtio_fs_backend.c"
#include "virtio_fs_pending.c"
#include "virtio_fs_dispatch.c"

#define	DOC_FUSE_IN_HEADER_SIZE		40U
#define	DOC_FUSE_INIT_IN_MIN_SIZE	56U
#define	DOC_FUSE_OUT_HEADER_SIZE	16U
#define	DOC_FUSE_INIT_OUT_MIN_SIZE	24U
#define	DOC_FUSE_INIT			26U
#define	DOC_FUSE_FORGET			2U
#define	DOC_FUSE_LOOKUP			1U
#define	DOC_FUSE_EIO			5

static struct virtio_fs_backend_session
active_backend(uint32_t inflight, uint32_t maximum_message)
{

	return ((struct virtio_fs_backend_session) {
		.phase = VIRTIO_FS_BACKEND_ACTIVE,
		.version = 1,
		.features = VIRTIO_FS_BACKEND_F_CANCEL |
		    VIRTIO_FS_BACKEND_F_FREEZE,
		.maximum_message = maximum_message,
		.maximum_inflight = inflight,
		.maximum_pending_bytes = maximum_message * inflight,
		.incarnation = 7,
	});
}

static void
fuse_request(uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE], uint32_t opcode,
    uint64_t unique)
{
	uint32_t length;

	length = opcode == DOC_FUSE_INIT ? DOC_FUSE_INIT_IN_MIN_SIZE :
	    opcode == DOC_FUSE_FORGET ? DOC_FUSE_IN_HEADER_SIZE + 8 :
	    DOC_FUSE_IN_HEADER_SIZE;
	memset(request, 0, DOC_FUSE_INIT_IN_MIN_SIZE);
	le32enc(request, length);
	le32enc(request + 4, opcode);
	le64enc(request + 8, unique);
	if (opcode == DOC_FUSE_INIT) {
		le32enc(request + DOC_FUSE_IN_HEADER_SIZE, 7);
		le32enc(request + DOC_FUSE_IN_HEADER_SIZE + 4, 31);
	}
}

static size_t
fuse_request_size(const uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE])
{

	return (le32dec(request));
}

static void
fuse_response(uint8_t response[DOC_FUSE_INIT_OUT_MIN_SIZE], int32_t error,
    uint64_t unique)
{

	memset(response, 0, DOC_FUSE_INIT_OUT_MIN_SIZE);
	le32enc(response, DOC_FUSE_INIT_OUT_MIN_SIZE);
	le32enc(response + 4, (uint32_t)error);
	le64enc(response + 8, unique);
	le32enc(response + 16, 7);
	le32enc(response + 20, 31);
}

static struct virtio_fs_backend_header
backend_response(const struct virtio_fs_backend_header *request,
    uint32_t payload_len)
{

	return ((struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_RESPONSE,
		.payload_len = payload_len,
		.request_id = request->request_id,
		.incarnation = request->incarnation,
	});
}

struct publish_state {
	int error;
	unsigned int calls;
	uint64_t request_id;
};

static int
publish_request(void *arg, const struct virtio_fs_backend_header *header,
    const void *payload)
{
	struct publish_state *state;

	state = arg;
	ATF_REQUIRE(payload != NULL);
	ATF_CHECK_EQ(header->type, VIRTIO_FS_BACKEND_REQUEST);
	state->calls++;
	state->request_id = header->request_id;
	return (state->error);
}

ATF_TC_WITHOUT_HEAD(transactional_publication);
ATF_TC_BODY(transactional_publication, tc)
{
	struct virtio_fs_backend_session backend;
	struct virtio_fs_backend_header outbound;
	struct virtio_fs_dispatch *dispatch;
	struct publish_state publisher;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE], guest[32];

	backend = active_backend(2, 4096);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_create(&backend, &dispatch), 0);
	fuse_request(request, DOC_FUSE_INIT, 8);
	memset(&publisher, 0, sizeof(publisher));
	publisher.error = ENOBUFS;
	ATF_CHECK_EQ(virtio_fs_dispatch_submit_publish_owned(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest), (uintptr_t)0x1234, publish_request, &publisher,
	    &outbound), ENOBUFS);
	ATF_CHECK_EQ(publisher.calls, 1);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 0);

	/* Failed publication must not publish the candidate INIT session. */
	fuse_request(request, DOC_FUSE_LOOKUP, 9);
	ATF_CHECK_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest), &outbound), EPROTO);

	fuse_request(request, DOC_FUSE_INIT, 10);
	publisher.error = 0;
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit_publish_owned(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest), (uintptr_t)0x5678, publish_request, &publisher,
	    &outbound), 0);
	ATF_CHECK_EQ(publisher.calls, 2);
	ATF_CHECK_EQ(outbound.request_id, publisher.request_id);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);
	virtio_fs_dispatch_destroy(dispatch);
}

ATF_TC_WITHOUT_HEAD(portable_error_response);
ATF_TC_BODY(portable_error_response, tc)
{
	struct virtio_fs_request_context request;
	uint8_t output[DOC_FUSE_OUT_HEADER_SIZE];

	memset(&request, 0, sizeof(request));
	ATF_CHECK_EQ(virtio_fs_dispatch_error_response(&request, output),
	    EINVAL);
	request.byte_order = VIRTIO_FS_BYTE_ORDER_LITTLE;
	request.unique = 0x1234;
	ATF_REQUIRE_EQ(virtio_fs_dispatch_error_response(&request, output), 0);
	ATF_CHECK_EQ(le32dec(output), DOC_FUSE_OUT_HEADER_SIZE);
	ATF_CHECK_EQ((int32_t)le32dec(output + 4), -DOC_FUSE_EIO);
	ATF_CHECK_EQ(le64dec(output + 8), request.unique);
	request.byte_order = VIRTIO_FS_BYTE_ORDER_BIG;
	ATF_REQUIRE_EQ(virtio_fs_dispatch_error_response(&request, output), 0);
	ATF_CHECK_EQ(be32dec(output), DOC_FUSE_OUT_HEADER_SIZE);
	ATF_CHECK_EQ((int32_t)be32dec(output + 4), -DOC_FUSE_EIO);
	ATF_CHECK_EQ(be64dec(output + 8), request.unique);
}

ATF_TC_WITHOUT_HEAD(transactional_submit_and_completion);
ATF_TC_BODY(transactional_submit_and_completion, tc)
{
	struct virtio_fs_backend_session backend;
	struct virtio_fs_backend_header outbound, reply;
	struct virtio_fs_dispatch *dispatch;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE];
	uint8_t response[DOC_FUSE_INIT_OUT_MIN_SIZE], guest[32];
	size_t written;
	uintptr_t owner;

	backend = active_backend(2, 4096);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_create(&backend, &dispatch), 0);
	fuse_request(request, DOC_FUSE_INIT, 10);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit_owned(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest), (uintptr_t)0xfeed,
	    &outbound), 0);
	ATF_CHECK_EQ(outbound.type, VIRTIO_FS_BACKEND_REQUEST);
	ATF_CHECK_EQ(outbound.request_id, 1);
	ATF_CHECK_EQ(outbound.incarnation, 7);
	ATF_CHECK_EQ(outbound.payload_len, fuse_request_size(request));
	ATF_CHECK_EQ(outbound.flags, 0);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_owner(dispatch, outbound.request_id,
	    outbound.incarnation, &owner), 0);
	ATF_CHECK_EQ(owner, (uintptr_t)0xfeed);

	fuse_response(response, 0, 10);
	reply = backend_response(&outbound, sizeof(response));
	memset(guest, 0xa5, sizeof(guest));
	owner = 0;
	ATF_REQUIRE_EQ(virtio_fs_dispatch_complete_owned(dispatch, &reply,
	    response, sizeof(response), guest, sizeof(guest), &written,
	    &owner), 0);
	ATF_CHECK_EQ(written, sizeof(response));
	ATF_CHECK_EQ(owner, (uintptr_t)0xfeed);
	ATF_CHECK(memcmp(guest, response, sizeof(response)) == 0);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 0);
	ATF_CHECK_EQ(virtio_fs_dispatch_owner(dispatch, outbound.request_id,
	    outbound.incarnation, &owner), ENOENT);

	/* Successful INIT published the session, so normal traffic is legal. */
	fuse_request(request, DOC_FUSE_LOOKUP, 11);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest),
	    &outbound), 0);
	reply = backend_response(&outbound, sizeof(response));
	fuse_response(response, -2, 11);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_complete(dispatch, &reply, response,
	    sizeof(response), guest, sizeof(guest), &written), 0);
	ATF_CHECK_EQ((int32_t)le32dec(guest + 4), -2);
	virtio_fs_dispatch_destroy(dispatch);
}

ATF_TC_WITHOUT_HEAD(failures_preserve_or_retire_ownership);
ATF_TC_BODY(failures_preserve_or_retire_ownership, tc)
{
	struct virtio_fs_backend_session backend;
	struct virtio_fs_backend_header outbound, reply;
	struct virtio_fs_dispatch *dispatch;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE];
	uint8_t response[DOC_FUSE_INIT_OUT_MIN_SIZE], guest[32];
	size_t written;

	backend = active_backend(2, 4096);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_create(&backend, &dispatch), 0);
	fuse_request(request, DOC_FUSE_INIT, 20);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest),
	    &outbound), 0);
	reply = backend_response(&outbound, sizeof(response));
	fuse_response(response, 0, 99);	/* Wrong FUSE unique. */
	ATF_CHECK_EQ(virtio_fs_dispatch_complete(dispatch, &reply, response,
	    sizeof(response), guest, sizeof(guest), &written), EPROTO);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);

	/* Too-small guest space also leaves ownership available for recovery. */
	fuse_response(response, 0, 20);
	ATF_CHECK_EQ(virtio_fs_dispatch_complete(dispatch, &reply, response,
	    sizeof(response), guest, 8, &written), EMSGSIZE);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);

	ATF_REQUIRE_EQ(virtio_fs_dispatch_abort(dispatch, outbound.request_id,
	    outbound.incarnation, guest, sizeof(guest), &written), 0);
	ATF_CHECK_EQ(written, DOC_FUSE_OUT_HEADER_SIZE);
	ATF_CHECK_EQ((int32_t)le32dec(guest + 4), -DOC_FUSE_EIO);
	ATF_CHECK_EQ(le64dec(guest + 8), 20);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 0);
	virtio_fs_dispatch_destroy(dispatch);
}

ATF_TC_WITHOUT_HEAD(noreply_pause_disconnect_and_limits);
ATF_TC_BODY(noreply_pause_disconnect_and_limits, tc)
{
	struct virtio_fs_backend_session backend;
	struct virtio_fs_backend_header init_header, outbound, reply;
	struct virtio_fs_pending_result drained[2];
	struct virtio_fs_dispatch *dispatch;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE];
	uint8_t response[DOC_FUSE_INIT_OUT_MIN_SIZE], guest[32];
	uint32_t pending;
	size_t count, written;
	uintptr_t owner;

	backend = active_backend(1, DOC_FUSE_INIT_IN_MIN_SIZE);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_create(&backend, &dispatch), 0);
	fuse_request(request, DOC_FUSE_INIT, 30);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest),
	    &init_header), 0);

	/*
	 * Saturation must not publish the replacement INIT transition.  Once
	 * the original INIT completes, an ordinary request remains legal.
	 */
	fuse_request(request, DOC_FUSE_INIT, 31);
	ATF_CHECK_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest),
	    &outbound), EBUSY);
	fuse_response(response, 0, 30);
	reply = backend_response(&init_header, sizeof(response));
	ATF_REQUIRE_EQ(virtio_fs_dispatch_complete(dispatch, &reply, response,
	    sizeof(response), guest, sizeof(guest), &written), 0);

	fuse_request(request, DOC_FUSE_FORGET, 32);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit_owned(dispatch,
	    VIRTIO_FS_QUEUE_HIPRIO, request, fuse_request_size(request), 0,
	    (uintptr_t)0xbeef, &outbound),
	    0);
	ATF_CHECK_EQ(outbound.request_id, 2);
	ATF_CHECK_EQ(outbound.flags, VIRTIO_FS_BACKEND_MSG_F_NOREPLY);
	owner = 0;
	ATF_REQUIRE_EQ(virtio_fs_dispatch_noreply_sent_owned(dispatch,
	    outbound.request_id, outbound.incarnation, &owner), 0);
	ATF_CHECK_EQ(owner, (uintptr_t)0xbeef);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 0);

	ATF_REQUIRE_EQ(virtio_fs_dispatch_pause(dispatch, &pending), 0);
	ATF_CHECK_EQ(pending, 0);
	fuse_request(request, DOC_FUSE_LOOKUP, 33);
	ATF_CHECK_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest),
	    &outbound), EBUSY);
	virtio_fs_dispatch_resume(dispatch);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest),
	    &outbound), 0);
	count = 0;
	ATF_CHECK_EQ(virtio_fs_dispatch_disconnect(dispatch, NULL, 0, &count),
	    EMSGSIZE);
	ATF_CHECK_EQ(count, 1);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_disconnect(dispatch, drained,
	    nitems(drained), &count), 0);
	ATF_CHECK_EQ(count, 1);
	ATF_CHECK_EQ(drained[0].request.unique, 33);
	ATF_CHECK_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest),
	    &outbound), EBUSY);
	virtio_fs_dispatch_destroy(dispatch);
}

ATF_TC_WITHOUT_HEAD(backend_error_is_portable_fuse_eio);
ATF_TC_BODY(backend_error_is_portable_fuse_eio, tc)
{
	struct virtio_fs_backend_session backend;
	struct virtio_fs_backend_header outbound, reply;
	struct virtio_fs_dispatch *dispatch;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE], guest[32];
	size_t written;

	backend = active_backend(1, 4096);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_create(&backend, &dispatch), 0);
	fuse_request(request, DOC_FUSE_INIT, 40);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest),
	    &outbound), 0);
	reply = backend_response(&outbound, 0);
	reply.status = -1234;	/* Private transport status is not guest errno. */
	ATF_REQUIRE_EQ(virtio_fs_dispatch_complete(dispatch, &reply, NULL, 0,
	    guest, sizeof(guest), &written), 0);
	ATF_CHECK_EQ(written, DOC_FUSE_OUT_HEADER_SIZE);
	ATF_CHECK_EQ((int32_t)le32dec(guest + 4), -DOC_FUSE_EIO);
	ATF_CHECK_EQ(le64dec(guest + 8), 40);
	virtio_fs_dispatch_destroy(dispatch);
}

ATF_TC_WITHOUT_HEAD(cancellation_is_explicit_and_retryable);
ATF_TC_BODY(cancellation_is_explicit_and_retryable, tc)
{
	struct virtio_fs_backend_session backend;
	struct virtio_fs_backend_header cancel, outbound, reply;
	struct virtio_fs_dispatch *dispatch;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE];
	uint8_t response[DOC_FUSE_INIT_OUT_MIN_SIZE], guest[32];
	size_t written;

	backend = active_backend(2, 4096);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_create(&backend, &dispatch), 0);
	fuse_request(request, DOC_FUSE_INIT, 50);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest),
	    &outbound), 0);
	fuse_response(response, 0, 50);
	reply = backend_response(&outbound, sizeof(response));
	ATF_REQUIRE_EQ(virtio_fs_dispatch_complete(dispatch, &reply, response,
	    sizeof(response), guest, sizeof(guest), &written), 0);

	fuse_request(request, DOC_FUSE_LOOKUP, 51);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest),
	    &outbound), 0);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_cancel(dispatch,
	    outbound.request_id, outbound.incarnation, &cancel), 0);
	ATF_CHECK_EQ(cancel.type, VIRTIO_FS_BACKEND_CANCEL);
	ATF_CHECK_EQ(cancel.request_id, outbound.request_id);
	/* A lost cancellation frame can be resent idempotently. */
	ATF_REQUIRE_EQ(virtio_fs_dispatch_cancel(dispatch,
	    outbound.request_id, outbound.incarnation, &cancel), 0);
	reply = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_CANCEL_REPLY,
		.request_id = cancel.request_id,
		.incarnation = cancel.incarnation,
	};
	written = 99;
	ATF_CHECK_EQ(virtio_fs_dispatch_cancel_complete(dispatch, &reply,
	    NULL, 0, &written), EMSGSIZE);
	ATF_CHECK_EQ(written, 0);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);
	reply = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_CANCEL_REPLY,
		.request_id = cancel.request_id,
		.incarnation = cancel.incarnation,
		.status = -EBUSY,
	};
	ATF_CHECK_EQ(virtio_fs_dispatch_cancel_complete(dispatch, &reply,
	    guest, sizeof(guest), &written), EIO);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);
	reply.status = 0;
	ATF_REQUIRE_EQ(virtio_fs_dispatch_cancel_complete(dispatch, &reply,
	    guest, sizeof(guest), &written), 0);
	ATF_CHECK_EQ(written, DOC_FUSE_OUT_HEADER_SIZE);
	ATF_CHECK_EQ((int32_t)le32dec(guest + 4), -DOC_FUSE_EIO);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 0);
	/* A duplicate late acknowledgement is a harmless cancellation race. */
	written = 99;
	ATF_CHECK_EQ(virtio_fs_dispatch_cancel_complete(dispatch, &reply,
	    guest, sizeof(guest), &written), 0);
	ATF_CHECK_EQ(written, 0);
	/*
	 * A backend may have completed the original operation before it
	 * observed CANCEL.  Its delayed normal reply is recognized by the
	 * bounded retirement index and cannot tear down the connection or
	 * recover the freed guest-chain owner.
	 */
	reply = backend_response(&outbound, DOC_FUSE_OUT_HEADER_SIZE);
	memset(response, 0, DOC_FUSE_OUT_HEADER_SIZE);
	le32enc(response, DOC_FUSE_OUT_HEADER_SIZE);
	le64enc(response + 8, 51);
	ATF_CHECK_EQ(virtio_fs_dispatch_complete(dispatch, &reply, response,
	    DOC_FUSE_OUT_HEADER_SIZE, guest, sizeof(guest), &written),
	    EALREADY);
	ATF_CHECK_EQ(virtio_fs_dispatch_retired_frame(dispatch, &reply,
	    DOC_FUSE_OUT_HEADER_SIZE), 0);

	/* The inverse race is also idempotent: the normal reply owns completion. */
	fuse_request(request, DOC_FUSE_LOOKUP, 52);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest), &outbound), 0);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_cancel(dispatch,
	    outbound.request_id, outbound.incarnation, &cancel), 0);
	reply = backend_response(&outbound, DOC_FUSE_OUT_HEADER_SIZE);
	memset(response, 0, DOC_FUSE_OUT_HEADER_SIZE);
	le32enc(response, DOC_FUSE_OUT_HEADER_SIZE);
	le64enc(response + 8, 52);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_complete(dispatch, &reply, response,
	    DOC_FUSE_OUT_HEADER_SIZE, guest, sizeof(guest), &written), 0);
	reply = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_CANCEL_REPLY,
		.request_id = cancel.request_id,
		.incarnation = cancel.incarnation,
	};
	ATF_CHECK_EQ(virtio_fs_dispatch_cancel_complete(dispatch, &reply,
	    guest, sizeof(guest), &written), 0);
	ATF_CHECK_EQ(written, 0);
	virtio_fs_dispatch_destroy(dispatch);

	backend.features = VIRTIO_FS_BACKEND_F_FREEZE;
	ATF_REQUIRE_EQ(virtio_fs_dispatch_create(&backend, &dispatch), 0);
	fuse_request(request, DOC_FUSE_INIT, 53);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest),
	    &outbound), 0);
	ATF_CHECK_EQ(virtio_fs_dispatch_cancel(dispatch,
	    outbound.request_id, outbound.incarnation, &cancel), ENOTSUP);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_abort(dispatch, outbound.request_id,
	    outbound.incarnation, guest, sizeof(guest), &written), 0);
	virtio_fs_dispatch_destroy(dispatch);
}

ATF_TC_WITHOUT_HEAD(session_state_alias_is_rejected);
ATF_TC_BODY(session_state_alias_is_rejected, tc)
{
	struct virtio_fs_backend_session backend;
	struct virtio_fs_dispatch *dispatch;
	struct virtio_fs_session session;
	uint32_t pending;

	backend = active_backend(2, 4096);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_create(&backend, &dispatch), 0);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_pause(dispatch, &pending), 0);
	ATF_CHECK_EQ(pending, 0);

	ATF_CHECK_EQ(virtio_fs_dispatch_session_snapshot(dispatch,
	    (struct virtio_fs_session *)(void *)dispatch), EINVAL);
	ATF_CHECK_EQ(virtio_fs_dispatch_session_restore(dispatch,
	    (const struct virtio_fs_session *)(const void *)dispatch), EINVAL);
	ATF_CHECK_EQ(virtio_fs_dispatch_session_snapshot(dispatch,
	    (struct virtio_fs_session *)(void *)dispatch->pending->entries),
	    EINVAL);
	ATF_CHECK_EQ(virtio_fs_dispatch_session_restore(dispatch,
	    (const struct virtio_fs_session *)(const void *)
	    dispatch->pending->buckets), EINVAL);
	ATF_CHECK_EQ(virtio_fs_dispatch_session_snapshot(dispatch,
	    (struct virtio_fs_session *)(void *)dispatch->tombstones), EINVAL);
	ATF_CHECK_EQ(virtio_fs_dispatch_session_restore(dispatch,
	    (const struct virtio_fs_session *)(const void *)
	    dispatch->tombstone_buckets), EINVAL);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_session_snapshot(dispatch,
	    &session), 0);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_session_restore(dispatch,
	    &session), 0);
	virtio_fs_dispatch_destroy(dispatch);
}

ATF_TC_WITHOUT_HEAD(publication_aliases_are_rejected);
ATF_TC_BODY(publication_aliases_are_rejected, tc)
{
	struct virtio_fs_backend_session backend;
	struct virtio_fs_backend_header cancel, outbound, reply;
	struct virtio_fs_dispatch *dispatch;
	struct virtio_fs_pending_result drained;
	struct virtio_fs_request_context context, context_before;
	uint8_t request[DOC_FUSE_INIT_IN_MIN_SIZE];
	uint8_t response[DOC_FUSE_INIT_OUT_MIN_SIZE], guest[32];
	size_t count, written;
	uintptr_t owner;
	uint32_t pending;

	backend = active_backend(2, 4096);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_create(&backend, &dispatch), 0);
	fuse_request(request, DOC_FUSE_INIT, 70);

	/* Output aliases must fail before accepting or reserving the request. */
	ATF_CHECK_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest), (struct virtio_fs_backend_header *)(void *)dispatch),
	    EINVAL);
	ATF_CHECK_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest), (struct virtio_fs_backend_header *)(void *)request),
	    EINVAL);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 0);
	ATF_CHECK_EQ(virtio_fs_dispatch_pause(dispatch,
	    (uint32_t *)(void *)dispatch), EINVAL);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit_owned(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest), (uintptr_t)0x7070, &outbound), 0);

	ATF_CHECK_EQ(virtio_fs_dispatch_owner(dispatch, outbound.request_id,
	    outbound.incarnation, (uintptr_t *)(void *)dispatch), EINVAL);
	ATF_CHECK_EQ(virtio_fs_dispatch_cancel(dispatch, outbound.request_id,
	    outbound.incarnation,
	    (struct virtio_fs_backend_header *)(void *)dispatch), EINVAL);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);

	fuse_response(response, 0, 70);
	reply = backend_response(&outbound, sizeof(response));
	written = 0x7171;
	owner = 0x7272;
	ATF_CHECK_EQ(virtio_fs_dispatch_complete_owned(dispatch, &reply,
	    response, sizeof(response), dispatch, sizeof(guest), &written,
	    &owner), EINVAL);
	ATF_CHECK_EQ(written, 0x7171);
	ATF_CHECK_EQ(owner, (uintptr_t)0x7272);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);

	/* Backend payload and guest publication storage must be disjoint. */
	written = 0x7373;
	owner = 0x7474;
	ATF_CHECK_EQ(virtio_fs_dispatch_complete_owned(dispatch, &reply,
	    response, sizeof(response), response, sizeof(response), &written,
	    &owner), EINVAL);
	ATF_CHECK_EQ(written, 0x7373);
	ATF_CHECK_EQ(owner, (uintptr_t)0x7474);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);

	/* Publication scalars cannot share storage with one another. */
	written = 0x7575;
	ATF_CHECK_EQ(virtio_fs_dispatch_complete_owned(dispatch, &reply,
	    response, sizeof(response), guest, sizeof(guest), &written,
	    (uintptr_t *)(void *)&written), EINVAL);
	ATF_CHECK_EQ(written, 0x7575);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);

	ATF_REQUIRE_EQ(virtio_fs_dispatch_complete_owned(dispatch, &reply,
	    response, sizeof(response), guest, sizeof(guest), &written,
	    &owner), 0);
	ATF_CHECK_EQ(written, sizeof(response));
	ATF_CHECK_EQ(owner, (uintptr_t)0x7070);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 0);

	/* The portable error helper also preserves an aliased request. */
	memset(&context, 0, sizeof(context));
	context.byte_order = VIRTIO_FS_BYTE_ORDER_LITTLE;
	context.unique = 71;
	context_before = context;
	ATF_CHECK_EQ(virtio_fs_dispatch_error_response(&context,
	    (uint8_t *)(void *)&context), EINVAL);
	ATF_CHECK(memcmp(&context, &context_before, sizeof(context)) == 0);

	/* Drain publications cannot overlap state or their count scalar. */
	fuse_request(request, DOC_FUSE_LOOKUP, 72);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_submit(dispatch,
	    VIRTIO_FS_QUEUE_REQUEST, request, fuse_request_size(request),
	    sizeof(guest), &outbound), 0);
	count = 99;
	ATF_CHECK_EQ(virtio_fs_dispatch_reset(dispatch,
	    (struct virtio_fs_pending_result *)(void *)dispatch, 1, &count),
	    EINVAL);
	ATF_CHECK_EQ(count, 99);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);
	ATF_CHECK_EQ(virtio_fs_dispatch_reset(dispatch, &drained, 1,
	    (size_t *)(void *)dispatch), EINVAL);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);
	ATF_CHECK_EQ(virtio_fs_dispatch_reset(dispatch,
	    (struct virtio_fs_pending_result *)(void *)&count, 1, &count),
	    EINVAL);
	ATF_CHECK_EQ(count, 99);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 1);

	/* A valid cancellation and abort still work after rejected attempts. */
	ATF_REQUIRE_EQ(virtio_fs_dispatch_cancel(dispatch,
	    outbound.request_id, outbound.incarnation, &cancel), 0);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_abort(dispatch, outbound.request_id,
	    outbound.incarnation, guest, sizeof(guest), &written), 0);
	ATF_CHECK_EQ(virtio_fs_dispatch_pending(dispatch), 0);
	ATF_REQUIRE_EQ(virtio_fs_dispatch_pause(dispatch, &pending), 0);
	ATF_CHECK_EQ(pending, 0);
	virtio_fs_dispatch_destroy(dispatch);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, transactional_submit_and_completion);
	ATF_TP_ADD_TC(tp, transactional_publication);
	ATF_TP_ADD_TC(tp, portable_error_response);
	ATF_TP_ADD_TC(tp, failures_preserve_or_retire_ownership);
	ATF_TP_ADD_TC(tp, noreply_pause_disconnect_and_limits);
	ATF_TP_ADD_TC(tp, backend_error_is_portable_fuse_eio);
	ATF_TP_ADD_TC(tp, cancellation_is_explicit_and_retryable);
	ATF_TP_ADD_TC(tp, session_state_alias_is_rejected);
	ATF_TP_ADD_TC(tp, publication_aliases_are_rejected);
	return (atf_no_error());
}
