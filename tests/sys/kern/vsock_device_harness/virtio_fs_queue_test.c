/*
 * Retained VirtIO filesystem queue ownership tests.
 */
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "virtio_fs_host.c"
#include "virtio_fs_backend.c"
#include "virtio_fs_backend_io.c"
#include "virtio_fs_pending.c"
#include "virtio_fs_dispatch.c"
#include "virtio_fs_chain.c"
#include "virtio_fs_outbox.c"
#include "virtio_fs_queue.c"

#define	DOC_FUSE_IN_HEADER_SIZE		40U
#define	DOC_FUSE_OUT_HEADER_SIZE	16U
#define	DOC_FUSE_INIT_IN_SIZE		56U
#define	DOC_FUSE_INIT_OUT_SIZE		24U
#define	DOC_FUSE_FORGET_SIZE		48U
#define	DOC_FUSE_LOOKUP			1U
#define	DOC_FUSE_FORGET			2U
#define	DOC_FUSE_INIT			26U

struct completion_state {
	uintptr_t cookie[8];
	size_t used[8];
	size_t count;
};

struct reset_completion_state {
	uint32_t queue_id;
	int error;
	size_t count;
};

struct discard_state {
	uintptr_t cookie[8];
	size_t count;
};

struct reset_thread_state {
	struct virtio_fs_queue *queue;
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	_Atomic bool done;
	bool started;
	int error;
	size_t discarded;
};

struct selective_reset_thread_state {
	struct virtio_fs_queue *queue;
	uint32_t queue_id;
	int error;
	size_t discarded;
};

struct blocking_discard_state {
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	uintptr_t cookie[8];
	size_t count;
	bool blocked;
	bool release;
};

static void *
reset_thread(void *arg)
{
	struct reset_thread_state *state;

	state = arg;
	pthread_mutex_lock(&state->mutex);
	state->started = true;
	pthread_cond_signal(&state->condition);
	pthread_mutex_unlock(&state->mutex);
	state->error = virtio_fs_queue_reset(state->queue, &state->discarded);
	atomic_store_explicit(&state->done, true, memory_order_release);
	return (NULL);
}

static void *
selective_reset_thread(void *arg)
{
	struct selective_reset_thread_state *state;

	state = arg;
	state->error = virtio_fs_queue_reset_one(state->queue,
	    state->queue_id, &state->discarded);
	return (NULL);
}

static void
complete_chain(void *arg, uintptr_t cookie, size_t used)
{
	struct completion_state *state;

	state = arg;
	ATF_REQUIRE(state->count < nitems(state->cookie));
	state->cookie[state->count] = cookie;
	state->used[state->count] = used;
	state->count++;
}

static void
complete_reset(void *arg, uint32_t queue_id, int error)
{
	struct reset_completion_state *state;

	state = arg;
	state->queue_id = queue_id;
	state->error = error;
	state->count++;
}

static void
discard_chain(void *arg, uintptr_t cookie)
{
	struct discard_state *state;

	state = arg;
	ATF_REQUIRE(state->count < nitems(state->cookie));
	state->cookie[state->count++] = cookie;
}

static void
blocking_discard_chain(void *arg, uintptr_t cookie)
{
	struct blocking_discard_state *state;

	state = arg;
	pthread_mutex_lock(&state->mutex);
	ATF_REQUIRE(state->count < nitems(state->cookie));
	state->cookie[state->count++] = cookie;
	if (!state->blocked &&
	    (cookie == (uintptr_t)0x901 || cookie == (uintptr_t)0x902)) {
		state->blocked = true;
		pthread_cond_broadcast(&state->condition);
		while (!state->release)
			pthread_cond_wait(&state->condition, &state->mutex);
	}
	pthread_mutex_unlock(&state->mutex);
}

static struct virtio_fs_backend_session
active_backend(void)
{

	return ((struct virtio_fs_backend_session) {
		.phase = VIRTIO_FS_BACKEND_ACTIVE,
		.version = 1,
		.features = VIRTIO_FS_BACKEND_F_CANCEL |
		    VIRTIO_FS_BACKEND_F_FREEZE,
		.maximum_message = 4096,
		.maximum_inflight = 4,
		.maximum_pending_bytes = 8192,
		.incarnation = 9,
	});
}

static size_t
encode_request(uint8_t *request, size_t capacity, uint32_t opcode,
    uint64_t unique)
{
	size_t length;

	length = opcode == DOC_FUSE_INIT ? DOC_FUSE_INIT_IN_SIZE :
	    opcode == DOC_FUSE_FORGET ? DOC_FUSE_FORGET_SIZE :
	    DOC_FUSE_IN_HEADER_SIZE;
	ATF_REQUIRE(length <= capacity);
	memset(request, 0, length);
	le32enc(request, length);
	le32enc(request + 4, opcode);
	le64enc(request + 8, unique);
	if (opcode == DOC_FUSE_INIT) {
		le32enc(request + DOC_FUSE_IN_HEADER_SIZE, 7);
		le32enc(request + DOC_FUSE_IN_HEADER_SIZE + 4, 31);
	}
	return (length);
}

static void
encode_response(uint8_t response[DOC_FUSE_INIT_OUT_SIZE], uint64_t unique)
{

	memset(response, 0, DOC_FUSE_INIT_OUT_SIZE);
	le32enc(response, DOC_FUSE_INIT_OUT_SIZE);
	le64enc(response + 8, unique);
	le32enc(response + 16, 7);
	le32enc(response + 20, 31);
}

static struct virtio_fs_backend_header
response_header(const struct virtio_fs_backend_header *request,
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

static void
receive_request(int fd, struct virtio_fs_backend_header *header,
    uint8_t *payload, size_t capacity)
{
	size_t length;

	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fd, header, payload,
	    capacity, &length), 0);
	ATF_CHECK_EQ(length, header->payload_len);
}

ATF_TC_WITHOUT_HEAD(fragmented_async_round_trip);
ATF_TC_BODY(fragmented_async_round_trip, tc)
{
	struct virtio_fs_backend_header inbound, reply;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_queue *queue;
	struct completion_state completed;
	uint8_t request[DOC_FUSE_INIT_IN_SIZE], backend_payload[64];
	uint8_t response[DOC_FUSE_INIT_OUT_SIZE], out0[8], out1[16];
	struct iovec iov[4];
	size_t request_len;
	int sockets[2];

	memset(&completed, 0, sizeof(completed));
	backend = active_backend();
	ATF_REQUIRE_EQ(virtio_fs_queue_create(&backend, 2, 1,
	    complete_chain, &completed, &queue), 0);
	request_len = encode_request(request, sizeof(request), DOC_FUSE_INIT,
	    100);
	iov[0] = (struct iovec){ request, 13 };
	iov[1] = (struct iovec){ request + 13, request_len - 13 };
	iov[2] = (struct iovec){ out0, sizeof(out0) };
	iov[3] = (struct iovec){ out1, sizeof(out1) };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit(queue,
	    VIRTIO_FS_QUEUE_REQUEST, iov, nitems(iov), 2, 2, true, 0x100),
	    0);
	ATF_CHECK_EQ(virtio_fs_queue_pending(queue), 1);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &inbound, backend_payload,
	    sizeof(backend_payload));
	ATF_CHECK_EQ(le32dec(backend_payload + 4), DOC_FUSE_INIT);
	encode_response(response, 100);
	reply = response_header(&inbound, sizeof(response));
	ATF_REQUIRE_EQ(virtio_fs_queue_receive(queue, &reply, response,
	    sizeof(response)), 0);
	ATF_CHECK_EQ(completed.count, 1);
	ATF_CHECK_EQ(completed.cookie[0], (uintptr_t)0x100);
	ATF_CHECK_EQ(completed.used[0], sizeof(response));
	ATF_CHECK(memcmp(out0, response, sizeof(out0)) == 0);
	ATF_CHECK(memcmp(out1, response + sizeof(out0), sizeof(out1)) == 0);
	ATF_CHECK_EQ(virtio_fs_queue_pending(queue), 0);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	virtio_fs_queue_destroy(queue);
}

ATF_TC_WITHOUT_HEAD(hiprio_precedes_normal_and_retires_noreply);
ATF_TC_BODY(hiprio_precedes_normal_and_retires_noreply, tc)
{
	struct virtio_fs_backend_header inbound, reply;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_queue *queue;
	struct completion_state completed;
	uint8_t request[DOC_FUSE_INIT_IN_SIZE], backend_payload[64];
	uint8_t response[DOC_FUSE_INIT_OUT_SIZE], output[32];
	struct iovec iov[2];
	size_t request_len;
	int sockets[2];

	memset(&completed, 0, sizeof(completed));
	backend = active_backend();
	ATF_REQUIRE_EQ(virtio_fs_queue_create(&backend, 1, 1,
	    complete_chain, &completed, &queue), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);

	/* Establish the FUSE session. */
	request_len = encode_request(request, sizeof(request), DOC_FUSE_INIT,
	    200);
	iov[0] = (struct iovec){ request, request_len };
	iov[1] = (struct iovec){ output, sizeof(output) };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit(queue,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x200), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &inbound, backend_payload,
	    sizeof(backend_payload));
	encode_response(response, 200);
	reply = response_header(&inbound, sizeof(response));
	ATF_REQUIRE_EQ(virtio_fs_queue_receive(queue, &reply, response,
	    sizeof(response)), 0);

	request_len = encode_request(request, sizeof(request), DOC_FUSE_LOOKUP,
	    201);
	iov[0] = (struct iovec){ request, request_len };
	iov[1] = (struct iovec){ output, sizeof(output) };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit(queue,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x201), 0);
	request_len = encode_request(request, sizeof(request), DOC_FUSE_FORGET,
	    202);
	iov[0] = (struct iovec){ request, request_len };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit(queue,
	    VIRTIO_FS_QUEUE_HIPRIO, iov, 1, 1, 0, true, 0x202), 0);

	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &inbound, backend_payload,
	    sizeof(backend_payload));
	ATF_CHECK_EQ(le32dec(backend_payload + 4), DOC_FUSE_FORGET);
	ATF_CHECK_EQ(completed.count, 2);
	ATF_CHECK_EQ(completed.cookie[1], (uintptr_t)0x202);
	ATF_CHECK_EQ(completed.used[1], 0);

	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &inbound, backend_payload,
	    sizeof(backend_payload));
	ATF_CHECK_EQ(le32dec(backend_payload + 4), DOC_FUSE_LOOKUP);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	virtio_fs_queue_destroy(queue);
}

ATF_TC_WITHOUT_HEAD(saturation_is_transactional_and_reset_discards);
ATF_TC_BODY(saturation_is_transactional_and_reset_discards, tc)
{
	struct virtio_fs_backend_header inbound, reply;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_queue *queue;
	struct completion_state completed;
	uint8_t request[DOC_FUSE_INIT_IN_SIZE], backend_payload[64];
	uint8_t response[DOC_FUSE_INIT_OUT_SIZE], output[32];
	struct iovec iov[2];
	size_t discarded, request_len;
	int sockets[2];

	memset(&completed, 0, sizeof(completed));
	backend = active_backend();
	ATF_REQUIRE_EQ(virtio_fs_queue_create(&backend, 1, 1,
	    complete_chain, &completed, &queue), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	request_len = encode_request(request, sizeof(request), DOC_FUSE_INIT,
	    300);
	iov[0] = (struct iovec){ request, request_len };
	iov[1] = (struct iovec){ output, sizeof(output) };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit(queue,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x300), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &inbound, backend_payload,
	    sizeof(backend_payload));
	encode_response(response, 300);
	reply = response_header(&inbound, sizeof(response));
	ATF_REQUIRE_EQ(virtio_fs_queue_receive(queue, &reply, response,
	    sizeof(response)), 0);

	request_len = encode_request(request, sizeof(request), DOC_FUSE_LOOKUP,
	    301);
	iov[0] = (struct iovec){ request, request_len };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit(queue,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x301), 0);
	le64enc(request + 8, 302);
	ATF_CHECK_EQ(virtio_fs_queue_submit(queue,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x302), ENOBUFS);
	ATF_CHECK_EQ(virtio_fs_queue_pending(queue), 1);
	ATF_REQUIRE_EQ(virtio_fs_queue_reset(queue, &discarded), 0);
	ATF_CHECK_EQ(discarded, 1);
	ATF_CHECK_EQ(completed.count, 1);
	ATF_CHECK_EQ(virtio_fs_queue_pending(queue), 0);

	/*
	 * Reset is a guest lifecycle transition, not a terminal backend
	 * disconnect.  A fresh FUSE INIT must be accepted by the same queue.
	 */
	request_len = encode_request(request, sizeof(request), DOC_FUSE_INIT,
	    303);
	iov[0] = (struct iovec){ request, request_len };
	iov[1] = (struct iovec){ output, sizeof(output) };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit(queue,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x303), 0);
	ATF_CHECK_EQ(virtio_fs_queue_pending(queue), 1);
	ATF_REQUIRE_EQ(virtio_fs_queue_reset(queue, &discarded), 0);
	ATF_CHECK_EQ(discarded, 1);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	virtio_fs_queue_destroy(queue);
}

ATF_TC_WITHOUT_HEAD(disconnect_completes_owned_chains);
ATF_TC_BODY(disconnect_completes_owned_chains, tc)
{
	struct virtio_fs_backend_header inbound, reply;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_queue *queue;
	struct completion_state completed;
	uint8_t request[DOC_FUSE_INIT_IN_SIZE], backend_payload[64];
	uint8_t response[DOC_FUSE_INIT_OUT_SIZE], output[32];
	struct iovec iov[2];
	size_t count, request_len;
	bool saw_forget, saw_lookup;
	int sockets[2];

	memset(&completed, 0, sizeof(completed));
	memset(output, 0, sizeof(output));
	backend = active_backend();
	ATF_REQUIRE_EQ(virtio_fs_queue_create(&backend, 2, 1,
	    complete_chain, &completed, &queue), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	request_len = encode_request(request, sizeof(request), DOC_FUSE_INIT,
	    400);
	iov[0] = (struct iovec){ request, request_len };
	iov[1] = (struct iovec){ output, sizeof(output) };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit(queue,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x400), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &inbound, backend_payload,
	    sizeof(backend_payload));
	encode_response(response, 400);
	reply = response_header(&inbound, sizeof(response));
	ATF_REQUIRE_EQ(virtio_fs_queue_receive(queue, &reply, response,
	    sizeof(response)), 0);

	request_len = encode_request(request, sizeof(request), DOC_FUSE_LOOKUP,
	    401);
	iov[0] = (struct iovec){ request, request_len };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit(queue,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x401), 0);
	request_len = encode_request(request, sizeof(request), DOC_FUSE_FORGET,
	    402);
	iov[0] = (struct iovec){ request, request_len };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit(queue,
	    VIRTIO_FS_QUEUE_HIPRIO, iov, 1, 1, 0, true, 0x402), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_fail(queue, &count), 0);
	ATF_CHECK_EQ(count, 2);
	ATF_CHECK_EQ(completed.count, 3);
	saw_forget = false;
	saw_lookup = false;
	for (size_t i = 1; i < completed.count; i++) {
		if (completed.cookie[i] == (uintptr_t)0x401) {
			saw_lookup = true;
			ATF_CHECK_EQ(completed.used[i],
			    DOC_FUSE_OUT_HEADER_SIZE);
		} else if (completed.cookie[i] == (uintptr_t)0x402) {
			saw_forget = true;
			ATF_CHECK_EQ(completed.used[i], 0);
		}
	}
	ATF_CHECK(saw_lookup);
	ATF_CHECK(saw_forget);
	ATF_CHECK_EQ((int32_t)le32dec(output + 4), -5);
	ATF_CHECK_EQ(le64dec(output + 8), 401);
	ATF_CHECK_EQ(virtio_fs_queue_pending(queue), 0);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	virtio_fs_queue_destroy(queue);
}

ATF_TC_WITHOUT_HEAD(selective_reset_preserves_other_queue);
ATF_TC_BODY(selective_reset_preserves_other_queue, tc)
{
	struct virtio_fs_backend_header inbound, reply;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_queue *queue;
	struct completion_state completed;
	struct discard_state discarded_chains;
	struct reset_completion_state reset_completed;
	uint8_t request[DOC_FUSE_INIT_IN_SIZE], backend_payload[64];
	uint8_t response[DOC_FUSE_INIT_OUT_SIZE], output1[32], output2[32];
	struct iovec iov[2];
	size_t discarded, request_len;
	int sockets[2];

	memset(&completed, 0, sizeof(completed));
	memset(&discarded_chains, 0, sizeof(discarded_chains));
	memset(&reset_completed, 0, sizeof(reset_completed));
	backend = active_backend();
	ATF_REQUIRE_EQ(virtio_fs_queue_create(&backend, 4, 1,
	    complete_chain, &completed, &queue), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_set_reset_complete(queue,
	    complete_reset, &reset_completed), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_set_discard(queue, discard_chain,
	    &discarded_chains), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	request_len = encode_request(request, sizeof(request), DOC_FUSE_INIT,
	    500);
	iov[0] = (struct iovec){ request, request_len };
	iov[1] = (struct iovec){ output1, sizeof(output1) };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit_on(queue, 1,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x500), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &inbound, backend_payload,
	    sizeof(backend_payload));
	encode_response(response, 500);
	reply = response_header(&inbound, sizeof(response));
	ATF_REQUIRE_EQ(virtio_fs_queue_receive(queue, &reply, response,
	    sizeof(response)), 0);

	request_len = encode_request(request, sizeof(request), DOC_FUSE_LOOKUP,
	    501);
	iov[0] = (struct iovec){ request, request_len };
	iov[1] = (struct iovec){ output1, sizeof(output1) };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit_on(queue, 1,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x501), 0);
	le64enc(request + 8, 502);
	iov[1] = (struct iovec){ output2, sizeof(output2) };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit_on(queue, 2,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x502), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_reset_one(queue, 1, &discarded), 0);
	ATF_CHECK_EQ(discarded, 1);
	ATF_CHECK_EQ(virtio_fs_queue_pending(queue), 1);
	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &inbound, backend_payload,
	    sizeof(backend_payload));
	ATF_CHECK_EQ(le64dec(backend_payload + 8), 502);
	ATF_CHECK_EQ(virtio_fs_queue_reset_one(queue, 2, &discarded),
	    EINPROGRESS);
	ATF_CHECK_EQ(discarded, 0);
	ATF_CHECK_EQ(virtio_fs_queue_pending(queue), 1);
	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &reply, backend_payload,
	    sizeof(backend_payload));
	ATF_CHECK_EQ(reply.type, VIRTIO_FS_BACKEND_CANCEL);
	ATF_CHECK_EQ(reply.request_id, inbound.request_id);
	reply.type = VIRTIO_FS_BACKEND_CANCEL_REPLY;
	ATF_REQUIRE_EQ(virtio_fs_queue_receive(queue, &reply, NULL, 0), 0);
	ATF_CHECK_EQ(completed.count, 1);
	ATF_CHECK_EQ(virtio_fs_queue_pending(queue), 0);
	ATF_CHECK_EQ(reset_completed.count, 1);
	ATF_CHECK_EQ(reset_completed.queue_id, 2);
	ATF_CHECK_EQ(reset_completed.error, 0);
	ATF_CHECK_EQ(discarded_chains.count, 2);
	ATF_CHECK_EQ(discarded_chains.cookie[0], (uintptr_t)0x501);
	ATF_CHECK_EQ(discarded_chains.cookie[1], (uintptr_t)0x502);
	ATF_CHECK_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), ENOENT);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	virtio_fs_queue_destroy(queue);
}

ATF_TC_WITHOUT_HEAD(reset_ignores_bounded_late_response);
ATF_TC_BODY(reset_ignores_bounded_late_response, tc)
{
	struct virtio_fs_backend_header inbound, reply;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_queue *queue;
	struct completion_state completed;
	uint8_t request[DOC_FUSE_INIT_IN_SIZE], backend_payload[64];
	uint8_t response[DOC_FUSE_INIT_OUT_SIZE], output[32];
	struct iovec iov[2];
	size_t discarded, request_len;
	int sockets[2];

	memset(&completed, 0, sizeof(completed));
	backend = active_backend();
	ATF_REQUIRE_EQ(virtio_fs_queue_create(&backend, 4, 1,
	    complete_chain, &completed, &queue), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	request_len = encode_request(request, sizeof(request), DOC_FUSE_INIT,
	    600);
	iov[0] = (struct iovec){ request, request_len };
	iov[1] = (struct iovec){ output, sizeof(output) };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit_on(queue, 3,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x600), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &inbound, backend_payload,
	    sizeof(backend_payload));
	ATF_REQUIRE_EQ(virtio_fs_queue_reset(queue, &discarded), 0);
	ATF_CHECK_EQ(discarded, 1);
	ATF_CHECK_EQ(completed.count, 0);

	encode_response(response, 600);
	reply = response_header(&inbound, sizeof(response));
	ATF_REQUIRE_EQ(virtio_fs_queue_receive(queue, &reply, response,
	    sizeof(response)), 0);
	ATF_CHECK_EQ(completed.count, 0);
	ATF_CHECK_EQ(virtio_fs_queue_pending(queue), 0);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	virtio_fs_queue_destroy(queue);
}

ATF_TC_WITHOUT_HEAD(full_reset_serializes_failure_scratch);
ATF_TC_BODY(full_reset_serializes_failure_scratch, tc)
{
	struct virtio_fs_backend_session backend;
	struct virtio_fs_queue *queue;
	struct completion_state completed;
	struct reset_thread_state state;
	pthread_t thread;

	memset(&completed, 0, sizeof(completed));
	memset(&state, 0, sizeof(state));
	backend = active_backend();
	ATF_REQUIRE_EQ(virtio_fs_queue_create(&backend, 2, 1,
	    complete_chain, &completed, &queue), 0);
	state.queue = queue;
	ATF_REQUIRE_EQ(pthread_mutex_init(&state.mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&state.condition, NULL), 0);

	/*
	 * Backend failure, selective reset, and full reset all use the same
	 * retained drain/completion arrays.  Holding the failure serializer
	 * must keep full reset outside that ownership-critical section.
	 */
	pthread_mutex_lock(&queue->failure_mutex);
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, reset_thread, &state), 0);
	pthread_mutex_lock(&state.mutex);
	while (!state.started)
		pthread_cond_wait(&state.condition, &state.mutex);
	pthread_mutex_unlock(&state.mutex);
	ATF_CHECK(!atomic_load_explicit(&state.done, memory_order_acquire));
	pthread_mutex_unlock(&queue->failure_mutex);

	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_CHECK(atomic_load_explicit(&state.done, memory_order_acquire));
	ATF_CHECK_EQ(state.error, 0);
	ATF_CHECK_EQ(state.discarded, 0);
	ATF_REQUIRE_EQ(pthread_cond_destroy(&state.condition), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&state.mutex), 0);
	virtio_fs_queue_destroy(queue);
}

ATF_TC_WITHOUT_HEAD(reset_cancel_failure_never_publishes_used);
ATF_TC_BODY(reset_cancel_failure_never_publishes_used, tc)
{
	struct virtio_fs_backend_header cancel, inbound;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_queue *queue;
	struct completion_state completed;
	struct discard_state discarded_state;
	struct reset_completion_state reset_completed;
	uint8_t request[DOC_FUSE_INIT_IN_SIZE], backend_payload[64], output[32];
	struct iovec iov[2];
	size_t completed_count, discarded, request_len;
	int sockets[2];

	memset(&completed, 0, sizeof(completed));
	memset(&discarded_state, 0, sizeof(discarded_state));
	memset(&reset_completed, 0, sizeof(reset_completed));
	backend = active_backend();
	ATF_REQUIRE_EQ(virtio_fs_queue_create(&backend, 4, 1,
	    complete_chain, &completed, &queue), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_set_discard(queue, discard_chain,
	    &discarded_state), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_set_reset_complete(queue,
	    complete_reset, &reset_completed), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	request_len = encode_request(request, sizeof(request), DOC_FUSE_INIT,
	    700);
	iov[0] = (struct iovec){ request, request_len };
	iov[1] = (struct iovec){ output, sizeof(output) };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit_on(queue, 7,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x700), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &inbound, backend_payload,
	    sizeof(backend_payload));
	ATF_REQUIRE_EQ(virtio_fs_queue_reset_one(queue, 7, &discarded),
	    EINPROGRESS);
	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &cancel, backend_payload,
	    sizeof(backend_payload));
	ATF_CHECK_EQ(cancel.type, VIRTIO_FS_BACKEND_CANCEL);
	cancel.type = VIRTIO_FS_BACKEND_CANCEL_REPLY;
	cancel.status = -EBUSY;
	ATF_CHECK_EQ(virtio_fs_queue_receive(queue, &cancel, NULL, 0), EIO);
	ATF_REQUIRE_EQ(virtio_fs_queue_fail(queue, &completed_count), 0);
	ATF_CHECK_EQ(completed_count, 0);
	ATF_CHECK_EQ(completed.count, 0);
	ATF_CHECK_EQ(discarded_state.count, 1);
	ATF_CHECK_EQ(discarded_state.cookie[0], (uintptr_t)0x700);
	ATF_CHECK_EQ(reset_completed.count, 1);
	ATF_CHECK_EQ(reset_completed.queue_id, 7);
	ATF_CHECK_EQ(reset_completed.error, EIO);
	ATF_CHECK_EQ(virtio_fs_queue_pending(queue), 0);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	virtio_fs_queue_destroy(queue);
}

ATF_TC_WITHOUT_HEAD(destroy_reclaims_sent_request);
ATF_TC_BODY(destroy_reclaims_sent_request, tc)
{
	struct virtio_fs_backend_header inbound;
	struct virtio_fs_backend_session backend;
	struct virtio_fs_queue *queue;
	struct completion_state completed;
	uint8_t request[DOC_FUSE_INIT_IN_SIZE], backend_payload[64], output[32];
	struct iovec iov[2];
	size_t request_len;
	int sockets[2];

	memset(&completed, 0, sizeof(completed));
	backend = active_backend();
	ATF_REQUIRE_EQ(virtio_fs_queue_create(&backend, 2, 1,
	    complete_chain, &completed, &queue), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	request_len = encode_request(request, sizeof(request), DOC_FUSE_INIT,
	    800);
	iov[0] = (struct iovec){ request, request_len };
	iov[1] = (struct iovec){ output, sizeof(output) };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit_on(queue, 1,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x800), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &inbound, backend_payload,
	    sizeof(backend_payload));
	ATF_CHECK_EQ(virtio_fs_queue_pending(queue), 1);

	/*
	 * The backend has taken the frame, so the ordinary reset path would
	 * return EBUSY.  Destruction must nevertheless retire the owner and
	 * return the guest chain exactly once.
	 */
	virtio_fs_queue_destroy(queue);
	ATF_CHECK_EQ(completed.count, 1);
	ATF_CHECK_EQ(completed.cookie[0], (uintptr_t)0x800);
	ATF_CHECK_EQ(completed.used[0], DOC_FUSE_OUT_HEADER_SIZE);
	ATF_CHECK_EQ(le32dec(output), DOC_FUSE_OUT_HEADER_SIZE);
	ATF_CHECK_EQ((int32_t)le32dec(output + 4), -5);
	ATF_CHECK_EQ(le64dec(output + 8), 800);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
}

ATF_TC_WITHOUT_HEAD(concurrent_selective_resets_keep_private_completions);
ATF_TC_BODY(concurrent_selective_resets_keep_private_completions, tc)
{
	struct selective_reset_thread_state first, second;
	struct virtio_fs_backend_header inbound, reply;
	struct virtio_fs_backend_session backend;
	struct blocking_discard_state discarded;
	struct virtio_fs_queue *queue;
	struct completion_state completed;
	uint8_t backend_payload[64], request[DOC_FUSE_INIT_IN_SIZE];
	uint8_t response[DOC_FUSE_INIT_OUT_SIZE], output[4][32];
	struct iovec iov[2];
	pthread_t first_thread, second_thread;
	uintptr_t expected[] = { 0x901, 0x902, 0xa01, 0xa02 };
	size_t request_len;
	int sockets[2];

	memset(&completed, 0, sizeof(completed));
	memset(&discarded, 0, sizeof(discarded));
	ATF_REQUIRE_EQ(pthread_mutex_init(&discarded.mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&discarded.condition, NULL), 0);
	backend = active_backend();
	ATF_REQUIRE_EQ(virtio_fs_queue_create(&backend, 4, 1,
	    complete_chain, &completed, &queue), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_set_discard(queue,
	    blocking_discard_chain, &discarded), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), 0);
	request_len = encode_request(request, sizeof(request), DOC_FUSE_INIT,
	    899);
	iov[0] = (struct iovec){ request, request_len };
	iov[1] = (struct iovec){ output[0], sizeof(output[0]) };
	ATF_REQUIRE_EQ(virtio_fs_queue_submit(queue,
	    VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1, true, 0x899), 0);
	ATF_REQUIRE_EQ(virtio_fs_queue_flush_one(queue, sockets[0]), 0);
	receive_request(sockets[1], &inbound, backend_payload,
	    sizeof(backend_payload));
	encode_response(response, 899);
	reply = response_header(&inbound, sizeof(response));
	ATF_REQUIRE_EQ(virtio_fs_queue_receive(queue, &reply, response,
	    sizeof(response)), 0);
	for (size_t i = 0; i < nitems(expected); i++) {
		request_len = encode_request(request, sizeof(request),
		    DOC_FUSE_LOOKUP, 900 + i);
		iov[0] = (struct iovec){ request, request_len };
		iov[1] = (struct iovec){ output[i], sizeof(output[i]) };
		ATF_REQUIRE_EQ(virtio_fs_queue_submit_on(queue,
		    i < 2 ? 1 : 2, VIRTIO_FS_QUEUE_REQUEST, iov, 2, 1, 1,
		    true, expected[i]), 0);
	}
	first = (struct selective_reset_thread_state) {
		.queue = queue,
		.queue_id = 1,
	};
	second = (struct selective_reset_thread_state) {
		.queue = queue,
		.queue_id = 2,
	};
	ATF_REQUIRE_EQ(pthread_create(&first_thread, NULL,
	    selective_reset_thread, &first), 0);
	pthread_mutex_lock(&discarded.mutex);
	while (!discarded.blocked)
		pthread_cond_wait(&discarded.condition, &discarded.mutex);
	pthread_mutex_unlock(&discarded.mutex);
	ATF_REQUIRE_EQ(pthread_create(&second_thread, NULL,
	    selective_reset_thread, &second), 0);
	ATF_REQUIRE_EQ(pthread_join(second_thread, NULL), 0);
	pthread_mutex_lock(&discarded.mutex);
	discarded.release = true;
	pthread_cond_broadcast(&discarded.condition);
	pthread_mutex_unlock(&discarded.mutex);
	ATF_REQUIRE_EQ(pthread_join(first_thread, NULL), 0);
	ATF_CHECK_EQ(first.error, 0);
	ATF_CHECK_EQ(first.discarded, 2);
	ATF_CHECK_EQ(second.error, 0);
	ATF_CHECK_EQ(second.discarded, 2);
	ATF_CHECK_EQ(discarded.count, nitems(expected));
	for (size_t i = 0; i < nitems(expected); i++) {
		size_t matches;

		matches = 0;
		for (size_t j = 0; j < discarded.count; j++)
			matches += discarded.cookie[j] == expected[i];
		ATF_CHECK_EQ(matches, 1);
	}
	ATF_CHECK_EQ(virtio_fs_queue_pending(queue), 0);
	ATF_REQUIRE_EQ(close(sockets[0]), 0);
	ATF_REQUIRE_EQ(close(sockets[1]), 0);
	virtio_fs_queue_destroy(queue);
	ATF_REQUIRE_EQ(pthread_cond_destroy(&discarded.condition), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&discarded.mutex), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, concurrent_selective_resets_keep_private_completions);
	ATF_TP_ADD_TC(tp, fragmented_async_round_trip);
	ATF_TP_ADD_TC(tp, hiprio_precedes_normal_and_retires_noreply);
	ATF_TP_ADD_TC(tp, saturation_is_transactional_and_reset_discards);
	ATF_TP_ADD_TC(tp, disconnect_completes_owned_chains);
	ATF_TP_ADD_TC(tp, selective_reset_preserves_other_queue);
	ATF_TP_ADD_TC(tp, reset_ignores_bounded_late_response);
	ATF_TP_ADD_TC(tp, full_reset_serializes_failure_scratch);
	ATF_TP_ADD_TC(tp, reset_cancel_failure_never_publishes_used);
	ATF_TP_ADD_TC(tp, destroy_reclaims_sent_request);
	return (atf_no_error());
}
