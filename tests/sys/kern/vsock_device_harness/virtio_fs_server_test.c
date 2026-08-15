/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "virtio_fs_backend.c"
#include "virtio_fs_backend_io.c"
#include "virtio_fs_outbox.c"
#include "virtiofsd_export.c"
#include "virtiofsd_fuse.c"
#include "virtiofsd_handle.c"
#include "virtiofsd_session.c"
#include "virtiofsd_server.c"

#define	TEST_INCARNATION	UINT64_C(0x1020304050607080)

struct server_fixture {
	struct virtiofsd_export *export;
	struct virtiofsd_session *session;
	struct virtiofsd_server *server;
	char path[32];
	int rootfd;
	int sockets[2];
};

static void
fixture_create(struct server_fixture *fixture)
{
	int fd;

	memset(fixture, 0, sizeof(*fixture));
	fixture->rootfd = -1;
	fixture->sockets[0] = -1;
	fixture->sockets[1] = -1;
	strcpy(fixture->path, "/tmp/virtiofsd-server.XXXXXX");
	ATF_REQUIRE(mkdtemp(fixture->path) != NULL);
	fixture->rootfd = open(fixture->path,
	    O_PATH | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(fixture->rootfd >= 0);
	fd = openat(fixture->rootfd, "file",
	    O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(write(fd, "data", 4), 4);
	ATF_REQUIRE_EQ(close(fd), 0);
	ATF_REQUIRE_EQ(virtiofsd_export_create(fixture->rootfd, 64,
	    &fixture->export), 0);
	ATF_REQUIRE_EQ(virtiofsd_session_create(fixture->export, 32, 4096,
	    &fixture->session), 0);
	ATF_REQUIRE_EQ(virtiofsd_server_create(fixture->session, 4096, 8,
	    32768, 2, &fixture->server), 0);
	ATF_REQUIRE_EQ(socketpair(AF_UNIX,
	    SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
	    fixture->sockets), 0);
}

static void
fixture_destroy(struct server_fixture *fixture)
{

	virtiofsd_server_destroy(fixture->server);
	virtiofsd_session_destroy(fixture->session);
	virtiofsd_export_destroy(fixture->export);
	ATF_REQUIRE_EQ(close(fixture->sockets[0]), 0);
	ATF_REQUIRE_EQ(close(fixture->sockets[1]), 0);
	ATF_REQUIRE_EQ(unlinkat(fixture->rootfd, "file", 0), 0);
	ATF_REQUIRE_EQ(close(fixture->rootfd), 0);
	ATF_REQUIRE_EQ(rmdir(fixture->path), 0);
}

static void
negotiate(struct server_fixture *fixture)
{
	struct virtio_fs_backend_header hello, reply;
	struct virtio_fs_backend_hello offer, selected;
	uint8_t payload[4096], wire[VIRTIO_FS_BACKEND_HELLO_SIZE];
	size_t payload_len;

	offer = (struct virtio_fs_backend_hello) {
		.minimum_version = 1,
		.maximum_version = 1,
		.features = VIRTIO_FS_BACKEND_F_ALL,
		.maximum_message = 4096,
		.maximum_inflight = 8,
		.maximum_pending_bytes = 32768,
	};
	ATF_REQUIRE_EQ(virtio_fs_backend_hello_encode(&offer, wire), 0);
	hello = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_HELLO,
		.payload_len = sizeof(wire),
		.request_id = 1,
	};
	int error = virtiofsd_server_handle(fixture->server, &hello, wire,
	    sizeof(wire));
	ATF_REQUIRE_MSG(error == 0, "HELLO failed: %d", error);
	ATF_REQUIRE_EQ(virtiofsd_server_flush_one(fixture->server,
	    fixture->sockets[0]), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fixture->sockets[1],
	    &reply, payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(reply.type, VIRTIO_FS_BACKEND_HELLO_REPLY);
	ATF_CHECK_EQ(reply.incarnation, 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_hello_decode(payload, payload_len,
	    &selected), 0);
	ATF_CHECK_EQ(selected.features, VIRTIO_FS_BACKEND_F_CANCEL |
	    VIRTIO_FS_BACKEND_F_FREEZE |
	    VIRTIO_FS_BACKEND_F_STATE_TRANSFER);
	ATF_CHECK_EQ(selected.maximum_inflight, 7);
}

static void
fuse_init(uint8_t wire[static 56], uint64_t unique)
{

	memset(wire, 0, 56);
	le32enc(wire, 56);
	le32enc(wire + 4, VIRTIOFSD_FUSE_INIT);
	le64enc(wire + 8, unique);
	le64enc(wire + 16, 1);
	le32enc(wire + 40, 7);
	le32enc(wire + 44, 35);
}

static void
wait_for_output(struct server_fixture *fixture)
{
	struct pollfd pfd;
	int error;

	/*
	 * HELLO may have left an already-consumed notification in the
	 * nonblocking wakeup pipe.  Drain it before arming the wait, then
	 * recheck the predicate so publication cannot be missed between the
	 * drain and poll.
	 */
	virtiofsd_server_drain_wakeup(fixture->server);
	if (virtiofsd_server_wants_write(fixture->server))
		return;
	error = virtiofsd_server_error(fixture->server);
	ATF_REQUIRE_MSG(error == 0, "worker failed: %s", strerror(error));
	pfd = (struct pollfd) {
		.fd = virtiofsd_server_wakeup_fd(fixture->server),
		.events = POLLIN,
	};
	ATF_REQUIRE_MSG(poll(&pfd, 1, 5000) == 1,
	    "worker output notification timed out");
	ATF_REQUIRE_MSG((pfd.revents & POLLIN) != 0,
	    "unexpected worker notification events %#x", pfd.revents);
	virtiofsd_server_drain_wakeup(fixture->server);
	error = virtiofsd_server_error(fixture->server);
	ATF_REQUIRE_MSG(error == 0, "worker failed: %s", strerror(error));
	ATF_REQUIRE_MSG(virtiofsd_server_wants_write(fixture->server),
	    "worker notification did not publish output");
}

static void
stop_fixture_workers(struct server_fixture *fixture)
{
	unsigned int worker;

	/*
	 * The cancellation test installs a queued job directly.  Retire the
	 * workers first so a newly created worker cannot observe that synthetic
	 * queue entry before CANCEL acquires the server mutex.  Relying on the
	 * workers already being asleep made the test scheduler-dependent.
	 */
	pthread_mutex_lock(&fixture->server->mutex);
	fixture->server->stopping = true;
	pthread_cond_broadcast(&fixture->server->cond);
	pthread_mutex_unlock(&fixture->server->mutex);
	for (worker = 0; worker < fixture->server->worker_count; worker++)
		ATF_REQUIRE_EQ(pthread_join(fixture->server->workers[worker],
		    NULL), 0);
	fixture->server->worker_count = 0;
	fixture->server->stopping = false;
}

ATF_TC_WITHOUT_HEAD(hello_request_and_quiesce_are_bounded);
ATF_TC_BODY(hello_request_and_quiesce_are_bounded, tc)
{
	struct server_fixture fixture;
	struct virtio_fs_backend_header header, reply;
	uint8_t fuse[56], payload[4096];
	size_t payload_len;

	fixture_create(&fixture);
	negotiate(&fixture);
	fuse_init(fuse, 101);
	header = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_REQUEST,
		.payload_len = sizeof(fuse),
		.request_id = 2,
		.incarnation = TEST_INCARNATION,
	};
	ATF_REQUIRE_EQ(virtiofsd_server_handle(fixture.server, &header, fuse,
	    sizeof(fuse)), 0);
	wait_for_output(&fixture);
	ATF_REQUIRE_EQ(virtiofsd_server_flush_one(fixture.server,
	    fixture.sockets[0]), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fixture.sockets[1],
	    &reply, payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(reply.type, VIRTIO_FS_BACKEND_RESPONSE);
	ATF_CHECK_EQ(reply.request_id, 2);
	ATF_CHECK_EQ(reply.status, 0);
	ATF_CHECK_EQ(le32dec(payload), payload_len);

	header.type = VIRTIO_FS_BACKEND_QUIESCE;
	header.payload_len = 0;
	header.request_id = VIRTIO_FS_BACKEND_CONTROL_ID_BIT | 3;
	ATF_REQUIRE_EQ(virtiofsd_server_handle(fixture.server, &header, NULL,
	    0), 0);
	/*
	 * The request response becomes visible before the worker retires its
	 * job.  QUIESCE is therefore allowed to complete asynchronously after
	 * handle() returns; wait for its barrier reply instead of assuming the
	 * worker has crossed that boundary merely because its response was
	 * flushed.
	 */
	wait_for_output(&fixture);
	ATF_REQUIRE_EQ(virtiofsd_server_flush_one(fixture.server,
	    fixture.sockets[0]), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fixture.sockets[1],
	    &reply, payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(reply.type, VIRTIO_FS_BACKEND_QUIESCE_REPLY);
	ATF_REQUIRE_EQ(payload_len, VIRTIOFSD_SESSION_STATE_SIZE);
	ATF_CHECK_EQ(le32dec(payload), VIRTIOFSD_SESSION_STATE_MAGIC);

	header.type = VIRTIO_FS_BACKEND_THAW;
	header.payload_len = (uint32_t)payload_len;
	header.request_id = VIRTIO_FS_BACKEND_CONTROL_ID_BIT | 4;
	ATF_REQUIRE_EQ(virtiofsd_server_handle(fixture.server, &header, payload,
	    payload_len), 0);
	ATF_REQUIRE_EQ(virtiofsd_server_flush_one(fixture.server,
	    fixture.sockets[0]), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fixture.sockets[1],
	    &reply, payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(reply.type, VIRTIO_FS_BACKEND_THAW_REPLY);
	ATF_CHECK_EQ(reply.status, 0);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(cancel_retires_work_before_late_completion);
ATF_TC_WITHOUT_HEAD(quiesce_live_node_transfers_active_state);
ATF_TC_BODY(quiesce_live_node_transfers_active_state, tc)
{
	struct server_fixture fixture;
	struct virtio_fs_backend_header header, reply;
	struct stat sb;
	uint8_t payload[4096];
	size_t payload_len;
	uint64_t nodeid;

	fixture_create(&fixture);
	negotiate(&fixture);
	fixture.server->incarnation = TEST_INCARNATION;
	fixture.session->initialized = true;
	fixture.session->byte_order = VIRTIOFSD_FUSE_ORDER_LITTLE;
	ATF_REQUIRE_EQ(virtiofsd_export_lookup(fixture.export,
	    VIRTIOFSD_ROOT_NODEID, "file", 4, &nodeid, &sb), 0);
	header = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_QUIESCE,
		.request_id = VIRTIO_FS_BACKEND_CONTROL_ID_BIT | 30,
		.incarnation = TEST_INCARNATION,
	};
	ATF_REQUIRE_EQ(virtiofsd_server_handle(fixture.server, &header, NULL,
	    0), 0);
	ATF_REQUIRE_EQ(virtiofsd_server_flush_one(fixture.server,
	    fixture.sockets[0]), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fixture.sockets[1],
	    &reply, payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(reply.type, VIRTIO_FS_BACKEND_QUIESCE_REPLY);
	ATF_CHECK_EQ(reply.status, 0);
	ATF_CHECK(payload_len > VIRTIOFSD_SESSION_STATE_SIZE);
	ATF_CHECK_EQ(le16dec(payload + 4), VIRTIOFSD_SESSION_STATE_VERSION);
	ATF_CHECK_EQ(fixture.server->phase, VIRTIO_FS_BACKEND_QUIESCED);
	ATF_CHECK_EQ(virtiofsd_server_error(fixture.server), 0);

	header.type = VIRTIO_FS_BACKEND_THAW;
	header.payload_len = (uint32_t)payload_len;
	header.request_id = VIRTIO_FS_BACKEND_CONTROL_ID_BIT | 31;
	ATF_REQUIRE_EQ(virtiofsd_server_handle(fixture.server, &header, NULL,
	    0), EINVAL);
	ATF_REQUIRE_EQ(virtiofsd_server_handle(fixture.server, &header, payload,
	    payload_len), 0);
	ATF_REQUIRE_EQ(virtiofsd_server_flush_one(fixture.server,
	    fixture.sockets[0]), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fixture.sockets[1],
	    &reply, payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(reply.status, 0);
	ATF_CHECK_EQ(payload_len, 0);
	ATF_CHECK_EQ(fixture.server->phase, VIRTIO_FS_BACKEND_ACTIVE);
	ATF_REQUIRE_EQ(virtiofsd_export_forget(fixture.export, nodeid, 1), 0);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(thaw_rejects_bad_state_without_losing_retry_fence);
ATF_TC_BODY(thaw_rejects_bad_state_without_losing_retry_fence, tc)
{
	struct server_fixture fixture;
	struct virtio_fs_backend_header header, reply;
	uint8_t bad[VIRTIOFSD_SESSION_STATE_SIZE] = {};
	uint8_t payload[4096], state[VIRTIOFSD_SESSION_STATE_SIZE];
	size_t payload_len;

	fixture_create(&fixture);
	negotiate(&fixture);
	fixture.server->incarnation = TEST_INCARNATION;
	header = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_QUIESCE,
		.request_id = VIRTIO_FS_BACKEND_CONTROL_ID_BIT | 20,
		.incarnation = TEST_INCARNATION,
	};
	ATF_REQUIRE_EQ(virtiofsd_server_handle(fixture.server, &header, NULL,
	    0), 0);
	ATF_REQUIRE_EQ(virtiofsd_server_flush_one(fixture.server,
	    fixture.sockets[0]), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fixture.sockets[1],
	    &reply, payload, sizeof(payload), &payload_len), 0);
	ATF_REQUIRE_EQ(payload_len, sizeof(state));
	memcpy(state, payload, sizeof(state));

	header.type = VIRTIO_FS_BACKEND_THAW;
	header.payload_len = sizeof(bad);
	header.request_id = VIRTIO_FS_BACKEND_CONTROL_ID_BIT | 21;
	ATF_REQUIRE_EQ(virtiofsd_server_handle(fixture.server, &header, bad,
	    sizeof(bad)), 0);
	ATF_REQUIRE_EQ(virtiofsd_server_flush_one(fixture.server,
	    fixture.sockets[0]), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fixture.sockets[1],
	    &reply, payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(reply.type, VIRTIO_FS_BACKEND_THAW_REPLY);
	ATF_CHECK_EQ(reply.status, -EPROTO);
	ATF_CHECK_EQ(fixture.server->phase, VIRTIO_FS_BACKEND_QUIESCED);
	ATF_CHECK_EQ(virtiofsd_server_error(fixture.server), 0);

	header.request_id = VIRTIO_FS_BACKEND_CONTROL_ID_BIT | 22;
	ATF_REQUIRE_EQ(virtiofsd_server_handle(fixture.server, &header, state,
	    sizeof(state)), 0);
	ATF_REQUIRE_EQ(virtiofsd_server_flush_one(fixture.server,
	    fixture.sockets[0]), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fixture.sockets[1],
	    &reply, payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(reply.status, 0);
	ATF_CHECK_EQ(fixture.server->phase, VIRTIO_FS_BACKEND_ACTIVE);
	fixture_destroy(&fixture);
}

ATF_TC_BODY(cancel_retires_work_before_late_completion, tc)
{
	struct server_fixture fixture;
	struct virtio_fs_backend_header cancel, request, reply;
	uint8_t fuse[56], payload[4096];
	struct virtiofsd_job *job;
	size_t payload_len;

	fixture_create(&fixture);
	negotiate(&fixture);
	fuse_init(fuse, 201);
	stop_fixture_workers(&fixture);
	request = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_REQUEST,
		.payload_len = sizeof(fuse),
		.request_id = 7,
		.incarnation = TEST_INCARNATION,
	};
	/*
	 * Install a queued job directly so this test proves queue retirement
	 * without relying on scheduler timing or recursively locking the
	 * session mutex.  The public CANCEL path must unlink and free it before
	 * acknowledging cancellation.
	 */
	pthread_mutex_lock(&fixture.server->mutex);
	fixture.server->incarnation = TEST_INCARNATION;
	job = &fixture.server->jobs[0];
	job->payload = malloc(sizeof(fuse));
	ATF_REQUIRE(job->payload != NULL);
	memcpy(job->payload, fuse, sizeof(fuse));
	job->header = request;
	job->state = VIRTIOFSD_JOB_QUEUED;
	job->next = VIRTIOFSD_JOB_NONE;
	fixture.server->job_head = 0;
	fixture.server->job_tail = 0;
	fixture.server->job_count = 1;
	pthread_mutex_unlock(&fixture.server->mutex);
	cancel = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_CANCEL,
		.request_id = 7,
		.incarnation = TEST_INCARNATION,
	};
	ATF_REQUIRE_EQ(virtiofsd_server_handle(fixture.server, &cancel, NULL,
	    0), 0);
	ATF_REQUIRE_EQ(virtiofsd_server_flush_one(fixture.server,
	    fixture.sockets[0]), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fixture.sockets[1],
	    &reply, payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(reply.type, VIRTIO_FS_BACKEND_CANCEL_REPLY);
	ATF_CHECK_EQ(reply.request_id, 7);
	pthread_mutex_lock(&fixture.server->mutex);
	ATF_CHECK_EQ(fixture.server->job_count, 0);
	ATF_CHECK_EQ(fixture.server->job_head, VIRTIOFSD_JOB_NONE);
	ATF_CHECK_EQ(fixture.server->job_tail, VIRTIOFSD_JOB_NONE);
	pthread_mutex_unlock(&fixture.server->mutex);
	ATF_CHECK(!fixture.session->initialized);
	ATF_CHECK_EQ(virtiofsd_server_flush_one(fixture.server,
	    fixture.sockets[0]), ENOENT);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(noreply_flag_must_match_fuse_semantics);
ATF_TC_BODY(noreply_flag_must_match_fuse_semantics, tc)
{
	struct server_fixture fixture;
	struct virtio_fs_backend_header request;
	uint8_t fuse[56];

	fixture_create(&fixture);
	negotiate(&fixture);
	fuse_init(fuse, 301);
	request = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_REQUEST,
		.flags = VIRTIO_FS_BACKEND_MSG_F_NOREPLY,
		.payload_len = sizeof(fuse),
		.request_id = 9,
		.incarnation = TEST_INCARNATION,
	};
	ATF_CHECK_EQ(virtiofsd_server_handle(fixture.server, &request, fuse,
	    sizeof(fuse)), EPROTO);
	ATF_CHECK(!fixture.session->initialized);
	pthread_mutex_lock(&fixture.server->mutex);
	ATF_CHECK_EQ(fixture.server->job_count, 0);
	pthread_mutex_unlock(&fixture.server->mutex);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(shutdown_waits_for_work_and_preserves_response_order);
ATF_TC_BODY(shutdown_waits_for_work_and_preserves_response_order, tc)
{
	struct server_fixture fixture;
	struct virtio_fs_backend_header header, reply;
	uint8_t payload[4096];
	size_t payload_len;

	fixture_create(&fixture);
	negotiate(&fixture);

	/*
	 * Model one active request and one already completed response.  The
	 * shutdown reply must not be published until the active request retires
	 * and must remain behind the earlier response.
	 */
	pthread_mutex_lock(&fixture.server->mutex);
	fixture.server->job_count = 1;
	reply = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_RESPONSE,
		.request_id = 10,
		.incarnation = TEST_INCARNATION,
	};
	fixture.server->incarnation = TEST_INCARNATION;
	ATF_REQUIRE_EQ(server_enqueue_locked(fixture.server, false, &reply,
	    NULL), 0);
	pthread_mutex_unlock(&fixture.server->mutex);

	header = (struct virtio_fs_backend_header) {
		.version = 1,
		.type = VIRTIO_FS_BACKEND_SHUTDOWN,
		.request_id = VIRTIO_FS_BACKEND_CONTROL_ID_BIT | 11,
		.incarnation = TEST_INCARNATION,
	};
	ATF_REQUIRE_EQ(virtiofsd_server_handle(fixture.server, &header, NULL,
	    0), 0);
	ATF_CHECK(!virtiofsd_server_closed(fixture.server));

	pthread_mutex_lock(&fixture.server->mutex);
	fixture.server->job_count = 0;
	ATF_REQUIRE_EQ(server_shutdown_complete_locked(fixture.server), 0);
	pthread_mutex_unlock(&fixture.server->mutex);
	ATF_CHECK(virtiofsd_server_closed(fixture.server));

	ATF_REQUIRE_EQ(virtiofsd_server_flush_one(fixture.server,
	    fixture.sockets[0]), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fixture.sockets[1],
	    &reply, payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(reply.type, VIRTIO_FS_BACKEND_RESPONSE);
	ATF_CHECK_EQ(reply.request_id, 10);

	ATF_REQUIRE_EQ(virtiofsd_server_flush_one(fixture.server,
	    fixture.sockets[0]), 0);
	ATF_REQUIRE_EQ(virtio_fs_backend_receive_frame(fixture.sockets[1],
	    &reply, payload, sizeof(payload), &payload_len), 0);
	ATF_CHECK_EQ(reply.type, VIRTIO_FS_BACKEND_SHUTDOWN_REPLY);
	ATF_CHECK_EQ(reply.request_id,
	    VIRTIO_FS_BACKEND_CONTROL_ID_BIT | 11);
	fixture_destroy(&fixture);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, hello_request_and_quiesce_are_bounded);
	ATF_TP_ADD_TC(tp,
	    quiesce_live_node_transfers_active_state);
	ATF_TP_ADD_TC(tp,
	    thaw_rejects_bad_state_without_losing_retry_fence);
	ATF_TP_ADD_TC(tp, cancel_retires_work_before_late_completion);
	ATF_TP_ADD_TC(tp, noreply_flag_must_match_fuse_semantics);
	ATF_TP_ADD_TC(tp,
	    shutdown_waits_for_work_and_preserves_response_order);
	return (atf_no_error());
}
