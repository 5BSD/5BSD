/* SPDX-License-Identifier: BSD-2-Clause */
/* Production configuration: Capsicum rights limits are compiled in and
 * applied to the test's descriptors (no capability-mode entry). */
#include "hypertrace.c"
#include <poll.h>
#include <stdarg.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno %d)\n", \
    __FILE__, __LINE__, #x, errno); abort(); } } while (0)

uint16_t vm_get_vmid(struct vmctx *ctx __unused) { return (1); }
int vm_get_identity(struct vmctx *ctx __unused, uint16_t *id,
    uint64_t *epoch) { *id = 1; *epoch = 77; return (0); }
const char *vm_get_name(struct vmctx *ctx __unused) { return ("test-vm"); }
static const char *fixture_root;
static bool fail_connector_once;
extern int __real_pthread_create(pthread_t *, const pthread_attr_t *,
    void *(*)(void *), void *);
int
__wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
    void *(*routine)(void *), void *argument)
{
	if (fail_connector_once && routine == ht_connector) {
		fail_connector_once = false;
		return (EAGAIN);
	}
	return (__real_pthread_create(thread, attributes, routine, argument));
}
extern int __real_open(const char *, int, ...);
int
__wrap_open(const char *path, int flags, ...)
{
	if (fixture_root != NULL &&
	    (strcmp(path, "/var/ddtrace") == 0 ||
	    strcmp(path, "/var/ddtrace/inbound") == 0))
		path = fixture_root;
	if ((flags & O_CREAT) != 0) {
		va_list args;
		va_start(args, flags);
		mode_t mode = va_arg(args, int);
		va_end(args);
		return (__real_open(path, flags, mode));
	}
	return (__real_open(path, flags));
}
int vm_export_attestation_fd(struct vmctx *ctx __unused) {
	return (open("/dev/null", O_RDONLY | O_CLOEXEC));
}

extern int __real_connectat(int, int, const struct sockaddr *, socklen_t);
int
__wrap_connectat(int directory, int socketfd, const struct sockaddr *address,
    socklen_t length)
{
	int result = __real_connectat(directory, socketfd, address, length);
	if (result == 0 || errno == EINPROGRESS) {
		errno = EINPROGRESS;
		return (-1);
	}
	return (result);
}

static void *
server(void *argument)
{
	int listener = *(int *)argument;
	for (int i = 0; i < 2; i++) {
		int peer = accept(listener, NULL, NULL);
		dtd_initmsg_t hello = {
		    .protocol_version = DTRACED_PROTOCOL_VERSION,
		    .kind = DTRACED_KIND_DTRACED };
		size_t transferred;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		CHECK(hello.protocol_version == DTRACED_PROTOCOL_VERSION);
		CHECK(hello.kind == DTRACED_KIND_FORWARDER);
		CHECK(strcmp(hello.ident, "test-vm") == 0);
		CHECK(hello.subs == (DTD_SUB_ELFWRITE |
		    DTD_SUB_ADMISSION_ACK));
		CHECK(hello.session_id[0] == 0x42);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		uint8_t ack = i == 0 ? 1 : 0;
		CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
		    deadline, &transferred) == 0);
		close(peer);
	}
	return (NULL);
}

struct ready_server_fixture {
	int listener;
	atomic_bool release;
};

static void *
ready_server(void *argument)
{
	struct ready_server_fixture *fixture = argument;
	int peers[2];

	for (int i = 0; i < 2; i++) {
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		size_t transferred;
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };

		peers[i] = accept(fixture->listener, NULL, NULL);
		CHECK(peers[i] >= 0);
		CHECK(dtraced_io_transfer(peers[i], &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peers[i], &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		CHECK(hello.kind == DTRACED_KIND_FORWARDER &&
		    hello.protocol_version == DTRACED_PROTOCOL_VERSION &&
		    hello.subs == (DTD_SUB_ADMISSION_ACK |
		    (i == 0 ? DTD_SUB_ELFWRITE | DTD_SUB_KILL |
		    DTD_SUB_CLEANUP | DTD_SUB_REPLAY_MANIFEST :
		    DTD_SUB_READDATA)));
		int identity_fd = dtraced_io_recv_fd(peers[i], deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		uint8_t ack = 1;
		CHECK(dtraced_io_transfer(peers[i], &ack, sizeof(ack), true,
		    deadline, &transferred) == 0);
		if (i == 0) {
			uint8_t count[4], replay_wire[DTRACED_REPLAY_KILL_WIRE_SIZE];
			dtraced_replay_kill_t replay = {
			    .pid = 123, .vmid = 1, .epoch = 77,
			    .source_id = { 0xa5 } };
			dtraced_wire_put_u32(count, 1);
			dtraced_wire_encode_replay_kill(replay_wire, &replay);
			CHECK(dtraced_io_transfer(peers[i], count, sizeof(count),
			    true, deadline, &transferred) == 0);
			CHECK(dtraced_io_transfer(peers[i], replay_wire,
			    sizeof(replay_wire), true, deadline, &transferred) == 0);
		}
	}
	while (!atomic_load(&fixture->release))
		usleep(1000);
	close(peers[0]);
	close(peers[1]);
	return (NULL);
}

static void *
bad_manifest_server(void *argument)
{
	int listener = *(int *)argument;
	int peer = accept(listener, NULL, NULL);
	dtd_initmsg_t hello = { .protocol_version =
	    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
	size_t transferred;
	int64_t deadline = dtraced_io_milliseconds() + 2000;
	uint8_t ack = 1, count[4], wire[DTRACED_REPLAY_KILL_WIRE_SIZE];
	dtraced_replay_kill_t replay = {
	    .pid = 124, .vmid = 1, .epoch = 77, .source_id = { 0xa6 } };

	CHECK(peer >= 0);
	CHECK(dtraced_wire_write_init(peer, &hello, deadline,
	    &transferred) == 0);
	CHECK(dtraced_wire_read_init(peer, &hello, deadline,
	    &transferred) == 0 &&
	    hello.subs == (DTD_SUB_ELFWRITE | DTD_SUB_KILL |
	    DTD_SUB_ADMISSION_ACK | DTD_SUB_REPLAY_MANIFEST));
	int identity_fd = dtraced_io_recv_fd(peer, deadline);
	CHECK(identity_fd >= 0);
	close(identity_fd);
	CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
	    deadline, &transferred) == 0);
	dtraced_wire_put_u32(count, 2);
	CHECK(dtraced_io_transfer(peer, count, sizeof(count), true,
	    deadline, &transferred) == 0);
	dtraced_wire_encode_replay_kill(wire, &replay);
	CHECK(dtraced_io_transfer(peer, wire, sizeof(wire), true,
	    deadline, &transferred) == 0);
	replay.pid = 123;
	replay.source_id[0] = 0xa5;
	dtraced_wire_encode_replay_kill(wire, &replay);
	CHECK(dtraced_io_transfer(peer, wire, sizeof(wire), true,
	    deadline, &transferred) == 0);
	close(peer);
	return (NULL);
}

static void *
handoff_server(void *argument)
{
	int fd = *(int *)argument;
	uint8_t frame[sizeof(dtraced_hdr_t) +
	    sizeof(dtraced_handoff_request_t)];
	const uint8_t operations[] = { DTRACED_HANDOFF_PREPARE,
	    DTRACED_HANDOFF_COMMIT, DTRACED_HANDOFF_COMMIT,
	    DTRACED_HANDOFF_RESERVE,
	    DTRACED_HANDOFF_CANCEL, DTRACED_HANDOFF_MUTATE,
	    DTRACED_HANDOFF_CLAIM,
	    DTRACED_HANDOFF_PROMOTE_IMPORT,
	    DTRACED_HANDOFF_ACTIVATE_IMPORT };
	for (size_t case_index = 0;
	    case_index < sizeof(operations) / sizeof(operations[0]);
	    case_index++) {
		uint8_t expected = operations[case_index];
		size_t length = 0;
		size_t transferred;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(dtraced_io_transfer(fd, &length, sizeof(length), false,
		    deadline, &transferred) == 0);
		CHECK(length == sizeof(frame));
		CHECK(dtraced_io_transfer(fd, frame, sizeof(frame), false,
		    deadline, &transferred) == 0);
		dtraced_hdr_t header;
		dtraced_handoff_request_t request;
		memcpy(&header, frame, sizeof(header));
		memcpy(&request, frame + sizeof(header), sizeof(request));
		CHECK(header.msg_type == DTRACED_MSG_HANDOFF);
		CHECK(request.op == expected && request.token[0] == 0xa1);
		CHECK(request.digest[0] ==
		    (expected == DTRACED_HANDOFF_PREPARE ? 0xd4 : 0xb2));
		uint8_t ack = case_index == 1 ? 0 : 1;
		CHECK(dtraced_io_transfer(fd, &ack, sizeof(ack), true,
		    deadline, &transferred) == 0);
	}
	return (NULL);
}

static uint8_t source_release_mode = DTRACED_RELEASE_MODE_LOCAL;
static bool source_release_truncate;
static uint8_t source_release_wire[DTRACED_RELEASE_ATTESTED_SIZE];

static void *
source_release_server(void *argument)
{
	int fd = *(int *)argument;
	uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_HANDOFF_WIRE_SIZE];
	uint8_t ack = 1;
	uint8_t mode = source_release_mode;
	size_t length = 0, transferred;
	int64_t deadline = dtraced_io_milliseconds() + 2000;
	dtraced_hdr_t header;
	dtraced_handoff_request_t request;

	CHECK(dtraced_io_transfer(fd, &length, sizeof(length), false,
	    deadline, &transferred) == 0 && length == sizeof(frame));
	CHECK(dtraced_io_transfer(fd, frame, sizeof(frame), false,
	    deadline, &transferred) == 0);
	CHECK(dtraced_wire_decode_header(&header, frame) == 0 &&
	    header.msg_type == DTRACED_MSG_HANDOFF);
	CHECK(dtraced_wire_decode_handoff(&request,
	    frame + DTRACED_MSGHDRSIZE) == 0 &&
	    request.op == DTRACED_HANDOFF_SOURCE_RELEASE &&
	    request.token[0] == 0xa1 && request.digest[0] == 0xb2);
	CHECK(dtraced_io_transfer(fd, &ack, sizeof(ack), true,
	    deadline, &transferred) == 0);
	CHECK(dtraced_io_transfer(fd, &mode, sizeof(mode), true,
	    deadline, &transferred) == 0);
	if (mode == DTRACED_RELEASE_MODE_SIGNED)
		CHECK(dtraced_io_transfer(fd, source_release_wire,
		    source_release_truncate ? 17 : sizeof(source_release_wire),
		    true, deadline, &transferred) == 0);
	close(fd);
	return (NULL);
}

static void *
source_release_open_server(void *argument)
{
	int listener = *(int *)argument;
	int peer = accept(listener, NULL, NULL);
	dtd_initmsg_t hello = { .protocol_version = DTRACED_PROTOCOL_VERSION,
	    .kind = DTRACED_KIND_DTRACED };
	size_t transferred;
	int64_t deadline = dtraced_io_milliseconds() + 2000;
	uint8_t ack = 1;

	CHECK(peer >= 0);
	CHECK(dtraced_wire_write_init(peer, &hello, deadline,
	    &transferred) == 0);
	CHECK(dtraced_wire_read_init(peer, &hello, deadline,
	    &transferred) == 0 &&
	    hello.kind == DTRACED_KIND_FORWARDER &&
	    hello.subs == (DTD_SUB_SOURCE_RELEASE | DTD_SUB_ADMISSION_ACK) &&
	    memcmp(hello.session_id, forwarder_session_id,
	    sizeof(hello.session_id)) == 0);
	int identity_fd = dtraced_io_recv_fd(peer, deadline);
	CHECK(identity_fd >= 0);
	close(identity_fd);
	CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
	    deadline, &transferred) == 0);
	return (source_release_server(&peer));
}

static void *
release_recovery_server(void *argument)
{
	int listener = *(int *)argument;
	int peer = accept(listener, NULL, NULL);
	dtd_initmsg_t hello = { .protocol_version = DTRACED_PROTOCOL_VERSION,
	    .kind = DTRACED_KIND_DTRACED };
	uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_HANDOFF_WIRE_SIZE];
	uint8_t ack = 1, mode = DTRACED_RELEASE_MODE_SIGNED;
	size_t length = 0, transferred;
	int64_t deadline = dtraced_io_milliseconds() + 2000;
	dtraced_hdr_t header;
	dtraced_handoff_request_t request;
	CHECK(peer >= 0);
	CHECK(dtraced_wire_write_init(peer, &hello, deadline,
	    &transferred) == 0);
	CHECK(dtraced_wire_read_init(peer, &hello, deadline,
	    &transferred) == 0 &&
	    hello.kind == DTRACED_KIND_RELEASE_RECOVERY &&
	    hello.subs == DTD_SUB_RELEASE_RECOVERY &&
	    memcmp(hello.session_id, (const uint8_t[16]){0}, 16) == 0 &&
	    strcmp(hello.ident, "hypertrace-release-recovery") == 0);
	CHECK(dtraced_io_read_size(peer, &length, deadline,
	    &transferred) == 0 && length == sizeof(frame));
	CHECK(dtraced_io_transfer(peer, frame, sizeof(frame), false,
	    deadline, &transferred) == 0);
	CHECK(dtraced_wire_decode_header(&header, frame) == 0 &&
	    header.msg_type == DTRACED_MSG_HANDOFF);
	CHECK(dtraced_wire_decode_handoff(&request,
	    frame + DTRACED_MSGHDRSIZE) == 0 &&
	    request.op == DTRACED_HANDOFF_RELEASE_RECOVER &&
	    request.token[0] == 0xa1 && request.digest[0] == 0xb2);
	CHECK(dtraced_io_transfer(peer, &ack, 1, true,
	    deadline, &transferred) == 0 &&
	    dtraced_io_transfer(peer, &mode, 1, true,
	    deadline, &transferred) == 0 &&
	    dtraced_io_transfer(peer, source_release_wire,
	    sizeof(source_release_wire), true, deadline,
	    &transferred) == 0);
	close(peer);
	return (NULL);
}

static void *
prestart_handoff_server(void *argument)
{
	int listener = *(int *)argument;
	const uint8_t operations[] = { DTRACED_HANDOFF_RESERVE,
	    DTRACED_HANDOFF_CANCEL, DTRACED_HANDOFF_RESERVE,
	    DTRACED_HANDOFF_MUTATE, DTRACED_HANDOFF_CLAIM,
	    DTRACED_HANDOFF_PROMOTE_IMPORT,
	    DTRACED_HANDOFF_PROMOTE_IMPORT,
	    DTRACED_HANDOFF_REKEY_APPLIED,
	    DTRACED_HANDOFF_REKEY_APPLIED,
	    DTRACED_HANDOFF_ACTIVATE_IMPORT,
	    DTRACED_HANDOFF_ACTIVATE_IMPORT,
	    DTRACED_HANDOFF_RESERVE,
	    DTRACED_HANDOFF_PROMOTE_IMPORT,
	    DTRACED_HANDOFF_PROMOTE_IMPORT,
	    DTRACED_HANDOFF_REPLAY_READY,
	    DTRACED_HANDOFF_REPLAY_READY,
	    DTRACED_HANDOFF_EXECUTION_START,
	    DTRACED_HANDOFF_EXECUTION_START,
	    DTRACED_HANDOFF_EXECUTION_START,
	    DTRACED_HANDOFF_REBIND_BEGIN,
	    DTRACED_HANDOFF_REBIND_BEGIN,
	    DTRACED_HANDOFF_REBIND_BEGIN,
	    DTRACED_HANDOFF_REBIND_STAGE,
	    DTRACED_HANDOFF_REBIND_STAGE,
	    DTRACED_HANDOFF_REBIND_STAGE,
	    DTRACED_HANDOFF_REBIND_PENDING,
	    DTRACED_HANDOFF_REBIND_PENDING,
	    DTRACED_HANDOFF_REBIND_PENDING,
	    DTRACED_HANDOFF_REBIND_CANCEL_PENDING,
	    DTRACED_HANDOFF_REBIND_CANCEL_PENDING,
	    DTRACED_HANDOFF_REBIND_CANCEL_PENDING,
	    DTRACED_HANDOFF_REBIND_COMMIT_EMPTY,
	    DTRACED_HANDOFF_REBIND_COMMIT_EMPTY,
	    DTRACED_HANDOFF_REBIND_COMMIT_EMPTY,
	    DTRACED_HANDOFF_REBIND_EMPTY_READY,
	    DTRACED_HANDOFF_REBIND_EMPTY_READY,
	    DTRACED_HANDOFF_REBIND_EMPTY_READY,
	    DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT,
	    DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT,
	    DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT,
	    DTRACED_HANDOFF_REBIND_BEGIN,
	    DTRACED_HANDOFF_DESTINATION_STATUS,
	    DTRACED_HANDOFF_REBIND_BEGIN,
	    DTRACED_HANDOFF_REBIND_BEGIN,
	    DTRACED_HANDOFF_RESET_MUTATION,
	    DTRACED_HANDOFF_RESET_MUTATION };
	for (size_t i = 0; i < sizeof(operations); i++) {
		int peer = accept(listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		size_t transferred, length;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		CHECK(hello.kind == DTRACED_KIND_FORWARDER &&
		    hello.protocol_version == DTRACED_PROTOCOL_VERSION &&
		    hello.subs == DTD_SUB_READDATA &&
		    memcmp(hello.session_id, forwarder_session_id,
		    sizeof(hello.session_id)) == 0 &&
		    strcmp(hello.ident, "test-vm") == 0);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		uint8_t frame[sizeof(dtraced_hdr_t) +
		    sizeof(dtraced_handoff_request_t)];
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 && length == sizeof(frame));
		CHECK(dtraced_io_transfer(peer, frame, sizeof(frame), false,
		    deadline, &transferred) == 0);
		dtraced_hdr_t header;
		dtraced_handoff_request_t request;
		memcpy(&header, frame, sizeof(header));
		memcpy(&request, frame + sizeof(header), sizeof(request));
		CHECK(header.msg_type == DTRACED_MSG_HANDOFF &&
		    request.op == operations[i] && request.token[0] == 0xa1 &&
		    request.digest[0] == 0xb2);
		if (i == 5 || i == 7 || i == 9 || i == 16 || i == 19 ||
		    i == 22 || i == 25 || i == 28 || i == 31 ||
		    i == 34 || i == 37 || i == 42 || i == 44) {
			close(peer); /* durable receipt, lost ACK */
			continue;
		}
		uint8_t ack = i == 13 ? 2 :
		    i == 14 || i == 18 || i == 21 || i == 24 ||
		    i == 27 || i == 30 || i == 33 || i == 36 ||
		    i == 39 || i == 40 ? 0 :
		    i == 15 || i == 17 || i == 20 || i == 23 ||
		    i == 26 || i == 29 || i == 32 || i == 35 ||
		    i == 38 || i == 41 || i == 43 || i == 45 ? 1 :
		    i >= 11 ? 0 : 1;
		CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
		    deadline, &transferred) == 0);
		if (i == 41) {
			dtraced_delivery_status_t status = { .phase = 'c',
			    .digest = { 0xb2 } };
			CHECK(dtraced_io_transfer(peer, &status,
			    sizeof(status), true, deadline, &transferred) == 0);
		}
		close(peer);
	}
	struct pollfd pending = { .fd = listener, .events = POLLIN };
	CHECK(poll(&pending, 1, 250) == 0);
	return (NULL);
}

struct import_fixture {
	int listener;
	uint8_t token[16];
	uint8_t digest[32];
	uint8_t bundle[32 + 3 + 4 + 5 + 32];
};

struct release_import_fixture {
	int listener;
	uint8_t token[16];
	uint8_t digest[32];
	uint8_t release[DTRACED_RELEASE_ATTESTED_SIZE];
};

static void *
release_import_server(void *argument)
{
	struct release_import_fixture *fixture = argument;
	for (int i = 0; i < 3; i++) {
		int peer = accept(fixture->listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		size_t transferred, length;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		uint8_t frame[DTRACED_MSGHDRSIZE +
		    DTRACED_HANDOFF_RELEASE_IMPORT_SIZE];
		dtraced_hdr_t header;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0 &&
		    hello.kind == DTRACED_KIND_FORWARDER &&
		    hello.subs == DTD_SUB_READDATA);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 && length == sizeof(frame));
		CHECK(dtraced_io_transfer(peer, frame, sizeof(frame), false,
		    deadline, &transferred) == 0);
		CHECK(dtraced_wire_decode_header(&header, frame) == 0 &&
		    header.msg_type == DTRACED_MSG_HANDOFF_RELEASE_IMPORT &&
		    memcmp(frame + DTRACED_MSGHDRSIZE, fixture->token, 16) == 0 &&
		    memcmp(frame + DTRACED_MSGHDRSIZE + 16,
		    fixture->digest, 32) == 0 &&
		    memcmp(frame + DTRACED_MSGHDRSIZE + 48,
		    fixture->release, sizeof(fixture->release)) == 0);
		if (i == 0) {
			close(peer); /* Durable stage, lost ACK. */
			continue;
		}
		uint8_t ack = i == 1 ? 1 : 0;
		CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
		    deadline, &transferred) == 0);
		close(peer);
	}
	return (NULL);
}

static void *
import_prestart_server(void *argument)
{
	struct import_fixture *fixture = argument;
	for (int i = 0; i < 4; i++) {
		int peer = accept(fixture->listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		size_t transferred, length;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		uint8_t header_wire[DTRACED_MSGHDRSIZE];
		uint8_t binding[DTRACED_HANDOFF_IMPORT_BINDING_SIZE];
		uint8_t bundle[sizeof(fixture->bundle)];
		dtraced_hdr_t header;

		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		CHECK(hello.kind == DTRACED_KIND_FORWARDER &&
		    hello.protocol_version == DTRACED_PROTOCOL_VERSION &&
		    hello.subs == DTD_SUB_READDATA &&
		    memcmp(hello.session_id, forwarder_session_id,
		    sizeof(hello.session_id)) == 0 &&
		    strcmp(hello.ident, "test-vm") == 0);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 &&
		    length == sizeof(header_wire) + sizeof(binding) +
		    sizeof(bundle));
		CHECK(dtraced_io_transfer(peer, header_wire,
		    sizeof(header_wire), false, deadline, &transferred) == 0);
		CHECK(dtraced_wire_decode_header(&header, header_wire) == 0 &&
		    header.msg_type == DTRACED_MSG_HANDOFF_IMPORT);
		CHECK(dtraced_io_transfer(peer, binding, sizeof(binding), false,
		    deadline, &transferred) == 0);
		CHECK(memcmp(binding, fixture->token, sizeof(fixture->token)) == 0 &&
		    memcmp(binding + sizeof(fixture->token), fixture->digest,
		    sizeof(fixture->digest)) == 0);
		CHECK(dtraced_io_transfer(peer, bundle, sizeof(bundle), false,
		    deadline, &transferred) == 0 &&
		    memcmp(bundle, fixture->bundle, sizeof(bundle)) == 0);
		if (i == 0) {
			close(peer); /* Durable import, lost ACK. */
			continue;
		}
		uint8_t ack = i == 1 ? 1 : i == 2 ? 0 : 2;
		CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
		    deadline, &transferred) == 0);
		close(peer);
	}
	struct pollfd pending = { .fd = fixture->listener, .events = POLLIN };
	CHECK(poll(&pending, 1, 250) == 0);
	return (NULL);
}

static void *
destination_status_server(void *argument)
{
	int listener = *(int *)argument;
	for (int i = 0; i < 3; i++) {
		int peer = accept(listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		size_t length, transferred;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		CHECK(hello.kind == DTRACED_KIND_FORWARDER &&
		    hello.subs == DTD_SUB_READDATA);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		uint8_t frame[sizeof(dtraced_hdr_t) +
		    sizeof(dtraced_handoff_request_t)];
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 && length == sizeof(frame));
		CHECK(dtraced_io_transfer(peer, frame, sizeof(frame), false,
		    deadline, &transferred) == 0);
		dtraced_handoff_request_t request;
		memcpy(&request, frame + sizeof(dtraced_hdr_t),
		    sizeof(request));
		CHECK(request.op == DTRACED_HANDOFF_DESTINATION_STATUS &&
		    request.token[0] == 0xa1 && request.digest[0] == 0xb2);
		uint8_t ack = 1;
		dtraced_delivery_status_t status = {
		    .phase = i == 0 ? 'c' : 'v' };
		status.digest[0] = i == 2 ? 0xb3 : 0xb2;
		CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &status, sizeof(status), true,
		    deadline, &transferred) == 0);
		close(peer);
	}
	return (NULL);
}

static void *
destination_ensure_server(void *argument)
{
	int listener = *(int *)argument;
	const uint8_t operations[] = { DTRACED_HANDOFF_RESERVE,
	    DTRACED_HANDOFF_DESTINATION_STATUS, DTRACED_HANDOFF_CANCEL,
	    DTRACED_HANDOFF_DESTINATION_STATUS, DTRACED_HANDOFF_RESERVE,
	    DTRACED_HANDOFF_DESTINATION_STATUS, DTRACED_HANDOFF_MUTATE,
	    DTRACED_HANDOFF_DESTINATION_STATUS, DTRACED_HANDOFF_CLAIM,
	    DTRACED_HANDOFF_DESTINATION_STATUS };
	for (size_t i = 0; i < sizeof(operations); i++) {
		int peer = accept(listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		size_t length, transferred;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		uint8_t frame[sizeof(dtraced_hdr_t) +
		    sizeof(dtraced_handoff_request_t)];
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 && length == sizeof(frame));
		CHECK(dtraced_io_transfer(peer, frame, sizeof(frame), false,
		    deadline, &transferred) == 0);
		dtraced_handoff_request_t request;
		memcpy(&request, frame + sizeof(dtraced_hdr_t),
		    sizeof(request));
		CHECK(request.op == operations[i] &&
		    request.token[0] == 0xa1 && request.digest[0] == 0xb2);
		if (i % 2 != 0) {
			uint8_t ack = 1;
			dtraced_delivery_status_t status = {
			    .phase = i == 1 ? 'v' : i == 7 ? 'm' :
			    i == 9 ? 'r' : 'c',
			    .digest = { 0xb2 } };
			CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
			    deadline, &transferred) == 0);
			CHECK(dtraced_io_transfer(peer, &status,
			    sizeof(status), true, deadline,
			    &transferred) == 0);
		}
		close(peer);
	}
	return (NULL);
}

struct handoff_nak_case {
	int listener;
	uint8_t op;
	uint8_t ack;
	bool drop_first;
	bool status_after_nak;
	uint8_t status_phase;
	bool extra;
};

static void *
handoff_nak_server(void *argument)
{
	struct handoff_nak_case *test = argument;
	int listener = test->listener;
	for (unsigned i = 0; i <
	    (test->drop_first || test->status_after_nak ? 2U : 1U); i++) {
		int peer = accept(listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		uint8_t frame[sizeof(dtraced_hdr_t) +
		    sizeof(dtraced_handoff_request_t)];
		size_t length, transferred;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 && length == sizeof(frame));
		CHECK(dtraced_io_transfer(peer, frame, sizeof(frame), false,
		    deadline, &transferred) == 0);
		dtraced_handoff_request_t request;
		memcpy(&request, frame + sizeof(dtraced_hdr_t),
		    sizeof(request));
		CHECK(request.op == (test->status_after_nak && i == 1 ?
		    DTRACED_HANDOFF_DESTINATION_STATUS : test->op));
		if (!test->drop_first || i != 0) {
			uint8_t ack = test->status_after_nak && i == 1 ?
			    1 : test->ack;
			CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack),
			    true, deadline, &transferred) == 0);
			if (test->status_after_nak && i == 1) {
				dtraced_delivery_status_t status = {
				    .phase = test->status_phase,
				    .digest = { 0xb2 } };
				CHECK(dtraced_io_transfer(peer, &status,
				    sizeof(status), true, deadline,
				    &transferred) == 0);
			}
		}
		close(peer);
	}
	struct pollfd pfd = { .fd = listener, .events = POLLIN };
	int ready = poll(&pfd, 1, 250);
	CHECK(ready >= 0);
	test->extra = ready != 0;
	if (ready > 0) {
		int peer = accept(listener, NULL, NULL);
		CHECK(peer >= 0);
		close(peer);
	}
	return (NULL);
}

struct mutation_reset_case {
	int listener;
	uint8_t final_ack;
	uint8_t status_ack;
	bool extra;
};

static void *
mutation_reset_server(void *argument)
{
	struct mutation_reset_case *test = argument;
	const uint8_t operations[] = { DTRACED_HANDOFF_REBIND_BEGIN,
	    DTRACED_HANDOFF_DESTINATION_STATUS,
	    DTRACED_HANDOFF_RESET_MUTATION };
	for (size_t i = 0; i < (test->status_ack == 2 ? 2 :
	    sizeof(operations)); i++) {
		int peer = accept(test->listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		uint8_t frame[sizeof(dtraced_hdr_t) +
		    sizeof(dtraced_handoff_request_t)];
		size_t length, transferred;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 && length == sizeof(frame));
		CHECK(dtraced_io_transfer(peer, frame, sizeof(frame), false,
		    deadline, &transferred) == 0);
		dtraced_handoff_request_t request;
		memcpy(&request, frame + sizeof(dtraced_hdr_t),
		    sizeof(request));
		CHECK(request.op == operations[i] &&
		    request.token[0] == 0xa1 && request.digest[0] == 0xb2);
		uint8_t ack = i == 2 ? test->final_ack :
		    i == 1 ? test->status_ack : 0;
		CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
		    deadline, &transferred) == 0);
		close(peer);
	}
	struct pollfd pfd = { .fd = test->listener, .events = POLLIN };
	CHECK(poll(&pfd, 1, 250) >= 0);
	test->extra = (pfd.revents & POLLIN) != 0;
	return (NULL);
}

static void *
source_fresh_server(void *argument)
{
	int listener = *(int *)argument;
	const uint8_t operations[] = { DTRACED_HANDOFF_PREPARE,
	    DTRACED_HANDOFF_SOURCE_STATUS, DTRACED_HANDOFF_PREPARE,
	    DTRACED_HANDOFF_SOURCE_STATUS, DTRACED_HANDOFF_ABORT,
	    DTRACED_HANDOFF_SOURCE_STATUS, DTRACED_HANDOFF_PREPARE,
	    DTRACED_HANDOFF_COMMIT, DTRACED_HANDOFF_SOURCE_STATUS,
	    DTRACED_HANDOFF_SOURCE_STATUS };
	for (size_t i = 0; i < sizeof(operations); i++) {
		int peer = accept(listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		size_t length, transferred;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		CHECK(hello.kind == DTRACED_KIND_FORWARDER &&
		    hello.subs == DTD_SUB_READDATA &&
		    memcmp(hello.session_id, forwarder_session_id,
		    sizeof(hello.session_id)) == 0);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		uint8_t frame[sizeof(dtraced_hdr_t) +
		    sizeof(dtraced_handoff_request_t)];
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 && length == sizeof(frame));
		CHECK(dtraced_io_transfer(peer, frame, sizeof(frame), false,
		    deadline, &transferred) == 0);
		dtraced_hdr_t header;
		dtraced_handoff_request_t request;
		memcpy(&header, frame, sizeof(header));
		memcpy(&request, frame + sizeof(header), sizeof(request));
		CHECK(header.msg_type == DTRACED_MSG_HANDOFF &&
		    request.op == operations[i] && request.token[0] == 0xa1 &&
		    request.digest[0] ==
		    (operations[i] == DTRACED_HANDOFF_PREPARE ? 0xd4 :
		    operations[i] == DTRACED_HANDOFF_COMMIT ? 0xb2 : 0));
		if (i != 2) {
			uint8_t ack = 1;
			CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
			    deadline, &transferred) == 0);
			if (operations[i] == DTRACED_HANDOFF_SOURCE_STATUS) {
				dtraced_delivery_status_t status = {
				    .phase = i == 1 || i == 3 ? 'p' :
				    i == 5 ? 0 : 'c' };
				if (status.phase == 'c')
					status.digest[0] = 0xb2;
				if (status.phase == 'p')
					status.digest[0] = 0xd4;
				if (i == 9)
					status.reserved[0] = 1;
				CHECK(dtraced_io_transfer(peer, &status,
				    sizeof(status), true, deadline,
				    &transferred) == 0);
			}
		}
		close(peer);
	}
	return (NULL);
}

static void *
source_ensure_server(void *argument)
{
	int listener = *(int *)argument;
	const uint8_t operations[] = { DTRACED_HANDOFF_PREPARE,
	    DTRACED_HANDOFF_SOURCE_STATUS, DTRACED_HANDOFF_ABORT,
	    DTRACED_HANDOFF_SOURCE_STATUS, DTRACED_HANDOFF_COMMIT,
	    DTRACED_HANDOFF_SOURCE_STATUS, DTRACED_HANDOFF_PREPARE,
	    DTRACED_HANDOFF_SOURCE_STATUS, DTRACED_HANDOFF_PREPARE,
	    DTRACED_HANDOFF_SOURCE_STATUS };
	for (size_t i = 0; i < sizeof(operations); i++) {
		int peer = accept(listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		size_t length, transferred;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		CHECK(hello.kind == DTRACED_KIND_FORWARDER &&
		    hello.subs == DTD_SUB_READDATA);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		uint8_t frame[sizeof(dtraced_hdr_t) +
		    sizeof(dtraced_handoff_request_t)];
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 && length == sizeof(frame));
		CHECK(dtraced_io_transfer(peer, frame, sizeof(frame), false,
		    deadline, &transferred) == 0);
		dtraced_handoff_request_t request;
		memcpy(&request, frame + sizeof(dtraced_hdr_t),
		    sizeof(request));
		CHECK(request.op == operations[i] && request.token[0] == 0xa1);
		if (i == 6) {
			uint8_t nak = 0;
			CHECK(dtraced_io_transfer(peer, &nak, sizeof(nak), true,
			    deadline, &transferred) == 0);
		} else if ((i & 1) != 0) {
			uint8_t ack = 1;
			dtraced_delivery_status_t status = {
			    .phase = i == 1 ? 'p' : i == 5 ? 'c' : 0 };
			if (status.phase == 'c')
				status.digest[0] = 0xb2;
			if (status.phase == 'p')
				status.digest[0] = 0xd4;
			CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
			    deadline, &transferred) == 0);
			CHECK(dtraced_io_transfer(peer, &status,
			    sizeof(status), true, deadline,
			    &transferred) == 0);
		}
		close(peer);
	}
	return (NULL);
}

static void *
source_gate_server(void *argument)
{
	int listener = *(int *)argument;
	for (unsigned i = 0; i < 4; i++) {
		int peer = accept(listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		size_t length, transferred;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		CHECK(hello.kind == DTRACED_KIND_FORWARDER &&
		    hello.subs == DTD_SUB_READDATA);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_HANDOFF_WIRE_SIZE];
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 && length == sizeof(frame));
		CHECK(dtraced_io_transfer(peer, frame, sizeof(frame), false,
		    deadline, &transferred) == 0);
		dtraced_handoff_request_t request;
		CHECK(dtraced_wire_decode_handoff(&request,
		    frame + DTRACED_MSGHDRSIZE) == 0 &&
		    request.op == (i < 2 ? DTRACED_HANDOFF_SOURCE_GATE_BEGIN :
		    DTRACED_HANDOFF_SOURCE_GATE_ABORT) &&
		    request.token[0] == 0xa1 && request.digest[0] == 0);
		if (i != 0 && i != 2) {
			uint8_t ack = 1;
			CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
			    deadline, &transferred) == 0);
		}
		close(peer);
	}
	return (NULL);
}

static void *
source_drain_server(void *argument)
{
	int listener = *(int *)argument;
	/* The first ACK is lost after an assumed durable HGD1 publication.
	 * The retry advances, and the final request reports no work left. */
	for (unsigned i = 0; i < 3; i++) {
		int peer = accept(listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		size_t length, transferred;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		CHECK(hello.kind == DTRACED_KIND_FORWARDER &&
		    hello.subs == DTD_SUB_READDATA);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_HANDOFF_WIRE_SIZE];
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 && length == sizeof(frame));
		CHECK(dtraced_io_transfer(peer, frame, sizeof(frame), false,
		    deadline, &transferred) == 0);
		dtraced_handoff_request_t request;
		CHECK(dtraced_wire_decode_handoff(&request,
		    frame + DTRACED_MSGHDRSIZE) == 0 &&
		    request.op == DTRACED_HANDOFF_SOURCE_DRAIN_STEP &&
		    request.token[0] == 0xa1 && request.digest[0] == 0xd4);
		if (i != 0) {
			uint8_t reply[2] = { 1, i == 1 ? 1 : 0 };
			CHECK(dtraced_io_transfer(peer, reply, sizeof(reply), true,
			    deadline, &transferred) == 0);
		}
		close(peer);
	}
	return (NULL);
}

static void *
prestart_delivery_server(void *argument)
{
	int listener = *(int *)argument;
	for (int i = 0; i < 8; i++) {
		int peer = accept(listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		size_t transferred, length;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		CHECK(hello.kind == DTRACED_KIND_FORWARDER &&
		    hello.protocol_version == DTRACED_PROTOCOL_VERSION &&
		    hello.subs == DTD_SUB_READDATA &&
		    memcmp(hello.session_id, forwarder_session_id,
		    sizeof(hello.session_id)) == 0);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		uint8_t frame[DTRACED_MSGHDRSIZE +
		    DTRACED_HANDOFF_BIND_DELIVERY_WIRE_SIZE];
		size_t expected = DTRACED_MSGHDRSIZE + (i == 4 || i == 5 ?
		    DTRACED_HANDOFF_BIND_DELIVERY_WIRE_SIZE :
		    DTRACED_HANDOFF_DELIVERY_WIRE_SIZE);
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 && length == expected);
		CHECK(dtraced_io_transfer(peer, frame, expected, false,
		    deadline, &transferred) == 0);
		dtraced_hdr_t header;
		dtraced_handoff_delivery_request_t request;
		CHECK(dtraced_wire_decode_header(&header, frame) == 0 &&
		    dtraced_wire_decode_handoff_delivery(&request,
		    frame + DTRACED_MSGHDRSIZE) == 0);
		if (i == 4 || i == 5)
			CHECK(frame[DTRACED_MSGHDRSIZE +
			    DTRACED_HANDOFF_DELIVERY_WIRE_SIZE] == 0xb3);
		CHECK(header.msg_type == (i < 4 || i >= 6 ?
		    DTRACED_MSG_HANDOFF_DELIVERY :
		    DTRACED_MSG_HANDOFF_BIND_DELIVERY) &&
		    request.token[0] == 0xa1 && request.digest[0] == 0xb2 &&
		    request.delivery_id == 77 && request.program_id[0] == 1 &&
		    request.source_id[0] == 2 &&
		    request.scope == (i == 7 ? 3 : 0));
		uint8_t ack = i == 1 ? 0 : 1;
		CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
		    deadline, &transferred) == 0);
		if (ack == 1) {
			dtraced_delivery_status_t status = {
			    .delivery_id = i == 2 ? 78 : 77,
			    .phase = i == 3 ? 't' : i == 5 ? 'p' : 'a',
			    .digest = { 0xb3 }
			};
			CHECK(dtraced_io_transfer(peer, &status,
			    sizeof(status), true, deadline, &transferred) == 0);
		}
		close(peer);
	}
	return (NULL);
}

static void *
prestart_kill_server(void *argument)
{
	int listener = *(int *)argument;
	for (int i = 0; i < 7; i++) {
		int peer = accept(listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		size_t transferred, length;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		CHECK(hello.kind == DTRACED_KIND_FORWARDER &&
		    hello.protocol_version == DTRACED_PROTOCOL_VERSION &&
		    hello.subs == DTD_SUB_READDATA &&
		    memcmp(hello.session_id, forwarder_session_id,
		    sizeof(hello.session_id)) == 0);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		uint8_t frame[sizeof(dtraced_hdr_t) +
		    sizeof(dtraced_handoff_kill_request_t)];
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 && length == sizeof(frame));
		CHECK(dtraced_io_transfer(peer, frame, sizeof(frame), false,
		    deadline, &transferred) == 0);
		dtraced_hdr_t header;
		dtraced_handoff_kill_request_t request;
		memcpy(&header, frame, sizeof(header));
		memcpy(&request, frame + sizeof(header), sizeof(request));
		CHECK(header.msg_type == (i < 4 || i == 6 ?
		    DTRACED_MSG_HANDOFF_KILL :
		    DTRACED_MSG_HANDOFF_BIND_KILL) &&
		    request.token[0] == 0xa1 && request.digest[0] == 0xb2 &&
		    request.pid == 123 && request.source_id[0] == 2);
		uint8_t ack = i == 1 ? 0 : 1;
		CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
		    deadline, &transferred) == 0);
		if (ack == 1) {
			dtraced_delivery_status_t status = {
			    .delivery_id = 123,
			    .phase = i == 3 ? 'x' : i == 2 || i == 5 ? 0 : 'p',
			    .revoked = 1
			};
			CHECK(dtraced_io_transfer(peer, &status,
			    sizeof(status), true, deadline, &transferred) == 0);
		}
		close(peer);
	}
	return (NULL);
}

static void *
prestart_cleanup_server(void *argument)
{
	int listener = *(int *)argument;
	for (int i = 0; i < 3; i++) {
		int peer = accept(listener, NULL, NULL);
		dtd_initmsg_t hello = { .protocol_version =
		    DTRACED_PROTOCOL_VERSION, .kind = DTRACED_KIND_DTRACED };
		size_t transferred, length;
		int64_t deadline = dtraced_io_milliseconds() + 2000;
		CHECK(peer >= 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), true,
		    deadline, &transferred) == 0);
		CHECK(dtraced_io_transfer(peer, &hello, sizeof(hello), false,
		    deadline, &transferred) == 0);
		CHECK(hello.kind == DTRACED_KIND_FORWARDER &&
		    hello.protocol_version == DTRACED_PROTOCOL_VERSION &&
		    hello.subs == DTD_SUB_READDATA &&
		    memcmp(hello.session_id, forwarder_session_id,
		    sizeof(hello.session_id)) == 0);
		int identity_fd = dtraced_io_recv_fd(peer, deadline);
		CHECK(identity_fd >= 0);
		close(identity_fd);
		uint8_t frame[DTRACED_MSGHDRSIZE +
		    DTRACED_HANDOFF_CLEANUP_WIRE_SIZE];
		CHECK(dtraced_io_transfer(peer, &length, sizeof(length), false,
		    deadline, &transferred) == 0 && length == sizeof(frame));
		CHECK(dtraced_io_transfer(peer, frame, sizeof(frame), false,
		    deadline, &transferred) == 0);
		dtraced_hdr_t header;
		dtraced_handoff_cleanup_request_t request;
		CHECK(dtraced_wire_decode_header(&header, frame) == 0 &&
		    header.msg_type == DTRACED_MSG_HANDOFF_CLEANUP);
		CHECK(dtraced_wire_decode_handoff_cleanup(&request,
		    frame + DTRACED_MSGHDRSIZE) == 0 &&
		    request.token[0] == 0xa1 && request.digest[0] == 0xb2 &&
		    request.delivery_id == 456);
		uint8_t ack = 1;
		CHECK(dtraced_io_transfer(peer, &ack, sizeof(ack), true,
		    deadline, &transferred) == 0);
		dtraced_delivery_status_t status = {
		    .delivery_id = i == 2 ? 457 : 456,
		    .phase = i == 0 || i == 2 ? 'a' : 0
		};
		uint8_t wire[DTRACED_STATUS_WIRE_SIZE];
		dtraced_wire_encode_status(wire, &status);
		CHECK(dtraced_io_transfer(peer, wire, sizeof(wire), true,
		    deadline, &transferred) == 0);
		close(peer);
	}
	return (NULL);
}

int
main(void)
{
	char directory[] = "/tmp/hypertrace-bhyve-connect-XXXXXX";
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	struct ht_channel channel = { .mutex = PTHREAD_MUTEX_INITIALIZER,
	    .fd = -1 };
	struct handoff_nak_case nak;
	pthread_t thread;
	int listener;
	CHECK(mkdtemp(directory) != NULL);
	CHECK(snprintf(address.sun_path, sizeof(address.sun_path), "%s/sub.sock",
	    directory) < (int)sizeof(address.sun_path));
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 1) == 0);
	sockdir = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	CHECK(sockdir >= 0);
	forwarder_session_id[0] = 0x42;
	CHECK(pthread_create(&thread, NULL, server, &listener) == 0);
	CHECK(ht_connect(&channel, (struct vmctx *)1, DTD_SUB_ELFWRITE |
	    DTD_SUB_ADMISSION_ACK) == 0);
	CHECK(atomic_load(&channel.configured));
	pthread_mutex_lock(&channel.mutex);
	ht_disconnect(&channel);
	pthread_mutex_unlock(&channel.mutex);
	CHECK(ht_connect(&channel, (struct vmctx *)1, DTD_SUB_ELFWRITE |
	    DTD_SUB_ADMISSION_ACK) == -1 && errno == EPROTO);
	CHECK(!atomic_load(&channel.configured) && channel.fd == -1);
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	close(sockdir);
	sockdir = -1;
	fixture_root = directory;
	CHECK(hypertrace_start((struct vmctx *)1) == -1 && errno == EINVAL);
	uint8_t ticket[16] = { 0xa1 }, digest[32] = { 0xb2 };
	CHECK(hypertrace_handoff_destination_prestart((struct vmctx *)1,
	    DTRACED_HANDOFF_RESERVE, ticket, digest) == -1 && errno == EINVAL);
	dtraced_delivery_status_t early_status = { .phase = 'c' };
	CHECK(hypertrace_handoff_source_status_fresh((struct vmctx *)1,
	    ticket, &early_status) == -1 && errno == EINVAL &&
	    early_status.phase == 0);
	CHECK(hypertrace_init((struct vmctx *)1) == 0);
	CHECK(hypertrace_initialized() && !started && !hypertrace_configured());
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 1) == 0);
	CHECK(pthread_create(&thread, NULL, source_release_open_server,
	    &listener) == 0);
	int release_fd = hypertrace_handoff_source_release_open(
	    (struct vmctx *)1);
	uint8_t release_wire[DTRACED_RELEASE_ATTESTED_SIZE];
	bool signed_release = true;
	CHECK(release_fd >= 0 &&
	    hypertrace_handoff_source_release_finish(release_fd,
	    ticket, digest, release_wire, &signed_release) == 0 &&
	    !signed_release);
	CHECK(fcntl(release_fd, F_GETFD) == -1 && errno == EBADF);
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	memset(source_release_wire, 0, sizeof(source_release_wire));
	memcpy(source_release_wire, "HSA1", 4);
	source_release_wire[4] = 1;
	source_release_wire[8] = 0x11;
	source_release_wire[40] = 0x22;
	memcpy(source_release_wire + 72, "HSL1HTH2", 8);
	memcpy(source_release_wire + 80, ticket, sizeof(ticket));
	memcpy(source_release_wire + 122, digest, sizeof(digest));
	uint8_t empty_transfer[DTRACED_TRANSFER_HEADER_SIZE +
	    DTRACED_TRANSFER_DIGEST_SIZE] = {};
	memcpy(empty_transfer, "HTX1", 4);
	memcpy(empty_transfer + 4, ticket, sizeof(ticket));
	CHECK(SHA256(empty_transfer, DTRACED_TRANSFER_HEADER_SIZE,
	    empty_transfer + DTRACED_TRANSFER_HEADER_SIZE) != NULL);
	memcpy(source_release_wire + 164,
	    empty_transfer + DTRACED_TRANSFER_HEADER_SIZE,
	    DTRACED_TRANSFER_DIGEST_SIZE);
	CHECK(SHA256(source_release_wire + 76, 120,
	    source_release_wire + 196) != NULL);
	CHECK(SHA256(source_release_wire + 72, 156,
	    source_release_wire + 228) != NULL);
	CHECK(hypertrace_release_attestation_inspect(source_release_wire,
	    ticket, digest) == 0);
	CHECK(hypertrace_release_transfer_inspect(source_release_wire,
	    ticket, digest, empty_transfer, sizeof(empty_transfer)) == 0);
	empty_transfer[20] = 1;
	CHECK(hypertrace_release_transfer_inspect(source_release_wire,
	    ticket, digest, empty_transfer, sizeof(empty_transfer)) == -1 &&
	    errno == EPROTO);
	empty_transfer[20] = 0;
	empty_transfer[32] ^= 1;
	CHECK(hypertrace_release_transfer_inspect(source_release_wire,
	    ticket, digest, empty_transfer, sizeof(empty_transfer)) == -1 &&
	    errno == EPROTO);
	empty_transfer[32] ^= 1;
	source_release_wire[164] ^= 1;
	CHECK(SHA256(source_release_wire + 76, 120,
	    source_release_wire + 196) != NULL);
	CHECK(SHA256(source_release_wire + 72, 156,
	    source_release_wire + 228) != NULL);
	CHECK(hypertrace_release_transfer_inspect(source_release_wire,
	    ticket, digest, empty_transfer, sizeof(empty_transfer)) == -1 &&
	    errno == EPROTO);
	source_release_wire[164] ^= 1;
	CHECK(SHA256(source_release_wire + 76, 120,
	    source_release_wire + 196) != NULL);
	CHECK(SHA256(source_release_wire + 72, 156,
	    source_release_wire + 228) != NULL);
	source_release_wire[122]++;
	CHECK(hypertrace_release_attestation_inspect(source_release_wire,
	    ticket, digest) == -1 && errno == EPROTO);
	source_release_wire[122]--;
	source_release_mode = DTRACED_RELEASE_MODE_SIGNED;
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 1) == 0);
	CHECK(pthread_create(&thread, NULL, source_release_open_server,
	    &listener) == 0);
	release_fd = hypertrace_handoff_source_release_open((struct vmctx *)1);
	CHECK(release_fd >= 0 &&
	    hypertrace_handoff_source_release_finish(release_fd, ticket,
	    digest, release_wire, &signed_release) == 0 && signed_release &&
	    memcmp(release_wire, source_release_wire,
	    sizeof(source_release_wire)) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 1) == 0);
	CHECK(pthread_create(&thread, NULL, release_recovery_server,
	    &listener) == 0);
	CHECK(hypertrace_release_recover(ticket, digest, release_wire) == 0 &&
	    memcmp(release_wire, source_release_wire,
	    sizeof(source_release_wire)) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	struct release_import_fixture release_import = { .token = { 0xa1 },
	    .digest = { 0xb2 } };
	memcpy(release_import.release, source_release_wire,
	    sizeof(release_import.release));
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address,
	    sizeof(address)) == 0 && listen(listener, 1) == 0);
	release_import.listener = listener;
	CHECK(pthread_create(&thread, NULL, release_import_server,
	    &release_import) == 0);
	CHECK(hypertrace_handoff_destination_stage_release_prestart(
	    (struct vmctx *)1, ticket, digest, source_release_wire) == 0);
	CHECK(hypertrace_handoff_destination_stage_release_prestart(
	    (struct vmctx *)1, ticket, digest, source_release_wire) == -1 &&
	    errno == EPROTO);
	uint8_t wrong_release_digest[32] = { 0xb3 };
	CHECK(hypertrace_handoff_destination_stage_release_prestart(
	    (struct vmctx *)1, ticket, wrong_release_digest,
	    source_release_wire) == -1 && errno == EPROTO);
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	source_release_truncate = true;
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 1) == 0);
	CHECK(pthread_create(&thread, NULL, source_release_open_server,
	    &listener) == 0);
	release_fd = hypertrace_handoff_source_release_open((struct vmctx *)1);
	CHECK(release_fd >= 0 &&
	    hypertrace_handoff_source_release_finish(release_fd, ticket,
	    digest, release_wire, &signed_release) == -1 && !signed_release);
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	source_release_truncate = false;
	source_release_mode = DTRACED_RELEASE_MODE_LOCAL;
	CHECK(hypertrace_handoff_destination_prestart((struct vmctx *)1,
	    DTRACED_HANDOFF_PREPARE, ticket, digest) == -1 && errno == EINVAL);
	uint8_t empty_digest[32] = {};
	uint8_t transfer_digest[32] = { 0xd4 };
	CHECK(hypertrace_handoff_destination_prestart((struct vmctx *)1,
	    DTRACED_HANDOFF_RESERVE, ticket, empty_digest) == -1 &&
	    errno == EINVAL);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 8) == 0);
	CHECK(pthread_create(&thread, NULL, prestart_handoff_server,
	    &listener) == 0);
	CHECK(hypertrace_handoff_destination_prestart((struct vmctx *)1,
	    DTRACED_HANDOFF_RESERVE, ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination_prestart((struct vmctx *)1,
	    DTRACED_HANDOFF_CANCEL, ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination_prestart((struct vmctx *)1,
	    DTRACED_HANDOFF_RESERVE, ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination_prestart((struct vmctx *)1,
	    DTRACED_HANDOFF_MUTATE, ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination_prestart((struct vmctx *)1,
	    DTRACED_HANDOFF_CLAIM, ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination_promote_prestart(
	    (struct vmctx *)1, ticket, digest) == 0);
	CHECK(hypertrace_handoff_rekey_applied((struct vmctx *)1,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination_prestart((struct vmctx *)1,
	    DTRACED_HANDOFF_RESERVE, ticket, digest) == -1 && errno == EPROTO);
	CHECK(hypertrace_handoff_destination_promote_prestart(
	    (struct vmctx *)1, ticket, digest) == -1 && errno == EPROTO);
	CHECK(hypertrace_handoff_destination_promote_prestart(
	    (struct vmctx *)1, ticket, digest) == -1 && errno == EPROTO);
	CHECK(hypertrace_handoff_replay_drain((struct vmctx *)1,
	    ticket, digest, 0) == -1 && errno == EINVAL);
	CHECK(hypertrace_handoff_replay_drain((struct vmctx *)1,
	    ticket, digest, 2000) == 0);
	CHECK(hypertrace_handoff_execution_start((struct vmctx *)1,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_execution_start((struct vmctx *)1,
	    ticket, digest) == -1 && errno == EPROTO);
	CHECK(hypertrace_handoff_rebind_begin((struct vmctx *)1,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_rebind_begin((struct vmctx *)1,
	    ticket, digest) == -1 && errno == EPROTO);
	CHECK(hypertrace_handoff_rebind_stage((struct vmctx *)1,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_rebind_stage((struct vmctx *)1,
	    ticket, digest) == -1 && errno == EPROTO);
	CHECK(hypertrace_handoff_rebind_pending((struct vmctx *)1,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_rebind_pending((struct vmctx *)1,
	    ticket, digest) == -1 && errno == EPROTO);
	CHECK(hypertrace_handoff_rebind_cancel_pending((struct vmctx *)1,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_rebind_cancel_pending((struct vmctx *)1,
	    ticket, digest) == -1 && errno == EPROTO);
	CHECK(hypertrace_handoff_rebind_commit_empty((struct vmctx *)1,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_rebind_commit_empty((struct vmctx *)1,
	    ticket, digest) == -1 && errno == EPROTO);
	CHECK(hypertrace_handoff_rebind_empty_ready((struct vmctx *)1,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_rebind_empty_ready((struct vmctx *)1,
	    ticket, digest) == -1 && errno == EPROTO);
	CHECK(hypertrace_handoff_rebind_nonempty_preflight((struct vmctx *)1,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_rebind_nonempty_preflight((struct vmctx *)1,
	    ticket, digest) == -1 && errno == EPROTO);
	bool rebind = true;
	CHECK(hypertrace_handoff_rebind_begin_optional((struct vmctx *)1,
	    ticket, digest, &rebind) == 0 && !rebind);
	CHECK(hypertrace_handoff_rebind_begin_optional((struct vmctx *)1,
	    ticket, digest, &rebind) == 0 && rebind);
	CHECK(hypertrace_handoff_rebind_begin_optional((struct vmctx *)1,
	    ticket, digest, NULL) == -1 && errno == EINVAL);
	CHECK(hypertrace_handoff_mutation_reset((struct vmctx *)1,
	    ticket, digest) == -1);
	CHECK(hypertrace_handoff_mutation_reset((struct vmctx *)1,
	    ticket, digest) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	CHECK(!hypertrace_configured());
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	for (unsigned i = 0; i < 3; i++) {
		listener = socket(AF_UNIX, SOCK_STREAM, 0);
		CHECK(listener >= 0);
		CHECK(bind(listener, (struct sockaddr *)&address,
		    sizeof(address)) == 0);
		CHECK(listen(listener, 2) == 0);
		nak = (struct handoff_nak_case){ .listener = listener,
		    .op = DTRACED_HANDOFF_REBIND_BEGIN,
		    .ack = i == 0 ? 2 : 0, .drop_first = i == 1,
		    .status_after_nak = i == 2, .status_phase = 'v' };
		CHECK(pthread_create(&thread, NULL, handoff_nak_server,
		    &nak) == 0);
		rebind = true;
		CHECK(hypertrace_handoff_rebind_begin_optional(
		    (struct vmctx *)1, ticket, digest, &rebind) == -1 &&
		    errno == (i == 2 ? EBUSY : EPROTO) && !rebind);
		CHECK(pthread_join(thread, NULL) == 0 && !nak.extra);
		close(listener);
		CHECK(unlink(address.sun_path) == 0);
	}
	for (unsigned i = 0; i < 3; i++) {
		listener = socket(AF_UNIX, SOCK_STREAM, 0);
		CHECK(listener >= 0);
		CHECK(bind(listener, (struct sockaddr *)&address,
		    sizeof(address)) == 0);
		CHECK(listen(listener, 3) == 0);
		struct mutation_reset_case reset_case = {
		    .listener = listener, .final_ack = i == 0 ? 1 : 0,
		    .status_ack = i == 2 ? 2 : 0 };
		CHECK(pthread_create(&thread, NULL, mutation_reset_server,
		    &reset_case) == 0);
		rebind = true;
		CHECK(hypertrace_handoff_rebind_begin_optional(
		    (struct vmctx *)1, ticket, digest, &rebind) ==
		    (i == 0 ? 0 : -1) && !rebind);
		CHECK(pthread_join(thread, NULL) == 0 && !reset_case.extra);
		close(listener);
		CHECK(unlink(address.sun_path) == 0);
	}
	struct import_fixture import = { .token = { 0xa1 },
	    .digest = { 0xb2 } };
	memcpy(import.bundle, "HTX1", 4);
	memcpy(import.bundle + 4, import.token, sizeof(import.token));
	dtraced_wire_put_u32(import.bundle + 20, 3);
	dtraced_wire_put_u32(import.bundle + 24, 1);
	memcpy(import.bundle + 32, "abc", 3);
	dtraced_wire_put_u32(import.bundle + 35, 5);
	memcpy(import.bundle + 39, "frame", 5);
	CHECK(SHA256(import.bundle,
	    sizeof(import.bundle) - SHA256_DIGEST_LENGTH,
	    import.bundle + sizeof(import.bundle) - SHA256_DIGEST_LENGTH) != NULL);
	CHECK(dtraced_transfer_wire_valid(import.bundle, sizeof(import.bundle),
	    import.token));
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 4) == 0);
	import.listener = listener;
	CHECK(pthread_create(&thread, NULL, import_prestart_server, &import) == 0);
	CHECK(hypertrace_handoff_destination_import_prestart((struct vmctx *)1,
	    import.token, import.digest, import.bundle, sizeof(import.bundle)) == 0);
	CHECK(hypertrace_handoff_destination_import_prestart((struct vmctx *)1,
	    import.token, import.digest, import.bundle, sizeof(import.bundle)) == -1 &&
	    errno == EPROTO);
	CHECK(hypertrace_handoff_destination_import_prestart((struct vmctx *)1,
	    import.token, import.digest, import.bundle, sizeof(import.bundle)) == -1 &&
	    errno == EPROTO);
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	dtraced_delivery_status_t destination_ticket = { .phase = 'c' };
	CHECK(hypertrace_handoff_destination_status_prestart(
	    (struct vmctx *)1, ticket, digest, &destination_ticket) == -1 &&
	    destination_ticket.phase == 0);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 3) == 0);
	CHECK(pthread_create(&thread, NULL, destination_status_server,
	    &listener) == 0);
	CHECK(hypertrace_handoff_destination_status_prestart(
	    (struct vmctx *)1, ticket, digest, &destination_ticket) == 0 &&
	    destination_ticket.phase == 'c');
	CHECK(hypertrace_handoff_destination_status_prestart(
	    (struct vmctx *)1, ticket, digest, &destination_ticket) == 0 &&
	    destination_ticket.phase == 'v');
	CHECK(hypertrace_handoff_destination_status_prestart(
	    (struct vmctx *)1, ticket, digest, &destination_ticket) == -1 &&
	    errno == EPROTO && destination_ticket.phase == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 10) == 0);
	CHECK(pthread_create(&thread, NULL, destination_ensure_server,
	    &listener) == 0);
	CHECK(hypertrace_handoff_destination_ensure((struct vmctx *)1,
	    DTRACED_HANDOFF_RESERVE, ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination_ensure((struct vmctx *)1,
	    DTRACED_HANDOFF_CANCEL, ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination_ensure((struct vmctx *)1,
	    DTRACED_HANDOFF_RESERVE, ticket, digest) == -1 && errno == EBUSY);
	CHECK(hypertrace_handoff_destination_ensure((struct vmctx *)1,
	    DTRACED_HANDOFF_MUTATE, ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination_ensure((struct vmctx *)1,
	    DTRACED_HANDOFF_CLAIM, ticket, digest) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	for (uint8_t ack = 0; ack <= 2; ack += 2) {
		listener = socket(AF_UNIX, SOCK_STREAM, 0);
		CHECK(listener >= 0);
		CHECK(bind(listener, (struct sockaddr *)&address,
		    sizeof(address)) == 0);
		CHECK(listen(listener, 2) == 0);
		nak = (struct handoff_nak_case){ .listener = listener,
		    .op = DTRACED_HANDOFF_MUTATE, .ack = ack };
		CHECK(pthread_create(&thread, NULL, handoff_nak_server,
		    &nak) == 0);
		CHECK(hypertrace_handoff_destination_ensure((struct vmctx *)1,
		    DTRACED_HANDOFF_MUTATE, ticket, digest) == -1 &&
		    errno == EPROTO);
		CHECK(pthread_join(thread, NULL) == 0 && !nak.extra);
		close(listener);
		CHECK(unlink(address.sun_path) == 0);
	}
	CHECK(hypertrace_handoff_source_fresh((struct vmctx *)1,
	    DTRACED_HANDOFF_RESERVE, ticket, digest) == -1 && errno == EINVAL);
	CHECK(hypertrace_handoff_source_fresh((struct vmctx *)1,
	    DTRACED_HANDOFF_PREPARE, ticket, empty_digest) == -1 && errno == EINVAL);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 10) == 0);
	CHECK(pthread_create(&thread, NULL, source_fresh_server,
	    &listener) == 0);
	started = true; /* Recovery must work even with the normal connector up. */
	dtraced_delivery_status_t source_ticket = { 0 };
	CHECK(hypertrace_handoff_source_fresh((struct vmctx *)1,
	    DTRACED_HANDOFF_PREPARE, ticket, transfer_digest) == 0);
	CHECK(hypertrace_handoff_source_status_fresh((struct vmctx *)1,
	    ticket, &source_ticket) == 0 && source_ticket.phase == 'p' &&
	    source_ticket.digest[0] == 0xd4);
	CHECK(hypertrace_handoff_source_fresh((struct vmctx *)1,
	    DTRACED_HANDOFF_PREPARE, ticket, transfer_digest) == -1);
	CHECK(hypertrace_handoff_source_status_fresh((struct vmctx *)1,
	    ticket, &source_ticket) == 0 && source_ticket.phase == 'p');
	CHECK(hypertrace_handoff_source_fresh((struct vmctx *)1,
	    DTRACED_HANDOFF_ABORT, ticket, empty_digest) == 0);
	CHECK(hypertrace_handoff_source_status_fresh((struct vmctx *)1,
	    ticket, &source_ticket) == 0 && source_ticket.phase == 0);
	CHECK(hypertrace_handoff_source_fresh((struct vmctx *)1,
	    DTRACED_HANDOFF_PREPARE, ticket, transfer_digest) == 0);
	CHECK(hypertrace_handoff_source_fresh((struct vmctx *)1,
	    DTRACED_HANDOFF_COMMIT, ticket, digest) == 0);
	CHECK(hypertrace_handoff_source_status_fresh((struct vmctx *)1,
	    ticket, &source_ticket) == 0 && source_ticket.phase == 'c' &&
	    source_ticket.digest[0] == 0xb2);
	CHECK(hypertrace_handoff_source_status_fresh((struct vmctx *)1,
	    ticket, &source_ticket) == -1 && errno == EPROTO &&
	    source_ticket.phase == 0);
	started = false;
	CHECK(pthread_join(thread, NULL) == 0);
	CHECK(!hypertrace_configured());
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 8) == 0);
	CHECK(pthread_create(&thread, NULL, source_ensure_server,
	    &listener) == 0);
	bool definitely_absent = false;
	CHECK(hypertrace_handoff_source_ensure((struct vmctx *)1,
	    DTRACED_HANDOFF_PREPARE, ticket, transfer_digest,
	    &definitely_absent) == 0 && !definitely_absent);
	CHECK(hypertrace_handoff_source_ensure((struct vmctx *)1,
	    DTRACED_HANDOFF_ABORT, ticket, empty_digest,
	    &definitely_absent) == 0 && !definitely_absent);
	CHECK(hypertrace_handoff_source_ensure((struct vmctx *)1,
	    DTRACED_HANDOFF_COMMIT, ticket, digest,
	    &definitely_absent) == 0 && !definitely_absent);
	CHECK(hypertrace_handoff_source_ensure((struct vmctx *)1,
	    DTRACED_HANDOFF_PREPARE, ticket, transfer_digest,
	    &definitely_absent) == -1 && definitely_absent);
	/* An absent status on a different socket cannot order a timed-out
	 * PREPARE which the daemon may still be processing. */
	CHECK(hypertrace_handoff_source_ensure((struct vmctx *)1,
	    DTRACED_HANDOFF_PREPARE, ticket, transfer_digest,
	    &definitely_absent) == -1 && !definitely_absent);
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	CHECK(hypertrace_handoff_source_gate_ensure((struct vmctx *)1,
	    DTRACED_HANDOFF_COMMIT, ticket) == -1 && errno == EINVAL);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address,
	    sizeof(address)) == 0);
	CHECK(listen(listener, 4) == 0);
	CHECK(pthread_create(&thread, NULL, source_gate_server,
	    &listener) == 0);
	CHECK(hypertrace_handoff_source_gate_ensure((struct vmctx *)1,
	    DTRACED_HANDOFF_SOURCE_GATE_BEGIN, ticket) == 0);
	CHECK(hypertrace_handoff_source_gate_ensure((struct vmctx *)1,
	    DTRACED_HANDOFF_SOURCE_GATE_ABORT, ticket) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	const uint8_t gate_naks[] = { DTRACED_HANDOFF_SOURCE_GATE_BEGIN,
	    DTRACED_HANDOFF_SOURCE_GATE_ABORT };
	for (size_t i = 0; i < 2 * sizeof(gate_naks); i++) {
		uint8_t op = gate_naks[i / 2];
		uint8_t ack = (i % 2) * 2;
		listener = socket(AF_UNIX, SOCK_STREAM, 0);
		CHECK(listener >= 0);
		CHECK(bind(listener, (struct sockaddr *)&address,
		    sizeof(address)) == 0);
		CHECK(listen(listener, 2) == 0);
		nak = (struct handoff_nak_case){ .listener = listener,
		    .op = op, .ack = ack };
		CHECK(pthread_create(&thread, NULL, handoff_nak_server,
		    &nak) == 0);
		CHECK(hypertrace_handoff_source_gate_ensure((struct vmctx *)1,
		    op, ticket) == -1 && errno == EPROTO);
		CHECK(pthread_join(thread, NULL) == 0 && !nak.extra);
		close(listener);
		CHECK(unlink(address.sun_path) == 0);
	}
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address,
	    sizeof(address)) == 0);
	CHECK(listen(listener, 4) == 0);
	CHECK(pthread_create(&thread, NULL, source_drain_server,
	    &listener) == 0);
	CHECK(hypertrace_handoff_source_drain((struct vmctx *)1,
	    ticket, transfer_digest) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	dtraced_handoff_delivery_request_t lookup = {
	    .token = { 0xa1 }, .digest = { 0xb2 }, .delivery_id = 77,
	    .program_id = { 1 }, .source_id = { 2 }
	};
	dtraced_handoff_bind_delivery_request_t bound_lookup = {
	    .delivery = {
	        .token = { 0xa1 }, .digest = { 0xb2 }, .delivery_id = 77,
	        .program_id = { 1 }, .source_id = { 2 }
	    }, .payload_digest = { 0xb3 }
	};
	dtraced_delivery_status_t status;
	lookup.scope = 1;
	CHECK(hypertrace_handoff_delivery_prestart((struct vmctx *)1,
	    &lookup, &status) == -1 && errno == EINVAL);
	lookup.scope = 0;
	CHECK(hypertrace_handoff_delivery_live((struct vmctx *)1,
	    &lookup, &status) == -1 && errno == EINVAL);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 4) == 0);
	CHECK(pthread_create(&thread, NULL, prestart_delivery_server,
	    &listener) == 0);
	CHECK(hypertrace_handoff_delivery_prestart((struct vmctx *)1,
	    &lookup, &status) == 0 && status.phase == 'a' &&
	    status.replay == 0 && status.digest[0] == 0xb3);
	CHECK(hypertrace_handoff_delivery_prestart((struct vmctx *)1,
	    &lookup, &status) == -1 && errno == EPROTO);
	CHECK(hypertrace_handoff_delivery_prestart((struct vmctx *)1,
	    &lookup, &status) == -1 && errno == EPROTO &&
	    status.delivery_id == 0);
	CHECK(hypertrace_handoff_delivery_prestart((struct vmctx *)1,
	    &lookup, &status) == -1 && errno == EPROTO &&
	    status.delivery_id == 0);
	CHECK(hypertrace_handoff_bind_delivery_prestart((struct vmctx *)1,
	    &bound_lookup, &status) == 0 && status.phase == 'a' &&
	    status.digest[0] == 0xb3);
	CHECK(hypertrace_handoff_bind_delivery_prestart((struct vmctx *)1,
	    &bound_lookup, &status) == -1 && errno == EPROTO &&
	    status.delivery_id == 0);
	started = true;
	CHECK(hypertrace_handoff_delivery_prestart((struct vmctx *)1,
	    &lookup, &status) == -1 && errno == EINVAL);
	CHECK(hypertrace_handoff_bind_delivery_prestart((struct vmctx *)1,
	    &bound_lookup, &status) == -1 && errno == EINVAL);
	CHECK(hypertrace_handoff_delivery_live((struct vmctx *)1,
	    &lookup, &status) == 0 && status.phase == 'a' &&
	    status.digest[0] == 0xb3);
	lookup.scope = 3;
	CHECK(hypertrace_handoff_delivery_live((struct vmctx *)1,
	    &lookup, &status) == 0 && status.phase == 'a' &&
	    status.digest[0] == 0xb3);
	lookup.scope = 0;
	started = false;
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	dtraced_handoff_kill_request_t kill_lookup = {
	    .token = { 0xa1 }, .digest = { 0xb2 }, .pid = 123,
	    .source_id = { 2 }
	};
	kill_lookup.reserved[0] = 1;
	CHECK(hypertrace_handoff_kill_prestart((struct vmctx *)1,
	    &kill_lookup, &status) == -1 && errno == EINVAL);
	kill_lookup.reserved[0] = 0;
	CHECK(hypertrace_handoff_kill_live((struct vmctx *)1,
	    &kill_lookup, &status) == -1 && errno == EINVAL);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 4) == 0);
	CHECK(pthread_create(&thread, NULL, prestart_kill_server,
	    &listener) == 0);
	CHECK(hypertrace_handoff_kill_prestart((struct vmctx *)1,
	    &kill_lookup, &status) == 0 && status.phase == 'p' &&
	    status.revoked == 1 && status.replay == 0);
	CHECK(hypertrace_handoff_kill_prestart((struct vmctx *)1,
	    &kill_lookup, &status) == -1 && errno == EPROTO);
	CHECK(hypertrace_handoff_kill_prestart((struct vmctx *)1,
	    &kill_lookup, &status) == 0 && status.phase == 0 &&
	    status.revoked == 1 && status.replay == 0);
	CHECK(hypertrace_handoff_kill_prestart((struct vmctx *)1,
	    &kill_lookup, &status) == -1 && errno == EPROTO &&
	    status.delivery_id == 0);
	CHECK(hypertrace_handoff_bind_kill_prestart((struct vmctx *)1,
	    &kill_lookup, &status) == 0 && status.phase == 'p' &&
	    status.revoked == 1);
	CHECK(hypertrace_handoff_bind_kill_prestart((struct vmctx *)1,
	    &kill_lookup, &status) == -1 && errno == EPROTO &&
	    status.delivery_id == 0);
	started = true;
	CHECK(hypertrace_handoff_kill_prestart((struct vmctx *)1,
	    &kill_lookup, &status) == -1 && errno == EINVAL);
	CHECK(hypertrace_handoff_bind_kill_prestart((struct vmctx *)1,
	    &kill_lookup, &status) == -1 && errno == EINVAL);
	CHECK(hypertrace_handoff_kill_live((struct vmctx *)1,
	    &kill_lookup, &status) == 0 && status.phase == 'p' &&
	    status.revoked == 1);
	started = false;
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	dtraced_handoff_cleanup_request_t cleanup_lookup = {
	    .token = { 0xa1 }, .digest = { 0xb2 }, .delivery_id = 456
	};
	cleanup_lookup.delivery_id = 0;
	CHECK(hypertrace_handoff_cleanup_prestart((struct vmctx *)1,
	    &cleanup_lookup, &status) == -1 && errno == EINVAL);
	cleanup_lookup.delivery_id = 456;
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 3) == 0);
	CHECK(pthread_create(&thread, NULL, prestart_cleanup_server,
	    &listener) == 0);
	CHECK(hypertrace_handoff_cleanup_prestart((struct vmctx *)1,
	    &cleanup_lookup, &status) == 0 && status.phase == 'a' &&
	    status.delivery_id == 456);
	CHECK(hypertrace_handoff_cleanup_prestart((struct vmctx *)1,
	    &cleanup_lookup, &status) == 0 && status.phase == 0);
	CHECK(hypertrace_handoff_cleanup_prestart((struct vmctx *)1,
	    &cleanup_lookup, &status) == -1 && errno == EPROTO &&
	    status.delivery_id == 0);
	started = true;
	CHECK(hypertrace_handoff_cleanup_prestart((struct vmctx *)1,
	    &cleanup_lookup, &status) == -1 && errno == EINVAL);
	started = false;
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	fail_connector_once = true;
	CHECK(hypertrace_start((struct vmctx *)1) == -1 && errno == EAGAIN);
	CHECK(hypertrace_initialized() && !started && !hypertrace_configured());
	CHECK(hypertrace_start((struct vmctx *)1) == 0 && started);
	CHECK(hypertrace_start((struct vmctx *)1) == -1 && errno == EALREADY);
	hypertrace_destroy();
	CHECK(!hypertrace_initialized() && !started && sockdir == -1);
	int handoff_pair[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, handoff_pair) == 0);
	wx.fd = handoff_pair[0];
	atomic_store(&wx.configured, true);
	CHECK(pthread_create(&thread, NULL, handoff_server,
	    &handoff_pair[1]) == 0);
	memset(digest, 0, sizeof(digest));
	CHECK(hypertrace_handoff_source(DTRACED_HANDOFF_PREPARE,
	    ticket, transfer_digest) == 0);
	CHECK(hypertrace_handoff_source(DTRACED_HANDOFF_COMMIT,
	    ticket, digest) == -1 && errno == EINVAL);
	digest[0] = 0xb2;
	CHECK(hypertrace_handoff_source(DTRACED_HANDOFF_COMMIT,
	    ticket, digest) == -1 && errno == EPROTO);
	CHECK(atomic_load(&wx.configured) && wx.fd == handoff_pair[0]);
	CHECK(hypertrace_handoff_source(DTRACED_HANDOFF_COMMIT,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_source(DTRACED_HANDOFF_RESERVE,
	    ticket, digest) == -1 && errno == EINVAL);
	CHECK(hypertrace_handoff_destination(DTRACED_HANDOFF_RESERVE,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination(DTRACED_HANDOFF_CANCEL,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination(DTRACED_HANDOFF_MUTATE,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination(DTRACED_HANDOFF_CLAIM,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination(DTRACED_HANDOFF_PROMOTE_IMPORT,
	    ticket, digest) == 0);
	CHECK(hypertrace_handoff_destination(DTRACED_HANDOFF_ACTIVATE_IMPORT,
	    ticket, digest) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	pthread_mutex_lock(&wx.mutex);
	ht_disconnect(&wx);
	pthread_mutex_unlock(&wx.mutex);
	close(handoff_pair[1]);
	CHECK(hypertrace_start_ready((struct vmctx *)1, 0) == -1 &&
	    errno == EINVAL);
	CHECK(hypertrace_init((struct vmctx *)1) == 0);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 2) == 0);
	struct ready_server_fixture ready = { .listener = listener };
	CHECK(pthread_create(&thread, NULL, ready_server, &ready) == 0);
	CHECK(hypertrace_start_ready((struct vmctx *)1, 2000) == 0);
	CHECK(hypertrace_configured());
	dtraced_replay_kill_t *replay = NULL;
	size_t replay_count = 1;
	CHECK(hypertrace_take_replay_kills((struct vmctx *)1,
	    &replay, &replay_count) == 0 && replay != NULL &&
	    replay_count == 1 && replay[0].pid == 123 &&
	    replay[0].vmid == 1 && replay[0].epoch == 77 &&
	    replay[0].source_id[0] == 0xa5);
	free(replay);
	atomic_store(&ready.release, true);
	hypertrace_destroy();
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	CHECK(hypertrace_init((struct vmctx *)1) == 0);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listener >= 0);
	CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(listener, 1) == 0);
	CHECK(pthread_create(&thread, NULL, bad_manifest_server,
	    &listener) == 0);
	CHECK(ht_connect(&rx, (struct vmctx *)1,
	    DTD_SUB_ELFWRITE | DTD_SUB_KILL | DTD_SUB_ADMISSION_ACK |
	    DTD_SUB_REPLAY_MANIFEST) == -1 && errno == EPROTO &&
	    rx.fd == -1 && !atomic_load(&rx.configured));
	CHECK(pthread_join(thread, NULL) == 0);
	close(listener);
	CHECK(unlink(address.sun_path) == 0);
	hypertrace_destroy();
	CHECK(hypertrace_init((struct vmctx *)1) == 0);
	CHECK(hypertrace_start_ready((struct vmctx *)1, 50) == -1 &&
	    errno == ETIMEDOUT);
	CHECK(!hypertrace_configured());
	hypertrace_destroy();
	CHECK(rmdir(directory) == 0);
	puts("PASS: bhyve handshake, lifecycle and source handoff framing");
	return (0);
}
