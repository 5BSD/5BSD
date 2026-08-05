/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <logcmp.h>
#include <logcmp_server.h>
#include <shmring.h>

#include "logcmp_test.h"
#include "logcmp_wakeup.h"

union wire_buffer {
	max_align_t align;
	uint8_t bytes[LOGCMP_MAX_MESSAGE];
};

struct fixture {
	struct service_session *session;
	pid_t child;
};

struct captured_record {
	struct logcmp_record record;
	char message[64];
	char attributes[64];
};

static int
capture_trusted(void *argument, const struct logcmp_record *record,
    const char *message, const char *attributes)
{
	struct captured_record *captured;

	captured = argument;
	captured->record = *record;
	if (record->message_length >= sizeof(captured->message) ||
	    record->attributes_length >= sizeof(captured->attributes))
		return (errno = EOVERFLOW, -1);
	memcpy(captured->message, message, record->message_length);
	captured->message[record->message_length] = '\0';
	memcpy(captured->attributes, attributes, record->attributes_length);
	captured->attributes[record->attributes_length] = '\0';
	return (0);
}

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE_MSG(control >= 0, "open mac_capability: %s",
	    strerror(errno));
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, name, sizeof(connect.name));
	if (ioctl(control, MAC_CAPABILITY_CONNECT, &connect) == -1) {
		error = errno;
		close(control);
		errno = error;
		return (-1);
	}
	close(control);
	return (connect.fd);
}

static void
channel_pair(int *client, int *provider)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_sendmsg_args send;
	uint32_t operation;

	*client = capability_connect("channel");
	ATF_REQUIRE(*client >= 0);
	operation = CHANNEL_OP_CREATE;
	memset(&send, 0, sizeof(send));
	send.payload = &operation;
	send.payload_len = sizeof(operation);
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_SENDMSG, &send));
	memset(&receive, 0, sizeof(receive));
	receive.fds = provider;
	receive.nfds = 1;
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_RECVMSG, &receive));
	ATF_REQUIRE_EQ(1, receive.nfds);
}

static void
fixture_create(struct fixture *fixture, int backend_error)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(logcmp_test_serve(provider, "org.test.log",
		    64U * 1024, backend_error));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
fixture_destroy(struct fixture *fixture, int expected_status)
{
	int status;

	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(expected_status, WEXITSTATUS(status));
}

static int
call(struct fixture *fixture, uint16_t opcode, const void *payload,
    size_t payload_length, const int *fds, size_t nfds,
    union wire_buffer *reply, size_t *reply_length)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	union wire_buffer request;
	struct logcmp_msg *message;

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, logcmp_message_init(message, opcode, 0));
	if (payload_length != 0)
		memcpy(message + 1, payload, payload_length);
	ATF_REQUIRE_EQ(0, logcmp_validate_message(message,
	    sizeof(*message) + payload_length, LOGCMP_MESSAGE_REQUEST));
	outgoing = (struct service_message){
		.size = sizeof(outgoing),
		.data = request.bytes,
		.length = sizeof(*message) + payload_length,
		.fds = fds,
		.nfds = nfds,
	};
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply->bytes;
	incoming.capacity = sizeof(reply->bytes);
	options.timeout_ms = 2000;
	if (service_session_call(fixture->session, &outgoing, &incoming,
	    &options) == -1)
		return (-1);
	*reply_length = incoming.length;
	return (0);
}

static int
reply_status(union wire_buffer *reply, size_t length, uint16_t opcode)
{
	struct logcmp_msg *message;

	message = (void *)reply->bytes;
	ATF_REQUIRE_EQ(0, logcmp_validate_message(message, length,
	    LOGCMP_MESSAGE_REPLY));
	ATF_REQUIRE_EQ(opcode, message->opcode);
	return (-message->status);
}

static size_t
make_record(void *storage, uint64_t sequence, const char *text)
{
	static const char subsystem[] = "tests.provider";
	static const char category[] = "dispatcher";
	struct logcmp_record *record;
	uint8_t *cursor;

	record = storage;
	memset(record, 0, sizeof(*record));
	record->sequence = sequence;
	record->timestamp_ns = sequence;
	record->severity = LOGCMP_SEVERITY_INFO;
	record->kind = LOGCMP_KIND_LOG;
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->subsystem_length = sizeof(subsystem) - 1;
	record->category_length = sizeof(category) - 1;
	record->message_length = strlen(text);
	cursor = (void *)(record + 1);
	memcpy(cursor, subsystem, sizeof(subsystem) - 1);
	cursor += sizeof(subsystem) - 1;
	memcpy(cursor, category, sizeof(category) - 1);
	cursor += sizeof(category) - 1;
	memcpy(cursor, text, record->message_length);
	cursor += record->message_length;
	return (cursor - (uint8_t *)storage);
}

ATF_TC_WITHOUT_HEAD(provider_stamps_trusted_receive_time);
ATF_TC_BODY(provider_stamps_trusted_receive_time, tc)
{
	struct captured_record first, second;
	struct logcmp_record *record;
	uint8_t storage[LOGCMP_MAX_RECORD];
	size_t length;

	memset(&first, 0, sizeof(first));
	memset(&second, 0, sizeof(second));
	length = make_record(storage, 41, "trusted-time");
	record = (void *)storage;
	record->receive_timestamp_ns = 1;
	record->receive_monotonic_ns = 2;
	ATF_REQUIRE(length <= LOGCMP_MAX_RECORD);
	ATF_REQUIRE_EQ(0,
	    logcmp_test_trusted_submit(record, capture_trusted, &first));
	ATF_REQUIRE_EQ(0,
	    logcmp_test_trusted_submit(record, capture_trusted, &second));
	ATF_CHECK_EQ(41, first.record.timestamp_ns);
	ATF_CHECK(first.record.receive_timestamp_ns > 1);
	ATF_CHECK(first.record.receive_monotonic_ns > 2);
	ATF_CHECK(second.record.receive_timestamp_ns >=
	    first.record.receive_timestamp_ns);
	ATF_CHECK(second.record.receive_monotonic_ns >=
	    first.record.receive_monotonic_ns);
	ATF_CHECK_STREQ("trusted-time", first.message);
	ATF_CHECK_STREQ("", first.attributes);
	ATF_CHECK_EQ(1, record->receive_timestamp_ns);
	ATF_CHECK_EQ(2, record->receive_monotonic_ns);
}

static void
attach_ring(struct fixture *fixture, uint64_t generation,
    struct shmring **producerp, int *wake_producer, int *statusp)
{
	struct shmring_fds producer, consumer;
	struct logcmp_attach_request attach;
	union wire_buffer reply;
	int fds[LOGCMP_ATTACH_FD_COUNT], wake[2];
	size_t length;

	memset(&producer, -1, sizeof(producer));
	memset(&consumer, -1, sizeof(consumer));
	ATF_REQUIRE_EQ(0, shmring_create(64U * 1024, SHMRING_MODE_RECORD,
	    LOGCMP_MAX_RECORD, generation, &producer, &consumer));
	ATF_REQUIRE_EQ(0, shmring_open(producerp, &producer,
	    SHMRING_ROLE_PRODUCER));
	ATF_REQUIRE_EQ(0, logcmp_wakeup_create(wake));
	fds[LOGCMP_ATTACH_FD_CONFIG] = consumer.config_fd;
	fds[LOGCMP_ATTACH_FD_DATA] = consumer.data_fd;
	fds[LOGCMP_ATTACH_FD_HEAD] = consumer.head_fd;
	fds[LOGCMP_ATTACH_FD_TAIL] = consumer.tail_fd;
	fds[LOGCMP_ATTACH_FD_WAKE_READ] = wake[LOGCMP_WAKE_CONSUMER];
	attach = (struct logcmp_attach_request){
		.generation = generation,
		.ring_size = 64U * 1024,
		.max_record = LOGCMP_MAX_RECORD,
	};
	ATF_REQUIRE_EQ(0, call(fixture, LOGCMP_OP_ATTACH, &attach,
	    sizeof(attach), fds, nitems(fds), &reply, &length));
	*statusp = reply_status(&reply, length, LOGCMP_OP_ATTACH);
	close(wake[LOGCMP_WAKE_CONSUMER]);
	*wake_producer = wake[LOGCMP_WAKE_PRODUCER];
	shmring_fds_close(&producer);
	shmring_fds_close(&consumer);
}

ATF_TC(provider_dispatch_and_ring_lifecycle);
ATF_TC_HEAD(provider_dispatch_and_ring_lifecycle, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "the real LogCmp dispatcher covers every operation and preserves a valid ring after duplicate attach");
}
ATF_TC_BODY(provider_dispatch_and_ring_lifecycle, tc)
{
	union wire_buffer reply;
	struct logcmp_hello hello;
	struct logcmp_query_request query;
	struct logcmp_stats *stats;
	struct logcmp_msg *message;
	struct shmring *first, *duplicate, *reopened;
	uint8_t record[LOGCMP_MAX_RECORD];
	int first_wake, duplicate_wake, reopened_wake, status;
	size_t length, record_length;

	struct fixture fixture;
	fixture_create(&fixture, 0);
	hello = (struct logcmp_hello){
		.min_version = LOGCMP_ABI_VERSION,
		.max_version = LOGCMP_ABI_VERSION,
		.features = LOGCMP_FEATURE_INLINE,
	};
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_HELLO, &hello,
	    sizeof(hello), NULL, 0, &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, LOGCMP_OP_HELLO));
	record_length = make_record(record, 1, "inline");
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_WRITE, record, record_length,
	    NULL, 0, &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, LOGCMP_OP_WRITE));

	attach_ring(&fixture, 10, &first, &first_wake, &status);
	ATF_REQUIRE_EQ(0, status);
	attach_ring(&fixture, 11, &duplicate, &duplicate_wake, &status);
	ATF_CHECK_EQ(EBUSY, status);
	shmring_close(duplicate);
	close(duplicate_wake);
	record_length = make_record(record, 2, "ring-after-duplicate");
	ATF_REQUIRE_EQ(0, shmring_write_record(first, record, record_length));
	ATF_REQUIRE_EQ(0, logcmp_wakeup_signal(first_wake, true));
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_FLUSH, NULL, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, LOGCMP_OP_FLUSH));
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_STATS, NULL, 0, NULL, 0,
	    &reply, &length));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length, LOGCMP_OP_STATS));
	message = (void *)reply.bytes;
	stats = (void *)(message + 1);
	ATF_CHECK_EQ(2, stats->accepted);

	memset(&query, 0, sizeof(query));
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_QUERY, &query, sizeof(query),
	    NULL, 0, &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, LOGCMP_OP_QUERY));
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_DETACH, NULL, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, LOGCMP_OP_DETACH));
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_FLUSH, NULL, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(ENOTCONN, reply_status(&reply, length, LOGCMP_OP_FLUSH));
	shmring_close(first);
	close(first_wake);
	attach_ring(&fixture, 12, &reopened, &reopened_wake, &status);
	ATF_REQUIRE_EQ(0, status);
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_DETACH, NULL, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, LOGCMP_OP_DETACH));
	shmring_close(reopened);
	close(reopened_wake);
	fixture_destroy(&fixture, 0);
}

ATF_TC(provider_backend_failures);
ATF_TC_HEAD(provider_backend_failures, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "sink, flush, and query backend failures are returned and counted without killing the session");
}
ATF_TC_BODY(provider_backend_failures, tc)
{
	union wire_buffer reply;
	struct logcmp_query_request query;
	struct logcmp_stats *stats;
	struct logcmp_msg *message;
	struct fixture fixture;
	struct shmring *ring;
	uint8_t record[LOGCMP_MAX_RECORD];
	int status, wake;
	size_t length, record_length;

	fixture_create(&fixture, EIO);
	record_length = make_record(record, 1, "rejected");
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_WRITE, record, record_length,
	    NULL, 0, &reply, &length));
	ATF_CHECK_EQ(EIO, reply_status(&reply, length, LOGCMP_OP_WRITE));
	memset(&query, 0, sizeof(query));
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_QUERY, &query, sizeof(query),
	    NULL, 0, &reply, &length));
	ATF_CHECK_EQ(EIO, reply_status(&reply, length, LOGCMP_OP_QUERY));
	attach_ring(&fixture, 20, &ring, &wake, &status);
	ATF_REQUIRE_EQ(0, status);
	record_length = make_record(record, 2, "ring-rejected");
	ATF_REQUIRE_EQ(0, shmring_write_record(ring, record, record_length));
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_FLUSH, NULL, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(EIO, reply_status(&reply, length, LOGCMP_OP_FLUSH));
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_STATS, NULL, 0, NULL, 0,
	    &reply, &length));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length, LOGCMP_OP_STATS));
	message = (void *)reply.bytes;
	stats = (void *)(message + 1);
	ATF_CHECK_EQ(0, stats->accepted);
	ATF_CHECK_EQ(3, stats->rejected);
	shmring_close(ring);
	close(wake);
	fixture_destroy(&fixture, 0);
}

ATF_TC(provider_malformed_descriptor_is_terminal);
ATF_TC_HEAD(provider_malformed_descriptor_is_terminal, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "an unexpected descriptor on a valid request terminates the provider session");
}
ATF_TC_BODY(provider_malformed_descriptor_is_terminal, tc)
{
	union wire_buffer reply;
	struct logcmp_hello hello;
	struct fixture fixture;
	int pipefd[2];
	size_t length;

	fixture_create(&fixture, 0);
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	hello = (struct logcmp_hello){
		.min_version = LOGCMP_ABI_VERSION,
		.max_version = LOGCMP_ABI_VERSION,
	};
	ATF_CHECK(call(&fixture, LOGCMP_OP_HELLO, &hello, sizeof(hello),
	    &pipefd[1], 1, &reply, &length) == -1);
	close(pipefd[0]);
	close(pipefd[1]);
	fixture_destroy(&fixture, 1);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{

	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_test_serve(-1, "org.test", 64U * 1024, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_test_serve(0, "", 64U * 1024, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_test_serve(0, "org.test", 1024, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_test_serve(0, "org.test", 64U * 1024, -1) == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, provider_dispatch_and_ring_lifecycle);
	ATF_TP_ADD_TC(tp, provider_backend_failures);
	ATF_TP_ADD_TC(tp, provider_malformed_descriptor_is_terminal);
	ATF_TP_ADD_TC(tp, provider_stamps_trusted_receive_time);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
