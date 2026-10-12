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

#include <fidl/bsd.log.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
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

/*
 * The provider is driven with the generated bsd.log.v1 client bindings;
 * call() keeps the test bodies in historical LOGC records by converting each
 * request to its method and each result back.  Raw fixtures carry
 * hand-built frames on a libservice session instead.
 */
struct fixture {
	struct fidl_bsd_connection *connection;
	struct service_session *session;	/* raw fixtures only */
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
	/*
	 * Plane-on tier only: absent off the plane, and claimed by Capsule on a
	 * live plane unless the image boots with
	 * kern.mac_capability_isolation.enforce=0.  Skip naming the cause.
	 */
	if (control < 0)
		atf_tc_skip("capability plane unavailable: /dev/mac_capability: "
		    "%s", strerror(errno));
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

struct result {
	bool done;
	int error;		/* transport */
	int status;		/* application errno */
	union wire_buffer *out;
	size_t length;		/* reply payload bytes */
};

static void
on_info(void *context, int error, struct bsd_log_v1_ProtocolInfo *value)
{
	struct result *r = context;
	r->done = true;
	r->error = error;
	if (error == 0 && value->wire_version != LOGCMP_WIRE_VERSION)
		r->error = EPROTONOSUPPORT;
}

static void
on_hello(void *context, int error, struct bsd_log_v1_Limits *value)
{
	struct result *r = context;
	struct logcmp_hello_reply *hello = (void *)(r->out->bytes +
	    sizeof(struct logcmp_msg));

	r->done = true;
	r->error = error;
	if (error != 0)
		return;
	hello->features = value->features;
	hello->ring_size = value->ring_size;
	hello->max_record = value->max_record;
	hello->max_text = value->max_text;
	hello->max_fields = value->max_fields;
	hello->minimum_severity = value->minimum_severity;
	r->length = (value->features & LOGCMP_FEATURE_INTEREST) != 0 ?
	    sizeof(*hello) : offsetof(struct logcmp_hello_reply,
	    minimum_severity);
}

static void
on_stats(void *context, int error, struct bsd_log_v1_Stats *value)
{
	struct result *r = context;
	struct logcmp_stats *stats = (void *)(r->out->bytes +
	    sizeof(struct logcmp_msg));

	r->done = true;
	r->error = error;
	if (error != 0)
		return;
	stats->accepted = value->accepted;
	stats->rejected = value->rejected;
	stats->client_dropped = value->client_dropped;
	stats->provider_filtered = value->provider_filtered;
	stats->provider_rate_limited = value->provider_rate_limited;
	stats->last_sequence = value->last_sequence;
	r->length = sizeof(*stats);
}

static void
on_query(void *context, int error, struct bsd_log_v1_Log_Query_Result *value)
{
	struct result *r = context;
	struct logcmp_query_reply *query = (void *)(r->out->bytes +
	    sizeof(struct logcmp_msg));

	r->done = true;
	r->error = error;
	if (error != 0)
		return;
	if (value->tag == bsd_log_v1_Log_Query_Result_err_tag) {
		r->status = (int)value->value.err;
		return;
	}
	query->cursor.generation = value->value.response.generation;
	query->cursor.offset = value->value.response.offset;
	query->result = value->value.response.found;
	query->record_length = (uint32_t)value->value.response.record_size;
	memcpy(query + 1, value->value.response.record,
	    value->value.response.record_size);
	r->length = sizeof(*query) + value->value.response.record_size;
}

#define	ON_EMPTY(name, type)						\
static void								\
name(void *context, int error, struct type *value)			\
{									\
	struct result *r = context;					\
	r->done = true;							\
	r->error = error;						\
	if (error == 0 && value->tag == type##_err_tag)			\
		r->status = (int)value->value.err;			\
}
ON_EMPTY(on_attach, bsd_log_v1_Log_Attach_Result)
ON_EMPTY(on_write, bsd_log_v1_Log_Write_Result)
ON_EMPTY(on_flush, bsd_log_v1_Log_Flush_Result)
ON_EMPTY(on_detach, bsd_log_v1_Log_Detach_Result)

static int
wait_result(struct fixture *fixture, struct result *r)
{
	struct timespec deadline;
	int error;

	ATF_REQUIRE_EQ(0, fidl_bsd_sync_deadline(&deadline, 5000));
	error = fidl_bsd_sync_wait(fixture->connection, &r->done, &deadline);
	if (error == 0)
		error = r->error;
	return (error);
}

static void
fixture_create(struct fixture *fixture, int backend_error)
{
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { 0 };
	uint32_t txid;
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
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(client, FIDL_BSD_CLIENT,
	    &fixture->connection));
	/* As liblogcmp: ATTACH descriptors keep their own inheritance. */
	fidl_bsd_connection_preserve_sent_inheritance(fixture->connection);
	ATF_REQUIRE_EQ(0, bsd_log_v1_Log_GetProtocolInfo(fixture->connection,
	    &empty, on_info, &r, &txid));
	ATF_REQUIRE_EQ(0, wait_result(fixture, &r));
}

/* A fresh provider whose FIDL session has not negotiated. */
static void
fixture_create_unnegotiated(struct fixture *fixture)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(logcmp_test_serve(provider, "org.test.log",
		    64U * 1024, 0));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(client, FIDL_BSD_CLIENT,
	    &fixture->connection));
}

/* A fresh provider behind a raw libservice session. */
static void
fixture_create_raw(struct fixture *fixture)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(logcmp_test_serve(provider, "org.test.log",
		    64U * 1024, 0));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
fixture_destroy(struct fixture *fixture, int expected_status)
{
	int status;

	if (fixture->connection != NULL)
		fidl_bsd_connection_destroy(fixture->connection);
	if (fixture->session != NULL)
		service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(expected_status, WEXITSTATUS(status));
}

/*
 * Send one request record as its bsd.log.v1 method and rebuild the result as
 * the reply record.  -1 when the session failed.
 */
static int
call(struct fixture *fixture, uint16_t opcode, const void *payload,
    size_t payload_length, const int *fds, size_t nfds,
    union wire_buffer *reply, size_t *reply_length)
{
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { .out = reply };
	struct logcmp_msg *message;
	uint32_t txid;
	int error;

	memset(reply, 0, sizeof(*reply));
	switch (opcode) {
	case LOGCMP_OP_HELLO: {
		const struct logcmp_hello *hello = payload;
		struct bsd_log_v1_HelloRequest q = { hello->features };

		ATF_REQUIRE_EQ(0, nfds);
		error = bsd_log_v1_Log_Hello(fixture->connection, &q, on_hello,
		    &r, &txid);
		break;
	}
	case LOGCMP_OP_ATTACH: {
		const struct logcmp_attach_request *a = payload;
		struct bsd_log_v1_AttachRequest q = { a->generation,
		    a->ring_size, a->max_record, fds[0], fds[1], fds[2],
		    fds[3], fds[4] };

		ATF_REQUIRE_EQ(LOGCMP_ATTACH_FD_COUNT, nfds);
		error = bsd_log_v1_Log_Attach(fixture->connection, &q,
		    on_attach, &r, &txid);
		break;
	}
	case LOGCMP_OP_WRITE: {
		struct bsd_log_v1_Record q = {
		    __DECONST(uint8_t *, payload), payload_length };

		error = bsd_log_v1_Log_Write(fixture->connection, &q, on_write,
		    &r, &txid);
		break;
	}
	case LOGCMP_OP_FLUSH:
		error = bsd_log_v1_Log_Flush(fixture->connection, &empty,
		    on_flush, &r, &txid);
		break;
	case LOGCMP_OP_STATS:
		error = bsd_log_v1_Log_GetStats(fixture->connection, &empty,
		    on_stats, &r, &txid);
		break;
	case LOGCMP_OP_DETACH:
		error = bsd_log_v1_Log_Detach(fixture->connection, &empty,
		    on_detach, &r, &txid);
		break;
	case LOGCMP_OP_QUERY: {
		const struct logcmp_query_request *query = payload;
		struct bsd_log_v1_QueryRequest q = {
			.generation = query->cursor.generation,
			.offset = query->cursor.offset,
			.minimum_severity = query->minimum_severity,
			.match_flags = query->match_flags,
			.from_ns = query->from_ns,
			.to_ns = query->to_ns,
			.subsystem = __DECONST(uint8_t *, query->subsystem),
			.subsystem_size = query->subsystem_length,
			.category = __DECONST(uint8_t *, query->category),
			.category_size = query->category_length
		};

		error = bsd_log_v1_Log_Query(fixture->connection, &q, on_query,
		    &r, &txid);
		break;
	}
	default:
		atf_tc_fail("unexpected opcode %u", opcode);
	}
	if (error == 0)
		error = wait_result(fixture, &r);
	if (error != 0)
		return (errno = error, -1);
	message = (void *)reply->bytes;
	message->magic = LOGCMP_MAGIC;
	message->opcode = opcode;
	message->status = -r.status;
	*reply_length = sizeof(*message) + (r.status == 0 ? r.length : 0);
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
		.features = LOGCMP_FEATURE_INLINE,
	};
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_HELLO, &hello,
	    sizeof(hello), NULL, 0, &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, LOGCMP_OP_HELLO));
	record_length = make_record(record, 1, "inline");
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_WRITE, record, record_length,
	    NULL, 0, &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, LOGCMP_OP_WRITE));
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_FLUSH, NULL, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, LOGCMP_OP_FLUSH));

	attach_ring(&fixture, 10, &first, &first_wake, &status);
	ATF_REQUIRE_EQ_MSG(0, status, "attach: %s", strerror(status));
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
	ATF_CHECK_EQ(0, reply_status(&reply, length, LOGCMP_OP_FLUSH));
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

ATF_TC(provider_ring_sink_failure_is_terminal);
ATF_TC_HEAD(provider_ring_sink_failure_is_terminal, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "flush and detach cannot leave a session usable after discarding a ring record");
}
ATF_TC_BODY(provider_ring_sink_failure_is_terminal, tc)
{
	const uint16_t operations[] = { LOGCMP_OP_FLUSH, LOGCMP_OP_DETACH };
	union wire_buffer reply;
	struct fixture fixture;
	struct shmring *ring;
	uint8_t record[LOGCMP_MAX_RECORD];
	size_t length, record_length;
	int status, wake;

	for (size_t i = 0; i < nitems(operations); i++) {
		fixture_create(&fixture, ENOSPC);
		attach_ring(&fixture, 20 + i, &ring, &wake, &status);
		ATF_REQUIRE_EQ(0, status);
		record_length = make_record(record, 1, "cannot-persist");
		ATF_REQUIRE_EQ(0, shmring_write_record(ring, record, record_length));
		/* No wake: the request itself must encounter the sink failure. */
		ATF_REQUIRE_EQ(0, call(&fixture, operations[i], NULL, 0,
		    NULL, 0, &reply, &length));
		ATF_CHECK_EQ(ENOSPC, reply_status(&reply, length, operations[i]));
		ATF_CHECK_EQ(-1, call(&fixture, LOGCMP_OP_FLUSH, NULL, 0,
		    NULL, 0, &reply, &length));
		shmring_close(ring);
		close(wake);
		fixture_destroy(&fixture, 1);
	}
}

ATF_TC(provider_backend_failures);
ATF_TC_HEAD(provider_backend_failures, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "inline rejection and sync/query errors are returned and counted without killing the session");
}
ATF_TC_BODY(provider_backend_failures, tc)
{
	union wire_buffer reply;
	struct logcmp_query_request query;
	struct logcmp_stats *stats;
	struct logcmp_msg *message;
	struct fixture fixture;
	uint8_t record[LOGCMP_MAX_RECORD];
	size_t length, record_length;

	fixture_create(&fixture, EIO);
	record_length = make_record(record, 1, "rejected");
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_WRITE, record, record_length,
	    NULL, 0, &reply, &length));
	ATF_CHECK_EQ(EIO, reply_status(&reply, length, LOGCMP_OP_WRITE));
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_FLUSH, NULL, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(EIO, reply_status(&reply, length, LOGCMP_OP_FLUSH));
	memset(&query, 0, sizeof(query));
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_QUERY, &query, sizeof(query),
	    NULL, 0, &reply, &length));
	ATF_CHECK_EQ(EIO, reply_status(&reply, length, LOGCMP_OP_QUERY));
	ATF_REQUIRE_EQ(0, call(&fixture, LOGCMP_OP_STATS, NULL, 0, NULL, 0,
	    &reply, &length));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length, LOGCMP_OP_STATS));
	message = (void *)reply.bytes;
	stats = (void *)(message + 1);
	ATF_CHECK_EQ(0, stats->accepted);
	ATF_CHECK_EQ(3, stats->rejected);
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
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	/* A GetProtocolInfo frame header: txid, flags {2,0,0}, magic 1. */
	struct {
		uint32_t txid;
		uint8_t flags[3], magic;
		uint64_t ordinal;
	} frame = { 1, { 2, 0, 0 }, 1, 1 };
	struct service_message outgoing = { .size = sizeof(outgoing),
		.data = &frame, .length = sizeof(frame) };
	uint8_t storage[64];
	struct service_reply incoming = { .size = sizeof(incoming),
		.data = storage, .capacity = sizeof(storage) };
	struct fidl_bsd_empty empty = { 0 };
	struct logcmp_msg legacy;
	struct logcmp_hello hello;
	union wire_buffer reply;
	struct fixture fixture;
	struct result r = { .out = &reply };
	int pipefd[2];
	uint32_t txid;

	options.timeout_ms = 2000;
	/* An attached descriptor. */
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	fixture_create_raw(&fixture);
	outgoing.fds = &pipefd[1];
	outgoing.nfds = 1;
	ATF_CHECK_EQ(-1, service_session_call(fixture.session, &outgoing,
	    &incoming, &options));
	fixture_destroy(&fixture, 1);
	close(pipefd[0]);
	close(pipefd[1]);

	/* A pre-FIDL HELLO record. */
	fixture_create_raw(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_message_init(&legacy, LOGCMP_OP_STATS, 0));
	outgoing = (struct service_message){ .size = sizeof(outgoing),
		.data = &legacy, .length = sizeof(legacy) };
	ATF_CHECK_EQ(-1, service_session_call(fixture.session, &outgoing,
	    &incoming, &options));
	fixture_destroy(&fixture, 1);

	/* A method before GetProtocolInfo. */
	fixture_create_unnegotiated(&fixture);
	hello = (struct logcmp_hello){ .features = 0 };
	{
		struct bsd_log_v1_HelloRequest q = { hello.features };

		ATF_REQUIRE_EQ(0, bsd_log_v1_Log_Hello(fixture.connection, &q,
		    on_hello, &r, &txid));
		ATF_CHECK(wait_result(&fixture, &r) != 0);
	}
	(void)empty;
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
	ATF_TP_ADD_TC(tp, provider_ring_sink_failure_is_terminal);
	ATF_TP_ADD_TC(tp, provider_malformed_descriptor_is_terminal);
	ATF_TP_ADD_TC(tp, provider_stamps_trusted_receive_time);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
