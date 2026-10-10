/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>

/* Exercise the real wire handler deterministically at its storage boundary. */
#include "../storage.c"

static bool deliver_record;
static int append_error, sync_error, sync_calls;
ssize_t __wrap_shmring_read_record(struct shmring *, void *, size_t);
int __wrap_shmring_consumer_arm(struct shmring *);
int __wrap_logcmp_store_append(struct logcmp_store *, const char *,
    const struct logcmp_record *, size_t, bool);
int __wrap_logcmp_store_flush(struct logcmp_store *);

ssize_t
__wrap_shmring_read_record(struct shmring *ring, void *buf, size_t capacity)
{
	struct storage_record *envelope = buf;
	struct logcmp_record *record = (void *)envelope->record;

	(void)ring;
	if (!deliver_record)
		return (errno = EAGAIN, -1);
	ATF_REQUIRE(capacity >= sizeof(*envelope));
	deliver_record = false;
	memset(envelope, 0, sizeof(*envelope));
	strlcpy(envelope->label, "test", sizeof(envelope->label));
	envelope->label_length = 4;
	envelope->record_length = sizeof(*record) + 3;
	record->sequence = record->timestamp_ns = 1;
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->kind = LOGCMP_KIND_LOG;
	record->severity = LOGCMP_SEVERITY_INFO;
	record->subsystem_length = 1;
	record->category_length = 1;
	record->message_length = 1;
	memcpy(record + 1, "abc", 3);
	return (offsetof(struct storage_record, record) + envelope->record_length);
}

int
__wrap_shmring_consumer_arm(struct shmring *ring)
{
	(void)ring;
	return (0);
}

int
__wrap_logcmp_store_append(struct logcmp_store *store, const char *label,
    const struct logcmp_record *record, size_t length, bool durable)
{
	(void)store; (void)label; (void)record; (void)length; (void)durable;
	return (append_error ? (errno = append_error, -1) : 0);
}

int
__wrap_logcmp_store_flush(struct logcmp_store *store)
{
	(void)store;
	sync_calls++;
	return (sync_error ? (errno = sync_error, -1) : 0);
}

static int
request(struct storage_session *session, int client, uint16_t operation,
    int expected_error)
{
	union storage_buffer buffer;
	struct storage_query query = { 0 };
	int disposition;

	message_init(&buffer.wire.message, operation, 0,
	    operation == STORAGE_OP_QUERY ? sizeof(query) : 0);
	if (operation == STORAGE_OP_QUERY) {
		query.label_length = 4;
		memcpy(query.label, "test", 4);
		memcpy(buffer.wire.payload, &query, sizeof(query));
	}
	ATF_REQUIRE_EQ(0, send_packet(client, &buffer,
	    sizeof(buffer.wire.message) + buffer.wire.message.length, NULL, 0));
	disposition = handle_session(session, NULL);
	if (expected_error == 0)
		ATF_REQUIRE_EQ(0, receive_status(client, operation, 1000));
	else
		ATF_REQUIRE_ERRNO(expected_error,
		    receive_status(client, operation, 1000) == -1);
	return (disposition);
}

ATF_TC_WITHOUT_HEAD(ingestion_failure_closes_barrier_session);
ATF_TC_BODY(ingestion_failure_closes_barrier_session, tc)
{
	int sockets[2];
	struct storage_session session = { 0 };

	for (int op = STORAGE_OP_FLUSH; op <= STORAGE_OP_QUERY; op++) {
		ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets));
		session.fd = sockets[1];
		strlcpy(session.label, "test", sizeof(session.label));
		deliver_record = true;
		append_error = ENOSPC;
		sync_calls = 0;
		ATF_CHECK_EQ(1, request(&session, sockets[0], op, ENOSPC));
		ATF_CHECK_EQ(0, sync_calls);
		/* Model the manager's close on the handler's terminal result. */
		close(sockets[1]);
		close(sockets[0]);
	}
	/* A separate healthy session is still usable. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets));
	session.fd = sockets[1];
	append_error = 0;
	deliver_record = true;
	ATF_CHECK_EQ(0, request(&session, sockets[0], STORAGE_OP_FLUSH, 0));
	ATF_CHECK_EQ(1, sync_calls);
	/* A sync-only error can be retried without hiding an ingestion loss. */
	sync_error = EIO;
	ATF_CHECK_EQ(0, request(&session, sockets[0], STORAGE_OP_FLUSH, EIO));
	sync_error = 0;
	ATF_CHECK_EQ(0, request(&session, sockets[0], STORAGE_OP_FLUSH, 0));
	close(sockets[1]);
	close(sockets[0]);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, ingestion_failure_closes_barrier_session);
	return (atf_no_error());
}
