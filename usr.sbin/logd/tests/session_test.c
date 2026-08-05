/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "session.h"

struct sink {
	unsigned	count;
	char		message[64];
};

static int
capture(void *arg, const struct logcmp_record *record, const char *message,
    const char *fields __unused)
{
	struct sink *sink;

	sink = arg;
	sink->count++;
	memcpy(sink->message, message, record->message_length);
	sink->message[record->message_length] = '\0';
	return (0);
}

static int
reject_sink(void *arg __unused, const struct logcmp_record *record __unused,
    const char *message __unused, const char *fields __unused)
{

	errno = EIO;
	return (-1);
}

static size_t
make_record(void *storage, uint64_t sequence, const char *text)
{
	struct logcmp_record *record;
	size_t length;

	record = storage;
	memset(record, 0, sizeof(*record));
	length = strlen(text);
	record->sequence = sequence;
	record->timestamp_ns = 1;
	record->severity = LOGCMP_SEVERITY_INFO;
	record->kind = LOGCMP_KIND_LOG;
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->subsystem_length = 3;
	record->category_length = 4;
	record->message_length = (uint32_t)length;
	memcpy(record + 1, "svctest", 7);
	memcpy((char *)(record + 1) + 7, text, length);
	return (sizeof(*record) + 7 + length);
}

ATF_TC(attach_and_drain);
ATF_TC_HEAD(attach_and_drain, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a matching record ring drains in order and updates statistics");
}
ATF_TC_BODY(attach_and_drain, tc)
{
	struct shmring_fds producer_fds, consumer_fds;
	struct logcmp_attach_request attach;
	struct logcmp_session session;
	struct shmring *producer;
	struct sink sink;
	uint8_t record[128];
	bool more;
	size_t length;

	memset(&sink, 0, sizeof(sink));
	logcmp_session_init(&session, 512);
	ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_RECORD, 512, 9,
	    &producer_fds, &consumer_fds));
	ATF_REQUIRE_EQ(0, shmring_open(&producer, &producer_fds,
	    SHMRING_ROLE_PRODUCER));
	memset(&attach, 0, sizeof(attach));
	attach.generation = 9;
	attach.ring_size = 4096;
	attach.max_record = 512;
	ATF_REQUIRE_EQ(0, logcmp_session_attach(&session, &attach,
	    &consumer_fds));
	length = make_record(record, 1, "first");
	ATF_REQUIRE_EQ(0, shmring_write_record(producer, record, length));
	length = make_record(record, 2, "second");
	ATF_REQUIRE_EQ(0, shmring_write_record(producer, record, length));
	more = false;
	ATF_REQUIRE_EQ(0, logcmp_session_drain_budget(&session, capture, &sink,
	    1, &more));
	ATF_CHECK(more);
	ATF_CHECK_EQ(1, sink.count);
	ATF_REQUIRE_EQ(0, logcmp_session_drain_budget(&session, capture, &sink,
	    1, &more));
	ATF_CHECK(!more);
	ATF_CHECK_EQ(2, sink.count);
	ATF_CHECK_STREQ("second", sink.message);
	ATF_CHECK_EQ(2, session.stats.accepted);
	ATF_CHECK_EQ(2, session.stats.last_sequence);
	logcmp_session_destroy(&session);
	shmring_close(producer);
	shmring_fds_close(&producer_fds);
	shmring_fds_close(&consumer_fds);
}

ATF_TC(attach_mismatch);
ATF_TC_HEAD(attach_mismatch, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "forged generation, geometry, role, and duplicate attach fail closed");
}
ATF_TC_BODY(attach_mismatch, tc)
{
	struct shmring_fds producer, consumer;
	struct logcmp_attach_request attach;
	struct logcmp_session session;

	logcmp_session_init(&session, 512);
	ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_RECORD, 512, 3,
	    &producer, &consumer));
	memset(&attach, 0, sizeof(attach));
	attach.generation = 4;
	attach.ring_size = 4096;
	attach.max_record = 512;
	ATF_CHECK_EQ(-1, logcmp_session_attach(&session, &attach, &consumer));
	ATF_CHECK_EQ(EPROTO, errno);
	attach.generation = 3;
	attach.ring_size = 8192;
	ATF_CHECK_EQ(-1, logcmp_session_attach(&session, &attach, &consumer));
	ATF_CHECK_EQ(EPROTO, errno);
	attach.ring_size = 4096;
	ATF_REQUIRE_EQ(0, logcmp_session_attach(&session, &attach, &consumer));
	ATF_CHECK_EQ(-1, logcmp_session_attach(&session, &attach, &consumer));
	logcmp_session_destroy(&session);
	shmring_fds_close(&producer);
	shmring_fds_close(&consumer);
}

ATF_TC(sequence_replay);
ATF_TC_HEAD(sequence_replay, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "duplicate and decreasing client sequences terminate ingestion");
}
ATF_TC_BODY(sequence_replay, tc)
{
	struct logcmp_session session;
	struct sink sink;
	uint8_t record[128];
	size_t length;

	memset(&sink, 0, sizeof(sink));
	logcmp_session_init(&session, 512);
	length = make_record(record, 8, "accepted");
	ATF_REQUIRE_EQ(0, logcmp_session_submit(&session, (const void *)record,
	    length, capture, &sink));
	ATF_CHECK_EQ(-1, logcmp_session_submit(&session, (const void *)record,
	    length, capture, &sink));
	ATF_CHECK_EQ(EPROTO, errno);
	ATF_CHECK_EQ(1, session.stats.accepted);
	ATF_CHECK_EQ(1, session.stats.rejected);
	logcmp_session_destroy(&session);
}

ATF_TC(sink_failure);
ATF_TC_HEAD(sink_failure, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "sink failures reject records without advancing accepted sequence");
}
ATF_TC_BODY(sink_failure, tc)
{
	struct logcmp_session session;
	struct sink sink;
	uint8_t record[128];
	size_t length;

	memset(&sink, 0, sizeof(sink));
	logcmp_session_init(&session, 512);
	length = make_record(record, 1, "retry");
	ATF_CHECK_EQ(-1, logcmp_session_submit(&session,
	    (const void *)record, length, reject_sink, NULL));
	ATF_CHECK_EQ(EIO, errno);
	ATF_CHECK_EQ(0, session.stats.accepted);
	ATF_CHECK_EQ(1, session.stats.rejected);
	ATF_CHECK_EQ(0, session.stats.last_sequence);
	ATF_REQUIRE_EQ(0, logcmp_session_submit(&session,
	    (const void *)record, length, capture, &sink));
	ATF_CHECK_EQ(1, session.stats.accepted);
	ATF_CHECK_EQ(1, session.stats.last_sequence);
	logcmp_session_destroy(&session);
}

ATF_TC_WITHOUT_HEAD(filter_and_rate_limit);
ATF_TC_BODY(filter_and_rate_limit, tc)
{
	struct logcmp_session session;
	struct sink sink;
	struct timespec pause = { .tv_nsec = 2000000 };
	uint8_t record[128];
	size_t length;

	memset(&sink, 0, sizeof(sink));
	logcmp_session_init(&session, 512);
	ATF_REQUIRE_EQ(0, logcmp_session_configure(&session,
	    LOGCMP_SEVERITY_ERROR, 0, 0));
	length = make_record(record, 1, "filtered");
	ATF_REQUIRE_EQ(0, logcmp_session_submit(&session,
	    (const void *)record, length, capture, &sink));
	ATF_CHECK_EQ(0, sink.count);
	ATF_CHECK_EQ(1, session.stats.provider_filtered);
	ATF_CHECK_EQ(1, session.stats.last_sequence);
	logcmp_session_destroy(&session);

	memset(&sink, 0, sizeof(sink));
	logcmp_session_init(&session, 512);
	ATF_REQUIRE_EQ(0, logcmp_session_configure(&session,
	    LOGCMP_SEVERITY_TRACE, 1, 2));
	for (uint64_t sequence = 1; sequence <= 3; sequence++) {
		length = make_record(record, sequence, "limited");
		ATF_REQUIRE_EQ(0, logcmp_session_submit(&session,
		    (const void *)record, length, capture, &sink));
	}
	ATF_CHECK_EQ(2, sink.count);
	ATF_CHECK_EQ(1, session.stats.provider_rate_limited);
	ATF_CHECK_EQ(1, session.stats.provider_rate_limited_by_severity[
	    LOGCMP_SEVERITY_INFO - 1]);
	ATF_CHECK_EQ(3, session.stats.last_sequence);
	ATF_REQUIRE_EQ(0, nanosleep(&pause, NULL));
	length = make_record(record, 4, "new-window");
	ATF_REQUIRE_EQ(0, logcmp_session_submit(&session,
	    (const void *)record, length, capture, &sink));
	ATF_CHECK_EQ(3, sink.count);
	logcmp_session_destroy(&session);
}

ATF_TC(detach_and_reattach);
ATF_TC_HEAD(detach_and_reattach, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "DETACH releases a session ring and permits a clean reopen");
}

ATF_TC_WITHOUT_HEAD(arguments_and_limits);
ATF_TC_BODY(arguments_and_limits, tc)
{
	struct logcmp_session session;
	uint8_t record[256];
	size_t length;

	logcmp_session_init(NULL, 0);
	logcmp_session_destroy(NULL);
	logcmp_session_init(&session, 96);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_session_configure(NULL, LOGCMP_SEVERITY_INFO, 0, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_session_configure(&session, 0, 0, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_session_configure(&session, 25, 0, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_session_configure(&session, LOGCMP_SEVERITY_INFO,
	    1, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_session_configure(&session, LOGCMP_SEVERITY_INFO,
	    0, 1) == -1);
	length = make_record(record, 1, "a record that exceeds a small limit");
	ATF_REQUIRE(length > 96);
	ATF_CHECK_ERRNO(EMSGSIZE, logcmp_session_submit(&session,
	    (const void *)record, length, capture, NULL) == -1);
	ATF_CHECK_EQ(1, session.stats.rejected);
	ATF_CHECK_ERRNO(EINVAL, logcmp_session_submit(NULL,
	    (const void *)record, length, capture, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_session_submit(&session,
	    NULL, 0, capture, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_session_submit(&session,
	    (const void *)record, length, NULL, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_session_drain(NULL, capture, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_session_drain(&session, NULL, NULL) == -1);
	ATF_CHECK_ERRNO(ENOTCONN,
	    logcmp_session_drain(&session, capture, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_session_detach(NULL) == -1);
	logcmp_session_destroy(&session);
}

ATF_TC_WITHOUT_HEAD(malformed_ring_record);
ATF_TC_BODY(malformed_ring_record, tc)
{
	struct shmring_fds producer_fds, consumer_fds;
	struct logcmp_attach_request attach;
	struct logcmp_session session;
	struct shmring *producer;
	struct sink sink;
	uint8_t record[128];
	size_t length;

	memset(&sink, 0, sizeof(sink));
	logcmp_session_init(&session, 512);
	ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_RECORD, 512, 21,
	    &producer_fds, &consumer_fds));
	ATF_REQUIRE_EQ(0, shmring_open(&producer, &producer_fds,
	    SHMRING_ROLE_PRODUCER));
	memset(&attach, 0, sizeof(attach));
	attach.generation = 21;
	attach.ring_size = 4096;
	attach.max_record = 512;
	ATF_REQUIRE_EQ(0, logcmp_session_attach(&session, &attach,
	    &consumer_fds));
	length = make_record(record, 1, "bad");
	((struct logcmp_record *)(void *)record)->timestamp_ns = 0;
	ATF_REQUIRE_EQ(0, shmring_write_record(producer, record, length));
	ATF_CHECK_ERRNO(EPROTO,
	    logcmp_session_drain(&session, capture, &sink) == -1);
	ATF_CHECK_EQ(0, session.stats.accepted);
	ATF_CHECK_EQ(1, session.stats.rejected);
	length = make_record(record, 2, "recovered");
	ATF_REQUIRE_EQ(0, shmring_write_record(producer, record, length));
	ATF_REQUIRE_EQ(0, logcmp_session_drain(&session, capture, &sink));
	ATF_CHECK_EQ(1, session.stats.accepted);
	ATF_CHECK_STREQ("recovered", sink.message);
	logcmp_session_destroy(&session);
	shmring_close(producer);
	shmring_fds_close(&producer_fds);
	shmring_fds_close(&consumer_fds);
}

ATF_TC_WITHOUT_HEAD(ring_sink_failure_recovery);
ATF_TC_BODY(ring_sink_failure_recovery, tc)
{
	struct shmring_fds producer_fds, consumer_fds;
	struct logcmp_attach_request attach;
	struct logcmp_session session;
	struct shmring *producer;
	struct sink sink;
	uint8_t record[128];
	size_t length;

	memset(&sink, 0, sizeof(sink));
	logcmp_session_init(&session, 512);
	ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_RECORD, 512, 22,
	    &producer_fds, &consumer_fds));
	ATF_REQUIRE_EQ(0, shmring_open(&producer, &producer_fds,
	    SHMRING_ROLE_PRODUCER));
	memset(&attach, 0, sizeof(attach));
	attach.generation = 22;
	attach.ring_size = 4096;
	attach.max_record = 512;
	ATF_REQUIRE_EQ(0, logcmp_session_attach(&session, &attach,
	    &consumer_fds));
	length = make_record(record, 1, "lost-to-sink");
	ATF_REQUIRE_EQ(0, shmring_write_record(producer, record, length));
	length = make_record(record, 2, "next");
	ATF_REQUIRE_EQ(0, shmring_write_record(producer, record, length));
	ATF_CHECK_ERRNO(EIO,
	    logcmp_session_drain(&session, reject_sink, NULL) == -1);
	ATF_CHECK_EQ(1, session.stats.rejected);
	ATF_REQUIRE_EQ(0, logcmp_session_drain(&session, capture, &sink));
	ATF_CHECK_EQ(1, session.stats.accepted);
	ATF_CHECK_EQ(2, session.stats.last_sequence);
	ATF_CHECK_STREQ("next", sink.message);
	logcmp_session_destroy(&session);
	shmring_close(producer);
	shmring_fds_close(&producer_fds);
	shmring_fds_close(&consumer_fds);
}
ATF_TC_BODY(detach_and_reattach, tc)
{
	struct shmring_fds producer1, consumer1, producer2, consumer2;
	struct logcmp_attach_request attach;
	struct logcmp_session session;

	logcmp_session_init(&session, 512);
	memset(&attach, 0, sizeof(attach));
	attach.ring_size = 4096;
	attach.max_record = 512;
	attach.generation = 11;
	ATF_REQUIRE_EQ(0, shmring_create(attach.ring_size,
	    SHMRING_MODE_RECORD, attach.max_record, attach.generation,
	    &producer1, &consumer1));
	ATF_REQUIRE_EQ(0, logcmp_session_attach(&session, &attach, &consumer1));
	session.stats.last_sequence = 99;
	ATF_REQUIRE_EQ(0, logcmp_session_detach(&session));
	ATF_CHECK_EQ(0, session.stats.last_sequence);
	ATF_CHECK_ERRNO(ENOTCONN, logcmp_session_detach(&session) == -1);

	attach.generation = 12;
	ATF_REQUIRE_EQ(0, shmring_create(attach.ring_size,
	    SHMRING_MODE_RECORD, attach.max_record, attach.generation,
	    &producer2, &consumer2));
	ATF_REQUIRE_EQ(0, logcmp_session_attach(&session, &attach, &consumer2));
	ATF_REQUIRE_EQ(0, logcmp_session_detach(&session));
	logcmp_session_destroy(&session);
	shmring_fds_close(&producer1);
	shmring_fds_close(&consumer1);
	shmring_fds_close(&producer2);
	shmring_fds_close(&consumer2);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, attach_and_drain);
	ATF_TP_ADD_TC(tp, attach_mismatch);
	ATF_TP_ADD_TC(tp, sequence_replay);
	ATF_TP_ADD_TC(tp, sink_failure);
	ATF_TP_ADD_TC(tp, filter_and_rate_limit);
	ATF_TP_ADD_TC(tp, detach_and_reattach);
	ATF_TP_ADD_TC(tp, arguments_and_limits);
	ATF_TP_ADD_TC(tp, malformed_ring_record);
	ATF_TP_ADD_TC(tp, ring_sink_failure_recovery);
	return (atf_no_error());
}
