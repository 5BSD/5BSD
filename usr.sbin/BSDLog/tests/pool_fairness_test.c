/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
int log_daemon_main(void);
#define main log_daemon_main
#include "../logcmp.c"
#undef main

struct producer_state {
	struct shmring *ring;
	unsigned delivered;
	bool refill;
	uint64_t sequence;
};

static void
produce(struct producer_state *producer)
{
	union { struct logcmp_record record; unsigned char bytes[512]; } data;
	struct logcmp_record *record = &data.record;

	memset(&data, 0, sizeof(data));
	record->sequence = ++producer->sequence;
	record->timestamp_ns = 1;
	record->severity = LOGCMP_SEVERITY_INFO;
	record->kind = LOGCMP_KIND_LOG;
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->subsystem_length = 3;
	record->category_length = 4;
	record->message_length = 1;
	memcpy(record + 1, "svctestx", 8);
	ATF_REQUIRE_EQ(0, shmring_write_record(producer->ring, &data,
	    sizeof(*record) + 8));
}

static int
capture_refill(void *arg, const struct logcmp_record *record __unused,
    const char *message __unused, const char *fields __unused)
{
	struct producer_state *producer = arg;

	producer->delivered++;
	if (producer->refill)
		produce(producer);
	return (0);
}

ATF_TC_WITHOUT_HEAD(busy_client_yields);
ATF_TC_BODY(busy_client_yields, tc)
{
	struct worker_state sessions[2];
	struct producer_state producers[2] = { 0 };
	struct shmring_fds producer_fds[2], consumer_fds;
	struct logcmp_attach_request attach = { .generation = 9,
	    .ring_size = 4096, .max_record = 512 };
	struct pool_state pool = { 0 };

	memset(sessions, 0, sizeof(sessions));
	pool.kq = kqueue();
	ATF_REQUIRE(pool.kq >= 0);
	ATF_REQUIRE_EQ(0, pool_change(&pool, LOGCMP_POOL_WORK_IDENT,
	    EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, &pool.work_source));
	for (unsigned i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_RECORD,
		    512, 9, &producer_fds[i], &consumer_fds));
		ATF_REQUIRE_EQ(0, shmring_open(&producers[i].ring,
		    &producer_fds[i], SHMRING_ROLE_PRODUCER));
		logcmp_session_init(&sessions[i].session, 512);
		ATF_REQUIRE_EQ(0, logcmp_session_attach(&sessions[i].session,
		    &attach, &consumer_fds));
		sessions[i].active = true;
		sessions[i].drain_pending = true;
		sessions[i].drain_batch = 1;
		sessions[i].record_sink = capture_refill;
		sessions[i].record_context = &producers[i];
		producers[i].refill = i == 0;
		produce(&producers[i]);
		ATF_REQUIRE_EQ(0, pool_queue_session(&pool, &sessions[i]));
		/* A duplicate wakeup must not insert the session twice. */
		ATF_REQUIRE_EQ(0, pool_queue_session(&pool, &sessions[i]));
	}
	pool_run_pending(&pool);
	ATF_CHECK_EQ(1, producers[1].delivered);
	ATF_CHECK_EQ(LOGCMP_POOL_WORK_BUDGET - 1, producers[0].delivered);
	ATF_CHECK(pool.pending_head == &sessions[0]);
	ATF_CHECK(pool.pending_tail == &sessions[0]);
	ATF_CHECK(sessions[0].pending_next == NULL);
	ATF_CHECK(!sessions[1].pending_queued);
	producers[0].refill = false;
	pool_run_pending(&pool);
	ATF_CHECK(pool.pending_head == NULL);
	ATF_CHECK_EQ(LOGCMP_POOL_WORK_BUDGET, producers[0].delivered);
	for (unsigned i = 0; i < 2; i++) {
		logcmp_session_destroy(&sessions[i].session);
		shmring_close(producers[i].ring);
		shmring_fds_close(&producer_fds[i]);
	}
	close(pool.kq);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, busy_client_yields);
	return (atf_no_error());
}
