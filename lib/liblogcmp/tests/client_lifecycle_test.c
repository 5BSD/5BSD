/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <logcmp.h>
#include <logcmp_server.h>
#include <shmring.h>

#include "fake_service.h"

static void *
emit_thread(void *argument)
{
	struct logcmp_emit_options options;

	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "parallel";
	return ((void *)(intptr_t)logcmp_emit(argument, &options));
}

struct burst {
	struct logcmp_logger *logger;
	unsigned count;
	int error;
};

static void *
emit_burst(void *argument)
{
	struct logcmp_emit_options options;
	struct burst *burst;
	unsigned i;

	burst = argument;
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "batched shared-memory record";
	for (i = 0; i < burst->count; i++) {
		if (logcmp_emit(burst->logger, &options) == -1) {
			burst->error = errno;
			break;
		}
	}
	return (NULL);
}

static void *
open_thread(void *argument)
{
	struct logcmp_client **client;

	client = argument;
	return ((void *)(intptr_t)logcmp_client_open(client));
}

static unsigned
open_descriptor_count(void)
{
	unsigned count;
	int fd, limit;

	count = 0;
	limit = getdtablesize();
	for (fd = 0; fd < limit; fd++)
		if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
			count++;
	return (count);
}

static int
emit_text(struct logcmp_logger *logger, const char *message)
{
	struct logcmp_emit_options options;

	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = message;
	return (logcmp_emit(logger, &options));
}

ATF_TC_WITHOUT_HEAD(concurrent_open_is_shared);
ATF_TC_BODY(concurrent_open_is_shared, tc)
{
	struct logcmp_client *clients[2];
	pthread_t threads[2];
	void *result;

	fake_service_reset();
	fake_service_fault_next(FAKE_SERVICE_FAULT_DELAY);
	ATF_REQUIRE_EQ(0, pthread_create(&threads[0], NULL, open_thread,
	    &clients[0]));
	ATF_REQUIRE_EQ(0, pthread_create(&threads[1], NULL, open_thread,
	    &clients[1]));
	ATF_REQUIRE_EQ(0, pthread_join(threads[0], &result));
	ATF_CHECK_EQ(0, (intptr_t)result);
	ATF_REQUIRE_EQ(0, pthread_join(threads[1], &result));
	ATF_CHECK_EQ(0, (intptr_t)result);
	ATF_CHECK_EQ(clients[0], clients[1]);
	ATF_CHECK_EQ(1, fake_service_created());
	logcmp_client_close(clients[0]);
	logcmp_client_close(clients[1]);
	ATF_CHECK_EQ(1, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(shared_client_serializes_rpc);
ATF_TC_BODY(shared_client_serializes_rpc, tc)
{
	struct logcmp_client *first, *second, *third;
	struct logcmp_logger *logger1, *logger2;
	struct logcmp_stats stats;
	pthread_t threads[2];
	void *result;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&first));
	ATF_REQUIRE_EQ(0, logcmp_client_open(&second));
	ATF_CHECK_EQ(first, second);
	ATF_CHECK_EQ(1, fake_service_created());
	ATF_REQUIRE_EQ(0, logcmp_logger_create(first, "test.service",
	    "first", &logger1));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(second, "test.service",
	    "second", &logger2));
	ATF_REQUIRE_EQ(0, pthread_create(&threads[0], NULL, emit_thread,
	    logger1));
	ATF_REQUIRE_EQ(0, pthread_create(&threads[1], NULL, emit_thread,
	    logger2));
	ATF_REQUIRE_EQ(0, pthread_join(threads[0], &result));
	ATF_CHECK_EQ(0, (intptr_t)result);
	ATF_REQUIRE_EQ(0, pthread_join(threads[1], &result));
	ATF_CHECK_EQ(0, (intptr_t)result);
	ATF_CHECK_EQ(2, fake_service_writes());
	ATF_CHECK_EQ(1, fake_service_max_concurrent());
	ATF_REQUIRE_EQ(0, logcmp_stats(first, &stats));
	ATF_CHECK_EQ(2, stats.accepted);
	logcmp_logger_destroy(logger1);
	logcmp_logger_destroy(logger2);
	logcmp_client_close(first);
	ATF_CHECK_EQ(0, fake_service_closed());
	logcmp_client_close(second);
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_REQUIRE_EQ(0, logcmp_client_open(&third));
	ATF_CHECK_EQ(2, fake_service_created());
	logcmp_client_close(third);
	ATF_CHECK_EQ(2, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(logger_retains_client_lifetime);
ATF_TC_BODY(logger_retains_client_lifetime, tc)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client, *reopened;
	struct logcmp_logger *logger;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "lifetime", &logger));
	logcmp_client_close(client);
	ATF_CHECK_EQ(0, fake_service_closed());
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "retained";
	ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	logcmp_logger_destroy(logger);
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_REQUIRE_EQ(0, logcmp_client_open(&reopened));
	ATF_CHECK_EQ(2, fake_service_created());
	logcmp_client_close(reopened);
	ATF_CHECK_EQ(2, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(shared_memory_burst_is_asynchronous_and_batched);
ATF_TC_BODY(shared_memory_burst_is_asynchronous_and_batched, tc)
{
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	struct burst bursts[8];
	pthread_t threads[8];
	unsigned i;

	fake_service_reset();
	fake_service_enable_ring();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "batch", &logger));
	for (i = 0; i < nitems(threads); i++) {
		bursts[i] = (struct burst){ .logger = logger, .count = 32 };
		ATF_REQUIRE_EQ(0, pthread_create(&threads[i], NULL, emit_burst,
		    &bursts[i]));
	}
	for (i = 0; i < nitems(threads); i++) {
		ATF_REQUIRE_EQ(0, pthread_join(threads[i], NULL));
		ATF_CHECK_EQ(0, bursts[i].error);
	}
	/* Compact pressure drains once during promotion, not once per record. */
	ATF_CHECK(fake_service_writes() >= 8);
	ATF_CHECK(fake_service_writes() < 256);
	ATF_CHECK_EQ(2, fake_service_attaches());
	ATF_CHECK_EQ(1, fake_service_detaches());
	ATF_CHECK_EQ(64U * 1024U, fake_service_ring_capacity());
	ATF_CHECK_EQ(SHMRING_SHAPE_BULK_SPSC,
	    fake_service_ring_shape());
	ATF_REQUIRE_EQ(0, logcmp_flush(client));
	ATF_CHECK_EQ(256, fake_service_writes());
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(ring_is_lazy_and_policy_selected);
ATF_TC_BODY(ring_is_lazy_and_policy_selected, tc)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	unsigned i;

	fake_service_reset();
	fake_service_enable_ring();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_CHECK_EQ(0, fake_service_attaches());
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "lazy", &logger));
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "low volume";
	for (i = 0; i < 7; i++)
		ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	ATF_CHECK_EQ(0, fake_service_attaches());
	ATF_CHECK_EQ(7, fake_service_writes());
	ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	ATF_CHECK_EQ(1, fake_service_attaches());
	ATF_CHECK_EQ(16U * 1024U, fake_service_ring_capacity());
	ATF_CHECK_EQ(SHMRING_SHAPE_COMPACT_SPSC,
	    fake_service_ring_shape());
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(final_close_drains_attached_ring);
ATF_TC_BODY(final_close_drains_attached_ring, tc)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	unsigned i;

	fake_service_reset();
	fake_service_enable_ring();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "close", &logger));
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "graceful close";
	for (i = 0; i < 9; i++)
		ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	ATF_CHECK_EQ(8, fake_service_writes());
	logcmp_client_close(client);
	ATF_CHECK_EQ(8, fake_service_writes());
	logcmp_logger_destroy(logger);
	ATF_CHECK_EQ(9, fake_service_writes());
	ATF_CHECK_EQ(1, fake_service_detaches());
	ATF_CHECK_EQ(1, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(failed_lazy_attach_preserves_inline_delivery);
ATF_TC_BODY(failed_lazy_attach_preserves_inline_delivery, tc)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	unsigned i;

	fake_service_reset();
	fake_service_enable_ring();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "fallback", &logger));
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "inline survives ring allocation failure";
	fake_service_fail_attach_with(ENOMEM);
	for (i = 0; i < 8; i++)
		ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	ATF_CHECK_EQ(8, fake_service_writes());
	ATF_CHECK_EQ(0, fake_service_attaches());
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	ATF_CHECK_EQ(9, fake_service_writes());
	ATF_CHECK_EQ(1, fake_service_attaches());
	ATF_CHECK_EQ(2, fake_service_created());
	ATF_CHECK_EQ(SHMRING_SHAPE_COMPACT_SPSC,
	    fake_service_ring_shape());
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(failed_bulk_promotion_recovers_inline);
ATF_TC_BODY(failed_bulk_promotion_recovers_inline, tc)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	char message[2001];
	unsigned i;

	fake_service_reset();
	fake_service_enable_ring();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "promotion", &logger));
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "activate compact";
	for (i = 0; i < 8; i++)
		ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	ATF_REQUIRE_EQ(1, fake_service_attaches());
	memset(message, 'p', sizeof(message) - 1);
	message[sizeof(message) - 1] = '\0';
	options.message = message;
	fake_service_fail_attach_with(ENOMEM);
	for (i = 0; i < 100; i++)
		if (logcmp_emit(logger, &options) == -1)
			break;
	ATF_REQUIRE_MSG(i < 100, "compact ring never requested promotion");
	ATF_REQUIRE_EQ(EAGAIN, errno);
	ATF_CHECK_EQ(1, fake_service_attaches());
	ATF_CHECK_EQ(1, fake_service_detaches());
	ATF_CHECK_EQ(0, fake_service_ring_capacity());
	options.message = "inline recovery";
	for (i = 0; i < 8; i++)
		ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	ATF_CHECK_EQ(2, fake_service_attaches());
	ATF_CHECK_EQ(SHMRING_SHAPE_COMPACT_SPSC,
	    fake_service_ring_shape());
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(promotion_flush_failure_preserves_compact_ring);
ATF_TC_BODY(promotion_flush_failure_preserves_compact_ring, tc)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	char message[2001];
	unsigned i;

	fake_service_reset();
	fake_service_enable_ring();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "flush-failure", &logger));
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "activate compact";
	for (i = 0; i < 8; i++)
		ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	memset(message, 'f', sizeof(message) - 1);
	message[sizeof(message) - 1] = '\0';
	options.message = message;
	fake_service_fail_operation(LOGCMP_OP_FLUSH, EIO);
	for (i = 0; i < 100; i++)
		if (logcmp_emit(logger, &options) == -1)
			break;
	ATF_REQUIRE(i < 100);
	ATF_REQUIRE_EQ(EAGAIN, errno);
	ATF_CHECK_EQ(1, fake_service_attaches());
	ATF_CHECK_EQ(0, fake_service_detaches());
	ATF_CHECK_EQ(0, fake_service_closed());
	ATF_CHECK_EQ(SHMRING_SHAPE_COMPACT_SPSC,
	    fake_service_ring_shape());
	ATF_REQUIRE_EQ(0, logcmp_flush(client));
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(promotion_detach_failure_abandons_session);
ATF_TC_BODY(promotion_detach_failure_abandons_session, tc)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	char message[2001];
	unsigned i;

	fake_service_reset();
	fake_service_enable_ring();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "detach-failure", &logger));
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "activate compact";
	for (i = 0; i < 8; i++)
		ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	memset(message, 'd', sizeof(message) - 1);
	message[sizeof(message) - 1] = '\0';
	options.message = message;
	fake_service_fail_operation(LOGCMP_OP_DETACH, ECONNRESET);
	for (i = 0; i < 100; i++)
		if (logcmp_emit(logger, &options) == -1)
			break;
	ATF_REQUIRE(i < 100);
	ATF_REQUIRE_EQ(EAGAIN, errno);
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_CHECK_EQ(0, fake_service_detaches());
	options.message = "reconnected inline";
	for (i = 0; i < 8; i++)
		ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	ATF_CHECK_EQ(2, fake_service_created());
	ATF_CHECK_EQ(2, fake_service_attaches());
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(repeated_attach_failure_leaks_no_descriptors);
ATF_TC_BODY(repeated_attach_failure_leaks_no_descriptors, tc)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	unsigned baseline, i;

	fake_service_reset();
	fake_service_enable_ring();
	baseline = open_descriptor_count();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "leaks", &logger));
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "force attach failure";
	for (i = 0; i < 100; i++) {
		fake_service_fail_attach_with(ENOMEM);
		ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	}
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
	ATF_CHECK_EQ(baseline, open_descriptor_count());
}

ATF_TC_WITHOUT_HEAD(corrupt_ring_is_terminal_and_reconnects);
ATF_TC_BODY(corrupt_ring_is_terminal_and_reconnects, tc)
{
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	unsigned i;

	(void)tc;
	fake_service_reset();
	fake_service_enable_ring();
	fake_service_corrupt_next_ring();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "org.example.test",
	    "corruption", &logger));
	for (i = 0; i < 8; i++)
		ATF_REQUIRE_EQ(0, emit_text(logger, "inline before attach"));
	ATF_REQUIRE_EQ(1, fake_service_attaches());
	ATF_CHECK_ERRNO(EPROTO,
	    emit_text(logger, "must reject corrupt ring") == -1);
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_REQUIRE_EQ(0, emit_text(logger, "fresh session after corruption"));
	ATF_CHECK_EQ(2, fake_service_created());
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(committed_record_survives_wakeup_failure);
ATF_TC_BODY(committed_record_survives_wakeup_failure, tc)
{
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	unsigned i;

	(void)tc;
	fake_service_reset();
	fake_service_enable_ring();
	fake_service_break_next_wakeup();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "org.example.test",
	    "wakeup", &logger));
	for (i = 0; i < 8; i++)
		ATF_REQUIRE_EQ(0, emit_text(logger, "inline before attach"));
	ATF_REQUIRE_EQ(1, fake_service_attaches());
	ATF_REQUIRE_EQ(0,
	    emit_text(logger, "committed before the broken edge"));
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_REQUIRE_EQ(0, emit_text(logger, "fresh session after broken edge"));
	ATF_CHECK_EQ(2, fake_service_created());
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(promotion_peer_death_abandons_session);
ATF_TC_BODY(promotion_peer_death_abandons_session, tc)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	char message[2001];
	unsigned i;

	(void)tc;
	fake_service_reset();
	fake_service_enable_ring();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "org.example.test",
	    "promotion-death", &logger));
	for (i = 0; i < 8; i++)
		ATF_REQUIRE_EQ(0, emit_text(logger, "inline before attach"));
	memset(message, 'd', sizeof(message) - 1);
	message[sizeof(message) - 1] = '\0';
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = message;
	fake_service_fail_operation(LOGCMP_OP_FLUSH, ECONNRESET);
	for (i = 0; i < 100; i++)
		if (logcmp_emit(logger, &options) == -1)
			break;
	ATF_REQUIRE(i < 100);
	ATF_REQUIRE_EQ(EAGAIN, errno);
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_REQUIRE_EQ(0, emit_text(logger, "fresh session after peer death"));
	ATF_CHECK_EQ(2, fake_service_created());
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(drop_recovery_emits_one_loss_record);
ATF_TC_BODY(drop_recovery_emits_one_loss_record, tc)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	struct logcmp_stats before, after;
	char message[2001];
	unsigned i;

	fake_service_reset();
	fake_service_enable_ring();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "loss", &logger));
	memset(message, 'x', sizeof(message) - 1);
	message[sizeof(message) - 1] = '\0';
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = message;
	for (i = 0; i < 1000; i++)
		if (logcmp_emit(logger, &options) == -1)
			break;
	ATF_REQUIRE_MSG(i < 1000, "test did not saturate the logging ring");
	ATF_REQUIRE_EQ(EAGAIN, errno);
	ATF_REQUIRE_EQ(0, logcmp_stats(client, &before));
	ATF_REQUIRE(before.client_dropped > 0);
	ATF_REQUIRE_EQ(0, logcmp_flush(client));
	options.message = "capacity recovered";
	ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	ATF_REQUIRE_EQ(0, logcmp_flush(client));
	ATF_CHECK_EQ(1, fake_service_loss_records());
	ATF_CHECK_EQ(before.client_dropped, fake_service_last_loss_count());
	ATF_REQUIRE_EQ(0, logcmp_stats(client, &after));
	ATF_CHECK_EQ(before.client_dropped, after.client_dropped);
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(fork_rejects_inherited_objects);
ATF_TC_BODY(fork_rejects_inherited_objects, tc)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	int status;
	pid_t pid;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "fork", &logger));
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "child";
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct logcmp_client *fresh;

		if (logcmp_emit(logger, &options) != -1 || errno != EINVAL)
			_exit(1);
		if (logcmp_client_open(&fresh) == -1)
			_exit(2);
		logcmp_client_close(fresh);
		logcmp_logger_destroy(logger);
		logcmp_client_close(client);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(open_failure_is_retryable);
ATF_TC_BODY(open_failure_is_retryable, tc)
{
	struct logcmp_client *client;

	fake_service_reset();
	fake_service_fault_next(FAKE_SERVICE_FAULT_INVALID_HELLO);
	ATF_CHECK_ERRNO(EPROTO, logcmp_client_open(&client) == -1);
	ATF_CHECK_EQ(1, fake_service_created());
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_CHECK_EQ(2, fake_service_created());
	logcmp_client_close(client);
	ATF_CHECK_EQ(2, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(malformed_replies_invalidate_session);
ATF_TC_BODY(malformed_replies_invalidate_session, tc)
{
	static const enum fake_service_fault protocol_faults[] = {
		FAKE_SERVICE_FAULT_TRUNCATE,
		FAKE_SERVICE_FAULT_WRONG_OPCODE,
		FAKE_SERVICE_FAULT_ATTACHED_FD
	};
	struct logcmp_client *client;
	struct logcmp_stats stats;
	unsigned i;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	for (i = 0; i < nitems(protocol_faults); i++) {
		fake_service_fault_next(protocol_faults[i]);
		ATF_CHECK_ERRNO(EPROTO, logcmp_stats(client, &stats) == -1);
		ATF_CHECK_EQ(i + 1, fake_service_closed());
		ATF_REQUIRE_EQ(0, logcmp_stats(client, &stats));
		ATF_CHECK_EQ(i + 2, fake_service_created());
	}
	fake_service_fault_next(FAKE_SERVICE_FAULT_STATUS);
	ATF_CHECK_ERRNO(EPERM, logcmp_stats(client, &stats) == -1);
	ATF_CHECK_EQ(3, fake_service_closed());
	ATF_REQUIRE_EQ(0, logcmp_stats(client, &stats));
	fake_service_fault_next(FAKE_SERVICE_FAULT_TIMEOUT);
	ATF_CHECK_ERRNO(ETIMEDOUT, logcmp_stats(client, &stats) == -1);
	ATF_CHECK_EQ(3, fake_service_closed());
	ATF_REQUIRE_EQ(0, logcmp_stats(client, &stats));
	logcmp_client_close(client);
	ATF_CHECK_EQ(4, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(peer_death_reconnects_without_replay);
ATF_TC_BODY(peer_death_reconnects_without_replay, tc)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "restart", &logger));
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_ERROR;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "unknown acceptance";
	fake_service_fail_write();
	ATF_CHECK_ERRNO(ECONNRESET, logcmp_emit(logger, &options) == -1);
	ATF_CHECK_EQ(0, fake_service_writes());
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_REQUIRE_EQ(0, logcmp_emit(logger, &options));
	ATF_CHECK_EQ(2, fake_service_created());
	ATF_CHECK_EQ(1, fake_service_writes());
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
	ATF_CHECK_EQ(2, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(per_severity_drop_accounting);
ATF_TC_BODY(per_severity_drop_accounting, tc)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	struct logcmp_stats stats;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "pressure", &logger));
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_ERROR;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = "dropped";
	fake_service_fail_write_with(EAGAIN);
	ATF_CHECK_ERRNO(EAGAIN, logcmp_emit(logger, &options) == -1);
	ATF_REQUIRE_EQ(0, logcmp_stats(client, &stats));
	ATF_CHECK_EQ(1, stats.client_dropped);
	ATF_CHECK_EQ(1, stats.client_dropped_by_severity[
	    LOGCMP_SEVERITY_ERROR - 1]);
	ATF_CHECK_EQ(0, stats.client_dropped_by_severity[
	    LOGCMP_SEVERITY_INFO - 1]);
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(scoped_query_cursor_and_retry);
ATF_TC_BODY(scoped_query_cursor_and_retry, tc)
{
	struct logcmp_client *client;
	struct logcmp_query_cursor cursor, original;
	uint8_t record[LOGCMP_MAX_RECORD];
	size_t length;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	memset(&cursor, 0, sizeof(cursor));
	original = cursor;
	ATF_CHECK_ERRNO(EMSGSIZE, logcmp_query_next(client, 0, &cursor,
	    record, sizeof(struct logcmp_record), &length) == -1);
	ATF_CHECK_EQ(original.generation, cursor.generation);
	ATF_CHECK_EQ(original.offset, cursor.offset);
	ATF_REQUIRE_EQ(1, logcmp_query_next(client, LOGCMP_SEVERITY_INFO,
	    &cursor, record, sizeof(record), &length));
	ATF_CHECK_EQ(77,
	    ((struct logcmp_record *)(void *)record)->sequence);
	ATF_CHECK_EQ(0, logcmp_validate_record((const void *)record, length));
	ATF_CHECK_EQ(1, cursor.generation);
	ATF_CHECK_EQ(128, cursor.offset);
	ATF_CHECK_EQ(0, logcmp_query_next(client, 0, &cursor, record,
	    sizeof(record), &length));
	ATF_CHECK_EQ(0, length);
	ATF_CHECK_EQ(256, cursor.offset);
	ATF_CHECK_ERRNO(EINVAL, logcmp_query_next(client, 25, &cursor,
	    record, sizeof(record), &length) == -1);
	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(query_ex_validates_and_passes_filters);
ATF_TC_BODY(query_ex_validates_and_passes_filters, tc)
{
	struct logcmp_client *client;
	struct logcmp_query_options options;
	struct logcmp_query_cursor cursor;
	uint8_t record[LOGCMP_MAX_RECORD];
	char oversized[LOGCMP_MAX_SUBSYSTEM + 2];
	size_t length;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));

	/* A fully specified filter still round-trips a valid request. */
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.minimum_severity = LOGCMP_SEVERITY_INFO;
	options.match_flags = LOGCMP_QUERY_MATCH_SUBSYSTEM_EXACT;
	options.from_ns = 1;
	options.to_ns = 100;
	options.subsystem = "tests.fake";
	options.category = "query";
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, logcmp_query_ex(client, &options, &cursor, record,
	    sizeof(record), &length));
	ATF_CHECK_EQ(77, ((struct logcmp_record *)(void *)record)->sequence);
	ATF_CHECK_EQ(0, logcmp_validate_record((const void *)record, length));

	/* An all-zero options (bar size) reproduces logcmp_query_next. */
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, logcmp_query_ex(client, &options, &cursor, record,
	    sizeof(record), &length));
	ATF_CHECK_EQ(77, ((struct logcmp_record *)(void *)record)->sequence);

	/* Bad options are rejected locally with EINVAL. */
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options) + 1;
	memset(&cursor, 0, sizeof(cursor));
	ATF_CHECK_ERRNO(EINVAL, logcmp_query_ex(client, &options, &cursor,
	    record, sizeof(record), &length) == -1);
	options.size = sizeof(options);
	options.match_flags = 0x80000000U;
	ATF_CHECK_ERRNO(EINVAL, logcmp_query_ex(client, &options, &cursor,
	    record, sizeof(record), &length) == -1);
	options.match_flags = 0;
	options.from_ns = 100;
	options.to_ns = 10;
	ATF_CHECK_ERRNO(EINVAL, logcmp_query_ex(client, &options, &cursor,
	    record, sizeof(record), &length) == -1);
	options.from_ns = 0;
	options.to_ns = 0;
	memset(oversized, 'a', sizeof(oversized) - 1);
	oversized[sizeof(oversized) - 1] = '\0';
	options.subsystem = oversized;
	ATF_CHECK_ERRNO(EINVAL, logcmp_query_ex(client, &options, &cursor,
	    record, sizeof(record), &length) == -1);

	logcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(emit_rejects_redaction_expansion);
ATF_TC_BODY(emit_rejects_redaction_expansion, tc)
{
	struct logcmp_attribute attributes[LOGCMP_MAX_ATTRIBUTES];
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	char keys[LOGCMP_MAX_ATTRIBUTES][55], message[1701];
	size_t i;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, logcmp_client_open(&client));
	ATF_REQUIRE_EQ(0, logcmp_logger_create(client, "test.service",
	    "privacy", &logger));
	memset(message, 'm', sizeof(message) - 1);
	message[sizeof(message) - 1] = '\0';
	memset(attributes, 0, sizeof(attributes));
	for (i = 0; i < LOGCMP_MAX_ATTRIBUTES; i++) {
		memset(keys[i], 'a', sizeof(keys[i]) - 1);
		keys[i][sizeof(keys[i]) - 3] = 'A' + i / 10;
		keys[i][sizeof(keys[i]) - 2] = '0' + i % 10;
		keys[i][sizeof(keys[i]) - 1] = '\0';
		attributes[i].size = sizeof(attributes[i]);
		attributes[i].key = keys[i];
		attributes[i].type = LOGCMP_ATTR_STRING;
		attributes[i].privacy = LOGCMP_PRIVACY_PRIVATE_HASH;
		attributes[i].value = "x";
		attributes[i].value_length = 1;
	}
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = LOGCMP_SEVERITY_INFO;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = message;
	options.attributes = attributes;
	options.nattributes = LOGCMP_MAX_ATTRIBUTES;
	ATF_CHECK_ERRNO(EMSGSIZE, logcmp_emit(logger, &options) == -1);
	ATF_CHECK_EQ(0, fake_service_writes());
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, shared_client_serializes_rpc);
	ATF_TP_ADD_TC(tp, logger_retains_client_lifetime);
	ATF_TP_ADD_TC(tp, shared_memory_burst_is_asynchronous_and_batched);
	ATF_TP_ADD_TC(tp, ring_is_lazy_and_policy_selected);
	ATF_TP_ADD_TC(tp, final_close_drains_attached_ring);
	ATF_TP_ADD_TC(tp, failed_lazy_attach_preserves_inline_delivery);
	ATF_TP_ADD_TC(tp, failed_bulk_promotion_recovers_inline);
	ATF_TP_ADD_TC(tp, promotion_flush_failure_preserves_compact_ring);
	ATF_TP_ADD_TC(tp, promotion_detach_failure_abandons_session);
	ATF_TP_ADD_TC(tp, repeated_attach_failure_leaks_no_descriptors);
	ATF_TP_ADD_TC(tp, corrupt_ring_is_terminal_and_reconnects);
	ATF_TP_ADD_TC(tp, committed_record_survives_wakeup_failure);
	ATF_TP_ADD_TC(tp, promotion_peer_death_abandons_session);
	ATF_TP_ADD_TC(tp, drop_recovery_emits_one_loss_record);
	ATF_TP_ADD_TC(tp, concurrent_open_is_shared);
	ATF_TP_ADD_TC(tp, fork_rejects_inherited_objects);
	ATF_TP_ADD_TC(tp, open_failure_is_retryable);
	ATF_TP_ADD_TC(tp, malformed_replies_invalidate_session);
	ATF_TP_ADD_TC(tp, peer_death_reconnects_without_replay);
	ATF_TP_ADD_TC(tp, per_severity_drop_accounting);
	ATF_TP_ADD_TC(tp, scoped_query_cursor_and_retry);
	ATF_TP_ADD_TC(tp, query_ex_validates_and_passes_filters);
	ATF_TP_ADD_TC(tp, emit_rejects_redaction_expansion);
	return (atf_no_error());
}
