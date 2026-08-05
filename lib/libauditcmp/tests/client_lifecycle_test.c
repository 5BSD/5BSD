/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include <auditcmp.h>

#include "fake_service.h"

struct caller {
	struct auditcmp_client *client;
	int error;
};

static void *
submit_record(void *argument)
{
	struct caller *caller;

	caller = argument;
	if (auditcmp_submit(caller->client, "org.test.subject", "create", 0) ==
	    -1)
		caller->error = errno;
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(independent_open_close_reopen);
ATF_TC_BODY(independent_open_close_reopen, tc)
{
	struct auditcmp_client *a, *b, *c;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, auditcmp_client_open(&a));
	ATF_REQUIRE_EQ(0, auditcmp_client_open(&b));
	ATF_CHECK(a != b);
	ATF_CHECK_EQ(2, fake_service_created());
	auditcmp_client_close(a);
	auditcmp_client_close(b);
	ATF_CHECK_EQ(2, fake_service_closed());
	ATF_REQUIRE_EQ(0, auditcmp_client_open(&c));
	auditcmp_client_close(c);
	ATF_CHECK_EQ(3, fake_service_created());
	ATF_CHECK_EQ(3, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(concurrent_independent_sessions);
ATF_TC_BODY(concurrent_independent_sessions, tc)
{
	struct auditcmp_client *clients[8];
	struct caller callers[8];
	pthread_t threads[8];
	unsigned i;

	fake_service_reset();
	for (i = 0; i < nitems(clients); i++) {
		ATF_REQUIRE_EQ(0, auditcmp_client_open(&clients[i]));
		callers[i] = (struct caller){ .client = clients[i] };
		ATF_REQUIRE_EQ(0, pthread_create(&threads[i], NULL, submit_record,
		    &callers[i]));
	}
	for (i = 0; i < nitems(clients); i++) {
		ATF_REQUIRE_EQ(0, pthread_join(threads[i], NULL));
		ATF_CHECK_EQ(0, callers[i].error);
		auditcmp_client_close(clients[i]);
	}
	ATF_CHECK(fake_service_max_concurrent() > 1);
}

ATF_TC_WITHOUT_HEAD(concurrent_calls_on_one_session);
ATF_TC_BODY(concurrent_calls_on_one_session, tc)
{
	struct auditcmp_client *client;
	struct caller callers[8];
	pthread_t threads[8];
	unsigned i;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, auditcmp_client_open(&client));
	for (i = 0; i < nitems(callers); i++) {
		callers[i] = (struct caller){ .client = client };
		ATF_REQUIRE_EQ(0, pthread_create(&threads[i], NULL, submit_record,
		    &callers[i]));
	}
	for (i = 0; i < nitems(callers); i++) {
		ATF_REQUIRE_EQ(0, pthread_join(threads[i], NULL));
		ATF_CHECK_EQ(0, callers[i].error);
	}
	ATF_CHECK(fake_service_max_concurrent() > 1);
	auditcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(fork_rejects_inherited_client);
ATF_TC_BODY(fork_rejects_inherited_client, tc)
{
	struct auditcmp_client *client;
	int status;
	pid_t pid;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, auditcmp_client_open(&client));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
	{
		struct auditcmp_client *fresh;

		if (auditcmp_submit(client, "org.test.subject", "create", 0) !=
		    -1 || errno != ECHILD)
			_exit(1);
		if (auditcmp_client_open(&fresh) == -1)
			_exit(2);
		auditcmp_client_close(fresh);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	auditcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(discovery_transport_and_service_errors);
ATF_TC_BODY(discovery_transport_and_service_errors, tc)
{
	struct auditcmp_client *client;
	struct auditcmp_stats stats;

	fake_service_reset();
	fake_service_fail_connect_next(ENOENT);
	ATF_CHECK_ERRNO(ENOENT, auditcmp_client_open(&client) == -1);
	ATF_REQUIRE_EQ(0, auditcmp_client_open(&client));
	fake_service_fail_next(ETIMEDOUT);
	ATF_CHECK_ERRNO(ETIMEDOUT, auditcmp_stats(client, &stats) == -1);
	ATF_REQUIRE_EQ(0, auditcmp_stats(client, &stats));
	fake_service_reply_mode(FAKE_REPLY_STATUS);
	ATF_CHECK_ERRNO(EPERM, auditcmp_stats(client, &stats) == -1);
	ATF_REQUIRE_EQ(0, auditcmp_stats(client, &stats));
	auditcmp_client_close(client);

	ATF_REQUIRE_EQ(0, auditcmp_client_open(&client));
	fake_service_fail_next(ECONNRESET);
	ATF_CHECK_ERRNO(ECONNRESET,
	    auditcmp_stats(client, &stats) == -1);
	ATF_CHECK_ERRNO(ECONNRESET,
	    auditcmp_stats(client, &stats) == -1);
	auditcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(protocol_errors_fail_closed);
ATF_TC_BODY(protocol_errors_fail_closed, tc)
{
	static const enum fake_reply_mode faults[] = {
		FAKE_REPLY_BAD_OPCODE, FAKE_REPLY_UNEXPECTED_FD,
		FAKE_REPLY_BAD_STATS, FAKE_REPLY_TRUNCATED
	};
	struct auditcmp_client *client;
	struct auditcmp_stats stats;
	unsigned i;

	for (i = 0; i < nitems(faults); i++) {
		fake_service_reset();
		ATF_REQUIRE_EQ(0, auditcmp_client_open(&client));
		fake_service_reply_mode(faults[i]);
		ATF_CHECK_ERRNO(EPROTO, auditcmp_stats(client, &stats) == -1);
		ATF_CHECK_ERRNO(EPROTO, auditcmp_stats(client, &stats) == -1);
		auditcmp_client_close(client);
	}
	fake_service_reset();
	fake_service_reply_mode(FAKE_REPLY_BAD_HELLO);
	ATF_CHECK_ERRNO(EPROTO, auditcmp_client_open(&client) == -1);
	ATF_REQUIRE_EQ(0, auditcmp_client_open(&client));
	auditcmp_client_close(client);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, independent_open_close_reopen);
	ATF_TP_ADD_TC(tp, concurrent_independent_sessions);
	ATF_TP_ADD_TC(tp, concurrent_calls_on_one_session);
	ATF_TP_ADD_TC(tp, fork_rejects_inherited_client);
	ATF_TP_ADD_TC(tp, discovery_transport_and_service_errors);
	ATF_TP_ADD_TC(tp, protocol_errors_fail_closed);
	return (atf_no_error());
}
