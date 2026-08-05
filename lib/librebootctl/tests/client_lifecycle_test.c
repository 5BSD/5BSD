/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <rebootctl.h>
#include "fake_service.h"

struct caller { struct rebootctl_client *client; int error; };

static void *
get_status(void *argument)
{
	struct caller *caller = argument;
	bool pending;
	if (rebootctl_status(caller->client, &pending) == -1 || !pending)
		caller->error = errno != 0 ? errno : EIO;
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(independent_open_close_reopen);
ATF_TC_BODY(independent_open_close_reopen, tc)
{
	struct rebootctl_client *a, *b, *c;
	fake_service_reset();
	ATF_REQUIRE_EQ(0, rebootctl_client_open(&a));
	ATF_REQUIRE_EQ(0, rebootctl_client_open(&b));
	ATF_CHECK(a != b);
	ATF_CHECK_EQ(2, fake_service_created());
	rebootctl_client_close(a);
	rebootctl_client_close(b);
	ATF_CHECK_EQ(2, fake_service_closed());
	ATF_REQUIRE_EQ(0, rebootctl_client_open(&c));
	ATF_CHECK_EQ(3, fake_service_created());
	rebootctl_client_close(c);
	ATF_CHECK_EQ(3, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(concurrent_independent_sessions);
ATF_TC_BODY(concurrent_independent_sessions, tc)
{
	struct rebootctl_client *clients[8];
	struct caller callers[8];
	pthread_t threads[8];
	unsigned i;
	fake_service_reset();
	for (i = 0; i < 8; i++) {
		ATF_REQUIRE_EQ(0, rebootctl_client_open(&clients[i]));
		callers[i] = (struct caller){ .client = clients[i] };
		ATF_REQUIRE_EQ(0, pthread_create(&threads[i], NULL, get_status,
		    &callers[i]));
	}
	for (i = 0; i < 8; i++) {
		ATF_REQUIRE_EQ(0, pthread_join(threads[i], NULL));
		ATF_CHECK_EQ(0, callers[i].error);
		rebootctl_client_close(clients[i]);
	}
	ATF_CHECK(fake_service_max_concurrent() > 1);
}

ATF_TC_WITHOUT_HEAD(concurrent_calls_on_one_session);
ATF_TC_BODY(concurrent_calls_on_one_session, tc)
{
	struct rebootctl_client *client;
	struct caller callers[8];
	pthread_t threads[8];
	unsigned i;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, rebootctl_client_open(&client));
	for (i = 0; i < nitems(callers); i++) {
		callers[i] = (struct caller){ .client = client };
		ATF_REQUIRE_EQ(0, pthread_create(&threads[i], NULL, get_status,
		    &callers[i]));
	}
	for (i = 0; i < nitems(callers); i++) {
		ATF_REQUIRE_EQ(0, pthread_join(threads[i], NULL));
		ATF_CHECK_EQ(0, callers[i].error);
	}
	ATF_CHECK(fake_service_max_concurrent() > 1);
	rebootctl_client_close(client);
}

ATF_TC_WITHOUT_HEAD(fork_rejects_inherited_client);
ATF_TC_BODY(fork_rejects_inherited_client, tc)
{
	struct rebootctl_client *client;
	bool pending;
	int status;
	pid_t pid;
	fake_service_reset();
	ATF_REQUIRE_EQ(0, rebootctl_client_open(&client));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct rebootctl_client *fresh;

		if (rebootctl_status(client, &pending) != -1 || errno != ECHILD)
			_exit(1);
		if (rebootctl_client_open(&fresh) == -1)
			_exit(2);
		rebootctl_client_close(fresh);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	rebootctl_client_close(client);
}

ATF_TC_WITHOUT_HEAD(discovery_transport_and_service_errors);
ATF_TC_BODY(discovery_transport_and_service_errors, tc)
{
	struct rebootctl_client *client;
	bool pending;

	fake_service_reset();
	fake_service_fail_connect_next(ENOENT);
	ATF_CHECK_ERRNO(ENOENT, rebootctl_client_open(&client) == -1);
	ATF_REQUIRE_EQ(0, rebootctl_client_open(&client));
	fake_service_fail_next(ETIMEDOUT);
	ATF_CHECK_ERRNO(ETIMEDOUT,
	    rebootctl_status(client, &pending) == -1);
	ATF_REQUIRE_EQ(0, rebootctl_status(client, &pending));
	fake_service_reply_mode(FAKE_REPLY_STATUS);
	ATF_CHECK_ERRNO(EPERM, rebootctl_status(client, &pending) == -1);
	ATF_REQUIRE_EQ(0, rebootctl_status(client, &pending));
	rebootctl_client_close(client);

	ATF_REQUIRE_EQ(0, rebootctl_client_open(&client));
	fake_service_fail_next(ECONNRESET);
	ATF_CHECK_ERRNO(ECONNRESET,
	    rebootctl_status(client, &pending) == -1);
	ATF_CHECK_ERRNO(ECONNRESET,
	    rebootctl_status(client, &pending) == -1);
	rebootctl_client_close(client);
}

ATF_TC_WITHOUT_HEAD(protocol_errors_fail_closed);
ATF_TC_BODY(protocol_errors_fail_closed, tc)
{
	static const enum fake_reply_mode faults[] = {
		FAKE_REPLY_BAD_OPCODE, FAKE_REPLY_UNEXPECTED_FD,
		FAKE_REPLY_TRUNCATED, FAKE_REPLY_BAD_MAGIC,
		FAKE_REPLY_BAD_VERSION, FAKE_REPLY_BAD_FLAGS,
		FAKE_REPLY_BAD_STATUS, FAKE_REPLY_ERROR_PAYLOAD,
		FAKE_REPLY_BAD_PENDING, FAKE_REPLY_BAD_RESERVED
	};
	struct rebootctl_client *client;
	bool pending;
	unsigned i;

	for (i = 0; i < nitems(faults); i++) {
		fake_service_reset();
		ATF_REQUIRE_EQ(0, rebootctl_client_open(&client));
		fake_service_reply_mode(faults[i]);
		ATF_CHECK_ERRNO(EPROTO,
		    rebootctl_status(client, &pending) == -1);
		ATF_CHECK_ERRNO(EPROTO,
		    rebootctl_status(client, &pending) == -1);
		rebootctl_client_close(client);
	}
}

ATF_TC_WITHOUT_HEAD(default_and_explicit_delays);
ATF_TC_BODY(default_and_explicit_delays, tc)
{
	struct rebootctl_client *client;

	(void)tc;
	fake_service_reset();
	ATF_REQUIRE_EQ(0, rebootctl_client_open(&client));
	ATF_REQUIRE_EQ(0, rebootctl_reboot(client, RB_REROOT));
	ATF_CHECK_EQ(REBOOTCTL_OP_REBOOT, fake_service_last_opcode());
	ATF_CHECK_EQ(RB_REROOT, fake_service_last_howto());
	ATF_CHECK_EQ(REBOOTCTL_DEFAULT_DELAY_MS,
	    fake_service_last_delay_ms());
	ATF_REQUIRE_EQ(0, rebootctl_shutdown(client));
	ATF_CHECK_EQ(REBOOTCTL_OP_SHUTDOWN, fake_service_last_opcode());
	ATF_CHECK_EQ(0, fake_service_last_howto());
	ATF_CHECK_EQ(REBOOTCTL_DEFAULT_DELAY_MS,
	    fake_service_last_delay_ms());
	ATF_REQUIRE_EQ(0, rebootctl_reboot_after(client, RB_HALT, 1234));
	ATF_CHECK_EQ(RB_HALT, fake_service_last_howto());
	ATF_CHECK_EQ(1234, fake_service_last_delay_ms());
	rebootctl_client_close(client);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, independent_open_close_reopen);
	ATF_TP_ADD_TC(tp, concurrent_independent_sessions);
	ATF_TP_ADD_TC(tp, concurrent_calls_on_one_session);
	ATF_TP_ADD_TC(tp, fork_rejects_inherited_client);
	ATF_TP_ADD_TC(tp, discovery_transport_and_service_errors);
	ATF_TP_ADD_TC(tp, protocol_errors_fail_closed);
	ATF_TP_ADD_TC(tp, default_and_explicit_delays);
	return (atf_no_error());
}
