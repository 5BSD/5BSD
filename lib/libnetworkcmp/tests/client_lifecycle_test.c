/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <networkcmp.h>
#include "fake_service.h"

struct caller { struct networkcmp_client *client; int error; };

static void *
call_hello(void *argument)
{
	struct caller *caller;
	struct networkcmp_hello_reply reply;

	caller = argument;
	if (networkcmp_hello(caller->client, &reply) == -1)
		caller->error = errno;
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(shared_open_close_reopen);
ATF_TC_BODY(shared_open_close_reopen, tc)
{
	struct networkcmp_client *a, *b, *c;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, networkcmp_client_open(&a));
	ATF_REQUIRE_EQ(0, networkcmp_client_open(&b));
	ATF_CHECK_EQ(a, b);
	ATF_CHECK_EQ(1, fake_service_created());
	networkcmp_client_close(a);
	networkcmp_client_close(b);
	ATF_CHECK_EQ(0, fake_service_closed());
	ATF_REQUIRE_EQ(0, networkcmp_client_open(&c));
	ATF_CHECK_EQ(a, c);
	ATF_CHECK_EQ(1, fake_service_created());
	networkcmp_client_close(c);
}

ATF_TC_WITHOUT_HEAD(concurrent_calls);
ATF_TC_BODY(concurrent_calls, tc)
{
	struct networkcmp_client *client;
	struct caller callers[8];
	pthread_t threads[8];
	unsigned i;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, networkcmp_client_open(&client));
	for (i = 0; i < 8; i++) {
		callers[i] = (struct caller){ .client = client };
		ATF_REQUIRE_EQ(0, pthread_create(&threads[i], NULL, call_hello,
		    &callers[i]));
	}
	for (i = 0; i < 8; i++) {
		ATF_REQUIRE_EQ(0, pthread_join(threads[i], NULL));
		ATF_CHECK_EQ(0, callers[i].error);
	}
	ATF_CHECK(fake_service_max_concurrent() > 1);
	networkcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(fork_rejects_inherited_handle);
ATF_TC_BODY(fork_rejects_inherited_handle, tc)
{
	struct networkcmp_client *client;
	struct networkcmp_hello_reply reply;
	int status;
	pid_t pid;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, networkcmp_client_open(&client));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(networkcmp_hello(client, &reply) == -1 && errno == EINVAL ?
		    0 : 1);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	networkcmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(peer_death_is_terminal);
ATF_TC_BODY(peer_death_is_terminal, tc)
{
	struct networkcmp_client *a, *b;
	struct networkcmp_hello_reply reply;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, networkcmp_client_open(&a));
	fake_service_fail(ECONNRESET);
	ATF_CHECK_ERRNO(ECONNRESET, networkcmp_hello(a, &reply) == -1);
	networkcmp_client_close(a);
	ATF_REQUIRE_EQ(0, networkcmp_client_open(&b));
	ATF_CHECK_EQ(a, b);
	ATF_CHECK_ERRNO(ECONNRESET, networkcmp_hello(b, &reply) == -1);
	networkcmp_client_close(b);
}

ATF_TC_WITHOUT_HEAD(malformed_reply_is_terminal);
ATF_TC_BODY(malformed_reply_is_terminal, tc)
{
	struct networkcmp_client *a, *b;
	struct networkcmp_hello_reply reply;
	unsigned calls;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, networkcmp_client_open(&a));
	fake_service_malformed_reply();
	ATF_CHECK_ERRNO(EPROTO, networkcmp_hello(a, &reply) == -1);
	calls = fake_service_calls();
	ATF_CHECK_ERRNO(EPROTO, networkcmp_hello(a, &reply) == -1);
	ATF_CHECK_EQ(calls, fake_service_calls());
	networkcmp_client_close(a);
	ATF_REQUIRE_EQ(0, networkcmp_client_open(&b));
	ATF_CHECK_EQ(a, b);
	ATF_CHECK_ERRNO(EPROTO, networkcmp_hello(b, &reply) == -1);
	ATF_CHECK_EQ(calls, fake_service_calls());
	networkcmp_client_close(b);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, shared_open_close_reopen);
	ATF_TP_ADD_TC(tp, concurrent_calls);
	ATF_TP_ADD_TC(tp, fork_rejects_inherited_handle);
	ATF_TP_ADD_TC(tp, peer_death_is_terminal);
	ATF_TP_ADD_TC(tp, malformed_reply_is_terminal);
	return (atf_no_error());
}
