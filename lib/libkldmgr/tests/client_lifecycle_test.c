/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <kldmgr.h>
#include "fake_service.h"

struct caller { struct kldmgr_client *client; int error; };

static void *
load_module(void *argument)
{
	struct caller *caller = argument;
	int id;

	if (kldmgr_load(caller->client, "if_bridge", &id) == -1 || id != 7)
		caller->error = errno != 0 ? errno : EIO;
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(independent_open_close_reopen);
ATF_TC_BODY(independent_open_close_reopen, tc)
{
	struct kldmgr_client *a, *b, *c;
	fake_service_reset();
	ATF_REQUIRE_EQ(0, kldmgr_client_open(&a));
	ATF_REQUIRE_EQ(0, kldmgr_client_open(&b));
	ATF_CHECK(a != b);
	ATF_CHECK_EQ(2, fake_service_created());
	kldmgr_client_close(a);
	kldmgr_client_close(b);
	ATF_CHECK_EQ(2, fake_service_closed());
	ATF_REQUIRE_EQ(0, kldmgr_client_open(&c));
	ATF_CHECK_EQ(3, fake_service_created());
	kldmgr_client_close(c);
	ATF_CHECK_EQ(3, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(concurrent_independent_sessions);
ATF_TC_BODY(concurrent_independent_sessions, tc)
{
	struct kldmgr_client *clients[8];
	struct caller callers[8];
	pthread_t threads[8];
	unsigned i;
	fake_service_reset();
	for (i = 0; i < 8; i++) {
		ATF_REQUIRE_EQ(0, kldmgr_client_open(&clients[i]));
		callers[i] = (struct caller){ .client = clients[i] };
		ATF_REQUIRE_EQ(0, pthread_create(&threads[i], NULL, load_module,
		    &callers[i]));
	}
	for (i = 0; i < 8; i++) {
		ATF_REQUIRE_EQ(0, pthread_join(threads[i], NULL));
		ATF_CHECK_EQ(0, callers[i].error);
		kldmgr_client_close(clients[i]);
	}
	ATF_CHECK(fake_service_max_concurrent() > 1);
}

ATF_TC_WITHOUT_HEAD(concurrent_calls_on_one_session);
ATF_TC_BODY(concurrent_calls_on_one_session, tc)
{
	struct kldmgr_client *client;
	struct caller callers[8];
	pthread_t threads[8];
	unsigned i;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, kldmgr_client_open(&client));
	for (i = 0; i < nitems(callers); i++) {
		callers[i] = (struct caller){ .client = client };
		ATF_REQUIRE_EQ(0, pthread_create(&threads[i], NULL, load_module,
		    &callers[i]));
	}
	for (i = 0; i < nitems(callers); i++) {
		ATF_REQUIRE_EQ(0, pthread_join(threads[i], NULL));
		ATF_CHECK_EQ(0, callers[i].error);
	}
	ATF_CHECK(fake_service_max_concurrent() > 1);
	kldmgr_client_close(client);
}

ATF_TC_WITHOUT_HEAD(module_request_padding_is_zeroed);
ATF_TC_BODY(module_request_padding_is_zeroed, tc)
{
	struct kldmgr_client *client;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, kldmgr_client_open(&client));
	ATF_REQUIRE_EQ(0, kldmgr_load(client, "if_bridge", NULL));
	ATF_CHECK_EQ(0, fake_service_nonzero_name_tail());
	kldmgr_client_close(client);
}

ATF_TC_WITHOUT_HEAD(fork_rejects_inherited_client);
ATF_TC_BODY(fork_rejects_inherited_client, tc)
{
	struct kldmgr_client *client;
	int status;
	pid_t pid;
	fake_service_reset();
	ATF_REQUIRE_EQ(0, kldmgr_client_open(&client));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct kldmgr_client *fresh;

		if (kldmgr_load(client, "if_bridge", NULL) != -1 ||
		    errno != ECHILD)
			_exit(1);
		if (kldmgr_client_open(&fresh) == -1)
			_exit(2);
		kldmgr_client_close(fresh);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	kldmgr_client_close(client);
}

ATF_TC_WITHOUT_HEAD(discovery_transport_and_service_errors);
ATF_TC_BODY(discovery_transport_and_service_errors, tc)
{
	struct kldmgr_client *client;
	struct kldmgr_list_entry entries[2];
	size_t count;
	int id;

	fake_service_reset();
	fake_service_fail_connect_next(ENOENT);
	ATF_CHECK_ERRNO(ENOENT, kldmgr_client_open(&client) == -1);
	ATF_REQUIRE_EQ(0, kldmgr_client_open(&client));
	fake_service_fail_next(ETIMEDOUT);
	ATF_CHECK_ERRNO(ETIMEDOUT,
	    kldmgr_list(client, entries, nitems(entries), &count) == -1);
	ATF_REQUIRE_EQ(0,
	    kldmgr_list(client, entries, nitems(entries), &count));
	fake_service_reply_mode(FAKE_REPLY_STATUS);
	ATF_CHECK_ERRNO(EPERM,
	    kldmgr_list(client, entries, nitems(entries), &count) == -1);
	ATF_REQUIRE_EQ(0,
	    kldmgr_list(client, entries, nitems(entries), &count));
	kldmgr_client_close(client);

	ATF_REQUIRE_EQ(0, kldmgr_client_open(&client));
	fake_service_fail_next(ECONNRESET);
	ATF_CHECK_ERRNO(ECONNRESET,
	    kldmgr_load(client, "if_bridge", &id) == -1);
	ATF_CHECK_ERRNO(ECONNRESET,
	    kldmgr_load(client, "if_bridge", &id) == -1);
	kldmgr_client_close(client);
}

ATF_TC_WITHOUT_HEAD(protocol_errors_fail_closed);
ATF_TC_BODY(protocol_errors_fail_closed, tc)
{
	static const enum fake_reply_mode module_faults[] = {
		FAKE_REPLY_BAD_OPCODE, FAKE_REPLY_UNEXPECTED_FD,
		FAKE_REPLY_TRUNCATED, FAKE_REPLY_BAD_MAGIC,
		FAKE_REPLY_BAD_VERSION, FAKE_REPLY_BAD_FLAGS,
		FAKE_REPLY_BAD_STATUS, FAKE_REPLY_ERROR_PAYLOAD,
		FAKE_REPLY_BAD_ID, FAKE_REPLY_BAD_ID_RESERVED
	};
	static const enum fake_reply_mode list_faults[] = {
		FAKE_REPLY_BAD_LIST_COUNT, FAKE_REPLY_BAD_LIST_RESERVED,
		FAKE_REPLY_BAD_LIST_ID, FAKE_REPLY_BAD_LIST_NAME
	};
	struct kldmgr_client *client;
	struct kldmgr_list_entry entry;
	size_t count;
	unsigned i;

	for (i = 0; i < nitems(module_faults); i++) {
		fake_service_reset();
		ATF_REQUIRE_EQ(0, kldmgr_client_open(&client));
		fake_service_reply_mode(module_faults[i]);
		ATF_CHECK_ERRNO(EPROTO,
		    kldmgr_load(client, "if_bridge", NULL) == -1);
		ATF_CHECK_ERRNO(EPROTO,
		    kldmgr_load(client, "if_bridge", NULL) == -1);
		kldmgr_client_close(client);
	}
	for (i = 0; i < nitems(list_faults); i++) {
		fake_service_reset();
		ATF_REQUIRE_EQ(0, kldmgr_client_open(&client));
		fake_service_reply_mode(list_faults[i]);
		ATF_CHECK_ERRNO(EPROTO,
		    kldmgr_list(client, &entry, 1, &count) == -1);
		ATF_CHECK_ERRNO(EPROTO,
		    kldmgr_list(client, &entry, 1, &count) == -1);
		kldmgr_client_close(client);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, independent_open_close_reopen);
	ATF_TP_ADD_TC(tp, concurrent_independent_sessions);
	ATF_TP_ADD_TC(tp, concurrent_calls_on_one_session);
	ATF_TP_ADD_TC(tp, module_request_padding_is_zeroed);
	ATF_TP_ADD_TC(tp, fork_rejects_inherited_client);
	ATF_TP_ADD_TC(tp, discovery_transport_and_service_errors);
	ATF_TP_ADD_TC(tp, protocol_errors_fail_closed);
	return (atf_no_error());
}
