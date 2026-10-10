/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <liboes.h>
#include <libservice.h>
#include <oes_broker_protocol.h>
#include <service_runtime.h>
#include <stdlib.h>
#include <unistd.h>
static int scenario, opened, duplicate_fd, reply_fd, session_closes, calls;
static bool fail_allocation;
static void *
test_calloc(size_t n, size_t size)
{
	if (fail_allocation) {
		errno = ENOMEM;
		return (NULL);
	}
	return (calloc(n, size));
}
#define calloc test_calloc
#include "../liboes.c"
#undef calloc
static int
fresh_fd(void)
{
	int p[2];
	ATF_REQUIRE_EQ(0, pipe(p));
	close(p[1]);
	return (p[0]);
}
static int
fake_open(const char *name, int *fd)
{
	ATF_CHECK_STREQ(OES_BROKER_ENDPOINT, name);
	if (scenario == 1)
		return (errno = EACCES, -1);
	*fd = opened = fresh_fd();
	return (0);
}
static int
fake_create(int fd, struct service_session **s)
{
	if (scenario == 2)
		return (errno = ENOMEM, -1);
	duplicate_fd = dup(fd);
	ATF_REQUIRE(duplicate_fd >= 0);
	*s = (void *)1;
	return (0);
}
static void
fake_close(struct service_session *s)
{
	(void)s;
	session_closes++;
	close(duplicate_fd);
}
static int
fake_call(struct service_session *s, const struct service_message *out,
    struct service_reply *in, const struct service_call_options *options)
{
	struct oes_broker_message *m = in->data;
	(void)s;
	calls++;
	ATF_CHECK_ERRNO(EBADF, fcntl(opened, F_GETFD) == -1);
	ATF_CHECK_EQ(0,
	    oes_broker_validate(out->data, out->length, out->nfds, false));
	ATF_CHECK_EQ(5000, options->timeout_ms);
	if (scenario == 3)
		return (errno = ETIMEDOUT, -1);
	*m = *(const struct oes_broker_message *)out->data;
	in->length = sizeof(*m);
	in->nfds = 0;
	if (scenario == 4) {
		m->status = EPERM;
		return (0);
	}
	*in->fds = reply_fd = fresh_fd();
	in->nfds = 1;
	if (scenario == 5)
		m->reserved = 1;
	if (scenario == 6)
		fail_allocation = true;
	return (0);
}
#define service_open	       fake_open
#define service_session_create fake_create
#define service_session_close  fake_close
#define service_session_call   fake_call
#include "../broker.c"
ATF_TC_WITHOUT_HEAD(cleanup_all_paths);
ATF_TC_BODY(cleanup_all_paths, tc)
{
	const int errors[] = { 0, EACCES, ENOMEM, ETIMEDOUT, EPERM, EPROTO,
		ENOMEM };
	for (scenario = 0; scenario < 7; scenario++) {
		opened = duplicate_fd = reply_fd = -1;
		calls = session_closes = 0;
		fail_allocation = false;
		oes_client_t *client = oes_client_create_brokered();
		if (scenario == 0) {
			ATF_REQUIRE(client != NULL);
			oes_client_destroy(client);
		} else {
			ATF_CHECK(client == NULL);
			ATF_CHECK_EQ(errors[scenario], errno);
		}
		if (opened >= 0)
			ATF_CHECK_ERRNO(EBADF, fcntl(opened, F_GETFD) == -1);
		if (duplicate_fd >= 0)
			ATF_CHECK_ERRNO(EBADF,
			    fcntl(duplicate_fd, F_GETFD) == -1);
		if (reply_fd >= 0)
			ATF_CHECK_ERRNO(EBADF, fcntl(reply_fd, F_GETFD) == -1);
		ATF_CHECK_EQ(scenario == 1 || scenario == 2 ? 0 : 1, session_closes);
		ATF_CHECK_EQ(scenario == 1 || scenario == 2 ? 0 : 1, calls);
	}
}
ATF_TC_WITHOUT_HEAD(preserves_caller_budget);
ATF_TC_BODY(preserves_caller_budget, tc)
{
	scenario = 1;
	ATF_REQUIRE_EQ(0, service_budget_begin(1000));
	ATF_CHECK(oes_client_create_brokered() == NULL);
	ATF_CHECK_ERRNO(EBUSY, service_budget_begin(1000) == -1);
	service_budget_end();
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, cleanup_all_paths);
	ATF_TP_ADD_TC(tp, preserves_caller_budget);
	return (atf_no_error());
}
