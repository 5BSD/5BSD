/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.oes.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
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
/* The scripted bsd.oes.v1 connection: each call completes immediately. */
static int
fake_create(int fd, enum fidl_bsd_role role, struct fidl_bsd_connection **c)
{
	ATF_CHECK_EQ(FIDL_BSD_CLIENT, role);
	if (scenario == 2)
		return (ENOMEM);
	duplicate_fd = dup(fd);
	ATF_REQUIRE(duplicate_fd >= 0);
	close(fd);
	*c = (void *)1;
	return (0);
}
static void
fake_destroy(struct fidl_bsd_connection *c)
{
	(void)c;
	session_closes++;
	close(duplicate_fd);
}
static int
fake_info(struct fidl_bsd_connection *c, struct fidl_bsd_empty *e,
    void (*done)(void *, int, struct bsd_oes_v1_ProtocolInfo *), void *ctx,
    uint32_t *txid)
{
	struct bsd_oes_v1_ProtocolInfo info = { OES_BROKER_VERSION };
	(void)c;
	(void)e;
	*txid = 1;
	ATF_CHECK_ERRNO(EBADF, fcntl(opened, F_GETFD) == -1);
	if (scenario == 7)
		info.wire_version = 2;
	done(ctx, 0, &info);
	return (0);
}
static int
fake_notify(struct fidl_bsd_connection *c, struct fidl_bsd_empty *e,
    void (*done)(void *, int, struct bsd_oes_v1_Broker_OpenNotify_Result *),
    void *ctx, uint32_t *txid)
{
	struct bsd_oes_v1_Broker_OpenNotify_Result r = {
		.tag = bsd_oes_v1_Broker_OpenNotify_Result_response_tag
	};
	(void)c;
	(void)e;
	*txid = 2;
	calls++;
	if (scenario == 3) {
		done(ctx, ETIMEDOUT, NULL);
		return (0);
	}
	if (scenario == 4) {
		r.tag = bsd_oes_v1_Broker_OpenNotify_Result_err_tag;
		r.value.err = EPERM;
	} else if (scenario == 5) {
		r.tag = bsd_oes_v1_Broker_OpenNotify_Result_err_tag;
		r.value.err = 0;	/* an error that is no errno */
	} else {
		r.value.response.client = reply_fd = fresh_fd();
		if (scenario == 6)
			fail_allocation = true;
	}
	done(ctx, 0, &r);
	/* The callback took the descriptor; the bindings close what is left. */
	if (r.tag == bsd_oes_v1_Broker_OpenNotify_Result_response_tag &&
	    r.value.response.client >= 0)
		close(r.value.response.client);
	return (0);
}
static int
fake_wait(struct fidl_bsd_connection *c, const bool *done,
    const struct timespec *deadline)
{
	(void)c;
	(void)deadline;
	ATF_CHECK(*done);
	return (0);
}
#define service_open			fake_open
#define fidl_bsd_connection_create	fake_create
#define fidl_bsd_connection_destroy	fake_destroy
#define bsd_oes_v1_Broker_GetProtocolInfo fake_info
#define bsd_oes_v1_Broker_OpenNotify	fake_notify
#define fidl_bsd_sync_wait		fake_wait
#include "../broker.c"
ATF_TC_WITHOUT_HEAD(cleanup_all_paths);
ATF_TC_BODY(cleanup_all_paths, tc)
{
	const int errors[] = { 0, EACCES, ENOMEM, ETIMEDOUT, EPERM, EPROTO,
		ENOMEM, EPROTONOSUPPORT };
	for (scenario = 0; scenario < 8; scenario++) {
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
		ATF_CHECK_EQ(scenario == 1 || scenario == 2 || scenario == 7 ?
		    0 : 1, calls);
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
