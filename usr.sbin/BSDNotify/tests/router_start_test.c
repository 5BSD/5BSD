/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Start of the BSDNotify router (router_main(), pdforked by main()).  The
 * router opens its own system.Audit session before it confines itself, then
 * sends its ready status over its control channel.  As in bsdlog's pool
 * workers (2026-11-12), that lookup could outlive its former 2 s bound while
 * switchboard was still activating BSDAudit, and the router then exited
 * without a status, leaving the provider only the end of the channel.
 * Lookups now wait for switchboard's answer.
 * These cases run the real router_main() in a forked child over a real
 * capability channel, with the Audit lookup and the confinement step
 * replaced, and read the ready status the way main() does.  Plane-on tier:
 * without /dev/mac_capability they skip.
 */
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "freebsd_test_suite/capability_tier.h"

int bsdnotify_main(void);
#define main bsdnotify_main
#define auditcmp_client_open mock_auditcmp_client_open
#define service_worker_enter_capability_mode mock_enter_capability_mode
#include "../bsdnotify.c"
#undef main

static int audit_error;		/* errno of a failing lookup */
static int audit_failures;	/* failing lookups before success; -1 never */
static unsigned audit_delay_ms;	/* time one failing lookup takes */
static unsigned audit_lookup_delay_ms;	/* time a succeeding lookup takes */
static int *audit_calls;	/* lookups made, shared with the parent */
static uint32_t *confine_flags;	/* shared with the parent */

int
mock_auditcmp_client_open(struct auditcmp_client **clientp)
{

	(*audit_calls)++;
	if (audit_failures < 0 || *audit_calls <= audit_failures) {
		if (audit_delay_ms != 0)
			usleep(audit_delay_ms * 1000);
		return (errno = audit_error, -1);
	}
	if (audit_lookup_delay_ms != 0)
		usleep(audit_lookup_delay_ms * 1000);
	*clientp = NULL;
	return (0);
}

int
mock_enter_capability_mode(uint32_t flags)
{

	*confine_flags = flags;
	return (0);
}

static void
require_plane(void)
{
	int fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);

	if (fd < 0)
		capability_plane_skip(errno);
	close(fd);
}

static uint64_t
now_ms(void)
{
	struct timespec ts;

	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts));
	return ((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

/*
 * Run router_main() in a child.  Return 0 and the router's ready status in
 * *statusp, or -1 with errno when no status arrived; then end the router by
 * closing its channel and collect its exit status.
 */
static int
run_router(int32_t *statusp, int *exitp, uint64_t *elapsedp)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct notify_policy_db db;
	struct router_control_reply ready;
	struct service_session *session;
	struct service_reply event;
	uint64_t start;
	int ends[2], error, rc;
	pid_t pid;

	require_plane();
	confine_flags = mmap(NULL, sizeof(*confine_flags),
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	ATF_REQUIRE(confine_flags != MAP_FAILED);
	*confine_flags = 0;
	audit_calls = mmap(NULL, sizeof(*audit_calls),
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	ATF_REQUIRE(audit_calls != MAP_FAILED);
	*audit_calls = 0;
	memset(&db, 0, sizeof(db));
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("{}", &db));
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	start = now_ms();
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		close(ends[0]);
		_exit(router_main(ends[1], &db));
	}
	close(ends[1]);
	ATF_REQUIRE_EQ(0, service_session_create(ends[0], &session));
	memset(&event, 0, sizeof(event));
	event.size = sizeof(event);
	event.data = &ready;
	event.capacity = sizeof(ready);
	/* As main() waits: a router that overruns surfaces as this timeout. */
	options.timeout_ms = NOTIFY_ROUTER_START_TIMEOUT_MS;
	rc = service_session_receive_event(session, &event, &options);
	error = errno;
	*elapsedp = now_ms() - start;
	if (rc == 0) {
		ATF_CHECK_EQ(sizeof(ready), event.length);
		ATF_CHECK_EQ(0, event.nfds);
		*statusp = ready.status;
	}
	service_session_close(session);
	ATF_REQUIRE_EQ(pid, waitpid(pid, exitp, 0));
	errno = error;
	return (rc);
}

ATF_TC(start_error_reaches_provider);
ATF_TC_HEAD(start_error_reaches_provider, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "A router that cannot start reports "
	    "its errno as the ready status, not only the channel's end");
}
ATF_TC_BODY(start_error_reaches_provider, tc)
{
	uint64_t elapsed;
	int32_t status;
	int rc, exitst;

	audit_error = EACCES;
	audit_failures = -1;
	status = 0;
	rc = run_router(&status, &exitst, &elapsed);
	ATF_REQUIRE_MSG(rc == 0, "no ready status: %s", strerror(errno));
	ATF_CHECK_EQ_MSG(EACCES, status, "ready status %d", (int)status);
	ATF_CHECK(WIFEXITED(exitst) && WEXITSTATUS(exitst) == 1);
	/* It stopped at the lookup: confinement was never reached. */
	ATF_CHECK_EQ(0, *confine_flags);
}

ATF_TC(audit_slow_activation_one_lookup);
ATF_TC_HEAD(audit_slow_activation_one_lookup, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
	atf_tc_set_md_var(tc, "descr", "A slow Audit activation is waited out "
	    "by one lookup; the router starts confined with NOFDRECV and the "
	    "rest of its restrictions");
}
ATF_TC_BODY(audit_slow_activation_one_lookup, tc)
{
	uint64_t elapsed;
	int32_t status;
	int rc, exitst;

	/* Half switchboard's bound: any delay below it is the same case. */
	audit_lookup_delay_ms = SERVICE_ACTIVATION_TIMEOUT_MS / 2;
	audit_failures = 0;
	status = -1;
	rc = run_router(&status, &exitst, &elapsed);
	ATF_REQUIRE_MSG(rc == 0, "no ready status: %s", strerror(errno));
	ATF_CHECK_EQ_MSG(0, status, "ready status %d", (int)status);
	ATF_CHECK_EQ(1, *audit_calls);
	ATF_CHECK_EQ((uint32_t)(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_RESTRICT), *confine_flags);
	ATF_CHECK(WIFEXITED(exitst) && WEXITSTATUS(exitst) == 0);
}

ATF_TC(audit_activation_bound_reported);
ATF_TC_HEAD(audit_activation_bound_reported, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
	atf_tc_set_md_var(tc, "descr", "switchboard's ETIMEDOUT at the end of "
	    "its activation bound is the router's answer after one lookup, "
	    "within the provider's own wait");
}
ATF_TC_BODY(audit_activation_bound_reported, tc)
{
	uint64_t elapsed;
	int32_t status;
	int rc, exitst;

	audit_error = ETIMEDOUT;
	audit_failures = -1;
	audit_delay_ms = SERVICE_ACTIVATION_TIMEOUT_MS;
	status = 0;
	rc = run_router(&status, &exitst, &elapsed);
	ATF_REQUIRE_MSG(rc == 0, "no ready status: %s", strerror(errno));
	ATF_CHECK_EQ_MSG(ETIMEDOUT, status, "ready status %d", (int)status);
	ATF_CHECK_EQ(1, *audit_calls);
	ATF_CHECK_MSG(elapsed < NOTIFY_ROUTER_START_TIMEOUT_MS,
	    "router took %ju ms, beyond the provider's wait", (uintmax_t)elapsed);
}

ATF_TC(audit_timeout_not_repeated);
ATF_TC_HEAD(audit_timeout_not_repeated, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "switchboard's ETIMEDOUT is final: "
	    "a lookup answered at once is not repeated");
}
ATF_TC_BODY(audit_timeout_not_repeated, tc)
{
	uint64_t elapsed;
	int32_t status;
	int rc, exitst;

	audit_error = ETIMEDOUT;
	audit_failures = 1;
	audit_delay_ms = 0;
	status = 0;
	rc = run_router(&status, &exitst, &elapsed);
	ATF_REQUIRE_MSG(rc == 0, "no ready status: %s", strerror(errno));
	ATF_CHECK_EQ_MSG(ETIMEDOUT, status, "ready status %d", (int)status);
	ATF_CHECK_EQ(1, *audit_calls);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, start_error_reaches_provider);
	ATF_TP_ADD_TC(tp, audit_slow_activation_one_lookup);
	ATF_TP_ADD_TC(tp, audit_activation_bound_reported);
	ATF_TP_ADD_TC(tp, audit_timeout_not_repeated);
	return (atf_no_error());
}
