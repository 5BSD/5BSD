/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Start of an ingress pool worker (pool_worker(), forked by start_pool()).
 * The worker opens its own system.Audit session before it confines itself,
 * then reports through the bootstrap socket.  On a loaded guest that lookup
 * outlived its 2 s bound while switchboard was still activating BSDAudit;
 * the worker exited without a status, the parent could only report EOF as
 * EIO, and bsdlog failed its start (2026-11-12).  These cases run the real
 * pool_worker() in a forked child, with the Audit lookup, the storage
 * session and the confinement step replaced, and read the result the way
 * start_pool() does, with service_bootstrap_parent().
 */
#include <atf-c.h>
int pool_start_daemon_main(void);
#define main pool_start_daemon_main
#define auditcmp_client_open mock_auditcmp_client_open
#define service_worker_enter_capability_mode mock_enter_capability_mode
#define logcmp_storage_session_activate mock_storage_session_activate
#define logcmp_storage_flush mock_storage_flush
#include "../logcmp.c"
#undef main

/* Parent wait: longer than any worker deadline exercised below. */
#define	TEST_BOOTSTRAP_TIMEOUT_MS	60000U

static int audit_error;		/* errno of a failing lookup */
static int audit_failures;	/* failing lookups before success; -1 never */
static unsigned audit_delay_ms;	/* time one failing lookup takes */
static int audit_calls;

int
mock_auditcmp_client_open(struct auditcmp_client **clientp)
{

	audit_calls++;
	if (audit_failures < 0 || audit_calls <= audit_failures) {
		if (audit_delay_ms != 0)
			usleep(audit_delay_ms * 1000);
		return (errno = audit_error, -1);
	}
	*clientp = NULL;
	return (0);
}

int
mock_enter_capability_mode(uint32_t flags __unused)
{

	return (0);
}

int
mock_storage_session_activate(struct logcmp_storage_session *session __unused)
{

	return (0);
}

int
mock_storage_flush(struct logcmp_storage_session *session __unused,
    uint32_t timeout_ms __unused)
{

	return (0);
}

/*
 * Run pool_worker() in a child; return service_bootstrap_parent()'s result
 * (errno in *errorp), then end the worker by closing its control socket and
 * collect its exit status.
 */
static int
run_worker(int *errorp, int *statusp, uint64_t *elapsedp)
{
	struct logcmp_storage_session storage;
	struct logcmp_config config;
	_Atomic uint32_t admitted;
	int control[2], store[2], rc;
	uint64_t start;
	pid_t pid;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, control));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, store));
	logcmp_config_default(&config);
	atomic_init(&admitted, 0);
	memset(&storage, 0, sizeof(storage));
	storage.control_fd = store[1];
	storage.producer_fds = (struct shmring_fds){ -1, -1, -1, -1 };
	start = service_monotime_ms();
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		close(control[0]);
		close(store[0]);
		_exit(pool_worker(control[1], &storage, &config, &admitted,
		    1, 0));
	}
	close(control[1]);
	close(store[1]);
	rc = service_bootstrap_parent(control[0], TEST_BOOTSTRAP_TIMEOUT_MS);
	*errorp = rc == -1 ? errno : 0;
	*elapsedp = service_monotime_ms() - start;
	close(control[0]);
	close(store[0]);
	ATF_REQUIRE_EQ(pid, waitpid(pid, statusp, 0));
	return (rc);
}

ATF_TC_WITHOUT_HEAD(start_error_reaches_parent);
ATF_TC_BODY(start_error_reaches_parent, tc)
{
	uint64_t elapsed;
	int error, status;

	audit_error = ENOENT;
	audit_failures = -1;
	ATF_CHECK_EQ(-1, run_worker(&error, &status, &elapsed));
	/* Before the fix the worker exited silently and this was EIO. */
	ATF_CHECK_MSG(error == ENOENT, "bootstrap error %d (%s), want ENOENT",
	    error, strerror(error));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 1);
}

ATF_TC_WITHOUT_HEAD(audit_activation_waited_out);
ATF_TC_BODY(audit_activation_waited_out, tc)
{
	uint64_t elapsed;
	int error, status;

	/* Two lookups time out while BSDAudit is still being activated. */
	audit_error = ETIMEDOUT;
	audit_failures = 2;
	audit_delay_ms = 100;
	ATF_CHECK_MSG(run_worker(&error, &status, &elapsed) == 0,
	    "bootstrap error %d (%s)", error, strerror(error));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "worker status %#x", status);
}

ATF_TC(audit_lookup_deadline);
ATF_TC_HEAD(audit_lookup_deadline, tc)
{
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(audit_lookup_deadline, tc)
{
	uint64_t elapsed;
	int error, status;

	/*
	 * Lookups that keep timing out are repeated only for as long as
	 * switchboard itself lets an activation take (10 s) plus one lookup,
	 * then the worker reports the timeout.
	 */
	audit_error = ETIMEDOUT;
	audit_failures = -1;
	audit_delay_ms = 500;
	ATF_CHECK_EQ(-1, run_worker(&error, &status, &elapsed));
	ATF_CHECK_MSG(error == ETIMEDOUT, "bootstrap error %d (%s)", error,
	    strerror(error));
	ATF_CHECK_MSG(elapsed >= 10000 && elapsed < 30000,
	    "worker gave up after %ju ms", (uintmax_t)elapsed);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, start_error_reaches_parent);
	ATF_TP_ADD_TC(tp, audit_activation_waited_out);
	ATF_TP_ADD_TC(tp, audit_lookup_deadline);
	return (atf_no_error());
}
