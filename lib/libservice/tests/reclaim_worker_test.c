/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>
#include <service_private.h>
#include <switchboard_svc_proto.h>

static int replies[2];
static _Atomic unsigned calls;
static _Atomic bool fail_once;
static _Atomic bool hold_result;

int
service_reclaim_send_result(const struct svc_reclaim_label_msg *m, int status)
{
	int result;

	(void)m;
	result = write(replies[1], &status, sizeof(status)) == sizeof(status) ? 0 : -1;
	while (atomic_load(&hold_result))
		usleep(1000);
	return (result);
}

static int
cleanup(const char *owner, void *context)
{
	(void)owner;
	(void)context;
	atomic_fetch_add(&calls, 1);
	return (atomic_exchange(&fail_once, false) ? EIO : 0);
}

static int
receipt(void)
{
	struct pollfd p = { .fd = replies[0], .events = POLLIN };
	int status;

	ATF_REQUIRE_EQ(1, poll(&p, 1, 10000));
	ATF_REQUIRE_EQ(sizeof(status), read(replies[0], &status, sizeof(status)));
	return (status);
}

static void
init(void)
{
	ATF_REQUIRE_EQ(0, pipe(replies));
	ATF_REQUIRE_EQ(0, service_set_reclaim_handler(cleanup, NULL));
}

static struct svc_reclaim_label_msg
retire(const char *owner, uint8_t generation)
{
	struct svc_reclaim_label_msg m;

	memset(&m, 0, sizeof(m));
	m.op = SVC_OP_RECLAIM_LABEL;
	strlcpy(m.label, "org.test.app/worker", sizeof(m.label));
	strlcpy(m.owner, owner, sizeof(m.owner));
	m.generation[0] = generation;
	return (m);
}

ATF_TC_WITHOUT_HEAD(fences_workers_without_touching_reinstall);
ATF_TC_BODY(fences_workers_without_touching_reinstall, tc)
{
	struct svc_reclaim_label_msg old = retire("install.old", 1);
	struct svc_reclaim_label_msg current = retire("install.new", 2);
	pid_t a, b;

	init();
	ATF_REQUIRE_EQ(0, service_reclaim_admit(old.owner));
	a = service_reclaim_fork(old.owner);
	ATF_REQUIRE(a >= 0);
	if (a == 0) {
		for (;;) pause();
	}
	ATF_REQUIRE_EQ(0, service_reclaim_admit(current.owner));
	b = service_reclaim_fork(current.owner);
	ATF_REQUIRE(b >= 0);
	if (b == 0) {
		for (;;) pause();
	}
	ATF_REQUIRE_EQ(0, service_reclaim_enqueue(&old));
	ATF_CHECK_EQ(0, receipt());
	ATF_CHECK_EQ(1, atomic_load(&calls));
	ATF_CHECK_ERRNO(ESTALE, service_reclaim_fork(old.owner) == -1);
	ATF_CHECK_EQ(0, kill(b, 0));
	for (unsigned n = 0; n < 1000 && service_reclaim_owner_retired(old.owner); n++)
		usleep(1000);
	ATF_CHECK(!service_reclaim_owner_retired(old.owner));
	ATF_REQUIRE_EQ(0, service_reclaim_enqueue(&old));
	ATF_CHECK_EQ(0, receipt());
	ATF_CHECK_EQ(2, atomic_load(&calls));
	ATF_REQUIRE_EQ(0, service_reclaim_enqueue(&current));
	ATF_CHECK_EQ(0, receipt());
	ATF_CHECK_EQ(3, atomic_load(&calls));
}

ATF_TC_WITHOUT_HEAD(failed_cleanup_retries_without_unfencing);
ATF_TC_BODY(failed_cleanup_retries_without_unfencing, tc)
{
	struct svc_reclaim_label_msg old = retire("install.old", 1);

	init();
	atomic_store(&fail_once, true);
	ATF_REQUIRE_EQ(0, service_reclaim_enqueue(&old));
	ATF_CHECK_EQ(EIO, receipt());
	ATF_CHECK_ERRNO(ESTALE, service_reclaim_fork(old.owner) == -1);
	ATF_REQUIRE_EQ(0, service_reclaim_enqueue(&old));
	ATF_CHECK_EQ(0, receipt());
	ATF_CHECK_EQ(2, atomic_load(&calls));
}

static void
retire_during_fork(void)
{
	struct svc_reclaim_label_msg m = retire("install.race", 3);

	ATF_REQUIRE_EQ(0, service_reclaim_enqueue(&m));
	usleep(50000);
	ATF_REQUIRE_EQ(0, atomic_load(&calls));
}

ATF_TC_WITHOUT_HEAD(retirement_waits_for_in_progress_fork);
ATF_TC_BODY(retirement_waits_for_in_progress_fork, tc)
{
	pid_t child;

	init();
	ATF_REQUIRE_EQ(0, pthread_atfork(retire_during_fork, NULL, NULL));
	ATF_REQUIRE_EQ(0, service_reclaim_admit("install.race"));
	child = service_reclaim_fork("install.race");
	ATF_REQUIRE(child >= 0);
	if (child == 0)
		for (;;) pause();
	ATF_CHECK_EQ(0, receipt());
	ATF_CHECK_EQ(1, atomic_load(&calls));
	ATF_CHECK_ERRNO(ESTALE, service_reclaim_fork("install.race") == -1);
}

ATF_TC_WITHOUT_HEAD(provider_death_terminates_owned_workers);
ATF_TC_BODY(provider_death_terminates_owned_workers, tc)
{
	int lifetime[2], ready[2], status, n;
	struct pollfd p;
	pid_t provider, worker;
	char byte;

	ATF_REQUIRE_EQ(0, pipe(lifetime));
	ATF_REQUIRE_EQ(0, pipe(ready));
	provider = fork();
	ATF_REQUIRE(provider >= 0);
	if (provider == 0) {
		close(lifetime[0]);
		close(ready[0]);
		init();
		ATF_REQUIRE_EQ(0, service_reclaim_admit("install.crash"));
		worker = service_reclaim_fork("install.crash");
		ATF_REQUIRE(worker >= 0);
		if (worker == 0) {
			close(ready[1]);
			for (;;) pause();
		}
		ATF_REQUIRE_EQ(sizeof(worker), write(ready[1], &worker, sizeof(worker)));
		_exit(0);
	}
	close(lifetime[1]);
	close(ready[1]);
	ATF_REQUIRE_EQ(sizeof(worker), read(ready[0], &worker, sizeof(worker)));
	ATF_REQUIRE_EQ(provider, waitpid(provider, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	p = (struct pollfd){ .fd = lifetime[0], .events = POLLIN };
	n = poll(&p, 1, 10000);
	if (n != 1)
		(void)kill(worker, SIGKILL);
	ATF_REQUIRE_EQ(1, n);
	ATF_CHECK_EQ(0, read(lifetime[0], &byte, sizeof(byte)));
}

ATF_TC_WITHOUT_HEAD(accepted_session_keeps_fence_until_handoff);
ATF_TC_BODY(accepted_session_keeps_fence_until_handoff, tc)
{
	struct svc_reclaim_label_msg old = retire("install.accepted", 4);
	init();
	atomic_store(&hold_result, true);
	ATF_REQUIRE_EQ(0, service_reclaim_admit(old.owner));
	ATF_REQUIRE_EQ(0, service_reclaim_enqueue(&old));
	ATF_CHECK_EQ(0, receipt());
	ATF_CHECK(service_reclaim_owner_retired(old.owner));
	ATF_CHECK_ERRNO(ESTALE, service_reclaim_admit(old.owner) == -1);
	ATF_CHECK(service_reclaim_owner_retired(old.owner));
	ATF_CHECK_ERRNO(ESTALE, service_reclaim_fork(old.owner) == -1);
	ATF_REQUIRE_EQ(0, service_reclaim_admit("install.replacement"));
	/* Receiving a receipt does not mean the sender has returned. Keep the
	 * send callback busy across handoff, then check eventual collection. */
	ATF_CHECK(service_reclaim_owner_retired(old.owner));
	atomic_store(&hold_result, false);
	for (unsigned attempt = 0; attempt < 1000 &&
	    service_reclaim_owner_retired(old.owner); attempt++)
		usleep(1000);
	ATF_CHECK(!service_reclaim_owner_retired(old.owner));
	ATF_CHECK_ERRNO(ESTALE, service_reclaim_fork(old.owner) == -1);
}

ATF_TC_WITHOUT_HEAD(failed_backlog_is_bounded_and_recovers);
ATF_TC_BODY(failed_backlog_is_bounded_and_recovers, tc)
{
	struct svc_reclaim_label_msg first, next;
	unsigned n;
	init();
	for (n = 0; n < 4096; n++) {
		next = retire("install.pending", 1);
		memcpy(next.generation + 4, &n, sizeof(n));
		snprintf(next.owner, sizeof(next.owner), "install.pending.%u", n);
		if (n == 0)
			first = next;
		atomic_store(&fail_once, true);
		if (service_reclaim_enqueue(&next) == -1) {
			ATF_REQUIRE_EQ(ENOBUFS, errno);
			break;
		}
		ATF_REQUIRE_EQ(EIO, receipt());
	}
	ATF_REQUIRE(n > 0 && n < 4096);
	/* Saturation never blocks a retry already in the work set. A completed
	 * retry frees space for work still retained by the manager's registry. */
	atomic_store(&fail_once, false);
	ATF_REQUIRE_EQ(0, service_reclaim_enqueue(&first));
	ATF_REQUIRE_EQ(0, receipt());
	int result = -1;
	for (unsigned attempt = 0; attempt < 1000 && result == -1; attempt++) {
		result = service_reclaim_enqueue(&next);
		if (result == -1) {
			ATF_REQUIRE_EQ(ENOBUFS, errno);
			usleep(1000);
		}
	}
	ATF_REQUIRE_EQ(0, result);
	ATF_REQUIRE_EQ(0, receipt());
}

ATF_TC_WITHOUT_HEAD(exited_workers_allow_new_sessions);
ATF_TC_BODY(exited_workers_allow_new_sessions, tc)
{
	pid_t child;
	int status;
	init();
	for (unsigned n = 0; n < 64; n++) {
		ATF_REQUIRE_EQ(0, service_reclaim_admit("install.updated"));
		child = service_reclaim_fork("install.updated");
		ATF_REQUIRE_MSG(child >= 0, "fork %u: %s", n, strerror(errno));
		if (child == 0)
			_exit(0);
		ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
		ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
	struct svc_reclaim_label_msg old = retire("install.updated", 7);
	ATF_REQUIRE_EQ(0, service_reclaim_enqueue(&old));
	ATF_CHECK_EQ(0, receipt());
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, exited_workers_allow_new_sessions);
	ATF_TP_ADD_TC(tp, failed_backlog_is_bounded_and_recovers);
	ATF_TP_ADD_TC(tp, accepted_session_keeps_fence_until_handoff);
	ATF_TP_ADD_TC(tp, provider_death_terminates_owned_workers);
	ATF_TP_ADD_TC(tp, retirement_waits_for_in_progress_fork);
	ATF_TP_ADD_TC(tp, fences_workers_without_touching_reinstall);
	ATF_TP_ADD_TC(tp, failed_cleanup_retries_without_unfencing);
	return (atf_no_error());
}
