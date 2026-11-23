/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * How session calls wait (service_runtime(3)): one thread at a time sleeps
 * in the kernel for the session's next message, the others sleep until
 * their reply comes or they take that role over, every wait has one
 * deadline, and a signal behaves as for a slow system call in the thread
 * sleeping in the kernel.  The session's other end is a mock provider driven
 * with raw channel calls.  Where the claim is "no time slices", the case
 * watches the waiting threads' sleeps with dtrace(1)'s sched:::sleep probe
 * (the providers are preloaded: the plane refuses a late kldload).  No case
 * orders its steps by time: a step that needs a thread asleep waits for that
 * thread's sleep event.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/thr.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <channel.h>

#include "libservice.h"
#include "sleep_watch.h"

/* ---- the mock provider ------------------------------------------------ */

static void
session_pair_dup(struct service_session **sessionp, int *providerp,
    int *clientdupp)
{
	int pair[2];

	if (mac_capability_channel_create(pair) == -1)
		atf_tc_skip("mac_capability channels unavailable: %s",
		    strerror(errno));
	if (clientdupp != NULL)
		ATF_REQUIRE((*clientdupp = dup(pair[0])) >= 0);
	ATF_REQUIRE_EQ(0, service_session_create(pair[0], sessionp));
	*providerp = pair[1];
}

static void
session_pair(struct service_session **sessionp, int *providerp)
{

	session_pair_dup(sessionp, providerp, NULL);
}

/*
 * Fill the session's channel toward the provider (which never reads) until
 * the kernel says EAGAIN, through a duplicate of the session's descriptor.
 */
static void
fill_queue(int clientdup)
{
	struct mac_capability_sendmsg_args send;
	char byte = 0;
	int n;

	for (n = 0;; n++) {
		memset(&send, 0, sizeof(send));
		send.payload = &byte;
		send.payload_len = sizeof(byte);
		if (ioctl(clientdup, MAC_CAPABILITY_SENDMSG, &send) == -1)
			break;
	}
	ATF_REQUIRE_EQ_MSG(EAGAIN, errno, "filling: %s", strerror(errno));
	ATF_REQUIRE(n > 0);
}

static uint64_t
now_ms(void)
{
	struct timespec ts;

	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts));
	return ((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

/* Receive one request: its first byte and its reply token. */
static char
provider_receive(int provider, uint64_t *tokenp)
{
	struct mac_capability_recvmsg_args recv;
	char byte;

	memset(&recv, 0, sizeof(recv));
	recv.payload = &byte;
	recv.payload_len = sizeof(byte);
	recv.flags = MAC_CAPABILITY_RECV_F_WAIT;
	recv._reserved[0] = MAC_CAPABILITY_RECV_WAIT_FOREVER;
	ATF_REQUIRE_MSG(ioctl(provider, MAC_CAPABILITY_RECVMSG, &recv) == 0,
	    "provider receive: %s", strerror(errno));
	*tokenp = recv.reply_token;
	return (byte);
}

static void
provider_reply(int provider, uint64_t token, char byte)
{
	struct mac_capability_sendmsg_args send;

	memset(&send, 0, sizeof(send));
	send.payload = &byte;
	send.payload_len = sizeof(byte);
	send.reply_token = token;
	ATF_REQUIRE_MSG(ioctl(provider, MAC_CAPABILITY_SENDMSG, &send) == 0,
	    "provider reply: %s", strerror(errno));
}

/* One call: request `byte`, the reply byte in *replyp; 0 or errno. */
static int
session_call(struct service_session *session, char byte, uint32_t timeout_ms,
    char *replyp)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message message;
	struct service_reply reply;

	memset(&message, 0, sizeof(message));
	message.size = sizeof(message);
	message.data = &byte;
	message.length = sizeof(byte);
	memset(&reply, 0, sizeof(reply));
	reply.size = sizeof(reply);
	reply.data = replyp;
	reply.capacity = 1;
	options.timeout_ms = timeout_ms;
	return (service_session_call(session, &message, &reply, &options) ==
	    -1 ? errno : 0);
}

/* ---- counting sleeps -------------------------------------------------- */

/*
 * Count every sleep of this process's threads, by thread and wait message,
 * between sleep_count_start() and sleep_count_stop() (dtrace prints the
 * aggregation when it is told to stop).
 */
#define	SLEEP_COUNT_MAX	64

struct sleep_count {
	pid_t	pid;
	FILE	*out;
	int	n;
	struct {
		long	tid;
		char	wmesg[32];	/* WMESGLEN is 8; td_wmesg is longer */
		long	count;
	} row[SLEEP_COUNT_MAX];
};

static void
sleep_count_start(struct sleep_count *c)
{
	char self[32], line[128];
	int p[2];

	snprintf(self, sizeof(self), "%d", (int)getpid());
	ATF_REQUIRE_EQ(0, pipe(p));
	c->pid = fork();
	ATF_REQUIRE(c->pid >= 0);
	if (c->pid == 0) {
		if (dup2(p[1], STDOUT_FILENO) < 0)
			_exit(126);
		closefrom(3);
		execl(SLEEP_WATCH_PROG, "dtrace", "-q", "-n",
		    "BEGIN { printf(\"READY\\n\"); }\n"
		    "sched:::sleep /pid == $1/ {\n"
		    "	@c[tid, stringof(curthread->td_wmesg)] = count(); }\n"
		    "END { printa(\"%d %s %@d\\n\", @c); printf(\"DONE\\n\"); }\n",
		    self, (char *)NULL);
		_exit(127);
	}
	close(p[1]);
	c->out = fdopen(p[0], "r");
	ATF_REQUIRE(c->out != NULL);
	c->n = 0;
	while (fgets(line, sizeof(line), c->out) != NULL)
		if (strcmp(line, "READY\n") == 0)
			return;
	atf_tc_fail("dtrace exited before tracing sched:::sleep");
}

static void
sleep_count_stop(struct sleep_count *c)
{
	char line[128], wmesg[32];
	long tid, count;
	int status;

	ATF_REQUIRE_EQ(0, kill(c->pid, SIGINT));
	while (fgets(line, sizeof(line), c->out) != NULL &&
	    strcmp(line, "DONE\n") != 0)
		if (sscanf(line, "%ld %31s %ld", &tid, wmesg, &count) == 3 &&
		    c->n < SLEEP_COUNT_MAX) {
			c->row[c->n].tid = tid;
			strlcpy(c->row[c->n].wmesg, wmesg,
			    sizeof(c->row[c->n].wmesg));
			c->row[c->n].count = count;
			c->n++;
		}
	fclose(c->out);
	(void)waitpid(c->pid, &status, 0);
}

/* Sleeps of `tid` (any thread: 0) with wait message `wmesg` (any: NULL). */
static long
sleep_count_of(const struct sleep_count *c, long tid, const char *wmesg)
{
	long total;

	total = 0;
	for (int i = 0; i < c->n; i++)
		if ((tid == 0 || c->row[i].tid == tid) &&
		    (wmesg == NULL || strcmp(c->row[i].wmesg, wmesg) == 0))
			total += c->row[i].count;
	return (total);
}

static long
self_tid(void)
{
	long tid;

	ATF_REQUIRE_EQ(0, thr_self(&tid));
	return (tid);
}

/* ---- following sleeps ------------------------------------------------- */

/*
 * Follow the session waits of this process's threads as they happen: a
 * channel receive ("mac_capabilityrv"), a channel send waiting for room
 * ("mcapsnd"), a condition wait ("uwait": libthr sleeps there for a private
 * condition variable) and a contended mutex ("umtxn").  Each event says
 * whether the sleep has a timeout.  sleep_trace_wait() blocks until a thread
 * goes to sleep in a named wait, so a case can act once a caller really is
 * asleep; the timed sleeps of every thread are kept, so a case can show that
 * a wait with no deadline never slept with one (a slice is a timed sleep).
 * The reader's own sleep on the pipe is not one of the four, so reading the
 * events produces none.
 */
#define	SLEEP_TRACE_MAX	64

struct sleep_trace {
	pid_t	pid;
	FILE	*out;
	int	n;
	struct {
		long	tid;
		char	wmesg[32];
	} timed[SLEEP_TRACE_MAX];
};

static void
sleep_trace_start(struct sleep_trace *t)
{
	char self[32], line[128];
	int p[2];

	snprintf(self, sizeof(self), "%d", (int)getpid());
	ATF_REQUIRE_EQ(0, pipe(p));
	t->pid = fork();
	ATF_REQUIRE(t->pid >= 0);
	if (t->pid == 0) {
		if (dup2(p[1], STDOUT_FILENO) < 0)
			_exit(126);
		closefrom(3);
		execl(SLEEP_WATCH_PROG, "dtrace", "-q", "-x",
		    "switchrate=100hz", "-n",
		    "BEGIN { printf(\"READY\\n\"); }\n"
		    "sched:::sleep /pid == $1 &&\n"
		    "    (stringof(curthread->td_wmesg) ==\n"
		    "    \"mac_capabilityrv\" ||\n"
		    "    stringof(curthread->td_wmesg) == \"mcapsnd\" ||\n"
		    "    stringof(curthread->td_wmesg) == \"uwait\" ||\n"
		    "    stringof(curthread->td_wmesg) == \"umtxn\")/ {\n"
		    "	printf(\"%d %s %d\\n\", tid,\n"
		    "	    stringof(curthread->td_wmesg),\n"
		    "	    curthread->td_sleeptimo != 0); }\n",
		    self, (char *)NULL);
		_exit(127);
	}
	close(p[1]);
	t->out = fdopen(p[0], "r");
	ATF_REQUIRE(t->out != NULL);
	t->n = 0;
	while (fgets(line, sizeof(line), t->out) != NULL)
		if (strcmp(line, "READY\n") == 0)
			return;
	atf_tc_fail("dtrace exited before tracing sched:::sleep");
}

/* Read one event, keeping it if the sleep is timed; false at end of file. */
static bool
sleep_trace_next(struct sleep_trace *t, long *tidp, char *wmesg)
{
	char line[128];
	int timed;

	for (;;) {
		if (fgets(line, sizeof(line), t->out) == NULL)
			return (false);
		if (sscanf(line, "%ld %31s %d", tidp, wmesg, &timed) == 3)
			break;
	}
	if (timed != 0) {
		ATF_REQUIRE_MSG(t->n < SLEEP_TRACE_MAX, "more than %d timed "
		    "sleeps (thread %ld in %s)", SLEEP_TRACE_MAX, *tidp, wmesg);
		t->timed[t->n].tid = *tidp;
		strlcpy(t->timed[t->n].wmesg, wmesg,
		    sizeof(t->timed[t->n].wmesg));
		t->n++;
	}
	return (true);
}

/*
 * Block until thread `tid` goes to sleep in the wait `wmesg`, or in `other`
 * when that is not NULL; the wait it went to sleep in is returned.
 */
static const char *
sleep_trace_wait(struct sleep_trace *t, long tid, const char *wmesg,
    const char *other)
{
	char got[32];
	long who;

	for (;;) {
		ATF_REQUIRE_MSG(sleep_trace_next(t, &who, got),
		    "dtrace exited before thread %ld slept in %s", tid, wmesg);
		if (who != tid)
			continue;
		if (strcmp(got, wmesg) == 0)
			return (wmesg);
		if (other != NULL && strcmp(got, other) == 0)
			return (other);
	}
}

/* Stop tracing; the events not read yet are still taken into account. */
static void
sleep_trace_stop(struct sleep_trace *t)
{
	char wmesg[32];
	long tid;
	int status;

	ATF_REQUIRE_EQ(0, kill(t->pid, SIGINT));
	while (sleep_trace_next(t, &tid, wmesg))
		;
	fclose(t->out);
	(void)waitpid(t->pid, &status, 0);
}

/* The timed sleeps of `tid` seen so far; the first one's wait in *wmesgp. */
static int
sleep_trace_timed(const struct sleep_trace *t, long tid, const char **wmesgp)
{
	int n;

	n = 0;
	*wmesgp = "";
	for (int i = 0; i < t->n; i++)
		if (t->timed[i].tid == tid && n++ == 0)
			*wmesgp = t->timed[i].wmesg;
	return (n);
}

/*
 * The timeout of the cases below whose call has a deadline: many 25 ms
 * slices long, so a sliced wait would sleep twenty times before it; any
 * length is the same case.  Nothing is ordered by it.
 */
#define	HOLD_MS	500

/* ---- a call answered later sleeps once -------------------------------- */

struct late_reply {
	struct sleep_trace *trace;
	long	caller;
	int	provider;
};

/* Answer the caller's request once the caller is asleep waiting for it. */
static void *
late_reply_thread(void *arg)
{
	struct late_reply *r = arg;
	uint64_t token;
	char byte;

	byte = provider_receive(r->provider, &token);
	(void)sleep_trace_wait(r->trace, r->caller, "mac_capabilityrv", NULL);
	provider_reply(r->provider, token, byte + 1);
	return (NULL);
}

ATF_TC(call_waits_in_one_sleep);
ATF_TC_HEAD(call_waits_in_one_sleep, tc)
{
	atf_tc_set_md_var(tc, "descr", "a call with no deadline, answered "
	    "once it is asleep, slept in the kernel for its reply with no "
	    "timeout: no time slices");
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(call_waits_in_one_sleep, tc)
{
	struct service_session *session;
	struct sleep_trace trace;
	struct late_reply r;
	const char *wmesg;
	pthread_t t;
	int timed;
	char reply = 0;

	session_pair(&session, &r.provider);
	sleep_trace_start(&trace);
	r.trace = &trace;
	r.caller = self_tid();
	ATF_REQUIRE_EQ(0, pthread_create(&t, NULL, late_reply_thread, &r));
	ATF_CHECK_EQ(0, session_call(session, 'a',
	    SERVICE_CLIENT_TIMEOUT_INFINITE, &reply));
	ATF_CHECK_EQ('b', reply);
	ATF_REQUIRE_EQ(0, pthread_join(t, NULL));
	sleep_trace_stop(&trace);
	timed = sleep_trace_timed(&trace, r.caller, &wmesg);
	ATF_CHECK_MSG(timed == 0, "the caller, with no deadline, slept %d "
	    "times with a timeout (first in %s)", timed, wmesg);
	service_session_close(session);
	close(r.provider);
}

/* ---- one deadline ----------------------------------------------------- */

ATF_TC(deadline_is_one_sleep);
ATF_TC_HEAD(deadline_is_one_sleep, tc)
{
	atf_tc_set_md_var(tc, "descr", "a call that times out sleeps once to "
	    "its deadline, not in slices");
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(deadline_is_one_sleep, tc)
{
	struct service_session *session;
	struct sleep_count c;
	long rv;
	int provider;
	char reply = 0;

	uint64_t start;

	session_pair(&session, &provider);
	sleep_count_start(&c);
	start = now_ms();
	ATF_CHECK_EQ(ETIMEDOUT, session_call(session, 'a', HOLD_MS, &reply));
	ATF_CHECK_MSG(now_ms() - start >= HOLD_MS, "timed out after %ju ms",
	    (uintmax_t)(now_ms() - start));
	sleep_count_stop(&c);
	rv = sleep_count_of(&c, self_tid(), "mac_capabilityrv");
	ATF_CHECK_MSG(rv >= 1 && rv <= 2, "the caller slept %ld times "
	    "before its deadline", rv);
	service_session_close(session);
	close(provider);
}

/* ---- two threads, replies out of order -------------------------------- */

struct two_calls {
	struct service_session *session;
	pthread_t thread;
	sem_t	started;	/* posted once tid is set */
	char	byte;
	char	reply;
	int	error;
	long	tid;
};

static void *
two_calls_thread(void *arg)
{
	struct two_calls *w = arg;

	w->tid = self_tid();
	(void)sem_post(&w->started);
	w->error = session_call(w->session, w->byte,
	    SERVICE_CLIENT_TIMEOUT_INFINITE, &w->reply);
	return (NULL);
}

/* Start a calling thread; return once its thread id is known. */
static void
two_calls_start(struct two_calls *w, struct service_session *session,
    char byte)
{

	memset(w, 0, sizeof(*w));
	w->session = session;
	w->byte = byte;
	ATF_REQUIRE_EQ(0, sem_init(&w->started, 0, 0));
	ATF_REQUIRE_EQ(0, pthread_create(&w->thread, NULL, two_calls_thread,
	    w));
	while (sem_wait(&w->started) == -1 && errno == EINTR)
		;
}

ATF_TC(two_threads_reverse_replies);
ATF_TC_HEAD(two_threads_reverse_replies, tc)
{
	atf_tc_set_md_var(tc, "descr", "two threads call on one session; the "
	    "thread that is not receiving is answered first, the receiver "
	    "after; neither waits in slices");
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(two_threads_reverse_replies, tc)
{
	struct service_session *session;
	struct sleep_trace trace;
	struct two_calls w[2];
	uint64_t token[2];
	const char *wmesg;
	char byte[2], got[32], role[2] = { 0, 0 };
	long tid;
	int provider, receiver, timed, waiter;

	session_pair(&session, &provider);
	sleep_trace_start(&trace);
	for (int i = 0; i < 2; i++)
		two_calls_start(&w[i], session, (char)('a' + 2 * i));
	byte[0] = provider_receive(provider, &token[0]);
	byte[1] = provider_receive(provider, &token[1]);
	/*
	 * No reply is on its way, so neither thread wakes again: wait until
	 * one is asleep receiving for the session and the other is asleep
	 * waiting for it.
	 */
	while (role[0] == 0 || role[1] == 0 || role[0] == role[1]) {
		ATF_REQUIRE_MSG(sleep_trace_next(&trace, &tid, got),
		    "dtrace exited before both callers slept");
		for (int i = 0; i < 2; i++) {
			if (tid != w[i].tid)
				continue;
			if (strcmp(got, "mac_capabilityrv") == 0)
				role[i] = 'r';
			else if (strcmp(got, "uwait") == 0)
				role[i] = 'w';
		}
	}
	receiver = role[0] == 'r' ? 0 : 1;
	waiter = 1 - receiver;
	/* Answer the waiter (the receiver delivers it), then the receiver. */
	for (int i = 0; i < 2; i++)
		if (byte[i] == w[waiter].byte)
			provider_reply(provider, token[i], byte[i] + 1);
	ATF_REQUIRE_EQ(0, pthread_join(w[waiter].thread, NULL));
	for (int i = 0; i < 2; i++)
		if (byte[i] == w[receiver].byte)
			provider_reply(provider, token[i], byte[i] + 1);
	ATF_REQUIRE_EQ(0, pthread_join(w[receiver].thread, NULL));
	sleep_trace_stop(&trace);
	for (int i = 0; i < 2; i++) {
		ATF_CHECK_EQ(0, w[i].error);
		ATF_CHECK_EQ(w[i].byte + 1, w[i].reply);
		timed = sleep_trace_timed(&trace, w[i].tid, &wmesg);
		ATF_CHECK_MSG(timed == 0, "the %s, with no deadline, slept "
		    "%d times with a timeout (first in %s)",
		    i == receiver ? "receiver" : "waiter", timed, wmesg);
	}
	service_session_close(session);
	close(provider);
}

/* ---- the receiver's call ends first: the other still gets its reply --- */

ATF_TC(receiver_handoff);
ATF_TC_HEAD(receiver_handoff, tc)
{
	atf_tc_set_md_var(tc, "descr", "when the thread receiving for the "
	    "session has its reply and leaves, another waiter takes over and "
	    "receives its own later reply");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(receiver_handoff, tc)
{
	struct service_session *session;
	struct two_calls w[2];
	pthread_t t[2];
	uint64_t token[2];
	char byte[2];
	int provider;

	session_pair(&session, &provider);
	for (int i = 0; i < 2; i++) {
		two_calls_start(&w[i], session, (char)('a' + 2 * i));
		t[i] = w[i].thread;
	}
	byte[0] = provider_receive(provider, &token[0]);
	byte[1] = provider_receive(provider, &token[1]);
	/* Answer one; once its thread has returned, answer the other. */
	provider_reply(provider, token[0], byte[0] + 1);
	for (int i = 0; i < 2; i++)
		if (w[i].byte == byte[0])
			ATF_REQUIRE_EQ(0, pthread_join(t[i], NULL));
	provider_reply(provider, token[1], byte[1] + 1);
	for (int i = 0; i < 2; i++) {
		if (w[i].byte == byte[1])
			ATF_REQUIRE_EQ(0, pthread_join(t[i], NULL));
		ATF_CHECK_EQ(0, w[i].error);
		ATF_CHECK_EQ(w[i].byte + 1, w[i].reply);
	}
	service_session_close(session);
	close(provider);
}

/* ---- a sender is not held up by a sleeping receiver ------------------- */

ATF_TC(sender_not_blocked_by_receiver);
ATF_TC_HEAD(sender_not_blocked_by_receiver, tc)
{
	atf_tc_set_md_var(tc, "descr", "while one thread sleeps waiting for "
	    "its reply, another thread's request goes out without waiting on "
	    "a lock the sleeping thread holds");
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(sender_not_blocked_by_receiver, tc)
{
	struct service_session *session;
	struct sleep_watch watch;
	struct sleep_count c;
	struct two_calls w[2];
	pthread_t t[2];
	uint64_t token[2];
	char byte[2];
	int provider;

	session_pair(&session, &provider);
	sleep_watch_start(&watch, SLEEP_WATCH_ANY_LEN);
	two_calls_start(&w[0], session, 'a');
	t[0] = w[0].thread;
	byte[0] = provider_receive(provider, &token[0]);
	/* The first caller now sleeps waiting for its reply. */
	sleep_watch_wait(&watch, 'R', w[0].tid);
	sleep_count_start(&c);
	two_calls_start(&w[1], session, 'c');
	t[1] = w[1].thread;
	byte[1] = provider_receive(provider, &token[1]);
	sleep_count_stop(&c);
	/* The second request arrived; did its thread wait on a lock? */
	ATF_CHECK_MSG(sleep_count_of(&c, w[1].tid, "umtxn") == 0,
	    "the second caller waited %ld times on a mutex to send",
	    sleep_count_of(&c, w[1].tid, "umtxn"));
	provider_reply(provider, token[1], byte[1] + 1);
	provider_reply(provider, token[0], byte[0] + 1);
	for (int i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ(0, pthread_join(t[i], NULL));
		ATF_CHECK_EQ(0, w[i].error);
	}
	sleep_watch_stop(&watch);
	service_session_close(session);
	close(provider);
}

/* ---- signals ---------------------------------------------------------- */

static atomic_int signals_taken;
static sem_t signal_handled;

static void
count_signal(int signo __unused)
{

	atomic_fetch_add(&signals_taken, 1);
	(void)sem_post(&signal_handled);
}

static void
catch_sigusr1(int flags)
{
	struct sigaction sa;

	ATF_REQUIRE_EQ(0, sem_init(&signal_handled, 0, 0));
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = count_signal;
	sa.sa_flags = flags;
	sigemptyset(&sa.sa_mask);
	ATF_REQUIRE_EQ(0, sigaction(SIGUSR1, &sa, NULL));
	atomic_store(&signals_taken, 0);
}

struct signaller {
	int		provider;
	pthread_t	target;
	long		target_tid;
	bool		restarts;	/* wait for the restarted sleep */
	struct sleep_watch *watch;
};

/*
 * Take the request, signal the caller once it sleeps for the reply, wait
 * for the handler; with a restart, wait for the call to sleep again; then
 * reply (a call that returned EINTR has cancelled its request, and the reply
 * is dropped).
 */
static void *
signaller_thread(void *arg)
{
	struct signaller *s = arg;
	uint64_t token;
	char byte;

	byte = provider_receive(s->provider, &token);
	sleep_watch_wait(s->watch, 'R', s->target_tid);
	(void)pthread_kill(s->target, SIGUSR1);
	while (sem_wait(&signal_handled) == -1 && errno == EINTR)
		;
	if (s->restarts)
		sleep_watch_wait(s->watch, 'R', s->target_tid);
	provider_reply(s->provider, token, byte + 1);
	return (NULL);
}

static void
signal_case(int flags, int expected_error)
{
	struct service_session *session;
	struct sleep_watch watch;
	struct signaller s;
	pthread_t t;
	char reply = 0;

	catch_sigusr1(flags);
	session_pair(&session, &s.provider);
	sleep_watch_start(&watch, SLEEP_WATCH_ANY_LEN);
	s.target = pthread_self();
	s.target_tid = self_tid();
	s.restarts = (flags & SA_RESTART) != 0;
	s.watch = &watch;
	ATF_REQUIRE_EQ(0, pthread_create(&t, NULL, signaller_thread, &s));
	ATF_CHECK_EQ_MSG(expected_error, session_call(session, 'a',
	    SERVICE_CLIENT_TIMEOUT_INFINITE, &reply), "call result");
	ATF_REQUIRE_EQ(0, pthread_join(t, NULL));
	ATF_CHECK_EQ(1, atomic_load(&signals_taken));
	sleep_watch_stop(&watch);
	service_session_close(session);
	close(s.provider);
}

ATF_TC(signal_sa_restart_restarts);
ATF_TC_HEAD(signal_sa_restart_restarts, tc)
{
	atf_tc_set_md_var(tc, "descr", "a signal with SA_RESTART restarts "
	    "a session call's wait, as read(2) on a pipe");
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(signal_sa_restart_restarts, tc)
{

	signal_case(SA_RESTART, 0);
}

ATF_TC(signal_without_sa_restart_eintr);
ATF_TC_HEAD(signal_without_sa_restart_eintr, tc)
{
	atf_tc_set_md_var(tc, "descr", "a signal without SA_RESTART ends a "
	    "session call's wait with EINTR, as read(2) on a pipe");
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(signal_without_sa_restart_eintr, tc)
{

	signal_case(0, EINTR);
}

/*
 * D2: only the thread sleeping in the kernel sees the signal; a thread
 * waiting for its reply while another receives does not get EINTR.
 */
struct waiter_signal {
	struct sleep_watch	*watch;
	struct two_calls	*w;
	int			 provider;
};

static void *
waiter_signal_thread(void *arg)
{
	struct waiter_signal *ws = arg;
	uint64_t token[2];
	char byte[2];
	char line[64], kind;
	long tid, receiver, waiter;
	pthread_t target;

	byte[0] = provider_receive(ws->provider, &token[0]);
	byte[1] = provider_receive(ws->provider, &token[1]);
	/* The receiver is the thread that sleeps in a channel receive. */
	for (receiver = 0; receiver == 0; ) {
		ATF_REQUIRE(fgets(line, sizeof(line), ws->watch->out) != NULL);
		if (sscanf(line, "%c %ld", &kind, &tid) == 2 && kind == 'R' &&
		    (tid == ws->w[0].tid || tid == ws->w[1].tid))
			receiver = tid;
	}
	waiter = receiver == ws->w[0].tid ? ws->w[1].tid : ws->w[0].tid;
	target = waiter == ws->w[0].tid ? ws->w[0].thread : ws->w[1].thread;
	(void)pthread_kill(target, SIGUSR1);
	while (sem_wait(&signal_handled) == -1 && errno == EINTR)
		;
	provider_reply(ws->provider, token[0], byte[0] + 1);
	provider_reply(ws->provider, token[1], byte[1] + 1);
	return (NULL);
}

ATF_TC(signal_spares_non_receiver);
ATF_TC_HEAD(signal_spares_non_receiver, tc)
{
	atf_tc_set_md_var(tc, "descr", "a signal to a thread waiting while "
	    "another thread receives for the session does not end its call");
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(signal_spares_non_receiver, tc)
{
	struct service_session *session;
	struct sleep_watch watch;
	struct waiter_signal ws;
	struct two_calls w[2];
	pthread_t t[2], helper;
	int provider;

	catch_sigusr1(0);
	session_pair(&session, &provider);
	sleep_watch_start(&watch, SLEEP_WATCH_ANY_LEN);
	for (int i = 0; i < 2; i++) {
		two_calls_start(&w[i], session, (char)('a' + 2 * i));
		t[i] = w[i].thread;
	}
	ws.watch = &watch;
	ws.w = w;
	ws.provider = provider;
	ATF_REQUIRE_EQ(0, pthread_create(&helper, NULL, waiter_signal_thread,
	    &ws));
	ATF_REQUIRE_EQ(0, pthread_join(helper, NULL));
	for (int i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ(0, pthread_join(t[i], NULL));
		ATF_CHECK_EQ_MSG(0, w[i].error, "thread %d: %s", i,
		    strerror(w[i].error));
	}
	ATF_CHECK_EQ(1, atomic_load(&signals_taken));
	sleep_watch_stop(&watch);
	service_session_close(session);
	close(provider);
}

/* ---- close wakes the receiver ----------------------------------------- */

ATF_TC(close_wakes_receiver);
ATF_TC_HEAD(close_wakes_receiver, tc)
{
	atf_tc_set_md_var(tc, "descr", "closing a session ends a call asleep "
	    "waiting for its reply with ECANCELED");
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(close_wakes_receiver, tc)
{
	struct service_session *session;
	struct sleep_count c;
	struct sleep_watch watch;
	struct two_calls w;
	pthread_t t;
	uint64_t token;
	int provider;

	session_pair(&session, &provider);
	sleep_watch_start(&watch, SLEEP_WATCH_ANY_LEN);
	two_calls_start(&w, session, 'a');
	t = w.thread;
	(void)provider_receive(provider, &token);
	sleep_watch_wait(&watch, 'R', w.tid);
	sleep_count_start(&c);
	/*
	 * Closing waits for the call, which only the close itself ends: the
	 * receiver wakes from its one sleep, with no sliced re-checks.
	 */
	service_session_close(session);
	ATF_REQUIRE_EQ(0, pthread_join(t, NULL));
	sleep_count_stop(&c);
	ATF_CHECK_EQ_MSG(ECANCELED, w.error, "the call ended with %s",
	    strerror(w.error));
	ATF_CHECK_MSG(sleep_count_of(&c, w.tid, "mac_capabilityrv") == 0,
	    "the receiver slept %ld more times before the close ended it",
	    sleep_count_of(&c, w.tid, "mac_capabilityrv"));
	sleep_watch_stop(&watch);
	close(provider);
}

/* ---- the send waits for room only until the call's deadline ----------- */

ATF_TC(send_waits_only_to_deadline);
ATF_TC_HEAD(send_waits_only_to_deadline, tc)
{
	atf_tc_set_md_var(tc, "descr", "a call whose request finds the "
	    "provider's queue full fails with ETIMEDOUT at its deadline, "
	    "unsent");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(send_waits_only_to_deadline, tc)
{
	struct service_session *session;
	uint64_t start;
	int clientdup, provider;
	char reply = 0;

	session_pair_dup(&session, &provider, &clientdup);
	fill_queue(clientdup);
	start = now_ms();
	ATF_CHECK_EQ(ETIMEDOUT, session_call(session, 'a', HOLD_MS, &reply));
	ATF_CHECK_MSG(now_ms() - start >= HOLD_MS, "timed out after %ju ms",
	    (uintmax_t)(now_ms() - start));
	service_session_close(session);
	close(clientdup);
	close(provider);
}

/* ---- restarts after signals keep the call's deadline ------------------ */

static atomic_int alarms;

static void
count_alarm(int signo __unused)
{

	atomic_fetch_add(&alarms, 1);
}

ATF_TC(restart_keeps_deadline);
ATF_TC_HEAD(restart_keeps_deadline, tc)
{
	atf_tc_set_md_var(tc, "descr", "signals with SA_RESTART arriving "
	    "more often than the call's timeout restart its wait without "
	    "restarting its deadline: the call still times out");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(restart_keeps_deadline, tc)
{
	struct service_session *session;
	struct itimerval every = { .it_interval = { 0, HOLD_MS * 200 },
	    .it_value = { 0, HOLD_MS * 200 } };	/* HOLD_MS / 5, in us */
	struct itimerval off = { { 0, 0 }, { 0, 0 } };
	struct sigaction sa;
	int provider;
	char reply = 0;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = count_alarm;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);
	ATF_REQUIRE_EQ(0, sigaction(SIGALRM, &sa, NULL));
	session_pair(&session, &provider);
	ATF_REQUIRE_EQ(0, setitimer(ITIMER_REAL, &every, NULL));
	ATF_CHECK_EQ(ETIMEDOUT, session_call(session, 'a', HOLD_MS, &reply));
	ATF_REQUIRE_EQ(0, setitimer(ITIMER_REAL, &off, NULL));
	ATF_CHECK_MSG(atomic_load(&alarms) >= 2, "%d signals arrived",
	    atomic_load(&alarms));
	service_session_close(session);
	close(provider);
}

/* ---- close wakes a sender asleep for room ----------------------------- */

ATF_TC(close_wakes_sender);
ATF_TC_HEAD(close_wakes_sender, tc)
{
	atf_tc_set_md_var(tc, "descr", "closing a session ends a call asleep "
	    "waiting for room to send with ECANCELED");
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(close_wakes_sender, tc)
{
	struct service_session *session;
	struct sleep_watch watch;
	struct two_calls w;
	int clientdup, provider;

	session_pair_dup(&session, &provider, &clientdup);
	fill_queue(clientdup);
	sleep_watch_start(&watch, 0);
	two_calls_start(&w, session, 'a');
	sleep_watch_wait(&watch, 'S', w.tid);
	service_session_close(session);
	ATF_REQUIRE_EQ(0, pthread_join(w.thread, NULL));
	ATF_CHECK_EQ_MSG(ECANCELED, w.error, "the call ended with %s",
	    strerror(w.error));
	sleep_watch_stop(&watch);
	close(clientdup);
	close(provider);
}

/* ---- an event wait with a zero timeout does not wait ------------------ */

ATF_TC(event_timeout_zero);
ATF_TC_HEAD(event_timeout_zero, tc)
{
	atf_tc_set_md_var(tc, "descr", "receive_event with a zero timeout "
	    "and nothing queued answers ETIMEDOUT at once; an event sent "
	    "after is then received");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(event_timeout_zero, tc)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct mac_capability_sendmsg_args send;
	struct service_session *session;
	struct service_reply event;
	int provider;
	char byte = 'e', got = 0;

	session_pair(&session, &provider);
	memset(&event, 0, sizeof(event));
	event.size = sizeof(event);
	event.data = &got;
	event.capacity = 1;
	options.timeout_ms = 0;
	ATF_CHECK_EQ(-1, service_session_receive_event(session, &event,
	    &options));
	ATF_CHECK_EQ(ETIMEDOUT, errno);
	memset(&send, 0, sizeof(send));
	send.payload = &byte;
	send.payload_len = sizeof(byte);
	ATF_REQUIRE_EQ(0, ioctl(provider, MAC_CAPABILITY_SENDMSG, &send));
	/* The event may still be on its way: wait for it, with no limit. */
	options.timeout_ms = SERVICE_CLIENT_TIMEOUT_INFINITE;
	ATF_CHECK_EQ(0, service_session_receive_event(session, &event,
	    &options));
	ATF_CHECK_EQ('e', got);
	service_session_close(session);
	close(provider);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, call_waits_in_one_sleep);
	ATF_TP_ADD_TC(tp, deadline_is_one_sleep);
	ATF_TP_ADD_TC(tp, two_threads_reverse_replies);
	ATF_TP_ADD_TC(tp, receiver_handoff);
	ATF_TP_ADD_TC(tp, sender_not_blocked_by_receiver);
	ATF_TP_ADD_TC(tp, signal_sa_restart_restarts);
	ATF_TP_ADD_TC(tp, signal_without_sa_restart_eintr);
	ATF_TP_ADD_TC(tp, signal_spares_non_receiver);
	ATF_TP_ADD_TC(tp, close_wakes_receiver);
	ATF_TP_ADD_TC(tp, send_waits_only_to_deadline);
	ATF_TP_ADD_TC(tp, restart_keeps_deadline);
	ATF_TP_ADD_TC(tp, close_wakes_sender);
	ATF_TP_ADD_TC(tp, event_timeout_zero);
	return (atf_no_error());
}
