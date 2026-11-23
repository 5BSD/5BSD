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
 * counts the waiting threads' sleeps with dtrace(1)'s sched:::sleep probe
 * (the providers are preloaded: the plane refuses a late kldload).
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/thr.h>
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
session_pair(struct service_session **sessionp, int *providerp)
{
	int pair[2];

	if (mac_capability_channel_create(pair) == -1)
		atf_tc_skip("mac_capability channels unavailable: %s",
		    strerror(errno));
	ATF_REQUIRE_EQ(0, service_session_create(pair[0], sessionp));
	*providerp = pair[1];
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

static void
sleep_ms(unsigned ms)
{
	struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000 };

	while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
		;
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

/*
 * The time a reply is held back in the cases below: many 25 ms slices long,
 * so a sliced wait would sleep twenty times; any length is the same case.
 */
#define	HOLD_MS	500

/* ---- a call answered later sleeps once -------------------------------- */

struct late_reply {
	int	provider;
	char	byte;
};

static void *
late_reply_thread(void *arg)
{
	struct late_reply *r = arg;
	uint64_t token;
	char byte;

	byte = provider_receive(r->provider, &token);
	sleep_ms(HOLD_MS);
	provider_reply(r->provider, token, byte + 1);
	return (NULL);
}

ATF_TC(call_waits_in_one_sleep);
ATF_TC_HEAD(call_waits_in_one_sleep, tc)
{
	atf_tc_set_md_var(tc, "descr", "a call whose reply comes late sleeps "
	    "in the kernel until it comes, not in 25 ms slices");
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(call_waits_in_one_sleep, tc)
{
	struct service_session *session;
	struct sleep_count c;
	struct late_reply r;
	pthread_t t;
	long rv;
	char reply = 0;

	session_pair(&session, &r.provider);
	sleep_count_start(&c);
	ATF_REQUIRE_EQ(0, pthread_create(&t, NULL, late_reply_thread, &r));
	ATF_CHECK_EQ(0, session_call(session, 'a',
	    SERVICE_CLIENT_TIMEOUT_INFINITE, &reply));
	ATF_CHECK_EQ('b', reply);
	ATF_REQUIRE_EQ(0, pthread_join(t, NULL));
	sleep_count_stop(&c);
	rv = sleep_count_of(&c, self_tid(), "mac_capabilityrv");
	ATF_CHECK_MSG(rv >= 1 && rv <= 2, "the caller slept %ld times in "
	    "channel receives for one reply", rv);
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

	session_pair(&session, &provider);
	sleep_count_start(&c);
	ATF_CHECK_EQ(ETIMEDOUT, session_call(session, 'a', HOLD_MS, &reply));
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
	atf_tc_set_md_var(tc, "descr", "two threads on one session get their "
	    "replies delivered in reverse order; neither waits in slices");
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(two_threads_reverse_replies, tc)
{
	struct service_session *session;
	struct two_calls w[2];
	struct sleep_count c;
	pthread_t t[2];
	uint64_t token[2];
	long sleeps;
	char byte[2];
	int provider;

	session_pair(&session, &provider);
	sleep_count_start(&c);
	for (int i = 0; i < 2; i++) {
		two_calls_start(&w[i], session, (char)('a' + 2 * i));
		t[i] = w[i].thread;
	}
	byte[0] = provider_receive(provider, &token[0]);
	byte[1] = provider_receive(provider, &token[1]);
	/* Both are waiting now; answer the second first, the first later. */
	sleep_ms(HOLD_MS);
	provider_reply(provider, token[1], byte[1] + 1);
	sleep_ms(HOLD_MS);
	provider_reply(provider, token[0], byte[0] + 1);
	for (int i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ(0, pthread_join(t[i], NULL));
		ATF_CHECK_EQ(0, w[i].error);
		ATF_CHECK_EQ(w[i].byte + 1, w[i].reply);
	}
	sleep_count_stop(&c);
	sleeps = sleep_count_of(&c, w[0].tid, NULL) +
	    sleep_count_of(&c, w[1].tid, NULL);
	/* Each thread sleeps a few times (its wait, a lock or two). */
	ATF_CHECK_MSG(sleeps <= 8, "the two callers slept %ld times over "
	    "%d ms", sleeps, 2 * HOLD_MS);
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
	/* Closing waits for the call, which only the close itself ends. */
	service_session_close(session);
	ATF_REQUIRE_EQ(0, pthread_join(t, NULL));
	ATF_CHECK_EQ_MSG(ECANCELED, w.error, "the call ended with %s",
	    strerror(w.error));
	sleep_watch_stop(&watch);
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
	return (atf_no_error());
}
