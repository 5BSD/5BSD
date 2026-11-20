/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Process discovery authority/transport tests and session mint wire tests.
 * Only the kernel process slot grants discovery; a channel merely held at a
 * descriptor, including the retired fixed lookup descriptor 3, does not.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/thr.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
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
#include "switchboard_svc_proto.h"
#include "service_bootstrap.h"

/*
 * Create a connected mac_capability channel pair via the channel device, or -1
 * with errno == ENODEV when the device is unavailable so a gated case can skip.
 * *client_end is the endpoint an inheritor probes; *switchboard_end is the end the
 * test's responder drives.  Both are returned as bare descriptors.
 */
static int
create_channel_pair(int *client_end, int *switchboard_end)
{
	int pair[2];

	if (mac_capability_channel_create(pair) == -1)
		return (-1);
	*client_end = pair[0];
	*switchboard_end = pair[1];
	return (0);
}

/*
 * A minimal switchboard-side responder that pumps one channel from a helper thread
 * and answers SVC_OP_AMBIENT_HELLO.  In RESP_LOOKUP mode it replies with the
 * magic ack (modeling domain.c's lookup channel); in RESP_ENOTSUP mode it
 * replies ENOTSUP (modeling svc_proto.c's unit control channel default), so the
 * probe must reject it.
 */
enum responder_mode {
	RESP_LOOKUP = 0,
	RESP_ENOTSUP = 1
};

struct responder {
	struct channel		*chan;
	enum responder_mode	 mode;
	pthread_t		 thread;
	volatile int		 stop;

};

static void
responder_request(struct channel *ch, struct channel_message *req, void *ctx)
{
	struct responder *r = ctx;
	uint32_t op = 0;

	(void)ch;
	if (channel_message_length(req) >= sizeof(op))
		memcpy(&op, channel_message_data(req), sizeof(op));
	if (op == SVC_OP_AMBIENT_HELLO && r->mode == RESP_LOOKUP) {
		struct svc_ambient_hello_reply rep = {
			.status = 0,
			.magic = SVC_AMBIENT_HELLO_MAGIC,
		};

		(void)channel_send_reply(req, &(struct channel_outgoing){
			.size = sizeof(struct channel_outgoing),
			.data = &rep,
			.length = sizeof(rep),
		});
	} else {
		struct svc_reply rep = { .status = ENOTSUP };

		(void)channel_send_reply(req, &(struct channel_outgoing){
			.size = sizeof(struct channel_outgoing),
			.data = &rep,
			.length = sizeof(rep),
		});
	}
	channel_message_free(req);
}

static void *
responder_thread(void *arg)
{
	struct responder *r = arg;

	while (!r->stop) {
		int wants, ready;

		wants = channel_wants_write(r->chan);
		if (wants == -1)
			wants = 0;
		ready = channel_wait(r->chan, wants, 20);
		if (ready <= 0)
			continue;
		if ((ready & CHANNEL_WAIT_WRITE) != 0)
			(void)channel_flush(r->chan);
		if ((ready & CHANNEL_WAIT_READ) != 0)
			(void)channel_dispatch(r->chan);
	}
	return (NULL);
}

static int
responder_start(struct responder *r, int switchboard_end, enum responder_mode mode)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);

	memset(r, 0, sizeof(*r));
	r->mode = mode;
	if (channel_create(switchboard_end, &options, &r->chan) == -1)
		return (-1);
	if (channel_set_request_handler(r->chan, responder_request, r) == -1) {
		channel_destroy(r->chan);
		r->chan = NULL;
		return (-1);
	}
	if (pthread_create(&r->thread, NULL, responder_thread, r) != 0) {
		channel_destroy(r->chan);
		r->chan = NULL;
		return (-1);
	}
	return (0);
}

static void
responder_stop(struct responder *r)
{

	if (r->chan == NULL)
		return;
	r->stop = 1;
	(void)pthread_join(r->thread, NULL);
	channel_destroy(r->chan);
}

static void
isolate_ambient_lookup(void)
{
	if (service_clear_ambient_lookup() == -1)
		atf_tc_skip("process discovery context unavailable");
}

ATF_TC_WITHOUT_HEAD(descriptor_cannot_grant_discovery);
ATF_TC_BODY(descriptor_cannot_grant_discovery, tc)
{
	int pair[2], saved;

	(void)tc;
	isolate_ambient_lookup();
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(pair));
	/*
	 * Recreate the retired route exactly: a live channel at descriptor 3 and
	 * the variable that named it.  Neither half may grant discovery.
	 */
	saved = fcntl(3, F_DUPFD_CLOEXEC, 10);
	ATF_REQUIRE(saved >= 0 || errno == EBADF);
	ATF_REQUIRE_EQ(3, dup2(pair[0], 3));
	ATF_REQUIRE_EQ(0, setenv("SERVICE_LOOKUP_FD", "3", 1));
	errno = 0;
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
	ATF_CHECK_EQ(ENOENT, errno);
	ATF_REQUIRE_EQ(0, unsetenv("SERVICE_LOOKUP_FD"));
	ATF_REQUIRE_EQ(0, close(3));
	if (saved >= 0) {
		ATF_REQUIRE_EQ(3, dup2(saved, 3));
		close(saved);
	}
	close(pair[0]);
	close(pair[1]);
}

ATF_TC_WITHOUT_HEAD(non_channel_install_rejected);
ATF_TC_BODY(non_channel_install_rejected, tc)
{
	int pair[2];

	(void)tc;
	isolate_ambient_lookup();
	ATF_REQUIRE_EQ(0, pipe(pair));
	ATF_CHECK_EQ(-1, service_install_ambient_lookup(pair[0]));
	ATF_CHECK_EQ(EINVAL, errno);
	close(pair[0]);
	close(pair[1]);
}

ATF_TC_WITHOUT_HEAD(context_holds_reference);
ATF_TC_BODY(context_holds_reference, tc)
{
	struct mac_cap_process_info info;
	int pair[2], fd;

	(void)tc;
	isolate_ambient_lookup();
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(pair));
	ATF_REQUIRE_EQ(0, service_install_ambient_lookup(pair[0]));
	ATF_CHECK(fcntl(pair[0], F_GETFD) & FD_CLOEXEC);
	close(pair[0]);
	ATF_REQUIRE_EQ(0, service_process_info(&info));
	ATF_CHECK_EQ(1, info.present);
	fd = syscall(SYS_cap_process, MAC_CAP_PROCESS_GET, -1, 0, NULL);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC);
	close(fd);
	ATF_REQUIRE_EQ(0, service_clear_ambient_lookup());
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
	ATF_CHECK_EQ(ENOENT, errno);
	close(pair[1]);
}

ATF_TC_WITHOUT_HEAD(wrong_protocol_fails_closed);
ATF_TC_BODY(wrong_protocol_fails_closed, tc)
{
	struct responder responder;
	int client, provider;

	(void)tc;
	isolate_ambient_lookup();
	ATF_REQUIRE_EQ(0, create_channel_pair(&client, &provider));
	ATF_REQUIRE_EQ(0, responder_start(&responder, provider, RESP_ENOTSUP));
	ATF_REQUIRE_EQ(0, service_install_ambient_lookup(client));
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
	ATF_REQUIRE_EQ(0, service_clear_ambient_lookup());
	responder_stop(&responder);
	close(client);
}

/*
 * Ambient lookups wait for switchboard's answer (2026-11-20).  A mock
 * switchboard, driven with raw channel calls from a thread, holds the other
 * end of this process's discovery route: it adopts the private channel the
 * client registers, acknowledges it, receives the lookup and then answers,
 * refuses, exits (closes the private channel) or lets a signal reach the
 * waiting client.  The former client bound was 2 s; the late answers come
 * after LATE_MS, past it.
 */
#define	LATE_MS	3000

enum mock_mode {
	MOCK_ANSWER,		/* a session channel, after delay_ms */
	MOCK_REFUSE,		/* status `status`, after delay_ms */
	MOCK_EXIT,		/* close the private channel after delay_ms */
	MOCK_REJECT_REGISTRATION, /* close the registered channel, no ACK */
	MOCK_SIGNAL_THEN_ANSWER, /* signal the sleeping client, then answer */
};

struct mock_switchboard {
	enum mock_mode	mode;
	int		route;		/* switchboard end of the route */
	unsigned	delay_ms;
	int32_t		status;
	pthread_t	client;		/* MOCK_SIGNAL_THEN_ANSWER */
	long		client_tid;
	int		session_peer;	/* provider end of an answered session */
	pthread_t	thread;
};

static int
mock_recv(int fd, void *payload, uint32_t len, int *fdp, uint64_t *tokenp)
{
	struct mac_capability_recvmsg_args recv;

	memset(&recv, 0, sizeof(recv));
	recv.payload = payload;
	recv.payload_len = len;
	recv.fds = fdp;
	recv.nfds = fdp != NULL ? 1 : 0;
	recv.flags = MAC_CAPABILITY_RECV_F_WAIT;
	recv._reserved[0] = MAC_CAPABILITY_RECV_WAIT_FOREVER;
	if (ioctl(fd, MAC_CAPABILITY_RECVMSG, &recv) == -1)
		return (-1);
	if (fdp != NULL && recv.nfds == 0)
		*fdp = -1;
	if (tokenp != NULL)
		*tokenp = recv.reply_token;
	return ((int)recv.payload_len);
}

static int
mock_send(int fd, const void *payload, uint32_t len, int *fdp,
    uint64_t token)
{
	struct mac_capability_sendmsg_args send;

	memset(&send, 0, sizeof(send));
	send.payload = __DECONST(void *, payload);
	send.payload_len = len;
	send.fds = fdp;
	send.nfds = fdp != NULL ? 1 : 0;
	send.reply_token = token;
	return (ioctl(fd, MAC_CAPABILITY_SENDMSG, &send));
}

static void
sleep_ms(unsigned ms)
{
	struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000 };

	while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
		continue;
}

/*
 * Wait until the client thread sleeps in the channel receive, so the signal
 * lands in the wait it is meant to interrupt.  Nothing reports that a thread
 * went to sleep, so the test looks at the thread's wait channel.
 */
static void
wait_client_asleep(long tid)
{
	struct kinfo_proc *kp;
	size_t len;
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID | KERN_PROC_INC_THREAD,
	    getpid() };
	bool asleep;

	for (asleep = false; !asleep; ) {
		len = 0;
		if (sysctl(mib, 4, NULL, &len, NULL, 0) == -1)
			return;
		len += 4 * sizeof(*kp);
		if ((kp = malloc(len)) == NULL)
			return;
		if (sysctl(mib, 4, kp, &len, NULL, 0) == 0)
			for (size_t i = 0; i < len / sizeof(*kp); i++)
				if (kp[i].ki_tid == tid &&
				    strncmp(kp[i].ki_wmesg, "mac_capabilityrv",
				    WMESGLEN) == 0)
					asleep = true;
		free(kp);
		if (!asleep)
			sleep_ms(1);
	}
}

static void *
mock_switchboard_thread(void *arg)
{
	struct mock_switchboard *m = arg;
	struct svc_register_lookup_req reg;
	struct svc_register_lookup_ack ack;
	struct svc_lookup_req req;
	struct svc_reply reply;
	uint64_t token;
	int identity, private_fd, session[2];

	if (mock_recv(m->route, &reg, sizeof(reg), &private_fd, NULL) !=
	    (int)sizeof(reg) || private_fd < 0)
		return (NULL);
	if (m->mode == MOCK_REJECT_REGISTRATION) {
		(void)close(private_fd);
		return (NULL);
	}
	ack.op = SVC_OP_REGISTER_LOOKUP;
	ack.status = 0;
	ack.magic = SVC_REGISTER_LOOKUP_MAGIC;
	if (mock_send(private_fd, &ack, sizeof(ack), NULL, 0) == -1 ||
	    mock_recv(private_fd, &req, sizeof(req), &identity, &token) !=
	    (int)sizeof(req)) {
		(void)close(private_fd);
		return (NULL);
	}
	if (identity >= 0)
		(void)close(identity);
	if (m->mode == MOCK_SIGNAL_THEN_ANSWER) {
		wait_client_asleep(m->client_tid);
		(void)pthread_kill(m->client, SIGUSR1);
		/* Let the client take the signal before the answer arrives. */
		sleep_ms(100);
	}
	sleep_ms(m->delay_ms);
	memset(&reply, 0, sizeof(reply));
	switch (m->mode) {
	case MOCK_EXIT:
		break;
	case MOCK_REFUSE:
		reply.status = m->status;
		(void)mock_send(private_fd, &reply, sizeof(reply), NULL, token);
		break;
	default:
		if (mac_capability_channel_create(session) == -1)
			break;
		(void)mock_send(private_fd, &reply, sizeof(reply), &session[0],
		    token);
		(void)close(session[0]);
		m->session_peer = session[1];
		break;
	}
	(void)close(private_fd);
	return (NULL);
}

static void
mock_start(struct mock_switchboard *m, enum mock_mode mode, unsigned delay_ms)
{
	int client;

	memset(m, 0, sizeof(*m));
	m->mode = mode;
	m->delay_ms = delay_ms;
	m->session_peer = -1;
	m->client = pthread_self();
	ATF_REQUIRE_EQ(0, thr_self(&m->client_tid));
	isolate_ambient_lookup();
	ATF_REQUIRE_EQ(0, create_channel_pair(&client, &m->route));
	ATF_REQUIRE_EQ(0, service_install_ambient_lookup(client));
	(void)close(client);
	ATF_REQUIRE_EQ(0, pthread_create(&m->thread, NULL,
	    mock_switchboard_thread, m));
}

static void
mock_finish(struct mock_switchboard *m)
{

	ATF_REQUIRE_EQ(0, pthread_join(m->thread, NULL));
	ATF_REQUIRE_EQ(0, service_clear_ambient_lookup());
	(void)close(m->route);
	if (m->session_peer >= 0)
		(void)close(m->session_peer);
}

static uint64_t
now_ms(void)
{
	struct timespec ts;

	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts));
	return ((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

ATF_TC(lookup_waits_for_late_answer);
ATF_TC_HEAD(lookup_waits_for_late_answer, tc)
{
	atf_tc_set_md_var(tc, "descr", "an ambient lookup waits for an "
	    "answer that comes after the former 2 s bound");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(lookup_waits_for_late_answer, tc)
{
	struct mock_switchboard m;
	uint64_t start;
	int fd;

	mock_start(&m, MOCK_ANSWER, LATE_MS);
	start = now_ms();
	fd = -1;
	ATF_CHECK_EQ_MSG(0, service_connect_ambient("org.test.late", &fd),
	    "lookup failed: %s", strerror(errno));
	ATF_CHECK(now_ms() - start >= LATE_MS);
	ATF_CHECK(fd >= 0);
	if (fd >= 0)
		(void)close(fd);
	mock_finish(&m);
}

ATF_TC(lookup_returns_refusal);
ATF_TC_HEAD(lookup_returns_refusal, tc)
{
	atf_tc_set_md_var(tc, "descr", "a late refusal is the lookup's error");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(lookup_returns_refusal, tc)
{
	struct mock_switchboard m;
	int fd;

	mock_start(&m, MOCK_REFUSE, LATE_MS);
	m.status = ECANCELED;
	fd = -1;
	ATF_CHECK_EQ(-1, service_connect_ambient("org.test.refused", &fd));
	ATF_CHECK_EQ_MSG(ECANCELED, errno, "errno %d (%s)", errno,
	    strerror(errno));
	ATF_CHECK_EQ(-1, fd);
	mock_finish(&m);
}

ATF_TC(lookup_reset_when_switchboard_exits);
ATF_TC_HEAD(lookup_reset_when_switchboard_exits, tc)
{
	atf_tc_set_md_var(tc, "descr", "a lookup whose switchboard exits "
	    "before answering fails with ECONNRESET");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(lookup_reset_when_switchboard_exits, tc)
{
	struct mock_switchboard m;
	int fd;

	mock_start(&m, MOCK_EXIT, LATE_MS);
	fd = -1;
	ATF_CHECK_EQ(-1, service_connect_ambient("org.test.orphaned", &fd));
	ATF_CHECK_EQ_MSG(ECONNRESET, errno, "errno %d (%s)", errno,
	    strerror(errno));
	mock_finish(&m);
}

ATF_TC(registration_refused_resets);
ATF_TC_HEAD(registration_refused_resets, tc)
{
	atf_tc_set_md_var(tc, "descr", "a registration switchboard refuses "
	    "(closes without an ACK) fails with ECONNRESET, not a hang");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(registration_refused_resets, tc)
{
	struct mock_switchboard m;
	int fd;

	mock_start(&m, MOCK_REJECT_REGISTRATION, 0);
	fd = -1;
	ATF_CHECK_EQ(-1, service_connect_ambient("org.test.unadopted", &fd));
	ATF_CHECK_EQ_MSG(ECONNRESET, errno, "errno %d (%s)", errno,
	    strerror(errno));
	mock_finish(&m);
}

static atomic_int signals_taken;

static void
count_signal(int signo __unused)
{

	atomic_fetch_add(&signals_taken, 1);
}

static void
catch_sigusr1(int flags)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = count_signal;
	sa.sa_flags = flags;
	(void)sigemptyset(&sa.sa_mask);
	ATF_REQUIRE_EQ(0, sigaction(SIGUSR1, &sa, NULL));
	atomic_store(&signals_taken, 0);
}

ATF_TC(signal_sa_restart_restarts);
ATF_TC_HEAD(signal_sa_restart_restarts, tc)
{
	atf_tc_set_md_var(tc, "descr", "a signal whose handler has "
	    "SA_RESTART restarts the wait for the answer, as read(2) on a "
	    "pipe does");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(signal_sa_restart_restarts, tc)
{
	struct mock_switchboard m;
	int fd;

	catch_sigusr1(SA_RESTART);
	mock_start(&m, MOCK_SIGNAL_THEN_ANSWER, 0);
	fd = -1;
	ATF_CHECK_EQ_MSG(0, service_connect_ambient("org.test.restart", &fd),
	    "lookup failed: %s", strerror(errno));
	ATF_CHECK_EQ(1, atomic_load(&signals_taken));
	if (fd >= 0)
		(void)close(fd);
	mock_finish(&m);
}

ATF_TC(signal_without_sa_restart_eintr);
ATF_TC_HEAD(signal_without_sa_restart_eintr, tc)
{
	atf_tc_set_md_var(tc, "descr", "a signal whose handler lacks "
	    "SA_RESTART ends the wait with EINTR, as read(2) on a pipe does");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(signal_without_sa_restart_eintr, tc)
{
	struct mock_switchboard m;
	int fd;

	catch_sigusr1(0);
	mock_start(&m, MOCK_SIGNAL_THEN_ANSWER, 0);
	fd = -1;
	ATF_CHECK_EQ(-1, service_connect_ambient("org.test.interrupted", &fd));
	ATF_CHECK_EQ_MSG(EINTR, errno, "errno %d (%s)", errno,
	    strerror(errno));
	ATF_CHECK_EQ(1, atomic_load(&signals_taken));
	ATF_CHECK_EQ(-1, fd);
	mock_finish(&m);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, descriptor_cannot_grant_discovery);
	ATF_TP_ADD_TC(tp, non_channel_install_rejected);
	ATF_TP_ADD_TC(tp, context_holds_reference);
	ATF_TP_ADD_TC(tp, wrong_protocol_fails_closed);
	ATF_TP_ADD_TC(tp, lookup_waits_for_late_answer);
	ATF_TP_ADD_TC(tp, lookup_returns_refusal);
	ATF_TP_ADD_TC(tp, lookup_reset_when_switchboard_exits);
	ATF_TP_ADD_TC(tp, registration_refused_resets);
	ATF_TP_ADD_TC(tp, signal_sa_restart_restarts);
	ATF_TP_ADD_TC(tp, signal_without_sa_restart_eintr);
	return (atf_no_error());
}
