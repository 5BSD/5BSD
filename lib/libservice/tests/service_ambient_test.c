/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Ambient lookup-channel helper tests (§21, §11a D1).
 *
 * The environment round-trip, the ambient descriptor marking, and the
 * rejection of an absent, non-channel, or wrong-kind SERVICE_LOOKUP_FD run
 * anywhere that needs no capability device.  The cases that prove
 * service_ambient_lookup_fd()'s BEHAVIORAL handshake — a genuine lookup channel
 * (one that answers SVC_OP_AMBIENT_HELLO with SVC_AMBIENT_HELLO_MAGIC) is
 * accepted, while a mac_capability channel that does NOT speak the lookup
 * protocol (a stand-in for a service's unit control channel, which returns
 * ENOTSUP) is REJECTED — need the channel device and are gated: they skip
 * cleanly when it is unavailable.
 *
 * The wrong-kind rejection is the D1 fix: before the handshake, ANY
 * mac_capability channel at fd 3 (including a unit control channel that shares
 * the number and the generic channel identity) was accepted as the ambient
 * lookup channel.  Now only a channel that answers HELLO is.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <channel.h>

#include "libservice.h"
#include "serviced_svc_proto.h"
#include "service_bootstrap.h"

/*
 * Create a connected mac_capability channel pair via the channel device, or -1
 * with errno == ENODEV when the device is unavailable so a gated case can skip.
 * *client_end is the endpoint an inheritor probes; *serviced_end is the end the
 * test's responder drives.  Both are returned as bare descriptors.
 */
static int
create_channel_pair(int *client_end, int *serviced_end)
{
	struct mac_capability_connect_args connect;
	struct mac_capability_sendmsg_args send;
	struct mac_capability_recvmsg_args receive;
	uint32_t op;
	int control, first, second, error;

	control = open("/dev/mac_capability", O_RDWR);
	if (control == -1) {
		errno = ENODEV;
		return (-1);
	}
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, "channel", sizeof(connect.name));
	if (ioctl(control, MAC_CAPABILITY_CONNECT, &connect) == -1) {
		error = errno;
		close(control);
		errno = error != 0 ? error : ENODEV;
		return (-1);
	}
	close(control);
	first = connect.fd;

	op = CHANNEL_OP_CREATE;
	memset(&send, 0, sizeof(send));
	send.payload = &op;
	send.payload_len = sizeof(op);
	if (ioctl(first, MAC_CAPABILITY_SENDMSG, &send) == -1) {
		error = errno;
		close(first);
		errno = error;
		return (-1);
	}
	second = -1;
	memset(&receive, 0, sizeof(receive));
	receive.fds = &second;
	receive.nfds = 1;
	if (ioctl(first, MAC_CAPABILITY_RECVMSG, &receive) == -1 ||
	    receive.nfds != 1 || second < 0) {
		error = errno != 0 ? errno : EIO;
		close(first);
		errno = error;
		return (-1);
	}
	*serviced_end = first;
	*client_end = second;
	return (0);
}

/*
 * A minimal serviced-side responder that pumps one channel from a helper thread
 * and answers SVC_OP_AMBIENT_HELLO.  In RESP_LOOKUP mode it replies with the
 * magic ack (modeling domain.c's lookup channel); in RESP_ENOTSUP mode it
 * replies ENOTSUP (modeling svc_proto.c's unit control channel default), so the
 * probe must reject it.
 */
enum responder_mode {
	RESP_LOOKUP = 0,
	RESP_ENOTSUP = 1,
	RESP_MINT_CAPTURE = 2
};

struct responder {
	struct channel		*chan;
	enum responder_mode	 mode;
	pthread_t		 thread;
	volatile int		 stop;
	/* RESP_MINT_CAPTURE: the fields of the last SVC_OP_MINT_DOMAIN seen. */
	volatile int		 mint_seen;
	uint32_t		 mint_uid;
	uint32_t		 mint_domain;
};

static void
responder_request(struct channel *ch, struct channel_message *req, void *ctx)
{
	struct responder *r = ctx;
	uint32_t op = 0;

	(void)ch;
	if (channel_message_length(req) >= sizeof(op))
		memcpy(&op, channel_message_data(req), sizeof(op));
	if (op == SVC_OP_MINT_DOMAIN && r->mode == RESP_MINT_CAPTURE) {
		struct svc_mint_domain_req mreq;
		struct svc_reply rep = { .status = 0 };

		/*
		 * Capture the wire request so the test can assert which domain
		 * field service_mint_session_domain() transmitted, then reply
		 * with no attached fd — the client fails EBADMSG after the round
		 * trip, which is irrelevant to what we are checking here.
		 */
		if (channel_message_length(req) >= sizeof(mreq)) {
			memcpy(&mreq, channel_message_data(req), sizeof(mreq));
			r->mint_uid = mreq.uid;
			r->mint_domain = mreq.domain;
			r->mint_seen = 1;
		}
		(void)channel_send_reply(req, &(struct channel_outgoing){
			.size = sizeof(struct channel_outgoing),
			.data = &rep,
			.length = sizeof(rep),
		});
		channel_message_free(req);
		return;
	}
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
responder_start(struct responder *r, int serviced_end, enum responder_mode mode)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);

	memset(r, 0, sizeof(*r));
	r->mode = mode;
	if (channel_create(serviced_end, &options, &r->chan) == -1)
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
	r->chan = NULL;
}

/* ------------------------------------------------------------------ */
/* Device-free cases (run anywhere).                                   */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(absent_env_returns_minus1);
ATF_TC_BODY(absent_env_returns_minus1, tc)
{

	/* No SERVICE_LOOKUP_FD in the environment: discovery yields nothing. */
	ATF_REQUIRE_EQ(0, unsetenv(SERVICE_LOOKUP_ENV));
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
}

ATF_TC_WITHOUT_HEAD(malformed_env_returns_minus1);
ATF_TC_BODY(malformed_env_returns_minus1, tc)
{

	/* A non-numeric or out-of-range value is rejected, not misparsed. */
	ATF_REQUIRE_EQ(0, setenv(SERVICE_LOOKUP_ENV, "not-a-number", 1));
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
	ATF_REQUIRE_EQ(0, setenv(SERVICE_LOOKUP_ENV, "-3", 1));
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
	(void)unsetenv(SERVICE_LOOKUP_ENV);
}

ATF_TC_WITHOUT_HEAD(non_channel_fd_rejected);
ATF_TC_BODY(non_channel_fd_rejected, tc)
{
	int pfd[2];
	char buf[16];

	/*
	 * A SERVICE_LOOKUP_FD that names an open descriptor which is NOT a
	 * mac_capability channel (here a pipe) is rejected at the GETINFO gate,
	 * before any handshake: discovery must not hand back an arbitrary
	 * inherited fd.
	 */
	ATF_REQUIRE_EQ(0, pipe(pfd));
	(void)snprintf(buf, sizeof(buf), "%d", pfd[0]);
	ATF_REQUIRE_EQ(0, setenv(SERVICE_LOOKUP_ENV, buf, 1));
	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());
	(void)unsetenv(SERVICE_LOOKUP_ENV);
	close(pfd[0]);
	close(pfd[1]);
}

ATF_TC_WITHOUT_HEAD(install_marks_ambient_and_sets_env);
ATF_TC_BODY(install_marks_ambient_and_sets_env, tc)
{
	const char *value;
	char expected[16];
	int pfd[2], flags;

	/*
	 * service_install_ambient_lookup() makes the descriptor ambient
	 * (§21.1) and advertises its number.  The ambient marking is a property
	 * of any descriptor, so a pipe suffices to observe it.
	 */
	ATF_REQUIRE_EQ(0, pipe(pfd));
	ATF_REQUIRE_EQ(0, fcntl(pfd[0], F_SETFD, FD_CLOEXEC));

	ATF_REQUIRE_EQ(0, service_install_ambient_lookup(pfd[0]));

	/* Not close-on-exec: survives exec. */
	flags = fcntl(pfd[0], F_GETFD);
	ATF_REQUIRE(flags != -1);
	ATF_CHECK_EQ(0, flags & FD_CLOEXEC);
	/* CAP_CLOFORK_UNLOCKED accepted (idempotent): survives fork. */
	ATF_CHECK_EQ(0, cap_clofork_limit(pfd[0], CAP_CLOFORK_UNLOCKED));

	/* The environment names exactly this descriptor. */
	(void)snprintf(expected, sizeof(expected), "%d", pfd[0]);
	value = getenv(SERVICE_LOOKUP_ENV);
	ATF_REQUIRE(value != NULL);
	ATF_CHECK_STREQ(expected, value);

	(void)unsetenv(SERVICE_LOOKUP_ENV);
	close(pfd[0]);
	close(pfd[1]);
}

ATF_TC_WITHOUT_HEAD(fixed_fd_non_channel_rejected);
ATF_TC_BODY(fixed_fd_non_channel_rejected, tc)
{
	int pfd[2], saved;

	/*
	 * With SERVICE_LOOKUP_FD absent, discovery falls back to probing the
	 * getty-path fixed descriptor (SERVICE_LOOKUP_FIXED_FD).  A non-channel
	 * descriptor parked there (here a pipe) must be rejected exactly as an
	 * env-named non-channel is, so a stale or unrelated fd 3 never leaks
	 * through as an ambient channel.  This case needs no device.
	 */
	ATF_REQUIRE_EQ(0, unsetenv(SERVICE_LOOKUP_ENV));

	/* Preserve whatever the harness left at fd 3, restore it afterward. */
	saved = dup(SERVICE_LOOKUP_FIXED_FD);

	ATF_REQUIRE_EQ(0, pipe(pfd));
	ATF_REQUIRE(dup2(pfd[0], SERVICE_LOOKUP_FIXED_FD) ==
	    SERVICE_LOOKUP_FIXED_FD);

	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());

	if (SERVICE_LOOKUP_FIXED_FD != pfd[0])
		(void)close(SERVICE_LOOKUP_FIXED_FD);
	close(pfd[0]);
	close(pfd[1]);
	if (saved >= 0) {
		(void)dup2(saved, SERVICE_LOOKUP_FIXED_FD);
		close(saved);
	}
}

/* ------------------------------------------------------------------ */
/* Behavioral-handshake cases (channel device; else skip).             */
/* ------------------------------------------------------------------ */

ATF_TC(env_lookup_channel_accepted);
ATF_TC_HEAD(env_lookup_channel_accepted, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "an env-named channel that answers HELLO with the magic is accepted");
}
ATF_TC_BODY(env_lookup_channel_accepted, tc)
{
	struct responder r;
	int client_end, serviced_end, got;

	if (create_channel_pair(&client_end, &serviced_end) == -1)
		atf_tc_skip("mac_capability channel device unavailable");
	ATF_REQUIRE_EQ(0, responder_start(&r, serviced_end, RESP_LOOKUP));

	(void)unsetenv(SERVICE_LOOKUP_ENV);
	ATF_REQUIRE_EQ(0, service_install_ambient_lookup(client_end));

	got = service_ambient_lookup_fd();
	ATF_CHECK_EQ(client_end, got);

	(void)unsetenv(SERVICE_LOOKUP_ENV);
	responder_stop(&r);
	close(client_end);
}

ATF_TC(env_non_lookup_channel_rejected);
ATF_TC_HEAD(env_non_lookup_channel_rejected, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "an env-named mac_capability channel that returns ENOTSUP (a unit "
	    "control channel stand-in) is rejected, not accepted");
}
ATF_TC_BODY(env_non_lookup_channel_rejected, tc)
{
	struct responder r;
	int client_end, serviced_end;
	char buf[16];

	/*
	 * The D1 fix: this channel answers MAC_CAPABILITY_GETINFO (so the old
	 * validator accepted it) but does NOT speak the lookup protocol — it
	 * returns ENOTSUP exactly as a service's unit control channel does.  It
	 * must be rejected.
	 */
	if (create_channel_pair(&client_end, &serviced_end) == -1)
		atf_tc_skip("mac_capability channel device unavailable");
	ATF_REQUIRE_EQ(0, responder_start(&r, serviced_end, RESP_ENOTSUP));

	(void)snprintf(buf, sizeof(buf), "%d", client_end);
	ATF_REQUIRE_EQ(0, setenv(SERVICE_LOOKUP_ENV, buf, 1));

	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());

	(void)unsetenv(SERVICE_LOOKUP_ENV);
	responder_stop(&r);
	close(client_end);
}

ATF_TC(fixed_fd_lookup_channel_accepted);
ATF_TC_HEAD(fixed_fd_lookup_channel_accepted, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "env absent: a HELLO-answering channel at the fixed fd is accepted");
}
ATF_TC_BODY(fixed_fd_lookup_channel_accepted, tc)
{
	struct responder r;
	int client_end, serviced_end, saved, got;

	/*
	 * The getty-path carry: capsule pins the channel at
	 * SERVICE_LOOKUP_FIXED_FD with no environment variable set.  A genuine
	 * lookup channel parked there must pass the handshake and be returned.
	 */
	if (create_channel_pair(&client_end, &serviced_end) == -1)
		atf_tc_skip("mac_capability channel device unavailable");
	ATF_REQUIRE_EQ(0, responder_start(&r, serviced_end, RESP_LOOKUP));

	ATF_REQUIRE_EQ(0, unsetenv(SERVICE_LOOKUP_ENV));

	saved = dup(SERVICE_LOOKUP_FIXED_FD);
	ATF_REQUIRE(dup2(client_end, SERVICE_LOOKUP_FIXED_FD) ==
	    SERVICE_LOOKUP_FIXED_FD);
	if (client_end != SERVICE_LOOKUP_FIXED_FD)
		close(client_end);

	got = service_ambient_lookup_fd();
	ATF_CHECK_EQ(SERVICE_LOOKUP_FIXED_FD, got);

	responder_stop(&r);
	(void)close(SERVICE_LOOKUP_FIXED_FD);
	if (saved >= 0) {
		(void)dup2(saved, SERVICE_LOOKUP_FIXED_FD);
		close(saved);
	}
}

ATF_TC(fixed_fd_non_lookup_channel_rejected);
ATF_TC_HEAD(fixed_fd_non_lookup_channel_rejected, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "env absent: a unit-control-channel stand-in at fd 3 is rejected");
}
ATF_TC_BODY(fixed_fd_non_lookup_channel_rejected, tc)
{
	struct responder r;
	int client_end, serviced_end, saved;

	/*
	 * The core D1 scenario: a bootstrap-launched service's unit control
	 * channel sits at fd 3 (SVC_CHANNEL_FD == SERVICE_LOOKUP_FIXED_FD) and
	 * answers GETINFO.  A login or su probing fd 3 must NOT mistake it for
	 * the ambient lookup channel; the handshake returns ENOTSUP, so
	 * discovery yields -1.
	 */
	if (create_channel_pair(&client_end, &serviced_end) == -1)
		atf_tc_skip("mac_capability channel device unavailable");
	ATF_REQUIRE_EQ(0, responder_start(&r, serviced_end, RESP_ENOTSUP));

	ATF_REQUIRE_EQ(0, unsetenv(SERVICE_LOOKUP_ENV));

	saved = dup(SERVICE_LOOKUP_FIXED_FD);
	ATF_REQUIRE(dup2(client_end, SERVICE_LOOKUP_FIXED_FD) ==
	    SERVICE_LOOKUP_FIXED_FD);
	if (client_end != SERVICE_LOOKUP_FIXED_FD)
		close(client_end);

	ATF_CHECK_EQ(-1, service_ambient_lookup_fd());

	responder_stop(&r);
	(void)close(SERVICE_LOOKUP_FIXED_FD);
	if (saved >= 0) {
		(void)dup2(saved, SERVICE_LOOKUP_FIXED_FD);
		close(saved);
	}
}

ATF_TC(env_takes_precedence_over_fixed_fd);
ATF_TC_HEAD(env_takes_precedence_over_fixed_fd, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "a valid env-named lookup channel wins over the fixed-fd fallback");
}
ATF_TC_BODY(env_takes_precedence_over_fixed_fd, tc)
{
	struct responder renv, rfixed;
	int envc, envs, fixedc, fixeds, saved, got;
	char buf[16];

	/*
	 * When SERVICE_LOOKUP_FD names a live lookup channel, the env source
	 * wins even if a different lookup channel also sits at the fixed fd; the
	 * fixed fd is only a fallback for the getty hop.  Two channels are
	 * needed, so this is gated on the device.
	 */
	if (create_channel_pair(&envc, &envs) == -1)
		atf_tc_skip("mac_capability channel device unavailable");
	if (create_channel_pair(&fixedc, &fixeds) == -1) {
		close(envc);
		close(envs);
		atf_tc_skip("mac_capability channel device unavailable");
	}
	ATF_REQUIRE_EQ(0, responder_start(&renv, envs, RESP_LOOKUP));
	ATF_REQUIRE_EQ(0, responder_start(&rfixed, fixeds, RESP_LOOKUP));

	saved = dup(SERVICE_LOOKUP_FIXED_FD);
	/* Keep envc off the fixed slot so the two are distinct. */
	if (envc == SERVICE_LOOKUP_FIXED_FD) {
		int moved = fcntl(envc, F_DUPFD, SERVICE_LOOKUP_FIXED_FD + 1);

		ATF_REQUIRE(moved >= 0);
		close(envc);
		envc = moved;
	}
	ATF_REQUIRE(dup2(fixedc, SERVICE_LOOKUP_FIXED_FD) ==
	    SERVICE_LOOKUP_FIXED_FD);
	if (fixedc != SERVICE_LOOKUP_FIXED_FD)
		close(fixedc);

	(void)snprintf(buf, sizeof(buf), "%d", envc);
	ATF_REQUIRE_EQ(0, setenv(SERVICE_LOOKUP_ENV, buf, 1));

	got = service_ambient_lookup_fd();
	ATF_CHECK_EQ(envc, got);

	(void)unsetenv(SERVICE_LOOKUP_ENV);
	responder_stop(&renv);
	responder_stop(&rfixed);
	close(envc);
	(void)close(SERVICE_LOOKUP_FIXED_FD);
	if (saved >= 0) {
		(void)dup2(saved, SERVICE_LOOKUP_FIXED_FD);
		close(saved);
	}
}

/* ------------------------------------------------------------------ */
/* service_mint_session_domain() transport (§6).                        */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(mint_session_domain_rejects_bad_kind);
ATF_TC_BODY(mint_session_domain_rejects_bad_kind, tc)
{
	int out = -1;

	/*
	 * An out-of-range kind is rejected with EINVAL before any channel work,
	 * so it never coerces to a scope the caller did not ask for.  The kind is
	 * validated ahead of touching syschan, so a harmless fd (0) suffices and
	 * this case needs no device.
	 */
	errno = 0;
	ATF_CHECK_EQ(-1, service_mint_session_domain(0, (enum service_mint_kind)7,
	    1001, &out));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(-1, out);
}

/*
 * Drive service_mint_session_domain()/service_mint_user_domain() against the
 * capture responder and assert the wire `domain` field carried the expected
 * value.  Gated on the channel device.
 */
static void
check_mint_transmits_domain(const atf_tc_t *tc, bool use_wrapper,
    enum service_mint_kind kind, uid_t uid, uint32_t expect_domain)
{
	struct responder r;
	int client_end, serviced_end, out;

	(void)tc;
	if (create_channel_pair(&client_end, &serviced_end) == -1)
		atf_tc_skip("mac_capability channel device unavailable");
	ATF_REQUIRE_EQ(0, responder_start(&r, serviced_end, RESP_MINT_CAPTURE));

	/*
	 * The mint reply carries no fd, so the client returns -1 (EBADMSG); the
	 * value under test is the captured request, read after responder_stop()
	 * joins the pump thread (happens-before).
	 */
	out = -1;
	if (use_wrapper)
		(void)service_mint_user_domain(client_end, uid, &out);
	else
		(void)service_mint_session_domain(client_end, kind, uid, &out);

	responder_stop(&r);

	ATF_CHECK_EQ(1, r.mint_seen);
	ATF_CHECK_EQ(expect_domain, r.mint_domain);
	ATF_CHECK_EQ((uint32_t)uid, r.mint_uid);
	if (out >= 0)
		close(out);
	close(client_end);
}

ATF_TC(mint_session_domain_user_sets_wire_user);
ATF_TC_HEAD(mint_session_domain_user_sets_wire_user, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "SERVICE_MINT_USER transmits domain == SVC_MINT_DOMAIN_USER");
}
ATF_TC_BODY(mint_session_domain_user_sets_wire_user, tc)
{

	check_mint_transmits_domain(tc, false, SERVICE_MINT_USER, 1001,
	    SVC_MINT_DOMAIN_USER);
}

ATF_TC(mint_session_domain_system_sets_wire_system);
ATF_TC_HEAD(mint_session_domain_system_sets_wire_system, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "SERVICE_MINT_SYSTEM transmits domain == SVC_MINT_DOMAIN_SYSTEM");
}
ATF_TC_BODY(mint_session_domain_system_sets_wire_system, tc)
{

	check_mint_transmits_domain(tc, false, SERVICE_MINT_SYSTEM, 0,
	    SVC_MINT_DOMAIN_SYSTEM);
}

ATF_TC(mint_user_domain_wrapper_sets_wire_user);
ATF_TC_HEAD(mint_user_domain_wrapper_sets_wire_user, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "the service_mint_user_domain() compat wrapper transmits the USER "
	    "domain (SVC_MINT_DOMAIN_USER), preserving existing-caller behavior");
}
ATF_TC_BODY(mint_user_domain_wrapper_sets_wire_user, tc)
{

	check_mint_transmits_domain(tc, true, SERVICE_MINT_USER, 4242,
	    SVC_MINT_DOMAIN_USER);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, absent_env_returns_minus1);
	ATF_TP_ADD_TC(tp, malformed_env_returns_minus1);
	ATF_TP_ADD_TC(tp, non_channel_fd_rejected);
	ATF_TP_ADD_TC(tp, install_marks_ambient_and_sets_env);
	ATF_TP_ADD_TC(tp, fixed_fd_non_channel_rejected);
	ATF_TP_ADD_TC(tp, env_lookup_channel_accepted);
	ATF_TP_ADD_TC(tp, env_non_lookup_channel_rejected);
	ATF_TP_ADD_TC(tp, fixed_fd_lookup_channel_accepted);
	ATF_TP_ADD_TC(tp, fixed_fd_non_lookup_channel_rejected);
	ATF_TP_ADD_TC(tp, env_takes_precedence_over_fixed_fd);
	ATF_TP_ADD_TC(tp, mint_session_domain_rejects_bad_kind);
	ATF_TP_ADD_TC(tp, mint_session_domain_user_sets_wire_user);
	ATF_TP_ADD_TC(tp, mint_session_domain_system_sets_wire_system);
	ATF_TP_ADD_TC(tp, mint_user_domain_wrapper_sets_wire_user);
	return (atf_no_error());
}
