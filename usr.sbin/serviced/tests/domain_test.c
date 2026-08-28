/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Lookup-domain scoping (§22) and minted user-domain channel (§21) tests.
 *
 * The pure-logic cases (allow-list scoping, mint authorization, the ambient
 * descriptor marking, and the ENOENT indistinguishability that hides an
 * out-of-scope name) run anywhere.  The end-to-end case that mints a real
 * user-domain channel and performs a USER-scoped lookup over it needs the
 * mac_capability channel device and is gated on root; it skips cleanly when the
 * device is unavailable.
 *
 * The implementation is included directly so the domain scope decision and the
 * private lookup-channel registry can be driven without a live serviced.
 * Function/data sections let the linker discard the unrelated broker paths.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <channel.h>

#include "libservice.h"

#include "../domain.c"
#include "../naming.c"

struct serviced_state sd;
int serviced_kq = -1;

/*
 * A system-only provider name (never on the user allow-list) and the two
 * allow-listed names.  Keep these in sync with user_system_allow[] in domain.c.
 */
#define	SYSTEM_ONLY_NAME	"org.5bsd.Storage"
#define	ALLOW_LOG_NAME		"org.5bsd.Log"
#define	ALLOW_NOTIFY_NAME	"org.5bsd.Notify"

/*
 * Leaf serviced symbols owned by other translation units.  The scope-decision
 * and mint paths under test reach these only on branches that do not run in the
 * unit environment (an out-of-scope or unregistered lookup returns before the
 * broker touches them), but the references must resolve at link time.
 */
int
serviced_fd_budget_check(size_t count, const char *what)
{

	(void)count;
	(void)what;
	return (0);
}

int
svc_channel_send_event(struct svc_runtime *svc, const void *data, size_t length,
    const int *fds, size_t nfds, int kq)
{

	(void)svc;
	(void)data;
	(void)length;
	(void)fds;
	(void)nfds;
	(void)kq;
	return (0);
}

void
cancel_idle_timer(struct svc_runtime *svc, int kq)
{

	(void)svc;
	(void)kq;
}

/*
 * mac_cap_create_channel is stubbed to produce a genuine mac_capability channel
 * pair via the channel device, so domain_mint_user_channel builds a real
 * serviced-side channel.  Without the device (non-root or no kernel support) it
 * fails with ENODEV and the gated test skips.  The pure-logic tests never call
 * it.
 */
int
mac_cap_create_channel(int *our_end, int *child_end)
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
		errno = error;
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
	(void)fcntl(first, F_SETFD, FD_CLOEXEC);
	(void)fcntl(second, F_SETFD, FD_CLOEXEC);
	*our_end = first;
	*child_end = second;
	return (0);
}

static void
provider_register(struct svc_runtime *svc, const char *name)
{

	memset(svc, 0, sizeof(*svc));
	strlcpy(svc->manifest.label, "org.5bsd.test.provider",
	    sizeof(svc->manifest.label));
	strlcpy(svc->manifest.provides[0], name,
	    sizeof(svc->manifest.provides[0]));
	svc->manifest.nprovides = 1;
	svc->protocol_ready = true;
	svc->state = SVC_STATE_RUNNING;
	ATF_REQUIRE_EQ(0, naming_register(name, svc));
	ATF_REQUIRE(naming_exists(name));
}

/* ------------------------------------------------------------------ */
/* Pure-logic cases (run anywhere).                                    */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(scope_system_resolves_all);
ATF_TC_BODY(scope_system_resolves_all, tc)
{
	struct svc_domain system = { .kind = SVC_DOMAIN_SYSTEM, .uid = 0 };

	/* SYSTEM (and a NULL domain) resolves every name, allow-listed or not. */
	ATF_CHECK(svc_domain_resolves(&system, SYSTEM_ONLY_NAME));
	ATF_CHECK(svc_domain_resolves(&system, ALLOW_LOG_NAME));
	ATF_CHECK(svc_domain_resolves(&system, "org.5bsd.Identity"));
	ATF_CHECK(svc_domain_resolves(NULL, SYSTEM_ONLY_NAME));
}

ATF_TC_WITHOUT_HEAD(scope_user_allow_list);
ATF_TC_BODY(scope_user_allow_list, tc)
{
	struct svc_domain user = { .kind = SVC_DOMAIN_USER, .uid = 1001 };

	/* USER resolves only the explicit system allow-list. */
	ATF_CHECK(svc_domain_resolves(&user, ALLOW_LOG_NAME));
	ATF_CHECK(svc_domain_resolves(&user, ALLOW_NOTIFY_NAME));
	/* Privileged system-only providers are invisible. */
	ATF_CHECK(!svc_domain_resolves(&user, SYSTEM_ONLY_NAME));
	ATF_CHECK(!svc_domain_resolves(&user, "org.5bsd.Identity"));
	ATF_CHECK(!svc_domain_resolves(&user, "org.5bsd.KernelModule"));
	/* No user-scoped services exist yet, so an unknown user name is denied. */
	ATF_CHECK(!svc_domain_resolves(&user, "org.5bsd.user.Thing"));
}

ATF_TC_WITHOUT_HEAD(mint_authorization);
ATF_TC_BODY(mint_authorization, tc)
{
	struct svc_domain system = { .kind = SVC_DOMAIN_SYSTEM, .uid = 0 };
	struct svc_domain user = { .kind = SVC_DOMAIN_USER, .uid = 1001 };

	/* Only a SYSTEM caller may mint; domains only narrow, never broaden. */
	ATF_CHECK(svc_domain_may_mint(&system));
	ATF_CHECK(svc_domain_may_mint(NULL));
	ATF_CHECK(!svc_domain_may_mint(&user));
}

ATF_TC_WITHOUT_HEAD(ambient_descriptor_marking);
ATF_TC_BODY(ambient_descriptor_marking, tc)
{
	int sv[2], flags;

	/*
	 * The ambient marking (§21.1) survives every fork and survives exec.
	 * cap_clofork_limit / fcntl work on any descriptor, so this needs no
	 * capability kernel.
	 */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	ATF_REQUIRE_EQ(0, fcntl(sv[0], F_SETFD, FD_CLOEXEC));

	ATF_REQUIRE_EQ(0, svc_fd_make_ambient(sv[0]));

	/* Not close-on-exec: survives exec. */
	flags = fcntl(sv[0], F_GETFD);
	ATF_REQUIRE(flags != -1);
	ATF_CHECK_EQ(0, flags & FD_CLOEXEC);
	/* CAP_CLOFORK_UNLOCKED accepted (idempotent): survives fork. */
	ATF_CHECK_EQ(0, cap_clofork_limit(sv[0], CAP_CLOFORK_UNLOCKED));

	close(sv[0]);
	close(sv[1]);
}

ATF_TC_WITHOUT_HEAD(default_requester_is_system);
ATF_TC_BODY(default_requester_is_system, tc)
{
	struct svc_runtime requester;
	int error, rv;

	/*
	 * A zero-initialized (unmarked) requester defaults to SVC_DOMAIN_SYSTEM,
	 * so a lookup of an unregistered name returns ENOENT exactly as before —
	 * the domain layer does not change the default path.
	 */
	memset(&requester, 0, sizeof(requester));
	ATF_CHECK_EQ(SVC_DOMAIN_SYSTEM, requester.domain.kind);
	error = 0;
	rv = naming_lookup("org.5bsd.Nonexistent", &requester,
	    &requester.domain, &error);
	ATF_CHECK_EQ(-1, rv);
	ATF_CHECK_EQ(ENOENT, error);
}

ATF_TC_WITHOUT_HEAD(user_scope_hides_registered_name);
ATF_TC_BODY(user_scope_hides_registered_name, tc)
{
	struct svc_runtime provider;
	struct svc_domain user = { .kind = SVC_DOMAIN_USER, .uid = 1001 };
	int error, rv;

	/*
	 * A system-only name that IS registered is invisible to a USER domain:
	 * the scope check runs before the registry, returns ENOENT, and never
	 * mints a channel.  ENOENT is therefore indistinguishable from a name
	 * that was never registered — the requester learns nothing.
	 */
	provider_register(&provider, SYSTEM_ONLY_NAME);

	error = 0;
	rv = naming_lookup(SYSTEM_ONLY_NAME, NULL, &user, &error);
	ATF_CHECK_EQ(-1, rv);
	ATF_CHECK_EQ(ENOENT, error);		/* registered, but out of scope */

	error = 0;
	rv = naming_lookup("org.5bsd.NeverRegistered", NULL, &user, &error);
	ATF_CHECK_EQ(-1, rv);
	ATF_CHECK_EQ(ENOENT, error);		/* unregistered: same answer */

	naming_remove_owner(&provider);
}

/* ------------------------------------------------------------------ */
/* End-to-end minted-channel case (root + channel device; else skip).  */
/* ------------------------------------------------------------------ */

struct pump_ctx {
	int		kq;
	volatile int	stop;
};

static void *
domain_pump_thread(void *argument)
{
	struct pump_ctx *ctx = argument;
	struct kevent ev;
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 20 * 1000 * 1000 };

	while (!ctx->stop) {
		int n = kevent(ctx->kq, NULL, 0, &ev, 1, &ts);

		if (n == 1)
			domain_channel_event(&ev, ctx->kq);
	}
	return (NULL);
}

ATF_TC(minted_channel_user_scoped);
ATF_TC_HEAD(minted_channel_user_scoped, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "a minted channel is tagged {USER,uid}, is ambient, and scopes "
	    "lookups to the user domain");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(minted_channel_user_scoped, tc)
{
	struct svc_runtime provider;
	struct svc_lookup_req req;
	struct svc_reply reply_data;
	struct service_message message = {
		.size = sizeof(message),
		.data = &req,
		.length = sizeof(req),
	};
	int reply_fd = -1;
	struct service_reply reply = {
		.size = sizeof(reply),
		.data = &reply_data,
		.capacity = sizeof(reply_data),
		.fds = &reply_fd,
		.fd_capacity = 1,
	};
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_session *session;
	struct pump_ctx ctx;
	pthread_t pump;
	int minted_fd, flags, kq, dupfd;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	serviced_kq = kq;

	minted_fd = -1;
	if (domain_mint_user_channel(4321, &minted_fd, kq) == -1) {
		if (errno == ENODEV)
			atf_tc_skip("mac_capability channel device unavailable");
		atf_tc_fail("domain_mint_user_channel: %s", strerror(errno));
	}

	/* The serviced-side registry entry is tagged {USER, uid}. */
	ATF_REQUIRE(lookup_channels != NULL);
	ATF_CHECK_EQ(SVC_DOMAIN_USER, lookup_channels->domain.kind);
	ATF_CHECK_EQ(4321, lookup_channels->domain.uid);

	/* The returned descriptor is ambient: not close-on-exec, unlocked. */
	flags = fcntl(minted_fd, F_GETFD);
	ATF_REQUIRE(flags != -1);
	ATF_CHECK_EQ(0, flags & FD_CLOEXEC);
	ATF_CHECK_EQ(0, cap_clofork_limit(minted_fd, CAP_CLOFORK_UNLOCKED));

	/* Register a system-only provider that a USER domain must not see. */
	provider_register(&provider, SYSTEM_ONLY_NAME);

	/* Pump the serviced side of the minted channel from a helper thread. */
	ctx.kq = kq;
	ctx.stop = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&pump, NULL, domain_pump_thread, &ctx));

	/* Client side: a USER-scoped lookup of the system-only name is ENOENT. */
	dupfd = fcntl(minted_fd, F_DUPFD_CLOEXEC, 0);
	ATF_REQUIRE(dupfd >= 0);
	ATF_REQUIRE_EQ(0, service_session_create(dupfd, &session));

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_LOOKUP;
	strlcpy(req.name, SYSTEM_ONLY_NAME, sizeof(req.name));
	options.timeout_ms = 2000;

	ATF_CHECK_EQ(0, service_session_call(session, &message, &reply,
	    &options));
	ATF_CHECK_EQ(sizeof(reply_data), reply.length);
	ATF_CHECK_EQ(ENOENT, reply_data.status);
	ATF_CHECK_EQ(0, reply.nfds);

	ctx.stop = 1;
	(void)pthread_join(pump, NULL);
	service_session_close(session);
	naming_remove_owner(&provider);
	domain_channel_teardown();
	close(minted_fd);
	close(kq);
}

ATF_TC(minted_system_channel_scoped);
ATF_TC_HEAD(minted_system_channel_scoped, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "the SYSTEM ambient channel serviced installs before /etc/rc is "
	    "tagged {SYSTEM}, is ambient, and resolves system-only names that a "
	    "user domain would hide");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(minted_system_channel_scoped, tc)
{
	struct svc_runtime provider;
	struct svc_lookup_req req;
	struct svc_reply reply_data;
	struct service_message message = {
		.size = sizeof(message),
		.data = &req,
		.length = sizeof(req),
	};
	int reply_fd = -1;
	struct service_reply reply = {
		.size = sizeof(reply),
		.data = &reply_data,
		.capacity = sizeof(reply_data),
		.fds = &reply_fd,
		.fd_capacity = 1,
	};
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_session *session;
	struct pump_ctx ctx;
	pthread_t pump;
	int minted_fd, flags, kq, dupfd;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	serviced_kq = kq;

	minted_fd = -1;
	if (domain_mint_system_channel(&minted_fd, kq) == -1) {
		if (errno == ENODEV)
			atf_tc_skip("mac_capability channel device unavailable");
		atf_tc_fail("domain_mint_system_channel: %s", strerror(errno));
	}

	/* The serviced-side registry entry is tagged {SYSTEM}: it resolves all. */
	ATF_REQUIRE(lookup_channels != NULL);
	ATF_CHECK_EQ(SVC_DOMAIN_SYSTEM, lookup_channels->domain.kind);

	/* The returned descriptor is ambient: not close-on-exec, unlocked. */
	flags = fcntl(minted_fd, F_GETFD);
	ATF_REQUIRE(flags != -1);
	ATF_CHECK_EQ(0, flags & FD_CLOEXEC);
	ATF_CHECK_EQ(0, cap_clofork_limit(minted_fd, CAP_CLOFORK_UNLOCKED));

	/* Register a system-only provider a USER domain would never see. */
	provider_register(&provider, SYSTEM_ONLY_NAME);

	ctx.kq = kq;
	ctx.stop = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&pump, NULL, domain_pump_thread, &ctx));

	/*
	 * Client side: a SYSTEM-scoped lookup of the system-only name RESOLVES
	 * (status 0, one attached channel), the exact opposite of the USER-domain
	 * channel that hides it (minted_channel_user_scoped).  This is the channel
	 * a login mint narrows FROM.
	 */
	dupfd = fcntl(minted_fd, F_DUPFD_CLOEXEC, 0);
	ATF_REQUIRE(dupfd >= 0);
	ATF_REQUIRE_EQ(0, service_session_create(dupfd, &session));

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_LOOKUP;
	strlcpy(req.name, SYSTEM_ONLY_NAME, sizeof(req.name));
	options.timeout_ms = 2000;

	ATF_CHECK_EQ(0, service_session_call(session, &message, &reply,
	    &options));
	ATF_CHECK_EQ(sizeof(reply_data), reply.length);
	ATF_CHECK_EQ(0, reply_data.status);
	ATF_CHECK_EQ(1, reply.nfds);
	if (reply_fd >= 0)
		close(reply_fd);

	ctx.stop = 1;
	(void)pthread_join(pump, NULL);
	service_session_close(session);
	naming_remove_owner(&provider);
	domain_channel_teardown();
	close(minted_fd);
	close(kq);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, scope_system_resolves_all);
	ATF_TP_ADD_TC(tp, scope_user_allow_list);
	ATF_TP_ADD_TC(tp, mint_authorization);
	ATF_TP_ADD_TC(tp, ambient_descriptor_marking);
	ATF_TP_ADD_TC(tp, default_requester_is_system);
	ATF_TP_ADD_TC(tp, user_scope_hides_registered_name);
	ATF_TP_ADD_TC(tp, minted_channel_user_scoped);
	ATF_TP_ADD_TC(tp, minted_system_channel_scoped);
	return (atf_no_error());
}
