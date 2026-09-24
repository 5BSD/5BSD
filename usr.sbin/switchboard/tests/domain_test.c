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
 * private lookup-channel registry can be driven without a live switchboard.
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
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <channel.h>

#include "libservice.h"
#include "service_bootstrap.h"

#include "../anoint.c"
#include "../domain.c"
#include "../naming.c"

/* These tests exercise name visibility; lifecycle identity has its own suite. */
int
svc_lifecycle_client(struct svc_runtime *svc __unused,
    struct svc_runtime *provider __unused,
    struct svc_new_client_msg *msg __unused)
{
	return (0);
}

struct switchboard_state sd;
int switchboard_kq = -1;

/*
 * A system-only provider name (no USER visibility) and the two names the base
 * system marks resolvable_by = ["user"].  The fixture stubs below model the
 * bundle-registry visibility that svc_name_user_resolvable() consults.
 */
#define	SYSTEM_ONLY_NAME	"system.Filesystem"
#define	ALLOW_LOG_NAME		"system.Log"
#define	ALLOW_NOTIFY_NAME	"system.Notify"

/*
 * Leaf switchboard symbols owned by other translation units.  The scope-decision
 * and mint paths under test reach these only on branches that do not run in the
 * unit environment (an out-of-scope or unregistered lookup returns before the
 * broker touches them), but the references must resolve at link time.
 */
int
switchboard_fd_budget_check(size_t count, const char *what)
{

	(void)count;
	(void)what;
	return (0);
}

/*
 * The capability control adoption (sctl.c) is not linked into this unit; the
 * SWITCHBOARD_CONTROL_NAME self-serve path is exercised by the VM integration test,
 * not here.  Take ownership of the provider fd (close it) and report success.
 */
int
sctl_adopt_channel(int provider_fd, uint64_t rights, bool capsule_relay)
{

	(void)rights;
	(void)capsule_relay;
	if (provider_fd >= 0)
		(void)close(provider_fd);
	return (0);
}

/*
 * On-demand activation lives in on_demand.c (not linked here).  The unit tests
 * exercise only the direct resolve/miss paths, where a miss returns ENOENT
 * without activating, so the stub simply reports "no on-demand launch".
 */
int
on_demand_launch_ambient(const char *name, struct svc_lookup_channel *lc,
    const struct svc_domain *domain, struct channel_message *request, int kq)
{

	(void)name;
	(void)lc;
	(void)domain;
	(void)request;
	(void)kq;
	errno = ENOENT;
	return (-1);
}

void
on_demand_lookup_channel_gone(struct svc_lookup_channel *lc, int kq)
{

	(void)lc;
	(void)kq;
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
 * Bundle-registry / manifest fixture for svc_name_user_resolvable() (domain.c).
 * USER-domain resolution now consults each provider's manifest visibility
 * (resolvable_by = ["user"]) rather than a list baked into switchboard; model that
 * here without a live bundle registry.  system.Log and system.Notify are the
 * base system's user-visible names; every other name is SYSTEM-only.  The
 * lookup->get->service->user_resolvable call chain is synchronous and
 * single-threaded, so a static carries the decision across it.
 */
static bool fixture_user_resolvable;

int
bundle_registry_lookup(const char *name, unsigned *bundle_idx,
    unsigned *service_idx)
{

	fixture_user_resolvable = (strcmp(name, ALLOW_LOG_NAME) == 0 ||
	    strcmp(name, ALLOW_NOTIFY_NAME) == 0);
	*bundle_idx = 0;
	*service_idx = 0;
	return (0);	/* all names are "known"; visibility decides the outcome */
}

struct capbundle *
bundle_registry_get(unsigned idx)
{
	static int token;

	(void)idx;
	return ((struct capbundle *)&token);
}

struct capbundle_service *
capbundle_service(const struct capbundle *b, unsigned i)
{
	static int token;

	(void)b;
	(void)i;
	return ((struct capbundle_service *)&token);
}

bool
capbundle_svc_user_resolvable(const struct capbundle_service *s)
{

	(void)s;
	return (fixture_user_resolvable);
}

/*
 * IPC anointments: this suite models only OPEN endpoints (no requires), so
 * the anointment layer is inert here and every name's visibility is decided
 * by resolvable_by exactly as before.  anoint_test.c owns the gated cases.
 */
int
capbundle_svc_provides_index(const struct capbundle_service *s,
    const char *name)
{

	(void)s;
	(void)name;
	return (-1);
}

unsigned
capbundle_svc_nrequires(const struct capbundle_service *s,
    unsigned provides_idx)
{

	(void)s;
	(void)provides_idx;
	return (0);
}

const char *
capbundle_svc_requires(const struct capbundle_service *s,
    unsigned provides_idx, unsigned j)
{

	(void)s;
	(void)provides_idx;
	(void)j;
	return (NULL);
}

/*
 * mac_cap_create_channel is stubbed to produce a genuine mac_capability channel
 * pair via the channel device, so domain_mint_user_channel builds a real
 * switchboard-side channel.  Without the device (non-root or no kernel support) it
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
	ATF_REQUIRE_EQ(0, naming_register(name, svc, false));
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

ATF_TC_WITHOUT_HEAD(mint_domain_kind_escalation_guard);
ATF_TC_BODY(mint_domain_kind_escalation_guard, tc)
{
	struct svc_domain system = { .kind = SVC_DOMAIN_SYSTEM, .uid = 0 };
	struct svc_domain user = { .kind = SVC_DOMAIN_USER, .uid = 1001 };
	enum svc_domain_kind kind;

	/*
	 * The SYSTEM-mint escalation guard (§6), unit-tested deterministically.
	 * svc_mint_domain_kind() resolves the wire `domain` field to the kind to
	 * mint AND refuses a SYSTEM request from any channel that is not itself
	 * SYSTEM — a user session must never widen its own scope.
	 */

	/* A SYSTEM channel may request either kind. */
	kind = (enum svc_domain_kind)0xdead;
	ATF_CHECK_EQ(0, svc_mint_domain_kind(&system, SVC_MINT_DOMAIN_USER,
	    &kind));
	ATF_CHECK_EQ(SVC_DOMAIN_USER, kind);
	kind = (enum svc_domain_kind)0xdead;
	ATF_CHECK_EQ(0, svc_mint_domain_kind(&system, SVC_MINT_DOMAIN_SYSTEM,
	    &kind));
	ATF_CHECK_EQ(SVC_DOMAIN_SYSTEM, kind);

	/* A NULL requester is the default authority (SYSTEM): may ask SYSTEM. */
	kind = (enum svc_domain_kind)0xdead;
	ATF_CHECK_EQ(0, svc_mint_domain_kind(NULL, SVC_MINT_DOMAIN_SYSTEM,
	    &kind));
	ATF_CHECK_EQ(SVC_DOMAIN_SYSTEM, kind);

	/*
	 * The adversarial case: a USER channel asking for SYSTEM is REFUSED with
	 * EPERM.  This is the privilege boundary the guard exists to hold.
	 */
	errno = 0;
	ATF_CHECK_EQ(-1, svc_mint_domain_kind(&user, SVC_MINT_DOMAIN_SYSTEM,
	    &kind));
	ATF_CHECK_EQ(EPERM, errno);

	/*
	 * A USER channel asking for USER passes this resolver (the kind itself is
	 * in-policy); minting is still blocked one layer up by svc_domain_may_mint
	 * — a USER channel may not mint AT ALL — verified in mint_authorization
	 * and end-to-end in user_channel_mints_neither.
	 */
	kind = (enum svc_domain_kind)0xdead;
	ATF_CHECK_EQ(0, svc_mint_domain_kind(&user, SVC_MINT_DOMAIN_USER,
	    &kind));
	ATF_CHECK_EQ(SVC_DOMAIN_USER, kind);

	/* An unknown wire domain value is EINVAL, never silently coerced. */
	errno = 0;
	ATF_CHECK_EQ(-1, svc_mint_domain_kind(&system, 0x5eU, &kind));
	ATF_CHECK_EQ(EINVAL, errno);
}

ATF_TC_WITHOUT_HEAD(control_domain_separation);
ATF_TC_BODY(control_domain_separation, tc)
{
	struct svc_domain system = { .kind = SVC_DOMAIN_SYSTEM, .uid = 0 };
	struct svc_domain user = { .kind = SVC_DOMAIN_USER, .uid = 1001 };
	struct svc_domain control = { .kind = SVC_DOMAIN_CONTROL, .uid = 0 };
	enum svc_domain_kind kind;

	/* Names are classified control by the reserved ".Control" namespace. */
	ATF_CHECK(name_is_control("service.Control"));
	ATF_CHECK(name_is_control("lifecycle.Control"));
	ATF_CHECK(name_is_control("storage.Control"));
	ATF_CHECK(!name_is_control("system.Network"));
	ATF_CHECK(!name_is_control("org.5bsd.ControlPanel")); /* not a component */
	ATF_CHECK(!name_is_control("Control"));		      /* no dot */
	/* The reserved helper. namespace is never a control name. */
	ATF_CHECK(!name_is_control("helper.org.5bsd.Net.Control"));

	/* WORKS: a control name resolves through a CONTROL channel. */
	ATF_CHECK(svc_domain_permits(&control, SVC_DOMAIN_CONTROL,
	    "service.Control"));

	/* DOESN'T: SYSTEM/USER/NULL channels cannot see a control name. */
	ATF_CHECK(!svc_domain_permits(&system, SVC_DOMAIN_CONTROL,
	    "service.Control"));
	ATF_CHECK(!svc_domain_permits(&user, SVC_DOMAIN_CONTROL,
	    "service.Control"));
	ATF_CHECK(!svc_domain_permits(NULL, SVC_DOMAIN_CONTROL,
	    "lifecycle.Control"));

	/* DOESN'T: a CONTROL channel resolves nothing but control names. */
	ATF_CHECK(!svc_domain_permits(&control, SVC_DOMAIN_SYSTEM,
	    SYSTEM_ONLY_NAME));
	ATF_CHECK(!svc_domain_permits(&control, SVC_DOMAIN_SYSTEM,
	    ALLOW_LOG_NAME));

	/* SYSTEM/USER behave exactly as before for non-control names. */
	ATF_CHECK(svc_domain_permits(&system, SVC_DOMAIN_SYSTEM,
	    SYSTEM_ONLY_NAME));
	ATF_CHECK(svc_domain_permits(&user, SVC_DOMAIN_SYSTEM, ALLOW_LOG_NAME));
	ATF_CHECK(!svc_domain_permits(&user, SVC_DOMAIN_SYSTEM,
	    SYSTEM_ONLY_NAME));

	/* Minting: only a SYSTEM (admin) channel may mint CONTROL; USER cannot. */
	kind = (enum svc_domain_kind)0xdead;
	ATF_CHECK_EQ(0, svc_mint_domain_kind(&system, SVC_MINT_DOMAIN_CONTROL,
	    &kind));
	ATF_CHECK_EQ(SVC_DOMAIN_CONTROL, kind);
	errno = 0;
	ATF_CHECK_EQ(-1, svc_mint_domain_kind(&user, SVC_MINT_DOMAIN_CONTROL,
	    &kind));
	ATF_CHECK_EQ(EPERM, errno);
}

ATF_TC_WITHOUT_HEAD(control_ondemand_gating);
ATF_TC_BODY(control_ondemand_gating, tc)
{
	struct svc_domain system = { .kind = SVC_DOMAIN_SYSTEM, .uid = 0 };
	struct svc_domain control = { .kind = SVC_DOMAIN_CONTROL, .uid = 0 };
	int error, rv;

	/*
	 * The control and service planes never cross for on-demand, either.
	 * These names are unregistered, so naming_lookup() takes the not-found
	 * branch and decides ENOENT (on-demand-eligible) vs EACCES (out of
	 * scope, no launch).
	 */

	/* A SYSTEM channel must NOT be able to force-launch a control name. */
	error = 0;
	rv = naming_lookup("service.Control", NULL, &system, NULL, &error,
	    NULL);
	ATF_CHECK_EQ(-1, rv);
	ATF_CHECK_EQ(EACCES, error);

	/* A CONTROL channel MAY on-demand its own control name. */
	error = 0;
	rv = naming_lookup("service.Control", NULL, &control, NULL, &error,
	    NULL);
	ATF_CHECK_EQ(-1, rv);
	ATF_CHECK_EQ(ENOENT, error);

	/* A CONTROL channel must NOT on-demand a non-control name. */
	error = 0;
	rv = naming_lookup(SYSTEM_ONLY_NAME, NULL, &control, NULL, &error,
	    NULL);
	ATF_CHECK_EQ(-1, rv);
	ATF_CHECK_EQ(EACCES, error);
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
	    &requester.domain, NULL, &error, NULL);
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
	 * A system-only name that is out of a USER domain's scope never mints a
	 * channel, whether it is registered or not.  naming_lookup() signals the
	 * out-of-scope case with EACCES *internally* so the caller fails fast
	 * (no on-demand launch the requester could never reach); the caller then
	 * maps EACCES to ENOENT on the wire, so the requester still cannot tell
	 * an out-of-scope name from an unregistered one (verified in the channel
	 * cases below).
	 */
	provider_register(&provider, SYSTEM_ONLY_NAME);

	error = 0;
	rv = naming_lookup(SYSTEM_ONLY_NAME, NULL, &user, NULL, &error, NULL);
	ATF_CHECK_EQ(-1, rv);
	ATF_CHECK_EQ(EACCES, error);		/* registered, but out of scope */

	error = 0;
	rv = naming_lookup("org.5bsd.NeverRegistered", NULL, &user, NULL,
	    &error, NULL);
	ATF_CHECK_EQ(-1, rv);
	ATF_CHECK_EQ(EACCES, error);		/* unregistered + out of scope */

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
	switchboard_kq = kq;

	minted_fd = -1;
	if (domain_mint_user_channel(4321, &minted_fd, kq) == -1) {
		if (errno == ENODEV)
			atf_tc_skip("mac_capability channel device unavailable");
		atf_tc_fail("domain_mint_user_channel: %s", strerror(errno));
	}

	/* The switchboard-side registry entry is tagged {USER, uid}. */
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

	/* Pump the switchboard side of the minted channel from a helper thread. */
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
	    "the SYSTEM ambient channel switchboard installs before /etc/rc is "
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
	switchboard_kq = kq;

	minted_fd = -1;
	if (domain_mint_system_channel(&minted_fd, kq) == -1) {
		if (errno == ENODEV)
			atf_tc_skip("mac_capability channel device unavailable");
		atf_tc_fail("domain_mint_system_channel: %s", strerror(errno));
	}

	/* The switchboard-side registry entry is tagged {SYSTEM}: it resolves all. */
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

/*
 * Drive the SVC_OP_AMBIENT_HELLO handshake against a minted lookup channel of
 * the given kind and assert the magic ack.  This is the switchboard side of the
 * D1 behavioral probe: a lookup channel answers HELLO with status 0 and
 * SVC_AMBIENT_HELLO_MAGIC.  Gated on the channel device.
 */
static void
hello_ack_over_minted_channel(const atf_tc_t *tc, enum svc_domain_kind kind)
{
	struct svc_ambient_hello_req req;
	struct svc_ambient_hello_reply reply_data;
	struct service_message message = {
		.size = sizeof(message),
		.data = &req,
		.length = sizeof(req),
	};
	struct service_reply reply = {
		.size = sizeof(reply),
		.data = &reply_data,
		.capacity = sizeof(reply_data),
	};
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_session *session;
	struct pump_ctx ctx;
	pthread_t pump;
	int minted_fd, kq, dupfd, rv;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;

	minted_fd = -1;
	if (kind == SVC_DOMAIN_USER)
		rv = domain_mint_user_channel(4321, &minted_fd, kq);
	else
		rv = domain_mint_system_channel(&minted_fd, kq);
	if (rv == -1) {
		if (errno == ENODEV)
			atf_tc_skip("mac_capability channel device unavailable");
		atf_tc_fail("domain_mint_*_channel: %s", strerror(errno));
	}

	ctx.kq = kq;
	ctx.stop = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&pump, NULL, domain_pump_thread, &ctx));

	dupfd = fcntl(minted_fd, F_DUPFD_CLOEXEC, 0);
	ATF_REQUIRE(dupfd >= 0);
	ATF_REQUIRE_EQ(0, service_session_create(dupfd, &session));

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_AMBIENT_HELLO;
	memset(&reply_data, 0, sizeof(reply_data));
	options.timeout_ms = 2000;

	ATF_CHECK_EQ(0, service_session_call(session, &message, &reply,
	    &options));
	ATF_CHECK_EQ(sizeof(reply_data), reply.length);
	ATF_CHECK_EQ(0, reply_data.status);
	ATF_CHECK_EQ(SVC_AMBIENT_HELLO_MAGIC, reply_data.magic);
	ATF_CHECK_EQ(0, reply.nfds);

	ctx.stop = 1;
	(void)pthread_join(pump, NULL);
	service_session_close(session);
	domain_channel_teardown();
	close(minted_fd);
	close(kq);
	(void)tc;
}

ATF_TC(hello_ack_over_user_channel);
ATF_TC_HEAD(hello_ack_over_user_channel, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "a USER lookup channel answers SVC_OP_AMBIENT_HELLO with the magic");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(hello_ack_over_user_channel, tc)
{

	hello_ack_over_minted_channel(tc, SVC_DOMAIN_USER);
}

ATF_TC(hello_ack_over_system_channel);
ATF_TC_HEAD(hello_ack_over_system_channel, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "a SYSTEM lookup channel answers SVC_OP_AMBIENT_HELLO with the magic");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(hello_ack_over_system_channel, tc)
{

	hello_ack_over_minted_channel(tc, SVC_DOMAIN_SYSTEM);
}

ATF_TC(unknown_op_over_lookup_channel_enotsup);
ATF_TC_HEAD(unknown_op_over_lookup_channel_enotsup, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "an unrecognized op on a lookup channel returns ENOTSUP — the same "
	    "default a unit control channel gives SVC_OP_AMBIENT_HELLO, which is "
	    "the discriminator the ambient probe relies on");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(unknown_op_over_lookup_channel_enotsup, tc)
{
	uint32_t op;
	struct svc_reply reply_data;
	struct service_message message = {
		.size = sizeof(message),
		.data = &op,
		.length = sizeof(op),
	};
	struct service_reply reply = {
		.size = sizeof(reply),
		.data = &reply_data,
		.capacity = sizeof(reply_data),
	};
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_session *session;
	struct pump_ctx ctx;
	pthread_t pump;
	int minted_fd, kq, dupfd;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;

	minted_fd = -1;
	if (domain_mint_user_channel(4321, &minted_fd, kq) == -1) {
		if (errno == ENODEV)
			atf_tc_skip("mac_capability channel device unavailable");
		atf_tc_fail("domain_mint_user_channel: %s", strerror(errno));
	}

	ctx.kq = kq;
	ctx.stop = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&pump, NULL, domain_pump_thread, &ctx));

	dupfd = fcntl(minted_fd, F_DUPFD_CLOEXEC, 0);
	ATF_REQUIRE(dupfd >= 0);
	ATF_REQUIRE_EQ(0, service_session_create(dupfd, &session));

	op = 0xdeadbeefU;		/* not READY/LOOKUP/MINT/HELLO */
	memset(&reply_data, 0, sizeof(reply_data));
	options.timeout_ms = 2000;

	ATF_CHECK_EQ(0, service_session_call(session, &message, &reply,
	    &options));
	ATF_CHECK_EQ(sizeof(reply_data), reply.length);
	ATF_CHECK_EQ(ENOTSUP, reply_data.status);

	ctx.stop = 1;
	(void)pthread_join(pump, NULL);
	service_session_close(session);
	domain_channel_teardown();
	close(minted_fd);
	close(kq);
}

/*
 * Count registered switchboard-side lookup channels matching a domain kind (and,
 * when match_uid is set, uid).  Used after the pump thread is joined so the
 * list read has a happens-before against the mint that mutated it.
 */
static int
count_domain_entries(enum svc_domain_kind kind, uid_t uid, bool match_uid)
{
	struct svc_lookup_channel *lc;
	int n = 0;

	for (lc = lookup_channels; lc != NULL; lc = lc->next) {
		if (lc->domain.kind == kind &&
		    (!match_uid || lc->domain.uid == uid))
			n++;
	}
	return (n);
}

ATF_TC(direct_mint_over_ambient_retired);
ATF_TC_HEAD(direct_mint_over_ambient_retired, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "direct SVC_OP_MINT_DOMAIN over the ambient lookup channel is RETIRED "
	    "(P1c): login/su mint session channels via the auth-agent, not here, "
	    "so switchboard refuses the direct mint with EPERM");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(direct_mint_over_ambient_retired, tc)
{
	struct pump_ctx ctx;
	pthread_t pump;
	int minted_fd, sysfd, userfd, kq;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;

	/* The ambient SYSTEM channel a login/su holds (the getty carry). */
	minted_fd = -1;
	if (domain_mint_system_channel(&minted_fd, kq) == -1) {
		if (errno == ENODEV)
			atf_tc_skip("mac_capability channel device unavailable");
		atf_tc_fail("domain_mint_system_channel: %s", strerror(errno));
	}

	ctx.kq = kq;
	ctx.stop = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&pump, NULL, domain_pump_thread, &ctx));

	/*
	 * Direct minting over the ambient lookup channel is RETIRED (P1c,
	 * domain.c lookup_channel_request): the auth-agent (system.Auth) is
	 * the single mint boundary, and login/su reach it via
	 * service_mint_session_via_agent — they can no longer mint their own
	 * session channel directly over the ambient carry.  switchboard therefore
	 * refuses SVC_OP_MINT_DOMAIN on a lookup channel with EPERM.  Assert the
	 * refusal (both the SYSTEM and USER kinds) so a regression that re-opens
	 * the direct-mint path is caught, and confirm no channel was minted.
	 */
	sysfd = -1;
	ATF_CHECK(service_mint_session_domain(minted_fd, SERVICE_MINT_SYSTEM, 0,
	    &sysfd) != 0);
	ATF_CHECK(sysfd < 0);

	userfd = -1;
	ATF_CHECK(service_mint_session_domain(minted_fd, SERVICE_MINT_USER, 7777,
	    &userfd) != 0);
	ATF_CHECK(userfd < 0);

	ctx.stop = 1;
	(void)pthread_join(pump, NULL);

	/* Nothing was minted: no USER {7777} channel, and no second SYSTEM one. */
	ATF_CHECK(count_domain_entries(SVC_DOMAIN_USER, 7777, true) == 0);

	if (sysfd >= 0)
		close(sysfd);
	if (userfd >= 0)
		close(userfd);
	domain_channel_teardown();
	close(minted_fd);
	close(kq);
}

ATF_TC(user_channel_mints_neither);
ATF_TC_HEAD(user_channel_mints_neither, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "the adversarial escalation guard: a USER lookup channel may mint "
	    "NEITHER a SYSTEM nor a USER channel — both are refused with EPERM");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(user_channel_mints_neither, tc)
{
	struct pump_ctx ctx;
	pthread_t pump;
	int minted_fd, out, kq;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;

	/* An already-narrowed USER session channel. */
	minted_fd = -1;
	if (domain_mint_user_channel(1001, &minted_fd, kq) == -1) {
		if (errno == ENODEV)
			atf_tc_skip("mac_capability channel device unavailable");
		atf_tc_fail("domain_mint_user_channel: %s", strerror(errno));
	}

	ctx.kq = kq;
	ctx.stop = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&pump, NULL, domain_pump_thread, &ctx));

	/*
	 * Domains only ever narrow: a USER channel cannot mint at all.  A request
	 * for a USER channel is refused (svc_domain_may_mint), and — the privilege
	 * boundary — a request for a SYSTEM channel is refused too (a user session
	 * can never widen its scope).  Both return EPERM.
	 */
	out = -1;
	ATF_CHECK_EQ(-1, service_mint_session_domain(minted_fd,
	    SERVICE_MINT_USER, 1001, &out));
	ATF_CHECK_EQ(EPERM, errno);
	ATF_CHECK_EQ(-1, out);

	out = -1;
	ATF_CHECK_EQ(-1, service_mint_session_domain(minted_fd,
	    SERVICE_MINT_SYSTEM, 0, &out));
	ATF_CHECK_EQ(EPERM, errno);
	ATF_CHECK_EQ(-1, out);

	/* No channel escaped: only the original USER channel is registered. */
	ctx.stop = 1;
	(void)pthread_join(pump, NULL);
	ATF_CHECK_EQ(0, count_domain_entries(SVC_DOMAIN_SYSTEM, 0, false));
	ATF_CHECK_EQ(1, count_domain_entries(SVC_DOMAIN_USER, 1001, true));

	domain_channel_teardown();
	close(minted_fd);
	close(kq);
}

/* ------------------------------------------------------------------ */
/* P2: private per-process lookup channel (SVC_OP_REGISTER_LOOKUP).    */
/* ------------------------------------------------------------------ */

/*
 * Reply handler for the test's one-way registration sends.  The test never
 * dispatches the shared channel's inbound side, so it exists only to satisfy
 * channel_send_request()'s non-NULL contract.
 */
static void
reg_reply_ignore(struct channel_request *request,
    struct channel_message *message, int error, void *context)
{

	(void)error;
	(void)context;
	if (message != NULL)
		channel_message_free(message);
	channel_request_release(request);
}

/*
 * Raw one-way SVC_OP_REGISTER_LOOKUP send over a shared lookup channel, so a
 * test can drive the switchboard-side adopt handler directly with an arbitrary
 * (including malformed) descriptor set and assert whether it adopts.  Returns 0
 * once the message is flushed.
 */
static int
register_send_raw(int shared_fd, int *fds, size_t nfds)
{
	struct svc_register_lookup_req reqmsg;
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct channel_outgoing out;
	struct channel *channel;
	struct channel_request *request;
	int dupfd, tries;

	dupfd = fcntl(shared_fd, F_DUPFD_CLOEXEC, 0);
	if (dupfd == -1)
		return (-1);
	if (channel_create(dupfd, &options, &channel) == -1) {
		(void)close(dupfd);
		return (-1);
	}
	memset(&reqmsg, 0, sizeof(reqmsg));
	reqmsg.op = SVC_OP_REGISTER_LOOKUP;
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &reqmsg;
	out.length = sizeof(reqmsg);
	out.fds = fds;
	out.nfds = nfds;
	request = NULL;
	if (channel_send_request(channel, &out, reg_reply_ignore, NULL,
	    &request) == -1) {
		channel_destroy(channel);
		return (-1);
	}
	for (tries = 0; channel_wants_write(channel) == 1 && tries < 50;
	    tries++) {
		if (channel_wait(channel, 1, 100) < 0)
			break;
		if (channel_flush(channel) == -1)
			break;
	}
	channel_destroy(channel);
	return (0);
}

/* Skip cleanly if the ungated channel-create syscall (P1) is not loaded. */
static void
require_channel_create_syscall(const atf_tc_t *tc)
{
	int probe[2];

	(void)tc;
	if (mac_capability_channel_create(probe) == -1) {
		if (errno == ENOSYS)
			atf_tc_skip("mac_capability_channel_create syscall "
			    "unavailable (P1 module not loaded)");
		return;		/* a transient failure — let the test proceed */
	}
	(void)close(probe[0]);
	(void)close(probe[1]);
}

/*
 * The end-to-end positive path: a process registers its OWN private lookup
 * channel over the inherited SYSTEM channel, gets a DISTINCT fd back, and its
 * lookups resolve on that private channel with the same SYSTEM scope.  Drives
 * the real client (service_ambient_lookup_channel / service_connect_ambient)
 * against the real switchboard adopt handler.
 */
ATF_TC(register_private_system_channel_resolves);
ATF_TC_HEAD(register_private_system_channel_resolves, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "a process registers a private SYSTEM lookup channel, receives a "
	    "DISTINCT endpoint, and resolves a system-only name over it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(register_private_system_channel_resolves, tc)
{
	struct svc_runtime provider;
	struct pump_ctx ctx;
	pthread_t pump;
	char envbuf[16];
	int minted_fd, kq, before, priv, sfd;

	require_channel_create_syscall(tc);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;

	minted_fd = -1;
	if (domain_mint_system_channel(&minted_fd, kq) == -1) {
		if (errno == ENODEV)
			atf_tc_skip("mac_capability channel device unavailable");
		atf_tc_fail("domain_mint_system_channel: %s", strerror(errno));
	}
	provider_register(&provider, SYSTEM_ONLY_NAME);
	before = count_domain_entries(SVC_DOMAIN_SYSTEM, 0, false);

	ctx.kq = kq;
	ctx.stop = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&pump, NULL, domain_pump_thread, &ctx));

	/* Advertise the inherited shared channel exactly as boot/login does. */
	ATF_REQUIRE(snprintf(envbuf, sizeof(envbuf), "%d", minted_fd) <
	    (int)sizeof(envbuf));
	ATF_REQUIRE_EQ(0, setenv(SERVICE_LOOKUP_ENV, envbuf, 1));

	/* First ambient use registers a private channel and memoizes it. */
	priv = service_ambient_lookup_channel();
	ATF_REQUIRE_MSG(priv >= 0, "expected an ambient channel");
	ATF_CHECK_MSG(priv != minted_fd,
	    "the effective lookup fd must be the DISTINCT private endpoint, "
	    "not the inherited shared fd");

	/* A lookup over the private channel resolves the system-only name. */
	sfd = -1;
	ATF_CHECK_EQ(0, service_connect_ambient(SYSTEM_ONLY_NAME, &sfd));
	ATF_CHECK(sfd >= 0);
	if (sfd >= 0)
		(void)close(sfd);

	ctx.stop = 1;
	(void)pthread_join(pump, NULL);

	/* Exactly one private SYSTEM channel was adopted (in addition to the
	 * shared one). */
	ATF_CHECK_EQ(before + 1,
	    count_domain_entries(SVC_DOMAIN_SYSTEM, 0, false));

	naming_remove_owner(&provider);
	domain_channel_teardown();
	(void)close(minted_fd);
	(void)close(kq);
}

/*
 * Adoption never widens scope: registering over a USER channel yields a private
 * USER channel that STILL hides a system-only name (ENOENT), the exact opposite
 * of the SYSTEM case above.  This is the security invariant end-to-end.
 */
ATF_TC(register_private_user_channel_hides);
ATF_TC_HEAD(register_private_user_channel_hides, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "a private channel registered over a USER channel keeps USER scope: "
	    "a system-only name stays hidden (ENOENT), never widened to SYSTEM");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(register_private_user_channel_hides, tc)
{
	struct svc_runtime provider;
	struct pump_ctx ctx;
	pthread_t pump;
	char envbuf[16];
	int minted_fd, kq, before, priv, sfd;

	require_channel_create_syscall(tc);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;

	minted_fd = -1;
	if (domain_mint_user_channel(4321, &minted_fd, kq) == -1) {
		if (errno == ENODEV)
			atf_tc_skip("mac_capability channel device unavailable");
		atf_tc_fail("domain_mint_user_channel: %s", strerror(errno));
	}
	provider_register(&provider, SYSTEM_ONLY_NAME);
	before = count_domain_entries(SVC_DOMAIN_USER, 4321, true);

	ctx.kq = kq;
	ctx.stop = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&pump, NULL, domain_pump_thread, &ctx));

	ATF_REQUIRE(snprintf(envbuf, sizeof(envbuf), "%d", minted_fd) <
	    (int)sizeof(envbuf));
	ATF_REQUIRE_EQ(0, setenv(SERVICE_LOOKUP_ENV, envbuf, 1));

	priv = service_ambient_lookup_channel();
	ATF_REQUIRE_MSG(priv >= 0, "expected an ambient channel");
	ATF_CHECK_MSG(priv != minted_fd,
	    "the effective lookup fd must be the DISTINCT private endpoint");

	/* The system-only name is invisible to the USER-scoped private channel. */
	sfd = -1;
	ATF_CHECK_EQ(-1, service_connect_ambient(SYSTEM_ONLY_NAME, &sfd));
	ATF_CHECK_EQ(ENOENT, errno);
	ATF_CHECK_EQ(-1, sfd);

	ctx.stop = 1;
	(void)pthread_join(pump, NULL);

	/* The adopted private channel is tagged {USER, 4321}, not widened. */
	ATF_CHECK_EQ(before + 1,
	    count_domain_entries(SVC_DOMAIN_USER, 4321, true));
	ATF_CHECK_EQ(0, count_domain_entries(SVC_DOMAIN_SYSTEM, 0, false));

	naming_remove_owner(&provider);
	domain_channel_teardown();
	(void)close(minted_fd);
	(void)close(kq);
}

/*
 * The adopt handler rejects a non-channel descriptor: a REGISTER_LOOKUP whose
 * attached fd is a pipe (GETINFO fails) adopts NOTHING.  Drives the real
 * handler over a raw send.
 */
ATF_TC(register_non_channel_fd_rejected);
ATF_TC_HEAD(register_non_channel_fd_rejected, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "a REGISTER_LOOKUP carrying a non-channel fd (a pipe) is rejected: "
	    "no private channel is adopted");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(register_non_channel_fd_rejected, tc)
{
	struct pump_ctx ctx;
	pthread_t pump;
	int minted_fd, kq, before, p[2];

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;

	minted_fd = -1;
	if (domain_mint_system_channel(&minted_fd, kq) == -1) {
		if (errno == ENODEV)
			atf_tc_skip("mac_capability channel device unavailable");
		atf_tc_fail("domain_mint_system_channel: %s", strerror(errno));
	}
	before = count_domain_entries(SVC_DOMAIN_SYSTEM, 0, false);

	ctx.kq = kq;
	ctx.stop = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&pump, NULL, domain_pump_thread, &ctx));

	ATF_REQUIRE_EQ(0, pipe(p));
	ATF_REQUIRE_EQ(0, register_send_raw(minted_fd, &p[0], 1));
	usleep(400000);			/* let the handler dispatch + reject */

	ctx.stop = 1;
	(void)pthread_join(pump, NULL);
	ATF_CHECK_EQ_MSG(before,
	    count_domain_entries(SVC_DOMAIN_SYSTEM, 0, false),
	    "a non-channel fd must not be adopted as a lookup channel");

	(void)close(p[0]);
	(void)close(p[1]);
	domain_channel_teardown();
	(void)close(minted_fd);
	(void)close(kq);
}

/*
 * The adopt handler rejects a REGISTER_LOOKUP that over-attaches descriptors:
 * even when both are genuine channels, an nfds != 1 request adopts NOTHING (the
 * count is the discriminator, so a client cannot smuggle extra endpoints).
 */
ATF_TC(register_multi_fd_rejected);
ATF_TC_HEAD(register_multi_fd_rejected, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "a REGISTER_LOOKUP carrying more than one descriptor is rejected: "
	    "no private channel is adopted");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(register_multi_fd_rejected, tc)
{
	struct pump_ctx ctx;
	pthread_t pump;
	int minted_fd, kq, before, two[2];

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;

	minted_fd = -1;
	if (domain_mint_system_channel(&minted_fd, kq) == -1) {
		if (errno == ENODEV)
			atf_tc_skip("mac_capability channel device unavailable");
		atf_tc_fail("domain_mint_system_channel: %s", strerror(errno));
	}
	before = count_domain_entries(SVC_DOMAIN_SYSTEM, 0, false);

	ctx.kq = kq;
	ctx.stop = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&pump, NULL, domain_pump_thread, &ctx));

	/* Two genuine channels (dups of the shared endpoint): rejected on count. */
	two[0] = fcntl(minted_fd, F_DUPFD_CLOEXEC, 0);
	two[1] = fcntl(minted_fd, F_DUPFD_CLOEXEC, 0);
	ATF_REQUIRE(two[0] >= 0 && two[1] >= 0);
	ATF_REQUIRE_EQ(0, register_send_raw(minted_fd, two, 2));
	usleep(400000);

	ctx.stop = 1;
	(void)pthread_join(pump, NULL);
	ATF_CHECK_EQ_MSG(before,
	    count_domain_entries(SVC_DOMAIN_SYSTEM, 0, false),
	    "a multi-fd register request must not be adopted");

	(void)close(two[0]);
	(void)close(two[1]);
	domain_channel_teardown();
	(void)close(minted_fd);
	(void)close(kq);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, scope_system_resolves_all);
	ATF_TP_ADD_TC(tp, scope_user_allow_list);
	ATF_TP_ADD_TC(tp, mint_authorization);
	ATF_TP_ADD_TC(tp, mint_domain_kind_escalation_guard);
	ATF_TP_ADD_TC(tp, control_domain_separation);
	ATF_TP_ADD_TC(tp, control_ondemand_gating);
	ATF_TP_ADD_TC(tp, ambient_descriptor_marking);
	ATF_TP_ADD_TC(tp, default_requester_is_system);
	ATF_TP_ADD_TC(tp, user_scope_hides_registered_name);
	ATF_TP_ADD_TC(tp, minted_channel_user_scoped);
	ATF_TP_ADD_TC(tp, minted_system_channel_scoped);
	ATF_TP_ADD_TC(tp, direct_mint_over_ambient_retired);
	ATF_TP_ADD_TC(tp, user_channel_mints_neither);
	ATF_TP_ADD_TC(tp, hello_ack_over_user_channel);
	ATF_TP_ADD_TC(tp, hello_ack_over_system_channel);
	ATF_TP_ADD_TC(tp, unknown_op_over_lookup_channel_enotsup);
	ATF_TP_ADD_TC(tp, register_private_system_channel_resolves);
	ATF_TP_ADD_TC(tp, register_private_user_channel_hides);
	ATF_TP_ADD_TC(tp, register_non_channel_fd_rejected);
	ATF_TP_ADD_TC(tp, register_multi_fd_rejected);
	return (atf_no_error());
}
