/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/event.h>

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

/*
 * This test includes the implementation so it can exercise the deliberately
 * private pending-lookup invariants.  Function/data sections let the linker
 * discard unrelated serviced integration paths and their dependencies.
 *
 * The provider-driven idle-shutdown feature (Phase 2) spans supervisor.c
 * (arm/cancel/fire and the NOTE_EXIT reactivation block) and svc_proto.c
 * (handle_idle); both are pulled into this translation unit so their internal
 * state machines can be driven directly.  Unrelated lifecycle branches are
 * discarded by --gc-sections; the few leaf symbols that survive on
 * do-nothing branches (empty pending list, no live descriptors) are stubbed
 * below.
 */
#include "../on_demand.c"
#include "../supervisor.c"
#include "../svc_proto.c"

struct serviced_state sd;
int serviced_kq = -1;

/*
 * Leaf serviced symbols owned by other translation units.  The idle
 * lifecycle paths under test reach these only on branches that are inert in
 * the unit environment, but the references must still resolve at link time.
 */
struct svc_runtime *
svc_by_label(const char *label)
{

	(void)label;
	return (NULL);
}

void
svc_remove(unsigned idx)
{

	(void)idx;
}

void
svc_reregister_kevents(int kq)
{

	(void)kq;
}

int
svc_exec(struct svc_runtime *svc, int kq)
{

	(void)svc;
	(void)kq;
	return (0);
}

void
svc_run_container_remove(const char *label)
{

	(void)label;
}

int
svc_exec_rc_stop(struct svc_runtime *svc, int kq)
{

	(void)svc;
	(void)kq;
	return (0);
}

void
naming_remove_owner(struct svc_runtime *owner)
{

	(void)owner;
}

int
authority_release_manifest(int channel_fd, const struct svc_manifest *m)
{

	(void)channel_fd;
	(void)m;
	return (0);
}

int
mac_cap_coalition_graceful(int coalition_fd, int sig, unsigned timeout_ms)
{

	(void)coalition_fd;
	(void)sig;
	(void)timeout_ms;
	return (0);
}

int
mac_cap_coalition_terminate(int coalition_fd)
{

	(void)coalition_fd;
	return (0);
}

static void
runtime_init(struct svc_runtime *runtime, const char *label, pid_t pid,
    uint64_t launch_id)
{

	memset(runtime, 0, sizeof(*runtime));
	strlcpy(runtime->manifest.label, label,
	    sizeof(runtime->manifest.label));
	runtime->pid = pid;
	runtime->launch_id = launch_id;
}

static void
pending_init(struct pending_lookup *pending,
    const struct svc_runtime *provider, const char *name)
{

	memset(pending, 0, sizeof(*pending));
	strlcpy(pending->name, name, sizeof(pending->name));
	strlcpy(pending->provider_label, provider->manifest.label,
	    sizeof(pending->provider_label));
	pending->provider_pid = provider->pid;
	pending->provider_launch_id = provider->launch_id;
}

ATF_TC(provider_incarnation);
ATF_TC_HEAD(provider_incarnation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "pending lookups match an exact provider process incarnation");
}
ATF_TC_BODY(provider_incarnation, tc)
{
	struct pending_lookup pending;
	struct svc_runtime original, replacement;

	runtime_init(&original, "org.test.provider", 101, 7);
	pending_init(&pending, &original, "org.test.endpoint");
	ATF_CHECK(pending_provider_matches(&pending, &original));

	runtime_init(&replacement, "org.test.provider", 102, 8);
	ATF_CHECK(!pending_provider_matches(&pending, &replacement));
	replacement.pid = original.pid;
	ATF_CHECK(!pending_provider_matches(&pending, &replacement));
	replacement.launch_id = original.launch_id;
	ATF_CHECK(pending_provider_matches(&pending, &replacement));
	strlcpy(replacement.manifest.label, "org.test.other",
	    sizeof(replacement.manifest.label));
	ATF_CHECK(!pending_provider_matches(&pending, &replacement));
}

ATF_TC(provider_name_filter);
ATF_TC_HEAD(provider_name_filter, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "same-name waiters remain isolated across provider incarnations");
}
ATF_TC_BODY(provider_name_filter, tc)
{
	struct pending_lookup old_pending, new_pending;
	struct svc_runtime old_provider, new_provider;

	runtime_init(&old_provider, "org.test.provider", 201, 10);
	runtime_init(&new_provider, "org.test.provider", 202, 11);
	pending_init(&old_pending, &old_provider, "org.test.endpoint");
	pending_init(&new_pending, &new_provider, "org.test.endpoint");
	old_pending.next = &new_pending;
	pending_list = &old_pending;
	npending = 2;

	ATF_CHECK(pending_for_provider_name(&old_provider,
	    "org.test.endpoint"));
	ATF_CHECK(pending_for_provider_name(&new_provider,
	    "org.test.endpoint"));
	ATF_CHECK(!pending_for_provider_name(&new_provider,
	    "org.test.unrelated"));
	old_pending.next = NULL;
	ATF_CHECK(!pending_for_provider_name(&new_provider,
	    "org.test.endpoint"));

	pending_list = NULL;
	npending = 0;
}

ATF_TC(timer_identifiers);
ATF_TC_HEAD(timer_identifiers, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "timer identifiers preserve their range, wrap, and avoid collisions");
}
ATF_TC_BODY(timer_identifiers, tc)
{
	struct pending_lookup pending;
	uintptr_t first, second;

	memset(&pending, 0, sizeof(pending));
	pending.timeout_ident = ON_DEMAND_TIMER_BIT | 1;
	pending_list = &pending;
	npending = 1;
	od_timer_next = pending.timeout_ident;
	first = next_timeout_ident();
	ATF_CHECK_EQ(ON_DEMAND_TIMER_BIT | 2, first);
	ATF_CHECK(on_demand_is_timer(first));

	pending_list = NULL;
	npending = 0;
	od_timer_next = (ON_DEMAND_TIMER_BIT << 1) - 1;
	first = next_timeout_ident();
	second = next_timeout_ident();
	ATF_CHECK_EQ((ON_DEMAND_TIMER_BIT << 1) - 1, first);
	ATF_CHECK_EQ(ON_DEMAND_TIMER_BIT | 1, second);
	ATF_CHECK(on_demand_is_timer(first));
	ATF_CHECK(on_demand_is_timer(second));
}

ATF_TC(timer_registration_failure);
ATF_TC_HEAD(timer_registration_failure, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "an unusable kqueue makes timeout registration fail immediately");
}
ATF_TC_BODY(timer_registration_failure, tc)
{
	struct pending_lookup pending;

	memset(&pending, 0, sizeof(pending));
	pending_list = NULL;
	npending = 0;
	od_timer_next = ON_DEMAND_TIMER_BIT | 1;
	errno = 0;
	ATF_CHECK_EQ(-1, arm_timeout(-1, &pending));
	ATF_CHECK_EQ(EBADF, errno);
	ATF_CHECK(on_demand_is_timer(pending.timeout_ident));
}

/*
 * Provider-driven idle shutdown (Phase 2).
 */

static void
idle_runtime_init(struct svc_runtime *svc, const char *label)
{

	memset(svc, 0, sizeof(*svc));
	strlcpy(svc->manifest.label, label, sizeof(svc->manifest.label));
	svc->pd_fd = -1;
	svc->channel_fd = -1;
	svc->coalition_fd = -1;
	svc->jail_fd = -1;
}

ATF_TC(idle_timer_arm_cancel);
ATF_TC_HEAD(idle_timer_arm_cancel, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "arm/cancel/re-arm of the provider idle timer register and delete a "
	    "unique EVFILT_TIMER, and are no-ops in the already-desired state");
}
ATF_TC_BODY(idle_timer_arm_cancel, tc)
{
	struct svc_runtime svc;
	struct kevent kev;
	uintptr_t id1, id2;
	int kq;

	(void)tc;
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	idle_runtime_init(&svc, "org.test.idle");

	/* No idle timeout requested: arm is a no-op. */
	svc.idle_timeout_sec = 0;
	arm_idle_timer(&svc, kq);
	ATF_CHECK_EQ(0, svc.idle_timer_ident);
	/* Cancel with nothing armed is a no-op. */
	cancel_idle_timer(&svc, kq);
	ATF_CHECK_EQ(0, svc.idle_timer_ident);

	/* Arm: a unique ident in the dedicated idle range. */
	svc.idle_timeout_sec = 5;
	arm_idle_timer(&svc, kq);
	id1 = svc.idle_timer_ident;
	ATF_CHECK(id1 != 0);
	ATF_CHECK((id1 & IDLE_TIMER_BIT) != 0);
	ATF_CHECK((id1 & STOP_TIMER_BIT) == 0);
	ATF_CHECK((id1 & ON_DEMAND_TIMER_BIT) == 0);
	/* An idle ident must never be mistaken for an on-demand timer. */
	ATF_CHECK(!on_demand_is_timer(id1));
	/* The timer is really registered: deleting it by hand succeeds. */
	EV_SET(&kev, id1, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	ATF_CHECK_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));

	/* Re-arm resets: cancels the old registration and adds a new ident. */
	arm_idle_timer(&svc, kq);
	id1 = svc.idle_timer_ident;
	arm_idle_timer(&svc, kq);
	id2 = svc.idle_timer_ident;
	ATF_CHECK(id2 != id1);
	ATF_CHECK((id2 & IDLE_TIMER_BIT) != 0);
	/* The previous registration is gone (re-arm deleted it first). */
	EV_SET(&kev, id1, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	errno = 0;
	ATF_CHECK(kevent(kq, &kev, 1, NULL, 0, NULL) == -1 && errno == ENOENT);

	/* Cancel deletes the live timer and clears the ident. */
	cancel_idle_timer(&svc, kq);
	ATF_CHECK_EQ(0, svc.idle_timer_ident);
	EV_SET(&kev, id2, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	errno = 0;
	ATF_CHECK(kevent(kq, &kev, 1, NULL, 0, NULL) == -1 && errno == ENOENT);

	(void)close(kq);
}

ATF_TC(idle_timer_ident_range);
ATF_TC_HEAD(idle_timer_ident_range, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "idle-timer idents occupy a bit range disjoint from restart, stop, "
	    "on-demand, and async-launch timer idents");
}
ATF_TC_BODY(idle_timer_ident_range, tc)
{
	uintptr_t width, launch_bit, ident;
	unsigned i;

	(void)tc;
	width = sizeof(uintptr_t) * 8;
	/* The three high-bit tags supervisor.c/on_demand.c reserve. */
	ATF_CHECK_EQ((uintptr_t)1 << (width - 1), STOP_TIMER_BIT);
	ATF_CHECK_EQ((uintptr_t)1 << (width - 2), ON_DEMAND_TIMER_BIT);
	ATF_CHECK_EQ((uintptr_t)1 << (width - 3), IDLE_TIMER_BIT);
	/* execute.c's async-launch tag is the next bit down. */
	launch_bit = (uintptr_t)1 << (width - 4);
	ATF_CHECK((IDLE_TIMER_BIT & STOP_TIMER_BIT) == 0);
	ATF_CHECK((IDLE_TIMER_BIT & ON_DEMAND_TIMER_BIT) == 0);
	ATF_CHECK((IDLE_TIMER_BIT & launch_bit) == 0);
	/* Restart idents (supervisor.c starts them at 10000) carry no tag. */
	ATF_CHECK((((uintptr_t)10000) & IDLE_TIMER_BIT) == 0);
	ATF_CHECK(IDLE_TIMER_BIT > 10000);

	/*
	 * Every ident arm_idle_timer hands out is IDLE_TIMER_BIT | k for a
	 * small monotonic k, so none of the other subsystems' tags is ever
	 * set and on_demand_is_timer() never claims one.
	 */
	for (i = 0; i < 128; i++) {
		ident = IDLE_TIMER_BIT | i;
		ATF_CHECK((ident & STOP_TIMER_BIT) == 0);
		ATF_CHECK((ident & ON_DEMAND_TIMER_BIT) == 0);
		ATF_CHECK((ident & launch_bit) == 0);
		ATF_CHECK(!on_demand_is_timer(ident));
	}
}

ATF_TC(idle_timer_fire_stops_provider);
ATF_TC_HEAD(idle_timer_fire_stops_provider, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a fired idle timer marks idle_stop_pending and initiates a graceful "
	    "stop on a running provider, but is inert once it left RUNNING");
	atf_tc_set_md_var(tc, "timeout", "20");
}
ATF_TC_BODY(idle_timer_fire_stops_provider, tc)
{
	struct svc_runtime svc;
	struct kevent kev;
	struct timespec deadline;
	int kq, n;

	(void)tc;
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	/* svc_graceful_stop reads the global serviced_kq. */
	serviced_kq = kq;

	idle_runtime_init(&svc, "org.test.idle");
	svc.state = SVC_STATE_RUNNING;
	svc.protocol_ready = true;
	svc.manifest.stop_timeout = 1;
	svc.idle_timeout_sec = 1;
	arm_idle_timer(&svc, kq);
	ATF_REQUIRE(svc.idle_timer_ident != 0);

	/* Wait for the one-shot idle timer to actually fire. */
	deadline.tv_sec = 5;
	deadline.tv_nsec = 0;
	n = kevent(kq, NULL, 0, &kev, 1, &deadline);
	ATF_REQUIRE_EQ(1, n);
	ATF_CHECK_EQ(EVFILT_TIMER, kev.filter);
	ATF_CHECK_EQ(svc.idle_timer_ident, kev.ident);
	ATF_CHECK_EQ(&svc, (struct svc_runtime *)kev.udata);

	/* Drive the branch the event loop would take. */
	supervisor_handle_timer(&kev);
	ATF_CHECK(svc.idle_stop_pending);
	ATF_CHECK_EQ(SVC_STATE_STOPPING, svc.state);
	ATF_CHECK_EQ(0, svc.idle_timer_ident);
	/* svc_graceful_stop armed the stop-timeout SIGKILL timer. */
	ATF_CHECK(svc.stop_kill_pending);

	/*
	 * An expiry that arrives after the provider already left RUNNING (for
	 * example it crashed and is restarting) must not re-enter idle stop.
	 */
	idle_runtime_init(&svc, "org.test.idle2");
	svc.state = SVC_STATE_STARTING;
	svc.idle_timer_ident = IDLE_TIMER_BIT | 0x5a5a;
	memset(&kev, 0, sizeof(kev));
	kev.ident = svc.idle_timer_ident;
	kev.filter = EVFILT_TIMER;
	kev.udata = &svc;
	supervisor_handle_timer(&kev);
	ATF_CHECK(!svc.idle_stop_pending);
	ATF_CHECK_EQ(SVC_STATE_STARTING, svc.state);
	ATF_CHECK_EQ(0, svc.idle_timer_ident);

	serviced_kq = -1;
	(void)close(kq);
}

ATF_TC(idle_note_exit_reactivatable);
ATF_TC_HEAD(idle_note_exit_reactivatable, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "after an idle-stopped provider's process exits, its slot returns to "
	    "STOPPED with a fresh unclaimed name table and intact manifest, ready "
	    "for on-demand relaunch");
}
ATF_TC_BODY(idle_note_exit_reactivatable, tc)
{
	struct svc_runtime svc;
	struct kevent kev;
	unsigned i;

	(void)tc;
	/* Empty pending list and registry: the teardown branches are inert. */
	pending_list = NULL;
	npending = 0;
	serviced_kq = -1;

	idle_runtime_init(&svc, "org.test.idle");
	svc.kind = SVC_KIND_NATIVE;
	svc.state = SVC_STATE_STOPPING;	/* graceful stop was under way */
	svc.pid = 0x7fffffff;		/* not our child; waitpid is a no-op */
	svc.launch_id = 42;
	svc.protocol_ready = true;
	svc.idle_stop_pending = true;
	svc.idle_timeout_sec = 30;
	svc.quiesce_pending = true;
	svc.restart_count = 4;
	svc.bundle_idx = 7;
	svc.bundle_svc_idx = 3;
	svc.manifest.nprovides = 2;
	strlcpy(svc.manifest.provides[0], "org.test.idle.a",
	    sizeof(svc.manifest.provides[0]));
	strlcpy(svc.manifest.provides[1], "org.test.idle.b",
	    sizeof(svc.manifest.provides[1]));
	svc.name_state[0] = SVC_NAME_READY;
	svc.name_state[1] = SVC_NAME_ACTIVATING;

	memset(&kev, 0, sizeof(kev));
	kev.filter = EVFILT_PROCDESC;
	kev.fflags = NOTE_EXIT;
	kev.data = 0;			/* WIFEXITED, status 0 */
	kev.udata = &svc;
	supervisor_handle_procdesc(&kev);

	/* Reactivatable, not removed. */
	ATF_CHECK_EQ(SVC_STATE_STOPPED, svc.state);
	ATF_CHECK_EQ(0, svc.pid);
	ATF_CHECK_EQ(0, svc.launch_id);
	ATF_CHECK(!svc.idle_stop_pending);
	ATF_CHECK_EQ(0, svc.idle_timeout_sec);
	ATF_CHECK(!svc.quiesce_pending);
	ATF_CHECK_EQ(0, svc.restart_count);
	ATF_CHECK(!svc.protocol_ready);
	/* Every provides[] name reverts to UNCLAIMED for a clean re-claim. */
	for (i = 0; i < nitems(svc.name_state); i++)
		ATF_CHECK_EQ(SVC_NAME_UNCLAIMED, svc.name_state[i]);
	/* Manifest and bundle origin are intact. */
	ATF_CHECK_STREQ("org.test.idle", svc.manifest.label);
	ATF_CHECK_EQ(2, svc.manifest.nprovides);
	ATF_CHECK_STREQ("org.test.idle.a", svc.manifest.provides[0]);
	ATF_CHECK_EQ(7, svc.bundle_idx);
	ATF_CHECK_EQ(3, svc.bundle_svc_idx);
}

/*
 * handle_idle exercises the real service channel, so it needs the
 * mac_capability channel device.  A provider thread drives svc_proto's
 * handle_idle over a genuine channel while the main thread plays the client.
 */
static int
idle_capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR);
	ATF_REQUIRE(control >= 0);
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, name, sizeof(connect.name));
	if (ioctl(control, MAC_CAPABILITY_CONNECT, &connect) == -1) {
		error = errno;
		close(control);
		errno = error;
		return (-1);
	}
	close(control);
	return (connect.fd);
}

static void
idle_channel_pair(int *first, int *second)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_sendmsg_args send;
	uint32_t op;

	*first = idle_capability_connect("channel");
	ATF_REQUIRE(*first >= 0);
	op = CHANNEL_OP_CREATE;
	memset(&send, 0, sizeof(send));
	send.payload = &op;
	send.payload_len = sizeof(op);
	ATF_REQUIRE(ioctl(*first, MAC_CAPABILITY_SENDMSG, &send) == 0);
	memset(&receive, 0, sizeof(receive));
	receive.fds = second;
	receive.nfds = 1;
	ATF_REQUIRE(ioctl(*first, MAC_CAPABILITY_RECVMSG, &receive) == 0);
	ATF_REQUIRE_EQ(1, receive.nfds);
}

struct idle_provider_ctx {
	int			 fd;
	struct svc_runtime	*svc;
	int			 error;
};

static void
idle_provider_request(struct channel *channel, struct channel_message *message,
    void *argument)
{
	struct idle_provider_ctx *ctx;

	(void)channel;
	ctx = argument;
	/* Exactly the dispatch svc_request would perform for SVC_OP_IDLE. */
	handle_idle(ctx->svc, message);
	channel_message_free(message);
}

static void *
idle_provider_thread(void *argument)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct idle_provider_ctx *ctx;
	struct channel *channel;
	int result, wants_write;

	ctx = argument;
	if (channel_create(ctx->fd, &options, &channel) == -1) {
		ctx->error = errno;
		return (NULL);
	}
	ctx->svc->control_channel = channel;
	ctx->svc->channel_fd = channel_fd(channel);
	if (channel_set_request_handler(channel, idle_provider_request,
	    ctx) == -1) {
		ctx->error = errno;
		ctx->svc->control_channel = NULL;
		channel_destroy(channel);
		return (NULL);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		result = channel_wait(channel, wants_write, 2000);
		if (result == -1)
			break;
		if (result == 0)
			continue;
		if ((result & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1)
			break;
		if ((result & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
	}
	ctx->svc->control_channel = NULL;
	ctx->svc->channel_fd = -1;
	channel_destroy(channel);
	return (NULL);
}

struct idle_client_reply {
	bool	done;
	int	status;
	int	error;
};

static void
idle_client_on_reply(struct channel_request *request,
    struct channel_message *message, int error, void *argument)
{
	struct idle_client_reply *reply;

	reply = argument;
	if (error != 0)
		reply->error = error;
	else if (channel_message_length(message) != sizeof(struct svc_reply) ||
	    channel_message_fd_count(message) != 0)
		reply->error = EPROTO;
	else
		reply->status =
		    ((const struct svc_reply *)channel_message_data(message))->
		    status;
	if (message != NULL)
		channel_message_free(message);
	channel_request_release(request);
	reply->done = true;
}

/*
 * Issue one SVC_OP_IDLE request for `seconds` on `client` and return handle_idle's
 * reply status.
 */
static int
idle_client_request(struct channel *client, unsigned seconds)
{
	struct idle_client_reply reply;
	struct svc_idle_req request;
	struct channel_request *pending;
	int result, wants_write;

	memset(&request, 0, sizeof(request));
	request.op = SVC_OP_IDLE;
	request.seconds = seconds;
	memset(&reply, 0, sizeof(reply));
	reply.status = -1;
	ATF_REQUIRE(channel_send_request(client,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(&request, sizeof(request)),
	    idle_client_on_reply, &reply, &pending) == 0);
	while (!reply.done) {
		wants_write = channel_wants_write(client);
		ATF_REQUIRE(wants_write >= 0);
		result = channel_wait(client, wants_write, 5000);
		ATF_REQUIRE(result > 0);
		if ((result & CHANNEL_WAIT_WRITE) != 0)
			ATF_REQUIRE(channel_flush(client) == 0);
		if ((result & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(client) == -1)
			ATF_REQUIRE(reply.done);
	}
	ATF_CHECK_EQ(0, reply.error);
	return (reply.status);
}

/*
 * Run a sequence of idle requests against one provider incarnation and leave
 * the final runtime state in *svc for inspection.
 */
static void
idle_run(int state, bool protocol_ready, const unsigned *seconds, size_t count,
    struct svc_runtime *svc, int *last_status)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct idle_provider_ctx provider;
	struct channel *client;
	pthread_t thread;
	size_t i;
	int pair[2];

	idle_channel_pair(&pair[0], &pair[1]);
	idle_runtime_init(svc, "org.test.idle");
	svc->state = state;
	svc->protocol_ready = protocol_ready;
	memset(&provider, 0, sizeof(provider));
	provider.fd = pair[1];
	provider.svc = svc;
	ATF_REQUIRE_EQ(0, pthread_create(&thread, NULL, idle_provider_thread,
	    &provider));
	ATF_REQUIRE_EQ(0, channel_create(pair[0], &options, &client));
	*last_status = -1;
	for (i = 0; i < count; i++)
		*last_status = idle_client_request(client, seconds[i]);
	channel_destroy(client);
	ATF_REQUIRE_EQ(0, pthread_join(thread, NULL));
	ATF_CHECK_EQ(0, provider.error);
}

ATF_TC(handle_idle_protocol);
ATF_TC_HEAD(handle_idle_protocol, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "handle_idle arms/cancels the idle timer for a ready provider and "
	    "rejects providers that are not RUNNING and protocol-ready with EBUSY");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(handle_idle_protocol, tc)
{
	struct svc_runtime svc;
	int kq, status;
	const unsigned arm_only[] = { 5 };
	const unsigned arm_then_cancel[] = { 5, 0 };

	(void)tc;
	/* handle_idle arms via the global serviced_kq. */
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	serviced_kq = kq;

	/* seconds > 0 on a ready provider arms and records the timeout. */
	idle_run(SVC_STATE_RUNNING, true, arm_only, nitems(arm_only), &svc,
	    &status);
	ATF_CHECK_EQ(0, status);
	ATF_CHECK_EQ(5, svc.idle_timeout_sec);
	ATF_CHECK(svc.idle_timer_ident != 0);
	ATF_CHECK((svc.idle_timer_ident & IDLE_TIMER_BIT) != 0);

	/* A following seconds == 0 cancels the pending timer. */
	idle_run(SVC_STATE_RUNNING, true, arm_then_cancel, nitems(arm_then_cancel),
	    &svc, &status);
	ATF_CHECK_EQ(0, status);
	ATF_CHECK_EQ(0, svc.idle_timeout_sec);
	ATF_CHECK_EQ(0, svc.idle_timer_ident);

	/* Not yet RUNNING: EBUSY, and nothing is armed. */
	idle_run(SVC_STATE_STARTING, true, arm_only, nitems(arm_only), &svc,
	    &status);
	ATF_CHECK_EQ(EBUSY, status);
	ATF_CHECK_EQ(0, svc.idle_timeout_sec);
	ATF_CHECK_EQ(0, svc.idle_timer_ident);

	/* RUNNING but not protocol-ready: EBUSY, and nothing is armed. */
	idle_run(SVC_STATE_RUNNING, false, arm_only, nitems(arm_only), &svc,
	    &status);
	ATF_CHECK_EQ(EBUSY, status);
	ATF_CHECK_EQ(0, svc.idle_timeout_sec);
	ATF_CHECK_EQ(0, svc.idle_timer_ident);

	serviced_kq = -1;
	(void)close(kq);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, provider_incarnation);
	ATF_TP_ADD_TC(tp, provider_name_filter);
	ATF_TP_ADD_TC(tp, timer_identifiers);
	ATF_TP_ADD_TC(tp, timer_registration_failure);
	ATF_TP_ADD_TC(tp, idle_timer_arm_cancel);
	ATF_TP_ADD_TC(tp, idle_timer_ident_range);
	ATF_TP_ADD_TC(tp, idle_timer_fire_stops_provider);
	ATF_TP_ADD_TC(tp, idle_note_exit_reactivatable);
	ATF_TP_ADD_TC(tp, handle_idle_protocol);
	return (atf_no_error());
}
