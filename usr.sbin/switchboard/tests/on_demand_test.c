/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <dev/mac_capability/mac_capability_coalition_proto.h>

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
#include <capability.h>

static bool cleanup_mock;
static uint32_t cleanup_phase;
static unsigned runtime_removals;
static unsigned slot_removals, launch_calls;

static int
cleanup_test_status(int fd, struct capability_coalition_status *state)
{
	if (!cleanup_mock)
		return (capability_coalition_status(fd, state));
	memset(state, 0, sizeof(*state));
	state->phase = cleanup_phase;
	if (cleanup_phase == CAPABILITY_COALITION_FAILED)
		state->cleanup_error = EIO;
	return (0);
}


/*
 * This test includes the implementation so it can exercise the deliberately
 * private pending-lookup invariants.  Function/data sections let the linker
 * discard unrelated switchboard integration paths and their dependencies.
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

/* The function-like macro leaves the status structure tag intact. */
#define capability_coalition_status(...) cleanup_test_status(__VA_ARGS__)
#include "../supervisor.c"
#undef capability_coalition_status
#include "../svc_proto.c"

struct switchboard_state sd;
int switchboard_kq = -1;

/* These lifecycle fixtures issue no grants; real revocation is VM-tested. */
void
svc_authority_revoke_unit(const struct svc_runtime *svc)
{
	ATF_REQUIRE_EQ(svc->domain.authority_identity, 0);
}


/*
 * Leaf switchboard symbols owned by other translation units.  The idle
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

	slot_removals++;
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

	launch_calls++;
	(void)svc;
	(void)kq;
	return (0);
}

void
svc_run_container_remove(const char *label)
{

	runtime_removals++;
	(void)label;
}

int
svc_exec_rc_stop(struct svc_runtime *svc, int kq)
{

	(void)svc;
	(void)kq;
	return (0);
}

int
svc_exec_rc_start(struct svc_runtime *svc, int kq)
{

	(void)svc;
	(void)kq;
	return (0);
}

/*
 * Ambient lookup channels live in domain.c (not linked here).  These tests use
 * only service-to-service requesters (ambient_lc == NULL), so the ambient
 * branches never run; the stubs exist only to resolve at link time.
 */
void
domain_unit_channels_close(const struct svc_runtime *svc __unused)
{
}

struct svc_runtime *
lookup_channel_requester(const struct svc_lookup_channel *lc __unused)
{
	return (NULL);
}

bool
lookup_channel_is_live(const struct svc_lookup_channel *lc)
{

	(void)lc;
	return (false);
}

void
lookup_channel_sync_events(struct svc_lookup_channel *lc, int kq)
{

	(void)lc;
	(void)kq;
}

void
naming_remove_owner(struct svc_runtime *owner)
{

	(void)owner;
}

int
capsule_release_manifest(int channel_fd, const struct svc_manifest *m)
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

/*
 * Bundle-derived slot policy (startup.c): a fresh on-demand slot must get
 * its owner uid and agent confinement exactly as a boot-loaded one.  Count
 * the applications so a test can assert on-demand went through it.
 */
static unsigned slot_policy_calls;

void
svc_slot_apply_bundle_policy(struct svc_runtime *svc, unsigned bundle_idx)
{

	(void)bundle_idx;
	svc->owner_uid = (uid_t)-1;
	slot_policy_calls++;
}

/*
 * Responsibility is decided by responsibility.c from the requester and the
 * session; on_demand.c only records that decision.  Remember the last call
 * so tests can assert the requester was threaded through.
 */
static const struct svc_runtime *resp_last_requester;
static const struct svc_domain *resp_last_session;
static unsigned resp_decide_calls;

/*
 * The party the stub records.  A test sets these to drive the launch
 * constraint check in od_launch(), which reads unit->responsible.
 */
static enum svc_responsible_kind resp_stub_kind = SVC_RESP_SWITCHBOARD;
static char resp_stub_label[SWITCHBOARD_LABEL_MAX];
static uid_t resp_stub_uid;

void
svc_responsibility_decide(struct svc_runtime *unit,
    const struct svc_runtime *requester,
    const struct svc_domain *session)
{

	resp_last_requester = requester;
	resp_last_session = session;
	resp_decide_calls++;
	memset(&unit->responsible, 0, sizeof(unit->responsible));
	unit->responsible.parent_fd = -1;
	unit->responsible.kind = resp_stub_kind;
	unit->responsible.uid = resp_stub_uid;
	strlcpy(unit->responsible.label, resp_stub_label,
	    sizeof(unit->responsible.label));
}

void
svc_responsibility_clear(struct svc_runtime *svc)
{

	memset(&svc->responsible, 0, sizeof(svc->responsible));
	svc->responsible.parent_fd = -1;
}

bool
svc_responsible_allowed(const struct svc_manifest *m,
    const struct svc_responsible *r)
{
	unsigned i;

	if (m->nlaunch_responsible == 0)
		return (true);
	/* Enough of the real rule for the on-demand path: kinds by name. */
	for (i = 0; i < m->nlaunch_responsible; i++) {
		const char *t = m->launch_responsible[i];

		if (r->kind == SVC_RESP_SWITCHBOARD &&
		    strcmp(t, "switchboard") == 0)
			return (true);
		if (r->kind == SVC_RESP_SESSION && strcmp(t, "session") == 0)
			return (true);
		if (r->kind == SVC_RESP_UNIT && strcmp(t, r->label) == 0)
			return (true);
		if (r->kind == SVC_RESP_SELF && strcmp(t, "self") == 0)
			return (true);
	}
	return (false);
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

ATF_TC_WITHOUT_HEAD(circuit_breaker_blocks_on_demand_relaunch);
ATF_TC_BODY(circuit_breaker_blocks_on_demand_relaunch, tc)
{
	struct svc_runtime svc;

	(void)tc;
	runtime_init(&svc, "org.test.crashloop", 0, 0);
	svc.manifest.max_failures = 3;

	svc.restart_count = 2;
	ATF_CHECK(!on_demand_circuit_open(&svc));
	svc.restart_count = 3;
	ATF_CHECK(on_demand_circuit_open(&svc));
	svc.restart_count = 30;
	ATF_CHECK(on_demand_circuit_open(&svc));

	/* A fresh runtime and an explicitly reset counter remain launchable. */
	svc.restart_count = 0;
	ATF_CHECK(!on_demand_circuit_open(&svc));
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
	svc.idle_timeout_sec = SVC_IDLE_MAX_SECONDS + 1;
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
	/* svc_graceful_stop reads the global switchboard_kq. */
	switchboard_kq = kq;

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

	switchboard_kq = -1;
	(void)close(kq);
}

/* Exercise actual compaction without replacing other fixtures' leaf stubs. */
struct svc_runtime *reload_test_by_label(const char *);
struct svc_runtime *reload_test_by_label_scoped(const char *, uid_t);
void reload_test_remove(unsigned);
void reload_test_reregister(int);
static int
reload_test_channel_rebind(struct svc_runtime *svc)
{
	(void)svc;
	atf_tc_fail("cleanup compaction fixture has no control channel");
	return (-1);
}
#define svc_channel_rebind reload_test_channel_rebind
#define svc_by_label reload_test_by_label
#define svc_by_label_scoped reload_test_by_label_scoped
#define svc_remove reload_test_remove
#define svc_reregister_kevents reload_test_reregister
#include "../reload.c"
#undef svc_channel_rebind
#undef svc_by_label
#undef svc_by_label_scoped
#undef svc_remove
#undef svc_reregister_kevents

void
svc_launch_cancel(struct svc_runtime *svc, int kq)
{
	(void)kq;
	ATF_REQUIRE(svc->launch == NULL);
}

void
activation_source_teardown(struct svc_runtime *svc, int kq)
{
	(void)svc;
	(void)kq;
}

void
naming_rebind_owner(struct svc_runtime *old, struct svc_runtime *new)
{
	(void)old;
	(void)new;
}

ATF_TC(cleanup_compaction);
ATF_TC_HEAD(cleanup_compaction, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "real service compaction rebinds pending cleanup events without losing ownership");
}
ATF_TC_BODY(cleanup_compaction, tc)
{
	struct svc_runtime *slots;
	struct kevent event;
	struct timespec timeout = { .tv_sec = 1 }, deadline;
	int fds[2], kq;
	char byte = 'x';

	(void)tc;
	slots = calloc(2, sizeof(*slots));
	ATF_REQUIRE(slots != NULL);
	idle_runtime_init(&slots[0], "org.test.removed");
	idle_runtime_init(&slots[1], "org.test.pending");
	ATF_REQUIRE_EQ(0, pipe(fds));
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;
	sd.services = slots;
	sd.nservices = 2;
	slots[1].state = SVC_STATE_STOPPING;
	slots[1].cleanup.pending = true;
	slots[1].cleanup.fd = fds[0];
	slots[1].cleanup.timer_ident = ++cleanup_timer_next_ident;
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &deadline));
	deadline.tv_sec += 30;
	slots[1].cleanup.deadline = deadline;
	ATF_REQUIRE_EQ(0, supervisor_cleanup_rebind(&slots[1], kq));
	/* Removing the pending slot records intent, without releasing it. */
	reload_test_remove(1);
	ATF_CHECK_EQ(2, sd.nservices);
	ATF_CHECK(slots[1].remove_pending);
	ATF_CHECK(fcntl(fds[0], F_GETFD) >= 0);
	/* Removing its predecessor really moves the pending slot. */
	reload_test_remove(0);
	reload_test_reregister(kq);
	ATF_REQUIRE_EQ(1, sd.nservices);
	ATF_CHECK_STREQ("org.test.pending", slots[0].manifest.label);
	ATF_CHECK(slots[0].cleanup.pending);
	ATF_CHECK(slots[0].remove_pending);
	ATF_CHECK_EQ(deadline.tv_sec, slots[0].cleanup.deadline.tv_sec);
	ATF_CHECK_EQ(deadline.tv_nsec, slots[0].cleanup.deadline.tv_nsec);
	ATF_REQUIRE_EQ(1, write(fds[1], &byte, 1));
	ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &event, 1, &timeout));
	ATF_CHECK_EQ(EVFILT_READ, event.filter);
	ATF_CHECK_EQ(fds[0], (int)event.ident);
	ATF_CHECK(event.udata == &slots[0]);
	ATF_REQUIRE_EQ(1, read(fds[0], &byte, 1));
	/* Expire the preserved timer and verify its relocated pointer too. */
	slots[0].cleanup.deadline.tv_sec -= 31;
	reload_test_reregister(kq);
	ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &event, 1, &timeout));
	ATF_CHECK_EQ(EVFILT_TIMER, event.filter);
	ATF_CHECK_EQ(slots[0].cleanup.timer_ident, event.ident);
	ATF_CHECK(event.udata == &slots[0]);
	close(fds[0]);
	close(fds[1]);
	close(kq);
	free(slots);
	sd.services = NULL;
	sd.nservices = 0;
	switchboard_kq = -1;
}

ATF_TC(cleanup_updated_intent);
ATF_TC_HEAD(cleanup_updated_intent, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "completion applies reload/removal requested while cleanup was pending");
}
ATF_TC_BODY(cleanup_updated_intent, tc)
{
	struct svc_runtime svc;
	int fds[2];
	unsigned remove;

	(void)tc;
	cleanup_mock = true;
	switchboard_kq = -1;
	for (remove = 0; remove < 2; remove++) {
		idle_runtime_init(&svc, "org.test.cleanup.intent");
		ATF_REQUIRE_EQ(0, pipe(fds));
		svc.cleanup.fd = fds[0];
		svc.cleanup.pending = true;
		svc.state = SVC_STATE_STOPPING;
		sd.services = &svc;
		sd.nservices = 1;
		launch_calls = slot_removals = runtime_removals = 0;
		cleanup_phase = CAPABILITY_COALITION_DRAINING;
		supervisor_cleanup_event(&svc);
		ATF_CHECK_EQ(0, runtime_removals);
		/* New intent arrives after the original exit-time snapshot. */
		svc.reload_pending = true;
		svc.remove_pending = remove != 0;
		svc.pending_manifest = svc.manifest;
		svc.pending_manifest.throttle_interval = 123;
		cleanup_phase = CAPABILITY_COALITION_COMPLETE;
		supervisor_cleanup_event(&svc);
		ATF_CHECK(!svc.cleanup.pending);
		ATF_CHECK_EQ(1, runtime_removals);
		ATF_CHECK_EQ(remove, slot_removals);
		ATF_CHECK_EQ(remove ? 0 : 1, launch_calls);
		if (!remove) {
			ATF_CHECK(!svc.reload_pending);
			ATF_CHECK_EQ(123, svc.manifest.throttle_interval);
		}
		close(fds[1]);
	}
	sd.services = NULL;
	sd.nservices = 0;
	cleanup_mock = false;
}

ATF_TC(cleanup_unenlisted_child);
ATF_TC_HEAD(cleanup_unenlisted_child, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "empty coalition cannot release runtime while an unenlisted child lives");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(cleanup_unenlisted_child, tc)
{
	struct svc_runtime svc;
	struct kevent event;
	struct timespec zero = { 0 }, timeout = { .tv_sec = 5 };
	int device, pd;
	pid_t child;

	(void)tc;
	cleanup_mock = false;
	child = pdfork(&pd, 0);
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		for (;;)
			pause();
	}
	device = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE(device >= 0);
	idle_runtime_init(&svc, "org.test.cleanup.unenlisted");
	svc.pid = child;
	svc.pd_fd = pd;
	svc.cleanup.fd = -1;
	svc.coalition_fd = capability_service_connect(device, "coalition");
	ATF_REQUIRE(svc.coalition_fd >= 0);
	switchboard_kq = kqueue();
	ATF_REQUIRE(switchboard_kq >= 0);
	runtime_removals = 0;
	supervisor_cleanup_failed_launch(&svc);
	ATF_REQUIRE(svc.cleanup.pending);
	ATF_REQUIRE(svc.cleanup.child_pending);
	ATF_REQUIRE(svc.cleanup.coalition_complete);
	ATF_CHECK_EQ(pd, svc.pd_fd);
	ATF_CHECK_EQ(-1, svc.cleanup.fd);
	ATF_CHECK_EQ(0, runtime_removals);
	ATF_CHECK_EQ(0, kevent(switchboard_kq, NULL, 0, &event, 1, &zero));
	ATF_REQUIRE_EQ(0, pdkill(pd, SIGKILL));
	ATF_REQUIRE_EQ(1, kevent(switchboard_kq, NULL, 0, &event, 1, &timeout));
	ATF_REQUIRE_EQ(EVFILT_PROCDESC, event.filter);
	ATF_REQUIRE_EQ(pd, (int)event.ident);
	ATF_REQUIRE((event.fflags & NOTE_EXIT) != 0);
	supervisor_handle_procdesc(&event);
	ATF_CHECK(!svc.cleanup.pending);
	ATF_CHECK(!svc.cleanup.child_pending);
	ATF_CHECK_EQ(-1, svc.pd_fd);
	ATF_CHECK_EQ(1, runtime_removals);
	ATF_CHECK_EQ(SVC_STATE_STOPPED, svc.state);
	close(device);
	close(switchboard_kq);
	switchboard_kq = -1;
}

/* A failed child registration must not suppress the other cleanup watches. */
ATF_TC_WITHOUT_HEAD(cleanup_registration_failure);
ATF_TC_BODY(cleanup_registration_failure, tc)
{
	struct svc_runtime svc;
	struct kevent event;
	struct timespec deadline, timeout = { .tv_sec = 5 };
	int fds[2], badfd, kq;

	(void)tc;
	idle_runtime_init(&svc, "org.test.cleanup.registration");
	ATF_REQUIRE_EQ(0, pipe(fds));
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	badfd = dup(fds[0]);
	ATF_REQUIRE(badfd >= 0);
	ATF_REQUIRE_EQ(0, close(badfd));
	svc.pd_fd = badfd;
	svc.cleanup.pending = true;
	svc.cleanup.child_pending = true;
	svc.cleanup.fd = fds[0];
	svc.cleanup.timer_ident = ++cleanup_timer_next_ident;
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &deadline));
	deadline.tv_sec += 1;
	svc.cleanup.deadline = deadline;
	runtime_removals = 0;
	ATF_REQUIRE_EQ(-1, supervisor_cleanup_rebind(&svc, kq));
	ATF_CHECK_EQ(EBADF, errno);
	ATF_CHECK_EQ(EBADF, svc.cleanup.error);
	ATF_CHECK(svc.cleanup.pending);
	ATF_CHECK(svc.cleanup.child_pending);
	ATF_CHECK_EQ(0, runtime_removals);
	ATF_CHECK_EQ(deadline.tv_sec, svc.cleanup.deadline.tv_sec);
	ATF_CHECK_EQ(deadline.tv_nsec, svc.cleanup.deadline.tv_nsec);
	/* The timer remains observable despite the preceding EBADF. */
	ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &event, 1, &timeout));
	ATF_CHECK_EQ(EVFILT_TIMER, event.filter);
	ATF_CHECK_EQ(svc.cleanup.timer_ident, event.ident);
	ATF_CHECK(event.udata == &svc);
	/* The coalition watch is also registered; this pipe stands in for it. */
	ATF_REQUIRE_EQ(1, write(fds[1], "R", 1));
	ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &event, 1, &timeout));
	ATF_CHECK_EQ(EVFILT_READ, event.filter);
	ATF_CHECK_EQ(fds[0], (int)event.ident);
	ATF_CHECK(event.udata == &svc);
	close(fds[0]);
	close(fds[1]);
	close(kq);
}

ATF_TC_WITHOUT_HEAD(cleanup_missing_coalition);
ATF_TC_BODY(cleanup_missing_coalition, tc)
{
	struct svc_runtime svc;
	struct kevent event;
	struct timespec timeout = { .tv_sec = 5 };
	int pd;
	pid_t child;

	(void)tc;
	cleanup_mock = false;
	child = pdfork(&pd, 0);
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		for (;;)
			pause();
	}
	idle_runtime_init(&svc, "org.test.cleanup.missing");
	svc.pid = child;
	svc.pd_fd = pd;
	svc.coalition_fd = -1;
	svc.cleanup.fd = -1;
	switchboard_kq = kqueue();
	ATF_REQUIRE(switchboard_kq >= 0);
	runtime_removals = 0;
	supervisor_cleanup_failed_launch(&svc);
	ATF_REQUIRE(svc.cleanup.pending);
	ATF_REQUIRE(svc.cleanup.child_pending);
	ATF_REQUIRE(!svc.cleanup.coalition_complete);
	ATF_CHECK_EQ(SVC_STATE_STOPPING, svc.state);
	ATF_CHECK(svc.cleanup.error != 0);
	ATF_CHECK_EQ(pd, svc.pd_fd);
	ATF_CHECK_EQ(0, runtime_removals);
	ATF_REQUIRE_EQ(0, pdkill(pd, SIGKILL));
	ATF_REQUIRE_EQ(1, kevent(switchboard_kq, NULL, 0, &event, 1, &timeout));
	ATF_REQUIRE_EQ(EVFILT_PROCDESC, event.filter);
	ATF_REQUIRE_EQ(pd, (int)event.ident);
	ATF_REQUIRE((event.fflags & NOTE_EXIT) != 0);
	supervisor_handle_procdesc(&event);
	ATF_CHECK(!svc.cleanup.child_pending);
	ATF_CHECK_EQ(-1, svc.pd_fd);
	/* Child exit alone cannot prove the missing coalition was cleaned up. */
	ATF_CHECK(svc.cleanup.pending);
	ATF_CHECK_EQ(SVC_STATE_STOPPING, svc.state);
	ATF_CHECK_EQ(0, runtime_removals);
	close(switchboard_kq);
	switchboard_kq = -1;
}

ATF_TC(cleanup_live_process);
ATF_TC_HEAD(cleanup_live_process, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "supervisor retains runtime until a real enlisted process finishes exiting");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(cleanup_live_process, tc)
{
	struct svc_runtime svc;
	struct coalition_req_hdr enlist = { .op = COALITION_OP_ENLIST };
	struct coalition_set_signal_req stop = {
	    .op = COALITION_OP_SET_SIGNAL, .signal = SIGSTOP };
	struct coalition_reply reply;
	struct capability_coalition_status state = { 0 };
	struct kevent event;
	struct timespec zero = { 0 }, timeout = { .tv_sec = 5 };
	int device, pd, status;
	pid_t child;

	(void)tc;
	cleanup_mock = false;
	child = pdfork(&pd, 0);
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		for (;;)
			pause();
	}
	device = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE(device >= 0);
	idle_runtime_init(&svc, "org.test.cleanup.process");
	svc.cleanup.fd = -1;
	svc.coalition_fd = capability_service_connect(device, "coalition");
	ATF_REQUIRE(svc.coalition_fd >= 0);
	ATF_REQUIRE_EQ(0, capability_service_call_fds(svc.coalition_fd,
	    &stop, sizeof(stop), NULL, 0, &reply, sizeof(reply), NULL, 0));
	ATF_REQUIRE_EQ(0, reply.status);
	ATF_REQUIRE_EQ(0, capability_service_call_fds(svc.coalition_fd,
	    &enlist, sizeof(enlist), &pd, 1, &reply, sizeof(reply), NULL, 0));
	ATF_REQUIRE_EQ(0, reply.status);
	switchboard_kq = kqueue();
	ATF_REQUIRE(switchboard_kq >= 0);
	runtime_removals = 0;
	supervisor_cleanup_failed_launch(&svc);
	ATF_REQUIRE(svc.cleanup.pending);
	ATF_REQUIRE(svc.cleanup.fd >= 0);
	ATF_CHECK_EQ(SVC_STATE_STOPPING, svc.state);
	ATF_CHECK_EQ(0, runtime_removals);
	ATF_REQUIRE_EQ(0, capability_coalition_status(svc.cleanup.fd, &state));
	ATF_CHECK_EQ(CAPABILITY_COALITION_DRAINING, state.phase);
	ATF_CHECK_EQ(1, state.processes);
	ATF_CHECK_EQ(0, kevent(switchboard_kq, NULL, 0, &event, 1, &zero));
	ATF_REQUIRE_EQ(0, pdkill(pd, SIGKILL));
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE_EQ(1, kevent(switchboard_kq, NULL, 0, &event, 1, &timeout));
	ATF_REQUIRE_EQ(EVFILT_READ, event.filter);
	ATF_REQUIRE_EQ(svc.cleanup.fd, (int)event.ident);
	ATF_REQUIRE(event.udata == &svc);
	supervisor_handle_channel(&event);
	ATF_CHECK(!svc.cleanup.pending);
	ATF_CHECK_EQ(-1, svc.cleanup.fd);
	ATF_CHECK_EQ(0, svc.cleanup.timer_ident);
	ATF_CHECK_EQ(SVC_STATE_STOPPED, svc.state);
	ATF_CHECK_EQ(1, runtime_removals);
	close(pd);
	close(device);
	close(switchboard_kq);
	switchboard_kq = -1;
}

ATF_TC(cleanup_live_outcomes);
ATF_TC_HEAD(cleanup_live_outcomes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "supervisor gate consumes real coalition completion and failure outcomes");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(cleanup_live_outcomes, tc)
{
	struct svc_runtime svc;
	struct coalition_req_hdr request = { .op = COALITION_OP_ENLIST };
	struct coalition_reply reply;
	int device, shm;
	unsigned fail;

	(void)tc;
	cleanup_mock = false;
	device = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE(device >= 0);
	switchboard_kq = kqueue();
	ATF_REQUIRE(switchboard_kq >= 0);
	for (fail = 0; fail < 2; fail++) {
		idle_runtime_init(&svc, "org.test.cleanup.live");
		svc.cleanup.fd = -1;
		svc.state = SVC_STATE_STARTING;
		svc.coalition_fd = capability_service_connect(device, "coalition");
		ATF_REQUIRE(svc.coalition_fd >= 0);
		shm = -1;
		if (fail) {
			shm = memfd_create("cleanup-live", MFD_ALLOW_SEALING);
			ATF_REQUIRE(shm >= 0);
			ATF_REQUIRE_EQ(0, ftruncate(shm, 4096));
			ATF_REQUIRE_EQ(0, fcntl(shm, F_ADD_SEALS, F_SEAL_SHRINK));
			ATF_REQUIRE_EQ(0, capability_service_call_fds(svc.coalition_fd,
			    &request, sizeof(request), &shm, 1, &reply, sizeof(reply),
			    NULL, 0));
			ATF_REQUIRE_EQ(0, reply.status);
		}
		runtime_removals = 0;
		supervisor_cleanup_failed_launch(&svc);
		ATF_CHECK_EQ(-1, svc.coalition_fd);
		ATF_CHECK_EQ(-1, svc.cleanup.fd);
		ATF_CHECK_EQ(fail != 0, svc.cleanup.pending);
		ATF_CHECK_EQ(fail ? EPERM : 0, svc.cleanup.error);
		ATF_CHECK_EQ(fail ? 0 : 1, runtime_removals);
		ATF_CHECK_EQ(fail ? SVC_STATE_STOPPING : SVC_STATE_STOPPED,
		    svc.state);
		if (shm >= 0)
			close(shm);
	}
	close(switchboard_kq);
	switchboard_kq = -1;
	close(device);
}

ATF_TC(cleanup_rebind_deadline);
ATF_TC_HEAD(cleanup_rebind_deadline, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "cleanup rebind preserves expired deadline and arms timer despite bad observer");
	atf_tc_set_md_var(tc, "timeout", "5");
}
ATF_TC_BODY(cleanup_rebind_deadline, tc)
{
	struct svc_runtime svc;
	struct kevent event;
	struct timespec timeout = { .tv_sec = 1 };
	struct timespec deadline;
	int kq;

	(void)tc;
	idle_runtime_init(&svc, "org.test.cleanup");
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	svc.cleanup.pending = true;
	svc.cleanup.fd = -1;
	svc.cleanup.timer_ident = ++cleanup_timer_next_ident;
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &deadline));
	deadline.tv_sec--;
	svc.cleanup.deadline = deadline;
	ATF_REQUIRE_EQ(0, supervisor_cleanup_rebind(&svc, kq));
	ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &event, 1, &timeout));
	ATF_CHECK_EQ(EVFILT_TIMER, event.filter);
	ATF_CHECK_EQ(svc.cleanup.timer_ident, event.ident);
	ATF_CHECK(event.udata == &svc);
	ATF_CHECK_EQ(deadline.tv_sec, svc.cleanup.deadline.tv_sec);
	ATF_CHECK_EQ(deadline.tv_nsec, svc.cleanup.deadline.tv_nsec);

	/* A failed read registration must not skip the independent timer. */
	svc.cleanup.fd = INT_MAX;
	ATF_REQUIRE_ERRNO(EBADF, supervisor_cleanup_rebind(&svc, kq) == -1);
	ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &event, 1, &timeout));
	ATF_CHECK_EQ(EVFILT_TIMER, event.filter);
	ATF_CHECK_EQ(svc.cleanup.timer_ident, event.ident);
	ATF_CHECK(event.udata == &svc);
	ATF_CHECK_EQ(deadline.tv_sec, svc.cleanup.deadline.tv_sec);
	close(kq);
}

ATF_TC(cleanup_terminal_states);
ATF_TC_HEAD(cleanup_terminal_states, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "failed/released cleanup retains runtime; a timed-out wait can complete later");
}
ATF_TC_BODY(cleanup_terminal_states, tc)
{
	struct svc_runtime svc;
	struct kevent event;
	uint32_t phases[] = { CAPABILITY_COALITION_FAILED,
	    CAPABILITY_COALITION_RELEASED, CAPABILITY_COALITION_DRAINING };
	unsigned i;
	int fds[2];

	(void)tc;
	cleanup_mock = true;
	switchboard_kq = kqueue();
	ATF_REQUIRE(switchboard_kq >= 0);
	for (i = 0; i < nitems(phases); i++) {
		idle_runtime_init(&svc, "org.test.cleanup");
		ATF_REQUIRE_EQ(0, pipe(fds));
		svc.cleanup.fd = fds[0];
		svc.cleanup.pending = true;
		svc.cleanup.was_stopping = true;
		svc.state = SVC_STATE_STOPPING;
		cleanup_phase = phases[i];
		runtime_removals = 0;
		supervisor_cleanup_event(&svc);
		ATF_CHECK(svc.cleanup.pending);
		ATF_CHECK_EQ(0, runtime_removals);
		ATF_CHECK_EQ(SVC_STATE_STOPPING, svc.state);
		if (cleanup_phase == CAPABILITY_COALITION_DRAINING) {
			/* An already-queued procdesc exit cannot restart cleanup. */
			EV_SET(&event, 0, EVFILT_PROCDESC, 0, NOTE_EXIT, 0, &svc);
			supervisor_handle_procdesc(&event);
			ATF_CHECK(svc.cleanup.pending);
			ATF_CHECK_EQ(fds[0], svc.cleanup.fd);
			ATF_CHECK_EQ(0, runtime_removals);
			svc.cleanup.timer_ident = ++cleanup_timer_next_ident;
			EV_SET(&event, svc.cleanup.timer_ident, EVFILT_TIMER,
			    0, 0, 0, &svc);
			supervisor_handle_timer(&event);
			ATF_CHECK_EQ(ETIMEDOUT, svc.cleanup.error);
			ATF_CHECK(svc.cleanup.pending);
			ATF_CHECK_EQ(0, runtime_removals);
			ATF_CHECK_EQ(fds[0], svc.cleanup.fd);
			cleanup_phase = CAPABILITY_COALITION_COMPLETE;
			supervisor_cleanup_event(&svc);
			ATF_CHECK(!svc.cleanup.pending);
			ATF_CHECK_EQ(0, svc.cleanup.error);
			ATF_CHECK_EQ(1, runtime_removals);
			ATF_CHECK_EQ(SVC_STATE_STOPPED, svc.state);
			supervisor_cleanup_event(&svc);
			ATF_CHECK_EQ(1, runtime_removals);
		} else {
			ATF_CHECK_EQ(-1, svc.cleanup.fd);
			ATF_CHECK_EQ(phases[i] == CAPABILITY_COALITION_FAILED ?
			    EIO : EBUSY, svc.cleanup.error);
		}
		ATF_CHECK_EQ(-1, fcntl(fds[0], F_GETFD));
		close(fds[1]);
	}
	close(switchboard_kq);
	switchboard_kq = -1;
	cleanup_mock = false;
}

ATF_TC(cleanup_stop_intent);
ATF_TC_HEAD(cleanup_stop_intent, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "explicit stop during cleanup suppresses restart without releasing the gate");
}
ATF_TC_BODY(cleanup_stop_intent, tc)
{
	struct svc_runtime svc;

	(void)tc;
	idle_runtime_init(&svc, "org.test.cleanup");
	svc.state = SVC_STATE_STOPPING;
	svc.cleanup.pending = true;
	svc_graceful_stop(&svc, -1);
	ATF_CHECK(svc.cleanup.was_stopping);
	ATF_CHECK(svc.cleanup.pending);
	ATF_CHECK_EQ(SVC_STATE_STOPPING, svc.state);
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
	switchboard_kq = -1;

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


static void
idle_channel_pair(int *first, int *second)
{
	int pair[2], error;

	error = mac_capability_channel_create(pair);
	if (error == -1 && errno == ENOSYS)
		atf_tc_skip("kernel channel creation syscall unavailable");
	ATF_REQUIRE_MSG(error == 0, "channel pair: %s", strerror(errno));
	*first = pair[0];
	*second = pair[1];
}

struct idle_provider_ctx {
	int			 fd;
	struct svc_runtime	*svc;
	int			 error;
	/*
	 * The svc_proto dispatch to run for each request.  Defaults to
	 * idle_provider_request (SVC_OP_IDLE); the readiness test installs
	 * ready_provider_request (SVC_OP_READY) to reuse this same thread.
	 */
	void			(*handler)(struct channel *,
				    struct channel_message *, void *);
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
	if (channel_set_request_handler(channel, ctx->handler,
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
	provider.handler = idle_provider_request;
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
	const unsigned oversized[] = { SVC_IDLE_MAX_SECONDS + 1 };

	(void)tc;
	/* handle_idle arms via the global switchboard_kq. */
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;

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

	/* An overflowing millisecond timeout is rejected without arming. */
	idle_run(SVC_STATE_RUNNING, true, oversized, nitems(oversized),
	    &svc, &status);
	ATF_CHECK_EQ(EINVAL, status);
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

	switchboard_kq = -1;
	(void)close(kq);
}

/*
 * handle_ready dispatch for the readiness harness: exactly what svc_request
 * would perform for SVC_OP_READY.
 */
static void
ready_provider_request(struct channel *channel, struct channel_message *message,
    void *argument)
{
	struct idle_provider_ctx *ctx;

	(void)channel;
	ctx = argument;
	handle_ready(ctx->svc, message);
	channel_message_free(message);
}

/*
 * Issue one SVC_OP_READY over `client` and return handle_ready's reply status.
 */
static int
ready_client_request(struct channel *client)
{
	struct idle_client_reply reply;
	struct svc_req_hdr request;
	struct channel_request *pending;
	int result, wants_write;

	memset(&request, 0, sizeof(request));
	request.op = SVC_OP_READY;
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
 * Drive a single SVC_OP_READY at a provider in `state` with manifest.ambient
 * = `ambient`, over a genuine channel, and leave the resulting runtime in
 * *svc.  nprovides == 0 so the names-claimed precondition is trivially met and
 * the on_demand_check_ready() call handle_ready() makes is a no-op.
 */
static void
ready_run(int state, bool ambient, struct svc_runtime *svc, int *status)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct idle_provider_ctx provider;
	struct channel *client;
	pthread_t thread;
	int pair[2];

	idle_channel_pair(&pair[0], &pair[1]);
	idle_runtime_init(svc, "org.test.ready");
	svc->state = state;
	svc->manifest.ambient = ambient;
	svc->manifest.nprovides = 0;
	memset(&provider, 0, sizeof(provider));
	provider.fd = pair[1];
	provider.svc = svc;
	provider.handler = ready_provider_request;
	ATF_REQUIRE_EQ(0, pthread_create(&thread, NULL, idle_provider_thread,
	    &provider));
	ATF_REQUIRE_EQ(0, channel_create(pair[0], &options, &client));
	*status = ready_client_request(client);
	channel_destroy(client);
	ATF_REQUIRE_EQ(0, pthread_join(thread, NULL));
	ATF_CHECK_EQ(0, provider.error);
}

ATF_TC(handle_ready_ambient_promotion);
ATF_TC_HEAD(handle_ready_ambient_promotion, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SVC_OP_READY promotes a STARTING ambient provider straight to "
	    "RUNNING (its own readiness IS the boundary, since it never enters "
	    "capability mode), while a sandboxed provider only records "
	    "protocol_ready and stays STARTING until capability-mode entry.  This "
	    "is what lets an on-demand ambient provider's waiter be drained.");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(handle_ready_ambient_promotion, tc)
{
	struct svc_runtime svc;
	int kq, status;

	(void)tc;
	/* handle_ready -> on_demand_check_ready reads the global switchboard_kq. */
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;
	pending_list = NULL;
	npending = 0;

	/*
	 * Ambient + STARTING: SVC_OP_READY is the readiness boundary, so the
	 * unit is promoted to RUNNING here (no NOTE_CAPMODE will ever fire).  This
	 * is exactly what allows on_demand_check_ready() to broker a waiting
	 * client to an on-demand ambient provider.
	 */
	ready_run(SVC_STATE_STARTING, true, &svc, &status);
	ATF_CHECK_EQ(0, status);
	ATF_CHECK_EQ(SVC_STATE_RUNNING, svc.state);
	ATF_CHECK(svc.protocol_ready);

	/*
	 * Sandboxed + STARTING: readiness is recorded but the unit stays
	 * STARTING; capability-mode entry (supervisor NOTE_CAPMODE) is the
	 * authoritative boundary that moves it to RUNNING.
	 */
	ready_run(SVC_STATE_STARTING, false, &svc, &status);
	ATF_CHECK_EQ(0, status);
	ATF_CHECK_EQ(SVC_STATE_STARTING, svc.state);
	ATF_CHECK(svc.protocol_ready);

	switchboard_kq = -1;
	(void)close(kq);
}

ATF_TC_WITHOUT_HEAD(idle_quiesce_busy_resumes_provider);
ATF_TC_BODY(idle_quiesce_busy_resumes_provider, tc)
{
	struct svc_runtime svc;
	int kq;

	(void)tc;
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	switchboard_kq = kq;
	idle_runtime_init(&svc, "org.test.idle-busy");
	svc.state = SVC_STATE_STOPPING;
	svc.protocol_ready = true;
	svc.idle_stop_pending = true;
	svc.quiesce_pending = true;
	svc.idle_timeout_sec = 5;
	svc.manifest.stop_timeout = 2;
	schedule_stop_kill(&svc, kq);
	ATF_REQUIRE(svc.stop_kill_pending);
	svc_quiesce_complete(&svc, EBUSY, kq);
	ATF_CHECK_EQ(SVC_STATE_RUNNING, svc.state);
	ATF_CHECK(!svc.idle_stop_pending);
	ATF_CHECK(!svc.quiesce_pending);
	ATF_CHECK(!svc.stop_kill_pending);
	ATF_CHECK_EQ(0, svc.idle_timeout_sec);
	switchboard_kq = -1;
	(void)close(kq);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, provider_incarnation);
	ATF_TP_ADD_TC(tp, provider_name_filter);
	ATF_TP_ADD_TC(tp, timer_identifiers);
	ATF_TP_ADD_TC(tp, timer_registration_failure);
	ATF_TP_ADD_TC(tp, circuit_breaker_blocks_on_demand_relaunch);
	ATF_TP_ADD_TC(tp, idle_timer_arm_cancel);
	ATF_TP_ADD_TC(tp, idle_timer_ident_range);
	ATF_TP_ADD_TC(tp, idle_timer_fire_stops_provider);
	ATF_TP_ADD_TC(tp, idle_quiesce_busy_resumes_provider);
	ATF_TP_ADD_TC(tp, idle_note_exit_reactivatable);
	ATF_TP_ADD_TC(tp, cleanup_stop_intent);
	ATF_TP_ADD_TC(tp, cleanup_terminal_states);
	ATF_TP_ADD_TC(tp, cleanup_rebind_deadline);
	ATF_TP_ADD_TC(tp, cleanup_live_outcomes);
	ATF_TP_ADD_TC(tp, cleanup_live_process);
	ATF_TP_ADD_TC(tp, cleanup_unenlisted_child);
	ATF_TP_ADD_TC(tp, cleanup_missing_coalition);
	ATF_TP_ADD_TC(tp, cleanup_registration_failure);
	ATF_TP_ADD_TC(tp, cleanup_updated_intent);
	ATF_TP_ADD_TC(tp, cleanup_compaction);
	ATF_TP_ADD_TC(tp, handle_idle_protocol);
	ATF_TP_ADD_TC(tp, handle_ready_ambient_promotion);
	return (atf_no_error());
}

struct svc_runtime *
svc_by_label_scoped(const char *name, uid_t owner)
{
 struct svc_runtime *svc=svc_by_label(name);
 return svc != NULL && svc->owner_uid == owner ? svc : NULL;
}
bool
svc_responsible_allowed_scoped(const struct svc_manifest *m, uid_t owner,
    const struct svc_responsible *responsible)
{
 (void)owner;return svc_responsible_allowed(m,responsible);
}
