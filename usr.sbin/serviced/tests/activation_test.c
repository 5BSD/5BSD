/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for the Phase 5 timer and path activation sources (activation.c).
 *
 * The implementation is included directly so the tests can drive its arm /
 * fire / teardown state machine and inspect the private ident scheme.  Demand
 * creation is intercepted by stubbing svc_launch_or_await(), so no capability
 * kernel, provider process, or wall-clock wait is needed: firing a source is
 * simulated by calling the same routing entry points the main event loop uses
 * (activation_timer_fire / activation_path_event).
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The other subsystems' ident-range bits, for disjointness assertions. */
#define	STOP_TIMER_BIT		((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 1))
#define	ON_DEMAND_TIMER_BIT	((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 2))
#define	IDLE_TIMER_BIT		((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 3))
#define	SVC_LAUNCH_TIMER_BIT	((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 4))

#include "../activation.c"

/* Full struct layout so the register_all test can build a fake bundle. */
#include "libcapbundle_internal.h"

struct serviced_state sd;
int serviced_kq = -1;

/* --- Stubs for symbols owned by other translation units. --- */

static unsigned launch_calls;
static struct svc_runtime *last_launched;

/*
 * Stand-in for the real launcher.  Records the demand and moves the unit to
 * STARTING, mirroring the visible state change svc_exec() makes, so coalescing
 * (a second fire while STARTING) can be observed.
 */
int
svc_launch_or_await(struct svc_runtime *svc, int kq)
{

	(void)kq;
	launch_calls++;
	last_launched = svc;
	svc->state = SVC_STATE_STARTING;
	return (0);
}

struct svc_runtime *
svc_by_label(const char *label)
{
	unsigned i;

	for (i = 0; i < sd.nservices; i++)
		if (strcmp(sd.services[i].manifest.label, label) == 0)
			return (&sd.services[i]);
	return (NULL);
}

/* Fake single-service bundle registry, populated per register_all test. */
static struct capbundle reg_bundle;
static bool reg_present;

unsigned
bundle_registry_count(void)
{

	return (reg_present ? 1 : 0);
}

struct capbundle *
bundle_registry_get(unsigned idx)
{

	return (reg_present && idx == 0 ? &reg_bundle : NULL);
}

/* --- Helpers --- */

static void
runtime_init(struct svc_runtime *svc, const char *label)
{

	memset(svc, 0, sizeof(*svc));
	svc_runtime_init_fds(svc);
	svc->state = SVC_STATE_STOPPED;
	strlcpy(svc->manifest.label, label, sizeof(svc->manifest.label));
}

static void
reset_globals(int kq)
{

	launch_calls = 0;
	last_launched = NULL;
	reg_present = false;
	serviced_kq = kq;
}

/*
 * The timer source arms a periodic EVFILT_TIMER with an ident in the dedicated
 * activation range, disjoint from every other timer subsystem, and teardown
 * removes it.
 */
ATF_TC(timer_arm_ident_and_teardown);
ATF_TC_HEAD(timer_arm_ident_and_teardown, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "timer arming registers a uniquely-identified periodic EVFILT_TIMER "
	    "disjoint from restart/idle/stop/on-demand/launch idents; teardown "
	    "deletes it");
}
ATF_TC_BODY(timer_arm_ident_and_teardown, tc)
{
	struct svc_runtime svc;
	struct kevent kev;
	uintptr_t id;
	int kq;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	reset_globals(kq);
	runtime_init(&svc, "org.test/timer");

	/* No interval declared: arm is a no-op. */
	activation_source_arm(&svc, kq);
	ATF_CHECK_EQ(0, svc.activation_timer_ident);

	svc.manifest.timer_interval_sec = 30;
	activation_source_arm(&svc, kq);
	id = svc.activation_timer_ident;
	ATF_CHECK(id != 0);
	ATF_CHECK(activation_timer_owns(id));
	/* Disjoint from every other timer range. */
	ATF_CHECK((id & STOP_TIMER_BIT) == 0);
	ATF_CHECK((id & ON_DEMAND_TIMER_BIT) == 0);
	ATF_CHECK((id & IDLE_TIMER_BIT) == 0);
	ATF_CHECK((id & SVC_LAUNCH_TIMER_BIT) == 0);

	/* Idempotent: a second arm does not replace the live timer. */
	activation_source_arm(&svc, kq);
	ATF_CHECK_EQ(id, svc.activation_timer_ident);

	/* Really registered: a manual delete succeeds exactly once. */
	EV_SET(&kev, id, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	ATF_CHECK_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));
	/* Re-add so teardown has something to delete. */
	EV_SET(&kev, id, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, 30, &svc);
	ATF_CHECK_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));

	activation_source_teardown(&svc, kq);
	ATF_CHECK_EQ(0, svc.activation_timer_ident);
	/* Gone from the kqueue. */
	EV_SET(&kev, id, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	errno = 0;
	ATF_CHECK(kevent(kq, &kev, 1, NULL, 0, NULL) == -1 && errno == ENOENT);

	(void)close(kq);
}

/*
 * Firing a timer on a stopped unit creates exactly one activation; a second
 * fire while it is still starting coalesces instead of stacking a launch.
 */
ATF_TC(timer_fire_and_coalesce);
ATF_TC_HEAD(timer_fire_and_coalesce, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a timer fire on a STOPPED unit launches it once; a fire while it is "
	    "already starting/running coalesces");
}
ATF_TC_BODY(timer_fire_and_coalesce, tc)
{
	int kq;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	reset_globals(kq);

	sd.services = calloc(2, sizeof(*sd.services));
	ATF_REQUIRE(sd.services != NULL);
	runtime_init(&sd.services[0], "org.test/timer");
	sd.services[0].manifest.timer_interval_sec = 30;
	sd.nservices = 1;

	activation_source_arm(&sd.services[0], kq);
	ATF_REQUIRE(sd.services[0].activation_timer_ident != 0);

	/* First fire: STOPPED -> one launch. */
	activation_timer_fire(sd.services[0].activation_timer_ident, kq);
	ATF_CHECK_EQ(1, launch_calls);
	ATF_CHECK_EQ(&sd.services[0], last_launched);
	ATF_CHECK_EQ(SVC_STATE_STARTING, sd.services[0].state);

	/* Second fire while STARTING: coalesced, no new launch. */
	activation_timer_fire(sd.services[0].activation_timer_ident, kq);
	ATF_CHECK_EQ(1, launch_calls);

	/* Running: still coalesced. */
	sd.services[0].state = SVC_STATE_RUNNING;
	activation_timer_fire(sd.services[0].activation_timer_ident, kq);
	ATF_CHECK_EQ(1, launch_calls);

	/* A completed oneshot re-activates on the next fire. */
	sd.services[0].state = SVC_STATE_DONE;
	activation_timer_fire(sd.services[0].activation_timer_ident, kq);
	ATF_CHECK_EQ(2, launch_calls);

	/* A stale ident (no owner) is ignored. */
	activation_timer_fire(sd.services[0].activation_timer_ident + 999, kq);
	ATF_CHECK_EQ(2, launch_calls);

	free(sd.services);
	sd.services = NULL;
	sd.nservices = 0;
	(void)close(kq);
}

/*
 * The path source opens and watches its path with a unique vnode descriptor; a
 * simulated NOTE_WRITE activates the stopped unit; a burst coalesces; and
 * teardown removes the watch.
 */
ATF_TC(path_arm_write_and_teardown);
ATF_TC_HEAD(path_arm_write_and_teardown, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "path arming opens+watches the path; NOTE_WRITE activates a STOPPED "
	    "unit; bursts coalesce; teardown removes the watch");
}
ATF_TC_BODY(path_arm_write_and_teardown, tc)
{
	struct kevent kev;
	char dir[PATH_MAX];
	int kq, watched_fd;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	reset_globals(kq);

	/* Real directory to watch, in the test's cwd. */
	(void)snprintf(dir, sizeof(dir), "./watched");
	ATF_REQUIRE(mkdir(dir, 0755) == 0 || errno == EEXIST);

	/* sd.services must hold the unit so path_owner() can find it by fd. */
	sd.services = calloc(1, sizeof(*sd.services));
	ATF_REQUIRE(sd.services != NULL);
	runtime_init(&sd.services[0], "org.test/pathwatch");
	strlcpy(sd.services[0].manifest.activation_path, dir,
	    sizeof(sd.services[0].manifest.activation_path));
	sd.nservices = 1;

	activation_source_arm(&sd.services[0], kq);
	watched_fd = sd.services[0].activation_path_fd;
	ATF_CHECK(watched_fd >= 0);
	/* The vnode ident (a descriptor) is disjoint from the timer range. */
	ATF_CHECK(!activation_timer_owns((uintptr_t)watched_fd));

	/* Idempotent arm keeps the same descriptor. */
	activation_source_arm(&sd.services[0], kq);
	ATF_CHECK_EQ(watched_fd, sd.services[0].activation_path_fd);

	/* Simulate a NOTE_WRITE event routed from the event loop. */
	EV_SET(&kev, watched_fd, EVFILT_VNODE, 0, NOTE_WRITE, 0,
	    &sd.services[0]);
	activation_path_event(&kev, kq);
	ATF_CHECK_EQ(1, launch_calls);
	ATF_CHECK_EQ(SVC_STATE_STARTING, sd.services[0].state);

	/* Burst: a second write while starting coalesces. */
	activation_path_event(&kev, kq);
	ATF_CHECK_EQ(1, launch_calls);

	activation_source_teardown(&sd.services[0], kq);
	ATF_CHECK_EQ(-1, sd.services[0].activation_path_fd);

	free(sd.services);
	sd.services = NULL;
	sd.nservices = 0;
	(void)rmdir(dir);
	(void)close(kq);
}

/*
 * A NOTE_DELETE on the watched path re-opens if the path was atomically
 * replaced, and cleanly drops the watch (no crash, fd cleared) if it is gone.
 */
ATF_TC(path_delete_reopen_and_drop);
ATF_TC_HEAD(path_delete_reopen_and_drop, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NOTE_DELETE re-registers when the path reappears and drops the "
	    "watch cleanly when it does not");
}
ATF_TC_BODY(path_delete_reopen_and_drop, tc)
{
	struct kevent kev;
	char dir[PATH_MAX];
	int kq, first_fd, second_fd;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	reset_globals(kq);

	(void)snprintf(dir, sizeof(dir), "./reopen");
	ATF_REQUIRE(mkdir(dir, 0755) == 0 || errno == EEXIST);

	sd.services = calloc(1, sizeof(*sd.services));
	ATF_REQUIRE(sd.services != NULL);
	runtime_init(&sd.services[0], "org.test/pathwatch");
	strlcpy(sd.services[0].manifest.activation_path, dir,
	    sizeof(sd.services[0].manifest.activation_path));
	sd.nservices = 1;

	activation_source_arm(&sd.services[0], kq);
	first_fd = sd.services[0].activation_path_fd;
	ATF_REQUIRE(first_fd >= 0);

	/*
	 * Atomic-replace case: the path still exists at event time (a new dir
	 * was put in place), so the delete handler re-opens and re-registers.
	 */
	EV_SET(&kev, first_fd, EVFILT_VNODE, 0, NOTE_DELETE, 0,
	    &sd.services[0]);
	activation_path_event(&kev, kq);
	ATF_CHECK_EQ(1, launch_calls);		/* the change created demand */
	second_fd = sd.services[0].activation_path_fd;
	ATF_CHECK(second_fd >= 0);		/* re-registered */

	/* Reset demand state so the drop case can re-fire. */
	sd.services[0].state = SVC_STATE_STOPPED;

	/* Removal case: delete the directory, then a delete event drops it. */
	ATF_REQUIRE(rmdir(dir) == 0);
	EV_SET(&kev, second_fd, EVFILT_VNODE, 0, NOTE_DELETE, 0,
	    &sd.services[0]);
	activation_path_event(&kev, kq);
	ATF_CHECK_EQ(2, launch_calls);
	ATF_CHECK_EQ(-1, sd.services[0].activation_path_fd);	/* dropped */

	free(sd.services);
	sd.services = NULL;
	sd.nservices = 0;
	(void)close(kq);
}

/*
 * activation_register_all() creates a stopped slot for a purely timer/path
 * activated unit that startup never launched, and arms its source.
 */
ATF_TC(register_all_creates_slot);
ATF_TC_HEAD(register_all_creates_slot, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "register_all allocates a stopped slot for a demand-only unit and "
	    "arms its declared activation source");
}
ATF_TC_BODY(register_all_creates_slot, tc)
{
	struct capbundle_service *cs;
	int kq;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	reset_globals(kq);

	sd.services = calloc(SERVICED_MAX_SERVICES, sizeof(*sd.services));
	ATF_REQUIRE(sd.services != NULL);
	sd.nservices = 0;

	/* Build a one-service fake bundle declaring a timer source. */
	memset(&reg_bundle, 0, sizeof(reg_bundle));
	strlcpy(reg_bundle.bundle_id, "org.test.reg",
	    sizeof(reg_bundle.bundle_id));
	reg_bundle.nservices = 1;
	cs = &reg_bundle.services[0];
	strlcpy(cs->label, "org.test.reg/timerunit", sizeof(cs->label));
	strlcpy(cs->program, "/dev/null", sizeof(cs->program));
	cs->timer_interval_sec = 60;
	reg_present = true;

	ATF_CHECK_EQ(0, activation_register_all(kq));
	ATF_CHECK_EQ(1, sd.nservices);
	ATF_CHECK_STREQ("org.test.reg/timerunit",
	    sd.services[0].manifest.label);
	ATF_CHECK_EQ(SVC_STATE_STOPPED, sd.services[0].state);
	ATF_CHECK(sd.services[0].activation_timer_ident != 0);

	/* Idempotent: a re-run neither duplicates the slot nor re-arms. */
	ATF_CHECK_EQ(0, activation_register_all(kq));
	ATF_CHECK_EQ(1, sd.nservices);

	free(sd.services);
	sd.services = NULL;
	sd.nservices = 0;
	(void)close(kq);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, timer_arm_ident_and_teardown);
	ATF_TP_ADD_TC(tp, timer_fire_and_coalesce);
	ATF_TP_ADD_TC(tp, path_arm_write_and_teardown);
	ATF_TP_ADD_TC(tp, path_delete_reopen_and_drop);
	ATF_TP_ADD_TC(tp, register_all_creates_slot);

	return (atf_no_error());
}
