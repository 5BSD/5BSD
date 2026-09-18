/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 *
 * registry_watch unit tests: the install-root watch is driven through a real
 * kqueue against temporary roots, with supervisor_reload stubbed, so the
 * mechanics -- arming, event routing, settle timer coalescing, a root that
 * disappears or appears later, and the settle override -- are proven without
 * a running switchboard.
 */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "switchboard.h"

/* ---- stubs for the switchboard globals registry_watch.c reaches ---- */
struct switchboard_state sd;
const char *switchboard_bundle_dir_system;
const char *switchboard_bundle_dir_user;
static unsigned reloads;
static unsigned fake_quarantined;	/* what the "scan" reports afterwards */
static unsigned fake_failures;		/* reloads left that "fail" outright */

int
supervisor_reload(int kq, char *summary, size_t sumlen)
{
	(void)kq; (void)summary; (void)sumlen;
	reloads++;
	if (fake_failures > 0) {
		fake_failures--;
		return (-1);
	}
	return (0);
}

unsigned
bundle_registry_quarantined(void)
{
	return (fake_quarantined);
}

/* ---- harness ---- */
static char sysroot[PATH_MAX], userroot[PATH_MAX], base[PATH_MAX];

static void
make_roots(bool with_user)
{
	strlcpy(base, "/tmp/rw.XXXXXX", sizeof(base));
	ATF_REQUIRE(mkdtemp(base) != NULL);
	snprintf(sysroot, sizeof(sysroot), "%s/System", base);
	snprintf(userroot, sizeof(userroot), "%s/Apps", base);
	ATF_REQUIRE_EQ(0, mkdir(sysroot, 0755));
	if (with_user)
		ATF_REQUIRE_EQ(0, mkdir(userroot, 0755));
	switchboard_bundle_dir_system = sysroot;
	switchboard_bundle_dir_user = userroot;
	reloads = 0;
	fake_quarantined = 0;
	fake_failures = 0;
	memset(&sd, 0, sizeof(sd));
	registry_watch_fini();		/* fresh module state per scenario */
}

/*
 * Pump the kqueue like switchboard's loop for up to `ms`, routing vnode events
 * and the settle timer to registry_watch.  Returns when `reloads` reaches
 * `want` or time runs out.
 */
static void
pump(int kq, unsigned want, int ms)
{
	struct timespec ts = { 0, 50 * 1000 * 1000 };
	struct kevent ev;
	int elapsed = 0, n;

	while (reloads < want && elapsed < ms) {
		n = kevent(kq, NULL, 0, &ev, 1, &ts);
		elapsed += 50;
		if (n <= 0)
			continue;
		if (ev.filter == EVFILT_VNODE && registry_watch_owns((int)ev.ident))
			registry_watch_event(&ev, kq);
		else if (ev.filter == EVFILT_TIMER &&
		    registry_watch_is_timer(ev.ident))
			registry_watch_timer_fire(kq);
	}
}

static void
drop_bundle(const char *root, const char *name)
{
	char p[PATH_MAX];

	snprintf(p, sizeof(p), "%s/%s.cap", root, name);
	ATF_REQUIRE_EQ(0, mkdir(p, 0755));
}

ATF_TC_WITHOUT_HEAD(change_settles_into_one_reload);
ATF_TC_BODY(change_settles_into_one_reload, tc)
{
	int kq = kqueue();

	ATF_REQUIRE(kq >= 0);
	make_roots(true);
	setenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE", "1", 1);
	registry_watch_arm(kq);
	ATF_CHECK(!registry_watch_pending());
	drop_bundle(sysroot, "New");
	pump(kq, 1, 4000);
	ATF_CHECK_EQ(1, reloads);
	ATF_CHECK(!registry_watch_pending());
	/* Quiet afterwards: no spurious reload. */
	pump(kq, 2, 1500);
	ATF_CHECK_EQ(1, reloads);
	close(kq);
}

ATF_TC_WITHOUT_HEAD(burst_coalesces_and_extends_settle);
ATF_TC_BODY(burst_coalesces_and_extends_settle, tc)
{
	int kq = kqueue();
	unsigned i;

	ATF_REQUIRE(kq >= 0);
	make_roots(true);
	setenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE", "1", 1);
	registry_watch_arm(kq);
	/* Ten writes across both roots within the settle window. */
	for (i = 0; i < 5; i++) {
		char n[16];

		snprintf(n, sizeof(n), "S%u", i); drop_bundle(sysroot, n);
		snprintf(n, sizeof(n), "U%u", i); drop_bundle(userroot, n);
		pump(kq, 1, 100);	/* route the events, do not wait it out */
	}
	ATF_CHECK_EQ(0, reloads);	/* still settling */
	ATF_CHECK(registry_watch_pending());
	pump(kq, 1, 4000);
	ATF_CHECK_EQ(1, reloads);	/* exactly one for the whole burst */
	close(kq);
}

ATF_TC_WITHOUT_HEAD(absent_root_is_watched_for_and_then_watched);
ATF_TC_BODY(absent_root_is_watched_for_and_then_watched, tc)
{
	int kq = kqueue();

	ATF_REQUIRE(kq >= 0);
	make_roots(false);		/* no Apps/ yet */
	setenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE", "1", 1);
	registry_watch_arm(kq);
	/* pkg creates Apps/ later and drops a bundle in. */
	ATF_REQUIRE_EQ(0, mkdir(userroot, 0755));
	pump(kq, 1, 4000);		/* parent watch -> arm -> settle -> reload */
	ATF_CHECK_EQ(1, reloads);
	drop_bundle(userroot, "Late");
	pump(kq, 2, 4000);		/* now the root itself is watched */
	ATF_CHECK_EQ(2, reloads);
	close(kq);
}

ATF_TC_WITHOUT_HEAD(removed_root_drops_watch_and_returns);
ATF_TC_BODY(removed_root_drops_watch_and_returns, tc)
{
	int kq = kqueue();

	ATF_REQUIRE(kq >= 0);
	make_roots(true);
	setenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE", "1", 1);
	registry_watch_arm(kq);
	ATF_REQUIRE_EQ(0, rmdir(userroot));
	pump(kq, 1, 4000);		/* the removal itself is a change */
	ATF_CHECK_EQ(1, reloads);
	/* Root gone: nothing under it can be watched, but its return is. */
	ATF_REQUIRE_EQ(0, mkdir(userroot, 0755));
	drop_bundle(userroot, "Back");
	pump(kq, 2, 4000);
	ATF_CHECK_EQ(2, reloads);
	close(kq);
}

ATF_TC_WITHOUT_HEAD(shutdown_suppresses_reload);
ATF_TC_BODY(shutdown_suppresses_reload, tc)
{
	int kq = kqueue();

	ATF_REQUIRE(kq >= 0);
	make_roots(true);
	setenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE", "1", 1);
	registry_watch_arm(kq);
	sd.shutting_down = true;
	drop_bundle(sysroot, "Late");
	pump(kq, 1, 2500);
	ATF_CHECK_EQ(0, reloads);
	ATF_CHECK(!registry_watch_pending());
	close(kq);
}

/* Bad settle overrides fall back to the 2s default; a good one is honoured. */
ATF_TC_WITHOUT_HEAD(settle_override_is_validated);
ATF_TC_BODY(settle_override_is_validated, tc)
{
	static const char *const bad[] = { "0", "abc", "-1", "61", "1x", "" };
	struct timeval t0, t1;
	unsigned i;
	int kq, ms;

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		kq = kqueue();
		ATF_REQUIRE(kq >= 0);
		make_roots(true);
		setenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE", bad[i], 1);
		registry_watch_arm(kq);
		drop_bundle(sysroot, "X");
		gettimeofday(&t0, NULL);
		pump(kq, 1, 5000);
		gettimeofday(&t1, NULL);
		ms = (int)((t1.tv_sec - t0.tv_sec) * 1000 +
		    (t1.tv_usec - t0.tv_usec) / 1000);
		ATF_CHECK_EQ_MSG(1, reloads, "override '%s'", bad[i]);
		ATF_CHECK_MSG(ms >= 1500, "override '%s' settled in %dms, "
		    "expected the 2s default", bad[i], ms);
		close(kq);
	}
	unsetenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE");
}

ATF_TC_WITHOUT_HEAD(unowned_descriptors_are_not_claimed);
ATF_TC_BODY(unowned_descriptors_are_not_claimed, tc)
{
	int kq = kqueue(), other;

	ATF_REQUIRE(kq >= 0);
	make_roots(true);
	registry_watch_arm(kq);
	other = open("/tmp", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(other >= 0);
	ATF_CHECK(!registry_watch_owns(other));
	ATF_CHECK(!registry_watch_owns(-1));
	ATF_CHECK(!registry_watch_is_timer(0));
	ATF_CHECK(!registry_watch_is_timer(1));
	close(other);
	close(kq);
}

/* A scan that quarantines a bundle (pkg still extracting) is retried a bounded
 * number of settled times, then gives up until the next real change. */
ATF_TC_WITHOUT_HEAD(quarantined_scan_is_retried_boundedly);
ATF_TC_BODY(quarantined_scan_is_retried_boundedly, tc)
{
	int kq = kqueue();

	ATF_REQUIRE(kq >= 0);
	make_roots(true);
	setenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE", "1", 1);
	registry_watch_arm(kq);
	fake_quarantined = 1;			/* every scan "finds" one */
	drop_bundle(sysroot, "Partial");
	pump(kq, 1, 4000);
	ATF_CHECK_EQ(1, reloads);
	ATF_CHECK(registry_watch_pending());	/* retry armed */
	pump(kq, 9, 14000);			/* 8 retries, then stop */
	ATF_CHECK_EQ(9, reloads);
	ATF_CHECK(!registry_watch_pending());
	pump(kq, 10, 2500);			/* no further retries */
	ATF_CHECK_EQ(9, reloads);
	/* Once a scan is clean, the retry budget is back for the next event. */
	fake_quarantined = 0;
	drop_bundle(sysroot, "Whole");
	pump(kq, 10, 4000);
	ATF_CHECK_EQ(10, reloads);
	ATF_CHECK(!registry_watch_pending());
	close(kq);
}

/*
 * A rescan that FAILS outright (a registered SYSTEM bundle caught half
 * written: previous registry retained) is retried on the settle timer just
 * like a quarantine -- nothing else would rescan once the copy completes --
 * and the retries stop as soon as a rescan succeeds.
 */
ATF_TC_WITHOUT_HEAD(failed_rescan_is_retried_until_it_succeeds);
ATF_TC_BODY(failed_rescan_is_retried_until_it_succeeds, tc)
{
	int kq = kqueue();

	ATF_REQUIRE(kq >= 0);
	make_roots(true);
	setenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE", "1", 1);
	registry_watch_arm(kq);
	fake_failures = 2;			/* first two rescans fail */
	drop_bundle(sysroot, "HalfWritten");
	pump(kq, 1, 4000);
	ATF_CHECK_EQ(1, reloads);
	ATF_CHECK(registry_watch_pending());	/* retry armed after failure */
	pump(kq, 3, 6000);			/* 2nd fails, 3rd succeeds */
	ATF_CHECK_EQ(3, reloads);
	ATF_CHECK_EQ(0, fake_failures);
	ATF_CHECK(!registry_watch_pending());	/* success ends the retries */
	pump(kq, 4, 2500);
	ATF_CHECK_EQ(3, reloads);
	close(kq);
}

/* A rescan that keeps failing is retried a bounded number of times only. */
ATF_TC_WITHOUT_HEAD(persistently_failing_rescan_gives_up);
ATF_TC_BODY(persistently_failing_rescan_gives_up, tc)
{
	int kq = kqueue();

	ATF_REQUIRE(kq >= 0);
	make_roots(true);
	setenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE", "1", 1);
	registry_watch_arm(kq);
	fake_failures = 1000;
	drop_bundle(sysroot, "Broken");
	pump(kq, 9, 14000);			/* 1 + 8 bounded retries */
	ATF_CHECK_EQ(9, reloads);
	ATF_CHECK(!registry_watch_pending());
	pump(kq, 10, 2500);
	ATF_CHECK_EQ(9, reloads);
	/* A fresh folder change gets a fresh budget. */
	fake_failures = 0;
	drop_bundle(userroot, "Fine");
	pump(kq, 10, 4000);
	ATF_CHECK_EQ(10, reloads);
	ATF_CHECK(!registry_watch_pending());
	close(kq);
}

/*
 * A permanently quarantined bundle must not re-arm the whole retry budget
 * on every later folder change: after exhaustion the watch waits for a
 * change; a later change gets ONE scan plus a fresh budget only if that
 * scan still quarantines -- which it will, so cap the cost: each change
 * costs the budget at most once, and nothing rescans between changes.
 */
ATF_TC_WITHOUT_HEAD(exhausted_budget_waits_for_a_change);
ATF_TC_BODY(exhausted_budget_waits_for_a_change, tc)
{
	int kq = kqueue();

	ATF_REQUIRE(kq >= 0);
	make_roots(true);
	setenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE", "1", 1);
	registry_watch_arm(kq);
	fake_quarantined = 1;			/* never comes whole */
	drop_bundle(sysroot, "Broken");
	pump(kq, 9, 14000);			/* 1 + 8 */
	ATF_CHECK_EQ(9, reloads);
	ATF_CHECK(!registry_watch_pending());
	pump(kq, 10, 3000);			/* nothing without a change */
	ATF_CHECK_EQ(9, reloads);
	close(kq);
}

/*
 * A real folder change that lands while retries are running resets the
 * budget: the change is what the retries exist for, so it must never
 * inherit a nearly spent budget from an earlier, unrelated bundle.
 */
ATF_TC_WITHOUT_HEAD(change_during_retries_restarts_the_budget);
ATF_TC_BODY(change_during_retries_restarts_the_budget, tc)
{
	int kq = kqueue();

	ATF_REQUIRE(kq >= 0);
	make_roots(true);
	setenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE", "1", 1);
	registry_watch_arm(kq);
	fake_quarantined = 1;
	drop_bundle(sysroot, "Broken");
	pump(kq, 6, 9000);			/* 1 + 5 retries in */
	ATF_CHECK_EQ(6, reloads);
	ATF_CHECK(registry_watch_pending());
	drop_bundle(userroot, "Arriving");	/* a change mid-retry */
	pump(kq, 7, 4000);
	ATF_CHECK_EQ(7, reloads);
	/* a full budget of 8 follows THIS change, not the 3 that were left */
	pump(kq, 15, 14000);
	ATF_CHECK_EQ(15, reloads);
	ATF_CHECK(!registry_watch_pending());
	close(kq);
}

/* Bundle directories are watched too: a write INSIDE an installed bundle
 * (pkg delete removing Bundle.ucl, an upgrade replacing files) reloads,
 * and a bundle dropped in after arming is picked up by the next re-arm. */
ATF_TC_WITHOUT_HEAD(bundle_dir_writes_reload);
ATF_TC_BODY(bundle_dir_writes_reload, tc)
{
	char p[PATH_MAX];
	int kq = kqueue(), fd;

	ATF_REQUIRE(kq >= 0);
	make_roots(true);
	drop_bundle(userroot, "Installed");		/* present before arming */
	setenv("SWITCHBOARD_REGISTRY_WATCH_SETTLE", "1", 1);
	registry_watch_arm(kq);
	ATF_CHECK_EQ(0, reloads);
	/* pkg delete: files vanish inside the bundle dir, root untouched. */
	snprintf(p, sizeof(p), "%s/Installed.cap/Bundle.ucl", userroot);
	fd = open(p, O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	pump(kq, 1, 4000);
	ATF_CHECK_EQ(1, reloads);
	ATF_REQUIRE_EQ(0, unlink(p));
	pump(kq, 2, 4000);
	ATF_CHECK_EQ(2, reloads);
	/* A bundle dropped in later is watched from the reload's re-arm on. */
	drop_bundle(userroot, "Later");
	pump(kq, 3, 4000);
	ATF_CHECK_EQ(3, reloads);
	snprintf(p, sizeof(p), "%s/Later.cap/Unit.ucl", userroot);
	fd = open(p, O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	pump(kq, 4, 4000);
	ATF_CHECK_EQ(4, reloads);
	close(kq);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, bundle_dir_writes_reload);
	ATF_TP_ADD_TC(tp, quarantined_scan_is_retried_boundedly);
	ATF_TP_ADD_TC(tp, failed_rescan_is_retried_until_it_succeeds);
	ATF_TP_ADD_TC(tp, persistently_failing_rescan_gives_up);
	ATF_TP_ADD_TC(tp, exhausted_budget_waits_for_a_change);
	ATF_TP_ADD_TC(tp, change_during_retries_restarts_the_budget);
	ATF_TP_ADD_TC(tp, change_settles_into_one_reload);
	ATF_TP_ADD_TC(tp, burst_coalesces_and_extends_settle);
	ATF_TP_ADD_TC(tp, absent_root_is_watched_for_and_then_watched);
	ATF_TP_ADD_TC(tp, removed_root_drops_watch_and_returns);
	ATF_TP_ADD_TC(tp, shutdown_suppresses_reload);
	ATF_TP_ADD_TC(tp, settle_override_is_validated);
	ATF_TP_ADD_TC(tp, unowned_descriptors_are_not_claimed);
	return (atf_no_error());
}
