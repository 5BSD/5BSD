/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 *
 * libcapreclaim tests: the reconcile picks the right orphans, boot destroys
 * immediately, the timer honours the seen-gone-twice grace (so an upgrade's
 * transient absence is never reaped), and the installed OR running union is
 * the live set.
 */
#include <sys/stat.h>
#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "capreclaim.h"

/* A test provider: a fixed set of owned owners and a record of destroy calls. */
struct fake {
	const char *const *owned;
	unsigned	   nowned;
	char		   destroyed[16][CAPRECLAIM_OWNER_MAX];
	unsigned	   ndestroyed;	/* recorded names (first 16) */
	unsigned	   ncalls;	/* every destroy() call */
	int		   destroy_rc;	/* injected destroy() result */
	int		   enumerate_rc;/* injected enumerate() result */
};

static int
fake_enumerate(void *arg, void (*emit)(void *, const char *), void *emit_arg)
{
	struct fake *f = arg;
	unsigned i;

	if (f->enumerate_rc != 0)
		return (errno = EIO, f->enumerate_rc);
	for (i = 0; i < f->nowned; i++)
		emit(emit_arg, f->owned[i]);
	return (0);
}

static int
fake_destroy(void *arg, const char *owner)
{
	struct fake *f = arg;

	f->ncalls++;
	if (f->destroy_rc != 0)
		return (errno = EBUSY, f->destroy_rc);
	if (f->ndestroyed < 16)
		strlcpy(f->destroyed[f->ndestroyed++], owner,
		    CAPRECLAIM_OWNER_MAX);
	return (0);
}

static bool
was_destroyed(const struct fake *f, const char *owner)
{
	unsigned i;

	for (i = 0; i < f->ndestroyed; i++)
		if (strcmp(f->destroyed[i], owner) == 0)
			return (true);
	return (false);
}

/* Make a temp dir with the given entries (each a subdir), return its fd. */
static int
make_dir(const char *const *entries, unsigned n)
{
	char tmpl[] = "/tmp/capreclaim.XXXXXX";
	char *dir = mkdtemp(tmpl);
	int fd;
	unsigned i;

	ATF_REQUIRE(dir != NULL);
	for (i = 0; i < n; i++) {
		char path[256];

		snprintf(path, sizeof(path), "%s/%s", dir, entries[i]);
		ATF_REQUIRE_EQ(0, mkdir(path, 0700));
	}
	fd = open(dir, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	return (fd);
}

ATF_TC_WITHOUT_HEAD(boot_destroys_orphans_immediately);
ATF_TC_BODY(boot_destroys_orphans_immediately, tc)
{
	const char *installed[] = { "Live.cap" };
	const char *owned[] = { "Live", "Gone" };
	struct fake f = { .owned = owned, .nowned = 2 };
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 1), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
	};

	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK(!was_destroyed(&f, "Live"));	/* installed -> live -> kept */
	ATF_CHECK(was_destroyed(&f, "Gone"));	/* orphan -> reaped at boot */
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

ATF_TC_WITHOUT_HEAD(timer_requires_seen_gone_twice);
ATF_TC_BODY(timer_requires_seen_gone_twice, tc)
{
	const char *installed[] = { "Live.cap" };
	const char *owned[] = { "Live", "Gone" };
	struct fake f = { .owned = owned, .nowned = 2 };
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 1), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
	};

	/* First timer pass: Gone is orphaned but only seen once -> not reaped. */
	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));
	ATF_CHECK(!was_destroyed(&f, "Gone"));
	/* Second pass: still orphaned -> seen twice -> reaped. */
	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_TIMER));
	ATF_CHECK(was_destroyed(&f, "Gone"));
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

ATF_TC_WITHOUT_HEAD(transient_absence_survives_upgrade);
ATF_TC_BODY(transient_absence_survives_upgrade, tc)
{
	/* Owner absent on pass 1 (mid-upgrade), back on pass 2: never reaped. */
	const char *gone[] = { };
	const char *back[] = { "App.cap" };
	const char *owned[] = { "App" };
	struct fake f = { .owned = owned, .nowned = 1 };
	int fd_gone = make_dir(gone, 0), fd_back = make_dir(back, 1);
	struct capreclaim r = {
		.sources = { { .fd = fd_gone, .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
	};

	/* Pass 1: App absent (upgrade in flight) -> orphaned once, not reaped. */
	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));
	/* Pass 2: App back -> not an orphan -> never reaped. */
	r.sources[0].fd = fd_back;
	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));
	ATF_CHECK(!was_destroyed(&f, "App"));
	(void)close(fd_gone);
	(void)close(fd_back);
	capreclaim_fini(&r);
}

ATF_TC_WITHOUT_HEAD(running_counts_as_live);
ATF_TC_BODY(running_counts_as_live, tc)
{
	/* Not installed but running (a removed-but-still-loaded unit): kept. */
	const char *installed[] = { };
	const char *running[] = { "Loaded" };	/* Run/ markers: no .cap suffix */
	const char *owned[] = { "Loaded" };
	struct fake f = { .owned = owned, .nowned = 1 };
	struct capreclaim r = {
		.sources = {
			{ .fd = make_dir(installed, 0), .strip_cap = true },
			{ .fd = make_dir(running, 1), .strip_cap = false },
		},
		.nsources = 2,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
	};

	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK(!was_destroyed(&f, "Loaded"));	/* running -> live */
	(void)close(r.sources[0].fd);
	(void)close(r.sources[1].fd);
	capreclaim_fini(&r);
}

/*
 * Safety floor: a completely empty live set is treated as "not published",
 * never as "everything is gone".  Even at boot, and even with owned resources,
 * an empty live set must destroy nothing -- otherwise a provider that reconciles
 * before switchboard has published, or against a directory being rewritten,
 * would wipe every owner's data.
 */
ATF_TC_WITHOUT_HEAD(empty_live_set_reaps_nothing);
ATF_TC_BODY(empty_live_set_reaps_nothing, tc)
{
	const char *installed[] = { };
	const char *owned[] = { "A", "B", "C" };
	struct fake f = { .owned = owned, .nowned = 3 };
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 0), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
	};

	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(0, f.ndestroyed);
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/* ---- Negative and edge cases ------------------------------------------- */

ATF_TC_WITHOUT_HEAD(missing_callbacks_are_einval);
ATF_TC_BODY(missing_callbacks_are_einval, tc)
{
	struct fake f = { 0 };
	struct capreclaim r = { .nsources = 0, .arg = &f };

	ATF_CHECK_ERRNO(EINVAL, capreclaim_run(NULL, CAPRECLAIM_BOOT) == -1);
	r.destroy = fake_destroy;		/* enumerate missing */
	ATF_CHECK_ERRNO(EINVAL, capreclaim_run(&r, CAPRECLAIM_BOOT) == -1);
	r.enumerate = fake_enumerate;
	r.destroy = NULL;			/* destroy missing */
	ATF_CHECK_ERRNO(EINVAL, capreclaim_run(&r, CAPRECLAIM_BOOT) == -1);
	ATF_CHECK_EQ(0, f.ncalls);
	capreclaim_fini(&r);
}

/* A source descriptor that is not a directory is a hard error: nothing reaped. */
ATF_TC_WITHOUT_HEAD(non_directory_source_is_a_hard_error);
ATF_TC_BODY(non_directory_source_is_a_hard_error, tc)
{
	const char *owned[] = { "Gone" };
	struct fake f = { .owned = owned, .nowned = 1 };
	char tmpl[] = "/tmp/capreclaim.file.XXXXXX";
	int fd = mkstemp(tmpl);
	struct capreclaim r = {
		.sources = { { .fd = fd, .strip_cap = true } }, .nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
	};

	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(-1, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK(errno != 0);
	ATF_CHECK_EQ(0, f.ncalls);		/* never reached destroy */
	(void)close(fd);
	(void)unlink(tmpl);
	capreclaim_fini(&r);
}

/* Every source absent (-1) is an empty live set: the safety floor holds. */
ATF_TC_WITHOUT_HEAD(all_sources_absent_reaps_nothing);
ATF_TC_BODY(all_sources_absent_reaps_nothing, tc)
{
	const char *owned[] = { "Gone", "AlsoGone" };
	struct fake f = { .owned = owned, .nowned = 2 };
	struct capreclaim_stats st;
	struct capreclaim r = {
		.sources = { { .fd = -1, .strip_cap = true },
			     { .fd = -1, .strip_cap = false } }, .nsources = 2,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
		.stats = &st,
	};

	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(0, f.ncalls);
	ATF_CHECK_EQ(0, st.nlive);
	ATF_CHECK_EQ(0, st.norphans);	/* not even computed */
	capreclaim_fini(&r);
}

/* strip_cap: only "<owner>.cap" entries are installed markers; ".cap" alone,
 * names without the suffix, and files are ignored. */
ATF_TC_WITHOUT_HEAD(strip_cap_accepts_only_marker_dirs);
ATF_TC_BODY(strip_cap_accepts_only_marker_dirs, tc)
{
	const char *installed[] = { "Live.cap", "README", "Bare", ".cap" };
	const char *owned[] = { "Live", "README", "Bare", "" };
	struct fake f = { .owned = owned, .nowned = 4 };
	struct capreclaim_stats st;
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 4), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
		.stats = &st,
	};

	ATF_CHECK_EQ(2, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(1, st.nlive);		/* only Live */
	ATF_CHECK_EQ(3, st.nowned);		/* "" is dropped as malformed */
	ATF_CHECK(!was_destroyed(&f, "Live"));
	ATF_CHECK(was_destroyed(&f, "README"));
	ATF_CHECK(was_destroyed(&f, "Bare"));
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/* Over-long names never enter a set: an over-long installed marker is not
 * live, and an over-long owned name is not an orphan (under-report, never
 * over-reap). */
ATF_TC_WITHOUT_HEAD(overlong_names_are_ignored);
ATF_TC_BODY(overlong_names_are_ignored, tc)
{
	char longname[CAPRECLAIM_OWNER_MAX + 8];
	char longcap[CAPRECLAIM_OWNER_MAX + 12];
	const char *installed[2];
	const char *owned[2];
	struct fake f;
	struct capreclaim_stats st;
	struct capreclaim r;

	memset(longname, 'x', sizeof(longname) - 1);
	longname[sizeof(longname) - 1] = '\0';
	snprintf(longcap, sizeof(longcap), "%s.cap", longname);
	installed[0] = "Live.cap";
	installed[1] = longcap;
	owned[0] = "Live";
	owned[1] = longname;
	memset(&f, 0, sizeof(f));
	f.owned = owned;
	f.nowned = 2;
	memset(&r, 0, sizeof(r));
	r.sources[0].fd = make_dir(installed, 2);
	r.sources[0].strip_cap = true;
	r.nsources = 1;
	r.enumerate = fake_enumerate;
	r.destroy = fake_destroy;
	r.arg = &f;
	r.stats = &st;

	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(1, st.nlive);
	ATF_CHECK_EQ(1, st.nowned);
	ATF_CHECK_EQ(0, f.ncalls);
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/* A failing enumerate is a hard error and destroys nothing. */
ATF_TC_WITHOUT_HEAD(enumerate_failure_destroys_nothing);
ATF_TC_BODY(enumerate_failure_destroys_nothing, tc)
{
	const char *installed[] = { "Live.cap" };
	const char *owned[] = { "Live", "Gone" };
	struct fake f = { .owned = owned, .nowned = 2, .enumerate_rc = -1 };
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 1), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
	};

	ATF_CHECK_ERRNO(EIO, capreclaim_run(&r, CAPRECLAIM_BOOT) == -1);
	ATF_CHECK_EQ(0, f.ncalls);
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/* A failing destroy is not counted, is reported in stats, and is retried on
 * the next pass once it succeeds. */
ATF_TC_WITHOUT_HEAD(destroy_failure_is_not_counted_and_retried);
ATF_TC_BODY(destroy_failure_is_not_counted_and_retried, tc)
{
	const char *installed[] = { "Live.cap" };
	const char *owned[] = { "Live", "Gone" };
	struct fake f = { .owned = owned, .nowned = 2, .destroy_rc = -1 };
	struct capreclaim_stats st;
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 1), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
		.stats = &st,
	};

	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(1, f.ncalls);
	ATF_CHECK_EQ(1, st.norphans);
	ATF_CHECK_EQ(0, st.ndestroyed);
	ATF_CHECK_EQ(1, st.nfailed);
	f.destroy_rc = 0;
	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK(was_destroyed(&f, "Gone"));
	ATF_CHECK_EQ(1, st.ndestroyed);
	ATF_CHECK_EQ(0, st.nfailed);
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/* The timer grace resets when an orphan reappears between passes: it must be
 * seen gone on two CONSECUTIVE passes. */
ATF_TC_WITHOUT_HEAD(grace_resets_when_owner_reappears);
ATF_TC_BODY(grace_resets_when_owner_reappears, tc)
{
	const char *installed[] = { "Live.cap" };
	const char *owned[] = { "Live", "Flap" };
	struct fake f = { .owned = owned, .nowned = 2 };
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 1), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
	};
	char path[256];

	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));	/* seen once */
	/* Flap is (re)installed before the next pass. */
	ATF_REQUIRE(mkdirat(r.sources[0].fd, "Flap.cap", 0700) == 0);
	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));	/* live again */
	ATF_REQUIRE(unlinkat(r.sources[0].fd, "Flap.cap", AT_REMOVEDIR) == 0);
	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));	/* seen once */
	ATF_CHECK_EQ(0, f.ncalls);
	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_TIMER));	/* twice */
	ATF_CHECK(was_destroyed(&f, "Flap"));
	(void)snprintf(path, sizeof(path), "%s", "");
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/* A boot pass never seeds the timer grace: a boot-pass orphan whose destroy
 * failed still needs two timer sightings. */
ATF_TC_WITHOUT_HEAD(boot_pass_does_not_seed_grace);
ATF_TC_BODY(boot_pass_does_not_seed_grace, tc)
{
	const char *installed[] = { "Live.cap" };
	const char *owned[] = { "Live", "Gone" };
	struct fake f = { .owned = owned, .nowned = 2, .destroy_rc = -1 };
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 1), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
	};

	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_BOOT));	/* fails */
	f.destroy_rc = 0;
	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));	/* seen once */
	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_TIMER));	/* twice */
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/* The same bundle present in several sources is one live entry. */
ATF_TC_WITHOUT_HEAD(live_set_deduplicates_across_sources);
ATF_TC_BODY(live_set_deduplicates_across_sources, tc)
{
	const char *installed[] = { "Both.cap", "OnlyInstalled.cap" };
	const char *running[] = { "Both", "OnlyRunning" };
	const char *owned[] = { "Both", "OnlyInstalled", "OnlyRunning", "Gone" };
	struct fake f = { .owned = owned, .nowned = 4 };
	struct capreclaim_stats st;
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 2), .strip_cap = true },
			     { .fd = make_dir(running, 2), .strip_cap = false } },
		.nsources = 2,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
		.stats = &st,
	};

	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(3, st.nlive);
	ATF_CHECK(was_destroyed(&f, "Gone"));
	ATF_CHECK(!was_destroyed(&f, "OnlyRunning"));
	(void)close(r.sources[0].fd);
	(void)close(r.sources[1].fd);
	capreclaim_fini(&r);
}

/* Duplicate owned names from the provider are one owner (one destroy). */
ATF_TC_WITHOUT_HEAD(duplicate_owned_names_destroy_once);
ATF_TC_BODY(duplicate_owned_names_destroy_once, tc)
{
	const char *installed[] = { "Live.cap" };
	const char *owned[] = { "Gone", "Gone", "Gone" };
	struct fake f = { .owned = owned, .nowned = 3 };
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 1), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
	};

	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(1, f.ncalls);
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/* Scale: hundreds of owners and markers reconcile exactly. */
ATF_TC_WITHOUT_HEAD(many_owners_reconcile_exactly);
ATF_TC_BODY(many_owners_reconcile_exactly, tc)
{
	enum { N = 300, INSTALLED = 137 };
	static char names[N][CAPRECLAIM_OWNER_MAX];
	static char caps[INSTALLED][CAPRECLAIM_OWNER_MAX];
	static const char *owned[N];
	static const char *installed[INSTALLED];
	struct fake f = { .owned = owned, .nowned = N };
	struct capreclaim_stats st;
	struct capreclaim r;
	unsigned i;

	for (i = 0; i < N; i++) {
		snprintf(names[i], sizeof(names[i]), "bundle-%03u", i);
		owned[i] = names[i];
	}
	for (i = 0; i < INSTALLED; i++) {
		snprintf(caps[i], sizeof(caps[i]), "bundle-%03u.cap", i);
		installed[i] = caps[i];
	}
	memset(&r, 0, sizeof(r));
	r.sources[0].fd = make_dir(installed, INSTALLED);
	r.sources[0].strip_cap = true;
	r.nsources = 1;
	r.enumerate = fake_enumerate;
	r.destroy = fake_destroy;
	r.arg = &f;
	r.stats = &st;
	ATF_CHECK_EQ(N - INSTALLED, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(INSTALLED, st.nlive);
	ATF_CHECK_EQ(N, st.nowned);
	ATF_CHECK_EQ(N - INSTALLED, st.norphans);
	ATF_CHECK_EQ(N - INSTALLED, f.ncalls);
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/* fini is NULL-safe and idempotent; the reconcile is reusable after it. */
ATF_TC_WITHOUT_HEAD(fini_is_null_safe_and_idempotent);
ATF_TC_BODY(fini_is_null_safe_and_idempotent, tc)
{
	const char *installed[] = { "Live.cap" };
	const char *owned[] = { "Gone" };
	struct fake f = { .owned = owned, .nowned = 1 };
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 1), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
	};

	capreclaim_fini(NULL);
	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));
	capreclaim_fini(&r);
	capreclaim_fini(&r);
	ATF_CHECK_EQ(0, r.nprev);
	/* Grace state was released: the next timer pass starts over. */
	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));
	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_TIMER));
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, missing_callbacks_are_einval);
	ATF_TP_ADD_TC(tp, non_directory_source_is_a_hard_error);
	ATF_TP_ADD_TC(tp, all_sources_absent_reaps_nothing);
	ATF_TP_ADD_TC(tp, strip_cap_accepts_only_marker_dirs);
	ATF_TP_ADD_TC(tp, overlong_names_are_ignored);
	ATF_TP_ADD_TC(tp, enumerate_failure_destroys_nothing);
	ATF_TP_ADD_TC(tp, destroy_failure_is_not_counted_and_retried);
	ATF_TP_ADD_TC(tp, grace_resets_when_owner_reappears);
	ATF_TP_ADD_TC(tp, boot_pass_does_not_seed_grace);
	ATF_TP_ADD_TC(tp, live_set_deduplicates_across_sources);
	ATF_TP_ADD_TC(tp, duplicate_owned_names_destroy_once);
	ATF_TP_ADD_TC(tp, many_owners_reconcile_exactly);
	ATF_TP_ADD_TC(tp, fini_is_null_safe_and_idempotent);
	ATF_TP_ADD_TC(tp, boot_destroys_orphans_immediately);
	ATF_TP_ADD_TC(tp, timer_requires_seen_gone_twice);
	ATF_TP_ADD_TC(tp, transient_absence_survives_upgrade);
	ATF_TP_ADD_TC(tp, running_counts_as_live);
	ATF_TP_ADD_TC(tp, empty_live_set_reaps_nothing);
	return (atf_no_error());
}
