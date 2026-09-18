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
#include <sys/capsicum.h>

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
	int		   destroy_rc;	/* injected destroy() result (all owners) */
	const char	  *fail_owner;	/* if set, only this owner's destroy fails */
	bool		   prune_destroyed; /* enumerate() omits already-destroyed owners */
	int		   enumerate_rc;/* injected enumerate() result */
};

static bool	was_destroyed(const struct fake *f, const char *owner);

static int
fake_enumerate(void *arg, void (*emit)(void *, const char *), void *emit_arg)
{
	struct fake *f = arg;
	unsigned i;

	if (f->enumerate_rc != 0)
		return (errno = EIO, f->enumerate_rc);
	for (i = 0; i < f->nowned; i++) {
		if (f->prune_destroyed && was_destroyed(f, f->owned[i]))
			continue;	/* a real destroy() removes the resource */
		emit(emit_arg, f->owned[i]);
	}
	return (0);
}

static int
fake_destroy(void *arg, const char *owner)
{
	struct fake *f = arg;

	f->ncalls++;
	if (f->fail_owner != NULL && strcmp(f->fail_owner, owner) == 0)
		return (errno = EBUSY, -1);
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
	char tmpl[] = "capreclaim.XXXXXX";	/* in the ATF work directory */
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

/* A client with its own readiness gate may opt out of the safety floor: an
 * empty live set then reaps every owner (boot) / graced (timer), while the
 * default still reaps nothing. */
ATF_TC_WITHOUT_HEAD(allow_empty_live_reaps_the_last_owner);
ATF_TC_BODY(allow_empty_live_reaps_the_last_owner, tc)
{
	const char *owned[] = { "LastGroup", "OtherGroup" };
	struct fake f = { .owned = owned, .nowned = 2 };
	struct capreclaim_stats st;
	struct capreclaim r = {
		.sources = { { .fd = make_dir(NULL, 0), .strip_cap = false } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
		.stats = &st,
	};

	/* Default: the floor holds. */
	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(0, f.ncalls);
	/* Opted out: a genuinely empty live set orphans everything. */
	r.allow_empty_live = true;
	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));	/* seen once */
	ATF_CHECK_EQ(0, f.ncalls);
	ATF_CHECK_EQ(2, st.norphans);
	ATF_CHECK_EQ(2, capreclaim_run(&r, CAPRECLAIM_TIMER));	/* twice */
	ATF_CHECK(was_destroyed(&f, "LastGroup") && was_destroyed(&f, "OtherGroup"));
	/* An absent source (-1) is still nothing, not an empty set, even opted out. */
	f.ncalls = 0; f.ndestroyed = 0;
	r.sources[0].fd = -1;
	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(0, f.ncalls);
	capreclaim_fini(&r);
}

/*
 * A source that exists but cannot be read (its descriptor lost CAP_READ, or
 * the directory was revoked) is a hard error, never an empty listing: a
 * partial or empty live set would turn every real owner into an orphan.
 */
ATF_TC_WITHOUT_HEAD(unreadable_source_fails_the_pass);
ATF_TC_BODY(unreadable_source_fails_the_pass, tc)
{
	const char *installed[] = { "Live.cap" };
	const char *owned[] = { "Live" };
	struct fake f = { .owned = owned, .nowned = 1 };
	struct capreclaim_stats st;
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 1), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
		.stats = &st,
	};
	cap_rights_t rights;

	/* Lookup only: opening "." for reading under it is refused. */
	cap_rights_init(&rights, CAP_LOOKUP, CAP_FSTAT);
	ATF_REQUIRE_EQ(0, cap_rights_limit(r.sources[0].fd, &rights));
	ATF_CHECK_ERRNO(ENOTCAPABLE, capreclaim_run(&r, CAPRECLAIM_BOOT) == -1);
	ATF_CHECK_EQ(0u, f.ndestroyed);
	ATF_CHECK(!st.floored);
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/* More sources than the array holds is a caller bug, refused up front. */
ATF_TC_WITHOUT_HEAD(too_many_sources_is_einval);
ATF_TC_BODY(too_many_sources_is_einval, tc)
{
	const char *owned[] = { "Gone" };
	struct fake f = { .owned = owned, .nowned = 1 };
	struct capreclaim r = {
		.nsources = 5,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
	};

	ATF_CHECK_ERRNO(EINVAL, capreclaim_run(&r, CAPRECLAIM_BOOT) == -1);
	ATF_CHECK_EQ(0u, f.ndestroyed);
}

/*
 * The floor is reported: a pass that read its sources and found nothing live
 * returns 0 with stats.floored set, so a caller can tell "not yet published"
 * from a settled pass and keep owing its boot pass.
 */
ATF_TC_WITHOUT_HEAD(floored_pass_is_reported);
ATF_TC_BODY(floored_pass_is_reported, tc)
{
	const char *owned[] = { "Gone" };
	struct fake f = { .owned = owned, .nowned = 1 };
	struct capreclaim_stats st;
	struct capreclaim r = {
		.sources = { { .fd = make_dir(NULL, 0), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
		.stats = &st,
	};
	const char *installed[] = { "Live.cap" };

	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK(st.floored);
	ATF_CHECK_EQ(0u, f.ndestroyed);
	/* once something is live the pass completes and is not floored */
	(void)close(r.sources[0].fd);
	r.sources[0].fd = make_dir(installed, 1);
	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK(!st.floored);
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/*
 * Grace is only confirmed across OBSERVED passes: an orphan seen once, then a
 * pass that could not observe (floored or failed), then seen again is NOT
 * destroyed -- the window restarts.
 */
ATF_TC_WITHOUT_HEAD(unobserved_pass_restarts_the_grace);
ATF_TC_BODY(unobserved_pass_restarts_the_grace, tc)
{
	const char *installed[] = { "Live.cap" };
	const char *owned[] = { "Live", "Gone" };
	struct fake f = { .owned = owned, .nowned = 2 };
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 1), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
	};
	int good = r.sources[0].fd, empty = make_dir(NULL, 0);

	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));	/* seen once */
	r.sources[0].fd = empty;				/* floored pass */
	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));
	r.sources[0].fd = good;
	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));	/* seen once again */
	ATF_CHECK(!was_destroyed(&f, "Gone"));
	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_TIMER));	/* now twice */
	ATF_CHECK(was_destroyed(&f, "Gone"));
	/* a failed pass (unreadable source) restarts it too */
	f.ndestroyed = 0;
	{
		const char *owned2[] = { "Live", "Gone2" };
		int bad = make_dir(installed, 1);
		cap_rights_t rights;

		f.owned = owned2;
		ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));
		cap_rights_init(&rights, CAP_LOOKUP);
		ATF_REQUIRE_EQ(0, cap_rights_limit(bad, &rights));
		r.sources[0].fd = bad;
		ATF_CHECK_EQ(-1, capreclaim_run(&r, CAPRECLAIM_TIMER));
		r.sources[0].fd = good;
		ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));
		ATF_CHECK(!was_destroyed(&f, "Gone2"));
		(void)close(bad);
	}
	(void)close(good);
	(void)close(empty);
	capreclaim_fini(&r);
}

/*
 * Adversarial: a VALID owner (under the cap) whose ".cap" marker directory
 * name is within four bytes of the cap must still be recognised as live and
 * NOT reaped.  The read buffer must hold "<owner>.cap", not just "<owner>":
 * if the marker overflows it the entry is dropped from the live set, its
 * container looks orphaned, and the boot pass destroys live data.
 */
ATF_TC_WITHOUT_HEAD(long_owner_marker_is_still_live);
ATF_TC_BODY(long_owner_marker_is_still_live, tc)
{
	char owner[CAPRECLAIM_OWNER_MAX];		/* a valid, near-max owner */
	char marker[CAPRECLAIM_OWNER_MAX + 8];
	const char *installed[1];
	const char *owned[1];
	struct fake f;
	struct capreclaim_stats st;
	struct capreclaim r;

	memset(owner, 'x', CAPRECLAIM_OWNER_MAX - 2);	/* 62 chars: strlen 62 < 64 */
	owner[CAPRECLAIM_OWNER_MAX - 2] = '\0';
	snprintf(marker, sizeof(marker), "%s.cap", owner);	/* 66 chars */
	installed[0] = marker;
	owned[0] = owner;
	memset(&f, 0, sizeof(f));
	f.owned = owned;
	f.nowned = 1;
	memset(&r, 0, sizeof(r));
	r.sources[0].fd = make_dir(installed, 1);
	r.sources[0].strip_cap = true;
	r.nsources = 1;
	r.enumerate = fake_enumerate;
	r.destroy = fake_destroy;
	r.arg = &f;
	r.stats = &st;

	ATF_CHECK_EQ(0, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(1, st.nlive);		/* the marker was read, stripped */
	ATF_CHECK_EQ(0, f.ncalls);		/* the owner is live: NOT reaped */
	ATF_CHECK(!was_destroyed(&f, owner));
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/*
 * Adversarial: the live/owned match is exact, never a prefix.  A live bundle
 * whose name is a prefix of an owned one must not shadow it (leaving a real
 * orphan un-reaped), and must not be mistaken for it.
 */
ATF_TC_WITHOUT_HEAD(live_match_is_exact_not_prefix);
ATF_TC_BODY(live_match_is_exact_not_prefix, tc)
{
	const char *installed[] = { "App.cap" };	/* only "App" is live */
	const char *owned[] = { "App", "App2" };	/* "App2" is an orphan */
	struct fake f;
	struct capreclaim_stats st;
	struct capreclaim r;

	memset(&f, 0, sizeof(f));
	f.owned = owned;
	f.nowned = 2;
	memset(&r, 0, sizeof(r));
	r.sources[0].fd = make_dir(installed, 1);
	r.sources[0].strip_cap = true;
	r.nsources = 1;
	r.enumerate = fake_enumerate;
	r.destroy = fake_destroy;
	r.arg = &f;
	r.stats = &st;

	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(1, f.ncalls);
	ATF_CHECK(was_destroyed(&f, "App2"));		/* the orphan, exactly */
	ATF_CHECK(!was_destroyed(&f, "App"));		/* the live one, kept */
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/*
 * Adversarial: ".cap"-strip edges.  A directory named exactly ".cap" is not a
 * marker (stripping would leave an empty owner), so it is ignored -- it must
 * not create a phantom "" live entry.  A doubled suffix "x.cap.cap" strips one
 * level to "x.cap", which is a legitimate owner name and matches its owner.
 */
ATF_TC_WITHOUT_HEAD(strip_cap_edge_names);
ATF_TC_BODY(strip_cap_edge_names, tc)
{
	const char *installed[] = { ".cap", "x.cap.cap" };
	const char *owned[] = { "x.cap", "orphan" };
	struct fake f;
	struct capreclaim_stats st;
	struct capreclaim r;

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

	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(1, st.nlive);			/* only "x.cap"; ".cap" ignored */
	ATF_CHECK(was_destroyed(&f, "orphan"));		/* the real orphan */
	ATF_CHECK(!was_destroyed(&f, "x.cap"));		/* matched via the strip */
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/*
 * Fault tolerance: one orphan whose destroy fails (a jail with a live process,
 * a module still in use, or the provider dying after reaping some) must not
 * block reaping the others in the same pass, and the stuck one is retried on
 * the next pass -- not lost, not counted.
 */
ATF_TC_WITHOUT_HEAD(partial_destroy_continues_past_a_failure);
ATF_TC_BODY(partial_destroy_continues_past_a_failure, tc)
{
	const char *installed[] = { "Live.cap" };
	const char *owned[] = { "A", "B", "C", "Live" };	/* A,B,C orphaned */
	struct fake f = { .owned = owned, .nowned = 4, .fail_owner = "B",
	    .prune_destroyed = true };
	struct capreclaim_stats st;
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 1), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
		.stats = &st,
	};

	/* First pass: A and C reaped, B fails but does not stop the others. */
	ATF_CHECK_EQ(2, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK_EQ(3, st.norphans);
	ATF_CHECK_EQ(2, st.ndestroyed);
	ATF_CHECK_EQ(1, st.nfailed);
	ATF_CHECK(was_destroyed(&f, "A"));
	ATF_CHECK(was_destroyed(&f, "C"));
	ATF_CHECK(!was_destroyed(&f, "B"));
	/* B unsticks (its process exits): the next pass reaps it. */
	f.fail_owner = NULL;
	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_BOOT));
	ATF_CHECK(was_destroyed(&f, "B"));
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

/*
 * Operability: a pass with status_dirfd set writes an operator-readable record
 * naming the managed (owned) owners and the orphans.
 */
ATF_TC_WITHOUT_HEAD(status_record_lists_the_managed_set);
ATF_TC_BODY(status_record_lists_the_managed_set, tc)
{
	const char *installed[] = { "Live.cap" };
	const char *owned[] = { "Live", "Gone" };
	struct fake f = { .owned = owned, .nowned = 2, .prune_destroyed = true };
	struct capreclaim_stats st;
	struct capreclaim r = {
		.sources = { { .fd = make_dir(installed, 1), .strip_cap = true } },
		.nsources = 1,
		.enumerate = fake_enumerate, .destroy = fake_destroy, .arg = &f,
		.stats = &st,
	};
	char buf[512];
	int dfd, rfd;
	ssize_t n;

	dfd = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dfd >= 0);
	r.status_dirfd = dfd;
	r.status_name = "Test";

	ATF_CHECK_EQ(1, capreclaim_run(&r, CAPRECLAIM_BOOT));	/* Gone reaped */
	rfd = openat(dfd, "Test", O_RDONLY);
	ATF_REQUIRE_MSG(rfd >= 0, "status record not written: %s", strerror(errno));
	n = read(rfd, buf, sizeof(buf) - 1);
	ATF_REQUIRE(n > 0);
	buf[n] = '\0';
	(void)close(rfd);
	ATF_CHECK(strstr(buf, "provider Test") != NULL);
	ATF_CHECK(strstr(buf, "manage Live") != NULL);	/* what it manages */
	ATF_CHECK(strstr(buf, "orphan Gone") != NULL);	/* reaped this pass */
	ATF_CHECK(strstr(buf, "owned=2") != NULL);
	/* No stale ".tmp" left behind. */
	ATF_CHECK_EQ(-1, openat(dfd, "Test.tmp", O_RDONLY));
	(void)close(dfd);
	(void)close(r.sources[0].fd);
	capreclaim_fini(&r);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, unreadable_source_fails_the_pass);
	ATF_TP_ADD_TC(tp, too_many_sources_is_einval);
	ATF_TP_ADD_TC(tp, floored_pass_is_reported);
	ATF_TP_ADD_TC(tp, unobserved_pass_restarts_the_grace);
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
	ATF_TP_ADD_TC(tp, allow_empty_live_reaps_the_last_owner);
	ATF_TP_ADD_TC(tp, boot_destroys_orphans_immediately);
	ATF_TP_ADD_TC(tp, timer_requires_seen_gone_twice);
	ATF_TP_ADD_TC(tp, transient_absence_survives_upgrade);
	ATF_TP_ADD_TC(tp, running_counts_as_live);
	ATF_TP_ADD_TC(tp, empty_live_set_reaps_nothing);
	ATF_TP_ADD_TC(tp, long_owner_marker_is_still_live);
	ATF_TP_ADD_TC(tp, live_match_is_exact_not_prefix);
	ATF_TP_ADD_TC(tp, strip_cap_edge_names);
	ATF_TP_ADD_TC(tp, partial_destroy_continues_past_a_failure);
	ATF_TP_ADD_TC(tp, status_record_lists_the_managed_set);
	return (atf_no_error());
}
