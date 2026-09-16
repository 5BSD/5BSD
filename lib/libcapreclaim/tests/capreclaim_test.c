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
	unsigned	   ndestroyed;
};

static int
fake_enumerate(void *arg, void (*emit)(void *, const char *), void *emit_arg)
{
	struct fake *f = arg;
	unsigned i;

	for (i = 0; i < f->nowned; i++)
		emit(emit_arg, f->owned[i]);
	return (0);
}

static int
fake_destroy(void *arg, const char *owner)
{
	struct fake *f = arg;

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

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, boot_destroys_orphans_immediately);
	ATF_TP_ADD_TC(tp, timer_requires_seen_gone_twice);
	ATF_TP_ADD_TC(tp, transient_absence_survives_upgrade);
	ATF_TP_ADD_TC(tp, running_counts_as_live);
	return (atf_no_error());
}
