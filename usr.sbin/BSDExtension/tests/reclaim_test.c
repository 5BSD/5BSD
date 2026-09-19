/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdextension's reconcile client: the module -> bundle owner map and the destroy
 * decisions, with the kldunload(2) seam stubbed.  Pure unit: no plane, no
 * privilege, no module is ever really unloaded.
 */
#include <sys/param.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "bsdextension.h"
#include "bsdextension_reclaim.h"

static char unloaded[8][64];
static unsigned nunloaded;
static const char *busy_module;

static int
stub_unload(const char *module)
{
	if (busy_module != NULL && strcmp(module, busy_module) == 0)
		return (EBUSY);
	if (nunloaded < nitems(unloaded))
		(void)strlcpy(unloaded[nunloaded], module, sizeof(unloaded[0]));
	nunloaded++;
	return (0);
}

static int
map_dir(void)
{
	int fd;

	ATF_REQUIRE_EQ(0, mkdir("owners", 0700));
	fd = open("owners", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	nunloaded = 0;
	busy_module = NULL;
	sysext_test_set_unloader(stub_unload);
	return (fd);
}

static bool
was_unloaded(const char *module)
{
	unsigned i;

	for (i = 0; i < nunloaded && i < nitems(unloaded); i++)
		if (strcmp(unloaded[i], module) == 0)
			return (true);
	return (false);
}

static int
find_entry(const struct sysext_test_entry *e, int n, const char *module,
    const char *bundle)
{
	int i;

	for (i = 0; i < n; i++)
		if (strcmp(e[i].module, module) == 0 &&
		    strcmp(e[i].bundle, bundle) == 0)
			return (i);
	return (-1);
}

ATF_TC_WITHOUT_HEAD(note_round_trips_and_dedups);
ATF_TC_BODY(note_round_trips_and_dedups, tc)
{
	struct sysext_test_entry e[8];
	int fd = map_dir(), n, i;

	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "geom_nop", "app.A", true));
	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "geom_nop", "app.B", false));
	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "if_edsc", "app.A", true));
	/* Re-noting is idempotent. */
	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "geom_nop", "app.A", false));
	n = sysext_test_owners_load(fd, e, nitems(e));
	ATF_REQUIRE_EQ(3, n);
	i = find_entry(e, n, "geom_nop", "app.A");
	ATF_REQUIRE(i >= 0);
	/* A later "already loaded" never demotes a real load. */
	ATF_CHECK(e[i].ours);
	/* "ours" is the module's for this boot: app.B found OUR load. */
	i = find_entry(e, n, "geom_nop", "app.B");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK(e[i].ours);
	ATF_CHECK(find_entry(e, n, "if_edsc", "app.A") >= 0);
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(a_real_load_marks_every_claim_of_the_module);
ATF_TC_BODY(a_real_load_marks_every_claim_of_the_module, tc)
{
	struct sysext_test_entry e[8];
	int fd = map_dir(), n, i;

	/* app.A found it loaded (by something else) before app.B loaded it...
	 * which cannot happen in one boot -- but a re-request after a reclaim
	 * unload can: the module's entries must agree either way. */
	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "if_edsc", "app.A", false));
	n = sysext_test_owners_load(fd, e, nitems(e));
	ATF_REQUIRE_EQ(1, n);
	ATF_CHECK(!e[0].ours);
	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "if_edsc", "app.B", true));
	n = sysext_test_owners_load(fd, e, nitems(e));
	ATF_REQUIRE_EQ(2, n);
	i = find_entry(e, n, "if_edsc", "app.A");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK(e[i].ours);
	/* The last claimant to go unloads it, whichever it is. */
	ATF_REQUIRE_EQ(0, sysext_test_destroy(fd, "app.B"));
	ATF_CHECK(!was_unloaded("if_edsc"));
	ATF_REQUIRE_EQ(0, sysext_test_destroy(fd, "app.A"));
	ATF_CHECK(was_unloaded("if_edsc"));
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(note_rejects_unsafe_names);
ATF_TC_BODY(note_rejects_unsafe_names, tc)
{
	struct sysext_test_entry e[4];
	int fd = map_dir();

	ATF_CHECK_EQ(-1, sysext_owner_note(fd, "../evil", "app.A", true));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(-1, sysext_owner_note(fd, "geom_nop", "a b", true));
	ATF_CHECK_EQ(-1, sysext_owner_note(fd, "", "app.A", true));
	ATF_CHECK_EQ(-1, sysext_owner_note(-1, "geom_nop", "app.A", true));
	ATF_CHECK_EQ(0, sysext_test_owners_load(fd, e, nitems(e)));
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(enumerate_lists_every_attributed_bundle);
ATF_TC_BODY(enumerate_lists_every_attributed_bundle, tc)
{
	char bundles[8][64];
	int fd = map_dir(), n;

	ATF_CHECK_EQ(0, sysext_test_enumerate(fd, bundles, nitems(bundles)));
	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "geom_nop", "app.A", true));
	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "if_edsc", "app.B", true));
	n = sysext_test_enumerate(fd, bundles, nitems(bundles));
	ATF_REQUIRE_EQ(2, n);
	ATF_CHECK((strcmp(bundles[0], "app.A") == 0 &&
	    strcmp(bundles[1], "app.B") == 0) ||
	    (strcmp(bundles[0], "app.B") == 0 &&
	    strcmp(bundles[1], "app.A") == 0));
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(destroy_unloads_only_our_unshared_modules);
ATF_TC_BODY(destroy_unloads_only_our_unshared_modules, tc)
{
	struct sysext_test_entry e[8];
	int fd = map_dir(), n;

	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "geom_nop", "app.A", true));
	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "geom_nop", "app.B", true));
	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "if_edsc", "app.A", true));
	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "mac_none", "app.A", false));
	ATF_REQUIRE_EQ(0, sysext_test_destroy(fd, "app.A"));
	/* geom_nop: still claimed by app.B, not unloaded. */
	ATF_CHECK(!was_unloaded("geom_nop"));
	/* if_edsc: ours and unshared, unloaded. */
	ATF_CHECK(was_unloaded("if_edsc"));
	/* mac_none: found already loaded, never unloaded. */
	ATF_CHECK(!was_unloaded("mac_none"));
	ATF_CHECK_EQ(1, nunloaded);
	/* Every attribution of app.A is gone; app.B's stays. */
	n = sysext_test_owners_load(fd, e, nitems(e));
	ATF_REQUIRE_EQ(1, n);
	ATF_CHECK_STREQ("geom_nop", e[0].module);
	ATF_CHECK_STREQ("app.B", e[0].bundle);
	/* Now app.B goes: geom_nop is unshared, unloaded. */
	ATF_REQUIRE_EQ(0, sysext_test_destroy(fd, "app.B"));
	ATF_CHECK(was_unloaded("geom_nop"));
	ATF_CHECK_EQ(0, sysext_test_owners_load(fd, e, nitems(e)));
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(destroy_keeps_a_busy_module_for_retry);
ATF_TC_BODY(destroy_keeps_a_busy_module_for_retry, tc)
{
	struct sysext_test_entry e[8];
	int fd = map_dir(), n;

	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "geom_nop", "app.A", true));
	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "if_edsc", "app.A", true));
	busy_module = "geom_nop";
	/* The pass reports a failure and keeps the busy entry. */
	ATF_CHECK_EQ(-1, sysext_test_destroy(fd, "app.A"));
	ATF_CHECK(was_unloaded("if_edsc"));
	ATF_CHECK(!was_unloaded("geom_nop"));
	n = sysext_test_owners_load(fd, e, nitems(e));
	ATF_REQUIRE_EQ(1, n);
	ATF_CHECK_STREQ("geom_nop", e[0].module);
	ATF_CHECK(e[0].ours);
	/* Its user goes away: the next pass unloads it. */
	busy_module = NULL;
	ATF_CHECK_EQ(0, sysext_test_destroy(fd, "app.A"));
	ATF_CHECK(was_unloaded("geom_nop"));
	ATF_CHECK_EQ(0, sysext_test_owners_load(fd, e, nitems(e)));
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(destroy_of_unknown_bundle_is_a_noop);
ATF_TC_BODY(destroy_of_unknown_bundle_is_a_noop, tc)
{
	struct sysext_test_entry e[8];
	int fd = map_dir();

	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "geom_nop", "app.A", true));
	ATF_CHECK_EQ(0, sysext_test_destroy(fd, "app.Z"));
	ATF_CHECK_EQ(0, nunloaded);
	ATF_CHECK_EQ(1, sysext_test_owners_load(fd, e, nitems(e)));
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(malformed_lines_are_dropped);
ATF_TC_BODY(malformed_lines_are_dropped, tc)
{
	struct sysext_test_entry e[8];
	int fd = map_dir(), mfd, n;
	const char *junk = "epoch 1.000000\n"
	    "geom_nop app.A 1\n"
	    "no-bundle\n"
	    "../x app.B 1\n"
	    "if_edsc app.B 7\n"
	    "if_edsc bad bundle 1\n"
	    "if_disc app.C 0\n"
	    "truncated app.D 1";	/* no newline: dropped */

	mfd = openat(fd, "modules.meta", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(mfd >= 0);
	ATF_REQUIRE_EQ((ssize_t)strlen(junk), write(mfd, junk, strlen(junk)));
	(void)close(mfd);
	n = sysext_test_owners_load(fd, e, nitems(e));
	ATF_REQUIRE_EQ(2, n);
	ATF_CHECK(find_entry(e, n, "geom_nop", "app.A") >= 0);
	ATF_CHECK(find_entry(e, n, "if_disc", "app.C") >= 0);
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(bundle_of_container);
ATF_TC_BODY(bundle_of_container, tc)
{
	char out[64];

	ATF_REQUIRE_EQ(0, sysext_bundle_of("app.Test/reclaimprobe", out,
	    sizeof(out)));
	ATF_CHECK_STREQ("app.Test", out);
	ATF_CHECK_EQ(-1, sysext_bundle_of("", out, sizeof(out)));
	ATF_CHECK_EQ(-1, sysext_bundle_of("/unit", out, sizeof(out)));
	ATF_CHECK_EQ(-1, sysext_bundle_of("noslash", out, sizeof(out)));
	ATF_CHECK_EQ(-1, sysext_bundle_of("app.Test/unit", out, 4));
}

ATF_TC_WITHOUT_HEAD(epoch_is_recorded_and_kept);
ATF_TC_BODY(epoch_is_recorded_and_kept, tc)
{
	struct sysext_test_entry e[8];
	int fd = map_dir(), mfd;
	char buf[256];
	ssize_t got;

	ATF_REQUIRE_EQ(0, sysext_owner_note(fd, "geom_nop", "app.A", true));
	mfd = openat(fd, "modules.meta", O_RDONLY);
	ATF_REQUIRE(mfd >= 0);
	got = read(mfd, buf, sizeof(buf) - 1);
	ATF_REQUIRE(got > 0);
	buf[got] = '\0';
	(void)close(mfd);
	ATF_CHECK_MSG(strncmp(buf, "epoch ", 6) == 0, "map: %s", buf);
	/* Rewriting the epoch keeps the entries (only a reboot resets them). */
	ATF_REQUIRE_EQ(0, sysext_test_epoch_write(fd, "42.000000"));
	ATF_CHECK_EQ(1, sysext_test_owners_load(fd, e, nitems(e)));
	(void)close(fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, note_round_trips_and_dedups);
	ATF_TP_ADD_TC(tp, a_real_load_marks_every_claim_of_the_module);
	ATF_TP_ADD_TC(tp, note_rejects_unsafe_names);
	ATF_TP_ADD_TC(tp, enumerate_lists_every_attributed_bundle);
	ATF_TP_ADD_TC(tp, destroy_unloads_only_our_unshared_modules);
	ATF_TP_ADD_TC(tp, destroy_keeps_a_busy_module_for_retry);
	ATF_TP_ADD_TC(tp, destroy_of_unknown_bundle_is_a_noop);
	ATF_TP_ADD_TC(tp, malformed_lines_are_dropped);
	ATF_TP_ADD_TC(tp, bundle_of_container);
	ATF_TP_ADD_TC(tp, epoch_is_recorded_and_kept);
	return (atf_no_error());
}
