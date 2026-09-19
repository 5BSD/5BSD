/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * warden's jail owner map (jail name -> bundle): the pure file logic behind
 * the reconcile, driven on a temp directory.  Jail removal itself needs a
 * kernel and root; the VM proof covers it.
 */
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <capreclaim.h>

#include "warden_reclaim.h"

static int
map_dir(void)
{
	int fd;

	ATF_REQUIRE_EQ(0, mkdir("owners", 0700));
	fd = open("owners", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	return (fd);
}

ATF_TC_WITHOUT_HEAD(note_is_idempotent_and_renotes_replace);
ATF_TC_BODY(note_is_idempotent_and_renotes_replace, tc)
{
	char jails[8][WARDEN_RECLAIM_JAIL_MAX], bundles[8][64];
	int fd = map_dir();

	ATF_CHECK_EQ(0, warden_test_owners_load(fd, jails, bundles, 8));
	ATF_REQUIRE_EQ(0, warden_owner_note(fd, "wj_aaaa", "App"));
	ATF_REQUIRE_EQ(0, warden_owner_note(fd, "wj_aaaa", "App"));	/* again */
	ATF_REQUIRE_EQ(0, warden_owner_note(fd, "wj_bbbb", "Other"));
	ATF_CHECK_EQ(2, warden_test_owners_load(fd, jails, bundles, 8));
	ATF_CHECK_STREQ("wj_aaaa", jails[0]); ATF_CHECK_STREQ("App", bundles[0]);
	ATF_CHECK_STREQ("wj_bbbb", jails[1]); ATF_CHECK_STREQ("Other", bundles[1]);
	/* a label reused by another bundle re-attributes the jail */
	ATF_REQUIRE_EQ(0, warden_owner_note(fd, "wj_aaaa", "Newer"));
	ATF_CHECK_EQ(2, warden_test_owners_load(fd, jails, bundles, 8));
	ATF_CHECK_STREQ("Newer", bundles[0]);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(note_rejects_unsafe_names);
ATF_TC_BODY(note_rejects_unsafe_names, tc)
{
	int fd = map_dir();

	ATF_CHECK_ERRNO(EINVAL, warden_owner_note(fd, "", "App") == -1);
	ATF_CHECK_ERRNO(EINVAL, warden_owner_note(fd, "wj_a", "") == -1);
	ATF_CHECK_ERRNO(EINVAL, warden_owner_note(fd, "wj a", "App") == -1);
	ATF_CHECK_ERRNO(EINVAL, warden_owner_note(fd, "wj_a", "A pp") == -1);
	ATF_CHECK_ERRNO(EINVAL, warden_owner_note(fd, "wj_a\n", "App") == -1);
	ATF_CHECK_ERRNO(EINVAL, warden_owner_note(fd, "wj_a", "../x") == -1);
	ATF_CHECK_ERRNO(EINVAL, warden_owner_note(-1, "wj_a", "App") == -1);
	close(fd);
}

/* Malformed lines in the map are dropped, never trusted. */
ATF_TC_WITHOUT_HEAD(load_drops_malformed_lines);
ATF_TC_BODY(load_drops_malformed_lines, tc)
{
	char jails[8][WARDEN_RECLAIM_JAIL_MAX], bundles[8][64];
	int fd = map_dir(), f;

	f = openat(fd, "jails.meta", O_WRONLY | O_CREAT, 0600);
	ATF_REQUIRE(f >= 0);
	ATF_REQUIRE(write(f, "wj_good App\nnospace\nwj_bad ../x\n wj_lead App\n"
	    "wj_ok2 B\nwj_trunc C", 68) > 0);
	close(f);
	ATF_CHECK_EQ(2, warden_test_owners_load(fd, jails, bundles, 8));
	ATF_CHECK_STREQ("wj_good", jails[0]);
	ATF_CHECK_STREQ("wj_ok2", jails[1]);
	close(fd);
}

/* destroy(bundle) removes exactly that bundle's entries and keeps the rest. */
ATF_TC_WITHOUT_HEAD(destroy_removes_only_the_bundles_entries);
ATF_TC_BODY(destroy_removes_only_the_bundles_entries, tc)
{
	char jails[8][WARDEN_RECLAIM_JAIL_MAX], bundles[8][64];
	int fd = map_dir();

	ATF_REQUIRE_EQ(0, warden_owner_note(fd, "wj_a1", "A"));
	ATF_REQUIRE_EQ(0, warden_owner_note(fd, "wj_a2", "A"));
	ATF_REQUIRE_EQ(0, warden_owner_note(fd, "wj_b1", "B"));
	ATF_CHECK_EQ(0, warden_test_destroy_entries(fd, "A"));
	ATF_CHECK_EQ(1, warden_test_owners_load(fd, jails, bundles, 8));
	ATF_CHECK_STREQ("wj_b1", jails[0]);
	ATF_CHECK_EQ(0, warden_test_destroy_entries(fd, "Nobody"));	/* no-op */
	ATF_CHECK_EQ(1, warden_test_owners_load(fd, jails, bundles, 8));
	close(fd);
}

ATF_TC_WITHOUT_HEAD(bundle_of_container);
ATF_TC_BODY(bundle_of_container, tc)
{
	char b[64];

	ATF_CHECK_EQ(0, warden_bundle_of("App/worker", b, sizeof(b)));
	ATF_CHECK_STREQ("App", b);
	ATF_CHECK_EQ(-1, warden_bundle_of("", b, sizeof(b)));
	ATF_CHECK_EQ(-1, warden_bundle_of("noslash", b, sizeof(b)));
	ATF_CHECK_EQ(-1, warden_bundle_of("/unit", b, sizeof(b)));
	ATF_CHECK_EQ(-1, warden_bundle_of("App/worker", b, 3));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, note_is_idempotent_and_renotes_replace);
	ATF_TP_ADD_TC(tp, note_rejects_unsafe_names);
	ATF_TP_ADD_TC(tp, load_drops_malformed_lines);
	ATF_TP_ADD_TC(tp, destroy_removes_only_the_bundles_entries);
	ATF_TP_ADD_TC(tp, bundle_of_container);
	return (atf_no_error());
}
