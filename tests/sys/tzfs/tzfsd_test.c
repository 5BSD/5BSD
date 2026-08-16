/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Integration tests for tzfsd(8): start the real daemon on a scratch pool and
 * drive it through libtzfsd, covering flavor listing, bare and flavor-clone
 * requests, the anonymous mount, rights attenuation, lifetime, and negatives.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include <trustedzfs.h>
#include "tzfsd.h"
#include "tzfs_test_helpers.h"

static bool
has_ioctl(const cap_ioctl_t *cmds, size_t ncmds, cap_ioctl_t wanted)
{
	size_t i;

	for (i = 0; i < ncmds; i++) {
		if (cmds[i] == wanted)
			return (true);
	}
	return (false);
}

/* list-flavors always offers at least "empty" (built live). */
ATF_TC_WITH_CLEANUP(list_flavors);
ATF_TC_HEAD(list_flavors, tc)
{
	atf_tc_set_md_var(tc, "descr", "list-flavors offers the live 'empty'");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(list_flavors, tc)
{
	struct tzfsd_flavor_info fl[TZFSD_MAX_FLAVORS];
	int chan, n, i;
	bool found_empty = false;

	tzt_require();
	tzt_pool_create(tc);
	tzt_daemon_start();

	chan = tzfsd_connect();
	ATF_REQUIRE(chan != -1);
	ATF_REQUIRE_EQ(0, tzfsd_ping(chan));

	n = tzfsd_list_flavors(chan, fl, TZFSD_MAX_FLAVORS);
	ATF_REQUIRE(n >= 1);
	for (i = 0; i < n; i++)
		if (strcmp(fl[i].name, "empty") == 0)
			found_empty = true;
	ATF_CHECK(found_empty);
	(void)close(chan);
}
ATF_TC_CLEANUP(list_flavors, tc) { tzt_cleanup(); }

/* A bare ephemeral claim: create, mount to a dir, release. */
ATF_TC_WITH_CLEANUP(bare_ephemeral);
ATF_TC_HEAD(bare_ephemeral, tc)
{
	atf_tc_set_md_var(tc, "descr", "bare ephemeral request mounts and releases");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(bare_ephemeral, tc)
{
	struct tzfsd_req req;
	struct tzfsd_grant g;
	int chan, dir;
	struct stat sb;

	tzt_require();
	tzt_pool_create(tc);
	tzt_daemon_start();

	chan = tzfsd_connect();
	ATF_REQUIRE(chan != -1);

	memset(&req, 0, sizeof(req));
	strlcpy(req.name, "t1", sizeof(req.name));
	req.rights = ZH_MOUNT | ZH_PROPS_READ;
	req.lifetime = TZFSD_EPHEMERAL;
	ATF_REQUIRE_EQ(0, tzfsd_request(chan, &req, &g));
	ATF_CHECK(strstr(g.dataset, "/ephemeral/t1") != NULL);

	dir = tzfsd_mount_dir(g.handle_fd, 0);
	ATF_REQUIRE(dir != -1);
	ATF_CHECK_EQ(0, fstat(dir, &sb));
	ATF_CHECK(S_ISDIR(sb.st_mode));
	(void)close(dir);
	(void)close(g.handle_fd);

	ATF_REQUIRE_EQ(0, tzfsd_release(chan, "t1"));
	/* Release is idempotent. */
	ATF_CHECK_EQ(0, tzfsd_release(chan, "t1"));
	(void)close(chan);
}
ATF_TC_CLEANUP(bare_ephemeral, tc) { tzt_cleanup(); }

/* Clone the live 'empty' flavor. */
ATF_TC_WITH_CLEANUP(empty_clone);
ATF_TC_HEAD(empty_clone, tc)
{
	atf_tc_set_md_var(tc, "descr", "flavor=empty clones and mounts");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(empty_clone, tc)
{
	struct tzfsd_req req;
	struct tzfsd_grant g;
	int chan, dir;

	tzt_require();
	tzt_pool_create(tc);
	tzt_daemon_start();

	chan = tzfsd_connect();
	ATF_REQUIRE(chan != -1);

	memset(&req, 0, sizeof(req));
	strlcpy(req.flavor, "empty", sizeof(req.flavor));
	strlcpy(req.name, "c1", sizeof(req.name));
	req.rights = ZH_MOUNT | ZH_PROPS_READ;
	req.lifetime = TZFSD_EPHEMERAL;
	ATF_REQUIRE_EQ(0, tzfsd_request(chan, &req, &g));

	dir = tzfsd_mount_dir(g.handle_fd, 0);
	ATF_CHECK(dir != -1);
	if (dir != -1)
		(void)close(dir);
	(void)close(g.handle_fd);
	ATF_CHECK_EQ(0, tzfsd_release(chan, "c1"));
	(void)close(chan);
}
ATF_TC_CLEANUP(empty_clone, tc) { tzt_cleanup(); }

/* A handle granted without ZH_MOUNT cannot be mounted. */
ATF_TC_WITH_CLEANUP(rights_attenuation);
ATF_TC_HEAD(rights_attenuation, tc)
{
	atf_tc_set_md_var(tc, "descr", "granted handle carries only requested rights");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(rights_attenuation, tc)
{
	struct tzfsd_req req;
	struct tzfsd_grant g;
	struct zfd_info_args info;
	const cap_ioctl_t expected[] = {
		ZFD_INFO, ZFD_DERIVE, ZFD_STAT, ZFD_GET_PROPS,
		ZFD_GET_ONE_PROP, ZFD_LIST_SNAPS, ZFD_HOLDS,
		ZFD_LIST_BOOKMARKS, ZFD_WAIT,
	};
	cap_ioctl_t cmds[16];
	ssize_t ncmds;
	size_t i;
	int chan;

	tzt_require();
	tzt_pool_create(tc);
	tzt_daemon_start();

	chan = tzfsd_connect();
	ATF_REQUIRE(chan != -1);

	memset(&req, 0, sizeof(req));
	strlcpy(req.name, "r1", sizeof(req.name));
	req.rights = ZH_PROPS_READ;		/* deliberately no ZH_MOUNT */
	req.lifetime = TZFSD_EPHEMERAL;
	ATF_REQUIRE_EQ(0, tzfsd_request(chan, &req, &g));
	ATF_REQUIRE_EQ(0, tzfs_info(g.handle_fd, &info));
	ATF_CHECK_EQ(0, info.zi_flags & ZHF_SUBTREE);

	/* The daemon installs the exact implicit read/watch ioctl profile. */
	ncmds = cap_ioctls_get(g.handle_fd, cmds, nitems(cmds));
	ATF_REQUIRE_EQ(nitems(expected), (size_t)ncmds);
	for (i = 0; i < nitems(expected); i++)
		ATF_CHECK(has_ioctl(cmds, (size_t)ncmds, expected[i]));
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    tzfs_snapshot(g.handle_fd, "blocked-by-ioctl-profile") == -1);

	/* Mount must be refused: the handle lacks ZH_MOUNT. */
	ATF_CHECK_EQ(-1, tzfs_mount(g.handle_fd, false));
	ATF_CHECK_EQ(ENOTCAPABLE, errno);
	/* No-subtree was requested and must not be inherited from provisioning. */
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    tzfs_openat(g.handle_fd, "child", 0, 0) == -1);
	(void)close(g.handle_fd);
	(void)tzfsd_release(chan, "r1");
	(void)close(chan);
}
ATF_TC_CLEANUP(rights_attenuation, tc) { tzt_cleanup(); }

/* An unavailable flavor is refused with ENOENT. */
ATF_TC_WITH_CLEANUP(unknown_flavor);
ATF_TC_HEAD(unknown_flavor, tc)
{
	atf_tc_set_md_var(tc, "descr", "request for an unavailable flavor fails ENOENT");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(unknown_flavor, tc)
{
	struct tzfsd_req req;
	struct tzfsd_grant g;
	int chan;

	tzt_require();
	tzt_pool_create(tc);
	tzt_daemon_start();

	chan = tzfsd_connect();
	ATF_REQUIRE(chan != -1);

	memset(&req, 0, sizeof(req));
	/* linux has no baked artifact on the scratch pool -> unavailable. */
	strlcpy(req.flavor, "linux", sizeof(req.flavor));
	strlcpy(req.name, "u1", sizeof(req.name));
	req.rights = ZH_MOUNT;
	req.lifetime = TZFSD_EPHEMERAL;
	ATF_CHECK_EQ(-1, tzfsd_request(chan, &req, &g));
	ATF_CHECK_EQ(ENOENT, errno);
	(void)close(chan);
}
ATF_TC_CLEANUP(unknown_flavor, tc) { tzt_cleanup(); }

/* A persistent claim's dataset survives; a bad name is rejected. */
ATF_TC_WITH_CLEANUP(persistent_and_badname);
ATF_TC_HEAD(persistent_and_badname, tc)
{
	atf_tc_set_md_var(tc, "descr", "persistent claim persists; bad name rejected");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(persistent_and_badname, tc)
{
	struct tzfsd_req req;
	struct tzfsd_grant g;
	int chan;

	tzt_require();
	tzt_pool_create(tc);
	tzt_daemon_start();

	chan = tzfsd_connect();
	ATF_REQUIRE(chan != -1);

	memset(&req, 0, sizeof(req));
	strlcpy(req.name, "p1", sizeof(req.name));
	req.rights = ZH_PROPS_READ;
	req.lifetime = TZFSD_PERSISTENT;
	ATF_REQUIRE_EQ(0, tzfsd_request(chan, &req, &g));
	(void)close(g.handle_fd);
	/* The persistent dataset exists. */
	ATF_CHECK_EQ(0, tzt_systemf("zfs list %s/Capabilities/persistent/p1 "
	    ">/dev/null 2>&1", tzt_pool));

	/* A name with a slash is rejected. */
	memset(&req, 0, sizeof(req));
	strlcpy(req.name, "bad/name", sizeof(req.name));
	req.rights = ZH_PROPS_READ;
	req.lifetime = TZFSD_EPHEMERAL;
	ATF_CHECK_EQ(-1, tzfsd_request(chan, &req, &g));
	ATF_CHECK_EQ(EINVAL, errno);

	/* Unknown handle-scope flags must not cross the protocol boundary. */
	memset(&req, 0, sizeof(req));
	strlcpy(req.name, "badflags", sizeof(req.name));
	req.rights = ZH_PROPS_READ;
	req.flags = ZHF_SUBTREE << 1;
	req.lifetime = TZFSD_EPHEMERAL;
	ATF_CHECK_EQ(-1, tzfsd_request(chan, &req, &g));
	ATF_CHECK_EQ(EINVAL, errno);
	(void)close(chan);
}
ATF_TC_CLEANUP(persistent_and_badname, tc) { tzt_cleanup(); }

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, list_flavors);
	ATF_TP_ADD_TC(tp, bare_ephemeral);
	ATF_TP_ADD_TC(tp, empty_clone);
	ATF_TP_ADD_TC(tp, rights_attenuation);
	ATF_TP_ADD_TC(tp, unknown_flavor);
	ATF_TP_ADD_TC(tp, persistent_and_badname);
	return (atf_no_error());
}
