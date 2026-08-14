/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TrustedZFS guid-pinning tests: handles follow renames, observe destroys as
 * sticky ENXIO, revive across export/import, and report invalidation via
 * kqueue.
 */

#include <sys/event.h>

#include "zfshandle_test_helpers.h"

static void
zht_setup(const atf_tc_t *tc, char *ds, size_t dslen)
{
	zht_require(tc);
	zht_pool_create(tc);
	snprintf(ds, dslen, "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", ds));
}

ATF_TC_WITH_CLEANUP(survives_rename);
ATF_TC_HEAD(survives_rename, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Handle follows the dataset across rename");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(survives_rename, tc)
{
	struct zfd_info_args info;
	char ds[256], renamed[256];
	int fd;

	zht_setup(tc, ds, sizeof(ds));
	fd = zht_open_req(ds, ZH_SNAPSHOT, 0);

	snprintf(renamed, sizeof(renamed), "%s/moved", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs rename %s %s", ds, renamed));

	ATF_REQUIRE_EQ(0, zfd_info(fd, &info));
	ATF_REQUIRE_EQ(1, info.zi_valid);
	ATF_REQUIRE_STREQ(renamed, info.zi_name);

	/* The snapshot lands on the renamed dataset. */
	ATF_REQUIRE_EQ(0, zfd_snapshot(fd, "after"));
	ATF_REQUIRE_EQ(0, zht_systemf(
	    "zfs list -H -t snapshot -o name %s@after >/dev/null", renamed));

	close(fd);
}
ATF_TC_CLEANUP(survives_rename, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(destroy_invalidates);
ATF_TC_HEAD(destroy_invalidates, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Destroy + same-name recreate leaves the handle dead (ENXIO)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(destroy_invalidates, tc)
{
	struct zfd_info_args info;
	struct zfd_stat_args st;
	char ds[256];
	int fd;

	zht_setup(tc, ds, sizeof(ds));
	fd = zht_open_req(ds, ZH_SNAPSHOT, 0);

	ATF_REQUIRE_EQ(0, zht_systemf("zfs destroy %s", ds));
	/* An impostor under the same name must not be reachable. */
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", ds));

	ATF_REQUIRE_ERRNO(ENXIO, zfd_stat(fd, &st) == -1);
	ATF_REQUIRE_ERRNO(ENXIO, zfd_snapshot(fd, "nope") == -1);
	ATF_REQUIRE_EQ(0, zfd_info(fd, &info));
	ATF_REQUIRE_EQ(0, info.zi_valid);

	/* Sticky: even though the name resolves, the handle stays dead. */
	ATF_REQUIRE_ERRNO(ENXIO, zfd_stat(fd, &st) == -1);

	close(fd);
}
ATF_TC_CLEANUP(destroy_invalidates, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(kqueue_invalidate);
ATF_TC_HEAD(kqueue_invalidate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Invalidation is observable via EVFILT_READ on the handle");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(kqueue_invalidate, tc)
{
	struct zfd_stat_args st;
	struct kevent kev;
	struct timespec ts = { 0, 0 };
	char ds[256];
	int fd, kq, n;

	zht_setup(tc, ds, sizeof(ds));
	fd = zht_open_req(ds, 0, 0);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));

	/* Valid handle: not readable. */
	n = kevent(kq, NULL, 0, &kev, 1, &ts);
	ATF_REQUIRE_EQ(0, n);

	ATF_REQUIRE_EQ(0, zht_systemf("zfs destroy %s", ds));
	/* Detection is lazy: poke the handle once. */
	ATF_REQUIRE_ERRNO(ENXIO, zfd_stat(fd, &st) == -1);

	n = kevent(kq, NULL, 0, &kev, 1, &ts);
	ATF_REQUIRE_EQ(1, n);
	ATF_REQUIRE_EQ((uintptr_t)fd, kev.ident);

	close(kq);
	close(fd);
}
ATF_TC_CLEANUP(kqueue_invalidate, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(export_import_revives);
ATF_TC_HEAD(export_import_revives, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Pool export is transient ENXIO; import revives the handle");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(export_import_revives, tc)
{
	struct zfd_stat_args st;
	char ds[256], cwd[1024];
	int fd;

	zht_setup(tc, ds, sizeof(ds));
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	fd = zht_open_req(ds, ZH_SNAPSHOT, 0);

	ATF_REQUIRE_EQ(0, zht_systemf("zpool export %s", zht_pool));
	ATF_REQUIRE_ERRNO(ENXIO, zfd_stat(fd, &st) == -1);

	ATF_REQUIRE_EQ(0, zht_systemf("zpool import -d %s %s", cwd,
	    zht_pool));
	ATF_REQUIRE_EQ(0, zfd_stat(fd, &st));
	ATF_REQUIRE_EQ(0, zfd_snapshot(fd, "back"));

	close(fd);
}
ATF_TC_CLEANUP(export_import_revives, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, survives_rename);
	ATF_TP_ADD_TC(tp, destroy_invalidates);
	ATF_TP_ADD_TC(tp, kqueue_invalidate);
	ATF_TP_ADD_TC(tp, export_import_revives);
	return (atf_no_error());
}
