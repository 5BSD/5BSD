/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TrustedZFS extended-verb tests: enumeration (children/snaps/holds/
 * bookmarks), single-property get, inherit, promote, bookmarks, wait,
 * and send-once semantics.  Driven through libtrustedzfs.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>

#include <fcntl.h>
#include <trustedzfs.h>

#include "zfshandle_test_helpers.h"

#define	PARENT_RIGHTS	(ZH_CREATE | ZH_DESTROY | ZH_SNAPSHOT | \
	ZH_SNAP_DESTROY | ZH_CLONE_SRC | ZH_SEND | ZH_HOLD | \
	ZH_RELEASE | ZH_ROLLBACK | ZH_PROPS_WRITE | ZH_PROMOTE | ZH_BOOKMARK)

static void
zht_setup(const atf_tc_t *tc, char *ds, size_t dslen)
{
	zht_require(tc);
	zht_pool_create(tc);
	snprintf(ds, dslen, "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", ds));
}

/* Count entries in a packed name-set nvlist by grepping the raw buffer. */
static int
buf_has(const void *buf, size_t len, const char *needle)
{
	size_t nl = strlen(needle);
	const char *p = buf;
	size_t i;

	if (len < nl)
		return (0);
	for (i = 0; i + nl <= len; i++)
		if (memcmp(p + i, needle, nl) == 0)
			return (1);
	return (0);
}

ATF_TC_WITH_CLEANUP(list_children);
ATF_TC_HEAD(list_children, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "list_children enumerates a subtree; needs the subtree flag");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(list_children, tc)
{
	char ds[256], want[256];
	void *buf;
	size_t len;
	int zfd;

	zht_setup(tc, ds, sizeof(ds));
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s/a", ds));
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s/b", ds));

	/* Non-subtree handle cannot enumerate. */
	zfd = tzfs_open(ds, 0, 0);
	ATF_REQUIRE(zfd >= 0);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    tzfs_list_children(zfd, &buf, &len) == -1);
	close(zfd);

	zfd = tzfs_open(ds, 0, ZHF_SUBTREE);
	ATF_REQUIRE(zfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_list_children(zfd, &buf, &len));
	snprintf(want, sizeof(want), "%s/a", ds);
	ATF_REQUIRE(buf_has(buf, len, want));
	snprintf(want, sizeof(want), "%s/b", ds);
	ATF_REQUIRE(buf_has(buf, len, want));
	free(buf);
	close(zfd);
}
ATF_TC_CLEANUP(list_children, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(list_snapshots);
ATF_TC_HEAD(list_snapshots, tc)
{
	atf_tc_set_md_var(tc, "descr", "list_snapshots enumerates snapshots");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(list_snapshots, tc)
{
	char ds[256], want[256];
	void *buf;
	size_t len;
	int zfd;

	zht_setup(tc, ds, sizeof(ds));
	zfd = tzfs_open(ds, ZH_SNAPSHOT, 0);
	ATF_REQUIRE(zfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(zfd, "s1"));
	ATF_REQUIRE_EQ(0, tzfs_snapshot(zfd, "s2"));

	ATF_REQUIRE_EQ(0, tzfs_list_snapshots(zfd, &buf, &len));
	snprintf(want, sizeof(want), "%s@s1", ds);
	ATF_REQUIRE(buf_has(buf, len, want));
	snprintf(want, sizeof(want), "%s@s2", ds);
	ATF_REQUIRE(buf_has(buf, len, want));
	free(buf);
	close(zfd);
}
ATF_TC_CLEANUP(list_snapshots, tc)
{
	zht_pool_cleanup(tc);
}

/* Match Capsule's numeric property query with implicit read rights only. */
static void
require_readonly(int zfd, uint64_t expected)
{
	uint64_t value;
	int is_string;

	value = UINT64_MAX;
	is_string = -1;
	ATF_REQUIRE_EQ(0, tzfs_get_one_prop(zfd, "readonly", NULL, 0,
	    &value, &is_string, NULL));
	ATF_REQUIRE_EQ(0, is_string);
	ATF_REQUIRE_EQ(expected, value);
}

ATF_TC_WITH_CLEANUP(readonly_inheritance);
ATF_TC_HEAD(readonly_inheritance, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "implicit property reads track readonly inheritance without write rights");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(readonly_inheritance, tc)
{
	char ds[256], child[512];
	int parent_writer, child_writer, reader;

	if (strcmp(atf_tc_get_config_var_wd(tc, "disposable_vm", "no"),
	    "yes") != 0)
		atf_tc_skip("requires disposable_vm=yes for pool mutation");
	zht_setup(tc, ds, sizeof(ds));
	snprintf(child, sizeof(child), "%s/child", ds);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", child));
	parent_writer = tzfs_open(ds, ZH_PROPS_WRITE, 0);
	ATF_REQUIRE(parent_writer >= 0);
	child_writer = tzfs_open(child, ZH_PROPS_WRITE, 0);
	ATF_REQUIRE(child_writer >= 0);
	reader = tzfs_open(child, 0, ZHF_SUBTREE);
	ATF_REQUIRE(reader >= 0);

	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(parent_writer, "readonly", 0));
	require_readonly(reader, 0);
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(parent_writer, "readonly", 1));
	require_readonly(reader, 1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    tzfs_set_prop_uint64(reader, "readonly", 0) == -1);
	require_readonly(reader, 1);

	/* A local override and inheritance must affect this same open handle. */
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(child_writer, "readonly", 0));
	require_readonly(reader, 0);
	ATF_REQUIRE_EQ(0, tzfs_inherit(child_writer, "readonly", false));
	require_readonly(reader, 1);
	ATF_REQUIRE_EQ(0, tzfs_set_prop_uint64(parent_writer, "readonly", 0));
	require_readonly(reader, 0);

	close(reader);
	close(child_writer);
	close(parent_writer);
}
ATF_TC_CLEANUP(readonly_inheritance, tc)
{
	if (strcmp(atf_tc_get_config_var_wd(tc, "disposable_vm", "no"),
	    "yes") == 0)
		zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(property_triad);
ATF_TC_HEAD(property_triad, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "get one property, set it, inherit (clear) it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(property_triad, tc)
{
	char ds[256], val[256];
	uint64_t iv;
	int zfd, is_str;
	uint32_t src;

	zht_setup(tc, ds, sizeof(ds));
	zfd = tzfs_open(ds, ZH_PROPS_WRITE, 0);
	ATF_REQUIRE(zfd >= 0);

	/* A numeric read-only property (used) comes back as an int. */
	ATF_REQUIRE_EQ(0, tzfs_get_one_prop(zfd, "compression", val,
	    sizeof(val), &iv, &is_str, &src));

	/* Set a user property, read it back, then inherit-clear it. */
	ATF_REQUIRE_EQ(0, tzfs_set_prop_string(zfd, "zht:k", "hello"));
	ATF_REQUIRE_EQ(0, tzfs_get_one_prop(zfd, "zht:k", val, sizeof(val),
	    &iv, &is_str, &src));
	ATF_REQUIRE_EQ(1, is_str);
	ATF_REQUIRE_STREQ("hello", val);

	ATF_REQUIRE_EQ(0, tzfs_inherit(zfd, "zht:k", false));
	ATF_REQUIRE_ERRNO(ENOENT,
	    tzfs_get_one_prop(zfd, "zht:k", val, sizeof(val), &iv, &is_str,
	    &src) == -1);

	/* Missing property -> ENOENT. */
	ATF_REQUIRE_ERRNO(ENOENT,
	    tzfs_get_one_prop(zfd, "zht:absent", val, sizeof(val), &iv,
	    &is_str, &src) == -1);
	close(zfd);
}
ATF_TC_CLEANUP(property_triad, tc)
{
	zht_pool_cleanup(tc);
}

/* Run only in the disposable TrustedZFS guest. Legacy namespace changes race
 * the handle read path; bounded stress does not guarantee every interleaving. */
ATF_TC_WITH_CLEANUP(property_rename_identity);
ATF_TC_HEAD(property_rename_identity, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "held property reads survive legacy rename and old-name replacement");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(property_rename_identity, tc)
{
	struct { uint64_t reads; int error; } result;
	char ds[256], moved[256], value[256];
	uint64_t expected, number;
	uint32_t source;
	int fd, is_string, stop[2], report[2], status, command_error = 0;
	pid_t child;

	zht_setup(tc, ds, sizeof(ds));
	snprintf(moved, sizeof(moved), "%s/moved", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs set atime=off %s", ds));
	fd = tzfs_open(ds, 0, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_get_one_prop(fd, "atime", value,
	    sizeof(value), &expected, &is_string, &source));
	ATF_REQUIRE_EQ(0, is_string);
	ATF_REQUIRE_EQ(0, pipe(stop));
	ATF_REQUIRE_EQ(0, pipe(report));
	ATF_REQUIRE_EQ(0, fcntl(stop[0], F_SETFL, O_NONBLOCK));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		char byte;
		ssize_t n;

		close(stop[1]);
		close(report[0]);
		memset(&result, 0, sizeof(result));
		for (;;) {
			if (tzfs_get_one_prop(fd, "atime", value, sizeof(value),
			    &number, &is_string, &source) != 0) {
				result.error = errno;
				break;
			}
			if (is_string != 0 || number != expected) {
				result.error = EINVAL;
				break;
			}
			if (tzfs_get_one_prop(fd, "mountpoint", value,
			    sizeof(value), &number, &is_string, &source) != 0) {
				result.error = errno;
				break;
			}
			if (is_string != 1 || strcmp(value, "none") != 0) {
				result.error = EINVAL;
				break;
			}
			result.reads++;
			/* Tell the parent the first pair passed before mutations. */
			if (result.reads == 1 && write(report[1], "R", 1) != 1)
				_exit(2);
			n = read(stop[0], &byte, 1);
			if (n == 0 || n == 1)
				break;
			if (errno != EAGAIN && errno != EINTR) {
				result.error = errno;
				break;
			}
		}
		/* Report startup failure distinctly so the parent cannot block. */
		if (result.reads == 0)
			(void)write(report[1], "F", 1);
		if (write(report[1], &result, sizeof(result)) != sizeof(result))
			_exit(2);
		close(fd);
		_exit(0);
	}
	close(stop[0]);
	close(report[1]);
	{
		char ready = 0;
		if (read(report[0], &ready, 1) != 1 || ready != 'R')
			command_error = 1;
	}
	for (unsigned i = 0; i < 32 && command_error == 0; i++) {
		command_error = zht_systemf("zfs rename %s %s", ds, moved);
		if (command_error == 0)
			command_error = zht_systemf("zfs create -o atime=on "
			    "-o canmount=off -o mountpoint=/zht-unused %s", ds);
		if (command_error == 0)
			command_error = zht_systemf("zfs destroy %s", ds);
		if (command_error == 0)
			command_error = zht_systemf("zfs rename %s %s", moved, ds);
	}
	close(stop[1]);
	memset(&result, 0, sizeof(result));
	ssize_t received = read(report[0], &result, sizeof(result));
	close(report[0]);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	close(fd);
	ATF_REQUIRE_EQ(0, command_error);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "property reader status %d", status);
	ATF_REQUIRE_EQ(sizeof(result), received);
	ATF_REQUIRE_MSG(result.error == 0, "property read error %d after %ju pairs",
	    result.error, (uintmax_t)result.reads);
	ATF_REQUIRE(result.reads > 1);
}
ATF_TC_CLEANUP(property_rename_identity, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(holds_and_bookmarks);
ATF_TC_HEAD(holds_and_bookmarks, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "enumerate holds and bookmarks; create/destroy bookmarks");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(holds_and_bookmarks, tc)
{
	char ds[256], want[256];
	void *buf;
	size_t len;
	int zfd, sfd;

	zht_setup(tc, ds, sizeof(ds));
	zfd = tzfs_open(ds, ZH_SNAPSHOT | ZH_SNAP_DESTROY | ZH_HOLD |
	    ZH_RELEASE | ZH_BOOKMARK, ZHF_SUBTREE);
	ATF_REQUIRE(zfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(zfd, "s1"));

	/* Hold the snapshot, enumerate holds via a snapshot handle. */
	sfd = tzfs_openat(zfd, "@s1", ZH_HOLD, 0);
	ATF_REQUIRE(sfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_hold(zfd, "s1", "keeper"));
	ATF_REQUIRE_EQ(0, tzfs_holds(sfd, &buf, &len));
	ATF_REQUIRE(buf_has(buf, len, "keeper"));
	free(buf);
	ATF_REQUIRE_EQ(0, tzfs_release(zfd, "s1", "keeper"));
	close(sfd);

	/* Bookmark the snapshot, list bookmarks, destroy it. */
	ATF_REQUIRE_MSG(tzfs_bookmark(zfd, "s1", "bm1") == 0,
	    "bookmark: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, tzfs_list_bookmarks(zfd, &buf, &len));
	snprintf(want, sizeof(want), "%s#bm1", ds);
	ATF_REQUIRE(buf_has(buf, len, want));
	free(buf);
	ATF_REQUIRE_EQ(0, tzfs_destroy_bookmark(zfd, "bm1"));
	ATF_REQUIRE_EQ(0, tzfs_list_bookmarks(zfd, &buf, &len));
	ATF_REQUIRE(!buf_has(buf, len, want));
	free(buf);
	close(zfd);
}
ATF_TC_CLEANUP(holds_and_bookmarks, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(promote_clone);
ATF_TC_HEAD(promote_clone, tc)
{
	atf_tc_set_md_var(tc, "descr", "promote a clone above its origin");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(promote_clone, tc)
{
	char ds[256], clone[256];
	int pfd, cfd, clfd;

	zht_setup(tc, ds, sizeof(ds));
	pfd = tzfs_open(ds, PARENT_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(pfd >= 0);
	cfd = tzfs_create(pfd, "child", 0);
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(cfd, "base"));
	clfd = tzfs_clone(pfd, cfd, "base", "clone1");
	ATF_REQUIRE(clfd >= 0);

	/* Before promote, the clone's origin is child@base. */
	snprintf(clone, sizeof(clone), "%s/clone1", ds);
	ATF_REQUIRE_EQ(0, zht_systemf(
	    "zfs get -H -o value origin %s | grep -q @base", clone));

	ATF_REQUIRE_MSG(tzfs_promote(clfd) == 0,
	    "promote: %s", strerror(errno));
	/* After promote, the clone has no origin. */
	ATF_REQUIRE_EQ(0, zht_systemf(
	    "zfs get -H -o value origin %s | grep -qx -", clone));

	close(clfd);
	close(cfd);
	close(pfd);
}
ATF_TC_CLEANUP(promote_clone, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(send_once);
ATF_TC_HEAD(send_once, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "send-once: keep-open-but-unsendable vs consume");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(send_once, tc)
{
	struct zfd_stat_args st;
	char ds[256];
	int zfd, sfd, fd;

	zht_setup(tc, ds, sizeof(ds));
	zfd = tzfs_open(ds, ZH_SNAPSHOT | ZH_SEND, ZHF_SEND_ONCE);
	ATF_REQUIRE(zfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(zfd, "s1"));

	/* Case ONCE: after one send, further sends fail; handle stays valid. */
	sfd = tzfs_openat(zfd, "@s1", ZH_SEND, 0);
	ATF_REQUIRE(sfd >= 0);
	fd = open("stream1.zfs", O_RDWR | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_send(sfd, NULL, NULL, fd, 0));
	ATF_REQUIRE(lseek(fd, 0, SEEK_SET) == 0);
	ATF_REQUIRE_ERRNO(EALREADY,
	    tzfs_send(sfd, NULL, NULL, fd, 0) == -1);
	/* Still valid for other ops. */
	ATF_REQUIRE_EQ(0, zfd_stat(sfd, &st));
	close(fd);
	close(sfd);
	close(zfd);

	/* Case ONCE|CONSUME: the handle is invalidated after the send. */
	zfd = tzfs_open(ds, ZH_SEND, ZHF_SEND_ONCE | ZHF_SEND_CONSUME);
	ATF_REQUIRE(zfd >= 0);
	sfd = tzfs_openat(zfd, "@s1", ZH_SEND, 0);
	ATF_REQUIRE(sfd >= 0);
	fd = open("stream2.zfs", O_RDWR | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_send(sfd, NULL, NULL, fd, 0));
	ATF_REQUIRE_ERRNO(ENXIO, zfd_stat(sfd, &st) == -1);
	close(fd);
	close(sfd);
	close(zfd);
}
ATF_TC_CLEANUP(send_once, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, list_children);
	ATF_TP_ADD_TC(tp, list_snapshots);
	ATF_TP_ADD_TC(tp, readonly_inheritance);
	ATF_TP_ADD_TC(tp, property_triad);
	ATF_TP_ADD_TC(tp, property_rename_identity);
	ATF_TP_ADD_TC(tp, holds_and_bookmarks);
	ATF_TP_ADD_TC(tp, promote_clone);
	ATF_TP_ADD_TC(tp, send_once);
	return (atf_no_error());
}
