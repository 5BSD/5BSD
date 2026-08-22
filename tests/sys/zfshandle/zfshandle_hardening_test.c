/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Regression tests for TrustedZFS security hardening.  These deliberately
 * exercise raw ioctl ABI boundaries and shared-object races in addition to
 * the public libtrustedzfs API.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/linker.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <trustedzfs.h>

#include "zfshandle_test_helpers.h"

#define	HARD_RIGHTS	(ZH_PROPS_WRITE | ZH_SNAPSHOT | ZH_SNAP_DESTROY | \
	ZH_ROLLBACK | ZH_CLONE_SRC | ZH_CREATE | ZH_DESTROY | ZH_SEND | \
	ZH_RECV | ZH_MOUNT | ZH_HOLD | ZH_RENAME | ZH_PROMOTE | \
	ZH_BOOKMARK | ZH_RELEASE)

static void
hard_setup(const atf_tc_t *tc, char *ds, size_t dslen)
{
	zht_require(tc);
	zht_pool_create(tc);
	snprintf(ds, dslen, "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", ds));
}

static void
check_cloexec(int fd)
{
	int flags;

	ATF_REQUIRE(fd >= 0);
	flags = fcntl(fd, F_GETFD);
	ATF_REQUIRE(flags != -1);
	ATF_CHECK((flags & FD_CLOEXEC) != 0);
}

static int *
exhaust_descriptor_table(size_t *countp, struct rlimit *savedp)
{
	struct rlimit limit;
	int *fill;
	int fd, maxfd, tablesize;
	size_t count;

	ATF_REQUIRE_EQ(0, getrlimit(RLIMIT_NOFILE, savedp));
	tablesize = getdtablesize();
	ATF_REQUIRE(tablesize > 0);
	maxfd = -1;
	for (fd = 0; fd < tablesize; fd++) {
		if (fcntl(fd, F_GETFD) != -1)
			maxfd = fd;
	}
	ATF_REQUIRE(maxfd >= 0);
	fill = calloc((size_t)maxfd + 1, sizeof(*fill));
	ATF_REQUIRE(fill != NULL);
	limit = *savedp;
	limit.rlim_cur = (rlim_t)maxfd + 1;
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_NOFILE, &limit));
	count = 0;
	while ((fd = open("/dev/null", O_RDONLY)) != -1) {
		ATF_REQUIRE(count < (size_t)maxfd + 1);
		fill[count++] = fd;
	}
	ATF_REQUIRE_EQ(EMFILE, errno);
	*countp = count;
	return (fill);
}

static void
restore_descriptor_table(int *fill, size_t count, const struct rlimit *saved)
{
	size_t i;

	for (i = 0; i < count; i++)
		close(fill[i]);
	free(fill);
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_NOFILE, saved));
}

ATF_TC_WITH_CLEANUP(returned_fds_cloexec);
ATF_TC_HEAD(returned_fds_cloexec, tc)
{
	atf_tc_set_md_var(tc, "descr", "every TrustedZFS-produced fd is CLOEXEC");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(returned_fds_cloexec, tc)
{
	char ds[256];
	int fd, dfd, cfd, ofd, pfd, rfd, mfd;

	hard_setup(tc, ds, sizeof(ds));
	fd = tzfs_open(ds, HARD_RIGHTS, ZHF_SUBTREE);
	check_cloexec(fd);
	dfd = tzfs_derive(fd, ZH_SNAPSHOT);
	check_cloexec(dfd);
	cfd = tzfs_create(fd, "child", 0);
	check_cloexec(cfd);
	ofd = tzfs_openat(fd, "child", ZH_SNAPSHOT, 0);
	check_cloexec(ofd);
	mfd = tzfs_mount(cfd, true);
	check_cloexec(mfd);
	ATF_REQUIRE_EQ(0, tzfs_unmount(cfd));
	pfd = tzfs_pool_open(zht_pool, HARD_RIGHTS);
	check_cloexec(pfd);
	rfd = tzfs_pool_root_open(pfd, ZH_PROPS_READ, 0);
	check_cloexec(rfd);
	close(rfd); close(pfd); close(mfd); close(ofd); close(cfd); close(dfd);
	close(fd);
}
ATF_TC_CLEANUP(returned_fds_cloexec, tc) { zht_pool_cleanup(tc); }

ATF_TC_WITH_CLEANUP(fd_install_failure_rolls_back);
ATF_TC_HEAD(fd_install_failure_rolls_back, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "create and clone roll back if their returned fd cannot install");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fd_install_failure_rolls_back, tc)
{
	struct rlimit saved;
	char ds[256];
	int *fill;
	size_t count;
	int fd;

	hard_setup(tc, ds, sizeof(ds));
	fd = tzfs_open(ds, HARD_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(fd >= 0);

	fill = exhaust_descriptor_table(&count, &saved);
	ATF_REQUIRE_ERRNO(EMFILE,
	    tzfs_create(fd, "unreported-create", 0) == -1);
	restore_descriptor_table(fill, count, &saved);
	ATF_REQUIRE_ERRNO(ENOENT,
	    tzfs_openat(fd, "unreported-create", 0, 0) == -1);

	ATF_REQUIRE_EQ(0, tzfs_snapshot(fd, "origin"));
	fill = exhaust_descriptor_table(&count, &saved);
	ATF_REQUIRE_ERRNO(EMFILE,
	    tzfs_clone(fd, fd, "origin", "unreported-clone") == -1);
	restore_descriptor_table(fill, count, &saved);
	ATF_REQUIRE_ERRNO(ENOENT,
	    tzfs_openat(fd, "unreported-clone", 0, 0) == -1);
	close(fd);
}
ATF_TC_CLEANUP(fd_install_failure_rolls_back, tc) { zht_pool_cleanup(tc); }

ATF_TC_WITH_CLEANUP(operation_ceiling_inherits);
ATF_TC_HEAD(operation_ceiling_inherits, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "kernel operation ceilings narrow monotonically and follow child fds");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(operation_ceiling_inherits, tc)
{
	struct zfd_limit_args lim;
	char ds[256], childds[256];
	int fd, child, origin, dest;

	hard_setup(tc, ds, sizeof(ds));
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s/child", ds));
	ATF_REQUIRE_EQ(0, zht_systemf("zfs snapshot %s/child@base", ds));

	fd = tzfs_open(ds, ZH_SNAPSHOT, ZHF_SUBTREE);
	ATF_REQUIRE_EQ(0, tzfs_limit_dataset_ioctls(fd,
	    TZFS_OP_INFO | TZFS_OP_DERIVE));
	child = tzfs_derive(fd, ZH_SNAPSHOT);
	ATF_REQUIRE(child >= 0);
	ATF_CHECK_ERRNO(ENOTCAPABLE, tzfs_snapshot(child, "blocked") == -1);
	memset(&lim, 0, sizeof(lim));
	lim.zl_ops = ZFD_OP_INFO | ZFD_OP_STAT;
	ATF_CHECK_ERRNO(ENOTCAPABLE, ioctl(fd, ZFD_LIMIT, &lim) == -1);
	close(child); close(fd);

	fd = tzfs_open(ds, ZH_SNAPSHOT, ZHF_SUBTREE);
	ATF_REQUIRE_EQ(0, tzfs_limit_dataset_ioctls(fd,
	    TZFS_OP_INFO | TZFS_OP_OPENAT));
	child = tzfs_openat(fd, "child", ZH_SNAPSHOT, 0);
	ATF_REQUIRE(child >= 0);
	ATF_CHECK_ERRNO(ENOTCAPABLE, tzfs_snapshot(child, "blocked2") == -1);
	close(child); close(fd);

	snprintf(childds, sizeof(childds), "%s/child", ds);
	origin = tzfs_open(childds, ZH_CLONE_SRC, 0);
	ATF_REQUIRE(origin >= 0);
	ATF_REQUIRE_EQ(0, tzfs_limit_dataset_ioctls(origin, TZFS_OP_INFO));
	dest = tzfs_open(ds, ZH_CREATE, ZHF_SUBTREE);
	ATF_REQUIRE(dest >= 0);
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    tzfs_clone(dest, origin, "base", "escaped") == -1);
	close(dest); close(origin);
}
ATF_TC_CLEANUP(operation_ceiling_inherits, tc) { zht_pool_cleanup(tc); }

static int
child_send_once(int zfd, int startfd, int resultfd)
{
	char ch;
	int out, result;

	if (read(startfd, &ch, 1) != 1)
		_exit(90);
	out = open("/dev/null", O_WRONLY);
	if (out == -1)
		_exit(91);
	result = tzfs_send(zfd, "s", NULL, out, 0) == 0 ? 0 : errno;
	(void)write(resultfd, &result, sizeof(result));
	close(out);
	_exit(0);
}

ATF_TC_WITH_CLEANUP(send_once_lineage_and_race);
ATF_TC_HEAD(send_once_lineage_and_race, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "send-once is immutable, lineage-wide, retryable, and race-safe");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(send_once_lineage_and_race, tc)
{
	struct zfd_info_args info;
	char ds[256], go = 'g';
	pid_t a, b;
	int fd, dfd, sfd, out, bad, start[2], result[2], r[2], status;

	hard_setup(tc, ds, sizeof(ds));
	fd = tzfs_open(ds, ZH_SNAPSHOT | ZH_SEND, ZHF_SEND_ONCE);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(fd, "s"));
	dfd = tzfs_derive(fd, ZH_SEND);
	sfd = tzfs_openat(fd, "@s", ZH_SEND, 0);
	ATF_REQUIRE(dfd >= 0 && sfd >= 0);
	bad = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(bad >= 0);
	ATF_REQUIRE(tzfs_send(sfd, NULL, NULL, bad, 0) == -1);
	close(bad);
	out = open("/dev/null", O_WRONLY);
	ATF_REQUIRE(out >= 0);
	ATF_REQUIRE_EQ(0, tzfs_send(dfd, "s", NULL, out, 0));
	ATF_CHECK_ERRNO(EALREADY, tzfs_send(sfd, NULL, NULL, out, 0) == -1);
	ATF_REQUIRE_EQ(0, tzfs_info(sfd, &info));
	ATF_CHECK_EQ(1, info.zi_valid);
	close(out); close(sfd); close(dfd); close(fd);

	fd = tzfs_open(ds, ZH_SEND, ZHF_SEND_ONCE | ZHF_SEND_CONSUME);
	dfd = tzfs_derive(fd, ZH_SEND);
	sfd = tzfs_openat(fd, "@s", ZH_SEND, 0);
	out = open("/dev/null", O_WRONLY);
	ATF_REQUIRE_EQ(0, tzfs_send(sfd, NULL, NULL, out, 0));
	ATF_REQUIRE_EQ(0, tzfs_info(fd, &info));
	ATF_CHECK_EQ(0, info.zi_valid);
	ATF_REQUIRE_EQ(0, tzfs_info(dfd, &info));
	ATF_CHECK_EQ(0, info.zi_valid);
	ATF_CHECK_ERRNO(ENXIO, tzfs_derive(fd, 0) == -1);
	close(out); close(sfd); close(dfd); close(fd);

	fd = tzfs_open(ds, ZH_SEND, ZHF_SEND_ONCE);
	ATF_REQUIRE(pipe(start) == 0 && pipe(result) == 0);
	a = fork();
	ATF_REQUIRE(a >= 0);
	if (a == 0) child_send_once(fd, start[0], result[1]);
	b = fork();
	ATF_REQUIRE(b >= 0);
	if (b == 0) child_send_once(fd, start[0], result[1]);
	close(start[0]); close(result[1]);
	ATF_REQUIRE_EQ(1, write(start[1], &go, 1));
	ATF_REQUIRE_EQ(1, write(start[1], &go, 1));
	ATF_REQUIRE_EQ((ssize_t)sizeof(r[0]), read(result[0], &r[0], sizeof(r[0])));
	ATF_REQUIRE_EQ((ssize_t)sizeof(r[1]), read(result[0], &r[1], sizeof(r[1])));
	ATF_REQUIRE_EQ(a, waitpid(a, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_REQUIRE_EQ(b, waitpid(b, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK((r[0] == 0 && (r[1] == EBUSY || r[1] == EALREADY)) ||
	    (r[1] == 0 && (r[0] == EBUSY || r[0] == EALREADY)));
	close(start[1]); close(result[0]); close(fd);
}
ATF_TC_CLEANUP(send_once_lineage_and_race, tc) { zht_pool_cleanup(tc); }

ATF_TC_WITH_CLEANUP(concurrent_mount_singleton);
ATF_TC_HEAD(concurrent_mount_singleton, tc)
{
	atf_tc_set_md_var(tc, "descr", "concurrent anonymous mounts produce one winner");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(concurrent_mount_singleton, tc)
{
	char ds[256], go = 'm';
	pid_t p[2];
	int fd, start[2], result[2], r[2], i, status;

	hard_setup(tc, ds, sizeof(ds));
	fd = tzfs_open(ds, ZH_MOUNT, 0);
	ATF_REQUIRE(pipe(start) == 0 && pipe(result) == 0);
	for (i = 0; i < 2; i++) {
		p[i] = fork();
		ATF_REQUIRE(p[i] >= 0);
		if (p[i] == 0) {
			int m;
			if (read(start[0], &go, 1) != 1) _exit(80);
			m = tzfs_mount(fd, true);
			r[i] = m >= 0 ? 0 : errno;
			if (m >= 0) close(m);
			(void)write(result[1], &r[i], sizeof(r[i]));
			_exit(0);
		}
	}
	close(start[0]); close(result[1]);
	ATF_REQUIRE_EQ(1, write(start[1], &go, 1));
	ATF_REQUIRE_EQ(1, write(start[1], &go, 1));
	ATF_REQUIRE_EQ((ssize_t)sizeof(r[0]), read(result[0], &r[0], sizeof(r[0])));
	ATF_REQUIRE_EQ((ssize_t)sizeof(r[1]), read(result[0], &r[1], sizeof(r[1])));
	for (i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ(p[i], waitpid(p[i], &status, 0));
		ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
	ATF_CHECK((r[0] == 0 && r[1] == EBUSY) ||
	    (r[1] == 0 && r[0] == EBUSY));
	ATF_REQUIRE_EQ(0, tzfs_unmount(fd));
	close(start[1]); close(result[0]); close(fd);
}
ATF_TC_CLEANUP(concurrent_mount_singleton, tc) { zht_pool_cleanup(tc); }

ATF_TC_WITH_CLEANUP(orphaned_scm_rights_close);
ATF_TC_HEAD(orphaned_scm_rights_close, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "an unread SCM_RIGHTS handle closes and unmounts without a thread");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(orphaned_scm_rights_close, tc)
{
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} control;
	struct cmsghdr *cm;
	struct iovec iov;
	struct msghdr msg;
	char ds[256], byte = 'h';
	int fd, mfd, sv[2];

	hard_setup(tc, ds, sizeof(ds));
	fd = tzfs_open(ds, ZH_MOUNT, 0);
	ATF_REQUIRE(fd >= 0);
	mfd = tzfs_mount(fd, true);
	ATF_REQUIRE(mfd >= 0);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	memset(&msg, 0, sizeof(msg));
	memset(&control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.buf;
	msg.msg_controllen = sizeof(control.buf);
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &fd, sizeof(fd));
	ATF_REQUIRE_EQ(1, sendmsg(sv[0], &msg, 0));
	ATF_REQUIRE_EQ(0, close(mfd));
	ATF_REQUIRE_EQ(0, close(fd));
	ATF_REQUIRE_EQ(0, close(sv[0]));
	/* unp_dispose() drops the unread descriptor through closef_nothread(). */
	ATF_REQUIRE_EQ(0, close(sv[1]));
}
ATF_TC_CLEANUP(orphaned_scm_rights_close, tc) { zht_pool_cleanup(tc); }

#define	BAD_IOCTL(fd, cmd, arg) \
	ATF_CHECK_ERRNO(EINVAL, ioctl((fd), (cmd), &(arg)) == -1)

ATF_TC_WITH_CLEANUP(strict_ioctl_abi);
ATF_TC_HEAD(strict_ioctl_abi, tc)
{
	atf_tc_set_md_var(tc, "descr", "malformed raw ioctl fields fail closed");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(strict_ioctl_abi, tc)
{
	struct zfd_derive_args derive;
	struct zfd_openat_args openat;
	struct zfd_snapshot_args snap;
	struct zfd_set_prop_args prop;
	struct zfd_create_args create;
	struct zfd_destroy_args destroy;
	struct zfd_send_args send;
	struct zfd_recv_args recv;
	struct zfd_inherit_args inherit;
	struct zfd_bookmark_args book;
	struct zfd_blkopen_args blk;
	struct zfd_mount_args mount;
	char ds[256];
	int fd;

	hard_setup(tc, ds, sizeof(ds));
	fd = tzfs_open(ds, HARD_RIGHTS, ZHF_SUBTREE);
	memset(&derive, 0, sizeof(derive)); derive.zd_pad = 1;
	BAD_IOCTL(fd, ZFD_DERIVE, derive);
	memset(&openat, 'x', sizeof(openat));
	BAD_IOCTL(fd, ZFD_OPENAT, openat);
	memset(&snap, 's', sizeof(snap));
	BAD_IOCTL(fd, ZFD_SNAPSHOT, snap);
	memset(&prop, 0, sizeof(prop)); strlcpy(prop.zsp_name, "x:y", sizeof(prop.zsp_name));
	prop.zsp_is_string = 2; BAD_IOCTL(fd, ZFD_SET_PROP, prop);
	prop.zsp_is_string = 0; prop.zsp_pad = 1; BAD_IOCTL(fd, ZFD_SET_PROP, prop);
	memset(&create, 0, sizeof(create)); strlcpy(create.zc_relname, "bad", sizeof(create.zc_relname));
	create.zc_type = ZFD_TYPE_FILESYSTEM; create.zc_volsize = 1; BAD_IOCTL(fd, ZFD_CREATE, create);
	create.zc_volsize = 0; create.zc_pad = 1; BAD_IOCTL(fd, ZFD_CREATE, create);
	create.zc_pad = 0; create.zc_handle_flags = ZHF_SEND_CONSUME; BAD_IOCTL(fd, ZFD_CREATE, create);
	create.zc_handle_flags = 0; create.zc_type = ZFD_TYPE_VOLUME; BAD_IOCTL(fd, ZFD_CREATE, create);
	memset(&destroy, 'x', sizeof(destroy)); BAD_IOCTL(fd, ZFD_DESTROY, destroy);
	memset(&send, 0, sizeof(send)); strlcpy(send.zs_snapname, "s", sizeof(send.zs_snapname));
	send.zs_flags = UINT32_C(0x80000000); BAD_IOCTL(fd, ZFD_SEND, send);
	memset(&recv, 0, sizeof(recv)); strlcpy(recv.zr_reltarget, "x@s", sizeof(recv.zr_reltarget));
	recv.zr_force = 2; BAD_IOCTL(fd, ZFD_RECV, recv);
	memset(&inherit, 0, sizeof(inherit)); strlcpy(inherit.zin_name, "compression", sizeof(inherit.zin_name));
	inherit.zin_received = 2; BAD_IOCTL(fd, ZFD_INHERIT, inherit);
	inherit.zin_received = 0; inherit.zin_pad = 1; BAD_IOCTL(fd, ZFD_INHERIT, inherit);
	memset(&book, 0, sizeof(book)); strlcpy(book.zbm_snapname, "ignored", sizeof(book.zbm_snapname));
	strlcpy(book.zbm_bookname, "b", sizeof(book.zbm_bookname)); BAD_IOCTL(fd, ZFD_DESTROY_BOOKMARK, book);
	memset(&blk, 0, sizeof(blk)); blk.zb_write = 2; BAD_IOCTL(fd, ZFD_BLKOPEN, blk);
	memset(&mount, 0, sizeof(mount)); mount.zm_rdonly = 2; BAD_IOCTL(fd, ZFD_MOUNT, mount);
	close(fd);
	ATF_CHECK_ERRNO(EINVAL, tzfs_open(ds, 0, ZHF_SEND_CONSUME) == -1);
}
ATF_TC_CLEANUP(strict_ioctl_abi, tc) { zht_pool_cleanup(tc); }

ATF_TC_WITH_CLEANUP(library_output_contracts);
ATF_TC_HEAD(library_output_contracts, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "library rejects null outputs and reports string truncation");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(library_output_contracts, tc)
{
	char ds[256], tiny[1];
	void *buf = (void *)(uintptr_t)1;
	size_t len = 99;
	int fd;

	hard_setup(tc, ds, sizeof(ds));
	fd = tzfs_open(ds, ZH_PROPS_WRITE, ZHF_SUBTREE);
	ATF_CHECK_ERRNO(EINVAL, tzfs_get_props(fd, NULL, &len) == -1);
	ATF_CHECK_ERRNO(EINVAL, tzfs_get_props(fd, &buf, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, tzfs_list_children(fd, NULL, &len) == -1);
	ATF_CHECK_ERRNO(EINVAL, tzfs_list_snapshots(fd, &buf, NULL) == -1);
	ATF_REQUIRE_EQ(0, tzfs_set_prop_string(fd, "zht:long", "value"));
	ATF_CHECK_ERRNO(ERANGE,
	    tzfs_get_one_prop(fd, "zht:long", tiny, sizeof(tiny), NULL,
	    NULL, NULL) == -1);
	ATF_CHECK_ERRNO(EFAULT, tzfs_info(fd, NULL) == -1);
	ATF_CHECK_ERRNO(EFAULT, tzfs_stat(fd, NULL) == -1);
	close(fd);
}
ATF_TC_CLEANUP(library_output_contracts, tc) { zht_pool_cleanup(tc); }

ATF_TC_WITH_CLEANUP(names_and_self_rename);
ATF_TC_HEAD(names_and_self_rename, tc)
{
	atf_tc_set_md_var(tc, "descr", "ordinary '..' substrings work and self rename stays scoped");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(names_and_self_rename, tc)
{
	struct zfd_info_args info;
	char ds[256], self[256], want[256];
	int fd, cfd;

	hard_setup(tc, ds, sizeof(ds));
	fd = tzfs_open(ds, ZH_CREATE | ZH_RENAME, ZHF_SUBTREE);
	cfd = tzfs_create(fd, "release..candidate", 0);
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_rename(fd, "release..candidate", "kept..name"));
	close(cfd); close(fd);
	snprintf(self, sizeof(self), "%s/self", ds);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", self));
	fd = tzfs_open(self, ZH_RENAME, 0);
	ATF_REQUIRE_EQ(0, tzfs_rename(fd, NULL, "renamed..leaf"));
	ATF_REQUIRE_EQ(0, tzfs_info(fd, &info));
	snprintf(want, sizeof(want), "%s/renamed..leaf", ds);
	ATF_CHECK_STREQ(want, info.zi_name);
	close(fd);
}
ATF_TC_CLEANUP(names_and_self_rename, tc) { zht_pool_cleanup(tc); }

ATF_TC_WITH_CLEANUP(namespace_identity_race);
ATF_TC_HEAD(namespace_identity_race, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "rename churn cannot redirect a handle operation to a name replacement");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(namespace_identity_race, tc)
{
	char ds[256], moved[256], snap[32];
	pid_t pid;
	int fd, i, status;

	hard_setup(tc, ds, sizeof(ds));
	snprintf(moved, sizeof(moved), "%s.moved", ds);
	fd = tzfs_open(ds, ZH_SNAPSHOT | ZH_SNAP_DESTROY, 0);
	ATF_REQUIRE(fd >= 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		for (i = 0; i < 40; i++) {
			if (zht_systemf("zfs rename %s %s", ds, moved) != 0 ||
			    zht_systemf("zfs rename %s %s", moved, ds) != 0)
				_exit(60);
		}
		_exit(0);
	}
	for (i = 0; i < 80; i++) {
		snprintf(snap, sizeof(snap), "race%03d", i);
		ATF_REQUIRE_MSG(tzfs_snapshot(fd, snap) == 0,
		    "snapshot %d: %s", i, strerror(errno));
		ATF_REQUIRE_MSG(tzfs_snap_destroy(fd, snap) == 0,
		    "destroy %d: %s", i, strerror(errno));
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "renamer status %#x", status);
	close(fd);
}
ATF_TC_CLEANUP(namespace_identity_race, tc) { zht_pool_cleanup(tc); }

static int
mint_as(const char *dataset, uint64_t rights)
{
	struct passwd *pw;
	pid_t pid;
	int p[2], result, status;

	pw = getpwnam("nobody");
	ATF_REQUIRE(pw != NULL);
	ATF_REQUIRE_EQ(0, pipe(p));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd;
		close(p[0]);
		(void)setgroups(0, NULL);
		if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
			_exit(70);
		fd = tzfs_open(dataset, rights, 0);
		result = fd >= 0 ? 0 : errno;
		if (fd >= 0) close(fd);
		(void)write(p[1], &result, sizeof(result));
		_exit(0);
	}
	close(p[1]);
	ATF_REQUIRE_EQ((ssize_t)sizeof(result), read(p[0], &result, sizeof(result)));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(p[0]);
	return (result);
}

ATF_TC_WITH_CLEANUP(delegation_permission_matrix);
ATF_TC_HEAD(delegation_permission_matrix, tc)
{
	atf_tc_set_md_var(tc, "descr", "zfs-allow permission combinations exactly gate minting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(delegation_permission_matrix, tc)
{
	char ds[256];

	hard_setup(tc, ds, sizeof(ds));
	ATF_CHECK_EQ(0, mint_as(ds, 0));
#define	ALLOW(perms) ATF_REQUIRE_EQ(0, zht_systemf("zfs allow nobody %s %s", (perms), ds))
#define	UNALLOW() (void)zht_systemf("zfs unallow nobody %s", ds)
	ALLOW("snapshot"); ATF_CHECK_EQ(0, mint_as(ds, ZH_SNAPSHOT)); UNALLOW();
	ALLOW("create"); ATF_CHECK(mint_as(ds, ZH_CREATE) != 0); UNALLOW();
	ALLOW("create,mount"); ATF_CHECK_EQ(0, mint_as(ds, ZH_CREATE)); UNALLOW();
	ALLOW("rename,mount"); ATF_CHECK(mint_as(ds, ZH_RENAME) != 0); UNALLOW();
	ALLOW("rename,mount,create"); ATF_CHECK_EQ(0, mint_as(ds, ZH_RENAME)); UNALLOW();
	ALLOW("receive,mount"); ATF_CHECK(mint_as(ds, ZH_RECV) != 0); UNALLOW();
	ALLOW("receive,mount,create"); ATF_CHECK_EQ(0, mint_as(ds, ZH_RECV)); UNALLOW();
	ALLOW("destroy"); ATF_CHECK(mint_as(ds, ZH_DESTROY) != 0); UNALLOW();
	ALLOW("destroy,mount"); ATF_CHECK_EQ(0, mint_as(ds, ZH_DESTROY)); UNALLOW();
	ALLOW("hold"); ATF_CHECK_EQ(0, mint_as(ds, ZH_HOLD)); UNALLOW();
	ALLOW("release"); ATF_CHECK_EQ(0, mint_as(ds, ZH_RELEASE)); UNALLOW();
	ALLOW("bookmark"); ATF_CHECK_EQ(0, mint_as(ds, ZH_BOOKMARK)); UNALLOW();
	ALLOW("send"); ATF_CHECK_EQ(0, mint_as(ds, ZH_SEND)); UNALLOW();
	ATF_CHECK(mint_as(ds, ZH_PROMOTE) != 0);
#undef ALLOW
#undef UNALLOW
}
ATF_TC_CLEANUP(delegation_permission_matrix, tc) { zht_pool_cleanup(tc); }

static int
counter(const char *name)
{
	int value;
	size_t len = sizeof(value);

	ATF_REQUIRE_EQ(0, sysctlbyname(name, &value, &len, NULL, 0));
	return (value);
}

ATF_TC_WITH_CLEANUP(mac_hooks_reached);
ATF_TC_HEAD(mac_hooks_reached, tc)
{
	atf_tc_set_md_var(tc, "descr", "handle verbs invoke the native MAC ZFS hooks");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mac_hooks_reached, tc)
{
	char ds[256];
	int fd, out, before_create, before_send, before_revert, before_delete;

	hard_setup(tc, ds, sizeof(ds));
	if (kldload("mac_test") == -1 && errno != EEXIST)
		atf_tc_skip("mac_test unavailable: %s", strerror(errno));
	before_create = counter("security.mac.test.counter.mount_check_snapshot_create");
	before_send = counter("security.mac.test.counter.zfs_check_send");
	before_revert = counter("security.mac.test.counter.mount_check_snapshot_revert");
	before_delete = counter("security.mac.test.counter.mount_check_snapshot_delete");
	fd = tzfs_open(ds, ZH_SNAPSHOT | ZH_SNAP_DESTROY | ZH_ROLLBACK | ZH_SEND, 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(fd, "mac"));
	out = open("/dev/null", O_WRONLY);
	ATF_REQUIRE_EQ(0, tzfs_send(fd, "mac", NULL, out, 0));
	ATF_REQUIRE_EQ(0, tzfs_rollback(fd, "mac"));
	ATF_REQUIRE_EQ(0, tzfs_snap_destroy(fd, "mac"));
	ATF_CHECK(counter("security.mac.test.counter.mount_check_snapshot_create") > before_create);
	ATF_CHECK(counter("security.mac.test.counter.zfs_check_send") > before_send);
	ATF_CHECK(counter("security.mac.test.counter.mount_check_snapshot_revert") > before_revert);
	ATF_CHECK(counter("security.mac.test.counter.mount_check_snapshot_delete") > before_delete);
	close(out); close(fd);
}
ATF_TC_CLEANUP(mac_hooks_reached, tc) { zht_pool_cleanup(tc); }

ATF_TC_WITH_CLEANUP(enumeration_ceiling);
ATF_TC_HEAD(enumeration_ceiling, tc)
{
	atf_tc_set_md_var(tc, "descr", "cursor-free enumeration has a hard entry ceiling");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "900");
}
ATF_TC_BODY(enumeration_ceiling, tc)
{
	char ds[256], bookmark[32];
	void *buf = NULL;
	size_t len = 0, limitlen;
	unsigned i, limit;
	int fd;

	hard_setup(tc, ds, sizeof(ds));
	limitlen = sizeof(limit);
	ATF_REQUIRE_EQ(0, sysctlbyname(
	    "vfs.zfs.trustedzfs.enum_max_entries", &limit, &limitlen,
	    NULL, 0));
	ATF_REQUIRE_EQ(sizeof(limit), limitlen);
	ATF_REQUIRE(limit > 0 && limit <= ZFSHANDLE_ENUM_MAX_ENTRIES);
	fd = tzfs_open(ds, ZH_SNAPSHOT | ZH_BOOKMARK, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(fd, "base"));
	for (i = 0; i <= limit; i++) {
		snprintf(bookmark, sizeof(bookmark), "b%05u", i);
		ATF_REQUIRE_EQ(0, tzfs_bookmark(fd, "base", bookmark));
	}
	ATF_CHECK_ERRNO(E2BIG, tzfs_list_bookmarks(fd, &buf, &len) == -1);
	ATF_CHECK(buf == NULL);
	ATF_CHECK_EQ(0, len);
	close(fd);
}
ATF_TC_CLEANUP(enumeration_ceiling, tc) { zht_pool_cleanup(tc); }

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, returned_fds_cloexec);
	ATF_TP_ADD_TC(tp, fd_install_failure_rolls_back);
	ATF_TP_ADD_TC(tp, operation_ceiling_inherits);
	ATF_TP_ADD_TC(tp, send_once_lineage_and_race);
	ATF_TP_ADD_TC(tp, concurrent_mount_singleton);
	ATF_TP_ADD_TC(tp, orphaned_scm_rights_close);
	ATF_TP_ADD_TC(tp, strict_ioctl_abi);
	ATF_TP_ADD_TC(tp, library_output_contracts);
	ATF_TP_ADD_TC(tp, names_and_self_rename);
	ATF_TP_ADD_TC(tp, namespace_identity_race);
	ATF_TP_ADD_TC(tp, delegation_permission_matrix);
	ATF_TP_ADD_TC(tp, mac_hooks_reached);
	ATF_TP_ADD_TC(tp, enumeration_ceiling);
	return (atf_no_error());
}
