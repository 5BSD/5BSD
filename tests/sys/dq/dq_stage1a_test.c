/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Stage 1a answers (D87): a served file is read-only, so every operation a
 * later stage will serve answers exactly what a read-only descriptor on a
 * real file answers, or the declared stage 1a value.  None of these posts
 * an event (the generic layer or the local fileop answers), so they run in
 * the controller process; the oracle is a read-only descriptor on the real
 * file wherever the answer is the generic layer's.
 */

#include <sys/param.h>
#include <sys/acl.h>
#include <sys/event.h>
#include <sys/extattr.h>
#include <sys/filio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <atf-c.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	DATA_LEN	8192

static unsigned char data[DATA_LEN];
static char oracle_path[DQT_PATH_MAX];

/*
 * Kernel-private fcntl commands (sys/sys/fcntl.h hides them from userland):
 * sys_fcntl never passes them, so both files answer EINVAL.
 */
#define	DQT_F_GET_RW_HINT	0x1000
#define	DQT_F_SET_RW_HINT	0x1001

/* served and oracle calls must agree in return value and errno. */
#define	SAME(expr_served, expr_oracle) do {				\
	long _s, _o;							\
	int _se, _oe;							\
	errno = 0;							\
	_s = (long)(expr_served);					\
	_se = _s == -1 ? errno : 0;					\
	errno = 0;							\
	_o = (long)(expr_oracle);					\
	_oe = _o == -1 ? errno : 0;					\
	ATF_CHECK_EQ_MSG(_o, _s, "%s: served %ld oracle %ld",		\
	    #expr_served, _s, _o);					\
	ATF_CHECK_EQ_MSG(_oe, _se, "%s: served errno %d oracle errno %d",	\
	    #expr_served, _se, _oe);					\
} while (0)

/* A served call that must fail with this errno. */
#define	FAILS(expr, want) do {						\
	long _r;							\
	errno = 0;							\
	_r = (long)(expr);						\
	ATF_CHECK_EQ_MSG(-1, _r, "%s: returned %ld", #expr, _r);	\
	ATF_CHECK_EQ_MSG(want, errno, "%s: errno %d want %d", #expr,	\
	    errno, want);						\
} while (0)

struct fixture {
	struct dqt_ctl	 c;
	struct dqt_object *o;
	int		 oracle;
};

static void
setup(struct fixture *f, unsigned seed)
{

	dqt_fill(data, sizeof(data), seed);
	f->oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&f->c);
	f->o = dqt_mint(&f->c, f->oracle, oracle_path, data, sizeof(data),
	    NULL);
}

static void
teardown(struct fixture *f)
{

	/* Nothing here may have reached the controller. */
	ATF_CHECK_EQ(0, f->c.records);
	dqt_fini(&f->c);
	(void)close(f->oracle);
}

ATF_TC(write_family);
ATF_TC_HEAD(write_family, tc)
{
	atf_tc_set_md_var(tc, "descr", "write, pwrite, writev, ftruncate, "
	    "posix_fallocate and fspacectl answer as on a read-only real file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(write_family, tc)
{
	struct fixture f;
	struct spacectl_range rqsr;
	struct iovec iov;
	char buf[16];

	setup(&f, 31);
	memset(buf, 'x', sizeof(buf));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	/* No FWRITE: dofilewrite refuses before any fileop runs. */
	SAME(write(f.o->fd, buf, sizeof(buf)), write(f.oracle, buf, sizeof(buf)));
	FAILS(write(f.o->fd, buf, sizeof(buf)), EBADF);
	SAME(pwrite(f.o->fd, buf, sizeof(buf), 0),
	    pwrite(f.oracle, buf, sizeof(buf), 0));
	SAME(writev(f.o->fd, &iov, 1), writev(f.oracle, &iov, 1));
	/* kern_ftruncate answers EINVAL "non-writable" for every read-only fd. */
	SAME(ftruncate(f.o->fd, 10), ftruncate(f.oracle, 10));
	FAILS(ftruncate(f.o->fd, 10), EINVAL);
	/* posix_fallocate returns the errno; fget_write gives EBADF. */
	ATF_CHECK_EQ(posix_fallocate(f.oracle, 0, 10),
	    posix_fallocate(f.o->fd, 0, 10));
	ATF_CHECK_EQ(EBADF, posix_fallocate(f.o->fd, 0, 10));
	rqsr.r_offset = 0;
	rqsr.r_len = 10;
	SAME(fspacectl(f.o->fd, SPACECTL_DEALLOC, &rqsr, 0, NULL),
	    fspacectl(f.oracle, SPACECTL_DEALLOC, &rqsr, 0, NULL));
	FAILS(fspacectl(f.o->fd, SPACECTL_DEALLOC, &rqsr, 0, NULL), EBADF);
	teardown(&f);
}

ATF_TC(setattr_eperm);
ATF_TC_HEAD(setattr_eperm, tc)
{
	atf_tc_set_md_var(tc, "descr", "fchmod, fchown, futimens and fchflags "
	    "answer EPERM, the non-owner's answer, until SETATTR events (D87)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setattr_eperm, tc)
{
	struct fixture f;
	struct timespec ts[2];
	struct stat before, after;

	setup(&f, 32);
	ATF_REQUIRE_EQ(0, fstat(f.o->fd, &before));
	FAILS(fchmod(f.o->fd, 0600), EPERM);
	FAILS(fchown(f.o->fd, 1, 1), EPERM);
	ts[0].tv_sec = 1;
	ts[0].tv_nsec = 0;
	ts[1] = ts[0];
	FAILS(futimens(f.o->fd, ts), EPERM);
	FAILS(fchflags(f.o->fd, UF_NODUMP), EPERM);
	/* The identity is untouched. */
	ATF_REQUIRE_EQ(0, fstat(f.o->fd, &after));
	dqt_check_stat_eq(&after, &before);
	teardown(&f);
}

ATF_TC(fsync_ok);
ATF_TC_HEAD(fsync_ok, tc)
{
	atf_tc_set_md_var(tc, "descr", "fsync and fdatasync succeed: nothing "
	    "is dirty on a read-only descriptor");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fsync_ok, tc)
{
	struct fixture f;

	setup(&f, 33);
	ATF_CHECK_EQ(0, fsync(f.o->fd));
	ATF_CHECK_EQ(0, fdatasync(f.o->fd));
	/* fadvise accepts every valid advice as vn_fadvise does on a VREG. */
	ATF_CHECK_EQ(0, posix_fadvise(f.o->fd, 0, 0, POSIX_FADV_SEQUENTIAL));
	ATF_CHECK_EQ(0, posix_fadvise(f.o->fd, 0, 100, POSIX_FADV_DONTNEED));
	ATF_CHECK_EQ(EINVAL, posix_fadvise(f.o->fd, 0, 0, 99));
	teardown(&f);
}

ATF_TC(mmap_enodev);
ATF_TC_HEAD(mmap_enodev, tc)
{
	atf_tc_set_md_var(tc, "descr", "mmap answers ENODEV: the dq pager is "
	    "stage 1b");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mmap_enodev, tc)
{
	struct fixture f;
	void *p;

	setup(&f, 34);
	errno = 0;
	p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, f.o->fd, 0);
	ATF_CHECK_EQ(MAP_FAILED, p);
	ATF_CHECK_EQ(ENODEV, errno);
	errno = 0;
	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, f.o->fd, 0);
	ATF_CHECK_EQ(MAP_FAILED, p);
	ATF_CHECK_EQ(ENODEV, errno);
	teardown(&f);
}

ATF_TC(sendfile_copy_file_range);
ATF_TC_HEAD(sendfile_copy_file_range, tc)
{
	atf_tc_set_md_var(tc, "descr", "sendfile and copy_file_range answer "
	    "EINVAL (invfo_sendfile, default copy_file_range) in stage 1a");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sendfile_copy_file_range, tc)
{
	struct fixture f;
	off_t sbytes;
	int out, sv[2];

	setup(&f, 35);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	sbytes = 0;
	FAILS(sendfile(f.o->fd, sv[0], 0, 100, NULL, &sbytes, 0), EINVAL);
	out = open("copy_out", O_RDWR | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE(out != -1);
	FAILS(copy_file_range(f.o->fd, NULL, out, NULL, 100, 0), EINVAL);
	(void)close(out);
	(void)close(sv[0]);
	(void)close(sv[1]);
	teardown(&f);
}

ATF_TC(acl_extattr);
ATF_TC_HEAD(acl_extattr, tc)
{
	atf_tc_set_md_var(tc, "descr", "ACL and extended attribute calls "
	    "answer EOPNOTSUPP");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(acl_extattr, tc)
{
	struct fixture f;
	acl_t acl;
	char buf[64];

	setup(&f, 36);
	errno = 0;
	acl = acl_get_fd(f.o->fd);
	ATF_CHECK_EQ(NULL, acl);
	ATF_CHECK_EQ(EOPNOTSUPP, errno);
	errno = 0;
	acl = acl_get_fd_np(f.o->fd, ACL_TYPE_NFS4);
	ATF_CHECK_EQ(NULL, acl);
	ATF_CHECK_EQ(EOPNOTSUPP, errno);
	FAILS(acl_delete_fd_np(f.o->fd, ACL_TYPE_ACCESS), EOPNOTSUPP);
	FAILS(extattr_get_fd(f.o->fd, EXTATTR_NAMESPACE_USER, "name", buf,
	    sizeof(buf)), EOPNOTSUPP);
	FAILS(extattr_list_fd(f.o->fd, EXTATTR_NAMESPACE_USER, buf,
	    sizeof(buf)), EOPNOTSUPP);
	FAILS(extattr_delete_fd(f.o->fd, EXTATTR_NAMESPACE_USER, "name"),
	    EOPNOTSUPP);
	teardown(&f);
}

ATF_TC(locks_refused);
ATF_TC_HEAD(locks_refused, tc)
{
	atf_tc_set_md_var(tc, "descr", "fcntl record locks are EBADF and "
	    "flock EOPNOTSUPP: the table lacks DFLAG_RECLOCK and DFLAG_FLOCK "
	    "(stage 0 rule; dp_lock = EVENT posts nothing in 1a)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(locks_refused, tc)
{
	struct fixture f;
	struct flock fl;

	setup(&f, 37);
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	FAILS(fcntl(f.o->fd, F_SETLK, &fl), EBADF);
	FAILS(fcntl(f.o->fd, F_SETLKW, &fl), EBADF);
	FAILS(fcntl(f.o->fd, F_GETLK, &fl), EBADF);
	FAILS(fcntl(f.o->fd, F_OFD_SETLK, &fl), EBADF);
	FAILS(flock(f.o->fd, LOCK_SH | LOCK_NB), EOPNOTSUPP);
	FAILS(flock(f.o->fd, LOCK_UN), EOPNOTSUPP);
	teardown(&f);
}

ATF_TC(fcntl_misc);
ATF_TC_HEAD(fcntl_misc, tc)
{
	atf_tc_set_md_var(tc, "descr", "F_READAHEAD, F_RDAHEAD and "
	    "F_ISUNIONSTACK succeed; the rw-hint commands are not reachable "
	    "from fcntl(2)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fcntl_misc, tc)
{
	struct fixture f;
	uint64_t hint;

	setup(&f, 38);
	SAME(fcntl(f.o->fd, F_READAHEAD, 0), fcntl(f.oracle, F_READAHEAD, 0));
	SAME(fcntl(f.o->fd, F_READAHEAD, 65536),
	    fcntl(f.oracle, F_READAHEAD, 65536));
	SAME(fcntl(f.o->fd, F_RDAHEAD, 1), fcntl(f.oracle, F_RDAHEAD, 1));
	SAME(fcntl(f.o->fd, F_RDAHEAD, 0), fcntl(f.oracle, F_RDAHEAD, 0));
	ATF_CHECK_EQ(0, fcntl(f.o->fd, F_ISUNIONSTACK, 0));
	/*
	 * F_GET_RW_HINT/F_SET_RW_HINT are numbered above every user command
	 * and reached only through the Linux compatibility layer
	 * (sys/sys/fcntl.h); sys_fcntl answers EINVAL for both files.  The
	 * dq answers (0, EPERM) are exercised by Linux fcntl only.
	 */
	hint = 0;
	SAME(fcntl(f.o->fd, DQT_F_GET_RW_HINT, &hint),
	    fcntl(f.oracle, DQT_F_GET_RW_HINT, &hint));
	FAILS(fcntl(f.o->fd, DQT_F_GET_RW_HINT, &hint), EINVAL);
	SAME(fcntl(f.o->fd, DQT_F_SET_RW_HINT, &hint),
	    fcntl(f.oracle, DQT_F_SET_RW_HINT, &hint));
	teardown(&f);
}

ATF_TC(ioctls);
ATF_TC_HEAD(ioctls, tc)
{
	atf_tc_set_md_var(tc, "descr", "FIONREAD, FIONBIO, FIOASYNC and "
	    "FIOSEEKDATA/HOLE are local; FIODTYPE is ENOTTY; FIOBMAP2 is "
	    "EOPNOTSUPP (declared difference)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(ioctls, tc)
{
	struct fixture f;
	struct fiobmap2_arg bm;
	off_t off;
	int on, served_nread, oracle_nread, type;

	setup(&f, 39);
	ATF_REQUIRE_EQ(100, lseek(f.o->fd, 100, SEEK_SET));
	ATF_REQUIRE_EQ(100, lseek(f.oracle, 100, SEEK_SET));
	/* size - f_offset, with the int truncation vn_ioctl applies too. */
	ATF_REQUIRE_EQ(0, ioctl(f.o->fd, FIONREAD, &served_nread));
	ATF_REQUIRE_EQ(0, ioctl(f.oracle, FIONREAD, &oracle_nread));
	ATF_CHECK_EQ(DATA_LEN - 100, served_nread);
	ATF_CHECK_EQ(oracle_nread, served_nread);
	on = 1;
	ATF_CHECK_EQ(0, ioctl(f.o->fd, FIONBIO, &on));
	on = 0;
	ATF_CHECK_EQ(0, ioctl(f.o->fd, FIONBIO, &on));
	ATF_CHECK_EQ(0, ioctl(f.o->fd, FIOASYNC, &on));
	off = 0;
	ATF_CHECK_EQ(0, ioctl(f.o->fd, FIOSEEKDATA, &off));
	ATF_CHECK_EQ(0, off);
	off = 0;
	ATF_CHECK_EQ(0, ioctl(f.o->fd, FIOSEEKHOLE, &off));
	ATF_CHECK_EQ(DATA_LEN, off);
	off = DATA_LEN;
	FAILS(ioctl(f.o->fd, FIOSEEKDATA, &off), ENXIO);
	/* dp_ioctl = DENY: every other ioctl, FIODTYPE included, is ENOTTY. */
	FAILS(ioctl(f.o->fd, FIODTYPE, &type), ENOTTY);
	/* No VOP_BMAP exists to run; a real file answers one (D87). */
	memset(&bm, 0, sizeof(bm));
	FAILS(ioctl(f.o->fd, FIOBMAP2, &bm), EOPNOTSUPP);
	teardown(&f);
}

ATF_TC(poll_select_kqueue);
ATF_TC_HEAD(poll_select_kqueue, tc)
{
	atf_tc_set_md_var(tc, "descr", "poll, select and kqueue READ/WRITE "
	    "answer as for the real file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(poll_select_kqueue, tc)
{
	struct fixture f;
	struct pollfd pfd[2];
	struct kevent kev[2], out[2];
	struct timespec zero = { 0, 0 };
	struct timeval tv;
	fd_set rfds, wfds;
	int kq, n, nfds;

	setup(&f, 40);
	pfd[0].fd = f.o->fd;
	pfd[1].fd = f.oracle;
	pfd[0].events = pfd[1].events =
	    POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM | POLLPRI;
	pfd[0].revents = pfd[1].revents = 0;
	ATF_REQUIRE_EQ(2, poll(pfd, 2, 0));
	/* poll_no_poll: the standard events minus POLLPRI, always ready. */
	ATF_CHECK_EQ(pfd[1].revents, pfd[0].revents);
	ATF_CHECK_EQ(POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM, pfd[0].revents);
	pfd[0].events = (short)0x8000;	/* outside POLLSTANDARD */
	pfd[0].revents = 0;
	ATF_REQUIRE_EQ(1, poll(pfd, 1, 0));
	ATF_CHECK_EQ(POLLNVAL, pfd[0].revents);

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_SET(f.o->fd, &rfds);
	FD_SET(f.o->fd, &wfds);
	FD_SET(f.oracle, &rfds);
	FD_SET(f.oracle, &wfds);
	nfds = MAX(f.o->fd, f.oracle) + 1;
	tv.tv_sec = tv.tv_usec = 0;
	ATF_CHECK_EQ(4, select(nfds, &rfds, &wfds, NULL, &tv));
	ATF_CHECK(FD_ISSET(f.o->fd, &rfds) && FD_ISSET(f.o->fd, &wfds));

	/* EVFILT_READ reports size - offset; EVFILT_WRITE is always ready. */
	ATF_REQUIRE_EQ(100, lseek(f.o->fd, 100, SEEK_SET));
	ATF_REQUIRE_EQ(100, lseek(f.oracle, 100, SEEK_SET));
	kq = kqueue();
	ATF_REQUIRE(kq != -1);
	EV_SET(&kev[0], f.o->fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	EV_SET(&kev[1], f.o->fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, kev, 2, NULL, 0, NULL));
	n = kevent(kq, NULL, 0, out, 2, &zero);
	ATF_REQUIRE_EQ(2, n);
	for (n = 0; n < 2; n++) {
		if (out[n].filter == EVFILT_READ)
			ATF_CHECK_EQ(DATA_LEN - 100, out[n].data);
		else {
			ATF_CHECK_EQ(EVFILT_WRITE, out[n].filter);
			ATF_CHECK_EQ(0, out[n].data);
		}
		ATF_CHECK((out[n].flags & EV_EOF) == 0);
	}
	/* The real file through the same filters. */
	EV_SET(&kev[0], f.o->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	EV_SET(&kev[1], f.o->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, kev, 2, NULL, 0, NULL));
	EV_SET(&kev[0], f.oracle, EVFILT_READ, EV_ADD, 0, 0, NULL);
	EV_SET(&kev[1], f.oracle, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, kev, 2, NULL, 0, NULL));
	n = kevent(kq, NULL, 0, out, 2, &zero);
	ATF_REQUIRE_EQ(2, n);
	for (n = 0; n < 2; n++) {
		if (out[n].filter == EVFILT_READ)
			ATF_CHECK_EQ(DATA_LEN - 100, out[n].data);
		else
			ATF_CHECK_EQ(0, out[n].data);
	}
	/*
	 * At the end of the file the served EVFILT_READ knote is not ready
	 * without NOTE_FILE_POLL and ready with it.  The oracle's knotes are
	 * removed first so only the served knote can answer.
	 */
	EV_SET(&kev[0], f.oracle, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	EV_SET(&kev[1], f.oracle, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, kev, 2, NULL, 0, NULL));
	ATF_REQUIRE_EQ(DATA_LEN, lseek(f.o->fd, 0, SEEK_END));
	EV_SET(&kev[0], f.o->fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, kev, 1, NULL, 0, NULL));
	ATF_CHECK_EQ(0, kevent(kq, NULL, 0, out, 2, &zero));
	EV_SET(&kev[0], f.o->fd, EVFILT_READ, EV_ADD | EV_CLEAR, NOTE_FILE_POLL,
	    0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, kev, 1, NULL, 0, NULL));
	n = kevent(kq, NULL, 0, out, 2, &zero);
	ATF_REQUIRE_EQ(1, n);
	ATF_CHECK_EQ((uintptr_t)f.o->fd, out[0].ident);
	ATF_CHECK_EQ(EVFILT_READ, out[0].filter);
	ATF_CHECK_EQ(0, out[0].data);
	(void)close(kq);
	teardown(&f);
}

ATF_TC(seals_readdir);
ATF_TC_HEAD(seals_readdir, tc)
{
	atf_tc_set_md_var(tc, "descr", "memfd seals answer EINVAL and "
	    "getdirentries ENOTDIR, as for a regular file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(seals_readdir, tc)
{
	struct fixture f;
	char buf[512];
	off_t base;

	setup(&f, 41);
	FAILS(fcntl(f.o->fd, F_ADD_SEALS, F_SEAL_WRITE), EINVAL);
	FAILS(fcntl(f.o->fd, F_GET_SEALS), EINVAL);
	SAME(getdirentries(f.o->fd, buf, sizeof(buf), &base),
	    getdirentries(f.oracle, buf, sizeof(buf), &base));
	/* kern_getdirentries refuses a non-directory before the fileop. */
	FAILS(getdirentries(f.o->fd, buf, sizeof(buf), &base), ENOTDIR);
	teardown(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, write_family);
	ATF_TP_ADD_TC(tp, setattr_eperm);
	ATF_TP_ADD_TC(tp, fsync_ok);
	ATF_TP_ADD_TC(tp, mmap_enodev);
	ATF_TP_ADD_TC(tp, sendfile_copy_file_range);
	ATF_TP_ADD_TC(tp, acl_extattr);
	ATF_TP_ADD_TC(tp, locks_refused);
	ATF_TP_ADD_TC(tp, fcntl_misc);
	ATF_TP_ADD_TC(tp, ioctls);
	ATF_TP_ADD_TC(tp, poll_select_kqueue);
	ATF_TP_ADD_TC(tp, seals_readdir);
	return (atf_no_error());
}
