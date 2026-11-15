/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The read-only object (D87, as amended by stage 1b-i): a descriptor minted
 * without DQ_MINT_F_WRITE answers every mutating data operation exactly as
 * a read-only descriptor on a real file does, or the declared value.  None
 * of these posts an event (the generic layer or the local fileop answers),
 * so they run in the controller process; the oracle is a read-only
 * descriptor on the real file wherever the answer is the generic layer's.
 * What stage 1b-i moved: locks are LOCK events (dq_lock_test), the
 * attribute calls post SETATTR after the kernel's own refusals
 * (dq_setattr_test; the local refusals stay pinned here), and a writable
 * object serves every write-side operation (writable_served below).
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
	dqt_lock(&f->c);
	ATF_CHECK_EQ(0, f->c.records);
	dqt_unlock(&f->c);
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

#define	NOBODY_UID	65534
#define	NOBODY_GID	65534

struct setattr_res {
	struct dqt_rr	 setuid_bit, setgid_bit;	/* as root, the owner */
	struct dqt_rr	 chmod, chown, utimens, chflags, sfflags;
};

/*
 * As root and owner, set-id bits (the identity rule, I3); then as an
 * unprivileged non-owner (uid nobody against an identity owned by
 * root), and as the owner (uid nobody against the second object, owned by
 * nobody) trying a system flag: refused by the kernel, no event.
 */
static void
child_setattr_unpriv(void *arg, void *result)
{
	int *fds = arg;
	struct setattr_res *r = result;
	struct timespec ts[2];

	/* Root, the owner: only the identity rule refuses (I3). */
	r->setuid_bit.rv = fchmod(fds[0], 04644);
	r->setuid_bit.err = r->setuid_bit.rv == -1 ? errno : 0;
	r->setgid_bit.rv = fchmod(fds[0], 02644);
	r->setgid_bit.err = r->setgid_bit.rv == -1 ? errno : 0;
	if (setgroups(0, NULL) != 0 || setgid(NOBODY_GID) != 0 ||
	    setuid(NOBODY_UID) != 0)
		_exit(2);
	r->chmod.rv = fchmod(fds[0], 0600);
	r->chmod.err = r->chmod.rv == -1 ? errno : 0;
	r->chown.rv = fchown(fds[0], NOBODY_UID, -1);
	r->chown.err = r->chown.rv == -1 ? errno : 0;
	ts[0].tv_sec = 1;
	ts[0].tv_nsec = 0;
	ts[1] = ts[0];
	r->utimens.rv = futimens(fds[0], ts);
	r->utimens.err = r->utimens.rv == -1 ? errno : 0;
	r->chflags.rv = fchflags(fds[0], UF_NODUMP);
	r->chflags.err = r->chflags.rv == -1 ? errno : 0;
	r->sfflags.rv = fchflags(fds[1], SF_ARCHIVED);
	r->sfflags.err = r->sfflags.rv == -1 ? errno : 0;
}

ATF_TC(setattr_local_refusals);
ATF_TC_HEAD(setattr_local_refusals, tc)
{
	atf_tc_set_md_var(tc, "descr", "the attribute calls the kernel refuses "
	    "before any SETATTR: set-id bits (EPERM, I3), a non-owner without "
	    "privilege (EPERM), a system flag without privilege (EPERM); "
	    "served SETATTR is dq_setattr_test's");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setattr_local_refusals, tc)
{
	struct fixture f;
	struct dqt_object *mine;
	struct dq_ident_file *id;
	struct dq_policy pol;
	struct setattr_res r;
	struct stat before, after;
	int fds[2];

	setup(&f, 32);
	ATF_REQUIRE_EQ(0, fstat(f.o->fd, &before));
	/* A second object of the same bytes owned by nobody. */
	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(id != NULL);
	*id = f.o->ident;
	id->di_uid = NOBODY_UID;
	id->di_gid = NOBODY_GID;
	dq_policy_default(&pol);
	mine = dqt_mint_ident(&f.c, id, &pol, data, sizeof(data));
	free(id);
	(void)mine;
	fds[0] = f.o->fd;
	fds[1] = f.c.objs[1].fd;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_setattr_unpriv, fds, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.chmod.rv);
	ATF_CHECK_EQ(EPERM, r.chmod.err);
	ATF_CHECK_EQ(-1, r.chown.rv);
	ATF_CHECK_EQ(EPERM, r.chown.err);
	ATF_CHECK_EQ(-1, r.utimens.rv);
	ATF_CHECK_EQ(EPERM, r.utimens.err);
	ATF_CHECK_EQ(-1, r.chflags.rv);
	ATF_CHECK_EQ(EPERM, r.chflags.err);
	ATF_CHECK_EQ(-1, r.sfflags.rv);
	ATF_CHECK_EQ(EPERM, r.sfflags.err);
	ATF_CHECK_EQ(-1, r.setuid_bit.rv);
	ATF_CHECK_EQ(EPERM, r.setuid_bit.err);
	ATF_CHECK_EQ(-1, r.setgid_bit.rv);
	ATF_CHECK_EQ(EPERM, r.setgid_bit.err);
	/* The identity is untouched and nothing was posted. */
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

ATF_TC(mmap_readonly_rules);
ATF_TC_HEAD(mmap_readonly_rules, tc)
{
	atf_tc_set_md_var(tc, "descr", "a read-only object maps as a "
	    "read-only real file does: MAP_PRIVATE (even PROT_WRITE, copy on "
	    "write) and shared PROT_READ succeed, shared PROT_WRITE is EACCES; "
	    "mapping posts nothing (pages come at the first fault, "
	    "dq_mmap_test)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mmap_readonly_rules, tc)
{
	struct fixture f;
	void *p, *q;

	setup(&f, 34);
#define	MAPS_SAME(prot, flags) do {					\
	errno = 0;							\
	p = mmap(NULL, 4096, (prot), (flags), f.o->fd, 0);		\
	int _pe = p == MAP_FAILED ? errno : 0;				\
	errno = 0;							\
	q = mmap(NULL, 4096, (prot), (flags), f.oracle, 0);		\
	int _qe = q == MAP_FAILED ? errno : 0;				\
	ATF_CHECK_EQ_MSG(q == MAP_FAILED, p == MAP_FAILED,		\
	    "%s %s: served %d oracle %d", #prot, #flags, _pe, _qe);	\
	ATF_CHECK_EQ_MSG(_qe, _pe, "%s %s: errno served %d oracle %d",	\
	    #prot, #flags, _pe, _qe);					\
	if (p != MAP_FAILED)						\
		(void)munmap(p, 4096);					\
	if (q != MAP_FAILED)						\
		(void)munmap(q, 4096);					\
} while (0)
	MAPS_SAME(PROT_READ, MAP_PRIVATE);
	MAPS_SAME(PROT_READ | PROT_WRITE, MAP_PRIVATE);
	MAPS_SAME(PROT_READ, MAP_SHARED);
	MAPS_SAME(PROT_READ | PROT_WRITE, MAP_SHARED);
#undef MAPS_SAME
	errno = 0;
	p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, f.o->fd, 0);
	ATF_CHECK_EQ(MAP_FAILED, p);
	ATF_CHECK_EQ(EACCES, errno);
	teardown(&f);
}

ATF_TC(copy_file_range_einval);
ATF_TC_HEAD(copy_file_range_einval, tc)
{
	atf_tc_set_md_var(tc, "descr", "copy_file_range answers EINVAL (the "
	    "default; no vnode to copy between); sendfile is served "
	    "(dq_sendfile_test)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(copy_file_range_einval, tc)
{
	struct fixture f;
	int out;

	setup(&f, 35);
	out = open("copy_out", O_RDWR | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE(out != -1);
	FAILS(copy_file_range(f.o->fd, NULL, out, NULL, 100, 0), EINVAL);
	(void)close(out);
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

struct lock_res {
	struct dqt_rr	 rd, fl;
};

static void
child_read_locks(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct lock_res *r = result;
	struct flock fl;

	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	r->rd.rv = fcntl(fd, F_SETLK, &fl);
	r->rd.err = r->rd.rv == -1 ? errno : 0;
	r->fl.rv = flock(fd, LOCK_SH | LOCK_NB);
	r->fl.err = r->fl.rv == -1 ? errno : 0;
}

ATF_TC(locks_are_events);
ATF_TC_HEAD(locks_are_events, tc)
{
	atf_tc_set_md_var(tc, "descr", "on a read-only object a write lock is "
	    "the generic layer's EBADF, as on a read-only real file, and a read "
	    "lock or flock is a LOCK event the controller answers (the table "
	    "has DFLAG_RECLOCK|DFLAG_FLOCK since 1b-i; dq_lock_test has the "
	    "rest)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(locks_are_events, tc)
{
	struct fixture f;
	struct lock_res r;
	struct flock fl;

	setup(&f, 37);
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	SAME(fcntl(f.o->fd, F_SETLK, &fl), fcntl(f.oracle, F_SETLK, &fl));
	FAILS(fcntl(f.o->fd, F_SETLK, &fl), EBADF);
	dqt_lock(&f.c);
	ATF_CHECK_EQ(0, f.c.records);
	dqt_unlock(&f.c);
	/* The controller refuses; the requester sees its word. */
	f.o->serve_errno = EAGAIN;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_read_locks, &f.o->fd, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.rd.rv);
	ATF_CHECK_EQ(EAGAIN, r.rd.err);
	ATF_CHECK_EQ(-1, r.fl.rv);
	/* flock(2) reports a conflict as EWOULDBLOCK, which is EAGAIN. */
	ATF_CHECK_EQ(EAGAIN, r.fl.err);
	ATF_CHECK(dqt_wait_events(&f.c, DQ_OP_LOCK, 2, DQT_WAIT_MS));
	dqt_lock(&f.c);
	ATF_REQUIRE_EQ(2, f.o->nlocks);
	ATF_CHECK_EQ(DQ_LOCK_POSIX, f.o->locks[0].dl_kind);
	ATF_CHECK_EQ(DQ_LOCK_SETLK, f.o->locks[0].dl_op);
	ATF_CHECK_EQ(F_RDLCK, f.o->locks[0].dl_type);
	ATF_CHECK_EQ(DQ_LOCK_FLOCK, f.o->locks[1].dl_kind);
	dqt_unlock(&f.c);
	dqt_fini(&f.c);
	(void)close(f.oracle);
}

struct served_res {
	struct dqt_rr	 write, pwrite, writev, ftruncate, fallocate, fspacectl;
	struct dqt_rr	 fsync, fdatasync, fchmod, futimens;
	struct stat	 st;
};

static void
child_writable(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct served_res *r = result;
	struct spacectl_range rqsr;
	struct iovec iov;
	struct timespec ts[2];
	char buf[16];
	int e;

#define	RR(field, expr) do {						\
	r->field.rv = (long)(expr);					\
	r->field.err = r->field.rv == -1 ? errno : 0;			\
} while (0)
	memset(buf, 'w', sizeof(buf));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	RR(write, write(fd, buf, sizeof(buf)));
	RR(pwrite, pwrite(fd, buf, sizeof(buf), 100));
	RR(writev, writev(fd, &iov, 1));
	RR(ftruncate, ftruncate(fd, 4096));
	e = posix_fallocate(fd, 0, 8192);
	r->fallocate.rv = e == 0 ? 0 : -1;
	r->fallocate.err = e;
	rqsr.r_offset = 0;
	rqsr.r_len = 512;
	RR(fspacectl, fspacectl(fd, SPACECTL_DEALLOC, &rqsr, 0, NULL));
	RR(fsync, fsync(fd));
	RR(fdatasync, fdatasync(fd));
	RR(fchmod, fchmod(fd, 0640));
	ts[0].tv_sec = 1000000;
	ts[0].tv_nsec = 0;
	ts[1] = ts[0];
	RR(futimens, futimens(fd, ts));
	(void)fstat(fd, &r->st);
#undef RR
}

ATF_TC(writable_served);
ATF_TC_HEAD(writable_served, tc)
{
	atf_tc_set_md_var(tc, "descr", "the D87 pins move: on an object minted "
	    "DQ_MINT_F_WRITE under dp_write = DQ_EVENT, write, pwrite, writev, "
	    "ftruncate, posix_fallocate, fspacectl, fsync, fdatasync, fchmod "
	    "and futimens are served events");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(writable_served, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct served_res r;
	struct stat bst;
	int backing, fd;

	dqt_fill(data, sizeof(data), 42);
	backing = dqt_make_oracle("backing", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	(void)close(backing);
	backing = open(oracle_path, O_RDWR);
	ATF_REQUIRE(backing != -1);
	dqt_init(&c);
	o = dqt_mint_backing(&c, backing, oracle_path, NULL, DQ_MINT_F_WRITE);
	ATF_CHECK_EQ(O_RDWR, fcntl(o->fd, F_GETFL) & O_ACCMODE);
	fd = o->fd;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_writable, &fd, &r, sizeof(r));
	ATF_CHECK_EQ(16, r.write.rv);
	ATF_CHECK_EQ(16, r.pwrite.rv);
	ATF_CHECK_EQ(16, r.writev.rv);
	ATF_CHECK_EQ_MSG(0, r.ftruncate.rv, "ftruncate: %s",
	    strerror(r.ftruncate.err));
	/* A filesystem without fallocate answers EINVAL/EOPNOTSUPP: the oracle's. */
	if (r.fallocate.rv != 0)
		ATF_CHECK_EQ(posix_fallocate(backing, 0, 8192), r.fallocate.err);
	if (r.fspacectl.rv != 0) {
		struct spacectl_range rq = { 0, 512 };

		errno = 0;
		(void)fspacectl(backing, SPACECTL_DEALLOC, &rq, 0, NULL);
		ATF_CHECK_EQ(errno, r.fspacectl.err);
	}
	ATF_CHECK_EQ(0, r.fsync.rv);
	ATF_CHECK_EQ(0, r.fdatasync.rv);
	ATF_CHECK_EQ(0, r.fchmod.rv);
	ATF_CHECK_EQ(0, r.futimens.rv);
	ATF_CHECK(dqt_wait_events(&c, DQ_OP_WRITE, 3, DQT_WAIT_MS));
	dqt_lock(&c);
	ATF_CHECK_EQ(3, c.events[DQ_OP_WRITE]);
	ATF_CHECK(c.events[DQ_OP_SETATTR] >= 3);
	ATF_CHECK_EQ(2, c.events[DQ_OP_FSYNC]);
	ATF_CHECK_EQ(1, c.events[DQ_OP_FALLOCATE]);
	ATF_CHECK_EQ(1, c.events[DQ_OP_FSPACECTL]);
	ATF_CHECK_EQ(0, c.reply_failures);
	dqt_unlock(&c);
	/* The backing file has what the requester wrote, and the served mode. */
	ATF_REQUIRE_EQ(0, fstat(backing, &bst));
	ATF_CHECK_EQ(0640, bst.st_mode & ALLPERMS);
	ATF_CHECK_EQ(0640, r.st.st_mode & ALLPERMS);
	ATF_CHECK_EQ(bst.st_size, r.st.st_size);
	ATF_CHECK_EQ(1000000, r.st.st_mtim.tv_sec);
	dqt_fini(&c);
	(void)close(backing);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, write_family);
	ATF_TP_ADD_TC(tp, setattr_local_refusals);
	ATF_TP_ADD_TC(tp, fsync_ok);
	ATF_TP_ADD_TC(tp, mmap_readonly_rules);
	ATF_TP_ADD_TC(tp, copy_file_range_einval);
	ATF_TP_ADD_TC(tp, acl_extattr);
	ATF_TP_ADD_TC(tp, locks_are_events);
	ATF_TP_ADD_TC(tp, writable_served);
	ATF_TP_ADD_TC(tp, fcntl_misc);
	ATF_TP_ADD_TC(tp, ioctls);
	ATF_TP_ADD_TC(tp, poll_select_kqueue);
	ATF_TP_ADD_TC(tp, seals_readdir);
	return (atf_no_error());
}
