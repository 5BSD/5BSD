/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Directory reads of a mounted mqueuefs(4): getdirentries(2) and
 * readdir(3) of the root, with no queues of ours and with several, with
 * large and single-entry buffers, read to the end and past it,
 * and after lseek(2).
 *
 * The queue name space is global, so queues that other programs own may
 * be listed too.  The cases therefore make claims only about ".", ".."
 * and the queues they create, whose names start with the case's name.
 */

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	MNTPT		"mnt"
#define	MAXQUEUES	5
#define	MAXENTS		1024
#define	BIGBUF		(64 * 1024)
#define	UID_NOBODY	65534
#define	GID_NOBODY	65534

struct ent {
	char	name[MAXNAMLEN + 1];
	off_t	off;		/* d_off: where the next entry starts */
	size_t	reclen;
	int	type;
};

struct listing {
	size_t		n;
	struct ent	e[MAXENTS];
};

static struct listing l1, l2;
static char bigbuf[BIGBUF];

static void
queue_name(const atf_tc_t *tc, int i, char *name, size_t len)
{
	int n;

	n = snprintf(name, len, "/%s.%d", atf_tc_get_ident(tc), i);
	ATF_REQUIRE(n > 0 && (size_t)n < len);
}

static void
queue_create(const atf_tc_t *tc, int i)
{
	struct mq_attr attr;
	char name[NAME_MAX];
	mqd_t mq;

	queue_name(tc, i, name, sizeof(name));
	memset(&attr, 0, sizeof(attr));
	attr.mq_maxmsg = 1;
	attr.mq_msgsize = 1;
	mq = mq_open(name, O_CREAT | O_EXCL | O_RDWR, 0600, &attr);
	ATF_REQUIRE_MSG(mq != (mqd_t)-1, "mq_open(%s): %s", name,
	    strerror(errno));
	ATF_REQUIRE_EQ(0, mq_close(mq));
}

static void
queue_remove(const atf_tc_t *tc, int i)
{
	char name[NAME_MAX];

	queue_name(tc, i, name, sizeof(name));
	ATF_REQUIRE_MSG(mq_unlink(name) == 0, "mq_unlink(%s): %s", name,
	    strerror(errno));
}

/* Remove whatever an earlier, interrupted run of this case left behind. */
static void
queues_purge(const atf_tc_t *tc)
{
	char name[NAME_MAX];
	int i;

	for (i = 0; i < MAXQUEUES; i++) {
		if (snprintf(name, sizeof(name), "/%s.%d",
		    atf_tc_get_ident(tc), i) < (int)sizeof(name))
			(void)mq_unlink(name);
	}
}

/*
 * Mount mqueuefs on MNTPT and return a descriptor for its root.  A kernel
 * without mqueuefs is a failure, not a skip: this file exists to exercise
 * it.  Where late kldload is refused, load it from the loader.
 */
static int
mqfs_setup(const atf_tc_t *tc)
{
	struct iovec iov[4];
	char fstype[] = "mqueuefs", path[PATH_MAX];
	int fd;

	if (modfind("mqueuefs") == -1 && kldload("mqueuefs") == -1)
		atf_tc_fail("mqueuefs is neither in the kernel nor loadable "
		    "(%s); set mqueuefs_load=\"YES\" in loader.conf",
		    strerror(errno));
	queues_purge(tc);

	ATF_REQUIRE_EQ(0, mkdir(MNTPT, 0755));
	ATF_REQUIRE(realpath(MNTPT, path) != NULL);
	iov[0].iov_base = __DECONST(char *, "fstype");
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = fstype;
	iov[1].iov_len = sizeof(fstype);
	iov[2].iov_base = __DECONST(char *, "fspath");
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = path;
	iov[3].iov_len = strlen(path) + 1;
	ATF_REQUIRE_MSG(nmount(iov, nitems(iov), 0) == 0,
	    "mount mqueuefs on %s: %s", path, strerror(errno));

	fd = open(MNTPT, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE_MSG(fd >= 0, "open(%s): %s", MNTPT, strerror(errno));
	return (fd);
}

/*
 * The end of a case that went well: nothing may still hold the mount, so
 * a plain unmount must succeed.
 */
static void
mqfs_teardown(const atf_tc_t *tc, int fd)
{
	ATF_REQUIRE_EQ(0, close(fd));
	queues_purge(tc);
	ATF_REQUIRE_MSG(unmount(MNTPT, 0) == 0, "unmount: %s",
	    strerror(errno));
}

/* Every other way out of a case, including a failed or timed-out body. */
static void
mqfs_cleanup(const atf_tc_t *tc)
{
	queues_purge(tc);
	(void)unmount(MNTPT, MNT_FORCE);
}

static off_t
tell(int fd)
{
	off_t off;

	off = lseek(fd, 0, SEEK_CUR);
	ATF_REQUIRE(off >= 0);
	return (off);
}

/*
 * One getdirentries(2) call that must succeed.  Check that what came back
 * is a sequence of whole, well-formed entries, append them to *l and
 * return the byte count.
 */
static ssize_t
dir_read(int fd, char *buf, size_t len, struct listing *l)
{
	struct dirent d;
	struct ent *e;
	off_t base, before;
	ssize_t ret;
	size_t left, pos;

	before = tell(fd);
	base = -1;
	ret = getdirentries(fd, buf, len, &base);
	ATF_REQUIRE_MSG(ret >= 0, "getdirentries(%zu bytes) at %jd: %s", len,
	    (intmax_t)before, strerror(errno));
	ATF_REQUIRE((size_t)ret <= len);
	ATF_REQUIRE_EQ(before, base);

	e = NULL;
	for (pos = 0; pos < (size_t)ret; pos += d.d_reclen) {
		left = (size_t)ret - pos;
		ATF_REQUIRE(left >= offsetof(struct dirent, d_name));
		memset(&d, 0, sizeof(d));
		memcpy(&d, buf + pos, MIN(left, sizeof(d)));
		ATF_REQUIRE(d.d_reclen <= left);
		ATF_REQUIRE(d.d_reclen <= sizeof(d));
		ATF_REQUIRE(d.d_namlen > 0);
		ATF_REQUIRE(d.d_reclen >= _GENERIC_DIRLEN(d.d_namlen));
		ATF_REQUIRE_EQ(d.d_namlen, strnlen(d.d_name, d.d_namlen + 1));
		ATF_REQUIRE(d.d_fileno != 0);

		ATF_REQUIRE(l->n < MAXENTS);
		e = &l->e[l->n++];
		memcpy(e->name, d.d_name, d.d_namlen + 1);
		e->off = d.d_off;
		e->reclen = d.d_reclen;
		e->type = d.d_type;
	}
	ATF_REQUIRE_EQ((size_t)ret, pos);
	/* The file offset is where the entry after the last one starts. */
	if (e != NULL)
		ATF_REQUIRE_EQ(e->off, tell(fd));
	return (ret);
}

/*
 * Read from the current offset to the end with a buffer of len bytes,
 * which must be large enough for any one entry, and check that the end
 * is reported again and again without moving the offset.
 */
static void
dir_list(int fd, size_t len, struct listing *l)
{
	off_t end;
	int i;

	ATF_REQUIRE(len >= sizeof(struct dirent) && len <= sizeof(bigbuf));
	l->n = 0;
	for (i = 0; dir_read(fd, bigbuf, len, l) > 0; i++)
		ATF_REQUIRE(i < MAXENTS);
	end = tell(fd);
	for (i = 0; i < 3; i++) {
		ATF_REQUIRE_EQ(0, dir_read(fd, bigbuf, len, l));
		ATF_REQUIRE_EQ(end, tell(fd));
	}
}

static const struct ent *
dir_find(const struct listing *l, const char *name, int *countp)
{
	const struct ent *e;
	size_t i;

	e = NULL;
	*countp = 0;
	for (i = 0; i < l->n; i++) {
		if (strcmp(l->e[i].name, name) == 0) {
			if (e == NULL)
				e = &l->e[i];
			(*countp)++;
		}
	}
	return (e);
}

/* "." and ".." are listed once each, as directories. */
static void
check_dots(const struct listing *l)
{
	const struct ent *e;
	int count;

	e = dir_find(l, ".", &count);
	ATF_REQUIRE_EQ(1, count);
	ATF_REQUIRE_EQ(DT_DIR, e->type);
	e = dir_find(l, "..", &count);
	ATF_REQUIRE_EQ(1, count);
	ATF_REQUIRE_EQ(DT_DIR, e->type);
}

/* Queue i of this case is listed once as a regular file, or not at all. */
static void
check_queue(const atf_tc_t *tc, const struct listing *l, int i, bool present)
{
	const struct ent *e;
	char name[NAME_MAX];
	int count;

	queue_name(tc, i, name, sizeof(name));
	e = dir_find(l, name + 1, &count);
	ATF_REQUIRE_EQ_MSG(present ? 1 : 0, count, "%s listed %d times", name,
	    count);
	if (present)
		ATF_REQUIRE_EQ(DT_REG, e->type);
}

static void
check_all(const atf_tc_t *tc, const struct listing *l, int nqueues)
{
	int i;

	check_dots(l);
	for (i = 0; i < MAXQUEUES; i++)
		check_queue(tc, l, i, i < nqueues);
}

static void
rewind_dir(int fd)
{
	ATF_REQUIRE_EQ(0, lseek(fd, 0, SEEK_SET));
}

ATF_TC_WITH_CLEANUP(empty);
ATF_TC_HEAD(empty, tc)
{
	atf_tc_set_md_var(tc, "descr", "Read a root directory that holds "
	    "none of our queues to its end, and past it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(empty, tc)
{
	struct stat sb;
	int fd;

	fd = mqfs_setup(tc);
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_REQUIRE(S_ISDIR(sb.st_mode));

	dir_list(fd, sizeof(bigbuf), &l1);
	check_all(tc, &l1, 0);

	/* Again from the start, on the same descriptor and on a new one. */
	rewind_dir(fd);
	dir_list(fd, sizeof(bigbuf), &l1);
	check_all(tc, &l1, 0);
	ATF_REQUIRE_EQ(0, close(fd));
	fd = open(MNTPT, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	dir_list(fd, sizeof(bigbuf), &l1);
	check_all(tc, &l1, 0);

	mqfs_teardown(tc, fd);
}
ATF_TC_CLEANUP(empty, tc)
{
	mqfs_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(queues);
ATF_TC_HEAD(queues, tc)
{
	atf_tc_set_md_var(tc, "descr", "Queues appear in and disappear from "
	    "the listing of an open root directory");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(queues, tc)
{
	int fd, i;

	fd = mqfs_setup(tc);
	for (i = 0; i < MAXQUEUES; i++)
		queue_create(tc, i);
	dir_list(fd, sizeof(bigbuf), &l1);
	check_all(tc, &l1, MAXQUEUES);

	queue_remove(tc, 1);
	queue_remove(tc, 3);
	rewind_dir(fd);
	dir_list(fd, sizeof(bigbuf), &l1);
	check_dots(&l1);
	for (i = 0; i < MAXQUEUES; i++)
		check_queue(tc, &l1, i, i % 2 == 0);

	queue_create(tc, 3);
	rewind_dir(fd);
	dir_list(fd, sizeof(bigbuf), &l1);
	check_dots(&l1);
	for (i = 0; i < MAXQUEUES; i++)
		check_queue(tc, &l1, i, i != 1);

	mqfs_teardown(tc, fd);
}
ATF_TC_CLEANUP(queues, tc)
{
	mqfs_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(buffer_sizes);
ATF_TC_HEAD(buffer_sizes, tc)
{
	atf_tc_set_md_var(tc, "descr", "The listing does not depend on the "
	    "buffer size, down to a buffer for one entry");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(buffer_sizes, tc)
{
	static const size_t sizes[] = {
		sizeof(struct dirent),
		sizeof(struct dirent) + 1,
		2 * sizeof(struct dirent) + sizeof(struct dirent) / 2,
		4096,
	};
	size_t i, j;
	int fd, q;

	fd = mqfs_setup(tc);
	for (q = 0; q < MAXQUEUES; q++)
		queue_create(tc, q);
	dir_list(fd, sizeof(bigbuf), &l1);
	check_all(tc, &l1, MAXQUEUES);

	for (i = 0; i < nitems(sizes); i++) {
		rewind_dir(fd);
		dir_list(fd, sizes[i], &l2);
		check_all(tc, &l2, MAXQUEUES);
		/* The same entries, in the same order, at the same offsets. */
		ATF_REQUIRE_EQ_MSG(l1.n, l2.n, "%zu entries with %zu bytes, "
		    "%zu with %zu", l1.n, sizeof(bigbuf), l2.n, sizes[i]);
		for (j = 0; j < l1.n; j++) {
			ATF_REQUIRE_STREQ(l1.e[j].name, l2.e[j].name);
			ATF_REQUIRE_EQ(l1.e[j].off, l2.e[j].off);
		}
	}

	mqfs_teardown(tc, fd);
}
ATF_TC_CLEANUP(buffer_sizes, tc)
{
	mqfs_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(seek);
ATF_TC_HEAD(seek, tc)
{
	atf_tc_set_md_var(tc, "descr", "lseek(2) to an entry's d_off resumes "
	    "with the entry after it; the end and beyond read as the end");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(seek, tc)
{
	off_t end;
	size_t i, j;
	int fd, q;

	fd = mqfs_setup(tc);
	for (q = 0; q < MAXQUEUES; q++)
		queue_create(tc, q);
	dir_list(fd, sizeof(bigbuf), &l1);
	check_all(tc, &l1, MAXQUEUES);
	end = l1.e[l1.n - 1].off;
	ATF_REQUIRE_EQ(end, tell(fd));

	/* Backwards, so that every seek but the first moves toward 0. */
	for (i = l1.n; i-- > 0;) {
		ATF_REQUIRE_EQ(l1.e[i].off, lseek(fd, l1.e[i].off, SEEK_SET));
		dir_list(fd, sizeof(bigbuf), &l2);
		ATF_REQUIRE_EQ(l1.n - i - 1, l2.n);
		for (j = 0; j < l2.n; j++)
			ATF_REQUIRE_STREQ(l1.e[i + 1 + j].name, l2.e[j].name);
		ATF_REQUIRE_EQ(end, tell(fd));
	}

	/* Past the end there is nothing, however often it is asked for. */
	for (i = 0; i < 3; i++) {
		ATF_REQUIRE_EQ(end + 1000000,
		    lseek(fd, end + 1000000, SEEK_SET));
		ATF_REQUIRE_EQ(0, getdirentries(fd, bigbuf, sizeof(bigbuf),
		    NULL));
		ATF_REQUIRE_EQ(0, getdirentries(fd, bigbuf,
		    sizeof(struct dirent), NULL));
	}

	/* And the whole directory is still there from the start. */
	rewind_dir(fd);
	dir_list(fd, sizeof(bigbuf), &l2);
	check_all(tc, &l2, MAXQUEUES);
	ATF_REQUIRE_EQ(l1.n, l2.n);

	mqfs_teardown(tc, fd);
}
ATF_TC_CLEANUP(seek, tc)
{
	mqfs_cleanup(tc);
}

/* Count our queues and the dot entries with readdir(3), to the end. */
static void
libc_list(DIR *dirp, const atf_tc_t *tc, int *dotsp, int *queuesp)
{
	struct dirent *d;
	size_t len;
	int i;

	*dotsp = *queuesp = 0;
	len = strlen(atf_tc_get_ident(tc));
	for (i = 0;; i++) {
		ATF_REQUIRE(i < MAXENTS);
		errno = 0;
		d = readdir(dirp);
		if (d == NULL)
			break;
		if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
			(*dotsp)++;
		else if (strncmp(d->d_name, atf_tc_get_ident(tc), len) == 0 &&
		    d->d_name[len] == '.')
			(*queuesp)++;
	}
	ATF_REQUIRE_EQ_MSG(0, errno, "readdir: %s", strerror(errno));
	/* Still the end when asked again. */
	ATF_REQUIRE(readdir(dirp) == NULL);
	ATF_REQUIRE_EQ(0, errno);
}

ATF_TC_WITH_CLEANUP(libc_readdir);
ATF_TC_HEAD(libc_readdir, tc)
{
	atf_tc_set_md_var(tc, "descr", "opendir(3), readdir(3) to the end, "
	    "rewinddir(3) and seekdir(3), as ls(1) reads a directory");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(libc_readdir, tc)
{
	DIR *dirp;
	long pos;
	int dots, fd, q, queues;

	fd = mqfs_setup(tc);
	dirp = fdopendir(fd);
	ATF_REQUIRE(dirp != NULL);
	libc_list(dirp, tc, &dots, &queues);
	ATF_REQUIRE_EQ(2, dots);
	ATF_REQUIRE_EQ(0, queues);

	for (q = 0; q < MAXQUEUES; q++)
		queue_create(tc, q);
	rewinddir(dirp);
	pos = telldir(dirp);
	libc_list(dirp, tc, &dots, &queues);
	ATF_REQUIRE_EQ(2, dots);
	ATF_REQUIRE_EQ(MAXQUEUES, queues);

	seekdir(dirp, pos);
	libc_list(dirp, tc, &dots, &queues);
	ATF_REQUIRE_EQ(2, dots);
	ATF_REQUIRE_EQ(MAXQUEUES, queues);

	/* closedir(3) closes fd. */
	ATF_REQUIRE_EQ(0, closedir(dirp));
	queues_purge(tc);
	ATF_REQUIRE_MSG(unmount(MNTPT, 0) == 0, "unmount: %s",
	    strerror(errno));
}
ATF_TC_CLEANUP(libc_readdir, tc)
{
	mqfs_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(unprivileged);
ATF_TC_HEAD(unprivileged, tc)
{
	atf_tc_set_md_var(tc, "descr", "A process with no privilege opens "
	    "the root directory and reads it to its end");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(unprivileged, tc)
{
	gid_t gid;
	pid_t pid;
	ssize_t ret;
	int fd, fd2, i, status;

	fd = mqfs_setup(tc);
	queue_create(tc, 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		/*
		 * The mount point sits in a directory that only root can
		 * search, so reach the root through the inherited
		 * descriptor; the open itself is checked against the new
		 * credentials.
		 */
		gid = GID_NOBODY;
		if (setgroups(1, &gid) != 0 || setgid(GID_NOBODY) != 0 ||
		    setuid(UID_NOBODY) != 0)
			_exit(10);
		fd2 = openat(fd, ".", O_RDONLY | O_DIRECTORY);
		if (fd2 < 0)
			_exit(11);
		for (i = 0; i < MAXENTS; i++) {
			ret = getdirentries(fd2, bigbuf, sizeof(bigbuf), NULL);
			if (ret < 0)
				_exit(12);
			if (ret == 0)
				break;
		}
		if (i == 0 || i == MAXENTS)
			_exit(13);
		if (getdirentries(fd2, bigbuf, sizeof(bigbuf), NULL) != 0)
			_exit(14);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child status %#x", status);

	mqfs_teardown(tc, fd);
}
ATF_TC_CLEANUP(unprivileged, tc)
{
	mqfs_cleanup(tc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, empty);
	ATF_TP_ADD_TC(tp, queues);
	ATF_TP_ADD_TC(tp, buffer_sizes);
	ATF_TP_ADD_TC(tp, seek);
	ATF_TP_ADD_TC(tp, libc_readdir);
	ATF_TP_ADD_TC(tp, unprivileged);
	return (atf_no_error());
}
