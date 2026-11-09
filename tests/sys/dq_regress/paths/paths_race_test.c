/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Races against path lookups.
 *
 * What it tries to break: the stage-1c wrappers and namei hooks add work
 * (and, for attached processes, sleeps) around every lookup, and the
 * start-directory code changed.  For an unattached process every outcome
 * must stay within the set the 3f330ee172d kernel allows, with no crash,
 * no hang and no leaked state:
 *  - a sibling thread rewrites the path buffer during the call (copyinstr
 *    takes one snapshot: the result names one of the possible strings);
 *  - a thread renames or unlinks a component during the lookup;
 *  - a thread closes, dup2()s and reopens the directory descriptor number
 *    during *at calls;
 *  - signals arrive during a blocking FIFO open, without SA_RESTART
 *    (EINTR) and with it (restarted, completes when a writer comes);
 *  - ftruncate, chmod and rename storms against stat.
 * Every loop is bounded by time and count, and alarm(2) turns a hang into
 * a failure.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>

#include "paths_common.h"

#define	RUN_SECONDS	2
#define	MAX_ITERS	200000
#define	HANG_ALARM	60

static atomic_bool stop;

static double
now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((double)ts.tv_sec + (double)ts.tv_nsec / 1e9);
}

/* Loop control for the main thread: bounded by time and count. */
static bool
keep_going(double start, int iter)
{

	return (iter < MAX_ITERS && now_s() - start < RUN_SECONDS);
}

static pthread_t
spawn(void *(*fn)(void *), void *arg)
{
	pthread_t t;

	atomic_store(&stop, false);
	ATF_REQUIRE(pthread_create(&t, NULL, fn, arg) == 0);
	return (t);
}

static void
finish(pthread_t t)
{

	atomic_store(&stop, true);
	ATF_REQUIRE(pthread_join(t, NULL) == 0);
}

static bool
in_set(ino_t ino, const ino_t *set, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (set[i] == ino)
			return (true);
	return (false);
}

/* ---- path buffer rewritten during the call ---- */

static char pathbuf[64];

struct flip {
	size_t	 pos;
	char	 a, b;
};

static void *
flipper(void *arg)
{
	const struct flip *f = arg;
	volatile char *p = (volatile char *)pathbuf;

	while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
		p[f->pos] = f->a;
		p[f->pos] = f->b;
	}
	p[f->pos] = f->a;
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(path_buffer_rewrite);
ATF_TC_BODY(path_buffer_rewrite, tc)
{
	static const struct flip dirbyte = { 1, 'A', 'B' };
	static const struct flip nulbyte = { 2, '/', '\0' };
	static const struct flip missing = { 1, 'A', 'C' };
	struct stat sb;
	ino_t set[4];
	pthread_t t;
	double start;
	int iter, fd, e, okA, okB;

	alarm(HANG_ALARM);
	pc_mkdir("dA");
	pc_mkdir("dB");
	pc_mkfile("dA/f", "A\n");
	pc_mkfile("dB/f", "B\n");
	set[0] = pc_ino("dA/f", true);
	set[1] = pc_ino("dB/f", true);
	set[2] = pc_ino("dA", true);
	set[3] = pc_ino("dB", true);

	/* One byte flips between two existing directories. */
	strlcpy(pathbuf, "dA/f", sizeof(pathbuf));
	t = spawn(flipper, __DECONST(void *, &dirbyte));
	okA = okB = 0;
	for (start = now_s(), iter = 0; keep_going(start, iter); iter++) {
		e = ERRNO_OF(stat(pathbuf, &sb));
		ATF_CHECK_MSG(e == 0, "stat: %s", strerror(e));
		if (e == 0) {
			ATF_CHECK(in_set(sb.st_ino, set, 2));
			okA += sb.st_ino == set[0];
			okB += sb.st_ino == set[1];
		}
		fd = open(pathbuf, O_RDONLY);
		ATF_CHECK(fd >= 0);
		if (fd >= 0) {
			ATF_CHECK(fstat(fd, &sb) == 0 &&
			    in_set(sb.st_ino, set, 2));
			close(fd);
		}
	}
	finish(t);
	printf("dir flip: %d A, %d B\n", okA, okB);

	/* The separator flips with a NUL: "dA" or "dA/f". */
	strlcpy(pathbuf, "dA/f", sizeof(pathbuf));
	t = spawn(flipper, __DECONST(void *, &nulbyte));
	for (start = now_s(), iter = 0; keep_going(start, iter); iter++) {
		e = ERRNO_OF(lstat(pathbuf, &sb));
		ATF_CHECK_MSG(e == 0, "lstat: %s", strerror(e));
		if (e == 0)
			ATF_CHECK(sb.st_ino == set[0] || sb.st_ino == set[2]);
		e = ERRNO_OF(access(pathbuf, R_OK));
		ATF_CHECK_MSG(e == 0, "access: %s", strerror(e));
	}
	finish(t);

	/* One of the two names does not exist: success or ENOENT only. */
	strlcpy(pathbuf, "dA/f", sizeof(pathbuf));
	t = spawn(flipper, __DECONST(void *, &missing));
	for (start = now_s(), iter = 0; keep_going(start, iter); iter++) {
		e = ERRNO_OF(stat(pathbuf, &sb));
		ATF_CHECK_MSG(e == 0 || e == ENOENT, "stat: %s", strerror(e));
		if (e == 0)
			ATF_CHECK(sb.st_ino == set[0]);
		e = ERRNO_OF(chmod(pathbuf, 0644));
		ATF_CHECK_MSG(e == 0 || e == ENOENT, "chmod: %s", strerror(e));
	}
	finish(t);

	/* Creating calls: only the two candidate names ever appear. */
	strlcpy(pathbuf, "nA", sizeof(pathbuf));
	{
		static const struct flip newbyte = { 1, 'A', 'B' };

		t = spawn(flipper, __DECONST(void *, &newbyte));
		for (start = now_s(), iter = 0; keep_going(start, iter) &&
		    iter < 2000; iter++) {
			e = ERRNO_OF(mkdir(pathbuf, 0755));
			ATF_CHECK_MSG(e == 0 || e == EEXIST, "mkdir: %s",
			    strerror(e));
			e = ERRNO_OF(rmdir(pathbuf));
			ATF_CHECK_MSG(e == 0 || e == ENOENT, "rmdir: %s",
			    strerror(e));
		}
		finish(t);
	}
	(void)rmdir("nA");
	(void)rmdir("nB");
	/* dA, dB and nothing else. */
	ATF_CHECK_EQ(pc_dirent_count("."), 2);
	alarm(0);
}

/* ---- components renamed / unlinked during lookup ---- */

static void *
swapper(void *arg __unused)
{

	while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
		(void)rename("x1", "xtmp");
		(void)rename("x2", "x1");
		(void)rename("xtmp", "x2");
	}
	return (NULL);
}

static void *
recreator(void *arg __unused)
{
	int fd;

	while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
		(void)unlink("y/f");
		fd = open("y/f", O_WRONLY | O_CREAT, 0644);
		if (fd >= 0)
			close(fd);
		(void)rmdir("y/sub");
		(void)mkdir("y/sub", 0755);
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(component_rename_unlink);
ATF_TC_BODY(component_rename_unlink, tc)
{
	struct stat sb;
	ino_t set[2], i1;
	pthread_t t;
	double start;
	int iter, fd, e, dfd, sub;

	alarm(HANG_ALARM);
	pc_mkdir("x1");
	pc_mkdir("x1/sub");
	pc_mkfile("x1/sub/f", NULL);
	pc_mkdir("x2");
	pc_mkdir("x2/sub");
	pc_mkfile("x2/sub/f", NULL);
	set[0] = i1 = pc_ino("x1/sub/f", true);
	set[1] = pc_ino("x2/sub/f", true);
	dfd = open("x1", O_DIRECTORY | O_RDONLY);
	sub = open("x1/sub", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(dfd >= 0 && sub >= 0);

	t = spawn(swapper, NULL);
	for (start = now_s(), iter = 0; keep_going(start, iter); iter++) {
		e = ERRNO_OF(stat("x1/sub/f", &sb));
		ATF_CHECK_MSG(e == 0 || e == ENOENT, "stat: %s", strerror(e));
		if (e == 0)
			ATF_CHECK(in_set(sb.st_ino, set, 2));
		fd = open("x2/sub/f", O_RDONLY);
		ATF_CHECK_MSG(fd >= 0 || errno == ENOENT, "open: %s",
		    strerror(errno));
		if (fd >= 0)
			close(fd);
		/* A descriptor is bound to its vnode, not to a name. */
		e = ERRNO_OF(fstatat(dfd, "sub/f", &sb, 0));
		ATF_CHECK_MSG(e == 0, "fstatat(dfd): %s", strerror(e));
		if (e == 0)
			ATF_CHECK_EQ(sb.st_ino, i1);
		e = ERRNO_OF(fstatat(sub, "../sub/f", &sb, 0));
		ATF_CHECK_MSG(e == 0, "fstatat(sub, ..): %s", strerror(e));
		if (e == 0)
			ATF_CHECK_EQ(sb.st_ino, i1);
	}
	finish(t);
	/* The swap is a permutation: both trees and nothing else exist. */
	ATF_CHECK(access("x1/sub/f", F_OK) == 0);
	ATF_CHECK(access("x2/sub/f", F_OK) == 0);
	ATF_CHECK(access("xtmp", F_OK) == -1);

	pc_mkdir("y");
	pc_mkdir("y/sub");
	pc_mkfile("y/f", NULL);
	t = spawn(recreator, NULL);
	for (start = now_s(), iter = 0; keep_going(start, iter); iter++) {
		fd = open("y/f", O_RDONLY);
		ATF_CHECK_MSG(fd >= 0 || errno == ENOENT, "open: %s",
		    strerror(errno));
		if (fd >= 0)
			close(fd);
		e = ERRNO_OF(stat("y/sub/.", &sb));
		ATF_CHECK_MSG(e == 0 || e == ENOENT, "stat sub: %s",
		    strerror(e));
		e = ERRNO_OF(stat("y/sub/..", &sb));
		/* TBC: ".." of a just-removed directory is ENOENT. */
		ATF_CHECK_MSG(e == 0 || e == ENOENT, "stat sub/..: %s",
		    strerror(e));
	}
	finish(t);
	close(dfd);
	close(sub);
	alarm(0);
}

/* ---- the dirfd number closed and reused during *at calls ---- */

struct churn {
	int	 n;
	int	 dira, dirb, file;
};

static void *
churner(void *arg)
{
	const struct churn *c = arg;

	while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
		(void)dup2(c->dira, c->n);
		(void)dup2(c->dirb, c->n);
		(void)dup2(c->file, c->n);
		(void)close(c->n);
		(void)dup2(c->dira, c->n);
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(dirfd_close_reopen);
ATF_TC_BODY(dirfd_close_reopen, tc)
{
	struct churn c;
	struct stat sb;
	ino_t files[2], self[3];
	pthread_t t;
	double start;
	int iter, fd, e, counts[4];

	alarm(HANG_ALARM);
	pc_mkdir("a");
	pc_mkdir("b");
	pc_mkfile("a/f", NULL);
	pc_mkfile("b/f", NULL);
	pc_mkfile("plain", NULL);
	files[0] = pc_ino("a/f", true);
	files[1] = pc_ino("b/f", true);
	self[0] = pc_ino("a", true);
	self[1] = pc_ino("b", true);
	self[2] = pc_ino("plain", true);
	c.dira = open("a", O_DIRECTORY | O_RDONLY);
	c.dirb = open("b", O_DIRECTORY | O_RDONLY);
	c.file = open("plain", O_RDONLY);
	c.n = 700;
	ATF_REQUIRE(c.dira >= 0 && c.dirb >= 0 && c.file >= 0);
	memset(counts, 0, sizeof(counts));
	t = spawn(churner, &c);
	for (start = now_s(), iter = 0; keep_going(start, iter); iter++) {
		e = ERRNO_OF(fstatat(c.n, "f", &sb, 0));
		ATF_CHECK_MSG(e == 0 || e == ENOTDIR || e == EBADF,
		    "fstatat: %s", strerror(e));
		if (e == 0) {
			ATF_CHECK(in_set(sb.st_ino, files, 2));
			counts[0]++;
		} else
			counts[e == ENOTDIR ? 1 : 2]++;
		fd = openat(c.n, "f", O_RDONLY);
		ATF_CHECK_MSG(fd >= 0 || errno == ENOTDIR || errno == EBADF,
		    "openat: %s", strerror(errno));
		if (fd >= 0) {
			ATF_CHECK(fstat(fd, &sb) == 0 &&
			    in_set(sb.st_ino, files, 2));
			close(fd);
		}
		e = ERRNO_OF(fstatat(c.n, "", &sb, AT_EMPTY_PATH));
		ATF_CHECK_MSG(e == 0 || e == EBADF, "fstatat empty: %s",
		    strerror(e));
		if (e == 0)
			ATF_CHECK(in_set(sb.st_ino, self, 3));
		e = ERRNO_OF(faccessat(c.n, "f", R_OK, 0));
		ATF_CHECK_MSG(e == 0 || e == ENOTDIR || e == EBADF,
		    "faccessat: %s", strerror(e));
		e = ERRNO_OF(mkdirat(c.n, "made", 0755));
		ATF_CHECK_MSG(e == 0 || e == EEXIST || e == ENOTDIR ||
		    e == EBADF, "mkdirat: %s", strerror(e));
		(void)unlinkat(c.n, "made", AT_REMOVEDIR);
	}
	finish(t);
	printf("ok %d, ENOTDIR %d, EBADF %d\n", counts[0], counts[1],
	    counts[2]);
	(void)rmdir("a/made");
	(void)rmdir("b/made");
	/* Nothing was created next to the plain file or elsewhere. */
	ATF_CHECK_EQ(pc_dirent_count("a"), 1);
	ATF_CHECK_EQ(pc_dirent_count("b"), 1);
	ATF_CHECK_EQ(pc_dirent_count("."), 3);
	alarm(0);
}

/* ---- signals during a blocking FIFO open ---- */

static atomic_int handled;

static void
on_usr1(int sig __unused)
{

	atomic_fetch_add(&handled, 1);
}

struct opener {
	int	 flags;
	int	 fd;
	int	 error;
	atomic_bool done;
};

static void *
fifo_opener(void *arg)
{
	struct opener *o = arg;

	errno = 0;
	o->fd = open("fifo", o->flags);
	o->error = o->fd < 0 ? errno : 0;
	atomic_store(&o->done, true);
	return (NULL);
}

static void
install(bool restart)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_usr1;
	sa.sa_flags = restart ? SA_RESTART : 0;
	sigemptyset(&sa.sa_mask);
	ATF_REQUIRE(sigaction(SIGUSR1, &sa, NULL) == 0);
}

static void
fifo_signal_case(int flags, bool restart)
{
	struct opener o;
	struct timespec pause = { 0, 50 * 1000 * 1000 };
	pthread_t t;
	int i, peer;

	install(restart);
	atomic_store(&handled, 0);
	memset(&o, 0, sizeof(o));
	o.flags = flags;
	o.fd = -1;
	atomic_store(&o.done, false);
	ATF_REQUIRE(pthread_create(&t, NULL, fifo_opener, &o) == 0);
	/* Signal until the open returns or enough signals were handled. */
	for (i = 0; i < 100 && !atomic_load(&o.done); i++) {
		nanosleep(&pause, NULL);
		(void)pthread_kill(t, SIGUSR1);
		if (restart && atomic_load(&handled) >= 5)
			break;
	}
	if (!restart) {
		/* Without SA_RESTART the open fails with EINTR. */
		ATF_REQUIRE(pthread_join(t, NULL) == 0);
		ATF_CHECK(atomic_load(&handled) >= 1);
		ATF_CHECK_MSG(o.fd == -1 && o.error == EINTR,
		    "open: fd %d error %d (%s), expected EINTR", o.fd,
		    o.error, strerror(o.error));
		if (o.fd >= 0)
			close(o.fd);
		return;
	}
	/* With SA_RESTART it is restarted and still waiting... */
	ATF_CHECK(atomic_load(&handled) >= 1);
	ATF_CHECK_MSG(!atomic_load(&o.done), "the open returned early: fd %d "
	    "error %d (%s)", o.fd, o.error, strerror(o.error));
	/* ...until the other side opens. */
	peer = -1;
	for (i = 0; i < 200 && !atomic_load(&o.done); i++) {
		if (peer < 0)
			peer = open("fifo", ((flags & O_ACCMODE) == O_RDONLY ?
			    O_WRONLY : O_RDONLY) | O_NONBLOCK);
		nanosleep(&pause, NULL);
	}
	ATF_REQUIRE(pthread_join(t, NULL) == 0);
	ATF_CHECK_MSG(o.fd >= 0, "restarted open: error %d (%s)", o.error,
	    strerror(o.error));
	if (o.fd >= 0)
		close(o.fd);
	if (peer >= 0)
		close(peer);
}

ATF_TC_WITHOUT_HEAD(fifo_open_signals);
ATF_TC_BODY(fifo_open_signals, tc)
{

	alarm(HANG_ALARM);
	ATF_REQUIRE(mkfifo("fifo", 0644) == 0);
	fifo_signal_case(O_RDONLY, false);
	fifo_signal_case(O_WRONLY, false);
	fifo_signal_case(O_RDONLY, true);
	fifo_signal_case(O_WRONLY, true);
	/* Through a symlink and an at-call: the same. */
	ATF_REQUIRE(rename("fifo", "realfifo") == 0);
	ATF_REQUIRE(symlink("realfifo", "fifo") == 0);
	fifo_signal_case(O_RDONLY, false);
	fifo_signal_case(O_RDONLY, true);
	alarm(0);
}

/* ---- truncate / chmod / rename storms against stat ---- */

static int stormfd;

static void *
truncator(void *arg __unused)
{
	static const off_t sizes[] = { 0, 4096, 65536 };
	unsigned i;

	for (i = 0; !atomic_load_explicit(&stop, memory_order_relaxed); i++)
		(void)ftruncate(stormfd, sizes[i % 3]);
	return (NULL);
}

static void *
chmodder(void *arg __unused)
{
	unsigned i;

	for (i = 0; !atomic_load_explicit(&stop, memory_order_relaxed); i++)
		(void)fchmod(stormfd, (i & 1) ? 0600 : 0644);
	return (NULL);
}

static void *
renamer(void *arg __unused)
{

	while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
		(void)rename("s/f", "s/g");
		(void)rename("s/g", "s/f");
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(storms);
ATF_TC_BODY(storms, tc)
{
	struct stat sb;
	pthread_t t1, t2, t3;
	ino_t ino;
	double start;
	int iter, e, dfd, seen;

	alarm(HANG_ALARM);
	pc_mkdir("s");
	pc_mkfile("s/f", NULL);
	ino = pc_ino("s/f", true);
	stormfd = open("s/f", O_RDWR);
	dfd = open("s", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(stormfd >= 0 && dfd >= 0);
	atomic_store(&stop, false);
	ATF_REQUIRE(pthread_create(&t1, NULL, truncator, NULL) == 0);
	ATF_REQUIRE(pthread_create(&t2, NULL, chmodder, NULL) == 0);
	ATF_REQUIRE(pthread_create(&t3, NULL, renamer, NULL) == 0);
	seen = 0;
	for (start = now_s(), iter = 0; keep_going(start, iter); iter++) {
		e = ERRNO_OF(stat("s/f", &sb));
		ATF_CHECK_MSG(e == 0 || e == ENOENT, "stat: %s", strerror(e));
		if (e == 0) {
			seen++;
			ATF_CHECK_EQ(sb.st_ino, ino);
			ATF_CHECK(sb.st_size == 0 || sb.st_size == 4096 ||
			    sb.st_size == 65536);
			ATF_CHECK((sb.st_mode & ALLPERMS) == 0600 ||
			    (sb.st_mode & ALLPERMS) == 0644);
			ATF_CHECK(S_ISREG(sb.st_mode));
		}
		e = ERRNO_OF(fstatat(dfd, "g", &sb, AT_SYMLINK_NOFOLLOW));
		ATF_CHECK_MSG(e == 0 || e == ENOENT, "fstatat: %s",
		    strerror(e));
		if (e == 0)
			ATF_CHECK_EQ(sb.st_ino, ino);
		e = ERRNO_OF(truncate("s/f", 4096));
		ATF_CHECK_MSG(e == 0 || e == ENOENT, "truncate: %s",
		    strerror(e));
		e = ERRNO_OF(utimes("s/g", NULL));
		ATF_CHECK_MSG(e == 0 || e == ENOENT, "utimes: %s",
		    strerror(e));
	}
	atomic_store(&stop, true);
	ATF_REQUIRE(pthread_join(t1, NULL) == 0);
	ATF_REQUIRE(pthread_join(t2, NULL) == 0);
	ATF_REQUIRE(pthread_join(t3, NULL) == 0);
	ATF_CHECK(seen > 0);
	/* Exactly one of the two names remains. */
	ATF_CHECK_EQ(pc_dirent_count("s"), 1);
	close(stormfd);
	close(dfd);
	alarm(0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, path_buffer_rewrite);
	ATF_TP_ADD_TC(tp, component_rename_unlink);
	ATF_TP_ADD_TC(tp, dirfd_close_reopen);
	ATF_TP_ADD_TC(tp, fifo_open_signals);
	ATF_TP_ADD_TC(tp, storms);
	return (atf_no_error());
}
