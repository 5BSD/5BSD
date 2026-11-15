/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue stage 1c-iii-b: the served-tree oracle (D173).  Two
 * identical trees are made: one is served by dq_serve_tree()'s iii-b mode
 * from its minted root, the other is the oracle.  The same fixed script
 * of *at calls runs from the served root in an attached child and from a
 * real descriptor of the oracle tree in the test itself; the transcripts
 * (results, errnos, sizes, types, modes, sorted directory listings) must
 * be identical.  Device, FIFO and socket nodes are reached through REAL.
 */

#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libdq.h>

#include "dq_test.h"

/* Every case is root (a controller of /dev/dq) and bounded in time. */
#define	DQ_TC_HEAD_BODY(name)						\
	ATF_TC_HEAD(name, tc)						\
	{								\
		atf_tc_set_md_var(tc, "require.user", "root");		\
		atf_tc_set_md_var(tc, "timeout", "120");		\
	}
#define	DQ_TC(name)	ATF_TC(name); DQ_TC_HEAD_BODY(name)
#define	DQ_TC_CLEANUP(name)	ATF_TC_WITH_CLEANUP(name); DQ_TC_HEAD_BODY(name)

#define	OUT_MAX		16384

struct out {
	char	buf[OUT_MAX];
	size_t	len;
};

static void
emit(struct out *o, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(o->buf + o->len, sizeof(o->buf) - o->len, fmt, ap);
	va_end(ap);
	if (n > 0)
		o->len = MIN(o->len + (size_t)n, sizeof(o->buf) - 1);
}

static int
cmpstr(const void *a, const void *b)
{

	return (strcmp(*(char *const *)a, *(char *const *)b));
}

/* The entries of a directory descriptor, sorted, with their types. */
static void
listing(struct out *o, int d)
{
	char buf[2048], *names[64], *p;
	struct dirent *dp;
	off_t base;
	ssize_t n;
	int i, k;

	k = 0;
	if (lseek(d, 0, SEEK_SET) != 0) {
		emit(o, "lseek %d\n", errno);
		return;
	}
	while ((n = getdirentries(d, buf, sizeof(buf), &base)) > 0) {
		for (p = buf; p < buf + n; p += dp->d_reclen) {
			dp = (struct dirent *)(void *)p;
			if (k < 64)
				asprintf(&names[k++], "%s:%u", dp->d_name,
				    dp->d_type);
		}
	}
	if (n < 0)
		emit(o, "getdirentries %d\n", errno);
	qsort(names, k, sizeof(names[0]), cmpstr);
	emit(o, "ls");
	for (i = 0; i < k; i++) {
		emit(o, " %s", names[i]);
		free(names[i]);
	}
	emit(o, "\n");
}

static void
st_line(struct out *o, const char *what, int r, const struct stat *st)
{

	if (r != 0)
		emit(o, "%s err %d\n", what, errno);
	else
		emit(o, "%s type %o mode %o size %jd nlink %u\n", what,
		    st->st_mode & S_IFMT, st->st_mode & ALLPERMS,
		    S_ISDIR(st->st_mode) ? (intmax_t)0 : (intmax_t)st->st_size,
		    S_ISDIR(st->st_mode) ? 0 : (unsigned)st->st_nlink);
}

#define	RET(o, what, x)	do {						\
	int _r = (x);							\
	emit((o), "%s %d\n", (what), _r < 0 ? errno : 0);		\
} while (0)

/* The script: the same calls from a directory descriptor D. */
static void
script(int D, struct out *o)
{
	struct sockaddr_un sun;
	struct stat st;
	char buf[128];
	ssize_t n;
	int fd, d, so;

	st_line(o, "stat a", fstatat(D, "a", &st, 0), &st);
	st_line(o, "lstat l", fstatat(D, "l", &st, AT_SYMLINK_NOFOLLOW), &st);
	st_line(o, "stat l", fstatat(D, "l", &st, 0), &st);
	st_line(o, "stat d", fstatat(D, "d", &st, 0), &st);
	st_line(o, "stat p", fstatat(D, "p", &st, 0), &st);
	st_line(o, "stat nope", fstatat(D, "nope", &st, 0), &st);
	st_line(o, "stat a/x", fstatat(D, "a/x", &st, 0), &st);
	st_line(o, "stat d/..", fstatat(D, "d/../a", &st, 0), &st);
	/* ".." after a symbolic link is the parent of its target. */
	st_line(o, "stat ds/../a", fstatat(D, "ds/../a", &st, 0), &st);
	st_line(o, "stat l/../a", fstatat(D, "l/../a", &st, 0), &st);
	st_line(o, "stat ds/f", fstatat(D, "ds/f", &st, 0), &st);
	/* Out of the tree: "..", and a symbolic link leaving it. */
	st_line(o, "stat ..", fstatat(D, "..", &st, 0), &st);
	st_line(o, "stat out", fstatat(D, "out", &st, 0), &st);
	st_line(o, "stat ../outside", fstatat(D, "../outside", &st, 0), &st);
	fd = openat(D, "a", O_RDONLY);
	if (fd < 0)
		emit(o, "open a %d\n", errno);
	else {
		n = read(fd, buf, sizeof(buf) - 1);
		buf[n > 0 ? n : 0] = '\0';
		emit(o, "read a %zd %s", n, buf);
		st_line(o, "fstat a", fstat(fd, &st), &st);
		close(fd);
	}
	RET(o, "open a wronly", fd = openat(D, "a", O_WRONLY | O_APPEND));
	if (fd >= 0) {
		emit(o, "write %zd\n", write(fd, "more\n", 5));
		close(fd);
	}
	RET(o, "open d wronly", openat(D, "d", O_WRONLY));
	RET(o, "open a dir", openat(D, "a", O_RDONLY | O_DIRECTORY));
	RET(o, "open l nofollow", openat(D, "l", O_RDONLY | O_NOFOLLOW));
	n = readlinkat(D, "l", buf, sizeof(buf));
	emit(o, "readlink l %zd %.*s\n", n, n > 0 ? (int)n : 0, buf);
	n = readlinkat(D, "a", buf, sizeof(buf));
	emit(o, "readlink a %d\n", n < 0 ? errno : 0);
	RET(o, "access a", faccessat(D, "a", R_OK | W_OK, 0));
	RET(o, "access nope", faccessat(D, "nope", F_OK, 0));
	RET(o, "mkdir nd", mkdirat(D, "nd", 0750));
	RET(o, "mkdir nd again", mkdirat(D, "nd", 0750));
	st_line(o, "stat nd", fstatat(D, "nd", &st, 0), &st);
	RET(o, "create nd/f", fd = openat(D, "nd/f", O_CREAT | O_EXCL |
	    O_WRONLY, 0640));
	if (fd >= 0) {
		emit(o, "write nd/f %zd\n", write(fd, "abc", 3));
		close(fd);
	}
	RET(o, "create nd/f excl", openat(D, "nd/f", O_CREAT | O_EXCL |
	    O_WRONLY, 0640));
	st_line(o, "stat nd/f", fstatat(D, "nd/f", &st, 0), &st);
	RET(o, "rename", renameat(D, "nd/f", D, "nd/g"));
	RET(o, "link", linkat(D, "nd/g", D, "nd/h", 0));
	st_line(o, "stat nd/g", fstatat(D, "nd/g", &st, 0), &st);
	RET(o, "symlink", symlinkat("g", D, "nd/s"));
	st_line(o, "stat nd/s", fstatat(D, "nd/s", &st, 0), &st);
	RET(o, "chmod nd/g", fchmodat(D, "nd/g", 0600, 0));
	st_line(o, "stat nd/g", fstatat(D, "nd/g", &st, 0), &st);
	RET(o, "rmdir nd nonempty", unlinkat(D, "nd", AT_REMOVEDIR));
	d = openat(D, "nd", O_RDONLY | O_DIRECTORY);
	if (d < 0)
		emit(o, "open nd %d\n", errno);
	else {
		listing(o, d);
		st_line(o, "stat via nd", fstatat(d, "g", &st, 0), &st);
		st_line(o, "stat via nd ..", fstatat(d, "../a", &st, 0), &st);
		RET(o, "unlink via nd", unlinkat(d, "h", 0));
		close(d);
	}
	RET(o, "unlink nd/g", unlinkat(D, "nd/g", 0));
	RET(o, "unlink nd/s", unlinkat(D, "nd/s", 0));
	RET(o, "rmdir nd", unlinkat(D, "nd", AT_REMOVEDIR));
	RET(o, "unlink nope", unlinkat(D, "nope", 0));
	/* The FIFO opens (REAL from a served start). */
	fd = openat(D, "p", O_RDONLY | O_NONBLOCK);
	emit(o, "open p %d\n", fd < 0 ? errno : 0);
	if (fd >= 0) {
		st_line(o, "fstat p", fstat(fd, &st), &st);
		close(fd);
	}
	/* An AF_UNIX connect to a socket node in the tree. */
	so = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, "sock", sizeof(sun.sun_path));
	sun.sun_len = SUN_LEN(&sun);
	RET(o, "connectat sock", connectat(D, so, (struct sockaddr *)&sun,
	    sun.sun_len));
	close(so);
	listing(o, D);
}

struct srv {
	int		 q;
	struct dqt_server server;	/* the controller thread */
	struct dq_tree	*tree;
};

static int
srv_handler(int q, const struct dq_event *ev, const void *body,
    size_t bodylen, void *arg)
{
	struct srv *s = arg;

	(void)q;
	(void)dq_serve_tree(s->tree, ev, body, bodylen);
	return (0);
}

/* One tree: a, l -> a, d/f, a FIFO p and a listening socket "sock". */
static int
make_tree(const char *dir, int *lsp)
{
	struct sockaddr_un sun;
	char path[PATH_MAX];
	int fd;

	ATF_REQUIRE(mkdir(dir, 0755) == 0);
	snprintf(path, sizeof(path), "%s/a", dir);
	fd = open(path, O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd >= 0 && write(fd, "tree\n", 5) == 5);
	close(fd);
	snprintf(path, sizeof(path), "%s/l", dir);
	ATF_REQUIRE(symlink("a", path) == 0);
	snprintf(path, sizeof(path), "%s/d", dir);
	ATF_REQUIRE(mkdir(path, 0755) == 0);
	snprintf(path, sizeof(path), "%s/d/f", dir);
	ATF_REQUIRE(close(open(path, O_CREAT | O_WRONLY, 0644)) == 0);
	snprintf(path, sizeof(path), "%s/p", dir);
	ATF_REQUIRE(mkfifo(path, 0644) == 0);
	snprintf(path, sizeof(path), "%s/ds", dir);
	ATF_REQUIRE(symlink("d", path) == 0);
	snprintf(path, sizeof(path), "%s/out", dir);
	ATF_REQUIRE(symlink("../outside", path) == 0);
	*lsp = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(*lsp >= 0);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/sock", dir);
	sun.sun_len = SUN_LEN(&sun);
	ATF_REQUIRE(bind(*lsp, (struct sockaddr *)&sun, sun.sun_len) == 0);
	ATF_REQUIRE(listen(*lsp, 4) == 0);
	fd = open(dir, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	return (fd);
}

DQ_TC(tree_oracle);
ATF_TC_BODY(tree_oracle, tc)
{
	struct srv s;
	struct out *real, *served;
	char cwd[PATH_MAX], prefix[PATH_MAX], bpath[PATH_MAX];
	int go[2], back[2], pd, status, ofd, bfd, sroot, ls1, ls2, fd;
	size_t got;
	uint64_t rootid;
	pid_t pid;
	char c;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(bpath, sizeof(bpath), "%s/backing", cwd);
	snprintf(prefix, sizeof(prefix), "%s/served", cwd);
	fd = open("outside", O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd >= 0 && write(fd, "outside!\n", 9) == 9);
	close(fd);
	ofd = make_tree("oracle", &ls1);
	bfd = make_tree(bpath, &ls2);
	memset(&s, 0, sizeof(s));
	s.q = dqt_open_queue();
	s.tree = dq_tree_create(s.q, bfd, prefix,
	    DQ_TREE_F_SERVED | DQ_TREE_F_WRITE);
	ATF_REQUIRE(s.tree != NULL);
	ATF_REQUIRE(dq_tree_root(s.tree, &sroot, &rootid) == 0);
	dqt_server_start(&s.server, s.q, srv_handler, &s);

	served = calloc(1, sizeof(*served));
	real = calloc(1, sizeof(*real));
	ATF_REQUIRE(served != NULL && real != NULL);
	ATF_REQUIRE(pipe(go) == 0 && pipe(back) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(s.q);
		if (read(go[0], &c, 1) != 1)
			_exit(1);
		script(sroot, served);
		_exit(write(back[1], served, sizeof(*served)) ==
		    (ssize_t)sizeof(*served) ? 0 : DQT_EXIT_NORESULT);
	}
	/* Only the child holds the write ends: its death is an EOF here. */
	close(go[0]);
	close(back[1]);
	ATF_REQUIRE_MSG(dq_attach(s.q, pd) == 0, "attach: %s",
	    strerror(errno));
	ATF_REQUIRE(write(go[1], "g", 1) == 1);
	got = dqt_read_full(back[0], served, sizeof(*served));
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	dqt_require_exit0(status, "the served script");
	ATF_REQUIRE_EQ(sizeof(*served), got);
	close(go[1]);
	close(back[0]);

	script(ofd, real);
	if (strcmp(real->buf, served->buf) != 0) {
		printf("--- real\n%s--- served\n%s", real->buf, served->buf);
		atf_tc_fail("the served transcript differs from the real one");
	}
	dqt_server_stop(&s.server);
	close(sroot);
	dq_tree_destroy(s.tree);
	close(s.q);
	close(ls1);
	close(ls2);
	close(pd);
	free(real);
	free(served);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, tree_oracle);
	return (atf_no_error());
}
