/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * dqpass: run a command attached to a DescriptorQueue that lets every
 * lookup through.
 *
 *   dqpass [-v] [-o file] command [argument ...]
 *
 * dqpass opens a queue, pdfork(2)s, attaches the child (DQ_IOC_ATTACH)
 * before it execs the command, and answers every RESOLVE event its
 * process tree posts with PASS.  It counts the events per operation and
 * class and prints the counts and the queue's statistics when the command
 * exits.  An attached process behaves as an unattached one would, except
 * for what dq(4) lists (no set-id or authority transitions, no jail_attach,
 * no setcred, no core dump), so running a program under dqpass is an
 * oracle for the transparency of the consultation path.
 *
 * The exit status is the command's (128 + the signal if one killed it),
 * or 125 when the command succeeded but a consultation was dropped, failed
 * closed, or was unmarked (a user-space lookup without an intent: a
 * kernel ledger failure), which a pass-everything run must never see.
 *
 * -v prints one line per event; -o writes the report to a file instead of
 * the standard error.  Build with -ldq; see dq(4) and libdq(3).
 */

#include <sys/types.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libdq.h>

#define	NCLASS		4		/* DQ_RCLASS_* 1..3, 0 unknown */
#define	BUFSIZE		(256 * 1024)

static const char *const opnames[DQ_ROP_MAX + 1] = {
	[0] = "?",
	[DQ_ROP_OPEN] = "open", [DQ_ROP_STAT] = "stat",
	[DQ_ROP_ACCESS] = "access", [DQ_ROP_READLINK] = "readlink",
	[DQ_ROP_REALPATH] = "realpath", [DQ_ROP_GETFH] = "getfh",
	[DQ_ROP_UNLINK] = "unlink", [DQ_ROP_RMDIR] = "rmdir",
	[DQ_ROP_RENAME] = "rename", [DQ_ROP_LINK] = "link",
	[DQ_ROP_SYMLINK] = "symlink", [DQ_ROP_MKDIR] = "mkdir",
	[DQ_ROP_MKNOD] = "mknod", [DQ_ROP_MKFIFO] = "mkfifo",
	[DQ_ROP_SETATTR] = "setattr", [DQ_ROP_TRUNCATE] = "truncate",
	[DQ_ROP_EXEC] = "exec", [DQ_ROP_EXEC_INTERP] = "exec_interp",
	[DQ_ROP_CONNECT] = "connect", [DQ_ROP_BIND] = "bind",
	[DQ_ROP_SOCKET] = "socket", [DQ_ROP_SOCKETPAIR] = "socketpair",
	[DQ_ROP_CHDIR] = "chdir", [DQ_ROP_CHROOT] = "chroot",
	[DQ_ROP_INOTIFY] = "inotify", [DQ_ROP_XATTR] = "xattr",
	[DQ_ROP_ACL] = "acl", [DQ_ROP_REVOKE] = "revoke",
	[DQ_ROP_INTERNAL] = "internal",
};

struct counts {
	unsigned long	 op[DQ_ROP_MAX + 1][NCLASS];
	unsigned long	 resolves;
	unsigned long	 interrupts;
	unsigned long	 others;	/* any other record */
	unsigned long	 bad;		/* malformed RESOLVE bodies */
	unsigned long	 reply_errors;
};

static int verbose;

static void
handle(int q, const struct dq_event *ev, struct counts *c)
{
	const struct dq_resolve_body *rb;
	const char *path, *path2;
	uint32_t op, cls;

	switch (ev->de_op) {
	case DQ_OP_RESOLVE:
		c->resolves++;
		if (dq_event_resolve(ev, &rb, &path, &path2, NULL, NULL) != 0) {
			c->bad++;
			/* Answer anyway: the lookup must not wait for nothing. */
			if (dq_reply_resolve_pass(q, ev->de_id) != 0)
				c->reply_errors++;
			return;
		}
		op = rb->drs_op <= DQ_ROP_MAX ? rb->drs_op : 0;
		cls = rb->drs_flags < NCLASS ? rb->drs_flags : 0;
		c->op[op][cls]++;
		if (verbose)
			fprintf(stderr, "dqpass: pid %d %s class %u rflags %#x "
			    "\"%s\"%s%s%s\n", ev->de_caller.dc_pid,
			    opnames[op], rb->drs_flags, rb->drs_rflags, path,
			    path2[0] != '\0' ? " \"" : "", path2,
			    path2[0] != '\0' ? "\"" : "");
		/* A late reply (the requester gave up) is ESRCH: not an error. */
		if (dq_reply_resolve_pass(q, ev->de_id) != 0 && errno != ESRCH)
			c->reply_errors++;
		return;
	case DQ_OP_INTERRUPT:
		c->interrupts++;
		return;
	default:
		c->others++;
		if (ev->de_id != 0)
			(void)dq_reply(q, ev->de_id, EIO, NULL, 0);
		return;
	}
}

/* One read of the queue, every record handled; false when it is empty. */
static bool
drain_once(int q, char *buf, struct counts *c)
{
	const struct dq_event *ev;
	ssize_t got;

	if (dq_read_events(q, buf, BUFSIZE, &got) != 0) {
		if (errno == EAGAIN || errno == EINTR)
			return (false);
		err(1, "read queue");
	}
	for (ev = dq_event_first(buf, (size_t)got); ev != NULL;
	    ev = dq_event_next(buf, (size_t)got, ev))
		handle(q, ev, c);
	return (got > 0);
}

static void
report(FILE *out, const struct counts *c, const struct dq_stats2 *st)
{
	unsigned long sum;
	int i, k;

	fprintf(out, "dqpass: %lu RESOLVE events, %lu INTERRUPT, %lu other, "
	    "%lu malformed, %lu reply errors\n", c->resolves, c->interrupts,
	    c->others, c->bad, c->reply_errors);
	fprintf(out, "dqpass: %-12s %10s %10s %10s\n", "op", "user",
	    "kconsumer", "kernel");
	for (i = 0; i <= DQ_ROP_MAX; i++) {
		for (sum = 0, k = 0; k < NCLASS; k++)
			sum += c->op[i][k];
		if (sum == 0)
			continue;
		fprintf(out, "dqpass: %-12s %10lu %10lu %10lu\n",
		    opnames[i] != NULL ? opnames[i] : "?",
		    c->op[i][DQ_RCLASS_USER], c->op[i][DQ_RCLASS_KCONSUMER],
		    c->op[i][DQ_RCLASS_KERNEL]);
	}
	fprintf(out, "dqpass: stats2 resolves %ju pass %ju kernel %ju "
	    "unmarked %ju failclosed %ju attached %ju dropped %ju "
	    "interrupts %ju deadline_misses %ju bad_replies %ju\n",
	    (uintmax_t)st->ds2_resolves, (uintmax_t)st->ds2_resolve_pass,
	    (uintmax_t)st->ds2_resolve_kernel,
	    (uintmax_t)st->ds2_resolve_unmarked,
	    (uintmax_t)st->ds2_resolve_failclosed,
	    (uintmax_t)st->ds2_attached, (uintmax_t)st->ds2_events_dropped,
	    (uintmax_t)st->ds2_interrupts, (uintmax_t)st->ds2_deadline_misses,
	    (uintmax_t)st->ds2_bad_replies);
}

static void
usage(void)
{

	fprintf(stderr, "usage: dqpass [-v] [-o file] command [argument ...]\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	struct counts c;
	struct dq_stats2 st;
	struct pollfd pfd[2];
	FILE *out;
	char *buf, b;
	pid_t pid;
	int ch, go[2], i, pd, q, status, rv;

	out = stderr;
	while ((ch = getopt(argc, argv, "o:v")) != -1) {
		switch (ch) {
		case 'o':
			out = fopen(optarg, "w");
			if (out == NULL)
				err(2, "%s", optarg);
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();

	buf = malloc(BUFSIZE);
	if (buf == NULL)
		err(2, "malloc");
	memset(&c, 0, sizeof(c));
	q = dq_open();		/* O_CLOFORK: the child never holds it */
	if (q == -1)
		err(2, "dq_open (%s)", DQ_DEVICE);
	if (fcntl(q, F_SETFL, O_NONBLOCK) == -1)
		err(2, "F_SETFL");
	if (pipe2(go, O_CLOEXEC) == -1)
		err(2, "pipe");

	pid = pdfork(&pd, PD_CLOEXEC);
	if (pid == -1)
		err(2, "pdfork");
	if (pid == 0) {
		/* Wait until attached: everything after this is consulted. */
		(void)close(go[1]);
		if (read(go[0], &b, 1) != 1)
			_exit(126);
		(void)close(go[0]);
		execvp(argv[0], argv);
		/* The exec's own lookup was answered: report how it failed. */
		fprintf(stderr, "dqpass: %s: %s\n", argv[0], strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}
	(void)close(go[0]);
	if (dq_attach(q, pd) == -1)
		err(2, "DQ_IOC_ATTACH");
	b = 'g';
	if (write(go[1], &b, 1) != 1)
		err(2, "start the command");
	(void)close(go[1]);

	/* Serve until the command exits; its descendants stay attached. */
	for (;;) {
		pfd[0].fd = q;
		pfd[0].events = POLLIN;
		pfd[1].fd = pd;
		pfd[1].events = POLLHUP;
		pfd[0].revents = pfd[1].revents = 0;
		rv = poll(pfd, 2, -1);
		if (rv == -1) {
			if (errno == EINTR)
				continue;
			err(2, "poll");
		}
		if ((pfd[0].revents & POLLIN) != 0)
			(void)drain_once(q, buf, &c);
		if ((pfd[1].revents & POLLHUP) != 0)
			break;
	}
	/* What the command's last moments posted. */
	for (i = 0; i < 10; i++) {
		pfd[0].fd = q;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		if (poll(pfd, 1, 50) <= 0)
			break;
		(void)drain_once(q, buf, &c);
	}
	if (pdwait(pd, &status, WEXITED, NULL, NULL) == -1)
		err(2, "pdwait");
	if (dq_get_stats2(q, &st) == -1)
		err(2, "DQ_IOC_GET_STATS2");
	report(out, &c, &st);
	if (out != stderr)
		(void)fclose(out);
	(void)close(q);

	if (WIFSIGNALED(status))
		return (128 + WTERMSIG(status));
	rv = WIFEXITED(status) ? WEXITSTATUS(status) : 125;
	if (rv == 0 && (st.ds2_events_dropped != 0 ||
	    st.ds2_resolve_failclosed != 0 || st.ds2_resolve_unmarked != 0))
		rv = 125;
	return (rv);
}
