/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * dqtree: run a command attached to a DescriptorQueue whose controller is
 * dq_serve_tree() over a directory, with that directory as the command's
 * served root and cwd (stage 1c-iii-c, D173).  It is chroot(8) of the
 * same directory done by a controller: the served-root suites oracle
 * (dq_tree_suites_test) runs kyua both ways and compares.
 *
 *   dqtree [-o file] dir command [argument ...]
 *
 * The tree serves writes and answers exec REAL of the backing binary;
 * the interpreter comes from the tree.  The exit status is the command's
 * (128 + the signal), or 125 when it succeeded but a consultation was
 * unmarked, failed closed or dropped, or a reply was malformed.
 *
 * The report (-o) also names every wait that went wrong, so a stall can
 * be traced to an operation: an event read SLOW_SEC or more after it was
 * posted, an answer that took SLOW_SEC or more, an answer that failed, and
 * every INTERRUPT (a requester that gave up: a signal, or its deadline
 * while the controller held the event), with the event's op, object or
 * path and how long the controller had held it.
 */

#include <sys/types.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libdq.h>

#define	BUFSIZE		(256 * 1024)
#define	SLOW_SEC	5.0
#define	NHELD		1024	/* recent waited events, by id */

/* A waited event the controller read: for the INTERRUPT that may follow. */
struct held {
	uint64_t	h_id;
	uint64_t	h_object;
	uint32_t	h_op;
	uint32_t	h_rop;
	double		h_read;		/* when the controller read it */
	char		h_path[64];
};

static struct held held[NHELD];
static FILE *evlog;

static void
usage(void)
{

	fprintf(stderr,
	    "usage: dqtree [-o file] dir command [argument ...]\n");
	exit(2);
}

static double
now(void)
{
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((double)ts.tv_sec + (double)ts.tv_nsec / 1e9);
}

/* Record a waited event as read, with its RESOLVE op and path. */
static struct held *
held_record(const struct dq_event *ev, double t)
{
	const struct dq_resolve_body *rb;
	const char *path, *path2, *sp, *sp2;
	const struct dq_setattr_body *sb;
	struct held *h;

	h = &held[ev->de_id % NHELD];
	memset(h, 0, sizeof(*h));
	h->h_id = ev->de_id;
	h->h_object = ev->de_object;
	h->h_op = ev->de_op;
	h->h_read = t;
	if (ev->de_op == DQ_OP_RESOLVE &&
	    dq_event_resolve_ext(ev, &rb, &path, &path2, &sp, &sp2,
	    &sb) == 0) {
		h->h_rop = rb->drs_op;
		strlcpy(h->h_path, path, sizeof(h->h_path));
	}
	return (h);
}

static void
held_log(const char *what, const struct held *h, double t, int error)
{

	fprintf(evlog, "dqtree: %s: id %ju op %u rop %u object %ju path '%s' "
	    "held %.3f s", what, (uintmax_t)h->h_id, h->h_op, h->h_rop,
	    (uintmax_t)h->h_object, h->h_path, t - h->h_read);
	if (error != 0)
		fprintf(evlog, " errno %d (EIO answered)", error);
	fprintf(evlog, "\n");
	fflush(evlog);
}

static void
drain(int q, struct dq_tree *t, char *buf)
{
	const struct dq_event *ev;
	const struct dq_interrupt_body *ib;
	const void *body;
	struct held *h, scratch;
	size_t bodylen;
	ssize_t got;
	double posted, t0, t1;
	int ret;

	if (dq_read_events(q, buf, BUFSIZE, &got) != 0)
		return;
	for (ev = dq_event_first(buf, (size_t)got); ev != NULL;
	    ev = dq_event_next(buf, (size_t)got, ev)) {
		body = dq_event_body(ev, &bodylen);
		t0 = now();
		posted = (double)ev->de_time.tv_sec +
		    (double)ev->de_time.tv_nsec / 1e9;
		if (ev->de_op == DQ_OP_INTERRUPT &&
		    dq_event_interrupt(ev, &ib) == 0) {
			h = &held[ib->din_id % NHELD];
			if (h->h_id == ib->din_id)
				held_log("interrupt", h, t0, 0);
			else
				fprintf(evlog, "dqtree: interrupt: id %ju "
				    "(not among the recent events)\n",
				    (uintmax_t)ib->din_id);
		}
		if (ev->de_id != 0)
			h = held_record(ev, t0);
		else {
			memset(&scratch, 0, sizeof(scratch));
			scratch.h_op = ev->de_op;
			scratch.h_object = ev->de_object;
			scratch.h_read = t0;
			h = &scratch;
		}
		if (t0 - posted >= SLOW_SEC) {
			fprintf(evlog, "dqtree: read late: id %ju op %u object "
			    "%ju path '%s' %.3f s after it was posted\n",
			    (uintmax_t)ev->de_id, ev->de_op,
			    (uintmax_t)ev->de_object, h->h_path, t0 - posted);
			fflush(evlog);
		}
		ret = dq_serve_tree(t, ev, body, bodylen);
		t1 = now();
		if (ret != 0 && ev->de_id != 0 && errno != ESRCH)
			held_log("answer failed", h, t1, errno);
		else if (ret != 0 && ev->de_id != 0)
			held_log("answer late (requester gone)", h, t1, 0);
		else if (t1 - t0 >= SLOW_SEC)
			held_log("slow answer", h, t1, 0);
	}
}

int
main(int argc, char **argv)
{
	struct dq_stats2 st;
	struct dq_tree *t;
	struct pollfd pfd[2];
	char dir[PATH_MAX], *buf, b;
	FILE *out;
	pid_t pid;
	int bfd, ch, go[2], i, pd, q, rv, sroot, status;

	out = evlog = stderr;
	while ((ch = getopt(argc, argv, "o:")) != -1) {
		switch (ch) {
		case 'o':
			out = evlog = fopen(optarg, "w");
			if (out == NULL)
				err(2, "%s", optarg);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 2)
		usage();
	if (realpath(argv[0], dir) == NULL)
		err(2, "%s", argv[0]);
	argc--;
	argv++;
	buf = malloc(BUFSIZE);
	if (buf == NULL)
		err(2, "malloc");
	bfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (bfd == -1)
		err(2, "%s", dir);
	q = dq_open();
	if (q == -1)
		err(2, "dq_open");
	if (fcntl(q, F_SETFL, O_NONBLOCK) == -1)
		err(2, "F_SETFL");
	t = dq_tree_create(q, bfd, dir, DQ_TREE_F_SERVED | DQ_TREE_F_ROOT |
	    DQ_TREE_F_WRITE | DQ_TREE_F_EXEC_REAL);
	if (t == NULL)
		err(2, "dq_tree_create");
	if (dq_tree_root(t, &sroot, NULL) == -1)
		err(2, "dq_tree_root");
	if (pipe2(go, O_CLOEXEC) == -1)
		err(2, "pipe");
	pid = pdfork(&pd, PD_CLOEXEC);
	if (pid == -1)
		err(2, "pdfork");
	if (pid == 0) {
		/* No directory of the controller's stays open. */
		(void)close(sroot);
		(void)close(bfd);
		(void)close(go[1]);
		if (read(go[0], &b, 1) != 1)
			_exit(126);
		(void)close(go[0]);
		execvp(argv[0], argv);
		fprintf(stderr, "dqtree: %s: %s\n", argv[0], strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}
	(void)close(go[0]);
	if (dq_attach_starts(q, pd, sroot, sroot) == -1)
		err(2, "DQ_IOC_ATTACH");
	/* The attachment holds the root; the controller needs no fd. */
	(void)close(sroot);
	b = 'g';
	if (write(go[1], &b, 1) != 1)
		err(2, "start the command");
	(void)close(go[1]);
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
			drain(q, t, buf);
		if ((pfd[1].revents & POLLHUP) != 0)
			break;
	}
	for (i = 0; i < 10; i++) {
		pfd[0].fd = q;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		if (poll(pfd, 1, 50) <= 0)
			break;
		drain(q, t, buf);
	}
	if (pdwait(pd, &status, WEXITED, NULL, NULL) == -1)
		err(2, "pdwait");
	if (dq_get_stats2(q, &st) == -1)
		err(2, "DQ_IOC_GET_STATS2");
	fprintf(out, "dqtree: stats2 resolves %ju served %ju unmarked %ju "
	    "failclosed %ju dropped %ju bad_replies %ju exdev %ju "
	    "retired %ju objects %d\n",
	    (uintmax_t)st.ds2_resolves, (uintmax_t)st.ds2_resolve_served,
	    (uintmax_t)st.ds2_resolve_unmarked,
	    (uintmax_t)st.ds2_resolve_failclosed,
	    (uintmax_t)st.ds2_events_dropped, (uintmax_t)st.ds2_bad_replies,
	    (uintmax_t)st.ds2_resolve_exdev, (uintmax_t)st.ds2_resolve_retired,
	    dq_tree_objects(t));
	/*
	 * The waits: an event answered after its deadline, or never, shows
	 * here (a requester that stalled until kern.dq.default_deadline_ms
	 * gave up).
	 */
	fprintf(out, "dqtree: waits posted %ju replies %ju late_replies %ju "
	    "interrupts %ju deadline_misses %ju async_deadlines %ju "
	    "queue_highwater %ju\n",
	    (uintmax_t)st.ds2_events_posted, (uintmax_t)st.ds2_replies,
	    (uintmax_t)st.ds2_late_replies, (uintmax_t)st.ds2_interrupts,
	    (uintmax_t)st.ds2_deadline_misses,
	    (uintmax_t)st.ds2_async_deadlines,
	    (uintmax_t)st.ds2_queue_highwater);
	if (out != stderr)
		(void)fclose(out);
	dq_tree_destroy(t);
	(void)close(q);
	if (WIFSIGNALED(status))
		return (128 + WTERMSIG(status));
	rv = WIFEXITED(status) ? WEXITSTATUS(status) : 125;
	if (rv == 0 && (st.ds2_events_dropped != 0 ||
	    st.ds2_resolve_failclosed != 0 || st.ds2_resolve_unmarked != 0 ||
	    st.ds2_bad_replies != 0))
		rv = 125;
	return (rv);
}
