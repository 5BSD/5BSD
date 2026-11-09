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
 */

#include <sys/types.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libdq.h>

#define	BUFSIZE		(256 * 1024)

static void
usage(void)
{

	fprintf(stderr,
	    "usage: dqtree [-o file] dir command [argument ...]\n");
	exit(2);
}

static void
drain(int q, struct dq_tree *t, char *buf)
{
	const struct dq_event *ev;
	const void *body;
	size_t bodylen;
	ssize_t got;

	if (dq_read_events(q, buf, BUFSIZE, &got) != 0)
		return;
	for (ev = dq_event_first(buf, (size_t)got); ev != NULL;
	    ev = dq_event_next(buf, (size_t)got, ev)) {
		body = dq_event_body(ev, &bodylen);
		(void)dq_serve_tree(t, ev, body, bodylen);
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

	out = stderr;
	while ((ch = getopt(argc, argv, "o:")) != -1) {
		switch (ch) {
		case 'o':
			out = fopen(optarg, "w");
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
