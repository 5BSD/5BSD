/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * dqswap: run an unmodified command attached to a supervisor queue and
 * answer its opens three ways, side by side:
 *
 *   dqswap [-D] [-j jail] [-l log] -s path=substitute -p path command ...
 *
 *   -s path=substitute	an open of path is answered SWAP: this program
 *			opens substitute itself and the kernel installs that
 *			real open file in the command.  Later reads never
 *			reach this program.
 *   -p path		an open of path is answered FD: the kernel mints a
 *			proxy descriptor; every read of it is a READ event
 *			answered here from memory.
 *   anything else	PASS: the command's own lookup proceeds.
 *
 *   -D			pdfork with PD_DAEMON, so the command outlives this
 *			program (for showing what each descriptor does once
 *			the supervisor is gone).
 *   -j jail		the command enters this jail before it is attached
 *			(there is no jail-wide attach: a process that enters
 *			the jail later by other means is not attached).
 *   -l log		the event log (default stderr): one line per record
 *			read from the queue.
 *
 * Paths are compared as strings with what the command passed to open(2):
 * give the absolute path and use it in the command.  stat(2) and every
 * other path call PASS, so they show the original file.
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/mount.h>
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libdq.h>

#define	BUFSIZE		(256 * 1024)

static const char *swap_path, *swap_subst, *proxy_path;
static char proxy_data[256];
static size_t proxy_len;
static FILE *out;
static unsigned long nrec;
static const char *jailname;

/* Who asked: the requesting process, its parent and its jail. */
static const char *
who(const struct dq_event *ev)
{
	static char b[80];

	snprintf(b, sizeof(b), "pid %d (ppid %d, jid %u)",
	    ev->de_caller.dc_pid, ev->de_caller.dc_ppid, ev->de_caller.dc_jid);
	return (b);
}

static void
answer_swap(int q, const struct dq_event *ev, const struct dq_resolve_body *rb,
    const char *path)
{
	int error, fd;

	/*
	 * Opened afresh for this answer, with the command's own access mode
	 * and status flags (the kernel wants them equal) and never O_TRUNC
	 * or O_CREAT: the kernel truncates for the command once it has
	 * checked the command's own permission, and this example hands over
	 * an existing file.  O_CLOFORK: no child of ours may share it.
	 *
	 * O_EXCL is ours to honour: the kernel resolves no name for a swap,
	 * and the name the command asked to create exclusively is answered
	 * with a file that exists.
	 */
	if (((int)rb->drs_mode & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) {
		fprintf(out, "dqswap: #%lu RESOLVE open \"%s\" %s -> errno "
		    "%d (O_EXCL)\n", nrec, path, who(ev), EEXIST);
		(void)dq_reply_resolve_errno(q, ev->de_id, EEXIST);
		return;
	}
	fd = open(swap_subst, ((int)rb->drs_mode & (O_ACCMODE | O_EXEC |
	    O_PATH | O_DIRECTORY | O_APPEND | O_NONBLOCK | O_SYNC | O_DSYNC |
	    O_DIRECT | O_ASYNC)) | O_CLOEXEC | O_CLOFORK);
	if (fd == -1) {
		error = errno;
		fprintf(out, "dqswap: #%lu RESOLVE open \"%s\" %s -> errno "
		    "%d (open %s)\n", nrec, path, who(ev), error,
		    swap_subst);
		(void)dq_reply_resolve_errno(q, ev->de_id, error);
		return;
	}
	if (dq_reply_resolve_swap(q, ev->de_id, fd, 0) == -1) {
		error = errno;
		fprintf(out, "dqswap: #%lu RESOLVE open \"%s\" %s -> SWAP "
		    "refused: %s\n", nrec, path, who(ev),
		    strerror(error));
		/* The event is still in flight unless it is gone. */
		if (error != ESRCH)
			(void)dq_reply_resolve_errno(q, ev->de_id, EIO);
	} else
		fprintf(out, "dqswap: #%lu RESOLVE open \"%s\" %s -> SWAP "
		    "(my fd %d of %s, now closed)\n", nrec, path,
		    who(ev), fd, swap_subst);
	(void)close(fd);
}

static void
answer_proxy(int q, const struct dq_event *ev, const char *path)
{
	struct dq_ident_file *ident;
	struct dq_policy pol;
	struct statfs sfs;
	struct stat st;
	uint64_t object;
	int32_t reason;
	int error, fd;

	ident = calloc(1, sizeof(*ident));
	if (ident == NULL)
		err(2, "calloc");
	error = 0;
	fd = open(proxy_path, O_RDONLY | O_CLOEXEC);
	if (fd == -1 || fstat(fd, &st) == -1 || fstatfs(fd, &sfs) == -1 ||
	    dq_ident_from_stat(ident, proxy_path, &st, &sfs, fd) == -1)
		error = errno != 0 ? errno : EIO;
	if (fd != -1)
		(void)close(fd);
	if (error != 0) {
		fprintf(out, "dqswap: #%lu RESOLVE open \"%s\" %s -> errno "
		    "%d\n", nrec, path, who(ev), error);
		(void)dq_reply_resolve_errno(q, ev->de_id, error);
		free(ident);
		return;
	}
	ident->di_size = proxy_len;
	dq_policy_default(&pol);
	pol.dp_events = DQ_EVENTS_CLOSE;
	reason = 0;
	if (dq_reply_resolve_fd(q, ev->de_id, DQ_KIND_FILE, 0, ident, &pol,
	    &object, &reason) == -1) {
		error = errno;
		fprintf(out, "dqswap: #%lu RESOLVE open \"%s\" %s -> FD "
		    "refused: %s (reason %d)\n", nrec, path,
		    who(ev), strerror(error), reason);
		if (error != ESRCH)
			(void)dq_reply_resolve_errno(q, ev->de_id, EIO);
	} else
		fprintf(out, "dqswap: #%lu RESOLVE open \"%s\" %s -> FD "
		    "(proxy object %ju)\n", nrec, path, who(ev),
		    (uintmax_t)object);
	free(ident);
}

static void
handle(int q, const struct dq_event *ev)
{
	const struct dq_resolve_body *rb;
	const struct dq_read_body *rd;
	const void *body;
	const char *path, *path2;
	size_t bodylen, n, off;

	nrec++;
	switch (ev->de_op) {
	case DQ_OP_RESOLVE:
		if (dq_event_resolve(ev, &rb, &path, &path2, NULL, NULL) != 0) {
			fprintf(out, "dqswap: #%lu RESOLVE malformed -> PASS\n",
			    nrec);
			(void)dq_reply_resolve_pass(q, ev->de_id);
			return;
		}
		if (rb->drs_op == DQ_ROP_OPEN && swap_path != NULL &&
		    strcmp(path, swap_path) == 0 &&
		    dq_resolve_accepts(rb, DQ_RESOLVE_SWAP)) {
			answer_swap(q, ev, rb, path);
			return;
		}
		if (rb->drs_op == DQ_ROP_OPEN && proxy_path != NULL &&
		    strcmp(path, proxy_path) == 0 &&
		    dq_resolve_accepts(rb, DQ_RESOLVE_FD)) {
			answer_proxy(q, ev, path);
			return;
		}
		fprintf(out, "dqswap: #%lu RESOLVE op %u \"%s\" %s -> PASS\n",
		    nrec, rb->drs_op, path, who(ev));
		if (dq_reply_resolve_pass(q, ev->de_id) != 0 && errno != ESRCH)
			fprintf(out, "dqswap: #%lu PASS failed: %s\n", nrec,
			    strerror(errno));
		return;
	case DQ_OP_READ:
		body = dq_event_body(ev, &bodylen);
		if (body == NULL || bodylen < sizeof(*rd)) {
			(void)dq_reply(q, ev->de_id, EIO, NULL, 0);
			return;
		}
		rd = body;
		off = rd->dr_offset;
		n = off >= proxy_len ? 0 : proxy_len - off;
		if (n > rd->dr_len)
			n = rd->dr_len;
		fprintf(out, "dqswap: #%lu READ proxy object %ju offset %ju "
		    "len %u %s -> %zu bytes\n", nrec,
		    (uintmax_t)ev->de_object, (uintmax_t)rd->dr_offset,
		    rd->dr_len, who(ev), n);
		if (dq_reply(q, ev->de_id, 0, proxy_data + off, n) == -1)
			fprintf(out, "dqswap: #%lu READ reply: %s\n", nrec,
			    strerror(errno));
		return;
	case DQ_OP_CLOSE:
		fprintf(out, "dqswap: #%lu CLOSE proxy object %ju\n", nrec,
		    (uintmax_t)ev->de_object);
		return;
	default:
		fprintf(out, "dqswap: #%lu op %u object %ju -> %s\n", nrec,
		    ev->de_op, (uintmax_t)ev->de_object,
		    ev->de_id != 0 ? "EIO" : "(no reply)");
		if (ev->de_id != 0)
			(void)dq_reply(q, ev->de_id, EIO, NULL, 0);
		return;
	}
}

static void
drain_once(int q, char *buf)
{
	const struct dq_event *ev;
	ssize_t got;

	if (dq_read_events(q, buf, BUFSIZE, &got) != 0) {
		if (errno == EAGAIN || errno == EINTR)
			return;
		err(2, "read queue");
	}
	for (ev = dq_event_first(buf, (size_t)got); ev != NULL;
	    ev = dq_event_next(buf, (size_t)got, ev))
		handle(q, ev);
	fflush(out);
}

static void
usage(void)
{

	fprintf(stderr, "usage: dqswap [-D] [-j jail] [-l log] [-s path=substitute] "
	    "[-p path] command [argument ...]\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	struct pollfd pfd[2];
	char *buf, *eq, b;
	pid_t pid;
	int ch, go[2], i, pd, pdflags, q, ready[2], status, rv;

	out = stderr;
	pdflags = PD_CLOEXEC;
	while ((ch = getopt(argc, argv, "Dj:l:p:s:")) != -1) {
		switch (ch) {
		case 'D':
			pdflags |= PD_DAEMON;
			break;
		case 'j':
			jailname = optarg;
			break;
		case 'l':
			out = fopen(optarg, "w");
			if (out == NULL)
				err(2, "%s", optarg);
			break;
		case 'p':
			proxy_path = optarg;
			break;
		case 's':
			eq = strchr(optarg, '=');
			if (eq == NULL)
				usage();
			*eq = '\0';
			swap_path = optarg;
			swap_subst = eq + 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();
	proxy_len = (size_t)snprintf(proxy_data, sizeof(proxy_data),
	    "PROXY CONTENT: these bytes exist only in dqswap (pid %d) memory\n",
	    getpid());

	buf = malloc(BUFSIZE);
	if (buf == NULL)
		err(2, "malloc");
	q = dq_open();		/* O_CLOFORK: the child never holds it */
	if (q == -1)
		err(2, "dq_open (%s)", DQ_DEVICE);
	if (fcntl(q, F_SETFL, O_NONBLOCK) == -1)
		err(2, "F_SETFL");
	if (pipe2(go, O_CLOEXEC) == -1 || pipe2(ready, O_CLOEXEC) == -1)
		err(2, "pipe");

	pid = pdfork(&pd, pdflags);
	if (pid == -1)
		err(2, "pdfork");
	if (pid == 0) {
		/*
		 * -j: enter the jail first.  An attached process may not
		 * change jail (EPERM), so the order is: enter, wait
		 * quiesced, be attached from outside, exec.
		 */
		if (jailname != NULL) {
			i = jail_getid(jailname);
			if (i == -1 || jail_attach(i) == -1) {
				fprintf(stderr, "dqswap: jail %s: %s\n",
				    jailname, i == -1 ? jail_errmsg :
				    strerror(errno));
				_exit(125);
			}
		}
		/* In place (and in the jail): now the parent may attach. */
		(void)close(ready[0]);
		b = 'r';
		if (write(ready[1], &b, 1) != 1)
			_exit(126);
		(void)close(ready[1]);
		/* Wait until attached: everything after this is consulted. */
		(void)close(go[1]);
		if (read(go[0], &b, 1) != 1)
			_exit(126);
		(void)close(go[0]);
		execvp(argv[0], argv);
		fprintf(stderr, "dqswap: %s: %s\n", argv[0], strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}
	(void)close(go[0]);
	(void)close(ready[1]);
	if (read(ready[0], &b, 1) != 1)
		errx(2, "the command did not start%s%s", jailname != NULL ?
		    " in jail " : "", jailname != NULL ? jailname : "");
	(void)close(ready[0]);
	if (dq_attach(q, pd) == -1)
		err(2, "DQ_IOC_ATTACH");
	fprintf(out, "dqswap: supervisor pid %d attached command pid %d%s%s\n",
	    getpid(), pid, jailname != NULL ? " in jail " : "",
	    jailname != NULL ? jailname : "");
	fflush(out);
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
			drain_once(q, buf);
		if ((pfd[1].revents & POLLHUP) != 0)
			break;
	}
	for (i = 0; i < 10; i++) {
		pfd[0].fd = q;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		if (poll(pfd, 1, 50) <= 0)
			break;
		drain_once(q, buf);
	}
	if (pdwait(pd, &status, WEXITED, NULL, NULL) == -1)
		err(2, "pdwait");
	fprintf(out, "dqswap: command exited, %lu records handled\n", nrec);
	fflush(out);
	(void)close(q);
	if (WIFSIGNALED(status))
		return (128 + WTERMSIG(status));
	return (WIFEXITED(status) ? WEXITSTATUS(status) : 125);
}
