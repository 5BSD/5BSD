/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * dqserve: a complete DescriptorQueue controller.
 *
 * It reads a file into memory, replaces every occurrence of a word with
 * asterisks, mints a served descriptor presenting the real file's identity
 * but the redacted bytes, then forks a child that reads the descriptor and
 * prints it.  The child sees a read-only regular file; what it reads is the
 * controller's redacted copy, not the file on disk.  The queue is opened
 * O_CLOFORK (dq_open does this), so the child inherits the served
 * descriptor and not the queue, and the controller's own EDEADLK rule does
 * not trip.
 *
 * Build with -ldq; see dq(4) and libdq(3).
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include <libdq.h>

struct served {
	unsigned char	*data;
	size_t		 len;
	int		 fd;		/* the minted descriptor */
	uint64_t	 object;
	int		 done;		/* CLOSE seen */
};

/* Replace each occurrence of word in buf with asterisks, in place. */
static void
redact(unsigned char *buf, size_t len, const char *word)
{
	size_t wlen, i;

	wlen = strlen(word);
	if (wlen == 0 || wlen > len)
		return;
	for (i = 0; i + wlen <= len; i++) {
		if (memcmp(buf + i, word, wlen) == 0) {
			memset(buf + i, '*', wlen);
			i += wlen - 1;
		}
	}
}

/*
 * One handler call per record.  A READ is answered from the redacted copy;
 * a short answer (or a zero-length one past the end) is the end of the
 * file.  CLOSE needs no reply and ends the loop.
 */
static int
handler(int q, const struct dq_event *ev, const void *body, size_t bodylen,
    void *arg)
{
	const struct dq_read_body *rb;
	struct served *s = arg;
	size_t off, n;

	switch (ev->de_op) {
	case DQ_OP_READ:
		if (bodylen < sizeof(*rb))
			return (dq_reply(q, ev->de_id, EIO, NULL, 0) == -1);
		rb = body;
		off = rb->dr_offset;
		n = off >= s->len ? 0 : s->len - off;
		if (n > rb->dr_len)
			n = rb->dr_len;
		if (dq_reply(q, ev->de_id, 0, s->data + off, n) == -1)
			warn("dq_reply");
		return (0);
	case DQ_OP_CLOSE:
		s->done = 1;
		return (1);
	default:
		/* No other event is possible under the default policy. */
		return (0);
	}
}

int
main(int argc, char **argv)
{
	struct served s;
	struct dq_ident_file *ident;
	struct dq_policy pol;
	struct statfs sfs;
	struct stat st;
	char path[PATH_MAX];
	const char *word;
	ssize_t n;
	off_t off;
	int file, q, reason;
	pid_t pid;

	if (argc != 3) {
		fprintf(stderr, "usage: %s file word-to-redact\n", argv[0]);
		return (2);
	}
	word = argv[2];

	/* Read the file and take its identity. */
	file = open(argv[1], O_RDONLY);
	if (file == -1)
		err(1, "open %s", argv[1]);
	if (fstat(file, &st) == -1)
		err(1, "fstat");
	if (fstatfs(file, &sfs) == -1)
		err(1, "fstatfs");
	if (realpath(argv[1], path) == NULL)
		err(1, "realpath %s", argv[1]);
	memset(&s, 0, sizeof(s));
	s.len = (size_t)st.st_size;
	s.data = malloc(s.len != 0 ? s.len : 1);
	if (s.data == NULL)
		err(1, "malloc");
	for (off = 0; (size_t)off < s.len; off += n) {
		n = pread(file, s.data + off, s.len - (size_t)off, off);
		if (n <= 0)
			err(1, "read %s", argv[1]);
	}
	redact(s.data, s.len, word);

	ident = calloc(1, sizeof(*ident));
	if (ident == NULL)
		err(1, "calloc");
	if (dq_ident_from_stat(ident, path, &st, &sfs, file) == -1)
		err(1, "dq_ident_from_stat");

	/* Open the queue and mint a read-only object serving the copy. */
	q = dq_open();
	if (q == -1)
		err(1, "dq_open (%s)", DQ_DEVICE);
	dq_policy_default(&pol);
	pol.dp_events = DQ_EVENTS_CLOSE;
	if (dq_mint_file(q, ident, &pol, &s.object, &s.fd, &reason) == -1)
		err(1, "dq_mint_file (reason %d)", reason);
	free(ident);
	(void)close(file);

	/* The child inherits the served descriptor, not the queue. */
	pid = fork();
	if (pid == -1)
		err(1, "fork");
	if (pid == 0) {
		unsigned char buf[4096];
		ssize_t r;

		(void)close(q);		/* O_CLOFORK already closed it */
		while ((r = read(s.fd, buf, sizeof(buf))) > 0)
			(void)write(STDOUT_FILENO, buf, (size_t)r);
		if (r == -1)
			err(1, "read served descriptor");
		(void)close(s.fd);
		_exit(0);
	}
	(void)close(s.fd);		/* the controller keeps only the queue */

	/* Serve until the child closes the descriptor (DQ_OP_CLOSE). */
	while (!s.done) {
		if (dq_dispatch(q, handler, &s) == -1)
			err(1, "dq_dispatch");
	}
	(void)waitpid(pid, NULL, 0);
	(void)close(q);
	free(s.data);
	return (0);
}
