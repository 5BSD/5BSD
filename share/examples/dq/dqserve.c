/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * dqserve: a complete DescriptorQueue controller, in two modes.
 *
 *   dqserve file word	read-only: serve a redacted copy of file
 *   dqserve -w file	writable: serve file itself through dq_serve_file()
 *
 * Read-only mode reads a file into memory, replaces every occurrence of a
 * word with asterisks, mints a served descriptor presenting the real file's
 * identity but the redacted bytes, then forks a child that reads the
 * descriptor and prints it.  The child sees a read-only regular file; what
 * it reads is the controller's redacted copy, not the file on disk.
 *
 * Writable mode mints a descriptor with DQ_MINT_F_WRITE under a policy of
 * dp_write = DQ_EVENT and answers every event with dq_serve_file() from
 * the real file: the child appends a line, locks, syncs, maps the file
 * shared and writable and writes a page back with msync, reads the whole
 * file back and prints it.  Every write, lock and sync is an event the
 * controller applies to the backing file; the controller could refuse,
 * redirect or log any of them instead.
 *
 * In both modes the child inherits the served descriptor and never the
 * queue (the kernel keeps a queue in the process that opened it), and the
 * controller's own EDEADLK rule does not trip.
 *
 * Build with -ldq; see dq(4) and libdq(3).
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/mman.h>
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
	unsigned char	*data;		/* read-only mode: the redacted copy */
	size_t		 len;
	int		 fd;		/* the minted descriptor */
	uint64_t	 object;
	int		 backing;	/* writable mode: the real file */
	struct dq_serve_opts opts;	/* writable mode */
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
 * Read-only mode: one handler call per record.  A READ is answered from
 * the redacted copy; a short answer (or a zero-length one past the end) is
 * the end of the file.  CLOSE needs no reply and ends the loop.
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
		/*
		 * A read-only object can still post LOCK (a read lock) and
		 * SETATTR (fchmod by the owner); this controller refuses both.
		 */
		if (ev->de_id != 0 &&
		    dq_reply(q, ev->de_id, ev->de_op == DQ_OP_LOCK ? ENOLCK :
		    EPERM, NULL, 0) == -1)
			warn("dq_reply");
		return (0);
	}
}

/* Writable mode: dq_serve_file() answers everything from the real file. */
static int
serve_handler(int q, const struct dq_event *ev, const void *body,
    size_t bodylen, void *arg)
{
	struct served *s = arg;

	if (dq_serve_file(q, ev, body, bodylen, s->backing, &s->opts) == -1)
		warn("dq_serve_file (op %u)", ev->de_op);
	if (ev->de_op == DQ_OP_CLOSE) {
		s->done = 1;
		return (1);
	}
	return (0);
}

/* The requester of writable mode: append, lock, sync, read back. */
static void
writable_child(int fd)
{
	static const char line[] = "appended through dq(4)\n";
	unsigned char buf[4096];
	unsigned char *p;
	volatile unsigned char *vp;
	struct stat st;
	ssize_t r;

	if (fcntl(fd, F_SETFL, O_APPEND) == -1)
		err(1, "F_SETFL O_APPEND");
	if (flock(fd, LOCK_EX) == -1)
		err(1, "flock");
	if (write(fd, line, sizeof(line) - 1) != (ssize_t)sizeof(line) - 1)
		err(1, "write served descriptor");
	if (fsync(fd) == -1)
		err(1, "fsync");
	if (flock(fd, LOCK_UN) == -1)
		err(1, "flock unlock");
	/*
	 * Through a shared writable mapping too: the fault is a READ, the
	 * store dirties the page, and msync(MS_SYNC) writes it back as a
	 * WRITE_ASYNC the controller applies to the file.  The last byte is
	 * rewritten in place with the bytes already there, so the file's
	 * content does not change.
	 */
	if (fstat(fd, &st) == -1)
		err(1, "fstat");
	if (st.st_size > 0) {
		p = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, 0);
		if (p == MAP_FAILED)
			err(1, "mmap");
		vp = p;	/* a real store, not optimised away */
		vp[st.st_size - 1] = vp[st.st_size - 1];
		if (msync(p, (size_t)st.st_size, MS_SYNC) == -1)
			err(1, "msync");
		(void)munmap(p, (size_t)st.st_size);
	}
	if (lseek(fd, 0, SEEK_SET) == -1)
		err(1, "lseek");
	while ((r = read(fd, buf, sizeof(buf))) > 0)
		(void)write(STDOUT_FILENO, buf, (size_t)r);
	if (r == -1)
		err(1, "read served descriptor");
}

static void
usage(void)
{

	fprintf(stderr, "usage: dqserve file word-to-redact\n"
	    "       dqserve -w file\n");
	exit(2);
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
	const char *file, *word;
	ssize_t n;
	off_t off;
	int ch, q, reason, writable;
	pid_t pid;

	writable = 0;
	while ((ch = getopt(argc, argv, "w")) != -1) {
		switch (ch) {
		case 'w':
			writable = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != (writable ? 1 : 2))
		usage();
	file = argv[0];
	word = writable ? NULL : argv[1];

	/* Take the file's identity. */
	memset(&s, 0, sizeof(s));
	s.backing = open(file, writable ? O_RDWR : O_RDONLY);
	if (s.backing == -1)
		err(1, "open %s", file);
	if (fstat(s.backing, &st) == -1)
		err(1, "fstat");
	if (fstatfs(s.backing, &sfs) == -1)
		err(1, "fstatfs");
	if (realpath(file, path) == NULL)
		err(1, "realpath %s", file);
	ident = calloc(1, sizeof(*ident));
	if (ident == NULL)
		err(1, "calloc");
	if (dq_ident_from_stat(ident, path, &st, &sfs, s.backing) == -1)
		err(1, "dq_ident_from_stat");

	if (!writable) {
		/* Read the file and redact the copy. */
		s.len = (size_t)st.st_size;
		s.data = malloc(s.len != 0 ? s.len : 1);
		if (s.data == NULL)
			err(1, "malloc");
		for (off = 0; (size_t)off < s.len; off += n) {
			n = pread(s.backing, s.data + off, s.len - (size_t)off,
			    off);
			if (n <= 0)
				err(1, "read %s", file);
		}
		redact(s.data, s.len, word);
	}

	/* Open the queue and mint the object. */
	q = dq_open();
	if (q == -1)
		err(1, "dq_open (%s)", DQ_DEVICE);
	dq_policy_default(&pol);
	pol.dp_events = DQ_EVENTS_CLOSE;
	if (writable) {
		pol.dp_write = DQ_EVENT;
		pol.dp_mmap_shared_write = DQ_ALLOW;
		pol.dp_events |= DQ_EVENTS_GETATTR;
		/* Lock owners, and the identity copy SETIDENT refreshes. */
		s.opts.so_state = dq_serve_state_create();
		if (s.opts.so_state == NULL)
			err(1, "dq_serve_state_create");
		s.opts.so_ident = ident;
		s.opts.so_flags = DQ_SERVE_F_SYNC_IDENT;
	}
	if (dq_mint_file_flags(q, ident, &pol, writable ? DQ_MINT_F_WRITE : 0,
	    &s.object, &s.fd, &reason) == -1)
		err(1, "dq_mint_file (reason %d)", reason);

	/* The child inherits the served descriptor, not the queue. */
	pid = fork();
	if (pid == -1)
		err(1, "fork");
	if (pid == 0) {
		unsigned char buf[4096];
		ssize_t r;

		(void)close(q);		/* no child has the queue: EBADF */
		if (writable)
			writable_child(s.fd);
		else {
			while ((r = read(s.fd, buf, sizeof(buf))) > 0)
				(void)write(STDOUT_FILENO, buf, (size_t)r);
			if (r == -1)
				err(1, "read served descriptor");
		}
		(void)close(s.fd);
		_exit(0);
	}
	(void)close(s.fd);		/* the controller keeps only the queue */

	/* Serve until the child closes the descriptor (DQ_OP_CLOSE). */
	while (!s.done) {
		if (dq_dispatch(q, writable ? serve_handler : handler, &s) == -1)
			err(1, "dq_dispatch");
	}
	(void)waitpid(pid, NULL, 0);
	(void)close(q);
	dq_serve_state_destroy(s.opts.so_state);
	(void)close(s.backing);
	free(ident);
	free(s.data);
	return (0);
}
