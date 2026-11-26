/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * capd_wait_file [-e] [-p pid] PATH [TEXT]: wait, without a deadline and
 * without polling, until PATH exists and is not empty, or (with TEXT) until
 * PATH contains TEXT, or (with -e) until PATH exists, whatever its type and
 * size (a socket, for example).  The wait is a kqueue on the file's
 * directory (a new entry) and then on the file (writes and growth); when the
 * watched file is removed or renamed away, the wait goes back to the
 * directory and the path's current file.  With -p, the wait also ends when
 * process PID exits (or is already gone), and then fails unless the
 * condition holds by then.  The test case's ATF timeout bounds it.
 * Exits 0 when the condition holds, 2 when PID exited first, 1 on an error.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
usage(void)
{

	fprintf(stderr, "usage: capd_wait_file [-e] [-p pid] path [text]\n");
	exit(1);
}

/* Whether the file now satisfies the wait; a missing file does not. */
static bool
satisfied(const char *path, const char *text, bool exists)
{
	struct stat sb;
	char *buf;
	ssize_t n;
	bool found;
	int fd;

	if (exists) {
		if (lstat(path, &sb) == 0)
			return (true);
		if (errno == ENOENT)
			return (false);
		err(1, "%s", path);
	}
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		if (errno == ENOENT)
			return (false);
		err(1, "%s", path);
	}
	if (fstat(fd, &sb) == -1)
		err(1, "%s", path);
	if (text == NULL) {
		close(fd);
		return (sb.st_size > 0);
	}
	buf = malloc((size_t)sb.st_size + 1);
	if (buf == NULL)
		err(1, "malloc");
	n = pread(fd, buf, (size_t)sb.st_size, 0);
	if (n == -1)
		err(1, "%s", path);
	buf[n] = '\0';
	found = strstr(buf, text) != NULL;
	free(buf);
	close(fd);
	return (found);
}

int
main(int argc, char **argv)
{
	struct kevent kev[2], ev;
	char dirbuf[PATH_MAX];
	const char *path, *text;
	char *end;
	long pid;
	bool exists;
	int ch, dfd, ffd, kq, n;

	exists = false;
	pid = -1;
	while ((ch = getopt(argc, argv, "ep:")) != -1) {
		switch (ch) {
		case 'e':
			exists = true;
			break;
		case 'p':
			errno = 0;
			pid = strtol(optarg, &end, 10);
			if (errno != 0 || end == optarg || *end != '\0' ||
			    pid <= 0)
				errx(1, "invalid pid: %s", optarg);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1 && argc != 2)
		usage();
	path = argv[0];
	text = argc == 2 ? argv[1] : NULL;
	if (exists && text != NULL)
		usage();
	if (strlcpy(dirbuf, path, sizeof(dirbuf)) >= sizeof(dirbuf))
		errx(1, "path too long");
	kq = kqueue();
	if (kq == -1)
		err(1, "kqueue");
	dfd = open(dirname(dirbuf), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd == -1)
		err(1, "%s", dirbuf);
	EV_SET(&kev[0], dfd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE, 0,
	    NULL);
	if (kevent(kq, kev, 1, NULL, 0, NULL) == -1)
		err(1, "kevent");
	if (pid != -1) {
		EV_SET(&kev[0], (uintptr_t)pid, EVFILT_PROC, EV_ADD, NOTE_EXIT,
		    0, NULL);
		if (kevent(kq, kev, 1, NULL, 0, NULL) == -1) {
			if (errno != ESRCH)
				err(1, "kevent pid %ld", pid);
			/* Already gone: the condition must hold now. */
			if (satisfied(path, text, exists))
				return (0);
			warnx("process %ld is gone and %s %s", pid, path,
			    text != NULL ? "lacks the text" : "is not there");
			return (2);
		}
	}
	ffd = -1;
	for (;;) {
		/*
		 * Watch the file once it exists; re-check after registering.
		 * Existence alone needs only the directory, and the path may
		 * name something open(2) refuses, such as a socket.
		 */
		if (ffd == -1 && !exists) {
			ffd = open(path, O_RDONLY | O_CLOEXEC);
			if (ffd != -1) {
				EV_SET(&kev[1], ffd, EVFILT_VNODE,
				    EV_ADD | EV_CLEAR, NOTE_WRITE | NOTE_EXTEND |
				    NOTE_DELETE | NOTE_RENAME, 0, NULL);
				if (kevent(kq, &kev[1], 1, NULL, 0, NULL) == -1)
					err(1, "kevent");
			} else if (errno != ENOENT)
				err(1, "%s", path);
		}
		if (satisfied(path, text, exists))
			return (0);
		n = kevent(kq, NULL, 0, &ev, 1, NULL);
		if (n == -1 && errno != EINTR)
			err(1, "kevent");
		if (n == 1 && ev.filter == EVFILT_PROC) {
			/* Whatever it wrote before it exited is there now. */
			if (satisfied(path, text, exists))
				return (0);
			warnx("process %ld exited and %s %s", pid, path,
			    text != NULL ? "lacks the text" : "is not there");
			return (2);
		}
		/*
		 * The watched file left the path (removed, or replaced by a
		 * rename): stop watching it (close drops its event) and look
		 * the path up again.  The directory event stays armed, so a
		 * replacement created later is seen.
		 */
		if (n == 1 && ffd != -1 && ev.ident == (uintptr_t)ffd &&
		    (ev.fflags & (NOTE_DELETE | NOTE_RENAME)) != 0) {
			close(ffd);
			ffd = -1;
		}
	}
}
