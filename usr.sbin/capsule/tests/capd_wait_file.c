/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * capd_wait_file PATH [TEXT]: wait, without a deadline and without polling,
 * until PATH exists and is not empty, or (with TEXT) until PATH contains
 * TEXT.  The wait is a kqueue on the file's directory (a new entry) and then
 * on the file (writes and growth); the test case's ATF timeout bounds it.
 * Exits 0 when the condition holds, 1 on an error.
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

/* Whether the file now satisfies the wait; a missing file does not. */
static bool
satisfied(const char *path, const char *text)
{
	struct stat sb;
	char *buf;
	ssize_t n;
	bool found;
	int fd;

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
	int dfd, ffd, kq, n;

	if (argc != 2 && argc != 3) {
		fprintf(stderr, "usage: capd_wait_file path [text]\n");
		return (1);
	}
	path = argv[1];
	text = argc == 3 ? argv[2] : NULL;
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
	ffd = -1;
	for (;;) {
		/* Watch the file once it exists; re-check after registering. */
		if (ffd == -1) {
			ffd = open(path, O_RDONLY | O_CLOEXEC);
			if (ffd != -1) {
				EV_SET(&kev[1], ffd, EVFILT_VNODE,
				    EV_ADD | EV_CLEAR, NOTE_WRITE | NOTE_EXTEND,
				    0, NULL);
				if (kevent(kq, &kev[1], 1, NULL, 0, NULL) == -1)
					err(1, "kevent");
			} else if (errno != ENOENT)
				err(1, "%s", path);
		}
		if (satisfied(path, text))
			return (0);
		n = kevent(kq, NULL, 0, &ev, 1, NULL);
		if (n == -1 && errno != EINTR)
			err(1, "kevent");
	}
}
