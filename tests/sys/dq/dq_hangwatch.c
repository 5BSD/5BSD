/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * dq_hangwatch: wait, event-driven, for a kyua run to stop making progress
 * (dq_hang.subr, T-R11, T-R12; owner 2026-11-19: no polling).
 *
 *   dq_hangwatch tmpdir pid seconds
 *
 * Progress is a new entry in tmpdir (kyua's work directory, kyua.XXXXXX,
 * appears there) or in one of the kyua.* directories under it (each case
 * gets a numbered work directory of its own): EVFILT_VNODE NOTE_WRITE and
 * NOTE_EXTEND on each.  The run is over when pid, the top of the watched
 * tree, exits (EVFILT_PROC NOTE_EXIT).  A stall is the deadline: an
 * EVFILT_TIMER of the given seconds, armed again at each progress event.
 * Nothing is looked at on a timer of its own.
 *
 * Each event is a line on stdout.  Exit 0: pid exited.  Exit 2: the
 * deadline passed with no progress (the caller captures the tree).
 * Exit 1: an error.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/stat.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int kq;
static size_t nwatch, maxwatch;
static struct watched {
	dev_t	dev;
	ino_t	ino;
} *watched;

static void
stamp(const char *what, const char *name)
{
	char buf[32];
	time_t now;

	now = time(NULL);
	strftime(buf, sizeof(buf), "%T", gmtime(&now));
	printf("%s %s %s\n", buf, what, name);
	fflush(stdout);
}

/* Watch directory path for new entries, once per directory. */
static void
watch_dir(const char *path)
{
	struct kevent kev;
	struct stat sb;
	size_t i;
	int fd;

	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd == -1)
		return;		/* gone already: kyua cleaned it up */
	if (fstat(fd, &sb) == -1)
		err(1, "fstat %s", path);
	for (i = 0; i < nwatch; i++) {
		if (watched[i].dev == sb.st_dev &&
		    watched[i].ino == sb.st_ino) {
			(void)close(fd);
			return;
		}
	}
	if (nwatch == maxwatch) {
		maxwatch = maxwatch == 0 ? 8 : 2 * maxwatch;
		watched = reallocarray(watched, maxwatch, sizeof(*watched));
		if (watched == NULL)
			err(1, "reallocarray");
	}
	watched[nwatch].dev = sb.st_dev;
	watched[nwatch].ino = sb.st_ino;
	nwatch++;
	EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	    NOTE_WRITE | NOTE_EXTEND, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		err(1, "kevent %s", path);
	stamp("watch", path);
}

/* The kyua.* directories under tmpdir. */
static void
watch_kyua_dirs(const char *tmpdir)
{
	char path[PATH_MAX];
	struct dirent *de;
	DIR *d;

	d = opendir(tmpdir);
	if (d == NULL)
		err(1, "opendir %s", tmpdir);
	while ((de = readdir(d)) != NULL) {
		if (strncmp(de->d_name, "kyua.", 5) != 0)
			continue;
		(void)snprintf(path, sizeof(path), "%s/%s", tmpdir,
		    de->d_name);
		watch_dir(path);
	}
	(void)closedir(d);
}

static void
arm_deadline(int64_t secs)
{
	struct kevent kev;

	EV_SET(&kev, 1, EVFILT_TIMER, EV_ADD | EV_ONESHOT, NOTE_SECONDS, secs,
	    NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		err(1, "kevent timer");
}

int
main(int argc, char **argv)
{
	struct kevent kev;
	const char *tmpdir;
	char *end;
	int64_t secs;
	pid_t pid;

	if (argc != 4)
		errx(1, "usage: dq_hangwatch tmpdir pid seconds");
	tmpdir = argv[1];
	pid = (pid_t)strtol(argv[2], &end, 10);
	if (*end != '\0' || pid <= 0)
		errx(1, "bad pid %s", argv[2]);
	secs = strtoll(argv[3], &end, 10);
	if (*end != '\0' || secs <= 0)
		errx(1, "bad seconds %s", argv[3]);
	kq = kqueue();
	if (kq == -1)
		err(1, "kqueue");
	EV_SET(&kev, pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		if (errno == ESRCH)
			return (0);	/* already over */
		err(1, "kevent proc");
	}
	watch_dir(tmpdir);
	watch_kyua_dirs(tmpdir);
	arm_deadline(secs);
	for (;;) {
		if (kevent(kq, NULL, 0, &kev, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "kevent");
		}
		switch (kev.filter) {
		case EVFILT_PROC:
			stamp("exit", argv[2]);
			return (0);
		case EVFILT_TIMER:
			stamp("deadline", argv[3]);
			return (2);
		case EVFILT_VNODE:
			stamp("progress", "");
			/* A new kyua.* directory is progress to watch. */
			watch_kyua_dirs(tmpdir);
			arm_deadline(secs);
			break;
		}
	}
}
