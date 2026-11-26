/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * rc_pin_daemon: the daemon of the rc routing pins' fixture rc.d scripts.
 *
 * usage: rc_pin_daemon -p pidfile
 *
 * It daemonizes as a classic rc daemon does, with a double fork: the
 * start command's child starts a session and forks the daemon, then exits,
 * so the daemon is an orphan whose parent is whoever reaps orphans.  The
 * start command exits only once the daemon has written its pid to the
 * pidfile, so the pid is there when rc.subr's start returns.  The daemon
 * then waits for a signal.  SIGTERM, the default of
 * rc.subr's stop, ends it.  It never times out: the test that started it
 * stops it.
 */

#include <err.h>
#include <fcntl.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libutil.h>

static void
usage(void)
{

	fprintf(stderr, "usage: rc_pin_daemon -p pidfile\n");
	exit(2);
}

int
main(int argc, char *argv[])
{
	struct pidfh *pfh;
	const char *path;
	sigset_t set;
	int ch, fd, ready[2], sig;
	char c;

	path = NULL;
	while ((ch = getopt(argc, argv, "p:")) != -1) {
		switch (ch) {
		case 'p':
			path = optarg;
			break;
		default:
			usage();
		}
	}
	if (path == NULL || optind != argc)
		usage();

	pfh = pidfile_open(path, 0600, NULL);
	if (pfh == NULL)
		err(1, "pidfile_open %s", path);
	if (pipe(ready) == -1)
		err(1, "pipe");
	switch (fork()) {
	case -1:
		err(1, "fork");
	case 0:
		break;
	default:
		/* The daemon's byte, or end of file if it failed. */
		close(ready[1]);
		return (read(ready[0], &c, 1) == 1 ? 0 : 1);
	}
	close(ready[0]);
	if (setsid() == -1)
		err(1, "setsid");
	/*
	 * Fork again and let the session leader exit: the daemon is a
	 * double-fork orphan, whose parent is whoever reaps orphans.
	 */
	switch (fork()) {
	case -1:
		err(1, "fork");
	case 0:
		break;
	default:
		_exit(0);
	}
	if (chdir("/") == -1)
		err(1, "chdir");
	if (pidfile_write(pfh) == -1)
		err(1, "pidfile_write %s", path);
	if ((fd = open(_PATH_DEVNULL, O_RDWR)) == -1)
		err(1, "%s", _PATH_DEVNULL);
	if (dup2(fd, STDIN_FILENO) == -1 || dup2(fd, STDOUT_FILENO) == -1 ||
	    dup2(fd, STDERR_FILENO) == -1)
		err(1, "dup2");
	if (fd > STDERR_FILENO)
		close(fd);
	c = 'r';
	if (write(ready[1], &c, 1) != 1)
		return (1);
	close(ready[1]);

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);
	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
		err(1, "sigprocmask");
	if (sigwait(&set, &sig) != 0)
		err(1, "sigwait");
	pidfile_remove(pfh);
	return (0);
}
