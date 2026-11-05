/*
 * ht-sockpair: connect a bhyve migration destination and source over one
 * AF_UNIX SOCK_STREAM socketpair (the same-host plaintext_unix opt-in, or
 * TLS over the same pair).  Each command receives its end as fd 3.
 *
 *   ht-sockpair [-p dstpidfile] [-f readyfile] [-t seconds] \
 *       DST-CMD ... -- SRC-CMD ...
 *
 * The destination is started first and left running (its pid is written
 * to dstpidfile).  The source starts once readyfile exists (or after
 * -t seconds, default 2) and ht-sockpair exits with the source's status.
 */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static pid_t
spawn(char **argv, int keep, int drop)
{
	pid_t pid;

	pid = fork();
	if (pid == -1)
		err(1, "fork");
	if (pid == 0) {
		close(drop);
		if (keep != 3) {
			if (dup2(keep, 3) == -1)
				err(127, "dup2");
			close(keep);
		}
		execvp(argv[0], argv);
		err(127, "exec %s", argv[0]);
	}
	return (pid);
}

int
main(int argc, char **argv)
{
	const char *pidfile = NULL, *ready = NULL;
	char **dst, **src;
	struct stat sb;
	int ch, i, sp[2], status, wait_s = 2;
	pid_t dpid, spid;
	FILE *f;

	while ((ch = getopt(argc, argv, "f:p:t:")) != -1) {
		switch (ch) {
		case 'f': ready = optarg; break;
		case 'p': pidfile = optarg; break;
		case 't': wait_s = atoi(optarg); break;
		default:
			fprintf(stderr, "usage: ht-sockpair [-p pidfile] [-f readyfile] "
			    "[-t seconds] DST-CMD ... -- SRC-CMD ...\n");
			return (2);
		}
	}
	argc -= optind;
	argv += optind;
	dst = argv;
	src = NULL;
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			argv[i] = NULL;
			src = &argv[i + 1];
			break;
		}
	}
	if (dst[0] == NULL || src == NULL || src[0] == NULL)
		errx(2, "need DST-CMD -- SRC-CMD");
	/* Keep fds 0-3 from colliding with the pair. */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		err(1, "socketpair");
	while (sp[0] <= 3 || sp[1] <= 3) {
		int a = fcntl(sp[0], F_DUPFD, 10), b = fcntl(sp[1], F_DUPFD, 10);
		close(sp[0]); close(sp[1]);
		sp[0] = a; sp[1] = b;
	}
	dpid = spawn(dst, sp[0], sp[1]);
	if (pidfile != NULL && (f = fopen(pidfile, "w")) != NULL) {
		fprintf(f, "%d\n", (int)dpid);
		fclose(f);
	}
	close(sp[0]);
	for (i = 0; i < wait_s * 10; i++) {
		if (ready != NULL && stat(ready, &sb) == 0)
			break;
		if (waitpid(dpid, &status, WNOHANG) == dpid)
			errx(1, "destination exited early (status %d)", status);
		usleep(100000);
	}
	spid = spawn(src, sp[1], -1);
	close(sp[1]);
	if (waitpid(spid, &status, 0) == -1)
		err(1, "waitpid");
	return (WIFEXITED(status) ? WEXITSTATUS(status) : 128);
}
