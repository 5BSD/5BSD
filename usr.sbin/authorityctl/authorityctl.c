/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * authorityctl — command-line interface to authorityd(8).
 *
 * Thin CLI wrapper around libauthorityctl.  Each invocation opens a
 * connection, sends one command, prints the result, and exits.
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <authorityctl.h>

static const char *sockpath;

static int
open_or_die(void)
{
	int fd;

	fd = authorityctl_open(sockpath);
	if (fd == -1)
		err(EX_UNAVAILABLE, "connect %s",
		    sockpath != NULL ? sockpath : AUTHORITYD_CTL_SOCK);
	return (fd);
}

static int
check(int error, const char *cmd)
{

	if (error == 0)
		return (0);
	warnx("%s: %s", cmd, strerror(error));
	return (error == EPERM ? EX_NOPERM : 1);
}

/* ----------------------------------------------------------------
 * Commands
 * ---------------------------------------------------------------- */

static int
cmd_status(void)
{
	struct authorityctl_status st;
	char summary[AUTHORITYCTL_SUMMARY_MAX];
	uint64_t up;
	int fd, error;

	fd = open_or_die();
	error = authorityctl_status(fd, &st, summary, sizeof(summary));
	close(fd);

	if (error != 0)
		return (check(error, "status"));

	up = st.uptime_usec;
	printf("authorityd: running\n");
	if (up < 1000000ULL)
		printf("uptime:  %llu ms\n",
		    (unsigned long long)(up / 1000));
	else if (up < 60000000ULL)
		printf("uptime:  %llu seconds\n",
		    (unsigned long long)(up / 1000000));
	else if (up < 3600000000ULL)
		printf("uptime:  %llu minutes\n",
		    (unsigned long long)(up / 60000000));
	else
		printf("uptime:  %llu hours\n",
		    (unsigned long long)(up / 3600000000ULL));

	if (summary[0] != '\0')
		printf("\n%s", summary);
	return (0);
}

static int
cmd_shutdown(void)
{
	int fd, error;

	fd = open_or_die();
	error = authorityctl_shutdown(fd);
	close(fd);

	if (error != 0)
		return (check(error, "shutdown"));
	printf("authorityd: shutdown initiated\n");
	return (0);
}

static int
cmd_reload(void)
{
	char summary[AUTHORITYCTL_SUMMARY_MAX];
	int fd, error;

	fd = open_or_die();
	error = authorityctl_reload(fd, summary, sizeof(summary));
	close(fd);

	if (error != 0)
		return (check(error, "reload"));
	if (summary[0] != '\0')
		printf("%s", summary);
	else
		printf("reload: no changes\n");
	return (0);
}
/* ----------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------- */

static void usage(void) __dead2;

static void
usage(void)
{

	fprintf(stderr,
	    "usage: authorityctl [-s socket] command\n"
	    "       authorityctl status\n"
	    "       authorityctl reload\n"
	    "       authorityctl shutdown\n");
	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			sockpath = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	if (strcmp(argv[0], "status") == 0 && argc == 1)
		return (cmd_status());
	if (strcmp(argv[0], "shutdown") == 0 && argc == 1)
		return (cmd_shutdown());
	if (strcmp(argv[0], "reload") == 0 && argc == 1)
		return (cmd_reload());

	usage();
	return (EX_USAGE);
}
