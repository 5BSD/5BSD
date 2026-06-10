/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * oraclectl — command-line interface to oracled(8).
 *
 * Thin CLI wrapper around liboraclectl.  Each invocation opens a
 * connection, sends one command, prints the result, and exits.
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <oraclectl.h>

static const char *sockpath;

static int
open_or_die(void)
{
	int fd;

	fd = oraclectl_open(sockpath);
	if (fd == -1)
		err(EX_UNAVAILABLE, "connect %s",
		    sockpath != NULL ? sockpath : ORACLED_CTL_SOCK);
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
	struct oraclectl_status st;
	char summary[ORACLECTL_SUMMARY_MAX];
	uint64_t up;
	int fd, error;

	fd = open_or_die();
	error = oraclectl_status(fd, &st, summary, sizeof(summary));
	close(fd);

	if (error != 0)
		return (check(error, "status"));

	up = st.uptime_usec;
	printf("oracled: running\n");
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
	error = oraclectl_shutdown(fd);
	close(fd);

	if (error != 0)
		return (check(error, "shutdown"));
	printf("oracled: shutdown initiated\n");
	return (0);
}

static int
cmd_reload(void)
{
	char summary[ORACLECTL_SUMMARY_MAX];
	int fd, error;

	fd = open_or_die();
	error = oraclectl_reload(fd, summary, sizeof(summary));
	close(fd);

	if (error != 0)
		return (check(error, "reload"));
	if (summary[0] != '\0')
		printf("%s", summary);
	else
		printf("reload: no changes\n");
	return (0);
}

static int
cmd_verify(void)
{
	char summary[ORACLECTL_SUMMARY_MAX];
	int fd, error;

	fd = open_or_die();
	error = oraclectl_verify(fd, summary, sizeof(summary));
	close(fd);

	if (error != 0)
		return (check(error, "verify"));
	if (summary[0] != '\0')
		printf("%s", summary);
	return (0);
}

static int
cmd_services(int verbose)
{
	char summary[ORACLECTL_SUMMARY_MAX];
	int fd, error;

	fd = open_or_die();
	error = oraclectl_services(fd, (uint32_t)verbose, summary,
	    sizeof(summary));
	close(fd);

	if (error != 0)
		return (check(error, "services"));
	if (summary[0] != '\0')
		printf("%s", summary);
	return (0);
}

static int
cmd_check(const char *filename)
{
	char summary[ORACLECTL_SUMMARY_MAX];
	int fd, error;

	fd = open_or_die();
	error = oraclectl_check(fd, filename, summary, sizeof(summary));
	close(fd);

	if (error != 0)
		return (check(error, "check"));
	if (summary[0] != '\0')
		printf("%s", summary);
	else
		printf("check: ok\n");
	return (0);
}

static int
cmd_load(const char *filename)
{
	char summary[ORACLECTL_SUMMARY_MAX];
	int fd, error;

	fd = open_or_die();
	error = oraclectl_load(fd, filename, summary, sizeof(summary));
	close(fd);

	if (error != 0)
		return (check(error, "load"));
	if (summary[0] != '\0')
		printf("%s", summary);
	else
		printf("load: ok\n");
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
	    "usage: oraclectl [-s socket] command [args]\n"
	    "       oraclectl status\n"
	    "       oraclectl services [-v]\n"
	    "       oraclectl check <filename>\n"
	    "       oraclectl load <filename>\n"
	    "       oraclectl verify\n"
	    "       oraclectl reload\n"
	    "       oraclectl shutdown\n");
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
	if (strcmp(argv[0], "services") == 0 && argc == 1)
		return (cmd_services(0));
	if (strcmp(argv[0], "services") == 0 && argc == 2 &&
	    strcmp(argv[1], "-v") == 0)
		return (cmd_services(1));
	if (strcmp(argv[0], "check") == 0 && argc == 2)
		return (cmd_check(argv[1]));
	if (strcmp(argv[0], "load") == 0 && argc == 2)
		return (cmd_load(argv[1]));
	if (strcmp(argv[0], "verify") == 0 && argc == 1)
		return (cmd_verify());
	if (strcmp(argv[0], "shutdown") == 0 && argc == 1)
		return (cmd_shutdown());
	if (strcmp(argv[0], "reload") == 0 && argc == 1)
		return (cmd_reload());

	usage();
	return (EX_USAGE);
}
