/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The 5BSD Project
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_dn_flow.h>
#include <netinet/ip_dummynet.h>
#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include "dnctl.h"

struct cmdline_opts g_co;

static void
usage(int status)
{
	fprintf(stderr, "usage: dnctl [-fnqv] [-s sort] "
	    "{pipe|queue|sched} [number] {config|delete|list|show|flush} ...\n"
	    "       dnctl [-fnqv] /absolute/config/file\n");
	exit(status);
}

static void
command(int ac, char **av)
{
	char *tmp, *end;
	long id;
	int ch, error = 0;

	optind = optreset = 1;
	while ((ch = getopt(ac, av, "fhnqs:v")) != -1) {
		switch (ch) {
		case 'f': g_co.do_force = 1; break;
		case 'h': usage(EX_OK); break;
		case 'n': g_co.test_only = 1; break;
		case 'q': g_co.do_quiet = 1; break;
		case 's': g_co.do_sort = atoi(optarg); break;
		case 'v': g_co.verbose = 1; break;
		default: usage(EX_USAGE);
		}
	}
	ac -= optind;
	av += optind;
	if (ac < 2)
		usage(EX_USAGE);
	if (strcmp(av[0], "pipe") == 0)
		g_co.do_pipe = 1;
	else if (strcmp(av[0], "queue") == 0 ||
	    strcmp(av[0], "flowset") == 0)
		g_co.do_pipe = 2;
	else if (strcmp(av[0], "sched") == 0)
		g_co.do_pipe = 3;
	else
		errx(EX_USAGE, "expected pipe, queue or sched: %s", av[0]);
	av++; ac--;
	if (ac > 1 && isdigit((unsigned char)av[0][0])) {
		tmp = av[0]; av[0] = av[1]; av[1] = tmp;
	}
	if (strcmp(av[0], "config") == 0) {
		ipfw_config_pipe(ac, av);
	} else if (strcmp(av[0], "list") == 0 ||
	    strcmp(av[0], "show") == 0 || strcmp(av[0], "print") == 0) {
		if (g_co.test_only)
			fprintf(stderr, "Testing only, list disabled\n");
		else
			dummynet_list(ac, av, strcmp(av[0], "show") == 0);
	} else if (strcmp(av[0], "delete") == 0) {
		if (ac < 2)
			errx(EX_USAGE, "missing object number");
		/* Validate the entire request before deleting any objects. */
		for (int i = 1; i < ac; i++) {
			id = strtol(av[i], &end, 10);
			if (*av[i] == '\0' || *end != '\0' ||
			    id <= 0 || id >= DN_MAX_ID - 1)
				errx(EX_DATAERR, "invalid object number: %s", av[i]);
		}
		for (int i = 1; i < ac; i++)
			error |= ipfw_delete_pipe(g_co.do_pipe, atoi(av[i]));
		if (error)
			exit(EX_UNAVAILABLE);
	} else if (strcmp(av[0], "flush") == 0) {
		if (ac != 1)
			errx(EX_USAGE, "unexpected flush argument");
		if (!g_co.do_force && isatty(STDIN_FILENO)) {
			fprintf(stderr, "Flush all Dummynet objects? [y/N] ");
			ch = getchar();
			if (ch != 'y' && ch != 'Y')
				return;
		}
		dummynet_flush();
	} else {
		errx(EX_USAGE, "unknown Dummynet command: %s", av[0]);
	}
}

static void
line(char *text)
{
	char **av = NULL, *word;
	char progname[] = "dnctl";
	int ac = 1;

	av = safe_calloc(2, sizeof(*av));
	av[0] = progname;
	while ((word = strsep(&text, " \t\r\n")) != NULL) {
		if (*word == '#')
			break;
		if (*word == '\0')
			continue;
		av = safe_realloc(av, (ac + 2) * sizeof(*av));
		av[ac++] = word;
	}
	av[ac] = NULL;
	if (ac > 1)
		command(ac, av);
	free(av);
}

int
main(int ac, char **av)
{
	FILE *fp;
	char *text = NULL;
	size_t cap = 0;

	if (ac > 1 && av[ac - 1][0] == '/') {
		/* File-level options apply to every command in the file. */
		for (int i = 1; i < ac - 1; i++) {
			if (strcmp(av[i], "-n") == 0) g_co.test_only = 1;
			else if (strcmp(av[i], "-f") == 0) g_co.do_force = 1;
			else if (strcmp(av[i], "-q") == 0) g_co.do_quiet = 1;
			else if (strcmp(av[i], "-v") == 0) g_co.verbose = 1;
			else usage(EX_USAGE);
		}
		fp = fopen(av[ac - 1], "r");
		if (fp == NULL)
			err(EX_NOINPUT, "%s", av[ac - 1]);
		while (getline(&text, &cap, fp) != -1)
			line(text);
		if (ferror(fp))
			err(EX_IOERR, "%s", av[ac - 1]);
		free(text);
		fclose(fp);
	} else if (ac == 2 && strpbrk(av[1], " \t") != NULL) {
		line(av[1]);
	} else {
		command(ac, av);
	}
	return (EX_OK);
}
