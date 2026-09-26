/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * reclaimstat -- show what each capability provider is managing.
 *
 * Every reconcile client (docs/book/src/plane/containers-and-storage.md) records, after
 * each pass, the set of bundles whose resources it currently holds -- plus the
 * pass's counts -- to /var/run/reclaim/<provider> via libcapreclaim.  This
 * reads those records and prints, per provider, what it manages and how its
 * last reconcile went.  No live query: the records are the providers' own
 * durable statements, so this works even for a sandboxed, capability-mode
 * provider that an operator cannot otherwise inspect.
 */
#include <sys/types.h>

#include <dirent.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "capreclaim.h"

static void
usage(void)
{
	(void)fprintf(stderr, "usage: reclaimstat [-a]\n"
	    "    -a  also list each provider's orphans (awaiting the grace)\n");
	exit(2);
}

/* Print one provider's record.  Returns 0 on success. */
static int
show(const char *dir, const char *name, bool orphans)
{
	char path[1024], line[256];
	FILE *f;
	char pass[32] = "?";
	char counts[160] = "";
	unsigned nmanage = 0;

	if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path))
		return (-1);
	f = fopen(path, "r");
	if (f == NULL)
		return (-1);
	/* First pass: header + count the managed set. */
	while (fgets(line, sizeof(line), f) != NULL) {
		line[strcspn(line, "\n")] = '\0';
		if (strncmp(line, "pass ", 5) == 0)
			(void)snprintf(pass, sizeof(pass), "%.31s", line + 5);
		else if (strncmp(line, "counts ", 7) == 0)
			(void)snprintf(counts, sizeof(counts), "%.159s", line + 7);
		else if (strncmp(line, "manage ", 7) == 0)
			nmanage++;
	}
	(void)strtok(pass, " ");	/* "boot"/"timer" only, drop "at ..." */
	printf("%-16s %u managed   [last %s pass: %s]\n", name, nmanage, pass,
	    counts[0] != '\0' ? counts : "(no pass yet)");
	/* Second pass: the names. */
	rewind(f);
	while (fgets(line, sizeof(line), f) != NULL) {
		line[strcspn(line, "\n")] = '\0';
		if (strncmp(line, "manage ", 7) == 0)
			printf("    %s\n", line + 7);
		else if (orphans && strncmp(line, "orphan ", 7) == 0)
			printf("    (orphan, awaiting grace) %s\n", line + 7);
	}
	(void)fclose(f);
	return (0);
}

int
main(int argc, char **argv)
{
	DIR *d;
	struct dirent *de;
	bool orphans = false, any = false;
	int ch, shown = 0;

	while ((ch = getopt(argc, argv, "a")) != -1) {
		switch (ch) {
		case 'a':
			orphans = true;
			break;
		default:
			usage();
		}
	}
	if (argc != optind)
		usage();

	d = opendir(CAPRECLAIM_STATUS_DIR);
	if (d == NULL) {
		if (errno == ENOENT) {
			printf("no reconcile records yet (%s absent): no provider "
			    "has run a reconcile pass\n", CAPRECLAIM_STATUS_DIR);
			return (0);
		}
		err(1, "%s", CAPRECLAIM_STATUS_DIR);
	}
	while ((de = readdir(d)) != NULL) {
		size_t len = strlen(de->d_name);

		if (de->d_name[0] == '.')
			continue;
		/* Skip a rename-in-progress temp file. */
		if (len > 4 && strcmp(de->d_name + len - 4, ".tmp") == 0)
			continue;
		any = true;
		if (show(CAPRECLAIM_STATUS_DIR, de->d_name, orphans) == 0)
			shown++;
	}
	(void)closedir(d);
	if (!any)
		printf("no reconcile records in %s\n", CAPRECLAIM_STATUS_DIR);
	return (shown == 0 && any ? 1 : 0);
}
