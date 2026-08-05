/*- SPDX-License-Identifier: BSD-2-Clause */

#include <sys/param.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <kldmgr.h>

#include "kldmgrd_policy.h"

static void usage(void) __dead2;

static void
usage(void)
{
	fprintf(stderr, "usage: kldmgrctl configtest [file]\n"
	    "       kldmgrctl list\n"
	    "       kldmgrctl load module\n"
	    "       kldmgrctl unload module\n");
	exit(EX_USAGE);
}

int
main(int argc, char **argv)
{
	struct kldmgr_list_entry entries[KLDMGR_LIST_MAX];
	struct kldmgrd_policy policy;
	struct kldmgr_client *client;
	const char *path;
	const char *operation;
	int id, error;
	size_t count, i;

	if (argc >= 2 && strcmp(argv[1], "configtest") == 0 && argc <= 3) {
		path = argc == 3 ? argv[2] : KLDMGRD_POLICY_PATH;
		if (kldmgrd_policy_load(path, &policy) == -1)
			err(EX_DATAERR, "%s", path);
		printf("%s: valid (labels=%zu, default=%s)\n", path, policy.count,
		    policy.count == 0 ? "deny" : "explicit-allow");
		return (0);
	}
	if (argc == 2 && strcmp(argv[1], "list") == 0) {
		if (kldmgr_client_open(&client) == -1)
			err(EX_UNAVAILABLE, "open %s", KLDMGR_INTERFACE);
		if (kldmgr_list(client, entries, nitems(entries), &count) == -1) {
			error = errno;

			kldmgr_client_close(client);
			errno = error;
			err(EX_UNAVAILABLE, "list");
		}
		kldmgr_client_close(client);
		for (i = 0; i < count; i++)
			printf("%d\t%s\n", entries[i].id, entries[i].name);
		return (0);
	}
	if (argc == 3 && (strcmp(argv[1], "load") == 0 ||
	    strcmp(argv[1], "unload") == 0)) {
		operation = argv[1];
		if (kldmgr_client_open(&client) == -1)
			err(EX_UNAVAILABLE, "open %s", KLDMGR_INTERFACE);
		if ((strcmp(operation, "load") == 0 ?
		    kldmgr_load(client, argv[2], &id) :
		    kldmgr_unload(client, argv[2], &id)) == -1) {
			error = errno;
			kldmgr_client_close(client);
			errno = error;
			err(EX_UNAVAILABLE, "%s %s", operation, argv[2]);
		}
		kldmgr_client_close(client);
		printf("id=%d\tmodule=%s\n", id, argv[2]);
		return (0);
	}
	usage();
}
