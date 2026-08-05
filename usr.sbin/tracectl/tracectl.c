/*- SPDX-License-Identifier: BSD-2-Clause */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "tracecmp_policy.h"

static void usage(void) __dead2;

static void
usage(void)
{
	fprintf(stderr, "usage: tracectl configtest [file]\n");
	exit(EX_USAGE);
}

int
main(int argc, char **argv)
{
	struct tracecmp_policy policy;
	const char *path;

	if (argc < 2 || strcmp(argv[1], "configtest") != 0 || argc > 3)
		usage();
	path = argc == 3 ? argv[2] : TRACECMP_POLICY_PATH;
	if (tracecmp_policy_load(path, &policy) == -1)
		err(EX_DATAERR, "%s", path);
	printf("%s: valid (labels=%zu, default=%s)\n", path, policy.count,
	    policy.count == 0 ? "deny" : "explicit-allow");
	return (0);
}
