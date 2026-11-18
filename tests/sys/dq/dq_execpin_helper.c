/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * dq_execpin_test's image: prints its real and effective uid and whether
 * PROC_NO_NEW_PRIVS is set (a dq ATTACH sets it), then stat(2)s each
 * argument, so an attached run posts a RESOLVE the test can find.
 */

#include <sys/param.h>
#include <sys/procctl.h>
#include <sys/stat.h>

#include <stdio.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct stat sb;
	int i, nnp;

	if (procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_STATUS, &nnp) != 0)
		nnp = -1;
	printf("uid=%d euid=%d nnp=%d\n", (int)getuid(), (int)geteuid(),
	    nnp == PROC_NO_NEW_PRIVS_ENABLE ? 1 : nnp == -1 ? -1 : 0);
	fflush(stdout);
	for (i = 1; i < argc; i++)
		(void)stat(argv[i], &sb);
	return (0);
}
