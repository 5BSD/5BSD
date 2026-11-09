/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * dq_exec_test's image: a dynamic program that prints what the kernel
 * gave it (AT_EXECPATH, the cwd, its arguments) and, with "wait" as an
 * argument, waits for its standard input to close so the test can look
 * at its mappings.
 */

#include <sys/param.h>
#include <sys/auxv.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	char path[PATH_MAX], cwd[PATH_MAX];
	int error, i;
	char c;

	error = elf_aux_info(AT_EXECPATH, path, sizeof(path));
	printf("execpath=%s\n", error == 0 ? path : strerror(error));
	printf("cwd=%s\n", getcwd(cwd, sizeof(cwd)) != NULL ? cwd :
	    strerror(errno));
	for (i = 0; i < argc; i++)
		printf("argv%d=%s\n", i, argv[i]);
	fflush(stdout);
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "wait") == 0) {
			while (read(STDIN_FILENO, &c, 1) == 1)
				;
		}
	}
	return (0);
}
