/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Helper for capmode_interp_test: a dynamically linked program that is
 * fexecve(2)d from capability mode.  It reports whether it is running in
 * capability mode and whether AT_EXECPATH names it, and holds still so the
 * test can read the command name the kernel gave it.
 *
 * Exit codes are above 200 so they never collide with an errno reported
 * by the test's exec child.
 */

#include <sys/param.h>
#include <sys/auxv.h>
#include <sys/capsicum.h>

#include <string.h>
#include <unistd.h>

/*
 * Descriptors 3 and 4 are a pipe pair from the test: writing on 3 tells
 * the test this process is up so it can read the kernel's command name
 * for it (kern.proc.pid is not readable from capability mode), and a
 * byte on 4 releases it.
 */
#define	READY_FD	3
#define	GO_FD		4

int
main(int argc, char **argv)
{
	char execpath[MAXPATHLEN], c;
	const char *base;
	unsigned int mode;

	if (argc != 2)
		return (201);
	if (cap_getmode(&mode) != 0 || mode != 1)
		return (202);

	if (elf_aux_info(AT_EXECPATH, execpath, sizeof(execpath)) != 0)
		return (205);
	base = strrchr(execpath, '/');
	base = base != NULL ? base + 1 : execpath;
	if (strcmp(base, argv[1]) != 0)
		return (206);

	if (write(READY_FD, "R", 1) == 1)
		(void)read(GO_FD, &c, 1);
	return (0);
}
