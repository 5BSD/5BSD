/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * pwd_paths_test's image: prints AT_EXECPATH (or the error
 * elf_aux_info(3) gives) and kern.proc.pathname for itself.
 */

#include <sys/param.h>
#include <sys/auxv.h>
#include <sys/sysctl.h>

#include <stdio.h>
#include <string.h>

int
main(void)
{
	char path[PATH_MAX];
	size_t len;
	int error, mib[4];

	error = elf_aux_info(AT_EXECPATH, path, sizeof(path));
	if (error == 0)
		printf("execpath=%s\n", path);
	else
		printf("execpath-error=%d\n", error);
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = -1;
	len = sizeof(path);
	if (sysctl(mib, 4, path, &len, NULL, 0) == 0)
		printf("pathname=%s\n", path);
	else
		printf("pathname-error\n");
	return (0);
}
