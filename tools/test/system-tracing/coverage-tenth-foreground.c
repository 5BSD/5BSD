/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#include <stdio.h>

int __wrap_daemon(int, int);

int
__wrap_daemon(int nochdir, int noclose)
{
	(void)nochdir;
	(void)noclose;
	fputs("foreground fixture\n", stderr);
	return (0);
}
