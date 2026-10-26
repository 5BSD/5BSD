/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * mkaudittrail - write the standard BSM test trail (see bsmgen.c) for
 * otelauditd -f.  -c damages the last record; -n omits the file tokens.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bsmgen.h"

int
main(int argc, char **argv)
{
	FILE *f;
	int ch, corrupt, files;

	corrupt = 0;
	files = 1;
	while ((ch = getopt(argc, argv, "cn")) != -1) {
		switch (ch) {
		case 'c':
			corrupt = 1;
			break;
		case 'n':
			files = 0;
			break;
		default:
			errx(2, "usage: mkaudittrail [-cn] file");
		}
	}
	if (optind + 1 != argc)
		errx(2, "usage: mkaudittrail [-cn] file");
	f = fopen(argv[optind], "w");
	if (f == NULL)
		err(1, "%s", argv[optind]);
	(void)bsmgen_trail(f, files, corrupt);
	if (fclose(f) != 0)
		err(1, "%s", argv[optind]);
	return (0);
}
