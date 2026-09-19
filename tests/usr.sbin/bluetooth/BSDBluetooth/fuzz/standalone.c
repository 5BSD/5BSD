/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Standalone driver for the fuzz harnesses.
 *
 * Links against the same LLVMFuzzerTestOneInput() harnesses but WITHOUT
 * libFuzzer's coverage runtime.  Each command-line argument is a file (or
 * a directory of files) that is replayed through the harness under
 * ASan/UBSan.  Two uses:
 *
 *   1. Reproduce a crash:  ./std_att_server crash-abcdef
 *   2. CI regression:      replay the whole seed corpus and fail if any
 *      input trips a sanitizer.  This runs anywhere a normal binary runs
 *      -- unlike the libFuzzer build, which needs its runtime to init.
 *
 * Directories are walked one level deep (the corpus layout).
 */

#include <sys/stat.h>

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

static int
run_file(const char *path)
{
	FILE *f;
	long n;
	size_t rd;
	uint8_t *buf;

	f = fopen(path, "rb");
	if (f == NULL) {
		perror(path);
		return (-1);
	}
	if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0) {
		fclose(f);
		return (-1);
	}
	rewind(f);
	buf = malloc((size_t)n == 0 ? 1 : (size_t)n);
	if (buf == NULL) {
		fclose(f);
		return (-1);
	}
	rd = fread(buf, 1, (size_t)n, f);
	fclose(f);

	LLVMFuzzerTestOneInput(buf, rd);
	free(buf);
	return (0);
}

static int
run_path(const char *path)
{
	struct stat st;
	DIR *d;
	struct dirent *de;
	int count = 0;

	if (stat(path, &st) != 0) {
		perror(path);
		return (0);
	}
	if (!S_ISDIR(st.st_mode)) {
		run_file(path);
		return (1);
	}

	d = opendir(path);
	if (d == NULL) {
		perror(path);
		return (0);
	}
	while ((de = readdir(d)) != NULL) {
		char child[1024];

		if (de->d_name[0] == '.')
			continue;
		snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
		count += run_path(child);
	}
	closedir(d);
	return (count);
}

int
main(int argc, char **argv)
{
	int i, total = 0;

	if (LLVMFuzzerInitialize != NULL)
		LLVMFuzzerInitialize(&argc, &argv);

	for (i = 1; i < argc; i++)
		total += run_path(argv[i]);

	fprintf(stderr, "standalone: replayed %d input(s) cleanly\n", total);
	return (0);
}
