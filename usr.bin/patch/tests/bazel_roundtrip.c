/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise the declared patch executable in Bazel's private test directory. */
#include <sys/types.h>
#include <sys/wait.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
write_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "w");
	if (f == NULL || fputs(text, f) == EOF || fclose(f) != 0)
		err(1, "write %s", path);
}

static void
check_file(const char *path, const char *expected)
{
	char buffer[1024];
	FILE *f = fopen(path, "r");
	size_t n;
	if (f == NULL)
		err(1, "open %s", path);
	n = fread(buffer, 1, sizeof(buffer), f);
	if (ferror(f) || n != strlen(expected) || memcmp(buffer, expected, n) != 0)
		errx(1, "unexpected contents: %s", path);
	if (fclose(f) != 0)
		err(1, "close %s", path);
}

static void
run_patch(const char *program, const char *option)
{
	int status;
	pid_t child = fork(), waited;
	if (child < 0)
		err(1, "fork");
	if (child == 0) {
		int in = open("change.diff", O_RDONLY);
		int out = open("stdout", O_WRONLY | O_CREAT | O_TRUNC, 0600);
		int error = open("stderr", O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (in < 0 || out < 0 || error < 0 || dup2(in, 0) < 0 ||
		    dup2(out, 1) < 0 || dup2(error, 2) < 0)
			_exit(126);
		close(in); close(out); close(error);
		execl(program, "patch", "-s", option, (char *)NULL);
		_exit(127);
	}
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		errx(1, "patch failed for %s", option);
	check_file("stdout", "");
	check_file("stderr", "");
}

int
main(int argc, char **argv)
{
	char program[PATH_MAX];
	const char *tmp = getenv("TEST_TMPDIR");
	if (argc != 2 || tmp == NULL)
		errx(1, "requires declared patch executable and TEST_TMPDIR");
	if (realpath(argv[1], program) == NULL || chdir(tmp) != 0)
		err(1, "test paths");
	if (unsetenv("LD_PRELOAD") != 0 || unsetenv("LD_LIBRARY_PATH") != 0 ||
	    setenv("LC_ALL", "C", 1) != 0)
		err(1, "test environment");
	write_file("input", "one\ntwo\n");
	write_file("change.diff", "--- input\n+++ input\n@@ -1,2 +1,2 @@\n one\n-two\n+three\n");
	run_patch(program, "--dry-run");
	check_file("input", "one\ntwo\n");
	run_patch(program, "--forward");
	check_file("input", "one\nthree\n");
	run_patch(program, "--reverse");
	check_file("input", "one\ntwo\n");
	return (0);
}
