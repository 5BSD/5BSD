/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
run(char *tool, char *a, char *b, char *c)
{
	int status;
	pid_t child = fork(), result;
	if (child == -1) err(1, "fork");
	if (child == 0) {
		execl(tool, tool, a, b, c, (char *)NULL);
		err(1, "exec %s", tool);
	}
	do { result = waitpid(child, &status, 0); } while (result == -1 && errno == EINTR);
	if (result == -1) err(1, "waitpid");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		errx(1, "%s failed: wait status %d", tool, status);
}

int
main(int argc, char **argv)
{
	char paths[7][PATH_MAX], libraries[3 * PATH_MAX] = "";
	char *tmp = getenv("TEST_TMPDIR"), *slash;
	FILE *expected, *actual;
	int a, b;
	if (argc != 8 || tmp == NULL) errx(1, "expected tools, fixtures and three runtime libraries under Bazel");
	for (int i = 0; i < 7; i++)
		if (realpath(argv[i + 1], paths[i]) == NULL) err(1, "%s", argv[i + 1]);
	for (int i = 4; i < 7; i++) {
		slash = strrchr(paths[i], '/');
		*slash = '\0';
		if (i != 4 && strlcat(libraries, ":", sizeof(libraries)) >= sizeof(libraries)) errx(1, "runtime path overflow");
		if (strlcat(libraries, paths[i], sizeof(libraries)) >= sizeof(libraries)) errx(1, "runtime path overflow");
	}
	if (unsetenv("LD_PRELOAD") || setenv("LD_LIBRARY_PATH", libraries, 1) || setenv("LC_ALL", "C", 1)) err(1, "environment");
	if (chdir(tmp)) err(1, "TEST_TMPDIR");
	run(paths[0], paths[2], paths[3], "patch");
	run(paths[1], paths[2], "restored", "patch");
	expected = fopen(paths[3], "rb");
	actual = fopen("restored", "rb");
	if (!expected || !actual) err(1, "open result");
	do {
		a = fgetc(expected); b = fgetc(actual);
		if (a != b) errx(1, "restored bytes differ from independent fixture");
	} while (a != EOF);
	if (ferror(expected) || ferror(actual)) errx(1, "read error");
	if (fclose(expected) || fclose(actual)) err(1, "close");
	return (0);
}
