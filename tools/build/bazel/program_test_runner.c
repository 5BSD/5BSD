/* SPDX-License-Identifier: BSD-2-Clause */
/* Select declared test runfiles, then preserve the program's process semantics. */
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *
required(const char *name)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0')
        errx(126, "missing %s", name);
    return (value);
}

int
main(int argc, char **argv)
{
    const char *root = required("TEST_SRCDIR");
    const char *workspace = required("TEST_WORKSPACE");
    const char *program = required("BSD_TEST_PROGRAM");
    const char *runtime = required("BSD_TEST_RUNTIME");
    char *executable, *libraries;

    (void)argc;
    if (root[0] != '/' || strchr(program, '/') != NULL ||
        strcmp(program, ".") == 0 || strcmp(program, "..") == 0 ||
        strchr(workspace, '/') != NULL || strcmp(workspace, ".") == 0 ||
        strcmp(workspace, "..") == 0)
        errx(126, "invalid test runfiles location");
    if (asprintf(&executable, "%s/%s/program-bin/%s", root, workspace,
        program) < 0)
        err(126, "asprintf");
    if (strcmp(runtime, "1") == 0) {
        if (asprintf(&libraries, "%s/%s/program-runtime/lib", root,
            workspace) < 0)
            err(126, "asprintf");
        if (setenv("LD_LIBRARY_PATH", libraries, 1) != 0)
            err(126, "setenv");
        free(libraries);
    } else if (strcmp(runtime, "0") == 0) {
        if (unsetenv("LD_LIBRARY_PATH") != 0)
            err(126, "unsetenv");
    } else
        errx(126, "invalid BSD_TEST_RUNTIME");
    if (unsetenv("LD_PRELOAD") != 0 || setenv("LC_ALL", "C", 1) != 0)
        err(126, "test environment");
    if (chdir(required("TEST_TMPDIR")) != 0)
        err(126, "TEST_TMPDIR");
    argv[0] = executable;
    execv(executable, argv);
    err(127, "%s", executable);
}
