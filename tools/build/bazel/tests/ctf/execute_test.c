/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <err.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
wait_ok(pid_t child)
{
    int status;
    pid_t result;
    do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    if (result != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        errx(1, "CTF fixture child failed");
}
int
main(int argc, char **argv)
{
    char paths[16384] = "", full[PATH_MAX], line[4096];
    int fds[2], first = 0, second = 0, label = 0;
    int shared = argc > 1 && strcmp(argv[1], "--shared") == 0;
    if (shared) { argc--; argv++; }
    if (argc < 4) errx(1, "merged executable, dumper and libraries required");
    for (int i = 3; i < argc; i++) {
        if (!realpath(argv[i], full)) err(1, "runtime library");
        char *slash = strrchr(full, '/');
        if (!slash) errx(1, "runtime path");
        *slash = '\0';
        if ((i > 3 && strlcat(paths, ":", sizeof(paths)) >= sizeof(paths)) ||
            strlcat(paths, full, sizeof(paths)) >= sizeof(paths)) errx(1, "runtime path length");
    }
    if (setenv("LD_LIBRARY_PATH", paths, 1)) err(1, "runtime environment");
    pid_t child;
    if (shared) {
        void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        if (!handle) errx(1, "dlopen: %s", dlerror());
        int (*first_value)(void) = (int (*)(void))dlsym(handle, "first_value");
        int (*second_value)(void) = (int (*)(void))dlsym(handle, "second_value");
        if (!first_value || !second_value || first_value() + second_value() != 42)
            errx(1, "merged shared library symbols/behavior");
        if (dlclose(handle)) errx(1, "dlclose");
    } else {
        child = fork();
        if (child < 0) err(1, "fork");
        if (child == 0) { execl(argv[1], argv[1], (char *)NULL); err(1, "exec merged artifact"); }
        wait_ok(child);
    }
    if (pipe(fds)) err(1, "pipe");
    child = fork();
    if (child < 0) err(1, "fork");
    if (child == 0) {
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) err(1, "stdout");
        close(fds[1]);
        execl(argv[2], argv[2], "-t", "-l", argv[1], (char *)NULL);
        err(1, "exec ctfdump");
    }
    close(fds[1]);
    FILE *input = fdopen(fds[0], "r");
    if (!input) err(1, "fdopen");
    while (fgets(line, sizeof(line), input)) {
        first |= strstr(line, "STRUCT first") != NULL;
        second |= strstr(line, "STRUCT second") != NULL;
        label |= strstr(line, "bazel-ctf-merged") != NULL;
    }
    if (ferror(input) || fclose(input)) errx(1, "CTF dump read");
    wait_ok(child);
    if (!first || !second || !label) errx(1, "merged CTF types/label absent");
    puts("merged CTF types, label and artifact behavior passed");
    return (0);
}
