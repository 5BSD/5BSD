/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
check(const char *program, const char *argument, const char *expected, int code)
{
    pid_t pid = fork(), waited;
    int status = 0;
    if (pid == -1) return (1);
    if (pid == 0) {
        int fd = open("diagnostic", O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd == -1 || dup2(fd, STDERR_FILENO) == -1) _exit(126);
        if (fd != STDERR_FILENO) close(fd);
        execl(program, program, argument, (char *)NULL);
        _exit(127);
    }
    do { waited = waitpid(pid, &status, 0); } while (waited == -1 && errno == EINTR);
    char message[65536];
    FILE *f = fopen("diagnostic", "r");
    if (f == NULL) return (1);
    size_t n = fread(message, 1, sizeof(message) - 1, f);
    int failed = ferror(f) || !feof(f);
    fclose(f);
    message[n] = '\0';
    if (failed || waited != pid || !WIFEXITED(status) || WEXITSTATUS(status) != code ||
        (expected != NULL ? strstr(message, expected) == NULL : n != 0)) {
        fprintf(stderr, "ASan case %s failed, status %d:\n%s", argument, status, message);
        return (1);
    }
    return (0);
}

int main(int argc, char **argv)
{
    char program[PATH_MAX], library[PATH_MAX];
    char *paths;
    size_t capacity;
    const char *tmp = getenv("TEST_TMPDIR");
    if (argc < 3 || (size_t)argc > SIZE_MAX / PATH_MAX ||
        tmp == NULL || realpath(argv[1], program) == NULL) return (2);
    capacity = (size_t)argc * PATH_MAX;
    paths = calloc(1, capacity);
    if (paths == NULL) return (2);
    for (int i = 2; i < argc; i++) {
        if (realpath(argv[i], library) == NULL) return (2);
        char *slash = strrchr(library, '/');
        if (slash == NULL) return (2);
        *slash = '\0';
        if ((i != 2 && strlcat(paths, ":", capacity) >= capacity) ||
            strlcat(paths, library, capacity) >= capacity) return (2);
    }
    if (chdir(tmp) == -1 || setenv("LD_LIBRARY_PATH", paths, 1) == -1 ||
        setenv("PATH", "/nonexistent", 1) == -1 ||
        setenv("ASAN_OPTIONS", "symbolize=0:exitcode=86", 1) == -1) return (2);
    free(paths);
    if (check(program, "7", NULL, 0) ||
        check(program, "8", "ERROR: AddressSanitizer: heap-buffer-overflow", 86) ||
        check(program, "freed", "ERROR: AddressSanitizer: heap-use-after-free", 86)) return (1);
    puts("native ASan clean, bounds and lifetime checks passed");
    return (0);
}
