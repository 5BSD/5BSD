/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef CLANG_TOOL_TEST_H
#define CLANG_TOOL_TEST_H
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static inline void
run_as(const char *program, char *const args[], const char *output)
{
    pid_t pid, waited;
    int status;

    pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(1);
    }
    if (pid == 0) {
        int fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd == -1 || dup2(fd, STDOUT_FILENO) == -1)
            _exit(126);
        if (fd != STDOUT_FILENO)
            close(fd);
        execv(program, args);
        perror(args[0]);
        _exit(127);
    }
    do { waited = waitpid(pid, &status, 0); } while (waited == -1 && errno == EINTR);
    if (waited != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "%s failed\n", args[0]);
        exit(1);
    }
}

static inline void
run(char *const args[], const char *output)
{
    run_as(args[0], args, output);
}

static inline void
check_text(const char *file, const char *expected, int present)
{
    char data[65536];
    FILE *f = fopen(file, "r");
    if (f == NULL) {
        perror(file);
        exit(1);
    }
    size_t n = fread(data, 1, sizeof(data) - 1, f);
    int failed = ferror(f) || !feof(f);
    fclose(f);
    data[n] = '\0';
    if (failed || (strstr(data, expected) != NULL) != present) {
        fprintf(stderr, "%s: unexpected presence/absence of %s\n%s\n", file, expected, data);
        exit(1);
    }
}

static inline void
contains(const char *file, const char *expected)
{
    check_text(file, expected, 1);
}

static inline void
identical(const char *left, const char *right)
{
    FILE *a = fopen(left, "rb"), *b = fopen(right, "rb");
    int x, y;
    if (a == NULL || b == NULL)
        exit(1);
    do {
        x = fgetc(a); y = fgetc(b);
        if (x != y)
            exit(1);
    } while (x != EOF);
    if (ferror(a) || ferror(b))
        exit(1);
    fclose(a); fclose(b);
}

#endif
