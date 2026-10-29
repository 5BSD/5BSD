/* SPDX-License-Identifier: BSD-2-Clause */
/* Run instrumentation, profile merging and coverage reporting with native tools. */
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
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

static void
run(char *const args[], const char *output)
{
    run_as(args[0], args, output);
}

static void
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

static void
contains(const char *file, const char *expected)
{
    check_text(file, expected, 1);
}

int
main(int argc, char **argv)
{
    char tools[3][PATH_MAX];
    const char *tmp = getenv("TEST_TMPDIR");
    if (argc != 4 || tmp == NULL)
        return (2);
    for (int i = 0; i < 3; ++i) {
        if (realpath(argv[i + 1], tools[i]) == NULL)
            return (2);
    }
    if (chdir(tmp) == -1 || setenv("PATH", "/nonexistent", 1) == -1 ||
        setenv("LLVM_PROFILE_FILE", "probe.profraw", 1) == -1)
        return (2);
    run((char *[]){tools[0], NULL}, "probe.out");
    run((char *[]){tools[1], "merge", "-sparse", "probe.profraw", "-o", "probe.profdata", NULL}, "merge.out");
    run((char *[]){tools[1], "show", "--all-functions", "--counts", "probe.profdata", NULL}, "profile.out");
    contains("profile.out", "main:");
    contains("profile.out", "Function count: 1");
    run((char *[]){tools[2], "report", tools[0], "-instr-profile=probe.profdata", NULL}, "coverage.out");
    contains("coverage.out", "sdk_probe.c");
    contains("coverage.out", "100.00%");
    puts("native instrumentation, profile merging and coverage reporting passed");
    return (0);
}
