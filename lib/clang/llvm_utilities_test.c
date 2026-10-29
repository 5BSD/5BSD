/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise native LLVM utilities on an object emitted by native Clang. */
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
run(char *const args[], const char *output)
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
        execv(args[0], args);
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
contains(const char *file, const char *expected)
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
    if (failed || strstr(data, expected) == NULL) {
        fprintf(stderr, "%s: missing %s\n%s\n", file, expected, data);
        exit(1);
    }
}

int
main(int argc, char **argv)
{
    char tools[5][PATH_MAX];
    const char *tmp = getenv("TEST_TMPDIR");
    if (argc != 6 || tmp == NULL)
        return (2);
    for (int i = 0; i < 5; i++) {
        if (realpath(argv[i + 1], tools[i]) == NULL) {
            perror(argv[i + 1]);
            return (2);
        }
    }
    if (chdir(tmp) == -1 || setenv("PATH", "/nonexistent", 1) == -1)
        return (2);
    FILE *f = fopen("probe.c", "w");
    if (f == NULL)
        return (2);
    if (fputs("const char marker[] = \"llvm_utilities_probe_marker\";\n"
        "int answer(void) { return 42; }\n", f) == EOF || fclose(f) != 0)
        return (2);
    run((char *[]){tools[0], "-O2", "-c", "probe.c", "-o", "probe.o", NULL}, "compile.out");
    run((char *[]){tools[1], "--defined-only", "probe.o", NULL}, "nm.out");
    contains("nm.out", " T answer\n");
    contains("nm.out", " R marker\n");
    run((char *[]){tools[2], "_Z6answerv", NULL}, "demangle.out");
    contains("demangle.out", "answer()\n");
    run((char *[]){tools[3], "-A", "probe.o", NULL}, "size.out");
    contains("size.out", ".text");
    contains("size.out", ".rodata");
    run((char *[]){tools[4], "-n", "10", "probe.o", NULL}, "strings.out");
    contains("strings.out", "llvm_utilities_probe_marker\n");
    puts("native LLVM symbol, demangling, section-size and string checks passed");
    return (0);
}
