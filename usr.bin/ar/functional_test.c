/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char program[PATH_MAX];

static void
write_file(const char *name, const char *text)
{
    FILE *f = fopen(name, "w");
    if (f == NULL || fputs(text, f) == EOF || fclose(f) != 0)
        err(1, "write %s", name);
}

static void
expect(const char *name, const char *text)
{
    char buf[4096];
    FILE *f = fopen(name, "r");
    if (f == NULL)
        err(1, "read %s", name);
    size_t n = fread(buf, 1, sizeof(buf), f);
    if (ferror(f) || n != strlen(text) || memcmp(buf, text, n) != 0)
        errx(1, "unexpected contents: %s", name);
    fclose(f);
}

static void
run(char *const args[], const char *input, const char *output)
{
    pid_t pid = fork();
    int status;
    if (pid < 0)
        err(1, "fork");
    if (pid == 0) {
        int in = open(input, O_RDONLY);
        int out = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (in < 0 || out < 0 || dup2(in, STDIN_FILENO) < 0 || dup2(out, STDOUT_FILENO) < 0)
            err(1, "redirect");
        close(in);
        close(out);
        execv(program, args);
        err(1, "exec ar");
    }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        errx(1, "ar operation failed: %s", args[1]);
}

int
main(int argc, char **argv)
{
    char paths[32768] = "", full[PATH_MAX];
    const char *tmp = getenv("TEST_TMPDIR");
    if (argc < 3 || tmp == NULL || realpath(argv[1], program) == NULL)
        errx(1, "program, runtime libraries and TEST_TMPDIR required");
    for (int i = 2; i < argc; i++) {
        if (realpath(argv[i], full) == NULL)
            err(1, "runtime input %s", argv[i]);
        char *slash = strrchr(full, '/');
        if (slash == NULL)
            errx(1, "invalid runtime input");
        *slash = '\0';
        if ((i > 2 && strlcat(paths, ":", sizeof(paths)) >= sizeof(paths)) ||
            strlcat(paths, full, sizeof(paths)) >= sizeof(paths))
            errx(1, "runtime path too long");
    }
    if (setenv("LD_LIBRARY_PATH", paths, 1) != 0 || chdir(tmp) != 0)
        err(1, "test environment");
    write_file("empty", "");
    write_file("a", "first payload\n");
    write_file("a_deliberately_long_member_filename", "second payload\n");
    run((char *const[]){"ar", "rcsD", "normal.a", "a", "a_deliberately_long_member_filename", NULL}, "empty", "output");
    run((char *const[]){"ar", "t", "normal.a", NULL}, "empty", "output");
    expect("output", "a\na_deliberately_long_member_filename\n");
    run((char *const[]){"ar", "p", "normal.a", "a_deliberately_long_member_filename", NULL}, "empty", "output");
    expect("output", "second payload\n");
    run((char *const[]){"ar", "d", "normal.a", "a", NULL}, "empty", "output");
    run((char *const[]){"ar", "t", "normal.a", NULL}, "empty", "output");
    expect("output", "a_deliberately_long_member_filename\n");
    run((char *const[]){"ar", "r", "normal.a", "a", NULL}, "empty", "output");
    write_file("a", "replacement payload\n");
    run((char *const[]){"ar", "r", "normal.a", "a", NULL}, "empty", "output");
    run((char *const[]){"ranlib", "normal.a", NULL}, "empty", "output");
    run((char *const[]){"ar", "p", "normal.a", "a", NULL}, "empty", "output");
    expect("output", "replacement payload\n");
    write_file("script", "CREATE scripted.a\nADDMOD a\nSAVE\nEND\n");
    run((char *const[]){"ar", "-M", NULL}, "script", "output");
    run((char *const[]){"ranlib", "scripted.a", NULL}, "empty", "output");
    run((char *const[]){"ar", "p", "scripted.a", "a", NULL}, "empty", "output");
    expect("output", "replacement payload\n");
    puts("archive edits, long members, ranlib invocation and MRI parser passed");
    return (0);
}
