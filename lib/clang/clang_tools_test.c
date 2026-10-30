/* SPDX-License-Identifier: BSD-2-Clause */
#include "tool_test.h"

static void
write_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (f == NULL || fputs(text, f) == EOF || fclose(f) != 0)
        exit(1);
}

int
main(int argc, char **argv)
{
    char tools[3][PATH_MAX];
    const char *tmp = getenv("TEST_TMPDIR");
    if (argc != 4 || tmp == NULL)
        return (2);
    for (int i = 0; i < 3; ++i)
        if (realpath(argv[i + 1], tools[i]) == NULL)
            return (2);
    if (chdir(tmp) == -1 || setenv("PATH", "/nonexistent", 1) == -1)
        return (2);
    write_text("leaf.h", "#define VALUE 42\n");
    write_text("other.h", "#define VALUE 7\n");
    write_text("local.h", "#include \"leaf.h\"\n");
    write_text("probe.c", "#include \"local.h\"\nint answer(void){return VALUE;}\n");
    char *scan[] = {tools[1], "-format=make", "--", tools[0], "-nostdinc", "-c", "probe.c", "-o", "probe.o", NULL};
    run(scan, "first.out");
    contains("first.out", "probe.c");
    contains("first.out", "local.h");
    contains("first.out", "leaf.h");
    check_text("first.out", "other.h", 0);
    write_text("local.h", "#include \"other.h\"\n");
    run(scan, "second.out");
    contains("second.out", "other.h");
    check_text("second.out", "leaf.h", 0);
    run((char *[]){tools[2], "--style=LLVM", "probe.c", NULL}, "formatted.c");
    contains("formatted.c", "int answer(void) { return VALUE; }");
    run((char *[]){tools[2], "--style=LLVM", "formatted.c", NULL}, "formatted-again.c");
    identical("formatted.c", "formatted-again.c");
    run((char *[]){tools[2], "--style=LLVM", "--dry-run", "--Werror", "formatted.c", NULL}, "validate.out");
    puts("native include mutation and format idempotence passed");
    return (0);
}
