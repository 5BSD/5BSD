/* SPDX-License-Identifier: BSD-2-Clause */
#include "tool_test.h"

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
