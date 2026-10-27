/* SPDX-License-Identifier: BSD-2-Clause */
#include "tools/build/bazel/tests/dtrace_archive/archiveprobe_provider.h"

/* Keep initialization observable; otherwise clang folds it into static data. */
static volatile int initialized;
static void __attribute__((constructor)) ordinary_init(void)
{
    initialized = 1;
}
int shared_first(int value)
{
    if (ARCHIVEPROBE_USED_ENABLED())
        ARCHIVEPROBE_USED(value);
    return initialized ? value + 1 : -1;
}
int shared_second(int value)
{
    if (ARCHIVEPROBE_USED_ENABLED())
        ARCHIVEPROBE_USED(value);
    return initialized ? value + 2 : -1;
}

int shared_initialization_ok(void)
{
    return initialized == 1;
}
