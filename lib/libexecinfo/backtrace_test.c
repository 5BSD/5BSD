/* SPDX-License-Identifier: BSD-2-Clause */
#include <err.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
__attribute__((noinline)) void native_backtrace_leaf(void) {
    void *frames[32];
    size_t count = backtrace(frames, 32);
    if (count < 2 || count > 32) errx(1, "unexpected frame count: %zu", count);
    char **names = backtrace_symbols_fmt(frames, count, "%n");
    if (!names) err(1, "backtrace_symbols_fmt");
    int leaf = 0, caller = 0;
    for (size_t i = 0; i < count; i++) {
        leaf |= strcmp(names[i], "native_backtrace_leaf") == 0;
        caller |= strcmp(names[i], "main") == 0;
    }
    if (!leaf || !caller) errx(1, "expected leaf and main symbols");
    free(names);
    FILE *output = tmpfile();
    if (!output) err(1, "tmpfile");
    if (backtrace_symbols_fd_fmt(frames, count, fileno(output), "%n") != 0)
        err(1, "backtrace_symbols_fd_fmt");
    rewind(output);
    char line[512];
    leaf = caller = 0;
    while (fgets(line, sizeof(line), output)) {
        leaf |= strcmp(line, "native_backtrace_leaf\n") == 0;
        caller |= strcmp(line, "main\n") == 0;
    }
    if (ferror(output) || !leaf || !caller) errx(1, "file descriptor symbol output");
    fclose(output);
}
int main(void) { native_backtrace_leaf(); return 0; }
