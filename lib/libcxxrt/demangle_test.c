/* SPDX-License-Identifier: BSD-2-Clause */
#include <err.h>
#include <stdlib.h>
#include <string.h>
extern char *__cxa_demangle(const char *, char *, size_t *, int *);
int main(void)
{
    int status = 123;
    size_t capacity = 0;
    char *value = __cxa_demangle("_Z3fooi", NULL, &capacity, &status);
    if (!value || status != 0 || strcmp(value, "foo(int)") != 0 || capacity < strlen(value) + 1)
        errx(1, "allocated demangling failed");
    char *second = __cxa_demangle("_Z3barv", value, &capacity, &status);
    if (!second || status != 0 || strcmp(second, "bar()") != 0)
        errx(1, "buffer reuse failed");
    free(second);
    value = __cxa_demangle("_Z", NULL, NULL, &status);
    if (value || status != -2) errx(1, "invalid name accepted");
    capacity = 128;
    value = malloc(capacity);
    if (!value) err(1, "malloc");
    second = __cxa_demangle("_Z3barv", value, &capacity, &status);
    if (second != value || capacity != 128 || status != 0)
        errx(1, "existing capacity not preserved");
    if (__cxa_demangle("_Z3barv", value, NULL, &status) != NULL || status != -3)
        errx(1, "missing capacity accepted");
    free(value);
    if (__cxa_demangle(NULL, NULL, NULL, &status) != NULL || status != -3)
        errx(1, "null name accepted");
    return (0);
}
