/* SPDX-License-Identifier: BSD-2-Clause */
/* Adapt upstream file fixture inputs to the common byte/exit comparator. */
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *required(const char *name) {
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') { fprintf(stderr, "missing %s\n", name); exit(1); }
    return value;
}
static void setting(const char *key, const char *value) {
    if (setenv(key, value, 1) != 0) { perror(key); exit(1); }
}
int main(void) {
    char root[PATH_MAX], path[PATH_MAX], key[64], number[32], *end;
    char *magic = NULL;
    size_t length = 0;
    int n, argc = 0;
    long count;
    n = snprintf(root, sizeof(root), "%s/%s", required("TEST_SRCDIR"), required("TEST_WORKSPACE"));
    if (n < 0 || (size_t)n >= sizeof(root)) return 1;
    errno = 0; count = strtol(required("FILE_MAGIC_COUNT"), &end, 10);
    if (errno || *end || count < 1 || count > 1024) return 1;
    for (long i = 0; i < count; ++i) {
        snprintf(key, sizeof(key), "FILE_MAGIC_%ld", i);
        n = snprintf(path, sizeof(path), "%s/test-magic/%s", root, required(key));
        if (n < 0 || (size_t)n >= sizeof(path)) return 1;
        size_t size = length + (i != 0) + (size_t)n + 1;
        char *next = realloc(magic, size);
        if (next == NULL) return 1;
        magic = next;
        if (i != 0) magic[length++] = ':';
        memcpy(magic + length, path, (size_t)n + 1); length += (size_t)n;
    }
    setting("MAGIC", magic); free(magic); setting("TZ", "Z");
    if (strcmp(required("FILE_HAS_FLAGS"), "1") == 0) {
        n = snprintf(path, sizeof(path), "%s/test-data/flags", root);
        if (n < 0 || (size_t)n >= sizeof(path)) return 1;
        FILE *stream = fopen(path, "rb");
        char *data = NULL; size_t used = 1, capacity = 128;
        if (stream == NULL || (data = malloc(capacity)) == NULL) return 1;
        data[0] = '-';
        int ch;
        while ((ch = fgetc(stream)) != EOF) {
            if (ch == 0) { fprintf(stderr, "NUL in flags file\n"); return 1; }
            if (used + 1 >= capacity) {
                capacity *= 2; char *next = realloc(data, capacity);
                if (next == NULL) return 1;
                data = next;
            }
            data[used++] = (char)ch;
        }
        if (ferror(stream) || fclose(stream) != 0) return 1;
        data[used] = '\0';
        /* Match shell word splitting of the maintained '-$(cat flags)' input. */
        char *save, *token = strtok_r(data, " \t\n", &save);
        while (token != NULL) {
            if (argc >= 1023) return 1;
            snprintf(key, sizeof(key), "BSD_COMPARE_ARG_%d", argc++);
            setting(key, token); token = strtok_r(NULL, " \t\n", &save);
        }
        free(data);
    }
    snprintf(key, sizeof(key), "BSD_COMPARE_ARG_%d", argc++); setting(key, "--brief");
    /* file(1) observes symlinks; materialize the fixture as the installed
     * upstream suite does, without changing its command-line semantics. */
    n = snprintf(path, sizeof(path), "%s/test-data/argument-0", root);
    if (n < 0 || (size_t)n >= sizeof(path)) return 1;
    FILE *source = fopen(path, "rb");
    if (source == NULL) return 1;
    n = snprintf(path, sizeof(path), "%s/fixture", required("TEST_TMPDIR"));
    if (n < 0 || (size_t)n >= sizeof(path)) return 1;
    FILE *copy = fopen(path, "wbx");
    if (copy == NULL) return 1;
    char buffer[16384]; size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), source)) != 0)
        if (fwrite(buffer, 1, bytes, copy) != bytes) return 1;
    if (ferror(source)) return 1;
    if (fclose(source) != 0 || fclose(copy) != 0) return 1;
    snprintf(key, sizeof(key), "BSD_COMPARE_ARG_%d", argc++); setting(key, path);
    setting("BSD_COMPARE_FILE_ARGC", "0");
    snprintf(number, sizeof(number), "%d", argc); setting("BSD_COMPARE_ARGC", number);
    n = snprintf(path, sizeof(path), "%s/test-adapter/compare", root);
    if (n < 0 || (size_t)n >= sizeof(path)) return 1;
    execl(path, path, (char *)NULL); perror(path); return 1;
}
