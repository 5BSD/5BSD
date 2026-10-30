/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bsdconf.h>

static char path[4096];
static int seen;
static void cleanup(void) { unlink(path); }
static int
parsed(struct bsdconf_option *option, uint32_t line, char *directive, char *value)
{
    (void)option; (void)line;
    if (strcmp(directive, "name") != 0 || value == NULL ||
        strcmp(bsdconf_unquote(value), "new value") != 0) return 17;
    seen++;
    return 0;
}
int
main(void)
{
    const char *tmp = getenv("TEST_TMPDIR");
    if (!tmp || snprintf(path, sizeof(path), "%s/bsdconf.XXXXXX", tmp) >= (int)sizeof(path)) return 1;
    int fd = mkstemp(path);
    if (fd < 0) return 2;
    atexit(cleanup);
    const char original[] = "# retained comment\nname=old\nuntouched=yes\n";
    if (write(fd, original, sizeof(original)-1) != sizeof(original)-1 || close(fd)) return 3;
    uint16_t processing = bsdconf_format_processing(BSDCONF_FORMAT_GENERIC);
    struct bsdconf_option changes[] = {
        { .type = BSDCONF_TYPE_STR, .directive = "name", .value.str = "new value", .action = BSDCONF_ACTION_SET_VALUE },
        {0}
    };
    if (bsdconf_put(changes, path, processing, 0) != 0 || !(changes[0].result & BSDCONF_VALUE_CHANGED)) return 4;
    struct bsdconf_option options[] = {
        { .type = BSDCONF_TYPE_STR, .directive = "name", .parse = parsed },
        {0}
    };
    if (bsdconf_parse(options, path, NULL, processing) != 0 || seen != 1) return 5;
    FILE *f = fopen(path, "r");
    if (!f) return 6;
    char output[256] = {0}; size_t count = fread(output, 1, sizeof(output)-1, f);
    if (ferror(f) || count == 0 || fclose(f)) return 7;
    if (!strstr(output, "# retained comment\n") || !strstr(output, "untouched=yes\n")) return 8;
    struct stat before, after;
    if (stat(path, &before)) return 9;
    changes[0].action = BSDCONF_ACTION_CHECK;
    if (bsdconf_put(changes, path, processing, 0) || (changes[0].result & BSDCONF_VALUE_CHANGED) || stat(path, &after)) return 10;
    if (before.st_ino != after.st_ino || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec) return 11;
    return 0;
}
