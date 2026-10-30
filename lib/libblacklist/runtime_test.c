/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <old_bl.h>

static char directory[4096];
static void
cleanup(void)
{
    unlink("server.sock");
    chdir("/");
    rmdir(directory);
}
static void
logger(int priority, struct syslog_data *data, const char *format, va_list ap)
{
    (void)priority;
    (void)data;
    vfprintf(stderr, format, ap);
}
int
main(void)
{
    const char *tmp = getenv("TEST_TMPDIR");
    if (tmp == NULL || snprintf(directory, sizeof(directory), "%s/blacklist.XXXXXX", tmp) >= (int)sizeof(directory)) return 1;
    if (mkdtemp(directory) == NULL || chdir(directory) != 0) return 2;
    atexit(cleanup);
    alarm(10);
    bl_t server = bl_create(true, "server.sock", logger);
    bl_t client = bl_create(false, "server.sock", logger);
    if (server == NULL || client == NULL || bl_getfd(server) < 0 || bl_getfd(client) < 0) return 3;
    int fds[2];
    if (pipe(fds) != 0) return 4;
    const int actions[] = {BLACKLIST_AUTH_FAIL, BLACKLIST_AUTH_OK, BLACKLIST_ABUSIVE_BEHAVIOR, BLACKLIST_BAD_USER};
    const bl_type_t expected[] = {BL_ADD, BL_DELETE, BL_ABUSE, BL_BADUSER};
    struct stat original;
    if (fstat(fds[0], &original) != 0) return 5;
    for (size_t i = 0; i < sizeof(actions)/sizeof(actions[0]); i++) {
        if (blacklist_r(client, actions[i], fds[0], "native-test") != 0) return 6;
        bl_info_t *info = bl_recv(server);
        if (info == NULL || info->bi_type != expected[i] || strcmp(info->bi_msg, "native-test") != 0 ||
            info->bi_uid != geteuid() || info->bi_gid != getegid() || info->bi_fd < 0) return 7;
        struct stat received;
        if (fstat(info->bi_fd, &received) != 0 || received.st_dev != original.st_dev || received.st_ino != original.st_ino) return 8;
        close(info->bi_fd);
    }
    close(fds[0]); close(fds[1]);
    blacklist_close(client);
    bl_destroy(server);
    return 0;
}
