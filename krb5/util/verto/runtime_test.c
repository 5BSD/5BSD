/* SPDX-License-Identifier: BSD-2-Clause */
#include <verto.h>
#include <unistd.h>
#include <stdlib.h>

static int observed;
static void ready(verto_ctx *ctx, verto_ev *ev)
{
    char byte;
    if (read(verto_get_fd(ev), &byte, 1) != 1 || byte != 'x')
        exit(2);
    observed++;
    verto_break(ctx);
}
static void expired(verto_ctx *ctx, verto_ev *ev)
{
    (void)ctx;
    (void)ev;
    exit(3);
}
int main(void)
{
    int fd[2];
    verto_ctx *ctx = verto_new(NULL, VERTO_EV_TYPE_IO | VERTO_EV_TYPE_TIMEOUT);
    if (ctx == NULL || pipe(fd) != 0)
        return 4;
    if (verto_add_io(ctx, VERTO_EV_FLAG_IO_READ, ready, fd[0]) == NULL ||
        verto_add_timeout(ctx, VERTO_EV_FLAG_NONE, expired, 2000) == NULL ||
        write(fd[1], "x", 1) != 1)
        return 5;
    verto_run(ctx);
    verto_free(ctx);
    close(fd[0]);
    close(fd[1]);
    return observed == 1 ? 0 : 6;
}
