/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dtraced.h>
#include <dtraced_io.h>
#include <dtraced_wire.h>
#define DMODE_LISTVMS 6
static int g_mode = DMODE_LISTVMS, receiver, prints;
static jmp_buf done;
static int open_dtraced(int kind) { assert(kind == DTD_SUB_INFO); return receiver; }
static void oprintf(const char *fmt, ...) { (void)fmt; prints++; }
static _Noreturn void fatal(const char *fmt, ...) { (void)fmt; longjmp(done, 2); }
static _Noreturn void finish(int status) { assert(status == EXIT_SUCCESS); longjmp(done, 1); }
#define exit finish
#include "cli-info.inc"
#undef exit
struct peer { int fd, test; };
static void *send_info(void *arg)
{
    struct peer *p = arg;
    dtraced_hdr_t hdr = { .msg_type = DTRACED_MSG_INFO };
    dtraced_infomsg_t info = { .client_kind = DTRACED_KIND_FORWARDER };
    size_t transferred;
    hdr.info.count = p->test == 0 ? 0 : 1;
    if (p->test == 2) hdr.info.count = SIZE_MAX;
    if (p->test == 5) hdr.msg_type = DTRACED_MSG_ELF;
    /* Send the header byte by byte, including a truncated header case. */
    unsigned char wire[DTRACED_MSGHDRSIZE];
    dtraced_wire_encode_header(wire, &hdr);
    size_t length = p->test == 3 ? sizeof(wire) / 2 : sizeof(wire);
    for (size_t i = 0; i < length; i++)
        assert(dtraced_io_transfer(p->fd, wire + i, 1, true,
            dtraced_io_milliseconds() + 3000, &transferred) == 0);
    if (p->test == 1 || p->test == 4 || p->test == 6 ||
        p->test == 7 || p->test == 8) {
        memcpy(info.client_name, "vm", 3);
        if (p->test == 4)
            memset(info.client_name, 'x', sizeof(info.client_name));
        unsigned char entry[DTRACED_INFO_WIRE_SIZE];
        dtraced_wire_encode_info(entry, &info);
        if (p->test == 7) entry[7] = 'x';
        if (p->test == 8) entry[0] = DTRACED_KIND_UNKNOWN;
        length = p->test == 6 ? sizeof(entry) / 2 : sizeof(entry);
        assert(dtraced_io_transfer(p->fd, entry, length, true,
            dtraced_io_milliseconds() + 3000, &transferred) == 0);
    }
    close(p->fd);
    return NULL;
}
int main(void)
{
    alarm(20);
    for (int test = 0; test < 9; test++) {
        int fds[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        receiver = fds[0]; prints = 0;
        struct peer peer = { fds[1], test };
        pthread_t thread; assert(pthread_create(&thread, NULL, send_info, &peer) == 0);
        int result = setjmp(done);
        if (result == 0) listing();
        assert(result == (test <= 1 ? 1 : 2));
        assert(prints == (test == 0 ? 1 : test == 1 ? 2 : 0));
        assert(pthread_join(thread, NULL) == 0);
    }
    puts("PASS: fragmented and empty VM listings; bounded sizes, names, types and EOF handling");
    return 0;
}
