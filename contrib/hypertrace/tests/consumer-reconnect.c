/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dtraced.h>
#include <dtraced_io.h>
#include <dtraced_wire.h>

static char test_sockpath[sizeof(((struct sockaddr_un *)0)->sun_path)];
#undef DTRACED_SOCKPATH
#define DTRACED_SOCKPATH test_sockpath

typedef struct dtd_arg {
    int rx_sock;
    int wx_sock;
    uint8_t rx_session[16];
    uint8_t program_digest[32];
    uint8_t program_registration[64];
} dtd_arg_t;
static atomic_bool g_intr;
static atomic_bool g_stop;
#include "consumer-reconnect.inc"

struct server_arg {
    int listener;
    uint8_t rx_session[16];
    uint8_t program_digest[32];
    uint8_t program_registration[64];
    char birth_ident[DTRACED_FDIDENTLEN];
};

static void *
accept_connections(void *opaque)
{
    struct server_arg *server = opaque;
    /* First HPI1 is refused. Reconnect must repeat it before opening wx. */
    for (int i = 0; i < 3; i++) {
        int fd = accept(server->listener, NULL, NULL);
        assert(fd >= 0);
        dtd_initmsg_t banner = {
            .protocol_version = DTRACED_PROTOCOL_VERSION,
            .kind = DTRACED_KIND_DTRACED
        }, hello = { 0 };
        size_t transferred;
        int64_t deadline = dtraced_io_milliseconds() + 3000;
        assert(dtraced_wire_write_init(fd, &banner, deadline,
            &transferred) == 0);
        assert(dtraced_wire_read_init(fd, &hello, deadline,
            &transferred) == 0);
        assert(hello.kind == DTRACED_KIND_CONSUMER);
        assert(hello.subs == (i < 2 ? DTD_SUB_ELFWRITE : DTD_SUB_READDATA));
        if (i == 0)
            strlcpy(server->birth_ident, hello.ident,
                sizeof(server->birth_ident));
        else
            assert(strcmp(hello.ident, server->birth_ident) == 0);
        if (i < 2)
            assert(memcmp(hello.session_id, server->rx_session, 16) == 0);
        else
            assert(memcmp(hello.session_id, server->rx_session, 16) != 0);
        if (i < 2) {
            size_t length;
            unsigned char frame[DTRACED_MSGHDRSIZE + 64];
            dtraced_hdr_t header = {0};
            unsigned char ack = i == 0 ? 0 : 1;
            assert(dtraced_io_read_size(fd, &length, deadline,
                &transferred) == 0 && length == sizeof(frame));
            assert(dtraced_io_transfer(fd, frame, sizeof(frame), false,
                deadline, &transferred) == 0);
            assert(dtraced_wire_decode_header(&header, frame) == 0 &&
                header.msg_type == DTRACED_MSG_CONSUMER_PROGRAM &&
                header.elf.len == 64 &&
                memcmp(frame + DTRACED_MSGHDRSIZE,
                server->program_registration, 64) == 0);
            assert(dtraced_io_transfer(fd, &ack, 1, true, deadline,
                &transferred) == 0);
        }
        close(fd);
    }
    return NULL;
}

int
main(void)
{
    alarm(15);
    assert(dtraced_connection_lost(ECONNRESET));
    assert(dtraced_connection_lost(EPIPE));
    assert(!dtraced_connection_lost(ETIMEDOUT));
    char directory[] = "/tmp/hypertrace-reconnect.XXXXXX";
    assert(mkdtemp(directory) != NULL);
    assert(snprintf(test_sockpath, sizeof(test_sockpath), "%s/s", directory) > 0);
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    assert(strlcpy(addr.sun_path, test_sockpath, sizeof(addr.sun_path)) <
        sizeof(addr.sun_path));
    assert(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(listener, 3) == 0);
    struct server_arg server = { .listener = listener,
        .rx_session = { 0x61 }, .program_digest = { 0x42 } };
    memcpy(server.program_registration, "HPI2", 4);
    memcpy(server.program_registration + 8, server.program_digest, 32);
    dtraced_wire_put_u64(server.program_registration + 40, 1);
    dtraced_wire_put_u64(server.program_registration + 48, 2);
    dtraced_wire_put_u64(server.program_registration + 56, 3);
    uint8_t digest[32], lifetime[24];
    assert(dtraced_wire_decode_consumer_program_v2(server.program_registration,
        64, digest, lifetime) == 0);
    assert(memcmp(digest, server.program_digest, 32) == 0);
    for (size_t n = 0; n < 64; n++)
        assert(dtraced_wire_decode_consumer_program_v2(server.program_registration,
            n, digest, lifetime) == EPROTO);
    const unsigned bad_offsets[] = {0, 4, 8, 40, 56};
    for (unsigned i = 0; i < sizeof(bad_offsets)/sizeof(bad_offsets[0]); i++) {
        uint8_t bad[64]; memcpy(bad, server.program_registration, 64);
        if (i == 0 || i == 1) bad[bad_offsets[i]] ^= 1;
        else memset(bad + bad_offsets[i], 0, i == 2 ? 32 : i == 3 ? 16 : 8);
        memset(digest, 0xaa, sizeof(digest)); memset(lifetime, 0xbb, sizeof(lifetime));
        assert(dtraced_wire_decode_consumer_program_v2(bad, 64, digest, lifetime) == EPROTO);
        for (unsigned j = 0; j < sizeof(digest); j++) assert(digest[j] == 0xaa);
        for (unsigned j = 0; j < sizeof(lifetime); j++) assert(lifetime[j] == 0xbb);
    }
    pthread_t thread;
    assert(pthread_create(&thread, NULL, accept_connections, &server) == 0);
    int old_rx[2], old_wx[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, old_rx) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, old_wx) == 0);
    dtd_arg_t connection = { .rx_sock = old_rx[0], .wx_sock = old_wx[0],
        .rx_session = { 0x61 }, .program_digest = { 0x42 } };
    memcpy(connection.program_registration, server.program_registration, 64);
    int rx = old_rx[0], wx = old_wx[0];
    assert(reconnect_dtraced(&connection, &rx, &wx) == 0);
    assert(rx >= 0 && wx >= 0 && rx != wx);
    assert(connection.rx_sock == rx && connection.wx_sock == wx);
    assert(pthread_join(thread, NULL) == 0);
    close(rx);
    close(wx);
    close(old_rx[1]);
    close(old_wx[1]);
    close(listener);
    assert(unlink(test_sockpath) == 0);
    assert(rmdir(directory) == 0);
    puts("PASS: receiver reconnect retains session and replaces both sockets");
    return 0;
}
