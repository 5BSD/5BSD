/* SPDX-License-Identifier: BSD-2-Clause */
#include <time.h>
#include <stdint.h>
static int test_clock_gettime(clockid_t, struct timespec *);
#define clock_gettime test_clock_gettime
#define main dtracedctl_main
#include "dtracedctl.c"
#undef main
#undef clock_gettime
#include <pthread.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", \
    __FILE__, __LINE__, #x); abort(); } } while (0)
static int fail_clock, huge_clock;
static int
test_clock_gettime(clockid_t clock, struct timespec *time)
{
    if (fail_clock) {
        errno = EIO;
        return (-1);
    }
    if (huge_clock) {
        time->tv_sec = INT64_MAX / 1000;
        time->tv_nsec = 0;
        return (0);
    }
    return (clock_gettime(clock, time));
}
struct peer {
    int fd;
    unsigned char ack;
    size_t count;
    uint64_t type;
    dtraced_stats_t stats;
};
static void *handshake(void *arg)
{
    int fd = accept(*(int *)arg, NULL, NULL);
    dtd_initmsg_t hello = { .kind = DTRACED_KIND_DTRACED,
        .protocol_version = DTRACED_PROTOCOL_VERSION };
    size_t transferred;
    CHECK(fd >= 0);
    CHECK(dtraced_io_transfer(fd, &hello, sizeof(hello), true,
        dtraced_io_milliseconds() + 2000, &transferred) == 0);
    CHECK(dtraced_io_transfer(fd, &hello, sizeof(hello), false,
        dtraced_io_milliseconds() + 2000, &transferred) == 0);
    CHECK(hello.kind == DTRACED_KIND_CONSUMER &&
        hello.subs == DTD_SUB_READDATA &&
        hello.protocol_version == DTRACED_PROTOCOL_VERSION);
    close(fd);
    return (NULL);
}
static void get(int fd, void *buffer, size_t length)
{
    size_t n;
    CHECK(dtraced_io_transfer(fd, buffer, length, false,
        dtraced_io_milliseconds() + 2000, &n) == 0);
}
static void *read_frame(void *arg)
{
    struct peer *peer = arg;
    uint64_t total, length, remaining;
    dtraced_hdr_t header;
    unsigned char size_wire[8], header_wire[DTRACED_MSGHDRSIZE];
    char name[64];
    get(peer->fd, size_wire, sizeof(size_wire));
    total = dtraced_wire_get_u64(size_wire);
    CHECK(total >= DTRACED_MSGHDRSIZE);
    get(peer->fd, header_wire, sizeof(header_wire));
    CHECK(dtraced_wire_decode_header(&header, header_wire) == 0);
    CHECK(header.msg_type == peer->type);
    CHECK(header.cleanup.num_entries == peer->count);
    remaining = total - DTRACED_MSGHDRSIZE;
    for (size_t i = 0; i < peer->count; i++) {
        CHECK(remaining >= sizeof(size_wire));
        get(peer->fd, size_wire, sizeof(size_wire));
        length = dtraced_wire_get_u64(size_wire);
        remaining -= sizeof(size_wire);
        CHECK(length <= sizeof(name) && remaining >= length);
        get(peer->fd, name, (size_t)length);
        CHECK(name[length - 1] == '\0' && strcmp(name, i ? "second" : "first") == 0);
        remaining -= length;
    }
    CHECK(remaining == 0);
    CHECK(send(peer->fd, &peer->ack, 1, MSG_NOSIGNAL) == 1);
    if (peer->ack == 1 && peer->type == DTRACED_MSG_STATS) {
        size_t transferred;
        unsigned char stats_wire[DTRACED_STATS_WIRE_SIZE];
        dtraced_wire_encode_stats(stats_wire, &peer->stats);
        CHECK(dtraced_io_transfer(peer->fd, stats_wire,
            sizeof(stats_wire), true, dtraced_io_milliseconds() + 2000,
            &transferred) == 0);
    }
    return (NULL);
}
int main(void)
{
    names_t parsed = {0};
    char valid_names[] = "first,second";
    char empty_name[] = "";
    char leading_comma[] = ",first";
    char doubled_comma[] = "first,,second";
    char trailing_comma[] = "first,";
    char oversized_name[4097];
    CHECK(parse_names(valid_names, &parsed) == 0);
    CHECK(parsed.n_strs == 2 && strcmp(parsed.str[0], "first") == 0 &&
        strcmp(parsed.str[1], "second") == 0);
    freenames(&parsed);
    CHECK(parse_names(empty_name, &parsed) == -1 && errno == EINVAL);
    CHECK(parse_names(leading_comma, &parsed) == -1 && errno == EINVAL);
    CHECK(parse_names(doubled_comma, &parsed) == -1 && errno == EINVAL);
    CHECK(parse_names(trailing_comma, &parsed) == -1 && errno == EINVAL);
    memset(oversized_name, 'x', sizeof(oversized_name));
    oversized_name[4096] = '\0';
    CHECK(parse_names(oversized_name, &parsed) == -1 && errno == EMSGSIZE);
    names_t no_names = {0};
    handle_t no_socket = { .sockfd = -1 };
    fail_clock = 1;
    CHECK(send_request(&no_socket, &no_names, DTRACED_MSG_CLEANUP,
        NULL) == -1 && errno == EIO);
    fail_clock = 0;
    huge_clock = 1;
    CHECK(send_request(&no_socket, &no_names, DTRACED_MSG_CLEANUP,
        NULL) == -1 && errno == EOVERFLOW);
    huge_clock = 0;

    char directory[] = "/tmp/hypertrace-control-client.XXXXXX";
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    CHECK(mkdtemp(directory) != NULL);
    CHECK(snprintf(path, sizeof(path), "%s/sub.sock", directory) > 0);
    CHECK(strlcpy(address.sun_path, path, sizeof(address.sun_path)) <
        sizeof(address.sun_path));
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(listener >= 0 && bind(listener, (struct sockaddr *)&address,
        sizeof(address)) == 0 && listen(listener, 1) == 0);
    pthread_t server;
    CHECK(pthread_create(&server, NULL, handshake, &listener) == 0);
    handle_t connected = open_dtraced(path);
    CHECK(connected.sockfd >= 0);
    close(connected.sockfd);
    CHECK(pthread_join(server, NULL) == 0);
    close(listener);
    CHECK(unlink(path) == 0 && rmdir(directory) == 0);
    int fds[2];
    char *values[] = { "first", "second" };
    names_t names = { .str = values, .n_strs = 2 };
    pthread_t thread;
    for (int pass = 0; pass < 4; pass++) {
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        handle_t handle = { .sockfd = fds[0] };
        struct peer peer = {
            .fd = fds[1], .ack = pass == 2 ? 0 : 1,
            .count = pass == 0 ? 0 : 2,
            .type = pass == 3 ? DTRACED_MSG_STATS : DTRACED_MSG_CLEANUP,
            .stats = { .forwarder_channels = 2,
                .outbound_deliveries = 7,
                .installed_deliveries = 3,
                .revoked_deliveries = 1 },
        };
        names.n_strs = peer.count;
        CHECK(pthread_create(&thread, NULL, read_frame, &peer) == 0);
        dtraced_stats_t stats = { 0 };
        int result = send_request(&handle, &names, peer.type,
            pass == 3 ? &stats : NULL);
        CHECK(pass == 2 ? result == -1 && errno == EPROTO : result == 0);
        if (pass == 3)
            CHECK(memcmp(&stats, &peer.stats, sizeof(stats)) == 0);
        CHECK(pthread_join(thread, NULL) == 0);
        close(fds[0]); close(fds[1]);
    }
    names.n_strs = 4097;
    handle_t invalid = { .sockfd = -1 };
    CHECK(send_request(&invalid, &names, DTRACED_MSG_CLEANUP,
        NULL) == -1 && errno == EINVAL);
    char long_name[4097]; memset(long_name, 'x', sizeof(long_name)); long_name[4096] = 0;
    values[0] = long_name; names.n_strs = 1;
    CHECK(send_request(&invalid, &names, DTRACED_MSG_CLEANUP,
        NULL) == -1 && errno == EMSGSIZE);
    puts("PASS: cleanup and stats frames, names, deadlines and NAK");
    return (0);
}
