// SPDX-License-Identifier: BSD-2-Clause
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "dtraced_wire.h"

#define HYPERTRACE_IOC_EPOCH_GATE_QUERY 44UL
struct hypertrace_epoch_gate {
    uint64_t epoch;
    uint16_t vmid;
    uint16_t reserved[3];
    uint32_t suspended;
    uint32_t reserved2;
    uint8_t token[16];
    uint8_t previous_token[16];
};
typedef struct dtrace_hdl { int unused; } dtrace_hdl_t;
typedef struct dtrace_consumer {
    int (*dc_consume_probe)(void);
    int (*dc_consume_rec)(void);
    void *dc_get_buf;
    void *dc_put_buf;
} dtrace_consumer_t;
typedef struct dtd_arg {
    int rx_sock;
    int wx_sock;
    uint8_t rx_session[16];
    uint8_t program_digest[32];
    void *hostpgp;
} dtd_arg_t;
static int chew(void) { return 0; }
static int chewrec(void) { return 0; }
static pthread_mutex_t g_dtpmtx = PTHREAD_MUTEX_INITIALIZER;
/* dtrace.c serializes every handle use through these helpers. */
static void dtp_lock(void) { pthread_mutex_lock(&g_dtpmtx); }
static void dtp_unlock(void) { pthread_mutex_unlock(&g_dtpmtx); }
static atomic_int g_intr, g_stop;
static dtrace_hdl_t handle;
static dtrace_hdl_t *g_dtp = &handle;
static FILE *g_ofp;
static int gate_open_failure, gate_suspended = 1, drain_failure;
static uint8_t gate_owner[16];
static int
fake_open(const char *path, int flags)
{
    assert(strcmp(path, "/dev/dtrace/hypertrace") == 0);
    assert((flags & O_CLOEXEC) != 0);
    return (gate_open_failure ? -1 : 77);
}
static int
fake_ioctl(int fd, unsigned long command, void *arg)
{
    struct hypertrace_epoch_gate *gate = arg;
    assert(fd == 77 && command == HYPERTRACE_IOC_EPOCH_GATE_QUERY);
    gate->suspended = gate_suspended;
    memcpy(gate->token, gate_owner, 16);
    return (0);
}
static int fake_close(int fd) { assert(fd == 77); return 0; }
static int
dtrace_consume_quiesced(dtrace_hdl_t *dtp, FILE *fp,
    dtrace_consumer_t *con, void *arg)
{
    assert(dtp == &handle && con->dc_consume_probe == chew &&
        con->dc_consume_rec == chewrec && arg == NULL);
    if (drain_failure)
        return (-1);
    assert(fputs("drained", fp) >= 0);
    return (0);
}

#define open fake_open
#define ioctl fake_ioctl
#define close fake_close
#include "consumer-drain-receiver.inc"
#undef open
#undef ioctl
#undef close

static int
exchange(dtd_arg_t *connection, dtraced_consumer_drain_t *challenge)
{
    int sockets[2];
    unsigned char wire[DTRACED_CONSUMER_DRAIN_WIRE_SIZE];
    unsigned char reply[DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE];
    dtraced_consumer_drain_t result = {0};
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    dtraced_wire_encode_consumer_drain(wire, challenge);
    assert(write(sockets[0], wire, sizeof(wire)) == sizeof(wire));
    assert(handle_consumer_drain(connection, sockets[1],
        dtraced_io_deadline_after(1000)) == 0);
    assert(read(sockets[0], reply, sizeof(reply)) == sizeof(reply));
    assert(dtraced_wire_decode_consumer_drain_ack(&result, reply) == 0);
    assert(memcmp(result.token, challenge->token, 16) == 0 &&
        result.vmid == challenge->vmid && result.epoch == challenge->epoch);
    assert(close(sockets[0]) == 0 && close(sockets[1]) == 0);
    return (result.result);
}

int
main(void)
{
    dtd_arg_t connection = {0};
    dtraced_consumer_drain_t challenge = {0};
    FILE *regular = tmpfile();
    assert(regular != NULL);
    g_ofp = regular;
    challenge.token[0] = 1;
    challenge.source_session[0] = 2;
    challenge.consumer_session[0] = connection.rx_session[0] = 3;
    challenge.program_digest[0] = connection.program_digest[0] = 4;
    challenge.vmid = 7;
    challenge.epoch = 9;
    memcpy(gate_owner, challenge.token, 16);
    assert(exchange(&connection, &challenge) == 1);
    challenge.consumer_session[0] = 5;
    assert(exchange(&connection, &challenge) == 0);
    challenge.consumer_session[0] = 3;
    gate_owner[0] = 8;
    assert(exchange(&connection, &challenge) == 0);
    gate_owner[0] = 1;
    gate_suspended = 0;
    assert(exchange(&connection, &challenge) == 0);
    gate_suspended = 1;
    drain_failure = 1;
    assert(exchange(&connection, &challenge) == 0);
    drain_failure = 0;
    gate_open_failure = 1;
    assert(exchange(&connection, &challenge) == 0);
    gate_open_failure = 0;
    atomic_store(&g_stop, 1);
    assert(exchange(&connection, &challenge) == 0);
    atomic_store(&g_stop, 0);
    assert(fclose(regular) == 0);
    g_ofp = NULL;
    assert(exchange(&connection, &challenge) == 0);
    return (0);
}
