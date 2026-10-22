/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
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
    uint8_t token[16], previous_token[16];
};
typedef struct { int dt_active; } dtrace_hdl_t;
#define DTRACE_STATUS_INACTIVE 1
typedef struct {
    uint8_t rx_session[16], program_digest[32];
} dtd_arg_t;
static pthread_mutex_t g_dtpmtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_pgplistmtx = PTHREAD_MUTEX_INITIALIZER;
/* dtrace.c serializes every handle use through these helpers and keeps a
 * per-thread hold count; the worker also reads deferred process wakeups. */
static _Thread_local int t_dtp_depth;
static atomic_int g_proc_wake;
static void dtp_lock(void) { pthread_mutex_lock(&g_dtpmtx); t_dtp_depth++; }
static void dtp_unlock(void) { t_dtp_depth--; pthread_mutex_unlock(&g_dtpmtx); }
static pthread_cond_t g_pgpcond = PTHREAD_COND_INITIALIZER;
static atomic_int g_intr, g_stop, g_session_stop, g_output_worker_done = 1;
static int g_processing_pgp, g_execution_reporting;
static FILE *g_ofp;
static int purge_failure, discard_requested;
static int async_busy, async_error, async_discards;
static int descendants_busy, descendants_error;
static int consumer_descendants_step(void) {
    assert(!g_processing_pgp && !g_execution_reporting &&
        atomic_load(&g_output_worker_done) && !async_busy);
    if (descendants_error) { errno = ESTALE; return -1; }
    return !descendants_busy;
}
static int dtrace_async_discard_step(void) {
    async_discards++;
    if (async_error) { errno = EIO; return -1; }
    return !async_busy;
}

static dtrace_hdl_t handle = {1}, *g_dtp = &handle;
static int dtrace_output_discard(dtrace_hdl_t *dtp, FILE *fp) {
    assert(dtp == &handle);
    discard_requested++;
    if (purge_failure) { errno = EIO; return -1; }
    return fp == NULL ? 0 : fpurge(fp);
}
static int gate_open_failure, gate_suspended = 1, stop_failure, stop_calls;
static uint8_t gate_owner[16];
static int fake_open(const char *path, int flags) {
    assert(strcmp(path, "/dev/dtrace/hypertrace") == 0);
    assert((flags & O_CLOEXEC) != 0);
    return gate_open_failure ? -1 : 77;
}
static int fake_ioctl(int fd, unsigned long command, void *arg) {
    struct hypertrace_epoch_gate *gate = arg;
    assert(fd == 77 && command == HYPERTRACE_IOC_EPOCH_GATE_QUERY);
    gate->suspended = gate_suspended;
    memcpy(gate->token, gate_owner, 16);
    return 0;
}
static int fake_close(int fd) { return fd == 77 ? 0 : close(fd); }
static int commit_peers[2], commit_count, commit_refuse, commit_open_failures;
static int original_peer, drop_original_reply;
static int open_dtraced_session(int subscription, uint8_t session[16]) {
    assert(subscription == DTD_SUB_READDATA && session[0] == 3);
    assert(atomic_load(&g_session_stop) && atomic_load(&g_output_worker_done));
    if (!drop_original_reply) {
        unsigned char reply[DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE];
        /* A single daemon worker must be able to finish its stop RPC before
         * this second request needs that worker. */
        assert(recv(original_peer, reply, sizeof(reply), MSG_PEEK | MSG_DONTWAIT) == sizeof(reply));
    }
    if (commit_open_failures) { commit_open_failures--; errno = EIO; return -1; }
    int pair[2];
    assert(commit_count < 2 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    commit_peers[commit_count++] = pair[1];
    unsigned char accepted = !commit_refuse;
    assert(write(pair[1], &accepted, 1) == 1);
    return pair[0];
}
static int dtrace_status(dtrace_hdl_t *dtp) {
    return dtp->dt_active ? 0 : DTRACE_STATUS_INACTIVE;
}
static int dtrace_stop(dtrace_hdl_t *dtp) {
    assert(dtp == &handle && atomic_load(&g_stop) &&
        atomic_load(&g_session_stop) && atomic_load(&g_output_worker_done) &&
        !g_processing_pgp && !g_execution_reporting);
    stop_calls++;
    return stop_failure ? -1 : 0;
}
#define open fake_open
#define ioctl fake_ioctl
#define close fake_close
#include "consumer-stop-receiver.inc"
#undef open
#undef ioctl
#undef close

typedef struct {
    int (*dc_consume_probe)(void), (*dc_consume_rec)(void);
    void *dc_get_buf, *dc_put_buf;
} dtrace_consumer_t;
#define DTRACE_STATUS_STOPPED 2
#define DTRACE_STATUS_EXITED 3
#define DTRACE_WORKSTATUS_DONE 1
#define DTRACE_WORKSTATUS_OKAY 0
static atomic_int g_siginfo, g_newline, g_impatient;
static int g_psc, g_pslive;
static int stop_on_sleep, stop_on_consume, consume_calls, aggregate_calls, teardown_calls, discard_calls;
static int chew(void) { return 0; }
static int chewrec(void) { return 0; }
static void dtrace_oformat_setup(dtrace_hdl_t *dtp) { assert(dtp == &handle); }
static void dtrace_sleep(dtrace_hdl_t *dtp) {
    assert(dtp == &handle);
    if (stop_on_sleep) atomic_store(&g_session_stop, 1);
}
static int dtrace_oformat(dtrace_hdl_t *dtp) { (void)dtp; return 0; }
static int dtrace_errno(dtrace_hdl_t *dtp) { (void)dtp; return 0; }
static int dtrace_aggregate_print(dtrace_hdl_t *dtp, FILE *fp, void *arg) {
    (void)dtp; (void)fp; (void)arg;
    aggregate_calls++;
    return 0;
}
static void oprintf(const char *text) { (void)text; }
static void dfatal(const char *text) { (void)text; abort(); }
static int dtrace_work_consumer(dtrace_hdl_t *dtp, FILE *fp,
    dtrace_consumer_t *con, void *arg) {
    (void)dtp; (void)fp; (void)con; (void)arg;
    consume_calls++;
    if (stop_on_consume) {
        assert(fputs("old-session-output", fp) >= 0);
        atomic_store(&g_session_stop, 1);
    }
    return DTRACE_WORKSTATUS_DONE;
}
static void dtrace_oformat_teardown(dtrace_hdl_t *dtp) {
    assert(dtp == &handle && !atomic_load(&g_output_worker_done));
    teardown_calls++;
}
static void dtrace_oformat_discard(dtrace_hdl_t *dtp) {
    assert(dtp == &handle && !atomic_load(&g_output_worker_done));
    discard_calls++;
}
#include "consumer-stop-worker.inc"

static int exchange(dtd_arg_t *connection, dtraced_consumer_stop_t *challenge) {
    int sockets[2];
    unsigned char wire[DTRACED_CONSUMER_STOP_WIRE_SIZE];
    unsigned char reply[DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE];
    dtraced_consumer_stop_t result = {0};
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    original_peer = sockets[0];
    if (drop_original_reply)
        assert(shutdown(sockets[0], SHUT_RD) == 0);
    dtraced_wire_encode_consumer_stop(wire, challenge);
    assert(write(sockets[0], wire, sizeof(wire)) == sizeof(wire));
    assert(handle_consumer_stop(connection, sockets[1],
        dtraced_io_deadline_after(1000)) == (commit_refuse ? -1 : 0));
    if (drop_original_reply) {
        assert(commit_count != 0);
        result = *challenge;
        result.result = 1;
    } else {
        assert(read(sockets[0], reply, sizeof(reply)) == sizeof(reply));
        assert(dtraced_wire_decode_consumer_stop_ack(&result, reply) == 0);
    }
    assert(memcmp(result.token, challenge->token, 16) == 0 &&
        result.vmid == challenge->vmid && result.epoch == challenge->epoch);
    close(sockets[0]); close(sockets[1]);
    for (int i = 0; i < commit_count; i++) {
        unsigned char frame[8 + DTRACED_MSGHDRSIZE + DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE];
        dtraced_hdr_t header;
        dtraced_consumer_stop_t proof;
        assert(read(commit_peers[i], frame, sizeof(frame)) == sizeof(frame));
        assert(dtraced_wire_get_u64(frame) == sizeof(frame) - 8);
        assert(dtraced_wire_decode_header(&header, frame + 8) == 0 &&
            header.msg_type == DTRACED_MSG_CONSUMER_STOP_COMMIT);
        assert(dtraced_wire_decode_consumer_stop_ack(&proof,
            frame + 8 + DTRACED_MSGHDRSIZE) == 0 && proof.result == 1);
        assert(memcmp(proof.token, challenge->token, 16) == 0);
        close(commit_peers[i]);
    }
    commit_count = 0;
    return result.result;
}
static void reset_admission(void) {
    atomic_store(&g_stop, 0);
    atomic_store(&g_session_stop, 0);
}
static void *finish_activity(void *unused) {
    (void)unused;
    while (!atomic_load(&g_session_stop))
        usleep(1000);
    pthread_mutex_lock(&g_pgplistmtx);
    g_processing_pgp = g_execution_reporting = 0;
    pthread_mutex_unlock(&g_pgplistmtx);
    atomic_store(&g_output_worker_done, 1);
    return NULL;
}
int main(void) {
    dtd_arg_t connection = {0};
    dtraced_consumer_stop_t challenge = {0};
    challenge.token[0] = gate_owner[0] = 1;
    challenge.source_session[0] = 2;
    challenge.consumer_session[0] = connection.rx_session[0] = 3;
    challenge.program_digest[0] = connection.program_digest[0] = 4;
    challenge.vmid = 7; challenge.epoch = 9;
    assert(exchange(&connection, &challenge) == 1 && stop_calls == 1);
    assert(atomic_load(&g_stop) && atomic_load(&g_session_stop));
    reset_admission();
    commit_open_failures = 1;
    assert(exchange(&connection, &challenge) == 1);
    reset_admission();
    commit_refuse = 1;
    assert(exchange(&connection, &challenge) == 1 && atomic_load(&g_session_stop));
    commit_refuse = 0;
    reset_admission();
    drop_original_reply = 1;
    assert(exchange(&connection, &challenge) == 1);
    drop_original_reply = 0;
    reset_admission();
    challenge.consumer_session[0]++;
    assert(exchange(&connection, &challenge) == 0 && !atomic_load(&g_stop));
    challenge.consumer_session[0]--;
    challenge.program_digest[0]++;
    assert(exchange(&connection, &challenge) == 0 && !atomic_load(&g_stop));
    challenge.program_digest[0]--;
    gate_suspended = 0;
    assert(exchange(&connection, &challenge) == 0 && !atomic_load(&g_stop));
    gate_suspended = 1;
    gate_owner[0]++;
    assert(exchange(&connection, &challenge) == 0 && !atomic_load(&g_stop));
    gate_owner[0]--;
    stop_failure = 1;
    int before_discard = discard_requested;
    assert(exchange(&connection, &challenge) == 0 && atomic_load(&g_stop));
    assert(discard_requested == before_discard + 1);
    stop_failure = 0;
    reset_admission();
    handle.dt_active = 0;
    int previous_calls = stop_calls;
    assert(exchange(&connection, &challenge) == 1 && stop_calls == previous_calls);
    handle.dt_active = 1;
    /* Each outstanding activity independently prevents a positive proof. */
    for (int which = 0; which < 5; which++) {
        reset_admission();
        descendants_busy = which == 4;
        async_busy = which == 3;
        g_processing_pgp = which == 0;
        g_execution_reporting = which == 1;
        atomic_store(&g_output_worker_done, which != 2);
        assert(consumer_stop_quiesce(&challenge,
            dtraced_io_deadline_after(20)) == 0 && errno == ETIMEDOUT);
        assert(atomic_load(&g_stop) && stop_calls == previous_calls);
    }
    descendants_busy = 0;
    descendants_error = 1;
    assert(consumer_stop_quiesce(&challenge, dtraced_io_deadline_after(1000)) == 0 && errno == ESTALE);
    descendants_error = 0;
    async_busy = 0;
    async_error = 1;
    assert(consumer_stop_quiesce(&challenge, dtraced_io_deadline_after(1000)) == 0 && errno == EIO);
    async_error = 0;
    g_processing_pgp = g_execution_reporting = 0;
    atomic_store(&g_output_worker_done, 1);
    pthread_mutex_lock(&g_dtpmtx);
    assert(consumer_stop_quiesce(&challenge,
        dtraced_io_deadline_after(20)) == 0 && errno == ETIMEDOUT);
    pthread_mutex_unlock(&g_dtpmtx);
    reset_admission();
    g_processing_pgp = g_execution_reporting = 1;
    atomic_store(&g_output_worker_done, 0);
    pthread_t finishing;
    assert(pthread_create(&finishing, NULL, finish_activity, NULL) == 0);
    assert(consumer_stop_quiesce(&challenge,
        dtraced_io_deadline_after(1000)) == 1);
    assert(pthread_join(finishing, NULL) == 0);
    gate_suspended = 0;
    assert(consumer_stop_quiesce(&challenge,
        dtraced_io_deadline_after(1000)) == 0);
    /* Exercise the real output worker, both ordinary and stopped exits. */
    dtrace_workarg_t work = { .print_upon_exit = 1 };
    for (int mode = 0; mode < 4; mode++) {
        reset_admission();
        atomic_store(&g_output_worker_done, 0);
        atomic_store(&g_session_stop, mode == 1);
        stop_on_sleep = mode == 2;
        stop_on_consume = mode == 3;
        if (mode == 3) {
            g_ofp = tmpfile(); assert(g_ofp);
            assert(setvbuf(g_ofp, NULL, _IOFBF, 4096) == 0);
        }
        consume_calls = aggregate_calls = teardown_calls = discard_calls = 0;
        assert(dtc_work(&work) == NULL);
        assert(atomic_load(&g_output_worker_done));
        assert(teardown_calls == (mode == 0) && discard_calls == (mode != 0));
        assert(consume_calls == (mode == 0 || mode == 3) && aggregate_calls == (mode == 0));
        if (mode == 3) {
            struct stat st;
            assert(fstat(fileno(g_ofp), &st) == 0 && st.st_size == 0);
            gate_suspended = 1;
            purge_failure = 1;
            assert(consumer_stop_quiesce(&challenge, dtraced_io_deadline_after(1000)) == 0 && errno == EIO);
            purge_failure = 0;
            assert(consumer_stop_quiesce(&challenge, dtraced_io_deadline_after(1000)) == 1);
            assert(fflush(g_ofp) == 0);
            assert(fstat(fileno(g_ofp), &st) == 0 && st.st_size == 0);
            assert(fclose(g_ofp) == 0); g_ofp = NULL;
        }
    }
    puts("PASS: collector stop identity, worker fencing, stop failure and bounded waits");
    return 0;
}
