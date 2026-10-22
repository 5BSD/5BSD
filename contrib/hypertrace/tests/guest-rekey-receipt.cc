/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/hypertrace.h>
#include <dev/dttransport/dttransport.h>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#define DTRACED_SLEEPTIME 10000
static int64_t now_ms;
static int64_t dtraced_io_milliseconds(void) { return now_ms; }
static int fake_usleep(unsigned int usec) {
    now_ms += usec / 1000;
    return 0;
}
static dtt_entry_t last_query;
static int mode, reads, writes, busy_writes;
static ssize_t fake_write(int fd, const void *data, size_t length) {
    assert(fd == 4 && length == sizeof(dtt_entry_t));
    ++writes;
    if (busy_writes > 0) {
        --busy_writes;
        errno = EBUSY;
        return -1;
    }
    last_query = *static_cast<const dtt_entry_t *>(data);
    return length;
}
static ssize_t fake_read(int fd, void *data, size_t length) {
    assert(fd == 4 && length == sizeof(dtt_entry_t));
    ++reads;
    if (mode == 5) {
        errno = EAGAIN;
        return -1;
    }
    dtt_entry_t reply{};
    if (mode == 1 && reads == 1) {
        reply.event_kind = DTT_VM_REKEY;
        reply.u.installed.vmid = 43;
        reply.u.installed.epoch = 100;
    } else {
        reply = last_query;
        reply.event_kind = last_query.event_kind ==
            DTT_REKEY_DELIVERY_QUERY ? DTT_REKEY_DELIVERY_RECEIPT :
            last_query.event_kind == DTT_REKEY_INGRESS_QUERY ?
            DTT_REKEY_INGRESS_RECEIPT : DTT_REKEY_KILL_RECEIPT;
        reply.u.installed.phase = last_query.event_kind ==
            DTT_REKEY_KILL_QUERY ? 'p' : 'a';
        reply.u.installed.revoked = last_query.event_kind ==
            DTT_REKEY_KILL_QUERY ? 1 : 0;
        if ((mode == 6 && reads == 1) ||
            (mode == 7 && reads <= 3) || mode == 9 || mode == 10)
            reply.u.installed.query_id++;
        if (mode == 2) {
            reply.u.installed.query_id++;
            reply.u.installed.vmid++;
        }
        if (mode == 3) reply.u.installed.digest[0]++;
        if (mode == 4) {
            reply.u.installed.phase = 'u';
            reply.u.installed.revoked = 0;
            memset(reply.u.installed.digest, 0, 32);
        }
        if (mode == 8) {
            reply.u.installed.phase = 't';
            reply.u.installed.revoked = 1;
            memset(reply.u.installed.digest, 0, 32);
        }
        if (mode == 9)
            now_ms += 10;
        if (mode == 10)
            reply.u.installed.replay = 1;
    }
    *static_cast<dtt_entry_t *>(data) = reply;
    return length;
}
#define usleep fake_usleep
#define write fake_write
#define read fake_read
namespace dtraced {
#include "guest-rekey-receipt.inc"
}
#undef read
#undef write
#undef usleep

int main(void) {
    uint8_t program[16] = {1}, source[16] = {2}, digest[32] = {3};
    auto query = [&](uint8_t kind, bool terminal_ok = false) {
        reads = writes = 0;
        now_ms = 0;
        return dtraced::query_guest_rekey_receipt(4, kind, 42, 99,
            43, 100, kind == DTT_REKEY_KILL_QUERY ? 123 : 71,
            program, source, digest, terminal_ok, 100);
    };
    assert(query(DTT_REKEY_DELIVERY_QUERY) && writes == 1 && reads == 1);
    busy_writes = 2;
    assert(query(DTT_REKEY_DELIVERY_QUERY) && writes == 3 && reads == 1);
    busy_writes = 100;
    assert(!query(DTT_REKEY_DELIVERY_QUERY) && errno == ETIMEDOUT);
    busy_writes = 0;
    mode = 1;
    assert(query(DTT_REKEY_INGRESS_QUERY) && writes == 1 && reads == 2);
    mode = 2;
    assert(!query(DTT_REKEY_DELIVERY_QUERY) && errno == EPROTO);
    mode = 3;
    assert(!query(DTT_REKEY_DELIVERY_QUERY) && errno == EPROTO);
    mode = 4;
    assert(!query(DTT_REKEY_INGRESS_QUERY) && errno == EAGAIN);
    mode = 5;
    assert(!query(DTT_REKEY_INGRESS_QUERY) && errno == ETIMEDOUT);
    mode = 6;
    assert(query(DTT_REKEY_DELIVERY_QUERY) && reads == 2);
    mode = 7;
    assert(query(DTT_REKEY_DELIVERY_QUERY) && reads == 4);
    mode = 9;
    assert(!query(DTT_REKEY_DELIVERY_QUERY) && errno == ETIMEDOUT);
    mode = 10;
    assert(!query(DTT_REKEY_DELIVERY_QUERY) && errno == EPROTO);
    mode = 8;
    assert(!query(DTT_REKEY_DELIVERY_QUERY) && errno == EPROTO);
    assert(query(DTT_REKEY_DELIVERY_QUERY, true));
    assert(!query(DTT_REKEY_INGRESS_QUERY, true) && errno == EINVAL);
    mode = 0;
    memset(program, 0, sizeof(program));
    memset(digest, 0, sizeof(digest));
    assert(query(DTT_REKEY_KILL_QUERY));
    assert(!query(DTT_REKEY_DELIVERY_QUERY) && errno == EINVAL);
    puts("PASS: exact source receipt replies, old identity and nonce, unavailable, deadline");
}
