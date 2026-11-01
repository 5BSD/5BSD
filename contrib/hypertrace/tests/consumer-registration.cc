/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The real event-loop path of a dtrace -E program registration.
 *
 * dtrace(1) opens its ELF receiver subscribed only to DTD_SUB_ELFWRITE and
 * sends DTRACED_MSG_CONSUMER_PROGRAM (HPI1/HPI2) on it, then waits for one
 * status byte.  state::dispatch_read() used to drop every read event of such a
 * socket ("acknowledgments belong to the sending worker"), so the registration
 * was never read and every dtrace -E failed with "failed to bind HyperTrace
 * consumer program: Operation timed out", with or without a guest.
 *
 * Oracles: before registration the readable ELF receiver gets a READ_DATA job;
 * that job answers HPI1 with status 1 and binds the program; afterwards the
 * receiver's bytes are left to the sending worker (no job); an unregistered
 * ELF-only consumer may send nothing but a registration; a refused
 * registration stays retryable; an unidentified consumer is never read.
 */
#include <sys/event.h>
#include <sys/socket.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include "dtraced_clientrequest.h"
#include "dtraced_connection.h"
#include "dtraced_io.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
#include "dtraced_wire.h"
using namespace dtraced;
namespace dtraced {
struct state_admission_test {
    static void control_machine(state &s) { s.ctrlmachine = 1; }
    /* Returns the READ_DATA job dispatched for one readable event, or null. */
    static job *readable(state &s, client_fd &c, int kq) {
        s.kq_hdl = kq;
        struct kevent event;
        EV_SET(&event, c.get_fd(), EVFILT_READ, 0, 0, 0, &c);
        assert(s.dispatch_read(&c, event));
        if (s.dispatched_jobs.empty())
            return (nullptr);
        assert(s.dispatched_jobs.size() == 1);
        job *pending = s.dispatched_jobs.front();
        s.dispatched_jobs.clear();
        assert(pending->kind == READ_DATA && pending->connsockfd == &c);
        return (pending);
    }
};
}
static void
send_frame(int fd, int type, const void *body, size_t len)
{
    unsigned char size_wire[8], header_wire[DTRACED_MSGHDRSIZE];
    dtraced_hdr_t header{};
    header.msg_type = type;
    header.elf.len = len;
    dtraced_wire_put_u64(size_wire, DTRACED_MSGHDRSIZE + len);
    dtraced_wire_encode_header(header_wire, &header);
    assert(write(fd, size_wire, sizeof(size_wire)) == sizeof(size_wire));
    assert(write(fd, header_wire, sizeof(header_wire)) ==
        (ssize_t)sizeof(header_wire));
    if (len != 0)
        assert(write(fd, body, len) == (ssize_t)len);
}
static client_fd *
consumer(state &s, int kq, int *peer, bool identified)
{
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    *peer = sv[1];
    dtd_initmsg_t hello{};
    hello.kind = DTRACED_KIND_CONSUMER;
    hello.subs = DTD_SUB_ELFWRITE;
    hello.session_id[0] = 0x51;
    if (identified)
        snprintf(hello.ident, sizeof(hello.ident),
            "dtrace-%u-0102030405060708090a0b0c0d0e0f10", (unsigned)getpid());
    else
        strlcpy(hello.ident, "dtrace-anonymous", sizeof(hello.ident));
    auto *c = new client_fd(kq, sv[0], hello);
    assert(c->enable_read(c));
    s.sockfds.insert(c);
    return (c);
}
int
main()
{
    alarm(30);
    state s{};
    state_admission_test::control_machine(s); /* host overlord, no spool */
    int kq = kqueue();
    assert(kq >= 0);
    int peer;
    client_fd *c = consumer(s, kq, &peer, true);
    assert(c->consumer_birth_valid && c->peer_pid == getpid());

    /* 1. The registration frame is read: a READ_DATA job is dispatched. */
    uint8_t digest[32];
    memset(digest, 0xa5, sizeof(digest));
    send_frame(peer, DTRACED_MSG_CONSUMER_PROGRAM, digest, sizeof(digest));
    job *pending = state_admission_test::readable(s, *c, kq);
    assert(pending != nullptr);	/* fails before the fix: dropped */

    /* 2. The job binds the program and answers status 1. */
    assert(pending->read_data(s));
    delete pending;
    unsigned char status = 0;
    assert(read(peer, &status, 1) == 1 && status == 1);
    assert(c->consumer_program_valid && c->consumer_registration_acked.load());
    assert(memcmp(c->consumer_program_digest.data(), digest, 32) == 0);

    /* 3. After registration, inbound bytes are delivery acknowledgments for
     *    the sending worker: the event loop must not start a reader. */
    unsigned char ack = 1;
    assert(write(peer, &ack, 1) == 1);
    assert(state_admission_test::readable(s, *c, kq) == nullptr);
    unsigned char drained;
    assert(read(c->get_fd(), &drained, 1) == 1 && drained == 1);

    /* 4. An unregistered ELF-only consumer may send only a registration. */
    int peer2;
    client_fd *c2 = consumer(s, kq, &peer2, true);
    send_frame(peer2, DTRACED_MSG_STATS, nullptr, 0);
    pending = state_admission_test::readable(s, *c2, kq);
    assert(pending != nullptr);
    errno = 0;
    assert(!pending->read_data(s) && errno == EPROTO);
    delete pending;
    assert(!c2->consumer_program_valid &&
        !c2->consumer_registration_acked.load());

    /* 5. A refused registration (all-zero digest) answers 0 and stays
     *    retryable on the same connection; the retry is read and bound. */
    int peer3;
    client_fd *c3 = consumer(s, kq, &peer3, true);
    uint8_t zero[32] = {};
    send_frame(peer3, DTRACED_MSG_CONSUMER_PROGRAM, zero, sizeof(zero));
    pending = state_admission_test::readable(s, *c3, kq);
    assert(pending != nullptr && pending->read_data(s));
    delete pending;
    assert(read(peer3, &status, 1) == 1 && status == 0);
    assert(!c3->consumer_registration_acked.load());
    send_frame(peer3, DTRACED_MSG_CONSUMER_PROGRAM, digest, sizeof(digest));
    pending = state_admission_test::readable(s, *c3, kq);
    assert(pending != nullptr && pending->read_data(s));
    delete pending;
    assert(read(peer3, &status, 1) == 1 && status == 1);
    assert(c3->consumer_registration_acked.load());

    /* 6. A consumer without a birth identity is never read. */
    int peer4;
    client_fd *c4 = consumer(s, kq, &peer4, false);
    assert(!c4->consumer_birth_valid);
    send_frame(peer4, DTRACED_MSG_CONSUMER_PROGRAM, digest, sizeof(digest));
    assert(state_admission_test::readable(s, *c4, kq) == nullptr);

    s.sockfds.clear();
    delete c; delete c2; delete c3; delete c4;
    close(peer); close(peer2); close(peer3); close(peer4); close(kq);
    puts("PASS: dtrace -E program registration is read, acknowledged once, "
        "and later ELF-receiver bytes stay with the sending worker");
}
