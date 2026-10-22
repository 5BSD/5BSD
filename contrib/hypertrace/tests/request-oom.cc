/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>
#include <sys/socket.h>
#include <cassert>
#include <cstring>
#include <new>
#include <cstdlib>
#include <unistd.h>
#include "dtraced_clientrequest.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
#include "dtraced_wire.h"
using namespace dtraced;
static int fail_after = -1;
extern "C" void *__real__Znwm(size_t);
extern "C" void *__wrap__Znwm(size_t size) {
    if (fail_after == 0) throw std::bad_alloc();
    if (fail_after > 0) --fail_after;
    return __real__Znwm(size);
}
int main() {
    state s{};
    char path[] = "/tmp/hypertrace-request.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    dir outbound(path, nullptr);
    s.outbounddir = &outbound;
    int kq = kqueue(), sv[2], sv2[2], consumer_pair[2]; assert(kq >= 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, consumer_pair) == 0);
    dtd_initmsg_t hello{};
    hello.kind = DTRACED_KIND_FORWARDER;
    hello.subs = DTD_SUB_CLEANUP | DTD_SUB_KILL;
    strlcpy(hello.ident, "target", sizeof(hello.ident));
    auto *client = new client_fd(kq, sv[0], hello);
    assert(client->enable_write(client)); s.sockfds.insert(client);
    auto *client2 = new client_fd(kq, sv2[0], hello);
    assert(client2->enable_write(client2)); s.sockfds.insert(client2);
    hello.kind = DTRACED_KIND_CONSUMER;
    hello.subs = DTD_SUB_READDATA;
    client_fd consumer(kq, consumer_pair[0], hello);
    consumer.peer_uid = 0; /* Model the privileged cleanup operator. */
    consumer.peer_pid = getpid();
    unsigned char payload[sizeof(size_t) + 7]; size_t len = 7;
    memcpy(payload, &len, sizeof(len)); memcpy(payload + sizeof(len), "target", len);
    uint8_t source[16] = {0x42};
    const char *kill_record =
        ".kill.0001.000000000000002a.0000007b.42000000000000000000000000000000";
    for (int type : {DTRACED_MSG_CLEANUP, DTRACED_MSG_KILL}) {
        unsigned failures = 0, successes = 0;
        for (int n = 0; n < 48; ++n) {
            dtraced_hdr_t hdr{}; hdr.msg_type = type;
            if (type == DTRACED_MSG_CLEANUP) hdr.cleanup.num_entries = 1;
            else { hdr.kill.pid = 123; hdr.kill.vmid = 1; hdr.kill.epoch = 42;
                hdr.kill.source_id[0] = 0x42; }
            client_request req(s, hdr, payload,
                type == DTRACED_MSG_KILL ? 0 : sizeof(payload), &consumer);
            fail_after = n;
            bool ok = req.handle();
            fail_after = -1;
            if (ok) ++successes; else { ++failures; assert(errno == ENOMEM); }
            if (type == DTRACED_MSG_KILL) {
                assert(outbound.source_revoked(source) == (ok ? 1 : 0));
                if (ok)
                    assert(unlinkat(outbound.dirfd, kill_record, 0) == 0);
            }
            for (auto *j : s.joblist) delete j;
            s.joblist.clear();
            assert(client->is_dead()); /* no leaked job reference */
            assert(client2->is_dead());
        }
        assert(failures >= 2 && successes != 0);
    }
    {
        job input(READ_DATA, client);
        size_t length = DTRACED_MSGHDRSIZE;
        assert(write(sv[1], &length, sizeof(length)) == sizeof(length));
        dtraced_hdr_t header{};
        header.msg_type = DTRACED_MSG_STATS;
        unsigned char header_wire[DTRACED_MSGHDRSIZE];
        dtraced_wire_encode_header(header_wire, &header);
        assert(write(sv[1], header_wire, sizeof(header_wire)) ==
            (ssize_t)sizeof(header_wire));
        fail_after = 0;
        assert(!input.read_data(s) && errno == ENOMEM);
        fail_after = -1;
    }
    assert(client->is_dead());
    s.sockfds.clear(); delete client; delete client2;
    close(sv[1]); close(sv2[1]); close(consumer_pair[1]); close(kq);
    assert(outbound.source_revoked(source) == 0);
    assert(unlinkat(outbound.dirfd, ".handoff.lock", 0) == 0);
    assert(rmdir(path) == 0);
    puts("PASS: allocation failure before durable kill commit and job publication; no leaked socket references");
}
