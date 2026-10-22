// SPDX-License-Identifier: BSD-2-Clause
#include <sys/socket.h>
#include <sys/event.h>
#include <cassert>
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include "dtraced_socket.h"
#include "dtraced_connection.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
using namespace dtraced;
using namespace std::chrono_literals;
int main() {
    dtd_initmsg_t init {};
    assert(!valid_initmsg(init));
    init.kind = DTRACED_KIND_CONSUMER;
#ifdef DTRACED_PROTOCOL_VERSION
    assert(!valid_initmsg(init));
    init.protocol_version = DTRACED_PROTOCOL_VERSION;
#endif
    assert(valid_initmsg(init));
    init.ident[1] = 'x';
    assert(!valid_initmsg(init));
    init.ident[1] = '\0';
    init.subs = DTD_SUB_ELFWRITE;
    assert(!valid_initmsg(init));
    init.session_id[0] = 0x7a;
    assert(!valid_initmsg(init));
    std::snprintf(init.ident, sizeof(init.ident),
        "dtrace-42-00000000000000000000000000000001");
    assert(valid_initmsg(init));
    init.protocol_version = 44;
    assert(!valid_initmsg(init));
    init.protocol_version = DTRACED_PROTOCOL_VERSION;
    uint32_t pid = 0;
    std::array<uint8_t, 16> birth{};
    assert(parse_consumer_birth(init.ident, pid, birth) &&
        pid == 42 && birth[15] == 1);
    init.ident[sizeof("dtrace-42-") - 1] = 'A';
    assert(!valid_initmsg(init));
    init.ident[sizeof("dtrace-42-") - 1] = '0';
    assert(valid_initmsg(init));
    init.session_id[0] = 0;
    init.kind = DTRACED_KIND_FORWARDER; init.subs = DTD_SUB_INFO;
    assert(!valid_initmsg(init));
    init.session_id[0] = 0x42;
    init.ident[0] = '\0';
    assert(!valid_initmsg(init));
    std::memset(init.ident, 0, sizeof(init.ident));
    strlcpy(init.ident, "guest-a", sizeof(init.ident));
    assert(valid_initmsg(init));
    init.ident[sizeof("guest-a")] = 'x';
    assert(!valid_initmsg(init));
    init.ident[sizeof("guest-a")] = '\0';
    assert(valid_initmsg(init));
    init.subs |= DTD_SUB_ADMISSION_ACK;
    assert(valid_initmsg(init));
    init.kind = DTRACED_KIND_CONSUMER;
    assert(!valid_initmsg(init));
    init.kind = DTRACED_KIND_FORWARDER;
    init.subs &= ~DTD_SUB_ADMISSION_ACK;
    init.subs = DTD_SUB_SOURCE_RELEASE;
    assert(!valid_initmsg(init));
    init.subs |= DTD_SUB_ADMISSION_ACK;
    assert(valid_initmsg(init));
    init.subs |= DTD_SUB_READDATA;
    assert(!valid_initmsg(init));
    init.subs = DTD_SUB_SOURCE_RELEASE | DTD_SUB_ADMISSION_ACK;
    init.kind = DTRACED_KIND_CONSUMER;
    assert(!valid_initmsg(init));
    init = {};
    init.protocol_version = DTRACED_PROTOCOL_VERSION;
    init.kind = DTRACED_KIND_RELEASE_RECOVERY;
    init.subs = DTD_SUB_RELEASE_RECOVERY;
    strlcpy(init.ident, "hypertrace-release-recovery",
        sizeof(init.ident));
    assert(valid_initmsg(init));
    init.session_id[0] = 1;
    assert(!valid_initmsg(init));
    init.session_id[0] = 0;
    init.subs |= DTD_SUB_READDATA;
    assert(!valid_initmsg(init));
    init.subs = DTD_SUB_RELEASE_RECOVERY;
    init.ident[0] = 'X';
    assert(!valid_initmsg(init));
    init.kind = DTRACED_KIND_FORWARDER;
    assert(!valid_initmsg(init));
    init = {};
    init.protocol_version = DTRACED_PROTOCOL_VERSION;
    init.kind = DTRACED_KIND_FORWARDER;
    init.session_id[0] = 0x42;
    strlcpy(init.ident, "guest-a", sizeof(init.ident));
    init.subs = DTD_SUB_REPLAY_MANIFEST;
    assert(!valid_initmsg(init));
    init.subs |= DTD_SUB_KILL;
    assert(!valid_initmsg(init));
    init.subs |= DTD_SUB_ADMISSION_ACK;
    assert(!valid_initmsg(init));
    init.subs |= DTD_SUB_ELFWRITE;
    assert(valid_initmsg(init));
    init.subs |= DTD_SUB_READDATA;
    assert(!valid_initmsg(init));
    memset(init.ident, 'x', sizeof(init.ident));
    assert(!valid_initmsg(init));
    memset(init.ident, 0, sizeof(init.ident));
    strlcpy(init.ident, "guest-a", sizeof(init.ident));
    init.subs = DTD_SUB_READDATA | DTD_SUB_ELFWRITE;
    assert(!valid_initmsg(init));
    init.subs |= 1ull << 63; assert(!valid_initmsg(init)); init.subs = 0;
    auto guest = guest_forwarder_initmsg(getpid());
    char expected_guest_name[DTRACED_FDIDENTLEN];
    snprintf(expected_guest_name, sizeof(expected_guest_name),
        "dtraced-dttransport-%d", getpid());
    assert(valid_initmsg(guest) &&
        guest.kind == DTRACED_KIND_FORWARDER &&
        guest.subs == DTD_SUB_ELFWRITE &&
        strcmp(guest.ident, expected_guest_name) == 0);
    int sv[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    char b[100];
    assert(!socket_transfer(sv[0], b, 1, false, 0ms));
    assert(errno == EINVAL);
    assert(!socket_transfer(sv[0], b, 1, false,
        std::chrono::milliseconds::max()));
    assert(errno == EOVERFLOW);
    auto start = std::chrono::steady_clock::now();
    assert(!socket_transfer(sv[0], b, 1, false, 60ms)); assert(errno == ETIMEDOUT);
    auto elapsed = std::chrono::steady_clock::now() - start;
    assert(elapsed >= 50ms && elapsed < 2s);
    std::atomic_bool stop {false};
    std::thread trickle([&] {
        while (!stop) { send(sv[1], "x", 1, MSG_NOSIGNAL); std::this_thread::sleep_for(10ms); }
    });
    start = std::chrono::steady_clock::now();
    assert(!socket_transfer(sv[0], b, sizeof(b), false, 60ms)); assert(errno == ETIMEDOUT);
    elapsed = std::chrono::steady_clock::now() - start;
    stop = true; trickle.join(); assert(elapsed >= 50ms && elapsed < 2s);
    close(sv[0]); close(sv[1]);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    int kq = kqueue(); assert(kq >= 0);
    {
        client_fd c(kq, sv[0], init);
        assert(c.enable_write(nullptr));
        state cleanup_state{};
        // Two real multi-part job writers; the reader verifies frame boundaries.
        auto writer = [&](char ch) {
            for (int n = 0; n < 30; ++n) {
                job j(CLEANUP, &c);
                j.cleanup_get() = new cleanup_job(32, std::string(128, ch));
				assert(j.send_cleanup(cleanup_state));
            }
        };
        std::thread a(writer, 'a'), z(writer, 'z');
        for (int n = 0; n < 60; ++n) {
            dtraced_hdr_t hdr;
            assert(socket_transfer(sv[1], &hdr, sizeof(hdr), false));
            assert(hdr.msg_type == DTRACED_MSG_CLEANUP && hdr.cleanup.num_entries == 32);
            char expected = 0;
            for (int i = 0; i < 32; ++i) {
                size_t len; assert(socket_transfer(sv[1], &len, sizeof(len), false));
                assert(len == 129); char name[129];
                assert(socket_transfer(sv[1], name, len, false));
                if (i == 0) expected = name[0];
                assert(expected == 'a' || expected == 'z');
                for (int k = 0; k < 128; ++k) assert(name[k] == expected);
                assert(name[128] == 0);
            }
        }
        a.join(); z.join(); assert(c.is_dead());
        state s {};
        std::atomic_bool done {false};
        std::thread churn([&] {
            while (!done) {
                { std::lock_guard lk(s.sockfdsmtx); s.sockfds.insert(&c); }
                { std::lock_guard lk(s.sockfdsmtx); s.sockfds.erase(&c); }
            }
        });
        std::thread info([&] {
            for (int n = 0; n < 300; ++n) { job j(SEND_INFO, &c); assert(j.send_info(s)); }
        });
        for (int n = 0; n < 300; ++n) {
            dtraced_hdr_t hdr; assert(socket_transfer(sv[1], &hdr, sizeof(hdr), false));
            assert(hdr.msg_type == DTRACED_MSG_INFO && hdr.info.count <= 1);
            if (hdr.info.count) {
                dtraced_infomsg_t item; assert(socket_transfer(sv[1], &item, sizeof(item), false));
                assert(item.client_kind == init.kind);
            }
        }
        info.join(); done = true; churn.join(); assert(c.is_dead());
    }
    close(sv[1]); close(kq);
}
