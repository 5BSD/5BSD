/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>
#include <sys/socket.h>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <set>
#include <string>
#include <vector>
#include <unistd.h>
#include "dtraced_clientrequest.h"
#include "dtraced_connection.h"
#include "dtraced_io.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
using namespace dtraced;
namespace dtraced {
struct state_admission_test {
    static void dispatch_control_read(state &s, client_fd &caller, int kq) {
        s.kq_hdl = kq;
        struct kevent event;
        EV_SET(&event, caller.get_fd(), EVFILT_READ, 0, 0, 0, &caller);
        assert(s.dispatch_read(&caller, event));
        assert(s.dispatched_jobs.size() == 1);
        job *pending = s.dispatched_jobs.front();
        assert(pending->kind == READ_DATA && pending->connsockfd == &caller);
        s.dispatched_jobs.clear();
        delete pending;
    }
};
}
int main() {
    alarm(15);
    state s{};
    int kq = kqueue(); assert(kq >= 0);
    std::vector<int> peers;
    auto add = [&](const char *name, int kind, uint64_t subs) {
        int sv[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        peers.push_back(sv[1]);
        dtd_initmsg_t hello{};
        hello.kind = kind; hello.subs = subs;
        strlcpy(hello.ident, name, sizeof(hello.ident));
        auto *client = new client_fd(kq, sv[0], hello);
        assert(client->enable_write(client));
        s.sockfds.insert(client);
    };
    add("alpha", DTRACED_KIND_FORWARDER, DTD_SUB_CLEANUP);
    add("alphabet", DTRACED_KIND_FORWARDER, DTD_SUB_CLEANUP);
    add("beta", DTRACED_KIND_FORWARDER, DTD_SUB_CLEANUP);
    add("unsubscribed", DTRACED_KIND_FORWARDER, 0);
    add("consumer", DTRACED_KIND_CONSUMER, DTD_SUB_CLEANUP);
    int admin[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, admin) == 0);
    dtd_initmsg_t admin_hello{}; admin_hello.kind = DTRACED_KIND_CONSUMER;
    admin_hello.subs = DTD_SUB_READDATA;
    client_fd caller(kq, admin[0], admin_hello);
    assert(caller.peer_uid == geteuid() && caller.peer_pid == getpid());
    assert(caller.enable_read(&caller));
    state_admission_test::dispatch_control_read(s, caller, kq);
    caller.peer_uid = 0;
    caller.peer_pid = getpid();
    dtraced_hdr_t denied{}; denied.msg_type = DTRACED_MSG_CLEANUP;
    caller.peer_uid = 1;
    client_request unprivileged(s, denied, nullptr, 0, &caller);
    assert(!unprivileged.handle() && errno == EPERM && s.joblist.empty());
    caller.peer_uid = 0;
    caller.kind = DTRACED_KIND_FORWARDER;
    client_request wrong_role(s, denied, nullptr, 0, &caller);
    assert(!wrong_role.handle() && errno == EPERM && s.joblist.empty());
    caller.kind = DTRACED_KIND_CONSUMER;
    denied.cleanup.vmid = 42;
    denied.cleanup.epoch = 99;
    client_request scoped_cleanup(s, denied, nullptr, 0, &caller);
    assert(!scoped_cleanup.handle() && errno == EPROTO &&
        s.joblist.empty());
    dtraced_hdr_t stats_hdr{}; stats_hdr.msg_type = DTRACED_MSG_STATS;
    caller.peer_uid = 1;
    client_request denied_stats(s, stats_hdr, nullptr, 0, &caller);
    assert(!denied_stats.handle() && errno == EPERM);
    caller.peer_uid = 0;
    stats_hdr.cleanup.vmid = 42;
    stats_hdr.cleanup.epoch = 99;
    client_request scoped_stats(s, stats_hdr, nullptr, 0, &caller);
    assert(!scoped_stats.handle() && errno == EPROTO);
    stats_hdr.cleanup.vmid = 0;
    stats_hdr.cleanup.epoch = 0;
    for (client_fd *fd : s.sockfds) {
        if (strcmp(fd->ident, "alpha") == 0) {
            outbound_delivery installed{}; installed.observed = true;
            outbound_delivery revoked{}; revoked.revoked = true;
            fd->outbound_deliveries.push_back(installed);
            fd->outbound_deliveries.push_back(revoked);
        }
    }
    client_request all_stats(s, stats_hdr, nullptr, 0, &caller);
    assert(all_stats.handle() && all_stats.stats_response() != nullptr);
    assert(all_stats.stats_response()->forwarder_channels == 4);
    assert(all_stats.stats_response()->outbound_deliveries == 2);
    assert(all_stats.stats_response()->installed_deliveries == 1);
    assert(all_stats.stats_response()->revoked_deliveries == 1);
    assert(caller.respond_with_stats(true, all_stats.stats_response()));
    unsigned char stats_ack = 0;
    dtraced_stats_t stats_wire{};
    size_t transferred = 0;
    int64_t deadline = dtraced_io_deadline_after(1000);
    assert(dtraced_io_transfer(admin[1], &stats_ack, sizeof(stats_ack),
        false, deadline, &transferred) == 0);
    assert(dtraced_io_transfer(admin[1], &stats_wire, sizeof(stats_wire),
        false, deadline, &transferred) == 0);
    assert(stats_ack == 1 && stats_wire.forwarder_channels == 4 &&
        stats_wire.installed_deliveries == 1);
    const char one[] = "beta";
    size_t one_len = sizeof(one);
    std::vector<unsigned char> filter(sizeof(one_len) + one_len);
    memcpy(filter.data(), &one_len, sizeof(one_len));
    memcpy(filter.data() + sizeof(one_len), one, one_len);
    stats_hdr.cleanup.num_entries = 1;
    client_request beta_stats(s, stats_hdr, filter.data(), filter.size(), &caller);
    assert(beta_stats.handle() && beta_stats.stats_response()->forwarder_channels == 1);
    assert(beta_stats.stats_response()->outbound_deliveries == 0);
    client_request malformed_stats(s, stats_hdr, nullptr, 0, &caller);
    assert(!malformed_stats.handle() && errno == EPROTO);
    auto request = [&](std::vector<std::string> names, std::set<std::string> expected) {
        std::vector<unsigned char> payload;
        for (const auto &name : names) {
            size_t len = name.size() + 1, start = payload.size();
            payload.resize(start + sizeof(len) + len);
            memcpy(payload.data() + start, &len, sizeof(len));
            memcpy(payload.data() + start + sizeof(len), name.c_str(), len);
        }
        dtraced_hdr_t hdr{}; hdr.msg_type = DTRACED_MSG_CLEANUP;
        hdr.cleanup.num_entries = names.size();
        client_request req(s, hdr, payload.data(), payload.size(), &caller);
        assert(req.handle());
        std::set<std::string> actual;
        for (job *j : s.joblist) {
            assert(j->kind == CLEANUP);
            assert(actual.insert(j->connsockfd->ident).second);
            assert(*j->cleanup_get() == names);
            if (names.size() == 1 && names[0] == "alpha") {
                j->connsockfd->vmid = 42;
                j->connsockfd->vm_epoch = 99;
				assert(!j->send_cleanup(s) && errno == ESTALE);
                j->connsockfd->vmid = 0;
                j->connsockfd->vm_epoch = 0;
            }
            delete j;
        }
        s.joblist.clear(); assert(actual == expected);
    };
    request({"alpha"}, {"alpha"});
    request({"missing"}, {});
    request({"alpha", "alpha", "beta"}, {"alpha", "beta"});
    request({}, {"alpha", "alphabet", "beta"});
    request({""}, {});
    for (auto *client : s.sockfds) delete client;
    s.sockfds.clear();
    for (int fd : peers) close(fd);
    close(admin[1]);
    close(kq);
    puts("PASS: cleanup routing and filtered stats, authorization and stale attestation rejection");
}
