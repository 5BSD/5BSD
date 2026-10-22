/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/socket.h>
#include <sys/event.h>
#include <dttransport.h>
#include <cassert>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <thread>
#include <unistd.h>
#include "dtraced_directory.h"
#include "dtraced_connection.h"
#include "dtraced_dttransport.h"
#include "dtraced_job.h"
#include "dtraced_process.h"
#include "dtraced_state.h"

using namespace dtraced;

static std::atomic<int> replay_seen{0};
static bool
observe_replay(dir &directory, struct dirent *entry)
{
    if (directory.memorized(entry->d_name))
        return true;
    if (strncmp(entry->d_name, "elf.", 4) == 0) {
        guest_delivery delivery{};
        assert(find_guest_delivery(*directory.state,
            directory.full_path() + entry->d_name, delivery));
        replay_seen.fetch_add(1);
    }
    return directory.memorize_file(entry);
}

static void
transfer(int fd, dtt_entry_t &entry, bool sending)
{
    unsigned char *bytes = reinterpret_cast<unsigned char *>(&entry);
    size_t offset = 0;
    while (offset < sizeof(entry)) {
        ssize_t n = sending ? write(fd, bytes + offset,
            sizeof(entry) - offset) : read(fd, bytes + offset,
            sizeof(entry) - offset);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        offset += static_cast<size_t>(n);
    }
}

static void
exercise(uint8_t host_phase, unsigned unavailable_replies = 0,
    bool lost_reply = false, bool grant = false)
{
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
    char path[] = "/tmp/hypertrace-recovery-query.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    dir inbound(path, grant ? observe_replay : nullptr);
    state s{};
    s.inbounddir = &inbound;
    inbound.state = &s;
    s.dtt_fd = pair[0];
    guest_delivery delivery{};
    delivery.delivery_id = host_phase == 't' ? 18 : 17;
    delivery.vmid = 42;
    delivery.epoch = 99;
    delivery.program_id[0] = 0x42;
    delivery.source_id[0] = 0x55;
    delivery.authorized_current = false;
    assert(inbound.record_delivery(guest_delivery_record(delivery),
        delivery_phase::pending, true));
    if (grant) {
        bool created = false;
        assert(inbound.write_identified_data(
            (const unsigned char *)"\177ELF", 4,
            delivery.program_id.data(), &created,
            delivery.source_id.data()) && created);
        assert(inbound.populate_existing());
        replay_seen.store(0);
    }
    s.guest_deliveries.push_back(delivery);
    std::thread watcher;
    if (grant)
        watcher = std::thread([&] { assert(inbound.listen()); });
    std::thread listener(listen_dttransport, &s);
    dtt_entry_t query{};
    transfer(pair[1], query, false);
    assert(query.event_kind == DTT_STATUS &&
        query.u.installed.delivery_id == delivery.delivery_id &&
        query.u.installed.vmid == 42 && query.u.installed.epoch == 99 &&
        query.u.installed.program_id[0] == 0x42 &&
        query.u.installed.source_id[0] == 0x55 &&
        query.u.installed.query_id != 0);
    for (unsigned attempt = 0; attempt < unavailable_replies; ++attempt) {
        uint64_t previous_query_id = query.u.installed.query_id;
        query.event_kind = DTT_HOST_STATUS;
        query.u.installed.phase = 'u';
        transfer(pair[1], query, true);
        assert(inbound.delivery_status(guest_delivery_record(delivery)) ==
            static_cast<int>(delivery_phase::pending));
        transfer(pair[1], query, false);
        assert(query.event_kind == DTT_STATUS &&
            query.u.installed.delivery_id == delivery.delivery_id &&
            query.u.installed.query_id != previous_query_id);
    }
    if (lost_reply) {
        dtt_entry_t stale = query;
        transfer(pair[1], query, false);
        assert(query.event_kind == DTT_STATUS &&
            query.u.installed.delivery_id == delivery.delivery_id &&
            query.u.installed.query_id != stale.u.installed.query_id);
        stale.event_kind = DTT_HOST_STATUS;
        stale.u.installed.phase = 't';
        transfer(pair[1], stale, true);
        assert(inbound.delivery_status(guest_delivery_record(delivery)) ==
            static_cast<int>(delivery_phase::pending));
    }
    query.event_kind = DTT_HOST_STATUS;
    query.u.installed.phase = host_phase;
    query.u.installed.replay = grant;
    if (grant)
        assert(SHA256((const unsigned char *)"\177ELF", 4,
            query.u.installed.digest) != nullptr);
    transfer(pair[1], query, true);
    if (host_phase != 't' && !grant) {
        dtt_entry_t terminal{};
        transfer(pair[1], terminal, false);
        assert(terminal.event_kind == DTT_UNINSTALLED &&
            terminal.u.installed.delivery_id == delivery.delivery_id);
        terminal.event_kind = DTT_HOST_UNINSTALLED;
        transfer(pair[1], terminal, true);
    }
    bool retired = false;
    for (int i = 0; i < 200; ++i) {
        {
            std::lock_guard lock(s.deliverymtx);
            retired = grant ? s.guest_deliveries.size() == 1 &&
                s.guest_deliveries[0].authorized_current :
                s.guest_deliveries.empty();
        }
        if (retired) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    assert(retired && inbound.delivery_status(guest_delivery_record(delivery)) ==
        (grant ? (int)delivery_phase::pending : 0));
    if (grant) {
        for (int i = 0; i < 200 && replay_seen.load() == 0; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (replay_seen.load() != 1)
            fprintf(stderr, "replay callback count: %d\n", replay_seen.load());
        assert(replay_seen.load() == 1);
    }
    s.shutdown.store(true);
    listener.join();
    if (grant) watcher.join();
    close(pair[0]); close(pair[1]);
    DIR *files = opendir(path);
    assert(files != nullptr);
    while (struct dirent *entry = readdir(files))
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
            assert(unlinkat(inbound.dirfd, entry->d_name, 0) == 0);
    assert(closedir(files) == 0 && rmdir(path) == 0);
}

static void
exercise_outbound(uint8_t host_phase, bool unavailable = false)
{
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
    char path[] = "/tmp/hypertrace-outbound-query.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    dir outbound(path, nullptr);
    state s{};
    s.outbounddir = &outbound;
    outbound.state = &s;
    s.dtt_fd = pair[0];
    durable_delivery record{};
    record.scope = 2;
    record.journal_version = 4;
    record.session_id[0] = 1;
    record.delivery_id = 71;
    record.program_id[0] = 2;
    record.source_id[0] = 3;
    record.peer_uid = 0;
    record.peer_pid = 100;
    assert(SHA256((const unsigned char *)"\177ELF", 4,
        record.payload_digest.data()) != nullptr);
    assert(outbound.record_delivery(record, delivery_phase::pending, true));
    std::thread listener(listen_dttransport, &s);
    dtt_entry_t query{};
    transfer(pair[1], query, false);
    assert(query.event_kind == DTT_INGRESS_STATUS &&
        query.u.installed.vmid == 0 && query.u.installed.epoch == 0 &&
        query.u.installed.delivery_id == record.delivery_id &&
        query.u.installed.program_id[0] == 2 &&
        query.u.installed.source_id[0] == 3 &&
        query.u.installed.query_id != 0);
    if (unavailable) {
        auto first = query.u.installed.query_id;
        query.event_kind = DTT_HOST_INGRESS_STATUS;
        query.u.installed.vmid = 42;
        query.u.installed.epoch = 99;
        query.u.installed.phase = 'u';
        transfer(pair[1], query, true);
        transfer(pair[1], query, false);
        assert(query.event_kind == DTT_INGRESS_STATUS &&
            query.u.installed.query_id != first &&
            outbound.delivery_status(record) == (int)delivery_phase::pending);
    }
    query.event_kind = DTT_HOST_INGRESS_STATUS;
    query.u.installed.vmid = 42;
    query.u.installed.epoch = 99;
    query.u.installed.phase = host_phase;
    query.u.installed.revoked = host_phase == 0;
    if (host_phase == 'a' || host_phase == 'p')
        memcpy(query.u.installed.digest, record.payload_digest.data(), 32);
    transfer(pair[1], query, true);
    int expected = host_phase == 'a' ? 0 : (int)delivery_phase::pending;
    bool settled = false;
    for (int i = 0; i < 200; ++i) {
        settled = outbound.delivery_status(record) == expected;
        if (settled) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    assert(settled);
    s.shutdown.store(true);
    listener.join();
    close(pair[0]); close(pair[1]);
    DIR *files = opendir(path);
    assert(files != nullptr);
    while (struct dirent *entry = readdir(files))
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
            assert(unlinkat(outbound.dirfd, entry->d_name, 0) == 0);
    assert(closedir(files) == 0 && rmdir(path) == 0);
}

static void
exercise_outbound_replay_queue(uint8_t host_phase, bool bound,
    bool expect_queued = true)
{
    int dtt[2], peer[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, dtt) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, peer) == 0);
    assert(fcntl(dtt[0], F_SETFL, O_NONBLOCK) == 0);
    int kq = kqueue();
    assert(kq >= 0);
    char path[] = "/tmp/hypertrace-replay-queue.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    dir outbound(path, nullptr);
    state s{};
    outbound.state = &s;
    s.outbounddir = &outbound;
    s.dtt_fd = dtt[0];
    durable_delivery record{};
    record.scope = 2;
    record.journal_version = 4;
    record.session_id[0] = 1;
    record.delivery_id = 81;
    if (bound) {
        record.vmid = 42;
        record.epoch = 99;
    }
    record.program_id[0] = 0xaa;
    record.source_id[0] = 0xbb;
    record.peer_uid = geteuid();
    record.peer_pid = getpid() + 1;
    bool created = false;
    assert(outbound.write_identified_data(
        (const unsigned char *)"\177ELF", 4, record.program_id.data(),
        &created, record.source_id.data()) && created);
    assert(SHA256((const unsigned char *)"\177ELF", 4,
        record.payload_digest.data()));
    assert(outbound.record_delivery(record, delivery_phase::pending, true));
    dtd_initmsg_t hello{};
    hello.kind = DTRACED_KIND_FORWARDER;
    hello.subs = DTD_SUB_ELFWRITE;
    hello.session_id[0] = 2;
    snprintf(hello.ident, sizeof(hello.ident),
        "dtraced-dttransport-%d", getpid());
    {
        client_fd forwarder(kq, peer[0], hello);
        forwarder.peer_uid = geteuid();
        forwarder.peer_pid = getpid();
        assert(forwarder.enable_write(&forwarder));
        s.sockfds.insert(&forwarder);
        std::thread listener(listen_dttransport, &s);
        dtt_entry_t query{};
        transfer(dtt[1], query, false);
        assert(query.event_kind == DTT_INGRESS_STATUS &&
            query.u.installed.delivery_id == record.delivery_id);
        query.event_kind = DTT_HOST_INGRESS_STATUS;
        query.u.installed.vmid = 42;
        query.u.installed.epoch = 99;
        query.u.installed.phase = host_phase;
        if (host_phase == 'p')
            memcpy(query.u.installed.digest,
                record.payload_digest.data(), 32);
        transfer(dtt[1], query, true);
        bool queued = false;
        for (int i = 0; i < 200; ++i) {
            {
                std::lock_guard lock(s.joblistmtx);
                queued = s.joblist.size() == 1;
            }
            if (queued) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        assert(queued == expect_queued);
        s.shutdown.store(true);
        listener.join();
        if (expect_queued) {
            job *replay = s.joblist.front();
            s.joblist.clear();
            assert(replay->notify_elfwrite_get().replay != nullptr &&
                replay->notify_elfwrite_get().replay->delivery_id ==
                record.delivery_id);
            delete replay;
        } else {
            assert(s.joblist.empty() &&
                outbound.delivery_status(record) ==
                (int)delivery_phase::pending);
        }
        s.sockfds.clear();
    }
    close(dtt[0]); close(dtt[1]); close(peer[1]); close(kq);
    DIR *files = opendir(path);
    assert(files != nullptr);
    while (struct dirent *entry = readdir(files))
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
            assert(unlinkat(outbound.dirfd, entry->d_name, 0) == 0);
    assert(closedir(files) == 0 && rmdir(path) == 0);
}

static void
exercise_vm_identity_query(void)
{
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
    state s{};
    s.dtt_fd = pair[0];
    std::thread listener(listen_dttransport, &s);
    uint16_t vmid = 0;
    uint64_t epoch = 0;
    std::thread requester([&] {
        assert(s.query_vm_identity(vmid, epoch));
    });
    dtt_entry_t query{};
    transfer(pair[1], query, false);
    assert(query.event_kind == DTT_VM_IDENTITY_QUERY &&
        query.u.installed.query_id != 0 &&
        query.u.installed.delivery_id == 0 &&
        query.u.installed.vmid == 0 && query.u.installed.epoch == 0);
    dtt_entry_t stale{};
    stale.event_kind = DTT_VM_IDENTITY;
    stale.u.installed.query_id = query.u.installed.query_id + 1;
    stale.u.installed.vmid = 42;
    stale.u.installed.epoch = 99;
    transfer(pair[1], stale, true);
    stale.u.installed.query_id = query.u.installed.query_id;
    transfer(pair[1], stale, true);
    requester.join();
    assert(vmid == 42 && epoch == 99);
    s.shutdown.store(true);
    listener.join();
    close(pair[0]); close(pair[1]);
}

static void
exercise_outbound_settled_before_reply(void)
{
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
    char path[] = "/tmp/hypertrace-settled-query.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    dir outbound(path, nullptr);
    state s{};
    s.outbounddir = &outbound;
    outbound.state = &s;
    s.dtt_fd = pair[0];
    durable_delivery record{};
    record.scope = 2;
    record.journal_version = 4;
    record.session_id[0] = 1;
    record.delivery_id = 84;
    record.vmid = 42;
    record.epoch = 99;
    record.program_id[0] = 2;
    record.source_id[0] = 3;
    record.peer_pid = 100;
    assert(SHA256((const unsigned char *)"\177ELF", 4,
        record.payload_digest.data()) != nullptr);
    assert(outbound.record_delivery(record, delivery_phase::pending, true));
    std::thread listener(listen_dttransport, &s);
    dtt_entry_t query{};
    transfer(pair[1], query, false);
    assert(query.event_kind == DTT_INGRESS_STATUS &&
        query.u.installed.delivery_id == record.delivery_id);
    assert(outbound.record_delivery(record, delivery_phase::accepted));
    assert(outbound.retire_accepted_outbound(record));
    query.event_kind = DTT_HOST_INGRESS_STATUS;
    query.u.installed.vmid = 42;
    query.u.installed.epoch = 99;
    query.u.installed.phase = 'a';
    memcpy(query.u.installed.digest, record.payload_digest.data(), 32);
    transfer(pair[1], query, true);
    uint16_t vmid = 0;
    uint64_t epoch = 0;
    std::thread requester([&] { assert(s.query_vm_identity(vmid, epoch)); });
    dtt_entry_t identity{};
    transfer(pair[1], identity, false);
    assert(identity.event_kind == DTT_VM_IDENTITY_QUERY);
    identity.event_kind = DTT_VM_IDENTITY;
    identity.u.installed.vmid = 42;
    identity.u.installed.epoch = 99;
    transfer(pair[1], identity, true);
    requester.join();
    assert(vmid == 42 && epoch == 99 && !s.shutdown.load());
    s.shutdown.store(true);
    listener.join();
    close(pair[0]); close(pair[1]);
    DIR *files = opendir(path);
    assert(files != nullptr);
    while (struct dirent *entry = readdir(files))
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
            assert(unlinkat(outbound.dirfd, entry->d_name, 0) == 0);
    assert(closedir(files) == 0 && rmdir(path) == 0);
}

int main()
{
    alarm(30);
    exercise('i');
    exercise('t');
    exercise('i', 2);
    exercise('i', 0, true);
    exercise('i', 0, false, true);
    exercise_outbound(0);
    exercise_outbound('p');
    exercise_outbound('a');
    exercise_outbound('a', true);
    exercise_outbound_replay_queue('p', false);
    exercise_outbound_replay_queue(0, true);
    exercise_outbound_replay_queue(0, false, false);
    exercise_vm_identity_query();
    exercise_outbound_settled_before_reply();
    puts("PASS: recovered inbound and outbound host status reconciliation");
}
