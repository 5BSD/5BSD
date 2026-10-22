/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/socket.h>
#include <dttransport.h>
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <poll.h>
#include <thread>
#include <unistd.h>
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_state.h"

using namespace dtraced;

static thread_local int fail_monotonic_after = -1;
extern "C" int __real_clock_gettime(clockid_t, struct timespec *);
extern "C" int
__wrap_clock_gettime(clockid_t clock, struct timespec *time)
{
    if (clock == CLOCK_MONOTONIC && fail_monotonic_after == 0) {
        errno = EIO;
        return -1;
    }
    if (clock == CLOCK_MONOTONIC && fail_monotonic_after > 0)
        --fail_monotonic_after;
    return __real_clock_gettime(clock, time);
}

static void
transfer(int fd, dtt_entry_t &entry, bool sending)
{
    auto *bytes = reinterpret_cast<unsigned char *>(&entry);
    size_t offset = 0;
    while (offset < sizeof(entry)) {
        ssize_t n = sending ? write(fd, bytes + offset, sizeof(entry) - offset) :
            read(fd, bytes + offset, sizeof(entry) - offset);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        offset += static_cast<size_t>(n);
    }
}

int main()
{
    alarm(75);
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
    char path[] = "/tmp/hypertrace-runtime-query.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    dir outbound(path, nullptr);
    state s{};
    s.outbounddir = &outbound;
    outbound.state = &s;
    s.dtt_fd = pair[0];
    std::thread listener(listen_dttransport, &s);
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
    assert(vmid == 42 && epoch == 99);
    pollfd ready{pair[1], POLLIN, 0};
    assert(poll(&ready, 1, 0) == 0);
    /* Delayed device admission must not grant a fresh reply deadline. */
    int slow_pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, slow_pair) == 0);
    assert(fcntl(slow_pair[0], F_SETFL, O_NONBLOCK) == 0);
    assert(fcntl(slow_pair[1], F_SETFL, O_NONBLOCK) == 0);
    state slow{};
    slow.dtt_fd = slow_pair[0];
    char filler[4096]{};
    size_t filled = 0;
    ssize_t n;
    while ((n = write(slow_pair[0], filler, sizeof(filler))) > 0)
        filled += static_cast<size_t>(n);
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    uint16_t ignored_vmid = 0;
    uint64_t ignored_epoch = 0;
    fail_monotonic_after = 0;
    assert(!slow.query_vm_identity(ignored_vmid, ignored_epoch));
    assert(errno == EIO && slow.vm_identity_query_id == 0);
    fail_monotonic_after = 2;
    assert(!slow.query_vm_identity(ignored_vmid, ignored_epoch));
    assert(errno == EIO && slow.vm_identity_query_id == 0);
    fail_monotonic_after = -1;
    bool timed_out = false;
    auto started = std::chrono::steady_clock::now();
    std::thread unanswered([&] {
        uint16_t ignored_vmid = 0;
        uint64_t ignored_epoch = 0;
        assert(!slow.query_vm_identity(ignored_vmid, ignored_epoch));
        timed_out = errno == ETIMEDOUT;
    });
    std::this_thread::sleep_for(std::chrono::seconds(5));
    char sink[65536];
    while (filled > 0) {
        n = read(slow_pair[1], sink, std::min(filled, sizeof(sink)));
        assert(n > 0);
        filled -= static_cast<size_t>(n);
    }
    unanswered.join();
    auto elapsed = std::chrono::steady_clock::now() - started;
    assert(timed_out);
    assert(elapsed >= std::chrono::seconds(9) &&
        elapsed < std::chrono::seconds(14));
    dtt_entry_t delayed_query{};
    transfer(slow_pair[1], delayed_query, false);
    assert(delayed_query.event_kind == DTT_VM_IDENTITY_QUERY);
    close(slow_pair[0]); close(slow_pair[1]);
    assert(poll(&ready, 1, 0) == 0);
    durable_delivery record{};
    record.scope = 2;
    record.journal_version = 4;
    record.session_id[0] = 1;
    record.delivery_id = 83;
    record.vmid = 42;
    record.epoch = 99;
    record.program_id[0] = 2;
    record.source_id[0] = 3;
    record.peer_pid = 100;
    assert(SHA256((const unsigned char *)"\177ELF", 4,
        record.payload_digest.data()) != nullptr);
    assert(outbound.record_delivery(record, delivery_phase::pending, true));

    assert(poll(&ready, 1, 65000) == 1 && (ready.revents & POLLIN));
    dtt_entry_t query{};
    transfer(pair[1], query, false);
    assert(query.event_kind == DTT_INGRESS_STATUS &&
        query.u.installed.delivery_id == record.delivery_id &&
        query.u.installed.query_id != 0);
    query.event_kind = DTT_HOST_INGRESS_STATUS;
    query.u.installed.vmid = 42;
    query.u.installed.epoch = 99;
    query.u.installed.phase = 'a';
    memcpy(query.u.installed.digest, record.payload_digest.data(), 32);
    transfer(pair[1], query, true);
    bool retired = false;
    for (int i = 0; i < 200; ++i) {
        retired = outbound.delivery_status(record) == 0;
        if (retired) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    assert(retired);
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
    int clock_pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, clock_pair) == 0);
    state clock_failed{};
    clock_failed.dtt_fd = clock_pair[0];
    std::thread failing_listener([&] {
        fail_monotonic_after = 0;
        listen_dttransport(&clock_failed);
        fail_monotonic_after = -1;
    });
    failing_listener.join();
    assert(clock_failed.shutdown.load());
    close(clock_pair[0]); close(clock_pair[1]);
    puts("PASS: runtime outbound reconciliation and transport clock failure");
}
