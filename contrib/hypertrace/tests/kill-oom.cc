/* SPDX-License-Identifier: BSD-2-Clause */
#include <dttransport.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <cassert>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <poll.h>
#include <thread>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include "dtraced_dttransport.h"
#include "dtraced_directory.h"
#include "dtraced_process.h"
#include "dtraced_state.h"

static std::atomic_int fail_after{-1};
extern "C" void *__real__Znwm(size_t);
extern "C" void *__wrap__Znwm(size_t size)
{
    if (fail_after.load() == 0) throw std::bad_alloc();
    if (fail_after.load() > 0) --fail_after;
    return __real__Znwm(size);
}

static void
exercise(bool fail, bool active = false)
{
    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    assert(fcntl(fd[0], F_SETFL, O_NONBLOCK) == 0);
    dtraced::state s{};
    char path[] = "/tmp/hypertrace-kill.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    dtraced::dir inbound(path, nullptr);
    s.inbounddir = &inbound;
    s.dtt_fd = fd[0];
    dtraced::guest_delivery revoked{};
    revoked.delivery_id = 17;
    revoked.vmid = 42;
    revoked.epoch = 99;
    revoked.program_id[0] = 0x11;
    revoked.source_id[0] = 0x42;
    dtraced::guest_delivery unrelated{};
    unrelated.source_id[0] = 0x43;
    assert(inbound.record_delivery(dtraced::guest_delivery_record(revoked),
        dtraced::delivery_phase::pending, true));
    s.guest_deliveries = {revoked, unrelated};
    if (active) {
        s.pidlist.insert(34567);
        s.pid_deliveries.emplace(34567, revoked);
    }
    std::thread listener(dtraced::listen_dttransport, &s);
    dtt_entry_t event{};
    event.event_kind = DTT_KILL;
    event.u.kill.pid = 12345;
	event.u.kill.source_id[0] = 0x42;
    event.u.kill.vmid = 42;
    event.u.kill.epoch = 99;
    fail_after = fail ? 0 : -1;
    assert(write(fd[1], &event, sizeof(event)) == sizeof(event));
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    bool queued = false;
    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard lk(s.killmtx);
            queued = !s.pids_to_kill.empty();
        }
        if (fail ? s.shutdown.load() : queued)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    fail_after = -1;
    if (fail) {
        assert(s.shutdown.load() == 1);
        assert(s.pids_to_kill.empty());
    } else {
        assert(s.pids_to_kill.size() == 1);
        assert(s.pids_to_kill.front().pid == 12345);
        assert(s.pids_to_kill.front().source_id[0] == 0x42);
        s.shutdown.store(1);
    }
    listener.join();
    assert(inbound.source_revoked(event.u.kill.source_id) == 1);
    if (fail) {
        assert(s.guest_deliveries.size() == 2 &&
            inbound.delivery_status(dtraced::guest_delivery_record(revoked)) ==
            (int)dtraced::delivery_phase::pending);
        std::vector<dtraced::durable_kill> recovered_kills;
        assert(inbound.list_kills(recovered_kills) &&
            recovered_kills.size() == 1 &&
            recovered_kills[0].pid == event.u.kill.pid &&
            recovered_kills[0].vmid == event.u.kill.vmid &&
            recovered_kills[0].epoch == event.u.kill.epoch);
        /* Model a crash after the kill journal sync but before the
         * separate source tombstone sync. Recovery must restore it. */
        const char *tombstone =
            ".revoke.42000000000000000000000000000000";
        assert(unlinkat(inbound.dirfd, tombstone, 0) == 0);
        dtraced::state restart{};
        restart.inbounddir = &inbound;
        restart.dtt_fd = fd[0];
        std::thread recovery(dtraced::listen_dttransport, &restart);
        auto recovered_by = std::chrono::steady_clock::now() +
            std::chrono::seconds(2);
        bool restored = false;
        while (std::chrono::steady_clock::now() < recovered_by) {
            {
                std::lock_guard children(restart.pidlistmtx);
                restored = restart.revoked_sources.count(
                    recovered_kills[0].source_id) == 1;
            }
            if (restored)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        assert(restored);
        struct stat tombstone_stat{};
        assert(fstatat(inbound.dirfd, tombstone, &tombstone_stat,
            AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(tombstone_stat.st_mode));
        restart.shutdown.store(1);
        recovery.join();
    } else {
        assert(s.guest_deliveries.size() == 2 &&
            !s.guest_deliveries[0].authorized_current);
		/* The listener may have sent the durable KILL observation before
		 * shutdown. It must not be mistaken for the terminal child event. */
		dtt_entry_t terminal{};
		bool terminal_seen = false;
		struct pollfd pending{fd[1], POLLIN, 0};
		while (poll(&pending, 1, 0) == 1) {
			dtt_entry_t ack{};
			assert(read(fd[1], &ack, sizeof(ack)) == sizeof(ack));
			if (ack.event_kind == DTT_UNINSTALLED) {
				assert(!active && !terminal_seen);
				terminal = ack;
				terminal_seen = true;
				continue;
			}
			assert(ack.event_kind == DTT_KILL_APPLIED &&
			    ack.u.kill.pid == event.u.kill.pid &&
			    ack.u.kill.vmid == event.u.kill.vmid &&
			    ack.u.kill.epoch == event.u.kill.epoch &&
			    memcmp(ack.u.kill.source_id, event.u.kill.source_id,
			    sizeof(ack.u.kill.source_id)) == 0);
		}
        if (active) {
            assert(!s.guest_deliveries[0].terminal_sent &&
                inbound.delivery_status(
                dtraced::guest_delivery_record(revoked)) ==
                (int)dtraced::delivery_phase::pending);
            assert(poll(&pending, 1, 0) == 0);
            s.pid_deliveries.erase(34567);
            s.pidlist.erase(34567);
            assert(dtraced::finish_guest_delivery(s, revoked));
        }
        assert(s.guest_deliveries[0].terminal_sent &&
            inbound.delivery_status(dtraced::guest_delivery_record(revoked)) ==
            (int)dtraced::delivery_phase::exited);
		if (!terminal_seen)
			assert(read(fd[1], &terminal, sizeof(terminal)) ==
			    sizeof(terminal));
		assert(terminal.event_kind == DTT_UNINSTALLED &&
            terminal.u.installed.delivery_id == 17);
        terminal.event_kind = DTT_HOST_UNINSTALLED;
        assert(dtraced::handle_host_observation(s, terminal));
        assert(s.guest_deliveries.size() == 1 &&
            s.guest_deliveries[0].source_id[0] == 0x43 &&
            inbound.delivery_status(dtraced::guest_delivery_record(revoked)) ==
            0);
    }
    close(fd[0]);
    close(fd[1]);
    DIR *files = opendir(path);
    assert(files != nullptr);
    while (struct dirent *entry = readdir(files))
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
            assert(unlinkat(inbound.dirfd, entry->d_name, 0) == 0);
    assert(closedir(files) == 0);
    assert(rmdir(path) == 0);
}

int main()
{
    exercise(true);
    exercise(false);
    exercise(false, true);
    puts("PASS: durable guest kill journal, crash-window recovery, kill-queue OOM and later events");
}
