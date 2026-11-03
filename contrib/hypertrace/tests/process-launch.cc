/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/wait.h>
#include <sys/procdesc.h>
#include <sys/ioctl.h>
#include <dttransport.h>
#include <poll.h>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <string>
#include <thread>
#include <chrono>
#include <unistd.h>
#include <vector>
#include "dtraced_process.h"
#include "dtraced_child_ledger.h"
#include "dtraced_state.h"
#include "dtraced_wire.h"
using namespace dtraced;
extern "C" int __real_ioctl(int, unsigned long, ...);
extern "C" int __wrap_ioctl(int fd, unsigned long command, ...) {
    va_list args;
    va_start(args, command);
    void *data = va_arg(args, void *);
    va_end(args);
    if (command == PDIOC_GET_BIRTH_IDENTITY) {
        auto *birth = static_cast<pd_birth_identity *>(data);
        pid_t pid;
        if (pdgetpid(fd, &pid) != 0) return -1;
        *birth = {pid, 0, 123, static_cast<uint64_t>(pid % 1000000)};
        return 0;
    }
    return __real_ioctl(fd, command, data);
}
static void get(void *p, size_t n) {
    auto *b = static_cast<unsigned char *>(p);
    while (n) { ssize_t r = read(0, b, n); assert(r > 0); b += r; n -= r; }
}
static void put(const void *p, size_t n) {
    auto *b = static_cast<const unsigned char *>(p);
    for (size_t i = 0; i < n; ++i) assert(write(1, b + i, 1) == 1);
}
int main(int argc, char **argv) {
    alarm(15);
    if (argc >= 4 && strcmp(argv[1], "-q") == 0) {
        sigset_t mask;
        assert(sigprocmask(SIG_SETMASK, nullptr, &mask) == 0);
        assert(sigismember(&mask, SIGINT) == 0 && sigismember(&mask, SIGTERM) == 0);
        struct sigaction disposition;
        assert(sigaction(SIGTERM, nullptr, &disposition) == 0);
        assert(disposition.sa_handler == SIG_DFL);
        assert(strcmp(argv[2], "-Y") == 0);
        std::string mode = argv[3];
        if (mode == "plain" || mode == "plain,host") return 17;
        if (mode.compare(0, 4, "elf.") == 0) {
            for (;;) pause();
        }
        assert(argc == 5 && strcmp(argv[4], "-N") == 0);
        unsigned char count_wire[8];
        get(count_wire, sizeof(count_wire));
        size_t count = dtraced_wire_get_u64(count_wire);
        assert(count == 2);
        std::vector<std::array<char, DTRACED_PROGIDENTLEN>> ids(count);
        for (auto &id : ids) get(id.data(), id.size());
        if (mode == "short") { put("DE", 2); return 0; }
        if (mode == "fail") put("FAIL FAIL", sizeof("FAIL FAIL"));
        else {
            put("DEL ident", sizeof("DEL ident"));
            if (mode == "wrong") ids[0].fill('X');
            /* a base program is acknowledged with no identifier */
            if (mode == "base" || mode == "baseinstalled") ids[0].fill(0);
            put(ids[0].data(), ids[0].size());
	    if (mode == "good" || mode == "notinstalled" ||
	        mode == "badstatus" || mode == "shortstatus" ||
	        mode == "base" || mode == "baseinstalled") {
		dtraced_launch_result_t result{};
		result.magic = mode == "badstatus" ? 0 :
		    DTRACED_LAUNCH_MAGIC;
		result.installed = mode == "good" || mode == "baseinstalled";
		memcpy(result.source_ident, ids[0].data(), ids[0].size());
		unsigned char result_wire[DTRACED_LAUNCH_WIRE_SIZE];
		dtraced_wire_encode_launch(result_wire, &result);
		put(result_wire, mode == "shortstatus" ? 4 :
		    sizeof(result_wire));
		if (mode == "shortstatus") return 0;
	    }
        }
        for (;;) pause();
    }
    sigset_t blocked, previous;
    sigemptyset(&blocked); sigaddset(&blocked, SIGINT); sigaddset(&blocked, SIGTERM);
    assert(sigprocmask(SIG_BLOCK, &blocked, &previous) == 0);
    struct sigaction ignored{}, old;
    ignored.sa_handler = SIG_IGN; sigemptyset(&ignored.sa_mask);
    assert(sigaction(SIGTERM, &ignored, &old) == 0);
    state s{};
    char ledger_path[] = "/tmp/hypertrace-guest-ledger.XXXXXX";
    assert(mkdtemp(ledger_path) != nullptr);
    dir inbound(ledger_path, nullptr);
    inbound.state = &s;
    s.inbounddir = &inbound;
    auto forget = [&](pid_t pid) {
        auto fd = s.pidfds.find(pid);
        assert(fd != s.pidfds.end());
        int status;
        pid_t waited = waitpid(pid, &status, WNOHANG);
        assert(waited == pid || (waited == -1 && errno == ECHILD));
        assert(close(fd->second) == 0);
        assert(retire_guest_child(inbound.dirfd, pid));
        s.pidfds.erase(fd);
        s.pid_sources.erase(pid);
        s.pidlist.erase(pid);
    };
    std::array<char, DTRACED_PROGIDENTLEN> a{}, b{};
    a.fill('A'); b.fill('B');
    for (const char *mode : {"good", "notinstalled", "badstatus",
	"shortstatus", "wrong", "short", "fail", "base", "baseinstalled"}) {
        s.identlist = {{a, {}}, {b, {}}};
	bool installed = false;
        bool ok = launch_program(s, mode, false, argv[0], &installed);
        bool base = strcmp(mode, "base") == 0;
        bool accepted = strcmp(mode, "good") == 0 ||
	    strcmp(mode, "notinstalled") == 0 || base;
	if (ok != (accepted || strcmp(mode, "fail") == 0))
	    fprintf(stderr, "launch mode %s returned %d (errno %d)\n",
	        mode, ok, errno);
        assert(ok == (accepted || strcmp(mode, "fail") == 0));
	assert(installed == (strcmp(mode, "good") == 0));
        assert(s.pidlist.size() == (accepted ? 1 : 0));
        assert(s.identlist.size() == (accepted && !base ? 1 : 2));
        if (accepted) {
            assert(s.identlist.front().ident == (base ? a : b));
            pid_t pid = *s.pidlist.begin();
            assert(pdkill(s.pidfds.at(pid), SIGTERM) == 0);
            int status; assert(pdwait(s.pidfds.at(pid), &status,
                WEXITED, nullptr, nullptr) == 0);
            assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM); forget(pid);
        }
        int status; assert(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);
    }
    s.identlist.clear();
    bool replay_installed = false;
    pid_t replay_pid = -1;
    assert(!launch_program(s, "good", false, argv[0],
        &replay_installed, &replay_pid, true) && errno == EAGAIN);
    assert(s.pidlist.empty() && replay_pid == -1);
    s.identlist = {{a, {}}, {b, {}}};
    assert(launch_program(s, "notinstalled", false, argv[0],
        &replay_installed, &replay_pid, true));
    assert(!replay_installed && replay_pid == -1 && s.pidlist.empty());
    s.identlist.clear();
    for (bool host : {false, true}) {
        assert(launch_program(s, "plain", host, argv[0]));
        assert(s.pidlist.size() == 1);
        pid_t pid = *s.pidlist.begin(); int status;
        assert(pdwait(s.pidfds.at(pid), &status,
            WEXITED, nullptr, nullptr) == 0);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 17); forget(pid);
    }
    const std::string sourced =
        "elf.11111111111111111111111111111111.42424242424242424242424242424242";
	std::array<uint8_t, 16> program_id{}, source_id{};
	assert(spool_identity_from_path(sourced, program_id, source_id));
	assert(program_id[0] == 0x11 && source_id[0] == 0x42);
	assert(!spool_identity_from_path("elf.11111111111111111111111111111111",
	    program_id, source_id));
	int observation[2]; assert(pipe(observation) == 0);
	guest_delivery delivery{};
	delivery.delivery_id = 17;
	delivery.vmid = 42;
	delivery.epoch = 99;
	delivery.program_id = program_id;
	delivery.source_id = source_id;
	assert(inbound.record_delivery(guest_delivery_record(delivery),
	    delivery_phase::pending, true));
	assert(!inbound.retire_terminal_delivery(guest_delivery_record(delivery)) &&
	    errno == EBUSY);
	s.guest_deliveries.push_back(delivery);
	guest_delivery found{};
	assert(find_guest_delivery(s, sourced, found) &&
	    found.delivery_id == delivery.delivery_id);
	assert(!find_guest_delivery(s, "bad", found) && errno == EPROTO);
	assert(send_install_observation(observation[1], delivery));
	dtt_entry_t entry{};
	assert(read(observation[0], &entry, sizeof(entry)) == sizeof(entry));
	assert(entry.event_kind == DTT_INSTALLED &&
	    entry.u.installed.delivery_id == 17 &&
	    entry.u.installed.vmid == 42 &&
	    entry.u.installed.epoch == 99 &&
	    entry.u.installed.program_id[0] == 0x11 &&
	    entry.u.installed.source_id[0] == 0x42);
	assert(send_uninstall_observation(observation[1], delivery));
	assert(read(observation[0], &entry, sizeof(entry)) == sizeof(entry) &&
	    entry.event_kind == DTT_UNINSTALLED &&
	    entry.u.installed.delivery_id == 17);
	delivery.delivery_id = 0;
	assert(!send_install_observation(observation[1], delivery) &&
	    errno == EINVAL);
	close(observation[0]); close(observation[1]);
    pid_t registered_pid = -1;
    assert(launch_program(s, sourced, false, argv[0], nullptr,
        &registered_pid));
    assert(s.pidlist.size() == 1 && s.pid_sources.size() == 1);
    pid_t sourced_pid = *s.pidlist.begin();
    assert(registered_pid == sourced_pid);
    assert(s.pid_sources.at(sourced_pid)[0] == 0x42);
    pid_t observed;
    assert(pdgetpid(s.pidfds.at(sourced_pid), &observed) == 0 &&
        observed == sourced_pid);
    assert(close(s.pidfds.at(sourced_pid)) == 0); /* Parent death closes it. */
    s.pidfds.erase(sourced_pid);
    bool disappeared = false;
    for (int i = 0; i < 200; ++i) {
        if (kill(sourced_pid, 0) == -1 && errno == ESRCH) {
            disappeared = true;
            break;
        }
        usleep(10000);
    }
    assert(disappeared);
    int sourced_status;
    assert(waitpid(sourced_pid, &sourced_status, WNOHANG) == -1 &&
        errno == ECHILD);
    assert(retire_guest_child(inbound.dirfd, sourced_pid));
    s.pidlist.erase(sourced_pid); s.pid_sources.erase(sourced_pid);
    int lifecycle[2]; assert(pipe(lifecycle) == 0);
    s.dtt_fd = lifecycle[1];
    registered_pid = -1;
    assert(launch_program(s, sourced, false, argv[0], nullptr,
        &registered_pid));
    assert(registered_pid > 1);
    s.pid_deliveries.emplace(registered_pid, s.guest_deliveries[0]);
    std::thread reaper(&state::reap_children, &s);
    assert(pdkill(s.pidfds.at(registered_pid), SIGTERM) == 0);
    struct pollfd ready{lifecycle[0], POLLIN, 0};
    assert(poll(&ready, 1, 5000) == 1);
    dtt_entry_t exit_event{};
    assert(read(lifecycle[0], &exit_event, sizeof(exit_event)) ==
        sizeof(exit_event) && exit_event.event_kind == DTT_UNINSTALLED &&
        exit_event.u.installed.delivery_id == 17);
    assert(s.pid_deliveries.empty());
    assert(s.guest_deliveries.size() == 1);
    exit_event.event_kind = DTT_HOST_UNINSTALLED;
    assert(handle_host_observation(s, exit_event));
    assert(s.guest_deliveries.empty());
	guest_delivery recovered = delivery;
	recovered.delivery_id = 20;
	recovered.authorized_current = false;
	assert(inbound.record_delivery(guest_delivery_record(recovered),
	    delivery_phase::pending, true));
	s.guest_deliveries.push_back(recovered);
	dtt_entry_t status_reply{};
	status_reply.event_kind = DTT_HOST_STATUS;
	status_reply.u.installed.delivery_id = recovered.delivery_id;
	status_reply.u.installed.vmid = recovered.vmid;
	status_reply.u.installed.epoch = recovered.epoch;
	memcpy(status_reply.u.installed.program_id,
	    recovered.program_id.data(), 16);
	memcpy(status_reply.u.installed.source_id,
	    recovered.source_id.data(), 16);
	status_reply.u.installed.phase = 'i';
	status_reply.u.installed.query_id = 123;
	assert(handle_host_status(s, status_reply));
	assert(read(lifecycle[0], &exit_event, sizeof(exit_event)) ==
	    sizeof(exit_event) && exit_event.event_kind == DTT_UNINSTALLED &&
	    exit_event.u.installed.delivery_id == 20);
	assert(inbound.delivery_status(guest_delivery_record(recovered)) ==
	    (int)delivery_phase::exited &&
	    s.guest_deliveries[0].terminal_sent);
	status_reply.event_kind = DTT_HOST_UNINSTALLED;
	status_reply.u.installed.phase = 0;
	status_reply.u.installed.query_id = 0;
	assert(handle_host_observation(s, status_reply));
	assert(s.guest_deliveries.empty() &&
	    inbound.delivery_status(guest_delivery_record(recovered)) == 0);
	recovered.delivery_id = 21;
	assert(inbound.record_delivery(guest_delivery_record(recovered),
	    delivery_phase::pending, true));
	s.guest_deliveries.push_back(recovered);
	status_reply.event_kind = DTT_HOST_STATUS;
	status_reply.u.installed.delivery_id = 21;
	status_reply.u.installed.phase = 't';
	status_reply.u.installed.query_id = 124;
	assert(handle_host_status(s, status_reply));
	assert(s.guest_deliveries.empty() &&
	    inbound.delivery_status(guest_delivery_record(recovered)) == 0);
	status_reply.u.installed.phase = 0;
	status_reply.u.installed.revoked = 0;
	assert(handle_host_status(s, status_reply)); /* Retired query is stale. */
	int replay_file = openat(inbound.dirfd, sourced.c_str(),
	    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	assert(replay_file >= 0);
	assert(write(replay_file, "\177ELF", 4) == 4 &&
	    fsync(replay_file) == 0 && close(replay_file) == 0);
	struct dirent memorized{};
	strlcpy(memorized.d_name, sourced.c_str(), sizeof(memorized.d_name));
	assert(inbound.memorize_file(&memorized) && inbound.memorized(sourced));
	guest_delivery replay = recovered;
	replay.delivery_id = 22;
	assert(inbound.record_delivery(guest_delivery_record(replay),
	    delivery_phase::pending, true));
	s.guest_deliveries.push_back(replay);
	status_reply.u.installed.delivery_id = replay.delivery_id;
	status_reply.u.installed.phase = 'i';
	status_reply.u.installed.replay = 1;
	status_reply.u.installed.query_id = 125;
	assert(SHA256((const unsigned char *)"\177ELF", 4,
	    status_reply.u.installed.digest) != nullptr);
	status_reply.u.installed.digest[0] ^= 1;
	assert(!handle_host_status(s, status_reply) && errno == EPROTO &&
	    !s.guest_deliveries[0].authorized_current);
	status_reply.u.installed.digest[0] ^= 1;
	assert(handle_host_status(s, status_reply));
	assert(s.guest_deliveries.size() == 1 &&
	    s.guest_deliveries[0].authorized_current &&
	    !s.guest_deliveries[0].terminal_sent &&
	    !inbound.memorized(sourced) &&
	    inbound.delivery_status(guest_delivery_record(replay)) ==
	    (int)delivery_phase::pending);
	assert(s.identlist.empty() && process_inbound(inbound, &memorized) &&
	    s.pidlist.empty() && !inbound.memorized(sourced));
	assert(finish_guest_delivery(s, replay));
	assert(read(lifecycle[0], &exit_event, sizeof(exit_event)) ==
	    sizeof(exit_event) && exit_event.event_kind == DTT_UNINSTALLED &&
	    exit_event.u.installed.delivery_id == 22);
	status_reply.event_kind = DTT_HOST_UNINSTALLED;
	status_reply.u.installed.phase = 0;
	status_reply.u.installed.replay = 0;
	status_reply.u.installed.query_id = 0;
	memset(status_reply.u.installed.digest, 0,
	    sizeof(status_reply.u.installed.digest));
	assert(handle_host_observation(s, status_reply));
	assert(s.guest_deliveries.empty());
    guest_delivery replacement = delivery;
    replacement.delivery_id = 18;
    assert(inbound.record_delivery(guest_delivery_record(replacement),
        delivery_phase::pending, true));
    s.guest_deliveries.push_back(replacement);
    guest_delivery old_delivery = replacement;
    old_delivery.delivery_id = 17;
    retire_guest_delivery(s, old_delivery);
    assert(s.guest_deliveries.size() == 1 &&
        s.guest_deliveries[0].delivery_id == 18);
    retire_guest_delivery(s, replacement);
    assert(s.guest_deliveries.empty());
    s.guest_deliveries.push_back(replacement);
    assert(finish_guest_delivery(s, replacement));
    assert(read(lifecycle[0], &exit_event, sizeof(exit_event)) ==
        sizeof(exit_event) && exit_event.event_kind == DTT_UNINSTALLED &&
        exit_event.u.installed.delivery_id == 18 &&
        s.guest_deliveries.size() == 1);
    exit_event.event_kind = DTT_HOST_UNINSTALLED;
    assert(handle_host_observation(s, exit_event));
    assert(s.guest_deliveries.empty());
    std::array<uint8_t, 16> revoked{};
    revoked.fill(0x42);
    s.revoked_sources.insert(revoked);
    assert(!launch_program(s, sourced, false, argv[0]));
    assert(errno == ECANCELED && s.pidlist.empty());
    assert(!launch_program(s, "elf.11111111111111111111111111111111", false, argv[0]));
    assert(errno == EPROTO && s.pidlist.empty() && s.pid_sources.empty());
    assert(launch_program(s, "plain", false, argv[0]));
    bool reaped = false;
    for (int i = 0; i < 500 && !reaped; ++i) {
        { std::lock_guard children(s.pidlistmtx);
          reaped = s.pidlist.empty() && s.pidfds.empty(); }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    s.shutdown.store(1);
    reaper.join();
    close(lifecycle[0]); close(lifecycle[1]);
    assert(reaped);
    assert(!launch_program(s, "plain", false, "/nonexistent/hypertrace-child"));
    assert(errno == ENOENT && s.pidlist.empty());
    s.cleanup_in_progress.store(true);
    assert(!launch_program(s, "plain", false, argv[0]));
    assert(errno == ECANCELED && s.pidlist.empty());
    s.cleanup_in_progress.store(false);
    sigset_t current;
    assert(sigprocmask(SIG_SETMASK, nullptr, &current) == 0);
    assert(sigismember(&current, SIGINT) == 1 && sigismember(&current, SIGTERM) == 1);
    struct sigaction disposition;
    assert(sigaction(SIGTERM, nullptr, &disposition) == 0 && disposition.sa_handler == SIG_IGN);
    assert(sigaction(SIGTERM, &old, nullptr) == 0);
    assert(sigprocmask(SIG_SETMASK, &previous, nullptr) == 0);
	std::vector<durable_delivery_state> records;
	assert(inbound.list_deliveries(records) && records.empty());
	guest_delivery interrupted = replacement;
	interrupted.delivery_id = 19;
	auto stale = guest_delivery_record(interrupted);
	assert(inbound.record_delivery(stale, delivery_phase::pending, true));
	assert(inbound.record_delivery(stale, delivery_phase::terminal));
	{
		dir reopened(ledger_path, nullptr);
		assert(reopened.list_deliveries(records) && records.size() == 1 &&
		    records[0].phase == delivery_phase::terminal);
		assert(reopened.retire_terminal_delivery(records[0].record));
	}
	assert(inbound.delivery_status(stale) == 0);
	DIR *files = opendir(ledger_path);
	assert(files != nullptr);
	while (struct dirent *entry = readdir(files)) {
		if (strcmp(entry->d_name, ".") != 0 &&
		    strcmp(entry->d_name, "..") != 0)
			assert(unlinkat(inbound.dirfd, entry->d_name, 0) == 0);
	}
	assert(closedir(files) == 0 && rmdir(ledger_path) == 0);
    puts("PASS: actual pdfork/procdesc launch and reaping, fragmented handshake, selected-ID validation, sourced child ownership, malformed/rejected-child cleanup, host/guest arguments, launch failure and independent child signal state");
}
