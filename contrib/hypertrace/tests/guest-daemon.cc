/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <atomic>
#include <algorithm>
#include <array>
#include <cassert>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <map>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <vector>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <semaphore.h>
#include "dtraced.h"
#include "dtraced_io.h"
#include "dtraced_wire.h"
#include "dtraced_elf.h"
#include "dttransport.h"
#include <sys/hypertrace.h>
struct durable_delivery { uint64_t delivery_id; };
enum class delivery_phase : char {
    pending = 'p', accepted = 'a', installed = 'i', exited = 'x',
    terminal = 't'
};
struct directory {
    std::mutex dirmtx;
    std::string path;
    std::map<uint64_t, delivery_phase> journal;
    const std::string &full_path() const { return path; }
    bool record_delivery(const durable_delivery &record, delivery_phase phase,
        bool require_new = false) {
        if (require_new && journal.count(record.delivery_id) != 0) {
            errno = EEXIST;
            return false;
        }
        journal[record.delivery_id] = phase;
        return true;
    }
    bool retire_terminal_delivery(const durable_delivery &record) {
        auto found = journal.find(record.delivery_id);
        if (found == journal.end()) return true;
        if (found->second != delivery_phase::terminal) {
            errno = EBUSY;
            return false;
        }
        journal.erase(found);
        return true;
    }
    bool write_identified_data(const unsigned char *data, size_t length,
        const uint8_t id[16], bool *created = nullptr,
        const uint8_t *source_id = nullptr) {
        static const char hex[] = "0123456789abcdef";
        char name[70]; memcpy(name, "elf.", 4);
        for (size_t i = 0; i < 16; i++) {
            name[4 + 2 * i] = hex[id[i] >> 4];
            name[5 + 2 * i] = hex[id[i] & 15];
        }
        name[36] = 0;
	if (source_id) {
	    name[36] = '.';
	    for (size_t i = 0; i < 16; i++) {
	        name[37 + 2 * i] = hex[source_id[i] >> 4];
	        name[38 + 2 * i] = hex[source_id[i] & 15];
	    }
	    name[69] = 0;
	}
	if (created) *created = false;
        std::string full = path + name;
        int fd = open(full.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0 && errno == EEXIST) {
            fd = open(full.c_str(), O_RDONLY | O_NOFOLLOW);
            if (fd < 0) return false;
            std::vector<unsigned char> old(length + 1);
            ssize_t n = read(fd, old.data(), old.size());
            close(fd);
            return n == (ssize_t)length && memcmp(old.data(), data, length) == 0;
        }
        if (fd < 0) return false;
        bool ok = write(fd, data, length) == (ssize_t)length && fsync(fd) == 0;
        if (close(fd) != 0) ok = false;
        if (!ok) unlink(full.c_str());
	if (ok && created) *created = true;
        return ok;
    }
};
struct guest_delivery {
    uint64_t delivery_id;
    uint16_t vmid;
    uint64_t epoch;
    std::array<uint8_t, 16> program_id;
    std::array<uint8_t, 16> source_id;
    bool terminal_sent = false;
    bool authorized_current = true;
    std::array<uint8_t, 16> journal_session_id{};
    uint8_t journal_version = 3;
    std::array<uint8_t, 32> payload_digest{};
};
static durable_delivery guest_delivery_record(const guest_delivery &delivery) {
    return {delivery.delivery_id};
}
struct state {
    std::atomic_bool shutdown{false};
    std::atomic_bool cleanup_in_progress{false};
    int dtt_fd, socket;
    sem_t socksema;
    directory *inbounddir;
    std::mutex deliverymtx;
    std::vector<guest_delivery> guest_deliveries;
	std::mutex host_elf_mtx;
	std::condition_variable host_elf_cv;
	uint64_t host_elf_waiting = 0;
	std::array<uint8_t, 16> host_elf_program{};
	std::array<uint8_t, 16> host_elf_source{};
	std::array<uint8_t, 32> host_elf_digest{};
	bool host_elf_accepted = false;
};
static int terminal_count;
static guest_delivery last_terminal{};
static bool send_uninstall_observation(int, const guest_delivery &delivery) {
    last_terminal = delivery;
    ++terminal_count;
    return true;
}
static void broadcast_shutdown(state &s) { s.shutdown.store(true); }
static int setup_connection(state *s) { return s->socket; }
static void closefd_generic(int *fd) { if (*fd >= 0) close(*fd); }
#undef __cleanup
#define __cleanup(fn) __attribute__((cleanup(fn)))
#define ERR(...) ((void)0)
#define DTRACED_SLEEPTIME 10000
static bool fail_deadline_clock;
static std::atomic<int> fail_deadline_after{-1};
static int64_t test_deadline_clock(void) {
    int remaining = fail_deadline_after.load();
    if (fail_deadline_clock || remaining == 0) {
        errno = EIO; return -1;
    }
    if (remaining > 0) fail_deadline_after.store(remaining - 1);
    return dtraced_io_milliseconds();
}
#define dtraced_io_milliseconds test_deadline_clock
#include "guest-daemon.inc"
#undef dtraced_io_milliseconds
static void put(int fd, const void *p, size_t length) {
    size_t transferred;
    assert(dtraced_io_transfer(fd, const_cast<void *>(p), length, true,
        dtraced_io_milliseconds() + 3000, &transferred) == 0);
}
int main()
{
    alarm(20);
    {
        state s;
        assert(sem_init(&s.socksema, 0, 0) == 0);
        assert(dtt_wait_socket(&s, dtraced_io_milliseconds() + 20) == -1);
        assert(errno == ETIMEDOUT);
        fail_deadline_clock = true;
        assert(dtt_wait_socket(&s, dtraced_io_milliseconds() + 1000) == -1);
        assert(errno == EIO);
        fail_deadline_clock = false;
        assert(sem_post(&s.socksema) == 0);
        assert(dtt_wait_socket(&s, dtraced_io_milliseconds() + 1000) == 0);
        std::thread stop([&] { usleep(20000); s.shutdown.store(true); });
        int64_t start = dtraced_io_milliseconds();
        assert(dtt_wait_socket(&s, start + 10000) == -1 && errno == ECANCELED);
        assert(dtraced_io_milliseconds() - start < 1000);
        stop.join(); assert(sem_destroy(&s.socksema) == 0);
    }
    for (int test = 0; test < 6; test++) {
        int socket[2], pipefd[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, socket) == 0);
        assert(pipe(pipefd) == 0);
        state s; s.socket = socket[0]; s.dtt_fd = pipefd[1];
        std::thread writer([&] { write_dttransport(&s); });
        dtraced_hdr_t hdr{}; hdr.msg_type = DTRACED_MSG_ELF;
        hdr.elf.delivery_id = 0x12345678;
		hdr.elf.vmid = 42;
		hdr.elf.epoch = 99;
        hdr.elf.program_id[0] = 0x42;
	hdr.elf.source_id[0] = 0x55;
        hdr.elf.len = test == 2 ? SIZE_MAX : test == 3 ? 4 : 5000;
        unsigned char wire[DTRACED_MSGHDRSIZE];
        dtraced_wire_encode_header(wire, &hdr);
        for (size_t i = 0; i < sizeof(wire); i++)
            put(socket[1], wire + i, 1);
        std::vector<unsigned char> payload(5000, 'x');
        memcpy(payload.data(), "\177ELF", 4);
        std::thread host;
        size_t offset = 0;
        if (test == 0 || test >= 4) {
	    host = std::thread([&] {
	        dtt_entry_t entry;
	        while (offset < payload.size()) {
	            assert(read(pipefd[0], &entry, sizeof(entry)) == sizeof(entry));
	            assert(entry.event_kind == DTT_ELF &&
	                entry.u.elf.totallen == payload.size() &&
	                entry.u.elf.delivery_id == hdr.elf.delivery_id &&
	                entry.u.elf.vmid == 42 &&
	                entry.u.elf.epoch == 99 &&
	                entry.u.elf.program_id[0] == 0x42 &&
	                entry.u.elf.source_id[0] == 0x55);
	            assert(entry.u.elf.len > 0 &&
	                entry.u.elf.len <= sizeof(entry.u.elf.data));
	            assert(memcmp(entry.u.elf.data, payload.data() + offset,
	                entry.u.elf.len) == 0);
	            offset += entry.u.elf.len;
	            assert(entry.u.elf.hasmore == (offset < payload.size()));
	        }
	        dtt_entry_t receipt{};
	        receipt.event_kind = DTT_HOST_ELF;
	        receipt.u.installed.delivery_id = hdr.elf.delivery_id;
	        receipt.u.installed.vmid = 42;
	        receipt.u.installed.epoch = 99;
	        receipt.u.installed.program_id[0] = 0x42;
	        receipt.u.installed.source_id[0] = 0x55;
	        assert(SHA256(payload.data(), payload.size(),
	            receipt.u.installed.digest) != nullptr);
	        if (test == 0) assert(dtt_host_elf(&s, &receipt));
	    });
	}
	if (test == 0) {
            put(socket[1], payload.data(), 777);
            put(socket[1], payload.data() + 777, payload.size() - 777);
            dtraced_delivery_ack_t ack{}; size_t moved;
            assert(dtraced_io_transfer(socket[1], &ack, sizeof(ack), false,
                dtraced_io_milliseconds() + 3000, &moved) == 0 &&
                ack.delivery_id == hdr.elf.delivery_id);
        } else if (test >= 4) {
	    put(socket[1], payload.data(), payload.size());
	    host.join();
	    char unexpected;
	    assert(recv(socket[1], &unexpected, 1, MSG_DONTWAIT) == -1 &&
	        (errno == EAGAIN || errno == EWOULDBLOCK));
	    if (test == 5) s.cleanup_in_progress.store(true);
	    else s.shutdown.store(true);
	    s.host_elf_cv.notify_all();
	} else if (test == 1) put(socket[1], payload.data(), 2);
        else if (test == 3) put(socket[1], "bad!", 4);
        close(socket[1]); writer.join(); assert(s.shutdown.load() == (test != 5));
	if (host.joinable()) host.join();
        close(pipefd[1]);
	dtt_entry_t entry;
        for (;;) {
            ssize_t n = read(pipefd[0], &entry, sizeof(entry));
            if (n == 0) break;
            assert(n == sizeof(entry) && (test == 0 || test >= 4));
	    assert(entry.event_kind == DTT_ELF &&
	        entry.u.elf.totallen == payload.size() &&
	        entry.u.elf.delivery_id == hdr.elf.delivery_id);
	    assert(entry.u.elf.program_id[0] == 0x42);
	    assert(entry.u.elf.source_id[0] == 0x55);
            assert(entry.u.elf.len > 0 && entry.u.elf.len <= sizeof(entry.u.elf.data));
            assert(memcmp(entry.u.elf.data, payload.data() + offset, entry.u.elf.len) == 0);
            offset += entry.u.elf.len;
            assert(entry.u.elf.hasmore == (offset < payload.size()));
        }
        assert(offset == ((test == 0 || test >= 4) ? payload.size() : 0));
	close(pipefd[0]);
    }
	/* A full dttransport queue followed by clock failure must stop the
	 * writer instead of retrying EAGAIN forever. */
	{
	    int socket[2], pipefd[2];
	    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, socket) == 0);
	    assert(pipe(pipefd) == 0);
	    assert(fcntl(pipefd[1], F_SETFL, O_NONBLOCK) == 0);
	    char filler[4096]{};
	    while (write(pipefd[1], filler, sizeof(filler)) > 0) {}
	    assert(errno == EAGAIN || errno == EWOULDBLOCK);
	    state s; s.socket = socket[0]; s.dtt_fd = pipefd[1];
	    fail_deadline_after.store(1);
	    std::thread writer([&] { write_dttransport(&s); });
	    dtraced_hdr_t hdr{};
	    hdr.msg_type = DTRACED_MSG_ELF;
	    hdr.elf.delivery_id = 75;
	    hdr.elf.vmid = 42;
	    hdr.elf.epoch = 99;
	    hdr.elf.program_id[0] = 1;
	    hdr.elf.source_id[0] = 2;
	    hdr.elf.len = 4;
	    put(socket[1], &hdr, sizeof(hdr));
	    put(socket[1], "\177ELF", 4);
	    writer.join();
	    assert(s.shutdown.load() && fail_deadline_after.load() == 0);
	    fail_deadline_after.store(-1);
	    close(socket[1]); close(pipefd[0]); close(pipefd[1]);
	}
	{
	    state s;
	    s.host_elf_waiting = 17;
	    s.host_elf_program[0] = 0x42;
	    s.host_elf_source[0] = 0x55;
	    s.host_elf_digest[0] = 0x42;
	    dtt_entry_t receipt{};
	    receipt.event_kind = DTT_HOST_ELF;
	    receipt.u.installed.delivery_id = 18;
	    receipt.u.installed.vmid = 42;
	    receipt.u.installed.epoch = 99;
	    receipt.u.installed.program_id[0] = 0x42;
	    receipt.u.installed.source_id[0] = 0x55;
	    receipt.u.installed.digest[0] = 0x42;
	    assert(dtt_host_elf(&s, &receipt) && !s.host_elf_accepted);
	    receipt.u.installed.delivery_id = 17;
	    receipt.u.installed.source_id[0] = 0x56;
	    assert(!dtt_host_elf(&s, &receipt) && errno == EPROTO);
	    receipt.u.installed.source_id[0] = 0x55;
	    receipt.u.installed.query_id = 1;
	    assert(!dtt_host_elf(&s, &receipt) && errno == EPROTO);
	    receipt.u.installed.query_id = 0;
	    receipt.u.installed.digest[0] = 0x43;
	    assert(!dtt_host_elf(&s, &receipt) && errno == EPROTO);
	    receipt.u.installed.digest[0] = 0x42;
	    assert(dtt_host_elf(&s, &receipt) && s.host_elf_accepted);
	}
    char path[] = "/tmp/hypertrace-publish.XXXXXX";
    assert(mkdtemp(path)); directory dir; dir.path = std::string(path) + "/";
    state s; s.inbounddir = &dir;
    dtt_elf_state assembly;
    dtt_entry_t entry{}; entry.event_kind = DTT_ELF;
    entry.u.elf.identifier = 9; entry.u.elf.totallen = 8;
    entry.u.elf.delivery_id = 17;
    entry.u.elf.vmid = 42;
    entry.u.elf.epoch = 99;
    entry.u.elf.program_id[0] = 0x42;
	entry.u.elf.source_id[0] = 0x55;
    entry.u.elf.len = 4; entry.u.elf.hasmore = 1;
    memcpy(entry.u.elf.data, "\177ELF", 4);
	entry.u.elf.program_id[0] = 0;
	assert(!dtt_elf(&s, assembly, &entry));
	entry.u.elf.program_id[0] = 0x42;
	entry.u.elf.source_id[0] = 0;
	assert(!dtt_elf(&s, assembly, &entry));
	entry.u.elf.source_id[0] = 0x55;
	entry.u.elf.delivery_id = 0;
	assert(!dtt_elf(&s, assembly, &entry));
	entry.u.elf.delivery_id = 17;
	entry.u.elf.epoch = 0;
	assert(!dtt_elf(&s, assembly, &entry));
	entry.u.elf.epoch = 99;
    assert(dtt_elf(&s, assembly, &entry));
	entry.u.elf.program_id[0] = 0x43;
	assert(!dtt_elf(&s, assembly, &entry));
	entry.u.elf.program_id[0] = 0x42;
	entry.u.elf.delivery_id = 18;
	assert(!dtt_elf(&s, assembly, &entry));
	entry.u.elf.delivery_id = 17;
	entry.u.elf.epoch = 100;
	assert(!dtt_elf(&s, assembly, &entry));
	entry.u.elf.epoch = 99;
    DIR *dp = opendir(path); assert(dp); unsigned count = 0;
    while (auto *de = readdir(dp)) if (de->d_name[0] != '.') count++;
    closedir(dp); assert(count == 0); /* No partially published file. */
    entry.u.elf.hasmore = 0; memcpy(entry.u.elf.data, "DATA", 4);
    assert(dtt_elf(&s, assembly, &entry)); assert(assembly.elf.data == nullptr);
    assert(s.guest_deliveries.size() == 1 &&
        s.guest_deliveries[0].delivery_id == 17 &&
        s.guest_deliveries[0].vmid == 42 &&
        s.guest_deliveries[0].epoch == 99 &&
        s.guest_deliveries[0].journal_version == 4);
    uint8_t expected_elf_digest[32];
    assert(SHA256(reinterpret_cast<const uint8_t *>("\177ELFDATA"), 8,
        expected_elf_digest) != nullptr &&
        memcmp(s.guest_deliveries[0].payload_digest.data(),
        expected_elf_digest, 32) == 0);
    assert(dir.journal.at(17) == delivery_phase::pending);
	dtt_entry_t host_receipt{};
	host_receipt.event_kind = DTT_HOST_INSTALLED;
	host_receipt.u.installed.delivery_id = 17;
	host_receipt.u.installed.vmid = 42;
	host_receipt.u.installed.epoch = 99;
	host_receipt.u.installed.program_id[0] = 0x42;
	host_receipt.u.installed.source_id[0] = 0x55;
	host_receipt.u.installed.source_id[0] = 0;
	assert(!handle_host_observation(s, host_receipt) && errno == EPROTO);
	assert(s.guest_deliveries.size() == 1);
	host_receipt.u.installed.source_id[0] = 0x55;
	assert(handle_host_observation(s, host_receipt));
	assert(s.guest_deliveries.size() == 1);
	assert(dir.journal.at(17) == delivery_phase::installed);
	host_receipt.u.installed.epoch = 100;
	host_receipt.event_kind = DTT_HOST_UNINSTALLED;
	assert(handle_host_observation(s, host_receipt));
	assert(s.guest_deliveries.size() == 1);
	host_receipt.u.installed.epoch = 99;
	assert(!handle_host_observation(s, host_receipt) && errno == EPROTO);
	assert(dir.journal.at(17) == delivery_phase::installed);
	s.guest_deliveries[0].terminal_sent = true;
	assert(handle_host_observation(s, host_receipt));
	assert(s.guest_deliveries.empty());
	assert(dir.journal.count(17) == 0);
	/* An exact retry waits for host status; changed bytes fail closed. */
	guest_delivery recovered{23, 42, 99, {0x42}, {0x55}};
	recovered.authorized_current = false;
	s.guest_deliveries.push_back(recovered);
	dir.journal[23] = delivery_phase::pending;
	entry.u.elf.delivery_id = 24;
	entry.u.elf.hasmore = 0;
	entry.u.elf.len = 8;
	entry.u.elf.totallen = 8;
	memcpy(entry.u.elf.data, "\177ELFDATA", 8);
	assert(dtt_elf(&s, assembly, &entry));
	assert(terminal_count == 1 && last_terminal.delivery_id == 24);
	assert(s.guest_deliveries.size() == 1 &&
	    s.guest_deliveries[0].delivery_id == 23);
	assert(dir.journal.at(23) == delivery_phase::pending);
	terminal_count = 0;
	entry.u.elf.delivery_id = 23;
	entry.u.elf.len = 4;
	entry.u.elf.hasmore = 1;
	memcpy(entry.u.elf.data, "\177ELF", 4);
	assert(dtt_elf(&s, assembly, &entry));
	entry.u.elf.hasmore = 0;
	memcpy(entry.u.elf.data, "DIFF", 4);
	assert(!dtt_elf(&s, assembly, &entry));
	assert(terminal_count == 0 &&
	    dir.journal.at(23) == delivery_phase::pending &&
	    !s.guest_deliveries[0].terminal_sent);
	hypertrace_elf_reset(&assembly.elf);
	entry.u.elf.hasmore = 0;
	memcpy(entry.u.elf.data, "\177ELFDATA", 8);
	entry.u.elf.len = 8;
	entry.u.elf.totallen = 8;
	assert(dtt_elf(&s, assembly, &entry));
	assert(terminal_count == 0 &&
	    dir.journal.at(23) == delivery_phase::pending &&
	    s.guest_deliveries.size() == 1 &&
	    !s.guest_deliveries[0].terminal_sent &&
	    !s.guest_deliveries[0].authorized_current);
	/* A token already terminal at restart repeats its uninstall instead. */
	s.guest_deliveries[0].terminal_sent = true;
	dir.journal[23] = delivery_phase::exited;
	assert(dtt_elf(&s, assembly, &entry));
	assert(terminal_count == 1 && last_terminal.delivery_id == 23 &&
	    dir.journal.at(23) == delivery_phase::exited);
	host_receipt.u.installed.delivery_id = 23;
	assert(handle_host_observation(s, host_receipt));
	assert(s.guest_deliveries.empty() && dir.journal.count(23) == 0);
	terminal_count = 0;
	entry.u.elf.len = 4;
	/* The later fragment checks still exercise an active delivery. */
	s.guest_deliveries.push_back({17, 42, 99, {0x42}, {0x55}});
	entry.u.elf.delivery_id = 17;
	entry.u.elf.source_id[0] = 0x56;
	entry.u.elf.hasmore = 1; memcpy(entry.u.elf.data, "\177ELF", 4);
	assert(dtt_elf(&s, assembly, &entry));
	entry.u.elf.source_id[0] = 0x55;
	assert(!dtt_elf(&s, assembly, &entry));
	hypertrace_elf_reset(&assembly.elf);
	entry.u.elf.source_id[0] = 0x55;
	entry.u.elf.hasmore = 1; memcpy(entry.u.elf.data, "\177ELF", 4);
	assert(dtt_elf(&s, assembly, &entry));
	entry.u.elf.hasmore = 0; memcpy(entry.u.elf.data, "DATA", 4);
	assert(dtt_elf(&s, assembly, &entry)); /* Same program, same file. */
	assert(terminal_count == 0 && s.guest_deliveries.size() == 1);
	entry.u.elf.delivery_id = 18;
	entry.u.elf.hasmore = 1; memcpy(entry.u.elf.data, "\177ELF", 4);
	assert(dtt_elf(&s, assembly, &entry));
	entry.u.elf.hasmore = 0; memcpy(entry.u.elf.data, "DATA", 4);
	assert(dtt_elf(&s, assembly, &entry));
	assert(terminal_count == 1 && last_terminal.delivery_id == 18 &&
	    s.guest_deliveries.size() == 1 &&
	    s.guest_deliveries[0].delivery_id == 17);
	entry.u.elf.delivery_id = 17;
	entry.u.elf.hasmore = 1; memcpy(entry.u.elf.data, "\177ELF", 4);
	assert(dtt_elf(&s, assembly, &entry));
	entry.u.elf.hasmore = 0; memcpy(entry.u.elf.data, "DIFF", 4);
	assert(!dtt_elf(&s, assembly, &entry)); /* Identity collision. */
	hypertrace_elf_reset(&assembly.elf);
    dp = opendir(path); assert(dp);
    while (auto *de = readdir(dp)) {
        if (de->d_name[0] == '.') continue;
	assert(strstr(de->d_name,
	    ".55000000000000000000000000000000") != nullptr);
        count++; std::string file = dir.path + de->d_name;
        int fd = open(file.c_str(), O_RDONLY); assert(fd >= 0);
        char data[8]; assert(read(fd, data, 8) == 8);
        assert(memcmp(data, "\177ELFDATA", 8) == 0); close(fd); assert(unlink(file.c_str()) == 0);
    }
    closedir(dp); assert(count == 1);
    entry.u.elf.totallen = SIZE_MAX;
    assert(!dtt_elf(&s, assembly, &entry));
    assert(rmdir(path) == 0);
    puts("PASS: guest ELF framing, host receipt gate, recovered-token retry and identity checks");
}
