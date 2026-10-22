/* SPDX-License-Identifier: BSD-2-Clause */
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <sys/hypertrace.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dtraced_directory.h"

using namespace dtraced;

static int gate_fd = -1, journal_fd = -1;
static bool suspended, fail_suspend, fail_intent_fsync, fail_directory_fsync;
static unsigned query_calls, suspend_calls, resume_calls;
static uint8_t owner[16];
static uint16_t live_vmid = 42;
static uint64_t live_epoch = 99;

extern "C" int __real_open(const char *, int, ...);
extern "C" int
__wrap_open(const char *path, int flags, ...)
{
	if (strcmp(path, "/dev/dtrace/hypertrace") == 0) {
		gate_fd = __real_open("/dev/null", flags);
		return (gate_fd);
	}
	va_list args;
	va_start(args, flags);
	mode_t mode = (flags & O_CREAT) ? (mode_t)va_arg(args, int) : 0;
	va_end(args);
	return (__real_open(path, flags, mode));
}

extern "C" int __real_ioctl(int, unsigned long, ...);
extern "C" int
__wrap_ioctl(int fd, unsigned long command, ...)
{
	va_list args;
	va_start(args, command);
	auto *gate = va_arg(args, hypertrace_epoch_gate *);
	va_end(args);
	if (fd != gate_fd)
		return (__real_ioctl(fd, command, gate));
	if (gate->vmid != live_vmid || gate->epoch != live_epoch) {
		errno = ESTALE;
		return (-1);
	}
	if (command == HYPERTRACE_IOC_EPOCH_GATE_QUERY) {
		query_calls++;
		gate->suspended = suspended ? 1 : 0;
		memcpy(gate->token, owner, sizeof(owner));
		return (0);
	}
	if (command == HYPERTRACE_IOC_EPOCH_SUSPEND) {
		suspend_calls++;
		if (fail_suspend) {
			fail_suspend = false;
			errno = EIO;
			return (-1);
		}
		if (suspended ||
		    memcmp(gate->previous_token, owner, sizeof(owner)) != 0 ||
		    memcmp(gate->token, owner, sizeof(owner)) == 0) {
			errno = EBUSY;
			return (-1);
		}
		memcpy(owner, gate->token, sizeof(owner));
		suspended = true;
		return (0);
	}
	if (command == HYPERTRACE_IOC_EPOCH_RESUME) {
		resume_calls++;
		if (!suspended || memcmp(gate->token, owner,
		    sizeof(owner)) != 0) {
			errno = ESTALE;
			return (-1);
		}
		suspended = false;
		return (0);
	}
	errno = ENOTTY;
	return (-1);
}

extern "C" int __real_fsync(int);
extern "C" int
__wrap_fsync(int fd)
{
	struct stat sb;
	if (fd == journal_fd && fail_directory_fsync) {
		fail_directory_fsync = false;
		errno = EIO;
		return (-1);
	}
	if (fail_intent_fsync && fstat(fd, &sb) == 0 &&
	    S_ISREG(sb.st_mode) && sb.st_size == 80) {
		fail_intent_fsync = false;
		errno = EIO;
		return (-1);
	}
	return (__real_fsync(fd));
}

#include <sys/event.h>
#include <sys/socket.h>
#include "dtraced_state.h"
#include "dtraced_connection.h"
namespace dtraced { struct state_attestation_test { static void set_control(state &s) { s.ctrlmachine = 1; } }; }

int main()
{
    char source_path[] = "/tmp/hypertrace-stop-source.XXXXXX";
    char ingress_path[] = "/tmp/hypertrace-stop-ingress.XXXXXX";
    assert(mkdtemp(source_path) && mkdtemp(ingress_path));
    state host{};
    state_attestation_test::set_control(host);
    dir outbound(source_path, nullptr), inbound(ingress_path, nullptr);
    host.outbounddir = &outbound; host.inbounddir = &inbound;
    inbound.state = outbound.state = &host;
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    int kq = kqueue(); assert(kq >= 0);
    dtd_initmsg_t hello{};
    hello.kind = DTRACED_KIND_CONSUMER;
    hello.subs = DTD_SUB_ELFWRITE;
    hello.session_id[0] = 0x76;
    snprintf(hello.ident, sizeof(hello.ident), "dtrace-%u-00000000000000000000000000000001", (unsigned)getpid());
    client_fd consumer(kq, sockets[0], hello);
    host.sockfds.insert(&consumer);
    consumer.consumer_program_valid = true;
    consumer.consumer_program_digest[0] = 0x51;
    assert(inbound.queue_recovered_consumer(&consumer) == 0);
    durable_session_stop stop{};
    stop.token[0] = 0xa1; stop.source_session[0] = 0xb2;
    stop.vmid = 42; stop.epoch = 99;
    std::vector<host_ingress_program_evidence> found;
    {
        dir alias(source_path, nullptr);
        assert(alias.fresh_session_consumers(outbound, stop, found) == -1 && errno == EINVAL);
    }
    assert(inbound.fresh_session_consumers(outbound, stop, found) == -1 && errno == EBUSY);
    auto add = [&](uint64_t id, uint64_t epoch, bool pinned) {
        durable_delivery ingress{};
        ingress.session_id[0] = 0x47;
        ingress.delivery_id = id; ingress.vmid = 42; ingress.epoch = epoch;
        ingress.program_id[0] = (uint8_t)id;
        ingress.source_id[0] = 0xbb;
        ingress.peer_uid = geteuid(); ingress.peer_pid = getpid();
        ingress.scope = 3; ingress.journal_version = 4;
        ingress.payload_digest[0] = 0xdd;
        assert(inbound.record_delivery(ingress, delivery_phase::pending, true));
        assert(inbound.record_delivery(ingress, delivery_phase::accepted));
        durable_consumer_receipt receipt{};
        receipt.ingress = ingress;
        receipt.consumer_session = consumer.session_id;
        receipt.consumer_uid = consumer.peer_uid;
        receipt.consumer_pid = consumer.peer_pid;
        assert(inbound.record_consumer_receipt(receipt, consumer_receipt_phase::pending) > 0);
        if (pinned) assert(inbound.record_consumer_program(receipt, consumer) == 1);
        return receipt;
    };
    auto first = add(1, 99, true);
    add(2, 99, true);
    add(3, 100, false); /* Another epoch does not require this stop's proof. */
    suspended = true;
    memcpy(owner, stop.token.data(), 16);
    assert(outbound.begin_fresh_session_stop(stop));
    assert(inbound.fresh_session_consumers(outbound, stop, found) == 1 && found.size() == 1);
    assert(found[0].recipient.consumer_session == consumer.session_id &&
        found[0].program_digest == consumer.consumer_program_digest);
    host.sockfds.erase(&consumer);
    consumer.retired = true;
    assert(inbound.fresh_session_consumers(outbound, stop, found) == 1 && found.size() == 1);
    auto wrong = stop; wrong.token[0]++;
    assert(inbound.fresh_session_consumers(outbound, wrong, found) == -1 && errno == ESTALE && found.size() == 1);
    auto missing = add(4, 99, false);
    assert(inbound.fresh_session_consumers(outbound, stop, found) == -1 && errno == EBUSY && found.size() == 1);
    assert(inbound.record_consumer_program(missing, consumer) == 1);
    assert(inbound.fresh_session_consumers(outbound, stop, found) == 1 && found.size() == 1);
    /* Crash after HCB1 but before HCR1 cannot yield a complete census. */
    auto interrupted = first;
    interrupted.ingress.delivery_id = 6;
    interrupted.ingress.program_id[0] = 6;
    assert(inbound.record_delivery(interrupted.ingress, delivery_phase::pending, true));
    assert(inbound.record_delivery(interrupted.ingress, delivery_phase::accepted));
    std::vector<durable_consumer_receipt> fixed;
    assert(inbound.consumer_cohort(interrupted.ingress, {interrupted}, fixed) == 1);
    assert(inbound.fresh_session_consumers(outbound, stop, found) == -1 &&
        errno == EBUSY && found.size() == 1);
    {
        dir restarted(ingress_path, nullptr);
        assert(restarted.fresh_session_consumers(outbound, stop, found) == -1 &&
            errno == EBUSY && found.size() == 1);
    }
    assert(inbound.record_consumer_receipt(interrupted, consumer_receipt_phase::pending) > 0);
    assert(inbound.fresh_session_consumers(outbound, stop, found) == -1 &&
        errno == EBUSY && found.size() == 1); // HCP1 is still absent.
    assert(inbound.record_consumer_program(interrupted, consumer) == 1);
    assert(inbound.fresh_session_consumers(outbound, stop, found) == 1 && found.size() == 1);
    int scanfd = openat(inbound.dirfd, ".", O_RDONLY | O_DIRECTORY);
    assert(scanfd >= 0);
    DIR *cohorts = fdopendir(scanfd); assert(cohorts);
    std::string cohort_name;
    for (dirent *entry; (entry = readdir(cohorts)) != nullptr;)
        if (strncmp(entry->d_name, ".cohort.", 8) == 0) {
            assert(cohort_name.empty());
            cohort_name = entry->d_name;
        }
    assert(closedir(cohorts) == 0 && !cohort_name.empty());
    int cohort_fd = openat(inbound.dirfd, cohort_name.c_str(), O_RDWR | O_NOFOLLOW);
    assert(cohort_fd >= 0);
    unsigned char magic;
    assert(pread(cohort_fd, &magic, 1, 0) == 1);
    unsigned char corrupt = magic ^ 1;
    assert(pwrite(cohort_fd, &corrupt, 1, 0) == 1 && fsync(cohort_fd) == 0);
    assert(inbound.fresh_session_consumers(outbound, stop, found) == -1 &&
        errno == EPROTO && found.size() == 1);
    assert(pwrite(cohort_fd, &magic, 1, 0) == 1 && fsync(cohort_fd) == 0);
    assert(close(cohort_fd) == 0);
    assert(inbound.fresh_session_consumers(outbound, stop, found) == 1 && found.size() == 1);
    {
        dir restarted(ingress_path, nullptr);
        assert(restarted.fresh_session_consumers(outbound, stop, found) == 1 &&
            found.size() == 1);
    }
    consumer.consumer_program_digest[0]++;
    add(5, 99, true);
    assert(inbound.fresh_session_consumers(outbound, stop, found) == -1 && errno == EPROTO && found.size() == 1);
    /* An empty epoch still needs its exact suspended admission fence before
     * a durable completion record, and must be retryable after reopening. */
    auto empty = stop; empty.epoch = 102; empty.token[0] ^= 0x40;
    assert(inbound.complete_fresh_session_stop(outbound, empty) == -1 && errno == EBUSY);
    live_epoch = empty.epoch;
    memcpy(owner, empty.token.data(), 16);
    assert(outbound.begin_fresh_session_stop(empty));
    assert(inbound.complete_fresh_session_stop(outbound, empty) == 1);
    {
        dir restarted(ingress_path, nullptr), source(source_path, nullptr);
        assert(restarted.complete_fresh_session_stop(source, empty) == 1);
        assert(source.fresh_session_stop_completed(empty) == 1);
        std::vector<std::string> plan{"unchanged"};
        assert(source.plan_fresh_session_ack_retirement(empty, plan) == 1 && plan.empty());
        int fd = openat(source.dirfd, ".fresh-done.002a.0000000000000066", O_RDWR);
        assert(fd >= 0);
        std::array<unsigned char, 160> saved{}, changed{};
        assert(pread(fd, saved.data(), saved.size(), 0) == (ssize_t)saved.size());
        changed = saved; changed[96] ^= 1;
        SHA256(changed.data(), 128, changed.data() + 128);
        assert(pwrite(fd, changed.data(), changed.size(), 0) == (ssize_t)changed.size());
        assert(source.fresh_session_stop_completed(empty) == -1 && errno == EPROTO);
        assert(pwrite(fd, saved.data(), saved.size(), 0) == (ssize_t)saved.size());
        assert(fsync(fd) == 0 && close(fd) == 0);
        assert(source.fresh_session_stop_completed(empty) == 1);
        durable_session_stop retained{};
        assert(source.fresh_session_stop_for_vm(empty.vmid, empty.epoch, retained) == 1 &&
            retained.token == empty.token);
    }
    for (dir *directory : {&inbound, &outbound}) {
        int fd = openat(directory->dirfd, ".", O_RDONLY | O_DIRECTORY);
        assert(fd >= 0);
        DIR *scan = fdopendir(fd); assert(scan);
        for (dirent *entry; (entry = readdir(scan)) != nullptr; )
            if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
                assert(unlinkat(directory->dirfd, entry->d_name, 0) == 0);
        assert(closedir(scan) == 0);
    }
    close(sockets[1]); close(kq);
    assert(rmdir(source_path) == 0 && rmdir(ingress_path) == 0);
    puts("PASS: durable collector census, duplicate owners, disconnected consumers and missing/conflicting proofs");
}
