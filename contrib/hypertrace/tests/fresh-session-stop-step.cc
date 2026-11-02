/* SPDX-License-Identifier: BSD-2-Clause */
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <openssl/sha.h>
#include <sys/hypertrace.h>
#include <amd64/include/vmm_dev.h>
#include <sys/stat.h>
#include <sys/procdesc.h>
#include <unistd.h>
#include <chrono>
#include <future>
#include <thread>
#include <atomic>
#include "dtraced_wire.h"

#include "dtraced_directory.h"

using namespace dtraced;

static int gate_fd = -1, journal_fd = -1;
static bool suspended, fail_suspend, fail_intent_fsync, fail_directory_fsync;
static bool fail_ack_directory, fail_handle_fsync, retired_handle, fail_handle_query;
static bool fail_resume_after_apply;
static bool fail_completion_file, fail_completion_directory, fail_completion_parent;
static unsigned query_calls, suspend_calls, resume_calls;
static uint8_t owner[16];
static uint16_t live_vmid = 42;
static uint64_t live_epoch = 99;
static int process_fd = -1;
static bool missing_process, fail_process_fsync;
static bool fail_exit_fsync, fail_exit_directory, fail_exit_parent;
static unsigned process_opens;
static unsigned boot_mode;
extern "C" int __real_sysctlbyname(const char *, void *, size_t *, const void *, size_t);
extern "C" int __wrap_sysctlbyname(const char *name, void *out, size_t *size,
    const void *input, size_t input_size) {
    if (strcmp(name, "kern.boot_id") != 0)
        return __real_sysctlbyname(name, out, size, input, input_size);
    assert(out && size && *size == 16 && input == nullptr && input_size == 0);
    if (boot_mode == 2) { errno = ENXIO; return -1; }
    memset(out, boot_mode == 3 ? 0 : boot_mode == 1 ? 0x52 : 0x51, 16);
    *size = boot_mode == 4 ? 15 : 16;
    return 0;
}
static bool wrong_birth;
static bool query_process_exit, process_exited;
static bool fail_reaper_query, fail_reaper_fsync;
static bool fail_legacy_unlink, fail_legacy_directory, fail_legacy_parent;
static unsigned reaper_flags, reaper_queries;
static unsigned process_polls;
static int polled_process_fd = -1;
extern "C" int __real_poll(struct pollfd *, nfds_t, int);
extern "C" int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout) {
    if (!query_process_exit) return __real_poll(fds, count, timeout);
    assert(count == 1 && timeout == 0 && fds[0].events == POLLIN);
    assert(fds[0].fd != process_fd && fcntl(fds[0].fd, F_GETFD) >= 0);
    process_polls++; polled_process_fd = fds[0].fd;
    fds[0].revents = process_exited ? POLLHUP : 0;
    return process_exited ? 1 : 0;
}

extern "C" int __wrap_pdopenpid(pid_t pid, int flags) {
    assert(pid == getpid() && flags == (PD_DAEMON | PD_CLOEXEC));
    process_opens++;
    if (missing_process) { errno = ESRCH; return -1; }
    process_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    return process_fd;
}
static int attestation_fd = -1;
static bool attestation_live = true;

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
	if (command == PDIOC_GET_REAPER_EXIT) {
		assert(fd != process_fd && fcntl(fd, F_GETFD) >= 0);
		reaper_queries++;
		if (fail_reaper_query) { errno = ENOTTY; return (-1); }
		auto *snapshot = reinterpret_cast<pd_reaper_exit *>(gate);
		*snapshot = {reaper_flags, 0};
		return (0);
	}
	if (fd == process_fd && command == PDIOC_GET_BIRTH_IDENTITY) {
		auto *birth = reinterpret_cast<pd_birth_identity *>(gate);
		*birth = {getpid(), 0, wrong_birth ? 101U : 100U, 200};
		return (0);
	}
	if (fd == attestation_fd && command == VM_GET_ATTESTATION) {
		auto *identity = reinterpret_cast<hypertrace_vm_attestation *>(gate);
		memset(identity, 0, sizeof(*identity));
		identity->vmid = live_vmid;
		identity->epoch = attestation_live ? live_epoch : live_epoch + 1;
		strlcpy(identity->name, "stop-source", sizeof(identity->name));
		return (0);
	}
	if (fd != gate_fd)
		return (__real_ioctl(fd, command, gate));
	if (command == HYPERTRACE_IOC_HANDLE_QUERY) {
		auto *query = reinterpret_cast<dtrace_handle_lifetime_t *>(gate);
		assert(query->generation[0] == 1 && query->generation[1] == 2 && query->serial == 3);
		if (fail_handle_query) { errno = ENOTTY; return (-1); }
		query->retired = retired_handle ? 1 : 0;
		return (0);
	}
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
		if (fail_resume_after_apply) {
			fail_resume_after_apply = false;
			errno = EIO;
			return (-1);
		}
		return (0);
	}
	errno = ENOTTY;
	return (-1);
}

static bool fail_ack_unlink, fail_ack_retire_sync, ack_retire_parent;
extern "C" int __real_unlinkat(int, const char *, int);
extern "C" int __wrap_unlinkat(int directory, const char *name, int flags) {
    if (strncmp(name, ".fresh-ack.", 11) == 0) {
        if (fail_ack_unlink) { fail_ack_unlink=false; errno=EIO; return -1; }
        int result=__real_unlinkat(directory,name,flags);
        if (result == 0 && fail_ack_retire_sync) {
            fail_ack_retire_sync=false; ack_retire_parent=true;
        }
        return result;
    }
    if (strncmp(name, ".process-exit.", 14) == 0) {
        assert(flags == 0);
        if (fail_legacy_unlink) {
            fail_legacy_unlink=false;errno=EIO;return -1;
        }
        int result=__real_unlinkat(directory,name,flags);
        if (result==0 && fail_legacy_directory) {
            fail_legacy_directory=false;fail_legacy_parent=true;
        }
        return result;
    }
    return __real_unlinkat(directory,name,flags);
}

extern "C" int __real_fsync(int);
extern "C" int
__wrap_fsync(int fd)
{
	struct stat sb;
	if (fstat(fd, &sb) == 0) {
		if (S_ISDIR(sb.st_mode) && ack_retire_parent) {
			ack_retire_parent=false; errno=EIO; return -1;
		}
		if (S_ISDIR(sb.st_mode) && fail_completion_parent) {
			fail_completion_parent = false; errno = EIO; return (-1);
		}
		if (S_ISREG(sb.st_mode) && sb.st_size == 160 &&
		    (fail_completion_file || fail_completion_directory)) {
			if (fail_completion_file) {
				fail_completion_file = false; errno = EIO; return (-1);
			}
			fail_completion_directory = false;
			fail_completion_parent = true;
		}
		if (S_ISDIR(sb.st_mode) && fail_legacy_parent) {
			fail_legacy_parent=false;errno=EIO;return (-1);
		}
		char magic[4];
		if (fail_reaper_fsync && S_ISREG(sb.st_mode) && sb.st_size == 192) {
			fail_reaper_fsync = false; errno = EIO; return (-1);
		}

		/* Publication uses a write-only temporary; prior HPB1 reads use
		 * read-only descriptors. Arm only during the exit-checkpoint test. */
		if ((fail_exit_fsync || fail_exit_directory) &&
		    S_ISREG(sb.st_mode) && sb.st_size == 184 &&
		    ((fcntl(fd, F_GETFL) & O_ACCMODE) == O_WRONLY ||
		    (pread(fd, magic, sizeof(magic), 0) == sizeof(magic) &&
		    memcmp(magic, "HPE1", 4) == 0))) {
			if (fail_exit_fsync) {
				fail_exit_fsync = false; errno = EIO; return (-1);
			}
			if (fail_exit_directory) {
				fail_exit_directory = false; fail_exit_parent = true;
			}
		}
		if (S_ISDIR(sb.st_mode) && fail_exit_parent) {
			fail_exit_parent = false; errno = EIO; return (-1);
		}
	}
	if (fail_process_fsync && fstat(fd, &sb) == 0 &&
	    S_ISREG(sb.st_mode) && sb.st_size == 378) {
		fail_process_fsync = false; errno = EIO; return (-1);
	}
	if (fail_handle_fsync && fstat(fd, &sb) == 0 &&
	    S_ISREG(sb.st_mode) && sb.st_size == 362) {
		fail_handle_fsync = false; errno = EIO; return (-1);
	}
	if (fd == journal_fd && fail_directory_fsync) {
		fail_directory_fsync = false;
		errno = EIO;
		return (-1);
	}
	if (fail_intent_fsync && fstat(fd, &sb) == 0 &&
	    S_ISREG(sb.st_mode) && (sb.st_size == 80 || sb.st_size == 224)) {
		fail_intent_fsync = false;
		errno = EIO;
		return (-1);
	}
	if (fail_ack_directory && fstat(fd, &sb) == 0 &&
	    S_ISREG(sb.st_mode) && sb.st_size == 224) {
		fail_ack_directory = false;
		fail_directory_fsync = true;
	}
	return (__real_fsync(fd));
}

#include <sys/event.h>
#include <sys/socket.h>
#include "dtraced_state.h"
#include "dtraced_connection.h"
#include "dtraced_clientrequest.h"
namespace dtraced { struct state_attestation_test { static void set_control(state &s) { s.ctrlmachine = 1; } }; }

int main()
{
    char source_path[] = "/tmp/hypertrace-stop-source.XXXXXX";
    char ingress_path[] = "/tmp/hypertrace-stop-ingress.XXXXXX";
    assert(mkdtemp(source_path) && mkdtemp(ingress_path));
    std::array<uint8_t, 192> saved_reaper{};
    std::string saved_reaper_name;
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
    snprintf(hello.ident, sizeof(hello.ident), "dtrace-%u-6400000000000000c800000000000000", (unsigned)getpid());
    client_fd consumer(kq, sockets[0], hello);
    host.sockfds.insert(&consumer);
    consumer.consumer_program_valid = true;
    consumer.consumer_program_digest[0] = 0x51;
    /* HPI2 is immutable for this authenticated connection, including retries. */
    {
        consumer.consumer_program_valid = false;
        assert(inbound.queue_recovered_consumer(&consumer) == 0);
        assert(consumer.consumer_replay_registration_pending.load());
        assert(host.joblist.empty());
        unsigned char registration[64]{};
        memcpy(registration, "HPI2", 4);
        memcpy(registration + 8, consumer.consumer_program_digest.data(), 32);
        dtraced_wire_put_u64(registration + 40, 1);
        dtraced_wire_put_u64(registration + 48, 2);
        dtraced_wire_put_u64(registration + 56, 3);
        dtraced_hdr_t header{};
        header.msg_type = DTRACED_MSG_CONSUMER_PROGRAM; header.elf.len = 64;
        auto register_program = [&](bool expected) {
            client_request request(host, header, registration, header.elf.len, &consumer);
            assert(request.handle() == expected);
        };
        wrong_birth = true; register_program(false);
        assert(!consumer.consumer_program_valid && consumer.consumer_process_fd == -1);
        wrong_birth = false;
        register_program(true); register_program(true);
        assert(consumer.consumer_process_fd >= 0);
        assert(!consumer.consumer_replay_registration_pending.load());
        assert(consumer.consumer_import_scan_done);
        registration[40] ^= 1; register_program(false); registration[40] ^= 1;
        header.elf.len = 32;
        memcpy(registration, consumer.consumer_program_digest.data(), 32);
        register_program(false); /* No downgrade to unbound registration. */
        assert(consumer.consumer_handle_lifetime[0] == 1);
    }
    assert(inbound.queue_recovered_consumer(&consumer) == 0);
    durable_session_stop stop{};
    stop.token[0] = 0xa1; stop.source_session[0] = 0xb2;
    stop.vmid = 42; stop.epoch = 99;
    std::vector<host_ingress_program_evidence> found;
    std::string first_process_binding;
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
        if (pinned) {
            if (id == 1) {
                fail_handle_fsync = true;
                assert(inbound.record_consumer_program(receipt, consumer) == -1 && errno == EIO);
                std::array<uint8_t, 76> saved_owner{};
                std::array<uint8_t, 32> saved_program{};
                assert(inbound.consumer_program_status(receipt, saved_owner, saved_program) == 0);
                fail_process_fsync = true;
                assert(inbound.record_consumer_program(receipt, consumer) == -1 && errno == EIO);
                assert(inbound.consumer_program_status(receipt, saved_owner, saved_program) == 0);
            }
            assert(inbound.record_consumer_program(receipt, consumer) == 1);
            std::array<uint8_t, 24> recovered_handle{};
            assert(inbound.consumer_handle_status(receipt, recovered_handle) == 1);
            assert(recovered_handle == consumer.consumer_handle_lifetime);
            {
                dir recovered(ingress_path, nullptr);
                recovered_handle = {};
                assert(recovered.consumer_handle_status(receipt, recovered_handle) == 1);
                assert(recovered_handle == consumer.consumer_handle_lifetime);
            }
            if (id == 1) {
                int scanfd = openat(inbound.dirfd, ".", O_RDONLY | O_DIRECTORY);
                assert(scanfd >= 0);
                DIR *scan = fdopendir(scanfd); assert(scan);
                std::string handle_name, process_name;
                for (dirent *entry; (entry = readdir(scan)) != nullptr; ) {
                    if (strncmp(entry->d_name, ".handle.", 8) == 0)
                        handle_name = entry->d_name;
                    if (strncmp(entry->d_name, ".process.", 9) == 0)
                        process_name = entry->d_name;
                }
                assert(closedir(scan) == 0 && !handle_name.empty());
                assert(!process_name.empty());
                first_process_binding = process_name;
                collector_owner_registry absent;
                unsigned opens_before = process_opens;
                assert(renameat(inbound.dirfd, process_name.c_str(), inbound.dirfd, ".saved-process") == 0);
                assert(inbound.recover_consumer_process(receipt, absent) == -1 && errno == EAGAIN);
                assert(process_opens == opens_before);
                assert(renameat(inbound.dirfd, ".saved-process", inbound.dirfd, process_name.c_str()) == 0);
                int process_file = openat(inbound.dirfd, process_name.c_str(), O_RDWR);
                assert(process_file >= 0);
                uint8_t saved; assert(pread(process_file, &saved, 1, 330) == 1);
                uint8_t changed = saved ^ 1;
                assert(pwrite(process_file, &changed, 1, 330) == 1);
                assert(inbound.recover_consumer_process(receipt, absent) == -1 && errno == EPROTO);
                assert(process_opens == opens_before);
                assert(pwrite(process_file, &saved, 1, 330) == 1 && fsync(process_file) == 0);
                assert(close(process_file) == 0);
                int fd = openat(inbound.dirfd, handle_name.c_str(), O_RDWR);
                assert(fd >= 0);
                uint8_t byte; assert(pread(fd, &byte, 1, 306) == 1);
                uint8_t corrupt = byte ^ 1;
                assert(pwrite(fd, &corrupt, 1, 306) == 1);
                recovered_handle.fill(0xaa);
                auto unchanged = recovered_handle;
                assert(inbound.consumer_handle_status(receipt, recovered_handle) == -1 && errno == EPROTO);
                assert(recovered_handle == unchanged);
                unsigned before_corrupt = process_polls;
                assert(inbound.consumer_process_exited(receipt, host.collector_owners) == -1 && errno == EPROTO);
                assert(process_polls == before_corrupt);
                assert(pwrite(fd, &byte, 1, 306) == 1 && fsync(fd) == 0);
                assert(close(fd) == 0);
            }
            if (id == 1) {
                assert(close(consumer.consumer_process_fd) == 0);
                consumer.consumer_process_fd = -1;
            }
            query_process_exit = true;
            collector_owner_registry missing_owners;
            unsigned before = process_polls;
            assert(inbound.consumer_process_exited(receipt, missing_owners) == -1 && errno == EAGAIN);
            assert(process_polls == before);
            assert(inbound.consumer_process_exited(receipt, host.collector_owners) == 0);
            process_exited = true;
            assert(inbound.consumer_process_exited(receipt, host.collector_owners) == 1);
            {
                dir recovered(ingress_path, nullptr);
                assert(recovered.consumer_process_exited(receipt, host.collector_owners) == 1);
                assert(recovered.consumer_process_exited(receipt, missing_owners) == -1 && errno == EAGAIN);
            }
            process_exited = query_process_exit = false;
            if (id == 2) {
                /* Restart has journals but no process descriptors. Only a new
                 * authenticated HPI2 registration can rebuild the exact pin. */
                state restarted{};
                state_attestation_test::set_control(restarted);
                dir recovered(ingress_path, nullptr);
                restarted.inbounddir = &recovered;
                recovered.state = &restarted;
                int pair[2];
                assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
                client_fd reconnected(kq, pair[0], hello);
                reconnected.consumer_replay_pending = true;
                restarted.sockfds.insert(&reconnected);
                assert(recovered.queue_recovered_consumer(&reconnected) == 0);
                assert(reconnected.consumer_replay_registration_pending.load());
                assert(restarted.joblist.empty());
                reconnected.consumer_replay_pending = false;
                query_process_exit = true;
                unsigned before = process_polls;
                assert(recovered.consumer_process_exited(receipt, restarted.collector_owners) == -1 && errno == EAGAIN);
                assert(process_polls == before);
                unsigned char registration[64]{};
                memcpy(registration, "HPI2", 4);
                memcpy(registration + 8, consumer.consumer_program_digest.data(), 32);
                memcpy(registration + 40, consumer.consumer_handle_lifetime.data(), 24);
                dtraced_hdr_t header{};
                header.msg_type = DTRACED_MSG_CONSUMER_PROGRAM;
                header.elf.len = sizeof(registration);
                auto register_again = [&](bool expected) {
                    client_request request(restarted, header, registration,
                        sizeof(registration), &reconnected);
                    assert(request.handle() == expected);
                };
                missing_process = true;
                register_again(false);
                assert(!reconnected.consumer_program_valid && reconnected.consumer_process_fd == -1);
                assert(recovered.consumer_process_exited(receipt, restarted.collector_owners) == -1 && errno == EAGAIN);
                assert(process_polls == before);
                missing_process = false;
                wrong_birth = true;
                register_again(false);
                assert(!reconnected.consumer_program_valid && reconnected.consumer_process_fd == -1);
                assert(recovered.consumer_process_exited(receipt, restarted.collector_owners) == -1 && errno == EAGAIN);
                assert(process_polls == before);
                assert(reconnected.consumer_replay_registration_pending.load());
                assert(restarted.joblist.empty());
                wrong_birth = false;
                register_again(true);
                assert(!reconnected.consumer_replay_registration_pending.load());
                assert(reconnected.consumer_import_scan_done);
                size_t queued = restarted.joblist.size();
                register_again(true);
                assert(restarted.joblist.size() == queued);
                assert(reconnected.consumer_program_valid);
                assert(recovered.record_consumer_program(receipt, reconnected) == 1);
                assert(close(reconnected.consumer_process_fd) == 0);
                reconnected.consumer_process_fd = -1;
                assert(recovered.consumer_process_exited(receipt, restarted.collector_owners) == 0);
                process_exited = true;
                assert(recovered.consumer_process_exited(receipt, restarted.collector_owners) == 1);
                process_exited = query_process_exit = false;
                restarted.sockfds.erase(&reconnected);
                assert(close(pair[1]) == 0);
            }
            {
                collector_owner_registry restored;
                unsigned before = process_opens;
                for (boot_mode = 1; boot_mode <= 4; boot_mode++) {
                    assert(inbound.recover_consumer_process(receipt, restored) == -1);
                    assert(errno == (boot_mode == 1 ? ESTALE : boot_mode == 2 ? ENXIO : EPROTO));
                    assert(process_opens == before);
                }
                boot_mode = 0;
                /* Reboot retirement: the verified HPB1 of an earlier boot is
                 * proof; the same boot is not, and evidence errors fail. */
                assert(inbound.consumer_prior_boot_retired(receipt) == 0);
                for (boot_mode = 1; boot_mode <= 4; boot_mode++) {
                    int prior = inbound.consumer_prior_boot_retired(receipt);
                    if (boot_mode == 1)
                        assert(prior == 1);
                    else
                        assert(prior == -1 && errno == (boot_mode == 2 ? ENXIO : EPROTO));
                }
                boot_mode = 1;
                assert(process_opens == before);
                {
                    /* Locate this receipt's HPB1 by checksummed identity
                     * mutation, then check identity, checksum and zero-boot
                     * refusals. Every case restores the original bytes. */
                    int scanfd = openat(inbound.dirfd, ".", O_RDONLY | O_DIRECTORY);
                    assert(scanfd >= 0);
                    DIR *scan = fdopendir(scanfd); assert(scan);
                    std::vector<std::string> names;
                    for (dirent *entry; (entry = readdir(scan)) != nullptr; )
                        if (strncmp(entry->d_name, ".process.", 9) == 0)
                            names.emplace_back(entry->d_name);
                    assert(closedir(scan) == 0 && !names.empty());
                    unsigned matched = 0;
                    for (const auto &name : names) {
                        int fd = openat(inbound.dirfd, name.c_str(), O_RDWR);
                        assert(fd >= 0);
                        uint8_t original[378], changed[378];
                        assert(pread(fd, original, sizeof(original), 0) == 378);
                        auto put = [&](const uint8_t *bytes) {
                            assert(pwrite(fd, bytes, 378, 0) == 378 && fsync(fd) == 0);
                        };
                        memcpy(changed, original, sizeof(changed));
                        changed[10] ^= 1;
                        SHA256(changed, 346, changed + 346);
                        put(changed);
                        int result = inbound.consumer_prior_boot_retired(receipt);
                        put(original);
                        if (result != -1 || errno != ESTALE) {
                            assert(result == 1);
                            assert(close(fd) == 0);
                            continue;
                        }
                        matched++;
                        memcpy(changed, original, sizeof(changed));
                        changed[340] ^= 1; /* checksum no longer matches */
                        put(changed);
                        assert(inbound.consumer_prior_boot_retired(receipt) == -1 && errno == EPROTO);
                        memset(changed + 330, 0, 16);
                        SHA256(changed, 346, changed + 346);
                        put(changed);
                        assert(inbound.consumer_prior_boot_retired(receipt) == -1 && errno == EPROTO);
                        put(original);
                        assert(fchmod(fd, 0644) == 0);
                        assert(inbound.consumer_prior_boot_retired(receipt) == -1 && errno == EPROTO);
                        assert(fchmod(fd, 0600) == 0);
                        assert(close(fd) == 0);
                        assert(inbound.consumer_prior_boot_retired(receipt) == 1);
                        break;
                    }
                    assert(matched == 1);
                }
                boot_mode = 0;
                missing_process = true;
                assert(inbound.recover_consumer_process(receipt, restored) == -1 && errno == ESRCH);
                missing_process = false;
                wrong_birth = true;
                assert(inbound.recover_consumer_process(receipt, restored) == -1 && errno == ESTALE);
                wrong_birth = false;
                assert(inbound.recover_consumer_process(receipt, restored) == 1);
                before = process_opens;
                assert(inbound.recover_consumer_process(receipt, restored) == 1);
                assert(process_opens == before);
                query_process_exit = true;
                assert(inbound.consumer_process_exited(receipt, restored) == 0);
                query_process_exit = false;
            }
            assert(inbound.consumer_kernel_handle_retired(receipt) == 0);
            retired_handle = true;
            assert(inbound.consumer_kernel_handle_retired(receipt) == 1);
            fail_handle_query = true;
            assert(inbound.consumer_kernel_handle_retired(receipt) == -1 && errno == ENOTTY);
            fail_handle_query = retired_handle = false;
            auto original_handle = consumer.consumer_handle_lifetime;
            consumer.consumer_handle_lifetime[0] ^= 1;
            assert(inbound.record_consumer_program(receipt, consumer) == -1 && errno == ESTALE);
            consumer.consumer_handle_lifetime = {};
            assert(inbound.record_consumer_program(receipt, consumer) == -1 && errno == ESTALE);
            consumer.consumer_handle_lifetime = original_handle;
            assert(inbound.record_consumer_program(receipt, consumer) == 1);
        }
        return receipt;
    };
    auto first_receipt = add(1, 99, true);
    auto second_receipt = add(2, 99, true);
    {
        std::vector<durable_consumer_receipt_state> inventory;
        assert(inbound.list_consumer_receipts(inventory));
        state restarted{};state_attestation_test::set_control(restarted);
        dir reopened(ingress_path,nullptr);reopened.state=&restarted;
        restarted.inbounddir=&reopened;
        query_process_exit=true;process_exited=false;
        unsigned before=process_opens;
        assert(restarted.recover_collector_owners(inventory));
        assert(process_opens==before+1); // Two receipts share one exact pin.
        auto key=collector_owner_identity(consumer.session_id,consumer.consumer_birth,
            consumer.peer_uid,consumer.peer_pid,consumer.consumer_program_digest,
            consumer.consumer_handle_lifetime);
        assert(restarted.collector_owners.retained(key));
        assert(restarted.recover_collector_owners(inventory));
        assert(process_opens==before+1);
        state missing{};state_attestation_test::set_control(missing);
        dir missing_in(ingress_path,nullptr);missing_in.state=&missing;
        missing.inbounddir=&missing_in;missing_process=true;
        assert(missing.recover_collector_owners(inventory));
        assert(!missing.collector_owners.retained(key));
        missing_process=false;query_process_exit=false;
    }

    {
        auto key = collector_owner_identity(consumer.session_id,
            consumer.consumer_birth, consumer.peer_uid, consumer.peer_pid,
            consumer.consumer_program_digest, consumer.consumer_handle_lifetime);
        collector_owner_registry restarted_empty;
        query_process_exit = true;
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, restarted_empty) == -1 && errno == EAGAIN);
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, host.collector_owners) == 0);
        assert(inbound.consumer_reaper_exit_status(first_receipt) == 0);
        process_exited = true;
        fail_reaper_query = true;
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, host.collector_owners) == -1 && errno == ENOTTY);
        assert(host.collector_owners.retained(key));
        fail_reaper_query = false;
        reaper_flags = PD_REAPER_EXITED | PD_REAPER_OWNED | PD_REAPER_EMPTY;
        fail_reaper_fsync = true;
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, host.collector_owners) == -1 && errno == EIO);
        assert(!fail_reaper_fsync && host.collector_owners.retained(key));
        assert(inbound.consumer_reaper_exit_status(first_receipt) == 0);
        fail_exit_fsync = true;
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, host.collector_owners) == -1 && errno == EIO);
        assert(!fail_exit_fsync && host.collector_owners.retained(key));
        assert(inbound.consumer_reaper_exit_status(first_receipt) == 1);
        assert(inbound.consumer_reaper_exit_status(second_receipt) == 1);

        /* Lost daemon after HRE1 sync but before HPE1: the exact durable
         * exit snapshot recovers process evidence without any retained pin. */
        unsigned snapshot_polls = process_polls, snapshot_opens = process_opens;
        assert(inbound.checkpoint_consumer_process_exit(second_receipt, restarted_empty) == 1);
        assert(process_polls == snapshot_polls && process_opens == snapshot_opens);
        fail_exit_directory = true;
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, host.collector_owners) == -1 && errno == EIO);
        assert(!fail_exit_directory && !fail_exit_parent && host.collector_owners.retained(key));
        unsigned polls_before = process_polls, opens_before = process_opens;
        /* Recover a different receipt after losing the first checkpoint reply.
         * The old per-receipt format could not establish this fact. */
        assert(inbound.checkpoint_consumer_process_exit(second_receipt, restarted_empty) == 1);
        assert(process_polls == polls_before && process_opens == opens_before);
        int retained_fd = polled_process_fd;
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, host.collector_owners) == 1);
        assert(!host.collector_owners.retained(key));
        assert(fcntl(retained_fd, F_GETFD) == -1 && errno == EBADF);
        {
            dir reopened(ingress_path, nullptr);
            assert(reopened.checkpoint_consumer_process_exit(second_receipt, restarted_empty) == 1);
            assert(process_polls == polls_before && process_opens == opens_before);
            unsigned queries_before = reaper_queries;
            assert(reopened.consumer_reaper_exit_status(second_receipt) == 1);
            assert(reaper_queries == queries_before);
            boot_mode = 1;
            assert(reopened.consumer_reaper_exit_status(second_receipt) == -1 && errno == ESTALE);
            assert(reopened.checkpoint_consumer_process_exit(second_receipt, restarted_empty) == -1 && errno == ESTALE);
            boot_mode = 0;
        }
        int scanfd = openat(inbound.dirfd, ".", O_RDONLY | O_DIRECTORY);
        assert(scanfd >= 0);
        DIR *scan = fdopendir(scanfd); assert(scan);
        std::string exit_name, reaper_name;
        for (dirent *entry; (entry = readdir(scan)) != nullptr; ) {
            if (strncmp(entry->d_name, ".process-retired.", 17) == 0)
                exit_name = entry->d_name;
            if (strncmp(entry->d_name, ".reaper-empty.", 13) == 0)
                reaper_name = entry->d_name;
        }
        assert(closedir(scan) == 0 && !exit_name.empty());
        assert(!reaper_name.empty());
        int reaper_fd = openat(inbound.dirfd, reaper_name.c_str(), O_RDWR);
        assert(reaper_fd >= 0);
        uint8_t damaged = 1;
        assert(pwrite(reaper_fd, &damaged, 1, 152) == 1);
        assert(inbound.consumer_reaper_exit_status(first_receipt) == -1 && errno == EPROTO);
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, restarted_empty) == -1 && errno == EPROTO);
        damaged = 0;
        assert(pwrite(reaper_fd, &damaged, 1, 152) == 1);
        assert(fsync(reaper_fd) == 0 && close(reaper_fd) == 0);
        assert(inbound.consumer_reaper_exit_status(first_receipt) == 1);
        saved_reaper_name = reaper_name;
        reaper_fd = openat(inbound.dirfd, reaper_name.c_str(), O_RDONLY);
        assert(reaper_fd >= 0);
        assert(read(reaper_fd, saved_reaper.data(), saved_reaper.size()) == (ssize_t)saved_reaper.size());
        assert(close(reaper_fd) == 0);
        /* An old HPE1 without HRE1 is only process evidence. */
        assert(unlinkat(inbound.dirfd, reaper_name.c_str(), 0) == 0);
        assert(inbound.consumer_reaper_exit_status(first_receipt) == 0);
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, restarted_empty) == 1);
        int fd = openat(inbound.dirfd, exit_name.c_str(), O_RDWR);
        assert(fd >= 0);
        uint8_t saved; assert(pread(fd, &saved, 1, 136) == 1);
        uint8_t changed = saved ^ 1;
        assert(pwrite(fd, &changed, 1, 136) == 1);
        assert(inbound.checkpoint_consumer_process_exit(second_receipt, restarted_empty) == -1 && errno == EPROTO);
        assert(process_polls == polls_before && process_opens == opens_before);
        assert(pwrite(fd, &saved, 1, 136) == 1 && fsync(fd) == 0);
        assert(close(fd) == 0);
        /* Existing HPX1 remains readable and can promote evidence for other
         * receipts without a descriptor. Corrupt legacy proof cannot promote. */
        assert(unlinkat(inbound.dirfd, exit_name.c_str(), 0) == 0);
        int source = openat(inbound.dirfd, first_process_binding.c_str(), O_RDONLY);
        assert(source >= 0);
        std::array<uint8_t, 378> legacy{};
        assert(read(source, legacy.data(), legacy.size()) == (ssize_t)legacy.size());
        assert(close(source) == 0);
        memcpy(legacy.data(), "HPX1", 4);
        SHA256(legacy.data(), 346, legacy.data() + 346);
        std::string legacy_name = ".process-exit." + first_process_binding.substr(9);
        int old_exit = openat(inbound.dirfd, legacy_name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
        assert(old_exit >= 0);
        legacy[377] ^= 1;
        assert(write(old_exit, legacy.data(), legacy.size()) == (ssize_t)legacy.size());
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, restarted_empty) == -1 && errno == EPROTO);
        legacy[377] ^= 1;
        assert(pwrite(old_exit, legacy.data(), legacy.size(), 0) == (ssize_t)legacy.size());
        assert(fsync(old_exit) == 0 && close(old_exit) == 0);
        struct stat legacy_stat;
        fail_exit_fsync=true;
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, restarted_empty)==-1 && errno==EIO);
        assert(fstatat(inbound.dirfd,legacy_name.c_str(),&legacy_stat,AT_SYMLINK_NOFOLLOW)==0);
        fail_legacy_unlink=true;
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, restarted_empty)==-1 && errno==EIO);
        assert(!fail_legacy_unlink);
        assert(fstatat(inbound.dirfd,legacy_name.c_str(),&legacy_stat,AT_SYMLINK_NOFOLLOW)==0);
        fail_legacy_directory=true;
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, restarted_empty)==-1 && errno==EIO);
        assert(!fail_legacy_directory && !fail_legacy_parent);
        assert(fstatat(inbound.dirfd,legacy_name.c_str(),&legacy_stat,AT_SYMLINK_NOFOLLOW)==-1 && errno==ENOENT);
        assert(inbound.checkpoint_consumer_process_exit(first_receipt, restarted_empty) == 1);
        assert(inbound.checkpoint_consumer_process_exit(second_receipt, restarted_empty) == 1);
        assert(process_polls == polls_before && process_opens == opens_before);
        process_exited = query_process_exit = false;
    }
    add(3, 100, false); /* Another epoch does not require this stop's proof. */
    suspended = true;
    memcpy(owner, stop.token.data(), 16);
    int control_pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, control_pair) == 0);
    hello.kind = DTRACED_KIND_FORWARDER;
    hello.subs = DTD_SUB_READDATA;
    memcpy(hello.session_id, stop.source_session.data(), 16);
    strlcpy(hello.ident, "stop-source", sizeof(hello.ident));
    client_fd source(kq, control_pair[0], hello);
    source.vmid = stop.vmid; source.vm_epoch = stop.epoch;
    source.vm_attestation_fd = attestation_fd = dup(control_pair[0]);
    assert(attestation_fd >= 0);
    dtraced_hdr_t stop_header{};
    stop_header.msg_type = DTRACED_MSG_SESSION_STOP;
    unsigned char stop_body[DTRACED_SESSION_STOP_WIRE_SIZE];
    dtraced_wire_encode_session_stop(stop_body, stop.token.data());
    auto control = [&](int expected, client_fd *peer = nullptr, size_t size = DTRACED_SESSION_STOP_WIRE_SIZE) {
        client_request request(host, stop_header, stop_body, size, peer ? peer : &source);
        bool ok = request.handle();
        assert(ok == (expected >= 0));
        if (ok) assert(request.drain_step_response() && *request.drain_step_response() == expected);
        else assert(request.drain_step_response() == nullptr);
    };
    control(-1, &consumer);
    attestation_live = false; control(-1); attestation_live = true;
    control(-1, &source, sizeof(stop_body) - 1);
    stop_body[4] = 1; control(-1); stop_body[4] = 0;
    suspended = false; control(-1); suspended = true;
    durable_session_stop absent{};
    assert(outbound.fresh_session_stop_for_vm(stop.vmid, stop.epoch, absent) == 0);
    /* Missing collector leaves the admission cut durable, never complete. */
    host.sockfds.erase(&consumer);
    control(1);
    assert(outbound.fresh_session_stop_for_vm(stop.vmid, stop.epoch, absent) == 1);
    host.sockfds.insert(&consumer);
    /* Reconnect keeps the collector available for stop, without replaying
     * a startup-memorized old program or discarding its completion evidence. */
    dirent old_file{};
    strcpy(old_file.d_name,
        "elf.01000000000000000000000000000000.bb000000000000000000000000000000");
    assert(inbound.memorize_file(&old_file));
    assert(consumer.consumer_process_fd == -1);
    assert(inbound.queue_recovered_consumer(&consumer) == -1 && errno == EOPNOTSUPP);
    /* Earlier exit-proof cases deliberately closed the connection pin.
     * Restore a mocked verified pin for the subsequent replay/stop cases. */
    consumer.consumer_process_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(consumer.consumer_process_fd >= 0);
    assert(inbound.queue_recovered_consumer(&consumer) == 0 && host.joblist.empty());
    assert(inbound.memorized(old_file.d_name) && !consumer.retired.load());
    int fence = openat(outbound.dirfd, ".fresh-stop.002a.0000000000000063", O_RDWR);
    assert(fence >= 0);
    unsigned char original;
    assert(pread(fence, &original, 1, 79) == 1);
    unsigned char corrupt = original ^ 1;
    assert(pwrite(fence, &corrupt, 1, 79) == 1);
    assert(inbound.queue_recovered_consumer(&consumer) == -1 && errno == EPROTO &&
        host.joblist.empty());
    assert(pwrite(fence, &original, 1, 79) == 1 && close(fence) == 0);
    source.session_id[0] ^= 1; control(-1); source.session_id[0] ^= 1;
    assert(inbound.fresh_session_consumers(outbound, stop, found) == 1 && found.size() == 1);
    assert(found[0].recipient.consumer_session == consumer.session_id &&
        found[0].program_digest == consumer.consumer_program_digest);

    /* Duplicate receipts must agree on handle lifetime, not just program.
     * A valid checksum on another lifetime must not be deduplicated away. */
    {
        std::string name = ".handle." + first_process_binding.substr(9);
        int fd = openat(inbound.dirfd, name.c_str(), O_RDWR);assert(fd >= 0);
        std::array<uint8_t, 362> original{}, changed{};
        assert(read(fd, original.data(), original.size()) == (ssize_t)original.size());
        changed=original;changed[322]^=4;
        SHA256(changed.data(),330,changed.data()+330);
        assert(pwrite(fd,changed.data(),changed.size(),0)==(ssize_t)changed.size());
        assert(inbound.fresh_session_consumers(outbound,stop,found)==-1 && errno==EPROTO);
        assert(host.stop_fresh_session_step(stop)==-1 && errno==EPROTO);
        assert(pwrite(fd,original.data(),original.size(),0)==(ssize_t)original.size());
        assert(fsync(fd)==0 && close(fd)==0);
        assert(inbound.fresh_session_consumers(outbound,stop,found)==1 && found.size()==1);
    }

    journal_fd = outbound.dirfd;
    const auto proof = found[0];
    assert(inbound.fresh_consumer_stop_receipt(outbound, stop, proof, false) == 0);
    auto wrong = proof;
    wrong.owner_wire[28] ^= 1;
    assert(inbound.fresh_consumer_stop_receipt(outbound, stop, wrong, true) == -1 && errno == ESTALE);
    suspended = false;
    assert(inbound.fresh_consumer_stop_receipt(outbound, stop, proof, true) == -1 && errno == EBUSY);
    suspended = true;
    fail_intent_fsync = true;
    assert(inbound.fresh_consumer_stop_receipt(outbound, stop, proof, true) == -1 && errno == EIO);
    assert(inbound.fresh_consumer_stop_receipt(outbound, stop, proof, false) == 0);
    fail_ack_directory = true;
    assert(inbound.fresh_consumer_stop_receipt(outbound, stop, proof, true) == -1 && errno == EIO);
    assert(inbound.fresh_consumer_stop_receipt(outbound, stop, proof, false) == 1);
    auto ack_name = [&] {
        int fd = openat(outbound.dirfd, ".", O_RDONLY | O_DIRECTORY);
        assert(fd >= 0);
        DIR *scan = fdopendir(fd); assert(scan);
        std::string name;
        for (dirent *entry; (entry = readdir(scan)) != nullptr; )
            if (strncmp(entry->d_name, ".fresh-ack.", 11) == 0) {
                assert(name.empty()); name = entry->d_name;
            }
        assert(closedir(scan) == 0 && !name.empty());
        return name;
    };
    /* A stopped collector can durably commit proof on an independent
     * authenticated connection, then retry after losing its commit reply. */
    assert(unlinkat(outbound.dirfd, ack_name().c_str(), 0) == 0);
    {
        int commit_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, commit_pair) == 0);
        dtd_initmsg_t commit_hello{};
        commit_hello.kind = DTRACED_KIND_CONSUMER;
        commit_hello.subs = DTD_SUB_READDATA;
        memcpy(commit_hello.session_id, consumer.session_id.data(), 16);
        strlcpy(commit_hello.ident, consumer.ident, sizeof(commit_hello.ident));
        client_fd committer(kq, commit_pair[0], commit_hello);
        dtraced_consumer_stop_t assertion{};
        memcpy(assertion.token, stop.token.data(), 16);
        memcpy(assertion.source_session, stop.source_session.data(), 16);
        memcpy(assertion.consumer_session, consumer.session_id.data(), 16);
        memcpy(assertion.program_digest, consumer.consumer_program_digest.data(), 32);
        assertion.vmid = stop.vmid; assertion.epoch = stop.epoch; assertion.result = 1;
        auto commit = [&](bool expected, client_fd *peer = nullptr) {
            dtraced_hdr_t header{};
            header.msg_type = DTRACED_MSG_CONSUMER_STOP_COMMIT;
            unsigned char header_wire[DTRACED_MSGHDRSIZE];
            dtraced_wire_encode_header(header_wire, &header);
            assert(dtraced_wire_decode_header(&header, header_wire) == 0);
            unsigned char body[DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE];
            dtraced_wire_encode_consumer_stop_ack(body, &assertion);
            client_request request(host, header, body, sizeof(body), peer ? peer : &committer);
            assert(request.handle() == expected);
        };
        commit(false, &source);
        assertion.result = 0; commit(false); assertion.result = 1;
        assertion.token[0] ^= 1; commit(false); assertion.token[0] ^= 1;
        assertion.program_digest[0] ^= 1; commit(false); assertion.program_digest[0] ^= 1;
        committer.consumer_birth[0] ^= 1; commit(false); committer.consumer_birth[0] ^= 1;
        suspended = false; commit(false); suspended = true;
        assert(inbound.fresh_consumer_stop_receipt(outbound, stop, proof, false) == 0);
        fail_ack_directory = true;
        commit(false);
        commit(true); /* Exact retry finishes durability after uncertain fsync. */
        commit(true); /* A lost response does not require another stop RPC. */
        assert(inbound.fresh_consumer_stop_receipt(outbound, stop, proof, false) == 1);
        assert(close(commit_pair[1]) == 0);
    }
    /* Remove only our synthetic receipt before exercising the real RPC. */
    assert(unlinkat(outbound.dirfd, ack_name().c_str(), 0) == 0);
    host.sockfds.erase(&consumer);
    assert(host.stop_fresh_session_step(stop) == -1 && errno == EAGAIN);
    host.sockfds.insert(&consumer);
    const char *completion_name = ".fresh-done.002a.0000000000000063";
    std::vector<std::string> retirement_plan{"unchanged"};
    assert(outbound.plan_fresh_session_ack_retirement(stop, retirement_plan) == -1 &&
        errno == EBUSY && retirement_plan == std::vector<std::string>{"unchanged"});
    assert(inbound.complete_fresh_session_stop(outbound, stop) == -1 && errno == EAGAIN);
    struct stat completion_stat;
    assert(fstatat(outbound.dirfd, completion_name, &completion_stat,
        AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT);
    std::atomic_bool allow_commit{false};
    auto respond = [&](bool accept) {
        unsigned char header_wire[DTRACED_MSGHDRSIZE];
        unsigned char body[DTRACED_CONSUMER_STOP_WIRE_SIZE];
        unsigned char reply[DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE];
        size_t transferred;
        auto deadline = dtraced_io_deadline_after(5000);
        assert(dtraced_io_transfer(sockets[1], header_wire, sizeof(header_wire), false, deadline, &transferred) == 0);
        dtraced_hdr_t header{};
        assert(dtraced_wire_decode_header(&header, header_wire) == 0 && header.msg_type == DTRACED_MSG_CONSUMER_STOP);
        assert(dtraced_io_transfer(sockets[1], body, sizeof(body), false, deadline, &transferred) == 0);
        dtraced_consumer_stop_t challenge{};
        assert(dtraced_wire_decode_consumer_stop(&challenge, body) == 0);
        assert(challenge.vmid == 42 && challenge.epoch == 99 &&
            memcmp(challenge.token, stop.token.data(), 16) == 0 &&
            memcmp(challenge.consumer_session, consumer.session_id.data(), 16) == 0);
        challenge.result = accept;
        dtraced_wire_encode_consumer_stop_ack(reply, &challenge);
        if (accept) {
            /* Lose the reply, let the single coordinator worker return,
             * then publish proof through the independent connection. */
            assert(shutdown(sockets[1], SHUT_WR) == 0);
            while (!allow_commit.load())
                std::this_thread::yield();
            int pair[2];
            assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
            dtd_initmsg_t identity{};
            identity.kind = DTRACED_KIND_CONSUMER;
            identity.subs = DTD_SUB_READDATA;
            memcpy(identity.session_id, consumer.session_id.data(), 16);
            strlcpy(identity.ident, consumer.ident, sizeof(identity.ident));
            client_fd committer(kq, pair[0], identity);
            dtraced_hdr_t commit{};
            commit.msg_type = DTRACED_MSG_CONSUMER_STOP_COMMIT;
            client_request request(host, commit, reply, sizeof(reply), &committer);
            assert(request.handle());
            assert(close(pair[1]) == 0);
            return;
        }
        assert(dtraced_io_transfer(sockets[1], reply, sizeof(reply), true, deadline, &transferred) == 0);
    };
    {
        /* A delivery awaiting this collector's ACK holds its stream, and
         * dtrace -E ACKs only after this daemon accepts its derived program
         * on a worker.  The stop step must report pending, not wait. */
        std::unique_lock delivery(consumer.output_mtx);
        auto step = std::async(std::launch::async, [&] {
            int result = host.stop_fresh_session_step(stop);
            return std::make_pair(result, errno);
        });
        bool returned = step.wait_for(std::chrono::seconds(3)) ==
            std::future_status::ready;
        delivery.unlock();
        auto [result, error] = step.get();
        assert(returned && result == -1 && error == EAGAIN);
        char sent;	/* nothing reached the collector */
        assert(recv(sockets[1], &sent, 1, MSG_DONTWAIT) == -1 &&
            errno == EAGAIN && !consumer.retired.load());
    }
    std::thread refused(respond, false);
    assert(host.stop_fresh_session_step(stop) == -1 && errno == EOPNOTSUPP);
    refused.join();
    assert(inbound.fresh_consumer_stop_receipt(outbound, stop, proof, false) == 0);
    std::thread accepted(respond, true);
    control(1);
    assert(inbound.fresh_consumer_stop_receipt(outbound, stop, proof, false) == 0);
    allow_commit = true;
    accepted.join();
    assert(consumer.retired.load());
    fail_completion_file = true;
    assert(host.stop_fresh_session_step(stop) == -1 && errno == EIO);
    assert(!fail_completion_file);
    assert(fstatat(outbound.dirfd, completion_name, &completion_stat,
        AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT);
    fail_completion_directory = true;
    assert(host.stop_fresh_session_step(stop) == -1 && errno == EIO);
    assert(!fail_completion_directory && !fail_completion_parent);
    assert(fstatat(outbound.dirfd, completion_name, &completion_stat,
        AT_SYMLINK_NOFOLLOW) == 0 && completion_stat.st_size == 160);
    const std::string rpc_ack_name = ack_name();
    std::array<unsigned char,224> rpc_ack{};
    int rpc_ack_fd = openat(outbound.dirfd, rpc_ack_name.c_str(), O_RDONLY);
    assert(rpc_ack_fd >= 0 && pread(rpc_ack_fd, rpc_ack.data(), rpc_ack.size(), 0) == (ssize_t)rpc_ack.size());
    assert(close(rpc_ack_fd) == 0);
    control(0);
    control(0); /* Lost control response retries completion and empty cleanup. */
    assert(fstatat(outbound.dirfd, rpc_ack_name.c_str(), &completion_stat, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT);
    // Restore only the isolated ACK fixture for corruption/retirement cases.
    rpc_ack_fd = openat(outbound.dirfd, rpc_ack_name.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(rpc_ack_fd >= 0 && write(rpc_ack_fd, rpc_ack.data(), rpc_ack.size()) == (ssize_t)rpc_ack.size());
    assert(fsync(rpc_ack_fd) == 0 && close(rpc_ack_fd) == 0);
    {
        int fd = openat(outbound.dirfd, completion_name, O_RDWR | O_NOFOLLOW);
        assert(fd >= 0);
        std::array<unsigned char,160> saved{}, changed{};
        assert(pread(fd, saved.data(), saved.size(), 0) == (ssize_t)saved.size());
        assert(memcmp(saved.data(), "FSD1", 4) == 0 &&
            memcmp(saved.data() + 8, "FSI1", 4) == 0 &&
            dtraced_wire_get_u64(saved.data() + 88) == 1);
        changed = saved; changed[159] ^= 1;
        assert(pwrite(fd, changed.data(), changed.size(), 0) == (ssize_t)changed.size());
        assert(host.stop_fresh_session_step(stop) == -1 && errno == EPROTO);
        changed = saved; changed[96] ^= 1;
        SHA256(changed.data(), 128, changed.data() + 128);
        assert(pwrite(fd, changed.data(), changed.size(), 0) == (ssize_t)changed.size());
        /* Publication still compares the summary with the full census.
         * Standalone lookup cannot reconstruct a retired census digest. */
        assert(inbound.complete_fresh_session_stop(outbound, stop) == -1 && errno == ESTALE);
        changed = saved; changed[4] = 1;
        SHA256(changed.data(), 128, changed.data() + 128);
        assert(pwrite(fd, changed.data(), changed.size(), 0) == (ssize_t)changed.size());
        assert(outbound.fresh_session_stop_completed(stop) == -1 && errno == EPROTO);
        changed = saved; dtraced_wire_put_u64(changed.data() + 88, UINT64_MAX);
        SHA256(changed.data(), 128, changed.data() + 128);
        assert(pwrite(fd, changed.data(), changed.size(), 0) == (ssize_t)changed.size());
        assert(outbound.fresh_session_stop_completed(stop) == -1 && errno == EPROTO);
        assert(pwrite(fd, saved.data(), saved.size(), 0) == (ssize_t)saved.size());
        assert(fsync(fd) == 0 && close(fd) == 0);
        assert(host.stop_fresh_session_step(stop) == 0);
    }
    {
        dir recovered_in(ingress_path, nullptr), recovered_out(source_path, nullptr);
        assert(recovered_in.fresh_consumer_stop_receipt(recovered_out, stop, proof, false) == 1);
    }
    {
        auto wrong_completion = stop; wrong_completion.source_session[0] ^= 1;
        assert(outbound.fresh_session_stop_completed(wrong_completion) == -1 && errno == ESTALE);
        fail_completion_file = true;
        assert(outbound.fresh_session_stop_completed(stop) == -1 && errno == EIO);
        fail_completion_directory = true;
        assert(outbound.fresh_session_stop_completed(stop) == -1 && errno == EIO);
        assert(outbound.fresh_session_stop_completed(stop) == 1);
        assert(fchmodat(outbound.dirfd, completion_name, 0644, 0) == 0);
        assert(outbound.fresh_session_stop_completed(stop) == -1 && errno == EPROTO);
        assert(fchmodat(outbound.dirfd, completion_name, 0600, 0) == 0);
        assert(linkat(outbound.dirfd, completion_name, outbound.dirfd, ".completion-link", 0) == 0);
        assert(outbound.fresh_session_stop_completed(stop) == -1 && errno == EPROTO);
        assert(unlinkat(outbound.dirfd, ".completion-link", 0) == 0);
        assert(renameat(outbound.dirfd, completion_name, outbound.dirfd, ".completion-saved") == 0);
        assert(symlinkat(".completion-saved", outbound.dirfd, completion_name) == 0);
        assert(outbound.fresh_session_stop_completed(stop) == -1 &&
            (errno == ELOOP || errno == EMLINK)); // O_NOFOLLOW on FreeBSD returns EMLINK.
        assert(unlinkat(outbound.dirfd, completion_name, 0) == 0);
        assert(renameat(outbound.dirfd, ".completion-saved", outbound.dirfd, completion_name) == 0);
        const char *fence_name = ".fresh-stop.002a.0000000000000063";
        assert(renameat(outbound.dirfd, fence_name, outbound.dirfd, ".fence-saved") == 0);
        assert(outbound.fresh_session_stop_completed(stop) == -1 && errno == EPROTO);
        assert(renameat(outbound.dirfd, ".fence-saved", outbound.dirfd, fence_name) == 0);
        char empty_path[] = "/tmp/hypertrace-completed-empty.XXXXXX";
        assert(mkdtemp(empty_path));
        {
            state restarted{}; state_attestation_test::set_control(restarted);
            dir empty(empty_path, nullptr), recovered_out(source_path, nullptr);
            restarted.inbounddir = &empty; restarted.outbounddir = &recovered_out;
            unsigned queries = query_calls, polls = process_polls;
            assert(restarted.stop_fresh_session_step(stop) == 0);
            assert(query_calls == queries && process_polls == polls && restarted.joblist.empty());
        }
        assert(rmdir(empty_path) == 0);
    }
    {
        std::string exact_name = ack_name();
        int fd = openat(outbound.dirfd, exact_name.c_str(), O_RDONLY);
        assert(fd >= 0);
        std::array<unsigned char, 224> original{}, foreign{};
        assert(pread(fd, original.data(), original.size(), 0) == (ssize_t)original.size());
        struct stat before, after;
        assert(fstat(fd, &before) == 0 && close(fd) == 0);
        assert(outbound.plan_fresh_session_ack_retirement(stop, retirement_plan) == 1 &&
            retirement_plan == std::vector<std::string>{exact_name});
        assert(fstatat(outbound.dirfd, exact_name.c_str(), &after, AT_SYMLINK_NOFOLLOW) == 0 &&
            before.st_ino == after.st_ino && before.st_size == after.st_size);
        /* A valid ACK for another exact stop is retained and excluded. */
        foreign = original; foreign[20] ^= 1;
        SHA256(foreign.data() + 4, 48, foreign.data() + 52);
        SHA256(foreign.data(), 192, foreign.data() + 192);
        std::string foreign_name = ".fresh-ack.";
        const char hex[] = "0123456789abcdef";
        for (size_t i=192; i<224; ++i) {
            foreign_name += hex[foreign[i] >> 4];
            foreign_name += hex[foreign[i] & 15];
        }
        int other = openat(outbound.dirfd, foreign_name.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(other >= 0);
        assert(write(other, foreign.data(), foreign.size()) == (ssize_t)foreign.size());
        assert(fsync(other) == 0 && close(other) == 0);
        assert(outbound.plan_fresh_session_ack_retirement(stop, retirement_plan) == 1 &&
            retirement_plan == std::vector<std::string>{exact_name});
        assert(fstatat(outbound.dirfd, foreign_name.c_str(), &after, AT_SYMLINK_NOFOLLOW) == 0);
        assert(fchmodat(outbound.dirfd, exact_name.c_str(), 0644, 0) == 0);
        assert(outbound.plan_fresh_session_ack_retirement(stop, retirement_plan) == -1 &&
            errno == EPROTO && retirement_plan == std::vector<std::string>{exact_name});
        assert(fchmodat(outbound.dirfd, exact_name.c_str(), 0600, 0) == 0);
        fd = openat(outbound.dirfd, exact_name.c_str(), O_RDONLY);
        assert(fd >= 0);
        std::array<unsigned char,224> unchanged{};
        assert(pread(fd, unchanged.data(), unchanged.size(), 0) == (ssize_t)unchanged.size() &&
            unchanged == original && close(fd) == 0);
        fail_ack_unlink = true;
        assert(outbound.retire_completed_fresh_session_acks() == -1 && errno == EIO);
        assert(fstatat(outbound.dirfd, exact_name.c_str(), &after, AT_SYMLINK_NOFOLLOW) == 0);
        fail_ack_retire_sync = true;
        assert(outbound.retire_completed_fresh_session_acks() == -1 && errno == EIO);
        assert(!fail_ack_retire_sync && !ack_retire_parent);
        assert(outbound.retire_completed_fresh_session_acks() == 1);
        assert(fstatat(outbound.dirfd, exact_name.c_str(), &after, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT);
        assert(fstatat(outbound.dirfd, foreign_name.c_str(), &after, AT_SYMLINK_NOFOLLOW) == 0);
        assert(outbound.retire_fresh_session_acks(stop) == 1); // Empty durable retry.
        assert(inbound.complete_fresh_session_stop(outbound, stop) == 1);
        assert(inbound.fresh_consumer_stop_receipt(outbound, stop, proof, true) == 1);
        assert(fstatat(outbound.dirfd, exact_name.c_str(), &after, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT);
        assert(outbound.fresh_session_stop_completed(stop) == 1);
        // Restore only this fixture's ACK for the following corruption tests.
        fd = openat(outbound.dirfd, exact_name.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(fd >= 0 && write(fd, original.data(), original.size()) == (ssize_t)original.size());
        assert(fsync(fd) == 0 && close(fd) == 0);
        assert(unlinkat(outbound.dirfd, foreign_name.c_str(), 0) == 0); // Fixture cleanup only.
    }
    int fd = openat(outbound.dirfd, ack_name().c_str(), O_RDWR);
    assert(fd >= 0);
    unsigned char corruption;
    assert(pread(fd, &corruption, 1, 223) == 1);
    corruption ^= 0xff;
    assert(pwrite(fd, &corruption, 1, 223) == 1 && close(fd) == 0);
    auto previous_plan = retirement_plan;
    assert(outbound.plan_fresh_session_ack_retirement(stop, retirement_plan) == -1 &&
        errno == EPROTO && retirement_plan == previous_plan);
    assert(host.stop_fresh_session_step(stop) == 0); // Durable FSD1 supersedes this ACK.
    control(0);
    /* Without completion evidence the old per-recipient proof is mandatory. */
    assert(unlinkat(outbound.dirfd, completion_name, 0) == 0);
    assert(host.stop_fresh_session_step(stop) == -1 && errno == EPROTO);
    control(-1);
    /* Retry this exact stop after a collector crash, with no connection or
     * retained descriptor. Process exit alone remains insufficient. */
    assert(unlinkat(outbound.dirfd, ack_name().c_str(), 0) == 0);
    assert(host.stop_fresh_session_step(stop) == -1 && errno == EAGAIN);
    int reaper_fd = openat(inbound.dirfd, saved_reaper_name.c_str(),
        O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(reaper_fd >= 0);
    assert(write(reaper_fd, saved_reaper.data(), saved_reaper.size()) == (ssize_t)saved_reaper.size());
    assert(fsync(reaper_fd) == 0 && close(reaper_fd) == 0 && fsync(inbound.dirfd) == 0);
    retired_handle = false;
    assert(host.stop_fresh_session_step(stop) == -1 && errno == EAGAIN);
    assert(inbound.fresh_consumer_stop_receipt(outbound, stop, proof, false) == 0);
    fail_handle_query = true;
    assert(host.stop_fresh_session_step(stop) == -1 && errno == EAGAIN);
    fail_handle_query = false;retired_handle = true;
    fail_ack_directory = true;
    assert(host.stop_fresh_session_step(stop) == -1 && errno == EIO);
    assert(host.stop_fresh_session_step(stop) == 0);
    assert(inbound.fresh_consumer_stop_receipt(outbound, stop, proof, false) == 1);
    {
        state restarted{};state_attestation_test::set_control(restarted);
        dir recovered_in(ingress_path, nullptr), recovered_out(source_path, nullptr);
        restarted.inbounddir=&recovered_in;restarted.outbounddir=&recovered_out;
        recovered_in.state=recovered_out.state=&restarted;
        assert(restarted.stop_fresh_session_step(stop) == 0);
    }
    host.deadfds.erase(&consumer); /* Fixture retains stack ownership. */
    /* Release has a distinct wire operation and cannot reopen the fenced source. */
    stop_header.msg_type = DTRACED_MSG_SESSION_RELEASE;
    control(-1); /* FST1 is not a release credential. */
    dtraced_wire_encode_session_release(stop_body, stop.token.data());
    unsigned resumes = resume_calls;
    control(-1);
    assert(resume_calls == resumes && suspended);
    live_epoch = source.vm_epoch = 100;
    stop_body[8] ^= 0x20;
    control(-1); /* Another owner cannot release this gate. */
    assert(resume_calls == resumes && suspended);
    memcpy(owner, stop_body + 8, 16);
    attestation_live = false; control(-1); attestation_live = true;
    control(-1, &consumer);
    fail_resume_after_apply = true;
    control(-1);
    assert(!suspended && resume_calls == resumes + 1);
    control(0); /* Resolve a lost resume result without another resume. */
    control(0);
    assert(resume_calls == resumes + 1);
    owner[0] ^= 1;
    control(-1); /* An unsuspended gate under another owner is not success. */
    /* Replacement PID recovery uses the immutable old identity, even when
     * its numeric PID is occupied. Kernel process/handle facts are mocked. */
    {
        int old_pair[2],new_pair[2],incarnation_pair[2];
        assert(socketpair(AF_UNIX,SOCK_STREAM,0,old_pair)==0);
        assert(socketpair(AF_UNIX,SOCK_STREAM,0,new_pair)==0);
        assert(socketpair(AF_UNIX,SOCK_STREAM,0,incarnation_pair)==0);
        dtd_initmsg_t identity{};identity.kind=DTRACED_KIND_CONSUMER;
        identity.subs=DTD_SUB_ELFWRITE;identity.session_id[0]=0xa7;
        strlcpy(identity.ident,consumer.ident,sizeof(identity.ident));
        client_fd old(kq,old_pair[0],identity),replacement(kq,new_pair[0],identity);
        client_fd incarnation(kq,incarnation_pair[0],identity);
        incarnation.consumer_birth[0]^=1; // Same PID, distinct monotonic birth.
        old.consumer_program_valid=true;
        old.consumer_program_digest=consumer.consumer_program_digest;
        old.consumer_handle_lifetime=consumer.consumer_handle_lifetime;
        for (auto *peer : {&old, &replacement, &incarnation}) {
            peer->consumer_program_valid = true;
            peer->consumer_program_digest = consumer.consumer_program_digest;
            peer->consumer_handle_lifetime = consumer.consumer_handle_lifetime;
            peer->consumer_process_fd = dup(consumer.consumer_process_fd);
            assert(peer->consumer_process_fd >= 0);
        }
        assert(inbound.queue_recovered_consumer(&old)==0);
        replacement.peer_pid=old.peer_pid+1;
        durable_delivery ingress=first_receipt.ingress;
        ingress.delivery_id=55;ingress.epoch=103;ingress.program_id[1]=55;
        assert(inbound.record_delivery(ingress,delivery_phase::pending,true));
        assert(inbound.record_delivery(ingress,delivery_phase::accepted));
        durable_consumer_receipt receipt{};receipt.ingress=ingress;
        receipt.consumer_session=old.session_id;receipt.consumer_uid=old.peer_uid;
        receipt.consumer_pid=old.peer_pid;
        std::vector<durable_consumer_receipt> cohort;
        assert(inbound.consumer_cohort(ingress,{receipt},cohort)==1);
        assert(inbound.record_consumer_receipt(receipt,consumer_receipt_phase::pending)>0);
        int previous_fd=process_fd;
        process_fd=open("/dev/null",O_RDONLY|O_CLOEXEC);assert(process_fd>=0);
        auto key=collector_owner_identity(old.session_id,old.consumer_birth,
            old.peer_uid,old.peer_pid,old.consumer_program_digest,old.consumer_handle_lifetime);
        assert(host.collector_owners.retain(key,process_fd)==0);
        assert(inbound.record_consumer_program(receipt,old)==1);
        assert(inbound.record_consumer_receipt(receipt,consumer_receipt_phase::no_derived)>0);
        assert(inbound.record_consumer_receipt(receipt,consumer_receipt_phase::executed_no_derived)>0);
        query_process_exit=true;process_exited=false;
        assert(inbound.queue_recovered_consumer(&replacement)==-1 && errno==EBUSY);
        assert(inbound.queue_recovered_consumer(&incarnation)==-1 && errno==EBUSY);
        process_exited=true;reaper_flags=PD_REAPER_EXITED|PD_REAPER_OWNED|PD_REAPER_EMPTY;
        retired_handle=false;
        assert(inbound.queue_recovered_consumer(&replacement)==-1 && errno==EBUSY);
        assert(inbound.queue_recovered_consumer(&incarnation)==-1 && errno==EBUSY);
        retired_handle=true;
        assert(inbound.queue_recovered_consumer(&incarnation)==0);
        assert(inbound.queue_recovered_consumer(&incarnation)==0);
        /* Rotated HCO1 must not hide the old immutable HCP1 on reconnect. */
        retired_handle=false;
        assert(inbound.queue_recovered_consumer(&incarnation)==-1 && errno==EBUSY);
        retired_handle=true;
        assert(inbound.queue_recovered_consumer(&replacement)==0);
        assert(host.joblist.empty());
        assert(inbound.queue_recovered_consumer(&replacement)==0);
        query_process_exit=process_exited=false;
        assert(close(process_fd)==0);process_fd=previous_fd;
        assert(close(old_pair[1])==0 && close(new_pair[1])==0 && close(incarnation_pair[1])==0);
    }
    /* Reconcile an authenticated registration with no admitted delivery.
     * A later pending receipt must recover HPB1 from durable HPE1. */
    {
        auto original_program=consumer.consumer_program_digest;
        consumer.consumer_program_digest[0]^=0x10;
        auto key=collector_owner_identity(consumer.session_id,consumer.consumer_birth,
            consumer.peer_uid,consumer.peer_pid,consumer.consumer_program_digest,
            consumer.consumer_handle_lifetime);
        int previous_process_fd=process_fd;
        process_fd=open("/dev/null",O_RDONLY|O_CLOEXEC);assert(process_fd>=0);
        assert(inbound.checkpoint_collector_exit(key,host.collector_owners)==0);
        assert(host.collector_owners.retain(key,process_fd)==0);
        query_process_exit=true;process_exited=false;
        assert(inbound.checkpoint_collector_exit(key,host.collector_owners)==0);
        process_exited=true;reaper_flags=PD_REAPER_EXITED|PD_REAPER_OWNED|PD_REAPER_EMPTY;
        fail_reaper_fsync=true;
        assert(inbound.checkpoint_collector_exit(key,host.collector_owners)==-1 && errno==EIO);
        assert(host.collector_owners.retained(key));
        fail_exit_fsync=true;
        assert(inbound.checkpoint_collector_exit(key,host.collector_owners)==-1 && errno==EIO);
        assert(host.collector_owners.retained(key));
        assert(inbound.checkpoint_collector_exit(key,host.collector_owners)==1);
        assert(!host.collector_owners.retained(key));
        assert(inbound.checkpoint_collector_exit(key,host.collector_owners)==0);
        auto late=add(4,101,false);
        assert(inbound.record_consumer_program(late,consumer)==1);
        assert(inbound.consumer_reaper_exit_status(late)==1);
        collector_owner_registry empty;
        assert(inbound.checkpoint_consumer_process_exit(late,empty)==1);
        /* Exercise the real background worker, without starting a daemon. */
        assert(host.collector_owners.retain(key,process_fd)==0);
        host.shutdown.store(0);
        std::thread worker([&]{host.close_filedescs();});
        {
            std::lock_guard lock(host.deadfdsmtx);
            host.deadfds_generation++;
        }
        host.deadfdscv.notify_all();
        for(unsigned i=0;i<200 && host.collector_owners.retained(key);i++)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        bool released=!host.collector_owners.retained(key);
        host.shutdown.store(1);host.deadfdscv.notify_all();worker.join();
        assert(released);
        assert(close(process_fd)==0);process_fd=previous_process_fd;
        process_exited=query_process_exit=false;
        consumer.consumer_program_digest=original_program;
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
    close(sockets[1]); close(control_pair[1]); close(kq);
    assert(rmdir(source_path) == 0 && rmdir(ingress_path) == 0);
    puts("PASS: collector stop RPC, durable ACK, refusal, fsync recovery, restart and corruption fencing");
}
