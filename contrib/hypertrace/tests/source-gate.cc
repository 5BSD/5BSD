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
	    S_ISREG(sb.st_mode) && sb.st_size == 94) {
		fail_intent_fsync = false;
		errno = EIO;
		return (-1);
	}
	return (__real_fsync(fd));
}

static void
find_intent(int fd, char name[39])
{
	int scanfd = openat(fd, ".", O_RDONLY | O_DIRECTORY);
	assert(scanfd >= 0);
	DIR *scan = fdopendir(scanfd);
	assert(scan != nullptr);
	unsigned count = 0;
	for (dirent *entry; (entry = readdir(scan)) != nullptr; ) {
		if (strncmp(entry->d_name, ".gate.", 6) == 0) {
			assert(strlen(entry->d_name) == 38);
			memcpy(name, entry->d_name, 39);
			count++;
		}
	}
	assert(closedir(scan) == 0 && count == 1);
}

static void
make_drain_name(const durable_handoff &ticket, char name[105])
{
	static const char hex[] = "0123456789abcdef";
	memcpy(name, ".drain.", 7);
	for (size_t i = 0; i < ticket.token.size(); i++) {
		name[7 + 2 * i] = hex[ticket.token[i] >> 4];
		name[8 + 2 * i] = hex[ticket.token[i] & 15];
	}
	name[39] = '.';
	memset(name + 40, 'a', 64);
	name[104] = '\0';
}

static void
put_drain_name(int directory, const char *name)
{
	int fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL, 0600);
	assert(fd >= 0);
	assert(write(fd, "x", 1) == 1 && close(fd) == 0);
}

int
main()
{
	char path[] = "/tmp/hypertrace-source-gate.XXXXXX";
	assert(mkdtemp(path) != nullptr);
	durable_handoff ticket{};
	ticket.token[0] = 0xa1;
	ticket.source_session[0] = 0xb2;
	ticket.source_vmid = live_vmid;
	ticket.source_epoch = live_epoch;
	ticket.transfer_digest[0] = 0xd4;
	char name[39] = {};
	{
		dir journal(path, nullptr);
		journal_fd = journal.dirfd;
		fail_intent_fsync = true;
		assert(!journal.source_gate_begin(ticket) && errno == EIO);
		assert(suspend_calls == 0 && !suspended);
		fail_directory_fsync = true;
		assert(!journal.source_gate_begin(ticket) && errno == EIO);
		assert(suspend_calls == 0 && !suspended);
		find_intent(journal.dirfd, name);
		fail_suspend = true;
		assert(!journal.source_gate_begin(ticket) && errno == EIO);
		assert(suspend_calls == 1 && !suspended);
		find_intent(journal.dirfd, name);
		struct stat sb;
		assert(fstatat(journal.dirfd, name, &sb, 0) == 0 &&
		    sb.st_size == 94);
	}
	/* A new daemon instance reads the durable intent and retries the CAS. */
	{
		dir recovered(path, nullptr);
		journal_fd = recovered.dirfd;
		assert(recovered.source_gate_begin(ticket));
		assert(suspended && owner[0] == ticket.token[0] &&
		    suspend_calls == 2);
		unsigned before = suspend_calls;
		assert(recovered.source_gate_begin(ticket) &&
		    suspend_calls == before);
		durable_handoff foreign = ticket;
		foreign.token[0] = 0xc3;
		char drain[105], foreign_drain[105];
		make_drain_name(ticket, drain);
		make_drain_name(foreign, foreign_drain);
		put_drain_name(recovered.dirfd, drain);
		put_drain_name(recovered.dirfd, foreign_drain);
		assert(!recovered.source_gate_begin(foreign) && errno == EBUSY);
		assert(recovered.prepare_handoff(ticket));
		assert(recovered.prepare_handoff(ticket));
		/* A lost PREPARE reply cannot be accepted after the VMM gate
		 * stops being suspended, even if HTH2 still says prepared. */
		suspended = false;
		assert(!recovered.prepare_handoff(ticket) && errno == ESTALE);
		suspended = true;
		assert(!recovered.source_gate_abort(ticket) && errno == EBUSY);
		assert(recovered.abort_handoff(ticket));
		fail_directory_fsync = true;
		assert(!recovered.source_gate_abort(ticket) && errno == EIO);
		/* RESUME and unlink already happened; retry must finish the sync. */
		assert(recovered.source_gate_abort(ticket));
		assert(!suspended && resume_calls == 1 &&
		    faccessat(recovered.dirfd, name, F_OK, 0) == -1 &&
		    errno == ENOENT);
		assert(faccessat(recovered.dirfd, drain, F_OK, 0) == -1 &&
		    errno == ENOENT);
		assert(faccessat(recovered.dirfd, foreign_drain, F_OK, 0) == 0);
		assert(recovered.source_gate_abort(ticket) && resume_calls == 1);
		/* The next ticket observes the completed token as its CAS parent. */
		assert(recovered.source_gate_begin(foreign));
		assert(suspended && owner[0] == foreign.token[0]);
		assert(!recovered.source_gate_abort(ticket) && errno == EBUSY);
		assert(recovered.source_gate_abort(foreign));
		assert(!suspended && resume_calls == 2);
		assert(faccessat(recovered.dirfd, foreign_drain, F_OK, 0) == -1 &&
		    errno == ENOENT);
		assert(!recovered.source_gate_begin(foreign) && errno == EALREADY);
		/* A durable post-destroy release retires the matching gate intent.
		 * Replaying the release after a lost ACK is harmless. */
		durable_handoff retired = ticket;
		retired.token[0] = 0xd4;
		assert(recovered.source_gate_begin(retired));
		find_intent(recovered.dirfd, name);
		assert(recovered.prepare_handoff(retired));
		retired.checkpoint_digest[0] = 0x55;
		assert(recovered.commit_handoff(retired));
		fail_directory_fsync = true;
		assert(!recovered.record_source_release(retired) && errno == EIO);
		assert(faccessat(recovered.dirfd, name, F_OK, 0) == 0);
		assert(recovered.record_source_release(retired));
		assert(faccessat(recovered.dirfd, name, F_OK, 0) == -1 &&
		    errno == ENOENT);
		assert(recovered.record_source_release(retired));
	}
	/* The retired VM lifetime is gone; the next fixture uses a new one. */
	suspended = false;
	memset(owner, 0, sizeof(owner));
	live_epoch++;
	{
		/* PREPARE must prove that an accepted source delivery has the
		 * exact ELF bytes the destination binder will need. */
		dir recovered(path, nullptr);
		journal_fd = recovered.dirfd;
		durable_handoff cut = ticket;
		cut.token[0] = 0xe1;
		cut.source_epoch = live_epoch;
		assert(recovered.source_gate_begin(cut));
		durable_delivery delivery{};
		delivery.session_id = cut.source_session;
		delivery.delivery_id = 91;
		delivery.vmid = cut.source_vmid;
		delivery.epoch = cut.source_epoch;
		delivery.program_id[0] = 0x91;
		delivery.source_id[0] = 0x92;
		delivery.peer_uid = 0;
		delivery.peer_pid = 123;
		delivery.journal_version = 4;
		const unsigned char elf[] = "\177ELFsource-cut";
		assert(SHA256(elf, sizeof(elf) - 1,
		    delivery.payload_digest.data()) != nullptr);
		assert(recovered.record_delivery(delivery,
		    delivery_phase::pending, true));
		assert(recovered.record_delivery(delivery,
		    delivery_phase::accepted));
		std::vector<uint8_t> captured{0xff};
		assert(recovered.verify_host_delivery_payload(delivery,
		    &captured) == 0 && captured.empty());
		assert(!recovered.prepare_handoff(cut) && errno == EBUSY);
		assert(recovered.write_identified_data(elf, sizeof(elf) - 1,
		    delivery.program_id.data(), nullptr,
		    delivery.source_id.data()));
		assert(recovered.verify_host_delivery_payload(delivery,
		    &captured) == 1 && captured.size() == sizeof(elf) - 1 &&
		    memcmp(captured.data(), elf, captured.size()) == 0);
		assert(dir::validate_host_delivery_payload(delivery, captured));
		captured.back() ^= 1;
		assert(!dir::validate_host_delivery_payload(delivery,
		    captured) && errno == EPROTO);
		captured.back() ^= 1;
		durable_cleanup queued{};
		queued.vmid = cut.source_vmid;
		queued.epoch = cut.source_epoch;
		queued.delivery_id = 93;
		assert(recovered.record_cleanup_pending(queued));
		assert(!recovered.prepare_handoff(cut) && errno == EBUSY);
		assert(recovered.record_cleanup_queued(queued));
		assert(recovered.prepare_handoff(cut));
		assert(recovered.abort_handoff(cut));
		assert(recovered.source_gate_abort(cut));
		live_epoch++;
		cut.token[0] = 0xe2;
		cut.source_epoch = live_epoch;
		assert(recovered.source_gate_begin(cut));
		delivery.delivery_id++;
		delivery.epoch = live_epoch;
		delivery.program_id[0]++;
		delivery.source_id[0]++;
		assert(recovered.record_delivery(delivery,
		    delivery_phase::pending, true));
		assert(recovered.record_delivery(delivery,
		    delivery_phase::accepted));
		const unsigned char changed[] = "\177ELFwrong-cut";
		assert(recovered.write_identified_data(changed,
		    sizeof(changed) - 1, delivery.program_id.data(),
		    nullptr, delivery.source_id.data()));
		assert(recovered.verify_host_delivery_payload(delivery,
		    &captured) == -1 && errno == EPROTO && captured.empty());
		assert(!recovered.prepare_handoff(cut) && errno == EPROTO);
		assert(recovered.source_gate_abort(cut));
		live_epoch++;
	}
	{
		dir recovered(path, nullptr);
		journal_fd = recovered.dirfd;
		/* A torn or altered intent refuses to authorize a kernel transition. */
		durable_handoff next = ticket;
		next.token[0] = 0xe5;
		next.source_epoch = live_epoch;
		assert(recovered.source_gate_begin(next));
		find_intent(recovered.dirfd, name);
		int fd = openat(recovered.dirfd, name, O_RDWR);
		assert(fd >= 0);
		uint8_t changed = 0xff;
		assert(pwrite(fd, &changed, 1, 20) == 1 && close(fd) == 0);
		unsigned before = query_calls;
		assert(!recovered.source_gate_begin(next) && errno == EPROTO &&
		    query_calls == before);
		assert(!recovered.source_gate_abort(next) && errno == EPROTO);
		/* The fixture owns its mock kernel; clear the corrupted test state. */
		assert(unlinkat(recovered.dirfd, name, 0) == 0);
		suspended = false;
		int scanfd = openat(recovered.dirfd, ".",
		    O_RDONLY | O_DIRECTORY);
		assert(scanfd >= 0);
		DIR *scan = fdopendir(scanfd);
		assert(scan != nullptr);
		for (dirent *entry; (entry = readdir(scan)) != nullptr; )
			if (strcmp(entry->d_name, ".") != 0 &&
			    strcmp(entry->d_name, "..") != 0)
				assert(unlinkat(recovered.dirfd,
				    entry->d_name, 0) == 0);
		assert(closedir(scan) == 0);
	}
	assert(rmdir(path) == 0);
	puts("PASS: source gate, outbound ELF cut, restart CAS, abort, and corruption fence");
}
