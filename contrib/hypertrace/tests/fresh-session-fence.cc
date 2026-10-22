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

int main()
{
    char path[] = "/tmp/hypertrace-fresh-stop.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    durable_session_stop stop{};
    stop.token[0] = 0xa1;
    stop.source_session[0] = 0xb2;
    stop.vmid = live_vmid;
    stop.epoch = live_epoch;
    const char *name = ".fresh-stop.002a.0000000000000063";
    {
        dir journal(path, nullptr);
        journal_fd = journal.dirfd;
        durable_session_stop found{};
        assert(journal.fresh_session_stop_for_vm(42, 99, found) == 0);
        assert(!journal.begin_fresh_session_stop(stop) && errno == EBUSY);
        suspended = true;
        assert(!journal.begin_fresh_session_stop(stop) && errno == EBUSY);
        memcpy(owner, stop.token.data(), 16);
        fail_intent_fsync = true;
        assert(!journal.begin_fresh_session_stop(stop) && errno == EIO);
        assert(journal.fresh_session_stop_for_vm(42, 99, found) == 0);
        fail_directory_fsync = true;
        assert(!journal.begin_fresh_session_stop(stop) && errno == EIO);
        assert(journal.fresh_session_stop_for_vm(42, 99, found) == 1 &&
            found.token == stop.token && found.source_session == stop.source_session);
        bool admitted = false;
        assert(journal.with_source_handoff_phase(42, 99,
            [&](int) { admitted = true; }) == -1 && errno == ECANCELED && !admitted);
        assert(journal.begin_fresh_session_stop(stop));
        auto other = stop;
        other.token[0]++;
        assert(!journal.begin_fresh_session_stop(other) && errno == ESTALE);
        other = stop;
        other.source_session[0]++;
        assert(!journal.begin_fresh_session_stop(other) && errno == ESTALE);
        assert(suspend_calls == 0 && resume_calls == 0);
    }
    {
        dir restarted(path, nullptr);
        journal_fd = restarted.dirfd;
        durable_session_stop found{};
        assert(restarted.fresh_session_stop_for_vm(42, 99, found) == 1);
        uint8_t source[16] = {1};
        assert(!restarted.lock_live_source(source, 42, 99) && errno == ECANCELED);
        bool admitted = false;
        assert(restarted.with_source_handoff_phase(42, 100,
            [&](int phase) { admitted = phase == 0; }) == 0 && admitted);
        assert(restarted.begin_fresh_session_stop(stop));
        int fd = openat(restarted.dirfd, name, O_RDWR);
        assert(fd >= 0);
        char corrupt = 1;
        assert(pwrite(fd, &corrupt, 1, 79) == 1 && close(fd) == 0);
        assert(restarted.fresh_session_stop_for_vm(42, 99, found) == -1 && errno == EPROTO);
        assert(!restarted.begin_fresh_session_stop(stop) && errno == EPROTO);
        assert(!restarted.lock_live_source(source, 42, 99) && errno == EPROTO);
        int scanfd = openat(restarted.dirfd, ".", O_RDONLY | O_DIRECTORY);
        assert(scanfd >= 0);
        DIR *scan = fdopendir(scanfd);
        assert(scan != nullptr);
        for (dirent *entry; (entry = readdir(scan)) != nullptr; )
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
                assert(unlinkat(restarted.dirfd, entry->d_name, 0) == 0);
        assert(closedir(scan) == 0);
    }
    assert(rmdir(path) == 0);
    puts("PASS: durable fresh stop, fsync recovery, old-epoch admission and corruption fences");
}
