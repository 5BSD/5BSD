/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <vector>
#include <unistd.h>
#include "dtraced_directory.h"

using namespace dtraced;

static bool fail_next_fsync;
extern "C" int __real_fsync(int);
extern "C" int
__wrap_fsync(int fd)
{
	if (fail_next_fsync) {
		fail_next_fsync = false;
		errno = EIO;
		return (-1);
	}
	return (__real_fsync(fd));
}

static void
remove_directory(const char *path)
{
	DIR *scan = opendir(path);
	assert(scan != nullptr);
	while (struct dirent *entry = readdir(scan)) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;
		char name[MAXPATHLEN];
		assert(snprintf(name, sizeof(name), "%s/%s", path,
		    entry->d_name) < (int)sizeof(name));
		assert(unlink(name) == 0);
	}
	assert(closedir(scan) == 0);
	assert(rmdir(path) == 0);
}

int
main()
{
	alarm(10);
	char path[] = "/tmp/hypertrace-guest-kill-rekey.XXXXXX";
	assert(mkdtemp(path) != nullptr);
	{
		dir inbound(path, nullptr);
		durable_kill applied{};
		applied.pid = 12345;
		applied.vmid = 42;
		applied.epoch = 99;
		applied.source_id[0] = 0x42;
		assert(inbound.record_kill(applied));
		assert(inbound.record_kill_applied(applied));
		durable_kill duplicate = applied;
		duplicate.pid = 12346;
		duplicate.source_id[0] = 0x43;
		assert(inbound.record_kill(duplicate));
		assert(inbound.fence_guest_rekey(1, 42, 99, 43, 100));
		durable_kill already_bound = duplicate;
		already_bound.vmid = 43;
		already_bound.epoch = 100;
		assert(inbound.record_kill(already_bound));
		assert(inbound.record_kill_applied(already_bound));
		fail_next_fsync = true;
		assert(!inbound.rekey_guest_kills(42, 99, 43, 100));
		assert(errno == EIO && !fail_next_fsync);
		std::vector<durable_kill> interrupted;
		assert(inbound.list_kills(interrupted));
		bool first_present = false, second_present = false;
		for (const durable_kill &record : interrupted) {
			if (record.pid == applied.pid &&
			    record.source_id == applied.source_id)
				first_present = true;
			if (record.pid == duplicate.pid &&
			    record.source_id == duplicate.source_id)
				second_present = true;
		}
		assert(first_present && second_present);
		{
			dir restarted(path, nullptr);
			assert(restarted.rekey_guest_kills(42, 99, 43, 100));
		}
		std::vector<durable_kill> records;
		assert(inbound.list_kills(records) && records.size() == 2);
		for (const durable_kill &record : records)
			assert(record.vmid == 43 && record.epoch == 100);
		durable_kill stale = applied;
		stale.pid = 12347;
		assert(!inbound.record_kill(stale) && errno == ESTALE);
		assert(!inbound.record_kill_applied(applied) && errno == ESTALE);
		durable_kill destination = applied;
		destination.vmid = 43;
		destination.epoch = 100;
		assert(inbound.kill_applied(destination) == 0);
		assert(inbound.kill_applied(already_bound) == 0);
		assert(inbound.source_revoked(applied.source_id.data()) == 1);
		/* A retry during pending restore must also clear ACKs on records
		 * which were already renamed before the earlier interruption. */
		assert(inbound.record_kill_applied(destination));
		assert(inbound.record_kill_applied(already_bound));
		assert(inbound.rekey_guest_kills(42, 99, 43, 100));
		assert(inbound.kill_applied(destination) == 0);
		assert(inbound.kill_applied(already_bound) == 0);
		assert(inbound.list_kills(records) && records.size() == 2);
	}
	remove_directory(path);

	char foreign_path[] = "/tmp/hypertrace-guest-kill-foreign.XXXXXX";
	assert(mkdtemp(foreign_path) != nullptr);
	{
		dir inbound(foreign_path, nullptr);
		durable_kill source{};
		source.pid = 12345;
		source.vmid = 42;
		source.epoch = 99;
		source.source_id[0] = 0x42;
		assert(inbound.record_kill(source));
		durable_kill foreign = source;
		foreign.vmid = 44;
		foreign.epoch = 101;
		foreign.source_id[0] = 0x44;
		assert(inbound.record_kill(foreign));
		assert(!inbound.fence_guest_rekey(1, 42, 99, 43, 100));
		assert(errno == ESTALE);
		assert(!inbound.rekey_guest_kills(42, 99, 43, 100));
		assert(errno == ESTALE);
		std::vector<durable_kill> records;
		assert(inbound.list_kills(records) && records.size() == 2);
		assert(inbound.kill_applied(source) == 0);
	}
	remove_directory(foreign_path);

	char collision_path[] = "/tmp/hypertrace-guest-kill-collision.XXXXXX";
	assert(mkdtemp(collision_path) != nullptr);
	{
		dir inbound(collision_path, nullptr);
		durable_kill source{};
		source.pid = 12345;
		source.vmid = 42;
		source.epoch = 99;
		source.source_id[0] = 0x42;
		assert(inbound.record_kill(source));
		durable_kill occupied = source;
		occupied.pid = 12346;
		occupied.vmid = 43;
		occupied.epoch = 100;
		assert(inbound.record_kill(occupied));
		assert(inbound.record_kill_applied(occupied));
		assert(!inbound.rekey_guest_kills(42, 99, 43, 100));
		assert(errno == ESTALE && inbound.kill_applied(occupied) == 1);
		assert(!inbound.fence_guest_rekey(1, 42, 99, 43, 100));
		assert(errno == ESTALE);
		std::vector<durable_kill> records;
		assert(inbound.list_kills(records) && records.size() == 2);
	}
	remove_directory(collision_path);

	char empty_path[] = "/tmp/hypertrace-guest-empty-kill-rekey.XXXXXX";
	assert(mkdtemp(empty_path) != nullptr);
	{
		dir inbound(empty_path, nullptr);
		assert(inbound.fence_guest_rekey(1, 42, 99, 43, 100));
		durable_kill source{};
		source.pid = 12345;
		source.vmid = 42;
		source.epoch = 99;
		source.source_id[0] = 0x42;
		assert(!inbound.record_kill(source) && errno == ESTALE);
		source.vmid = 43;
		source.epoch = 100;
		assert(inbound.record_kill(source));
	}
	remove_directory(empty_path);

	char retired_path[] = "/tmp/hypertrace-guest-kill-retired.XXXXXX";
	assert(mkdtemp(retired_path) != nullptr);
	{
		dir inbound(retired_path, nullptr);
		assert(inbound.fence_guest_rekey(1, 43, 100, 44, 101));
		durable_kill source{};
		source.pid = 12345;
		source.vmid = 42;
		source.epoch = 99;
		source.source_id[0] = 0x42;
		assert(inbound.record_kill(source));
		assert(!inbound.rekey_guest_kills(42, 99, 43, 100));
		assert(errno == ESTALE);
		std::vector<durable_kill> records;
		assert(inbound.list_kills(records) && records.size() == 1);
		assert(records[0].vmid == 42 && records[0].epoch == 99);
	}
	remove_directory(retired_path);

	char overlap_path[] = "/tmp/hypertrace-guest-kill-overlap.XXXXXX";
	assert(mkdtemp(overlap_path) != nullptr);
	{
		dir inbound(overlap_path, nullptr);
		durable_kill source{};
		source.pid = 12345;
		source.vmid = 42;
		source.epoch = 99;
		source.source_id[0] = 0x42;
		assert(inbound.record_kill(source));
		char lock_path[MAXPATHLEN];
		assert(snprintf(lock_path, sizeof(lock_path), "%s/.handoff.lock",
		    overlap_path) < (int)sizeof(lock_path));
		int lockfd = open(lock_path, O_RDWR | O_CREAT, 0600);
		assert(lockfd >= 0 && flock(lockfd, LOCK_EX) == 0);
		int ready[2], result[2];
		assert(pipe(ready) == 0 && pipe(result) == 0);
		pid_t child = fork();
		assert(child >= 0);
		if (child == 0) {
			close(lockfd);
			close(ready[0]);
			close(result[0]);
			dir restarted(overlap_path, nullptr);
			char signal = 'r';
			if (write(ready[1], &signal, 1) != 1)
				_exit(2);
			signal = restarted.record_kill_applied(source) ? 'y' : 'n';
			if (write(result[1], &signal, 1) != 1)
				_exit(3);
			_exit(0);
		}
		close(ready[1]);
		close(result[1]);
		char signal;
		assert(read(ready[0], &signal, 1) == 1 && signal == 'r');
		struct pollfd wait_result = {result[0], POLLIN, 0};
		assert(poll(&wait_result, 1, 100) == 0);
		assert(flock(lockfd, LOCK_UN) == 0);
		assert(poll(&wait_result, 1, 1000) == 1);
		assert(read(result[0], &signal, 1) == 1 && signal == 'y');
		int status;
		assert(waitpid(child, &status, 0) == child &&
		    WIFEXITED(status) && WEXITSTATUS(status) == 0);
		assert(close(ready[0]) == 0 && close(result[0]) == 0 &&
		    close(lockfd) == 0);
		assert(inbound.kill_applied(source) == 1);
	}
	remove_directory(overlap_path);
	puts("PASS: guest KILL rekey is durable, clears ACKs, rejects foreign identities, and fences concurrent ACK writers");
}
