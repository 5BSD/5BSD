/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <poll.h>
#include <vector>
#include <unistd.h>
#include "dtraced_directory.h"

using namespace dtraced;

static int fail_fsync_number;
extern "C" int __real_fsync(int);
extern "C" int
__wrap_fsync(int fd)
{
	if (fail_fsync_number > 0 && --fail_fsync_number == 0) {
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

enum class guest_mutation { transition, retire_inbound, retire_outbound };

static void
assert_rekey_lock_blocks(const char *path, const durable_delivery &record,
    guest_mutation mutation)
{
	char lock_path[MAXPATHLEN];
	assert(snprintf(lock_path, sizeof(lock_path), "%s/.handoff.lock",
	    path) < (int)sizeof(lock_path));
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
		dir restarted(path, nullptr);
		char signal = 'r';
		if (write(ready[1], &signal, 1) != 1)
			_exit(2);
		bool ok = mutation == guest_mutation::transition ?
		    restarted.record_delivery(record, delivery_phase::accepted) :
		    mutation == guest_mutation::retire_inbound ?
		    restarted.retire_terminal_delivery(record) :
		    restarted.retire_accepted_outbound(record);
		signal = ok ? 'y' : 'n';
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
}

int
main()
{
	alarm(10);
	char path[] = "/tmp/hypertrace-guest-delivery-rekey.XXXXXX";
	assert(mkdtemp(path) != nullptr);
	{
		dir inbound(path, nullptr);
		durable_delivery source{};
		source.session_id[0] = 1;
		source.delivery_id = 17;
		source.vmid = 42;
		source.epoch = 99;
		source.program_id[0] = 2;
		source.source_id[0] = 3;
		source.scope = 1;
		source.journal_version = 3;
		assert(inbound.record_delivery(source, delivery_phase::pending, true));
		durable_delivery_state entry{source, delivery_phase::pending};
		/* All source records must exist before the durable rekey fence. */
		source.delivery_id = 19;
		assert(inbound.record_delivery(source, delivery_phase::pending, true));
		assert(inbound.record_delivery(source, delivery_phase::accepted));
		durable_delivery_state renamed{source, delivery_phase::accepted};
		durable_delivery terminal = source;
		terminal.delivery_id = 23;
		assert(inbound.record_delivery(terminal, delivery_phase::pending, true));
		assert(inbound.record_delivery(terminal, delivery_phase::terminal));
		durable_delivery_state terminal_entry{terminal,
		    delivery_phase::terminal};
		auto wrong = entry;
		wrong.record.program_id[0] = 9;
		assert(!inbound.rekey_guest_delivery(wrong, 43, 100));
		assert(errno == EPROTO);
		fail_fsync_number = 1;
		assert(!inbound.rekey_guest_delivery(entry, 43, 100));
		assert(errno == EIO && fail_fsync_number == 0);
		std::vector<durable_delivery_state> pending;
		assert(inbound.list_deliveries(pending) && pending.size() == 3);
		for (const auto &record : pending)
			assert(record.record.vmid == 42);
		/* Crash after marker rename but before its directory fsync. */
		fail_fsync_number = 2;
		assert(!inbound.rekey_guest_delivery(entry, 43, 100));
		assert(errno == EIO && fail_fsync_number == 0);
		source.delivery_id = 21;
		assert(!inbound.record_delivery(source, delivery_phase::pending, true));
		assert(errno == ESTALE);
		{
			dir restarted(path, nullptr);
			assert(restarted.rekey_guest_delivery(entry, 43, 100));
		}
		std::vector<durable_delivery_state> moved;
		assert(inbound.list_deliveries(moved) && moved.size() == 3);
		for (const auto &record : moved)
			assert(record.record.delivery_id == 17 ?
			    record.record.vmid == 43 && record.record.epoch == 100 &&
			    record.phase == delivery_phase::pending :
			    record.record.vmid == 42 &&
			    (record.record.delivery_id == 19 ?
			    record.phase == delivery_phase::accepted :
			    record.record.delivery_id == 23 &&
			    record.phase == delivery_phase::terminal));
		assert(inbound.rekey_guest_delivery(entry, 43, 100));
		/* A stale daemon cannot mint another old-identity record. */
		assert(!inbound.record_delivery(source, delivery_phase::pending, true));
		assert(errno == ESTALE);
		assert(!inbound.retire_terminal_delivery(terminal));
		assert(errno == ESTALE);
		assert(!inbound.rekey_guest_delivery(renamed, 44, 101));
		assert(errno == EPROTO);
		/* A failed directory fsync may follow a completed rename. */
		fail_fsync_number = 3;
		assert(!inbound.rekey_guest_delivery(renamed, 43, 100));
		assert(errno == EIO && fail_fsync_number == 0);
		std::vector<durable_delivery_state> after_rename;
		assert(inbound.list_deliveries(after_rename) &&
		    after_rename.size() == 3);
		assert(inbound.rekey_guest_delivery(renamed, 43, 100));
		assert(inbound.rekey_guest_delivery(terminal_entry, 43, 100));
	}
	remove_directory(path);

	char outbound_path[] = "/tmp/hypertrace-guest-outbound-rekey.XXXXXX";
	assert(mkdtemp(outbound_path) != nullptr);
	{
		dir outbound(outbound_path, nullptr);
		durable_delivery source{};
		source.session_id[0] = 4;
		source.delivery_id = 18;
		source.vmid = 42;
		source.epoch = 99;
		source.program_id[0] = 5;
		source.source_id[0] = 6;
		source.peer_uid = 1000;
		source.peer_pid = 12345;
		source.scope = 2;
		source.journal_version = 4;
		source.payload_digest[0] = 7;
		assert(outbound.record_delivery(source, delivery_phase::pending, true));
		durable_delivery_state entry{source, delivery_phase::pending};
		durable_delivery second = source;
		second.delivery_id = 22;
		second.program_id[0] = 9;
		second.source_id[0] = 10;
		assert(outbound.record_delivery(second, delivery_phase::pending, true));
		assert(outbound.record_delivery(second, delivery_phase::accepted));
		durable_delivery_state second_entry{second,
		    delivery_phase::accepted};
		assert(outbound.rekey_guest_delivery(entry, 43, 100));
		std::vector<durable_delivery_state> moved;
		assert(outbound.list_deliveries(moved) && moved.size() == 2);
		assert(!outbound.retire_accepted_outbound(second));
		assert(errno == ESTALE);
		assert(outbound.rekey_guest_delivery(second_entry, 43, 100));
		/* A new identity-free outbound token is still recoverable; it
		 * cannot be sent while the driver's rekey gate is pending. */
		durable_delivery unbound = source;
		unbound.delivery_id = 27;
		unbound.vmid = 0;
		unbound.epoch = 0;
		unbound.program_id[0] = 11;
		unbound.source_id[0] = 12;
		assert(outbound.record_delivery(unbound, delivery_phase::pending,
		    true));
		assert(outbound.record_delivery(unbound, delivery_phase::accepted));
		assert(outbound.retire_accepted_outbound(unbound));
		source.delivery_id = 21;
		assert(!outbound.record_delivery(source, delivery_phase::pending, true));
		assert(errno == ESTALE);
		entry.record.vmid = 0;
		entry.record.epoch = 0;
		assert(!outbound.rekey_guest_delivery(entry, 43, 100));
		assert(errno == EINVAL);
		/* HTD3 has no payload digest for an exact host receipt check. */
		source.delivery_id = 20;
		source.program_id[0] = 11;
		source.source_id[0] = 12;
		source.journal_version = 3;
		source.payload_digest.fill(0);
		entry = {source, delivery_phase::pending};
		assert(!outbound.rekey_guest_delivery(entry, 43, 100));
		assert(errno == EINVAL);
	}
	remove_directory(outbound_path);

	char duplicate_path[] = "/tmp/hypertrace-guest-phase-duplicate.XXXXXX";
	assert(mkdtemp(duplicate_path) != nullptr);
	{
		dir inbound(duplicate_path, nullptr);
		durable_delivery source{};
		source.session_id[0] = 8;
		source.delivery_id = 23;
		source.vmid = 42;
		source.epoch = 99;
		source.program_id[0] = 9;
		source.source_id[0] = 10;
		source.scope = 1;
		source.journal_version = 3;
		assert(inbound.record_delivery(source, delivery_phase::pending, true));
		DIR *scan = opendir(duplicate_path);
		assert(scan != nullptr);
		char from[MAXPATHLEN] = {}, to[MAXPATHLEN] = {};
		while (struct dirent *file = readdir(scan)) {
			if (strncmp(file->d_name, ".delivery.", 10) != 0)
				continue;
			assert(snprintf(from, sizeof(from), "%s/%s",
			    duplicate_path, file->d_name) < (int)sizeof(from));
			assert(snprintf(to, sizeof(to), "%s/%s",
			    duplicate_path, file->d_name) < (int)sizeof(to));
			to[strlen(to) - 1] = 'a';
			break;
		}
		assert(closedir(scan) == 0 && from[0] != '\0');
		assert(link(from, to) == 0);
		durable_delivery_state entry{source, delivery_phase::pending};
		assert(!inbound.fence_guest_rekey(1, 42, 99, 43, 100));
		assert(errno == EPROTO);
		assert(!inbound.rekey_guest_delivery(entry, 43, 100));
		assert(errno == EPROTO);
		assert(unlink(to) == 0);
		assert(inbound.fence_guest_rekey(1, 42, 99, 43, 100));
		assert(inbound.rekey_guest_delivery(entry, 43, 100));
	}
	remove_directory(duplicate_path);

	char empty_path[] = "/tmp/hypertrace-guest-empty-rekey.XXXXXX";
	assert(mkdtemp(empty_path) != nullptr);
	{
		dir outbound(empty_path, nullptr);
		assert(outbound.fence_guest_rekey(2, 42, 99, 43, 100));
		assert(outbound.fence_guest_rekey(2, 42, 99, 43, 100));
		assert(!outbound.fence_guest_rekey(2, 42, 99, 44, 101));
		assert(errno == EPROTO);
		durable_delivery source{};
		source.session_id[0] = 1;
		source.delivery_id = 28;
		source.vmid = 42;
		source.epoch = 99;
		source.program_id[0] = 2;
		source.source_id[0] = 3;
		source.peer_uid = 1000;
		source.peer_pid = 12345;
		source.scope = 2;
		source.journal_version = 4;
		source.payload_digest[0] = 7;
		assert(!outbound.record_delivery(source, delivery_phase::pending,
		    true));
		assert(errno == ESTALE);
		source.vmid = 43;
		source.epoch = 100;
		assert(outbound.record_delivery(source, delivery_phase::pending,
		    true));
	}
	remove_directory(empty_path);

	char malformed_path[] = "/tmp/hypertrace-guest-rekey-marker.XXXXXX";
	assert(mkdtemp(malformed_path) != nullptr);
	{
		dir inbound(malformed_path, nullptr);
		durable_delivery source{};
		source.session_id[0] = 8;
		source.delivery_id = 24;
		source.vmid = 42;
		source.epoch = 99;
		source.program_id[0] = 9;
		source.source_id[0] = 10;
		source.scope = 1;
		source.journal_version = 3;
		assert(inbound.record_delivery(source, delivery_phase::pending, true));
		char marker[MAXPATHLEN];
		assert(snprintf(marker, sizeof(marker),
		    "%s/.guest-rekey.%04x.%016llx", malformed_path, 42,
		    99ULL) < (int)sizeof(marker));
		assert(mkfifo(marker, 0600) == 0);
		assert(!inbound.record_delivery(source, delivery_phase::accepted));
		assert(errno == EPROTO);
		durable_delivery_state entry{source, delivery_phase::pending};
		assert(!inbound.rekey_guest_delivery(entry, 43, 100));
		assert(errno == EPROTO);
	}
	remove_directory(malformed_path);

	char pair_inbound_path[] = "/tmp/hypertrace-pair-inbound.XXXXXX";
	char pair_outbound_path[] = "/tmp/hypertrace-pair-outbound.XXXXXX";
	assert(mkdtemp(pair_inbound_path) != nullptr);
	assert(mkdtemp(pair_outbound_path) != nullptr);
	{
		dir inbound(pair_inbound_path, nullptr);
		dir outbound(pair_outbound_path, nullptr);
		durable_delivery source{};
		source.session_id[0] = 1;
		source.delivery_id = 30;
		source.vmid = 42;
		source.epoch = 99;
		source.program_id[0] = 2;
		source.source_id[0] = 3;
		source.scope = 1;
		source.journal_version = 3;
		char malformed[MAXPATHLEN];
		assert(snprintf(malformed, sizeof(malformed), "%s/.kill.bad",
		    pair_outbound_path) < (int)sizeof(malformed));
		int fd = open(malformed, O_WRONLY | O_CREAT | O_EXCL, 0600);
		assert(fd >= 0 && close(fd) == 0);
		assert(!inbound.fence_guest_rekey_pair(outbound, 42, 99,
		    43, 100));
		assert(errno == EPROTO);
		/* A bad outbound journal must not fence a healthy inbound one. */
		assert(inbound.record_delivery(source, delivery_phase::pending,
		    true));
		assert(unlink(malformed) == 0);
		assert(!inbound.fence_guest_rekey_pair(inbound, 42, 99,
		    43, 100));
		assert(errno == EINVAL);
		assert(inbound.fence_guest_rekey_pair(outbound, 42, 99,
		    43, 100));
		assert(inbound.fence_guest_rekey_pair(outbound, 42, 99,
		    43, 100));
		source.delivery_id++;
		assert(!inbound.record_delivery(source, delivery_phase::pending,
		    true));
		assert(errno == ESTALE);
		source.scope = 2;
		source.journal_version = 4;
		source.peer_uid = 1000;
		source.peer_pid = 12345;
		source.payload_digest[0] = 7;
		assert(!outbound.record_delivery(source, delivery_phase::pending,
		    true));
		assert(errno == ESTALE);
	}
	remove_directory(pair_inbound_path);
	remove_directory(pair_outbound_path);

	char complete_in_path[] = "/tmp/hypertrace-pair-complete-in.XXXXXX";
	char complete_out_path[] = "/tmp/hypertrace-pair-complete-out.XXXXXX";
	assert(mkdtemp(complete_in_path) != nullptr);
	assert(mkdtemp(complete_out_path) != nullptr);
	{
		dir inbound(complete_in_path, nullptr);
		dir outbound(complete_out_path, nullptr);
		durable_delivery received{};
		received.session_id[0] = 1;
		received.delivery_id = 40;
		received.vmid = 42;
		received.epoch = 99;
		received.program_id[0] = 2;
		received.source_id[0] = 3;
		received.scope = 1;
		received.journal_version = 3;
		assert(inbound.record_delivery(received,
		    delivery_phase::pending, true));
		durable_delivery sent = received;
		sent.delivery_id = 41;
		sent.scope = 2;
		sent.journal_version = 4;
		sent.peer_uid = 1000;
		sent.peer_pid = 12345;
		sent.payload_digest[0] = 7;
		assert(outbound.record_delivery(sent,
		    delivery_phase::pending, true));
		durable_kill kill{};
		kill.pid = 12345;
		kill.vmid = 42;
		kill.epoch = 99;
		kill.source_id[0] = 4;
		assert(inbound.record_kill(kill));
		assert(inbound.record_kill_applied(kill));
		assert(!inbound.guest_rekey_pair_complete(outbound, 42, 99,
		    43, 100) && errno == EBUSY);
		assert(inbound.fence_guest_rekey(1, 42, 99, 43, 100));
		assert(!inbound.guest_rekey_pair_complete(outbound, 42, 99,
		    43, 100) && errno == EBUSY);
		assert(inbound.fence_guest_rekey_pair(outbound, 42, 99,
		    43, 100));
		assert(!inbound.guest_rekey_pair_complete(outbound, 42, 99,
		    43, 100) && errno == EBUSY);
		assert(inbound.rekey_guest_delivery(
		    {received, delivery_phase::pending}, 43, 100));
		assert(inbound.rekey_guest_kills(42, 99, 43, 100));
		assert(!inbound.guest_rekey_pair_complete(outbound, 42, 99,
		    43, 100) && errno == EBUSY);
		assert(outbound.rekey_guest_delivery(
		    {sent, delivery_phase::pending}, 43, 100));
		assert(inbound.guest_rekey_pair_complete(outbound, 42, 99,
		    43, 100));
		kill.vmid = 43;
		kill.epoch = 100;
		assert(inbound.record_kill_applied(kill));
		assert(!inbound.guest_rekey_pair_complete(outbound, 42, 99,
		    43, 100) && errno == EBUSY);
		assert(inbound.rekey_guest_kills(42, 99, 43, 100));
		assert(inbound.guest_rekey_pair_complete(outbound, 42, 99,
		    43, 100));
		durable_delivery unbound = sent;
		unbound.delivery_id = 42;
		unbound.vmid = 0;
		unbound.epoch = 0;
		unbound.program_id[0] = 5;
		unbound.source_id[0] = 6;
		assert(outbound.record_delivery(unbound,
		    delivery_phase::pending, true));
		assert(outbound.record_delivery(unbound,
		    delivery_phase::accepted));
		assert(!inbound.guest_rekey_pair_complete(outbound, 42, 99,
		    43, 100) && errno == EBUSY);
		assert(outbound.retire_accepted_outbound(unbound));
		assert(inbound.guest_rekey_pair_complete(outbound, 42, 99,
		    43, 100));
		char orphan[MAXPATHLEN];
		assert(snprintf(orphan, sizeof(orphan), "%s/.killack.orphan",
		    complete_in_path) < (int)sizeof(orphan));
		int fd = open(orphan, O_WRONLY | O_CREAT | O_EXCL, 0600);
		assert(fd >= 0 && close(fd) == 0);
		assert(!inbound.guest_rekey_pair_complete(outbound, 42, 99,
		    43, 100) && errno == EBUSY);
		assert(unlink(orphan) == 0);
		assert(inbound.guest_rekey_pair_complete(outbound, 42, 99,
		    43, 100));
		assert(outbound.fence_guest_rekey(2, 43, 100, 44, 101));
		assert(!inbound.guest_rekey_pair_complete(outbound, 42, 99,
		    43, 100) && errno == ESTALE);
	}
	remove_directory(complete_in_path);
	remove_directory(complete_out_path);

	char conflict_inbound_path[] = "/tmp/hypertrace-pair-conflict-in.XXXXXX";
	char conflict_outbound_path[] = "/tmp/hypertrace-pair-conflict-out.XXXXXX";
	assert(mkdtemp(conflict_inbound_path) != nullptr);
	assert(mkdtemp(conflict_outbound_path) != nullptr);
	{
		dir inbound(conflict_inbound_path, nullptr);
		dir outbound(conflict_outbound_path, nullptr);
		assert(outbound.fence_guest_rekey(2, 42, 99, 44, 101));
		assert(!inbound.fence_guest_rekey_pair(outbound, 42, 99,
		    43, 100));
		assert(errno == EPROTO);
		durable_delivery source{};
		source.session_id[0] = 1;
		source.delivery_id = 31;
		source.vmid = 42;
		source.epoch = 99;
		source.program_id[0] = 2;
		source.source_id[0] = 3;
		source.scope = 1;
		source.journal_version = 3;
		assert(inbound.record_delivery(source, delivery_phase::pending,
		    true));
	}
	remove_directory(conflict_inbound_path);
	remove_directory(conflict_outbound_path);

	char retired_inbound_path[] = "/tmp/hypertrace-pair-retired-in.XXXXXX";
	char retired_outbound_path[] = "/tmp/hypertrace-pair-retired-out.XXXXXX";
	assert(mkdtemp(retired_inbound_path) != nullptr);
	assert(mkdtemp(retired_outbound_path) != nullptr);
	{
		dir inbound(retired_inbound_path, nullptr);
		dir outbound(retired_outbound_path, nullptr);
		assert(outbound.fence_guest_rekey(2, 42, 99, 43, 100));
		assert(outbound.fence_guest_rekey(2, 43, 100, 44, 101));
		assert(!outbound.fence_guest_rekey(2, 42, 99, 43, 100));
		assert(errno == ESTALE);
		assert(!inbound.fence_guest_rekey_pair(outbound, 42, 99,
		    43, 100));
		assert(errno == ESTALE);
		/* Failed pair preflight did not publish an inbound marker. */
		assert(inbound.fence_guest_rekey(1, 42, 99, 45, 102));
	}
	remove_directory(retired_inbound_path);
	remove_directory(retired_outbound_path);

	char retired_delivery_path[] = "/tmp/hypertrace-delivery-retired.XXXXXX";
	assert(mkdtemp(retired_delivery_path) != nullptr);
	{
		dir inbound(retired_delivery_path, nullptr);
		assert(inbound.fence_guest_rekey(1, 43, 100, 44, 101));
		durable_delivery source{};
		source.session_id[0] = 1;
		source.delivery_id = 33;
		source.vmid = 42;
		source.epoch = 99;
		source.program_id[0] = 2;
		source.source_id[0] = 3;
		source.scope = 1;
		source.journal_version = 3;
		assert(inbound.record_delivery(source, delivery_phase::pending,
		    true));
		durable_delivery_state entry{source, delivery_phase::pending};
		assert(!inbound.rekey_guest_delivery(entry, 43, 100));
		assert(errno == ESTALE);
		assert(inbound.delivery_status(source) ==
		    (int)delivery_phase::pending);
	}
	remove_directory(retired_delivery_path);

	char occupied_path[] = "/tmp/hypertrace-delivery-occupied.XXXXXX";
	assert(mkdtemp(occupied_path) != nullptr);
	{
		dir inbound(occupied_path, nullptr);
		durable_delivery destination{};
		destination.session_id[0] = 1;
		destination.delivery_id = 34;
		destination.vmid = 43;
		destination.epoch = 100;
		destination.program_id[0] = 2;
		destination.source_id[0] = 3;
		destination.scope = 1;
		destination.journal_version = 3;
		assert(inbound.record_delivery(destination,
		    delivery_phase::pending, true));
		durable_delivery source = destination;
		source.vmid = 42;
		source.epoch = 99;
		assert(!inbound.rekey_guest_delivery(
		    {source, delivery_phase::pending}, 43, 100));
		assert(errno == ESTALE);
		assert(!inbound.fence_guest_rekey(1, 42, 99, 43, 100));
		assert(errno == ESTALE);
	}
	remove_directory(occupied_path);

	char occupied_pair_in[] = "/tmp/hypertrace-pair-occupied-in.XXXXXX";
	char occupied_pair_out[] = "/tmp/hypertrace-pair-occupied-out.XXXXXX";
	assert(mkdtemp(occupied_pair_in) != nullptr);
	assert(mkdtemp(occupied_pair_out) != nullptr);
	{
		dir inbound(occupied_pair_in, nullptr);
		dir outbound(occupied_pair_out, nullptr);
		durable_delivery destination{};
		destination.session_id[0] = 1;
		destination.delivery_id = 35;
		destination.vmid = 43;
		destination.epoch = 100;
		destination.program_id[0] = 2;
		destination.source_id[0] = 3;
		destination.scope = 1;
		destination.journal_version = 3;
		assert(inbound.record_delivery(destination,
		    delivery_phase::pending, true));
		assert(!inbound.fence_guest_rekey_pair(outbound, 42, 99,
		    43, 100));
		assert(errno == ESTALE);
		durable_delivery source = destination;
		source.delivery_id++;
		source.vmid = 42;
		source.epoch = 99;
		assert(inbound.record_delivery(source,
		    delivery_phase::pending, true));
	}
	remove_directory(occupied_pair_in);
	remove_directory(occupied_pair_out);

	char retry_inbound_path[] = "/tmp/hypertrace-pair-retry-in.XXXXXX";
	char retry_outbound_path[] = "/tmp/hypertrace-pair-retry-out.XXXXXX";
	assert(mkdtemp(retry_inbound_path) != nullptr);
	assert(mkdtemp(retry_outbound_path) != nullptr);
	{
		dir inbound(retry_inbound_path, nullptr);
		dir outbound(retry_outbound_path, nullptr);
		fail_fsync_number = 3; /* Outbound marker file fsync. */
		assert(!inbound.fence_guest_rekey_pair(outbound, 42, 99,
		    43, 100));
		assert(errno == EIO && fail_fsync_number == 0);
		durable_delivery source{};
		source.session_id[0] = 1;
		source.delivery_id = 32;
		source.vmid = 42;
		source.epoch = 99;
		source.program_id[0] = 2;
		source.source_id[0] = 3;
		source.scope = 1;
		source.journal_version = 3;
		assert(!inbound.record_delivery(source, delivery_phase::pending,
		    true));
		assert(errno == ESTALE);
		assert(inbound.fence_guest_rekey_pair(outbound, 42, 99,
		    43, 100));
		assert(inbound.fence_guest_rekey_pair(outbound, 42, 99,
		    43, 100));
	}
	remove_directory(retry_inbound_path);
	remove_directory(retry_outbound_path);

	char overlap_path[] = "/tmp/hypertrace-guest-delivery-overlap.XXXXXX";
	assert(mkdtemp(overlap_path) != nullptr);
	{
		dir journal(overlap_path, nullptr);
		durable_delivery inbound{};
		inbound.session_id[0] = 1;
		inbound.delivery_id = 25;
		inbound.vmid = 42;
		inbound.epoch = 99;
		inbound.program_id[0] = 2;
		inbound.source_id[0] = 3;
		inbound.scope = 1;
		inbound.journal_version = 3;
		assert(journal.record_delivery(inbound, delivery_phase::pending,
		    true));
		assert_rekey_lock_blocks(overlap_path, inbound,
		    guest_mutation::transition);
		assert(journal.record_delivery(inbound, delivery_phase::terminal));
		assert_rekey_lock_blocks(overlap_path, inbound,
		    guest_mutation::retire_inbound);
		durable_delivery outbound = inbound;
		outbound.delivery_id = 26;
		outbound.scope = 2;
		outbound.journal_version = 4;
		outbound.peer_uid = 1000;
		outbound.peer_pid = 12345;
		outbound.payload_digest[0] = 7;
		assert(journal.record_delivery(outbound, delivery_phase::pending,
		    true));
		assert_rekey_lock_blocks(overlap_path, outbound,
		    guest_mutation::transition);
		assert_rekey_lock_blocks(overlap_path, outbound,
		    guest_mutation::retire_outbound);
	}
	remove_directory(overlap_path);

	char transaction_in[] = "/tmp/hypertrace-rekey-transaction-in.XXXXXX";
	char transaction_out[] = "/tmp/hypertrace-rekey-transaction-out.XXXXXX";
	assert(mkdtemp(transaction_in) != nullptr);
	assert(mkdtemp(transaction_out) != nullptr);
	{
		auto inbound = std::make_unique<dir>(transaction_in, nullptr);
		auto outbound = std::make_unique<dir>(transaction_out, nullptr);
		durable_delivery incoming{};
		incoming.session_id[0] = 1;
		incoming.delivery_id = 42;
		incoming.vmid = 42;
		incoming.epoch = 99;
		incoming.program_id[0] = 2;
		incoming.source_id[0] = 3;
		incoming.scope = 1;
		incoming.journal_version = 3;
		assert(inbound->record_delivery(incoming,
		    delivery_phase::pending, true));
		durable_delivery outgoing = incoming;
		outgoing.delivery_id = 43;
		outgoing.scope = 2;
		outgoing.journal_version = 4;
		outgoing.peer_uid = 1000;
		outgoing.peer_pid = 12345;
		outgoing.payload_digest[0] = 7;
		assert(outbound->record_delivery(outgoing,
		    delivery_phase::pending, true));
		durable_kill kill{123, 42, 99, {}};
		kill.source_id[0] = 3;
		assert(inbound->record_kill(kill));
		bool authorize_outbound = false, authorize_kill = false;
		int inbound_checked = 0, outbound_checked = 0,
		    kills_checked = 0;
		auto inbound_receipt = [&](const durable_delivery_state &entry) {
			++inbound_checked;
			return (entry.record.scope == 1 &&
			    entry.record.vmid == 42 && entry.record.epoch == 99 &&
			    entry.record.delivery_id == 42);
		};
		auto outbound_receipt = [&](const durable_delivery_state &entry) {
			++outbound_checked;
			return (authorize_outbound && entry.record.scope == 2 &&
			    entry.record.vmid == 42 && entry.record.epoch == 99 &&
			    entry.record.delivery_id == 43 &&
			    entry.record.payload_digest[0] == 7);
		};
		auto kill_receipt = [&](const durable_kill &entry) {
			++kills_checked;
			return (authorize_kill && entry.vmid == 42 && entry.epoch == 99 &&
			    entry.pid == 123 && entry.source_id[0] == 3);
		};
		auto check_old_identity = [&]() {
			std::vector<durable_delivery_state> pending;
			std::vector<durable_kill> saved_kills;
			assert(inbound->list_deliveries(pending) && pending.size() == 1 &&
			    pending[0].record.vmid == 42 &&
			    pending[0].record.epoch == 99);
			pending.clear();
			assert(outbound->list_deliveries(pending) && pending.size() == 1 &&
			    pending[0].record.vmid == 42 &&
			    pending[0].record.epoch == 99);
			assert(inbound->list_kills(saved_kills) &&
			    saved_kills.size() == 1 && saved_kills[0].vmid == 42 &&
			    saved_kills[0].epoch == 99);
		};
		assert(!inbound->rekey_guest_journals_with_receipts(*outbound,
		    42, 99, 43, 100, inbound_receipt, outbound_receipt,
		    kill_receipt));
		assert(errno == EACCES);
		assert(inbound_checked == 1 && outbound_checked == 1 &&
		    kills_checked == 0);
		check_old_identity();
		assert(!inbound->guest_rekey_pair_complete(*outbound,
		    42, 99, 43, 100));
		inbound.reset();
		outbound.reset();
		inbound = std::make_unique<dir>(transaction_in, nullptr);
		outbound = std::make_unique<dir>(transaction_out, nullptr);
		authorize_outbound = true;
		assert(!inbound->rekey_guest_journals_with_receipts(*outbound,
		    42, 99, 43, 100, inbound_receipt, outbound_receipt,
		    kill_receipt));
		assert(errno == EACCES);
		check_old_identity();
		authorize_kill = true;
		assert(inbound->rekey_guest_journals_with_receipts(*outbound,
		    42, 99, 43, 100, inbound_receipt, outbound_receipt,
		    kill_receipt));
		assert(inbound->guest_rekey_pair_complete(*outbound,
		    42, 99, 43, 100));
		assert(inbound->rekey_guest_journals_with_receipts(*outbound,
		    42, 99, 43, 100, inbound_receipt, outbound_receipt,
		    kill_receipt));
		assert(inbound_checked == 4 && outbound_checked == 4 &&
		    kills_checked == 3);
		assert(!inbound->rekey_guest_journals_with_receipts(*outbound,
		    42, 99, 43, 100, {}, outbound_receipt, kill_receipt));
		assert(errno == EINVAL);
	}
	remove_directory(transaction_in);
	remove_directory(transaction_out);
	char v4_in[] = "/tmp/hypertrace-rekey-v4-in.XXXXXX";
	char v4_out[] = "/tmp/hypertrace-rekey-v4-out.XXXXXX";
	assert(mkdtemp(v4_in) != nullptr && mkdtemp(v4_out) != nullptr);
	{
		dir inbound(v4_in, nullptr), outbound(v4_out, nullptr);
		durable_delivery incoming{};
		incoming.session_id[0] = 1;
		incoming.delivery_id = 72;
		incoming.vmid = 42;
		incoming.epoch = 99;
		incoming.program_id[0] = 2;
		incoming.source_id[0] = 3;
		incoming.scope = 1;
		incoming.journal_version = 4;
		incoming.payload_digest[0] = 9;
		assert(inbound.record_delivery(incoming,
		    delivery_phase::pending, true));
		assert(inbound.record_delivery(incoming,
		    delivery_phase::accepted));
		durable_delivery terminal = incoming;
		terminal.delivery_id = 73;
		terminal.payload_digest[0] = 10;
		assert(inbound.record_delivery(terminal,
		    delivery_phase::pending, true));
		assert(inbound.record_delivery(terminal,
		    delivery_phase::terminal));
		bool authorize_terminal = false;
		int terminal_checks = 0;
		auto receipt = [&](const durable_delivery_state &entry) {
			if (entry.record.journal_version != 4 ||
			    entry.record.vmid != 42 || entry.record.epoch != 99)
				return (false);
			if (entry.record.delivery_id == 72)
				return (entry.phase == delivery_phase::accepted &&
				    entry.record.payload_digest[0] == 9);
			++terminal_checks;
			if (entry.record.delivery_id != 73 ||
			    entry.phase != delivery_phase::terminal ||
			    entry.record.payload_digest[0] != 10)
				return (false);
			if (!authorize_terminal) {
				errno = EACCES;
				return (false);
			}
			return (true);
		};
		auto none_delivery = [](const durable_delivery_state &) {
			return (false);
		};
		auto none_kill = [](const durable_kill &) { return (false); };
		assert(!inbound.rekey_guest_journals_with_receipts(outbound,
		    42, 99, 43, 100, receipt, none_delivery, none_kill));
		assert(errno == EACCES && terminal_checks == 1);
		authorize_terminal = true;
		/* Reopen both journals to model the daemon restarting after
		 * one receipt failed following the durable pair fence. */
		dir restarted_inbound(v4_in, nullptr);
		dir restarted_outbound(v4_out, nullptr);
		assert(restarted_inbound.rekey_guest_journals_with_receipts(
		    restarted_outbound,
		    42, 99, 43, 100, receipt, none_delivery, none_kill));
		std::vector<durable_delivery_state> migrated;
		assert(restarted_inbound.list_deliveries(migrated) &&
		    migrated.size() == 2 && terminal_checks == 2);
		bool saw_accepted = false, saw_terminal = false;
		for (const auto &entry : migrated) {
			assert(entry.record.vmid == 43 &&
			    entry.record.epoch == 100);
			if (entry.record.delivery_id == 72) {
				assert(entry.phase == delivery_phase::accepted &&
				    entry.record.payload_digest[0] == 9);
				saw_accepted = true;
			} else {
				assert(entry.record.delivery_id == 73 &&
				    entry.phase == delivery_phase::terminal &&
				    entry.record.payload_digest[0] == 10);
				saw_terminal = true;
			}
		}
		assert(saw_accepted && saw_terminal);
	}
	remove_directory(v4_in);
	remove_directory(v4_out);
	puts("PASS: guest delivery rekey survives restart and fences concurrent and stale writers");
}
