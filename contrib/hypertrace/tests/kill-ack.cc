/* SPDX-License-Identifier: BSD-2-Clause */
#include <dttransport.h>
#include <sys/socket.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <thread>
#include <vector>
#include <unistd.h>
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_state.h"

using namespace dtraced;

int
main()
{
	alarm(10);
	char path[] = "/tmp/hypertrace-kill-ack.XXXXXX";
	assert(mkdtemp(path) != nullptr);
	dir inbound(path, nullptr);
	int fd[2];
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
	assert(fcntl(fd[0], F_SETFL, O_NONBLOCK) == 0);
	state guest{};
	guest.inbounddir = &inbound;
	guest.dtt_fd = fd[0];
	std::thread listener(listen_dttransport, &guest);
	dtt_entry_t kill{};
	kill.event_kind = DTT_KILL;
	kill.u.kill.pid = 12345;
	kill.u.kill.vmid = 42;
	kill.u.kill.epoch = 99;
	kill.u.kill.source_id[0] = 0x42;
	assert(write(fd[1], &kill, sizeof(kill)) == sizeof(kill));
	struct pollfd pending{fd[1], POLLIN, 0};
	assert(poll(&pending, 1, 2000) == 1);
	dtt_entry_t ack{};
	assert(read(fd[1], &ack, sizeof(ack)) == sizeof(ack));
	assert(ack.event_kind == DTT_KILL_APPLIED &&
	    ack.u.kill.pid == kill.u.kill.pid &&
	    ack.u.kill.vmid == kill.u.kill.vmid &&
	    ack.u.kill.epoch == kill.u.kill.epoch &&
	    memcmp(ack.u.kill.source_id, kill.u.kill.source_id, 16) == 0);
	durable_kill record{};
	record.pid = kill.u.kill.pid;
	record.vmid = kill.u.kill.vmid;
	record.epoch = kill.u.kill.epoch;
	memcpy(record.source_id.data(), kill.u.kill.source_id, 16);
	assert(inbound.kill_applied(record) == 0);
	ack.event_kind = DTT_HOST_KILL_APPLIED;
	assert(write(fd[1], &ack, sizeof(ack)) == sizeof(ack));
	auto deadline = std::chrono::steady_clock::now() +
	    std::chrono::seconds(2);
	while (inbound.kill_applied(record) != 1 &&
	    std::chrono::steady_clock::now() < deadline)
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	assert(inbound.kill_applied(record) == 1);
	/* A host reconnect can replay its durable KILL, but a locally
	 * confirmed record must not reopen ACK traffic. */
	assert(write(fd[1], &kill, sizeof(kill)) == sizeof(kill));
	assert(poll(&pending, 1, 50) == 0);
	dtt_entry_t unconfirmed = kill;
	unconfirmed.u.kill.pid = 12346;
	unconfirmed.u.kill.source_id[0] = 0x43;
	assert(write(fd[1], &unconfirmed, sizeof(unconfirmed)) ==
	    sizeof(unconfirmed));
	assert(poll(&pending, 1, 2000) == 1);
	dtt_entry_t retry{};
	assert(read(fd[1], &retry, sizeof(retry)) == sizeof(retry));
	assert(retry.event_kind == DTT_KILL_APPLIED &&
	    retry.u.kill.pid == unconfirmed.u.kill.pid &&
	    retry.u.kill.source_id[0] == 0x43);
	guest.shutdown.store(1);
	listener.join();
	assert(inbound.source_revoked(record.source_id.data()) == 1);
	std::vector<durable_kill> recovered;
	assert(inbound.list_kills(recovered) && recovered.size() == 2);
	assert(fcntl(fd[1], F_SETFL, O_NONBLOCK) == 0);
	while (read(fd[1], &ack, sizeof(ack)) == sizeof(ack))
		assert(ack.event_kind == DTT_KILL_APPLIED);
	state restarted{};
	restarted.inbounddir = &inbound;
	restarted.dtt_fd = fd[0];
	std::thread recovery(listen_dttransport, &restarted);
	assert(poll(&pending, 1, 2000) == 1);
	assert(read(fd[1], &retry, sizeof(retry)) == sizeof(retry));
	assert(retry.event_kind == DTT_KILL_APPLIED &&
	    retry.u.kill.pid == unconfirmed.u.kill.pid &&
	    retry.u.kill.source_id[0] == 0x43);
	assert(poll(&pending, 1, 50) == 0);
	restarted.shutdown.store(1);
	recovery.join();
	close(fd[0]);
	close(fd[1]);
	DIR *entries = opendir(path);
	assert(entries != nullptr);
	while (struct dirent *entry = readdir(entries))
		if (strcmp(entry->d_name, ".") != 0 &&
		    strcmp(entry->d_name, "..") != 0)
			assert(unlinkat(inbound.dirfd, entry->d_name, 0) == 0);
	assert(closedir(entries) == 0);
	assert(rmdir(path) == 0);
	puts("PASS: guest kill ACK persists; restart replays only unconfirmed kills");
}
