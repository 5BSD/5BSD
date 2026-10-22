/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/hypertrace.h>
#include <sys/ioctl.h>
#include <amd64/include/vmm_dev.h>
#include <atomic>
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <thread>
#include <unistd.h>

#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_io.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
#include "dtraced_wire.h"

using namespace dtraced;

namespace dtraced {
struct state_attestation_test {
	static void setup(state &s, int listener, int kq, dir &journal)
	{
		s.ctrlmachine = 1;
		s.sockfd = listener;
		s.kq_hdl = kq;
		s.outbounddir = &journal;
	}
	static client_fd *accepted(state &s)
	{
		assert(s.sockfds.size() == 1);
		return (*s.sockfds.begin());
	}
	static job *take_replay(state &s)
	{
		std::lock_guard jobs(s.joblistmtx);
		if (s.joblist.empty())
			return (nullptr);
		job *item = s.joblist.front();
		s.joblist.pop_front();
		return (item);
	}
	static void remove(state &s, client_fd *client)
	{
		s.client_events.remove(client->event_cookie);
		s.sockfds.erase(client);
	}
};
}

extern "C" int
__wrap_ioctl(int fd __unused, unsigned long request, ...)
{
	if (request != VM_GET_ATTESTATION) {
		errno = ENOTTY;
		return (-1);
	}
	va_list args;
	va_start(args, request);
	void *output = va_arg(args, void *);
	va_end(args);
	hypertrace_vm_attestation attestation{};
	attestation.vmid = 8;
	attestation.epoch = 22;
	strlcpy(attestation.name, "admit-vm", sizeof(attestation.name));
	memcpy(output, &attestation, sizeof(attestation));
	return (0);
}

int
main()
{
	alarm(10);
	char path[] = "/tmp/hypertrace-admission-replay.XXXXXX";
	assert(mkdtemp(path) != nullptr);
	{
		dir journal(path, nullptr);
		durable_kill kill{123, 8, 22, {}};
		kill.source_id[0] = 0x55;
		assert(journal.record_kill(kill));
		char socket_path[sizeof(sockaddr_un::sun_path)];
		assert(snprintf(socket_path, sizeof(socket_path), "%s/sub.sock",
		    path) < (int)sizeof(socket_path));
		sockaddr_un address{};
		address.sun_family = AF_UNIX;
		strlcpy(address.sun_path, socket_path, sizeof(address.sun_path));
		int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		int kq = kqueue();
		assert(listener >= 0 && kq >= 0);
		assert(bind(listener, (sockaddr *)&address, sizeof(address)) == 0);
		assert(listen(listener, 1) == 0);
		state host{};
		state_attestation_test::setup(host, listener, kq, journal);
		std::atomic_bool admitted{false}, sent{false};
		std::thread client([&] {
			int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
			assert(fd >= 0);
			assert(connect(fd, (sockaddr *)&address,
			    sizeof(address)) == 0);
			dtd_initmsg_t hello{};
			size_t transferred;
			int64_t deadline = dtraced_io_milliseconds() + 4000;
			assert(dtraced_io_transfer(fd, &hello, sizeof(hello),
			    false, deadline, &transferred) == 0);
			assert(hello.kind == DTRACED_KIND_DTRACED);
			hello = {};
			hello.kind = DTRACED_KIND_FORWARDER;
			hello.protocol_version = DTRACED_PROTOCOL_VERSION;
			hello.subs = DTD_SUB_ELFWRITE | DTD_SUB_KILL |
			    DTD_SUB_ADMISSION_ACK;
			hello.session_id[0] = 0x42;
			strlcpy(hello.ident, "admit-vm", sizeof(hello.ident));
			assert(dtraced_io_transfer(fd, &hello, sizeof(hello), true,
			    deadline, &transferred) == 0);
			int attestation = open("/dev/null", O_RDONLY | O_CLOEXEC);
			assert(attestation >= 0);
			assert(dtraced_io_send_fd(fd, attestation, deadline) == 0);
			close(attestation);
			uint8_t ack = 0;
			assert(dtraced_io_transfer(fd, &ack, sizeof(ack), false,
			    deadline, &transferred) == 0 && ack == 1);
			admitted.store(true);
			dtraced_hdr_t frame{};
			assert(dtraced_io_transfer(fd, &frame, sizeof(frame), false,
			    deadline, &transferred) == 0);
			assert(frame.msg_type == DTRACED_MSG_KILL &&
			    frame.kill.pid == 123 && frame.kill.vmid == 8 &&
			    frame.kill.epoch == 22 && frame.kill.source_id[0] == 0x55);
			close(fd);
		});
		std::thread worker([&] {
			job *item;
			while ((item = state_attestation_test::take_replay(host)) ==
			    nullptr)
				usleep(1000);
			assert(item->kind == KILL);
			assert(item->send_kill(host));
			delete item;
			sent.store(true);
		});
		assert(host.accept_new_connection());
		worker.join();
		client.join();
		assert(admitted.load() && sent.load());
		client_fd *accepted = state_attestation_test::accepted(host);
		state_attestation_test::remove(host, accepted);
		delete accepted;
		/* Create the smaller PID second: filesystem enumeration order must
		 * not decide the manifest bytes on either admission or reconnect. */
		durable_kill earlier{122, 8, 22, {}};
		earlier.source_id[0] = 0x54;
		assert(journal.record_kill(earlier));
		for (unsigned attempt = 0; attempt < 2; ++attempt) {
			std::thread manifest_client([&] {
				int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
				assert(fd >= 0 && connect(fd, (sockaddr *)&address,
				    sizeof(address)) == 0);
				dtd_initmsg_t hello{};
				size_t transferred;
				int64_t deadline = dtraced_io_milliseconds() + 4000;
				assert(dtraced_wire_read_init(fd, &hello, deadline,
				    &transferred) == 0);
				hello = {};
				hello.kind = DTRACED_KIND_FORWARDER;
				hello.protocol_version = DTRACED_PROTOCOL_VERSION;
				hello.subs = DTD_SUB_ELFWRITE | DTD_SUB_KILL |
				    DTD_SUB_ADMISSION_ACK | DTD_SUB_REPLAY_MANIFEST;
				hello.session_id[0] = 0x43 + attempt;
				strlcpy(hello.ident, "admit-vm", sizeof(hello.ident));
				assert(dtraced_wire_write_init(fd, &hello, deadline,
				    &transferred) == 0);
				int attestation = open("/dev/null", O_RDONLY | O_CLOEXEC);
				assert(attestation >= 0);
				assert(dtraced_io_send_fd(fd, attestation, deadline) == 0);
				close(attestation);
				uint8_t ack = 0, count_wire[4], kill_wire[32];
				assert(dtraced_io_transfer(fd, &ack, 1, false, deadline,
				    &transferred) == 0 && ack == 1);
				assert(dtraced_io_transfer(fd, count_wire,
				    sizeof(count_wire), false, deadline, &transferred) == 0 &&
				    dtraced_wire_get_u32(count_wire) == 2);
				for (unsigned i = 0; i < 2; ++i) {
					assert(dtraced_io_transfer(fd, kill_wire,
					    sizeof(kill_wire), false, deadline,
					    &transferred) == 0);
					dtraced_replay_kill_t replay{};
					assert(dtraced_wire_decode_replay_kill(&replay,
					    kill_wire) == 0 && replay.pid == 122 + (int)i &&
					    replay.vmid == 8 && replay.epoch == 22 &&
					    replay.source_id[0] == 0x54 + i);
				}
				close(fd);
			});
			assert(host.accept_new_connection());
			manifest_client.join();
			assert(host.joblist.empty());
			accepted = state_attestation_test::accepted(host);
			state_attestation_test::remove(host, accepted);
			delete accepted;
		}
		close(listener);
		close(kq);
		assert(unlink(socket_path) == 0);
		DIR *scan = opendir(path);
		assert(scan != nullptr);
		for (dirent *entry; (entry = readdir(scan)) != nullptr; )
			if (strcmp(entry->d_name, ".") != 0 &&
			    strcmp(entry->d_name, "..") != 0)
				assert(unlinkat(journal.dirfd, entry->d_name, 0) == 0);
		assert(closedir(scan) == 0);
	}
	assert(rmdir(path) == 0);
	puts("PASS: attested admission ACK and bounded replay manifest");
}
