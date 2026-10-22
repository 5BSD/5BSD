/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>
#include <sys/socket.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
using namespace dtraced;

int main()
{
	char path[] = "/tmp/hypertrace-outbound-admission.XXXXXX";
	assert(mkdtemp(path) != nullptr);
	const char *name =
	    "elf.77777777777777777777777777777777.88000000000000000000000000000000";
	{
		state s{};
		dir outbound(path, &process_outbound);
		outbound.state = &s;
		s.outbounddir = &outbound;
		int fd = openat(outbound.dirfd, name, O_CREAT | O_WRONLY, 0600);
		assert(fd >= 0 && write(fd, "\177ELF", 4) == 4);
		assert(close(fd) == 0);
		struct dirent file{};
		assert(strlcpy(file.d_name, name, sizeof(file.d_name)) <
		    sizeof(file.d_name));
		assert(process_outbound(outbound, &file));
		assert(!outbound.memorized(name) && s.joblist.empty());

		int sv[2];
		assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
		int kq = kqueue();
		assert(kq >= 0);
		dtd_initmsg_t hello{};
		hello.kind = DTRACED_KIND_FORWARDER;
		hello.subs = DTD_SUB_ELFWRITE;
		{
			client_fd forwarder(kq, sv[0], hello);
			assert(forwarder.enable_write(&forwarder));
			s.sockfds.insert(&forwarder);
			assert(process_outbound(outbound, &file));
			assert(outbound.memorized(name) && s.joblist.size() == 1);
			for (job *pending : s.joblist)
				delete pending;
			s.joblist.clear();
			s.sockfds.clear();
		}
		close(sv[1]);
		close(kq);
		assert(unlinkat(outbound.dirfd, name, 0) == 0);
	}
	assert(rmdir(path) == 0);
	puts("PASS: live outbound ELF waits for a forwarder without restart replay");
}
