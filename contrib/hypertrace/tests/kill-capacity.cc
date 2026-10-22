/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/stat.h>

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>

#include "dtraced_directory.h"

using namespace dtraced;

int
main()
{
	alarm(45);
	char path[] = "/tmp/hypertrace-kill-capacity.XXXXXX";
	assert(mkdtemp(path) != nullptr);
	{
		dir journal(path, nullptr);
		char name[70];
		for (unsigned pid = 2; pid < 16386; ++pid) {
			int length = snprintf(name, sizeof(name),
			    ".kill.0007.0000000000000009.%08x."
			    "55000000000000000000000000000000", pid);
			assert(length == 69);
			int fd = openat(journal.dirfd, name,
			    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
			assert(fd >= 0);
			assert(close(fd) == 0);
		}
		std::vector<durable_kill> recovered;
		assert(journal.list_kills(recovered) && recovered.size() == 16384);
		durable_kill duplicate{};
		duplicate.pid = 2;
		duplicate.vmid = 7;
		duplicate.epoch = 9;
		duplicate.source_id[0] = 0x55;
		assert(journal.record_kill(duplicate));
		assert(journal.kill_applied(duplicate) == 0);
		assert(journal.record_kill_applied(duplicate));
		assert(journal.record_kill_applied(duplicate));
		assert(journal.kill_applied(duplicate) == 1);
		duplicate.pid = 16386;
		assert(!journal.record_kill_applied(duplicate) && errno == ENOENT);
		assert(!journal.record_kill(duplicate) && errno == ENOSPC);
		assert(journal.source_revoked_for_vm(
		    duplicate.source_id.data(), 7, 9) == 1);
		int length = snprintf(name, sizeof(name),
		    ".kill.0007.0000000000000009.%08x."
		    "55000000000000000000000000000000", 16386);
		assert(length == 69);
		int fd = openat(journal.dirfd, name,
		    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
		assert(fd >= 0 && close(fd) == 0);
		recovered.clear();
		assert(!journal.list_kills(recovered) && errno == ENOSPC &&
		    recovered.empty());
		assert(journal.source_revoked_for_vm(
		    duplicate.source_id.data(), 7, 9) == -1 && errno == ENOSPC);
		int scanfd = openat(journal.dirfd, ".", O_RDONLY | O_DIRECTORY);
		assert(scanfd >= 0);
		DIR *scan = fdopendir(scanfd);
		assert(scan != nullptr);
		for (dirent *entry; (entry = readdir(scan)) != nullptr; ) {
			if (entry->d_name[0] == '.') {
				if (strncmp(entry->d_name, ".kill.", 6) != 0 &&
				    strncmp(entry->d_name, ".killack.", 9) != 0 &&
				    strcmp(entry->d_name, ".handoff.lock") != 0)
					continue;
			}
			assert(unlinkat(journal.dirfd, entry->d_name, 0) == 0);
		}
		assert(closedir(scan) == 0);
	}
	assert(rmdir(path) == 0);
	puts("PASS: durable kill cap and exact duplicate at capacity");
	return (0);
}
