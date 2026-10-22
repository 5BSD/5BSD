/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/stat.h>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include "dtraced_directory.h"

using namespace dtraced;

int main()
{
	char path[] = "/tmp/hypertrace-fresh-directory.XXXXXX";
	assert(mkdtemp(path) != nullptr);
	dir parent(path, nullptr);
	int old = openat(parent.dirfd, "old-journal", O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(old >= 0 && write(old, "old", 3) == 3 && close(old) == 0);
	assert(!parent.fresh_empty_session(0, 7) && errno == EINVAL);
	assert(!parent.fresh_empty_session(1, 0) && errno == EINVAL);
	auto fresh = parent.fresh_empty_session(1, 7);
	assert(fresh && !fresh->file_exists("old-journal"));
	struct stat first, again;
	assert(fstat(fresh->dirfd, &first) == 0);
	assert((first.st_mode & 0777) == 0700);
	auto retry = parent.fresh_empty_session(1, 7);
	assert(retry && fstat(retry->dirfd, &again) == 0 && first.st_ino == again.st_ino);
	int work = openat(fresh->dirfd, "queued", O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(work >= 0 && close(work) == 0);
	assert(!parent.fresh_empty_session(1, 7) && errno == EEXIST);
	auto recovered = parent.existing_session(1, 7);
	assert(recovered && recovered->file_exists("queued") &&
	    !recovered->file_exists("old-journal"));
	assert(!parent.existing_session(1, 99) && errno == ENOENT);
	auto next = parent.fresh_empty_session(1, 8);
	assert(next && !next->file_exists("queued") && !next->file_exists("old-journal"));
	assert(symlinkat(".session.0001.0000000000000007", parent.dirfd,
	    ".session.0001.0000000000000009") == 0);
	assert(!parent.fresh_empty_session(1, 9));
	assert(fchmod(next->dirfd, 0755) == 0);
	assert(!parent.fresh_empty_session(1, 8) && errno == EPERM);
	assert(fchmod(next->dirfd, 0700) == 0);
	assert(fchmod(parent.dirfd, 0755) == 0);
	assert(!parent.fresh_empty_session(1, 10) && errno == EPERM);
	assert(fchmod(parent.dirfd, 0700) == 0);
	assert(parent.file_exists("old-journal"));
	assert(unlinkat(fresh->dirfd, "queued", 0) == 0);
	fresh.reset(); retry.reset(); next.reset(); recovered.reset();
	assert(unlinkat(parent.dirfd, ".session.0001.0000000000000007", AT_REMOVEDIR) == 0);
	assert(unlinkat(parent.dirfd, ".session.0001.0000000000000008", AT_REMOVEDIR) == 0);
	assert(unlinkat(parent.dirfd, ".session.0001.0000000000000009", 0) == 0);
	assert(unlinkat(parent.dirfd, "old-journal", 0) == 0);
	assert(rmdir(path) == 0);
}
