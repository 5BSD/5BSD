/* SPDX-License-Identifier: BSD-2-Clause */
/* Run inside the real Capsule guest, after its manager has launched rc. */
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "storage_test.h"

#define CHECK(name, test) do { \
	if (!(test)) { \
		printf("STORAGE_FAIL %s line=%d errno=%d\n", name, __LINE__, errno); \
		return (1); \
	} \
	printf("STORAGE_CHECK %s\n", name); \
} while (0)

static int
ordinary_programs(void)
{
	gid_t group = 65534;
	char shell[] = "sh", options[] = "-eu";
	char script[] = "/etc/security-programs.sh";
	char path[] = "PATH=/bin:/usr/bin", locale[] = "LC_ALL=C";
	char temporary[] = "TMPDIR=/tmp", home[] = "HOME=/nonexistent";
	char *const arguments[] = {shell, options, script, NULL};
	char *const environment[] = {path, locale, temporary, home, NULL};

	CHECK("drop-groups", setgroups(1, &group) == 0);
	CHECK("drop-gid", setgid(group) == 0);
	CHECK("drop-uid", setuid(65534) == 0);
	CHECK("unprivileged", getuid() == 65534 && geteuid() == 65534);
	CHECK("root-not-recoverable", setuid(0) == -1 && errno == EPERM);
	execve("/bin/sh", arguments, environment);
	perror("ordinary programs exec");
	return (1);
}

int
storage_test(void)
{
	struct statfs root, temporary;
	struct stat st;
	char buffer[16384], directory[] = "/tmp/integrity.XXXXXXXX";
	char target[PATH_MAX], alias[PATH_MAX];
	ssize_t count;
	pid_t child;
	int source, dest, status;
	void *mapping;

	CHECK("root-readonly", statfs("/", &root) == 0 &&
	    (root.f_flags & MNT_RDONLY) != 0);
	CHECK("tmp-separate", statfs("/tmp", &temporary) == 0 &&
	    memcmp(&root.f_fsid, &temporary.f_fsid, sizeof(root.f_fsid)) != 0);
	CHECK("tmp-flags", strcmp(temporary.f_fstypename, "tmpfs") == 0 &&
	    (temporary.f_flags & (MNT_RDONLY | MNT_NOEXEC | MNT_NOSUID)) ==
	    (MNT_NOEXEC | MNT_NOSUID));
	CHECK("tmp-bound", temporary.f_bsize > 0 && temporary.f_blocks > 0 &&
	    (uint64_t)temporary.f_blocks * temporary.f_bsize <= 64 * 1024 * 1024);
	CHECK("tmp-mode", stat("/tmp", &st) == 0 && st.st_uid == 0 &&
	    (st.st_mode & 07777) == 01777);
	CHECK("root-unmount-denied", unmount("/tmp", MNT_FORCE) == -1 &&
	    errno == EPERM);
	CHECK("root-scratch", mkdtemp(directory) != NULL);
	CHECK("target-path", snprintf(target, sizeof(target), "%s/sh", directory) > 0);
	CHECK("alias-path", snprintf(alias, sizeof(alias), "%s/system", directory) > 0);
	CHECK("symlink", symlink("/boot/capsule.conf", alias) == 0);
	dest = open(alias, O_WRONLY | O_TRUNC);
	CHECK("system-alias-write-denied", dest == -1 && errno == EROFS);
	CHECK("remove-alias", unlink(alias) == 0);
	CHECK("system-hardlink-denied", link("/boot/capsule.conf", alias) == -1 &&
	    (errno == EXDEV || errno == EROFS));
	source = open("/bin/sh", O_RDONLY);
	dest = open(target, O_WRONLY | O_CREAT | O_EXCL, 0700);
	CHECK("copy-open", source >= 0 && dest >= 0);
	while ((count = read(source, buffer, sizeof(buffer))) > 0)
		CHECK("copy-write", write(dest, buffer, count) == count);
	CHECK("copy-read", count == 0);
	CHECK("copy-close", close(source) == 0 && close(dest) == 0);
	CHECK("system-replace-denied", rename(target, "/bin/sh") == -1 &&
	    (errno == EXDEV || errno == EROFS));
	/* A successful exec is a test failure, even when the replacement exits 0. */
	child = fork();
	CHECK("exec-fork", child >= 0);
	if (child == 0) {
		execl(target, "sh", "-c", "exit 0", NULL);
		_exit(errno == EACCES ? 73 : 74);
	}
	CHECK("tmp-exec-denied", waitpid(child, &status, 0) == child &&
	    WIFEXITED(status) && WEXITSTATUS(status) == 73);
	source = open(target, O_RDONLY);
	CHECK("mapping-open", source >= 0);
	mapping = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, source, 0);
	CHECK("tmp-executable-mapping-denied", mapping == MAP_FAILED && errno == EACCES);
	CHECK("mapping-close", close(source) == 0);
	CHECK("scratch-cleanup", unlink(target) == 0 && rmdir(directory) == 0);
	child = fork();
	CHECK("ordinary-fork", child >= 0);
	if (child == 0)
		_exit(ordinary_programs());
	CHECK("ordinary-programs", waitpid(child, &status, 0) == child &&
	    WIFEXITED(status) && WEXITSTATUS(status) == 0);
	puts("STORAGE_PASS immutable system, public scratch and unprivileged programs");
	return (0);
}
