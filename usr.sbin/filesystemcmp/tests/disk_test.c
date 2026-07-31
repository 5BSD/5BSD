/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "disk.h"

static int
temporary_root(const atf_tc_t *tc)
{
	const char *path;
	int fd;

	path = atf_tc_get_config_var(tc, "srcdir");
	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	return (fd);
}

static void
unique_name(char *name, size_t size, const char *prefix)
{

	snprintf(name, size, "%s.%ld", prefix, (long)getpid());
}

static void
limit_persistent_root(int fd)
{
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_PREAD, CAP_PWRITE,
	    CAP_SEEK, CAP_FCNTL, CAP_LOOKUP, CAP_FSTAT, CAP_FSTATAT,
	    CAP_FTRUNCATE, CAP_FSYNC, CAP_CREATE, CAP_MKDIRAT, CAP_UNLINKAT,
	    CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &rights));
	ATF_REQUIRE_EQ(0, cap_fcntls_limit(fd, 0));
}

ATF_TC(persistent_lifecycle);
ATF_TC_HEAD(persistent_lifecycle, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "vnode storage persists data across independent store sessions");
}
ATF_TC_BODY(persistent_lifecycle, tc)
{
	struct disk_store *first, *second;
	struct filesystemcmp_handle root, file;
	char template[] = "/tmp/filesystemcmp.persist.XXXXXX";
	char *path;
	char name[64], data[8] = {};
	int rootfd;

	path = mkdtemp(template);
	ATF_REQUIRE(path != NULL);
	rootfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(rootfd >= 0);
	unique_name(name, sizeof(name), "disk-persist");
	(void)unlinkat(rootfd, name, 0);
	ATF_REQUIRE_EQ(0, disk_store_create(rootfd, false, UINT64_MAX, 16, 1024,
	    &first));
	ATF_REQUIRE_EQ(0, disk_root(first, &root));
	ATF_REQUIRE_EQ(0, disk_create(first, root, name, strlen(name),
	    FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600, &file));
	ATF_REQUIRE_EQ(7, disk_write(first, file, 0, "durable", 7));
	ATF_REQUIRE_EQ(0, disk_sync(first, file));
	ATF_REQUIRE_EQ(0, disk_sync(first, root));
	disk_store_destroy(first);

	ATF_REQUIRE_EQ(0, disk_store_create(rootfd, false, UINT64_MAX, 16, 1024,
	    &second));
	ATF_REQUIRE_EQ(0, disk_root(second, &root));
	ATF_REQUIRE_EQ(0, disk_lookup(second, root, name, strlen(name), &file));
	ATF_REQUIRE_EQ(7, disk_read(second, file, 0, data, sizeof(data)));
	ATF_CHECK_EQ(0, memcmp(data, "durable", 7));
	ATF_REQUIRE_EQ(0, disk_close(second, file));
	errno = 0;
	ATF_CHECK_EQ(-1, disk_read(second, file, 0, data, sizeof(data)));
	ATF_CHECK_EQ(ESTALE, errno);
	ATF_REQUIRE_EQ(0, disk_unlink(second, root, name, strlen(name)));
	ATF_REQUIRE_EQ(0, disk_sync(second, root));
	disk_store_destroy(second);
	close(rootfd);
	ATF_REQUIRE_EQ(0, rmdir(path));
}

ATF_TC(readonly_and_symlink_security);
ATF_TC_HEAD(readonly_and_symlink_security, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "read-only bundle roots reject mutation and never follow symlinks");
}
ATF_TC_BODY(readonly_and_symlink_security, tc)
{
	struct disk_store *store;
	struct filesystemcmp_handle root, object;
	char file_name[64], link_name[64], data[4] = {};
	int rootfd, fd;

	rootfd = temporary_root(tc);
	unique_name(file_name, sizeof(file_name), "disk-ro");
	unique_name(link_name, sizeof(link_name), "disk-link");
	(void)unlinkat(rootfd, file_name, 0);
	(void)unlinkat(rootfd, link_name, 0);
	fd = openat(rootfd, file_name, O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(3, write(fd, "yes", 3));
	close(fd);
	ATF_REQUIRE_EQ(0, symlinkat(file_name, rootfd, link_name));

	ATF_REQUIRE_EQ(0, disk_store_create(rootfd, true, UINT64_MAX, 16, 1024,
	    &store));
	ATF_REQUIRE_EQ(0, disk_root(store, &root));
	ATF_REQUIRE_EQ(0, disk_lookup(store, root, file_name,
	    strlen(file_name), &object));
	ATF_REQUIRE_EQ(3, disk_read(store, object, 0, data, sizeof(data)));
	ATF_CHECK_EQ(0, memcmp(data, "yes", 3));
	errno = 0;
	ATF_CHECK_EQ(-1, disk_write(store, object, 0, "no", 2));
	ATF_CHECK_EQ(EROFS, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, disk_create(store, root, "new", 3, 0, 0600,
	    &object));
	ATF_CHECK_EQ(EROFS, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, disk_lookup(store, root, link_name,
	    strlen(link_name), &object));
	/* FreeBSD reports EMLINK for O_NOFOLLOW on a final symlink. */
	ATF_CHECK(errno == ELOOP || errno == EMLINK || errno == EFTYPE);
	disk_store_destroy(store);
	ATF_REQUIRE_EQ(0, unlinkat(rootfd, link_name, 0));
	ATF_REQUIRE_EQ(0, unlinkat(rootfd, file_name, 0));
	close(rootfd);
}

ATF_TC(directories_rename_and_bounds);
ATF_TC_HEAD(directories_rename_and_bounds, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "directory-relative mutation, collision, and file bounds are enforced");
}
ATF_TC_BODY(directories_rename_and_bounds, tc)
{
	struct disk_store *store;
	struct filesystemcmp_handle root, dir, file, found;
	char template[] = "/tmp/filesystemcmp.rename.XXXXXX";
	char *path;
	char dir_name[64], old_name[64], new_name[64];
	int rootfd;

	path = mkdtemp(template);
	ATF_REQUIRE(path != NULL);
	rootfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(rootfd >= 0);
	unique_name(dir_name, sizeof(dir_name), "disk-dir");
	unique_name(old_name, sizeof(old_name), "disk-old");
	unique_name(new_name, sizeof(new_name), "disk-new");
	(void)unlinkat(rootfd, old_name, 0);
	(void)unlinkat(rootfd, new_name, 0);
	(void)unlinkat(rootfd, dir_name, AT_REMOVEDIR);
	ATF_REQUIRE_EQ(0, disk_store_create(rootfd, false, UINT64_MAX, 16, 8,
	    &store));
	ATF_REQUIRE_EQ(0, disk_root(store, &root));
	ATF_REQUIRE_EQ(0, disk_create(store, root, dir_name, strlen(dir_name),
	    FILESYSTEMCMP_CREATE_DIRECTORY | FILESYSTEMCMP_CREATE_EXCLUSIVE,
	    0700, &dir));
	ATF_REQUIRE_EQ(0, disk_create(store, root, old_name, strlen(old_name),
	    FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600, &file));
	errno = 0;
	ATF_CHECK_EQ(-1, disk_write(store, file, 8, "x", 1));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_REQUIRE_EQ(0, disk_rename(store, root, old_name, strlen(old_name),
	    dir, new_name, strlen(new_name)));
	ATF_REQUIRE_EQ(0, disk_lookup(store, dir, new_name, strlen(new_name),
	    &found));
	ATF_REQUIRE_EQ(0, disk_unlink(store, dir, new_name, strlen(new_name)));
	ATF_REQUIRE_EQ(0, disk_unlink(store, root, dir_name, strlen(dir_name)));
	disk_store_destroy(store);
	close(rootfd);
	ATF_REQUIRE_EQ(0, rmdir(path));
}

ATF_TC(capability_mode);
ATF_TC_HEAD(capability_mode, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "all vnode operations remain descriptor-relative in capability mode");
}

ATF_TC(quota_restart_accounting);
ATF_TC_HEAD(quota_restart_accounting, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "durable quota includes preexisting bytes and rejects growth atomically");
}
ATF_TC_BODY(quota_restart_accounting, tc)
{
	struct disk_store *store;
	struct filesystemcmp_handle root, seed, next;
	char template[] = "/tmp/filesystemcmp.disk.XXXXXX";
	char *path;
	int fd, rootfd;

	path = mkdtemp(template);
	ATF_REQUIRE(path != NULL);
	rootfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(rootfd >= 0);
	fd = openat(rootfd, "seed", O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(6, write(fd, "123456", 6));
	close(fd);

	ATF_REQUIRE_EQ(0, disk_store_create(rootfd, false, 8, 8, 8, &store));
	ATF_REQUIRE_EQ(0, disk_root(store, &root));
	ATF_REQUIRE_EQ(0, disk_lookup(store, root, "seed", 4, &seed));
	ATF_REQUIRE_EQ(0, disk_create(store, root, "next", 4,
	    FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600, &next));
	errno = 0;
	ATF_CHECK_EQ(-1, disk_write(store, next, 0, "abc", 3));
	ATF_CHECK_EQ(ENOSPC, errno);
	ATF_REQUIRE_EQ(2, disk_write(store, next, 0, "ab", 2));
	errno = 0;
	ATF_CHECK_EQ(-1, disk_write(store, seed, 6, "x", 1));
	ATF_CHECK_EQ(ENOSPC, errno);
	ATF_REQUIRE_EQ(0, disk_unlink(store, root, "seed", 4));
	errno = 0;
	ATF_CHECK_EQ(-1, disk_write(store, seed, 0, "x", 1));
	ATF_CHECK_EQ(ESTALE, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, disk_write(store, next, 2, "c", 1));
	ATF_CHECK_EQ(ENOSPC, errno);
	ATF_REQUIRE_EQ(0, disk_close(store, seed));
	ATF_REQUIRE_EQ(1, disk_write(store, next, 2, "c", 1));
	disk_store_destroy(store);
	ATF_REQUIRE_EQ(0, unlinkat(rootfd, "next", 0));
	close(rootfd);
	ATF_REQUIRE_EQ(0, rmdir(path));
}

ATF_TC(hardlink_quota_security);
ATF_TC_HEAD(hardlink_quota_security, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "writable hard links are rejected so quota cannot be aliased");
}

ATF_TC(object_quota_restart_and_atomicity);
ATF_TC_HEAD(object_quota_restart_and_atomicity, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "persistent object quota counts files and directories across restart without failed-create residue");
}
ATF_TC_BODY(object_quota_restart_and_atomicity, tc)
{
	struct disk_store *store;
	struct filesystemcmp_handle root, object;
	struct stat status;
	char template[] = "/tmp/filesystemcmp.objects.XXXXXX";
	char *path;
	int rootfd;

	path = mkdtemp(template);
	ATF_REQUIRE(path != NULL);
	rootfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(rootfd >= 0);
	/* The root and each durable child count toward max_objects. */
	ATF_REQUIRE_EQ(0, disk_store_create(rootfd, false, 4096, 3, 1024,
	    &store));
	ATF_REQUIRE_EQ(0, disk_root(store, &root));
	ATF_REQUIRE_EQ(0, disk_create(store, root, "file", 4,
	    FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600, &object));
	ATF_REQUIRE_EQ(0, disk_close(store, object));
	ATF_REQUIRE_EQ(0, disk_create(store, root, "dir", 3,
	    FILESYSTEMCMP_CREATE_DIRECTORY | FILESYSTEMCMP_CREATE_EXCLUSIVE,
	    0700, &object));
	ATF_REQUIRE_EQ(0, disk_close(store, object));
	errno = 0;
	ATF_CHECK_EQ(-1, disk_create(store, root, "residue", 7,
	    FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600, &object));
	ATF_CHECK_EQ(ENOSPC, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, fstatat(rootfd, "residue", &status,
	    AT_SYMLINK_NOFOLLOW));
	ATF_CHECK_EQ(ENOENT, errno);
	disk_store_destroy(store);

	ATF_REQUIRE_EQ(0, disk_store_create(rootfd, false, 4096, 3, 1024,
	    &store));
	ATF_REQUIRE_EQ(0, disk_root(store, &root));
	errno = 0;
	ATF_CHECK_EQ(-1, disk_create(store, root, "restart-residue", 15,
	    FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600, &object));
	ATF_CHECK_EQ(ENOSPC, errno);
	ATF_REQUIRE_EQ(0, disk_unlink(store, root, "file", 4));
	ATF_REQUIRE_EQ(0, disk_create(store, root, "replacement", 11,
	    FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600, &object));
	disk_store_destroy(store);

	ATF_REQUIRE_EQ(0, unlinkat(rootfd, "replacement", 0));
	ATF_REQUIRE_EQ(0, unlinkat(rootfd, "dir", AT_REMOVEDIR));
	close(rootfd);
	ATF_REQUIRE_EQ(0, rmdir(path));
}

ATF_TC(object_quota_rejects_oversized_restart);
ATF_TC_HEAD(object_quota_rejects_oversized_restart, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "startup rejects a persistent tree whose durable object count exceeds policy");
}
ATF_TC_BODY(object_quota_rejects_oversized_restart, tc)
{
	struct disk_store *store;
	char template[] = "/tmp/filesystemcmp.objectscan.XXXXXX";
	char *path;
	int fd, rootfd;

	path = mkdtemp(template);
	ATF_REQUIRE(path != NULL);
	rootfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(rootfd >= 0);
	fd = openat(rootfd, "one", O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	fd = openat(rootfd, "two", O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	errno = 0;
	ATF_CHECK_EQ(-1, disk_store_create(rootfd, false, 4096, 2, 1024,
	    &store));
	ATF_CHECK_EQ(ENOSPC, errno);
	ATF_REQUIRE_EQ(0, unlinkat(rootfd, "two", 0));
	ATF_REQUIRE_EQ(0, unlinkat(rootfd, "one", 0));
	close(rootfd);
	ATF_REQUIRE_EQ(0, rmdir(path));
}
ATF_TC_BODY(hardlink_quota_security, tc)
{
	struct disk_store *store;
	struct filesystemcmp_handle root, object;
	char template[] = "/tmp/filesystemcmp.hardlink.XXXXXX";
	char *path;
	int fd, rootfd;

	path = mkdtemp(template);
	ATF_REQUIRE(path != NULL);
	rootfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(rootfd >= 0);
	fd = openat(rootfd, "first", O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(4, write(fd, "data", 4));
	close(fd);
	ATF_REQUIRE_EQ(0, linkat(rootfd, "first", rootfd, "second", 0));
	ATF_REQUIRE_EQ(0, disk_store_create(rootfd, false, 16, 8, 16, &store));
	ATF_REQUIRE_EQ(0, disk_root(store, &root));
	errno = 0;
	ATF_CHECK_EQ(-1, disk_lookup(store, root, "first", 5, &object));
	ATF_CHECK_EQ(EMLINK, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, disk_unlink(store, root, "second", 6));
	ATF_CHECK_EQ(EMLINK, errno);
	disk_store_destroy(store);
	ATF_REQUIRE_EQ(0, unlinkat(rootfd, "second", 0));
	ATF_REQUIRE_EQ(0, unlinkat(rootfd, "first", 0));
	close(rootfd);
	ATF_REQUIRE_EQ(0, rmdir(path));
}
ATF_TC_BODY(capability_mode, tc)
{
	struct disk_store *store;
	struct filesystemcmp_handle root, file;
	char template[] = "/tmp/filesystemcmp.capmode.XXXXXX";
	char *path;
	char name[64], data[4] = {};
	int rootfd, status;
	pid_t pid;

	path = mkdtemp(template);
	ATF_REQUIRE(path != NULL);
	rootfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(rootfd >= 0);
	unique_name(name, sizeof(name), "disk-cap");
	(void)unlinkat(rootfd, name, 0);
	limit_persistent_root(rootfd);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (disk_store_create(rootfd, false, UINT64_MAX, 8, 128,
		    &store) == -1 ||
		    cap_enter() == -1 || disk_root(store, &root) == -1 ||
		    disk_create(store, root, name, strlen(name),
		    FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600, &file) == -1 ||
		    disk_write(store, file, 0, "cap", 3) != 3 ||
		    disk_sync(store, file) == -1 ||
		    disk_sync(store, root) == -1 ||
		    disk_read(store, file, 0, data, sizeof(data)) != 3 ||
		    memcmp(data, "cap", 3) != 0 ||
		    disk_unlink(store, root, name, strlen(name)) == -1)
			_exit(1);
		disk_store_destroy(store);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	(void)unlinkat(rootfd, name, 0);
	close(rootfd);
	ATF_REQUIRE_EQ(0, rmdir(path));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, persistent_lifecycle);
	ATF_TP_ADD_TC(tp, readonly_and_symlink_security);
	ATF_TP_ADD_TC(tp, directories_rename_and_bounds);
	ATF_TP_ADD_TC(tp, capability_mode);
	ATF_TP_ADD_TC(tp, quota_restart_accounting);
	ATF_TP_ADD_TC(tp, hardlink_quota_security);
	ATF_TP_ADD_TC(tp, object_quota_restart_and_atomicity);
	ATF_TP_ADD_TC(tp, object_quota_rejects_oversized_restart);
	return (atf_no_error());
}
