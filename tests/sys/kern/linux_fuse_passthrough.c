/* SPDX-License-Identifier: BSD-2-Clause */
/* Private-directory libfuse integration fixture, disposable guests only. */
#define FUSE_USE_VERSION 31
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
static char root[PATH_MAX];
static int full(char* out, const char* path)
{
	return snprintf(out, PATH_MAX, "%s%s", root, path) >= PATH_MAX
	    ? -ENAMETOOLONG
	    : 0;
}
#define PATH(p)                                                                \
	char path[PATH_MAX];                                                   \
	int e = full(path, p);                                                 \
	if (e)                                                                 \
	return e
#define RESULT(call)                                                           \
	do {                                                                   \
		int r = (call);                                                \
		return r < 0 ? -errno : r;                                     \
	} while (0)
static int attr(const char* p, struct stat* st, struct fuse_file_info* fi)
{
	PATH(p);
	if (fi)
		RESULT(fstat(fi->fh, st));
	RESULT(lstat(path, st));
}
static int rdlink(const char* p, char* b, size_t n)
{
	PATH(p);
	ssize_t r = readlink(path, b, n - 1);
	if (r < 0)
		return -errno;
	b[r] = 0;
	return 0;
}
static int mkdir_cb(const char* p, mode_t m)
{
	PATH(p);
	if (mkdir(path, m) < 0)
		return -errno;
	const struct fuse_context* c = fuse_get_context();
	RESULT(lchown(path, c->uid, c->gid));
}
static int unlink_cb(const char* p)
{
	PATH(p);
	RESULT(unlink(path));
}
static int rmdir_cb(const char* p)
{
	PATH(p);
	RESULT(rmdir(path));
}
static int rename_cb(const char* a, const char* b, unsigned flags)
{
	PATH(a);
	char target[PATH_MAX];
	if ((e = full(target, b)))
		return e;
	if (flags)
		return -EINVAL;
	RESULT(rename(path, target));
}
static int link_cb(const char* a, const char* b)
{
	PATH(a);
	char target[PATH_MAX];
	if ((e = full(target, b)))
		return e;
	RESULT(link(path, target));
}
static int symlink_cb(const char* a, const char* b)
{
	PATH(b);
	RESULT(symlink(a, path));
}
static int chmod_cb(const char* p, mode_t m, struct fuse_file_info* fi)
{
	PATH(p);
	if (fi)
		RESULT(fchmod(fi->fh, m));
	RESULT(chmod(path, m));
}
static int chown_cb(const char* p, uid_t u, gid_t g, struct fuse_file_info* fi)
{
	PATH(p);
	if (fi)
		RESULT(fchown(fi->fh, u, g));
	RESULT(lchown(path, u, g));
}
static int truncate_cb(const char* p, off_t n, struct fuse_file_info* fi)
{
	PATH(p);
	if (fi)
		RESULT(ftruncate(fi->fh, n));
	RESULT(truncate(path, n));
}
static int open_cb(const char* p, struct fuse_file_info* fi)
{
	PATH(p);
	int fd = open(path, fi->flags);
	if (fd < 0)
		return -errno;
	fi->fh = fd;
	return 0;
}
static int create_cb(const char* p, mode_t m, struct fuse_file_info* fi)
{
	PATH(p);
	int fd = open(path, fi->flags | O_CREAT, m);
	if (fd < 0)
		return -errno;
	fi->fh = fd;
	const struct fuse_context* c = fuse_get_context();
	if (fchown(fd, c->uid, c->gid) < 0) {
		int e = errno;
		close(fd);
		return -e;
	}
	return 0;
}
static int read_cb(
    const char* p, char* b, size_t n, off_t off, struct fuse_file_info* fi)
{
	(void)p;
	RESULT(pread(fi->fh, b, n, off));
}
static int write_cb(const char* p, const char* b, size_t n, off_t off,
    struct fuse_file_info* fi)
{
	(void)p;
	RESULT(pwrite(fi->fh, b, n, off));
}
static int release_cb(const char* p, struct fuse_file_info* fi)
{
	(void)p;
	RESULT(close(fi->fh));
}
static int flush_cb(const char* p, struct fuse_file_info* fi)
{
	(void)p;
	int fd = dup(fi->fh);
	if (fd < 0)
		return -errno;
	RESULT(close(fd));
}
static int sync_cb(const char* p, int data, struct fuse_file_info* fi)
{
	(void)p;
	RESULT(data ? fdatasync(fi->fh) : fsync(fi->fh));
}
static int utimens_cb(
    const char* p, const struct timespec tv[2], struct fuse_file_info* fi)
{
	PATH(p);
	if (fi)
		RESULT(futimens(fi->fh, tv));
	RESULT(utimensat(AT_FDCWD, path, tv, AT_SYMLINK_NOFOLLOW));
}
static int readdir_cb(const char* p, void* b, fuse_fill_dir_t fill, off_t off,
    struct fuse_file_info* fi, enum fuse_readdir_flags flags)
{
	PATH(p);
	(void)fi;
	(void)flags;
	DIR* d = opendir(path);
	if (!d)
		return -errno;
	if (off)
		seekdir(d, off);
	struct dirent* ent;
	while ((ent = readdir(d))) {
		struct stat st
		    = { .st_ino = ent->d_ino, .st_mode = ent->d_type << 12 };
		if (fill(b, ent->d_name, &st, telldir(d), 0))
			break;
	}
	closedir(d);
	return 0;
}
static int setxattr_cb(
    const char* p, const char* n, const char* v, size_t z, int f)
{
	PATH(p);
	RESULT(lsetxattr(path, n, v, z, f));
}
static int getxattr_cb(const char* p, const char* n, char* v, size_t z)
{
	PATH(p);
	RESULT(lgetxattr(path, n, v, z));
}
static int listxattr_cb(const char* p, char* v, size_t z)
{
	PATH(p);
	RESULT(llistxattr(path, v, z));
}
static int removexattr_cb(const char* p, const char* n)
{
	PATH(p);
	RESULT(lremovexattr(path, n));
}
static void* init_cb(struct fuse_conn_info* conn, struct fuse_config* cfg)
{
	cfg->entry_timeout = 0;
	cfg->attr_timeout = 0;
	cfg->negative_timeout = 0;
	if (getenv("FUSE_TEST_WRITEBACK") &&
	    !strcmp(getenv("FUSE_TEST_WRITEBACK"), "writeback")) {
		if ((conn->capable & FUSE_CAP_WRITEBACK_CACHE) == 0) {
			fprintf(stderr, "FUSE_TEST_WRITEBACK_UNSUPPORTED\n");
			exit(3);
		}
		conn->want |= FUSE_CAP_WRITEBACK_CACHE;
		fprintf(stderr, "FUSE_TEST_WRITEBACK_NEGOTIATED\n");
	}
	return NULL;
}
static const struct fuse_operations ops = { .getattr = attr,
	.readlink = rdlink,
	.mkdir = mkdir_cb,
	.unlink = unlink_cb,
	.rmdir = rmdir_cb,
	.rename = rename_cb,
	.link = link_cb,
	.symlink = symlink_cb,
	.chmod = chmod_cb,
	.chown = chown_cb,
	.truncate = truncate_cb,
	.open = open_cb,
	.create = create_cb,
	.read = read_cb,
	.write = write_cb,
	.release = release_cb,
	.flush = flush_cb,
	.fsync = sync_cb,
	.utimens = utimens_cb,
	.readdir = readdir_cb,
	.setxattr = setxattr_cb,
	.getxattr = getxattr_cb,
	.listxattr = listxattr_cb,
	.removexattr = removexattr_cb,
	.init = init_cb };
int main(int argc, char** argv)
{
	const char* dir = getenv("FUSE_TEST_ROOT");
	if (!dir || !realpath(dir, root))
		return 2;
	return fuse_main(argc, argv, &ops, NULL);
}
