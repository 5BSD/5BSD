/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 libfuse STORE integration probe. Disposable VMs only. */
#define _GNU_SOURCE
#define FUSE_USE_VERSION 31
#include <fuse_lowlevel.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned reads;
static off_t server_size;
static void
lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param entry = {0};
	if (parent != FUSE_ROOT_ID || strcmp(name, "data") != 0) {
		fuse_reply_err(req, ENOENT);
		return;
	}
	entry.ino = 2;
	entry.attr.st_ino = 2;
	entry.attr.st_mode = S_IFREG | 0600;
	entry.attr.st_nlink = 1;
	entry.attr.st_uid = getuid();
	entry.attr.st_gid = getgid();
	entry.attr_timeout = 3600;
	entry.entry_timeout = 0;
	fuse_reply_entry(req, &entry);
}
static void
getattr_cb(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct stat st = {0};
	(void)fi;
	st.st_ino = ino;
	st.st_mode = ino == FUSE_ROOT_ID ? S_IFDIR | 0700 : S_IFREG | 0600;
	st.st_nlink = 1;
	if (ino != FUSE_ROOT_ID)
		st.st_size = __atomic_load_n(&server_size, __ATOMIC_RELAXED);
	st.st_uid = getuid();
	st.st_gid = getgid();
	fuse_reply_attr(req, &st, 3600);
}
static void
open_cb(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	(void)ino;
	fi->fh = 42;
	fi->keep_cache = 1;
	fuse_reply_open(req, fi);
}
static void
read_cb(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	(void)ino; (void)size; (void)off; (void)fi;
	__atomic_fetch_add(&reads, 1, __ATOMIC_RELAXED);
	/* Every requested byte must have come from STORE, not READ. */
	fuse_reply_err(req, EIO);
}
static void *
serve(void *arg)
{
	return (void *)(intptr_t)fuse_session_loop(arg);
}
static int
store(struct fuse_session *se, fuse_ino_t ino, off_t off, void *data, size_t size)
{
	struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
	buf.buf[0].mem = data;
	return fuse_lowlevel_notify_store(se, ino, off, &buf, 0);
}
#define CHECK(test) do { if (!(test)) { \
	fprintf(stderr, "STORE failed line %d: %s (errno %d)\n", \
	    __LINE__, #test, errno); exit(1); } } while (0)
int
main(int argc, char **argv)
{
	const struct fuse_lowlevel_ops ops = {
		.lookup = lookup, .getattr = getattr_cb, .open = open_cb,
		.read = read_cb,
	};
	char *options[] = { (char *)"store", NULL };
	struct fuse_args args = FUSE_ARGS_INIT(1, options);
	struct fuse_session *se;
	struct stat st;
	pthread_t thread;
	char path[4096], *data, *buf, *mapped;
	size_t page = sysconf(_SC_PAGESIZE), size = 2 * page + 37;
	int fd;

	CHECK(argc == 2);
	alarm(60);
	CHECK(snprintf(path, sizeof(path), "%s/data", argv[1]) < (int)sizeof(path));
	se = fuse_session_new(&args, &ops, sizeof(ops), NULL);
	CHECK(se != NULL);
	CHECK(fuse_session_mount(se, argv[1]) == 0);
	CHECK(pthread_create(&thread, NULL, serve, se) == 0);
	fd = open(path, O_RDONLY);
	CHECK(fd >= 0);
	data = malloc(size);
	buf = malloc(size);
	CHECK(data != NULL && buf != NULL);
	memset(data, 's', size);
	CHECK(store(se, 999, 0, data, 0) == -ENOENT);
	/* STORE reports data the server already owns, including its new size. */
	__atomic_store_n(&server_size, size, __ATOMIC_RELAXED);
	CHECK(store(se, 2, 0, data, size) == 0);
	CHECK(fstat(fd, &st) == 0 && st.st_size == (off_t)size);
	CHECK(pread(fd, buf, size, 0) == (ssize_t)size);
	CHECK(memcmp(data, buf, size) == 0);
	mapped = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	CHECK(mapped != MAP_FAILED);
	CHECK(memcmp(mapped, data, size) == 0);
	for (size_t i = size; i < 3 * page; i++)
		CHECK(mapped[i] == 0);
	memcpy(data + 17, "XYZ", 3);
	CHECK(store(se, 2, 17, data + 17, 3) == 0);
	CHECK(pread(fd, buf, size, 0) == (ssize_t)size);
	CHECK(memcmp(data, buf, size) == 0);
	CHECK(memcmp(mapped, data, size) == 0);
	CHECK(__atomic_load_n(&reads, __ATOMIC_RELAXED) == 0);
	CHECK(munmap(mapped, size) == 0);
	CHECK(close(fd) == 0);
	CHECK(umount2(argv[1], 0) == 0);
	fuse_session_unmount(se);
	pthread_cancel(thread);
	CHECK(pthread_join(thread, NULL) == 0);
	fuse_session_destroy(se);
	fuse_opt_free_args(&args);
	free(buf);
	free(data);
	puts("FUSE_STORE_PASS");
	return 0;
}
