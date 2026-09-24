/* SPDX-License-Identifier: BSD-2-Clause */
/* Real Linux64 libfuse CREATE flag probe. Disposable guests only. */
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
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, \
    "FUSE_FLAGS failed line %d: %s errno %d\n", __LINE__, #x, errno); \
    exit(1); } } while (0)
static unsigned creates, releases, reads, writes;
static char contents[4];
static int exclusive;
static void
lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	(void)parent; (void)name;
	fuse_reply_err(req, ENOENT);
}
static void
getattr_cb(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct stat st = {0};
	(void)fi;
	st.st_ino = ino;
	st.st_mode = ino == FUSE_ROOT_ID ? S_IFDIR | 0700 : S_IFREG | 0600;
	st.st_nlink = 1;
	st.st_uid = getuid(); st.st_gid = getgid();
	st.st_size = ino == FUSE_ROOT_ID ? 0 : sizeof(contents);
	fuse_reply_attr(req, &st, 0);
}
static void
create_cb(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode,
    struct fuse_file_info *fi)
{
	struct fuse_entry_param e = {0};
	CHECK(parent == FUSE_ROOT_ID && strcmp(name, "new") == 0);
	CHECK((fi->flags & (O_ACCMODE | O_CREAT | O_TRUNC | O_EXCL)) ==
	    (O_RDWR | O_CREAT | exclusive));
	__atomic_fetch_add(&creates, 1, __ATOMIC_RELAXED);
	e.ino = e.attr.st_ino = 2;
	e.attr.st_mode = S_IFREG | mode;
	e.attr.st_nlink = 1;
	e.attr.st_uid = getuid(); e.attr.st_gid = getgid();
	e.attr_timeout = 0;
	fi->fh = 42;
	fi->direct_io = 1;
	fuse_reply_create(req, &e, fi);
}
static void
read_cb(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	CHECK(ino == 2 && fi->fh == 42 && off == 0 && size == sizeof(contents));
	CHECK((fi->flags & O_ACCMODE) == O_RDWR);
	__atomic_fetch_add(&reads, 1, __ATOMIC_RELAXED);
	fuse_reply_buf(req, contents, sizeof(contents));
}
static void
write_cb(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	CHECK(ino == 2 && fi->fh == 42 && off == 0 && size == sizeof(contents));
	CHECK((fi->flags & O_ACCMODE) == O_RDWR);
	memcpy(contents, buf, size);
	__atomic_fetch_add(&writes, 1, __ATOMIC_RELAXED);
	fuse_reply_write(req, size);
}
static void
release_cb(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	CHECK(ino == 2 && fi->fh == 42);
	CHECK((fi->flags & (O_ACCMODE | O_TRUNC)) == O_RDWR);
	__atomic_fetch_add(&releases, 1, __ATOMIC_RELAXED);
	fuse_reply_err(req, 0);
}
static void *serve(void *arg) { return (void *)(intptr_t)fuse_session_loop(arg); }
int
main(int argc, char **argv)
{
	const struct fuse_lowlevel_ops ops = { .lookup = lookup,
	    .getattr = getattr_cb, .create = create_cb, .read = read_cb,
	    .write = write_cb, .release = release_cb };
	char *options[] = { (char *)"flags", NULL };
	struct fuse_args args = FUSE_ARGS_INIT(1, options);
	struct fuse_session *se;
	pthread_t thread;
	char path[4096], buf[4];
	CHECK(argc == 2 || (argc == 3 && strcmp(argv[2], "exclusive") == 0));
	exclusive = argc == 3 ? O_EXCL : 0;
	alarm(60);
	CHECK(snprintf(path, sizeof(path), "%s/new", argv[1]) < (int)sizeof(path));
	CHECK((se = fuse_session_new(&args, &ops, sizeof(ops), NULL)) != NULL);
	CHECK(fuse_session_mount(se, argv[1]) == 0);
	CHECK(pthread_create(&thread, NULL, serve, se) == 0);
	int fd = open(path, O_CREAT | O_RDWR | exclusive, 0600);
	CHECK(fd >= 0);
	CHECK(pwrite(fd, "data", 4, 0) == 4);
	CHECK(pread(fd, buf, 4, 0) == 4 && memcmp(buf, "data", 4) == 0);
	CHECK(close(fd) == 0);
	/* Linux can deliver RELEASE asynchronously after close returns. */
	for (unsigned i = 0; i < 500 &&
	    __atomic_load_n(&releases, __ATOMIC_RELAXED) == 0; i++)
		usleep(10000);
	CHECK(__atomic_load_n(&releases, __ATOMIC_RELAXED) == 1);
	CHECK(umount2(argv[1], 0) == 0);
	fuse_session_unmount(se);
	pthread_cancel(thread);
	CHECK(pthread_join(thread, NULL) == 0);
	CHECK(creates == 1 && releases == 1 && reads == 1 && writes == 1);
	fuse_session_destroy(se);
	fuse_opt_free_args(&args);
	puts("FUSE_FLAGS_PASS");
	return (0);
}
