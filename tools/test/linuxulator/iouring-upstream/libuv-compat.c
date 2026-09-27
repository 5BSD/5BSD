/* SPDX-License-Identifier: BSD-2-Clause */
/* Application API checks with read-only observation of pinned libuv internals.
 * No upstream source changes: distinguish successful fallback from ring use.
 * Run each case in its own process and impose an external timeout.
 */
#include "uv.h"
#include "uv-common.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

static uv_loop_t loop;
static unsigned callbacks, ring_ops, pool_ops, retries;
static int sqpoll;
static char data[4096], received[4096];

struct observed_cqe {
    uint64_t user_data;
    int32_t result;
    uint32_t flags;
};

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "FAIL line=%d expression=%s\n", __LINE__, #x); \
    exit(1); \
} } while (0)

static struct uv__iou *
fs_ring(void)
{
    return &uv__get_internal_fields((&loop))->iou;
}

static void
fs_done(uv_fs_t *req)
{
    (void)req;
    callbacks++;
}

static ssize_t
finish(const char *name, int rc, uv_fs_t *req, int require_ring)
{
    unsigned before = callbacks;
    int ring = fs_ring()->in_flight != 0;
    unsigned cqhead = ring ? *fs_ring()->cqhead : 0;
    int fallback = 0;
    ssize_t result;

    CHECK(rc == 0);
    CHECK(uv_run(&loop, UV_RUN_DEFAULT) == 0);
    CHECK(callbacks == before + 1);
    CHECK(fs_ring()->in_flight == 0);
    if (ring) {
        const struct observed_cqe *cqe = fs_ring()->cqe;
        CHECK(*fs_ring()->cqhead == cqhead + 1);
        cqe += cqhead & fs_ring()->cqmask;
        CHECK(cqe->user_data == (uintptr_t)req);
        fallback = cqe->result == UV_ENOTSUP;
        if (!fallback)
            CHECK(cqe->result == req->result);
        ring_ops++;
        if (fallback)
            retries++;
    } else {
        pool_ops++;
    }
    result = req->result;
    printf("OP %s result=%ld submitted=%s completion=%s\n", name,
        (long)result, ring ? "ring" : "pool",
        ring && !fallback ? "ring" : "pool");
    if (sqpoll && require_ring)
        CHECK(ring && !fallback);
    uv_fs_req_cleanup(req);
    return result;
}

static void
filesystem(void)
{
    uv_fs_t req;
    uv_buf_t buf;
    int fd;

    CHECK(finish("mkdir", uv_fs_mkdir(&loop, &req, "dir", 0700, fs_done), &req, 0) == 0);
    fd = finish("open", uv_fs_open(&loop, &req, "dir/file",
        O_RDWR | O_CREAT | O_EXCL, 0600, fs_done), &req, 1);
    CHECK(fd >= 0);
    buf = uv_buf_init(data, sizeof(data));
    CHECK(finish("write", uv_fs_write(&loop, &req, fd, &buf, 1, 0, fs_done),
        &req, 1) == sizeof(data));
    CHECK(finish("fsync", uv_fs_fsync(&loop, &req, fd, fs_done), &req, 1) == 0);
    buf = uv_buf_init(received, sizeof(received));
    CHECK(finish("read", uv_fs_read(&loop, &req, fd, &buf, 1, 0, fs_done),
        &req, 1) == sizeof(received));
    CHECK(memcmp(data, received, sizeof(data)) == 0);
    CHECK(finish("fstat", uv_fs_fstat(&loop, &req, fd, fs_done), &req, 1) == 0);
    CHECK(req.statbuf.st_size == sizeof(data));
    CHECK(finish("truncate", uv_fs_ftruncate(&loop, &req, fd, 37, fs_done), &req, 0) == 0);
    CHECK(finish("close", uv_fs_close(&loop, &req, fd, fs_done), &req, 0) == 0);
    CHECK(finish("stat", uv_fs_stat(&loop, &req, "dir/file", fs_done), &req, 1) == 0);
    CHECK(req.statbuf.st_size == 37);
    CHECK(finish("rename", uv_fs_rename(&loop, &req, "dir/file", "dir/renamed", fs_done), &req, 1) == 0);
    CHECK(finish("link", uv_fs_link(&loop, &req, "dir/renamed", "dir/hard", fs_done), &req, 0) == 0);
    CHECK(finish("symlink", uv_fs_symlink(&loop, &req, "renamed", "dir/sym", 0, fs_done), &req, 0) == 0);
    CHECK(finish("lstat", uv_fs_lstat(&loop, &req, "dir/sym", fs_done), &req, 1) == 0);
    CHECK(S_ISLNK(req.statbuf.st_mode));
    CHECK(finish("unlink-sym", uv_fs_unlink(&loop, &req, "dir/sym", fs_done), &req, 1) == 0);
    CHECK(finish("unlink-hard", uv_fs_unlink(&loop, &req, "dir/hard", fs_done), &req, 1) == 0);
    CHECK(finish("unlink", uv_fs_unlink(&loop, &req, "dir/renamed", fs_done), &req, 1) == 0);
    CHECK(finish("missing", uv_fs_stat(&loop, &req, "dir/absent", fs_done), &req, 1) == UV_ENOENT);
    CHECK(finish("rmdir", uv_fs_rmdir(&loop, &req, "dir", fs_done), &req, 0) == 0);
}

static unsigned poll_callbacks;

static void
poll_done(uv_poll_t *handle, int status, int events)
{
    char value;
    int fd = *(int *)handle->data;
    CHECK(status == 0 && (events & UV_READABLE) != 0);
    CHECK(read(fd, &value, 1) == 1 && value == 'x');
    poll_callbacks++;
    CHECK(uv_poll_stop(handle) == 0);
    uv_close((uv_handle_t *)handle, NULL);
}

static void
polling(void)
{
    struct uv__iou *ctl = &uv__get_internal_fields((&loop))->ctl;
    uv_poll_t handle;
    int pair[2];
    unsigned before, after;

    CHECK(ctl->ringfd >= 0);
    before = *ctl->sqtail;
    for (unsigned i = 0; i < 32; i++) {
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        CHECK(uv_poll_init(&loop, &handle, pair[0]) == 0);
        handle.data = &pair[0];
        CHECK(uv_poll_start(&handle, UV_READABLE, poll_done) == 0);
        CHECK(write(pair[1], "x", 1) == 1);
        CHECK(uv_run(&loop, UV_RUN_DEFAULT) == 0);
        CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
    }
    after = *ctl->sqtail;
    printf("POLL callbacks=%u epoll_ring_submissions=%u\n", poll_callbacks, after - before);
    CHECK(poll_callbacks == 32 && after - before >= 32);
}

static void
cancellation(void)
{
    enum { N = 32 };
    uv_fs_t req[N];
    uv_buf_t bufs[N];
    char buffers[N][64];
    int cancel_rc[N];
    unsigned seen[N] = {0};
    unsigned submitted = 0, cancelled = 0, busy = 0;
    unsigned cqhead = 0;
    int fd = open("cancel-file", O_RDWR | O_CREAT | O_EXCL, 0600);

    CHECK(fd >= 0);
    CHECK(write(fd, data, sizeof(data)) == sizeof(data));
    for (unsigned i = 0; i < N; i++) {
        unsigned before = fs_ring()->in_flight;
        bufs[i] = uv_buf_init(buffers[i], sizeof(buffers[i]));
        CHECK(uv_fs_read(&loop, &req[i], fd, &bufs[i], 1, 0, fs_done) == 0);
        if (fs_ring()->in_flight > before)
            submitted++;
    }
    if (submitted != 0)
        cqhead = *fs_ring()->cqhead;
    for (unsigned i = 0; i < N; i++) {
        cancel_rc[i] = uv_cancel((uv_req_t *)&req[i]);
        CHECK(cancel_rc[i] == 0 || cancel_rc[i] == UV_EBUSY);
    }
    CHECK(uv_run(&loop, UV_RUN_DEFAULT) == 0);
    CHECK(callbacks == N && fs_ring()->in_flight == 0);
    if (submitted != 0) {
        const struct observed_cqe *cqes = fs_ring()->cqe;
        CHECK(*fs_ring()->cqhead == cqhead + submitted);
        for (unsigned i = 0; i < submitted; i++) {
            const struct observed_cqe *cqe = &cqes[(cqhead + i) & fs_ring()->cqmask];
            uintptr_t offset;
            unsigned index;
            CHECK(cqe->user_data >= (uintptr_t)req);
            offset = cqe->user_data - (uintptr_t)req;
            CHECK(offset < sizeof(req) && offset % sizeof(req[0]) == 0);
            index = offset / sizeof(req[0]);
            CHECK(seen[index]++ == 0);
            CHECK(cqe->result != UV_ENOTSUP);
            CHECK(cqe->result == req[index].result);
        }
    }
    for (unsigned i = 0; i < N; i++) {
        printf("CANCEL_OP index=%u cancel=%d completion=%ld\n", i,
            cancel_rc[i], (long)req[i].result);
        if (cancel_rc[i] == 0) {
            CHECK(req[i].result == UV_ECANCELED);
            cancelled++;
        } else {
            CHECK(req[i].result == sizeof(buffers[i]));
            CHECK(memcmp(buffers[i], data, sizeof(buffers[i])) == 0);
            busy++;
        }
        if (sqpoll)
            CHECK(seen[i] == 1);
        uv_fs_req_cleanup(&req[i]);
    }
    if (sqpoll)
        CHECK(submitted == N);
    printf("CANCEL callbacks=%u ring_submitted=%u cancelled=%u already_busy=%u\n",
        callbacks, submitted, cancelled, busy);
    CHECK(close(fd) == 0 && unlink("cancel-file") == 0);
}

int
main(int argc, char **argv)
{
    struct utsname identity;
    char directory[] = "/tmp/libuv-compat.XXXXXX";

    CHECK(argc == 3);
    CHECK(strcmp(argv[1], "default") == 0 || strcmp(argv[1], "sqpoll") == 0);
    sqpoll = strcmp(argv[1], "sqpoll") == 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    CHECK(setenv("UV_USE_IO_URING", sqpoll ? "1" : "0", 1) == 0);
    CHECK(uname(&identity) == 0);
    printf("LIBUV version=%s mode=%s case=%s kernel=%s\n",
        uv_version_string(), argv[1], argv[2], identity.release);
    CHECK(mkdtemp(directory) != NULL && chdir(directory) == 0);
    for (unsigned i = 0; i < sizeof(data); i++)
        data[i] = (char)(i * 37 + 11);
    CHECK(uv_loop_init(&loop) == 0);
    if (sqpoll)
        CHECK(uv_loop_configure(&loop, UV_LOOP_USE_IO_URING_SQPOLL) == 0);
    if (strcmp(argv[2], "fs") == 0)
        filesystem();
    else if (strcmp(argv[2], "poll") == 0)
        polling();
    else if (strcmp(argv[2], "cancel") == 0)
        cancellation();
    else
        CHECK(0);
    printf("COUNTS ring_ops=%u pool_ops=%u ring_to_pool_retries=%u\n",
        ring_ops, pool_ops, retries);
    CHECK(retries == 0);
    CHECK(uv_loop_close(&loop) == 0);
    uv_library_shutdown();
    CHECK(chdir("/") == 0 && rmdir(directory) == 0);
    puts("LIBUV_PASS");
    return 0;
}
