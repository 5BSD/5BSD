/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Exercise the production block backend's WRITE ZEROES primitive on a real
 * file.  Including the implementation keeps static request processing in
 * scope while --gc-sections discards unrelated bhyve integration paths.
 */

#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "block_if.c"

static size_t pwrite_limit;
static bool pwrite_return_zero;
static unsigned int pwrite_calls;
static unsigned int mevent_disable_calls;
static unsigned int mevent_enable_calls;

ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int, const void *, size_t, off_t);

ssize_t
__wrap_pwrite(int fd, const void *buffer, size_t length, off_t offset)
{

	pwrite_calls++;
	if (pwrite_return_zero)
		return (0);
	if (pwrite_limit != 0)
		length = MIN(length, pwrite_limit);
	return (__real_pwrite(fd, buffer, length, offset));
}

/*
 * Sanitizer metadata retains otherwise dead block_if.c functions, so satisfy
 * their bhyve integration references.  The focused tests never call these.
 */
int raw_stdio;

void
set_config_value_node(nvlist_t *parent __unused, const char *name __unused,
    const char *value __unused)
{
}

const char *
get_config_value_node(const nvlist_t *parent __unused,
    const char *name __unused)
{

	return (NULL);
}

bool
get_config_bool_node_default(const nvlist_t *parent __unused,
    const char *name __unused, bool def)
{

	return (def);
}

int
pci_parse_legacy_config(nvlist_t *nvl __unused, const char *opt __unused)
{

	return (0);
}

int
pci_emul_add_boot_device(struct pci_devinst *pi __unused,
    int bootindex __unused)
{

	return (0);
}

struct mevent *
mevent_add(int fd __unused, enum ev_type type __unused,
    void (*func)(int, enum ev_type, void *) __unused, void *param __unused)
{

	return (NULL);
}

struct mevent *
mevent_add_flags(int fd __unused, enum ev_type type __unused,
    int fflags __unused,
    void (*func)(int, enum ev_type, void *) __unused, void *param __unused)
{

	return (NULL);
}

int
mevent_disable(struct mevent *evp __unused)
{

	mevent_disable_calls++;
	return (0);
}

int
mevent_enable(struct mevent *evp __unused)
{

	mevent_enable_calls++;
	return (0);
}

static int callback_calls;
static int callback_error;
static size_t resize_size;

static void
record_completion(struct blockif_req *req __unused, int error)
{

	callback_calls++;
	callback_error = error;
}

static void
record_resize(struct blockif_ctxt *bc __unused, void *arg __unused,
    size_t new_size)
{

	callback_calls++;
	resize_size = new_size;
}

static void
write_pattern(int fd, uint8_t value, size_t length)
{
	uint8_t buffer[PAGE_SIZE];
	off_t offset;
	size_t chunk;
	ssize_t done;

	memset(buffer, value, sizeof(buffer));
	for (offset = 0; offset < (off_t)length; offset += done) {
		chunk = MIN(sizeof(buffer), length - (size_t)offset);
		done = pwrite(fd, buffer, chunk, offset);
		ATF_REQUIRE(done == (ssize_t)chunk);
	}
}

static void
check_range(int fd, off_t offset, size_t length, uint8_t value)
{
	uint8_t buffer[PAGE_SIZE];
	uint8_t expected[PAGE_SIZE];
	size_t checked, chunk;
	ssize_t done;

	memset(expected, value, sizeof(expected));
	for (checked = 0; checked < length; checked += chunk) {
		chunk = MIN(sizeof(buffer), length - checked);
		done = pread(fd, buffer, chunk, offset + (off_t)checked);
		ATF_REQUIRE(done == (ssize_t)chunk);
		ATF_CHECK(memcmp(buffer, expected, chunk) == 0);
	}
}

static void
init_scheduler(struct blockif_ctxt *bc)
{
	int i;

	memset(bc, 0, sizeof(*bc));
	TAILQ_INIT(&bc->bc_freeq);
	TAILQ_INIT(&bc->bc_pendq);
	TAILQ_INIT(&bc->bc_busyq);
	for (i = 0; i < BLOCKIF_MAXREQ; i++) {
		bc->bc_reqs[i].be_status = BST_FREE;
		TAILQ_INSERT_TAIL(&bc->bc_freeq, &bc->bc_reqs[i], be_link);
	}
}

ATF_TC_WITHOUT_HEAD(write_zeroes_file);
ATF_TC_BODY(write_zeroes_file, tc)
{
	struct blockif_ctxt bc;
	struct blockif_elem be;
	struct blockif_req req;
	const char *path = "block-if-zero";
	const off_t offset = PAGE_SIZE;
	const size_t length = MAXPHYS + PAGE_SIZE + 17;
	const size_t file_size = (size_t)offset + length + PAGE_SIZE;
	int fd;

	(void)unlink(path);
	fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(ftruncate(fd, file_size) == 0);
	write_pattern(fd, 0xa5, file_size);

	memset(&bc, 0, sizeof(bc));
	bc.bc_fd = fd;
	memset(&req, 0, sizeof(req));
	req.br_offset = offset;
	req.br_resid = length;
	req.br_callback = record_completion;
	memset(&be, 0, sizeof(be));
	be.be_req = &req;
	be.be_op = BOP_WRITE_ZEROES;

	callback_calls = 0;
	callback_error = -1;
	blockif_proc(&bc, &be, NULL);
	ATF_REQUIRE_EQ(callback_calls, 1);
	ATF_REQUIRE_EQ(callback_error, 0);
	ATF_CHECK_EQ(req.br_resid, 0);
	check_range(fd, 0, offset, 0xa5);
	check_range(fd, offset, length, 0);
	check_range(fd, offset + (off_t)length, PAGE_SIZE, 0xa5);

	ATF_REQUIRE(close(fd) == 0);
	ATF_REQUIRE(unlink(path) == 0);
}

ATF_TC_WITHOUT_HEAD(write_zeroes_errors);
ATF_TC_BODY(write_zeroes_errors, tc)
{
	struct blockif_ctxt bc;
	struct blockif_elem be;
	struct blockif_req req;

	memset(&bc, 0, sizeof(bc));
	bc.bc_fd = -1;
	bc.bc_rdonly = 1;
	memset(&req, 0, sizeof(req));
	req.br_resid = PAGE_SIZE;
	req.br_callback = record_completion;
	memset(&be, 0, sizeof(be));
	be.be_req = &req;
	be.be_op = BOP_WRITE_ZEROES;
	callback_calls = 0;
	callback_error = -1;
	blockif_proc(&bc, &be, NULL);
	ATF_CHECK_EQ(callback_calls, 1);
	ATF_CHECK_EQ(callback_error, EROFS);
	ATF_CHECK_EQ(req.br_resid, PAGE_SIZE);

	bc.bc_rdonly = 0;
	callback_calls = 0;
	callback_error = -1;
	blockif_proc(&bc, &be, NULL);
	ATF_CHECK_EQ(callback_calls, 1);
	ATF_CHECK_EQ(callback_error, EBADF);
	ATF_CHECK_EQ(req.br_resid, PAGE_SIZE);

	bc.bc_magic = BLOCKIF_SIG;
	req.br_offset = -1;
	ATF_CHECK_EQ(blockif_write_zeroes(&bc, &req), EINVAL);
	req.br_offset = 0;
	req.br_resid = -1;
	ATF_CHECK_EQ(blockif_write_zeroes(&bc, &req), EINVAL);
	req.br_offset = OFF_MAX;
	req.br_resid = 1;
	ATF_CHECK_EQ(blockif_write_zeroes(&bc, &req), EINVAL);
}

ATF_TC_WITHOUT_HEAD(translated_write_retries_short_pwrite);
ATF_TC_BODY(translated_write_retries_short_pwrite, tc)
{
	struct blockif_ctxt bc;
	struct blockif_elem be;
	struct blockif_req req;
	uint8_t actual[2][PAGE_SIZE];
	uint8_t data[2][PAGE_SIZE];
	uint8_t scratch[MAXPHYS];
	const char *path = "block-if-short-write";
	ssize_t done;
	int fd;

	(void)unlink(path);
	fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	memset(data[0], 0x5a, sizeof(data[0]));
	memset(data[1], 0xc3, sizeof(data[1]));

	memset(&bc, 0, sizeof(bc));
	bc.bc_fd = fd;
	memset(&req, 0, sizeof(req));
	req.br_iov[0] = (struct iovec){
		.iov_base = data[0],
		.iov_len = sizeof(data[0]),
	};
	req.br_iov[1] = (struct iovec){
		.iov_base = data[1],
		.iov_len = sizeof(data[1]),
	};
	req.br_iovcnt = 2;
	req.br_resid = sizeof(data);
	req.br_callback = record_completion;
	memset(&be, 0, sizeof(be));
	be.be_req = &req;
	be.be_op = BOP_WRITE;

	callback_calls = 0;
	callback_error = -1;
	pwrite_calls = 0;
	pwrite_limit = 1024;
	/*
	 * Force the translated backend to make partial progress.  It must retry
	 * the unwritten suffix of the staged chunk before consuming more guest
	 * iovecs.
	 */
	blockif_proc(&bc, &be, scratch);
	pwrite_limit = 0;
	ATF_REQUIRE_EQ(callback_calls, 1);
	ATF_REQUIRE_EQ(callback_error, 0);
	ATF_CHECK_EQ(req.br_resid, 0);
	ATF_CHECK(pwrite_calls > 1);

	done = pread(fd, actual, sizeof(actual), 0);
	ATF_REQUIRE_EQ(done, (ssize_t)sizeof(actual));
	ATF_CHECK(memcmp(actual, data, sizeof(data)) == 0);

	ATF_REQUIRE(close(fd) == 0);
	ATF_REQUIRE(unlink(path) == 0);
}

ATF_TC_WITHOUT_HEAD(translated_read_eof_makes_progress);
ATF_TC_BODY(translated_read_eof_makes_progress, tc)
{
	struct blockif_ctxt bc;
	struct blockif_elem be;
	struct blockif_req req;
	uint8_t data[2][PAGE_SIZE];
	uint8_t scratch[MAXPHYS];
	const char *path = "block-if-short-read";
	int fd;

	(void)unlink(path);
	fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);

	memset(&bc, 0, sizeof(bc));
	bc.bc_fd = fd;
	memset(&req, 0, sizeof(req));
	req.br_iov[0] = (struct iovec){
		.iov_base = data[0],
		.iov_len = sizeof(data[0]),
	};
	req.br_iov[1] = (struct iovec){
		.iov_base = data[1],
		.iov_len = sizeof(data[1]),
	};
	req.br_iovcnt = 2;
	req.br_resid = sizeof(data);
	req.br_callback = record_completion;
	memset(&be, 0, sizeof(be));
	be.be_req = &req;
	be.be_op = BOP_READ;

	callback_calls = 0;
	callback_error = -1;
	/*
	 * A non-NULL translation buffer selects blockif_proc()'s multi-iovec
	 * geometry path.  Reading an empty backing file must fail promptly,
	 * retaining the full residual instead of retrying the same EOF forever.
	 */
	blockif_proc(&bc, &be, scratch);
	ATF_CHECK_EQ(callback_calls, 1);
	ATF_CHECK_EQ(callback_error, EIO);
	ATF_CHECK_EQ(req.br_resid, (ssize_t)sizeof(data));

	ATF_REQUIRE(close(fd) == 0);
	ATF_REQUIRE(unlink(path) == 0);
}

ATF_TC_WITHOUT_HEAD(translated_write_zero_progress_fails);
ATF_TC_BODY(translated_write_zero_progress_fails, tc)
{
	struct blockif_ctxt bc;
	struct blockif_elem be;
	struct blockif_req req;
	uint8_t data[2][PAGE_SIZE];
	uint8_t scratch[MAXPHYS];
	const char *path = "block-if-zero-progress-write";
	int fd;

	(void)unlink(path);
	fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	memset(data, 0x6d, sizeof(data));

	memset(&bc, 0, sizeof(bc));
	bc.bc_fd = fd;
	memset(&req, 0, sizeof(req));
	req.br_iov[0] = (struct iovec){
		.iov_base = data[0],
		.iov_len = sizeof(data[0]),
	};
	req.br_iov[1] = (struct iovec){
		.iov_base = data[1],
		.iov_len = sizeof(data[1]),
	};
	req.br_iovcnt = 2;
	req.br_resid = sizeof(data);
	req.br_callback = record_completion;
	memset(&be, 0, sizeof(be));
	be.be_req = &req;
	be.be_op = BOP_WRITE;

	callback_calls = 0;
	callback_error = -1;
	pwrite_calls = 0;
	pwrite_return_zero = true;
	blockif_proc(&bc, &be, scratch);
	pwrite_return_zero = false;

	ATF_CHECK_EQ(pwrite_calls, 1);
	ATF_CHECK_EQ(callback_calls, 1);
	ATF_CHECK_EQ(callback_error, EIO);
	ATF_CHECK_EQ(req.br_resid, (ssize_t)sizeof(data));

	ATF_REQUIRE(close(fd) == 0);
	ATF_REQUIRE(unlink(path) == 0);
}

ATF_TC_WITHOUT_HEAD(delete_uses_operation_range);
ATF_TC_BODY(delete_uses_operation_range, tc)
{
	struct blockif_ctxt bc;
	struct blockif_elem *be;
	struct blockif_req req;

	init_scheduler(&bc);
	memset(&req, 0, sizeof(req));
	req.br_offset = 8 * PAGE_SIZE;
	req.br_resid = 32 * PAGE_SIZE;
	/*
	 * VirtIO DISCARD carries a 16-byte request descriptor, but blockif's
	 * scheduling endpoint is the end of the backing-store operation.
	 */
	req.br_iovcnt = 1;
	req.br_iov[0].iov_len = 16;
	ATF_REQUIRE(blockif_enqueue(&bc, &req, BOP_DELETE));
	be = TAILQ_FIRST(&bc.bc_pendq);
	ATF_REQUIRE(be != NULL);
	ATF_CHECK_EQ(be->be_block, req.br_offset + req.br_resid);
}

ATF_TC_WITHOUT_HEAD(delete_rejects_invalid_range);
ATF_TC_BODY(delete_rejects_invalid_range, tc)
{
	struct blockif_ctxt bc;
	struct blockif_req req;

	memset(&bc, 0, sizeof(bc));
	bc.bc_magic = BLOCKIF_SIG;
	memset(&req, 0, sizeof(req));

	req.br_offset = -1;
	req.br_resid = PAGE_SIZE;
	ATF_CHECK_EQ(blockif_delete(&bc, &req), EINVAL);
	req.br_offset = 0;
	req.br_resid = -1;
	ATF_CHECK_EQ(blockif_delete(&bc, &req), EINVAL);
	req.br_offset = OFF_MAX;
	req.br_resid = 1;
	ATF_CHECK_EQ(blockif_delete(&bc, &req), EINVAL);
}

ATF_TC_WITHOUT_HEAD(flush_is_scheduler_barrier);
ATF_TC_BODY(flush_is_scheduler_barrier, tc)
{
	struct blockif_ctxt bc;
	struct blockif_elem *be, *first, *flush;
	struct blockif_req before, barrier, after;

	init_scheduler(&bc);
	memset(&before, 0, sizeof(before));
	before.br_offset = 0;
	before.br_iovcnt = 1;
	before.br_iov[0].iov_len = PAGE_SIZE;
	memset(&barrier, 0, sizeof(barrier));
	memset(&after, 0, sizeof(after));
	after.br_offset = 64 * PAGE_SIZE;
	after.br_iovcnt = 1;
	after.br_iov[0].iov_len = PAGE_SIZE;

	ATF_REQUIRE(blockif_enqueue(&bc, &before, BOP_WRITE));
	ATF_REQUIRE(blockif_dequeue(&bc, pthread_self(), &first));
	ATF_REQUIRE_EQ(first->be_req, &before);

	ATF_REQUIRE(blockif_enqueue(&bc, &barrier, BOP_FLUSH));
	flush = TAILQ_FIRST(&bc.bc_pendq);
	ATF_REQUIRE(flush != NULL);
	ATF_REQUIRE_EQ(flush->be_req, &barrier);
	ATF_REQUIRE(blockif_enqueue(&bc, &after, BOP_WRITE));

	/* The later random write is runnable, but cannot pass the flush. */
	ATF_CHECK(!blockif_dequeue(&bc, pthread_self(), &be));
	blockif_complete(&bc, first);
	ATF_REQUIRE(blockif_dequeue(&bc, pthread_self(), &be));
	ATF_REQUIRE_EQ(be, flush);
	ATF_CHECK(!blockif_dequeue(&bc, pthread_self(), &first));
	blockif_complete(&bc, be);
	ATF_REQUIRE(blockif_dequeue(&bc, pthread_self(), &be));
	ATF_CHECK_EQ(be->be_req, &after);
}

ATF_TC_WITHOUT_HEAD(nested_quiesce_ownership);
ATF_TC_BODY(nested_quiesce_ownership, tc)
{
	struct blockif_ctxt bc;
	const char *path;
	int fd;

	path = "block-if-quiesce";
	(void)unlink(path);
	fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);

	init_scheduler(&bc);
	bc.bc_magic = BLOCKIF_SIG;
	bc.bc_fd = fd;
	bc.bc_resize_event = (struct mevent *)(uintptr_t)1;
	bc.bc_resize_cb = record_resize;
	ATF_REQUIRE_EQ(pthread_mutex_init(&bc.bc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&bc.bc_cond, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&bc.bc_work_done_cond, NULL), 0);
	callback_calls = 0;
	resize_size = 0;
	mevent_disable_calls = 0;
	mevent_enable_calls = 0;

	ATF_REQUIRE_EQ(blockif_suspend(&bc), 0);
	ATF_CHECK_EQ(bc.bc_paused, 1);
	ATF_CHECK_EQ(mevent_disable_calls, 1);
	ATF_REQUIRE_EQ(blockif_suspend(&bc), 0);
	ATF_CHECK_EQ(bc.bc_paused, 2);
	ATF_CHECK_EQ(mevent_disable_calls, 1);

	/* Capacity changes remain invisible until the final owner resumes. */
	ATF_REQUIRE_EQ(ftruncate(fd, PAGE_SIZE), 0);
	blockif_resized(fd, EVF_VNODE, &bc);
	ATF_CHECK_EQ(callback_calls, 0);
	ATF_CHECK_EQ(bc.bc_size, 0);

	/* Releasing checkpoint ownership must preserve guest suspend. */
	blockif_resume(&bc);
	ATF_CHECK_EQ(bc.bc_paused, 1);
	ATF_CHECK_EQ(mevent_enable_calls, 0);
	blockif_resume(&bc);
	ATF_CHECK_EQ(bc.bc_paused, 0);
	ATF_CHECK_EQ(mevent_enable_calls, 1);
	ATF_CHECK_EQ(callback_calls, 1);
	ATF_CHECK_EQ(resize_size, PAGE_SIZE);
	ATF_CHECK_EQ(bc.bc_size, PAGE_SIZE);

	pthread_cond_destroy(&bc.bc_work_done_cond);
	pthread_cond_destroy(&bc.bc_cond);
	pthread_mutex_destroy(&bc.bc_mtx);
	close(fd);
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(suspend_flush_failure_rolls_back);
ATF_TC_BODY(suspend_flush_failure_rolls_back, tc)
{
	struct blockif_ctxt bc;

	init_scheduler(&bc);
	bc.bc_magic = BLOCKIF_SIG;
	bc.bc_fd = -1;
	ATF_REQUIRE_EQ(pthread_mutex_init(&bc.bc_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&bc.bc_cond, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&bc.bc_work_done_cond, NULL), 0);

	ATF_CHECK_EQ(blockif_suspend(&bc), EBADF);
	ATF_CHECK_EQ(bc.bc_paused, 0);

	pthread_cond_destroy(&bc.bc_work_done_cond);
	pthread_cond_destroy(&bc.bc_cond);
	pthread_mutex_destroy(&bc.bc_mtx);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, write_zeroes_file);
	ATF_TP_ADD_TC(tp, write_zeroes_errors);
	ATF_TP_ADD_TC(tp, translated_write_retries_short_pwrite);
	ATF_TP_ADD_TC(tp, translated_read_eof_makes_progress);
	ATF_TP_ADD_TC(tp, translated_write_zero_progress_fails);
	ATF_TP_ADD_TC(tp, delete_uses_operation_range);
	ATF_TP_ADD_TC(tp, delete_rejects_invalid_range);
	ATF_TP_ADD_TC(tp, flush_is_scheduler_barrier);
	ATF_TP_ADD_TC(tp, nested_quiesce_ownership);
	ATF_TP_ADD_TC(tp, suspend_flush_failure_rolls_back);
	return (atf_no_error());
}
