/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Native 5BSD rqueue smoke test: exercises the rqueue_setup/enter/register
 * syscalls directly (no Linux ABI), proving the completion-ring engine is
 * available to native programs.  Exit status = failing check number, 0 = ok.
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/io_uring.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define	OP_NOP		0
#define	OP_TIMEOUT	11
#define	OP_OPENAT	18
#define	OP_READ		22
#define	OP_WRITE	23
#define	ENTER_GETEVENTS	1
#define	OFF_SQ_RING	0ULL
#define	OFF_SQES	0x10000000ULL

static int ring_fd;
static char *sqbase;
static struct io_uring_sqe *sqes;
static volatile uint32_t *sq_tail, *sq_array, *cq_head, *cq_tail;
static struct io_uring_cqe *cqes;
static uint32_t sqmask, cqmask, sqi, cqi;

static long
rq_setup(uint32_t entries, struct io_uring_params *p)
{
	return (syscall(SYS_rqueue_setup, entries, p));
}

static int
ring_init(uint32_t entries)
{
	struct io_uring_params p;
	long r;
	uint32_t ringsz, sqesz;

	memset(&p, 0, sizeof(p));
	r = rq_setup(entries, &p);
	if (r < 0)
		return (-1);
	ring_fd = (int)r;
	ringsz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
	if (p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe) > ringsz)
		ringsz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
	sqbase = mmap(NULL, ringsz, PROT_READ | PROT_WRITE, MAP_SHARED, ring_fd,
	    OFF_SQ_RING);
	if (sqbase == MAP_FAILED)
		return (-1);
	sqesz = p.sq_entries * sizeof(struct io_uring_sqe);
	sqes = mmap(NULL, sqesz, PROT_READ | PROT_WRITE, MAP_SHARED, ring_fd,
	    OFF_SQES);
	if (sqes == MAP_FAILED)
		return (-1);
	sq_tail = (volatile uint32_t *)(sqbase + p.sq_off.tail);
	sq_array = (volatile uint32_t *)(sqbase + p.sq_off.array);
	cq_head = (volatile uint32_t *)(sqbase + p.cq_off.head);
	cq_tail = (volatile uint32_t *)(sqbase + p.cq_off.tail);
	cqes = (struct io_uring_cqe *)(sqbase + p.cq_off.cqes);
	sqmask = p.sq_entries - 1;
	cqmask = p.cq_entries - 1;
	sqi = cqi = 0;
	return (0);
}

/* submit one sqe, reap one cqe; returns res, or a sentinel on framing error */
static int
one(uint8_t op, int fd, void *addr, uint32_t len, uint64_t off, uint32_t misc,
    uint64_t ud)
{
	uint32_t slot = sqi & sqmask;
	long r;

	memset(&sqes[slot], 0, sizeof(sqes[slot]));
	sqes[slot].opcode = op;
	sqes[slot].fd = fd;
	sqes[slot].addr = (uint64_t)(uintptr_t)addr;
	sqes[slot].len = len;
	sqes[slot].off = off;
	sqes[slot].rw_flags = misc;
	sqes[slot].user_data = ud;
	sq_array[sqi & sqmask] = slot;
	sqi++;
	__atomic_store_n(sq_tail, sqi, __ATOMIC_RELEASE);
	r = syscall(SYS_rqueue_enter, ring_fd, 1, 1, ENTER_GETEVENTS, NULL, 0);
	if (r != 1)
		return (-100000);
	if (__atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) != cqi + 1)
		return (-100001);
	if (cqes[cqi & cqmask].user_data != ud)
		return (-100002);
	r = cqes[cqi & cqmask].res;
	cqi++;
	__atomic_store_n(cq_head, cqi, __ATOMIC_RELEASE);
	return ((int)r);
}

int
main(void)
{
	char wbuf[16], rbuf[16];
	int fd;

	/* 1: setup + mmap */
	if (ring_init(8) != 0)
		return (1);

	/* 2: NOP round-trips through the native ring */
	if (one(OP_NOP, -1, NULL, 0, 0, 0, 0x1) != 0)
		return (2);

	/* 3: real WRITE/READ on a temp file (neutral opcode, native) */
	(void)unlink("/tmp/rqueue_native.tmp");
	fd = open("/tmp/rqueue_native.tmp", O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0)
		return (3);
	memcpy(wbuf, "rqueue!", 7);
	if (one(OP_WRITE, fd, wbuf, 7, 0, 0, 0x2) != 7)
		return (4);
	memset(rbuf, 0, sizeof(rbuf));
	if (one(OP_READ, fd, rbuf, 7, 0, 0, 0x3) != 7 ||
	    memcmp(rbuf, "rqueue!", 7) != 0)
		return (5);
	(void)close(fd);
	(void)unlink("/tmp/rqueue_native.tmp");

	/* 4: a bad-fd READ reports a negative BSD errno (native, not Linux) */
	if (one(OP_READ, 9999, rbuf, 4, 0, 0, 0x4) != -EBADF)
		return (6);

	/* 5: a Linux-flavored opcode has no native handler -> -EINVAL */
	if (one(OP_OPENAT, -100 /* AT_FDCWD */, "/nonexistent", 0, 0, 0, 0x5)
	    != -EINVAL)
		return (7);

	/* 6: TIMEOUT completes with the native errno -ETIMEDOUT */
	{
		struct { int64_t tv_sec; int64_t tv_nsec; } ts = { 0, 20000000 };

		if (one(OP_TIMEOUT, -1, &ts, 0, 0, 0, 0x6) != -ETIMEDOUT)
			return (8);
	}

	(void)syscall(SYS_close, ring_fd);
	return (0);
}
