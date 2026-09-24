/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux io_uring ring-resize oracle; each case owns a fresh ring. */
#include "linux_test.h"

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427
#define IORING_REGISTER_RESIZE_RINGS 33
#define IORING_SETUP_CQSIZE (1U << 3)
#define IORING_SETUP_SINGLE_ISSUER (1U << 12)
#define IORING_SETUP_DEFER_TASKRUN (1U << 13)
#define IORING_ENTER_GETEVENTS 1
#define IORING_OFF_SQ_RING 0ULL
#define IORING_OFF_SQES 0x10000000ULL
#define IORING_OP_NOP 0
struct sqoff { u32 head, tail, ring_mask, ring_entries, flags, dropped, array, resv1; u64 user_addr; };
struct cqoff { u32 head, tail, ring_mask, ring_entries, overflow, cqes, flags, resv1; u64 user_addr; };
struct params {
	u32 sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle;
	u32 features, wq_fd, resv[3];
	struct sqoff sq_off;
	struct cqoff cq_off;
};
struct sqe {
	u8 opcode, flags; u16 ioprio; int fd;
	u64 off, addr; u32 len, rw_flags; u64 user_data;
	u16 buf_index, personality; int splice_fd_in; u64 pad2[2];
};
struct cqe { u64 user_data; int res; u32 flags; };
static long
setup(u32 flags)
{
	struct params p = {0};
	p.flags = flags;
	return (sys2(SYS_io_uring_setup, 4, &p));
}
static long
new_ring(u32 flags, struct params *p)
{
	*p = (struct params){0};
	p->flags = flags;
	return (sys2(SYS_io_uring_setup, 4, p));
}
static long
resize(int fd, struct params *p, u32 nr)
{
	return (sys4(SYS_io_uring_register, fd,
	    IORING_REGISTER_RESIZE_RINGS, p, nr));
}
static void
want_size(struct params *p, u32 sq, u32 cq)
{
	*p = (struct params){0};
	p->sq_entries = sq;
	p->cq_entries = cq;
	p->flags = IORING_SETUP_CQSIZE;
}
static int
requires_defer(void)
{
	struct params p;
	long fd, result;

	fd = setup(0);
	if (fd < 0)
		return (1);
	want_size(&p, 8, 16);
	result = resize(fd, &p, 1);
	sys1(SYS_close, fd);
	return (result == -22 ? 0 : 2);
}
static int
bad_arguments(void)
{
	struct params p;
	long fd;
	int error;

	fd = setup(IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN);
	if (fd < 0)
		return (1);
	error = 0;
	want_size(&p, 8, 16);
	if (resize(fd, 0, 1) != -22)
		error = 2;
	if (resize(fd, &p, 0) != -22 || resize(fd, &p, 2) != -22)
		error = 3;
	p.flags |= IORING_SETUP_SINGLE_ISSUER;
	if (resize(fd, &p, 1) != -22)
		error = 4;
	want_size(&p, 8, 16);
	if (resize(fd, (struct params *)1, 1) != -14)
		error = 5;
	sys1(SYS_close, fd);
	return (error);
}
static int
empty_growth_and_shrink(void)
{
	struct params p;
	long fd, ring;
	volatile u32 *entries;
	int error;

	fd = setup(IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN);
	if (fd < 0)
		return (1);
	want_size(&p, 8, 16);
	if (resize(fd, &p, 1) != 0 || p.sq_entries != 8 ||
	    p.cq_entries != 16) {
		error = 2;
		goto out;
	}
	ring = sys6(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, IORING_OFF_SQ_RING);
	if (ring < 0) {
		error = 3;
		goto out;
	}
	entries = (volatile u32 *)(ring + p.sq_off.ring_entries);
	error = *entries != 8 ? 4 : 0;
	sys2(SYS_munmap, ring, 4096);
	if (error != 0)
		goto out;
	want_size(&p, 2, 4);
	if (resize(fd, &p, 1) != 0 || p.sq_entries != 2 ||
	    p.cq_entries != 4)
		error = 5;
out:
	sys1(SYS_close, fd);
	return (error);
}
static int
occupied_shrink(int cq_case)
{
	struct params p, next;
	long fd, ring, sqes;
	volatile u32 *sq_head, *sq_tail, *sq_array, *cq_head, *cq_tail;
	struct sqe *entries;
	int i, error;

	fd = new_ring(IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN, &p);
	if (fd < 0)
		return (1);
	ring = sys6(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fd, IORING_OFF_SQ_RING);
	sqes = sys6(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fd, IORING_OFF_SQES);
	if (ring < 0 || sqes < 0) {
		error = 2;
		goto out;
	}
	sq_head = (volatile u32 *)(ring + p.sq_off.head);
	sq_tail = (volatile u32 *)(ring + p.sq_off.tail);
	sq_array = (volatile u32 *)(ring + p.sq_off.array);
	cq_head = (volatile u32 *)(ring + p.cq_off.head);
	cq_tail = (volatile u32 *)(ring + p.cq_off.tail);
	entries = (struct sqe *)sqes;
	for (i = 0; i < (cq_case ? 4 : 3); i++) {
		entries[i].opcode = IORING_OP_NOP;
		entries[i].user_data = 0x123400 + i;
		sq_array[i] = i;
	}
	__atomic_store_n(sq_tail, cq_case ? 4 : 3, __ATOMIC_RELEASE);
	if (cq_case) {
		if (sys6(SYS_io_uring_enter, fd, 4, 4,
		    IORING_ENTER_GETEVENTS, 0, 0) != 4 || *cq_tail - *cq_head != 4) {
			error = 3;
			goto out;
		}
	}
	want_size(&next, 2, cq_case ? 2 : 4);
	if (resize(fd, &next, 1) != -75 || *sq_head != (cq_case ? 4 : 0)) {
		error = 4;
		goto out;
	}
	if (cq_case)
		__atomic_store_n(cq_head, 4, __ATOMIC_RELEASE);
	else if (sys6(SYS_io_uring_enter, fd, 3, 0, 0, 0, 0) != 3) {
		error = 5;
		goto out;
	}
	want_size(&next, 2, 4);
	if (resize(fd, &next, 1) != 0 || next.sq_entries != 2 ||
	    next.cq_entries != 4) {
		error = 6;
		goto out;
	}
	error = 0;
out:
	if (ring >= 0)
		sys2(SYS_munmap, ring, 4096);
	if (sqes >= 0)
		sys2(SYS_munmap, sqes, 4096);
	sys1(SYS_close, fd);
	return (error);
}
static int pending_sq_shrink(void) { return (occupied_shrink(0)); }
static int pending_cq_shrink(void) { return (occupied_shrink(1)); }
static const struct subtest cases[] = {
	{ "requires_defer", requires_defer },
	{ "bad_arguments", bad_arguments },
	{ "empty_growth_and_shrink", empty_growth_and_shrink },
	{ "pending_sq_shrink", pending_sq_shrink },
	{ "pending_cq_shrink", pending_cq_shrink },
};
static int
test(int argc, char **argv, char **envp __attribute__((unused)))
{
	return (run_subtests(argc, argv, cases,
	    sizeof(cases) / sizeof(cases[0])));
}
