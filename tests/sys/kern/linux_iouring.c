/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * io_uring phase 1: the ring/setup/enter/register foundation.  Sets up a
 * ring, mmaps SQ/CQ/SQES at the IORING_OFF_* offsets using the returned
 * sq_off/cq_off, submits NOP SQEs, drives io_uring_enter, reaps the CQEs
 * (user_data preserved, res==0), batches several, checks REGISTER_PROBE
 * (NOP supported, an unimplemented op not), and validates setup errors.
 * Exit status = failed check number.
 */
#include "linux_test.h"

#define	SYS_io_uring_setup	425
#define	SYS_io_uring_enter	426
#define	SYS_io_uring_register	427
#define	IORING_OFF_SQ_RING	0ULL
#define	IORING_OFF_SQES		0x10000000ULL
#define	IORING_ENTER_GETEVENTS	1
#define	IORING_OP_NOP		0
#define	IORING_REGISTER_PROBE	8
#define	IO_URING_OP_SUPPORTED	1


struct sqe {
	u8 opcode; u8 flags; u16 ioprio; int fd;
	u64 off; u64 addr; u32 len; u32 rw_flags; u64 user_data;
	u16 buf_index; u16 personality; int splice_fd_in; u64 pad2[2];
};
struct cqe { u64 user_data; int res; u32 flags; };
struct sqoff { u32 head, tail, ring_mask, ring_entries, flags, dropped, array, resv1; u64 user_addr; };
struct cqoff { u32 head, tail, ring_mask, ring_entries, overflow, cqes, flags, resv1; u64 user_addr; };
struct params {
	u32 sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle,
	    features, wq_fd, resv[3];
	struct sqoff sq_off;
	struct cqoff cq_off;
};
struct probe_op { u8 op; u8 resv; u16 flags; u32 resv2; };
struct probe { u8 last_op; u8 ops_len; u16 resv; u32 resv2[3]; struct probe_op ops[64]; };

static long
setup(u32 entries, struct params *p)
{
	return (call(SYS_io_uring_setup, entries, (long)p, 0, 0, 0, 0));
}

static int
test(int argc __attribute__((unused)), char **argv __attribute__((unused)),
    char **envp __attribute__((unused)))
{
	struct params p;
	long fd, r, i;
	char *sqbase;
	struct sqe *sqes;
	volatile u32 *sq_tail, *sq_array, *cq_head, *cq_tail;
	struct cqe *cqes;
	u32 ringsz, sqesz;

	/* 1-2: validation. */
	xmemset(&p, 0, sizeof(p));
	if (setup(0, &p) != -EINVAL) return (1);
	xmemset(&p, 0, sizeof(p));
	p.flags = 0x80000000;			/* unknown setup flag */
	if (setup(8, &p) != -EINVAL) return (2);

	/* 3: a plain ring of 8 entries. */
	xmemset(&p, 0, sizeof(p));
	fd = setup(8, &p);
	if (fd < 0) { msgnum("setup ", fd); return (3); }
	if (p.sq_entries != 8 || p.cq_entries < 8) { msgnum("entries ", p.sq_entries); return (3); }

	/* 4: mmap the ring region and the SQE array. */
	ringsz = p.sq_off.array + p.sq_entries * sizeof(u32);
	if (p.cq_off.cqes + p.cq_entries * sizeof(struct cqe) > ringsz)
		ringsz = p.cq_off.cqes + p.cq_entries * sizeof(struct cqe);
	r = call(SYS_mmap, 0, ringsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
	    IORING_OFF_SQ_RING);
	if (r < 0) { msgnum("mmap ring ", r); return (4); }
	sqbase = (char *)r;
	sqesz = p.sq_entries * sizeof(struct sqe);
	r = call(SYS_mmap, 0, sqesz, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
	    IORING_OFF_SQES);
	if (r < 0) { msgnum("mmap sqes ", r); return (4); }
	sqes = (struct sqe *)r;

	sq_tail = (volatile u32 *)(sqbase + p.sq_off.tail);
	sq_array = (volatile u32 *)(sqbase + p.sq_off.array);
	cq_head = (volatile u32 *)(sqbase + p.cq_off.head);
	cq_tail = (volatile u32 *)(sqbase + p.cq_off.tail);
	cqes = (struct cqe *)(sqbase + p.cq_off.cqes);

	/* 5: submit one NOP, reap it, user_data preserved and res==0. */
	xmemset(&sqes[0], 0, sizeof(sqes[0]));
	sqes[0].opcode = IORING_OP_NOP;
	sqes[0].user_data = 0xCAFEF00DULL;
	sq_array[0] = 0;
	__atomic_store_n(sq_tail, 1, __ATOMIC_RELEASE);
	r = call(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0);
	if (r != 1) { msgnum("enter submitted ", r); return (5); }
	if (__atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) != 1) { msgnum("cq_tail ", *cq_tail); return (5); }
	if (cqes[0].user_data != 0xCAFEF00DULL) { msgnum("cqe udata lo ", (long)cqes[0].user_data); return (5); }
	if (cqes[0].res != 0) { msgnum("cqe res ", cqes[0].res); return (5); }
	__atomic_store_n(cq_head, 1, __ATOMIC_RELEASE);

	/* 6: batch of 5 NOPs, each CQE in order with its user_data. */
	for (i = 0; i < 5; i++) {
		xmemset(&sqes[i], 0, sizeof(sqes[i]));
		sqes[i].opcode = IORING_OP_NOP;
		sqes[i].user_data = 0x100 + i;
		sq_array[(1 + i) & (p.sq_entries - 1)] = i;
	}
	__atomic_store_n(sq_tail, 1 + 5, __ATOMIC_RELEASE);
	r = call(SYS_io_uring_enter, fd, 5, 5, IORING_ENTER_GETEVENTS, 0, 0);
	if (r != 5) { msgnum("batch submitted ", r); return (6); }
	for (i = 0; i < 5; i++) {
		u32 h = 1 + i;
		if (cqes[h & (p.cq_entries - 1)].user_data != (u64)(0x100 + i)) {
			msgnum("batch cqe ", (long)cqes[h & (p.cq_entries - 1)].user_data);
			return (6);
		}
	}
	__atomic_store_n(cq_head, 1 + 5, __ATOMIC_RELEASE);

	/* 7: REGISTER_PROBE - NOP supported, an unimplemented op (e.g. 40) not. */
	{
		struct probe pr;

		xmemset(&pr, 0, sizeof(pr));
		r = call(SYS_io_uring_register, fd, IORING_REGISTER_PROBE, (long)&pr, 64, 0, 0);
		if (r != 0) { msgnum("register probe ", r); return (7); }
		if ((pr.ops[IORING_OP_NOP].flags & IO_URING_OP_SUPPORTED) == 0) return (7);
		if ((pr.ops[40].flags & IO_URING_OP_SUPPORTED) != 0) return (7); /* not yet */
		if (pr.last_op == 0) return (7);
	}

	/* 8: enter on a non-ring fd is EOPNOTSUPP. */
	if (call(SYS_io_uring_enter, 0, 0, 0, 0, 0, 0) != -EOPNOTSUPP &&
	    call(SYS_io_uring_enter, 1, 0, 0, 0, 0, 0) != -EOPNOTSUPP)
		return (8);

	(void)sys1(SYS_close, fd);
	return (0);
}
