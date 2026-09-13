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
#define	IORING_OP_READV		1
#define	IORING_OP_WRITEV	2
#define	IORING_OP_FSYNC		3
#define	IORING_OP_READ		22
#define	IORING_OP_WRITE		23
#define	IORING_OP_FALLOCATE	17
#define	IORING_OP_CLOSE		19
#define	IORING_OP_FADVISE	24
#define	IORING_OP_FTRUNCATE	55
#define	IORING_OP_TIMEOUT	11
#define	IORING_OP_TIMEOUT_REMOVE	12
#define	IORING_OP_ASYNC_CANCEL	14
#define	IORING_REGISTER_PROBE	8
#define	IO_URING_OP_SUPPORTED	1

/* SQE flags. */
#define	IOSQE_IO_DRAIN		(1U << 1)
#define	IOSQE_IO_LINK		(1U << 2)
#define	IOSQE_IO_HARDLINK	(1U << 3)
#define	IOSQE_CQE_SKIP_SUCCESS	(1U << 6)
/* TIMEOUT / CANCEL flags and the errnos those ops report (Linux values). */
#define	IORING_TIMEOUT_ETIME_SUCCESS	(1U << 5)
#define	IORING_ASYNC_CANCEL_ALL	(1U << 0)
#define	ELINUX_ETIME		62
#define	ELINUX_ECANCELED	125

struct kts { long long tv_sec; long long tv_nsec; };


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

/* Ring state shared with the submit/reap helper (set up in test()). */
static int fd_ring;
static char *g_sqbase;
static struct sqe *g_sqes;
static volatile u32 *g_sq_tail, *g_sq_array, *g_cq_head, *g_cq_tail;
static struct cqe *g_cqes;
static u32 g_sqmask, g_cqmask, g_sqi, g_cqi;

/* Submit one SQE and reap its single completion; returns the CQE res. */
static int
iou_do(int fd, u8 opcode, void *addr, u32 len, u64 off, u32 rw_flags, u64 ud,
    long *res)
{
	long r;
	u32 slot = g_sqi & g_sqmask;

	xmemset(&g_sqes[slot], 0, sizeof(g_sqes[slot]));
	g_sqes[slot].opcode = opcode;
	g_sqes[slot].fd = fd;
	g_sqes[slot].addr = (u64)(unsigned long)addr;
	g_sqes[slot].len = len;
	g_sqes[slot].off = off;
	g_sqes[slot].rw_flags = rw_flags;
	g_sqes[slot].user_data = ud;
	g_sq_array[g_sqi & g_sqmask] = slot;
	g_sqi++;
	__atomic_store_n(g_sq_tail, g_sqi, __ATOMIC_RELEASE);
	r = call(SYS_io_uring_enter, fd_ring, 1, 1, IORING_ENTER_GETEVENTS, 0, 0);
	if (r != 1)
		return (-1);
	if (__atomic_load_n(g_cq_tail, __ATOMIC_ACQUIRE) != g_cqi + 1)
		return (-2);
	if (g_cqes[g_cqi & g_cqmask].user_data != ud)
		return (-3);
	*res = g_cqes[g_cqi & g_cqmask].res;
	g_cqi++;
	__atomic_store_n(g_cq_head, g_cqi, __ATOMIC_RELEASE);
	return (0);
}

/* ---- phase 4 helpers: build multi-SQE chains, submit, reap by user_data ---- */
/* Stage one SQE into the next submission slot without submitting. */
static void
iou_sqe(u8 opcode, u8 flags, int fd, u64 off, void *addr, u32 len, u32 misc,
    u64 ud)
{
	u32 slot = g_sqi & g_sqmask;

	xmemset(&g_sqes[slot], 0, sizeof(g_sqes[slot]));
	g_sqes[slot].opcode = opcode;
	g_sqes[slot].flags = flags;
	g_sqes[slot].fd = fd;
	g_sqes[slot].off = off;
	g_sqes[slot].addr = (u64)(unsigned long)addr;
	g_sqes[slot].len = len;
	g_sqes[slot].rw_flags = misc;		/* the SQE flags-union word */
	g_sqes[slot].user_data = ud;
	g_sq_array[g_sqi & g_sqmask] = slot;
	g_sqi++;
}

/* Publish the staged SQEs and drive io_uring_enter. */
static long
iou_flush(u32 nsub, u32 nwait)
{
	__atomic_store_n(g_sq_tail, g_sqi, __ATOMIC_RELEASE);
	return (call(SYS_io_uring_enter, fd_ring, nsub, nwait,
	    IORING_ENTER_GETEVENTS, 0, 0));
}

/* Drain all currently-available CQEs into out[]; returns the count. */
static int
iou_reap(struct cqe *out, int max)
{
	u32 tail = __atomic_load_n(g_cq_tail, __ATOMIC_ACQUIRE);
	int n = 0;

	while (g_cqi != tail && n < max) {
		out[n++] = g_cqes[g_cqi & g_cqmask];
		g_cqi++;
	}
	__atomic_store_n(g_cq_head, g_cqi, __ATOMIC_RELEASE);
	return (n);
}

static int
cqe_find(struct cqe *c, int n, u64 ud, int *res)
{
	int i;

	for (i = 0; i < n; i++) {
		if (c[i].user_data == ud) {
			*res = c[i].res;
			return (1);
		}
	}
	return (0);
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

	/* wire the helper to this ring (continue from the current positions). */
	fd_ring = fd;
	g_sqbase = sqbase; g_sqes = sqes; g_cqes = cqes;
	g_sq_tail = sq_tail; g_sq_array = sq_array;
	g_cq_head = cq_head; g_cq_tail = cq_tail;
	g_sqmask = p.sq_entries - 1; g_cqmask = p.cq_entries - 1;
	g_sqi = 1 + 5; g_cqi = 1 + 5;

	/* 7-10: real I/O through the ring against a temp file. */
	{
		long tf = tmpfile_fd("iouring_io");
		char wbuf[16], rbuf[16];
		struct iovec iov[2];
		long res;

		if (tf < 0) return (7);
		/* WRITE "hello!!" at offset 0 */
		for (i = 0; i < 7; i++) wbuf[i] = "hello!!"[i];
		if (iou_do(tf, IORING_OP_WRITE, wbuf, 7, 0, 0, 0x701, &res) != 0) return (7);
		if (res != 7) { msgnum("uring write res ", res); return (7); }
		/* READ 7 bytes back at offset 0 */
		xmemset(rbuf, 0, sizeof(rbuf));
		if (iou_do(tf, IORING_OP_READ, rbuf, 7, 0, 0, 0x702, &res) != 0) return (8);
		if (res != 7 || xmemcmp(rbuf, "hello!!", 7) != 0) { msgnum("uring read res ", res); return (8); }
		/* WRITEV two iovecs "AB","CD" at offset 0 */
		iov[0].iov_base = "AB"; iov[0].iov_len = 2;
		iov[1].iov_base = "CD"; iov[1].iov_len = 2;
		if (iou_do(tf, IORING_OP_WRITEV, iov, 2, 0, 0, 0x703, &res) != 0) return (9);
		if (res != 4) { msgnum("uring writev res ", res); return (9); }
		/* FSYNC */
		if (iou_do(tf, IORING_OP_FSYNC, 0, 0, 0, 0, 0x704, &res) != 0) return (10);
		if (res != 0) { msgnum("uring fsync res ", res); return (10); }
		/* READ back the writev result to confirm "ABCD" */
		xmemset(rbuf, 0, sizeof(rbuf));
		if (iou_do(tf, IORING_OP_READ, rbuf, 4, 0, 0, 0x705, &res) != 0) return (10);
		if (res != 4 || xmemcmp(rbuf, "ABCD", 4) != 0) return (10);
		/* a READ on a bad fd completes with -EBADF, ring stays healthy */
		if (iou_do(9999, IORING_OP_READ, rbuf, 4, 0, 0, 0x706, &res) != 0) return (10);
		if (res != -EBADF) { msgnum("uring badfd res ", res); return (10); }
		/* FTRUNCATE: length is carried in the off field. */
		if (iou_do(tf, IORING_OP_FTRUNCATE, 0, 0, 4096, 0, 0x707, &res) != 0) return (10);
		if (res != 0) { msgnum("ftruncate res ", res); return (10); }
		/* FALLOCATE: off=offset, addr=len, len=mode(0). */
		if (iou_do(tf, IORING_OP_FALLOCATE, (void *)8192, 0, 0, 0, 0x708, &res) != 0) return (10);
		if (res != 0) { msgnum("fallocate res ", res); return (10); }
		/* FADVISE: off=offset, addr=len, advice in the flags union. */
		if (iou_do(tf, IORING_OP_FADVISE, (void *)4096, 0, 0, 3 /* WILLNEED */, 0x709, &res) != 0) return (10);
		if (res != 0) { msgnum("fadvise res ", res); return (10); }
		/* CLOSE the fd through the ring, then a further op on it is EBADF. */
		if (iou_do(tf, IORING_OP_CLOSE, 0, 0, 0, 0, 0x70a, &res) != 0) return (10);
		if (res != 0) { msgnum("ring close res ", res); return (10); }
		if (iou_do(tf, IORING_OP_READ, rbuf, 4, 0, 0, 0x70b, &res) != 0) return (10);
		if (res != -EBADF) { msgnum("post-close read ", res); return (10); }
	}

	/* ---- phase 4: async model (timeout / cancel / links / drain) ---- */
	{
		struct cqe c[8];
		struct kts ts;
		long tf;
		int n, res = 0;

		/* 11: a relative TIMEOUT fires with -ETIME. */
		ts.tv_sec = 0; ts.tv_nsec = 20000000LL;	/* 20 ms */
		iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0, 0, 0xA01);
		if (iou_flush(1, 1) != 1) return (11);
		n = iou_reap(c, 8);
		if (n != 1 || !cqe_find(c, n, 0xA01, &res) || res != -ELINUX_ETIME) {
			msgnum("timeout res ", res); return (11);
		}

		/* 12: a count TIMEOUT completes with 0 once N completions land. */
		ts.tv_sec = 10; ts.tv_nsec = 0;		/* long: count wins */
		iou_sqe(IORING_OP_TIMEOUT, 0, -1, 2 /* off=count */, &ts, 0, 0, 0xA02);
		if (iou_flush(1, 0) != 1) return (12);	/* arm, do not wait */
		iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0xA03);
		iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0xA04);
		if (iou_flush(2, 3) != 2) return (12);	/* 2 NOPs + count timeout */
		n = iou_reap(c, 8);
		if (n != 3) { msgnum("count reap n ", n); return (12); }
		if (!cqe_find(c, n, 0xA02, &res) || res != 0) {
			msgnum("count timeout res ", res); return (12);
		}

		/* 13: ASYNC_CANCEL of an armed timeout: cancel=0, target=-ECANCELED. */
		ts.tv_sec = 30; ts.tv_nsec = 0;
		iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0, 0, 0xA05);
		if (iou_flush(1, 0) != 1) return (13);
		/* cancel keys on sqe->addr == target user_data */
		iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0xA05, 0, 0, 0xA06);
		if (iou_flush(1, 2) != 1) return (13);
		n = iou_reap(c, 8);
		if (!cqe_find(c, n, 0xA06, &res) || res != 0) {
			msgnum("cancel res ", res); return (13);
		}
		if (!cqe_find(c, n, 0xA05, &res) || res != -ELINUX_ECANCELED) {
			msgnum("cancelled timeout res ", res); return (13);
		}

		/* 14: soft link failure cancels the successor. */
		iou_sqe(IORING_OP_READ, IOSQE_IO_LINK, 9999, 0, c, 4, 0, 0xB01);
		iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0xB02);
		if (iou_flush(2, 2) != 2) return (14);
		n = iou_reap(c, 8);
		if (!cqe_find(c, n, 0xB01, &res) || res != -EBADF) {
			msgnum("link head res ", res); return (14);
		}
		if (!cqe_find(c, n, 0xB02, &res) || res != -ELINUX_ECANCELED) {
			msgnum("link tail res ", res); return (14);
		}

		/* 15: async op linked to fd I/O - the WRITE runs after the timeout. */
		tf = tmpfile_fd("iouring_link");
		if (tf < 0) return (15);
		ts.tv_sec = 0; ts.tv_nsec = 20000000LL;
		iou_sqe(IORING_OP_TIMEOUT, IOSQE_IO_LINK, -1, 0, &ts, 0,
		    IORING_TIMEOUT_ETIME_SUCCESS, 0xC01);
		iou_sqe(IORING_OP_WRITE, 0, tf, 0, "hello!!", 7, 0, 0xC02);
		if (iou_flush(2, 2) != 2) return (15);
		n = iou_reap(c, 8);
		if (!cqe_find(c, n, 0xC01, &res) || res != 0) {
			msgnum("link timeout res ", res); return (15);
		}
		if (!cqe_find(c, n, 0xC02, &res) || res != 7) {
			msgnum("linked write res ", res); return (15);
		}
		(void)sys1(SYS_close, tf);

		/* 16: IOSQE_CQE_SKIP_SUCCESS elides the successful head's CQE. */
		iou_sqe(IORING_OP_NOP, IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS,
		    -1, 0, 0, 0, 0, 0xD01);
		iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0xD02);
		if (iou_flush(2, 1) != 2) return (16);
		n = iou_reap(c, 8);
		if (n != 1) { msgnum("skip reap n ", n); return (16); }
		if (c[0].user_data != 0xD02ULL) {
			msgnum("skip udata ", (long)c[0].user_data); return (16);
		}
		if (cqe_find(c, n, 0xD01, &res)) return (16);	/* must be absent */

		/* 17: IOSQE_IO_DRAIN waits for the outstanding timeout first. */
		ts.tv_sec = 0; ts.tv_nsec = 25000000LL;	/* 25 ms */
		iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0, 0, 0xE01);
		if (iou_flush(1, 0) != 1) return (17);
		iou_sqe(IORING_OP_NOP, IOSQE_IO_DRAIN, -1, 0, 0, 0, 0, 0xE02);
		if (iou_flush(1, 2) != 1) return (17);
		n = iou_reap(c, 8);
		if (n != 2) { msgnum("drain reap n ", n); return (17); }
		/* the barrier NOP must be posted after the timeout it drained. */
		if (c[0].user_data != 0xE01ULL || c[1].user_data != 0xE02ULL) {
			msgnum("drain order ", (long)c[0].user_data); return (17);
		}
		if (c[0].res != -ELINUX_ETIME || c[1].res != 0) return (17);
	}

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
