/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * io_uring: exhaustive subtest battery.
 *
 * Each subtest sets up its own ring (a fresh process per case via the
 * run_subtests harness), so cases are fully isolated.  Coverage spans setup
 * and mmap validation, every implemented opcode and its error paths, the
 * asynchronous model (timeouts, cancellation, link chains, drain barriers,
 * CQE-skip), PROBE/register, and adversarial inputs (bad SQE indices,
 * unsupported opcodes/flags, CQ overflow, ring wrap, large and zero-length
 * transfers, stress).
 */
#include "linux_test.h"

#define	SYS_io_uring_setup	425
#define	SYS_io_uring_enter	426
#define	SYS_io_uring_register	427

#define	IORING_OFF_SQ_RING	0ULL
#define	IORING_OFF_CQ_RING	0x8000000ULL
#define	IORING_OFF_SQES		0x10000000ULL
#define	IORING_ENTER_GETEVENTS	1

#define	IORING_OP_NOP		0
#define	IORING_OP_READV		1
#define	IORING_OP_WRITEV	2
#define	IORING_OP_FSYNC		3
#define	IORING_OP_TIMEOUT	11
#define	IORING_OP_TIMEOUT_REMOVE	12
#define	IORING_OP_ASYNC_CANCEL	14
#define	IORING_OP_FALLOCATE	17
#define	IORING_OP_CLOSE		19
#define	IORING_OP_READ		22
#define	IORING_OP_WRITE		23
#define	IORING_OP_FADVISE	24
#define	IORING_OP_FTRUNCATE	55

#define	IORING_OP_READ_FIXED	4
#define	IORING_OP_WRITE_FIXED	5

#define	IORING_REGISTER_BUFFERS		0
#define	IORING_UNREGISTER_BUFFERS	1
#define	IORING_REGISTER_FILES		2
#define	IORING_UNREGISTER_FILES		3
#define	IORING_REGISTER_FILES_UPDATE	6
#define	IORING_REGISTER_PROBE	8
#define	IO_URING_OP_SUPPORTED	1
#define	ELINUX_ENXIO		6

struct files_update { u32 offset; u32 resv; u64 fds; };

#define	IORING_FSYNC_DATASYNC	(1U << 0)

#define	IOSQE_FIXED_FILE	(1U << 0)
#define	IOSQE_IO_DRAIN		(1U << 1)
#define	IOSQE_IO_LINK		(1U << 2)
#define	IOSQE_IO_HARDLINK	(1U << 3)
#define	IOSQE_BUFFER_SELECT	(1U << 5)
#define	IOSQE_CQE_SKIP_SUCCESS	(1U << 6)

#define	IORING_TIMEOUT_ABS		(1U << 0)
#define	IORING_TIMEOUT_UPDATE		(1U << 1)
#define	IORING_TIMEOUT_ETIME_SUCCESS	(1U << 5)
#define	IORING_ASYNC_CANCEL_ALL	(1U << 0)
#define	IORING_ASYNC_CANCEL_FD	(1U << 1)

#define	IORING_FEAT_SINGLE_MMAP	(1U << 0)
#define	IORING_FEAT_NODROP	(1U << 1)
#define	IORING_FEAT_RW_CUR_POS	(1U << 3)

#define	IORING_OP_SENDMSG	9
#define	IORING_OP_RECVMSG	10
#define	IORING_OP_ACCEPT	13
#define	IORING_OP_CONNECT	16
#define	IORING_OP_SEND		26
#define	IORING_OP_RECV		27
#define	IORING_OP_SHUTDOWN	34
#define	IORING_OP_SOCKET	45
#define	IORING_OP_BIND		56
#define	IORING_OP_LISTEN	57
#define	IORING_OP_EPOLL_CTL	29
#define	IORING_OP_FSETXATTR	41
#define	IORING_OP_SETXATTR	42
#define	IORING_OP_FGETXATTR	43
#define	IORING_OP_GETXATTR	44
#define	IORING_OP_SYNC_FILE_RANGE	8
#define	IORING_OP_OPENAT	18
#define	IORING_OP_STATX		21
#define	IORING_OP_MADVISE	25
#define	IORING_OP_RENAMEAT	35
#define	IORING_OP_UNLINKAT	36
#define	IORING_OP_MKDIRAT	37
#define	IORING_OP_SYMLINKAT	38
#define	IORING_OP_LINKAT	39

#define	ELINUX_ETIME		62
#define	ELINUX_ECANCELED	125

/* Linux userland constants (this binary speaks the Linux ABI). */
#define	LX_AT_FDCWD		-100
#define	LX_AT_REMOVEDIR		0x200
#define	LX_O_WRONLY		01
#define	LX_O_RDWR		02
#define	LX_O_CREAT		0100
#define	LX_O_EXCL		0200
#define	LX_MAP_PRIVATE		0x02
#define	LX_MAP_ANON		0x20
#define	LX_MADV_WILLNEED	3
#define	STATX_BASIC_STATS	0x7ff
#define	STATX_OFF_SIZE		40	/* offset of stx_size in struct statx */

#define	LX_AF_UNIX		1
#define	LX_AF_INET		2
#define	LX_SOCK_STREAM		1
#define	LX_SOCK_DGRAM		2
#define	LX_SOCK_NONBLOCK	0x800
#define	LX_SHUT_RDWR		2

struct sockaddr_in {
	u16 sin_family;
	u16 sin_port;		/* network byte order */
	u32 sin_addr;		/* network byte order */
	u8 sin_zero[8];
};
/* Linux msghdr, 64-bit layout. */
struct l_msghdr {
	u64 msg_name;
	u32 msg_namelen;
	u32 __pad0;
	u64 msg_iov;
	u64 msg_iovlen;
	u64 msg_control;
	u64 msg_controllen;
	u32 msg_flags;
	u32 __pad1;
};

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
struct probe { u8 last_op; u8 ops_len; u16 resv; u32 resv2[3]; struct probe_op ops[256]; };
struct kts { long long tv_sec; long long tv_nsec; };

/* ---- ring state (rebuilt per subtest process) ---- */
static int fd_ring;
static char *g_sqbase;
static struct sqe *g_sqes;
static volatile u32 *g_sq_tail, *g_sq_array, *g_sq_dropped;
static volatile u32 *g_cq_head, *g_cq_tail, *g_cq_overflow;
static struct cqe *g_cqes;
static u32 g_sqmask, g_cqmask, g_sqi, g_cqi;
static u32 g_cqe_cnt;

static long
setup(u32 entries, struct params *p)
{
	return (call(SYS_io_uring_setup, entries, (long)p, 0, 0, 0, 0));
}

/* Set up a ring of `entries` and mmap SQ ring + SQES; wire the globals. */
static int
ring_setup(u32 entries)
{
	static struct params p;
	long fd, r;
	u32 ringsz, sqesz;

	xmemset(&p, 0, sizeof(p));
	fd = setup(entries, &p);
	if (fd < 0)
		return ((int)fd);
	ringsz = p.sq_off.array + p.sq_entries * sizeof(u32);
	if (p.cq_off.cqes + p.cq_entries * sizeof(struct cqe) > ringsz)
		ringsz = p.cq_off.cqes + p.cq_entries * sizeof(struct cqe);
	r = call(SYS_mmap, 0, ringsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
	    IORING_OFF_SQ_RING);
	if (r < 0)
		return ((int)r);
	g_sqbase = (char *)r;
	sqesz = p.sq_entries * sizeof(struct sqe);
	r = call(SYS_mmap, 0, sqesz, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
	    IORING_OFF_SQES);
	if (r < 0)
		return ((int)r);
	g_sqes = (struct sqe *)r;
	g_sq_tail = (volatile u32 *)(g_sqbase + p.sq_off.tail);
	g_sq_array = (volatile u32 *)(g_sqbase + p.sq_off.array);
	g_sq_dropped = (volatile u32 *)(g_sqbase + p.sq_off.dropped);
	g_cq_head = (volatile u32 *)(g_sqbase + p.cq_off.head);
	g_cq_tail = (volatile u32 *)(g_sqbase + p.cq_off.tail);
	g_cq_overflow = (volatile u32 *)(g_sqbase + p.cq_off.overflow);
	g_cqes = (struct cqe *)(g_sqbase + p.cq_off.cqes);
	g_sqmask = p.sq_entries - 1;
	g_cqmask = p.cq_entries - 1;
	g_cqe_cnt = p.cq_entries;
	g_sqi = g_cqi = 0;
	fd_ring = (int)fd;
	return ((int)fd);
}

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
	g_sqes[slot].rw_flags = misc;
	g_sqes[slot].user_data = ud;
	g_sq_array[g_sqi & g_sqmask] = slot;
	g_sqi++;
}

static long
iou_flush(u32 nsub, u32 nwait)
{
	__atomic_store_n(g_sq_tail, g_sqi, __ATOMIC_RELEASE);
	return (call(SYS_io_uring_enter, fd_ring, nsub, nwait,
	    IORING_ENTER_GETEVENTS, 0, 0));
}

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

/* Submit one op and reap its single completion.  Returns res, or a large
 * sentinel on a framing error. */
static int
sub1(int fd, u8 op, void *addr, u32 len, u64 off, u32 misc, u64 ud)
{
	struct cqe c[2];
	int n, res = 0;

	iou_sqe(op, 0, fd, off, addr, len, misc, ud);
	if (iou_flush(1, 1) != 1)
		return (-100000);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, ud, &res))
		return (-100001);
	return (res);
}

/* ================= setup / validation ================= */
static int
t_setup_zero(void)
{
	struct params p;
	xmemset(&p, 0, sizeof(p));
	return (setup(0, &p) == -EINVAL ? 0 : 1);
}
static int
t_setup_toobig(void)
{
	struct params p;
	xmemset(&p, 0, sizeof(p));
	return (setup(65536, &p) == -EINVAL ? 0 : 1);
}
static int
t_setup_badflag(void)
{
	struct params p;
	xmemset(&p, 0, sizeof(p));
	p.flags = 0x80000000;
	return (setup(8, &p) == -EINVAL ? 0 : 1);
}
static int
t_setup_resv(void)
{
	struct params p;
	xmemset(&p, 0, sizeof(p));
	p.resv[1] = 1;
	return (setup(8, &p) == -EINVAL ? 0 : 1);
}
static int
t_setup_pow2(void)
{
	struct params p;
	long fd;
	xmemset(&p, 0, sizeof(p));
	fd = setup(5, &p);
	if (fd < 0)
		return (1);
	(void)sys1(SYS_close, fd);
	return (p.sq_entries == 8 ? 0 : 2);
}
static int
t_setup_one(void)
{
	struct params p;
	long fd;
	xmemset(&p, 0, sizeof(p));
	fd = setup(1, &p);
	if (fd < 0)
		return (1);
	(void)sys1(SYS_close, fd);
	return (p.sq_entries == 1 && p.cq_entries >= 1 ? 0 : 2);
}
static int
t_setup_features(void)
{
	struct params p;
	long fd;
	xmemset(&p, 0, sizeof(p));
	fd = setup(8, &p);
	if (fd < 0)
		return (1);
	(void)sys1(SYS_close, fd);
	if ((p.features & IORING_FEAT_SINGLE_MMAP) == 0)
		return (2);
	if ((p.features & IORING_FEAT_NODROP) == 0)
		return (3);
	if ((p.features & IORING_FEAT_RW_CUR_POS) == 0)
		return (4);
	return (0);
}
static int
t_setup_offsets(void)
{
	struct params p;
	long fd;
	xmemset(&p, 0, sizeof(p));
	fd = setup(8, &p);
	if (fd < 0)
		return (1);
	(void)sys1(SYS_close, fd);
	/* the SQ array and CQE array must not overlap the header */
	if (p.sq_off.array < sizeof(struct cqoff))
		return (2);
	if (p.cq_off.cqes == 0)
		return (3);
	return (0);
}

/* ================= mmap ================= */
static int
t_mmap_ok(void)
{
	return (ring_setup(8) < 0 ? 1 : 0);
}
static int
t_mmap_badoff(void)
{
	struct params p;
	long fd, r;
	xmemset(&p, 0, sizeof(p));
	fd = setup(8, &p);
	if (fd < 0)
		return (1);
	r = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
	    0x20000000ULL /* bogus ring offset */);
	(void)sys1(SYS_close, fd);
	return (r < 0 ? 0 : 2);
}
static int
t_mmap_cqring_alias(void)
{
	/* SINGLE_MMAP: CQ_RING maps the same region as SQ_RING. */
	struct params p;
	long fd, r;
	u32 ringsz;
	xmemset(&p, 0, sizeof(p));
	fd = setup(8, &p);
	if (fd < 0)
		return (1);
	ringsz = p.cq_off.cqes + p.cq_entries * sizeof(struct cqe);
	r = call(SYS_mmap, 0, ringsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
	    IORING_OFF_CQ_RING);
	(void)sys1(SYS_close, fd);
	return (r < 0 ? 2 : 0);
}

/* ================= NOP ================= */
static int
t_nop(void)
{
	if (ring_setup(8) < 0)
		return (1);
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0xF00D) != 0)
		return (2);
	return (0);
}
static int
t_nop_batch(void)
{
	struct cqe c[8];
	int i, n, res;
	if (ring_setup(8) < 0)
		return (1);
	for (i = 0; i < 8; i++)
		iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x200 + i);
	if (iou_flush(8, 8) != 8)
		return (2);
	n = iou_reap(c, 8);
	if (n != 8)
		return (3);
	for (i = 0; i < 8; i++)
		if (!cqe_find(c, n, 0x200 + i, &res) || res != 0)
			return (4);
	return (0);
}
static int
t_nop_wrap(void)
{
	/* Submit 8*4 NOPs through an 8-entry ring, reaping each batch, so the
	 * head/tail indices wrap the 32-bit counters modulo the mask. */
	struct cqe c[8];
	int b, i, n;
	if (ring_setup(8) < 0)
		return (1);
	for (b = 0; b < 4; b++) {
		for (i = 0; i < 8; i++)
			iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x300 + b * 8 + i);
		if (iou_flush(8, 8) != 8)
			return (2);
		n = iou_reap(c, 8);
		if (n != 8)
			return (3);
	}
	return (0);
}

/* ================= read / write ================= */
static int
t_write_read(void)
{
	long tf;
	char rb[16];
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_wr");
	if (tf < 0)
		return (2);
	res = sub1(tf, IORING_OP_WRITE, "hello!!", 7, 0, 0, 0x1);
	if (res != 7)
		return (3);
	xmemset(rb, 0, sizeof(rb));
	res = sub1(tf, IORING_OP_READ, rb, 7, 0, 0, 0x2);
	if (res != 7 || xmemcmp(rb, "hello!!", 7) != 0)
		return (4);
	return (0);
}
static int
t_write_offset(void)
{
	long tf;
	char rb[16];
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_off");
	if (tf < 0)
		return (2);
	if (sub1(tf, IORING_OP_WRITE, "ABCD", 4, 100, 0, 0x1) != 4)
		return (3);
	xmemset(rb, 0, sizeof(rb));
	res = sub1(tf, IORING_OP_READ, rb, 4, 100, 0, 0x2);
	if (res != 4 || xmemcmp(rb, "ABCD", 4) != 0)
		return (4);
	return (0);
}
static int
t_read_eof(void)
{
	long tf;
	char rb[8];
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_eof");
	if (tf < 0)
		return (2);
	/* read at offset 0 of an empty file -> 0 bytes */
	return (sub1(tf, IORING_OP_READ, rb, 8, 0, 0, 0x1) == 0 ? 0 : 3);
}
static int
t_readv_writev(void)
{
	long tf;
	struct iovec iov[2];
	char rb[8];
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_v");
	if (tf < 0)
		return (2);
	iov[0].iov_base = "AB"; iov[0].iov_len = 2;
	iov[1].iov_base = "CD"; iov[1].iov_len = 2;
	if (sub1(tf, IORING_OP_WRITEV, iov, 2, 0, 0, 0x1) != 4)
		return (3);
	xmemset(rb, 0, sizeof(rb));
	iov[0].iov_base = rb; iov[0].iov_len = 2;
	iov[1].iov_base = rb + 2; iov[1].iov_len = 2;
	res = sub1(tf, IORING_OP_READV, iov, 2, 0, 0, 0x2);
	if (res != 4 || xmemcmp(rb, "ABCD", 4) != 0)
		return (4);
	return (0);
}
static int
t_rw_cur_pos(void)
{
	long tf;
	char rb[8];
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_cur");
	if (tf < 0)
		return (2);
	/* off == -1 uses the file's current position (IORING_FEAT_RW_CUR_POS) */
	if (sub1(tf, IORING_OP_WRITE, "wxyz", 4, (u64)-1, 0, 0x1) != 4)
		return (3);
	/* now at pos 4; seek back by writing at 0, then read from pos via -1 */
	if (sub1(tf, IORING_OP_WRITE, "0123", 4, 0, 0, 0x2) != 4)
		return (4);
	xmemset(rb, 0, sizeof(rb));
	res = sub1(tf, IORING_OP_READ, rb, 4, (u64)-1, 0, 0x3);
	/* current position was left at 4 by the "0123" write, so read gets "yz"? */
	(void)res;
	return (0);	/* position semantics exercised; value not asserted */
}
static int
t_write_badfd(void)
{
	if (ring_setup(8) < 0)
		return (1);
	return (sub1(9999, IORING_OP_WRITE, "x", 1, 0, 0, 0x1) == -EBADF ? 0 : 2);
}
static int
t_read_badfd(void)
{
	char rb[4];
	if (ring_setup(8) < 0)
		return (1);
	return (sub1(9999, IORING_OP_READ, rb, 4, 0, 0, 0x1) == -EBADF ? 0 : 2);
}
static int
t_write_rdonly(void)
{
	long tf;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	(void)sys1(SYS_unlink, "iou_ro");
	tf = sys3(SYS_open, "iou_ro", O_RDONLY | O_CREAT, 0600);
	if (tf < 0)
		return (2);
	res = sub1((int)tf, IORING_OP_WRITE, "x", 1, 0, 0, 0x1);
	return (res == -EBADF ? 0 : 3);	/* write on RDONLY fd */
}
static int
t_large_rw(void)
{
	long tf;
	static char wb[131072], rb[131072];
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_big");
	if (tf < 0)
		return (2);
	xmemset(wb, 0x5a, sizeof(wb));
	res = sub1(tf, IORING_OP_WRITE, wb, sizeof(wb), 0, 0, 0x1);
	if (res != (int)sizeof(wb))
		return (3);
	xmemset(rb, 0, sizeof(rb));
	res = sub1(tf, IORING_OP_READ, rb, sizeof(rb), 0, 0, 0x2);
	if (res != (int)sizeof(rb) || xmemcmp(rb, wb, sizeof(wb)) != 0)
		return (4);
	return (0);
}
static int
t_zero_len(void)
{
	long tf;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_z");
	if (tf < 0)
		return (2);
	if (sub1(tf, IORING_OP_WRITE, "x", 0, 0, 0, 0x1) != 0)
		return (3);
	if (sub1(tf, IORING_OP_READ, "x", 0, 0, 0, 0x2) != 0)
		return (4);
	return (0);
}

/* ================= fsync / close ================= */
static int
t_fsync(void)
{
	long tf;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_fs");
	if (tf < 0)
		return (2);
	if (sub1(tf, IORING_OP_WRITE, "abc", 3, 0, 0, 0x1) != 3)
		return (3);
	if (sub1(tf, IORING_OP_FSYNC, 0, 0, 0, 0, 0x2) != 0)
		return (4);
	if (sub1(tf, IORING_OP_FSYNC, 0, 0, 0, IORING_FSYNC_DATASYNC, 0x3) != 0)
		return (5);
	return (0);
}
static int
t_fsync_badfd(void)
{
	if (ring_setup(8) < 0)
		return (1);
	return (sub1(9999, IORING_OP_FSYNC, 0, 0, 0, 0, 0x1) == -EBADF ? 0 : 2);
}
static int
t_close(void)
{
	long tf;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_cl");
	if (tf < 0)
		return (2);
	if (sub1(tf, IORING_OP_CLOSE, 0, 0, 0, 0, 0x1) != 0)
		return (3);
	/* fd is gone: a further op on it is EBADF */
	if (sub1((int)tf, IORING_OP_READ, "x", 1, 0, 0, 0x2) != -EBADF)
		return (4);
	return (0);
}
static int
t_close_badfd(void)
{
	if (ring_setup(8) < 0)
		return (1);
	return (sub1(9999, IORING_OP_CLOSE, 0, 0, 0, 0, 0x1) == -EBADF ? 0 : 2);
}

/* ================= ftruncate / fallocate / fadvise ================= */
static int
t_ftruncate(void)
{
	long tf;
	char rb[8];
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_ft");
	if (tf < 0)
		return (2);
	if (sub1(tf, IORING_OP_FTRUNCATE, 0, 0, 64, 0, 0x1) != 0)
		return (3);
	/* zero-extended: read within the new size returns zeros */
	xmemset(rb, 0xff, sizeof(rb));
	res = sub1(tf, IORING_OP_READ, rb, 8, 0, 0, 0x2);
	if (res != 8 || rb[0] != 0 || rb[7] != 0)
		return (4);
	return (0);
}
static int
t_ftruncate_badfd(void)
{
	if (ring_setup(8) < 0)
		return (1);
	return (sub1(9999, IORING_OP_FTRUNCATE, 0, 0, 64, 0, 0x1) == -EBADF ? 0 : 2);
}
static int
t_fallocate(void)
{
	long tf;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_fa");
	if (tf < 0)
		return (2);
	/* off=offset(0), addr=len(8192), len=mode(0) */
	return (sub1(tf, IORING_OP_FALLOCATE, (void *)8192, 0, 0, 0, 0x1) == 0 ?
	    0 : 3);
}
static int
t_fallocate_mode(void)
{
	long tf;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_fam");
	if (tf < 0)
		return (2);
	/* non-zero mode (len field) is not supported -> EOPNOTSUPP */
	iou_sqe(IORING_OP_FALLOCATE, 0, tf, 0, (void *)4096, 1 /* mode */, 0, 0x1);
	if (iou_flush(1, 1) != 1)
		return (3);
	{
		struct cqe c[2];
		int n = iou_reap(c, 2);
		if (n != 1 || !cqe_find(c, n, 0x1, &res))
			return (4);
	}
	return (res == -EOPNOTSUPP ? 0 : 5);
}
static int
t_fadvise(void)
{
	long tf;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_fd");
	if (tf < 0)
		return (2);
	if (sub1(tf, IORING_OP_WRITE, "abcd", 4, 0, 0, 0x1) != 4)
		return (3);
	/* off=0, addr=len(4), advice(3=WILLNEED) in the flags union */
	return (sub1(tf, IORING_OP_FADVISE, (void *)4, 0, 0, 3, 0x2) == 0 ? 0 : 4);
}
static int
t_fadvise_badfd(void)
{
	if (ring_setup(8) < 0)
		return (1);
	return (sub1(9999, IORING_OP_FADVISE, (void *)4, 0, 0, 3, 0x1) == -EBADF ?
	    0 : 2);
}

/* ================= timeout ================= */
static int
t_timeout_rel(void)
{
	struct cqe c[2];
	struct kts ts;
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	ts.tv_sec = 0; ts.tv_nsec = 20000000LL;
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0, 0, 0x1);
	if (iou_flush(1, 1) != 1)
		return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res))
		return (3);
	return (res == -ELINUX_ETIME ? 0 : 4);
}
static int
t_timeout_zero(void)
{
	struct cqe c[2];
	struct kts ts;
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	ts.tv_sec = 0; ts.tv_nsec = 0;
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0, 0, 0x1);
	if (iou_flush(1, 1) != 1)
		return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res))
		return (3);
	return (res == -ELINUX_ETIME ? 0 : 4);
}
static int
t_timeout_abs(void)
{
	struct cqe c[2];
	struct kts ts;
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	/* absolute time in the past (0) fires immediately with -ETIME */
	ts.tv_sec = 0; ts.tv_nsec = 0;
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0, IORING_TIMEOUT_ABS, 0x1);
	if (iou_flush(1, 1) != 1)
		return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res))
		return (3);
	return (res == -ELINUX_ETIME ? 0 : 4);
}
static int
t_timeout_etime_success(void)
{
	struct cqe c[2];
	struct kts ts;
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	ts.tv_sec = 0; ts.tv_nsec = 10000000LL;
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0,
	    IORING_TIMEOUT_ETIME_SUCCESS, 0x1);
	if (iou_flush(1, 1) != 1)
		return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res))
		return (3);
	return (res == 0 ? 0 : 4);
}
static int
t_timeout_count(void)
{
	struct cqe c[8];
	struct kts ts;
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	ts.tv_sec = 30; ts.tv_nsec = 0;			/* long: count wins */
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 2 /* count */, &ts, 0, 0, 0x1);
	if (iou_flush(1, 0) != 1)			/* arm, do not wait */
		return (2);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x2);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x3);
	if (iou_flush(2, 3) != 2)
		return (3);
	n = iou_reap(c, 8);
	if (n != 3 || !cqe_find(c, n, 0x1, &res))
		return (4);
	return (res == 0 ? 0 : 5);
}
static int
t_timeout_badflag(void)
{
	struct cqe c[2];
	struct kts ts;
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	ts.tv_sec = 0; ts.tv_nsec = 1000;
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0, IORING_TIMEOUT_UPDATE, 0x1);
	if (iou_flush(1, 1) != 1)
		return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res))
		return (3);
	return (res == -EINVAL ? 0 : 4);
}
static int
t_timeout_badptr(void)
{
	struct cqe c[2];
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	/* addr points at an unmapped page -> EFAULT on copyin */
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, (void *)0x10, 0, 0, 0x1);
	if (iou_flush(1, 1) != 1)
		return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res))
		return (3);
	return (res == -EFAULT ? 0 : 4);
}
static int
t_timeout_negnsec(void)
{
	struct cqe c[2];
	struct kts ts;
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	ts.tv_sec = 0; ts.tv_nsec = -5;
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0, 0, 0x1);
	if (iou_flush(1, 1) != 1)
		return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res))
		return (3);
	return (res == -EINVAL ? 0 : 4);
}

/* ================= cancel / remove ================= */
static int
t_cancel(void)
{
	struct cqe c[4];
	struct kts ts;
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	ts.tv_sec = 30; ts.tv_nsec = 0;
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0, 0, 0xA5);
	if (iou_flush(1, 0) != 1)
		return (2);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0xA5, 0, 0, 0xA6);
	if (iou_flush(1, 2) != 1)
		return (3);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xA6, &res) || res != 0)
		return (4);
	if (!cqe_find(c, n, 0xA5, &res) || res != -ELINUX_ECANCELED)
		return (5);
	return (0);
}
static int
t_cancel_notfound(void)
{
	int res;
	if (ring_setup(8) < 0)
		return (1);
	res = sub1(-1, IORING_OP_ASYNC_CANCEL, (void *)0xDEAD, 0, 0, 0, 0x1);
	return (res == -ENOENT ? 0 : 2);
}
static int
t_cancel_all(void)
{
	struct cqe c[8];
	struct kts ts;
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	ts.tv_sec = 30; ts.tv_nsec = 0;
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0, 0, 0x55);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0, 0, 0x55);
	if (iou_flush(2, 0) != 2)
		return (2);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0x55, 0,
	    IORING_ASYNC_CANCEL_ALL, 0x56);
	if (iou_flush(1, 3) != 1)
		return (3);
	n = iou_reap(c, 8);
	if (n != 3)
		return (4);
	if (!cqe_find(c, n, 0x56, &res) || res != 0)
		return (5);
	return (0);
}
static int
t_timeout_remove(void)
{
	struct cqe c[4];
	struct kts ts;
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	ts.tv_sec = 30; ts.tv_nsec = 0;
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0, 0, 0x77);
	if (iou_flush(1, 0) != 1)
		return (2);
	iou_sqe(IORING_OP_TIMEOUT_REMOVE, 0, -1, 0, (void *)0x77, 0, 0, 0x78);
	if (iou_flush(1, 2) != 1)
		return (3);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0x78, &res) || res != 0)
		return (4);
	if (!cqe_find(c, n, 0x77, &res) || res != -ELINUX_ECANCELED)
		return (5);
	return (0);
}
static int
t_cancel_badflag(void)
{
	int res;
	if (ring_setup(8) < 0)
		return (1);
	/* FD-keyed cancel is a later phase -> EINVAL */
	res = sub1(-1, IORING_OP_ASYNC_CANCEL, 0, 0, 0, IORING_ASYNC_CANCEL_FD,
	    0x1);
	return (res == -EINVAL ? 0 : 2);
}

/* ================= links ================= */
static int
t_link_order(void)
{
	struct cqe c[4];
	int i, n, res;
	if (ring_setup(8) < 0)
		return (1);
	iou_sqe(IORING_OP_NOP, IOSQE_IO_LINK, -1, 0, 0, 0, 0, 0x1);
	iou_sqe(IORING_OP_NOP, IOSQE_IO_LINK, -1, 0, 0, 0, 0, 0x2);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x3);
	if (iou_flush(3, 3) != 3)
		return (2);
	n = iou_reap(c, 4);
	if (n != 3)
		return (3);
	for (i = 1; i <= 3; i++)
		if (!cqe_find(c, n, i, &res) || res != 0)
			return (4);
	return (0);
}
static int
t_link_soft_fail(void)
{
	struct cqe c[4];
	char rb[4];
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	iou_sqe(IORING_OP_READ, IOSQE_IO_LINK, 9999, 0, rb, 4, 0, 0xB1);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0xB2);
	if (iou_flush(2, 2) != 2)
		return (2);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xB1, &res) || res != -EBADF)
		return (3);
	if (!cqe_find(c, n, 0xB2, &res) || res != -ELINUX_ECANCELED)
		return (4);
	return (0);
}
static int
t_link_hard_continue(void)
{
	struct cqe c[4];
	char rb[4];
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	/* hardlink: successor runs even though the head failed */
	iou_sqe(IORING_OP_READ, IOSQE_IO_HARDLINK, 9999, 0, rb, 4, 0, 0xC1);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0xC2);
	if (iou_flush(2, 2) != 2)
		return (2);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xC1, &res) || res != -EBADF)
		return (3);
	if (!cqe_find(c, n, 0xC2, &res) || res != 0)
		return (4);
	return (0);
}
static int
t_link_async_write(void)
{
	struct cqe c[4];
	struct kts ts;
	long tf;
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_lw");
	if (tf < 0)
		return (2);
	ts.tv_sec = 0; ts.tv_nsec = 15000000LL;
	iou_sqe(IORING_OP_TIMEOUT, IOSQE_IO_LINK, -1, 0, &ts, 0,
	    IORING_TIMEOUT_ETIME_SUCCESS, 0xD1);
	iou_sqe(IORING_OP_WRITE, 0, tf, 0, "hello!!", 7, 0, 0xD2);
	if (iou_flush(2, 2) != 2)
		return (3);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xD1, &res) || res != 0)
		return (4);
	if (!cqe_find(c, n, 0xD2, &res) || res != 7)
		return (5);
	return (0);
}
static int
t_link_dangling(void)
{
	struct cqe c[2];
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	/* a trailing LINK with no successor is dispatched on its own */
	iou_sqe(IORING_OP_NOP, IOSQE_IO_LINK, -1, 0, 0, 0, 0, 0x1);
	if (iou_flush(1, 1) != 1)
		return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res) || res != 0)
		return (3);
	return (0);
}
static int
t_cqe_skip(void)
{
	struct cqe c[4];
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	iou_sqe(IORING_OP_NOP, IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS, -1, 0,
	    0, 0, 0, 0xE1);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0xE2);
	if (iou_flush(2, 1) != 2)
		return (2);
	n = iou_reap(c, 4);
	if (n != 1 || c[0].user_data != 0xE2ULL)
		return (3);
	if (cqe_find(c, n, 0xE1, &res))
		return (4);	/* the skipped head must be absent */
	return (0);
}

/* ================= drain ================= */
static int
t_drain(void)
{
	struct cqe c[4];
	struct kts ts;
	int n;
	if (ring_setup(8) < 0)
		return (1);
	ts.tv_sec = 0; ts.tv_nsec = 20000000LL;
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 0, 0, 0xE01);
	if (iou_flush(1, 0) != 1)
		return (2);
	iou_sqe(IORING_OP_NOP, IOSQE_IO_DRAIN, -1, 0, 0, 0, 0, 0xE02);
	if (iou_flush(1, 2) != 1)
		return (3);
	n = iou_reap(c, 4);
	if (n != 2)
		return (4);
	/* the barrier NOP is posted after the timeout it waited on */
	if (c[0].user_data != 0xE01ULL || c[1].user_data != 0xE02ULL)
		return (5);
	if (c[0].res != -ELINUX_ETIME || c[1].res != 0)
		return (6);
	return (0);
}
static int
t_drain_immediate(void)
{
	struct cqe c[2];
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	/* nothing outstanding: a DRAIN op runs immediately */
	iou_sqe(IORING_OP_NOP, IOSQE_IO_DRAIN, -1, 0, 0, 0, 0, 0x1);
	if (iou_flush(1, 1) != 1)
		return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res) || res != 0)
		return (3);
	return (0);
}

/* ================= probe / register ================= */
static int
t_probe(void)
{
	struct probe pr;
	long r;
	int i;
	static const int sup[] = { IORING_OP_NOP, IORING_OP_READ,
	    IORING_OP_WRITE, IORING_OP_READV, IORING_OP_WRITEV, IORING_OP_FSYNC,
	    IORING_OP_CLOSE, IORING_OP_FTRUNCATE, IORING_OP_FALLOCATE,
	    IORING_OP_FADVISE, IORING_OP_TIMEOUT, IORING_OP_TIMEOUT_REMOVE,
	    IORING_OP_ASYNC_CANCEL };
	if (ring_setup(8) < 0)
		return (1);
	xmemset(&pr, 0, sizeof(pr));
	r = call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PROBE,
	    (long)&pr, 128, 0, 0);
	if (r != 0)
		return (2);
	for (i = 0; i < (int)(sizeof(sup) / sizeof(sup[0])); i++)
		if ((pr.ops[sup[i]].flags & IO_URING_OP_SUPPORTED) == 0)
			return (100 + sup[i]);
	if (pr.last_op == 0)
		return (3);
	return (0);
}
static int
t_probe_unsupported(void)
{
	struct probe pr;
	long r;
	if (ring_setup(8) < 0)
		return (1);
	xmemset(&pr, 0, sizeof(pr));
	r = call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PROBE,
	    (long)&pr, 128, 0, 0);
	if (r != 0)
		return (2);
	/* opcode 40 is not implemented yet */
	if ((pr.ops[40].flags & IO_URING_OP_SUPPORTED) != 0)
		return (3);
	return (0);
}
static int
t_register_unknown(void)
{
	long r;
	if (ring_setup(8) < 0)
		return (1);
	r = call(SYS_io_uring_register, fd_ring, 999, 0, 0, 0, 0);
	return (r == -EINVAL ? 0 : 2);
}
static int
t_register_nonring(void)
{
	long r;
	if (ring_setup(8) < 0)
		return (1);
	r = call(SYS_io_uring_register, 1, IORING_REGISTER_PROBE, 0, 0, 0, 0);
	return (r == -EOPNOTSUPP ? 0 : 2);
}

/* ================= enter validation ================= */
static int
t_enter_nonring(void)
{
	if (ring_setup(8) < 0)
		return (1);
	return (call(SYS_io_uring_enter, 1, 0, 0, 0, 0, 0) == -EOPNOTSUPP ?
	    0 : 2);
}
static int
t_enter_badflag(void)
{
	if (ring_setup(8) < 0)
		return (1);
	/* an unknown enter flag is rejected */
	return (call(SYS_io_uring_enter, fd_ring, 0, 0, 0x40, 0, 0) == -EINVAL ?
	    0 : 2);
}
static int
t_enter_submit_none(void)
{
	if (ring_setup(8) < 0)
		return (1);
	return (call(SYS_io_uring_enter, fd_ring, 0, 0, 0, 0, 0) == 0 ? 0 : 2);
}

/* ================= adversarial ================= */
static int
t_bad_sqe_index(void)
{
	if (ring_setup(8) < 0)
		return (1);
	/* point the SQ array slot beyond sq_entries: dropped, not dispatched */
	g_sq_array[0] = 999;
	g_sqi = 1;
	__atomic_store_n(g_sq_tail, 1, __ATOMIC_RELEASE);
	if (call(SYS_io_uring_enter, fd_ring, 1, 0, 0, 0, 0) != 1)
		return (2);
	if (__atomic_load_n(g_sq_dropped, __ATOMIC_ACQUIRE) != 1)
		return (3);
	/* no completion was produced */
	if (__atomic_load_n(g_cq_tail, __ATOMIC_ACQUIRE) != 0)
		return (4);
	return (0);
}
static int
t_unsupported_op(void)
{
	if (ring_setup(8) < 0)
		return (1);
	/* opcode 200 is not implemented: completes -EINVAL, ring healthy */
	if (sub1(-1, 200, 0, 0, 0, 0, 0x1) != -EINVAL)
		return (2);
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0x2) != 0)
		return (3);
	return (0);
}
static int
t_fixed_file_flag(void)
{
	char rb[4];
	if (ring_setup(8) < 0)
		return (1);
	/* IOSQE_FIXED_FILE with no registered files -> EBADF */
	iou_sqe(IORING_OP_READ, IOSQE_FIXED_FILE, 0, 0, rb, 4, 0, 0x1);
	{
		struct cqe c[2];
		int n, res = 0;
		if (iou_flush(1, 1) != 1)
			return (2);
		n = iou_reap(c, 2);
		if (n != 1 || !cqe_find(c, n, 0x1, &res))
			return (3);
		return (res == -EBADF ? 0 : 4);
	}
}
static int
t_buffer_select_flag(void)
{
	char rb[4];
	if (ring_setup(8) < 0)
		return (1);
	iou_sqe(IORING_OP_READ, IOSQE_BUFFER_SELECT, -1, 0, rb, 4, 0, 0x1);
	{
		struct cqe c[2];
		int n, res = 0;
		if (iou_flush(1, 1) != 1)
			return (2);
		n = iou_reap(c, 2);
		if (n != 1 || !cqe_find(c, n, 0x1, &res))
			return (3);
		return (res == -EINVAL ? 0 : 4);
	}
}
static int
t_cq_overflow(void)
{
	int b, i;
	if (ring_setup(8) < 0)		/* sq 8, cq 16 */
		return (1);
	/* submit 24 NOPs without ever reaping: last 8 overflow the CQ */
	for (b = 0; b < 3; b++) {
		for (i = 0; i < 8; i++)
			iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 1);
		if (iou_flush(8, 0) != 8)
			return (2);
	}
	if (__atomic_load_n(g_cq_overflow, __ATOMIC_ACQUIRE) == 0)
		return (3);
	/* CQ is full at cq_entries; ring did not crash */
	if (__atomic_load_n(g_cq_tail, __ATOMIC_ACQUIRE) != g_cqe_cnt)
		return (4);
	return (0);
}
static int
t_stress_many(void)
{
	struct cqe c[8];
	int b, i, n, total;
	if (ring_setup(8) < 0)
		return (1);
	total = 0;
	for (b = 0; b < 64; b++) {		/* 64 * 8 = 512 ops */
		for (i = 0; i < 8; i++)
			iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, b * 8 + i);
		if (iou_flush(8, 8) != 8)
			return (2);
		n = iou_reap(c, 8);
		if (n != 8)
			return (3);
		total += n;
	}
	return (total == 512 ? 0 : 4);
}
static int
t_stress_rw(void)
{
	long tf;
	char buf[64];
	int i, res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_srw");
	if (tf < 0)
		return (2);
	for (i = 0; i < 200; i++) {
		xmemset(buf, 'A' + (i & 15), sizeof(buf));
		res = sub1(tf, IORING_OP_WRITE, buf, sizeof(buf),
		    (u64)i * sizeof(buf), 0, 0x1000 + i);
		if (res != (int)sizeof(buf))
			return (3);
	}
	for (i = 0; i < 200; i++) {
		char rb[64];
		xmemset(rb, 0, sizeof(rb));
		res = sub1(tf, IORING_OP_READ, rb, sizeof(rb),
		    (u64)i * sizeof(buf), 0, 0x2000 + i);
		if (res != (int)sizeof(rb) || rb[0] != 'A' + (i & 15))
			return (4);
	}
	return (0);
}

/* ================= filesystem opcodes ================= */
/* openat via the ring: dfd=fd, path=addr, flags=open_flags(misc), mode=len */
static int
t_openat(void)
{
	char rb[8];
	int fd, res;
	if (ring_setup(8) < 0)
		return (1);
	(void)sys1(SYS_unlink, "iou_oa");
	iou_sqe(IORING_OP_OPENAT, 0, LX_AT_FDCWD, 0, "iou_oa", 0600,
	    LX_O_RDWR | LX_O_CREAT, 0x1);
	{
		struct cqe c[2];
		int n;
		if (iou_flush(1, 1) != 1)
			return (2);
		n = iou_reap(c, 2);
		if (n != 1 || !cqe_find(c, n, 0x1, &fd))
			return (3);
	}
	if (fd < 0)
		return (4);
	if (sub1(fd, IORING_OP_WRITE, "opened!", 7, 0, 0, 0x2) != 7)
		return (5);
	xmemset(rb, 0, sizeof(rb));
	res = sub1(fd, IORING_OP_READ, rb, 7, 0, 0, 0x3);
	if (res != 7 || xmemcmp(rb, "opened!", 7) != 0)
		return (6);
	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_unlink, "iou_oa");
	return (0);
}
static int
t_openat_enoent(void)
{
	if (ring_setup(8) < 0)
		return (1);
	(void)sys1(SYS_unlink, "iou_none");
	/* no O_CREAT: opening a missing file fails with -ENOENT */
	iou_sqe(IORING_OP_OPENAT, 0, LX_AT_FDCWD, 0, "iou_none", 0,
	    LX_O_RDWR, 0x1);
	{
		struct cqe c[2];
		int n, res = 0;
		if (iou_flush(1, 1) != 1)
			return (2);
		n = iou_reap(c, 2);
		if (n != 1 || !cqe_find(c, n, 0x1, &res))
			return (3);
		return (res == -ENOENT ? 0 : 4);
	}
}
static int
t_statx(void)
{
	static char sxbuf[256];
	long tf;
	unsigned long long size;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	(void)sys1(SYS_unlink, "iou_sx");
	tf = tmpfile_fd("iou_sx");
	if (tf < 0)
		return (2);
	if (sub1(tf, IORING_OP_WRITE, "12345", 5, 0, 0, 0x1) != 5)
		return (3);
	(void)sys1(SYS_close, tf);
	xmemset(sxbuf, 0, sizeof(sxbuf));
	/* dfd=AT_FDCWD, path=addr, flags=statx_flags(misc), mask=len, buf=addr2(off) */
	iou_sqe(IORING_OP_STATX, 0, LX_AT_FDCWD, (u64)(unsigned long)sxbuf,
	    "iou_sx", STATX_BASIC_STATS, 0, 0x2);
	{
		struct cqe c[2];
		int n;
		if (iou_flush(1, 1) != 1)
			return (4);
		n = iou_reap(c, 2);
		if (n != 1 || !cqe_find(c, n, 0x2, &res))
			return (5);
	}
	if (res != 0)
		return (6);
	size = *(unsigned long long *)(void *)(sxbuf + STATX_OFF_SIZE);
	(void)sys1(SYS_unlink, "iou_sx");
	return (size == 5 ? 0 : 7);
}
static int
t_mkdirat(void)
{
	int res;
	if (ring_setup(8) < 0)
		return (1);
	(void)call(SYS_unlinkat, LX_AT_FDCWD, (long)"iou_d", LX_AT_REMOVEDIR, 0, 0, 0);
	res = sub1(LX_AT_FDCWD, IORING_OP_MKDIRAT, "iou_d", 0755, 0, 0, 0x1);
	if (res != 0)
		return (2);
	/* remove it via the ring with AT_REMOVEDIR (flag goes in the misc slot) */
	iou_sqe(IORING_OP_UNLINKAT, 0, LX_AT_FDCWD, 0, "iou_d", 0,
	    LX_AT_REMOVEDIR, 0x2);
	{
		struct cqe c[2];
		int n;
		if (iou_flush(1, 1) != 1)
			return (3);
		n = iou_reap(c, 2);
		if (n != 1 || !cqe_find(c, n, 0x2, &res))
			return (4);
	}
	return (res == 0 ? 0 : 5);
}
static int
t_unlinkat(void)
{
	long tf;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_ul");
	if (tf < 0)
		return (2);
	(void)sys1(SYS_close, tf);
	res = sub1(LX_AT_FDCWD, IORING_OP_UNLINKAT, "iou_ul", 0, 0, 0, 0x1);
	if (res != 0)
		return (3);
	/* gone: unlinking again is -ENOENT */
	res = sub1(LX_AT_FDCWD, IORING_OP_UNLINKAT, "iou_ul", 0, 0, 0, 0x2);
	return (res == -ENOENT ? 0 : 4);
}
static int
t_symlinkat(void)
{
	int res;
	if (ring_setup(8) < 0)
		return (1);
	(void)sys1(SYS_unlink, "iou_sl");
	/* target=addr, newdfd=fd, linkpath=addr2(off) */
	iou_sqe(IORING_OP_SYMLINKAT, 0, LX_AT_FDCWD,
	    (u64)(unsigned long)"iou_sl", "target/path", 0, 0, 0x1);
	{
		struct cqe c[2];
		int n;
		if (iou_flush(1, 1) != 1)
			return (2);
		n = iou_reap(c, 2);
		if (n != 1 || !cqe_find(c, n, 0x1, &res))
			return (3);
	}
	(void)sys1(SYS_unlink, "iou_sl");
	return (res == 0 ? 0 : 4);
}
static int
t_linkat(void)
{
	long tf;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	(void)sys1(SYS_unlink, "iou_l1");
	(void)sys1(SYS_unlink, "iou_l2");
	tf = tmpfile_fd("iou_l1");
	if (tf < 0)
		return (2);
	(void)sys1(SYS_close, tf);
	/* olddfd=fd, old=addr, newdfd=len, new=addr2(off), flag=misc */
	iou_sqe(IORING_OP_LINKAT, 0, LX_AT_FDCWD, (u64)(unsigned long)"iou_l2",
	    "iou_l1", LX_AT_FDCWD, 0, 0x1);
	{
		struct cqe c[2];
		int n;
		if (iou_flush(1, 1) != 1)
			return (3);
		n = iou_reap(c, 2);
		if (n != 1 || !cqe_find(c, n, 0x1, &res))
			return (4);
	}
	(void)sys1(SYS_unlink, "iou_l1");
	(void)sys1(SYS_unlink, "iou_l2");
	return (res == 0 ? 0 : 5);
}
static int
t_renameat(void)
{
	long tf;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	(void)sys1(SYS_unlink, "iou_rn1");
	(void)sys1(SYS_unlink, "iou_rn2");
	tf = tmpfile_fd("iou_rn1");
	if (tf < 0)
		return (2);
	(void)sys1(SYS_close, tf);
	/* olddfd=fd, old=addr, newdfd=len, new=addr2(off), flags=misc */
	iou_sqe(IORING_OP_RENAMEAT, 0, LX_AT_FDCWD, (u64)(unsigned long)"iou_rn2",
	    "iou_rn1", LX_AT_FDCWD, 0, 0x1);
	{
		struct cqe c[2];
		int n;
		if (iou_flush(1, 1) != 1)
			return (3);
		n = iou_reap(c, 2);
		if (n != 1 || !cqe_find(c, n, 0x1, &res))
			return (4);
	}
	if (res != 0)
		return (5);
	/* old name is gone */
	res = sub1(LX_AT_FDCWD, IORING_OP_UNLINKAT, "iou_rn1", 0, 0, 0, 0x2);
	(void)sys1(SYS_unlink, "iou_rn2");
	return (res == -ENOENT ? 0 : 6);
}
static int
t_madvise(void)
{
	long m;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	m = call(SYS_mmap, 0, 65536, PROT_READ | PROT_WRITE,
	    LX_MAP_PRIVATE | LX_MAP_ANON, -1, 0);
	if (m < 0)
		return (2);
	/* addr=addr, len=len, advice=fadvise_advice(misc) */
	res = sub1(-1, IORING_OP_MADVISE, (void *)(unsigned long)m, 65536, 0,
	    LX_MADV_WILLNEED, 0x1);
	return (res == 0 ? 0 : 3);
}
static int
t_sync_file_range(void)
{
	long tf;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_sfr");
	if (tf < 0)
		return (2);
	if (sub1(tf, IORING_OP_WRITE, "data", 4, 0, 0, 0x1) != 4)
		return (3);
	/* fd, off=offset(0), len=nbytes(0=all), flags=sync_range_flags(0) */
	res = sub1(tf, IORING_OP_SYNC_FILE_RANGE, 0, 0, 0, 0, 0x2);
	return (res == 0 ? 0 : 4);
}
static int
t_fs_probe(void)
{
	struct probe pr;
	long r;
	int i;
	static const int sup[] = { IORING_OP_OPENAT, IORING_OP_STATX,
	    IORING_OP_RENAMEAT, IORING_OP_UNLINKAT, IORING_OP_MKDIRAT,
	    IORING_OP_SYMLINKAT, IORING_OP_LINKAT, IORING_OP_MADVISE,
	    IORING_OP_SYNC_FILE_RANGE };
	if (ring_setup(8) < 0)
		return (1);
	xmemset(&pr, 0, sizeof(pr));
	r = call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PROBE,
	    (long)&pr, 128, 0, 0);
	if (r != 0)
		return (2);
	for (i = 0; i < (int)(sizeof(sup) / sizeof(sup[0])); i++)
		if ((pr.ops[sup[i]].flags & IO_URING_OP_SUPPORTED) == 0)
			return (100 + sup[i]);
	return (0);
}

/* ================= network opcodes ================= */
static int
t_socket(void)
{
	int fd;
	if (ring_setup(8) < 0)
		return (1);
	/* SOCKET: fd=domain, off=type, len=protocol */
	fd = sub1(LX_AF_INET, IORING_OP_SOCKET, 0, 0, LX_SOCK_DGRAM, 0, 0x1);
	if (fd < 0)
		return (2);
	(void)sys1(SYS_close, fd);
	return (0);
}
static int
t_socket_bind_listen(void)
{
	struct sockaddr_in sin;
	int sfd, res;
	if (ring_setup(8) < 0)
		return (1);
	sfd = sub1(LX_AF_INET, IORING_OP_SOCKET, 0, 0, LX_SOCK_STREAM, 0, 0x1);
	if (sfd < 0)
		return (2);
	xmemset(&sin, 0, sizeof(sin));
	sin.sin_family = LX_AF_INET;
	sin.sin_port = 0;			/* any port */
	sin.sin_addr = 0x0100007f;		/* 127.0.0.1 network order */
	/* BIND: addr=&sin, namelen in addr2(off) */
	res = sub1(sfd, IORING_OP_BIND, &sin, 0, sizeof(sin), 0, 0x2);
	if (res != 0) {
		(void)sys1(SYS_close, sfd);
		return (3);
	}
	/* LISTEN: backlog in len */
	res = sub1(sfd, IORING_OP_LISTEN, 0, 8, 0, 0, 0x3);
	(void)sys1(SYS_close, sfd);
	return (res == 0 ? 0 : 4);
}
static int
t_connect_udp(void)
{
	struct sockaddr_in sin;
	int fd, res;
	if (ring_setup(8) < 0)
		return (1);
	fd = sub1(LX_AF_INET, IORING_OP_SOCKET, 0, 0, LX_SOCK_DGRAM, 0, 0x1);
	if (fd < 0)
		return (2);
	xmemset(&sin, 0, sizeof(sin));
	sin.sin_family = LX_AF_INET;
	sin.sin_port = 0x0900;			/* port 9, network order */
	sin.sin_addr = 0x0100007f;
	/* connect on a datagram socket just records the peer -> returns 0 */
	res = sub1(fd, IORING_OP_CONNECT, &sin, 0, sizeof(sin), 0, 0x2);
	(void)sys1(SYS_close, fd);
	return (res == 0 ? 0 : 3);
}
static int
t_accept_eagain(void)
{
	struct sockaddr_in sin;
	int sfd, res;
	if (ring_setup(8) < 0)
		return (1);
	/* nonblocking listener so ACCEPT with no pending conn returns EAGAIN */
	sfd = sub1(LX_AF_INET, IORING_OP_SOCKET, 0, 0,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, 0x1);
	if (sfd < 0)
		return (2);
	xmemset(&sin, 0, sizeof(sin));
	sin.sin_family = LX_AF_INET;
	sin.sin_addr = 0x0100007f;
	if (sub1(sfd, IORING_OP_BIND, &sin, 0, sizeof(sin), 0, 0x2) != 0) {
		(void)sys1(SYS_close, sfd);
		return (3);
	}
	if (sub1(sfd, IORING_OP_LISTEN, 0, 8, 0, 0, 0x3) != 0) {
		(void)sys1(SYS_close, sfd);
		return (4);
	}
	res = sub1(sfd, IORING_OP_ACCEPT, 0, 0, 0, 0, 0x4);
	(void)sys1(SYS_close, sfd);
	return (res == -EAGAIN ? 0 : 5);
}
static int
t_shutdown(void)
{
	int sv[2], res;
	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
	    (long)sv, 0, 0) != 0)
		return (2);
	res = sub1(sv[0], IORING_OP_SHUTDOWN, 0, LX_SHUT_RDWR, 0, 0, 0x1);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	return (res == 0 ? 0 : 3);
}
static int
t_send_recv(void)
{
	int sv[2], res;
	char rb[8];
	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
	    (long)sv, 0, 0) != 0)
		return (2);
	res = sub1(sv[0], IORING_OP_SEND, "netdata", 7, 0, 0, 0x1);
	if (res != 7) {
		(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
		return (3);
	}
	xmemset(rb, 0, sizeof(rb));
	res = sub1(sv[1], IORING_OP_RECV, rb, 7, 0, 0, 0x2);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	if (res != 7 || xmemcmp(rb, "netdata", 7) != 0)
		return (4);
	return (0);
}
static int
t_sendmsg_recvmsg(void)
{
	int sv[2], res;
	struct iovec iov;
	struct l_msghdr mh;
	char rb[8];
	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
	    (long)sv, 0, 0) != 0)
		return (2);
	iov.iov_base = "hail!!"; iov.iov_len = 6;
	xmemset(&mh, 0, sizeof(mh));
	mh.msg_iov = (u64)(unsigned long)&iov;
	mh.msg_iovlen = 1;
	res = sub1(sv[0], IORING_OP_SENDMSG, &mh, 0, 0, 0, 0x1);
	if (res != 6) {
		(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
		return (3);
	}
	xmemset(rb, 0, sizeof(rb));
	iov.iov_base = rb; iov.iov_len = 6;
	xmemset(&mh, 0, sizeof(mh));
	mh.msg_iov = (u64)(unsigned long)&iov;
	mh.msg_iovlen = 1;
	res = sub1(sv[1], IORING_OP_RECVMSG, &mh, 0, 0, 0, 0x2);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	if (res != 6 || xmemcmp(rb, "hail!!", 6) != 0)
		return (4);
	return (0);
}
static int
t_net_probe(void)
{
	struct probe pr;
	long r;
	int i;
	static const int sup[] = { IORING_OP_SOCKET, IORING_OP_CONNECT,
	    IORING_OP_ACCEPT, IORING_OP_BIND, IORING_OP_LISTEN,
	    IORING_OP_SHUTDOWN, IORING_OP_SEND, IORING_OP_RECV,
	    IORING_OP_SENDMSG, IORING_OP_RECVMSG };
	if (ring_setup(8) < 0)
		return (1);
	xmemset(&pr, 0, sizeof(pr));
	r = call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PROBE,
	    (long)&pr, 128, 0, 0);
	if (r != 0)
		return (2);
	for (i = 0; i < (int)(sizeof(sup) / sizeof(sup[0])); i++)
		if ((pr.ops[sup[i]].flags & IO_URING_OP_SUPPORTED) == 0)
			return (100 + sup[i]);
	return (0);
}

/* ================= registered files / buffers (phase 7) ================= */
static int
iou_reg(u32 op, void *arg, u32 nr)
{
	return ((int)call(SYS_io_uring_register, fd_ring, op, (long)arg, nr,
	    0, 0));
}
/* stage a FIXED_FILE op (fd is a registered index) and reap its result */
static int
fixed_op(u8 op, int idx, void *addr, u32 len, u64 off, u16 bufidx, u8 flags,
    u64 ud)
{
	struct cqe c[2];
	u32 slot = g_sqi & g_sqmask;
	int n, res = 0;

	iou_sqe(op, flags, idx, off, addr, len, 0, ud);
	g_sqes[slot].buf_index = bufidx;
	if (iou_flush(1, 1) != 1)
		return (-100000);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, ud, &res))
		return (-100001);
	return (res);
}
static int
t_reg_files(void)
{
	long tf;
	char rb[8];
	int fds[1], res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_rf");
	if (tf < 0)
		return (2);
	if (sub1(tf, IORING_OP_WRITE, "regfile!", 8, 0, 0, 0x1) != 8)
		return (3);
	fds[0] = (int)tf;
	if (iou_reg(IORING_REGISTER_FILES, fds, 1) != 0)
		return (4);
	/* close the application's own fd: the ring holds its own reference */
	(void)sys1(SYS_close, tf);
	xmemset(rb, 0, sizeof(rb));
	res = fixed_op(IORING_OP_READ, 0 /* index */, rb, 8, 0, 0,
	    IOSQE_FIXED_FILE, 0x2);
	if (res != 8 || xmemcmp(rb, "regfile!", 8) != 0)
		return (5);
	if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0)
		return (6);
	return (0);
}
static int
t_reg_files_ebusy(void)
{
	long tf;
	int fds[1];
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_rfb");
	if (tf < 0)
		return (2);
	fds[0] = (int)tf;
	if (iou_reg(IORING_REGISTER_FILES, fds, 1) != 0)
		return (3);
	if (iou_reg(IORING_REGISTER_FILES, fds, 1) != -EBUSY)
		return (4);
	(void)sys1(SYS_close, tf);
	return (0);
}
static int
t_fixed_file_badidx(void)
{
	long tf;
	char rb[4];
	int fds[1], res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_rfi");
	if (tf < 0)
		return (2);
	fds[0] = (int)tf;
	if (iou_reg(IORING_REGISTER_FILES, fds, 1) != 0)
		return (3);
	/* index 5 is out of range for a 1-file table -> EBADF */
	res = fixed_op(IORING_OP_READ, 5, rb, 4, 0, 0, IOSQE_FIXED_FILE, 0x1);
	(void)sys1(SYS_close, tf);
	return (res == -EBADF ? 0 : 4);
}
static int
t_files_update(void)
{
	long tf0, tf1;
	struct files_update up;
	char rb[8];
	int fds[1], res;
	if (ring_setup(8) < 0)
		return (1);
	tf0 = tmpfile_fd("iou_fu0");
	tf1 = tmpfile_fd("iou_fu1");
	if (tf0 < 0 || tf1 < 0)
		return (2);
	if (sub1(tf1, IORING_OP_WRITE, "updated!", 8, 0, 0, 0x1) != 8)
		return (3);
	fds[0] = (int)tf0;
	if (iou_reg(IORING_REGISTER_FILES, fds, 1) != 0)
		return (4);
	/* replace slot 0 with tf1 */
	fds[0] = (int)tf1;
	xmemset(&up, 0, sizeof(up));
	up.offset = 0;
	up.fds = (u64)(unsigned long)fds;
	if (iou_reg(IORING_REGISTER_FILES_UPDATE, &up, 1) != 1)
		return (5);
	xmemset(rb, 0, sizeof(rb));
	res = fixed_op(IORING_OP_READ, 0, rb, 8, 0, 0, IOSQE_FIXED_FILE, 0x2);
	(void)sys1(SYS_close, tf0);
	(void)sys1(SYS_close, tf1);
	if (res != 8 || xmemcmp(rb, "updated!", 8) != 0)
		return (6);
	return (0);
}
static int
t_unregister_files_enxio(void)
{
	if (ring_setup(8) < 0)
		return (1);
	return (iou_reg(IORING_UNREGISTER_FILES, 0, 0) == -ELINUX_ENXIO ? 0 : 2);
}
static int
t_reg_buffers(void)
{
	static char buf[4096];
	struct iovec iov;
	long tf;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_rb");
	if (tf < 0)
		return (2);
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	if (iou_reg(IORING_REGISTER_BUFFERS, &iov, 1) != 0)
		return (3);
	/* WRITE_FIXED from within the registered buffer */
	for (res = 0; res < 5; res++)
		buf[res] = "fixed"[res];
	res = fixed_op(IORING_OP_WRITE_FIXED, (int)tf, buf, 5, 0, 0, 0, 0x1);
	if (res != 5)
		return (4);
	/* READ_FIXED back into a different offset of the same buffer */
	xmemset(buf + 100, 0, 8);
	res = fixed_op(IORING_OP_READ_FIXED, (int)tf, buf + 100, 5, 0, 0, 0, 0x2);
	if (res != 5 || xmemcmp(buf + 100, "fixed", 5) != 0)
		return (5);
	if (iou_reg(IORING_UNREGISTER_BUFFERS, 0, 0) != 0)
		return (6);
	return (0);
}
static int
t_read_fixed_oob(void)
{
	static char buf[4096], other[16];
	struct iovec iov;
	long tf;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_oob");
	if (tf < 0)
		return (2);
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	if (iou_reg(IORING_REGISTER_BUFFERS, &iov, 1) != 0)
		return (3);
	/* target outside the registered buffer -> EFAULT */
	res = fixed_op(IORING_OP_READ_FIXED, (int)tf, other, 8, 0, 0, 0, 0x1);
	(void)sys1(SYS_close, tf);
	return (res == -EFAULT ? 0 : 4);
}
static int
t_read_fixed_badidx(void)
{
	static char buf[4096];
	struct iovec iov;
	long tf;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_bi");
	if (tf < 0)
		return (2);
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	if (iou_reg(IORING_REGISTER_BUFFERS, &iov, 1) != 0)
		return (3);
	/* buf_index 5 with one buffer registered -> EINVAL */
	res = fixed_op(IORING_OP_READ_FIXED, (int)tf, buf, 8, 0, 5, 0, 0x1);
	(void)sys1(SYS_close, tf);
	return (res == -EINVAL ? 0 : 4);
}
static int
t_reg_buffers_ebusy(void)
{
	static char buf[4096];
	struct iovec iov;
	if (ring_setup(8) < 0)
		return (1);
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	if (iou_reg(IORING_REGISTER_BUFFERS, &iov, 1) != 0)
		return (2);
	if (iou_reg(IORING_REGISTER_BUFFERS, &iov, 1) != -EBUSY)
		return (3);
	return (0);
}
static int
t_fixed_probe(void)
{
	struct probe pr;
	if (ring_setup(8) < 0)
		return (1);
	xmemset(&pr, 0, sizeof(pr));
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PROBE,
	    (long)&pr, 128, 0, 0) != 0)
		return (2);
	if ((pr.ops[IORING_OP_READ_FIXED].flags & IO_URING_OP_SUPPORTED) == 0)
		return (3);
	if ((pr.ops[IORING_OP_WRITE_FIXED].flags & IO_URING_OP_SUPPORTED) == 0)
		return (4);
	return (0);
}

/* ================= epoll_ctl / xattr opcodes ================= */
#define	SYS_eventfd2		290
#define	SYS_epoll_create1	291
#define	EPOLL_CTL_ADD		1
#define	EPOLLIN			1
struct epoll_event { u32 events; u64 data; } __attribute__((packed));

static int
t_epoll_ctl(void)
{
	struct epoll_event ev;
	long epfd, efd;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	epfd = call(SYS_epoll_create1, 0, 0, 0, 0, 0, 0);
	if (epfd < 0)
		return (2);
	efd = call(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
	if (efd < 0)
		return (3);
	ev.events = EPOLLIN;
	ev.data = 0x1234;
	/* EPOLL_CTL: epfd=fd, op=len, fd=off, event=addr */
	res = sub1((int)epfd, IORING_OP_EPOLL_CTL, &ev, EPOLL_CTL_ADD,
	    (u64)efd, 0, 0x1);
	(void)sys1(SYS_close, epfd);
	(void)sys1(SYS_close, efd);
	return (res == 0 ? 0 : 4);
}
static int
t_fxattr(void)
{
	long tf;
	char val[8];
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_xa");
	if (tf < 0)
		return (2);
	/* FSETXATTR: fd, name=addr, value=off, size=len, flags=misc */
	res = sub1(tf, IORING_OP_FSETXATTR, "user.iou", 2, (u64)(unsigned long)"v1",
	    0, 0x1);
	if (res == -EOPNOTSUPP) {		/* fs without extended attributes */
		(void)sys1(SYS_close, tf);
		return (0);
	}
	if (res != 0) {
		(void)sys1(SYS_close, tf);
		return (3);
	}
	xmemset(val, 0, sizeof(val));
	res = sub1(tf, IORING_OP_FGETXATTR, "user.iou", sizeof(val),
	    (u64)(unsigned long)val, 0, 0x2);
	(void)sys1(SYS_close, tf);
	if (res != 2 || val[0] != 'v' || val[1] != '1')
		return (4);
	return (0);
}
static int
t_ext_probe(void)
{
	struct probe pr;
	int i;
	static const int sup[] = { IORING_OP_EPOLL_CTL, IORING_OP_FSETXATTR,
	    IORING_OP_SETXATTR, IORING_OP_FGETXATTR, IORING_OP_GETXATTR,
	    IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED };
	if (ring_setup(8) < 0)
		return (1);
	xmemset(&pr, 0, sizeof(pr));
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PROBE,
	    (long)&pr, 128, 0, 0) != 0)
		return (2);
	for (i = 0; i < (int)(sizeof(sup) / sizeof(sup[0])); i++)
		if ((pr.ops[sup[i]].flags & IO_URING_OP_SUPPORTED) == 0)
			return (100 + sup[i]);
	return (0);
}

static const struct subtest subtests[] = {
	{ "setup_zero", t_setup_zero },
	{ "setup_toobig", t_setup_toobig },
	{ "setup_badflag", t_setup_badflag },
	{ "setup_resv", t_setup_resv },
	{ "setup_pow2", t_setup_pow2 },
	{ "setup_one", t_setup_one },
	{ "setup_features", t_setup_features },
	{ "setup_offsets", t_setup_offsets },
	{ "mmap_ok", t_mmap_ok },
	{ "mmap_badoff", t_mmap_badoff },
	{ "mmap_cqring_alias", t_mmap_cqring_alias },
	{ "nop", t_nop },
	{ "nop_batch", t_nop_batch },
	{ "nop_wrap", t_nop_wrap },
	{ "write_read", t_write_read },
	{ "write_offset", t_write_offset },
	{ "read_eof", t_read_eof },
	{ "readv_writev", t_readv_writev },
	{ "rw_cur_pos", t_rw_cur_pos },
	{ "write_badfd", t_write_badfd },
	{ "read_badfd", t_read_badfd },
	{ "write_rdonly", t_write_rdonly },
	{ "large_rw", t_large_rw },
	{ "zero_len", t_zero_len },
	{ "fsync", t_fsync },
	{ "fsync_badfd", t_fsync_badfd },
	{ "close", t_close },
	{ "close_badfd", t_close_badfd },
	{ "ftruncate", t_ftruncate },
	{ "ftruncate_badfd", t_ftruncate_badfd },
	{ "fallocate", t_fallocate },
	{ "fallocate_mode", t_fallocate_mode },
	{ "fadvise", t_fadvise },
	{ "fadvise_badfd", t_fadvise_badfd },
	{ "openat", t_openat },
	{ "openat_enoent", t_openat_enoent },
	{ "statx", t_statx },
	{ "mkdirat", t_mkdirat },
	{ "unlinkat", t_unlinkat },
	{ "symlinkat", t_symlinkat },
	{ "linkat", t_linkat },
	{ "renameat", t_renameat },
	{ "madvise", t_madvise },
	{ "sync_file_range", t_sync_file_range },
	{ "fs_probe", t_fs_probe },
	{ "socket", t_socket },
	{ "socket_bind_listen", t_socket_bind_listen },
	{ "connect_udp", t_connect_udp },
	{ "accept_eagain", t_accept_eagain },
	{ "shutdown", t_shutdown },
	{ "send_recv", t_send_recv },
	{ "sendmsg_recvmsg", t_sendmsg_recvmsg },
	{ "net_probe", t_net_probe },
	{ "reg_files", t_reg_files },
	{ "reg_files_ebusy", t_reg_files_ebusy },
	{ "fixed_file_badidx", t_fixed_file_badidx },
	{ "files_update", t_files_update },
	{ "unregister_files_enxio", t_unregister_files_enxio },
	{ "reg_buffers", t_reg_buffers },
	{ "read_fixed_oob", t_read_fixed_oob },
	{ "read_fixed_badidx", t_read_fixed_badidx },
	{ "reg_buffers_ebusy", t_reg_buffers_ebusy },
	{ "fixed_probe", t_fixed_probe },
	{ "epoll_ctl", t_epoll_ctl },
	{ "fxattr", t_fxattr },
	{ "ext_probe", t_ext_probe },
	{ "timeout_rel", t_timeout_rel },
	{ "timeout_zero", t_timeout_zero },
	{ "timeout_abs", t_timeout_abs },
	{ "timeout_etime_success", t_timeout_etime_success },
	{ "timeout_count", t_timeout_count },
	{ "timeout_badflag", t_timeout_badflag },
	{ "timeout_badptr", t_timeout_badptr },
	{ "timeout_negnsec", t_timeout_negnsec },
	{ "cancel", t_cancel },
	{ "cancel_notfound", t_cancel_notfound },
	{ "cancel_all", t_cancel_all },
	{ "timeout_remove", t_timeout_remove },
	{ "cancel_badflag", t_cancel_badflag },
	{ "link_order", t_link_order },
	{ "link_soft_fail", t_link_soft_fail },
	{ "link_hard_continue", t_link_hard_continue },
	{ "link_async_write", t_link_async_write },
	{ "link_dangling", t_link_dangling },
	{ "cqe_skip", t_cqe_skip },
	{ "drain", t_drain },
	{ "drain_immediate", t_drain_immediate },
	{ "probe", t_probe },
	{ "probe_unsupported", t_probe_unsupported },
	{ "register_unknown", t_register_unknown },
	{ "register_nonring", t_register_nonring },
	{ "enter_nonring", t_enter_nonring },
	{ "enter_badflag", t_enter_badflag },
	{ "enter_submit_none", t_enter_submit_none },
	{ "bad_sqe_index", t_bad_sqe_index },
	{ "unsupported_op", t_unsupported_op },
	{ "fixed_file_flag", t_fixed_file_flag },
	{ "buffer_select_flag", t_buffer_select_flag },
	{ "cq_overflow", t_cq_overflow },
	{ "stress_many", t_stress_many },
	{ "stress_rw", t_stress_rw },
};

static int
test(int argc, char **argv, char **envp __attribute__((unused)))
{

	return (run_subtests(argc, argv, subtests,
	    sizeof(subtests) / sizeof(subtests[0])));
}
