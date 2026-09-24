/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * io_uring: exhaustive subtest battery.
 *
 * Each subtest sets up its own ring (a fresh process per case via the
 * ATF wrapper or VM runner), so cases are fully isolated.  Coverage spans setup
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
#ifdef __aarch64__
#define	SYS_setuid_test	146
#else
#define	SYS_setuid_test	105
#endif

#define	IORING_OFF_SQ_RING	0ULL
#define	IORING_OFF_CQ_RING	0x8000000ULL
#define	IORING_OFF_SQES		0x10000000ULL
#define	IORING_OFF_PBUF_RING		0x80000000ULL
#define	IORING_OFF_PBUF_SHIFT		16
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
#define	IORING_OP_OPENAT2	28
#define	IORING_OP_WRITE		23
#define	IORING_OP_FADVISE	24
#define	IORING_OP_FTRUNCATE	55
#define	IORING_OP_URING_CMD	46
#define	SOCKET_URING_OP_SIOCINQ	0
#define	SOCKET_URING_OP_SIOCOUTQ	1
#define	SOCKET_URING_OP_GETSOCKOPT	2
#define	SOCKET_URING_OP_SETSOCKOPT	3
#define	SOCKET_URING_OP_GETSOCKNAME	5
#define	LX_SOL_SOCKET	1
#define	LX_SO_REUSEADDR	2
#define	ENOPROTOOPT	92
#define	EPROTONOSUPPORT	93

#define	IORING_OP_READ_FIXED	4
#define	IORING_OP_WRITE_FIXED	5

#define	IORING_REGISTER_BUFFERS		0
#define	IORING_UNREGISTER_BUFFERS	1
#define	IORING_REGISTER_FILES		2
#define	IORING_UNREGISTER_FILES		3
#define	IORING_REGISTER_EVENTFD		4
#define	IORING_UNREGISTER_EVENTFD	5
#define	IORING_REGISTER_FILES_UPDATE	6
#define	IORING_REGISTER_PROBE	8
#define	IORING_REGISTER_PERSONALITY	9
#define	IORING_UNREGISTER_PERSONALITY	10
#define	IORING_REGISTER_PBUF_RING	22
#define	IORING_UNREGISTER_PBUF_RING	23
#define	IORING_REGISTER_SYNC_CANCEL	24
#define	IORING_REGISTER_FILE_ALLOC_RANGE	25
#define	IORING_REGISTER_PBUF_STATUS	26
#define	IORING_REGISTER_ZCRX_IFQ	32
#define	IORING_REGISTER_ZCRX_CTRL	36
#define	IORING_FILE_INDEX_ALLOC	(~0U)
#define	IOU_PBUF_RING_MMAP	1
#define	IOU_PBUF_RING_INC	2
#define	IO_URING_OP_SUPPORTED	1
#define	ELINUX_ENXIO		6
#define	ELINUX_EOVERFLOW	75

struct files_update { u32 offset; u32 resv; u64 fds; };
struct file_index_range { u32 off, len; u64 resv; };
struct l_open_how { u64 flags, mode, resolve; };
struct pbuf_reg { u64 ring_addr; u32 ring_entries; u16 bgid, flags; u32 min_left, resv[5]; };
struct pbuf_status { u32 buf_group, head, resv[8]; };
struct uring_buf { u64 addr; u32 len; u16 bid, resv; };
static long pbuf_register(struct pbuf_reg *);
static long pbuf_unregister(u16);
union uring_buf_ring {
 struct { u64 resv1; u32 resv2; u16 resv3; volatile u16 tail; } h;
 struct uring_buf bufs[];
};

#define	IORING_FSYNC_DATASYNC	(1U << 0)
#define	LX_FALLOC_FL_KEEP_SIZE	0x01
#define	LX_FALLOC_FL_PUNCH_HOLE	0x02
#define	LX_FALLOC_FL_COLLAPSE_RANGE	0x08
#define	LX_FALLOC_FL_ZERO_RANGE	0x10
#define	LX_FALLOC_FL_INSERT_RANGE	0x20
#define	LX_FALLOC_FL_UNSHARE_RANGE	0x40
#define	LX_FALLOC_FL_WRITE_ZEROES	0x80

#define	IOSQE_FIXED_FILE	(1U << 0)
#define	IOSQE_IO_DRAIN		(1U << 1)
#define	IOSQE_IO_LINK		(1U << 2)
#define	IOSQE_IO_HARDLINK	(1U << 3)
#define	IOSQE_ASYNC		(1U << 4)
#define	IOSQE_BUFFER_SELECT	(1U << 5)
#define	IOSQE_CQE_SKIP_SUCCESS	(1U << 6)

#define	IORING_TIMEOUT_ABS		(1U << 0)
#define	IORING_TIMEOUT_UPDATE		(1U << 1)
#define	IORING_TIMEOUT_BOOTTIME	(1U << 2)
#define	IORING_TIMEOUT_REALTIME	(1U << 3)
#define	IORING_LINK_TIMEOUT_UPDATE	(1U << 4)
#define	IORING_TIMEOUT_ETIME_SUCCESS	(1U << 5)
#define	IORING_TIMEOUT_MULTISHOT	(1U << 6)
#define	IORING_TIMEOUT_IMMEDIATE_ARG	(1U << 7)
#define	IORING_ASYNC_CANCEL_ALL	(1U << 0)
#define	IORING_ASYNC_CANCEL_FD	(1U << 1)
#define	IORING_ASYNC_CANCEL_ANY	(1U << 2)
#define	IORING_ASYNC_CANCEL_FD_FIXED	(1U << 3)
#define	IORING_ASYNC_CANCEL_USERDATA	(1U << 4)
#define	IORING_ASYNC_CANCEL_OP	(1U << 5)
#define	IORING_OP_LAST		65
#define	IORING_RECVSEND_POLL_FIRST	(1U << 0)
#define	IORING_RECV_MULTISHOT		(1U << 1)
#define	IORING_RECVSEND_FIXED_BUF	(1U << 2)
#define	IORING_SEND_ZC_REPORT_USAGE	(1U << 3)
#define	IORING_RECVSEND_BUNDLE		(1U << 4)
#define	IORING_SEND_VECTORIZED		(1U << 5)
#define	IORING_NOTIF_USAGE_ZC_COPIED	(1U << 31)
#define	LX_MSG_WAITALL		0x100
#define	IORING_ACCEPT_MULTISHOT	(1U << 0)
#define	IORING_ACCEPT_DONTWAIT	(1U << 1)
#define	IORING_ACCEPT_POLL_FIRST	(1U << 2)

#define	IORING_FEAT_SINGLE_MMAP	(1U << 0)
#define	IORING_FEAT_NODROP	(1U << 1)
#define	IORING_FEAT_RW_CUR_POS	(1U << 3)
#define	IORING_FEAT_CQE_SKIP	(1U << 11)
#define	IORING_FEAT_LINKED_FILE	(1U << 12)
#define	IORING_FEAT_REG_REG_RING	(1U << 13)
#define	IORING_FEAT_RECVSEND_BUNDLE	(1U << 14)

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
#define	IORING_OP_READV_FIXED	60
#define	IORING_OP_WRITEV_FIXED	61
#define	IORING_OP_NOP128	63
#define	IORING_OP_PIPE		62
#define	IORING_OP_SPLICE	30
#define	SPLICE_F_FD_IN_FIXED	(1U << 31)
#define	IORING_OP_EPOLL_WAIT	59
#define	IORING_OP_FIXED_FD_INSTALL	54
#define	IORING_FIXED_FD_NO_CLOEXEC	1U
#define	IORING_OP_SEND_ZC	47
#define	IORING_OP_SENDMSG_ZC	48
#define	IORING_OP_LINK_TIMEOUT	15
#define	IORING_OP_FUTEX_WAKE	52
#define	IORING_OP_FUTEX_WAIT	51
#define	IORING_OP_FUTEX_WAITV	53
#define	IORING_OP_WAITID	50
#define	IORING_OP_RECV_ZC	58
#define	IORING_OP_POLL_ADD	6
#define	IORING_OP_POLL_REMOVE	7
#define	IORING_OP_READ_MULTISHOT	49
#define	LX_SOCK_DGRAM		2
#define	IORING_POLL_ADD_MULTI	1
#define	IORING_POLL_UPDATE_EVENTS	(1U << 1)
#define	IORING_POLL_UPDATE_USER_DATA	(1U << 2)
#define	LX_POLLIN		1
#define	LX_POLLOUT		4
#define	LX_P_ALL		0
#define	LX_P_PID		1
#define	LX_P_PIDFD		3
#define	LX_WNOWAIT		0x01000000
#define	LX_WEXITED		0x00000004
#define	LX_WSTOPPED		0x00000002
#define	LX_WCONTINUED		0x00000008
#define	LX_WNOHANG		0x00000001
#define	ELINUX_ECHILD		10
struct l_futex_waitv { u64 val; u64 uaddr; u32 flags; u32 resv; };
#define	IORING_CQE_F_MORE	2
#define	IORING_CQE_F_32	(1U << 15)
#define	IORING_SETUP_CQE32	(1U << 11)
#define	IORING_SETUP_SINGLE_ISSUER	(1U << 12)
#define	IORING_SETUP_DEFER_TASKRUN	(1U << 13)
#define	IORING_SETUP_CQE_MIXED	(1U << 18)
#define	IORING_FEAT_RW_ATTR	(1U << 16)
#define	IORING_RW_ATTR_FLAG_PI	(1U << 0)
#define	IORING_OFF_ZCRX_REGION	0x30000000ULL
#define	IORING_MEM_REGION_TYPE_USER	1U
#define	ZCRX_REG_IMPORT		1U
#define	ZCRX_REG_NODEV		2U
#define	ZCRX_AREA_DMABUF	1U
#define	ZCRX_CTRL_FLUSH_RQ	0U
#define	IORING_SQ_CQ_OVERFLOW	(1U << 1)
#define	IORING_CQE_F_NOTIF	8
#define	IORING_CQE_F_BUF_MORE	16
#define	FUTEX2_SIZE_U32		0x02
#define	FUTEX2_PRIVATE		0x80
#define	FUTEX_BITSET_ANY	0xffffffffU
#define	IORING_OP_FILES_UPDATE	20
#define	IORING_OP_TEE		33
#define	IORING_OP_MSG_RING	40
#define	IORING_MSG_DATA		0
#define	IORING_OP_PROVIDE_BUFFERS	31
#define	IORING_OP_REMOVE_BUFFERS	32
#define	IORING_CQE_F_BUFFER	1
#define	IORING_CQE_BUFFER_SHIFT	16
#define	ELINUX_ENOBUFS		105
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

#define	ELINUX_EPIPE		32
#define	RWF_NOSIGNAL		0x100
#define	ELINUX_EMSGSIZE	90
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
#define	LX_MADV_NORMAL		0
#define	LX_MADV_WILLNEED	3
#define	LX_MADV_DONTNEED	4
#define	STATX_BASIC_STATS	0x7ff
#define	STATX_OFF_SIZE		40	/* offset of stx_size in struct statx */

#define	LX_AF_UNIX		1
#define	LX_AF_INET		2
#define	LX_SOCK_STREAM		1
#define	LX_SOCK_DGRAM		2
#define	LX_SOCK_NONBLOCK	0x800
#define	LX_O_CLOEXEC		0x80000
#define	LX_SOCK_CLOEXEC	LX_O_CLOEXEC
#define	LX_SHUT_RDWR		2

struct sockaddr_in {
	u16 sin_family;
	u16 sin_port;		/* network byte order */
	u32 sin_addr;		/* network byte order */
	u8 sin_zero[8];
};
struct sockaddr_un {
	u16 sun_family;
	char sun_path[108];
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
	u16 buf_index; u16 personality;
	union {
		int splice_fd_in;
		struct { u8 write_stream; u8 __pad4[3]; };
	};
	u64 pad2[2];
};
struct cqe { u64 user_data; int res; u32 flags; };
struct io_uring_attr_pi {
	u16 flags;
	u16 app_tag;
	u32 len;
	u64 addr;
	u64 seed;
	u64 rsvd;
};
struct recvmsg_out { u32 namelen, controllen, payloadlen, flags; };
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
struct linux_pollfd { int fd; short events, revents; };
struct sync_cancel_reg {
	u64 addr;
	int fd;
	u32 flags;
	struct kts timeout;
	u8 opcode;
	u8 pad[7];
	u64 pad2[3];
};
struct zcrx_region_desc {
	u64 user_addr, size;
	u32 flags, id;
	u64 mmap_offset, resv[4];
};
struct zcrx_offsets {
	u32 head, tail, rqes, resv2;
	u64 resv[2];
};
struct zcrx_area_reg {
	u64 addr, len, rq_area_token;
	u32 flags, dmabuf_fd;
	u64 resv[2];
};
struct zcrx_ifq_reg {
	u32 if_idx, if_rxq, rq_entries, flags;
	u64 area_ptr, region_ptr;
	struct zcrx_offsets offsets;
	u32 zcrx_id, rx_buf_len;
	u64 resv[3];
};

static long
wait_readable(int fd, int timeout_ms)
{
	struct linux_pollfd pfd;
	struct timespec ts;

	pfd.fd = fd;
	pfd.events = LX_POLLIN;
	pfd.revents = 0;
	ts.tv_sec = timeout_ms / 1000;
	ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
	if (call(SYS_ppoll, (long)&pfd, 1, (long)&ts, 0, 0, 0) != 1)
		return (0);
	return ((pfd.revents & LX_POLLIN) != 0);
}
struct zcrx_ctrl {
	u32 zcrx_id, op;
	u64 resv[2], data[6];
};
struct zcrx_rqe { u64 off; u32 len, pad; };

/* ---- ring state (rebuilt per subtest process) ---- */
static int fd_ring;
static int zcrx_tcp_pair(int *, int *);
static char *g_sqbase;
static struct sqe *g_sqes;
static volatile u32 *g_sq_head, *g_sq_tail, *g_sq_array, *g_sq_dropped, *g_sq_flags;
static volatile u32 *g_cq_head, *g_cq_tail, *g_cq_overflow;
static struct cqe *g_cqes;
static u32 g_sqmask, g_cqmask, g_sqi, g_cqi;
static u32 g_cqe_cnt, g_features;
static u32 g_ring_map_len, g_sqes_map_len;

static void
put(const char *s)
{
	u32 n = 0;

	while (s[n] != '\0')
		n++;
	(void)call(SYS_write, 1, (long)s, n, 0, 0, 0);
}

static void
putnum(long v)
{
	char b[24];
	unsigned long n;
	int i = 0;

	if (v < 0) {
		put("-");
		n = (unsigned long)(-(v + 1)) + 1;
	} else
		n = (unsigned long)v;
	do {
		b[i++] = (char)('0' + n % 10);
		n /= 10;
	} while (n != 0);
	while (i != 0)
		(void)call(SYS_write, 1, (long)&b[--i], 1, 0, 0, 0);
}

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
	g_ring_map_len = ringsz;
	sqesz = p.sq_entries * sizeof(struct sqe);
	r = call(SYS_mmap, 0, sqesz, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
	    IORING_OFF_SQES);
	if (r < 0)
		return ((int)r);
	g_sqes = (struct sqe *)r;
	g_sqes_map_len = sqesz;
	g_sq_head = (volatile u32 *)(g_sqbase + p.sq_off.head);
	g_sq_tail = (volatile u32 *)(g_sqbase + p.sq_off.tail);
	g_sq_array = (volatile u32 *)(g_sqbase + p.sq_off.array);
	g_sq_dropped = (volatile u32 *)(g_sqbase + p.sq_off.dropped);
	g_sq_flags = (volatile u32 *)(g_sqbase + p.sq_off.flags);
	g_cq_head = (volatile u32 *)(g_sqbase + p.cq_off.head);
	g_cq_tail = (volatile u32 *)(g_sqbase + p.cq_off.tail);
	g_cq_overflow = (volatile u32 *)(g_sqbase + p.cq_off.overflow);
	g_cqes = (struct cqe *)(g_sqbase + p.cq_off.cqes);
	g_sqmask = p.sq_entries - 1;
	g_cqmask = p.cq_entries - 1;
	g_cqe_cnt = p.cq_entries;
	g_features = p.features;
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

/* Like sub1 but with explicit sqe flags (e.g. IOSQE_ASYNC worker offload). */
static int
sub1flags(int fd, u8 op, u8 flags, void *addr, u32 len, u64 off, u64 ud)
{
	struct cqe c[2];
	int n, res = 0;

	iou_sqe(op, flags, fd, off, addr, len, 0, ud);
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
/* IORING_SETUP_CQSIZE (1<<3): the app sizes the completion queue. */
static int
t_setup_cqsize(void)
{
	struct params p;
	long fd;
	xmemset(&p, 0, sizeof(p));
	p.flags = (1U << 3);
	p.cq_entries = 64;
	fd = setup(4, &p);
	if (fd < 0)
		return (1);
	(void)sys1(SYS_close, fd);
	return (p.sq_entries == 4 && p.cq_entries == 64 ? 0 : 2);
}
/* CQSIZE rounds a non-pow2 CQ request up (100 -> 128). */
static int
t_setup_cqsize_pow2(void)
{
	struct params p;
	long fd;
	xmemset(&p, 0, sizeof(p));
	p.flags = (1U << 3);
	p.cq_entries = 100;
	fd = setup(8, &p);
	if (fd < 0)
		return (1);
	(void)sys1(SYS_close, fd);
	return (p.cq_entries == 128 ? 0 : 2);
}
/* CQSIZE with cq_entries == 0 is invalid. */
static int
t_setup_cqsize_zero(void)
{
	struct params p;
	xmemset(&p, 0, sizeof(p));
	p.flags = (1U << 3);
	p.cq_entries = 0;
	return (setup(8, &p) == -EINVAL ? 0 : 1);
}
/* CQSIZE smaller than the SQ is invalid. */
static int
t_setup_cqsize_toosmall(void)
{
	struct params p;
	xmemset(&p, 0, sizeof(p));
	p.flags = (1U << 3);
	p.cq_entries = 4;
	return (setup(16, &p) == -EINVAL ? 0 : 1);
}
/* IORING_SETUP_CLAMP (1<<4): an over-cap SQ is clamped, not rejected. */
static int
t_setup_clamp(void)
{
	struct params p;
	long fd;
	xmemset(&p, 0, sizeof(p));
	p.flags = (1U << 4);
	fd = setup(65536, &p);
	if (fd < 0)
		return (1);
	(void)sys1(SYS_close, fd);
	return (p.sq_entries == 32768 && p.cq_entries == 65536 ? 0 : 2);
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
	if ((p.features & IORING_FEAT_RECVSEND_BUNDLE) == 0)
		return (5);
	if ((p.features & IORING_FEAT_CQE_SKIP) == 0)
		return (6);
	if ((p.features & IORING_FEAT_REG_REG_RING) == 0)
		return (7);
	if ((p.features & IORING_FEAT_LINKED_FILE) == 0)
		return (8);
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
/* Inline ring writes signal like Linux; worker writes already run off-thread. */
static int
rw_nosignal_child(int kind, int vec, int async, int suppress)
{
	struct iovec one;
	struct cqe c;
	int fds[2], n;

	if (kind == 0) {
		if (sys2(SYS_pipe2, fds, 0) != 0)
			return (40);
	} else if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
	    (long)fds, 0, 0) != 0)
		return (41);
	(void)sys1(SYS_close, kind == 0 ? fds[0] : fds[1]);
	if (ring_setup(8) < 0)
		return (42);
	one.iov_base = "n";
	one.iov_len = 1;
	iou_sqe(vec ? IORING_OP_WRITEV : IORING_OP_WRITE,
	    async ? IOSQE_ASYNC : 0, fds[kind == 0 ? 1 : 0], (u64)-1,
	    vec ? (void *)&one : (void *)"n", vec ? 1 : 1,
	    suppress ? RWF_NOSIGNAL : 0, 0x4e53);
	if (iou_flush(1, 1) != 1)
		return (43);
	n = iou_reap(&c, 1);
	if (n != 1 || c.user_data != 0x4e53 || c.res != -ELINUX_EPIPE ||
	    c.flags != 0)
		return (45);
	(void)sys1(SYS_close, fd_ring);
	(void)sys1(SYS_close, fds[kind == 0 ? 1 : 0]);
	return (0);
}

static int
t_rw_nosignal(void)
{
	long pid;
	int async, kind, status, suppress, vec;

	for (kind = 0; kind < 2; kind++)
		for (vec = 0; vec < 2; vec++)
			for (async = 0; async < 2; async++)
				for (suppress = 0; suppress < 2; suppress++) {
					pid = fork_process();
					if (pid < 0)
						return (1);
					if (pid == 0)
						(void)sys1(SYS_exit_group,
						    rw_nosignal_child(kind, vec, async,
						    suppress));
					status = 0;
					if (sys4(SYS_wait4, pid, &status, 0, 0) != pid)
						return (2);
					if (!async && !suppress) {
						if ((status & 0x7f) != SIGPIPE)
							return (3);
					} else if (status != 0)
						return (4);
				}
	return (0);
}

/* ===== IOSQE_ASYNC (worker-pool offload) ===== */
/* An async WRITE then async READ must round-trip through the worker pool. */
static int
t_async_write_read(void)
{
	long tf;
	char rb[16];
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_async");
	if (tf < 0)
		return (2);
	res = sub1flags(tf, IORING_OP_WRITE, IOSQE_ASYNC, "async!!", 7, 0, 0x1);
	if (res != 7)
		return (3);
	xmemset(rb, 0, sizeof(rb));
	res = sub1flags(tf, IORING_OP_READ, IOSQE_ASYNC, rb, 7, 0, 0x2);
	if (res != 7 || xmemcmp(rb, "async!!", 7) != 0)
		return (4);
	return (0);
}
/* Async positioned (pread/pwrite offset) I/O via the worker pool. */
static int
t_async_offset(void)
{
	long tf;
	char rb[16];
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_async_off");
	if (tf < 0)
		return (2);
	if (sub1flags(tf, IORING_OP_WRITE, IOSQE_ASYNC, "WXYZ", 4, 64, 0x1) != 4)
		return (3);
	xmemset(rb, 0, sizeof(rb));
	res = sub1flags(tf, IORING_OP_READ, IOSQE_ASYNC, rb, 4, 64, 0x2);
	if (res != 4 || xmemcmp(rb, "WXYZ", 4) != 0)
		return (4);
	return (0);
}
/* Async READV/WRITEV must copy the iovec in and run off-thread. */
static int
t_async_readv_writev(void)
{
	long tf;
	struct iovec iov[2];
	char rb[8];
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_async_v");
	if (tf < 0)
		return (2);
	iov[0].iov_base = "12"; iov[0].iov_len = 2;
	iov[1].iov_base = "34"; iov[1].iov_len = 2;
	if (sub1flags(tf, IORING_OP_WRITEV, IOSQE_ASYNC, iov, 2, 0, 0x1) != 4)
		return (3);
	xmemset(rb, 0, sizeof(rb));
	iov[0].iov_base = rb; iov[0].iov_len = 2;
	iov[1].iov_base = rb + 2; iov[1].iov_len = 2;
	res = sub1flags(tf, IORING_OP_READV, IOSQE_ASYNC, iov, 2, 0, 0x2);
	if (res != 4 || xmemcmp(rb, "1234", 4) != 0)
		return (4);
	return (0);
}
/*
 * Submit many async reads at once: they fan out across worker processes and
 * every completion must come back with the right byte count and data.  This
 * exercises pool growth and concurrent resolution onto ctx->ready.
 */
static int
t_async_many(void)
{
	long tf;
	char buf[64], rb[16][8];
	struct cqe c[16];
	int i, n, got;
	if (ring_setup(32) < 0)
		return (1);
	tf = tmpfile_fd("iou_async_many");
	if (tf < 0)
		return (2);
	for (i = 0; i < (int)sizeof(buf); i++)
		buf[i] = (char)('A' + (i & 15));
	if (sub1(tf, IORING_OP_WRITE, buf, sizeof(buf), 0, 0, 0x1) !=
	    (int)sizeof(buf))
		return (3);
	/* 16 async reads, each 4 bytes at a distinct offset. */
	for (i = 0; i < 16; i++) {
		xmemset(rb[i], 0, sizeof(rb[i]));
		iou_sqe(IORING_OP_READ, IOSQE_ASYNC, tf, (u64)(i * 4), rb[i], 4,
		    0, 0x100 + i);
	}
	if (iou_flush(16, 16) != 16)
		return (4);
	got = 0;
	while (got < 16) {
		n = iou_reap(c, 16);
		if (n <= 0)
			return (5);
		for (i = 0; i < n; i++) {
			if (c[i].res != 4)
				return (6);
		}
		got += n;
	}
	/* Verify one read landed with the expected bytes. */
	if (xmemcmp(rb[1], &buf[4], 4) != 0)
		return (7);
	return (0);
}
/* A bad-fd async op still returns the negative errno from the worker path. */
static int
t_async_badfd(void)
{
	char rb[4];
	if (ring_setup(8) < 0)
		return (1);
	return (sub1flags(9999, IORING_OP_READ, IOSQE_ASYNC, rb, 4, 0, 0x1) ==
	    -EBADF ? 0 : 2);
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
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_ro", 0);
	tf = sys4(SYS_openat, AT_FDCWD, "iou_ro", O_RDONLY | O_CREAT, 0600);
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

/* A nonzero attr_type_mask must never be silently ignored.  Linux v7.1
 * advertises RW_ATTR and validates PI metadata; a frontend without a metadata
 * backend keeps the feature clear and returns EOPNOTSUPP for the known mask. */
static int
t_rw_attr(void)
{
	struct io_uring_attr_pi pi;
	struct cqe c;
	long tf;
	char byte = 'a';
	int expected;

	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_rw_attr");
	if (tf < 0)
		return (2);

	/* attr_ptr has no meaning while the mask is zero and is ignored. */
	iou_sqe(IORING_OP_WRITE, 0, (int)tf, 0, &byte, 1, 0, 0xa100);
	g_sqes[(g_sqi - 1) & g_sqmask].pad2[0] = 1;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 || c.res != 1)
		return (3);

	/* Unknown attribute bits are an ABI error before any I/O side effect. */
	byte = 'b';
	iou_sqe(IORING_OP_WRITE, 0, (int)tf, 1, &byte, 1, 0, 0xa101);
	g_sqes[(g_sqi - 1) & g_sqmask].pad2[0] = (u64)&pi;
	g_sqes[(g_sqi - 1) & g_sqmask].pad2[1] = 2;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 || c.res != -EINVAL)
		return (4);

	/* A known PI request is validated on Linux and explicitly unsupported
	 * when the advertised feature is clear. */
	xmemset(&pi, 0, sizeof(pi));
	byte = 'c';
	iou_sqe(IORING_OP_WRITE, 0, (int)tf, 1, &byte, 1, 0, 0xa102);
	g_sqes[(g_sqi - 1) & g_sqmask].pad2[0] = 1;
	g_sqes[(g_sqi - 1) & g_sqmask].pad2[1] = IORING_RW_ATTR_FLAG_PI;
	expected = (g_features & IORING_FEAT_RW_ATTR) != 0 ? -EFAULT : -EOPNOTSUPP;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 || c.res != expected)
		return (5);

	if ((g_features & IORING_FEAT_RW_ATTR) != 0) {
		pi.rsvd = 1;
		iou_sqe(IORING_OP_READ, 0, (int)tf, 0, &byte, 1, 0, 0xa103);
		g_sqes[(g_sqi - 1) & g_sqmask].pad2[0] = (u64)&pi;
		g_sqes[(g_sqi - 1) & g_sqmask].pad2[1] = IORING_RW_ATTR_FLAG_PI;
		if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
		    c.res != -EINVAL)
			return (6);
	}
	(void)sys1(SYS_close, tf);
	(void)sys1(SYS_close, fd_ring);
	return (0);
}

static int
rw_attr_matrix_submit(u8 opcode, int fd, u64 attr_ptr, u64 attr_mask,
    u64 user_data)
{
	struct iovec iov;
	struct cqe c;
	void *buf;
	char byte = 'z';
	u32 slot;

	iov.iov_base = &byte;
	iov.iov_len = 1;
	buf = opcode == IORING_OP_READV || opcode == IORING_OP_WRITEV ||
	    opcode == IORING_OP_READV_FIXED || opcode == IORING_OP_WRITEV_FIXED ?
	    (void *)&iov : (void *)&byte;
	iou_sqe(opcode, 0, fd, 0, buf, 1, 0, user_data);
	slot = (g_sqi - 1) & g_sqmask;
	g_sqes[slot].pad2[0] = attr_ptr;
	g_sqes[slot].pad2[1] = attr_mask;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != user_data)
		return (-100000);
	return (c.res);
}

static int
t_rw_attr_opcode_matrix(void)
{
	static const u8 ops[] = {
		IORING_OP_READV, IORING_OP_WRITEV,
		IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED,
		IORING_OP_READ, IORING_OP_WRITE,
		IORING_OP_READV_FIXED, IORING_OP_WRITEV_FIXED
	};
	struct io_uring_attr_pi pi;
	long tf;
	int expected;
	u32 i;

	if (ring_setup(16) < 0)
		return (1);
	tf = tmpfile_fd("iou_rw_attr_matrix");
	if (tf < 0 || sub1((int)tf, IORING_OP_WRITE, "a", 1, 0, 0,
	    0xa200) != 1)
		return (2);
	xmemset(&pi, 0, sizeof(pi));
	for (i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
		if (rw_attr_matrix_submit(ops[i], (int)tf, (u64)&pi, 2,
		    0xa210 + i) != -EINVAL)
			return (3 + (int)i);
	}
	expected = (g_features & IORING_FEAT_RW_ATTR) != 0 ? -EFAULT :
	    -EOPNOTSUPP;
	for (i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
		if (rw_attr_matrix_submit(ops[i], (int)tf, 1,
		    IORING_RW_ATTR_FLAG_PI, 0xa220 + i) != expected)
			return (20 + (int)i);
	}
	(void)sys1(SYS_close, tf);
	(void)sys1(SYS_close, fd_ring);
	return (0);
}

#define	IOPRIO_CLASS_RT		1
#define	IOPRIO_CLASS_BE		2
#define	IOPRIO_CLASS_IDLE	3
#define	IOPRIO_PRIO(class, data)	(((class) << 13) | (data))

static int
rw_ioprio_submit(u8 opcode, int fd, void *buf, u32 len, u64 off,
    u16 ioprio, u8 write_stream, u64 user_data)
{
	struct cqe c;
	u32 slot;

	iou_sqe(opcode, 0, fd, off, buf, len, 0, user_data);
	slot = (g_sqi - 1) & g_sqmask;
	g_sqes[slot].ioprio = ioprio;
	g_sqes[slot].write_stream = write_stream;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != user_data)
		return (-100000);
	return (c.res);
}

static int
t_rw_ioprio(void)
{
	long tf;
	char buf[4], byte;

	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_rw_ioprio");
	if (tf < 0)
		return (2);
	byte = 'b';
	if (rw_ioprio_submit(IORING_OP_WRITE, (int)tf, &byte, 1, 0,
	    IOPRIO_PRIO(IOPRIO_CLASS_BE, 4), 0, 0xa300) != 1)
		return (3);
	byte = 'i';
	if (rw_ioprio_submit(IORING_OP_WRITE, (int)tf, &byte, 1, 1,
	    IOPRIO_PRIO(IOPRIO_CLASS_IDLE, 7), 0, 0xa301) != 1)
		return (4);
	/* Class NONE examines only the low three level bits.  Higher data bits
	 * are Linux hints and write_stream is an independent advisory byte. */
	byte = 'h';
	if (rw_ioprio_submit(IORING_OP_WRITE, (int)tf, &byte, 1, 2,
	    0x0008, 255, 0xa302) != 1)
		return (5);
	byte = 'r';
	if (rw_ioprio_submit(IORING_OP_WRITE, (int)tf, &byte, 1, 3,
	    IOPRIO_PRIO(IOPRIO_CLASS_RT, 0), 0, 0xa303) != 1)
		return (6);
	xmemset(buf, 0, sizeof(buf));
	if (sub1((int)tf, IORING_OP_READ, buf, sizeof(buf), 0, 0,
	    0xa304) != (int)sizeof(buf) || xmemcmp(buf, "bihr", 4) != 0)
		return (7);
	(void)sys1(SYS_close, tf);
	(void)sys1(SYS_close, fd_ring);
	return (0);
}

static int
t_rw_ioprio_opcode_matrix(void)
{
	static const u8 ops[] = {
		IORING_OP_READV, IORING_OP_WRITEV,
		IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED,
		IORING_OP_READ, IORING_OP_WRITE,
		IORING_OP_READV_FIXED, IORING_OP_WRITEV_FIXED
	};
	static const u16 invalid[] = { 0x0001, 0x8000, 0xe000 };
	struct iovec iov;
	long tf;
	char byte = 'x';
	u32 i, j;
	void *buf;

	if (ring_setup(32) < 0)
		return (1);
	tf = tmpfile_fd("iou_rw_ioprio_matrix");
	if (tf < 0)
		return (2);
	iov.iov_base = &byte;
	iov.iov_len = 1;
	for (i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
		buf = ops[i] == IORING_OP_READV || ops[i] == IORING_OP_WRITEV ||
		    ops[i] == IORING_OP_READV_FIXED ||
		    ops[i] == IORING_OP_WRITEV_FIXED ? (void *)&iov : &byte;
		for (j = 0; j < sizeof(invalid) / sizeof(invalid[0]); j++)
			if (rw_ioprio_submit(ops[i], (int)tf, buf, 1, 0,
			    invalid[j], 0, 0xa310 + i * 4 + j) != -EINVAL)
				return (3 + (int)i * 3 + (int)j);
	}
	(void)sys1(SYS_close, tf);
	(void)sys1(SYS_close, fd_ring);
	return (0);
}

static int
rw_ioprio_unprivileged_child(void *arg __attribute__((unused)))
{
	char byte = 'x';

	if (call(SYS_setuid_test, 65534, 0, 0, 0, 0, 0) != 0)
		return (1);
	if (ring_setup(8) < 0)
		return (2);
	return (rw_ioprio_submit(IORING_OP_WRITE, -1, &byte, 1, 0,
	    IOPRIO_PRIO(IOPRIO_CLASS_RT, 0), 0, 0xa330) == -EPERM ? 0 : 3);
}

static int
t_rw_ioprio_privilege(void)
{

	return (run_child(rw_ioprio_unprivileged_child, 0));
}

static int iou_reg(u32, void *, u32);
static int fixed_op(u8, int, void *, u32, u64, u16, u8, u64);

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
fsync_option_submit(u8 flags, int fd, u64 off, u32 len, u32 fsync_flags,
    u16 personality, u16 buf_index, int splice_fd_in, u64 addr, u64 addr3,
    u64 pad, u64 user_data)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_FSYNC, flags, fd, off, (void *)(unsigned long)addr,
	    len, fsync_flags, user_data);
	g_sqes[slot].personality = personality;
	g_sqes[slot].buf_index = buf_index;
	g_sqes[slot].splice_fd_in = splice_fd_in;
	g_sqes[slot].pad2[0] = addr3;
	g_sqes[slot].pad2[1] = pad;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != user_data || c.flags != 0)
		return (-100000);
	return (c.res);
}

static int
t_fsync_flags(void)
{
	long tf, personality;
	int fds[2], pfd[2];

	if (ring_setup(16) < 0)
		return (1);
	tf = tmpfile_fd("iou_fsync_flags");
	if (tf < 0 || sub1(tf, IORING_OP_WRITE, "data", 4, 0, 0, 0x10) != 4)
		return (2);
	/* Generic checks precede personality, opcode preparation, and file lookup. */
	{
		u32 slot = g_sqi & g_sqmask;
		struct cqe c;
		iou_sqe(IORING_OP_FSYNC, 0, 9999, 0, 0, 0, 0, 0x11);
		g_sqes[slot].ioprio = 1;
		g_sqes[slot].personality = 99;
		g_sqes[slot].addr = 1;
		if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
		    c.res != -EINVAL)
			return (3);
	}
	if (fsync_option_submit(IOSQE_BUFFER_SELECT, 9999, 0, 0, 0, 99,
	    0, 0, 0, 0, 0, 0x12) != -EOPNOTSUPP)
		return (4);
	/* FSYNC prep rejects addr, buf_index, and splice_fd_in before file lookup. */
	if (fsync_option_submit(0, 9999, 0, 0, 0, 0, 0, 0, 1, 0, 0,
	    0x13) != -EINVAL ||
	    fsync_option_submit(0, 9999, 0, 0, 0, 0, 1, 0, 0, 0, 0,
	    0x14) != -EINVAL ||
	    fsync_option_submit(0, 9999, 0, 0, 0, 0, 0, 1, 0, 0, 0,
	    0x15) != -EINVAL)
		return (5);
	personality = iou_reg(IORING_REGISTER_PERSONALITY, 0, 0);
	if (personality <= 0 || personality > 65535)
		return (6);
	/* Unknown flags fail in prep; both supported modes accept range inputs. */
	if (fsync_option_submit(0, 9999, 0, 0, 2, (u16)personality, 0, 0,
	    0, 0, 0, 0x16) != -EINVAL)
		return (70);
	/* File lookup precedes execution-time range validation. */
	if (fsync_option_submit(0, 9999, (u64)-1, 0, 0, 0, 0, 0,
	    0, 0, 0, 0x25) != -EBADF)
		return (75);
	if (fsync_option_submit(0, (int)tf, 0, 0, 0, (u16)personality, 0, 0,
	    0, 0, 0, 0x17) != 0)
		return (71);
	if (fsync_option_submit(0, (int)tf, 1, 2, IORING_FSYNC_DATASYNC,
	    (u16)personality, 0, 0, 0, 0, 0, 0x18) != 0)
		return (72);
	if (fsync_option_submit(0, (int)tf, (u64)-1, 0, 0, 0, 0, 0,
	    0, 0, 0, 0x19) != -EINVAL)
		return (73);
	if (fsync_option_submit(0, (int)tf, 0x7fffffffffffffffULL, 2, 0, 0,
	    0, 0, 0, 0, 0, 0x1a) != 0)
		return (74);
	/* addr3 and final padding are unused; ASYNC forces worker execution. */
	if (fsync_option_submit(IOSQE_ASYNC, (int)tf, 0, 0,
	    IORING_FSYNC_DATASYNC, (u16)personality, 0, 0, 0,
	    0x1122334455667788ULL, 0x8877665544332211ULL, 0x1b) != 0)
		return (8);
	if (sys2(SYS_pipe2, pfd, 0) != 0 ||
	    fsync_option_submit(0, pfd[0], 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    0x1c) != -EINVAL)
		return (9);
	(void)sys1(SYS_close, pfd[0]);
	(void)sys1(SYS_close, pfd[1]);
	/* Registered files stay pinned after ambient close; sparse slots fail. */
	fds[0] = (int)tf;
	fds[1] = -1;
	if (iou_reg(IORING_REGISTER_FILES, fds, 2) != 0 ||
	    sys1(SYS_close, tf) != 0)
		return (10);
	if (fsync_option_submit(IOSQE_FIXED_FILE, 0, 0, 0,
	    IORING_FSYNC_DATASYNC, 0, 0, 0, 0, 0, 0, 0x20) != 0 ||
	    fsync_option_submit(IOSQE_FIXED_FILE, 1, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0x21) != -EBADF ||
	    fsync_option_submit(IOSQE_FIXED_FILE, 99, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0x22) != -EBADF)
		return (11);
	if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0 ||
	    fsync_option_submit(IOSQE_FIXED_FILE, 0, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0x23) != -EBADF ||
	    iou_reg(IORING_UNREGISTER_PERSONALITY, 0, (u32)personality) != 0 ||
	    sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0x24) != 0 ||
	    sys1(SYS_close, fd_ring) != 0)
		return (12);
	return (0);
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
ftruncate_option_submit(u8 flags, int fd, u64 length, int field, u64 ud)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_FTRUNCATE, flags, fd, length, 0, 0, 0, ud);
	switch (field) {
	case 1: g_sqes[slot].addr = 1; break;
	case 2: g_sqes[slot].len = 1; break;
	case 3: g_sqes[slot].rw_flags = 1; break;
	case 4: g_sqes[slot].buf_index = 1; break;
	case 5: g_sqes[slot].splice_fd_in = 1; break;
	case 6: g_sqes[slot].pad2[0] = 1; break;	/* addr3 */
	case 7: g_sqes[slot].pad2[1] = 0xfeed; break;
	case 8: g_sqes[slot].ioprio = 1; break;
	default: break;
	}
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != ud)
		return (-100000);
	return (c.res);
}

static int
t_ftruncate_options(void)
{
	char rb[16];
	int files[2], pfd[2], res;
	long tf, ro, dfd, sfd;

	if (ring_setup(32) < 0)
		return (1);
	tf = tmpfile_fd("iou_ftruncate_options");
	if (tf < 0 || sys3(SYS_write, tf, "12345678", 8) != 8)
		return (2);

	/* Linux reserves every union field except off and the final SQE word. */
	for (int field = 1; field <= 6; field++) {
		if (ftruncate_option_submit(0, (int)tf, 3, field,
		    0xf100 + field) != -EINVAL ||
		    sys3(SYS_lseek, tf, 0, 2) != 8)
			return (3);
	}
	if (ftruncate_option_submit(0, (int)tf, 7, 7, 0xf108) != 0 ||
	    sys3(SYS_lseek, tf, 0, 2) != 7)
		return (4);
	if (ftruncate_option_submit(0, (int)tf, 6, 8, 0xf109) != -EINVAL ||
	    ftruncate_option_submit(IOSQE_BUFFER_SELECT, (int)tf, 6, 0,
	    0xf10a) != -EOPNOTSUPP ||
	    sys3(SYS_lseek, tf, 0, 2) != 7)
		return (5);

	/* Execution errors do not change the file and a later truncate recovers. */
	if (ftruncate_option_submit(0, (int)tf, (u64)-1, 0, 0xf110) !=
	    -EINVAL ||
	    ftruncate_option_submit(0, 9999, 4, 0, 0xf111) != -EBADF ||
	    ftruncate_option_submit(0, 9999, (u64)-1, 0, 0xf112) != -EBADF ||
	    sys3(SYS_lseek, tf, 0, 2) != 7)
		return (6);

	/* do_ftruncate requires a writable regular file. */
	ro = sys4(SYS_openat, LX_AT_FDCWD, "iou_ftruncate_options",
	    O_RDONLY, 0);
	dfd = sys4(SYS_openat, LX_AT_FDCWD, ".", O_RDONLY | O_DIRECTORY, 0);
	sfd = sys3(SYS_socket, LX_AF_UNIX, LX_SOCK_STREAM, 0);
	if (ro < 0 || dfd < 0 || sfd < 0 || sys2(SYS_pipe2, pfd, 0) != 0)
		return (7);
	if (ftruncate_option_submit(0, (int)ro, 2, 0, 0xf120) != -EINVAL ||
	    ftruncate_option_submit(0, (int)dfd, 2, 0, 0xf121) != -EINVAL ||
	    ftruncate_option_submit(0, pfd[1], 2, 0, 0xf122) != -EINVAL ||
	    ftruncate_option_submit(0, (int)sfd, 2, 0, 0xf123) != -EINVAL ||
	    sys3(SYS_lseek, tf, 0, 2) != 7)
		return (8);
	(void)sys1(SYS_close, ro);
	(void)sys1(SYS_close, dfd);
	(void)sys1(SYS_close, sfd);
	(void)sys1(SYS_close, pfd[0]);
	(void)sys1(SYS_close, pfd[1]);

	/* Preparation errors precede fixed-slot lookup and preserve the file. */
	files[0] = (int)tf;
	files[1] = -1;
	if (iou_reg(IORING_REGISTER_FILES, files, 2) != 0)
		return (9);
	if (ftruncate_option_submit(IOSQE_FIXED_FILE, 9, 2, 1,
	    0xf130) != -EINVAL ||
	    ftruncate_option_submit(IOSQE_FIXED_FILE, 9, 2, 6,
	    0xf131) != -EINVAL ||
	    sys3(SYS_lseek, tf, 0, 2) != 7)
		return (10);

	/* A fixed file pins its object after the ambient descriptor is closed. */
	(void)sys1(SYS_close, tf);
	if (ftruncate_option_submit(IOSQE_FIXED_FILE, 0, 4, 0,
	    0xf132) != 0)
		return (11);
	xmemset(rb, 0, sizeof(rb));
	res = fixed_op(IORING_OP_READ, 0, rb, sizeof(rb), 0, 0,
	    IOSQE_FIXED_FILE, 0xf133);
	if (res != 4 || xmemcmp(rb, "1234", 4) != 0)
		return (12);
	if (ftruncate_option_submit(IOSQE_FIXED_FILE, 1, 2, 0,
	    0xf134) != -EBADF ||
	    ftruncate_option_submit(IOSQE_FIXED_FILE, 2, 2, 0,
	    0xf135) != -EBADF ||
	    ftruncate_option_submit(IOSQE_FIXED_FILE, 1, (u64)-1, 0,
	    0xf136) != -EBADF)
		return (13);
	if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0 ||
	    ftruncate_option_submit(IOSQE_FIXED_FILE, 0, 2, 0,
	    0xf137) != -EBADF)
		return (14);

	tf = tmpfile_fd("iou_ftruncate_recover");
	if (tf < 0 || ftruncate_option_submit(IOSQE_ASYNC, (int)tf, 9, 0,
	    0xf140) != 0 || sys3(SYS_lseek, tf, 0, 2) != 9)
		return (15);
	(void)sys1(SYS_close, tf);
	return (0);
}
static int
iou_fallocate(int fd, u32 mode, long long off, long long len, u64 ud)
{
	return (sub1(fd, IORING_OP_FALLOCATE, (void *)(unsigned long)len,
	    mode, (u64)off, 0, ud));
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
	static char block[4096];
	struct stat st;
	long tf;
	int i;

	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_fam");
	if (tf < 0)
		return (2);
	xmemset(block, 'A', sizeof(block));
	for (i = 0; i < 3; i++)
		if (sys4(SYS_pwrite64, tf, block, sizeof(block), i * 4096) !=
		    (long)sizeof(block))
			return (3);
	if (iou_fallocate(tf, LX_FALLOC_FL_PUNCH_HOLE |
	    LX_FALLOC_FL_KEEP_SIZE, 4096, 4096, 0x1) != 0)
		return (4);
	if (sys2(SYS_fstat, tf, &st) != 0 || st.st_size != 12288)
		return (5);
	xmemset(block, 0xff, sizeof(block));
	if (sys4(SYS_pread64, tf, block, sizeof(block), 4096) !=
	    (long)sizeof(block))
		return (6);
	for (i = 0; i < (int)sizeof(block); i++)
		if (block[i] != 0)
			return (7);
	if (sys4(SYS_pread64, tf, block, 1, 0) != 1 || block[0] != 'A' ||
	    sys4(SYS_pread64, tf, block, 1, 8192) != 1 || block[0] != 'A')
		return (8);
	/* Entirely past EOF is a successful no-op; straddling EOF keeps size. */
	if (iou_fallocate(tf, 3, 16384, 4096, 0x2) != 0 ||
	    iou_fallocate(tf, 3, 12288 - 512, 1024, 0x3) != 0 ||
	    sys2(SYS_fstat, tf, &st) != 0 || st.st_size != 12288)
		return (12);
	return (0);
}

static int
t_fallocate_modes_invalid(void)
{
	static const u32 unsupported[] = {
	    LX_FALLOC_FL_KEEP_SIZE, LX_FALLOC_FL_ZERO_RANGE,
	    LX_FALLOC_FL_COLLAPSE_RANGE, LX_FALLOC_FL_INSERT_RANGE,
	    LX_FALLOC_FL_UNSHARE_RANGE, LX_FALLOC_FL_WRITE_ZEROES
	};
	long tf, rfd, sfd;
	int pfd[2], i;

	if (ring_setup(16) < 0)
		return (1);
	tf = tmpfile_fd("iou_fam_invalid");
	if (tf < 0 || sys3(SYS_write, tf, "keep", 4) != 4)
		return (2);
	if (iou_fallocate(tf, LX_FALLOC_FL_PUNCH_HOLE, 0, 4096, 0x10) !=
	    -EOPNOTSUPP)
		return (3);
	for (i = 0; i < (int)(sizeof(unsupported) / sizeof(unsupported[0])); i++)
		if (iou_fallocate(tf, unsupported[i], 0, 4096, 0x20 + i) !=
		    -EOPNOTSUPP)
			return (4);
	/* io_uring resolves its request file before vfs_fallocate validation. */
	if (iou_fallocate(9999, 0x100, 0, 4096, 0x30) != -EBADF ||
	    iou_fallocate(tf, 0, 0, 0, 0x31) != -EINVAL ||
	    iou_fallocate(tf, 0, -1, 4096, 0x32) != -EINVAL ||
	    iou_fallocate(tf, 0, 0x7fffffffffffff00LL, 4096, 0x33) != -EFBIG)
		return (5);
	rfd = sys4(SYS_openat, LX_AT_FDCWD, "iou_fam_invalid", O_RDONLY, 0);
	if (rfd < 0 || iou_fallocate((int)rfd, 0, 0, 4096, 0x34) != -EBADF)
		return (6);
	if (sys2(SYS_pipe2, pfd, 0) != 0 ||
	    iou_fallocate(pfd[1], 0, 0, 4096, 0x35) != -ESPIPE)
		return (7);
	rfd = sys4(SYS_openat, LX_AT_FDCWD, ".", O_RDONLY | O_DIRECTORY, 0);
	if (rfd < 0 || iou_fallocate((int)rfd, 0, 0, 4096, 0x36) != -EISDIR)
		return (8);
	sfd = sys3(SYS_socket, LX_AF_UNIX, LX_SOCK_STREAM, 0);
	if (sfd < 0 || iou_fallocate((int)sfd, 0, 0, 4096, 0x37) != -ENODEV)
		return (9);
	return (0);
}

static int
fallocate_option_submit(u8 flags, int fd, u64 off, u64 alloc_len, u32 mode,
    u16 personality, u16 buf_index, u32 rw_flags, int splice_fd_in, u64 addr3,
    u64 pad, u64 user_data)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_FALLOCATE, flags, fd, off,
	    (void *)(unsigned long)alloc_len, mode, rw_flags, user_data);
	g_sqes[slot].personality = personality;
	g_sqes[slot].buf_index = buf_index;
	g_sqes[slot].splice_fd_in = splice_fd_in;
	g_sqes[slot].pad2[0] = addr3;
	g_sqes[slot].pad2[1] = pad;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != user_data || c.flags != 0)
		return (-100000);
	return (c.res);
}

static int
t_fallocate_options(void)
{
	long tf, pathfd, rfd, personality;
	int files[2], pfd[2];

	if (ring_setup(16) < 0)
		return (1);
	tf = call(SYS_memfd_create, (long)"iou_fallocate_options", 0, 0, 0, 0, 0);
	pathfd = tmpfile_fd("iou_fallocate_options_path");
	if (tf < 0 || pathfd < 0 || sys1(SYS_close, pathfd) != 0)
		return (2);
	/* Generic validation precedes personality, opcode prep, and file lookup. */
	{
		u32 slot = g_sqi & g_sqmask;
		struct cqe c;
		iou_sqe(IORING_OP_FALLOCATE, 0, 9999, 0, (void *)4096, 0, 1,
		    0xfa01);
		g_sqes[slot].personality = 99;
		g_sqes[slot].buf_index = 1;
		if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
		    c.res != -EINVAL)
			return (3);
	}
	if (fallocate_option_submit(IOSQE_BUFFER_SELECT, 9999, 0, 4096, 0,
	    99, 0, 0, 0, 0, 0, 0xfa02) != -EOPNOTSUPP)
		return (4);
	/* These opcode fields are rejected during preparation before fd lookup. */
	if (fallocate_option_submit(0, 9999, 0, 4096, 0, 0, 1, 0, 0, 0,
	    0, 0xfa03) != -EINVAL ||
	    fallocate_option_submit(0, 9999, 0, 4096, 0, 0, 0, 1, 0, 0,
	    0, 0xfa04) != -EINVAL ||
	    fallocate_option_submit(0, 9999, 0, 4096, 0, 0, 0, 0, 1, 0,
	    0, 0xfa05) != -EINVAL)
		return (5);
	if (fallocate_option_submit(0, 9999, 0, 4096, 0, 99, 0, 0, 0, 0,
	    0, 0xfa06) != -EINVAL)
		return (6);
	personality = iou_reg(IORING_REGISTER_PERSONALITY, 0, 0);
	if (personality <= 0 || personality > 65535)
		return (7);
	/* io_uring resolves its request file before mode and range validation. */
	if (fallocate_option_submit(0, 9999, 0, 4096, 0x100,
	    (u16)personality, 0, 0, 0, 0, 0, 0xfa07) != -EBADF ||
	    fallocate_option_submit(0, 9999, (u64)-1, 4096, 0,
	    (u16)personality, 0, 0, 0, 0, 0, 0xfa08) != -EBADF)
		return (8);
	if (fallocate_option_submit(0, (int)tf, (u64)-1, 4096, 0,
	    (u16)personality, 0, 0, 0, 0, 0, 0xfa09) != -EINVAL ||
	    fallocate_option_submit(0, (int)tf, 0, 0, 0, 0, 0, 0, 0, 0,
	    0, 0xfa0a) != -EINVAL ||
	    fallocate_option_submit(0, (int)tf, 0x7fffffffffffff00ULL, 4096,
	    0, 0, 0, 0, 0, 0, 0, 0xfa0b) != -EFBIG)
		return (9);
	/* ASYNC and tail words are accepted, and allocation grows the file. */
	if (fallocate_option_submit(IOSQE_ASYNC, (int)tf, 4096, 4096, 0,
	    (u16)personality, 0, 0, 0, 0x1122334455667788ULL,
	    0x8877665544332211ULL, 0xfa0c) != 0 ||
	    sys3(SYS_lseek, tf, 0, 2) != 8192)
		return (10);
	rfd = sys4(SYS_openat, LX_AT_FDCWD, "iou_fallocate_options_path",
	    O_RDONLY, 0);
	if (rfd < 0 || fallocate_option_submit(0, (int)rfd, 0, 4096, 0, 0,
	    0, 0, 0, 0, 0, 0xfa0d) != -EBADF)
		return (11);
	if (sys2(SYS_pipe2, pfd, 0) != 0 ||
	    fallocate_option_submit(0, pfd[1], 0, 4096, 0, 0, 0, 0, 0, 0,
	    0, 0xfa0e) != -ESPIPE)
		return (12);
	(void)sys1(SYS_close, rfd);
	(void)sys1(SYS_close, pfd[0]);
	(void)sys1(SYS_close, pfd[1]);
	/* A registered file remains pinned after ambient close. */
	files[0] = (int)tf;
	files[1] = -1;
	if (iou_reg(IORING_REGISTER_FILES, files, 2) != 0 ||
	    sys1(SYS_close, tf) != 0)
		return (13);
	if (fallocate_option_submit(IOSQE_FIXED_FILE, 0, 8192, 4096, 0, 0,
	    0, 0, 0, 0, 0, 0xfa10) != 0 ||
	    fallocate_option_submit(IOSQE_FIXED_FILE, 1, 0, 4096, 0, 0,
	    0, 0, 0, 0, 0, 0xfa11) != -EBADF ||
	    fallocate_option_submit(IOSQE_FIXED_FILE, 99, 0, 4096, 0, 0,
	    0, 0, 0, 0, 0, 0xfa12) != -EBADF)
		return (14);
	if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0 ||
	    fallocate_option_submit(IOSQE_FIXED_FILE, 0, 0, 4096, 0, 0,
	    0, 0, 0, 0, 0, 0xfa13) != -EBADF ||
	    iou_reg(IORING_UNREGISTER_PERSONALITY, 0, (u32)personality) != 0 ||
	    sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0xfa14) != 0)
		return (15);
	return (0);
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

static int
fadvise_option_submit(u8 flags, int fd, u64 off, u64 length, u32 fallback_len,
    u32 advice, u16 personality, u16 buf_index, int splice_fd_in, u64 addr3,
    u64 pad, u64 user_data)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_FADVISE, flags, fd, off,
	    (void *)(unsigned long)length, fallback_len, advice, user_data);
	g_sqes[slot].personality = personality;
	g_sqes[slot].buf_index = buf_index;
	g_sqes[slot].splice_fd_in = splice_fd_in;
	g_sqes[slot].pad2[0] = addr3;
	g_sqes[slot].pad2[1] = pad;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != user_data || c.flags != 0)
		return (-100000);
	return (c.res);
}

static int
t_fadvise_options(void)
{
	int files[2], pipefd[2];
	long fd, personality;

	if (ring_setup(16) < 0)
		return (1);
	fd = tmpfile_fd("iou_fadvise_options");
	if (fd < 0 || sub1((int)fd, IORING_OP_WRITE, "fadvise", 7, 0, 0,
	    0xe001) != 7)
		return (2);
	/* Generic validation precedes personality lookup and opcode fields. */
	{
		u32 slot = g_sqi & g_sqmask;
		struct cqe c;
		iou_sqe(IORING_OP_FADVISE, 0, 9999, 0, (void *)1, 0, 0,
		    0xe002);
		g_sqes[slot].ioprio = 1;
		g_sqes[slot].personality = 99;
		if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
		    c.res != -EINVAL)
			return (3);
	}
	if (fadvise_option_submit(IOSQE_BUFFER_SELECT, 9999, 0, 1, 0, 0,
	    99, 0, 0, 0, 0, 0xe003) != -EOPNOTSUPP)
		return (4);
	/* Both reserved fields precede personality and file lookup. */
	if (fadvise_option_submit(0, 9999, 0, 1, 0, 0, 99, 1, 0, 0, 0,
	    0xe004) != -EINVAL ||
	    fadvise_option_submit(0, 9999, 0, 1, 0, 0, 99, 0, 1, 0, 0,
	    0xe005) != -EINVAL)
		return (5);
	personality = iou_reg(IORING_REGISTER_PERSONALITY, 0, 0);
	if (personality <= 0 || personality > 65535)
		return (6);
	/* Primary addr length, len fallback, zero length, and every advice. */
	for (u32 advice = 0; advice <= 5; advice++)
		if (fadvise_option_submit(0, (int)fd, 0, advice == 1 ? 0 : 7,
		    advice == 1 ? 7 : 0, advice, (u16)personality, 0, 0, 0, 0,
		    0xe010 + advice) != 0)
			return (7);
	if (fadvise_option_submit(0, (int)fd, 0, 0, 0, 0, 0, 0, 0,
	    0, 0, 0xe018) != 0)
		return (8);
	/* File resolution precedes execution-time advice/range validation. */
	if (fadvise_option_submit(0, 9999, 0, 1, 0, 0xffffffffU, 0, 0, 0,
	    0, 0, 0xe020) != -EBADF ||
	    fadvise_option_submit(0, (int)fd, 0, 1, 0, 0xffffffffU, 0, 0, 0,
	    0, 0, 0xe021) != -EINVAL ||
	    fadvise_option_submit(0, (int)fd, (u64)-1, 1, 0, 0, 0, 0, 0,
	    0, 0, 0xe022) != 0 ||
	    fadvise_option_submit(0, (int)fd, 0, (u64)-1, 0, 0, 0, 0, 0,
	    0, 0, 0xe023) != -EINVAL)
		return (9);
	if (sys2(SYS_pipe2, pipefd, 0) != 0 ||
	    fadvise_option_submit(0, pipefd[0], 0, 1, 0, 0, 0, 0, 0, 0, 0,
	    0xe024) != -ESPIPE)
		return (10);
	(void)sys1(SYS_close, pipefd[0]);
	(void)sys1(SYS_close, pipefd[1]);
	/* Unused addr3/tail words and ASYNC are accepted. */
	if (fadvise_option_submit(IOSQE_ASYNC, (int)fd, 0, 7, 0, 3,
	    (u16)personality, 0, 0, 0x1122334455667788ULL,
	    0x8877665544332211ULL, 0xe025) != 0)
		return (11);
	files[0] = (int)fd;
	files[1] = -1;
	if (iou_reg(IORING_REGISTER_FILES, files, 2) != 0 ||
	    sys1(SYS_close, fd) != 0)
		return (12);
	if (fadvise_option_submit(IOSQE_FIXED_FILE, 0, 0, 7, 0, 0, 0, 0, 0,
	    0, 0, 0xe030) != 0 ||
	    fadvise_option_submit(IOSQE_FIXED_FILE, 1, 0, 7, 0, 0, 0, 0, 0,
	    0, 0, 0xe031) != -EBADF ||
	    fadvise_option_submit(IOSQE_FIXED_FILE, 99, 0, 7, 0, 0, 0, 0, 0,
	    0, 0, 0xe032) != -EBADF)
		return (13);
	if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0 ||
	    fadvise_option_submit(IOSQE_FIXED_FILE, 0, 0, 7, 0, 0, 0, 0, 0,
	    0, 0, 0xe033) != -EBADF ||
	    iou_reg(IORING_UNREGISTER_PERSONALITY, 0, (u32)personality) != 0 ||
	    sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0xe034) != 0 ||
	    sys1(SYS_close, fd_ring) != 0)
		return (14);
	return (0);
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
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x1);
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
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x1);
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
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, IORING_TIMEOUT_ABS, 0x1);
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
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1,
	    IORING_TIMEOUT_ETIME_SUCCESS, 0x1);
	if (iou_flush(1, 1) != 1)
		return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res))
		return (3);
	return (res == -ELINUX_ETIME ? 0 : 4);
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
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 2 /* count */, &ts, 1, 0, 0x1);
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
static int t_timeout_multishot_finite(void)
{
	struct kts ts = { 0, 10000000 };
	struct cqe c[4];
	int n, more = 0, terminal = 0;

	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 3, &ts, 1,
	    IORING_TIMEOUT_MULTISHOT, 0xa1);
	if (iou_flush(1, 3) != 1) return (2);
	n = iou_reap(c, 4);
	if (n != 3) return (3);
	for (int i = 0; i < n; i++) {
		if (c[i].user_data != 0xa1 || c[i].res != -ELINUX_ETIME) return (4);
		if (c[i].flags & IORING_CQE_F_MORE) more++; else terminal++;
	}
	return (more == 2 && terminal == 1 ? 0 : 5);
}

static int t_timeout_multishot_cancel(void)
{
	/* Keep the next shot well beyond the cancellation path under slow TCG. */
	struct kts ts = { 1, 0 };
	struct cqe c[4];
	int n, res;

	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1,
	    IORING_TIMEOUT_MULTISHOT, 0xa1);
	if (iou_flush(1, 1) != 1) return (2);
	n = iou_reap(c, 4);
	if (n != 1 || c[0].user_data != 0xa1 || c[0].res != -ELINUX_ETIME ||
	    !(c[0].flags & IORING_CQE_F_MORE)) return (3);
	iou_sqe(IORING_OP_TIMEOUT_REMOVE, 0, -1, 0, (void *)0xa1, 0, 0, 0xc1);
	if (iou_flush(1, 2) != 1) return (4);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xc1, &res) || res != 0) return (5);
	if (!cqe_find(c, n, 0xa1, &res) || res != -ELINUX_ECANCELED) return (6);
	return (0);
}

static int t_timeout_update(void)
{
	struct kts longts = { 30, 0 }, shortts = { 0, 10000000 };
	struct cqe c[4];
	int n, res;

	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &longts, 1, 0, 0xa1);
	if (iou_flush(1, 0) != 1) return (2);
	iou_sqe(IORING_OP_TIMEOUT_REMOVE, 0, -1, (u64)(unsigned long)&shortts,
	    (void *)0xa1, 0, IORING_TIMEOUT_UPDATE, 0xc1);
	if (iou_flush(1, 1) != 1) return (3);
	n = iou_reap(c, 4);
	if (n != 1 || !cqe_find(c, n, 0xc1, &res) || res != 0) return (4);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS, 0, 0) < 0)
		return (5);
	n = iou_reap(c, 4);
	return (n == 1 && cqe_find(c, n, 0xa1, &res) && res == -ELINUX_ETIME ? 0 : 6);
}

static int t_timeout_update_absolute(void)
{
	struct kts longts = { 30, 0 }, past = { 0, 0 };
	struct cqe c[4];
	int n, res;

	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &longts, 1, 0, 0xa1);
	if (iou_flush(1, 0) != 1) return (2);
	iou_sqe(IORING_OP_TIMEOUT_REMOVE, 0, -1, (u64)(unsigned long)&past,
	    (void *)0xa1, 0, IORING_TIMEOUT_UPDATE | IORING_TIMEOUT_ABS, 0xc1);
	if (iou_flush(1, 2) != 1) return (3);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xc1, &res) || res != 0) return (4);
	if (!cqe_find(c, n, 0xa1, &res) || res != -ELINUX_ETIME) return (5);
	return (0);
}

static int t_link_timeout_update(void)
{
	struct kts longts = { 30, 0 }, shortts = { 0, 10000000 };
	struct cqe c[5];
	int p[2], n, res;

	if (ring_setup(8) < 0 || call(SYS_pipe2, (long)p, 0, 0, 0, 0, 0) != 0)
		return (1);
	iou_sqe(IORING_OP_POLL_ADD, IOSQE_IO_LINK, p[0], 0, 0, 0, LX_POLLIN, 0xa1);
	iou_sqe(IORING_OP_LINK_TIMEOUT, 0, -1, 0, &longts, 1, 0, 0xa2);
	if (iou_flush(2, 0) != 2) return (2);
	iou_sqe(IORING_OP_TIMEOUT_REMOVE, 0, -1, (u64)(unsigned long)&shortts,
	    (void *)0xa2, 0, IORING_TIMEOUT_UPDATE | IORING_LINK_TIMEOUT_UPDATE,
	    0xc1);
	if (iou_flush(1, 3) != 1) return (3);
	n = iou_reap(c, 5);
	if (!cqe_find(c, n, 0xc1, &res) || res != 0) return (4);
	if (!cqe_find(c, n, 0xa1, &res) || res != -ELINUX_ECANCELED) return (5);
	if (!cqe_find(c, n, 0xa2, &res) || res != -ELINUX_ETIME) return (6);
	return (0);
}

static int t_timeout_update_invalid(void)
{
	struct kts longts = { 30, 0 }, bad = { -1, 0 };

	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &longts, 1, 0, 0xa1);
	if (iou_flush(1, 0) != 1) return (2);
	if (sub1(-1, IORING_OP_TIMEOUT_REMOVE, (void *)0xa1, 0,
	    (u64)(unsigned long)&bad, IORING_TIMEOUT_UPDATE, 0xc1) != -EINVAL)
		return (3);
	if (sub1(-1, IORING_OP_TIMEOUT_REMOVE, (void *)0xa1, 0, 1,
	    IORING_TIMEOUT_UPDATE, 0xc2) != -EFAULT) return (4);
	if (sub1(-1, IORING_OP_TIMEOUT_REMOVE, (void *)0xa1, 0,
	    (u64)(unsigned long)&longts, 1U << 31, 0xc3) != -EINVAL) return (5);
	if (sub1(-1, IORING_OP_TIMEOUT_REMOVE, (void *)0xdead, 0,
	    (u64)(unsigned long)&longts, IORING_TIMEOUT_UPDATE, 0xc4) != -ENOENT)
		return (6);
	/* Rejected updates and a missing key leave the original timeout live. */
	iou_sqe(IORING_OP_TIMEOUT_REMOVE, 0, -1, 0, (void *)0xa1, 0, 0, 0xc5);
	if (iou_flush(1, 2) != 1) return (7);
	{ struct cqe c[2]; int n = iou_reap(c, 2), res;
	  if (!cqe_find(c, n, 0xc5, &res) || res != 0 ||
	      !cqe_find(c, n, 0xa1, &res) || res != -ELINUX_ECANCELED)
		return (8); }
	return (0);
}

static int
t_timeout_immediate_basic(void)
{
	struct kts now;
	u64 deadline;

	if (ring_setup(8) < 0)
		return (1);
	if (sub1(-1, IORING_OP_TIMEOUT, (void *)(unsigned long)20000000,
	    1, 0, IORING_TIMEOUT_IMMEDIATE_ARG, 0xb10) != -ELINUX_ETIME)
		return (2);
	if (sub1(-1, IORING_OP_TIMEOUT, 0, 1, 0,
	    IORING_TIMEOUT_IMMEDIATE_ARG | IORING_TIMEOUT_ABS,
	    0xb11) != -ELINUX_ETIME)
		return (3);
	if (sys2(SYS_clock_gettime, 1, &now) != 0)
		return (4);
	deadline = (u64)now.tv_sec * 1000000000ULL + now.tv_nsec +
	    20000000ULL;
	if (sub1(-1, IORING_OP_TIMEOUT, (void *)(unsigned long)deadline,
	    1, 0, IORING_TIMEOUT_IMMEDIATE_ARG | IORING_TIMEOUT_ABS,
	    0xb12) != -ELINUX_ETIME)
		return (5);
	if (sub1(-1, IORING_OP_TIMEOUT, (void *)1, 1, 0,
	    0, 0xb13) != -EFAULT)
		return (6);
	return (0);
}

static int
t_timeout_immediate_invalid(void)
{
	struct kts longts = { 30, 0 };
	struct cqe c[4];
	int n, res;

	if (ring_setup(8) < 0)
		return (1);
	if (sub1(-1, IORING_OP_TIMEOUT,
	    (void *)(unsigned long)(1ULL << 63), 1, 0,
	    IORING_TIMEOUT_IMMEDIATE_ARG, 0xb20) != -EINVAL)
		return (2);
	if (sub1(-1, IORING_OP_TIMEOUT, (void *)1, 1, 0,
	    IORING_TIMEOUT_IMMEDIATE_ARG | IORING_TIMEOUT_UPDATE,
	    0xb21) != -EINVAL)
		return (3);
	if (sub1(-1, IORING_OP_TIMEOUT_REMOVE, (void *)0xb22, 0, 0,
	    IORING_TIMEOUT_IMMEDIATE_ARG, 0xb23) != -EINVAL)
		return (4);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &longts, 1, 0, 0xb24);
	if (iou_flush(1, 0) != 1)
		return (5);
	if (sub1(-1, IORING_OP_TIMEOUT_REMOVE, (void *)0xb24, 0,
	    1ULL << 63, IORING_TIMEOUT_UPDATE |
	    IORING_TIMEOUT_IMMEDIATE_ARG, 0xb25) != -EINVAL)
		return (6);
	iou_sqe(IORING_OP_TIMEOUT_REMOVE, 0, -1, 0, (void *)0xb24,
	    0, 0, 0xb26);
	if (iou_flush(1, 2) != 1)
		return (6);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xb26, &res) || res != 0 ||
	    !cqe_find(c, n, 0xb24, &res) ||
	    res != -ELINUX_ECANCELED)
		return (8);
	return (0);
}

static int
t_timeout_immediate_update(void)
{
	struct kts longts = { 30, 0 };
	struct cqe c[4];
	int n, res;

	if (ring_setup(8) < 0)
		return (1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &longts, 1, 0, 0xb30);
	if (iou_flush(1, 0) != 1)
		return (2);
	iou_sqe(IORING_OP_TIMEOUT_REMOVE, 0, -1, 10000000ULL,
	    (void *)0xb30, 0, IORING_TIMEOUT_UPDATE |
	    IORING_TIMEOUT_IMMEDIATE_ARG, 0xb31);
	if (iou_flush(1, 2) != 1)
		return (3);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xb31, &res) || res != 0 ||
	    !cqe_find(c, n, 0xb30, &res) ||
	    res != -ELINUX_ETIME)
		return (4);
	return (0);
}

static int
t_timeout_immediate_link_multishot(void)
{
	struct cqe c[5];
	int p[2], n, res, more, terminal;

	if (ring_setup(8) < 0 ||
	    call(SYS_pipe2, (long)p, 0, 0, 0, 0, 0) != 0)
		return (1);
	iou_sqe(IORING_OP_POLL_ADD, IOSQE_IO_LINK, p[0], 0, 0, 0,
	    LX_POLLIN, 0xb40);
	iou_sqe(IORING_OP_LINK_TIMEOUT, 0, -1, 0,
	    (void *)(unsigned long)20000000, 1,
	    IORING_TIMEOUT_IMMEDIATE_ARG, 0xb41);
	if (iou_flush(2, 2) != 2)
		return (2);
	n = iou_reap(c, 5);
	if (!cqe_find(c, n, 0xb40, &res) ||
	    res != -ELINUX_ECANCELED ||
	    !cqe_find(c, n, 0xb41, &res) ||
	    res != -ELINUX_ETIME)
		return (3);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 3,
	    (void *)(unsigned long)20000000, 1,
	    IORING_TIMEOUT_MULTISHOT | IORING_TIMEOUT_IMMEDIATE_ARG,
	    0xb42);
	if (iou_flush(1, 1) != 1)
		return (4);
	n = iou_reap(c, 5);
	while (n < 3) {
		if (call(SYS_io_uring_enter, fd_ring, 0, 1,
		    IORING_ENTER_GETEVENTS, 0, 0) < 0)
			return (5);
		n += iou_reap(c + n, 5 - n);
	}
	if (n != 3)
		return (5);
	more = terminal = 0;
	for (int i = 0; i < n; i++) {
		if (c[i].user_data != 0xb42 ||
		    c[i].res != -ELINUX_ETIME)
			return (6);
		if ((c[i].flags & IORING_CQE_F_MORE) != 0)
			more++;
		else
			terminal++;
	}
	(void)sys1(SYS_close, p[0]);
	(void)sys1(SYS_close, p[1]);
	return (more == 2 && terminal == 1 ? 0 : 7);
}

static int
timeout_reserved_one(u8 opcode, u64 addr3, u64 pad, u32 flags, u64 user_data)
{
	struct kts ts = { 1, 0 };
	struct cqe c;
	u32 slot;

	iou_sqe(opcode, 0, -1, opcode == IORING_OP_TIMEOUT_REMOVE &&
	    (flags & IORING_TIMEOUT_UPDATE) != 0 ? (u64)&ts : 0,
	    opcode == IORING_OP_TIMEOUT ? (void *)&ts : (void *)0xdead,
	    opcode == IORING_OP_TIMEOUT ? 1 : 0, flags, user_data);
	slot = (g_sqi - 1) & g_sqmask;
	g_sqes[slot].pad2[0] = addr3;
	g_sqes[slot].pad2[1] = pad;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != user_data)
		return (-100000);
	return (c.res);
}

static int
timeout_reserved_link(u64 addr3, u64 pad, u64 base)
{
	struct kts ts = { 1, 0 };
	struct cqe c[2];
	u32 slot;
	int n, res;

	iou_sqe(IORING_OP_NOP, IOSQE_IO_LINK, -1, 0, 0, 0, 0, base);
	iou_sqe(IORING_OP_LINK_TIMEOUT, 0, -1, 0, &ts, 1, 0, base + 1);
	slot = (g_sqi - 1) & g_sqmask;
	g_sqes[slot].pad2[0] = addr3;
	g_sqes[slot].pad2[1] = pad;
	if (iou_flush(2, 2) != 2 || (n = iou_reap(c, 2)) != 2)
		return (1);
	if (!cqe_find(c, n, base, &res) || res != -ELINUX_ECANCELED ||
	    !cqe_find(c, n, base + 1, &res) || res != -EINVAL)
		return (2);
	return (0);
}

static int
t_timeout_reserved_fields(void)
{
	u32 update = IORING_TIMEOUT_UPDATE;
	int error;

	if (ring_setup(16) < 0)
		return (1);
	if (timeout_reserved_one(IORING_OP_TIMEOUT, 1, 0, 0, 0xb50) !=
	    -EINVAL ||
	    timeout_reserved_one(IORING_OP_TIMEOUT, 0, 1, 0, 0xb51) !=
	    -EINVAL)
		return (2);
	if (timeout_reserved_one(IORING_OP_TIMEOUT_REMOVE, 1, 0, 0, 0xb52) !=
	    -EINVAL ||
	    timeout_reserved_one(IORING_OP_TIMEOUT_REMOVE, 0, 1, 0, 0xb53) !=
	    -EINVAL)
		return (3);
	/* Reserved extensions precede update-time pointer import. */
	if (timeout_reserved_one(IORING_OP_TIMEOUT_REMOVE, 1, 0, update,
	    0xb54) != -EINVAL ||
	    timeout_reserved_one(IORING_OP_TIMEOUT_REMOVE, 0, 1, update,
	    0xb55) != -EINVAL)
		return (4);
	error = timeout_reserved_link(1, 0, 0xb56);
	if (error != 0)
		return (5 + error);
	error = timeout_reserved_link(0, 1, 0xb58);
	if (error != 0)
		return (8 + error);
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0xb5a) != 0)
		return (11);
	(void)sys1(SYS_close, fd_ring);
	return (0);
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
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, IORING_TIMEOUT_UPDATE, 0x1);
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
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, (void *)0x10, 1, 0, 0x1);
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
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x1);
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
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0xA5);
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
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x55);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x55);
	if (iou_flush(2, 0) != 2)
		return (2);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0x55, 0,
	    IORING_ASYNC_CANCEL_ALL, 0x56);
	if (iou_flush(1, 3) != 1)
		return (3);
	n = iou_reap(c, 8);
	if (n != 3)
		return (4);
	if (!cqe_find(c, n, 0x56, &res) || res != 2)
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
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x77);
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
	struct kts ts = { 30, 0 };
	int res;

	if (ring_setup(8) < 0)
		return (1);
	/* Every invalid form must fail without disturbing an existing request. */
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x44);
	if (iou_flush(1, 0) != 1)
		return (2);
	res = sub1(-1, IORING_OP_ASYNC_CANCEL, 0, 0, 0,
	    IORING_ASYNC_CANCEL_ANY | IORING_ASYNC_CANCEL_FD, 0x51);
	if (res != -EINVAL)
		return (3);
	res = sub1(-1, IORING_OP_ASYNC_CANCEL, 0, IORING_OP_TIMEOUT, 0,
	    IORING_ASYNC_CANCEL_ANY | IORING_ASYNC_CANCEL_OP, 0x52);
	if (res != -EINVAL)
		return (4);
	res = sub1(-1, IORING_OP_ASYNC_CANCEL, 0, IORING_OP_LAST, 0,
	    IORING_ASYNC_CANCEL_OP, 0x53);
	if (res != -EINVAL)
		return (5);
	res = sub1(-1, IORING_OP_ASYNC_CANCEL, 0, 0, 0, 1U << 31, 0x54);
	if (res != -EINVAL)
		return (6);
	res = sub1(9999, IORING_OP_ASYNC_CANCEL, 0, 0, 0,
	    IORING_ASYNC_CANCEL_FD, 0x55);
	if (res != -EBADF)
		return (7);
	res = sub1(9999, IORING_OP_ASYNC_CANCEL, 0, 0, 0,
	    IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_FD_FIXED, 0x56);
	if (res != -EBADF)
		return (8);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0x44, 0, 0, 0x57);
	if (iou_flush(1, 2) != 1)
		return (9);
	{ struct cqe c[2]; int n = iou_reap(c, 2);
	  if (!cqe_find(c, n, 0x57, &res) || res != 0 ||
	      !cqe_find(c, n, 0x44, &res) || res != -ELINUX_ECANCELED)
		return (10); }
	return (0);
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
	iou_sqe(IORING_OP_TIMEOUT, IOSQE_IO_LINK, -1, 0, &ts, 1,
	    IORING_TIMEOUT_ETIME_SUCCESS, 0xD1);
	iou_sqe(IORING_OP_WRITE, 0, tf, 0, "hello!!", 7, 0, 0xD2);
	if (iou_flush(2, 2) != 2)
		return (3);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xD1, &res) || res != -ELINUX_ETIME)
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
	/* Errors must still produce a CQE even when success would be skipped. */
	char byte = 0;
	iou_sqe(IORING_OP_READ, IOSQE_CQE_SKIP_SUCCESS, -1, 0,
	    &byte, 1, 0, 0xE3);
	if (iou_flush(1, 1) != 1)
		return (5);
	n = iou_reap(c, 4);
	if (n != 1 || c[0].user_data != 0xE3ULL || c[0].res != -EBADF)
		return (6);
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
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0xE01);
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
	/* Socket URING_CMD is dispatched by the Linuxulator front end. */
	if ((pr.ops[46].flags & IO_URING_OP_SUPPORTED) == 0)
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
	return (call(SYS_io_uring_enter, fd_ring, 0, 0, 0x100, 0, 0) == -EINVAL ?
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
	if (call(SYS_io_uring_enter, fd_ring, 1, 0, 0, 0, 0) != 0)
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
	/* Linux rejects buffer-select on WRITE during common preparation. */
	iou_sqe(IORING_OP_WRITE, IOSQE_BUFFER_SELECT, -1, 0, rb, 4, 0, 0x1);
	{
		struct cqe c[2];
		int n, res = 0;
		if (iou_flush(1, 1) != 1)
			return (2);
		n = iou_reap(c, 2);
		if (n != 1 || !cqe_find(c, n, 0x1, &res))
			return (3);
		return (res == -EOPNOTSUPP ? 0 : 4);
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
	if ((__atomic_load_n(g_sq_flags, __ATOMIC_ACQUIRE) &
	    IORING_SQ_CQ_OVERFLOW) == 0)
		return (3);
	/* CQ is full at cq_entries; backlogged CQEs have not been lost. */
	if (__atomic_load_n(g_cq_overflow, __ATOMIC_ACQUIRE) != 0)
		return (5);
	if (__atomic_load_n(g_cq_tail, __ATOMIC_ACQUIRE) != g_cqe_cnt)
		return (4);
	return (0);
}
/*
 * NODROP: completions that overflow the CQ are backlogged, not lost.  Submit
 * more NOPs than the CQ holds, then drain and re-enter until all are seen -
 * every user_data must come back exactly once.
 */
static int t_cq_overflow_recover(void)
{
	int i, b, got = 0, sent = 0;
	unsigned seen = 0;
	struct cqe c[16];
	int n;
	if (ring_setup(8) < 0)		/* sq 8, cq 16 */
		return (1);
	/* submit 20 NOPs (batches of 8) with distinct user_data, no reaping */
	while (sent < 20) {
		int batch = 20 - sent > 8 ? 8 : 20 - sent;
		for (i = 0; i < batch; i++)
			iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0,
			    (u64)(0x100 + sent + i));
		if (iou_flush(batch, 0) != batch)
			return (2);
		sent += batch;
	}
	/* some overflowed (20 > cq 16) */
	if ((__atomic_load_n(g_sq_flags, __ATOMIC_ACQUIRE) &
	    IORING_SQ_CQ_OVERFLOW) == 0)
		return (3);
	if (__atomic_load_n(g_cq_overflow, __ATOMIC_ACQUIRE) != 0)
		return (5);
	/* drain the CQ, re-entering to flush the backlog, until all 20 arrive */
	for (b = 0; b < 12 && got < 20; b++) {
		n = iou_reap(c, 16);
		for (i = 0; i < n; i++) {
			u64 ud = c[i].user_data;
			if (ud >= 0x100 && ud < 0x114) {
				seen |= (1u << (unsigned)(ud - 0x100));
				got++;
			}
		}
		if (got < 20)
			(void)call(SYS_io_uring_enter, fd_ring, 0, 1,
			    IORING_ENTER_GETEVENTS, 0, 0);
	}
	if (got != 20 || seen != 0xFFFFFu)	/* all 20, each once, none lost */
		return (4);
	return (0);
}
/*
 * The overflow backlog is bounded: flooding a ring with far more completions
 * than the CQ and backlog can hold must not wedge or exhaust it - excess
 * completions are dropped-and-counted, and the ring stays usable afterwards.
 */
static int t_cq_overflow_bounded(void)
{
	int b, i, n;
	struct cqe c[16];
	if (ring_setup(8) < 0)		/* cq 16, backlog cap 4*16 = 64 */
		return (1);
	/* 200 NOPs, never reaping: overruns the CQ and the backlog cap */
	for (b = 0; b < 25; b++) {
		for (i = 0; i < 8; i++)
			iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 1);
		if (iou_flush(8, 0) != 8)
			return (2);
	}
	if ((__atomic_load_n(g_sq_flags, __ATOMIC_ACQUIRE) &
	    IORING_SQ_CQ_OVERFLOW) == 0)
		return (3);
	/*
	 * Drain: reap the CQ, then while the backlog flag is still set, enter
	 * with min_complete=1 (which flushes the backlog into the CQ) and reap
	 * again.  Stop once the CQ is empty and the overflow flag has cleared.
	 */
	for (b = 0; b < 200; b++) {
		n = iou_reap(c, 16);
		if (n == 0 && (__atomic_load_n(g_sq_flags, __ATOMIC_ACQUIRE) &
		    IORING_SQ_CQ_OVERFLOW) == 0)
			break;
		if ((__atomic_load_n(g_sq_flags, __ATOMIC_ACQUIRE) &
		    IORING_SQ_CQ_OVERFLOW) != 0)
			(void)call(SYS_io_uring_enter, fd_ring, 0, 1,
			    IORING_ENTER_GETEVENTS, 0, 0);
	}
	/* the ring survived the storm and still completes work */
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0x999) != 0)
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
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_oa", 0);
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
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_oa", 0);
	return (0);
}
static int
t_openat_enoent(void)
{
	if (ring_setup(8) < 0)
		return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_none", 0);
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
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_sx", 0);
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
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_sx", 0);
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
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_sl", 0);
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
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_sl", 0);
	return (res == 0 ? 0 : 4);
}
static int
t_linkat(void)
{
	long tf;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_l1", 0);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_l2", 0);
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
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_l1", 0);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_l2", 0);
	return (res == 0 ? 0 : 5);
}
static int
t_renameat(void)
{
	long tf;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_rn1", 0);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_rn2", 0);
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
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_rn2", 0);
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
/* MADVISE takes its 64-bit length from off, falling back to len when zero. */
static int
t_madvise_length(void)
{
	u8 *p;
	long m;
	int res;

	if (ring_setup(8) < 0)
		return (1);
	m = call(SYS_mmap, 0, 3 * PAGE, PROT_READ | PROT_WRITE,
	    LX_MAP_PRIVATE | LX_MAP_ANON, -1, 0);
	if (m < 0)
		return (2);
	p = (u8 *)(unsigned long)m;
	p[0] = 0x11;
	p[PAGE] = 0x22;
	p[2 * PAGE] = 0x33;

	/* off wins over the conflicting one-page legacy len. */
	res = sub1(12345, IORING_OP_MADVISE, p, PAGE, 2 * PAGE,
	    LX_MADV_DONTNEED, 0x901);
	if (res != 0 || p[0] != 0 || p[PAGE] != 0 || p[2 * PAGE] != 0x33)
		return (3);

	/* A zero off retains the legacy 32-bit len fallback. */
	p[0] = 0x44;
	p[PAGE] = 0x55;
	res = sub1(-77, IORING_OP_MADVISE, p, PAGE, 0,
	    LX_MADV_DONTNEED, 0x902);
	if (res != 0 || p[0] != 0 || p[PAGE] != 0x55)
		return (4);
	(void)sys2(SYS_munmap, p, 3 * PAGE);
	return (0);
}

static int
t_madvise_options(void)
{
	struct cqe c[2];
	u8 *p;
	long m;
	u32 slot;
	int i, res;

	if (ring_setup(8) < 0)
		return (1);
	m = call(SYS_mmap, 0, 2 * PAGE, PROT_READ | PROT_WRITE,
	    LX_MAP_PRIVATE | LX_MAP_ANON, -1, 0);
	if (m < 0)
		return (2);
	p = (u8 *)(unsigned long)m;

	/* fd is ignored for this no-file opcode, as on Linux. */
	if (sub1(12345, IORING_OP_MADVISE, p, PAGE, 0,
	    LX_MADV_NORMAL, 0x910) != 0)
		return (3);
	if (sub1(12345, IORING_OP_MADVISE, p + 1, PAGE, 0,
	    LX_MADV_NORMAL, 0x911) != -EINVAL ||
	    sub1(12345, IORING_OP_MADVISE, p, PAGE, 0,
	    0x7fffffffU, 0x912) != -EINVAL ||
	    sub1(12345, IORING_OP_MADVISE, p, 0, (u64)-1,
	    LX_MADV_NORMAL, 0x913) != -EINVAL)
		return (4);

	/* Linux prep reserves buf_index and splice_fd_in. */
	for (i = 0; i < 2; i++) {
		p[0] = 0x61 + i;
		slot = g_sqi & g_sqmask;
		iou_sqe(IORING_OP_MADVISE, 0, 12345, PAGE, p, PAGE,
		    LX_MADV_DONTNEED, 0x920 + i);
		if (i == 0)
			g_sqes[slot].buf_index = 1;
		else
			g_sqes[slot].splice_fd_in = 1;
		if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
		    !cqe_find(c, 1, 0x920 + i, &res) || res != -EINVAL ||
		    p[0] != 0x61 + i)
			return (5 + i);
	}

	/* FIXED_FILE is ignored because MADVISE does not acquire a file. */
	p[0] = 0x71;
	iou_sqe(IORING_OP_MADVISE, IOSQE_FIXED_FILE, 0, PAGE, p, PAGE,
	    LX_MADV_DONTNEED, 0x930);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
	    !cqe_find(c, 1, 0x930, &res) || res != 0 || p[0] != 0)
		return (7);

	/* ioprio is rejected before the advice can discard. */
	p[0] = 0x72;
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_MADVISE, 0, 12345, PAGE, p, PAGE,
	    LX_MADV_DONTNEED, 0x931);
	g_sqes[slot].ioprio = 1;
	if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
	    !cqe_find(c, 1, 0x931, &res) || res != -EINVAL || p[0] != 0x72)
		return (8);

	/* A valid request still works after all rejected preparations. */
	if (sub1(12345, IORING_OP_MADVISE, p, PAGE, 0,
	    LX_MADV_DONTNEED, 0x932) != 0 || p[0] != 0)
		return (9);
	(void)sys2(SYS_munmap, p, 2 * PAGE);
	return (0);
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
t_sync_file_range_options(void)
{
	struct cqe c[2];
	long tf;
	int fds[2], pfd[2], flags, i, res;
	u32 slot;

	if (ring_setup(16) < 0)
		return (1);
	/* A missing fixed-file table is distinguished from a bad slot. */
	if (fixed_op(IORING_OP_SYNC_FILE_RANGE, 0, 0, 0, 0, 0,
	    IOSQE_FIXED_FILE, 0x940) != -EBADF)
		return (2);
	tf = tmpfile_fd("iou_sfr_options");
	if (tf < 0 || sub1((int)tf, IORING_OP_WRITE, "range", 5, 0, 0,
	    0x941) != 5)
		return (3);
	for (flags = 0; flags < 8; flags++)
		if (sub1((int)tf, IORING_OP_SYNC_FILE_RANGE, 0, 5, 0,
		    (u32)flags, 0x950 + flags) != 0)
			return (4);
	if (sub1((int)tf, IORING_OP_SYNC_FILE_RANGE, 0, 0,
	    0x7fffffffffffffffULL, 0, 0x960) != 0 ||
	    sub1((int)tf, IORING_OP_SYNC_FILE_RANGE, 0, 1,
	    0x7fffffffffffffffULL, 0, 0x961) != -EINVAL ||
	    sub1((int)tf, IORING_OP_SYNC_FILE_RANGE, 0, 1, (u64)-1,
	    0, 0x962) != -EINVAL ||
	    sub1((int)tf, IORING_OP_SYNC_FILE_RANGE, 0, 1, 0,
	    8, 0x963) != -EINVAL)
		return (5);
	/* File lookup wins over invalid operation arguments. */
	if (sub1(9999, IORING_OP_SYNC_FILE_RANGE, 0, 1, (u64)-1,
	    8, 0x964) != -EBADF)
		return (6);
	/* Linux prep reserves addr, buf_index, and splice_fd_in. */
	for (i = 0; i < 3; i++) {
		slot = g_sqi & g_sqmask;
		iou_sqe(IORING_OP_SYNC_FILE_RANGE, 0, (int)tf, 0,
		    i == 0 ? (void *)1 : 0, 0, 0, 0x970 + i);
		if (i == 1)
			g_sqes[slot].buf_index = 1;
		if (i == 2)
			g_sqes[slot].splice_fd_in = 1;
		if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
		    !cqe_find(c, 1, 0x970 + i, &res) || res != -EINVAL)
			return (7 + i);
	}
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SYNC_FILE_RANGE, 0, (int)tf, 0, 0, 0, 0,
	    0x974);
	g_sqes[slot].ioprio = 1;
	if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
	    !cqe_find(c, 1, 0x974, &res) || res != -EINVAL)
		return (10);
	if (sys2(SYS_pipe2, pfd, 0) != 0 ||
	    sub1(pfd[0], IORING_OP_SYNC_FILE_RANGE, 0, 0, 0, 0,
	    0x975) != -ESPIPE)
		return (11);
	(void)sys1(SYS_close, pfd[0]);
	(void)sys1(SYS_close, pfd[1]);
	fds[0] = (int)tf;
	fds[1] = -1;
	if (iou_reg(IORING_REGISTER_FILES, fds, 2) != 0)
		return (12);
	(void)sys1(SYS_close, tf);
	if (fixed_op(IORING_OP_SYNC_FILE_RANGE, 0, 0, 0, 0, 0,
	    IOSQE_FIXED_FILE, 0x976) != 0 ||
	    fixed_op(IORING_OP_SYNC_FILE_RANGE, 1, 0, 0, 0, 0,
	    IOSQE_FIXED_FILE, 0x977) != -EBADF ||
	    fixed_op(IORING_OP_SYNC_FILE_RANGE, 2, 0, 0, 0, 0,
	    IOSQE_FIXED_FILE, 0x978) != -EBADF)
		return (13);
	return (0);
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
netctl_option_submit(u8 opcode, u8 flags, int fd, void *addr, u64 addr2,
    u32 len, int field, u64 ud)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(opcode, flags, fd, addr2, addr, len, 0, ud);
	switch (field) {
	case 1: g_sqes[slot].len = 1; break;
	case 2: g_sqes[slot].rw_flags = 1; break;
	case 3: g_sqes[slot].buf_index = 1; break;
	case 4: g_sqes[slot].splice_fd_in = 1; break;
	case 5: g_sqes[slot].pad2[0] = 1; break;	/* addr3 */
	case 6: g_sqes[slot].pad2[1] = 0xbeef; break;
	case 7: g_sqes[slot].ioprio = 1; break;
	case 8: g_sqes[slot].off = 1; break;
	case 9: g_sqes[slot].addr = 1; break;
	default: break;
	}
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != ud)
		return (-100000);
	return (c.res);
}

static int
t_bind_listen_options(void)
{
	struct sockaddr_in sin;
	int files[2], sfd, sfd2, dgram, pfd, res;

	if (ring_setup(32) < 0)
		return (1);
	xmemset(&sin, 0, sizeof(sin));
	sin.sin_family = LX_AF_INET;
	sin.sin_addr = 0x0100007f;

	sfd = (int)sys3(SYS_socket, LX_AF_INET, LX_SOCK_STREAM, 0);
	if (sfd < 0)
		return (2);

	/* BIND reserves len/rw_flags/buf_index/splice_fd_in. */
	for (int field = 1; field <= 4; field++)
		if (netctl_option_submit(IORING_OP_BIND, 0, sfd, &sin,
		    sizeof(sin), 0, field, 0xb100 + field) != -EINVAL)
			return (3);
	if (netctl_option_submit(IORING_OP_BIND, 0, sfd, &sin, sizeof(sin),
	    0, 7, 0xb107) != -EINVAL ||
	    netctl_option_submit(IORING_OP_BIND, IOSQE_BUFFER_SELECT, sfd,
	    &sin, sizeof(sin), 0, 0, 0xb108) != -EOPNOTSUPP)
		return (4);

	/* Linux copies the sockaddr before looking up a fixed-file slot. */
	if (netctl_option_submit(IORING_OP_BIND, IOSQE_FIXED_FILE, 9,
	    (void *)1, sizeof(sin), 0, 0, 0xb109) != -EFAULT ||
	    netctl_option_submit(IORING_OP_BIND, IOSQE_FIXED_FILE, 9,
	    &sin, 129, 0, 0, 0xb10a) != -EINVAL)
		return (5);

	/* addr3 and the final word are unused; successful bind proves no side
	 * effect escaped any preceding preparation failure. */
	if (netctl_option_submit(IORING_OP_BIND, 0, sfd, &sin, sizeof(sin),
	    0, 5, 0xb10b) != 0)
		return (6);

	/* LISTEN reserves addr2, addr, rw_flags, buf_index and splice_fd_in. */
	if (netctl_option_submit(IORING_OP_LISTEN, 0, sfd, 0, 0, 8, 8,
	    0xb110) != -EINVAL ||
	    netctl_option_submit(IORING_OP_LISTEN, 0, sfd, 0, 0, 8, 9,
	    0xb111) != -EINVAL)
		return (7);
	for (int field = 2; field <= 4; field++)
		if (netctl_option_submit(IORING_OP_LISTEN, 0, sfd, 0, 0, 8,
		    field, 0xb112 + field) != -EINVAL)
			return (8);
	if (netctl_option_submit(IORING_OP_LISTEN, 0, sfd, 0, 0, 8, 7,
	    0xb118) != -EINVAL ||
	    netctl_option_submit(IORING_OP_LISTEN, IOSQE_BUFFER_SELECT, sfd,
	    0, 0, 8, 0, 0xb119) != -EOPNOTSUPP)
		return (9);
	/* LISTEN also ignores addr3 and the final word. */
	if (netctl_option_submit(IORING_OP_LISTEN, 0, sfd, 0, 0, 8, 5,
	    0xb11a) != 0 ||
	    netctl_option_submit(IORING_OP_LISTEN, 0, sfd, 0, 0, 8, 6,
	    0xb11b) != 0)
		return (10);

	/* Registered sockets retain lifetime after their ambient fd closes. */
	sfd2 = (int)sys3(SYS_socket, LX_AF_INET, LX_SOCK_STREAM, 0);
	if (sfd2 < 0)
		return (11);
	files[0] = sfd2;
	files[1] = -1;
	if (iou_reg(IORING_REGISTER_FILES, files, 2) != 0)
		return (12);
	(void)sys1(SYS_close, sfd2);
	if (netctl_option_submit(IORING_OP_BIND, IOSQE_FIXED_FILE, 0, &sin,
	    sizeof(sin), 0, 0, 0xb120) != 0 ||
	    netctl_option_submit(IORING_OP_LISTEN, IOSQE_FIXED_FILE, 0, 0, 0,
	    4, 0, 0xb121) != 0)
		return (13);
	if (netctl_option_submit(IORING_OP_BIND, IOSQE_FIXED_FILE, 1, &sin,
	    sizeof(sin), 0, 0, 0xb122) != -EBADF ||
	    netctl_option_submit(IORING_OP_LISTEN, IOSQE_FIXED_FILE, 2, 0, 0,
	    4, 0, 0xb123) != -EBADF)
		return (14);
	if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0 ||
	    netctl_option_submit(IORING_OP_LISTEN, IOSQE_FIXED_FILE, 0, 0, 0,
	    4, 0, 0xb124) != -EBADF)
		return (15);

	/* File-type failures and a fresh successful pair verify recovery. */
	pfd = (int)tmpfile_fd("iou_bind_notsock");
	dgram = (int)sys3(SYS_socket, LX_AF_INET, LX_SOCK_DGRAM, 0);
	if (pfd < 0 || dgram < 0 ||
	    netctl_option_submit(IORING_OP_BIND, 0, pfd, &sin, sizeof(sin),
	    0, 0, 0xb130) != -ENOTSOCK ||
	    netctl_option_submit(IORING_OP_LISTEN, 0, dgram, 0, 0, 4, 0,
	    0xb131) != -EOPNOTSUPP)
		return (16);
	sfd2 = (int)sys3(SYS_socket, LX_AF_INET, LX_SOCK_STREAM, 0);
	if (sfd2 < 0 ||
	    netctl_option_submit(IORING_OP_BIND, 0, sfd2, &sin, sizeof(sin),
	    0, 0, 0xb132) != 0 ||
	    netctl_option_submit(IORING_OP_LISTEN, IOSQE_ASYNC, sfd2, 0, 0,
	    1, 0, 0xb133) != 0)
		return (17);
	res = (int)sys1(SYS_close, sfd2);
	(void)sys1(SYS_close, pfd);
	(void)sys1(SYS_close, dgram);
	(void)sys1(SYS_close, sfd);
	return (res == 0 ? 0 : 18);
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
connect_shutdown_submit(u8 opcode, u8 flags, int fd, void *addr, u64 off,
    u32 len, int field, u64 ud)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(opcode, flags, fd, off, addr, len, 0, ud);
	switch (field) {
	case 1: g_sqes[slot].len = 1; break;
	case 2: g_sqes[slot].rw_flags = 1; break;
	case 3: g_sqes[slot].buf_index = 1; break;
	case 4: g_sqes[slot].splice_fd_in = 1; break;
	case 5: g_sqes[slot].pad2[0] = 1; break;
	case 6: g_sqes[slot].pad2[1] = 0xcafe; break;
	case 7: g_sqes[slot].ioprio = 1; break;
	case 8: g_sqes[slot].off = 1; break;
	case 9: g_sqes[slot].addr = 1; break;
	default: break;
	}
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != ud)
		return (-100000);
	return (c.res);
}

static int
t_connect_shutdown_options(void)
{
	struct sockaddr_in sin;
	char ch;
	int files[2], sv[2], sv2[2], fd, fd2, tf;

	if (ring_setup(32) < 0)
		return (1);
	xmemset(&sin, 0, sizeof(sin));
	sin.sin_family = LX_AF_INET;
	sin.sin_port = 0x0900;
	sin.sin_addr = 0x0100007f;
	fd = (int)sys3(SYS_socket, LX_AF_INET, LX_SOCK_DGRAM, 0);
	if (fd < 0)
		return (2);

	/* CONNECT reserves len/rw_flags/buf_index/splice_fd_in. */
	for (int field = 1; field <= 4; field++)
		if (connect_shutdown_submit(IORING_OP_CONNECT, 0, fd, &sin,
		    sizeof(sin), 0, field, 0xc100 + field) != -EINVAL)
			return (3);
	if (connect_shutdown_submit(IORING_OP_CONNECT, 0, fd, &sin,
	    sizeof(sin), 0, 7, 0xc107) != -EINVAL ||
	    connect_shutdown_submit(IORING_OP_CONNECT, IOSQE_BUFFER_SELECT,
	    fd, &sin, sizeof(sin), 0, 0, 0xc108) != -EOPNOTSUPP)
		return (4);
	/* Sockaddr copyin and bounds checks precede fixed-slot resolution. */
	if (connect_shutdown_submit(IORING_OP_CONNECT, IOSQE_FIXED_FILE, 9,
	    (void *)1, sizeof(sin), 0, 0, 0xc109) != -EFAULT ||
	    connect_shutdown_submit(IORING_OP_CONNECT, IOSQE_FIXED_FILE, 9,
	    &sin, 129, 0, 0, 0xc10a) != -EINVAL)
		return (5);
	/* addr3 and the final SQE word are unused. */
	if (connect_shutdown_submit(IORING_OP_CONNECT, 0, fd, &sin,
	    sizeof(sin), 0, 5, 0xc10b) != 0)
		return (6);
	fd2 = (int)sys3(SYS_socket, LX_AF_INET, LX_SOCK_DGRAM, 0);
	if (fd2 < 0)
		return (7);
	files[0] = fd2;
	files[1] = -1;
	if (iou_reg(IORING_REGISTER_FILES, files, 2) != 0)
		return (8);
	(void)sys1(SYS_close, fd2);
	if (connect_shutdown_submit(IORING_OP_CONNECT, IOSQE_FIXED_FILE, 0,
	    &sin, sizeof(sin), 0, 6, 0xc110) != 0 ||
	    connect_shutdown_submit(IORING_OP_CONNECT, IOSQE_FIXED_FILE, 1,
	    &sin, sizeof(sin), 0, 0, 0xc111) != -EBADF ||
	    connect_shutdown_submit(IORING_OP_CONNECT, IOSQE_FIXED_FILE, 2,
	    &sin, sizeof(sin), 0, 0, 0xc112) != -EBADF)
		return (9);
	if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0 ||
	    connect_shutdown_submit(IORING_OP_CONNECT, IOSQE_FIXED_FILE, 0,
	    &sin, sizeof(sin), 0, 0, 0xc113) != -EBADF)
		return (10);
	(void)sys1(SYS_close, fd);

	/* SHUTDOWN reserves off/addr/rw_flags/buf_index/splice_fd_in. */
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
	    (long)sv, 0, 0) != 0)
		return (11);
	if (connect_shutdown_submit(IORING_OP_SHUTDOWN, 0, sv[0], 0, 0,
	    LX_SHUT_RDWR, 8, 0xc120) != -EINVAL ||
	    connect_shutdown_submit(IORING_OP_SHUTDOWN, 0, sv[0], 0, 0,
	    LX_SHUT_RDWR, 9, 0xc121) != -EINVAL)
		return (12);
	for (int field = 2; field <= 4; field++)
		if (connect_shutdown_submit(IORING_OP_SHUTDOWN, 0, sv[0], 0, 0,
		    LX_SHUT_RDWR, field, 0xc122 + field) != -EINVAL)
			return (13);
	if (connect_shutdown_submit(IORING_OP_SHUTDOWN, 0, sv[0], 0, 0,
	    LX_SHUT_RDWR, 7, 0xc127) != -EINVAL ||
	    connect_shutdown_submit(IORING_OP_SHUTDOWN, IOSQE_BUFFER_SELECT,
	    sv[0], 0, 0, LX_SHUT_RDWR, 0, 0xc128) != -EOPNOTSUPP ||
	    connect_shutdown_submit(IORING_OP_SHUTDOWN, 0, sv[0], 0, 0,
	    99, 0, 0xc129) != -EINVAL)
		return (14);
	/* addr3 and the final word are unused; fixed file pins the socket. */
	files[0] = sv[0];
	files[1] = -1;
	if (iou_reg(IORING_REGISTER_FILES, files, 2) != 0)
		return (15);
	(void)sys1(SYS_close, sv[0]);
	if (connect_shutdown_submit(IORING_OP_SHUTDOWN, IOSQE_FIXED_FILE, 0,
	    0, 0, LX_SHUT_RDWR, 5, 0xc12a) != 0 ||
	    sys3(SYS_read, sv[1], &ch, 1) != 0)
		return (16);
	if (connect_shutdown_submit(IORING_OP_SHUTDOWN, IOSQE_FIXED_FILE, 1,
	    0, 0, LX_SHUT_RDWR, 0, 0xc12b) != -EBADF ||
	    connect_shutdown_submit(IORING_OP_SHUTDOWN, IOSQE_FIXED_FILE, 2,
	    0, 0, LX_SHUT_RDWR, 0, 0xc12c) != -EBADF)
		return (17);
	if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0)
		return (18);
	(void)sys1(SYS_close, sv[1]);

	tf = (int)tmpfile_fd("iou_shutdown_notsock");
	if (tf < 0 || connect_shutdown_submit(IORING_OP_SHUTDOWN, 0, tf, 0,
	    0, LX_SHUT_RDWR, 0, 0xc130) != -ENOTSOCK)
		return (19);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
	    (long)sv2, 0, 0) != 0 ||
	    connect_shutdown_submit(IORING_OP_SHUTDOWN, IOSQE_ASYNC, sv2[0],
	    0, 0, LX_SHUT_RDWR, 0, 0xc131) != 0)
		return (20);
	(void)sys1(SYS_close, tf);
	(void)sys1(SYS_close, sv2[0]);
	(void)sys1(SYS_close, sv2[1]);
	return (0);
}

static int
t_accept_parks(void)
{
	struct sockaddr_in sin;
	struct cqe c[4];
	int sfd, res, n;
	if (ring_setup(8) < 0)
		return (1);
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
	/*
	 * Fast poll: ACCEPT with no pending connection must PARK (not block,
	 * not return EAGAIN).  A batched NOP still completes; the ACCEPT stays
	 * armed until a connection arrives (freed at ring teardown here).
	 */
	iou_sqe(IORING_OP_ACCEPT, 0, sfd, 0, 0, 0, 0, 0x4);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x5);
	if (iou_flush(2, 1) != 2) {
		(void)sys1(SYS_close, sfd);
		return (5);
	}
	n = iou_reap(c, 4);
	(void)sys1(SYS_close, sfd);
	if (n != 1 || !cqe_find(c, n, 0x5, &res) || res != 0)
		return (6);
	if (cqe_find(c, n, 0x4, &res))		/* ACCEPT must still be parked */
		return (7);
	return (0);
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
	/* buf_index 5 with one buffer registered -> EFAULT */
	res = fixed_op(IORING_OP_READ_FIXED, (int)tf, buf, 8, 0, 5, 0, 0x1);
	(void)sys1(SYS_close, tf);
	return (res == -EFAULT ? 0 : 4);
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
#define	EPOLL_CTL_ADD		1
#define	EPOLL_CTL_DEL		2
#define	EPOLL_CTL_MOD		3
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
epoll_ctl_op(u8 sqe_flags, int epfd, int op, int target,
    struct epoll_event *event, int field)
{
	struct cqe c[2];
	u32 slot;
	int res;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_EPOLL_CTL, sqe_flags, epfd, (u64)target, event,
	    (u32)op, 0, 0xe000 + g_sqi);
	switch (field) {
	case 1: g_sqes[slot].buf_index = 1; break;
	case 2: g_sqes[slot].splice_fd_in = 1; break;
	case 3: g_sqes[slot].pad2[0] = 1; break;
	case 4: g_sqes[slot].ioprio = 1; break;
	default: break;
	}
	if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
	    !cqe_find(c, 1, 0xe000 + g_sqi - 1, &res))
		return (-100000);
	return (res);
}

static int
t_epoll_ctl_options(void)
{
	struct epoll_event ev;
	long epfd, efd, efd2;

	if (ring_setup(16) < 0)
		return (1);
	epfd = call(SYS_epoll_create1, 0, 0, 0, 0, 0, 0);
	efd = call(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
	efd2 = call(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
	if (epfd < 0 || efd < 0 || efd2 < 0)
		return (2);
	ev.events = EPOLLIN;
	ev.data = 0x1111;
	if (epoll_ctl_op(0, (int)epfd, EPOLL_CTL_ADD, (int)efd, &ev, 0) != 0 ||
	    epoll_ctl_op(0, (int)epfd, EPOLL_CTL_ADD, (int)efd, &ev, 0) != -EEXIST)
		return (3);
	ev.data = 0x2222;
	if (epoll_ctl_op(0, (int)epfd, EPOLL_CTL_MOD, (int)efd, &ev, 0) != 0)
		return (4);
	/* Every operation except DEL imports the event pointer first. */
	if (epoll_ctl_op(0, (int)epfd, 99, (int)efd,
	    (struct epoll_event *)1, 0) != -EFAULT ||
	    epoll_ctl_op(0, (int)epfd, 99, (int)efd, &ev, 0) != -EINVAL)
		return (5);
	/* DEL also ignores its event pointer. */
	if (epoll_ctl_op(0, (int)epfd, EPOLL_CTL_DEL, (int)efd,
	    (struct epoll_event *)1, 0) != 0 ||
	    epoll_ctl_op(0, (int)epfd, EPOLL_CTL_DEL, (int)efd,
	    (struct epoll_event *)1, 0) != -ENOENT)
		return (6);
	/* The two fields rejected by Linux preparation must have no side effect. */
	if (epoll_ctl_op(0, (int)epfd, EPOLL_CTL_ADD, (int)efd, &ev, 1) != -EINVAL ||
	    epoll_ctl_op(0, (int)epfd, EPOLL_CTL_ADD, (int)efd, &ev, 2) != -EINVAL ||
	    epoll_ctl_op(0, (int)epfd, EPOLL_CTL_DEL, (int)efd,
	    (struct epoll_event *)1, 0) != -ENOENT)
		return (7);
	/* Other unused tail data is accepted by Linux for this opcode. */
	if (epoll_ctl_op(0, (int)epfd, EPOLL_CTL_ADD, (int)efd, &ev, 3) != 0 ||
	    epoll_ctl_op(0, (int)epfd, EPOLL_CTL_DEL, (int)efd,
	    (struct epoll_event *)1, 0) != 0)
		return (8);
	if (epoll_ctl_op(0, (int)epfd, EPOLL_CTL_ADD, (int)efd, &ev, 4) != -EINVAL ||
	    epoll_ctl_op(IOSQE_BUFFER_SELECT, (int)epfd, EPOLL_CTL_ADD,
	    (int)efd, &ev, 0) != -EOPNOTSUPP)
		return (9);
	/* EPOLL_CTL is not a needs_file opcode: FIXED_FILE is ignored. */
	if (epoll_ctl_op(IOSQE_FIXED_FILE, (int)epfd, EPOLL_CTL_ADD,
	    (int)efd, &ev, 0) != 0 ||
	    epoll_ctl_op(IOSQE_FIXED_FILE, (int)epfd, EPOLL_CTL_DEL,
	    (int)efd, (struct epoll_event *)1, 0) != 0)
		return (10);
	if (epoll_ctl_op(0, 9999, EPOLL_CTL_ADD, (int)efd, &ev, 0) != -EBADF ||
	    epoll_ctl_op(0, (int)epfd, EPOLL_CTL_ADD, 9999, &ev, 0) != -EBADF ||
	    epoll_ctl_op(0, (int)epfd, EPOLL_CTL_ADD, (int)epfd, &ev, 0) != -EINVAL)
		return (11);
	/* ADD/MOD import event data before descriptor lookup. */
	if (epoll_ctl_op(0, 9999, EPOLL_CTL_ADD, 9999,
	    (struct epoll_event *)1, 0) != -EFAULT)
		return (12);
	/* A second target remains usable after all rejected requests. */
	if (epoll_ctl_op(0, (int)epfd, EPOLL_CTL_ADD, (int)efd2, &ev, 0) != 0 ||
	    epoll_ctl_op(0, (int)epfd, EPOLL_CTL_DEL, (int)efd2,
	    (struct epoll_event *)1, 0) != 0)
		return (13);
	return (0);
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
xattr_op(int op, u8 sqe_flags, int xfd, const char *name, void *value,
    u32 size, u32 xflags, const char *path, int field)
{
	struct cqe c[2];
	u32 slot;
	int res;

	slot = g_sqi & g_sqmask;
	iou_sqe((u8)op, sqe_flags, xfd, (u64)(unsigned long)value,
	    (void *)name, size, xflags, 0xa000 + g_sqi);
	g_sqes[slot].pad2[0] = (u64)(unsigned long)path;
	switch (field) {
	case 1: g_sqes[slot].buf_index = 1; break;
	case 2: g_sqes[slot].splice_fd_in = 1; break;
	case 3: g_sqes[slot].pad2[0] = 1; break;
	case 4: g_sqes[slot].ioprio = 1; break;
	default: break;
	}
	if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
	    !cqe_find(c, 1, 0xa000 + g_sqi - 1, &res))
		return (-100000);
	return (res);
}

#define XATTR_CREATE  1
#define XATTR_REPLACE 2

static int
t_xattr_options(void)
{
	char val[16];
	int files[1], i, res;
	long tf, ff;

	if (ring_setup(16) < 0)
		return (1);
	tf = tmpfile_fd("iou_xattr_options");
	if (tf < 0)
		return (2);
	res = xattr_op(IORING_OP_FSETXATTR, 0, (int)tf, "user.options",
	    (void *)"abcdefgh", 8, 0, 0, 0);
	if (res == -EOPNOTSUPP)
		return (0);
	if (res != 0)
		return (3);
	/* CREATE tests existence, independent of the replacement value size. */
	if (xattr_op(IORING_OP_FSETXATTR, 0, (int)tf, "user.options",
	    (void *)"x", 1, XATTR_CREATE, 0, 0) != -EEXIST)
		return (4);
	xmemset(val, 0, sizeof(val));
	if (xattr_op(IORING_OP_FGETXATTR, 0, (int)tf, "user.options", val,
	    sizeof(val), 0, 0, 0) != 8 || xmemcmp(val, "abcdefgh", 8) != 0)
		return (5);
	if (xattr_op(IORING_OP_FSETXATTR, 0, (int)tf, "user.missing",
	    (void *)"x", 1, XATTR_REPLACE, 0, 0) != -ENODATA)
		return (6);
	if (xattr_op(IORING_OP_FSETXATTR, 0, (int)tf, "user.options",
	    (void *)"new", 3, XATTR_REPLACE, 0, 0) != 0)
		return (7);
	if (xattr_op(IORING_OP_FSETXATTR, 0, (int)tf, "user.options",
	    (void *)"bad", 3, 4, 0, 0) != -EINVAL ||
	    xattr_op(IORING_OP_FSETXATTR, 0, (int)tf, "user.options",
	    (void *)"bad", 3, XATTR_CREATE | XATTR_REPLACE, 0, 0) != -EEXIST ||
	    xattr_op(IORING_OP_FSETXATTR, 0, (int)tf, "user.both_missing",
	    (void *)"bad", 3, XATTR_CREATE | XATTR_REPLACE, 0, 0) != -ENODATA)
		return (8);
	if (xattr_op(IORING_OP_FGETXATTR, 0, (int)tf, "user.options", val,
	    sizeof(val), 1, 0, 0) != -EINVAL)
		return (9);
	if (xattr_op(IORING_OP_FGETXATTR, 0, (int)tf, "user.options", 0,
	    0, 0, 0, 0) != 3 ||
	    xattr_op(IORING_OP_FGETXATTR, 0, (int)tf, "user.options", val,
	    2, 0, 0, 0) != -ERANGE ||
	    xattr_op(IORING_OP_FGETXATTR, 0, (int)tf, "user.absent", val,
	    sizeof(val), 0, 0, 0) != -ENODATA)
		return (10);
	/* Path opcodes ignore fd and use addr3 as the pathname. */
	if (xattr_op(IORING_OP_SETXATTR, 0, 9999, "user.path",
	    (void *)"path", 4, XATTR_CREATE, "iou_xattr_options", 0) != 0)
		return (11);
	xmemset(val, 0, sizeof(val));
	if (xattr_op(IORING_OP_GETXATTR, 0, -123, "user.path", val,
	    sizeof(val), 0, "iou_xattr_options", 0) != 4 ||
	    xmemcmp(val, "path", 4) != 0)
		return (12);
	/* Path variants reject FIXED_FILE before importing their arguments. */
	if (xattr_op(IORING_OP_SETXATTR, IOSQE_FIXED_FILE, 0,
	    (const char *)1, (void *)1, 1, 4, (const char *)1, 0) != -EBADF ||
	    xattr_op(IORING_OP_GETXATTR, IOSQE_FIXED_FILE, 0,
	    (const char *)1, (void *)1, 1, 4, (const char *)1, 0) != -EBADF)
		return (13);
	/* Fd variants import and validate arguments before resolving a bad fd. */
	if (xattr_op(IORING_OP_FSETXATTR, 0, 9999, "user.badfd",
	    (void *)"x", 1, 4, 0, 0) != -EINVAL ||
	    xattr_op(IORING_OP_FGETXATTR, 0, 9999, "user.badfd", val,
	    sizeof(val), 1, 0, 0) != -EINVAL)
		return (14);
	/* Linux accepts otherwise-unused union fields for these old opcodes. */
	for (i = 1; i <= 3; i++) {
		xmemset(val, 0, sizeof(val));
		if (xattr_op(IORING_OP_FGETXATTR, 0, (int)tf, "user.options",
		    val, sizeof(val), 0, 0, i) != 3 ||
		    xmemcmp(val, "new", 3) != 0)
			return (15);
	}
	if (xattr_op(IORING_OP_FGETXATTR, 0, (int)tf, "user.options", val,
	    sizeof(val), 0, 0, 4) != -EINVAL ||
	    xattr_op(IORING_OP_FGETXATTR, IOSQE_BUFFER_SELECT, (int)tf,
	    "user.options", val, sizeof(val), 0, 0, 0) != -EOPNOTSUPP)
		return (16);
	/* Fixed fd operations retain the registered file after ambient close. */
	ff = tmpfile_fd("iou_xattr_fixed");
	if (ff < 0)
		return (17);
	files[0] = (int)ff;
	if (iou_reg(IORING_REGISTER_FILES, files, 1) != 0 ||
	    sys1(SYS_close, ff) != 0)
		return (18);
	if (xattr_op(IORING_OP_FSETXATTR, IOSQE_FIXED_FILE, 0, "user.fixed",
	    (void *)"fixed", 5, 0, 0, 0) != 0)
		return (19);
	xmemset(val, 0, sizeof(val));
	if (xattr_op(IORING_OP_FGETXATTR, IOSQE_FIXED_FILE, 0, "user.fixed",
	    val, sizeof(val), 0, 0, 0) != 5 || xmemcmp(val, "fixed", 5) != 0)
		return (20);
	/* Fd-xattr preparation validates flags before fixed-slot lookup. */
	if (xattr_op(IORING_OP_FSETXATTR, IOSQE_FIXED_FILE, 1, "user.fixed",
	    (void *)"x", 1, 4, 0, 0) != -EINVAL ||
	    xattr_op(IORING_OP_FGETXATTR, IOSQE_FIXED_FILE, 1, "user.fixed",
	    val, sizeof(val), 1, 0, 0) != -EINVAL)
		return (21);
	if (xattr_op(IORING_OP_FGETXATTR, IOSQE_FIXED_FILE, 1, "user.fixed",
	    val, sizeof(val), 0, 0, 0) != -EBADF)
		return (22);
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

/* ================= provided buffers (BUFFER_SELECT) ================= */
/* stage one SQE with an explicit buf_group and flags, then submit+reap. */
static int
grp_op(u8 op, u8 flags, int fd, u64 off, void *addr, u32 len, u16 bgrp,
    u64 ud, struct cqe *out)
{
	u32 slot = g_sqi & g_sqmask;
	int n;

	iou_sqe(op, flags, fd, off, addr, len, 0, ud);
	g_sqes[slot].buf_index = bgrp;		/* buf_group shares buf_index */
	if (iou_flush(1, 1) != 1)
		return (-100000);
	n = iou_reap(out, 2);
	if (n != 1 || out[0].user_data != ud)
		return (-100001);
	return (0);
}
static int
t_provided_buffers(void)
{
	static char pool[256];		/* 4 * 64 */
	struct cqe c[2];
	long tf;
	if (ring_setup(8) < 0)
		return (1);
	/* provide 4 buffers of 64 bytes, group 7, ids 0..3 */
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 4 /* nbufs */, 0 /* first bid */,
	    pool, 64 /* each */, 7, 0x1, c) != 0)
		return (2);
	if (c[0].res != 0)
		return (3);
	/* a READ with BUFFER_SELECT lands in the first buffer (bid 0) */
	tf = tmpfile_fd("iou_pb");
	if (tf < 0)
		return (4);
	if (sub1(tf, IORING_OP_WRITE, "SELECTED", 8, 0, 0, 0x2) != 8)
		return (5);
	xmemset(pool, 0, sizeof(pool));
	if (grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, (int)tf, 0, 0, 64, 7,
	    0x3, c) != 0)
		return (6);
	if (c[0].res != 8)
		return (7);
	if ((c[0].flags & IORING_CQE_F_BUFFER) == 0)
		return (8);
	if ((c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 0)	/* bid 0 */
		return (9);
	if (xmemcmp(pool, "SELECTED", 8) != 0)			/* first buffer */
		return (10);
	(void)sys1(SYS_close, tf);
	return (0);
}
static int
t_buffer_select_enobufs(void)
{
	struct cqe c[2];
	long tf;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_nb");
	if (tf < 0)
		return (2);
	/* no buffers in group 3 -> ENOBUFS */
	if (grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, (int)tf, 0, 0, 64, 3,
	    0x1, c) != 0)
		return (3);
	(void)sys1(SYS_close, tf);
	return (c[0].res == -ELINUX_ENOBUFS ? 0 : 4);
}
static int
t_remove_buffers(void)
{
	static char pool[256];
	struct cqe c[2];
	if (ring_setup(8) < 0)
		return (1);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 4, 0, pool, 64, 9, 0x1, c) != 0)
		return (2);
	/* remove 2 of the 4 in group 9 -> res 2 */
	if (grp_op(IORING_OP_REMOVE_BUFFERS, 0, 2 /* nbufs */, 0, 0, 0, 9,
	    0x2, c) != 0)
		return (3);
	return (c[0].res == 2 ? 0 : 4);
}
static int
provided_option_submit(u8 op, u8 flags, int count, u64 off, void *addr,
    u32 len, u16 bgid, u16 ioprio, u32 rw_flags, int splice_fd_in,
    u64 pad0, u64 pad1, u64 user_data)
{
	struct cqe c[2];
	u32 slot;
	int n, res;

	slot = g_sqi & g_sqmask;
	iou_sqe(op, flags, count, off, addr, len, rw_flags, user_data);
	g_sqes[slot].buf_index = bgid;
	g_sqes[slot].ioprio = ioprio;
	g_sqes[slot].splice_fd_in = splice_fd_in;
	g_sqes[slot].pad2[0] = pad0;
	g_sqes[slot].pad2[1] = pad1;
	if (iou_flush(1, 1) != 1)
		return (-100000);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, user_data, &res))
		return (-100001);
	return (res);
}

static int
t_provided_buffer_options(void)
{
	struct pbuf_reg reg;
	static char pool[32];
	int res;

	if (ring_setup(16) < 0)
		return (1);
	/* A never-created group is distinct from an empty existing group. */
	if (provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 1, 0, 0, 0,
	    77, 0, 0, 0, 0, 0, 0xb01) != -ENOENT)
		return (2);

	/* PROVIDE_BUFFERS preparation bounds and reserved fields. */
	if (provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, 0, 0, pool, 8,
	    77, 0, 0, 0, 0, 0, 0xb02) != -E2BIG ||
	    provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, -1, 0, pool, 8,
	    77, 0, 0, 0, 0, 0, 0xb03) != -E2BIG ||
	    provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, 65537, 0,
	    pool, 8, 77, 0, 0, 0, 0, 0, 0xb04) != -E2BIG ||
	    provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, 1, 0, pool, 0,
	    77, 0, 0, 0, 0, 0, 0xb05) != -EINVAL ||
	    provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, 1, 65536,
	    pool, 8, 77, 0, 0, 0, 0, 0, 0xb06) != -E2BIG ||
	    provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, 2, 65535,
	    pool, 8, 77, 0, 0, 0, 0, 0, 0xb07) != -EINVAL ||
	    provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, 2, 0,
	    (void *)(unsigned long)(~0ULL - 3), 8, 77, 0, 0, 0, 0, 0,
	    0xb08) != -ELINUX_EOVERFLOW ||
	    provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, 1, 0, pool, 8,
	    77, 1, 0, 0, 0, 0, 0xb09) != -EINVAL ||
	    provided_option_submit(IORING_OP_PROVIDE_BUFFERS,
	    IOSQE_BUFFER_SELECT, 1, 0, pool, 8, 77, 0, 0, 0, 0, 0,
	    0xb0a) != -EOPNOTSUPP ||
	    provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, 1, 0, pool, 8,
	    77, 0, 1, 0, 0, 0, 0xb0b) != -EINVAL ||
	    provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, 1, 0, pool, 8,
	    77, 0, 0, 1, 0, 0, 0xb0c) != -EINVAL)
		return (3);

	/* FIXED_FILE is ignored: fd is a count. Tail words and ASYNC are legal. */
	if (provided_option_submit(IORING_OP_PROVIDE_BUFFERS,
	    IOSQE_FIXED_FILE | IOSQE_ASYNC, 2, 10, pool, 8, 77, 0, 0, 0,
	    0x1234, 0x5678, 0xb10) != 0)
		return (4);
	if (provided_option_submit(IORING_OP_REMOVE_BUFFERS, IOSQE_FIXED_FILE,
	    1, 0, 0, 0, 77, 0, 0, 0, 0, 0, 0xb11) != 1 ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 100, 0, 0, 0,
	    77, 0, 0, 0, 0, 0, 0xb12) != 1 ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 1, 0, 0, 0,
	    77, 0, 0, 0, 0, 0, 0xb13) != 0)
		return (5);
	/* Empty groups accept later provide/remove operations. */
	if (provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, 1, 20, pool,
	    8, 77, 0, 0, 0, 0, 0, 0xb14) != 0 ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 1, 0, 0, 0,
	    77, 0, 0, 0, 0, 0, 0xb15) != 1)
		return (6);

	/* Registration replaces an empty classic group, but not a live one. */
	xmemset(&reg, 0, sizeof(reg));
	reg.ring_entries = 4;
	reg.bgid = 77;
	reg.flags = IOU_PBUF_RING_MMAP;
	if (pbuf_register(&reg) != 0 ||
	    provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, 1, 0,
	    pool, 8, 77, 0, 0, 0, 0, 0, 0xb16) != -EINVAL ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 1, 0, 0, 0,
	    77, 0, 0, 0, 0, 0, 0xb17) != -EINVAL ||
	    pbuf_unregister(77) != 0 ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 1, 0, 0, 0,
	    77, 0, 0, 0, 0, 0, 0xb18) != -ENOENT)
		return (7);
	if (provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, 1, 0, pool,
	    8, 79, 0, 0, 0, 0, 0, 0xb19) != 0)
		return (8);
	xmemset(&reg, 0, sizeof(reg));
	reg.ring_entries = 4;
	reg.bgid = 79;
	reg.flags = IOU_PBUF_RING_MMAP;
	if (pbuf_register(&reg) != -17 ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 1, 0, 0, 0,
	    79, 0, 0, 0, 0, 0, 0xb1a) != 1)
		return (9);

	/* REMOVE_BUFFERS validates count and every unused SQE field. */
	if (provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 0, 0, 0, 0,
	    77, 0, 0, 0, 0, 0, 0xb20) != -EINVAL ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 65537, 0, 0, 0,
	    77, 0, 0, 0, 0, 0, 0xb21) != -EINVAL ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 1, 1, 0, 0,
	    77, 0, 0, 0, 0, 0, 0xb22) != -EINVAL ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 1, 0, pool, 0,
	    77, 0, 0, 0, 0, 0, 0xb23) != -EINVAL ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 1, 0, 0, 1,
	    77, 0, 0, 0, 0, 0, 0xb24) != -EINVAL ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 1, 0, 0, 0,
	    77, 0, 1, 0, 0, 0, 0xb25) != -EINVAL ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 1, 0, 0, 0,
	    77, 0, 0, 1, 0, 0, 0xb26) != -EINVAL ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 1, 0, 0, 0,
	    77, 1, 0, 0, 0, 0, 0xb27) != -EINVAL ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS,
	    IOSQE_BUFFER_SELECT, 1, 0, 0, 0, 77, 0, 0, 0, 0, 0,
	    0xb28) != -EOPNOTSUPP)
		return (10);

	/* Legacy management cannot operate on a registered provided ring. */
	xmemset(&reg, 0, sizeof(reg));
	reg.ring_entries = 4;
	reg.bgid = 78;
	reg.flags = IOU_PBUF_RING_MMAP;
	if (pbuf_register(&reg) != 0)
		return (11);
	res = provided_option_submit(IORING_OP_PROVIDE_BUFFERS, 0, 1, 0,
	    pool, 8, 78, 0, 0, 0, 0, 0, 0xb30);
	if (res != -EINVAL ||
	    provided_option_submit(IORING_OP_REMOVE_BUFFERS, 0, 1, 0, 0, 0,
	    78, 0, 0, 0, 0, 0, 0xb31) != -EINVAL ||
	    pbuf_unregister(78) != 0)
		return (12);
	return (0);
}

static int
t_provided_probe(void)
{
	struct probe pr;
	if (ring_setup(8) < 0)
		return (1);
	xmemset(&pr, 0, sizeof(pr));
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PROBE,
	    (long)&pr, 128, 0, 0) != 0)
		return (2);
	if ((pr.ops[IORING_OP_PROVIDE_BUFFERS].flags & IO_URING_OP_SUPPORTED) == 0)
		return (3);
	if ((pr.ops[IORING_OP_REMOVE_BUFFERS].flags & IO_URING_OP_SUPPORTED) == 0)
		return (4);
	return (0);
}

/* ================= FILES_UPDATE(op) / TEE / MSG_RING ================= */
static int
t_files_update_op(void)
{
	long tf0, tf1;
	char rb[8];
	int fds[1], res;
	if (ring_setup(8) < 0)
		return (1);
	tf0 = tmpfile_fd("iou_fuo0");
	tf1 = tmpfile_fd("iou_fuo1");
	if (tf0 < 0 || tf1 < 0)
		return (2);
	if (sub1(tf1, IORING_OP_WRITE, "opupdate", 8, 0, 0, 0x1) != 8)
		return (3);
	fds[0] = (int)tf0;
	if (iou_reg(IORING_REGISTER_FILES, fds, 1) != 0)
		return (4);
	/* update slot 0 -> tf1 via the SQE op: off=offset, len=nr, addr=fds */
	fds[0] = (int)tf1;
	res = sub1(-1, IORING_OP_FILES_UPDATE, fds, 1, 0, 0, 0x2);
	if (res != 1)
		return (5);
	xmemset(rb, 0, sizeof(rb));
	res = fixed_op(IORING_OP_READ, 0, rb, 8, 0, 0, IOSQE_FIXED_FILE, 0x3);
	(void)sys1(SYS_close, tf0);
	(void)sys1(SYS_close, tf1);
	if (res != 8 || xmemcmp(rb, "opupdate", 8) != 0)
		return (6);
	return (0);
}
static int
files_update_option_submit(u8 flags, int fd, int *fds, u32 nr, u64 off,
    u16 ioprio, u32 rw_flags, int splice_fd_in, u16 buf_index,
    u64 pad0, u64 pad1, u64 user_data)
{
	struct cqe c[2];
	u32 slot;
	int n, res;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_FILES_UPDATE, flags, fd, off, fds, nr, rw_flags,
	    user_data);
	g_sqes[slot].ioprio = ioprio;
	g_sqes[slot].buf_index = buf_index;
	g_sqes[slot].splice_fd_in = splice_fd_in;
	g_sqes[slot].pad2[0] = pad0;
	g_sqes[slot].pad2[1] = pad1;
	if (iou_flush(1, 1) != 1)
		return (-100000);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, user_data, &res))
		return (-100001);
	return (res);
}

static int
t_files_update_options(void)
{
	struct file_index_range range = { 1, 2, 0 };
	long a, b, c, d, e, m;
	int sparse[4] = { -1, -1, -1, -1 };
	int pair[2], clear[2] = { -1, -1 }, one, res;
	char byte;

	if (ring_setup(16) < 0)
		return (1);
	a = tmpfile_fd("iou_fuoa");
	b = tmpfile_fd("iou_fuob");
	c = tmpfile_fd("iou_fuoc");
	d = tmpfile_fd("iou_fuod");
	e = tmpfile_fd("iou_fuoe");
	if (a < 0 || b < 0 || c < 0 || d < 0 || e < 0)
		return (2);
	if (sub1((int)a, IORING_OP_WRITE, "A", 1, 0, 0, 0xf01) != 1 ||
	    sub1((int)b, IORING_OP_WRITE, "B", 1, 0, 0, 0xf02) != 1 ||
	    sub1((int)c, IORING_OP_WRITE, "C", 1, 0, 0, 0xf03) != 1 ||
	    sub1((int)d, IORING_OP_WRITE, "D", 1, 0, 0, 0xf04) != 1 ||
	    sub1((int)e, IORING_OP_WRITE, "E", 1, 0, 0, 0xf05) != 1)
		return (3);

	/* Automatic allocation requires a registered table. */
	one = (int)a;
	if (files_update_option_submit(0, -1, &one, 1,
	    IORING_FILE_INDEX_ALLOC, 0, 0, 0, 0, 0, 0, 0xf10) !=
	    -ELINUX_ENXIO || one != (int)a)
		return (4);
	if (iou_reg(IORING_REGISTER_FILES, sparse, 4) != 0 ||
	    iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, &range, 0) != 0)
		return (5);

	/* Linux validates every meaningful option before touching the table. */
	one = (int)a;
	if (files_update_option_submit(IOSQE_FIXED_FILE, -1, &one, 1,
	    IORING_FILE_INDEX_ALLOC, 0, 0, 0, 0, 0, 0, 0xf11) != -EINVAL ||
	    files_update_option_submit(IOSQE_BUFFER_SELECT, -1, &one, 1,
	    IORING_FILE_INDEX_ALLOC, 0, 0, 0, 0, 0, 0, 0xf12) !=
	    -EOPNOTSUPP ||
	    files_update_option_submit(0, -1, &one, 1,
	    IORING_FILE_INDEX_ALLOC, 1, 0, 0, 0, 0, 0, 0xf13) != -EINVAL ||
	    files_update_option_submit(0, -1, &one, 1,
	    IORING_FILE_INDEX_ALLOC, 0, 1, 0, 0, 0, 0, 0xf14) != -EINVAL ||
	    files_update_option_submit(0, -1, &one, 1,
	    IORING_FILE_INDEX_ALLOC, 0, 0, 1, 0, 0, 0, 0xf15) != -EINVAL ||
	    files_update_option_submit(0, -1, &one, 0,
	    IORING_FILE_INDEX_ALLOC, 0, 0, 0, 0, 0, 0, 0xf16) != -EINVAL ||
	    files_update_option_submit(IOSQE_FIXED_FILE, -1, (int *)1, 1,
	    IORING_FILE_INDEX_ALLOC, 0, 0, 0, 0, 0, 0, 0xf17) != -EINVAL)
		return (6);
	if (fixed_op(IORING_OP_READ, 1, &byte, 1, 0, 0, IOSQE_FIXED_FILE,
	    0xf18) != -EBADF ||
	    fixed_op(IORING_OP_READ, 2, &byte, 1, 0, 0, IOSQE_FIXED_FILE,
	    0xf19) != -EBADF)
		return (7);

	/* Allocation returns zero-based slots in the input array. */
	pair[0] = (int)a;
	pair[1] = (int)b;
	if (files_update_option_submit(0, 777, pair, 2,
	    IORING_FILE_INDEX_ALLOC, 0, 0, 0, 9, 0, 0, 0xf20) != 2 ||
	    pair[0] != 1 || pair[1] != 2)
		return (8);
	(void)sys1(SYS_close, a);
	(void)sys1(SYS_close, b);
	byte = 0;
	if (fixed_op(IORING_OP_READ, 1, &byte, 1, 0, 0, IOSQE_FIXED_FILE,
	    0xf21) != 1 || byte != 'A')
		return (9);
	byte = 0;
	if (fixed_op(IORING_OP_READ, 2, &byte, 1, 0, 0, IOSQE_FIXED_FILE,
	    0xf22) != 1 || byte != 'B')
		return (10);

	one = (int)c;
	if (files_update_option_submit(0, -1, &one, 1,
	    IORING_FILE_INDEX_ALLOC, 0, 0, 0, 0, 0, 0, 0xf23) != -ENFILE ||
	    one != (int)c)
		return (11);

	/* Clearing the range makes the allocator wrap to its first slot. */
	{ struct files_update up;
	  xmemset(&up, 0, sizeof(up)); up.offset = 1;
	  up.fds = (u64)(unsigned long)clear;
	  if (iou_reg(IORING_REGISTER_FILES_UPDATE, &up, 2) != 2)
		return (12); }
	one = (int)c;
	if (files_update_option_submit(IOSQE_ASYNC, -1, &one, 1,
	    IORING_FILE_INDEX_ALLOC, 0, 0, 0, 0, 0, 0, 0xf24) != 1 ||
	    one != 2)
		return (13);
	(void)sys1(SYS_close, c);
	byte = 0;
	if (fixed_op(IORING_OP_READ, 2, &byte, 1, 0, 0, IOSQE_FIXED_FILE,
	    0xf25) != 1 || byte != 'C')
		return (14);

	/* A later bad fd returns the committed prefix and leaves the next slot. */
	{ struct files_update up;
	  xmemset(&up, 0, sizeof(up)); up.offset = 1;
	  up.fds = (u64)(unsigned long)clear;
	  if (iou_reg(IORING_REGISTER_FILES_UPDATE, &up, 2) != 2)
		return (15); }
	pair[0] = (int)d;
	pair[1] = 9999;
	if (files_update_option_submit(0, -1, pair, 2,
	    IORING_FILE_INDEX_ALLOC, 0, 0, 0, 0, 0, 0, 0xf26) != 1 ||
	    pair[0] != 2 || pair[1] != 9999)
		return (16);
	(void)sys1(SYS_close, d);
	byte = 0;
	if (fixed_op(IORING_OP_READ, 2, &byte, 1, 0, 0, IOSQE_FIXED_FILE,
	    0xf27) != 1 || byte != 'D' ||
	    fixed_op(IORING_OP_READ, 1, &byte, 1, 0, 0, IOSQE_FIXED_FILE,
	    0xf28) != -EBADF)
		return (17);

	/* A failed slot-index copyout rolls the new registration back. */
	{ struct files_update up;
	  xmemset(&up, 0, sizeof(up)); up.offset = 1;
	  up.fds = (u64)(unsigned long)clear;
	  if (iou_reg(IORING_REGISTER_FILES_UPDATE, &up, 2) != 2)
		return (18); }
	m = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
	    LX_MAP_PRIVATE | LX_MAP_ANON, -1, 0);
	if (m < 0)
		return (19);
	*(int *)m = (int)e;
	if (call(SYS_mprotect, m, 4096, PROT_READ, 0, 0, 0) != 0)
		return (20);
	res = files_update_option_submit(0, -1, (int *)m, 1,
	    IORING_FILE_INDEX_ALLOC, 0, 0, 0, 0, 0, 0, 0xf29);
	if (call(SYS_mprotect, m, 4096, PROT_READ | PROT_WRITE, 0, 0, 0) != 0)
		return (21);
	if (res != -EFAULT ||
	    fixed_op(IORING_OP_READ, 1, &byte, 1, 0, 0, IOSQE_FIXED_FILE,
	    0xf2a) != -EBADF ||
	    fixed_op(IORING_OP_READ, 2, &byte, 1, 0, 0, IOSQE_FIXED_FILE,
	    0xf2b) != -EBADF)
		return (22);
	(void)sys1(SYS_munmap, m);
	(void)sys1(SYS_close, e);
	return (iou_reg(IORING_UNREGISTER_FILES, 0, 0) == 0 ? 0 : 23);
}

static int
t_tee(void)
{
	int a[2], b[2];
	char rb[8];
	u32 slot;
	struct cqe c[2];
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_pipe2, (long)a, 0, 0, 0, 0, 0) != 0)
		return (2);
	if (call(SYS_pipe2, (long)b, 0, 0, 0, 0, 0) != 0)
		return (3);
	if (call(SYS_write, a[1], (long)"TEEDATA", 7, 0, 0, 0) != 7)
		return (4);
	/* TEE: fd_in=splice_fd_in, fd_out=fd, len, flags=splice_flags */
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_TEE, 0, b[1] /* fd_out */, 0, 0, 7, 0, 0x1);
	g_sqes[slot].splice_fd_in = a[0];
	if (iou_flush(1, 1) != 1)
		return (5);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res) || res != 7)
		return (6);
	xmemset(rb, 0, sizeof(rb));
	if (call(SYS_read, b[0], (long)rb, 7, 0, 0, 0) != 7 ||
	    xmemcmp(rb, "TEEDATA", 7) != 0)
		return (7);
	(void)sys1(SYS_close, a[0]); (void)sys1(SYS_close, a[1]);
	(void)sys1(SYS_close, b[0]); (void)sys1(SYS_close, b[1]);
	return (0);
}
static int
t_msg_ring(void)
{
	struct cqe c[4];
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	/* self-message: MSG_DATA posts {user_data=off, res=len} to the target */
	iou_sqe(IORING_OP_MSG_RING, 0, fd_ring /* target */, 0xBEEF /* off=ud */,
	    (void *)IORING_MSG_DATA, 42 /* len=res */, 0, 0x1);
	if (iou_flush(1, 2) != 1)		/* op CQE + message CQE */
		return (2);
	n = iou_reap(c, 4);
	if (n != 2)
		return (3);
	if (!cqe_find(c, n, 0x1, &res) || res != 0)		/* the op itself */
		return (4);
	if (!cqe_find(c, n, 0xBEEF, &res) || res != 42)		/* the message */
		return (5);
	return (0);
}
static int
t_msg_tee_probe(void)
{
	struct probe pr;
	int i;
	static const int sup[] = { IORING_OP_FILES_UPDATE, IORING_OP_TEE,
	    IORING_OP_MSG_RING };
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

/* ================= extended opcodes (pipe/splice/zc/futex/...) ========= */
static int
t_pipe(void)
{
	int pfd[2];
	char rb[8];
	if (ring_setup(8) < 0)
		return (1);
	/* PIPE: addr=fds array, flags=pipe_flags */
	if (sub1(0, IORING_OP_PIPE, pfd, 0, 0, 0, 0x1) != 0)
		return (2);
	if (call(SYS_write, pfd[1], (long)"pipe!!", 6, 0, 0, 0) != 6)
		return (3);
	xmemset(rb, 0, sizeof(rb));
	if (call(SYS_read, pfd[0], (long)rb, 6, 0, 0, 0) != 6 ||
	    xmemcmp(rb, "pipe!!", 6) != 0)
		return (4);
	(void)sys1(SYS_close, pfd[0]); (void)sys1(SYS_close, pfd[1]);
	return (0);
}
static int
pipe_direct_submit(void *out, u32 pipe_flags, u32 file_index, u64 key,
    int expected)
{
	struct cqe c[1];
	u32 slot = g_sqi & g_sqmask;

	iou_sqe(IORING_OP_PIPE, 0, 0, 0, out, 0, pipe_flags, key);
	g_sqes[slot].splice_fd_in = (int)file_index;
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].user_data != key || c[0].res != expected)
		return (1);
	return (0);
}

static int
pipe_option_submit(u8 sqe_flags, int fd, u64 off, void *out, u32 pipe_flags,
    u32 file_index, u16 ioprio, u16 buf_index, u64 pad0, u64 pad1, u64 ud)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_PIPE, sqe_flags, fd, off, out, 0, pipe_flags, ud);
	g_sqes[slot].ioprio = ioprio;
	g_sqes[slot].buf_index = buf_index;
	g_sqes[slot].splice_fd_in = (int)file_index;
	g_sqes[slot].pad2[0] = pad0;
	g_sqes[slot].pad2[1] = pad1;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != ud)
		return (-100000);
	return (c.res);
}

static int
t_pipe_options(void)
{
	static const u32 flags[] = { 0, 04000, 02000000, 02004000 };
	int pfd[2], fl, fdfl, i;

	if (ring_setup(16) < 0)
		return (1);

	/* Ordinary pipes preserve NONBLOCK and CLOEXEC independently. */
	for (i = 0; i < 4; i++) {
		pfd[0] = pfd[1] = -1;
		if (pipe_option_submit(0, 0, 0, pfd, flags[i], 0, 0, 0,
		    0, 0, 0xc00 + (u64)i) != 0 || pfd[0] < 0 || pfd[1] < 0)
			return (2);
		fl = (int)sys3(SYS_fcntl, pfd[0], 3 /* F_GETFL */, 0);
		fdfl = (int)sys3(SYS_fcntl, pfd[0], 1 /* F_GETFD */, 0);
		if (fl < 0 || fdfl < 0 ||
		    ((fl & 04000) != 0) != ((flags[i] & 04000) != 0) ||
		    ((fdfl & 1) != 0) != ((flags[i] & 02000000) != 0))
			return (3);
		fl = (int)sys3(SYS_fcntl, pfd[1], 3 /* F_GETFL */, 0);
		fdfl = (int)sys3(SYS_fcntl, pfd[1], 1 /* F_GETFD */, 0);
		if (fl < 0 || fdfl < 0 ||
		    ((fl & 04000) != 0) != ((flags[i] & 04000) != 0) ||
		    ((fdfl & 1) != 0) != ((flags[i] & 02000000) != 0))
			return (4);
		(void)sys1(SYS_close, pfd[0]);
		(void)sys1(SYS_close, pfd[1]);
	}

	/* PIPE is descriptorless: FIXED_FILE is ignored without a file table. */
	pfd[0] = pfd[1] = -1;
	if (pipe_option_submit(IOSQE_FIXED_FILE, 0, 0, pfd, 0, 0, 0, 0,
	    0, 0, 0xc10) != 0 || pfd[0] < 0 || pfd[1] < 0)
		return (5);
	(void)sys1(SYS_close, pfd[0]);
	(void)sys1(SYS_close, pfd[1]);

	/* Reserved fields and generic flags fail before creation or copyout. */
	pfd[0] = 71; pfd[1] = 72;
	if (pipe_option_submit(0, 1, 0, pfd, 0, 0, 0, 0, 0, 0,
	    0xc11) != -EINVAL || pfd[0] != 71 || pfd[1] != 72 ||
	    pipe_option_submit(0, 0, 1, pfd, 0, 0, 0, 0, 0, 0,
	    0xc12) != -EINVAL ||
	    pipe_option_submit(0, 0, 0, pfd, 0, 0, 0, 0, 1, 0,
	    0xc13) != -EINVAL ||
	    pipe_option_submit(0, 0, 0, pfd, 0, 0, 1, 0, 0, 0,
	    0xc14) != -EINVAL ||
	    pipe_option_submit(IOSQE_BUFFER_SELECT, 0, 0, pfd, 0, 0, 0,
	    7, 0, 0, 0xc15) != -EOPNOTSUPP)
		return (6);

	/* Invalid pipe flags are preparation errors even with FIXED_FILE set. */
	if (pipe_option_submit(IOSQE_FIXED_FILE, 0, 0, pfd, 1U << 16, 0,
	    0, 0, 0, 0, 0xc16) != -EINVAL || pfd[0] != 71 || pfd[1] != 72 ||
	    pipe_option_submit(IOSQE_FIXED_FILE, 1, 0, (void *)1, 1U << 16,
	    0, 0, 0, 0, 0, 0xc17) != -EINVAL)
		return (7);

	/* buf_index and the final base-SQE word are unused without selection. */
	pfd[0] = pfd[1] = -1;
	if (pipe_option_submit(0, 0, 0, pfd, 0, 0, 0, 9, 0, 0x2222,
	    0xc18) != 0 || pfd[0] < 0 || pfd[1] < 0)
		return (8);
	(void)sys1(SYS_close, pfd[0]);
	(void)sys1(SYS_close, pfd[1]);

	/* Copyout failure closes both new files and a following request recovers. */
	if (pipe_option_submit(0, 0, 0, (void *)1, 0, 0, 0, 0, 0, 0,
	    0xc19) != -EFAULT)
		return (9);
	pfd[0] = pfd[1] = -1;
	if (pipe_option_submit(0, 0, 0, pfd, 0, 0, 0, 0, 0, 0,
	    0xc1a) != 0 || pfd[0] < 0 || pfd[1] < 0)
		return (10);
	(void)sys1(SYS_close, pfd[0]);
	(void)sys1(SYS_close, pfd[1]);
	return (0);
}

static int
t_pipe_direct(void)
{
	struct file_index_range range = { 1, 3, 0 };
	char rb[4];
	int table[5] = { -1, -1, -1, -1, -1 };
	int out[2], res;

	if (ring_setup(8) < 0 ||
	    iou_reg(IORING_REGISTER_FILES, table, 5) != 0 ||
	    iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, &range, 0) != 0)
		return (1);
	out[0] = out[1] = -7;
	if (pipe_direct_submit(out, 0, IORING_FILE_INDEX_ALLOC, 0x191, 0) ||
	    out[0] != 1 || out[1] != 2)
		return (2);
	if (fixed_op(IORING_OP_WRITE, 2, "AB", 2, ~0ULL, 0,
	    IOSQE_FIXED_FILE, 0x192) != 2)
		return (3);
	xmemset(rb, 0, sizeof(rb));
	if (fixed_op(IORING_OP_READ, 1, rb, 2, ~0ULL, 0,
	    IOSQE_FIXED_FILE, 0x193) != 2 || xmemcmp(rb, "AB", 2) != 0)
		return (4);

	/* Only one allocation slot remains, so the pair fails atomically. */
	out[0] = 31; out[1] = 32;
	if (pipe_direct_submit(out, 04000, IORING_FILE_INDEX_ALLOC,
	    0x194, -ENFILE) || out[0] != 31 || out[1] != 32)
		return (5);

	/* Explicit one-based slot 4 installs in zero-based slots 3 and 4. */
	out[0] = out[1] = -8;
	if (pipe_direct_submit(out, 04000, 4, 0x195, 0) ||
	    out[0] != 0 || out[1] != 0)
		return (6);
	if (fixed_op(IORING_OP_WRITE, 4, "CD", 2, ~0ULL, 0,
	    IOSQE_FIXED_FILE, 0x196) != 2)
		return (7);
	xmemset(rb, 0, sizeof(rb));
	if (fixed_op(IORING_OP_READ, 3, rb, 2, ~0ULL, 0,
	    IOSQE_FIXED_FILE, 0x197) != 2 || xmemcmp(rb, "CD", 2) != 0)
		return (8);

	/* Bounds, CLOEXEC, and copyout faults preserve prior registrations. */
	out[0] = 41; out[1] = 42;
	if (pipe_direct_submit(out, 0, 5, 0x198, -EINVAL) ||
	    out[0] != 41 || out[1] != 42)
		return (9);
	if (pipe_direct_submit(out, 02000000, 1, 0x199, -EINVAL))
		return (10);
	if (pipe_direct_submit((void *)1, 0, 1, 0x19a, -EFAULT))
		return (11);
	/* Linux removes the newly installed pair after EFAULT; replaced slots
	 * are not resurrected. Both explicit target slots are therefore empty. */
	if (fixed_op(IORING_OP_READ, 0, rb, 1, ~0ULL, 0,
	    IOSQE_FIXED_FILE, 0x19b) != -EBADF ||
	    fixed_op(IORING_OP_READ, 1, rb, 1, ~0ULL, 0,
	    IOSQE_FIXED_FILE, 0x19c) != -EBADF)
		return (12);

	if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0)
		return (14);
	out[0] = 51; out[1] = 52;
	res = pipe_direct_submit(out, 0, 1, 0x19d, -ELINUX_ENXIO);
	return (res == 0 && out[0] == 51 && out[1] == 52 ? 0 : 15);
}

static int
t_splice(void)
{
	int a[2], b[2];
	char rb[8];
	u32 slot;
	struct cqe c[2];
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_pipe2, (long)a, 0, 0, 0, 0, 0) != 0)
		return (2);
	if (call(SYS_pipe2, (long)b, 0, 0, 0, 0, 0) != 0)
		return (3);
	if (call(SYS_write, a[1], (long)"SPLICED", 7, 0, 0, 0) != 7)
		return (4);
	/* fd_in=splice_fd_in, off_in=addr(-1), fd_out=fd, off_out=off(-1) */
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SPLICE, 0, b[1] /* fd_out */, (u64)-1 /* off_out */,
	    (void *)(u64)-1 /* off_in */, 7, 0, 0x1);
	g_sqes[slot].splice_fd_in = a[0];
	if (iou_flush(1, 1) != 1)
		return (5);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res) || res != 7)
		return (6);
	xmemset(rb, 0, sizeof(rb));
	if (call(SYS_read, b[0], (long)rb, 7, 0, 0, 0) != 7 ||
	    xmemcmp(rb, "SPLICED", 7) != 0)
		return (7);
	(void)sys1(SYS_close, a[0]); (void)sys1(SYS_close, a[1]);
	(void)sys1(SYS_close, b[0]); (void)sys1(SYS_close, b[1]);
	return (0);
}
static int
splice_offset_sqe(int fd_in, int fd_out, u64 off_in, u64 off_out,
    u32 len, u32 flags, u64 ud)
{
    struct cqe c[2];
    u32 slot = g_sqi & g_sqmask;
    int res;

    iou_sqe(IORING_OP_SPLICE, 0, fd_out, off_out,
        (void *)(unsigned long)off_in, len, flags, ud);
    g_sqes[slot].splice_fd_in = fd_in;
    if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
        !cqe_find(c, 1, ud, &res))
        return (-100000);
    return (res);
}

static int
t_splice_offsets(void)
{
    const char initial[] = "abcdefghijklmnop";
    int pipefd[2], fd;
    char buf[8];
    long off;

    if (ring_setup(8) < 0)
        return (1);
    fd = (int)tmpfile_fd("iou-splice-offsets");
    if (fd < 0)
        return (2);
    (void)sys3(SYS_unlinkat, AT_FDCWD, "iou-splice-offsets", 0);
    if (sys2(SYS_pipe2, pipefd, 0) != 0 ||
        sys4(SYS_pwrite64, fd, initial, 16, 0) != 16 ||
        sys3(SYS_lseek, fd, 0, 0) != 0)
        return (3);

    /* Explicit input offset leaves the file position alone. */
    if (splice_offset_sqe(fd, pipefd[1], 4, (u64)-1, 5, 0, 0x900) != 5 ||
        sys3(SYS_lseek, fd, 0, 1) != 0 ||
        sys3(SYS_read, pipefd[0], buf, 5) != 5 ||
        xmemcmp(buf, "efghi", 5) != 0)
        return (4);
    if (splice_offset_sqe(fd, pipefd[1], (u64)-1, (u64)-1, 3, 0,
        0x901) != 3 || sys3(SYS_lseek, fd, 0, 1) != 3 ||
        sys3(SYS_read, pipefd[0], buf, 3) != 3 ||
        xmemcmp(buf, "abc", 3) != 0)
        return (5);

    /* Explicit output offset leaves the same descriptor position alone. */
    if (sys3(SYS_write, pipefd[1], "XYZ", 3) != 3 ||
        splice_offset_sqe(pipefd[0], fd, (u64)-1, 6, 3, 0, 0x902) != 3 ||
        sys3(SYS_lseek, fd, 0, 1) != 3 ||
        sys4(SYS_pread64, fd, buf, 3, 6) != 3 ||
        xmemcmp(buf, "XYZ", 3) != 0)
        return (6);
    if (sys3(SYS_write, pipefd[1], "Q", 1) != 1 ||
        splice_offset_sqe(pipefd[0], fd, (u64)-1, (u64)-1, 1, 0,
        0x903) != 1 || sys3(SYS_lseek, fd, 0, 1) != 4 ||
        sys4(SYS_pread64, fd, buf, 1, 3) != 1 || buf[0] != 'Q')
        return (7);

    /* Direct splice updates its user offset; io_uring does not. */
    off = 10;
    if (call(SYS_splice, fd, (long)&off, pipefd[1], 0, 2, 0) != 2 ||
        off != 12 || sys3(SYS_lseek, fd, 0, 1) != 4 ||
        sys3(SYS_read, pipefd[0], buf, 2) != 2 ||
        xmemcmp(buf, "kl", 2) != 0)
        return (8);

    /* Bad offsets and flags must not consume a pipe or move file position. */
    if (sys3(SYS_write, pipefd[1], "r", 1) != 1 ||
        splice_offset_sqe(pipefd[0], fd, 0, (u64)-1, 1, 0,
        0x904) != -ESPIPE ||
        sys3(SYS_read, pipefd[0], buf, 1) != 1 || buf[0] != 'r')
        return (9);
    if (splice_offset_sqe(fd, pipefd[1], (u64)-1, 0, 1, 0,
        0x905) != -ESPIPE || sys3(SYS_lseek, fd, 0, 1) != 4)
        return (10);
    if (splice_offset_sqe(fd, pipefd[1], (u64)-2, (u64)-1, 1, 0,
        0x906) != -EINVAL || sys3(SYS_lseek, fd, 0, 1) != 4)
        return (11);
    if (sys3(SYS_write, pipefd[1], "s", 1) != 1 ||
        splice_offset_sqe(pipefd[0], fd, (u64)-1, (u64)-2, 1, 0,
        0x907) != -EINVAL ||
        sys3(SYS_read, pipefd[0], buf, 1) != 1 || buf[0] != 's')
        return (12);
    if (splice_offset_sqe(fd, pipefd[1], 0, (u64)-1, 1, 1U << 16,
        0x908) != -EINVAL ||
        splice_offset_sqe(fd, fd, 0, 0, 1, 0, 0x909) != -EINVAL ||
        sys3(SYS_lseek, fd, 0, 1) != 4)
        return (13);
    if (sys4(SYS_pread64, fd, buf, 3, 6) != 3 ||
        xmemcmp(buf, "XYZ", 3) != 0)
        return (14);
    (void)sys1(SYS_close, pipefd[0]);
    (void)sys1(SYS_close, pipefd[1]);
    (void)sys1(SYS_close, fd);
    return (0);
}

static int
fixed_splice_sqe(u8 op, u8 sqe_flags, int fd_in, int fd_out,
    u64 off_in, u64 off_out, u32 len, u32 splice_flags, u64 ud)
{
    struct cqe c[2];
    u32 slot = g_sqi & g_sqmask;
    int res;

    iou_sqe(op, sqe_flags, fd_out, off_out,
        (void *)(unsigned long)off_in, len, splice_flags, ud);
    g_sqes[slot].splice_fd_in = fd_in;
    if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
        !cqe_find(c, 1, ud, &res))
        return (-100000);
    return (res);
}

static int
splice_option_sqe(u8 sqe_flags, int fd_in, int fd_out, u64 off_in,
    u64 off_out, u32 len, u32 splice_flags, u16 ioprio, u16 buf_index,
    u64 pad0, u64 pad1, u64 ud)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SPLICE, sqe_flags, fd_out, off_out,
	    (void *)(unsigned long)off_in, len, splice_flags, ud);
	g_sqes[slot].ioprio = ioprio;
	g_sqes[slot].buf_index = buf_index;
	g_sqes[slot].splice_fd_in = fd_in;
	g_sqes[slot].pad2[0] = pad0;
	g_sqes[slot].pad2[1] = pad1;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != ud)
		return (-100000);
	return (c.res);
}

static int
t_splice_options(void)
{
	static const char data[] = "abcdefghijklmnop";
	int p[2], q[2], fds[3], src, tf, i;
	char ch;

	if (ring_setup(32) < 0 || sys2(SYS_pipe2, p, 0) != 0 ||
	    sys2(SYS_pipe2, q, 0) != 0)
		return (1);
	src = (int)tmpfile_fd("iou-splice-options-src");
	tf = (int)tmpfile_fd("iou-splice-options-dst");
	if (src < 0 || tf < 0 || sys4(SYS_pwrite64, src, data, 16, 0) != 16)
		return (2);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou-splice-options-src", 0);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou-splice-options-dst", 0);

	/* Generic options reject, but unused buffer and tail words are accepted. */
	if (splice_option_sqe(0, src, p[1], 0, (u64)-1, 0, 0, 1, 0,
	    0, 0, 0xe000) != -EINVAL ||
	    splice_option_sqe(IOSQE_BUFFER_SELECT, src, p[1], 0, (u64)-1,
	    0, 0, 0, 0, 0, 0, 0xe001) != -EOPNOTSUPP ||
	    splice_option_sqe(0, src, p[1], 0, (u64)-1, 0, 0, 0, 7,
	    0x1111, 0x2222, 0xe002) != 0)
		return (3);

	/* Every Linux SPLICE_F hint combination transfers the selected byte. */
	for (i = 0; i < 16; i++) {
		if (splice_option_sqe(0, src, p[1], (u64)i, (u64)-1, 1,
		    (u32)i, 0, 0, 0, 0, 0xe010 + (u64)i) != 1 ||
		    sys3(SYS_read, p[0], &ch, 1) != 1 || ch != data[i])
			return (4);
	}

	/* Flag validation precedes both registered input and output lookup. */
	fds[0] = src; fds[1] = p[1]; fds[2] = -1;
	if (iou_reg(IORING_REGISTER_FILES, fds, 3) != 0)
		return (5);
	if (splice_option_sqe(IOSQE_FIXED_FILE, 8, 2, 0, (u64)-1, 1,
	    SPLICE_F_FD_IN_FIXED | (1U << 16), 0, 0, 0, 0,
	    0xe020) != -EINVAL)
		return (6);

	/* Both registered directions retain their files after ambient close. */
	(void)sys1(SYS_close, src);
	(void)sys1(SYS_close, p[1]);
	if (splice_option_sqe(IOSQE_FIXED_FILE, 0, 1, 0, (u64)-1, 1,
	    SPLICE_F_FD_IN_FIXED, 0, 0, 0, 0, 0xe021) != 1 ||
	    sys3(SYS_read, p[0], &ch, 1) != 1 || ch != 'a')
		return (7);
	if (splice_option_sqe(IOSQE_FIXED_FILE, 0, 2, 1, (u64)-1, 1,
	    SPLICE_F_FD_IN_FIXED, 0, 0, 0, 0, 0xe022) != -EBADF ||
	    splice_option_sqe(IOSQE_FIXED_FILE, 0, 3, 1, (u64)-1, 1,
	    SPLICE_F_FD_IN_FIXED, 0, 0, 0, 0, 0xe023) != -EBADF ||
	    splice_option_sqe(IOSQE_FIXED_FILE, 2, 1, 1, (u64)-1, 1,
	    SPLICE_F_FD_IN_FIXED, 0, 0, 0, 0, 0xe024) != -EBADF ||
	    splice_option_sqe(IOSQE_FIXED_FILE, 3, 1, 1, (u64)-1, 1,
	    SPLICE_F_FD_IN_FIXED, 0, 0, 0, 0, 0xe025) != -EBADF)
		return (8);
	if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0 ||
	    splice_option_sqe(IOSQE_FIXED_FILE, 0, 1, 1, (u64)-1, 1,
	    SPLICE_F_FD_IN_FIXED, 0, 0, 0, 0, 0xe026) != -EBADF)
		return (9);

	/* Descriptor and shape failures have no output side effects. */
	if (splice_option_sqe(0, -1, q[1], (u64)-1, (u64)-1, 0, 0,
	    0, 0, 0, 0, 0xe027) != -EBADF ||
	    splice_option_sqe(0, q[0], -1, (u64)-1, (u64)-1, 0, 0,
	    0, 0, 0, 0, 0xe028) != -EBADF ||
	    splice_option_sqe(0, tf, tf, 0, 0, 1, 0, 0, 0, 0, 0,
	    0xe029) != -EINVAL)
		return (10);

	/* A fresh asynchronous transfer proves recovery after the negative matrix. */
	if (sys3(SYS_write, q[1], "R", 1) != 1 ||
	    splice_option_sqe(IOSQE_ASYNC, q[0], tf, (u64)-1, 0, 1, 0,
	    0, 0, 0, 0, 0xe02a) != 1 ||
	    sys4(SYS_pread64, tf, &ch, 1, 0) != 1 || ch != 'R')
		return (11);
	(void)sys1(SYS_close, p[0]);
	(void)sys1(SYS_close, q[0]);
	(void)sys1(SYS_close, q[1]);
	(void)sys1(SYS_close, tf);
	return (0);
}

static int
tee_option_sqe(u8 sqe_flags, int fd_in, int fd_out, u64 off_in, u64 off_out,
    u32 len, u32 splice_flags, u16 ioprio, u16 buf_index, u64 pad0, u64 pad1,
    u64 ud)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_TEE, sqe_flags, fd_out, off_out,
	    (void *)(unsigned long)off_in, len, splice_flags, ud);
	g_sqes[slot].ioprio = ioprio;
	g_sqes[slot].buf_index = buf_index;
	g_sqes[slot].splice_fd_in = fd_in;
	g_sqes[slot].pad2[0] = pad0;
	g_sqes[slot].pad2[1] = pad1;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != ud)
		return (-100000);
	return (c.res);
}

static int
t_tee_options(void)
{
	int a[2], b[2], c[2], fds[3], tf, i;
	char ch;

	if (ring_setup(16) < 0 || sys2(SYS_pipe2, a, 0) != 0 ||
	    sys2(SYS_pipe2, b, 0) != 0 || sys2(SYS_pipe2, c, 0) != 0)
		return (1);
	tf = (int)tmpfile_fd("iou-tee-options");
	if (tf < 0)
		return (2);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou-tee-options", 0);

	/* TEE requires both offsets to be zero and validates them before flags. */
	if (tee_option_sqe(0, a[0], b[1], 1, 0, 0, 0, 0, 0, 0, 0,
	    0xb00) != -EINVAL ||
	    tee_option_sqe(0, a[0], b[1], 0, 1, 0, 0, 0, 0, 0, 0,
	    0xb01) != -EINVAL ||
	    tee_option_sqe(0, a[0], b[1], 1, 1, 0, 1U << 16, 0, 0,
	    0, 0, 0xb02) != -EINVAL)
		return (3);

	/* Generic options and opcode flags fail during preparation. */
	if (tee_option_sqe(0, a[0], b[1], 0, 0, 0, 1U << 16, 0, 0,
	    0, 0, 0xb03) != -EINVAL ||
	    tee_option_sqe(0, a[0], b[1], 0, 0, 0, 0, 1, 0,
	    0, 0, 0xb04) != -EINVAL ||
	    tee_option_sqe(IOSQE_BUFFER_SELECT, a[0], b[1], 0, 0, 0, 0,
	    0, 7, 0, 0, 0xb05) != -EOPNOTSUPP)
		return (4);

	/* Unused buffer and tail words are ignored when buffer selection is off. */
	if (tee_option_sqe(0, a[0], b[1], 0, 0, 0, 0, 0, 9,
	    0x1111, 0x2222, 0xb06) != 0)
		return (5);

	/* Every Linux SPLICE_F hint combination is accepted and preserves input. */
	if (sys3(SYS_write, a[1], "T", 1) != 1)
		return (6);
	for (i = 0; i < 16; i++) {
		if (tee_option_sqe(0, a[0], b[1], 0, 0, 1, (u32)i, 0, 0,
		    0, 0, 0xb10 + (u64)i) != 1 ||
		    sys3(SYS_read, b[0], &ch, 1) != 1 || ch != 'T')
			return (7);
	}
	if (sys3(SYS_read, a[0], &ch, 1) != 1 || ch != 'T')
		return (8);

	/* Descriptor and pipe-shape errors do not turn into successful requests. */
	if (tee_option_sqe(0, -1, b[1], 0, 0, 0, 0, 0, 0, 0, 0,
	    0xb20) != -EBADF)
		return (91);
	if (tee_option_sqe(0, a[0], -1, 0, 0, 0, 0, 0, 0, 0, 0,
	    0xb21) != -EBADF)
		return (92);
	if (sys3(SYS_write, a[1], "D", 1) != 1)
		return (93);
	if (tee_option_sqe(0, tf, b[1], 0, 0, 1, 0, 0, 0, 0, 0,
	    0xb22) != -EINVAL)
		return (93);
	if (tee_option_sqe(0, a[0], tf, 0, 0, 1, 0, 0, 0, 0, 0,
	    0xb23) != -EINVAL)
		return (94);
	if (tee_option_sqe(0, a[0], a[1], 0, 0, 1, 0, 0, 0, 0, 0,
	    0xb24) != -EINVAL)
		return (95);
	if (sys3(SYS_read, a[0], &ch, 1) != 1 || ch != 'D')
		return (96);
	if (tee_option_sqe(0, a[0], b[1], 0, 0, 1, 2, 0, 0, 0, 0,
	    0xb25) != -EAGAIN)
		return (97);

	fds[0] = a[0];
	fds[1] = b[1];
	fds[2] = -1;
	if (iou_reg(IORING_REGISTER_FILES, fds, 3) != 0 ||
	    sys3(SYS_write, a[1], "F", 1) != 1)
		return (10);

	/* Input, output, and both directions support registered files. */
	if (tee_option_sqe(IOSQE_FIXED_FILE, a[0], 1, 0, 0, 1, 0, 0, 0,
	    0, 0, 0xb30) != 1 || sys3(SYS_read, b[0], &ch, 1) != 1 || ch != 'F' ||
	    tee_option_sqe(0, 0, b[1], 0, 0, 1, SPLICE_F_FD_IN_FIXED,
	    0, 0, 0, 0, 0xb31) != 1 ||
	    sys3(SYS_read, b[0], &ch, 1) != 1 || ch != 'F' ||
	    tee_option_sqe(IOSQE_FIXED_FILE, 0, 1, 0, 0, 1,
	    SPLICE_F_FD_IN_FIXED, 0, 0, 0, 0, 0xb32) != 1 ||
	    sys3(SYS_read, b[0], &ch, 1) != 1 || ch != 'F')
		return (11);

	/* Registered files remain usable after both ambient descriptors close. */
	(void)sys1(SYS_close, a[0]);
	(void)sys1(SYS_close, b[1]);
	if (tee_option_sqe(IOSQE_FIXED_FILE, 0, 1, 0, 0, 1,
	    SPLICE_F_FD_IN_FIXED, 0, 0, 0, 0, 0xb33) != 1 ||
	    sys3(SYS_read, b[0], &ch, 1) != 1 || ch != 'F')
		return (12);

	/* Preparation errors precede bad output slots and have no pipe effects. */
	if (tee_option_sqe(IOSQE_FIXED_FILE, 0, 2, 0, 0, 1,
	    SPLICE_F_FD_IN_FIXED | (1U << 16), 0, 0, 0, 0,
	    0xb34) != -EINVAL ||
	    tee_option_sqe(IOSQE_FIXED_FILE, 0, 2, 1, 0, 1,
	    SPLICE_F_FD_IN_FIXED, 0, 0, 0, 0, 0xb35) != -EINVAL ||
	    tee_option_sqe(IOSQE_FIXED_FILE, 0, 2, 0, 0, 1,
	    SPLICE_F_FD_IN_FIXED, 0, 0, 0, 0, 0xb36) != -EBADF ||
	    tee_option_sqe(IOSQE_FIXED_FILE, 0, 8, 0, 0, 1,
	    SPLICE_F_FD_IN_FIXED, 0, 0, 0, 0, 0xb37) != -EBADF ||
	    tee_option_sqe(0, 2, c[1], 0, 0, 1, SPLICE_F_FD_IN_FIXED,
	    0, 0, 0, 0, 0xb38) != -EBADF ||
	    tee_option_sqe(0, 8, c[1], 0, 0, 1, SPLICE_F_FD_IN_FIXED,
	    0, 0, 0, 0, 0xb39) != -EBADF)
		return (13);

	/* A valid request after the negative matrix still duplicates exactly once. */
	if (tee_option_sqe(IOSQE_FIXED_FILE, 0, 1, 0, 0, 1,
	    SPLICE_F_FD_IN_FIXED, 0, 0, 0, 0, 0xb3a) != 1 ||
	    sys3(SYS_read, b[0], &ch, 1) != 1 || ch != 'F' ||
	    iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0 ||
	    tee_option_sqe(IOSQE_FIXED_FILE, 0, 1, 0, 0, 1,
	    SPLICE_F_FD_IN_FIXED, 0, 0, 0, 0, 0xb3b) != -EBADF)
		return (14);

	(void)sys1(SYS_close, a[1]);
	(void)sys1(SYS_close, b[0]);
	(void)sys1(SYS_close, c[0]);
	(void)sys1(SYS_close, c[1]);
	(void)sys1(SYS_close, tf);
	return (0);
}

static int
t_splice_fixed_input(void)
{
    int a[2], b[2], fds[4], src, dst;
    char buf[8];

    if (ring_setup(8) < 0)
        return (1);
    src = (int)tmpfile_fd("iou-splice-fixed-src");
    dst = (int)tmpfile_fd("iou-splice-fixed-dst");
    if (src < 0 || dst < 0 ||
        sys2(SYS_pipe2, a, 0) != 0 || sys2(SYS_pipe2, b, 0) != 0)
        return (2);
    (void)sys3(SYS_unlinkat, AT_FDCWD, "iou-splice-fixed-src", 0);
    (void)sys3(SYS_unlinkat, AT_FDCWD, "iou-splice-fixed-dst", 0);
    if (sys4(SYS_pwrite64, src, "abcdefgh", 8, 0) != 8)
        return (3);
    fds[0] = src;
    fds[1] = a[0];
    fds[2] = a[1];
    fds[3] = -1;
    if (iou_reg(IORING_REGISTER_FILES, fds, 4) != 0)
        return (4);
    (void)sys1(SYS_close, src);

    /* The source slot survives closing the ordinary descriptor. */
    if (fixed_splice_sqe(IORING_OP_SPLICE, 0, 0, a[1], 2,
        (u64)-1, 3, SPLICE_F_FD_IN_FIXED, 0xa00) != 3 ||
        sys3(SYS_read, a[0], buf, 3) != 3 ||
        xmemcmp(buf, "cde", 3) != 0)
        return (5);
    if (fixed_splice_sqe(IORING_OP_SPLICE, IOSQE_FIXED_FILE, 0, 2,
        (u64)-1, (u64)-1, 2, SPLICE_F_FD_IN_FIXED, 0xa01) != 2 ||
        sys3(SYS_read, a[0], buf, 2) != 2 ||
        xmemcmp(buf, "ab", 2) != 0)
        return (6);

    /* A pipe can also be a registered input, including for TEE. */
    if (sys3(SYS_write, a[1], "XY", 2) != 2 ||
        fixed_splice_sqe(IORING_OP_SPLICE, 0, 1, dst, (u64)-1,
        1, 2, SPLICE_F_FD_IN_FIXED, 0xa02) != 2 ||
        sys4(SYS_pread64, dst, buf, 2, 1) != 2 ||
        xmemcmp(buf, "XY", 2) != 0)
        return (7);
    if (sys3(SYS_write, a[1], "QR", 2) != 2 ||
        fixed_splice_sqe(IORING_OP_TEE, 0, 1, b[1], 0, 0, 2,
        SPLICE_F_FD_IN_FIXED, 0xa03) != 2 ||
        sys3(SYS_read, b[0], buf, 2) != 2 ||
        xmemcmp(buf, "QR", 2) != 0 ||
        sys3(SYS_read, a[0], buf, 2) != 2 ||
        xmemcmp(buf, "QR", 2) != 0)
        return (8);

    /* Bad slots and flags have no file-position or pipe side effects. */
    if (fixed_splice_sqe(IORING_OP_SPLICE, 0, 8, a[1], 0,
        (u64)-1, 1, SPLICE_F_FD_IN_FIXED, 0xa04) != -EBADF ||
        fixed_splice_sqe(IORING_OP_SPLICE, 0, 3, a[1], 0,
        (u64)-1, 1, SPLICE_F_FD_IN_FIXED, 0xa05) != -EBADF ||
        fixed_splice_sqe(IORING_OP_TEE, 0, 8, b[1], 0, 0, 1,
        SPLICE_F_FD_IN_FIXED, 0xa06) != -EBADF)
        return (9);
    if (fixed_splice_sqe(IORING_OP_SPLICE, 0, 8, a[1], 0,
        (u64)-1, 1, SPLICE_F_FD_IN_FIXED | (1U << 16),
        0xa07) != -EINVAL ||
        fixed_splice_sqe(IORING_OP_TEE, 0, 8, b[1], 0, 0, 1,
        SPLICE_F_FD_IN_FIXED | (1U << 16), 0xa08) != -EINVAL)
        return (10);
    if (sys3(SYS_lseek, dst, 0, 1) != 0 ||
        sys4(SYS_pread64, dst, buf, 2, 1) != 2 ||
        xmemcmp(buf, "XY", 2) != 0)
        return (11);
    if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0 ||
        fixed_splice_sqe(IORING_OP_SPLICE, 0, 0, a[1], 0,
        (u64)-1, 1, SPLICE_F_FD_IN_FIXED, 0xa09) != -EBADF)
        return (12);
    (void)sys1(SYS_close, a[0]);
    (void)sys1(SYS_close, a[1]);
    (void)sys1(SYS_close, b[0]);
    (void)sys1(SYS_close, b[1]);
    (void)sys1(SYS_close, dst);
    return (0);
}

static int
t_nop128(void)
{
	if (ring_setup(8) < 0)
		return (1);
	return (sub1(-1, IORING_OP_NOP128, 0, 0, 0, 0, 0x1) == -EINVAL ? 0 : 2);
}
static int
t_readv_writev_fixed(void)
{
	static char buf[4096];
	struct iovec iov[2];
	long tf;
	char *rb = buf + 64;
	int res;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_vf");
	if (tf < 0)
		return (2);
	iov[0].iov_base = buf; iov[0].iov_len = sizeof(buf);
	if (iou_reg(IORING_REGISTER_BUFFERS, &iov[0], 1) != 0)
		return (3);
	buf[0] = 'V'; buf[1] = 'F';
	iov[0].iov_base = buf; iov[0].iov_len = 2;
	res = sub1(tf, IORING_OP_WRITEV_FIXED, iov, 1, 0, 0, 0x1);
	if (res != 2)
		return (4);
	xmemset(rb, 0, 8);
	iov[0].iov_base = rb; iov[0].iov_len = 2;
	res = sub1(tf, IORING_OP_READV_FIXED, iov, 1, 0, 0, 0x2);
	if (res != 2 || rb[0] != 'V' || rb[1] != 'F')
		return (5);
	(void)sys1(SYS_close, tf);
	return (0);
}
static int
t_writev_fixed_noreg(void)
{
	struct iovec iov;
	long tf;
	char b[2];
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_vfn");
	if (tf < 0)
		return (2);
	b[0] = 'x';
	iov.iov_base = b; iov.iov_len = 1;
	/* no registered buffers -> EFAULT */
	if (sub1(tf, IORING_OP_WRITEV_FIXED, &iov, 1, 0, 0, 0x1) != -EFAULT)
		return (3);
	(void)sys1(SYS_close, tf);
	return (0);
}
static int
t_epoll_wait(void)
{
	struct epoll_event ev;
	long epfd, efd;
	int res;
	u64 one = 1;
	if (ring_setup(8) < 0)
		return (1);
	epfd = call(SYS_epoll_create1, 0, 0, 0, 0, 0, 0);
	efd = call(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
	if (epfd < 0 || efd < 0)
		return (2);
	ev.events = EPOLLIN;
	ev.data = 0x99;
	if (sub1((int)epfd, IORING_OP_EPOLL_CTL, &ev, EPOLL_CTL_ADD, (u64)efd,
	    0, 0x1) != 0)
		return (3);
	/* make it readable */
	if (call(SYS_write, efd, (long)&one, 8, 0, 0, 0) != 8)
		return (4);
	{
		struct epoll_event out[4];
		/* EPOLL_WAIT: epfd=fd, events=addr, maxevents=len */
		res = sub1((int)epfd, IORING_OP_EPOLL_WAIT, out, 4, 0, 0, 0x2);
	}
	(void)sys1(SYS_close, epfd);
	(void)sys1(SYS_close, efd);
	return (res == 1 ? 0 : 5);
}
static int
t_epoll_wait_deferred(void)
{
    struct epoll_event ev, out[2];
    struct cqe c[2];
    long epfd, efd;
    u64 one = 1;
    int res;

    if (ring_setup(8) < 0)
        return (1);
    epfd = sys1(SYS_epoll_create1, 0);
    efd = sys2(SYS_eventfd2, 0, 0);
    if (epfd < 0 || efd < 0)
        return (2);
    ev.events = EPOLLIN;
    ev.data = 0x1234;
    if (sub1((int)epfd, IORING_OP_EPOLL_CTL, &ev, EPOLL_CTL_ADD,
        (u64)efd, 0, 0xc00) != 0)
        return (3);
    xmemset(out, 0, sizeof(out));
    iou_sqe(IORING_OP_EPOLL_WAIT, 0, (int)epfd, 0, out, 2, 0, 0xc01);
    if (iou_flush(1, 0) != 1 || iou_reap(c, 2) != 0)
        return (4);
    if (sys3(SYS_write, efd, &one, sizeof(one)) != sizeof(one))
        return (5);
    if (iou_flush(0, 1) != 0 || iou_reap(c, 2) != 1 ||
        !cqe_find(c, 1, 0xc01, &res) || res != 1 ||
        (out[0].events & EPOLLIN) == 0 || out[0].data != 0x1234)
        return (6);
    (void)sys1(SYS_close, efd);
    (void)sys1(SYS_close, epfd);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
t_epoll_wait_cancel(void)
{
    struct epoll_event out[2];
    struct cqe c[3];
    long epfd;
    int n, wait_res, cancel_res;

    if (ring_setup(8) < 0)
        return (1);
    epfd = sys1(SYS_epoll_create1, 0);
    if (epfd < 0)
        return (2);
    xmemset(out, 0xa5, sizeof(out));
    iou_sqe(IORING_OP_EPOLL_WAIT, 0, (int)epfd, 0, out, 2, 0, 0xc10);
    if (iou_flush(1, 0) != 1 || iou_reap(c, 3) != 0)
        return (3);
    iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0,
        (void *)(unsigned long)0xc10, 0, 0, 0xc11);
    if (iou_flush(1, 2) != 1)
        return (4);
    n = iou_reap(c, 3);
    if (n != 2 || !cqe_find(c, n, 0xc10, &wait_res) ||
        !cqe_find(c, n, 0xc11, &cancel_res))
        return (5);
    if (wait_res != -ELINUX_ECANCELED || cancel_res != 0 ||
        ((u8 *)out)[0] != 0xa5) {
        put("EPOLL_CANCEL_DIAG "); putnum(wait_res); put(" ");
        putnum(cancel_res); put("\n");
        return (6);
    }
    (void)sys1(SYS_close, epfd);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
t_epoll_wait_fixed(void)
{
    struct epoll_event ev, out[2];
    struct cqe c[3];
    long epfd, efd;
    int fds[1], n, res = 0, cancel_res = 0;
    u64 one = 1, got = 0;

    if (ring_setup(8) < 0)
        return (1);
    epfd = sys1(SYS_epoll_create1, 0);
    efd = sys2(SYS_eventfd2, 0, 0);
    if (epfd < 0 || efd < 0)
        return (2);
    ev.events = EPOLLIN;
    ev.data = 0xdead;
    if (sub1((int)epfd, IORING_OP_EPOLL_CTL, &ev, EPOLL_CTL_ADD,
        (u64)efd, 0, 0xc40) != 0)
        return (3);
    fds[0] = (int)epfd;
    if (iou_reg(IORING_REGISTER_FILES, fds, 1) != 0)
        return (4);
    (void)sys1(SYS_close, epfd);
    xmemset(out, 0, sizeof(out));
    iou_sqe(IORING_OP_EPOLL_WAIT, IOSQE_FIXED_FILE, 1, 0,
        out, 2, 0, 0xc41);
    if (iou_flush(1, 1) != 1 || iou_reap(c, 3) != 1 ||
        !cqe_find(c, 1, 0xc41, &res) || res != -EBADF)
        return (5);
    iou_sqe(IORING_OP_EPOLL_WAIT, IOSQE_FIXED_FILE, 0, 0,
        out, 2, 0, 0xc42);
    if (iou_flush(1, 0) != 1 || iou_reap(c, 3) != 0)
        return (6);
    if (sys3(SYS_write, efd, &one, sizeof(one)) != sizeof(one))
        return (7);
    n = iou_flush(0, 1);
    if (n != 0 || iou_reap(c, 3) != 1 ||
        !cqe_find(c, 1, 0xc42, &res) || res != 1 ||
        (out[0].events & EPOLLIN) == 0 || out[0].data != 0xdead) {
        put("EPOLL_FIXED_READY_DIAG "); putnum(n); put(" ");
        putnum(res); put(" "); putnum(out[0].events); put(" ");
        putnum(out[0].data); put("\n");
        return (8);
    }
    if (sys3(SYS_read, efd, &got, sizeof(got)) != sizeof(got) || got != 1)
        return (9);
    iou_sqe(IORING_OP_EPOLL_WAIT, IOSQE_FIXED_FILE, 0, 0,
        out, 2, 0, 0xc43);
    if (iou_flush(1, 0) != 1 || iou_reap(c, 3) != 0)
        return (10);
    iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0,
        (void *)(unsigned long)0xc43, 0, 0, 0xc44);
    if (iou_flush(1, 2) != 1)
        return (11);
    n = iou_reap(c, 3);
    if (n != 2 || !cqe_find(c, n, 0xc43, &res) ||
        !cqe_find(c, n, 0xc44, &cancel_res) ||
        res != -ELINUX_ECANCELED || cancel_res != 0) {
        put("EPOLL_FIXED_DIAG "); putnum(n); put(" ");
        putnum(res); put(" "); putnum(cancel_res); put("\n");
        return (12);
    }
    if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0)
        return (13);
    (void)sys1(SYS_close, efd);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
t_epoll_wait_close_reuse(void)
{
    struct epoll_event ev, out[2];
    struct cqe c[2];
    long epfd, replacement, efd;
    u64 one = 1;
    int res;

    if (ring_setup(8) < 0)
        return (1);
    epfd = sys1(SYS_epoll_create1, 0);
    efd = sys2(SYS_eventfd2, 0, 0);
    if (epfd < 0 || efd < 0)
        return (2);
    ev.events = EPOLLIN;
    ev.data = 0xbeef;
    if (sub1((int)epfd, IORING_OP_EPOLL_CTL, &ev, EPOLL_CTL_ADD,
        (u64)efd, 0, 0xc50) != 0)
        return (3);
    xmemset(out, 0, sizeof(out));
    iou_sqe(IORING_OP_EPOLL_WAIT, 0, (int)epfd, 0, out, 2, 0, 0xc51);
    if (iou_flush(1, 0) != 1 || iou_reap(c, 2) != 0)
        return (4);
    (void)sys1(SYS_close, epfd);
    replacement = sys1(SYS_epoll_create1, 0);
    if (replacement != epfd)
        return (5);
    if (sys3(SYS_write, efd, &one, sizeof(one)) != sizeof(one))
        return (6);
    if (iou_flush(0, 1) != 0 || iou_reap(c, 2) != 1 ||
        !cqe_find(c, 1, 0xc51, &res) || res != 1 ||
        out[0].data != 0xbeef || (out[0].events & EPOLLIN) == 0)
        return (7);
    (void)sys1(SYS_close, replacement);
    (void)sys1(SYS_close, efd);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
t_epoll_wait_close_reuse_cancel(void)
{
    struct epoll_event out[2];
    struct cqe c[3];
    long epfd, replacement;
    int n, wait_res = 0, cancel_res = 0;

    if (ring_setup(8) < 0)
        return (1);
    epfd = sys1(SYS_epoll_create1, 0);
    if (epfd < 0)
        return (2);
    xmemset(out, 0xa5, sizeof(out));
    iou_sqe(IORING_OP_EPOLL_WAIT, 0, (int)epfd, 0, out, 2, 0, 0xc60);
    if (iou_flush(1, 0) != 1 || iou_reap(c, 3) != 0)
        return (3);
    (void)sys1(SYS_close, epfd);
    replacement = sys1(SYS_epoll_create1, 0);
    if (replacement != epfd)
        return (4);
    iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0,
        (void *)(unsigned long)0xc60, 0, 0, 0xc61);
    if (iou_flush(1, 2) != 1)
        return (5);
    n = iou_reap(c, 3);
    if (n != 2 || !cqe_find(c, n, 0xc60, &wait_res) ||
        !cqe_find(c, n, 0xc61, &cancel_res) ||
        wait_res != -ELINUX_ECANCELED || cancel_res != 0 ||
        ((u8 *)out)[0] != 0xa5) {
        put("EPOLL_REUSE_CANCEL_DIAG "); putnum(n); put(" ");
        putnum(wait_res); put(" "); putnum(cancel_res); put("\n");
        return (6);
    }
    (void)sys1(SYS_close, replacement);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}


/* Race child readiness against cancellation; exactly one wait CQE may win. */
static int
t_epoll_wait_ready_cancel_race(void)
{
    struct epoll_event ev, out[2];
    struct cqe c[4];
    struct timespec delay;
    long epfd, efd, pid;
    u64 one = 1;
    int i, n, wait_res, cancel_res, status;

    for (i = 0; i < 16; i++) {
        if (ring_setup(8) < 0)
            return (1);
        epfd = sys1(SYS_epoll_create1, 0);
        efd = sys2(SYS_eventfd2, 0, 0);
        if (epfd < 0 || efd < 0)
            return (2);
        ev.events = EPOLLIN;
        ev.data = 0xface;
        if (sub1((int)epfd, IORING_OP_EPOLL_CTL, &ev,
            EPOLL_CTL_ADD, (u64)efd, 0, 0xc70) != 0)
            return (3);
        xmemset(out, 0xa5, sizeof(out));
        iou_sqe(IORING_OP_EPOLL_WAIT, 0, (int)epfd, 0,
            out, 2, 0, 0xc71);
        if (iou_flush(1, 0) != 1)
            return (4);
        pid = fork_process();
        if (pid < 0)
            return (5);
        if (pid == 0) {
            delay.tv_sec = 0;
            delay.tv_nsec = (i % 4) * 1000000;
            (void)sys2(SYS_nanosleep, &delay, 0);
            (void)sys3(SYS_write, efd, &one, sizeof(one));
            (void)sys1(SYS_exit_group, 0);
        }
        delay.tv_sec = 0;
        delay.tv_nsec = ((i + 2) % 4) * 1000000;
        (void)sys2(SYS_nanosleep, &delay, 0);
        iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0,
            (void *)(unsigned long)0xc71, 0, 0, 0xc72);
        if (iou_flush(1, 2) != 1)
            return (6);
        n = iou_reap(c, 4);
        wait_res = cancel_res = 0;
        if (n != 2 || !cqe_find(c, n, 0xc71, &wait_res) ||
            !cqe_find(c, n, 0xc72, &cancel_res))
            return (7);
        if (wait_res == 1) {
            if (cancel_res != -2 || out[0].data != 0xface ||
                (out[0].events & EPOLLIN) == 0)
                return (8);
        } else if (wait_res == -ELINUX_ECANCELED) {
            if (cancel_res != 0 || ((u8 *)out)[0] != 0xa5)
                return (9);
        } else {
            put("EPOLL_RACE_DIAG "); putnum(i); put(" ");
            putnum(wait_res); put(" "); putnum(cancel_res); put("\n");
            return (10);
        }
        status = 0;
        if (sys4(SYS_wait4, pid, &status, 0, 0) != pid || status != 0)
            return (11);
        (void)sys1(SYS_close, epfd);
        (void)sys1(SYS_close, efd);
        (void)sys1(SYS_close, fd_ring);
    }
    return (0);
}

static int
t_epoll_wait_badfields(void)
{
    struct epoll_event out[2];
    struct cqe c[2];
    long epfd;
    u32 slot;
    int i, res;

    if (ring_setup(8) < 0)
        return (1);
    epfd = sys1(SYS_epoll_create1, 0);
    if (epfd < 0)
        return (2);
    for (i = 0; i < 4; i++) {
        slot = g_sqi & g_sqmask;
        iou_sqe(IORING_OP_EPOLL_WAIT, 0, (int)epfd, 0, out, 2,
            0, 0xc20 + i);
        if (i == 0) g_sqes[slot].off = 1;
        if (i == 1) g_sqes[slot].rw_flags = 1;
        if (i == 2) g_sqes[slot].buf_index = 1;
        if (i == 3) g_sqes[slot].splice_fd_in = 1;
        if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
            !cqe_find(c, 1, 0xc20 + i, &res) || res != -EINVAL)
            return (3 + i);
    }
    (void)sys1(SYS_close, epfd);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
fixed_install_option_submit(u8 flags, int slot_index, u32 install_flags,
    u16 personality, int badfield, u64 pad, u64 ud)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_FIXED_FD_INSTALL, flags, slot_index, 0, 0, 0,
	    install_flags, ud);
	g_sqes[slot].personality = personality;
	if (badfield == 1) g_sqes[slot].off = 1;
	if (badfield == 2) g_sqes[slot].addr = 1;
	if (badfield == 3) g_sqes[slot].len = 1;
	if (badfield == 4) g_sqes[slot].buf_index = 1;
	if (badfield == 5) g_sqes[slot].splice_fd_in = 1;
	if (badfield == 6) g_sqes[slot].pad2[0] = 1;
	g_sqes[slot].pad2[1] = pad;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != ud || c.flags != 0)
		return (-100000);
	return (c.res);
}

static int
t_fixed_fd_install_options(void)
{
	int files[2], fd, installed;
	long personality;

	if (ring_setup(16) < 0) return (1);
	fd = (int)tmpfile_fd("iou_fixed_install_opt"); if (fd < 0) return (2);
	files[0] = fd; files[1] = -1;
	if (iou_reg(IORING_REGISTER_FILES, files, 2) != 0) return (3);
	/* Generic options precede personality and opcode preparation. */
	if (fixed_install_option_submit(IOSQE_FIXED_FILE, 99, 0, 0, 0, 0,
	    0xd001) != -EBADF) return (4);
	{ u32 slot = g_sqi & g_sqmask;
	  iou_sqe(IORING_OP_FIXED_FD_INSTALL, IOSQE_FIXED_FILE, 99, 0, 0, 0,
	      0, 0xd002); g_sqes[slot].ioprio = 1; g_sqes[slot].personality = 99;
	  if (iou_flush(1,1)!=1 || iou_reap((struct cqe[1]){{0}},0)!=0) return (5);
	  { struct cqe c; if (iou_reap(&c,1)!=1 || c.res!=-EINVAL) return (6); } }
	{ u32 slot = g_sqi & g_sqmask; struct cqe c;
	  iou_sqe(IORING_OP_FIXED_FD_INSTALL,
	      IOSQE_FIXED_FILE|IOSQE_BUFFER_SELECT, 99, 0, 0, 0, 0, 0xd003);
	  g_sqes[slot].personality = 99;
	  if (iou_flush(1,1)!=1 || iou_reap(&c,1)!=1 || c.res!=-EOPNOTSUPP)
	      return (7); }
	/* All six reserved fields win over missing FIXED_FILE and bad slots. */
	for (int field = 1; field <= 6; field++)
		if (fixed_install_option_submit(0, 99, 0, 0, field, 0,
		    0xd010 + field) != -EINVAL) return (8);
	if (fixed_install_option_submit(0, 99, 0x80000000U, 0, 0, 0,
	    0xd020) != -EBADF ||
	    fixed_install_option_submit(IOSQE_FIXED_FILE, 99, 2, 0, 0, 0,
	    0xd021) != -EINVAL) return (9);
	/* Valid personality is rejected after field and flag validation. */
	personality = iou_reg(IORING_REGISTER_PERSONALITY, 0, 0);
	if (personality <= 0 || personality > 65535) return (10);
	if (fixed_install_option_submit(IOSQE_FIXED_FILE, 0, 2,
	    (u16)personality, 0, 0, 0xd022) != -EINVAL ||
	    fixed_install_option_submit(IOSQE_FIXED_FILE, 0, 0,
	    (u16)personality, 0, 0, 0xd023) != -EPERM) return (11);
	/* ASYNC and final padding are accepted; source slot remains healthy. */
	installed = fixed_install_option_submit(IOSQE_FIXED_FILE|IOSQE_ASYNC,
	    0, IORING_FIXED_FD_NO_CLOEXEC, 0, 0, 0xfeedface, 0xd024);
	if (installed < 0 || sys1(SYS_close, installed) != 0 ||
	    fixed_op(IORING_OP_FSYNC, 0, 0, 0, 0, 0, IOSQE_FIXED_FILE,
	    0xd025) != 0) return (12);
	if (iou_reg(IORING_UNREGISTER_PERSONALITY, 0, (u32)personality) != 0 ||
	    iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0 ||
	    sys1(SYS_close, fd) != 0) return (13);
	return (0);
}

static int
t_fixed_fd_install(void)
{
	long tf;
	char rb[8];
	int fds[1], newfd;
	if (ring_setup(8) < 0)
		return (1);
	tf = tmpfile_fd("iou_ffi");
	if (tf < 0)
		return (2);
	if (sub1(tf, IORING_OP_WRITE, "installd", 8, 0, 0, 0x1) != 8)
		return (3);
	fds[0] = (int)tf;
	if (iou_reg(IORING_REGISTER_FILES, fds, 1) != 0)
		return (4);
	/* install registered index 0 into the normal table */
	newfd = sub1flags(0 /* index */, IORING_OP_FIXED_FD_INSTALL,
    IOSQE_FIXED_FILE, 0, 0, 0, 0x2);
	if (newfd < 0)
		return (5);
	xmemset(rb, 0, sizeof(rb));
	if (call(SYS_read, newfd, (long)rb, 8, 0, 0, 0) != 8 ||
	    xmemcmp(rb, "installd", 8) != 0)
		return (6);
	(void)sys1(SYS_close, newfd);
	(void)sys1(SYS_close, tf);
	return (0);
}
static int
t_send_zc_skip(void)
{
	int sv[2], res;
	char rb[4];

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	res = sub1flags(sv[0], IORING_OP_SEND_ZC,
	    IOSQE_CQE_SKIP_SUCCESS, "skip", 4, 0, 0xd00);
	if (res != -EINVAL)
		return (3);
	if (sys3(SYS_read, sv[1], rb, sizeof(rb)) != -EAGAIN)
		return (4);
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0xd01) != 0)
		return (5);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_sendmsg_zc_skip(void)
{
	struct l_msghdr mh;
	struct iovec iov;
	struct cqe c[2];
	char rb[4];
	int sv[2], n, res;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	iov.iov_base = "skip";
	iov.iov_len = 4;
	xmemset(&mh, 0, sizeof(mh));
	mh.msg_iov = (u64)(unsigned long)&iov;
	mh.msg_iovlen = 1;
	iou_sqe(IORING_OP_SENDMSG_ZC, IOSQE_CQE_SKIP_SUCCESS,
	    sv[0], 0, &mh, 0, 0, 0xd10);
	if (iou_flush(1, 1) != 1)
		return (3);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0xd10, &res) || res != -EINVAL ||
	    c[0].flags != 0)
		return (4);
	if (sys3(SYS_read, sv[1], rb, sizeof(rb)) != -EAGAIN)
		return (5);
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0xd11) != 0)
		return (6);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_send_zc(void)
{
	int sv[2], n, i;
	char rb[8];
	struct cqe c[4];
	int more = 0, notif = 0;
	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0)
	    != 0)
		return (2);
	/* SEND_ZC posts a primary (F_MORE) CQE and an F_NOTIF CQE */
	iou_sqe(IORING_OP_SEND_ZC, 0, sv[0], 0, "zcbytes", 7, 0, 0x1);
	if (iou_flush(1, 2) != 1)
		return (3);
	n = iou_reap(c, 4);
	if (n != 2)
		return (4);
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x1ULL)
			continue;
		if (c[i].flags & IORING_CQE_F_MORE) { more = 1; if (c[i].res != 7) return (5); }
		if (c[i].flags & IORING_CQE_F_NOTIF) notif = 1;
	}
	if (!more || !notif)
		return (6);
	xmemset(rb, 0, sizeof(rb));
	if (sub1(sv[1], IORING_OP_RECV, rb, 7, 0, 0, 0x2) != 7 ||
	    xmemcmp(rb, "zcbytes", 7) != 0)
		return (7);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}
static int
t_send_zc_addr3(void)
{
	struct cqe c[4];
	char rb[8];
	u32 slot;
	int sv[2], n, i, primary, notif;

	if (ring_setup(8) < 0)
		return (1);
	if (zcrx_tcp_pair(&sv[0], &sv[1]) != 0)
		return (2);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SEND_ZC, 0, sv[0], 0, "addr3", 5, 0, 0xd20);
	g_sqes[slot].ioprio = IORING_SEND_ZC_REPORT_USAGE;
	g_sqes[slot].pad2[0] = 0xd21;
	if (iou_flush(1, 2) != 1)
		return (3);
	n = iou_reap(c, 4);
	primary = notif = 0;
	for (i = 0; i < n; i++) {
		if (c[i].user_data == 0xd20 &&
		    (c[i].flags & IORING_CQE_F_NOTIF) == 0) {
			if (c[i].res != 5 ||
			    (c[i].flags & IORING_CQE_F_MORE) == 0)
				return (4);
			primary = 1;
		} else if (c[i].user_data == 0xd21 &&
		    (c[i].flags & IORING_CQE_F_NOTIF) != 0) {
			if ((u32)c[i].res != IORING_NOTIF_USAGE_ZC_COPIED)
				return (5);
			notif = 1;
		}
	}
	if (n != 2 || !primary || !notif)
		return (6);
	xmemset(rb, 0, sizeof(rb));
	if (sys3(SYS_read, sv[1], rb, 5) != 5 ||
	    xmemcmp(rb, "addr3", 5) != 0)
		return (7);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_sendmsg_zc_addr3(void)
{
	struct l_msghdr mh;
	struct iovec iov;
	struct cqe c[4];
	char rb[8];
	u32 slot;
	int sv[2], n, i, primary, notif;

	if (ring_setup(8) < 0)
		return (1);
	if (zcrx_tcp_pair(&sv[0], &sv[1]) != 0)
		return (2);
	iov.iov_base = "msg3";
	iov.iov_len = 4;
	xmemset(&mh, 0, sizeof(mh));
	mh.msg_iov = (u64)(unsigned long)&iov;
	mh.msg_iovlen = 1;
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SENDMSG_ZC, 0, sv[0], 0, &mh, 0, 0, 0xd30);
	g_sqes[slot].pad2[0] = 0xd31;
	if (iou_flush(1, 2) != 1)
		return (3);
	n = iou_reap(c, 4);
	primary = notif = 0;
	for (i = 0; i < n; i++) {
		if (c[i].user_data == 0xd30 &&
		    (c[i].flags & IORING_CQE_F_NOTIF) == 0) {
			if (c[i].res != 4 ||
			    (c[i].flags & IORING_CQE_F_MORE) == 0)
				return (4);
			primary = 1;
		} else if (c[i].user_data == 0xd31 &&
		    (c[i].flags & IORING_CQE_F_NOTIF) != 0) {
			if (c[i].res != 0)
				return (5);
			notif = 1;
		}
	}
	if (n != 2 || !primary || !notif)
		return (6);
	xmemset(rb, 0, sizeof(rb));
	if (sys3(SYS_read, sv[1], rb, 4) != 4 ||
	    xmemcmp(rb, "msg3", 4) != 0)
		return (7);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_send_zc_reserved(void)
{
	struct l_msghdr mh;
	struct iovec iov;
	struct cqe c[4];
	char rb[4];
	u32 slot;
	int sv[2], n, op, res;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	iov.iov_base = "x";
	iov.iov_len = 1;
	xmemset(&mh, 0, sizeof(mh));
	mh.msg_iov = (u64)(unsigned long)&iov;
	mh.msg_iovlen = 1;
	for (op = IORING_OP_SEND_ZC; op <= IORING_OP_SENDMSG_ZC; op++) {
		slot = g_sqi & g_sqmask;
		iou_sqe((u8)op, 0, sv[0], 0,
		    op == IORING_OP_SEND_ZC ? (void *)"x" : (void *)&mh,
		    op == IORING_OP_SEND_ZC ? 1 : 0, 0, 0xd40 + op);
		g_sqes[slot].pad2[0] = 0xd80 + op;
		g_sqes[slot].pad2[1] = 1;
		if (iou_flush(1, 1) != 1)
			return (3 + op);
		n = iou_reap(c, 4);
		if (n != 1 || !cqe_find(c, n, 0xd40 + op, &res) ||
		    res != -EINVAL || c[0].flags != 0)
			return (60 + op);
		if (sys3(SYS_read, sv[1], rb, sizeof(rb)) != -EAGAIN)
			return (90 + op);
	}
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0xd90) != 0)
		return (120);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_send_addrlen_padding(void)
{
	struct cqe c[2]; char rb[4]; u32 slot; int sv[2], n, res;
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM | LX_SOCK_NONBLOCK,
	    0, (long)sv, 0, 0) != 0) return (2);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SEND, 0, sv[0], 0, (void *)"p", 1, 0, 0xd94);
	g_sqes[slot].splice_fd_in = 1 << 16;
	if (iou_flush(1, 1) != 1) return (3);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0xd94, &res) || res != -EINVAL ||
	    c[0].flags != 0) return (4);
	if (sys3(SYS_read, sv[1], rb, sizeof(rb)) != -EAGAIN) return (5);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]); return (0);
}

static int
t_sendmsg_reserved_fields(void)
{
	struct l_msghdr mh; struct iovec iov; struct cqe c[2]; char rb[4];
	u32 slot; int sv[2], n, which, res;
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM | LX_SOCK_NONBLOCK,
	    0, (long)sv, 0, 0) != 0) return (2);
	iov.iov_base = "r"; iov.iov_len = 1; xmemset(&mh, 0, sizeof(mh));
	mh.msg_iov = (u64)(unsigned long)&iov; mh.msg_iovlen = 1;
	for (which = 0; which < 2; which++) {
		slot = g_sqi & g_sqmask;
		iou_sqe(IORING_OP_SENDMSG, 0, sv[0], 0, &mh, 0, 0, 0xd95 + which);
		if (which == 0) g_sqes[slot].off = 1;
		else g_sqes[slot].splice_fd_in = 1;
		if (iou_flush(1, 1) != 1) return (3 + which);
		n = iou_reap(c, 2);
		if (n != 1 || !cqe_find(c, n, 0xd95 + which, &res) ||
		    res != -EINVAL || c[0].flags != 0) return (10 + which);
		if (sys3(SYS_read, sv[1], rb, sizeof(rb)) != -EAGAIN)
			return (20 + which);
	}
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]); return (0);
}

static int
t_recv_addr2_reserved(void)
{
	struct cqe c[2];
	char ch;
	u32 slot;
	int sv[2], n, op, res;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	for (op = IORING_OP_RECVMSG; op <= IORING_OP_RECV; op +=
	    IORING_OP_RECV - IORING_OP_RECVMSG) {
		ch = (op == IORING_OP_RECV) ? 'r' : 'm';
		if (sys3(SYS_write, sv[1], &ch, 1) != 1)
			return (3 + op);
		slot = g_sqi & g_sqmask;
		/* A reserved addr2 must win over the deliberately bad buffer. */
		iou_sqe((u8)op, 0, sv[0], 0, (void *)1,
		    op == IORING_OP_RECV ? 1 : 0, 0, 0xd97 + op);
		g_sqes[slot].off = 1;
		if (iou_flush(1, 1) != 1)
			return (40 + op);
		n = iou_reap(c, 2);
		if (n != 1 || !cqe_find(c, n, 0xd97 + op, &res) ||
		    res != -EINVAL || c[0].flags != 0)
			return (80 + op);
		ch = 0;
		if (sys3(SYS_read, sv[0], &ch, 1) != 1 ||
		    ch != ((op == IORING_OP_RECV) ? 'r' : 'm'))
			return (120 + op);
	}
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0xdd0) != 0)
		return (160);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_send_zc_addrlen_padding(void)
{
	struct cqe c[4];
	char rb[4];
	u32 slot;
	int sv[2], n, res;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SEND_ZC, 0, sv[0], 0, (void *)"p", 1, 0, 0xd98);
	g_sqes[slot].pad2[0] = 0xd99;
	g_sqes[slot].splice_fd_in = 1 << 16;
	if (iou_flush(1, 1) != 1)
		return (3);
	n = iou_reap(c, 4);
	if (n != 1 || !cqe_find(c, n, 0xd98, &res) || res != -EINVAL ||
	    c[0].flags != 0)
		return (4);
	if (sys3(SYS_read, sv[1], rb, sizeof(rb)) != -EAGAIN)
		return (5);
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0xd9a) != 0)
		return (6);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_sendmsg_zc_reserved_fields(void)
{
	struct l_msghdr mh;
	struct iovec iov;
	struct cqe c[4];
	char rb[4];
	u32 slot;
	int sv[2], n, which, res;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	iov.iov_base = "r";
	iov.iov_len = 1;
	xmemset(&mh, 0, sizeof(mh));
	mh.msg_iov = (u64)(unsigned long)&iov;
	mh.msg_iovlen = 1;
	for (which = 0; which < 2; which++) {
		slot = g_sqi & g_sqmask;
		iou_sqe(IORING_OP_SENDMSG_ZC, 0, sv[0], 0, &mh, 0, 0,
		    0xda0 + which);
		g_sqes[slot].pad2[0] = 0xdb0 + which;
		if (which == 0)
			g_sqes[slot].off = 1;
		else
			g_sqes[slot].splice_fd_in = 1;
		if (iou_flush(1, 1) != 1)
			return (3 + which);
		n = iou_reap(c, 4);
		if (n != 1 || !cqe_find(c, n, 0xda0 + which, &res) ||
		    res != -EINVAL || c[0].flags != 0)
			return (10 + which);
		if (sys3(SYS_read, sv[1], rb, sizeof(rb)) != -EAGAIN)
			return (20 + which);
	}
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0xdc0) != 0)
		return (30);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	return (0);
}
static int
t_send_zc_error_notification(void)
{
	struct l_msghdr mh;
	struct iovec iov;
	struct cqe c[4];
	u32 slot;
	int sv[2], op, n, i, primary, notif;
	u64 primary_ud, notif_ud;

	if (ring_setup(8) < 0)
		return (1);
	iov.iov_base = "err";
	iov.iov_len = 3;
	xmemset(&mh, 0, sizeof(mh));
	mh.msg_iov = (u64)(unsigned long)&iov;
	mh.msg_iovlen = 1;
	for (op = IORING_OP_SEND_ZC; op <= IORING_OP_SENDMSG_ZC; op++) {
		if (zcrx_tcp_pair(&sv[0], &sv[1]) != 0)
			return (2 + op);
		if (sys2(SYS_shutdown, sv[0], LX_SHUT_RDWR) != 0)
			return (60 + op);
		primary_ud = 0xda0 + op;
		notif_ud = 0xdb0 + op;
		slot = g_sqi & g_sqmask;
		iou_sqe((u8)op, 0, sv[0], 0,
		    op == IORING_OP_SEND_ZC ? (void *)"err" : (void *)&mh,
		    op == IORING_OP_SEND_ZC ? 3 : 0, 0, primary_ud);
		g_sqes[slot].pad2[0] = notif_ud;
		if (iou_flush(1, 1) != 1)
			return (90 + op);
		n = iou_reap(c, 4);
		primary = notif = 0;
		for (i = 0; i < n; i++) {
			if (c[i].user_data == primary_ud &&
			    (c[i].flags & IORING_CQE_F_NOTIF) == 0) {
				if (c[i].res != -ELINUX_EPIPE ||
				    (c[i].flags & IORING_CQE_F_MORE) == 0)
					return (120 + op);
				primary = 1;
			} else if (c[i].user_data == notif_ud &&
			    (c[i].flags & IORING_CQE_F_NOTIF) != 0) {
				if (c[i].res != 0)
					return (150 + op);
				notif = 1;
			}
		}
		if (n != 2 || !primary || !notif)
			return (180 + op);
		(void)sys1(SYS_close, sv[0]);
		(void)sys1(SYS_close, sv[1]);
	}
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0xdc0) != 0)
		return (220);
	return (0);
}
static int
t_send_zc_error_report_usage(void)
{
	struct l_msghdr mh;
	struct iovec iov;
	struct cqe c[4];
	u32 slot;
	int sv[2], op, n, i, primary, notif;
	u64 primary_ud, notif_ud;

	if (ring_setup(8) < 0)
		return (1);
	iov.iov_base = "usage";
	iov.iov_len = 5;
	xmemset(&mh, 0, sizeof(mh));
	mh.msg_iov = (u64)(unsigned long)&iov;
	mh.msg_iovlen = 1;
	for (op = IORING_OP_SEND_ZC; op <= IORING_OP_SENDMSG_ZC; op++) {
		if (zcrx_tcp_pair(&sv[0], &sv[1]) != 0)
			return (2 + op);
		if (sys2(SYS_shutdown, sv[0], LX_SHUT_RDWR) != 0)
			return (60 + op);
		primary_ud = 0xdd0 + op;
		notif_ud = 0xde0 + op;
		slot = g_sqi & g_sqmask;
		iou_sqe((u8)op, 0, sv[0], 0,
		    op == IORING_OP_SEND_ZC ? (void *)"usage" : (void *)&mh,
		    op == IORING_OP_SEND_ZC ? 5 : 0, 0, primary_ud);
		g_sqes[slot].ioprio = IORING_SEND_ZC_REPORT_USAGE;
		g_sqes[slot].pad2[0] = notif_ud;
		if (iou_flush(1, 1) != 1)
			return (90 + op);
		n = iou_reap(c, 4);
		primary = notif = 0;
		for (i = 0; i < n; i++) {
			if (c[i].user_data == primary_ud &&
			    (c[i].flags & IORING_CQE_F_NOTIF) == 0) {
				if (c[i].res != -ELINUX_EPIPE ||
				    (c[i].flags & IORING_CQE_F_MORE) == 0)
					return (120 + op);
				primary = 1;
			} else if (c[i].user_data == notif_ud &&
			    (c[i].flags & IORING_CQE_F_NOTIF) != 0) {
				if ((u32)c[i].res != IORING_NOTIF_USAGE_ZC_COPIED)
					return (150 + op);
				notif = 1;
			}
		}
		if (n != 2 || !primary || !notif)
			return (180 + op);
		(void)sys1(SYS_close, sv[0]);
		(void)sys1(SYS_close, sv[1]);
	}
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0xdf0) != 0)
		return (220);
	return (0);
}
static int
t_link_timeout(void)
{
	struct cqe c[4];
	struct kts ts = { 1, 0 };
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	/* NOP (linked) -> LINK_TIMEOUT; the timeout is redundant (-ECANCELED) */
	iou_sqe(IORING_OP_NOP, IOSQE_IO_LINK, -1, 0, 0, 0, 0, 0x1);
	iou_sqe(IORING_OP_LINK_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x2);
	if (iou_flush(2, 2) != 2)
		return (2);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0x1, &res) || res != 0)
		return (3);
	if (!cqe_find(c, n, 0x2, &res) || res != -ELINUX_ECANCELED)
		return (4);
	return (0);
}
static int
t_futex_wake(void)
{
	static u32 word = 0;
	u32 slot;
	struct cqe c[2];
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	/* wake up to 1 waiter on a futex with none waiting -> 0 woken */
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_FUTEX_WAKE, 0, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
	    1 /* nr */, &word, 0, 0, 0x1);
	g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;	/* addr3 = mask */
	if (iou_flush(1, 1) != 1)
		return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res) || res != 0)
		return (3);
	return (0);
}
static int
t_futex_wait_eagain(void)
{
	static u32 word = 5;
	u32 slot;
	struct cqe c[2];
	int n, res = 0;
	if (ring_setup(8) < 0)
		return (1);
	/* wait expecting val 6 while *word==5 -> EAGAIN immediately */
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_FUTEX_WAIT, 0, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
	    6 /* val */, &word, 0, 0, 0x1);
	g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
	if (iou_flush(1, 1) != 1)
		return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res) || res != -EAGAIN)
		return (3);
	return (0);
}


/* Pending futex requests must return control to the submitter. */
static int
t_futex_wait_pending_wake(void)
{
    static u32 word;
    struct cqe c[4];
    u32 slot;
    int n, wait_res = 0, wake_res = 0;

    if (ring_setup(8) < 0)
        return (1);
    word = 0;
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_FUTEX_WAIT, 0,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0, &word, 0, 0, 0xd10);
    g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
    if (iou_flush(1, 0) != 1 || iou_reap(c, 4) != 0)
        return (2);
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_FUTEX_WAKE, 0,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 1, &word, 0, 0, 0xd11);
    g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
    if (iou_flush(1, 2) != 1)
        return (3);
    n = iou_reap(c, 4);
    if (n != 2 || !cqe_find(c, n, 0xd10, &wait_res) ||
        !cqe_find(c, n, 0xd11, &wake_res) ||
        wait_res != 0 || wake_res != 1)
        return (4);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
t_futex_wait_pending_cancel(void)
{
    static u32 word;
    struct cqe c[4];
    u32 slot;
    int n, wait_res = 0, cancel_res = 0;

    if (ring_setup(8) < 0)
        return (1);
    word = 0;
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_FUTEX_WAIT, 0,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0, &word, 0, 0, 0xd20);
    g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
    if (iou_flush(1, 0) != 1 || iou_reap(c, 4) != 0)
        return (2);
    iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0,
        (void *)(unsigned long)0xd20, 0, 0, 0xd21);
    if (iou_flush(1, 2) != 1)
        return (3);
    n = iou_reap(c, 4);
    if (n != 2 || !cqe_find(c, n, 0xd20, &wait_res) ||
        !cqe_find(c, n, 0xd21, &cancel_res) ||
        wait_res != -ELINUX_ECANCELED || cancel_res != 1) {
        put("FUTEX_CANCEL_DIAG "); putnum(n); put(" ");
        putnum(wait_res); put(" "); putnum(cancel_res); put("\n");
        return (4);
    }
    (void)sys1(SYS_close, fd_ring);
    return (0);
}


static int
t_futex_wait_mask_select(void)
{
    static u32 word;
    struct cqe c[4];
    u32 slot;
    int n, wait_res = -1, wake_res = -1, cancel_res = -1;

    if (ring_setup(8) < 0)
        return (1);
    word = 0;
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_FUTEX_WAIT, 0,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0, &word, 0, 0, 0xd60);
    g_sqes[slot].pad2[0] = 1;
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_FUTEX_WAIT, 0,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0, &word, 0, 0, 0xd61);
    g_sqes[slot].pad2[0] = 2;
    if (iou_flush(2, 0) != 2 || iou_reap(c, 4) != 0)
        return (2);
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_FUTEX_WAKE, 0,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 1, &word, 0, 0, 0xd62);
    g_sqes[slot].pad2[0] = 2;
    if (iou_flush(1, 2) != 1)
        return (3);
    n = iou_reap(c, 4);
    if (n != 2 || !cqe_find(c, n, 0xd61, &wait_res) ||
        !cqe_find(c, n, 0xd62, &wake_res) ||
        wait_res != 0 || wake_res != 1)
        return (4);
    iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0,
        (void *)(unsigned long)0xd60, 0, 0, 0xd63);
    if (iou_flush(1, 2) != 1)
        return (5);
    n = iou_reap(c, 4);
    if (n != 2 || !cqe_find(c, n, 0xd60, &wait_res) ||
        !cqe_find(c, n, 0xd63, &cancel_res) ||
        wait_res != -ELINUX_ECANCELED || cancel_res != 1)
        return (6);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
t_futex_waitv_pending_wake(void)
{
    static u32 words[2];
    struct l_futex_waitv wv[2];
    struct cqe c[4];
    u32 slot;
    int i, n, submitted, wait_res = -1, wake_res = -1;

    if (ring_setup(8) < 0)
        return (1);
    xmemset(words, 0, sizeof(words));
    xmemset(wv, 0, sizeof(wv));
    for (i = 0; i < 2; i++) {
        wv[i].uaddr = (u64)(unsigned long)&words[i];
        wv[i].flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
    }
    iou_sqe(IORING_OP_FUTEX_WAITV, 0, 0, 0, wv, 2, 0, 0xd30);
    submitted = iou_flush(1, 0);
    n = iou_reap(c, 4);
    if (submitted != 1 || n != 0) {
        put("FUTEX_WAITV_PREP_DIAG "); putnum(submitted);
        put(" "); putnum(n); put(" ");
        if (n > 0) putnum(c[0].res);
        put("\n");
        return (2);
    }
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_FUTEX_WAKE, 0,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 1, &words[1], 0, 0, 0xd31);
    g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
    if (iou_flush(1, 2) != 1)
        return (3);
    n = iou_reap(c, 4);
    if (n != 2 || !cqe_find(c, n, 0xd30, &wait_res) ||
        !cqe_find(c, n, 0xd31, &wake_res) ||
        wait_res != 1 || wake_res != 1)
        return (4);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
t_futex_waitv_pending_cancel(void)
{
    static u32 word;
    struct l_futex_waitv wv;
    struct cqe c[4];
    int n, submitted, wait_res = 0, cancel_res = 0;

    if (ring_setup(8) < 0)
        return (1);
    word = 0;
    xmemset(&wv, 0, sizeof(wv));
    wv.uaddr = (u64)(unsigned long)&word;
    wv.flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
    iou_sqe(IORING_OP_FUTEX_WAITV, 0, 0, 0, &wv, 1, 0, 0xd40);
    submitted = iou_flush(1, 0);
    n = iou_reap(c, 4);
    if (submitted != 1 || n != 0) {
        put("FUTEX_WAITV_CANCEL_PREP_DIAG "); putnum(submitted);
        put(" "); putnum(n); put(" ");
        if (n > 0) putnum(c[0].res);
        put("\n");
        return (2);
    }
    iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0,
        (void *)(unsigned long)0xd40, 0, 0, 0xd41);
    if (iou_flush(1, 2) != 1)
        return (3);
    n = iou_reap(c, 4);
    if (n != 2 || !cqe_find(c, n, 0xd40, &wait_res) ||
        !cqe_find(c, n, 0xd41, &cancel_res) ||
        wait_res != -ELINUX_ECANCELED || cancel_res != 1) {
        put("FUTEX_WAITV_CANCEL_DIAG "); putnum(n); put(" ");
        putnum(wait_res); put(" "); putnum(cancel_res); put("\n");
        return (4);
    }
    (void)sys1(SYS_close, fd_ring);
    return (0);
}


static int
t_futex_wait_external_wake(void)
{
    static u32 word;
    struct cqe c[2];
    u32 slot;
    int res;

    if (ring_setup(8) < 0)
        return (1);
    word = 0;
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_FUTEX_WAIT, 0,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0, &word, 0, 0, 0xd70);
    g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
    if (iou_flush(1, 0) != 1 || iou_reap(c, 2) != 0)
        return (2);
    if (futex_wake((int *)&word, 1) != 1)
        return (3);
    if (iou_flush(0, 1) != 0 || iou_reap(c, 2) != 1 ||
        !cqe_find(c, 1, 0xd70, &res) || res != 0)
        return (4);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
t_futex_wait_close_pending(void)
{
    static u32 word;
    struct cqe c[2];
    u32 slot;

    if (ring_setup(8) < 0)
        return (1);
    word = 0;
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_FUTEX_WAIT, 0,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0, &word, 0, 0, 0xd80);
    g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
    if (iou_flush(1, 0) != 1 || iou_reap(c, 2) != 0)
        return (2);
    if (sys1(SYS_close, fd_ring) != 0)
        return (3);
    if (sys2(SYS_munmap, g_sqes, g_sqes_map_len) != 0 ||
        sys2(SYS_munmap, g_sqbase, g_ring_map_len) != 0)
        return (4);
    sleep_ms(20);
    return (futex_wake((int *)&word, 1) == 0 ? 0 : 5);
}

static int
t_futex_waitv_bad_second_key(void)
{
    static u32 word;
    struct l_futex_waitv wv[2];
    struct cqe c[2];
    int res;

    if (ring_setup(8) < 0)
        return (1);
    word = 0;
    xmemset(wv, 0, sizeof(wv));
    wv[0].uaddr = (u64)(unsigned long)&word;
    wv[0].flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
    wv[1].uaddr = 0x1000;
    wv[1].flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
    iou_sqe(IORING_OP_FUTEX_WAITV, 0, 0, 0, wv, 2, 0, 0xd90);
    if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
        !cqe_find(c, 1, 0xd90, &res) || res != -EFAULT)
        return (2);
    if (futex_wake((int *)&word, 1) != 0)
        return (3);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
t_futex_wait_wake_cancel_race(void)
{
    static u32 word;
    struct cqe c[4];
    u32 slot;
    int i, n, wait_res, wake_res, cancel_res;

    for (i = 0; i < 32; i++) {
        if (ring_setup(8) < 0)
            return (1);
        word = 0;
        slot = g_sqi & g_sqmask;
        iou_sqe(IORING_OP_FUTEX_WAIT, 0,
            FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0, &word, 0, 0, 0xda0);
        g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
        if (iou_flush(1, 0) != 1 || iou_reap(c, 4) != 0)
            return (2);
        slot = g_sqi & g_sqmask;
        iou_sqe(IORING_OP_FUTEX_WAKE, 0,
            FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 1, &word, 0, 0, 0xda1);
        g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
        iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0,
            (void *)(unsigned long)0xda0, 0, 0, 0xda2);
        if (iou_flush(2, 3) != 2)
            return (3);
        n = iou_reap(c, 4);
        wait_res = wake_res = cancel_res = -999;
        if (n != 3 || !cqe_find(c, n, 0xda0, &wait_res) ||
            !cqe_find(c, n, 0xda1, &wake_res) ||
            !cqe_find(c, n, 0xda2, &cancel_res))
            return (4);
        if (!((wait_res == 0 && wake_res == 1 && cancel_res == -ENOENT) ||
            (wait_res == -ELINUX_ECANCELED && wake_res == 1 &&
            cancel_res == 1))) {
            put("FUTEX_RACE_DIAG "); putnum(i); put(" ");
            putnum(wait_res); put(" "); putnum(wake_res); put(" ");
            putnum(cancel_res); put("\n");
            return (5);
        }
        (void)sys1(SYS_close, fd_ring);
    }
    return (0);
}


static int
t_futex_wait_cancel_op_all(void)
{
    static u32 words[2];
    struct cqe c[4];
    u32 slot;
    int i, n, res = -999;

    if (ring_setup(8) < 0)
        return (1);
    for (i = 0; i < 2; i++) {
        words[i] = 0;
        slot = g_sqi & g_sqmask;
        iou_sqe(IORING_OP_FUTEX_WAIT, 0,
            FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0, &words[i], 0, 0,
            0xdb0 + i);
        g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
    }
    if (iou_flush(2, 0) != 2 || iou_reap(c, 4) != 0)
        return (2);
    iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, 0,
        IORING_OP_FUTEX_WAIT,
        IORING_ASYNC_CANCEL_OP | IORING_ASYNC_CANCEL_ALL, 0xdb2);
    if (iou_flush(1, 3) != 1)
        return (3);
    n = iou_reap(c, 4);
    if (n != 3 || !cqe_find(c, n, 0xdb2, &res) || res != 1) {
        put("FUTEX_OP_ALL_DIAG "); putnum(n); put(" "); putnum(res);
        for (int j = 0; j < n; j++) { put(" "); putnum(c[j].user_data);
            put(":"); putnum(c[j].res); }
        put("\n");
        return (4);
    }
    for (i = 0; i < 2; i++)
        if (!cqe_find(c, n, 0xdb0 + i, &res) ||
            res != -ELINUX_ECANCELED ||
            futex_wake((int *)&words[i], 1) != 0)
            return (5 + i);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
t_futex_wait_link_timeout(void)
{
    static u32 word;
    struct kts ts = { 0, 20000000 };
    struct cqe c[3];
    u32 slot;
    int n, res;

    if (ring_setup(8) < 0)
        return (1);
    word = 0;
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_FUTEX_WAIT, IOSQE_IO_LINK,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0, &word, 0, 0, 0xdc0);
    g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
    iou_sqe(IORING_OP_LINK_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0xdc1);
    if (iou_flush(2, 2) != 2)
        return (2);
    n = iou_reap(c, 3);
    if (n != 2 || !cqe_find(c, n, 0xdc0, &res) ||
        res != -ELINUX_ECANCELED ||
        !cqe_find(c, n, 0xdc1, &res) || res != 1) {
        put("FUTEX_LINK_TIMEOUT_DIAG "); putnum(n);
        for (int j = 0; j < n; j++) { put(" "); putnum(c[j].user_data);
            put(":"); putnum(c[j].res); }
        put("\n");
        return (3);
    }
    if (futex_wake((int *)&word, 1) != 0)
        return (4);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
t_futex_fixed_flag_ignored(void)
{
    static u32 word;
    char info[128];
    struct l_futex_waitv wv;
    struct cqe c[2];
    u32 slot;
    int i, res, expected;

    if (ring_setup(8) < 0)
        return (1);
    word = 0;
    xmemset(&wv, 0, sizeof(wv));
    xmemset(info, 0xa5, sizeof(info));
    wv.uaddr = (u64)(unsigned long)&word;
    wv.val = 1;
    wv.flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
    for (i = 0; i < 4; i++) {
        slot = g_sqi & g_sqmask;
        switch (i) {
        case 0:
            iou_sqe(IORING_OP_FUTEX_WAIT, IOSQE_FIXED_FILE,
                FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 1, &word, 0, 0, 0xdd0);
            g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
            expected = -EAGAIN;
            break;
        case 1:
            iou_sqe(IORING_OP_FUTEX_WAITV, IOSQE_FIXED_FILE,
                0, 0, &wv, 1, 0, 0xdd1);
            expected = -EAGAIN;
            break;
        case 2:
            iou_sqe(IORING_OP_FUTEX_WAKE, IOSQE_FIXED_FILE,
                FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 1, &word, 0, 0, 0xdd2);
            g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
            expected = 0;
            break;
        default:
            iou_sqe(IORING_OP_WAITID, IOSQE_FIXED_FILE, 0,
                (u64)(unsigned long)info, 0, LX_P_ALL, 0, 0xdd3);
            g_sqes[slot].splice_fd_in = LX_WEXITED | LX_WNOHANG;
            expected = -ELINUX_ECHILD;
            break;
        }
        if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
            !cqe_find(c, 1, 0xdd0 + i, &res))
            return (2);
        if (res != expected) {
            put("FUTEX_FIXED_DIAG "); putnum(i); put(" ");
            putnum(res); put("\n");
            return (3);
        }
    }
    (void)sys1(SYS_close, fd_ring);
    return (0);
}
static int
t_futex_sqe_badfields(void)
{
    static u32 word = 5;
    struct l_futex_waitv wv;
    struct cqe c[2];
    u32 slot;
    u8 op;
    int which, field, maxfield, fd, len, res, n;
    u64 off, addr;

    if (ring_setup(32) < 0)
        return (1);
    xmemset(&wv, 0, sizeof(wv));
    wv.val = 6;
    wv.uaddr = (u64)(unsigned long)&word;
    wv.flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
    for (which = 0; which < 3; which++) {
        op = which == 0 ? IORING_OP_FUTEX_WAIT :
            which == 1 ? IORING_OP_FUTEX_WAKE : IORING_OP_FUTEX_WAITV;
        maxfield = which == 2 ? 7 : 4;
        for (field = 0; field < maxfield; field++) {
            slot = g_sqi & g_sqmask;
            fd = which == 2 ? 0 : FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
            len = which == 2 ? 1 : 0;
            off = which == 0 ? 6 : which == 1 ? 1 : 0;
            addr = (u64)(unsigned long)(which == 2 ? (void *)&wv :
                (void *)&word);
            iou_sqe(op, 0, fd, off, (void *)(unsigned long)addr,
                len, 0, 0xd50 + which * 8 + field);
            if (which != 2)
                g_sqes[slot].pad2[0] = FUTEX_BITSET_ANY;
            if (field == 0) g_sqes[slot].len = which == 2 ? 0 : 1;
            if (field == 1) g_sqes[slot].rw_flags = 1;
            if (field == 2) g_sqes[slot].buf_index = 1;
            if (field == 3) g_sqes[slot].splice_fd_in = 1;
            if (field == 4) g_sqes[slot].fd = -1;
            if (field == 5) g_sqes[slot].off = 1;
            if (field == 6) g_sqes[slot].pad2[0] = 1;
            if (iou_flush(1, 1) != 1)
                return (2);
            n = iou_reap(c, 2);
            res = 0;
            if (n != 1 || !cqe_find(c, n,
                0xd50 + which * 8 + field, &res) || res != -EINVAL) {
                put("FUTEX_SQE_BADFIELDS_DIAG "); putnum(which);
                put(" "); putnum(field); put(" "); putnum(res);
                put("\n");
                return (3);
            }
        }
    }
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

/* ================= extra errno constants (Linux values) ================= */
#define	ELINUX_EEXIST		17
#define	ELINUX_EISDIR		21
#define	ELINUX_ENOTEMPTY	39
#define	ELINUX_EFBIG		27

/* ================= setup rounding matrix ================= */
static int
setup_rounds(u32 entries, u32 want_sq)
{
	struct params p;
	long fd;
	xmemset(&p, 0, sizeof(p));
	fd = setup(entries, &p);
	if (fd < 0)
		return (2);
	(void)sys1(SYS_close, fd);
	return (p.sq_entries == want_sq && p.cq_entries == want_sq * 2 ? 0 : 3);
}
static int t_setup_2(void)    { return setup_rounds(2, 2); }
static int t_setup_3(void)    { return setup_rounds(3, 4); }
static int t_setup_7(void)    { return setup_rounds(7, 8); }
static int t_setup_16(void)   { return setup_rounds(16, 16); }
static int t_setup_17(void)   { return setup_rounds(17, 32); }
static int t_setup_64(void)   { return setup_rounds(64, 64); }
static int t_setup_1000(void) { return setup_rounds(1000, 1024); }
static int t_setup_4096(void) { return setup_rounds(4096, 4096); }
static int t_setup_32768(void){ return setup_rounds(32768, 32768); }
static int
t_setup_resv0(void)
{
	struct params p;
	xmemset(&p, 0, sizeof(p));
	p.resv[0] = 1;
	return (setup(8, &p) == -EINVAL ? 0 : 1);
}
static int
t_setup_resv2(void)
{
	struct params p;
	xmemset(&p, 0, sizeof(p));
	p.resv[2] = 0xdead;
	return (setup(8, &p) == -EINVAL ? 0 : 1);
}
static int
t_setup_flag_iopoll(void)
{
	struct params p;
	xmemset(&p, 0, sizeof(p));
	p.flags = 1;			/* IORING_SETUP_IOPOLL, not honored */
	return (setup(8, &p) == -EINVAL ? 0 : 1);
}
static int
t_setup_flag_sqpoll(void)
{
	struct params p;
	long fd;

	xmemset(&p, 0, sizeof(p));
	p.flags = 2;			/* IORING_SETUP_SQPOLL */
	fd = setup(8, &p);
	if (fd < 0)
		return (1);
	(void)sys1(SYS_close, fd);
	return (p.sq_entries == 8 ? 0 : 2);
}

/* ================= per-opcode bad-fd error paths ================= */
static int t_writev_badfd(void)
{
	struct iovec iov;
	if (ring_setup(8) < 0) return (1);
	iov.iov_base = "x"; iov.iov_len = 1;
	return (sub1(9999, IORING_OP_WRITEV, &iov, 1, 0, 0, 0x1) == -EBADF ? 0 : 2);
}
static int t_readv_badfd(void)
{
	struct iovec iov; char b[4];
	if (ring_setup(8) < 0) return (1);
	iov.iov_base = b; iov.iov_len = 4;
	return (sub1(9999, IORING_OP_READV, &iov, 1, 0, 0, 0x1) == -EBADF ? 0 : 2);
}
static int t_shutdown_badfd(void)
{
	if (ring_setup(8) < 0) return (1);
	return (sub1(9999, IORING_OP_SHUTDOWN, 0, 2, 0, 0, 0x1) == -EBADF ? 0 : 2);
}
static int t_listen_badfd(void)
{
	if (ring_setup(8) < 0) return (1);
	return (sub1(9999, IORING_OP_LISTEN, 0, 8, 0, 0, 0x1) == -EBADF ? 0 : 2);
}
static int t_send_badfd(void)
{
	if (ring_setup(8) < 0) return (1);
	return (sub1(9999, IORING_OP_SEND, "x", 1, 0, 0, 0x1) == -EBADF ? 0 : 2);
}
static int t_recv_badfd(void)
{
	char b[4];
	if (ring_setup(8) < 0) return (1);
	return (sub1(9999, IORING_OP_RECV, b, 4, 0, 0, 0x1) == -EBADF ? 0 : 2);
}
static int t_sync_file_range_badfd(void)
{
	if (ring_setup(8) < 0) return (1);
	return (sub1(9999, IORING_OP_SYNC_FILE_RANGE, 0, 0, 0, 0, 0x1) == -EBADF ? 0 : 2);
}

/* ================= EFAULT paths ================= */
static int t_readv_badptr(void)
{
	if (ring_setup(8) < 0) return (1);
	/* iovec array pointer unmapped -> copyinuio EFAULT */
	return (sub1(0, IORING_OP_READV, (void *)0x10, 1, 0, 0, 0x1) == -EFAULT ? 0 : 2);
}
static int t_writev_badptr(void)
{
	if (ring_setup(8) < 0) return (1);
	return (sub1(1, IORING_OP_WRITEV, (void *)0x10, 1, 0, 0, 0x1) == -EFAULT ? 0 : 2);
}
static int t_openat_badpath(void)
{
	int r;
	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_OPENAT, 0, LX_AT_FDCWD, 0, (void *)0x10, 0600,
	    LX_O_RDWR | LX_O_CREAT, 0x1);
	{ struct cqe c[2]; int n; if (iou_flush(1,1)!=1) return (2);
	  n = iou_reap(c,2); if (n!=1 || !cqe_find(c,n,0x1,&r)) return (3); }
	return (r == -EFAULT ? 0 : 4);
}
static int t_statx_badbuf(void)
{
	long tf; int r;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_sxb"); if (tf < 0) return (2);
	(void)sys1(SYS_close, tf);
	/* statxbuf(addr2/off) unmapped -> EFAULT */
	iou_sqe(IORING_OP_STATX, 0, LX_AT_FDCWD, 0x10 /* buf */, "iou_sxb",
	    STATX_BASIC_STATS, 0, 0x1);
	{ struct cqe c[2]; int n; if (iou_flush(1,1)!=1) return (3);
	  n = iou_reap(c,2); if (n!=1 || !cqe_find(c,n,0x1,&r)) return (4); }
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_sxb", 0);
	return (r == -EFAULT ? 0 : 5);
}

/* ================= filesystem error paths ================= */
static int t_mkdirat_eexist(void)
{
	int r;
	if (ring_setup(8) < 0) return (1);
	(void)call(SYS_unlinkat, LX_AT_FDCWD, (long)"iou_de", LX_AT_REMOVEDIR, 0, 0, 0);
	if (sub1(LX_AT_FDCWD, IORING_OP_MKDIRAT, "iou_de", 0755, 0, 0, 0x1) != 0)
		return (2);
	r = sub1(LX_AT_FDCWD, IORING_OP_MKDIRAT, "iou_de", 0755, 0, 0, 0x2);
	(void)call(SYS_unlinkat, LX_AT_FDCWD, (long)"iou_de", LX_AT_REMOVEDIR, 0, 0, 0);
	return (r == -ELINUX_EEXIST ? 0 : 3);
}
static int t_symlinkat_eexist(void)
{
	long tf; int r;
	if (ring_setup(8) < 0) return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_sle", 0);
	tf = tmpfile_fd("iou_sle"); if (tf < 0) return (2);
	(void)sys1(SYS_close, tf);
	iou_sqe(IORING_OP_SYMLINKAT, 0, LX_AT_FDCWD, (u64)(unsigned long)"iou_sle",
	    "target", 0, 0, 0x1);
	{ struct cqe c[2]; int n; if (iou_flush(1,1)!=1) return (3);
	  n = iou_reap(c,2); if (n!=1 || !cqe_find(c,n,0x1,&r)) return (4); }
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_sle", 0);
	return (r == -ELINUX_EEXIST ? 0 : 5);
}
static int t_renameat_enoent(void)
{
	int r;
	if (ring_setup(8) < 0) return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_rne", 0);
	iou_sqe(IORING_OP_RENAMEAT, 0, LX_AT_FDCWD, (u64)(unsigned long)"iou_rne2",
	    "iou_rne", LX_AT_FDCWD, 0, 0x1);
	{ struct cqe c[2]; int n; if (iou_flush(1,1)!=1) return (2);
	  n = iou_reap(c,2); if (n!=1 || !cqe_find(c,n,0x1,&r)) return (3); }
	return (r == -ENOENT ? 0 : 4);
}
static int t_statx_enoent(void)
{
	static char sx[256]; int r;
	if (ring_setup(8) < 0) return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_sxe", 0);
	iou_sqe(IORING_OP_STATX, 0, LX_AT_FDCWD, (u64)(unsigned long)sx,
	    "iou_sxe", STATX_BASIC_STATS, 0, 0x1);
	{ struct cqe c[2]; int n; if (iou_flush(1,1)!=1) return (2);
	  n = iou_reap(c,2); if (n!=1 || !cqe_find(c,n,0x1,&r)) return (3); }
	return (r == -ENOENT ? 0 : 4);
}
static int t_unlinkat_isdir(void)
{
	int r;
	if (ring_setup(8) < 0) return (1);
	(void)call(SYS_unlinkat, LX_AT_FDCWD, (long)"iou_ud", LX_AT_REMOVEDIR, 0, 0, 0);
	if (sub1(LX_AT_FDCWD, IORING_OP_MKDIRAT, "iou_ud", 0755, 0, 0, 0x1) != 0)
		return (2);
	/* unlink (no REMOVEDIR) a directory -> EISDIR */
	r = sub1(LX_AT_FDCWD, IORING_OP_UNLINKAT, "iou_ud", 0, 0, 0, 0x2);
	(void)call(SYS_unlinkat, LX_AT_FDCWD, (long)"iou_ud", LX_AT_REMOVEDIR, 0, 0, 0);
	return (r == -ELINUX_EISDIR ? 0 : 3);
}

/* ================= ring mechanics ================= */
static int t_submit_partial(void)
{
	struct cqe c[8]; int i, n;
	if (ring_setup(8) < 0) return (1);
	for (i = 0; i < 5; i++) iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x10 + i);
	if (iou_flush(3, 3) != 3) return (2);		/* submit only 3 */
	n = iou_reap(c, 8); if (n != 3) return (3);
	if (iou_flush(2, 2) != 2) return (4);		/* submit the rest */
	n = iou_reap(c, 8); if (n != 2) return (5);
	return (0);
}
static int t_submit_zero_queued(void)
{
	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x1);
	__atomic_store_n(g_sq_tail, g_sqi, __ATOMIC_RELEASE);
	if (call(SYS_io_uring_enter, fd_ring, 0, 0, IORING_ENTER_GETEVENTS, 0, 0) != 0)
		return (2);
	if (__atomic_load_n(g_cq_tail, __ATOMIC_ACQUIRE) != 0) return (3);
	return (0);
}
static int t_reap_no_wait(void)
{
	struct cqe c[2]; int n, res;
	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x1);
	__atomic_store_n(g_sq_tail, g_sqi, __ATOMIC_RELEASE);
	if (call(SYS_io_uring_enter, fd_ring, 1, 0, 0, 0, 0) != 1) return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res) || res != 0) return (3);
	return (0);
}
static int t_cq_exactly_full(void)
{
	int b, i;
	if (ring_setup(8) < 0) return (1);		/* cq = 16 */
	for (b = 0; b < 2; b++) {
		for (i = 0; i < 8; i++) iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 1);
		if (iou_flush(8, 0) != 8) return (2);
	}
	if (__atomic_load_n(g_cq_overflow, __ATOMIC_ACQUIRE) != 0) return (3);
	if (__atomic_load_n(g_cq_tail, __ATOMIC_ACQUIRE) != 16) return (4);
	return (0);
}
static int t_min_complete_two(void)
{
	struct cqe c[8]; int i, n;
	if (ring_setup(8) < 0) return (1);
	for (i = 0; i < 4; i++) iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x20 + i);
	if (iou_flush(4, 2) != 4) return (2);
	n = iou_reap(c, 8); if (n != 4) return (3);
	return (0);
}
static int t_sq_dropped_many(void)
{
	struct cqe c;
	int i;

	if (ring_setup(8) < 0) return (1);
	for (i = 0; i < 3; i++) { g_sq_array[i] = 999; g_sqi++; }
	__atomic_store_n(g_sq_tail, g_sqi, __ATOMIC_RELEASE);
	/* Each bad index is dropped, ends this batch, and submits no SQE. */
	for (i = 0; i < 3; i++) {
		if (call(SYS_io_uring_enter, fd_ring, 3 - i, 0, 0, 0, 0) != 0)
			return (2);
		if (__atomic_load_n(g_sq_dropped, __ATOMIC_ACQUIRE) != (u32)i + 1 ||
		    __atomic_load_n(g_sq_head, __ATOMIC_ACQUIRE) != (u32)i + 1)
			return (3);
		if (__atomic_load_n(g_cq_tail, __ATOMIC_ACQUIRE) != 0) return (4);
	}
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x51);
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != 0x51 || c.res != 0)
		return (5);
	return (0);
}
static int t_large_ring(void)
{
	struct cqe c[8]; int b, i, n;
	if (ring_setup(4096) < 0) return (1);
	for (b = 0; b < 16; b++) {
		for (i = 0; i < 8; i++) iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 1);
		if (iou_flush(8, 8) != 8) return (2);
		n = iou_reap(c, 8); if (n != 8) return (3);
	}
	return (0);
}

/* ================= link / cancel / timeout matrices ================= */
static int t_link_chain5(void)
{
	struct cqe c[8]; int i, n, res;
	if (ring_setup(8) < 0) return (1);
	for (i = 0; i < 5; i++)
		iou_sqe(IORING_OP_NOP, i < 4 ? IOSQE_IO_LINK : 0, -1, 0, 0, 0, 0, 0x1 + i);
	if (iou_flush(5, 5) != 5) return (2);
	n = iou_reap(c, 8); if (n != 5) return (3);
	for (i = 0; i < 5; i++) if (!cqe_find(c, n, 0x1 + i, &res) || res != 0) return (4);
	return (0);
}
static int t_link_fail_middle(void)
{
	struct cqe c[8]; char rb[4]; int n, res;
	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_NOP, IOSQE_IO_LINK, -1, 0, 0, 0, 0, 0x1);
	iou_sqe(IORING_OP_READ, IOSQE_IO_LINK, 9999, 0, rb, 4, 0, 0x2);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x3);
	if (iou_flush(3, 3) != 3) return (2);
	n = iou_reap(c, 8);
	if (!cqe_find(c, n, 0x1, &res) || res != 0) return (3);
	if (!cqe_find(c, n, 0x2, &res) || res != -EBADF) return (4);
	if (!cqe_find(c, n, 0x3, &res) || res != -ELINUX_ECANCELED) return (5);
	return (0);
}
static int t_hardlink_all(void)
{
	struct cqe c[8]; char rb[4]; int n, res;
	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_NOP, IOSQE_IO_HARDLINK, -1, 0, 0, 0, 0, 0x1);
	iou_sqe(IORING_OP_READ, IOSQE_IO_HARDLINK, 9999, 0, rb, 4, 0, 0x2);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x3);
	if (iou_flush(3, 3) != 3) return (2);
	n = iou_reap(c, 8);
	if (!cqe_find(c, n, 0x1, &res) || res != 0) return (3);
	if (!cqe_find(c, n, 0x2, &res) || res != -EBADF) return (4);
	if (!cqe_find(c, n, 0x3, &res) || res != 0) return (5);
	return (0);
}
static int t_cqe_skip_middle(void)
{
	struct cqe c[8]; int n, res;
	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_NOP, IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS, -1, 0, 0, 0, 0, 0x1);
	iou_sqe(IORING_OP_NOP, IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS, -1, 0, 0, 0, 0, 0x2);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x3);
	if (iou_flush(3, 1) != 3) return (2);
	n = iou_reap(c, 8);
	if (n != 1 || c[0].user_data != 0x3ULL) return (3);
	if (cqe_find(c, n, 0x1, &res) || cqe_find(c, n, 0x2, &res)) return (4);
	return (0);
}
static int t_link_plus_independent(void)
{
	struct cqe c[8]; int n, res, i;
	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_NOP, IOSQE_IO_LINK, -1, 0, 0, 0, 0, 0x1);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x2);	/* end of chain */
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x3);	/* independent */
	if (iou_flush(3, 3) != 3) return (2);
	n = iou_reap(c, 8); if (n != 3) return (3);
	for (i = 1; i <= 3; i++) if (!cqe_find(c, n, i, &res) || res != 0) return (4);
	return (0);
}
static int t_two_timeouts_fire(void)
{
	struct cqe c[4]; struct kts ts; int n, res;
	if (ring_setup(8) < 0) return (1);
	ts.tv_sec = 0; ts.tv_nsec = 20000000LL;
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x2);
	if (iou_flush(2, 2) != 2) return (2);
	n = iou_reap(c, 4); if (n != 2) return (3);
	if (!cqe_find(c, n, 0x1, &res) || res != -ELINUX_ETIME) return (4);
	if (!cqe_find(c, n, 0x2, &res) || res != -ELINUX_ETIME) return (5);
	return (0);
}
static int t_timeout_count5(void)
{
	struct cqe c[8]; struct kts ts; int i, n, res;
	if (ring_setup(8) < 0) return (1);
	ts.tv_sec = 30; ts.tv_nsec = 0;
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 5, &ts, 1, 0, 0x1);
	if (iou_flush(1, 0) != 1) return (2);
	for (i = 0; i < 5; i++) iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x100 + i);
	if (iou_flush(5, 6) != 5) return (3);
	n = iou_reap(c, 8);
	if (!cqe_find(c, n, 0x1, &res) || res != 0) return (4);
	return (0);
}
static int t_cancel_one_of_two(void)
{
	struct cqe c[4]; struct kts ts; int n, res;
	if (ring_setup(8) < 0) return (1);
	ts.tv_sec = 30; ts.tv_nsec = 0;
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0xA1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0xA2);
	if (iou_flush(2, 0) != 2) return (2);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0xA1, 0, 0, 0xC1);
	if (iou_flush(1, 2) != 1) return (3);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xC1, &res) || res != 0) return (4);
	if (!cqe_find(c, n, 0xA1, &res) || res != -ELINUX_ECANCELED) return (5);
	return (0);
}
static int t_cancel_all_three(void)
{
	struct cqe c[8]; struct kts ts; int n, res, i, cc = 0;
	if (ring_setup(8) < 0) return (1);
	ts.tv_sec = 30; ts.tv_nsec = 0;
	for (i = 0; i < 3; i++) iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x77);
	if (iou_flush(3, 0) != 3) return (2);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0x77, 0,
	    IORING_ASYNC_CANCEL_ALL, 0xC2);
	if (iou_flush(1, 4) != 1) return (3);
	n = iou_reap(c, 8); if (n != 4) return (4);
	if (!cqe_find(c, n, 0xC2, &res) || res != 3) return (5);
	for (i = 0; i < n; i++) if (c[i].user_data == 0x77ULL && c[i].res == -ELINUX_ECANCELED) cc++;
	return (cc == 3 ? 0 : 6);
}
static int t_timeout_remove_notfound(void)
{
	if (ring_setup(8) < 0) return (1);
	return (sub1(-1, IORING_OP_TIMEOUT_REMOVE, (void *)0xDEAD, 0, 0, 0, 0x1)
	    == -ENOENT ? 0 : 2);
}

/* ================= registered files depth ================= */
static int t_reg_files_sparse(void)
{
	long tf0, tf2; char rb[8]; int fds[3], res;
	if (ring_setup(8) < 0) return (1);
	tf0 = tmpfile_fd("iou_sp0"); tf2 = tmpfile_fd("iou_sp2");
	if (tf0 < 0 || tf2 < 0) return (2);
	if (sub1(tf2, IORING_OP_WRITE, "sparse!!", 8, 0, 0, 0x1) != 8) return (3);
	fds[0] = (int)tf0; fds[1] = -1; fds[2] = (int)tf2;
	if (iou_reg(IORING_REGISTER_FILES, fds, 3) != 0) return (4);
	(void)sys1(SYS_close, tf0); (void)sys1(SYS_close, tf2);
	/* index 1 is sparse -> EBADF */
	if (fixed_op(IORING_OP_READ, 1, rb, 8, 0, 0, IOSQE_FIXED_FILE, 0x2) != -EBADF)
		return (5);
	xmemset(rb, 0, sizeof(rb));
	res = fixed_op(IORING_OP_READ, 2, rb, 8, 0, 0, IOSQE_FIXED_FILE, 0x3);
	if (res != 8 || xmemcmp(rb, "sparse!!", 8) != 0) return (6);
	return (0);
}
static int t_reg_files_badfd(void)
{
	int fds[1];
	if (ring_setup(8) < 0) return (1);
	fds[0] = 9999;
	return (iou_reg(IORING_REGISTER_FILES, fds, 1) == -EBADF ? 0 : 2);
}
static int t_fixed_fsync(void)
{
	long tf; int fds[1], res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_ffs"); if (tf < 0) return (2);
	if (sub1(tf, IORING_OP_WRITE, "abc", 3, 0, 0, 0x1) != 3) return (3);
	fds[0] = (int)tf;
	if (iou_reg(IORING_REGISTER_FILES, fds, 1) != 0) return (4);
	res = fixed_op(IORING_OP_FSYNC, 0, 0, 0, 0, 0, IOSQE_FIXED_FILE, 0x2);
	(void)sys1(SYS_close, tf);
	return (res == 0 ? 0 : 5);
}
static int t_files_update_oob(void)
{
	long tf; struct files_update up; int fds[1];
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_fuo"); if (tf < 0) return (2);
	fds[0] = (int)tf;
	if (iou_reg(IORING_REGISTER_FILES, fds, 1) != 0) return (3);
	xmemset(&up, 0, sizeof(up)); up.offset = 5; up.fds = (u64)(unsigned long)fds;
	(void)sys1(SYS_close, tf);
	return (iou_reg(IORING_REGISTER_FILES_UPDATE, &up, 1) == -EINVAL ? 0 : 4);
}

/* ================= registered buffers depth ================= */
static int t_read_fixed_offset(void)
{
	static char buf[4096]; struct iovec iov; long tf; int res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_rfo"); if (tf < 0) return (2);
	iov.iov_base = buf; iov.iov_len = sizeof(buf);
	if (iou_reg(IORING_REGISTER_BUFFERS, &iov, 1) != 0) return (3);
	buf[2000] = 'Z';
	res = fixed_op(IORING_OP_WRITE_FIXED, (int)tf, buf + 2000, 1, 0, 0, 0, 0x1);
	if (res != 1) return (4);
	buf[2000] = 0;
	res = fixed_op(IORING_OP_READ_FIXED, (int)tf, buf + 2000, 1, 0, 0, 0, 0x2);
	(void)sys1(SYS_close, tf);
	return (res == 1 && buf[2000] == 'Z' ? 0 : 5);
}
static int t_read_fixed_boundary(void)
{
	static char buf[4096]; struct iovec iov; long tf; int res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_rfb2"); if (tf < 0) return (2);
	iov.iov_base = buf; iov.iov_len = sizeof(buf);
	if (iou_reg(IORING_REGISTER_BUFFERS, &iov, 1) != 0) return (3);
	/* exactly to the end of the registered buffer: ok */
	res = fixed_op(IORING_OP_WRITE_FIXED, (int)tf, buf + 4090, 6, 0, 0, 0, 0x1);
	(void)sys1(SYS_close, tf);
	return (res == 6 ? 0 : 4);
}
static int t_read_fixed_onepast(void)
{
	static char buf[4096]; struct iovec iov; long tf; int res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_rf1"); if (tf < 0) return (2);
	iov.iov_base = buf; iov.iov_len = sizeof(buf);
	if (iou_reg(IORING_REGISTER_BUFFERS, &iov, 1) != 0) return (3);
	/* one past the end -> EFAULT */
	res = fixed_op(IORING_OP_READ_FIXED, (int)tf, buf + 4094, 4, 0, 0, 0, 0x1);
	(void)sys1(SYS_close, tf);
	return (res == -EFAULT ? 0 : 4);
}
static int t_reg_buffers_zero(void)
{
	if (ring_setup(8) < 0) return (1);
	return (iou_reg(IORING_REGISTER_BUFFERS, (void *)0x1000, 0) == -EINVAL ? 0 : 2);
}

/* ================= provided buffers depth ================= */
static int t_provided_two_groups(void)
{
	static char p1[128], p2[128]; struct cqe c[2]; long tf; int res;
	if (ring_setup(8) < 0) return (1);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 2, 0, p1, 64, 1, 0x1, c) != 0) return (2);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 2, 0, p2, 64, 2, 0x2, c) != 0) return (3);
	tf = tmpfile_fd("iou_2g"); if (tf < 0) return (4);
	if (sub1(tf, IORING_OP_WRITE, "GG", 2, 0, 0, 0x3) != 2) return (5);
	if (grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, (int)tf, 0, 0, 64, 2, 0x4, c) != 0)
		return (6);
	res = c[0].res;
	(void)sys1(SYS_close, tf);
	if (res != 2) return (7);
	if ((c[0].flags & IORING_CQE_F_BUFFER) == 0) return (8);
	return (0);
}
static int t_provided_consume_all(void)
{
	static char pool[128]; struct cqe c[2]; long tf; int i, res;
	if (ring_setup(8) < 0) return (1);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 2, 0, pool, 64, 5, 0x1, c) != 0) return (2);
	tf = tmpfile_fd("iou_ca"); if (tf < 0) return (3);
	if (sub1(tf, IORING_OP_WRITE, "x", 1, 0, 0, 0x2) != 1) return (4);
	for (i = 0; i < 2; i++) {
		if (grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, (int)tf, 0, 0, 1, 5, 0x10 + i, c) != 0)
			return (5);
		if (c[0].res != 1) return (6);
	}
	/* third select: group empty -> ENOBUFS */
	if (grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, (int)tf, 0, 0, 1, 5, 0x20, c) != 0)
		return (7);
	res = c[0].res;
	(void)sys1(SYS_close, tf);
	return (res == -ELINUX_ENOBUFS ? 0 : 8);
}
static int t_provided_remove_excess(void)
{
	static char pool[256]; struct cqe c[2];
	if (ring_setup(8) < 0) return (1);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 4, 0, pool, 64, 6, 0x1, c) != 0) return (2);
	if (grp_op(IORING_OP_REMOVE_BUFFERS, 0, 100, 0, 0, 0, 6, 0x2, c) != 0) return (3);
	return (c[0].res == 4 ? 0 : 4);
}
static int t_provided_recv_select(void)
{
	static char pool[128]; struct cqe c[2]; int sv[2], res;
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 2, 0, pool, 64, 8, 0x1, c) != 0) return (3);
	if (sub1(sv[0], IORING_OP_SEND, "recvsel", 7, 0, 0, 0x2) != 7) return (4);
	if (grp_op(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 64, 8, 0x3, c) != 0)
		return (5);
	res = c[0].res;
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (res != 7) return (6);
	if ((c[0].flags & IORING_CQE_F_BUFFER) == 0) return (7);
	if (xmemcmp(pool, "recvsel", 7) != 0) return (8);
	return (0);
}
static int t_provided_readv_select(void)
{
	static char pool[64]; struct cqe c[2]; struct iovec iov[2]; long tf;
	if (ring_setup(8) < 0) return (1);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 1, 21, pool, 64, 9, 0x1, c) != 0) return (2);
	tf = tmpfile_fd("iou_pbrv"); if (tf < 0) return (3);
	if (sub1(tf, IORING_OP_WRITE, "readvector", 10, 0, 0, 0x2) != 10) return (4);
	iov[0].iov_base = (void *)1; iov[0].iov_len = 4;
	iov[1] = iov[0];
	/* READV+BUFFER_SELECT accepts exactly one iovec and copies it in at prep. */
	if (grp_op(IORING_OP_READV, IOSQE_BUFFER_SELECT, (int)tf, 0, iov, 2, 9, 0x3, c) != 0) return (5);
	if (c[0].res != -EINVAL) return (6);
	if (grp_op(IORING_OP_READV, IOSQE_BUFFER_SELECT, (int)tf, 0, (void *)1, 1, 9, 0x4, c) != 0) return (7);
	if (c[0].res != -EFAULT) return (8);
	if (grp_op(IORING_OP_READV, IOSQE_BUFFER_SELECT, (int)tf, 0, iov, 1, 9, 0x5, c) != 0) return (9);
	(void)sys1(SYS_close, tf);
	if (c[0].res != 4 || (c[0].flags & IORING_CQE_F_BUFFER) == 0) return (10);
	if ((c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 21) return (11);
	return (xmemcmp(pool, "read", 4) == 0 ? 0 : 12);
}
static int t_provided_send_select(void)
{
	static char pool[64]; struct cqe c[2]; int sv[2]; char rb[64];
	xmemset(pool, 0, sizeof(pool)); xmemcpy(pool, "sendbuf", 7);
	if (ring_setup(8) < 0) return (1);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 1, 5, pool, 64, 10, 0x1, c) != 0) return (2);
	/* EBADF wins before selection, so the buffer remains available. */
	if (grp_op(IORING_OP_SEND, IOSQE_BUFFER_SELECT, -1, 0, 0, 7, 10, 0x2, c) != 0) return (3);
	if (c[0].res != -EBADF) return (4);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0) return (5);
	if (grp_op(IORING_OP_SEND, IOSQE_BUFFER_SELECT, sv[0], 0, 0, 7, 10, 0x3, c) != 0) return (6);
	/* Linux consumes and sends the complete selected legacy buffer. */
	if (c[0].res != 64) return (7);
	if ((c[0].flags & IORING_CQE_F_BUFFER) == 0) return (8);
	if ((c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 5) return (9);
	if (sys3(SYS_read, sv[1], (long)rb, sizeof(rb)) != (long)sizeof(rb) ||
	    xmemcmp(rb, "sendbuf", 7) != 0) return (10);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]); return (0);
}
static int t_provided_recvmsg_select(void)
{
	static char pool[64]; struct cqe c[2]; struct l_msghdr mh;
	struct iovec iov[2]; int sv[2]; char ignored[8];
	if (ring_setup(8) < 0) return (1);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 1, 8, pool, 64, 11, 0x1, c) != 0) return (2);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0) return (3);
	xmemset(&mh, 0, sizeof(mh)); iov[0].iov_base = ignored; iov[0].iov_len = 4; iov[1] = iov[0];
	mh.msg_iov = (u64)(unsigned long)iov; mh.msg_iovlen = 2;
	if (grp_op(IORING_OP_RECVMSG, IOSQE_BUFFER_SELECT, sv[1], 0, &mh, 0, 11, 0x2, c) != 0) return (4);
	if (c[0].res != -EINVAL) return (5);
	if (sys3(SYS_write, sv[0], (long)"message", 7) != 7) return (6);
	mh.msg_iovlen = 1;
	if (grp_op(IORING_OP_RECVMSG, IOSQE_BUFFER_SELECT, sv[1], 0, &mh, 0, 11, 0x3, c) != 0) return (7);
	if (c[0].res != 4 || (c[0].flags & IORING_CQE_F_BUFFER) == 0 ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 8) return (8);
	if (xmemcmp(pool, "mess", 4) != 0 || sys3(SYS_read, sv[1], (long)ignored, 3) != 3 ||
	    xmemcmp(ignored, "age", 3) != 0) return (9);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]); return (0);
}

/* ================= opcode sweep ================= */
static int sweep_einval(u8 op)
{
	int res;
	if (ring_setup(8) < 0) return (1);
	res = sub1(-1, op, 0, 0, 0, 0, 0x1);
	if (res != -EINVAL) return (2);
	/* ring still healthy */
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0x2) != 0) return (3);
	return (0);
}
static int t_opcode_65(void)  { return sweep_einval(65); }
static int t_opcode_100(void) { return sweep_einval(100); }
static int t_opcode_200(void) { return sweep_einval(200); }
static int t_opcode_255(void) { return sweep_einval(255); }
static int
uring_sockcmd(int fd, u32 cmd, u32 level, u32 optname, void *optval,
    u32 optlen, u32 flags)
{
    struct cqe c[2];
    u32 slot;
    int res;

    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_URING_CMD, 0, fd, cmd, 0, 0, flags, 0xc001);
    g_sqes[slot].addr = (u64)level | ((u64)optname << 32);
    g_sqes[slot].splice_fd_in = (int)optlen;
    g_sqes[slot].pad2[0] = (u64)(unsigned long)optval;
    if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
        !cqe_find(c, 1, 0xc001, &res))
        return (-100000);
    return (res);
}

static int
t_uring_cmd_socket(void)
{
    int sv[2], val, res;
    long tf;
    char buf[8];
    struct probe pr;

    if (ring_setup(8) < 0) return (1);
    xmemset(&pr, 0, sizeof(pr));
    if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PROBE,
        (long)&pr, 128, 0, 0) != 0 ||
        (pr.ops[IORING_OP_URING_CMD].flags & IO_URING_OP_SUPPORTED) == 0)
        return (2);
    if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
        (long)sv, 0, 0) != 0) return (3);
    if (call(SYS_write, sv[0], (long)"abcd", 4, 0, 0, 0) != 4)
        return (4);
    res = uring_sockcmd(sv[1], SOCKET_URING_OP_SIOCINQ, 0, 0, 0, 0, 0);
    if (res != -EOPNOTSUPP) return (5);
    if (call(SYS_read, sv[1], (long)buf, 4, 0, 0, 0) != 4)
        return (6);
    res = uring_sockcmd(sv[1], SOCKET_URING_OP_SIOCINQ, 0, 0, 0, 0, 0);
    if (res != -EOPNOTSUPP) return (7);
    val = 1;
    if (uring_sockcmd(sv[0], SOCKET_URING_OP_SETSOCKOPT,
        LX_SOL_SOCKET, LX_SO_REUSEADDR, &val, sizeof(val), 0) != 0)
        return (8);
    val = 0;
    res = uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, LX_SO_REUSEADDR, &val, sizeof(val), 0);
    if (res != sizeof(val) || val != 1) return (9);
    tf = tmpfile_fd("uring_cmd_sock");
    if (tf < 0) return (10);
    if (uring_sockcmd((int)tf, SOCKET_URING_OP_SIOCINQ,
        0, 0, 0, 0, 0) != -EOPNOTSUPP) return (11);
    if (uring_sockcmd(9999, SOCKET_URING_OP_SIOCINQ,
        0, 0, 0, 0, 0) != -EBADF) return (12);
    if (uring_sockcmd(sv[0], 255, 0, 0, 0, 0, 0) != -EOPNOTSUPP)
        return (13);
    if (uring_sockcmd(sv[0], SOCKET_URING_OP_SIOCINQ,
        0, 0, 0, 0, 4) != -EINVAL) return (14);
    return (0);
}
static int
t_uring_cmd_sockopt_negative(void)
{
    int sv[2], val, res;
    u32 slot;
    struct cqe c[2];

    if (ring_setup(8) < 0) return (1);
    if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
        (long)sv, 0, 0) != 0) return (2);
    val = 1;
    if (uring_sockcmd(sv[0], SOCKET_URING_OP_SETSOCKOPT,
        LX_SOL_SOCKET, LX_SO_REUSEADDR, &val, 1, 0) != -EINVAL)
        return (3);
    if (uring_sockcmd(sv[0], SOCKET_URING_OP_SETSOCKOPT,
        LX_SOL_SOCKET, LX_SO_REUSEADDR, (void *)1, sizeof(val), 0)
        != -EFAULT) return (4);
    if (uring_sockcmd(sv[0], SOCKET_URING_OP_SETSOCKOPT,
        LX_SOL_SOCKET, LX_SO_REUSEADDR, &val, sizeof(val), 0) != 0)
        return (5);
    if (uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, LX_SO_REUSEADDR, (void *)1, sizeof(val), 0)
        != -EFAULT) return (6);
    val = 0;
    res = uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, LX_SO_REUSEADDR, &val, 1, 0);
    if (res != 1 || (val & 255) != 1) return (7);
    if (uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, 9999, &val, sizeof(val), 0) != -ENOPROTOOPT)
        return (8);
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_URING_CMD, 0, sv[0],
        (u64)SOCKET_URING_OP_GETSOCKOPT | (1ULL << 32), 0, 0, 0, 0xc002);
    g_sqes[slot].addr = (u64)LX_SOL_SOCKET |
        ((u64)LX_SO_REUSEADDR << 32);
    g_sqes[slot].splice_fd_in = sizeof(val);
    g_sqes[slot].pad2[0] = (u64)(unsigned long)&val;
    if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
        !cqe_find(c, 1, 0xc002, &res) || res != -EINVAL)
        return (9);
    return (0);
}

static int
t_uring_cmd_tcp(void)
{
    struct sockaddr_in sin;
    int lfd, cfd, afd, addrlen, got, direct;
    char buf[8];

    if (ring_setup(8) < 0) return (1);
    lfd = (int)call(SYS_socket, LX_AF_INET, LX_SOCK_STREAM, 0, 0, 0, 0);
    if (lfd < 0) return (2);
    xmemset(&sin, 0, sizeof(sin));
    sin.sin_family = LX_AF_INET;
    sin.sin_addr = 0x0100007f;
    if (call(SYS_bind, lfd, (long)&sin, sizeof(sin), 0, 0, 0) != 0)
        return (3);
    addrlen = sizeof(sin);
    if (call(SYS_getsockname, lfd, (long)&sin, (long)&addrlen,
        0, 0, 0) != 0 || sin.sin_port == 0) return (4);
    if (call(SYS_listen, lfd, 1, 0, 0, 0, 0) != 0) return (5);
    cfd = (int)call(SYS_socket, LX_AF_INET, LX_SOCK_STREAM, 0, 0, 0, 0);
    if (cfd < 0) return (6);
    if (call(SYS_connect, cfd, (long)&sin, sizeof(sin), 0, 0, 0) != 0)
        return (7);
    afd = (int)call(SYS_accept, lfd, 0, 0, 0, 0, 0);
    if (afd < 0) return (8);
    if (call(SYS_write, cfd, (long)"hello", 5, 0, 0, 0) != 5)
        return (9);
    if (!wait_readable(afd, 1000)) return (10);
    direct = -1;
    if (call(SYS_ioctl, afd, 0x541b, (long)&direct, 0, 0, 0) != 0 ||
        direct != 5) return (10);
    got = uring_sockcmd(afd, SOCKET_URING_OP_SIOCINQ, 0, 0, 0, 0, 0);
    if (got != direct) return (11);
    direct = -1;
    if (call(SYS_ioctl, cfd, 0x5411, (long)&direct, 0, 0, 0) != 0)
        return (12);
    got = uring_sockcmd(cfd, SOCKET_URING_OP_SIOCOUTQ, 0, 0, 0, 0, 0);
    if (got != direct) return (13);
    if (call(SYS_read, afd, (long)buf, 5, 0, 0, 0) != 5)
        return (14);
    if (uring_sockcmd(afd, SOCKET_URING_OP_SIOCINQ,
        0, 0, 0, 0, 0) != 0) return (15);
    return (0);
}

static int
t_uring_cmd_sockopt_matrix(void)
{
    static const int opts[] = {2, 3, 4, 5, 6, 7, 8, 9, 39};
    int sv[2], direct, cmd, dlen, i, got;

    if (ring_setup(8) < 0) return (1);
    if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
        (long)sv, 0, 0) != 0) return (2);
    for (i = 0; i < (int)(sizeof(opts) / sizeof(opts[0])); i++) {
        direct = cmd = -1;
        dlen = sizeof(direct);
        if (call(SYS_getsockopt, sv[0], LX_SOL_SOCKET, opts[i],
            (long)&direct, (long)&dlen, 0) != 0)
            return (10 + i);
        got = uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
            LX_SOL_SOCKET, opts[i], &cmd, sizeof(cmd), 0);
        if (got != dlen || cmd != direct)
            return (20 + i);
    }
    return (0);
}

static int
t_uring_cmd_fixed_file(void)
{
    int sv[2], val, res;
    u32 slot;
    struct cqe c[2];

    if (ring_setup(8) < 0) return (1);
    if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
        (long)sv, 0, 0) != 0) return (2);
    if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_FILES,
        (long)&sv[0], 1, 0, 0) != 0) return (3);
    val = 0;
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_URING_CMD, IOSQE_FIXED_FILE, 0,
        SOCKET_URING_OP_GETSOCKOPT, 0, 0, 0, 0xc004);
    g_sqes[slot].addr = (u64)LX_SOL_SOCKET |
        ((u64)3 << 32); /* SO_TYPE */
    g_sqes[slot].splice_fd_in = sizeof(val);
    g_sqes[slot].pad2[0] = (u64)(unsigned long)&val;
    if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
        !cqe_find(c, 1, 0xc004, &res) || res != sizeof(val) || val != 1)
        return (4);
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_URING_CMD, IOSQE_FIXED_FILE, 1,
        SOCKET_URING_OP_GETSOCKOPT, 0, 0, 0, 0xc005);
    g_sqes[slot].addr = (u64)LX_SOL_SOCKET | ((u64)3 << 32);
    g_sqes[slot].splice_fd_in = sizeof(val);
    g_sqes[slot].pad2[0] = (u64)(unsigned long)&val;
    if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
        !cqe_find(c, 1, 0xc005, &res) || res != -EBADF)
        return (5);
    return (0);
}

static int
t_uring_cmd_udp(void)
{
    struct sockaddr_in sin;
    int fd, addrlen, direct, got;
    char buf[8];

    if (ring_setup(8) < 0) return (1);
    fd = (int)call(SYS_socket, LX_AF_INET, LX_SOCK_DGRAM, 0, 0, 0, 0);
    if (fd < 0) return (2);
    xmemset(&sin, 0, sizeof(sin));
    sin.sin_family = LX_AF_INET;
    sin.sin_addr = 0x0100007f;
    if (call(SYS_bind, fd, (long)&sin, sizeof(sin), 0, 0, 0) != 0)
        return (3);
    addrlen = sizeof(sin);
    if (call(SYS_getsockname, fd, (long)&sin, (long)&addrlen,
        0, 0, 0) != 0 || sin.sin_port == 0) return (4);
    if (call(SYS_connect, fd, (long)&sin, sizeof(sin), 0, 0, 0) != 0)
        return (5);
    if (call(SYS_write, fd, (long)"udp", 3, 0, 0, 0) != 3)
        return (6);
    if (!wait_readable(fd, 1000)) return (7);
    direct = -1;
    if (call(SYS_ioctl, fd, 0x541b, (long)&direct, 0, 0, 0) != 0)
        return (8);
    got = uring_sockcmd(fd, SOCKET_URING_OP_SIOCINQ, 0, 0, 0, 0, 0);
    if (got != direct) return (9);
    direct = -1;
    if (call(SYS_ioctl, fd, 0x5411, (long)&direct, 0, 0, 0) != 0)
        return (10);
    got = uring_sockcmd(fd, SOCKET_URING_OP_SIOCOUTQ, 0, 0, 0, 0, 0);
    if (got != direct) return (11);
    if (call(SYS_read, fd, (long)buf, 3, 0, 0, 0) != 3)
        return (12);
    return (0);
}

static int
t_uring_cmd_linger(void)
{
    struct { int onoff, seconds; } setv, direct, got;
    int sv[2], dlen, res;

    if (ring_setup(8) < 0) return (1);
    if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
        (long)sv, 0, 0) != 0) return (2);
    setv.onoff = 1; setv.seconds = 7;
    if (uring_sockcmd(sv[0], SOCKET_URING_OP_SETSOCKOPT,
        LX_SOL_SOCKET, 13, &setv, sizeof(setv), 0) != 0)
        return (3);
    dlen = sizeof(direct);
    xmemset(&direct, 0, sizeof(direct));
    if (call(SYS_getsockopt, sv[0], LX_SOL_SOCKET, 13,
        (long)&direct, (long)&dlen, 0) != 0 || dlen != sizeof(direct) ||
        direct.onoff != 1 || direct.seconds != 7)
        return (4);
    xmemset(&got, 0, sizeof(got));
    res = uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, 13, &got, sizeof(got), 0);
    if (res != sizeof(got) ||
        xmemcmp(&got, &direct, sizeof(got)) != 0)
        return (5);
    xmemset(&got, 0, sizeof(got));
    res = uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, 13, &got, 4, 0);
    if (res != 4 || got.onoff != 1) return (6);
    if (uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, 13, (void *)1, sizeof(got), 0) != -EFAULT)
        return (7);
    return (0);
}

static int
t_uring_cmd_sock_timeouts(void)
{
    struct { long long sec, usec; } setv, direct, got;
    int sv[2], opts[2] = {66, 67}, dlen, res, i;

    if (ring_setup(8) < 0) return (1);
    if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
        (long)sv, 0, 0) != 0) return (2);
    for (i = 0; i < 2; i++) {
        setv.sec = 1; setv.usec = 250000;
        if (uring_sockcmd(sv[0], SOCKET_URING_OP_SETSOCKOPT,
            LX_SOL_SOCKET, opts[i], &setv, sizeof(setv), 0) != 0)
            return (3 + i * 10);
        dlen = sizeof(direct);
        xmemset(&direct, 0, sizeof(direct));
        if (call(SYS_getsockopt, sv[0], LX_SOL_SOCKET, opts[i],
            (long)&direct, (long)&dlen, 0) != 0 ||
            dlen != sizeof(direct)) return (4 + i * 10);
        xmemset(&got, 0, sizeof(got));
        res = uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
            LX_SOL_SOCKET, opts[i], &got, sizeof(got), 0);
        if (res != sizeof(got) ||
            xmemcmp(&got, &direct, sizeof(got)) != 0)
            return (5 + i * 10);
        xmemset(&got, 0, sizeof(got));
        res = uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
            LX_SOL_SOCKET, opts[i], &got, 8, 0);
        if (res != 8 || got.sec != direct.sec)
            return (6 + i * 10);
        if (uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
            LX_SOL_SOCKET, opts[i], (void *)1, sizeof(got), 0)
            != -EFAULT) return (7 + i * 10);
        setv.usec = 1000000;
        if (uring_sockcmd(sv[0], SOCKET_URING_OP_SETSOCKOPT,
            LX_SOL_SOCKET, opts[i], &setv, sizeof(setv), 0) != -33)
            return (8 + i * 10);
    }
    return (0);
}

static int
t_uring_cmd_tcp_sockopt(void)
{
    int fd, val, len;

    if (ring_setup(8) < 0) return (1);
    fd = (int)call(SYS_socket, LX_AF_INET, LX_SOCK_STREAM, 0, 0, 0, 0);
    if (fd < 0) return (2);
    val = 1;
    if (uring_sockcmd(fd, SOCKET_URING_OP_SETSOCKOPT,
        6, 1, &val, sizeof(val), 0) != 0) return (3);
    val = 0; len = sizeof(val);
    if (call(SYS_getsockopt, fd, 6, 1, (long)&val,
        (long)&len, 0) != 0 || len != sizeof(val) || val != 1)
        return (4);
    if (uring_sockcmd(fd, SOCKET_URING_OP_GETSOCKOPT,
        6, 1, &val, sizeof(val), 0) != -EOPNOTSUPP)
        return (5);
    return (0);
}

static int
t_uring_cmd_passcred(void)
{
    int sv[2], val, got, len, res;

    if (ring_setup(8) < 0) return (1);
    if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
        (long)sv, 0, 0) != 0) return (2);
    val = 1;
    if (uring_sockcmd(sv[0], SOCKET_URING_OP_SETSOCKOPT,
        LX_SOL_SOCKET, 16, &val, sizeof(val), 0) != 0)
        return (3);
    got = 0; len = sizeof(got);
    if (call(SYS_getsockopt, sv[0], LX_SOL_SOCKET, 16,
        (long)&got, (long)&len, 0) != 0 || len != sizeof(got) || got != 1)
        return (4);
    got = 0;
    res = uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, 16, &got, sizeof(got), 0);
    if (res != sizeof(got) || got != 1) return (5);
    got = 0;
    res = uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, 16, &got, 1, 0);
    if (res != 1 || (got & 255) != 1) return (6);
    if (uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, 16, (void *)1, sizeof(got), 0) != -EFAULT)
        return (7);
    return (0);
}

static int
t_uring_cmd_peercred(void)
{
    struct { int pid, uid, gid; } direct, got;
    int sv[2], len, res;

    if (ring_setup(8) < 0) return (1);
    if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
        (long)sv, 0, 0) != 0) return (2);
    len = sizeof(direct);
    if (call(SYS_getsockopt, sv[0], LX_SOL_SOCKET, 17,
        (long)&direct, (long)&len, 0) != 0 || len != sizeof(direct))
        return (3);
    xmemset(&got, 0, sizeof(got));
    res = uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, 17, &got, sizeof(got), 0);
    if (res != sizeof(got) || xmemcmp(&got, &direct, sizeof(got)) != 0)
        return (4);
    got.pid = 0;
    res = uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, 17, &got, 4, 0);
    if (res != 4 || got.pid != direct.pid) return (5);
    if (uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, 17, (void *)1, sizeof(got), 0) != -EFAULT)
        return (6);
    return (0);
}

static int
t_uring_cmd_pacing(void)
{
    int fd, setv, direct, got, len, res;

    if (ring_setup(8) < 0) return (1);
    fd = (int)call(SYS_socket, LX_AF_INET, LX_SOCK_STREAM, 0, 0, 0, 0);
    if (fd < 0) return (2);
    setv = 100000;
    if (uring_sockcmd(fd, SOCKET_URING_OP_SETSOCKOPT,
        LX_SOL_SOCKET, 47, &setv, sizeof(setv), 0) != 0) return (3);
    direct = 0; len = sizeof(direct);
    if (call(SYS_getsockopt, fd, LX_SOL_SOCKET, 47,
        (long)&direct, (long)&len, 0) != 0 || len != sizeof(direct))
        return (4);
    got = 0;
    res = uring_sockcmd(fd, SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, 47, &got, sizeof(got), 0);
    if (res != sizeof(got) || got != direct) return (5);
    got = 0;
    res = uring_sockcmd(fd, SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, 47, &got, 1, 0);
    if (res != 1 || (got & 255) != (direct & 255)) return (6);
    if (uring_sockcmd(fd, SOCKET_URING_OP_GETSOCKOPT,
        LX_SOL_SOCKET, 47, (void *)1, sizeof(got), 0) != -EFAULT)
        return (7);
    return (0);
}

static int
t_uring_cmd_timestamps(void)
{
    static const int opts[] = {29, 35, 63, 64};
    int sv[2], val, direct, got, len, res, i;

    if (ring_setup(8) < 0) return (1);
    for (i = 0; i < 4; i++) {
        if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_DGRAM, 0,
            (long)sv, 0, 0) != 0) return (2 + i * 10);
        val = 1;
        if (uring_sockcmd(sv[0], SOCKET_URING_OP_SETSOCKOPT,
            LX_SOL_SOCKET, opts[i], &val, sizeof(val), 0) != 0)
            return (3 + i * 10);
        direct = 0; len = sizeof(direct);
        if (call(SYS_getsockopt, sv[0], LX_SOL_SOCKET, opts[i],
            (long)&direct, (long)&len, 0) != 0 ||
            len != sizeof(direct)) return (4 + i * 10);
        got = 0;
        res = uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
            LX_SOL_SOCKET, opts[i], &got, sizeof(got), 0);
        if (res != sizeof(got) || got != direct) return (5 + i * 10);
        got = 0;
        res = uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
            LX_SOL_SOCKET, opts[i], &got, 1, 0);
        if (res != 1 || (got & 255) != (direct & 255))
            return (6 + i * 10);
        if (uring_sockcmd(sv[0], SOCKET_URING_OP_GETSOCKOPT,
            LX_SOL_SOCKET, opts[i], (void *)1, sizeof(got), 0) != -EFAULT)
            return (7 + i * 10);
        (void)sys1(SYS_close, sv[0]);
        (void)sys1(SYS_close, sv[1]);
    }
    return (0);
}

static int
t_uring_cmd128_socket(void)
{
    struct params p;
    struct sqe *q;
    struct cqe *c;
    volatile u32 *sqhead, *sqtail, *sqarray, *cqhead, *cqtail;
    char *sqbase;
    int sv[2], fd, val, res;
    long r;
    u32 ringsz;

    xmemset(&p, 0, sizeof(p));
    p.flags = 1U << 10; /* IORING_SETUP_SQE128 */
    fd = (int)setup(8, &p);
    if (fd < 0) return (1);
    ringsz = p.sq_off.array + p.sq_entries * sizeof(u32);
    if (p.cq_off.cqes + p.cq_entries * sizeof(struct cqe) > ringsz)
        ringsz = p.cq_off.cqes + p.cq_entries * sizeof(struct cqe);
    r = call(SYS_mmap, 0, ringsz, PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, IORING_OFF_SQ_RING);
    if (r < 0) return (2);
    sqbase = (char *)r;
    r = call(SYS_mmap, 0, p.sq_entries * 128,
        PROT_READ | PROT_WRITE, MAP_SHARED, fd, IORING_OFF_SQES);
    if (r < 0) return (3);
    q = (struct sqe *)r;
    sqhead = (volatile u32 *)(sqbase + p.sq_off.head);
    sqtail = (volatile u32 *)(sqbase + p.sq_off.tail);
    sqarray = (volatile u32 *)(sqbase + p.sq_off.array);
    cqhead = (volatile u32 *)(sqbase + p.cq_off.head);
    cqtail = (volatile u32 *)(sqbase + p.cq_off.tail);
    c = (struct cqe *)(sqbase + p.cq_off.cqes);
    if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
        (long)sv, 0, 0) != 0) return (4);
    xmemset(q, 0, 128);
    q->opcode = 64; /* URING_CMD128 */
    q->fd = sv[0];
    q->off = SOCKET_URING_OP_GETSOCKOPT;
    q->addr = (u64)LX_SOL_SOCKET | ((u64)3 << 32);
    q->splice_fd_in = sizeof(val);
    q->pad2[0] = (u64)(unsigned long)&val;
    q->user_data = 0xc128;
    val = 0;
    sqarray[0] = 0;
    __atomic_store_n(sqtail, 1, __ATOMIC_RELEASE);
    if (call(SYS_io_uring_enter, fd, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0) != 1) return (5);
    if (__atomic_load_n(cqtail, __ATOMIC_ACQUIRE) != 1 ||
        c[0].user_data != 0xc128) return (6);
    res = c[0].res;
    *cqhead = 1;
    *sqhead = 1;
    return (res == sizeof(val) && val == 1 ? 0 :
        res == -EINVAL ? 72 : res == -EOPNOTSUPP ? 73 :
        res == sizeof(val) ? 71 : 74);
}

static int
t_uring_cmd128_probe(void)
{
    struct probe pr;

    if (ring_setup(8) < 0) return (1);
    xmemset(&pr, 0, sizeof(pr));
    if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PROBE,
        (long)&pr, 128, 0, 0) != 0) return (2);
    return ((pr.ops[64].flags & IO_URING_OP_SUPPORTED) != 0 ? 0 : 3);
}

static int
uring_socknamecmd(int fd, int peer, void *addr, void *namelen,
    int ioprio, unsigned int flags)
{
    struct cqe c[2];
    u32 slot;
    int res;

    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_URING_CMD, 0, fd,
        SOCKET_URING_OP_GETSOCKNAME, addr, 0, flags, 0xc006);
    g_sqes[slot].ioprio = ioprio;
    g_sqes[slot].splice_fd_in = peer;
    g_sqes[slot].pad2[0] = (u64)(unsigned long)namelen;
    if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
        !cqe_find(c, 1, 0xc006, &res)) return (-100000);
    return (res);
}

static int
t_uring_cmd_getsockname(void)
{
    struct sockaddr_un bindaddr, direct, got;
    int fd, sv[2], dlen, glen, res;

    if (ring_setup(8) < 0) return (1);
    fd = (int)call(SYS_socket, LX_AF_UNIX, LX_SOCK_DGRAM, 0, 0, 0, 0);
    if (fd < 0) return (2);
    xmemset(&bindaddr, 0, sizeof(bindaddr));
    bindaddr.sun_family = LX_AF_UNIX;
    xmemcpy(bindaddr.sun_path, "/uring_getname", 15);
    (void)call(SYS_unlinkat, LX_AT_FDCWD,
        (long)bindaddr.sun_path, 0, 0, 0, 0);
    if (call(SYS_bind, fd, (long)&bindaddr, 18, 0, 0, 0) != 0)
        return (3);
    xmemset(&direct, 0, sizeof(direct));
    dlen = sizeof(direct);
    if (call(SYS_getsockname, fd, (long)&direct, (long)&dlen,
        0, 0, 0) != 0 || dlen < 3) return (4);
    xmemset(&got, 0, sizeof(got));
    glen = sizeof(got);
    res = uring_socknamecmd(fd, 0, &got, &glen, 0, 0);
    if (res != 0 || glen != dlen ||
        xmemcmp(&got, &direct, dlen) != 0) return (5);
    xmemset(&got, 0, sizeof(got));
    glen = 2;
    res = uring_socknamecmd(fd, 0, &got, &glen, 0, 0);
    if (res != 0 || glen != dlen || got.sun_family != LX_AF_UNIX)
        return (6);
    if (uring_socknamecmd(fd, 0, &got, (void *)1, 0, 0)
        != -EFAULT) return (7);
    if (uring_socknamecmd(fd, 2, &got, &glen, 0, 0)
        != -EINVAL) return (8);
    if (uring_socknamecmd(fd, 0, &got, &glen, 1, 0)
        != -EINVAL) return (9);
    if (uring_socknamecmd(fd, 1, &got, &glen, 0, 0)
        != -ENOTCONN) return (10);
    if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
        (long)sv, 0, 0) != 0) return (11);
    xmemset(&direct, 0, sizeof(direct));
    dlen = sizeof(direct);
    if (call(SYS_getpeername, sv[0], (long)&direct,
        (long)&dlen, 0, 0, 0) != 0) return (12);
    xmemset(&got, 0, sizeof(got));
    glen = sizeof(got);
    res = uring_socknamecmd(sv[0], 1, &got, &glen, 0, 0);
    if (res != 0 || glen != dlen ||
        xmemcmp(&got, &direct, dlen) != 0) return (13);
    return (0);
}

static int
t_sqe_mixed_cmd128(void)
{
    struct params p;
    struct sqe *q;
    struct cqe *c;
    volatile u32 *sqhead, *sqtail, *cqhead, *cqtail;
    char *sqbase;
    int sv[2], fd, val, seen1, seen2, seen3;
    long r;
    u32 ringsz;

    xmemset(&p, 0, sizeof(p));
    p.flags = (1U << 19) | (1U << 16); /* SQE_MIXED, NO_SQARRAY */
    fd = (int)setup(8, &p);
    if (fd < 0) return (1);
    ringsz = p.cq_off.cqes + p.cq_entries * sizeof(struct cqe);
    r = call(SYS_mmap, 0, ringsz, PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, IORING_OFF_SQ_RING);
    if (r < 0) return (2);
    sqbase = (char *)r;
    r = call(SYS_mmap, 0, p.sq_entries * sizeof(struct sqe),
        PROT_READ | PROT_WRITE, MAP_SHARED, fd, IORING_OFF_SQES);
    if (r < 0) return (3);
    q = (struct sqe *)r;
    sqhead = (volatile u32 *)(sqbase + p.sq_off.head);
    sqtail = (volatile u32 *)(sqbase + p.sq_off.tail);
    cqhead = (volatile u32 *)(sqbase + p.cq_off.head);
    cqtail = (volatile u32 *)(sqbase + p.cq_off.tail);
    c = (struct cqe *)(sqbase + p.cq_off.cqes);
    if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
        (long)sv, 0, 0) != 0) return (4);
    xmemset(q, 0, 4 * sizeof(*q));
    q[0].opcode = IORING_OP_NOP;
    q[0].user_data = 0xc101;
    q[1].opcode = 64;
    q[1].fd = sv[0];
    q[1].off = SOCKET_URING_OP_GETSOCKOPT;
    q[1].addr = (u64)LX_SOL_SOCKET | ((u64)3 << 32);
    q[1].splice_fd_in = sizeof(val);
    q[1].pad2[0] = (u64)(unsigned long)&val;
    q[1].user_data = 0xc102;
    q[3].opcode = IORING_OP_NOP;
    q[3].user_data = 0xc103;
    val = 0;
    __atomic_store_n(sqtail, 4, __ATOMIC_RELEASE);
    r = call(SYS_io_uring_enter, fd, 4, 3,
        IORING_ENTER_GETEVENTS, 0, 0);
    if (r != 4) return (5);
    if (__atomic_load_n(sqhead, __ATOMIC_ACQUIRE) != 4 ||
        __atomic_load_n(cqtail, __ATOMIC_ACQUIRE) != 3)
        return (6);
    seen1 = seen2 = seen3 = 0;
    for (int i = 0; i < 3; i++) {
        if (c[i].user_data == 0xc101 && c[i].res == 0) seen1++;
        if (c[i].user_data == 0xc102 && c[i].res == 4) seen2++;
        if (c[i].user_data == 0xc103 && c[i].res == 0) seen3++;
    }
    *cqhead = 3;
    return (seen1 == 1 && seen2 == 1 && seen3 == 1 && val == 1
        ? 0 : 7);
}

static int t_uring_cmd_badfd(void) {
	if (ring_setup(8) < 0) return (1);
	return (sub1(9999, IORING_OP_URING_CMD, 0, 0, 0, 0, 0x1) == -EBADF ? 0 : 2);
}
static int t_uring_cmd128_requires_sqe128(void){ return sweep_einval(64); }
struct zring {
	struct params p;
	int fd;
	char *base;
	struct sqe *sqes;
	volatile u32 *sqtail, *cqhead, *cqtail, *array;
	u32 sqi, cqi, cqe_stride;
};

static u8 zcrx_area0[16 * PAGE] __attribute__((aligned(PAGE)));
static u8 zcrx_area1[4 * PAGE] __attribute__((aligned(PAGE)));
static u8 zcrx_user_rq[PAGE] __attribute__((aligned(PAGE)));

static int
zring_open(struct zring *zr, u32 flags)
{
	u32 ringsz;
	long r;

	xmemset(zr, 0, sizeof(*zr));
	zr->fd = -1;
	zr->p.flags = flags;
	zr->cqe_stride = (flags & IORING_SETUP_CQE_MIXED) != 0 ? 16 : 32;
	r = setup(8, &zr->p);
	if (r < 0)
		return ((int)r);
	zr->fd = (int)r;
	ringsz = zr->p.sq_off.array + zr->p.sq_entries * sizeof(u32);
	if (zr->p.cq_off.cqes + zr->p.cq_entries * zr->cqe_stride > ringsz)
		ringsz = zr->p.cq_off.cqes +
		    zr->p.cq_entries * zr->cqe_stride;
	r = call(SYS_mmap, 0, ringsz, PROT_READ | PROT_WRITE, MAP_SHARED,
	    zr->fd, IORING_OFF_SQ_RING);
	if (r < 0)
		return ((int)r);
	zr->base = (char *)r;
	r = call(SYS_mmap, 0, zr->p.sq_entries * sizeof(struct sqe),
	    PROT_READ | PROT_WRITE, MAP_SHARED, zr->fd, IORING_OFF_SQES);
	if (r < 0)
		return ((int)r);
	zr->sqes = (struct sqe *)r;
	zr->sqtail = (volatile u32 *)(zr->base + zr->p.sq_off.tail);
	zr->array = (volatile u32 *)(zr->base + zr->p.sq_off.array);
	zr->cqhead = (volatile u32 *)(zr->base + zr->p.cq_off.head);
	zr->cqtail = (volatile u32 *)(zr->base + zr->p.cq_off.tail);
	return (0);
}

static void
zreg_init(struct zcrx_ifq_reg *reg, struct zcrx_area_reg *area,
    struct zcrx_region_desc *region, void *mem, u64 memsz)
{

	xmemset(reg, 0, sizeof(*reg));
	xmemset(area, 0, sizeof(*area));
	xmemset(region, 0, sizeof(*region));
	reg->rq_entries = 8;
	reg->flags = ZCRX_REG_NODEV;
	reg->area_ptr = (u64)(unsigned long)area;
	reg->region_ptr = (u64)(unsigned long)region;
	area->addr = (u64)(unsigned long)mem;
	area->len = memsz;
	region->size = PAGE;
}

static long
zring_register(struct zring *zr, struct zcrx_ifq_reg *reg)
{

	return (call(SYS_io_uring_register, zr->fd, IORING_REGISTER_ZCRX_IFQ,
	    (long)reg, 1, 0, 0));
}

static struct cqe *
zring_cqe(struct zring *zr, u32 n)
{

	return ((struct cqe *)(zr->base + zr->p.cq_off.cqes +
	    ((zr->cqi + n) & (zr->p.cq_entries - 1)) * zr->cqe_stride));
}

static long
zring_submit(struct zring *zr, const struct sqe *sqe, u32 wait)
{
	u32 slot;

	slot = zr->sqi & (zr->p.sq_entries - 1);
	zr->sqes[slot] = *sqe;
	zr->array[slot] = slot;
	zr->sqi++;
	__atomic_store_n(zr->sqtail, zr->sqi, __ATOMIC_RELEASE);
	return (call(SYS_io_uring_enter, zr->fd, 1, wait,
	    wait != 0 ? IORING_ENTER_GETEVENTS : 0, 0, 0));
}

static void
zring_consume(struct zring *zr, u32 n)
{

	zr->cqi += n;
	__atomic_store_n(zr->cqhead, zr->cqi, __ATOMIC_RELEASE);
}

static int
zcrx_tcp_pair(int *client, int *accepted)
{
	struct sockaddr_in sin;
	u32 len;
	int listener;

	xmemset(&sin, 0, sizeof(sin));
	listener = (int)call(SYS_socket, LX_AF_INET, LX_SOCK_STREAM, 0,
	    0, 0, 0);
	if (listener < 0)
		return (1);
	sin.sin_family = LX_AF_INET;
	sin.sin_addr = 0x0100007f;
	len = sizeof(sin);
	if (call(SYS_bind, listener, (long)&sin, sizeof(sin), 0, 0, 0) != 0 ||
	    call(SYS_getsockname, listener, (long)&sin, (long)&len,
	    0, 0, 0) != 0 ||
	    call(SYS_listen, listener, 1, 0, 0, 0, 0) != 0)
		return (2);
	*client = (int)call(SYS_socket, LX_AF_INET, LX_SOCK_STREAM, 0,
	    0, 0, 0);
	if (*client < 0 || call(SYS_connect, *client, (long)&sin,
	    sizeof(sin), 0, 0, 0) != 0)
		return (3);
	*accepted = (int)call(SYS_accept, listener, 0, 0, 0, 0, 0);
	(void)call(SYS_close, listener, 0, 0, 0, 0, 0);
	return (*accepted < 0 ? 4 : 0);
}

static int
t_zcrx_register_nodev(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;
	long rq;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	if (zring_register(&zr, &reg) != 0)
		return (2);
	if (reg.rx_buf_len != PAGE || reg.rq_entries != 8 ||
	    reg.offsets.head != 0 || reg.offsets.tail != 4 ||
	    reg.offsets.rqes < 8 || region.mmap_offset < IORING_OFF_ZCRX_REGION)
		return (3);
	rq = call(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED,
	    zr.fd, region.mmap_offset);
	if (rq < 0 || *(volatile u32 *)((char *)rq + reg.offsets.head) != 0 ||
	    *(volatile u32 *)((char *)rq + reg.offsets.tail) != 0)
		return (4);
	return (call(SYS_close, zr.fd, 0, 0, 0, 0, 0) == 0 ? 0 : 5);
}

static int
t_zcrx_setup_requirements(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;

	if (zring_open(&zr, IORING_SETUP_CQE32) != 0)
		return (1);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	if (zring_register(&zr, &reg) != -EINVAL)
		return (2);
	(void)call(SYS_close, zr.fd, 0, 0, 0, 0, 0);
	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN) != 0)
		return (3);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	if (zring_register(&zr, &reg) != -EINVAL)
		return (4);
	(void)call(SYS_close, zr.fd, 0, 0, 0, 0, 0);
	{
		int error;

		error = zring_open(&zr, IORING_SETUP_DEFER_TASKRUN |
		    IORING_SETUP_CQE32);
		if (error == -EINVAL)
			return (0);
		if (error != 0)
			return (5);
	}
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	return (zring_register(&zr, &reg) == -EINVAL ? 0 : 6);
}

static int
t_zcrx_recv_bounded(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;
	struct sqe sqe;
	struct cqe *data, *done;
	u64 off;
	int client, accepted;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	if (zring_register(&zr, &reg) != 0)
		return (2);
	if (zcrx_tcp_pair(&client, &accepted) != 0 ||
	    call(SYS_write, client, (long)"hello", 5, 0, 0, 0) != 5)
		return (3);
	xmemset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_RECV_ZC;
	sqe.ioprio = IORING_RECV_MULTISHOT;
	sqe.fd = accepted;
	sqe.len = 5;
	sqe.splice_fd_in = (int)reg.zcrx_id;
	sqe.user_data = 0x5a5a;
	if (zring_submit(&zr, &sqe, 1) != 1 ||
	    __atomic_load_n(zr.cqtail, __ATOMIC_ACQUIRE) != 2)
		return (4);
	data = zring_cqe(&zr, 0);
	done = zring_cqe(&zr, 1);
	if (data->user_data != 0x5a5a || data->res != 5 ||
	    (data->flags & IORING_CQE_F_MORE) == 0 ||
	    done->user_data != 0x5a5a || done->res != 0 ||
	    (done->flags & IORING_CQE_F_MORE) != 0)
		return (5);
	off = *(u64 *)((char *)data + sizeof(*data)) & ((1ULL << 48) - 1);
	if (off + 5 > sizeof(zcrx_area0) ||
	    zcrx_area0[off] != 'h' || zcrx_area0[off + 1] != 'e' ||
	    zcrx_area0[off + 2] != 'l' || zcrx_area0[off + 3] != 'l' ||
	    zcrx_area0[off + 4] != 'o')
		return (6);
	return (0);
}

static int
t_zcrx_registration_negative(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	reg.if_idx = 1;
	if (zring_register(&zr, &reg) != -EINVAL) return (2);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	reg.if_rxq = 1;
	if (zring_register(&zr, &reg) != -EINVAL) return (3);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	reg.flags = 0;
	if (zring_register(&zr, &reg) != -ENODEV) return (4);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	reg.flags |= ZCRX_REG_IMPORT;
	if (zring_register(&zr, &reg) != -EINVAL) return (5);
	xmemset(&reg, 0, sizeof(reg));
	reg.flags = ZCRX_REG_IMPORT;
	if (zring_register(&zr, &reg) != -EBADF) return (12);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	area.flags = ZCRX_AREA_DMABUF;
	if (zring_register(&zr, &reg) != -EINVAL) return (6);
	zreg_init(&reg, &area, &region, zcrx_area0 + 1, sizeof(zcrx_area0));
	if (zring_register(&zr, &reg) != -EINVAL) return (7);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0) - 1);
	if (zring_register(&zr, &reg) != -EINVAL) return (8);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	reg.resv[0] = 1;
	if (zring_register(&zr, &reg) != -EINVAL) return (9);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	region.size = 0;
	if (zring_register(&zr, &reg) != -EINVAL) return (10);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	region.user_addr = (u64)(unsigned long)zcrx_user_rq;
	if (zring_register(&zr, &reg) != -EFAULT) return (11);
	return (0);
}

static int
zcrx_unprivileged_child(void *arg __attribute__((unused)))
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;

	if (call(SYS_setuid_test, 65534, 0, 0, 0, 0, 0) != 0)
		return (1);
	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (2);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	return (zring_register(&zr, &reg) == -EPERM ? 0 : 3);
}

static int
t_zcrx_privilege(void)
{

	return (run_child(zcrx_unprivileged_child, 0));
}

static int
t_zcrx_memory_protection(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	if (call(SYS_mprotect, (long)zcrx_area1, PAGE, PROT_READ,
	    0, 0, 0) != 0)
		return (2);
	zreg_init(&reg, &area, &region, zcrx_area1, PAGE);
	if (zring_register(&zr, &reg) != -EFAULT)
		return (3);
	if (call(SYS_mprotect, (long)zcrx_area1, PAGE,
	    PROT_READ | PROT_WRITE, 0, 0, 0) != 0)
		return (4);
	if (call(SYS_mprotect, (long)zcrx_user_rq, PAGE, PROT_READ,
	    0, 0, 0) != 0)
		return (5);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	region.user_addr = (u64)(unsigned long)zcrx_user_rq;
	region.flags = IORING_MEM_REGION_TYPE_USER;
	if (zring_register(&zr, &reg) != -EFAULT)
		return (6);
	if (call(SYS_mprotect, (long)zcrx_user_rq, PAGE,
	    PROT_READ | PROT_WRITE, 0, 0, 0) != 0)
		return (7);
	return (0);
}

static int
t_zcrx_copyout_rollback(void)
{
	struct zcrx_ifq_reg *reg;
	struct zcrx_area_reg *area;
	struct zcrx_region_desc *region;
	struct zring zr;
	char *pages;
	long r;
	int i;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	r = call(SYS_mmap, 0, 3 * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (r < 0)
		return (2);
	pages = (char *)r;
	reg = (struct zcrx_ifq_reg *)pages;
	area = (struct zcrx_area_reg *)(pages + PAGE);
	region = (struct zcrx_region_desc *)(pages + 2 * PAGE);
	for (i = 0; i < 3; i++) {
		zreg_init(reg, area, region, zcrx_area0, sizeof(zcrx_area0));
		if (call(SYS_mprotect, (long)(pages + i * PAGE), PAGE,
		    PROT_READ, 0, 0, 0) != 0)
			return (3 + i);
		if (zring_register(&zr, reg) != -EFAULT)
			return (6 + i);
		if (call(SYS_mprotect, (long)(pages + i * PAGE), PAGE,
		    PROT_READ | PROT_WRITE, 0, 0, 0) != 0)
			return (9 + i);
	}
	return (0);
}

static int
t_zcrx_sqe_negative(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;
	struct sqe sqe;
	struct cqe *cqe;
	int i;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	if (zring_register(&zr, &reg) != 0)
		return (2);
	for (i = 0; i < 4; i++) {
		xmemset(&sqe, 0, sizeof(sqe));
		sqe.opcode = IORING_OP_RECV_ZC;
		sqe.ioprio = IORING_RECV_MULTISHOT;
		sqe.fd = -1;
		sqe.splice_fd_in = (int)reg.zcrx_id;
		sqe.user_data = 0x6000 + i;
		if (i == 0) sqe.ioprio = 0;
		if (i == 1) sqe.addr = 1;
		if (i == 2) sqe.off = 1;
		if (i == 3) sqe.rw_flags = 1;
		if (zring_submit(&zr, &sqe, 1) != 1)
			return (10 + i);
		cqe = zring_cqe(&zr, 0);
		if (cqe->user_data != sqe.user_data || cqe->res != -EINVAL)
			return (20 + i);
		zring_consume(&zr, 1);
	}
	xmemset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_RECV_ZC;
	sqe.ioprio = IORING_RECV_MULTISHOT;
	sqe.fd = -1;
	sqe.splice_fd_in = (int)reg.zcrx_id;
	if (zring_submit(&zr, &sqe, 1) != 1 ||
	    zring_cqe(&zr, 0)->res != -EBADF)
		return (30);
	return (0);
}

static int
t_zcrx_refill_reuse(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zcrx_rqe *rqe;
	struct zcrx_ctrl ctrl;
	struct zring zr;
	struct sqe sqe;
	volatile u32 *tail;
	u64 first, second;
	long rq;
	int client, accepted;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	zreg_init(&reg, &area, &region, zcrx_area1, PAGE);
	if (zring_register(&zr, &reg) != 0)
		return (2);
	rq = call(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED,
	    zr.fd, region.mmap_offset);
	if (rq < 0 || zcrx_tcp_pair(&client, &accepted) != 0)
		return (3);
	xmemset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_RECV_ZC;
	sqe.ioprio = IORING_RECV_MULTISHOT;
	sqe.fd = accepted;
	sqe.len = 1;
	sqe.splice_fd_in = (int)reg.zcrx_id;
	if (call(SYS_write, client, (long)"a", 1, 0, 0, 0) != 1 ||
	    zring_submit(&zr, &sqe, 1) != 1 ||
	    __atomic_load_n(zr.cqtail, __ATOMIC_ACQUIRE) != 2)
		return (4);
	first = *(u64 *)((char *)zring_cqe(&zr, 0) + sizeof(struct cqe));
	zring_consume(&zr, 2);
	rqe = (struct zcrx_rqe *)((char *)rq + reg.offsets.rqes);
	rqe[0].off = first;
	rqe[0].len = PAGE;
	tail = (volatile u32 *)((char *)rq + reg.offsets.tail);
	__atomic_store_n(tail, 1, __ATOMIC_RELEASE);
	xmemset(&ctrl, 0, sizeof(ctrl));
	ctrl.zcrx_id = reg.zcrx_id;
	ctrl.op = ZCRX_CTRL_FLUSH_RQ;
	if (call(SYS_io_uring_register, zr.fd, IORING_REGISTER_ZCRX_CTRL,
	    (long)&ctrl, 0, 0, 0) != 0)
		return (5);
	sqe.user_data = 2;
	if (call(SYS_write, client, (long)"b", 1, 0, 0, 0) != 1 ||
	    zring_submit(&zr, &sqe, 1) != 1 ||
	    __atomic_load_n(zr.cqtail, __ATOMIC_ACQUIRE) != 4)
		return (6);
	second = *(u64 *)((char *)zring_cqe(&zr, 0) + sizeof(struct cqe));
	return ((first & ((1ULL << 48) - 1)) ==
	    (second & ((1ULL << 48) - 1)) ? 0 : 7);
}

static int
t_zcrx_user_region(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE_MIXED) != 0)
		return (1);
	xmemset(zcrx_user_rq, 0xa5, sizeof(zcrx_user_rq));
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	region.user_addr = (u64)(unsigned long)zcrx_user_rq;
	region.flags = IORING_MEM_REGION_TYPE_USER;
	if (zring_register(&zr, &reg) != 0)
		return (2);
	if (region.mmap_offset != 0 ||
	    *(volatile u32 *)(zcrx_user_rq + reg.offsets.head) != 0 ||
	    *(volatile u32 *)(zcrx_user_rq + reg.offsets.tail) != 0)
		return (3);
	return (0);
}
static int
t_zcrx_multishot_cancel(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;
	struct sqe sqe;
	struct cqe *cqe;
	int client, accepted, i, saw_cancel, saw_terminal;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	if (zring_register(&zr, &reg) != 0 ||
	    zcrx_tcp_pair(&client, &accepted) != 0)
		return (2);
	xmemset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_RECV_ZC;
	sqe.ioprio = IORING_RECV_MULTISHOT | IORING_RECVSEND_POLL_FIRST;
	sqe.fd = accepted;
	sqe.splice_fd_in = (int)reg.zcrx_id;
	sqe.user_data = 0x7100;
	if (zring_submit(&zr, &sqe, 0) != 1 ||
	    __atomic_load_n(zr.cqtail, __ATOMIC_ACQUIRE) != 0)
		return (3);
	if (call(SYS_write, client, (long)"one", 3, 0, 0, 0) != 3 ||
	    call(SYS_io_uring_enter, zr.fd, 0, 1, IORING_ENTER_GETEVENTS,
	    0, 0) < 0)
		return (4);
	cqe = zring_cqe(&zr, 0);
	if (cqe->user_data != 0x7100 || cqe->res != 3 ||
	    (cqe->flags & IORING_CQE_F_MORE) == 0)
		return (5);
	zring_consume(&zr, 1);
	if (call(SYS_write, client, (long)"two", 3, 0, 0, 0) != 3 ||
	    call(SYS_io_uring_enter, zr.fd, 0, 1, IORING_ENTER_GETEVENTS,
	    0, 0) < 0)
		return (6);
	cqe = zring_cqe(&zr, 0);
	if (cqe->user_data != 0x7100 || cqe->res != 3 ||
	    (cqe->flags & IORING_CQE_F_MORE) == 0)
		return (7);
	zring_consume(&zr, 1);
	xmemset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_ASYNC_CANCEL;
	sqe.fd = -1;
	sqe.addr = 0x7100;
	sqe.user_data = 0x7101;
	if (zring_submit(&zr, &sqe, 2) != 1)
		return (8);
	saw_cancel = saw_terminal = 0;
	for (i = 0; i < 2; i++) {
		cqe = zring_cqe(&zr, i);
		if (cqe->user_data == 0x7101 && cqe->res == 0)
			saw_cancel++;
		if (cqe->user_data == 0x7100 && cqe->res == -ELINUX_ECANCELED &&
		    (cqe->flags & IORING_CQE_F_MORE) == 0)
			saw_terminal++;
	}
	return (saw_cancel == 1 && saw_terminal == 1 ? 0 : 9);
}

static int
t_zcrx_fixed_file(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;
	struct sqe sqe;
	int client, accepted, fds[1];

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	if (zring_register(&zr, &reg) != 0 ||
	    zcrx_tcp_pair(&client, &accepted) != 0)
		return (2);
	fds[0] = accepted;
	if (call(SYS_io_uring_register, zr.fd, IORING_REGISTER_FILES,
	    (long)fds, 1, 0, 0) != 0)
		return (3);
	if (call(SYS_write, client, (long)"fixed", 5, 0, 0, 0) != 5)
		return (4);
	xmemset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_RECV_ZC;
	sqe.flags = IOSQE_FIXED_FILE;
	sqe.ioprio = IORING_RECV_MULTISHOT;
	sqe.fd = 0;
	sqe.len = 5;
	sqe.splice_fd_in = (int)reg.zcrx_id;
	sqe.user_data = 0x7200;
	if (zring_submit(&zr, &sqe, 1) != 1 ||
	    __atomic_load_n(zr.cqtail, __ATOMIC_ACQUIRE) != 2 ||
	    zring_cqe(&zr, 0)->res != 5 || zring_cqe(&zr, 1)->res != 0)
		return (5);
	return (0);
}

static int
t_zcrx_multi_instance(void)
{
	struct zcrx_ifq_reg r0, r1;
	struct zcrx_area_reg a0, a1;
	struct zcrx_region_desc d0, d1;
	struct zring zr;
	struct sqe sqe;
	struct cqe *cqe;
	u64 off;
	int client, accepted;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	zreg_init(&r0, &a0, &d0, zcrx_area0, sizeof(zcrx_area0));
	zreg_init(&r1, &a1, &d1, zcrx_area1, sizeof(zcrx_area1));
	if (zring_register(&zr, &r0) != 0 || zring_register(&zr, &r1) != 0)
		return (2);
	if (r0.zcrx_id == r1.zcrx_id || d0.mmap_offset == d1.mmap_offset)
		return (3);
	if (zcrx_tcp_pair(&client, &accepted) != 0 ||
	    call(SYS_write, client, (long)"second", 6, 0, 0, 0) != 6)
		return (4);
	xmemset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_RECV_ZC;
	sqe.ioprio = IORING_RECV_MULTISHOT;
	sqe.fd = accepted;
	sqe.len = 6;
	sqe.splice_fd_in = (int)r1.zcrx_id;
	if (zring_submit(&zr, &sqe, 1) != 1 ||
	    __atomic_load_n(zr.cqtail, __ATOMIC_ACQUIRE) != 2)
		return (5);
	cqe = zring_cqe(&zr, 0);
	off = *(u64 *)((char *)cqe + sizeof(*cqe)) & ((1ULL << 48) - 1);
	if (cqe->res != 6 || off + 6 > sizeof(zcrx_area1) ||
	    xmemcmp(zcrx_area1 + off, "second", 6) != 0)
		return (6);
	return (0);
}

static int
t_zcrx_cqe_mixed(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;
	struct sqe sqe;
	struct cqe *data, *done;
	int client, accepted;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE_MIXED) != 0)
		return (1);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	if (zring_register(&zr, &reg) != 0 ||
	    zcrx_tcp_pair(&client, &accepted) != 0 ||
	    call(SYS_write, client, (long)"mix", 3, 0, 0, 0) != 3)
		return (2);
	xmemset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_RECV_ZC;
	sqe.ioprio = IORING_RECV_MULTISHOT;
	sqe.fd = accepted;
	sqe.len = 3;
	sqe.splice_fd_in = (int)reg.zcrx_id;
	if (zring_submit(&zr, &sqe, 1) != 1 ||
	    __atomic_load_n(zr.cqtail, __ATOMIC_ACQUIRE) != 3)
		return (3);
	data = zring_cqe(&zr, 0);
	done = zring_cqe(&zr, 2);
	if (data->res != 3 || (data->flags & (IORING_CQE_F_MORE |
	    IORING_CQE_F_32)) != (IORING_CQE_F_MORE | IORING_CQE_F_32) ||
	    done->res != 0 || (done->flags & IORING_CQE_F_32) != 0)
		return (4);
	return (0);
}

static int
t_zcrx_ctrl_negative(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zcrx_ctrl ctrl;
	struct zring zr;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	xmemset(&ctrl, 0, sizeof(ctrl));
	ctrl.zcrx_id = 99;
	if (call(SYS_io_uring_register, zr.fd, IORING_REGISTER_ZCRX_CTRL,
	    (long)&ctrl, 0, 0, 0) != -ENXIO)
		return (2);
	ctrl.op = 1;
	if (call(SYS_io_uring_register, zr.fd, IORING_REGISTER_ZCRX_CTRL,
	    (long)&ctrl, 0, 0, 0) != -ENXIO)
		return (3);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	if (zring_register(&zr, &reg) != 0)
		return (4);
	xmemset(&ctrl, 0, sizeof(ctrl));
	ctrl.zcrx_id = reg.zcrx_id;
	ctrl.data[0] = 1;
	if (call(SYS_io_uring_register, zr.fd, IORING_REGISTER_ZCRX_CTRL,
	    (long)&ctrl, 0, 0, 0) != -EINVAL)
		return (5);
	return (call(SYS_io_uring_register, zr.fd, IORING_REGISTER_ZCRX_CTRL,
	    (long)&ctrl, 1, 0, 0) == -EINVAL ? 0 : 6);
}

static int
t_zcrx_close_teardown(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;
	int i;

	for (i = 0; i < 32; i++) {
		if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
		    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
			return (1);
		zreg_init(&reg, &area, &region, zcrx_area0,
		    sizeof(zcrx_area0));
		if (zring_register(&zr, &reg) != 0)
			return (2);
		if (call(SYS_close, zr.fd, 0, 0, 0, 0, 0) != 0)
			return (3);
	}
	return (0);
}

static int
zcrx_submit_expect(struct zring *zr, int fd, u32 id, int expected, u64 ud)
{
	struct sqe sqe;
	struct cqe *cqe;

	xmemset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_RECV_ZC;
	sqe.ioprio = IORING_RECV_MULTISHOT;
	sqe.fd = fd;
	sqe.splice_fd_in = (int)id;
	sqe.user_data = ud;
	if (zring_submit(zr, &sqe, 1) != 1)
		return (1);
	cqe = zring_cqe(zr, 0);
	if (cqe->user_data != ud || cqe->res != expected ||
	    (cqe->flags & IORING_CQE_F_MORE) != 0)
		return (2);
	zring_consume(zr, 1);
	return (0);
}

static int
t_zcrx_socket_negative(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;
	int fd, sv[2], client, accepted;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	if (zring_register(&zr, &reg) != 0)
		return (2);
	if (call(SYS_pipe2, (long)sv, 0, 0, 0, 0, 0) != 0 ||
	    zcrx_submit_expect(&zr, sv[0], reg.zcrx_id,
	    -ENOTSOCK, 0x7300) != 0)
		return (3);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
	    (long)sv, 0, 0) != 0 || zcrx_submit_expect(&zr, sv[0],
	    reg.zcrx_id, -EPROTONOSUPPORT, 0x7301) != 0)
		return (4);
	fd = (int)call(SYS_socket, LX_AF_INET, LX_SOCK_DGRAM, 0, 0, 0, 0);
	if (fd < 0 || zcrx_submit_expect(&zr, fd, reg.zcrx_id,
	    -EPROTONOSUPPORT, 0x7302) != 0)
		return (5);
	if (zcrx_tcp_pair(&client, &accepted) != 0 ||
	    zcrx_submit_expect(&zr, accepted, reg.zcrx_id + 99,
	    -EINVAL, 0x7303) != 0)
		return (6);
	return (0);
}

static int
t_zcrx_peer_eof(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;
	struct sqe sqe;
	struct cqe *cqe;
	int client, accepted;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	if (zring_register(&zr, &reg) != 0 ||
	    zcrx_tcp_pair(&client, &accepted) != 0)
		return (2);
	xmemset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_RECV_ZC;
	sqe.ioprio = IORING_RECV_MULTISHOT | IORING_RECVSEND_POLL_FIRST;
	sqe.fd = accepted;
	sqe.splice_fd_in = (int)reg.zcrx_id;
	sqe.user_data = 0x7310;
	if (zring_submit(&zr, &sqe, 0) != 1 ||
	    __atomic_load_n(zr.cqtail, __ATOMIC_ACQUIRE) != 0)
		return (3);
	if (call(SYS_close, client, 0, 0, 0, 0, 0) != 0 ||
	    call(SYS_io_uring_enter, zr.fd, 0, 1, IORING_ENTER_GETEVENTS,
	    0, 0) < 0)
		return (4);
	cqe = zring_cqe(&zr, 0);
	return (cqe->user_data == 0x7310 && cqe->res == 0 &&
	    (cqe->flags & IORING_CQE_F_MORE) == 0 ? 0 : 5);
}

static int
t_zcrx_refill_corruption(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zcrx_rqe *rqe;
	struct zcrx_ctrl ctrl;
	struct zring zr;
	struct sqe sqe;
	volatile u32 *head, *tail;
	u64 first, second, off;
	long rq;
	int client, accepted, i;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	zreg_init(&reg, &area, &region, zcrx_area1, PAGE);
	if (zring_register(&zr, &reg) != 0)
		return (2);
	rq = call(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED,
	    zr.fd, region.mmap_offset);
	if (rq < 0 || zcrx_tcp_pair(&client, &accepted) != 0)
		return (3);
	xmemset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_RECV_ZC;
	sqe.ioprio = IORING_RECV_MULTISHOT;
	sqe.fd = accepted;
	sqe.len = 1;
	sqe.splice_fd_in = (int)reg.zcrx_id;
	if (call(SYS_write, client, (long)"a", 1, 0, 0, 0) != 1 ||
	    zring_submit(&zr, &sqe, 1) != 1)
		return (4);
	first = *(u64 *)((char *)zring_cqe(&zr, 0) + sizeof(struct cqe));
	off = first & ((1ULL << 48) - 1);
	zring_consume(&zr, 2);
	rqe = (struct zcrx_rqe *)((char *)rq + reg.offsets.rqes);
	rqe[0].off = off + 1;
	rqe[1].off = (1ULL << 48) | off;
	rqe[2].off = off;
	rqe[3].off = off;
	for (i = 0; i < 4; i++) {
		rqe[i].len = PAGE;
		rqe[i].pad = 0;
	}
	head = (volatile u32 *)((char *)rq + reg.offsets.head);
	tail = (volatile u32 *)((char *)rq + reg.offsets.tail);
	__atomic_store_n(tail, 4, __ATOMIC_RELEASE);
	xmemset(&ctrl, 0, sizeof(ctrl));
	ctrl.zcrx_id = reg.zcrx_id;
	if (call(SYS_io_uring_register, zr.fd, IORING_REGISTER_ZCRX_CTRL,
	    (long)&ctrl, 0, 0, 0) != 0 ||
	    __atomic_load_n(head, __ATOMIC_ACQUIRE) != 2)
		return (5);
	if (call(SYS_io_uring_register, zr.fd, IORING_REGISTER_ZCRX_CTRL,
	    (long)&ctrl, 0, 0, 0) != 0 ||
	    __atomic_load_n(head, __ATOMIC_ACQUIRE) != 4)
		return (6);
	if (call(SYS_write, client, (long)"b", 1, 0, 0, 0) != 1 ||
	    zring_submit(&zr, &sqe, 1) != 1)
		return (7);
	second = *(u64 *)((char *)zring_cqe(&zr, 0) + sizeof(struct cqe));
	return ((second & ((1ULL << 48) - 1)) == off ? 0 : 8);
}

static int
zcrx_pending_exit_child(void *arg __attribute__((unused)))
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;
	struct sqe sqe;
	int client, accepted;

	if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
	    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
		return (1);
	zreg_init(&reg, &area, &region, zcrx_area0, sizeof(zcrx_area0));
	if (zring_register(&zr, &reg) != 0 ||
	    zcrx_tcp_pair(&client, &accepted) != 0)
		return (2);
	xmemset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_RECV_ZC;
	sqe.ioprio = IORING_RECV_MULTISHOT | IORING_RECVSEND_POLL_FIRST;
	sqe.fd = accepted;
	sqe.splice_fd_in = (int)reg.zcrx_id;
	if (zring_submit(&zr, &sqe, 0) != 1 ||
	    __atomic_load_n(zr.cqtail, __ATOMIC_ACQUIRE) != 0)
		return (3);
	return (0);
}

static int
t_zcrx_pending_exit(void)
{
	int i;

	for (i = 0; i < 16; i++)
		if (run_child(zcrx_pending_exit_child, 0) != 0)
			return (i + 1);
	return (0);
}

static int
t_zcrx_pending_close(void)
{
	struct zcrx_ifq_reg reg;
	struct zcrx_area_reg area;
	struct zcrx_region_desc region;
	struct zring zr;
	struct sqe sqe;
	int client, accepted, i;

	for (i = 0; i < 16; i++) {
		if (zring_open(&zr, IORING_SETUP_SINGLE_ISSUER |
		    IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32) != 0)
			return (1);
		zreg_init(&reg, &area, &region, zcrx_area0,
		    sizeof(zcrx_area0));
		if (zring_register(&zr, &reg) != 0 ||
		    zcrx_tcp_pair(&client, &accepted) != 0)
			return (2);
		xmemset(&sqe, 0, sizeof(sqe));
		sqe.opcode = IORING_OP_RECV_ZC;
		sqe.ioprio = IORING_RECV_MULTISHOT |
		    IORING_RECVSEND_POLL_FIRST;
		sqe.fd = accepted;
		sqe.splice_fd_in = (int)reg.zcrx_id;
		if (zring_submit(&zr, &sqe, 0) != 1 ||
		    __atomic_load_n(zr.cqtail, __ATOMIC_ACQUIRE) != 0 ||
		    call(SYS_close, zr.fd, 0, 0, 0, 0, 0) != 0)
			return (3);
	}
	return (0);
}

/* Authoritative negotiation contract: the opcodes we cannot implement are
 * reported absent by PROBE, and a representative supported set is present. */
static int t_negotiation_probe(void)
{
	struct probe pr;
	int i;
	static const int sup[] = { IORING_OP_NOP, IORING_OP_READ, IORING_OP_WRITE,
	    IORING_OP_POLL_ADD, IORING_OP_TIMEOUT, IORING_OP_SOCKET,
	    IORING_OP_OPENAT, IORING_OP_PROVIDE_BUFFERS,
	    IORING_OP_RECV_ZC, IORING_OP_URING_CMD,
	    64 /* URING_CMD128 */ };
	if (ring_setup(8) < 0) return (1);
	xmemset(&pr, 0, sizeof(pr));
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PROBE,
	    (long)&pr, 128, 0, 0) != 0) return (2);
	for (i = 0; i < (int)(sizeof(sup) / sizeof(sup[0])); i++)
		if ((pr.ops[sup[i]].flags & IO_URING_OP_SUPPORTED) == 0)
			return (200 + sup[i]);
	return (0);
}
static int t_waitid_badargs(void)    { return sweep_einval(50); }
static int t_futex_waitv_badargs(void) { return sweep_einval(53); }
static int t_read_multishot_unsup(void) { return sweep_einval(49); }

/* ================= stress ================= */
static int t_stress_1000(void)
{
	struct cqe c[8]; int b, i, n, total = 0;
	if (ring_setup(8) < 0) return (1);
	for (b = 0; b < 125; b++) {
		for (i = 0; i < 8; i++) iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 1);
		if (iou_flush(8, 8) != 8) return (2);
		n = iou_reap(c, 8); if (n != 8) return (3);
		total += n;
	}
	return (total == 1000 ? 0 : 4);
}
static int t_stress_timeouts(void)
{
	static struct cqe c[64]; struct kts ts; int i, n, total = 0;
	if (ring_setup(64) < 0) return (1);		/* cq = 128 */
	ts.tv_sec = 0; ts.tv_nsec = 15000000LL;
	for (i = 0; i < 40; i++) iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x1);
	if (iou_flush(40, 40) != 40) return (2);
	while (total < 40) {
		n = iou_reap(c, 64);
		if (n == 0) {
			if (call(SYS_io_uring_enter, fd_ring, 0, 40 - total,
			    IORING_ENTER_GETEVENTS, 0, 0) < 0) return (3);
			continue;
		}
		for (i = 0; i < n; i++) if (c[i].res != -ELINUX_ETIME) return (4);
		total += n;
	}
	return (0);
}
static int t_stress_fixed(void)
{
	long tf; int fds[1], i, res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_sf"); if (tf < 0) return (2);
	if (sub1(tf, IORING_OP_WRITE, "stress__", 8, 0, 0, 0x1) != 8) return (3);
	fds[0] = (int)tf;
	if (iou_reg(IORING_REGISTER_FILES, fds, 1) != 0) return (4);
	(void)sys1(SYS_close, tf);
	for (i = 0; i < 100; i++) {
		char rb[8];
		xmemset(rb, 0, sizeof(rb));
		res = fixed_op(IORING_OP_READ, 0, rb, 8, 0, 0, IOSQE_FIXED_FILE, 0x100 + i);
		if (res != 8 || xmemcmp(rb, "stress__", 8) != 0) return (5);
	}
	return (0);
}

/* ================= waitid / futex_waitv ================= */
static int t_waitid_echild(void)
{
	static char siginfo[128];
	u32 slot;
	struct cqe c[2];
	int n, res = 0;
	if (ring_setup(8) < 0) return (1);
	/* idtype=len(P_ALL), id=fd(0), options=file_index, siginfo=addr2(off) */
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_WAITID, 0, 0 /* id */, (u64)(unsigned long)siginfo,
	    0 /* addr must be 0 */, LX_P_ALL, 0, 0x1);
	g_sqes[slot].splice_fd_in = LX_WEXITED | LX_WNOHANG;	/* options */
	if (iou_flush(1, 1) != 1) return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res)) return (3);
	/* no children in this fresh process -> ECHILD */
	return (res == -ELINUX_ECHILD ? 0 : 4);
}

static int
t_waitid_sqe_badfields(void)
{
    u32 info[32];
    struct cqe c[2];
    u32 slot;
    int i, n, res;

    if (ring_setup(8) < 0)
        return (1);
    for (i = 0; i < 4; i++) {
        xmemset(info, 0xa5, sizeof(info));
        slot = g_sqi & g_sqmask;
        iou_sqe(IORING_OP_WAITID, 0, 0,
            (u64)(unsigned long)info, 0, LX_P_ALL, 0, 0xd80 + i);
        g_sqes[slot].splice_fd_in = LX_WEXITED | LX_WNOHANG;
        if (i == 0) g_sqes[slot].addr = 1;
        if (i == 1) g_sqes[slot].buf_index = 1;
        if (i == 2) g_sqes[slot].pad2[0] = 1;
        if (i == 3) g_sqes[slot].rw_flags = 1;
        if (iou_flush(1, 1) != 1)
            return (2);
        n = iou_reap(c, 2);
        res = 0;
        if (n != 1 || !cqe_find(c, n, 0xd80 + i, &res) ||
            res != -EINVAL || ((u8 *)info)[0] != 0xa5) {
            put("WAITID_SQE_BADFIELDS_DIAG "); putnum(i);
            put(" "); putnum(res); put("\n");
            return (3);
        }
    }
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
waitid_sqe(int which, int id, u32 options, void *info, u32 bad_field,
    u64 ud)
{
    struct cqe c[2];
    u32 slot = g_sqi & g_sqmask;
    int res;

    iou_sqe(IORING_OP_WAITID, 0, id, (u64)(unsigned long)info,
        (void *)(unsigned long)bad_field, (u32)which, 0, ud);
    g_sqes[slot].splice_fd_in = (int)options;
    if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
        !cqe_find(c, 1, ud, &res))
        return (-100000);
    return (res);
}

/* Child exit and cancellation may race, but never lose the child state. */
static int
t_waitid_exit_cancel_race(void)
{
    struct timespec delay = { 0, 20000000 };
    u32 info[32], slot;
    struct cqe c[4];
    long pid;
    int i, n, wait_res, cancel_res, status, reaped;

    for (i = 0; i < 8; i++) {
        if (ring_setup(8) < 0) return (1);
        pid = fork_process();
        if (pid < 0) return (2);
        if (pid == 0) {
            (void)sys2(SYS_nanosleep, &delay, 0);
            (void)sys1(SYS_exit_group, 51);
        }
        xmemset(info, 0xa5, sizeof(info));
        slot = g_sqi & g_sqmask;
        iou_sqe(IORING_OP_WAITID, 0, (int)pid,
            (u64)(unsigned long)info, 0, LX_P_PID, 0, 0xc10);
        g_sqes[slot].splice_fd_in = LX_WEXITED;
        if (iou_flush(1, 0) != 1) return (3);
        (void)sys2(SYS_nanosleep, &delay, 0);
        iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0,
            (void *)(unsigned long)0xc10, 0, 0, 0xc11);
        if (iou_flush(1, 2) != 1) return (4);
        n = iou_reap(c, 4);
        if (n != 2 || !cqe_find(c, n, 0xc10, &wait_res) ||
            !cqe_find(c, n, 0xc11, &cancel_res)) return (5);
        status = 0;
        reaped = (int)sys4(SYS_wait4, pid, &status, 0, 0);
        if (wait_res == 0) {
            if (reaped != -ELINUX_ECHILD || info[0] != SIGCHLD) {
                put("WAITID_RACE_FAIL "); putnum(i); put(" ");
                putnum(wait_res); put(" "); putnum(cancel_res);
                put(" "); putnum(reaped); put(" ");
                putnum(info[0]); put("\n");
                return (6);
            }
        } else if (wait_res == -ELINUX_ECANCELED) {
            if (reaped != pid || info[0] != 0) {
                put("WAITID_RACE_FAIL "); putnum(i); put(" ");
                putnum(wait_res); put(" "); putnum(cancel_res);
                put(" "); putnum(reaped); put(" ");
                putnum(info[0]); put("\n");
                return (7);
            }
        } else return (8);
        (void)sys1(SYS_close, fd_ring);
    }
    return (0);
}

static int
t_waitid_lifecycle(void)
{
    struct timespec delay = { 0, 200000000 };
    u32 info[32], second[32];
    long pid;
    int status;

    if (ring_setup(8) < 0)
        return (1);
    pid = fork_process();
    if (pid < 0)
        return (2);
    if (pid == 0) {
        (void)sys2(SYS_nanosleep, &delay, 0);
        (void)sys1(SYS_exit_group, 23);
    }

    /* An existing child that has not exited gives zeroed siginfo. */
    xmemset(info, 0xa5, sizeof(info));
    if (waitid_sqe(LX_P_PID, (int)pid, LX_WEXITED | LX_WNOHANG,
        info, 0, 0xb00) != 0 || info[0] != 0)
        return (3);
    if (waitid_sqe(99, (int)pid, LX_WEXITED | LX_WNOHANG,
        info, 0, 0xb01) != -EINVAL ||
        waitid_sqe(LX_P_PID, 0, LX_WEXITED | LX_WNOHANG,
        info, 0, 0xb02) != -EINVAL ||
        waitid_sqe(LX_P_PID, (int)pid, 1U << 27,
        info, 0, 0xb03) != -EINVAL ||
        waitid_sqe(LX_P_PID, (int)pid, LX_WEXITED,
        info, 1, 0xb04) != -EINVAL)
        return (4);

    /* WNOWAIT observes exit without reaping; a second wait consumes it. */
    xmemset(info, 0, sizeof(info));
    if (waitid_sqe(LX_P_PID, (int)pid, LX_WEXITED | LX_WNOWAIT,
        info, 0, 0xb05) != 0 || info[0] != SIGCHLD ||
        info[2] != 1 /* CLD_EXITED */ || info[4] != (u32)pid ||
        info[6] != 23)
        return (5);
    xmemset(second, 0, sizeof(second));
    if (waitid_sqe(LX_P_PID, (int)pid, LX_WEXITED,
        second, 0, 0xb06) != 0 || second[0] != SIGCHLD ||
        second[4] != (u32)pid || second[6] != 23)
        return (6);
    status = 0;
    if (sys4(SYS_wait4, pid, &status, LX_WNOHANG, 0) !=
        -ELINUX_ECHILD)
        return (7);
    if (waitid_sqe(LX_P_PID, (int)pid, LX_WEXITED | LX_WNOHANG,
        info, 0, 0xb07) != -ELINUX_ECHILD)
        return (8);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

/* A pidfd is an ID for WAITID, not the ring's target descriptor. */
static int
t_waitid_pidfd(void)
{
    struct timespec delay = { 0, 200000000 };
    u32 info[32];
    long pid, pfd;
    int status;

    if (ring_setup(8) < 0)
        return (1);
    pid = fork_process();
    if (pid < 0)
        return (2);
    if (pid == 0) {
        (void)sys2(SYS_nanosleep, &delay, 0);
        (void)sys1(SYS_exit_group, 31);
    }
    pfd = sys2(SYS_pidfd_open, pid, 0);
    if (pfd < 0)
        return (3);
    xmemset(info, 0xa5, sizeof(info));
    if (waitid_sqe(LX_P_PIDFD, (int)pfd, LX_WEXITED | LX_WNOHANG,
        info, 0, 0xb20) != 0 || info[0] != 0)
        return (4);
    {
        int wrong_fd, bad_fd;

        wrong_fd = waitid_sqe(LX_P_PIDFD, fd_ring,
            LX_WEXITED | LX_WNOHANG, info, 0, 0xb21);
        bad_fd = waitid_sqe(LX_P_PIDFD, -1,
            LX_WEXITED | LX_WNOHANG, info, 0, 0xb22);
        if (wrong_fd != -EBADF || bad_fd != -EINVAL) {
            put("WAITID_PIDFD_DIAG "); putnum(wrong_fd); put(" ");
            putnum(bad_fd); put("\n");
            return (5);
        }
    }
    xmemset(info, 0, sizeof(info));
    if (waitid_sqe(LX_P_PIDFD, (int)pfd, LX_WEXITED | LX_WNOWAIT,
        info, 0, 0xb23) != 0 || info[0] != SIGCHLD ||
        info[2] != 1 || info[4] != (u32)pid || info[6] != 31)
        return (6);
    xmemset(info, 0, sizeof(info));
    if (waitid_sqe(LX_P_PIDFD, (int)pfd, LX_WEXITED,
        info, 0, 0xb24) != 0 || info[4] != (u32)pid || info[6] != 31)
        return (7);
    status = 0;
    if (sys4(SYS_wait4, pid, &status, LX_WNOHANG, 0) !=
        -ELINUX_ECHILD ||
        waitid_sqe(LX_P_PIDFD, (int)pfd, LX_WEXITED | LX_WNOHANG,
        info, 0, 0xb25) != -ELINUX_ECHILD)
        return (8);
    (void)sys1(SYS_close, pfd);
    if (waitid_sqe(LX_P_PIDFD, (int)pfd, LX_WEXITED | LX_WNOHANG,
        info, 0, 0xb26) != -EBADF)
        return (9);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

/* WAITID delivers stop and continue transitions as well as exits. */
static int
t_waitid_stop_continue(void)
{
    struct timespec delay = { 1, 0 };
    u32 info[32];
    long pid;
    int status;

    if (ring_setup(8) < 0)
        return (1);
    pid = fork_process();
    if (pid < 0)
        return (2);
    if (pid == 0) {
        (void)sys2(SYS_nanosleep, &delay, 0);
        (void)sys1(SYS_exit_group, 32);
    }
    if (sys2(SYS_kill, pid, SIGSTOP) != 0)
        return (3);
    xmemset(info, 0, sizeof(info));
    if (waitid_sqe(LX_P_PID, (int)pid, LX_WSTOPPED,
        info, 0, 0xb30) != 0 || info[0] != SIGCHLD ||
        info[2] != 5 /* CLD_STOPPED */ || info[4] != (u32)pid ||
        info[6] != SIGSTOP)
        return (4);
    if (sys2(SYS_kill, pid, SIGCONT) != 0)
        return (5);
    xmemset(info, 0, sizeof(info));
    if (waitid_sqe(LX_P_PID, (int)pid, LX_WCONTINUED,
        info, 0, 0xb31) != 0 || info[0] != SIGCHLD ||
        info[2] != 6 /* CLD_CONTINUED */ || info[4] != (u32)pid ||
        info[6] != SIGCONT)
        return (6);
    xmemset(info, 0, sizeof(info));
    if (waitid_sqe(LX_P_PID, (int)pid, LX_WEXITED,
        info, 0, 0xb32) != 0 || info[0] != SIGCHLD ||
        info[2] != 1 || info[4] != (u32)pid || info[6] != 32)
        return (7);
    status = 0;
    if (sys4(SYS_wait4, pid, &status, LX_WNOHANG, 0) !=
        -ELINUX_ECHILD)
        return (8);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

/* Submission must return before the child exits; completion then reaps it. */
static int
t_waitid_pending_exit(void)
{
    struct timespec delay = { 0, 200000000 };
    u32 info[32], slot;
    struct cqe c[2];
    long pid;
    int n, res, status;

    if (ring_setup(8) < 0)
        return (1);
    pid = fork_process();
    if (pid < 0)
        return (2);
    if (pid == 0) {
        (void)sys2(SYS_nanosleep, &delay, 0);
        (void)sys1(SYS_exit_group, 37);
    }
    xmemset(info, 0xa5, sizeof(info));
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_WAITID, 0, (int)pid,
        (u64)(unsigned long)info, 0, LX_P_PID, 0, 0xb12);
    g_sqes[slot].splice_fd_in = LX_WEXITED;
    if (iou_flush(1, 0) != 1)
        return (3);
    if (info[0] != 0xa5a5a5a5U)
        return (4);
    if (call(SYS_io_uring_enter, fd_ring, 0, 1,
        IORING_ENTER_GETEVENTS, 0, 0) < 0)
        return (5);
    n = iou_reap(c, 2);
    if (n != 1 || !cqe_find(c, n, 0xb12, &res) || res != 0 ||
        info[0] != SIGCHLD || info[2] != 1 ||
        info[4] != (u32)pid || info[6] != 37)
        return (6);
    status = 0;
    if (sys4(SYS_wait4, pid, &status, LX_WNOHANG, 0) !=
        -ELINUX_ECHILD)
        return (7);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

/* Linux accepts a null siginfo for both a live WNOHANG child and exit. */
static int
t_waitid_null_info(void)
{
    struct timespec delay = { 0, 200000000 };
    long pid;
    int status;

    if (ring_setup(8) < 0)
        return (1);
    pid = fork_process();
    if (pid < 0)
        return (2);
    if (pid == 0) {
        (void)sys2(SYS_nanosleep, &delay, 0);
        (void)sys1(SYS_exit_group, 39);
    }
    if (waitid_sqe(LX_P_PID, (int)pid, LX_WEXITED | LX_WNOHANG,
        0, 0, 0xb15) != 0)
        return (3);
    if (waitid_sqe(LX_P_PID, (int)pid, LX_WEXITED,
        0, 0, 0xb16) != 0)
        return (4);
    status = 0;
    if (sys4(SYS_wait4, pid, &status, LX_WNOHANG, 0) !=
        -ELINUX_ECHILD)
        return (5);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

/* The pidfd is resolved when submitted, before userspace can reuse it. */
static int
t_waitid_pending_pidfd_close(void)
{
    struct timespec delay = { 0, 200000000 };
    u32 info[32], slot;
    struct cqe c[2];
    long pid, pfd;
    int n, res;

    if (ring_setup(8) < 0)
        return (1);
    pid = fork_process();
    if (pid < 0)
        return (2);
    if (pid == 0) {
        (void)sys2(SYS_nanosleep, &delay, 0);
        (void)sys1(SYS_exit_group, 41);
    }
    pfd = sys2(SYS_pidfd_open, pid, 0);
    if (pfd < 0)
        return (3);
    xmemset(info, 0xa5, sizeof(info));
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_WAITID, 0, (int)pfd,
        (u64)(unsigned long)info, 0, LX_P_PIDFD, 0, 0xb13);
    g_sqes[slot].splice_fd_in = LX_WEXITED;
    if (iou_flush(1, 0) != 1 || info[0] != 0xa5a5a5a5U)
        return (4);
    if (sys1(SYS_close, pfd) != 0)
        return (5);
    if (call(SYS_io_uring_enter, fd_ring, 0, 1,
        IORING_ENTER_GETEVENTS, 0, 0) < 0)
        return (6);
    n = iou_reap(c, 2);
    if (n != 1 || !cqe_find(c, n, 0xb13, &res) || res != 0 ||
        info[0] != SIGCHLD || info[4] != (u32)pid || info[6] != 41)
        return (7);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

/* Closing a ring cancels a pending wait without reaping its child. */
static int
t_waitid_close_pending(void)
{
    struct timespec delay = { 0, 200000000 };
    u32 info[32], slot;
    long pid;
    int status;

    if (ring_setup(8) < 0)
        return (1);
    pid = fork_process();
    if (pid < 0)
        return (2);
    if (pid == 0) {
        (void)sys2(SYS_nanosleep, &delay, 0);
        (void)sys1(SYS_exit_group, 43);
    }
    xmemset(info, 0xa5, sizeof(info));
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_WAITID, 0, (int)pid,
        (u64)(unsigned long)info, 0, LX_P_PID, 0, 0xb14);
    g_sqes[slot].splice_fd_in = LX_WEXITED;
    if (iou_flush(1, 0) != 1)
        return (3);
    if (sys1(SYS_close, fd_ring) != 0)
        return (4);
    status = 0;
    if (sys4(SYS_wait4, pid, &status, 0, 0) != pid ||
        ((status >> 8) & 0xff) != 43)
        return (5);
    return (0);
}

/* Opcode-wide cancellation must resolve both process waiters once. */
static int
t_waitid_cancel_op_all(void)
{
    struct timespec delay = { 0, 500000000 };
    u32 info[2][32], slot;
    struct cqe c[4];
    long pid[2];
    int i, n, res, status;

    if (ring_setup(8) < 0)
        return (1);
    for (i = 0; i < 2; i++) {
        pid[i] = fork_process();
        if (pid[i] < 0)
            return (2);
        if (pid[i] == 0) {
            (void)sys2(SYS_nanosleep, &delay, 0);
            (void)sys1(SYS_exit_group, 45 + i);
        }
        xmemset(info[i], 0xa5, sizeof(info[i]));
        slot = g_sqi & g_sqmask;
        iou_sqe(IORING_OP_WAITID, 0, (int)pid[i],
            (u64)(unsigned long)info[i], 0, LX_P_PID, 0, 0xb20 + i);
        g_sqes[slot].splice_fd_in = LX_WEXITED;
    }
    if (iou_flush(2, 0) != 2 || iou_reap(c, 4) != 0)
        return (3);
    iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, 0,
        IORING_OP_WAITID,
        IORING_ASYNC_CANCEL_OP | IORING_ASYNC_CANCEL_ALL, 0xb22);
    if (iou_flush(1, 3) != 1)
        return (4);
    n = iou_reap(c, 4);
    if (n != 3 || !cqe_find(c, n, 0xb22, &res) || res != 1)
        return (5);
    for (i = 0; i < 2; i++) {
        if (!cqe_find(c, n, 0xb20 + i, &res) ||
            res != -ELINUX_ECANCELED || info[i][0] != 0)
            return (6 + i);
        status = 0;
        if (sys4(SYS_wait4, pid[i], &status, 0, 0) != pid[i] ||
            ((status >> 8) & 0xff) != 45 + i)
            return (8 + i);
    }
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

static int
t_waitid_link_timeout(void)
{
    struct timespec delay = { 0, 500000000 };
    struct kts ts = { 0, 20000000 };
    u32 info[32], slot;
    struct cqe c[3];
    long pid;
    int n, res, status;

    if (ring_setup(8) < 0)
        return (1);
    pid = fork_process();
    if (pid < 0)
        return (2);
    if (pid == 0) {
        (void)sys2(SYS_nanosleep, &delay, 0);
        (void)sys1(SYS_exit_group, 47);
    }
    xmemset(info, 0xa5, sizeof(info));
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_WAITID, IOSQE_IO_LINK, (int)pid,
        (u64)(unsigned long)info, 0, LX_P_PID, 0, 0xb23);
    g_sqes[slot].splice_fd_in = LX_WEXITED;
    iou_sqe(IORING_OP_LINK_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0xb24);
    if (iou_flush(2, 2) != 2)
        return (3);
    n = iou_reap(c, 3);
    if (n != 2 || !cqe_find(c, n, 0xb23, &res) ||
        res != -ELINUX_ECANCELED ||
        !cqe_find(c, n, 0xb24, &res) || res != 1 || info[0] != 0)
        return (4);
    status = 0;
    if (sys4(SYS_wait4, pid, &status, 0, 0) != pid ||
        ((status >> 8) & 0xff) != 47)
        return (5);
    (void)sys1(SYS_close, fd_ring);
    return (0);
}

/* A pending child wait must remain cancellable while the child is alive. */
static int
t_waitid_cancel_pending(void)
{
    struct timespec delay = { 0, 500000000 };
    u32 info[32];
    struct cqe c[4];
    long pid;
    int n, wait_res, cancel_res, status, submitted;
    u32 slot;

    if (ring_setup(8) < 0)
        return (1);
    pid = fork_process();
    if (pid < 0)
        return (2);
    if (pid == 0) {
        (void)sys2(SYS_nanosleep, &delay, 0);
        (void)sys1(SYS_exit_group, 29);
    }

    xmemset(info, 0xa5, sizeof(info));
    slot = g_sqi & g_sqmask;
    iou_sqe(IORING_OP_WAITID, 0, (int)pid,
        (u64)(unsigned long)info, 0, LX_P_PID, 0, 0xb10);
    g_sqes[slot].splice_fd_in = LX_WEXITED;
    submitted = iou_flush(1, 0);
    if (submitted != 1)
        return (100 - submitted);
    iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0,
        (void *)(unsigned long)0xb10, 0, 0, 0xb11);
    submitted = iou_flush(1, 2);
    if (submitted != 1)
        return (120 - submitted);
    n = iou_reap(c, 4);
    if (n != 2 || !cqe_find(c, n, 0xb10, &wait_res) ||
        !cqe_find(c, n, 0xb11, &cancel_res))
        return (4);
    status = 0;
    if (sys4(SYS_wait4, pid, &status, 0, 0) != pid ||
        ((status >> 8) & 0xff) != 29)
        return (5);
    if (wait_res != -ELINUX_ECANCELED || cancel_res != 1 || info[0] != 0) {
        put("WAITID_CANCEL_DIAG "); putnum(wait_res); put(" ");
        putnum(cancel_res); put(" "); putnum(info[0]); put("\n");
        return (6);
    }
    (void)sys1(SYS_close, fd_ring);
    return (0);
}



static int t_futex_waitv_eagain(void)
{
	static u32 word = 5;
	struct l_futex_waitv wv;
	struct cqe c[2];
	int n, res = 0;
	if (ring_setup(8) < 0) return (1);
	xmemset(&wv, 0, sizeof(wv));
	wv.val = 6;			/* expect 6 while *word == 5 */
	wv.uaddr = (u64)(unsigned long)&word;
	wv.flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
	/* waiters=addr, nr=len */
	iou_sqe(IORING_OP_FUTEX_WAITV, 0, 0, 0, &wv, 1, 0, 0x1);
	if (iou_flush(1, 1) != 1) return (2);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x1, &res)) return (3);
	return (res == -EAGAIN ? 0 : 4);
}

/* ================= ioprio network options ================= */
static int
sub1_ioprio(int fd, u8 op, void *addr, u32 len, u32 misc, u16 ioprio, u64 ud)
{
	struct cqe c[2];
	u32 slot;
	int n, res = 0;

	slot = g_sqi & g_sqmask;
	iou_sqe(op, 0, fd, 0, addr, len, misc, ud);
	g_sqes[slot].ioprio = ioprio;
	if (iou_flush(1, 1) != 1)
		return (-100000);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, ud, &res))
		return (-100001);
	return (res);
}

static int
t_ioprio_net_invalid(void)
{
	static const u8 ops[] = { IORING_OP_SEND, IORING_OP_RECV,
	    IORING_OP_SENDMSG, IORING_OP_RECVMSG, IORING_OP_ACCEPT };
	int i;

	if (ring_setup(8) < 0)
		return (1);
	for (i = 0; i < (int)(sizeof(ops) / sizeof(ops[0])); i++)
		if (sub1_ioprio(-1, ops[i], 0, 0, 0, 0x40,
		    0x900 + (u64)i) != -EINVAL)
			return (2 + i);
	return (0);
}

static int
t_ioprio_poll_first_recv(void)
{
	struct cqe c[2];
	u32 slot;
	int sv[2], n, res;
	char b = 0;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	if (call(SYS_write, sv[0], (long)"R", 1, 0, 0, 0) != 1)
		return (3);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECV, 0, sv[1], 0, &b, 1, 0, 0x911);
	g_sqes[slot].ioprio = IORING_RECVSEND_POLL_FIRST;
	if (iou_flush(1, 0) != 1)
		return (4);
	/* An already-ready poll may fire during the submission enter. */
	n = iou_reap(c, 2);
	if (n == 0) {
		if (call(SYS_io_uring_enter, fd_ring, 0, 1,
		    IORING_ENTER_GETEVENTS, 0, 0) < 0)
			return (5);
		n = iou_reap(c, 2);
	}
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (n != 1 || !cqe_find(c, n, 0x911, &res))
		return (7);
	return (res == 1 && b == 'R' ? 0 : 8);
}

static int
t_ioprio_poll_first_send(void)
{
	struct cqe c[2];
	u32 slot;
	int sv[2], n, res;
	char b = 0;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SEND, 0, sv[0], 0, (void *)"S", 1, 0, 0x912);
	g_sqes[slot].ioprio = IORING_RECVSEND_POLL_FIRST;
	if (iou_flush(1, 0) != 1)
		return (3);
	n = iou_reap(c, 2);
	if (n == 0) {
		if (call(SYS_io_uring_enter, fd_ring, 0, 1,
		    IORING_ENTER_GETEVENTS, 0, 0) < 0)
			return (4);
		n = iou_reap(c, 2);
	}
	if (call(SYS_read, sv[1], (long)&b, 1, 0, 0, 0) != 1)
		return (6);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (n != 1 || !cqe_find(c, n, 0x912, &res))
		return (7);
	return (res == 1 && b == 'S' ? 0 : 8);
}

static int
t_ioprio_poll_first_cancel(void)
{
	struct cqe c[4];
	u32 slot;
	int sv[2], n, res;
	char b;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECV, 0, sv[1], 0, &b, 1, 0, 0x913);
	g_sqes[slot].ioprio = IORING_RECVSEND_POLL_FIRST;
	if (iou_flush(1, 0) != 1 || iou_reap(c, 4) != 0)
		return (3);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0x913, 0, 0,
	    0x914);
	if (iou_flush(1, 2) != 1)
		return (4);
	n = iou_reap(c, 4);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (!cqe_find(c, n, 0x914, &res) || res != 0)
		return (5);
	if (!cqe_find(c, n, 0x913, &res) || res != -ELINUX_ECANCELED)
		return (6);
	return (0);
}

/* ================= POLL_ADD / POLL_REMOVE ================= */
static int t_poll_add_ready(void)
{
	int sv[2], res;
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	/* make sv[1] readable */
	if (call(SYS_write, sv[0], (long)"p", 1, 0, 0, 0) != 1) return (3);
	/* POLL_ADD: fd=sv[1], events=poll32_events(misc) */
	res = sub1(sv[1], IORING_OP_POLL_ADD, 0, 0, 0, LX_POLLIN, 0x1);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return ((res & LX_POLLIN) ? 0 : 4);
}
static int t_poll_add_deferred(void)
{
	int sv[2], res;
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	/* arm the poll while sv[1] is NOT yet readable */
	iou_sqe(IORING_OP_POLL_ADD, 0, sv[1], 0, 0, 0, LX_POLLIN, 0x1);
	if (iou_flush(1, 0) != 1) return (3);
	/* now make it readable and wait */
	if (call(SYS_write, sv[0], (long)"q", 1, 0, 0, 0) != 1) return (4);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS, 0, 0) < 0)
		return (5);
	{ struct cqe c[2]; int n = iou_reap(c, 2);
	  if (n != 1 || !cqe_find(c, n, 0x1, &res)) return (6); }
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return ((res & LX_POLLIN) ? 0 : 7);
}
static int t_poll_remove(void)
{
	int sv[2], res; struct cqe c[4]; int n;
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	/* arm a poll that will not become ready, then cancel it */
	iou_sqe(IORING_OP_POLL_ADD, 0, sv[1], 0, 0, 0, LX_POLLIN, 0xA1);
	if (iou_flush(1, 0) != 1) return (3);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0xA1, 0, 0, 0xA2);
	if (iou_flush(1, 2) != 1) return (4);
	n = iou_reap(c, 4);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (!cqe_find(c, n, 0xA2, &res) || res != 0) return (5);
	if (!cqe_find(c, n, 0xA1, &res) || res != -ELINUX_ECANCELED) return (6);
	return (0);
}
static int t_poll_remove_notfound(void)
{
	if (ring_setup(8) < 0) return (1);
	return (sub1(-1, IORING_OP_POLL_REMOVE, (void *)0xDEAD, 0, 0, 0, 0x1)
	    == -ENOENT ? 0 : 2);
}
static int t_poll_update_userdata(void)
{
	int sv[2], n, res;
	struct cqe c[4];

	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	iou_sqe(IORING_OP_POLL_ADD, 0, sv[1], 0, 0, 0, LX_POLLIN, 0xa1);
	if (iou_flush(1, 0) != 1) return (3);
	iou_sqe(IORING_OP_POLL_REMOVE, 0, -1, 0xb1, (void *)0xa1,
	    IORING_POLL_UPDATE_USER_DATA, 0, 0xc1);
	if (iou_flush(1, 1) != 1) return (4);
	n = iou_reap(c, 4);
	if (n != 1 || !cqe_find(c, n, 0xc1, &res) || res != 0) return (5);
	if (sub1(-1, IORING_OP_POLL_REMOVE, (void *)0xa1, 0, 0, 0, 0xc2) != -ENOENT)
		return (6);
	if (call(SYS_write, sv[0], (long)"u", 1, 0, 0, 0) != 1) return (7);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS, 0, 0) < 0)
		return (8);
	n = iou_reap(c, 4);
	return (n == 1 && cqe_find(c, n, 0xb1, &res) && (res & LX_POLLIN) ? 0 : 9);
}

static int t_poll_update_events(void)
{
	int sv[2], n, res;
	struct cqe c[4];

	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	iou_sqe(IORING_OP_POLL_ADD, 0, sv[1], 0, 0, 0, LX_POLLIN, 0xa1);
	if (iou_flush(1, 0) != 1) return (3);
	/* A stream socket is writable now; changing READ to WRITE must wake it. */
	iou_sqe(IORING_OP_POLL_REMOVE, 0, -1, 0, (void *)0xa1,
	    IORING_POLL_UPDATE_EVENTS, 4, 0xc1);
	if (iou_flush(1, 2) != 1) return (4);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xc1, &res) || res != 0) return (5);
	if (!cqe_find(c, n, 0xa1, &res) || !(res & 4)) return (6);
	return (0);
}

static int t_poll_update_combined(void)
{
	int sv[2], n, res, more = 0;
	struct cqe c[6];
	char byte;

	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	iou_sqe(IORING_OP_POLL_ADD, 0, sv[1], 0, 0, 0, LX_POLLIN, 0xa1);
	if (iou_flush(1, 0) != 1) return (3);
	iou_sqe(IORING_OP_POLL_REMOVE, 0, -1, 0xb1, (void *)0xa1,
	    IORING_POLL_ADD_MULTI | IORING_POLL_UPDATE_EVENTS |
	    IORING_POLL_UPDATE_USER_DATA, LX_POLLIN, 0xc1);
	if (iou_flush(1, 1) != 1) return (4);
	n = iou_reap(c, 6);
	if (n != 1 || !cqe_find(c, n, 0xc1, &res) || res != 0) return (5);
	if (call(SYS_write, sv[0], (long)"a", 1, 0, 0, 0) != 1) return (6);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS, 0, 0) < 0)
		return (7);
	n = iou_reap(c, 6);
	for (int i = 0; i < n; i++) if (c[i].user_data == 0xb1 &&
	    (c[i].flags & IORING_CQE_F_MORE) && (c[i].res & LX_POLLIN)) more++;
	if (more != 1 || call(SYS_read, sv[1], (long)&byte, 1, 0, 0, 0) != 1)
		return (8);
	if (call(SYS_write, sv[0], (long)"b", 1, 0, 0, 0) != 1) return (9);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS, 0, 0) < 0)
		return (10);
	n = iou_reap(c, 6); more = 0;
	for (int i = 0; i < n; i++) if (c[i].user_data == 0xb1 &&
	    (c[i].flags & IORING_CQE_F_MORE) && (c[i].res & LX_POLLIN)) more++;
	if (more != 1) return (11);
	iou_sqe(IORING_OP_POLL_REMOVE, 0, -1, 0, (void *)0xb1, 0, 0, 0xc2);
	if (iou_flush(1, 2) != 1) return (12);
	n = iou_reap(c, 6);
	if (!cqe_find(c, n, 0xc2, &res) || res != 0) return (13);
	if (!cqe_find(c, n, 0xb1, &res) || res != -ELINUX_ECANCELED) return (14);
	return (0);
}

static int t_poll_update_invalid(void)
{
	int sv[2], res;
	struct cqe c[4];

	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	iou_sqe(IORING_OP_POLL_ADD, 0, sv[1], 0, 0, 0, LX_POLLIN, 0xa1);
	if (iou_flush(1, 0) != 1) return (3);
	if (sub1(-1, IORING_OP_POLL_REMOVE, (void *)0xa1,
	    IORING_POLL_ADD_MULTI, 0, 0, 0xc1) != -EINVAL) return (4);
	if (sub1(-1, IORING_OP_POLL_REMOVE, (void *)0xa1, 0, 0x55, 0, 0xc2)
	    != -EINVAL) return (5);
	if (sub1(-1, IORING_OP_POLL_REMOVE, (void *)0xa1, 0, 0, LX_POLLIN, 0xc3)
	    != -EINVAL) return (6);
	if (sub1(-1, IORING_OP_POLL_REMOVE, (void *)0xa1, 0, 0, 1U << 31, 0xc4)
	    != -EINVAL) return (7);
	iou_sqe(IORING_OP_POLL_REMOVE, 0, -1, 0, (void *)0xdead,
	    IORING_POLL_UPDATE_USER_DATA, 0, 0xc5);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 4) != 1 || c[0].res != -ENOENT)
		return (8);
	/* Invalid and missing-key updates leave the original request armed. */
	if (call(SYS_write, sv[0], (long)"x", 1, 0, 0, 0) != 1) return (9);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS, 0, 0) < 0)
		return (10);
	if (iou_reap(c, 4) != 1 || !cqe_find(c, 1, 0xa1, &res) ||
	    !(res & LX_POLLIN)) return (11);
	return (0);
}

static int t_poll_multishot(void)
{
	int sv[2], res, i, more;
	struct cqe c[4];
	int n;
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	/* arm a MULTISHOT poll on sv[1] read-readiness (stays armed) */
	iou_sqe(IORING_OP_POLL_ADD, 0, sv[1], 0, 0, IORING_POLL_ADD_MULTI,
	    LX_POLLIN, 0x1);
	if (iou_flush(1, 0) != 1) return (3);
	/* first readiness -> one F_MORE CQE reporting POLLIN */
	if (call(SYS_write, sv[0], (long)"a", 1, 0, 0, 0) != 1) return (4);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS, 0, 0)
	    < 0) return (5);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0x1, &res) || !(res & LX_POLLIN)) return (6);
	more = 0;
	for (i = 0; i < n; i++)
		if (c[i].user_data == 0x1 && (c[i].flags & IORING_CQE_F_MORE))
			more = 1;
	if (!more) return (7);		/* must still be armed */
	/* a second readiness transition -> a second F_MORE CQE, same user_data */
	if (call(SYS_write, sv[0], (long)"b", 1, 0, 0, 0) != 1) return (8);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS, 0, 0)
	    < 0) return (9);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0x1, &res) || !(res & LX_POLLIN)) return (10);
	/* cancel it -> the multishot poll ends (terminal ECANCELED CQE) */
	iou_sqe(IORING_OP_POLL_REMOVE, 0, -1, 0, (void *)0x1, 0, 0, 0x2);
	if (iou_flush(1, 2) != 1) return (11);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0x2, &res) || res != 0) return (12);
	if (!cqe_find(c, n, 0x1, &res) || res != -ELINUX_ECANCELED) return (13);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}
static int t_poll_close_reuse(void)
{
	int old[2], fresh[2], n, res;
	struct cqe c[2];
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
	    (long)old, 0, 0) != 0) return (2);
	iou_sqe(IORING_OP_POLL_ADD, 0, old[1], 0, 0, 0,
	    LX_POLLIN, 0xabc1);
	if (iou_flush(1, 0) != 1) return (3);
	if (sys1(SYS_close, old[1]) != 0) return (4);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
	    (long)fresh, 0, 0) != 0 || fresh[0] != old[1]) return (5);
	if (call(SYS_write, fresh[1], (long)"n", 1, 0, 0, 0) != 1)
		return (6);
	if (iou_reap(c, 2) != 0) return (7);
	if (call(SYS_write, old[0], (long)"o", 1, 0, 0, 0) != 1)
		return (8);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1,
	    IORING_ENTER_GETEVENTS, 0, 0) < 0) return (9);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0xabc1, &res) ||
	    (res & LX_POLLIN) == 0) return (10);
	return (0);
}

/* Cancellation still selects the held request after its fd is reused. */
static int t_poll_cancel_closed(void)
{
	int old[2], fresh[2], n, res;
	struct cqe c[4];
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
	    (long)old, 0, 0) != 0) return (2);
	iou_sqe(IORING_OP_POLL_ADD, 0, old[1], 0, 0, 0,
	    LX_POLLIN, 0xabc2);
	if (iou_flush(1, 0) != 1) return (3);
	if (sys1(SYS_close, old[1]) != 0 ||
	    call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
	    (long)fresh, 0, 0) != 0 || fresh[0] != old[1]) return (4);
	iou_sqe(IORING_OP_POLL_REMOVE, 0, -1, 0,
	    (void *)0xabc2, 0, 0, 0xabc3);
	if (iou_flush(1, 2) != 1) return (5);
	n = iou_reap(c, 4);
	if (n != 2 || !cqe_find(c, n, 0xabc3, &res) || res != 0)
		return (6);
	if (!cqe_find(c, n, 0xabc2, &res) ||
	    res != -ELINUX_ECANCELED) return (7);
	return (0);
}

/* A ring may be polled, and closing it must release its armed request. */
static int t_poll_ring_self_close(void)
{
	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_POLL_ADD, 0, fd_ring, 0, 0, 0,
	    LX_POLLIN, 0xabc4);
	if (iou_flush(1, 0) != 1) return (2);
	return (sys1(SYS_close, fd_ring) == 0 ? 0 : 3);
}

static int t_poll_ring_self_cancel(void)
{
	struct cqe c[4];
	int n, pollres, cancelres;
	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_POLL_ADD, 0, fd_ring, 0, 0, 0,
	    LX_POLLIN, 0xabc5);
	iou_sqe(IORING_OP_POLL_REMOVE, 0, -1, 0,
	    (void *)0xabc5, 0, 0, 0xabc6);
	if (iou_flush(2, 2) != 2) return (2);
	n = iou_reap(c, 4);
	if (n != 2 || !cqe_find(c, n, 0xabc5, &pollres) ||
	    !cqe_find(c, n, 0xabc6, &cancelres)) return (3);
	return (pollres == -ELINUX_ECANCELED && cancelres == 0 ? 0 : 4);
}

static int t_poll_ring_cross_reuse(void)
{
 struct params bp, freshp;
 struct sqe *bsqes;
 struct cqe out[2];
 char *base;
 volatile u32 *tail,*array;
 long bfd, dupfd, fresh, m, n;
 u32 ringsz, sqesz;
 int res;
 xmemset(&bp,0,sizeof(bp));
 bfd=setup(8,&bp);if(bfd<0)return 1;
 ringsz=bp.sq_off.array+bp.sq_entries*sizeof(u32);
 if(bp.cq_off.cqes+bp.cq_entries*sizeof(struct cqe)>ringsz)
  ringsz=bp.cq_off.cqes+bp.cq_entries*sizeof(struct cqe);
 sqesz=bp.sq_entries*sizeof(struct sqe);
 m=call(SYS_mmap,0,ringsz,PROT_READ|PROT_WRITE,MAP_SHARED,bfd,IORING_OFF_SQ_RING);
 if(m<0)return 2;
 base=(char *)m;
 m=call(SYS_mmap,0,sqesz,PROT_READ|PROT_WRITE,MAP_SHARED,bfd,IORING_OFF_SQES);
 if(m<0)return 3;
 bsqes=(struct sqe *)m;
 tail=(volatile u32 *)(base+bp.sq_off.tail);
 array=(volatile u32 *)(base+bp.sq_off.array);
 dupfd=call(SYS_dup,bfd,0,0,0,0,0);if(dupfd<0)return 4;
 if(ring_setup(8)<0)return 5;
 iou_sqe(IORING_OP_POLL_ADD,0,(int)bfd,0,0,0,LX_POLLIN,0xabc7);
 if(iou_flush(1,0)!=1)return 6;
 if(sys1(SYS_close,bfd)!=0)return 7;
 xmemset(&freshp,0,sizeof(freshp));
 fresh=setup(8,&freshp);if(fresh!=bfd)return 8;
 if(iou_reap(out,2)!=0)return 9;
 xmemset(&bsqes[0],0,sizeof(bsqes[0]));
 bsqes[0].opcode=IORING_OP_NOP;bsqes[0].fd=-1;bsqes[0].user_data=0xabc8;
 array[0]=0;__atomic_store_n(tail,1,__ATOMIC_RELEASE);
 if(call(SYS_io_uring_enter,dupfd,1,0,0,0,0)!=1)return 10;
 if(call(SYS_io_uring_enter,fd_ring,0,1,IORING_ENTER_GETEVENTS,0,0)<0)return 11;
 n=iou_reap(out,2);
 if(n!=1||!cqe_find(out,n,0xabc7,&res)||(res&LX_POLLIN)==0)return 12;
 return 0;
}
/* Probe POLL_UPDATE against a ring whose original fd was reused. */
static int t_poll_ring_update_reuse(void)
{
 struct params bp,freshp;
 struct sqe *bsqes;
 struct cqe out[4];
 char *base;
 volatile u32 *tail,*array;
 long bfd,dupfd,fresh,m,n;
 u32 ringsz,sqesz;
 int res;
 xmemset(&bp,0,sizeof(bp));
 bfd=setup(8,&bp);if(bfd<0)return 1;
 ringsz=bp.sq_off.array+bp.sq_entries*sizeof(u32);
 if(bp.cq_off.cqes+bp.cq_entries*sizeof(struct cqe)>ringsz)
  ringsz=bp.cq_off.cqes+bp.cq_entries*sizeof(struct cqe);
 sqesz=bp.sq_entries*sizeof(struct sqe);
 m=call(SYS_mmap,0,ringsz,PROT_READ|PROT_WRITE,MAP_SHARED,bfd,IORING_OFF_SQ_RING);
 if(m<0)return 2;
 base=(char *)m;
 m=call(SYS_mmap,0,sqesz,PROT_READ|PROT_WRITE,MAP_SHARED,bfd,IORING_OFF_SQES);
 if(m<0)return 3;
 bsqes=(struct sqe *)m;
 tail=(volatile u32 *)(base+bp.sq_off.tail);
 array=(volatile u32 *)(base+bp.sq_off.array);
 dupfd=call(SYS_dup,bfd,0,0,0,0,0);if(dupfd<0)return 4;
 if(ring_setup(8)<0)return 5;
 iou_sqe(IORING_OP_POLL_ADD,0,(int)bfd,0,0,0,LX_POLLIN,0xddd1);
 if(iou_flush(1,0)!=1)return 6;
 iou_sqe(IORING_OP_POLL_REMOVE,0,-1,0xddd2,(void *)0xddd1,
     IORING_POLL_UPDATE_USER_DATA,0,0xddd3);
 if(iou_flush(1,1)!=1)return 7;
 n=iou_reap(out,4);
 if(n!=1||!cqe_find(out,n,0xddd3,&res)||res!=0)return 8;
 iou_sqe(IORING_OP_POLL_REMOVE,0,-1,0xddd4,(void *)0xddd1,
     IORING_POLL_UPDATE_USER_DATA,0,0xddd5);
 if(iou_flush(1,1)!=1)return 9;
 n=iou_reap(out,4);
 if(n!=1||!cqe_find(out,n,0xddd5,&res)||res!=-ENOENT)return 10;
 if(sys1(SYS_close,bfd)!=0)return 11;
 xmemset(&freshp,0,sizeof(freshp));
 fresh=setup(8,&freshp);if(fresh!=bfd)return 12;
 if(iou_reap(out,4)!=0)return 13;
 xmemset(&bsqes[0],0,sizeof(bsqes[0]));
 bsqes[0].opcode=IORING_OP_NOP;bsqes[0].fd=-1;bsqes[0].user_data=0xddd6;
 array[0]=0;__atomic_store_n(tail,1,__ATOMIC_RELEASE);
 if(call(SYS_io_uring_enter,dupfd,1,0,0,0,0)!=1)return 14;
 if(call(SYS_io_uring_enter,fd_ring,0,1,IORING_ENTER_GETEVENTS,0,0)<0)return 15;
 n=iou_reap(out,4);
 if(n!=1||!cqe_find(out,n,0xddd2,&res)||(res&LX_POLLIN)==0)return 16;
 return 0;
}
/* A ring target terminates a MULTI poll on first readiness, even after fd reuse. */
static int t_poll_ring_multishot_terminal_reuse(void)
{
 struct params bp,freshp;
 struct sqe *bsqes;
 struct cqe out[4];
 char *base;
 volatile u32 *tail,*array;
 long bfd,dupfd,fresh,m,n;
 u32 ringsz,sqesz;
 int res,more=0;
 xmemset(&bp,0,sizeof(bp));
 bfd=setup(8,&bp);if(bfd<0)return 1;
 ringsz=bp.sq_off.array+bp.sq_entries*sizeof(u32);
 if(bp.cq_off.cqes+bp.cq_entries*sizeof(struct cqe)>ringsz)
  ringsz=bp.cq_off.cqes+bp.cq_entries*sizeof(struct cqe);
 sqesz=bp.sq_entries*sizeof(struct sqe);
 m=call(SYS_mmap,0,ringsz,PROT_READ|PROT_WRITE,MAP_SHARED,bfd,IORING_OFF_SQ_RING);
 if(m<0)return 2;
 base=(char *)m;
 m=call(SYS_mmap,0,sqesz,PROT_READ|PROT_WRITE,MAP_SHARED,bfd,IORING_OFF_SQES);
 if(m<0)return 3;
 bsqes=(struct sqe *)m;
 tail=(volatile u32 *)(base+bp.sq_off.tail);
 array=(volatile u32 *)(base+bp.sq_off.array);
 dupfd=call(SYS_dup,bfd,0,0,0,0,0);if(dupfd<0)return 4;
 if(ring_setup(8)<0)return 5;
 iou_sqe(IORING_OP_POLL_ADD,0,(int)bfd,0,0,IORING_POLL_ADD_MULTI,LX_POLLIN,0xdee1);
 if(iou_flush(1,0)!=1)return 6;
 if(sys1(SYS_close,bfd)!=0)return 7;
 xmemset(&freshp,0,sizeof(freshp));fresh=setup(8,&freshp);
 if(fresh!=bfd)return 8;
 if(iou_reap(out,4)!=0)return 9;
 xmemset(&bsqes[0],0,sizeof(bsqes[0]));
 bsqes[0].opcode=IORING_OP_NOP;bsqes[0].fd=-1;bsqes[0].user_data=0xdee2;
 array[0]=0;__atomic_store_n(tail,1,__ATOMIC_RELEASE);
 if(call(SYS_io_uring_enter,dupfd,1,0,0,0,0)!=1)return 10;
 if(call(SYS_io_uring_enter,fd_ring,0,1,IORING_ENTER_GETEVENTS,0,0)<0)return 11;
 n=iou_reap(out,4);
 if(n!=1||!cqe_find(out,n,0xdee1,&res)||(res&LX_POLLIN)==0)return 12;
 for(int i=0;i<n;i++)if(out[i].user_data==0xdee1&&(out[i].flags&IORING_CQE_F_MORE))more=1;
 if(more)return 13;
 iou_sqe(IORING_OP_POLL_REMOVE,0,-1,0,(void *)0xdee1,0,0,0xdee3);
 if(iou_flush(1,1)!=1)return 14;
 n=iou_reap(out,4);
 if(n!=1||!cqe_find(out,n,0xdee3,&res)||res!=-ENOENT)return 15;
 return 0;
}
/* Updating a ring-target poll to MULTI still gives a terminal readiness CQE. */
static int t_poll_ring_update_multi_terminal_reuse(void)
{
 struct params bp,freshp;
 struct sqe *bsqes;
 struct cqe out[4];
 char *base;
 volatile u32 *tail,*array;
 long bfd,dupfd,fresh,m,n;
 u32 ringsz,sqesz;
 int res,more=0;
 xmemset(&bp,0,sizeof(bp));
 bfd=setup(8,&bp);if(bfd<0)return 1;
 ringsz=bp.sq_off.array+bp.sq_entries*sizeof(u32);
 if(bp.cq_off.cqes+bp.cq_entries*sizeof(struct cqe)>ringsz)
  ringsz=bp.cq_off.cqes+bp.cq_entries*sizeof(struct cqe);
 sqesz=bp.sq_entries*sizeof(struct sqe);
 m=call(SYS_mmap,0,ringsz,PROT_READ|PROT_WRITE,MAP_SHARED,bfd,IORING_OFF_SQ_RING);
 if(m<0)return 2;
 base=(char *)m;
 m=call(SYS_mmap,0,sqesz,PROT_READ|PROT_WRITE,MAP_SHARED,bfd,IORING_OFF_SQES);
 if(m<0)return 3;
 bsqes=(struct sqe *)m;
 tail=(volatile u32 *)(base+bp.sq_off.tail);
 array=(volatile u32 *)(base+bp.sq_off.array);
 dupfd=call(SYS_dup,bfd,0,0,0,0,0);if(dupfd<0)return 4;
 if(ring_setup(8)<0)return 5;
 iou_sqe(IORING_OP_POLL_ADD,0,(int)bfd,0,0,0,LX_POLLIN,0xdee1);
 if(iou_flush(1,0)!=1)return 6;
 iou_sqe(IORING_OP_POLL_REMOVE,0,-1,0,(void *)0xdee1,
     IORING_POLL_UPDATE_EVENTS|IORING_POLL_ADD_MULTI,LX_POLLIN,0xdee4);
 if(iou_flush(1,1)!=1)return 17;
 n=iou_reap(out,4);
 if(n!=1||!cqe_find(out,n,0xdee4,&res)||res!=0)return 18;
 if(sys1(SYS_close,bfd)!=0)return 7;
 xmemset(&freshp,0,sizeof(freshp));fresh=setup(8,&freshp);
 if(fresh!=bfd)return 8;
 if(iou_reap(out,4)!=0)return 9;
 xmemset(&bsqes[0],0,sizeof(bsqes[0]));
 bsqes[0].opcode=IORING_OP_NOP;bsqes[0].fd=-1;bsqes[0].user_data=0xdee2;
 array[0]=0;__atomic_store_n(tail,1,__ATOMIC_RELEASE);
 if(call(SYS_io_uring_enter,dupfd,1,0,0,0,0)!=1)return 10;
 if(call(SYS_io_uring_enter,fd_ring,0,1,IORING_ENTER_GETEVENTS,0,0)<0)return 11;
 n=iou_reap(out,4);
 if(n!=1||!cqe_find(out,n,0xdee1,&res)||(res&LX_POLLIN)==0)return 12;
 for(int i=0;i<n;i++)if(out[i].user_data==0xdee1&&(out[i].flags&IORING_CQE_F_MORE))more=1;
 if(more)return 13;
 iou_sqe(IORING_OP_POLL_REMOVE,0,-1,0,(void *)0xdee1,0,0,0xdee3);
 if(iou_flush(1,1)!=1)return 14;
 n=iou_reap(out,4);
 if(n!=1||!cqe_find(out,n,0xdee3,&res)||res!=-ENOENT)return 15;
 return 0;
}
/* A target with no remaining user fd still has an in-flight completion. */
static int t_poll_ring_cross_last_close(void)
{
 struct params bp, freshp;
 struct sqe *bsqes;
 struct cqe out[2];
 struct kts ts={1,0};
 char *base;
 volatile u32 *tail,*array;
 long bfd, fresh, m, n;
 u32 ringsz, sqesz;
 int res;
 xmemset(&bp,0,sizeof(bp));
 bfd=setup(8,&bp);if(bfd<0)return 1;
 ringsz=bp.sq_off.array+bp.sq_entries*sizeof(u32);
 if(bp.cq_off.cqes+bp.cq_entries*sizeof(struct cqe)>ringsz)
  ringsz=bp.cq_off.cqes+bp.cq_entries*sizeof(struct cqe);
 sqesz=bp.sq_entries*sizeof(struct sqe);
 m=call(SYS_mmap,0,ringsz,PROT_READ|PROT_WRITE,MAP_SHARED,bfd,IORING_OFF_SQ_RING);
 if(m<0)return 2;
 base=(char *)m;
 m=call(SYS_mmap,0,sqesz,PROT_READ|PROT_WRITE,MAP_SHARED,bfd,IORING_OFF_SQES);
 if(m<0)return 3;
 bsqes=(struct sqe *)m;
 tail=(volatile u32 *)(base+bp.sq_off.tail);
 array=(volatile u32 *)(base+bp.sq_off.array);
 if(ring_setup(8)<0)return 4;
 iou_sqe(IORING_OP_POLL_ADD,0,(int)bfd,0,0,0,LX_POLLIN,0xabcb);
 if(iou_flush(1,0)!=1)return 5;
 xmemset(&bsqes[0],0,sizeof(bsqes[0]));
 bsqes[0].opcode=IORING_OP_TIMEOUT;bsqes[0].fd=-1;
 bsqes[0].addr=(u64)(unsigned long)&ts;bsqes[0].len=1;
 bsqes[0].user_data=0xabcc;
 array[0]=0;__atomic_store_n(tail,1,__ATOMIC_RELEASE);
 if(call(SYS_io_uring_enter,bfd,1,0,0,0,0)!=1)return 6;
 if(sys1(SYS_close,bfd)!=0)return 7;
 xmemset(&freshp,0,sizeof(freshp));
 fresh=setup(8,&freshp);if(fresh!=bfd)return 8;
 if(iou_reap(out,2)!=0)return 9;
 if(call(SYS_io_uring_enter,fd_ring,0,1,IORING_ENTER_GETEVENTS,0,0)<0)return 10;
 n=iou_reap(out,2);
 if(n!=1||!cqe_find(out,n,0xabcb,&res)||(res&LX_POLLIN)==0)return 11;
 return 0;
}
/* FD cancellation must match the watched ring identity, not its reused fd. */
static int t_poll_ring_fd_cancel(void)
{
 struct params bp,freshp;
 struct cqe out[4];
 long bfd,dupfd,fresh;
 int n,pollres,cancelres;
 xmemset(&bp,0,sizeof(bp));
 bfd=setup(8,&bp);if(bfd<0)return 1;
 dupfd=sys1(SYS_dup,bfd);if(dupfd<0)return 2;
 if(ring_setup(8)<0)return 3;
 iou_sqe(IORING_OP_POLL_ADD,0,(int)bfd,0,0,0,LX_POLLIN,0xabcd);
 if(iou_flush(1,0)!=1)return 4;
 if(sys1(SYS_close,bfd)!=0)return 5;
 xmemset(&freshp,0,sizeof(freshp));
 fresh=setup(8,&freshp);if(fresh!=bfd)return 6;
 if(sub1((int)fresh,IORING_OP_ASYNC_CANCEL,0,0,0,
     IORING_ASYNC_CANCEL_FD,0xabce)!=-ENOENT)return 7;
 if(iou_reap(out,2)!=0)return 8;
 iou_sqe(IORING_OP_ASYNC_CANCEL,0,(int)dupfd,0,0,0,
     IORING_ASYNC_CANCEL_FD,0xabcf);
 if(iou_flush(1,2)!=1)return 9;
 n=iou_reap(out,4);
 if(n!=2||!cqe_find(out,n,0xabcd,&pollres)||
     !cqe_find(out,n,0xabcf,&cancelres))return 10;
 return pollres==-ELINUX_ECANCELED&&cancelres==0?0:11;
}

/* A and B can poll each other; closing both must release both requests. */
static int t_poll_ring_mutual_close(void)
{
 struct params bp;
 struct sqe *bsqes;
 char *base;
 volatile u32 *tail, *array;
 long bfd, m;
 u32 ringsz, sqesz;

 xmemset(&bp, 0, sizeof(bp));
 bfd = setup(8, &bp);
 if (bfd < 0) return 1;
 ringsz = bp.sq_off.array + bp.sq_entries * sizeof(u32);
 if (bp.cq_off.cqes + bp.cq_entries * sizeof(struct cqe) > ringsz)
  ringsz = bp.cq_off.cqes + bp.cq_entries * sizeof(struct cqe);
 sqesz = bp.sq_entries * sizeof(struct sqe);
 m = call(SYS_mmap, 0, ringsz, PROT_READ | PROT_WRITE, MAP_SHARED,
     bfd, IORING_OFF_SQ_RING);
 if (m < 0) return 2;
 base = (char *)m;
 m = call(SYS_mmap, 0, sqesz, PROT_READ | PROT_WRITE, MAP_SHARED,
     bfd, IORING_OFF_SQES);
 if (m < 0) return 3;
 bsqes = (struct sqe *)m;
 tail = (volatile u32 *)(base + bp.sq_off.tail);
 array = (volatile u32 *)(base + bp.sq_off.array);
 if (ring_setup(8) < 0) return 4;
 iou_sqe(IORING_OP_POLL_ADD, 0, (int)bfd, 0, 0, 0,
     LX_POLLIN, 0xabc9);
 if (iou_flush(1, 0) != 1) return 5;
 xmemset(&bsqes[0], 0, sizeof(bsqes[0]));
 bsqes[0].opcode = IORING_OP_POLL_ADD;
 bsqes[0].fd = fd_ring;
 bsqes[0].rw_flags = LX_POLLIN;
 bsqes[0].user_data = 0xabca;
 array[0] = 0;
 __atomic_store_n(tail, 1, __ATOMIC_RELEASE);
 if (call(SYS_io_uring_enter, bfd, 1, 0, 0, 0, 0) != 1) return 6;
 if (sys1(SYS_close, fd_ring) != 0) return 7;
 if (sys1(SYS_close, bfd) != 0) return 8;
 return 0;
}
static int t_poll_badfd(void)
{
	int res;
	if (ring_setup(8) < 0) return (1);
	/* poll on a bad fd -> POLLNVAL -> -EBADF */
	res = sub1(9999, IORING_OP_POLL_ADD, 0, 0, 0, LX_POLLIN, 0x1);
	return (res == -EBADF ? 0 : 2);
}
static int t_poll_probe(void)
{
	struct probe pr;
	if (ring_setup(8) < 0) return (1);
	xmemset(&pr, 0, sizeof(pr));
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PROBE,
	    (long)&pr, 128, 0, 0) != 0) return (2);
	if ((pr.ops[IORING_OP_POLL_ADD].flags & IO_URING_OP_SUPPORTED) == 0) return (3);
	if ((pr.ops[IORING_OP_POLL_REMOVE].flags & IO_URING_OP_SUPPORTED) == 0) return (4);
	return (0);
}
/* REGISTER_EVENTFD: a posted completion signals the registered eventfd. */
static int t_register_eventfd(void)
{
	long efd;
	int efdi;
	struct cqe c[2];
	int n;
	unsigned long long val = 0;
	if (ring_setup(8) < 0) return (1);
	efd = call(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
	if (efd < 0) return (2);
	efdi = (int)efd;
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_EVENTFD,
	    (long)&efdi, 1, 0, 0) != 0) return (3);
	/* a NOP completion must bump the eventfd count */
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x1);
	if (iou_flush(1, 1) != 1) return (4);
	n = iou_reap(c, 2);
	if (n != 1) return (5);
	if (call(SYS_read, efd, (long)&val, 8, 0, 0, 0) != 8 || val < 1)
		return (6);
	/* after unregister, a completion no longer signals it */
	if (call(SYS_io_uring_register, fd_ring, IORING_UNREGISTER_EVENTFD,
	    0, 0, 0, 0) != 0) return (7);
	(void)sys1(SYS_close, efd);
	return (0);
}

/* ================= fast-poll async (never block the ring) ================= */
static int t_fastpoll_recv(void)
{
	int sv[2], res;
	static char rb[16];
	struct cqe c[4];
	int n;
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	/*
	 * Submit a RECV on an empty socket (would block) plus a NOP, in one
	 * batch.  The RECV must be parked on a readiness poll, NOT block the
	 * submitting thread, so the NOP still completes.
	 */
	iou_sqe(IORING_OP_RECV, 0, sv[1], 0, rb, sizeof(rb), 0, 0xD1);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0xD2);
	if (iou_flush(2, 1) != 2) return (3);
	n = iou_reap(c, 4);
	if (n != 1 || !cqe_find(c, n, 0xD2, &res) || res != 0) return (4);
	if (cqe_find(c, n, 0xD1, &res)) return (5);	/* RECV must still be parked */
	/* now deliver data; the parked RECV completes on the next enter */
	if (call(SYS_write, sv[0], (long)"async!!", 7, 0, 0, 0) != 7) return (6);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS, 0, 0) < 0)
		return (7);
	n = iou_reap(c, 4);
	if (n != 1 || !cqe_find(c, n, 0xD1, &res)) return (8);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (res != 7 || xmemcmp(rb, "async!!", 7) != 0) return (9);
	return (0);
}
static int t_fastpoll_two_recv(void)
{
	int a[2], b[2], res;
	static char ra[8], rb[8];
	struct cqe c[8];
	int n;
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)a, 0, 0) != 0)
		return (2);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)b, 0, 0) != 0)
		return (3);
	/* two would-block RECVs parked concurrently on different sockets */
	iou_sqe(IORING_OP_RECV, 0, a[1], 0, ra, sizeof(ra), 0, 0x1);
	iou_sqe(IORING_OP_RECV, 0, b[1], 0, rb, sizeof(rb), 0, 0x2);
	if (iou_flush(2, 0) != 2) return (4);
	n = iou_reap(c, 8);
	if (n != 0) return (5);				/* both parked, none blocked */
	/* feed both, then reap both */
	if (call(SYS_write, a[0], (long)"AA", 2, 0, 0, 0) != 2) return (6);
	if (call(SYS_write, b[0], (long)"BBB", 3, 0, 0, 0) != 3) return (7);
	if (call(SYS_io_uring_enter, fd_ring, 0, 2, IORING_ENTER_GETEVENTS, 0, 0) < 0)
		return (8);
	n = iou_reap(c, 8);
	(void)sys1(SYS_close, a[0]); (void)sys1(SYS_close, a[1]);
	(void)sys1(SYS_close, b[0]); (void)sys1(SYS_close, b[1]);
	if (n != 2) return (9);
	if (!cqe_find(c, n, 0x1, &res) || res != 2) return (10);
	if (!cqe_find(c, n, 0x2, &res) || res != 3) return (11);
	return (0);
}

/* ================= batch 3: depth + adversarial + stress ================= */
#define	LX_O_TRUNC	01000
#define	LX_O_APPEND	02000
#define	LX_O_NONBLOCK	04000
#define	STATX_OFF_NLINK	16
#define	STATX_OFF_MODE	28
#define	STATX_OFF_INO	32
#define	LX_S_IFREG	0x8000

/* ---- fast-poll depth ---- */
static int t_fastpoll_read_sock(void)
{
	int sv[2], res;
	static char rb[8];
	struct cqe c[4];
	int n;
	if (ring_setup(8) < 0) return (1);
	/* nonblocking socketpair so an empty READ returns EAGAIN and parks */
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0,
	    (long)sv, 0, 0) != 0) return (2);
	/* off = -1: sockets are not seekable, so READ must use the read path */
	iou_sqe(IORING_OP_READ, 0, sv[1], (u64)-1, rb, sizeof(rb), 0, 0xD1);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0xD2);
	if (iou_flush(2, 1) != 2) return (3);
	n = iou_reap(c, 4);
	if (n != 1 || !cqe_find(c, n, 0xD2, &res)) return (4);
	if (cqe_find(c, n, 0xD1, &res)) return (5);
	if (call(SYS_write, sv[0], (long)"sockok", 6, 0, 0, 0) != 6) return (6);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS, 0, 0) < 0)
		return (7);
	n = iou_reap(c, 4);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (n != 1 || !cqe_find(c, n, 0xD1, &res) || res != 6) return (8);
	if (xmemcmp(rb, "sockok", 6) != 0) return (9);
	return (0);
}
static int t_fastpoll_recv_linked(void)
{
	int sv[2], res;
	static char rb[8];
	struct cqe c[4];
	int n;
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	/* RECV parks (LINK) -> NOP successor must run only after RECV completes */
	iou_sqe(IORING_OP_RECV, IOSQE_IO_LINK, sv[1], 0, rb, sizeof(rb), 0, 0x1);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x2);
	if (iou_flush(2, 0) != 2) return (3);
	n = iou_reap(c, 4);
	if (n != 0) return (4);				/* both suspended behind RECV */
	if (call(SYS_write, sv[0], (long)"link", 4, 0, 0, 0) != 4) return (5);
	if (call(SYS_io_uring_enter, fd_ring, 0, 2, IORING_ENTER_GETEVENTS, 0, 0) < 0)
		return (6);
	n = iou_reap(c, 4);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (n != 2) return (7);
	if (!cqe_find(c, n, 0x1, &res) || res != 4) return (8);
	if (!cqe_find(c, n, 0x2, &res) || res != 0) return (9);
	return (0);
}
static int t_fastpoll_recv_cancel(void)
{
	int sv[2], res;
	static char rb[8];
	struct cqe c[4];
	int n;
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	iou_sqe(IORING_OP_RECV, 0, sv[1], 0, rb, sizeof(rb), 0, 0xA1);
	if (iou_flush(1, 0) != 1) return (3);
	/* ASYNC_CANCEL covers a parked RECV; POLL_REMOVE is for POLL_ADD. */
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0xA1, 0, 0, 0xA2);
	if (iou_flush(1, 2) != 1) return (4);
	n = iou_reap(c, 4);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (!cqe_find(c, n, 0xA2, &res) || res != 0) return (5);
	if (!cqe_find(c, n, 0xA1, &res) || res != -ELINUX_ECANCELED) return (6);
	return (0);
}
/* A parked receive follows its captured file across close and fd reuse. */
static int t_fastpoll_close_reuse(void)
{
	int old[2], fresh[2], oldfd, n, res;
	static char rb[8];
	struct cqe c[4];

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)old, 0, 0) != 0)
		return (2);
	oldfd = old[1];
	iou_sqe(IORING_OP_RECV, 0, oldfd, 0, rb, sizeof(rb), 0, 0xd3);
	if (iou_flush(1, 0) != 1 || iou_reap(c, 4) != 0)
		return (3);
	if (sys1(SYS_close, oldfd) != 0 ||
	    call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)fresh, 0, 0) != 0 ||
	    fresh[0] != oldfd)
		return (4);
	/* Readiness on the reused descriptor must not complete the old request. */
	if (call(SYS_write, fresh[1], (long)"new", 3, 0, 0, 0) != 3)
		return (5);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0xd4);
	if (iou_flush(1, 1) != 1)
		return (7);
	n = iou_reap(c, 4);
	if (n != 1 || !cqe_find(c, n, 0xd4, &res) || res != 0 ||
	    cqe_find(c, n, 0xd3, &res))
		return (7);
	/* The held original socket remains the request target after close. */
	if (call(SYS_write, old[0], (long)"old", 3, 0, 0, 0) != 3 ||
	    call(SYS_io_uring_enter, fd_ring, 0, 1,
	    IORING_ENTER_GETEVENTS, 0, 0) < 0)
		return (8);
	n = iou_reap(c, 4);
	if (n != 1 || !cqe_find(c, n, 0xd3, &res) || res != 3 ||
	    xmemcmp(rb, "old", 3) != 0)
		return (9);
	(void)sys1(SYS_close, old[0]);
	(void)sys1(SYS_close, fresh[0]);
	(void)sys1(SYS_close, fresh[1]);
	return (0);
}

static int t_fastpoll_many(void)
{
	int sv[4][2], i, res;
	static char rb[4][8];
	struct cqe c[8];
	int n;
	if (ring_setup(16) < 0) return (1);
	for (i = 0; i < 4; i++)
		if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0,
		    (long)sv[i], 0, 0) != 0) return (2);
	for (i = 0; i < 4; i++)
		iou_sqe(IORING_OP_RECV, 0, sv[i][1], 0, rb[i], 8, 0, 0x100 + i);
	if (iou_flush(4, 0) != 4) return (3);
	if (iou_reap(c, 8) != 0) return (4);		/* all four parked */
	for (i = 0; i < 4; i++)
		if (call(SYS_write, sv[i][0], (long)"z", 1, 0, 0, 0) != 1) return (5);
	if (call(SYS_io_uring_enter, fd_ring, 0, 4, IORING_ENTER_GETEVENTS, 0, 0) < 0)
		return (6);
	n = iou_reap(c, 8);
	for (i = 0; i < 4; i++) {
		(void)sys1(SYS_close, sv[i][0]); (void)sys1(SYS_close, sv[i][1]);
	}
	if (n != 4) return (7);
	for (i = 0; i < 4; i++)
		if (!cqe_find(c, n, 0x100 + i, &res) || res != 1) return (8);
	return (0);
}

/* ---- RW / fs variants ---- */
static int t_write_read_1(void)
{
	long tf; char rb[2];
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_w1"); if (tf < 0) return (2);
	if (sub1(tf, IORING_OP_WRITE, "Z", 1, 0, 0, 0x1) != 1) return (3);
	rb[0] = 0;
	if (sub1(tf, IORING_OP_READ, rb, 1, 0, 0, 0x2) != 1 || rb[0] != 'Z') return (4);
	(void)sys1(SYS_close, tf); return (0);
}
static int t_write_read_odd(void)
{
	long tf; static char wb[4097], rb[4097]; int i;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_odd"); if (tf < 0) return (2);
	for (i = 0; i < 4097; i++) wb[i] = (char)(i & 0x7f);
	if (sub1(tf, IORING_OP_WRITE, wb, 4097, 0, 0, 0x1) != 4097) return (3);
	xmemset(rb, 0, sizeof(rb));
	if (sub1(tf, IORING_OP_READ, rb, 4097, 0, 0, 0x2) != 4097) return (4);
	if (xmemcmp(rb, wb, 4097) != 0) return (5);
	(void)sys1(SYS_close, tf); return (0);
}
static int t_read_partial(void)
{
	long tf; char rb[16]; int res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_pr"); if (tf < 0) return (2);
	if (sub1(tf, IORING_OP_WRITE, "abc", 3, 0, 0, 0x1) != 3) return (3);
	/* request 16 but only 3 available -> short read of 3 */
	res = sub1(tf, IORING_OP_READ, rb, 16, 0, 0, 0x2);
	(void)sys1(SYS_close, tf);
	return (res == 3 ? 0 : 4);
}
static int t_huge_len_read(void)
{
	long tf; static char rb[65536]; int res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_hl"); if (tf < 0) return (2);
	if (sub1(tf, IORING_OP_WRITE, "eightby!", 8, 0, 0, 0x1) != 8) return (3);
	/* absurd length must clamp to what's there or fail cleanly, not crash */
	res = sub1(tf, IORING_OP_READ, rb, 0xFFFFFFFFU, 0, 0, 0x2);
	(void)sys1(SYS_close, tf);
	return ((res == 8 || res < 0) && res != -100001 ? 0 : 4);
}
static int t_ftruncate_shrink(void)
{
	long tf; char rb[8]; int res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_sh"); if (tf < 0) return (2);
	if (sub1(tf, IORING_OP_WRITE, "12345678", 8, 0, 0, 0x1) != 8) return (3);
	if (sub1(tf, IORING_OP_FTRUNCATE, 0, 0, 3, 0, 0x2) != 0) return (4);
	res = sub1(tf, IORING_OP_READ, rb, 8, 0, 0, 0x3);	/* only 3 left */
	(void)sys1(SYS_close, tf);
	return (res == 3 ? 0 : 5);
}
static int t_fadvise_values(void)
{
	long tf; int adv, res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_fav"); if (tf < 0) return (2);
	if (sub1(tf, IORING_OP_WRITE, "data", 4, 0, 0, 0x1) != 4) return (3);
	for (adv = 0; adv <= 5; adv++) {
		res = sub1(tf, IORING_OP_FADVISE, (void *)4, 0, 0, (u32)adv, 0x10 + adv);
		if (res != 0) { (void)sys1(SYS_close, tf); return (4); }
	}
	(void)sys1(SYS_close, tf); return (0);
}
static int t_openat_excl(void)
{
	long tf; int res;
	if (ring_setup(8) < 0) return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_ex", 0);
	tf = tmpfile_fd("iou_ex"); if (tf < 0) return (2);
	(void)sys1(SYS_close, tf);
	/* O_CREAT|O_EXCL on an existing file -> EEXIST */
	iou_sqe(IORING_OP_OPENAT, 0, LX_AT_FDCWD, 0, "iou_ex", 0600,
	    LX_O_RDWR | LX_O_CREAT | LX_O_EXCL, 0x1);
	{ struct cqe c[2]; int n; if (iou_flush(1,1)!=1) return (3);
	  n = iou_reap(c,2); if (n!=1 || !cqe_find(c,n,0x1,&res)) return (4); }
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_ex", 0);
	return (res == -ELINUX_EEXIST ? 0 : 5);
}
static int t_openat_trunc(void)
{
	long tf; int fd; char rb[8]; int res;
	if (ring_setup(8) < 0) return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_tr", 0);
	tf = tmpfile_fd("iou_tr"); if (tf < 0) return (2);
	if (sub1(tf, IORING_OP_WRITE, "OLDDATA!", 8, 0, 0, 0x1) != 8) return (3);
	(void)sys1(SYS_close, tf);
	/* open with O_TRUNC clears it */
	iou_sqe(IORING_OP_OPENAT, 0, LX_AT_FDCWD, 0, "iou_tr", 0600,
	    LX_O_RDWR | LX_O_TRUNC, 0x2);
	{ struct cqe c[2]; int n; if (iou_flush(1,1)!=1) return (4);
	  n = iou_reap(c,2); if (n!=1 || !cqe_find(c,n,0x2,&fd)) return (5); }
	if (fd < 0) return (6);
	res = sub1(fd, IORING_OP_READ, rb, 8, 0, 0, 0x3);	/* truncated -> 0 */
	(void)sys1(SYS_close, fd); (void)sys3(SYS_unlinkat, AT_FDCWD, "iou_tr", 0);
	return (res == 0 ? 0 : 7);
}
static int t_renameat_replace(void)
{
	long a, b; static char sx[256]; int res;
	if (ring_setup(8) < 0) return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_ra", 0); (void)sys3(SYS_unlinkat, AT_FDCWD, "iou_rb", 0);
	a = tmpfile_fd("iou_ra"); b = tmpfile_fd("iou_rb");
	if (a < 0 || b < 0) return (2);
	if (sub1(a, IORING_OP_WRITE, "SRC", 3, 0, 0, 0x1) != 3) return (3);
	(void)sys1(SYS_close, a); (void)sys1(SYS_close, b);
	/* rename a over existing b (replace) */
	iou_sqe(IORING_OP_RENAMEAT, 0, LX_AT_FDCWD, (u64)(unsigned long)"iou_rb",
	    "iou_ra", LX_AT_FDCWD, 0, 0x2);
	{ struct cqe c[2]; int n; if (iou_flush(1,1)!=1) return (4);
	  n = iou_reap(c,2); if (n!=1 || !cqe_find(c,n,0x2,&res) || res != 0) return (5); }
	/* b now has SRC's content: size 3 */
	xmemset(sx, 0, sizeof(sx));
	iou_sqe(IORING_OP_STATX, 0, LX_AT_FDCWD, (u64)(unsigned long)sx, "iou_rb",
	    STATX_BASIC_STATS, 0, 0x3);
	{ struct cqe c[2]; int n; if (iou_flush(1,1)!=1) return (6);
	  n = iou_reap(c,2); if (n!=1 || !cqe_find(c,n,0x3,&res) || res != 0) return (7); }
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_rb", 0);
	return (*(unsigned long long *)(void *)(sx + STATX_OFF_SIZE) == 3 ? 0 : 8);
}
static int t_linkat_same_ino(void)
{
	long tf; static char s1[256], s2[256]; int res;
	unsigned long long i1, i2;
	if (ring_setup(8) < 0) return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_li1", 0); (void)sys3(SYS_unlinkat, AT_FDCWD, "iou_li2", 0);
	tf = tmpfile_fd("iou_li1"); if (tf < 0) return (2);
	(void)sys1(SYS_close, tf);
	iou_sqe(IORING_OP_LINKAT, 0, LX_AT_FDCWD, (u64)(unsigned long)"iou_li2",
	    "iou_li1", LX_AT_FDCWD, 0, 0x1);
	{ struct cqe c[2]; int n; if (iou_flush(1,1)!=1) return (3);
	  n = iou_reap(c,2); if (n!=1 || !cqe_find(c,n,0x1,&res) || res != 0) return (4); }
	xmemset(s1, 0, sizeof(s1)); xmemset(s2, 0, sizeof(s2));
	iou_sqe(IORING_OP_STATX, 0, LX_AT_FDCWD, (u64)(unsigned long)s1, "iou_li1",
	    STATX_BASIC_STATS, 0, 0x2);
	iou_sqe(IORING_OP_STATX, 0, LX_AT_FDCWD, (u64)(unsigned long)s2, "iou_li2",
	    STATX_BASIC_STATS, 0, 0x3);
	{ struct cqe c[4]; int n; if (iou_flush(2,2)!=2) return (5);
	  n = iou_reap(c,4); if (n!=2) return (6);
	  if (!cqe_find(c,n,0x2,&res)||res!=0||!cqe_find(c,n,0x3,&res)||res!=0) return (7); }
	i1 = *(unsigned long long *)(void *)(s1 + STATX_OFF_INO);
	i2 = *(unsigned long long *)(void *)(s2 + STATX_OFF_INO);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_li1", 0); (void)sys3(SYS_unlinkat, AT_FDCWD, "iou_li2", 0);
	return (i1 != 0 && i1 == i2 ? 0 : 8);
}
static int t_statx_fields(void)
{
	long tf; static char sx[256]; int res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_sf2"); if (tf < 0) return (2);
	if (sub1(tf, IORING_OP_WRITE, "x", 1, 0, 0, 0x1) != 1) return (3);
	(void)sys1(SYS_close, tf);
	xmemset(sx, 0, sizeof(sx));
	iou_sqe(IORING_OP_STATX, 0, LX_AT_FDCWD, (u64)(unsigned long)sx, "iou_sf2",
	    STATX_BASIC_STATS, 0, 0x2);
	{ struct cqe c[2]; int n; if (iou_flush(1,1)!=1) return (4);
	  n = iou_reap(c,2); if (n!=1 || !cqe_find(c,n,0x2,&res) || res != 0) return (5); }
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_sf2", 0);
	if (*(u32 *)(void *)(sx + STATX_OFF_NLINK) < 1) return (6);
	if ((*(unsigned short *)(void *)(sx + STATX_OFF_MODE) & LX_S_IFREG) == 0) return (7);
	return (0);
}

static int
statx_option_op(u8 sqe_flags, int field, u32 statx_flags, const char *path,
    void *buf)
{
	struct cqe c[2];
	u32 slot;
	int res;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_STATX, sqe_flags, LX_AT_FDCWD,
	    (u64)(unsigned long)buf, (void *)path, STATX_BASIC_STATS,
	    statx_flags, 0xe100 + g_sqi);
	switch (field) {
	case 1: g_sqes[slot].buf_index = 1; break;
	case 2: g_sqes[slot].splice_fd_in = 1; break;
	case 3: g_sqes[slot].pad2[0] = 1; break;
	case 4: g_sqes[slot].pad2[1] = 1; break;
	case 5: g_sqes[slot].ioprio = 1; break;
	default: break;
	}
	if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
	    !cqe_find(c, 1, 0xe100 + g_sqi - 1, &res))
		return (-100000);
	return (res);
}

static int
t_statx_options(void)
{
	static unsigned char sx[256];
	long fd;

	if (ring_setup(16) < 0)
		return (1);
	fd = tmpfile_fd("iou_statx_options");
	if (fd < 0)
		return (2);
	(void)sys1(SYS_close, fd);
	if (statx_option_op(0, 0, 0, "iou_statx_options", sx) != 0)
		return (3);
	/* Linux preparation rejects these before FIXED_FILE. */
	if (statx_option_op(0, 1, 0, "iou_statx_options", sx) != -EINVAL ||
	    statx_option_op(0, 2, 0, "iou_statx_options", sx) != -EINVAL ||
	    statx_option_op(IOSQE_FIXED_FILE, 1, 0,
	    "iou_statx_options", sx) != -EINVAL ||
	    statx_option_op(IOSQE_FIXED_FILE, 2, 0,
	    "iou_statx_options", sx) != -EINVAL)
		return (4);
	if (statx_option_op(IOSQE_FIXED_FILE, 0, 0,
	    "iou_statx_options", sx) != -EBADF)
		return (5);
	/* The remaining tail words are ignored for STATX. */
	if (statx_option_op(0, 3, 0, "iou_statx_options", sx) != 0 ||
	    statx_option_op(0, 4, 0, "iou_statx_options", sx) != 0)
		return (6);
	if (statx_option_op(0, 5, 0, "iou_statx_options", sx) != -EINVAL ||
	    statx_option_op(IOSQE_BUFFER_SELECT, 0, 0,
	    "iou_statx_options", sx) != -EOPNOTSUPP)
		return (7);
	if (statx_option_op(0, 0, 0x80000000U,
	    "iou_statx_options", sx) != -EINVAL ||
	    statx_option_op(0, 0, 0, (const char *)1, sx) != -EFAULT ||
	    statx_option_op(0, 0, 0, "iou_statx_options", (void *)1) != -EFAULT)
		return (8);
	if (statx_option_op(0, 0, 0, "iou_statx_options", sx) != 0)
		return (9);
	(void)sys3(SYS_unlinkat, LX_AT_FDCWD, "iou_statx_options", 0);
	return (0);
}

static int
path_option_op(u8 opcode, u8 sqe_flags, int field, const char *oldpath,
    const char *newpath)
{
	struct cqe c[2];
	u32 slot, len, misc;
	u64 off;
	int res;

	off = 0;
	len = 0;
	misc = 0;
	switch (opcode) {
	case IORING_OP_RENAMEAT:
	case IORING_OP_LINKAT:
		off = (u64)(unsigned long)newpath;
		len = (u32)LX_AT_FDCWD;
		break;
	case IORING_OP_MKDIRAT:
		len = 0700;
		break;
	case IORING_OP_SYMLINKAT:
		off = (u64)(unsigned long)newpath;
		break;
	default:
		break;
	}
	slot = g_sqi & g_sqmask;
	iou_sqe(opcode, sqe_flags, LX_AT_FDCWD, off, (void *)oldpath,
	    len, misc, 0xe200 + g_sqi);
	switch (field) {
	case 1: g_sqes[slot].buf_index = 1; break;
	case 2: g_sqes[slot].splice_fd_in = 1; break;
	case 3: g_sqes[slot].off = 1; break;
	case 4: g_sqes[slot].len = 1; break;
	case 5: g_sqes[slot].rw_flags = 1; break;
	case 6: g_sqes[slot].rw_flags = 0x80000000U; break;
	default: break;
	}
	if (iou_flush(1, 1) != 1 || iou_reap(c, 2) != 1 ||
	    !cqe_find(c, 1, 0xe200 + g_sqi - 1, &res))
		return (-100000);
	return (res);
}

static int
t_path_ops_options(void)
{
	static const u8 ops[] = { IORING_OP_RENAMEAT, IORING_OP_UNLINKAT,
	    IORING_OP_MKDIRAT, IORING_OP_SYMLINKAT, IORING_OP_LINKAT };
	long fd;
	unsigned i;

	if (ring_setup(32) < 0)
		return (1);
	/* All five operations reject these fields before FIXED_FILE. */
	for (i = 0; i < sizeof(ops); i++) {
		if (path_option_op(ops[i], IOSQE_FIXED_FILE, 1, "missing-a",
		    "missing-b") != -EINVAL ||
		    path_option_op(ops[i], IOSQE_FIXED_FILE, 2, "missing-a",
		    "missing-b") != -EINVAL ||
		    path_option_op(ops[i], IOSQE_FIXED_FILE, 0, "missing-a",
		    "missing-b") != -EBADF)
			return (2);
	}
	/* Additional opcode-specific reserved words have the same precedence. */
	if (path_option_op(IORING_OP_UNLINKAT, IOSQE_FIXED_FILE, 3,
	    "missing", 0) != -EINVAL ||
	    path_option_op(IORING_OP_UNLINKAT, IOSQE_FIXED_FILE, 4,
	    "missing", 0) != -EINVAL ||
	    path_option_op(IORING_OP_MKDIRAT, IOSQE_FIXED_FILE, 3,
	    "missing", 0) != -EINVAL ||
	    path_option_op(IORING_OP_MKDIRAT, IOSQE_FIXED_FILE, 5,
	    "missing", 0) != -EINVAL ||
	    path_option_op(IORING_OP_SYMLINKAT, IOSQE_FIXED_FILE, 4,
	    "a", "missing") != -EINVAL ||
	    path_option_op(IORING_OP_SYMLINKAT, IOSQE_FIXED_FILE, 5,
	    "a", "missing") != -EINVAL)
		return (3);
	/* Unknown operation flags are rejected without pathname side effects. */
	if (path_option_op(IORING_OP_RENAMEAT, 0, 6, "missing-a",
	    "missing-b") != -EINVAL ||
	    path_option_op(IORING_OP_UNLINKAT, 0, 6, "missing", 0) != -EINVAL ||
	    path_option_op(IORING_OP_LINKAT, 0, 6, "missing-a",
	    "missing-b") != -EINVAL)
		return (4);
	/* Each operation remains usable after the preparation failures. */
	fd = tmpfile_fd("iou_po_src");
	if (fd < 0) return (5);
	(void)sys1(SYS_close, fd);
	if (path_option_op(IORING_OP_MKDIRAT, 0, 0, "iou_po_dir", 0) != 0 ||
	    path_option_op(IORING_OP_SYMLINKAT, 0, 0, "target",
	    "iou_po_sym") != 0 ||
	    path_option_op(IORING_OP_LINKAT, 0, 0, "iou_po_src",
	    "iou_po_link") != 0 ||
	    path_option_op(IORING_OP_RENAMEAT, 0, 0, "iou_po_link",
	    "iou_po_renamed") != 0 ||
	    path_option_op(IORING_OP_UNLINKAT, 0, 0, "iou_po_renamed", 0) != 0)
		return (6);
	(void)sys3(SYS_unlinkat, LX_AT_FDCWD, "iou_po_src", 0);
	(void)sys3(SYS_unlinkat, LX_AT_FDCWD, "iou_po_sym", 0);
	(void)sys3(SYS_unlinkat, LX_AT_FDCWD, "iou_po_dir", LX_AT_REMOVEDIR);
	return (0);
}

/* ---- register depth ---- */
static int t_fixed_writev(void)
{
	long tf; int fds[1], res; struct iovec iov[2]; char rb[8];
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_fw"); if (tf < 0) return (2);
	fds[0] = (int)tf;
	if (iou_reg(IORING_REGISTER_FILES, fds, 1) != 0) return (3);
	(void)sys1(SYS_close, tf);
	iov[0].iov_base = "AB"; iov[0].iov_len = 2;
	iov[1].iov_base = "CD"; iov[1].iov_len = 2;
	res = fixed_op(IORING_OP_WRITEV, 0, iov, 2, 0, 0, IOSQE_FIXED_FILE, 0x1);
	if (res != 4) return (4);
	xmemset(rb, 0, sizeof(rb));
	iov[0].iov_base = rb; iov[0].iov_len = 4;
	res = fixed_op(IORING_OP_READV, 0, iov, 1, 0, 0, IOSQE_FIXED_FILE, 0x2);
	if (res != 4 || xmemcmp(rb, "ABCD", 4) != 0) return (5);
	return (0);
}
static int t_reg_buffers_multi(void)
{
	static char b0[1024], b1[1024]; struct iovec iov[2]; long tf; int res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_rbm"); if (tf < 0) return (2);
	iov[0].iov_base = b0; iov[0].iov_len = sizeof(b0);
	iov[1].iov_base = b1; iov[1].iov_len = sizeof(b1);
	if (iou_reg(IORING_REGISTER_BUFFERS, iov, 2) != 0) return (3);
	b1[0] = 'Q';
	/* WRITE_FIXED from buffer index 1 */
	res = fixed_op(IORING_OP_WRITE_FIXED, (int)tf, b1, 1, 0, 1, 0, 0x1);
	if (res != 1) return (4);
	b1[0] = 0;
	res = fixed_op(IORING_OP_READ_FIXED, (int)tf, b1, 1, 0, 1, 0, 0x2);
	(void)sys1(SYS_close, tf);
	return (res == 1 && b1[0] == 'Q' ? 0 : 5);
}
static int t_provided_bid_order(void)
{
	static char pool[128]; struct cqe c[2]; long tf; int res;
	if (ring_setup(8) < 0) return (1);
	/* provide 2 buffers starting at bid 10 -> ids 10,11 */
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 2, 10, pool, 64, 3, 0x1, c) != 0) return (2);
	tf = tmpfile_fd("iou_bo"); if (tf < 0) return (3);
	if (sub1(tf, IORING_OP_WRITE, "y", 1, 0, 0, 0x2) != 1) return (4);
	if (grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, (int)tf, 0, 0, 1, 3, 0x3, c) != 0)
		return (5);
	res = c[0].res;
	(void)sys1(SYS_close, tf);
	if (res != 1) return (6);
	/* first select yields the lowest bid, 10 */
	if ((c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 10) return (7);
	return (0);
}

/* ---- timeout / cancel / link depth ---- */
static int t_cancel_all_none(void)
{
	if (ring_setup(8) < 0) return (1);
	/* cancel-all reports the number of matches, including zero. */
	return (sub1(-1, IORING_OP_ASYNC_CANCEL, (void *)0xBEEF, 0, 0,
	    IORING_ASYNC_CANCEL_ALL, 0x1) == 0 ? 0 : 2);
}
static int t_cancel_fd_identity(void)
{
	int a[2], b[2], dupfd, n, res;
	struct cqe c[8];

	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)a, 0, 0) != 0 ||
	    call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)b, 0, 0) != 0)
		return (2);
	dupfd = (int)sys1(SYS_dup, a[1]);
	if (dupfd < 0) return (3);
	iou_sqe(IORING_OP_POLL_ADD, 0, a[1], 0, 0, 0, LX_POLLIN, 0xa1);
	iou_sqe(IORING_OP_POLL_ADD, 0, b[1], 0, 0, 0, LX_POLLIN, 0xb1);
	if (iou_flush(2, 0) != 2) return (4);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, dupfd, 0, 0, 0,
	    IORING_ASYNC_CANCEL_FD, 0xc1);
	if (iou_flush(1, 2) != 1) return (5);
	n = iou_reap(c, 8);
	if (!cqe_find(c, n, 0xc1, &res) || res != 0) return (6);
	if (!cqe_find(c, n, 0xa1, &res) || res != -ELINUX_ECANCELED) return (7);
	if (cqe_find(c, n, 0xb1, &res)) return (8);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0xb1, 0, 0, 0xc2);
	if (iou_flush(1, 2) != 1) return (9);
	n = iou_reap(c, 2);
	if (!cqe_find(c, n, 0xc2, &res) || res != 0 ||
	    !cqe_find(c, n, 0xb1, &res) || res != -ELINUX_ECANCELED) return (10);
	return (0);
}

static int t_cancel_fd_all(void)
{
	int a[2], b[2], dupfd, n, res, cc = 0, i;
	struct cqe c[8];

	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)a, 0, 0) != 0 ||
	    call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)b, 0, 0) != 0)
		return (2);
	dupfd = (int)sys1(SYS_dup, a[1]);
	if (dupfd < 0) return (3);
	iou_sqe(IORING_OP_POLL_ADD, 0, a[1], 0, 0, 0, LX_POLLIN, 0xa1);
	iou_sqe(IORING_OP_POLL_ADD, 0, dupfd, 0, 0, 0, LX_POLLIN, 0xa2);
	iou_sqe(IORING_OP_POLL_ADD, 0, b[1], 0, 0, 0, LX_POLLIN, 0xb1);
	if (iou_flush(3, 0) != 3) return (4);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, dupfd, 0, 0, 0,
	    IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_ALL, 0xc1);
	if (iou_flush(1, 3) != 1) return (5);
	n = iou_reap(c, 8);
	if (!cqe_find(c, n, 0xc1, &res) || res != 2) return (6);
	for (i = 0; i < n; i++)
		if ((c[i].user_data == 0xa1 || c[i].user_data == 0xa2) &&
		    c[i].res == -ELINUX_ECANCELED) cc++;
	if (cc != 2 || cqe_find(c, n, 0xb1, &res)) return (7);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0xb1, 0, 0, 0xc2);
	if (iou_flush(1, 2) != 1) return (8);
	n = iou_reap(c, 2);
	if (!cqe_find(c, n, 0xc2, &res) || res != 0 ||
	    !cqe_find(c, n, 0xb1, &res) || res != -ELINUX_ECANCELED) return (9);
	return (0);
}

static int t_cancel_any(void)
{
	struct kts ts = { 30, 0 };
	struct cqe c[8];
	int n, res, i, cc = 0;

	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0xa1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0xa2);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0xa3);
	if (iou_flush(3, 0) != 3) return (2);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, 0, 0,
	    IORING_ASYNC_CANCEL_ANY, 0xc1);
	if (iou_flush(1, 4) != 1) return (3);
	n = iou_reap(c, 8);
	if (!cqe_find(c, n, 0xc1, &res) || res != 3) return (4);
	for (i = 0; i < n; i++) if (c[i].res == -ELINUX_ECANCELED) cc++;
	return (cc == 3 ? 0 : 5);
}

static int t_cancel_op(void)
{
	struct kts ts = { 30, 0 };
	int sv[2], n, res;
	struct cqe c[8];

	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x11);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0x12);
	iou_sqe(IORING_OP_POLL_ADD, 0, sv[1], 0, 0, 0, LX_POLLIN, 0x13);
	if (iou_flush(3, 0) != 3) return (3);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, 0, IORING_OP_TIMEOUT,
	    IORING_ASYNC_CANCEL_OP | IORING_ASYNC_CANCEL_ALL, 0x20);
	if (iou_flush(1, 3) != 1) return (4);
	n = iou_reap(c, 8);
	if (!cqe_find(c, n, 0x20, &res) || res != 2) return (5);
	if (cqe_find(c, n, 0x13, &res)) return (6);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0x13, 0, 0, 0x21);
	if (iou_flush(1, 2) != 1) return (7);
	n = iou_reap(c, 2);
	if (!cqe_find(c, n, 0x21, &res) || res != 0 ||
	    !cqe_find(c, n, 0x13, &res) || res != -ELINUX_ECANCELED) return (8);
	return (0);
}

static int t_cancel_fd_userdata(void)
{
	int a[2], b[2], n, res;
	struct cqe c[8];

	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)a, 0, 0) != 0 ||
	    call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)b, 0, 0) != 0)
		return (2);
	iou_sqe(IORING_OP_POLL_ADD, 0, a[1], 0, 0, 0, LX_POLLIN, 0x44);
	iou_sqe(IORING_OP_POLL_ADD, 0, a[1], 0, 0, 0, LX_POLLIN, 0x45);
	iou_sqe(IORING_OP_POLL_ADD, 0, b[1], 0, 0, 0, LX_POLLIN, 0x44);
	if (iou_flush(3, 0) != 3) return (3);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, a[1], 0, (void *)0x44, 0,
	    IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_USERDATA, 0x50);
	if (iou_flush(1, 2) != 1) return (4);
	n = iou_reap(c, 8);
	if (!cqe_find(c, n, 0x50, &res) || res != 0) return (5);
	if (!cqe_find(c, n, 0x44, &res) || res != -ELINUX_ECANCELED) return (6);
	if (cqe_find(c, n, 0x45, &res)) return (7);
	/* The same user_data on the other file and the other user_data survive. */
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, 0, 0, IORING_ASYNC_CANCEL_ANY, 0x51);
	if (iou_flush(1, 3) != 1) return (8);
	n = iou_reap(c, 8);
	return (cqe_find(c, n, 0x51, &res) && res == 2 ? 0 : 9);
}

static int t_cancel_fd_fixed(void)
{
	int sv[2], fds[1], n, res;
	struct cqe c[4];

	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	fds[0] = sv[1];
	if (iou_reg(IORING_REGISTER_FILES, fds, 1) != 0) return (3);
	iou_sqe(IORING_OP_POLL_ADD, 0, sv[1], 0, 0, 0, LX_POLLIN, 0xa1);
	if (iou_flush(1, 0) != 1) return (4);
	/* IOSQE_FIXED_FILE is an alternate way to mark the cancel fd fixed. */
	iou_sqe(IORING_OP_ASYNC_CANCEL, IOSQE_FIXED_FILE, 0, 0, 0, 0,
	    IORING_ASYNC_CANCEL_FD, 0xc1);
	if (iou_flush(1, 2) != 1) return (5);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xc1, &res) || res != 0) return (6);
	if (!cqe_find(c, n, 0xa1, &res) || res != -ELINUX_ECANCELED) return (7);
	/* The request's retained file identity survives closing its numeric fd. */
	iou_sqe(IORING_OP_POLL_ADD, 0, sv[1], 0, 0, 0, LX_POLLIN, 0xa2);
	if (iou_flush(1, 0) != 1) return (8);
	if (sys1(SYS_close, sv[1]) != 0) return (9);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, 0, 0, 0, 0,
	    IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_FD_FIXED, 0xc2);
	if (iou_flush(1, 2) != 1) return (10);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xc2, &res) || res != 0) return (11);
	if (!cqe_find(c, n, 0xa2, &res) || res != -ELINUX_ECANCELED) return (12);
	return (iou_reg(IORING_UNREGISTER_FILES, 0, 0) == 0 ? 0 : 13);
}

static void
sync_cancel_init(struct sync_cancel_reg *sc)
{
	xmemset(sc, 0, sizeof(*sc));
	sc->timeout.tv_sec = -1;
	sc->timeout.tv_nsec = -1;
}

static int
t_sync_cancel_userdata(void)
{
	struct sync_cancel_reg sc;
	struct kts ts = { 30, 0 };
	struct cqe c[2];
	int n, res;

	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0xa1);
	if (iou_flush(1, 0) != 1) return (2);
	sync_cancel_init(&sc); sc.addr = 0xa1;
	if (iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 1) != 0) return (3);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS,
	    0, 0) < 0) return (4);
	n = iou_reap(c, 2);
	return (n == 1 && cqe_find(c, n, 0xa1, &res) &&
	    res == -ELINUX_ECANCELED ? 0 : 5);
}

static int
t_sync_cancel_all_any(void)
{
	struct sync_cancel_reg sc;
	struct kts ts = { 30, 0 };
	struct cqe c[4];
	int n, i, cancelled;

	if (ring_setup(8) < 0) return (1);
	for (i = 0; i < 3; i++)
		iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0xa1);
	if (iou_flush(3, 0) != 3) return (2);
	sync_cancel_init(&sc); sc.addr = 0xa1;
	sc.flags = IORING_ASYNC_CANCEL_ALL;
	if (iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 1) != 3) return (3);
	if (call(SYS_io_uring_enter, fd_ring, 0, 3, IORING_ENTER_GETEVENTS,
	    0, 0) < 0) return (4);
	n = iou_reap(c, 4); cancelled = 0;
	for (i = 0; i < n; i++) if (c[i].res == -ELINUX_ECANCELED) cancelled++;
	if (cancelled != 3) return (5);
	/* ANY is a cancel-all selector and succeeds with a zero match count. */
	sync_cancel_init(&sc); sc.flags = IORING_ASYNC_CANCEL_ANY;
	return (iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 1) == 0 ? 0 : 6);
}

static int
t_sync_cancel_fd_op(void)
{
	struct sync_cancel_reg sc;
	struct kts ts = { 30, 0 };
	struct cqe c[4];
	int sv[2], n, res;

	if (ring_setup(8) < 0 || call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0) return (1);
	iou_sqe(IORING_OP_POLL_ADD, 0, sv[1], 0, 0, 0, LX_POLLIN, 0xa1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0xa2);
	if (iou_flush(2, 0) != 2) return (2);
	sync_cancel_init(&sc); sc.fd = sv[1]; sc.flags = IORING_ASYNC_CANCEL_FD;
	if (iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 1) != 0) return (3);
	sync_cancel_init(&sc); sc.opcode = IORING_OP_TIMEOUT;
	sc.flags = IORING_ASYNC_CANCEL_OP | IORING_ASYNC_CANCEL_ALL;
	if (iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 1) != 1) return (4);
	if (call(SYS_io_uring_enter, fd_ring, 0, 2, IORING_ENTER_GETEVENTS,
	    0, 0) < 0) return (5);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0xa1, &res) || res != -ELINUX_ECANCELED ||
	    !cqe_find(c, n, 0xa2, &res) || res != -ELINUX_ECANCELED) return (6);
	return (0);
}

static int
t_sync_cancel_fixed(void)
{
	struct sync_cancel_reg sc;
	struct cqe c[2];
	int sv[2], fds[1], n, res;

	if (ring_setup(8) < 0 || call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM, 0, (long)sv, 0, 0) != 0) return (1);
	fds[0] = sv[1];
	if (iou_reg(IORING_REGISTER_FILES, fds, 1) != 0) return (2);
	iou_sqe(IORING_OP_POLL_ADD, 0, sv[1], 0, 0, 0, LX_POLLIN, 0xa1);
	if (iou_flush(1, 0) != 1 || sys1(SYS_close, sv[1]) != 0) return (3);
	sync_cancel_init(&sc); sc.fd = 0;
	sc.flags = IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_FD_FIXED;
	if (iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 1) != 0) return (4);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS,
	    0, 0) < 0) return (5);
	n = iou_reap(c, 2);
	if (!cqe_find(c, n, 0xa1, &res) || res != -ELINUX_ECANCELED) return (6);
	return (iou_reg(IORING_UNREGISTER_FILES, 0, 0) == 0 ? 0 : 7);
}

static int
t_sync_cancel_invalid(void)
{
	struct sync_cancel_reg sc;
	struct kts ts = { 30, 0 };
	struct cqe c[2];
	int n, res;

	if (ring_setup(8) < 0) return (1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &ts, 1, 0, 0xa1);
	if (iou_flush(1, 0) != 1) return (2);
	sync_cancel_init(&sc); sc.addr = 0xdead;
	if (iou_reg(IORING_REGISTER_SYNC_CANCEL, 0, 1) != -EINVAL ||
	    iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 0) != -EINVAL ||
	    iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 2) != -EINVAL ||
	    iou_reg(IORING_REGISTER_SYNC_CANCEL, (void *)1, 1) != -EFAULT ||
	    iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 1) != -ENOENT) return (3);
	sc.flags = 1U << 31;
	if (iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 1) != -EINVAL) return (4);
	sync_cancel_init(&sc); sc.pad[3] = 1;
	if (iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 1) != -EINVAL) return (5);
	sync_cancel_init(&sc); sc.pad2[2] = 1;
	if (iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 1) != -EINVAL) return (6);
	sync_cancel_init(&sc); sc.fd = 9999; sc.flags = IORING_ASYNC_CANCEL_FD;
	if (iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 1) != -EBADF) return (7);
	sync_cancel_init(&sc); sc.fd = 99;
	sc.flags = IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_FD_FIXED;
	if (iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 1) != -EBADF) return (8);
	/* Rejected and missing registrations did not disturb the target. */
	sync_cancel_init(&sc); sc.addr = 0xa1;
	if (iou_reg(IORING_REGISTER_SYNC_CANCEL, &sc, 1) != 0) return (9);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS,
	    0, 0) < 0) return (10);
	n = iou_reap(c, 2);
	return (n == 1 && cqe_find(c, n, 0xa1, &res) &&
	    res == -ELINUX_ECANCELED ? 0 : 11);
}

static int
t_file_alloc_range_invalid(void)
{
	struct file_index_range range;
	int fds[3] = { -1, -1, -1 };

	if (ring_setup(8) < 0) return (1);
	xmemset(&range, 0, sizeof(range)); range.len = 1;
	if (iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, &range, 0) != -ELINUX_ENXIO ||
	    iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, 0, 0) != -EINVAL ||
	    iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, &range, 1) != -EINVAL ||
	    iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, (void *)1, 0) != -EFAULT)
		return (2);
	if (iou_reg(IORING_REGISTER_FILES, fds, 3) != 0) return (3);
	range.off = ~0U; range.len = 2;
	if (iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, &range, 0) != -ELINUX_EOVERFLOW)
		return (4);
	range.off = 2; range.len = 2;
	if (iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, &range, 0) != -EINVAL)
		return (5);
	range.off = 0; range.len = 3; range.resv = 1;
	if (iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, &range, 0) != -EINVAL)
		return (6);
	/* A zero-sized allocation window is valid and makes allocation fail. */
	range.off = 2; range.len = 0; range.resv = 0;
	if (iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, &range, 0) != 0)
		return (7);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_dir_none", 0);
	{ u32 slot = g_sqi & g_sqmask;
	  iou_sqe(IORING_OP_OPENAT, 0, LX_AT_FDCWD, 0, "iou_dir_none", 0600,
	      LX_O_RDWR | LX_O_CREAT, 0xd1); g_sqes[slot].splice_fd_in = (int)IORING_FILE_INDEX_ALLOC;
	  if (iou_flush(1, 1) != 1) return (8);
	  { struct cqe c[1]; if (iou_reap(c,1)!=1 || c[0].res!=-ENFILE) return (9); } }
	return (iou_reg(IORING_UNREGISTER_FILES, 0, 0) == 0 ? 0 : 10);
}

static void
set_file_index(u32 slot, u32 index)
{
	g_sqes[slot].splice_fd_in = (int)index;
}

static int
close_option_submit(u8 flags, int fd, u32 file_index, u16 ioprio,
    u64 off, u64 addr, u32 len, u32 rw_flags, u16 buf_index,
    u64 addr3, u64 pad, u64 ud)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_CLOSE, flags, fd, off, (void *)(unsigned long)addr,
	    len, rw_flags, ud);
	g_sqes[slot].ioprio = ioprio;
	g_sqes[slot].buf_index = buf_index;
	set_file_index(slot, file_index);
	g_sqes[slot].pad2[0] = addr3;
	g_sqes[slot].pad2[1] = pad;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != ud || c.flags != 0)
		return (-100000);
	return (c.res);
}

static int
t_close_options(void)
{
	int files[2], tf, tf2;

	if (ring_setup(16) < 0) return (1);
	/* Generic checks precede CLOSE preparation. */
	if (close_option_submit(IOSQE_FIXED_FILE, 7, 0, 1, 1, 1, 1, 1, 1,
	    0, 0, 0xc001) != -EINVAL ||
	    close_option_submit(IOSQE_FIXED_FILE|IOSQE_BUFFER_SELECT, 7, 0, 0,
	    1, 1, 1, 1, 1, 0, 0, 0xc002) != -EOPNOTSUPP) return (2);
	/* Each reserved field wins over FIXED_FILE. */
	if (close_option_submit(IOSQE_FIXED_FILE, 7, 0, 0, 1, 0, 0, 0, 0,
	    0, 0, 0xc003) != -EINVAL ||
	    close_option_submit(IOSQE_FIXED_FILE, 7, 0, 0, 0, 1, 0, 0, 0,
	    0, 0, 0xc004) != -EINVAL ||
	    close_option_submit(IOSQE_FIXED_FILE, 7, 0, 0, 0, 0, 1, 0, 0,
	    0, 0, 0xc005) != -EINVAL ||
	    close_option_submit(IOSQE_FIXED_FILE, 7, 0, 0, 0, 0, 0, 1, 0,
	    0, 0, 0xc006) != -EINVAL ||
	    close_option_submit(IOSQE_FIXED_FILE, 7, 0, 0, 0, 0, 0, 0, 1,
	    0, 0, 0xc007) != -EINVAL) return (3);
	if (close_option_submit(IOSQE_FIXED_FILE, 7, 0, 0, 0, 0, 0, 0, 0,
	    0, 0, 0xc008) != -EBADF) return (4);
	/* Direct CLOSE requires fd zero; FIXED_FILE rejection occurs first. */
	if (close_option_submit(0, 7, 1, 0, 0, 0, 0, 0, 0, 0, 0,
	    0xc009) != -EINVAL ||
	    close_option_submit(IOSQE_FIXED_FILE, 7, 1, 0, 0, 0, 0, 0, 0,
	    0, 0, 0xc00a) != -EBADF) return (5);
	/* Ordinary ASYNC close accepts unused tail words and really closes fd. */
	tf = (int)tmpfile_fd("iou_close_opt"); if (tf < 0) return (6);
	if (close_option_submit(IOSQE_ASYNC, tf, 0, 0, 0, 0, 0, 0, 0,
	    0x1234, 0x5678, 0xc00b) != 0 || sys1(SYS_close, tf) != -EBADF)
		return (7);
	/* A rejected direct close preserves the slot; valid ASYNC close removes it. */
	tf2 = (int)tmpfile_fd("iou_close_opt2"); if (tf2 < 0) return (8);
	files[0] = tf2; files[1] = -1;
	if (iou_reg(IORING_REGISTER_FILES, files, 2) != 0) return (9);
	if (close_option_submit(0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
	    0xc00c) != -EINVAL ||
	    fixed_op(IORING_OP_FSYNC, 0, 0, 0, 0, 0, IOSQE_FIXED_FILE,
	    0xc00d) != 0) return (10);
	if (close_option_submit(IOSQE_ASYNC, 0, 1, 0, 0, 0, 0, 0, 0,
	    0x9abc, 0xdef0, 0xc00e) != 0 ||
	    fixed_op(IORING_OP_FSYNC, 0, 0, 0, 0, 0, IOSQE_FIXED_FILE,
	    0xc00f) != -EBADF || sys1(SYS_close, tf2) != 0) return (11);
	return (iou_reg(IORING_UNREGISTER_FILES, 0, 0) == 0 ? 0 : 12);
}

static int
close_direct_one(u32 index, int fd, u8 flags, int badfield, u64 ud)
{
	struct cqe c[1];
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_CLOSE, flags, fd, 0, 0, 0, 0, ud);
	set_file_index(slot, index);
	if (badfield == 1) g_sqes[slot].off = 1;
	if (badfield == 2) g_sqes[slot].addr = 1;
	if (badfield == 3) g_sqes[slot].len = 1;
	if (badfield == 4) g_sqes[slot].rw_flags = 1;
	if (badfield == 5) g_sqes[slot].buf_index = 1;
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].user_data != ud || c[0].flags != 0)
		return (-100000);
	return (c[0].res);
}

static int
t_close_direct(void)
{
	long tf, ambient;
	int fds[2], res;

	if (ring_setup(16) < 0) return (1);
	if (close_direct_one(1, 0, 0, 0, 0xc01) != -ELINUX_ENXIO)
		return (2);
	tf = tmpfile_fd("iou_close_direct");
	if (tf < 0 || sub1((int)tf, IORING_OP_WRITE, "C", 1, 0, 0,
	    0xc02) != 1) return (3);
	fds[0] = (int)tf; fds[1] = -1;
	if (iou_reg(IORING_REGISTER_FILES, fds, 2) != 0) return (4);
	if (close_direct_one(2, 0, 0, 0, 0xc03) != -EBADF ||
	    close_direct_one(3, 0, 0, 0, 0xc04) != -EINVAL) return (5);
	/* fd must be zero and IOSQE_FIXED_FILE is invalid for direct CLOSE. */
	if (close_direct_one(1, 1, 0, 0, 0xc05) != -EINVAL ||
	    fixed_op(IORING_OP_FSYNC, 0, 0, 0, 0, 0, IOSQE_FIXED_FILE,
	    0xc06) != 0 ||
	    close_direct_one(1, 0, IOSQE_FIXED_FILE, 0, 0xc07) != -EBADF ||
	    fixed_op(IORING_OP_FSYNC, 0, 0, 0, 0, 0, IOSQE_FIXED_FILE,
	    0xc08) != 0) return (6);
	/* Every reserved CLOSE field rejects without removing the slot. */
	for (int field = 1; field <= 5; field++) {
		res = close_direct_one(1, 0, 0, field, 0xc10 + field);
		if (res != -EINVAL || fixed_op(IORING_OP_FSYNC, 0, 0, 0, 0,
		    0, IOSQE_FIXED_FILE, 0xc20 + field) != 0) return (7);
	}
	if (close_direct_one(1, 0, 0, 0, 0xc30) != 0 ||
	    fixed_op(IORING_OP_FSYNC, 0, 0, 0, 0, 0, IOSQE_FIXED_FILE,
	    0xc31) != -EBADF ||
	    close_direct_one(1, 0, 0, 0, 0xc32) != -EBADF) return (8);
	if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0) return (9);
	/* file_index zero remains ordinary CLOSE. */
	ambient = tmpfile_fd("iou_close_ambient");
	if (ambient < 0 || close_direct_one(0, (int)ambient, 0, 0,
	    0xc40) != 0 || sys1(SYS_close, ambient) != -EBADF) return (10);
	return (sys1(SYS_close, tf) == 0 ? 0 : 11);
}

static int
t_open_direct_alloc_range(void)
{
	struct file_index_range range = { 1, 2, 0 };
	struct files_update up;
	struct cqe c[2];
	char rb[4];
	int fds[4] = { -1, -1, -1, -1 }, clear = -1, n, res;
	u32 slot;

	if (ring_setup(8) < 0 || iou_reg(IORING_REGISTER_FILES, fds, 4) != 0 ||
	    iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, &range, 0) != 0) return (1);
	for (int i = 0; i < 2; i++) {
		char *name = i == 0 ? "iou_da1" : "iou_da2";
		(void)sys3(SYS_unlinkat, AT_FDCWD, name, 0);
		slot = g_sqi & g_sqmask;
		iou_sqe(IORING_OP_OPENAT, 0, LX_AT_FDCWD, 0, name, 0600,
		    LX_O_RDWR | LX_O_CREAT, 0xd0 + i); set_file_index(slot, IORING_FILE_INDEX_ALLOC);
		if (iou_flush(1, 1) != 1) return (2);
		n = iou_reap(c, 2); if (n != 1 || c[0].res != 1 + i) return (3);
		if (fixed_op(IORING_OP_WRITE, 1 + i, "ok", 2, 0, 0,
		    IOSQE_FIXED_FILE, 0xe0 + i) != 2) return (4);
	}
	/* The configured range is full. */
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT, 0, LX_AT_FDCWD, 0, "iou_da3", 0600,
	    LX_O_RDWR | LX_O_CREAT, 0xd3); set_file_index(slot, IORING_FILE_INDEX_ALLOC);
	if (iou_flush(1, 1) != 1 || iou_reap(c,1)!=1 || c[0].res != -ENFILE)
		return (5);
	/* Free slot 1; allocation wraps and reuses it. */
	xmemset(&up,0,sizeof(up));up.offset=1;up.fds=(u64)(unsigned long)&clear;
	if (iou_reg(IORING_REGISTER_FILES_UPDATE,&up,1)!=1) return (6);
	slot=g_sqi&g_sqmask;iou_sqe(IORING_OP_OPENAT,0,LX_AT_FDCWD,0,"iou_da4",0600,
	    LX_O_RDWR|LX_O_CREAT,0xd4);set_file_index(slot,IORING_FILE_INDEX_ALLOC);
	if(iou_flush(1,1)!=1||iou_reap(c,1)!=1||c[0].res!=1)return (7);
	xmemset(rb,0,sizeof(rb));res=fixed_op(IORING_OP_READ,1,rb,2,0,0,
	    IOSQE_FIXED_FILE,0xe4);if(res!=0)return (8);
	return (0);
}

static int
t_linked_file_feature(void)
{
	struct cqe c[4];
	int files[2] = { -1, -1 };
	int open_result, result, write_result;
	char byte = 0;
	u32 slot;

	if (ring_setup(8) < 0 ||
	    iou_reg(IORING_REGISTER_FILES, files, 2) != 0)
		return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_linked_file", 0);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT, IOSQE_IO_LINK, LX_AT_FDCWD, 0,
	    "iou_linked_file", 0600, LX_O_RDWR | LX_O_CREAT, 0x7511);
	set_file_index(slot, 1);
	iou_sqe(IORING_OP_WRITE, IOSQE_FIXED_FILE, 0, 0,
	    "L", 1, 0, 0x7512);
	if (iou_flush(2, 2) != 2 || iou_reap(c, 2) != 2)
		return (2);
	if (!cqe_find(c, 2, 0x7511, &result) ||
	    !cqe_find(c, 2, 0x7512, &result))
		return (3);
	open_result = write_result = -1;
	for (int i = 0; i < 2; i++) {
		if (c[i].user_data == 0x7511)
			open_result = c[i].res;
		if (c[i].user_data == 0x7512)
			write_result = c[i].res;
	}
	if (open_result != 0 || write_result != 1)
		return (4);
	if (fixed_op(IORING_OP_READ, 0, &byte, 1, 0, 0,
	    IOSQE_FIXED_FILE, 0x7513) != 1 || byte != 'L')
		return (5);

	/* A failed producer cancels its dependent; slot 1 stays empty. */
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_linked_missing", 0);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT, IOSQE_IO_LINK, LX_AT_FDCWD, 0,
	    "iou_linked_missing", 0600, 0, 0x7521);
	set_file_index(slot, 2);
	iou_sqe(IORING_OP_READ, IOSQE_FIXED_FILE, 1, 0,
	    &byte, 1, 0, 0x7522);
	if (iou_flush(2, 2) != 2 || iou_reap(c, 2) != 2)
		return (6);
	open_result = write_result = 0;
	for (int i = 0; i < 2; i++) {
		if (c[i].user_data == 0x7521)
			open_result = c[i].res;
		if (c[i].user_data == 0x7522)
			write_result = c[i].res;
	}
	if (open_result != -ENOENT || write_result != -ELINUX_ECANCELED)
		return (7);
	return (0);
}

static int
open_submit(u8 op, u8 flags, u64 off, void *path, u32 len, u32 open_flags,
    u16 ioprio, u16 buf_index, u32 file_index, u64 addr3, u64 pad, u64 ud)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(op, flags, LX_AT_FDCWD, off, path, len, open_flags, ud);
	g_sqes[slot].ioprio = ioprio;
	g_sqes[slot].buf_index = buf_index;
	set_file_index(slot, file_index);
	g_sqes[slot].pad2[0] = addr3;
	g_sqes[slot].pad2[1] = pad;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != ud || c.flags != 0)
		return (-100000);
	return (c.res);
}

static int
t_open_options(void)
{
	struct { struct l_open_how how; u64 extra; } ext;
	int files[2] = { -1, -1 };
	int fd;

	if (ring_setup(16) < 0) return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_open_opt", 0);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_open_opt2", 0);
	/* Generic option checks precede opcode preparation. */
	if (open_submit(IORING_OP_OPENAT, 0, 0, (void *)1, 0600,
	    LX_O_RDWR|LX_O_CREAT, 1, 0, 0, 0, 0, 0xb001) != -EINVAL ||
	    open_submit(IORING_OP_OPENAT, IOSQE_BUFFER_SELECT, 0, (void *)1,
	    0600, LX_O_RDWR|LX_O_CREAT, 0, 7, 0, 0, 0, 0xb002) != -EOPNOTSUPP)
		return (2);
	/* OPENAT checks buf_index, FIXED_FILE, and pathname in that order. */
	if (open_submit(IORING_OP_OPENAT, IOSQE_FIXED_FILE, 0, (void *)1, 0600,
	    LX_O_RDWR|LX_O_CREAT, 0, 1, 0, 0, 0, 0xb003) != -EINVAL ||
	    open_submit(IORING_OP_OPENAT, IOSQE_FIXED_FILE, 0, (void *)1, 0600,
	    LX_O_RDWR|LX_O_CREAT, 0, 0, 0, 0, 0, 0xb004) != -EBADF ||
	    open_submit(IORING_OP_OPENAT, 0, 0, (void *)1, 0600,
	    LX_O_RDWR|LX_O_CREAT, 0, 0, 0, 0, 0, 0xb005) != -EFAULT)
		return (3);
	xmemset(&ext, 0, sizeof(ext)); ext.how.flags = LX_O_RDWR|LX_O_CREAT;
	ext.how.mode = 0600;
	/* OPENAT2 copies open_how before buf_index, FIXED_FILE, and pathname. */
	if (open_submit(IORING_OP_OPENAT2, 0, 1, "iou_open_opt2",
	    sizeof(ext.how)-1, 0, 0, 0, 0, 0, 0, 0xb006) != -EINVAL ||
	    open_submit(IORING_OP_OPENAT2, 0, 1, "iou_open_opt2",
	    sizeof(ext.how), 0, 0, 1, 0, 0, 0, 0xb007) != -EFAULT)
		return (4);
	ext.extra = 1;
	if (open_submit(IORING_OP_OPENAT2, IOSQE_FIXED_FILE,
	    (u64)(unsigned long)&ext, "iou_open_opt2", sizeof(ext), 0,
	    0, 0, 0, 0, 0, 0xb008) != -E2BIG) return (5);
	ext.extra = 0;
	if (open_submit(IORING_OP_OPENAT2, IOSQE_FIXED_FILE,
	    (u64)(unsigned long)&ext.how, "iou_open_opt2", sizeof(ext.how), 0,
	    0, 1, 0, 0, 0, 0xb009) != -EINVAL ||
	    open_submit(IORING_OP_OPENAT2, IOSQE_FIXED_FILE,
	    (u64)(unsigned long)&ext.how, "iou_open_opt2", sizeof(ext.how), 0,
	    0, 0, 0, 0, 0, 0xb00a) != -EBADF ||
	    open_submit(IORING_OP_OPENAT2, 0, (u64)(unsigned long)&ext.how,
	    (void *)1, sizeof(ext.how), 0, 0, 0, 0, 0, 0, 0xb00b) != -EFAULT)
		return (6);
	/* Generic checks still precede the OPENAT2 copy. */
	if (open_submit(IORING_OP_OPENAT2, 0, 1, "iou_open_opt2",
	    sizeof(ext.how), 0, 1, 0, 0, 0, 0, 0xb00c) != -EINVAL ||
	    open_submit(IORING_OP_OPENAT2, IOSQE_BUFFER_SELECT, 1,
	    "iou_open_opt2", sizeof(ext.how), 0, 0, 0, 0, 0, 0, 0xb00d) !=
	    -EOPNOTSUPP) return (7);
	/* Invalid open_how flags, mode, and resolve have no side effect. */
	ext.how.flags = ~0ULL;
	if (open_submit(IORING_OP_OPENAT2, 0, (u64)(unsigned long)&ext.how,
	    "iou_open_opt2", sizeof(ext.how), 0, 0, 0, 0, 0, 0, 0xb00e) !=
	    -EINVAL) return (8);
	ext.how.flags = LX_O_RDWR; ext.how.mode = 0600;
	if (open_submit(IORING_OP_OPENAT2, 0, (u64)(unsigned long)&ext.how,
	    "iou_open_opt2", sizeof(ext.how), 0, 0, 0, 0, 0, 0, 0xb00f) !=
	    -EINVAL) return (9);
	ext.how.mode = 0; ext.how.resolve = ~0ULL;
	if (open_submit(IORING_OP_OPENAT2, 0, (u64)(unsigned long)&ext.how,
	    "iou_open_opt2", sizeof(ext.how), 0, 0, 0, 0, 0, 0, 0xb010) !=
	    -EINVAL) return (10);
	/* ASYNC and the unused tail words are accepted. */
	fd = open_submit(IORING_OP_OPENAT, IOSQE_ASYNC, 0, "iou_open_opt", 0600,
	    LX_O_RDWR|LX_O_CREAT, 0, 0, 0, 0x1234, 0x5678, 0xb011);
	if (fd < 0 || sys1(SYS_close, fd) != 0) return (11);
	/* Failed direct opens preserve an empty slot; a valid one fills it. */
	if (iou_reg(IORING_REGISTER_FILES, files, 2) != 0) return (12);
	ext.how.flags = LX_O_RDWR|LX_O_CREAT; ext.how.mode = 0600;
	ext.how.resolve = 0; ext.extra = 1;
	if (open_submit(IORING_OP_OPENAT2, 0, (u64)(unsigned long)&ext,
	    "iou_open_opt2", sizeof(ext), 0, 0, 0, 1, 0, 0, 0xb012) != -E2BIG ||
	    fixed_op(IORING_OP_FSYNC, 0, 0, 0, 0, 0, IOSQE_FIXED_FILE,
	    0xb013) != -EBADF) return (13);
	ext.extra = 0;
	if (open_submit(IORING_OP_OPENAT2, IOSQE_ASYNC,
	    (u64)(unsigned long)&ext.how, "iou_open_opt2", sizeof(ext.how), 0,
	    0, 0, 1, 0x9abc, 0xdef0, 0xb014) != 0 ||
	    fixed_op(IORING_OP_WRITE, 0, "ok", 2, 0, 0, IOSQE_FIXED_FILE,
	    0xb015) != 2) return (14);
	return (iou_reg(IORING_UNREGISTER_FILES, 0, 0) == 0 ? 0 : 15);
}

static int
t_open_direct_cloexec(void)
{
	struct {
		struct l_open_how how;
		u64 extra;
	} ext;
	struct cqe c[2];
	int files[2] = { -1, -1 };
	u32 slot;

	if (ring_setup(8) < 0 ||
	    iou_reg(IORING_REGISTER_FILES, files, 2) != 0)
		return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_cloexec_at", 0);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_cloexec_at2", 0);

	/* OPENAT imports the pathname before rejecting direct O_CLOEXEC. */
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT, 0, AT_FDCWD, 0, (void *)1, 0600,
	    LX_O_RDWR | LX_O_CREAT | LX_O_CLOEXEC, 0xa80);
	set_file_index(slot, 1);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].res != -EFAULT)
		return (2);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT, 0, AT_FDCWD, 0, "iou_cloexec_at", 0600,
	    LX_O_RDWR | LX_O_CREAT | LX_O_CLOEXEC, 0xa81);
	set_file_index(slot, 1);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].res != -EINVAL || c[0].flags != 0 ||
	    call(SYS_openat, AT_FDCWD, (long)"iou_cloexec_at",
	    LX_O_RDWR, 0, 0, 0) != -ENOENT)
		return (3);

	/* OPENAT2 copies and extends open_how before pathname import. */
	xmemset(&ext, 0, sizeof(ext));
	ext.how.flags = LX_O_RDWR | LX_O_CREAT | LX_O_CLOEXEC;
	ext.how.mode = 0600;
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT2, 0, AT_FDCWD, 1, "iou_cloexec_at2",
	    sizeof(ext.how), 0, 0xa82);
	set_file_index(slot, 1);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].res != -EFAULT)
		return (4);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT2, 0, AT_FDCWD, (u64)(unsigned long)&ext.how,
	    (void *)1, sizeof(ext.how), 0, 0xa83);
	set_file_index(slot, 1);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].res != -EFAULT)
		return (5);
	ext.extra = 1;
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT2, 0, AT_FDCWD, (u64)(unsigned long)&ext,
	    "iou_cloexec_at2", sizeof(ext), 0, 0xa84);
	set_file_index(slot, 1);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].res != -E2BIG)
		return (6);
	ext.extra = 0;
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT2, 0, AT_FDCWD, (u64)(unsigned long)&ext.how,
	    "iou_cloexec_at2", sizeof(ext.how), 0, 0xa85);
	set_file_index(slot, 1);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].res != -EINVAL || c[0].flags != 0 ||
	    call(SYS_openat, AT_FDCWD, (long)"iou_cloexec_at2",
	    LX_O_RDWR, 0, 0, 0) != -ENOENT)
		return (7);

	/* Both rejected slots remain available for valid direct opens. */
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT, 0, AT_FDCWD, 0, "iou_cloexec_at", 0600,
	    LX_O_RDWR | LX_O_CREAT, 0xa86);
	set_file_index(slot, 1);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 || c[0].res != 0 ||
	    fixed_op(IORING_OP_WRITE, 0, "a", 1, 0, 0, IOSQE_FIXED_FILE,
	    0xa87) != 1)
		return (8);
	ext.how.flags &= ~LX_O_CLOEXEC;
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT2, 0, AT_FDCWD, (u64)(unsigned long)&ext.how,
	    "iou_cloexec_at2", sizeof(ext.how), 0, 0xa88);
	set_file_index(slot, 2);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 || c[0].res != 0 ||
	    fixed_op(IORING_OP_WRITE, 1, "b", 1, 0, 0, IOSQE_FIXED_FILE,
	    0xa89) != 1)
		return (9);
	return (0);
}

static int
t_open_socket_direct_explicit(void)
{
	struct cqe c[2];
	int fds[4] = { -1, -1, -1, -1 }, res, newfd;
	u32 slot;

	if (ring_setup(8) < 0 || iou_reg(IORING_REGISTER_FILES, fds, 4) != 0)
		return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_de", 0);
	slot=g_sqi&g_sqmask;iou_sqe(IORING_OP_OPENAT,0,LX_AT_FDCWD,0,"iou_de",0600,
	    LX_O_RDWR|LX_O_CREAT,0xf1);set_file_index(slot,4); /* one-based -> slot 3 */
	if(iou_flush(1,1)!=1||iou_reap(c,1)!=1||c[0].res!=0)return (2);
	if(fixed_op(IORING_OP_WRITE,3,"file",4,0,0,IOSQE_FIXED_FILE,0xf2)!=4)return (3);
	/* Explicit installation replaces an occupied slot. */
	slot=g_sqi&g_sqmask;iou_sqe(IORING_OP_SOCKET,0,LX_AF_UNIX,LX_SOCK_STREAM,0,0,0,0xf3);
	set_file_index(slot,4);if(iou_flush(1,1)!=1||iou_reap(c,1)!=1||c[0].res!=0)return (4);
	newfd=sub1flags(3,IORING_OP_FIXED_FD_INSTALL,IOSQE_FIXED_FILE,0,0,0,0xf4);
	if(newfd<0)return (5);res=(int)sys1(SYS_close,newfd);if(res!=0)return (6);
	/* One-based explicit indices reject zero-via-direct absence and OOB. */
	slot=g_sqi&g_sqmask;iou_sqe(IORING_OP_OPENAT,0,LX_AT_FDCWD,0,"iou_oob",0600,
	    LX_O_RDWR|LX_O_CREAT,0xf5);set_file_index(slot,5);
	if(iou_flush(1,1)!=1||iou_reap(c,1)!=1||c[0].res!=-EINVAL)return (7);
	return (0);
}

static int
t_openat2_direct(void)
{
	struct l_open_how how;
	struct file_index_range range = { 0, 2, 0 };
	struct cqe c[1];
	char data[4] = { 0 };
	int fds[3] = { -1, -1, -1 }, res;
	u32 slot;

	if (ring_setup(8) < 0 ||
	    iou_reg(IORING_REGISTER_FILES, fds, 3) != 0 ||
	    iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, &range, 0) != 0)
		return (1);
	xmemset(&how, 0, sizeof(how));
	how.flags = LX_O_RDWR | LX_O_CREAT;
	how.mode = 0600;
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_openat2_direct", 0);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT2, 0, LX_AT_FDCWD,
	    (u64)(unsigned long)&how, "iou_openat2_direct", sizeof(how), 0,
	    0xf6);
	set_file_index(slot, IORING_FILE_INDEX_ALLOC);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 || c[0].res != 0)
		return (2);
	if (fixed_op(IORING_OP_WRITE, 0, "v2", 2, 0, 0,
	    IOSQE_FIXED_FILE, 0xf7) != 2)
		return (3);
	/* A failed open does not consume the allocation hint or replace a slot. */
	how.flags = LX_O_RDWR;
	how.mode = 0;
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT2, 0, LX_AT_FDCWD,
	    (u64)(unsigned long)&how, "iou_openat2_missing", sizeof(how), 0,
	    0xf8);
	set_file_index(slot, IORING_FILE_INDEX_ALLOC);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].res != -ENOENT)
		return (4);
	/* Explicit one-based installation into slot 2 returns zero. */
	how.flags = LX_O_RDWR | LX_O_CREAT;
	how.mode = 0600;
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_openat2_explicit", 0);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_OPENAT2, 0, LX_AT_FDCWD,
	    (u64)(unsigned long)&how, "iou_openat2_explicit", sizeof(how), 0,
	    0xf9);
	set_file_index(slot, 3);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 || c[0].res != 0)
		return (5);
	if (fixed_op(IORING_OP_WRITE, 2, "ok", 2, 0, 0,
	    IOSQE_FIXED_FILE, 0xfa) != 2)
		return (6);
	res = fixed_op(IORING_OP_READ, 0, data, 2, 0, 0,
	    IOSQE_FIXED_FILE, 0xfb);
	return (res == 2 && xmemcmp(data, "v2", 2) == 0 ? 0 : 7);
}

static int t_link_all_skip(void)
{
	struct cqe c[4]; int n, res;
	if (ring_setup(8) < 0) return (1);
	/* every op in the chain skips its success CQE except by count we get 0 */
	iou_sqe(IORING_OP_NOP, IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS, -1, 0, 0, 0, 0, 0x1);
	iou_sqe(IORING_OP_NOP, IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS, -1, 0, 0, 0, 0, 0x2);
	iou_sqe(IORING_OP_NOP, IOSQE_CQE_SKIP_SUCCESS, -1, 0, 0, 0, 0, 0x3);
	if (iou_flush(3, 0) != 3) return (2);
	/* run_ready already posted (none); nothing to reap */
	n = iou_reap(c, 4);
	if (n != 0) return (3);
	/* ring healthy */
	if (sub1(-1, IORING_OP_NOP, 0, 0, 0, 0, 0x4) != 0) return (4);
	(void)res;
	return (0);
}
static int t_link_async_rw(void)
{
	struct cqe c[4]; struct kts ts; long tf; int n, res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_lar"); if (tf < 0) return (2);
	ts.tv_sec = 0; ts.tv_nsec = 12000000LL;
	/* ETIME_SUCCESS keeps the link alive while the timeout reports ETIME. */
	iou_sqe(IORING_OP_TIMEOUT, IOSQE_IO_LINK, -1, 0, &ts, 1,
	    IORING_TIMEOUT_ETIME_SUCCESS, 0x1);
	iou_sqe(IORING_OP_WRITE, IOSQE_IO_LINK, tf, 0, "chain!!", 7, 0, 0x2);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x3);
	if (iou_flush(3, 3) != 3) return (3);
	n = iou_reap(c, 4);
	(void)sys1(SYS_close, tf);
	if (n != 3) return (4);
	if (!cqe_find(c, n, 0x1, &res) || res != -ELINUX_ETIME) return (5);
	if (!cqe_find(c, n, 0x2, &res) || res != 7) return (6);
	if (!cqe_find(c, n, 0x3, &res) || res != 0) return (7);
	return (0);
}

/* ---- adversarial ---- */
static int t_garbage_sweep(void)
{
	int op;
	/*
	 * Submit every opcode 0..64 with empty args on a fresh ring; the
	 * kernel must survive each (no panic, no hang).  We submit without a
	 * GETEVENTS wait so a parking op does not block, drain whatever posted,
	 * and move on.  The invariant is simply that the process completes.
	 */
	for (op = 0; op <= 64; op++) {
		struct cqe c[2];
		if (ring_setup(8) < 0) return (1);
		iou_sqe((u8)op, 0, -1, 0, 0, 0, 0, 0x1);
		__atomic_store_n(g_sq_tail, g_sqi, __ATOMIC_RELEASE);
		if (call(SYS_io_uring_enter, fd_ring, 1, 0, 0, 0, 0) != 1) {
			(void)sys1(SYS_close, fd_ring);
			return (2);
		}
		(void)iou_reap(c, 2);
		(void)sys1(SYS_close, fd_ring);
	}
	return (0);
}
static int t_sq_index_boundary(void)
{
	if (ring_setup(8) < 0) return (1);
	g_sq_array[0] = 8;		/* == sq_entries: out of range -> dropped */
	g_sqi = 1;
	__atomic_store_n(g_sq_tail, 1, __ATOMIC_RELEASE);
	if (call(SYS_io_uring_enter, fd_ring, 1, 0, 0, 0, 0) != 0) return (2);
	if (__atomic_load_n(g_sq_dropped, __ATOMIC_ACQUIRE) != 1) return (3);
	return (0);
}
static int t_probe_nr0(void)
{
	struct probe pr;
	if (ring_setup(8) < 0) return (1);
	xmemset(&pr, 0, sizeof(pr));
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PROBE,
	    (long)&pr, 0, 0, 0) != 0) return (2);
	return (pr.ops_len == 0 && pr.last_op != 0 ? 0 : 3);
}
static int t_probe_nr256(void)
{
	struct probe pr;
	if (ring_setup(8) < 0) return (1);
	xmemset(&pr, 0, sizeof(pr));
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PROBE,
	    (long)&pr, 256, 0, 0) != 0) return (2);
	/* clamped to IORING_OP_LAST (65) */
	return (pr.ops_len == 65 ? 0 : 3);
}
static int t_enter_submit_huge(void)
{
	struct cqe c[8]; int i, n;
	if (ring_setup(8) < 0) return (1);
	for (i = 0; i < 3; i++) iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 0x1 + i);
	__atomic_store_n(g_sq_tail, g_sqi, __ATOMIC_RELEASE);
	/* to_submit far exceeds what's queued: submit only the 3 present */
	if (call(SYS_io_uring_enter, fd_ring, 100, 3, IORING_ENTER_GETEVENTS, 0, 0) != 3)
		return (2);
	n = iou_reap(c, 8);
	return (n == 3 ? 0 : 3);
}
static int t_double_close(void)
{
	long tf; int res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_dc"); if (tf < 0) return (2);
	if (sub1(tf, IORING_OP_CLOSE, 0, 0, 0, 0, 0x1) != 0) return (3);
	res = sub1((int)tf, IORING_OP_CLOSE, 0, 0, 0, 0, 0x2);
	return (res == -EBADF ? 0 : 4);
}

/* ---- stress ---- */
static int t_stress_5000(void)
{
	struct cqe c[8]; int b, i, n, total = 0;
	if (ring_setup(8) < 0) return (1);
	for (b = 0; b < 625; b++) {
		for (i = 0; i < 8; i++) iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 1);
		if (iou_flush(8, 8) != 8) return (2);
		n = iou_reap(c, 8); if (n != 8) return (3);
		total += n;
	}
	return (total == 5000 ? 0 : 4);
}
static int t_stress_mixed_rw(void)
{
	long tf; char buf[32]; int i, res;
	if (ring_setup(8) < 0) return (1);
	tf = tmpfile_fd("iou_smx"); if (tf < 0) return (2);
	for (i = 0; i < 300; i++) {
		xmemset(buf, 'a' + (i % 26), sizeof(buf));
		res = sub1(tf, IORING_OP_WRITE, buf, sizeof(buf), (u64)i * 32, 0, 0x1);
		if (res != (int)sizeof(buf)) return (3);
		if ((i & 3) == 0 && sub1(tf, IORING_OP_FSYNC, 0, 0, 0, 0, 0x2) != 0)
			return (4);
	}
	(void)sys1(SYS_close, tf);
	return (0);
}
static int t_stress_reg_cycle(void)
{
	static char buf[4096]; struct iovec iov; int i;
	if (ring_setup(8) < 0) return (1);
	iov.iov_base = buf; iov.iov_len = sizeof(buf);
	/* register/unregister repeatedly: no leak, no crash */
	for (i = 0; i < 50; i++) {
		if (iou_reg(IORING_REGISTER_BUFFERS, &iov, 1) != 0) return (2);
		if (iou_reg(IORING_UNREGISTER_BUFFERS, 0, 0) != 0) return (3);
	}
	return (0);
}
static int t_stress_open_close(void)
{
	int i, fd;
	if (ring_setup(8) < 0) return (1);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_oc", 0);
	for (i = 0; i < 100; i++) {
		fd = sub1(LX_AT_FDCWD, IORING_OP_OPENAT, "iou_oc", 0600,
		    0, LX_O_RDWR | LX_O_CREAT, 0x1);
		if (fd < 0) return (2);
		if (sub1(fd, IORING_OP_CLOSE, 0, 0, 0, 0, 0x2) != 0) return (3);
	}
	(void)sys3(SYS_unlinkat, AT_FDCWD, "iou_oc", 0);
	return (0);
}

/* A selected buffer returned after EAGAIN/cancel keeps its full capacity. */
static int
t_provided_retry_capacity(void)
{
	static char pool[64];
	static const char payload[] = "0123456789abcdef";
	struct cqe c[4];
	u32 slot;
	int sv[2], n, res;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_DGRAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 1, 40, pool, sizeof(pool),
	    16, 0x910, c) != 0 || c[0].res != 0)
		return (3);
	/* The empty receive selects only four bytes, gets EAGAIN, and parks. */
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 4, 0,
	    0x911);
	g_sqes[slot].buf_index = 16;
	if (iou_flush(1, 0) != 1 || iou_reap(c, 4) != 0)
		return (4);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0x911, 0, 0,
	    0x912);
	if (iou_flush(1, 2) != 1)
		return (5);
	n = iou_reap(c, 4);
	if (!cqe_find(c, n, 0x912, &res) || res != 0 ||
	    !cqe_find(c, n, 0x911, &res) || res != -ELINUX_ECANCELED)
		return (6);
	/* Reusing the same buffer for a larger request must expose all 64 bytes. */
	if (call(SYS_write, sv[0], (long)payload, sizeof(payload) - 1,
	    0, 0, 0) != (long)sizeof(payload) - 1)
		return (7);
	xmemset(pool, 0, sizeof(pool));
	if (grp_op(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0,
	    sizeof(pool), 16, 0x913, c) != 0)
		return (8);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (c[0].res != (int)sizeof(payload) - 1 ||
	    (c[0].flags & IORING_CQE_F_BUFFER) == 0 ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 40)
		return (9);
	return (xmemcmp(pool, payload, sizeof(payload) - 1) == 0 ? 0 : 10);
}

/* ================= SEND_ZC ioprio options ================= */
static int
t_ioprio_send_zc_fixed(void)
{
	static char buf[64];
	struct iovec reg;
	struct cqe c[4];
	char rb[8];
	u32 slot;
	int sv[2], n, i, primary = 0, notif = 0;

	if (ring_setup(8) < 0)
		return (1);
	xmemset(buf, 0, sizeof(buf));
	xmemcpy(buf + 3, "fixed", 5);
	reg.iov_base = buf; reg.iov_len = sizeof(buf);
	if (iou_reg(IORING_REGISTER_BUFFERS, &reg, 1) != 0)
		return (2);
	if (zcrx_tcp_pair(&sv[0], &sv[1]) != 0)
		return (3);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SEND_ZC, 0, sv[0], 0, buf + 3, 5, 0, 0x960);
	g_sqes[slot].buf_index = 0;
	g_sqes[slot].ioprio =
	    IORING_RECVSEND_FIXED_BUF | IORING_SEND_ZC_REPORT_USAGE;
	if (iou_flush(1, 2) != 1)
		return (4);
	n = iou_reap(c, 4);
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x960)
			continue;
		if ((c[i].flags & IORING_CQE_F_NOTIF) != 0) {
			if ((u32)c[i].res != IORING_NOTIF_USAGE_ZC_COPIED)
				return (5);
			notif = 1;
		} else {
			if (c[i].res != 5)
				return (c[i].res < 0 ? -c[i].res : 20);
			if ((c[i].flags & IORING_CQE_F_MORE) == 0)
				return (21);
			primary = 1;
		}
	}
	xmemset(rb, 0, sizeof(rb));
	if (!primary || !notif ||
	    call(SYS_read, sv[1], (long)rb, 5, 0, 0, 0) != 5 ||
	    xmemcmp(rb, "fixed", 5) != 0)
		return (6);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_ioprio_send_zc_fixed_vectorized(void)
{
	static char buf[64];
	struct iovec reg, parts[2];
	struct cqe c[4];
	char rb[8];
	u32 slot;
	int sv[2], n, i, primary = 0, notif = 0;

	if (ring_setup(8) < 0)
		return (1);
	xmemset(buf, 0, sizeof(buf));
	xmemcpy(buf + 3, "fixed", 5);
	reg.iov_base = buf; reg.iov_len = sizeof(buf);
	parts[0].iov_base = buf + 3; parts[0].iov_len = 2;
	parts[1].iov_base = buf + 5; parts[1].iov_len = 3;
	if (iou_reg(IORING_REGISTER_BUFFERS, &reg, 1) != 0)
		return (2);
	if (zcrx_tcp_pair(&sv[0], &sv[1]) != 0)
		return (3);
	if (sys3(SYS_fcntl, sv[1], 4 /* F_SETFL */, 04000) != 0)
		return (30);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SEND_ZC, 0, sv[0], 0, parts, 2, 0, 0x960);
	g_sqes[slot].buf_index = 0;
	g_sqes[slot].ioprio =
	    IORING_RECVSEND_FIXED_BUF | IORING_SEND_ZC_REPORT_USAGE |
	    IORING_SEND_VECTORIZED;
	if (iou_flush(1, 2) != 1)
		return (4);
	n = iou_reap(c, 4);
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x960)
			continue;
		if ((c[i].flags & IORING_CQE_F_NOTIF) != 0) {
			if ((u32)c[i].res != IORING_NOTIF_USAGE_ZC_COPIED)
				return (5);
			notif = 1;
		} else {
			if (c[i].res != 5)
				return (c[i].res < 0 ? -c[i].res : 20);
			if ((c[i].flags & IORING_CQE_F_MORE) == 0)
				return (21);
			primary = 1;
		}
	}
	if (!primary)
		return (40);
	if (!notif)
		return (41);
	/*
	 * A successful SEND_ZC CQE means that the send was accepted, but the
	 * receiving TCP socket can still report EAGAIN until the input path runs.
	 * Wait for receive readiness so this test checks the transferred bytes
	 * rather than scheduler timing.
	 */
	if (!wait_readable(sv[1], 1000))
		return (6);
	xmemset(rb, 0, sizeof(rb));
	if (call(SYS_read, sv[1], (long)rb, 5, 0, 0, 0) != 5)
		return (7);
	if (xmemcmp(rb, "fixed", 5) != 0)
		return (8);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_ioprio_sendmsg_zc_fixed(void)
{
	static char buf[64];
	struct iovec reg, parts[2];
	struct l_msghdr mh;
	struct cqe c[4];
	char rb[8];
	u32 slot;
	int sv[2], n, i, primary = 0, notif = 0;

	if (ring_setup(8) < 0)
		return (1);
	xmemset(buf, 0, sizeof(buf));
	xmemcpy(buf, "msg", 3); xmemcpy(buf + 8, "fix", 3);
	reg.iov_base = buf; reg.iov_len = sizeof(buf);
	if (iou_reg(IORING_REGISTER_BUFFERS, &reg, 1) != 0)
		return (2);
	if (zcrx_tcp_pair(&sv[0], &sv[1]) != 0)
		return (3);
	parts[0].iov_base = buf; parts[0].iov_len = 3;
	parts[1].iov_base = buf + 8; parts[1].iov_len = 3;
	xmemset(&mh, 0, sizeof(mh));
	mh.msg_iov = (u64)(unsigned long)parts;
	mh.msg_iovlen = 2;
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SENDMSG_ZC, 0, sv[0], 0, &mh, 0, 0, 0x961);
	g_sqes[slot].buf_index = 0;
	g_sqes[slot].ioprio =
	    IORING_RECVSEND_FIXED_BUF | IORING_SEND_ZC_REPORT_USAGE | IORING_SEND_VECTORIZED;
	if (iou_flush(1, 2) != 1)
		return (4);
	n = iou_reap(c, 4);
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x961)
			continue;
		if ((c[i].flags & IORING_CQE_F_NOTIF) != 0) {
			if ((u32)c[i].res != IORING_NOTIF_USAGE_ZC_COPIED)
				return (5);
			notif = 1;
		} else {
			if (c[i].res != 6)
				return (c[i].res < 0 ? -c[i].res : 20);
			if ((c[i].flags & IORING_CQE_F_MORE) == 0)
				return (21);
			primary = 1;
		}
	}
	xmemset(rb, 0, sizeof(rb));
	if (!primary || !notif ||
	    call(SYS_read, sv[1], (long)rb, 6, 0, 0, 0) != 6 ||
	    xmemcmp(rb, "msgfix", 6) != 0)
		return (6);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_ioprio_send_zc_fixed_invalid(void)
{
	static char buf[16];
	struct iovec reg;
	struct cqe c[4];
	u32 slot;
	int sv[2], n, i, primary, notif;

	if (ring_setup(8) < 0)
		return (1);
	if (zcrx_tcp_pair(&sv[0], &sv[1]) != 0)
		return (2);
	for (i = 0; i < 2; i++) {
		if (i != 0) {
			reg.iov_base = buf; reg.iov_len = sizeof(buf);
			if (iou_reg(IORING_REGISTER_BUFFERS, &reg, 1) != 0)
				return (5);
		}
		slot = g_sqi & g_sqmask;
		iou_sqe(IORING_OP_SEND_ZC, 0, sv[0], 0,
		    i == 0 ? (void *)buf : (void *)(buf + 15),
		    i == 0 ? 1 : 2, 0, 0x962 + i);
		g_sqes[slot].ioprio = IORING_RECVSEND_FIXED_BUF;
		if (iou_flush(1, 2) != 1)
			return (6 + i);
		n = iou_reap(c, 4); primary = notif = 0;
		for (int j = 0; j < n; j++) {
			if ((c[j].flags & IORING_CQE_F_NOTIF) != 0) {
				if (c[j].res != 0) return (20 + i);
				notif = 1;
			} else {
				if (c[j].res != -EFAULT ||
				    (c[j].flags & IORING_CQE_F_MORE) == 0)
					return (30 + i);
				primary = 1;
			}
		}
		if (n != 2 || !primary || !notif)
			return (40 + i);
	}
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_ioprio_sendmsg_zc_fixed_badmsg(void)
{
	struct cqe c[4];
	u32 slot;
	int sv[2], n, primary = 0, notif = 0;

	if (ring_setup(8) < 0 || zcrx_tcp_pair(&sv[0], &sv[1]) != 0)
		return (1);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SENDMSG_ZC, 0, sv[0], 0, (void *)1, 0, 0, 0x964);
	g_sqes[slot].ioprio = IORING_RECVSEND_FIXED_BUF |
	    IORING_SEND_ZC_REPORT_USAGE;
	g_sqes[slot].pad2[0] = 0x965;
	if (iou_flush(1, 2) != 1)
		return (2);
	n = iou_reap(c, 4);
	for (int i = 0; i < n; i++) {
		if (c[i].user_data == 0x964 &&
		    (c[i].flags & IORING_CQE_F_NOTIF) == 0) {
			if (c[i].res != -EFAULT ||
			    (c[i].flags & IORING_CQE_F_MORE) == 0) return (3);
			primary = 1;
		} else if (c[i].user_data == 0x965 &&
		    (c[i].flags & IORING_CQE_F_NOTIF) != 0) {
			if ((u32)c[i].res != IORING_NOTIF_USAGE_ZC_COPIED) return (4);
			notif = 1;
		}
	}
	return (n == 2 && primary && notif ? 0 : 5);
}

static int
t_ioprio_sendmsg_zc_fixed_iovlen(void)
{
	struct l_msghdr mh;
	struct cqe c[4];
	u32 slot;
	int sv[2], n, primary = 0, notif = 0;

	if (ring_setup(8) < 0 || zcrx_tcp_pair(&sv[0], &sv[1]) != 0)
		return (1);
	xmemset(&mh, 0, sizeof(mh));
	mh.msg_iov = 1;
	mh.msg_iovlen = 1025;
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SENDMSG_ZC, 0, sv[0], 0, &mh, 0, 0, 0xfe0);
	g_sqes[slot].ioprio = IORING_RECVSEND_FIXED_BUF |
	    IORING_SEND_ZC_REPORT_USAGE;
	g_sqes[slot].pad2[0] = 0xfe1;
	if (iou_flush(1, 2) != 1)
		return (2);
	n = iou_reap(c, 4);
	for (int i = 0; i < n; i++) {
		if (c[i].user_data == 0xfe0 &&
		    (c[i].flags & IORING_CQE_F_NOTIF) == 0) {
			if (c[i].res != -ELINUX_EMSGSIZE ||
			    (c[i].flags & IORING_CQE_F_MORE) == 0) return (3);
			primary = 1;
		} else if (c[i].user_data == 0xfe1 &&
		    (c[i].flags & IORING_CQE_F_NOTIF) != 0) {
			if ((u32)c[i].res != IORING_NOTIF_USAGE_ZC_COPIED) return (4);
			notif = 1;
		}
	}
	return (n == 2 && primary && notif ? 0 : 5);
}

static int
t_ioprio_send_zc_fixed_zero_vector(void)
{
	static char buf[8];
	struct iovec reg;
	struct l_msghdr mh;
	struct cqe c[4];
	u32 slot;
	int sv[2], op, n, primary, notif;
	u64 primary_ud, notif_ud;

	if (ring_setup(8) < 0)
		return (1);
	reg.iov_base = buf; reg.iov_len = sizeof(buf);
	if (iou_reg(IORING_REGISTER_BUFFERS, &reg, 1) != 0)
		return (2);
	xmemset(&mh, 0, sizeof(mh));
	for (op = IORING_OP_SEND_ZC; op <= IORING_OP_SENDMSG_ZC; op++) {
		if (zcrx_tcp_pair(&sv[0], &sv[1]) != 0)
			return (3 + op);
		if (sys3(SYS_fcntl, sv[1], 4 /* F_SETFL */, 04000) != 0)
			return (60 + op);
		primary_ud = 0xff0 + op;
		notif_ud = 0x1000 + op;
		slot = g_sqi & g_sqmask;
		iou_sqe((u8)op, 0, sv[0], 0,
		    op == IORING_OP_SEND_ZC ? 0 : (void *)&mh, 0, 0, primary_ud);
		g_sqes[slot].buf_index = 0;
		g_sqes[slot].ioprio = IORING_RECVSEND_FIXED_BUF |
		    IORING_SEND_ZC_REPORT_USAGE |
		    (op == IORING_OP_SEND_ZC ? IORING_SEND_VECTORIZED : 0);
		g_sqes[slot].pad2[0] = notif_ud;
		if (iou_flush(1, 2) != 1)
			return (90 + op);
		n = iou_reap(c, 4); primary = notif = 0;
		for (int i = 0; i < n; i++) {
			if (c[i].user_data == primary_ud &&
			    (c[i].flags & IORING_CQE_F_NOTIF) == 0) {
				if (c[i].res != 0 ||
				    (c[i].flags & IORING_CQE_F_MORE) == 0) return (120 + op);
				primary = 1;
			} else if (c[i].user_data == notif_ud &&
			    (c[i].flags & IORING_CQE_F_NOTIF) != 0) {
				if ((u32)c[i].res != IORING_NOTIF_USAGE_ZC_COPIED)
					return (150 + op);
				notif = 1;
			}
		}
		if (n != 2 || !primary || !notif)
			return (180 + op);
		if (sys3(SYS_read, sv[1], buf, 1) != -EAGAIN)
			return (210 + op);
		(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	}
	return (0);
}

static int
t_ioprio_send_vectorized(void)
{
	struct iovec iov[2];
	struct cqe c[2];
	char rb[8];
	u32 slot;
	int sv[2], n, res;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	iov[0].iov_base = "vec"; iov[0].iov_len = 3;
	iov[1].iov_base = "tor"; iov[1].iov_len = 3;
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SEND, 0, sv[0], 0, iov, 2, 0, 0x950);
	g_sqes[slot].ioprio =
	    IORING_SEND_VECTORIZED | IORING_RECVSEND_POLL_FIRST;
	if (iou_flush(1, 1) != 1)
		return (3);
	n = iou_reap(c, 2);
	if (n != 1 || !cqe_find(c, n, 0x950, &res) || res != 6)
		return (4);
	xmemset(rb, 0, sizeof(rb));
	if (call(SYS_read, sv[1], (long)rb, 6, 0, 0, 0) != 6 ||
	    xmemcmp(rb, "vector", 6) != 0)
		return (5);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_ioprio_send_zc_vectorized(void)
{
	struct iovec iov[2];
	struct cqe c[4];
	char rb[8];
	u32 slot;
	int sv[2], n, i, primary = 0, notif = 0;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	iov[0].iov_base = "zc"; iov[0].iov_len = 2;
	iov[1].iov_base = "vec"; iov[1].iov_len = 3;
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SEND_ZC, 0, sv[0], 0, iov, 2, 0, 0x951);
	g_sqes[slot].ioprio =
	    IORING_SEND_VECTORIZED | IORING_SEND_ZC_REPORT_USAGE;
	if (iou_flush(1, 2) != 1)
		return (3);
	n = iou_reap(c, 4);
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x951)
			continue;
		if ((c[i].flags & IORING_CQE_F_NOTIF) != 0) {
			if ((u32)c[i].res != IORING_NOTIF_USAGE_ZC_COPIED)
				return (4);
			notif = 1;
		} else {
			if (c[i].res != 5)
				return (c[i].res < 0 ? -c[i].res : 20);
			if ((c[i].flags & IORING_CQE_F_MORE) == 0)
				return (21);
			primary = 1;
		}
	}
	if (!primary)
		return (51);
	if (!notif)
		return (52);
	xmemset(rb, 0, sizeof(rb));
	if (call(SYS_read, sv[1], (long)rb, 5, 0, 0, 0) != 5)
		return (53);
	if (xmemcmp(rb, "zcvec", 5) != 0)
		return (54);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_ioprio_send_vectorized_badptr(void)
{
	int sv[2], res;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	res = sub1_ioprio(sv[0], IORING_OP_SEND, (void *)0x10, 1, 0,
	    IORING_SEND_VECTORIZED, 0x952);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (res == -EFAULT ? 0 : 3);
}

static int
t_ioprio_send_zc_report(void)
{
	struct cqe c[4];
	char rb[16];
	int sv[2], n, i, primary, notif;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	iou_sqe(IORING_OP_SEND_ZC, 0, sv[0], 0, "plain", 5, 0, 0x940);
	if (iou_flush(1, 2) != 1)
		return (3);
	n = iou_reap(c, 4); primary = notif = 0;
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x940)
			continue;
		if ((c[i].flags & IORING_CQE_F_NOTIF) != 0) {
			if (c[i].res != 0)
				return (4);
			notif = 1;
		} else {
			if (c[i].res != 5)
				return (c[i].res < 0 ? -c[i].res : 20);
			if ((c[i].flags & IORING_CQE_F_MORE) == 0)
				return (21);
			primary = 1;
		}
	}
	if (!primary || !notif)
		return (50 + primary + 2 * notif);
	{
		u32 slot = g_sqi & g_sqmask;
		iou_sqe(IORING_OP_SEND_ZC, 0, sv[0], 0, "usage", 5, 0,
		    0x941);
		g_sqes[slot].ioprio = IORING_RECVSEND_POLL_FIRST |
		    IORING_SEND_ZC_REPORT_USAGE;
	}
	if (iou_flush(1, 2) != 1)
		return (6);
	n = iou_reap(c, 4); primary = notif = 0;
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x941)
			continue;
		if ((c[i].flags & IORING_CQE_F_NOTIF) != 0) {
			if ((u32)c[i].res != IORING_NOTIF_USAGE_ZC_COPIED)
				return (7);
			notif = 1;
		} else {
			if (c[i].res != 5)
				return (c[i].res < 0 ? -c[i].res : 20);
			if ((c[i].flags & IORING_CQE_F_MORE) == 0)
				return (21);
			primary = 1;
		}
	}
	if (!primary || !notif)
		return (8);
	xmemset(rb, 0, sizeof(rb));
	if (call(SYS_read, sv[1], (long)rb, 10, 0, 0, 0) != 10 ||
	    xmemcmp(rb, "plainusage", 10) != 0)
		return (9);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_ioprio_sendmsg_zc_report(void)
{
	struct iovec iov;
	struct l_msghdr mh;
	struct cqe c[4];
	int sv[2], n, i, primary = 0, notif = 0;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	iov.iov_base = "msgzc"; iov.iov_len = 5;
	xmemset(&mh, 0, sizeof(mh));
	mh.msg_iov = (u64)(unsigned long)&iov;
	mh.msg_iovlen = 1;
	{
		u32 slot = g_sqi & g_sqmask;
		iou_sqe(IORING_OP_SENDMSG_ZC, 0, sv[0], 0, &mh, 0, 0,
		    0x942);
		g_sqes[slot].ioprio = IORING_SEND_ZC_REPORT_USAGE;
	}
	if (iou_flush(1, 2) != 1)
		return (3);
	n = iou_reap(c, 4);
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x942)
			continue;
		if ((c[i].flags & IORING_CQE_F_NOTIF) != 0) {
			if ((u32)c[i].res != IORING_NOTIF_USAGE_ZC_COPIED)
				return (4);
			notif = 1;
		} else {
			if (c[i].res != 5)
				return (c[i].res < 0 ? -c[i].res : 20);
			if ((c[i].flags & IORING_CQE_F_MORE) == 0)
				return (21);
			primary = 1;
		}
	}
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (primary && notif ? 0 : 50 + primary + 2 * notif);
}

static int
t_ioprio_send_zc_invalid(void)
{
	struct l_msghdr mh;
	struct cqe c[4];
	u32 slot;
	int sv[2], n, i, found;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SEND_ZC, 0, sv[0], 0, "x", 1, 0, 0x943);
	g_sqes[slot].ioprio = 0x40;
	if (iou_flush(1, 1) != 1)
		return (3);
	n = iou_reap(c, 4); found = 0;
	for (i = 0; i < n; i++)
		if (c[i].user_data == 0x943 &&
		    (c[i].flags & IORING_CQE_F_NOTIF) == 0 &&
		    c[i].res == -EINVAL)
			found = 1;
	if (!found)
		return (4);
	xmemset(&mh, 0, sizeof(mh));
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SENDMSG_ZC, 0, sv[0], 0, &mh, 0, 0, 0x944);
	g_sqes[slot].ioprio = 0x40;
	if (iou_flush(1, 1) != 1)
		return (5);
	n = iou_reap(c, 4); found = 0;
	for (i = 0; i < n; i++)
		if (c[i].user_data == 0x944 &&
		    (c[i].flags & IORING_CQE_F_NOTIF) == 0 &&
		    c[i].res == -EINVAL)
			found = 1;
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (found ? 0 : 6);
}

/* ================= network ACCEPT ioprio options ================= */
static int
unix_listener(struct sockaddr_un *sun)
{
	static const char path[] = "iou_accept.sock";
	long fd;

	(void)sys3(SYS_unlinkat, AT_FDCWD, path, 0);
	fd = call(SYS_socket, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, 0, 0, 0);
	if (fd < 0)
		return ((int)fd);
	xmemset(sun, 0, sizeof(*sun));
	sun->sun_family = LX_AF_UNIX;
	xmemcpy(sun->sun_path, path, sizeof(path));
	if (call(SYS_bind, fd, (long)sun, sizeof(*sun), 0, 0, 0) != 0 ||
	    call(SYS_listen, fd, 8, 0, 0, 0, 0) != 0) {
		(void)sys1(SYS_close, fd);
		return (-1);
	}
	return ((int)fd);
}

static int
unix_connect(const struct sockaddr_un *sun)
{
	long error, fd;

	fd = call(SYS_socket, LX_AF_UNIX, LX_SOCK_STREAM, 0, 0, 0, 0);
	if (fd < 0)
		return ((int)fd);
	error = call(SYS_connect, fd, (long)sun, sizeof(*sun), 0, 0, 0);
	if (error != 0) {
		(void)sys1(SYS_close, fd);
		return ((int)error);
	}
	return ((int)fd);
}

static int
socket_option_submit(u8 flags, int domain, u64 type, u32 protocol,
    u32 file_index, int field, u64 ud)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SOCKET, flags, domain, type, 0, protocol, 0, ud);
	g_sqes[slot].splice_fd_in = (int)file_index;
	switch (field) {
	case 1: g_sqes[slot].addr = 1; break;
	case 2: g_sqes[slot].rw_flags = 1; break;
	case 3: g_sqes[slot].buf_index = 1; break;
	case 4: g_sqes[slot].pad2[0] = 1; break;
	case 5: g_sqes[slot].pad2[1] = 0xfeed; break;
	case 6: g_sqes[slot].ioprio = 1; break;
	default: break;
	}
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != ud)
		return (-100000);
	return (c.res);
}

static int
accept_option_submit(u8 flags, int fd, void *addr, void *addrlen,
    u32 accept_flags, u32 ioprio, u32 file_index, int field, u64 ud)
{
	struct cqe c;
	u32 slot;

	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_ACCEPT, flags, fd, (u64)(unsigned long)addrlen,
	    addr, 0, accept_flags, ud);
	g_sqes[slot].ioprio = (u16)ioprio;
	g_sqes[slot].splice_fd_in = (int)file_index;
	if (field == 1)
		g_sqes[slot].len = 1;
	else if (field == 2)
		g_sqes[slot].buf_index = 1;
	else if (field == 3)
		g_sqes[slot].pad2[0] = 1;
	else if (field == 4)
		g_sqes[slot].pad2[1] = 0xbeef;
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != ud)
		return (-100000);
	return (c.res);
}

static int
t_socket_accept_options(void)
{
	struct sockaddr_un sun;
	int files[2], clients[6], fd, installed, listener, res;

	if (ring_setup(32) < 0)
		return (1);
	/* SOCKET reserves addr, rw_flags, and buf_index. */
	for (int field = 1; field <= 3; field++)
		if (socket_option_submit(0, LX_AF_UNIX, LX_SOCK_STREAM, 0,
		    0, field, 0xd100 + field) != -EINVAL)
			return (2);
	if (socket_option_submit(0, LX_AF_UNIX, LX_SOCK_STREAM, 0, 0, 6,
	    0xd106) != -EINVAL ||
	    socket_option_submit(IOSQE_BUFFER_SELECT, LX_AF_UNIX,
	    LX_SOCK_STREAM, 0, 0, 0, 0xd107) != -EOPNOTSUPP)
		return (3);
	/* addr3 and the final SQE word are unused. */
	fd = socket_option_submit(0, LX_AF_UNIX, LX_SOCK_STREAM, 0, 0, 4,
	    0xd108);
	if (fd < 0)
		return (4);
	(void)sys1(SYS_close, fd);
	fd = socket_option_submit(0, LX_AF_UNIX, LX_SOCK_STREAM, 0, 0, 5,
	    0xd109);
	if (fd < 0)
		return (5);
	(void)sys1(SYS_close, fd);
	/* FIXED_FILE is ignored by descriptorless SOCKET. */
	fd = socket_option_submit(IOSQE_FIXED_FILE, LX_AF_UNIX,
	    LX_SOCK_DGRAM, 0, 0, 0, 0xd10a);
	if (fd < 0)
		return (6);
	(void)sys1(SYS_close, fd);
	/* Both creation flags are reflected on the returned descriptor. */
	fd = socket_option_submit(IOSQE_ASYNC, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK | LX_SOCK_CLOEXEC, 0, 0, 0,
	    0xd10b);
	if (fd < 0 || (sys3(SYS_fcntl, fd, 3, 0) & LX_O_NONBLOCK) == 0 ||
	    (sys3(SYS_fcntl, fd, 1, 0) & 1) == 0)
		return (7);
	(void)sys1(SYS_close, fd);
	if (socket_option_submit(0, LX_AF_UNIX, LX_SOCK_STREAM | 0x40000000,
	    0, 0, 0, 0xd10c) != -EINVAL ||
	    socket_option_submit(0, -1, LX_SOCK_STREAM, 0, 0, 0,
	    0xd10d) != -EAFNOSUPPORT)
		return (8);

	/* Direct SOCKET output uses file_index and rejects CLOEXEC first. */
	files[0] = -1;
	files[1] = -1;
	if (iou_reg(IORING_REGISTER_FILES, files, 2) != 0)
		return (9);
	if (socket_option_submit(0, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_CLOEXEC, 0, 1, 0, 0xd110) != -EINVAL ||
	    socket_option_submit(0, LX_AF_UNIX, LX_SOCK_STREAM, 0, 1, 1,
	    0xd111) != -EINVAL)
		return (10);
	if (socket_option_submit(0, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, 1, 0, 0xd112) != 0)
		return (11);
	installed = sub1flags(0, IORING_OP_FIXED_FD_INSTALL,
	    IOSQE_FIXED_FILE, 0, 0, 0, 0xd113);
	if (installed < 0 ||
	    (sys3(SYS_fcntl, installed, 3, 0) & LX_O_NONBLOCK) == 0)
		return (12);
	(void)sys1(SYS_close, installed);
	if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0)
		return (13);

	listener = unix_listener(&sun);
	if (listener < 0)
		return (14);
	/* ACCEPT reserves len and buf_index; failures do not consume a peer. */
	clients[0] = unix_connect(&sun);
	if (clients[0] < 0 ||
	    accept_option_submit(0, listener, 0, 0, 0, 0, 0, 1,
	    0xd120) != -EINVAL ||
	    accept_option_submit(0, listener, 0, 0, 0, 0, 0, 2,
	    0xd121) != -EINVAL ||
	    accept_option_submit(IOSQE_BUFFER_SELECT, listener, 0, 0, 0, 0,
	    0, 0, 0xd122) != -EOPNOTSUPP ||
	    accept_option_submit(0, listener, 0, 0, 0x40000000, 0, 0, 0,
	    0xd123) != -EINVAL)
		return (15);
	fd = accept_option_submit(0, listener, 0, 0,
	    LX_SOCK_NONBLOCK | LX_SOCK_CLOEXEC, IORING_ACCEPT_DONTWAIT,
	    0, 3, 0xd124);
	if (fd < 0 || (sys3(SYS_fcntl, fd, 3, 0) & LX_O_NONBLOCK) == 0 ||
	    (sys3(SYS_fcntl, fd, 1, 0) & 1) == 0)
		return (16);
	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_close, clients[0]);

	/* The final word is also ignored, and a fresh peer proves recovery. */
	clients[1] = unix_connect(&sun);
	if (clients[1] < 0)
		return (17);
	fd = accept_option_submit(0, listener, 0, 0, 0,
	    IORING_ACCEPT_DONTWAIT, 0, 4, 0xd125);
	if (fd < 0)
		return (18);
	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_close, clients[1]);

	/* A registered listener remains usable after its ambient fd closes. */
	files[0] = listener;
	files[1] = -1;
	if (iou_reg(IORING_REGISTER_FILES, files, 2) != 0)
		return (19);
	(void)sys1(SYS_close, listener);
	clients[2] = unix_connect(&sun);
	if (clients[2] < 0)
		return (20);
	fd = accept_option_submit(IOSQE_FIXED_FILE | IOSQE_ASYNC, 0, 0, 0,
	    0, IORING_ACCEPT_DONTWAIT, 0, 0, 0xd126);
	if (fd < 0)
		return (21);
	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_close, clients[2]);
	if (accept_option_submit(IOSQE_FIXED_FILE, 1, 0, 0, 0,
	    IORING_ACCEPT_DONTWAIT, 0, 0, 0xd127) != -EBADF ||
	    accept_option_submit(IOSQE_FIXED_FILE, 2, 0, 0, 0,
	    IORING_ACCEPT_DONTWAIT, 0, 0, 0xd128) != -EBADF)
		return (22);
	if (iou_reg(IORING_UNREGISTER_FILES, 0, 0) != 0 ||
	    accept_option_submit(IOSQE_FIXED_FILE, 0, 0, 0, 0,
	    IORING_ACCEPT_DONTWAIT, 0, 0, 0xd129) != -EBADF)
		return (23);

	fd = (int)tmpfile_fd("iou_accept_notsock");
	if (fd < 0 || accept_option_submit(0, fd, 0, 0, 0,
	    IORING_ACCEPT_DONTWAIT, 0, 0, 0xd12a) != -ENOTSOCK)
		return (24);
	res = socket_option_submit(0, LX_AF_UNIX, LX_SOCK_DGRAM, 0, 0, 0,
	    0xd12b);
	(void)sys1(SYS_close, fd);
	if (res < 0)
		return (25);
	(void)sys1(SYS_close, res);
	return (0);
}

static int
t_socket_direct_cloexec(void)
{
	struct cqe c[2];
	int files[1] = { -1 };
	int newfd;
	u32 slot;

	if (ring_setup(8) < 0 ||
	    iou_reg(IORING_REGISTER_FILES, files, 1) != 0)
		return (1);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SOCKET, 0, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_CLOEXEC, 0, 0, 0, 0xb0e);
	set_file_index(slot, 1);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].user_data != 0xb0e || c[0].res != -EINVAL || c[0].flags != 0)
		return (2);
	/* Rejection leaves the slot empty for an otherwise identical socket. */
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SOCKET, 0, LX_AF_UNIX, LX_SOCK_STREAM,
	    0, 0, 0, 0xb0f);
	set_file_index(slot, 1);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].user_data != 0xb0f || c[0].res != 0)
		return (3);
	newfd = sub1flags(0, IORING_OP_FIXED_FD_INSTALL, IOSQE_FIXED_FILE,
	    0, 0, 0, 0xb10);
	if (newfd < 0)
		return (4);
	(void)sys1(SYS_close, newfd);
	return (0);
}

static int
t_accept_direct(void)
{
	struct file_index_range range = { 0, 2, 0 };
	struct sockaddr_un sun;
	struct cqe c[2];
	char buf[4];
	int fds[2] = { -1, -1 };
	int sfd, client[5], afd, n, res;
	u32 slot;

	if (ring_setup(8) < 0 ||
	    iou_reg(IORING_REGISTER_FILES, fds, 2) != 0 ||
	    iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, &range, 0) != 0)
		return (1);
	sfd = unix_listener(&sun);
	if (sfd < 0)
		return (2);
	client[0] = unix_connect(&sun);
	if (client[0] < 0)
		return (3);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_ACCEPT, 0, sfd, 0, 0, 0, 0, 0xb10);
	set_file_index(slot, IORING_FILE_INDEX_ALLOC);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 || c[0].res != 0)
		return (4);
	afd = sub1flags(0, IORING_OP_FIXED_FD_INSTALL, IOSQE_FIXED_FILE,
	    0, 0, 0, 0xb11);
	if (afd < 0)
		return (5);
	if (sys3(SYS_write, client[0], "ping", 4) != 4 ||
	    sys3(SYS_read, afd, buf, 4) != 4 || xmemcmp(buf, "ping", 4) != 0)
		return (6);
	(void)sys1(SYS_close, afd);

	/* Explicit direct installation uses a one-based index and returns zero. */
	client[1] = unix_connect(&sun);
	if (client[1] < 0)
		return (7);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_ACCEPT, 0, sfd, 0, 0, 0, 0, 0xb12);
	set_file_index(slot, 2);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 || c[0].res != 0)
		return (8);
	afd = sub1flags(1, IORING_OP_FIXED_FD_INSTALL, IOSQE_FIXED_FILE,
	    0, 0, 0, 0xb13);
	if (afd < 0)
		return (9);
	if (sys3(SYS_write, afd, "pong", 4) != 4 ||
	    sys3(SYS_read, client[1], buf, 4) != 4 ||
	    xmemcmp(buf, "pong", 4) != 0)
		return (10);
	(void)sys1(SYS_close, afd);

	/* Multishot direct accept requires automatic allocation, not an
	 * explicit fixed slot, and rejection must not consume a connection. */
	client[2] = unix_connect(&sun);
	if (client[2] < 0)
		return (11);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_ACCEPT, 0, sfd, 0, 0, 0, 0, 0xb14);
	g_sqes[slot].ioprio = IORING_ACCEPT_MULTISHOT;
	set_file_index(slot, 1);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].res != -EINVAL)
		return (12);
	res = sub1_ioprio(sfd, IORING_OP_ACCEPT, 0, 0, 0,
	    IORING_ACCEPT_DONTWAIT, 0xb15);
	if (res < 0)
		return (13);
	(void)sys1(SYS_close, res);

	/* With both direct slots occupied, allocation closes the accepted fd. */
	client[3] = unix_connect(&sun);
	if (client[3] < 0)
		return (14);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_ACCEPT, 0, sfd, 0, 0, 0, 0, 0xb16);
	set_file_index(slot, IORING_FILE_INDEX_ALLOC);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].res != -ENFILE)
		return (15);

	/* The listener remains usable after direct-install failure. */
	client[4] = unix_connect(&sun);
	if (client[4] < 0)
		return (16);
	res = sub1_ioprio(sfd, IORING_OP_ACCEPT, 0, 0, 0,
	    IORING_ACCEPT_DONTWAIT, 0xb17);
	if (res < 0)
		return (17);
	(void)sys1(SYS_close, res);
	for (n = 0; n < 5; n++)
		(void)sys1(SYS_close, client[n]);
	(void)sys1(SYS_close, sfd);
	return (0);
}

static int
t_accept_direct_multishot(void)
{
	struct file_index_range range = { 0, 4, 0 };
	struct sockaddr_un sun;
	struct cqe c[8];
	char got[2];
	int fds[4] = { -1, -1, -1, -1 };
	int sfd, clients[4], installed[2], slots[2];
	int i, j, n, res, cancel, terminal;
	u32 slot;

	if (ring_setup(8) < 0 ||
	    iou_reg(IORING_REGISTER_FILES, fds, 4) != 0 ||
	    iou_reg(IORING_REGISTER_FILE_ALLOC_RANGE, &range, 0) != 0)
		return (1);
	sfd = unix_listener(&sun);
	if (sfd < 0)
		return (2);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_ACCEPT, 0, sfd, 0, 0, 0, 0, 0xb18);
	g_sqes[slot].ioprio = IORING_ACCEPT_MULTISHOT |
	    IORING_ACCEPT_POLL_FIRST;
	set_file_index(slot, IORING_FILE_INDEX_ALLOC);
	if (iou_flush(1, 0) != 1)
		return (3);
	clients[0] = unix_connect(&sun);
	clients[1] = unix_connect(&sun);
	if (clients[0] < 0 || clients[1] < 0)
		return (4);
	if (call(SYS_io_uring_enter, fd_ring, 0, 2, IORING_ENTER_GETEVENTS,
	    0, 0) < 0)
		return (5);
	n = iou_reap(c, 8);
	if (n != 2)
		return (6);
	for (i = 0; i < 2; i++) {
		if (c[i].user_data != 0xb18 || c[i].res < 0 ||
		    (c[i].flags & IORING_CQE_F_MORE) == 0)
			return (7);
		slots[i] = c[i].res;
	}
	if (slots[0] == slots[1] || slots[0] < 0 || slots[0] > 3 ||
	    slots[1] < 0 || slots[1] > 3)
		return (8);
	if (sys3(SYS_write, clients[0], "a", 1) != 1 ||
	    sys3(SYS_write, clients[1], "b", 1) != 1)
		return (9);
	for (i = 0; i < 2; i++) {
		installed[i] = sub1flags(slots[i], IORING_OP_FIXED_FD_INSTALL,
		    IOSQE_FIXED_FILE, 0, 0, 0, 0xb20 + i);
		if (installed[i] < 0 || sys3(SYS_read, installed[i], &got[i], 1) != 1)
			return (10 + i);
	}
	if (!((got[0] == 'a' && got[1] == 'b') ||
	    (got[0] == 'b' && got[1] == 'a')))
		return (12);
	for (i = 0; i < 2; i++)
		(void)sys1(SYS_close, installed[i]);

	/* Cancel the armed multishot request and require its terminal CQE. */
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0xb18, 0, 0, 0xb19);
	if (iou_flush(1, 2) != 1)
		return (13);
	n = iou_reap(c, 8);
	cancel = terminal = 0;
	for (i = 0; i < n; i++) {
		if (c[i].user_data == 0xb19 && c[i].res == 0)
			cancel = 1;
		if (c[i].user_data == 0xb18 && c[i].res == -ELINUX_ECANCELED &&
		    (c[i].flags & IORING_CQE_F_MORE) == 0)
			terminal = 1;
	}
	if (!cancel || !terminal)
		return (14);

	/* An explicit fixed slot remains a preparation error and leaves the
	 * queued connection for a following ordinary accept. */
	clients[2] = unix_connect(&sun);
	if (clients[2] < 0)
		return (15);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_ACCEPT, 0, sfd, 0, 0, 0, 0, 0xb1a);
	g_sqes[slot].ioprio = IORING_ACCEPT_MULTISHOT;
	set_file_index(slot, 4);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].user_data != 0xb1a || c[0].res != -EINVAL || c[0].flags != 0)
		return (16);
	res = sub1_ioprio(sfd, IORING_OP_ACCEPT, 0, 0, 0,
	    IORING_ACCEPT_DONTWAIT, 0xb1b);
	if (res < 0)
		return (17);
	(void)sys1(SYS_close, res);

	/* Direct accept cannot retain close-on-exec metadata in a fixed slot. */
	clients[3] = unix_connect(&sun);
	if (clients[3] < 0)
		return (18);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_ACCEPT, 0, sfd, 0, 0, 0,
	    LX_SOCK_CLOEXEC, 0xb1c);
	set_file_index(slot, IORING_FILE_INDEX_ALLOC);
	if (iou_flush(1, 1) != 1 || iou_reap(c, 1) != 1 ||
	    c[0].user_data != 0xb1c || c[0].res != -EINVAL || c[0].flags != 0)
		return (19);
	res = sub1_ioprio(sfd, IORING_OP_ACCEPT, 0, 0, 0,
	    IORING_ACCEPT_DONTWAIT, 0xb1d);
	if (res < 0)
		return (20);
	(void)sys1(SYS_close, res);
	for (j = 0; j < 4; j++)
		(void)sys1(SYS_close, clients[j]);
	(void)sys1(SYS_close, sfd);
	return (0);
}

static int
t_ioprio_accept_multishot(void)
{
	struct sockaddr_un sun;
	struct cqe c[8];
	u32 slot;
	int sfd, clients[2], accepted[2], n, i, res, na = 0;

	if (ring_setup(8) < 0)
		return (1);
	sfd = unix_listener(&sun);
	if (sfd < 0)
		return (2);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_ACCEPT, 0, sfd, 0, 0, 0, 0, 0x930);
	g_sqes[slot].ioprio =
	    IORING_ACCEPT_MULTISHOT | IORING_ACCEPT_POLL_FIRST;
	if (iou_flush(1, 0) != 1 || iou_reap(c, 8) != 0)
		return (3);
	clients[0] = unix_connect(&sun);
	clients[1] = unix_connect(&sun);
	if (clients[0] < 0)
		return (-clients[0]);
	if (clients[1] < 0)
		return (-clients[1]);
	if (call(SYS_io_uring_enter, fd_ring, 0, 2, IORING_ENTER_GETEVENTS,
	    0, 0) < 0)
		return (5);
	n = iou_reap(c, 8);
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x930 ||
		    (c[i].flags & IORING_CQE_F_MORE) == 0 || c[i].res < 0)
			return (6);
		if (na < 2)
			accepted[na++] = c[i].res;
	}
	if (n != 2 || na != 2)
		return (7);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0x930, 0, 0,
	    0x931);
	if (iou_flush(1, 2) != 1)
		return (8);
	n = iou_reap(c, 8);
	for (i = 0; i < 2; i++) {
		(void)sys1(SYS_close, clients[i]);
		(void)sys1(SYS_close, accepted[i]);
	}
	(void)sys1(SYS_close, sfd);
	if (!cqe_find(c, n, 0x931, &res) || res != 0)
		return (9);
	if (!cqe_find(c, n, 0x930, &res) || res != -ELINUX_ECANCELED)
		return (10);
	return (0);
}

static int
t_ioprio_accept_dontwait(void)
{
	struct sockaddr_un sun;
	int sfd, res;

	if (ring_setup(8) < 0)
		return (1);
	sfd = unix_listener(&sun);
	if (sfd < 0)
		return (2);
	res = sub1_ioprio(sfd, IORING_OP_ACCEPT, 0, 0, 0,
	    IORING_ACCEPT_DONTWAIT, 0x932);
	(void)sys1(SYS_close, sfd);
	return (res == -EAGAIN ? 0 : 3);
}

static int
t_ioprio_accept_invalid(void)
{
	struct sockaddr_un sun;
	struct cqe c[2];
	u32 slot;
	int sfd, n, res;

	if (ring_setup(8) < 0)
		return (1);
	sfd = unix_listener(&sun);
	if (sfd < 0)
		return (2);
	if (sub1_ioprio(sfd, IORING_OP_ACCEPT, 0, 0, 0, 0x8, 0x933) !=
	    -EINVAL)
		return (3);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_ACCEPT, 0, sfd, 0, 0, 0, 0, 0x934);
	g_sqes[slot].ioprio = IORING_ACCEPT_MULTISHOT;
	g_sqes[slot].buf_index = 1;
	if (iou_flush(1, 1) != 1)
		return (4);
	n = iou_reap(c, 2);
	(void)sys1(SYS_close, sfd);
	if (n != 1 || !cqe_find(c, n, 0x934, &res))
		return (5);
	return (res == -EINVAL ? 0 : 6);
}

/* ================= registered provided-buffer rings ================= */
static long
pbuf_register(struct pbuf_reg *reg)
{
	return (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_RING,
	    (long)reg, 1, 0, 0));
}

static long
pbuf_unregister(u16 bgid)
{
	struct pbuf_reg reg;

	xmemset(&reg, 0, sizeof(reg));
	reg.bgid = bgid;
	return (call(SYS_io_uring_register, fd_ring,
	    IORING_UNREGISTER_PBUF_RING, (long)&reg, 1, 0, 0));
}

static int
t_pbuf_ring_mmap(void)
{
	struct pbuf_reg reg;
	struct pbuf_status st;
	union uring_buf_ring *br;
	struct cqe c[2];
	char data[16];
	long m;
	int p[2];

	if (ring_setup(8) < 0)
		return (1);
	xmemset(&reg, 0, sizeof(reg));
	reg.ring_entries = 8; reg.bgid = 41; reg.flags = IOU_PBUF_RING_MMAP;
	if (pbuf_register(&reg) != 0)
		return (2);
	m = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd_ring, IORING_OFF_PBUF_RING | ((u64)reg.bgid << IORING_OFF_PBUF_SHIFT));
	if (m < 0)
		return (3);
	br = (union uring_buf_ring *)m;
	br->bufs[0].addr = (u64)(unsigned long)data;
	br->bufs[0].len = sizeof(data);
	br->bufs[0].bid = 501;
	__atomic_store_n(&br->h.tail, 1, __ATOMIC_RELEASE);
	if (call(SYS_pipe2, (long)p, 0, 0, 0, 0, 0) != 0 ||
	    call(SYS_write, p[1], (long)"pbuf", 4, 0, 0, 0) != 4)
		return (4);
	if (grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, p[0], (u64)-1, 0, 16,
	    41, 0xa01, c) != 0 || c[0].res != 4 ||
	    (c[0].flags & IORING_CQE_F_BUFFER) == 0 ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 501 ||
	    xmemcmp(data, "pbuf", 4) != 0) {
		put("PBUF_MMAP_DIAG "); putnum(c[0].res); put(" ");
		putnum(c[0].flags); put(" "); putnum(data[0]); put("\n");
		return (5);
	}
	xmemset(&st, 0, sizeof(st)); st.buf_group = 41;
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
	    (long)&st, 1, 0, 0) != 0 || st.head != 1)
		return (6);
	if (pbuf_unregister(41) != 0 || pbuf_unregister(41) != -2)
		return (7);
	(void)sys1(SYS_close, p[0]); (void)sys1(SYS_close, p[1]);
	return (0);
}

static int
t_pbuf_ring_user_wrap(void)
{
	struct pbuf_reg reg;
	union uring_buf_ring *br;
	struct cqe c[2];
	static char data[8][8];
	long m;
	int p[2], i;

	if (ring_setup(8) < 0)
		return (1);
	m = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
	    LX_MAP_PRIVATE | LX_MAP_ANON, -1, 0);
	if (m < 0)
		return (2);
	br = (union uring_buf_ring *)m;
	xmemset(&reg, 0, sizeof(reg)); reg.ring_addr = m;
	reg.ring_entries = 4; reg.bgid = 42;
	if (pbuf_register(&reg) != 0)
		return (3);
	if (call(SYS_pipe2, (long)p, 0, 0, 0, 0, 0) != 0)
		return (4);
	for (i = 0; i < 8; i++) {
		br->bufs[i & 3].addr = (u64)(unsigned long)data[i];
		br->bufs[i & 3].len = sizeof(data[i]);
		br->bufs[i & 3].bid = 600 + i;
		__atomic_store_n(&br->h.tail, (u16)(i + 1), __ATOMIC_RELEASE);
		if (call(SYS_write, p[1], (long)"W", 1, 0, 0, 0) != 1 ||
		    grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, p[0], (u64)-1, 0, 8,
		    42, 0xa10 + i, c) != 0 || c[0].res != 1 ||
		    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != (u32)(600 + i) ||
		    data[i][0] != 'W') {
			put("PBUF_USER_DIAG "); putnum(i); put(" ");
			putnum(c[0].res); put(" "); putnum(c[0].flags); put("\n");
			return (5);
		}
	}
	if (pbuf_unregister(42) != 0)
		return (6);
	(void)sys1(SYS_close, p[0]); (void)sys1(SYS_close, p[1]);
	return (0);
}

static int
t_pbuf_ring_retry_cancel(void)
{
	struct pbuf_reg reg;
	struct pbuf_status st;
	union uring_buf_ring *br;
	struct cqe c[4];
	static char data[2][8];
	long m;
	int p[2], n, res;

	if (ring_setup(8) < 0)
		return (1);
	xmemset(&reg, 0, sizeof(reg));
	reg.ring_entries = 4; reg.bgid = 46; reg.flags = IOU_PBUF_RING_MMAP;
	if (pbuf_register(&reg) != 0)
		return (2);
	m = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd_ring, IORING_OFF_PBUF_RING | ((u64)reg.bgid << IORING_OFF_PBUF_SHIFT));
	if (m < 0 || call(SYS_pipe2, (long)p, 04000, 0, 0, 0, 0) != 0)
		return (3);
	br = (union uring_buf_ring *)m;
	br->bufs[0].addr = (u64)(unsigned long)data[0];
	br->bufs[0].len = sizeof(data[0]); br->bufs[0].bid = 710;
	__atomic_store_n(&br->h.tail, 1, __ATOMIC_RELEASE);
	iou_sqe(IORING_OP_READ, IOSQE_BUFFER_SELECT, p[0], (u64)-1, 0, 8, 0,
	    0xa30);
	g_sqes[(g_sqi - 1) & g_sqmask].buf_index = 46;
	if (iou_flush(1, 0) != 1 || iou_reap(c, 4) != 0 ||
	    pbuf_unregister(46) != -16)
		return (4);
	if (call(SYS_write, p[1], (long)"R", 1, 0, 0, 0) != 1 ||
	    call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS,
	    0, 0) < 0)
		return (5);
	n = iou_reap(c, 4);
	if (n != 1 || !cqe_find(c, n, 0xa30, &res) || res != 1 ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 710 || data[0][0] != 'R')
		return (6);
	xmemset(&st, 0, sizeof(st)); st.buf_group = 46;
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
	    (long)&st, 1, 0, 0) != 0 || st.head != 1)
		return (7);
	br->bufs[1].addr = (u64)(unsigned long)data[1];
	br->bufs[1].len = sizeof(data[1]); br->bufs[1].bid = 711;
	__atomic_store_n(&br->h.tail, 2, __ATOMIC_RELEASE);
	iou_sqe(IORING_OP_READ, IOSQE_BUFFER_SELECT, p[0], (u64)-1, 0, 8, 0,
	    0xa31);
	g_sqes[(g_sqi - 1) & g_sqmask].buf_index = 46;
	if (iou_flush(1, 0) != 1 || iou_reap(c, 4) != 0)
		return (8);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0xa31, 0, 0,
	    0xa32);
	if (iou_flush(1, 2) != 1)
		return (9);
	n = iou_reap(c, 4);
	if (n != 2 || !cqe_find(c, n, 0xa31, &res) || res != -ELINUX_ECANCELED ||
	    !cqe_find(c, n, 0xa32, &res) || res != 0)
		return (10);
	xmemset(&st, 0, sizeof(st)); st.buf_group = 46;
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
	    (long)&st, 1, 0, 0) != 0 || st.head != 1 || pbuf_unregister(46) != 0)
		return (11);
	(void)sys1(SYS_close, p[0]); (void)sys1(SYS_close, p[1]);
	return (0);
}

static int
t_pbuf_ring_incremental(void)
{
	struct pbuf_reg reg;
	struct pbuf_status st;
	union uring_buf_ring *br;
	struct cqe c[2];
	static char data[16];
	long m;
	int p[2];

	if (ring_setup(8) < 0)
		return (1);
	xmemset(&reg, 0, sizeof(reg));
	reg.ring_entries = 4;
	reg.bgid = 48;
	reg.flags = IOU_PBUF_RING_MMAP | IOU_PBUF_RING_INC;
	reg.min_left = 3;
	if (pbuf_register(&reg) != 0)
		return (2);
	m = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd_ring, IORING_OFF_PBUF_RING | ((u64)reg.bgid << IORING_OFF_PBUF_SHIFT));
	if (m < 0)
		return (3);
	br = (union uring_buf_ring *)m;
	br->bufs[0].addr = (u64)(unsigned long)data;
	br->bufs[0].len = 10;
	br->bufs[0].bid = 730;
	__atomic_store_n(&br->h.tail, 1, __ATOMIC_RELEASE);
	if (call(SYS_pipe2, (long)p, 0, 0, 0, 0, 0) != 0)
		return (4);

	if (call(SYS_write, p[1], (long)"abc", 3, 0, 0, 0) != 3 ||
	    grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, p[0], (u64)-1, 0, 3,
	    48, 0xa40, c) != 0 || c[0].res != 3 ||
	    (c[0].flags & (IORING_CQE_F_BUFFER | IORING_CQE_F_BUF_MORE)) !=
	    (IORING_CQE_F_BUFFER | IORING_CQE_F_BUF_MORE) ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 730 ||
	    br->bufs[0].addr != (u64)(unsigned long)(data + 3) ||
	    br->bufs[0].len != 7)
		return (5);
	xmemset(&st, 0, sizeof(st));
	st.buf_group = 48;
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
	    (long)&st, 1, 0, 0) != 0 || st.head != 0)
		return (6);

	if (call(SYS_write, p[1], (long)"defg", 4, 0, 0, 0) != 4 ||
	    grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, p[0], (u64)-1, 0, 4,
	    48, 0xa41, c) != 0 || c[0].res != 4 ||
	    (c[0].flags & IORING_CQE_F_BUF_MORE) == 0 ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 730 ||
	    br->bufs[0].addr != (u64)(unsigned long)(data + 7) ||
	    br->bufs[0].len != 3)
		return (7);
	if (call(SYS_write, p[1], (long)"h", 1, 0, 0, 0) != 1 ||
	    grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, p[0], (u64)-1, 0, 1,
	    48, 0xa42, c) != 0 || c[0].res != 1 ||
	    (c[0].flags & IORING_CQE_F_BUFFER) == 0 ||
	    (c[0].flags & IORING_CQE_F_BUF_MORE) != 0 ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 730 ||
	    br->bufs[0].len != 0 || xmemcmp(data, "abcdefgh", 8) != 0)
		return (8);
	xmemset(&st, 0, sizeof(st));
	st.buf_group = 48;
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
	    (long)&st, 1, 0, 0) != 0 || st.head != 1)
		return (9);

	br->bufs[1].addr = (u64)(unsigned long)(data + 10);
	br->bufs[1].len = 2;
	br->bufs[1].bid = 731;
	__atomic_store_n(&br->h.tail, 2, __ATOMIC_RELEASE);
	(void)sys1(SYS_close, p[1]);
	if (grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, p[0], (u64)-1, 0, 2,
	    48, 0xa43, c) != 0 || c[0].res != 0 ||
	    (c[0].flags & (IORING_CQE_F_BUFFER | IORING_CQE_F_BUF_MORE)) !=
	    (IORING_CQE_F_BUFFER | IORING_CQE_F_BUF_MORE) ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 731 ||
	    br->bufs[1].addr != (u64)(unsigned long)(data + 10) ||
	    br->bufs[1].len != 2)
		return (10);
	xmemset(&st, 0, sizeof(st));
	st.buf_group = 48;
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
	    (long)&st, 1, 0, 0) != 0 || st.head != 1 ||
	    pbuf_unregister(48) != 0)
		return (11);
	(void)sys1(SYS_close, p[0]);
	return (0);
}

static int
t_pbuf_ring_incremental_user(void)
{
	struct pbuf_reg reg;
	struct pbuf_status st;
	union uring_buf_ring *br;
	struct cqe c[2];
	static char data[2][8];
	long m;
	int p[2];

	if (ring_setup(8) < 0)
		return (1);
	m = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
	    LX_MAP_PRIVATE | LX_MAP_ANON, -1, 0);
	if (m < 0)
		return (2);
	br = (union uring_buf_ring *)m;
	xmemset(&reg, 0, sizeof(reg));
	reg.ring_addr = m;
	reg.ring_entries = 2;
	reg.bgid = 50;
	reg.flags = IOU_PBUF_RING_INC;
	if (pbuf_register(&reg) != 0 ||
	    call(SYS_pipe2, (long)p, 0, 0, 0, 0, 0) != 0)
		return (3);
	br->bufs[0].addr = (u64)(unsigned long)data[0];
	br->bufs[0].len = 6;
	br->bufs[0].bid = 760;
	__atomic_store_n(&br->h.tail, 1, __ATOMIC_RELEASE);
	if (call(SYS_write, p[1], (long)"ab", 2, 0, 0, 0) != 2 ||
	    grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, p[0], (u64)-1, 0, 2,
	    50, 0xa60, c) != 0 || c[0].res != 2 ||
	    (c[0].flags & IORING_CQE_F_BUF_MORE) == 0 ||
	    br->bufs[0].addr != (u64)(unsigned long)(data[0] + 2) ||
	    br->bufs[0].len != 4)
		return (4);
	if (call(SYS_write, p[1], (long)"cdef", 4, 0, 0, 0) != 4 ||
	    grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, p[0], (u64)-1, 0, 4,
	    50, 0xa61, c) != 0 || c[0].res != 4 ||
	    (c[0].flags & IORING_CQE_F_BUF_MORE) != 0 ||
	    xmemcmp(data[0], "abcdef", 6) != 0)
		return (5);
	br->bufs[1].addr = (u64)(unsigned long)data[1];
	br->bufs[1].len = 1;
	br->bufs[1].bid = 761;
	__atomic_store_n(&br->h.tail, 2, __ATOMIC_RELEASE);
	if (call(SYS_write, p[1], (long)"W", 1, 0, 0, 0) != 1 ||
	    grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, p[0], (u64)-1, 0, 1,
	    50, 0xa62, c) != 0 || c[0].res != 1 ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 761 ||
	    data[1][0] != 'W')
		return (6);
	br->bufs[0].addr = (u64)(unsigned long)data[0];
	br->bufs[0].len = 3;
	br->bufs[0].bid = 762;
	__atomic_store_n(&br->h.tail, 3, __ATOMIC_RELEASE);
	if (call(SYS_write, p[1], (long)"X", 1, 0, 0, 0) != 1 ||
	    grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, p[0], (u64)-1, 0, 1,
	    50, 0xa63, c) != 0 || c[0].res != 1 ||
	    (c[0].flags & IORING_CQE_F_BUF_MORE) == 0 ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 762 ||
	    br->bufs[0].len != 2)
		return (7);
	if (call(SYS_write, p[1], (long)"YZ", 2, 0, 0, 0) != 2 ||
	    grp_op(IORING_OP_READ, IOSQE_BUFFER_SELECT, p[0], (u64)-1, 0, 2,
	    50, 0xa64, c) != 0 || c[0].res != 2 ||
	    (c[0].flags & IORING_CQE_F_BUF_MORE) != 0 ||
	    xmemcmp(data[0], "XYZ", 3) != 0)
		return (8);
	xmemset(&st, 0, sizeof(st));
	st.buf_group = 50;
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
	    (long)&st, 1, 0, 0) != 0 || st.head != 3 ||
	    pbuf_unregister(50) != 0)
		return (9);
	(void)sys1(SYS_close, p[0]);
	(void)sys1(SYS_close, p[1]);
	return (0);
}

static int
t_pbuf_ring_incremental_multishot(void)
{
	struct pbuf_reg reg;
	struct pbuf_status st;
	union uring_buf_ring *br;
	struct cqe c[8];
	static char data[8];
	long m;
	u32 slot;
	int sv[2], n, i, res, shots;

	if (ring_setup(8) < 0)
		return (1);
	xmemset(&reg, 0, sizeof(reg));
	reg.ring_entries = 4;
	reg.bgid = 49;
	reg.flags = IOU_PBUF_RING_MMAP | IOU_PBUF_RING_INC;
	reg.min_left = 1;
	if (pbuf_register(&reg) != 0)
		return (2);
	m = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd_ring, IORING_OFF_PBUF_RING | ((u64)reg.bgid << IORING_OFF_PBUF_SHIFT));
	if (m < 0)
		return (3);
	br = (union uring_buf_ring *)m;
	br->bufs[0].addr = (u64)(unsigned long)data;
	br->bufs[0].len = sizeof(data);
	br->bufs[0].bid = 740;
	__atomic_store_n(&br->h.tail, 1, __ATOMIC_RELEASE);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_DGRAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (4);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0,
	    sizeof(data), 0, 0xa50);
	g_sqes[slot].buf_index = 49;
	g_sqes[slot].ioprio = IORING_RECV_MULTISHOT;
	if (iou_flush(1, 0) != 1 || iou_reap(c, 8) != 0 ||
	    pbuf_unregister(49) != -16)
		return (5);
	if (call(SYS_write, sv[0], (long)"one", 3, 0, 0, 0) != 3 ||
	    call(SYS_write, sv[0], (long)"xy", 2, 0, 0, 0) != 2 ||
	    call(SYS_io_uring_enter, fd_ring, 0, 2, IORING_ENTER_GETEVENTS,
	    0, 0) < 0)
		return (6);
	n = iou_reap(c, 8);
	shots = 0;
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0xa50)
			continue;
		if ((c[i].res != 3 && c[i].res != 2) ||
		    (c[i].flags & (IORING_CQE_F_BUFFER | IORING_CQE_F_MORE |
		    IORING_CQE_F_BUF_MORE)) !=
		    (IORING_CQE_F_BUFFER | IORING_CQE_F_MORE |
		    IORING_CQE_F_BUF_MORE) ||
		    (c[i].flags >> IORING_CQE_BUFFER_SHIFT) != 740)
			return (7);
		shots++;
	}
	if (shots != 2 || xmemcmp(data, "onexy", 5) != 0 ||
	    br->bufs[0].addr != (u64)(unsigned long)(data + 5) ||
	    br->bufs[0].len != 3)
		return (8);
	xmemset(&st, 0, sizeof(st));
	st.buf_group = 49;
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
	    (long)&st, 1, 0, 0) != 0 || st.head != 0)
		return (9);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0xa50, 0, 0,
	    0xa51);
	if (iou_flush(1, 2) != 1)
		return (10);
	n = iou_reap(c, 8);
	if (n != 2 || !cqe_find(c, n, 0xa51, &res) || res != 0 ||
	    !cqe_find(c, n, 0xa50, &res) || res != -ELINUX_ECANCELED)
		return (11);
	for (i = 0; i < n; i++)
		if (c[i].user_data == 0xa50 &&
		    (c[i].res != -ELINUX_ECANCELED || c[i].flags != 0))
			return (12);
	if (call(SYS_write, sv[0], (long)"zzz", 3, 0, 0, 0) != 3 ||
	    grp_op(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 8,
	    49, 0xa52, c) != 0 || c[0].res != 3 ||
	    (c[0].flags & IORING_CQE_F_BUFFER) == 0 ||
	    (c[0].flags & IORING_CQE_F_BUF_MORE) != 0 ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 740 ||
	    xmemcmp(data + 5, "zzz", 3) != 0 || br->bufs[0].len != 0)
		return (13);
	xmemset(&st, 0, sizeof(st));
	st.buf_group = 49;
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
	    (long)&st, 1, 0, 0) != 0 || st.head != 1 ||
	    pbuf_unregister(49) != 0)
		return (14);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_pbuf_ring_incremental_bundle(void)
{
	struct pbuf_reg reg;
	struct pbuf_status st;
	union uring_buf_ring *br;
	struct cqe c[8];
	static char data[8] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' };
	char got[8];
	long m;
	u32 slot;
	int sv[2], n, i, rounds, total, terminal, saw_more;

	if (ring_setup(8) < 0)
		return (1);
	xmemset(&reg, 0, sizeof(reg));
	reg.ring_entries = 4;
	reg.bgid = 51;
	reg.flags = IOU_PBUF_RING_MMAP | IOU_PBUF_RING_INC;
	if (pbuf_register(&reg) != 0)
		return (2);
	m = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd_ring, IORING_OFF_PBUF_RING | ((u64)reg.bgid << IORING_OFF_PBUF_SHIFT));
	if (m < 0 ||
	    call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (3);
	br = (union uring_buf_ring *)m;
	br->bufs[0].addr = (u64)(unsigned long)data;
	br->bufs[0].len = sizeof(data);
	br->bufs[0].bid = 770;
	__atomic_store_n(&br->h.tail, 1, __ATOMIC_RELEASE);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SEND, IOSQE_BUFFER_SELECT, sv[0], 0, 0, 5, 0,
	    0xa70);
	g_sqes[slot].buf_index = 51;
	g_sqes[slot].ioprio = IORING_RECVSEND_BUNDLE;
	if (iou_flush(1, 1) != 1)
		return (4);
	total = terminal = saw_more = 0;
	for (rounds = 0; rounds < 4 && !terminal; rounds++) {
		n = iou_reap(c, 8);
		if (n == 0) {
			if (call(SYS_io_uring_enter, fd_ring, 0, 1,
			    IORING_ENTER_GETEVENTS, 0, 0) < 0)
				return (5);
			n = iou_reap(c, 8);
		}
		for (i = 0; i < n; i++) {
			if (c[i].user_data != 0xa70 || c[i].res <= 0 ||
			    (c[i].flags & IORING_CQE_F_BUFFER) == 0 ||
			    (c[i].flags >> IORING_CQE_BUFFER_SHIFT) != 770)
				return (6);
			total += c[i].res;
			if ((c[i].flags & IORING_CQE_F_BUF_MORE) != 0) {
				if ((c[i].flags & IORING_CQE_F_MORE) == 0)
					return (7);
				saw_more++;
			}
			if ((c[i].flags & IORING_CQE_F_MORE) == 0)
				terminal++;
		}
	}
	if (total != 8 || terminal != 1 || saw_more != 1 ||
	    br->bufs[0].len != 0)
		return (8);
	xmemset(got, 0, sizeof(got));
	if (call(SYS_read, sv[1], (long)got, sizeof(got), 0, 0, 0) !=
	    (long)sizeof(got) || xmemcmp(got, data, sizeof(got)) != 0)
		return (9);
	xmemset(&st, 0, sizeof(st));
	st.buf_group = 51;
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
	    (long)&st, 1, 0, 0) != 0 || st.head != 1 ||
	    pbuf_unregister(51) != 0)
		return (10);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_pbuf_ring_invalid(void)
{
	struct pbuf_reg reg;
	struct cqe c[2];
	static char b[8];

	if (ring_setup(8) < 0)
		return (1);
	xmemset(&reg, 0, sizeof(reg)); reg.ring_entries = 3; reg.bgid = 43;
	if (pbuf_register(&reg) != -EINVAL)
		return (2);
	reg.ring_entries = 4; reg.flags = 0x8000;
	if (pbuf_register(&reg) != -EINVAL)
		return (3);
	reg.flags = IOU_PBUF_RING_INC;
	if (pbuf_register(&reg) != -EINVAL)
		return (4);
	reg.flags = 0; reg.min_left = 1;
	if (pbuf_register(&reg) != -EINVAL)
		return (5);
	reg.min_left = 0;
	reg.flags = IOU_PBUF_RING_MMAP; reg.ring_addr = 4096;
	if (pbuf_register(&reg) != -EINVAL)
		return (5);
	xmemset(&reg, 0, sizeof(reg)); reg.ring_entries = 4; reg.bgid = 43;
	reg.ring_addr = 1;
	if (pbuf_register(&reg) != -EINVAL)
		return (6);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 1, 700, b, 8, 44,
	    0xa20, c) != 0)
		return (7);
	xmemset(&reg, 0, sizeof(reg)); reg.ring_entries = 4; reg.bgid = 44;
	reg.flags = IOU_PBUF_RING_MMAP;
	if (pbuf_register(&reg) != -17)
		return (8);
	reg.bgid = 45;
	if (pbuf_register(&reg) != 0)
		return (9);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 1, 701, b, 8, 45,
	    0xa21, c) != 0 || c[0].res != -EINVAL)
		return (10);
	reg.flags = 1;
	if (call(SYS_io_uring_register, fd_ring, IORING_UNREGISTER_PBUF_RING,
	    (long)&reg, 1, 0, 0) != -EINVAL)
		return (11);
	return (pbuf_unregister(45) == 0 ? 0 : 12);
}

/* ================= network provided-buffer bundles ================= */
static int
t_pbuf_recv_bundle_multibuf(void)
{
 struct pbuf_reg reg;
 struct pbuf_status st;
 union uring_buf_ring *br;
 struct cqe c[4];
 static char pool[12];
 long m;
 u32 slot;
 int sv[2], n, i;

 if (ring_setup(8) < 0)
  return (1);
 xmemset(&reg, 0, sizeof(reg));
 reg.ring_entries = 4;
 reg.bgid = 53;
 reg.flags = IOU_PBUF_RING_MMAP;
 if (pbuf_register(&reg) != 0)
  return (2);
 m = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
     fd_ring, IORING_OFF_PBUF_RING | ((u64)reg.bgid << IORING_OFF_PBUF_SHIFT));
 if (m < 0 ||
     call(SYS_socketpair, LX_AF_UNIX,
     LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
  return (3);
 br = (union uring_buf_ring *)m;
 for (i = 0; i < 3; i++) {
  br->bufs[i].addr = (u64)(unsigned long)(pool + i * 4);
  br->bufs[i].len = 4;
  br->bufs[i].bid = 800 + i;
 }
 __atomic_store_n(&br->h.tail, 3, __ATOMIC_RELEASE);
 if (call(SYS_write, sv[0], (long)"0123456789", 10, 0, 0, 0) != 10)
  return (4);
 slot = g_sqi & g_sqmask;
 iou_sqe(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 12, 0, 0xa81);
 g_sqes[slot].buf_index = 53;
 g_sqes[slot].ioprio = IORING_RECVSEND_BUNDLE;
 if (iou_flush(1, 1) != 1)
  return (5);
 n = iou_reap(c, 4);
 if (n != 1 || c[0].res != 10 ||
     (c[0].flags & IORING_CQE_F_BUFFER) == 0 ||
     (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 800 ||
     xmemcmp(pool, "0123456789", 10) != 0)
  return (6);
 xmemset(&st, 0, sizeof(st));
 st.buf_group = 53;
 if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
     (long)&st, 1, 0, 0) != 0)
  return (7);
 if (st.head != 3 || pbuf_unregister(53) != 0)
  return (8);
 (void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
 return (0);
}

static int
t_pbuf_recv_bundle_multishot(void)
{
	struct pbuf_reg reg;
	struct pbuf_status st;
	union uring_buf_ring *br;
	struct cqe c[8];
	static char pool[16];
	long m;
	u32 slot;
	int sv[2], n, i;

	if (ring_setup(8) < 0)
		return (1);
	xmemset(&reg, 0, sizeof(reg));
	reg.ring_entries = 4;
	reg.bgid = 55;
	reg.flags = IOU_PBUF_RING_MMAP;
	if (pbuf_register(&reg) != 0)
		return (2);
	m = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd_ring, IORING_OFF_PBUF_RING |
	    ((u64)reg.bgid << IORING_OFF_PBUF_SHIFT));
	if (m < 0 || call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_DGRAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (3);
	br = (union uring_buf_ring *)m;
	for (i = 0; i < 4; i++) {
		br->bufs[i].addr = (u64)(unsigned long)(pool + i * 4);
		br->bufs[i].len = 4;
		br->bufs[i].bid = 820 + i;
	}
	__atomic_store_n(&br->h.tail, 4, __ATOMIC_RELEASE);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0,
	    sizeof(pool), 0, 0xa84);
	g_sqes[slot].buf_index = 55;
	g_sqes[slot].ioprio =
	    IORING_RECVSEND_BUNDLE | IORING_RECV_MULTISHOT;
	if (iou_flush(1, 0) != 1 || iou_reap(c, 8) != 0)
		return (4);
	if (call(SYS_write, sv[0], (long)"abcdef", 6, 0, 0, 0) != 6 ||
	    call(SYS_write, sv[0], (long)"ghijkl", 6, 0, 0, 0) != 6 ||
	    call(SYS_io_uring_enter, fd_ring, 0, 2, IORING_ENTER_GETEVENTS,
	    0, 0) < 0)
		return (5);
	n = iou_reap(c, 8);
	if (n != 2 || c[0].user_data != 0xa84 ||
	    c[1].user_data != 0xa84 || c[0].res != 6 || c[1].res != 6)
		return (6);
	if ((c[0].flags & (IORING_CQE_F_BUFFER | IORING_CQE_F_MORE)) !=
	    (IORING_CQE_F_BUFFER | IORING_CQE_F_MORE) ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 820 ||
	    c[1].flags != (IORING_CQE_F_BUFFER |
	    (822U << IORING_CQE_BUFFER_SHIFT)))
		return (7);
	if (xmemcmp(pool, "abcdef", 6) != 0 ||
	    xmemcmp(pool + 8, "ghijkl", 6) != 0)
		return (8);
	xmemset(&st, 0, sizeof(st));
	st.buf_group = 55;
	if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
	    (long)&st, 1, 0, 0) != 0 || st.head != 4 ||
	    pbuf_unregister(55) != 0)
		return (9);
	(void)sys1(SYS_close, sv[0]);
	(void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_pbuf_recv_bundle_empty_recover(void)
{
 struct pbuf_reg reg;
 struct pbuf_status st;
 union uring_buf_ring *br;
 struct cqe c[4];
 static char data[8];
 long m;
 u32 slot;
 int sv[2], n;

 if (ring_setup(8) < 0)
  return (1);
 xmemset(&reg, 0, sizeof(reg));
 reg.ring_entries = 4;
 reg.bgid = 54;
 reg.flags = IOU_PBUF_RING_MMAP;
 if (pbuf_register(&reg) != 0)
  return (2);
 m = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
     fd_ring, IORING_OFF_PBUF_RING | ((u64)reg.bgid << IORING_OFF_PBUF_SHIFT));
 if (m < 0 ||
     call(SYS_socketpair, LX_AF_UNIX,
     LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
  return (3);
 br = (union uring_buf_ring *)m;
 if (call(SYS_write, sv[0], (long)"ABCD", 4, 0, 0, 0) != 4)
  return (4);
 slot = g_sqi & g_sqmask;
 iou_sqe(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 4, 0, 0xa82);
 g_sqes[slot].buf_index = 54;
 g_sqes[slot].ioprio = IORING_RECVSEND_BUNDLE;
 if (iou_flush(1, 1) != 1)
  return (5);
 n = iou_reap(c, 4);
 if (n != 1 || c[0].res != -ELINUX_ENOBUFS || c[0].flags != 0)
  return (6);
 xmemset(&st, 0, sizeof(st)); st.buf_group = 54;
 if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
     (long)&st, 1, 0, 0) != 0 || st.head != 0)
  return (7);
 br->bufs[0].addr = (u64)(unsigned long)data;
 br->bufs[0].len = 4;
 br->bufs[0].bid = 810;
 __atomic_store_n(&br->h.tail, 1, __ATOMIC_RELEASE);
 slot = g_sqi & g_sqmask;
 iou_sqe(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 4, 0, 0xa83);
 g_sqes[slot].buf_index = 54;
 g_sqes[slot].ioprio = IORING_RECVSEND_BUNDLE;
 if (iou_flush(1, 1) != 1)
  return (8);
 n = iou_reap(c, 4);
 if (n != 1 || c[0].res != 4 ||
     (c[0].flags & IORING_CQE_F_BUFFER) == 0 ||
     (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 810 ||
     xmemcmp(data, "ABCD", 4) != 0)
  return (9);
 xmemset(&st, 0, sizeof(st)); st.buf_group = 54;
 if (call(SYS_io_uring_register, fd_ring, IORING_REGISTER_PBUF_STATUS,
     (long)&st, 1, 0, 0) != 0 || st.head != 1 ||
     pbuf_unregister(54) != 0)
  return (10);
 (void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
 return (0);
}

static int
t_ioprio_send_bundle(void)
{
	static char pool[12];
	struct cqe c[8];
	char rb[16];
	u32 slot;
	int sv[2], n, i, rounds, total = 0, seen = 0, terminal = 0;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	xmemcpy(pool, "abcdEFGHijkl", sizeof(pool));
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 3, 80, pool, 4, 20,
	    0x990, c) != 0)
		return (3);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_SEND, IOSQE_BUFFER_SELECT, sv[0], 0, 0,
	    sizeof(pool), 0, 0x991);
	g_sqes[slot].buf_index = 20;
	g_sqes[slot].ioprio = IORING_RECVSEND_BUNDLE;
	if (iou_flush(1, 1) != 1)
		return (4);
	for (rounds = 0; rounds < 4 && !terminal; rounds++) {
		n = iou_reap(c, 8);
		if (n == 0) {
			if (call(SYS_io_uring_enter, fd_ring, 0, 1,
			    IORING_ENTER_GETEVENTS, 0, 0) < 0)
				return (5);
			n = iou_reap(c, 8);
		}
		if (n < 1 || n > 3)
			return (6);
		for (i = 0; i < n; i++) {
			if (c[i].user_data != 0x991 || c[i].res <= 0 ||
			    (c[i].flags & IORING_CQE_F_BUFFER) == 0)
				return (7);
			if ((c[i].flags >> IORING_CQE_BUFFER_SHIFT) != 80 + seen)
				return (8);
			total += c[i].res;
			seen += (c[i].res + 3) / 4;
			if ((c[i].flags & IORING_CQE_F_MORE) == 0) {
				if (i + 1 != n)
					return (9);
				terminal = 1;
			}
		}
	}
	if (!terminal || total != 12 || seen != 3)
		return (10);
	xmemset(rb, 0, sizeof(rb));
	if (call(SYS_read, sv[1], (long)rb, 12, 0, 0, 0) != 12 ||
	    xmemcmp(rb, pool, 12) != 0)
		return (11);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_ioprio_recv_bundle(void)
{
	static char pool[12];
	struct cqe c[4];
	char tail[12];
	u32 slot;
	int sv[2], n, left;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 3, 90, pool, 4, 21,
	    0x992, c) != 0)
		return (3);
	if (call(SYS_write, sv[0], (long)"0123456789", 10, 0, 0, 0) != 10)
		return (4);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 12, 0,
	    0x993);
	g_sqes[slot].buf_index = 21;
	g_sqes[slot].ioprio = IORING_RECVSEND_BUNDLE;
	if (iou_flush(1, 1) != 1)
		return (5);
	n = iou_reap(c, 4);
	if (n != 1 || c[0].user_data != 0x993 || c[0].res < 4 ||
	    c[0].res > 10 || (c[0].flags & IORING_CQE_F_BUFFER) == 0 ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 90 ||
	    xmemcmp(pool, "0123456789", c[0].res) != 0)
		return (6);
	left = 10 - c[0].res;
	if (left != 0) {
		xmemset(tail, 0, sizeof(tail));
		if (call(SYS_read, sv[1], (long)tail, left, 0, 0, 0) != left ||
		    xmemcmp(tail, &"0123456789"[c[0].res], left) != 0)
			return (7);
	}
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_ioprio_recv_bundle_limit(void)
{
	static char pool[12];
	struct cqe c[4];
	u32 slot;
	int sv[2], n;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 3, 95, pool, 4, 22,
	    0x994, c) != 0 ||
	    call(SYS_write, sv[0], (long)"abcdefghijkl", 12, 0, 0, 0) != 12)
		return (3);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 5, 0,
	    0x995);
	g_sqes[slot].buf_index = 22;
	g_sqes[slot].ioprio = IORING_RECVSEND_BUNDLE;
	if (iou_flush(1, 1) != 1)
		return (4);
	n = iou_reap(c, 4);
	if (n != 1 || c[0].res < 4 || c[0].res > 12 ||
	    (c[0].flags & IORING_CQE_F_BUFFER) == 0 ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 95 ||
	    xmemcmp(pool, "abcdefghijkl", c[0].res) != 0)
		return (5);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_ioprio_recv_bundle_multishot(void)
{
	static char pool[16];
	struct cqe c[8];
	u32 slot;
	int sv[2], n, i, res, seen1 = 0, seen2 = 0;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_DGRAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 4, 100, pool, 4, 23,
	    0x997, c) != 0)
		return (3);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 16, 0,
	    0x998);
	g_sqes[slot].buf_index = 23;
	g_sqes[slot].ioprio = IORING_RECVSEND_BUNDLE | IORING_RECV_MULTISHOT;
	if (iou_flush(1, 0) != 1 || iou_reap(c, 8) != 0)
		return (4);
	if (call(SYS_write, sv[0], (long)"abcdef", 6, 0, 0, 0) != 6 ||
	    call(SYS_write, sv[0], (long)"ghijkl", 6, 0, 0, 0) != 6)
		return (5);
	if (call(SYS_io_uring_enter, fd_ring, 0, 2, IORING_ENTER_GETEVENTS,
	    0, 0) < 0)
		return (6);
	n = iou_reap(c, 8);
	if (n != 2)
		return (7);
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x998 || c[i].res != 4 ||
		    (c[i].flags & (IORING_CQE_F_BUFFER | IORING_CQE_F_MORE)) !=
		    (IORING_CQE_F_BUFFER | IORING_CQE_F_MORE))
			return (8);
		if ((c[i].flags >> IORING_CQE_BUFFER_SHIFT) == 100)
			seen1 = 1;
		if ((c[i].flags >> IORING_CQE_BUFFER_SHIFT) == 101)
			seen2 = 1;
	}
	if (!seen1 || !seen2 || xmemcmp(pool, "abcd", 4) != 0 ||
	    xmemcmp(pool + 4, "ghij", 4) != 0)
		return (9);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0x998, 0, 0,
	    0x999);
	if (iou_flush(1, 2) != 1)
		return (10);
	n = iou_reap(c, 8);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (!cqe_find(c, n, 0x999, &res) || res != 0 ||
	    !cqe_find(c, n, 0x998, &res) || res != -ELINUX_ECANCELED)
		return (11);
	return (0);
}

static int
t_ioprio_bundle_retry_reuse(void)
{
	static char pool[8];
	struct cqe c[6];
	u32 slot;
	int sv[2], n, res;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 2, 110, pool, 4, 25,
	    0x99e, c) != 0)
		return (3);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 8, 0,
	    0x99f);
	g_sqes[slot].buf_index = 25;
	g_sqes[slot].ioprio = IORING_RECVSEND_BUNDLE;
	if (iou_flush(1, 0) != 1 || iou_reap(c, 6) != 0)
		return (4);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0x99f, 0, 0,
	    0x9a0);
	if (iou_flush(1, 2) != 1)
		return (5);
	n = iou_reap(c, 6);
	if (!cqe_find(c, n, 0x9a0, &res) || res != 0 ||
	    !cqe_find(c, n, 0x99f, &res) || res != -ELINUX_ECANCELED)
		return (6);
	if (call(SYS_write, sv[0], (long)"reuse", 5, 0, 0, 0) != 5 ||
	    grp_op(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 4,
	    25, 0x9a1, c) != 0 || c[0].res != 4 ||
	    (c[0].flags >> IORING_CQE_BUFFER_SHIFT) != 110 ||
	    xmemcmp(pool, "reus", 4) != 0)
		return (7);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_ioprio_bundle_invalid(void)
{
	struct l_msghdr mh;
	char ch;
	int sv[2];

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_STREAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	if (sub1_ioprio(sv[0], IORING_OP_SEND, "x", 1, 0,
	    IORING_RECVSEND_BUNDLE, 0x99a) != -EINVAL ||
	    sub1_ioprio(sv[1], IORING_OP_RECV, &ch, 1, 0,
	    IORING_RECVSEND_BUNDLE, 0x99b) != -EINVAL)
		return (3);
	xmemset(&mh, 0, sizeof(mh));
	if (sub1_ioprio(sv[0], IORING_OP_SENDMSG, &mh, 0, 0,
	    IORING_RECVSEND_BUNDLE, 0x99c) != -EINVAL ||
	    sub1_ioprio(sv[1], IORING_OP_RECVMSG, &mh, 0, 0,
	    IORING_RECVSEND_BUNDLE, 0x99d) != -EINVAL)
		return (4);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

/* ================= network RECV_MULTISHOT ================= */
static int
t_ioprio_recv_multishot(void)
{
	static char pool[256];
	struct cqe c[8];
	u32 slot;
	int sv[2], n, i, res, seen3 = 0, seen4 = 0;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_DGRAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 4, 30, pool, 64, 15,
	    0x920, c) != 0)
		return (3);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 64, 0,
	    0x921);
	g_sqes[slot].buf_index = 15;
	g_sqes[slot].ioprio = IORING_RECV_MULTISHOT;
	if (iou_flush(1, 0) != 1 || iou_reap(c, 8) != 0)
		return (4);
	if (call(SYS_write, sv[0], (long)"one", 3, 0, 0, 0) != 3 ||
	    call(SYS_write, sv[0], (long)"four", 4, 0, 0, 0) != 4)
		return (5);
	if (call(SYS_io_uring_enter, fd_ring, 0, 2, IORING_ENTER_GETEVENTS,
	    0, 0) < 0)
		return (6);
	n = iou_reap(c, 8);
	if (n != 2)
		return (7);
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x921 ||
		    (c[i].flags & (IORING_CQE_F_MORE | IORING_CQE_F_BUFFER)) !=
		    (IORING_CQE_F_MORE | IORING_CQE_F_BUFFER))
			return (8);
		if (c[i].res == 3 && (c[i].flags >> IORING_CQE_BUFFER_SHIFT) == 30)
			seen3 = 1;
		if (c[i].res == 4 && (c[i].flags >> IORING_CQE_BUFFER_SHIFT) == 31)
			seen4 = 1;
	}
	if (!seen3 || !seen4 || xmemcmp(pool, "one", 3) != 0 ||
	    xmemcmp(pool + 64, "four", 4) != 0)
		return (9);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0x921, 0, 0,
	    0x922);
	if (iou_flush(1, 2) != 1)
		return (10);
	n = iou_reap(c, 8);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (!cqe_find(c, n, 0x922, &res) || res != 0)
		return (11);
	if (!cqe_find(c, n, 0x921, &res) || res != -ELINUX_ECANCELED)
		return (12);
	return (0);
}

static int
t_ioprio_recvmsg_multishot(void)
{
	static char pool[384];
	struct l_msghdr mh;
	struct recvmsg_out *out;
	struct cqe c[8];
	u32 slot;
	int sv[2], n, i, res, seen3 = 0, seen4 = 0;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_DGRAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 3, 60, pool, 128, 18,
	    0x980, c) != 0)
		return (3);
	xmemset(&mh, 0, sizeof(mh));
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECVMSG, IOSQE_BUFFER_SELECT, sv[1], 0, &mh, 0,
	    0, 0x981);
	g_sqes[slot].buf_index = 18;
	g_sqes[slot].ioprio = IORING_RECV_MULTISHOT;
	if (iou_flush(1, 0) != 1 || iou_reap(c, 8) != 0)
		return (4);
	if (call(SYS_write, sv[0], (long)"cat", 3, 0, 0, 0) != 3 ||
	    call(SYS_write, sv[0], (long)"dogs", 4, 0, 0, 0) != 4)
		return (5);
	if (call(SYS_io_uring_enter, fd_ring, 0, 2, IORING_ENTER_GETEVENTS,
	    0, 0) < 0)
		return (6);
	n = iou_reap(c, 8);
	if (n != 2)
		return (70 + n);
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x981 ||
		    (c[i].flags & (IORING_CQE_F_MORE | IORING_CQE_F_BUFFER)) !=
		    (IORING_CQE_F_MORE | IORING_CQE_F_BUFFER))
			return (8);
		if (c[i].res == 19 &&
		    (c[i].flags >> IORING_CQE_BUFFER_SHIFT) == 60)
			seen3 = 1;
		if (c[i].res == 20 &&
		    (c[i].flags >> IORING_CQE_BUFFER_SHIFT) == 61)
			seen4 = 1;
	}
	out = (struct recvmsg_out *)pool;
	if (!seen3 || out->namelen != 0 || out->controllen != 0 ||
	    out->payloadlen != 3 || xmemcmp(pool + sizeof(*out), "cat", 3) != 0)
		return (9);
	out = (struct recvmsg_out *)(pool + 128);
	if (!seen4 || out->namelen != 0 || out->controllen != 0 ||
	    out->payloadlen != 4 ||
	    xmemcmp(pool + 128 + sizeof(*out), "dogs", 4) != 0)
		return (10);
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0x981, 0, 0,
	    0x982);
	if (iou_flush(1, 2) != 1)
		return (11);
	n = iou_reap(c, 8);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (!cqe_find(c, n, 0x982, &res) || res != 0 ||
	    !cqe_find(c, n, 0x981, &res) || res != -ELINUX_ECANCELED)
		return (12);
	return (0);
}

static int
t_ioprio_recvmsg_multishot_invalid(void)
{
	static char tiny[8];
	struct l_msghdr mh;
	struct cqe c[4];
	u32 slot;
	int sv[2], n, res;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_DGRAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	xmemset(&mh, 0, sizeof(mh));
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECVMSG, IOSQE_BUFFER_SELECT, sv[1], 0, &mh, 0,
	    0, 0x983);
	g_sqes[slot].buf_index = 19;
	g_sqes[slot].ioprio = IORING_RECV_MULTISHOT;
	g_sqes[slot].splice_fd_in = 1;	/* optlen is invalid for RECVMSG */
	if (iou_flush(1, 1) != 1 || iou_reap(c, 4) != 1 ||
	    c[0].res != -EINVAL)
		return (3);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 1, 70, tiny, sizeof(tiny),
	    19, 0x984, c) != 0)
		return (4);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECVMSG, IOSQE_BUFFER_SELECT, sv[1], 0, &mh, 0,
	    0, 0x985);
	g_sqes[slot].buf_index = 19;
	g_sqes[slot].ioprio = IORING_RECV_MULTISHOT;
	if (iou_flush(1, 0) != 1)
		return (5);
	if (call(SYS_write, sv[0], (long)"x", 1, 0, 0, 0) != 1)
		return (6);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS,
	    0, 0) < 0)
		return (7);
	n = iou_reap(c, 4);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (n != 1 || !cqe_find(c, n, 0x985, &res))
		return (8);
	return (res == -EFAULT ? 0 : 9);
}

static int
t_ioprio_recv_multishot_limit(void)
{
	static char pool[128];
	char tail[2];
	struct cqe c[4];
	u32 slot;
	int sv[2], n, i, more = 0, terminal = 0;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_DGRAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 2, 50, pool, 64, 17,
	    0x970, c) != 0)
		return (3);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 64, 0,
	    0x971);
	g_sqes[slot].buf_index = 17;
	g_sqes[slot].ioprio = IORING_RECV_MULTISHOT;
	g_sqes[slot].splice_fd_in = 7;	/* optlen: total multishot bytes */
	if (iou_flush(1, 0) != 1 || iou_reap(c, 4) != 0)
		return (4);
	if (call(SYS_write, sv[0], (long)"one", 3, 0, 0, 0) != 3 ||
	    call(SYS_write, sv[0], (long)"four", 4, 0, 0, 0) != 4)
		return (5);
	if (call(SYS_io_uring_enter, fd_ring, 0, 2, IORING_ENTER_GETEVENTS,
	    0, 0) < 0)
		return (6);
	n = iou_reap(c, 4);
	if (n != 2)
		return (7);
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x971 ||
		    (c[i].flags & IORING_CQE_F_BUFFER) == 0)
			return (8);
		if (c[i].res == 3 && (c[i].flags & IORING_CQE_F_MORE) != 0)
			more = 1;
		if (c[i].res == 4 && (c[i].flags & IORING_CQE_F_MORE) == 0)
			terminal = 1;
	}
	if (!more || !terminal || xmemcmp(pool, "one", 3) != 0 ||
	    xmemcmp(pool + 64, "four", 4) != 0)
		return (9);
	if (call(SYS_write, sv[0], (long)"x", 1, 0, 0, 0) != 1)
		return (10);
	xmemset(tail, 0, sizeof(tail));
	if (sub1(sv[1], IORING_OP_RECV, tail, 1, 0, 0, 0x972) != 1 ||
	    tail[0] != 'x')
		return (11);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

static int
t_ioprio_recv_multishot_invalid(void)
{
	struct cqe c[2];
	u32 slot;
	int sv[2], n, res;

	if (ring_setup(8) < 0)
		return (1);
	if (call(SYS_socketpair, LX_AF_UNIX,
	    LX_SOCK_DGRAM | LX_SOCK_NONBLOCK, 0, (long)sv, 0, 0) != 0)
		return (2);
	if (sub1_ioprio(sv[1], IORING_OP_RECV, 0, 64, 0,
	    IORING_RECV_MULTISHOT, 0x923) != -EINVAL)
		return (3);
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_RECV, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 64,
	    LX_MSG_WAITALL, 0x924);
	g_sqes[slot].buf_index = 15;
	g_sqes[slot].ioprio = IORING_RECV_MULTISHOT;
	if (iou_flush(1, 1) != 1)
		return (4);
	n = iou_reap(c, 2);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (n != 1 || !cqe_find(c, n, 0x924, &res))
		return (5);
	return (res == -EINVAL ? 0 : 6);
}

/* ================= READ_MULTISHOT ================= */
static int t_read_multishot(void)
{
	static char pool[256];		/* 4 x 64 */
	int sv[2], res, n, i, seen3 = 0, seen4 = 0;
	u32 slot;
	struct cqe c[8];
	if (ring_setup(8) < 0) return (1);
	/* datagram socketpair: each read returns one message */
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_DGRAM | LX_SOCK_NONBLOCK, 0,
	    (long)sv, 0, 0) != 0) return (2);
	/* provide 4 buffers, group 5, bids 0..3 */
	if (grp_op(IORING_OP_PROVIDE_BUFFERS, 0, 4, 0, pool, 64, 5, 0x1, c) != 0)
		return (3);
	/* arm the multishot read (no data yet -> parks) */
	slot = g_sqi & g_sqmask;
	iou_sqe(IORING_OP_READ_MULTISHOT, IOSQE_BUFFER_SELECT, sv[1], 0, 0, 0,
	    0, 0x115);
	g_sqes[slot].buf_index = 5;		/* buf_group */
	if (iou_flush(1, 0) != 1) return (4);
	if (iou_reap(c, 8) != 0) return (5);	/* parked, nothing yet */
	/* two datagrams -> two F_MORE completions */
	if (call(SYS_write, sv[0], (long)"AAA", 3, 0, 0, 0) != 3) return (6);
	if (call(SYS_write, sv[0], (long)"BBBB", 4, 0, 0, 0) != 4) return (7);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, IORING_ENTER_GETEVENTS, 0, 0) < 0)
		return (8);
	n = iou_reap(c, 8);
	if (n != 2) return (9);
	for (i = 0; i < n; i++) {
		if (c[i].user_data != 0x115ULL) return (10);
		if ((c[i].flags & IORING_CQE_F_MORE) == 0) return (11);
		if ((c[i].flags & IORING_CQE_F_BUFFER) == 0) return (12);
		if (c[i].res == 3) seen3 = 1;
		if (c[i].res == 4) seen4 = 1;
	}
	if (!seen3 || !seen4) return (13);
	if (xmemcmp(pool, "AAA", 3) != 0) return (14);		/* bid 0 */
	if (xmemcmp(pool + 64, "BBBB", 4) != 0) return (15);	/* bid 1 */
	/* Cancel the data request: POLL_REMOVE only removes POLL_ADD. */
	iou_sqe(IORING_OP_ASYNC_CANCEL, 0, -1, 0, (void *)0x115, 0, 0, 0x2);
	if (iou_flush(1, 2) != 1) return (16);
	n = iou_reap(c, 8);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (!cqe_find(c, n, 0x2, &res) || res != 0) return (17);
	if (!cqe_find(c, n, 0x115, &res) || res != -ELINUX_ECANCELED) return (18);
	return (0);
}
static int t_read_multishot_needs_bufsel(void)
{
	int sv[2];
	if (ring_setup(8) < 0) return (1);
	if (call(SYS_socketpair, LX_AF_UNIX, LX_SOCK_DGRAM, 0, (long)sv, 0, 0) != 0)
		return (2);
	/* multishot read without IOSQE_BUFFER_SELECT -> EINVAL */
	if (sub1(sv[1], IORING_OP_READ_MULTISHOT, 0, 0, 0, 0, 0x1) != -EINVAL)
		return (3);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	return (0);
}

/* enter wait arguments: deadlines and atomic signal-mask replacement. */
#define IORING_ENTER_EXT_ARG (1U << 3)
#define IORING_ENTER_ABS_TIMER (1U << 5)
#define IORING_FEAT_EXT_ARG (1U << 8)
struct enter_arg { u64 sigmask; u32 sigmask_sz, min_wait_usec; u64 ts; };

static long
enter_timed(u32 nsub, u32 nwait, struct timespec *ts, u32 flags, u64 *mask)
{
	struct enter_arg arg = { (u64)mask, 8, 0, (u64)ts };

	__atomic_store_n(g_sq_tail, g_sqi, __ATOMIC_RELEASE);
	return (call(SYS_io_uring_enter, fd_ring, nsub, nwait,
	    IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG | flags,
	    (long)&arg, sizeof(arg)));
}

static long
mono_ns(void)
{
	struct timespec ts;

	if (sys2(SYS_clock_gettime, 1, &ts) != 0)
		return (-1);
	return (ts.tv_sec * 1000000000L + ts.tv_nsec);
}

static int
t_enter_timeout(void)
{
	struct timespec ts = { 0, 30000000 };
	struct params p;
	long start, elapsed;

	xmemset(&p, 0, sizeof(p));
	long fd = call(SYS_io_uring_setup, 2, (long)&p, 0, 0, 0, 0);
	if (fd < 0 || !(p.features & IORING_FEAT_EXT_ARG))
		return (1);
	(void)sys1(SYS_close, fd);
	if (ring_setup(4) < 0)
		return (2);
	start = mono_ns();
	if (enter_timed(0, 1, &ts, 0, 0) != -ELINUX_ETIME)
		return (3);
	elapsed = mono_ns() - start;
	if (elapsed < 20000000 || elapsed > 2000000000L)
		return (4);
	ts.tv_nsec = 0;
	if (enter_timed(0, 1, &ts, 0, 0) != -ELINUX_ETIME)
		return (5);
	/* A timeout is an enter result, not a fabricated completion. */
	if (*g_cq_head != *g_cq_tail)
		return (6);
	(void)sys1(SYS_close, fd_ring);
	return (0);
}

static int
t_enter_absolute(void)
{
	struct timespec ts;
	long start;

	if (ring_setup(4) < 0 || sys2(SYS_clock_gettime, 1, &ts) != 0)
		return (1);
	ts.tv_nsec += 30000000;
	if (ts.tv_nsec >= 1000000000) {
		ts.tv_nsec -= 1000000000;
		ts.tv_sec++;
	}
	start = mono_ns();
	if (enter_timed(0, 1, &ts, IORING_ENTER_ABS_TIMER, 0) != -ELINUX_ETIME)
		return (2);
	if (mono_ns() - start < 20000000)
		return (3);
	/* The same expired absolute deadline must not become a relative wait. */
	start = mono_ns();
	if (enter_timed(0, 1, &ts, IORING_ENTER_ABS_TIMER, 0) != -ELINUX_ETIME ||
	    mono_ns() - start > 1000000000L)
		return (4);
	(void)sys1(SYS_close, fd_ring);
	return (0);
}

static int
t_enter_poll_timeout(void)
{
	struct timespec ts = { 0, 30000000 };
	struct cqe c;
	int pipes[2];
	char ch = 'x';

	if (ring_setup(4) < 0 || sys2(SYS_pipe2, pipes, 0) != 0)
		return (1);
	iou_sqe(IORING_OP_POLL_ADD, 0, pipes[0], 0, 0, 0, LX_POLLIN, 731);
	if (iou_flush(1, 0) != 1)
		return (2);
	if (enter_timed(0, 1, &ts, 0, 0) != -ELINUX_ETIME)
		return (3);
	/* Timing out the waiter must leave the poll request armed. */
	if (sys3(SYS_write, pipes[1], &ch, 1) != 1)
		return (4);
	ts.tv_sec = 1;
	if (enter_timed(0, 1, &ts, 0, 0) != 0 || iou_reap(&c, 1) != 1 ||
	    c.user_data != 731 || !(c.res & LX_POLLIN))
		return (5);
	(void)sys1(SYS_close, pipes[0]);
	(void)sys1(SYS_close, pipes[1]);
	(void)sys1(SYS_close, fd_ring);
	return (0);
}

/* Expiry must drain queued readiness once, without spinning on idle polls. */
static int
enter_poll_expired(u32 flags, int fast, int multi, u32 min_complete)
{
	struct timespec ts = { 0, 0 };
	struct cqe c;
	int pipes[2];
	char sent = 'z', received = 0;
	long start;

	if (ring_setup(4) < 0 || sys2(SYS_pipe2, pipes, 0) != 0)
		return (1);
	if (fast && sys3(SYS_fcntl, pipes[0], 4 /* F_SETFL */, O_NONBLOCK) != 0)
		return (10);
	if (fast)
		iou_sqe(IORING_OP_READ, 0, pipes[0], -1, &received, 1, 0, 736);
	else
		iou_sqe(IORING_OP_POLL_ADD, 0, pipes[0], 0, 0, multi,
		    LX_POLLIN, 736);
	if (iou_flush(1, 0) != 1)
		return (2);
	/* Leave an idle poll armed across several expired waits. */
	start = mono_ns();
	for (int i = 0; i < 3; i++) {
		if (enter_timed(0, min_complete, &ts, flags, 0) != -ELINUX_ETIME)
			return (3);
	}
	if (mono_ns() - start > 1000000000L)
		return (4);
	if (sys3(SYS_write, pipes[1], &sent, 1) != 1)
		return (5);
	if (enter_timed(0, min_complete, &ts, flags, 0) != 0 ||
	    iou_reap(&c, 1) != 1 || c.user_data != 736)
		return (6);
	if (fast ? c.res != 1 || received != sent : !(c.res & LX_POLLIN))
		return (7);
	if (!!(c.flags & IORING_CQE_F_MORE) != multi)
		return (8);
	/* Even a persistent ready target must not keep the waiter spinning. */
	if (enter_timed(0, 1, &ts, flags, 0) != -ELINUX_ETIME)
		return (9);
	(void)sys1(SYS_close, pipes[0]);
	(void)sys1(SYS_close, pipes[1]);
	(void)sys1(SYS_close, fd_ring);
	return (0);
}
static int t_enter_poll_zero(void) { return (enter_poll_expired(0, 0, 0, 1)); }
static int t_enter_poll_expired(void)
{ return (enter_poll_expired(IORING_ENTER_ABS_TIMER, 0, 0, 1)); }
static int t_enter_poll_partial(void) { return (enter_poll_expired(0, 0, 0, 2)); }
static int t_enter_fast_poll_zero(void) { return (enter_poll_expired(0, 1, 0, 1)); }
static int t_enter_multishot_zero(void) { return (enter_poll_expired(0, 0, 1, 2)); }

static int
t_enter_partial(void)
{
	struct timespec ts = { 0, 30000000 };
	struct cqe c;

	if (ring_setup(4) < 0)
		return (1);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 732);
	if (iou_flush(1, 0) != 1)
		return (2);
	if (enter_timed(0, 2, &ts, 0, 0) != 0 || iou_reap(&c, 1) != 1 ||
	    c.user_data != 732 || c.res != 0)
		return (3);
	(void)sys1(SYS_close, fd_ring);
	return (0);
}

static int
t_enter_completion(void)
{
	struct timespec op_ts = { 0, 10000000 }, wait_ts = { 2, 0 };
	struct cqe c;

	if (ring_setup(4) < 0)
		return (1);
	iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &op_ts, 1, 0, 733);
	if (enter_timed(1, 1, &wait_ts, 0, 0) != 1 ||
	    iou_reap(&c, 1) != 1 || c.user_data != 733 ||
	    c.res != -ELINUX_ETIME)
		return (2);
	(void)sys1(SYS_close, fd_ring);
	return (0);
}

static int
t_enter_args(void)
{
	struct enter_arg arg = { 0, 0, 0, 0 };
	struct timespec ts = { 0, 0 };
	u64 mask = 0;
	long flags = IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG;

	if (ring_setup(4) < 0)
		return (1);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, flags, (long)&arg, 23) != -EINVAL)
		return (2);
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, flags, 1, 24) != -EFAULT)
		return (3);
	arg.ts = 1;
	if (call(SYS_io_uring_enter, fd_ring, 0, 0, flags, (long)&arg, 24) != -EFAULT)
		return (4);
	arg.ts = (u64)&ts;
	arg.sigmask = (u64)&mask;
	arg.sigmask_sz = 7;
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, flags, (long)&arg, 24) != -EINVAL)
		return (5);
	arg.sigmask = 1;
	arg.sigmask_sz = 8;
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, flags, (long)&arg, 24) != -EFAULT)
		return (6);
	arg.sigmask = 0;
	arg.min_wait_usec = 1;
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, flags, (long)&arg, 24) != -ELINUX_ETIME)
		return (10);
	arg.min_wait_usec = 0;
	/* Without GETEVENTS, the wait argument is not accessed. */
	if (call(SYS_io_uring_enter, fd_ring, 0, 0, IORING_ENTER_EXT_ARG, 1, 0) != 0)
		return (7);
	/* Legacy mask validation, with a ring that needs to wait. */
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, 1, (long)&mask, 7) != -EINVAL ||
	    call(SYS_io_uring_enter, fd_ring, 0, 1, 1, 1, 8) != -EFAULT)
		return (8);
	/* A ready CQ also bypasses mask copying for a nonempty wait. */
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 738);
	if (iou_flush(1, 0) != 1 ||
	    call(SYS_io_uring_enter, fd_ring, 0, 1, 1, 1, 8) != 0)
		return (11);
	arg.sigmask = 1;
	arg.sigmask_sz = 8;
	if (call(SYS_io_uring_enter, fd_ring, 0, 1, flags, (long)&arg, 24) != 0)
		return (12);
	/* An empty wait need not inspect even an invalid legacy mask. */
	if (call(SYS_io_uring_enter, fd_ring, 0, 0, 1, 1, 8) != 0)
		return (9);
	(void)sys1(SYS_close, fd_ring);
	return (0);
}

static int
t_enter_time_bounds(void)
{
	struct timespec expired[] = {
		{ -1, 0 }, { 1, -1000000000 },
		{ (-9223372036854775807L - 1), 9223372036854775807L }
	};
	struct timespec future[] = {
		{ 9223372036854775807L, 9223372036854775807L },
		{ 0, 9223372036854775807L }
	};
	struct timespec op_ts = { 0, 1000000 };
	struct cqe c;

	if (ring_setup(4) < 0)
		return (1);
	for (u32 i = 0; i < sizeof(expired) / sizeof(expired[0]); i++) {
		if (enter_timed(0, 1, &expired[i], 0, 0) != -ELINUX_ETIME)
			return (2);
	}
	/* Saturating long waits must remain interruptible by completions. */
	for (u32 i = 0; i < sizeof(future) / sizeof(future[0]); i++) {
		iou_sqe(IORING_OP_TIMEOUT, 0, -1, 0, &op_ts, 1, 0, 737);
		if (iou_flush(1, 0) != 1 ||
		    enter_timed(0, 1, &future[i], 0, 0) != 0 ||
		    iou_reap(&c, 1) != 1 || c.res != -ELINUX_ETIME)
			return (3);
	}
	(void)sys1(SYS_close, fd_ring);
	return (0);
}

static int
t_enter_submit_error(void)
{
	struct cqe c;

	if (ring_setup(4) < 0)
		return (1);
	iou_sqe(IORING_OP_NOP, 0, -1, 0, 0, 0, 0, 734);
	__atomic_store_n(g_sq_tail, g_sqi, __ATOMIC_RELEASE);
	if (call(SYS_io_uring_enter, fd_ring, 1, 2,
	    IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG, 1, 24) != 1 ||
	    iou_reap(&c, 1) != 1 || c.user_data != 734)
		return (2);
	(void)sys1(SYS_close, fd_ring);
	return (0);
}

static volatile int enter_signal_hits;
#ifdef __aarch64__
__asm__(".globl enter_restorer\nenter_restorer:\n mov x8, #139\n svc #0\n brk #0\n");
#else
__asm__(".globl enter_restorer\nenter_restorer:\n mov $15, %eax\n syscall\n hlt\n");
#endif
void enter_restorer(void);
static void
enter_handler(int sig __attribute__((unused)))
{
	enter_signal_hits++;
}

static int
enter_signal_case(int extended, int poll_wait, int expiry)
{
	struct { void *handler; u64 flags; void *restorer; u64 mask; } sa, oldsa;
	struct timespec ts = { 1, 0 };
	u64 mask = 1UL << (SIGUSR1 - 1), empty = 0, oldmask = 0, current = 0;
	int pipes[2] = { -1, -1 }, rc = 0;
	long r;

	if (ring_setup(4) < 0)
		return (1);
	sa.handler = (void *)enter_handler;
	sa.flags = 0x04000000 | 0x10000000; /* SA_RESTORER | SA_RESTART */
	sa.restorer = (void *)enter_restorer;
	sa.mask = 0;
	if (sys4(SYS_rt_sigaction, SIGUSR1, &sa, &oldsa, 8) != 0 ||
	    sys4(SYS_rt_sigprocmask, SIG_BLOCK, &mask, &oldmask, 8) != 0)
		return (2);
	enter_signal_hits = 0;
	if (poll_wait) {
		if (sys2(SYS_pipe2, pipes, 0) != 0) { rc = 3; goto out; }
		iou_sqe(IORING_OP_POLL_ADD, 0, pipes[0], 0, 0, 0, LX_POLLIN, 735);
		if (iou_flush(1, 0) != 1) { rc = 4; goto out; }
	}
	/* Queue while blocked; enter must atomically unblock and deliver it. */
	if (sys2(SYS_kill, sys0(SYS_getpid), SIGUSR1) != 0) { rc = 5; goto out; }
	if (expiry != 0)
		ts.tv_sec = 0;
	if (extended)
		r = enter_timed(0, 1, &ts,
		    expiry == 2 ? IORING_ENTER_ABS_TIMER : 0, &empty);
	else
		r = call(SYS_io_uring_enter, fd_ring, 0, 1, 1, (long)&empty, 8);
	if (r != -EINTR || enter_signal_hits != 1) { rc = 6; goto out; }
	if (sys4(SYS_rt_sigprocmask, SIG_BLOCK, 0, &current, 8) != 0 ||
	    !(current & mask)) { rc = 7; goto out; }
	/* Success/timeout must restore the original mask as well. */
	ts.tv_sec = 0;
	ts.tv_nsec = 1000000;
	if (enter_timed(0, 1, &ts, 0, &empty) != -ELINUX_ETIME ||
	    sys4(SYS_rt_sigprocmask, SIG_BLOCK, 0, &current, 8) != 0 ||
	    !(current & mask)) { rc = 8; goto out; }
 out:
	(void)sys4(SYS_rt_sigprocmask, SIG_SETMASK, &oldmask, 0, 8);
	(void)sys4(SYS_rt_sigaction, SIGUSR1, &oldsa, 0, 8);
	if (pipes[0] >= 0) {
		(void)sys1(SYS_close, pipes[0]);
		(void)sys1(SYS_close, pipes[1]);
	}
	(void)sys1(SYS_close, fd_ring);
	return (rc);
}
static int t_enter_signal(void) { return (enter_signal_case(0, 0, 0)); }
static int t_enter_signal_ext(void) { return (enter_signal_case(1, 0, 0)); }
static int t_enter_signal_poll(void) { return (enter_signal_case(1, 1, 0)); }

static int t_enter_signal_zero(void) { return (enter_signal_case(1, 0, 1)); }
static int t_enter_signal_expired(void) { return (enter_signal_case(1, 0, 2)); }
static int t_enter_signal_poll_zero(void) { return (enter_signal_case(1, 1, 1)); }
static int t_enter_signal_poll_expired(void) { return (enter_signal_case(1, 1, 2)); }

/* A blocking inline op may return ERESTART; it must become an EINTR CQE. */
static int
t_enter_read_restart(void)
{
	struct { void *handler; u64 flags; void *restorer; u64 mask; } sa, oldsa;
	struct timespec delay = { 0, 50000000 };
	struct cqe c;
	u64 mask = 1UL << (SIGUSR1 - 1), oldmask;
	int pipes[2], status, rc = 0;
	char byte = 'r';
	long pid, parent;

	if (ring_setup(4) < 0 || sys2(SYS_pipe2, pipes, 0) != 0)
		return (1);
	sa.handler = (void *)enter_handler;
	sa.flags = 0x04000000 | 0x10000000;
	sa.restorer = (void *)enter_restorer;
	sa.mask = 0;
	if (sys4(SYS_rt_sigaction, SIGUSR1, &sa, &oldsa, 8) != 0 ||
	    sys4(SYS_rt_sigprocmask, SIG_UNBLOCK, &mask, &oldmask, 8) != 0)
		return (2);
	enter_signal_hits = 0;
	parent = sys0(SYS_getpid);
	pid = fork_process();
	if (pid < 0)
		return (3);
	if (pid == 0) {
		(void)sys2(SYS_nanosleep, &delay, 0);
		(void)sys2(SYS_kill, parent, SIGUSR1);
		/* Also release the read if the signal raced ahead of submission. */
		(void)sys2(SYS_nanosleep, &delay, 0);
		(void)sys3(SYS_write, pipes[1], &byte, 1);
		(void)sys1(SYS_exit_group, 0);
	}
	iou_sqe(IORING_OP_READ, 0, pipes[0], (u64)-1, &byte, 1, 0, 739);
	if (iou_flush(1, 1) != 1 || iou_reap(&c, 1) != 1 ||
	    c.user_data != 739 || c.res != -EINTR || enter_signal_hits != 1)
		rc = 4;
	if (sys4(SYS_wait4, pid, &status, 0, 0) != pid || status != 0)
		rc = 5;
	(void)sys4(SYS_rt_sigprocmask, SIG_SETMASK, &oldmask, 0, 8);
	(void)sys4(SYS_rt_sigaction, SIGUSR1, &oldsa, 0, 8);
	(void)sys1(SYS_close, pipes[0]);
	(void)sys1(SYS_close, pipes[1]);
	(void)sys1(SYS_close, fd_ring);
	return (rc);
}

static const struct subtest subtests[] = {
	{ "enter_read_restart", t_enter_read_restart },
	{ "enter_poll_zero", t_enter_poll_zero },
	{ "enter_poll_expired", t_enter_poll_expired },
	{ "enter_poll_partial", t_enter_poll_partial },
	{ "enter_fast_poll_zero", t_enter_fast_poll_zero },
	{ "enter_multishot_zero", t_enter_multishot_zero },
	{ "enter_signal_zero", t_enter_signal_zero },
	{ "enter_signal_expired", t_enter_signal_expired },
	{ "enter_signal_poll_zero", t_enter_signal_poll_zero },
	{ "enter_signal_poll_expired", t_enter_signal_poll_expired },
	{ "enter_time_bounds", t_enter_time_bounds },
	{ "enter_timeout", t_enter_timeout },
	{ "enter_absolute", t_enter_absolute },
	{ "enter_poll_timeout", t_enter_poll_timeout },
	{ "enter_partial", t_enter_partial },
	{ "enter_completion", t_enter_completion },
	{ "enter_args", t_enter_args },
	{ "enter_submit_error", t_enter_submit_error },
	{ "enter_signal", t_enter_signal },
	{ "enter_signal_ext", t_enter_signal_ext },
	{ "enter_signal_poll", t_enter_signal_poll },
	{ "setup_zero", t_setup_zero },
	{ "setup_toobig", t_setup_toobig },
	{ "setup_badflag", t_setup_badflag },
	{ "setup_resv", t_setup_resv },
	{ "setup_pow2", t_setup_pow2 },
	{ "setup_one", t_setup_one },
	{ "setup_cqsize", t_setup_cqsize },
	{ "setup_cqsize_pow2", t_setup_cqsize_pow2 },
	{ "setup_cqsize_zero", t_setup_cqsize_zero },
	{ "setup_cqsize_toosmall", t_setup_cqsize_toosmall },
	{ "setup_clamp", t_setup_clamp },
	{ "setup_features", t_setup_features },
	{ "linked_file_feature", t_linked_file_feature },
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
	{ "rw_nosignal", t_rw_nosignal },
	{ "async_write_read", t_async_write_read },
	{ "async_offset", t_async_offset },
	{ "async_readv_writev", t_async_readv_writev },
	{ "async_many", t_async_many },
	{ "async_badfd", t_async_badfd },
	{ "rw_cur_pos", t_rw_cur_pos },
	{ "write_badfd", t_write_badfd },
	{ "read_badfd", t_read_badfd },
	{ "write_rdonly", t_write_rdonly },
	{ "large_rw", t_large_rw },
	{ "zero_len", t_zero_len },
	{ "rw_attr", t_rw_attr },
	{ "rw_attr_opcode_matrix", t_rw_attr_opcode_matrix },
	{ "rw_ioprio", t_rw_ioprio },
	{ "rw_ioprio_opcode_matrix", t_rw_ioprio_opcode_matrix },
	{ "rw_ioprio_privilege", t_rw_ioprio_privilege },
	{ "fsync", t_fsync },
	{ "fsync_badfd", t_fsync_badfd },
	{ "fsync_flags", t_fsync_flags },
	{ "close", t_close },
	{ "close_badfd", t_close_badfd },
	{ "ftruncate", t_ftruncate },
	{ "ftruncate_badfd", t_ftruncate_badfd },
	{ "ftruncate_options", t_ftruncate_options },
	{ "fallocate", t_fallocate },
	{ "fallocate_mode", t_fallocate_mode },
	{ "fallocate_modes_invalid", t_fallocate_modes_invalid },
	{ "fallocate_options", t_fallocate_options },
	{ "fadvise", t_fadvise },
	{ "fadvise_badfd", t_fadvise_badfd },
	{ "fadvise_options", t_fadvise_options },
	{ "openat", t_openat },
	{ "openat_enoent", t_openat_enoent },
	{ "statx", t_statx },
	{ "mkdirat", t_mkdirat },
	{ "unlinkat", t_unlinkat },
	{ "symlinkat", t_symlinkat },
	{ "linkat", t_linkat },
	{ "renameat", t_renameat },
	{ "madvise", t_madvise },
	{ "madvise_length", t_madvise_length },
	{ "madvise_options", t_madvise_options },
	{ "sync_file_range", t_sync_file_range },
	{ "sync_file_range_options", t_sync_file_range_options },
	{ "fs_probe", t_fs_probe },
	{ "socket", t_socket },
	{ "socket_bind_listen", t_socket_bind_listen },
	{ "bind_listen_options", t_bind_listen_options },
	{ "connect_udp", t_connect_udp },
	{ "connect_shutdown_options", t_connect_shutdown_options },
	{ "socket_accept_options", t_socket_accept_options },
	{ "accept_parks", t_accept_parks },
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
	{ "epoll_ctl_options", t_epoll_ctl_options },
	{ "fxattr", t_fxattr },
	{ "xattr_options", t_xattr_options },
	{ "ext_probe", t_ext_probe },
	{ "provided_buffers", t_provided_buffers },
	{ "buffer_select_enobufs", t_buffer_select_enobufs },
	{ "remove_buffers", t_remove_buffers },
	{ "provided_buffer_options", t_provided_buffer_options },
	{ "provided_probe", t_provided_probe },
	{ "files_update_op", t_files_update_op },
	{ "files_update_options", t_files_update_options },
	{ "tee", t_tee },
	{ "tee_options", t_tee_options },
	{ "msg_ring", t_msg_ring },
	{ "msg_tee_probe", t_msg_tee_probe },
	{ "pipe", t_pipe },
	{ "pipe_options", t_pipe_options },
	{ "splice", t_splice },
	{ "splice_offsets", t_splice_offsets },
	{ "splice_options", t_splice_options },
	{ "splice_fixed_input", t_splice_fixed_input },
	{ "nop128", t_nop128 },
	{ "readv_writev_fixed", t_readv_writev_fixed },
	{ "writev_fixed_noreg", t_writev_fixed_noreg },
	{ "epoll_wait", t_epoll_wait },
	{ "epoll_wait_deferred", t_epoll_wait_deferred },
	{ "epoll_wait_cancel", t_epoll_wait_cancel },
	{ "epoll_wait_badfields", t_epoll_wait_badfields },
	{ "epoll_wait_fixed", t_epoll_wait_fixed },
	{ "epoll_wait_close_reuse", t_epoll_wait_close_reuse },
	{ "epoll_wait_close_reuse_cancel", t_epoll_wait_close_reuse_cancel },
	{ "epoll_wait_ready_cancel_race", t_epoll_wait_ready_cancel_race },
	{ "fixed_fd_install", t_fixed_fd_install },
	{ "fixed_fd_install_options", t_fixed_fd_install_options },
	{ "send_zc_skip", t_send_zc_skip },
	{ "sendmsg_zc_skip", t_sendmsg_zc_skip },
	{ "send_zc", t_send_zc },
	{ "send_zc_addr3", t_send_zc_addr3 },
	{ "sendmsg_zc_addr3", t_sendmsg_zc_addr3 },
	{ "send_zc_reserved", t_send_zc_reserved },
	{ "send_addrlen_padding", t_send_addrlen_padding },
	{ "sendmsg_reserved_fields", t_sendmsg_reserved_fields },
	{ "recv_addr2_reserved", t_recv_addr2_reserved },
	{ "send_zc_addrlen_padding", t_send_zc_addrlen_padding },
	{ "sendmsg_zc_reserved_fields", t_sendmsg_zc_reserved_fields },
	{ "send_zc_error_notification", t_send_zc_error_notification },
	{ "send_zc_error_report_usage", t_send_zc_error_report_usage },
	{ "link_timeout", t_link_timeout },
	{ "futex_wake", t_futex_wake },
	{ "futex_wait_eagain", t_futex_wait_eagain },
	{ "futex_wait_pending_wake", t_futex_wait_pending_wake },
	{ "futex_wait_pending_cancel", t_futex_wait_pending_cancel },
	{ "futex_wait_mask_select", t_futex_wait_mask_select },
	{ "futex_waitv_pending_wake", t_futex_waitv_pending_wake },
	{ "futex_waitv_pending_cancel", t_futex_waitv_pending_cancel },
	{ "futex_wait_external_wake", t_futex_wait_external_wake },
	{ "futex_wait_close_pending", t_futex_wait_close_pending },
	{ "futex_waitv_bad_second_key", t_futex_waitv_bad_second_key },
	{ "futex_wait_wake_cancel_race", t_futex_wait_wake_cancel_race },
	{ "futex_wait_cancel_op_all", t_futex_wait_cancel_op_all },
	{ "futex_wait_link_timeout", t_futex_wait_link_timeout },
	{ "futex_fixed_flag_ignored", t_futex_fixed_flag_ignored },
	{ "futex_sqe_badfields", t_futex_sqe_badfields },
	{ "setup_2", t_setup_2 },
	{ "setup_3", t_setup_3 },
	{ "setup_7", t_setup_7 },
	{ "setup_16", t_setup_16 },
	{ "setup_17", t_setup_17 },
	{ "setup_64", t_setup_64 },
	{ "setup_1000", t_setup_1000 },
	{ "setup_4096", t_setup_4096 },
	{ "setup_32768", t_setup_32768 },
	{ "setup_resv0", t_setup_resv0 },
	{ "setup_resv2", t_setup_resv2 },
	{ "setup_flag_iopoll", t_setup_flag_iopoll },
	{ "setup_flag_sqpoll", t_setup_flag_sqpoll },
	{ "writev_badfd", t_writev_badfd },
	{ "readv_badfd", t_readv_badfd },
	{ "shutdown_badfd", t_shutdown_badfd },
	{ "listen_badfd", t_listen_badfd },
	{ "send_badfd", t_send_badfd },
	{ "recv_badfd", t_recv_badfd },
	{ "sync_file_range_badfd", t_sync_file_range_badfd },
	{ "readv_badptr", t_readv_badptr },
	{ "writev_badptr", t_writev_badptr },
	{ "openat_badpath", t_openat_badpath },
	{ "statx_badbuf", t_statx_badbuf },
	{ "mkdirat_eexist", t_mkdirat_eexist },
	{ "symlinkat_eexist", t_symlinkat_eexist },
	{ "renameat_enoent", t_renameat_enoent },
	{ "statx_enoent", t_statx_enoent },
	{ "unlinkat_isdir", t_unlinkat_isdir },
	{ "submit_partial", t_submit_partial },
	{ "submit_zero_queued", t_submit_zero_queued },
	{ "reap_no_wait", t_reap_no_wait },
	{ "cq_exactly_full", t_cq_exactly_full },
	{ "min_complete_two", t_min_complete_two },
	{ "sq_dropped_many", t_sq_dropped_many },
	{ "large_ring", t_large_ring },
	{ "link_chain5", t_link_chain5 },
	{ "link_fail_middle", t_link_fail_middle },
	{ "hardlink_all", t_hardlink_all },
	{ "cqe_skip_middle", t_cqe_skip_middle },
	{ "link_plus_independent", t_link_plus_independent },
	{ "two_timeouts_fire", t_two_timeouts_fire },
	{ "timeout_count5", t_timeout_count5 },
	{ "cancel_one_of_two", t_cancel_one_of_two },
	{ "cancel_all_three", t_cancel_all_three },
	{ "cancel_fd_identity", t_cancel_fd_identity },
	{ "cancel_fd_all", t_cancel_fd_all },
	{ "cancel_any", t_cancel_any },
	{ "cancel_op", t_cancel_op },
	{ "cancel_fd_userdata", t_cancel_fd_userdata },
	{ "cancel_fd_fixed", t_cancel_fd_fixed },
	{ "sync_cancel_userdata", t_sync_cancel_userdata },
	{ "sync_cancel_all_any", t_sync_cancel_all_any },
	{ "sync_cancel_fd_op", t_sync_cancel_fd_op },
	{ "sync_cancel_fixed", t_sync_cancel_fixed },
	{ "sync_cancel_invalid", t_sync_cancel_invalid },
	{ "file_alloc_range_invalid", t_file_alloc_range_invalid },
	{ "pipe_direct", t_pipe_direct },
	{ "close_options", t_close_options },
	{ "close_direct", t_close_direct },
	{ "open_direct_alloc_range", t_open_direct_alloc_range },
	{ "open_options", t_open_options },
	{ "open_direct_cloexec", t_open_direct_cloexec },
	{ "open_socket_direct_explicit", t_open_socket_direct_explicit },
	{ "openat2_direct", t_openat2_direct },
	{ "socket_direct_cloexec", t_socket_direct_cloexec },
	{ "accept_direct", t_accept_direct },
	{ "accept_direct_multishot", t_accept_direct_multishot },
	{ "timeout_remove_notfound", t_timeout_remove_notfound },
	{ "reg_files_sparse", t_reg_files_sparse },
	{ "reg_files_badfd", t_reg_files_badfd },
	{ "fixed_fsync", t_fixed_fsync },
	{ "files_update_oob", t_files_update_oob },
	{ "read_fixed_offset", t_read_fixed_offset },
	{ "read_fixed_boundary", t_read_fixed_boundary },
	{ "read_fixed_onepast", t_read_fixed_onepast },
	{ "reg_buffers_zero", t_reg_buffers_zero },
	{ "provided_two_groups", t_provided_two_groups },
	{ "provided_consume_all", t_provided_consume_all },
	{ "provided_remove_excess", t_provided_remove_excess },
	{ "provided_recv_select", t_provided_recv_select },
	{ "provided_readv_select", t_provided_readv_select },
	{ "provided_send_select", t_provided_send_select },
	{ "provided_recvmsg_select", t_provided_recvmsg_select },
	{ "opcode_65", t_opcode_65 },
	{ "opcode_100", t_opcode_100 },
	{ "opcode_200", t_opcode_200 },
	{ "opcode_255", t_opcode_255 },
	{ "uring_cmd_badfd", t_uring_cmd_badfd },
	{ "uring_cmd_socket", t_uring_cmd_socket },
	{ "uring_cmd_tcp_sockopt", t_uring_cmd_tcp_sockopt },
	{ "uring_cmd_passcred", t_uring_cmd_passcred },
	{ "uring_cmd_peercred", t_uring_cmd_peercred },
	{ "uring_cmd_pacing", t_uring_cmd_pacing },
	{ "uring_cmd_timestamps", t_uring_cmd_timestamps },
	{ "uring_cmd_linger", t_uring_cmd_linger },
	{ "uring_cmd_sock_timeouts", t_uring_cmd_sock_timeouts },
	{ "uring_cmd_udp", t_uring_cmd_udp },
	{ "uring_cmd_sockopt_matrix", t_uring_cmd_sockopt_matrix },
	{ "uring_cmd_fixed_file", t_uring_cmd_fixed_file },
	{ "uring_cmd_tcp", t_uring_cmd_tcp },
	{ "uring_cmd_sockopt_negative", t_uring_cmd_sockopt_negative },
	{ "uring_cmd128_requires_sqe128", t_uring_cmd128_requires_sqe128 },
	{ "uring_cmd128_socket", t_uring_cmd128_socket },
	{ "uring_cmd128_probe", t_uring_cmd128_probe },
	{ "uring_cmd_getsockname", t_uring_cmd_getsockname },
	{ "sqe_mixed_cmd128", t_sqe_mixed_cmd128 },
	{ "zcrx_register_nodev", t_zcrx_register_nodev },
	{ "zcrx_setup_requirements", t_zcrx_setup_requirements },
	{ "zcrx_recv_bounded", t_zcrx_recv_bounded },
	{ "zcrx_registration_negative", t_zcrx_registration_negative },
	{ "zcrx_privilege", t_zcrx_privilege },
	{ "zcrx_memory_protection", t_zcrx_memory_protection },
	{ "zcrx_copyout_rollback", t_zcrx_copyout_rollback },
	{ "zcrx_sqe_negative", t_zcrx_sqe_negative },
	{ "zcrx_refill_reuse", t_zcrx_refill_reuse },
	{ "zcrx_user_region", t_zcrx_user_region },
	{ "zcrx_multishot_cancel", t_zcrx_multishot_cancel },
	{ "zcrx_fixed_file", t_zcrx_fixed_file },
	{ "zcrx_multi_instance", t_zcrx_multi_instance },
	{ "zcrx_cqe_mixed", t_zcrx_cqe_mixed },
	{ "zcrx_ctrl_negative", t_zcrx_ctrl_negative },
	{ "zcrx_close_teardown", t_zcrx_close_teardown },
	{ "zcrx_socket_negative", t_zcrx_socket_negative },
	{ "zcrx_peer_eof", t_zcrx_peer_eof },
	{ "zcrx_refill_corruption", t_zcrx_refill_corruption },
	{ "zcrx_pending_exit", t_zcrx_pending_exit },
	{ "zcrx_pending_close", t_zcrx_pending_close },
	{ "negotiation_probe", t_negotiation_probe },
	{ "waitid_badargs", t_waitid_badargs },
	{ "futex_waitv_badargs", t_futex_waitv_badargs },
	{ "ioprio_send_zc_fixed", t_ioprio_send_zc_fixed },
	{ "ioprio_send_zc_fixed_vectorized", t_ioprio_send_zc_fixed_vectorized },
	{ "ioprio_sendmsg_zc_fixed", t_ioprio_sendmsg_zc_fixed },
	{ "ioprio_send_zc_fixed_invalid", t_ioprio_send_zc_fixed_invalid },
	{ "ioprio_sendmsg_zc_fixed_badmsg", t_ioprio_sendmsg_zc_fixed_badmsg },
	{ "ioprio_sendmsg_zc_fixed_iovlen", t_ioprio_sendmsg_zc_fixed_iovlen },
	{ "ioprio_send_zc_fixed_zero_vector", t_ioprio_send_zc_fixed_zero_vector },
	{ "ioprio_send_vectorized", t_ioprio_send_vectorized },
	{ "ioprio_send_zc_vectorized", t_ioprio_send_zc_vectorized },
	{ "ioprio_send_vectorized_badptr", t_ioprio_send_vectorized_badptr },
	{ "ioprio_send_zc_report", t_ioprio_send_zc_report },
	{ "ioprio_sendmsg_zc_report", t_ioprio_sendmsg_zc_report },
	{ "ioprio_send_zc_invalid", t_ioprio_send_zc_invalid },
	{ "ioprio_accept_multishot", t_ioprio_accept_multishot },
	{ "ioprio_accept_dontwait", t_ioprio_accept_dontwait },
	{ "ioprio_accept_invalid", t_ioprio_accept_invalid },
	{ "pbuf_ring_mmap", t_pbuf_ring_mmap },
	{ "pbuf_ring_user_wrap", t_pbuf_ring_user_wrap },
	{ "pbuf_ring_retry_cancel", t_pbuf_ring_retry_cancel },
	{ "pbuf_ring_incremental", t_pbuf_ring_incremental },
	{ "pbuf_ring_incremental_user", t_pbuf_ring_incremental_user },
	{ "pbuf_ring_incremental_multishot", t_pbuf_ring_incremental_multishot },
	{ "pbuf_ring_incremental_bundle", t_pbuf_ring_incremental_bundle },
	{ "pbuf_ring_invalid", t_pbuf_ring_invalid },
	{ "pbuf_recv_bundle_multibuf", t_pbuf_recv_bundle_multibuf },
	{ "pbuf_recv_bundle_multishot", t_pbuf_recv_bundle_multishot },
	{ "pbuf_recv_bundle_empty_recover", t_pbuf_recv_bundle_empty_recover },
	{ "ioprio_send_bundle", t_ioprio_send_bundle },
	{ "ioprio_recv_bundle", t_ioprio_recv_bundle },
	{ "ioprio_recv_bundle_limit", t_ioprio_recv_bundle_limit },
	{ "ioprio_recv_bundle_multishot", t_ioprio_recv_bundle_multishot },
	{ "ioprio_bundle_retry_reuse", t_ioprio_bundle_retry_reuse },
	{ "ioprio_bundle_invalid", t_ioprio_bundle_invalid },
	{ "provided_retry_capacity", t_provided_retry_capacity },
	{ "ioprio_recv_multishot", t_ioprio_recv_multishot },
	{ "ioprio_recvmsg_multishot", t_ioprio_recvmsg_multishot },
	{ "ioprio_recvmsg_multishot_invalid", t_ioprio_recvmsg_multishot_invalid },
	{ "ioprio_recv_multishot_limit", t_ioprio_recv_multishot_limit },
	{ "ioprio_recv_multishot_invalid", t_ioprio_recv_multishot_invalid },
	{ "read_multishot_unsup", t_read_multishot_unsup },
	{ "read_multishot", t_read_multishot },
	{ "read_multishot_needs_bufsel", t_read_multishot_needs_bufsel },
	{ "stress_1000", t_stress_1000 },
	{ "stress_timeouts", t_stress_timeouts },
	{ "stress_fixed", t_stress_fixed },
	{ "waitid_echild", t_waitid_echild },
	{ "waitid_sqe_badfields", t_waitid_sqe_badfields },
	{ "waitid_lifecycle", t_waitid_lifecycle },
	{ "waitid_pidfd", t_waitid_pidfd },
	{ "waitid_stop_continue", t_waitid_stop_continue },
	{ "waitid_pending_exit", t_waitid_pending_exit },
	{ "waitid_null_info", t_waitid_null_info },
	{ "waitid_exit_cancel_race", t_waitid_exit_cancel_race },
	{ "waitid_pending_pidfd_close", t_waitid_pending_pidfd_close },
	{ "waitid_close_pending", t_waitid_close_pending },
	{ "waitid_cancel_op_all", t_waitid_cancel_op_all },
	{ "waitid_link_timeout", t_waitid_link_timeout },
	{ "waitid_cancel_pending", t_waitid_cancel_pending },
	{ "futex_waitv_eagain", t_futex_waitv_eagain },
	{ "ioprio_net_invalid", t_ioprio_net_invalid },
	{ "ioprio_poll_first_recv", t_ioprio_poll_first_recv },
	{ "ioprio_poll_first_send", t_ioprio_poll_first_send },
	{ "ioprio_poll_first_cancel", t_ioprio_poll_first_cancel },
	{ "poll_add_ready", t_poll_add_ready },
	{ "poll_add_deferred", t_poll_add_deferred },
	{ "poll_remove", t_poll_remove },
	{ "poll_remove_notfound", t_poll_remove_notfound },
	{ "poll_update_userdata", t_poll_update_userdata },
	{ "poll_update_events", t_poll_update_events },
	{ "poll_update_combined", t_poll_update_combined },
	{ "poll_update_invalid", t_poll_update_invalid },
	{ "poll_multishot", t_poll_multishot },
	{ "poll_close_reuse", t_poll_close_reuse },
	{ "poll_cancel_closed", t_poll_cancel_closed },
	{ "poll_ring_self_close", t_poll_ring_self_close },
	{ "poll_ring_self_cancel", t_poll_ring_self_cancel },
	{ "poll_ring_cross_reuse", t_poll_ring_cross_reuse },
	{ "poll_ring_update_reuse", t_poll_ring_update_reuse },
	{ "poll_ring_multishot_terminal_reuse", t_poll_ring_multishot_terminal_reuse },
	{ "poll_ring_update_multi_terminal_reuse", t_poll_ring_update_multi_terminal_reuse },
	{ "poll_ring_cross_last_close", t_poll_ring_cross_last_close },
	{ "poll_ring_fd_cancel", t_poll_ring_fd_cancel },
	{ "poll_ring_mutual_close", t_poll_ring_mutual_close },
	{ "poll_badfd", t_poll_badfd },
	{ "poll_probe", t_poll_probe },
	{ "register_eventfd", t_register_eventfd },
	{ "fastpoll_recv", t_fastpoll_recv },
	{ "fastpoll_two_recv", t_fastpoll_two_recv },
	{ "fastpoll_read_sock", t_fastpoll_read_sock },
	{ "fastpoll_recv_linked", t_fastpoll_recv_linked },
	{ "fastpoll_recv_cancel", t_fastpoll_recv_cancel },
	{ "fastpoll_close_reuse", t_fastpoll_close_reuse },
	{ "fastpoll_many", t_fastpoll_many },
	{ "write_read_1", t_write_read_1 },
	{ "write_read_odd", t_write_read_odd },
	{ "read_partial", t_read_partial },
	{ "huge_len_read", t_huge_len_read },
	{ "ftruncate_shrink", t_ftruncate_shrink },
	{ "fadvise_values", t_fadvise_values },
	{ "openat_excl", t_openat_excl },
	{ "openat_trunc", t_openat_trunc },
	{ "renameat_replace", t_renameat_replace },
	{ "linkat_same_ino", t_linkat_same_ino },
	{ "statx_fields", t_statx_fields },
	{ "statx_options", t_statx_options },
	{ "path_ops_options", t_path_ops_options },
	{ "fixed_writev", t_fixed_writev },
	{ "reg_buffers_multi", t_reg_buffers_multi },
	{ "provided_bid_order", t_provided_bid_order },
	{ "cancel_all_none", t_cancel_all_none },
	{ "link_all_skip", t_link_all_skip },
	{ "link_async_rw", t_link_async_rw },
	{ "garbage_sweep", t_garbage_sweep },
	{ "sq_index_boundary", t_sq_index_boundary },
	{ "probe_nr0", t_probe_nr0 },
	{ "probe_nr256", t_probe_nr256 },
	{ "enter_submit_huge", t_enter_submit_huge },
	{ "double_close", t_double_close },
	{ "stress_5000", t_stress_5000 },
	{ "stress_mixed_rw", t_stress_mixed_rw },
	{ "stress_reg_cycle", t_stress_reg_cycle },
	{ "stress_open_close", t_stress_open_close },
	{ "timeout_rel", t_timeout_rel },
	{ "timeout_zero", t_timeout_zero },
	{ "timeout_abs", t_timeout_abs },
	{ "timeout_etime_success", t_timeout_etime_success },
	{ "timeout_count", t_timeout_count },
	{ "timeout_multishot_finite", t_timeout_multishot_finite },
	{ "timeout_multishot_cancel", t_timeout_multishot_cancel },
	{ "timeout_update", t_timeout_update },
	{ "timeout_update_absolute", t_timeout_update_absolute },
	{ "link_timeout_update", t_link_timeout_update },
	{ "timeout_update_invalid", t_timeout_update_invalid },
	{ "timeout_immediate_basic", t_timeout_immediate_basic },
	{ "timeout_immediate_invalid", t_timeout_immediate_invalid },
	{ "timeout_immediate_update", t_timeout_immediate_update },
	{ "timeout_immediate_link_multishot", t_timeout_immediate_link_multishot },
	{ "timeout_reserved_fields", t_timeout_reserved_fields },
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
	{ "cq_overflow_recover", t_cq_overflow_recover },
	{ "cq_overflow_bounded", t_cq_overflow_bounded },
	{ "stress_many", t_stress_many },
	{ "stress_rw", t_stress_rw },
};

static int
test(int argc, char **argv, char **envp __attribute__((unused)))
{

	return (run_subtests(argc, argv, subtests,
	    sizeof(subtests) / sizeof(subtests[0])));
}
