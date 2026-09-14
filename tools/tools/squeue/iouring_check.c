/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * iouring_check -- standalone conformance program for the LINUX io_uring
 * front-end of the shared squeue engine, the companion to squeue_check
 * (which drives the native squeue_* front-end).  The two front-ends share one
 * kernel engine; running both proves the engine is correct through each face.
 *
 * The Linux io_uring ABI is reachable only by a Linux-branded binary under the
 * Linuxulator, so unlike squeue_check this is a freestanding, statically
 * linked Linux/amd64 program with no libc: it makes raw Linux syscalls and
 * emits its own TAP.  Build it with a Linux target:
 *
 *	clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static \
 *	    -fno-stack-protector -fno-builtin -O2 -Wall -o iouring_check \
 *	    iouring_check.c
 *
 * Run it on a 5BSD host with the Linuxulator (linux64) loaded; it prints TAP
 * ("ok N - desc" / "not ok N", trailing "1..N") and exits 0 iff all passed.
 * A missing engine prints "1..0 # SKIP" and exits 0.
 */

typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

/* Linux/amd64 syscall numbers. */
#define	SYS_read		0
#define	SYS_write		1
#define	SYS_open		2
#define	SYS_close		3
#define	SYS_mmap		9
#define	SYS_munmap		11
#define	SYS_pwrite64		18
#define	SYS_socketpair		53
#define	SYS_exit_group		231
#define	SYS_unlink		87
#define	SYS_io_uring_setup	425
#define	SYS_io_uring_enter	426
#define	SYS_io_uring_register	427

/* Linux errno values (the front-end translates BSD -> Linux for completions). */
#define	LX_EBADF	9
#define	LX_EINVAL	22
#define	LX_ENOSYS	38
#define	LX_ETIME	62	/* io_uring timer expiry (Linux ETIME) */
#define	LX_ECANCELED	125

#define	PROT_READ	0x1
#define	PROT_WRITE	0x2
#define	MAP_SHARED	0x1
#define	O_RDWR		2
#define	O_CREAT		0100
#define	O_EXCL		0200
#define	O_TRUNC		01000
#define	AF_UNIX		1
#define	SOCK_STREAM	1
#define	POLLIN		0x0001

#define	IORING_OFF_SQ_RING	0ULL
#define	IORING_OFF_SQES		0x10000000ULL
#define	IORING_ENTER_GETEVENTS	1
#define	IORING_SETUP_CQSIZE	(1U << 3)
#define	IORING_SETUP_CLAMP	(1U << 4)

#define	OP_NOP		0
#define	OP_POLL_ADD	6
#define	OP_TIMEOUT	11
#define	OP_READ		22
#define	OP_WRITE	23

#define	IOSQE_FIXED_FILE	(1U << 0)
#define	IOSQE_IO_LINK		(1U << 2)
#define	IOSQE_IO_HARDLINK	(1U << 3)
#define	IOSQE_ASYNC		(1U << 4)

#define	SQ_MAX_ENTRIES	32768

/* ---- freestanding syscall + libc-lite ---- */
static long
call(long nr, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long result;

	__asm__ volatile("syscall" : "=a"(result) :
	    "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) :
	    "rcx", "r11", "memory");
	return (result);
}
#define	sys1(n, a)		call(n, (long)(a), 0, 0, 0, 0, 0)
#define	sys2(n, a, b)		call(n, (long)(a), (long)(b), 0, 0, 0, 0)
#define	sys3(n, a, b, c)	call(n, (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define	sys4(n, a, b, c, d)	call(n, (long)(a), (long)(b), (long)(c), \
    (long)(d), 0, 0)
#define	sys6(n, a, b, c, d, e, f) call(n, (long)(a), (long)(b), (long)(c), \
    (long)(d), (long)(e), (long)(f))

static void
xmemset(void *p, int v, unsigned long n)
{
	volatile char *c = p;

	while (n-- > 0)
		*c++ = (char)v;
}

static int
xmemcmp(const void *a, const void *b, unsigned long n)
{
	const unsigned char *x = a, *y = b;

	for (; n > 0; n--, x++, y++)
		if (*x != *y)
			return (*x - *y);
	return (0);
}

static unsigned long
xstrlen(const char *s)
{
	unsigned long n = 0;

	while (s[n] != '\0')
		n++;
	return (n);
}

/* ---- TAP printer (stdout via write) ---- */
static int tap_n;
static int tap_failed;

static void
pr(const char *s)
{
	(void)sys3(SYS_write, 1, s, xstrlen(s));
}

static void
prnum(long v)
{
	char buf[24];
	int i = 23, neg = 0;
	unsigned long u;

	if (v < 0) {
		neg = 1;
		u = (unsigned long)-v;
	} else
		u = (unsigned long)v;
	buf[i] = '\0';
	do {
		buf[--i] = (char)('0' + u % 10);
		u /= 10;
	} while (u != 0);
	if (neg)
		buf[--i] = '-';
	pr(&buf[i]);
}

static void
ok(int cond, const char *desc)
{
	tap_n++;
	pr(cond ? "ok " : "not ok ");
	prnum(tap_n);
	pr(" - ");
	pr(desc);
	pr("\n");
	if (!cond)
		tap_failed++;
}

/* ---- io_uring wire structs (shared ABI) ---- */
struct sqe {
	u8 opcode; u8 flags; u16 ioprio; int fd;
	u64 off; u64 addr; u32 len; u32 rw_flags; u64 user_data;
	u16 buf_index; u16 personality; int splice_fd_in; u64 pad2[2];
};
struct cqe { u64 user_data; int res; u32 flags; };
struct sqoff { u32 head, tail, ring_mask, ring_entries, flags, dropped, array,
    resv1; u64 user_addr; };
struct cqoff { u32 head, tail, ring_mask, ring_entries, overflow, cqes, flags,
    resv1; u64 user_addr; };
struct params {
	u32 sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle,
	    features, wq_fd, resv[3];
	struct sqoff sq_off;
	struct cqoff cq_off;
};
struct kts { long long tv_sec, tv_nsec; };

struct ring {
	int fd;
	char *base;
	unsigned long basesz;
	struct sqe *sqes;
	unsigned long sqesz;
	volatile u32 *sq_tail, *sq_array, *cq_head, *cq_tail;
	struct cqe *cqes;
	u32 sqmask, cqmask, sqi, cqi;
};

static long
setup(u32 entries, struct params *p)
{
	return (call(SYS_io_uring_setup, entries, (long)p, 0, 0, 0, 0));
}

static int
ring_open_flags(struct ring *r, u32 entries, u32 flags, u32 want_cq)
{
	struct params p;
	long fd, m;
	u32 ringsz;

	xmemset(r, 0, sizeof(*r));
	xmemset(&p, 0, sizeof(p));
	p.flags = flags;
	p.cq_entries = want_cq;
	fd = setup(entries, &p);
	if (fd < 0)
		return ((int)fd);
	r->fd = (int)fd;
	ringsz = p.sq_off.array + p.sq_entries * sizeof(u32);
	if (p.cq_off.cqes + p.cq_entries * sizeof(struct cqe) > ringsz)
		ringsz = p.cq_off.cqes + p.cq_entries * sizeof(struct cqe);
	r->basesz = ringsz;
	m = call(SYS_mmap, 0, ringsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
	    IORING_OFF_SQ_RING);
	if (m < 0)
		return ((int)m);
	r->base = (char *)m;
	r->sqesz = p.sq_entries * sizeof(struct sqe);
	m = call(SYS_mmap, 0, r->sqesz, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
	    IORING_OFF_SQES);
	if (m < 0)
		return ((int)m);
	r->sqes = (struct sqe *)m;
	r->sq_tail = (volatile u32 *)(void *)(r->base + p.sq_off.tail);
	r->sq_array = (volatile u32 *)(void *)(r->base + p.sq_off.array);
	r->cq_head = (volatile u32 *)(void *)(r->base + p.cq_off.head);
	r->cq_tail = (volatile u32 *)(void *)(r->base + p.cq_off.cqes -
	    (p.cq_off.cqes - p.cq_off.tail));
	r->cq_tail = (volatile u32 *)(void *)(r->base + p.cq_off.tail);
	r->cqes = (struct cqe *)(void *)(r->base + p.cq_off.cqes);
	r->sqmask = p.sq_entries - 1;
	r->cqmask = p.cq_entries - 1;
	r->sqi = r->cqi = 0;
	return (0);
}

static int
ring_open(struct ring *r, u32 entries)
{
	return (ring_open_flags(r, entries, 0, 0));
}

static void
ring_close(struct ring *r)
{
	if (r->sqes != 0)
		(void)sys2(SYS_munmap, r->sqes, r->sqesz);
	if (r->base != 0)
		(void)sys2(SYS_munmap, r->base, r->basesz);
	if (r->fd >= 0)
		(void)sys1(SYS_close, r->fd);
	r->fd = -1;
}

static void
push(struct ring *r, u8 op, u8 flags, int fd, void *addr, u32 len, u64 off,
    u32 misc, u64 ud)
{
	u32 slot = r->sqi & r->sqmask;
	struct sqe *s = &r->sqes[slot];

	xmemset(s, 0, sizeof(*s));
	s->opcode = op;
	s->flags = flags;
	s->fd = fd;
	s->addr = (u64)(unsigned long)addr;
	s->len = len;
	s->off = off;
	s->rw_flags = misc;		/* also poll32_events (union) */
	s->user_data = ud;
	r->sq_array[r->sqi & r->sqmask] = slot;
	r->sqi++;
	__atomic_store_n(r->sq_tail, r->sqi, __ATOMIC_RELEASE);
}

static long
enter(struct ring *r, u32 to_submit, u32 min_complete, u32 flags)
{
	return (call(SYS_io_uring_enter, r->fd, to_submit, min_complete, flags,
	    0, 0));
}

struct cqrec { u64 ud; int res; };

static u32
reap(struct ring *r, struct cqrec *out, u32 max)
{
	u32 tail, n = 0;

	tail = __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE);
	while (r->cqi != tail) {
		if (out != 0 && n < max) {
			out[n].ud = r->cqes[r->cqi & r->cqmask].user_data;
			out[n].res = r->cqes[r->cqi & r->cqmask].res;
		}
		n++;
		r->cqi++;
	}
	__atomic_store_n(r->cq_head, r->cqi, __ATOMIC_RELEASE);
	return (n);
}

static int
one(struct ring *r, u8 op, u8 flags, int fd, void *addr, u32 len, u64 off,
    u32 misc, u64 ud)
{
	struct cqrec c;

	push(r, op, flags, fd, addr, len, off, misc, ud);
	if (enter(r, 1, 1, IORING_ENTER_GETEVENTS) != 1)
		return (-100000);
	if (reap(r, &c, 1) != 1 || c.ud != ud)
		return (-100001);
	return (c.res);
}

static int
find_res(const struct cqrec *r, u32 n, u64 ud, int *res)
{
	u32 i;

	for (i = 0; i < n; i++)
		if (r[i].ud == ud) {
			*res = r[i].res;
			return (1);
		}
	return (0);
}

static int
mkfile(const char *path, const char *data, u32 len)
{
	int fd;

	(void)sys1(SYS_unlink, path);
	fd = (int)sys3(SYS_open, path, O_RDWR | O_CREAT | O_EXCL | O_TRUNC,
	    0600);
	if (fd < 0)
		return (fd);
	if (len > 0 && call(SYS_pwrite64, fd, (long)data, len, 0, 0, 0) !=
	    (long)len) {
		(void)sys1(SYS_close, fd);
		return (-1);
	}
	return (fd);
}

/* ---- checks ---- */
static void
t_functional(void)
{
	struct ring r;
	char wbuf[16], rbuf[16];
	int fd, res;

	if (ring_open(&r, 8) != 0) {
		ok(0, "ring setup + mmap");
		return;
	}
	ok(1, "ring setup + mmap");
	ok(one(&r, OP_NOP, 0, -1, 0, 0, 0, 0, 0x1) == 0, "NOP round-trip");

	xmemset(wbuf, 0, sizeof(wbuf));
	wbuf[0] = 'i'; wbuf[1] = 'o'; wbuf[2] = 'u'; wbuf[3] = 'r';
	wbuf[4] = 'i'; wbuf[5] = 'n'; wbuf[6] = 'g';
	fd = mkfile("/tmp/iouring_check.tmp", 0, 0);
	res = one(&r, OP_WRITE, 0, fd, wbuf, 7, 0, 0, 0x2);
	ok(res == 7, "WRITE returns byte count");
	xmemset(rbuf, 0, sizeof(rbuf));
	res = one(&r, OP_READ, 0, fd, rbuf, 7, 0, 0, 0x3);
	ok(res == 7 && xmemcmp(rbuf, wbuf, 7) == 0, "READ returns data");

	ok(one(&r, OP_READ, 0, 9999, rbuf, 4, 0, 0, 0x4) == -LX_EBADF,
	    "bad-fd READ -> Linux -EBADF");
	{
		struct kts ts = { 0, 20000000 };
		/* io_uring reports a timer expiry as -ETIME, not -ETIMEDOUT. */
		ok(one(&r, OP_TIMEOUT, 0, -1, &ts, 0, 0, 0, 0x5) == -LX_ETIME,
		    "TIMEOUT -> Linux -ETIME");
	}
	/* IOSQE_ASYNC worker-pool round-trip. */
	ok(one(&r, OP_WRITE, IOSQE_ASYNC, fd, wbuf, 7, 0, 0, 0x6) == 7,
	    "IOSQE_ASYNC WRITE round-trip");
	xmemset(rbuf, 0, sizeof(rbuf));
	res = one(&r, OP_READ, IOSQE_ASYNC, fd, rbuf, 7, 0, 0, 0x7);
	ok(res == 7 && xmemcmp(rbuf, wbuf, 7) == 0,
	    "IOSQE_ASYNC READ round-trip");

	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_unlink, (long)"/tmp/iouring_check.tmp");
	ring_close(&r);
}

static void
t_cqsize(void)
{
	struct params p;
	long fd;

	xmemset(&p, 0, sizeof(p));
	fd = setup(8, &p);
	ok(fd >= 0 && p.sq_entries == 8 && p.cq_entries == 16,
	    "default CQ = 2x SQ");
	if (fd >= 0)
		(void)sys1(SYS_close, fd);

	xmemset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_CQSIZE;
	p.cq_entries = 64;
	fd = setup(4, &p);
	ok(fd >= 0 && p.sq_entries == 4 && p.cq_entries == 64,
	    "CQSIZE sizes CQ independently");
	if (fd >= 0)
		(void)sys1(SYS_close, fd);

	xmemset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_CQSIZE;
	p.cq_entries = 100;
	fd = setup(8, &p);
	ok(fd >= 0 && p.cq_entries == 128, "CQSIZE rounds CQ up to pow2");
	if (fd >= 0)
		(void)sys1(SYS_close, fd);

	xmemset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_CQSIZE;
	p.cq_entries = 0;
	ok(setup(8, &p) == -LX_EINVAL, "CQSIZE with cq_entries=0 -> -EINVAL");

	xmemset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_CLAMP;
	fd = setup(SQ_MAX_ENTRIES + 1, &p);
	ok(fd >= 0 && p.sq_entries == SQ_MAX_ENTRIES &&
	    p.cq_entries == SQ_MAX_ENTRIES * 2, "CLAMP clamps over-cap SQ");
	if (fd >= 0)
		(void)sys1(SYS_close, fd);
}

static void
t_links(void)
{
	struct ring r;
	struct cqrec recs[4];
	char buf[8];
	u32 n;
	int fd, res;

	if (ring_open(&r, 8) != 0) {
		ok(0, "ring for link chains");
		return;
	}
	xmemset(buf, 'x', sizeof(buf));
	fd = mkfile("/tmp/iouring_check_l.tmp", buf, 7);

	push(&r, OP_READ, IOSQE_IO_LINK, 9999, buf, 4, 0, 0, 0x10);
	push(&r, OP_NOP, 0, -1, 0, 0, 0, 0, 0x11);
	(void)enter(&r, 2, 2, IORING_ENTER_GETEVENTS);
	n = reap(&r, recs, 4);
	ok(find_res(recs, n, 0x10, &res) && res == -LX_EBADF &&
	    find_res(recs, n, 0x11, &res) && res == -LX_ECANCELED,
	    "soft IO_LINK: failed head cancels successor");

	push(&r, OP_READ, IOSQE_IO_HARDLINK, 9999, buf, 4, 0, 0, 0x20);
	push(&r, OP_NOP, 0, -1, 0, 0, 0, 0, 0x21);
	(void)enter(&r, 2, 2, IORING_ENTER_GETEVENTS);
	n = reap(&r, recs, 4);
	ok(find_res(recs, n, 0x20, &res) && res == -LX_EBADF &&
	    find_res(recs, n, 0x21, &res) && res == 0,
	    "hard IO_HARDLINK: failed head keeps successor");

	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_unlink, (long)"/tmp/iouring_check_l.tmp");
	ring_close(&r);
}

/* poll-wait + async: the poll-path lost-wakeup regression, Linux side. */
static void
t_poll_wait(int iters)
{
	struct ring r;
	char buf[64];
	int i, fd, sv[2], bad = 0;

	fd = mkfile("/tmp/iouring_check_pw.tmp", 0, 0);
	xmemset(buf, 'z', sizeof(buf));
	(void)call(SYS_pwrite64, fd, (long)buf, sizeof(buf), 0, 0, 0);
	for (i = 0; i < iters && !bad; i++) {
		if (call(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (long)sv, 0,
		    0) != 0) {
			bad = 1;
			break;
		}
		if (ring_open(&r, 8) != 0) {
			(void)sys1(SYS_close, sv[0]);
			(void)sys1(SYS_close, sv[1]);
			bad = 1;
			break;
		}
		push(&r, OP_POLL_ADD, 0, sv[1], 0, 0, 0, POLLIN, 0x1);
		push(&r, OP_READ, IOSQE_ASYNC, fd, buf, sizeof(buf), 0, 0, 0x2);
		if (enter(&r, 2, 1, IORING_ENTER_GETEVENTS) < 1 ||
		    reap(&r, 0, 0) < 1)
			bad = 1;
		ring_close(&r);
		(void)sys1(SYS_close, sv[0]);
		(void)sys1(SYS_close, sv[1]);
	}
	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_unlink, (long)"/tmp/iouring_check_pw.tmp");
	ok(!bad, "poll-wait + async resolve does not hang");
}

static int
test(void)
{
	struct params p;

	/* Probe: no engine -> SKIP cleanly. */
	xmemset(&p, 0, sizeof(p));
	if (setup(0, &p) == -LX_ENOSYS) {
		pr("1..0 # SKIP io_uring not present (ENOSYS)\n");
		return (0);
	}

	t_functional();
	t_cqsize();
	t_links();
	t_poll_wait(50);

	pr("1..");
	prnum(tap_n);
	pr("\n");
	if (tap_failed > 0) {
		pr("# FAILED ");
		prnum(tap_failed);
		pr(" of ");
		prnum(tap_n);
		pr(" checks\n");
	} else {
		pr("# all checks passed\n");
	}
	return (tap_failed > 0 ? 1 : 0);
}

__attribute__((force_align_arg_pointer)) void
start_c(long *sp)
{
	(void)sp;
	(void)sys1(SYS_exit_group, test());
	__builtin_unreachable();
}

__asm__(
	".globl _start\n"
	"_start:\n"
	"	xor %rbp, %rbp\n"
	"	mov %rsp, %rdi\n"
	"	and $-16, %rsp\n"
	"	call start_c\n"
	"	hlt\n");
