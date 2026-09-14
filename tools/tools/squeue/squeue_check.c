/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * squeue_check -- a self-contained conformance and stress program for the
 * native 5BSD squeue (Shared Queue) io_uring-compatible engine.
 *
 * Unlike the in-tree ATF tests (tests/sys/kern/squeue_*), this is a single
 * standalone binary that depends only on installed public headers
 * (<sys/io_uring.h>, <sys/syscall.h>) and -lpthread.  It builds and runs on
 * any installed 5BSD system without the source tree or the kyua/ATF harness,
 * so it can be dropped into a package, a CI job, or run by hand.
 *
 * Output is TAP (Test Anything Protocol): one "ok N - desc" / "not ok N"
 * line per check, a trailing "1..N" plan, and a "# ..." diagnostic on
 * failure.  Exit status is 0 if every check passed, 1 otherwise, so it also
 * works as a plain pass/fail gate.  Feed it to prove(1) for a summary:
 *
 *	cc -O2 -Wall -o squeue_check squeue_check.c -lpthread
 *	prove -e ./squeue_check :::            # or just ./squeue_check
 *
 * Options:
 *	-v		verbose: also print a diagnostic for passing checks
 *	-i <n>		scale the stress/soak iteration counts by roughly n
 *	-q		quick: minimal iteration counts (smoke only)
 *
 * Requires root (registered files / capsicum / some sysctls) and amd64.
 */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/io_uring.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Public syscall numbers; fall back to the assigned values if the installed
 * <sys/syscall.h> predates them. */
#ifndef SYS_squeue_setup
#define	SYS_squeue_setup	636
#endif
#ifndef SYS_squeue_enter
#define	SYS_squeue_enter	637
#endif
#ifndef SYS_squeue_register
#define	SYS_squeue_register	638
#endif

#define	OP_NOP		0
#define	OP_POLL_ADD	6
#define	OP_TIMEOUT	11
#define	OP_READ		22
#define	OP_WRITE	23
#define	ENTER_GETEVENTS	1
#define	OFF_SQ_RING	0ULL
#define	OFF_SQES	0x10000000ULL
#define	REGISTER_FILES	2
#define	REGISTER_EVENTFD	4
#define	UNREGISTER_EVENTFD 5
#define	SQ_MAX_ENTRIES	32768
#define	POLLIN_BIT	0x0001

/* ---- TAP harness ---- */
static int tap_n;
static int tap_failed;
static int opt_verbose;

static void
ok(int cond, const char *fmt, ...)
{
	va_list ap;
	char desc[256];

	va_start(ap, fmt);
	vsnprintf(desc, sizeof(desc), fmt, ap);
	va_end(ap);
	tap_n++;
	printf("%sok %d - %s\n", cond ? "" : "not ", tap_n, desc);
	if (!cond)
		tap_failed++;
	fflush(stdout);
}

static void
diag(const char *fmt, ...)
{
	va_list ap;

	if (!opt_verbose)
		return;
	printf("# ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	fflush(stdout);
}

/* ---- minimal ring wrapper (public ABI only) ---- */
struct ring {
	int fd;
	char *base;
	size_t basesz;
	struct io_uring_sqe *sqes;
	size_t sqesz;
	volatile uint32_t *sq_tail, *sq_array, *cq_head, *cq_tail;
	struct io_uring_cqe *cqes;
	uint32_t sqmask, cqmask, sqi, cqi, cq_entries;
};

static long
sq_setup(uint32_t entries, struct io_uring_params *p)
{
	return (syscall(SYS_squeue_setup, entries, p));
}

static int
ring_open_flags(struct ring *r, uint32_t entries, uint32_t flags,
    uint32_t want_cq)
{
	struct io_uring_params p;
	long fd;
	uint32_t ringsz;

	memset(r, 0, sizeof(*r));
	memset(&p, 0, sizeof(p));
	p.flags = flags;
	p.cq_entries = want_cq;
	fd = sq_setup(entries, &p);
	if (fd < 0)
		return (-1);
	r->fd = (int)fd;
	ringsz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
	if (p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe) > ringsz)
		ringsz = p.cq_off.cqes +
		    p.cq_entries * sizeof(struct io_uring_cqe);
	r->basesz = ringsz;
	r->base = mmap(NULL, ringsz, PROT_READ | PROT_WRITE, MAP_SHARED, r->fd,
	    OFF_SQ_RING);
	if (r->base == MAP_FAILED)
		return (-1);
	r->sqesz = p.sq_entries * sizeof(struct io_uring_sqe);
	r->sqes = mmap(NULL, r->sqesz, PROT_READ | PROT_WRITE, MAP_SHARED,
	    r->fd, OFF_SQES);
	if (r->sqes == MAP_FAILED)
		return (-1);
	r->sq_tail = (volatile uint32_t *)(void *)(r->base + p.sq_off.tail);
	r->sq_array = (volatile uint32_t *)(void *)(r->base + p.sq_off.array);
	r->cq_head = (volatile uint32_t *)(void *)(r->base + p.cq_off.head);
	r->cq_tail = (volatile uint32_t *)(void *)(r->base + p.cq_off.tail);
	r->cqes = (struct io_uring_cqe *)(void *)(r->base + p.cq_off.cqes);
	r->sqmask = p.sq_entries - 1;
	r->cqmask = p.cq_entries - 1;
	r->cq_entries = p.cq_entries;
	r->sqi = r->cqi = 0;
	return (0);
}

static int
ring_open(struct ring *r, uint32_t entries)
{
	return (ring_open_flags(r, entries, 0, 0));
}

static void
ring_close(struct ring *r)
{
	if (r->sqes != NULL && r->sqes != MAP_FAILED)
		munmap(r->sqes, r->sqesz);
	if (r->base != NULL && r->base != MAP_FAILED)
		munmap(r->base, r->basesz);
	if (r->fd >= 0)
		syscall(SYS_close, r->fd);
	r->fd = -1;
}

static void
ring_push(struct ring *r, uint8_t op, uint8_t flags, int fd, void *addr,
    uint32_t len, uint64_t off, uint32_t misc, uint64_t ud)
{
	uint32_t slot = r->sqi & r->sqmask;
	struct io_uring_sqe *s = &r->sqes[slot];

	memset(s, 0, sizeof(*s));
	s->opcode = op;
	s->flags = flags;
	s->fd = fd;
	s->addr = (uint64_t)(uintptr_t)addr;
	s->len = len;
	s->off = off;
	s->rw_flags = misc;
	s->poll32_events = misc;
	s->user_data = ud;
	r->sq_array[r->sqi & r->sqmask] = slot;
	r->sqi++;
	__atomic_store_n(r->sq_tail, r->sqi, __ATOMIC_RELEASE);
}

static long
ring_enter(struct ring *r, uint32_t to_submit, uint32_t min_complete,
    uint32_t flags)
{
	return (syscall(SYS_squeue_enter, r->fd, to_submit, min_complete,
	    flags, NULL, 0));
}

struct cqrec { uint64_t ud; int32_t res; };

/* Snapshot all posted CQEs into out[] (up to max), then advance cq_head. */
static uint32_t
ring_reap(struct ring *r, struct cqrec *out, uint32_t max)
{
	uint32_t tail, n = 0;

	tail = __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE);
	while (r->cqi != tail) {
		if (out != NULL && n < max) {
			out[n].ud = r->cqes[r->cqi & r->cqmask].user_data;
			out[n].res = (int32_t)r->cqes[r->cqi & r->cqmask].res;
		}
		n++;
		r->cqi++;
	}
	__atomic_store_n(r->cq_head, r->cqi, __ATOMIC_RELEASE);
	return (n);
}

/* Submit one op and reap exactly one completion; return its res. */
static int
one(struct ring *r, uint8_t op, uint8_t flags, int fd, void *addr,
    uint32_t len, uint64_t off, uint32_t misc, uint64_t ud)
{
	struct cqrec c;

	ring_push(r, op, flags, fd, addr, len, off, misc, ud);
	if (ring_enter(r, 1, 1, ENTER_GETEVENTS) != 1)
		return (-100000);
	if (ring_reap(r, &c, 1) != 1 || c.ud != ud)
		return (-100001);
	return (c.res);
}

static int
find_res(const struct cqrec *r, uint32_t n, uint64_t ud, int32_t *res)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (r[i].ud == ud) {
			*res = r[i].res;
			return (1);
		}
	return (0);
}

static uint64_t
sysctl_u64(const char *name)
{
	uint64_t v = 0;
	size_t sz = sizeof(v);

	if (sysctlbyname(name, &v, &sz, NULL, 0) != 0)
		return ((uint64_t)-1);
	return (v);
}

/* ==== checks ==== */

static void
t_functional(void)
{
	struct ring r;
	char wbuf[16], rbuf[16];
	int fd, res;

	if (ring_open(&r, 8) != 0) {
		ok(0, "ring setup + mmap (errno %d)", errno);
		return;
	}
	ok(1, "ring setup + mmap");

	ok(one(&r, OP_NOP, 0, -1, NULL, 0, 0, 0, 0x1) == 0, "NOP round-trip");

	(void)unlink("/tmp/squeue_check.tmp");
	fd = open("/tmp/squeue_check.tmp", O_RDWR | O_CREAT | O_EXCL, 0600);
	memcpy(wbuf, "squeue!", 7);
	res = one(&r, OP_WRITE, 0, fd, wbuf, 7, 0, 0, 0x2);
	ok(res == 7, "WRITE returns byte count (got %d)", res);
	memset(rbuf, 0, sizeof(rbuf));
	res = one(&r, OP_READ, 0, fd, rbuf, 7, 0, 0, 0x3);
	ok(res == 7 && memcmp(rbuf, "squeue!", 7) == 0, "READ returns data");

	ok(one(&r, OP_READ, 0, 9999, rbuf, 4, 0, 0, 0x4) == -EBADF,
	    "bad-fd READ -> -EBADF");

	{
		struct { int64_t s, ns; } ts = { 0, 20000000 };
		ok(one(&r, OP_TIMEOUT, 0, -1, &ts, 0, 0, 0, 0x5) == -ETIMEDOUT,
		    "TIMEOUT -> -ETIMEDOUT");
	}

	/* IOSQE_ASYNC worker-pool round-trip. */
	memcpy(wbuf, "async5B", 7);
	ok(one(&r, OP_WRITE, IOSQE_ASYNC, fd, wbuf, 7, 0, 0, 0x6) == 7,
	    "IOSQE_ASYNC WRITE round-trip");
	memset(rbuf, 0, sizeof(rbuf));
	res = one(&r, OP_READ, IOSQE_ASYNC, fd, rbuf, 7, 0, 0, 0x7);
	ok(res == 7 && memcmp(rbuf, "async5B", 7) == 0,
	    "IOSQE_ASYNC READ round-trip");

	/* Negative-offset positioned async op must be rejected, not panic. */
	ok(one(&r, OP_READ, IOSQE_ASYNC, fd, rbuf, 4, 0x8000000000000000ULL, 0,
	    0x8) == -EINVAL, "negative-offset async op -> -EINVAL");

	(void)close(fd);
	(void)unlink("/tmp/squeue_check.tmp");
	ring_close(&r);
}

static void
t_kqueue_source(void)
{
	struct ring r;
	struct kevent kev;
	struct timespec zero = { 0, 0 };
	int kq, n;

	if (ring_open(&r, 8) != 0) {
		ok(0, "ring for kqueue source");
		return;
	}
	kq = kqueue();
	EV_SET(&kev, r.fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) != 0) {
		ok(0, "register ring with kqueue (errno %d)", errno);
		close(kq);
		ring_close(&r);
		return;
	}
	ok(kevent(kq, NULL, 0, &kev, 1, &zero) == 0, "ring not readable idle");
	/* submit a NOP without reaping: a completion becomes ready */
	ring_push(&r, OP_NOP, 0, -1, NULL, 0, 0, 0, 0x9);
	(void)ring_enter(&r, 1, 0, 0);
	n = kevent(kq, NULL, 0, &kev, 1, &zero);
	ok(n == 1 && (long)kev.data >= 1, "ring readable with pending CQE");
	(void)ring_reap(&r, NULL, 0);
	ok(kevent(kq, NULL, 0, &kev, 1, &zero) == 0, "ring quiet after reap");
	close(kq);
	ring_close(&r);
}

static void
t_eventfd(void)
{
	struct ring r;
	int efd, reg;
	uint64_t val = 0;

	if (ring_open(&r, 8) != 0) {
		ok(0, "ring for eventfd");
		return;
	}
	efd = eventfd(0, EFD_NONBLOCK);
	reg = efd;
	if (syscall(SYS_squeue_register, r.fd, REGISTER_EVENTFD, &reg, 1) != 0) {
		ok(0, "REGISTER_EVENTFD (errno %d)", errno);
		close(efd);
		ring_close(&r);
		return;
	}
	(void)one(&r, OP_NOP, 0, -1, NULL, 0, 0, 0, 0xE);
	ok(read(efd, &val, sizeof(val)) == (ssize_t)sizeof(val) && val >= 1,
	    "eventfd signalled on completion");
	(void)syscall(SYS_squeue_register, r.fd, UNREGISTER_EVENTFD, NULL, 0);
	close(efd);
	ring_close(&r);
}

static void
t_cqsize(void)
{
	struct io_uring_params p;
	long fd;

	/* default: cq = 2 * sq */
	memset(&p, 0, sizeof(p));
	fd = sq_setup(8, &p);
	ok(fd >= 0 && p.sq_entries == 8 && p.cq_entries == 16,
	    "default CQ = 2x SQ");
	if (fd >= 0)
		close((int)fd);

	/* CQSIZE explicit */
	memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_CQSIZE;
	p.cq_entries = 64;
	fd = sq_setup(4, &p);
	ok(fd >= 0 && p.sq_entries == 4 && p.cq_entries == 64,
	    "CQSIZE sizes CQ independently");
	if (fd >= 0)
		close((int)fd);

	/* CQSIZE non-pow2 rounds up */
	memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_CQSIZE;
	p.cq_entries = 100;
	fd = sq_setup(8, &p);
	ok(fd >= 0 && p.cq_entries == 128, "CQSIZE rounds CQ up to pow2");
	if (fd >= 0)
		close((int)fd);

	/* CQSIZE == 0 invalid */
	memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_CQSIZE;
	p.cq_entries = 0;
	ok(sq_setup(8, &p) < 0, "CQSIZE with cq_entries=0 rejected");

	/* CQSIZE < SQ invalid */
	memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_CQSIZE;
	p.cq_entries = 4;
	ok(sq_setup(16, &p) < 0, "CQSIZE < SQ rejected");

	/* CLAMP clamps an over-cap SQ */
	memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_CLAMP;
	fd = sq_setup(SQ_MAX_ENTRIES + 1, &p);
	ok(fd >= 0 && p.sq_entries == SQ_MAX_ENTRIES &&
	    p.cq_entries == SQ_MAX_ENTRIES * 2, "CLAMP clamps over-cap SQ");
	if (fd >= 0)
		close((int)fd);

	/* over-cap without CLAMP is an error */
	memset(&p, 0, sizeof(p));
	ok(sq_setup(SQ_MAX_ENTRIES + 1, &p) < 0, "over-cap SQ without CLAMP");
}

static void
t_links(void)
{
	struct ring r;
	struct cqrec recs[4];
	char buf[8] = "link5B!";
	uint32_t n;
	int fd;
	int32_t res;

	if (ring_open(&r, 8) != 0) {
		ok(0, "ring for link chains");
		return;
	}
	(void)unlink("/tmp/squeue_check_l.tmp");
	fd = open("/tmp/squeue_check_l.tmp", O_RDWR | O_CREAT | O_EXCL, 0600);
	(void)pwrite(fd, buf, 7, 0);

	/* Soft link: failed head cancels the successor (-ECANCELED). */
	ring_push(&r, OP_READ, IOSQE_IO_LINK, 9999, buf, 4, 0, 0, 0x10);
	ring_push(&r, OP_NOP, 0, -1, NULL, 0, 0, 0, 0x11);
	(void)ring_enter(&r, 2, 2, ENTER_GETEVENTS);
	n = ring_reap(&r, recs, 4);
	ok(find_res(recs, n, 0x10, &res) && res == -EBADF &&
	    find_res(recs, n, 0x11, &res) && res == -ECANCELED,
	    "soft IO_LINK: failed head cancels successor");

	/* Hard link: failed head does NOT cancel the successor. */
	ring_push(&r, OP_READ, IOSQE_IO_HARDLINK, 9999, buf, 4, 0, 0, 0x20);
	ring_push(&r, OP_NOP, 0, -1, NULL, 0, 0, 0, 0x21);
	(void)ring_enter(&r, 2, 2, ENTER_GETEVENTS);
	n = ring_reap(&r, recs, 4);
	ok(find_res(recs, n, 0x20, &res) && res == -EBADF &&
	    find_res(recs, n, 0x21, &res) && res == 0,
	    "hard IO_HARDLINK: failed head keeps successor");

	(void)close(fd);
	(void)unlink("/tmp/squeue_check_l.tmp");
	ring_close(&r);
}

static void
t_leak(int rings)
{
	struct ring r;
	u_long before, after;
	int i, tries;

	before = sysctl_u64("kern.squeue.wired_pages");
	for (i = 0; i < rings; i++) {
		uint32_t ent = 1U << (1 + (i % 6));
		uint32_t flags = (i % 3 == 0) ? IORING_SETUP_CQSIZE : 0;
		uint32_t wantcq = flags ? ent * 4 : 0;

		if (ring_open_flags(&r, ent, flags, wantcq) != 0) {
			ok(0, "ring lifecycle open (iter %d, errno %d)", i,
			    errno);
			return;
		}
		(void)one(&r, OP_NOP, 0, -1, NULL, 0, 0, 0, 0x1);
		ring_close(&r);
	}
	if (before == (u_long)-1) {
		ok(1, "ring lifecycle churn (%d rings; wired_pages n/a)",
		    rings);
		return;
	}
	after = sysctl_u64("kern.squeue.wired_pages");
	for (tries = 0; tries < 100 && after > before; tries++) {
		usleep(10000);
		after = sysctl_u64("kern.squeue.wired_pages");
	}
	ok(after <= before, "no wired-page leak across %d rings (%lu -> %lu)",
	    rings, before, after);
}

static void
t_combinatorial(int iters)
{
	struct ring r;
	static const uint8_t ops[] = { OP_NOP, OP_WRITE, OP_READ };
	static const uint8_t flg[] = { 0, IOSQE_ASYNC, IOSQE_IO_DRAIN,
	    IOSQE_CQE_SKIP_SUCCESS };
	char buf[8] = "combo5B";
	int fd, k, bad = 0;
	unsigned a, b;

	if (ring_open(&r, 16) != 0) {
		ok(0, "ring for combinatorial");
		return;
	}
	(void)unlink("/tmp/squeue_check_c.tmp");
	fd = open("/tmp/squeue_check_c.tmp", O_RDWR | O_CREAT | O_EXCL, 0600);
	(void)pwrite(fd, buf, 7, 0);

	for (k = 0; k < iters && !bad; k++) {
		for (a = 0; a < sizeof(ops); a++) {
			for (b = 0; b < sizeof(flg); b++) {
				uint8_t op = ops[a], f = flg[b];
				void *ad = (op == OP_NOP) ? NULL : buf;
				uint32_t ln = (op == OP_NOP) ? 0 : 7;

				ring_push(&r, op, f,
				    op == OP_NOP ? -1 : fd, ad, ln, 0, 0,
				    0x1000 + b);
				/* CQE_SKIP posts no CQE on success. */
				if (f == IOSQE_CQE_SKIP_SUCCESS) {
					if (ring_enter(&r, 1, 0,
					    ENTER_GETEVENTS) < 1)
						bad = 1;
				} else if (ring_enter(&r, 1, 1,
				    ENTER_GETEVENTS) != 1)
					bad = 1;
				(void)ring_reap(&r, NULL, 0);
			}
		}
	}
	ok(!bad, "combinatorial op/flag matrix (%d iters)", iters);
	(void)close(fd);
	(void)unlink("/tmp/squeue_check_c.tmp");
	ring_close(&r);
}

/* Concurrency: many threads each drive their own ring with async I/O.
 * Exercises the shared worker pool and the completion-delivery wakeup path
 * (the msleep-path lost-wakeup class). */
struct wa { int iters; int rc; };
static void *
conc_worker(void *arg)
{
	struct wa *w = arg;
	struct ring r;
	char buf[256];
	int i, fd, got, want = 8;

	w->rc = 0;
	fd = open("/tmp/squeue_check_conc.tmp", O_RDWR | O_CREAT, 0600);
	if (fd < 0) { w->rc = 1; return (NULL); }
	memset(buf, 'y', sizeof(buf));
	(void)pwrite(fd, buf, sizeof(buf), 0);
	if (ring_open(&r, 32) != 0) { close(fd); w->rc = 2; return (NULL); }
	for (i = 0; i < w->iters; i++) {
		int j;

		for (j = 0; j < want; j++)
			ring_push(&r, OP_READ, IOSQE_ASYNC, fd, buf,
			    sizeof(buf), 0, 0, 0x1000 + j);
		if (ring_enter(&r, want, (uint32_t)want, ENTER_GETEVENTS) < 0) {
			w->rc = 3;
			break;
		}
		got = 0;
		while (got < want) {
			int n = (int)ring_reap(&r, NULL, 0);
			if (n == 0 && ring_enter(&r, 0,
			    (uint32_t)(want - got), ENTER_GETEVENTS) < 0) {
				w->rc = 4;
				break;
			}
			got += n;
		}
		if (w->rc != 0)
			break;
	}
	ring_close(&r);
	close(fd);
	return (NULL);
}

static void
t_concurrency(int iters)
{
	pthread_t th[8];
	struct wa wa[8];
	int i, bad = 0;

	for (i = 0; i < 8; i++) {
		wa[i].iters = iters;
		wa[i].rc = 0;
		if (pthread_create(&th[i], NULL, conc_worker, &wa[i]) != 0)
			bad = 1;
	}
	for (i = 0; i < 8; i++)
		pthread_join(th[i], NULL);
	for (i = 0; i < 8; i++)
		if (wa[i].rc != 0)
			bad = 1;
	(void)unlink("/tmp/squeue_check_conc.tmp");
	ok(!bad, "8-thread concurrent async I/O (%d iters each)", iters);
}

/* Poll-wait + async: arm a poll on a never-ready fd (forces the poll-scan
 * wait path) while an async read resolves onto the ready list.  A lost wakeup
 * here would hang; success means enter() returns the read's completion. */
static void
t_poll_wait(int iters)
{
	struct ring r;
	char buf[64];
	int i, fd, sv[2], bad = 0;

	fd = open("/tmp/squeue_check_pw.tmp", O_RDWR | O_CREAT, 0600);
	memset(buf, 'z', sizeof(buf));
	(void)pwrite(fd, buf, sizeof(buf), 0);
	for (i = 0; i < iters && !bad; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
			bad = 1;
			break;
		}
		if (ring_open(&r, 8) != 0) {
			close(sv[0]);
			close(sv[1]);
			bad = 1;
			break;
		}
		ring_push(&r, OP_POLL_ADD, 0, sv[1], NULL, 0, 0, POLLIN_BIT,
		    0x1);
		ring_push(&r, OP_READ, IOSQE_ASYNC, fd, buf, sizeof(buf), 0, 0,
		    0x2);
		if (ring_enter(&r, 2, 1, ENTER_GETEVENTS) < 1 ||
		    ring_reap(&r, NULL, 0) < 1)
			bad = 1;
		ring_close(&r);
		close(sv[0]);
		close(sv[1]);
	}
	close(fd);
	(void)unlink("/tmp/squeue_check_pw.tmp");
	ok(!bad, "poll-wait + async resolve does not hang (%d iters)", iters);
}

/* Capsicum: in capability mode a native ring may only touch registered
 * (fixed) files, never raw ambient fds.  cap_enter is irreversible -> child. */
static void
t_capmode(void)
{
	pid_t pid = fork();

	if (pid == 0) {
		struct ring r;
		char cb[8];
		int cfd, rf, rc = 0;

		if (ring_open(&r, 8) != 0)
			_exit(10);
		(void)unlink("/tmp/squeue_check_cap.tmp");
		cfd = open("/tmp/squeue_check_cap.tmp",
		    O_RDWR | O_CREAT | O_EXCL, 0600);
		if (cfd < 0 || pwrite(cfd, "CAPMODE", 7, 0) != 7)
			_exit(11);
		rf = cfd;
		if (syscall(SYS_squeue_register, r.fd, REGISTER_FILES, &rf, 1)
		    != 0)
			_exit(12);
		if (cap_enter() != 0)
			_exit(13);
		/* raw ambient fd rejected in capmode */
		if (one(&r, OP_READ, 0, cfd, cb, 7, 0, 0, 0xA) != -ENOTCAPABLE)
			rc |= 1;
		/* IOSQE_ASYNC must not offload around the check */
		if (one(&r, OP_READ, IOSQE_ASYNC, cfd, cb, 7, 0, 0, 0xC) !=
		    -ENOTCAPABLE)
			rc |= 2;
		/* the registered (fixed index 0) file still works */
		memset(cb, 0, sizeof(cb));
		if (one(&r, OP_READ, IOSQE_FIXED_FILE, 0, cb, 7, 0, 0, 0xB) !=
		    7 || memcmp(cb, "CAPMODE", 7) != 0)
			rc |= 4;
		_exit(rc);
	} else if (pid < 0) {
		ok(0, "capmode confinement (fork failed)");
	} else {
		int st;

		(void)waitpid(pid, &st, 0);
		(void)unlink("/tmp/squeue_check_cap.tmp");
		ok(WIFEXITED(st) && WEXITSTATUS(st) == 0,
		    "capmode: raw fd denied, fixed fd allowed");
	}
}

int
main(int argc, char **argv)
{
	int c, scale = 1, quick = 0;
	long probe;

	while ((c = getopt(argc, argv, "vqi:")) != -1) {
		switch (c) {
		case 'v': opt_verbose = 1; break;
		case 'q': quick = 1; break;
		case 'i': scale = atoi(optarg); if (scale < 1) scale = 1; break;
		default:
			fprintf(stderr, "usage: %s [-v] [-q] [-i scale]\n",
			    argv[0]);
			return (2);
		}
	}

	/* Fail fast with a clear TAP bail-out if the engine is absent. */
	probe = syscall(SYS_squeue_setup, 0, NULL);
	if (probe < 0 && errno == ENOSYS) {
		printf("1..0 # SKIP squeue engine not present (ENOSYS)\n");
		return (0);
	}

	diag("scale=%d quick=%d", scale, quick);
	t_functional();
	t_kqueue_source();
	t_eventfd();
	t_cqsize();
	t_links();
	t_combinatorial(quick ? 5 : 50 * scale);
	t_leak(quick ? 20 : 200 * scale);
	t_concurrency(quick ? 10 : 100 * scale);
	t_poll_wait(quick ? 30 : 200 * scale);
	t_capmode();

	printf("1..%d\n", tap_n);
	if (tap_failed > 0)
		printf("# FAILED %d of %d checks\n", tap_failed, tap_n);
	else
		printf("# all %d checks passed\n", tap_n);
	return (tap_failed > 0 ? 1 : 0);
}
