/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * squeue_soak -- combinatorial + soak/leak exercise for the native 5BSD
 * squeue engine.  Its purpose is not throughput (this runs under emulation)
 * but to generate enough *varied* churn that the debugging kernel
 * (WITNESS / INVARIANTS / KASAN, all in the GENERIC-DEBUG test kernel) has a real
 * chance to trip on a lock-order bug, use-after-free, or leak, and to prove
 * that ring teardown returns wired memory to the system.
 *
 * Three phases:
 *   A. combinatorial: every {NOP,WRITE,READ} x {plain,ASYNC,DRAIN,
 *      CQE_SKIP_SUCCESS} combination, plus 2- and 3-deep IOSQE_IO_LINK
 *      chains (including a short-circuiting failed link), submitted in
 *      batches and reaped, for many iterations.
 *   B. lifecycle churn: create and tear down many rings of varied sizes
 *      (including IORING_SETUP_CQSIZE), then assert kern.squeue.wired_pages
 *      has returned to (at most) its pre-test baseline -- i.e. no ring or
 *      page leak across create/destroy.
 *   C. counters: kern.squeue.rings advanced by at least the rings we made.
 *
 * Iterations are overridable via argv[1] for a longer manual soak.
 * Exit status = failing check number, 0 = ok.
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/io_uring.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	OP_NOP		0
#define	OP_WRITE	23
#define	OP_READ		22
#define	ENTER_GETEVENTS	1
#define	OFF_SQ_RING	0ULL
#define	OFF_SQES	0x10000000ULL

#define	DEF_ITERS	400	/* combinatorial rounds; bounded for TCG */
#define	DEF_RINGS	300	/* ring create/destroy cycles */

static int ring_fd;
static char *sqbase;
static struct io_uring_sqe *sqes;
static volatile uint32_t *sq_tail, *sq_array, *cq_head, *cq_tail;
static struct io_uring_cqe *cqes;
static uint32_t sqmask, cqmask, sqi, cqi, cq_entries;

/* Open a ring with the given flags/cq size; leaves globals set. */
static int
ring_open(uint32_t entries, uint32_t flags, uint32_t want_cq)
{
	struct io_uring_params p;
	long r;
	uint32_t ringsz, sqesz;

	memset(&p, 0, sizeof(p));
	p.flags = flags;
	p.cq_entries = want_cq;
	r = syscall(SYS_squeue_setup, entries, &p);
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
	sq_tail = (volatile uint32_t *)(void *)(sqbase + p.sq_off.tail);
	sq_array = (volatile uint32_t *)(void *)(sqbase + p.sq_off.array);
	cq_head = (volatile uint32_t *)(void *)(sqbase + p.cq_off.head);
	cq_tail = (volatile uint32_t *)(void *)(sqbase + p.cq_off.tail);
	cqes = (struct io_uring_cqe *)(void *)(sqbase + p.cq_off.cqes);
	sqmask = p.sq_entries - 1;
	cqmask = p.cq_entries - 1;
	cq_entries = p.cq_entries;
	sqi = cqi = 0;
	return (0);
}

static void
ring_close(void)
{
	(void)syscall(SYS_close, ring_fd);
	ring_fd = -1;
}

/* Fill the next SQE slot; does not publish.  Returns the slot index. */
static void
prep(uint8_t op, uint8_t flags, int fd, void *addr, uint32_t len,
    uint64_t off, uint64_t ud)
{
	uint32_t slot = sqi & sqmask;

	memset(&sqes[slot], 0, sizeof(sqes[slot]));
	sqes[slot].opcode = op;
	sqes[slot].flags = flags;
	sqes[slot].fd = fd;
	sqes[slot].addr = (uint64_t)(uintptr_t)addr;
	sqes[slot].len = len;
	sqes[slot].off = off;
	sqes[slot].user_data = ud;
	sq_array[sqi & sqmask] = slot;
	sqi++;
}

/* Publish nsub SQEs and wait for at least nwait completions. */
static long
flush(uint32_t nsub, uint32_t nwait)
{
	__atomic_store_n(sq_tail, sqi, __ATOMIC_RELEASE);
	return (syscall(SYS_squeue_enter, ring_fd, nsub, nwait,
	    ENTER_GETEVENTS, NULL, 0));
}

/* Drain every currently-posted CQE; returns how many were reaped. */
static uint32_t
drain_cq(void)
{
	uint32_t tail, n = 0;

	tail = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
	while (cqi != tail) {
		cqi++;
		n++;
	}
	__atomic_store_n(cq_head, cqi, __ATOMIC_RELEASE);
	return (n);
}

struct cqrec { uint64_t ud; int32_t res; };

/*
 * Snapshot every currently-posted CQE into out[] (up to max), then advance
 * cq_head past all of them.  Returns the number captured.  Callers look up
 * multiple user_data values against the snapshot -- reaping one at a time
 * would drain siblings posted in the same batch before they were inspected.
 */
static uint32_t
reap_all(struct cqrec *out, uint32_t max)
{
	uint32_t tail, n = 0;

	tail = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
	while (cqi != tail) {
		if (n < max) {
			out[n].ud = cqes[cqi & cqmask].user_data;
			out[n].res = (int32_t)cqes[cqi & cqmask].res;
			n++;
		}
		cqi++;
	}
	__atomic_store_n(cq_head, cqi, __ATOMIC_RELEASE);
	return (n);
}

/* Find the res posted for user_data ud in a CQE snapshot; 1 if found. */
static int
find_res(const struct cqrec *r, uint32_t n, uint64_t ud, int32_t *res)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (r[i].ud == ud) {
			*res = r[i].res;
			return (1);
		}
	}
	return (0);
}

static u_long
wired_pages(void)
{
	u_long v = 0;
	size_t sz = sizeof(v);

	if (sysctlbyname("kern.squeue.wired_pages", &v, &sz, NULL, 0) != 0)
		return ((u_long)-1);
	return (v);
}

static uint64_t
rings_counter(void)
{
	uint64_t v = 0;
	size_t sz = sizeof(v);

	(void)sysctlbyname("kern.squeue.rings", &v, &sz, NULL, 0);
	return (v);
}

/* One combinatorial round on the current ring; returns 0 or a check code. */
static int
combo_round(int fd, uint64_t base)
{
	static const uint8_t ops[] = { OP_NOP, OP_WRITE, OP_READ };
	static const uint8_t flg[] = { 0, IOSQE_ASYNC, IOSQE_IO_DRAIN,
	    IOSQE_CQE_SKIP_SUCCESS };
	char buf[8] = "soak5B!";
	uint64_t ud = base;
	unsigned i, j;
	uint32_t nsub, posted;

	/* single ops across the opcode x flag matrix */
	for (i = 0; i < sizeof(ops); i++) {
		for (j = 0; j < sizeof(flg); j++) {
			uint8_t op = ops[i], f = flg[j];
			void *a = NULL;
			uint32_t len = 0;

			if (op == OP_WRITE) { a = buf; len = 7; }
			else if (op == OP_READ) { a = buf; len = 7; }
			prep(op, f, op == OP_NOP ? -1 : fd, a, len, 0, ud++);
			/*
			 * CQE_SKIP_SUCCESS posts no completion on success, so
			 * do not wait for one (min_complete=0) -- otherwise the
			 * enter would block for a CQE that never arrives.
			 */
			if (f == IOSQE_CQE_SKIP_SUCCESS) {
				if (flush(1, 0) < 1)
					return (59);
			} else if (flush(1, 1) != 1)
				return (60);
			(void)drain_cq();
		}
	}

	/* a 3-deep IOSQE_IO_LINK chain, submitted together */
	prep(OP_WRITE, IOSQE_IO_LINK, fd, buf, 7, 0, ud++);
	prep(OP_NOP, IOSQE_IO_LINK, -1, NULL, 0, 0, ud++);
	prep(OP_READ, 0, fd, buf, 7, 0, ud++);
	nsub = 3;
	if (flush(nsub, nsub) < 1)
		return (61);
	posted = drain_cq();
	if (posted != 3)
		return (62);

	/*
	 * Soft link (IOSQE_IO_LINK): a failed head short-circuits the chain.
	 * A bad-fd READ (fails -EBADF) soft-linked to a NOP: the NOP must be
	 * cancelled and post -ECANCELED (not run to success).  Both still emit
	 * a CQE, so a CQE-counting reaper stays balanced.
	 */
	{
		uint64_t head = ud++, tail = ud++;
		struct cqrec recs[4];
		uint32_t n;
		int32_t r = 0;

		prep(OP_READ, IOSQE_IO_LINK, 9999, buf, 4, 0, head);
		prep(OP_NOP, 0, -1, NULL, 0, 0, tail);
		if (flush(2, 2) < 1)
			return (63);
		n = reap_all(recs, 4);
		if (!find_res(recs, n, head, &r) || r != -EBADF)
			return (64);
		if (!find_res(recs, n, tail, &r) || r != -ECANCELED)
			return (65);
	}

	/*
	 * Hard link (IOSQE_IO_HARDLINK): a failed head does NOT cancel the
	 * chain -- the successor still runs.  Same bad-fd READ hard-linked to
	 * a NOP: the NOP must run and succeed (res 0), not be cancelled.
	 */
	{
		uint64_t head = ud++, tail = ud++;
		struct cqrec recs[4];
		uint32_t n;
		int32_t r = 0;

		prep(OP_READ, IOSQE_IO_HARDLINK, 9999, buf, 4, 0, head);
		prep(OP_NOP, 0, -1, NULL, 0, 0, tail);
		if (flush(2, 2) < 1)
			return (66);
		n = reap_all(recs, 4);
		if (!find_res(recs, n, head, &r) || r != -EBADF)
			return (67);
		if (!find_res(recs, n, tail, &r) || r != 0)
			return (68);
	}
	return (0);
}

int
main(int argc, char **argv)
{
	long iters = DEF_ITERS, nrings = DEF_RINGS, k;
	u_long w_before, w_after;
	uint64_t rc_before, rc_after;
	int fd, rc;

	if (argc > 1) {
		long v = strtol(argv[1], NULL, 10);
		if (v > 0) { iters = v; nrings = v; }
	}

	w_before = wired_pages();
	rc_before = rings_counter();

	/* Phase A: combinatorial op/flag/chain churn on a stable ring. */
	if (ring_open(16, 0, 0) != 0)
		return (1);
	(void)unlink("/tmp/squeue_soak.tmp");
	fd = open("/tmp/squeue_soak.tmp", O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0)
		return (2);
	if (pwrite(fd, "soak5B!", 7, 0) != 7)
		return (3);
	for (k = 0; k < iters; k++) {
		rc = combo_round(fd, (uint64_t)k << 8);
		if (rc != 0)
			return (rc);
	}
	(void)close(fd);
	(void)unlink("/tmp/squeue_soak.tmp");
	ring_close();

	/* Phase B: ring lifecycle churn across varied geometries. */
	for (k = 0; k < nrings; k++) {
		uint32_t ent = 1U << (1 + (k % 6));	/* 2..64 */
		uint32_t flags = 0, wantcq = 0;

		if (k % 3 == 0) {
			flags = (1U << 3);		/* CQSIZE */
			wantcq = ent * 4;
		}
		if (ring_open(ent, flags, wantcq) != 0)
			return (50);
		/* do a little work so the ring is not trivially empty */
		prep(OP_NOP, 0, -1, NULL, 0, 0, 0xABC0 + (uint64_t)k);
		if (flush(1, 1) != 1)
			return (51);
		(void)drain_cq();
		ring_close();
	}

	/* Phase C: leak + counter assertions. */
	rc_after = rings_counter();

	/*
	 * Every ring we opened was closed, so wired pages must return to (at
	 * most) the pre-test baseline.  A close can drop the last ref slightly
	 * after the syscall returns if a worker kproc briefly held one, so
	 * poll for the value to settle rather than reading it once.
	 */
	w_after = wired_pages();
	if (w_before != (u_long)-1) {
		int tries;

		for (tries = 0; tries < 100 && w_after != (u_long)-1 &&
		    w_after > w_before; tries++) {
			usleep(10000);		/* 10ms */
			w_after = wired_pages();
		}
		if (w_after != (u_long)-1 && w_after > w_before)
			return (70);
	}
	/* the rings-created counter advanced by at least what we made. */
	if (rc_after < rc_before + (uint64_t)(1 + nrings))
		return (71);

	return (0);
}
