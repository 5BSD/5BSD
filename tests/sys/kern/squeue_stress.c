/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * squeue concurrency and lifecycle-race stress test.
 *
 * Functional tests prove correctness on the happy path; this program exercises
 * the paths where the hard bugs live: closing a ring while asynchronous work
 * (timeouts, polls, worker-pool file I/O) is in flight, and many threads
 * driving rings at once.  Run under a debug kernel (WITNESS, INVARIANTS,
 * QUEUE_MACRO_DEBUG_TRASH, and/or KASAN) so a lifecycle race trips an assertion
 * or sanitizer rather than passing silently.  Exit status = failing test
 * number, 0 = ok.
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/io_uring.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define	OP_NOP		0
#define	OP_TIMEOUT	11
#define	OP_READ		22
#define	OP_WRITE	23
#define	OP_POLL_ADD	6
#define	ENTER_GETEVENTS	1
#define	OFF_SQ_RING	0ULL
#define	OFF_SQES	0x10000000ULL
#define	POLLIN_BIT	0x0001

struct ring {
	int fd;
	char *sqbase;
	size_t ringsz;
	struct io_uring_sqe *sqes;
	size_t sqesz;
	volatile uint32_t *sq_tail, *sq_array, *cq_head, *cq_tail;
	struct io_uring_cqe *cqes;
	uint32_t sqmask, cqmask, sqi, cqi;
};

/* Create a ring and map its three regions.  Returns 0 on success. */
static int
ring_open(struct ring *r, uint32_t entries)
{
	struct io_uring_params p;
	long fd;

	memset(r, 0, sizeof(*r));
	memset(&p, 0, sizeof(p));
	fd = syscall(SYS_squeue_setup, entries, &p);
	if (fd < 0)
		return (-1);
	r->fd = (int)fd;
	r->ringsz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
	if (p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe) > r->ringsz)
		r->ringsz = p.cq_off.cqes +
		    p.cq_entries * sizeof(struct io_uring_cqe);
	r->sqbase = mmap(NULL, r->ringsz, PROT_READ | PROT_WRITE, MAP_SHARED,
	    r->fd, OFF_SQ_RING);
	if (r->sqbase == MAP_FAILED)
		return (-1);
	r->sqesz = p.sq_entries * sizeof(struct io_uring_sqe);
	r->sqes = mmap(NULL, r->sqesz, PROT_READ | PROT_WRITE, MAP_SHARED,
	    r->fd, OFF_SQES);
	if (r->sqes == MAP_FAILED)
		return (-1);
	r->sq_tail = (volatile uint32_t *)(r->sqbase + p.sq_off.tail);
	r->sq_array = (volatile uint32_t *)(r->sqbase + p.sq_off.array);
	r->cq_head = (volatile uint32_t *)(r->sqbase + p.cq_off.head);
	r->cq_tail = (volatile uint32_t *)(r->sqbase + p.cq_off.tail);
	r->cqes = (struct io_uring_cqe *)(r->sqbase + p.cq_off.cqes);
	r->sqmask = p.sq_entries - 1;
	r->cqmask = p.cq_entries - 1;
	return (0);
}

static void
ring_close(struct ring *r)
{
	if (r->sqes != NULL && r->sqes != MAP_FAILED)
		munmap(r->sqes, r->sqesz);
	if (r->sqbase != NULL && r->sqbase != MAP_FAILED)
		munmap(r->sqbase, r->ringsz);
	if (r->fd >= 0)
		syscall(SYS_close, r->fd);
	r->fd = -1;
	r->sqbase = NULL;
	r->sqes = NULL;
}

/* Queue one sqe (does not enter). */
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

/* Reap all currently available completions. */
static int
ring_reap(struct ring *r)
{
	uint32_t tail = __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE);
	int n = 0;

	while (r->cqi != tail) {
		r->cqi++;
		n++;
	}
	__atomic_store_n(r->cq_head, r->cqi, __ATOMIC_RELEASE);
	return (n);
}

/*
 * Test 1: close a ring with an armed TIMEOUT in flight.  The callout may fire
 * during or after teardown; a regression corrupts ctx lists (caught by
 * QUEUE_MACRO_DEBUG_TRASH / INVARIANTS / KASAN).
 */
static int
t_race_close_timeout(void)
{
	struct { int64_t s, ns; } ts = { 0, 1000000 };	/* 1ms */
	struct ring r;
	int i;

	for (i = 0; i < 400; i++) {
		if (ring_open(&r, 8) != 0)
			return (11);
		ring_push(&r, OP_TIMEOUT, 0, -1, &ts, 0, 0, 0, 0x1);
		if (ring_enter(&r, 1, 0, 0) != 1) {
			ring_close(&r);
			return (12);
		}
		/* close immediately, racing the callout */
		ring_close(&r);
	}
	return (0);
}

/*
 * Test 2: close a ring while IOSQE_ASYNC worker-pool file I/O is in flight.
 * Exercises ctx->refs and worker-vs-teardown ordering.
 */
static int
t_race_close_async(void)
{
	struct ring r;
	char buf[512];
	int i, fd;

	memset(buf, 'x', sizeof(buf));
	fd = open("/tmp/squeue_stress.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return (21);
	(void)pwrite(fd, buf, sizeof(buf), 0);
	for (i = 0; i < 300; i++) {
		int j;

		if (ring_open(&r, 32) != 0) {
			close(fd);
			return (22);
		}
		for (j = 0; j < 8; j++)
			ring_push(&r, OP_READ, IOSQE_ASYNC, fd, buf,
			    sizeof(buf), 0, 0, 0x100 + j);
		if (ring_enter(&r, 8, 0, 0) != 8) {
			ring_close(&r);
			close(fd);
			return (23);
		}
		/* close while workers may still be running the reads */
		ring_close(&r);
	}
	close(fd);
	(void)unlink("/tmp/squeue_stress.tmp");
	return (0);
}

/*
 * Test 3: close a ring with an armed POLL_ADD (persistent kqueue knote) on a
 * socketpair.  Exercises knote teardown vs fdrop(kqfp) ordering.
 */
static int
t_race_close_poll(void)
{
	struct ring r;
	int i, sv[2];

	for (i = 0; i < 300; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
			return (31);
		if (ring_open(&r, 8) != 0) {
			close(sv[0]);
			close(sv[1]);
			return (32);
		}
		ring_push(&r, OP_POLL_ADD, 0, sv[1], NULL, 0, 0, POLLIN_BIT, 0x1);
		if (ring_enter(&r, 1, 0, 0) != 1) {
			ring_close(&r);
			close(sv[0]);
			close(sv[1]);
			return (33);
		}
		/* make it ready in some iterations to race the fire vs close */
		if ((i & 1) == 0)
			(void)write(sv[0], "x", 1);
		ring_close(&r);
		close(sv[0]);
		close(sv[1]);
	}
	return (0);
}

/* Worker for test 4: hammer a private ring with async file I/O. */
struct worker_arg { int rc; };
static void *
conc_worker(void *arg)
{
	struct worker_arg *wa = arg;
	struct ring r;
	char buf[256];
	int i, fd, got;

	wa->rc = 0;
	fd = open("/tmp/squeue_stress.tmp", O_RDWR | O_CREAT, 0600);
	if (fd < 0) {
		wa->rc = 41;
		return (NULL);
	}
	memset(buf, 'y', sizeof(buf));
	(void)pwrite(fd, buf, sizeof(buf), 0);
	if (ring_open(&r, 32) != 0) {
		close(fd);
		wa->rc = 42;
		return (NULL);
	}
	for (i = 0; i < 200; i++) {
		int j, want = 8;

		for (j = 0; j < want; j++)
			ring_push(&r, OP_READ, IOSQE_ASYNC, fd, buf,
			    sizeof(buf), 0, 0, 0x1000 + j);
		if (ring_enter(&r, want, (uint32_t)want, ENTER_GETEVENTS) < 0) {
			wa->rc = 43;
			break;
		}
		got = 0;
		while (got < want) {
			int n = ring_reap(&r);
			if (n == 0) {
				if (ring_enter(&r, 0, (uint32_t)(want - got),
				    ENTER_GETEVENTS) < 0) {
					wa->rc = 44;
					break;
				}
			}
			got += n;
		}
		if (wa->rc != 0)
			break;
	}
	ring_close(&r);
	close(fd);
	return (NULL);
}

/*
 * Test 4: many threads, each driving its own ring with async I/O concurrently,
 * to stress the shared worker pool, the global wired-memory accounting, and
 * completion delivery under SMP contention.
 */
static int
t_concurrent_rings(void)
{
	pthread_t th[8];
	struct worker_arg wa[8];
	int i, n = 8;

	for (i = 0; i < n; i++) {
		wa[i].rc = 0;
		if (pthread_create(&th[i], NULL, conc_worker, &wa[i]) != 0)
			return (45);
	}
	for (i = 0; i < n; i++)
		pthread_join(th[i], NULL);
	for (i = 0; i < n; i++)
		if (wa[i].rc != 0)
			return (wa[i].rc);
	(void)unlink("/tmp/squeue_stress.tmp");
	return (0);
}

int
main(void)
{
	int rc;

	if ((rc = t_race_close_timeout()) != 0)
		return (rc);
	if ((rc = t_race_close_async()) != 0)
		return (rc);
	if ((rc = t_race_close_poll()) != 0)
		return (rc);
	if ((rc = t_concurrent_rings()) != 0)
		return (rc);
	return (0);
}
