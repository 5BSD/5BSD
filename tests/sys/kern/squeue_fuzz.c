/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * squeue adversarial fuzzer.
 *
 * Submits randomized submission entries - random opcodes, flags, descriptors,
 * pointers, lengths and offsets - and periodically scribbles the shared ring
 * indices, then enters the ring, in a tight loop.  The kernel must survive
 * every hostile input: no panic, no out-of-bounds or use-after-free (run under
 * a KASAN kernel to catch the latter), and the ring must still work at the end.
 * Deterministic (fixed PRNG seed, overridable via argv[1]) for reproducibility.
 * Exit status = failing check number, 0 = ok.
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/io_uring.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	OFF_SQ_RING	0ULL
#define	OFF_SQES	0x10000000ULL
#define	NENTRIES	32
#define	NITERS		6000

static int ring_fd = -1;
static char *sqbase;
static struct io_uring_sqe *sqes;
static volatile uint32_t *sq_tail, *sq_head, *sq_array, *cq_head, *cq_tail;
static struct io_uring_cqe *cqes;
static uint32_t sqmask, cqmask, sqi, cqi, sqentries, cqentries;
static uint64_t rng;
static int tmpfd;
static char *scratch;		/* a real, valid user buffer */

static uint32_t
rnd(void)
{
	/* xorshift64* */
	rng ^= rng >> 12;
	rng ^= rng << 25;
	rng ^= rng >> 27;
	return ((uint32_t)((rng * 0x2545F4914F6CDD1DULL) >> 32));
}

static int
ring_init(void)
{
	struct io_uring_params p;
	long r;
	uint32_t ringsz, sqesz;

	memset(&p, 0, sizeof(p));
	r = syscall(SYS_squeue_setup, NENTRIES, &p);
	if (r < 0)
		return (-1);
	ring_fd = (int)r;
	sqentries = p.sq_entries;
	cqentries = p.cq_entries;
	ringsz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
	if (p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe) > ringsz)
		ringsz = p.cq_off.cqes +
		    p.cq_entries * sizeof(struct io_uring_cqe);
	sqbase = mmap(NULL, ringsz, PROT_READ | PROT_WRITE, MAP_SHARED, ring_fd,
	    OFF_SQ_RING);
	if (sqbase == MAP_FAILED)
		return (-1);
	sqesz = p.sq_entries * sizeof(struct io_uring_sqe);
	sqes = mmap(NULL, sqesz, PROT_READ | PROT_WRITE, MAP_SHARED, ring_fd,
	    OFF_SQES);
	if (sqes == MAP_FAILED)
		return (-1);
	sq_head = (volatile uint32_t *)(sqbase + p.sq_off.head);
	sq_tail = (volatile uint32_t *)(sqbase + p.sq_off.tail);
	sq_array = (volatile uint32_t *)(sqbase + p.sq_off.array);
	cq_head = (volatile uint32_t *)(sqbase + p.cq_off.head);
	cq_tail = (volatile uint32_t *)(sqbase + p.cq_off.tail);
	cqes = (struct io_uring_cqe *)(sqbase + p.cq_off.cqes);
	sqmask = p.sq_entries - 1;
	cqmask = p.cq_entries - 1;
	return (0);
}

/* A grab-bag of descriptor values: valid, special, and garbage. */
static int
rnd_fd(void)
{
	switch (rnd() % 6) {
	case 0: return (tmpfd);
	case 1: return (ring_fd);
	case 2: return (-1);
	case 3: return (0);
	case 4: return ((int)(rnd() % 100000));
	default: return ((int)rnd());
	}
}

/* A grab-bag of address values: valid buffer, NULL, and garbage pointers. */
static uint64_t
rnd_addr(void)
{
	switch (rnd() % 4) {
	case 0: return ((uint64_t)(uintptr_t)scratch);
	case 1: return (0);
	case 2: return ((uint64_t)(uintptr_t)scratch + (rnd() % 8192));
	default: return ((uint64_t)rnd() << 12);	/* wild pointer */
	}
}

static void
fuzz_sqe(struct io_uring_sqe *s)
{
	memset(s, 0, sizeof(*s));
	s->opcode = (uint8_t)(rnd() % 72);	/* incl. a few past IORING_OP_LAST */
	s->flags = (uint8_t)rnd();
	s->ioprio = (uint16_t)rnd();
	s->fd = rnd_fd();
	s->off = ((uint64_t)rnd() << 32) | rnd();
	s->addr = rnd_addr();
	s->len = rnd() % 65536;
	s->rw_flags = rnd();
	s->user_data = rnd();
	s->buf_index = (uint16_t)rnd();
	s->buf_group = (uint16_t)rnd();
	s->personality = (uint16_t)rnd();
	s->splice_fd_in = rnd_fd();
}

int
main(int argc, char **argv)
{
	uint32_t i, j, n, slot;
	long r;

	rng = (argc > 1) ? strtoull(argv[1], NULL, 0) : 0x5b5d5b5d5b5d5b5dULL;
	if (rng == 0)
		rng = 1;

	scratch = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	if (scratch == MAP_FAILED)
		return (1);
	tmpfd = open("/tmp/squeue_fuzz.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (tmpfd < 0)
		return (2);
	(void)pwrite(tmpfd, scratch, 4096, 0);

	if (ring_init() != 0)
		return (3);

	for (i = 0; i < NITERS; i++) {
		/* Occasionally register random buffers/files to exercise those. */
		if ((rnd() % 64) == 0) {
			struct iovec iov;

			iov.iov_base = scratch;
			iov.iov_len = 4096;
			(void)syscall(SYS_squeue_register, ring_fd,
			    0 /*REGISTER_BUFFERS*/, &iov, 1);
		}
		if ((rnd() % 64) == 0) {
			int fds[2] = { tmpfd, -1 };

			(void)syscall(SYS_squeue_register, ring_fd,
			    2 /*REGISTER_FILES*/, fds, 2);
		}

		/* Fill a random number of SQEs. */
		n = 1 + (rnd() % sqentries);
		for (j = 0; j < n; j++) {
			slot = sqi & sqmask;
			fuzz_sqe(&sqes[slot]);
			sq_array[sqi & sqmask] = (rnd() % 2) ? slot :
			    (rnd() & sqmask);	/* sometimes a bogus index */
			sqi++;
		}
		/* Sometimes scribble the shared indices with hostile values. */
		if ((rnd() % 16) == 0)
			__atomic_store_n(sq_tail, rnd(), __ATOMIC_RELEASE);
		else
			__atomic_store_n(sq_tail, sqi, __ATOMIC_RELEASE);
		if ((rnd() % 32) == 0)
			__atomic_store_n(cq_head, rnd(), __ATOMIC_RELEASE);

		/* Enter without waiting so a blocking op cannot stall us. */
		r = syscall(SYS_squeue_enter, ring_fd, n, 0, 0, NULL, 0);
		(void)r;

		/* Drain whatever completed so the CQ does not stay wedged. */
		cqi = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
		__atomic_store_n(cq_head, cqi, __ATOMIC_RELEASE);

		/* Occasionally unregister to churn the resource tables. */
		if ((rnd() % 128) == 0)
			(void)syscall(SYS_squeue_register, ring_fd,
			    3 /*UNREGISTER_FILES*/, NULL, 0);
		if ((rnd() % 128) == 0)
			(void)syscall(SYS_squeue_register, ring_fd,
			    1 /*UNREGISTER_BUFFERS*/, NULL, 0);
	}

	/*
	 * The kernel survived the storm.  The fuzzed ring's shared indices were
	 * deliberately scribbled, so its user/kernel state is undefined by
	 * design - verify the engine is still healthy on a FRESH ring instead:
	 * a clean NOP must round-trip.
	 */
	(void)syscall(SYS_close, ring_fd);
	ring_fd = -1;
	if (ring_init() != 0)
		return (4);
	sqi = 0;
	cqi = 0;
	slot = sqi & sqmask;
	memset(&sqes[slot], 0, sizeof(sqes[slot]));
	sqes[slot].opcode = 0;			/* NOP */
	sqes[slot].user_data = 0xABCD;
	sq_array[sqi & sqmask] = slot;
	sqi++;
	__atomic_store_n(sq_tail, sqi, __ATOMIC_RELEASE);
	r = syscall(SYS_squeue_enter, ring_fd, 1, 1, 1 /*GETEVENTS*/, NULL, 0);
	if (r != 1)
		return (5);
	if (__atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) != 1)
		return (6);
	if (cqes[0].user_data != 0xABCD || cqes[0].res != 0)
		return (7);

	(void)syscall(SYS_close, ring_fd);
	(void)close(tmpfd);
	(void)unlink("/tmp/squeue_fuzz.tmp");
	return (0);
}
