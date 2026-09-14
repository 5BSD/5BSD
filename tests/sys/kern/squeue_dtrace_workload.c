/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * squeue_dtrace_workload -- a tiny standalone squeue workload for the DTrace
 * provider test.  It sets up a native squeue ring and submits/reaps NOP
 * operations in a loop for a fixed wall-clock window, so that a concurrently
 * running "dtrace -c" has ample time to enable the squeue:::submit and
 * squeue:::complete probes and observe them firing -- even under a slow
 * TCG-emulated guest.
 *
 * This is deliberately NOT an ATF test binary: an ATF program invoked as a
 * bare "-c" child (no test-case name) exits 0 without running any body, so it
 * would never issue a single squeue operation.  A plain main() always works.
 *
 * Exit status: 0 on success, non-zero on setup/framing failure.
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/io_uring.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define	OP_NOP		0
#define	ENTER_GETEVENTS	1
#define	OFF_SQ_RING	0ULL
#define	OFF_SQES	0x10000000ULL

/*
 * Submit NOPs for at least this long (seconds) so a background dtrace has
 * ample time to enable its probes and observe them firing, even when dtrace's
 * probe-enable is slow (e.g. a TCG-emulated guest).  Overridable via argv[1].
 */
#define	RUN_SECONDS	8

static int ring_fd;
static char *sqbase;
static struct io_uring_sqe *sqes;
static volatile uint32_t *sq_tail, *sq_array, *cq_head, *cq_tail;
static struct io_uring_cqe *cqes;
static uint32_t sqmask, cqmask, sqi, cqi;

static int
ring_init(uint32_t entries)
{
	struct io_uring_params p;
	long r;
	uint32_t ringsz, sqesz;

	memset(&p, 0, sizeof(p));
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
	sqi = cqi = 0;
	return (0);
}

static int
nop(uint64_t ud)
{
	uint32_t slot = sqi & sqmask;
	long r;

	memset(&sqes[slot], 0, sizeof(sqes[slot]));
	sqes[slot].opcode = OP_NOP;
	sqes[slot].user_data = ud;
	sq_array[sqi & sqmask] = slot;
	sqi++;
	__atomic_store_n(sq_tail, sqi, __ATOMIC_RELEASE);
	r = syscall(SYS_squeue_enter, ring_fd, 1, 1, ENTER_GETEVENTS, NULL, 0);
	if (r != 1)
		return (-1);
	if (cqes[cqi & cqmask].user_data != ud)
		return (-1);
	cqi++;
	__atomic_store_n(cq_head, cqi, __ATOMIC_RELEASE);
	return (0);
}

int
main(int argc, char **argv)
{
	struct timespec start, now, nap;
	uint64_t ud;
	long secs = RUN_SECONDS;

	if (argc > 1) {
		secs = strtol(argv[1], NULL, 10);
		if (secs <= 0)
			secs = RUN_SECONDS;
	}

	if (ring_init(8) != 0)
		return (1);

	nap.tv_sec = 0;
	nap.tv_nsec = 2 * 1000 * 1000;	/* 2ms between submissions */
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (ud = 1;; ud++) {
		if (nop(ud) != 0)
			return (2);
		nanosleep(&nap, NULL);
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec >= secs)
			break;
	}
	return (0);
}
