/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Native 5BSD squeue smoke test: exercises the squeue_setup/enter/register
 * syscalls directly (no Linux ABI), proving the completion-ring engine is
 * available to native programs.  Exit status = failing check number, 0 = ok.
 */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/mman.h>
#include <sys/event.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/io_uring.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define	REGISTER_FILES	2	/* IORING_REGISTER_FILES */
#define	SQ_MAX_ENTRIES_T	32768	/* userspace mirror of SQ_MAX_ENTRIES */

#define	OP_NOP		0
#define	OP_TIMEOUT	11
#define	OP_OPENAT	18
#define	OP_READ		22
#define	OP_WRITE	23
#define	ENTER_GETEVENTS	1
#define	OFF_SQ_RING	0ULL
#define	OFF_SQES	0x10000000ULL

static int ring_fd;
static char *sqbase;
static struct io_uring_sqe *sqes;
static volatile uint32_t *sq_tail, *sq_array, *cq_head, *cq_tail;
static struct io_uring_cqe *cqes;
static uint32_t sqmask, cqmask, sqi, cqi;

static long
sq_setup(uint32_t entries, struct io_uring_params *p)
{
	return (syscall(SYS_squeue_setup, entries, p));
}

static int
ring_init(uint32_t entries)
{
	struct io_uring_params p;
	long r;
	uint32_t ringsz, sqesz;

	memset(&p, 0, sizeof(p));
	r = sq_setup(entries, &p);
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
	sq_tail = (volatile uint32_t *)(sqbase + p.sq_off.tail);
	sq_array = (volatile uint32_t *)(sqbase + p.sq_off.array);
	cq_head = (volatile uint32_t *)(sqbase + p.cq_off.head);
	cq_tail = (volatile uint32_t *)(sqbase + p.cq_off.tail);
	cqes = (struct io_uring_cqe *)(sqbase + p.cq_off.cqes);
	sqmask = p.sq_entries - 1;
	cqmask = p.cq_entries - 1;
	sqi = cqi = 0;
	return (0);
}

/* submit one sqe, reap one cqe; returns res, or a sentinel on framing error */
static int
one(uint8_t op, int fd, void *addr, uint32_t len, uint64_t off, uint32_t misc,
    uint64_t ud)
{
	uint32_t slot = sqi & sqmask;
	long r;

	memset(&sqes[slot], 0, sizeof(sqes[slot]));
	sqes[slot].opcode = op;
	sqes[slot].fd = fd;
	sqes[slot].addr = (uint64_t)(uintptr_t)addr;
	sqes[slot].len = len;
	sqes[slot].off = off;
	sqes[slot].rw_flags = misc;
	sqes[slot].user_data = ud;
	sq_array[sqi & sqmask] = slot;
	sqi++;
	__atomic_store_n(sq_tail, sqi, __ATOMIC_RELEASE);
	r = syscall(SYS_squeue_enter, ring_fd, 1, 1, ENTER_GETEVENTS, NULL, 0);
	if (r != 1)
		return (-100000);
	if (__atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) != cqi + 1)
		return (-100001);
	if (cqes[cqi & cqmask].user_data != ud)
		return (-100002);
	r = cqes[cqi & cqmask].res;
	cqi++;
	__atomic_store_n(cq_head, cqi, __ATOMIC_RELEASE);
	return ((int)r);
}

/* Like one() but with explicit sqe flags (e.g. IOSQE_ASYNC worker offload). */
static int
one_flags(uint8_t op, uint8_t flags, int fd, void *addr, uint32_t len,
    uint64_t off, uint64_t ud)
{
	uint32_t slot = sqi & sqmask;
	long r;

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
	__atomic_store_n(sq_tail, sqi, __ATOMIC_RELEASE);
	r = syscall(SYS_squeue_enter, ring_fd, 1, 1, ENTER_GETEVENTS, NULL, 0);
	if (r != 1)
		return (-100000);
	if (cqes[cqi & cqmask].user_data != ud)
		return (-100002);
	r = cqes[cqi & cqmask].res;
	cqi++;
	__atomic_store_n(cq_head, cqi, __ATOMIC_RELEASE);
	return ((int)r);
}

int
main(void)
{
	char wbuf[16], rbuf[16];
	int fd;

	/* 1: setup + mmap */
	if (ring_init(8) != 0)
		return (1);

	/* 2: NOP round-trips through the native ring */
	if (one(OP_NOP, -1, NULL, 0, 0, 0, 0x1) != 0)
		return (2);

	/* 3: real WRITE/READ on a temp file (neutral opcode, native) */
	(void)unlink("/tmp/squeue_native.tmp");
	fd = open("/tmp/squeue_native.tmp", O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0)
		return (3);
	memcpy(wbuf, "squeue!", 7);
	if (one(OP_WRITE, fd, wbuf, 7, 0, 0, 0x2) != 7)
		return (4);
	memset(rbuf, 0, sizeof(rbuf));
	if (one(OP_READ, fd, rbuf, 7, 0, 0, 0x3) != 7 ||
	    memcmp(rbuf, "squeue!", 7) != 0)
		return (5);
	(void)close(fd);
	(void)unlink("/tmp/squeue_native.tmp");

	/* 4: a bad-fd READ reports a negative BSD errno (native, not Linux) */
	if (one(OP_READ, 9999, rbuf, 4, 0, 0, 0x4) != -EBADF)
		return (6);

	/* 5: a Linux-flavored opcode has no native handler -> -EINVAL */
	if (one(OP_OPENAT, -100 /* AT_FDCWD */, "/nonexistent", 0, 0, 0, 0x5)
	    != -EINVAL)
		return (7);

	/* 6: TIMEOUT completes with the native errno -ETIMEDOUT */
	{
		struct { int64_t tv_sec; int64_t tv_nsec; } ts = { 0, 20000000 };

		if (one(OP_TIMEOUT, -1, &ts, 0, 0, 0, 0x6) != -ETIMEDOUT)
			return (8);
	}

	/* 7: IOSQE_ASYNC worker-pool offload round-trips natively */
	(void)unlink("/tmp/squeue_native.tmp");
	fd = open("/tmp/squeue_native.tmp", O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0)
		return (9);
	memcpy(wbuf, "async5B", 7);
	if (one_flags(OP_WRITE, IOSQE_ASYNC, fd, wbuf, 7, 0, 0x7) != 7)
		return (10);
	memset(rbuf, 0, sizeof(rbuf));
	if (one_flags(OP_READ, IOSQE_ASYNC, fd, rbuf, 7, 0, 0x8) != 7 ||
	    memcmp(rbuf, "async5B", 7) != 0)
		return (11);
	(void)close(fd);
	(void)unlink("/tmp/squeue_native.tmp");

	/* 8: the ring is a first-class kqueue source (EVFILT_READ) */
	{
		struct kevent kev;
		struct timespec zero = { 0, 0 };
		uint32_t slot;
		int kq, n;

		kq = kqueue();
		if (kq < 0)
			return (12);
		EV_SET(&kev, ring_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(kq, &kev, 1, NULL, 0, NULL) != 0)
			return (13);
		/* nothing pending -> ring not readable */
		if (kevent(kq, NULL, 0, &kev, 1, &zero) != 0)
			return (14);
		/* submit a NOP but do NOT reap it: a completion becomes ready */
		slot = sqi & sqmask;
		memset(&sqes[slot], 0, sizeof(sqes[slot]));
		sqes[slot].opcode = OP_NOP;
		sqes[slot].user_data = 0x9;
		sq_array[sqi & sqmask] = slot;
		sqi++;
		__atomic_store_n(sq_tail, sqi, __ATOMIC_RELEASE);
		if (syscall(SYS_squeue_enter, ring_fd, 1, 0, 0, NULL, 0) != 1)
			return (15);
		/* the ring must now report readable with a pending count */
		n = kevent(kq, NULL, 0, &kev, 1, &zero);
		if (n != 1 || (long)kev.data < 1)
			return (16);
		/* reap it; the ring goes quiet again */
		cqi++;
		__atomic_store_n(cq_head, cqi, __ATOMIC_RELEASE);
		if (kevent(kq, NULL, 0, &kev, 1, &zero) != 0)
			return (17);
		(void)close(kq);
	}

	/* 9: REGISTER_EVENTFD - a completion signals the registered eventfd */
	{
		int efd, ereg;
		uint64_t val = 0;

		efd = eventfd(0, EFD_NONBLOCK);
		if (efd < 0)
			return (18);
		ereg = efd;
		if (syscall(SYS_squeue_register, ring_fd, 4 /*REGISTER_EVENTFD*/,
		    &ereg, 1) != 0)
			return (19);
		if (one(OP_NOP, -1, NULL, 0, 0, 0, 0xE) != 0)
			return (20);
		if (read(efd, &val, sizeof(val)) != (ssize_t)sizeof(val) ||
		    val < 1)
			return (21);
		(void)syscall(SYS_squeue_register, ring_fd,
		    5 /*UNREGISTER_EVENTFD*/, NULL, 0);
		(void)close(efd);
	}

	/*
	 * 10: an IOSQE_ASYNC positioned op with a negative offset must be
	 * rejected (-EINVAL), not reach the fs and panic (ffs_read: uio
	 * offset < 0).  The worker path calls fo_read/fo_write directly, so it
	 * needs the same negative-offset guard the inline kern_pread path has.
	 */
	{
		char nb[8];
		int nfd;

		(void)unlink("/tmp/squeue_negoff.tmp");
		nfd = open("/tmp/squeue_negoff.tmp", O_RDWR | O_CREAT | O_EXCL,
		    0600);
		if (nfd < 0)
			return (25);
		if (one_flags(OP_READ, IOSQE_ASYNC, nfd, nb, 4,
		    0x8000000000000000ULL, 0xF) != -EINVAL)
			return (26);
		(void)close(nfd);
		(void)unlink("/tmp/squeue_negoff.tmp");
	}

	/* 11: the kern.squeue observability counters advance on activity */
	{
		uint64_t sub0 = 0, sub1v = 0, comp0 = 0, comp1 = 0;
		size_t sz = sizeof(uint64_t);

		if (sysctlbyname("kern.squeue.submitted", &sub0, &sz, NULL, 0)
		    != 0)
			return (27);
		sz = sizeof(uint64_t);
		(void)sysctlbyname("kern.squeue.completed", &comp0, &sz, NULL, 0);
		if (one(OP_NOP, -1, NULL, 0, 0, 0, 0x30) != 0)
			return (28);
		sz = sizeof(uint64_t);
		(void)sysctlbyname("kern.squeue.submitted", &sub1v, &sz, NULL, 0);
		sz = sizeof(uint64_t);
		(void)sysctlbyname("kern.squeue.completed", &comp1, &sz, NULL, 0);
		if (sub1v <= sub0 || comp1 <= comp0)
			return (29);
	}

	/*
	 * 12: capability-mode confinement.  A native squeue ring in capability
	 * mode may only touch registered (fixed) files, never raw ambient fds.
	 * cap_enter() is irreversible, so run this in a child.
	 */
	{
		pid_t pid = fork();

		if (pid == 0) {
			char cb[8];
			int cfd, rf;

			(void)unlink("/tmp/squeue_cap.tmp");
			cfd = open("/tmp/squeue_cap.tmp",
			    O_RDWR | O_CREAT | O_EXCL, 0600);
			if (cfd < 0)
				_exit(31);
			if (pwrite(cfd, "CAPMODE", 7, 0) != 7)
				_exit(32);
			/* register the file BEFORE entering capability mode */
			rf = cfd;
			if (syscall(SYS_squeue_register, ring_fd, REGISTER_FILES,
			    &rf, 1) != 0)
				_exit(33);
			if (cap_enter() != 0)
				_exit(34);
			/* a raw ambient-fd op is refused in capability mode */
			if (one(OP_READ, cfd, cb, 7, 0, 0, 0xA) != -ENOTCAPABLE)
				_exit(35);
			/* IOSQE_ASYNC must not offload a raw fd around the check */
			if (one_flags(OP_READ, IOSQE_ASYNC, cfd, cb, 7, 0, 0xC)
			    != -ENOTCAPABLE)
				_exit(37);
			/* the registered (fixed index 0) file still works */
			memset(cb, 0, sizeof(cb));
			if (one_flags(OP_READ, IOSQE_FIXED_FILE, 0, cb, 7, 0,
			    0xB) != 7 || memcmp(cb, "CAPMODE", 7) != 0)
				_exit(36);
			_exit(0);
		} else if (pid < 0) {
			return (22);
		} else {
			int st;

			if (waitpid(pid, &st, 0) != pid)
				return (23);
			if (!WIFEXITED(st))
				return (24);
			if (WEXITSTATUS(st) != 0)
				return (WEXITSTATUS(st));
		}
	}

	/*
	 * 13: IORING_SETUP_CQSIZE / IORING_SETUP_CLAMP.  The CQ can be sized
	 * independently of the SQ (rounded up to a power of two, >= SQ, bounded
	 * by SQ_MAX_CQ_ENTRIES); CLAMP turns over-cap requests into clamps
	 * instead of errors.  These fresh rings do not touch the main ring.
	 */
	{
		struct io_uring_params cp;
		long cr;

		/* default (no CQSIZE): cq_entries == 2 * sq_entries */
		memset(&cp, 0, sizeof(cp));
		cr = sq_setup(8, &cp);
		if (cr < 0 || cp.sq_entries != 8 || cp.cq_entries != 16)
			return (40);
		(void)close((int)cr);

		/* CQSIZE: caller sizes the CQ; 64 is already a power of two */
		memset(&cp, 0, sizeof(cp));
		cp.flags = IORING_SETUP_CQSIZE;
		cp.cq_entries = 64;
		cr = sq_setup(4, &cp);
		if (cr < 0 || cp.sq_entries != 4 || cp.cq_entries != 64)
			return (41);
		(void)close((int)cr);

		/* CQSIZE: a non-pow2 request is rounded up (100 -> 128) */
		memset(&cp, 0, sizeof(cp));
		cp.flags = IORING_SETUP_CQSIZE;
		cp.cq_entries = 100;
		cr = sq_setup(8, &cp);
		if (cr < 0 || cp.cq_entries != 128)
			return (42);
		(void)close((int)cr);

		/* CQSIZE with cq_entries == 0 is invalid */
		memset(&cp, 0, sizeof(cp));
		cp.flags = IORING_SETUP_CQSIZE;
		cp.cq_entries = 0;
		if (sq_setup(8, &cp) >= 0)
			return (43);

		/* CQSIZE smaller than the SQ is invalid (16 SQ, 4 CQ) */
		memset(&cp, 0, sizeof(cp));
		cp.flags = IORING_SETUP_CQSIZE;
		cp.cq_entries = 4;
		if (sq_setup(16, &cp) >= 0)
			return (44);

		/* an unsupported setup flag is rejected */
		memset(&cp, 0, sizeof(cp));
		cp.flags = 0x2 /* IORING_SETUP_SQPOLL */;
		if (sq_setup(8, &cp) >= 0)
			return (45);

		/* over-cap SQ without CLAMP is an error ... */
		memset(&cp, 0, sizeof(cp));
		if (sq_setup(SQ_MAX_ENTRIES_T + 1, &cp) >= 0)
			return (46);

		/* ... but CLAMP clamps SQ to the cap (and default CQ = 2x) */
		memset(&cp, 0, sizeof(cp));
		cp.flags = IORING_SETUP_CLAMP;
		cr = sq_setup(SQ_MAX_ENTRIES_T + 1, &cp);
		if (cr < 0 || cp.sq_entries != SQ_MAX_ENTRIES_T ||
		    cp.cq_entries != SQ_MAX_ENTRIES_T * 2)
			return (47);
		(void)close((int)cr);
	}

	(void)syscall(SYS_close, ring_fd);
	return (0);
}
