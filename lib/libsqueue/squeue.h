/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libsqueue: an ergonomic userland interface to the 5BSD squeue (Shared Queue)
 * completion-ring engine, so applications need not hand-roll the ring mmaps
 * and head/tail bookkeeping.  The API mirrors the common liburing shape.
 *
 * The engine is io_uring-compatible on the wire, so the on-ring structures and
 * the IORING_ and IOSQE_ constants come from <sys/io_uring.h>; this header adds
 * the setup, submission-entry preparation, submission and completion helpers.
 * It is header-only (all inline); no library need be linked.
 */
#ifndef _SQUEUE_H_
#define	_SQUEUE_H_

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/io_uring.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>

#define	SQUEUE_OFF_SQ_RING	0ULL
#define	SQUEUE_OFF_SQES		0x10000000ULL

struct squeue {
	int		 sq_fd;		/* ring descriptor */
	void		*sq_ring;	/* SQ/CQ ring mapping (region 0) */
	size_t		 sq_ringsz;
	struct io_uring_sqe *sq_sqes;	/* SQE array (region 1) */
	size_t		 sq_sqesz;
	/* cached ring pointers */
	_Atomic uint32_t *sq_khead;	/* kernel-owned SQ head */
	_Atomic uint32_t *sq_ktail;	/* SQ tail (we advance) */
	uint32_t	*sq_array;
	_Atomic uint32_t *cq_khead;	/* CQ head (we advance) */
	_Atomic uint32_t *cq_ktail;	/* kernel-owned CQ tail */
	struct io_uring_cqe *cq_cqes;
	uint32_t	 sq_mask;
	uint32_t	 cq_mask;
	uint32_t	 sq_entries;
	uint32_t	 cq_entries;
	uint32_t	 sq_sqetail;	/* our local SQE fill position */
};

/*
 * Create a ring able to hold at least "entries" submissions and map its
 * regions.  Returns 0 on success or a negative errno.
 */
static inline int
squeue_init(struct squeue *q, unsigned entries)
{
	struct io_uring_params p;
	long fd;
	uint32_t ringsz;

	memset(q, 0, sizeof(*q));
	memset(&p, 0, sizeof(p));
	fd = syscall(SYS_squeue_setup, entries, &p);
	if (fd < 0)
		return (-errno);
	q->sq_fd = (int)fd;
	q->sq_entries = p.sq_entries;
	q->cq_entries = p.cq_entries;
	ringsz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
	if (p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe) > ringsz)
		ringsz = p.cq_off.cqes +
		    p.cq_entries * sizeof(struct io_uring_cqe);
	q->sq_ringsz = ringsz;
	q->sq_ring = mmap(NULL, ringsz, PROT_READ | PROT_WRITE, MAP_SHARED,
	    q->sq_fd, SQUEUE_OFF_SQ_RING);
	if (q->sq_ring == MAP_FAILED)
		goto fail;
	q->sq_sqesz = p.sq_entries * sizeof(struct io_uring_sqe);
	q->sq_sqes = (struct io_uring_sqe *)mmap(NULL, q->sq_sqesz,
	    PROT_READ | PROT_WRITE, MAP_SHARED, q->sq_fd, SQUEUE_OFF_SQES);
	if (q->sq_sqes == MAP_FAILED)
		goto fail;
	/* The ring base is page-aligned and every offset field is naturally
	 * aligned, so these casts are safe; the (void *) hop tells the compiler
	 * so (-Wcast-align). */
	q->sq_khead = (_Atomic uint32_t *)(void *)((char *)q->sq_ring +
	    p.sq_off.head);
	q->sq_ktail = (_Atomic uint32_t *)(void *)((char *)q->sq_ring +
	    p.sq_off.tail);
	q->sq_array = (uint32_t *)(void *)((char *)q->sq_ring + p.sq_off.array);
	q->cq_khead = (_Atomic uint32_t *)(void *)((char *)q->sq_ring +
	    p.cq_off.head);
	q->cq_ktail = (_Atomic uint32_t *)(void *)((char *)q->sq_ring +
	    p.cq_off.tail);
	q->cq_cqes = (struct io_uring_cqe *)(void *)((char *)q->sq_ring +
	    p.cq_off.cqes);
	q->sq_mask = p.sq_entries - 1;
	q->cq_mask = p.cq_entries - 1;
	q->sq_sqetail = atomic_load_explicit(q->sq_ktail, memory_order_relaxed);
	return (0);
fail:
	{
		int e = errno;

		if (q->sq_ring != MAP_FAILED && q->sq_ring != NULL)
			munmap(q->sq_ring, q->sq_ringsz);
		(void)close(q->sq_fd);
		return (-e);
	}
}

static inline void
squeue_exit(struct squeue *q)
{

	if (q->sq_sqes != NULL && q->sq_sqes != MAP_FAILED)
		munmap(q->sq_sqes, q->sq_sqesz);
	if (q->sq_ring != NULL && q->sq_ring != MAP_FAILED)
		munmap(q->sq_ring, q->sq_ringsz);
	if (q->sq_fd >= 0)
		(void)close(q->sq_fd);
	memset(q, 0, sizeof(*q));
	q->sq_fd = -1;
}

/*
 * Obtain the next free submission entry, or NULL if the ring is full (the
 * kernel has not consumed enough).  The returned SQE is zeroed.
 */
static inline struct io_uring_sqe *
squeue_get_sqe(struct squeue *q)
{
	uint32_t head, next;
	struct io_uring_sqe *sqe;

	head = atomic_load_explicit(q->sq_khead, memory_order_acquire);
	next = q->sq_sqetail + 1;
	if (next - head > q->sq_entries)
		return (NULL);		/* SQ full */
	sqe = &q->sq_sqes[q->sq_sqetail & q->sq_mask];
	q->sq_sqetail = next;
	memset(sqe, 0, sizeof(*sqe));
	return (sqe);
}

/* ---- submission-entry preparation ---- */
static inline void
squeue_prep_nop(struct io_uring_sqe *sqe)
{

	sqe->opcode = IORING_OP_NOP;
}
static inline void
squeue_prep_rw(struct io_uring_sqe *sqe, uint8_t op, int fd, const void *addr,
    unsigned len, uint64_t off)
{

	sqe->opcode = op;
	sqe->fd = fd;
	sqe->off = off;
	sqe->addr = (uint64_t)(uintptr_t)addr;
	sqe->len = len;
}
static inline void
squeue_prep_read(struct io_uring_sqe *sqe, int fd, void *buf, unsigned n,
    uint64_t off)
{

	squeue_prep_rw(sqe, IORING_OP_READ, fd, buf, n, off);
}
static inline void
squeue_prep_write(struct io_uring_sqe *sqe, int fd, const void *buf, unsigned n,
    uint64_t off)
{

	squeue_prep_rw(sqe, IORING_OP_WRITE, fd, buf, n, off);
}
static inline void
squeue_prep_readv(struct io_uring_sqe *sqe, int fd, const struct iovec *iov,
    unsigned nr, uint64_t off)
{

	squeue_prep_rw(sqe, IORING_OP_READV, fd, iov, nr, off);
}
static inline void
squeue_prep_writev(struct io_uring_sqe *sqe, int fd, const struct iovec *iov,
    unsigned nr, uint64_t off)
{

	squeue_prep_rw(sqe, IORING_OP_WRITEV, fd, iov, nr, off);
}
static inline void
squeue_prep_fsync(struct io_uring_sqe *sqe, int fd, unsigned fsync_flags)
{

	sqe->opcode = IORING_OP_FSYNC;
	sqe->fd = fd;
	sqe->fsync_flags = fsync_flags;
}
static inline void
squeue_prep_poll_add(struct io_uring_sqe *sqe, int fd, unsigned poll_mask)
{

	sqe->opcode = IORING_OP_POLL_ADD;
	sqe->fd = fd;
	sqe->poll32_events = poll_mask;
}
static inline void
squeue_sqe_set_data(struct io_uring_sqe *sqe, uint64_t user_data)
{

	sqe->user_data = user_data;
}
static inline void
squeue_sqe_set_flags(struct io_uring_sqe *sqe, uint8_t flags)
{

	sqe->flags = flags;
}

/* ---- submission ---- */
/* Publish prepared SQEs; returns the number submitted or a negative errno. */
static inline int
squeue_submit_and_wait(struct squeue *q, unsigned wait_nr)
{
	uint32_t ktail, i;
	unsigned to_submit;
	long r;

	ktail = atomic_load_explicit(q->sq_ktail, memory_order_relaxed);
	to_submit = q->sq_sqetail - ktail;
	/* fill the SQ index array for the newly prepared entries in order */
	for (i = 0; i < to_submit; i++) {
		uint32_t idx = ktail + i;

		q->sq_array[idx & q->sq_mask] = idx & q->sq_mask;
	}
	atomic_store_explicit(q->sq_ktail, q->sq_sqetail, memory_order_release);
	r = syscall(SYS_squeue_enter, q->sq_fd, to_submit, wait_nr,
	    wait_nr > 0 ? IORING_ENTER_GETEVENTS : 0, NULL, 0);
	if (r < 0)
		return (-errno);
	return ((int)r);
}
static inline int
squeue_submit(struct squeue *q)
{

	return (squeue_submit_and_wait(q, 0));
}

/* ---- completion ---- */
/* Peek at the next completion without consuming it; 0 if none available. */
static inline struct io_uring_cqe *
squeue_peek_cqe(struct squeue *q)
{
	uint32_t head, tail;

	head = atomic_load_explicit(q->cq_khead, memory_order_relaxed);
	tail = atomic_load_explicit(q->cq_ktail, memory_order_acquire);
	if (head == tail)
		return (NULL);
	return (&q->cq_cqes[head & q->cq_mask]);
}
/* Wait for and return the next completion (blocks via squeue_enter). */
static inline int
squeue_wait_cqe(struct squeue *q, struct io_uring_cqe **cqep)
{
	struct io_uring_cqe *cqe;
	long r;

	for (;;) {
		cqe = squeue_peek_cqe(q);
		if (cqe != NULL) {
			*cqep = cqe;
			return (0);
		}
		r = syscall(SYS_squeue_enter, q->sq_fd, 0, 1,
		    IORING_ENTER_GETEVENTS, NULL, 0);
		if (r < 0)
			return (-errno);
	}
}
/* Mark one previously peeked/waited completion as consumed. */
static inline void
squeue_cqe_seen(struct squeue *q, struct io_uring_cqe *cqe __unused)
{
	uint32_t head;

	head = atomic_load_explicit(q->cq_khead, memory_order_relaxed);
	atomic_store_explicit(q->cq_khead, head + 1, memory_order_release);
}

/* ---- registration ---- */
static inline int
squeue_register_files(struct squeue *q, const int *fds, unsigned nr)
{

	if (syscall(SYS_squeue_register, q->sq_fd, IORING_REGISTER_FILES,
	    (void *)(uintptr_t)fds, nr) != 0)
		return (-errno);
	return (0);
}
static inline int
squeue_register_buffers(struct squeue *q, const struct iovec *iov, unsigned nr)
{

	if (syscall(SYS_squeue_register, q->sq_fd, IORING_REGISTER_BUFFERS,
	    (void *)(uintptr_t)iov, nr) != 0)
		return (-errno);
	return (0);
}
static inline int
squeue_register_eventfd(struct squeue *q, int efd)
{

	if (syscall(SYS_squeue_register, q->sq_fd, IORING_REGISTER_EVENTFD,
	    &efd, 1) != 0)
		return (-errno);
	return (0);
}

/* Library version accessors (the only out-of-line symbols; -lsqueue). */
int	squeue_major_version(void);
int	squeue_minor_version(void);

#endif /* _SQUEUE_H_ */
