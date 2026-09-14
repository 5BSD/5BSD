/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * squeue: the native 5BSD completion-ring engine shared by the native
 * squeue_* syscalls and the Linux io_uring front-end.  This header holds the
 * kernel-internal engine types, the front-end description, and the engine KPI.
 *
 * Includers must already have pulled in <sys/queue.h>, <sys/callout.h>,
 * <sys/selinfo.h>, <sys/lock.h>, <sys/mutex.h>, <sys/uio.h>, <vm/vm.h>,
 * <vm/vm_object.h> and <sys/io_uring.h> (for the on-ring structures).
 */
#ifndef _SYS_SQUEUE_H_
#define	_SYS_SQUEUE_H_

#ifdef _KERNEL

#define	SQ_MAX_ENTRIES		32768
#define	SQ_MAX_CQ_ENTRIES	(SQ_MAX_ENTRIES * 2)	/* IORING_SETUP_CQSIZE */
#define	SQ_MSG_DONTWAIT	0x40	/* Linux MSG_DONTWAIT */
#define	SQ_MAX_REG_FILES	4096
#define	SQ_MAX_REG_BUFS	1024
#define	SQ_MAX_PBUFS		65536
#define	SQ_LINUX_ETIME		62	/* Linux ETIME (no BSD equivalent) */

/*
 * Sentinel returned by the ABI-neutral core for an opcode it does not handle
 * itself; sq_issue_op then routes the request to the front-end's issue_ext
 * hook.  Byte counts are >= 0 and real errnos are small-negative, so INT32_MIN
 * never collides with a real result.
 */
#define	SQ_NOTHANDLED		INT32_MIN

/* Request lifecycle. */
enum sq_state {
	SQ_ST_NEW = 0,		/* freshly prepped, not yet issued */
	SQ_ST_ARMED,		/* async op waiting on ctx->pending */
	SQ_ST_READY,		/* resolved, on ctx->ready, CQE not yet posted */
};

struct squeue_ctx;

/*
 * A single tracked request.  Members reachable only from the owning thread
 * (link_next while a chain is being built) need no lock; membership on the
 * ctx->pending / ctx->ready / ctx->drain lists and the state/res fields are
 * protected by ctx->mtx.
 */
struct sq_req {
	TAILQ_ENTRY(sq_req)	entry;		/* pending / ready / drain */
	struct squeue_ctx	*ctx;
	struct sq_req		*link_next;	/* next SQE in this link chain */
	struct io_uring_sqe	sqe;		/* private, stable copy */
	struct callout		co;		/* TIMEOUT */
	uint64_t		user_data;
	uint8_t			opcode;
	uint8_t			sqe_flags;
	enum sq_state		state;
	int32_t			res;		/* completion result */
	uint32_t		cflags;		/* CQE flags */
	bool			posted;		/* op already posted its CQE(s) */
	bool			retry;		/* fast-poll: re-issue when ready */
	bool			tmo_count;	/* count-based timeout armed */
	uint32_t		tmo_target;	/* cq_count value that fires it */
	/*
	 * Fields below are appended (never inserted) and are touched only by
	 * the ABI-neutral engine, never by a front-end.  Keeping them at the
	 * end preserves the offsets of every field the Linux front-end reads,
	 * so the engine and the io_uring module stay binary-compatible.
	 */
	TAILQ_ENTRY(sq_req)	wq;		/* async worker-pool queue */
	/* async worker offload (IOSQE_ASYNC file I/O): set on the submitting
	 * thread, consumed and cleared by the worker before the req is readied */
	struct file		*ofp;		/* held target file */
	struct uio		*ouio;		/* prepared user-space uio */
	struct vmspace		*ovm;		/* owner address space (ref held) */
	bool			owrite;		/* offloaded op is a write */
	bool			ocur;		/* use current file offset */
	bool			multishot;	/* POLL_ADD multishot: stay armed */
};

/*
 * Ring layout (offsets reported to userspace via sq_off/cq_off, so the exact
 * placement is private).  Region 0 (SQ_RING & CQ_RING, single mmap): this
 * header + cqes[] + the SQ index array.  Region 1 (SQES): io_uring_sqe[].
 */
struct sq_rings {
	uint32_t	sq_head;
	uint32_t	sq_tail;
	uint32_t	cq_head;
	uint32_t	cq_tail;
	uint32_t	sq_ring_mask;
	uint32_t	cq_ring_mask;
	uint32_t	sq_ring_entries;
	uint32_t	cq_ring_entries;
	uint32_t	sq_dropped;
	uint32_t	sq_flags;
	uint32_t	cq_flags;
	uint32_t	cq_overflow;
};

TAILQ_HEAD(sq_reqq, sq_req);

/*
 * A completion that could not be written to the CQ because it was full.
 * Backlogged in submission order and flushed into the CQ as the application
 * drains it, so a completion is never lost (IORING_FEAT_NODROP).
 */
struct sq_ovfl {
	TAILQ_ENTRY(sq_ovfl)	entry;
	uint64_t		user_data;
	int32_t			res;
	uint32_t		cflags;
};
TAILQ_HEAD(sq_ovflq, sq_ovfl);

/* A single application-provided buffer (PROVIDE_BUFFERS / BUFFER_SELECT). */
struct sq_pbuf {
	TAILQ_ENTRY(sq_pbuf)	entry;
	uint16_t		bgid;	/* buffer group */
	uint16_t		bid;	/* buffer id within the group */
	uint64_t		addr;
	uint32_t		len;
};
TAILQ_HEAD(sq_pbufq, sq_pbuf);

struct squeue_ctx {
	struct mtx	mtx;
	struct selinfo	sel;		/* poll/kqueue on CQ readiness */
	vm_object_t	obj;		/* wired ring backing store */
	char		*kva;		/* kernel mapping of obj */
	vm_size_t	objsize;	/* total object/kva size */
	vm_size_t	ring_region;	/* bytes of region 0 (page-rounded) */
	vm_size_t	sqes_off;	/* obj offset of the SQES region */
	vm_size_t	sqes_size;
	struct sq_rings *rings;
	struct io_uring_cqe *cqes;
	uint32_t	*sq_array;
	struct io_uring_sqe *sqes;
	uint32_t	sq_entries;
	uint32_t	cq_entries;
	uint32_t	sq_mask;
	uint32_t	cq_mask;
	uint32_t	setup_flags;
	bool		is_linux;	/* front-end ABI: Linux vs native 5BSD */
	/* Front-end hook for ABI-specific (non-neutral) opcodes; NULL = none. */
	int32_t		(*issue_ext)(struct squeue_ctx *, struct sq_req *,
			    struct thread *);
	/* Front-end errno translator (BSD errno -> negative ABI errno). */
	int		(*err_xlate)(int);
	int		cq_waiters;
	/* async request tracking (all under mtx) */
	struct sq_reqq	pending;	/* SQ_ST_ARMED reqs */
	struct sq_reqq	ready;		/* SQ_ST_READY reqs, need draining */
	struct sq_reqq	drain;		/* chain heads held by a barrier */
	int		npending;	/* length of pending */
	uint32_t	cq_count;	/* real completions, for count timeouts */
	/* registered resources (set once, read under mtx) */
	struct iovec	*reg_bufs;	/* REGISTER_BUFFERS */
	uint32_t	reg_nbufs;
	struct file	**reg_files;	/* REGISTER_FILES (held references) */
	struct filecaps	*reg_caps;	/* per-file capsicum rights, captured at
					 * register time and re-applied to the
					 * transient fd on each fixed-file op */
	uint32_t	reg_nfiles;
	struct sq_pbufq pbufs;		/* PROVIDE_BUFFERS pool */
	uint32_t	npbufs;		/* provided buffers held (bounded) */
	struct sq_reqq	polls;		/* armed POLL_ADD requests */
	int		npolls;
	/*
	 * Appended (never inserted) so the offsets of every field the Linux
	 * front-end reads stay fixed and the engine/module remain binary-
	 * compatible.  refs = the ring file's reference plus one per in-flight
	 * worker-pool job, so the context outlives an offloaded request.
	 */
	int		refs;
	/*
	 * Per-ring kqueue used for readiness: armed POLL_ADD targets and
	 * fast-poll retry fds are registered here (plus the ring itself, so a
	 * single kevent wait covers completions and target readiness).  Created
	 * lazily on first readiness need; held as a file * (its transient fd is
	 * closed).  Engine-internal - a front-end never touches it.
	 */
	struct file	*kqfp;
	bool		kq_ring_armed;	/* the ring's own knote is registered */
	struct sq_ovflq	overflow;	/* CQEs awaiting CQ space (NODROP backlog) */
	uint32_t	noverflow;	/* current backlog length (bounded) */
	/* REGISTER_EVENTFD: signalled on every posted completion. */
	struct file	*eventfd_fp;	/* held eventfd reference, or NULL */
	struct eventfd	*eventfd;	/* efd to signal (eventfd_fp->f_data) */
};

/*
 * Front-end description passed to kern_squeue_setup: which ABI the ring serves
 * and how it translates errnos / handles non-core opcodes.  A native ("squeue")
 * front-end passes is_linux=false and NULL hooks; the Linux io_uring front-end
 * passes its translator and opcode extension.
 */
struct sq_frontend {
	bool		is_linux;
	int		(*err_xlate)(int);
	int32_t		(*issue_ext)(struct squeue_ctx *, struct sq_req *,
			    struct thread *);
};

/* Engine helpers a front-end's issue_ext hook may call. */
void	sq_post_cqe(struct squeue_ctx *ctx, uint64_t user_data,
	    int32_t res, uint32_t cflags);
void	sq_wake(struct squeue_ctx *ctx);
int32_t	sq_result(struct squeue_ctx *ctx, struct thread *td, int error);
int32_t	sq_err(struct squeue_ctx *ctx, int bsd_errno);

/* Engine KPI: both the native squeue_* syscalls and the Linux front-end. */
int	kern_squeue_setup(struct thread *td, uint32_t entries,
	    struct io_uring_params *params, const struct sq_frontend *fe,
	    int *fdp);
int	kern_squeue_enter(struct thread *td, int fd, uint32_t to_submit,
	    uint32_t min_complete, uint32_t flags, const void *arg,
	    size_t argsz);
int	kern_squeue_register(struct thread *td, int fd, uint32_t op,
	    void *arg, uint32_t nr_args);

#endif /* _KERNEL */
#endif /* _SYS_SQUEUE_H_ */
