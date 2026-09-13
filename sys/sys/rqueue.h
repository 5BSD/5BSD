/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * rqueue: the native 5BSD completion-ring engine shared by the native
 * rqueue_* syscalls and the Linux io_uring front-end.  This header holds the
 * kernel-internal engine types, the front-end description, and the engine KPI.
 *
 * Includers must already have pulled in <sys/queue.h>, <sys/callout.h>,
 * <sys/selinfo.h>, <sys/lock.h>, <sys/mutex.h>, <sys/uio.h>, <vm/vm.h>,
 * <vm/vm_object.h> and <sys/io_uring.h> (for the on-ring structures).
 */
#ifndef _SYS_RQUEUE_H_
#define	_SYS_RQUEUE_H_

#ifdef _KERNEL

#define	IOU_MAX_ENTRIES		32768
#define	IOU_MSG_DONTWAIT	0x40	/* Linux MSG_DONTWAIT */
#define	IOU_MAX_REG_FILES	4096
#define	IOU_MAX_REG_BUFS	1024
#define	IOU_MAX_PBUFS		65536
#define	IOU_LINUX_ETIME		62	/* Linux ETIME (no BSD equivalent) */

/*
 * Sentinel returned by the ABI-neutral core for an opcode it does not handle
 * itself; iou_issue_op then routes the request to the front-end's issue_ext
 * hook.  Byte counts are >= 0 and real errnos are small-negative, so INT32_MIN
 * never collides with a real result.
 */
#define	IOU_NOTHANDLED		INT32_MIN

/* Request lifecycle. */
enum iou_state {
	IOU_ST_NEW = 0,		/* freshly prepped, not yet issued */
	IOU_ST_ARMED,		/* async op waiting on ctx->pending */
	IOU_ST_READY,		/* resolved, on ctx->ready, CQE not yet posted */
};

struct io_uring_ctx;

/*
 * A single tracked request.  Members reachable only from the owning thread
 * (link_next while a chain is being built) need no lock; membership on the
 * ctx->pending / ctx->ready / ctx->drain lists and the state/res fields are
 * protected by ctx->mtx.
 */
struct iou_req {
	TAILQ_ENTRY(iou_req)	entry;		/* pending / ready / drain */
	struct io_uring_ctx	*ctx;
	struct iou_req		*link_next;	/* next SQE in this link chain */
	struct io_uring_sqe	sqe;		/* private, stable copy */
	struct callout		co;		/* TIMEOUT */
	uint64_t		user_data;
	uint8_t			opcode;
	uint8_t			sqe_flags;
	enum iou_state		state;
	int32_t			res;		/* completion result */
	uint32_t		cflags;		/* CQE flags */
	bool			posted;		/* op already posted its CQE(s) */
	bool			retry;		/* fast-poll: re-issue when ready */
	bool			tmo_count;	/* count-based timeout armed */
	uint32_t		tmo_target;	/* cq_count value that fires it */
};

/*
 * Ring layout (offsets reported to userspace via sq_off/cq_off, so the exact
 * placement is private).  Region 0 (SQ_RING & CQ_RING, single mmap): this
 * header + cqes[] + the SQ index array.  Region 1 (SQES): io_uring_sqe[].
 */
struct iou_rings {
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

TAILQ_HEAD(iou_reqq, iou_req);

/* A single application-provided buffer (PROVIDE_BUFFERS / BUFFER_SELECT). */
struct iou_pbuf {
	TAILQ_ENTRY(iou_pbuf)	entry;
	uint16_t		bgid;	/* buffer group */
	uint16_t		bid;	/* buffer id within the group */
	uint64_t		addr;
	uint32_t		len;
};
TAILQ_HEAD(iou_pbufq, iou_pbuf);

struct io_uring_ctx {
	struct mtx	mtx;
	struct selinfo	sel;		/* poll/kqueue on CQ readiness */
	vm_object_t	obj;		/* wired ring backing store */
	char		*kva;		/* kernel mapping of obj */
	vm_size_t	objsize;	/* total object/kva size */
	vm_size_t	ring_region;	/* bytes of region 0 (page-rounded) */
	vm_size_t	sqes_off;	/* obj offset of the SQES region */
	vm_size_t	sqes_size;
	struct iou_rings *rings;
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
	int32_t		(*issue_ext)(struct io_uring_ctx *, struct iou_req *,
			    struct thread *);
	/* Front-end errno translator (BSD errno -> negative ABI errno). */
	int		(*err_xlate)(int);
	int		cq_waiters;
	/* async request tracking (all under mtx) */
	struct iou_reqq	pending;	/* IOU_ST_ARMED reqs */
	struct iou_reqq	ready;		/* IOU_ST_READY reqs, need draining */
	struct iou_reqq	drain;		/* chain heads held by a barrier */
	int		npending;	/* length of pending */
	uint32_t	cq_count;	/* real completions, for count timeouts */
	/* registered resources (set once, read under mtx) */
	struct iovec	*reg_bufs;	/* REGISTER_BUFFERS */
	uint32_t	reg_nbufs;
	struct file	**reg_files;	/* REGISTER_FILES (held references) */
	uint32_t	reg_nfiles;
	struct iou_pbufq pbufs;		/* PROVIDE_BUFFERS pool */
	struct iou_reqq	polls;		/* armed POLL_ADD requests */
	int		npolls;
};

/*
 * Front-end description passed to kern_rqueue_setup: which ABI the ring serves
 * and how it translates errnos / handles non-core opcodes.  A native ("rqueue")
 * front-end passes is_linux=false and NULL hooks; the Linux io_uring front-end
 * passes its translator and opcode extension.
 */
struct iou_frontend {
	bool		is_linux;
	int		(*err_xlate)(int);
	int32_t		(*issue_ext)(struct io_uring_ctx *, struct iou_req *,
			    struct thread *);
};

/* Engine helpers a front-end's issue_ext hook may call. */
void	iou_post_cqe(struct io_uring_ctx *ctx, uint64_t user_data,
	    int32_t res, uint32_t cflags);
void	iou_wake(struct io_uring_ctx *ctx);
int32_t	iou_result(struct io_uring_ctx *ctx, struct thread *td, int error);
int32_t	iou_err(struct io_uring_ctx *ctx, int bsd_errno);

/* Engine KPI: both the native rqueue_* syscalls and the Linux front-end. */
int	kern_rqueue_setup(struct thread *td, uint32_t entries,
	    struct io_uring_params *params, const struct iou_frontend *fe,
	    int *fdp);
int	kern_rqueue_enter(struct thread *td, int fd, uint32_t to_submit,
	    uint32_t min_complete, uint32_t flags, const void *arg,
	    size_t argsz);
int	kern_rqueue_register(struct thread *td, int fd, uint32_t op,
	    void *arg, uint32_t nr_args);

#endif /* _KERNEL */
#endif /* _SYS_RQUEUE_H_ */
