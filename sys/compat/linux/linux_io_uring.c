/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * io_uring for the Linuxulator - engine + Linux front-end.
 *
 * The engine (iou_* / kern_io_uring_*) is ABI-neutral and written as the
 * native core described in docs/linuxulator-io_uring-design.md; it is built
 * into the Linux module and exercised through the Linux ABI.
 *
 * Phases 1-3 implement the shared SQ/CQ/SQE rings (a wired OBJT_PHYS object
 * dual-mapped into the kernel and, via fo_mmap, into the process), the
 * setup/enter/register syscalls, the submit/complete/wait loop, and the
 * synchronous file opcodes (NOP, READ, WRITE, READV, WRITEV, FSYNC, CLOSE,
 * FTRUNCATE, FALLOCATE, FADVISE) plus IORING_REGISTER_PROBE.
 *
 * Phase 4 adds the asynchronous request model: requests are tracked as
 * struct iou_req, SQEs are grouped into link chains (IOSQE_IO_LINK /
 * IOSQE_IO_HARDLINK), IOSQE_IO_DRAIN acts as a barrier, IOSQE_CQE_SKIP_SUCCESS
 * elides successful CQEs, and the TIMEOUT / TIMEOUT_REMOVE / ASYNC_CANCEL
 * opcodes are supported.  Synchronous opcodes still complete inline in the
 * submitting thread's context; an asynchronous op (TIMEOUT) arms and completes
 * later from callout context, and any linked successor runs when a thread next
 * drives io_uring_enter (which has the correct fd table and can block on I/O),
 * so no kernel worker needs to borrow the caller's file table.
 *
 * An unimplemented opcode completes with res = -EINVAL and is reported
 * unsupported by PROBE, exactly as a Linux kernel lacking it would.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/rwlock.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/sbuf.h>
#include <sys/syscallsubr.h>
#include <sys/uio.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/pmap.h>

#include <sys/io_uring.h>

#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#include <compat/linux/linux_util.h>
#include <compat/linux/linux.h>
#include <compat/linux/linux_errno.h>

#define	IOU_MAX_ENTRIES		32768
#define	IOU_MSG_DONTWAIT	0x40	/* Linux MSG_DONTWAIT */

/*
 * Sentinel returned by the ABI-neutral core for an opcode it does not handle
 * itself; iou_issue_op then routes the request to the front-end's issue_ext
 * hook (the Linux-flavored opcodes live there).  Byte counts are >= 0 and real
 * errnos are small-negative, so INT32_MIN never collides with a real result.
 */
#define	IOU_NOTHANDLED		INT32_MIN

MALLOC_DEFINE(M_LINUX_IOURING, "linux_iouring", "Linux io_uring");

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
	int32_t			res;		/* completion result (Linux) */
	uint32_t		cflags;		/* CQE flags */
	bool			posted;		/* op already posted its CQE(s) */
	bool			retry;		/* fast-poll: re-issue when ready */
	bool			tmo_count;	/* count-based timeout armed */
	uint32_t		tmo_target;	/* cq_count value that fires it */
};

/*
 * Our ring layout (offsets are reported to userspace via sq_off/cq_off, so
 * the exact placement is private; liburing follows the reported offsets).
 * Region 0 (SQ_RING & CQ_RING, single mmap): io_rings header + cqes[] + the
 * SQ index array.  Region 1 (SQES): io_uring_sqe[].
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
	/* cqes[] follows at cqes_off; sq index array follows at array_off. */
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

#define	IOU_MAX_PBUFS		65536

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

#define	IOU_MAX_REG_FILES	4096
#define	IOU_MAX_REG_BUFS	1024

/* ---- opcode support matrix (drives dispatch + PROBE) ---- */
static bool
iou_op_supported(uint8_t op)
{

	switch (op) {
	case IORING_OP_NOP:
	case IORING_OP_READ:
	case IORING_OP_WRITE:
	case IORING_OP_READV:
	case IORING_OP_WRITEV:
	case IORING_OP_READ_MULTISHOT:
	case IORING_OP_READ_FIXED:
	case IORING_OP_WRITE_FIXED:
	case IORING_OP_FSYNC:
	case IORING_OP_CLOSE:
	case IORING_OP_FTRUNCATE:
	case IORING_OP_FALLOCATE:
	case IORING_OP_FADVISE:
	case IORING_OP_TIMEOUT:
	case IORING_OP_TIMEOUT_REMOVE:
	case IORING_OP_ASYNC_CANCEL:
	case IORING_OP_OPENAT:
	case IORING_OP_OPENAT2:
	case IORING_OP_STATX:
	case IORING_OP_RENAMEAT:
	case IORING_OP_UNLINKAT:
	case IORING_OP_MKDIRAT:
	case IORING_OP_SYMLINKAT:
	case IORING_OP_LINKAT:
	case IORING_OP_MADVISE:
	case IORING_OP_SYNC_FILE_RANGE:
	case IORING_OP_SOCKET:
	case IORING_OP_CONNECT:
	case IORING_OP_ACCEPT:
	case IORING_OP_BIND:
	case IORING_OP_LISTEN:
	case IORING_OP_SHUTDOWN:
	case IORING_OP_SEND:
	case IORING_OP_RECV:
	case IORING_OP_SENDMSG:
	case IORING_OP_RECVMSG:
	case IORING_OP_EPOLL_CTL:
	case IORING_OP_FSETXATTR:
	case IORING_OP_SETXATTR:
	case IORING_OP_FGETXATTR:
	case IORING_OP_GETXATTR:
	case IORING_OP_PROVIDE_BUFFERS:
	case IORING_OP_REMOVE_BUFFERS:
	case IORING_OP_FILES_UPDATE:
	case IORING_OP_TEE:
	case IORING_OP_MSG_RING:
	case IORING_OP_READV_FIXED:
	case IORING_OP_WRITEV_FIXED:
	case IORING_OP_NOP128:
	case IORING_OP_PIPE:
	case IORING_OP_SPLICE:
	case IORING_OP_EPOLL_WAIT:
	case IORING_OP_FIXED_FD_INSTALL:
	case IORING_OP_SEND_ZC:
	case IORING_OP_SENDMSG_ZC:
	case IORING_OP_LINK_TIMEOUT:
	case IORING_OP_FUTEX_WAKE:
	case IORING_OP_FUTEX_WAIT:
	case IORING_OP_FUTEX_WAITV:
	case IORING_OP_WAITID:
	case IORING_OP_POLL_ADD:
	case IORING_OP_POLL_REMOVE:
		return (true);
	default:
		return (false);	/* filled in by later phases */
	}
}

static bool
iou_op_async(uint8_t op)
{

	/* Ops that do not complete synchronously in the submitting thread. */
	return (op == IORING_OP_TIMEOUT || op == IORING_OP_POLL_ADD);
}

/*
 * Fast-poll eligibility: ops that, on EAGAIN, should be parked on a readiness
 * poll and re-issued when the target fd is ready (so the ring never blocks the
 * submitting thread on a would-block socket/pipe).  Returns the poll events to
 * wait for, or 0 if the op is not fast-poll eligible.
 */
static short
iou_pollable_events(uint8_t op)
{

	switch (op) {
	case IORING_OP_READ:
	case IORING_OP_READV:
	case IORING_OP_RECV:
	case IORING_OP_RECVMSG:
	case IORING_OP_READ_MULTISHOT:
	case IORING_OP_ACCEPT:
		return (POLLIN);
	case IORING_OP_WRITE:
	case IORING_OP_WRITEV:
	case IORING_OP_SEND:
	case IORING_OP_SENDMSG:
		return (POLLOUT);
	default:
		return (0);
	}
}

/* ---- ring backing store: a wired OBJT_PHYS object, dual-mapped ---- */
static int
iou_ring_alloc(struct io_uring_ctx *ctx)
{
	vm_page_t *ma;
	vm_size_t cqes_off, array_off;
	int i, npages;

	/* Region 0: header, then cqes[cq_entries], then sq array[sq_entries]. */
	cqes_off = roundup2(sizeof(struct iou_rings), sizeof(struct io_uring_cqe));
	array_off = cqes_off + (vm_size_t)ctx->cq_entries * sizeof(struct io_uring_cqe);
	ctx->ring_region = round_page(array_off +
	    (vm_size_t)ctx->sq_entries * sizeof(uint32_t));
	ctx->sqes_off = ctx->ring_region;
	ctx->sqes_size = round_page((vm_size_t)ctx->sq_entries *
	    sizeof(struct io_uring_sqe));
	ctx->objsize = ctx->ring_region + ctx->sqes_size;
	npages = atop(ctx->objsize);

	ctx->obj = vm_pager_allocate(OBJT_PHYS, NULL, ctx->objsize,
	    VM_PROT_DEFAULT, 0, curthread->td_ucred);
	if (ctx->obj == NULL)
		return (ENOMEM);
	ctx->kva = (char *)kva_alloc(ctx->objsize);
	if (ctx->kva == NULL) {
		vm_object_deallocate(ctx->obj);
		ctx->obj = NULL;
		return (ENOMEM);
	}
	ma = malloc(npages * sizeof(*ma), M_LINUX_IOURING, M_WAITOK);
	VM_OBJECT_WLOCK(ctx->obj);
	for (i = 0; i < npages; i++) {
		ma[i] = vm_page_grab(ctx->obj, i, VM_ALLOC_NORMAL |
		    VM_ALLOC_WIRED | VM_ALLOC_ZERO);
		vm_page_valid(ma[i]);
		vm_page_xunbusy(ma[i]);
	}
	VM_OBJECT_WUNLOCK(ctx->obj);
	pmap_qenter(ctx->kva, ma, npages);
	free(ma, M_LINUX_IOURING);

	ctx->rings = (struct iou_rings *)ctx->kva;
	ctx->cqes = (struct io_uring_cqe *)(ctx->kva + cqes_off);
	ctx->sq_array = (uint32_t *)(ctx->kva + array_off);
	ctx->sqes = (struct io_uring_sqe *)(ctx->kva + ctx->sqes_off);

	ctx->rings->sq_ring_mask = ctx->sq_mask = ctx->sq_entries - 1;
	ctx->rings->cq_ring_mask = ctx->cq_mask = ctx->cq_entries - 1;
	ctx->rings->sq_ring_entries = ctx->sq_entries;
	ctx->rings->cq_ring_entries = ctx->cq_entries;
	return (0);
}

static void iou_req_free(struct iou_req *req);

static void
iou_ctx_free(struct io_uring_ctx *ctx)
{
	struct iou_req *req;

	/*
	 * No more references to the ring: drain any outstanding requests.
	 * Callouts are stopped (callout_drain) before the memory is released.
	 */
	while ((req = TAILQ_FIRST(&ctx->pending)) != NULL) {
		TAILQ_REMOVE(&ctx->pending, req, entry);
		iou_req_free(req);
	}
	while ((req = TAILQ_FIRST(&ctx->ready)) != NULL) {
		TAILQ_REMOVE(&ctx->ready, req, entry);
		iou_req_free(req);
	}
	while ((req = TAILQ_FIRST(&ctx->polls)) != NULL) {
		TAILQ_REMOVE(&ctx->polls, req, entry);
		iou_req_free(req);
	}
	while ((req = TAILQ_FIRST(&ctx->drain)) != NULL) {
		TAILQ_REMOVE(&ctx->drain, req, entry);
		while (req != NULL) {
			struct iou_req *next = req->link_next;
			iou_req_free(req);
			req = next;
		}
	}

	{
		struct iou_pbuf *pb;

		while ((pb = TAILQ_FIRST(&ctx->pbufs)) != NULL) {
			TAILQ_REMOVE(&ctx->pbufs, pb, entry);
			free(pb, M_LINUX_IOURING);
		}
	}
	if (ctx->reg_bufs != NULL)
		free(ctx->reg_bufs, M_LINUX_IOURING);
	if (ctx->reg_files != NULL) {
		uint32_t i;

		for (i = 0; i < ctx->reg_nfiles; i++)
			if (ctx->reg_files[i] != NULL)
				fdrop(ctx->reg_files[i], curthread);
		free(ctx->reg_files, M_LINUX_IOURING);
	}
	if (ctx->kva != NULL) {
		pmap_qremove(ctx->kva, atop(ctx->objsize));
		kva_free(ctx->kva, ctx->objsize);
	}
	if (ctx->obj != NULL)
		vm_object_deallocate(ctx->obj);
	seldrain(&ctx->sel);
	knlist_destroy(&ctx->sel.si_note);
	mtx_destroy(&ctx->mtx);
	free(ctx, M_LINUX_IOURING);
}

/* ---- completion ---- */
static void
iou_post_cqe(struct io_uring_ctx *ctx, uint64_t user_data, int32_t res,
    uint32_t cflags)
{
	struct io_uring_cqe *cqe;
	uint32_t tail;

	mtx_assert(&ctx->mtx, MA_OWNED);
	tail = ctx->rings->cq_tail;
	if ((uint32_t)(tail - ctx->rings->cq_head) >= ctx->cq_entries) {
		/* CQ full: NODROP - bump overflow (kept simple, no backlog). */
		ctx->rings->cq_overflow++;
		return;
	}
	cqe = &ctx->cqes[tail & ctx->cq_mask];
	cqe->user_data = user_data;
	cqe->res = res;
	cqe->flags = cflags;
	atomic_thread_fence_rel();
	ctx->rings->cq_tail = tail + 1;
}

static uint32_t
iou_cq_ready(struct io_uring_ctx *ctx)
{

	return (ctx->rings->cq_tail - ctx->rings->cq_head);
}

static void
iou_wake(struct io_uring_ctx *ctx)
{

	mtx_assert(&ctx->mtx, MA_OWNED);
	selwakeuppri(&ctx->sel, PSOCK);
	KNOTE_LOCKED(&ctx->sel.si_note, 0);
	if (ctx->cq_waiters > 0)
		wakeup(&ctx->cq_waiters);
}

/*
 * Post a request's CQE (honouring IOSQE_CQE_SKIP_SUCCESS) and account it for
 * count-based timeouts.  Caller holds ctx->mtx.
 */
static void iou_check_count_timeouts(struct io_uring_ctx *ctx);

static void
iou_complete(struct io_uring_ctx *ctx, struct iou_req *req, int32_t res,
    uint32_t cflags)
{

	mtx_assert(&ctx->mtx, MA_OWNED);
	if (req->posted) {
		/* The op emitted its own CQE(s) (e.g. SEND_ZC notif). */
	} else if (res >= 0 && (req->sqe_flags & IOSQE_CQE_SKIP_SUCCESS) != 0) {
		/* Successful CQE elided by request flag. */
	} else {
		iou_post_cqe(ctx, req->user_data, res, cflags);
	}
	/*
	 * Only "real" completions advance the count that satisfies
	 * count-based timeouts; a timeout expiring must not count toward
	 * another timeout's threshold.
	 */
	if (req->opcode != IORING_OP_TIMEOUT &&
	    req->opcode != IORING_OP_LINK_TIMEOUT) {
		ctx->cq_count++;
		iou_check_count_timeouts(ctx);
	}
	iou_wake(ctx);
}

/* ---- request allocation ---- */
static void
iou_req_free(struct iou_req *req)
{

	callout_drain(&req->co);
	free(req, M_LINUX_IOURING);
}

/* ---- inline (synchronous) opcodes ---- */
/*
 * Translate a (positive) BSD errno to the negative completion value the ring's
 * ABI expects: a negative Linux errno for the Linux front-end, or a negative
 * native errno for the native 5BSD front-end.  This keeps the engine's error
 * handling ABI-neutral - internally it works in BSD errnos.
 */
static int32_t
iou_err(struct io_uring_ctx *ctx, int bsd_errno)
{

	return (ctx->is_linux ? bsd_to_linux_errno(bsd_errno) : -bsd_errno);
}

/* Timeout expiry code: Linux io_uring returns -ETIME (no BSD equivalent). */
static int32_t
iou_etime(struct io_uring_ctx *ctx)
{

	return (ctx->is_linux ? -LINUX_ENOTIME : -ETIMEDOUT);
}

static int32_t
iou_result(struct io_uring_ctx *ctx, struct thread *td, int error)
{

	if (error != 0)
		return (iou_err(ctx, error));
	return ((int32_t)td->td_retval[0]);
}

/*
 * Cancel one pending (ARMED) request by user_data, moving it to the ready
 * list with res=-ECANCELED.  Returns true if a request was cancelled.
 * Caller holds ctx->mtx.
 */
static bool
iou_cancel_one(struct io_uring_ctx *ctx, uint64_t user_data)
{
	struct iou_req *req;

	mtx_assert(&ctx->mtx, MA_OWNED);
	TAILQ_FOREACH(req, &ctx->pending, entry) {
		if (req->state != IOU_ST_ARMED || req->user_data != user_data)
			continue;
		callout_stop(&req->co);
		req->state = IOU_ST_READY;
		req->res = iou_err(ctx, ECANCELED);
		TAILQ_REMOVE(&ctx->pending, req, entry);
		ctx->npending--;
		TAILQ_INSERT_TAIL(&ctx->ready, req, entry);
		iou_wake(ctx);
		return (true);
	}
	return (false);
}

/* Single-buffer read/write (READ/WRITE and READ_FIXED/WRITE_FIXED). */
static int32_t
iou_rw1(struct io_uring_ctx *ctx, struct thread *td, int fd, void *buf,
    uint32_t len, off_t off, bool cur, bool write)
{
	struct uio auio;
	struct iovec aiov;
	int error;

	aiov.iov_base = buf;
	aiov.iov_len = len;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = cur ? -1 : off;
	auio.uio_resid = len;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_td = td;
	if (write) {
		auio.uio_rw = UIO_WRITE;
		error = cur ? kern_writev(td, fd, &auio) :
		    kern_pwritev(td, fd, &auio, off);
	} else {
		auio.uio_rw = UIO_READ;
		error = cur ? kern_readv(td, fd, &auio) :
		    kern_preadv(td, fd, &auio, off);
	}
	return (iou_result(ctx, td, error));
}

/*
 * Validate that [addr, addr+len) lies within registered buffer buf_index.
 * Returns 0 on success or a negative Linux errno (matching Linux, which
 * reports -EFAULT for an out-of-range fixed buffer and -EINVAL for a bad
 * index / no buffers registered).
 */
static int32_t
iou_check_fixed_buf(struct io_uring_ctx *ctx, uint16_t idx, uint64_t addr,
    uint32_t len)
{
	uintptr_t base, end, a;
	int32_t ret = 0;

	mtx_lock(&ctx->mtx);
	if (ctx->reg_bufs == NULL || idx >= ctx->reg_nbufs) {
		ret = -EINVAL;
	} else {
		base = (uintptr_t)ctx->reg_bufs[idx].iov_base;
		end = base + ctx->reg_bufs[idx].iov_len;
		a = (uintptr_t)addr;
		if (a < base || a + len < a || a + len > end)
			ret = -EFAULT;
	}
	mtx_unlock(&ctx->mtx);
	return (ret);
}

static int iou_do_files_update(struct io_uring_ctx *ctx, uint32_t off,
    uint64_t fds_uptr, uint32_t nr, struct thread *td);
static int iou_fixed_install(struct io_uring_ctx *ctx, struct thread *td,
    int idx, int *fdp);

/* ---- application-provided buffers ---- */
/* PROVIDE_BUFFERS: add nbufs buffers to a group.  Returns Linux res. */
static int32_t
iou_provide_buffers(struct io_uring_ctx *ctx, const struct io_uring_sqe *sqe)
{
	struct iou_pbuf *pb;
	uint32_t nbufs, i, elen;
	uint64_t base;
	uint16_t bgid, bid;

	nbufs = (uint32_t)sqe->fd;	/* PROVIDE_BUFFERS reuses fd as count */
	elen = sqe->len;		/* length of each buffer */
	base = sqe->addr;
	bgid = sqe->buf_group;
	bid = (uint16_t)sqe->off;	/* starting buffer id */
	if (nbufs == 0 || nbufs > IOU_MAX_PBUFS)
		return (-EINVAL);
	for (i = 0; i < nbufs; i++) {
		pb = malloc(sizeof(*pb), M_LINUX_IOURING, M_WAITOK);
		pb->bgid = bgid;
		pb->bid = bid + i;
		pb->addr = base + (uint64_t)i * elen;
		pb->len = elen;
		mtx_lock(&ctx->mtx);
		TAILQ_INSERT_TAIL(&ctx->pbufs, pb, entry);
		mtx_unlock(&ctx->mtx);
	}
	return (0);
}

/* REMOVE_BUFFERS: drop up to nbufs from a group.  res = number removed. */
static int32_t
iou_remove_buffers(struct io_uring_ctx *ctx, const struct io_uring_sqe *sqe)
{
	struct iou_pbuf *pb, *tmp;
	uint32_t nbufs, removed = 0;
	uint16_t bgid;

	nbufs = (uint32_t)sqe->fd;
	bgid = sqe->buf_group;
	if (nbufs == 0)
		return (-EINVAL);
	mtx_lock(&ctx->mtx);
	TAILQ_FOREACH_SAFE(pb, &ctx->pbufs, entry, tmp) {
		if (removed >= nbufs)
			break;
		if (pb->bgid != bgid)
			continue;
		TAILQ_REMOVE(&ctx->pbufs, pb, entry);
		free(pb, M_LINUX_IOURING);
		removed++;
	}
	mtx_unlock(&ctx->mtx);
	return ((int32_t)removed);
}

/*
 * Select (and consume) a provided buffer from a group for a BUFFER_SELECT op.
 * On success rewrites the addr and len out-params to the chosen buffer and
 * returns its id in bid; returns ENOBUFS if the group is empty.
 */
static int
iou_pbuf_select(struct io_uring_ctx *ctx, uint16_t bgid, uint32_t want,
    uint64_t *addr, uint32_t *len, uint16_t *bid)
{
	struct iou_pbuf *pb;

	mtx_lock(&ctx->mtx);
	TAILQ_FOREACH(pb, &ctx->pbufs, entry) {
		if (pb->bgid != bgid)
			continue;
		TAILQ_REMOVE(&ctx->pbufs, pb, entry);
		mtx_unlock(&ctx->mtx);
		*addr = pb->addr;
		*len = (want == 0 || want > pb->len) ? pb->len : want;
		*bid = pb->bid;
		free(pb, M_LINUX_IOURING);
		return (0);
	}
	mtx_unlock(&ctx->mtx);
	return (ENOBUFS);
}

/* Return a selected-but-unused buffer to the head of its group. */
static void
iou_pbuf_return(struct io_uring_ctx *ctx, uint16_t bgid, uint16_t bid,
    uint64_t addr, uint32_t len)
{
	struct iou_pbuf *pb;

	pb = malloc(sizeof(*pb), M_LINUX_IOURING, M_WAITOK);
	pb->bgid = bgid;
	pb->bid = bid;
	pb->addr = addr;
	pb->len = len;
	mtx_lock(&ctx->mtx);
	TAILQ_INSERT_HEAD(&ctx->pbufs, pb, entry);
	mtx_unlock(&ctx->mtx);
}

/*
 * Linux front-end opcode extension: the opcodes that delegate to the
 * Linuxulator's own syscall handlers (so Linux flag/path/sockaddr translation
 * stays identical to the direct syscalls).  Registered as ctx->issue_ext by
 * the Linux front-end and invoked by iou_issue_op for opcodes the ABI-neutral
 * core does not handle.  A native front-end supplies its own equivalent.
 */
static int32_t
linux_iou_issue_ext(struct io_uring_ctx *ctx, struct iou_req *req,
    struct thread *td)
{
	const struct io_uring_sqe *sqe = &req->sqe;

	switch (sqe->opcode) {
	case IORING_OP_TEE: {
		struct linux_tee_args a;

		bzero(&a, sizeof(a));
		a.fd_in = sqe->splice_fd_in;
		a.fd_out = sqe->fd;
		a.len = sqe->len;
		a.flags = sqe->splice_flags;
		return (iou_result(ctx, td, linux_tee(td, &a)));
	}
	case IORING_OP_PIPE: {
		struct linux_pipe2_args a;

		bzero(&a, sizeof(a));
		a.pipefds = (void *)(uintptr_t)sqe->addr;
		a.flags = sqe->pipe_flags;
		return (iou_result(ctx, td, linux_pipe2(td, &a)));
	}
	case IORING_OP_SPLICE: {
		struct linux_splice_args a;

		/*
		 * io_uring passes offsets by value; we support the pipe /
		 * current-position case where both are -1 (NULL to splice).
		 */
		if (sqe->splice_off_in != (uint64_t)-1 ||
		    sqe->off != (uint64_t)-1)
			return (-EINVAL);
		bzero(&a, sizeof(a));
		a.fd_in = sqe->splice_fd_in;
		a.off_in = NULL;
		a.fd_out = sqe->fd;
		a.off_out = NULL;
		a.len = sqe->len;
		a.flags = sqe->splice_flags;
		return (iou_result(ctx, td, linux_splice(td, &a)));
	}
	case IORING_OP_EPOLL_WAIT: {
		struct linux_epoll_pwait_args a;

		bzero(&a, sizeof(a));
		a.epfd = sqe->fd;
		a.events = (void *)(uintptr_t)sqe->addr;
		a.maxevents = (int)sqe->len;
		a.timeout = 0;
		a.mask = NULL;
		a.sigsetsize = 0;
		return (iou_result(ctx, td, linux_epoll_pwait(td, &a)));
	}
	case IORING_OP_SEND_ZC:
	case IORING_OP_SENDMSG_ZC: {
		int32_t r;

		if (sqe->opcode == IORING_OP_SEND_ZC) {
			struct linux_sendto_args a;

			bzero(&a, sizeof(a));
			a.s = sqe->fd;
			a.msg = (l_uintptr_t)sqe->addr;
			a.len = sqe->len;
			a.flags = sqe->msg_flags;
			a.to = (l_uintptr_t)sqe->addr2;
			a.tolen = sqe->addr_len;
			r = iou_result(ctx, td, linux_sendto(td, &a));
		} else {
			struct linux_sendmsg_args a;

			bzero(&a, sizeof(a));
			a.s = sqe->fd;
			a.msg = (l_uintptr_t)sqe->addr;
			a.flags = sqe->msg_flags;
			r = iou_result(ctx, td, linux_sendmsg(td, &a));
		}
		mtx_lock(&ctx->mtx);
		if (r < 0) {
			iou_post_cqe(ctx, req->user_data, r, 0);
		} else {
			iou_post_cqe(ctx, req->user_data, r, IORING_CQE_F_MORE);
			iou_post_cqe(ctx, req->user_data,
			    (int32_t)IORING_NOTIF_USAGE_ZC_COPIED,
			    IORING_CQE_F_NOTIF);
		}
		mtx_unlock(&ctx->mtx);
		req->posted = true;
		return (r);
	}
	case IORING_OP_FUTEX_WAKE: {
		struct linux_futex_wake_args a;

		bzero(&a, sizeof(a));
		a.uaddr = (void *)(uintptr_t)sqe->addr;
		a.mask = sqe->addr3;
		a.nr = (int)sqe->off;
		a.flags = sqe->futex_flags;
		return (iou_result(ctx, td, linux_futex_wake(td, &a)));
	}
	case IORING_OP_FUTEX_WAIT: {
		struct linux_futex_wait_args a;

		bzero(&a, sizeof(a));
		a.uaddr = (void *)(uintptr_t)sqe->addr;
		a.val = sqe->off;
		a.mask = sqe->addr3;
		a.flags = sqe->futex_flags;
		a.timeout = NULL;
		a.clockid = 0;
		return (iou_result(ctx, td, linux_futex_wait(td, &a)));
	}
	case IORING_OP_FUTEX_WAITV: {
		struct linux_futex_waitv_args a;

		bzero(&a, sizeof(a));
		a.waiters = (void *)(uintptr_t)sqe->addr;
		a.nr_futexes = sqe->len;
		a.flags = 0;
		a.timeout = NULL;
		a.clockid = 0;
		return (iou_result(ctx, td, linux_futex_waitv(td, &a)));
	}
	case IORING_OP_WAITID: {
		struct linux_waitid_args a;

		bzero(&a, sizeof(a));
		a.idtype = (int)sqe->len;
		a.id = (int)sqe->fd;
		a.info = (void *)(uintptr_t)sqe->addr2;
		a.options = (int)sqe->file_index;
		a.rusage = NULL;
		return (iou_result(ctx, td, linux_waitid(td, &a)));
	}
	case IORING_OP_OPENAT: {
		struct linux_openat_args a;

		if (sqe->file_index != 0)
			return (-EINVAL);
		bzero(&a, sizeof(a));
		a.dfd = sqe->fd;
		a.filename = (void *)(uintptr_t)sqe->addr;
		a.flags = sqe->open_flags;
		a.mode = sqe->len;
		return (iou_result(ctx, td, linux_openat(td, &a)));
	}
	case IORING_OP_OPENAT2: {
		struct linux_openat2_args a;

		if (sqe->file_index != 0)
			return (-EINVAL);
		bzero(&a, sizeof(a));
		a.dfd = sqe->fd;
		a.filename = (void *)(uintptr_t)sqe->addr;
		a.how = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		return (iou_result(ctx, td, linux_openat2(td, &a)));
	}
	case IORING_OP_STATX: {
		struct linux_statx_args a;

		bzero(&a, sizeof(a));
		a.dirfd = sqe->fd;
		a.pathname = (void *)(uintptr_t)sqe->addr;
		a.flags = sqe->statx_flags;
		a.mask = sqe->len;
		a.statxbuf = (void *)(uintptr_t)sqe->addr2;
		return (iou_result(ctx, td, linux_statx(td, &a)));
	}
	case IORING_OP_RENAMEAT: {
		struct linux_renameat2_args a;

		bzero(&a, sizeof(a));
		a.olddfd = sqe->fd;
		a.oldname = (void *)(uintptr_t)sqe->addr;
		a.newdfd = (int)sqe->len;
		a.newname = (void *)(uintptr_t)sqe->addr2;
		a.flags = sqe->rename_flags;
		return (iou_result(ctx, td, linux_renameat2(td, &a)));
	}
	case IORING_OP_UNLINKAT: {
		struct linux_unlinkat_args a;

		bzero(&a, sizeof(a));
		a.dfd = sqe->fd;
		a.pathname = (void *)(uintptr_t)sqe->addr;
		a.flag = sqe->unlink_flags;
		return (iou_result(ctx, td, linux_unlinkat(td, &a)));
	}
	case IORING_OP_MKDIRAT: {
		struct linux_mkdirat_args a;

		bzero(&a, sizeof(a));
		a.dfd = sqe->fd;
		a.pathname = (void *)(uintptr_t)sqe->addr;
		a.mode = sqe->len;
		return (iou_result(ctx, td, linux_mkdirat(td, &a)));
	}
	case IORING_OP_SYMLINKAT: {
		struct linux_symlinkat_args a;

		bzero(&a, sizeof(a));
		a.oldname = (void *)(uintptr_t)sqe->addr;
		a.newdfd = sqe->fd;
		a.newname = (void *)(uintptr_t)sqe->addr2;
		return (iou_result(ctx, td, linux_symlinkat(td, &a)));
	}
	case IORING_OP_LINKAT: {
		struct linux_linkat_args a;

		bzero(&a, sizeof(a));
		a.olddfd = sqe->fd;
		a.oldname = (void *)(uintptr_t)sqe->addr;
		a.newdfd = (int)sqe->len;
		a.newname = (void *)(uintptr_t)sqe->addr2;
		a.flag = sqe->hardlink_flags;
		return (iou_result(ctx, td, linux_linkat(td, &a)));
	}
	case IORING_OP_MADVISE: {
		struct linux_madvise_args a;

		bzero(&a, sizeof(a));
		a.addr = (l_ulong)sqe->addr;
		a.len = sqe->len;
		a.behav = sqe->fadvise_advice;
		return (iou_result(ctx, td, linux_madvise(td, &a)));
	}
	case IORING_OP_SYNC_FILE_RANGE: {
		struct linux_sync_file_range_args a;

		bzero(&a, sizeof(a));
		a.fd = sqe->fd;
		a.offset = (off_t)sqe->off;
		a.nbytes = (off_t)sqe->len;
		a.flags = sqe->sync_range_flags;
		return (iou_result(ctx, td, linux_sync_file_range(td, &a)));
	}
	case IORING_OP_SOCKET: {
		struct linux_socket_args a;

		if (sqe->file_index != 0)
			return (-EINVAL);
		bzero(&a, sizeof(a));
		a.domain = sqe->fd;
		a.type = (int)sqe->off;
		a.protocol = (int)sqe->len;
		return (iou_result(ctx, td, linux_socket(td, &a)));
	}
	case IORING_OP_CONNECT: {
		struct linux_connect_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.name = (l_uintptr_t)sqe->addr;
		a.namelen = (int)sqe->off;
		return (iou_result(ctx, td, linux_connect(td, &a)));
	}
	case IORING_OP_ACCEPT: {
		struct linux_accept4_args a;

		if (sqe->file_index != 0)
			return (-EINVAL);
		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.addr = (l_uintptr_t)sqe->addr;
		a.namelen = (l_uintptr_t)sqe->addr2;
		a.flags = sqe->accept_flags;
		return (iou_result(ctx, td, linux_accept4(td, &a)));
	}
	case IORING_OP_BIND: {
		struct linux_bind_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.name = (l_uintptr_t)sqe->addr;
		a.namelen = (int)sqe->addr2;
		return (iou_result(ctx, td, linux_bind(td, &a)));
	}
	case IORING_OP_LISTEN: {
		struct linux_listen_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.backlog = (int)sqe->len;
		return (iou_result(ctx, td, linux_listen(td, &a)));
	}
	case IORING_OP_SHUTDOWN: {
		struct linux_shutdown_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.how = (int)sqe->len;
		return (iou_result(ctx, td, linux_shutdown(td, &a)));
	}
	case IORING_OP_SEND: {
		struct linux_sendto_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.msg = (l_uintptr_t)sqe->addr;
		a.len = sqe->len;
		a.flags = sqe->msg_flags | IOU_MSG_DONTWAIT;
		a.to = (l_uintptr_t)sqe->addr2;
		a.tolen = sqe->addr_len;
		return (iou_result(ctx, td, linux_sendto(td, &a)));
	}
	case IORING_OP_RECV: {
		struct linux_recvfrom_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.buf = (l_uintptr_t)sqe->addr;
		a.len = sqe->len;
		a.flags = sqe->msg_flags | IOU_MSG_DONTWAIT;
		return (iou_result(ctx, td, linux_recvfrom(td, &a)));
	}
	case IORING_OP_SENDMSG: {
		struct linux_sendmsg_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.msg = (l_uintptr_t)sqe->addr;
		a.flags = sqe->msg_flags | IOU_MSG_DONTWAIT;
		return (iou_result(ctx, td, linux_sendmsg(td, &a)));
	}
	case IORING_OP_RECVMSG: {
		struct linux_recvmsg_args a;

		bzero(&a, sizeof(a));
		a.s = sqe->fd;
		a.msg = (l_uintptr_t)sqe->addr;
		a.flags = sqe->msg_flags | IOU_MSG_DONTWAIT;
		return (iou_result(ctx, td, linux_recvmsg(td, &a)));
	}
	case IORING_OP_EPOLL_CTL: {
		struct linux_epoll_ctl_args a;

		bzero(&a, sizeof(a));
		a.epfd = sqe->fd;
		a.op = (int)sqe->len;
		a.fd = (int)sqe->off;
		a.event = (void *)(uintptr_t)sqe->addr;
		return (iou_result(ctx, td, linux_epoll_ctl(td, &a)));
	}
	case IORING_OP_FSETXATTR: {
		struct linux_fsetxattr_args a;

		bzero(&a, sizeof(a));
		a.fd = sqe->fd;
		a.name = (void *)(uintptr_t)sqe->addr;
		a.value = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		a.flags = sqe->xattr_flags;
		return (iou_result(ctx, td, linux_fsetxattr(td, &a)));
	}
	case IORING_OP_SETXATTR: {
		struct linux_setxattr_args a;

		bzero(&a, sizeof(a));
		a.path = (void *)(uintptr_t)sqe->addr3;
		a.name = (void *)(uintptr_t)sqe->addr;
		a.value = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		a.flags = sqe->xattr_flags;
		return (iou_result(ctx, td, linux_setxattr(td, &a)));
	}
	case IORING_OP_FGETXATTR: {
		struct linux_fgetxattr_args a;

		bzero(&a, sizeof(a));
		a.fd = sqe->fd;
		a.name = (void *)(uintptr_t)sqe->addr;
		a.value = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		return (iou_result(ctx, td, linux_fgetxattr(td, &a)));
	}
	case IORING_OP_GETXATTR: {
		struct linux_getxattr_args a;

		bzero(&a, sizeof(a));
		a.path = (void *)(uintptr_t)sqe->addr3;
		a.name = (void *)(uintptr_t)sqe->addr;
		a.value = (void *)(uintptr_t)sqe->addr2;
		a.size = sqe->len;
		return (iou_result(ctx, td, linux_getxattr(td, &a)));
	}
	default:
		return (iou_err(ctx, EINVAL));
	}
}

/*
 * Execute one synchronous ABI-neutral SQE inline in the submitting thread's
 * context (so target fds and user buffers resolve against the caller).  Uses
 * only kern_* calls, no Linux dependencies, so it can move into sys/kern.
 * Returns the completion result, or IOU_NOTHANDLED for an opcode the core does
 * not implement (iou_issue_op then routes it to the front-end's issue_ext).
 * A -1 offset means "current file position".
 */
static int32_t
iou_issue_inline(struct io_uring_ctx *ctx, struct iou_req *req,
    struct thread *td)
{
	const struct io_uring_sqe *sqe = &req->sqe;
	struct uio *uiop;
	off_t off;
	int error;
	bool cur;

	off = (off_t)sqe->off;
	cur = (sqe->off == (uint64_t)-1);
	td->td_retval[0] = 0;	/* zero-returning ops report 0, not a stale count */

	/*
	 * Provided-buffer selection: only READ and RECV take a selected
	 * buffer here (the common single-shot case).  Consume one from the
	 * group, rewrite the op's target buffer, and report the id in the
	 * completion flags.
	 */
	if ((req->sqe_flags & IOSQE_BUFFER_SELECT) != 0 &&
	    sqe->opcode != IORING_OP_READ_MULTISHOT) {
		uint64_t baddr;
		uint32_t blen;
		uint16_t bid;

		/* READ_MULTISHOT selects buffers itself in its own loop. */
		if (sqe->opcode != IORING_OP_READ &&
		    sqe->opcode != IORING_OP_RECV)
			return (-EINVAL);
		error = iou_pbuf_select(ctx, sqe->buf_group, sqe->len,
		    &baddr, &blen, &bid);
		if (error != 0)
			return (iou_err(ctx, error));	/* -ENOBUFS */
		req->sqe.addr = baddr;
		req->sqe.len = blen;
		req->cflags = IORING_CQE_F_BUFFER |
		    ((uint32_t)bid << IORING_CQE_BUFFER_SHIFT);
	}

	switch (sqe->opcode) {
	case IORING_OP_NOP:
		return (0);
	case IORING_OP_POLL_REMOVE: {
		/* Cancel an armed POLL_ADD by user_data (sqe->addr). */
		struct iou_req *p, *tmp;
		bool found = false;

		mtx_lock(&ctx->mtx);
		TAILQ_FOREACH_SAFE(p, &ctx->polls, entry, tmp) {
			if (p->state != IOU_ST_ARMED || p->user_data != sqe->addr)
				continue;
			TAILQ_REMOVE(&ctx->polls, p, entry);
			ctx->npolls--;
			p->state = IOU_ST_READY;
			p->res = iou_err(ctx, ECANCELED);
			TAILQ_INSERT_TAIL(&ctx->ready, p, entry);
			iou_wake(ctx);
			found = true;
			break;
		}
		mtx_unlock(&ctx->mtx);
		return (found ? 0 : iou_err(ctx, ENOENT));
	}
	case IORING_OP_PROVIDE_BUFFERS:
		return (iou_provide_buffers(ctx, sqe));
	case IORING_OP_REMOVE_BUFFERS:
		return (iou_remove_buffers(ctx, sqe));
	case IORING_OP_FILES_UPDATE:
		/* off=offset, len=nr, addr=fd array */
		return (iou_result(ctx, td, iou_do_files_update(ctx, (uint32_t)off,
		    sqe->addr, sqe->len, td)));
	case IORING_OP_MSG_RING: {
		struct file *tfp;
		struct io_uring_ctx *tctx;

		/* Only IORING_MSG_DATA (post a CQE to a target ring). */
		if (sqe->addr != IORING_MSG_DATA)
			return (-EINVAL);
		error = fget(td, sqe->fd, &cap_no_rights, &tfp);
		if (error != 0)
			return (iou_err(ctx, error));
		if (tfp->f_type != DTYPE_IORING) {
			fdrop(tfp, td);
			return (-EOPNOTSUPP);
		}
		tctx = tfp->f_data;
		mtx_lock(&tctx->mtx);
		iou_post_cqe(tctx, sqe->off, (int32_t)sqe->len, 0);
		iou_wake(tctx);
		mtx_unlock(&tctx->mtx);
		fdrop(tfp, td);
		return (0);
	}
	case IORING_OP_NOP128:
		return (0);		/* NOP for SQE128 rings */
	case IORING_OP_FIXED_FD_INSTALL: {
		int newfd;

		/* Install a registered descriptor into the normal table. */
		error = iou_fixed_install(ctx, td, sqe->fd, &newfd);
		if (error != 0)
			return (iou_err(ctx, error));
		td->td_retval[0] = newfd;
		return ((int32_t)newfd);
	}
	case IORING_OP_LINK_TIMEOUT:
		/*
		 * Bounds a preceding linked request.  In this engine a linked
		 * predecessor has already completed by the time we get here, so
		 * the timeout is redundant and completes -ECANCELED, exactly as
		 * Linux reports a link-timeout whose target finished first.
		 */
		return (iou_err(ctx, ECANCELED));
	case IORING_OP_READ:
	case IORING_OP_WRITE:
		return (iou_rw1(ctx, td, sqe->fd, (void *)(uintptr_t)sqe->addr,
		    sqe->len, off, cur, sqe->opcode == IORING_OP_WRITE));
	case IORING_OP_READ_FIXED:
	case IORING_OP_WRITE_FIXED: {
		int32_t r = iou_check_fixed_buf(ctx, sqe->buf_index, sqe->addr,
		    sqe->len);

		if (r != 0)
			return (r);
		return (iou_rw1(ctx, td, sqe->fd, (void *)(uintptr_t)sqe->addr,
		    sqe->len, off, cur,
		    sqe->opcode == IORING_OP_WRITE_FIXED));
	}
	case IORING_OP_READ_MULTISHOT: {
		/*
		 * Multishot read: drain everything currently readable into
		 * provided buffers, posting an F_MORE completion (with the
		 * buffer id) per read, then either finish (EOF/error/no buffer,
		 * terminal CQE without F_MORE) or return EAGAIN to re-arm the
		 * readiness poll.  Requires IOSQE_BUFFER_SELECT.
		 */
		uint64_t baddr;
		uint32_t blen;
		uint16_t bid;
		int32_t r;

		if ((req->sqe_flags & IOSQE_BUFFER_SELECT) == 0)
			return (-EINVAL);
		for (;;) {
			error = iou_pbuf_select(ctx, sqe->buf_group, 0, &baddr,
			    &blen, &bid);
			if (error != 0)
				return (iou_err(ctx, ENOBUFS));	/* terminal */
			r = iou_rw1(ctx, td, sqe->fd, (void *)(uintptr_t)baddr,
			    blen, 0, true /* current pos */, false /* read */);
			if (r > 0) {
				mtx_lock(&ctx->mtx);
				iou_post_cqe(ctx, req->user_data, r,
				    IORING_CQE_F_MORE | IORING_CQE_F_BUFFER |
				    ((uint32_t)bid << IORING_CQE_BUFFER_SHIFT));
				iou_wake(ctx);
				mtx_unlock(&ctx->mtx);
				continue;		/* drain more */
			}
			/* nothing consumed: hand the buffer back */
			iou_pbuf_return(ctx, sqe->buf_group, bid, baddr, blen);
			return (r);		/* 0=EOF, -EAGAIN=re-arm, else error */
		}
	}
	case IORING_OP_READV:
	case IORING_OP_WRITEV:
	case IORING_OP_READV_FIXED:
	case IORING_OP_WRITEV_FIXED: {
		bool wr = sqe->opcode == IORING_OP_WRITEV ||
		    sqe->opcode == IORING_OP_WRITEV_FIXED;
		bool fixed = sqe->opcode == IORING_OP_READV_FIXED ||
		    sqe->opcode == IORING_OP_WRITEV_FIXED;

		/* The vectored-fixed variants require registered buffers. */
		if (fixed) {
			mtx_lock(&ctx->mtx);
			if (ctx->reg_bufs == NULL) {
				mtx_unlock(&ctx->mtx);
				return (-EINVAL);
			}
			mtx_unlock(&ctx->mtx);
		}
		error = copyinuio((void *)(uintptr_t)sqe->addr, sqe->len, &uiop);
		if (error != 0)
			return (iou_err(ctx, error));
		if (!wr)
			error = cur ? kern_readv(td, sqe->fd, uiop) :
			    kern_preadv(td, sqe->fd, uiop, off);
		else
			error = cur ? kern_writev(td, sqe->fd, uiop) :
			    kern_pwritev(td, sqe->fd, uiop, off);
		free(uiop, M_IOV);
		return (iou_result(ctx, td, error));
	}
	case IORING_OP_FSYNC:
		/* IORING_FSYNC_DATASYNC selects fdatasync. */
		error = kern_fsync(td, sqe->fd,
		    (sqe->fsync_flags & 1 /* DATASYNC */) == 0);
		return (iou_result(ctx, td, error));
	case IORING_OP_CLOSE:
		return (iou_result(ctx, td, kern_close(td, sqe->fd)));
	case IORING_OP_FTRUNCATE:
		return (iou_result(ctx, td, kern_ftruncate(td, sqe->fd, off)));
	case IORING_OP_FALLOCATE:
		/* off/addr/len = offset/len/mode; mode 0 == plain allocate. */
		if (sqe->len != 0)
			return (iou_err(ctx, EOPNOTSUPP)); /* modes: later */
		return (iou_result(ctx, td, kern_posix_fallocate(td, sqe->fd, off,
		    (off_t)sqe->addr)));
	case IORING_OP_FADVISE: {
		off_t len = sqe->addr != 0 ? (off_t)sqe->addr : (off_t)sqe->len;

		/* POSIX_FADV_* share values on Linux and FreeBSD. */
		return (iou_result(ctx, td, kern_posix_fadvise(td, sqe->fd, off, len,
		    sqe->fadvise_advice)));
	}
	case IORING_OP_ASYNC_CANCEL:
	case IORING_OP_TIMEOUT_REMOVE: {
		bool all, found;

		/*
		 * ASYNC_CANCEL keys on sqe->addr (user_data) by default;
		 * TIMEOUT_REMOVE keys on sqe->addr (the timeout's user_data).
		 * We track only timeouts as cancellable requests today, so the
		 * two share a code path.  IORING_ASYNC_CANCEL_ALL cancels every
		 * match.  A match reports 0; no match reports -ENOENT.
		 */
		if (sqe->opcode == IORING_OP_ASYNC_CANCEL &&
		    (sqe->cancel_flags & ~IORING_ASYNC_CANCEL_ALL) != 0)
			return (-EINVAL);	/* FD/OP/ANY keys: later phase */
		all = sqe->opcode == IORING_OP_ASYNC_CANCEL &&
		    (sqe->cancel_flags & IORING_ASYNC_CANCEL_ALL) != 0;
		found = false;
		mtx_lock(&ctx->mtx);
		while (iou_cancel_one(ctx, sqe->addr)) {
			found = true;
			if (!all)
				break;
		}
		mtx_unlock(&ctx->mtx);
		return (found ? 0 : iou_err(ctx, ENOENT));
	}
	default:
		/* Not a core opcode: let the front-end's issue_ext handle it. */
		return (IOU_NOTHANDLED);
	}
}

/*
 * Resolve a registered (fixed) descriptor: install the held file into a
 * transient fd so the standard kern_* path can operate on it.  Holding the
 * reference in the ctx means the op works even after the application has
 * closed its own descriptor for the file.  Returns 0 and *fdp on success.
 */
static int
iou_fixed_install(struct io_uring_ctx *ctx, struct thread *td, int idx,
    int *fdp)
{
	struct file *fp;
	int error;

	mtx_lock(&ctx->mtx);
	if (ctx->reg_files == NULL || idx < 0 ||
	    (uint32_t)idx >= ctx->reg_nfiles || ctx->reg_files[idx] == NULL) {
		mtx_unlock(&ctx->mtx);
		return (EBADF);
	}
	fp = ctx->reg_files[idx];
	if (!fhold(fp)) {
		mtx_unlock(&ctx->mtx);
		return (EBADF);
	}
	mtx_unlock(&ctx->mtx);
	error = finstall(td, fp, fdp, 0, NULL);
	if (error != 0)
		fdrop(fp, td);
	return (error);
}

/*
 * Issue wrapper: if IOSQE_FIXED_FILE is set, translate the fixed index into a
 * transient real descriptor, run the op against it, then release it.  This
 * keeps every opcode's dispatch fixed-file agnostic.
 */
static int32_t
iou_dispatch(struct io_uring_ctx *ctx, struct iou_req *req, struct thread *td)
{
	int32_t res;

	/* ABI-neutral core first; anything it declines goes to the front-end. */
	res = iou_issue_inline(ctx, req, td);
	if (res == IOU_NOTHANDLED)
		res = ctx->issue_ext != NULL ?
		    ctx->issue_ext(ctx, req, td) : iou_err(ctx, EINVAL);
	return (res);
}

static int32_t
iou_issue_op(struct io_uring_ctx *ctx, struct iou_req *req, struct thread *td)
{
	struct iou_req tmp;
	int32_t res;
	int error, tmpfd;

	if ((req->sqe_flags & IOSQE_FIXED_FILE) == 0)
		return (iou_dispatch(ctx, req, td));

	error = iou_fixed_install(ctx, td, req->sqe.fd, &tmpfd);
	if (error != 0)
		return (iou_err(ctx, error));
	tmp = *req;
	tmp.sqe.fd = tmpfd;
	tmp.sqe_flags &= ~IOSQE_FIXED_FILE;
	tmp.cflags = 0;
	res = iou_dispatch(ctx, &tmp, td);
	req->cflags = tmp.cflags;	/* carry back a BUFFER_SELECT id */
	(void)kern_close(td, tmpfd);
	return (res);
}

/* ---- asynchronous opcodes ---- */
static void
iou_timeout_cb(void *arg)
{
	struct iou_req *req = arg;
	struct io_uring_ctx *ctx = req->ctx;

	mtx_assert(&ctx->mtx, MA_OWNED);	/* callout_init_mtx */
	if (req->state != IOU_ST_ARMED)
		return;				/* cancelled just ahead of us */
	req->state = IOU_ST_READY;
	req->res = (req->sqe.timeout_flags & IORING_TIMEOUT_ETIME_SUCCESS) != 0 ?
	    0 : iou_etime(ctx) /* Linux ETIME (62) */;
	/*
	 * Post the CQE now, from callout context, so a thread blocked in a
	 * poll-based wait (kern_poll_kfds on the ring fd) sees the ring become
	 * readable.  run_ready then only needs to run any linked successor.
	 */
	iou_post_cqe(ctx, req->user_data, req->res, 0);
	req->posted = true;
	TAILQ_REMOVE(&ctx->pending, req, entry);
	ctx->npending--;
	TAILQ_INSERT_TAIL(&ctx->ready, req, entry);
	iou_wake(ctx);
}

static void
iou_check_count_timeouts(struct io_uring_ctx *ctx)
{
	struct iou_req *req, *tmp;

	mtx_assert(&ctx->mtx, MA_OWNED);
	TAILQ_FOREACH_SAFE(req, &ctx->pending, entry, tmp) {
		if (!req->tmo_count || req->state != IOU_ST_ARMED)
			continue;
		if (ctx->cq_count < req->tmo_target)
			continue;
		/* Requested number of completions reached before the timer. */
		callout_stop(&req->co);
		req->state = IOU_ST_READY;
		req->res = 0;
		TAILQ_REMOVE(&ctx->pending, req, entry);
		ctx->npending--;
		TAILQ_INSERT_TAIL(&ctx->ready, req, entry);
		/* woken by the caller that advanced cq_count */
	}
}

/*
 * Arm an asynchronous op (TIMEOUT).  Returns 0 on success (request now owns
 * itself on the pending list), or a negative Linux errno to complete with.
 */
static int32_t
iou_arm_async(struct io_uring_ctx *ctx, struct iou_req *req, struct thread *td)
{
	const struct io_uring_sqe *sqe = &req->sqe;
	struct __kernel_timespec kts;
	struct timespec ts, now;
	struct timeval tv;
	uint32_t flags;
	int error, ticks;

	if (sqe->opcode == IORING_OP_POLL_ADD) {
		/*
		 * Arm a poll: recorded on ctx->polls and resolved by
		 * kern_poll_kfds in the waiting thread.  Multishot and update
		 * are not supported (single-shot readiness only).
		 */
		if ((sqe->len & (IORING_POLL_ADD_MULTI | IORING_POLL_UPDATE_EVENTS |
		    IORING_POLL_UPDATE_USER_DATA)) != 0)
			return (-EINVAL);
		mtx_lock(&ctx->mtx);
		req->state = IOU_ST_ARMED;
		TAILQ_INSERT_TAIL(&ctx->polls, req, entry);
		ctx->npolls++;
		mtx_unlock(&ctx->mtx);
		return (0);
	}

	KASSERT(sqe->opcode == IORING_OP_TIMEOUT, ("not a timeout"));
	flags = sqe->timeout_flags;
	/* Reject flags whose behaviour we do not implement. */
	if ((flags & ~(IORING_TIMEOUT_ABS | IORING_TIMEOUT_BOOTTIME |
	    IORING_TIMEOUT_REALTIME | IORING_TIMEOUT_ETIME_SUCCESS)) != 0)
		return (-EINVAL);
	error = copyin((void *)(uintptr_t)sqe->addr, &kts, sizeof(kts));
	if (error != 0)
		return (iou_err(ctx, error));
	ts.tv_sec = kts.tv_sec;
	ts.tv_nsec = kts.tv_nsec;
	if (ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L)
		return (-EINVAL);

	if ((flags & IORING_TIMEOUT_ABS) != 0) {
		if ((flags & IORING_TIMEOUT_REALTIME) != 0)
			getnanotime(&now);
		else
			getnanouptime(&now);
		timespecsub(&ts, &now, &ts);
		if (ts.tv_sec < 0)
			timespecclear(&ts);
	}
	TIMESPEC_TO_TIMEVAL(&tv, &ts);
	ticks = tvtohz(&tv);		/* clamped to >= 1 tick */

	mtx_lock(&ctx->mtx);
	req->state = IOU_ST_ARMED;
	if (sqe->off != 0) {
		req->tmo_count = true;
		req->tmo_target = ctx->cq_count + (uint32_t)sqe->off;
	}
	TAILQ_INSERT_TAIL(&ctx->pending, req, entry);
	ctx->npending++;
	callout_reset(&req->co, ticks, iou_timeout_cb, req);
	/* A count target already satisfied fires on the next completion. */
	iou_check_count_timeouts(ctx);
	mtx_unlock(&ctx->mtx);
	return (0);
}

/* ---- chain execution ---- */
static void iou_run_chain(struct io_uring_ctx *ctx, struct iou_req *req,
    struct thread *td);

/* Complete an entire (remaining) chain as cancelled. */
static void
iou_cancel_chain(struct io_uring_ctx *ctx, struct iou_req *req)
{
	struct iou_req *next;

	while (req != NULL) {
		next = req->link_next;
		mtx_lock(&ctx->mtx);
		iou_complete(ctx, req, iou_err(ctx, ECANCELED), 0);
		mtx_unlock(&ctx->mtx);
		iou_req_free(req);
		req = next;
	}
}

/*
 * Run a link chain as far as it can go synchronously.  Inline ops complete
 * immediately; on reaching an async op the chain is suspended (its remaining
 * successors hang off req->link_next and run from iou_run_ready once the async
 * op resolves).  A soft-linked failure cancels the remaining successors.
 */
static void
iou_run_chain(struct io_uring_ctx *ctx, struct iou_req *req, struct thread *td)
{
	struct iou_req *next;
	int32_t res;
	bool fail, softlink;

	while (req != NULL) {
		if (iou_op_async(req->opcode)) {
			res = iou_arm_async(ctx, req, td);
			if (res == 0)
				return;		/* suspended; owns itself */
			/* arm failed: complete inline and fall through */
			next = req->link_next;
			mtx_lock(&ctx->mtx);
			iou_complete(ctx, req, res, 0);
			mtx_unlock(&ctx->mtx);
			softlink = (req->sqe_flags & IOSQE_IO_LINK) != 0;
			iou_req_free(req);
			if (res < 0 && softlink) {
				iou_cancel_chain(ctx, next);
				return;
			}
			req = next;
			continue;
		}

		res = iou_issue_op(ctx, req, td);
		/*
		 * Fast poll: a would-block op is parked on a readiness poll and
		 * re-issued from iou_poll_scan when the fd is ready, rather than
		 * blocking the submitter or completing with EAGAIN.  The chain is
		 * suspended; its successors run once the retry completes.
		 */
		if (res == iou_err(ctx, EAGAIN)) {
			short ev = iou_pollable_events(req->opcode);

			if (ev != 0) {
				mtx_lock(&ctx->mtx);
				req->retry = true;
				req->state = IOU_ST_ARMED;
				req->sqe.poll32_events = ev;
				TAILQ_INSERT_TAIL(&ctx->polls, req, entry);
				ctx->npolls++;
				mtx_unlock(&ctx->mtx);
				return;
			}
		}
		next = req->link_next;
		fail = res < 0;
		softlink = (req->sqe_flags & IOSQE_IO_LINK) != 0;
		mtx_lock(&ctx->mtx);
		iou_complete(ctx, req, res, req->cflags);
		mtx_unlock(&ctx->mtx);
		iou_req_free(req);
		if (fail && softlink) {
			iou_cancel_chain(ctx, next);
			return;
		}
		req = next;
	}
}

static void iou_kick_drain(struct io_uring_ctx *ctx, struct thread *td);

/*
 * Post CQEs for resolved async requests and run any suspended successors, all
 * in the calling thread's context (correct fd table, may block).  Called from
 * io_uring_enter at entry and after every wakeup in the wait loop.
 */
static void
iou_run_ready(struct io_uring_ctx *ctx, struct thread *td)
{
	struct iou_req *req, *cont;
	int32_t res;
	bool cancelled;

	for (;;) {
		mtx_lock(&ctx->mtx);
		req = TAILQ_FIRST(&ctx->ready);
		if (req != NULL)
			TAILQ_REMOVE(&ctx->ready, req, entry);
		mtx_unlock(&ctx->mtx);
		if (req == NULL)
			break;

		res = req->res;
		cont = req->link_next;
		mtx_lock(&ctx->mtx);
		iou_complete(ctx, req, res, req->cflags);
		mtx_unlock(&ctx->mtx);
		/*
		 * A cancelled request (or a soft-linked failure) cancels its
		 * successors; a timeout that expired with ETIME is a failure for
		 * link purposes when soft-linked.
		 */
		cancelled = res == iou_err(ctx, ECANCELED) ||
		    (res < 0 && (req->sqe_flags & IOSQE_IO_LINK) != 0);
		iou_req_free(req);
		if (cont != NULL) {
			if (cancelled)
				iou_cancel_chain(ctx, cont);
			else
				iou_run_chain(ctx, cont, td);
		}
		iou_kick_drain(ctx, td);
	}
}

/*
 * Release barrier-held chains once no async request is outstanding.  Each
 * released chain runs to its first async op (which re-raises npending and
 * stops the release), preserving submission order across the barrier.
 */
static void
iou_kick_drain(struct io_uring_ctx *ctx, struct thread *td)
{
	struct iou_req *head;

	for (;;) {
		mtx_lock(&ctx->mtx);
		if (ctx->npending > 0 || TAILQ_EMPTY(&ctx->drain)) {
			mtx_unlock(&ctx->mtx);
			return;
		}
		head = TAILQ_FIRST(&ctx->drain);
		TAILQ_REMOVE(&ctx->drain, head, entry);
		mtx_unlock(&ctx->mtx);
		iou_run_chain(ctx, head, td);
	}
}

/*
 * Dispatch one built link chain: either run it now, or, if a drain barrier is
 * in effect, hold it until the barrier lifts (preserving order).
 */
static void
iou_dispatch_chain(struct io_uring_ctx *ctx, struct iou_req *head,
    struct thread *td)
{
	bool defer;

	mtx_lock(&ctx->mtx);
	defer = !TAILQ_EMPTY(&ctx->drain) ||
	    ((head->sqe_flags & IOSQE_IO_DRAIN) != 0 && ctx->npending > 0);
	if (defer) {
		TAILQ_INSERT_TAIL(&ctx->drain, head, entry);
		mtx_unlock(&ctx->mtx);
		return;
	}
	mtx_unlock(&ctx->mtx);
	iou_run_chain(ctx, head, td);
}

/* ---- submission ---- */
static int
iou_submit(struct io_uring_ctx *ctx, uint32_t to_submit, struct thread *td)
{
	struct iou_req *req, *ch_head, *ch_prev;
	struct io_uring_sqe sqe;
	uint32_t head, idx;
	int submitted;

	ch_head = ch_prev = NULL;
	for (submitted = 0; (uint32_t)submitted < to_submit; submitted++) {
		mtx_lock(&ctx->mtx);
		head = ctx->rings->sq_head;
		if (head == ctx->rings->sq_tail) {
			mtx_unlock(&ctx->mtx);
			break;			/* nothing more queued */
		}
		idx = ctx->sq_array[head & ctx->sq_mask];
		if (idx >= ctx->sq_entries) {
			ctx->rings->sq_dropped++;
			ctx->rings->sq_head = head + 1;
			mtx_unlock(&ctx->mtx);
			continue;
		}
		/* Copy the SQE out for a stable, private view (SUBMIT_STABLE). */
		sqe = ctx->sqes[idx];
		ctx->rings->sq_head = head + 1;
		mtx_unlock(&ctx->mtx);

		req = malloc(sizeof(*req), M_LINUX_IOURING, M_WAITOK | M_ZERO);
		req->ctx = ctx;
		req->sqe = sqe;
		req->opcode = sqe.opcode;
		req->sqe_flags = sqe.flags;
		req->user_data = sqe.user_data;
		req->state = IOU_ST_NEW;
		callout_init_mtx(&req->co, &ctx->mtx, 0);

		if (ch_head == NULL)
			ch_head = req;
		else
			ch_prev->link_next = req;
		ch_prev = req;

		/* A chain ends at the first SQE without a link flag. */
		if ((sqe.flags & (IOSQE_IO_LINK | IOSQE_IO_HARDLINK)) == 0) {
			iou_dispatch_chain(ctx, ch_head, td);
			ch_head = ch_prev = NULL;
		}
	}
	/* A dangling link at the end of the batch is dispatched on its own. */
	if (ch_head != NULL)
		iou_dispatch_chain(ctx, ch_head, td);

	return (submitted);
}

/* Map BSD poll revents to the Linux poll/epoll bits an app expects. */
static int32_t
iou_poll_res(struct io_uring_ctx *ctx, short revents)
{

	if ((revents & POLLNVAL) != 0)
		return (iou_err(ctx, EBADF));
	/* POLLIN/PRI/OUT/ERR/HUP share values between BSD and Linux. */
	return ((int32_t)(revents &
	    (POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLRDNORM |
	    POLLWRNORM | POLLRDBAND | POLLWRBAND)));
}

/*
 * Wait for either the ring to become readable (a completion posted) or one of
 * the armed POLL_ADD targets to become ready, via kern_poll_kfds over the ring
 * fd plus the target fds.  Ready single-shot polls are moved to the ready list
 * (the enter loop's run_ready posts them and runs any linked successor).
 * Runs in the io_uring_enter thread, so target fds resolve against its table.
 */
static int
iou_poll_scan(struct io_uring_ctx *ctx, int ringfd, struct thread *td)
{
	struct pollfd *kfds;
	struct iou_req **reqs, *req;
	int error, n, i;

	mtx_lock(&ctx->mtx);
	n = ctx->npolls;
	mtx_unlock(&ctx->mtx);
	if (n <= 0)
		return (0);

	kfds = malloc((n + 1) * sizeof(*kfds), M_LINUX_IOURING, M_WAITOK | M_ZERO);
	reqs = malloc(n * sizeof(*reqs), M_LINUX_IOURING, M_WAITOK | M_ZERO);
	mtx_lock(&ctx->mtx);
	i = 0;
	TAILQ_FOREACH(req, &ctx->polls, entry) {
		if (i >= n)
			break;
		kfds[i + 1].fd = req->sqe.fd;
		kfds[i + 1].events = (short)req->sqe.poll32_events;
		reqs[i] = req;
		i++;
	}
	n = i;
	mtx_unlock(&ctx->mtx);
	kfds[0].fd = ringfd;
	kfds[0].events = POLLIN;

	error = kern_poll_kfds(td, kfds, n + 1, NULL, NULL);
	if (error != 0) {
		free(kfds, M_LINUX_IOURING);
		free(reqs, M_LINUX_IOURING);
		return (error);
	}

	struct iou_reqq torun;
	struct iou_req *rq;

	TAILQ_INIT(&torun);
	mtx_lock(&ctx->mtx);
	for (i = 0; i < n; i++) {
		struct iou_req *r, *found = NULL;

		if (kfds[i + 1].revents == 0)
			continue;
		/* Confirm the request is still armed (not cancelled meanwhile). */
		TAILQ_FOREACH(r, &ctx->polls, entry) {
			if (r == reqs[i]) {
				found = r;
				break;
			}
		}
		if (found == NULL || found->state != IOU_ST_ARMED)
			continue;
		TAILQ_REMOVE(&ctx->polls, found, entry);
		ctx->npolls--;
		if (found->retry) {
			/* fast-poll: re-issue the op now that the fd is ready */
			found->retry = false;
			found->state = IOU_ST_NEW;
			TAILQ_INSERT_TAIL(&torun, found, entry);
		} else {
			found->state = IOU_ST_READY;
			found->res = iou_poll_res(ctx, kfds[i + 1].revents);
			TAILQ_INSERT_TAIL(&ctx->ready, found, entry);
		}
	}
	mtx_unlock(&ctx->mtx);
	free(kfds, M_LINUX_IOURING);
	free(reqs, M_LINUX_IOURING);

	/* Re-run parked ops (and their chains) outside the lock. */
	while ((rq = TAILQ_FIRST(&torun)) != NULL) {
		TAILQ_REMOVE(&torun, rq, entry);
		iou_run_chain(ctx, rq, td);
	}
	return (0);
}

static int
iou_wait_cq(struct io_uring_ctx *ctx, uint32_t min_complete, int ringfd,
    struct thread *td)
{
	int error, np;

	error = 0;
	for (;;) {
		iou_run_ready(ctx, td);
		mtx_lock(&ctx->mtx);
		if (iou_cq_ready(ctx) >= min_complete) {
			mtx_unlock(&ctx->mtx);
			break;
		}
		np = ctx->npolls;
		if (np > 0) {
			mtx_unlock(&ctx->mtx);
			/* Wait on the ring fd + poll targets together. */
			error = iou_poll_scan(ctx, ringfd, td);
			if (error != 0)
				break;
			continue;
		}
		ctx->cq_waiters++;
		error = msleep(&ctx->cq_waiters, &ctx->mtx, PCATCH, "iouring", 0);
		ctx->cq_waiters--;
		mtx_unlock(&ctx->mtx);
		if (error != 0)
			break;
	}
	if (error == ERESTART || error == EINTR)
		error = EINTR;
	return (error);
}

/* ---- fileops ---- */
static int
iou_fo_mmap(struct file *fp, vm_map_t map, vm_offset_t *addr, vm_size_t size,
    vm_prot_t prot, vm_prot_t maxprot, int flags, vm_ooffset_t foff,
    struct thread *td)
{
	struct io_uring_ctx *ctx = fp->f_data;
	vm_ooffset_t objoff;
	int error;

	switch (foff) {
	case IORING_OFF_SQ_RING:
	case IORING_OFF_CQ_RING:
		objoff = 0;
		if (size > ctx->ring_region)
			return (EINVAL);
		break;
	case IORING_OFF_SQES:
		objoff = ctx->sqes_off;
		if (size > ctx->sqes_size)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}
	vm_object_reference(ctx->obj);
	error = vm_mmap_object(map, addr, size, prot, maxprot, flags, ctx->obj,
	    objoff, FALSE, td);
	if (error != 0)
		vm_object_deallocate(ctx->obj);
	return (error);
}

static int
iou_fo_poll(struct file *fp, int events, struct ucred *cred, struct thread *td)
{
	struct io_uring_ctx *ctx = fp->f_data;
	int revents = 0;

	mtx_lock(&ctx->mtx);
	if ((events & (POLLIN | POLLRDNORM)) != 0 && iou_cq_ready(ctx) > 0)
		revents |= events & (POLLIN | POLLRDNORM);
	if (revents == 0 && (events & (POLLIN | POLLRDNORM)) != 0)
		selrecord(td, &ctx->sel);
	mtx_unlock(&ctx->mtx);
	return (revents);
}

static int
iou_fo_close(struct file *fp, struct thread *td)
{
	struct io_uring_ctx *ctx = fp->f_data;

	fp->f_data = NULL;
	if (ctx != NULL)
		iou_ctx_free(ctx);
	return (0);
}

static int
iou_fo_stat(struct file *fp, struct stat *sb, struct ucred *cred)
{

	bzero(sb, sizeof(*sb));
	sb->st_mode = S_IFIFO;
	return (0);
}

static int
iou_fo_fill_kinfo(struct file *fp, struct kinfo_file *kif, struct filedesc *fdp)
{

	kif->kf_type = KF_TYPE_UNKNOWN;
	return (0);
}

static const struct fileops linux_iouring_ops = {
	.fo_read = invfo_rdwr,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = invfo_ioctl,
	.fo_poll = iou_fo_poll,
	.fo_kqfilter = invfo_kqfilter,
	.fo_stat = iou_fo_stat,
	.fo_close = iou_fo_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_mmap = iou_fo_mmap,
	.fo_fill_kinfo = iou_fo_fill_kinfo,
	.fo_cmp = file_kcmp_generic,
	.fo_flags = DFLAG_PASSABLE,
};

/* ---- KPI: setup / enter / register ---- */
int
kern_io_uring_setup(struct thread *td, uint32_t entries,
    struct io_uring_params *p, bool linux_abi, int *fdp)
{
	struct io_uring_ctx *ctx;
	struct file *fp;
	int error, fd;

	if (entries == 0 || entries > IOU_MAX_ENTRIES)
		return (EINVAL);
	/* Only the plain ring; reject setup flags we do not honor. */
	if (p->flags != 0)
		return (EINVAL);
	if (p->resv[0] != 0 || p->resv[1] != 0 || p->resv[2] != 0)
		return (EINVAL);

	ctx = malloc(sizeof(*ctx), M_LINUX_IOURING, M_WAITOK | M_ZERO);
	mtx_init(&ctx->mtx, "iouring", NULL, MTX_DEF);
	knlist_init_mtx(&ctx->sel.si_note, &ctx->mtx);
	TAILQ_INIT(&ctx->pending);
	TAILQ_INIT(&ctx->ready);
	TAILQ_INIT(&ctx->drain);
	TAILQ_INIT(&ctx->pbufs);
	TAILQ_INIT(&ctx->polls);
	ctx->sq_entries = 1U << flsl(entries - 1);	/* round up to pow2 */
	if (ctx->sq_entries < entries)
		ctx->sq_entries <<= 1;
	if (ctx->sq_entries < 1)
		ctx->sq_entries = 1;
	ctx->cq_entries = ctx->sq_entries * 2;
	ctx->setup_flags = p->flags;
	ctx->is_linux = linux_abi;
	/*
	 * Route non-core opcodes to the Linux front-end's handler.  When the
	 * core is relocated to sys/kern this becomes a registration hook the
	 * Linux module installs; a native front-end supplies its own (or none).
	 */
	ctx->issue_ext = linux_abi ? linux_iou_issue_ext : NULL;

	error = iou_ring_alloc(ctx);
	if (error != 0) {
		knlist_destroy(&ctx->sel.si_note);
		mtx_destroy(&ctx->mtx);
		free(ctx, M_LINUX_IOURING);
		return (error);
	}

	error = falloc(td, &fp, &fd, 0);
	if (error != 0) {
		iou_ctx_free(ctx);
		return (error);
	}
	finit(fp, FREAD | FWRITE, DTYPE_IORING, ctx, &linux_iouring_ops);

	p->sq_entries = ctx->sq_entries;
	p->cq_entries = ctx->cq_entries;
	p->features = IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP |
	    IORING_FEAT_SUBMIT_STABLE | IORING_FEAT_RW_CUR_POS |
	    IORING_FEAT_CUR_PERSONALITY | IORING_FEAT_FAST_POLL |
	    IORING_FEAT_POLL_32BITS;
	p->sq_off.head = offsetof(struct iou_rings, sq_head);
	p->sq_off.tail = offsetof(struct iou_rings, sq_tail);
	p->sq_off.ring_mask = offsetof(struct iou_rings, sq_ring_mask);
	p->sq_off.ring_entries = offsetof(struct iou_rings, sq_ring_entries);
	p->sq_off.flags = offsetof(struct iou_rings, sq_flags);
	p->sq_off.dropped = offsetof(struct iou_rings, sq_dropped);
	p->sq_off.array = (uint32_t)((char *)ctx->sq_array - ctx->kva);
	p->cq_off.head = offsetof(struct iou_rings, cq_head);
	p->cq_off.tail = offsetof(struct iou_rings, cq_tail);
	p->cq_off.ring_mask = offsetof(struct iou_rings, cq_ring_mask);
	p->cq_off.ring_entries = offsetof(struct iou_rings, cq_ring_entries);
	p->cq_off.overflow = offsetof(struct iou_rings, cq_overflow);
	p->cq_off.cqes = (uint32_t)((char *)ctx->cqes - ctx->kva);
	p->cq_off.flags = offsetof(struct iou_rings, cq_flags);

	*fdp = fd;
	fdrop(fp, td);
	return (0);
}

int
kern_io_uring_enter(struct thread *td, int fd, uint32_t to_submit,
    uint32_t min_complete, uint32_t flags, const void *arg __unused,
    size_t argsz __unused)
{
	struct io_uring_ctx *ctx;
	struct file *fp;
	int error, submitted;

	if ((flags & ~(IORING_ENTER_GETEVENTS)) != 0)
		return (EINVAL);	/* GETEVENTS only (no SQPOLL/registered) */
	error = fget(td, fd, &cap_no_rights, &fp);
	if (error != 0)
		return (error);
	if (fp->f_type != DTYPE_IORING) {
		fdrop(fp, td);
		return (EOPNOTSUPP);
	}
	ctx = fp->f_data;
	submitted = iou_submit(ctx, to_submit, td);
	/* Post any completions that resolved during/ahead of this submit. */
	iou_run_ready(ctx, td);
	if ((flags & IORING_ENTER_GETEVENTS) != 0 && min_complete > 0) {
		error = iou_wait_cq(ctx, min_complete, fd, td);
		if (error != 0 && submitted == 0) {
			fdrop(fp, td);
			return (error);
		}
	}
	fdrop(fp, td);
	td->td_retval[0] = submitted;
	return (0);
}

/* ---- registered buffers ---- */
static int
iou_register_buffers(struct io_uring_ctx *ctx, void *arg, uint32_t nr)
{
	struct iovec *bufs;
	int error;

	if (nr == 0 || nr > IOU_MAX_REG_BUFS)
		return (EINVAL);
	mtx_lock(&ctx->mtx);
	if (ctx->reg_bufs != NULL) {
		mtx_unlock(&ctx->mtx);
		return (EBUSY);
	}
	mtx_unlock(&ctx->mtx);
	bufs = malloc(nr * sizeof(*bufs), M_LINUX_IOURING, M_WAITOK | M_ZERO);
	/* Linux struct iovec is layout-identical on LP64. */
	error = copyin(arg, bufs, nr * sizeof(*bufs));
	if (error != 0) {
		free(bufs, M_LINUX_IOURING);
		return (error);
	}
	mtx_lock(&ctx->mtx);
	if (ctx->reg_bufs != NULL) {
		mtx_unlock(&ctx->mtx);
		free(bufs, M_LINUX_IOURING);
		return (EBUSY);
	}
	ctx->reg_bufs = bufs;
	ctx->reg_nbufs = nr;
	mtx_unlock(&ctx->mtx);
	return (0);
}

static int
iou_unregister_buffers(struct io_uring_ctx *ctx)
{
	struct iovec *bufs;

	mtx_lock(&ctx->mtx);
	if (ctx->reg_bufs == NULL) {
		mtx_unlock(&ctx->mtx);
		return (ENXIO);
	}
	bufs = ctx->reg_bufs;
	ctx->reg_bufs = NULL;
	ctx->reg_nbufs = 0;
	mtx_unlock(&ctx->mtx);
	free(bufs, M_LINUX_IOURING);
	return (0);
}

/* ---- registered files ---- */
static int
iou_register_files(struct io_uring_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{
	struct file **files;
	int *fds, error;
	uint32_t i;

	if (nr == 0 || nr > IOU_MAX_REG_FILES)
		return (EINVAL);
	mtx_lock(&ctx->mtx);
	if (ctx->reg_files != NULL) {
		mtx_unlock(&ctx->mtx);
		return (EBUSY);
	}
	mtx_unlock(&ctx->mtx);

	fds = malloc(nr * sizeof(*fds), M_LINUX_IOURING, M_WAITOK);
	error = copyin(arg, fds, nr * sizeof(*fds));
	if (error != 0) {
		free(fds, M_LINUX_IOURING);
		return (error);
	}
	files = malloc(nr * sizeof(*files), M_LINUX_IOURING, M_WAITOK | M_ZERO);
	for (i = 0; i < nr; i++) {
		if (fds[i] == -1)
			continue;		/* sparse slot */
		error = fget(td, fds[i], &cap_no_rights, &files[i]);
		if (error != 0) {
			while (i-- > 0)
				if (files[i] != NULL)
					fdrop(files[i], td);
			free(files, M_LINUX_IOURING);
			free(fds, M_LINUX_IOURING);
			return (error);
		}
	}
	free(fds, M_LINUX_IOURING);

	mtx_lock(&ctx->mtx);
	if (ctx->reg_files != NULL) {
		mtx_unlock(&ctx->mtx);
		for (i = 0; i < nr; i++)
			if (files[i] != NULL)
				fdrop(files[i], td);
		free(files, M_LINUX_IOURING);
		return (EBUSY);
	}
	ctx->reg_files = files;
	ctx->reg_nfiles = nr;
	mtx_unlock(&ctx->mtx);
	return (0);
}

static int
iou_unregister_files(struct io_uring_ctx *ctx, struct thread *td)
{
	struct file **files;
	uint32_t i, nr;

	mtx_lock(&ctx->mtx);
	if (ctx->reg_files == NULL) {
		mtx_unlock(&ctx->mtx);
		return (ENXIO);
	}
	files = ctx->reg_files;
	nr = ctx->reg_nfiles;
	ctx->reg_files = NULL;
	ctx->reg_nfiles = 0;
	mtx_unlock(&ctx->mtx);
	for (i = 0; i < nr; i++)
		if (files[i] != NULL)
			fdrop(files[i], td);
	free(files, M_LINUX_IOURING);
	return (0);
}

/* IORING_REGISTER_FILES_UPDATE: unpack the struct, then update a slot range. */
static int
iou_files_update(struct io_uring_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{
	struct io_uring_files_update up;
	int error;

	error = copyin(arg, &up, sizeof(up));
	if (error != 0)
		return (error);
	return (iou_do_files_update(ctx, up.offset, up.fds, nr, td));
}

/* Core: replace registered-file slots [off, off+nr) from the fd array. */
static int
iou_do_files_update(struct io_uring_ctx *ctx, uint32_t off, uint64_t fds_uptr,
    uint32_t nr, struct thread *td)
{
	struct file *newfp, *oldfp;
	int *fds, error, fd;
	uint32_t i, done;

	if (nr == 0)
		return (EINVAL);
	fds = malloc(nr * sizeof(*fds), M_LINUX_IOURING, M_WAITOK);
	error = copyin((void *)(uintptr_t)fds_uptr, fds, nr * sizeof(*fds));
	if (error != 0) {
		free(fds, M_LINUX_IOURING);
		return (error);
	}
	mtx_lock(&ctx->mtx);
	if (ctx->reg_files == NULL || off >= ctx->reg_nfiles ||
	    off + nr > ctx->reg_nfiles) {
		mtx_unlock(&ctx->mtx);
		free(fds, M_LINUX_IOURING);
		return (EINVAL);
	}
	mtx_unlock(&ctx->mtx);

	done = 0;
	for (i = 0; i < nr; i++) {
		fd = fds[i];
		newfp = NULL;
		if (fd != -1) {
			error = fget(td, fd, &cap_no_rights, &newfp);
			if (error != 0)
				break;
		}
		mtx_lock(&ctx->mtx);
		oldfp = ctx->reg_files[off + i];
		ctx->reg_files[off + i] = newfp;
		mtx_unlock(&ctx->mtx);
		if (oldfp != NULL)
			fdrop(oldfp, td);
		done++;
	}
	free(fds, M_LINUX_IOURING);
	td->td_retval[0] = done;
	return (error);
}

static int
iou_register_probe(struct io_uring_ctx *ctx, void *arg, uint32_t nr)
{
	struct io_uring_probe *probe;
	size_t sz;
	uint32_t i;
	int error;

	if (nr > IORING_OP_LAST)
		nr = IORING_OP_LAST;
	sz = sizeof(*probe) + nr * sizeof(struct io_uring_probe_op);
	probe = malloc(sz, M_LINUX_IOURING, M_WAITOK | M_ZERO);
	error = copyin(arg, probe, sz);
	if (error != 0) {
		free(probe, M_LINUX_IOURING);
		return (error);
	}
	probe->last_op = IORING_OP_LAST - 1;
	probe->ops_len = nr;
	for (i = 0; i < nr; i++) {
		probe->ops[i].op = i;
		probe->ops[i].flags = iou_op_supported(i) ?
		    IO_URING_OP_SUPPORTED : 0;
	}
	error = copyout(probe, arg, sz);
	free(probe, M_LINUX_IOURING);
	return (error);
}

int
kern_io_uring_register(struct thread *td, int fd, uint32_t op, void *arg,
    uint32_t nr_args)
{
	struct io_uring_ctx *ctx;
	struct file *fp;
	int error;

	error = fget(td, fd, &cap_no_rights, &fp);
	if (error != 0)
		return (error);
	if (fp->f_type != DTYPE_IORING) {
		fdrop(fp, td);
		return (EOPNOTSUPP);
	}
	ctx = fp->f_data;
	switch (op) {
	case IORING_REGISTER_PROBE:
		error = iou_register_probe(ctx, arg, nr_args);
		break;
	case IORING_REGISTER_BUFFERS:
		error = iou_register_buffers(ctx, arg, nr_args);
		break;
	case IORING_UNREGISTER_BUFFERS:
		error = iou_unregister_buffers(ctx);
		break;
	case IORING_REGISTER_FILES:
		error = iou_register_files(ctx, arg, nr_args, td);
		break;
	case IORING_UNREGISTER_FILES:
		error = iou_unregister_files(ctx, td);
		break;
	case IORING_REGISTER_FILES_UPDATE:
		error = iou_files_update(ctx, arg, nr_args, td);
		break;
	default:
		error = EINVAL;		/* later phases */
		break;
	}
	fdrop(fp, td);
	return (error);
}

/* ---- Linux front-end ---- */
int
linux_io_uring_setup(struct thread *td, struct linux_io_uring_setup_args *args)
{
	struct io_uring_params p;
	int error, fd;

	error = copyin(args->params, &p, sizeof(p));
	if (error != 0)
		return (error);
	error = kern_io_uring_setup(td, args->entries, &p, true, &fd);
	if (error != 0)
		return (error);
	error = copyout(&p, args->params, sizeof(p));
	if (error != 0) {
		(void)kern_close(td, fd);
		return (error);
	}
	td->td_retval[0] = fd;
	return (0);
}

int
linux_io_uring_enter(struct thread *td, struct linux_io_uring_enter_args *args)
{

	return (kern_io_uring_enter(td, args->fd, args->to_submit,
	    args->min_complete, args->flags, NULL, 0));
}

int
linux_io_uring_register(struct thread *td,
    struct linux_io_uring_register_args *args)
{

	return (kern_io_uring_register(td, args->fd, args->opcode,
	    args->arg, args->nr_args));
}
