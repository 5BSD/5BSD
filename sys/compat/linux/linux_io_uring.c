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
	int		cq_waiters;
	/* async request tracking (all under mtx) */
	struct iou_reqq	pending;	/* IOU_ST_ARMED reqs */
	struct iou_reqq	ready;		/* IOU_ST_READY reqs, need draining */
	struct iou_reqq	drain;		/* chain heads held by a barrier */
	int		npending;	/* length of pending */
	uint32_t	cq_count;	/* real completions, for count timeouts */
};

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
	case IORING_OP_FSYNC:
	case IORING_OP_CLOSE:
	case IORING_OP_FTRUNCATE:
	case IORING_OP_FALLOCATE:
	case IORING_OP_FADVISE:
	case IORING_OP_TIMEOUT:
	case IORING_OP_TIMEOUT_REMOVE:
	case IORING_OP_ASYNC_CANCEL:
		return (true);
	default:
		return (false);	/* filled in by later phases */
	}
}

static bool
iou_op_async(uint8_t op)
{

	/* Ops that do not complete synchronously in the submitting thread. */
	return (op == IORING_OP_TIMEOUT);
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
	while ((req = TAILQ_FIRST(&ctx->drain)) != NULL) {
		TAILQ_REMOVE(&ctx->drain, req, entry);
		while (req != NULL) {
			struct iou_req *next = req->link_next;
			iou_req_free(req);
			req = next;
		}
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
	if (res >= 0 && (req->sqe_flags & IOSQE_CQE_SKIP_SUCCESS) != 0) {
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
/* Result of an issued op: byte count / 0, or a negative *Linux* errno. */
static int32_t
iou_result(struct thread *td, int error)
{

	if (error != 0)
		return (bsd_to_linux_errno(error));	/* already a negative Linux errno */
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
		req->res = -LINUX_ECANCELED;
		TAILQ_REMOVE(&ctx->pending, req, entry);
		ctx->npending--;
		TAILQ_INSERT_TAIL(&ctx->ready, req, entry);
		iou_wake(ctx);
		return (true);
	}
	return (false);
}

/*
 * Execute one synchronous SQE inline in the submitting thread's context (so
 * target fds and user buffers resolve against the caller).  Returns the Linux
 * completion result.  A -1 offset means "current file position".
 */
static int32_t
iou_issue_inline(struct io_uring_ctx *ctx, struct iou_req *req,
    struct thread *td)
{
	const struct io_uring_sqe *sqe = &req->sqe;
	struct uio auio, *uiop;
	struct iovec aiov;
	off_t off;
	int error;
	bool cur;

	off = (off_t)sqe->off;
	cur = (sqe->off == (uint64_t)-1);
	td->td_retval[0] = 0;	/* zero-returning ops report 0, not a stale count */

	/* Fixed (registered) descriptors are a later phase. */
	if ((req->sqe_flags & IOSQE_FIXED_FILE) != 0)
		return (-LINUX_EBADF);
	/* Provided-buffer selection is a later phase. */
	if ((req->sqe_flags & IOSQE_BUFFER_SELECT) != 0)
		return (-EINVAL);

	switch (sqe->opcode) {
	case IORING_OP_NOP:
		return (0);
	case IORING_OP_READ:
	case IORING_OP_WRITE:
		aiov.iov_base = (void *)(uintptr_t)sqe->addr;
		aiov.iov_len = sqe->len;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = cur ? -1 : off;
		auio.uio_resid = sqe->len;
		auio.uio_segflg = UIO_USERSPACE;
		auio.uio_td = td;
		if (sqe->opcode == IORING_OP_READ) {
			auio.uio_rw = UIO_READ;
			error = cur ? kern_readv(td, sqe->fd, &auio) :
			    kern_preadv(td, sqe->fd, &auio, off);
		} else {
			auio.uio_rw = UIO_WRITE;
			error = cur ? kern_writev(td, sqe->fd, &auio) :
			    kern_pwritev(td, sqe->fd, &auio, off);
		}
		return (iou_result(td, error));
	case IORING_OP_READV:
	case IORING_OP_WRITEV:
		error = copyinuio((void *)(uintptr_t)sqe->addr, sqe->len, &uiop);
		if (error != 0)
			return (bsd_to_linux_errno(error));
		if (sqe->opcode == IORING_OP_READV)
			error = cur ? kern_readv(td, sqe->fd, uiop) :
			    kern_preadv(td, sqe->fd, uiop, off);
		else
			error = cur ? kern_writev(td, sqe->fd, uiop) :
			    kern_pwritev(td, sqe->fd, uiop, off);
		free(uiop, M_IOV);
		return (iou_result(td, error));
	case IORING_OP_FSYNC:
		/* IORING_FSYNC_DATASYNC selects fdatasync. */
		error = kern_fsync(td, sqe->fd,
		    (sqe->fsync_flags & 1 /* DATASYNC */) == 0);
		return (iou_result(td, error));
	case IORING_OP_CLOSE:
		return (iou_result(td, kern_close(td, sqe->fd)));
	case IORING_OP_FTRUNCATE:
		return (iou_result(td, kern_ftruncate(td, sqe->fd, off)));
	case IORING_OP_FALLOCATE:
		/* off/addr/len = offset/len/mode; mode 0 == plain allocate. */
		if (sqe->len != 0)
			return (bsd_to_linux_errno(EOPNOTSUPP)); /* modes: later */
		return (iou_result(td, kern_posix_fallocate(td, sqe->fd, off,
		    (off_t)sqe->addr)));
	case IORING_OP_FADVISE: {
		off_t len = sqe->addr != 0 ? (off_t)sqe->addr : (off_t)sqe->len;

		/* POSIX_FADV_* share values on Linux and FreeBSD. */
		return (iou_result(td, kern_posix_fadvise(td, sqe->fd, off, len,
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
		return (found ? 0 : -LINUX_ENOENT);
	}
	default:
		return (-EINVAL);	/* Linux EINVAL == BSD EINVAL (22) */
	}
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
	    0 : -LINUX_ENOTIME /* Linux ETIME (62) */;
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

	KASSERT(sqe->opcode == IORING_OP_TIMEOUT, ("not a timeout"));
	flags = sqe->timeout_flags;
	/* Reject flags whose behaviour we do not implement. */
	if ((flags & ~(IORING_TIMEOUT_ABS | IORING_TIMEOUT_BOOTTIME |
	    IORING_TIMEOUT_REALTIME | IORING_TIMEOUT_ETIME_SUCCESS)) != 0)
		return (-EINVAL);
	error = copyin((void *)(uintptr_t)sqe->addr, &kts, sizeof(kts));
	if (error != 0)
		return (bsd_to_linux_errno(error));
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
		iou_complete(ctx, req, -LINUX_ECANCELED, 0);
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

		res = iou_issue_inline(ctx, req, td);
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
		cancelled = res == -LINUX_ECANCELED ||
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

static int
iou_wait_cq(struct io_uring_ctx *ctx, uint32_t min_complete, struct thread *td)
{
	int error;

	error = 0;
	for (;;) {
		iou_run_ready(ctx, td);
		mtx_lock(&ctx->mtx);
		if (iou_cq_ready(ctx) >= min_complete) {
			mtx_unlock(&ctx->mtx);
			break;
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
    struct io_uring_params *p, int *fdp)
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
	ctx->sq_entries = 1U << flsl(entries - 1);	/* round up to pow2 */
	if (ctx->sq_entries < entries)
		ctx->sq_entries <<= 1;
	if (ctx->sq_entries < 1)
		ctx->sq_entries = 1;
	ctx->cq_entries = ctx->sq_entries * 2;
	ctx->setup_flags = p->flags;

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
		error = iou_wait_cq(ctx, min_complete, td);
		if (error != 0 && submitted == 0) {
			fdrop(fp, td);
			return (error);
		}
	}
	fdrop(fp, td);
	td->td_retval[0] = submitted;
	return (0);
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
	error = kern_io_uring_setup(td, args->entries, &p, &fd);
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
