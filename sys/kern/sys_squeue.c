/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * squeue: the native 5BSD completion-ring engine.
 *
 * This is the ABI-neutral core of the io_uring-compatible ring: the shared
 * SQ/CQ/SQE rings (a wired OBJT_PHYS object dual-mapped into the kernel and,
 * via fo_mmap, into the process), the submit/complete/wait loop, the async
 * request model (link chains, drain barrier, timeouts, cancellation, fast
 * poll), registered files/buffers, provided buffers, and every opcode that
 * uses only kern_* interfaces.  ABI-specific opcodes (flag/path/sockaddr
 * translation) are supplied by a front-end via ctx->issue_ext.
 *
 * Two front-ends drive this engine: the native squeue_setup/squeue_enter/
 * squeue_register syscalls below, and the Linux io_uring front-end in
 * sys/compat/linux/linux_io_uring.c (which registers its errno translator and
 * opcode extension).  The engine itself has no Linux dependencies.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/capsicum.h>
#include <sys/condvar.h>
#include <sys/event.h>
#include <sys/eventfd.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/resourcevar.h>
#include <sys/rwlock.h>
#include <sys/sysctl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/vmmeter.h>
#include <sys/sbuf.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/uio.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/pmap.h>

#include <sys/io_uring.h>
#include <sys/squeue.h>

MALLOC_DEFINE(M_SQUEUE, "squeue", "5BSD completion-ring (squeue) engine");

#define	SQ_MAX_REG_FILES	4096
#define	SQ_MAX_REG_BUFS	1024

/*
 * System-wide bound on the physical memory all squeue rings may wire, so a
 * process cannot exhaust wired memory by creating many/large rings.  Defaulted
 * to 1/8 of RAM at boot and tunable via kern.squeue.max_wired_pages.
 */
static u_long	sq_wired_pages;		/* currently wired by all rings */
static u_long	sq_max_wired_pages;	/* cap (0 = uninitialised) */

static SYSCTL_NODE(_kern, OID_AUTO, squeue, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "5BSD squeue completion-ring engine");
SYSCTL_ULONG(_kern_squeue, OID_AUTO, wired_pages, CTLFLAG_RD, &sq_wired_pages,
    0, "Physical pages currently wired by squeue rings");
SYSCTL_ULONG(_kern_squeue, OID_AUTO, max_wired_pages, CTLFLAG_RW,
    &sq_max_wired_pages, 0, "Maximum physical pages squeue rings may wire");

static void
sq_wired_init(void *dummy __unused)
{

	if (sq_max_wired_pages == 0)
		sq_max_wired_pages = vm_cnt.v_page_count / 8;
}
SYSINIT(squeue_wired, SI_SUB_KMEM, SI_ORDER_ANY, sq_wired_init, NULL);

/* ---- opcode support matrix (drives dispatch + PROBE) ---- */
static bool
sq_op_supported(uint8_t op)
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
sq_op_async(uint8_t op)
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
sq_pollable_events(uint8_t op)
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
sq_ring_alloc(struct squeue_ctx *ctx)
{
	vm_page_t *ma;
	vm_size_t cqes_off, array_off;
	int i, npages;

	/* Region 0: header, then cqes[cq_entries], then sq array[sq_entries]. */
	cqes_off = roundup2(sizeof(struct sq_rings), sizeof(struct io_uring_cqe));
	array_off = cqes_off + (vm_size_t)ctx->cq_entries * sizeof(struct io_uring_cqe);
	ctx->ring_region = round_page(array_off +
	    (vm_size_t)ctx->sq_entries * sizeof(uint32_t));
	ctx->sqes_off = ctx->ring_region;
	ctx->sqes_size = round_page((vm_size_t)ctx->sq_entries *
	    sizeof(struct io_uring_sqe));
	ctx->objsize = ctx->ring_region + ctx->sqes_size;
	npages = atop(ctx->objsize);

	/*
	 * Bound wired memory.  Per-process: the ring's pages must fit within
	 * RLIMIT_MEMLOCK unless the caller holds PRIV_VM_MLOCK (matching mlock).
	 * System-wide: reserve against the global cap so many rings cannot
	 * exhaust wired memory.
	 */
	if (ptoa((vm_offset_t)npages) > lim_cur(curthread, RLIMIT_MEMLOCK) &&
	    priv_check(curthread, PRIV_VM_MLOCK) != 0)
		return (ENOMEM);
	if (atomic_fetchadd_long(&sq_wired_pages, npages) + npages >
	    sq_max_wired_pages) {
		atomic_subtract_long(&sq_wired_pages, npages);
		return (ENOMEM);
	}

	ctx->obj = vm_pager_allocate(OBJT_PHYS, NULL, ctx->objsize,
	    VM_PROT_DEFAULT, 0, curthread->td_ucred);
	if (ctx->obj == NULL) {
		atomic_subtract_long(&sq_wired_pages, npages);
		return (ENOMEM);
	}
	ctx->kva = (char *)kva_alloc(ctx->objsize);
	if (ctx->kva == NULL) {
		vm_object_deallocate(ctx->obj);
		ctx->obj = NULL;
		atomic_subtract_long(&sq_wired_pages, npages);
		return (ENOMEM);
	}
	ma = malloc(npages * sizeof(*ma), M_SQUEUE, M_WAITOK);
	VM_OBJECT_WLOCK(ctx->obj);
	for (i = 0; i < npages; i++) {
		ma[i] = vm_page_grab(ctx->obj, i, VM_ALLOC_NORMAL |
		    VM_ALLOC_WIRED | VM_ALLOC_ZERO);
		vm_page_valid(ma[i]);
		vm_page_xunbusy(ma[i]);
	}
	VM_OBJECT_WUNLOCK(ctx->obj);
	pmap_qenter(ctx->kva, ma, npages);
	free(ma, M_SQUEUE);

	ctx->rings = (struct sq_rings *)ctx->kva;
	ctx->cqes = (struct io_uring_cqe *)(ctx->kva + cqes_off);
	ctx->sq_array = (uint32_t *)(ctx->kva + array_off);
	ctx->sqes = (struct io_uring_sqe *)(ctx->kva + ctx->sqes_off);

	ctx->rings->sq_ring_mask = ctx->sq_mask = ctx->sq_entries - 1;
	ctx->rings->cq_ring_mask = ctx->cq_mask = ctx->cq_entries - 1;
	ctx->rings->sq_ring_entries = ctx->sq_entries;
	ctx->rings->cq_ring_entries = ctx->cq_entries;
	return (0);
}

static void sq_req_free(struct sq_req *req);
static void sq_ctx_rele(struct squeue_ctx *ctx);
static int sq_kq_arm(struct squeue_ctx *ctx, struct sq_req *req,
    struct thread *td);
static void sq_kq_del(struct squeue_ctx *ctx, int fd, short filter,
    struct thread *td);
static short sq_kq_filter(const struct sq_req *req);

static void
sq_ctx_free(struct squeue_ctx *ctx)
{
	struct sq_req *req;

	/*
	 * No more references to the ring: drain any outstanding requests.
	 * Callouts are stopped (callout_drain) before the memory is released.
	 *
	 * Drop the readiness kqueue first: its knotes carry udata pointers to
	 * the poll requests we are about to free, so draining them (fdrop ->
	 * kqueue_close -> knote teardown) before the frees guarantees no knote
	 * can reference freed memory afterwards.
	 */
	if (ctx->kqfp != NULL) {
		fdrop(ctx->kqfp, curthread);
		ctx->kqfp = NULL;
	}
	/*
	 * A pending IORING_OP_TIMEOUT still has a live callout that fires under
	 * ctx->mtx and mutates ctx->pending/ready.  Splice every list to a local
	 * head under the lock, and neutralise each pending request's state first
	 * so a racing callout (sq_timeout_cb checks state == ARMED) becomes a
	 * no-op instead of touching a list we are tearing down.  Then free
	 * locally - sq_req_free's callout_drain waits out any in-flight callout.
	 */
	{
		struct sq_reqq lpending, lready, lpolls, ldrain;
		struct sq_req *next;

		TAILQ_INIT(&lpending);
		TAILQ_INIT(&lready);
		TAILQ_INIT(&lpolls);
		TAILQ_INIT(&ldrain);
		mtx_lock(&ctx->mtx);
		TAILQ_FOREACH(req, &ctx->pending, entry)
			req->state = SQ_ST_READY;	/* disarm racing callout */
		TAILQ_CONCAT(&lpending, &ctx->pending, entry);
		TAILQ_CONCAT(&lready, &ctx->ready, entry);
		TAILQ_CONCAT(&lpolls, &ctx->polls, entry);
		TAILQ_CONCAT(&ldrain, &ctx->drain, entry);
		ctx->npending = 0;
		ctx->npolls = 0;
		mtx_unlock(&ctx->mtx);

		while ((req = TAILQ_FIRST(&lpending)) != NULL) {
			TAILQ_REMOVE(&lpending, req, entry);
			sq_req_free(req);
		}
		while ((req = TAILQ_FIRST(&lready)) != NULL) {
			TAILQ_REMOVE(&lready, req, entry);
			sq_req_free(req);
		}
		while ((req = TAILQ_FIRST(&lpolls)) != NULL) {
			TAILQ_REMOVE(&lpolls, req, entry);
			sq_req_free(req);
		}
		while ((req = TAILQ_FIRST(&ldrain)) != NULL) {
			TAILQ_REMOVE(&ldrain, req, entry);
			while (req != NULL) {
				next = req->link_next;
				sq_req_free(req);
				req = next;
			}
		}
	}

	{
		struct sq_ovfl *o;

		while ((o = TAILQ_FIRST(&ctx->overflow)) != NULL) {
			TAILQ_REMOVE(&ctx->overflow, o, entry);
			free(o, M_SQUEUE);
		}
	}
	if (ctx->eventfd_fp != NULL) {
		fdrop(ctx->eventfd_fp, curthread);
		ctx->eventfd_fp = NULL;
		ctx->eventfd = NULL;
	}
	{
		struct sq_pbuf *pb;

		while ((pb = TAILQ_FIRST(&ctx->pbufs)) != NULL) {
			TAILQ_REMOVE(&ctx->pbufs, pb, entry);
			free(pb, M_SQUEUE);
		}
	}
	if (ctx->reg_bufs != NULL)
		free(ctx->reg_bufs, M_SQUEUE);
	if (ctx->reg_files != NULL) {
		uint32_t i;

		for (i = 0; i < ctx->reg_nfiles; i++) {
			if (ctx->reg_files[i] != NULL)
				fdrop(ctx->reg_files[i], curthread);
			if (ctx->reg_caps != NULL)
				filecaps_free(&ctx->reg_caps[i]);
		}
		free(ctx->reg_files, M_SQUEUE);
		free(ctx->reg_caps, M_SQUEUE);
	}
	if (ctx->kva != NULL) {
		pmap_qremove(ctx->kva, atop(ctx->objsize));
		kva_free(ctx->kva, ctx->objsize);
	}
	if (ctx->obj != NULL) {
		vm_object_deallocate(ctx->obj);
		atomic_subtract_long(&sq_wired_pages, atop(ctx->objsize));
	}
	seldrain(&ctx->sel);
	knlist_destroy(&ctx->sel.si_note);
	mtx_destroy(&ctx->mtx);
	free(ctx, M_SQUEUE);
}

/* ---- completion ---- */

/* Write one CQE directly to the ring; false if the CQ has no room. */
static bool
sq_cq_post_raw(struct squeue_ctx *ctx, uint64_t user_data, int32_t res,
    uint32_t cflags)
{
	struct io_uring_cqe *cqe;
	uint32_t tail;

	mtx_assert(&ctx->mtx, MA_OWNED);
	tail = ctx->rings->cq_tail;
	if ((uint32_t)(tail - ctx->rings->cq_head) >= ctx->cq_entries)
		return (false);
	cqe = &ctx->cqes[tail & ctx->cq_mask];
	cqe->user_data = user_data;
	cqe->res = res;
	cqe->flags = cflags;
	atomic_thread_fence_rel();
	ctx->rings->cq_tail = tail + 1;
	/* REGISTER_EVENTFD: wake an eventfd-based loop (leaf lock, safe here). */
	if (ctx->eventfd != NULL)
		eventfd_signal(ctx->eventfd);
	return (true);
}

/*
 * Flush backlogged completions into the CQ (in order) while there is room.
 * Clears the CQ-overflow flag once the backlog drains.  Caller holds mtx.
 */
static void
sq_cq_flush(struct squeue_ctx *ctx)
{
	struct sq_ovfl *o;

	mtx_assert(&ctx->mtx, MA_OWNED);
	while ((o = TAILQ_FIRST(&ctx->overflow)) != NULL) {
		if (!sq_cq_post_raw(ctx, o->user_data, o->res, o->cflags))
			return;			/* CQ full again; leave the rest */
		TAILQ_REMOVE(&ctx->overflow, o, entry);
		ctx->noverflow--;
		free(o, M_SQUEUE);
	}
	ctx->rings->sq_flags &= ~IORING_SQ_CQ_OVERFLOW;
}

/*
 * Post a completion.  Backlogged entries are flushed first so ordering is
 * preserved; if the CQ is (still) full the completion joins the backlog rather
 * than being dropped (IORING_FEAT_NODROP).  Only a genuine allocation failure
 * under memory pressure drops a completion, which the cq_overflow counter
 * records.  Caller holds ctx->mtx.
 */
void
sq_post_cqe(struct squeue_ctx *ctx, uint64_t user_data, int32_t res,
    uint32_t cflags)
{
	struct sq_ovfl *o;

	mtx_assert(&ctx->mtx, MA_OWNED);
	sq_cq_flush(ctx);
	if (TAILQ_EMPTY(&ctx->overflow) &&
	    sq_cq_post_raw(ctx, user_data, res, cflags))
		return;
	/*
	 * CQ full: preserve the completion on the backlog, but bound the backlog
	 * so a peer that never reaps (yet keeps triggering completions, e.g. a
	 * multishot poll on a busy fd) cannot exhaust kernel memory.  Past the
	 * cap the completion is dropped and only counted - the same last-resort
	 * behaviour as a genuine allocation failure.
	 */
	if (ctx->noverflow >= 4u * ctx->cq_entries)
		goto drop;
	o = malloc(sizeof(*o), M_SQUEUE, M_NOWAIT);
	if (o == NULL)
		goto drop;		/* out of memory: last resort */
	o->user_data = user_data;
	o->res = res;
	o->cflags = cflags;
	TAILQ_INSERT_TAIL(&ctx->overflow, o, entry);
	ctx->noverflow++;
	ctx->rings->cq_overflow++;
	ctx->rings->sq_flags |= IORING_SQ_CQ_OVERFLOW;
	return;
drop:
	ctx->rings->cq_overflow++;
	ctx->rings->sq_flags |= IORING_SQ_CQ_OVERFLOW;
}

static uint32_t
sq_cq_ready(struct squeue_ctx *ctx)
{

	return (ctx->rings->cq_tail - ctx->rings->cq_head);
}

void
sq_wake(struct squeue_ctx *ctx)
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
static void sq_check_count_timeouts(struct squeue_ctx *ctx);

static void
sq_complete(struct squeue_ctx *ctx, struct sq_req *req, int32_t res,
    uint32_t cflags)
{

	mtx_assert(&ctx->mtx, MA_OWNED);
	if (req->posted) {
		/* The op emitted its own CQE(s) (e.g. SEND_ZC notif). */
	} else if (res >= 0 && (req->sqe_flags & IOSQE_CQE_SKIP_SUCCESS) != 0) {
		/* Successful CQE elided by request flag. */
	} else {
		sq_post_cqe(ctx, req->user_data, res, cflags);
	}
	/*
	 * Only "real" completions advance the count that satisfies
	 * count-based timeouts; a timeout expiring must not count toward
	 * another timeout's threshold.
	 */
	if (req->opcode != IORING_OP_TIMEOUT &&
	    req->opcode != IORING_OP_LINK_TIMEOUT) {
		ctx->cq_count++;
		sq_check_count_timeouts(ctx);
	}
	sq_wake(ctx);
}

/* ---- request allocation ---- */
static void
sq_req_free(struct sq_req *req)
{

	callout_drain(&req->co);
	/*
	 * Defensive: an offloaded request normally clears these in the worker
	 * before it is readied, but release anything still held so a teardown
	 * on an unusual path cannot leak a file, uio, or vmspace reference.
	 */
	if (req->ofp != NULL)
		fdrop(req->ofp, curthread);
	if (req->ouio != NULL)
		free(req->ouio, M_IOV);
	if (req->ovm != NULL)
		vmspace_free(req->ovm);
	free(req, M_SQUEUE);
}

/* ---- inline (synchronous) opcodes ---- */
/*
 * Translate a (positive) BSD errno to the negative completion value the ring's
 * ABI expects: a negative Linux errno for the Linux front-end, or a negative
 * native errno for the native 5BSD front-end.  This keeps the engine's error
 * handling ABI-neutral - internally it works in BSD errnos.
 */
int32_t
sq_err(struct squeue_ctx *ctx, int bsd_errno)
{

	/* Front-end translator (e.g. bsd_to_linux_errno); default: negate. */
	return (ctx->err_xlate != NULL ? ctx->err_xlate(bsd_errno) :
	    -bsd_errno);
}

static int32_t
sq_etime(struct squeue_ctx *ctx)
{

	return (ctx->is_linux ? -SQ_LINUX_ETIME : -ETIMEDOUT);
}

int32_t
sq_result(struct squeue_ctx *ctx, struct thread *td, int error)
{

	if (error != 0)
		return (sq_err(ctx, error));
	return ((int32_t)td->td_retval[0]);
}

/*
 * Cancel one pending (ARMED) request by user_data, moving it to the ready
 * list with res=-ECANCELED.  Returns true if a request was cancelled.
 * Caller holds ctx->mtx.
 */
static bool
sq_cancel_one(struct squeue_ctx *ctx, uint64_t user_data)
{
	struct sq_req *req;

	mtx_assert(&ctx->mtx, MA_OWNED);
	TAILQ_FOREACH(req, &ctx->pending, entry) {
		if (req->state != SQ_ST_ARMED || req->user_data != user_data)
			continue;
		callout_stop(&req->co);
		req->state = SQ_ST_READY;
		req->res = sq_err(ctx, ECANCELED);
		TAILQ_REMOVE(&ctx->pending, req, entry);
		ctx->npending--;
		TAILQ_INSERT_TAIL(&ctx->ready, req, entry);
		sq_wake(ctx);
		return (true);
	}
	return (false);
}

/* Single-buffer read/write (READ/WRITE and READ_FIXED/WRITE_FIXED). */
static int32_t
sq_rw1(struct squeue_ctx *ctx, struct thread *td, int fd, void *buf,
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
	return (sq_result(ctx, td, error));
}

/*
 * Validate that [addr, addr+len) lies within registered buffer buf_index.
 * Returns 0 on success or a negative Linux errno (matching Linux, which
 * reports -EFAULT for an out-of-range fixed buffer and -EINVAL for a bad
 * index / no buffers registered).
 */
static int32_t
sq_check_fixed_buf(struct squeue_ctx *ctx, uint16_t idx, uint64_t addr,
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

static int sq_do_files_update(struct squeue_ctx *ctx, uint32_t off,
    uint64_t fds_uptr, uint32_t nr, struct thread *td);
static int sq_fixed_install(struct squeue_ctx *ctx, struct thread *td,
    int idx, int *fdp);

/* ---- application-provided buffers ---- */
/* PROVIDE_BUFFERS: add nbufs buffers to a group.  Returns Linux res. */
static int32_t
sq_provide_buffers(struct squeue_ctx *ctx, const struct io_uring_sqe *sqe)
{
	struct sq_pbuf *pb;
	uint32_t nbufs, i, elen;
	uint64_t base;
	uint16_t bgid, bid;

	nbufs = (uint32_t)sqe->fd;	/* PROVIDE_BUFFERS reuses fd as count */
	elen = sqe->len;		/* length of each buffer */
	base = sqe->addr;
	bgid = sqe->buf_group;
	bid = (uint16_t)sqe->off;	/* starting buffer id */
	if (nbufs == 0 || nbufs > SQ_MAX_PBUFS)
		return (-EINVAL);
	for (i = 0; i < nbufs; i++) {
		pb = malloc(sizeof(*pb), M_SQUEUE, M_WAITOK);
		pb->bgid = bgid;
		pb->bid = bid + i;
		pb->addr = base + (uint64_t)i * elen;
		pb->len = elen;
		mtx_lock(&ctx->mtx);
		/* Global cap so repeated PROVIDE_BUFFERS cannot exhaust memory. */
		if (ctx->npbufs >= SQ_MAX_PBUFS) {
			mtx_unlock(&ctx->mtx);
			free(pb, M_SQUEUE);
			return (i > 0 ? (int32_t)i : -ENOMEM);
		}
		TAILQ_INSERT_TAIL(&ctx->pbufs, pb, entry);
		ctx->npbufs++;
		mtx_unlock(&ctx->mtx);
	}
	return (0);
}

/* REMOVE_BUFFERS: drop up to nbufs from a group.  res = number removed. */
static int32_t
sq_remove_buffers(struct squeue_ctx *ctx, const struct io_uring_sqe *sqe)
{
	struct sq_pbuf *pb, *tmp;
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
		ctx->npbufs--;
		free(pb, M_SQUEUE);
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
sq_pbuf_select(struct squeue_ctx *ctx, uint16_t bgid, uint32_t want,
    uint64_t *addr, uint32_t *len, uint16_t *bid)
{
	struct sq_pbuf *pb;

	mtx_lock(&ctx->mtx);
	TAILQ_FOREACH(pb, &ctx->pbufs, entry) {
		if (pb->bgid != bgid)
			continue;
		TAILQ_REMOVE(&ctx->pbufs, pb, entry);
		ctx->npbufs--;
		mtx_unlock(&ctx->mtx);
		*addr = pb->addr;
		*len = (want == 0 || want > pb->len) ? pb->len : want;
		*bid = pb->bid;
		free(pb, M_SQUEUE);
		return (0);
	}
	mtx_unlock(&ctx->mtx);
	return (ENOBUFS);
}

/* Return a selected-but-unused buffer to the head of its group. */
static void
sq_pbuf_return(struct squeue_ctx *ctx, uint16_t bgid, uint16_t bid,
    uint64_t addr, uint32_t len)
{
	struct sq_pbuf *pb;

	pb = malloc(sizeof(*pb), M_SQUEUE, M_WAITOK);
	pb->bgid = bgid;
	pb->bid = bid;
	pb->addr = addr;
	pb->len = len;
	mtx_lock(&ctx->mtx);
	TAILQ_INSERT_HEAD(&ctx->pbufs, pb, entry);
	ctx->npbufs++;
	mtx_unlock(&ctx->mtx);
}

/*
 * Execute one synchronous ABI-neutral SQE inline in the submitting thread's
 * context (so target fds and user buffers resolve against the caller).  Uses
 * only kern_* calls, no Linux dependencies, so it can move into sys/kern.
 * Returns the completion result, or SQ_NOTHANDLED for an opcode the core does
 * not implement (sq_issue_op then routes it to the front-end's issue_ext).
 * A -1 offset means "current file position".
 */
static int32_t
sq_issue_inline(struct squeue_ctx *ctx, struct sq_req *req,
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
		error = sq_pbuf_select(ctx, sqe->buf_group, sqe->len,
		    &baddr, &blen, &bid);
		if (error != 0)
			return (sq_err(ctx, error));	/* -ENOBUFS */
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
		struct sq_req *p, *tmp;
		bool found = false, delkn = false;
		int delfd = -1;
		short delfilt = 0;

		mtx_lock(&ctx->mtx);
		TAILQ_FOREACH_SAFE(p, &ctx->polls, entry, tmp) {
			if (p->state != SQ_ST_ARMED || p->user_data != sqe->addr)
				continue;
			TAILQ_REMOVE(&ctx->polls, p, entry);
			ctx->npolls--;
			/*
			 * A multishot poll's knote is persistent (EV_CLEAR); a
			 * single-shot's is EV_ONESHOT and self-heals, so only the
			 * multishot needs an explicit delete.  Capture its
			 * (fd,filter) now while p is valid.
			 */
			if (p->multishot) {
				delkn = true;
				delfd = p->sqe.fd;
				delfilt = sq_kq_filter(p);
			}
			p->state = SQ_ST_READY;
			p->res = sq_err(ctx, ECANCELED);
			TAILQ_INSERT_TAIL(&ctx->ready, p, entry);
			sq_wake(ctx);
			found = true;
			break;
		}
		mtx_unlock(&ctx->mtx);
		if (delkn)
			sq_kq_del(ctx, delfd, delfilt, td);
		return (found ? 0 : sq_err(ctx, ENOENT));
	}
	case IORING_OP_PROVIDE_BUFFERS:
		return (sq_provide_buffers(ctx, sqe));
	case IORING_OP_REMOVE_BUFFERS:
		return (sq_remove_buffers(ctx, sqe));
	case IORING_OP_FILES_UPDATE:
		/* off=offset, len=nr, addr=fd array */
		return (sq_result(ctx, td, sq_do_files_update(ctx, (uint32_t)off,
		    sqe->addr, sqe->len, td)));
	case IORING_OP_MSG_RING: {
		struct file *tfp;
		struct squeue_ctx *tctx;

		/* Only IORING_MSG_DATA (post a CQE to a target ring). */
		if (sqe->addr != IORING_MSG_DATA)
			return (-EINVAL);
		error = fget(td, sqe->fd, &cap_no_rights, &tfp);
		if (error != 0)
			return (sq_err(ctx, error));
		if (tfp->f_type != DTYPE_IORING) {
			fdrop(tfp, td);
			return (-EOPNOTSUPP);
		}
		tctx = tfp->f_data;
		mtx_lock(&tctx->mtx);
		sq_post_cqe(tctx, sqe->off, (int32_t)sqe->len, 0);
		sq_wake(tctx);
		mtx_unlock(&tctx->mtx);
		fdrop(tfp, td);
		return (0);
	}
	case IORING_OP_NOP128:
		return (0);		/* NOP for SQE128 rings */
	case IORING_OP_FIXED_FD_INSTALL: {
		int newfd;

		/* Install a registered descriptor into the normal table. */
		error = sq_fixed_install(ctx, td, sqe->fd, &newfd);
		if (error != 0)
			return (sq_err(ctx, error));
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
		return (sq_err(ctx, ECANCELED));
	case IORING_OP_READ:
	case IORING_OP_WRITE:
		return (sq_rw1(ctx, td, sqe->fd, (void *)(uintptr_t)sqe->addr,
		    sqe->len, off, cur, sqe->opcode == IORING_OP_WRITE));
	case IORING_OP_READ_FIXED:
	case IORING_OP_WRITE_FIXED: {
		int32_t r = sq_check_fixed_buf(ctx, sqe->buf_index, sqe->addr,
		    sqe->len);

		if (r != 0)
			return (r);
		return (sq_rw1(ctx, td, sqe->fd, (void *)(uintptr_t)sqe->addr,
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
			error = sq_pbuf_select(ctx, sqe->buf_group, 0, &baddr,
			    &blen, &bid);
			if (error != 0)
				return (sq_err(ctx, ENOBUFS));	/* terminal */
			r = sq_rw1(ctx, td, sqe->fd, (void *)(uintptr_t)baddr,
			    blen, 0, true /* current pos */, false /* read */);
			if (r > 0) {
				mtx_lock(&ctx->mtx);
				sq_post_cqe(ctx, req->user_data, r,
				    IORING_CQE_F_MORE | IORING_CQE_F_BUFFER |
				    ((uint32_t)bid << IORING_CQE_BUFFER_SHIFT));
				sq_wake(ctx);
				mtx_unlock(&ctx->mtx);
				continue;		/* drain more */
			}
			/* nothing consumed: hand the buffer back */
			sq_pbuf_return(ctx, sqe->buf_group, bid, baddr, blen);
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
			return (sq_err(ctx, error));
		if (!wr)
			error = cur ? kern_readv(td, sqe->fd, uiop) :
			    kern_preadv(td, sqe->fd, uiop, off);
		else
			error = cur ? kern_writev(td, sqe->fd, uiop) :
			    kern_pwritev(td, sqe->fd, uiop, off);
		free(uiop, M_IOV);
		return (sq_result(ctx, td, error));
	}
	case IORING_OP_FSYNC:
		/* IORING_FSYNC_DATASYNC selects fdatasync. */
		error = kern_fsync(td, sqe->fd,
		    (sqe->fsync_flags & 1 /* DATASYNC */) == 0);
		return (sq_result(ctx, td, error));
	case IORING_OP_CLOSE:
		return (sq_result(ctx, td, kern_close(td, sqe->fd)));
	case IORING_OP_FTRUNCATE:
		return (sq_result(ctx, td, kern_ftruncate(td, sqe->fd, off)));
	case IORING_OP_FALLOCATE:
		/* off/addr/len = offset/len/mode; mode 0 == plain allocate. */
		if (sqe->len != 0)
			return (sq_err(ctx, EOPNOTSUPP)); /* modes: later */
		return (sq_result(ctx, td, kern_posix_fallocate(td, sqe->fd, off,
		    (off_t)sqe->addr)));
	case IORING_OP_FADVISE: {
		off_t len = sqe->addr != 0 ? (off_t)sqe->addr : (off_t)sqe->len;

		/* POSIX_FADV_* share values on Linux and FreeBSD. */
		return (sq_result(ctx, td, kern_posix_fadvise(td, sqe->fd, off, len,
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
		while (sq_cancel_one(ctx, sqe->addr)) {
			found = true;
			if (!all)
				break;
		}
		mtx_unlock(&ctx->mtx);
		return (found ? 0 : sq_err(ctx, ENOENT));
	}
	default:
		/* Not a core opcode: let the front-end's issue_ext handle it. */
		return (SQ_NOTHANDLED);
	}
}

/*
 * Resolve a registered (fixed) descriptor: install the held file into a
 * transient fd so the standard kern_* path can operate on it.  Holding the
 * reference in the ctx means the op works even after the application has
 * closed its own descriptor for the file.  Returns 0 and *fdp on success.
 */
static int
sq_fixed_install(struct squeue_ctx *ctx, struct thread *td, int idx,
    int *fdp)
{
	struct filecaps caps;
	struct file *fp;
	int error;

	filecaps_init(&caps);
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
	/*
	 * Re-apply the rights captured at register time so a fixed-file op can
	 * never exceed the original descriptor's capsicum rights.  Copy under
	 * the lock (finstall moves/consumes the caps) so the stored template
	 * stays intact for the next use.
	 */
	(void)filecaps_copy(&ctx->reg_caps[idx], &caps, true);
	mtx_unlock(&ctx->mtx);
	error = finstall(td, fp, fdp, 0, &caps);
	if (error != 0) {
		filecaps_free(&caps);
		fdrop(fp, td);
	}
	return (error);
}

/*
 * Issue wrapper: if IOSQE_FIXED_FILE is set, translate the fixed index into a
 * transient real descriptor, run the op against it, then release it.  This
 * keeps every opcode's dispatch fixed-file agnostic.
 */
static int32_t
sq_dispatch(struct squeue_ctx *ctx, struct sq_req *req, struct thread *td)
{
	int32_t res;

	/* ABI-neutral core first; anything it declines goes to the front-end. */
	res = sq_issue_inline(ctx, req, td);
	if (res == SQ_NOTHANDLED)
		res = ctx->issue_ext != NULL ?
		    ctx->issue_ext(ctx, req, td) : sq_err(ctx, EINVAL);
	return (res);
}

/*
 * Opcodes that reference no descriptor at all (they act on the ring, on
 * user_data, or on the registered tables), so they are always safe in
 * capability mode.  Every other opcode consumes sqe->fd and, on a native ring
 * in capability mode, must name a registered (fixed) file so the operable set
 * is an explicit, rights-limited capability set rather than the ambient table.
 */
static bool
sq_capmode_fdless(uint8_t op)
{

	switch (op) {
	case IORING_OP_NOP:
	case IORING_OP_NOP128:
	case IORING_OP_TIMEOUT:
	case IORING_OP_LINK_TIMEOUT:
	case IORING_OP_TIMEOUT_REMOVE:
	case IORING_OP_ASYNC_CANCEL:
	case IORING_OP_POLL_REMOVE:
	case IORING_OP_PROVIDE_BUFFERS:
	case IORING_OP_REMOVE_BUFFERS:
	case IORING_OP_FILES_UPDATE:
	case IORING_OP_FIXED_FD_INSTALL:
		return (true);
	default:
		return (false);
	}
}

static int32_t
sq_issue_op(struct squeue_ctx *ctx, struct sq_req *req, struct thread *td)
{
	struct sq_req tmp;
	int32_t res;
	int error, tmpfd;

	/*
	 * Capsicum: a native squeue ring in capability mode is a closed
	 * capability set.  Any op that touches a descriptor must use a
	 * registered (fixed) file - whose rights were captured at register
	 * time - never a raw ambient fd number.  Per-descriptor cap_rights are
	 * still enforced downstream by fget/kern_*; this adds the sandbox-set
	 * confinement on top.  Native only: the Linux front-end is untouched.
	 */
	if (!ctx->is_linux && IN_CAPABILITY_MODE(td) &&
	    (req->sqe_flags & IOSQE_FIXED_FILE) == 0 &&
	    !sq_capmode_fdless(req->opcode))
		return (sq_err(ctx, ENOTCAPABLE));

	if ((req->sqe_flags & IOSQE_FIXED_FILE) == 0)
		return (sq_dispatch(ctx, req, td));

	error = sq_fixed_install(ctx, td, req->sqe.fd, &tmpfd);
	if (error != 0)
		return (sq_err(ctx, error));
	tmp = *req;
	tmp.sqe.fd = tmpfd;
	tmp.sqe_flags &= ~IOSQE_FIXED_FILE;
	tmp.cflags = 0;
	res = sq_dispatch(ctx, &tmp, td);
	req->cflags = tmp.cflags;	/* carry back a BUFFER_SELECT id */
	(void)kern_close(td, tmpfd);
	return (res);
}

/* ---- asynchronous opcodes ---- */
static void
sq_timeout_cb(void *arg)
{
	struct sq_req *req = arg;
	struct squeue_ctx *ctx = req->ctx;

	mtx_assert(&ctx->mtx, MA_OWNED);	/* callout_init_mtx */
	if (req->state != SQ_ST_ARMED)
		return;				/* cancelled just ahead of us */
	req->state = SQ_ST_READY;
	req->res = (req->sqe.timeout_flags & IORING_TIMEOUT_ETIME_SUCCESS) != 0 ?
	    0 : sq_etime(ctx) /* Linux ETIME (62) */;
	/*
	 * Post the CQE now, from callout context, so a thread blocked in a
	 * poll-based wait (kern_poll_kfds on the ring fd) sees the ring become
	 * readable.  run_ready then only needs to run any linked successor.
	 */
	sq_post_cqe(ctx, req->user_data, req->res, 0);
	req->posted = true;
	TAILQ_REMOVE(&ctx->pending, req, entry);
	ctx->npending--;
	TAILQ_INSERT_TAIL(&ctx->ready, req, entry);
	sq_wake(ctx);
}

static void
sq_check_count_timeouts(struct squeue_ctx *ctx)
{
	struct sq_req *req, *tmp;

	mtx_assert(&ctx->mtx, MA_OWNED);
	TAILQ_FOREACH_SAFE(req, &ctx->pending, entry, tmp) {
		if (!req->tmo_count || req->state != SQ_ST_ARMED)
			continue;
		if (ctx->cq_count < req->tmo_target)
			continue;
		/* Requested number of completions reached before the timer. */
		callout_stop(&req->co);
		req->state = SQ_ST_READY;
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
sq_arm_async(struct squeue_ctx *ctx, struct sq_req *req, struct thread *td)
{
	const struct io_uring_sqe *sqe = &req->sqe;
	struct __kernel_timespec kts;
	struct timespec ts, now;
	struct timeval tv;
	uint32_t flags;
	int error, ticks;

	if (sqe->opcode == IORING_OP_POLL_ADD) {
		/*
		 * Arm a poll: register a readiness knote on the ring's kqueue
		 * and record the request on ctx->polls; sq_poll_scan resolves it
		 * when the knote fires.  IORING_POLL_ADD_MULTI keeps the poll
		 * armed and posts an F_MORE CQE per readiness (multishot).  The
		 * poll-update variants are not supported.
		 */
		if ((sqe->len & (IORING_POLL_UPDATE_EVENTS |
		    IORING_POLL_UPDATE_USER_DATA)) != 0)
			return (-EINVAL);
		req->multishot = (sqe->len & IORING_POLL_ADD_MULTI) != 0;
		error = sq_kq_arm(ctx, req, td);	/* outside mtx: may sleep */
		if (error != 0)
			return (sq_err(ctx, error));
		mtx_lock(&ctx->mtx);
		req->state = SQ_ST_ARMED;
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
		return (sq_err(ctx, error));
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
	req->state = SQ_ST_ARMED;
	if (sqe->off != 0) {
		req->tmo_count = true;
		req->tmo_target = ctx->cq_count + (uint32_t)sqe->off;
	}
	TAILQ_INSERT_TAIL(&ctx->pending, req, entry);
	ctx->npending++;
	callout_reset(&req->co, ticks, sq_timeout_cb, req);
	/* A count target already satisfied fires on the next completion. */
	sq_check_count_timeouts(ctx);
	mtx_unlock(&ctx->mtx);
	return (0);
}

/*
 * ---- asynchronous worker pool ----
 *
 * Blocking file I/O (a READ/WRITE on a regular file backed by slow storage)
 * would otherwise stall the submitting thread and hold up every other request
 * on the ring.  When IOSQE_ASYNC is set we hand such an op to a pool of
 * dedicated kernel processes: each worker borrows the ring owner's address
 * space (vmspace_switch_aio, exactly as the aio(4) daemons do) so the user
 * buffers resolve, performs the transfer through the held struct file *, then
 * resolves the request onto ctx->ready just like any other async op - the
 * owner thread posts the CQE and runs the chain's successors with its own file
 * table.  This is the same mechanism SQPOLL will reuse to issue work off-thread.
 */
#define	SQ_MAX_WORKERS	8

static struct mtx	sq_wq_mtx;
static struct cv	sq_wq_cv;
static TAILQ_HEAD(, sq_req) sq_workq;
static int		sq_nworkers;	/* worker procs created */
static int		sq_nidle;	/* workers blocked on sq_wq_cv */

static void
sq_wq_init(void *dummy __unused)
{

	mtx_init(&sq_wq_mtx, "squeue workq", NULL, MTX_DEF);
	cv_init(&sq_wq_cv, "squeue worker");
	TAILQ_INIT(&sq_workq);
}
SYSINIT(squeue_wq, SI_SUB_KTHREAD_INIT, SI_ORDER_ANY, sq_wq_init, NULL);

static void
squeue_worker(void *arg __unused)
{
	struct proc *p = curproc;
	struct thread *td = curthread;
	struct vmspace *myvm;
	struct sq_req *req;
	struct squeue_ctx *ctx;
	ssize_t before, cnt;
	int32_t res;
	int error, flags;

	/* Keep a reference to our own vmspace to restore between jobs. */
	myvm = vmspace_acquire_ref(p);

	mtx_lock(&sq_wq_mtx);
	for (;;) {
		while ((req = TAILQ_FIRST(&sq_workq)) == NULL) {
			sq_nidle++;
			cv_wait(&sq_wq_cv, &sq_wq_mtx);
			sq_nidle--;
		}
		TAILQ_REMOVE(&sq_workq, req, wq);
		mtx_unlock(&sq_wq_mtx);

		ctx = req->ctx;
		flags = req->ocur ? 0 : FOF_OFFSET;

		/* Borrow the owner's address space for the user-buffer copy. */
		vmspace_switch_aio(req->ovm);
		req->ouio->uio_td = td;
		before = req->ouio->uio_resid;
		if (req->owrite)
			error = fo_write(req->ofp, req->ouio, req->ofp->f_cred,
			    flags, td);
		else
			error = fo_read(req->ofp, req->ouio, req->ofp->f_cred,
			    flags, td);
		cnt = before - req->ouio->uio_resid;
		/* Partial transfer reports the byte count; a hard error its errno. */
		if (cnt > 0 || error == 0)
			res = (int32_t)cnt;
		else
			res = sq_err(ctx, error);

		/* Restore our own address space before releasing the borrowed one. */
		if (p->p_vmspace != myvm)
			vmspace_switch_aio(myvm);
		vmspace_free(req->ovm);
		req->ovm = NULL;
		fdrop(req->ofp, td);
		req->ofp = NULL;
		free(req->ouio, M_IOV);
		req->ouio = NULL;

		/* Resolve like any async op: pending -> ready, wake a waiter. */
		mtx_lock(&ctx->mtx);
		req->res = res;
		req->state = SQ_ST_READY;
		TAILQ_REMOVE(&ctx->pending, req, entry);
		ctx->npending--;
		TAILQ_INSERT_TAIL(&ctx->ready, req, entry);
		sq_wake(ctx);
		mtx_unlock(&ctx->mtx);
		/*
		 * Release our ctx reference.  If the ring was closed while the
		 * transfer ran this drops the last reference and tears the engine
		 * down (including the req we just readied); touch neither again.
		 */
		sq_ctx_rele(ctx);

		mtx_lock(&sq_wq_mtx);
	}
}

/* Opcodes whose blocking file transfer the worker pool can run off-thread. */
static bool
sq_offload_op(uint8_t op)
{

	switch (op) {
	case IORING_OP_READ:
	case IORING_OP_WRITE:
	case IORING_OP_READV:
	case IORING_OP_WRITEV:
	case IORING_OP_READ_FIXED:
	case IORING_OP_WRITE_FIXED:
	case IORING_OP_READV_FIXED:
	case IORING_OP_WRITEV_FIXED:
		return (true);
	default:
		return (false);
	}
}

/*
 * Offload is offered only when the application explicitly asked for async
 * execution (IOSQE_ASYNC) on an offloadable data-transfer op.  Provided-buffer
 * selection is handled inline (the worker path does not run that preamble), so
 * a BUFFER_SELECT request falls through to the normal issue path.
 */
static bool
sq_offload_eligible(struct sq_req *req)
{

	/*
	 * Fixed-file ops are excluded: sqe->fd is a registered index, not a
	 * real descriptor, so the worker's fget() would be wrong.  They fall
	 * through to sq_issue_op, which resolves the index to a transient fd
	 * and runs inline.  BUFFER_SELECT is handled inline for the same
	 * reason (the worker path does not run that preamble).
	 */
	return ((req->sqe_flags & IOSQE_ASYNC) != 0 && !req->retry &&
	    (req->sqe_flags & (IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE)) == 0 &&
	    sq_offload_op(req->opcode));
}

/*
 * Prepare and enqueue an offloaded request.  Returns 0 when the request has
 * been handed to the pool (it now owns itself and will resolve onto
 * ctx->ready), or a negative ABI errno if it could not be started (the caller
 * completes it inline).
 */
static int32_t
sq_offload_submit(struct squeue_ctx *ctx, struct sq_req *req,
    struct thread *td)
{
	const struct io_uring_sqe *sqe = &req->sqe;
	cap_rights_t rights;
	struct file *fp;
	struct uio *uiop;
	struct iovec *iov;
	off_t off;
	bool wr, vec, fixed, cur, spawn, have_bufs;
	int error;

	wr = req->opcode == IORING_OP_WRITE ||
	    req->opcode == IORING_OP_WRITEV ||
	    req->opcode == IORING_OP_WRITE_FIXED ||
	    req->opcode == IORING_OP_WRITEV_FIXED;
	vec = req->opcode == IORING_OP_READV ||
	    req->opcode == IORING_OP_WRITEV ||
	    req->opcode == IORING_OP_READV_FIXED ||
	    req->opcode == IORING_OP_WRITEV_FIXED;
	fixed = req->opcode == IORING_OP_READ_FIXED ||
	    req->opcode == IORING_OP_WRITE_FIXED ||
	    req->opcode == IORING_OP_READV_FIXED ||
	    req->opcode == IORING_OP_WRITEV_FIXED;
	off = (off_t)sqe->off;
	cur = (sqe->off == (uint64_t)-1);

	/*
	 * A positioned transfer with a negative offset would reach the fs
	 * (fo_read/fo_write with FOF_OFFSET) and panic (e.g. ffs_read: uio
	 * offset < 0).  The inline path is protected by kern_pread/pwrite's
	 * check; the worker path calls fo_* directly, so validate here.
	 */
	if (!cur && off < 0)
		return (-EINVAL);

	/* Fixed (registered-buffer) variants require registered buffers. */
	if (fixed) {
		if (req->opcode == IORING_OP_READ_FIXED ||
		    req->opcode == IORING_OP_WRITE_FIXED) {
			int32_t r = sq_check_fixed_buf(ctx, sqe->buf_index,
			    sqe->addr, sqe->len);

			if (r != 0)
				return (r);
		} else {
			mtx_lock(&ctx->mtx);
			have_bufs = ctx->reg_bufs != NULL;
			mtx_unlock(&ctx->mtx);
			if (!have_bufs)
				return (-EINVAL);
		}
	}

	/* Grab a private reference to the target file in the owner's table. */
	if (wr)
		error = fget_write(td, sqe->fd,
		    cap_rights_init(&rights, CAP_WRITE, CAP_PWRITE), &fp);
	else
		error = fget_read(td, sqe->fd,
		    cap_rights_init(&rights, CAP_READ, CAP_PREAD), &fp);
	if (error != 0)
		return (sq_err(ctx, error));

	/* Build the user-space uio now, in the owner's address space. */
	if (vec) {
		error = copyinuio((void *)(uintptr_t)sqe->addr, sqe->len, &uiop);
		if (error != 0) {
			fdrop(fp, td);
			return (sq_err(ctx, error));
		}
	} else {
		uiop = malloc(sizeof(*uiop) + sizeof(*iov), M_IOV, M_WAITOK);
		iov = (struct iovec *)(uiop + 1);
		iov->iov_base = (void *)(uintptr_t)sqe->addr;
		iov->iov_len = sqe->len;
		uiop->uio_iov = iov;
		uiop->uio_iovcnt = 1;
		uiop->uio_resid = sqe->len;
		uiop->uio_segflg = UIO_USERSPACE;
	}
	uiop->uio_offset = cur ? 0 : off;
	uiop->uio_rw = wr ? UIO_WRITE : UIO_READ;

	/*
	 * Decide whether we must grow the pool.  A worker is needed up front if
	 * none exists yet or all are busy; create it before queuing so a spawn
	 * failure never leaves the request with no thread to drain it.
	 */
	mtx_lock(&sq_wq_mtx);
	spawn = (sq_nidle == 0 && sq_nworkers < SQ_MAX_WORKERS);
	if (spawn)
		sq_nworkers++;
	mtx_unlock(&sq_wq_mtx);

	if (spawn) {
		struct proc *wp;

		if (kproc_create(squeue_worker, NULL, &wp, 0, 0, "squeue") != 0) {
			mtx_lock(&sq_wq_mtx);
			sq_nworkers--;
			spawn = (sq_nworkers > 0);	/* fall back to an existing worker */
			mtx_unlock(&sq_wq_mtx);
			if (!spawn) {
				/* No worker at all: run this op inline instead. */
				fdrop(fp, td);
				free(uiop, M_IOV);
				return (SQ_NOTHANDLED);
			}
		}
	}

	req->ofp = fp;
	req->ouio = uiop;
	req->owrite = wr;
	req->ocur = cur;
	req->ovm = vmspace_acquire_ref(td->td_proc);

	mtx_lock(&ctx->mtx);
	ctx->refs++;			/* keep ctx alive until the worker resolves */
	req->state = SQ_ST_ARMED;
	TAILQ_INSERT_TAIL(&ctx->pending, req, entry);
	ctx->npending++;
	mtx_unlock(&ctx->mtx);

	mtx_lock(&sq_wq_mtx);
	TAILQ_INSERT_TAIL(&sq_workq, req, wq);
	cv_signal(&sq_wq_cv);
	mtx_unlock(&sq_wq_mtx);
	return (0);
}

/* ---- chain execution ---- */
static void sq_run_chain(struct squeue_ctx *ctx, struct sq_req *req,
    struct thread *td);

/* Complete an entire (remaining) chain as cancelled. */
static void
sq_cancel_chain(struct squeue_ctx *ctx, struct sq_req *req)
{
	struct sq_req *next;

	while (req != NULL) {
		next = req->link_next;
		mtx_lock(&ctx->mtx);
		sq_complete(ctx, req, sq_err(ctx, ECANCELED), 0);
		mtx_unlock(&ctx->mtx);
		sq_req_free(req);
		req = next;
	}
}

/*
 * Run a link chain as far as it can go synchronously.  Inline ops complete
 * immediately; on reaching an async op the chain is suspended (its remaining
 * successors hang off req->link_next and run from sq_run_ready once the async
 * op resolves).  A soft-linked failure cancels the remaining successors.
 */
static void
sq_run_chain(struct squeue_ctx *ctx, struct sq_req *req, struct thread *td)
{
	struct sq_req *next;
	int32_t res;
	bool fail, softlink;
	/*
	 * In capability mode a native ring must not offload a raw-fd op to the
	 * worker pool (that would fget the ambient fd, bypassing the fixed-file
	 * confinement enforced in sq_issue_op).  When confined, such ops fall
	 * through to sq_issue_op, which rejects them with ENOTCAPABLE.
	 */
	bool confined = !ctx->is_linux && IN_CAPABILITY_MODE(td);

	while (req != NULL) {
		if (sq_op_async(req->opcode)) {
			res = sq_arm_async(ctx, req, td);
			if (res == 0)
				return;		/* suspended; owns itself */
			/* arm failed: complete inline and fall through */
			next = req->link_next;
			mtx_lock(&ctx->mtx);
			sq_complete(ctx, req, res, 0);
			mtx_unlock(&ctx->mtx);
			softlink = (req->sqe_flags & IOSQE_IO_LINK) != 0;
			sq_req_free(req);
			if (res < 0 && softlink) {
				sq_cancel_chain(ctx, next);
				return;
			}
			req = next;
			continue;
		}

		/*
		 * IOSQE_ASYNC file I/O: hand the op to the worker pool so a slow
		 * transfer does not stall the submitter.  On success the chain is
		 * suspended (successors run from sq_run_ready when it resolves);
		 * SQ_NOTHANDLED means the pool declined and we issue inline.
		 */
		if (!confined && sq_offload_eligible(req)) {
			res = sq_offload_submit(ctx, req, td);
			if (res == 0)
				return;			/* suspended; owns itself */
			if (res != SQ_NOTHANDLED) {
				next = req->link_next;
				mtx_lock(&ctx->mtx);
				sq_complete(ctx, req, res, 0);
				mtx_unlock(&ctx->mtx);
				softlink = (req->sqe_flags & IOSQE_IO_LINK) != 0;
				sq_req_free(req);
				if (res < 0 && softlink) {
					sq_cancel_chain(ctx, next);
					return;
				}
				req = next;
				continue;
			}
			/* SQ_NOTHANDLED: fall through to inline issue. */
		}

		res = sq_issue_op(ctx, req, td);
		/*
		 * Fast poll: a would-block op is parked on a readiness poll and
		 * re-issued from sq_poll_scan when the fd is ready, rather than
		 * blocking the submitter or completing with EAGAIN.  The chain is
		 * suspended; its successors run once the retry completes.
		 */
		if (res == sq_err(ctx, EAGAIN)) {
			short ev = sq_pollable_events(req->opcode);

			/*
			 * Fixed-file ops carry a registered index in sqe.fd, not a
			 * real descriptor (the transient fd was already closed), so
			 * they cannot be readiness-armed here - complete EAGAIN and
			 * let the application retry.
			 */
			if ((req->sqe_flags & IOSQE_FIXED_FILE) != 0)
				ev = 0;
			if (ev != 0) {
				req->sqe.poll32_events = ev;
				/* Arm the readiness knote outside the lock. */
				if (sq_kq_arm(ctx, req, td) == 0) {
					mtx_lock(&ctx->mtx);
					req->retry = true;
					req->state = SQ_ST_ARMED;
					TAILQ_INSERT_TAIL(&ctx->polls, req, entry);
					ctx->npolls++;
					mtx_unlock(&ctx->mtx);
					return;
				}
				/* arm failed: fall through and complete EAGAIN */
			}
		}
		next = req->link_next;
		fail = res < 0;
		softlink = (req->sqe_flags & IOSQE_IO_LINK) != 0;
		mtx_lock(&ctx->mtx);
		sq_complete(ctx, req, res, req->cflags);
		mtx_unlock(&ctx->mtx);
		sq_req_free(req);
		if (fail && softlink) {
			sq_cancel_chain(ctx, next);
			return;
		}
		req = next;
	}
}

static void sq_kick_drain(struct squeue_ctx *ctx, struct thread *td);

/*
 * Post CQEs for resolved async requests and run any suspended successors, all
 * in the calling thread's context (correct fd table, may block).  Called from
 * io_uring_enter at entry and after every wakeup in the wait loop.
 */
static void
sq_run_ready(struct squeue_ctx *ctx, struct thread *td)
{
	struct sq_req *req, *cont;
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
		sq_complete(ctx, req, res, req->cflags);
		mtx_unlock(&ctx->mtx);
		/*
		 * A cancelled request (or a soft-linked failure) cancels its
		 * successors; a timeout that expired with ETIME is a failure for
		 * link purposes when soft-linked.
		 */
		cancelled = res == sq_err(ctx, ECANCELED) ||
		    (res < 0 && (req->sqe_flags & IOSQE_IO_LINK) != 0);
		sq_req_free(req);
		if (cont != NULL) {
			if (cancelled)
				sq_cancel_chain(ctx, cont);
			else
				sq_run_chain(ctx, cont, td);
		}
		sq_kick_drain(ctx, td);
	}
}

/*
 * Release barrier-held chains once no async request is outstanding.  Each
 * released chain runs to its first async op (which re-raises npending and
 * stops the release), preserving submission order across the barrier.
 */
static void
sq_kick_drain(struct squeue_ctx *ctx, struct thread *td)
{
	struct sq_req *head;

	for (;;) {
		mtx_lock(&ctx->mtx);
		if (ctx->npending > 0 || TAILQ_EMPTY(&ctx->drain)) {
			mtx_unlock(&ctx->mtx);
			return;
		}
		head = TAILQ_FIRST(&ctx->drain);
		TAILQ_REMOVE(&ctx->drain, head, entry);
		mtx_unlock(&ctx->mtx);
		sq_run_chain(ctx, head, td);
	}
}

/*
 * Dispatch one built link chain: either run it now, or, if a drain barrier is
 * in effect, hold it until the barrier lifts (preserving order).
 */
static void
sq_dispatch_chain(struct squeue_ctx *ctx, struct sq_req *head,
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
	sq_run_chain(ctx, head, td);
}

/* ---- submission ---- */
static int
sq_submit(struct squeue_ctx *ctx, uint32_t to_submit, struct thread *td)
{
	struct sq_req *req, *ch_head, *ch_prev;
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

		req = malloc(sizeof(*req), M_SQUEUE, M_WAITOK | M_ZERO);
		req->ctx = ctx;
		req->sqe = sqe;
		req->opcode = sqe.opcode;
		req->sqe_flags = sqe.flags;
		req->user_data = sqe.user_data;
		req->state = SQ_ST_NEW;
		callout_init_mtx(&req->co, &ctx->mtx, 0);

		if (ch_head == NULL)
			ch_head = req;
		else
			ch_prev->link_next = req;
		ch_prev = req;

		/* A chain ends at the first SQE without a link flag. */
		if ((sqe.flags & (IOSQE_IO_LINK | IOSQE_IO_HARDLINK)) == 0) {
			sq_dispatch_chain(ctx, ch_head, td);
			ch_head = ch_prev = NULL;
		}
	}
	/* A dangling link at the end of the batch is dispatched on its own. */
	if (ch_head != NULL)
		sq_dispatch_chain(ctx, ch_head, td);

	return (submitted);
}

/* Map BSD poll revents to the Linux poll/epoll bits an app expects. */
static int32_t
sq_poll_res(struct squeue_ctx *ctx, short revents)
{

	if ((revents & POLLNVAL) != 0)
		return (sq_err(ctx, EBADF));
	/* POLLIN/PRI/OUT/ERR/HUP share values between BSD and Linux. */
	return ((int32_t)(revents &
	    (POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLRDNORM |
	    POLLWRNORM | POLLRDBAND | POLLWRBAND)));
}

/*
 * ---- kqueue-based readiness ----
 *
 * Armed POLL_ADD targets and fast-poll retry fds are registered as EVFILT_READ
 * / EVFILT_WRITE knotes (EV_ONESHOT, so a fired knote deletes itself) on the
 * ring's private kqueue; the ring fd itself is registered level-triggered so a
 * completion also breaks the wait.  One kern_kevent_fp() call then blocks on
 * completions and every target at once and reports only the ready ones - O(ready)
 * rather than the O(nfds) rescan a poll(2) does.  A knote's udata is the owning
 * request; because a fired ONESHOT knote is gone and a request removed before it
 * fires is EV_DELETEd (sq_kq_unarm), a stale udata is never dereferenced - the
 * scan matches it against ctx->polls by identity and skips a miss.  All kevent
 * calls run without ctx->mtx (they may sleep).
 */
struct sq_kev_io {
	struct kevent	*changes;
	struct kevent	*events;
};
static int
sq_kev_copyin(void *arg, struct kevent *kevp, int count)
{
	struct sq_kev_io *io = arg;

	bcopy(io->changes, kevp, count * sizeof(*kevp));
	io->changes += count;
	return (0);
}
static int
sq_kev_copyout(void *arg, struct kevent *kevp, int count)
{
	struct sq_kev_io *io = arg;

	bcopy(kevp, io->events, count * sizeof(*kevp));
	io->events += count;
	return (0);
}
static int
sq_kevent(struct squeue_ctx *ctx, struct thread *td, struct kevent *changes,
    int nchanges, struct kevent *events, int nevents,
    const struct timespec *ts)
{
	struct sq_kev_io io = { .changes = changes, .events = events };
	struct kevent_copyops kops = {
		.arg = &io,
		.k_copyin = sq_kev_copyin,
		.k_copyout = sq_kev_copyout,
		.kevent_size = sizeof(struct kevent),
	};

	return (kern_kevent_fp(td, ctx->kqfp, nchanges, nevents, &kops, ts));
}

/* Lazily create the per-ring kqueue, held as a file * with its fd closed. */
static int
sq_kq_ensure(struct squeue_ctx *ctx, struct thread *td)
{
	struct file *fp;
	int error, fd;

	if (ctx->kqfp != NULL)
		return (0);
	error = kern_kqueue(td, 0, false, NULL);
	if (error != 0)
		return (error);
	fd = td->td_retval[0];
	td->td_retval[0] = 0;
	error = fget(td, fd, &cap_no_rights, &fp);
	(void)kern_close(td, fd);
	if (error != 0)
		return (error);
	ctx->kqfp = fp;
	return (0);
}

/* The readiness filter a poll request is waiting on. */
static short
sq_kq_filter(const struct sq_req *req)
{

	if ((req->sqe.poll32_events & (POLLOUT | POLLWRNORM | POLLWRBAND)) != 0 &&
	    (req->sqe.poll32_events & (POLLIN | POLLPRI | POLLRDNORM)) == 0)
		return (EVFILT_WRITE);
	return (EVFILT_READ);
}

/* Register a poll target's one-shot readiness knote (udata = request). */
static int
sq_kq_arm(struct squeue_ctx *ctx, struct sq_req *req, struct thread *td)
{
	struct kevent kev;
	int error;

	error = sq_kq_ensure(ctx, td);
	if (error != 0)
		return (error);
	/*
	 * Single-shot polls and fast-poll retries use EV_ONESHOT (a fired knote
	 * deletes itself).  A multishot poll stays armed, so it uses EV_CLEAR
	 * (edge-triggered): it fires once per readiness transition and must be
	 * explicitly removed (sq_kq_del) when the poll ends.
	 */
	EV_SET(&kev, req->sqe.fd, sq_kq_filter(req),
	    EV_ADD | (req->multishot ? EV_CLEAR : EV_ONESHOT), 0, 0, req);
	return (sq_kevent(ctx, td, &kev, 1, NULL, 0, NULL));
}

/*
 * Delete a knote by (fd, filter).  Used to tear down a multishot poll's
 * persistent EV_CLEAR knote when the poll ends (POLL_REMOVE or EV_EOF).  Takes
 * values, not the request, so it never touches memory that may have been freed.
 */
static void
sq_kq_del(struct squeue_ctx *ctx, int fd, short filter, struct thread *td)
{
	struct kevent kev;

	if (ctx->kqfp == NULL)
		return;
	EV_SET(&kev, fd, filter, EV_DELETE, 0, 0, NULL);
	(void)sq_kevent(ctx, td, &kev, 1, NULL, 0, NULL);	/* ENOENT is fine */
}

/*
 * No explicit unarm for single-shot: knotes are EV_ONESHOT, so a fired one is
 * already gone,
 * and a request cancelled before firing (POLL_REMOVE) leaves a knote that
 * self-deletes the next time its fd is ready.  sq_poll_scan matches a fired
 * knote to its request by both udata identity AND ident==fd, so a request
 * pointer reused after free can never be resolved against the wrong fd.  Any
 * knote still registered at teardown is drained by fdrop(kqfp).
 */

/*
 * Block until a completion is posted or an armed target becomes ready, then
 * resolve the ready targets.  A fired one-shot knote has already left the
 * kqueue; the ring's level-triggered knote (udata == NULL) simply breaks the
 * wait.  Runs in the squeue_enter thread, so target fds resolve against its
 * table.  Replaces the former kern_poll_kfds rescan.
 */
static int
sq_poll_scan(struct squeue_ctx *ctx, int ringfd, struct thread *td)
{
	struct kevent *evs;
	struct sq_reqq torun;
	struct sq_req *rq, *r, *found;
	struct { int fd; short filt; } *dels;
	int error, n, maxev, i, ndel;

	error = sq_kq_ensure(ctx, td);
	if (error != 0)
		return (error);
	/* Arm the ring's own knote once so a completion breaks the wait. */
	if (!ctx->kq_ring_armed) {
		struct kevent rk;

		EV_SET(&rk, ringfd, EVFILT_READ, EV_ADD, 0, 0, NULL);
		error = sq_kevent(ctx, td, &rk, 1, NULL, 0, NULL);
		if (error != 0)
			return (error);
		ctx->kq_ring_armed = true;
	}

	mtx_lock(&ctx->mtx);
	maxev = ctx->npolls + 1;		/* targets + ring */
	mtx_unlock(&ctx->mtx);
	evs = malloc(maxev * sizeof(*evs), M_SQUEUE, M_WAITOK | M_ZERO);
	/* (fd,filter) of multishot polls that ended this scan, to EV_DELETE. */
	dels = malloc(maxev * sizeof(*dels), M_SQUEUE, M_WAITOK | M_ZERO);
	ndel = 0;

	error = sq_kevent(ctx, td, NULL, 0, evs, maxev, NULL);	/* blocks */
	if (error != 0) {
		free(evs, M_SQUEUE);
		free(dels, M_SQUEUE);
		return (error);
	}
	n = td->td_retval[0];

	TAILQ_INIT(&torun);
	mtx_lock(&ctx->mtx);
	for (i = 0; i < n; i++) {
		short rev;

		if (evs[i].udata == NULL)
			continue;		/* the ring: completion readiness */
		/*
		 * Confirm the request is still armed (not cancelled meanwhile)
		 * and that the fired fd is really this request's target - guards
		 * against a request pointer reused after free landing on a
		 * different fd.
		 */
		found = NULL;
		TAILQ_FOREACH(r, &ctx->polls, entry) {
			if (r == (struct sq_req *)evs[i].udata) {
				found = r;
				break;
			}
		}
		if (found == NULL || found->state != SQ_ST_ARMED ||
		    (int)evs[i].ident != found->sqe.fd)
			continue;

		rev = (short)found->sqe.poll32_events;
		if ((evs[i].flags & EV_EOF) != 0)
			rev |= POLLHUP;

		/*
		 * Multishot poll that is still live (no EOF): post an F_MORE CQE
		 * with the ready mask and leave it armed - its EV_CLEAR knote
		 * fires again on the next readiness transition.
		 */
		if (found->multishot && (evs[i].flags & EV_EOF) == 0) {
			sq_post_cqe(ctx, found->user_data, sq_poll_res(ctx, rev),
			    IORING_CQE_F_MORE);
			sq_wake(ctx);
			continue;
		}

		/* Terminal: single-shot fire, fast-poll retry, or multishot EOF. */
		TAILQ_REMOVE(&ctx->polls, found, entry);
		ctx->npolls--;
		if (found->multishot) {
			/* remove the persistent knote after dropping the lock */
			dels[ndel].fd = found->sqe.fd;
			dels[ndel].filt = evs[i].filter;
			ndel++;
		}
		if (found->retry) {
			/* fast-poll: re-issue the op now that the fd is ready */
			found->retry = false;
			found->state = SQ_ST_NEW;
			TAILQ_INSERT_TAIL(&torun, found, entry);
		} else {
			found->state = SQ_ST_READY;
			found->res = sq_poll_res(ctx, rev);
			TAILQ_INSERT_TAIL(&ctx->ready, found, entry);
		}
	}
	mtx_unlock(&ctx->mtx);
	free(evs, M_SQUEUE);

	/* Tear down ended multishot knotes (outside the lock: kevent sleeps). */
	for (i = 0; i < ndel; i++)
		sq_kq_del(ctx, dels[i].fd, dels[i].filt, td);
	free(dels, M_SQUEUE);

	/* Re-run parked ops (and their chains) outside the lock. */
	while ((rq = TAILQ_FIRST(&torun)) != NULL) {
		TAILQ_REMOVE(&torun, rq, entry);
		sq_run_chain(ctx, rq, td);
	}
	return (0);
}

static int
sq_wait_cq(struct squeue_ctx *ctx, uint32_t min_complete, int ringfd,
    struct thread *td)
{
	int error, np;

	error = 0;
	for (;;) {
		sq_run_ready(ctx, td);
		mtx_lock(&ctx->mtx);
		/* The app may have drained the CQ; pull in any backlog now. */
		sq_cq_flush(ctx);
		if (sq_cq_ready(ctx) >= min_complete) {
			mtx_unlock(&ctx->mtx);
			break;
		}
		np = ctx->npolls;
		if (np > 0) {
			mtx_unlock(&ctx->mtx);
			/* Wait on the ring fd + poll targets together. */
			error = sq_poll_scan(ctx, ringfd, td);
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
sq_fo_mmap(struct file *fp, vm_map_t map, vm_offset_t *addr, vm_size_t size,
    vm_prot_t prot, vm_prot_t maxprot, int flags, vm_ooffset_t foff,
    struct thread *td)
{
	struct squeue_ctx *ctx = fp->f_data;
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
sq_fo_poll(struct file *fp, int events, struct ucred *cred, struct thread *td)
{
	struct squeue_ctx *ctx = fp->f_data;
	int revents = 0;

	mtx_lock(&ctx->mtx);
	if ((events & (POLLIN | POLLRDNORM)) != 0 && sq_cq_ready(ctx) > 0)
		revents |= events & (POLLIN | POLLRDNORM);
	if (revents == 0 && (events & (POLLIN | POLLRDNORM)) != 0)
		selrecord(td, &ctx->sel);
	mtx_unlock(&ctx->mtx);
	return (revents);
}

/*
 * kqueue support: a squeue ring is a first-class event source.  Registering it
 * with EVFILT_READ reports the ring readable (kn_data = number of pending
 * CQEs) whenever completions are available, so a ring can be multiplexed in a
 * kevent loop alongside sockets, timers and other descriptors.  Completions
 * fire the note through the KNOTE_LOCKED in sq_wake().  This is additive - it
 * only replaces the invfo_kqfilter stub - so both front-ends keep identical
 * submit/complete behaviour; the shared engine is unchanged.
 */
static void
sq_kq_detach(struct knote *kn)
{
	struct squeue_ctx *ctx = kn->kn_hook;

	knlist_remove(&ctx->sel.si_note, kn, 0);
}

static int
sq_kq_event(struct knote *kn, long hint __unused)
{
	struct squeue_ctx *ctx = kn->kn_hook;

	mtx_assert(&ctx->mtx, MA_OWNED);	/* si_note is locked by ctx->mtx */
	kn->kn_data = sq_cq_ready(ctx);
	return (kn->kn_data > 0);
}

static const struct filterops sq_filtops = {
	.f_isfd = 1,
	.f_detach = sq_kq_detach,
	.f_event = sq_kq_event,
};

static int
sq_fo_kqfilter(struct file *fp, struct knote *kn)
{
	struct squeue_ctx *ctx = fp->f_data;

	/* Readiness == "a completion is available", so only EVFILT_READ. */
	if (kn->kn_filter != EVFILT_READ)
		return (EINVAL);
	kn->kn_fop = &sq_filtops;
	kn->kn_hook = ctx;
	knlist_add(&ctx->sel.si_note, kn, 0);
	return (0);
}

/*
 * Drop a reference to the context.  The ring file holds one; each in-flight
 * worker-pool job holds one more, so the engine memory outlives an offloaded
 * request even if the application closes the ring while the transfer runs.
 */
static void
sq_ctx_rele(struct squeue_ctx *ctx)
{
	bool last;

	mtx_lock(&ctx->mtx);
	last = (--ctx->refs == 0);
	mtx_unlock(&ctx->mtx);
	if (last)
		sq_ctx_free(ctx);
}

static int
sq_fo_close(struct file *fp, struct thread *td)
{
	struct squeue_ctx *ctx = fp->f_data;

	fp->f_data = NULL;
	if (ctx != NULL)
		sq_ctx_rele(ctx);
	return (0);
}

static int
sq_fo_stat(struct file *fp, struct stat *sb, struct ucred *cred)
{

	bzero(sb, sizeof(*sb));
	sb->st_mode = S_IFIFO;
	return (0);
}

static int
sq_fo_fill_kinfo(struct file *fp, struct kinfo_file *kif, struct filedesc *fdp)
{

	kif->kf_type = KF_TYPE_UNKNOWN;
	return (0);
}

static const struct fileops squeue_fileops = {
	.fo_read = invfo_rdwr,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = invfo_ioctl,
	.fo_poll = sq_fo_poll,
	.fo_kqfilter = sq_fo_kqfilter,
	.fo_stat = sq_fo_stat,
	.fo_close = sq_fo_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_mmap = sq_fo_mmap,
	.fo_fill_kinfo = sq_fo_fill_kinfo,
	.fo_cmp = file_kcmp_generic,
	.fo_flags = DFLAG_PASSABLE,
};

/* ---- KPI: setup / enter / register (declared in sys/squeue.h) ---- */
int
kern_squeue_setup(struct thread *td, uint32_t entries,
    struct io_uring_params *p, const struct sq_frontend *fe, int *fdp)
{
	struct squeue_ctx *ctx;
	struct file *fp;
	int error, fd;

	if (entries == 0 || entries > SQ_MAX_ENTRIES)
		return (EINVAL);
	/* Only the plain ring; reject setup flags we do not honor. */
	if (p->flags != 0)
		return (EINVAL);
	if (p->resv[0] != 0 || p->resv[1] != 0 || p->resv[2] != 0)
		return (EINVAL);

	ctx = malloc(sizeof(*ctx), M_SQUEUE, M_WAITOK | M_ZERO);
	ctx->refs = 1;			/* the ring file's reference */
	mtx_init(&ctx->mtx, "iouring", NULL, MTX_DEF);
	knlist_init_mtx(&ctx->sel.si_note, &ctx->mtx);
	TAILQ_INIT(&ctx->pending);
	TAILQ_INIT(&ctx->ready);
	TAILQ_INIT(&ctx->drain);
	TAILQ_INIT(&ctx->pbufs);
	TAILQ_INIT(&ctx->polls);
	TAILQ_INIT(&ctx->overflow);
	ctx->sq_entries = 1U << flsl(entries - 1);	/* round up to pow2 */
	if (ctx->sq_entries < entries)
		ctx->sq_entries <<= 1;
	if (ctx->sq_entries < 1)
		ctx->sq_entries = 1;
	ctx->cq_entries = ctx->sq_entries * 2;
	ctx->setup_flags = p->flags;
	ctx->is_linux = fe->is_linux;
	ctx->issue_ext = fe->issue_ext;
	ctx->err_xlate = fe->err_xlate;

	error = sq_ring_alloc(ctx);
	if (error != 0) {
		knlist_destroy(&ctx->sel.si_note);
		mtx_destroy(&ctx->mtx);
		free(ctx, M_SQUEUE);
		return (error);
	}

	error = falloc(td, &fp, &fd, 0);
	if (error != 0) {
		sq_ctx_free(ctx);
		return (error);
	}
	finit(fp, FREAD | FWRITE, DTYPE_IORING, ctx, &squeue_fileops);

	p->sq_entries = ctx->sq_entries;
	p->cq_entries = ctx->cq_entries;
	p->features = IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP |
	    IORING_FEAT_SUBMIT_STABLE | IORING_FEAT_RW_CUR_POS |
	    IORING_FEAT_CUR_PERSONALITY | IORING_FEAT_FAST_POLL |
	    IORING_FEAT_POLL_32BITS;
	p->sq_off.head = offsetof(struct sq_rings, sq_head);
	p->sq_off.tail = offsetof(struct sq_rings, sq_tail);
	p->sq_off.ring_mask = offsetof(struct sq_rings, sq_ring_mask);
	p->sq_off.ring_entries = offsetof(struct sq_rings, sq_ring_entries);
	p->sq_off.flags = offsetof(struct sq_rings, sq_flags);
	p->sq_off.dropped = offsetof(struct sq_rings, sq_dropped);
	p->sq_off.array = (uint32_t)((char *)ctx->sq_array - ctx->kva);
	p->cq_off.head = offsetof(struct sq_rings, cq_head);
	p->cq_off.tail = offsetof(struct sq_rings, cq_tail);
	p->cq_off.ring_mask = offsetof(struct sq_rings, cq_ring_mask);
	p->cq_off.ring_entries = offsetof(struct sq_rings, cq_ring_entries);
	p->cq_off.overflow = offsetof(struct sq_rings, cq_overflow);
	p->cq_off.cqes = (uint32_t)((char *)ctx->cqes - ctx->kva);
	p->cq_off.flags = offsetof(struct sq_rings, cq_flags);

	*fdp = fd;
	fdrop(fp, td);
	return (0);
}

int
kern_squeue_enter(struct thread *td, int fd, uint32_t to_submit,
    uint32_t min_complete, uint32_t flags, const void *arg __unused,
    size_t argsz __unused)
{
	struct squeue_ctx *ctx;
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
	submitted = sq_submit(ctx, to_submit, td);
	/* Post any completions that resolved during/ahead of this submit. */
	sq_run_ready(ctx, td);
	if ((flags & IORING_ENTER_GETEVENTS) != 0 && min_complete > 0) {
		error = sq_wait_cq(ctx, min_complete, fd, td);
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
sq_register_buffers(struct squeue_ctx *ctx, void *arg, uint32_t nr)
{
	struct iovec *bufs;
	int error;

	if (nr == 0 || nr > SQ_MAX_REG_BUFS)
		return (EINVAL);
	mtx_lock(&ctx->mtx);
	if (ctx->reg_bufs != NULL) {
		mtx_unlock(&ctx->mtx);
		return (EBUSY);
	}
	mtx_unlock(&ctx->mtx);
	bufs = malloc(nr * sizeof(*bufs), M_SQUEUE, M_WAITOK | M_ZERO);
	/* Linux struct iovec is layout-identical on LP64. */
	error = copyin(arg, bufs, nr * sizeof(*bufs));
	if (error != 0) {
		free(bufs, M_SQUEUE);
		return (error);
	}
	mtx_lock(&ctx->mtx);
	if (ctx->reg_bufs != NULL) {
		mtx_unlock(&ctx->mtx);
		free(bufs, M_SQUEUE);
		return (EBUSY);
	}
	ctx->reg_bufs = bufs;
	ctx->reg_nbufs = nr;
	mtx_unlock(&ctx->mtx);
	return (0);
}

static int
sq_unregister_buffers(struct squeue_ctx *ctx)
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
	free(bufs, M_SQUEUE);
	return (0);
}

/* ---- registered files ---- */
static int
sq_register_files(struct squeue_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{
	struct file **files;
	struct filecaps *caps;
	int *fds, error;
	uint32_t i;

	if (nr == 0 || nr > SQ_MAX_REG_FILES)
		return (EINVAL);
	mtx_lock(&ctx->mtx);
	if (ctx->reg_files != NULL) {
		mtx_unlock(&ctx->mtx);
		return (EBUSY);
	}
	mtx_unlock(&ctx->mtx);

	fds = malloc(nr * sizeof(*fds), M_SQUEUE, M_WAITOK);
	error = copyin(arg, fds, nr * sizeof(*fds));
	if (error != 0) {
		free(fds, M_SQUEUE);
		return (error);
	}
	files = malloc(nr * sizeof(*files), M_SQUEUE, M_WAITOK | M_ZERO);
	caps = malloc(nr * sizeof(*caps), M_SQUEUE, M_WAITOK);
	for (i = 0; i < nr; i++)
		filecaps_init(&caps[i]);
	for (i = 0; i < nr; i++) {
		if (fds[i] == -1)
			continue;		/* sparse slot */
		/* Capture the descriptor's real capsicum rights (Capsicum). */
		error = fget_cap(td, fds[i], &cap_no_rights, NULL, &files[i],
		    &caps[i]);
		if (error != 0) {
			while (i-- > 0) {
				if (files[i] != NULL)
					fdrop(files[i], td);
				filecaps_free(&caps[i]);
			}
			free(caps, M_SQUEUE);
			free(files, M_SQUEUE);
			free(fds, M_SQUEUE);
			return (error);
		}
	}
	free(fds, M_SQUEUE);

	mtx_lock(&ctx->mtx);
	if (ctx->reg_files != NULL) {
		mtx_unlock(&ctx->mtx);
		for (i = 0; i < nr; i++) {
			if (files[i] != NULL)
				fdrop(files[i], td);
			filecaps_free(&caps[i]);
		}
		free(caps, M_SQUEUE);
		free(files, M_SQUEUE);
		return (EBUSY);
	}
	ctx->reg_files = files;
	ctx->reg_caps = caps;
	ctx->reg_nfiles = nr;
	mtx_unlock(&ctx->mtx);
	return (0);
}

static int
sq_unregister_files(struct squeue_ctx *ctx, struct thread *td)
{
	struct file **files;
	struct filecaps *caps;
	uint32_t i, nr;

	mtx_lock(&ctx->mtx);
	if (ctx->reg_files == NULL) {
		mtx_unlock(&ctx->mtx);
		return (ENXIO);
	}
	files = ctx->reg_files;
	caps = ctx->reg_caps;
	nr = ctx->reg_nfiles;
	ctx->reg_files = NULL;
	ctx->reg_caps = NULL;
	ctx->reg_nfiles = 0;
	mtx_unlock(&ctx->mtx);
	for (i = 0; i < nr; i++) {
		if (files[i] != NULL)
			fdrop(files[i], td);
		filecaps_free(&caps[i]);
	}
	free(files, M_SQUEUE);
	free(caps, M_SQUEUE);
	return (0);
}

/* IORING_REGISTER_FILES_UPDATE: unpack the struct, then update a slot range. */
static int
sq_files_update(struct squeue_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{
	struct io_uring_files_update up;
	int error;

	error = copyin(arg, &up, sizeof(up));
	if (error != 0)
		return (error);
	return (sq_do_files_update(ctx, up.offset, up.fds, nr, td));
}

/* Core: replace registered-file slots [off, off+nr) from the fd array. */
static int
sq_do_files_update(struct squeue_ctx *ctx, uint32_t off, uint64_t fds_uptr,
    uint32_t nr, struct thread *td)
{
	struct file *newfp, *oldfp;
	struct filecaps newcaps, oldcaps;
	int *fds, error, fd;
	uint32_t i, done;

	/* Bound the count before allocating (attacker-controlled nr). */
	if (nr == 0 || nr > SQ_MAX_REG_FILES)
		return (EINVAL);
	fds = malloc(nr * sizeof(*fds), M_SQUEUE, M_WAITOK);
	error = copyin((void *)(uintptr_t)fds_uptr, fds, nr * sizeof(*fds));
	if (error != 0) {
		free(fds, M_SQUEUE);
		return (error);
	}
	mtx_lock(&ctx->mtx);
	/* Overflow-safe range check: off and off+nr must lie within the table. */
	if (ctx->reg_files == NULL || off >= ctx->reg_nfiles ||
	    nr > ctx->reg_nfiles - off) {
		mtx_unlock(&ctx->mtx);
		free(fds, M_SQUEUE);
		return (EINVAL);
	}
	mtx_unlock(&ctx->mtx);

	done = 0;
	for (i = 0; i < nr; i++) {
		fd = fds[i];
		newfp = NULL;
		filecaps_init(&newcaps);
		if (fd != -1) {
			/* Capture the new descriptor's capsicum rights too. */
			error = fget_cap(td, fd, &cap_no_rights, NULL, &newfp,
			    &newcaps);
			if (error != 0)
				break;
		}
		mtx_lock(&ctx->mtx);
		oldfp = ctx->reg_files[off + i];
		oldcaps = ctx->reg_caps[off + i];
		ctx->reg_files[off + i] = newfp;
		ctx->reg_caps[off + i] = newcaps;
		mtx_unlock(&ctx->mtx);
		if (oldfp != NULL)
			fdrop(oldfp, td);
		filecaps_free(&oldcaps);
		done++;
	}
	free(fds, M_SQUEUE);
	td->td_retval[0] = done;
	return (error);
}

static int
sq_register_probe(struct squeue_ctx *ctx, void *arg, uint32_t nr)
{
	struct io_uring_probe *probe;
	size_t sz;
	uint32_t i;
	int error;

	if (nr > IORING_OP_LAST)
		nr = IORING_OP_LAST;
	sz = sizeof(*probe) + nr * sizeof(struct io_uring_probe_op);
	probe = malloc(sz, M_SQUEUE, M_WAITOK | M_ZERO);
	error = copyin(arg, probe, sz);
	if (error != 0) {
		free(probe, M_SQUEUE);
		return (error);
	}
	probe->last_op = IORING_OP_LAST - 1;
	probe->ops_len = nr;
	for (i = 0; i < nr; i++) {
		probe->ops[i].op = i;
		probe->ops[i].flags = sq_op_supported(i) ?
		    IO_URING_OP_SUPPORTED : 0;
	}
	error = copyout(probe, arg, sz);
	free(probe, M_SQUEUE);
	return (error);
}

/*
 * IORING_REGISTER_EVENTFD: arg points to the eventfd's descriptor.  Hold a
 * reference to the eventfd file; sq_cq_post_raw then signals it on every
 * completion so an eventfd/epoll/kqueue loop can wait on the ring without
 * polling the CQ.
 */
static int
sq_register_eventfd(struct squeue_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{
	struct file *efp;
	int error, efd_fd;

	if (nr != 1)
		return (EINVAL);
	error = copyin(arg, &efd_fd, sizeof(efd_fd));
	if (error != 0)
		return (error);
	error = fget(td, efd_fd, &cap_no_rights, &efp);
	if (error != 0)
		return (error);
	if (efp->f_type != DTYPE_EVENTFD) {
		fdrop(efp, td);
		return (EINVAL);
	}
	mtx_lock(&ctx->mtx);
	if (ctx->eventfd_fp != NULL) {
		mtx_unlock(&ctx->mtx);
		fdrop(efp, td);
		return (EBUSY);
	}
	ctx->eventfd_fp = efp;			/* keep the reference */
	ctx->eventfd = efp->f_data;
	mtx_unlock(&ctx->mtx);
	return (0);
}

static int
sq_unregister_eventfd(struct squeue_ctx *ctx, struct thread *td)
{
	struct file *efp;

	mtx_lock(&ctx->mtx);
	efp = ctx->eventfd_fp;
	ctx->eventfd_fp = NULL;
	ctx->eventfd = NULL;
	mtx_unlock(&ctx->mtx);
	if (efp == NULL)
		return (EINVAL);
	fdrop(efp, td);
	return (0);
}

int
kern_squeue_register(struct thread *td, int fd, uint32_t op, void *arg,
    uint32_t nr_args)
{
	struct squeue_ctx *ctx;
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
		error = sq_register_probe(ctx, arg, nr_args);
		break;
	case IORING_REGISTER_BUFFERS:
		error = sq_register_buffers(ctx, arg, nr_args);
		break;
	case IORING_UNREGISTER_BUFFERS:
		error = sq_unregister_buffers(ctx);
		break;
	case IORING_REGISTER_FILES:
		error = sq_register_files(ctx, arg, nr_args, td);
		break;
	case IORING_UNREGISTER_FILES:
		error = sq_unregister_files(ctx, td);
		break;
	case IORING_REGISTER_FILES_UPDATE:
		error = sq_files_update(ctx, arg, nr_args, td);
		break;
	case IORING_REGISTER_EVENTFD:
		error = sq_register_eventfd(ctx, arg, nr_args, td);
		break;
	case IORING_UNREGISTER_EVENTFD:
		error = sq_unregister_eventfd(ctx, td);
		break;
	default:
		error = EINVAL;		/* later phases */
		break;
	}
	fdrop(fp, td);
	return (error);
}


/* ---- native squeue_* syscalls (5BSD front-end: BSD errnos, core opcodes) ---- */
static const struct sq_frontend squeue_native_frontend = {
	.is_linux = false,
	.err_xlate = NULL,	/* negate: cqe->res carries a negative BSD errno */
	.issue_ext = NULL,	/* core opcodes only (native fs/net: later) */
};

int
sys_squeue_setup(struct thread *td, struct squeue_setup_args *uap)
{
	struct io_uring_params p;
	int error, fd;

	error = copyin(uap->params, &p, sizeof(p));
	if (error != 0)
		return (error);
	error = kern_squeue_setup(td, uap->entries, &p,
	    &squeue_native_frontend, &fd);
	if (error != 0)
		return (error);
	error = copyout(&p, uap->params, sizeof(p));
	if (error != 0) {
		(void)kern_close(td, fd);
		return (error);
	}
	td->td_retval[0] = fd;
	return (0);
}

int
sys_squeue_enter(struct thread *td, struct squeue_enter_args *uap)
{

	return (kern_squeue_enter(td, uap->fd, uap->to_submit,
	    uap->min_complete, uap->flags, uap->arg, uap->argsz));
}

int
sys_squeue_register(struct thread *td, struct squeue_register_args *uap)
{

	return (kern_squeue_register(td, uap->fd, uap->op, uap->arg,
	    uap->nr_args));
}
