/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * io_uring for the Linuxulator - engine + Linux front-end (phase 1).
 *
 * The engine (iou_* / kern_io_uring_*) is ABI-neutral and written as the
 * native core described in docs/linuxulator-io_uring-design.md; for phase 1
 * it is built into the Linux module and exercised through the Linux ABI.
 * Phase 1 implements the shared SQ/CQ/SQE rings (a wired OBJT_PHYS object
 * dual-mapped into the kernel and, via fo_mmap, into the process), the
 * setup/enter/register syscalls, the submit/complete/wait loop, the NOP
 * opcode, and IORING_REGISTER_PROBE.  Further opcodes arrive in later phases;
 * an unimplemented opcode completes with res = -EINVAL and is reported
 * unsupported by PROBE, exactly as a Linux kernel lacking it would.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/user.h>
#include <sys/sbuf.h>
#include <sys/syscallsubr.h>

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

#define	IOU_MAX_ENTRIES		32768

MALLOC_DEFINE(M_LINUX_IOURING, "linux_iouring", "Linux io_uring");

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
};

/* ---- opcode support matrix (drives dispatch + PROBE) ---- */
static bool
iou_op_supported(uint8_t op)
{

	switch (op) {
	case IORING_OP_NOP:
		return (true);
	default:
		return (false);	/* filled in by later phases */
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

static void
iou_ctx_free(struct io_uring_ctx *ctx)
{

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
		/* CQ full: NODROP - bump overflow (phase 1 keeps it simple). */
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

/* ---- submission ---- */
static int32_t
iou_issue(struct io_uring_ctx *ctx, const struct io_uring_sqe *sqe)
{

	switch (sqe->opcode) {
	case IORING_OP_NOP:
		return (0);
	default:
		return (-EINVAL);	/* Linux EINVAL == BSD EINVAL (22) */
	}
}

static int
iou_submit(struct io_uring_ctx *ctx, uint32_t to_submit)
{
	const struct io_uring_sqe *sqe;
	uint32_t head, idx;
	int32_t res;
	int submitted;

	mtx_lock(&ctx->mtx);
	head = ctx->rings->sq_head;
	for (submitted = 0; (uint32_t)submitted < to_submit; submitted++) {
		if (head == ctx->rings->sq_tail)
			break;			/* nothing more queued */
		idx = ctx->sq_array[head & ctx->sq_mask];
		if (idx >= ctx->sq_entries) {
			ctx->rings->sq_dropped++;
			head++;
			continue;
		}
		sqe = &ctx->sqes[idx];
		res = iou_issue(ctx, sqe);
		iou_post_cqe(ctx, sqe->user_data, res, 0);
		head++;
	}
	ctx->rings->sq_head = head;
	if (iou_cq_ready(ctx) > 0) {
		selwakeuppri(&ctx->sel, PSOCK);
		if (ctx->cq_waiters > 0)
			wakeup(&ctx->cq_waiters);
	}
	mtx_unlock(&ctx->mtx);
	return (submitted);
}

static int
iou_wait_cq(struct io_uring_ctx *ctx, uint32_t min_complete)
{
	int error;

	error = 0;
	mtx_lock(&ctx->mtx);
	while (iou_cq_ready(ctx) < min_complete) {
		ctx->cq_waiters++;
		error = msleep(&ctx->cq_waiters, &ctx->mtx, PCATCH, "iouring", 0);
		ctx->cq_waiters--;
		if (error != 0)
			break;
	}
	mtx_unlock(&ctx->mtx);
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
	/* Phase 1: only the plain ring; reject setup flags we do not honor. */
	if (p->flags != 0)
		return (EINVAL);
	if (p->resv[0] != 0 || p->resv[1] != 0 || p->resv[2] != 0)
		return (EINVAL);

	ctx = malloc(sizeof(*ctx), M_LINUX_IOURING, M_WAITOK | M_ZERO);
	mtx_init(&ctx->mtx, "iouring", NULL, MTX_DEF);
	knlist_init_mtx(&ctx->sel.si_note, &ctx->mtx);
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
		return (EINVAL);	/* phase 1: GETEVENTS only */
	error = fget(td, fd, &cap_no_rights, &fp);
	if (error != 0)
		return (error);
	if (fp->f_type != DTYPE_IORING) {
		fdrop(fp, td);
		return (EOPNOTSUPP);
	}
	ctx = fp->f_data;
	submitted = iou_submit(ctx, to_submit);
	if ((flags & IORING_ENTER_GETEVENTS) != 0 && min_complete > 0) {
		error = iou_wait_cq(ctx, min_complete);
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
