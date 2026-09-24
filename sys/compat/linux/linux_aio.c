/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Linux legacy AIO context and mmap ring.  File-I/O jobs use native AIO;
 * this file owns only the Linux address-space and completion ABI.
 */
#include <sys/param.h>
#include <sys/aio.h>
#include <sys/condvar.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/signalvar.h>
#include <sys/uio.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/refcount.h>
#include <sys/resourcevar.h>
#include <sys/rwlock.h>
#include <sys/selinfo.h>
#include <sys/smp.h>
#include <sys/sx.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#include <amd64/linux/linux.h>
#include <amd64/linux/linux_proto.h>
#include <compat/linux/linux_aio.h>
#include <compat/linux/linux_common.h>
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_errno.h>
#include <compat/linux/linux_file.h>
#include <compat/linux/linux_mib.h>
#include <compat/linux/linux_util.h>

#define LINUX_AIO_MAX_EVENTS 65536U
#define LINUX_AIO_MAX_WIRED_PAGES 65536UL

static u_long linux_aio_wired_pages;
static u_long linux_aio_max_wired_pages = LINUX_AIO_MAX_WIRED_PAGES;
SYSCTL_NODE(_compat_linux, OID_AUTO, aio, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Linux legacy AIO contexts");
SYSCTL_ULONG(_compat_linux_aio, OID_AUTO, wired_pages, CTLFLAG_RD,
    &linux_aio_wired_pages, 0, "Pages wired for Linux AIO rings");
SYSCTL_ULONG(_compat_linux_aio, OID_AUTO, max_wired_pages, CTLFLAG_RWTUN,
    &linux_aio_max_wired_pages, 0, "Maximum wired Linux AIO ring pages");

struct linux_aio_event_node {
	TAILQ_ENTRY(linux_aio_event_node) link;
	struct l_aio_event event;
};

struct linux_aio_ctx {
	TAILQ_ENTRY(linux_aio_ctx) link;
	struct mtx mtx;
	struct sx get_sx;
	struct cv cv;
	TAILQ_HEAD(, linux_aio_event_node) overflow;
	vm_object_t obj;
	void *kva;
	struct l_aio_ring *ring;
	vm_size_t size;
	vm_offset_t user_addr;
	uint32_t nr;
	uint32_t pending;
	uint32_t completed;
	uint32_t ring_queued;
	uint32_t seen_head;
	bool dying;
};

struct linux_aio_req {
	TAILQ_ENTRY(linux_aio_req) poll_link;
	struct l_aio_iocb iocb;
	struct linux_aio_event_node *event_node;
	struct eventfd *eventfd;
	struct file *poll_fp;
	struct ucred *poll_cred;
	struct linux_aio_ctx *poll_ctx;
	struct l_aio_iocb *user_cb;
	unsigned int poll_refs;
	short poll_events;
	short poll_result;
	bool poll_active;
};

static struct mtx linux_aio_poll_mtx;
static struct sx linux_aio_poll_start_sx;
static struct cv linux_aio_poll_cv;
static struct selinfo linux_aio_poll_sel;
static TAILQ_HEAD(, linux_aio_req) linux_aio_polls;
static volatile unsigned long linux_aio_poll_generation;
static unsigned int linux_aio_poll_count;
static bool linux_aio_poll_started;
static bool linux_aio_poll_stopping;
static bool linux_aio_poll_exited;

static void linux_aio_poll_cancel_ctx(struct linux_aio_ctx *ctx);
static int linux_aio_poll_cancel(struct linux_aio_ctx *ctx,
    struct l_aio_iocb *user_cb);
static int linux_aio_poll_submit(struct linux_aio_ctx *ctx,
    struct linux_aio_req *req, struct l_aio_iocb *user_cb);

struct linux_aio_mm {
	struct sx sx;
	TAILQ_HEAD(, linux_aio_ctx) contexts;
	u_int refs;
};

static struct linux_aio_mm *
linux_aio_mm_get(struct linux_pemuldata *pem, bool create)
{
	struct linux_aio_mm *mm;

	LINUX_PEM_XLOCK(pem);
	mm = pem->aio_mm;
	if (mm == NULL && create) {
		mm = malloc(sizeof(*mm), M_LINUX, M_WAITOK | M_ZERO);
		sx_init(&mm->sx, "laio-mm");
		TAILQ_INIT(&mm->contexts);
		mm->refs = 1; /* pem's ownership */
		pem->aio_mm = mm;
	}
	if (mm != NULL)
		refcount_acquire(&mm->refs);
	LINUX_PEM_XUNLOCK(pem);
	return (mm);
}

static void
linux_aio_ctx_free(struct linux_aio_ctx *ctx, struct thread *td, bool unmap)
{
	mtx_lock(&ctx->mtx);
	ctx->dying = true;
	mtx_unlock(&ctx->mtx);
	linux_aio_poll_cancel_ctx(ctx);
	mtx_lock(&ctx->mtx);
	while (ctx->pending != 0)
		cv_wait(&ctx->cv, &ctx->mtx);
	mtx_unlock(&ctx->mtx);
	(void)aio_compat_reap_done(td, ctx);
	if (unmap && ctx->user_addr != 0)
		(void)kern_munmap(td, ctx->user_addr, ctx->size);
	if (ctx->kva != NULL) {
		pmap_qremove(ctx->kva, atop(ctx->size));
		kva_free(ctx->kva, ctx->size);
	}
	if (ctx->obj != NULL) {
		vm_object_deallocate(ctx->obj);
		atomic_subtract_long(&linux_aio_wired_pages, atop(ctx->size));
	}
	while (!TAILQ_EMPTY(&ctx->overflow)) {
		struct linux_aio_event_node *node;

		node = TAILQ_FIRST(&ctx->overflow);
		TAILQ_REMOVE(&ctx->overflow, node, link);
		free(node, M_LINUX);
	}
	cv_destroy(&ctx->cv);
	sx_destroy(&ctx->get_sx);
	mtx_destroy(&ctx->mtx);
	free(ctx, M_LINUX);
}

static void
linux_aio_mm_put(struct linux_aio_mm *mm, struct thread *td)
{
	struct linux_aio_ctx *ctx;

	if (!refcount_release(&mm->refs))
		return;
	sx_xlock(&mm->sx);
	while ((ctx = TAILQ_FIRST(&mm->contexts)) != NULL) {
		TAILQ_REMOVE(&mm->contexts, ctx, link);
		/* The native process-exec/exit rundown precedes this cleanup. */
		aio_compat_drain(td, ctx);
		linux_aio_ctx_free(ctx, td, false);
	}
	sx_xunlock(&mm->sx);
	sx_destroy(&mm->sx);
	free(mm, M_LINUX);
}

void
linux_aio_proc_share(struct linux_pemuldata *parent,
    struct linux_pemuldata *child)
{
	struct linux_aio_mm *mm;

	LINUX_PEM_SLOCK(parent);
	mm = parent->aio_mm;
	if (mm != NULL)
		refcount_acquire(&mm->refs);
	child->aio_mm = mm;
	LINUX_PEM_SUNLOCK(parent);
}

void
linux_aio_proc_release(struct linux_pemuldata *pem, struct thread *td)
{
	struct linux_aio_mm *mm;

	LINUX_PEM_XLOCK(pem);
	mm = pem->aio_mm;
	pem->aio_mm = NULL;
	LINUX_PEM_XUNLOCK(pem);
	if (mm != NULL)
		linux_aio_mm_put(mm, td);
}

static int
linux_aio_ring_alloc(struct thread *td, struct linux_aio_ctx *ctx,
    uint32_t wanted)
{
	vm_page_t *pages;
	void *kva;
	u_long npages;
	uint32_t i;

	ctx->size = round_page(sizeof(struct l_aio_ring) +
	    ((vm_size_t)wanted + 2) * sizeof(struct l_aio_event));
	npages = atop(ctx->size);
	if (ctx->size > lim_cur(td, RLIMIT_MEMLOCK) &&
	    priv_check(td, PRIV_VM_MLOCK) != 0)
		return (ENOMEM);
	if (atomic_fetchadd_long(&linux_aio_wired_pages, npages) + npages >
	    linux_aio_max_wired_pages) {
		atomic_subtract_long(&linux_aio_wired_pages, npages);
		return (ENOMEM);
	}
	ctx->obj = vm_pager_allocate(OBJT_PHYS, NULL, ctx->size,
	    VM_PROT_DEFAULT, 0, td->td_ucred);
	if (ctx->obj == NULL) {
		atomic_subtract_long(&linux_aio_wired_pages, npages);
		return (ENOMEM);
	}
	kva = kva_alloc(ctx->size);
	if (kva == NULL)
		return (ENOMEM);
	ctx->kva = kva;
	pages = mallocarray(npages, sizeof(*pages), M_LINUX, M_WAITOK);
	VM_OBJECT_WLOCK(ctx->obj);
	for (i = 0; i < npages; i++) {
		pages[i] = vm_page_grab(ctx->obj, i, VM_ALLOC_NORMAL |
		    VM_ALLOC_WIRED | VM_ALLOC_ZERO);
		vm_page_valid(pages[i]);
		vm_page_xunbusy(pages[i]);
	}
	VM_OBJECT_WUNLOCK(ctx->obj);
	pmap_qenter(kva, pages, npages);
	free(pages, M_LINUX);
	ctx->ring = ctx->kva;
	ctx->nr = (ctx->size - sizeof(struct l_aio_ring)) /
	    sizeof(struct l_aio_event);
	ctx->ring->nr = ctx->nr;
	ctx->ring->magic = LINUX_AIO_RING_MAGIC;
	ctx->ring->compat_features = LINUX_AIO_RING_COMPAT;
	ctx->ring->header_length = sizeof(struct l_aio_ring);
	return (0);
}

int
linux_io_setup(struct thread *td, struct linux_io_setup_args *uap)
{
	struct linux_pemuldata *pem;
	struct linux_aio_mm *mm;
	struct linux_aio_ctx *ctx;
	vm_offset_t addr;
	l_ulong initial;
	uint32_t ring_events;
	int error;

	error = copyin(uap->ctxp, &initial, sizeof(initial));
	if (error != 0)
		return (error);
	if (initial != 0 || uap->nr_events == 0)
		return (EINVAL);
	/* Match Linux's 32-bit ring-size arithmetic and error ordering. */
	ring_events = MAX(uap->nr_events, (uint32_t)mp_ncpus * 4);
	ring_events *= 2;
	if (ring_events > UINT32_C(0x10000000) / sizeof(struct l_aio_event))
		return (EINVAL);
	if (ring_events == 0 || uap->nr_events > LINUX_AIO_MAX_EVENTS)
		return (EAGAIN);
	pem = pem_find(td->td_proc);
	if (pem == NULL)
		return (EINVAL);
	mm = linux_aio_mm_get(pem, true);
	ctx = malloc(sizeof(*ctx), M_LINUX, M_WAITOK | M_ZERO);
	mtx_init(&ctx->mtx, "laio-ctx", NULL, MTX_DEF);
	sx_init(&ctx->get_sx, "laio-get");
	cv_init(&ctx->cv, "laio-cv");
	TAILQ_INIT(&ctx->overflow);
	error = linux_aio_ring_alloc(td, ctx, uap->nr_events);
	if (error != 0)
		goto fail;
	addr = 0;
	vm_object_reference(ctx->obj);
	error = vm_mmap_object(&td->td_proc->p_vmspace->vm_map, &addr,
	    ctx->size, VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE, MAP_SHARED, ctx->obj, 0, false, td);
	if (error != 0) {
		vm_object_deallocate(ctx->obj);
		goto fail;
	}
	ctx->user_addr = addr;
	ctx->ring->id = ~0U;
	initial = addr;
	error = copyout(&initial, uap->ctxp, sizeof(initial));
	if (error != 0)
		goto fail;
	sx_xlock(&mm->sx);
	TAILQ_INSERT_TAIL(&mm->contexts, ctx, link);
	sx_xunlock(&mm->sx);
	linux_aio_mm_put(mm, td);
	return (0);
fail:
	linux_aio_ctx_free(ctx, td, true);
	linux_aio_mm_put(mm, td);
	return (error);
}

int
linux_io_destroy(struct thread *td, struct linux_io_destroy_args *uap)
{
	struct linux_pemuldata *pem;
	struct linux_aio_mm *mm;
	struct linux_aio_ctx *ctx;

	pem = pem_find(td->td_proc);
	if (pem == NULL || (mm = linux_aio_mm_get(pem, false)) == NULL)
		return (EINVAL);
	sx_xlock(&mm->sx);
	TAILQ_FOREACH(ctx, &mm->contexts, link) {
		if (ctx->user_addr == uap->ctx)
			break;
	}
	if (ctx != NULL) {
		TAILQ_REMOVE(&mm->contexts, ctx, link);
		mtx_lock(&ctx->mtx);
		ctx->dying = true;
		mtx_unlock(&ctx->mtx);
	}
	sx_xunlock(&mm->sx);
	if (ctx == NULL) {
		linux_aio_mm_put(mm, td);
		return (EINVAL);
	}
	aio_compat_drain(td, ctx);
	linux_aio_ctx_free(ctx, td, true);
	linux_aio_mm_put(mm, td);
	return (0);
}

static void
linux_aio_req_free(struct linux_aio_req *req)
{
	if (req->poll_fp != NULL)
		fdrop(req->poll_fp, curthread);
	if (req->poll_cred != NULL)
		crfree(req->poll_cred);
	if (req->eventfd != NULL)
		eventfd_put(req->eventfd);
	if (req->event_node != NULL)
		free(req->event_node, M_LINUX);
	free(req, M_LINUX);
}

static void
linux_aio_release(struct kaiocb *job __unused, void *private)
{
	linux_aio_req_free(private);
}

/* Publish from native AIO completion or the independent poll consumer. */
static void
linux_aio_post(struct linux_aio_ctx *ctx, struct linux_aio_req *req,
    void *user_cb, int64_t result)
{
	struct linux_aio_event_node *node;
	uint32_t head, tail, next;

	node = req->event_node;
	req->event_node = NULL;
	node->event.data = req->iocb.data;
	node->event.obj = (uintptr_t)user_cb;
	node->event.res = result;
	node->event.res2 = 0;
	mtx_lock(&ctx->mtx);
	if (!ctx->dying) {
		head = atomic_load_acq_32(&ctx->ring->head);
		tail = atomic_load_acq_32(&ctx->ring->tail);
		next = tail + 1 == ctx->nr ? 0 : tail + 1;
		if (head < ctx->nr && tail < ctx->nr && next != head) {
			ctx->ring->events[tail] = node->event;
			atomic_store_rel_32(&ctx->ring->tail, next);
			ctx->ring_queued++;
			free(node, M_LINUX);
		} else
			TAILQ_INSERT_TAIL(&ctx->overflow, node, link);
		ctx->completed++;
	} else
		free(node, M_LINUX);
	mtx_unlock(&ctx->mtx);
	/* Match Linux: publish the event and tail before signaling eventfd. */
	if (req->eventfd != NULL)
		eventfd_signal(req->eventfd);
	mtx_lock(&ctx->mtx);
	KASSERT(ctx->pending > 0, ("Linux AIO pending underflow"));
	ctx->pending--;
	cv_broadcast(&ctx->cv);
	mtx_unlock(&ctx->mtx);
}

/* Called with the native kaio lock held; this path never faults user memory. */
static void
linux_aio_done(struct kaiocb *job, void *cookie)
{
	struct linux_aio_req *req;
	int error;

	req = job->compat_private;
	error = job->uaiocb._aiocb_private.error;
	linux_aio_post(cookie, req, job->ujob, error == 0 ?
	    job->uaiocb._aiocb_private.status : bsd_to_linux_errno(error));
}

static void
linux_aio_poll_put(struct linux_aio_req *req)
{
	bool last;

	mtx_lock(&linux_aio_poll_mtx);
	KASSERT(req->poll_refs > 0, ("Linux AIO poll ref underflow"));
	last = --req->poll_refs == 0;
	mtx_unlock(&linux_aio_poll_mtx);
	if (last)
		linux_aio_req_free(req);
}

static void
linux_aio_poll_worker(void *arg __unused)
{
	struct linux_aio_req **reqs, *req;
	struct poll_file *files;
	TAILQ_HEAD(, linux_aio_req) done;
	unsigned int capacity, i, j, ready;
	unsigned long observed;
	short result;
	int error;

	for (;;) {
		mtx_lock(&linux_aio_poll_mtx);
		if (linux_aio_poll_stopping) {
			mtx_unlock(&linux_aio_poll_mtx);
			break;
		}
		capacity = MAX(linux_aio_poll_count, 1);
		mtx_unlock(&linux_aio_poll_mtx);
		files = mallocarray(capacity, sizeof(*files), M_LINUX,
		    M_WAITOK | M_ZERO);
		reqs = mallocarray(capacity, sizeof(*reqs), M_LINUX, M_WAITOK);
		mtx_lock(&linux_aio_poll_mtx);
		if (linux_aio_poll_count > capacity) {
			mtx_unlock(&linux_aio_poll_mtx);
			free(reqs, M_LINUX);
			free(files, M_LINUX);
			continue;
		}
		if (linux_aio_poll_stopping) {
			mtx_unlock(&linux_aio_poll_mtx);
			free(reqs, M_LINUX);
			free(files, M_LINUX);
			break;
		}
		i = 0;
		TAILQ_FOREACH(req, &linux_aio_polls, poll_link) {
			req->poll_refs++; /* snapshot through the blocking wait */
			reqs[i] = req;
			files[i].fp = req->poll_fp;
			files[i].cred = req->poll_cred;
			files[i].events = req->poll_events;
			i++;
		}
		observed = linux_aio_poll_generation;
		mtx_unlock(&linux_aio_poll_mtx);
		ready = 0;
		error = kern_poll_fps(curthread, files, i,
		    &linux_aio_poll_sel, &linux_aio_poll_generation, observed,
		    &ready);
		TAILQ_INIT(&done);
		mtx_lock(&linux_aio_poll_mtx);
		if (error == 0 && ready != 0) {
			for (j = 0; j < i; j++) {
				req = reqs[j];
				if (!req->poll_active || files[j].revents == 0)
					continue;
				bsd_to_linux_poll_events(files[j].revents,
				    &result);
				req->poll_result = result;
				TAILQ_REMOVE(&linux_aio_polls, req, poll_link);
				linux_aio_poll_count--;
				req->poll_active = false;
				TAILQ_INSERT_TAIL(&done, req, poll_link);
			}
		}
		mtx_unlock(&linux_aio_poll_mtx);
		while ((req = TAILQ_FIRST(&done)) != NULL) {
			TAILQ_REMOVE(&done, req, poll_link);
			linux_aio_post(req->poll_ctx, req, req->user_cb,
			    req->poll_result);
			linux_aio_poll_put(req); /* list ownership */
		}
		for (j = 0; j < i; j++)
			linux_aio_poll_put(reqs[j]);
		free(reqs, M_LINUX);
		free(files, M_LINUX);
	}
	seltdfini(curthread);
	mtx_lock(&linux_aio_poll_mtx);
	linux_aio_poll_exited = true;
	cv_broadcast(&linux_aio_poll_cv);
	mtx_unlock(&linux_aio_poll_mtx);
	kproc_exit(0);
}

static int
linux_aio_poll_submit(struct linux_aio_ctx *ctx, struct linux_aio_req *req,
    struct l_aio_iocb *user_cb)
{
	struct proc *worker;
	int error;

	if ((req->iocb.buf & ~0xffffULL) != 0 || req->iocb.offset != 0 ||
	    req->iocb.nbytes != 0 || req->iocb.rw_flags != 0)
		return (EINVAL);
	req->poll_cred = crhold(curthread->td_ucred);
	linux_to_bsd_poll_events(curthread, req->iocb.fd,
	    (short)req->iocb.buf, &req->poll_events);
	sx_xlock(&linux_aio_poll_start_sx);
	if (!linux_aio_poll_started) {
		error = kproc_create(linux_aio_poll_worker, NULL, &worker,
		    0, 0, "linuxaio-poll");
		if (error == 0)
			linux_aio_poll_started = true;
	} else
		error = 0;
	sx_xunlock(&linux_aio_poll_start_sx);
	if (error != 0)
		return (error);
	req->poll_ctx = ctx;
	req->user_cb = user_cb;
	req->poll_refs = 1;
	req->poll_active = true;
	mtx_lock(&linux_aio_poll_mtx);
	TAILQ_INSERT_TAIL(&linux_aio_polls, req, poll_link);
	linux_aio_poll_count++;
	atomic_add_long(&linux_aio_poll_generation, 1);
	mtx_unlock(&linux_aio_poll_mtx);
	selwakeup(&linux_aio_poll_sel);
	return (0);
}

static int
linux_aio_poll_cancel(struct linux_aio_ctx *ctx, struct l_aio_iocb *user_cb)
{
	struct linux_aio_req *req;

	mtx_lock(&linux_aio_poll_mtx);
	TAILQ_FOREACH(req, &linux_aio_polls, poll_link)
		if (req->poll_ctx == ctx && req->user_cb == user_cb)
			break;
	if (req != NULL) {
		TAILQ_REMOVE(&linux_aio_polls, req, poll_link);
		linux_aio_poll_count--;
		req->poll_active = false;
		atomic_add_long(&linux_aio_poll_generation, 1);
	}
	mtx_unlock(&linux_aio_poll_mtx);
	if (req == NULL)
		return (ENOENT);
	selwakeup(&linux_aio_poll_sel);
	linux_aio_post(ctx, req, user_cb, 0);
	linux_aio_poll_put(req);
	return (EINPROGRESS);
}

static void
linux_aio_poll_cancel_ctx(struct linux_aio_ctx *ctx)
{
	struct linux_aio_req *req, *next;
	TAILQ_HEAD(, linux_aio_req) done;
	bool changed;

	TAILQ_INIT(&done);
	changed = false;
	mtx_lock(&linux_aio_poll_mtx);
	TAILQ_FOREACH_SAFE(req, &linux_aio_polls, poll_link, next) {
		if (req->poll_ctx != ctx)
			continue;
		TAILQ_REMOVE(&linux_aio_polls, req, poll_link);
		linux_aio_poll_count--;
		req->poll_active = false;
		TAILQ_INSERT_TAIL(&done, req, poll_link);
		changed = true;
	}
	if (changed)
		atomic_add_long(&linux_aio_poll_generation, 1);
	mtx_unlock(&linux_aio_poll_mtx);
	if (changed)
		selwakeup(&linux_aio_poll_sel);
	while ((req = TAILQ_FIRST(&done)) != NULL) {
		TAILQ_REMOVE(&done, req, poll_link);
		linux_aio_post(ctx, req, req->user_cb, 0);
		linux_aio_poll_put(req);
	}
}

static void
linux_aio_poll_init(void *arg __unused)
{

	mtx_init(&linux_aio_poll_mtx, "laio-poll", NULL, MTX_DEF);
	sx_init(&linux_aio_poll_start_sx, "laio-poll-start");
	cv_init(&linux_aio_poll_cv, "laio-poll-exit");
	TAILQ_INIT(&linux_aio_polls);
}
SYSINIT(linux_aio_poll, SI_SUB_TASKQ, SI_ORDER_ANY, linux_aio_poll_init,
    NULL);

static void
linux_aio_poll_uninit(void *arg __unused)
{

	sx_xlock(&linux_aio_poll_start_sx);
	if (linux_aio_poll_started) {
		mtx_lock(&linux_aio_poll_mtx);
		KASSERT(TAILQ_EMPTY(&linux_aio_polls),
		    ("Linux AIO polls remain on module unload"));
		linux_aio_poll_stopping = true;
		atomic_add_long(&linux_aio_poll_generation, 1);
		mtx_unlock(&linux_aio_poll_mtx);
		selwakeup(&linux_aio_poll_sel);
		mtx_lock(&linux_aio_poll_mtx);
		while (!linux_aio_poll_exited)
			cv_wait(&linux_aio_poll_cv, &linux_aio_poll_mtx);
		mtx_unlock(&linux_aio_poll_mtx);
	}
	sx_xunlock(&linux_aio_poll_start_sx);
	cv_destroy(&linux_aio_poll_cv);
	sx_destroy(&linux_aio_poll_start_sx);
	mtx_destroy(&linux_aio_poll_mtx);
}
SYSUNINIT(linux_aio_poll, SI_SUB_TASKQ, SI_ORDER_ANY, linux_aio_poll_uninit,
    NULL);

/* Linux ABI validation stays here; native AIO only sees FOF_* policy. */
static int
linux_aio_rwf_flags(uint32_t flags, int type, int *foflags)
{

	if ((flags & ~LINUX_RWF_SUPPORTED) != 0)
		return (EOPNOTSUPP);
	if ((flags & (LINUX_RWF_APPEND | LINUX_RWF_NOAPPEND)) ==
	    (LINUX_RWF_APPEND | LINUX_RWF_NOAPPEND))
		return (EINVAL);
	if ((flags & (LINUX_RWF_NOWAIT | LINUX_RWF_ATOMIC |
	    LINUX_RWF_DONTCACHE)) != 0)
		return (EOPNOTSUPP);
	*foflags = 0;
	if (type == LIO_WRITE || type == LIO_WRITEV) {
		if ((flags & LINUX_RWF_DSYNC) != 0)
			*foflags |= FOF_DSYNC;
		if ((flags & LINUX_RWF_SYNC) != 0)
			*foflags |= FOF_SYNC;
		if ((flags & LINUX_RWF_APPEND) != 0)
			*foflags |= FOF_APPEND;
		if ((flags & LINUX_RWF_NOAPPEND) != 0)
			*foflags |= FOF_NOAPPEND;
		if ((flags & LINUX_RWF_NOSIGNAL) != 0)
			*foflags |= FOF_NOSIGPIPE;
	}
	return (0);
}

static int
linux_aio_copyin(void *user_cb __unused, struct kaiocb *job, int type,
    void *cookie __unused)
{
	struct linux_aio_req *req;
	struct l_aio_iocb *iocb;
	struct aiocb *cb;
	int error;

	req = job->compat_private;
	iocb = &req->iocb;
	cb = &job->uaiocb;
	if (iocb->reserved2 != 0)
		return (EINVAL);
	/*
	 * Linux interprets reqprio only for read/write IOCBs carrying the
	 * IOPRIO flag.  Other flag bits and an otherwise nonzero field are
	 * forward-compatible and ignored.
	 */
	if ((type == LIO_READ || type == LIO_WRITE || type == LIO_READV ||
	    type == LIO_WRITEV) &&
	    (iocb->flags & LINUX_IOCB_FLAG_IOPRIO) != 0) {
		error = linux_ioprio_check_cap(curthread, iocb->reqprio);
		if (error != 0)
			return (error);
	}
	/* Linux requires all operation-specific fsync fields to be zero. */
	if ((type == LIO_SYNC || type == LIO_DSYNC) &&
	    (iocb->buf != 0 || iocb->offset != 0 || iocb->nbytes != 0 ||
	    iocb->rw_flags != 0))
		return (EINVAL);
	error = linux_aio_rwf_flags(iocb->rw_flags, type,
	    &job->compat_foflags);
	if (error != 0)
		return (error);
	if (type == LIO_READ || type == LIO_READV || type == LIO_WRITE ||
	    type == LIO_WRITEV)
		job->ioflags |= KAIOCB_IO_COMPAT_GENERIC;
	if (type == LIO_WRITE || type == LIO_WRITEV)
		job->ioflags |= KAIOCB_IO_LINUX_SIGPIPE;
	bzero(cb, sizeof(*cb));
	cb->aio_fildes = iocb->fd;
	cb->aio_buf = (void *)(uintptr_t)iocb->buf;
	cb->aio_nbytes = iocb->nbytes;
	cb->aio_offset = iocb->offset;
	cb->aio_sigevent.sigev_notify = SIGEV_NONE;
	if (type == LIO_READV || type == LIO_WRITEV) {
		if (iocb->nbytes > UIO_MAXIOV)
			return (EINVAL);
		error = copyinuio((void *)(uintptr_t)iocb->buf,
		    iocb->nbytes, &job->uiop);
		if (error != 0)
			return (error);
	}
	return (0);
}

static int
linux_aio_type(uint16_t opcode)
{
	switch (opcode) {
	case LINUX_IOCB_CMD_PREAD: return (LIO_READ);
	case LINUX_IOCB_CMD_PWRITE: return (LIO_WRITE);
	case LINUX_IOCB_CMD_PREADV: return (LIO_READV);
	case LINUX_IOCB_CMD_PWRITEV: return (LIO_WRITEV);
	case LINUX_IOCB_CMD_FSYNC: return (LIO_SYNC);
	case LINUX_IOCB_CMD_FDSYNC: return (LIO_DSYNC);
	default: return (-1);
	}
}

/* Account for events consumed directly from the mmap ring by userland. */
static int
linux_aio_reconcile_head(struct linux_aio_ctx *ctx)
{
	uint32_t head, delta;

	mtx_assert(&ctx->mtx, MA_OWNED);
	head = atomic_load_acq_32(&ctx->ring->head);
	if (head >= ctx->nr)
		return (EINVAL);
	delta = head >= ctx->seen_head ? head - ctx->seen_head :
	    ctx->nr - ctx->seen_head + head;
	if (delta > ctx->ring_queued)
		return (EINVAL);
	ctx->ring_queued -= delta;
	ctx->completed -= delta;
	ctx->seen_head = head;
	return (0);
}

int
linux_io_submit(struct thread *td, struct linux_io_submit_args *uap)
{
	struct linux_pemuldata *pem;
	struct linux_aio_mm *mm;
	struct linux_aio_ctx *ctx;
	struct linux_aio_req *req;
	struct l_aio_iocb *user_cb;
	struct file *fp;
	uintptr_t slot;
	uint32_t key;
	int error, i, submitted, type;

	if (uap->nr < 0)
		return (EINVAL);
	pem = pem_find(td->td_proc);
	if (pem == NULL || (mm = linux_aio_mm_get(pem, false)) == NULL)
		return (EINVAL);
	sx_slock(&mm->sx);
	TAILQ_FOREACH(ctx, &mm->contexts, link)
		if (ctx->user_addr == uap->ctx)
			break;
	if (ctx == NULL) {
		error = EINVAL;
		goto out;
	}
	(void)aio_compat_reap_done(td, NULL);
	submitted = 0;
	error = 0;
	for (i = 0; i < uap->nr; i++) {
		slot = (uintptr_t)uap->iocbpp + (size_t)i * sizeof(user_cb);
		if (slot < (uintptr_t)uap->iocbpp) {
			error = EFAULT;
			break;
		}
		error = copyin((void *)slot, &user_cb, sizeof(user_cb));
		if (error != 0)
			break;
		req = malloc(sizeof(*req), M_LINUX, M_WAITOK | M_ZERO);
		error = copyin(user_cb, &req->iocb, sizeof(req->iocb));
		if (error != 0) {
			linux_aio_req_free(req);
			break;
		}
		/* Linux rejects reserved fields before acquiring a request file. */
		if (req->iocb.reserved2 != 0 ||
		    (int64_t)req->iocb.nbytes < 0) {
			linux_aio_req_free(req);
			error = EINVAL;
			break;
		}
		/* The target descriptor is checked before aio_key is written. */
		error = fget(td, req->iocb.fd, &cap_no_rights, &fp);
		if (error != 0) {
			linux_aio_req_free(req);
			break;
		}
		if (req->iocb.opcode == LINUX_IOCB_CMD_POLL)
			req->poll_fp = fp;
		else
			fdrop(fp, td);
		if ((req->iocb.flags & LINUX_IOCB_FLAG_RESFD) != 0) {
			error = fget(td, req->iocb.resfd, &cap_no_rights, &fp);
			if (error == 0) {
				req->eventfd = eventfd_get(fp);
				fdrop(fp, td);
				if (req->eventfd == NULL)
					error = EINVAL;
			}
			if (error != 0) {
				linux_aio_req_free(req);
				break;
			}
		}
		req->event_node = malloc(sizeof(*req->event_node), M_LINUX,
		    M_WAITOK | M_ZERO);
		mtx_lock(&ctx->mtx);
		error = linux_aio_reconcile_head(ctx);
		/* Reserve one ring slot; completed events also consume capacity. */
		if (error == 0 && (ctx->dying ||
		    ctx->pending + ctx->completed >= ctx->nr - 1))
			error = EAGAIN;
		if (error != 0) {
			mtx_unlock(&ctx->mtx);
			linux_aio_req_free(req);
			break;
		}
		ctx->pending++;
		mtx_unlock(&ctx->mtx);
		/* Linux initializes aio_key before dispatch, and io_cancel reads it. */
		key = 0;
		error = copyout(&key, &user_cb->key, sizeof(key));
		if (error != 0) {
			mtx_lock(&ctx->mtx);
			ctx->pending--;
			mtx_unlock(&ctx->mtx);
			linux_aio_req_free(req);
			break;
		}
		/* Linux dispatches the opcode only after initializing aio_key. */
		if (req->iocb.opcode == LINUX_IOCB_CMD_POLL)
			error = linux_aio_poll_submit(ctx, req, user_cb);
		else {
			type = linux_aio_type(req->iocb.opcode);
			if (type < 0)
				error = EINVAL;
			else
				error = aio_compat_submit(td, user_cb, type,
				    linux_aio_copyin, linux_aio_done,
				    linux_aio_release, ctx, req);
		}
		if (error != 0) {
			mtx_lock(&ctx->mtx);
			KASSERT(ctx->pending > 0,
			    ("Linux AIO failed-submit underflow"));
			ctx->pending--;
			mtx_unlock(&ctx->mtx);
			linux_aio_req_free(req);
			break;
		}
		submitted++;
	}
	if (submitted != 0) {
		td->td_retval[0] = submitted;
		error = 0;
	}
out:
	sx_sunlock(&mm->sx);
	linux_aio_mm_put(mm, td);
	return (error);
}

static void
linux_aio_flush_overflow(struct linux_aio_ctx *ctx)
{
	struct linux_aio_event_node *node;
	uint32_t head, tail, next;

	mtx_assert(&ctx->mtx, MA_OWNED);
	while ((node = TAILQ_FIRST(&ctx->overflow)) != NULL) {
		head = atomic_load_acq_32(&ctx->ring->head);
		tail = atomic_load_acq_32(&ctx->ring->tail);
		if (head >= ctx->nr || tail >= ctx->nr)
			break;
		next = tail + 1 == ctx->nr ? 0 : tail + 1;
		if (next == head)
			break;
		TAILQ_REMOVE(&ctx->overflow, node, link);
		ctx->ring->events[tail] = node->event;
		atomic_store_rel_32(&ctx->ring->tail, next);
		ctx->ring_queued++;
		free(node, M_LINUX);
	}
}

int
linux_io_getevents(struct thread *td, struct linux_io_getevents_args *uap)
{
	struct linux_pemuldata *pem;
	struct linux_aio_mm *mm;
	struct linux_aio_ctx *ctx;
	struct l_aio_event event;
	struct l_timespec timeout;
	struct timeval tv;
	uint32_t head, tail;
	int error, copied, remaining, timo;
	uint32_t start_ticks, elapsed;
	__int128 timeout_ns;
	bool infinite_timeout, zero_timeout;

	if (uap->min_nr < 0 || uap->nr < 0 || uap->min_nr > uap->nr)
		return (EINVAL);
	timo = 0;
	infinite_timeout = uap->timeout == NULL;
	zero_timeout = false;
	if (uap->timeout != NULL) {
		error = copyin(uap->timeout, &timeout, sizeof(timeout));
		if (error != 0)
			return (error);
		/* Linux copies the raw timespec and converts it to ktime without
		 * requiring canonical seconds or nanoseconds.  A negative ktime
		 * waits until an event or signal; KTIME_MAX has no timer.
		 */
		timeout_ns = (__int128)timeout.tv_sec * 1000000000 +
		    timeout.tv_nsec;
		infinite_timeout = timeout_ns < 0 || timeout_ns >= INT64_MAX;
		zero_timeout = timeout_ns == 0;
		if (!infinite_timeout && !zero_timeout) {
			tv.tv_sec = timeout.tv_sec;
			tv.tv_usec = timeout.tv_nsec / 1000 +
			    (timeout.tv_nsec % 1000 > 0);
			timo = tvtohz(&tv);
		}
	}
	start_ticks = (uint32_t)ticks;
	pem = pem_find(td->td_proc);
	if (pem == NULL || (mm = linux_aio_mm_get(pem, false)) == NULL)
		return (EINVAL);
	sx_slock(&mm->sx);
	TAILQ_FOREACH(ctx, &mm->contexts, link)
		if (ctx->user_addr == uap->ctx)
			break;
	if (ctx == NULL) {
		error = EINVAL;
		goto out;
	}
	sx_xlock(&ctx->get_sx);
	copied = 0;
	error = 0;
	while (copied < uap->nr) {
		mtx_lock(&ctx->mtx);
		error = linux_aio_reconcile_head(ctx);
		if (error != 0) {
			mtx_unlock(&ctx->mtx);
			break;
		}
		linux_aio_flush_overflow(ctx);
		head = atomic_load_acq_32(&ctx->ring->head);
		tail = atomic_load_acq_32(&ctx->ring->tail);
		if (head >= ctx->nr || tail >= ctx->nr) {
			mtx_unlock(&ctx->mtx);
			error = EINVAL;
			break;
		}
		if (head == tail) {
			if (copied >= uap->min_nr || zero_timeout) {
				mtx_unlock(&ctx->mtx);
				break;
			}
			if (infinite_timeout)
				error = cv_wait_sig(&ctx->cv, &ctx->mtx);
			else {
				elapsed = (uint32_t)ticks - start_ticks;
				if (elapsed >= (uint32_t)timo) {
					mtx_unlock(&ctx->mtx);
					break;
				}
				remaining = timo - elapsed;
				error = cv_timedwait_sig(&ctx->cv, &ctx->mtx,
				    remaining);
			}
			mtx_unlock(&ctx->mtx);
			if (error != 0) {
				if (error == EWOULDBLOCK)
					error = 0;
				break;
			}
			continue;
		}
		event = ctx->ring->events[head];
		mtx_unlock(&ctx->mtx);
		error = copyout(&event, uap->events + copied, sizeof(event));
		if (error != 0)
			break;
		mtx_lock(&ctx->mtx);
		error = linux_aio_reconcile_head(ctx);
		if (error == 0 && ctx->seen_head == head) {
			if (ctx->ring_queued == 0 || ctx->completed == 0)
				error = EINVAL;
			else {
				ctx->seen_head = head + 1 == ctx->nr ? 0 : head + 1;
				atomic_store_rel_32(&ctx->ring->head,
				    ctx->seen_head);
				ctx->ring_queued--;
				ctx->completed--;
			}
		}
		if (error == 0)
			linux_aio_flush_overflow(ctx);
		mtx_unlock(&ctx->mtx);
		if (error != 0)
			break;
		copied++;
	}
	sx_xunlock(&ctx->get_sx);
	if (copied != 0) {
		td->td_retval[0] = copied;
		error = 0;
	}
out:
	sx_sunlock(&mm->sx);
	linux_aio_mm_put(mm, td);
	if (error == ERESTART)
		error = EINTR;
	return (error);
}

int
linux_io_cancel(struct thread *td, struct linux_io_cancel_args *uap)
{
	struct linux_pemuldata *pem;
	struct linux_aio_mm *mm;
	struct linux_aio_ctx *ctx;
	uint32_t key;
	int error, state;

	/* Linux checks the IOCB key before resolving the context. */
	error = copyin(&uap->iocb->key, &key, sizeof(key));
	if (error != 0)
		return (error);
	if (key != 0)
		return (EINVAL);
	pem = pem_find(td->td_proc);
	if (pem == NULL || (mm = linux_aio_mm_get(pem, false)) == NULL)
		return (EINVAL);
	sx_slock(&mm->sx);
	TAILQ_FOREACH(ctx, &mm->contexts, link)
		if (ctx->user_addr == uap->ctx)
			break;
	if (ctx == NULL)
		error = EINVAL;
	else {
		error = linux_aio_poll_cancel(ctx, uap->iocb);
		if (error == ENOENT) {
			error = aio_compat_cancel(td, ctx, uap->iocb, &state);
			if (error == 0) {
				switch (state) {
				case AIO_CANCELED: error = EINPROGRESS; break;
				case AIO_NOTCANCELED: error = EAGAIN; break;
				default: error = EINVAL; break;
				}
			}
		}
	}
	sx_sunlock(&mm->sx);
	linux_aio_mm_put(mm, td);
	return (error);
}

int
linux_io_pgetevents(struct thread *td, struct linux_io_pgetevents_args *uap)
{
	struct linux_io_getevents_args args;
	struct l_aio_sigset lsig;
	sigset_t mask;
	l_sigset_t lmask;
	bool masked;
	int error;

	/* Linux32 has a distinct compat timespec and no legacy AIO contexts yet. */
	if (SV_PROC_FLAG(td->td_proc, SV_ILP32))
		return (ENOSYS);
	masked = false;
	if (uap->sig != NULL) {
		error = copyin(uap->sig, &lsig, sizeof(lsig));
		if (error != 0)
			return (error);
		if (lsig.mask != 0) {
			if (lsig.size != sizeof(lmask))
				return (EINVAL);
			error = copyin((void *)(uintptr_t)lsig.mask,
			    &lmask, sizeof(lmask));
			if (error != 0)
				return (error);
			linux_to_bsd_sigset(&lmask, &mask);
			error = kern_sigprocmask(td, SIG_SETMASK, &mask,
			    &td->td_oldsigmask, 0);
			if (error != 0)
				return (error);
			masked = true;
			td->td_pflags |= TDP_OLDMASK;
		}
	}
	bzero(&args, sizeof(args));
	args.ctx = uap->ctx;
	args.min_nr = uap->min_nr;
	args.nr = uap->nr;
	args.events = uap->events;
	args.timeout = uap->timeout;
	error = linux_io_getevents(td, &args);
	/* Linux io_pgetevents does not restart after running a signal handler. */
	if (error == ERESTART)
		error = EINTR;
	/* A signal unblocked only by the temporary mask can remain pending
	 * when the completion wait reaches its timeout.  Linux reports that
	 * interrupted empty wait instead of a successful zero-event result.
	 */
	if (masked && error == 0 && td->td_retval[0] == 0 &&
	    SIGPENDING(td))
		error = EINTR;
	if (masked)
		ast_sched(td, error == EINTR || error == ERESTART ?
		    TDA_SIGSUSPEND : TDA_PSELECT);
	return (error);
}
