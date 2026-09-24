/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * squeue: the native 5BSD completion-ring engine.
 *
 * This is the ABI-neutral core of the io_uring-compatible ring: the shared
 * SQ/CQ/SQE rings (a wired managed object dual-mapped into the kernel and,
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
#include <sys/counter.h>
#include <sys/cpuset.h>
#include <sys/event.h>
#include <sys/eventfd.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/osd.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/racct.h>
#include <sys/resourcevar.h>
#include <sys/sched.h>
#include <sys/refcount.h>
#include <sys/rwlock.h>
#include <sys/sdt.h>
#include <sys/sysctl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sleepqueue.h>
#include <sys/smp.h>
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
#include <vm/vm_map.h>

#include <net/bpf.h>
#include <netinet/in.h>

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

#include <sys/io_uring.h>
#include <sys/squeue.h>

MALLOC_DEFINE(M_SQUEUE, "squeue", "5BSD completion-ring (squeue) engine");

struct sq_bpf_filter {
	struct sq_bpf_filter *next;
	uint32_t	ninsns;
	struct bpf_insn insns[];
};

struct sq_bpf_set {
	struct sq_bpf_filter *filters[IORING_OP_LAST];
	uint8_t deny[IORING_OP_LAST];
};

#define	SQ_BPF_MAXINSNS	4096
#define	SQ_MAX_REG_FILES	4096
#define	SQ_MAX_REG_BUFS	1024

/*
 * System-wide bound on the physical memory all squeue rings may wire, so a
 * process cannot exhaust wired memory by creating many/large rings.  Defaulted
 * to 1/8 of RAM at boot and tunable via kern.squeue.max_wired_pages.
 */
static u_long	sq_live_requests;
static u_long	sq_wired_pages;		/* currently wired by all rings */
static u_long	sq_max_wired_pages;	/* cap (0 = uninitialised) */

static SYSCTL_NODE(_kern, OID_AUTO, squeue, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "5BSD squeue completion-ring engine");
SYSCTL_ULONG(_kern_squeue, OID_AUTO, live_requests, CTLFLAG_RD,
    &sq_live_requests, 0, "Allocated squeue requests, including linked successors");
SYSCTL_ULONG(_kern_squeue, OID_AUTO, wired_pages, CTLFLAG_RD, &sq_wired_pages,
    0, "Physical pages currently wired by squeue rings");
SYSCTL_ULONG(_kern_squeue, OID_AUTO, max_wired_pages, CTLFLAG_RW,
    &sq_max_wired_pages, 0, "Maximum physical pages squeue rings may wire");

/* A task identity lives independently of reusable thread pointers and tids.
 * The OSD reference dies with the thread; each SINGLE_ISSUER ring holds one. */
struct sq_issuer { u_int refs; };
static int sq_issuer_slot;
static u_long sq_issuer_tokens, sq_issuer_refs;
SYSCTL_ULONG(_kern_squeue, OID_AUTO, issuer_tokens, CTLFLAG_RD,
    &sq_issuer_tokens, 0, "Live squeue task identities, including thread OSD");
SYSCTL_ULONG(_kern_squeue, OID_AUTO, issuer_refs, CTLFLAG_RD,
    &sq_issuer_refs, 0, "Task identity references held by squeue rings");

static void
sq_issuer_rele(void *arg)
{
	struct sq_issuer *id = arg;

	if (refcount_release(&id->refs)) {
		atomic_subtract_long(&sq_issuer_tokens, 1);
		free(id, M_SQUEUE);
	}
}

static void
sq_issuer_init(void *arg __unused)
{
	sq_issuer_slot = osd_thread_register(sq_issuer_rele);
}
SYSINIT(squeue_issuer, SI_SUB_KTHREAD_INIT, SI_ORDER_ANY, sq_issuer_init, NULL);

#define	SQ_RINGFD_REG_MAX	16
struct sq_ring_registry {
	struct task cleanup_task;
	struct file *files[SQ_RINGFD_REG_MAX];
};
static int sq_ring_registry_slot;

static void
sq_ring_registry_cleanup(void *arg, int pending __unused)
{
	struct sq_ring_registry *registry;
	u_int i;

	registry = arg;
	for (i = 0; i < SQ_RINGFD_REG_MAX; i++)
		if (registry->files[i] != NULL)
			fdrop(registry->files[i], curthread);
	free(registry, M_SQUEUE);
}

static void
sq_ring_registry_rele(void *arg)
{
	struct sq_ring_registry *registry;

	/* OSD destructors run under osd_object; file close paths may sleep. */
	registry = arg;
	taskqueue_enqueue(taskqueue_thread, &registry->cleanup_task);
}

static void
sq_ring_registry_init(void *arg __unused)
{

	sq_ring_registry_slot = osd_thread_register(sq_ring_registry_rele);
}
SYSINIT(squeue_ring_registry, SI_SUB_KTHREAD_INIT, SI_ORDER_ANY,
    sq_ring_registry_init, NULL);

static struct sq_ring_registry *
sq_ring_registry_get(struct thread *td, bool create)
{
	struct sq_ring_registry *registry;
	void **reserved;
	int error;

	registry = osd_thread_get(td, sq_ring_registry_slot);
	if (registry == NULL && create) {
		registry = malloc(sizeof(*registry), M_SQUEUE, M_WAITOK | M_ZERO);
		TASK_INIT(&registry->cleanup_task, 0, sq_ring_registry_cleanup,
		    registry);
		reserved = osd_reserve(sq_ring_registry_slot);
		error = osd_thread_set_reserved(td, sq_ring_registry_slot,
		    reserved, registry);
		if (__predict_false(error != 0))
			panic("cannot install squeue ring registry: %d", error);
	}
	return (registry);
}

static int
sq_ring_file_get(struct thread *td, uint32_t fd, bool registered,
    struct file **fpp)
{
	struct sq_ring_registry *registry;
	struct file *fp;
	int error;

	if (registered) {
		if (fd >= SQ_RINGFD_REG_MAX)
			return (EINVAL);
		registry = sq_ring_registry_get(td, false);
		if (registry == NULL || registry->files[fd] == NULL)
			return (EBADF);
		fp = registry->files[fd];
		MPASS(fhold(fp));
		error = 0;
	} else
		error = fget(td, (int)fd, &cap_no_rights, &fp);
	if (error != 0)
		return (error);
	if (fp->f_type != DTYPE_IORING) {
		fdrop(fp, td);
		return (EOPNOTSUPP);
	}
	*fpp = fp;
	return (0);
}

static struct sq_issuer *
sq_issuer_get(struct thread *td)
{
	struct sq_issuer *id;
	void **reserved;
	int error;

	MPASS(td == curthread);
	id = osd_thread_get(td, sq_issuer_slot);
	if (id == NULL) {
		id = malloc(sizeof(*id), M_SQUEUE, M_WAITOK);
		refcount_init(&id->refs, 1);
		reserved = osd_reserve(sq_issuer_slot);
		error = osd_thread_set_reserved(td, sq_issuer_slot, reserved, id);
		if (__predict_false(error != 0))
			panic("cannot install squeue issuer identity: %d", error);
		atomic_add_long(&sq_issuer_tokens, 1);
	}
	refcount_acquire(&id->refs);
	atomic_add_long(&sq_issuer_refs, 1);
	return (id);
}

/* Counts held table references, including unpublished registration prefixes. */
static u_long sq_registered_files;
SYSCTL_ULONG(_kern_squeue, OID_AUTO, registered_files, CTLFLAG_RD,
    &sq_registered_files, 0, "File references held by squeue registrations");

static int
sq_reg_file_get(struct thread *td, int fd, struct file **fpp,
    struct filecaps *caps)
{
	struct file *fp;
	int error;

	*fpp = NULL;
	error = fget_cap(td, fd, &cap_no_rights, NULL, &fp, caps);
	if (error != 0)
		return (error);
	/* Ring files would create self/cross-ring reference cycles. */
	if (fp->f_type == DTYPE_IORING) {
		fdrop(fp, td);
		filecaps_free(caps);
		filecaps_init(caps);
		return (EBADF);
	}
	*fpp = fp;
	atomic_add_long(&sq_registered_files, 1);
	return (0);
}

static void
sq_reg_file_drop(struct file *fp, struct filecaps *caps, struct thread *td)
{
	if (fp != NULL) {
		atomic_subtract_long(&sq_registered_files, 1);
		fdrop(fp, td);
	}
	filecaps_free(caps);
}

/* A tagged registered-file generation outlives removal while requests use it. */
struct sq_file_node {
	struct squeue_ctx *ctx;
	struct file *fp;
	struct filecaps caps;
	u_int refs;
	uint64_t tag;
};

static struct sq_file_node *
sq_file_node_alloc(struct squeue_ctx *ctx, struct thread *td, int fd,
    uint64_t tag, int *errorp)
{
	struct sq_file_node *node;

	node = malloc(sizeof(*node), M_SQUEUE, M_WAITOK | M_ZERO);
	filecaps_init(&node->caps);
	*errorp = sq_reg_file_get(td, fd, &node->fp, &node->caps);
	if (*errorp != 0) {
		free(node, M_SQUEUE);
		return (NULL);
	}
	node->ctx = ctx;
	node->tag = tag;
	refcount_init(&node->refs, 1); /* table reference */
	return (node);
}

static struct sq_file_node *
sq_file_node_adopt(struct squeue_ctx *ctx, struct file *fp,
    struct filecaps *caps, uint64_t tag)
{
	struct sq_file_node *node;

	node = malloc(sizeof(*node), M_SQUEUE, M_WAITOK | M_ZERO);
	node->ctx = ctx;
	node->fp = fp;
	node->caps = *caps;
	filecaps_init(caps);
	node->tag = tag;
	refcount_init(&node->refs, 1);
	atomic_add_long(&sq_registered_files, 1);
	return (node);
}

static struct sq_file_node *
sq_file_node_hold_locked(struct squeue_ctx *ctx, int idx)
{
	struct sq_file_node *node;

	sx_assert(&ctx->files_sx, SA_LOCKED);
	if (ctx->reg_files == NULL || idx < 0 ||
	    (uint32_t)idx >= ctx->reg_nfiles)
		return (NULL);
	node = ctx->reg_files[idx];
	if (node != NULL)
		refcount_acquire(&node->refs);
	return (node);
}

static void
sq_file_node_rele(struct sq_file_node *node, struct thread *td)
{
	struct squeue_ctx *ctx;

	if (node == NULL || !refcount_release(&node->refs))
		return;
	ctx = node->ctx;
	if (node->tag != 0) {
		mtx_lock(&ctx->mtx);
		sq_post_cqe(ctx, node->tag, 0, 0);
		sq_wake(ctx);
		mtx_unlock(&ctx->mtx);
	}
	sq_reg_file_drop(node->fp, &node->caps, td);
	free(node, M_SQUEUE);
}

static int
sq_close_direct_fd(struct squeue_ctx *ctx, struct thread *td,
    uint32_t file_index)
{
	struct sq_file_node *node;
	uint32_t slot;
	int error;

	node = NULL;
	sx_xlock(&ctx->files_sx);
	if (ctx->reg_files == NULL) {
		error = ENXIO;
	} else if (file_index == 0 || file_index - 1 >= ctx->reg_nfiles) {
		error = EINVAL;
	} else {
		slot = file_index - 1;
		node = ctx->reg_files[slot];
		if (node == NULL) {
			error = EBADF;
		} else {
			ctx->reg_files[slot] = NULL;
			ctx->file_alloc_hint = slot;
			error = 0;
		}
	}
	sx_xunlock(&ctx->files_sx);
	sq_file_node_rele(node, td);
	return (error);
}

static void
sq_wired_init(void *dummy __unused)
{

	if (sq_max_wired_pages == 0)
		sq_max_wired_pages = vm_cnt.v_page_count / 8;
}
SYSINIT(squeue_wired, SI_SUB_KMEM, SI_ORDER_ANY, sq_wired_init, NULL);

/*
 * Registered buffers own physical pages, not live userspace mappings.  A
 * detached table remains alive until its last issued request is destroyed.
 * Quotas count page references (including overlapping registrations) against
 * both the system cap and the registering real uid's aggregate MEMLOCK limit.
 * The account holds uidinfo, so exit/setuid cannot change the charge owner.
 */
struct sq_buf_account {
	LIST_ENTRY(sq_buf_account) link;
	struct uidinfo *uid;
	u_long pages;
};
static LIST_HEAD(, sq_buf_account) sq_buf_accounts =
    LIST_HEAD_INITIALIZER(sq_buf_accounts);
static struct mtx sq_buf_account_mtx;
MTX_SYSINIT(sq_buf_account, &sq_buf_account_mtx, "squeue buffers", MTX_DEF);

struct sq_buf {
	uintptr_t base;
	size_t len;
	char *kva;
	vm_page_t *pages;
	int npages;
	struct vm_map_pin *pin;
};
struct sq_buf_backing {
	struct sq_buf buf;
	u_int refs;
	u_long charged;
	struct sq_buf_account *account;
	struct vmspace *vm;
};
struct sq_buf_node {
	struct squeue_ctx *ctx;
	struct sq_buf_backing *backing;
	u_int refs;
	uint64_t tag;
};
struct sq_buf_table {
	u_int refs;
	uint32_t count;
	struct sq_buf_node *nodes[];
};
static struct sx sq_register_global_sx;
SX_SYSINIT(squeue_register_global, &sq_register_global_sx,
    "squeue register global");

struct sq_personality {
	LIST_ENTRY(sq_personality) link;
	struct ucred *cred;
	uint16_t id;
};

static int
sq_buf_charge(struct sq_buf_backing *backing, u_long pages, struct thread *td)
{
	struct sq_buf_account *a, *fresh;
	u_long limit, old;

	if (pages == 0)
		return (0);
	limit = lim_cur(td, RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	fresh = malloc(sizeof(*fresh), M_SQUEUE, M_WAITOK | M_ZERO);
	mtx_lock(&sq_buf_account_mtx);
	LIST_FOREACH(a, &sq_buf_accounts, link)
		if (a->uid == td->td_ucred->cr_ruidinfo)
			break;
	if (a == NULL) {
		a = fresh;
		fresh = NULL;
		a->uid = td->td_ucred->cr_ruidinfo;
		uihold(a->uid);
		LIST_INSERT_HEAD(&sq_buf_accounts, a, link);
	}
	/* Even privileged callers obey an explicitly lowered resource limit. */
	if (pages > limit || a->pages > limit - pages)
		goto fail;
	old = atomic_load_long(&sq_wired_pages);
	for (;;) {
		if (pages > sq_max_wired_pages || old > sq_max_wired_pages - pages)
			goto fail;
		if (atomic_fcmpset_long(&sq_wired_pages, &old, old + pages))
			break;
	}
	a->pages += pages;
	backing->account = a;
	backing->charged = pages;
	mtx_unlock(&sq_buf_account_mtx);
	free(fresh, M_SQUEUE);
	return (0);
fail:
	if (a->pages == 0) {
		LIST_REMOVE(a, link);
	} else
		a = NULL;
	mtx_unlock(&sq_buf_account_mtx);
	if (a != NULL) {
		uifree(a->uid);
		free(a, M_SQUEUE);
	}
	free(fresh, M_SQUEUE);
	return (ENOMEM);
}

static void
sq_buf_backing_rele(struct sq_buf_backing *backing)
{
	struct sq_buf_account *a;
	struct sq_buf *b;

	if (backing == NULL || !refcount_release(&backing->refs))
		return;
	b = &backing->buf;
	if (b->kva != 0) {
		pmap_qremove(b->kva, b->npages);
		kva_free(b->kva, ptoa((vm_size_t)b->npages));
	}
	if (b->pin != NULL)
		vm_map_unpin_pages(&backing->vm->vm_map, b->pin);
	free(b->pages, M_SQUEUE);
	if ((a = backing->account) != NULL) {
		atomic_subtract_long(&sq_wired_pages, backing->charged);
		mtx_lock(&sq_buf_account_mtx);
		KASSERT(a->pages >= backing->charged, ("squeue buffer charge"));
		a->pages -= backing->charged;
		if (a->pages == 0)
			LIST_REMOVE(a, link);
		else
			a = NULL;
		mtx_unlock(&sq_buf_account_mtx);
		if (a != NULL) {
			uifree(a->uid);
			free(a, M_SQUEUE);
		}
	}
	if (backing->vm != NULL)
		vmspace_free(backing->vm);
	free(backing, M_SQUEUE);
}

static void
sq_buf_node_rele(struct sq_buf_node *node)
{
	struct squeue_ctx *ctx;

	if (node == NULL || !refcount_release(&node->refs))
		return;
	ctx = node->ctx;
	if (node->tag != 0 && ctx != NULL) {
		mtx_lock(&ctx->mtx);
		sq_post_cqe(ctx, node->tag, 0, 0);
		sq_wake(ctx);
		mtx_unlock(&ctx->mtx);
	}
	sq_buf_backing_rele(node->backing);
	free(node, M_SQUEUE);
}

static struct sq_buf_node *
sq_buf_node_clone(struct squeue_ctx *ctx, struct sq_buf_node *source)
{
	struct sq_buf_node *node;

	if (source == NULL)
		return (NULL);
	node = malloc(sizeof(*node), M_SQUEUE, M_WAITOK | M_ZERO);
	node->ctx = ctx;
	node->backing = source->backing;
	refcount_acquire(&node->backing->refs);
	refcount_init(&node->refs, 1);
	return (node);
}

static struct sq_buf_node *
sq_buf_node_alloc(struct squeue_ctx *ctx, const struct iovec *iov, uint64_t tag,
    struct thread *td, int *errorp)
{
	struct sq_buf_backing *backing;
	struct sq_buf_node *node;
	struct sq_buf *b;
	uintptr_t base;
	size_t len;
	int i, npages;

	base = (uintptr_t)iov->iov_base;
	len = iov->iov_len;
	if (base == 0 && len == 0) {
		*errorp = tag != 0 ? EINVAL : 0;
		return (NULL);
	}
	if (base == 0 || len == 0 || len > (1UL << 30)) {
		*errorp = EFAULT;
		return (NULL);
	}
	if (base > UINTPTR_MAX - round_page(len) ||
	    base + len > UINTPTR_MAX - PAGE_MASK) {
		*errorp = EOVERFLOW;
		return (NULL);
	}
	backing = malloc(sizeof(*backing), M_SQUEUE, M_WAITOK | M_ZERO);
	refcount_init(&backing->refs, 1);
	backing->vm = vmspace_acquire_ref(td->td_proc);
	b = &backing->buf;
	b->base = base;
	b->len = len;
	npages = atop(round_page(base + len) - trunc_page(base));
	*errorp = sq_buf_charge(backing, npages, td);
	if (*errorp != 0)
		goto fail;
	b->pages = mallocarray(npages, sizeof(*b->pages), M_SQUEUE,
	    M_WAITOK | M_ZERO);
	*errorp = vm_map_pin_pages(&backing->vm->vm_map, base, len, b->pages,
	    npages, &b->pin);
	if (*errorp != 0) {
		*errorp = EFAULT;
		goto fail;
	}
	b->npages = npages;
	for (i = 0; i < npages; i++)
		if ((b->pages[i]->oflags & VPO_UNMANAGED) != 0) {
			*errorp = EFAULT;
			goto fail;
		}
	b->kva = kva_alloc(ptoa((vm_size_t)npages));
	if (b->kva == 0) {
		*errorp = ENOMEM;
		goto fail;
	}
	pmap_qenter(b->kva, b->pages, npages);
	node = malloc(sizeof(*node), M_SQUEUE, M_WAITOK | M_ZERO);
	node->ctx = ctx;
	node->backing = backing;
	node->tag = tag;
	refcount_init(&node->refs, 1);
	*errorp = 0;
	return (node);
fail:
	sq_buf_backing_rele(backing);
	return (NULL);
}

/* Pin a parameter region in its owner's vmspace for registered waits. */
static struct sq_buf_backing *
sq_param_region_pin(uintptr_t addr, vm_size_t size, struct thread *td,
    int *errorp)
{
	struct sq_buf_backing *backing;
	struct sq_buf *b;
	int i, npages;

	backing = malloc(sizeof(*backing), M_SQUEUE, M_WAITOK | M_ZERO);
	refcount_init(&backing->refs, 1);
	backing->vm = vmspace_acquire_ref(td->td_proc);
	b = &backing->buf;
	b->base = addr;
	b->len = size;
	npages = atop(size);
	*errorp = sq_buf_charge(backing, npages, td);
	if (*errorp != 0)
		goto fail;
	b->pages = mallocarray(npages, sizeof(*b->pages), M_SQUEUE,
	    M_WAITOK | M_ZERO);
	*errorp = vm_map_pin_pages(&backing->vm->vm_map, addr, size,
	    b->pages, npages, &b->pin);
	if (*errorp != 0) {
		*errorp = EFAULT;
		goto fail;
	}
	b->npages = npages;
	for (i = 0; i < npages; i++)
		if ((b->pages[i]->oflags & VPO_UNMANAGED) != 0) {
			*errorp = EFAULT;
			goto fail;
		}
	b->kva = (char *)kva_alloc(size);
	if (b->kva == NULL) {
		*errorp = ENOMEM;
		goto fail;
	}
	pmap_qenter(b->kva, b->pages, npages);
	*errorp = 0;
	return (backing);
fail:
	sq_buf_backing_rele(backing);
	return (NULL);
}

static void
sq_buf_table_rele(struct sq_buf_table *table)
{
	uint32_t i;

	if (table == NULL || !refcount_release(&table->refs))
		return;
	for (i = 0; i < table->count; i++)
		sq_buf_node_rele(table->nodes[i]);
	free(table, M_SQUEUE);
}

/*
 * Observability.  A DTrace provider ("squeue") with probes on the hot events,
 * plus cumulative counters exported read-only under kern.squeue for at-a-glance
 * monitoring without DTrace.
 */
SDT_PROVIDER_DEFINE(squeue);
SDT_PROBE_DEFINE3(squeue, , , setup, "int" /*fd*/, "u_int" /*entries*/,
    "pid_t");
SDT_PROBE_DEFINE3(squeue, , , submit, "void *" /*ctx*/, "uint8_t" /*opcode*/,
    "uint64_t" /*user_data*/);
SDT_PROBE_DEFINE4(squeue, , , complete, "void *" /*ctx*/,
    "uint64_t" /*user_data*/, "int32_t" /*res*/, "uint32_t" /*cflags*/);
SDT_PROBE_DEFINE1(squeue, , , overflow, "void *" /*ctx*/);
/*
 * Async lifecycle probes, for tracing the worker-pool / ready-list / waiter
 * flow where completion-delivery races live (a submitted async op must reach
 * offload -> ready -> complete, and a blocked waiter must be woken):
 *   offload  a request was handed to the worker pool
 *   ready    a worker resolved an async op and put it on the ready list
 *   wait     a thread in squeue_enter is about to sleep for completions
 *   wakeup   a completion signalled the ring (nwaiters = threads then blocked)
 * Pair ready with complete (same user_data) to spot a stranded completion, and
 * wait with wakeup to spot a waiter that slept with work already pending.
 */
SDT_PROBE_DEFINE3(squeue, , , offload, "void *" /*ctx*/, "uint64_t" /*ud*/,
    "uint8_t" /*opcode*/);
SDT_PROBE_DEFINE3(squeue, , , ready, "void *" /*ctx*/, "uint64_t" /*ud*/,
    "int32_t" /*res*/);
SDT_PROBE_DEFINE2(squeue, , , wait, "void *" /*ctx*/, "uint32_t" /*min*/);
SDT_PROBE_DEFINE2(squeue, , , wakeup, "void *" /*ctx*/, "int" /*nwaiters*/);

static counter_u64_t sq_stat_rings;	/* rings created */
static counter_u64_t sq_stat_submitted;	/* SQEs consumed */
static counter_u64_t sq_stat_completed;	/* CQEs posted */
static counter_u64_t sq_stat_overflowed;/* completions backlogged or dropped */

SYSCTL_COUNTER_U64(_kern_squeue, OID_AUTO, rings, CTLFLAG_RD, &sq_stat_rings,
    "Rings created since boot");
SYSCTL_COUNTER_U64(_kern_squeue, OID_AUTO, submitted, CTLFLAG_RD,
    &sq_stat_submitted, "Submission entries consumed since boot");
SYSCTL_COUNTER_U64(_kern_squeue, OID_AUTO, completed, CTLFLAG_RD,
    &sq_stat_completed, "Completion entries posted since boot");
SYSCTL_COUNTER_U64(_kern_squeue, OID_AUTO, overflowed, CTLFLAG_RD,
    &sq_stat_overflowed, "Completions backlogged or dropped on a full CQ");

static void
sq_stat_init(void *dummy __unused)
{

	sq_stat_rings = counter_u64_alloc(M_WAITOK);
	sq_stat_submitted = counter_u64_alloc(M_WAITOK);
	sq_stat_completed = counter_u64_alloc(M_WAITOK);
	sq_stat_overflowed = counter_u64_alloc(M_WAITOK);
}
SYSINIT(squeue_stat, SI_SUB_KMEM, SI_ORDER_ANY, sq_stat_init, NULL);

/* ---- core opcode advertisement; front ends contribute their extensions ---- */
static bool
sq_op_supported(struct squeue_ctx *ctx, uint8_t op)
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
	case IORING_OP_PROVIDE_BUFFERS:
	case IORING_OP_REMOVE_BUFFERS:
	case IORING_OP_FILES_UPDATE:
	case IORING_OP_MSG_RING:
	case IORING_OP_READV_FIXED:
	case IORING_OP_WRITEV_FIXED:
	case IORING_OP_NOP128:
	case IORING_OP_FIXED_FD_INSTALL:
	case IORING_OP_LINK_TIMEOUT:
	case IORING_OP_POLL_ADD:
	case IORING_OP_POLL_REMOVE:
		return (true);
	default:
		return (ctx->issue_ext != NULL && ctx->op_supported != NULL &&
		    ctx->op_supported(op));
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
	case IORING_OP_READ_FIXED:
	case IORING_OP_READV_FIXED:
	case IORING_OP_RECV:
	case IORING_OP_RECVMSG:
	case IORING_OP_READ_MULTISHOT:
	case IORING_OP_RECV_ZC:
	case IORING_OP_ACCEPT:
	case IORING_OP_EPOLL_WAIT:
		return (POLLIN);
	case IORING_OP_WRITE:
	case IORING_OP_WRITEV:
	case IORING_OP_WRITE_FIXED:
	case IORING_OP_WRITEV_FIXED:
	case IORING_OP_SEND:
	case IORING_OP_SENDMSG:
	case IORING_OP_SEND_ZC:
	case IORING_OP_SENDMSG_ZC:
		return (POLLOUT);
	default:
		return (0);
	}
}

/* Retry readiness is derived from the opcode: never overwrite the SQE union
 * containing the original read/write or socket flags. */
static short
sq_request_poll_events(const struct sq_req *req)
{

	return (req->opcode == IORING_OP_POLL_ADD ?
	    (short)req->sqe.poll32_events : sq_pollable_events(req->opcode));
}

/* ---- ring backing store: a wired, managed object, dual-mapped ---- */
static int
sq_ring_alloc(struct squeue_ctx *ctx)
{
	vm_page_t *ma;
	vm_size_t cqes_off, array_off;
	int i, npages;

	/* Region 0: header, then cqes[cq_entries], then sq array[sq_entries]. */
	cqes_off = roundup2(sizeof(struct sq_rings), sizeof(struct io_uring_cqe));
	array_off = cqes_off + (vm_size_t)ctx->cq_entries * ctx->cqe_stride;
	ctx->ring_region = round_page(array_off +
	    ((ctx->setup_flags & IORING_SETUP_NO_SQARRAY) != 0 ? 0 :
	    (vm_size_t)ctx->sq_entries * sizeof(uint32_t)));
	ctx->sqes_off = ctx->ring_region;
	ctx->sqes_size = round_page((vm_size_t)ctx->sq_entries *
	    ctx->sqe_stride);
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

	ctx->obj = vm_object_allocate(OBJT_SWAP, npages);
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
	ctx->sq_array = (ctx->setup_flags & IORING_SETUP_NO_SQARRAY) != 0 ?
	    NULL : (uint32_t *)(ctx->kva + array_off);
	ctx->sqes = (struct io_uring_sqe *)(ctx->kva + ctx->sqes_off);

	ctx->rings->sq_ring_mask = ctx->sq_mask = ctx->sq_entries - 1;
	ctx->rings->cq_ring_mask = ctx->cq_mask = ctx->cq_entries - 1;
	ctx->rings->sq_ring_entries = ctx->sq_entries;
	ctx->rings->cq_ring_entries = ctx->cq_entries;
	return (0);
}

/*
 * NO_MMAP uses two caller-owned, pinned regions.  The kernel maps the same
 * pages through sq_buf_backing so userspace and the worker pool see one ring.
 */
static int
sq_ring_alloc_user(struct squeue_ctx *ctx, struct io_uring_params *p,
    struct thread *td)
{
	struct sq_buf_backing *ring, *sqes;
	vm_size_t cqes_off, array_off;
	uintptr_t ring_addr, sqes_addr;
	int error;

	cqes_off = roundup2(sizeof(struct sq_rings),
	    sizeof(struct io_uring_cqe));
	array_off = cqes_off + (vm_size_t)ctx->cq_entries * ctx->cqe_stride;
	ctx->ring_region = round_page(array_off +
	    ((ctx->setup_flags & IORING_SETUP_NO_SQARRAY) != 0 ? 0 :
	    (vm_size_t)ctx->sq_entries * sizeof(uint32_t)));
	ctx->sqes_size = round_page((vm_size_t)ctx->sq_entries *
	    ctx->sqe_stride);
	ctx->sqes_off = ctx->ring_region;
	ctx->objsize = ctx->ring_region + ctx->sqes_size;
	ring_addr = (uintptr_t)p->cq_off.user_addr;
	sqes_addr = (uintptr_t)p->sq_off.user_addr;
	if (ring_addr == 0 || sqes_addr == 0)
		return (EFAULT);
	if (((ring_addr | sqes_addr) & PAGE_MASK) != 0)
		return (EINVAL);
	if (ring_addr > UINTPTR_MAX - ctx->ring_region ||
	    sqes_addr > UINTPTR_MAX - ctx->sqes_size)
		return (EOVERFLOW);
	ring = sq_param_region_pin(ring_addr, ctx->ring_region, td, &error);
	if (error != 0)
		return (error);
	sqes = sq_param_region_pin(sqes_addr, ctx->sqes_size, td, &error);
	if (error != 0) {
		sq_buf_backing_rele(ring);
		return (error);
	}
	ctx->ring_user = ring;
	ctx->sqes_user = sqes;
	ctx->kva = ring->buf.kva;
	ctx->rings = (struct sq_rings *)ctx->kva;
	ctx->cqes = (struct io_uring_cqe *)(ctx->kva + cqes_off);
	ctx->sq_array = (ctx->setup_flags & IORING_SETUP_NO_SQARRAY) != 0 ?
	    NULL : (uint32_t *)(ctx->kva + array_off);
	ctx->sqes = (struct io_uring_sqe *)sqes->buf.kva;
	/* The caller owns the memory; reset only the ring control fields. */
	bzero(ctx->rings, sizeof(*ctx->rings));
	ctx->rings->sq_ring_mask = ctx->sq_mask = ctx->sq_entries - 1;
	ctx->rings->cq_ring_mask = ctx->cq_mask = ctx->cq_entries - 1;
	ctx->rings->sq_ring_entries = ctx->sq_entries;
	ctx->rings->cq_ring_entries = ctx->cq_entries;
	return (0);
}

static void
sq_ring_backing_free(vm_object_t obj, char *kva, vm_size_t size)
{
	vm_page_t m;
	vm_pindex_t i;

	if (obj == NULL)
		return;
	if (kva != NULL) {
		pmap_qremove(kva, atop(size));
		kva_free(kva, size);
	}
	VM_OBJECT_WLOCK(obj);
	for (i = 0; i < atop(size); i++) {
		m = vm_page_lookup(obj, i);
		if (m != NULL)
			vm_page_unwire(m, PQ_ACTIVE);
	}
	VM_OBJECT_WUNLOCK(obj);
	atomic_subtract_long(&sq_wired_pages, atop(size));
	vm_object_deallocate(obj);
}

/* Separate managed backing for a mmap-capable parameter region. */
static int
sq_param_region_alloc(vm_size_t size, struct thread *td, vm_object_t *objp,
    char **kvap)
{
	vm_object_t obj;
	vm_page_t *pages;
	char *kva;
	vm_pindex_t i, npages;
	u_long old;

	*objp = NULL;
	*kvap = NULL;
	npages = atop(size);
	if (size > lim_cur(td, RLIMIT_MEMLOCK) &&
	    priv_check(td, PRIV_VM_MLOCK) != 0)
		return (ENOMEM);
	old = atomic_load_long(&sq_wired_pages);
	for (;;) {
		if (npages > sq_max_wired_pages ||
		    old > sq_max_wired_pages - npages)
			return (ENOMEM);
		if (atomic_fcmpset_long(&sq_wired_pages, &old, old + npages))
			break;
	}
	obj = vm_object_allocate(OBJT_SWAP, npages);
	if (obj == NULL) {
		atomic_subtract_long(&sq_wired_pages, npages);
		return (ENOMEM);
	}
	kva = (char *)kva_alloc(size);
	if (kva == NULL) {
		sq_ring_backing_free(obj, NULL, size);
		return (ENOMEM);
	}
	pages = mallocarray(npages, sizeof(*pages), M_SQUEUE, M_WAITOK);
	VM_OBJECT_WLOCK(obj);
	for (i = 0; i < npages; i++) {
		pages[i] = vm_page_grab(obj, i, VM_ALLOC_NORMAL |
		    VM_ALLOC_WIRED | VM_ALLOC_ZERO);
		vm_page_valid(pages[i]);
		vm_page_xunbusy(pages[i]);
	}
	VM_OBJECT_WUNLOCK(obj);
	pmap_qenter(kva, pages, npages);
	free(pages, M_SQUEUE);
	*objp = obj;
	*kvap = kva;
	return (0);
}

struct sq_zcrx_rq_hdr {
	volatile uint32_t head;
	volatile uint32_t tail;
};

struct sq_zcrx_rqe {
	uint64_t off;
	uint32_t len;
	uint32_t pad;
};

struct sq_zcrx {
	TAILQ_ENTRY(sq_zcrx) entry;
	uint32_t id;
	uint32_t rq_entries;
	uint32_t rq_mask;
	uint32_t cached_head;
	vm_object_t rq_obj;
	struct sq_buf_backing *rq_user;
	char *rq_kva;
	vm_size_t rq_size;
	struct sq_zcrx_rq_hdr *rq;
	struct sq_zcrx_rqe *rqes;
	struct sq_buf_backing *area;
	uint32_t nchunks;
	uint32_t alloc_hint;
	bool *busy;
};

static struct sq_zcrx *
sq_zcrx_find(struct squeue_ctx *ctx, uint32_t id)
{
	struct sq_zcrx *z;

	TAILQ_FOREACH(z, &ctx->zcrx, entry)
		if (z->id == id)
			return (z);
	return (NULL);
}

static void
sq_zcrx_free(struct sq_zcrx *z)
{

	if (z == NULL)
		return;
	sq_ring_backing_free(z->rq_obj,
	    z->rq_obj != NULL ? z->rq_kva : NULL, z->rq_size);
	sq_buf_backing_rele(z->rq_user);
	sq_buf_backing_rele(z->area);
	free(z->busy, M_SQUEUE);
	free(z, M_SQUEUE);
}

static void
sq_zcrx_refill_locked(struct sq_zcrx *z, bool stop_invalid)
{
	struct sq_zcrx_rqe *rqe;
	uint64_t off;
	uint32_t entries, idx;

	entries = atomic_load_acq_32(&z->rq->tail) - z->cached_head;
	entries = MIN(entries, z->rq_entries);
	while (entries-- != 0) {
		rqe = &z->rqes[z->cached_head++ & z->rq_mask];
		off = atomic_load_acq_64(&rqe->off);
		if (rqe->pad != 0 || (off >> 48) != 0) {
			if (stop_invalid)
				break;
			continue;
		}
		idx = (uint32_t)(off >> PAGE_SHIFT);
		if (idx >= z->nchunks) {
			if (stop_invalid)
				break;
			continue;
		}
		if (z->busy[idx])
			z->busy[idx] = false;
	}
	atomic_store_rel_32(&z->rq->head, z->cached_head);
}

bool
sq_zcrx_exists(struct squeue_ctx *ctx, uint32_t id)
{
	bool found;

	mtx_lock(&ctx->mtx);
	found = sq_zcrx_find(ctx, id) != NULL;
	mtx_unlock(&ctx->mtx);
	return (found);
}

int
sq_zcrx_refill(struct squeue_ctx *ctx, uint32_t id)
{
	struct sq_zcrx *z;

	mtx_lock(&ctx->mtx);
	z = sq_zcrx_find(ctx, id);
	if (z != NULL)
		sq_zcrx_refill_locked(z, true);
	mtx_unlock(&ctx->mtx);
	return (z == NULL ? ENOENT : 0);
}

int
sq_zcrx_register_nodev(struct squeue_ctx *ctx, struct sq_zcrx_reg *reg,
    struct thread *td, sq_zcrx_publish_t publish, void *cookie)
{
	struct sq_zcrx *z;
	vm_map_t map;
	vm_size_t need;
	uint32_t entries, id;
	bool writable;
	int error;

	if (reg->area_addr == 0 || reg->area_len == 0 ||
	    ((reg->area_addr | reg->area_len) & PAGE_MASK) != 0 ||
	    reg->area_addr > UINTPTR_MAX - reg->area_len ||
	    reg->area_len / PAGE_SIZE > UINT32_MAX)
		return (EINVAL);
	if (reg->rq_entries == 0 || reg->rq_entries > SQ_MAX_ENTRIES)
		return (EINVAL);
	entries = 1U << flsl(reg->rq_entries - 1);
	if (entries < reg->rq_entries)
		entries <<= 1;
	need = round_page(64 + (vm_size_t)entries * sizeof(struct sq_zcrx_rqe));
	if (reg->rq_size < need || (reg->rq_size & PAGE_MASK) != 0)
		return (EINVAL);
	if (reg->rq_user && (reg->rq_addr == 0 ||
	    (reg->rq_addr & PAGE_MASK) != 0 ||
	    reg->rq_addr > UINTPTR_MAX - reg->rq_size))
		return (EINVAL);

	map = &td->td_proc->p_vmspace->vm_map;
	vm_map_lock_read(map);
	writable = vm_map_check_protection(map, reg->area_addr,
	    reg->area_addr + reg->area_len, VM_PROT_WRITE) &&
	    (!reg->rq_user || vm_map_check_protection(map, reg->rq_addr,
	    reg->rq_addr + reg->rq_size, VM_PROT_WRITE));
	vm_map_unlock_read(map);
	if (!writable)
		return (EFAULT);

	z = malloc(sizeof(*z), M_SQUEUE, M_WAITOK | M_ZERO);
	z->rq_entries = entries;
	z->rq_mask = entries - 1;
	z->rq_size = (vm_size_t)reg->rq_size;
	z->nchunks = (uint32_t)(reg->area_len >> PAGE_SHIFT);
	z->busy = mallocarray(z->nchunks, sizeof(*z->busy), M_SQUEUE,
	    M_WAITOK | M_ZERO);
	z->area = sq_param_region_pin(reg->area_addr,
	    (vm_size_t)reg->area_len, td, &error);
	if (error != 0)
		goto fail;
	if (reg->rq_user) {
		z->rq_user = sq_param_region_pin(reg->rq_addr, z->rq_size,
		    td, &error);
		if (error != 0)
			goto fail;
		z->rq_kva = z->rq_user->buf.kva;
	} else {
		error = sq_param_region_alloc(z->rq_size, td, &z->rq_obj,
		    &z->rq_kva);
		if (error != 0)
			goto fail;
	}
	z->rq = (struct sq_zcrx_rq_hdr *)z->rq_kva;
	z->rqes = (struct sq_zcrx_rqe *)(z->rq_kva + 64);
	bzero(z->rq_kva, z->rq_size);

	mtx_lock(&ctx->mtx);
	id = ctx->zcrx_next_id++;
	if (id >= 0x7fffffffU || sq_zcrx_find(ctx, id) != NULL) {
		mtx_unlock(&ctx->mtx);
		error = ENOSPC;
		goto fail;
	}
	z->id = id;
	mtx_unlock(&ctx->mtx);

	reg->id = id;
	reg->rq_entries = entries;
	reg->rx_buf_len = PAGE_SIZE;
	reg->head_off = offsetof(struct sq_zcrx_rq_hdr, head);
	reg->tail_off = offsetof(struct sq_zcrx_rq_hdr, tail);
	reg->rqes_off = 64;
	reg->mmap_offset = reg->rq_user ? 0 : IORING_MAP_OFF_ZCRX_REGION +
	    ((uint64_t)id << IORING_OFF_ZCRX_SHIFT);
	error = publish(cookie, reg);
	if (error != 0)
		goto fail;
	mtx_lock(&ctx->mtx);
	TAILQ_INSERT_TAIL(&ctx->zcrx, z, entry);
	mtx_unlock(&ctx->mtx);
	return (0);
fail:
	sq_zcrx_free(z);
	return (error);
}

struct sq_pbuf_ring {
	TAILQ_ENTRY(sq_pbuf_ring) entry;
	uint16_t bgid;
	uint32_t entries;
	uint32_t mask;
	uint32_t head;
	uint32_t busy;
	uint32_t min_left_sub_one;
	bool mmap_ring;
	bool incremental;
	vm_object_t obj;
	void *kva;
	vm_size_t size;
	struct sq_buf_table *table;
	struct io_uring_buf_ring *ring;
};


static void sq_pbuf_ring_free(struct sq_pbuf_ring *r);
static bool sq_pbuf_group_exists(struct squeue_ctx *ctx, uint16_t bgid);
static void sq_req_free(struct sq_req *req);
static void sq_finish_link(struct sq_req *req);
static void sq_unissue(struct sq_req *req);
static int sq_cancel_req(struct sq_req *req);
static void sq_link_timeout_cb(void *arg);
static void sq_timeout_cb(void *arg);
static void sq_ctx_rele(struct squeue_ctx *ctx);
static void sq_run_ready(struct squeue_ctx *ctx, struct thread *td);
static const struct fileops squeue_poll_fileops;
static struct ucred *sq_personality_get(struct squeue_ctx *ctx, uint16_t id);
static void sq_kq_wake_task(void *arg, int pending);
static int sq_kq_arm(struct squeue_ctx *ctx, struct sq_req *req,
    struct thread *td);
static int sq_poll_remove_update(struct squeue_ctx *ctx,
    struct sq_req *update, struct thread *td);
static int sq_timeout_remove_update(struct squeue_ctx *ctx,
    struct sq_req *update);
static void sq_kq_del(struct squeue_ctx *ctx, int fd, short filter,
    struct thread *td);
static void sq_kq_del_req(struct sq_req *req, struct thread *td);
static short sq_kq_filter(const struct sq_req *req);

static void
sq_free_chain(struct sq_req *req)
{
	struct sq_req *next;

	while (req != NULL) {
		next = req->link_next;
		if (req->link_timeout != NULL)
			sq_req_free(req->link_timeout);
		sq_req_free(req);
		req = next;
	}
}

static void sq_ctx_rele(struct squeue_ctx *);

static void
sq_ctx_free(struct squeue_ctx *ctx)
{
	struct sq_req *req;
	struct file *kqfp;
	struct sq_bpf_filter *filter, *next_filter;
	struct squeue_ctx *poll_root, *worker_root;
	uint32_t i;

	/* No references remain.  Stop publishing wake tasks, drain any
	 * running task, and drop the private readiness queue before requests. */
	mtx_lock(&ctx->mtx);
	kqfp = ctx->kqfp;
	ctx->kqfp = NULL;
	mtx_unlock(&ctx->mtx);
	taskqueue_drain(taskqueue_thread, &ctx->kq_wake_task);
	if (kqfp != NULL)
		fdrop(kqfp, curthread);
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

		TAILQ_INIT(&lpending);
		TAILQ_INIT(&lready);
		TAILQ_INIT(&lpolls);
		TAILQ_INIT(&ldrain);
		mtx_lock(&ctx->mtx);
		TAILQ_FOREACH(req, &ctx->pending, entry) {
			req->state = SQ_ST_READY;
			if (req->link_target != NULL) {
				req->link_target->link_timeout = NULL;
				req->link_target = NULL;
			}
		}
		TAILQ_CONCAT(&lpending, &ctx->pending, entry);
		TAILQ_CONCAT(&lready, &ctx->ready, entry);
		TAILQ_CONCAT(&lpolls, &ctx->polls, entry);
		TAILQ_CONCAT(&ldrain, &ctx->drain, entry);
		ctx->npending = 0;
		ctx->npolls = 0;
		mtx_unlock(&ctx->mtx);

		while ((req = TAILQ_FIRST(&lpending)) != NULL) {
			TAILQ_REMOVE(&lpending, req, entry);
			sq_free_chain(req);
		}
		while ((req = TAILQ_FIRST(&lready)) != NULL) {
			TAILQ_REMOVE(&lready, req, entry);
			sq_free_chain(req);
		}
		while ((req = TAILQ_FIRST(&lpolls)) != NULL) {
			TAILQ_REMOVE(&lpolls, req, entry);
			sq_free_chain(req);
		}
		while ((req = TAILQ_FIRST(&ldrain)) != NULL) {
			TAILQ_REMOVE(&ldrain, req, entry);
			sq_free_chain(req);
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
		struct sq_pbuf_ring *pr;
		struct sq_zcrx *z;

		while ((z = TAILQ_FIRST(&ctx->zcrx)) != NULL) {
			TAILQ_REMOVE(&ctx->zcrx, z, entry);
			sq_zcrx_free(z);
		}
		while ((pb = TAILQ_FIRST(&ctx->pbufs)) != NULL) {
			TAILQ_REMOVE(&ctx->pbufs, pb, entry);
			free(pb, M_SQUEUE);
		}
		while ((pr = TAILQ_FIRST(&ctx->pbuf_rings)) != NULL) {
			TAILQ_REMOVE(&ctx->pbuf_rings, pr, entry);
			sq_pbuf_ring_free(pr);
		}
		free(ctx->legacy_pbuf_groups, M_SQUEUE);
		ctx->legacy_pbuf_groups = NULL;
	}
	if (ctx->reg_bufs != NULL) {
		uint32_t i;

		for (i = 0; i < ctx->reg_bufs->count; i++)
			if (ctx->reg_bufs->nodes[i] != NULL)
				ctx->reg_bufs->nodes[i]->tag = 0;
		/* Ring teardown has no CQ consumer for resource-tag events. */
		sq_buf_table_rele(ctx->reg_bufs);
	}
	if (ctx->reg_files != NULL) {
		uint32_t i;

		for (i = 0; i < ctx->reg_nfiles; i++) {
			if (ctx->reg_files[i] != NULL)
				ctx->reg_files[i]->tag = 0; /* no consumer during teardown */
			sq_file_node_rele(ctx->reg_files[i], curthread);
		}
		free(ctx->reg_files, M_SQUEUE);
	}
	{
		struct sq_personality *personality;

		while ((personality = LIST_FIRST(&ctx->personalities)) != NULL) {
			LIST_REMOVE(personality, link);
			crfree(personality->cred);
			free(personality, M_SQUEUE);
		}
	}
	for (i = 0; i < IORING_OP_LAST; i++) {
		for (filter = ctx->bpf_filters[i]; filter != NULL;
		    filter = next_filter) {
			next_filter = filter->next;
			free(filter, M_SQUEUE);
		}
	}
	if (ctx->owner_uid != NULL)
		uifree(ctx->owner_uid);
	if (ctx->owner_vm != NULL)
		vmspace_free(ctx->owner_vm);
	sq_ring_backing_free(ctx->obj, ctx->kva, ctx->objsize);
	sq_buf_backing_rele(ctx->sqes_user);
	sq_buf_backing_rele(ctx->ring_user);
	sq_ring_backing_free(ctx->param_obj, ctx->param_obj != NULL ?
	    ctx->param_kva : NULL, ctx->param_size);
	sq_buf_backing_rele(ctx->param_user);
	seldrain(&ctx->sel);
	if (ctx->submitter != NULL) {
		atomic_subtract_long(&sq_issuer_refs, 1);
		sq_issuer_rele(ctx->submitter);
	}
	knlist_destroy(&ctx->sel.si_note);
	sx_destroy(&ctx->files_sx);
	sx_destroy(&ctx->mmap_sx);
	sx_destroy(&ctx->register_sx);
	sx_destroy(&ctx->kq_sx);
	cv_destroy(&ctx->sqpoll_cv);
	mtx_destroy(&ctx->mtx);
	/* Attachments retain their poller and worker-control owners until all
	 * offloaded work and mappings have gone away.  One reference covers an
	 * owner used for both roles. */
	poll_root = ctx->sqpoll_root;
	worker_root = ctx->worker_root;
	free(ctx, M_SQUEUE);
	if (poll_root != NULL && poll_root != ctx)
		sq_ctx_rele(poll_root);
	if (worker_root != NULL && worker_root != ctx && worker_root != poll_root)
		sq_ctx_rele(worker_root);
}

/* ---- completion ---- */

/* Write one CQE directly to the ring; false if the CQ has no room. */
static bool
sq_cq_post_raw_ext(struct squeue_ctx *ctx, uint64_t user_data, int32_t res,
    uint32_t cflags, uint64_t extra1, uint64_t extra2, bool big)
{
	struct io_uring_cqe *cqe;
	uint32_t head, tail, used;
	bool mixed_big;

	mtx_assert(&ctx->mtx, MA_OWNED);
	tail = ctx->rings->cq_tail;
	head = atomic_load_acq_32(&ctx->rings->cq_head);
	used = tail - head;
	mixed_big = big &&
	    (ctx->setup_flags & IORING_SETUP_CQE_MIXED) != 0;
	/* A mixed 32-byte CQE may not straddle the physical ring wrap. */
	if (mixed_big && (tail & ctx->cq_mask) == ctx->cq_mask) {
		if (used >= ctx->cq_entries)
			return (false);
		cqe = (struct io_uring_cqe *)((char *)ctx->cqes +
		    (vm_size_t)(tail & ctx->cq_mask) * ctx->cqe_stride);
		cqe->user_data = 0;
		cqe->res = 0;
		cqe->flags = IORING_CQE_F_SKIP;
		tail++;
		used++;
		atomic_store_rel_32(&ctx->rings->cq_tail, tail);
		counter_u64_add(sq_stat_completed, 1);
	}
	if (used > ctx->cq_entries ||
	    ctx->cq_entries - used < (mixed_big ? 2u : 1u))
		return (false);
	cqe = (struct io_uring_cqe *)((char *)ctx->cqes +
	    (vm_size_t)(tail & ctx->cq_mask) * ctx->cqe_stride);
	cqe->user_data = user_data;
	cqe->res = res;
	cqe->flags = cflags;
	if (ctx->cqe_stride > sizeof(*cqe) || mixed_big) {
		struct io_uring_cqe *ext = cqe + 1;
		if (big) {
			bcopy(&extra1, ext, sizeof(extra1));
			bcopy(&extra2, (char *)ext + sizeof(extra1), sizeof(extra2));
		} else
			bzero(ext, sizeof(*ext));
	}
	tail += mixed_big ? 2 : 1;
	atomic_store_rel_32(&ctx->rings->cq_tail, tail);
	counter_u64_add(sq_stat_completed, 1);
	SDT_PROBE4(squeue, , , complete, ctx, user_data, res, cflags);
	if (ctx->eventfd != NULL && !ctx->eventfd_async &&
	    (atomic_load_acq_32(&ctx->rings->cq_flags) &
	    IORING_CQ_EVENTFD_DISABLED) == 0)
		eventfd_signal(ctx->eventfd);
	return (true);
}

static void
sq_cq_flush(struct squeue_ctx *ctx)
{
	struct sq_ovfl *o;

	mtx_assert(&ctx->mtx, MA_OWNED);
	while ((o = TAILQ_FIRST(&ctx->overflow)) != NULL) {
		if (!sq_cq_post_raw_ext(ctx, o->user_data, o->res, o->cflags,
		    o->extra1, o->extra2, o->big))
			return;
		TAILQ_REMOVE(&ctx->overflow, o, entry);
		ctx->noverflow--;
		free(o, M_SQUEUE);
	}
	ctx->rings->sq_flags &= ~IORING_SQ_CQ_OVERFLOW;
}

static bool
sq_post_cqe_impl_ext(struct squeue_ctx *ctx, uint64_t user_data, int32_t res,
    uint32_t cflags, uint64_t extra1, uint64_t extra2, bool big)
{
	struct sq_ovfl *o;

	mtx_assert(&ctx->mtx, MA_OWNED);
	sq_cq_flush(ctx);
	if (TAILQ_EMPTY(&ctx->overflow) &&
	    sq_cq_post_raw_ext(ctx, user_data, res, cflags, extra1, extra2, big))
		return (true);
	if (ctx->noverflow >= 4u * ctx->cq_entries)
		goto drop;
	o = malloc(sizeof(*o), M_SQUEUE, M_NOWAIT);
	if (o == NULL)
		goto drop;
	o->user_data = user_data;
	o->res = res;
	o->cflags = cflags;
	o->extra1 = extra1;
	o->extra2 = extra2;
	o->big = big;
	TAILQ_INSERT_TAIL(&ctx->overflow, o, entry);
	ctx->noverflow++;
	/* Linux counts completions lost to overflow, not CQEs held here. */
	ctx->rings->sq_flags |= IORING_SQ_CQ_OVERFLOW;
	counter_u64_add(sq_stat_overflowed, 1);
	SDT_PROBE1(squeue, , , overflow, ctx);
	return (true);
drop:
	ctx->rings->cq_overflow++;
	ctx->rings->sq_flags |= IORING_SQ_CQ_OVERFLOW;
	counter_u64_add(sq_stat_overflowed, 1);
	SDT_PROBE1(squeue, , , overflow, ctx);
	return (false);
}

static bool
sq_post_cqe_impl(struct squeue_ctx *ctx, uint64_t user_data, int32_t res,
    uint32_t cflags)
{
	return (sq_post_cqe_impl_ext(ctx, user_data, res, cflags, 0, 0, false));
}

void
sq_post_cqe(struct squeue_ctx *ctx, uint64_t user_data, int32_t res,
    uint32_t cflags)
{

	(void)sq_post_cqe_impl(ctx, user_data, res, cflags);
}

static uint32_t
sq_cq_ready(struct squeue_ctx *ctx)
{

	return (ctx->rings->cq_tail - atomic_load_acq_32(&ctx->rings->cq_head));
}

void
sq_wake(struct squeue_ctx *ctx)
{

	mtx_assert(&ctx->mtx, MA_OWNED);
	SDT_PROBE2(squeue, , , wakeup, ctx, ctx->cq_waiters);
	if ((ctx->setup_flags & IORING_SETUP_TASKRUN_FLAG) != 0 &&
	    !TAILQ_EMPTY(&ctx->ready))
		ctx->rings->sq_flags |= IORING_SQ_TASKRUN;
	selwakeuppri(&ctx->sel, PSOCK);
	KNOTE_LOCKED(&ctx->sel.si_note, 0);
	if (ctx->kqfp != NULL)
		taskqueue_enqueue(taskqueue_thread, &ctx->kq_wake_task);
	if (ctx->cq_waiters > 0)
		wakeup(&ctx->cq_waiters);
}

static void sq_check_count_timeouts(struct squeue_ctx *ctx);

void
sq_post_multishot_cqe(struct squeue_ctx *ctx, struct sq_req *req,
    int32_t res, uint32_t cflags)
{

	mtx_assert(&ctx->mtx, MA_OWNED);
	sq_post_cqe(ctx, req->user_data, res, cflags);
	ctx->cq_count++;
	sq_check_count_timeouts(ctx);
	sq_wake(ctx);
}

int32_t
sq_zcrx_recv(struct squeue_ctx *ctx, struct sq_req *req, struct thread *td,
    uint32_t id)
{
	struct sq_zcrx *z;
	struct socket *so;
	struct file *fp;
	struct iovec iov;
	struct uio uio;
	uint32_t idx, i, want;
	int32_t result;
	int error, flags;

	error = fget_read(td, req->sqe.fd, &cap_read_rights, &fp);
	if (error != 0)
		return (sq_err(ctx, error));
	if (fp->f_type != DTYPE_SOCKET) {
		fdrop(fp, td);
		return (sq_err(ctx, ENOTSOCK));
	}
	so = fp->f_data;
	if (so->so_type != SOCK_STREAM || so->so_proto == NULL ||
	    so->so_proto->pr_protocol != IPPROTO_TCP) {
		fdrop(fp, td);
		return (sq_err(ctx, EPROTONOSUPPORT));
	}

	mtx_lock(&ctx->mtx);
	z = sq_zcrx_find(ctx, id);
	if (z == NULL) {
		mtx_unlock(&ctx->mtx);
		fdrop(fp, td);
		return (sq_err(ctx, EINVAL));
	}
	sq_zcrx_refill_locked(z, false);
	idx = z->nchunks;
	for (i = 0; i < z->nchunks; i++) {
		uint32_t candidate = (z->alloc_hint + i) % z->nchunks;

		if (!z->busy[candidate]) {
			idx = candidate;
			z->busy[idx] = true;
			z->alloc_hint = (idx + 1) % z->nchunks;
			break;
		}
	}
	mtx_unlock(&ctx->mtx);
	if (idx == z->nchunks) {
		fdrop(fp, td);
		return (sq_err(ctx, ENOMEM));
	}

	want = PAGE_SIZE;
	if (req->net_mshot_remaining != 0)
		want = MIN(want, req->net_mshot_remaining);
	iov.iov_base = z->area->buf.kva + (vm_size_t)idx * PAGE_SIZE;
	iov.iov_len = want;
	bzero(&uio, sizeof(uio));
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = want;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_td = td;
	flags = MSG_NBIO;
#ifdef MAC
	error = mac_socket_check_receive(td->td_ucred, so);
	if (error == 0)
#endif
		error = soreceive(so, NULL, &uio, NULL, NULL, &flags);
	result = (int32_t)(want - uio.uio_resid);
	if (result != 0 && (error == EWOULDBLOCK || error == ERESTART ||
	    error == EINTR))
		error = 0;
	fdrop(fp, td);

	mtx_lock(&ctx->mtx);
	if (error != 0 || result == 0) {
		z->busy[idx] = false;
		mtx_unlock(&ctx->mtx);
		return (error != 0 ? sq_err(ctx,
		    error == EWOULDBLOCK ? EAGAIN : error) : 0);
	}
	(void)sq_post_cqe_impl_ext(ctx, req->user_data, result,
	    IORING_CQE_F_MORE | ((ctx->setup_flags & IORING_SETUP_CQE_MIXED) != 0 ?
	    IORING_CQE_F_32 : 0), (uint64_t)idx << PAGE_SHIFT, 0, true);
	ctx->cq_count++;
	sq_check_count_timeouts(ctx);
	sq_wake(ctx);
	mtx_unlock(&ctx->mtx);

	if (req->net_mshot_remaining != 0) {
		req->net_mshot_remaining -= MIN((uint32_t)result,
		    req->net_mshot_remaining);
		if (req->net_mshot_remaining == 0)
			return (0);
	}
	return (sq_err(ctx, EAGAIN));
}

/*
 * Post a request's CQE (honouring IOSQE_CQE_SKIP_SUCCESS) and account it for
 * count-based timeouts.  Caller holds ctx->mtx.
 */
static void
sq_complete(struct squeue_ctx *ctx, struct sq_req *req, int32_t res,
    uint32_t cflags)
{

	mtx_assert(&ctx->mtx, MA_OWNED);
	sq_unissue(req);
	sq_finish_link(req);
	if (req->posted) {
		/* The op emitted its own CQE(s) (e.g. SEND_ZC notif). */
	} else if (res >= 0 && (req->sqe_flags & IOSQE_CQE_SKIP_SUCCESS) != 0) {
		/* Successful CQE elided by request flag. */
	} else {
		(void)sq_post_cqe_impl_ext(ctx, req->user_data, res, cflags,
		    req->cqe_extra1, req->cqe_extra2, req->cqe_big);
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

/*
 * Park a front-end request on an external event source without occupying a
 * worker.  The source owns one context reference until sq_ext_finish().
 * activate runs after cancellation can find the request, under the ring lock.
 */
int
sq_ext_park(struct sq_req *req, void *arg, void (*cancel)(void *),
    void (*activate)(void *))
{
	struct squeue_ctx *ctx = req->ctx;

	mtx_lock(&ctx->mtx);
	if (req->cancel_requested) {
		mtx_unlock(&ctx->mtx);
		return (ECANCELED);
	}
	atomic_add_int(&ctx->refs, 1);
	sq_unissue(req);
	req->ext_arg = arg;
	req->ext_cancel = cancel;
	req->state = SQ_ST_ARMED;
	TAILQ_INSERT_TAIL(&ctx->pending, req, entry);
	ctx->npending++;
	activate(arg);
	if (ctx->ext_poll != NULL)
		cv_broadcast(&ctx->sqpoll_cv);
	mtx_unlock(&ctx->mtx);
	return (0);
}

void
sq_ext_finish(struct sq_req *req, int32_t res)
{
	struct squeue_ctx *ctx = req->ctx;

	mtx_lock(&ctx->mtx);
	KASSERT(req->ext_cancel != NULL && req->state == SQ_ST_ARMED,
	    ("squeue external request not armed"));
	req->ext_cancel = NULL;
	req->ext_arg = NULL;
	TAILQ_REMOVE(&ctx->pending, req, entry);
	ctx->npending--;
	/* A successful WAITID probe may already have reaped its child.  A
	 * cancellation arriving after that point cannot undo the event. */
	req->res = req->cancel_requested && !(ctx->is_linux &&
	    req->opcode == IORING_OP_WAITID && res == 0) ?
	    sq_err(ctx, ECANCELED) : res;
	req->state = SQ_ST_READY;
	TAILQ_INSERT_TAIL(&ctx->ready, req, entry);
	sq_wake(ctx);
	cv_broadcast(&ctx->sqpoll_cv);
	mtx_unlock(&ctx->mtx);
	sq_ctx_rele(ctx);
}

/* ---- request allocation ---- */
static void
sq_req_free(struct sq_req *req)
{

	callout_drain(&req->co);
	if (req->poll_delete) {
		if (req->poll_id != 0)
			sq_kq_del_req(req, curthread);
		else
			sq_kq_del(req->ctx, req->sqe.fd,
			    sq_kq_filter(req), curthread);
	}
	/*
	 * Defensive: an offloaded request normally clears these in the worker
	 * before it is readied, but release anything still held so a teardown
	 * on an unusual path cannot leak a file, uio, or vmspace reference.
	 */
	if (req->ofp != NULL)
		fdrop(req->ofp, curthread);
	if (req->match_fp != NULL)
		fdrop(req->match_fp, curthread);
	if (req->poll_caps != NULL) {
		filecaps_free(req->poll_caps);
		free(req->poll_caps, M_SQUEUE);
	}
	sq_file_node_rele(req->file_node, curthread);
	if (req->ouio != NULL)
		free(req->ouio, M_IOV);
	if (req->ovm != NULL)
		vmspace_free(req->ovm);
	if (req->buf_uio != NULL)
		free(req->buf_uio, M_IOV);
	if (req->pbuf_selected)
		sq_recycle_buffer(req);
	sq_buf_table_rele(req->buf_table);
	if (req->cred != NULL)
		crfree(req->cred);
	atomic_subtract_long(&sq_live_requests, 1);
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

	/* An SQE has already been consumed; it cannot restart the syscall. */
	if (bsd_errno == ERESTART)
		bsd_errno = EINTR;
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

static struct mtx	sq_wq_mtx;
static struct cv	sq_wq_cv;
static TAILQ_HEAD(, sq_req) sq_workq;

/* All association and execution ownership transitions use the ring lock. */
static void
sq_unissue(struct sq_req *req)
{
	mtx_assert(&req->ctx->mtx, MA_OWNED);
	if (req->issuing) {
		TAILQ_REMOVE(&req->ctx->issuing, req, issue_entry);
		req->issuing = false;
		req->issuer = NULL;
		callout_stop(&req->co);
	}
}

static void
sq_finish_link(struct sq_req *req)
{
	struct squeue_ctx *ctx = req->ctx;
	struct sq_req *lt = req->link_timeout;

	mtx_assert(&ctx->mtx, MA_OWNED);
	if (lt == NULL)
		return;
	req->link_timeout = NULL;
	lt->link_target = NULL;
	callout_stop(&lt->co);
	if (lt->state == SQ_ST_ARMED) {
		TAILQ_REMOVE(&ctx->pending, lt, entry);
		ctx->npending--;
	}
	lt->state = SQ_ST_READY;
	lt->res = sq_err(ctx, ECANCELED);
	TAILQ_INSERT_TAIL(&ctx->ready, lt, entry);
	sq_wake(ctx);
}

/* Cancellation is sticky until the executor relinquishes the request.  An
 * interruptible sleep can start just after the first cancellation attempt;
 * retry while that same executor still owns this request.  Never interrupt
 * an uninterruptible wait or publish completion while I/O can use its memory. */
static void
sq_interrupt_cb(void *arg)
{
	struct sq_req *req = arg;
	struct thread *td = req->issuer;

	mtx_assert(&req->ctx->mtx, MA_OWNED);
	if (!req->cancel_requested || td == NULL)
		return;
	thread_lock(td);
	if (TD_ON_SLEEPQ(td) && (td->td_flags & TDF_SINTR) != 0)
		sleepq_abort(td, EINTR); /* releases thread lock */
	else
		thread_unlock(td);
	callout_reset(&req->co, 1, sq_interrupt_cb, req);
}

static int
sq_cancel_req(struct sq_req *req)
{
	struct squeue_ctx *ctx = req->ctx;

	mtx_assert(&ctx->mtx, MA_OWNED);
	if (req->cancel_requested)
		return (EALREADY);
	if (req->ext_cancel != NULL) {
		req->cancel_requested = true;
		req->ext_cancel(req->ext_arg);
		if (ctx->ext_poll != NULL)
			cv_broadcast(&ctx->sqpoll_cv);
		return (0);
	}
	if (req->worker_owned) {
		/* A queued request can retire without waiting behind unrelated I/O.
		 * Workers drop the queue lock before acquiring the ring lock. */
		mtx_lock(&sq_wq_mtx);
		if (req->work_queued) {
			TAILQ_REMOVE(&sq_workq, req, wq);
			req->work_queued = false;
			req->worker_owned = false;
			/* Last-close cancels the queue before dropping the file's
			 * reference, so this cannot be the final context reference. */
			KASSERT(ctx->refs > 1, ("queued squeue request without owner"));
			atomic_subtract_int(&ctx->refs, 1);
		}
		mtx_unlock(&sq_wq_mtx);
	}
	if (req->worker_owned || req->issuing) {
		req->cancel_requested = true;
		sq_interrupt_cb(req);
		return (0);
	}
	if (req->state != SQ_ST_ARMED)
		return (ENOENT);
	callout_stop(&req->co);
	if (req->on_poll) {
		TAILQ_REMOVE(&ctx->polls, req, entry);
		ctx->npolls--;
		req->on_poll = false;
		req->poll_delete = true;
	} else {
		TAILQ_REMOVE(&ctx->pending, req, entry);
		ctx->npending--;
	}
	if (req->link_target != NULL) {
		req->link_target->link_timeout = NULL;
		req->link_target = NULL;
	}
	sq_finish_link(req);
	req->state = SQ_ST_READY;
	req->res = sq_err(ctx, ECANCELED);
	TAILQ_INSERT_TAIL(&ctx->ready, req, entry);
	sq_wake(ctx);
	return (0);
}

struct sq_cancel_match {
	uint64_t	user_data;
	struct file	*fp;
	uint32_t	flags;
	uint8_t		opcode;
};

static bool
sq_cancel_matches(const struct sq_req *req, const struct sq_cancel_match *match,
    bool timeout_only)
{
	bool match_user_data;

	if (req->opcode == IORING_OP_LINK_TIMEOUT)
		return (false);
	if (timeout_only)
		return (req->opcode == IORING_OP_TIMEOUT &&
		    req->user_data == match->user_data);
	if ((match->flags & IORING_ASYNC_CANCEL_ANY) != 0)
		return (true);
	if ((match->flags & IORING_ASYNC_CANCEL_FD) != 0 &&
	    req->match_fp != match->fp &&
	    !(req->poll_ring_target && match->fp != NULL &&
	    match->fp->f_type == DTYPE_IORING &&
	    req->poll_target_ctx == match->fp->f_data))
		return (false);
	if ((match->flags & IORING_ASYNC_CANCEL_OP) != 0 &&
	    req->opcode != match->opcode)
		return (false);
	match_user_data = (match->flags & IORING_ASYNC_CANCEL_USERDATA) != 0 ||
	    (match->flags & (IORING_ASYNC_CANCEL_FD |
	    IORING_ASYNC_CANCEL_OP)) == 0;
	return (!match_user_data || req->user_data == match->user_data);
}

static int
sq_cancel_match(struct squeue_ctx *ctx, const struct sq_cancel_match *criteria,
    bool timeout_only, bool all, struct sq_req *exclude)
{
	struct sq_req *req, *match;
	int count = 0;
	bool already = false, external = false;

	mtx_assert(&ctx->mtx, MA_OWNED);
	for (;;) {
		match = NULL;
		TAILQ_FOREACH(req, &ctx->pending, entry) {
			if (!sq_cancel_matches(req, criteria, timeout_only))
				continue;
			if (req->cancel_requested) { already = true; continue; }
			match = req;
			break;
		}
		if (!timeout_only && match == NULL) {
			TAILQ_FOREACH(req, &ctx->polls, entry) {
				if (sq_cancel_matches(req, criteria, false)) {
					match = req;
					break;
				}
			}
		}
		if (!timeout_only && match == NULL) {
			TAILQ_FOREACH(req, &ctx->issuing, issue_entry) {
				if (req == exclude ||
				    !sq_cancel_matches(req, criteria, false))
					continue;
				if (req->cancel_requested) { already = true; continue; }
				match = req;
				break;
			}
		}
		if (match == NULL)
			break;
		external = match->ext_cancel != NULL;
		(void)sq_cancel_req(match);
		count++;
		if (!all)
			return (external && ctx->is_linux ? 1 : 0);
	}
	if (all && ctx->is_linux && count != 0 &&
	    (criteria->flags & IORING_ASYNC_CANCEL_OP) != 0 &&
	    (criteria->opcode == IORING_OP_FUTEX_WAIT ||
	    criteria->opcode == IORING_OP_FUTEX_WAITV ||
	    criteria->opcode == IORING_OP_WAITID))
		return (1); /* Linux futex-list cancel reports one successful scan. */
	if (all)
		return (count);
	return (sq_err(ctx, already ? EALREADY : ENOENT));
}

/* Native ring policy; Linux supplies its own decoder through the front end. */
static int
sq_native_rw_flags(uint32_t flags, int *foflags)
{

	if ((flags & ~IORING_RWF_SUPPORTED) != 0)
		return (EOPNOTSUPP);
	if ((flags & (IORING_RWF_APPEND | IORING_RWF_NOAPPEND)) ==
	    (IORING_RWF_APPEND | IORING_RWF_NOAPPEND))
		return (EINVAL);
	if ((flags & (IORING_RWF_NOWAIT | IORING_RWF_ATOMIC |
	    IORING_RWF_DONTCACHE)) != 0)
		return (EOPNOTSUPP);
	if ((flags & IORING_RWF_HIPRI) != 0)
		return (EINVAL);
	*foflags = 0;
	if ((flags & IORING_RWF_DSYNC) != 0)
		*foflags |= FOF_DSYNC;
	if ((flags & IORING_RWF_SYNC) != 0)
		*foflags |= FOF_SYNC;
	if ((flags & IORING_RWF_APPEND) != 0)
		*foflags |= FOF_APPEND;
	if ((flags & IORING_RWF_NOAPPEND) != 0)
		*foflags |= FOF_NOAPPEND;
	if ((flags & IORING_RWF_NOSIGNAL) != 0)
		*foflags |= FOF_NOSIGPIPE;
	return (0);
}

/* Single-buffer read/write (READ/WRITE and READ_FIXED/WRITE_FIXED). */
static int32_t
sq_rw1(struct squeue_ctx *ctx, struct thread *td, int fd, void *buf,
    uint32_t len, off_t off, bool cur, bool write, int foflags)
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
	error = kern_rwv(td, fd, &auio, cur ? -1 : off, write, foflags);
	return (sq_result(ctx, td, error));
}

/* Snapshot a fixed request once; retries retain the original generation. */
static int
sq_fixed_prepare(struct squeue_ctx *ctx, struct sq_req *req)
{
	const struct io_uring_sqe *sqe = &req->sqe;
	struct sq_buf_table *table;
	struct sq_buf_node *node;
	struct sq_buf *b;
	struct uio *uio;
	struct iovec *v;
	uintptr_t addr;
	bool vec;
	int error, i;

	if (req->buf_uio != NULL)
		return (0);
	vec = sqe->opcode == IORING_OP_READV_FIXED ||
	    sqe->opcode == IORING_OP_WRITEV_FIXED;
	if (vec) {
		error = copyinuio((void *)(uintptr_t)sqe->addr, sqe->len, &uio);
		if (error != 0)
			return (error);
	} else {
		uio = allocuio(1);
		uio->uio_iovcnt = 1;
		uio->uio_resid = sqe->len;
		uio->uio_iov[0].iov_base = (void *)(uintptr_t)sqe->addr;
		uio->uio_iov[0].iov_len = sqe->len;
	}
	mtx_lock(&ctx->mtx);
	table = ctx->reg_bufs;
	if (table != NULL)
		refcount_acquire(&table->refs);
	mtx_unlock(&ctx->mtx);
	error = EFAULT;
	if (table == NULL || sqe->buf_index >= table->count)
		goto fail;
	node = table->nodes[sqe->buf_index];
	if (node == NULL)
		goto fail;
	b = &node->backing->buf;
	for (i = 0; i < uio->uio_iovcnt; i++) {
		v = &uio->uio_iov[i];
		addr = (uintptr_t)v->iov_base;
		/* Subtraction makes overflow and both interval ends explicit. */
		if (addr < b->base || addr - b->base > b->len ||
		    v->iov_len > b->len - (addr - b->base) ||
		    (vec && v->iov_len == 0))
			goto fail;
		v->iov_base = (void *)(b->kva + (b->base & PAGE_MASK) +
		    (addr - b->base));
	}
	uio->uio_segflg = UIO_SYSSPACE;
	uio->uio_offset = (off_t)sqe->off;
	uio->uio_td = curthread;
	req->buf_uio = uio;
	req->buf_table = table;
	return (0);
fail:
	sq_buf_table_rele(table);
	free(uio, M_IOV);
	return (error);
}

int
sq_prepare_fixed_buffer(struct squeue_ctx *ctx, struct sq_req *req,
    uint64_t addr, uint32_t len, bool vector)
{
	uint64_t saved_addr;
	uint32_t saved_len;
	uint8_t saved_op;
	int error;

	saved_addr = req->sqe.addr;
	saved_len = req->sqe.len;
	saved_op = req->sqe.opcode;
	req->sqe.addr = addr;
	req->sqe.len = len;
	if (vector && (saved_op == IORING_OP_SEND_ZC ||
	    saved_op == IORING_OP_SENDMSG_ZC))
		req->sqe.opcode = IORING_OP_WRITEV_FIXED;
	else if (!vector && saved_op == IORING_OP_SEND_ZC)
		req->sqe.opcode = IORING_OP_WRITE_FIXED;
	error = sq_fixed_prepare(ctx, req);
	req->sqe.addr = saved_addr;
	req->sqe.len = saved_len;
	req->sqe.opcode = saved_op;
	return (error);
}

static void
sq_fixed_dirty(struct sq_req *req)
{
	struct sq_buf *b;

	if (req->buf_table == NULL)
		return;
	b = &req->buf_table->nodes[req->sqe.buf_index]->backing->buf;
	vm_map_pin_dirty(b->pin);
}

static int sq_do_files_update(struct squeue_ctx *ctx, uint32_t off,
    uint64_t fds_uptr, uint64_t tags_uptr, uint32_t nr, struct thread *td);
static int sq_do_files_update_alloc(struct squeue_ctx *ctx, uint64_t fds_uptr,
    uint32_t nr, struct thread *td);
static int sq_fixed_install(struct squeue_ctx *ctx, struct thread *td,
    int idx, int install_flags, int *fdp, struct sq_file_node **nodep);
static int32_t sq_msg_ring(struct squeue_ctx *ctx, struct sq_req *req,
    struct thread *td);

/* A registered provided-buffer ring.  The producer-owned tail lives in the
 * shared ring; head and selection ownership are protected by ctx->mtx. */

static struct sq_pbuf_ring *
sq_pbuf_ring_find(struct squeue_ctx *ctx, uint16_t bgid)
{
	struct sq_pbuf_ring *r;

	TAILQ_FOREACH(r, &ctx->pbuf_rings, entry)
		if (r->bgid == bgid)
			return (r);
	return (NULL);
}

static void
sq_pbuf_ring_free(struct sq_pbuf_ring *r)
{

	if (r->mmap_ring) {
		if (r->kva != 0) {
			pmap_qremove(r->kva, atop(r->size));
			kva_free(r->kva, r->size);
		}
		if (r->obj != NULL) {
			vm_object_deallocate(r->obj);
			atomic_subtract_long(&sq_wired_pages, atop(r->size));
		}
	} else
		sq_buf_table_rele(r->table);
	free(r, M_SQUEUE);
}

static int
sq_pbuf_ring_alloc_mmap(struct sq_pbuf_ring *r, struct thread *td)
{
	vm_page_t *ma;
	int i, npages;

	npages = atop(r->size);
	if (r->size > lim_cur(td, RLIMIT_MEMLOCK) &&
	    priv_check(td, PRIV_VM_MLOCK) != 0)
		return (ENOMEM);
	if (atomic_fetchadd_long(&sq_wired_pages, npages) + npages >
	    sq_max_wired_pages) {
		atomic_subtract_long(&sq_wired_pages, npages);
		return (ENOMEM);
	}
	r->obj = vm_pager_allocate(OBJT_PHYS, NULL, r->size,
	    VM_PROT_DEFAULT, 0, td->td_ucred);
	if (r->obj == NULL)
		goto fail_charge;
	r->kva = kva_alloc(r->size);
	if (r->kva == 0)
		goto fail_obj;
	ma = mallocarray(npages, sizeof(*ma), M_SQUEUE, M_WAITOK);
	VM_OBJECT_WLOCK(r->obj);
	for (i = 0; i < npages; i++) {
		ma[i] = vm_page_grab(r->obj, i, VM_ALLOC_NORMAL |
		    VM_ALLOC_WIRED | VM_ALLOC_ZERO);
		vm_page_valid(ma[i]);
		vm_page_xunbusy(ma[i]);
	}
	VM_OBJECT_WUNLOCK(r->obj);
	pmap_qenter(r->kva, ma, npages);
	free(ma, M_SQUEUE);
	r->ring = r->kva;
	return (0);
fail_obj:
	vm_object_deallocate(r->obj);
	r->obj = NULL;
fail_charge:
	atomic_subtract_long(&sq_wired_pages, npages);
	return (ENOMEM);
}

static int
sq_pbuf_ring_pin(struct sq_pbuf_ring *r, uintptr_t addr, struct thread *td)
{
	struct sq_buf_table *table;
	struct sq_buf_node *node;
	struct iovec iov;
	int error;

	table = malloc(sizeof(*table) + sizeof(*table->nodes), M_SQUEUE,
	    M_WAITOK | M_ZERO);
	refcount_init(&table->refs, 1);
	table->count = 1;
	iov.iov_base = (void *)addr;
	iov.iov_len = r->size;
	node = sq_buf_node_alloc(NULL, &iov, 0, td, &error);
	if (error != 0) {
		free(table, M_SQUEUE);
		return (error);
	}
	table->nodes[0] = node;
	r->table = table;
	r->ring = (struct io_uring_buf_ring *)(node->backing->buf.kva +
	    (addr & PAGE_MASK));
	return (0);
}

static int
sq_register_pbuf_ring(struct squeue_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{
	struct io_uring_buf_reg reg;
	struct sq_pbuf_ring *r;
	struct sq_pbuf *pb;
	vm_size_t bytes;
	int error;

	if (arg == NULL)
		return (EFAULT);
	if (nr != 1)
		return (EINVAL);
	error = copyin(arg, &reg, sizeof(reg));
	if (error != 0)
		return (error);
	if (reg.ring_entries == 0 || reg.ring_entries > 32768 ||
	    !powerof2(reg.ring_entries) || reg.bgid > 0x7fff ||
	    reg.resv[0] != 0 || reg.resv[1] != 0 ||
	    reg.resv[2] != 0 || reg.resv[3] != 0 || reg.resv[4] != 0 ||
	    (reg.flags & ~(IOU_PBUF_RING_MMAP | IOU_PBUF_RING_INC)) != 0 ||
	    (reg.min_left != 0 && (reg.flags & IOU_PBUF_RING_INC) == 0))
		return (EINVAL);
	if ((reg.flags & IOU_PBUF_RING_MMAP) != 0) {
		if (reg.ring_addr != 0)
			return (EINVAL);
	} else if (reg.ring_addr == 0 || (reg.ring_addr & PAGE_MASK) != 0) {
		return (EINVAL);
	}
	bytes = round_page((vm_size_t)reg.ring_entries *
	    sizeof(struct io_uring_buf));
	r = malloc(sizeof(*r), M_SQUEUE, M_WAITOK | M_ZERO);
	r->bgid = reg.bgid;
	r->entries = reg.ring_entries;
	r->mask = reg.ring_entries - 1;
	r->size = bytes;
	r->mmap_ring = (reg.flags & IOU_PBUF_RING_MMAP) != 0;
	r->incremental = (reg.flags & IOU_PBUF_RING_INC) != 0;
	if (reg.min_left != 0)
		r->min_left_sub_one = reg.min_left - 1;
	error = r->mmap_ring ? sq_pbuf_ring_alloc_mmap(r, td) :
	    sq_pbuf_ring_pin(r, (uintptr_t)reg.ring_addr, td);
	if (error != 0) {
		free(r, M_SQUEUE);
		return (error == EFAULT ? EINVAL : error);
	}
	mtx_lock(&ctx->mtx);
	if (sq_pbuf_ring_find(ctx, reg.bgid) != NULL) {
		error = EEXIST;
	} else {
		error = 0;
		TAILQ_FOREACH(pb, &ctx->pbufs, entry)
			if (pb->bgid == reg.bgid) {
				error = EEXIST;
				break;
			}
	}
	if (error == 0) {
		/* Linux replaces an empty legacy group with the mapped ring. */
		if (sq_pbuf_group_exists(ctx, reg.bgid))
			ctx->legacy_pbuf_groups[reg.bgid / 64] &=
			    ~(1ULL << (reg.bgid % 64));
		TAILQ_INSERT_TAIL(&ctx->pbuf_rings, r, entry);
	}
	mtx_unlock(&ctx->mtx);
	if (error != 0)
		sq_pbuf_ring_free(r);
	return (error);
}

static int
sq_unregister_pbuf_ring(struct squeue_ctx *ctx, void *arg, uint32_t nr)
{
	struct io_uring_buf_reg reg;
	struct sq_pbuf_ring *r;
	int error;

	if (arg == NULL)
		return (EFAULT);
	if (nr != 1)
		return (EINVAL);
	error = copyin(arg, &reg, sizeof(reg));
	if (error != 0)
		return (error);
	if (reg.ring_addr != 0 || reg.ring_entries != 0 || reg.flags != 0 ||
	    reg.min_left != 0 || reg.resv[0] != 0 || reg.resv[1] != 0 ||
	    reg.resv[2] != 0 || reg.resv[3] != 0 || reg.resv[4] != 0)
		return (EINVAL);
	mtx_lock(&ctx->mtx);
	r = sq_pbuf_ring_find(ctx, reg.bgid);
	if (r == NULL)
		error = ENOENT;
	else if (r->busy != 0)
		error = EBUSY;
	else {
		TAILQ_REMOVE(&ctx->pbuf_rings, r, entry);
		error = 0;
	}
	mtx_unlock(&ctx->mtx);
	if (error == 0)
		sq_pbuf_ring_free(r);
	return (error);
}

static int
sq_pbuf_status(struct squeue_ctx *ctx, void *arg, uint32_t nr)
{
	struct io_uring_buf_status st;
	struct sq_pbuf_ring *r;
	int error;

	if (arg == NULL)
		return (EFAULT);
	if (nr != 1)
		return (EINVAL);
	error = copyin(arg, &st, sizeof(st));
	if (error != 0)
		return (error);
	for (unsigned int i = 0; i < nitems(st.resv); i++)
		if (st.resv[i] != 0)
			return (EINVAL);
	if (st.buf_group > UINT16_MAX)
		return (EINVAL);
	mtx_lock(&ctx->mtx);
	r = sq_pbuf_ring_find(ctx, (uint16_t)st.buf_group);
	if (r == NULL)
		error = ENOENT;
	else {
		st.head = r->head;
		error = 0;
	}
	mtx_unlock(&ctx->mtx);
	return (error == 0 ? copyout(&st, arg, sizeof(st)) : error);
}

/* ---- application-provided buffers ---- */
/* PROVIDE_BUFFERS: add nbufs buffers to a group.  Returns Linux res. */
static bool
sq_pbuf_group_exists(struct squeue_ctx *ctx, uint16_t bgid)
{

	return (ctx->legacy_pbuf_groups != NULL &&
	    (ctx->legacy_pbuf_groups[bgid / 64] & (1ULL << (bgid % 64))) != 0);
}

/* PROVIDE_BUFFERS: add buffers to a persistent legacy group. */
static int32_t
sq_provide_buffers(struct squeue_ctx *ctx, const struct io_uring_sqe *sqe)
{
	struct sq_pbuf *pb, *tmp;
	struct sq_pbufq pending;
	uint64_t *groups;
	uint32_t nbufs, i, elen, existing, add;
	uint64_t base;
	uint16_t bgid, bid;
	bool need_groups;
	int32_t result;

	nbufs = (uint32_t)sqe->fd;
	elen = sqe->len;
	base = sqe->addr;
	bgid = sqe->buf_group;
	bid = (uint16_t)sqe->off;
	groups = NULL;
	mtx_lock(&ctx->mtx);
	if (sq_pbuf_ring_find(ctx, bgid) != NULL) {
		mtx_unlock(&ctx->mtx);
		return (-EINVAL);
	}
	need_groups = ctx->legacy_pbuf_groups == NULL;
	mtx_unlock(&ctx->mtx);
	if (need_groups)
		groups = mallocarray(1024, sizeof(uint64_t), M_SQUEUE,
		    M_WAITOK | M_ZERO);

	TAILQ_INIT(&pending);
	for (i = 0; i < nbufs; i++) {
		pb = malloc(sizeof(*pb), M_SQUEUE, M_WAITOK);
		pb->bgid = bgid;
		pb->bid = bid + i;
		pb->addr = base + (uint64_t)i * elen;
		pb->len = elen;
		TAILQ_INSERT_TAIL(&pending, pb, entry);
	}

	mtx_lock(&ctx->mtx);
	if (sq_pbuf_ring_find(ctx, bgid) != NULL) {
		result = -EINVAL;
		goto out_unlock;
	}
	if (ctx->legacy_pbuf_groups == NULL) {
		ctx->legacy_pbuf_groups = groups;
		groups = NULL;
	}
	ctx->legacy_pbuf_groups[bgid / 64] |= 1ULL << (bgid % 64);
	existing = 0;
	TAILQ_FOREACH(pb, &ctx->pbufs, entry)
		if (pb->bgid == bgid)
			existing++;
	add = MIN(nbufs, UINT16_MAX - existing);
	add = MIN(add, SQ_MAX_PBUFS - ctx->npbufs);
	if (add == 0) {
		result = existing == UINT16_MAX ? -EOVERFLOW : -ENOMEM;
		goto out_unlock;
	}
	for (i = 0; i < add; i++) {
		pb = TAILQ_FIRST(&pending);
		TAILQ_REMOVE(&pending, pb, entry);
		TAILQ_INSERT_TAIL(&ctx->pbufs, pb, entry);
		ctx->npbufs++;
	}
	result = 0;
out_unlock:
	mtx_unlock(&ctx->mtx);
	TAILQ_FOREACH_SAFE(pb, &pending, entry, tmp) {
		TAILQ_REMOVE(&pending, pb, entry);
		free(pb, M_SQUEUE);
	}
	free(groups, M_SQUEUE);
	return (result);
}

/* REMOVE_BUFFERS: an empty group remains present until ring teardown. */
static int32_t
sq_remove_buffers(struct squeue_ctx *ctx, const struct io_uring_sqe *sqe)
{
	struct sq_pbuf *pb, *tmp;
	uint32_t nbufs, removed = 0;
	uint16_t bgid;

	nbufs = (uint32_t)sqe->fd;
	bgid = sqe->buf_group;
	mtx_lock(&ctx->mtx);
	if (sq_pbuf_ring_find(ctx, bgid) != NULL) {
		mtx_unlock(&ctx->mtx);
		return (-EINVAL);
	}
	if (!sq_pbuf_group_exists(ctx, bgid)) {
		mtx_unlock(&ctx->mtx);
		return (-ENOENT);
	}
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

static int
sq_pbuf_ring_select(struct squeue_ctx *ctx, uint16_t bgid, uint64_t want,
    uint64_t *addr, uint32_t *len, uint32_t *cap, uint16_t *bid,
    struct sq_pbuf_ring **ringp)
{
	struct sq_pbuf_ring *r;
	struct io_uring_buf b;
	uint16_t tail;

	mtx_lock(&ctx->mtx);
	r = sq_pbuf_ring_find(ctx, bgid);
	if (r == NULL) {
		mtx_unlock(&ctx->mtx);
		return (ENOENT);
	}
	tail = atomic_load_acq_16(&r->ring->tail);
	if ((uint16_t)(tail - r->head) == 0 || r->busy != 0) {
		mtx_unlock(&ctx->mtx);
		return (ENOBUFS);
	}
	b = r->ring->bufs[r->head & r->mask];
	if (b.addr == 0 || b.len == 0) {
		mtx_unlock(&ctx->mtx);
		return (EINVAL);
	}
	r->busy++;
	mtx_unlock(&ctx->mtx);
	*addr = b.addr;
	*cap = b.len;
	*len = (want == 0 || want > b.len) ? b.len : (uint32_t)want;
	*bid = b.bid;
	*ringp = r;
	return (0);
}

/*
 * Select (and consume) a provided buffer from a group for a BUFFER_SELECT op.
 * On success rewrites the addr and len out-params to the chosen buffer and
 * returns its id in bid; returns ENOBUFS if the group is empty.
 */
static int
sq_pbuf_select(struct squeue_ctx *ctx, uint16_t bgid, uint64_t want,
    uint64_t *addr, uint32_t *len, uint32_t *cap, uint16_t *bid)
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
		*cap = pb->len;
		*len = (want == 0 || want > pb->len) ? pb->len : (uint32_t)want;
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

int
sq_select_buffer(struct squeue_ctx *ctx, struct sq_req *req, uint64_t want)
{
	int error;

	if (req->pbuf_selected)
		return (0);
	error = sq_pbuf_ring_select(ctx, req->sqe.buf_group, want,
	    &req->pbuf_addr, &req->pbuf_len, &req->pbuf_cap, &req->pbuf_bid,
	    &req->pbuf_ring);
	if (error == ENOENT)
		error = sq_pbuf_select(ctx, req->sqe.buf_group, want,
		    &req->pbuf_addr, &req->pbuf_len, &req->pbuf_cap,
		    &req->pbuf_bid);
	if (error != 0)
		return (error);
	req->pbuf_ring_count = req->pbuf_ring != NULL ? 1 : 0;
	req->pbuf_selected = true;
	req->cflags = IORING_CQE_F_BUFFER |
	    ((uint32_t)req->pbuf_bid << IORING_CQE_BUFFER_SHIFT);
	return (0);
}

void
sq_recycle_buffer(struct sq_req *req)
{

	if (!req->pbuf_selected)
		return;
	if (req->pbuf_ring != NULL) {
		mtx_lock(&req->ctx->mtx);
		KASSERT(req->pbuf_ring->busy > 0, ("pbuf ring busy"));
		req->pbuf_ring->busy--;
		mtx_unlock(&req->ctx->mtx);
		req->pbuf_ring = NULL;
		req->pbuf_ring_count = 0;
	} else
		sq_pbuf_return(req->ctx, req->sqe.buf_group, req->pbuf_bid,
		    req->pbuf_addr, req->pbuf_cap);
	req->pbuf_selected = false;
	req->pbuf_cap = 0;
	req->cflags = 0;
}

uint32_t
sq_consume_buffer(struct sq_req *req, uint32_t consumed)
{
	uint32_t cflags;

	cflags = req->cflags;
	if (req->pbuf_ring != NULL) {
		struct io_uring_buf *b;
		uint32_t left, used;

		mtx_lock(&req->ctx->mtx);
		KASSERT(req->pbuf_ring->busy > 0, ("pbuf ring busy"));
		if (req->pbuf_ring->incremental) {
			b = &req->pbuf_ring->ring->bufs[
			    req->pbuf_ring->head & req->pbuf_ring->mask];
			used = MIN(consumed, req->pbuf_cap);
			left = req->pbuf_cap - used;
			if (left > req->pbuf_ring->min_left_sub_one || used == 0) {
				b->addr = req->pbuf_addr + used;
				b->len = left;
				cflags |= IORING_CQE_F_BUF_MORE;
			} else {
				b->len = 0;
				req->pbuf_ring->head++;
			}
		} else
			req->pbuf_ring->head += req->pbuf_ring_count;
		req->pbuf_ring->busy--;
		mtx_unlock(&req->ctx->mtx);
		req->pbuf_ring = NULL;
		req->pbuf_ring_count = 0;
	}
	req->pbuf_selected = false;
	req->pbuf_cap = 0;
	req->cflags = 0;
	return (cflags);
}

int
sq_select_buffer_batch(struct squeue_ctx *ctx, uint16_t bgid, uint64_t want,
    struct sq_pbuf_desc *bufs, uint32_t maxbufs, uint32_t maxlegacy,
    uint32_t *nbufsp)
{
	struct sq_pbuf *pb, *tmp;
	uint64_t remaining;
	uint32_t n;
	uint16_t next_bid;

	if (bufs == NULL || nbufsp == NULL || maxbufs == 0 ||
	    maxlegacy == 0)
		return (EINVAL);
	n = 0; remaining = want; next_bid = 0;
	mtx_lock(&ctx->mtx);
	{
		struct sq_pbuf_ring *r = sq_pbuf_ring_find(ctx, bgid);
		if (r != NULL) {
			uint16_t tail = atomic_load_acq_16(&r->ring->tail);
			uint32_t avail = MIN((uint32_t)(uint16_t)(tail - r->head),
			    r->entries);
			if (r->busy != 0)
				avail = 0;
			while (n < avail && n < maxbufs &&
			    (want == 0 || remaining != 0)) {
				struct io_uring_buf b =
				    r->ring->bufs[(r->head + n) & r->mask];
				if (b.addr == 0 || b.len == 0)
					break;
				bufs[n].addr = b.addr; bufs[n].cap = b.len;
				bufs[n].len = b.len; bufs[n].bid = b.bid;
				bufs[n].ring = r;
				if (want != 0 && bufs[n].len > remaining)
					bufs[n].len = (uint32_t)remaining;
				if (want != 0) remaining -= bufs[n].len;
				n++;
			}
			if (n != 0) r->busy++;
			mtx_unlock(&ctx->mtx);
			*nbufsp = n;
			return (n == 0 ? ENOBUFS : 0);
		}
	}
	/* Apply the legacy limit while selection still owns the group lock. */
	maxbufs = MIN(maxbufs, maxlegacy);
	TAILQ_FOREACH_SAFE(pb, &ctx->pbufs, entry, tmp) {
		if (pb->bgid != bgid)
			continue;
		if (n != 0 && pb->bid != next_bid)
			break;
		bufs[n].addr = pb->addr; bufs[n].cap = pb->len;
		bufs[n].len = pb->len; bufs[n].bid = pb->bid;
		bufs[n].ring = NULL;
		if (want != 0 && bufs[n].len > remaining)
			bufs[n].len = (uint32_t)remaining;
		next_bid = pb->bid + 1;
		TAILQ_REMOVE(&ctx->pbufs, pb, entry); ctx->npbufs--;
		free(pb, M_SQUEUE);
		if (want != 0) remaining -= bufs[n].len;
		n++;
		if (n == maxbufs || (want != 0 && remaining == 0)) break;
	}
	mtx_unlock(&ctx->mtx); *nbufsp = n;
	return (n == 0 ? ENOBUFS : 0);
}

void
sq_return_buffer_batch(struct squeue_ctx *ctx, uint16_t bgid,
    const struct sq_pbuf_desc *bufs, uint32_t nbufs)
{
	uint32_t i;

	if (nbufs != 0 && bufs[0].ring != NULL) {
		mtx_lock(&ctx->mtx);
		KASSERT(bufs[0].ring->busy > 0, ("pbuf batch busy"));
		bufs[0].ring->busy--;
		mtx_unlock(&ctx->mtx);
		return;
	}
	for (i = nbufs; i-- != 0;)
		sq_pbuf_return(ctx, bgid, bufs[i].bid, bufs[i].addr, bufs[i].cap);
}

bool
sq_commit_buffer_batch(struct squeue_ctx *ctx, uint16_t bgid,
    const struct sq_pbuf_desc *bufs, uint32_t nbufs, uint32_t used,
    uint32_t consumed)
{
	bool more;

	more = false;
	if (nbufs != 0 && bufs[0].ring != NULL) {
		struct sq_pbuf_ring *r;
		uint32_t i, left, take;

		r = bufs[0].ring;
		mtx_lock(&ctx->mtx);
		KASSERT(r->busy > 0, ("pbuf batch busy"));
		if (r->incremental) {
			left = consumed;
			for (i = 0; i < used && i < nbufs; i++) {
				struct io_uring_buf *b;

				b = &r->ring->bufs[r->head & r->mask];
				take = MIN(left, bufs[i].cap);
				if (bufs[i].cap - take > r->min_left_sub_one ||
				    take == 0) {
					b->addr = bufs[i].addr + take;
					b->len = bufs[i].cap - take;
					more = true;
					break;
				}
				b->len = 0;
				r->head++;
				left -= take;
			}
		} else
			r->head += used;
		r->busy--;
		mtx_unlock(&ctx->mtx);
	} else if (used < nbufs)
		sq_return_buffer_batch(ctx, bgid, bufs + used, nbufs - used);
	return (more);
}

bool
sq_buffer_group_empty(struct squeue_ctx *ctx, uint16_t bgid)
{
	struct sq_pbuf *pb; bool empty = true;

	mtx_lock(&ctx->mtx);
	{
		struct sq_pbuf_ring *r = sq_pbuf_ring_find(ctx, bgid);
		if (r != NULL)
			empty = (uint16_t)(atomic_load_acq_16(&r->ring->tail) -
			    r->head) == 0;
	}
	TAILQ_FOREACH(pb, &ctx->pbufs, entry)
		if (pb->bgid == bgid) { empty = false; break; }
	mtx_unlock(&ctx->mtx);
	return (empty);
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
sq_nop(struct squeue_ctx *ctx, const struct io_uring_sqe *sqe,
    struct thread *td)
{
	struct sq_buf_table *table;
	struct sq_file_node *fnode;
	struct file *fp;
	uint32_t flags;
	int error;

	flags = sqe->nop_flags;
	if ((flags & IORING_NOP_FILE) != 0) {
		fnode = NULL;
		if ((flags & IORING_NOP_FIXED_FILE) != 0) {
			sx_slock(&ctx->files_sx);
			fnode = sq_file_node_hold_locked(ctx, sqe->fd);
			sx_sunlock(&ctx->files_sx);
			if (fnode == NULL)
				return (sq_err(ctx, EBADF));
			fp = fnode->fp;
			MPASS(fhold(fp));
		} else {
			error = fget(td, sqe->fd, &cap_no_rights, &fp);
			if (error != 0)
				return (sq_err(ctx, error));
		}
		fdrop(fp, td);
		sq_file_node_rele(fnode, td);
	}
	if ((flags & IORING_NOP_FIXED_BUFFER) != 0) {
		mtx_lock(&ctx->mtx);
		table = ctx->reg_bufs;
		if (table != NULL)
			refcount_acquire(&table->refs);
		mtx_unlock(&ctx->mtx);
		if (table == NULL || sqe->buf_index >= table->count ||
		    table->nodes[sqe->buf_index] == NULL) {
			sq_buf_table_rele(table);
			return (sq_err(ctx, EFAULT));
		}
		sq_buf_table_rele(table);
	}
	return ((flags & IORING_NOP_INJECT_RESULT) != 0 ?
	    (int32_t)sqe->len : 0);
}

static int32_t
sq_issue_inline(struct squeue_ctx *ctx, struct sq_req *req,
    struct thread *td)
{
	const struct io_uring_sqe *sqe = &req->sqe;
	struct file *fp;
	struct uio *uiop;
	off_t off;
	int error;
	bool cur;

	off = (off_t)sqe->off;
	cur = (sqe->off == (uint64_t)-1);
	td->td_retval[0] = 0;	/* zero-returning ops report 0, not a stale count */

	/* Core reads use the shared selector.  ABI-specific network opcodes
	 * select in their front-end issue hook. */
	if ((req->sqe_flags & IOSQE_BUFFER_SELECT) != 0 &&
	    (sqe->opcode == IORING_OP_READ || sqe->opcode == IORING_OP_READV)) {
		error = sq_select_buffer(ctx, req, sqe->opcode == IORING_OP_READV ?
		    req->pbuf_want : sqe->len);
		if (error != 0)
			return (sq_err(ctx, error));
	}

	switch (sqe->opcode) {
	case IORING_OP_NOP:
		return (sq_nop(ctx, sqe, td));
	case IORING_OP_POLL_REMOVE:
		return (sq_poll_remove_update(ctx, req, td));
	case IORING_OP_PROVIDE_BUFFERS:
		return (sq_provide_buffers(ctx, sqe));
	case IORING_OP_REMOVE_BUFFERS:
		return (sq_remove_buffers(ctx, sqe));
	case IORING_OP_FILES_UPDATE:
		/* off=offset, len=nr, addr=fd array */
		if ((uint32_t)off == IORING_FILE_INDEX_ALLOC)
			return (sq_result(ctx, td, sq_do_files_update_alloc(ctx,
			    sqe->addr, sqe->len, td)));
		return (sq_result(ctx, td, sq_do_files_update(ctx, (uint32_t)off,
		    sqe->addr, 0, sqe->len, td)));
	case IORING_OP_MSG_RING:
		return (sq_msg_ring(ctx, req, td));
	case IORING_OP_NOP128:
		return (0);		/* NOP for SQE128 rings */
	case IORING_OP_FIXED_FD_INSTALL: {
		struct sq_file_node *node = NULL;
		int newfd;

		/* Install a registered descriptor into the normal table. */
		error = sq_fixed_install(ctx, td, sqe->fd,
		    (sqe->install_fd_flags & IORING_FIXED_FD_NO_CLOEXEC) != 0 ?
		    0 : O_CLOEXEC, &newfd, &node);
		sq_file_node_rele(node, td);
		if (error != 0)
			return (sq_err(ctx, error));
		td->td_retval[0] = newfd;
		return ((int32_t)newfd);
	}
	case IORING_OP_LINK_TIMEOUT:
		/* Valid linked deadlines are detached during chain preparation. */
		return (sq_err(ctx, EINVAL));
	case IORING_OP_READ:
	case IORING_OP_WRITE:
		return (sq_rw1(ctx, td, sqe->fd,
		    (void *)(uintptr_t)(req->pbuf_selected ? req->pbuf_addr : sqe->addr),
		    req->pbuf_selected ? req->pbuf_len : sqe->len, off, cur,
		    sqe->opcode == IORING_OP_WRITE, req->rw_foflags));
	case IORING_OP_READ_FIXED:
	case IORING_OP_WRITE_FIXED:
	case IORING_OP_READV_FIXED:
	case IORING_OP_WRITEV_FIXED: {
		bool wr = sqe->opcode == IORING_OP_WRITE_FIXED ||
		    sqe->opcode == IORING_OP_WRITEV_FIXED;

		error = sq_fixed_prepare(ctx, req);
		if (error != 0)
			return (sq_err(ctx, error));
		uiop = cloneuio(req->buf_uio);
		error = kern_rwv(td, sqe->fd, uiop, cur ? -1 : off, wr,
		    req->rw_foflags);
		if (!wr)
			sq_fixed_dirty(req);
		free(uiop, M_IOV);
		return (sq_result(ctx, td, error));
	}
	case IORING_OP_READ_MULTISHOT: {
		int32_t r;

		if ((req->sqe_flags & IOSQE_BUFFER_SELECT) == 0)
			return (-EINVAL);
		for (;;) {
			error = sq_select_buffer(ctx, req, 0);
			if (error != 0)
				return (sq_err(ctx, ENOBUFS));
			r = sq_rw1(ctx, td, sqe->fd,
			    (void *)(uintptr_t)req->pbuf_addr, req->pbuf_len, 0,
			    true, false, req->rw_foflags);
			if (r > 0) {
				uint32_t cflags;

				cflags = sq_consume_buffer(req, (uint32_t)r);
				mtx_lock(&ctx->mtx);
				sq_post_multishot_cqe(ctx, req, r,
				    cflags | IORING_CQE_F_MORE);
				mtx_unlock(&ctx->mtx);
				continue;
			}
			sq_recycle_buffer(req);
			return (r);
		}
	}

	case IORING_OP_READV:
	case IORING_OP_WRITEV: {
		bool wr = sqe->opcode == IORING_OP_WRITEV;

		if (req->pbuf_selected)
			return (sq_rw1(ctx, td, sqe->fd,
			    (void *)(uintptr_t)req->pbuf_addr, req->pbuf_len, off,
			    cur, false, req->rw_foflags));
		error = copyinuio((void *)(uintptr_t)sqe->addr, sqe->len, &uiop);
		if (error != 0)
			return (sq_err(ctx, error));
		error = kern_rwv(td, sqe->fd, uiop, cur ? -1 : off, wr,
		    req->rw_foflags);
		free(uiop, M_IOV);
		return (sq_result(ctx, td, error));
	}
	case IORING_OP_FSYNC:
		/* Linux resolves and pins the file before range validation. */
		error = fget(td, sqe->fd, &cap_fsync_rights, &fp);
		if (error != 0)
			return (sq_err(ctx, error));
		if (off < 0)
			error = EINVAL;
		else if (fp->f_type != DTYPE_VNODE)
			error = EINVAL;
		else
			error = kern_fsync_fp(td, fp,
			    (sqe->fsync_flags & IORING_FSYNC_DATASYNC) == 0);
		fdrop(fp, td);
		return (sq_result(ctx, td, error));
	case IORING_OP_CLOSE:
		if (sqe->file_index != 0)
			error = sq_close_direct_fd(ctx, td, sqe->file_index);
		else
			error = kern_close(td, sqe->fd);
		return (sq_result(ctx, td, error));
	case IORING_OP_FTRUNCATE:
		/* Linux resolves and pins its request file before validating the
		 * length.  Let that frontend preserve the resulting EBADF/EINVAL
		 * ordering; native squeue retains the native syscall contract. */
		if (ctx->issue_ext != NULL)
			return (SQ_NOTHANDLED);
		return (sq_result(ctx, td, kern_ftruncate(td, sqe->fd, off)));
	case IORING_OP_FALLOCATE:
		/*
		 * Linux mode decoding and Linux vfs_fallocate() errno precedence
		 * belong to its front end.  Native squeue exposes plain allocation.
		 */
		if (ctx->issue_ext != NULL)
			return (SQ_NOTHANDLED);
		if (sqe->len != 0)
			return (sq_err(ctx, EOPNOTSUPP));
		return (sq_result(ctx, td, kern_posix_fallocate(td, sqe->fd, off,
		    (off_t)sqe->addr)));
	case IORING_OP_FADVISE: {
		off_t len = sqe->addr != 0 ? (off_t)sqe->addr : (off_t)sqe->len;

		/* Linux file/error ordering differs from the native syscall. */
		if (ctx->issue_ext != NULL)
			return (SQ_NOTHANDLED);
		return (sq_result(ctx, td, kern_posix_fadvise(td, sqe->fd, off, len,
		    sqe->fadvise_advice)));
	}
	case IORING_OP_TIMEOUT_REMOVE:
		return (sq_timeout_remove_update(ctx, req));
	case IORING_OP_ASYNC_CANCEL: {
		const uint32_t cancel_mask = IORING_ASYNC_CANCEL_ALL |
		    IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_ANY |
		    IORING_ASYNC_CANCEL_FD_FIXED | IORING_ASYNC_CANCEL_USERDATA |
		    IORING_ASYNC_CANCEL_OP;
		struct sq_cancel_match match = { .user_data = sqe->addr };
		bool fixed, all;
		int result;

		if (sqe->off != 0 || sqe->splice_fd_in != 0 ||
		    (sqe->cancel_flags & ~cancel_mask) != 0)
			return (sq_err(ctx, EINVAL));
		match.flags = sqe->cancel_flags;
		if ((match.flags & IORING_ASYNC_CANCEL_ANY) != 0 &&
		    (match.flags & (IORING_ASYNC_CANCEL_FD |
		    IORING_ASYNC_CANCEL_OP)) != 0)
			return (sq_err(ctx, EINVAL));
		if ((match.flags & IORING_ASYNC_CANCEL_OP) != 0) {
			if (sqe->len >= IORING_OP_LAST)
				return (sq_err(ctx, EINVAL));
			match.opcode = (uint8_t)sqe->len;
		}
		if ((match.flags & IORING_ASYNC_CANCEL_FD) != 0) {
			fixed = (match.flags & IORING_ASYNC_CANCEL_FD_FIXED) != 0 ||
			    (req->sqe_flags & IOSQE_FIXED_FILE) != 0;
			if (fixed) {
				sx_slock(&ctx->files_sx);
				if (ctx->reg_files == NULL || sqe->fd < 0 ||
				    (uint32_t)sqe->fd >= ctx->reg_nfiles ||
				    ctx->reg_files[sqe->fd] == NULL ||
				    !fhold(ctx->reg_files[sqe->fd]->fp))
					match.fp = NULL;
				else
					match.fp = ctx->reg_files[sqe->fd]->fp;
				sx_sunlock(&ctx->files_sx);
				if (match.fp == NULL)
					return (sq_err(ctx, EBADF));
			} else {
				result = fget(td, sqe->fd, &cap_no_rights, &match.fp);
				if (result != 0)
					return (sq_err(ctx, result));
			}
		}
		all = (match.flags & (IORING_ASYNC_CANCEL_ALL |
		    IORING_ASYNC_CANCEL_ANY)) != 0;
		mtx_lock(&ctx->mtx);
		result = sq_cancel_match(ctx, &match, false, all, req);
		mtx_unlock(&ctx->mtx);
		if (match.fp != NULL)
			fdrop(match.fp, td);
		return (result);
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
    int install_flags, int *fdp, struct sq_file_node **nodep)
{
	struct sq_file_node *node;
	struct filecaps caps;
	struct file *fp;
	bool acquired;
	int error;

	filecaps_init(&caps);
	acquired = false;
	node = *nodep;
	if (node == NULL) {
		sx_slock(&ctx->files_sx);
		node = sq_file_node_hold_locked(ctx, idx);
		sx_sunlock(&ctx->files_sx);
		if (node == NULL)
			return (EBADF);
		*nodep = node;
		acquired = true;
	}
	fp = node->fp;
	if (!fhold(fp)) {
		if (acquired) {
			*nodep = NULL;
			sq_file_node_rele(node, td);
		}
		return (EBADF);
	}
	(void)filecaps_copy(&node->caps, &caps, true);
	error = finstall(td, fp, fdp, install_flags, &caps);
	if (error != 0)
		filecaps_free(&caps);
	/* finstall acquires the descriptor's own reference on success. */
	fdrop(fp, td);
	return (error);
}

/* Reinstall a request's captured ambient file with its original rights.
 * A parked EPOLL_WAIT stays bound to its epoll instance across fd reuse. */
int
sq_install_held_fd(struct sq_req *req, struct thread *td, int *fdp)
{
	struct filecaps caps;
	int error;

	if (req->poll_capture_error != 0)
		return (req->poll_capture_error);
	if (req->match_fp == NULL || req->poll_caps == NULL ||
	    !fhold(req->match_fp))
		return (EBADF);
	filecaps_init(&caps);
	(void)filecaps_copy(req->poll_caps, &caps, true);
	error = finstall(td, req->match_fp, fdp, 0, &caps);
	if (error != 0)
		filecaps_free(&caps);
	fdrop(req->match_fp, td);
	return (error);
}

/* Resolve a secondary input slot for a front-end opcode.  The temporary fd
 * owns the file and captured capabilities until the caller closes it. */
int
sq_install_registered_fd(struct squeue_ctx *ctx, struct thread *td,
    int index, int *fdp)
{
	struct sq_file_node *node;
	int error;

	node = NULL;
	error = sq_fixed_install(ctx, td, index, 0, fdp, &node);
	if (node != NULL)
		sq_file_node_rele(node, td);
	return (error);
}

/*
 * Install a held source registered-file reference in a target ring.  The
 * source slot remains registered; the extra reference and a copy of its
 * captured Capsicum rights become the target slot's ownership on success.
 */
static int
sq_msg_install_file(struct squeue_ctx *src, struct squeue_ctx *dst,
    uint32_t src_idx, uint32_t dst_idx, struct thread *td, int32_t *resultp)
{
	struct sq_file_node *srcnode, *newnode, *oldnode;
	struct filecaps caps;
	struct file *fp;
	uint32_t i, slot;
	bool alloc;
	int error;

	filecaps_init(&caps);
	srcnode = newnode = oldnode = NULL;
	sx_slock(&src->files_sx);
	srcnode = sq_file_node_hold_locked(src, src_idx);
	if (srcnode != NULL && fhold(srcnode->fp)) {
		fp = srcnode->fp;
		(void)filecaps_copy(&srcnode->caps, &caps, true);
		error = 0;
	} else {
		fp = NULL;
		error = EBADF;
	}
	sx_sunlock(&src->files_sx);
	if (error != 0)
		goto out;
	newnode = sq_file_node_adopt(dst, fp, &caps, 0);
	fp = NULL;

	alloc = dst_idx == IORING_FILE_INDEX_ALLOC;
	sx_xlock(&dst->files_sx);
	if (dst->reg_files == NULL) {
		error = ENXIO;
		goto unlock;
	}
	if (alloc) {
		slot = dst->file_alloc_hint;
		for (i = 0; i < dst->file_alloc_end - dst->file_alloc_start; i++) {
			if (slot >= dst->file_alloc_end)
				slot = dst->file_alloc_start;
			if (dst->reg_files[slot] == NULL)
				break;
			slot++;
		}
		if (i == dst->file_alloc_end - dst->file_alloc_start) {
			error = ENFILE;
			goto unlock;
		}
	} else {
		if (dst_idx == 0 || dst_idx - 1 >= dst->reg_nfiles) {
			error = EINVAL;
			goto unlock;
		}
		slot = dst_idx - 1;
	}
	oldnode = dst->reg_files[slot];
	dst->reg_files[slot] = newnode;
	newnode = NULL;
	if (alloc) {
		dst->file_alloc_hint = slot + 1;
		if (dst->file_alloc_hint >= dst->file_alloc_end)
			dst->file_alloc_hint = dst->file_alloc_start;
	}
	*resultp = alloc ? (int32_t)slot : 0;
	error = 0;
unlock:
	sx_xunlock(&dst->files_sx);
out:
	if (fp != NULL)
		fdrop(fp, td);
	filecaps_free(&caps);
	sq_file_node_rele(srcnode, td);
	sq_file_node_rele(newnode, td);
	sq_file_node_rele(oldnode, td);
	return (error);
}

/* Linux-compatible MSG_DATA and registered-file transfer semantics. */
static int32_t
sq_msg_ring(struct squeue_ctx *ctx, struct sq_req *req, struct thread *td)
{
	const struct io_uring_sqe *sqe;
	struct squeue_ctx *tctx;
	struct file *tfp;
	uint32_t flags, src_idx;
	int32_t result;
	bool posted;
	int error;

	sqe = &req->sqe;
	error = fget(td, sqe->fd, &cap_no_rights, &tfp);
	if (error != 0)
		return (sq_err(ctx, error));
	if (tfp->f_type != DTYPE_IORING) {
		fdrop(tfp, td);
		return (ctx->is_linux ? -SQ_LINUX_EBADFD : sq_err(ctx, EBADF));
	}
	tctx = tfp->f_data;
	flags = sqe->msg_ring_flags;
	src_idx = (uint32_t)sqe->addr3;
	switch (sqe->addr) {
	case IORING_MSG_DATA:
		if (src_idx != 0 ||
		    (flags & ~IORING_MSG_RING_FLAGS_PASS) != 0 ||
		    ((flags & IORING_MSG_RING_FLAGS_PASS) == 0 &&
		    sqe->file_index != 0)) {
			result = sq_err(ctx, EINVAL);
			break;
		}
		mtx_lock(&tctx->mtx);
		if (tctx->disabled) {
			mtx_unlock(&tctx->mtx);
			result = ctx->is_linux ? -SQ_LINUX_EBADFD :
			    sq_err(ctx, EBADF);
			break;
		}
		posted = sq_post_cqe_impl(tctx, sqe->off, (int32_t)sqe->len,
		    (flags & IORING_MSG_RING_FLAGS_PASS) != 0 ?
		    sqe->file_index : 0);
		if (posted)
			sq_wake(tctx);
		mtx_unlock(&tctx->mtx);
		result = posted ? 0 : sq_err(ctx, EOVERFLOW);
		break;
	case IORING_MSG_SEND_FD:
		if (sqe->len != 0 || tctx == ctx) {
			result = sq_err(ctx, EINVAL);
			break;
		}
		mtx_lock(&tctx->mtx);
		if (tctx->disabled) {
			mtx_unlock(&tctx->mtx);
			result = ctx->is_linux ? -SQ_LINUX_EBADFD :
			    sq_err(ctx, EBADF);
			break;
		}
		mtx_unlock(&tctx->mtx);
		error = sq_msg_install_file(ctx, tctx, src_idx,
		    sqe->file_index, td, &result);
		if (error != 0) {
			result = sq_err(ctx, error);
			break;
		}
		if ((flags & IORING_MSG_RING_CQE_SKIP) != 0)
			break;
		mtx_lock(&tctx->mtx);
		posted = sq_post_cqe_impl(tctx, sqe->off, result, 0);
		if (posted)
			sq_wake(tctx);
		mtx_unlock(&tctx->mtx);
		if (!posted)
			result = sq_err(ctx, EOVERFLOW);
		break;
	default:
		result = sq_err(ctx, EINVAL);
		break;
	}
	fdrop(tfp, td);
	return (result);
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
sq_issue_op_impl(struct squeue_ctx *ctx, struct sq_req *req, struct thread *td)
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

	/* These Linux opcodes do not consume a request file.  IOSQE_FIXED_FILE
	 * is ignored by Linux for them, even when sqe.fd has another meaning. */
	if (ctx->is_linux && (req->sqe_flags & IOSQE_FIXED_FILE) != 0 &&
	    (req->opcode == IORING_OP_FUTEX_WAIT ||
	    req->opcode == IORING_OP_FUTEX_WAKE ||
	    req->opcode == IORING_OP_FUTEX_WAITV ||
	    req->opcode == IORING_OP_WAITID ||
	    req->opcode == IORING_OP_MADVISE ||
	    req->opcode == IORING_OP_EPOLL_CTL ||
	    req->opcode == IORING_OP_PROVIDE_BUFFERS ||
	    req->opcode == IORING_OP_REMOVE_BUFFERS ||
	    req->opcode == IORING_OP_PIPE ||
	    req->opcode == IORING_OP_SOCKET))
		return (sq_dispatch(ctx, req, td));

	if ((req->sqe_flags & IOSQE_FIXED_FILE) == 0 ||
	    req->opcode == IORING_OP_FIXED_FD_INSTALL ||
	    req->opcode == IORING_OP_ASYNC_CANCEL) {
		if (req->poll_use_held_fd &&
		    req->opcode != IORING_OP_EPOLL_WAIT) {
			int savedfd;

			error = sq_install_held_fd(req, td, &tmpfd);
			if (error != 0)
				return (sq_err(ctx, error));
			savedfd = req->sqe.fd;
			req->sqe.fd = tmpfd;
			res = sq_dispatch(ctx, req, td);
			req->sqe.fd = savedfd;
			(void)kern_close(td, tmpfd);
			return (res);
		}
		return (sq_dispatch(ctx, req, td));
	}

	error = sq_fixed_install(ctx, td, req->sqe.fd, 0, &tmpfd,
	    &req->file_node);
	if (error != 0)
		return (sq_err(ctx, error));
	tmp = *req;
	tmp.sqe.fd = tmpfd;
	tmp.sqe_flags &= ~IOSQE_FIXED_FILE;
	/* The fixed file is already resolved into tmpfd.  Do not let an
	 * extension such as EPOLL_WAIT perform ambient held-file resolution
	 * again when a fast-poll retry reaches the front end. */
	tmp.poll_use_held_fd = false;
	tmp.cflags = 0;
	res = sq_dispatch(ctx, &tmp, td);
	req->cflags = tmp.cflags;	/* carry back a BUFFER_SELECT id */
	req->net_mshot_remaining = tmp.net_mshot_remaining;
	/* Fixed-buffer preparation can acquire resources in the dispatch copy.
	 * The tracked request, not this stack copy, must release them. */
	req->buf_table = tmp.buf_table;
	req->buf_uio = tmp.buf_uio;
	(void)kern_close(td, tmpfd);
	return (res);
}

static int32_t
sq_issue_op(struct squeue_ctx *ctx, struct sq_req *req, struct thread *td)
{
	struct ucred *saved;
	int32_t result;

	saved = td->td_ucred;
	if (req->cred != NULL)
		td->td_ucred = req->cred;
	result = sq_issue_op_impl(ctx, req, td);
	td->td_ucred = saved;
	return (result);
}

/* Decode either a userspace timespec or the immediate nanosecond form. */
static int
sq_timeout_arg(uint64_t arg, uint32_t flags, struct __kernel_timespec *ts)
{

	if ((flags & IORING_TIMEOUT_IMMEDIATE_ARG) != 0) {
		if (arg > INT64_MAX)
			return (EINVAL);
		ts->tv_sec = arg / 1000000000ULL;
		ts->tv_nsec = arg % 1000000000ULL;
		return (0);
	}
	return (copyin((void *)(uintptr_t)arg, ts, sizeof(*ts)));
}

/* Read the deadline before any member of its chain can have side effects. */
static int
sq_link_prepare(struct sq_req *lt)
{
	struct io_uring_sqe *q = &lt->sqe;
	struct __kernel_timespec ts;
	uint32_t clocks = IORING_TIMEOUT_BOOTTIME | IORING_TIMEOUT_REALTIME;
	int error;

	if (q->len != 1 || q->off != 0 || q->buf_index != 0 ||
	    q->splice_fd_in != 0 ||
	    (q->flags & ~(IOSQE_FIXED_FILE | IOSQE_IO_LINK | IOSQE_IO_HARDLINK | IOSQE_ASYNC |
	    IOSQE_CQE_SKIP_SUCCESS)) != 0 ||
	    (q->timeout_flags & ~(IORING_TIMEOUT_ABS | clocks |
	    IORING_TIMEOUT_ETIME_SUCCESS | IORING_TIMEOUT_MULTISHOT |
	    IORING_TIMEOUT_IMMEDIATE_ARG)) != 0 ||
	    (q->timeout_flags & clocks) == clocks ||
	    (q->timeout_flags & (IORING_TIMEOUT_ABS | IORING_TIMEOUT_MULTISHOT)) ==
	    (IORING_TIMEOUT_ABS | IORING_TIMEOUT_MULTISHOT))
		return (EINVAL);
	error = sq_timeout_arg(q->addr, q->timeout_flags, &ts);
	if (error != 0)
		return (error);
	if (ts.tv_sec < 0 || ts.tv_nsec < 0)
		return (EINVAL);
	if (ts.tv_sec > INT64_MAX - ts.tv_nsec / 1000000000) {
		ts.tv_sec = INT64_MAX;
		ts.tv_nsec = 999999999;
	} else {
		ts.tv_sec += ts.tv_nsec / 1000000000;
		ts.tv_nsec %= 1000000000;
	}
	lt->timeout_sec = ts.tv_sec;
	lt->timeout_nsec = ts.tv_nsec;
	return (0);
}

static void
sq_link_arm(struct sq_req *req)
{
	struct squeue_ctx *ctx = req->ctx;
	struct sq_req *lt = req->link_timeout;
	struct timespec ts, now;
	sbintime_t delay;

	mtx_assert(&ctx->mtx, MA_OWNED);
	if (lt == NULL || lt->state != SQ_ST_NEW)
		return;
	ts.tv_sec = lt->timeout_sec;
	ts.tv_nsec = lt->timeout_nsec;
	if (lt->sqe.timeout_flags & IORING_TIMEOUT_ABS) {
		if (lt->sqe.timeout_flags & IORING_TIMEOUT_REALTIME)
			getnanotime(&now);
		else
			getnanouptime(&now);
		timespecsub(&ts, &now, &ts);
		if (ts.tv_sec < 0)
			timespecclear(&ts);
	}
	delay = tstosbt_sat(ts);
	/* Clamp the sum as well as the conversion before callout adds uptime. */
	delay = MIN(delay, SBT_MAX - sbinuptime());
	lt->state = SQ_ST_ARMED;
	TAILQ_INSERT_TAIL(&ctx->pending, lt, entry);
	ctx->npending++;
	callout_reset_sbt(&lt->co, delay, 0, sq_link_timeout_cb, lt, 0);
}

static void
sq_link_timeout_cb(void *arg)
{
	struct sq_req *lt = arg, *target = lt->link_target;
	struct squeue_ctx *ctx = lt->ctx;
	int error;
	bool linux_external;

	mtx_assert(&ctx->mtx, MA_OWNED);
	if (lt->state != SQ_ST_ARMED || target == NULL)
		return;
	/* Detach before cancellation can finish the target or another deadline. */
	linux_external = ctx->is_linux && target->ext_cancel != NULL &&
	    (target->opcode == IORING_OP_FUTEX_WAIT ||
	    target->opcode == IORING_OP_FUTEX_WAITV ||
	    target->opcode == IORING_OP_WAITID);
	target->link_timeout = NULL;
	lt->link_target = NULL;
	error = sq_cancel_req(target);
	lt->res = error == 0 ? (linux_external ? 1 : sq_etime(ctx)) :
	    sq_err(ctx, error);
	lt->state = SQ_ST_READY;
	TAILQ_REMOVE(&ctx->pending, lt, entry);
	ctx->npending--;
	TAILQ_INSERT_TAIL(&ctx->ready, lt, entry);
	sq_post_cqe(ctx, lt->user_data, lt->res, 0);
	lt->posted = true;
	sq_wake(ctx);
}

/* ---- asynchronous opcodes ---- */
static int
sq_timeout_remove_update(struct squeue_ctx *ctx, struct sq_req *update)
{
	const struct io_uring_sqe *sqe = &update->sqe;
	struct sq_req *target;
	struct timespec ts, now;
	struct timeval tv;
	bool linked;
	int error, ticks;

	if (sqe->len != 0 || sqe->buf_index != 0 || sqe->splice_fd_in != 0)
		return (sq_err(ctx, EINVAL));
	if ((sqe->timeout_flags & IORING_TIMEOUT_UPDATE) == 0) {
		struct sq_cancel_match match = { .user_data = sqe->addr };

		mtx_lock(&ctx->mtx);
		error = sq_cancel_match(ctx, &match, true, false, update);
		mtx_unlock(&ctx->mtx);
		return (error);
	}

	linked = (sqe->timeout_flags & IORING_LINK_TIMEOUT_UPDATE) != 0;
	ts.tv_sec = update->timeout_sec;
	ts.tv_nsec = update->timeout_nsec;
	if ((sqe->timeout_flags & IORING_TIMEOUT_ABS) != 0) {
		getnanouptime(&now);
		timespecsub(&ts, &now, &ts);
		if (ts.tv_sec < 0)
			timespecclear(&ts);
	}
	TIMESPEC_TO_TIMEVAL(&tv, &ts);
	ticks = tvtohz(&tv);

	error = ENOENT;
	mtx_lock(&ctx->mtx);
	TAILQ_FOREACH(target, &ctx->pending, entry) {
		if (target->user_data != sqe->addr ||
		    target->opcode != (linked ? IORING_OP_LINK_TIMEOUT :
		    IORING_OP_TIMEOUT))
			continue;
		callout_stop(&target->co);
		target->timeout_sec = update->timeout_sec;
		target->timeout_nsec = update->timeout_nsec;
		target->timeout_ticks = ticks;
		target->timeout_repeats = 0;
		target->tmo_count = false;
		if (linked)
			callout_reset(&target->co, ticks, sq_link_timeout_cb, target);
		else
			callout_reset(&target->co, ticks, sq_timeout_cb, target);
		error = 0;
		break;
	}
	mtx_unlock(&ctx->mtx);
	return (error == 0 ? 0 : sq_err(ctx, error));
}

static void
sq_timeout_cb(void *arg)
{
	struct sq_req *req = arg;
	struct squeue_ctx *ctx = req->ctx;

	mtx_assert(&ctx->mtx, MA_OWNED);	/* callout_init_mtx */
	if (req->state != SQ_ST_ARMED)
		return;				/* cancelled just ahead of us */
	if ((req->sqe.timeout_flags & IORING_TIMEOUT_MULTISHOT) != 0 &&
	    (req->timeout_repeats == 0 || --req->timeout_repeats != 0)) {
		sq_post_cqe(ctx, req->user_data, sq_etime(ctx), IORING_CQE_F_MORE);
		callout_reset(&req->co, req->timeout_ticks, sq_timeout_cb, req);
		sq_wake(ctx);
		return;
	}
	sq_finish_link(req);
	req->state = SQ_ST_READY;
	req->res = sq_etime(ctx);	/* ETIME_SUCCESS affects link policy only */
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
	bool readied = false;

	mtx_assert(&ctx->mtx, MA_OWNED);
	restart:
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
		sq_finish_link(req);
		readied = true;
		goto restart;
	}
	/*
	 * Wake a waiter so it converts the readied timeout(s): the caller that
	 * advanced cq_count usually will, but a count timeout satisfied at arm
	 * time (or by a peer thread) has no such caller, which would otherwise
	 * strand it before a sole waiter on another thread.
	 */
	if (readied)
		sq_wake(ctx);
}

/*
 * Arm an asynchronous op (TIMEOUT).  Returns 0 on success (request now owns
 * itself on the pending list), or a negative Linux errno to complete with.
 */
static int32_t
sq_arm_async(struct squeue_ctx *ctx, struct sq_req *req, struct thread *td)
{
	const struct io_uring_sqe *sqe = &req->sqe;
	struct timespec ts, now;
	struct timeval tv;
	uint32_t flags;
	int error, ticks;

	if (sqe->opcode == IORING_OP_POLL_ADD) {
		if (!ctx->is_linux && IN_CAPABILITY_MODE(td) &&
		    (req->sqe_flags & IOSQE_FIXED_FILE) == 0)
			return (sq_err(ctx, ENOTCAPABLE));
		/*
		 * Arm a poll: register a readiness knote on the ring's kqueue
		 * and record the request on ctx->polls; sq_poll_scan resolves it
		 * when the knote fires.  IORING_POLL_ADD_MULTI keeps the poll
		 * armed and posts an F_MORE CQE per readiness (multishot).  The
		 * poll-update variants are not supported.
		 */
		/* Linux 6.18 accepts only MULTI for POLL_ADD.  LEVEL is
		 * declared in UAPI but still rejected by io_poll_add_prep(). */
		if ((sqe->len & ~IORING_POLL_ADD_MULTI) != 0)
			return (-EINVAL);
		/* Linux ring descriptors terminate even a MULTI poll at first readiness. */
		req->multishot = (sqe->len & IORING_POLL_ADD_MULTI) != 0 &&
		    !req->poll_ring_target;
		error = sq_kq_arm(ctx, req, td);	/* outside mtx: may sleep */
		if (error != 0)
			return (sq_err(ctx, error));
		mtx_lock(&ctx->mtx);
		if (req->cancel_requested) {
			mtx_unlock(&ctx->mtx);
			sx_xunlock(&ctx->kq_sx);
			if (req->poll_id != 0)
				sq_kq_del_req(req, td);
			else
				sq_kq_del(ctx, req->sqe.fd, sq_kq_filter(req), td);
			return (sq_err(ctx, ECANCELED));
		}
		sq_unissue(req);
		req->state = SQ_ST_ARMED;
		req->on_poll = true;
		TAILQ_INSERT_TAIL(&ctx->polls, req, entry);
		ctx->npolls++;
		/*
		 * Wake any thread that went to sleep on this ring when npolls was
		 * 0 (the msleep path): it must re-evaluate and switch to the
		 * poll-scan path, otherwise nobody services this poll and its
		 * completion is never delivered to that waiter.
		 */
		sq_wake(ctx);
		mtx_unlock(&ctx->mtx);
		sx_xunlock(&ctx->kq_sx);
		return (0);
	}

	KASSERT(sqe->opcode == IORING_OP_TIMEOUT, ("not a timeout"));
	flags = sqe->timeout_flags;
	ts.tv_sec = req->timeout_sec;
	ts.tv_nsec = req->timeout_nsec;

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
	req->timeout_ticks = ticks;
	if ((flags & IORING_TIMEOUT_MULTISHOT) != 0)
		req->timeout_repeats = (uint32_t)sqe->off;

	mtx_lock(&ctx->mtx);
	if (req->cancel_requested) {
		mtx_unlock(&ctx->mtx);
		return (sq_err(ctx, ECANCELED));
	}
	sq_unissue(req);
	req->state = SQ_ST_ARMED;
	if (sqe->off != 0 && (flags & IORING_TIMEOUT_MULTISHOT) == 0) {
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
 * table.  SQPOLL also needs off-thread submission, but its raw-fd and copyin
 * paths require the submitter's process context and cannot use this worker
 * pool directly.
 */
#define	SQ_DEFAULT_WORKERS	8
#define	SQ_WORKERS_LIMIT	256

static int		sq_max_workers = SQ_DEFAULT_WORKERS;
static int		sq_nworkers;	/* worker procs created */
static int		sq_nidle;	/* workers blocked on sq_wq_cv */

static int
sysctl_squeue_max_workers(SYSCTL_HANDLER_ARGS)
{
	int error, value;

	value = atomic_load_int(&sq_max_workers);
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value < 1 || value > SQ_WORKERS_LIMIT)
		return (EINVAL);
	atomic_store_int(&sq_max_workers, value);
	return (0);
}
SYSCTL_PROC(_kern_squeue, OID_AUTO, max_workers,
    CTLTYPE_INT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_squeue_max_workers, "I",
    "Maximum system-wide squeue workers (1-256)");
SYSCTL_INT(_kern_squeue, OID_AUTO, workers, CTLFLAG_RD, &sq_nworkers, 0,
    "Live system-wide squeue workers");
SYSCTL_INT(_kern_squeue, OID_AUTO, idle_workers, CTLFLAG_RD, &sq_nidle, 0,
    "Idle system-wide squeue workers");

static void
sq_wq_init(void *dummy __unused)
{

	mtx_init(&sq_wq_mtx, "squeue workq", NULL, MTX_DEF);
	cv_init(&sq_wq_cv, "squeue worker");
	TAILQ_INIT(&sq_workq);
}
SYSINIT(squeue_wq, SI_SUB_KTHREAD_INIT, SI_ORDER_ANY, sq_wq_init, NULL);

/* ATTACH_WQ chains share a canonical worker-control owner.  A child context
 * retains that owner until its final in-flight job and mapping complete. */
static struct squeue_ctx *
sq_wq_owner(struct squeue_ctx *ctx)
{
	return (ctx->worker_root != NULL ? ctx->worker_root : ctx);
}

/* Return the oldest request whose ring has room in its class. */
static struct sq_req *
sq_wq_take(cpuset_t *mask, bool *affinity)
{
	struct sq_req *req;
	struct squeue_ctx *owner;

	mtx_assert(&sq_wq_mtx, MA_OWNED);
	TAILQ_FOREACH(req, &sq_workq, wq) {
		KASSERT(req->worker_class < SQ_WORKER_CLASSES,
		    ("invalid squeue worker class"));
		owner = sq_wq_owner(req->ctx);
		if (owner->worker_active[req->worker_class] >=
		    owner->worker_max[req->worker_class])
			continue;
		owner->worker_active[req->worker_class]++;
		*affinity = owner->worker_affinity_set;
		if (*affinity)
			CPU_COPY(&owner->worker_affinity, mask);
		TAILQ_REMOVE(&sq_workq, req, wq);
		req->work_queued = false;
		return (req);
	}
	return (NULL);
}

static void
squeue_worker(void *arg __unused)
{
	struct proc *p = curproc;
	struct thread *td = curthread;
	struct vmspace *myvm;
	struct sq_req *req;
	struct ucred *savedcred;
	struct squeue_ctx *ctx, *owner;
	cpuset_t basemask, jobmask;
	ssize_t before, cnt;
	int32_t res;
	bool affinity, affinity_applied, closing;
	int error, flags;

	/* Keep a reference to our own VM between jobs. */
	myvm = vmspace_acquire_ref(p);

	mtx_lock(&sq_wq_mtx);
	for (;;) {
		while ((req = sq_wq_take(&jobmask, &affinity)) == NULL) {
			sq_nidle++;
			cv_wait(&sq_wq_cv, &sq_wq_mtx);
			sq_nidle--;
		}
		mtx_unlock(&sq_wq_mtx);

		affinity_applied = false;
		if (affinity) {
			error = kern_cpuset_getaffinity(td, CPU_LEVEL_WHICH,
			    CPU_WHICH_TID, td->td_tid, sizeof(basemask), &basemask);
			KASSERT(error == 0,
			    ("cannot read squeue worker affinity: %d", error));
			error = kern_cpuset_setaffinity(td, CPU_LEVEL_WHICH,
			    CPU_WHICH_TID, td->td_tid, &jobmask);
			if (error != 0) {
				ctx = req->ctx;
				res = sq_err(ctx, error);
				goto release;
			}
			affinity_applied = true;
		}

		ctx = req->ctx;
		mtx_lock(&ctx->mtx);
		req->issuer = td;
		if (req->cancel_requested) {
			mtx_unlock(&ctx->mtx);
			res = sq_err(ctx, ECANCELED);
			goto release;
		}
		mtx_unlock(&ctx->mtx);
		flags = req->rw_foflags | (req->ocur ? 0 : FOF_OFFSET);

		/* Borrow the owner's address space for the user-buffer copy. */
		if (req->ovm != NULL)
			vmspace_switch_aio(req->ovm);
		req->ouio->uio_td = td;
		before = req->ouio->uio_resid;
		savedcred = td->td_ucred;
		if (req->cred != NULL)
			td->td_ucred = req->cred;
		if (req->owrite)
			error = fo_write(req->ofp, req->ouio, req->ofp->f_cred,
			    flags | FOF_NOSIGPIPE, td);
		else
			error = fo_read(req->ofp, req->ouio, req->ofp->f_cred,
			    flags, td);
		td->td_ucred = savedcred;
		cnt = before - req->ouio->uio_resid;
		if (!req->owrite)
			sq_fixed_dirty(req);
		/* Partial transfer reports the byte count; a hard error its errno. */
		if (error == 0 || (cnt > 0 && (error == EINTR ||
		    error == ERESTART || error == EWOULDBLOCK)))
			res = (int32_t)cnt;
		else
			res = sq_err(ctx, error);

	release:
		if (affinity_applied) {
			error = kern_cpuset_setaffinity(td, CPU_LEVEL_WHICH,
			    CPU_WHICH_TID, td->td_tid, &basemask);
			KASSERT(error == 0,
			    ("cannot restore squeue worker affinity: %d", error));
		}
		/* Restore our own address space before releasing the borrowed one. */
		if (p->p_vmspace != myvm)
			vmspace_switch_aio(myvm);
		if (req->ovm != NULL)
			vmspace_free(req->ovm);
		req->ovm = NULL;
		fdrop(req->ofp, td);
		req->ofp = NULL;
		free(req->ouio, M_IOV);
		req->ouio = NULL;

		/* Release the per-ring class slot before making more work eligible. */
		mtx_lock(&sq_wq_mtx);
		owner = sq_wq_owner(ctx);
		KASSERT(owner->worker_active[req->worker_class] > 0,
		    ("squeue worker class underflow"));
		owner->worker_active[req->worker_class]--;
		cv_broadcast(&sq_wq_cv);
		mtx_unlock(&sq_wq_mtx);

		/* Buffer accounting may take ctx->mtx; finish it before the
		 * pending-to-ready transition acquires that mutex. */
		if (req->pbuf_selected) {
			if (res >= 0)
				req->cflags = sq_consume_buffer(req, (uint32_t)res);
			else
				sq_recycle_buffer(req);
		}
		/* Resolve like any async op: pending -> ready, wake a waiter. */
		mtx_lock(&ctx->mtx);
		req->issuer = NULL;
		req->worker_owned = false;
		callout_stop(&req->co);
		if (req->cancel_requested && res == sq_err(ctx, EINTR))
			res = sq_err(ctx, ECANCELED);
		sq_finish_link(req);
		req->res = res;
		req->state = SQ_ST_READY;
		TAILQ_REMOVE(&ctx->pending, req, entry);
		ctx->npending--;
		TAILQ_INSERT_TAIL(&ctx->ready, req, entry);
		/*
		 * Linux's EVENTFD_ASYNC notification is raised by an io-wq worker
		 * when it queues task work, before that work publishes the CQE.  Our
		 * worker-to-ready transition is the equivalent boundary: the next
		 * enter converts this request into a CQE in the owner's context.
		 */
		if (ctx->eventfd != NULL && ctx->eventfd_async &&
		    (atomic_load_acq_32(&ctx->rings->cq_flags) &
		    IORING_CQ_EVENTFD_DISABLED) == 0)
			eventfd_signal(ctx->eventfd);
		SDT_PROBE3(squeue, , , ready, ctx, req->user_data, res);
		sq_wake(ctx);
		closing = ctx->closing;
		mtx_unlock(&ctx->mtx);
		/* The last ring-file close may have already drained its ready list.
		 * Retire this late completion and cancel any proxy-owning linked
		 * successor before releasing our worker context reference. */
		if (closing)
			sq_run_ready(ctx, td);
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
 * Offload is offered for explicit IOSQE_ASYNC operations and for SQPOLL
 * transfers that could block the single poller shared by attached rings.
 * READ/READV select their provided buffer before entering the worker pool.
 */
static bool
sq_offload_eligible(struct sq_req *req)
{

	/*
	 * BUFFER_SELECT is handled inline because the worker path does not run
	 * that preamble.  Fixed files are safe here: sq_offload_submit resolves
	 * the slot through a transient rights-preserving descriptor and keeps the
	 * selected generation on the request until the worker has finished.
	 */
	/* A shared SQPOLL thread must not block on a pipe or regular-file
	 * transfer: one stalled member would stop every attached ring.  Linux
	 * tries nonblocking issue and then io-wq; our worker pool owns these
	 * potentially blocking transfers from the start. */
	return (((req->sqe_flags & IOSQE_ASYNC) != 0 ||
	    (req->ctx->setup_flags & IORING_SETUP_SQPOLL) != 0) &&
	    !req->retry && sq_offload_op(req->opcode) &&
	    ((req->sqe_flags & IOSQE_BUFFER_SELECT) == 0 ||
	    req->opcode == IORING_OP_READ || req->opcode == IORING_OP_READV));
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
	bool wr, vec, fixed, fixed_file, cur, spawn;
	int error, fd, tmpfd;

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
	fixed_file = (req->sqe_flags & IOSQE_FIXED_FILE) != 0;
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

	if ((req->sqe_flags & IOSQE_BUFFER_SELECT) != 0) {
		error = sq_select_buffer(ctx, req,
		    vec ? req->pbuf_want : sqe->len);
		if (error != 0)
			return (sq_err(ctx, error));
	}
	if (fixed) {
		error = sq_fixed_prepare(ctx, req);
		if (error != 0)
			return (sq_err(ctx, error));
	}

	/*
	 * Grab a private reference to the target.  A fixed slot is first
	 * installed with its captured filecaps, so the ordinary fget path checks
	 * exactly the same read/write rights as inline issue.  file_node pins the
	 * selected generation after the transient descriptor is closed.
	 */
	fd = sqe->fd;
	tmpfd = -1;
	if (fixed_file) {
		error = sq_fixed_install(ctx, td, sqe->fd, 0, &tmpfd,
		    &req->file_node);
		if (error != 0)
			return (sq_err(ctx, error));
		fd = tmpfd;
	}
	if (wr)
		error = fget_write(td, fd, cur ? &cap_write_rights :
		    cap_rights_init(&rights, CAP_WRITE, CAP_PWRITE), &fp);
	else
		error = fget_read(td, fd, cur ? &cap_read_rights :
		    cap_rights_init(&rights, CAP_READ, CAP_PREAD), &fp);
	if (tmpfd >= 0)
		(void)kern_close(td, tmpfd);
	if (error != 0)
		return (sq_err(ctx, error));

	if (!cur && (fp->f_ops->fo_flags & DFLAG_SEEKABLE) == 0) {
		fdrop(fp, td);
		return (sq_err(ctx, ESPIPE));
	}

	/* Ordinary vectors are copied in; fixed vectors already own their pages. */
	if (fixed) {
		uiop = cloneuio(req->buf_uio);
	} else if (vec && !req->pbuf_selected) {
		error = copyinuio((void *)(uintptr_t)sqe->addr, sqe->len, &uiop);
		if (error != 0) {
			fdrop(fp, td);
			return (sq_err(ctx, error));
		}
	} else {
		uiop = malloc(sizeof(*uiop) + sizeof(*iov), M_IOV, M_WAITOK);
		iov = (struct iovec *)(uiop + 1);
		iov->iov_base = (void *)(uintptr_t)(req->pbuf_selected ?
		    req->pbuf_addr : sqe->addr);
		iov->iov_len = req->pbuf_selected ? req->pbuf_len : sqe->len;
		uiop->uio_iov = iov;
		uiop->uio_iovcnt = 1;
		uiop->uio_resid = iov->iov_len;
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
	spawn = (sq_nidle == 0 &&
	    sq_nworkers < atomic_load_int(&sq_max_workers));
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
	req->ovm = fixed ? NULL : vmspace_acquire_ref(td->td_proc);
	/* Seekable file transfers are bounded; pipes and sockets are unbounded. */
	req->worker_class = (fp->f_ops->fo_flags & DFLAG_SEEKABLE) != 0 ?
	    SQ_WORKER_BOUND : SQ_WORKER_UNBOUND;

	/* Publish pending and queued ownership together, in ring -> queue order. */
	mtx_lock(&ctx->mtx);
	if (req->cancel_requested) {
		mtx_unlock(&ctx->mtx);
		return (sq_err(ctx, ECANCELED));
	}
	atomic_add_int(&ctx->refs, 1);
	sq_unissue(req);
	req->worker_owned = true;
	req->state = SQ_ST_ARMED;
	TAILQ_INSERT_TAIL(&ctx->pending, req, entry);
	ctx->npending++;
	SDT_PROBE3(squeue, , , offload, ctx, req->user_data, req->opcode);
	mtx_lock(&sq_wq_mtx);
	req->work_queued = true;
	TAILQ_INSERT_TAIL(&sq_workq, req, wq);
	cv_signal(&sq_wq_cv);
	mtx_unlock(&sq_wq_mtx);
	mtx_unlock(&ctx->mtx);
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
	int error;
	bool fail, softlink;
	/*
	 * In capability mode a native ring must not offload a raw-fd op to the
	 * worker pool (that would fget the ambient fd, bypassing the fixed-file
	 * confinement enforced in sq_issue_op).  When confined, such ops fall
	 * through to sq_issue_op, which rejects them with ENOTCAPABLE.
	 */
	bool confined = !ctx->is_linux && IN_CAPABILITY_MODE(td);

	while (req != NULL) {
		mtx_lock(&ctx->mtx);
		if (!req->issuing)
			TAILQ_INSERT_TAIL(&ctx->issuing, req, issue_entry);
		req->issuing = true;
		req->issuer = td;
		sq_link_arm(req);
		mtx_unlock(&ctx->mtx);
		/* Validate before either inline issue or worker/async dispatch. */
		error = 0;
		if ((req->opcode == IORING_OP_TIMEOUT_REMOVE &&
		    ((req->sqe_flags & (IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT)) != 0 ||
		    req->sqe.len != 0 || req->sqe.buf_index != 0)) ||
		    (req->opcode == IORING_OP_ASYNC_CANCEL &&
		    (req->sqe_flags & IOSQE_BUFFER_SELECT) != 0))
			error = EINVAL;
		if (sq_offload_op(req->opcode) ||
		    req->opcode == IORING_OP_READ_MULTISHOT)
			error = (ctx->rw_flags != NULL ? ctx->rw_flags :
			    sq_native_rw_flags)(req->sqe.rw_flags, &req->rw_foflags);
		if ((req->sqe_flags & ~(IOSQE_FIXED_FILE | IOSQE_IO_DRAIN |
		    IOSQE_IO_LINK | IOSQE_IO_HARDLINK | IOSQE_ASYNC |
		    IOSQE_BUFFER_SELECT | IOSQE_CQE_SKIP_SUCCESS)) != 0)
			error = EINVAL;
		if (error != 0) {
			next = req->link_next;
			softlink = (req->sqe_flags & IOSQE_IO_LINK) != 0;
			mtx_lock(&ctx->mtx);
			sq_complete(ctx, req, sq_err(ctx, error), 0);
			mtx_unlock(&ctx->mtx);
			sq_req_free(req);
			if (softlink) {
				sq_cancel_chain(ctx, next);
				return;
			}
			req = next;
			continue;
		}
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

		mtx_lock(&ctx->mtx);
		fail = req->cancel_requested;
		mtx_unlock(&ctx->mtx);
		if (fail)
			res = sq_err(ctx, ECANCELED);
		else if (req->poll_first) {
			req->poll_first = false;
			res = sq_err(ctx, EAGAIN);
		} else
			res = sq_issue_op(ctx, req, td);
		if (res == SQ_EXT_PENDING)
			return;
		mtx_lock(&ctx->mtx);
		if (req->cancel_requested && res == sq_err(ctx, EINTR))
			res = sq_err(ctx, ECANCELED);
		mtx_unlock(&ctx->mtx);
		if (req->pbuf_selected && res != sq_err(ctx, EAGAIN)) {
			if (res >= 0)
				req->cflags = sq_consume_buffer(req, (uint32_t)res);
			else
				sq_recycle_buffer(req);
		}
		/*
		 * Fast poll: a would-block op is parked on a readiness poll and
		 * re-issued from sq_poll_scan when the fd is ready, rather than
		 * blocking the submitter or completing with EAGAIN.  The chain is
		 * suspended; its successors run once the retry completes.
		 */
		if (res == sq_err(ctx, EAGAIN) && !req->complete_eagain) {
			short ev = sq_pollable_events(req->opcode);

			/* A registered-ring selection stays owned across fast-poll
			 * retry, keeping its descriptor stable and unregister busy. */
			if (req->pbuf_ring == NULL)
				sq_recycle_buffer(req);

			/* Fixed files need a held-file knote because sqe.fd is a
			 * registered index. EPOLL_WAIT can use the captured identity;
			 * other fast-poll opcodes retain their descriptor path. */
			if ((req->sqe_flags & IOSQE_FIXED_FILE) != 0 &&
			    (req->opcode != IORING_OP_EPOLL_WAIT ||
			    req->match_fp == NULL))
				ev = 0;
			if (ev != 0) {
				/* Arm and retry by captured file identity, so closing or
				 * reusing the descriptor cannot retarget the request. */
				req->poll_use_held_fd = true;
				if (sq_kq_arm(ctx, req, td) == 0) {
					mtx_lock(&ctx->mtx);
					if (req->cancel_requested) {
						mtx_unlock(&ctx->mtx);
						sx_xunlock(&ctx->kq_sx);
						if (req->poll_id != 0)
							sq_kq_del_req(req, td);
						else
							sq_kq_del(ctx, req->sqe.fd,
							    sq_kq_filter(req), td);
						res = sq_err(ctx, ECANCELED);
						goto complete;
					}
					sq_unissue(req);
					req->on_poll = true;
					req->retry = true;
					req->state = SQ_ST_ARMED;
					TAILQ_INSERT_TAIL(&ctx->polls, req, entry);
					ctx->npolls++;
					mtx_unlock(&ctx->mtx);
					sx_xunlock(&ctx->kq_sx);
					return;
				}
				/* arm failed: fall through and complete EAGAIN */
			}
		}
	complete:
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
	bool cancelled, closing;

	for (;;) {
		mtx_lock(&ctx->mtx);
		closing = ctx->closing;
		req = TAILQ_FIRST(&ctx->ready);
		if (req != NULL)
			TAILQ_REMOVE(&ctx->ready, req, entry);
		else if ((ctx->setup_flags & IORING_SETUP_TASKRUN_FLAG) != 0)
			ctx->rings->sq_flags &= ~IORING_SQ_TASKRUN;
		mtx_unlock(&ctx->mtx);
		if (req == NULL)
			break;

		res = req->res;
		cont = req->link_next;
		/* A queued worker can be canceled before it runs.  It still owns
		 * a selected buffer, but must not publish a buffer-tagged error. */
		if (res < 0 && req->pbuf_selected)
			sq_recycle_buffer(req);
		mtx_lock(&ctx->mtx);
		sq_complete(ctx, req, res, req->cflags);
		mtx_unlock(&ctx->mtx);
		/*
		 * A cancelled request (or a soft-linked failure) cancels its
		 * successors; a timeout that expired with ETIME is a failure for
		 * link purposes when soft-linked.
		 */
		cancelled = closing || (res < 0 &&
		    (req->sqe_flags & IOSQE_IO_HARDLINK) == 0 &&
		    !(req->opcode == IORING_OP_TIMEOUT &&
		    (req->sqe.timeout_flags & IORING_TIMEOUT_ETIME_SUCCESS) != 0 &&
		    res == sq_etime(ctx)));
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
 * True while a drain barrier must keep waiting: async ops are still pending, or
 * a single-shot poll is armed.  A single-shot poll is a prior in-flight
 * operation that will complete, so IOSQE_IO_DRAIN must order it ahead of the
 * drained op (Linux waits for polls too).  Multishot polls are persistent
 * subscriptions rather than one-shot operations, so the barrier does not wait
 * for them -- that would never lift.  Caller holds ctx->mtx.
 */
static bool
sq_drain_blocked(struct squeue_ctx *ctx)
{
	struct sq_req *p;

	mtx_assert(&ctx->mtx, MA_OWNED);
	if (ctx->npending > 0)
		return (true);
	TAILQ_FOREACH(p, &ctx->polls, entry) {
		if (p->state == SQ_ST_ARMED && !p->multishot)
			return (true);
	}
	return (false);
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
		bool closing;

		mtx_lock(&ctx->mtx);
		closing = ctx->closing;
		if (TAILQ_EMPTY(&ctx->drain) ||
		    (!closing && sq_drain_blocked(ctx))) {
			mtx_unlock(&ctx->mtx);
			return;
		}
		head = TAILQ_FIRST(&ctx->drain);
		TAILQ_REMOVE(&ctx->drain, head, entry);
		mtx_unlock(&ctx->mtx);
		if (closing)
			sq_cancel_chain(ctx, head);
		else
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
	struct sq_req *r, *bad = NULL, *next, *lt;

	for (r = head; r != NULL; r = r->link_next) {
		if (r->prep_error != 0) { bad = r; break; }
	}
	if (bad != NULL) {
		for (r = head; r != NULL; r = next) {
			next = r->link_next;
			mtx_lock(&ctx->mtx);
			sq_complete(ctx, r, sq_err(ctx,
			    r->prep_error != 0 ? r->prep_error : ECANCELED), 0);
			mtx_unlock(&ctx->mtx);
			sq_req_free(r);
		}
		return;
	}
	for (r = head; r != NULL; r = r->link_next) {
		lt = r->link_next;
		if (lt == NULL || lt->opcode != IORING_OP_LINK_TIMEOUT)
			continue;
		r->link_next = lt->link_next;
		lt->link_next = NULL;
		r->link_timeout = lt;
		lt->link_target = r;
	}

	mtx_lock(&ctx->mtx);
	defer = !TAILQ_EMPTY(&ctx->drain) ||
	    ((head->sqe_flags & IOSQE_IO_DRAIN) != 0 && sq_drain_blocked(ctx));
	if (defer) {
		TAILQ_INSERT_TAIL(&ctx->drain, head, entry);
		mtx_unlock(&ctx->mtx);
		return;
	}
	mtx_unlock(&ctx->mtx);
	sq_run_chain(ctx, head, td);
}

/*
 * Validate the SQE fields whose meaning is fixed by the common io_uring
 * layout.  Front ends retain policy for ABI-specific flag values, while the
 * shared engine rejects fields which Linux reserves for each opcode.  Keeping
 * this in preparation prevents a malformed linked request from allowing an
 * earlier member of the chain to have side effects.
 */
static bool
sq_prep_field_set(const struct io_uring_sqe *q, unsigned int field)
{

	switch (field) {
	case 0: return (q->off != 0);
	case 1: return (q->addr != 0);
	case 2: return (q->len != 0);
	case 3: return (q->rw_flags != 0);
	case 4: return (q->buf_index != 0);
	case 5: return (q->splice_fd_in != 0);
	case 6: return (q->addr3 != 0);
	case 7: return (q->__pad2[0] != 0);
	case 8: return (q->fd != 0);
	default: return (false);
	}
}

static uint8_t
sq_bpf_pdu_size(uint8_t opcode)
{

	switch (opcode) {
	case IORING_OP_SOCKET:
		return (sizeof(((struct io_uring_bpf_ctx *)0)->socket));
	case IORING_OP_OPENAT:
	case IORING_OP_OPENAT2:
		return (sizeof(((struct io_uring_bpf_ctx *)0)->open));
	case IORING_OP_CONNECT:
		return (sizeof(((struct io_uring_bpf_ctx *)0)->connect));
	default:
		return (0);
	}
}

/* Linux's io_uring filter verifier permits only context-word loads and a
 * side-effect-free classic-BPF ALU/jump subset. */
static bool
sq_bpf_validate(const struct bpf_insn *insns, uint32_t ninsns)
{
	const struct bpf_insn *insn;
	uint32_t i;

	if (ninsns == 0 || ninsns > SQ_BPF_MAXINSNS ||
	    !bpf_validate(insns, ninsns))
		return (false);
	for (i = 0; i < ninsns; i++) {
		insn = &insns[i];
		switch (insn->code) {
		case BPF_LD | BPF_W | BPF_ABS:
			if (insn->k >= sizeof(struct io_uring_bpf_ctx) ||
			    (insn->k & 3) != 0)
				return (false);
			break;
		case BPF_LD | BPF_W | BPF_LEN:
		case BPF_LDX | BPF_W | BPF_LEN:
		case BPF_RET | BPF_K:
		case BPF_RET | BPF_A:
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU | BPF_NEG:
		case BPF_LD | BPF_IMM:
		case BPF_LDX | BPF_IMM:
		case BPF_MISC | BPF_TAX:
		case BPF_MISC | BPF_TXA:
		case BPF_LD | BPF_MEM:
		case BPF_LDX | BPF_MEM:
		case BPF_ST:
		case BPF_STX:
		case BPF_JMP | BPF_JA:
		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP | BPF_JSET | BPF_X:
			break;
		default:
			return (false);
		}
	}
	return (true);
}

static int
sq_bpf_run(struct squeue_ctx *ctx, const struct sq_req *req)
{
	struct io_uring_bpf_ctx bctx;
	struct sq_bpf_filter *filter;
	uint32_t words[sizeof(bctx) / sizeof(uint32_t)], value;
	uint8_t pdu_size;
	unsigned int i;
	bool deny;

	if (atomic_load_acq_8(&ctx->bpf_active) == 0)
		return (0);
	/*
	 * Filters are immutable after release publication and remain alive until
	 * the final context reference is gone.  Submission can therefore walk a
	 * chain without serializing unrelated ring completion and timeout state.
	 */
	filter = (struct sq_bpf_filter *)atomic_load_acq_ptr(
	    (uintptr_t *)&ctx->bpf_filters[req->opcode]);
	deny = atomic_load_acq_8(&ctx->bpf_deny[req->opcode]) != 0;
	if (filter == NULL && !deny)
		return (0);
	bzero(&bctx, sizeof(bctx));
	bctx.user_data = req->user_data;
	bctx.opcode = req->opcode;
	bctx.sqe_flags = req->sqe_flags;
	pdu_size = sq_bpf_pdu_size(req->opcode);
	bctx.pdu_size = pdu_size;
	if (req->opcode == IORING_OP_SOCKET) {
		bctx.socket.family = req->sqe.fd;
		bctx.socket.type = req->sqe.off;
		bctx.socket.protocol = req->sqe.len;
	} else if (req->opcode == IORING_OP_OPENAT) {
		bctx.open.flags = req->sqe.open_flags;
		bctx.open.mode = req->sqe.len;
	} else if (pdu_size != 0)
		bcopy(req->bpf_pdu, &bctx.socket, pdu_size);
	/* FreeBSD packet BPF loads words in network order.  Linux io_uring
	 * context loads are native-endian, so byte-swap each context word. */
	for (i = 0; i < nitems(words); i++) {
		bcopy((const char *)&bctx + i * sizeof(value), &value,
		    sizeof(value));
		words[i] = htonl(value);
	}
	while (filter != NULL) {
		if (bpf_filter(filter->insns, (u_char *)words, sizeof(bctx),
		    sizeof(bctx)) == 0)
			return (EACCES);
		filter = filter->next;
	}
	return (deny ? EACCES : 0);
}

static int
sq_bpf_import(void *arg, uint32_t nr_args, struct sq_bpf_filter **filterp,
    uint32_t *opcodep, uint32_t *flagsp)
{
	struct io_uring_bpf reg;
	struct sq_bpf_filter *filter;
	size_t bytes;
	uint8_t pdu_size;
	int error;

	if (nr_args != 1)
		return (EINVAL);
	error = copyin(arg, &reg, sizeof(reg));
	if (error != 0)
		return (error);
	if (reg.cmd_type != IO_URING_BPF_CMD_FILTER || reg.cmd_flags != 0 ||
	    reg.resv != 0 || reg.filter.opcode >= IORING_OP_LAST ||
	    (reg.filter.flags & ~(IO_URING_BPF_FILTER_DENY_REST |
	    IO_URING_BPF_FILTER_SZ_STRICT)) != 0 ||
	    memcchr(reg.filter.resv, 0, sizeof(reg.filter.resv)) != NULL ||
	    memcchr(reg.filter.resv2, 0, sizeof(reg.filter.resv2)) != NULL ||
	    reg.filter.filter_len == 0 ||
	    reg.filter.filter_len > SQ_BPF_MAXINSNS)
		return (EINVAL);
	pdu_size = sq_bpf_pdu_size(reg.filter.opcode);
	error = 0;
	if (reg.filter.pdu_size != pdu_size &&
	    ((reg.filter.flags & IO_URING_BPF_FILTER_SZ_STRICT) != 0 ||
	    reg.filter.pdu_size > pdu_size))
		error = EMSGSIZE;
	reg.filter.pdu_size = pdu_size;
	if (copyout(&reg.filter,
	    &((struct io_uring_bpf *)arg)->filter, sizeof(reg.filter)) != 0)
		return (EFAULT);
	if (error != 0)
		return (error);
	bytes = sizeof(*filter) +
	    (size_t)reg.filter.filter_len * sizeof(struct bpf_insn);
	filter = malloc(bytes, M_SQUEUE, M_WAITOK | M_ZERO);
	filter->ninsns = reg.filter.filter_len;
	error = copyin((const void *)(uintptr_t)reg.filter.filter_ptr,
	    filter->insns, (size_t)filter->ninsns * sizeof(struct bpf_insn));
	if (error != 0 || !sq_bpf_validate(filter->insns, filter->ninsns)) {
		free(filter, M_SQUEUE);
		return (error != 0 ? error : EINVAL);
	}
	*filterp = filter;
	*opcodep = reg.filter.opcode;
	*flagsp = reg.filter.flags;
	return (0);
}

static void
sq_bpf_ctx_install(struct squeue_ctx *ctx, struct sq_bpf_filter *filter,
    uint32_t opcode, uint32_t flags)
{
	uint32_t i;

	/* register_sx serializes writers.  Publish only fully built programs. */
	filter->next = ctx->bpf_filters[opcode];
	atomic_store_rel_ptr((uintptr_t *)&ctx->bpf_filters[opcode],
	    (uintptr_t)filter);
	if ((flags & IO_URING_BPF_FILTER_DENY_REST) != 0) {
		for (i = 0; i < IORING_OP_LAST; i++)
			if (i != opcode && ctx->bpf_filters[i] == NULL)
				atomic_store_rel_8(&ctx->bpf_deny[i], 1);
	}
	atomic_store_rel_8(&ctx->bpf_active, 1);
}

static int
sq_register_bpf_filter(struct squeue_ctx *ctx, void *arg, uint32_t nr_args)
{
	struct sq_bpf_filter *filter;
	uint32_t flags, opcode;
	int error;

	error = sq_bpf_import(arg, nr_args, &filter, &opcode, &flags);
	if (error != 0)
		return (error);
	sq_bpf_ctx_install(ctx, filter, opcode, flags);
	return (0);
}

static struct sq_bpf_filter *
sq_bpf_chain_clone(const struct sq_bpf_filter *source)
{
	struct sq_bpf_filter *clone, *head, **tail;
	size_t bytes;

	head = NULL;
	tail = &head;
	for (; source != NULL; source = source->next) {
		bytes = sizeof(*clone) +
		    (size_t)source->ninsns * sizeof(struct bpf_insn);
		clone = malloc(bytes, M_SQUEUE, M_WAITOK);
		bcopy(source, clone, bytes);
		clone->next = NULL;
		*tail = clone;
		tail = &clone->next;
	}
	return (head);
}

struct sq_bpf_set *
kern_squeue_bpf_task_clone(const struct sq_bpf_set *source)
{
	struct sq_bpf_set *clone;
	uint32_t i;

	if (source == NULL)
		return (NULL);
	clone = malloc(sizeof(*clone), M_SQUEUE, M_WAITOK | M_ZERO);
	for (i = 0; i < IORING_OP_LAST; i++) {
		clone->filters[i] = sq_bpf_chain_clone(source->filters[i]);
		clone->deny[i] = source->deny[i];
	}
	return (clone);
}

void
kern_squeue_bpf_task_free(struct sq_bpf_set *set)
{
	struct sq_bpf_filter *filter, *next;
	uint32_t i;

	if (set == NULL)
		return;
	for (i = 0; i < IORING_OP_LAST; i++) {
		for (filter = set->filters[i]; filter != NULL; filter = next) {
			next = filter->next;
			free(filter, M_SQUEUE);
		}
	}
	free(set, M_SQUEUE);
}

int
kern_squeue_bpf_task_register(struct sq_bpf_set **setp, void *arg,
    uint32_t nr_args)
{
	struct sq_bpf_filter *filter;
	struct sq_bpf_set *set;
	uint32_t flags, i, opcode;
	int error;

	error = sq_bpf_import(arg, nr_args, &filter, &opcode, &flags);
	if (error != 0)
		return (error);
	set = *setp;
	if (set == NULL) {
		set = malloc(sizeof(*set), M_SQUEUE, M_WAITOK | M_ZERO);
		*setp = set;
	}
	filter->next = set->filters[opcode];
	set->filters[opcode] = filter;
	if ((flags & IO_URING_BPF_FILTER_DENY_REST) != 0) {
		for (i = 0; i < IORING_OP_LAST; i++)
			if (i != opcode && set->filters[i] == NULL)
				set->deny[i] = 1;
	}
	return (0);
}

int
kern_squeue_bpf_task_attach(struct thread *td, int fd,
    const struct sq_bpf_set *set)
{
	struct sq_bpf_filter *filter;
	struct squeue_ctx *ctx;
	struct file *fp;
	bool active;
	uint32_t i;
	int error;

	if (set == NULL)
		return (0);
	error = sq_ring_file_get(td, fd, false, &fp);
	if (error != 0)
		return (error);
	ctx = fp->f_data;
	active = false;
	sx_xlock(&sq_register_global_sx);
	sx_xlock(&ctx->register_sx);
	for (i = 0; i < IORING_OP_LAST; i++) {
		filter = sq_bpf_chain_clone(set->filters[i]);
		if (filter != NULL) {
			ctx->bpf_filters[i] = filter;
			active = true;
		}
		if (set->deny[i] != 0) {
			ctx->bpf_deny[i] = 1;
			active = true;
		}
	}
	if (active)
		atomic_store_rel_8(&ctx->bpf_active, 1);
	sx_xunlock(&ctx->register_sx);
	sx_xunlock(&sq_register_global_sx);
	fdrop(fp, td);
	return (0);
}

static int
sq_prepare_common(const struct squeue_ctx *ctx, const struct io_uring_sqe *q)
{
	uint16_t mask;
	unsigned int field;

	/* Opcodes which assign a request-priority/option meaning to ioprio. */
	if (q->ioprio != 0) {
		switch (q->opcode) {
		case IORING_OP_READV:
		case IORING_OP_WRITEV:
		case IORING_OP_READ_FIXED:
		case IORING_OP_WRITE_FIXED:
		case IORING_OP_SENDMSG:
		case IORING_OP_RECVMSG:
		case IORING_OP_ACCEPT:
		case IORING_OP_READ:
		case IORING_OP_WRITE:
		case IORING_OP_SEND:
		case IORING_OP_RECV:
		case IORING_OP_SEND_ZC:
		case IORING_OP_SENDMSG_ZC:
		case IORING_OP_RECV_ZC:
		case IORING_OP_READV_FIXED:
		case IORING_OP_WRITEV_FIXED:
			break;
		default:
			return (EINVAL);
		}
	}

	/* Only receive/read operations consume a selected buffer. */
	if ((q->flags & IOSQE_BUFFER_SELECT) != 0) {
		switch (q->opcode) {
		case IORING_OP_READV:
		case IORING_OP_RECVMSG:
		case IORING_OP_READ:
		case IORING_OP_SEND:
		case IORING_OP_RECV:
		case IORING_OP_READ_MULTISHOT:
			break;
		default:
			return (EOPNOTSUPP);
		}
	}

	/* Operations without an ordinary input descriptor reject FIXED_FILE. */
	if ((q->flags & IOSQE_FIXED_FILE) != 0) {
		switch (q->opcode) {
		case IORING_OP_OPENAT:
		case IORING_OP_OPENAT2:
			if (ctx->is_linux)
				break;
			return (EBADF);
		case IORING_OP_CLOSE:
			if (ctx->is_linux)
				break;
			return (EBADF);
		case IORING_OP_SETXATTR:
		case IORING_OP_GETXATTR:
			return (EBADF);
		default:
			break;
		}
	}

	/* Bit N says union field N must be zero for this opcode. */
	mask = 0;
	switch (q->opcode) {
	case 3: mask = 0x032; break;
	case 6: mask = 0x013; break;
	case 7: mask = 0x030; break;
	case 8: mask = 0x032; break;
	case 10: mask = 0x001; break;
	case 11: mask = 0x0f0; break;
	case 12: mask = 0x0f4; break;
	case 13: mask = 0x014; break;
	case 14: mask = 0x021; break;
	case 15: mask = 0x0c0; break;
	case 16: mask = 0x03c; break;
	case 17: mask = 0x038; break;
	case 18: mask = ctx->is_linux ? 0 : 0x010; break;
	case 19: mask = ctx->is_linux ? 0 : 0x01f; break;
	case 21: mask = 0x030; break;
	case 24: mask = 0x030; break;
	case 25: mask = 0x030; break;
	case 28: mask = ctx->is_linux ? 0 : 0x010; break;
	case 29: mask = 0x030; break;
	case 31: mask = 0x028; break;
	case 32: mask = 0x02f; break;
	case 33: mask = 0x003; break;
	case 34: mask = 0x03b; break;
	case 35: mask = 0x030; break;
	case 36: mask = 0x035; break;
	case 37: mask = 0x039; break;
	case 38: mask = 0x03c; break;
	case 39: mask = 0x030; break;
	case 40: mask = 0x010; break;
	case 45: mask = 0x01a; break;
	case 47: mask = 0x080; break;
	case 48: mask = 0x080; break;
	case 49: mask = 0x006; break;
	case 50: mask = 0x05a; break;
	case 51: mask = 0x03c; break;
	case 52: mask = 0x03c; break;
	case 54: mask = 0x077; break;
	case 55: mask = 0x07e; break;
	case 56: mask = 0x03c; break;
	case 57: mask = 0x03b; break;
	case 59: mask = 0x039; break;
	case 62: mask = 0x141; break;
	default: break;
	}
	for (field = 0; field < 9; field++)
		if ((mask & (1U << field)) != 0 && sq_prep_field_set(q, field))
			return (EINVAL);
	/* Linux pathname operations validate their opcode-specific reserved
	 * fields before rejecting a fixed-file flag. */
	if ((q->flags & IOSQE_FIXED_FILE) != 0 &&
	    (q->opcode == IORING_OP_STATX ||
	    q->opcode == IORING_OP_RENAMEAT ||
	    q->opcode == IORING_OP_UNLINKAT ||
	    q->opcode == IORING_OP_MKDIRAT ||
	    q->opcode == IORING_OP_SYMLINKAT ||
	    q->opcode == IORING_OP_LINKAT))
		return (EBADF);
	if (q->opcode == IORING_OP_CLOSE && !ctx->is_linux &&
	    q->file_index != 0 && q->fd != 0)
		return (EINVAL);
	if (q->opcode == IORING_OP_FIXED_FD_INSTALL &&
	    (q->flags & IOSQE_FIXED_FILE) == 0)
		return (EBADF);
	return (0);
}

/* Preparation failures stop an ordinary submission batch.  Execution errors
 * (including a bad I/O fd) do not.  Restrictions are immutable once enabled. */
static int
sq_prepare(struct squeue_ctx *ctx, struct sq_req *req, struct sq_req *prev)
{
	const struct io_uring_sqe *q = &req->sqe;
	struct __kernel_timespec ts;
	int error;

	if (q->opcode >= IORING_OP_LAST ||
	    (q->flags & ~(IOSQE_FIXED_FILE | IOSQE_IO_DRAIN | IOSQE_IO_LINK |
	    IOSQE_IO_HARDLINK | IOSQE_ASYNC | IOSQE_BUFFER_SELECT |
	    IOSQE_CQE_SKIP_SUCCESS)) != 0)
		return (EINVAL);
	if (q->opcode == IORING_OP_FILES_UPDATE &&
	    (q->flags & IOSQE_BUFFER_SELECT) != 0)
		return (EOPNOTSUPP);
	if (ctx->restricted && (!ctx->allowed_ops[q->opcode] ||
	    (q->flags & ctx->required_sqe_flags) != ctx->required_sqe_flags ||
	    (q->flags & ~(ctx->allowed_sqe_flags | ctx->required_sqe_flags)) != 0))
		return (EACCES);
	error = sq_prepare_common(ctx, q);
	if (error != 0)
		return (error);
	if (q->personality != 0) {
		req->cred = sq_personality_get(ctx, q->personality);
		if (req->cred == NULL)
			return (EINVAL);
	}
	if (q->opcode == IORING_OP_FSYNC &&
	    (q->fsync_flags & ~IORING_FSYNC_DATASYNC) != 0)
		return (EINVAL);
	if (q->opcode == IORING_OP_NOP) {
		const uint32_t nop_mask = IORING_NOP_INJECT_RESULT |
		    IORING_NOP_FILE | IORING_NOP_FIXED_FILE |
		    IORING_NOP_FIXED_BUFFER | IORING_NOP_TW |
		    IORING_NOP_CQE32;

		if ((q->nop_flags & ~nop_mask) != 0 ||
		    ((q->nop_flags & IORING_NOP_CQE32) != 0 &&
		    (ctx->setup_flags & (IORING_SETUP_CQE32 |
		    IORING_SETUP_CQE_MIXED)) == 0))
			return (EINVAL);
		if ((q->nop_flags & IORING_NOP_CQE32) != 0) {
			req->cqe_big = true;
			req->cqe_extra1 = q->off;
			req->cqe_extra2 = q->addr;
			if ((ctx->setup_flags & IORING_SETUP_CQE_MIXED) != 0)
				req->cflags |= IORING_CQE_F_32;
		}
	}
	if (q->opcode == IORING_OP_MSG_RING &&
	    (q->msg_ring_flags & ~(IORING_MSG_RING_CQE_SKIP |
	    IORING_MSG_RING_FLAGS_PASS)) != 0)
		return (EINVAL);
	if (q->opcode == IORING_OP_FIXED_FD_INSTALL &&
	    (q->install_fd_flags & ~IORING_FIXED_FD_NO_CLOEXEC) != 0)
		return (EINVAL);
	if (q->opcode == IORING_OP_FIXED_FD_INSTALL && req->cred != NULL)
		return (EPERM);
	if (q->opcode == IORING_OP_FILES_UPDATE &&
	    ((q->flags & IOSQE_FIXED_FILE) != 0 ||
	    q->rw_flags != 0 || q->splice_fd_in != 0 || q->len == 0))
		return (EINVAL);
	if (q->opcode == IORING_OP_PROVIDE_BUFFERS) {
		uint64_t size;

		if (q->fd <= 0 || q->fd > SQ_MAX_PBUFS)
			return (E2BIG);
		if (q->len == 0)
			return (EINVAL);
		size = (uint64_t)q->len * (uint32_t)q->fd;
		if (q->addr > UINT64_MAX - size)
			return (EOVERFLOW);
		if (q->addr > VM_MAXUSER_ADDRESS ||
		    size > VM_MAXUSER_ADDRESS - q->addr)
			return (EFAULT);
		if (q->off > UINT16_MAX)
			return (E2BIG);
		if (q->off + (uint32_t)q->fd > SQ_MAX_PBUFS)
			return (EINVAL);
	}
	if (q->opcode == IORING_OP_REMOVE_BUFFERS &&
	    (q->fd <= 0 || q->fd > SQ_MAX_PBUFS))
		return (EINVAL);
	if (q->opcode == IORING_OP_LINK_TIMEOUT) {
		error = sq_link_prepare(req);
		if (error == 0 && (prev == NULL || prev->opcode == IORING_OP_LINK_TIMEOUT))
			error = EINVAL;
		return (error);
	}
	if (q->opcode == IORING_OP_TIMEOUT) {
		if ((q->timeout_flags & ~(IORING_TIMEOUT_ABS | IORING_TIMEOUT_BOOTTIME |
		    IORING_TIMEOUT_REALTIME | IORING_TIMEOUT_ETIME_SUCCESS |
		    IORING_TIMEOUT_MULTISHOT |
		    IORING_TIMEOUT_IMMEDIATE_ARG)) != 0 ||
		    (q->timeout_flags & (IORING_TIMEOUT_BOOTTIME |
		    IORING_TIMEOUT_REALTIME)) == (IORING_TIMEOUT_BOOTTIME |
		    IORING_TIMEOUT_REALTIME) ||
		    (q->timeout_flags & (IORING_TIMEOUT_ABS |
		    IORING_TIMEOUT_MULTISHOT)) == (IORING_TIMEOUT_ABS |
		    IORING_TIMEOUT_MULTISHOT))
			return (EINVAL);
		error = sq_timeout_arg(q->addr, q->timeout_flags, &ts);
		if (error != 0)
			return (error);
		if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L)
			return (EINVAL);
		req->timeout_sec = ts.tv_sec;
		req->timeout_nsec = ts.tv_nsec;
	}
	if (q->opcode == IORING_OP_TIMEOUT_REMOVE &&
	    (q->timeout_flags & IORING_TIMEOUT_UPDATE_MASK) != 0) {
		if ((q->timeout_flags & ~(IORING_TIMEOUT_UPDATE_MASK |
		    IORING_TIMEOUT_ABS | IORING_TIMEOUT_IMMEDIATE_ARG)) != 0)
			return (EINVAL);
		error = sq_timeout_arg(q->addr2, q->timeout_flags, &ts);
		if (error != 0)
			return (error);
		if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L)
			return (EINVAL);
		req->timeout_sec = ts.tv_sec;
		req->timeout_nsec = ts.tv_nsec;
	} else if (q->opcode == IORING_OP_TIMEOUT_REMOVE &&
	    (q->timeout_flags != 0 || q->off != 0))
		return (EINVAL);
	if (q->opcode == IORING_OP_READV &&
	    (q->flags & IOSQE_BUFFER_SELECT) != 0) {
		struct iovec iov;

		if (q->len != 1)
			return (EINVAL);
		error = copyin((void *)(uintptr_t)q->addr, &iov, sizeof(iov));
		if (error != 0)
			return (error);
		req->pbuf_want = iov.iov_len;
	}
	if (ctx->prepare_ext != NULL) {
		error = ctx->prepare_ext(req);
		if (error != 0)
			return (error);
	}
	error = sq_bpf_run(ctx, req);
	if (error != 0)
		return (error);
	/* Linux cancellation matches file identity, including dup'd descriptors
	 * and descriptors closed after an operation became outstanding.  Capture
	 * that identity without turning a normal execution-time EBADF into a
	 * batch-stopping preparation error. */
	if (q->opcode != IORING_OP_ASYNC_CANCEL) {
		if ((req->sqe_flags & IOSQE_FIXED_FILE) != 0) {
			sx_slock(&ctx->files_sx);
			if (ctx->reg_files != NULL && q->fd >= 0 &&
			    (uint32_t)q->fd < ctx->reg_nfiles &&
			    ctx->reg_files[q->fd] != NULL &&
			    fhold(ctx->reg_files[q->fd]->fp)) {
				req->match_fp = ctx->reg_files[q->fd]->fp;
				if (q->opcode == IORING_OP_POLL_ADD)
					req->poll_event_error = cap_check(
					    &ctx->reg_files[q->fd]->caps.fc_rights,
					    &cap_event_rights);
			}
			sx_sunlock(&ctx->files_sx);
		} else if ((ctx->is_linux &&
		    q->opcode == IORING_OP_EPOLL_WAIT) ||
		    sq_pollable_events(q->opcode) != 0) {
			/* Snapshot the file and its rights before returning to
			 * userland. A parked operation survives descriptor
			 * close/reuse and retries against this same identity. */
			req->poll_use_held_fd = ctx->is_linux &&
			    q->opcode == IORING_OP_EPOLL_WAIT;
			req->poll_caps = malloc(sizeof(*req->poll_caps),
			    M_SQUEUE, M_WAITOK | M_ZERO);
			filecaps_init(req->poll_caps);
			req->poll_capture_error = fget_cap(curthread, q->fd,
			    &cap_no_rights, NULL, &req->match_fp,
			    req->poll_caps);
			if (req->poll_capture_error != 0) {
				filecaps_free(req->poll_caps);
				free(req->poll_caps, M_SQUEUE);
				req->poll_caps = NULL;
			}
		} else if (q->opcode == IORING_OP_POLL_ADD) {
			req->poll_event_error = fget(curthread, q->fd,
			    &cap_event_rights, &req->match_fp);
			if (req->poll_event_error == 0 &&
			    req->match_fp->f_type == DTYPE_IORING) {
				struct file *target_fp, *proxy_fp;
				struct squeue_ctx *target_ctx;

				/* A ring file in the source request or its knote
				 * would prevent the last descriptor close.  A private
				 * proxy holds only the target context and attaches its
				 * readiness note to that context's knlist. */
				target_fp = req->match_fp;
				target_ctx = target_fp->f_data;
				atomic_add_int(&target_ctx->refs, 1);
				req->poll_event_error = falloc_noinstall(curthread,
				    &proxy_fp);
				if (req->poll_event_error == 0) {
					finit(proxy_fp, FREAD, DTYPE_SQUEUE_POLL,
					    target_ctx, &squeue_poll_fileops);
					req->poll_ring_target = true;
					req->poll_target_ctx = target_ctx;
					req->match_fp = proxy_fp;
				} else {
					sq_ctx_rele(target_ctx);
					req->match_fp = NULL;
				}
				fdrop(target_fp, curthread);
			}
		} else
			(void)fget(curthread, q->fd, &cap_no_rights,
			    &req->match_fp);
	}
	return (0);
}

/* ---- submission ---- */
static int
sq_submit(struct squeue_ctx *ctx, uint32_t to_submit, struct thread *td)
{
	struct sq_req *req, *ch_head, *ch_prev;
	struct io_uring_sqe sqe;
	uint32_t head, idx, tail;
	int submitted;
	bool rewind, stop, mixed128, layout_bad;

	ch_head = ch_prev = NULL;
	rewind = (ctx->setup_flags & IORING_SETUP_SQ_REWIND) != 0;
	for (submitted = 0; (uint32_t)submitted < to_submit; submitted++) {
		mtx_lock(&ctx->mtx);
		if (rewind) {
			if ((uint32_t)submitted >= ctx->sq_entries) {
				mtx_unlock(&ctx->mtx);
				break;
			}
			head = idx = (uint32_t)submitted;
			tail = 0;
		} else {
			head = ctx->rings->sq_head;
			/* Pair with the producer publishing SQEs before advancing tail. */
			tail = atomic_load_acq_32(&ctx->rings->sq_tail);
			if (head == tail) {
				mtx_unlock(&ctx->mtx);
				break;		/* nothing more queued */
			}
			idx = ctx->sq_array != NULL ?
			    ctx->sq_array[head & ctx->sq_mask] : head & ctx->sq_mask;
		}
		if (idx >= ctx->sq_entries) {
			ctx->rings->sq_dropped++;
			if (!rewind)
				atomic_store_rel_32(&ctx->rings->sq_head, head + 1);
			mtx_unlock(&ctx->mtx);
			break; /* consumed bad index, but no SQE was submitted */
		}
		/* Copy the first 64 bytes; SQE128's extension is opcode-specific. */
		bcopy((char *)ctx->sqes + (vm_size_t)idx * ctx->sqe_stride,
		    &sqe, sizeof(sqe));
		mixed128 = false;
		layout_bad = false;
		if ((sqe.opcode == IORING_OP_NOP128 ||
		    sqe.opcode == IORING_OP_URING_CMD128) &&
		    ctx->sqe_stride == sizeof(sqe)) {
			if ((ctx->setup_flags & IORING_SETUP_SQE_MIXED) == 0 ||
			    (uint32_t)submitted + 1 >= to_submit ||
			    idx >= ctx->sq_entries - 1 ||
			    (!rewind && tail - head < 2))
				layout_bad = true;
			else
				mixed128 = true;
		}
		if (!rewind)
			atomic_store_rel_32(&ctx->rings->sq_head,
			    head + 1 + (mixed128 ? 1 : 0));
		mtx_unlock(&ctx->mtx);

		req = malloc(sizeof(*req), M_SQUEUE, M_WAITOK | M_ZERO);
		atomic_add_long(&sq_live_requests, 1);
		req->ctx = ctx;
		req->sqe = sqe;
		req->opcode = sqe.opcode;
		req->sqe_flags = sqe.flags;
		req->user_data = sqe.user_data;
		req->state = SQ_ST_NEW;
		callout_init_mtx(&req->co, &ctx->mtx, 0);
		counter_u64_add(sq_stat_submitted, 1);
		SDT_PROBE3(squeue, , , submit, ctx, req->opcode, req->user_data);

		req->prep_error = layout_bad ? EINVAL :
		    sq_prepare(ctx, req, ch_prev);
		if (mixed128)
			submitted++;
		stop = req->prep_error != 0 &&
		    (sqe.flags & (IOSQE_IO_LINK | IOSQE_IO_HARDLINK)) == 0 &&
		    (ctx->setup_flags & IORING_SETUP_SUBMIT_ALL) == 0;

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
		if (stop) { submitted++; break; }
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
 * Armed targets use persistent EV_CLEAR notes.  POLL_ADD and ordinary-file
 * fast-poll requests use held file objects so descriptor close/reuse cannot
 * detach or retarget a pending request.  A scan fans readiness out to all
 * matching requests.  A private EVFILT_USER note wakes the scan for
 * completions without holding a reference to the
 * ring's own file (which would form a cycle on process exit).  All kevent
 * calls run without ctx->mtx because they may sleep.
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
sq_kevent_fp(struct file *fp, struct thread *td, struct kevent *changes,
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

	return (kern_kevent_fp(td, fp, nchanges, nevents, &kops, ts));
}

static int
sq_kevent(struct squeue_ctx *ctx, struct thread *td, struct kevent *changes,
    int nchanges, struct kevent *events, int nevents,
    const struct timespec *ts)
{
	return (sq_kevent_fp(ctx->kqfp, td, changes, nchanges, events, nevents, ts));
}

/* EVFILT_USER carries no ring file reference.  Registration may sleep, so
 * sq_wake schedules this task instead of calling kevent under ctx->mtx. */
static void
sq_kq_wake_task(void *arg, int pending __unused)
{
	struct squeue_ctx *ctx = arg;
	struct file *fp;
	struct kevent kev;

	mtx_lock(&ctx->mtx);
	fp = ctx->kqfp;
	if (fp != NULL && !fhold(fp))
		fp = NULL;
	mtx_unlock(&ctx->mtx);
	if (fp == NULL)
		return;
	EV_SET(&kev, 0, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
	(void)sq_kevent_fp(fp, curthread, &kev, 1, NULL, 0, NULL);
	fdrop(fp, curthread);
}

/* Lazily create the per-ring kqueue, held as a file * with its fd closed. */
static int
sq_kq_ensure(struct squeue_ctx *ctx, struct thread *td)
{
	struct file *fp;
	struct kevent kev;
	int error, fd;

	sx_xlock(&ctx->kq_sx);
	if (ctx->kqfp != NULL) {
		sx_xunlock(&ctx->kq_sx);
		return (0);
	}
	error = kern_kqueue(td, 0, false, NULL);
	if (error != 0) {
		sx_xunlock(&ctx->kq_sx);
		return (error);
	}
	fd = td->td_retval[0];
	td->td_retval[0] = 0;
	error = fget(td, fd, &cap_no_rights, &fp);
	(void)kern_close(td, fd);
	if (error != 0) {
		sx_xunlock(&ctx->kq_sx);
		return (error);
	}
	EV_SET(&kev, 0, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_TRIGGER, 0, NULL);
	error = sq_kevent_fp(fp, td, &kev, 1, NULL, 0, NULL);
	if (error != 0) {
		fdrop(fp, td);
		sx_xunlock(&ctx->kq_sx);
		return (error);
	}
	mtx_lock(&ctx->mtx);
	ctx->kqfp = fp;
	mtx_unlock(&ctx->mtx);
	sx_xunlock(&ctx->kq_sx);
	return (0);
}

/* The readiness filter a poll request is waiting on. */
static short
sq_kq_filter(const struct sq_req *req)
{

	if ((sq_request_poll_events(req) & (POLLOUT | POLLWRNORM | POLLWRBAND)) != 0 &&
	    (sq_request_poll_events(req) & (POLLIN | POLLPRI | POLLRDNORM)) == 0)
		return (EVFILT_WRITE);
	return (EVFILT_READ);
}

/* Register POLL_ADD and ordinary-file fast-poll retries by held file.
 * Success leaves kq_sx locked until the caller publishes the request on
 * ctx->polls.  The scanner takes the same lock before matching events, so
 * immediate readiness cannot be consumed before publication. */
static int
sq_kq_arm(struct squeue_ctx *ctx, struct sq_req *req, struct thread *td)
{
	struct kevent kev;
	int error;

	error = sq_kq_ensure(ctx, td);
	if (error != 0)
		return (error);
	/* POLL_ADD is keyed by the held file, not the user's reusable fd. */
	if (req->opcode == IORING_OP_POLL_ADD) {
		if (req->poll_event_error != 0)
			return (req->poll_event_error);
		if (req->match_fp == NULL)
			return (EBADF);
	}
	sx_xlock(&ctx->kq_sx);
	if (req->opcode == IORING_OP_POLL_ADD ||
	    req->poll_use_held_fd) {
		if (req->match_fp == NULL) {
			sx_xunlock(&ctx->kq_sx);
			return (EBADF);
		}
		mtx_lock(&ctx->mtx);
		if (req->poll_id == 0) {
			ctx->poll_next_id++;
			if (ctx->poll_next_id == 0)
				ctx->poll_next_id++;
			req->poll_id = ctx->poll_next_id;
		}
		mtx_unlock(&ctx->mtx);
		EV_SET(&kev, req->poll_id, sq_kq_filter(req),
		    EV_ADD | EV_CLEAR, 0, 0, (void *)2);
		error = kern_kevent_file(td, ctx->kqfp, req->match_fp, &kev);
	} else {
		/* Fast-poll retries still share one fd/filter knote. */
		EV_SET(&kev, req->sqe.fd, sq_kq_filter(req),
		    EV_ADD | EV_CLEAR, 0, 0, (void *)1);
		error = sq_kevent(ctx, td, &kev, 1, NULL, 0, NULL);
	}
	if (error != 0)
		sx_xunlock(&ctx->kq_sx);
	return (error);
}

/* Delete one file-identity knote while its request still holds the file. */
static void
sq_kq_del_req(struct sq_req *req, struct thread *td)
{
	struct squeue_ctx *ctx = req->ctx;
	struct kevent kev;

	if (req->match_fp == NULL || req->poll_id == 0)
		return;
	sx_xlock(&ctx->kq_sx);
	if (ctx->kqfp != NULL) {
		EV_SET(&kev, req->poll_id, sq_kq_filter(req),
		    EV_DELETE, 0, 0, NULL);
		(void)kern_kevent_file(td, ctx->kqfp, req->match_fp, &kev);
	}
	sx_xunlock(&ctx->kq_sx);
}

/*
 * Delete a descriptor-keyed fast-poll knote by (fd, filter).  Held-file
 * POLL_ADD notes use sq_kq_del_req() and their private request identity.
 * Takes values, not the request, so it never touches freed request memory.
 */
static void
sq_kq_del(struct squeue_ctx *ctx, int fd, short filter, struct thread *td)
{
	struct kevent kev;
	struct sq_req *r;
	bool keep = false;

	/* fdescfree() detaches p_fd before closing the last ring file.
	 * kqueue_register() would dereference it for an fd-keyed EV_DELETE;
	 * the private kqueue will drop its remaining notes at context teardown. */
	if (atomic_load_ptr(&td->td_proc->p_fd) == NULL)
		return;

	sx_xlock(&ctx->kq_sx);
	mtx_lock(&ctx->mtx);
	TAILQ_FOREACH(r, &ctx->polls, entry) {
		if (r->sqe.fd == fd && sq_kq_filter(r) == filter)
			keep = true;
	}
	TAILQ_FOREACH(r, &ctx->issuing, issue_entry) {
		if (!r->cancel_requested && r->sqe.fd == fd &&
		    sq_kq_filter(r) == filter)
			keep = true;
	}
	mtx_unlock(&ctx->mtx);
	if (!keep && ctx->kqfp != NULL) {
		EV_SET(&kev, fd, filter, EV_DELETE, 0, 0, NULL);
		(void)sq_kevent(ctx, td, &kev, 1, NULL, 0, NULL);
	}
	sx_xunlock(&ctx->kq_sx);
}

/* Remove or atomically update a POLL_ADD selected by its old user_data. */
static int
sq_poll_remove_update(struct squeue_ctx *ctx, struct sq_req *update,
    struct thread *td)
{
	struct io_uring_sqe *sqe = &update->sqe;
	struct sq_req *p, *r;
	struct kevent kev;
	uint32_t flags;
	short old_filter, new_filter;
	bool keep_old, rearm;
	int error;

	flags = sqe->len;
	if ((flags & ~(IORING_POLL_UPDATE_EVENTS |
	    IORING_POLL_UPDATE_USER_DATA | IORING_POLL_ADD_MULTI)) != 0 ||
	    flags == IORING_POLL_ADD_MULTI || sqe->buf_index != 0 ||
	    sqe->splice_fd_in != 0 ||
	    ((flags & IORING_POLL_UPDATE_USER_DATA) == 0 && sqe->off != 0) ||
	    ((flags & IORING_POLL_UPDATE_EVENTS) == 0 &&
	    sqe->poll32_events != 0))
		return (sq_err(ctx, EINVAL));

	if ((flags & (IORING_POLL_UPDATE_EVENTS |
	    IORING_POLL_UPDATE_USER_DATA)) == 0) {
		error = ENOENT;
		mtx_lock(&ctx->mtx);
		TAILQ_FOREACH(p, &ctx->polls, entry) {
			if (p->opcode == IORING_OP_POLL_ADD &&
			    p->user_data == sqe->addr) {
				error = sq_cancel_req(p);
				break;
			}
		}
		mtx_unlock(&ctx->mtx);
		return (error == 0 ? 0 : sq_err(ctx, error));
	}

	if ((flags & IORING_POLL_UPDATE_EVENTS) == 0) {
		error = ENOENT;
		mtx_lock(&ctx->mtx);
		TAILQ_FOREACH(p, &ctx->polls, entry) {
			if (p->opcode == IORING_OP_POLL_ADD &&
			    p->user_data == sqe->addr) {
				p->user_data = sqe->off;
				p->sqe.user_data = sqe->off;
				error = 0;
				break;
			}
		}
		mtx_unlock(&ctx->mtx);
		return (error == 0 ? 0 : sq_err(ctx, error));
	}

	sx_xlock(&ctx->kq_sx);
	mtx_lock(&ctx->mtx);
	p = NULL;
	TAILQ_FOREACH(r, &ctx->polls, entry) {
		if (r->opcode == IORING_OP_POLL_ADD &&
		    r->user_data == sqe->addr) {
			p = r;
			break;
		}
	}
	if (p == NULL) {
		mtx_unlock(&ctx->mtx);
		sx_xunlock(&ctx->kq_sx);
		return (sq_err(ctx, ENOENT));
	}
	if (p->poll_id != 0) {
		old_filter = sq_kq_filter(p);
		TAILQ_REMOVE(&ctx->polls, p, entry);
		ctx->npolls--;
		p->on_poll = false;
		p->sqe.poll32_events = sqe->poll32_events;
		p->sqe.len = flags & IORING_POLL_ADD_MULTI;
		p->multishot = (flags & IORING_POLL_ADD_MULTI) != 0 &&
		    !p->poll_ring_target;
		if ((flags & IORING_POLL_UPDATE_USER_DATA) != 0) {
			p->user_data = sqe->off;
			p->sqe.user_data = sqe->off;
		}
		new_filter = sq_kq_filter(p);
		mtx_unlock(&ctx->mtx);
		error = 0;
		if (old_filter != new_filter) {
			EV_SET(&kev, p->poll_id, old_filter,
			    EV_DELETE, 0, 0, NULL);
			(void)kern_kevent_file(td, ctx->kqfp,
			    p->match_fp, &kev);
			EV_SET(&kev, p->poll_id, new_filter,
			    EV_ADD | EV_CLEAR, 0, 0, (void *)2);
			error = kern_kevent_file(td, ctx->kqfp,
			    p->match_fp, &kev);
		}
		mtx_lock(&ctx->mtx);
		if (error == 0) {
			p->on_poll = true;
			TAILQ_INSERT_TAIL(&ctx->polls, p, entry);
			ctx->npolls++;
		} else {
			p->state = SQ_ST_READY;
			p->res = sq_err(ctx, ECANCELED);
			sq_finish_link(p);
			TAILQ_INSERT_TAIL(&ctx->ready, p, entry);
		}
		sq_wake(ctx);
		mtx_unlock(&ctx->mtx);
		sx_xunlock(&ctx->kq_sx);
		return (0);
	}
	old_filter = sq_kq_filter(p);
	TAILQ_REMOVE(&ctx->polls, p, entry);
	ctx->npolls--;
	p->on_poll = false;
	p->sqe.poll32_events = sqe->poll32_events;
	p->sqe.len = flags & IORING_POLL_ADD_MULTI;
	p->multishot = (flags & IORING_POLL_ADD_MULTI) != 0 &&
		    !p->poll_ring_target;
	if ((flags & IORING_POLL_UPDATE_USER_DATA) != 0) {
		p->user_data = sqe->off;
		p->sqe.user_data = sqe->off;
	}
	new_filter = sq_kq_filter(p);
	keep_old = false;
	TAILQ_FOREACH(r, &ctx->polls, entry) {
		if (r->sqe.fd == p->sqe.fd && sq_kq_filter(r) == old_filter) {
			keep_old = true;
			break;
		}
	}
	mtx_unlock(&ctx->mtx);

	if (old_filter != new_filter && !keep_old) {
		EV_SET(&kev, p->sqe.fd, old_filter, EV_DELETE, 0, 0, NULL);
		(void)sq_kevent(ctx, td, &kev, 1, NULL, 0, NULL);
	}
	rearm = old_filter != new_filter;
	error = 0;
	if (rearm) {
		EV_SET(&kev, p->sqe.fd, new_filter, EV_ADD | EV_CLEAR, 0, 0,
		    (void *)1);
		error = sq_kevent(ctx, td, &kev, 1, NULL, 0, NULL);
	}
	mtx_lock(&ctx->mtx);
	if (error == 0) {
		p->on_poll = true;
		TAILQ_INSERT_TAIL(&ctx->polls, p, entry);
		ctx->npolls++;
		sq_wake(ctx);
	} else {
		p->poll_delete = rearm;
		p->state = SQ_ST_READY;
		p->res = sq_err(ctx, ECANCELED);
		sq_finish_link(p);
		TAILQ_INSERT_TAIL(&ctx->ready, p, entry);
		sq_wake(ctx);
	}
	mtx_unlock(&ctx->mtx);
	sx_xunlock(&ctx->kq_sx);
	return (0);
}

/*
 * Block until a completion is posted or an armed target becomes ready.
 * The user event (udata == NULL) breaks the wait for completions.  Target
 * readiness is resolved against ctx->polls, never against a request pointer
 * retained by a knote.  Runs in the submitting thread's descriptor table.
 */
static int
sq_poll_scan(struct squeue_ctx *ctx, struct thread *td,
    sbintime_t deadline)
{
	struct kevent *evs;
	struct sq_reqq torun;
	struct sq_req *rq, *found, *next;
	struct { int fd; short filt; } *dels;
	int error, n, maxev, i, ndel;
	struct timespec ts, *tsp;
	sbintime_t remaining;

	error = sq_kq_ensure(ctx, td);
	if (error != 0)
		return (error);

	mtx_lock(&ctx->mtx);
	maxev = ctx->npolls + 1;		/* targets + ring */
	mtx_unlock(&ctx->mtx);
	evs = malloc(maxev * sizeof(*evs), M_SQUEUE, M_WAITOK | M_ZERO);
	/* (fd,filter) of multishot polls that ended this scan, to EV_DELETE. */
	dels = malloc(maxev * sizeof(*dels), M_SQUEUE, M_WAITOK | M_ZERO);
	ndel = 0;

	tsp = NULL;
	if (deadline != 0) {
		remaining = deadline - sbinuptime();
		ts = sbttots(MAX(remaining, 0));
		tsp = &ts;
	}
	error = sq_kevent(ctx, td, NULL, 0, evs, maxev, tsp);
	if (error != 0) {
		free(evs, M_SQUEUE);
		free(dels, M_SQUEUE);
		return (error);
	}
	n = td->td_retval[0];

	TAILQ_INIT(&torun);
	sx_xlock(&ctx->kq_sx);
	mtx_lock(&ctx->mtx);
	for (i = 0; i < n; i++) {
		short rev;

		if (evs[i].udata == NULL)
			continue;		/* the ring: completion readiness */

		if (evs[i].udata == (void *)1) {
			dels[ndel].fd = evs[i].ident;
			dels[ndel++].filt = evs[i].filter;
		}
		TAILQ_FOREACH_SAFE(found, &ctx->polls, entry, next) {
		if (sq_kq_filter(found) != evs[i].filter)
			continue;
		if (evs[i].udata == (void *)2) {
			if (found->poll_id == 0 ||
			    found->poll_id != evs[i].ident)
				continue;
		} else if (evs[i].udata == (void *)1) {
			if (found->poll_id != 0 ||
			    found->sqe.fd != (int)evs[i].ident)
				continue;
		} else
			continue;
		rev = sq_request_poll_events(found);
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
		found->on_poll = false;
		found->poll_delete = true;
		if (found->retry) {
			/* fast-poll: re-issue the op now that the fd is ready */
			found->retry = false;
			found->state = SQ_ST_NEW;
			/* Retain cancellation identity until sq_run_chain resumes. */
			found->issuing = true;
			TAILQ_INSERT_TAIL(&ctx->issuing, found, issue_entry);
			TAILQ_INSERT_TAIL(&torun, found, entry);
		} else {
			sq_finish_link(found);
			found->state = SQ_ST_READY;
			found->res = sq_poll_res(ctx, rev);
			TAILQ_INSERT_TAIL(&ctx->ready, found, entry);
		}
		}
	}
	mtx_unlock(&ctx->mtx);
	sx_xunlock(&ctx->kq_sx);
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
sq_wait_cq(struct squeue_ctx *ctx, uint32_t min_complete, int ringfd __unused,
    struct thread *td, sbintime_t deadline, uint32_t min_wait_usec)
{
	sbintime_t min_deadline, now, wait_deadline;
	bool expired_scan, min_active;
	int error, np;

	error = 0;
	expired_scan = false;
	min_active = min_wait_usec != 0;
	min_deadline = min_active ? sbinuptime() +
	    (sbintime_t)min_wait_usec * SBT_1US : 0;
	for (;;) {
		sq_run_ready(ctx, td);
		mtx_lock(&ctx->mtx);
		/* The app may have drained the CQ; pull in any backlog now. */
		sq_cq_flush(ctx);
		now = sbinuptime();
		if (min_active && now >= min_deadline)
			min_active = false;
		if (sq_cq_ready(ctx) >= min_complete ||
		    (!min_active && min_wait_usec != 0 &&
		    sq_cq_ready(ctx) != 0)) {
			mtx_unlock(&ctx->mtx);
			break;
		}
		np = ctx->npolls;
		/* With no ordinary timeout, the minimum interval bounds an
		 * otherwise empty wait.  With one, wait for its first completion. */
		if (!min_active && min_wait_usec != 0 && deadline == 0)
			deadline = min_deadline;
		if (!min_active && deadline != 0 && now >= deadline) {
			mtx_unlock(&ctx->mtx);
			/*
			 * Readiness may already be queued in the kqueue, including
			 * for a zero-length wait.  Drain it once without sleeping
			 * before deciding that no completion is available.
			 */
			if (np > 0 && !expired_scan) {
				expired_scan = true;
				error = sq_poll_scan(ctx, td, deadline);
				if (error != 0)
					break;
				continue;
			}
			/* An expired wait still observes its temporary sigmask. */
			error = sig_intr();
			if (error == 0)
				error = ETIMEDOUT;
			break;
		}
		/* Linux arms the minimum timer first, even when the ordinary
		 * timeout is shorter.  It checks the ordinary deadline after it. */
		wait_deadline = min_active ? min_deadline : deadline;
		if (np > 0) {
			mtx_unlock(&ctx->mtx);
			/* Wait on the ring fd + poll targets together. */
			error = sq_poll_scan(ctx, td, wait_deadline);
			if (error != 0)
				break;
			continue;
		}
		/*
		 * Close a lost-wakeup window: a worker resolves an async op by
		 * moving the request onto ctx->ready and calling sq_wake (which
		 * only wakes if cq_waiters > 0), but ready->CQE conversion
		 * happens in sq_run_ready() at the top of this loop, outside the
		 * lock.  If a worker inserted into ready in the gap between that
		 * sq_run_ready() and this lock, sq_cq_ready() above still sees
		 * nothing (the req is on ready, not yet a CQE) and sq_wake found
		 * no waiter.  Re-run the loop to convert it rather than sleeping
		 * forever.  This check is under the same ctx->mtx a worker must
		 * hold to insert+wake, so ready is either seen here or the
		 * subsequent sq_wake sees cq_waiters > 0.
		 */
		if (!TAILQ_EMPTY(&ctx->ready)) {
			mtx_unlock(&ctx->mtx);
			continue;
		}
		SDT_PROBE2(squeue, , , wait, ctx, min_complete);
		ctx->cq_waiters++;
		error = msleep_sbt(&ctx->cq_waiters, &ctx->mtx, PCATCH,
		    "iouring", wait_deadline, 0, C_ABSOLUTE);
		ctx->cq_waiters--;
		mtx_unlock(&ctx->mtx);
		/* Recheck completions before reporting a deadline expiration. */
		if (error == EWOULDBLOCK)
			continue;
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
	struct sq_pbuf_ring *pr;
	struct sq_zcrx *z;
	vm_object_t obj;
	vm_ooffset_t objoff;
	vm_size_t psize;
	uint16_t bgid;
	int error;

	if (foff >= IORING_MAP_OFF_ZCRX_REGION &&
	    foff < IORING_OFF_PBUF_RING &&
	    ((foff - IORING_MAP_OFF_ZCRX_REGION) &
	    ((1ULL << IORING_OFF_ZCRX_SHIFT) - 1)) == 0) {
		uint32_t id = (uint32_t)((foff - IORING_MAP_OFF_ZCRX_REGION) >>
		    IORING_OFF_ZCRX_SHIFT);

		mtx_lock(&ctx->mtx);
		z = sq_zcrx_find(ctx, id);
		if (z == NULL || z->rq_obj == NULL) {
			mtx_unlock(&ctx->mtx);
			return (ctx->mmap_bad_offset_errno);
		}
		obj = z->rq_obj;
		psize = z->rq_size;
		vm_object_reference(obj);
		mtx_unlock(&ctx->mtx);
		if (size > psize) {
			vm_object_deallocate(obj);
			return (EINVAL);
		}
		error = vm_mmap_object(map, addr, size, prot, maxprot, flags, obj,
		    0, FALSE, td);
		if (error != 0)
			vm_object_deallocate(obj);
		return (error);
	}
	if (foff >= IORING_OFF_PBUF_RING && (foff & 0xffff) == 0 &&
	    (foff & ~((vm_ooffset_t)0x7fff0000 | IORING_OFF_PBUF_RING)) == 0) {
		bgid = (uint16_t)((foff & 0x7fff0000) >> IORING_OFF_PBUF_SHIFT);
		mtx_lock(&ctx->mtx);
		pr = sq_pbuf_ring_find(ctx, bgid);
		if (pr == NULL || !pr->mmap_ring) {
			mtx_unlock(&ctx->mtx);
			return (ctx->mmap_bad_offset_errno);
		}
		obj = pr->obj;
		psize = pr->size;
		vm_object_reference(obj);
		mtx_unlock(&ctx->mtx);
		if (size > psize) {
			vm_object_deallocate(obj);
			return (EINVAL);
		}
		error = vm_mmap_object(map, addr, size, prot, maxprot, flags, obj,
		    0, FALSE, td);
		if (error != 0)
			vm_object_deallocate(obj);
		return (error);
	}
	sx_slock(&ctx->mmap_sx);
	obj = ctx->obj;
	switch (foff) {
	case IORING_OFF_SQ_RING:
	case IORING_OFF_CQ_RING:
		if (ctx->ring_user != NULL) {
			error = ctx->mmap_bad_offset_errno;
			goto out;
		}
		objoff = 0;
		if (size > ctx->ring_region) {
			error = EINVAL;
			goto out;
		}
		break;
	case IORING_OFF_SQES:
		if (ctx->sqes_user != NULL) {
			error = ctx->mmap_bad_offset_errno;
			goto out;
		}
		objoff = ctx->sqes_off;
		if (size > ctx->sqes_size) {
			error = EINVAL;
			goto out;
		}
		break;
	case IORING_MAP_OFF_PARAM_REGION:
		if (ctx->param_obj == NULL) {
			error = ctx->mmap_bad_offset_errno;
			goto out;
		}
		if (size > ctx->param_size) {
			error = EINVAL;
			goto out;
		}
		obj = ctx->param_obj;
		objoff = 0;
		break;
	default:
		error = ctx->mmap_bad_offset_errno;
		goto out;
	}
	vm_object_reference(obj);
	error = vm_mmap_object(map, addr, size, prot, maxprot, flags, obj,
	    objoff, FALSE, td);
	if (error != 0)
		vm_object_deallocate(obj);
out:
	sx_sunlock(&ctx->mmap_sx);
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
	/*
	 * Readiness is "a completion is or can be made available".  A CQE
	 * already in the ring counts; so does a request a worker/cancel has
	 * moved onto ctx->ready but not yet converted to a CQE (conversion runs
	 * in the squeue_enter thread via sq_run_ready).  Without the ready-list
	 * term, a completion resolved while a thread is blocked on the ring's
	 * internal knote in sq_poll_scan would never wake it (sq_wake's KNOTE
	 * would see the note "not ready"), stranding the completion.
	 */
	return (kn->kn_data > 0 || !TAILQ_EMPTY(&ctx->ready));
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

	last = atomic_fetchadd_int(&ctx->refs, -1) == 1;
	if (last)
		sq_ctx_free(ctx);
}

/*
 * A SQ poller is a kernel thread in the ring creator's process.  Unlike a
 * generic worker it must see that process's vmspace, file table and creds
 * while preparing and issuing arbitrary SQEs.  An OSD callback handles both
 * normal exit and exec/exit's forced thread teardown.  It only queues work:
 * dropping the final context reference may sleep, so cannot run in OSD.
 */
static int sq_sqpoll_slot;
static struct mtx sq_sqpoll_done_mtx;
static TAILQ_HEAD(, squeue_ctx) sq_sqpoll_doneq;
static struct task sq_sqpoll_done_task;

static void
sq_sqpoll_done_run(void *arg __unused, int pending __unused)
{
	struct squeue_ctx *root, *member;
	uint64_t pass;

	for (;;) {
		mtx_lock(&sq_sqpoll_done_mtx);
		root = TAILQ_FIRST(&sq_sqpoll_doneq);
		if (root != NULL)
			TAILQ_REMOVE(&sq_sqpoll_doneq, root, sqpoll_done_entry);
		mtx_unlock(&sq_sqpoll_done_mtx);
		if (root == NULL)
			break;
		mtx_lock(&root->mtx);
		root->sqpoll_td = NULL;
		root->sqpoll_dead = !root->sqpoll_stop;
		root->sqpoll_running = false;
		root->sqpoll_busy = false;
		atomic_set_32(&root->rings->sq_flags, IORING_SQ_NEED_WAKEUP);
		cv_broadcast(&root->sqpoll_cv);
		pass = ++root->sqpoll_pass;
		mtx_unlock(&root->mtx);
		/* Never nest two ring mutexes, even in the deferred exit task. */
		for (;;) {
			mtx_lock(&root->mtx);
			member = NULL;
			TAILQ_FOREACH(member, &root->sqpoll_members,
			    sqpoll_member_entry) {
				if (member != root && member->sqpoll_seen != pass) {
					member->sqpoll_seen = pass;
					member->sqpoll_busy = false;
					cv_broadcast(&root->sqpoll_cv);
					atomic_add_int(&member->refs, 1);
					break;
				}
			}
			mtx_unlock(&root->mtx);
			if (member == NULL)
				break;
			mtx_lock(&member->mtx);
			member->sqpoll_dead = root->sqpoll_dead;
			member->sqpoll_running = false;
			atomic_set_32(&member->rings->sq_flags,
			    IORING_SQ_NEED_WAKEUP);
			cv_broadcast(&member->sqpoll_cv);
			mtx_unlock(&member->mtx);
			sq_ctx_rele(member);
		}
		sq_ctx_rele(root);
	}
}

static void
sq_sqpoll_osd_rele(void *arg)
{
	struct squeue_ctx *ctx = arg;

	mtx_lock(&sq_sqpoll_done_mtx);
	TAILQ_INSERT_TAIL(&sq_sqpoll_doneq, ctx, sqpoll_done_entry);
	mtx_unlock(&sq_sqpoll_done_mtx);
	taskqueue_enqueue(taskqueue_thread, &sq_sqpoll_done_task);
}

static void
sq_sqpoll_init(void *arg __unused)
{

	mtx_init(&sq_sqpoll_done_mtx, "sqpoll done", NULL, MTX_DEF);
	TAILQ_INIT(&sq_sqpoll_doneq);
	TASK_INIT(&sq_sqpoll_done_task, 0, sq_sqpoll_done_run, NULL);
	sq_sqpoll_slot = osd_thread_register(sq_sqpoll_osd_rele);
}
SYSINIT(squeue_sqpoll, SI_SUB_KTHREAD_INIT, SI_ORDER_ANY,
    sq_sqpoll_init, NULL);

/* The process-context pump probes each parked extension once per pass. */
static void
sq_ext_poll_run(struct squeue_ctx *ctx, struct thread *td)
{
	struct sq_req *req;
	int32_t result;

	if (ctx->ext_poll == NULL)
		return;
	for (;;) {
		mtx_lock(&ctx->mtx);
		TAILQ_FOREACH(req, &ctx->pending, entry) {
			if (req->ext_arg != NULL && !req->ext_poll_seen &&
			    req->opcode == IORING_OP_WAITID)
				break;
		}
		if (req == NULL) {
			TAILQ_FOREACH(req, &ctx->pending, entry)
				req->ext_poll_seen = false;
			mtx_unlock(&ctx->mtx);
			break;
		}
		req->ext_poll_seen = true;
		mtx_unlock(&ctx->mtx);
		result = ctx->ext_poll(req, td);
		if (result != SQ_EXT_PENDING) {
			sq_ext_finish(req, result);
			sq_run_ready(ctx, td);
		}
	}
}

/* Linux uses the longest idle interval of all rings on a shared poller.
 * Preserve each ring's requested interval so removal can lower the maximum. */
static void
sq_sqpoll_update_idle_locked(struct squeue_ctx *root)
{
	struct squeue_ctx *member;
	uint32_t idle_ms;

	mtx_assert(&root->mtx, MA_OWNED);
	idle_ms = 0;
	TAILQ_FOREACH(member, &root->sqpoll_members, sqpoll_member_entry)
		idle_ms = MAX(idle_ms, member->sqpoll_idle_ms);
	root->sqpoll_group_idle_ms = idle_ms;
}

/* Visit each attached ring once per pass.  The per-ring busy flag lets close
 * unlink it and wait for its current submission without stopping the group. */
static bool
sq_sqpoll_pass(struct squeue_ctx *root, struct thread *td,
    sbintime_t *ext_deadline)
{
	struct squeue_ctx *member, *chosen;
	uint64_t pass;
	uint32_t head, tail;
	bool did_work;

	did_work = false;
	mtx_lock(&root->mtx);
	pass = ++root->sqpoll_pass;
	mtx_unlock(&root->mtx);
	for (;;) {
		mtx_lock(&root->mtx);
		chosen = NULL;
		if (!root->sqpoll_stop) {
			TAILQ_FOREACH(member, &root->sqpoll_members,
			    sqpoll_member_entry) {
				if (member->sqpoll_seen != pass) {
					chosen = member;
					member->sqpoll_seen = pass;
					break;
				}
			}
		}
		if (chosen != NULL) {
			atomic_add_int(&chosen->refs, 1);
			chosen->sqpoll_busy = true;
		}
		mtx_unlock(&root->mtx);
		if (chosen == NULL)
			break;
		if (chosen->ext_poll != NULL && sbinuptime() >= *ext_deadline)
			sq_ext_poll_run(chosen, td);
		mtx_lock(&chosen->mtx);
		if (!chosen->disabled) {
			head = atomic_load_acq_32(&chosen->rings->sq_head);
			tail = atomic_load_acq_32(&chosen->rings->sq_tail);
		} else
			head = tail = 0;
		if ((chosen->setup_flags & IORING_SETUP_SQPOLL) == 0)
			head = tail;
		if (head != tail)
			atomic_clear_32(&chosen->rings->sq_flags,
			    IORING_SQ_NEED_WAKEUP);
		mtx_unlock(&chosen->mtx);
		if (head != tail) {
			(void)sq_submit(chosen,
			    MIN(MIN(tail - head, chosen->sq_entries), 8), td);
			did_work = true;
		}
		/* A worker may finish after the SQ head catches its tail.  SQPOLL
		 * must publish that CQE without another submission or enter call. */
		sq_run_ready(chosen, td);
		mtx_lock(&root->mtx);
		chosen->sqpoll_busy = false;
		cv_broadcast(&root->sqpoll_cv);
		mtx_unlock(&root->mtx);
		if (chosen != root) {
			mtx_lock(&chosen->mtx);
			cv_broadcast(&chosen->sqpoll_cv);
			mtx_unlock(&chosen->mtx);
		}
		sq_ctx_rele(chosen);
	}
	if (sbinuptime() >= *ext_deadline)
		*ext_deadline = sbinuptime() + mstosbt(10);
	return (did_work);
}

static void
sq_sqpoll_thread(void *arg)
{
	struct squeue_ctx *root = arg, *member;
	struct thread *td = curthread;
	sbintime_t deadline, idle, ext_deadline;
	uint32_t seq, idle_ms;
	void **reserved;
	bool work, pending;
	int error;

	reserved = osd_reserve(sq_sqpoll_slot);
	error = osd_thread_set_reserved(td, sq_sqpoll_slot, reserved, root);
	KASSERT(error == 0, ("squeue SQPOLL OSD registration: %d", error));
	if (root->sqpoll_thread_init != NULL)
		root->sqpoll_thread_init(td);
	if ((root->setup_flags & IORING_SETUP_SQ_AFF) != 0)
		error = cpuset_setithread(td->td_tid, root->sqpoll_aff_cpu);
	else
		error = 0;
	mtx_lock(&root->mtx);
	root->sqpoll_start_error = error;
	root->sqpoll_ready = true;
	cv_broadcast(&root->sqpoll_cv);
	mtx_unlock(&root->mtx);
	if (error != 0)
		goto out;
	idle_ms = root->sqpoll_group_idle_ms;
	idle = mstosbt(idle_ms);
	deadline = sbinuptime() + idle;
	ext_deadline = 0;
	for (;;) {
		PROC_LOCK(td->td_proc);
		if (thread_suspend_check_needed())
			(void)thread_suspend_check(0);
		PROC_UNLOCK(td->td_proc);
		mtx_lock(&root->mtx);
		if (idle_ms != root->sqpoll_group_idle_ms) {
			idle_ms = root->sqpoll_group_idle_ms;
			idle = mstosbt(idle_ms);
			deadline = sbinuptime() + idle;
			/* Attachment can change the interval after the wake
			 * sequence was sampled; this pass is spinning again. */
			TAILQ_FOREACH(member, &root->sqpoll_members,
			    sqpoll_member_entry)
				atomic_clear_32(&member->rings->sq_flags,
				    IORING_SQ_NEED_WAKEUP);
		}
		if (root->sqpoll_stop) {
			mtx_unlock(&root->mtx);
			/* Close marks extension waits canceled before stopping us.
			 * Give the owner-context pump one final pass to release them. */
			sq_ext_poll_run(root, td);
			break;
		}
		mtx_unlock(&root->mtx);
		work = sq_sqpoll_pass(root, td, &ext_deadline);
		if (work) {
			deadline = sbinuptime() + idle;
			continue;
		}
		mtx_lock(&root->mtx);
		if (root->sqpoll_stop) {
			mtx_unlock(&root->mtx);
			sq_ext_poll_run(root, td);
			break;
		}
		if (sbinuptime() < deadline) {
			mtx_unlock(&root->mtx);
			sched_relinquish(td);
			continue;
		}
		/* Mark every member asleep before the final tail check. */
		TAILQ_FOREACH(member, &root->sqpoll_members,
		    sqpoll_member_entry)
			atomic_set_32(&member->rings->sq_flags,
			    IORING_SQ_NEED_WAKEUP);
		atomic_thread_fence_seq_cst();
		pending = false;
		TAILQ_FOREACH(member, &root->sqpoll_members,
		    sqpoll_member_entry) {
			if ((member->setup_flags & IORING_SETUP_SQPOLL) != 0 &&
			    atomic_load_acq_32(&member->rings->sq_tail) !=
			    atomic_load_acq_32(&member->rings->sq_head)) {
				pending = true;
				break;
			}
		}
		if (pending) {
			mtx_unlock(&root->mtx);
			continue;
		}
		seq = root->sqpoll_wake_seq;
		while (!root->sqpoll_stop && seq == root->sqpoll_wake_seq) {
			(void)cv_timedwait(&root->sqpoll_cv, &root->mtx,
			    MAX(1, hz / 100));
			/* Time out regularly for extension polls and forced exit. */
			break;
		}
		if (seq != root->sqpoll_wake_seq) {
			TAILQ_FOREACH(member, &root->sqpoll_members,
			    sqpoll_member_entry)
				atomic_clear_32(&member->rings->sq_flags,
				    IORING_SQ_NEED_WAKEUP);
		}
		mtx_unlock(&root->mtx);
		deadline = sbinuptime() + idle;
	}
out:
#ifdef RACCT
	if (racct_enable) {
		PROC_LOCK(td->td_proc);
		racct_sub(td->td_proc, RACCT_NTHR, 1);
		PROC_UNLOCK(td->td_proc);
	}
#endif
	kthread_exit();
}

static void sq_sqpoll_stop(struct squeue_ctx *, struct thread *);

static int
sq_sqpoll_start(struct squeue_ctx *ctx, struct thread *td)
{
	int error;

#ifdef RACCT
	/* kthread_add() does not charge RACCT_NTHR for user processes. */
	if (racct_enable) {
		PROC_LOCK(td->td_proc);
		error = racct_add(td->td_proc, RACCT_NTHR, 1);
		PROC_UNLOCK(td->td_proc);
		if (error != 0)
			return (EPROCLIM);
	}
#endif
	mtx_lock(&ctx->mtx);
	if (!ctx->sqpoll_linked) {
		ctx->sqpoll_root = ctx;
		ctx->sqpoll_linked = true;
		TAILQ_INSERT_TAIL(&ctx->sqpoll_members, ctx,
		    sqpoll_member_entry);
		sq_sqpoll_update_idle_locked(ctx);
	}
	atomic_add_int(&ctx->refs, 1);
	ctx->sqpoll_running = true;
	mtx_unlock(&ctx->mtx);
	error = kthread_add(sq_sqpoll_thread, ctx, td->td_proc,
	    &ctx->sqpoll_td, 0, 0, "squeue-sqpoll");
	if (error != 0) {
		ctx->sqpoll_running = false;
		atomic_subtract_int(&ctx->refs, 1);
#ifdef RACCT
		if (racct_enable) {
			PROC_LOCK(td->td_proc);
			racct_sub(td->td_proc, RACCT_NTHR, 1);
			PROC_UNLOCK(td->td_proc);
		}
#endif
	} else {
		mtx_lock(&ctx->mtx);
		while (!ctx->sqpoll_ready)
			cv_wait(&ctx->sqpoll_cv, &ctx->mtx);
		error = ctx->sqpoll_start_error;
		mtx_unlock(&ctx->mtx);
		if (error != 0)
			sq_sqpoll_stop(ctx, td);
	}
	return (error);
}

int
sq_ext_poll_start(struct squeue_ctx *ctx, struct thread *td)
{
	int error;

	if (ctx->ext_poll == NULL)
		return (EOPNOTSUPP);
	sx_xlock(&ctx->register_sx);
	if (ctx->sqpoll_running)
		error = 0;
	else
		error = sq_sqpoll_start(ctx, td);
	sx_xunlock(&ctx->register_sx);
	return (error);
}

static void
sq_sqpoll_stop(struct squeue_ctx *ctx, struct thread *td)
{

	mtx_lock(&ctx->mtx);
	if (!ctx->sqpoll_running) {
		mtx_unlock(&ctx->mtx);
		return;
	}
	ctx->sqpoll_stop = true;
	ctx->sqpoll_wake_seq++;
	cv_broadcast(&ctx->sqpoll_cv);
	if (ctx->sqpoll_td != td)
		while (ctx->sqpoll_running)
			cv_wait(&ctx->sqpoll_cv, &ctx->mtx);
	mtx_unlock(&ctx->mtx);
}

/* Close must let the owner-context poller retire canceled extension waits
 * before unlinking this ring from a shared SQPOLL group.  A canceled WAITID
 * owns a context reference and cannot be freed from an arbitrary closer. */
static void
sq_sqpoll_drain_ext(struct squeue_ctx *ctx, struct thread *td)
{
	struct squeue_ctx *root = ctx->sqpoll_root;
	struct sq_req *req;
	bool pending, running;

	if (ctx->ext_poll == NULL || root == NULL)
		return;
	if (root->sqpoll_td == td) {
		sq_ext_poll_run(ctx, td);
		return;
	}
	for (;;) {
		mtx_lock(&ctx->mtx);
		pending = false;
		TAILQ_FOREACH(req, &ctx->pending, entry) {
			if (req->ext_arg != NULL && req->cancel_requested) {
				pending = true;
				break;
			}
		}
		mtx_unlock(&ctx->mtx);
		if (!pending)
			return;
		mtx_lock(&root->mtx);
		running = root->sqpoll_running && !root->sqpoll_dead;
		if (running) {
			root->sqpoll_wake_seq++;
			cv_broadcast(&root->sqpoll_cv);
		}
		mtx_unlock(&root->mtx);
		if (!running)
			return;
		mtx_lock(&ctx->mtx);
		(void)cv_timedwait(&ctx->sqpoll_cv, &ctx->mtx,
		    MAX(1, hz / 100));
		mtx_unlock(&ctx->mtx);
	}
}

static bool
sq_sqpoll_detach(struct squeue_ctx *ctx, struct thread *td)
{
	struct squeue_ctx *root = ctx->sqpoll_root;
	bool self, last;

	mtx_lock(&root->mtx);
	self = root->sqpoll_td == td;
	if (ctx->sqpoll_linked) {
		TAILQ_REMOVE(&root->sqpoll_members, ctx,
		    sqpoll_member_entry);
		ctx->sqpoll_linked = false;
	}
	last = TAILQ_EMPTY(&root->sqpoll_members);
	sq_sqpoll_update_idle_locked(root);
	root->sqpoll_wake_seq++;
	cv_broadcast(&root->sqpoll_cv);
	if (!self)
		while (ctx->sqpoll_busy && root->sqpoll_running)
			cv_wait(&root->sqpoll_cv, &root->mtx);
	mtx_unlock(&root->mtx);
	if (last)
		sq_sqpoll_stop(root, td);
	return (self);
}

static int
sq_fo_close(struct file *fp, struct thread *td)
{
	struct squeue_ctx *ctx = fp->f_data;

	fp->f_data = NULL;
	if (ctx != NULL) {
		struct sq_req *r;
		bool self;

		self = ctx->sqpoll_root != NULL ?
		    ctx->sqpoll_root->sqpoll_td == td : ctx->sqpoll_td == td;
		/* Cancel parked extension waits while their process pump is alive. */
		mtx_lock(&ctx->mtx);
		ctx->closing = true;
		restart_ext:
		TAILQ_FOREACH(r, &ctx->pending, entry) {
			if (r->ext_cancel != NULL && !r->cancel_requested) {
				(void)sq_cancel_req(r);
				goto restart_ext;
			}
		}
		mtx_unlock(&ctx->mtx);
		if ((ctx->setup_flags & IORING_SETUP_SQPOLL) != 0) {
			sq_sqpoll_drain_ext(ctx, td);
			self = sq_sqpoll_detach(ctx, td);
		}
		else
			sq_sqpoll_stop(ctx, td);
		if (self) {
			/* The poller can close its own ring from an SQE. */
			sq_ctx_rele(ctx);
			return (0);
		}
		mtx_lock(&ctx->mtx);
		restart:
		TAILQ_FOREACH(r, &ctx->pending, entry) {
			if (!r->cancel_requested) {
				(void)sq_cancel_req(r);
				goto restart;
			}
		}
		while ((r = TAILQ_FIRST(&ctx->polls)) != NULL)
			(void)sq_cancel_req(r);
		mtx_unlock(&ctx->mtx);
		/* A deferred poll may hold a proxy for this very context.  Retire
		 * ready requests and cancel both linked successors and drain-held
		 * chains before dropping the ring file's last context reference. */
		sq_run_ready(ctx, td);
		sq_kick_drain(ctx, td);
		sq_ctx_rele(ctx);
	}
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

	kif->kf_type = KF_TYPE_SQUEUE;
	return (0);
}

/* The proxy is never installed in a descriptor table.  Its file reference
 * belongs to a poll request and its private kqueue note; both must disappear
 * before the target context can be freed. */
static int
sq_poll_proxy_close(struct file *fp, struct thread *td __unused)
{
	struct squeue_ctx *target = fp->f_data;

	fp->f_data = NULL;
	if (target != NULL)
		sq_ctx_rele(target);
	return (0);
}

static const struct fileops squeue_poll_fileops = {
	.fo_read = invfo_rdwr,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = invfo_ioctl,
	.fo_poll = sq_fo_poll,
	.fo_kqfilter = sq_fo_kqfilter,
	.fo_stat = sq_fo_stat,
	.fo_close = sq_poll_proxy_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_mmap = sq_fo_mmap,
	.fo_fill_kinfo = sq_fo_fill_kinfo,
	.fo_cmp = file_kcmp_generic,
};

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
	struct squeue_ctx *ctx, *source, *root;
	struct sq_ring_registry *registry;
	struct file *fp, *attach_fp;
	uint32_t sqe, cqe;
	int error, fd, slot;
	bool attach_sqpoll;

	attach_fp = NULL;
	attach_sqpoll = false;
	if (entries == 0)
		return (EINVAL);
	/* Reject setup modes whose contracts the shared engine does not honor. */
	if ((p->flags & ~SQ_SUPPORTED_SETUP_FLAGS) != 0)
		return (EINVAL);
	/* Every attachment shares its source chain's worker controls; SQPOLL
	 * attachments also reuse the poller when it belongs to this process. */
	if ((p->flags & IORING_SETUP_ATTACH_WQ) != 0) {
		error = fget(td, (int)p->wq_fd, &cap_no_rights, &fp);
		if (error == EBADF)
			return (ENXIO);
		if (error != 0)
			return (error);
		error = fp->f_type == DTYPE_IORING ? 0 : EINVAL;
		if (error == 0 && (p->flags & IORING_SETUP_SQPOLL) != 0 &&
		    ((((struct squeue_ctx *)fp->f_data)->setup_flags &
		    IORING_SETUP_SQPOLL) == 0 ||
		    ((struct squeue_ctx *)fp->f_data)->is_linux != fe->is_linux))
			error = EINVAL;
		fdrop(fp, td);
		if (error != 0)
			return (error);
	}
	if ((p->flags & IORING_SETUP_SQPOLL) != 0 &&
	    (p->flags & (IORING_SETUP_COOP_TASKRUN |
	    IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_DEFER_TASKRUN)) != 0)
		return (EINVAL);
	if ((p->flags & IORING_SETUP_SQ_AFF) != 0) {
		cpuset_t allowed;

		if ((p->flags & IORING_SETUP_SQPOLL) == 0 ||
		    p->sq_thread_cpu >= CPU_SETSIZE ||
		    CPU_ABSENT(p->sq_thread_cpu))
			return (EINVAL);
		CPU_ZERO(&allowed);
		error = kern_cpuset_getaffinity(td, CPU_LEVEL_CPUSET,
		    CPU_WHICH_TID, td->td_tid, sizeof(allowed), &allowed);
		if (error != 0)
			return (error);
		if (!CPU_ISSET(p->sq_thread_cpu, &allowed))
			return (EINVAL);
	}
	if ((p->flags & IORING_SETUP_REGISTERED_FD_ONLY) != 0 &&
	    (p->flags & IORING_SETUP_NO_MMAP) == 0)
		return (EINVAL);
	if ((p->flags & IORING_SETUP_TASKRUN_FLAG) != 0 &&
	    (p->flags & (IORING_SETUP_COOP_TASKRUN |
	    IORING_SETUP_DEFER_TASKRUN)) == 0)
		return (EINVAL);
	if ((p->flags & IORING_SETUP_DEFER_TASKRUN) != 0 &&
	    (p->flags & IORING_SETUP_SINGLE_ISSUER) == 0)
		return (EINVAL);
	if ((p->flags & IORING_SETUP_SQ_REWIND) != 0 &&
	    (p->flags & IORING_SETUP_NO_SQARRAY) == 0)
		return (EINVAL);
	if ((p->flags & (IORING_SETUP_CQE32 | IORING_SETUP_CQE_MIXED)) ==
	    (IORING_SETUP_CQE32 | IORING_SETUP_CQE_MIXED))
		return (EINVAL);
	if ((p->flags & (IORING_SETUP_SQE128 | IORING_SETUP_SQE_MIXED)) ==
	    (IORING_SETUP_SQE128 | IORING_SETUP_SQE_MIXED))
		return (EINVAL);
	if (p->resv[0] != 0 || p->resv[1] != 0 || p->resv[2] != 0)
		return (EINVAL);

	/*
	 * Size the submission queue.  Requests over the cap are an error
	 * unless IORING_SETUP_CLAMP was asked, in which case they are clamped
	 * (Linux semantics).
	 */
	if (entries > SQ_MAX_ENTRIES) {
		if ((p->flags & IORING_SETUP_CLAMP) == 0)
			return (EINVAL);
		entries = SQ_MAX_ENTRIES;
	}
	sqe = 1U << flsl(entries - 1);		/* round up to pow2 */
	if (sqe < entries)
		sqe <<= 1;
	if (sqe < 1)
		sqe = 1;

	/*
	 * Size the completion queue.  Default is 2x the SQ; with
	 * IORING_SETUP_CQSIZE the caller supplies p->cq_entries, which is
	 * rounded up to a power of two, must be >= the SQ size, and is bounded
	 * by SQ_MAX_CQ_ENTRIES (clamped only if IORING_SETUP_CLAMP).
	 */
	if ((p->flags & IORING_SETUP_CQSIZE) != 0) {
		if (p->cq_entries == 0)
			return (EINVAL);
		cqe = 1U << flsl(p->cq_entries - 1);
		if (cqe < p->cq_entries)
			cqe <<= 1;
		if (cqe > SQ_MAX_CQ_ENTRIES) {
			if ((p->flags & IORING_SETUP_CLAMP) == 0)
				return (EINVAL);
			cqe = SQ_MAX_CQ_ENTRIES;
		}
		if (cqe < sqe)
			return (EINVAL);
	} else {
		cqe = sqe * 2;
	}
	if ((p->flags & IORING_SETUP_SQE_MIXED) != 0 && sqe < 2)
		return (EOVERFLOW);
	if ((p->flags & IORING_SETUP_CQE_MIXED) != 0 && cqe < 2)
		return (EOVERFLOW);

	ctx = malloc(sizeof(*ctx), M_SQUEUE, M_WAITOK | M_ZERO);
	ctx->refs = 1;			/* the ring file's reference */
	ctx->worker_root = ctx;
	TAILQ_INIT(&ctx->sqpoll_members);
	ctx->owner_uid = td->td_ucred->cr_ruidinfo;
	uihold(ctx->owner_uid);
	ctx->owner_vm = vmspace_acquire_ref(td->td_proc);
	mtx_init(&ctx->mtx, "iouring", NULL, MTX_DEF);
	cv_init(&ctx->sqpoll_cv, "squeue sqpoll");
	sx_init(&ctx->kq_sx, "squeue kqueue");
	sx_init(&ctx->register_sx, "squeue register");
	sx_init(&ctx->mmap_sx, "squeue mmap");
	sx_init(&ctx->files_sx, "squeue files");
	TASK_INIT(&ctx->kq_wake_task, 0, sq_kq_wake_task, ctx);
	knlist_init_mtx(&ctx->sel.si_note, &ctx->mtx);
	TAILQ_INIT(&ctx->issuing);
	TAILQ_INIT(&ctx->pending);
	TAILQ_INIT(&ctx->ready);
	TAILQ_INIT(&ctx->drain);
	TAILQ_INIT(&ctx->pbufs);
	TAILQ_INIT(&ctx->pbuf_rings);
	TAILQ_INIT(&ctx->zcrx);
	TAILQ_INIT(&ctx->polls);
	TAILQ_INIT(&ctx->overflow);
	LIST_INIT(&ctx->personalities);
	ctx->personality_next = 1;
	ctx->worker_max[SQ_WORKER_BOUND] = atomic_load_int(&sq_max_workers);
	ctx->worker_max[SQ_WORKER_UNBOUND] = atomic_load_int(&sq_max_workers);
	ctx->sq_entries = sqe;
	ctx->cq_entries = cqe;
	ctx->sqe_stride = sizeof(struct io_uring_sqe) *
	    ((p->flags & IORING_SETUP_SQE128) != 0 ? 2 : 1);
	ctx->cqe_stride = sizeof(struct io_uring_cqe) *
	    ((p->flags & IORING_SETUP_CQE32) != 0 ? 2 : 1);
	ctx->setup_flags = p->flags;
	ctx->disabled = (p->flags & IORING_SETUP_R_DISABLED) != 0;
	ctx->sqpoll_idle_ms = p->sq_thread_idle != 0 ? p->sq_thread_idle : 1000;
	ctx->sqpoll_aff_cpu = p->sq_thread_cpu;
	ctx->sqpoll_thread_init = fe->sqpoll_thread_init;
	ctx->ext_poll = fe->ext_poll;
	ctx->is_linux = fe->is_linux;
	ctx->issue_ext = fe->issue_ext;
	ctx->op_supported = fe->op_supported;
	ctx->rw_flags = fe->rw_flags;
	ctx->prepare_ext = fe->prepare_ext;
	ctx->clockid_xlate = fe->clockid_xlate;
	ctx->register_query = fe->register_query;
	ctx->register_ext = fe->register_ext;
	ctx->wait_clockid = CLOCK_UPTIME;
	ctx->err_xlate = fe->err_xlate;
	ctx->mmap_bad_offset_errno = fe->mmap_bad_offset_errno != 0 ?
	    fe->mmap_bad_offset_errno : EINVAL;

	error = (p->flags & IORING_SETUP_NO_MMAP) != 0 ?
	    sq_ring_alloc_user(ctx, p, td) : sq_ring_alloc(ctx);
	if (error != 0) {
		knlist_destroy(&ctx->sel.si_note);
		sx_destroy(&ctx->files_sx);
		sx_destroy(&ctx->mmap_sx);
		sx_destroy(&ctx->register_sx);
		sx_destroy(&ctx->kq_sx);
		cv_destroy(&ctx->sqpoll_cv);
		mtx_destroy(&ctx->mtx);
		uifree(ctx->owner_uid);
		vmspace_free(ctx->owner_vm);
		free(ctx, M_SQUEUE);
		return (error);
	}

	if ((p->flags & IORING_SETUP_SINGLE_ISSUER) != 0 && !ctx->disabled)
		ctx->submitter = sq_issuer_get(td);
	if ((p->flags & IORING_SETUP_ATTACH_WQ) != 0) {
		error = fget(td, (int)p->wq_fd, &cap_no_rights, &attach_fp);
		if (error == EBADF)
			error = ENXIO;
		if (error == 0 && attach_fp->f_type != DTYPE_IORING)
			error = EINVAL;
		if (error == 0 && (p->flags & IORING_SETUP_SQPOLL) != 0 &&
		    ((((struct squeue_ctx *)attach_fp->f_data)->setup_flags &
		    IORING_SETUP_SQPOLL) == 0 ||
		    ((struct squeue_ctx *)attach_fp->f_data)->is_linux != fe->is_linux))
			error = EINVAL;
		if (error != 0) {
			if (attach_fp != NULL)
				fdrop(attach_fp, td);
			sq_ctx_free(ctx);
			return (error);
		}
		source = attach_fp->f_data;
		root = source->worker_root;
		atomic_add_int(&root->refs, 1);
		ctx->worker_root = root;
		if ((p->flags & IORING_SETUP_SQPOLL) != 0) {
			root = source->sqpoll_root;
			mtx_lock(&root->mtx);
			attach_sqpoll = root->sqpoll_running &&
			    !root->sqpoll_dead && !root->sqpoll_stop &&
			    root->sqpoll_td != NULL &&
			    root->sqpoll_td->td_proc == td->td_proc;
			mtx_unlock(&root->mtx);
		}
	}
	error = falloc(td, &fp, &fd, 0);
	if (error != 0) {
		if (attach_fp != NULL)
			fdrop(attach_fp, td);
		sq_ctx_free(ctx);
		return (error);
	}
	finit(fp, FREAD | FWRITE, DTYPE_IORING, ctx, &squeue_fileops);
	if (attach_sqpoll) {
		root = ((struct squeue_ctx *)attach_fp->f_data)->sqpoll_root;
		if (root != ctx->worker_root)
			atomic_add_int(&root->refs, 1);
		mtx_lock(&root->mtx);
		ctx->sqpoll_root = root;
		ctx->sqpoll_running = true;
		ctx->sqpoll_linked = true;
		TAILQ_INSERT_TAIL(&root->sqpoll_members, ctx,
		    sqpoll_member_entry);
		sq_sqpoll_update_idle_locked(root);
		root->sqpoll_wake_seq++;
		cv_broadcast(&root->sqpoll_cv);
		mtx_unlock(&root->mtx);
	}
	if (attach_fp != NULL)
		fdrop(attach_fp, td);
	if ((p->flags & IORING_SETUP_SQPOLL) != 0 && !attach_sqpoll) {
		error = sq_sqpoll_start(ctx, td);
		if (error != 0) {
			(void)kern_close(td, fd);
			fdrop(fp, td);
			return (error);
		}
	}

	p->sq_entries = ctx->sq_entries;
	p->cq_entries = ctx->cq_entries;
	p->features = SQ_SUPPORTED_FEATURE_FLAGS | fe->feature_flags;
	p->sq_off.head = offsetof(struct sq_rings, sq_head);
	p->sq_off.tail = offsetof(struct sq_rings, sq_tail);
	p->sq_off.ring_mask = offsetof(struct sq_rings, sq_ring_mask);
	p->sq_off.ring_entries = offsetof(struct sq_rings, sq_ring_entries);
	p->sq_off.flags = offsetof(struct sq_rings, sq_flags);
	p->sq_off.dropped = offsetof(struct sq_rings, sq_dropped);
	p->sq_off.array = ctx->sq_array != NULL ?
	    (uint32_t)((char *)ctx->sq_array - ctx->kva) : 0;
	p->cq_off.head = offsetof(struct sq_rings, cq_head);
	p->cq_off.tail = offsetof(struct sq_rings, cq_tail);
	p->cq_off.ring_mask = offsetof(struct sq_rings, cq_ring_mask);
	p->cq_off.ring_entries = offsetof(struct sq_rings, cq_ring_entries);
	p->cq_off.overflow = offsetof(struct sq_rings, cq_overflow);
	p->cq_off.cqes = (uint32_t)((char *)ctx->cqes - ctx->kva);
	p->cq_off.flags = offsetof(struct sq_rings, cq_flags);

	if ((p->flags & IORING_SETUP_REGISTERED_FD_ONLY) != 0) {
		registry = sq_ring_registry_get(td, true);
		for (slot = 0; slot < SQ_RINGFD_REG_MAX &&
		    registry->files[slot] != NULL; slot++)
			;
		if (slot == SQ_RINGFD_REG_MAX) {
			(void)kern_close(td, fd);
			fdrop(fp, td);
			return (EBUSY);
		}
		MPASS(fhold(fp));
		registry->files[slot] = fp;
		error = kern_close(td, fd);
		KASSERT(error == 0, ("registered ring setup fd close"));
		*fdp = slot;
	} else
		*fdp = fd;
	counter_u64_add(sq_stat_rings, 1);
	SDT_PROBE3(squeue, , , setup, fd, ctx->sq_entries, td->td_proc->p_pid);
	fdrop(fp, td);
	return (0);
}

/*
 * Setup front ends copy params out after the ring has been created.  Undo the
 * registered-slot ownership on a failed copyout, not an unrelated numeric fd.
 */
void
kern_squeue_setup_abort(struct thread *td, int value, uint32_t flags)
{
	struct sq_ring_registry *registry;
	struct file *fp;

	if ((flags & IORING_SETUP_REGISTERED_FD_ONLY) == 0) {
		(void)kern_close(td, value);
		return;
	}
	registry = sq_ring_registry_get(td, false);
	if (registry == NULL || value < 0 || value >= SQ_RINGFD_REG_MAX)
		return;
	fp = registry->files[value];
	registry->files[value] = NULL;
	if (fp != NULL)
		fdrop(fp, td);
}

/* Saturate the 64-bit wire time before narrowing to an sbintime deadline. */
static sbintime_t
sq_enter_deadline(struct squeue_ctx *ctx, struct thread *td,
    const struct __kernel_timespec *kt, bool absolute)
{
	struct timespec clock_now, ts;
	int64_t sec, nsec;
	sbintime_t delta, now;
	clockid_t clockid;

	/* Even an extreme tv_nsec cannot bring these seconds into range. */
	if (kt->tv_sec > INT64_C(20000000000))
		return (SBT_MAX);
	if (kt->tv_sec < -INT64_C(20000000000))
		return (1);
	sec = kt->tv_sec + kt->tv_nsec / 1000000000;
	nsec = kt->tv_nsec % 1000000000;
	if (nsec < 0) {
		sec--;
		nsec += 1000000000;
	}
	if (sec < 0)
		return (1);

	/*
	 * Callouts use uptime.  For an absolute deadline in the ring's selected
	 * clock domain, convert the remaining interval to that common base.
	 */
	if (absolute) {
		clockid = atomic_load_int(&ctx->wait_clockid);
		if (kern_clock_gettime(td, clockid, &clock_now) != 0)
			return (1);
		if (sec < clock_now.tv_sec ||
		    (sec == clock_now.tv_sec && nsec <= clock_now.tv_nsec))
			return (1);
		sec -= clock_now.tv_sec;
		nsec -= clock_now.tv_nsec;
		if (nsec < 0) {
			sec--;
			nsec += 1000000000;
		}
	}
	if (sec >= (SBT_MAX >> 32))
		return (SBT_MAX);
	ts.tv_sec = sec;
	ts.tv_nsec = nsec;
	delta = tstosbt(ts);
	now = sbinuptime();
	return (delta > SBT_MAX - now ? SBT_MAX : now + delta);
}

/* Native callers use a native sigset_t; Linux supplies its ABI translator. */
static int
sq_copy_sigset(const void *arg, size_t size, sigset_t *set)
{

	if (size != sizeof(*set))
		return (EINVAL);
	return (copyin(arg, set, sizeof(*set)));
}

static int
sq_enter_wait(struct squeue_ctx *ctx, struct thread *td, uint32_t min_complete,
    int fd, uint32_t flags, const void *arg, size_t argsz,
    int (*copy_sigset)(const void *, size_t, sigset_t *))
{
	struct io_uring_getevents_arg ext;
	struct io_uring_reg_wait reg_wait;
	struct __kernel_timespec kt;
	sigset_t set;
	const void *mask;
	size_t masksz;
	sbintime_t deadline;
	uint32_t min_wait_usec;
	int error;

	mask = arg;
	masksz = argsz;
	deadline = 0;
	min_wait_usec = 0;
	if ((flags & IORING_ENTER_EXT_ARG) != 0) {
		if ((flags & IORING_ENTER_EXT_ARG_REG) != 0) {
			uintptr_t off = (uintptr_t)arg;

			if (argsz != sizeof(reg_wait))
				return (EINVAL);
			if (off % sizeof(long) != 0 ||
			    !ctx->param_wait_arg ||
			    ctx->param_size < sizeof(reg_wait) ||
			    off > ctx->param_size - sizeof(reg_wait))
				return (EFAULT);
			bcopy(ctx->param_kva + off, &reg_wait,
			    sizeof(reg_wait));
			if ((reg_wait.flags & ~IORING_REG_WAIT_TS) != 0)
				return (EINVAL);
			min_wait_usec = reg_wait.min_wait_usec;
			mask = (const void *)(uintptr_t)reg_wait.sigmask;
			masksz = reg_wait.sigmask_sz;
			if ((reg_wait.flags & IORING_REG_WAIT_TS) != 0) {
				kt = reg_wait.ts;
				deadline = sq_enter_deadline(ctx, td, &kt,
				    (flags & IORING_ENTER_ABS_TIMER) != 0);
			}
		} else {
			if (argsz != sizeof(ext))
				return (EINVAL);
			error = copyin(arg, &ext, sizeof(ext));
			if (error != 0)
				return (error);
			min_wait_usec = ext.min_wait_usec;
			mask = (const void *)(uintptr_t)ext.sigmask;
			masksz = ext.sigmask_sz;
			if (ext.ts != 0) {
				error = copyin((const void *)(uintptr_t)ext.ts,
				    &kt, sizeof(kt));
				if (error != 0)
					return (error);
				deadline = sq_enter_deadline(ctx, td, &kt,
				    (flags & IORING_ENTER_ABS_TIMER) != 0);
			}
		}
	}

	min_complete = MIN(min_complete, ctx->cq_entries);
	mtx_lock(&ctx->mtx);
	sq_cq_flush(ctx);
	error = sq_cq_ready(ctx) >= min_complete;
	mtx_unlock(&ctx->mtx);
	/* As on Linux, a ready CQ needs no temporary signal mask. */
	if (error != 0)
		return (0);
	if (mask != NULL) {
		error = copy_sigset(mask, masksz, &set);
		if (error != 0)
			return (error);
		error = kern_sigprocmask(td, SIG_SETMASK, &set,
		    &td->td_oldsigmask, 0);
		if (error != 0)
			return (error);
		td->td_pflags |= TDP_OLDMASK;
	}
	error = sq_wait_cq(ctx, min_complete, fd, td, deadline,
	    min_wait_usec);
	if (mask != NULL) {
		/* Preserve the temporary mask until an interrupting signal runs. */
		ast_sched(td, error == EINTR ? TDA_SIGSUSPEND : TDA_PSELECT);
	}
	if (error != 0) {
		sq_run_ready(ctx, td);
		mtx_lock(&ctx->mtx);
		sq_cq_flush(ctx);
		/* An interrupted/timed-out wait can still return a partial batch. */
		if (sq_cq_ready(ctx) != 0)
			error = 0;
		mtx_unlock(&ctx->mtx);
	}
	return (error);
}

int
kern_squeue_enter_sigmask(struct thread *td, int fd, uint32_t to_submit,
    uint32_t min_complete, uint32_t flags, const void *arg, size_t argsz,
    int (*copy_sigset)(const void *, size_t, sigset_t *))
{
	struct squeue_ctx *ctx;
	struct file *fp;
	int error, submitted;

	if ((flags & ~SQ_SUPPORTED_ENTER_FLAGS) != 0)
		return (EINVAL);
	error = sq_ring_file_get(td, fd,
	    (flags & IORING_ENTER_REGISTERED_RING) != 0, &fp);
	if (error != 0)
		return (error);
	ctx = fp->f_data;
	mtx_lock(&ctx->mtx);
	error = ctx->disabled ? SQ_BAD_RING_STATE :
	    (to_submit != 0 && ctx->submitter != NULL &&
	    ctx->submitter != osd_thread_get(td, sq_issuer_slot) ? EEXIST : 0);
	mtx_unlock(&ctx->mtx);
	if (error != 0) {
		fdrop(fp, td);
		return (error);
	}
	if ((ctx->setup_flags & IORING_SETUP_SQPOLL) != 0) {
		struct squeue_ctx *root = ctx->sqpoll_root;

		mtx_lock(&root->mtx);
		if (root->sqpoll_dead || !root->sqpoll_running) {
			mtx_unlock(&root->mtx);
			fdrop(fp, td);
			return (EOWNERDEAD);
		}
		if ((flags & IORING_ENTER_SQ_WAKEUP) != 0) {
			root->sqpoll_wake_seq++;
			cv_broadcast(&root->sqpoll_cv);
		}
		mtx_unlock(&root->mtx);
		if ((flags & IORING_ENTER_SQ_WAIT) != 0) {
			mtx_lock(&ctx->mtx);
			while (atomic_load_acq_32(&ctx->rings->sq_tail) -
			    atomic_load_acq_32(&ctx->rings->sq_head) >=
			    ctx->sq_entries && !ctx->sqpoll_dead) {
				if (cv_wait_sig(&ctx->sqpoll_cv, &ctx->mtx) != 0)
					break;
			}
			mtx_unlock(&ctx->mtx);
		}
		/* Linux reports the requested count; the poller consumes SQEs. */
		submitted = to_submit;
	} else
		submitted = sq_submit(ctx, to_submit, td);
	/* Post any completions that resolved during/ahead of this submit. */
	sq_run_ready(ctx, td);
	if ((flags & IORING_ENTER_GETEVENTS) != 0 &&
	    (to_submit == 0 || submitted == to_submit)) {
		error = sq_enter_wait(ctx, td, min_complete, fd, flags, arg,
		    argsz, copy_sigset != NULL ? copy_sigset : sq_copy_sigset);
		if (error != 0 && submitted == 0) {
			fdrop(fp, td);
			return (error);
		}
	}
	fdrop(fp, td);
	td->td_retval[0] = submitted;
	return (0);
}

/* Preserve the original native in-kernel entry point and calling convention. */
int
kern_squeue_enter(struct thread *td, int fd, uint32_t to_submit,
    uint32_t min_complete, uint32_t flags, const void *arg, size_t argsz)
{

	int error;

	error = kern_squeue_enter_sigmask(td, fd, to_submit, min_complete,
	    flags, arg, argsz, NULL);
	return (error == SQ_BAD_RING_STATE ? EBADF : error);
}

/* ---- registered buffers ---- */
static int
sq_register_buffers_data(struct squeue_ctx *ctx, uint64_t iov_uptr,
    uint64_t tags_uptr, uint32_t nr, struct thread *td)
{
	struct sq_buf_table *table;
	struct iovec iov;
	uint64_t tag;
	uint32_t i;
	int error;

	mtx_lock(&ctx->mtx);
	error = ctx->reg_bufs != NULL ? EBUSY : 0;
	mtx_unlock(&ctx->mtx);
	if (error != 0)
		return (error);
	if (nr == 0 || nr > SQ_MAX_REG_BUFS)
		return (EINVAL);
	table = malloc(sizeof(*table) + nr * sizeof(*table->nodes), M_SQUEUE,
	    M_WAITOK | M_ZERO);
	refcount_init(&table->refs, 1);
	table->count = nr;
	for (i = 0; i < nr; i++) {
		memset(&iov, 0, sizeof(iov));
		if (iov_uptr != 0) {
			error = copyin((void *)(uintptr_t)(iov_uptr +
			    i * sizeof(iov)), &iov, sizeof(iov));
			if (error != 0)
				goto fail;
		}
		tag = 0;
		if (tags_uptr != 0) {
			error = copyin((void *)(uintptr_t)(tags_uptr +
			    i * sizeof(tag)), &tag, sizeof(tag));
			if (error != 0)
				goto fail;
		}
		table->nodes[i] = sq_buf_node_alloc(ctx, &iov, tag, td, &error);
		if (error != 0)
			goto fail;
	}
	mtx_lock(&ctx->mtx);
	if (ctx->reg_bufs != NULL) {
		mtx_unlock(&ctx->mtx);
		error = EBUSY;
		goto fail;
	}
	ctx->reg_bufs = table;
	ctx->reg_nbufs = nr;
	mtx_unlock(&ctx->mtx);
	return (0);
fail:
	/* Failed initial registration must never publish lifetime tag CQEs. */
	for (i = 0; i < nr; i++)
		if (table->nodes[i] != NULL)
			table->nodes[i]->tag = 0;
	sq_buf_table_rele(table);
	return (error);
}

static int
sq_register_buffers(struct squeue_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{

	return (sq_register_buffers_data(ctx, (uintptr_t)arg, 0, nr, td));
}

static int
sq_register_buffers2(struct squeue_ctx *ctx, void *arg, uint32_t size,
    struct thread *td)
{
	struct io_uring_rsrc_register rr;
	int error;

	if (size != sizeof(rr))
		return (EINVAL);
	error = copyin(arg, &rr, sizeof(rr));
	if (error != 0)
		return (error);
	if (rr.nr == 0 || rr.resv2 != 0 ||
	    (rr.flags & ~IORING_RSRC_REGISTER_SPARSE) != 0 ||
	    ((rr.flags & IORING_RSRC_REGISTER_SPARSE) != 0 && rr.data != 0))
		return (EINVAL);
	return (sq_register_buffers_data(ctx, rr.data, rr.tags, rr.nr, td));
}

static int
sq_unregister_buffers(struct squeue_ctx *ctx)
{
	struct sq_buf_table *table;

	mtx_lock(&ctx->mtx);
	table = ctx->reg_bufs;
	if (table == NULL) {
		mtx_unlock(&ctx->mtx);
		return (ENXIO);
	}
	ctx->reg_bufs = NULL;
	ctx->reg_nbufs = 0;
	mtx_unlock(&ctx->mtx);
	sq_buf_table_rele(table);
	return (0);
}

static int
sq_buf_table_replace(struct squeue_ctx *ctx, uint32_t idx,
    struct sq_buf_node *node)
{
	struct sq_buf_table *old, *new;
	uint32_t i, nr;

	/* register_sx serializes table shape; ctx->mtx protects readers. */
	nr = ctx->reg_nbufs;
	new = malloc(sizeof(*new) + nr * sizeof(*new->nodes), M_SQUEUE,
	    M_WAITOK | M_ZERO);
	refcount_init(&new->refs, 1);
	new->count = nr;
	mtx_lock(&ctx->mtx);
	old = ctx->reg_bufs;
	if (old == NULL || idx >= old->count) {
		mtx_unlock(&ctx->mtx);
		free(new, M_SQUEUE);
		return (old == NULL ? ENXIO : EINVAL);
	}
	for (i = 0; i < nr; i++) {
		if (i == idx)
			continue;
		new->nodes[i] = old->nodes[i];
		if (new->nodes[i] != NULL)
			refcount_acquire(&new->nodes[i]->refs);
	}
	new->nodes[idx] = node;
	ctx->reg_bufs = new;
	mtx_unlock(&ctx->mtx);
	sq_buf_table_rele(old);
	return (0);
}

static int
sq_buffers_update2(struct squeue_ctx *ctx, void *arg, uint32_t size,
    struct thread *td)
{
	struct io_uring_rsrc_update2 up;
	struct sq_buf_node *node;
	struct iovec iov;
	uint64_t tag;
	uint32_t done;
	int error;

	if (size != sizeof(up))
		return (EINVAL);
	error = copyin(arg, &up, sizeof(up));
	if (error != 0)
		return (error);
	if (up.nr == 0 || up.resv != 0 || up.resv2 != 0)
		return (EINVAL);
	if (up.nr > UINT32_MAX - up.offset)
		return (EOVERFLOW);
	mtx_lock(&ctx->mtx);
	error = ctx->reg_bufs == NULL ? ENXIO :
	    (up.offset >= ctx->reg_nbufs ||
	    up.nr > ctx->reg_nbufs - up.offset ? EINVAL : 0);
	mtx_unlock(&ctx->mtx);
	if (error != 0)
		return (error);
	for (done = 0; done < up.nr; done++) {
		error = copyin((void *)(uintptr_t)(up.data + done * sizeof(iov)),
		    &iov, sizeof(iov));
		if (error != 0)
			break;
		tag = 0;
		if (up.tags != 0) {
			error = copyin((void *)(uintptr_t)(up.tags +
			    done * sizeof(tag)), &tag, sizeof(tag));
			if (error != 0)
				break;
		}
		node = sq_buf_node_alloc(ctx, &iov, tag, td, &error);
		if (error != 0)
			break;
		error = sq_buf_table_replace(ctx, up.offset + done, node);
		if (error != 0) {
			node->tag = 0;
			sq_buf_node_rele(node);
			break;
		}
	}
	if (done != 0)
		error = 0;
	td->td_retval[0] = done;
	return (error);
}

/* ---- registered files ---- */
static int
sq_register_files_data(struct squeue_ctx *ctx, uint64_t fds_uptr,
    uint64_t tags_uptr, uint32_t nr, int limit_error, struct thread *td)
{
	struct sq_file_node **nodes;
	uint64_t tag;
	uint32_t i;
	int error, fd;

	sx_xlock(&ctx->files_sx);
	if (ctx->reg_files != NULL) {
		error = EBUSY;
		goto out;
	}
	if (nr == 0 || nr > SQ_MAX_REG_FILES) {
		error = nr > SQ_MAX_REG_FILES ? limit_error : EINVAL;
		goto out;
	}
	nodes = mallocarray(nr, sizeof(*nodes), M_SQUEUE, M_WAITOK | M_ZERO);
	error = 0;
	for (i = 0; i < nr; i++) {
		tag = 0;
		if (tags_uptr != 0) {
			error = copyin((void *)(uintptr_t)(tags_uptr +
			    i * sizeof(tag)), &tag, sizeof(tag));
			if (error != 0)
				break;
		}
		fd = -1;
		if (fds_uptr != 0) {
			error = copyin((void *)(uintptr_t)(fds_uptr +
			    i * sizeof(fd)), &fd, sizeof(fd));
			if (error != 0)
				break;
		}
		if (fd == -1) {
			if (tag != 0)
				error = EINVAL;
			if (error != 0)
				break;
			continue;
		}
		nodes[i] = sq_file_node_alloc(ctx, td, fd, tag, &error);
		if (error != 0)
			break;
	}
	if (error != 0) {
		/* Failed initial registration must not emit tag CQEs. */
		for (i = 0; i < nr; i++) {
			if (nodes[i] != NULL)
				nodes[i]->tag = 0;
			sq_file_node_rele(nodes[i], td);
		}
		free(nodes, M_SQUEUE);
		goto out;
	}
	ctx->reg_files = nodes;
	ctx->reg_nfiles = nr;
	ctx->file_alloc_start = 0;
	ctx->file_alloc_end = nr;
	ctx->file_alloc_hint = 0;
out:
	sx_xunlock(&ctx->files_sx);
	return (error);
}

static int
sq_register_files(struct squeue_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{

	return (sq_register_files_data(ctx, (uintptr_t)arg, 0, nr, EINVAL, td));
}

static int
sq_register_files2(struct squeue_ctx *ctx, void *arg, uint32_t size,
    struct thread *td)
{
	struct io_uring_rsrc_register rr;
	int error;

	if (size != sizeof(rr))
		return (EINVAL);
	error = copyin(arg, &rr, sizeof(rr));
	if (error != 0)
		return (error);
	if (rr.nr == 0 || rr.resv2 != 0 ||
	    (rr.flags & ~IORING_RSRC_REGISTER_SPARSE) != 0 ||
	    ((rr.flags & IORING_RSRC_REGISTER_SPARSE) != 0 && rr.data != 0))
		return (EINVAL);
	return (sq_register_files_data(ctx, rr.data, rr.tags, rr.nr, EMFILE, td));
}

static int
sq_unregister_files(struct squeue_ctx *ctx, struct thread *td)
{
	struct sq_file_node **nodes;
	uint32_t i, nr;

	sx_xlock(&ctx->files_sx);
	if (ctx->reg_files == NULL) {
		sx_xunlock(&ctx->files_sx);
		return (ENXIO);
	}
	nodes = ctx->reg_files;
	nr = ctx->reg_nfiles;
	ctx->reg_files = NULL;
	ctx->reg_nfiles = 0;
	ctx->file_alloc_start = 0;
	ctx->file_alloc_end = 0;
	ctx->file_alloc_hint = 0;
	sx_xunlock(&ctx->files_sx);
	for (i = 0; i < nr; i++)
		sq_file_node_rele(nodes[i], td);
	free(nodes, M_SQUEUE);
	return (0);
}

int
sq_install_direct_fd(struct squeue_ctx *ctx, struct thread *td, int fd,
    uint32_t file_index, int32_t *resultp)
{
	struct sq_file_node *node, *oldnode;
	uint32_t i, slot;
	bool alloc;
	int error;

	alloc = file_index == IORING_FILE_INDEX_ALLOC;
	node = oldnode = NULL;
	sx_xlock(&ctx->files_sx);
	if (ctx->reg_files == NULL) {
		error = ENXIO;
		goto out;
	}
	if (alloc) {
		slot = ctx->file_alloc_hint;
		for (i = 0; i < ctx->file_alloc_end - ctx->file_alloc_start; i++) {
			if (slot >= ctx->file_alloc_end)
				slot = ctx->file_alloc_start;
			if (ctx->reg_files[slot] == NULL)
				break;
			slot++;
		}
		if (i == ctx->file_alloc_end - ctx->file_alloc_start) {
			error = ENFILE;
			goto out;
		}
	} else {
		if (file_index == 0 || file_index - 1 >= ctx->reg_nfiles) {
			error = EINVAL;
			goto out;
		}
		slot = file_index - 1;
	}
	node = sq_file_node_alloc(ctx, td, fd, 0, &error);
	if (error != 0)
		goto out;
	oldnode = ctx->reg_files[slot];
	ctx->reg_files[slot] = node;
	node = NULL;
	if (alloc) {
		ctx->file_alloc_hint = slot + 1;
		if (ctx->file_alloc_hint >= ctx->file_alloc_end)
			ctx->file_alloc_hint = ctx->file_alloc_start;
	}
	*resultp = alloc ? (int32_t)slot : 0;
out:
	sx_xunlock(&ctx->files_sx);
	sq_file_node_rele(node, td);
	sq_file_node_rele(oldnode, td);
	(void)kern_close(td, fd);
	return (error);
}

int
sq_install_direct_fds(struct squeue_ctx *ctx, struct thread *td, int fds[2],
    uint32_t file_index, uint64_t result_uptr)
{
	struct sq_file_node *nodes[2] = { NULL, NULL };
	struct sq_file_node *oldnodes[2] = { NULL, NULL };
	struct sq_file_node *removed[2] = { NULL, NULL };
	uint32_t i, j, slot[2], scan, span;
	int results[2], error, installed;
	bool alloc;

	installed = 0;
	alloc = file_index == IORING_FILE_INDEX_ALLOC;
	nodes[0] = sq_file_node_alloc(ctx, td, fds[0], 0, &error);
	if (error == 0)
		nodes[1] = sq_file_node_alloc(ctx, td, fds[1], 0, &error);
	(void)kern_close(td, fds[0]);
	(void)kern_close(td, fds[1]);
	if (error != 0)
		goto out;

	sx_xlock(&ctx->files_sx);
	if (ctx->reg_files == NULL) {
		error = ENXIO;
		goto unlock;
	}
	span = ctx->file_alloc_end - ctx->file_alloc_start;
	scan = ctx->file_alloc_hint;
	for (j = 0; j < 2; j++) {
		if (alloc) {
			for (i = 0; i < span; i++) {
				if (scan >= ctx->file_alloc_end)
					scan = ctx->file_alloc_start;
				if (ctx->reg_files[scan] == NULL)
					break;
				scan++;
			}
			if (i == span) {
				error = ENFILE;
				goto rollback;
			}
			slot[j] = scan++;
			results[j] = (int)slot[j];
		} else {
			if (file_index == 0 || file_index - 1 >= ctx->reg_nfiles) {
				error = EINVAL;
				goto rollback;
			}
			slot[j] = file_index - 1;
			file_index++;
			results[j] = 0;
		}
		oldnodes[j] = ctx->reg_files[slot[j]];
		ctx->reg_files[slot[j]] = nodes[j];
		nodes[j] = NULL;
		installed++;
	}
	error = copyout(results, (void *)(uintptr_t)result_uptr,
	    sizeof(results));
	if (error != 0)
		goto rollback;
	if (alloc) {
		ctx->file_alloc_hint = slot[1] + 1;
		if (ctx->file_alloc_hint >= ctx->file_alloc_end)
			ctx->file_alloc_hint = ctx->file_alloc_start;
	}
	goto unlock;
rollback:
	for (i = 0; i < (uint32_t)installed; i++) {
		removed[i] = ctx->reg_files[slot[i]];
		ctx->reg_files[slot[i]] = NULL;
	}
unlock:
	sx_xunlock(&ctx->files_sx);
out:
	for (i = 0; i < 2; i++) {
		sq_file_node_rele(nodes[i], td);
		sq_file_node_rele(oldnodes[i], td);
		sq_file_node_rele(removed[i], td);
	}
	return (error);
}

static int
sq_register_file_alloc_range(struct squeue_ctx *ctx, void *arg, uint32_t nr)
{
	struct io_uring_file_index_range range;
	uint32_t end;
	int error;

	if (arg == NULL || nr != 0)
		return (EINVAL);
	if ((error = copyin(arg, &range, sizeof(range))) != 0)
		return (error);
	if (range.len > UINT32_MAX - range.off)
		return (EOVERFLOW);
	end = range.off + range.len;
	sx_xlock(&ctx->files_sx);
	if (ctx->reg_files == NULL)
		error = ENXIO;
	else if (range.resv != 0 || end > ctx->reg_nfiles)
		error = EINVAL;
	else {
		ctx->file_alloc_start = range.off;
		ctx->file_alloc_end = end;
		ctx->file_alloc_hint = range.off;
		error = 0;
	}
	sx_xunlock(&ctx->files_sx);
	return (error);
}

/* IORING_REGISTER_FILES_UPDATE: unpack the struct, then update a slot range. */
static int
sq_files_update(struct squeue_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{
	struct io_uring_files_update up;
	int error;

	if (nr == 0)
		return (EINVAL);
	error = copyin(arg, &up, sizeof(up));
	if (error != 0)
		return (error);
	if (up.resv != 0)
		return (EINVAL);
	return (sq_do_files_update(ctx, up.offset, up.fds, 0, nr, td));
}

static int
sq_files_update2(struct squeue_ctx *ctx, void *arg, uint32_t size,
    struct thread *td)
{
	struct io_uring_rsrc_update2 up;
	int error;

	if (size != sizeof(up))
		return (EINVAL);
	error = copyin(arg, &up, sizeof(up));
	if (error != 0)
		return (error);
	if (up.nr == 0 || up.resv != 0 || up.resv2 != 0)
		return (EINVAL);
	return (sq_do_files_update(ctx, up.offset, up.data, up.tags, up.nr, td));
}

/* Register calls and FILES_UPDATE SQEs share this table lifetime lock.
 * Each imported descriptor commits separately, as on Linux: a later failure
 * returns the completed prefix, and an invalid fd clears its destination. */
static int
sq_do_files_update_alloc(struct squeue_ctx *ctx, uint64_t fds_uptr,
    uint32_t nr, struct thread *td)
{
	struct sq_file_node *node;
	uint32_t done, i, slot;
	int error, fd;

	error = 0;
	for (done = 0; done < nr; done++) {
		error = copyin((void *)(uintptr_t)(fds_uptr +
		    done * sizeof(fd)), &fd, sizeof(fd));
		if (error != 0)
			break;
		node = sq_file_node_alloc(ctx, td, fd, 0, &error);
		if (error != 0)
			break;

		sx_xlock(&ctx->files_sx);
		if (ctx->reg_files == NULL) {
			error = ENXIO;
			goto unlock;
		}
		slot = ctx->file_alloc_hint;
		for (i = 0; i < ctx->file_alloc_end - ctx->file_alloc_start; i++) {
			if (slot >= ctx->file_alloc_end)
				slot = ctx->file_alloc_start;
			if (ctx->reg_files[slot] == NULL)
				break;
			slot++;
		}
		if (i == ctx->file_alloc_end - ctx->file_alloc_start) {
			error = ENFILE;
			goto unlock;
		}
		ctx->reg_files[slot] = node;
		ctx->file_alloc_hint = slot + 1;
		if (ctx->file_alloc_hint >= ctx->file_alloc_end)
			ctx->file_alloc_hint = ctx->file_alloc_start;
		error = copyout(&slot, (void *)(uintptr_t)(fds_uptr +
		    done * sizeof(fd)), sizeof(fd));
		if (error == 0)
			node = NULL;
		else {
			ctx->reg_files[slot] = NULL;
			ctx->file_alloc_hint = slot;
		}
unlock:
		sx_xunlock(&ctx->files_sx);
		sq_file_node_rele(node, td);
		if (error != 0)
			break;
	}
	if (done != 0)
		error = 0;
	td->td_retval[0] = done;
	return (error);
}

static int
sq_do_files_update(struct squeue_ctx *ctx, uint32_t off, uint64_t fds_uptr,
    uint64_t tags_uptr, uint32_t nr, struct thread *td)
{
	struct sq_file_node **oldnodes, *node;
	uint64_t tag;
	uint32_t done, i;
	int error, fd;

	if (nr == 0)
		return (EINVAL);
	if (nr > UINT32_MAX - off)
		return (EOVERFLOW);
	oldnodes = mallocarray(nr, sizeof(*oldnodes), M_SQUEUE,
	    M_WAITOK | M_ZERO);
	sx_xlock(&ctx->files_sx);
	if (ctx->reg_files == NULL) {
		error = ENXIO;
		goto out;
	}
	if (off >= ctx->reg_nfiles || nr > ctx->reg_nfiles - off) {
		error = EINVAL;
		goto out;
	}
	error = 0;
	for (done = 0; done < nr; done++) {
		tag = 0;
		if (tags_uptr != 0) {
			error = copyin((void *)(uintptr_t)(tags_uptr +
			    done * sizeof(tag)), &tag, sizeof(tag));
			if (error != 0)
				break;
		}
		error = copyin((void *)(uintptr_t)(fds_uptr + done * sizeof(fd)),
		    &fd, sizeof(fd));
		if (error != 0)
			break;
		if ((fd == IORING_REGISTER_FILES_SKIP || fd == -1) && tag != 0) {
			error = EINVAL;
			break;
		}
		if (fd == IORING_REGISTER_FILES_SKIP)
			continue;
		oldnodes[done] = ctx->reg_files[off + done];
		ctx->reg_files[off + done] = NULL;
		if (oldnodes[done] != NULL)
			ctx->file_alloc_hint = off + done;
		if (fd != -1) {
			node = sq_file_node_alloc(ctx, td, fd, tag, &error);
			if (error != 0)
				break;
			ctx->reg_files[off + done] = node;
			ctx->file_alloc_hint = off + done + 1;
		}
	}
	if (done != 0)
		error = 0;
	td->td_retval[0] = done;
out:
	sx_xunlock(&ctx->files_sx);
	for (i = 0; i < nr; i++)
		sq_file_node_rele(oldnodes[i], td);
	free(oldnodes, M_SQUEUE);
	return (error);
}

static int
sq_register_probe(struct squeue_ctx *ctx, void *arg, uint32_t nr)
{
	struct io_uring_probe *probe;
	size_t sz;
	uint32_t i;
	int error;

	if (arg == NULL || nr > 256)
		return (EINVAL);
	if (nr > IORING_OP_LAST)
		nr = IORING_OP_LAST;
	sz = sizeof(*probe) + nr * sizeof(struct io_uring_probe_op);
	probe = malloc(sz, M_SQUEUE, M_WAITOK | M_ZERO);
	error = copyin(arg, probe, sz);
	if (error != 0)
		goto out;
	/* The entire input, including entry fields, must initially be zero. */
	if (memcchr(probe, 0, sz) != NULL) {
		error = EINVAL;
		goto out;
	}
	probe->last_op = IORING_OP_LAST - 1;
	probe->ops_len = nr;
	for (i = 0; i < nr; i++) {
		probe->ops[i].op = i;
		probe->ops[i].flags = sq_op_supported(ctx, i) ?
		    IO_URING_OP_SUPPORTED : 0;
	}
	error = copyout(probe, arg, sz);
out:
	free(probe, M_SQUEUE);
	return (error);
}

/*
 * EVENTFD and EVENTFD_ASYNC share one registration slot and retain the eventfd
 * file.  Ordinary mode signals when a CQE is published; async mode signals at
 * the worker-to-ready boundary so an event loop can call enter and publish the
 * worker's completion in the owning thread's context.
 */
static int
sq_register_eventfd(struct squeue_ctx *ctx, void *arg, uint32_t nr,
    bool async, struct thread *td)
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
	ctx->eventfd_async = async;
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
	ctx->eventfd_async = false;
	mtx_unlock(&ctx->mtx);
	if (efp == NULL)
		return (ENXIO);
	fdrop(efp, td);
	return (0);
}

static int
sq_register_restrictions(struct squeue_ctx *ctx, void *arg, uint32_t nr)
{
	struct io_uring_restriction *res;
	uint8_t ops[IORING_OP_LAST] = {0}, reg[IORING_REGISTER_LAST] = {0};
	uint8_t allowed = 0, required = 0;
	int error;
	uint32_t i;

	if (!ctx->disabled)
		return (SQ_BAD_RING_STATE);
	if (ctx->restrictions_registered)
		return (EBUSY);
	if (arg == NULL || nr > IORING_RESTRICTION_LAST + IORING_REGISTER_LAST + IORING_OP_LAST)
		return (EINVAL);
	res = mallocarray(MAX(nr, 1), sizeof(*res), M_SQUEUE, M_WAITOK);
	error = nr == 0 ? 0 : copyin(arg, res, nr * sizeof(*res));
	for (i = 0; error == 0 && i < nr; i++) {
		switch (res[i].opcode) {
		case IORING_RESTRICTION_REGISTER_OP:
			if (res[i].register_op >= IORING_REGISTER_LAST) error = EINVAL;
			else reg[res[i].register_op] = 1;
			break;
		case IORING_RESTRICTION_SQE_OP:
			if (res[i].sqe_op >= IORING_OP_LAST) error = EINVAL;
			else ops[res[i].sqe_op] = 1;
			break;
		case IORING_RESTRICTION_SQE_FLAGS_ALLOWED:
			allowed = res[i].sqe_flags;
			break;
		case IORING_RESTRICTION_SQE_FLAGS_REQUIRED:
			required = res[i].sqe_flags;
			break;
		default:
			error = EINVAL;
		}
	}
	free(res, M_SQUEUE);
	if (error != 0)
		return (error);
	memcpy(ctx->allowed_ops, ops, sizeof(ops));
	memcpy(ctx->allowed_register, reg, sizeof(reg));
	ctx->allowed_sqe_flags = allowed;
	ctx->required_sqe_flags = required;
	ctx->restrictions_registered = true;
	return (0);
}

static int
sq_enable(struct squeue_ctx *ctx, struct thread *td)
{
	struct sq_issuer *id = NULL;

	if (!ctx->disabled)
		return (SQ_BAD_RING_STATE);
	if ((ctx->setup_flags & IORING_SETUP_SINGLE_ISSUER) != 0)
		id = sq_issuer_get(td);
	mtx_lock(&ctx->mtx);
	ctx->submitter = id;
	ctx->restricted = ctx->restrictions_registered;
	ctx->disabled = false;
	mtx_unlock(&ctx->mtx);
	if ((ctx->setup_flags & IORING_SETUP_SQPOLL) != 0) {
		struct squeue_ctx *root = ctx->sqpoll_root;

		mtx_lock(&root->mtx);
		root->sqpoll_wake_seq++;
		cv_broadcast(&root->sqpoll_cv);
		mtx_unlock(&root->mtx);
	}
	return (0);
}

static int
sq_register_sync_cancel(struct squeue_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{
	const uint32_t mask = IORING_ASYNC_CANCEL_ALL |
	    IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_ANY |
	    IORING_ASYNC_CANCEL_FD_FIXED | IORING_ASYNC_CANCEL_USERDATA |
	    IORING_ASYNC_CANCEL_OP;
	struct io_uring_sync_cancel_reg reg;
	struct sq_cancel_match match;
	sbintime_t deadline;
	bool all, waited;
	int error, result;

	if (arg == NULL || nr != 1)
		return (EINVAL);
	if ((error = copyin(arg, &reg, sizeof(reg))) != 0)
		return (error);
	if ((reg.flags & ~mask) != 0 || reg.pad[0] != 0 ||
	    reg.pad[1] != 0 || reg.pad[2] != 0 || reg.pad[3] != 0 ||
	    reg.pad[4] != 0 || reg.pad[5] != 0 || reg.pad[6] != 0 ||
	    reg.pad2[0] != 0 || reg.pad2[1] != 0 || reg.pad2[2] != 0)
		return (EINVAL);
	deadline = 0;
	memset(&match, 0, sizeof(match));
	match.user_data = reg.addr;
	match.flags = reg.flags;
	match.opcode = reg.opcode;
	if ((reg.flags & IORING_ASYNC_CANCEL_FD) != 0) {
		if ((reg.flags & IORING_ASYNC_CANCEL_FD_FIXED) != 0) {
			sx_slock(&ctx->files_sx);
			if (reg.fd < 0 || (uint32_t)reg.fd >= ctx->reg_nfiles ||
			    ctx->reg_files == NULL || ctx->reg_files[reg.fd] == NULL ||
			    !fhold(ctx->reg_files[reg.fd]->fp))
				match.fp = NULL;
			else
				match.fp = ctx->reg_files[reg.fd]->fp;
			sx_sunlock(&ctx->files_sx);
			if (match.fp == NULL)
				return (EBADF);
		} else {
			error = fget(td, reg.fd, &cap_no_rights, &match.fp);
			if (error != 0)
				return (error);
		}
	}
	all = (reg.flags & (IORING_ASYNC_CANCEL_ALL |
	    IORING_ASYNC_CANCEL_ANY)) != 0;
	waited = false;
	mtx_lock(&ctx->mtx);
	for (;;) {
		result = sq_cancel_match(ctx, &match, false, all, NULL);
		if (result != sq_err(ctx, EALREADY))
			break;
		if (!waited && (reg.timeout.tv_sec != -1 ||
		    reg.timeout.tv_nsec != -1)) {
			sbintime_t delta, now;

			now = sbinuptime();
			if (reg.timeout.tv_sec >= (SBT_MAX >> 32))
				deadline = SBT_MAX;
			else {
				delta = reg.timeout.tv_sec * SBT_1S +
				    nstosbt(reg.timeout.tv_nsec);
				if (delta <= 0)
					deadline = now;
				else if (SBT_MAX - now < delta)
					deadline = SBT_MAX;
				else
					deadline = now + delta;
			}
		}
		waited = true;
		ctx->cq_waiters++;
		error = msleep_sbt(&ctx->cq_waiters, &ctx->mtx, PCATCH,
		    "sqsync", deadline, 0, deadline != 0 ? C_ABSOLUTE : 0);
		ctx->cq_waiters--;
		if (error != 0) {
			result = error == EWOULDBLOCK ? ETIMEDOUT : EINTR;
			break;
		}
	}
	mtx_unlock(&ctx->mtx);
	if (match.fp != NULL)
		fdrop(match.fp, td);
	if (result == ETIMEDOUT || result == EINTR)
		return (result);
	if (result == sq_err(ctx, ENOENT))
		return (waited ? 0 : ENOENT);
	if (result == sq_err(ctx, EALREADY))
		return (EALREADY);
	if (result < 0)
		return (EINVAL);
	td->td_retval[0] = result;
	return (0);
}

static int
sq_register_iowq_affinity(struct squeue_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{
	cpuset_t allowed, mask;
	size_t len;
	int error;

	if (arg == NULL || nr == 0)
		return (EINVAL);
	CPU_ZERO(&mask);
	len = MIN((size_t)nr, sizeof(mask));
	error = copyin(arg, &mask, len);
	if (error != 0)
		return (error);
	error = kern_cpuset_getaffinity(td, CPU_LEVEL_WHICH, CPU_WHICH_TID,
	    td->td_tid, sizeof(allowed), &allowed);
	if (error != 0)
		return (error);
	if (CPU_EMPTY(&mask) || !CPU_SUBSET(&allowed, &mask))
		return (EINVAL);
	ctx = sq_wq_owner(ctx);
	mtx_lock(&sq_wq_mtx);
	CPU_COPY(&mask, &ctx->worker_affinity);
	ctx->worker_affinity_set = true;
	cv_broadcast(&sq_wq_cv);
	mtx_unlock(&sq_wq_mtx);
	return (0);
}

static int
sq_unregister_iowq_affinity(struct squeue_ctx *ctx, void *arg, uint32_t nr)
{

	if (arg != NULL || nr != 0)
		return (EINVAL);
	ctx = sq_wq_owner(ctx);
	mtx_lock(&sq_wq_mtx);
	ctx->worker_affinity_set = false;
	cv_broadcast(&sq_wq_cv);
	mtx_unlock(&sq_wq_mtx);
	return (0);
}

static int
sq_register_iowq_max_workers(struct squeue_ctx *ctx, void *arg, uint32_t nr)
{
	uint32_t counts[SQ_WORKER_CLASSES], previous[SQ_WORKER_CLASSES];
	int error, i;

	if (arg == NULL || nr != SQ_WORKER_CLASSES)
		return (EINVAL);
	error = copyin(arg, counts, sizeof(counts));
	if (error != 0)
		return (error);
	for (i = 0; i < SQ_WORKER_CLASSES; i++)
		if (counts[i] > INT_MAX)
			return (EINVAL);
	ctx = sq_wq_owner(ctx);
	mtx_lock(&sq_wq_mtx);
	for (i = 0; i < SQ_WORKER_CLASSES; i++) {
		previous[i] = ctx->worker_max[i];
		if (counts[i] != 0)
			ctx->worker_max[i] = counts[i];
	}
	cv_broadcast(&sq_wq_cv);
	mtx_unlock(&sq_wq_mtx);
	/* Linux applies the limits before returning the previous pair. */
	return (copyout(previous, arg, sizeof(previous)));
}

static struct ucred *
sq_personality_get(struct squeue_ctx *ctx, uint16_t id)
{
	struct sq_personality *personality;
	struct ucred *cred;

	cred = NULL;
	mtx_lock(&ctx->mtx);
	LIST_FOREACH(personality, &ctx->personalities, link)
		if (personality->id == id) {
			cred = crhold(personality->cred);
			break;
		}
	mtx_unlock(&ctx->mtx);
	return (cred);
}

static int
sq_register_send_msg_ring(void *arg, uint32_t nr, struct thread *td)
{
	struct io_uring_sqe sqe;
	struct squeue_ctx *tctx;
	struct file *tfp;
	bool posted;
	int error;

	if (arg == NULL || nr != 1)
		return (EINVAL);
	error = copyin(arg, &sqe, sizeof(sqe));
	if (error != 0)
		return (error);
	/* Linux's blind command accepts only a flagless MSG_DATA SQE. */
	if (sqe.opcode != IORING_OP_MSG_RING || sqe.flags != 0 ||
	    sqe.buf_index != 0 || sqe.personality != 0 ||
	    sqe.addr != IORING_MSG_DATA || sqe.addr3 != 0 ||
	    (sqe.msg_ring_flags & ~IORING_MSG_RING_FLAGS_PASS) != 0 ||
	    ((sqe.msg_ring_flags & IORING_MSG_RING_FLAGS_PASS) == 0 &&
	    sqe.file_index != 0))
		return (EINVAL);
	error = fget(td, sqe.fd, &cap_no_rights, &tfp);
	if (error != 0)
		return (error);
	if (tfp->f_type != DTYPE_IORING) {
		fdrop(tfp, td);
		return (SQ_BAD_RING_STATE);
	}
	tctx = tfp->f_data;
	mtx_lock(&tctx->mtx);
	if (tctx->disabled) {
		mtx_unlock(&tctx->mtx);
		fdrop(tfp, td);
		return (SQ_BAD_RING_STATE);
	}
	posted = sq_post_cqe_impl(tctx, sqe.off, (int32_t)sqe.len,
	    (sqe.msg_ring_flags & IORING_MSG_RING_FLAGS_PASS) != 0 ?
	    sqe.file_index : 0);
	if (posted)
		sq_wake(tctx);
	mtx_unlock(&tctx->mtx);
	fdrop(tfp, td);
	return (posted ? 0 : EOVERFLOW);
}

static int
sq_register_personality(struct squeue_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{
	struct sq_personality *personality, *scan;
	uint32_t attempts;
	uint16_t id;

	if (arg != NULL || nr != 0)
		return (EINVAL);
	personality = malloc(sizeof(*personality), M_SQUEUE, M_WAITOK | M_ZERO);
	personality->cred = crhold(td->td_ucred);
	mtx_lock(&ctx->mtx);
	for (attempts = 0; attempts < UINT16_MAX; attempts++) {
		id = ctx->personality_next++;
		if (ctx->personality_next == 0)
			ctx->personality_next = 1;
		LIST_FOREACH(scan, &ctx->personalities, link)
			if (scan->id == id)
				break;
		if (scan == NULL)
			break;
	}
	if (attempts == UINT16_MAX) {
		mtx_unlock(&ctx->mtx);
		crfree(personality->cred);
		free(personality, M_SQUEUE);
		return (ENOSPC);
	}
	personality->id = id;
	LIST_INSERT_HEAD(&ctx->personalities, personality, link);
	mtx_unlock(&ctx->mtx);
	td->td_retval[0] = id;
	return (0);
}

static int
sq_unregister_personality(struct squeue_ctx *ctx, void *arg, uint32_t id)
{
	struct sq_personality *personality;

	if (arg != NULL || id == 0 || id > UINT16_MAX)
		return (EINVAL);
	mtx_lock(&ctx->mtx);
	LIST_FOREACH(personality, &ctx->personalities, link)
		if (personality->id == id)
			break;
	if (personality != NULL)
		LIST_REMOVE(personality, link);
	mtx_unlock(&ctx->mtx);
	if (personality == NULL)
		return (EINVAL);
	crfree(personality->cred);
	free(personality, M_SQUEUE);
	return (0);
}

static int
sq_ringfds_register(void *arg, uint32_t nr, struct thread *td)
{
	struct sq_ring_registry *registry;
	struct io_uring_rsrc_update update;
	struct file *fp;
	uint32_t done, end, i, start;
	int error;

	if (nr == 0 || nr > SQ_RINGFD_REG_MAX)
		return (EINVAL);
	registry = sq_ring_registry_get(td, true);
	error = 0;
	for (done = 0; done < nr; done++) {
		error = copyin((char *)arg + done * sizeof(update), &update,
		    sizeof(update));
		if (error != 0)
			break;
		if (update.resv != 0) {
			error = EINVAL;
			break;
		}
		if (update.offset == UINT32_MAX) {
			start = 0;
			end = SQ_RINGFD_REG_MAX;
		} else if (update.offset < SQ_RINGFD_REG_MAX) {
			start = update.offset;
			end = start + 1;
		} else {
			error = EINVAL;
			break;
		}
		error = sq_ring_file_get(td, (uint32_t)update.data, false, &fp);
		if (error != 0)
			break;
		for (i = start; i < end && registry->files[i] != NULL; i++)
			;
		if (i == end) {
			fdrop(fp, td);
			error = EBUSY;
			break;
		}
		registry->files[i] = fp;
		update.offset = i;
		error = copyout(&update, (char *)arg + done * sizeof(update),
		    sizeof(update));
		if (error != 0) {
			registry->files[i] = NULL;
			fdrop(fp, td);
			break;
		}
	}
	if (done != 0)
		error = 0;
	td->td_retval[0] = done;
	return (error);
}

static int
sq_ringfds_unregister(void *arg, uint32_t nr, struct thread *td)
{
	struct sq_ring_registry *registry;
	struct io_uring_rsrc_update update;
	uint32_t done;
	int error;

	if (nr == 0 || nr > SQ_RINGFD_REG_MAX)
		return (EINVAL);
	registry = sq_ring_registry_get(td, false);
	if (registry == NULL) {
		td->td_retval[0] = 0;
		return (0);
	}
	error = 0;
	for (done = 0; done < nr; done++) {
		error = copyin((char *)arg + done * sizeof(update), &update,
		    sizeof(update));
		if (error != 0)
			break;
		if (update.resv != 0 || update.data != 0 ||
		    update.offset >= SQ_RINGFD_REG_MAX) {
			error = EINVAL;
			break;
		}
		if (registry->files[update.offset] != NULL) {
			fdrop(registry->files[update.offset], td);
			registry->files[update.offset] = NULL;
		}
	}
	if (done != 0)
		error = 0;
	td->td_retval[0] = done;
	return (error);
}

static int
sq_clone_buffers(struct squeue_ctx *dst, void *arg, uint32_t nr_args,
    struct thread *td)
{
	struct io_uring_clone_buffers cb;
	struct sq_buf_table *source, *old, *new;
	struct squeue_ctx *src;
	struct file *srcfp;
	uint32_t clone_nr, dst_count, i;
	int error;

	if (arg == NULL || nr_args != 1)
		return (EINVAL);
	error = copyin(arg, &cb, sizeof(cb));
	if (error != 0)
		return (error);
	if ((cb.flags & ~(IORING_REGISTER_SRC_REGISTERED |
	    IORING_REGISTER_DST_REPLACE)) != 0 ||
	    memcchr(cb.pad, 0, sizeof(cb.pad)) != NULL)
		return (EINVAL);
	error = sq_ring_file_get(td, cb.src_fd,
	    (cb.flags & IORING_REGISTER_SRC_REGISTERED) != 0, &srcfp);
	if (error != 0)
		return (error);
	src = srcfp->f_data;
	error = 0;
	sx_xlock(&src->register_sx);
	if (src->submitter != NULL &&
	    src->submitter != osd_thread_get(td, sq_issuer_slot))
		error = EEXIST;
	else if (dst->owner_uid != src->owner_uid ||
	    dst->owner_vm != src->owner_vm)
		error = EINVAL;
	mtx_lock(&src->mtx);
	source = src->reg_bufs;
	if (source != NULL)
		refcount_acquire(&source->refs);
	mtx_unlock(&src->mtx);
	sx_xunlock(&src->register_sx);
	if (error != 0)
		goto out_file;
	sx_xlock(&dst->register_sx);
	if (dst->submitter != NULL &&
	    dst->submitter != osd_thread_get(td, sq_issuer_slot))
		error = EEXIST;
	else if (dst->restricted &&
	    !dst->allowed_register[IORING_REGISTER_CLONE_BUFFERS])
		error = EACCES;
	else if (cb.nr == 0 && (cb.src_off != 0 || cb.dst_off != 0))
		error = EINVAL;
	else if (dst->reg_bufs != NULL &&
	    (cb.flags & IORING_REGISTER_DST_REPLACE) == 0)
		error = EBUSY;
	else if (source == NULL)
		error = ENXIO;
	if (error != 0)
		goto out_dst;
	clone_nr = cb.nr == 0 ? source->count : cb.nr;
	if (clone_nr > source->count || cb.src_off > source->count ||
	    clone_nr > source->count - cb.src_off) {
		error = EINVAL;
		goto out_dst;
	}
	if (clone_nr > UINT32_MAX - cb.dst_off) {
		error = EOVERFLOW;
		goto out_dst;
	}
	dst_count = clone_nr + cb.dst_off;
	if (dst_count > SQ_MAX_REG_BUFS) {
		error = EINVAL;
		goto out_dst;
	}
	old = dst->reg_bufs;
	if (old != NULL && old->count > dst_count)
		dst_count = old->count;
	new = malloc(sizeof(*new) + dst_count * sizeof(*new->nodes),
	    M_SQUEUE, M_WAITOK | M_ZERO);
	refcount_init(&new->refs, 1);
	new->count = dst_count;
	if (old != NULL)
		for (i = 0; i < cb.dst_off && i < old->count; i++) {
			new->nodes[i] = old->nodes[i];
			if (new->nodes[i] != NULL)
				refcount_acquire(&new->nodes[i]->refs);
		}
	for (i = 0; i < clone_nr; i++)
		new->nodes[cb.dst_off + i] = sq_buf_node_clone(dst,
		    source->nodes[cb.src_off + i]);
	mtx_lock(&dst->mtx);
	dst->reg_bufs = new;
	dst->reg_nbufs = dst_count;
	mtx_unlock(&dst->mtx);
	sq_buf_table_rele(old);
	error = 0;
out_dst:
	sx_xunlock(&dst->register_sx);
	sq_buf_table_rele(source);
out_file:
	fdrop(srcfp, td);
	return (error);
}

static int
sq_register_clock(struct squeue_ctx *ctx, void *arg, uint32_t nr)
{
	struct io_uring_clock_register reg;
	clockid_t clockid;
	int error;

	if (arg == NULL || nr != 0)
		return (EINVAL);
	error = copyin(arg, &reg, sizeof(reg));
	if (error != 0)
		return (error);
	if (memcchr(reg.__resv, 0, sizeof(reg.__resv)) != NULL)
		return (EINVAL);
	if (ctx->clockid_xlate != NULL)
		error = ctx->clockid_xlate(reg.clockid, &clockid);
	else if (reg.clockid == CLOCK_UPTIME ||
	    reg.clockid == CLOCK_MONOTONIC) {
		clockid = reg.clockid;
		error = 0;
	} else
		error = EINVAL;
	if (error != 0)
		return (EINVAL);
	atomic_store_int(&ctx->wait_clockid, clockid);
	return (0);
}

/* Registration and mapping share the same region lifetime in both ABIs. */
static int
sq_register_mem_region(struct squeue_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{
	struct io_uring_mem_region_reg reg;
	struct io_uring_region_desc rd;
	struct sq_buf_backing *user;
	vm_object_t obj;
	char *kva;
	vm_size_t size;
	int error;

	if (arg == NULL || nr != 1)
		return (EINVAL);
	if (ctx->param_obj != NULL || ctx->param_user != NULL)
		return (EBUSY);
	error = copyin(arg, &reg, sizeof(reg));
	if (error != 0)
		return (error);
	error = copyin((void *)(uintptr_t)reg.region_uptr, &rd, sizeof(rd));
	if (error != 0)
		return (error);
	if (memcchr(reg.__resv, 0, sizeof(reg.__resv)) != NULL ||
	    (reg.flags & ~((uint64_t)IORING_MEM_REGION_REG_WAIT_ARG)) != 0)
		return (EINVAL);
	if ((reg.flags & IORING_MEM_REGION_REG_WAIT_ARG) != 0 &&
	    !ctx->disabled)
		return (EINVAL);
	if (memcchr(rd.__resv, 0, sizeof(rd.__resv)) != NULL ||
	    (rd.flags & ~IORING_MEM_REGION_TYPE_USER) != 0)
		return (EINVAL);
	if (((rd.flags & IORING_MEM_REGION_TYPE_USER) != 0) !=
	    (rd.user_addr != 0))
		return (EFAULT);
	if (rd.size == 0 || rd.mmap_offset != 0 || rd.id != 0)
		return (EINVAL);
	if (rd.size >> PAGE_SHIFT > INT_MAX)
		return (E2BIG);
	if (((rd.user_addr | rd.size) & PAGE_MASK) != 0)
		return (EINVAL);
	if (rd.user_addr > UINT64_MAX - rd.size)
		return (EOVERFLOW);

	size = (vm_size_t)rd.size;
	obj = NULL;
	user = NULL;
	kva = NULL;
	if ((rd.flags & IORING_MEM_REGION_TYPE_USER) != 0) {
		user = sq_param_region_pin((uintptr_t)rd.user_addr, size,
		    td, &error);
		if (error != 0)
			return (error);
		kva = user->buf.kva;
	} else {
		error = sq_param_region_alloc(size, td, &obj, &kva);
		if (error != 0)
			return (error);
		rd.mmap_offset = IORING_MAP_OFF_PARAM_REGION;
	}
	sx_xlock(&ctx->mmap_sx);
	ctx->param_obj = obj;
	ctx->param_user = user;
	ctx->param_kva = kva;
	ctx->param_size = size;
	ctx->param_wait_arg =
	    (reg.flags & IORING_MEM_REGION_REG_WAIT_ARG) != 0;
	sx_xunlock(&ctx->mmap_sx);
	error = copyout(&rd, (void *)(uintptr_t)reg.region_uptr, sizeof(rd));
	if (error == 0)
		return (0);
	/* A failed output copy must allow a clean retry of registration. */
	sx_xlock(&ctx->mmap_sx);
	ctx->param_obj = NULL;
	ctx->param_user = NULL;
	ctx->param_kva = NULL;
	ctx->param_size = 0;
	ctx->param_wait_arg = false;
	sx_xunlock(&ctx->mmap_sx);
	sq_ring_backing_free(obj, obj != NULL ? kva : NULL, size);
	sq_buf_backing_rele(user);
	return (error);
}

static int
sq_resize_rings(struct squeue_ctx *ctx, void *arg, uint32_t nr,
    struct thread *td)
{
	struct squeue_ctx next = {0};
	struct io_uring_params p;
	vm_object_t oldobj;
	struct sq_buf_backing *oldring, *oldsqes;
	char *oldkva;
	vm_size_t oldsize;
	uint32_t sqe, cqe, sq_head, sq_tail, cq_head, cq_tail;
	uint32_t i, src, dst;
	int error;

	if ((ctx->setup_flags & IORING_SETUP_DEFER_TASKRUN) == 0 ||
	    arg == NULL || nr != 1)
		return (EINVAL);
	error = copyin(arg, &p, sizeof(p));
	if (error != 0)
		return (error);
	if ((p.flags & ~(IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP)) != 0 ||
	    p.sq_entries == 0)
		return (EINVAL);
	if (p.sq_entries > SQ_MAX_ENTRIES) {
		if ((p.flags & IORING_SETUP_CLAMP) == 0)
			return (EINVAL);
		p.sq_entries = SQ_MAX_ENTRIES;
	}
	sqe = 1U << flsl(p.sq_entries - 1);
	if (sqe < p.sq_entries)
		sqe <<= 1;
	if ((p.flags & IORING_SETUP_CQSIZE) != 0) {
		if (p.cq_entries == 0)
			return (EINVAL);
		if (p.cq_entries > SQ_MAX_CQ_ENTRIES) {
			if ((p.flags & IORING_SETUP_CLAMP) == 0)
				return (EINVAL);
			p.cq_entries = SQ_MAX_CQ_ENTRIES;
		}
		cqe = 1U << flsl(p.cq_entries - 1);
		if (cqe < p.cq_entries)
			cqe <<= 1;
		if (cqe < sqe)
			return (EINVAL);
	} else
		cqe = sqe * 2;
	if ((ctx->setup_flags & IORING_SETUP_SQE_MIXED) != 0 && sqe < 2)
		return (EOVERFLOW);
	if ((ctx->setup_flags & IORING_SETUP_CQE_MIXED) != 0 && cqe < 2)
		return (EOVERFLOW);

	next.setup_flags = ctx->setup_flags;
	next.sq_entries = sqe;
	next.cq_entries = cqe;
	next.sqe_stride = ctx->sqe_stride;
	next.cqe_stride = ctx->cqe_stride;
	error = (ctx->setup_flags & IORING_SETUP_NO_MMAP) != 0 ?
	    sq_ring_alloc_user(&next, &p, td) : sq_ring_alloc(&next);
	if (error != 0)
		return (error);
	p.sq_entries = sqe;
	p.cq_entries = cqe;
	p.flags |= ctx->setup_flags & (IORING_SETUP_NO_SQARRAY |
	    IORING_SETUP_SQE128 | IORING_SETUP_CQE32 |
	    IORING_SETUP_CQE_MIXED | IORING_SETUP_SQE_MIXED |
	    IORING_SETUP_SQ_REWIND |
	    IORING_SETUP_NO_MMAP);
	p.sq_off.head = offsetof(struct sq_rings, sq_head);
	p.sq_off.tail = offsetof(struct sq_rings, sq_tail);
	p.sq_off.ring_mask = offsetof(struct sq_rings, sq_ring_mask);
	p.sq_off.ring_entries = offsetof(struct sq_rings, sq_ring_entries);
	p.sq_off.flags = offsetof(struct sq_rings, sq_flags);
	p.sq_off.dropped = offsetof(struct sq_rings, sq_dropped);
	/* Linux resize preserves the caller's sq_off.array field. */
	if (!ctx->is_linux)
		p.sq_off.array = next.sq_array != NULL ?
		    (uint32_t)((char *)next.sq_array - next.kva) : 0;
	p.cq_off.head = offsetof(struct sq_rings, cq_head);
	p.cq_off.tail = offsetof(struct sq_rings, cq_tail);
	p.cq_off.ring_mask = offsetof(struct sq_rings, cq_ring_mask);
	p.cq_off.ring_entries = offsetof(struct sq_rings, cq_ring_entries);
	p.cq_off.overflow = offsetof(struct sq_rings, cq_overflow);
	p.cq_off.cqes = (uint32_t)((char *)next.cqes - next.kva);
	p.cq_off.flags = offsetof(struct sq_rings, cq_flags);
	if ((error = copyout(&p, arg, sizeof(p))) != 0)
		goto fail;

	sx_xlock(&ctx->mmap_sx);
	mtx_lock(&ctx->mtx);
	sq_head = atomic_load_acq_32(&ctx->rings->sq_head);
	sq_tail = atomic_load_acq_32(&ctx->rings->sq_tail);
	cq_head = atomic_load_acq_32(&ctx->rings->cq_head);
	cq_tail = atomic_load_acq_32(&ctx->rings->cq_tail);
	if (sq_tail - sq_head > ctx->sq_entries ||
	    sq_tail - sq_head > sqe || cq_tail - cq_head > ctx->cq_entries ||
	    cq_tail - cq_head > cqe) {
		error = EOVERFLOW;
		goto out_locked;
	}
	*next.rings = *ctx->rings;
	next.rings->sq_head = sq_head;
	next.rings->sq_tail = sq_tail;
	next.rings->cq_head = cq_head;
	next.rings->cq_tail = cq_tail;
	next.rings->sq_ring_mask = sqe - 1;
	next.rings->cq_ring_mask = cqe - 1;
	next.rings->sq_ring_entries = sqe;
	next.rings->cq_ring_entries = cqe;
	for (i = sq_head; i != sq_tail; i++) {
		src = ctx->sq_array == NULL ? i & ctx->sq_mask :
		    ctx->sq_array[i & ctx->sq_mask];
		dst = i & next.sq_mask;
		if (next.sq_array != NULL)
			next.sq_array[dst] = src >= ctx->sq_entries ?
			    UINT32_MAX : dst;
		if (src < ctx->sq_entries)
			bcopy((char *)ctx->sqes +
			    (vm_size_t)src * ctx->sqe_stride,
			    (char *)next.sqes +
			    (vm_size_t)dst * next.sqe_stride, ctx->sqe_stride);
	}
	for (i = cq_head; i != cq_tail; i++)
		bcopy((char *)ctx->cqes +
		    (vm_size_t)(i & ctx->cq_mask) * ctx->cqe_stride,
		    (char *)next.cqes +
		    (vm_size_t)(i & next.cq_mask) * next.cqe_stride,
		    ctx->cqe_stride);
	oldobj = ctx->obj;
	oldring = ctx->ring_user;
	oldsqes = ctx->sqes_user;
	oldkva = ctx->kva;
	oldsize = ctx->objsize;
	ctx->obj = next.obj;
	ctx->ring_user = next.ring_user;
	ctx->sqes_user = next.sqes_user;
	ctx->kva = next.kva;
	ctx->objsize = next.objsize;
	ctx->ring_region = next.ring_region;
	ctx->sqes_off = next.sqes_off;
	ctx->sqes_size = next.sqes_size;
	ctx->rings = next.rings;
	ctx->cqes = next.cqes;
	ctx->sq_array = next.sq_array;
	ctx->sqes = next.sqes;
	ctx->sq_entries = sqe;
	ctx->cq_entries = cqe;
	ctx->sq_mask = sqe - 1;
	ctx->cq_mask = cqe - 1;
	mtx_unlock(&ctx->mtx);
	sq_ring_backing_free(oldobj, oldkva, oldsize);
	sq_buf_backing_rele(oldsqes);
	sq_buf_backing_rele(oldring);
	sx_xunlock(&ctx->mmap_sx);
	return (0);
out_locked:
	mtx_unlock(&ctx->mtx);
	sx_xunlock(&ctx->mmap_sx);
fail:
	sq_ring_backing_free(next.obj, next.kva, next.objsize);
	sq_buf_backing_rele(next.sqes_user);
	sq_buf_backing_rele(next.ring_user);
	return (error);
}

int
kern_squeue_register(struct thread *td, int fd, uint32_t op, void *arg,
    uint32_t nr_args)
{
	struct squeue_ctx *ctx;
	struct file *fp;
	bool registered_ring;
	int error;

	registered_ring = (op & IORING_REGISTER_USE_REGISTERED_RING) != 0;
	op &= ~IORING_REGISTER_USE_REGISTERED_RING;
	if (op >= IORING_REGISTER_LAST)
		return (EINVAL);
	/* Linux blind registrations use fd -1 and do not resolve a source ring. */
	if (fd == -1)
		return (op == IORING_REGISTER_SEND_MSG_RING ?
		    sq_register_send_msg_ring(arg, nr_args, td) : EINVAL);
	error = sq_ring_file_get(td, fd, registered_ring, &fp);
	if (error != 0)
		return (error);
	ctx = fp->f_data;
	sx_xlock(&sq_register_global_sx);
	if (op == IORING_REGISTER_CLONE_BUFFERS) {
		error = sq_clone_buffers(ctx, arg, nr_args, td);
		sx_xunlock(&sq_register_global_sx);
		fdrop(fp, td);
		return (error);
	}
	sx_xlock(&ctx->register_sx);
	if (ctx->submitter != NULL && ctx->submitter != osd_thread_get(td, sq_issuer_slot)) {
		error = EEXIST;
		goto out;
	}
	if (ctx->restricted && !ctx->allowed_register[op]) {
		error = EACCES;
		goto out;
	}
	switch (op) {
	case IORING_REGISTER_PERSONALITY:
		error = sq_register_personality(ctx, arg, nr_args, td);
		break;
	case IORING_UNREGISTER_PERSONALITY:
		error = sq_unregister_personality(ctx, arg, nr_args);
		break;
	case IORING_REGISTER_IOWQ_AFF:
		error = sq_register_iowq_affinity(ctx, arg, nr_args, td);
		break;
	case IORING_UNREGISTER_IOWQ_AFF:
		error = sq_unregister_iowq_affinity(ctx, arg, nr_args);
		break;
	case IORING_REGISTER_IOWQ_MAX_WORKERS:
		error = sq_register_iowq_max_workers(ctx, arg, nr_args);
		break;
	case IORING_REGISTER_RESTRICTIONS:
		error = sq_register_restrictions(ctx, arg, nr_args);
		break;
	case IORING_REGISTER_ENABLE_RINGS:
		error = arg != NULL || nr_args != 0 ? EINVAL : sq_enable(ctx, td);
		break;
	case IORING_REGISTER_PROBE:
		error = sq_register_probe(ctx, arg, nr_args);
		break;
	case IORING_REGISTER_BUFFERS:
		error = arg == NULL ? EFAULT :
		    sq_register_buffers(ctx, arg, nr_args, td);
		break;
	case IORING_UNREGISTER_BUFFERS:
		error = arg != NULL || nr_args != 0 ? EINVAL :
		    sq_unregister_buffers(ctx);
		break;
	case IORING_REGISTER_BUFFERS2:
		error = sq_register_buffers2(ctx, arg, nr_args, td);
		break;
	case IORING_REGISTER_BUFFERS_UPDATE:
		error = sq_buffers_update2(ctx, arg, nr_args, td);
		break;
	case IORING_REGISTER_FILES:
		error = arg == NULL ? EFAULT : sq_register_files(ctx, arg, nr_args, td);
		break;
	case IORING_UNREGISTER_FILES:
		error = arg != NULL || nr_args != 0 ? EINVAL :
		    sq_unregister_files(ctx, td);
		break;
	case IORING_REGISTER_FILES_UPDATE:
		error = sq_files_update(ctx, arg, nr_args, td);
		break;
	case IORING_REGISTER_FILES2:
		error = sq_register_files2(ctx, arg, nr_args, td);
		break;
	case IORING_REGISTER_FILES_UPDATE2:
		error = sq_files_update2(ctx, arg, nr_args, td);
		break;
	case IORING_REGISTER_EVENTFD:
		error = sq_register_eventfd(ctx, arg, nr_args, false, td);
		break;
	case IORING_REGISTER_EVENTFD_ASYNC:
		error = sq_register_eventfd(ctx, arg, nr_args, true, td);
		break;
	case IORING_UNREGISTER_EVENTFD:
		error = arg != NULL || nr_args != 0 ? EINVAL :
		    sq_unregister_eventfd(ctx, td);
		break;
	case IORING_REGISTER_RING_FDS:
		error = sq_ringfds_register(arg, nr_args, td);
		break;
	case IORING_UNREGISTER_RING_FDS:
		error = sq_ringfds_unregister(arg, nr_args, td);
		break;
	case IORING_REGISTER_PBUF_RING:
		error = sq_register_pbuf_ring(ctx, arg, nr_args, td);
		break;
	case IORING_UNREGISTER_PBUF_RING:
		error = sq_unregister_pbuf_ring(ctx, arg, nr_args);
		break;
	case IORING_REGISTER_PBUF_STATUS:
		error = sq_pbuf_status(ctx, arg, nr_args);
		break;
	case IORING_REGISTER_SYNC_CANCEL:
		error = sq_register_sync_cancel(ctx, arg, nr_args, td);
		break;
	case IORING_REGISTER_FILE_ALLOC_RANGE:
		error = sq_register_file_alloc_range(ctx, arg, nr_args);
		break;
	case IORING_REGISTER_CLOCK:
		error = sq_register_clock(ctx, arg, nr_args);
		break;
	case IORING_REGISTER_RESIZE_RINGS:
		error = sq_resize_rings(ctx, arg, nr_args, td);
		break;
	case IORING_REGISTER_MEM_REGION:
		error = sq_register_mem_region(ctx, arg, nr_args, td);
		break;
	case IORING_REGISTER_QUERY:
		error = ctx->register_query != NULL ?
		    ctx->register_query(td, arg, nr_args) : EINVAL;
		break;
	case IORING_REGISTER_BPF_FILTER:
		error = sq_register_bpf_filter(ctx, arg, nr_args);
		break;
	default:
		error = ctx->register_ext != NULL ?
		    ctx->register_ext(ctx, td, op, arg, nr_args) : EINVAL;
		break;
	}
out:
	sx_xunlock(&ctx->register_sx);
	sx_xunlock(&sq_register_global_sx);
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
		kern_squeue_setup_abort(td, fd, p.flags);
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

	int error;

	error = kern_squeue_register(td, uap->fd, uap->op, uap->arg,
	    uap->nr_args);
	return (error == SQ_BAD_RING_STATE ? EBADF : error);
}
