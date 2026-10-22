/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Kernel services and amd64 machine primitives that dtrace.c, hypertrace.c
 * and hypertrace_map.c call, for the userland harness.  Machine primitives
 * follow sys/cddl/dev/dtrace/amd64/{dtrace_asm.S,dtrace_isa.c,dtrace_subr.c}
 * contracts (fault flags, return values); kernel services follow their
 * documented contracts with deterministic, test-controllable behaviour.
 * Not production code.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/conf.h>
#include <sys/eventhandler.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/sx.h>
#include <sys/taskqueue.h>
#include <sys/ucred.h>
#include <sys/dtrace_bsd.h>
#include <sys/cpuvar.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <sys/hypertrace.h>
#include <sys/taskq.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <machine/stdarg.h>
#include <machine/vmm.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <machine/vmparam.h>
#include <machine/pmap.h>
#include <machine/bhyve_hypercall.h>

#include "khx_kern.h"
#include "khx_dtrace.h"

MALLOC_DEFINE(M_SOLARIS, "solaris", "harness OpenSolaris compat");
uint64_t khx_probe_args[16];

#include "dtrace_cddl.h"
/* khx_kern.c allocates these per thread/process with this bound. */
_Static_assert(sizeof(struct kdtrace_thread) <= 4096, "kdtrace_thread size");
_Static_assert(sizeof(struct kdtrace_proc) <= 4096, "kdtrace_proc size");

/* Kernel globals provided by kern_dtrace.c, kern_proc.c, ... */
struct proc proc0;
const char *panicstr;
long physmem = 1L << 20;
dtrace_trap_func_t dtrace_trap_func;
dtrace_fault_func_t dtrace_fault_func;
int dtrace_vtime_active;
dtrace_vtime_switch_func_t dtrace_vtime_switch_func;
char const hex2ascii_data[] = "0123456789abcdefghijklmnopqrstuvwxyz";
struct lock_class *lock_classes[LOCK_CLASS_MAX + 1];
static int khx_vnet_marker __section("set_vnet") __used;

/* ---- OpenSolaris compat: kmem, taskq, cmn_err --------------------------- */
void *
zfs_kmem_alloc(size_t size, int kmflags)
{
	return (malloc(size, M_SOLARIS, kmflags));
}

/* kmem_free(9F) must be given the allocation's size.  FreeBSD's SPL
 * ignores it, so a mismatch is harmless there but breaks the Solaris
 * contract; the harness counts and reports each one.  Size 0 is the
 * FreeBSD port's own "size unknown" idiom (kmem_free(state, 0)). */
static long khx_kmem_size_mismatches;

long
khx_kmem_mismatches(void)
{
	return (khx_kmem_size_mismatches);
}

void
zfs_kmem_free(void *buf, size_t size)
{
	if (buf != NULL && size != 0 && khx_host_alloc_size(buf) != size) {
		khx_kmem_size_mismatches++;
		khx_host_log("kmem_free size %zu != allocation %zu from %p\n",
		    size, (size_t)khx_host_alloc_size(buf),
		    __builtin_return_address(0));
	}
	free(buf, M_SOLARIS);
}

/* The SPL kmem_cache_t carries a UMA zone pointer; the harness keeps its
 * own size/live accounting behind that opaque pointer. */
struct khx_kc {
	size_t size;
	long live;
};
#define KC(c) ((struct khx_kc *)(void *)(c)->kc_zone)

kmem_cache_t *
kmem_cache_create(const char *name, size_t bufsize, size_t align __unused,
    int (*ctor)(void *, void *, int), void (*dtor)(void *, void *),
    void (*reclaim)(void *) __unused, void *priv __unused, vmem_t *vmp __unused,
    int cflags __unused)
{
	kmem_cache_t *c;

	if (ctor != NULL || dtor != NULL)
		panic("kmem_cache ctor/dtor not modelled");
	c = malloc(sizeof(*c), M_SOLARIS, M_WAITOK | M_ZERO);
	strlcpy(c->kc_name, name, sizeof(c->kc_name));
	c->kc_zone = (void *)malloc(sizeof(struct khx_kc), M_SOLARIS,
	    M_WAITOK | M_ZERO);
	KC(c)->size = bufsize;
	return (c);
}

void
kmem_cache_destroy(kmem_cache_t *c)
{
	if (KC(c)->live != 0)
		panic("kmem_cache_destroy(%s) with %ld live objects", c->kc_name,
		    KC(c)->live);
	free(KC(c), M_SOLARIS);
	free(c, M_SOLARIS);
}

void *
kmem_cache_alloc(kmem_cache_t *c, int flags)
{
	void *p = malloc(KC(c)->size, M_SOLARIS, flags);

	if (p != NULL)
		KC(c)->live++;
	return (p);
}

void
kmem_cache_free(kmem_cache_t *c, void *buf)
{
	KC(c)->live--;
	free(buf, M_SOLARIS);
}

struct khx_taskq_ent {
	struct task task;
	task_func_t *func;
	void *arg;
};

static void
khx_taskq_run(void *arg, int pending __unused)
{
	struct khx_taskq_ent *e = arg;

	e->func(e->arg);
	free(e, M_SOLARIS);
}

static taskq_t *khx_taskqs[8];

/* Run every pending task of every taskq (the taskq threads' work). */
void
khx_taskqs_run(void)
{
	for (int i = 0; i < 8; i++)
		if (khx_taskqs[i] != NULL)
			khx_taskqueue_run(khx_taskqs[i]->tq_queue);
}

taskq_t *
taskq_create(const char *name, int nthreads, pri_t pri, int minalloc __unused,
    int maxalloc __unused, uint_t flags __unused)
{
	taskq_t *tq;

	tq = malloc(sizeof(*tq), M_SOLARIS, M_WAITOK | M_ZERO);
	tq->tq_queue = taskqueue_create(name, M_WAITOK,
	    taskqueue_thread_enqueue, &tq->tq_queue);
	(void)taskqueue_start_threads(&tq->tq_queue, nthreads, pri, "%s", name);
	for (int i = 0; i < 8; i++) {
		if (khx_taskqs[i] == NULL) {
			khx_taskqs[i] = tq;
			break;
		}
	}
	return (tq);
}

void
taskq_destroy(taskq_t *tq)
{
	for (int i = 0; i < 8; i++)
		if (khx_taskqs[i] == tq)
			khx_taskqs[i] = NULL;
	khx_taskqueue_run(tq->tq_queue);
	taskqueue_free(tq->tq_queue);
	free(tq, M_SOLARIS);
}

taskqid_t
taskq_dispatch(taskq_t *tq, task_func_t func, void *arg, uint_t flags)
{
	struct khx_taskq_ent *e;

	e = malloc(sizeof(*e), M_SOLARIS,
	    (flags & (TQ_SLEEP | TQ_NOQUEUE)) == TQ_SLEEP ? M_WAITOK : M_NOWAIT);
	if (e == NULL)
		return (0);
	e->func = func;
	e->arg = arg;
	TASK_INIT(&e->task, 0, khx_taskq_run, e);
	taskqueue_enqueue(tq->tq_queue, &e->task);
	return ((taskqid_t)(void *)e);
}

void
cmn_err(int ce, const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (ce == CE_PANIC)
		panic("%s", buf);
	printf("cmn_err(%d): %s\n", ce, buf);
}

void
vpanic(const char *fmt, va_list ap)
{
	char buf[512];

	vsnprintf(buf, sizeof(buf), fmt, ap);
	panic("%s", buf);
}

void
spl_panic(const char *file, const char *func, int line, const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	panic("%s:%s:%d: %s", file, func, line, buf);
}

/* ---- callout(9) ----------------------------------------------------------
 * Only pending callouts are tracked; tests fire them explicitly. */
#define KHX_MAX_CALLOUTS 256
static struct callout *khx_callouts[KHX_MAX_CALLOUTS];

static void
khx_callout_untrack(struct callout *c)
{
	for (int i = 0; i < KHX_MAX_CALLOUTS; i++)
		if (khx_callouts[i] == c)
			khx_callouts[i] = NULL;
}

static void
khx_callout_track(struct callout *c)
{
	int i, free_slot = -1;

	for (i = 0; i < KHX_MAX_CALLOUTS; i++) {
		if (khx_callouts[i] == c)
			return;
		if (khx_callouts[i] == NULL && free_slot < 0)
			free_slot = i;
	}
	if (free_slot < 0)
		panic("too many pending callouts");
	khx_callouts[free_slot] = c;
}

void
callout_init(struct callout *c, int mpsafe __unused)
{
	khx_callout_untrack(c);
	memset(c, 0, sizeof(*c));
}

int
callout_reset_sbt_on(struct callout *c, sbintime_t sbt, sbintime_t prec
    __unused, void (*func)(void *), void *arg, int cpu __unused,
    int flags __unused)
{
	int was = (c->c_iflags & CALLOUT_PENDING) != 0;

	khx_callout_track(c);
	c->c_func = func;
	c->c_arg = arg;
	c->c_time = sbt;
	c->c_iflags |= CALLOUT_PENDING;
	return (was);
}

int
_callout_stop_safe(struct callout *c, int flags __unused)
{
	int was = (c->c_iflags & CALLOUT_PENDING) != 0;

	c->c_iflags &= ~CALLOUT_PENDING;
	khx_callout_untrack(c);
	return (was);
}

int
khx_callout_fire(void (*func)(void *))
{
	int i, n = 0;
	struct callout *c;

	for (i = 0; i < KHX_MAX_CALLOUTS; i++) {
		c = khx_callouts[i];
		if (c == NULL || (c->c_iflags & CALLOUT_PENDING) == 0)
			continue;
		if (func != NULL && c->c_func != func)
			continue;
		c->c_iflags &= ~CALLOUT_PENDING;
		khx_callouts[i] = NULL;
		c->c_func(c->c_arg);
		n++;
	}
	return (n);
}

int
khx_callout_pending(void (*func)(void *))
{
	int i, n = 0;

	for (i = 0; i < KHX_MAX_CALLOUTS; i++)
		if (khx_callouts[i] != NULL &&
		    (khx_callouts[i]->c_iflags & CALLOUT_PENDING) &&
		    (func == NULL || khx_callouts[i]->c_func == func))
			n++;
	return (n);
}

/* ---- unr(9) -------------------------------------------------------------- */
struct unrhdr {
	int low, high;
	uint8_t *map;
	int fail;
};
static int khx_unr_fail;

void
khx_fail_alloc_unr(int on)
{
	khx_unr_fail = on;
}

struct unrhdr *
new_unrhdr(int low, int high, struct mtx *mutex __unused)
{
	struct unrhdr *uh = malloc(sizeof(*uh), M_SOLARIS, M_WAITOK | M_ZERO);

	uh->low = low;
	uh->high = MIN(high, low + (1 << 20));	/* bounded for the harness */
	uh->map = malloc(uh->high - low + 1, M_SOLARIS, M_WAITOK | M_ZERO);
	return (uh);
}

void
delete_unrhdr(struct unrhdr *uh)
{
	free(uh->map, M_SOLARIS);
	free(uh, M_SOLARIS);
}

int
alloc_unr(struct unrhdr *uh)
{
	if (khx_unr_fail)
		return (-1);
	for (int i = 0; i <= uh->high - uh->low; i++) {
		if (!uh->map[i]) {
			uh->map[i] = 1;
			return (uh->low + i);
		}
	}
	return (-1);
}

void
free_unr(struct unrhdr *uh, u_int item)
{
	if ((int)item < uh->low || (int)item > uh->high ||
	    !uh->map[item - uh->low])
		panic("free_unr(%u): not allocated", item);
	uh->map[item - uh->low] = 0;
}

/* ---- eventhandler(9) -------------------------------------------------- */
#define KHX_MAX_EH 16
static struct {
	char name[32];
	void *func, *arg;
	int live;
} khx_eh[KHX_MAX_EH];
static struct eventhandler_list khx_eh_list;

eventhandler_tag
eventhandler_register(struct eventhandler_list *list __unused,
    const char *name, void *func, void *arg, int priority __unused)
{
	for (int i = 0; i < KHX_MAX_EH; i++) {
		if (!khx_eh[i].live) {
			strlcpy(khx_eh[i].name, name, sizeof(khx_eh[i].name));
			khx_eh[i].func = func;
			khx_eh[i].arg = arg;
			khx_eh[i].live = 1;
			return ((eventhandler_tag)&khx_eh[i]);
		}
	}
	panic("too many event handlers");
}

void
eventhandler_deregister(struct eventhandler_list *list __unused,
    eventhandler_tag tag)
{
	for (int i = 0; i < KHX_MAX_EH; i++)
		if ((eventhandler_tag)&khx_eh[i] == tag)
			khx_eh[i].live = 0;
}

/* Invoke every live handler registered under `name' (test driver). */
int
khx_eh_invoke(const char *name, void (*call)(void *func, void *arg,
    void *ctx), void *ctx)
{
	int n = 0;

	for (int i = 0; i < KHX_MAX_EH; i++) {
		if (khx_eh[i].live && strcmp(khx_eh[i].name, name) == 0) {
			call(khx_eh[i].func, khx_eh[i].arg, ctx);
			n++;
		}
	}
	return (n);
}

struct eventhandler_list *
eventhandler_find_list(const char *name __unused)
{
	return (&khx_eh_list);
}

void *
khx_eventhandler_find(const char *name, void **arg)
{
	for (int i = 0; i < KHX_MAX_EH; i++)
		if (khx_eh[i].live && strcmp(khx_eh[i].name, name) == 0) {
			if (arg != NULL)
				*arg = khx_eh[i].arg;
			return (khx_eh[i].func);
		}
	return (NULL);
}

/* ---- devfs cdevpriv: one private datum per open file ------------------- */
struct khx_file {
	void *priv;
	d_priv_dtor_t *dtr;
	int has;
};
static __thread struct khx_file *khx_curfile;

struct khx_file *
khx_file_new(void)
{
	return (khx_host_alloc(sizeof(struct khx_file), 1, 0, "khx-file"));
}

void
khx_file_set_current(struct khx_file *fp)
{
	khx_curfile = fp;
}

void
khx_file_close(struct khx_file *fp)
{
	if (fp->has && fp->dtr != NULL)
		fp->dtr(fp->priv);
	khx_host_free(fp, "khx-file");
}

int
devfs_get_cdevpriv(void **datap)
{
	if (khx_curfile == NULL || !khx_curfile->has)
		return (EBADF);
	*datap = khx_curfile->priv;
	return (0);
}

int
devfs_set_cdevpriv(void *priv, d_priv_dtor_t *dtr)
{
	if (khx_curfile == NULL)
		panic("devfs_set_cdevpriv without a current file");
	if (khx_curfile->has)
		return (EBUSY);
	khx_curfile->priv = priv;
	khx_curfile->dtr = dtr;
	khx_curfile->has = 1;
	return (0);
}

/* ---- processes, credentials, privilege --------------------------------- */
static int khx_priv_deny;
static long khx_psignals, khx_kdb_entries;

void
khx_priv_deny_all(int on)
{
	khx_priv_deny = on;
}

int
priv_check(struct thread *td __unused, int priv __unused)
{
	return (khx_priv_deny ? EPERM : 0);
}

struct ucred *
crhold(struct ucred *cr)
{
	cr->cr_ref++;
	return (cr);
}

void
crfree(struct ucred *cr)
{
	if (cr->cr_ref == 0)
		panic("crfree: zero reference");
	cr->cr_ref--;
}

struct proc *
pfind(pid_t pid __unused)
{
	return (NULL);
}

ssize_t
proc_readmem(struct thread *td __unused, struct proc *p __unused,
    vm_offset_t va __unused, void *buf __unused, size_t len __unused)
{
	return (-1);
}

static int khx_last_signal;
static pid_t khx_last_signal_pid;

void
kern_psignal(struct proc *p, int sig)
{
	/* kern_psignal(9) requires the process lock. */
	if (!mtx_owned(&p->p_mtx))
		panic("kern_psignal without the process lock");
	khx_psignals++;
	khx_last_signal = sig;
	khx_last_signal_pid = p->p_pid;
}

int
khx_psignal_last(pid_t *pid)
{
	*pid = khx_last_signal_pid;
	return (khx_last_signal);
}

long
khx_psignal_count(void)
{
	return (khx_psignals);
}

void
kdb_enter(const char *why __unused, const char *msg __unused)
{
	khx_kdb_entries++;
}

long
khx_kdb_count(void)
{
	return (khx_kdb_entries);
}

/* One preloaded "dtrace_dof" file (the loader's anonymous enablings). */
static const char *khx_preload_buf;
static size_t khx_preload_len;

void
khx_preload_dof(const char *buf, unsigned long len)
{
	khx_preload_buf = buf;
	khx_preload_len = len;
}

caddr_t
preload_search_by_type(const char *type)
{
	if (khx_preload_buf == NULL || strcmp(type, "dtrace_dof") != 0)
		return (NULL);
	return ((caddr_t)(uintptr_t)&khx_preload_buf);
}

void *
preload_fetch_addr(caddr_t mod)
{
	return (mod == (caddr_t)(uintptr_t)&khx_preload_buf ?
	    __DECONST(char *, khx_preload_buf) : NULL);
}

size_t
preload_fetch_size(caddr_t mod)
{
	return (mod == (caddr_t)(uintptr_t)&khx_preload_buf ?
	    khx_preload_len : 0);
}

void
spinlock_enter(void)
{
	curthread->td_md.md_spinlock_count++;
}

void
spinlock_exit(void)
{
	if (curthread->td_md.md_spinlock_count == 0)
		panic("spinlock_exit without enter");
	curthread->td_md.md_spinlock_count--;
}

/* ---- packet provenance epochs (uipc_mbuf.c) ------------------------- */
static uint64_t khx_mbufid_epochs[HYPERTRACE_MAX_VMS];

void
mbufid_v2_vm_epoch_publish(uint16_t vmid, uint64_t epoch)
{
	khx_mbufid_epochs[vmid] = epoch;
}

void
mbufid_v2_vm_epoch_revoke(uint16_t vmid, uint64_t epoch)
{
	if (khx_mbufid_epochs[vmid] == epoch)
		khx_mbufid_epochs[vmid] = 0;
}

uint64_t
khx_mbufid_epoch(uint16_t vmid)
{
	return (khx_mbufid_epochs[vmid]);
}

/* ---- amd64 DTrace machine primitives ---------------------------------- */
uint32_t
dtrace_cas32(uint32_t *target, uint32_t cmp, uint32_t new)
{
	__atomic_compare_exchange_n(target, &cmp, new, 0, __ATOMIC_SEQ_CST,
	    __ATOMIC_SEQ_CST);
	return (cmp);
}

void *
dtrace_casptr(volatile void *target, volatile void *cmp, volatile void *new)
{
	void *expect = (void *)(uintptr_t)cmp;

	__atomic_compare_exchange_n((void *volatile *)target, &expect,
	    (void *)(uintptr_t)new, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
	return (expect);
}

void
dtrace_membar_producer(void)
{
	__atomic_thread_fence(__ATOMIC_RELEASE);
}

void
dtrace_membar_consumer(void)
{
	__atomic_thread_fence(__ATOMIC_ACQUIRE);
}

/* The cookie is the previous "interrupts enabled" state of this thread. */
dtrace_icookie_t
dtrace_interrupt_disable(void)
{
	dtrace_icookie_t prev = curthread->td_md.md_saved_flags;

	curthread->td_md.md_saved_flags = 1;
	return (prev);
}

void
dtrace_interrupt_enable(dtrace_icookie_t cookie)
{
	curthread->td_md.md_saved_flags = cookie;
}

int
khx_interrupts_disabled(void)
{
	return (curthread->td_md.md_saved_flags != 0);
}

/*
 * amd64 dtrace_asm.S primitives used by the real dtrace_isa.c.  A user
 * access that would fault traps into dtrace_trap(), which records
 * CPU_DTRACE_BADADDR and the faulting address; here faults come from the
 * harness's injected user fault ranges.
 */
uint32_t cpu_stdext_feature;
struct kva_layout_s kva_layout = {
	.km_low = PAGE_SIZE,
	.km_high = ~(vm_offset_t)0,
};

static int
khx_fault_at(uintptr_t addr, size_t len)
{
	/* The first page is never mapped, as in every FreeBSD process. */
	if (addr < PAGE_SIZE || khx_host_user_faults((void *)addr, len)) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		cpu_core[curcpu].cpuc_dtrace_illval = addr;
		return (1);
	}
	return (0);
}

void
dtrace_copy_nosmap(uintptr_t src, uintptr_t dst, size_t len)
{
	if (khx_fault_at(src, len) || khx_fault_at(dst, len))
		return;
	memmove((void *)dst, (void *)src, len);
}

void
dtrace_copy_smap(uintptr_t src, uintptr_t dst, size_t len)
{
	dtrace_copy_nosmap(src, dst, len);
}

void
dtrace_copystr_nosmap(uintptr_t src, uintptr_t dst, size_t len,
    volatile uint16_t *flags)
{
	for (size_t i = 0; i < len; i++) {
		if ((*flags & CPU_DTRACE_BADADDR) != 0)
			return;
		if (khx_fault_at(src + i, 1) || khx_fault_at(dst + i, 1))
			return;
		((char *)dst)[i] = ((const char *)src)[i];
		if (((const char *)src)[i] == '\0')
			return;
	}
}

void
dtrace_copystr_smap(uintptr_t src, uintptr_t dst, size_t len,
    volatile uint16_t *flags)
{
	dtrace_copystr_nosmap(src, dst, len, flags);
}

#define KHX_FUWORD_NOCHECK(bits)					\
uint##bits##_t								\
dtrace_fuword##bits##_nocheck_nosmap(void *uaddr)			\
{									\
	if (khx_fault_at((uintptr_t)uaddr, bits / 8))			\
		return (0);						\
	return (*(volatile uint##bits##_t *)uaddr);			\
}									\
uint##bits##_t								\
dtrace_fuword##bits##_nocheck_smap(void *uaddr)				\
{									\
	return (dtrace_fuword##bits##_nocheck_nosmap(uaddr));		\
}
KHX_FUWORD_NOCHECK(8)
KHX_FUWORD_NOCHECK(16)
KHX_FUWORD_NOCHECK(32)
KHX_FUWORD_NOCHECK(64)

ulong_t
dtrace_fulword_nosmap(void *uaddr)
{
	return (dtrace_fuword64_nocheck_nosmap(uaddr));
}

ulong_t
dtrace_fulword_smap(void *uaddr)
{
	return (dtrace_fulword_nosmap(uaddr));
}

greg_t
dtrace_getfp(void)
{
	return ((greg_t)__builtin_frame_address(1));
}

/* ddb and linker symbol tables used by dtrace_db.c for immstack(). */
#include <ddb/ddb.h>
#include <ddb/db_sym.h>
db_symtab_t db_symtabs[MAXNOSYMTABS];
int db_nsymtab;
db_symtab_t *db_last_symtab;
linker_file_list_t linker_files = TAILQ_HEAD_INITIALIZER(linker_files);
struct kobjop_desc linker_search_symbol_desc;
struct kobjop_desc linker_symbol_values_desc;

/* kobj dispatch for the linker methods dtrace_db.c calls: a test may bind
 * a method for any class; otherwise the method's default runs. */
static struct kobj_method khx_kobj_bound[4];

void
khx_kobj_bind(kobjop_desc_t desc, kobjop_t func)
{
	for (int i = 0; i < 4; i++) {
		if (khx_kobj_bound[i].desc == NULL ||
		    khx_kobj_bound[i].desc == desc) {
			khx_kobj_bound[i].desc = desc;
			khx_kobj_bound[i].func = func;
			return;
		}
	}
	panic("khx_kobj_bind: table full");
}

kobj_method_t *
kobj_lookup_method(kobj_class_t cls __unused, kobj_method_t **cep __unused,
    kobjop_desc_t desc)
{
	for (int i = 0; i < 4; i++)
		if (khx_kobj_bound[i].desc == desc)
			return ((kobj_method_t *)&khx_kobj_bound[i]);
	return (&desc->deflt);
}

/* Synthetic, deterministic kernel stacks. */
pc_t khx_kstack[64];
int khx_kstack_depth = 4;
uint64_t khx_ustack[64];
int khx_ustack_depth = 3;
ulong_t khx_regs[64];

/* amd64 dtrace_asm.S: the caller is never known from probe context. */
uintptr_t
dtrace_caller(int aframes __unused)
{
	return ((uintptr_t)-1);
}

static uint64_t khx_fake_time;

void
khx_set_hrtime(long long t)
{
	khx_fake_time = (uint64_t)t;
}

uint64_t
dtrace_gethrtime(void)
{
	return (khx_fake_time != 0 ? khx_fake_time++ :
	    (uint64_t)khx_host_monotonic_ns());
}

uint64_t
dtrace_gethrestime(void)
{
	return ((uint64_t)1700000000 * 1000000000ULL +
	    (uint64_t)khx_host_monotonic_ns());
}

void
dtrace_toxic_ranges(void (*func)(uintptr_t, uintptr_t))
{
	/* The null page and the region above the user address space. */
	func(0, PAGE_SIZE);
	func(VM_MAXUSER_ADDRESS, ~(uintptr_t)0);
}

int
dtrace_trap(struct trapframe *frame __unused, u_int type __unused)
{
	return (0);
}

void
dtrace_invop_init(void)
{
}

void
dtrace_invop_uninit(void)
{
}

/*
 * amd64 dtrace_asm.S dtrace_probe_error, instruction for instruction: the
 * sixth value (illval) goes on the stack where the real dtrace_getarg(5)
 * reads it.
 */
__asm__(
"	.text\n"
"	.globl	dtrace_probe_error\n"
"	.type	dtrace_probe_error,@function\n"
"dtrace_probe_error:\n"
"	pushq	%rbp\n"
"	movq	%rsp, %rbp\n"
"	subq	$0x8, %rsp\n"
"	movq	%r9, (%rsp)\n"
"	movq	%r8, %r9\n"
"	movq	%rcx, %r8\n"
"	movq	%rdx, %rcx\n"
"	movq	%rsi, %rdx\n"
"	movq	%rdi, %rsi\n"
"	movl	dtrace_probeid_error(%rip), %edi\n"
"	call	dtrace_probe\n"
"	addq	$0x8, %rsp\n"
"	leave\n"
"	ret\n"
"	.size	dtrace_probe_error, .-dtrace_probe_error\n");

/* ---- guest hypercall and address translation ---------------------------- */
static int khx_hypercall_ret;
static long khx_hypercalls;
static hypertrace_args_t khx_last_htr;
static int khx_last_hypercall_id;
static uintptr_t khx_last_pcstack[HYPERTRACE_STACK_MAX_FRAMES];
/* History of the most recent hypercalls (index by count modulo 8). */
static struct {
	hypertrace_args_t htr;
	uintptr_t pcstack[HYPERTRACE_STACK_MAX_FRAMES];
	int id;
} khx_hc_hist[8];

const hypertrace_args_t *
khx_hypercall_nth(long n, int *id, uintptr_t **pcstack)
{
	if (n < 0 || n >= khx_hypercalls || khx_hypercalls - n > 8)
		return (NULL);
	*id = khx_hc_hist[n % 8].id;
	*pcstack = khx_hc_hist[n % 8].pcstack;
	return (&khx_hc_hist[n % 8].htr);
}

void
khx_hypercall_result(int ret)
{
	khx_hypercall_ret = ret;
}

long
khx_hypercall_count(void)
{
	return (khx_hypercalls);
}

const hypertrace_args_t *
khx_hypercall_last(int *id, uintptr_t **pcstack)
{
	if (id != NULL)
		*id = khx_last_hypercall_id;
	if (pcstack != NULL)
		*pcstack = khx_last_pcstack;
	return (&khx_last_htr);
}

int
hypercall_dtrace_probe(int id, uintptr_t args, lwpid_t tid __unused)
{
	const hypertrace_args_t *a = (const hypertrace_args_t *)args;

	khx_last_hypercall_id = id;
	khx_last_htr = *a;
	memset(khx_last_pcstack, 0, sizeof(khx_last_pcstack));
	if (a->htr_pcstack != NULL && a->htr_pcstack_count <=
	    HYPERTRACE_STACK_MAX_FRAMES)
		memcpy(khx_last_pcstack, a->htr_pcstack,
		    a->htr_pcstack_count * sizeof(uintptr_t));
	khx_hc_hist[khx_hypercalls % 8].htr = *a;
	khx_hc_hist[khx_hypercalls % 8].id = id;
	memcpy(khx_hc_hist[khx_hypercalls % 8].pcstack, khx_last_pcstack,
	    sizeof(khx_last_pcstack));
	khx_hypercalls++;
	return (khx_hypercall_ret);
}

/* Guest translation: identity over registered guest ranges unless the
 * real amd64 dtrace_vm_subr.c page walker is linked. */
#ifndef KHX_REAL_GLA2HVA
static struct {
	uint64_t gla;
	uint64_t len;
	void *hva;
} khx_guest_maps[8];

void
khx_guest_map(int slot, uint64_t gla, void *hva, uint64_t len)
{
	khx_guest_maps[slot].gla = gla;
	khx_guest_maps[slot].hva = hva;
	khx_guest_maps[slot].len = len;
}

int
dtrace_gla2hva(struct vm_guest_paging *paging __unused, uint64_t gla,
    uint64_t *hva)
{
	for (int i = 0; i < 8; i++) {
		if (khx_guest_maps[i].len != 0 && gla >= khx_guest_maps[i].gla &&
		    gla - khx_guest_maps[i].gla < khx_guest_maps[i].len) {
			*hva = (uint64_t)(uintptr_t)khx_guest_maps[i].hva +
			    (gla - khx_guest_maps[i].gla);
			return (0);
		}
	}
	return (EFAULT);
}
#endif

/* ---- CPUID for bhyve_hypercalls_enabled() ------------------------------ */
static int khx_bhyve_guest;

void
khx_cpuid_bhyve_guest(int on)
{
	khx_bhyve_guest = on;
}

void
khx_do_cpuid(u_int ax, u_int *p)
{
	memset(p, 0, 4 * sizeof(*p));
	if (!khx_bhyve_guest)
		return;
	if (ax == 0x40000000) {
		p[0] = 0x40000001;
		p[1] = 0x76796862U;
		p[2] = 0x68622065U;
		p[3] = 0x20657679U;
	} else if (ax == 0x40000001) {
		p[1] = BHYVE_HYPERTRACE_SIGNATURE;
		p[2] = BHYVE_HYPERTRACE_VERSION;
		p[3] = 1;
	}
}
