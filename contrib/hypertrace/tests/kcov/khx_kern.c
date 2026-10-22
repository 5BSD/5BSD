/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Kernel-ABI shim for running original kernel sources in a userland
 * harness.  Compiled with -D_KERNEL against the source tree's headers (the
 * same configuration as the production objects) and linked with khx_host.c.
 * Symbol names that collide with libc (malloc, free, printf, ...) are
 * renamed in every kernel-ABI object by the driver with objcopy, so this
 * file defines them under their kernel names.
 *
 * Each shim implements the documented kernel contract that the measured
 * production code relies on: lock ownership and assertions are enforced,
 * sleeping drops and reacquires interlocks, allocation can fail only for
 * M_NOWAIT, and copyin/copyout fault on injected ranges.  Not production
 * code; excluded from reported coverage.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/condvar.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/rwlock.h>
#include <sys/sema.h>
#include <sys/smp.h>
#include <sys/sx.h>
#include <sys/ucred.h>
#include <sys/jail.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/dtrace_bsd.h>
#include <machine/stdarg.h>

#include "khx_kern.h"

/* kdtrace_thread/proc are CDDL types; khx_dtrace.c checks they fit. */
#define KHX_KDTRACE_SIZE 4096

/* ---- global kernel variables ------------------------------------------ */
int hz = 1000;
volatile int ticks;
int mp_ncpus = KHX_NCPU;
u_int mp_maxid = KHX_NCPU - 1;
cpuset_t all_cpus;
struct pcpu *cpuid_to_pcpu[MAXCPU];
struct cpuhead cpuhead = STAILQ_HEAD_INITIALIZER(cpuhead);
static struct proc khx_proc0;
static struct thread khx_thread0 __aligned(128);	/* lock words use low bits */
struct ucred khx_cred0;
struct prison prison0;
volatile time_t time_second = 1;
volatile time_t time_uptime = 1;
sbintime_t tick_sbt = SBT_1MS;
hostid_t dtrace_node_id;

/* An empty pcpu linker set so DPCPU references link. */
static int khx_pcpu_marker __section("set_pcpu") __used;

static struct pcpu *khx_pcpus;
static struct pstats khx_stats0;

/* ---- fatal and console output ----------------------------------------- */
static char khx_cons[1 << 16];
static size_t khx_cons_len;

void
khx_printf_reset(void)
{
	khx_cons_len = 0;
	khx_cons[0] = '\0';
}

int
khx_printf_seen(const char *needle)
{
	return (strstr(khx_cons, needle) != NULL);
}

const char *
khx_printf_buffer(void)
{
	return (khx_cons);
}

static void
khx_cons_append(const char *fmt, va_list ap)
{
	char line[1024];
	int n;

	n = vsnprintf(line, sizeof(line), fmt, ap);
	if (n < 0)
		return;
	if ((size_t)n >= sizeof(line))
		n = sizeof(line) - 1;
	if (khx_cons_len + n + 1 >= sizeof(khx_cons))
		khx_cons_len = 0;	/* wrap; tests reset before asserting */
	memcpy(khx_cons + khx_cons_len, line, n);
	khx_cons_len += n;
	khx_cons[khx_cons_len] = '\0';
	if (khx_host_verbose())
		khx_host_log("%s", line);
}

int
printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	khx_cons_append(fmt, ap);
	va_end(ap);
	return (0);
}

int
vprintf(const char *fmt, va_list ap)
{
	khx_cons_append(fmt, ap);
	return (0);
}

void
log(int level __unused, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	khx_cons_append(fmt, ap);
	va_end(ap);
}

int
uprintf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	khx_cons_append(fmt, ap);
	va_end(ap);
	return (0);
}

void
panic(const char *fmt, ...)
{
	char msg[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	khx_host_panic(msg);
}


/* ---- CPUs and threads -------------------------------------------------- */
struct khx_thread {
	struct thread td;
	struct proc proc_storage;
	struct pstats stats;
	struct ucred cred;
};

static void
khx_pcpu_setup(void)
{
	int i;

	khx_pcpus = khx_host_alloc(sizeof(struct pcpu) * KHX_NCPU, 1, 0,
	    "pcpu");
	CPU_ZERO(&all_cpus);
	for (i = 0; i < KHX_NCPU; i++) {
		khx_pcpus[i].pc_cpuid = i;
		khx_pcpus[i].pc_prvspace = &khx_pcpus[i];
		cpuid_to_pcpu[i] = &khx_pcpus[i];
		CPU_SET(i, &all_cpus);
		STAILQ_INSERT_TAIL(&cpuhead, &khx_pcpus[i], pc_allcpu);
	}
}

static void
khx_cred_setup(struct ucred *cr)
{
	cr->cr_ref = 1;
	cr->cr_prison = &prison0;
	cr->cr_uid = 0;
	cr->cr_ruid = 0;
}

struct thread *
khx_thread_new(const char *name, pid_t pid)
{
	struct khx_thread *kt;

	kt = khx_host_alloc(sizeof(*kt), 1, 0, "khx-thread");
	khx_cred_setup(&kt->cred);
	if (pid == 0) {
		kt->td.td_proc = &khx_proc0;
	} else {
		kt->td.td_proc = &kt->proc_storage;
		kt->proc_storage.p_pid = pid;
		kt->proc_storage.p_stats = &kt->stats;
		kt->stats.p_start.tv_sec = pid;
		kt->stats.p_start.tv_usec = pid % 1000000;
		kt->proc_storage.p_ucred = &kt->cred;
		kt->proc_storage.p_pptr = &khx_proc0;
		strlcpy(kt->proc_storage.p_comm, name,
		    sizeof(kt->proc_storage.p_comm));
		mtx_init(&kt->proc_storage.p_mtx, "process lock", NULL,
		    MTX_DEF | MTX_DUPOK);
	}
	kt->td.td_ucred = &kt->cred;
	kt->td.td_dtrace = khx_host_alloc(KHX_KDTRACE_SIZE, 1, 0,
	    "khx-kdtrace");
	if (pid != 0)
		kt->proc_storage.p_dtrace = khx_host_alloc(
		    KHX_KDTRACE_SIZE, 1, 0, "khx-kdtrace");
	kt->td.td_tid = 100000 + (lwpid_t)(khx_host_alloc_count() & 0xffff);
	strlcpy(kt->td.td_name, name, sizeof(kt->td.td_name));
	return (&kt->td);
}

void
khx_thread_free(struct thread *td)
{
	khx_host_free(td, "khx-thread");
}

struct thread *
khx_set_curthread(struct thread *td)
{
	struct pcpu *pc = get_pcpu();
	struct thread *old = pc->pc_curthread;

	pc->pc_curthread = td;
	return (old);
}

void
khx_set_curcpu(int cpu)
{
	struct pcpu *pc = get_pcpu();
	struct thread *td = pc->pc_curthread;

	/* Per-pthread pcpu copies: each pthread owns a private pcpu image so
	 * curthread is per-pthread; only pc_cpuid differs per CPU. */
	pc->pc_cpuid = cpu;
	pc->pc_curthread = td;
}

void
khx_pthread_attach(int cpu, struct thread *td)
{
	struct pcpu *pc;

	pc = khx_host_alloc(sizeof(*pc), 1, 0, "pcpu-private");
	*pc = khx_pcpus[cpu];
	pc->pc_prvspace = pc;
	pc->pc_curthread = td;
	khx_host_set_gsbase(pc);
}

void
khx_kern_boot(void)
{
	khx_pcpu_setup();
	khx_cred_setup(&khx_cred0);
	khx_proc0.p_pid = 0;
	khx_proc0.p_ucred = &khx_cred0;
	khx_proc0.p_stats = &khx_stats0;
	khx_thread0.td_proc = &khx_proc0;
	khx_thread0.td_ucred = &khx_cred0;
	khx_thread0.td_tid = 100000;
	khx_thread0.td_dtrace = khx_host_alloc(KHX_KDTRACE_SIZE, 1,
	    0, "khx-kdtrace");
	khx_proc0.p_dtrace = khx_host_alloc(KHX_KDTRACE_SIZE, 1, 0,
	    "khx-kdtrace");
	strlcpy(khx_thread0.td_name, "thread0", sizeof(khx_thread0.td_name));
	khx_pthread_attach(0, &khx_thread0);
}

/* ---- malloc(9) --------------------------------------------------------- */
MALLOC_DEFINE(M_TEMP, "temp", "harness temporary");
MALLOC_DEFINE(M_DEVBUF, "devbuf", "harness device buffers");

void *
(malloc)(size_t size, struct malloc_type *type, int flags)
{
	void *p;

	if ((flags & (M_WAITOK | M_NOWAIT)) == 0 ||
	    (flags & (M_WAITOK | M_NOWAIT)) == (M_WAITOK | M_NOWAIT))
		panic("malloc: exactly one of M_WAITOK/M_NOWAIT required");
	p = khx_host_alloc(size, (flags & M_ZERO) != 0, (flags & M_NOWAIT) != 0,
	    type != NULL ? type->ks_shortdesc : "?");
	if (p == NULL && (flags & M_NOWAIT) == 0)
		panic("M_WAITOK allocation failed");
	return (p);
}

void
free(void *addr, struct malloc_type *type)
{
	khx_host_free(addr, type != NULL ? type->ks_shortdesc : "?");
}

void
zfree(void *addr, struct malloc_type *type)
{
	if (addr != NULL)
		explicit_bzero(addr, khx_host_alloc_size(addr));
	free(addr, type);
}

void *
realloc(void *addr, size_t size, struct malloc_type *type, int flags)
{
	void *n;
	size_t old;

	n = malloc(size, type, flags);
	if (n == NULL)
		return (NULL);
	if (addr != NULL) {
		old = khx_host_alloc_size(addr);
		memcpy(n, addr, old < size ? old : size);
		free(addr, type);
	}
	return (n);
}

void *
reallocf(void *addr, size_t size, struct malloc_type *type, int flags)
{
	void *n = realloc(addr, size, type, flags);

	if (n == NULL)
		free(addr, type);
	return (n);
}

void
malloc_init(void *data __unused)
{
}

void
malloc_uninit(void *data __unused)
{
}

void
explicit_bzero(void *b, size_t len)
{
	volatile char *p = b;

	while (len-- > 0)
		*p++ = 0;
}

/* ---- mutex(9) ---------------------------------------------------------- */
#define KHX_MTX(c) __containerof(c, struct mtx, mtx_lock)

void
_mtx_init(volatile uintptr_t *c, const char *name, const char *type __unused,
    int opts)
{
	struct mtx *m = KHX_MTX(c);

	if ((opts & MTX_SPIN) != 0)
		panic("spin mutexes are not expected in this harness");
	if (lock_initialized(&m->lock_object))
		panic("mtx_init: %s already initialized", name);
	m->lock_object.lo_name = name;
	m->lock_object.lo_flags = LO_INITIALIZED |
	    ((opts & MTX_RECURSE) ? LO_RECURSABLE : 0);
	m->mtx_lock = MTX_UNOWNED;
	khx_host_lock_init(m, name, (opts & MTX_RECURSE) != 0, 0);
}

void
_mtx_destroy(volatile uintptr_t *c)
{
	struct mtx *m = KHX_MTX(c);

	if (!lock_initialized(&m->lock_object))
		panic("mtx_destroy of uninitialized mutex");
	if (m->mtx_lock != MTX_UNOWNED)
		panic("mtx_destroy of owned mutex %s", m->lock_object.lo_name);
	khx_host_lock_destroy(m);
	m->mtx_lock = MTX_DESTROYED;
	m->lock_object.lo_flags &= ~LO_INITIALIZED;
}

void
mtx_sysinit(const void *arg)
{
	const struct mtx_args *margs = arg;

	mtx_init((struct mtx *)margs->ma_mtx, margs->ma_desc, NULL,
	    margs->ma_opts);
}

/* Optional test hook run before a sleep mutex is acquired (deterministic
 * interleavings at a lock acquisition point). */
static void (*khx_mtx_hook)(void *, struct mtx *, const char *, int);
static void *khx_mtx_hook_arg;

void
khx_set_mtx_hook(void (*hook)(void *, struct mtx *, const char *, int),
    void *arg)
{
	khx_mtx_hook = hook;
	khx_mtx_hook_arg = arg;
}

void
__mtx_lock_flags(volatile uintptr_t *c, int opts __unused, const char *file,
    int line)
{
	struct mtx *m = KHX_MTX(c);

	if (!lock_initialized(&m->lock_object))
		panic("mtx_lock of uninitialized mutex at %s:%d", file, line);
	if (khx_mtx_hook != NULL)
		khx_mtx_hook(khx_mtx_hook_arg, m, file, line);
	khx_host_lock_acquire(m, curthread, KHX_LOCK_EXCL, 0, NULL, file, line);
	m->mtx_lock = (uintptr_t)curthread;
}

void
__mtx_unlock_flags(volatile uintptr_t *c, int opts __unused,
    const char *file __unused, int line __unused)
{
	struct mtx *m = KHX_MTX(c);

	if (khx_host_lock_release(m, curthread, KHX_LOCK_EXCL) == 0)
		m->mtx_lock = MTX_UNOWNED;
}

int
_mtx_trylock_flags_(volatile uintptr_t *c, int opts __unused,
    const char *file, int line)
{
	struct mtx *m = KHX_MTX(c);
	int acquired;

	khx_host_lock_acquire(m, curthread, KHX_LOCK_EXCL, 1, &acquired, file,
	    line);
	if (acquired)
		m->mtx_lock = (uintptr_t)curthread;
	return (acquired);
}

void
__mtx_assert(const volatile uintptr_t *c, int what, const char *file,
    int line)
{
	const struct mtx *m = KHX_MTX(c);
	int owned = khx_host_lock_held(m, curthread, KHX_LOCK_EXCL);

	switch (what & ~(MA_RECURSED | MA_NOTRECURSED)) {
	case MA_OWNED:
		if (!owned)
			panic("mutex %s not owned at %s:%d",
			    m->lock_object.lo_name, file, line);
		break;
	case MA_NOTOWNED:
		if (owned)
			panic("mutex %s owned at %s:%d",
			    m->lock_object.lo_name, file, line);
		break;
	default:
		panic("unknown mtx_assert");
	}
}

/* ---- sx(9) ------------------------------------------------------------- */
static void
khx_sx_publish(struct sx *sx)
{
	int n = khx_host_lock_sharers(sx);

	if (khx_host_lock_held(sx, curthread, KHX_LOCK_EXCL))
		sx->sx_lock = (uintptr_t)curthread;
	else
		sx->sx_lock = SX_SHARERS_LOCK(n);
}

void
sx_init_flags(struct sx *sx, const char *description, int opts)
{
	sx->lock_object.lo_name = description;
	sx->lock_object.lo_flags = LO_INITIALIZED | LO_SLEEPABLE |
	    ((opts & SX_RECURSE) ? LO_RECURSABLE : 0);
	sx->sx_lock = SX_LOCK_UNLOCKED;
	khx_host_lock_init(sx, description, (opts & SX_RECURSE) != 0, 1);
}

void
sx_sysinit(const void *arg)
{
	const struct sx_args *sargs = arg;

	sx_init_flags(sargs->sa_sx, sargs->sa_desc, sargs->sa_flags);
}

void
sx_destroy(struct sx *sx)
{
	if (sx->sx_lock != SX_LOCK_UNLOCKED)
		panic("sx_destroy of held lock %s", sx->lock_object.lo_name);
	khx_host_lock_destroy(sx);
	sx->sx_lock = SX_LOCK_DESTROYED;
	sx->lock_object.lo_flags &= ~LO_INITIALIZED;
}

int
_sx_xlock(struct sx *sx, int opts __unused, const char *file, int line)
{
	khx_host_lock_acquire(sx, curthread, KHX_LOCK_EXCL, 0, NULL, file,
	    line);
	sx->sx_lock = (uintptr_t)curthread;
	return (0);
}

void
_sx_xunlock(struct sx *sx, const char *file __unused, int line __unused)
{
	if (khx_host_lock_release(sx, curthread, KHX_LOCK_EXCL) == 0)
		sx->sx_lock = SX_LOCK_UNLOCKED;
}

int
_sx_slock(struct sx *sx, int opts __unused, const char *file, int line)
{
	khx_host_lock_acquire(sx, curthread, KHX_LOCK_SHARED, 0, NULL, file,
	    line);
	khx_sx_publish(sx);
	return (0);
}

void
_sx_sunlock(struct sx *sx, const char *file __unused, int line __unused)
{
	khx_host_lock_release(sx, curthread, KHX_LOCK_SHARED);
	sx->sx_lock = SX_SHARERS_LOCK(khx_host_lock_sharers(sx));
}

int
sx_try_xlock_(struct sx *sx, const char *file, int line)
{
	int acquired;

	khx_host_lock_acquire(sx, curthread, KHX_LOCK_EXCL, 1, &acquired, file,
	    line);
	if (acquired)
		sx->sx_lock = (uintptr_t)curthread;
	return (acquired);
}

void
_sx_assert(const struct sx *sx, int what, const char *file, int line)
{
	int x = khx_host_lock_held(sx, curthread, KHX_LOCK_EXCL);
	int s = khx_host_lock_held(sx, curthread, KHX_LOCK_SHARED);

	switch (what & ~(SA_RECURSED | SA_NOTRECURSED)) {
	case SA_XLOCKED:
		if (!x)
			panic("sx %s not xlocked at %s:%d",
			    sx->lock_object.lo_name, file, line);
		break;
	case SA_SLOCKED:
		if (!s)
			panic("sx %s not slocked at %s:%d",
			    sx->lock_object.lo_name, file, line);
		break;
	case SA_LOCKED:
		if (!x && !s)
			panic("sx %s not locked at %s:%d",
			    sx->lock_object.lo_name, file, line);
		break;
	case SA_UNLOCKED:
		if (x || s)
			panic("sx %s locked at %s:%d",
			    sx->lock_object.lo_name, file, line);
		break;
	default:
		panic("unknown sx_assert");
	}
}

/* ---- condvar(9), sleep(9), sema(9) ------------------------------------- */
void
cv_init(struct cv *cvp, const char *desc)
{
	cvp->cv_description = desc;
	cvp->cv_waiters = 0;
}

void
cv_destroy(struct cv *cvp)
{
	if (cvp->cv_waiters != 0)
		panic("cv_destroy with waiters");
}

/* Publish host lock state through the word inline accessors read. */
static void
khx_lock_publish(struct lock_object *lock)
{
	struct thread *owner = NULL;
	int sharers;

	if (khx_host_lock_held(lock, curthread, KHX_LOCK_EXCL))
		owner = curthread;
	if ((lock->lo_flags & LO_SLEEPABLE) != 0) {
		sharers = khx_host_lock_sharers(lock);
		((struct sx *)lock)->sx_lock = owner != NULL ?
		    (uintptr_t)owner : SX_SHARERS_LOCK(sharers);
	} else
		((struct mtx *)lock)->mtx_lock = owner != NULL ?
		    (uintptr_t)owner : MTX_UNOWNED;
}

int
khx_release_locks_after_panic(struct thread *td)
{
	const void *keys[64];
	int n, i;

	n = khx_host_lock_force_release_all(td, keys, 64);
	for (i = 0; i < n && i < 64; i++)
		khx_lock_publish((struct lock_object *)(uintptr_t)keys[i]);
	td->td_critnest = 0;
	return (n);
}

static int
khx_sleep_on(const void *wchan, struct lock_object *lock, const char *wmesg,
    int timo, int catch_signals, int unlock)
{
	int mode = 0, depth = 0, error;
	struct thread *td = curthread;

	if (lock != NULL) {
		khx_host_lock_sleep_drop(lock, td, &mode, &depth);
		khx_lock_publish(lock);
	}
	error = khx_host_sleep(wchan, wmesg, timo, catch_signals);
	if (lock != NULL && !unlock) {
		khx_host_lock_sleep_reacquire(lock, td, mode, depth);
		khx_lock_publish(lock);
	}
	return (error);
}

void
_cv_wait(struct cv *cvp, struct lock_object *lock)
{
	cvp->cv_waiters++;
	(void)khx_sleep_on(cvp, lock, cvp->cv_description, 0, 0, 0);
	cvp->cv_waiters--;
}

void
_cv_wait_unlock(struct cv *cvp, struct lock_object *lock)
{
	(void)khx_sleep_on(cvp, lock, cvp->cv_description, 0, 0, 1);
}

int
_cv_wait_sig(struct cv *cvp, struct lock_object *lock)
{
	int error;

	cvp->cv_waiters++;
	error = khx_sleep_on(cvp, lock, cvp->cv_description, 0, 1, 0);
	cvp->cv_waiters--;
	return (error);
}

int
_cv_timedwait_sbt(struct cv *cvp, struct lock_object *lock, sbintime_t sbt,
    sbintime_t pr __unused, int flags __unused)
{
	int error, timo;

	timo = (int)(sbt / SBT_1MS);
	if (timo <= 0)
		timo = 1;
	cvp->cv_waiters++;
	error = khx_sleep_on(cvp, lock, cvp->cv_description, timo, 0, 0);
	cvp->cv_waiters--;
	return (error);
}

int
_cv_timedwait_sig_sbt(struct cv *cvp, struct lock_object *lock,
    sbintime_t sbt, sbintime_t pr __unused, int flags __unused)
{
	int error, timo;

	timo = (int)(sbt / SBT_1MS);
	if (timo <= 0)
		timo = 1;
	cvp->cv_waiters++;
	error = khx_sleep_on(cvp, lock, cvp->cv_description, timo, 1, 0);
	cvp->cv_waiters--;
	return (error);
}

void
cv_signal(struct cv *cvp)
{
	khx_host_wakeup(cvp, 0);
}

void
cv_broadcastpri(struct cv *cvp, int pri __unused)
{
	khx_host_wakeup(cvp, 1);
}

int
_sleep(const void *ident, struct lock_object *lock, int priority,
    const char *wmesg, sbintime_t sbt, sbintime_t pr __unused,
    int flags __unused)
{
	int timo = sbt == 0 ? 0 : (int)(sbt / SBT_1MS);

	if (sbt != 0 && timo <= 0)
		timo = 1;
	return (khx_sleep_on(ident, lock, wmesg, timo, (priority & PCATCH) != 0,
	    (priority & PDROP) != 0));
}

void
wakeup(const void *chan)
{
	khx_host_wakeup(chan, 1);
}

void
wakeup_one(const void *chan)
{
	khx_host_wakeup(chan, 0);
}

int
pause_sbt(const char *wmesg, sbintime_t sbt, sbintime_t pr __unused,
    int flags __unused)
{
	int timo = (int)(sbt / SBT_1MS);

	return (khx_host_sleep(&ticks, wmesg, timo <= 0 ? 1 : timo, 0) ==
	    EWOULDBLOCK ? 0 : 0);
}

void
sema_init(struct sema *sema, int value, const char *description)
{
	mtx_init(&sema->sema_mtx, description, "sema backing lock", MTX_DEF);
	cv_init(&sema->sema_cv, description);
	sema->sema_waiters = 0;
	sema->sema_value = value;
}

void
sema_destroy(struct sema *sema)
{
	if (sema->sema_waiters != 0)
		panic("sema_destroy with waiters");
	cv_destroy(&sema->sema_cv);
	mtx_destroy(&sema->sema_mtx);
}

void
_sema_post(struct sema *sema, const char *file __unused, int line __unused)
{
	mtx_lock(&sema->sema_mtx);
	sema->sema_value++;
	if (sema->sema_waiters && sema->sema_value > 0)
		cv_signal(&sema->sema_cv);
	mtx_unlock(&sema->sema_mtx);
}

void
_sema_wait(struct sema *sema, const char *file __unused, int line __unused)
{
	mtx_lock(&sema->sema_mtx);
	while (sema->sema_value == 0) {
		sema->sema_waiters++;
		cv_wait(&sema->sema_cv, &sema->sema_mtx);
		sema->sema_waiters--;
	}
	sema->sema_value--;
	mtx_unlock(&sema->sema_mtx);
}

/* ---- copyin/copyout and uio ------------------------------------------- */
static khx_uiomove_hook_t khx_uio_hook;
static void *khx_uio_hook_arg;

void
khx_set_uiomove_hook(khx_uiomove_hook_t hook, void *arg)
{
	khx_uio_hook = hook;
	khx_uio_hook_arg = arg;
}

static int (*khx_copy_hook)(void *, int, const void *, size_t);
static void *khx_copy_hook_arg;

void
khx_set_copy_hook(int (*hook)(void *, int, const void *, size_t), void *arg)
{
	khx_copy_hook = hook;
	khx_copy_hook_arg = arg;
}

static int
khx_copy_hooked(int out, const void *uaddr, size_t len)
{
	int (*hook)(void *, int, const void *, size_t) = khx_copy_hook;

	if (hook == NULL)
		return (0);
	return (hook(khx_copy_hook_arg, out, uaddr, len));
}

int
copyin(const void *udaddr, void *kaddr, size_t len)
{
	if (khx_copy_hooked(0, udaddr, len) != 0)
		return (EFAULT);
	if (khx_host_copy_should_fail() || khx_host_user_faults(udaddr, len))
		return (EFAULT);
	memcpy(kaddr, udaddr, len);
	return (0);
}

int
copyin_nofault(const void *udaddr, void *kaddr, size_t len)
{
	return (copyin(udaddr, kaddr, len));
}

int
copyout(const void *kaddr, void *udaddr, size_t len)
{
	if (khx_copy_hooked(1, udaddr, len) != 0)
		return (EFAULT);
	if (khx_host_copy_should_fail() || khx_host_user_faults(udaddr, len))
		return (EFAULT);
	memcpy(udaddr, kaddr, len);
	return (0);
}

int
copyout_nofault(const void *kaddr, void *udaddr, size_t len)
{
	return (copyout(kaddr, udaddr, len));
}

int
copyinstr(const void *udaddr, void *kaddr, size_t len, size_t *done)
{
	const char *u = udaddr;
	char *k = kaddr;
	size_t i;

	if (khx_host_copy_should_fail())
		return (EFAULT);
	for (i = 0; i < len; i++) {
		if (khx_host_user_faults(u + i, 1))
			return (EFAULT);
		k[i] = u[i];
		if (u[i] == '\0') {
			if (done != NULL)
				*done = i + 1;
			return (0);
		}
	}
	if (done != NULL)
		*done = len;
	return (ENAMETOOLONG);
}

void
khx_uio_init(struct uio *uio, struct iovec *iov, void *buf, size_t len,
    enum uio_rw rw, enum uio_seg seg, struct thread *td)
{
	iov->iov_base = buf;
	iov->iov_len = len;
	uio->uio_iov = iov;
	uio->uio_iovcnt = 1;
	uio->uio_offset = 0;
	uio->uio_resid = len;
	uio->uio_segflg = seg;
	uio->uio_rw = rw;
	uio->uio_td = td;
}

int
uiomove(void *cp, int n, struct uio *uio)
{
	struct iovec *iov;
	size_t cnt;
	int error = 0;

	KASSERT(uio->uio_rw == UIO_READ || uio->uio_rw == UIO_WRITE,
	    ("uiomove: mode"));
	if (khx_uio_hook != NULL) {
		error = khx_uio_hook(khx_uio_hook_arg, cp, n, uio);
		if (error != 0)
			return (error);
	}
	while (n > 0 && uio->uio_resid) {
		KASSERT(uio->uio_iovcnt > 0, ("uiomove: iovcnt"));
		iov = uio->uio_iov;
		cnt = iov->iov_len;
		if (cnt == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}
		if (cnt > (size_t)n)
			cnt = n;
		switch (uio->uio_segflg) {
		case UIO_USERSPACE:
			if (uio->uio_rw == UIO_READ)
				error = copyout(cp, iov->iov_base, cnt);
			else
				error = copyin(iov->iov_base, cp, cnt);
			if (error)
				return (error);
			break;
		case UIO_SYSSPACE:
			if (uio->uio_rw == UIO_READ)
				memmove(iov->iov_base, cp, cnt);
			else
				memmove(cp, iov->iov_base, cnt);
			break;
		default:
			panic("uiomove: unsupported segment");
		}
		iov->iov_base = (char *)iov->iov_base + cnt;
		iov->iov_len -= cnt;
		uio->uio_resid -= cnt;
		uio->uio_offset += cnt;
		cp = (char *)cp + cnt;
		n -= cnt;
	}
	return (0);
}

/* ---- devfs ------------------------------------------------------------- */
#define KHX_MAX_CDEVS 32
static struct cdev *khx_cdevs[KHX_MAX_CDEVS];
static int khx_make_dev_error;

void
khx_fail_make_dev(int error)
{
	khx_make_dev_error = error;
}

void
make_dev_args_init_impl(struct make_dev_args *args, size_t sz)
{
	memset(args, 0, sz);
	args->mda_size = sz;
}

static struct cdev *
khx_cdev_alloc(struct cdevsw *devsw, const char *name)
{
	struct cdev *dev;
	int i;

	dev = khx_host_alloc(sizeof(*dev), 1, 0, "cdev");
	dev->si_devsw = devsw;
	strlcpy(dev->si_name, name, SPECNAMELEN + 1);
	for (i = 0; i < KHX_MAX_CDEVS; i++) {
		if (khx_cdevs[i] == NULL) {
			khx_cdevs[i] = dev;
			return (dev);
		}
	}
	panic("too many cdevs");
}

int
make_dev_s(struct make_dev_args *args, struct cdev **cdev, const char *fmt,
    ...)
{
	char name[SPECNAMELEN + 1];
	struct cdev *dev;
	va_list ap;
	int error;

	if (khx_make_dev_error != 0) {
		error = khx_make_dev_error;
		khx_make_dev_error = 0;
		return (error);
	}
	va_start(ap, fmt);
	vsnprintf(name, sizeof(name), fmt, ap);
	va_end(ap);
	if (khx_cdev_find(name) != NULL)
		return (EEXIST);
	dev = khx_cdev_alloc(args->mda_devsw, name);
	dev->si_drv1 = args->mda_si_drv1;
	dev->si_drv2 = args->mda_si_drv2;
	dev->si_uid = args->mda_uid;
	dev->si_gid = args->mda_gid;
	dev->si_mode = args->mda_mode;
	*cdev = dev;
	return (0);
}

struct cdev *
make_dev(struct cdevsw *devsw, int unit __unused, uid_t uid, gid_t gid,
    int mode, const char *fmt, ...)
{
	char name[SPECNAMELEN + 1];
	struct cdev *dev;
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(name, sizeof(name), fmt, ap);
	va_end(ap);
	dev = khx_cdev_alloc(devsw, name);
	dev->si_uid = uid;
	dev->si_gid = gid;
	dev->si_mode = mode;
	return (dev);
}

/* devfs keeps a per-cdev count of threads inside cdevsw methods and
 * destroy_dev() waits for it to drain.  Tests enter methods through these
 * wrappers so that contract is preserved. */
static void
khx_dev_enter(struct cdev *dev)
{
	__atomic_add_fetch(&dev->si_threadcount, 1, __ATOMIC_SEQ_CST);
}

static void
khx_dev_leave(struct cdev *dev)
{
	__atomic_sub_fetch(&dev->si_threadcount, 1, __ATOMIC_SEQ_CST);
}

int
khx_dev_open(struct cdev *dev, int flags, struct thread *td)
{
	int e;

	khx_dev_enter(dev);
	e = dev->si_devsw->d_open(dev, flags, S_IFCHR, td);
	khx_dev_leave(dev);
	return (e);
}

int
khx_dev_close(struct cdev *dev, int flags, struct thread *td)
{
	int e;

	khx_dev_enter(dev);
	e = dev->si_devsw->d_close(dev, flags, S_IFCHR, td);
	khx_dev_leave(dev);
	return (e);
}

int
khx_dev_read(struct cdev *dev, struct uio *uio, int flags)
{
	int e;

	khx_dev_enter(dev);
	e = dev->si_devsw->d_read(dev, uio, flags);
	khx_dev_leave(dev);
	return (e);
}

int
khx_dev_write(struct cdev *dev, struct uio *uio, int flags)
{
	int e;

	khx_dev_enter(dev);
	e = dev->si_devsw->d_write(dev, uio, flags);
	khx_dev_leave(dev);
	return (e);
}

int
khx_dev_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags,
    struct thread *td)
{
	int e;

	khx_dev_enter(dev);
	e = dev->si_devsw->d_ioctl(dev, cmd, data, flags, td);
	khx_dev_leave(dev);
	return (e);
}

static void (*khx_destroy_hook)(void *, struct cdev *);
static void *khx_destroy_hook_arg;

void
khx_set_destroy_dev_hook(void (*hook)(void *, struct cdev *), void *arg)
{
	khx_destroy_hook = hook;
	khx_destroy_hook_arg = arg;
}

void
destroy_dev(struct cdev *dev)
{
	int i;

	if (khx_destroy_hook != NULL)
		khx_destroy_hook(khx_destroy_hook_arg, dev);
	while (__atomic_load_n(&dev->si_threadcount, __ATOMIC_SEQ_CST) != 0)
		khx_host_yield();

	for (i = 0; i < KHX_MAX_CDEVS; i++) {
		if (khx_cdevs[i] == dev) {
			khx_cdevs[i] = NULL;
			khx_host_free(dev, "cdev");
			return;
		}
	}
	panic("destroy_dev of unknown cdev");
}

/* destroy_dev_sched_cb(): queued; khx_destroy_dev_sched_run() plays the
 * kernel's destroy_dev_tq taskqueue (destroy_dev(), then the callback). */
#define	KHX_MAX_DEVSCHED 16
static struct {
	struct cdev *dev;
	void (*cb)(void *);
	void *arg;
} khx_devsched[KHX_MAX_DEVSCHED];
static int khx_ndevsched;

int
destroy_dev_sched_cb(struct cdev *dev, void (*cb)(void *), void *arg)
{
	if (khx_ndevsched == KHX_MAX_DEVSCHED)
		panic("destroy_dev_sched_cb: queue full");
	khx_devsched[khx_ndevsched].dev = dev;
	khx_devsched[khx_ndevsched].cb = cb;
	khx_devsched[khx_ndevsched].arg = arg;
	khx_ndevsched++;
	return (1);
}

int
khx_destroy_dev_sched_pending(void)
{
	return (khx_ndevsched);
}

void
khx_destroy_dev_sched_run(void)
{
	while (khx_ndevsched > 0) {
		int i = --khx_ndevsched;

		destroy_dev(khx_devsched[i].dev);
		if (khx_devsched[i].cb != NULL)
			khx_devsched[i].cb(khx_devsched[i].arg);
	}
}

int
khx_dev_mmap_single(struct cdev *dev, vm_ooffset_t *offset, vm_size_t size,
    struct vm_object **objp, int nprot)
{
	int e;

	khx_dev_enter(dev);
	e = dev->si_devsw->d_mmap_single(dev, offset, size, objp, nprot);
	khx_dev_leave(dev);
	return (e);
}

struct cdev *
khx_cdev_find(const char *name)
{
	int i;

	for (i = 0; i < KHX_MAX_CDEVS; i++)
		if (khx_cdevs[i] != NULL &&
		    strcmp(khx_cdevs[i]->si_name, name) == 0)
			return (khx_cdevs[i]);
	return (NULL);
}

int
khx_cdev_count(void)
{
	int i, n = 0;

	for (i = 0; i < KHX_MAX_CDEVS; i++)
		n += khx_cdevs[i] != NULL;
	return (n);
}

/* ---- modules and SYSINIT ---------------------------------------------- */
#define KHX_MAX_MODULES 16
static const moduledata_t *khx_modules[KHX_MAX_MODULES];
static int khx_module_state[KHX_MAX_MODULES];

void
module_register_init(const void *arg)
{
	const moduledata_t *data = arg;
	int i, error;

	for (i = 0; i < KHX_MAX_MODULES; i++) {
		if (khx_modules[i] == NULL) {
			khx_modules[i] = data;
			error = data->evhand != NULL ?
			    data->evhand(NULL, MOD_LOAD, data->priv) : 0;
			khx_module_state[i] = error == 0 ? 1 : -error;
			return;
		}
	}
	panic("too many modules");
}

int
khx_module_event(const char *name, int what)
{
	int i, error;

	for (i = 0; i < KHX_MAX_MODULES; i++) {
		if (khx_modules[i] != NULL &&
		    strcmp(khx_modules[i]->name, name) == 0) {
			error = khx_modules[i]->evhand(NULL, what,
			    khx_modules[i]->priv);
			if (what == MOD_UNLOAD && error == 0)
				khx_module_state[i] = 0;
			if (what == MOD_LOAD && error == 0)
				khx_module_state[i] = 1;
			return (error);
		}
	}
	return (ENOENT);
}

int
khx_module_loaded(const char *name)
{
	int i;

	for (i = 0; i < KHX_MAX_MODULES; i++)
		if (khx_modules[i] != NULL &&
		    strcmp(khx_modules[i]->name, name) == 0)
			return (khx_module_state[i]);
	return (0);
}

SET_DECLARE(sysinit_set, struct sysinit);
SET_DECLARE(sysuninit_set, struct sysinit);
/* MALLOC_DEFINE above guarantees both linker sets exist. */

static void
khx_run_set(struct sysinit **begin, struct sysinit **end, int reverse)
{
	struct sysinit **sorted, **sipp, *tmp;
	size_t n = end - begin, i, j;

	sorted = khx_host_alloc(sizeof(*sorted) * (n ? n : 1), 0, 0, "sysinit");
	for (i = 0, sipp = begin; sipp < end; sipp++, i++)
		sorted[i] = *sipp;
	for (i = 0; i < n; i++) {
		for (j = i + 1; j < n; j++) {
			int swap = sorted[j]->subsystem < sorted[i]->subsystem ||
			    (sorted[j]->subsystem == sorted[i]->subsystem &&
			    sorted[j]->order < sorted[i]->order);
			if (swap) {
				tmp = sorted[i];
				sorted[i] = sorted[j];
				sorted[j] = tmp;
			}
		}
	}
	for (i = 0; i < n; i++) {
		tmp = sorted[reverse ? n - 1 - i : i];
		if (tmp->func != NULL)
			tmp->func(tmp->udata);
	}
	khx_host_free(sorted, "sysinit");
}

void
khx_run_sysinits(void)
{
	khx_run_set(SET_BEGIN(sysinit_set), SET_LIMIT(sysinit_set), 0);
}

void
khx_run_sysuninits(void)
{
	khx_run_set(SET_BEGIN(sysuninit_set), SET_LIMIT(sysuninit_set), 1);
}

/* ---- SMP --------------------------------------------------------------- */
static long khx_rendezvous;
static void (*khx_rv_hook)(void *);
static void *khx_rv_arg;

long
khx_rendezvous_count(void)
{
	return (khx_rendezvous);
}

void
khx_set_rendezvous_hook(void (*hook)(void *), void *arg)
{
	khx_rv_hook = hook;
	khx_rv_arg = arg;
}

/* Each CPU's part runs on the calling pthread with curcpu set to that CPU,
 * in the barrier order setup -> action -> teardown, as on hardware. */
void
smp_rendezvous_cpus(cpuset_t map, void (*setup)(void *),
    void (*action)(void *), void (*teardown)(void *), void *arg)
{
	struct pcpu *pc = get_pcpu();
	u_int saved = pc->pc_cpuid;
	int i;

	khx_rendezvous++;
	if (khx_rv_hook != NULL)
		khx_rv_hook(khx_rv_arg);
	for (i = 0; i < KHX_NCPU; i++) {
		if (!CPU_ISSET(i, &map))
			continue;
		pc->pc_cpuid = i;
		if (setup != NULL && setup != smp_no_rendezvous_barrier)
			setup(arg);
	}
	for (i = 0; i < KHX_NCPU; i++) {
		if (!CPU_ISSET(i, &map))
			continue;
		pc->pc_cpuid = i;
		if (action != NULL && action != smp_no_rendezvous_barrier)
			action(arg);
	}
	for (i = 0; i < KHX_NCPU; i++) {
		if (!CPU_ISSET(i, &map))
			continue;
		pc->pc_cpuid = i;
		if (teardown != NULL && teardown != smp_no_rendezvous_barrier)
			teardown(arg);
	}
	pc->pc_cpuid = saved;
}

void
smp_rendezvous(void (*setup)(void *), void (*action)(void *),
    void (*teardown)(void *), void *arg)
{
	smp_rendezvous_cpus(all_cpus, setup, action, teardown, arg);
}

void
smp_no_rendezvous_barrier(void *arg __unused)
{
}

void
critical_enter_KBI(void)
{
	curthread->td_critnest++;
}

void
critical_exit_KBI(void)
{
	if (curthread->td_critnest == 0)
		panic("critical_exit without enter");
	curthread->td_critnest--;
}

static int khx_random_zeros;

void
khx_random_zero_next(int n)
{
	khx_random_zeros = n;
}

void
arc4random_buf(void *buf, size_t len)
{
	if (khx_random_zeros > 0) {
		khx_random_zeros--;
		memset(buf, 0, len);
		return;
	}
	khx_host_random(buf, len);
}

uint32_t
arc4random(void)
{
	uint32_t v;

	khx_host_random(&v, sizeof(v));
	return (v);
}
