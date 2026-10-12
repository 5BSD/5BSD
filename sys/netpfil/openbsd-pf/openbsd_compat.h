/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * 5BSD compatibility layer for OpenBSD PF (contrib/openbsd-pf/sys/net).
 *
 * This header is force-included (cc -include) before every OpenBSD vendor
 * source file of the pf module.  It pulls in every 5BSD kernel header the
 * vendor code needs *first*, so that later #include lines in the vendor
 * files are no-ops, and then maps the OpenBSD kernel programming interfaces
 * PF uses onto 5BSD (FreeBSD-derived) kernel services.
 *
 * Name clashes:
 *  - "struct task" exists in both kernels with different layouts.  While
 *    the 5BSD headers are processed "task" is renamed to __fbsd_task, so
 *    5BSD structures embedding a task keep their exact layout; afterwards
 *    "struct task" is OpenBSD's.
 *  - rwlock, mutex, malloc/free, mbuf and route helpers that differ in
 *    signature are redefined after the 5BSD headers.
 *
 * Glue files (sys/netpfil/openbsd-pf/ *.c) are compiled with
 * -DOPENBSD_PF_GLUE; they see the same types but keep 5BSD semantics for
 * free(9).
 */
#ifndef _OPENBSD_PF_COMPAT_H_
#define _OPENBSD_PF_COMPAT_H_

#include "opt_global.h"

/* OpenBSD queue.h invalidates removed entries; pf asserts on that. */
#ifndef QUEUE_MACRO_DEBUG_TRASH
#define	QUEUE_MACRO_DEBUG_TRASH
#endif

#define	task	__fbsd_task

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/sx.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/pcpu.h>
#include <sys/counter.h>
#include <sys/callout.h>
#include <sys/taskqueue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/conf.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/time.h>
#include <sys/stdarg.h>
#include <sys/stdint.h>
#include <sys/endian.h>
#include <sys/epoch.h>
#include <sys/limits.h>
#include <sys/refcount.h>
#include <sys/random.h>
#include <sys/libkern.h>
#include <sys/eventhandler.h>
#include <sys/priv.h>
#include <sys/ucred.h>
#include <sys/jail.h>
#include <machine/atomic.h>
#include <machine/cpu.h>

#include <vm/uma.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_private.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/if_clone.h>
#include <net/ethernet.h>
#include <net/bpf.h>
#include <net/route.h>
#include <net/route/nhop.h>
#include <net/route/route_ctl.h>
#include <net/vnet.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/in_fib.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <machine/in_cksum.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/if_ether.h>
#include <netinet/igmp.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_var.h>
#include <netinet6/in6_fib.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/nd6.h>
#include <netinet6/scope6_var.h>
#endif

#include <crypto/siphash/siphash.h>
#include <crypto/sha2/sha256.h>
#include <crypto/sha2/sha512.h>
#include <sys/md5.h>

#undef	task

typedef unsigned int	uint;

/*
 * OpenBSD KASSERT() takes only the expression; 5BSD's takes a message
 * too.  Dispatch on the number of arguments so both forms work (vendor
 * code and 5BSD headers/macros used by the glue).
 */
#undef	KASSERT
#ifdef INVARIANTS
#define	_OBSD_KASSERT1(e)	do {					\
	if (__predict_false(!(e)))					\
		kassert_panic("assertion \"%s\" failed: file \"%s\", line %d",\
		    #e, __FILE__, __LINE__);				\
} while (0)
#define	_OBSD_KASSERT2(e, msg)	do {					\
	if (__predict_false(!(e)))					\
		kassert_panic msg;					\
} while (0)
#define	KASSERTMSG(e, fmt, ...)	do {					\
	if (__predict_false(!(e)))					\
		kassert_panic("assertion \"%s\" failed: " fmt, #e, ##__VA_ARGS__);\
} while (0)
#else
#define	_OBSD_KASSERT1(e)	do { } while (0)
#define	_OBSD_KASSERT2(e, msg)	do { } while (0)
#define	KASSERTMSG(e, fmt, ...)	do { } while (0)
#endif
#define	_OBSD_KASSERT_SEL(_1, _2, NAME, ...)	NAME
#define	KASSERT(...)							\
	_OBSD_KASSERT_SEL(__VA_ARGS__, _OBSD_KASSERT2, _OBSD_KASSERT1)(__VA_ARGS__)
#define	CTASSERT_OBSD(x)	_Static_assert((x), #x)

void	unhandled_af(int) __dead2;

/* Forward declarations of OpenBSD-only types referenced in prototypes. */
struct tdb;
struct netstack;
struct proc;
struct ifqueue;
struct mbuf_list;
union sockaddr_union {
	struct sockaddr		sa;
	struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
};

/* OpenBSD SipHash API (crypto/siphash.h) on 5BSD crypto/siphash. */
typedef struct {
	uint64_t	k0;
	uint64_t	k1;
} SIPHASH_KEY;
#undef	SipHash24_Init
#define	SipHash24_Init(ctx, key) do {					\
	SipHash_InitX((ctx), 2, 4);					\
	SipHash_SetKey((ctx), (const uint8_t *)(key));			\
} while (0)
#define	SipHash24_Update(ctx, p, l)	SipHash_Update((ctx), (p), (l))
#define	SipHash24_End(ctx)		SipHash_End(ctx)
#define	SipHash24_Final(d, ctx)		SipHash_Final((d), (ctx))
static __inline uint64_t
obsd_SipHash24(const SIPHASH_KEY *key, const void *p, size_t l)
{
	SIPHASH_CTX ctx;

	SipHash24_Init(&ctx, key);
	SipHash_Update(&ctx, p, l);
	return (SipHash_End(&ctx));
}
#undef	SipHash24
#define	SipHash24(key, p, l)		obsd_SipHash24((key), (p), (l))

/* OpenBSD netinet/in.h and in_pcb.h helpers. */
int	inet_nat64(int, const void *, void *, const void *, u_int8_t);
int	inet_nat46(int, const void *, void *, const void *, u_int8_t);
int	in_baddynamic(u_int16_t, u_int16_t);

/* Network stack globals under their OpenBSD names. */
#define	tcp_mssdflt	V_tcp_mssdflt

/* sys/socket.h protocol family that collides with pf's PF_DIVERT action */
#undef	PF_DIVERT
#undef	TASK_INITIALIZER

/* Route labels (OpenBSD net/route.h); implemented in the glue. */
#define	RTLABEL_LEN	32
const char	*rtlabel_id2name(u_int16_t, char *, size_t);
u_int16_t	 rtlabel_name2id(const char *);
void		 rtlabel_unref(u_int16_t);

/* ------------------------------------------------------------------ */
/* Basic OpenBSD types and helpers                                     */
/* ------------------------------------------------------------------ */

#ifndef nitems
#define	nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif
#ifndef ISSET
#define	ISSET(t, f)	((t) & (f))
#define	SET(t, f)	((t) |= (f))
#define	CLR(t, f)	((t) &= ~(f))
#endif
#define	betoh16(x)	be16toh(x)
#define	betoh32(x)	be32toh(x)
#define	betoh64(x)	be64toh(x)
#define	letoh16(x)	le16toh(x)
#define	letoh32(x)	le32toh(x)
#define	swap32(x)	bswap32(x)

#ifndef READ_ONCE
#define	READ_ONCE(x)		(*(volatile __typeof(x) *)&(x))
#endif
#ifndef WRITE_ONCE
#define	WRITE_ONCE(x, v)	(*(volatile __typeof(x) *)&(x) = (v))
#endif

#define	atomic_inc_int(p)		atomic_add_int((p), 1)
#define	atomic_dec_int(p)		atomic_subtract_int((p), 1)
#define	atomic_inc_int_nv(p)		(atomic_fetchadd_int((p), 1) + 1)
#define	atomic_dec_int_nv(p)		(atomic_fetchadd_int((p), -1) - 1)
#define	atomic_add_int_nv(p, v)		(atomic_fetchadd_int((p), (v)) + (v))
#define	atomic_inc_long(p)		atomic_add_long((p), 1)
#define	atomic_dec_long(p)		atomic_subtract_long((p), 1)
#define	atomic_inc_long_nv(p)		(atomic_fetchadd_long((p), 1) + 1)
#define	atomic_cas_uint(p, o, n)	obsd_atomic_cas_uint((p), (o), (n))
#define	atomic_cas_ptr(p, o, n)		obsd_atomic_cas_ptr((void *)(p), (void *)(o), (void *)(n))
#define	atomic_setbits_int(p, b)	atomic_set_int((p), (b))
#define	atomic_clearbits_int(p, b)	atomic_clear_int((p), (b))
#define	membar_producer()		atomic_thread_fence_rel()
#define	membar_consumer()		atomic_thread_fence_acq()
#define	membar_sync()			atomic_thread_fence_seq_cst()

static __inline u_int
obsd_atomic_cas_uint(volatile u_int *p, u_int o, u_int n)
{
	u_int old = o;

	atomic_fcmpset_int(p, &old, n);
	return (old);
}
static __inline void *
obsd_atomic_cas_ptr(void *p, void *o, void *n)
{
	uintptr_t old = (uintptr_t)o;

	atomic_fcmpset_ptr((volatile uintptr_t *)p, &old, (uintptr_t)n);
	return ((void *)old);
}

#define	imax(a, b)	max((a), (b))
#define	imin(a, b)	min((a), (b))

/* Debug log helpers.  log() exists in 5BSD with the same signature. */
#define	addlog		printf

#define	splassert_fail(want, have, func)				\
	panic("%s: lock assertion failed (want %d have %d)", (func),	\
	    (int)(want), (int)(have))

#define	KERNEL_LOCK()		do { } while (0)
#define	KERNEL_UNLOCK()		do { } while (0)
#define	KERNEL_ASSERT_LOCKED()	do { } while (0)

/*
 * The OpenBSD network lock serialises the stack.  5BSD protects
 * networking objects with the net epoch and per-object locks; pf provides
 * its own locks, so NET_LOCK only serialises pf configuration paths.
 */
extern struct sx obsd_net_lock;
#define	NET_LOCK()		sx_xlock(&obsd_net_lock)
#define	NET_UNLOCK()		sx_xunlock(&obsd_net_lock)
#define	NET_LOCK_SHARED()	sx_slock(&obsd_net_lock)
#define	NET_UNLOCK_SHARED()	sx_sunlock(&obsd_net_lock)
#define	NET_ASSERT_LOCKED()	do { } while (0)
#define	NET_ASSERT_LOCKED_EXCLUSIVE()	do { } while (0)

/* Interrupt priority levels are meaningless here. */
#define	IPL_NONE	0
#define	IPL_SOFTNET	1
#define	IPL_NET		2
#define	IPL_MPFLOOR	3
#define	IPL_MPSAFE	0
#define	splsoftnet()	0
#define	splnet()	0
#define	splx(s)		do { (void)(s); } while (0)

/* ------------------------------------------------------------------ */
/* Locks                                                               */
/* ------------------------------------------------------------------ */

/*
 * OpenBSD rwlock -> 5BSD rwlock (adaptive, not sleepable).  The pf
 * packet path runs inside the net epoch from pfil hooks, so the pf locks
 * must not sleep.  Statically initialised locks (RWLOCK_INITIALIZER) are
 * set up by the glue at module load.
 */
#define	RW_WRITE	0x0001UL
#define	RW_READ		0x0002UL
#define	RW_DOWNGRADE	0x0004UL
#define	RW_OPMASK	0x0007UL
#define	RW_INTR		0x0010UL
#define	RW_SLEEPFAIL	0x0020UL
#define	RW_NOSLEEP	0x0040UL
#define	RWLOCK_INITIALIZER(name)	{ .lock_object = { .lo_name = (name) } }

/*
 * OpenBSD rwlocks are sleepable.  Locks taken on the packet path (pf_lock,
 * pf_state_lock) are 5BSD rwlocks; locks only taken in ioctl and task
 * context that sleep while held (pfioctl_rw, the state list lock, pflow
 * and pfsync configuration locks) are declared struct sx in the vendor
 * files ("5BSD: sleepable").  These macros dispatch on the lock type.
 */
#define	_OBSD_RW(l, sxop, rwop)						\
	_Generic((l),							\
	    struct sx *: sxop((struct sx *)(l)),			\
	    default: rwop((struct rwlock *)(l)))
#undef	rw_init
#define	rw_init(l, name)						\
	_Generic((l),							\
	    struct sx *: sx_init_flags((struct sx *)(l), (name), SX_NEW | SX_DUPOK), \
	    default: rw_init_flags((struct rwlock *)(l), (name), RW_NEW | RW_DUPOK))
#define	rw_enter_write(l)	_OBSD_RW(l, sx_xlock, rw_wlock)
#define	rw_exit_write(l)	_OBSD_RW(l, sx_xunlock, rw_wunlock)
#define	rw_enter_read(l)	_OBSD_RW(l, sx_slock, rw_rlock)
#define	rw_exit_read(l)		_OBSD_RW(l, sx_sunlock, rw_runlock)
#define	rw_exit(l)		_OBSD_RW(l, sx_unlock, rw_unlock)
#define	_obsd_sx_assert_w(l)	sx_assert((l), SA_XLOCKED)
#define	_obsd_rw_assert_w(l)	rw_assert((l), RA_WLOCKED)
#define	_obsd_sx_assert_r(l)	sx_assert((l), SA_SLOCKED)
#define	_obsd_rw_assert_r(l)	rw_assert((l), RA_RLOCKED)
#define	_obsd_sx_assert_a(l)	sx_assert((l), SA_LOCKED)
#define	_obsd_rw_assert_a(l)	rw_assert((l), RA_LOCKED)
#define	_obsd_sx_assert_u(l)	sx_assert((l), SA_UNLOCKED)
#define	_obsd_rw_assert_u(l)	rw_assert((l), RA_UNLOCKED)
#define	rw_assert_wrlock(l)	_OBSD_RW(l, _obsd_sx_assert_w, _obsd_rw_assert_w)
#define	rw_assert_rdlock(l)	_OBSD_RW(l, _obsd_sx_assert_r, _obsd_rw_assert_r)
#define	rw_assert_anylock(l)	_OBSD_RW(l, _obsd_sx_assert_a, _obsd_rw_assert_a)
#define	rw_assert_unlocked(l)	_OBSD_RW(l, _obsd_sx_assert_u, _obsd_rw_assert_u)
static __inline int
obsd_rw_enter(struct rwlock *rw, u_long flags)
{
	switch (flags & RW_OPMASK) {
	case RW_WRITE:
		if (flags & RW_NOSLEEP)
			return (rw_try_wlock(rw) ? 0 : EBUSY);
		rw_wlock(rw);
		break;
	case RW_READ:
		if (flags & RW_NOSLEEP)
			return (rw_try_rlock(rw) ? 0 : EBUSY);
		rw_rlock(rw);
		break;
	case RW_DOWNGRADE:
		rw_downgrade(rw);
		break;
	}
	return (0);
}
static __inline int
obsd_sx_enter(struct sx *sx, u_long flags)
{
	switch (flags & RW_OPMASK) {
	case RW_WRITE:
		if (flags & RW_NOSLEEP)
			return (sx_try_xlock(sx) ? 0 : EBUSY);
		if (flags & RW_INTR)
			return (sx_xlock_sig(sx));
		sx_xlock(sx);
		break;
	case RW_READ:
		if (flags & RW_NOSLEEP)
			return (sx_try_slock(sx) ? 0 : EBUSY);
		if (flags & RW_INTR)
			return (sx_slock_sig(sx));
		sx_slock(sx);
		break;
	case RW_DOWNGRADE:
		sx_downgrade(sx);
		break;
	}
	return (0);
}
#define	rw_enter(l, f)							\
	_Generic((l),							\
	    struct sx *: obsd_sx_enter((struct sx *)(l), (f)),		\
	    default: obsd_rw_enter((struct rwlock *)(l), (f)))
static __inline int
obsd_rw_status(struct rwlock *rw)
{
	return (rw_wowned(rw) ? RW_WRITE : 0);
}
static __inline int
obsd_sx_status(struct sx *sx)
{
	return (sx_xlocked(sx) ? RW_WRITE : 0);
}
#define	rw_status(l)							\
	_Generic((l),							\
	    struct sx *: obsd_sx_status((struct sx *)(l)),		\
	    default: obsd_rw_status((struct rwlock *)(l)))

/* OpenBSD struct mutex -> 5BSD default mutex. */
struct mutex {
	struct mtx	mtx;
};
#define	MUTEX_INITIALIZER(ipl)		{ }
#define	MUTEX_INITIALIZER_FLAGS(i, n, f)	{ }
#undef	mtx_init
#define	mtx_init(m, ipl)	mtx_init_flags((m), (ipl), #m, 0)
#define	mtx_init_flags(m, ipl, name, f)					\
	_mtx_init(&(m)->mtx.mtx_lock, (name), NULL,			\
	    MTX_DEF | MTX_NEW | MTX_DUPOK)
#define	mtx_enter(m)		mtx_lock(&(m)->mtx)
#define	mtx_leave(m)		mtx_unlock(&(m)->mtx)
#define	mtx_enter_try(m)	mtx_trylock(&(m)->mtx)
#define	MUTEX_ASSERT_LOCKED(m)	mtx_assert(&(m)->mtx, MA_OWNED)
#define	MUTEX_ASSERT_UNLOCKED(m) mtx_assert(&(m)->mtx, MA_NOTOWNED)

/* Producer/consumer lock (sys/pclock.h): sequence counter + mutex. */
struct pc_lock {
	volatile u_int	pcl_gen;
	struct mtx	pcl_mtx;
};
#define	PC_LOCK_INITIALIZER()	{ }
static __inline void
pc_lock_init(struct pc_lock *pcl)
{
	pcl->pcl_gen = 0;
	_mtx_init(&pcl->pcl_mtx.mtx_lock, "pf pclock", NULL,
	    MTX_DEF | MTX_NEW | MTX_DUPOK);
}
static __inline unsigned int
pc_sprod_enter(struct pc_lock *pcl)
{
	mtx_lock(&pcl->pcl_mtx);
	atomic_add_rel_int(&pcl->pcl_gen, 1);
	return (pcl->pcl_gen);
}
static __inline void
pc_sprod_leave(struct pc_lock *pcl, unsigned int gen)
{
	atomic_add_rel_int(&pcl->pcl_gen, 1);
	mtx_unlock(&pcl->pcl_mtx);
}
#define	pc_mprod_enter(pcl)		pc_sprod_enter(pcl)
#define	pc_mprod_leave(pcl, g)		pc_sprod_leave((pcl), (g))
static __inline void
pc_cons_enter(struct pc_lock *pcl, unsigned int *genp)
{
	unsigned int gen;

	while ((gen = atomic_load_acq_int(&pcl->pcl_gen)) & 1)
		cpu_spinwait();
	*genp = gen;
}
static __inline int
pc_cons_leave(struct pc_lock *pcl, unsigned int *genp)
{
	unsigned int gen;

	atomic_thread_fence_acq();
	gen = atomic_load_int(&pcl->pcl_gen);
	if (gen == *genp)
		return (0);
	while ((gen = atomic_load_acq_int(&pcl->pcl_gen)) & 1)
		cpu_spinwait();
	*genp = gen;
	return (1);
}

/* ------------------------------------------------------------------ */
/* Reference counts (sys/refcnt.h)                                     */
/* ------------------------------------------------------------------ */

struct refcnt {
	volatile u_int	r_refs;
};
#define	REFCNT_INITIALIZER()	{ .r_refs = 1 }
static __inline void
refcnt_init(struct refcnt *r)
{
	r->r_refs = 1;
}
static __inline void
refcnt_init_trace(struct refcnt *r, int id)
{
	r->r_refs = 1;
}
static __inline void
refcnt_take(struct refcnt *r)
{
	refcount_acquire(&r->r_refs);
}
static __inline int
refcnt_rele(struct refcnt *r)
{
	return (refcount_release(&r->r_refs));
}
static __inline u_int
refcnt_read(struct refcnt *r)
{
	return (refcount_load(&r->r_refs));
}
void	refcnt_rele_wake(struct refcnt *);
void	refcnt_finalize(struct refcnt *, const char *);
int	refcnt_shared(struct refcnt *);

/* ------------------------------------------------------------------ */
/* Memory: malloc(9) types and pool(9)                                 */
/* ------------------------------------------------------------------ */

MALLOC_DECLARE(M_PF);
/*
 * OpenBSD M_WAITOK|M_CANFAIL may sleep and the caller handles failure.
 * pf's own locks are not sleepable here, so such an allocation made with
 * one of them held does not sleep (and may fail).
 */
#define	M_CANFAIL	0x40000000
int	obsd_pf_nosleep(void);
static __inline int
obsd_malloc_flags(int flags)
{
	if (flags & M_CANFAIL) {
		flags &= ~M_CANFAIL;
		if ((flags & M_WAITOK) && obsd_pf_nosleep())
			flags = (flags & ~M_WAITOK) | M_NOWAIT;
	}
	return (flags);
}
#ifndef OPENBSD_PF_GLUE
#undef	malloc
#define	malloc(s, t, f)		(malloc)((s), (t), obsd_malloc_flags(f))
#undef	mallocarray
#define	mallocarray(n, s, t, f)	(mallocarray)((n), (s), (t), obsd_malloc_flags(f))
#endif
#define	M_IFADDR	M_PF
#define	M_IFGROUP	M_PF
#define	M_IPOPTS	M_PF
#define	M_RTABLE	M_PF

#ifndef OPENBSD_PF_GLUE
/* OpenBSD free(9) takes the allocation size as a third argument. */
#define	free(p, t, s)	free((p), (t))
#define	freezero(p, s)	zfree((p), M_PF)
#endif

#define	PR_WAITOK	0x0001
#define	PR_NOWAIT	0x0002
#define	PR_LIMITFAIL	0x0004
#define	PR_ZERO		0x0008
#define	PR_RWLOCK	0x0010

struct pool {
	uma_zone_t	pr_zone;
	const char	*pr_wchan;
	size_t		pr_size;
	u_int		pr_hardlimit;
	volatile u_int	pr_nout;
	u_long		pr_nget;
	u_long		pr_nfail;
	u_long		pr_nput;
};
typedef struct pool pool_t;

void	pool_init(struct pool *, size_t, u_int, int, int, const char *, void *);
void	pool_destroy(struct pool *);
void	*pool_get(struct pool *, int);
void	pool_put(struct pool *, void *);
int	pool_sethardlimit(struct pool *, u_int);
#define	pool_sethiwat(pp, n)		do { } while (0)
#define	pool_setlowat(pp, n)		do { } while (0)
#define	pool_cache_init(pp)		do { } while (0)
#define	pool_setipl(pp, ipl)		do { } while (0)

/* ------------------------------------------------------------------ */
/* Per-CPU memory and counters (sys/percpu.h)                          */
/* ------------------------------------------------------------------ */

struct cpumem {
	void	*cm_mem[MAXCPU];
	size_t	cm_sz;
};
struct cpumem_iter {
	int	cmi_cpu;
};
struct cpumem	*cpumem_malloc(size_t, struct malloc_type *);
void		 cpumem_free(struct cpumem *, struct malloc_type *, size_t);
void		*cpumem_first(struct cpumem_iter *, struct cpumem *);
void		*cpumem_next(struct cpumem_iter *, struct cpumem *);
static __inline void *
cpumem_enter(struct cpumem *cm)
{
	sched_pin();
	return (cm->cm_mem[PCPU_GET(cpuid)]);
}
static __inline void
cpumem_leave(struct cpumem *cm, void *p)
{
	sched_unpin();
}
#define	CPUMEM_FOREACH(_v, _i, _cm)					\
	for ((_v) = cpumem_first((_i), (_cm)); (_v) != NULL;		\
	    (_v) = cpumem_next((_i), (_cm)))

struct cpumem	*counters_alloc(unsigned int);
void		 counters_free(struct cpumem *, unsigned int);
void		 counters_read(struct cpumem *, uint64_t *, unsigned int,
		    uint64_t *);
void		 counters_zero(struct cpumem *, unsigned int);
void		 counters_add(struct cpumem *, unsigned int, uint64_t);
static __inline void
obsd_counters_inc(struct cpumem *cm, unsigned int c)
{
	counters_add(cm, c, 1);
}
static __inline void
obsd_counters_pkt(struct cpumem *cm, unsigned int c, unsigned int b,
    uint64_t v)
{
	counters_add(cm, c, 1);
	counters_add(cm, b, v);
}
/* ifnet counters: OpenBSD if_counters vs 5BSD counter(9) array */
static __inline void
obsd_ifcounters_inc(counter_u64_t *ic, unsigned int c)
{
	counter_u64_add(ic[c], 1);
}
static __inline void
obsd_ifcounters_pkt(counter_u64_t *ic, unsigned int c, unsigned int b,
    uint64_t v)
{
	counter_u64_add(ic[c], 1);
	counter_u64_add(ic[b], v);
}
#define	counters_inc(cm, c)						\
	_Generic((cm), struct cpumem *: obsd_counters_inc,		\
	    default: obsd_ifcounters_inc)((cm), (c))
#define	counters_pkt(cm, c, b, v)					\
	_Generic((cm), struct cpumem *: obsd_counters_pkt,		\
	    default: obsd_ifcounters_pkt)((cm), (c), (b), (v))
#define	ifc_ipackets	IFCOUNTER_IPACKETS
#define	ifc_ierrors	IFCOUNTER_IERRORS
#define	ifc_opackets	IFCOUNTER_OPACKETS
#define	ifc_oerrors	IFCOUNTER_OERRORS
#define	ifc_collisions	IFCOUNTER_COLLISIONS
#define	ifc_ibytes	IFCOUNTER_IBYTES
#define	ifc_obytes	IFCOUNTER_OBYTES
#define	ifc_imcasts	IFCOUNTER_IMCASTS
#define	ifc_omcasts	IFCOUNTER_OMCASTS
#define	ifc_iqdrops	IFCOUNTER_IQDROPS
#define	ifc_oqdrops	IFCOUNTER_OQDROPS
#define	ifc_noproto	IFCOUNTER_NOPROTO

/* ------------------------------------------------------------------ */
/* Timeouts (sys/timeout.h) and tasks (sys/task.h)                     */
/* ------------------------------------------------------------------ */

/*
 * OpenBSD timeouts run in a thread context and pf's handlers take locks
 * that may block; here a callout only queues the handler on the pf
 * taskqueue thread.
 */
struct timeout {
	void			(*to_func)(void *);
	void			*to_arg;
	struct vnet		*to_vnet;	/* vnet of the last timeout_add */
	int			 to_flags;
	volatile int		 to_initialized;
	struct callout		 to_callout;
	struct __fbsd_task	 to_task;
};
#define	TIMEOUT_PROC		0x01
#define	TIMEOUT_INITIALIZER(_f, _a)	{ .to_func = (_f), .to_arg = (_a) }
#define	TIMEOUT_INITIALIZER_FLAGS(_f, _a, _k, _fl)	\
	{ .to_func = (_f), .to_arg = (_a), .to_flags = (_fl) }

void	timeout_set(struct timeout *, void (*)(void *), void *);
#define	timeout_set_proc(to, f, a)	timeout_set((to), (f), (a))
#define	timeout_set_flags(to, f, a, k, fl)	timeout_set((to), (f), (a))
int	timeout_add(struct timeout *, int);
int	timeout_add_sec(struct timeout *, int);
int	timeout_add_msec(struct timeout *, uint64_t);
int	timeout_add_usec(struct timeout *, uint64_t);
int	timeout_add_nsec(struct timeout *, uint64_t);
int	timeout_del(struct timeout *);
int	timeout_del_barrier(struct timeout *);
void	timeout_barrier(struct timeout *);
int	timeout_pending(struct timeout *);
int	timeout_initialized(struct timeout *);

struct taskq;
struct task {
	void			(*t_func)(void *);
	void			*t_arg;
	struct vnet		*t_vnet;	/* vnet of the last task_add */
	volatile int		 t_initialized;
	struct __fbsd_task	 t_task;
};
#define	TASK_INITIALIZER(_f, _a)	{ .t_func = (_f), .t_arg = (_a) }
void	task_set(struct task *, void (*)(void *), void *);
int	task_add(struct taskq *, struct task *);
int	task_del(struct taskq *, struct task *);
void	taskq_barrier(struct taskq *);
void	taskq_del_barrier(struct taskq *, struct task *);
int	task_pending(struct task *);
extern struct taskq *const systq;
extern struct taskq *const systqmp;
struct taskq *net_tq(unsigned int);
void	net_tq_barriers(const char *);

/* ------------------------------------------------------------------ */
/* SMR (sys/smr.h): the pf users only need an RCU-like read section.   */
/* ------------------------------------------------------------------ */

struct smr_entry {
	struct epoch_context	smr_ctx;
	void			(*smr_func)(void *);
	void			*smr_arg;
};
void	smr_read_enter(void);
void	smr_read_leave(void);
void	smr_barrier(void);
void	smr_init(struct smr_entry *);
void	smr_call(struct smr_entry *, void (*)(void *), void *);
#define	SMR_ASSERT_CRITICAL()	do { } while (0)
#define	SMR_PTR_GET(pptr)		atomic_load_ptr(pptr)
#define	SMR_PTR_GET_LOCKED(pptr)	(*(pptr))
#define	SMR_PTR_SET_LOCKED(pptr, v)	atomic_store_rel_ptr((volatile uintptr_t *)(pptr), (uintptr_t)(v))
#define	SMR_SLIST_HEAD(name, type)	SLIST_HEAD(name, type)
#define	SMR_SLIST_ENTRY(type)		SLIST_ENTRY(type)
#define	SMR_SLIST_INIT(h)		SLIST_INIT(h)
#define	SMR_SLIST_FOREACH(v, h, f)	SLIST_FOREACH(v, h, f)
#define	SMR_SLIST_INSERT_HEAD_LOCKED(h, e, f)	SLIST_INSERT_HEAD(h, e, f)
#define	SMR_SLIST_REMOVE_LOCKED(h, e, t, f)	SLIST_REMOVE(h, e, t, f)

/* ------------------------------------------------------------------ */
/* Time                                                                */
/* ------------------------------------------------------------------ */

static __inline time_t
getuptime(void)
{
	return (time_uptime);
}
static __inline time_t
gettime(void)
{
	return (time_second);
}
static __inline uint64_t
getnsecuptime(void)
{
	struct timespec ts;

	getnanouptime(&ts);
	return ((uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec);
}
#define	SEC_TO_NSEC(s)		((uint64_t)(s) * 1000000000ULL)
#define	MSEC_TO_NSEC(m)		((uint64_t)(m) * 1000000ULL)
#define	USEC_TO_NSEC(u)		((uint64_t)(u) * 1000ULL)
#define	INFSLP			UINT64_MAX

/* ------------------------------------------------------------------ */
/* Privileges, processes, misc                                         */
/* ------------------------------------------------------------------ */

#define	suser(p)	priv_check(curthread, PRIV_NETINET_PF)
#define	sched_pause(f)	do { } while (0)

#define	coverage(...)	do { } while (0)

/* ------------------------------------------------------------------ */
/* OpenBSD typed red-black trees (RBT_*) on top of sys/tree.h RB_*     */
/* ------------------------------------------------------------------ */

#define	RBT_HEAD(name, type)		RB_HEAD(name, type)
#define	RBT_ENTRY(type)			RB_ENTRY(type)
#define	RBT_INITIALIZER(head)		RB_INITIALIZER(head)
#define	RBT_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE(name, type, field, cmp)
#define	RBT_GENERATE(name, type, field, cmp)				\
	RB_GENERATE(name, type, field, cmp)
#define	RBT_INIT(name, head)		RB_INIT(head)
#define	RBT_INSERT(name, head, elm)	RB_INSERT(name, head, elm)
#define	RBT_REMOVE(name, head, elm)	RB_REMOVE(name, head, elm)
#define	RBT_FIND(name, head, key)	RB_FIND(name, head, key)
#define	RBT_NFIND(name, head, key)	RB_NFIND(name, head, key)
#define	RBT_ROOT(name, head)		RB_ROOT(head)
#define	RBT_EMPTY(name, head)		RB_EMPTY(head)
#define	RBT_MIN(name, head)		RB_MIN(name, head)
#define	RBT_MAX(name, head)		RB_MAX(name, head)
#define	RBT_NEXT(name, elm)		RB_NEXT(name, NULL, elm)
#define	RBT_PREV(name, elm)		RB_PREV(name, NULL, elm)
#define	RBT_LEFT(name, elm)		RB_LEFT(elm, __rbt_field_unused)
#define	RBT_FOREACH(var, name, head)	RB_FOREACH(var, name, head)
#define	RBT_FOREACH_SAFE(var, name, head, tvar)				\
	RB_FOREACH_SAFE(var, name, head, tvar)
#define	RBT_FOREACH_REVERSE(var, name, head)				\
	RB_FOREACH_REVERSE(var, name, head)
#define	RBT_FOREACH_REVERSE_SAFE(var, name, head, tvar)			\
	RB_FOREACH_REVERSE_SAFE(var, name, head, tvar)

/* ------------------------------------------------------------------ */
/* Kernel configuration and constants                                  */
/* ------------------------------------------------------------------ */

#ifdef INVARIANTS
#ifndef DIAGNOSTIC
#define	DIAGNOSTIC
#endif
#endif

/* OpenBSD NMBCLUSTERS is a compile-time constant used in initialisers. */
#define	NMBCLUSTERS		(256 * 1024)
#define	CACHELINESIZE		CACHE_LINE_SIZE
#define	CLONE_SHIFT		8
#define	CLONE_MAPSZ		128
#define	MAXPFTABLES_OBSD	0
#define	RT_TABLEID_MAX		255
#define	RT_TABLEID_BITS		8
#define	RT_TABLEID_MASK		0xff
#define	RT_RESOLVE		0x1

#define	__IPV6_ADDR_INT32_ONE	htonl(1)
#define	__IPV6_ADDR_INT32_MLL	htonl(0xff020000)

extern long obsd_nmbclust;	/* nmbclusters, as a long */
#define	nmbclust		obsd_nmbclust
#define	IFQ_MAXPRIO		7
#define	IFQ_DEFPRIO		3

/* OpenBSD's global securelevel: use the caller's prison securelevel. */
static __inline int
obsd_securelevel(void)
{
	return (curthread->td_ucred->cr_prison->pr_securelevel);
}
#define	securelevel		obsd_securelevel()

/*
 * OpenBSD sysctl helpers.  5BSD registers pf's sysctl(9) nodes in the glue
 * (pf_sysctl.c), which calls the OpenBSD handlers with kernel buffers; these
 * copy a read-only structure into such a buffer.
 */
static __inline int
obsd_sysctl_rdstruct(void *oldp, size_t *oldlenp, void *newp, const void *sp,
    size_t len)
{
	if (newp != NULL)
		return (EPERM);
	if (oldp != NULL) {
		if (*oldlenp < len)
			return (ENOMEM);
		memcpy(oldp, sp, len);
	}
	*oldlenp = len;
	return (0);
}
#define	sysctl_rdstruct(o, ol, n, p, l)	obsd_sysctl_rdstruct((o), (ol), (n), (p), (l))
#define	sysctl_struct(o, ol, n, nl, p, l)	obsd_sysctl_rdstruct((o), (ol), (n), (p), (l))
#define	NET_PFLOW_STATS		1

/*
 * Interface send queue disciplines (OpenBSD ifq(9)).  Queue attachment to
 * 5BSD interfaces is provided by the glue (openbsd_ifq.c).
 */
struct ifq_ops;
extern const struct ifq_ops * const ifq_priq_ops;
void	obsd_ifq_attach(struct ifnet *, const struct ifq_ops *, void *);
#define	ifq_attach(ifq, ops, arg)					\
	obsd_ifq_attach(__containerof((ifq), struct ifnet, if_snd), (ops), (arg))

/* curcpu()->ci_schedstate.spc_schedflags & SPCF_SHOULDYIELD */
struct obsd_schedstate {
	int	spc_schedflags;
};
struct obsd_cpu_info {
	struct obsd_schedstate	ci_schedstate;
};
#define	SPCF_SHOULDYIELD	0x0002
#undef	curcpu
#define	curcpu()	(&(struct obsd_cpu_info){ .ci_schedstate = {	\
	.spc_schedflags = should_yield() ? SPCF_SHOULDYIELD : 0 } })

/* ------------------------------------------------------------------ */
/* mbufs                                                               */
/* ------------------------------------------------------------------ */

#define	M_DONTWAIT	M_NOWAIT
/* OpenBSD MCLGETL(): attach external storage of at least len bytes. */
struct mbuf	*obsd_mclgetl(struct mbuf *, int, u_int);
#define	MCLGETL(m, how, len)	obsd_mclgetl((m), (how), (len))
#define	ifq_purge(ifq)		do { } while (0)
#define	M_WAIT		M_WAITOK

/* OpenBSD m_copyback() may allocate and returns an error code. */
#define	m_copyback(m, off, len, cp, how)				\
	(m_copyback((m), (off), (len), (c_caddr_t)(cp)), 0)
#define	m_dup_pkt(m, extra, how)	m_dup((m), (how))
#define	m_calchdrlen(m)			m_fixhdr(m)

/* OpenBSD M_PREPEND() is an expression yielding the (new) mbuf. */
static __inline struct mbuf *
obsd_m_prepend(struct mbuf *m, int plen, int how)
{
	if (M_LEADINGSPACE(m) >= plen) {
		m->m_data -= plen;
		m->m_len += plen;
	} else
		m = m_prepend(m, plen, how);
	if (m != NULL && (m->m_flags & M_PKTHDR))
		m->m_pkthdr.len += plen;
	return (m);
}
#undef	M_PREPEND
#define	M_PREPEND(m, plen, how)	((m) = obsd_m_prepend((m), (plen), (how)))
#define	m_removehdr(m)			m_demote_pkthdr(m)

/* OpenBSD packet header fields under 5BSD names. */
#define	ph_rtableid	fibnum
#define	ph_flowid	flowid

/* Checksum flags: requests for delayed computation on output. */
#define	M_TCP_CSUM_OUT		(CSUM_IP_TCP | CSUM_IP6_TCP)
#define	M_UDP_CSUM_OUT		(CSUM_IP_UDP | CSUM_IP6_UDP)
/*
 * pf caches its own software verification in OpenBSD; here inbound
 * checksums are always verified in software (no free csum_flags bits).
 * The glue finalises delayed outbound checksums before pf_test().
 */
#define	M_TCP_CSUM_IN_OK	0
#define	M_TCP_CSUM_IN_BAD	0
#define	_Q_INVALID		((void *)-1)

/* OpenBSD packet tag types are defined in sys/mbuf.h. */


/* mbuf lists and queues (OpenBSD sys/mbuf.h). */
struct mbuf_list {
	struct mbuf	*ml_head;
	struct mbuf	*ml_tail;
	u_int		 ml_len;
};
#define	MBUF_LIST_INITIALIZER()	{ NULL, NULL, 0 }
#define	ml_len(_ml)		((_ml)->ml_len)
#define	ml_empty(_ml)		((_ml)->ml_len == 0)
#define	MBUF_LIST_FIRST(_ml)	((_ml)->ml_head)
#define	MBUF_LIST_NEXT(_m)	((_m)->m_nextpkt)
#define	MBUF_LIST_FOREACH(_ml, _m)					\
	for ((_m) = MBUF_LIST_FIRST(_ml); (_m) != NULL;			\
	    (_m) = MBUF_LIST_NEXT(_m))
void		 ml_init(struct mbuf_list *);
void		 ml_enqueue(struct mbuf_list *, struct mbuf *);
struct mbuf	*ml_dequeue(struct mbuf_list *);
void		 ml_enlist(struct mbuf_list *, struct mbuf_list *);
struct mbuf	*ml_dechain(struct mbuf_list *);
unsigned int	 ml_purge(struct mbuf_list *);
unsigned int	 ml_hdatalen(struct mbuf_list *);

struct mbuf_queue {
	struct mutex		mq_mtx;
	struct mbuf_list	mq_list;
	u_int			mq_maxlen;
	u_int			mq_drops;
};
void		 mq_init(struct mbuf_queue *, u_int, int);
int		 mq_push(struct mbuf_queue *, struct mbuf *);
int		 mq_enqueue(struct mbuf_queue *, struct mbuf *);
struct mbuf	*mq_dequeue(struct mbuf_queue *);
int		 mq_enlist(struct mbuf_queue *, struct mbuf_list *);
void		 mq_delist(struct mbuf_queue *, struct mbuf_list *);
unsigned int	 mq_purge(struct mbuf_queue *);
unsigned int	 mq_hdatalen(struct mbuf_queue *);
void		 mq_set_maxlen(struct mbuf_queue *, u_int);
#define	mq_len(_mq)		READ_ONCE((_mq)->mq_list.ml_len)
#define	mq_empty(_mq)		(mq_len(_mq) == 0)
#define	mq_full(_mq)		(mq_len((_mq)) >= READ_ONCE((_mq)->mq_maxlen))
#define	mq_drops(_mq)		READ_ONCE((_mq)->mq_drops)

/* ------------------------------------------------------------------ */
/* Interfaces                                                          */
/* ------------------------------------------------------------------ */

struct ifnet	*if_get(unsigned int);
void		 if_put(struct ifnet *);
void		 if_addrhook_add(struct ifnet *, struct task *);
void		 if_addrhook_del(struct ifnet *, struct task *);
void		 if_detachhook_add(struct ifnet *, struct task *);
void		 if_detachhook_del(struct ifnet *, struct task *);
void		 if_linkstatehook_add(struct ifnet *, struct task *);
void		 if_linkstatehook_del(struct ifnet *, struct task *);
#define	if_get_smr(idx)		ifnet_byindex(idx)

/* OpenBSD ifnet fields and flags without a 5BSD equivalent. */
#define	if_xflags		if_ispare[0]
#define	IFXF_CLONED		0x0001
#define	IFXF_MPSAFE		0x0002
#define	IFF_RUNNING		IFF_DRV_RUNNING	/* kept in if_flags */
#define	LINK_STATE_IS_UP(s)	((s) == LINK_STATE_UP)
#define	if_alloc_sadl(ifp)	do { } while (0)
#define	if_counters_alloc(ifp)	do { } while (0)
void	obsd_if_attach(struct ifnet *);
void	obsd_if_detach(struct ifnet *);
#define	if_attach(ifp)		obsd_if_attach(ifp)
#define	if_detach(ifp)		obsd_if_detach(ifp)

#define	IFT_PFLOW		0xf9
#define	if_rdomain		if_fib


/* Multicast membership (OpenBSD in_addmulti/in_delmulti). */
struct in_multi	*obsd_in_addmulti(struct in_addr *, struct ifnet *);
void		 obsd_in_delmulti(struct in_multi *);
#define	in_addmulti(a, ifp)	obsd_in_addmulti((a), (ifp))
#define	in_delmulti(inm)	obsd_in_delmulti(inm)

/* OpenBSD struct ip_moptions as used by pfsync (index, ttl, loop). */
struct obsd_ip_moptions {
	u_int		imo_ifidx;
	u_int8_t	imo_ttl;
	u_int8_t	imo_loop;
};
#define	ip_moptions	obsd_ip_moptions
#define	IFT_PFSYNC_OBSD		IFT_PFSYNC
#ifndef ifr_data
#define	ifr_data		ifr_ifru.ifru_data
#endif

/* Kernel sockets with OpenBSD calling conventions (name in an mbuf). */
int	obsd_socreate(int, struct socket **, int, int);
int	obsd_sobind(struct socket *, struct mbuf *);
int	obsd_sosend(struct socket *, struct mbuf *, struct uio *,
	    struct mbuf *, struct mbuf *, int);
#define	socreate(d, aso, t, p)	obsd_socreate((d), (aso), (t), (p))
#define	sobind(so, nam, p)	obsd_sobind((so), (nam))
#define	soclose(so, flags)	soclose(so)
#define	sosend(so, nam, uio, top, ctl, flags)				\
	obsd_sosend((so), (nam), (uio), (top), (ctl), (flags))
#define	solock(so)		do { } while (0)
#define	sounlock(so)		do { } while (0)
#define	solock_shared(so)	do { } while (0)
#define	sounlock_shared(so)	do { } while (0)

/* OpenBSD interface cloners (if_clone_attach of a static cloner). */
struct obsd_if_clone {
	const char	*ifc_name;
	int		(*ifc_create)(struct obsd_if_clone *, int);
	int		(*ifc_destroy)(struct ifnet *);
};
#define	if_clone	obsd_if_clone
#define	IF_CLONE_INITIALIZER(name, create, destroy)			\
	{ .ifc_name = (name), .ifc_create = (create),			\
	  .ifc_destroy = (destroy) }
void	obsd_if_clone_attach(struct obsd_if_clone *);
void	obsd_if_clone_detach(struct obsd_if_clone *);
#define	if_clone_attach(ifc)	obsd_if_clone_attach(ifc)
#define	if_clone_detach(ifc)	obsd_if_clone_detach(ifc)

/* bpf(4) with OpenBSD's caddr_t interface handle */
#define	BPF_DIRECTION_IN	1
#define	BPF_DIRECTION_OUT	2
#undef	bpfattach
#define	bpfattach(bpfp, ifp, dlt, hlen)	bpfattach((ifp), (dlt), (hlen))
#define	bpf_mtap_hdr(bpf, hdr, hlen, m, dir)				\
	(bpf_mtap2((struct bpf_if *)(bpf), (void *)(hdr), (hlen), (m)), 0)
#define	if_unit(name)		ifunit_ref(name)
#define	IFG_ALL_OBSD		"all"

/* ------------------------------------------------------------------ */
/* Routing (OpenBSD net/route.h, net/rtable.h) on 5BSD FIBs/nexthops   */
/* ------------------------------------------------------------------ */

/*
 * The result of an OpenBSD rtalloc(): a referenced 5BSD nexthop plus the
 * fields pf reads.  Routing domains map onto FIB numbers.
 */
struct obsd_rtentry {
	struct nhop_object	*rt_nh;
	struct ifaddr		*rt_ifa;
	u_int			 rt_ifidx;
	u_int			 rt_flags;
	u_int16_t		 rt_labelid;
	struct sockaddr_storage	 rt_gwbuf;
};
#define	rtentry		obsd_rtentry
struct rtentry	*rtalloc(struct sockaddr *, int, unsigned int);
struct rtentry	*rtalloc_mpath(struct sockaddr *, uint32_t *, unsigned int);
struct rtentry	*rtable_iterate(struct rtentry *);
void		 rtfree(struct rtentry *);
int		 rtisvalid(struct rtentry *);
int		 rtable_exists(unsigned int);
unsigned int	 rtable_l2(unsigned int);

#define	sintosa(sin)	((struct sockaddr *)(sin))
#define	sin6tosa(sin6)	((struct sockaddr *)(sin6))
#define	sstosa(ss)	((struct sockaddr *)(ss))
#define	satosin(sa)	((struct sockaddr_in *)(sa))
#define	satosin6(sa)	((struct sockaddr_in6 *)(sa))

/* ------------------------------------------------------------------ */
/* IP layer entry points with OpenBSD signatures (glue/openbsd_net.c)  */
/* ------------------------------------------------------------------ */

#define	IP_FORWARDING		0x1
#define	IP_FORWARDING_IPSEC	0x2
/* IPV6_FORWARDING is an ip6_output() flag on 5BSD; only used as a bit. */
#define	IPV6_FORWARDING_IPSEC	0x8000
#define	ip_forwarding		V_ipforwarding
#define	ip6_forwarding		V_ip6_forwarding
#define	ipstat_inc(c)		IPSTAT_INC(c)
#define	ip6stat_inc(c)		IP6STAT_INC(c)
#define	tcpstat_inc(c)		TCPSTAT_INC(c)
#define	ip_randomid()		((u_int16_t)arc4random())
#ifndef timersub
#define	timersub(tvp, uvp, vvp)	do {					\
	(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;			\
	(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;		\
	if ((vvp)->tv_usec < 0) {					\
		(vvp)->tv_sec--;					\
		(vvp)->tv_usec += 1000000;				\
	}								\
} while (0)
#endif
#define	tcps_inswcsum		tcps_rcvtotal
#define	if_congested()		0
extern int obsd_ipmultipath, obsd_ip6_multipath, obsd_ip_directedbcast;
#define	ipmultipath		obsd_ipmultipath
#define	ip6_multipath		obsd_ip6_multipath
#define	ip_directedbcast	obsd_ip_directedbcast
#define	IP_REDIRECT		0x8000
#define	IPV6_REDIRECT		0x8000
#ifndef IN_CLASSA_NSHIFT
#define	IN_CLASSA_NSHIFT	24
#endif
#ifndef IN_LOOPBACKNET
#define	IN_LOOPBACKNET		127
#endif
u_int16_t	stoeplitz_n32(u_int32_t);
#define	ip_mtudisc		V_path_mtu_discovery
#define	ip_defttl		V_ip_defttl
#define	ip6_defhlim		V_ip6_defhlim
extern u_int32_t obsd_tcp_iss;
#define	tcp_iss			obsd_tcp_iss
#define	in_hdr_cksum_out(m, ifp)	obsd_in_hdr_cksum_out(m)
void	obsd_in_hdr_cksum_out(struct mbuf *);

/* OpenBSD SHA2 API (crypto/sha2.h) */
typedef SHA512_CTX	SHA2_CTX;
#define	SHA512Init(c)		SHA512_Init(c)
#define	SHA512Update(c, p, l)	SHA512_Update((c), (p), (l))
#define	SHA512Final(d, c)	SHA512_Final((d), (c))

int	obsd_ip_output(struct mbuf *, struct mbuf *, struct route *, int,
	    struct obsd_ip_moptions *, struct inpcb *, u_int32_t);
#define	ip_output(m, opt, ro, flags, imo, inp, ipsec)			\
	obsd_ip_output((m), (opt), (ro), (flags), (imo), (inp), (ipsec))
#ifdef INET6
int	obsd_ip6_output(struct mbuf *, struct ip6_pktopts *, struct route_in6 *,
	    int, struct ip6_moptions *, struct inpcb *);
#define	ip6_output(m, opt, ro, flags, im6o, inp)			\
	obsd_ip6_output((m), (opt), (ro), (flags), (im6o), (inp))
#endif
void	obsd_ip_forward(struct mbuf *, struct ifnet *, struct route *, int);
#define	ip_forward(m, ifp, ro, flags)	obsd_ip_forward((m), (ifp), (ro), (flags))
void	obsd_ip6_forward(struct mbuf *, struct route_in6 *, int);
#define	ip6_forward(m, ro, flags)	obsd_ip6_forward((m), (ro), (flags))
void	ip_send(struct mbuf *);
void	ip6_send(struct mbuf *);
void	obsd_icmp_error(struct mbuf *, int, int, u_int32_t, int);
#define	icmp_error(m, t, c, d, mtu)	obsd_icmp_error((m), (t), (c), (d), (mtu))
void	obsd_icmp6_error(struct mbuf *, int, int, int);
#define	icmp6_error(m, t, c, p)		obsd_icmp6_error((m), (t), (c), (p))
int	obsd_ip_fragment(struct mbuf *, struct mbuf_list *, struct ifnet *, u_long);
#define	ip_fragment(m, ml, ifp, mtu)	obsd_ip_fragment((m), (ml), (ifp), (mtu))
int	obsd_ip6_fragment(struct mbuf *, struct mbuf_list *, int, u_char, u_long);
#define	ip6_fragment(m, ml, hl, p, mtu)	obsd_ip6_fragment((m), (ml), (hl), (p), (mtu))
int	if_output_tso(struct ifnet *, struct mbuf **, struct sockaddr *,
	    struct rtentry *, u_int);
int	if_output_ml(struct ifnet *, struct mbuf_list *, struct sockaddr *,
	    struct rtentry *);
int	if_output_obsd(struct ifnet *, struct mbuf *, struct sockaddr *,
	    struct rtentry *);
int	if_enqueue(struct ifnet *, struct mbuf *);
void	in_proto_cksum_out(struct mbuf *, struct ifnet *);
void	in6_proto_cksum_out(struct mbuf *, struct ifnet *);
int	frag6_deletefraghdr(struct mbuf *, int);
int	obsd_in4_cksum(struct mbuf *, u_int8_t, int, int);
#define	in4_cksum	obsd_in4_cksum
void	divert_packet(struct mbuf *, int, u_int16_t);
void	divert6_packet(struct mbuf *, int, u_int16_t);

/* inpcb lookups (OpenBSD signatures, referenced result) */
struct inpcbtable;
extern struct inpcbtable *const obsd_tcbtable, *const obsd_udbtable,
    *const obsd_tcb6table, *const obsd_udb6table;
#define	tcbtable	(*obsd_tcbtable)
#define	udbtable	(*obsd_udbtable)
#define	tcb6table	(*obsd_tcb6table)
#define	udb6table	(*obsd_udb6table)
struct inpcb *obsd_in_pcblookup(struct inpcbtable *, struct in_addr, u_int,
	    struct in_addr, u_int, u_int);
struct inpcb *obsd_in_pcblookup_listen(struct inpcbtable *, struct in_addr,
	    u_int, struct mbuf *, u_int);
struct inpcb *obsd_in6_pcblookup(struct inpcbtable *, const struct in6_addr *,
	    u_int, const struct in6_addr *, u_int, u_int);
struct inpcb *obsd_in6_pcblookup_listen(struct inpcbtable *, struct in6_addr *,
	    u_int, struct mbuf *, u_int);
#define	in_pcblookup(t, fa, fp, la, lp, r)	obsd_in_pcblookup((t), (fa), (fp), (la), (lp), (r))
#define	in_pcblookup_listen(t, la, lp, m, r)	obsd_in_pcblookup_listen((t), (la), (lp), (m), (r))
#define	in6_pcblookup(t, fa, fp, la, lp, r)	obsd_in6_pcblookup((t), (fa), (fp), (la), (lp), (r))
#define	in6_pcblookup_listen(t, la, lp, m, r)	obsd_in6_pcblookup_listen((t), (la), (lp), (m), (r))
#undef	in_pcbref
#define	in_pcbref(inp)		obsd_in_pcbref(inp)
#define	in_pcbunref(inp)	obsd_in_pcbunref(inp)
struct inpcb	*obsd_in_pcbref(struct inpcb *);
void		 obsd_in_pcbunref(struct inpcb *);

/* struct socket credentials under their OpenBSD names */
#define	so_euid		so_cred->cr_uid
/* 5BSD jail extension: the jail (prison id) of a socket. */
#define	PF_SO_JID(so)	((int32_t)(so)->so_cred->cr_prison->pr_id)
#define	so_egid		so_cred->cr_gid

/* ------------------------------------------------------------------ */
/* DTrace: SDT probes of OpenBSD PF (defined in pf_sdt.c)              */
/* ------------------------------------------------------------------ */
#include <sys/sdt.h>
SDT_PROVIDER_DECLARE(pf);
SDT_PROBE_DECLARE(pf, , reason, set);
SDT_PROBE_DECLARE(pf, frag, reassemble, entry);
SDT_PROBE_DECLARE(pf, frag, reassemble6, entry);
SDT_PROBE_DECLARE(pf, ioctl, ioctl, entry);
SDT_PROBE_DECLARE(pf, ioctl, ioctl, return);
SDT_PROBE_DECLARE(pf, ioctl, xact, begin);
SDT_PROBE_DECLARE(pf, ioctl, xact, commit);
SDT_PROBE_DECLARE(pf, ioctl, xact, rollback);
SDT_PROBE_DECLARE(pf, ip, anchor, enter);
SDT_PROBE_DECLARE(pf, ip, route_to, entry);
SDT_PROBE_DECLARE(pf, ip, rules, entry);
SDT_PROBE_DECLARE(pf, ip, test, entry);
SDT_PROBE_DECLARE(pf, ip, test, finish);
SDT_PROBE_DECLARE(pf, ip6, route_to, entry);
SDT_PROBE_DECLARE(pf, log, pflog, packet);
SDT_PROBE_DECLARE(pf, nat, af_to, translate);
SDT_PROBE_DECLARE(pf, nat, transaddr, entry);
SDT_PROBE_DECLARE(pf, pflow, flow, export);
SDT_PROBE_DECLARE(pf, pfsync, packet, input);
SDT_PROBE_DECLARE(pf, pfsync, packet, send);
SDT_PROBE_DECLARE(pf, state, purge, run);
SDT_PROBE_DECLARE(pf, state, state, create);
SDT_PROBE_DECLARE(pf, state, state, free);
SDT_PROBE_DECLARE(pf, state, state, insert);
SDT_PROBE_DECLARE(pf, state, state, remove);
SDT_PROBE_DECLARE(pf, state, state, transition);
SDT_PROBE_DECLARE(pf, syncookie, cookie, send);
SDT_PROBE_DECLARE(pf, syncookie, cookie, validate);
SDT_PROBE_DECLARE(pf, table, addr, match);
SDT_PROBE_DECLARE(pf, rule, jail, match);
SDT_PROBE_DECLARE(pf, table, addr, update);
#define	PF_SDT1(m, f, n, a)		SDT_PROBE1(pf, m, f, n, a)
#define	PF_SDT2(m, f, n, a, b)		SDT_PROBE2(pf, m, f, n, a, b)
#define	PF_SDT3(m, f, n, a, b, c)	SDT_PROBE3(pf, m, f, n, a, b, c)
#define	PF_SDT4(m, f, n, a, b, c, d)	SDT_PROBE4(pf, m, f, n, a, b, c, d)
#define	PF_SDT_REASON(x)	SDT_PROBE3(pf, , reason, set, (x), __FILE__, __LINE__)

/* ------------------------------------------------------------------ */
/* VNET: OpenBSD PF globals are per-vnet (see PF_VNET_* in pfvar.h)    */
/* ------------------------------------------------------------------ */
#define	PF_VNET_DEFINE(t, n)		VNET_DEFINE(t, n##_vnet)
#define	PF_VNET_DEFINE_STATIC(t, n)	VNET_DEFINE_STATIC(t, n##_vnet)
#define	PF_VNET_DEFINE_ARRAY(t, n, d)	VNET_DEFINE(t, n##_vnet[d])
#define	PF_VNET_DECLARE(t, n)		VNET_DECLARE(t, n##_vnet)
#define	PF_VNET_DECLARE_ARRAY(t, n, d)	VNET_DECLARE(t, n##_vnet[d])
/* Struct tags that share a name with a per-vnet variable. */
#define	PF_KTAG(x)			x##_ktag
#define	pf_statetbl	VNET(pf_statetbl_vnet)
#define	pf_queues	VNET(pf_queues_vnet)
#define	pf_queues_active	VNET(pf_queues_active_vnet)
#define	pf_queues_inactive	VNET(pf_queues_inactive_vnet)
#define	pf_status	VNET(pf_status_vnet)
#define	pf_status_fcounters	VNET(pf_status_fcounters_vnet)
#define	tree_src_tracking	VNET(tree_src_tracking_vnet)
#define	tree_id	VNET(tree_id_vnet)
#define	pf_state_list	VNET(pf_state_list_vnet)
#define	pf_statelim_id_tree_active	VNET(pf_statelim_id_tree_active_vnet)
#define	pf_statelim_list_active	VNET(pf_statelim_list_active_vnet)
#define	pf_statelim_id_tree_inactive	VNET(pf_statelim_id_tree_inactive_vnet)
#define	pf_statelim_nm_tree_inactive	VNET(pf_statelim_nm_tree_inactive_vnet)
#define	pf_statelim_list_inactive	VNET(pf_statelim_list_inactive_vnet)
#define	pf_sourcelim_id_tree_active	VNET(pf_sourcelim_id_tree_active_vnet)
#define	pf_sourcelim_list_active	VNET(pf_sourcelim_list_active_vnet)
#define	pf_sourcelim_id_tree_inactive	VNET(pf_sourcelim_id_tree_inactive_vnet)
#define	pf_sourcelim_nm_tree_inactive	VNET(pf_sourcelim_nm_tree_inactive_vnet)
#define	pf_sourcelim_list_inactive	VNET(pf_sourcelim_list_inactive_vnet)
#define	pf_source_gc	VNET(pf_source_gc_vnet)
#define	pf_purge_states_task	VNET(pf_purge_states_task_vnet)
#define	pf_purge_states_to	VNET(pf_purge_states_to_vnet)
#define	pf_purge_to	VNET(pf_purge_to_vnet)
#define	pf_purge_task	VNET(pf_purge_task_vnet)
#define	pf_purge_states_limit	VNET(pf_purge_states_limit_vnet)
#define	pf_purge_states_collect	VNET(pf_purge_states_collect_vnet)
#define	pf_purge_cur	VNET(pf_purge_cur_vnet)
#define	pf_default_rule	VNET(pf_default_rule_vnet)
#define	pf_default_rule_new	VNET(pf_default_rule_new_vnet)
#define	pf_anchor_stack	VNET(pf_anchor_stack_vnet)
#define	pfi_all	VNET(pfi_all_vnet)
#define	pfi_ifs	VNET(pfi_ifs_vnet)
#define	pfi_update	VNET(pfi_update_vnet)
#define	pfi_buffer	VNET(pfi_buffer_vnet)
#define	pfi_buffer_cnt	VNET(pfi_buffer_cnt_vnet)
#define	pfi_buffer_max	VNET(pfi_buffer_max_vnet)
#define	pfr_ktables	VNET(pfr_ktables_vnet)
#define	pfr_ktable_cnt	VNET(pfr_ktable_cnt_vnet)
#define	pf_anchors	VNET(pf_anchors_vnet)
#define	pf_main_anchor	VNET(pf_main_anchor_vnet)
#define	pf_osfp_list	VNET(pf_osfp_list_vnet)
#define	pfn_fragqueue	VNET(pfn_fragqueue_vnet)
#define	pfn_frnode_tree	VNET(pfn_frnode_tree_vnet)
#define	pf_frag_mtx	VNET(pf_frag_mtx_vnet)
#define	pf_syncookie_status	VNET(pf_syncookie_status_vnet)
#define	pflog_ifs	VNET(pflog_ifs_vnet)
#define	pflowif_list	VNET(pflowif_list_vnet)
#define	pfsyncif	VNET(pfsyncif_vnet)
#define	pf_trans_set	VNET(pf_trans_set_vnet)

#ifndef OPENBSD_PF_GLUE
/*
 * OpenBSD defines the INADDR_* addresses in network byte order inside the
 * kernel (__IPADDR); 5BSD's are in host order.  The symmetric ones
 * (INADDR_ANY, INADDR_BROADCAST) need no change.
 */
#undef	INADDR_PFSYNC_GROUP
#define	INADDR_PFSYNC_GROUP	htonl(0xe00000f0)	/* 224.0.0.240 */
#undef	INADDR_ALLHOSTS_GROUP
#define	INADDR_ALLHOSTS_GROUP	htonl(0xe0000001)	/* 224.0.0.1 */
/* Likewise OpenBSD's IN_MULTICAST() takes a network-order address. */
#undef	IN_MULTICAST
#define	IN_MULTICAST(a)		((ntohl((u_int32_t)(a)) & 0xf0000000) == 0xe0000000)
#endif

/* ------------------------------------------------------------------ */
/* m_tag: OpenBSD's m_pkthdr.pf lives in PACKET_TAG_PF (sys/mbuf.h).   */
/* Vendor code reads it with PF_MTAG_R()/PF_PDTAG_R(), which never     */
/* allocate (no tag: default values), and writes it with PF_MTAG_W()/  */
/* PF_PDTAG_W(), which allocate the tag.  PF_PDTAG_* cache the tag in  */
/* the pf_pdesc so pf_test() looks it up once.                         */
/* ------------------------------------------------------------------ */
struct pf_pdesc;
struct pkthdr_pf *obsd_pf_mtag_w(struct mbuf *);
struct pkthdr_pf *obsd_pf_pdtag(struct pf_pdesc *, int);
#define	PF_MTAG_R(m)	m_pf_ro(m)
#define	PF_MTAG_W(m)	obsd_pf_mtag_w(m)
#define	PF_PDTAG_R(pd)	((const struct pkthdr_pf *)obsd_pf_pdtag((pd), 0))
#define	PF_PDTAG_W(pd)	obsd_pf_pdtag((pd), 1)

#endif /* _OPENBSD_PF_COMPAT_H_ */
