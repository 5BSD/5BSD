/*
 * kmock.h — userspace kernel-environment mock for the vsock RX harness.
 *
 * This shim lets the KERNEL source sys/kern/uipc_vsock.c compile and run as a
 * userspace ATF test (mirroring how vsock_device_harness builds the bhyve
 * device).  The vsock socket domain + loopback transport are driven directly;
 * a mock vtvsock_transport captures the packets the code would emit on the
 * wire, and a REAL-behaving socket-buffer layer makes the credit/rx_bytes
 * accounting meaningful (a fake sbappend/sbspace would make those tests lie).
 *
 * Force-included (-include kmock.h) before the DUT; the <sys/...> shadow
 * headers in this dir are empty and exist only so the DUT's #include lines
 * resolve here instead of to the real kernel headers.
 */
#ifndef VSOCK_KMOCK_H
#define VSOCK_KMOCK_H

#include <sys/types.h>
#include <sys/socket.h>		/* real: sockaddr, AF_*, msghdr, SOCK_* */
#include <sys/queue.h>		/* real: TAILQ/LIST */
#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- basic kernel spellings ---- */
typedef unsigned char	u_char;
typedef unsigned short	u_short;
typedef unsigned int	u_int;
typedef unsigned long	u_long;
#ifndef __unused
#define __unused	__attribute__((__unused__))
#endif
#define __printflike(a,b)
#define CTASSERT(x)	_Static_assert(x, #x)
#define nitems(a)	(sizeof(a) / sizeof((a)[0]))
#ifndef MIN
#define MIN(a,b)	((a) < (b) ? (a) : (b))
#define MAX(a,b)	((a) > (b) ? (a) : (b))
#endif
#define __predict_false(x)	(x)
#define __predict_true(x)	(x)

/* ---- printf/panic ---- */
static inline int
vs_printf(const char *fmt __unused, ...) { return (0); }
#define printf	vs_printf
static inline void vs_log(int p __unused, const char *fmt __unused, ...) {}
#define log	vs_log
static inline void vs_panic(const char *fmt __unused, ...) { abort(); }
#define panic	vs_panic
#define KASSERT(exp, msg)	do { if (!(exp)) abort(); } while (0)
#define MPASS(exp)		do { if (!(exp)) abort(); } while (0)

/* ---- malloc ---- */
struct malloc_type { const char *name; };
#define MALLOC_DEFINE(t, sn, ln)	struct malloc_type t[1] = {{ sn }}
#define MALLOC_DECLARE(t)		extern struct malloc_type t[1]
#define M_WAITOK	0x0001
#define M_NOWAIT	0x0002
#define M_ZERO		0x0100
/* Capture libc malloc/free before shadowing them with the 2-arg kernel forms. */
static void *(* const libc_malloc)(size_t) = malloc;
static void (* const libc_free)(void *) = free;
static inline void kfree(void *p) { libc_free(p); }
static inline void *
k_malloc(size_t s, struct malloc_type *t __unused, int fl)
{
	void *p = libc_malloc(s);
	if (p != NULL && (fl & M_ZERO))
		memset(p, 0, s);
	return (p);
}
static inline void *
k_realloc(void *o, size_t s, struct malloc_type *t __unused, int fl __unused)
{ extern void *realloc(void *, size_t); return (realloc(o, s)); }
#define malloc(s, t, f)		k_malloc((s), (t), (f))
#define realloc(o, s, t, f)	k_realloc((o), (s), (t), (f))
#define free(p, t)		kfree((void *)(p))

/* ---- counters ---- */
typedef uint64_t *counter_u64_t;
static inline counter_u64_t counter_u64_alloc(int fl __unused)
{ return ((counter_u64_t)calloc(1, sizeof(uint64_t))); }
static inline void counter_u64_free(counter_u64_t c) { kfree((void *)c); }
static inline void counter_u64_add(counter_u64_t c, int64_t v) { if (c) *c += v; }
static inline uint64_t counter_u64_fetch(counter_u64_t c) { return (c ? *c : 0); }

/* ---- SDT probes: no-ops ---- */
#define SDT_PROVIDER_DEFINE(p)
#define SDT_PROBE_DEFINE0(a,b,c,d)
#define SDT_PROBE_DEFINE1(a,b,c,d,e)
#define SDT_PROBE_DEFINE2(a,b,c,d,e,f)
#define SDT_PROBE_DEFINE3(a,b,c,d,e,f,g)
#define SDT_PROBE_DEFINE4(a,b,c,d,e,f,g,h)
#define SDT_PROBE_DEFINE5(a,b,c,d,e,f,g,h,i)
#define SDT_PROBE_DEFINE6(a,b,c,d,e,f,g,h,i,j)
#define SDT_PROBE1(...)
#define SDT_PROBE2(...)
#define SDT_PROBE3(...)
#define SDT_PROBE4(...)
#define SDT_PROBE5(...)
#define SDT_PROBE6(...)

/* ---- sysctl: no-ops ---- */
#define SYSCTL_NODE(...)		struct __sysctl_dummy { int x; }
#define SYSCTL_DECL(...)
#define SYSCTL_INT(...)
#define SYSCTL_UINT(...)
#define SYSCTL_U32(...)
#define SYSCTL_U64(...)
#define SYSCTL_LONG(...)
#define SYSCTL_ULONG(...)
#define SYSCTL_PROC(...)
#define SYSCTL_COUNTER_U64(...)
#define OID_AUTO 0
#define CTLFLAG_RD	0
#define CTLFLAG_RW	0
#define CTLFLAG_MPSAFE	0
#define CTLTYPE_ULONG	0
#define CTLTYPE_U64	0
/* sysctl handler machinery: the DUT defines handler functions but the harness
 * never invokes them, so provide the signature + a stub sysctl_handle_int. */
struct sysctl_oid;
struct sysctl_req { void *newptr; };
#define SYSCTL_HANDLER_ARGS	struct sysctl_oid *oidp __unused, \
	void *arg1 __unused, intmax_t arg2 __unused, struct sysctl_req *req __unused
static inline int
sysctl_handle_int(struct sysctl_oid *o __unused, void *p __unused,
    int a __unused, struct sysctl_req *r __unused) { return (0); }
static inline int
sysctl_handle_long(struct sysctl_oid *o __unused, void *p __unused,
    int a __unused, struct sysctl_req *r __unused) { return (0); }

/* ---- mutex: single-threaded harness, so a recursion-tolerant no-op ---- */
struct mtx { int depth; };
#define MTX_DEF		0
#define MA_OWNED	0
#define MA_NOTOWNED	0
static inline void mtx_init(struct mtx *m, const char *n __unused,
    const char *t __unused, int o __unused) { m->depth = 0; }
static inline void mtx_destroy(struct mtx *m __unused) {}
static inline void mtx_lock(struct mtx *m) { m->depth++; }
static inline void mtx_unlock(struct mtx *m) { m->depth--; }
static inline void mtx_assert(struct mtx *m __unused, int w __unused) {}
#define MTX_SYSINIT(a,b,c,d)

/* ---- sleep/wakeup: the target tests are synchronous and never actually
 * block, so msleep returns EWOULDBLOCK (timeout) immediately and wakeup is a
 * no-op.  Tests that require a real blocking wakeup are out of scope here and
 * live in the e2e suite. ---- */
#define PSOCK		0
#define PCATCH		0
#define PDROP		0
static inline int
msleep(void *chan __unused, struct mtx *m __unused, int pri __unused,
    const char *w __unused, int timo __unused) { return (EWOULDBLOCK); }
static inline int
msleep_sbt(void *chan __unused, struct mtx *m __unused, int pri __unused,
    const char *w __unused, int64_t sbt __unused, int64_t pr __unused,
    int fl __unused) { return (EWOULDBLOCK); }
static inline void wakeup(void *chan __unused) {}
#define tstosbt(x)	(0)
#define sbttots(x)	(0)
#define SBT_1S		1
#define hz		1000

/* ---- callout: record armed/stopped; the reaper/timeout tests fire it
 * manually. ---- */
struct callout { void (*fn)(void *); void *arg; int active; };
static inline void callout_init(struct callout *c, int mp __unused)
{ c->fn = NULL; c->arg = NULL; c->active = 0; }
static inline void
callout_reset(struct callout *c, int t __unused, void (*fn)(void *), void *a)
{ c->fn = fn; c->arg = a; c->active = 1; }
static inline int callout_stop(struct callout *c) { int r = c->active; c->active = 0; return (r); }
static inline int callout_drain(struct callout *c) { int r = c->active; c->active = 0; return (r); }
#define callout_active(c)	((c)->active)
static inline void callout_init_mtx(struct callout *c, struct mtx *m __unused, int fl __unused)
{ callout_init(c, 1); }
static inline int ppsratecheck(void *lt __unused, int *cur __unused, int max __unused) { return (1); }

/* ---- vnet: single default vnet ---- */
struct vnet { int dummy; };
extern struct vnet *curvnet;
#define CURVNET_SET(v)		do { struct vnet *_ov = curvnet; curvnet = (v)
#define CURVNET_RESTORE()	curvnet = _ov; } while (0)
#define VNET_ASSERT(exp, msg)	do { } while (0)

/* ---- thread / cred (unused detail) ---- */
struct ucred { int cr_flags; };
struct thread { struct ucred *td_ucred; struct proc *td_proc; };
struct proc { int p_pid; };
static inline int priv_check(struct thread *td __unused, int p __unused) { return (0); }
#define PRIV_NET_VSOCK	0
#define PRIV_NETINET_RESERVEDPORT 0
#define SOPT_GET 1
#define SOPT_SET 2
struct sockopt { int sopt_dir, sopt_level, sopt_name; void *sopt_val;
    size_t sopt_valsize; struct thread *sopt_td; };
static inline int sooptcopyin(struct sockopt *s, void *buf, size_t l, size_t m __unused)
{ size_t n = s->sopt_valsize < l ? s->sopt_valsize : l; memcpy(buf, s->sopt_val, n); return (0); }
static inline int sooptcopyout(struct sockopt *s, const void *buf, size_t l)
{ size_t n = s->sopt_valsize < l ? s->sopt_valsize : l; memcpy(s->sopt_val, buf, n); s->sopt_valsize = l; return (0); }

/* ======================================================================
 * mbuf — minimal but real: a linked chain of byte buffers.
 * ==================================================================== */
#define MLEN		2048
#define MHLEN		2048
#define MT_DATA		1
struct mbuf {
	struct mbuf	*m_next;
	struct mbuf	*m_nextpkt;
	int		 m_len;
	int		 m_flags;
	char		*m_data;
	struct { int len; } m_pkthdr;
	char		 m_dat[MLEN];
};
#define M_EOR		0x00000004
#define M_PROTO1	0x00001000
#define M_PKTHDR	0x00000002

static inline struct mbuf *
m_get(int how __unused, int type __unused)
{
	struct mbuf *m = calloc(1, sizeof(*m));
	if (m != NULL) m->m_data = m->m_dat;
	return (m);
}
static inline struct mbuf *
m_gethdr(int how, int type)
{
	struct mbuf *m = m_get(how, type);
	if (m != NULL) m->m_flags |= M_PKTHDR;
	return (m);
}
static inline void
m_freem(struct mbuf *m)
{
	while (m != NULL) { struct mbuf *n = m->m_next; kfree(m); m = n; }
}
static inline int
m_length(struct mbuf *m, struct mbuf **last)
{
	int n = 0;
	for (; m != NULL; m = m->m_next) { n += m->m_len; if (last && !m->m_next) *last = m; }
	return (n);
}
struct uio;
struct mbuf *m_uiotombuf(struct uio *uio, int how, int len, int align, int flags);
void m_cat(struct mbuf *, struct mbuf *);
void m_copyback(struct mbuf *, int, int, const void *);
static inline struct mbuf *
m_getm2(struct mbuf *prev __unused, int len, int how, int type, int flags)
{ struct mbuf *m = m_get(how, type); if (m == NULL) return (NULL);
  if (flags & M_PKTHDR) m->m_flags |= M_PKTHDR; m->m_len = len; return (m); }

/* ======================================================================
 * socket / sockbuf — real byte accounting so credit tests are meaningful.
 * ==================================================================== */
struct sockbuf {
	int		 sb_state;
	u_int		 sb_cc;		/* bytes currently queued */
	u_int		 sb_hiwat;
	u_int		 sb_lowat;
	int		 sb_timeo;
	struct mbuf	*sb_mb;		/* queued chain (record list) */
	struct mbuf	*sb_mbtail;
};
#define SBS_CANTSENDMORE	0x0010
#define SBS_CANTRCVMORE		0x0020

struct socket {
	int		 so_type;
	int		 so_state;
	int		 so_options;
	int		 so_error;
	uint64_t	 so_gencnt;
	void		*so_pcb;
	struct vnet	*so_vnet;
	struct ucred	*so_cred;
	short		 so_qlimit;
	struct sockbuf	 so_rcv;
	struct sockbuf	 so_snd;
	/* listen-side overlay (real kernel unions these; keep separate here) */
	u_int		 sol_sbrcv_hiwat;
	u_int		 sol_sbsnd_hiwat;
	int		 so_listening;
};
#define SS_ISCONNECTED		0x0002
#define SS_ISCONNECTING		0x0004
#define SS_ISDISCONNECTING	0x0008
#define SS_NBIO			0x0100
#define SS_ISDISCONNECTED	0x2000
#define SO_ACCEPTCONN		0x0002
#define SOLISTENING(so)		((so)->so_listening)

/* locks: no-ops (single thread) */
#define SOCK_RECVBUF_LOCK(so)	do { } while (0)
#define SOCK_RECVBUF_UNLOCK(so)	do { } while (0)
#define SOCK_SENDBUF_LOCK(so)	do { } while (0)
#define SOCK_SENDBUF_UNLOCK(so)	do { } while (0)
#define SOCK_LOCK(so)		do { } while (0)
#define SOCK_UNLOCK(so)		do { } while (0)
#define SOCKBUF_LOCK(sb)	do { } while (0)
#define SOCKBUF_UNLOCK(sb)	do { } while (0)
#define SOCK_IO_SEND_LOCK(so, fl)	(0)
#define SOCK_IO_SEND_UNLOCK(so)		do { } while (0)
#define SBLOCKWAIT(f)		0
#define SBL_WAIT		0
#define SBL_NOINTR		0

static inline u_int
sbspace(struct sockbuf *sb)
{
	return (sb->sb_hiwat > sb->sb_cc ? sb->sb_hiwat - sb->sb_cc : 0);
}
static inline u_int
sbavail(struct sockbuf *sb) { return (sb->sb_cc); }
static inline void
sbappendstream_locked(struct sockbuf *sb, struct mbuf *m, int flags __unused)
{
	sb->sb_cc += m_length(m, NULL);
	m_freem(m);		/* harness: we only track byte counts */
}
static inline void
sbappendrecord_locked(struct sockbuf *sb, struct mbuf *m)
{
	sb->sb_cc += m_length(m, NULL);
	m_freem(m);
}
static inline void
sbappend(struct sockbuf *sb, struct mbuf *m, int flags __unused)
{ sbappendstream_locked(sb, m, 0); }

/* socket state transitions */
static inline void socantrcvmore_locked(struct socket *so) { so->so_rcv.sb_state |= SBS_CANTRCVMORE; }
static inline void socantsendmore_locked(struct socket *so) { so->so_snd.sb_state |= SBS_CANTSENDMORE; }
static inline void socantrcvmore(struct socket *so) { socantrcvmore_locked(so); }
static inline void socantsendmore(struct socket *so) { socantsendmore_locked(so); }
static inline void soisconnected(struct socket *so)
{ so->so_state &= ~(SS_ISCONNECTING | SS_ISDISCONNECTING); so->so_state |= SS_ISCONNECTED; }
static inline void soisdisconnected(struct socket *so)
{ so->so_state &= ~(SS_ISCONNECTING | SS_ISCONNECTED); so->so_state |= SS_ISDISCONNECTED;
  so->so_rcv.sb_state |= SBS_CANTRCVMORE; so->so_snd.sb_state |= SBS_CANTSENDMORE; }
static inline void sorwakeup_locked(struct socket *so __unused) {}
static inline void sowwakeup_locked(struct socket *so __unused) {}
static inline void sorwakeup(struct socket *so __unused) {}
static inline void sowwakeup(struct socket *so __unused) {}
static inline int
soreserve(struct socket *so, u_long snd, u_long rcv)
{ so->so_snd.sb_hiwat = snd; so->so_rcv.sb_hiwat = rcv; return (0); }
static inline int
so_setsockopt(struct socket *so, int level __unused, int name __unused,
    const void *val, size_t len __unused)
{ int v = *(const int *)val; so->so_snd.sb_hiwat = v; so->so_rcv.sb_hiwat = v; return (0); }

/* sonewconn: allocate a child socket cloned from the listener, run pr_attach */
struct socket *vsock_kmock_sonewconn(struct socket *head, int connstatus);
#define sonewconn(head, cs)	vsock_kmock_sonewconn((head), (cs))
static inline int solisten_proto_check(struct socket *so __unused) { return (0); }
static inline void solisten_proto(struct socket *so, int backlog)
{ so->so_options |= SO_ACCEPTCONN; so->so_listening = 1; so->so_qlimit = backlog; }

/* uio */
struct uio {
	struct iovec	*uio_iov;
	int		 uio_iovcnt;
	ssize_t		 uio_resid;
	struct thread	*uio_td;
};

/* protosw / domain (registration is stubbed; the DUT reaches ops through the
 * global protosw it defines, so give the real named fields it initializes). */
struct protosw {
	short	pr_type;
	short	pr_protocol;
	short	pr_flags;
	void	*pr_attach; void *pr_bind; void *pr_listen; void *pr_accept;
	void	*pr_connect; void *pr_peeraddr; void *pr_sockaddr;
	void	*pr_ctloutput; void *pr_setsbopt; void *pr_soreceive;
	void	*pr_send; void *pr_sosend; void *pr_disconnect; void *pr_close;
	void	*pr_detach; void *pr_shutdown; void *pr_abort; void *pr_sopoll;
	void	*pr_control;
};
struct domain { int dom_family; const char *dom_name; void *dom_probe;
    int dom_nprotosw; struct protosw *dom_protosw[8]; };
#define PR_CONNREQUIRED		0x0004
#define PR_ATOMIC		0x0001
#define PR_SOCKBUF		0x1000
#define DOMAIN_SET(name)
#define pr_domain	dom
struct pr_usrreqs { int dummy; };
#define VNET_DOMAIN_SET(name)

/* module (stubbed) */
typedef struct module *module_t;
#define DECLARE_MODULE(a,b,c,d)
#define MODULE_VERSION(a,b)
typedef int modeventtype_t;
#define MOD_LOAD	0
#define MOD_UNLOAD	1

/* misc systm */
#define bzero(p, n)	memset((p), 0, (n))
#define bcopy(s, d, n)	memmove((d), (s), (n))
#define ovbcopy(s, d, n) memmove((d), (s), (n))
extern volatile int ticks;
extern uint32_t arc4random(void);
extern uint32_t arc4random_uniform(uint32_t);


/* ---- pr_send flags, ifnet (unused), cdev + module boilerplate ---- */
#define PRUS_OOB	0x1
#define PRUS_EOF	0x2
#define PRUS_MORETOCOME	0x4
struct ifnet;
struct cdev;
struct cdevsw { int d_version; const char *d_name; void *d_ioctl; void *d_open; };
#define D_VERSION	0
#define UID_ROOT	0
#define GID_WHEEL	0
#define MOD_QUIESCE	2
typedef struct { const char *name; int (*evhand)(module_t, int, void *); void *priv; } moduledata_t;
static inline struct cdev *
make_dev(struct cdevsw *c __unused, int u __unused, int uid __unused,
    int gid __unused, int mode __unused, const char *fmt __unused, ...)
{ static struct cdev *d = (struct cdev *)1; return (d); }
static inline void destroy_dev(struct cdev *d __unused) {}
#define SI_SUB_PROTO_DOMAIN	0
#define SI_ORDER_ANY		0
#define SI_ORDER_MIDDLE		0

#endif /* VSOCK_KMOCK_H */
