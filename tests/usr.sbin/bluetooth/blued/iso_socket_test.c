/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Unit tests for the AF_BLUETOOTH ISO/CIS kernel socket
 * (sys/netgraph/bluetooth/socket/ng_btsocket_iso.c).
 *
 * Style: TU-include harness (mirrors l2cap_data_test.c).  We neutralise the
 * kernel-only primitive headers, provide userspace shims for mbuf clusters,
 * mutexes, callouts, socket buffers and the netgraph node/hook plumbing, then
 * #include the kernel .c directly.  Because everything lands in one
 * translation unit the tests can call the static entry points
 * (ng_btsocket_iso_send2 / ng_btsocket_iso_data_input / ...) with crafted
 * mbufs and a fake routing-info, and can reach the file-scope statics
 * (ng_btsocket_iso_node, the mutexes, the socket/route lists) directly.
 *
 * Oracle.  Every framing value asserted below is hand-derived from the
 * Bluetooth Core Specification 6.3, Vol 4 Part E §5.4.5 (HCI ISO Data
 * packet: Connection_Handle + PB_Flag + TS_Flag, Data_Total_Length, and the
 * ISO Data Load sub-header Packet_Sequence_Number / ISO_SDU_Length /
 * Packet_Status_Flag), never captured from the implementation's own output.
 *
 * The mbuf shim models the real cluster sizing (MHLEN vs MCLBYTES) and
 * records each mbuf's *logical* capacity so the finding-#1 test can assert
 * that no emitted HCI ISO fragment ever exceeds a single cluster, while the
 * underlying backing store is oversized so a regression cannot corrupt the
 * test process's heap -- it fails an assertion instead.
 */

#include <atf-c.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "spec_iso_socket_oracles.h"

/* ---------------------------------------------------------------------- */
/* Neutralise the kernel-only primitive headers the TU pulls in.          */
/* ---------------------------------------------------------------------- */
#define _SYS_SYSTM_H_
#define _SYS_KERNEL_H_
#define _SYS_MALLOC_H_
#define _SYS_MBUF_H_
#define _SYS_MUTEX_H_
#define _SYS_LOCK_H_
#define _SYS_CALLOUT_H_
#define _SYS_SYSCTL_H_
#define _SYS_TASKQUEUE_H_
#define _SYS_SOCKETVAR_H_
#define _SYS_DOMAIN_H_
#define _SYS_PROTOSW_H_
#define _SYS_FILEDESC_H_
#define _SYS_IOCCOM_H_
#define _SYS_SDT_H
#define _NET_VNET_H_
#define _NETGRAPH_NETGRAPH_H_
#define _NETGRAPH_NG_MESSAGE_H_

/* sys/param.h (real) gives us MCLBYTES, MSIZE, struct timeval, u_int types;
 * sys/socket.h (real) gives struct sockaddr, AF_BLUETOOTH, SOCK_SEQPACKET;
 * sys/endian.h (real) gives htole16/le16toh.  These are userspace-safe. */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/bitstring.h>

/* MHLEN is defined in the neutralised sys/mbuf.h; supply a representative
 * value (amd64 uses ~160).  MCLBYTES comes from sys/param.h (2048). */
#ifndef MHLEN
#define MHLEN	160
#endif

/* ---------------------------------------------------------------------- */
/* min()/KASSERT (normally sys/systm.h)                                    */
/* ---------------------------------------------------------------------- */
#ifndef min
#define min(a, b)	((a) < (b) ? (a) : (b))
#endif

/* KASSERT must actually fire in the tests so the finding-#1 cluster
 * invariant in send2() is checked, not compiled away. */
#define KASSERT(exp, msg)	do { if (!(exp)) { printf msg; abort(); } } while (0)

static int	ppsratecheck(struct timeval *, int *, int);
static int
ppsratecheck(struct timeval *lasttime, int *curpps, int maxpps)
{
	(void)lasttime; (void)curpps; (void)maxpps;
	return (1);
}

/* ---------------------------------------------------------------------- */
/* malloc/free (normally sys/malloc.h): map onto calloc/free.             */
/* ---------------------------------------------------------------------- */
#define M_NOWAIT	0x0001
#define M_WAITOK	0x0002
#define M_ZERO		0x0100
#define M_NETGRAPH	0
#define MT_DATA		1

static int g_kernel_malloc_fail;
static void *
ng_ut_kernel_malloc(size_t sz)
{
	if (g_kernel_malloc_fail > 0) {
		g_kernel_malloc_fail--;
		return (NULL);
	}
	return (calloc(1, sz));
}
#define malloc(sz, type, flags)	ng_ut_kernel_malloc((sz))
#define free(ptr, type)		free((ptr))

/* ---------------------------------------------------------------------- */
/* struct mtx (normally sys/mutex.h).  Single-threaded owned-count model   */
/* so mtx_assert(MA_OWNED) genuinely checks the lock discipline.           */
/* ---------------------------------------------------------------------- */
struct mtx { int owned; };
#define MA_OWNED	1
#define MA_NOTOWNED	0
#define MTX_DEF		0
#define MTX_DUPOK	0

static void
mtx_init(struct mtx *m, const char *a, const char *b, int c)
{
	(void)a; (void)b; (void)c;
	m->owned = 0;
}
static void mtx_lock(struct mtx *m)	{ m->owned++; }
static void mtx_unlock(struct mtx *m)	{ m->owned--; }
static int
mtx_trylock(struct mtx *m)
{
	if (m->owned != 0)
		return (0);
	m->owned = 1;
	return (1);
}
static void mtx_destroy(struct mtx *m)	{ (void)m; }
#define mtx_assert(m, what)	do {					\
	if ((what) == MA_OWNED)						\
		assert((m)->owned > 0);					\
	else if ((what) == MA_NOTOWNED)					\
		assert((m)->owned == 0);				\
} while (0)

/* ---------------------------------------------------------------------- */
/* struct callout (normally sys/callout.h): no-op, timers never fire.      */
/* ---------------------------------------------------------------------- */
struct callout { int c_dummy; };
#define callout_init_mtx(c, m, f)	do { (void)(c); } while (0)
#define callout_reset(c, t, fn, a)	(0)
#define callout_stop(c)			(0)
#define callout_drain(c)		(0)

/* ---------------------------------------------------------------------- */
/* Userspace mbuf with realistic MHLEN/MCLBYTES capacity accounting.       */
/* The backing store is intentionally oversized: a segmentation regression */
/* fails the m_len <= m_cap assertion in the data-capture sink rather than  */
/* corrupting the heap.                                                     */
/* ---------------------------------------------------------------------- */
#define NG_MBUF_STORE	16384
#define NG_MBUF_HEAD	64	/* headroom for M_PREPEND */

#define M_EXT		0x00000001
#define M_PKTHDR	0x00000002

struct mbuf {
	int		m_len;
	int		m_flags;
	int		m_cap;		/* logical capacity: MHLEN or MCLBYTES */
	struct {
		int	len;
	}		m_pkthdr;
	struct mbuf    *m_next;		/* chain within a record */
	struct mbuf    *m_nextpkt;	/* next record in a socket buffer */
	unsigned char  *m_data;
	unsigned char	m_store[NG_MBUF_STORE];
};

static int	g_mbuf_live;	/* leak detector */
static int	g_mbuf_alloc_fail;

static struct mbuf *
ng_mbuf_alloc(void)
{
	struct mbuf	*m;

	if (g_mbuf_alloc_fail > 0) {
		g_mbuf_alloc_fail--;
		return (NULL);
	}
	m = calloc(1, sizeof(*m));
	if (m != NULL) {
		m->m_data = m->m_store + NG_MBUF_HEAD;
		m->m_cap = MHLEN;
		m->m_flags = M_PKTHDR;
		g_mbuf_live++;
	}
	return (m);
}

static void
m_freem(struct mbuf *m)
{
	struct mbuf	*n;

	while (m != NULL) {
		n = m->m_next;
		g_mbuf_live--;
		(free)(m);
		m = n;
	}
}

#define NG_FREE_M(m)	do {			\
	if ((m) != NULL) {			\
		m_freem((m));			\
		(m) = NULL;			\
	}					\
} while (0)

/* MGETHDR: fresh header mbuf, MHLEN of usable space. */
#define MGETHDR(m, how, type)	do { (m) = ng_mbuf_alloc(); } while (0)

/* MCLGET: "attach a cluster" -> capacity grows to MCLBYTES.  Returns
 * nonzero on success (always, here).  m_data stays at the buffer base. */
static int
ng_mclget(struct mbuf *m)
{
	if (m == NULL)
		return (0);
	m->m_data = m->m_store + NG_MBUF_HEAD;
	m->m_cap = MCLBYTES;
	m->m_flags |= M_EXT;
	return (1);
}
#define MCLGET(m, how)		ng_mclget((m))

#define mtod(m, t)		((t)((void *)(m)->m_data))

static struct mbuf *
m_pullup(struct mbuf *m, int s)
{
	/* Our records are contiguous single mbufs, so m_len == pkthdr.len. */
	if (m == NULL)
		return (NULL);
	if (m->m_len >= s)
		return (m);
	m_freem(m);
	return (NULL);
}

static void
m_adj(struct mbuf *m, int n)
{
	if (m == NULL)
		return;
	if (n < 0)
		n = 0;
	if (n > m->m_len)
		n = m->m_len;
	m->m_data += n;
	m->m_len -= n;
	m->m_pkthdr.len -= n;
}

static void
m_copydata(struct mbuf *m, int off, int len, caddr_t dst)
{
	int		copied = 0;

	/* Walk the chain like the kernel's m_copydata. */
	while (m != NULL && off >= m->m_len) {
		off -= m->m_len;
		m = m->m_next;
	}
	while (m != NULL && copied < len) {
		int chunk = m->m_len - off;
		if (chunk > len - copied)
			chunk = len - copied;
		memcpy(dst + copied, m->m_data + off, (size_t)chunk);
		copied += chunk;
		off = 0;
		m = m->m_next;
	}
	assert(copied == len);
}

static struct mbuf *
m_dup(struct mbuf *m, int how)
{
	struct mbuf	*n;
	int		 total;

	(void)how;
	if (m == NULL)
		return (NULL);
	n = ng_mbuf_alloc();
	if (n == NULL)
		return (NULL);
	total = m->m_pkthdr.len;
	assert(total <= NG_MBUF_STORE - NG_MBUF_HEAD);
	m_copydata(m, 0, total, (caddr_t)n->m_data);
	n->m_len = n->m_pkthdr.len = total;
	return (n);
}

static void
m_cat(struct mbuf *m, struct mbuf *n)
{
	/* Model the kernel: append n's chain to the tail of m.  Our records
	 * fit in one buffer, so copy inline; caller fixes m_pkthdr.len. */
	int		room, cp;

	if (m == NULL || n == NULL) {
		if (n != NULL)
			m_freem(n);
		return;
	}
	while (m->m_next != NULL)
		m = m->m_next;
	room = NG_MBUF_STORE - (int)(m->m_data - m->m_store) - m->m_len;
	cp = n->m_len;
	if (cp > room)
		cp = room;
	if (cp > 0)
		memcpy(m->m_data + m->m_len, n->m_data, (size_t)cp);
	m->m_len += cp;
	m_freem(n);
}

/* M_PREPEND: grow toward the front (normally sys/mbuf.h). */
#define M_PREPEND(m, size, how)	do {					\
	(m) = ng_m_prepend((m), (size));				\
} while (0)

static struct mbuf *
ng_m_prepend(struct mbuf *m, int size)
{
	int	head;

	if (m == NULL)
		return (NULL);
	head = (int)(m->m_data - m->m_store);
	if (head >= size) {
		m->m_data -= size;
	} else {
		if (m->m_len + size > NG_MBUF_STORE) {
			m_freem(m);
			return (NULL);
		}
		memmove(m->m_store + size, m->m_data, (size_t)m->m_len);
		m->m_data = m->m_store;
	}
	m->m_len += size;
	m->m_pkthdr.len += size;
	return (m);
}

/* ---------------------------------------------------------------------- */
/* struct socket + sockbuf (normally sys/socketvar.h).                     */
/* Records are linked via m_nextpkt; sbavail == queued bytes.              */
/* ---------------------------------------------------------------------- */
struct sockbuf {
	struct mbuf	*sb_mb;		/* head record */
	struct mbuf	*sb_mbtail;	/* tail record */
	long		 sb_hiwat;
	long		 sb_cc;		/* queued bytes */
};

struct socket {
	void		*so_pcb;
	int		 so_type;
	int		 so_error;
	void		*so_vnet;
	int		 so_listening;
	struct sockbuf	 so_snd;
	struct sockbuf	 so_rcv;
};

static struct socket *g_sonewconn_result;

struct thread { int td_dummy; };
struct ifnet;

#define SOLISTENING(so)		((so)->so_listening)
#define SOCK_LOCK(so)		do { (void)(so); } while (0)
#define SOCK_UNLOCK(so)		do { (void)(so); } while (0)

static int
soreserve(struct socket *so, u_long snd, u_long rcv)
{
	so->so_snd.sb_hiwat = (long)snd;
	so->so_rcv.sb_hiwat = (long)rcv;
	return (0);
}

static void
sbappendrecord(struct sockbuf *sb, struct mbuf *m)
{
	m->m_nextpkt = NULL;
	if (sb->sb_mb == NULL)
		sb->sb_mb = m;
	else
		sb->sb_mbtail->m_nextpkt = m;
	sb->sb_mbtail = m;
	sb->sb_cc += m->m_pkthdr.len;
}

static void
sbdroprecord(struct sockbuf *sb)
{
	struct mbuf	*m = sb->sb_mb;

	if (m == NULL)
		return;
	sb->sb_mb = m->m_nextpkt;
	if (sb->sb_mb == NULL)
		sb->sb_mbtail = NULL;
	sb->sb_cc -= m->m_pkthdr.len;
	m->m_nextpkt = NULL;
	m_freem(m);
}

#define sbavail(sb)	((sb)->sb_cc)
#define sbspace(sb)	((sb)->sb_hiwat - (sb)->sb_cc)

#define sorwakeup(so)	do { (void)(so); } while (0)
#define sowwakeup(so)	do { (void)(so); } while (0)
#define soisconnected(so)	do { (void)(so); } while (0)
#define soisdisconnected(so)	do { (void)(so); } while (0)
#define soisconnecting(so)	do { (void)(so); } while (0)
#define soisdisconnecting(so)	do { (void)(so); } while (0)

static struct socket *
sonewconn(struct socket *head, int connstatus)
{
	struct socket *so;

	(void)head;
	(void)connstatus;
	so = g_sonewconn_result;
	g_sonewconn_result = NULL;
	return (so);
}

static int solisten_proto_check(struct socket *so)	{ (void)so; return (0); }
static void solisten_proto(struct socket *so, int b)	{ (void)so; (void)b; }

/* struct sockopt (normally sys/socketvar.h). */
struct sockopt {
	int		 sopt_dir;
	int		 sopt_level;
	int		 sopt_name;
	void		*sopt_val;
	size_t		 sopt_valsize;
	struct thread	*sopt_td;
};
#define SOPT_GET	0
#define SOPT_SET	1

static int
sooptcopyout(struct sockopt *sopt, const void *buf, size_t len)
{
	size_t	n = len < sopt->sopt_valsize ? len : sopt->sopt_valsize;

	if (sopt->sopt_val != NULL && n > 0)
		memcpy(sopt->sopt_val, buf, n);
	sopt->sopt_valsize = n;	/* report copied length (mirrors kernel) */
	return (0);
}

/* ---------------------------------------------------------------------- */
/* Netgraph node / hook / item / message plumbing (netgraph.h,            */
/* ng_message.h).  Only enough to compile the node methods and to capture  */
/* the HCI ISO data / LP messages the socket emits.                        */
/* ---------------------------------------------------------------------- */
struct ng_node { int nd_dummy; };
struct ng_hook { void *hk_private; int hk_valid; };
struct ng_item;

typedef struct ng_node *	node_p;
typedef struct ng_hook *	hook_p;
typedef struct ng_item *	item_p;

#define NG_ABI_VERSION		12

#define NG_NODE_UNREF(n)		do { (void)(n); } while (0)
#define NG_HOOK_REF(h)			do { (void)(h); } while (0)
#define NG_HOOK_UNREF(h)		do { (void)(h); } while (0)
#define NG_HOOK_PRIVATE(h)		((h)->hk_private)
#define NG_HOOK_SET_PRIVATE(h, v)	do { (h)->hk_private = (void *)(v); } while (0)
#define NG_HOOK_NOT_VALID(h)		((h) == NULL || (h)->hk_valid == 0)
#define NG_HOOK_NAME(h)			"iso"

/* Netgraph type descriptor (subset of struct ng_type). */
typedef int ng_constructor_t(node_p);
typedef int ng_rcvmsg_t(node_p, item_p, hook_p);
typedef int ng_shutdown_t(node_p);
typedef int ng_newhook_t(node_p, hook_p, const char *);
typedef int ng_connect_t(hook_p);
typedef int ng_rcvdata_t(hook_p, item_p);
typedef int ng_disconnect_t(hook_p);

struct ng_type {
	u_int32_t		 version;
	const char		*name;
	ng_constructor_t	*constructor;
	ng_rcvmsg_t		*rcvmsg;
	ng_shutdown_t		*shutdown;
	ng_newhook_t		*newhook;
	ng_connect_t		*connect;
	ng_rcvdata_t		*rcvdata;
	ng_disconnect_t		*disconnect;
};

static int g_newtype_error, g_make_node_error, g_name_node_error;
static int ng_newtype(struct ng_type *t)
{ (void)t; return (g_newtype_error); }
static int
ng_make_node_common(struct ng_type *t, node_p *np)
{
	(void)t;
	if (g_make_node_error != 0)
		return (g_make_node_error);
	*np = (node_p)calloc(1, sizeof(struct ng_node));
	return (*np == NULL ? ENOMEM : 0);
}
static int ng_name_node(node_p n, const char *s)
{ (void)n; (void)s; return (g_name_node_error); }

/* ng_mesg (normally ng_message.h). */
struct ng_mesg {
	struct {
		uint32_t	version;
		uint32_t	spare;
		uint32_t	arglen;
		uint32_t	cmd;
		uint32_t	flags;
		uint32_t	token;
		uint32_t	typecookie;
	}		header;
	char		data[];
};

static int g_message_alloc_fail;
#define NG_MKMESSAGE(msg, cookie, cmdid, len, how)	do {		\
	if (g_message_alloc_fail > 0) {					\
		g_message_alloc_fail--;					\
		(msg) = NULL;						\
	} else								\
		(msg) = calloc(1, sizeof(struct ng_mesg) + (len));	\
	if ((msg) != NULL) {						\
		(msg)->header.typecookie = (cookie);			\
		(msg)->header.cmd = (cmdid);				\
		(msg)->header.arglen = (len);				\
	}								\
} while (0)

#define NG_FREE_MSG(msg)	do {					\
	if ((msg) != NULL) { (free)((msg)); (msg) = NULL; }		\
} while (0)

/* Netgraph queue item (normally netgraph.h). */
struct ng_item {
	STAILQ_ENTRY(ng_item)	el_next;
	long			el_flags;
	struct mbuf	       *m;
	struct ng_mesg	       *msg;
	hook_p			hook;
};
#define NGQF_TYPE	0x01
#define NGQF_DATA	0x00
#define NGQF_MESG	0x01
#define NGI_MSG(i)		((i)->msg)
#define NGI_GET_MSG(i, x)	do { (x) = (i)->msg; (i)->msg = NULL; } while (0)
#define NGI_GET_M(i, x)		do { (x) = (i)->m; (i)->m = NULL; } while (0)
#define NGI_GET_HOOK(i, x)	do { (x) = (i)->hook; (i)->hook = NULL; } while (0)
#define NGI_SET_HOOK(i, h)	do { (i)->hook = (h); } while (0)
#define NG_FREE_ITEM(i)		do { if ((i) != NULL) { (free)((i)); (i) = NULL; } } while (0)

/* ---- capture sinks for emitted HCI data / control messages ---------- */
struct cap_pkt {
	int		m_len;
	int		m_cap;
	unsigned char	data[NG_MBUF_STORE];
};
static struct cap_pkt	g_cap[64];
static int		g_ncap;
static int		g_ncapmsg;
static int		g_sendmsg_error;

static void
ng_ut_capture_data(struct mbuf *m)
{
	struct cap_pkt	*c;
	int		 total, off, copied;
	struct mbuf	*t;

	if (g_ncap >= (int)(sizeof(g_cap) / sizeof(g_cap[0])))
		return;
	c = &g_cap[g_ncap++];
	total = m->m_pkthdr.len;
	c->m_len = m->m_pkthdr.len;
	c->m_cap = m->m_cap;
	if (total > (int)sizeof(c->data))
		total = (int)sizeof(c->data);
	copied = 0;
	for (t = m; t != NULL && copied < total; t = t->m_next) {
		off = t->m_len;
		if (off > total - copied)
			off = total - copied;
		memcpy(c->data + copied, t->m_data, (size_t)off);
		copied += off;
	}
}

#define NG_SEND_MSG_HOOK(error, node, msg, hook, flags)	do {		\
	(error) = g_sendmsg_error;					\
	g_ncapmsg++;							\
	(free)((msg));							\
	(msg) = NULL;							\
} while (0)

#define NG_SEND_DATA_ONLY(error, hook, m)	do {			\
	(error) = 0;							\
	ng_ut_capture_data((m));					\
	m_freem((m));							\
	(m) = NULL;							\
} while (0)

/* ---------------------------------------------------------------------- */
/* taskqueue (normally sys/taskqueue.h): no-op.                            */
/* ---------------------------------------------------------------------- */
struct task { int t_dummy; };
struct taskqueue;
#define taskqueue_swi		((struct taskqueue *)0)
#define taskqueue_enqueue(tq, t)	(0)
#define TASK_INIT(t, p, fn, ctx)	do { (void)(fn); } while (0)

/* ---------------------------------------------------------------------- */
/* CURVNET (normally net/vnet.h): no-op.                                   */
/* ---------------------------------------------------------------------- */
#define CURVNET_SET(v)		do { (void)(v); } while (0)
#define CURVNET_RESTORE()	do { } while (0)

/* ---------------------------------------------------------------------- */
/* SDT probes (normally sys/sdt.h): compile to nothing.                    */
/* ---------------------------------------------------------------------- */
#define SDT_PROVIDER_DECLARE(p)				struct __sdt_hack
#define SDT_PROBE_DEFINE1(p, m, f, n, a0)		struct __sdt_hack
#define SDT_PROBE_DEFINE2(p, m, f, n, a0, a1)		struct __sdt_hack
#define SDT_PROBE1(p, m, f, n, a0)			do { } while (0)
#define SDT_PROBE2(p, m, f, n, a0, a1)			do { } while (0)

/* ---------------------------------------------------------------------- */
/* sysctl (normally sys/sysctl.h): declarations that absorb the source.    */
/* ---------------------------------------------------------------------- */
#define SYSCTL_DECL(name)				struct __sysctl_hack
#define SYSCTL_NODE(p, n, nm, a, h, d)			int __sysctl_node_##nm(void)
#define SYSCTL_UINT(p, n, nm, a, ptr, val, d)		struct __sysctl_hack

/* SYSINIT (normally sys/kernel.h): the init hook never auto-runs here. */
#define SYSINIT(uniq, subs, order, func, ident)		extern int __sysinit_##uniq

/* ---------------------------------------------------------------------- */
/* Real bluetooth UAPI + socket headers.                                   */
/* ---------------------------------------------------------------------- */
/* Suppress ng_btsocket.h's "initialise new sockaddr member" reminder
 * (guarded by L2CAP_SOCKET_CHECKED); we only use sockaddr_iso here. */
#define L2CAP_SOCKET_CHECKED
#include <netgraph/bluetooth/include/ng_bluetooth.h>
#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>
#include <netgraph/bluetooth/include/ng_btsocket.h>
#include <netgraph/bluetooth/include/ng_btsocket_iso.h>

/* bluetooth_iso_rtx_timeout() (normally ng_bluetooth.c). */
uint32_t
bluetooth_iso_rtx_timeout(void)
{
	return (1);
}

/* The public entry-point prototypes live behind #ifdef _KERNEL in
 * ng_btsocket_iso.h, which we do not define; forward-declare the one that
 * ng_btsocket_iso.c references before its definition (abort/close). */
int ng_btsocket_iso_disconnect(struct socket *);

/* ====================================================================== */
/* The kernel translation unit under test.                                 */
/* ====================================================================== */
#include "ng_btsocket_iso.c"

/* ====================================================================== */
/* Test scaffolding                                                        */
/* ====================================================================== */

/*
 * HCI ISO packet field helpers, spec Vol 4 Part E §5.4.5.
 * con_handle word = Connection_Handle(12) | PB_Flag(2)<<12 | TS_Flag(1)<<14.
 */
#define ISO_HDR_LEN		BT_ISOS_HCI_HEADER_LEN
#define ISO_DL_LEN		BT_ISOS_DATA_LOAD_HEADER_LEN

static struct ng_hook	g_hook;
static ng_btsocket_iso_rtentry_t g_rt;

static bdaddr_t	g_src = { { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 } };

static void
harness_reset(void)
{
	g_ncap = 0;
	g_ncapmsg = 0;
	g_kernel_malloc_fail = 0;
	g_message_alloc_fail = 0;
	g_mbuf_alloc_fail = 0;
	g_newtype_error = 0;
	g_make_node_error = 0;
	g_name_node_error = 0;
	g_sendmsg_error = 0;
	g_sonewconn_result = NULL;
	/* Route lists / mutexes are file-scope statics in the TU. */
	static int inited;
	if (!inited) {
		mtx_init(&ng_btsocket_iso_rt_mtx, "rt", NULL, MTX_DEF);
		mtx_init(&ng_btsocket_iso_sockets_mtx, "so", NULL, MTX_DEF);
		mtx_init(&ng_btsocket_iso_queue_mtx, "q", NULL, MTX_DEF);
		LIST_INIT(&ng_btsocket_iso_rt);
		LIST_INIT(&ng_btsocket_iso_sockets);
		inited = 1;
	}
	/* A live node so the socket entry points do not bail with EINVAL. */
	if (ng_btsocket_iso_node == NULL)
		ng_btsocket_iso_node = (node_p)calloc(1, sizeof(struct ng_node));
	/* Exercise the production diagnostics alongside every socket state and
	 * malformed-frame transition; log formatting is part of these paths. */
	ng_btsocket_iso_debug_level = NG_BTSOCKET_INFO_LEVEL;

	/* Detach any leftover sockets from a previous case. */
	while (!LIST_EMPTY(&ng_btsocket_iso_sockets)) {
		ng_btsocket_iso_pcb_p p = LIST_FIRST(&ng_btsocket_iso_sockets);
		LIST_REMOVE(p, next);
		if (p->rx_frag != NULL) {
			m_freem(p->rx_frag);
			p->rx_sdu_len = 0;
		}
		if (p->so != NULL) {
			while (p->so->so_snd.sb_mb != NULL)
				sbdroprecord(&p->so->so_snd);
			while (p->so->so_rcv.sb_mb != NULL)
				sbdroprecord(&p->so->so_rcv);
			(free)(p->so);
		}
		(free)(p);
	}
}

/* Build a bound, OPEN pcb+socket attached to g_rt with a given handle. */
static ng_btsocket_iso_pcb_p
make_open_pcb(u_int16_t con_handle)
{
	struct socket		*so;
	ng_btsocket_iso_pcb_p	 pcb;

	so = calloc(1, sizeof(*so));
	assert(so != NULL);
	so->so_type = SOCK_SEQPACKET;
	so->so_snd.sb_hiwat = NG_BTSOCKET_ISO_SENDSPACE;
	so->so_rcv.sb_hiwat = NG_BTSOCKET_ISO_RECVSPACE;

	pcb = calloc(1, sizeof(*pcb));
	assert(pcb != NULL);
	mtx_init(&pcb->pcb_mtx, "pcb", NULL, MTX_DEF);
	pcb->so = so;
	so->so_pcb = pcb;
	pcb->state = NG_BTSOCKET_ISO_OPEN;
	pcb->con_handle = con_handle;
	bcopy(&g_src, &pcb->src, sizeof(pcb->src));
	pcb->rt = &g_rt;

	LIST_INSERT_HEAD(&ng_btsocket_iso_sockets, pcb, next);
	return (pcb);
}

/* Queue a tx SDU (single contiguous mbuf record) of `len` bytes filled with
 * a byte pattern derived from `seed` onto the pcb's send queue. */
static void
queue_tx_sdu(ng_btsocket_iso_pcb_p pcb, int len, int seed)
{
	struct mbuf	*m;
	int		 i;

	m = ng_mbuf_alloc();
	assert(m != NULL);
	for (i = 0; i < len; i++)
		m->m_data[i] = (unsigned char)((seed + i) & 0xff);
	m->m_len = m->m_pkthdr.len = len;
	sbappendrecord(&pcb->so->so_snd, m);
}

static void
sync_completed(u_int16_t con_handle, u_int16_t completed)
{
	struct ng_mesg			*msg;
	ng_hci_sync_con_queue_ep	*ep;
	ng_btsocket_iso_pcb_t		*pcb;

	mtx_lock(&ng_btsocket_iso_sockets_mtx);
	pcb = ng_btsocket_iso_pcb_by_handle(&g_rt.src, con_handle);
	if (pcb != NULL) {
		if ((pcb->flags & NG_BTSOCKET_ISO_TIMO) == 0)
			ng_btsocket_iso_timeout(pcb);
		mtx_unlock(&pcb->pcb_mtx);
	}
	mtx_unlock(&ng_btsocket_iso_sockets_mtx);

	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_SYNC_CON_QUEUE,
	    sizeof(*ep), M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	ep = (ng_hci_sync_con_queue_ep *)msg->data;
	ep->con_handle = con_handle;
	ep->completed = completed;

	NG_HOOK_SET_PRIVATE(&g_hook, &g_rt);
	ng_btsocket_iso_default_msg_input(msg, &g_hook);
}

/* Build an inbound HCI ISO data packet mbuf.
 * pb: PB_Flag; ts: TS_Flag; with_dl: prepend the ISO Data Load sub-header;
 * payload/len: SDU payload bytes; sdu_len: value for the ISO_SDU_Length field
 * (only meaningful when with_dl). */
static struct mbuf *
build_iso_in(u_int16_t con_handle, u_int8_t pb, u_int8_t ts, int with_dl,
    u_int16_t sdu_len, const unsigned char *payload, int len)
{
	struct mbuf	*m;
	unsigned char	*p;
	int		 dl = with_dl ? ISO_DL_LEN : 0;
	int		 total = ISO_HDR_LEN + dl + len;
	u_int16_t	 chw, lenw;

	m = ng_mbuf_alloc();
	assert(m != NULL);
	p = m->m_data;

	chw = (u_int16_t)((con_handle & BT_ISOS_HANDLE_MASK) |
	    ((u_int16_t)pb << BT_ISOS_PB_SHIFT) |
	    ((u_int16_t)ts << BT_ISOS_TS_SHIFT));
	lenw = (u_int16_t)(dl + len);	/* Data_Total_Length */

	p[0] = BT_ISOS_H4_ISO_DATA;
	le16enc(&p[1], chw);
	le16enc(&p[3], lenw);
	if (with_dl) {
		le16enc(&p[5], 0x0000);			/* seq_num */
		le16enc(&p[7], (u_int16_t)(sdu_len & BT_ISOS_SDU_LEN_MASK));
	}
	if (len > 0)
		memcpy(p + ISO_HDR_LEN + dl, payload, (size_t)len);
	m->m_len = m->m_pkthdr.len = total;
	return (m);
}

/* Decode fields of a captured emitted fragment. */
static u_int16_t cap_chw(int i)  { return (le16dec(&g_cap[i].data[1])); }
static u_int16_t cap_len(int i)  { return (le16dec(&g_cap[i].data[3])); }
static u_int8_t
cap_pb(int i)
{
	return ((cap_chw(i) >> BT_ISOS_PB_SHIFT) & BT_ISOS_PB_MASK);
}

static u_int16_t
cap_handle(int i)
{
	return (cap_chw(i) & BT_ISOS_HANDLE_MASK);
}

/* ====================================================================== */
/* Finding #1 (CRITICAL): send2 segmentation must never overflow a cluster */
/* ====================================================================== */
ATF_TC_WITHOUT_HEAD(send2_frag_overflow_bounded);
ATF_TC_BODY(send2_frag_overflow_bounded, tc)
{
	ng_btsocket_iso_pcb_p	pcb;
	int			i, total_payload;
	unsigned char		reasm[8192];
	int			roff;

	harness_reset();

	/*
	 * Simulate a controller (or a pre-#3-clamp route) advertising an
	 * oversized Data_Total_Length: 4095 (> a 2048-byte cluster).  This is
	 * the exact input the review flagged: frag_len derived from pkt_size
	 * would drive m_copydata past the cluster.  We set rt->pkt_size
	 * DIRECTLY to bypass the NODE_UP clamp and prove send2's own
	 * per-fragment cap holds the line.
	 */
	bzero(&g_rt, sizeof(g_rt));
	bcopy(&g_src, &g_rt.src, sizeof(g_rt.src));
	g_rt.hook = &g_hook;
	g_hook.hk_valid = 1;
	g_rt.pkt_size = 4095;
	g_rt.num_pkts = 255;
	g_rt.pending = 0;

	pcb = make_open_pcb(0x0123);
	queue_tx_sdu(pcb, 4095, 0x40);

	mtx_lock(&ng_btsocket_iso_rt_mtx);
	mtx_lock(&pcb->pcb_mtx);
	(void)ng_btsocket_iso_send2(pcb);
	mtx_unlock(&pcb->pcb_mtx);
	mtx_unlock(&ng_btsocket_iso_rt_mtx);

	/* At least two fragments (a 4095-byte SDU cannot fit one cluster). */
	ATF_REQUIRE(g_ncap >= 2);
	ATF_CHECK_MSG(pcb->so->so_snd.sb_mb != NULL,
	    "send record retired before HCI completions");

	total_payload = 0;
	roff = 0;
	for (i = 0; i < g_ncap; i++) {
		int hdr = (i == 0) ? (ISO_HDR_LEN + ISO_DL_LEN) : ISO_HDR_LEN;
		int payload;

		/* CRITICAL invariant: never exceed one cluster. */
		ATF_CHECK_MSG(g_cap[i].m_len <= (int)MCLBYTES,
		    "fragment %d m_len=%d exceeds MCLBYTES=%d",
		    i, g_cap[i].m_len, (int)MCLBYTES);
		/* And never exceed the mbuf's own allocated capacity. */
		ATF_CHECK_MSG(g_cap[i].m_len <= g_cap[i].m_cap,
		    "fragment %d m_len=%d exceeds capacity=%d",
		    i, g_cap[i].m_len, g_cap[i].m_cap);

		/* Handle preserved (§5.4.5). */
		ATF_CHECK_EQ(0x0123, cap_handle(i));

		/* PB_Flag sequence: first=0b00, middle=0b01, last=0b11. */
		if (i == 0)
			ATF_CHECK_EQ(BT_ISOS_PB_FIRST, cap_pb(i));
		else if (i == g_ncap - 1)
			ATF_CHECK_EQ(BT_ISOS_PB_LAST, cap_pb(i));
		else
			ATF_CHECK_EQ(BT_ISOS_PB_CONTINUATION, cap_pb(i));

		/* Data_Total_Length == sub-header(first only) + this payload. */
		payload = g_cap[i].m_len - hdr;
		ATF_CHECK_EQ(cap_len(i), (u_int16_t)(g_cap[i].m_len - ISO_HDR_LEN));

		/* Accumulate reassembled SDU payload in order. */
		memcpy(reasm + roff, g_cap[i].data + hdr, (size_t)payload);
		roff += payload;
		total_payload += payload;
	}

	/* Total copied == SDU: no bytes lost, no overflow (§5.4.5). */
	ATF_CHECK_EQ(4095, total_payload);

	/* First fragment carries ISO_SDU_Length == whole SDU length. */
	ATF_CHECK_EQ(4095,
	    ((le16dec(&g_cap[0].data[7]))) & BT_ISOS_SDU_LEN_MASK);

	/* Reassembled bytes equal the original ascending pattern. */
	for (i = 0; i < 4095; i++)
		ATF_REQUIRE_EQ((unsigned char)((0x40 + i) & 0xff), reasm[i]);

	sync_completed(0x0123, (u_int16_t)g_ncap);
	ATF_CHECK_MSG(pcb->so->so_snd.sb_mb == NULL,
	    "send record not retired after final HCI completion");
}

/* ====================================================================== */
/* Finding #7: single complete SDU -> one packet, coherent framing.        */
/* ====================================================================== */
ATF_TC_WITHOUT_HEAD(send2_complete_sdu);
ATF_TC_BODY(send2_complete_sdu, tc)
{
	ng_btsocket_iso_pcb_p	pcb;

	harness_reset();
	bzero(&g_rt, sizeof(g_rt));
	bcopy(&g_src, &g_rt.src, sizeof(g_rt.src));
	g_rt.hook = &g_hook;
	g_hook.hk_valid = 1;
	g_rt.pkt_size = 251;
	g_rt.num_pkts = 8;
	g_rt.pending = 0;

	pcb = make_open_pcb(0x00ab);
	queue_tx_sdu(pcb, 100, 0x10);

	mtx_lock(&ng_btsocket_iso_rt_mtx);
	mtx_lock(&pcb->pcb_mtx);
	(void)ng_btsocket_iso_send2(pcb);
	mtx_unlock(&pcb->pcb_mtx);
	mtx_unlock(&ng_btsocket_iso_rt_mtx);

	ATF_REQUIRE_EQ(1, g_ncap);
	/* PB_Flag = 0b10 (complete SDU). */
	ATF_CHECK_EQ(BT_ISOS_PB_COMPLETE, cap_pb(0));
	/* Data_Total_Length = sub-header + 100. */
	ATF_CHECK_EQ((u_int16_t)(ISO_DL_LEN + 100), cap_len(0));
	/* ISO_SDU_Length = 100. */
	ATF_CHECK_EQ(100, ((le16dec(&g_cap[0].data[7]))) & BT_ISOS_SDU_LEN_MASK);
	ATF_CHECK(g_cap[0].m_len <= (int)MCLBYTES);
	ATF_CHECK_MSG(pcb->so->so_snd.sb_mb != NULL,
	    "send record retired before HCI completion");
	sync_completed(0x00ab, 1);
	ATF_CHECK_MSG(pcb->so->so_snd.sb_mb == NULL,
	    "complete SDU record not retired after HCI completion");
}

/* ====================================================================== */
/* Finding #7: pkt_size boundaries -> coherent max_pdu, no leak/overflow.  */
/* ====================================================================== */
ATF_TC_WITHOUT_HEAD(send2_pkt_size_boundaries);
ATF_TC_BODY(send2_pkt_size_boundaries, tc)
{
	static const u_int16_t	sizes[] = { 1, 4, 5, 251, 4095 };
	unsigned		si;

	for (si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
		ng_btsocket_iso_pcb_p	pcb;
		int			i, total;

		harness_reset();
		bzero(&g_rt, sizeof(g_rt));
		bcopy(&g_src, &g_rt.src, sizeof(g_rt.src));
		g_rt.hook = &g_hook;
		g_hook.hk_valid = 1;
		g_rt.pkt_size = sizes[si];
		g_rt.num_pkts = 255;
		g_rt.pending = 0;

		pcb = make_open_pcb(0x0011);

		queue_tx_sdu(pcb, 300, 0x01);	/* forces both code paths */

		mtx_lock(&ng_btsocket_iso_rt_mtx);
		mtx_lock(&pcb->pcb_mtx);
		(void)ng_btsocket_iso_send2(pcb);
		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_rt_mtx);

		total = 0;
		for (i = 0; i < g_ncap; i++) {
			int hdr = (i == 0) ? (ISO_HDR_LEN + ISO_DL_LEN)
					   : ISO_HDR_LEN;
			/*
			 * The core #1 invariant, holding for every fragment
			 * class and every pkt_size: a single emitted HCI ISO
			 * packet never exceeds one cluster.
			 */
			ATF_CHECK_MSG(g_cap[i].m_len <= (int)MCLBYTES,
			    "pkt_size=%u frag %d m_len=%d > MCLBYTES",
			    sizes[si], i, g_cap[i].m_len);
			/* Data_Total_Length matches the fragment payload. */
			ATF_CHECK_EQ(cap_len(i),
			    (u_int16_t)(g_cap[i].m_len - ISO_HDR_LEN));
			total += g_cap[i].m_len - hdr;
		}
		/* Whole SDU transmitted, no bytes dropped. */
		ATF_CHECK_EQ(300, total);

		ATF_CHECK_MSG(pcb->so->so_snd.sb_mb != NULL,
		    "pkt_size=%u retired send record before completion",
		    sizes[si]);
		sync_completed(0x0011, (u_int16_t)g_ncap);
		ATF_CHECK_MSG(pcb->so->so_snd.sb_mb == NULL,
		    "pkt_size=%u did not retire send record after completion",
		    sizes[si]);
	}
}

/* ====================================================================== */
/* Completion accounting: partial ISOAL batches must not drop the SDU.     */
/* ====================================================================== */
ATF_TC_WITHOUT_HEAD(send2_partial_batch_completion);
ATF_TC_BODY(send2_partial_batch_completion, tc)
{
	ng_btsocket_iso_pcb_p	pcb;

	harness_reset();
	bzero(&g_rt, sizeof(g_rt));
	bcopy(&g_src, &g_rt.src, sizeof(g_rt.src));
	g_rt.hook = &g_hook;
	g_hook.hk_valid = 1;
	g_rt.pkt_size = 100;
	g_rt.num_pkts = 1;
	g_rt.pending = 0;

	pcb = make_open_pcb(0x0066);
	queue_tx_sdu(pcb, 220, 0x20);

	mtx_lock(&ng_btsocket_iso_rt_mtx);
	mtx_lock(&pcb->pcb_mtx);
	(void)ng_btsocket_iso_send2(pcb);
	mtx_unlock(&pcb->pcb_mtx);
	mtx_unlock(&ng_btsocket_iso_rt_mtx);

	ATF_REQUIRE_EQ(1, g_ncap);
	ATF_CHECK_EQ(BT_ISOS_PB_FIRST, cap_pb(0));
	ATF_CHECK_MSG(pcb->so->so_snd.sb_mb != NULL,
	    "partial first batch dropped the queued SDU");

	sync_completed(0x0066, 1);
	ATF_CHECK_MSG(pcb->so->so_snd.sb_mb != NULL,
	    "non-final batch completion dropped the queued SDU");
	ATF_CHECK_EQ(2, g_ncap);
	ATF_CHECK_EQ(BT_ISOS_PB_CONTINUATION, cap_pb(1));

	sync_completed(0x0066, 1);
	ATF_CHECK_MSG(pcb->so->so_snd.sb_mb != NULL,
	    "second non-final batch completion dropped the queued SDU");
	ATF_CHECK_EQ(3, g_ncap);
	ATF_CHECK_EQ(BT_ISOS_PB_LAST, cap_pb(2));

	sync_completed(0x0066, 1);
	ATF_CHECK_MSG(pcb->so->so_snd.sb_mb == NULL,
	    "final batch completion did not retire queued SDU");
}

/* Fragment counts use all eight bits; finality is independent metadata. */
ATF_TC_WITHOUT_HEAD(fragment_ring_full_width_count);
ATF_TC_BODY(fragment_ring_full_width_count, tc)
{
	struct ng_btsocket_iso_pcb pcb;

	bzero(&pcb, sizeof(pcb));
	ATF_REQUIRE_EQ(0, ng_btsocket_iso_frag_ring_put(&pcb, 128, 0));
	ATF_CHECK_EQ(128, pcb.frag_ring[0]);
	ATF_CHECK_EQ(0, pcb.frag_ring_is_final[0]);
	ATF_REQUIRE_EQ(0, ng_btsocket_iso_frag_ring_put(&pcb, 255, 1));
	ATF_CHECK_EQ(255, pcb.frag_ring[1]);
	ATF_CHECK_EQ(1, pcb.frag_ring_is_final[1]);
}

/* ====================================================================== */
/* Finding #1/#3/#7: NODE_UP clamps an oversized advertised pkt_size.      */
/* ====================================================================== */
ATF_TC_WITHOUT_HEAD(node_up_clamps_pkt_size);
ATF_TC_BODY(node_up_clamps_pkt_size, tc)
{
	struct {
		u_int16_t	in;
		u_int16_t	expect;
	} cases[] = {
		{ 0,	NG_BTSOCKET_ISO_DEFAULT_PKT_SIZE },
		{ 100,	100 },
		{ 0xffff, NG_BTSOCKET_ISO_MAX_PKT_SIZE },
		{ 0x3fff, NG_BTSOCKET_ISO_MAX_PKT_SIZE },
	};
	unsigned	ci;

	harness_reset();

	for (ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ci++) {
		struct ng_mesg		*msg;
		ng_hci_node_up_ep	*ep;

		bzero(&g_rt, sizeof(g_rt));
		g_hook.hk_valid = 1;
		NG_HOOK_SET_PRIVATE(&g_hook, &g_rt);	/* pre-attached rt */

		NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_NODE_UP,
		    sizeof(*ep), M_NOWAIT);
		ATF_REQUIRE(msg != NULL);
		ep = (ng_hci_node_up_ep *)msg->data;
		bcopy(&g_src, &ep->bdaddr, sizeof(ep->bdaddr));
		ep->pkt_size = cases[ci].in;
		ep->num_pkts = 4;

		ng_btsocket_iso_default_msg_input(msg, &g_hook);

		ATF_CHECK_MSG(g_rt.pkt_size == cases[ci].expect,
		    "pkt_size in=%u -> %u, expected %u",
		    cases[ci].in, g_rt.pkt_size, cases[ci].expect);
	}
	/* The clamp bound must itself fit a cluster (defence for #1). */
	ATF_CHECK(NG_BTSOCKET_ISO_MAX_PKT_SIZE + ISO_HDR_LEN <= (int)MCLBYTES);
	NG_HOOK_SET_PRIVATE(&g_hook, NULL);
}

/* ====================================================================== */
/* Finding #4: 0b00 + 0b11 reassembly must be bounded to MAX_REASM.        */
/* ====================================================================== */
ATF_TC_WITHOUT_HEAD(data_input_first_last_bounded);
ATF_TC_BODY(data_input_first_last_bounded, tc)
{
	ng_btsocket_iso_pcb_p	pcb;
	struct mbuf		*m;
	static unsigned char	buf[20000];

	harness_reset();
	bzero(&g_rt, sizeof(g_rt));
	bcopy(&g_src, &g_rt.src, sizeof(g_rt.src));
	g_rt.hook = &g_hook;
	g_hook.hk_valid = 1;
	NG_HOOK_SET_PRIVATE(&g_hook, &g_rt);
	memset(buf, 0x5a, sizeof(buf));

	pcb = make_open_pcb(0x0055);

	/*
	 * Case A: first fragment (0b00) larger than MAX_REASM (0x0FFF).
	 * A single ~16 KB first fragment can never become a valid SDU, so it
	 * must be rejected up front; rx_frag stays empty.
	 */
	m = build_iso_in(0x0055, BT_ISOS_PB_FIRST, 0, 1,
	    BT_ISOS_SDU_LEN_MASK, buf, 8000);
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_CHECK_MSG(pcb->rx_frag == NULL,
	    "oversized first fragment was buffered");
	ATF_CHECK_EQ(0, pcb->so->so_rcv.sb_cc);

	/*
	 * Case B: first(0b00, 3000) + last(0b11, 2000) exceeds the
	 * declared 12-bit ISO_SDU_Length (0x0fff).  The first is accepted;
	 * the completed record must be dropped, NOT delivered (§5.4.5).
	 */
	m = build_iso_in(0x0055, BT_ISOS_PB_FIRST, 0, 1,
	    BT_ISOS_SDU_LEN_MASK, buf, 3000);
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_REQUIRE_MSG(pcb->rx_frag != NULL, "valid first fragment dropped");

	m = build_iso_in(0x0055, BT_ISOS_PB_LAST, 0, 0, 0, buf, 2000);
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_CHECK_MSG(pcb->rx_frag == NULL, "reassembly not cleared");
	ATF_CHECK_MSG(pcb->so->so_rcv.sb_cc == 0,
	    "oversized reassembled SDU (%ld bytes) was delivered",
	    pcb->so->so_rcv.sb_cc);
}

/* ====================================================================== */
/* Finding #5: TS_Flag on a continuation fragment must not eat 4 bytes.    */
/* ====================================================================== */
ATF_TC_WITHOUT_HEAD(data_input_ts_on_continuation);
ATF_TC_BODY(data_input_ts_on_continuation, tc)
{
	ng_btsocket_iso_pcb_p	pcb;
	struct mbuf		*m;
	unsigned char		a[10], c[8], b[6];
	int			i;

	harness_reset();
	bzero(&g_rt, sizeof(g_rt));
	bcopy(&g_src, &g_rt.src, sizeof(g_rt.src));
	g_rt.hook = &g_hook;
	g_hook.hk_valid = 1;
	NG_HOOK_SET_PRIVATE(&g_hook, &g_rt);

	for (i = 0; i < 10; i++) a[i] = (unsigned char)(0xa0 + i);
	for (i = 0; i < 8; i++)  c[i] = (unsigned char)(0xc0 + i);
	for (i = 0; i < 6; i++)  b[i] = (unsigned char)(0xb0 + i);

	pcb = make_open_pcb(0x0077);

	/* First fragment (0b00) with sub-header: 10 payload bytes. */
	m = build_iso_in(0x0077, 0x00, 0, 1, 24, a, 10);
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_REQUIRE(pcb->rx_frag != NULL);

	/*
	 * Continuation (0b01) with TS_Flag=1 but NO timestamp bytes present
	 * (malformed).  The fix must NOT strip 4 bytes: all 8 payload bytes
	 * are appended.  A regression would consume 4 as a phantom timestamp.
	 */
	m = build_iso_in(0x0077, 0x01, 1, 0, 0, c, 8);
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_REQUIRE(pcb->rx_frag != NULL);

	/* Last (0b11): 6 bytes, completes and delivers. */
	m = build_iso_in(0x0077, 0x03, 0, 0, 0, b, 6);
	ng_btsocket_iso_data_input(m, &g_hook);

	/* Delivered SDU length must be 10 + 8 + 6 = 24 (not 20). */
	ATF_CHECK_MSG(pcb->so->so_rcv.sb_cc == 24,
	    "delivered %ld bytes, expected 24 (TS wrongly stripped?)",
	    pcb->so->so_rcv.sb_cc);
	ATF_REQUIRE(pcb->so->so_rcv.sb_mb != NULL);
	ATF_CHECK_EQ(24, pcb->so->so_rcv.sb_mb->m_pkthdr.len);

	/* The continuation's 8 bytes are intact and in place (offset 10). */
	{
		unsigned char *d = pcb->so->so_rcv.sb_mb->m_data;
		for (i = 0; i < 8; i++)
			ATF_CHECK_EQ((unsigned char)(0xc0 + i), d[10 + i]);
	}
}

ATF_TC_WITHOUT_HEAD(data_input_sdu_length_mismatch);
ATF_TC_BODY(data_input_sdu_length_mismatch, tc)
{
	ng_btsocket_iso_pcb_p	pcb;
	struct mbuf		*m;
	unsigned char		a[4], b[4], c[3];

	harness_reset();
	bzero(&g_rt, sizeof(g_rt));
	bcopy(&g_src, &g_rt.src, sizeof(g_rt.src));
	g_rt.hook = &g_hook;
	g_hook.hk_valid = 1;
	NG_HOOK_SET_PRIVATE(&g_hook, &g_rt);

	memset(a, 0xa1, sizeof(a));
	memset(b, 0xb2, sizeof(b));
	memset(c, 0xc3, sizeof(c));
	pcb = make_open_pcb(0x0088);

	/* Complete PB=0b10 must deliver exactly ISO_SDU_Length bytes. */
	m = build_iso_in(0x0088, 0x02, 0, 1, 100, c, sizeof(c));
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_CHECK_EQ(0, pcb->so->so_rcv.sb_cc);

	/* Segmented overrun: declared 6, first 4, continuation 4. */
	m = build_iso_in(0x0088, 0x00, 0, 1, 6, a, sizeof(a));
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_REQUIRE(pcb->rx_frag != NULL);
	ATF_CHECK_EQ(6, pcb->rx_sdu_len);
	m = build_iso_in(0x0088, 0x01, 0, 0, 0, b, sizeof(b));
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_CHECK(pcb->rx_frag == NULL);
	ATF_CHECK_EQ(0, pcb->rx_sdu_len);
	ATF_CHECK_EQ(0, pcb->so->so_rcv.sb_cc);

	/* Segmented underfill: declared 8, first 4, last 3. */
	m = build_iso_in(0x0088, 0x00, 0, 1, 8, a, sizeof(a));
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_REQUIRE(pcb->rx_frag != NULL);
	m = build_iso_in(0x0088, 0x03, 0, 0, 0, c, sizeof(c));
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_CHECK(pcb->rx_frag == NULL);
	ATF_CHECK_EQ(0, pcb->rx_sdu_len);
	ATF_CHECK_EQ(0, pcb->so->so_rcv.sb_cc);

	/* Recovery: exact declared length delivers. */
	m = build_iso_in(0x0088, 0x00, 0, 1, 8, a, sizeof(a));
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_REQUIRE(pcb->rx_frag != NULL);
	m = build_iso_in(0x0088, 0x03, 0, 0, 0, b, sizeof(b));
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_REQUIRE(pcb->so->so_rcv.sb_mb != NULL);
	ATF_CHECK_EQ(8, pcb->so->so_rcv.sb_mb->m_pkthdr.len);
}

ATF_TC_WITHOUT_HEAD(data_input_lost_status_aborts_reassembly);
ATF_TC_BODY(data_input_lost_status_aborts_reassembly, tc)
{
	ng_btsocket_iso_pcb_p	pcb;
	struct mbuf		*m;
	unsigned char		a[4], b[4], lost = 0xee;

	harness_reset();
	bzero(&g_rt, sizeof(g_rt));
	bcopy(&g_src, &g_rt.src, sizeof(g_rt.src));
	g_rt.hook = &g_hook;
	g_hook.hk_valid = 1;
	NG_HOOK_SET_PRIVATE(&g_hook, &g_rt);

	memset(a, 0xa1, sizeof(a));
	memset(b, 0xb2, sizeof(b));
	pcb = make_open_pcb(0x0099);

	m = build_iso_in(0x0099, BT_ISOS_PB_FIRST, 0, 1, 8, a, sizeof(a));
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_REQUIRE(pcb->rx_frag != NULL);
	ATF_CHECK_EQ(8, pcb->rx_sdu_len);

	m = build_iso_in(0x0099, BT_ISOS_PB_COMPLETE, 0, 1, 1, &lost,
	    sizeof(lost));
	le16enc(&m->m_data[7], (uint16_t)(1 |
	    (BT_ISOS_STATUS_LOST << BT_ISOS_STATUS_SHIFT)));
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_CHECK(pcb->rx_frag == NULL);
	ATF_CHECK_EQ(0, pcb->rx_sdu_len);

	m = build_iso_in(0x0099, BT_ISOS_PB_LAST, 0, 0, 0, b, sizeof(b));
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_CHECK_EQ(0, pcb->so->so_rcv.sb_cc);
	ATF_CHECK(pcb->rx_frag == NULL);
}

ATF_TC_WITHOUT_HEAD(data_input_rejection_and_recovery_matrix);
ATF_TC_BODY(data_input_rejection_and_recovery_matrix, tc)
{
	static const unsigned char byte = 0x5a;
	static const unsigned char oversized[BT_ISOS_SDU_LEN_MASK + 1];
	ng_btsocket_iso_pcb_p pcb;
	struct ng_hook no_private;
	struct mbuf *m;

	harness_reset();
	bzero(&g_rt, sizeof(g_rt));
	bcopy(&g_src, &g_rt.src, sizeof(g_rt.src));
	g_rt.hook = &g_hook;
	g_hook.hk_valid = 1;
	NG_HOOK_SET_PRIVATE(&g_hook, &g_rt);

	m = build_iso_in(0x321, 2, 0, 1, 1, &byte, 1);
	ng_btsocket_iso_data_input(m, NULL);
	bzero(&no_private, sizeof(no_private));
	no_private.hk_valid = 1;
	m = build_iso_in(0x321, 2, 0, 1, 1, &byte, 1);
	ng_btsocket_iso_data_input(m, &no_private);
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	m->m_len = m->m_pkthdr.len = 1;
	ng_btsocket_iso_data_input(m, &g_hook);
	/* A non-contiguous short first mbuf exercises header pullup failure. */
	m = build_iso_in(0x321, 2, 0, 1, 1, &byte, 1);
	m->m_len = 1;
	ng_btsocket_iso_data_input(m, &g_hook);

	/* Header length mismatch and truncated timestamp/data-load headers. */
	m = build_iso_in(0x321, 2, 0, 1, 1, &byte, 1);
	m->m_data[3]++;
	ng_btsocket_iso_data_input(m, &g_hook);
	m = build_iso_in(0x321, 2, 1, 0, 0, &byte, 1);
	ng_btsocket_iso_data_input(m, &g_hook);
	m = build_iso_in(0x321, 2, 0, 0, 0, &byte, 1);
	ng_btsocket_iso_data_input(m, &g_hook);

	/* Packet_Status_Flag=lost is rejected before socket lookup. */
	m = build_iso_in(0x321, 2, 0, 1, 1, &byte, 1);
	le16enc(&m->m_data[7], (uint16_t)(1 |
	    (BT_ISOS_STATUS_LOST << BT_ISOS_STATUS_SHIFT)));
	ng_btsocket_iso_data_input(m, &g_hook);
	m = build_iso_in(0x777, 2, 0, 1, 1, &byte, 1);
	ng_btsocket_iso_data_input(m, &g_hook);

	pcb = make_open_pcb(0x321);
	pcb->state = NG_BTSOCKET_ISO_CLOSED;
	m = build_iso_in(0x321, 2, 0, 1, 1, &byte, 1);
	ng_btsocket_iso_data_input(m, &g_hook);
	pcb->state = NG_BTSOCKET_ISO_OPEN;

	/* Continuation and last fragments require an existing first fragment. */
	m = build_iso_in(0x321, 1, 0, 0, 0, &byte, 1);
	ng_btsocket_iso_data_input(m, &g_hook);
	m = build_iso_in(0x321, 3, 0, 0, 0, &byte, 1);
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_CHECK(pcb->rx_frag == NULL);

	/* A second first fragment replaces stale partial reassembly safely. */
	m = build_iso_in(0x321, 0, 0, 1, 2, &byte, 1);
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_REQUIRE(pcb->rx_frag != NULL);
	m = build_iso_in(0x321, 0, 0, 1, 1, &byte, 1);
		ng_btsocket_iso_data_input(m, &g_hook);
		ATF_REQUIRE(pcb->rx_frag != NULL);
		NG_FREE_M(pcb->rx_frag);
		pcb->rx_sdu_len = 0;

	/* Complete SDU with timestamp: timestamp precedes data-load header. */
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	m->m_data[0] = BT_ISOS_H4_ISO_DATA;
	le16enc(&m->m_data[1], (uint16_t)(0x321 |
	    (BT_ISOS_PB_COMPLETE << BT_ISOS_PB_SHIFT) |
	    (1U << BT_ISOS_TS_SHIFT)));
	le16enc(&m->m_data[3], 9);
	memset(&m->m_data[5], 0xa5, 4);
	le16enc(&m->m_data[9], 7);
	le16enc(&m->m_data[11], 1);
	m->m_data[13] = byte;
	m->m_len = m->m_pkthdr.len = 14;
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_REQUIRE(pcb->so->so_rcv.sb_mb != NULL);
	ATF_CHECK_EQ(1, pcb->so->so_rcv.sb_mb->m_pkthdr.len);
	ATF_CHECK_EQ(byte, pcb->so->so_rcv.sb_mb->m_data[0]);
	sbdroprecord(&pcb->so->so_rcv);

	/* A complete packet discards stale partial reassembly. */
	pcb->rx_frag = ng_mbuf_alloc();
	ATF_REQUIRE(pcb->rx_frag != NULL);
	pcb->rx_frag->m_len = pcb->rx_frag->m_pkthdr.len = 1;
	m = build_iso_in(0x321, 2, 0, 1, 1, &byte, 1);
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_CHECK(pcb->rx_frag == NULL);
	ATF_CHECK(pcb->so->so_rcv.sb_mb != NULL);
	sbdroprecord(&pcb->so->so_rcv);

	/* Bound first fragments and receive-buffer exhaustion. */
	m = build_iso_in(0x321, BT_ISOS_PB_FIRST, 0, 1,
	    BT_ISOS_SDU_LEN_MASK, oversized,
	    sizeof(oversized));
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_CHECK(pcb->rx_frag == NULL);
	pcb->so->so_rcv.sb_hiwat = 0;
	m = build_iso_in(0x321, 2, 0, 1, 1, &byte, 1);
	ng_btsocket_iso_data_input(m, &g_hook);
	ATF_CHECK(pcb->so->so_rcv.sb_mb == NULL);
	harness_reset();
}

/* ====================================================================== */
/* Finding #2: connect() while OPEN/DISCONNECTING -> EISCONN.              */
/* ====================================================================== */
static struct socket *
attach_socket(void)
{
	struct socket	*so;
	struct thread	 td;
	int		 error;

	so = calloc(1, sizeof(*so));
	assert(so != NULL);
	so->so_type = SOCK_SEQPACKET;
	error = ng_btsocket_iso_attach(so, BLUETOOTH_PROTO_ISO, &td);
	assert(error == 0);
	return (so);
}

static void
fill_sa(struct sockaddr_iso *sa)
{
	bzero(sa, sizeof(*sa));
	sa->iso_len = sizeof(*sa);
	sa->iso_family = AF_BLUETOOTH;
	sa->iso_bdaddr_type = 0x01;		/* LE random */
	sa->iso_cis_handle = 0x0010;
	sa->iso_bdaddr.b[0] = 0xaa;		/* != src, != ANY */
}

ATF_TC_WITHOUT_HEAD(connect_state_machine);
ATF_TC_BODY(connect_state_machine, tc)
{
	struct socket		*so;
	ng_btsocket_iso_pcb_p	 pcb;
	ng_btsocket_iso_rtentry_t bad_rt;
	struct ng_hook		 bad_hook;
	struct sockaddr_iso	 sa;
	struct thread		 td;

	harness_reset();
	so = attach_socket();
	pcb = so2iso_pcb(so);
	fill_sa(&sa);

	/* OPEN -> EISCONN (finding #2: do not overwrite the live CIS/route). */
	pcb->state = NG_BTSOCKET_ISO_OPEN;
	ATF_CHECK_EQ(EISCONN,
	    ng_btsocket_iso_connect(so, (struct sockaddr *)&sa, &td));

	/* DISCONNECTING -> EISCONN as well. */
	pcb->state = NG_BTSOCKET_ISO_DISCONNECTING;
	ATF_CHECK_EQ(EISCONN,
	    ng_btsocket_iso_connect(so, (struct sockaddr *)&sa, &td));

	/* CONNECTING -> EINPROGRESS (unchanged behaviour). */
	pcb->state = NG_BTSOCKET_ISO_CONNECTING;
	ATF_CHECK_EQ(EINPROGRESS,
	    ng_btsocket_iso_connect(so, (struct sockaddr *)&sa, &td));

	/*
	 * CLOSED with no matching route -> EHOSTUNREACH: proves a CLOSED
	 * socket passes the state guard and proceeds to route resolution.
	 */
	pcb->state = NG_BTSOCKET_ISO_CLOSED;
	ATF_CHECK_EQ(EHOSTUNREACH,
	    ng_btsocket_iso_connect(so, (struct sockaddr *)&sa, &td));

	/* Route search skips dead hooks, selects a live controller route, copies
	 * an implicit source address, and starts the lower connection timeout. */
	bzero(&g_rt, sizeof(g_rt));
	bcopy(&g_src, &g_rt.src, sizeof(g_rt.src));
	g_rt.hook = &g_hook;
	g_hook.hk_valid = 1;
	bzero(&bad_rt, sizeof(bad_rt));
	bzero(&bad_hook, sizeof(bad_hook));
	bad_rt.hook = &bad_hook;
	bad_hook.hk_valid = 0;
	LIST_INSERT_HEAD(&ng_btsocket_iso_rt, &g_rt, next);
	LIST_INSERT_HEAD(&ng_btsocket_iso_rt, &bad_rt, next);
	pcb->state = NG_BTSOCKET_ISO_CLOSED;
	bzero(&pcb->src, sizeof(pcb->src));
	ATF_CHECK_EQ(0,
	    ng_btsocket_iso_connect(so, (struct sockaddr *)&sa, &td));
	ATF_CHECK_EQ(NG_BTSOCKET_ISO_CONNECTING, pcb->state);
	ATF_CHECK_EQ(&g_rt, pcb->rt);
	ATF_CHECK_EQ(0, bcmp(&pcb->src, &g_src, sizeof(g_src)));
	ATF_CHECK((pcb->flags & NG_BTSOCKET_ISO_CLIENT) != 0);
	ATF_CHECK((pcb->flags & NG_BTSOCKET_ISO_TIMO) != 0);
	LIST_REMOVE(&bad_rt, next);
	LIST_REMOVE(&g_rt, next);

	ng_btsocket_iso_detach(so);
	(free)(so);
}

/* ====================================================================== */
/* Address / option validation edges.                                     */
/* ====================================================================== */
ATF_TC_WITHOUT_HEAD(sockaddr_and_option_edges);
ATF_TC_BODY(sockaddr_and_option_edges, tc)
{
	struct socket		*so;
	ng_btsocket_iso_pcb_p	 pcb;
	struct sockaddr_iso	 sa;
	struct sockopt		 sopt;
	struct thread		 td;
	int			 tmp;

	harness_reset();
	so = attach_socket();
	pcb = so2iso_pcb(so);

	/* --- bind edges --- */
	fill_sa(&sa);
	sa.iso_family = AF_INET;
	ATF_CHECK_EQ(EAFNOSUPPORT,
	    ng_btsocket_iso_bind(so, (struct sockaddr *)&sa, &td));

	fill_sa(&sa);
	sa.iso_len = sizeof(sa) - 1;
	ATF_CHECK_EQ(EINVAL,
	    ng_btsocket_iso_bind(so, (struct sockaddr *)&sa, &td));

	/* --- connect edges --- */
	fill_sa(&sa);
	sa.iso_family = AF_INET;
	ATF_CHECK_EQ(EAFNOSUPPORT,
	    ng_btsocket_iso_connect(so, (struct sockaddr *)&sa, &td));

	fill_sa(&sa);
	sa.iso_len = 1;
	ATF_CHECK_EQ(EINVAL,
	    ng_btsocket_iso_connect(so, (struct sockaddr *)&sa, &td));

	/* dst == BDADDR_ANY -> EDESTADDRREQ */
	fill_sa(&sa);
	bzero(&sa.iso_bdaddr, sizeof(sa.iso_bdaddr));
	ATF_CHECK_EQ(EDESTADDRREQ,
	    ng_btsocket_iso_connect(so, (struct sockaddr *)&sa, &td));

	/* bad address type (not 0x00/0x01) -> EINVAL */
	fill_sa(&sa);
	sa.iso_bdaddr_type = 0x02;
	ATF_CHECK_EQ(EINVAL,
	    ng_btsocket_iso_connect(so, (struct sockaddr *)&sa, &td));

	/* CIS handle out of 12-bit range (> 0x0EFF) -> EINVAL */
	fill_sa(&sa);
	sa.iso_cis_handle = 0x0F00;
	ATF_CHECK_EQ(EINVAL,
	    ng_btsocket_iso_connect(so, (struct sockaddr *)&sa, &td));

	/* --- getsockopt edges (SOL_ISO) --- */
	/* Non-SOL_ISO level: pass-through, returns 0. */
	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_level = SOL_SOCKET;
	ATF_CHECK_EQ(0, ng_btsocket_iso_ctloutput(so, &sopt));

	/* SOL_ISO but socket not OPEN -> ENOTCONN, for any optlen. */
	pcb->state = NG_BTSOCKET_ISO_CLOSED;
	tmp = 0;
	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_level = SOL_ISO;
	sopt.sopt_name = SO_ISO_MTU;
	sopt.sopt_val = &tmp;
	sopt.sopt_valsize = 0;			/* optlen 0 */
	ATF_CHECK_EQ(ENOTCONN, ng_btsocket_iso_ctloutput(so, &sopt));

	sopt.sopt_valsize = 1;			/* optlen 1 */
	ATF_CHECK_EQ(ENOTCONN, ng_btsocket_iso_ctloutput(so, &sopt));

	/* OPEN with a route: SO_ISO_MTU returns pkt_size; large optlen ok. */
	bzero(&g_rt, sizeof(g_rt));
	g_rt.pkt_size = 200;
	g_rt.hook = &g_hook;
	g_hook.hk_valid = 1;
	pcb->rt = &g_rt;
	pcb->state = NG_BTSOCKET_ISO_OPEN;

	tmp = -1;
	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_level = SOL_ISO;
	sopt.sopt_name = SO_ISO_MTU;
	sopt.sopt_val = &tmp;
	sopt.sopt_valsize = sizeof(int) * 4;	/* oversized optlen */
	ATF_CHECK_EQ(0, ng_btsocket_iso_ctloutput(so, &sopt));
	ATF_CHECK_EQ(200, tmp);
	ATF_CHECK_EQ(sizeof(int), sopt.sopt_valsize);

	/* Unknown option name -> EINVAL. */
	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_level = SOL_ISO;
	sopt.sopt_name = 0x7fff;
	sopt.sopt_val = &tmp;
	sopt.sopt_valsize = sizeof(int);
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_ctloutput(so, &sopt));

	pcb->rt = NULL;
	pcb->state = NG_BTSOCKET_ISO_CLOSED;
	ng_btsocket_iso_detach(so);
	(free)(so);
}

ATF_TC_WITHOUT_HEAD(socket_api_lifecycle_matrix);
ATF_TC_BODY(socket_api_lifecycle_matrix, tc)
{
	struct socket *so;
	ng_btsocket_iso_pcb_p pcb;
	struct sockaddr_iso sa, got;
	struct sockopt sopt;
	struct thread td;
	int value = 0;

	harness_reset();
	so = attach_socket();
	pcb = so2iso_pcb(so);
	fill_sa(&sa);
	ATF_CHECK_EQ(0, ng_btsocket_iso_bind(so,
	    (struct sockaddr *)&sa, &td));
	ATF_CHECK_EQ(0, ng_btsocket_iso_sockaddr(so,
	    (struct sockaddr *)&got));
	ATF_CHECK_EQ(0, memcmp(&got.iso_bdaddr, &sa.iso_bdaddr,
	    sizeof(sa.iso_bdaddr)));

	pcb->dst = sa.iso_bdaddr;
	pcb->dst.b[1] = 0xbb;
	pcb->dst_type = 1;
	pcb->con_handle = 0x123;
	ATF_CHECK_EQ(0, ng_btsocket_iso_peeraddr(so,
	    (struct sockaddr *)&got));
	ATF_CHECK_EQ(0x123, got.iso_cis_handle);
	ATF_CHECK_EQ(1, got.iso_bdaddr_type);
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_control(so, 0, NULL, NULL, &td));
	ATF_CHECK_EQ(0, ng_btsocket_iso_listen(so, 3, &td));

	bzero(&sopt, sizeof(sopt));
	sopt.sopt_level = SOL_ISO;
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_name = SO_ISO_MTU;
	sopt.sopt_val = &value;
	sopt.sopt_valsize = sizeof(value);
	ATF_CHECK_EQ(ENOPROTOOPT, ng_btsocket_iso_ctloutput(so, &sopt));
	sopt.sopt_dir = 0xff;
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_ctloutput(so, &sopt));

	pcb->state = NG_BTSOCKET_ISO_DISCONNECTING;
	ATF_CHECK_EQ(EINPROGRESS, ng_btsocket_iso_disconnect(so));
	pcb->state = NG_BTSOCKET_ISO_CLOSED;
	ATF_CHECK_EQ(0, ng_btsocket_iso_disconnect(so));
	pcb->state = NG_BTSOCKET_ISO_CLOSED;
	ng_btsocket_iso_close(so);
	pcb->state = NG_BTSOCKET_ISO_CLOSED;
	ng_btsocket_iso_abort(so);
	ATF_CHECK_EQ(ECONNABORTED, so->so_error);

	ng_btsocket_iso_detach(so);
	(free)(so);
}

ATF_TC_WITHOUT_HEAD(socket_api_guard_completion);
ATF_TC_BODY(socket_api_guard_completion, tc)
{
	struct socket bare, *so, *other;
	ng_btsocket_iso_pcb_p pcb;
	struct sockaddr_iso sa, got;
	struct sockopt sopt;
	struct thread td;
	node_p oldnode;
	int value = 0;

	harness_reset();
	bzero(&bare, sizeof(bare));
	fill_sa(&sa);
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_bind(&bare, NULL, &td));
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_bind(&bare,
	    (struct sockaddr *)&sa, &td));
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_connect(&bare,
	    (struct sockaddr *)&sa, &td));
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_disconnect(&bare));
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_listen(&bare, 1, &td));
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_peeraddr(&bare,
	    (struct sockaddr *)&got));
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_sockaddr(&bare,
	    (struct sockaddr *)&got));

	so = attach_socket();
	pcb = so2iso_pcb(so);
	ATF_REQUIRE(pcb != NULL);
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_connect(so, NULL, &td));
	bcopy(&sa.iso_bdaddr, &pcb->src, sizeof(pcb->src));
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_connect(so,
	    (struct sockaddr *)&sa, &td));
	bzero(&pcb->src, sizeof(pcb->src));

	/* Exact duplicate non-wildcard binds are rejected across sockets. */
	ATF_REQUIRE_EQ(0, ng_btsocket_iso_bind(so,
	    (struct sockaddr *)&sa, &td));
	other = attach_socket();
	ATF_CHECK_EQ(EADDRINUSE, ng_btsocket_iso_bind(other,
	    (struct sockaddr *)&sa, &td));
	ng_btsocket_iso_detach(other);
	(free)(other);

	/* Detach owns all teardown even when a live connection has both a
	 * scheduled timeout and an incomplete inbound SDU. */
	other = attach_socket();
	ng_btsocket_iso_pcb_p other_pcb = so2iso_pcb(other);
	ATF_REQUIRE(other_pcb != NULL);
	other_pcb->state = NG_BTSOCKET_ISO_OPEN;
	other_pcb->rt = &g_rt;
	other_pcb->flags |= NG_BTSOCKET_ISO_TIMO;
	other_pcb->rx_frag = ng_mbuf_alloc();
	ATF_REQUIRE(other_pcb->rx_frag != NULL);
	other_pcb->rx_frag->m_len = other_pcb->rx_frag->m_pkthdr.len = 1;
	ng_btsocket_iso_detach(other);
	ATF_CHECK(other->so_pcb == NULL);
	(free)(other);

	/* Getsockopt distinguishes a missing route and returns the CIS handle. */
	bzero(&sopt, sizeof(sopt));
	sopt.sopt_level = SOL_ISO;
	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_name = SO_ISO_MTU;
	sopt.sopt_val = &value;
	sopt.sopt_valsize = sizeof(value);
	pcb->state = NG_BTSOCKET_ISO_OPEN;
	pcb->rt = NULL;
	ATF_CHECK_EQ(ENETDOWN, ng_btsocket_iso_ctloutput(so, &sopt));
	bzero(&g_rt, sizeof(g_rt));
	g_rt.hook = &g_hook;
	g_hook.hk_valid = 1;
	pcb->rt = &g_rt;
	pcb->con_handle = 0x234;
	sopt.sopt_name = SO_ISO_CONNINFO;
	ATF_CHECK_EQ(0, ng_btsocket_iso_ctloutput(so, &sopt));
	ATF_CHECK_EQ(0x234, value);

	/* OPEN disconnect sends the lower request and enters its guarded state. */
	ATF_CHECK_EQ(0, ng_btsocket_iso_disconnect(so));
	ATF_CHECK_EQ(NG_BTSOCKET_ISO_DISCONNECTING, pcb->state);
	pcb->state = NG_BTSOCKET_ISO_CLOSED;

	/* All public address/option entry points reject a missing netgraph node. */
	oldnode = ng_btsocket_iso_node;
	ng_btsocket_iso_node = NULL;
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_bind(so,
	    (struct sockaddr *)&sa, &td));
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_connect(so,
	    (struct sockaddr *)&sa, &td));
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_ctloutput(so, &sopt));
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_disconnect(so));
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_listen(so, 1, &td));
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_peeraddr(so,
	    (struct sockaddr *)&got));
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_sockaddr(so,
	    (struct sockaddr *)&got));
	ng_btsocket_iso_detach(so); /* missing-node detach is deliberately a no-op */
	ATF_CHECK(so->so_pcb != NULL);
	ng_btsocket_iso_node = oldnode;

	ng_btsocket_iso_detach(so);
	(free)(so);
}

ATF_TC_WITHOUT_HEAD(socket_send_entry_matrix);
ATF_TC_BODY(socket_send_entry_matrix, tc)
{
	ng_btsocket_iso_pcb_p pcb;
	struct socket bare;
	struct mbuf *m, *control;

#define NEW_SDU(_len) do {                                                   \
	m = ng_mbuf_alloc();                                                   \
	ATF_REQUIRE(m != NULL);                                                \
	m->m_len = m->m_pkthdr.len = (_len);                                  \
} while (0)

	harness_reset();
	bzero(&bare, sizeof(bare));
	NEW_SDU(1);
	ng_btsocket_iso_node = NULL;
	ATF_CHECK_EQ(ENETDOWN, ng_btsocket_iso_send(&bare, 0, m, NULL, NULL,
	    NULL));
	ng_btsocket_iso_node = (node_p)calloc(1, sizeof(struct ng_node));
	NEW_SDU(1);
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_send(&bare, 0, m, NULL, NULL,
	    NULL));

	pcb = make_open_pcb(0x234);
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_send(pcb->so, 0, NULL, NULL,
	    NULL, NULL));
	NEW_SDU(1);
	control = ng_mbuf_alloc();
	ATF_REQUIRE(control != NULL);
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_send(pcb->so, 0, m, NULL,
	    control, NULL));

	pcb->state = NG_BTSOCKET_ISO_CLOSED;
	NEW_SDU(1);
	ATF_CHECK_EQ(ENOTCONN, ng_btsocket_iso_send(pcb->so, 0, m, NULL,
	    NULL, NULL));
	pcb->state = NG_BTSOCKET_ISO_OPEN;
	pcb->rt = NULL;
	NEW_SDU(1);
	ATF_CHECK_EQ(ENETDOWN, ng_btsocket_iso_send(pcb->so, 0, m, NULL,
	    NULL, NULL));

	bzero(&g_rt, sizeof(g_rt));
	bcopy(&g_src, &g_rt.src, sizeof(g_rt.src));
	pcb->rt = &g_rt;
	NEW_SDU(1);
	ATF_CHECK_EQ(ENETDOWN, ng_btsocket_iso_send(pcb->so, 0, m, NULL,
	    NULL, NULL));
	g_rt.hook = &g_hook;
	g_hook.hk_valid = 1;
	g_rt.pkt_size = 251;
	g_rt.num_pkts = 8;
	NEW_SDU(0x1000);
	ATF_CHECK_EQ(EMSGSIZE, ng_btsocket_iso_send(pcb->so, 0, m, NULL,
	    NULL, NULL));

	NEW_SDU(100);
	ATF_REQUIRE_EQ(0, ng_btsocket_iso_send(pcb->so, 0, m, NULL, NULL,
	    NULL));
	ATF_CHECK_EQ(1, g_ncap);
	ATF_CHECK(pcb->so->so_snd.sb_mb != NULL);
	sync_completed(0x234, 1);
	ATF_CHECK(pcb->so->so_snd.sb_mb == NULL);

	/* A pending completion timer queues the SDU without a duplicate send. */
	pcb->flags |= NG_BTSOCKET_ISO_TIMO;
	NEW_SDU(2);
	ATF_REQUIRE_EQ(0, ng_btsocket_iso_send(pcb->so, 0, m, NULL, NULL,
	    NULL));
	ATF_CHECK_EQ(1, g_ncap);
	ATF_CHECK(pcb->so->so_snd.sb_mb != NULL);
#undef NEW_SDU
	harness_reset();
}

ATF_TC_WITHOUT_HEAD(lp_message_and_timeout_matrix);
ATF_TC_BODY(lp_message_and_timeout_matrix, tc)
{
	ng_btsocket_iso_pcb_p pcb, child_pcb;
	struct socket *child;
	struct ng_mesg *msg;
	ng_hci_lp_con_cfm_ep *cfm;
	ng_hci_lp_con_ind_ep *ind;
	ng_hci_lp_discon_ind_ep *dis;
	struct mbuf *m;

	harness_reset();
	bzero(&g_rt, sizeof(g_rt));
	bcopy(&g_src, &g_rt.src, sizeof(g_rt.src));
	g_hook.hk_valid = 1;
	g_rt.hook = &g_hook;
	NG_HOOK_SET_PRIVATE(&g_hook, &g_rt);
	pcb = make_open_pcb(0x77);

	/* Netgraph node methods and both disconnect route branches. */
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_node_constructor(
	    ng_btsocket_iso_node));
	ATF_CHECK_EQ(0, ng_btsocket_iso_node_newhook(ng_btsocket_iso_node,
	    &g_hook, "iso"));
	ATF_CHECK_EQ(0, ng_btsocket_iso_node_connect(&g_hook));
	NG_HOOK_SET_PRIVATE(&g_hook, NULL);
	ATF_CHECK_EQ(0, ng_btsocket_iso_node_disconnect(&g_hook));
	NG_HOOK_SET_PRIVATE(&g_hook, &g_rt);
	ATF_CHECK_EQ(0, ng_btsocket_iso_node_disconnect(&g_hook));

	/* Message-size guards for all three lower-protocol indications. */
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_CFM, 0, M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	ATF_CHECK_EQ(EMSGSIZE, ng_btsocket_iso_process_lp_con_cfm(msg, &g_rt));
	NG_FREE_MSG(msg);
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_IND, 0, M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	ATF_CHECK_EQ(EMSGSIZE, ng_btsocket_iso_process_lp_con_ind(msg, &g_rt));
	NG_FREE_MSG(msg);
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_DISCON_IND, 0, M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	ATF_CHECK_EQ(EMSGSIZE,
	    ng_btsocket_iso_process_lp_discon_ind(msg, &g_rt));
	NG_FREE_MSG(msg);

	/* Connect confirmation success and controller rejection. */
	for (int status = 0; status <= 1; status++) {
		pcb->state = NG_BTSOCKET_ISO_CONNECTING;
		pcb->flags |= NG_BTSOCKET_ISO_TIMO;
		NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_CFM,
		    sizeof(*cfm), M_NOWAIT);
		ATF_REQUIRE(msg != NULL);
		cfm = (ng_hci_lp_con_cfm_ep *)msg->data;
		cfm->status = (uint16_t)status;
		cfm->con_handle = 0x77;
		bcopy(&pcb->dst, &cfm->bdaddr, sizeof(cfm->bdaddr));
		ATF_CHECK_EQ(0, ng_btsocket_iso_process_lp_con_cfm(msg, &g_rt));
		ATF_CHECK_EQ(status == 0 ? NG_BTSOCKET_ISO_OPEN :
		    NG_BTSOCKET_ISO_CLOSED, pcb->state);
		NG_FREE_MSG(msg);
	}

	/* No listener and resource-limited listener both emit a response. */
	for (int listening = 0; listening <= 1; listening++) {
		pcb->so->so_listening = listening;
		NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_IND,
		    sizeof(*ind), M_NOWAIT);
		ATF_REQUIRE(msg != NULL);
		ind = (ng_hci_lp_con_ind_ep *)msg->data;
		ind->bdaddr.b[0] = 0xaa;
		ATF_CHECK_EQ(0, ng_btsocket_iso_process_lp_con_ind(msg, &g_rt));
		NG_FREE_MSG(msg);
	}
	pcb->so->so_listening = 0;

	/* A listening socket accepts a child and preserves peer/route state. */
	child = attach_socket();
	child_pcb = so2iso_pcb(child);
	ATF_REQUIRE(child_pcb != NULL);
	memset(&child_pcb->src, 0x99, sizeof(child_pcb->src));
	pcb->so->so_listening = 1;
	g_sonewconn_result = child;
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_IND,
	    sizeof(*ind), M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	ind = (ng_hci_lp_con_ind_ep *)msg->data;
	memset(&ind->bdaddr, 0x42, sizeof(ind->bdaddr));
	ind->con_handle = 0x88;
	ATF_CHECK_EQ(0, ng_btsocket_iso_process_lp_con_ind(msg, &g_rt));
	ATF_CHECK_EQ(NG_BTSOCKET_ISO_CONNECTING, child_pcb->state);
	ATF_CHECK_EQ(0, bcmp(&child_pcb->src, &g_src, sizeof(g_src)));
	ATF_CHECK_EQ(0, bcmp(&child_pcb->dst, &ind->bdaddr,
	    sizeof(ind->bdaddr)));
	ATF_CHECK_EQ(&g_rt, child_pcb->rt);
	ATF_CHECK((child_pcb->flags & NG_BTSOCKET_ISO_CLIENT) == 0);
	ATF_CHECK(child_pcb->flags & NG_BTSOCKET_ISO_TIMO);
	NG_FREE_MSG(msg);

	/* The subsequent controller confirmation opens that accepted child. */
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_CFM,
	    sizeof(*cfm), M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	cfm = (ng_hci_lp_con_cfm_ep *)msg->data;
	cfm->status = 0;
	cfm->con_handle = 0x88;
	cfm->bdaddr = child_pcb->dst;
	ATF_CHECK_EQ(0, ng_btsocket_iso_process_lp_con_cfm(msg, &g_rt));
	ATF_CHECK_EQ(NG_BTSOCKET_ISO_OPEN, child_pcb->state);
	ATF_CHECK_EQ(0x88, child_pcb->con_handle);
	NG_FREE_MSG(msg);
	pcb->so->so_listening = 0;

	/* Matching and nonmatching disconnect indications. */
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_DISCON_IND,
	    sizeof(*dis), M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	dis = (ng_hci_lp_discon_ind_ep *)msg->data;
	dis->con_handle = 0x123;
	ATF_CHECK_EQ(0, ng_btsocket_iso_process_lp_discon_ind(msg, &g_rt));
	NG_FREE_MSG(msg);
	pcb->con_handle = 0x77;
	pcb->state = NG_BTSOCKET_ISO_OPEN;
	pcb->flags |= NG_BTSOCKET_ISO_TIMO;
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_DISCON_IND,
	    sizeof(*dis), M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	dis = (ng_hci_lp_discon_ind_ep *)msg->data;
	dis->con_handle = 0x77;
	ATF_CHECK_EQ(0, ng_btsocket_iso_process_lp_discon_ind(msg, &g_rt));
	ATF_CHECK_EQ(NG_BTSOCKET_ISO_CLOSED, pcb->state);
	NG_FREE_MSG(msg);

	/* Outbound LP helpers: route guards and successful message emission. */
	mtx_lock(&pcb->pcb_mtx);
	pcb->rt = NULL;
	ATF_CHECK_EQ(ENETDOWN, ng_btsocket_iso_send_lp_con_req(pcb));
	ATF_CHECK_EQ(ENETDOWN, ng_btsocket_iso_send_lp_discon_req(pcb));
	pcb->rt = &g_rt;
	ATF_CHECK_EQ(0, ng_btsocket_iso_send_lp_con_req(pcb));
	ATF_CHECK_EQ(0, ng_btsocket_iso_send_lp_discon_req(pcb));
	mtx_unlock(&pcb->pcb_mtx);
	ATF_CHECK_EQ(ENETDOWN,
	    ng_btsocket_iso_send_lp_con_rsp(NULL, &pcb->dst,
	    pcb->con_handle, 0));
	ATF_CHECK_EQ(0, ng_btsocket_iso_send_lp_con_rsp(&g_rt, &pcb->dst,
	    pcb->con_handle, 0));

	/* Timeout state machine: connect, send, disconnect, and invalid state. */
	mtx_lock(&pcb->pcb_mtx);
	pcb->state = NG_BTSOCKET_ISO_CONNECTING;
	pcb->flags |= NG_BTSOCKET_ISO_TIMO;
	ng_btsocket_iso_process_timeout(pcb);
	ATF_CHECK_EQ(NG_BTSOCKET_ISO_CLOSED, pcb->state);
	pcb->state = NG_BTSOCKET_ISO_OPEN;
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	m->m_len = m->m_pkthdr.len = 1;
	sbappendrecord(&pcb->so->so_snd, m);
	g_rt.pending = 3;
	pcb->tx_unsynced = 2;
	pcb->flags |= NG_BTSOCKET_ISO_TIMO;
	ng_btsocket_iso_process_timeout(pcb);
	ATF_CHECK(pcb->so->so_snd.sb_mb == NULL);
	ATF_CHECK_EQ(1, g_rt.pending);
	ATF_CHECK_EQ(0, pcb->tx_unsynced);
	pcb->state = NG_BTSOCKET_ISO_DISCONNECTING;
	pcb->flags |= NG_BTSOCKET_ISO_TIMO;
	ng_btsocket_iso_process_timeout(pcb);
	ATF_CHECK_EQ(NG_BTSOCKET_ISO_CLOSED, pcb->state);
	pcb->state = 0xff;
	pcb->flags |= NG_BTSOCKET_ISO_TIMO;
	ng_btsocket_iso_process_timeout(pcb);
	mtx_unlock(&pcb->pcb_mtx);
}

ATF_TC_WITHOUT_HEAD(node_queue_init_and_route_cleanup);
ATF_TC_BODY(node_queue_init_and_route_cleanup, tc)
{
	ng_btsocket_iso_pcb_p pcb;
	ng_btsocket_iso_rtentry_p rt;
	struct ng_item *item;
	struct ng_mesg *msg;
	struct mbuf *m;
	struct ng_hook bad_hook;

	harness_reset();
	ng_btsocket_iso_node = NULL;
	ng_btsocket_iso_init(NULL);
	ATF_REQUIRE(ng_btsocket_iso_node != NULL);
	ATF_CHECK_EQ(0, ng_btsocket_iso_node_shutdown(ng_btsocket_iso_node));
	ATF_REQUIRE(ng_btsocket_iso_node != NULL);

	bzero(&g_hook, sizeof(g_hook));
	g_hook.hk_valid = 1;
	/* Direct default-message guards and first-time route creation. */
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_NODE_UP, 0, M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	ng_btsocket_iso_default_msg_input(msg, NULL);
	g_hook.hk_valid = 0;
	ng_btsocket_iso_default_msg_input(msg, &g_hook);
	g_hook.hk_valid = 1;
	ng_btsocket_iso_default_msg_input(msg, &g_hook);
	NG_FREE_MSG(msg);

	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_NODE_UP,
	    sizeof(ng_hci_node_up_ep), M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	/* An all-zero controller address must not create a route. */
	bzero(msg->data, sizeof(ng_hci_node_up_ep));
	ng_btsocket_iso_default_msg_input(msg, &g_hook);
	ATF_CHECK(NG_HOOK_PRIVATE(&g_hook) == NULL);
	NG_FREE_MSG(msg);

	/* A queued unknown message traverses rcvmsg -> input -> default. */
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, 0x7fffffff, 0, M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	item = calloc(1, sizeof(*item));
	ATF_REQUIRE(item != NULL);
	item->msg = msg;
	item->el_flags = NGQF_MESG;
	ATF_CHECK_EQ(0, ng_btsocket_iso_node_rcvmsg(ng_btsocket_iso_node,
	    item, &g_hook));
	ng_btsocket_iso_input(NULL, 0);

	/* Queue each LP command through the public receive path so the input
	 * task's LP/default discriminator is covered as well as its handlers. */
	NG_HOOK_SET_PRIVATE(&g_hook, &g_rt);
	for (uint32_t cmd = NGM_HCI_LP_CON_CFM;
	    cmd <= NGM_HCI_LP_DISCON_IND; cmd++) {
		NG_MKMESSAGE(msg, NGM_HCI_COOKIE, cmd, 0, M_NOWAIT);
		ATF_REQUIRE(msg != NULL);
		item = calloc(1, sizeof(*item));
		ATF_REQUIRE(item != NULL);
		item->msg = msg;
		item->el_flags = NGQF_MESG;
		ATF_CHECK_EQ(0, ng_btsocket_iso_node_rcvmsg(
		    ng_btsocket_iso_node, item, &g_hook));
		ng_btsocket_iso_input(NULL, 0);
	}

	/* A queued short data packet reaches the ISO framing length guard. */
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	m->m_len = m->m_pkthdr.len = 1;
	item = calloc(1, sizeof(*item));
	ATF_REQUIRE(item != NULL);
	item->m = m;
	item->el_flags = NGQF_DATA;
	ATF_CHECK_EQ(0, ng_btsocket_iso_node_rcvdata(&g_hook, item));
	ng_btsocket_iso_input(NULL, 0);

	/* Invalid cookies are rejected before queueing. */
	NG_MKMESSAGE(msg, 0xdeadbeef, 1, 0, M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	item = calloc(1, sizeof(*item));
	ATF_REQUIRE(item != NULL);
	item->msg = msg;
	ATF_CHECK_EQ(EINVAL, ng_btsocket_iso_node_rcvmsg(
	    ng_btsocket_iso_node, item, &g_hook));
	NG_FREE_MSG(msg);

	/* LP wrapper drops missing routes and dispatches unknown commands. */
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_CFM, 0, M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	ng_btsocket_iso_lp_msg_input(msg, NULL);
	bzero(&bad_hook, sizeof(bad_hook));
	bad_hook.hk_valid = 1;
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_CFM, 0, M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	ng_btsocket_iso_lp_msg_input(msg, &bad_hook);
	NG_HOOK_SET_PRIVATE(&g_hook, &g_rt);
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, 0x7fffffff, 0, M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	ng_btsocket_iso_lp_msg_input(msg, &g_hook);

	/* Route cleanup closes dependent sockets, then removes the dead route. */
	rt = calloc(1, sizeof(*rt));
	ATF_REQUIRE(rt != NULL);
	rt->hook = &bad_hook;
	rt->src = g_src;
	bad_hook.hk_valid = 0;
	NG_HOOK_SET_PRIVATE(&bad_hook, rt);
	LIST_INSERT_HEAD(&ng_btsocket_iso_rt, rt, next);
	pcb = make_open_pcb(0x88);
	pcb->rt = rt;
	pcb->flags |= NG_BTSOCKET_ISO_TIMO;
	ng_btsocket_iso_rtclean(NULL, 0);
	ATF_CHECK_EQ(NG_BTSOCKET_ISO_CLOSED, pcb->state);
	ATF_CHECK_EQ(ENETDOWN, pcb->so->so_error);
	ATF_CHECK(pcb->rt == NULL);
	ATF_CHECK(NG_HOOK_PRIVATE(&bad_hook) == NULL);
}

ATF_TC_WITHOUT_HEAD(fault_and_dispatch_matrix);
ATF_TC_BODY(fault_and_dispatch_matrix, tc)
{
	ng_btsocket_iso_pcb_p pcb;
	struct ng_item *item;
	struct ng_mesg *msg;
	ng_hci_lp_con_cfm_ep *cfm;
	ng_hci_lp_con_ind_ep *ind;
	ng_hci_lp_discon_ind_ep *dis;
	ng_hci_node_up_ep *up;
	struct mbuf *m;
	struct socket bare;
	struct thread td;
	struct ng_hook alloc_hook;
	struct socket *child;
	ng_btsocket_iso_pcb_p child_pcb;
	node_p oldnode;

	harness_reset();
	ng_btsocket_iso_debug_level = NG_BTSOCKET_INFO_LEVEL;

	/* Node replacement and module initialization must leave no stale node. */
	oldnode = ng_btsocket_iso_node;
	g_make_node_error = ENOMEM;
	ATF_CHECK_EQ(ENOMEM, ng_btsocket_iso_node_shutdown(oldnode));
	ATF_CHECK(ng_btsocket_iso_node == NULL);
	ng_btsocket_iso_node = oldnode;
	g_make_node_error = 0;
	g_name_node_error = EIO;
	ATF_CHECK_EQ(EIO, ng_btsocket_iso_node_shutdown(oldnode));
	ATF_CHECK(ng_btsocket_iso_node == NULL);

	g_name_node_error = 0;
	g_newtype_error = EIO;
	ng_btsocket_iso_init(NULL);
	ATF_CHECK(ng_btsocket_iso_node == NULL);
	g_newtype_error = 0;
	g_make_node_error = ENOMEM;
	ng_btsocket_iso_init(NULL);
	ATF_CHECK(ng_btsocket_iso_node == NULL);
	g_make_node_error = 0;
	g_name_node_error = EIO;
	ng_btsocket_iso_init(NULL);
	ATF_CHECK(ng_btsocket_iso_node == NULL);
	g_name_node_error = 0;
	ng_btsocket_iso_init(NULL);
	ATF_REQUIRE(ng_btsocket_iso_node != NULL);
	ng_btsocket_iso_debug_level = NG_BTSOCKET_INFO_LEVEL;

	/* Both receive queues reject a new item at their configured bound. */
	ng_btsocket_iso_queue.len = ng_btsocket_iso_queue.maxlen;
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_NODE_UP, 0, M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	item = calloc(1, sizeof(*item));
	ATF_REQUIRE(item != NULL);
	item->msg = msg;
	ATF_CHECK_EQ(ENOBUFS, ng_btsocket_iso_node_rcvmsg(
	    ng_btsocket_iso_node, item, &g_hook));
	NG_FREE_MSG(msg);
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	item = calloc(1, sizeof(*item));
	ATF_REQUIRE(item != NULL);
	item->m = m;
	ATF_CHECK_EQ(ENOBUFS, ng_btsocket_iso_node_rcvdata(&g_hook, item));
	m_freem(m);
	ng_btsocket_iso_queue.len = 0;

	bzero(&g_rt, sizeof(g_rt));
	bcopy(&g_src, &g_rt.src, sizeof(g_rt.src));
	bzero(&g_hook, sizeof(g_hook));
	g_hook.hk_valid = 1;
	g_rt.hook = &g_hook;
	NG_HOOK_SET_PRIVATE(&g_hook, &g_rt);

	/* A valid NODE_UP cleanly abandons route creation on allocation failure. */
	bzero(&alloc_hook, sizeof(alloc_hook));
	alloc_hook.hk_valid = 1;
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_NODE_UP,
	    sizeof(*up), M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	up = (ng_hci_node_up_ep *)msg->data;
	up->bdaddr = g_src;
	g_kernel_malloc_fail = 1;
	ng_btsocket_iso_default_msg_input(msg, &alloc_hook);
	ATF_CHECK(NG_HOOK_PRIVATE(&alloc_hook) == NULL);
	NG_FREE_MSG(msg);

	/* Exercise every successful LP dispatcher arm with unmatched events. */
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_CFM,
	    sizeof(*cfm), M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	cfm = (ng_hci_lp_con_cfm_ep *)msg->data;
	memset(&cfm->bdaddr, 0xee, sizeof(cfm->bdaddr));
	ng_btsocket_iso_lp_msg_input(msg, &g_hook);
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_IND,
	    sizeof(*ind), M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	ng_btsocket_iso_lp_msg_input(msg, &g_hook);
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_DISCON_IND,
	    sizeof(*dis), M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	ng_btsocket_iso_lp_msg_input(msg, &g_hook);

	/* Matching confirmation in the wrong state is rejected. */
	pcb = make_open_pcb(0x77);
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_CFM,
	    sizeof(*cfm), M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	cfm = (ng_hci_lp_con_cfm_ep *)msg->data;
	cfm->bdaddr = pcb->dst;
	ATF_CHECK_EQ(ENOENT, ng_btsocket_iso_process_lp_con_cfm(msg, &g_rt));
	NG_FREE_MSG(msg);

	/* Completion accounting handles excess credits with an empty ring. */
	g_rt.pending = 0;
	sync_completed(0x77, 2);
	ATF_CHECK_EQ(0, g_rt.pending);

	/* A wildcard listener adopts the route address and closes a child when
	 * the controller response cannot be emitted. */
	child = attach_socket();
	child_pcb = so2iso_pcb(child);
	ATF_REQUIRE(child_pcb != NULL);
	bzero(&pcb->src, sizeof(pcb->src));
	pcb->so->so_listening = 1;
	g_sonewconn_result = child;
	g_sendmsg_error = EIO;
	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_IND,
	    sizeof(*ind), M_NOWAIT);
	ATF_REQUIRE(msg != NULL);
	ind = (ng_hci_lp_con_ind_ep *)msg->data;
	memset(&ind->bdaddr, 0x42, sizeof(ind->bdaddr));
	ATF_CHECK_EQ(EIO, ng_btsocket_iso_process_lp_con_ind(msg, &g_rt));
	ATF_CHECK_EQ(NG_BTSOCKET_ISO_CLOSED, child_pcb->state);
	ATF_CHECK_EQ(EIO, child->so_error);
	ATF_CHECK_EQ(0, bcmp(&child_pcb->src, &g_src, sizeof(g_src)));
	NG_FREE_MSG(msg);
	pcb->so->so_listening = 0;
	g_sendmsg_error = 0;

	/* All outbound control encoders propagate allocation and send faults. */
	mtx_lock(&pcb->pcb_mtx);
	g_message_alloc_fail = 1;
	ATF_CHECK_EQ(ENOMEM, ng_btsocket_iso_send_lp_con_req(pcb));
	g_message_alloc_fail = 1;
	ATF_CHECK_EQ(ENOMEM, ng_btsocket_iso_send_lp_discon_req(pcb));
	mtx_unlock(&pcb->pcb_mtx);
	g_message_alloc_fail = 1;
	ATF_CHECK_EQ(ENOMEM,
	    ng_btsocket_iso_send_lp_con_rsp(&g_rt, &pcb->dst,
	    pcb->con_handle, 0));
	g_sendmsg_error = EIO;
	mtx_lock(&pcb->pcb_mtx);
	ATF_CHECK_EQ(EIO, ng_btsocket_iso_send_lp_con_req(pcb));
	ATF_CHECK_EQ(EIO, ng_btsocket_iso_send_lp_discon_req(pcb));
	mtx_unlock(&pcb->pcb_mtx);
	ATF_CHECK_EQ(EIO,
	    ng_btsocket_iso_send_lp_con_rsp(&g_rt, &pcb->dst,
	    pcb->con_handle, 0));
	g_sendmsg_error = 0;

	/* Ring saturation and attach precondition/allocation failures. */
	pcb->frag_ring_head = NG_BTSOCKET_ISO_FRAG_RING_SZ - 1;
	pcb->frag_ring_tail = 0;
	ATF_CHECK_EQ(ENOBUFS, ng_btsocket_iso_frag_ring_put(pcb, 1, 1));
	bzero(&bare, sizeof(bare));
	bare.so_type = SOCK_SEQPACKET;
	oldnode = ng_btsocket_iso_node;
	ng_btsocket_iso_node = NULL;
	ATF_CHECK_EQ(EPROTONOSUPPORT,
	    ng_btsocket_iso_attach(&bare, BLUETOOTH_PROTO_ISO, &td));
	ng_btsocket_iso_node = oldnode;
	bare.so_type = SOCK_STREAM;
	ATF_CHECK_EQ(ESOCKTNOSUPPORT,
	    ng_btsocket_iso_attach(&bare, BLUETOOTH_PROTO_ISO, &td));
	bare.so_type = SOCK_SEQPACKET;
	bare.so_pcb = pcb;
	ATF_CHECK_EQ(EISCONN,
	    ng_btsocket_iso_attach(&bare, BLUETOOTH_PROTO_ISO, &td));
	bare.so_pcb = NULL;
	bare.so_snd.sb_hiwat = bare.so_rcv.sb_hiwat = 1;
	g_kernel_malloc_fail = 1;
	ATF_CHECK_EQ(ENOMEM,
	    ng_btsocket_iso_attach(&bare, BLUETOOTH_PROTO_ISO, &td));

	harness_reset();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, send2_frag_overflow_bounded);
	ATF_TP_ADD_TC(tp, send2_complete_sdu);
	ATF_TP_ADD_TC(tp, send2_pkt_size_boundaries);
	ATF_TP_ADD_TC(tp, send2_partial_batch_completion);
	ATF_TP_ADD_TC(tp, fragment_ring_full_width_count);
	ATF_TP_ADD_TC(tp, node_up_clamps_pkt_size);
	ATF_TP_ADD_TC(tp, data_input_first_last_bounded);
	ATF_TP_ADD_TC(tp, data_input_ts_on_continuation);
	ATF_TP_ADD_TC(tp, data_input_sdu_length_mismatch);
	ATF_TP_ADD_TC(tp, data_input_lost_status_aborts_reassembly);
	ATF_TP_ADD_TC(tp, data_input_rejection_and_recovery_matrix);
	ATF_TP_ADD_TC(tp, connect_state_machine);
	ATF_TP_ADD_TC(tp, sockaddr_and_option_edges);
	ATF_TP_ADD_TC(tp, socket_api_lifecycle_matrix);
	ATF_TP_ADD_TC(tp, socket_api_guard_completion);
	ATF_TP_ADD_TC(tp, socket_send_entry_matrix);
	ATF_TP_ADD_TC(tp, lp_message_and_timeout_matrix);
	ATF_TP_ADD_TC(tp, node_queue_init_and_route_cleanup);
	ATF_TP_ADD_TC(tp, fault_and_dispatch_matrix);

	return (atf_no_error());
}
