/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Assertion-based (known-answer) ATF conformance tests for the kernel L2CAP
 * LE Credit-Based (CoC, code 0x14) and Enhanced Credit-Based (ECRED, code
 * 0x17) *data plane*: SDU<->K-frame segmentation/reassembly, credit flow
 * control, channel lifecycle, and the RTX/ERTX signalling guard timers.
 *
 * Where l2cap_sig_test.c / l2cap_sig_rsp_test.c #include ONLY the signalling
 * decoder TU (ng_l2cap_evnt.c) against a flat, hand-rolled channel/command
 * registry, the credit *data path* lives in ng_l2cap_ulpi.c (write/receive),
 * ng_l2cap_cmds.c (con_wakeup segmentation + command_timeout dispatch) and
 * ng_l2cap_misc.c (channel/command allocators + the real RTX/ERTX timeout
 * arming).  None of those TUs are compiled by the signalling tests, so their
 * branch coverage is 0.
 *
 * Technique (extends the sig-test shim): instead of neutralising the l2cap
 * headers and re-declaring cut-down structs, this program keeps the REAL
 * l2cap headers (ng_l2cap_var.h/cmds.h/evnt.h/llpi.h/ulpi.h/misc.h) and the
 * REAL netgraph-bluetooth UAPI, and only fakes the handful of kernel
 * primitives the four TUs bottom out in:
 *
 *   - a userspace malloc-backed struct mbuf plus m_split/m_cat/m_adj/... and
 *     the M_PREPEND / MGETHDR / mtod / NG_FREE_M macros,
 *   - kernel malloc()/free() (3-/2-arg) mapped onto calloc()/free(),
 *   - a loopback ng_l2cap_lp_send() that CAPTURES every emitted K-frame /
 *     C-frame (dcid + bytes) so a TX SDU's segmentation is observable, and
 *     leaves a placeholder ACL mbuf in con->tx_pkt so con_wakeup's
 *     save/restore chaining runs unchanged,
 *   - ng_l2cap_lp_deliver() wired straight to ng_l2cap_con_wakeup() (the real
 *     segmentation/dispatch loop in ng_l2cap_cmds.c),
 *   - a manually-fireable fake callout registry replacing ng_callout()/
 *     ng_uncallout() so RTX/ERTX (Core Spec Vol 3 Part A Section 6.2) expiry
 *     is driven on demand via fire_callouts(),
 *   - NG_SEND_MSG_HOOK / NG_SEND_DATA_ONLY sinks that record the L2CA_*
 *     confirmations and the reassembled SDU delivered upstream.
 *
 * The four kernel TUs are then #included after the shim.  ng_l2cap_llpi.c is
 * NOT compiled; its lp_send/lp_deliver/lp_con_* entry points are provided as
 * the loopback stubs above.
 *
 * Every expected value is taken from the Core Spec Vol 3 Part A
 * (/usr/src/bluetooth-specs/Core_Specification_6_3.txt), cited per case, and
 * is NEVER captured from the decoder's current output.
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/queue.h>

#include <sys/resource.h>
#include <sys/wait.h>

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <atf-c.h>

#include "spec_oracles.h"

#define L2DATA_ENUM(name, value) L2DATA_##name = value,
enum {
	BT_CORE63_L2CAP_CID_ORACLES(L2DATA_ENUM)
	BT_CORE63_L2CAP_COMMAND_ORACLES(L2DATA_ENUM)
	BT_CORE63_L2CAP_RESULT_ORACLES(L2DATA_ENUM)
	BT_ASSIGNED_EATT_PSM_ORACLES(L2DATA_ENUM)
	L2DATA_CONNECTION_SUCCESS = BT_CORE63_L2CAP_CONNECTION_SUCCESS,
	L2DATA_CONNECTION_PENDING = BT_CORE63_L2CAP_CONNECTION_PENDING,
	L2DATA_CONNECTION_PSM_NOT_SUPPORTED =
	    BT_CORE63_L2CAP_CONNECTION_PSM_NOT_SUPPORTED,
	L2DATA_CREDIT_COUNT_MAX = BT_CORE63_L2CAP_CREDIT_COUNT_MAX,
	L2DATA_LE_COC_MPS_MIN = BT_CORE63_L2CAP_LE_COC_MPS_MIN,
	/* FreeBSD receive-window policy, not a Core-mandated credit grant. */
	L2DATA_IMPL_INITIAL_CREDITS = 65,
	L2DATA_IMPL_WRITE_SUCCESS = 0,
};
#undef L2DATA_ENUM

/* ---------------------------------------------------------------------- */
/* Neutralise the kernel-only primitive headers the four TUs include.     */
/* ---------------------------------------------------------------------- */
#define _SYS_SYSTM_H_
#define _SYS_KERNEL_H_
#define _SYS_MALLOC_H_
#define _SYS_MBUF_H_
#define _SYS_CALLOUT_H_
#define _SYS_SDT_H
#define _NETGRAPH_NETGRAPH_H_
#define _NETGRAPH_NG_MESSAGE_H_

/* ----- netgraph glue types (normally netgraph/netgraph.h) ------------- */
typedef void *	node_p;
typedef void *	hook_p;

#define NG_NODE_NAME(n)		"l2cap_ut"
#define NG_NODE_NOT_VALID(n)	((n) == NULL)
#define NG_NODE_PRIVATE(n)	((void *)(n))
#define NG_HOOK_NOT_VALID(h)	(0)
#define NG_HOOK_NAME(h)		"l2c"

#define hz			1000

/* ----- SDT probes: compile to nothing (normally sys/sdt.h) ------------ */
#define SDT_PROVIDER_DECLARE(prov)			struct __sdt_hack
#define SDT_PROBE_DECLARE(prov, mod, func, name)	struct __sdt_hack
#define SDT_PROBE_DEFINE2(prov, mod, func, name, a0, a1) \
							struct __sdt_hack
#define SDT_PROBE_DEFINE3(prov, mod, func, name, a0, a1, a2) \
							struct __sdt_hack
#define SDT_PROBE2(prov, mod, func, name, a0, a1)	do { } while (0)
#define SDT_PROBE3(prov, mod, func, name, a0, a1, a2)	do { } while (0)

/* ----- malloc/mbuf tunables (normally sys/malloc.h, sys/mbuf.h) ------- */
#define M_NOWAIT	0x0001
#define M_WAITOK	0x0002
#define M_ZERO		0x0100
#define MT_DATA		1
#define M_NETGRAPH	0

/*
 * Kernel malloc()/free() take a type + flags; map them onto calloc()/free().
 * The self-referential function-macro trick: `free(p)` (1 arg) and
 * `malloc(n)` (1 arg) do NOT match these 2-/3-parameter macros, so libc's
 * own allocators (and atf's) are untouched -- only the kernel-style 2-/3-arg
 * calls in the TUs are rewritten.  All kernel allocations here pass M_ZERO,
 * which calloc() honours unconditionally.
 */
#define malloc(sz, type, flags)	calloc(1, (sz))
#define free(ptr, type)		free((ptr))

#define KASSERT(exp, msg)	do { } while (0)

/* ----- fake struct callout (normally sys/callout.h) ------------------- */
struct callout {
	int		c_pending;
	node_p		c_node;
	void	      (*c_fn)(node_p, hook_p, void *, int);
	void	       *c_arg1;
	int		c_arg2;
};
#define callout_pending(c)	((c)->c_pending)
#define callout_init(c, mp)	memset((c), 0, sizeof(*(c)))
#define ng_callout_init(c)	memset((c), 0, sizeof(*(c)))

/* ---------------------------------------------------------------------- */
/* Userspace mbuf.                                                         */
/* ---------------------------------------------------------------------- */
#define NG_MBUF_STORE	4096
#define NG_MBUF_HEAD	64	/* leading headroom for prepends */

#define M_PROTO2	0x00000004

struct mbuf {
	int		m_len;
	int		m_flags;
	struct {
		int	len;
	}		m_pkthdr;
	struct mbuf    *m_next;		/* intra-record (unused, kept NULL) */
	struct mbuf    *m_nextpkt;	/* ACL packet chain (tx_pkt) */
	unsigned char  *m_data;
	unsigned char	m_store[NG_MBUF_STORE];
};

static struct mbuf *
ng_mbuf_alloc(void)
{
	struct mbuf	*m;

	m = calloc(1, sizeof(*m));
	if (m != NULL)
		m->m_data = m->m_store + NG_MBUF_HEAD;
	return (m);
}

static void
m_freem(struct mbuf *m)
{
	struct mbuf	*n;

	while (m != NULL) {
		n = m->m_next;
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

static struct mbuf *
m_pullup(struct mbuf *m, int s)
{

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

	memcpy(dst, m->m_data + off, (size_t)len);
}

static struct mbuf *
m_split(struct mbuf *m, int off, int how)
{
	struct mbuf	*n;
	int		 tail;

	(void)how;
	if (m == NULL || off < 0 || off > m->m_len)
		return (NULL);
	tail = m->m_len - off;
	n = ng_mbuf_alloc();
	if (n == NULL)
		return (NULL);
	memcpy(n->m_data, m->m_data + off, (size_t)tail);
	n->m_len = n->m_pkthdr.len = tail;
	m->m_len = m->m_pkthdr.len = off;
	return (n);
}

static void
m_cat(struct mbuf *m, struct mbuf *n)
{
	int		room, cp;

	if (m == NULL || n == NULL) {
		if (n != NULL)
			m_freem(n);
		return;
	}
	room = NG_MBUF_STORE - (int)(m->m_data - m->m_store) - m->m_len;
	cp = n->m_len;
	if (cp > room)
		cp = room;
	if (cp > 0)
		memcpy(m->m_data + m->m_len, n->m_data, (size_t)cp);
	m->m_len += cp;
	/* Caller adjusts m_pkthdr.len itself (matches kernel m_cat usage). */
	m_freem(n);
}

static void
m_copyback(struct mbuf *m, int off, int len, const void *src)
{

	if (m == NULL || len <= 0)
		return;
	memcpy(m->m_data + off, src, (size_t)len);
	if (off + len > m->m_len)
		m->m_len = off + len;
	if (off + len > m->m_pkthdr.len)
		m->m_pkthdr.len = off + len;
}

#define mtod(m, t)		((t)((m)->m_data))
#define MGETHDR(m, how, type)	((m) = ng_mbuf_alloc())

/* M_PREPEND (normally sys/mbuf.h): grow towards the front. */
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
/* ng_mesg (normally netgraph/ng_message.h).                              */
/* ---------------------------------------------------------------------- */
#define NGF_RESP	0x00000001

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
	char		data[0];
};

#define NG_MKMESSAGE(msg, cookie, cmdid, len, how)	do {		\
	(msg) = calloc(1, sizeof(struct ng_mesg) + (len));		\
	if ((msg) != NULL) {						\
		(msg)->header.typecookie = (cookie);			\
		(msg)->header.cmd = (cmdid);				\
		(msg)->header.arglen = (len);				\
	}								\
} while (0)

/* Forward decls of the capture sinks (defined after the UAPI is visible). */
static void	ng_ut_capture_msg(struct ng_mesg *msg);
static void	ng_ut_capture_data(struct mbuf *m);

#define NG_SEND_MSG_HOOK(error, node, msg, hook, flags)	do {		\
	(error) = 0;							\
	ng_ut_capture_msg((msg));					\
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
/* Real UAPI + real l2cap headers.                                        */
/* ---------------------------------------------------------------------- */
#include <netgraph/bluetooth/include/ng_bluetooth.h>
#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>
#include <netgraph/bluetooth/l2cap/ng_l2cap_var.h>
#include <netgraph/bluetooth/l2cap/ng_l2cap_cmds.h>
#include <netgraph/bluetooth/l2cap/ng_l2cap_evnt.h>
#include <netgraph/bluetooth/l2cap/ng_l2cap_llpi.h>
#include <netgraph/bluetooth/l2cap/ng_l2cap_ulpi.h>
#include <netgraph/bluetooth/l2cap/ng_l2cap_misc.h>

/* ---------------------------------------------------------------------- */
/* Capture registries.                                                    */
/* ---------------------------------------------------------------------- */

/* Every frame handed to the loopback ng_l2cap_lp_send(). */
struct cap_frame {
	u_int16_t	dcid;
	int		len;
	u_int8_t	data[600];
};
#define MAX_FRAMES	32
static struct cap_frame	g_frames[MAX_FRAMES];
static int		g_nframes;

/* Every SDU delivered upstream via NG_SEND_DATA_ONLY (idtype prefix kept). */
struct cap_data {
	int		len;
	u_int8_t	data[1024];
};
#define MAX_DATA	16
static struct cap_data	g_data[MAX_DATA];
static int		g_ndata;

/* L2CA_WriteRsp confirmations. */
static int		g_write_n;
static int		g_write_result;
static int		g_write_length;
static u_int16_t	g_write_lcid;
static u_int16_t	g_write_idtype;

/* Generic upstream-message accounting. */
static int		g_nmsg;
static uint32_t		g_last_msg_cmd;

/* Knob: force ng_l2cap_lp_send() to fail (exercise NO_RESOURCES arms). */
static int		g_lp_send_err;

static void
ng_ut_capture_msg(struct ng_mesg *msg)
{

	if (msg == NULL)
		return;
	g_nmsg++;
	g_last_msg_cmd = msg->header.cmd;
	if (msg->header.cmd == NGM_L2CAP_L2CA_WRITE) {
		ng_l2cap_l2ca_write_op	*op =
		    (ng_l2cap_l2ca_write_op *)msg->data;

		g_write_n++;
		g_write_result = op->result;
		g_write_length = op->length;
		g_write_lcid = op->lcid;
		g_write_idtype = op->idtype;
	}
}

static void
ng_ut_capture_data(struct mbuf *m)
{
	struct cap_data	*d;
	int		 n;

	if (m == NULL || g_ndata >= MAX_DATA)
		return;
	d = &g_data[g_ndata++];
	n = m->m_len;
	if (n > (int)sizeof(d->data))
		n = (int)sizeof(d->data);
	d->len = n;
	memcpy(d->data, m->m_data, (size_t)n);
}

static u_int16_t
frame_le16(const struct cap_frame *f, int off)
{

	return ((u_int16_t)(f->data[off] | (f->data[off + 1] << 8)));
}

/* ---------------------------------------------------------------------- */
/* Fake callout registry -- manually fireable timers.                     */
/* ---------------------------------------------------------------------- */
#define MAX_CALLOUTS	16
static struct callout  *g_callouts[MAX_CALLOUTS];
static int		g_ncallouts;

int
ng_callout(struct callout *c, node_p node, hook_p hook, int ticks,
    void (*fn)(node_p, hook_p, void *, int), void *arg1, int arg2)
{
	int	i;

	(void)hook;
	(void)ticks;
	c->c_pending = 1;
	c->c_node = node;
	c->c_fn = fn;
	c->c_arg1 = arg1;
	c->c_arg2 = arg2;

	for (i = 0; i < g_ncallouts; i++)
		if (g_callouts[i] == c)
			return (0);
	if (g_ncallouts < MAX_CALLOUTS)
		g_callouts[g_ncallouts++] = c;
	return (0);
}

static void
callout_forget(struct callout *c)
{
	int	i;

	for (i = 0; i < g_ncallouts; i++) {
		if (g_callouts[i] == c) {
			g_callouts[i] = g_callouts[--g_ncallouts];
			return;
		}
	}
}

int
ng_uncallout(struct callout *c, node_p node)
{

	(void)node;
	if (!c->c_pending)
		return (0);		/* already fired / not pending */
	c->c_pending = 0;
	callout_forget(c);
	return (1);			/* successfully stopped */
}

int
ng_uncallout_drain(struct callout *c, node_p node)
{

	return (ng_uncallout(c, node));
}

/* Count currently-armed callouts. */
static int
callouts_pending(void)
{

	return (g_ncallouts);
}

/* Fire every armed callout (deferred timer expiry).  Returns # fired. */
static int
fire_callouts(void)
{
	struct callout	*snap[MAX_CALLOUTS];
	int		 n, i;

	n = g_ncallouts;
	for (i = 0; i < n; i++)
		snap[i] = g_callouts[i];
	g_ncallouts = 0;
	for (i = 0; i < n; i++) {
		snap[i]->c_pending = 0;
		if (snap[i]->c_fn != NULL)
			snap[i]->c_fn(snap[i]->c_node, NULL,
			    snap[i]->c_arg1, snap[i]->c_arg2);
	}
	return (n);
}

/* ---------------------------------------------------------------------- */
/* llpi.c stand-ins (llpi.c itself is NOT compiled).                      */
/* ---------------------------------------------------------------------- */
static struct ng_l2cap		g_l2cap;

/*
 * Loopback ng_l2cap_lp_send(): capture the emitted frame, then leave a
 * placeholder ACL mbuf in con->tx_pkt so con_wakeup's save/restore chaining
 * (which asserts tx_pkt == NULL before each send and re-links tx_pkt via
 * m_nextpkt afterwards) runs exactly as in the kernel.  The caller-owned
 * data mbuf m is consumed here, matching the real lp_send contract.
 */
int
ng_l2cap_lp_send(ng_l2cap_con_p con, u_int16_t dcid, struct mbuf *m)
{
	struct cap_frame	*f;
	struct mbuf		*ph;
	int			 n;

	if (m != NULL && g_nframes < MAX_FRAMES) {
		f = &g_frames[g_nframes++];
		f->dcid = dcid;
		n = m->m_len;
		if (n > (int)sizeof(f->data))
			n = (int)sizeof(f->data);
		f->len = n;
		memcpy(f->data, m->m_data, (size_t)n);
	}
	m_freem(m);

	if (g_lp_send_err != 0)
		return (g_lp_send_err);

	/* Placeholder ACL packet so tx_pkt chaining is exercised. */
	ph = ng_mbuf_alloc();
	con->tx_pkt = ph;
	return (0);
}

void
ng_l2cap_lp_deliver(ng_l2cap_con_p con)
{

	ng_l2cap_con_wakeup(con);
}

int
ng_l2cap_lp_con_req(ng_l2cap_p l2cap, bdaddr_p bdaddr, int type, uint8_t own_address_type __unused)
{

	(void)l2cap;
	(void)bdaddr;
	(void)type;
	return (0);
}

int
ng_l2cap_lp_con_update(ng_l2cap_con_p con, u_int16_t a, u_int16_t b,
    u_int16_t c, u_int16_t d)
{

	(void)con;
	(void)a;
	(void)b;
	(void)c;
	(void)d;
	return (0);
}

void
ng_l2cap_process_lp_timeout(node_p node, hook_p hook, void *a1, int a2)
{

	(void)node;
	(void)hook;
	(void)a1;
	(void)a2;
}

void
ng_l2cap_process_discon_timeout(node_p node, hook_p hook, void *a1, int a2)
{

	(void)node;
	(void)hook;
	(void)a1;
	(void)a2;
}

/* bluetooth_* timeout knobs (normally ng_bluetooth.c). */
uint32_t bluetooth_hci_connect_timeout(void)	{ return (5); }
uint32_t bluetooth_l2cap_rtx_timeout(void)	{ return (3); }
uint32_t bluetooth_l2cap_ertx_timeout(void)	{ return (7); }

/* ---------------------------------------------------------------------- */
/* The code under test: the four data-path TUs.                           */
/* ---------------------------------------------------------------------- */
#include "ng_l2cap_misc.c"
#include "ng_l2cap_cmds.c"
#include "ng_l2cap_ulpi.c"
#include "ng_l2cap_evnt.c"
/* ---------------------------------------------------------------------- */

/* ====================================================================== */
/* Harness                                                                */
/* ====================================================================== */

static bdaddr_t	g_addr = { { 1, 2, 3, 4, 5, 6 } };

static void
reset_all(void)
{

	memset(g_frames, 0, sizeof(g_frames));
	g_nframes = 0;
	memset(g_data, 0, sizeof(g_data));
	g_ndata = 0;
	g_write_n = g_write_result = g_write_length = 0;
	g_write_lcid = g_write_idtype = 0;
	g_nmsg = 0;
	g_last_msg_cmd = 0;
	g_lp_send_err = 0;
	g_ncallouts = 0;

	memset(&g_l2cap, 0, sizeof(g_l2cap));
	g_l2cap.node = (node_p)&g_l2cap;		/* NG_NODE_PRIVATE -> l2cap */
	g_l2cap.l2c = (hook_p)&g_l2cap;			/* upstream hook connected */
	LIST_INIT(&g_l2cap.con_list);
	LIST_INIT(&g_l2cap.chan_list);
}

static ng_l2cap_con_p
mk_con(u_int8_t linktype, u_int8_t encryption)
{
	ng_l2cap_con_p	con;

	con = ng_l2cap_new_con(&g_l2cap, &g_addr, linktype);
	ATF_REQUIRE(con != NULL);
	con->encryption = encryption;
	con->state = NG_L2CAP_CON_OPEN;
	return (con);
}

/*
 * Create an OPEN credit-based channel with fully-populated flow-control
 * parameters, as if a CoC/ECRED connect had just completed.
 */
static ng_l2cap_chan_p
mk_open_chan(ng_l2cap_con_p con, int idtype, u_int16_t dcid,
    u_int16_t mps_local, u_int16_t mps_remote,
    u_int16_t credits_local, u_int16_t credits_remote,
    u_int16_t imtu, u_int16_t omtu)
{
	ng_l2cap_chan_p	ch;

	ch = ng_l2cap_new_chan(&g_l2cap, con, NG_L2CAP_PSM_EATT, idtype);
	ATF_REQUIRE(ch != NULL);
	ch->dcid = dcid;
	ch->mps = mps_local;
	ch->mps_remote = mps_remote;
	ch->credits_local = credits_local;
	ch->credits_remote = credits_remote;
	ch->imtu = imtu;
	ch->omtu = omtu;
	ch->le_psm = NG_L2CAP_PSM_EATT;
	ch->state = NG_L2CAP_OPEN;
	return (ch);
}

/* Drive a raw L2CAP DATA frame (K-frame) into the receive path. */
static int
feed_data(ng_l2cap_con_p con, u_int16_t dcid, const u_int8_t *payload,
    int plen)
{
	struct mbuf	*m;
	ng_l2cap_hdr_t	*h;

	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	h = (ng_l2cap_hdr_t *)m->m_data;
	h->length = htole16((u_int16_t)plen);
	h->dcid = htole16(dcid);
	if (plen > 0)
		memcpy(m->m_data + sizeof(*h), payload, (size_t)plen);
	m->m_len = m->m_pkthdr.len = sizeof(*h) + plen;
	con->rx_pkt = m;
	return (ng_l2cap_l2ca_receive(con));
}

/* Drive one signalling C-frame into ng_l2cap_receive() (LE or BR/EDR). */
static void
feed_sig(ng_l2cap_con_p con, u_int16_t sig_cid, u_int8_t code, u_int8_t ident,
    const u_int8_t *payload, int plen)
{
	struct mbuf		*m;
	ng_l2cap_hdr_t		*lh;
	ng_l2cap_cmd_hdr_t	*ch;

	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	lh = (ng_l2cap_hdr_t *)m->m_data;
	lh->length = htole16((u_int16_t)(4 + plen));
	lh->dcid = htole16(sig_cid);
	ch = (ng_l2cap_cmd_hdr_t *)(m->m_data + 4);
	ch->code = code;
	ch->ident = ident;
	ch->length = htole16((u_int16_t)plen);
	if (plen > 0)
		memcpy(m->m_data + 8, payload, (size_t)plen);
	m->m_len = m->m_pkthdr.len = 8 + plen;
	con->rx_pkt = m;
	(void)ng_l2cap_receive(con);
}

/*
 * Issue an L2CA_Write of a SDU on channel scid, exercising ulpi.c write_req
 * plus the cmds.c con_wakeup segmentation loop.
 */
static int
do_write(ng_l2cap_con_p con, ng_l2cap_chan_p ch, const u_int8_t *sdu,
    int slen)
{
	struct mbuf		*m;
	ng_l2cap_l2ca_hdr_t	*h;

	(void)con;
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	h = (ng_l2cap_l2ca_hdr_t *)m->m_data;
	h->token = 0x1234;
	h->length = (u_int16_t)slen;
	h->lcid = ch->scid;
	h->idtype = ch->idtype;
	if (slen > 0)
		memcpy(m->m_data + sizeof(*h), sdu, (size_t)slen);
	m->m_len = m->m_pkthdr.len = sizeof(*h) + slen;
	return (ng_l2cap_l2ca_write_req(&g_l2cap, m));
}

/* Free any placeholder ACL mbufs a test left in con->tx_pkt. */
static void
drain_tx(ng_l2cap_con_p con)
{
	struct mbuf	*m, *n;

	for (m = con->tx_pkt; m != NULL; m = n) {
		n = m->m_nextpkt;
		m_freem(m);
	}
	con->tx_pkt = NULL;
}

/* Store a little-endian u16 at byte offset off. */
static void
w16(u_int8_t *b, int off, u_int16_t v)
{

	b[off] = (u_int8_t)(v & 0xff);
	b[off + 1] = (u_int8_t)((v >> 8) & 0xff);
}

/* Complete the upper-layer decision for an inbound dynamic channel. */
static int
respond_inbound(ng_l2cap_chan_p ch, u_int16_t result)
{
	ng_l2cap_l2ca_con_rsp_ip	ip;
	struct ng_mesg			*msg;
	int				 error;

	memset(&ip, 0, sizeof(ip));
	bcopy(&ch->con->remote, &ip.bdaddr, sizeof(ip.bdaddr));
	ip.ident = ch->ident;
	ip.linktype = ch->con->linktype;
	ip.lcid = ch->scid;
	ip.result = result;

	msg = calloc(1, sizeof(*msg) + sizeof(ip));
	ATF_REQUIRE(msg != NULL);
	msg->header.typecookie = NGM_L2CAP_COOKIE;
	msg->header.cmd = NGM_L2CAP_L2CA_CON_RSP;
	msg->header.arglen = sizeof(ip);
	msg->header.token = 0x2222;
	memcpy(msg->data, &ip, sizeof(ip));
	error = ng_l2cap_l2ca_con_rsp_req(&g_l2cap, msg);
	(free)(msg);
	return (error);
}

/* ====================================================================== */
/* CoC/ECRED data TX -- Core Spec Vol 3 Part A Sections 3.4, 10.1         */
/* ====================================================================== */

/*
 * §3.4.1 / §3.4.2: an outgoing SDU is segmented into K-frames.  "The first
 * K-frame of the SDU ... contains the L2CAP SDU Length field" (a 2-octet
 * little-endian total-SDU-length prefix); continuation K-frames do not.  The
 * K-frame Information payload shall not exceed the peer's MPS.  §10.1: each
 * K-frame consumes one credit from the credit count the peer granted us
 * (credits_remote).
 */
ATF_TC_WITHOUT_HEAD(tx_segments_sdu_len_prefix_and_credits);
ATF_TC_BODY(tx_segments_sdu_len_prefix_and_credits, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[50];
	int		i, total;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	/* mps_remote=23 (LE minimum) forces multi-frame segmentation. */
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, L2DATA_LE_COC_MPS_MIN, 65, 10, 512, 512);
	for (i = 0; i < (int)sizeof(sdu); i++)
		sdu[i] = (u_int8_t)i;

	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));

	/*
	 * SDU=50, MPS=23: first frame carries the 2-byte length + 21 data
	 * (payload 23), then 23, then 6 -> three K-frames.
	 */
	ATF_REQUIRE_EQ(3, g_nframes);
	/* First K-frame: SDU-Length prefix == total SDU size (50). */
	ATF_CHECK_EQ(50, frame_le16(&g_frames[0], 0));
	ATF_CHECK_EQ(0x0041, g_frames[0].dcid);		/* sent on peer DCID */
	ATF_CHECK_EQ(L2DATA_LE_COC_MPS_MIN, g_frames[0].len);
	ATF_CHECK_EQ(L2DATA_LE_COC_MPS_MIN, g_frames[1].len);
	ATF_CHECK_EQ(6, g_frames[2].len);		/* final remainder */

	/* Reassembled data (skip the 2-byte prefix on frame 0) matches. */
	total = (g_frames[0].len - 2) + g_frames[1].len + g_frames[2].len;
	ATF_CHECK_EQ(50, total);
	ATF_CHECK_EQ(0, memcmp(&g_frames[0].data[2], &sdu[0], 21));
	ATF_CHECK_EQ(0, memcmp(&g_frames[1].data[0], &sdu[21], 23));
	ATF_CHECK_EQ(0, memcmp(&g_frames[2].data[0], &sdu[44], 6));

	/* One credit consumed per K-frame: 10 - 3 == 7. */
	ATF_CHECK_EQ(7, ch->credits_remote);

	/* L2CA_WriteRsp reported success. */
	ATF_CHECK_EQ(1, g_write_n);
	ATF_CHECK_EQ(L2DATA_IMPL_WRITE_SUCCESS, g_write_result);

	drain_tx(con);
}

/*
 * §3.4.2 single-frame SDU: when the whole SDU (plus its 2-byte length prefix)
 * fits within one MPS, exactly one K-frame is emitted and one credit spent.
 */
ATF_TC_WITHOUT_HEAD(tx_single_kframe);
ATF_TC_BODY(tx_single_kframe, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[8] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 247, 65, 5, 512, 512);

	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));

	ATF_REQUIRE_EQ(1, g_nframes);
	ATF_CHECK_EQ(8, frame_le16(&g_frames[0], 0));	/* SDU-Length = 8 */
	ATF_CHECK_EQ(10, g_frames[0].len);		/* 2 + 8 */
	ATF_CHECK_EQ(4, ch->credits_remote);		/* 5 - 1 */
	ATF_CHECK_EQ(L2DATA_IMPL_WRITE_SUCCESS, g_write_result);

	drain_tx(con);
}

/*
 * §10.1: with zero peer-granted credits the sender "shall not send" a K-frame.
 * The write is refused up (L2CA_WriteRsp result = No Resources / ENOBUFS
 * internally) and no frame leaves.
 */
ATF_TC_WITHOUT_HEAD(tx_zero_credits_refused);
ATF_TC_BODY(tx_zero_credits_refused, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[4] = { 1, 2, 3, 4 };

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 247, 65, 0, 512, 512);

	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));

	ATF_CHECK_EQ(0, g_nframes);			/* nothing sent */
	ATF_CHECK_EQ(0, ch->credits_remote);		/* unchanged */
	ATF_CHECK_EQ(1, g_write_n);
	ATF_CHECK_EQ(NG_L2CAP_NO_RESOURCES, g_write_result);

	drain_tx(con);
}

/*
 * §10.1 mid-SDU credit exhaustion is a flow-control stall.  Preserve the
 * channel and unsent SDU, emit no premature WriteRsp, then resume exactly one
 * K-frame per peer-granted credit until the complete SDU is delivered.
 */
ATF_TC_WITHOUT_HEAD(tx_mid_sdu_exhaustion_stalls_and_resumes);
ATF_TC_BODY(tx_mid_sdu_exhaustion_stalls_and_resumes, tc)
{
	ng_l2cap_con_p con;
	ng_l2cap_chan_p ch;
	u_int8_t sdu[50], credit[4];
	int i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, L2DATA_LE_COC_MPS_MIN, 65, 1, 512, 512);
	for (i = 0; i < (int)sizeof(sdu); i++)
		sdu[i] = (u_int8_t)i;

	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));
	ATF_REQUIRE_EQ(1, g_nframes);
	ATF_CHECK_EQ(NG_L2CAP_OPEN, ch->state);
	ATF_CHECK(ch->tx_sdu_pending != NULL);
	ATF_CHECK_EQ(0, g_write_n);
	ATF_CHECK_EQ(50, frame_le16(&g_frames[0], 0));
	ATF_CHECK_EQ(0, memcmp(g_frames[0].data + 2, sdu, 21));

	/* Grant one credit: exactly one continuation, still incomplete. */
	/* Credit packet CID is the peer's Source CID, our channel DCID. */
	w16(credit, 0, ch->dcid);
	w16(credit, 2, 1);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_FLOW_CONTROL_CREDIT,
	    0x40, credit, sizeof(credit));
	ATF_REQUIRE_EQ(2, g_nframes);
	ATF_CHECK_EQ(L2DATA_LE_COC_MPS_MIN, g_frames[1].len);
	ATF_CHECK_EQ(0, memcmp(g_frames[1].data, sdu + 21, 23));
	ATF_CHECK(ch->tx_sdu_pending != NULL);
	ATF_CHECK_EQ(0, g_write_n);

	/* Final credit completes the SDU and only now acknowledges the write. */
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_FLOW_CONTROL_CREDIT,
	    0x41, credit, sizeof(credit));
	ATF_REQUIRE_EQ(3, g_nframes);
	ATF_CHECK_EQ(6, g_frames[2].len);
	ATF_CHECK_EQ(0, memcmp(g_frames[2].data, sdu + 44, 6));
	ATF_CHECK(ch->tx_sdu_pending == NULL);
	ATF_CHECK_EQ(NG_L2CAP_OPEN, ch->state);
	ATF_CHECK_EQ(1, g_write_n);
	ATF_CHECK_EQ(L2DATA_IMPL_WRITE_SUCCESS, g_write_result);
	ATF_CHECK_EQ((int)sizeof(sdu), g_write_length);

	drain_tx(con);
}

static void
check_tx_stalled_sdu_serializes(int idtype)
{
	ng_l2cap_con_p con;
	ng_l2cap_chan_p ch;
	u_int8_t first[50], second[4] = { 0xd0, 0xd1, 0xd2, 0xd3 };
	u_int8_t credit[4];
	int i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, idtype, 0x0041, 247,
	    L2DATA_LE_COC_MPS_MIN, 65, 1, 512, 512);
	for (i = 0; i < (int)sizeof(first); i++)
		first[i] = (u_int8_t)i;

	ATF_REQUIRE_EQ(0, do_write(con, ch, first, sizeof(first)));
	ATF_REQUIRE(ch->tx_sdu_pending != NULL);
	ATF_REQUIRE_EQ(1, g_nframes);
	drain_tx(con);

	/* A later socket record remains queued; it must not get a new SDU header. */
	ATF_REQUIRE_EQ(0, do_write(con, ch, second, sizeof(second)));
	ATF_CHECK_EQ(1, g_nframes);
	ATF_CHECK_EQ(0, g_write_n);
	ATF_CHECK(ch->tx_sdu_pending != NULL);

	/* Three credits finish the first SDU, leaving one for the queued second. */
	w16(credit, 0, ch->dcid);
	w16(credit, 2, 3);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_FLOW_CONTROL_CREDIT,
	    0x42, credit, sizeof(credit));
	ATF_CHECK(ch->tx_sdu_pending == NULL);
	ATF_REQUIRE_EQ(4, g_nframes);
	ATF_CHECK_EQ(0, memcmp(g_frames[1].data, first + 21, 23));
	ATF_CHECK_EQ(0, memcmp(g_frames[2].data, first + 44, 6));
	/* The queued SDU starts only after the continuation and final fragments. */
	ATF_CHECK_EQ(sizeof(second), frame_le16(&g_frames[3], 0));
	ATF_CHECK_EQ(0, memcmp(g_frames[3].data + 2, second, sizeof(second)));
	ATF_CHECK_EQ(2, g_write_n);
	ATF_CHECK_EQ(L2DATA_IMPL_WRITE_SUCCESS, g_write_result);
	drain_tx(con);
}

ATF_TC_WITHOUT_HEAD(tx_legacy_stalled_sdu_serializes_later_writes);
ATF_TC_BODY(tx_legacy_stalled_sdu_serializes_later_writes, tc)
{
	check_tx_stalled_sdu_serializes(NG_L2CAP_L2CA_IDTYPE_LE);
}

ATF_TC_WITHOUT_HEAD(tx_ecbfc_stalled_sdu_serializes_later_writes);
ATF_TC_BODY(tx_ecbfc_stalled_sdu_serializes_later_writes, tc)
{
	check_tx_stalled_sdu_serializes(NG_L2CAP_L2CA_IDTYPE_ECBFC);
}

/* ====================================================================== */
/* CoC/ECRED data RX -- Core Spec Vol 3 Part A Sections 3.4.3, 10.1       */
/* ====================================================================== */

/*
 * §3.4.3 reassembly: a SDU split across multiple K-frames is reassembled and
 * delivered once complete.  §10.1: each received K-frame consumes one local
 * credit (credits_local).  When the SDU completes and local credits have been
 * spent, an L2CAP_FLOW_CONTROL_CREDIT (code 0x16) is emitted to replenish the
 * peer (§4.24), carrying our SCID and the number of credits returned.
 */
ATF_TC_WITHOUT_HEAD(rx_reassembles_and_replenishes);
ATF_TC_BODY(rx_reassembles_and_replenishes, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	f0[12], f1[8];
	int		i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	/* local mps 247, local credits start at 10. */
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 247, 10, 65, 512, 512);
	scid = ch->scid;

	/* SDU total length 18: frame0 = [len=18][10 data], frame1 = [8 data]. */
	f0[0] = 18; f0[1] = 0;
	for (i = 0; i < 10; i++)
		f0[2 + i] = (u_int8_t)(0x10 + i);
	for (i = 0; i < 8; i++)
		f1[i] = (u_int8_t)(0x20 + i);

	ATF_REQUIRE_EQ(0, feed_data(con, scid, f0, sizeof(f0)));
	/* One frame consumed one local credit; SDU incomplete, nothing up. */
	ATF_CHECK_EQ(9, ch->credits_local);
	ATF_CHECK_EQ(0, g_ndata);

	ATF_REQUIRE_EQ(0, feed_data(con, scid, f1, sizeof(f1)));

	/*
	 * SDU complete and delivered upstream.  ng_l2cap_l2ca_receive()
	 * rebuilds an L2CAP-framed packet then prepends the 2-byte idtype
	 * tag, so the delivered buffer is [idtype(2)][L2CAP hdr(4)][SDU(18)].
	 */
	ATF_REQUIRE_EQ(1, g_ndata);
	ATF_CHECK_EQ(2 + 4 + 18, g_data[0].len);
	ATF_CHECK_EQ(0, memcmp(&g_data[0].data[6], &f0[2], 10));
	ATF_CHECK_EQ(0, memcmp(&g_data[0].data[16], &f1[0], 8));

	/* Local credits replenished back to the initial level. */
	ATF_CHECK_EQ(L2DATA_IMPL_INITIAL_CREDITS, ch->credits_local);

	/* A FLOW_CONTROL_CREDIT PDU was emitted on the LE signalling CID. */
	ATF_REQUIRE_EQ(1, g_nframes);
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_LESIGNAL_CID, g_frames[0].dcid);
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_FLOW_CONTROL_CREDIT,
	    g_frames[0].data[0]);
	ATF_CHECK_EQ(scid, frame_le16(&g_frames[0], 4));	/* our SCID */
	/* credits granted back = INITIAL - (10 - 2 consumed) = 65 - 8 = 57. */
	ATF_CHECK_EQ(L2DATA_IMPL_INITIAL_CREDITS - 8,
	    frame_le16(&g_frames[0], 6));

	drain_tx(con);
}

/* EATT data on a dynamic ECBFC CID must resolve to the ECBFC bearer. */
ATF_TC_WITHOUT_HEAD(rx_ecbfc_dynamic_cid_routes_to_bearer);
ATF_TC_BODY(rx_ecbfc_dynamic_cid_routes_to_bearer, tc)
{
	ng_l2cap_con_p con;
	ng_l2cap_chan_p ch;
	u_int8_t frame[6] = { 4, 0, 0xa1, 0xa2, 0xa3, 0xa4 };

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0041,
	    247, 247, 10, 10, 512, 512);

	ATF_REQUIRE_EQ(0, feed_data(con, ch->scid, frame, sizeof(frame)));
	ATF_REQUIRE_EQ(1, g_ndata);
	ATF_CHECK_EQ(NG_L2CAP_L2CA_IDTYPE_ECBFC,
	    (u_int16_t)(g_data[0].data[0] | (g_data[0].data[1] << 8)));
	ATF_CHECK_EQ(0, memcmp(g_data[0].data + 6, frame + 2, 4));
	drain_tx(con);
}

/*
 * §10.1: "the device shall ... disconnect the L2CAP channel if it receives a
 * K-frame on an L2CAP channel from the peer device that has a credit count of
 * zero."
 */
ATF_TC_WITHOUT_HEAD(rx_zero_local_credits_disconnects);
ATF_TC_BODY(rx_zero_local_credits_disconnects, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	f0[6] = { 4, 0, 0xaa, 0xbb, 0xcc, 0xdd };

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 247, 0, 65, 512, 512);
	scid = ch->scid;

	ATF_CHECK_EQ(EPROTO, feed_data(con, scid, f0, sizeof(f0)));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);		/* channel torn down */
	ATF_CHECK_EQ(0, g_ndata);

	drain_tx(con);
}

/*
 * §3.4.3: a K-frame whose Information payload exceeds the local MPS is illegal
 * -- the receiver shall disconnect the channel.
 */
ATF_TC_WITHOUT_HEAD(rx_kframe_exceeds_mps_disconnects);
ATF_TC_BODY(rx_kframe_exceeds_mps_disconnects, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	f0[40];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	/* local MPS deliberately tiny (23); frame payload 40 > 23. */
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    L2DATA_LE_COC_MPS_MIN, 247, 65, 65, 512, 512);
	scid = ch->scid;
	memset(f0, 0x55, sizeof(f0));
	f0[0] = 36; f0[1] = 0;

	ATF_CHECK_EQ(EMSGSIZE, feed_data(con, scid, f0, sizeof(f0)));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);

	drain_tx(con);
}

/*
 * §3.4.3: the first K-frame's declared SDU Length must not exceed the
 * channel's MTU; otherwise the receiver shall disconnect.
 */
ATF_TC_WITHOUT_HEAD(rx_sdu_len_exceeds_mtu_disconnects);
ATF_TC_BODY(rx_sdu_len_exceeds_mtu_disconnects, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	f0[10];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	/* imtu deliberately 16; first frame claims SDU length 1000. */
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 247, 65, 65, 16, 512);
	scid = ch->scid;
	memset(f0, 0, sizeof(f0));
	f0[0] = (u_int8_t)(1000 & 0xff);
	f0[1] = (u_int8_t)(1000 >> 8);

	ATF_CHECK_EQ(EMSGSIZE, feed_data(con, scid, f0, sizeof(f0)));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);

	drain_tx(con);
}

/*
 * §3.4.3: reassembly overflow -- if the running total of received segment
 * bytes exceeds the declared SDU Length, the receiver shall disconnect.
 */
ATF_TC_WITHOUT_HEAD(rx_reassembly_overflow_disconnects);
ATF_TC_BODY(rx_reassembly_overflow_disconnects, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	f0[12], f1[20];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 247, 65, 65, 512, 512);
	scid = ch->scid;

	/* Declare SDU length 18, deliver 10 then 20 (=30 > 18). */
	f0[0] = 18; f0[1] = 0;
	memset(&f0[2], 0x33, 10);
	memset(f1, 0x44, sizeof(f1));

	ATF_REQUIRE_EQ(0, feed_data(con, scid, f0, sizeof(f0)));
	ATF_CHECK_EQ(EMSGSIZE, feed_data(con, scid, f1, sizeof(f1)));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);
	ATF_CHECK_EQ(0, g_ndata);

	drain_tx(con);
}

/* ====================================================================== */
/* Credit overflow -- Core Spec Vol 3 Part A Section 10.1                 */
/* ====================================================================== */

/*
 * §10.1: "if the sum of ... credits exceeds 65535, the device shall
 * disconnect the L2CAP channel."  A FLOW_CONTROL_CREDIT that would push
 * credits_remote past 0xFFFF makes the stack move the channel to
 * W4_L2CAP_DISCON_RSP and enqueue an L2CAP_DISCONNECTION_REQ.  (This arm at
 * ng_l2cap_evnt.c ~:962 is otherwise untested.)
 */
ATF_TC_WITHOUT_HEAD(credit_overflow_sends_disconnect);
ATF_TC_BODY(credit_overflow_sends_disconnect, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0055,
	    247, 247, 65, L2DATA_CREDIT_COUNT_MAX, 512, 512);

	/* FLOW_CONTROL_CREDIT for cid=0x0055 (our DCID), credits=2 -> >0xFFFF */
	w16(p, 0, 0x0055);
	w16(p, 2, 2);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_FLOW_CONTROL_CREDIT,
	    0x40, p, sizeof(p));

	/* Channel moved to W4_L2CAP_DISCON_RSP and a DISCON_REQ was queued. */
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_DISCON_RSP, ch->state);
	ATF_CHECK(!TAILQ_EMPTY(&con->cmd_list));
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_DISCON_REQ,
	    TAILQ_FIRST(&con->cmd_list)->code);

	drain_tx(con);
}

/*
 * §4.24 / §10.1: a FLOW_CONTROL_CREDIT with a nonzero credit value that does
 * NOT overflow simply adds to credits_remote (enabling more TX).  A zero
 * credit value "shall be ignored".
 */
ATF_TC_WITHOUT_HEAD(credit_grant_and_zero_ignored);
ATF_TC_BODY(credit_grant_and_zero_ignored, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0055,
	    247, 247, 65, 5, 512, 512);

	/* +10 credits. */
	w16(p, 0, 0x0055);
	w16(p, 2, 10);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_FLOW_CONTROL_CREDIT,
	    0x40, p, sizeof(p));
	ATF_CHECK_EQ(15, ch->credits_remote);

	/* Zero credit -> ignored, count unchanged. */
	w16(p, 2, 0);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_FLOW_CONTROL_CREDIT,
	    0x41, p, sizeof(p));
	ATF_CHECK_EQ(15, ch->credits_remote);

	drain_tx(con);
}

/* ====================================================================== */
/* Channel lifecycle -- Core Spec Vol 3 Part A Section 3 / 4.22           */
/* ====================================================================== */

/*
 * A full inbound CoC lifecycle driven end to end: LE Credit Based Connection
	 * Request (§4.22) creates a pending channel; an explicit upper-layer accept
	 * opens it and emits LE Credit Based Connection Response 0x15.  The peer then
 * grants credits and we write an SDU (segmented, credits spent), and finally
 * the peer disconnects (Disconnection Request §4.6) tearing the channel down.
 */
ATF_TC_WITHOUT_HEAD(lifecycle_connect_write_disconnect);
ATF_TC_BODY(lifecycle_connect_write_disconnect, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	req[10], credit[4], dis[4], sdu[8];
	int		i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, /*encrypted*/1);

	/* --- LE Credit Based Connection Request (peer -> us) --- */
	/* upper-layer SPSM, scid=0x0060, mtu=512, mps=247, credits=8 */
	w16(req, 0, 0x0080);
	w16(req, 2, 0x0060);
	w16(req, 4, 512);
	w16(req, 6, 247);
	w16(req, 8, 8);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_LE_CREDIT_CON_REQ,
	    0x50, req, sizeof(req));

	/* The hook alone is not acceptance: no success is emitted while pending. */
	ch = ng_l2cap_chan_by_dcid(&g_l2cap, 0x0060, NG_L2CAP_L2CA_IDTYPE_LE);
	ATF_REQUIRE(ch != NULL);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CA_CON_RSP, ch->state);
	ATF_CHECK_EQ(0, g_nframes);
	ATF_CHECK_EQ(0x0060, ch->dcid);
	ATF_CHECK_EQ(8, ch->credits_remote);
	ATF_CHECK_EQ(L2DATA_IMPL_INITIAL_CREDITS, ch->credits_local);
	scid = ch->scid;
	ATF_REQUIRE_EQ(0, respond_inbound(ch, L2DATA_CONNECTION_SUCCESS));
	ATF_CHECK_EQ(NG_L2CAP_OPEN, ch->state);

	/* A LE Credit Based Connection Response (0x15) was emitted. */
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_LE_CREDIT_CON_RSP,
	    g_frames[0].data[0]);
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_LESIGNAL_CID, g_frames[0].dcid);

	/* --- write an SDU (fits one K-frame; credits_remote 8 -> 7) --- */
	g_nframes = 0;
	for (i = 0; i < (int)sizeof(sdu); i++)
		sdu[i] = (u_int8_t)(0x70 + i);
	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));
	ATF_CHECK_EQ(1, g_nframes);
	ATF_CHECK_EQ(8, frame_le16(&g_frames[0], 0));
	ATF_CHECK_EQ(7, ch->credits_remote);
	ATF_CHECK_EQ(L2DATA_IMPL_WRITE_SUCCESS, g_write_result);

	/* --- peer Disconnection Request tears the channel down --- */
	w16(dis, 0, scid);		/* dcid (our scid) */
	w16(dis, 2, 0x0060);		/* scid (peer scid) */
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_DISCON_REQ,
	    0x51, dis, sizeof(dis));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);

	(void)credit;
	drain_tx(con);
}

/* An upper-layer listener miss becomes wire result 0x0002, with no orphan. */
ATF_TC_WITHOUT_HEAD(inbound_le_coc_listener_rejects_spsm);
ATF_TC_BODY(inbound_le_coc_listener_rejects_spsm, tc)
{
	ng_l2cap_con_p con;
	ng_l2cap_chan_p ch;
	u_int8_t req[10];
	u_int16_t scid;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, 0x0080);
	w16(req, 2, 0x0060);
	w16(req, 4, 512);
	w16(req, 6, 247);
	w16(req, 8, 8);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_LE_CREDIT_CON_REQ,
	    0x52, req, sizeof(req));
	ch = ng_l2cap_chan_by_dcid_con(con, 0x0060,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	ATF_REQUIRE(ch != NULL);
	scid = ch->scid;
	ATF_REQUIRE_EQ(0, respond_inbound(ch,
	    L2DATA_CONNECTION_PSM_NOT_SUPPORTED));
	ATF_CHECK(ng_l2cap_chan_by_scid_con(con, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);
	ATF_REQUIRE_EQ(1, g_nframes);
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_LE_CREDIT_CON_RSP,
	    g_frames[0].data[0]);
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_LE_COC_SPSM_NOT_SUPPORTED,
	    frame_le16(&g_frames[0], 12));
	drain_tx(con);
}

/* ====================================================================== */
/* RTX / ERTX guard timers -- Core Spec Vol 3 Part A Section 6.2          */
/* ====================================================================== */

/*
 * §6.2: a signalling Request that goes unanswered fires the RTX timer; on
 * expiry the L2CAP entity fails the associated L2CA primitive.  Here an
 * outgoing CON_REQ arms RTX (via con_wakeup's ng_l2cap_command_timeout after
 * a successful lp_send); firing the fake callout runs
 * ng_l2cap_process_command_timeout, which reports L2CA_ConnectCfm(Timeout)
 * up and frees the half-open channel.
 */
ATF_TC_WITHOUT_HEAD(rtx_con_req_expiry_fails_primitive);
ATF_TC_BODY(rtx_con_req_expiry_fails_primitive, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;
	u_int16_t	scid;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);

	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->state = NG_L2CAP_W4_L2CAP_CON_RSP;
	scid = ch->scid;

	/* Build + queue an outgoing CON_REQ command, then run con_wakeup. */
	cmd = ng_l2cap_new_cmd(con, ch, ng_l2cap_get_ident(con),
	    L2DATA_NG_L2CAP_CON_REQ, 0x77);
	ATF_REQUIRE(cmd != NULL);
	_ng_l2cap_con_req(cmd->aux, cmd->ident, ch->psm, ch->scid);
	ATF_REQUIRE(cmd->aux != NULL);
	ng_l2cap_link_cmd(con, cmd);
	ng_l2cap_con_wakeup(con);

	/* RTX now armed. */
	ATF_CHECK_EQ(1, callouts_pending());
	ATF_CHECK_EQ(0, g_nmsg);

	/* Fire it: the primitive fails with Timeout and the channel is freed. */
	ATF_CHECK_EQ(1, fire_callouts());
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_BREDR) == NULL);
	ATF_CHECK_EQ(0, callouts_pending());

	drain_tx(con);
}

/*
 * §6.2: a Connection Response with result "Pending" (0x0001) restarts the
 * timer as ERTX; a later successful Connection Response cancels ERTX and
 * completes the channel.  Drive both responses and observe the callout being
 * (re)armed then cancelled.
 */
ATF_TC_WITHOUT_HEAD(ertx_pending_then_success_cancels);
ATF_TC_BODY(ertx_pending_then_success_cancels, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;
	u_int8_t	ident;
	u_int8_t	rsp[8];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);

	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->state = NG_L2CAP_W4_L2CAP_CON_RSP;

	/* Arm RTX by sending an outgoing CON_REQ. */
	ident = ng_l2cap_get_ident(con);
	cmd = ng_l2cap_new_cmd(con, ch, ident, L2DATA_NG_L2CAP_CON_REQ,
	    0x99);
	ATF_REQUIRE(cmd != NULL);
	_ng_l2cap_con_req(cmd->aux, cmd->ident, ch->psm, ch->scid);
	ATF_REQUIRE(cmd->aux != NULL);
	ng_l2cap_link_cmd(con, cmd);
	ng_l2cap_con_wakeup(con);
	ATF_CHECK_EQ(1, callouts_pending());	/* RTX armed */

	/* --- Connection Response: Pending -> RTX cancelled, ERTX armed --- */
	w16(rsp, 0, ch->scid);	/* dcid (peer) echoes our scid area */
	w16(rsp, 2, ch->scid);	/* scid */
	w16(rsp, 4, L2DATA_CONNECTION_PENDING);
	w16(rsp, 6, 0x0000);
	feed_sig(con, L2DATA_NG_L2CAP_SIGNAL_CID,
	    L2DATA_NG_L2CAP_CON_RSP, ident,
	    rsp, sizeof(rsp));
	ATF_CHECK_EQ(1, callouts_pending());		/* ERTX still armed */
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_CON_RSP, ch->state);
	ATF_CHECK(!TAILQ_EMPTY(&con->cmd_list));	/* command still pending */

	/* --- Connection Response: Success -> ERTX cancelled, open --- */
	w16(rsp, 0, 0x0071);		/* peer's real DCID */
	w16(rsp, 2, ch->scid);
	w16(rsp, 4, L2DATA_CONNECTION_SUCCESS);
	w16(rsp, 6, 0x0000);
	feed_sig(con, L2DATA_NG_L2CAP_SIGNAL_CID,
	    L2DATA_NG_L2CAP_CON_RSP, ident,
	    rsp, sizeof(rsp));
	ATF_CHECK_EQ(0, callouts_pending());		/* ERTX cancelled */
	ATF_CHECK_EQ(0x0071, ch->dcid);			/* peer DCID recorded */
	ATF_CHECK_EQ(NG_L2CAP_CONFIG, ch->state);	/* moved to CONFIG */

	drain_tx(con);
}

/* ====================================================================== */
/* ECRED all-or-nothing -- Core Spec Vol 3 Part A Section 4.25            */
/* ====================================================================== */

/*
 * §4.25: an Enhanced Credit Based Connection Request lists 1..5 Source CIDs;
 * "the same result" applies to every channel.  A well-formed request for
 * three fresh CIDs opens all three as ECBFC channels (state OPEN, peer SCIDs
 * recorded as our DCIDs).
 */
ATF_TC_WITHOUT_HEAD(ecred_connects_all_channels);
ATF_TC_BODY(ecred_connects_all_channels, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	c1, c2, c3;
	u_int8_t	req[14];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);

	/* le_psm=EATT, mtu=512, mps=247, credits=8, scids 0x0040/0x0041/0x0042 */
	w16(req, 0, L2DATA_NG_L2CAP_PSM_EATT);
	w16(req, 2, 512);
	w16(req, 4, 247);
	w16(req, 6, 8);
	w16(req, 8, 0x0040);
	w16(req, 10, 0x0041);
	w16(req, 12, 0x0042);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_CREDIT_CON_REQ,
	    0x60, req, sizeof(req));

	c1 = ng_l2cap_chan_by_dcid(&g_l2cap, 0x0040, NG_L2CAP_L2CA_IDTYPE_ECBFC);
	c2 = ng_l2cap_chan_by_dcid(&g_l2cap, 0x0041, NG_L2CAP_L2CA_IDTYPE_ECBFC);
	c3 = ng_l2cap_chan_by_dcid(&g_l2cap, 0x0042, NG_L2CAP_L2CA_IDTYPE_ECBFC);
	ATF_REQUIRE(c1 != NULL && c2 != NULL && c3 != NULL);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CA_CON_RSP, c1->state);
	ATF_CHECK_EQ(0, g_nframes);
	ATF_REQUIRE_EQ(0, respond_inbound(c1, L2DATA_CONNECTION_SUCCESS));
	ATF_CHECK_EQ(0, g_nframes);
	ATF_REQUIRE_EQ(0, respond_inbound(c2, L2DATA_CONNECTION_SUCCESS));
	ATF_CHECK_EQ(0, g_nframes);
	ATF_REQUIRE_EQ(0, respond_inbound(c3, L2DATA_CONNECTION_SUCCESS));
	ATF_CHECK_EQ(NG_L2CAP_OPEN, c1->state);
	ATF_CHECK_EQ(NG_L2CAP_OPEN, c2->state);
	ATF_CHECK_EQ(NG_L2CAP_OPEN, c3->state);
	ATF_CHECK_EQ(8, c2->credits_remote);

	/*
	 * A CREDIT_CON_RSP (0x18) was emitted, Result 0x0000 "All connections
	 * successful", carrying the three locally allocated Destination CIDs in
	 * Source-CID order (Core Spec Vol 3 Part A §4.26, Table 4.20).  Response
	 * layout: code(1) ident(1) len(2) mtu(2) mps(2) credits(2) result(2)
	 * dcids[], so result is at octet 10 and the DCID list starts at 12.
	 */
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_CREDIT_CON_RSP,
	    g_frames[0].data[0]);
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_LE_COC_SUCCESS,
	    frame_le16(&g_frames[0], 10));
	ATF_CHECK_EQ(c1->scid, frame_le16(&g_frames[0], 12));
	ATF_CHECK_EQ(c2->scid, frame_le16(&g_frames[0], 14));
	ATF_CHECK_EQ(c3->scid, frame_le16(&g_frames[0], 16));

	drain_tx(con);
}

ATF_TC_WITHOUT_HEAD(ecred_listener_reject_is_atomic);
ATF_TC_BODY(ecred_listener_reject_is_atomic, tc)
{
	ng_l2cap_con_p con;
	ng_l2cap_chan_p c1, c2;
	u_int8_t req[12];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, 0x0080);
	w16(req, 2, 512); w16(req, 4, 247); w16(req, 6, 8);
	w16(req, 8, 0x0040); w16(req, 10, 0x0041);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_CREDIT_CON_REQ,
	    0x63, req, sizeof(req));
	c1 = ng_l2cap_chan_by_dcid_con(con, 0x0040,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	c2 = ng_l2cap_chan_by_dcid_con(con, 0x0041,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	ATF_REQUIRE(c1 != NULL && c2 != NULL);
	ATF_REQUIRE_EQ(0, respond_inbound(c1, L2DATA_CONNECTION_SUCCESS));
	ATF_REQUIRE_EQ(0, respond_inbound(c2,
	    L2DATA_CONNECTION_PSM_NOT_SUPPORTED));
	ATF_CHECK(ng_l2cap_chan_by_dcid_con(con, 0x0040,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);
	ATF_CHECK(ng_l2cap_chan_by_dcid_con(con, 0x0041,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);
	ATF_REQUIRE_EQ(1, g_nframes);
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_LE_COC_SPSM_NOT_SUPPORTED,
	    frame_le16(&g_frames[0], 10));
	ATF_CHECK_EQ(0, frame_le16(&g_frames[0], 12));
	ATF_CHECK_EQ(0, frame_le16(&g_frames[0], 14));
	drain_tx(con);
}

/*
 * Vol 3 Part A Section 4: Identifier correlates a signaling transaction and
 * may be reused after the response.  A later same-sized ECBFC group using the
 * same Identifier is a distinct request.  If its response cannot be sent,
 * rollback must remove only the new group, never the older open bearers.
 */
ATF_TC_WITHOUT_HEAD(ecred_reused_ident_send_failure_is_group_local);
ATF_TC_BODY(ecred_reused_ident_send_failure_is_group_local, tc)
{
	ng_l2cap_con_p con;
	ng_l2cap_chan_p old1, old2, new1, new2;
	u_int8_t req[12];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, L2DATA_NG_L2CAP_PSM_EATT);
	w16(req, 2, 512); w16(req, 4, 247); w16(req, 6, 8);
	w16(req, 8, 0x0040); w16(req, 10, 0x0041);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_CREDIT_CON_REQ,
	    0x65, req, sizeof(req));
	old1 = ng_l2cap_chan_by_dcid_con(con, 0x0040,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	old2 = ng_l2cap_chan_by_dcid_con(con, 0x0041,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	ATF_REQUIRE(old1 != NULL && old2 != NULL);
	ATF_REQUIRE_EQ(0, respond_inbound(old1, L2DATA_CONNECTION_SUCCESS));
	ATF_REQUIRE_EQ(0, respond_inbound(old2, L2DATA_CONNECTION_SUCCESS));
	ATF_REQUIRE_EQ(NG_L2CAP_OPEN, old1->state);
	ATF_REQUIRE_EQ(NG_L2CAP_OPEN, old2->state);
	ATF_CHECK_EQ(0, old1->ident);
	ATF_CHECK_EQ(0, old1->ecbfc_group_id);
	drain_tx(con);

	/* Reuse Identifier 0x65 with the same number of distinct Source CIDs. */
	w16(req, 8, 0x0050); w16(req, 10, 0x0051);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_CREDIT_CON_REQ,
	    0x65, req, sizeof(req));
	new1 = ng_l2cap_chan_by_dcid_con(con, 0x0050,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	new2 = ng_l2cap_chan_by_dcid_con(con, 0x0051,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	ATF_REQUIRE(new1 != NULL && new2 != NULL);
	ATF_REQUIRE_EQ(0, respond_inbound(new1, L2DATA_CONNECTION_SUCCESS));
	g_lp_send_err = ENOBUFS;
	ATF_REQUIRE_EQ(0, respond_inbound(new2, L2DATA_CONNECTION_SUCCESS));

	ATF_CHECK(ng_l2cap_chan_by_dcid_con(con, 0x0050,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);
	ATF_CHECK(ng_l2cap_chan_by_dcid_con(con, 0x0051,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);
	ATF_CHECK_EQ(old1, ng_l2cap_chan_by_dcid_con(con, 0x0040,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC));
	ATF_CHECK_EQ(old2, ng_l2cap_chan_by_dcid_con(con, 0x0041,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC));
	ATF_CHECK_EQ(NG_L2CAP_OPEN, old1->state);
	ATF_CHECK_EQ(NG_L2CAP_OPEN, old2->state);
	drain_tx(con);
}

ATF_TC_WITHOUT_HEAD(legacy_accept_response_send_failure_rolls_back);
ATF_TC_BODY(legacy_accept_response_send_failure_rolls_back, tc)
{
	ng_l2cap_con_p con;
	ng_l2cap_chan_p ch;
	u_int8_t req[10];
	u_int16_t scid;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, 0x0080); w16(req, 2, 0x0060);
	w16(req, 4, 512); w16(req, 6, 247); w16(req, 8, 8);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_LE_CREDIT_CON_REQ,
	    0x64, req, sizeof(req));
	ch = ng_l2cap_chan_by_dcid_con(con, 0x0060, NG_L2CAP_L2CA_IDTYPE_LE);
	ATF_REQUIRE(ch != NULL);
	scid = ch->scid;
	g_lp_send_err = ENOBUFS;
	ATF_REQUIRE_EQ(0, respond_inbound(ch, L2DATA_CONNECTION_SUCCESS));
	ATF_CHECK(ng_l2cap_chan_by_scid_con(con, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);
	ATF_CHECK_EQ(NGM_L2CAP_L2CA_DISCON_IND, g_last_msg_cmd);
	drain_tx(con);
}

ATF_TC_WITHOUT_HEAD(flow_credit_send_failure_disconnects);
ATF_TC_BODY(flow_credit_send_failure_disconnects, tc)
{
	ng_l2cap_con_p con;
	ng_l2cap_chan_p ch;
	u_int8_t frame[6] = { 4, 0, 1, 2, 3, 4 };
	u_int16_t scid;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 247, 1, 8, 512, 512);
	scid = ch->scid;
	g_lp_send_err = ENOBUFS;
	(void)feed_data(con, scid, frame, sizeof(frame));
	ATF_CHECK(ng_l2cap_chan_by_scid_con(con, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);
	ATF_CHECK_EQ(NGM_L2CAP_L2CA_DISCON_IND, g_last_msg_cmd);
	drain_tx(con);
}

/*
 * §4.25: "If any of the Source CIDs ... is already in use ... the response
 * shall refuse the request."  A request that repeats a CID already open on
 * the link is refused, and -- all-or-nothing -- no NEW channel is created for
 * the other (fresh) CID in the same request.
 */
ATF_TC_WITHOUT_HEAD(ecred_scid_in_use_refused_all);
ATF_TC_BODY(ecred_scid_in_use_refused_all, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	pre;
	u_int8_t	req[12];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);

	/* Pre-existing ECBFC channel whose DCID (peer SCID) is 0x0041. */
	pre = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0041,
	    247, 247, 65, 8, 512, 512);
	ATF_REQUIRE(pre != NULL);

	/* Request for scids 0x0050 (fresh) and 0x0041 (already in use). */
	w16(req, 0, L2DATA_NG_L2CAP_PSM_EATT);
	w16(req, 2, 512);
	w16(req, 4, 247);
	w16(req, 6, 8);
	w16(req, 8, 0x0050);
	w16(req, 10, 0x0041);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_CREDIT_CON_REQ,
	    0x61, req, sizeof(req));

	/* No new channel was created for the fresh CID (rejected before alloc). */
	ATF_CHECK(ng_l2cap_chan_by_dcid(&g_l2cap, 0x0050,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);

	/*
	 * A refusing CREDIT_CON_RSP (0x18), Result 0x000A "Source CID already
	 * allocated" (Core Spec Vol 3 Part A §4.26, Table 4.20), with every
	 * Destination CID set to the null CID 0x0000 (all-or-nothing refusal).
	 */
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_CREDIT_CON_RSP,
	    g_frames[0].data[0]);
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_LE_COC_SCID_IN_USE,
	    frame_le16(&g_frames[0], 10));
	ATF_CHECK_EQ(0x0000, frame_le16(&g_frames[0], 12));
	ATF_CHECK_EQ(0x0000, frame_le16(&g_frames[0], 14));

	drain_tx(con);
}

/*
 * §4.25: a request that duplicates a Source CID WITHIN the same request is
 * malformed and refused (Result "Invalid Source CID").
 */
ATF_TC_WITHOUT_HEAD(ecred_duplicate_scid_in_request_refused);
ATF_TC_BODY(ecred_duplicate_scid_in_request_refused, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	req[12];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);

	/* scids 0x0043 and 0x0043 (duplicate). */
	w16(req, 0, L2DATA_NG_L2CAP_PSM_EATT);
	w16(req, 2, 512);
	w16(req, 4, 247);
	w16(req, 6, 8);
	w16(req, 8, 0x0043);
	w16(req, 10, 0x0043);
	feed_sig(con, L2DATA_NG_L2CAP_LESIGNAL_CID,
	    L2DATA_NG_L2CAP_CREDIT_CON_REQ,
	    0x62, req, sizeof(req));

	ATF_CHECK(ng_l2cap_chan_by_dcid(&g_l2cap, 0x0043,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);
	/*
	 * Result 0x0009 "Invalid Source CID" with all-zero Destination CIDs
	 * (Core Spec Vol 3 Part A §4.26, Table 4.20).
	 */
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_CREDIT_CON_RSP,
	    g_frames[0].data[0]);
	ATF_CHECK_EQ(L2DATA_NG_L2CAP_LE_COC_INVALID_SCID,
	    frame_le16(&g_frames[0], 10));
	ATF_CHECK_EQ(0x0000, frame_le16(&g_frames[0], 12));
	ATF_CHECK_EQ(0x0000, frame_le16(&g_frames[0], 14));

	drain_tx(con);
}

/* ====================================================================== */

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, tx_segments_sdu_len_prefix_and_credits);
	ATF_TP_ADD_TC(tp, tx_single_kframe);
	ATF_TP_ADD_TC(tp, tx_zero_credits_refused);
	ATF_TP_ADD_TC(tp, tx_mid_sdu_exhaustion_stalls_and_resumes);
	ATF_TP_ADD_TC(tp, tx_legacy_stalled_sdu_serializes_later_writes);
	ATF_TP_ADD_TC(tp, tx_ecbfc_stalled_sdu_serializes_later_writes);

	ATF_TP_ADD_TC(tp, rx_reassembles_and_replenishes);
	ATF_TP_ADD_TC(tp, rx_ecbfc_dynamic_cid_routes_to_bearer);
	ATF_TP_ADD_TC(tp, rx_zero_local_credits_disconnects);
	ATF_TP_ADD_TC(tp, rx_kframe_exceeds_mps_disconnects);
	ATF_TP_ADD_TC(tp, rx_sdu_len_exceeds_mtu_disconnects);
	ATF_TP_ADD_TC(tp, rx_reassembly_overflow_disconnects);

	ATF_TP_ADD_TC(tp, credit_overflow_sends_disconnect);
	ATF_TP_ADD_TC(tp, credit_grant_and_zero_ignored);

	ATF_TP_ADD_TC(tp, lifecycle_connect_write_disconnect);
	ATF_TP_ADD_TC(tp, inbound_le_coc_listener_rejects_spsm);

	ATF_TP_ADD_TC(tp, rtx_con_req_expiry_fails_primitive);
	ATF_TP_ADD_TC(tp, ertx_pending_then_success_cancels);

	ATF_TP_ADD_TC(tp, ecred_connects_all_channels);
	ATF_TP_ADD_TC(tp, ecred_listener_reject_is_atomic);
	ATF_TP_ADD_TC(tp, ecred_reused_ident_send_failure_is_group_local);
	ATF_TP_ADD_TC(tp, legacy_accept_response_send_failure_rolls_back);
	ATF_TP_ADD_TC(tp, flow_credit_send_failure_disconnects);
	ATF_TP_ADD_TC(tp, ecred_scid_in_use_refused_all);
	ATF_TP_ADD_TC(tp, ecred_duplicate_scid_in_request_refused);

	return (atf_no_error());
}
