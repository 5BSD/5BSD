/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * DEEP companion to l2cap_data_test.c.  Same #include-the-kernel-TU shim
 * (malloc-backed mbuf, loopback ng_l2cap_lp_send, fireable fake-callout
 * registry -- copied verbatim below), but many more known-answer cases that
 * push the credit/flow-control data plane and channel state machine far past
 * what l2cap_data_test.c reached: every TX segmentation size class (0, exactly
 * MPS, MPS+1, many-frame, exactly/over MTU), every RX reassembly size class
 * and disconnect trigger, exact FLOW_CONTROL_CREDIT replenishment values, the
 * ECBFC reconfigure DATA path (incoming reconfigure changing TX segmentation),
 * per-channel independent credit accounting, the full CONNECT/CONFIG/OPEN/
 * DISCONNECT state machine (BR/EDR outbound + inbound accept/config), the
 * RTX guard timers on CFG/DISCON/ECHO/INFO requests, and ng_l2cap_con_fail.
 *
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

#include "spec_l2cap_core63_oracles.h"

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
/*
 * Fault-injection budgets (Core-Spec-independent harness knob).  When a budget
 * is >= 0 it counts down on each matching allocation and returns NULL once it
 * reaches 0, so a test can force ng_l2cap_new_chan()/new_cmd() (kernel malloc)
 * or a response-PDU MGETHDR (mbuf) to fail on the Nth allocation and thereby
 * drive the ENOMEM/ENOBUFS reject arms.  -1 == unlimited (normal operation).
 */
static int	g_kmalloc_budget = -1;	/* kernel malloc() 3-arg calls */
static int	g_mbuf_budget = -1;	/* ng_mbuf_alloc()/MGETHDR calls */

/*
 * When >= 0, the feed_* helpers set the built mbuf's m_len to this value
 * (leaving m_pkthdr.len and the payload intact) so the kernel's
 * NG_L2CAP_M_PULLUP() wrapper actually invokes our m_pullup() -- see the
 * m_pullup fault seam below.  -1 == full-length feed (normal operation).
 */
static int	g_short_mlen = -1;

/*
 * Loopback ng_l2cap_lp_con_req() knobs.  The real lower layer either fails
 * to start an ACL/LE connection (g_lp_con_req_err != 0) or eventually
 * registers a connection descriptor for the target address; when
 * g_lp_con_req_make is set the stub creates that descriptor so the
 * "con == NULL -> LP_ConnectReq -> re-lookup" arm in the ping/get_info
 * request paths can be driven without dereferencing a NULL connection.
 */
static int	g_lp_con_req_err;
static int	g_lp_con_req_make;

/*
 * ng_mesg (NG_MKMESSAGE) allocation fault seam.  The kernel builds every
 * upstream L2CA_* confirmation/indication with NG_MKMESSAGE (a netgraph
 * message allocation, distinct from mbufs and channel/command descriptors).
 * When this budget hits 0 the allocation returns NULL, driving the
 * "msg == NULL -> ENOMEM" arm the rsp/ind confirmations all carry.  The
 * test-input helper mk_l2ca_msg() calls calloc() directly and is unaffected.
 */
static int	g_mkmsg_budget = -1;
static int	g_con_ind_fail_after = -1;

static void *
ut_mkmsg(size_t sz)
{

	if (g_mkmsg_budget == 0)
		return (NULL);
	if (g_mkmsg_budget > 0)
		g_mkmsg_budget--;
	return (calloc(1, sz));
}

static void *
ut_kmalloc(size_t sz)
{

	if (g_kmalloc_budget == 0)
		return (NULL);
	if (g_kmalloc_budget > 0)
		g_kmalloc_budget--;
	return (calloc(1, sz));
}

#define malloc(sz, type, flags)	ut_kmalloc((sz))
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

	if (g_mbuf_budget == 0)
		return (NULL);
	if (g_mbuf_budget > 0)
		g_mbuf_budget--;
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

/*
 * m_pullup fault seam (Core-Spec-independent harness knob).
 *
 * The kernel wrapper NG_L2CAP_M_PULLUP(m, s) only calls m_pullup() when
 * m->m_len < s.  Our userspace mbufs are a single contiguous store, so a
 * well-formed record always has m_len == m_pkthdr.len >= s and m_pullup() is
 * never invoked -- which leaves every "... -> m_pullup() -> NULL -> ENOBUFS"
 * arm in ng_l2cap_receive() / process_signal_cmd() / the per-command
 * process_*() decoders / l2ca_receive() / write_req() unreachable.
 *
 * To reach them a test (a) builds the fed frame with a deliberately short
 * m_len via g_short_mlen so the wrapper actually calls m_pullup(), and
 * (b) arms g_pullup_fail_at = N so the Nth real pullup along the decode path
 * returns NULL.  g_pullup_calls counts real invocations.  A "real" pullup
 * (m_len < s) that is not the armed one succeeds by growing m_len up to s
 * (the bytes are already contiguous at m_data), exactly like the kernel's
 * coalescing pullup, so decoding proceeds normally to the target site.
 */
static int	g_pullup_calls;		/* count of real m_pullup() invocations */
static int	g_pullup_fail_at = -1;	/* fail the Nth invocation (1-based); -1 off */

static struct mbuf *
m_pullup(struct mbuf *m, int s)
{

	if (m == NULL)
		return (NULL);
	if (m->m_len >= s)
		return (m);		/* nothing to coalesce */

	g_pullup_calls++;
	if (g_pullup_fail_at > 0 && g_pullup_calls == g_pullup_fail_at) {
		m_freem(m);
		return (NULL);
	}

	/*
	 * Successful pullup: the whole record is contiguous in m_store, so
	 * the s requested bytes at m_data are present whenever the true
	 * record length (m_pkthdr.len) is at least s.  Grow m_len to s.
	 */
	if (s <= m->m_pkthdr.len &&
	    (int)(m->m_data - m->m_store) + s <= NG_MBUF_STORE) {
		m->m_len = s;
		return (m);
	}
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
	if ((cmdid) == NGM_L2CAP_L2CA_CON_IND &&			\
	    g_con_ind_fail_after == 0)				\
		(msg) = NULL;					\
	else {							\
		(msg) = ut_mkmsg(sizeof(struct ng_mesg) + (len));	\
		if ((cmdid) == NGM_L2CAP_L2CA_CON_IND &&		\
		    g_con_ind_fail_after > 0)			\
			g_con_ind_fail_after--;			\
	}							\
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
static u_int16_t	g_discon_lcid;
static u_int16_t	g_discon_idtype;

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
	} else if (msg->header.cmd == NGM_L2CAP_L2CA_DISCON_IND) {
		ng_l2cap_l2ca_discon_ind_ip *ip =
		    (ng_l2cap_l2ca_discon_ind_ip *)msg->data;

		g_discon_lcid = ip->lcid;
		g_discon_idtype = ip->idtype;
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
	ng_l2cap_con_p	con;

	if (g_lp_con_req_err != 0)
		return (g_lp_con_req_err);
	if (g_lp_con_req_make) {
		con = ng_l2cap_new_con(l2cap, bdaddr, type);
		if (con != NULL)
			con->state = NG_L2CAP_CON_OPEN;
	}
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
#define ng_l2cap_lp_con_req ng_l2cap_lp_con_req_real_unused
#define ng_l2cap_lp_con_update ng_l2cap_lp_con_update_real_unused
#define ng_l2cap_lp_send ng_l2cap_lp_send_real_unused
#define ng_l2cap_lp_deliver ng_l2cap_lp_deliver_real_unused
#define ng_l2cap_process_lp_timeout ng_l2cap_process_lp_timeout_real_unused
#define ng_l2cap_process_discon_timeout ng_l2cap_process_discon_timeout_real_unused
int ng_l2cap_lp_con_req(ng_l2cap_p, bdaddr_p, int, uint8_t);
int ng_l2cap_lp_con_update(ng_l2cap_con_p, u_int16_t, u_int16_t,
    u_int16_t, u_int16_t);
int ng_l2cap_lp_send(ng_l2cap_con_p, u_int16_t, struct mbuf *);
void ng_l2cap_lp_deliver(ng_l2cap_con_p);
void ng_l2cap_process_lp_timeout(node_p, hook_p, void *, int);
void ng_l2cap_process_discon_timeout(node_p, hook_p, void *, int);
#include "ng_l2cap_llpi.c"
#undef ng_l2cap_process_discon_timeout
#undef ng_l2cap_process_lp_timeout
#undef ng_l2cap_lp_deliver
#undef ng_l2cap_lp_send
#undef ng_l2cap_lp_con_update
#undef ng_l2cap_lp_con_req
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
	g_discon_lcid = g_discon_idtype = 0;
	g_lp_send_err = 0;
	g_ncallouts = 0;
	g_kmalloc_budget = -1;
	g_mbuf_budget = -1;
	g_short_mlen = -1;
	g_pullup_calls = 0;
	g_pullup_fail_at = -1;
	g_lp_con_req_err = 0;
	g_lp_con_req_make = 0;
	g_mkmsg_budget = -1;
	g_con_ind_fail_after = -1;

	memset(&g_l2cap, 0, sizeof(g_l2cap));
	/* Diagnostic formatting is part of every state transition under test. */
	g_l2cap.debug = NG_L2CAP_INFO_LEVEL;
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

	ch = ng_l2cap_new_chan(&g_l2cap, con, BT_ASSIGNED_L2CAP_SPSM_EATT, idtype);
	ATF_REQUIRE(ch != NULL);
	ch->dcid = dcid;
	ch->mps = mps_local;
	ch->mps_remote = mps_remote;
	ch->credits_local = credits_local;
	ch->credits_remote = credits_remote;
	ch->imtu = imtu;
	ch->omtu = omtu;
	ch->le_psm = BT_ASSIGNED_L2CAP_SPSM_EATT;
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
	if (g_short_mlen >= 0)
		m->m_len = g_short_mlen;
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
	if (g_short_mlen >= 0)
		m->m_len = g_short_mlen;
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
	if (g_short_mlen >= 0)
		m->m_len = g_short_mlen;
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

/* ====================================================================== */
/* Deep data-path helpers (extend the shared harness above).              */
/* ====================================================================== */

/*
 * Build a heap ng_mesg carrying an L2CA_* request input struct.  The kernel
 * L2CA request handlers never free their input message (the socket layer
 * owns it), so the caller frees it after the call returns.
 */
static struct ng_mesg *
mk_l2ca_msg(uint32_t cmd, const void *arg, size_t arglen)
{
	struct ng_mesg	*msg;

	msg = calloc(1, sizeof(struct ng_mesg) + arglen);
	ATF_REQUIRE(msg != NULL);
	msg->header.typecookie = NGM_L2CAP_COOKIE;
	msg->header.cmd = cmd;
	msg->header.arglen = (uint32_t)arglen;
	msg->header.token = 0x2222;
	if (arg != NULL && arglen > 0)
		memcpy(msg->data, arg, arglen);
	return (msg);
}

/* Issue an L2CA_Connect (outgoing) for a given idtype on an existing con. */
static int
l2ca_con_req(u_int16_t psm, u_int8_t linktype, u_int8_t idtype)
{
	ng_l2cap_l2ca_con_ip	ip;
	struct ng_mesg		*msg;
	int			 err;

	memset(&ip, 0, sizeof(ip));
	ip.psm = psm;
	bcopy(&g_addr, &ip.bdaddr, sizeof(ip.bdaddr));
	ip.linktype = linktype;
	ip.idtype = idtype;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CON, &ip, sizeof(ip));
	err = ng_l2cap_l2ca_con_req(&g_l2cap, msg);
	(free)(msg);
	return (err);
}

/* Issue an L2CA_Reconfig for an OPEN ECBFC channel. */
static int
l2ca_reconfig(ng_l2cap_chan_p ch, u_int16_t mtu, u_int16_t mps)
{
	ng_l2cap_l2ca_reconfig_ip	ip;
	struct ng_mesg			*msg;
	int				 err;

	memset(&ip, 0, sizeof(ip));
	ip.lcid = ch->scid;
	ip.mtu = mtu;
	ip.mps = mps;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_RECONFIG, &ip, sizeof(ip));
	err = ng_l2cap_l2ca_reconfig_req(&g_l2cap, msg);
	(free)(msg);
	return (err);
}

/* Issue an L2CA_Disconnect for a channel identified by scid/idtype. */
static int
l2ca_discon_req(ng_l2cap_chan_p ch, u_int16_t idtype)
{
	ng_l2cap_l2ca_discon_ip	ip;
	struct ng_mesg		*msg;
	int			 err;

	memset(&ip, 0, sizeof(ip));
	ip.lcid = ch->scid;
	ip.idtype = idtype;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_DISCON, &ip, sizeof(ip));
	err = ng_l2cap_l2ca_discon_req(&g_l2cap, msg);
	(free)(msg);
	return (err);
}

/* Issue an L2CA_Config for a BR/EDR channel. */
static int
l2ca_cfg_req(ng_l2cap_chan_p ch, u_int16_t imtu)
{
	ng_l2cap_l2ca_cfg_ip	ip;
	struct ng_mesg		*msg;
	int			 err;

	memset(&ip, 0, sizeof(ip));
	ip.lcid = ch->scid;
	ip.imtu = imtu;
	bcopy(ng_l2cap_default_flow(), &ip.oflow, sizeof(ip.oflow));
	ip.flush_timo = NG_L2CAP_FLUSH_TIMO_DEFAULT;
	ip.link_timo = NG_L2CAP_LINK_TIMO_DEFAULT;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CFG, &ip, sizeof(ip));
	err = ng_l2cap_l2ca_cfg_req(&g_l2cap, msg);
	(free)(msg);
	return (err);
}

/* Issue an L2CA_Ping (BR/EDR echo). */
static int
l2ca_ping_req(void)
{
	ng_l2cap_l2ca_ping_ip	ip;
	struct ng_mesg		*msg;
	int			 err;

	memset(&ip, 0, sizeof(ip));
	bcopy(&g_addr, &ip.bdaddr, sizeof(ip.bdaddr));
	ip.echo_size = 0;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_PING, &ip, sizeof(ip));
	err = ng_l2cap_l2ca_ping_req(&g_l2cap, msg);
	(free)(msg);
	return (err);
}

/* Issue an L2CA_GetInfo. */
static int
l2ca_get_info_req(u_int8_t linktype)
{
	ng_l2cap_l2ca_get_info_ip	ip;
	struct ng_mesg			*msg;
	int				 err;

	memset(&ip, 0, sizeof(ip));
	bcopy(&g_addr, &ip.bdaddr, sizeof(ip.bdaddr));
	ip.info_type = 1;
	ip.linktype = linktype;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_GET_INFO, &ip, sizeof(ip));
	err = ng_l2cap_l2ca_get_info_req(&g_l2cap, msg);
	(free)(msg);
	return (err);
}

/* Issue an L2CA_EnableCLT for a PSM. */
static int
l2ca_enable_clt(u_int16_t psm, u_int16_t enable)
{
	ng_l2cap_l2ca_enable_clt_ip	ip;
	struct ng_mesg			*msg;
	int				 err;

	memset(&ip, 0, sizeof(ip));
	ip.psm = psm;
	ip.enable = enable;
	msg = mk_l2ca_msg(0, &ip, sizeof(ip));
	err = ng_l2cap_l2ca_enable_clt(&g_l2cap, msg);
	(free)(msg);
	return (err);
}

/* The ident of the (single) command currently queued on the connection. */
static u_int8_t
first_cmd_ident(ng_l2cap_con_p con)
{
	ng_l2cap_cmd_p	cmd = TAILQ_FIRST(&con->cmd_list);

	ATF_REQUIRE(cmd != NULL);
	return (cmd->ident);
}

/* ====================================================================== */
/* TX segmentation size classes -- Core Spec Vol 3 Part A §3.4.1, §3.4.2  */
/* ====================================================================== */

/*
 * §3.4.2: a zero-length SDU is still a valid SDU.  It is sent as a single
 * K-frame carrying only the 2-octet SDU-Length field (value 0), consuming
 * exactly one credit.
 */
ATF_TC_WITHOUT_HEAD(tx_zero_length_sdu);
ATF_TC_BODY(tx_zero_length_sdu, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);

	ATF_REQUIRE_EQ(0, do_write(con, ch, NULL, 0));

	ATF_REQUIRE_EQ(1, g_nframes);
	ATF_CHECK_EQ(2, g_frames[0].len);		/* only the SDU-Length */
	ATF_CHECK_EQ(0, frame_le16(&g_frames[0], 0));	/* SDU-Length == 0 */
	ATF_CHECK_EQ(4, ch->credits_remote);		/* 5 - 1 */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, g_write_result);

	drain_tx(con);
}

/*
 * §3.4.1: when SDU-Length(2) + data exactly equals the peer MPS, the whole
 * SDU still fits in a single K-frame (K-frame Information payload == MPS).
 */
ATF_TC_WITHOUT_HEAD(tx_exactly_mps_single_frame);
ATF_TC_BODY(tx_exactly_mps_single_frame, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[21];		/* 2 + 21 == 23 == MPS */
	int		i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);
	for (i = 0; i < (int)sizeof(sdu); i++)
		sdu[i] = (u_int8_t)(0xb0 + i);

	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));

	ATF_REQUIRE_EQ(1, g_nframes);
	ATF_CHECK_EQ(23, g_frames[0].len);		/* exactly MPS */
	ATF_CHECK_EQ(21, frame_le16(&g_frames[0], 0));	/* SDU-Length 21 */
	ATF_CHECK_EQ(4, ch->credits_remote);
	ATF_CHECK_EQ(0, memcmp(&g_frames[0].data[2], sdu, 21));

	drain_tx(con);
}

/*
 * §3.4.1: SDU one octet larger than fits in a single MPS K-frame spills into
 * a second (continuation) K-frame; the first frame is full (== MPS) and the
 * second carries the single remaining octet.  Two credits are spent.
 */
ATF_TC_WITHOUT_HEAD(tx_mps_plus_one_two_frames);
ATF_TC_BODY(tx_mps_plus_one_two_frames, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[22];		/* one more than 21 */
	int		i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);
	for (i = 0; i < (int)sizeof(sdu); i++)
		sdu[i] = (u_int8_t)i;

	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));

	ATF_REQUIRE_EQ(2, g_nframes);
	ATF_CHECK_EQ(23, g_frames[0].len);		/* first == MPS */
	ATF_CHECK_EQ(22, frame_le16(&g_frames[0], 0));	/* SDU-Length 22 */
	ATF_CHECK_EQ(1, g_frames[1].len);		/* remaining octet */
	ATF_CHECK_EQ(sdu[21], g_frames[1].data[0]);
	ATF_CHECK_EQ(3, ch->credits_remote);		/* 5 - 2 */

	drain_tx(con);
}

/*
 * §3.4.1 / §10.1: a large SDU is spread across many K-frames; one credit is
 * consumed per frame and the reassembled payload matches the original.
 */
ATF_TC_WITHOUT_HEAD(tx_many_frames_credit_decrement);
ATF_TC_BODY(tx_many_frames_credit_decrement, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[200];
	int		i, off, exp_frames;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	/* MPS 23 -> first frame carries 21 SDU bytes, rest carry 23. */
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 40, 512, 512);
	for (i = 0; i < (int)sizeof(sdu); i++)
		sdu[i] = (u_int8_t)(i * 7);

	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));

	/* 21 in frame0, then ceil((200-21)/23) = ceil(179/23)=8 -> 9 frames. */
	exp_frames = 1 + ((200 - 21) + 22) / 23;
	ATF_CHECK_EQ(9, exp_frames);
	ATF_REQUIRE_EQ(exp_frames, g_nframes);
	ATF_CHECK_EQ(200, frame_le16(&g_frames[0], 0));
	ATF_CHECK_EQ(40 - exp_frames, ch->credits_remote);

	/* Reassemble the emitted frames and compare to the source SDU. */
	off = 0;
	ATF_CHECK_EQ(0, memcmp(&g_frames[0].data[2], &sdu[off],
	    g_frames[0].len - 2));
	off += g_frames[0].len - 2;
	for (i = 1; i < g_nframes; i++) {
		ATF_CHECK_EQ(0, memcmp(&g_frames[i].data[0], &sdu[off],
		    g_frames[i].len));
		off += g_frames[i].len;
	}
	ATF_CHECK_EQ(200, off);

	drain_tx(con);
}

/*
 * §4.23 / write path: a dynamic (non-fixed) channel enforces the negotiated
 * outgoing MTU (omtu).  An SDU exactly equal to omtu is accepted; omtu+1 is
 * refused up with EMSGSIZE before any K-frame leaves.
 */
ATF_TC_WITHOUT_HEAD(tx_omtu_boundary);
ATF_TC_BODY(tx_omtu_boundary, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[41];
	int		i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	/* omtu deliberately 40, mps big enough for a single frame. */
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 247, 65, 5, 512, 40);
	for (i = 0; i < (int)sizeof(sdu); i++)
		sdu[i] = (u_int8_t)i;

	/* Exactly omtu: accepted, one frame. */
	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, 40));
	ATF_CHECK_EQ(1, g_nframes);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, g_write_result);

	/* omtu + 1: refused before segmentation. */
	g_nframes = 0;
	g_write_n = 0;
	ATF_CHECK_EQ(EMSGSIZE, do_write(con, ch, sdu, 41));
	ATF_CHECK_EQ(0, g_nframes);
	ATF_CHECK_EQ(0, g_write_n);		/* no L2CA_WriteRsp emitted */

	drain_tx(con);
}

/*
 * §3.4.1: several SDUs written back-to-back on the same channel each run the
 * con_wakeup segmentation loop; credits decrement cumulatively and every
 * SDU's frames are emitted in order (save/restore ACL chaining per write).
 */
ATF_TC_WITHOUT_HEAD(tx_sequential_writes_chaining);
ATF_TC_BODY(tx_sequential_writes_chaining, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[30];
	int		i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 20, 512, 512);
	for (i = 0; i < (int)sizeof(sdu); i++)
		sdu[i] = (u_int8_t)i;

	/* Each 30-byte SDU with MPS 23 -> 2 frames (21 + 9). */
	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));
	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));
	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));

	ATF_CHECK_EQ(6, g_nframes);			/* 3 SDUs * 2 frames */
	ATF_CHECK_EQ(20 - 6, ch->credits_remote);	/* 6 credits spent */
	/* Each SDU begins with its own SDU-Length prefix (30). */
	ATF_CHECK_EQ(30, frame_le16(&g_frames[0], 0));
	ATF_CHECK_EQ(30, frame_le16(&g_frames[2], 0));
	ATF_CHECK_EQ(30, frame_le16(&g_frames[4], 0));

	drain_tx(con);
}

/*
 * Guard: a peer MPS below 2 cannot even carry the SDU-Length field, so the
 * segmentation loop refuses the write (EINVAL) rather than underflowing
 * (mps - 2).  Regression guard on ng_l2cap_cmds.c:236.
 */
ATF_TC_WITHOUT_HEAD(tx_mps_below_two_einval);
ATF_TC_BODY(tx_mps_below_two_einval, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[4] = { 1, 2, 3, 4 };

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 1, 65, 5, 512, 512);		/* mps_remote == 1 */

	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));
	ATF_CHECK_EQ(0, g_nframes);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_NO_RESOURCES, g_write_result);
	ATF_CHECK_EQ(5, ch->credits_remote);		/* unchanged */

	drain_tx(con);
}

/*
 * Write to a channel that is not OPEN is rejected with EHOSTDOWN and no
 * command is queued (ng_l2cap_ulpi.c state check).
 */
ATF_TC_WITHOUT_HEAD(tx_wrong_state_ehostdown);
ATF_TC_BODY(tx_wrong_state_ehostdown, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[4] = { 1, 2, 3, 4 };

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);
	ch->state = NG_L2CAP_CONFIG;			/* not OPEN */

	ATF_CHECK_EQ(EHOSTDOWN, do_write(con, ch, sdu, sizeof(sdu)));
	ATF_CHECK_EQ(0, g_nframes);
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));

	drain_tx(con);
}

/*
 * Write referencing a non-existent local CID is rejected with ENOENT.
 */
ATF_TC_WITHOUT_HEAD(tx_unknown_channel_enoent);
ATF_TC_BODY(tx_unknown_channel_enoent, tc)
{
	ng_l2cap_con_p		con;
	struct mbuf		*m;
	ng_l2cap_l2ca_hdr_t	*h;
	u_int8_t		sdu[4] = { 1, 2, 3, 4 };

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);

	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	h = (ng_l2cap_l2ca_hdr_t *)m->m_data;
	h->token = 0x1;
	h->length = (u_int16_t)sizeof(sdu);
	h->lcid = 0x0049;				/* no such channel */
	h->idtype = NG_L2CAP_L2CA_IDTYPE_LE;
	memcpy(m->m_data + sizeof(*h), sdu, sizeof(sdu));
	m->m_len = m->m_pkthdr.len = sizeof(*h) + sizeof(sdu);

	ATF_CHECK_EQ(ENOENT, ng_l2cap_l2ca_write_req(&g_l2cap, m));
	ATF_CHECK_EQ(0, g_nframes);

	drain_tx(con);
}

/*
 * Write with a local CID below the dynamic range (< 0x0040) is EINVAL.
 */
ATF_TC_WITHOUT_HEAD(tx_lcid_too_small_einval);
ATF_TC_BODY(tx_lcid_too_small_einval, tc)
{
	ng_l2cap_con_p		con;
	struct mbuf		*m;
	ng_l2cap_l2ca_hdr_t	*h;
	u_int8_t		sdu[2] = { 9, 9 };

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);

	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	h = (ng_l2cap_l2ca_hdr_t *)m->m_data;
	h->token = 0x1;
	h->length = (u_int16_t)sizeof(sdu);
	h->lcid = 0x0003;				/* below BT_CORE63_L2CAP_CID_DYNAMIC_FIRST */
	h->idtype = NG_L2CAP_L2CA_IDTYPE_LE;
	memcpy(m->m_data + sizeof(*h), sdu, sizeof(sdu));
	m->m_len = m->m_pkthdr.len = sizeof(*h) + sizeof(sdu);

	ATF_CHECK_EQ(EINVAL, ng_l2cap_l2ca_write_req(&g_l2cap, m));

	drain_tx(con);
}

/*
 * Write whose declared L2CA length does not match the actual payload length
 * is rejected with EMSGSIZE.
 */
ATF_TC_WITHOUT_HEAD(tx_length_mismatch_emsgsize);
ATF_TC_BODY(tx_length_mismatch_emsgsize, tc)
{
	ng_l2cap_con_p		con;
	ng_l2cap_chan_p		ch;
	struct mbuf		*m;
	ng_l2cap_l2ca_hdr_t	*h;
	u_int8_t		sdu[4] = { 1, 2, 3, 4 };

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);

	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	h = (ng_l2cap_l2ca_hdr_t *)m->m_data;
	h->token = 0x1;
	h->length = 99;					/* wrong */
	h->lcid = ch->scid;
	h->idtype = NG_L2CAP_L2CA_IDTYPE_LE;
	memcpy(m->m_data + sizeof(*h), sdu, sizeof(sdu));
	m->m_len = m->m_pkthdr.len = sizeof(*h) + sizeof(sdu);

	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_write_req(&g_l2cap, m));
	ATF_CHECK_EQ(0, g_nframes);

	drain_tx(con);
}

/*
 * Write packet smaller than the L2CA header is rejected with EMSGSIZE.
 */
ATF_TC_WITHOUT_HEAD(tx_header_too_small_emsgsize);
ATF_TC_BODY(tx_header_too_small_emsgsize, tc)
{
	ng_l2cap_con_p	con;
	struct mbuf	*m;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);

	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	m->m_len = m->m_pkthdr.len = 3;			/* < sizeof(l2ca_hdr) */

	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_write_req(&g_l2cap, m));

	drain_tx(con);
}

/*
 * §10.1 / write path: if the very first K-frame fails to send (lower layer
 * out of resources) the write is reported up as No Resources.
 */
ATF_TC_WITHOUT_HEAD(tx_lp_send_fail_no_resources);
ATF_TC_BODY(tx_lp_send_fail_no_resources, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);
	g_lp_send_err = ENOBUFS;			/* force lp_send failure */

	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));
	ATF_CHECK_EQ(1, g_write_n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_NO_RESOURCES, g_write_result);
	ATF_CHECK_EQ_MSG(5, ch->credits_remote,
	    "a locally rejected K-frame must not consume the peer's credit");

	drain_tx(con);
}

/*
 * A BR/EDR (non-CoC) channel has no per-frame credit accounting: the SDU is
 * sent whole in one L2CAP packet on the channel's DCID.  Exercises the
 * non-segmenting branch of the WRITE handler.
 */
ATF_TC_WITHOUT_HEAD(tx_bredr_non_coc_write);
ATF_TC_BODY(tx_bredr_non_coc_write, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[16];
	int		i;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	/* BR/EDR channel: mps_remote == 0 so the CoC path is not taken. */
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0055,
	    0, 0, 0, 0, 672, 672);
	ch->le_psm = 0;
	for (i = 0; i < (int)sizeof(sdu); i++)
		sdu[i] = (u_int8_t)(0xc0 + i);

	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));

	ATF_REQUIRE_EQ(1, g_nframes);
	ATF_CHECK_EQ(0x0055, g_frames[0].dcid);		/* sent on DCID */
	ATF_CHECK_EQ(16, g_frames[0].len);		/* no SDU-Length prefix */
	ATF_CHECK_EQ(0, memcmp(g_frames[0].data, sdu, 16));
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, g_write_result);

	drain_tx(con);
}

/*
 * A write on a channel whose DCID is the connectionless CID (0x0002) is
 * wrapped in a CLT header carrying the channel PSM (broadcast path).
 */
ATF_TC_WITHOUT_HEAD(tx_clt_broadcast_write);
ATF_TC_BODY(tx_clt_broadcast_write, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[4] = { 0xde, 0xad, 0xbe, 0xef };

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, BT_CORE63_L2CAP_CID_CONNECTIONLESS,
	    0, 0, 0, 0, 672, 672);
	ch->psm = BT_ASSIGNED_L2CAP_PSM_SDP;
	ch->le_psm = 0;

	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));

	ATF_REQUIRE_EQ(1, g_nframes);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CID_CONNECTIONLESS, g_frames[0].dcid);
	/* CLT header (2-byte PSM) precedes the payload. */
	ATF_CHECK_EQ(2 + 4, g_frames[0].len);
	ATF_CHECK_EQ(BT_ASSIGNED_L2CAP_PSM_SDP, frame_le16(&g_frames[0], 0));
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, g_write_result);

	drain_tx(con);
}

/* ====================================================================== */
/* RX reassembly size classes -- Core Spec Vol 3 Part A §3.4.3            */
/* ====================================================================== */

/*
 * §3.4.3: an SDU that fits inside a single K-frame (SDU-Length + data <= MPS)
 * is reassembled and delivered from that one frame.
 */
ATF_TC_WITHOUT_HEAD(rx_single_frame_complete);
ATF_TC_BODY(rx_single_frame_complete, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	f0[10];
	int		i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 247, 10, 65, 512, 512);
	scid = ch->scid;

	f0[0] = 8; f0[1] = 0;				/* SDU-Length 8 */
	for (i = 0; i < 8; i++)
		f0[2 + i] = (u_int8_t)(0x30 + i);

	ATF_REQUIRE_EQ(0, feed_data(con, scid, f0, sizeof(f0)));
	ATF_REQUIRE_EQ(1, g_ndata);
	ATF_CHECK_EQ(2 + 4 + 8, g_data[0].len);		/* idtype + hdr + SDU */
	ATF_CHECK_EQ(0, memcmp(&g_data[0].data[6], &f0[2], 8));
	/* Credits replenished to initial after completion. */
	ATF_CHECK_EQ(NG_L2CAP_LE_COC_INITIAL_CREDITS, ch->credits_local);

	drain_tx(con);
}

/*
 * §3.4.3: an SDU whose declared length exactly equals the channel MTU is
 * accepted (boundary; only SDU-Length > MTU triggers disconnect).
 */
ATF_TC_WITHOUT_HEAD(rx_exact_mtu_accepted);
ATF_TC_BODY(rx_exact_mtu_accepted, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	f0[42];
	int		i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	/* imtu 40, local mps big enough to carry 2 + 40 in one K-frame. */
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 247, 10, 65, 40, 512);
	scid = ch->scid;

	f0[0] = 40; f0[1] = 0;				/* SDU-Length == imtu */
	for (i = 0; i < 40; i++)
		f0[2 + i] = (u_int8_t)i;

	ATF_REQUIRE_EQ(0, feed_data(con, scid, f0, sizeof(f0)));
	ATF_REQUIRE_EQ(1, g_ndata);
	ATF_CHECK_EQ(2 + 4 + 40, g_data[0].len);

	drain_tx(con);
}

/*
 * §3.4.3: an SDU spanning many K-frames is reassembled in order.  Feed a
 * 5-fragment SDU and check the delivered payload and the exact replenishment
 * credit value (initial - remaining_local).
 */
ATF_TC_WITHOUT_HEAD(rx_many_kframes_reassembled);
ATF_TC_BODY(rx_many_kframes_reassembled, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	f[6];
	u_int8_t	expect[22];
	int		i, k;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	/* local MPS 6 -> 4 SDU bytes in frame0, 6 per continuation. */
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    6, 247, 10, 65, 512, 512);
	scid = ch->scid;

	/* SDU total 22: frame0 carries len(2)+4 data; then 6,6,6. */
	for (i = 0; i < 22; i++)
		expect[i] = (u_int8_t)(0x40 + i);

	f[0] = 22; f[1] = 0;
	memcpy(&f[2], &expect[0], 4);
	ATF_REQUIRE_EQ(0, feed_data(con, scid, f, 6));		/* frame0 */
	ATF_CHECK_EQ(0, g_ndata);				/* incomplete */

	for (k = 4; k < 22; k += 6) {
		int n = (22 - k) < 6 ? (22 - k) : 6;
		memcpy(f, &expect[k], n);
		ATF_REQUIRE_EQ(0, feed_data(con, scid, f, n));
	}

	ATF_REQUIRE_EQ(1, g_ndata);
	ATF_CHECK_EQ(2 + 4 + 22, g_data[0].len);
	ATF_CHECK_EQ(0, memcmp(&g_data[0].data[6], expect, 22));
	ATF_CHECK_EQ(NG_L2CAP_LE_COC_INITIAL_CREDITS, ch->credits_local);

	drain_tx(con);
}

/*
 * §3.4.3: the first K-frame of an SDU must be at least 2 octets (to carry the
 * SDU-Length field).  A 1-octet first K-frame is malformed -> disconnect.
 */
ATF_TC_WITHOUT_HEAD(rx_first_kframe_too_short_disconnects);
ATF_TC_BODY(rx_first_kframe_too_short_disconnects, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	f0[1] = { 0x00 };

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 247, 10, 65, 512, 512);
	scid = ch->scid;

	ATF_CHECK_EQ(EMSGSIZE, feed_data(con, scid, f0, sizeof(f0)));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);

	drain_tx(con);
}

/*
 * §4.24 / §10.1: exact replenishment credit value.  Starting from the initial
 * credit level, receiving a 2-frame SDU spends 2 local credits; the emitted
 * FLOW_CONTROL_CREDIT returns exactly 2, restoring the peer to initial.
 */
ATF_TC_WITHOUT_HEAD(rx_replenish_exact_value);
ATF_TC_BODY(rx_replenish_exact_value, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	f0[8], f1[6];
	int		i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	/* Start at the initial local-credit level; local MPS small. */
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    6, 247, NG_L2CAP_LE_COC_INITIAL_CREDITS, 65, 512, 512);
	scid = ch->scid;

	/* SDU length 10: frame0 = len(2)+4 data (mps 6), frame1 = 6 data. */
	f0[0] = 10; f0[1] = 0;
	for (i = 0; i < 4; i++)
		f0[2 + i] = (u_int8_t)(0x50 + i);
	for (i = 0; i < 6; i++)
		f1[i] = (u_int8_t)(0x60 + i);

	ATF_REQUIRE_EQ(0, feed_data(con, scid, f0, 6));	/* len(2) + 4 == MPS */
	ATF_CHECK_EQ(NG_L2CAP_LE_COC_INITIAL_CREDITS - 1, ch->credits_local);
	ATF_REQUIRE_EQ(0, feed_data(con, scid, f1, sizeof(f1)));

	ATF_REQUIRE_EQ(1, g_ndata);
	/* Exactly one FLOW_CONTROL_CREDIT PDU, value 2, on our SCID. */
	ATF_REQUIRE_EQ(1, g_nframes);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CID_LE_SIGNAL, g_frames[0].dcid);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT, g_frames[0].data[0]);
	ATF_CHECK_EQ(scid, frame_le16(&g_frames[0], 4));
	ATF_CHECK_EQ(2, frame_le16(&g_frames[0], 6));	/* returned credits */
	ATF_CHECK_EQ(NG_L2CAP_LE_COC_INITIAL_CREDITS, ch->credits_local);

	drain_tx(con);
}

/*
 * A data K-frame on a channel that is not OPEN is dropped with EHOSTDOWN.
 */
ATF_TC_WITHOUT_HEAD(rx_wrong_state_ehostdown);
ATF_TC_BODY(rx_wrong_state_ehostdown, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	f0[6] = { 4, 0, 1, 2, 3, 4 };

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 247, 10, 65, 512, 512);
	scid = ch->scid;
	ch->state = NG_L2CAP_CONFIG;			/* not OPEN */

	ATF_CHECK_EQ(EHOSTDOWN, feed_data(con, scid, f0, sizeof(f0)));
	ATF_CHECK_EQ(0, g_ndata);

	drain_tx(con);
}

/*
 * A data K-frame addressed to an unknown CID is dropped with ENOENT.
 */
ATF_TC_WITHOUT_HEAD(rx_unknown_channel_enoent);
ATF_TC_BODY(rx_unknown_channel_enoent, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	f0[6] = { 4, 0, 1, 2, 3, 4 };

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);

	ATF_CHECK_EQ(ENOENT, feed_data(con, 0x0049, f0, sizeof(f0)));
	ATF_CHECK_EQ(0, g_ndata);

	drain_tx(con);
}

/* ====================================================================== */
/* ECRED per-channel credit accounting -- Core Spec Vol 3 Part A §4.25    */
/* ====================================================================== */

/*
 * §4.25 / §10.1: multiple ECBFC channels on one link each keep independent
 * credit counts.  Writing different-sized SDUs on two channels decrements
 * only that channel's credits; a FLOW_CONTROL_CREDIT for one channel does
 * not affect the other.
 */
ATF_TC_WITHOUT_HEAD(ecred_per_channel_independent_credits);
ATF_TC_BODY(ecred_per_channel_independent_credits, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	a, b;
	u_int8_t	sdu[30];
	u_int8_t	p[4];
	int		i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	a = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 23, 65, 10, 512, 512);
	b = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0072,
	    247, 23, 65, 10, 512, 512);
	for (i = 0; i < (int)sizeof(sdu); i++)
		sdu[i] = (u_int8_t)i;

	/* 30-byte SDU on A with MPS 23 -> 2 frames -> A: 10-2 = 8. */
	ATF_REQUIRE_EQ(0, do_write(con, a, sdu, sizeof(sdu)));
	ATF_CHECK_EQ(8, a->credits_remote);
	ATF_CHECK_EQ(10, b->credits_remote);		/* B untouched */

	/* 8-byte SDU on B -> 1 frame -> B: 10-1 = 9. */
	ATF_REQUIRE_EQ(0, do_write(con, b, sdu, 8));
	ATF_CHECK_EQ(8, a->credits_remote);		/* A untouched */
	ATF_CHECK_EQ(9, b->credits_remote);

	/* Grant +5 credits to B only (FLOW_CONTROL_CREDIT for B's DCID). */
	w16(p, 0, 0x0072);
	w16(p, 2, 5);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT,
	    0x40, p, sizeof(p));
	ATF_CHECK_EQ(8, a->credits_remote);
	ATF_CHECK_EQ(14, b->credits_remote);

	drain_tx(con);
}

/* ====================================================================== */
/* ECRED reconfigure -- Core Spec Vol 3 Part A §4.27                      */
/* ====================================================================== */

/*
 * §4.27: L2CA_Reconfig on an OPEN ECBFC channel queues an L2CAP Credit Based
 * Reconfigure Request (0x19) carrying the new MTU/MPS and the channel's local
 * CID, marks the channel reconfig-pending, and stashes the requested values
 * to be applied on a successful response.
 */
ATF_TC_WITHOUT_HEAD(reconfig_req_queues_command);
ATF_TC_BODY(reconfig_req_queues_command, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 247, 65, 8, 512, 512);

	ATF_REQUIRE_EQ(0, l2ca_reconfig(ch, 600, 300));

	ATF_CHECK_EQ(1, ch->reconfig_pending);
	ATF_CHECK_EQ(600, ch->pending_imtu);
	ATF_CHECK_EQ(300, ch->pending_mps);
	/* Reconfigure Request PDU emitted on the LE signalling CID. */
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ, g_frames[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CID_LE_SIGNAL, g_frames[0].dcid);
	/* Body: [code][ident][len(2)][mtu(2)][mps(2)][dcid(2)]. */
	ATF_CHECK_EQ(600, frame_le16(&g_frames[0], 4));
	ATF_CHECK_EQ(300, frame_le16(&g_frames[0], 6));
	ATF_CHECK_EQ(ch->scid, frame_le16(&g_frames[0], 8));

	drain_tx(con);
}

/*
 * §4.27: MTU may not be reduced by a reconfigure; such a request is refused
 * locally (EINVAL) before any PDU is sent.  Below-minimum params, a
 * non-existent CID, and a non-OPEN channel are likewise refused.
 */
ATF_TC_WITHOUT_HEAD(reconfig_req_validation);
ATF_TC_BODY(reconfig_req_validation, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch, closed;
	ng_l2cap_l2ca_reconfig_ip	ip;
	struct ng_mesg	*msg;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 247, 65, 8, 512, 512);		/* imtu 512 */

	/* MTU reduction (400 < current imtu 512): EINVAL. */
	ATF_CHECK_EQ(EINVAL, l2ca_reconfig(ch, 400, 300));
	ATF_CHECK_EQ(0, ch->reconfig_pending);
	ATF_CHECK_EQ(0, g_nframes);

	/* Below-minimum MPS (< 64): EINVAL. */
	ATF_CHECK_EQ(EINVAL, l2ca_reconfig(ch, 600, 32));

	/* Unknown local CID: ENOENT. */
	memset(&ip, 0, sizeof(ip));
	ip.lcid = 0x004f;
	ip.mtu = 600;
	ip.mps = 300;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_RECONFIG, &ip, sizeof(ip));
	ATF_CHECK_EQ(ENOENT, ng_l2cap_l2ca_reconfig_req(&g_l2cap, msg));
	(free)(msg);

	/* Non-OPEN channel: EINVAL. */
	closed = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0073,
	    247, 247, 65, 8, 512, 512);
	closed->state = NG_L2CAP_CONFIG;
	ATF_CHECK_EQ(EINVAL, l2ca_reconfig(closed, 600, 300));

	drain_tx(con);
}

/*
 * §4.27: a second reconfigure while one is still outstanding is refused with
 * EBUSY (the reconfig_pending guard).
 */
ATF_TC_WITHOUT_HEAD(reconfig_req_concurrent_ebusy);
ATF_TC_BODY(reconfig_req_concurrent_ebusy, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 247, 65, 8, 512, 512);

	ATF_REQUIRE_EQ(0, l2ca_reconfig(ch, 600, 300));
	ATF_CHECK_EQ(1, ch->reconfig_pending);
	/* Second attempt while pending. */
	ATF_CHECK_EQ(EBUSY, l2ca_reconfig(ch, 700, 400));

	drain_tx(con);
}

/*
 * §4.27 (initiator, success path): after L2CA_Reconfig the Credit Based
 * Reconfigure Request stays a timed, PENDING command (like CFG_REQ), so when
 * the peer's Reconfigure Response (0x1A, success) arrives it is paired via
 * ng_l2cap_cmd_by_ident() and the stashed pending_imtu/pending_mps are put
 * into effect -- Core Spec Vol 3 Part A §4.27 requires the new MTU/MPS to take
 * effect on the initiator on success.  reconfig_pending is cleared so a later
 * reconfigure is accepted.  (Regression guard for the fix in
 * ng_l2cap_con_wakeup()/ng_l2cap_process_command_timeout(): the request was
 * previously freed on send, dropping the response.)
 */
ATF_TC_WITHOUT_HEAD(reconfig_initiator_applies_on_success);
ATF_TC_BODY(reconfig_initiator_applies_on_success, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	ident;
	u_int8_t	rsp[2];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 247, 65, 8, 512, 512);

	ATF_REQUIRE_EQ(0, l2ca_reconfig(ch, 600, 300));
	/* Request is pending until the peer responds. */
	ATF_CHECK_EQ(1, ch->reconfig_pending);
	ident = (u_int8_t)g_frames[0].data[1];		/* ident from the PDU */

	/* Peer accepts: Credit Based Reconfigure Response, result = success. */
	w16(rsp, 0, BT_CORE63_L2CAP_RECONFIG_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP,
	    ident, rsp, sizeof(rsp));

	/* New MTU/MPS now in effect on the initiator; guard cleared. */
	ATF_CHECK_EQ(600, ch->imtu);
	ATF_CHECK_EQ(300, ch->mps);
	ATF_CHECK_EQ(0, ch->reconfig_pending);

	drain_tx(con);
}

/*
 * §4.27 (peer-initiated, DATA path): an incoming Credit Based Reconfigure
 * Request that raises our outgoing MPS is applied to the OPEN ECBFC channel
 * (mps_remote updated) and is answered with a success Reconfigure Response.
 * A subsequent TX then segments using the NEW, larger MPS -- proving the
 * reconfigure took effect on the data plane.
 */
ATF_TC_WITHOUT_HEAD(reconfig_incoming_changes_tx_segmentation);
ATF_TC_BODY(reconfig_incoming_changes_tx_segmentation, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	req[6];
	u_int8_t	sdu[40];
	int		i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	/* Start with a tiny outgoing MPS (23) and matching omtu. */
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 23, 65, 20, 64, 64);
	for (i = 0; i < (int)sizeof(sdu); i++)
		sdu[i] = (u_int8_t)i;

	/* Peer reconfigure: mtu=64 (unchanged omtu), mps=100, dcid = our DCID. */
	w16(req, 0, 64);				/* mtu */
	w16(req, 2, 100);				/* mps */
	w16(req, 4, ch->dcid);				/* peer's local CID */
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ,
	    0x40, req, sizeof(req));

	/* New outgoing MPS applied. */
	ATF_CHECK_EQ(100, ch->mps_remote);
	/* A success Reconfigure Response (0x1A) was emitted. */
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP, g_frames[0].data[0]);

	/* Now a 40-byte SDU fits in ONE K-frame (2 + 40 <= 100). */
	g_nframes = 0;
	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));
	ATF_CHECK_EQ(1, g_nframes);
	ATF_CHECK_EQ(2 + 40, g_frames[0].len);
	ATF_CHECK_EQ(40, frame_le16(&g_frames[0], 0));

	drain_tx(con);
}

/*
 * §4.27: an incoming reconfigure on an unencrypted link is refused (local
 * hardening policy) -- the channel parameters are left unchanged and a
 * non-success Reconfigure Response is returned.
 */
ATF_TC_WITHOUT_HEAD(reconfig_incoming_unencrypted_rejected);
ATF_TC_BODY(reconfig_incoming_unencrypted_rejected, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	req[6];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, /*encryption*/0);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 23, 65, 20, 512, 512);

	w16(req, 0, 600);
	w16(req, 2, 300);
	w16(req, 4, ch->dcid);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ,
	    0x40, req, sizeof(req));

	ATF_CHECK_EQ(23, ch->mps_remote);		/* unchanged */
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP, g_frames[0].data[0]);
	/* result != success (unacceptable params) */
	ATF_CHECK(frame_le16(&g_frames[0], 4) != BT_CORE63_L2CAP_RECONFIG_SUCCESS);

	drain_tx(con);
}

/* ====================================================================== */
/* Channel state machine -- Core Spec Vol 3 Part A §3 / §4.6              */
/* ====================================================================== */

/*
 * Outbound BR/EDR channel lifecycle: L2CA_Connect drives the channel through
 * CLOSED -> W4_L2CAP_CON_RSP; an inbound Connection Response (Success) moves
 * it to CONFIG and records the peer DCID; L2CA_Config then keeps it in CONFIG
 * while a CFG_REQ is sent.  State asserted at each step.
 */
ATF_TC_WITHOUT_HEAD(sm_outbound_bredr_connect_config);
ATF_TC_BODY(sm_outbound_bredr_connect_config, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	ident;
	u_int8_t	rsp[8];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);

	/* --- L2CA_Connect --- */
	ATF_REQUIRE_EQ(0, l2ca_con_req(0x0001, NG_HCI_LINK_ACL,
	    NG_L2CAP_L2CA_IDTYPE_BREDR));
	ch = ng_l2cap_chan_by_scid(&g_l2cap,
	    TAILQ_FIRST(&con->cmd_list)->ch->scid, NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_CON_RSP, ch->state);
	ATF_CHECK_EQ(1, callouts_pending());		/* RTX on CON_REQ */
	ident = first_cmd_ident(con);

	/* --- inbound Connection Response: Success --- */
	w16(rsp, 0, 0x0080);		/* peer DCID */
	w16(rsp, 2, ch->scid);		/* our SCID */
	w16(rsp, 4, BT_CORE63_L2CAP_RESULT_SUCCESS);
	w16(rsp, 6, 0x0000);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, ident,
	    rsp, sizeof(rsp));
	ATF_CHECK_EQ(NG_L2CAP_CONFIG, ch->state);
	ATF_CHECK_EQ(0x0080, ch->dcid);
	ATF_CHECK_EQ(0, callouts_pending());		/* RTX cancelled */

	/* --- L2CA_Config --- */
	ATF_REQUIRE_EQ(0, l2ca_cfg_req(ch, 0x0030));
	ATF_CHECK_EQ(NG_L2CAP_CONFIG, ch->state);
	ATF_CHECK_EQ(1, callouts_pending());		/* RTX on CFG_REQ */
	/* A CFG_REQ PDU was emitted on the BR/EDR signalling CID. */
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONFIG_REQ,
	    g_frames[g_nframes - 1].data[0]);

	drain_tx(con);
}

/*
 * §4.6: L2CA_Disconnect on an OPEN channel moves it to W4_L2CAP_DISCON_RSP,
 * emits a Disconnection Request, and arms RTX.  An inbound Disconnection
 * Response then tears the channel down.
 */
ATF_TC_WITHOUT_HEAD(sm_disconnect_req_then_rsp);
ATF_TC_BODY(sm_disconnect_req_then_rsp, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid, dcid;
	u_int8_t	ident;
	u_int8_t	rsp[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0071,
	    247, 247, 65, 8, 512, 512);
	scid = ch->scid;
	dcid = ch->dcid;

	ATF_REQUIRE_EQ(0, l2ca_discon_req(ch, NG_L2CAP_L2CA_IDTYPE_LE));
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_DISCON_RSP, ch->state);
	ATF_CHECK_EQ(1, callouts_pending());		/* RTX on DISCON_REQ */
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, g_frames[0].data[0]);
	ident = first_cmd_ident(con);

	/* Inbound Disconnection Response echoing our DCID/SCID. */
	w16(rsp, 0, dcid);
	w16(rsp, 2, scid);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_RSP, ident,
	    rsp, sizeof(rsp));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);		/* torn down */
	ATF_CHECK_EQ(0, callouts_pending());

	drain_tx(con);
}

/* ====================================================================== */
/* RTX/ERTX guard timers on data-adjacent commands -- §6.2               */
/* ====================================================================== */

/*
 * §6.2: an unanswered CFG_REQ times out; the RTX expiry reports
 * L2CA_ConfigRsp(Timeout) up while leaving the channel in place (the config
 * timeout does not free the channel in this stack).
 */
ATF_TC_WITHOUT_HEAD(rtx_cfg_req_timeout);
ATF_TC_BODY(rtx_cfg_req_timeout, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0080,
	    0, 0, 0, 0, 672, 672);
	ch->le_psm = 0;
	ch->state = NG_L2CAP_CONFIG;

	ATF_REQUIRE_EQ(0, l2ca_cfg_req(ch, 0x0030));
	ATF_CHECK_EQ(1, callouts_pending());		/* RTX armed */
	ATF_CHECK_EQ(0, g_nmsg);

	ATF_CHECK_EQ(1, fire_callouts());		/* RTX expiry */
	ATF_CHECK_EQ(0, callouts_pending());
	/* Channel still exists after a config timeout. */
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, ch->scid,
	    NG_L2CAP_L2CA_IDTYPE_BREDR) != NULL);

	drain_tx(con);
}

/*
 * §6.2: an unanswered DISCON_REQ times out; the RTX expiry reports
 * L2CA_DisconnectRsp(Timeout) up and frees the channel.
 */
ATF_TC_WITHOUT_HEAD(rtx_discon_req_timeout_frees);
ATF_TC_BODY(rtx_discon_req_timeout_frees, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0071,
	    247, 247, 65, 8, 512, 512);
	scid = ch->scid;

	ATF_REQUIRE_EQ(0, l2ca_discon_req(ch, NG_L2CAP_L2CA_IDTYPE_LE));
	ATF_CHECK_EQ(1, callouts_pending());

	ATF_CHECK_EQ(1, fire_callouts());
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);
	ATF_CHECK_EQ(0, callouts_pending());

	drain_tx(con);
}

/*
 * §6.2: an L2CA_Ping (Echo Request) arms RTX; on expiry the ping primitive is
 * failed with Timeout (ECHO_REQ timeout branch of the command dispatcher).
 */
ATF_TC_WITHOUT_HEAD(rtx_ping_req_timeout);
ATF_TC_BODY(rtx_ping_req_timeout, tc)
{
	ng_l2cap_con_p	con;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_l2cap.ctl = (hook_p)&g_l2cap;			/* control hook up */

	ATF_REQUIRE_EQ(0, l2ca_ping_req());
	ATF_CHECK_EQ(1, callouts_pending());		/* RTX on ECHO_REQ */
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECHO_REQ, g_frames[0].data[0]);

	ATF_CHECK_EQ(1, fire_callouts());
	ATF_CHECK_EQ(0, callouts_pending());

	drain_tx(con);
}

/*
 * §6.2: an L2CA_GetInfo (Information Request) arms RTX; on expiry the info
 * primitive is failed with Timeout (INFO_REQ timeout branch).
 */
ATF_TC_WITHOUT_HEAD(rtx_get_info_req_timeout);
ATF_TC_BODY(rtx_get_info_req_timeout, tc)
{
	ng_l2cap_con_p	con;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_l2cap.ctl = (hook_p)&g_l2cap;

	ATF_REQUIRE_EQ(0, l2ca_get_info_req(NG_HCI_LINK_ACL));
	ATF_CHECK_EQ(1, callouts_pending());		/* RTX on INFO_REQ */
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_INFO_REQ, g_frames[0].data[0]);

	ATF_CHECK_EQ(1, fire_callouts());
	ATF_CHECK_EQ(0, callouts_pending());

	drain_tx(con);
}

/* ====================================================================== */
/* Connect-primitive idtype fan-out + CLT + enable -- ulpi.c coverage    */
/* ====================================================================== */

/*
 * L2CA_Connect builds a different signalling PDU per idtype.  Drive LE CoC,
 * ECBFC, ATT, SMP and BR/EDR connects and confirm each half-opens a channel
 * in W4_L2CAP_CON_RSP with an appropriate command queued.
 */
ATF_TC_WITHOUT_HEAD(con_req_idtype_fan_out);
ATF_TC_BODY(con_req_idtype_fan_out, tc)
{
	ng_l2cap_con_p	le, acl;

	reset_all();
	le = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);

	/* LE Credit Based Connection. */
	ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_SPSM_EATT,
	    NG_HCI_LINK_LE_PUBLIC, NG_L2CAP_L2CA_IDTYPE_LE));
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ,
	    g_frames[g_nframes - 1].data[0]);

	/* Enhanced Credit Based Connection. */
	ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_SPSM_EATT,
	    NG_HCI_LINK_LE_PUBLIC, NG_L2CAP_L2CA_IDTYPE_ECBFC));
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    g_frames[g_nframes - 1].data[0]);

	/* ATT and SMP fixed-CID connects use plain Connection Request PDUs. */
	ATF_REQUIRE_EQ(0, l2ca_con_req(0x001f, NG_HCI_LINK_LE_PUBLIC,
	    NG_L2CAP_L2CA_IDTYPE_ATT));
	ATF_REQUIRE_EQ(0, l2ca_con_req(0x001f, NG_HCI_LINK_LE_PUBLIC,
	    NG_L2CAP_L2CA_IDTYPE_SMP));

	/* BR/EDR classic connect. */
	acl = mk_con(NG_HCI_LINK_ACL, 1);
	ATF_REQUIRE_EQ(0, l2ca_con_req(0x0001, NG_HCI_LINK_ACL,
	    NG_L2CAP_L2CA_IDTYPE_BREDR));
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONNECTION_REQ, g_frames[g_nframes - 1].data[0]);

	(void)le;
	drain_tx(le);
	drain_tx(acl);
}

/*
 * §4.22 / write path: if the lower layer refuses the outbound LE Credit Based
 * Connection Request, the connect primitive is failed up with No Resources and
 * the half-open channel is freed (CON_REQ error branch of con_wakeup).
 */
ATF_TC_WITHOUT_HEAD(con_req_lp_send_failure_frees_channel);
ATF_TC_BODY(con_req_lp_send_failure_frees_channel, tc)
{
	ng_l2cap_con_p	con;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	g_lp_send_err = ENOBUFS;

	ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_SPSM_EATT,
	    NG_HCI_LINK_LE_PUBLIC, NG_L2CAP_L2CA_IDTYPE_LE));

	/* Channel was freed; no LE channels remain and no RTX is armed. */
	ATF_CHECK(LIST_EMPTY(&g_l2cap.chan_list));
	ATF_CHECK_EQ(0, callouts_pending());
	/* L2CA_Connect confirmation reported No Resources. */
	ATF_CHECK_EQ(1, g_nmsg);

	drain_tx(con);
}

/*
 * A connectionless (CLT) L2CAP packet for an enabled PSM is delivered upstream
 * unchanged (ng_l2cap_l2ca_clt_receive).  Disabling the PSM via L2CA_EnableCLT
 * then causes the same packet to be dropped.
 */
ATF_TC_WITHOUT_HEAD(clt_receive_and_enable_gate);
ATF_TC_BODY(clt_receive_and_enable_gate, tc)
{
	ng_l2cap_con_p	con;
	struct mbuf	*m;
	ng_l2cap_hdr_t	*h;
	ng_l2cap_clt_hdr_t *c;
	u_int8_t	payload[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);

	/* Build [L2CAP hdr][CLT hdr(psm=SDP)][payload]. */
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	h = (ng_l2cap_hdr_t *)m->m_data;
	h->length = htole16((u_int16_t)(sizeof(*c) + sizeof(payload)));
	h->dcid = htole16(BT_CORE63_L2CAP_CID_CONNECTIONLESS);
	c = (ng_l2cap_clt_hdr_t *)(m->m_data + sizeof(*h));
	c->psm = htole16(BT_ASSIGNED_L2CAP_PSM_SDP);
	memcpy(m->m_data + sizeof(*h) + sizeof(*c), payload, sizeof(payload));
	m->m_len = m->m_pkthdr.len =
	    sizeof(*h) + sizeof(*c) + sizeof(payload);
	con->rx_pkt = m;

	ATF_REQUIRE_EQ(0, ng_l2cap_l2ca_clt_receive(con));
	ATF_CHECK_EQ(1, g_ndata);			/* delivered upstream */

	/* Disable SDP CLT and re-feed: dropped. */
	ATF_REQUIRE_EQ(0, l2ca_enable_clt(BT_ASSIGNED_L2CAP_PSM_SDP, 0));
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	h = (ng_l2cap_hdr_t *)m->m_data;
	h->length = htole16((u_int16_t)(sizeof(*c) + sizeof(payload)));
	h->dcid = htole16(BT_CORE63_L2CAP_CID_CONNECTIONLESS);
	c = (ng_l2cap_clt_hdr_t *)(m->m_data + sizeof(*h));
	c->psm = htole16(BT_ASSIGNED_L2CAP_PSM_SDP);
	memcpy(m->m_data + sizeof(*h) + sizeof(*c), payload, sizeof(payload));
	m->m_len = m->m_pkthdr.len =
	    sizeof(*h) + sizeof(*c) + sizeof(payload);
	con->rx_pkt = m;
	ATF_REQUIRE_EQ(0, ng_l2cap_l2ca_clt_receive(con));
	ATF_CHECK_EQ(1, g_ndata);			/* still 1: dropped */

	drain_tx(con);
}

ATF_TC_WITHOUT_HEAD(clt_receive_rejection_matrix);
ATF_TC_BODY(clt_receive_rejection_matrix, tc)
{
	ng_l2cap_con_p con;
	struct mbuf *m;
	ng_l2cap_hdr_t *h;
	ng_l2cap_clt_hdr_t *c;
	static const struct {
		u_int16_t psm;
		u_int32_t disabled;
	} gated[] = {
		{ BT_ASSIGNED_L2CAP_PSM_RFCOMM, NG_L2CAP_CLT_RFCOMM_DISABLED },
		{ BT_ASSIGNED_L2CAP_PSM_TCS_BIN, NG_L2CAP_CLT_TCP_DISABLED },
	};

	/* A deliberately inconsistent record reaches the signed short-packet
	 * check without being consumed by the pullup shim. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	m->m_len = sizeof(*h) + sizeof(*c);
	m->m_pkthdr.len = sizeof(*h) + sizeof(*c) - 1;
	con->rx_pkt = m;
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_clt_receive(con));

	/* The connectionless MTU is enforced independently of the L2CAP header. */
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	h = (ng_l2cap_hdr_t *)m->m_data;
	h->length = htole16(sizeof(*c) + BT_CORE63_L2CAP_MTU_DEFAULT_BR_EDR + 1);
	h->dcid = htole16(BT_CORE63_L2CAP_CID_CONNECTIONLESS);
	c = (ng_l2cap_clt_hdr_t *)(m->m_data + sizeof(*h));
	c->psm = htole16(BT_ASSIGNED_L2CAP_PSM_SDP);
	m->m_len = m->m_pkthdr.len = sizeof(*h) + sizeof(*c) +
	    BT_CORE63_L2CAP_MTU_DEFAULT_BR_EDR + 1;
	con->rx_pkt = m;
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_clt_receive(con));

	/* RFCOMM and TCP each have an independent administrative drop bit. */
	for (size_t i = 0; i < nitems(gated); i++) {
		m = ng_mbuf_alloc();
		ATF_REQUIRE(m != NULL);
		h = (ng_l2cap_hdr_t *)m->m_data;
		h->length = htole16(sizeof(*c) + 1);
		h->dcid = htole16(BT_CORE63_L2CAP_CID_CONNECTIONLESS);
		c = (ng_l2cap_clt_hdr_t *)(m->m_data + sizeof(*h));
		c->psm = htole16(gated[i].psm);
		m->m_len = m->m_pkthdr.len = sizeof(*h) + sizeof(*c) + 1;
		con->rx_pkt = m;
		g_l2cap.flags |= gated[i].disabled;
		ATF_CHECK_EQ(0, ng_l2cap_l2ca_clt_receive(con));
		g_l2cap.flags &= ~gated[i].disabled;
	}

	/* Both selectors also pass traffic when their drop bit is clear. */
	for (size_t i = 0; i < nitems(gated); i++) {
		m = ng_mbuf_alloc();
		ATF_REQUIRE(m != NULL);
		h = (ng_l2cap_hdr_t *)m->m_data;
		h->length = htole16(sizeof(*c) + 1);
		h->dcid = htole16(BT_CORE63_L2CAP_CID_CONNECTIONLESS);
		c = (ng_l2cap_clt_hdr_t *)(m->m_data + sizeof(*h));
		c->psm = htole16(gated[i].psm);
		m->m_len = m->m_pkthdr.len = sizeof(*h) + sizeof(*c) + 1;
		con->rx_pkt = m;
		ATF_CHECK_EQ(0, ng_l2cap_l2ca_clt_receive(con));
	}
	ATF_CHECK_EQ(2, g_ndata);

	/* A valid PSM still fails cleanly when the upstream hook is absent. */
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	h = (ng_l2cap_hdr_t *)m->m_data;
	h->length = htole16(sizeof(*c) + 1);
	h->dcid = htole16(BT_CORE63_L2CAP_CID_CONNECTIONLESS);
	c = (ng_l2cap_clt_hdr_t *)(m->m_data + sizeof(*h));
	c->psm = htole16(BT_ASSIGNED_L2CAP_PSM_SDP);
	m->m_len = m->m_pkthdr.len = sizeof(*h) + sizeof(*c) + 1;
	con->rx_pkt = m;
	g_l2cap.l2c = NULL;
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_clt_receive(con));
	drain_tx(con);
}

ATF_TC_WITHOUT_HEAD(cfg_request_fault_completion);
ATF_TC_BODY(cfg_request_fault_completion, tc)
{
	ng_l2cap_con_p con;
	ng_l2cap_chan_p ch;
	ng_l2cap_l2ca_cfg_ip cfg;
	ng_l2cap_l2ca_cfg_rsp_ip ip;
	struct ng_mesg *msg;

	/* ConfigReq has three distinct allocation stages: option mbuf,
	 * command descriptor, and encoded request mbuf. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0055,
	    0, 0, 0, 0, 672, 672);
	g_mbuf_budget = 0;
	ATF_CHECK_EQ(ENOBUFS, l2ca_cfg_req(ch, 48));
	g_mbuf_budget = -1;
	g_kmalloc_budget = 0;
	ATF_CHECK_EQ(ENOMEM, l2ca_cfg_req(ch, 48));
	g_kmalloc_budget = -1;
	g_mbuf_budget = 1;
	ATF_CHECK_EQ(ENOBUFS, l2ca_cfg_req(ch, 48));
	g_mbuf_budget = -1;
	drain_tx(con);

	/* Fixed ATT/SMP CIDs remain OPEN when a local reconfiguration is sent. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, BT_CORE63_L2CAP_CID_ATT,
	    0, 0, 0, 0, 672, 672);
	ch->scid = BT_CORE63_L2CAP_CID_ATT;
	ATF_REQUIRE_EQ(0, l2ca_cfg_req(ch, 48));
	ATF_CHECK_EQ(NG_L2CAP_OPEN, ch->state);
	drain_tx(con);

	/* Non-default flush timeout and outbound flow each become wire options. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0055,
	    0, 0, 0, 0, 672, 672);
	memset(&cfg, 0, sizeof(cfg));
	cfg.lcid = ch->scid;
	cfg.imtu = BT_CORE63_L2CAP_MTU_DEFAULT_BR_EDR;
	bcopy(ng_l2cap_default_flow(), &cfg.oflow, sizeof(cfg.oflow));
	cfg.oflow.flags ^= 1;
	cfg.flush_timo = NG_L2CAP_FLUSH_TIMO_DEFAULT - 1;
	cfg.link_timo = NG_L2CAP_LINK_TIMO_DEFAULT;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CFG, &cfg, sizeof(cfg));
	ATF_REQUIRE_EQ(0, ng_l2cap_l2ca_cfg_req(&g_l2cap, msg));
	(free)(msg);
	drain_tx(con);

	/* Receiving the peer half after our half completes configuration. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0055,
	    0, 0, 0, 0, 672, 672);
	ch->state = NG_L2CAP_CONFIG;
	ch->cfg_state = NG_L2CAP_CFG_OUT;
	ATF_REQUIRE_EQ(0, ng_l2cap_l2ca_cfg_rsp(ch, 0x2222,
	    BT_CORE63_L2CAP_RESULT_SUCCESS));
	ATF_CHECK_EQ(NG_L2CAP_OPEN, ch->state);
	drain_tx(con);

	/* Sending our half after the peer half reaches the same OPEN state. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0055,
	    0, 0, 0, 0, 672, 672);
	ch->state = NG_L2CAP_CONFIG;
	ch->cfg_state = NG_L2CAP_CFG_IN;
	ch->ident = 0x44;
	memset(&ip, 0, sizeof(ip));
	ip.lcid = ch->scid;
	ip.omtu = ch->omtu;
	bcopy(&ch->iflow, &ip.iflow, sizeof(ip.iflow));
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CFG_RSP, &ip, sizeof(ip));
	ATF_REQUIRE_EQ(0, ng_l2cap_l2ca_cfg_rsp_req(&g_l2cap, msg));
	(free)(msg);
	ATF_CHECK_EQ(NG_L2CAP_OPEN, ch->state);
	drain_tx(con);

	/* ConfigRsp mirrors its independent option/command/PDU failures and
	 * copies a changed inbound QoS flow into the channel. */
	for (int fault = 0; fault < 3; fault++) {
		reset_all();
		con = mk_con(NG_HCI_LINK_ACL, 1);
		ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0055,
		    0, 0, 0, 0, 672, 672);
		ch->state = NG_L2CAP_CONFIG;
		ch->ident = 0x44;
		memset(&ip, 0, sizeof(ip));
		ip.lcid = ch->scid;
		ip.omtu = 48;
		ip.iflow.flags = 1;
		msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CFG_RSP, &ip, sizeof(ip));
		if (fault == 0)
			g_mbuf_budget = 0;
		else if (fault == 1)
			g_kmalloc_budget = 0;
		else
			g_mbuf_budget = 1;
		ATF_CHECK_EQ(fault == 1 ? ENOMEM : ENOBUFS,
		    ng_l2cap_l2ca_cfg_rsp_req(&g_l2cap, msg));
		(free)(msg);
		g_mbuf_budget = g_kmalloc_budget = -1;
		drain_tx(con);
	}
}

ATF_TC_WITHOUT_HEAD(credit_and_fixed_channel_fault_completion);
ATF_TC_BODY(credit_and_fixed_channel_fault_completion, tc)
{
	ng_l2cap_con_p con;
	ng_l2cap_chan_p ch;
	u_int8_t sdu[4] = { 2, 0, 0xaa, 0xbb };
	ng_l2cap_l2ca_ping_ip *pip;
	struct ng_mesg *msg;
	size_t msglen;
	u_int16_t scid;
	u_int16_t con_handle;

	/* Completing an SDU with depleted credits must fail closed if either
	 * the replenishment command or its signalling mbuf cannot be allocated. */
	for (int fault = 0; fault < 2; fault++) {
		reset_all();
		con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
		ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
		    23, 23, 1, 5, 512, 512);
		scid = ch->scid;
		if (fault == 0)
			g_kmalloc_budget = 0;
		else
			g_mbuf_budget = 1; /* inbound K-frame succeeds, credit PDU fails */
		ATF_CHECK_EQ(ENOMEM, feed_data(con, scid, sdu, sizeof(sdu)));
		ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
		    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);
		g_kmalloc_budget = g_mbuf_budget = -1;
		drain_tx(con);
	}

	/* SMP is a fixed channel just like ATT: disconnect is local and keyed
	 * by the controller connection handle, not a dynamic CID. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0, NG_L2CAP_L2CA_IDTYPE_SMP);
	ATF_REQUIRE(ch != NULL);
	con_handle = con->con_handle;
	ch->scid = ch->dcid = BT_CORE63_L2CAP_CID_SMP;
	ch->state = NG_L2CAP_OPEN;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_DISCON,
	    &(ng_l2cap_l2ca_discon_ip){ .lcid = con_handle,
	    .idtype = NG_L2CAP_L2CA_IDTYPE_SMP },
	    sizeof(ng_l2cap_l2ca_discon_ip));
	ATF_CHECK_EQ(0, ng_l2cap_l2ca_discon_req(&g_l2cap, msg));
	(free)(msg);
	ATF_CHECK(ng_l2cap_chan_by_conhandle(&g_l2cap, BT_CORE63_L2CAP_CID_SMP,
	    con_handle) == NULL);
	/* Repeating the fixed-channel request reports the missing channel. */
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_DISCON,
	    &(ng_l2cap_l2ca_discon_ip){ .lcid = con_handle,
	    .idtype = NG_L2CAP_L2CA_IDTYPE_SMP },
	    sizeof(ng_l2cap_l2ca_discon_ip));
	ATF_CHECK_EQ(EINVAL, ng_l2cap_l2ca_discon_req(&g_l2cap, msg));
	(free)(msg);
	drain_tx(con);

	/* A sufficiently large message reaches the echo protocol maximum check,
	 * rather than the earlier message-overflow guard. */
	reset_all();
	msglen = sizeof(*msg) + sizeof(*pip) + NG_L2CAP_MAX_ECHO_SIZE + 1;
	msg = calloc(1, msglen);
	ATF_REQUIRE(msg != NULL);
	msg->header.arglen = sizeof(*pip) + NG_L2CAP_MAX_ECHO_SIZE + 1;
	pip = (ng_l2cap_l2ca_ping_ip *)msg->data;
	pip->bdaddr = g_addr;
	pip->echo_size = NG_L2CAP_MAX_ECHO_SIZE + 1;
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_ping_req(&g_l2cap, msg));
	(free)(msg);

	/* An otherwise-valid write drops its mbuf if no command can be made. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0055,
	    0, 0, 0, 0, 672, 672);
	g_kmalloc_budget = 0;
	ATF_CHECK_EQ(ENOMEM, do_write(con, ch, sdu, sizeof(sdu)));
	g_kmalloc_budget = -1;
	drain_tx(con);

	/* Disconnect indications preserve ECBFC identity for exact socket lookup,
	 * while fixed channels identify themselves with the controller handle. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0055,
	    23, 23, 1, 1, 512, 512);
	ATF_CHECK_EQ(0, ng_l2cap_l2ca_discon_ind(ch));
	ATF_CHECK_EQ(NG_L2CAP_L2CA_IDTYPE_ECBFC, g_discon_idtype);
	ATF_CHECK_EQ(ch->scid, g_discon_lcid);
	drain_tx(con);

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0,
	    NG_L2CAP_L2CA_IDTYPE_ATT);
	ATF_REQUIRE(ch != NULL);
	ch->scid = ch->dcid = BT_CORE63_L2CAP_CID_ATT;
	ch->state = NG_L2CAP_OPEN;
	ATF_CHECK_EQ(0, ng_l2cap_l2ca_discon_ind(ch));
	drain_tx(con);
}

/*
 * A connectionless (CLT, CID 0x0002) L2CAP frame is BR/EDR-only (Vol 3 Part A
 * §2.1 / Table 2.1).  Arriving on an LE-U link it MUST be dropped by the
 * ng_l2cap_receive() CID router, never delivered upstream.  Driving the frame
 * through the real router (not ng_l2cap_l2ca_clt_receive() directly) exercises
 * the linktype guard; on an LE link g_ndata must stay 0.  (Kills a `||`->`&&`
 * weakening of that guard that would let LE-link CLT traffic through.)
 */
ATF_TC_WITHOUT_HEAD(clt_on_le_link_dropped);
ATF_TC_BODY(clt_on_le_link_dropped, tc)
{
	ng_l2cap_con_p	con;
	struct mbuf	*m;
	ng_l2cap_hdr_t	*h;
	ng_l2cap_clt_hdr_t *c;
	u_int8_t	payload[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	reset_all();
	/* SDP CLT enabled so a BR/EDR frame WOULD be delivered upstream. */
	ATF_REQUIRE_EQ(0, l2ca_enable_clt(BT_ASSIGNED_L2CAP_PSM_SDP, 1));
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);

	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	h = (ng_l2cap_hdr_t *)m->m_data;
	h->length = htole16((u_int16_t)(sizeof(*c) + sizeof(payload)));
	h->dcid = htole16(BT_CORE63_L2CAP_CID_CONNECTIONLESS);
	c = (ng_l2cap_clt_hdr_t *)(m->m_data + sizeof(*h));
	c->psm = htole16(BT_ASSIGNED_L2CAP_PSM_SDP);
	memcpy(m->m_data + sizeof(*h) + sizeof(*c), payload, sizeof(payload));
	m->m_len = m->m_pkthdr.len =
	    sizeof(*h) + sizeof(*c) + sizeof(payload);
	con->rx_pkt = m;

	(void)ng_l2cap_receive(con);
	ATF_CHECK_EQ_MSG(0, g_ndata,
	    "a CLT frame on an LE-U link must be dropped, not delivered");

	drain_tx(con);
}

/*
 * L2CA_EnableCLT covers each PSM selector plus the enable-all (psm 0) and the
 * unsupported-PSM (ENOTSUP) arms.
 */
ATF_TC_WITHOUT_HEAD(enable_clt_all_selectors);
ATF_TC_BODY(enable_clt_all_selectors, tc)
{

	reset_all();

	ATF_CHECK_EQ(0, l2ca_enable_clt(BT_ASSIGNED_L2CAP_PSM_SDP, 1));
	ATF_CHECK_EQ(0, l2ca_enable_clt(BT_ASSIGNED_L2CAP_PSM_SDP, 0));
	ATF_CHECK_EQ(0, l2ca_enable_clt(BT_ASSIGNED_L2CAP_PSM_RFCOMM, 1));
	ATF_CHECK_EQ(0, l2ca_enable_clt(BT_ASSIGNED_L2CAP_PSM_RFCOMM, 0));
	ATF_CHECK_EQ(0, l2ca_enable_clt(BT_ASSIGNED_L2CAP_PSM_TCS_BIN, 1));
	ATF_CHECK_EQ(0, l2ca_enable_clt(BT_ASSIGNED_L2CAP_PSM_TCS_BIN, 0));
	ATF_CHECK_EQ(0, l2ca_enable_clt(0, 1));		/* enable all */
	ATF_CHECK_EQ(0, l2ca_enable_clt(0, 0));		/* disable all */
	ATF_CHECK_EQ(ENOTSUP, l2ca_enable_clt(0x1234, 1)); /* unsupported */
}

/*
 * Inbound accept: L2CA_ConnectRsp(Success) on a channel awaiting the upper
 * layer's decision moves it to CONFIG and queues an outgoing Connection
 * Response (exercises ng_l2cap_l2ca_con_rsp_req + the CON_RSP dispatch arm).
 */
ATF_TC_WITHOUT_HEAD(con_rsp_req_accept);
ATF_TC_BODY(con_rsp_req_accept, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	ng_l2cap_l2ca_con_rsp_ip	ip;
	struct ng_mesg	*msg;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->dcid = 0x0080;
	ch->ident = 0x33;
	ch->state = NG_L2CAP_W4_L2CA_CON_RSP;

	memset(&ip, 0, sizeof(ip));
	bcopy(&g_addr, &ip.bdaddr, sizeof(ip.bdaddr));
	ip.ident = 0x34; /* accepted, but exercises the peer-ident mismatch path */
	ip.linktype = NG_HCI_LINK_ACL;
	ip.lcid = ch->scid;
	ip.result = BT_CORE63_L2CAP_RESULT_SUCCESS;
	ip.status = 0;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CON_RSP, &ip, sizeof(ip));
	ATF_REQUIRE_EQ(0, ng_l2cap_l2ca_con_rsp_req(&g_l2cap, msg));
	(free)(msg);

	ATF_CHECK_EQ(NG_L2CAP_CONFIG, ch->state);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONNECTION_RSP, g_frames[0].data[0]);

	drain_tx(con);
}

/*
 * Inbound config completion: L2CA_ConfigRsp on a BR/EDR channel in CONFIG
 * queues a Configuration Response and records the outbound-config-done flag
 * (exercises ng_l2cap_l2ca_cfg_rsp_req + the CFG_RSP dispatch arm).
 */
ATF_TC_WITHOUT_HEAD(cfg_rsp_req_completes_out);
ATF_TC_BODY(cfg_rsp_req_completes_out, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	ng_l2cap_l2ca_cfg_rsp_ip	ip;
	struct ng_mesg	*msg;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->dcid = 0x0080;
	ch->ident = 0x44;
	ch->state = NG_L2CAP_CONFIG;

	memset(&ip, 0, sizeof(ip));
	ip.lcid = ch->scid;
	ip.omtu = 0x0200;
	bcopy(ng_l2cap_default_flow(), &ip.iflow, sizeof(ip.iflow));
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CFG_RSP, &ip, sizeof(ip));
	ATF_REQUIRE_EQ(0, ng_l2cap_l2ca_cfg_rsp_req(&g_l2cap, msg));
	(free)(msg);

	ATF_CHECK_EQ(0x0200, ch->omtu);
	ATF_CHECK((ch->cfg_state & NG_L2CAP_CFG_OUT) != 0);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONFIG_RSP, g_frames[0].data[0]);

	drain_tx(con);
}

/*
 * ACL connection failure (ng_l2cap_con_fail): every queued command is flushed
 * with its type-specific upper-layer notification, all channels are torn down,
 * and the connection descriptor is freed.  Queues a mix of command codes to
 * fan out through the con_fail switch.
 */
ATF_TC_WITHOUT_HEAD(con_fail_flushes_all_commands);
ATF_TC_BODY(con_fail_flushes_all_commands, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ca, cb, cc, cd;
	ng_l2cap_cmd_p	cmd;

	reset_all();
	g_l2cap.ctl = (hook_p)&g_l2cap;			/* for ping/info rsp */
	con = mk_con(NG_HCI_LINK_ACL, 1);

	ca = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cb = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cc = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cd = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ca && cb && cc && cd);

	/* CON_REQ -> l2ca_con_rsp(result). */
	cmd = ng_l2cap_new_cmd(con, ca, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x1);
	ng_l2cap_link_cmd(con, cmd);
	/* CFG_REQ -> l2ca_discon_ind. */
	cmd = ng_l2cap_new_cmd(con, cb, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x2);
	ng_l2cap_link_cmd(con, cmd);
	/* WRITE -> l2ca_discon_ind. */
	cmd = ng_l2cap_new_cmd(con, cc, ng_l2cap_get_ident(con),
	    NGM_L2CAP_L2CA_WRITE, 0x3);
	ng_l2cap_link_cmd(con, cmd);
	/* DISCON_REQ -> l2ca_discon_rsp. */
	cmd = ng_l2cap_new_cmd(con, cd, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, 0x4);
	ng_l2cap_link_cmd(con, cmd);
	/* ECHO_REQ (no channel) -> l2ca_ping_rsp. */
	cmd = ng_l2cap_new_cmd(con, NULL, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_ECHO_REQ, 0x5);
	ng_l2cap_link_cmd(con, cmd);
	/* INFO_REQ (no channel) -> l2ca_get_info_rsp. */
	cmd = ng_l2cap_new_cmd(con, NULL, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_INFO_REQ, 0x6);
	ng_l2cap_link_cmd(con, cmd);

	ng_l2cap_con_fail(con, NG_L2CAP_TIMEOUT);

	/* Connection and all its channels are gone. */
	ATF_CHECK(LIST_EMPTY(&g_l2cap.con_list));
	ATF_CHECK(LIST_EMPTY(&g_l2cap.chan_list));
}

/* ====================================================================== */
/* LE Credit Based Connection signalling -- Core Spec Vol 3 Part A §4.22  */
/* (code 0x14 request / 0x15 response).  These drive the SIGNALLING       */
/* decode+response path of ng_l2cap_process_le_credit_con_req/_rsp, which  */
/* the data-plane tests above never exercise (they hand-build channels).  */
/* Every expected response byte is hand-encoded from §4.22 and the local  */
/* stack constants (LOCAL_MTU 512, LOCAL_MPS 247, INITIAL_CREDITS 65).    */
/* ====================================================================== */

/* Feed one LE Credit Based Connection Request (0x14). §4.22 body:
 * [le_psm(2)][scid(2)][mtu(2)][mps(2)][initial_credits(2)]. */
static void
feed_le_credit_con_req(ng_l2cap_con_p con, u_int8_t ident, u_int16_t psm,
    u_int16_t scid, u_int16_t mtu, u_int16_t mps, u_int16_t credits)
{
	u_int8_t	req[10];

	w16(req, 0, psm);
	w16(req, 2, scid);
	w16(req, 4, mtu);
	w16(req, 6, mps);
	w16(req, 8, credits);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ,
	    ident, req, sizeof(req));
}

static int l2ca_con_rsp_req(u_int16_t, u_int8_t, u_int8_t, u_int16_t);

/*
 * §4.22: a valid LE Credit Based Connection Request for a supported SPSM on an
 * encrypted link is accepted: a channel is opened (state OPEN, dcid = peer
 * SCID) and an LE Credit Based Connection Response (0x15) carrying our local
 * MTU/MPS/credits and result 0x0000 (Success) is returned.  Response body per
 * §4.22: [dcid(2)][mtu(2)][mps(2)][initial_credits(2)][result(2)].
 */
ATF_TC_WITHOUT_HEAD(le_coc_con_req_success);
ATF_TC_BODY(le_coc_con_req_success, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);

	feed_le_credit_con_req(con, 0x40, 0x0080, 0x0045,
	    120, 120, 4);

	/* The peer request is deferred until the upper layer accepts it. */
	ch = ng_l2cap_chan_by_dcid(&g_l2cap, 0x0045, NG_L2CAP_L2CA_IDTYPE_LE);
	ATF_REQUIRE(ch != NULL);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CA_CON_RSP, ch->state);
	ATF_CHECK_EQ(0x0045, ch->dcid);
	ATF_CHECK_EQ(120, ch->omtu);			/* peer MTU */
	ATF_CHECK_EQ(120, ch->mps_remote);		/* peer MPS */
	ATF_CHECK_EQ(4, ch->credits_remote);		/* peer credits */

	ATF_REQUIRE_EQ(0, l2ca_con_rsp_req(ch->scid, NG_HCI_LINK_LE_PUBLIC,
	    0x40, BT_CORE63_L2CAP_RESULT_SUCCESS));
	ATF_CHECK_EQ(NG_L2CAP_OPEN, ch->state);

	/* LE Credit Based Connection Response (0x15), result Success. */
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP, g_frames[0].data[0]);
	ATF_CHECK_EQ(0x40, g_frames[0].data[1]);	/* ident echoed */
	ATF_CHECK_EQ(ch->scid, frame_le16(&g_frames[0], 4));	/* our DCID */
	ATF_CHECK_EQ(512, frame_le16(&g_frames[0], 6));		/* LOCAL_MTU */
	ATF_CHECK_EQ(247, frame_le16(&g_frames[0], 8));		/* LOCAL_MPS */
	ATF_CHECK_EQ(65, frame_le16(&g_frames[0], 10));		/* credits */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_SUCCESS, frame_le16(&g_frames[0], 12));

	drain_tx(con);
}

/*
 * §4.22 reject arms (result in the 0x15 response, no channel opened):
 *  - MTU below the LE minimum (23) -> Unacceptable Parameters (0x000b);
 *  - SCID below the dynamic range  -> Invalid Source CID   (0x0009);
 *  - SCID already in use on link    -> Source CID already allocated (0x000a).
 */
ATF_TC_WITHOUT_HEAD(le_coc_con_req_reject_params_scid);
ATF_TC_BODY(le_coc_con_req_reject_params_scid, tc)
{
	ng_l2cap_con_p	con;

	/* --- Unacceptable Parameters: MTU 10 < 23. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	feed_le_credit_con_req(con, 0x41, 0x0080, 0x0045,
	    10, 120, 4);
	ATF_CHECK(ng_l2cap_chan_by_dcid(&g_l2cap, 0x0045,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP, g_frames[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_UNACCEPTABLE_PARAMS,
	    frame_le16(&g_frames[0], 12));
	drain_tx(con);

	/* --- Initial Credits may be zero; the channel starts flow-stopped. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	feed_le_credit_con_req(con, 0x42, 0x0080, 0x0045,
	    120, 120, 0);
	ATF_REQUIRE_EQ(0, l2ca_con_rsp_req(
	    ng_l2cap_chan_by_dcid(&g_l2cap, 0x0045,
	    NG_L2CAP_L2CA_IDTYPE_LE)->scid, NG_HCI_LINK_LE_PUBLIC,
	    0x42, BT_CORE63_L2CAP_RESULT_SUCCESS));
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_SUCCESS,
	    frame_le16(&g_frames[0], 12));
	ATF_CHECK(ng_l2cap_chan_by_dcid(&g_l2cap, 0x0045,
	    NG_L2CAP_L2CA_IDTYPE_LE) != NULL);
	drain_tx(con);

	/*
	 * --- MPS above the LE maximum is Unacceptable Parameters. §4.22
	 * fixes the MPS range at 23..65533; an MPS of 65534 (== 65533 + 1)
	 * must be rejected, no channel opened.  (Kills a `mps > 65533` ->
	 * `mps > 65535` weakening that would accept 65534/65535.)
	 */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	feed_le_credit_con_req(con, 0x43, 0x0080, 0x0045,
	    120, 65534, 4);
	ATF_CHECK(ng_l2cap_chan_by_dcid(&g_l2cap, 0x0045,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_UNACCEPTABLE_PARAMS,
	    frame_le16(&g_frames[0], 12));
	drain_tx(con);

	/* --- Invalid Source CID: scid 0x0010 < BT_CORE63_L2CAP_CID_DYNAMIC_FIRST. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	feed_le_credit_con_req(con, 0x43, 0x0080, 0x0010,
	    120, 120, 4);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_INVALID_SOURCE_CID,
	    frame_le16(&g_frames[0], 12));
	drain_tx(con);

	/* --- Source CID already in use. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	(void)mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0045,
	    247, 247, 65, 8, 512, 512);
	feed_le_credit_con_req(con, 0x44, 0x0080, 0x0045,
	    120, 120, 4);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_SOURCE_CID_ALLOCATED,
	    frame_le16(&g_frames[0], 12));
	drain_tx(con);
}

/*
 * §4.22 security/PSM reject arms:
 *  - unknown SPSM with no upper-layer hook -> SPSM Not Supported (0x0002);
 *  - unencrypted link (local hardening)    -> Insufficient Encryption (0x0008).
 */
ATF_TC_WITHOUT_HEAD(le_coc_con_req_reject_spsm_enc);
ATF_TC_BODY(le_coc_con_req_reject_spsm_enc, tc)
{
	ng_l2cap_con_p	con;

	/* --- SPSM Not Supported: unknown PSM, hook detached. --- */
	reset_all();
	g_l2cap.l2c = NULL;				/* no upper layer */
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	feed_le_credit_con_req(con, 0x45, 0x0100, 0x0045, 120, 120, 4);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP, g_frames[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_SPSM_NOT_SUPPORTED,
	    frame_le16(&g_frames[0], 12));
	drain_tx(con);

	/* --- Insufficient Encryption: valid EATT request, link unencrypted. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, /*encryption*/0);
	feed_le_credit_con_req(con, 0x46, 0x0080, 0x0045,
	    120, 120, 4);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_INSUFF_ENCRYPTION,
	    frame_le16(&g_frames[0], 12));
	drain_tx(con);
}

/*
 * §4.22 (initiator): our outgoing LE Credit Based Connection Request
 * (L2CA_Connect, idtype LE) leaves the channel in W4_L2CAP_CON_RSP with an RTX
 * timer armed.  An LE Credit Based Connection Response (0x15) with result
 * Success and in-range params completes the channel: it moves to OPEN, records
 * the peer DCID/MTU/MPS/credits, and cancels the RTX guard.
 */
ATF_TC_WITHOUT_HEAD(le_coc_con_rsp_success);
ATF_TC_BODY(le_coc_con_rsp_success, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	ident;
	u_int8_t	rsp[10];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_SPSM_EATT,
	    NG_HCI_LINK_LE_PUBLIC, NG_L2CAP_L2CA_IDTYPE_LE));
	ch = TAILQ_FIRST(&con->cmd_list)->ch;
	ATF_REQUIRE(ch != NULL);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_CON_RSP, ch->state);
	ATF_CHECK_EQ(1, callouts_pending());		/* RTX armed */
	ident = first_cmd_ident(con);
	g_nframes = 0;

	/* Response: dcid=0x0055, mtu=200, mps=100, credits=10, Success. */
	w16(rsp, 0, 0x0055);
	w16(rsp, 2, 200);
	w16(rsp, 4, 100);
	w16(rsp, 6, 10);
	w16(rsp, 8, BT_CORE63_L2CAP_CREDIT_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP,
	    ident, rsp, sizeof(rsp));

	ATF_CHECK_EQ(NG_L2CAP_OPEN, ch->state);
	ATF_CHECK_EQ(0x0055, ch->dcid);
	ATF_CHECK_EQ(200, ch->omtu);
	ATF_CHECK_EQ(100, ch->mps_remote);
	ATF_CHECK_EQ(10, ch->credits_remote);
	ATF_CHECK_EQ(0, callouts_pending());		/* RTX cancelled */

	drain_tx(con);
}

/*
 * §4.22 (initiator) failure/validation arms:
 *  - result != Success                -> channel torn down;
 *  - result Success but MTU < 23       -> EINVAL, channel torn down;
 *  - unknown ident                     -> ignored (no matching command).
 */
ATF_TC_WITHOUT_HEAD(le_coc_con_rsp_failure_and_invalid);
ATF_TC_BODY(le_coc_con_rsp_failure_and_invalid, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	ident;
	u_int8_t	rsp[10];

	/* --- Peer rejects: result = No Resources. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_SPSM_EATT,
	    NG_HCI_LINK_LE_PUBLIC, NG_L2CAP_L2CA_IDTYPE_LE));
	ch = TAILQ_FIRST(&con->cmd_list)->ch;
	scid = ch->scid;
	ident = first_cmd_ident(con);
	w16(rsp, 0, 0); w16(rsp, 2, 0); w16(rsp, 4, 0); w16(rsp, 6, 0);
	w16(rsp, 8, BT_CORE63_L2CAP_CREDIT_NO_RESOURCES);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP,
	    ident, rsp, sizeof(rsp));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);		/* freed */
	drain_tx(con);

	/* --- result Success but invalid MTU (10 < 23): EINVAL, freed. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_SPSM_EATT,
	    NG_HCI_LINK_LE_PUBLIC, NG_L2CAP_L2CA_IDTYPE_LE));
	ch = TAILQ_FIRST(&con->cmd_list)->ch;
	scid = ch->scid;
	ident = first_cmd_ident(con);
	w16(rsp, 0, 0x0055);
	w16(rsp, 2, 10);				/* MTU < 23 */
	w16(rsp, 4, 100);
	w16(rsp, 6, 10);
	w16(rsp, 8, BT_CORE63_L2CAP_CREDIT_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP,
	    ident, rsp, sizeof(rsp));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);		/* freed */
	drain_tx(con);

	/* --- Unknown ident: response ignored, channel left pending. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_SPSM_EATT,
	    NG_HCI_LINK_LE_PUBLIC, NG_L2CAP_L2CA_IDTYPE_LE));
	ch = TAILQ_FIRST(&con->cmd_list)->ch;
	scid = ch->scid;
	w16(rsp, 0, 0x0055); w16(rsp, 2, 200); w16(rsp, 4, 100);
	w16(rsp, 6, 10); w16(rsp, 8, BT_CORE63_L2CAP_CREDIT_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP,
	    (u_int8_t)(first_cmd_ident(con) + 1), rsp, sizeof(rsp));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) != NULL);		/* still pending */
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_CON_RSP,
	    ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE)->state);
	drain_tx(con);
}

/* ====================================================================== */
/* Enhanced Credit Based Connection signalling -- Core Spec Vol 3 Part A  */
/* §4.25 (code 0x17 request / 0x18 response).  These reach                */
/* ng_l2cap_process_credit_con_req/_rsp via injected signalling PDUs.     */
/* ====================================================================== */

/*
 * §4.25: an Enhanced Credit Based Connection Request listing two Source CIDs
 * on an encrypted link opens two ECBFC channels and returns an Enhanced Credit
 * Based Connection Response (0x18) with result Success and a Destination CID
 * for each.  Response body per §4.25:
 * [mtu(2)][mps(2)][initial_credits(2)][result(2)][dcid...(2 each)].
 */
ATF_TC_WITHOUT_HEAD(ecbfc_con_req_success_multi);
ATF_TC_BODY(ecbfc_con_req_success_multi, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	a, b;
	u_int8_t	req[12];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);

	/* [le_psm][mtu][mps][credits][scid0][scid1] */
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200);				/* mtu >= 64 */
	w16(req, 4, 200);				/* mps >= 64 */
	w16(req, 6, 5);					/* credits */
	w16(req, 8, 0x0050);				/* scid0 */
	w16(req, 10, 0x0051);				/* scid1 */
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x50, req, sizeof(req));

	a = ng_l2cap_chan_by_dcid(&g_l2cap, 0x0050,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	b = ng_l2cap_chan_by_dcid(&g_l2cap, 0x0051,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	ATF_REQUIRE(a != NULL && b != NULL);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CA_CON_RSP, a->state);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CA_CON_RSP, b->state);
	ATF_CHECK_EQ(200, a->omtu);
	ATF_CHECK_EQ(200, a->mps_remote);
	ATF_CHECK_EQ(5, a->credits_remote);

	ATF_REQUIRE_EQ(0, l2ca_con_rsp_req(a->scid, NG_HCI_LINK_LE_PUBLIC,
	    0x50, BT_CORE63_L2CAP_RESULT_SUCCESS));
	ATF_CHECK_EQ(0, g_nframes);
	ATF_REQUIRE_EQ(0, l2ca_con_rsp_req(b->scid, NG_HCI_LINK_LE_PUBLIC,
	    0x50, BT_CORE63_L2CAP_RESULT_SUCCESS));
	ATF_CHECK_EQ(NG_L2CAP_OPEN, a->state);
	ATF_CHECK_EQ(NG_L2CAP_OPEN, b->state);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP, g_frames[0].data[0]);
	ATF_CHECK_EQ(512, frame_le16(&g_frames[0], 4));		/* LOCAL_MTU */
	ATF_CHECK_EQ(247, frame_le16(&g_frames[0], 6));		/* LOCAL_MPS */
	ATF_CHECK_EQ(65, frame_le16(&g_frames[0], 8));		/* credits */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_SUCCESS, frame_le16(&g_frames[0], 10));
	/* Two Destination CIDs (our SCIDs) follow. */
	ATF_CHECK_EQ(a->scid, frame_le16(&g_frames[0], 12));
	ATF_CHECK_EQ(b->scid, frame_le16(&g_frames[0], 14));

	drain_tx(con);
}

/*
 * §4.25 reject arms in the 0x18 response (dcid list zero-filled):
 *  - MTU < 64 (ECBFC minimum)  -> Unacceptable Parameters (0x000b);
 *  - unencrypted link          -> Insufficient Encryption (0x0008);
 *  - Source CID already in use -> Source CID already allocated (0x000a).
 */
ATF_TC_WITHOUT_HEAD(ecbfc_con_req_reject_arms);
ATF_TC_BODY(ecbfc_con_req_reject_arms, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	req[12];

	/* --- Unacceptable Parameters: MTU 32 < 64. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 32); w16(req, 4, 200); w16(req, 6, 5); w16(req, 8, 0x0050);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x51, req, sizeof(req));
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP, g_frames[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_UNACCEPTABLE_PARAMS,
	    frame_le16(&g_frames[0], 10));
	drain_tx(con);

	/* --- Insufficient Encryption: valid params, unencrypted link. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, /*encryption*/0);
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5); w16(req, 8, 0x0050);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x52, req, sizeof(req));
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_INSUFF_ENCRYPTION,
	    frame_le16(&g_frames[0], 10));
	drain_tx(con);

	/* --- Source CID already allocated. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	(void)mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0050,
	    247, 247, 65, 8, 512, 512);
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5); w16(req, 8, 0x0050);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x53, req, sizeof(req));
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_SOURCE_CID_ALLOCATED,
	    frame_le16(&g_frames[0], 10));
	drain_tx(con);

	/* --- Unsupported SPSM when no upper L2CAP service hook exists. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	g_l2cap.l2c = NULL;
	w16(req, 0, 0x0081);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5);
	w16(req, 8, 0x0050);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x5d, req, 10);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_SPSM_NOT_SUPPORTED,
	    frame_le16(&g_frames[0], 10));
	drain_tx(con);

	/* --- Source CID below the dynamic range. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5);
	w16(req, 8, 0x0010);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x5e, req, 10);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_INVALID_SOURCE_CID,
	    frame_le16(&g_frames[0], 10));
	drain_tx(con);

	/* --- Duplicate Source CIDs in one atomic request. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5);
	w16(req, 8, 0x0050); w16(req, 10, 0x0050);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x5f, req, sizeof(req));
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_INVALID_SOURCE_CID,
	    frame_le16(&g_frames[0], 10));
	drain_tx(con);
}

/*
 * §4.25: an Enhanced Credit Based Connection Request whose Source CID list is
 * malformed (empty, odd-length, or longer than 10 octets == >5 CIDs) is a
 * length error: the PDU is dropped and NO response is emitted.
 */
ATF_TC_WITHOUT_HEAD(ecbfc_con_req_bad_cid_list);
ATF_TC_BODY(ecbfc_con_req_bad_cid_list, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	req[20];

	/* --- No Source CIDs at all: cmd_length == 8 (< 8+2). --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x54, req, 8);
	ATF_CHECK_EQ(0, g_nframes);
	drain_tx(con);

	/* --- Odd-length CID list (3 octets). --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x55, req, 11);
	ATF_CHECK_EQ(0, g_nframes);
	drain_tx(con);

	/* --- 6 Source CIDs == 12 octets (> 10 max).  Use BR/EDR signaling
	 * here: the 24-octet command frame exceeds LE-U's 23-octet MTUsig and
	 * would correctly be rejected at the frame layer before this parser. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	memset(req, 0, sizeof(req));
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x56, req, 20);
	ATF_CHECK_EQ(0, g_nframes);
	drain_tx(con);
}

/*
 * §4.25 (initiator): our outgoing Enhanced Credit Based Connection Request
 * (L2CA_Connect, idtype ECBFC) parks the channel in W4_L2CAP_CON_RSP.  An
 * Enhanced Credit Based Connection Response (0x18) with result Success and one
 * Destination CID completes it: OPEN, peer DCID/MTU/MPS/credits recorded.
 */
ATF_TC_WITHOUT_HEAD(ecbfc_con_rsp_success);
ATF_TC_BODY(ecbfc_con_rsp_success, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	ident;
	u_int8_t	rsp[10];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_SPSM_EATT,
	    NG_HCI_LINK_LE_PUBLIC, NG_L2CAP_L2CA_IDTYPE_ECBFC));
	ch = TAILQ_FIRST(&con->cmd_list)->ch;
	ATF_REQUIRE(ch != NULL);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_CON_RSP, ch->state);
	ident = first_cmd_ident(con);
	g_nframes = 0;

	/* [mtu][mps][credits][result][dcid0] */
	w16(rsp, 0, 200);
	w16(rsp, 2, 100);
	w16(rsp, 4, 10);
	w16(rsp, 6, BT_CORE63_L2CAP_CREDIT_SUCCESS);
	w16(rsp, 8, 0x0055);				/* peer DCID */
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    ident, rsp, sizeof(rsp));

	ATF_CHECK_EQ(NG_L2CAP_OPEN, ch->state);
	ATF_CHECK_EQ(0x0055, ch->dcid);
	ATF_CHECK_EQ(200, ch->omtu);
	ATF_CHECK_EQ(100, ch->mps_remote);
	ATF_CHECK_EQ(10, ch->credits_remote);
	ATF_CHECK_EQ(0, callouts_pending());

	drain_tx(con);
}

/*
 * §4.25 (initiator) 0x18 response error arms:
 *  - too short (cmd_length < 8)             -> dropped, no state change;
 *  - odd-length DCID list                   -> dropped;
 *  - result Success but MTU < 64            -> EINVAL, channel torn down;
 *  - result Success but DCID below range    -> REJECT to ULP, channel torn down;
 *  - result != Success                      -> channel torn down.
 */
ATF_TC_WITHOUT_HEAD(ecbfc_con_rsp_error_arms);
ATF_TC_BODY(ecbfc_con_rsp_error_arms, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;
	u_int8_t	ident;
	u_int8_t	rsp[20];

#define ECBFC_SETUP_OUTGOING()						\
	do {								\
		reset_all();						\
		con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);			\
		ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_SPSM_EATT,	\
		    NG_HCI_LINK_LE_PUBLIC, NG_L2CAP_L2CA_IDTYPE_ECBFC));	\
		ch = TAILQ_FIRST(&con->cmd_list)->ch;			\
		scid = ch->scid;					\
		ident = first_cmd_ident(con);				\
		g_nframes = 0;						\
	} while (0)

	/* --- Too short: length 6 < sizeof(rsp cp) 8, dropped. --- */
	ECBFC_SETUP_OUTGOING();
	w16(rsp, 0, 200); w16(rsp, 2, 100); w16(rsp, 4, 10);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    ident, rsp, 6);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_CON_RSP,
	    ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC)->state);		/* unchanged */
	drain_tx(con);

	/* --- Odd-length DCID list: 8 + 1 = 9 octets, dropped. --- */
	ECBFC_SETUP_OUTGOING();
	w16(rsp, 0, 200); w16(rsp, 2, 100); w16(rsp, 4, 10);
	w16(rsp, 6, BT_CORE63_L2CAP_CREDIT_SUCCESS); rsp[8] = 0x55;
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    ident, rsp, 9);
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) != NULL);		/* still pending */
	drain_tx(con);

	/* --- Six DCIDs exceeds the fixed five-channel response maximum. --- */
	ECBFC_SETUP_OUTGOING();
	memset(rsp, 0, sizeof(rsp));
	w16(rsp, 0, 200); w16(rsp, 2, 100); w16(rsp, 4, 10);
	w16(rsp, 6, BT_CORE63_L2CAP_CREDIT_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    ident, rsp, sizeof(rsp));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) != NULL);
	drain_tx(con);

	/* --- A response with no matching identifier is ignored. --- */
	ECBFC_SETUP_OUTGOING();
	w16(rsp, 0, 200); w16(rsp, 2, 100); w16(rsp, 4, 10);
	w16(rsp, 6, BT_CORE63_L2CAP_CREDIT_SUCCESS); w16(rsp, 8, 0x0055);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    (u_int8_t)(ident + 1), rsp, 10);
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) != NULL);
	drain_tx(con);

	/* --- Identifier collision with an unrelated command code is ignored. --- */
	ECBFC_SETUP_OUTGOING();
	TAILQ_FIRST(&con->cmd_list)->code = BT_CORE63_L2CAP_CMD_ECHO_REQ;
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    ident, rsp, 10);
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) != NULL);
	drain_tx(con);

	/* --- A matching command whose channel left the wait state is ignored. --- */
	ECBFC_SETUP_OUTGOING();
	ch->state = NG_L2CAP_OPEN;
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    ident, rsp, 10);
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) != NULL);
	drain_tx(con);

	/* --- A response after the guard was disarmed fails the untimeout check. --- */
	ECBFC_SETUP_OUTGOING();
	ATF_REQUIRE_EQ(0,
	    ng_l2cap_command_untimeout(TAILQ_FIRST(&con->cmd_list)));
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    ident, rsp, 10);
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) != NULL);
	drain_tx(con);

	/* --- Success but MTU < 64: EINVAL, channel torn down. --- */
	ECBFC_SETUP_OUTGOING();
	w16(rsp, 0, 32);				/* MTU < 64 */
	w16(rsp, 2, 100); w16(rsp, 4, 10);
	w16(rsp, 6, BT_CORE63_L2CAP_CREDIT_SUCCESS); w16(rsp, 8, 0x0055);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    ident, rsp, 10);
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);		/* freed */
	drain_tx(con);

	/* --- Success cannot be delivered upstream: the opened channel is freed. */
	ECBFC_SETUP_OUTGOING();
	w16(rsp, 0, 200); w16(rsp, 2, 100); w16(rsp, 4, 10);
	w16(rsp, 6, BT_CORE63_L2CAP_CREDIT_SUCCESS); w16(rsp, 8, 0x0055);
	g_mkmsg_budget = 0;
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    ident, rsp, 10);
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);
	drain_tx(con);

	/* --- Success but DCID 0x0010 below range: freed. --- */
	ECBFC_SETUP_OUTGOING();
	w16(rsp, 0, 200); w16(rsp, 2, 100); w16(rsp, 4, 10);
	w16(rsp, 6, BT_CORE63_L2CAP_CREDIT_SUCCESS);
	w16(rsp, 8, 0x0010);				/* DCID < FIRST_CID */
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    ident, rsp, 10);
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);		/* freed */
	drain_tx(con);

	/* --- result = No Resources: channel torn down. --- */
	ECBFC_SETUP_OUTGOING();
	w16(rsp, 0, 200); w16(rsp, 2, 100); w16(rsp, 4, 10);
	w16(rsp, 6, BT_CORE63_L2CAP_CREDIT_NO_RESOURCES); w16(rsp, 8, 0x0055);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    ident, rsp, 10);
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);		/* freed */
	drain_tx(con);
#undef ECBFC_SETUP_OUTGOING
}

/* ====================================================================== */
/* Flow Control Credit (0x16) -- Core Spec Vol 3 Part A §4.24 / §10.1     */
/* ====================================================================== */

/*
 * §10.1: a Flow Control Credit with a zero credit value shall be ignored;
 * a credit for an unknown CID is likewise ignored.  Neither changes state.
 */
ATF_TC_WITHOUT_HEAD(flow_credit_zero_and_unknown_ignored);
ATF_TC_BODY(flow_credit_zero_and_unknown_ignored, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0060,
	    247, 247, 65, 7, 512, 512);

	/* Zero credits for our channel: ignored (remote credit unchanged). */
	w16(p, 0, 0x0060);
	w16(p, 2, 0);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT,
	    0x60, p, sizeof(p));
	ATF_CHECK_EQ(7, ch->credits_remote);

	/* Non-zero credits for an unknown CID: ignored. */
	w16(p, 0, 0x0069);
	w16(p, 2, 5);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT,
	    0x61, p, sizeof(p));
	ATF_CHECK_EQ(7, ch->credits_remote);

	drain_tx(con);
}

/*
 * §10.1: "The device receiving the credit packet shall disconnect the L2CAP
 * channel if the credit count exceeds 65535."  Priming the channel with the
 * maximum credit and adding one more triggers a clean L2CAP Disconnection
 * Request and moves the channel to W4_L2CAP_DISCON_RSP.
 */
ATF_TC_WITHOUT_HEAD(flow_credit_overflow_disconnects);
ATF_TC_BODY(flow_credit_overflow_disconnects, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0060,
	    247, 247, 65, 0xFFFF, 512, 512);

	w16(p, 0, 0x0060);
	w16(p, 2, 1);					/* 0xFFFF + 1 > 0xFFFF */
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT,
	    0x62, p, sizeof(p));

	/*
	 * §10.1: the channel is torn down.  The handler moves it to
	 * W4_L2CAP_DISCON_RSP and emits an L2CAP Disconnection Request on the
	 * wire.  (Regression guard: the overflow path must call
	 * ng_l2cap_lp_deliver() itself, because ng_l2cap_lp_receive() does not
	 * run con_wakeup after ng_l2cap_receive(); without it the mandated
	 * disconnect would be queued but never sent -- the bug fixed alongside
	 * this test.)
	 */
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_DISCON_RSP, ch->state);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, g_frames[0].data[0]);

	drain_tx(con);
}

/*
 * §10.1 boundary: the channel is disconnected only if the credit count
 * *exceeds* 65535.  A running total of exactly 65535 (0xFFFE + 1) is legal
 * and MUST leave the channel open with credits_remote == 0xFFFF and no
 * Disconnection Request on the wire.  (Kills a `> 0xFFFF` -> `>= 0xFFFF`
 * off-by-one that would spuriously tear down a channel at the legal max.)
 */
ATF_TC_WITHOUT_HEAD(flow_credit_max_no_disconnect);
ATF_TC_BODY(flow_credit_max_no_disconnect, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0060,
	    247, 247, 65, 0xFFFE, 512, 512);

	w16(p, 0, 0x0060);
	w16(p, 2, 1);					/* 0xFFFE + 1 == 0xFFFF */
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT,
	    0x62, p, sizeof(p));

	ATF_CHECK_EQ(NG_L2CAP_OPEN, ch->state);
	ATF_CHECK_EQ(0xFFFF, ch->credits_remote);
	{
		int i, saw_discon = 0;
		for (i = 0; i < g_nframes; i++)
			if (g_frames[i].data[0] == BT_CORE63_L2CAP_CMD_DISCONNECT_REQ)
				saw_discon = 1;
		ATF_CHECK_EQ(0, saw_discon);
	}

	drain_tx(con);
}

/*
 * §4.24: on a BR/EDR link a Flow Control Credit is matched to the owning
 * channel by DCID via the BR/EDR idtype and increments its remote credits.
 */
ATF_TC_WITHOUT_HEAD(flow_credit_bredr_replenish);
ATF_TC_BODY(flow_credit_bredr_replenish, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0060,
	    247, 247, 65, 3, 512, 512);

	w16(p, 0, 0x0060);
	w16(p, 2, 9);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT,
	    0x63, p, sizeof(p));
	ATF_CHECK_EQ(12, ch->credits_remote);

	drain_tx(con);
}

/*
 * §10.1 boundary complement to flow_credit_max_no_disconnect: a running total
 * of exactly 65536 (0xFFFE + 2) *exceeds* the 16-bit maximum and MUST tear the
 * channel down.  (The accepted-at-0xFFFF case is covered separately; this pins
 * the other side of the `> 0xFFFF` comparison so a `>=` regression that fired
 * one credit early -- or a `+` that silently wrapped to 0 without disconnect --
 * is caught.)
 */
ATF_TC_WITHOUT_HEAD(flow_credit_max_plus_one_disconnects);
ATF_TC_BODY(flow_credit_max_plus_one_disconnects, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0060,
	    247, 247, 65, 0xFFFE, 512, 512);

	w16(p, 0, 0x0060);
	w16(p, 2, 2);					/* 0xFFFE + 2 == 0x10000 */
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT,
	    0x64, p, sizeof(p));

	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_DISCON_RSP, ch->state);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, g_frames[0].data[0]);

	drain_tx(con);
}

/*
 * §3.4.3 / §10.1: mid-SDU credit exhaustion on the LE CoC transmit path.  An
 * SDU is segmented into K-frames, each consuming one remote credit.  Running
 * out of peer transmit credits is a WAIT condition, not a protocol error: the
 * partial SDU remains parked and the channel stays open until the peer grants
 * more credits with FLOW_CONTROL_CREDIT.
 */
ATF_TC_WITHOUT_HEAD(tx_mid_sdu_credit_exhaustion_stalls);
ATF_TC_BODY(tx_mid_sdu_credit_exhaustion_stalls, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch, c;
	u_int8_t	sdu[40];
	u_int8_t	credit[4];
	u_int16_t	scid;
	int		i, still_present;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	/*
	 * mps_remote = 20 => first K-frame carries mps-2 = 18 SDU bytes, each
	 * continuation up to 20.  A 40-byte SDU needs 3 K-frames (18 + 20 + 2)
	 * but only 2 credits are granted: the third frame cannot be sent.
	 */
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0060,
	    247, 20, 65, 2, 512, 512);
	scid = ch->scid;

	for (i = 0; i < (int)sizeof(sdu); i++)
		sdu[i] = (u_int8_t)i;

	/* Returns 0: the write is "accepted" then fails mid-segmentation. */
	ATF_REQUIRE_EQ(0, do_write(con, ch, sdu, sizeof(sdu)));

	/* Two partial K-frames made it onto the wire before credits ran out. */
	ATF_CHECK_EQ(2, g_nframes);

	/* The L2CA_WriteRsp is deferred while the SDU is credit-stalled. */
	ATF_CHECK_EQ(0, g_write_n);
	ATF_CHECK(ch->tx_sdu_pending != NULL);
	ATF_CHECK_EQ(0x1234, ch->tx_pending_token);
	ATF_CHECK_EQ(sizeof(sdu), ch->tx_pending_len);

	/*
	 * The channel remains registered and open; credit exhaustion is not a
	 * disconnect trigger.  Search by the saved scid rather than assuming the
	 * pointer's list position.
	 */
	still_present = 0;
	LIST_FOREACH(c, &g_l2cap.chan_list, next)
		if (c->scid == scid)
			still_present = 1;
	ATF_CHECK_EQ(1, still_present);

	/* One granted credit resumes and completes the parked final K-frame. */
	w16(credit, 0, ch->dcid);
	w16(credit, 2, 1);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT,
	    0x55, credit, sizeof(credit));
	ATF_CHECK_EQ(3, g_nframes);
	ATF_CHECK(ch->tx_sdu_pending == NULL);
	ATF_CHECK_EQ(1, g_write_n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, g_write_result);
	ATF_CHECK_EQ(0, ch->credits_remote);

	drain_tx(con);
}

/* ====================================================================== */
/* Credit Based Reconfigure Request (0x19) reject arms -- §4.27           */
/* ====================================================================== */

/* Feed one Credit Based Reconfigure Request. §4.27 body:
 * [mtu(2)][mps(2)][dcid...(2 each)]. */
static void
feed_reconfig_req(ng_l2cap_con_p con, u_int8_t ident, u_int16_t mtu,
    u_int16_t mps, const u_int16_t *dcids, int ndcids)
{
	u_int8_t	req[4 + 5 * 2];
	int		i;

	w16(req, 0, mtu);
	w16(req, 2, mps);
	for (i = 0; i < ndcids; i++)
		w16(req, 4 + i * 2, dcids[i]);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ,
	    ident, req, 4 + ndcids * 2);
}

/*
 * §4.27: the Credit Based Reconfigure Request DCID list holds 1..5 CIDs (an
 * even octet count of 2..10).  A request carrying 6 DCIDs (cid_list_len 12)
 * is malformed and MUST be rejected before decode -- it must never be parsed
 * into the fixed dcids[5] array.  The handler drops it (EMSGSIZE) with no
 * response on the wire.  (Kills a `cid_list_len > 10` -> `> 12` weakening
 * that would overflow dcids[5].)
 */
ATF_TC_WITHOUT_HEAD(reconfig_req_too_many_dcids);
ATF_TC_BODY(reconfig_req_too_many_dcids, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	req[4 + 6 * 2];
	int		i;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);

	w16(req, 0, 600);				/* mtu */
	w16(req, 2, 300);				/* mps */
	for (i = 0; i < 6; i++)				/* 6 DCIDs -> len 12 */
		w16(req, 4 + i * 2, 0x0071 + i);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ,
	    0x7A, req, sizeof(req));

	ATF_CHECK_EQ_MSG(0, g_nframes,
	    "a reconfigure request with 6 DCIDs must be dropped, not answered");

	drain_tx(con);
}

/*
 * §4.27 reconfigure-result arms in the 0x1A response:
 *  - duplicate DCID in the request       -> DCID Invalid (0x0003);
 *  - unknown DCID                         -> DCID Invalid (0x0003);
 *  - MTU below the ECBFC minimum (64)     -> Unacceptable Parameters (0x0004);
 *  - MTU reduction below current omtu     -> MTU Reduction (0x0001).
 */
ATF_TC_WITHOUT_HEAD(reconfig_req_result_arms);
ATF_TC_BODY(reconfig_req_result_arms, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	d2[2], d1[1];

	/* --- Duplicate DCID -> DCID Invalid (checked before ch lookup). --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	d2[0] = 0x0071; d2[1] = 0x0071;
	feed_reconfig_req(con, 0x70, 600, 300, d2, 2);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP, g_frames[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RECONFIG_INVALID_DCID,
	    frame_le16(&g_frames[0], 4));
	drain_tx(con);

	/* --- Unknown DCID -> DCID Invalid. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	d1[0] = 0x0079;
	feed_reconfig_req(con, 0x71, 600, 300, d1, 1);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RECONFIG_INVALID_DCID,
	    frame_le16(&g_frames[0], 4));
	drain_tx(con);

	/* --- MTU below minimum (32 < 64) -> Unacceptable Parameters. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	(void)mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 247, 65, 8, 512, 512);
	d1[0] = 0x0071;
	feed_reconfig_req(con, 0x72, 32, 300, d1, 1);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RECONFIG_UNACCEPTABLE_PARAMS,
	    frame_le16(&g_frames[0], 4));
	drain_tx(con);

	/* --- MTU reduction (100 < current omtu 512) -> MTU Reduction. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 247, 65, 8, 512, 512);		/* omtu 512 */
	d1[0] = ch->dcid;
	feed_reconfig_req(con, 0x73, 100, 300, d1, 1);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RECONFIG_MTU_REDUCTION,
	    frame_le16(&g_frames[0], 4));
	drain_tx(con);
}

/*
 * §4.27: MPS reduction is permitted only when reconfiguring a single channel.
 * Two channels with an MPS below their current value -> MPS Reduction for more
 * than one channel (0x0002).
 */
ATF_TC_WITHOUT_HEAD(reconfig_req_mps_reduction_multi);
ATF_TC_BODY(reconfig_req_mps_reduction_multi, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	a, b;
	u_int16_t	d2[2];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	/* omtu small (64) so the new MTU does not trip the reduction check. */
	a = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 200, 65, 8, 64, 64);
	b = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0072,
	    247, 200, 65, 8, 64, 64);
	d2[0] = a->dcid;
	d2[1] = b->dcid;

	/* mtu 512 (no reduction), mps 100 < 200 on two channels. */
	feed_reconfig_req(con, 0x74, 512, 100, d2, 2);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RECONFIG_MPS_REDUCTION_MULTI,
	    frame_le16(&g_frames[0], 4));
	/* Parameters left unchanged on rejection. */
	ATF_CHECK_EQ(200, a->mps_remote);
	ATF_CHECK_EQ(200, b->mps_remote);

	drain_tx(con);
}

/*
 * §4.27: a Reconfigure Request whose DCID list is malformed (odd length or
 * empty) is a length error -- dropped with no response emitted.
 */
ATF_TC_WITHOUT_HEAD(reconfig_req_bad_list_len);
ATF_TC_BODY(reconfig_req_bad_list_len, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	req[8];

	/* Empty DCID list: cmd_length 4 < 4+2. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, 600);
	w16(req, 2, 300);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ,
	    0x75, req, 4);
	ATF_CHECK_EQ(0, g_nframes);
	drain_tx(con);

	/* Odd-length DCID list: 4 + 3 = 7 octets. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, 600);
	w16(req, 2, 300);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ,
	    0x76, req, 7);
	ATF_CHECK_EQ(0, g_nframes);
	drain_tx(con);
}

/*
 * §4.27 (initiator) Reconfigure Response failure + mismatch arms:
 *  - result != Success                       -> pending MTU/MPS discarded,
 *                                               reconfig_pending cleared;
 *  - ident matching no Reconfigure Request   -> ignored (guard untouched).
 */
ATF_TC_WITHOUT_HEAD(reconfig_rsp_failure_and_mismatch);
ATF_TC_BODY(reconfig_rsp_failure_and_mismatch, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	ident;
	u_int8_t	rsp[2];

	/* --- Peer rejects the reconfigure: values discarded. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 247, 65, 8, 512, 512);
	ATF_REQUIRE_EQ(0, l2ca_reconfig(ch, 600, 300));
	ATF_CHECK_EQ(1, ch->reconfig_pending);
	ident = (u_int8_t)g_frames[0].data[1];

	w16(rsp, 0, BT_CORE63_L2CAP_RECONFIG_UNACCEPTABLE_PARAMS);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP,
	    ident, rsp, sizeof(rsp));
	/* Guard cleared, but the requested values did NOT take effect. */
	ATF_CHECK_EQ(0, ch->reconfig_pending);
	ATF_CHECK_EQ(512, ch->imtu);			/* unchanged */
	ATF_CHECK_EQ(247, ch->mps);			/* unchanged */
	drain_tx(con);

	/* --- Response ident matches no Reconfigure Request: ignored. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 247, 65, 8, 512, 512);
	ATF_REQUIRE_EQ(0, l2ca_reconfig(ch, 600, 300));
	ident = (u_int8_t)g_frames[0].data[1];
	w16(rsp, 0, BT_CORE63_L2CAP_RECONFIG_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP,
	    (u_int8_t)(ident + 1), rsp, sizeof(rsp));
	/* Unrelated ident: pending request still outstanding. */
	ATF_CHECK_EQ(1, ch->reconfig_pending);
	drain_tx(con);
}

/* ====================================================================== */
/* con_wakeup lp_send-failure fan-out -- ng_l2cap_cmds.c error arms       */
/* Every request-code arm has an lp_send()!=0 branch that fails the       */
/* upper-layer primitive (BT_CORE63_L2CAP_RESULT_NO_RESOURCES) instead of arming RTX.   */
/* Drive each via the g_lp_send_err knob.  These are stack-internal error */
/* paths (Core Spec Vol 3 Part A §6.1 command transmission).              */
/* ====================================================================== */
ATF_TC_WITHOUT_HEAD(con_wakeup_lp_send_failures);
ATF_TC_BODY(con_wakeup_lp_send_failures, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;

	/* --- CON_REQ (BR/EDR): failure frees the channel. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_lp_send_err = ENOBUFS;
	ATF_REQUIRE_EQ(0, l2ca_con_req(0x0001, NG_HCI_LINK_ACL,
	    NG_L2CAP_L2CA_IDTYPE_BREDR));
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));		/* command flushed */
	ATF_CHECK_EQ(0, callouts_pending());		/* no RTX on failure */
	drain_tx(con);

	/* --- CFG_REQ: failure reports cfg_rsp(NO_RESOURCES), channel kept. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0080,
	    0, 0, 0, 0, 672, 672);
	ch->le_psm = 0;
	ch->state = NG_L2CAP_CONFIG;
	scid = ch->scid;
	g_lp_send_err = ENOBUFS;
	ATF_REQUIRE_EQ(0, l2ca_cfg_req(ch, 0x0030));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_BREDR) != NULL);
	ATF_CHECK_EQ(0, callouts_pending());
	drain_tx(con);

	/* --- DISCON_REQ: failure frees the channel. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0071,
	    247, 247, 65, 8, 512, 512);
	scid = ch->scid;
	g_lp_send_err = ENOBUFS;
	ATF_REQUIRE_EQ(0, l2ca_discon_req(ch, NG_L2CAP_L2CA_IDTYPE_LE));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);
	drain_tx(con);

	/* --- ECHO_REQ (ping): failure reports ping_rsp(NO_RESOURCES). --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_l2cap.ctl = (hook_p)&g_l2cap;
	g_lp_send_err = ENOBUFS;
	ATF_REQUIRE_EQ(0, l2ca_ping_req());
	ATF_CHECK_EQ(0, callouts_pending());
	drain_tx(con);

	/* --- INFO_REQ: failure reports get_info_rsp(NO_RESOURCES). --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_l2cap.ctl = (hook_p)&g_l2cap;
	g_lp_send_err = ENOBUFS;
	ATF_REQUIRE_EQ(0, l2ca_get_info_req(NG_HCI_LINK_ACL));
	ATF_CHECK_EQ(0, callouts_pending());
	drain_tx(con);

	/* --- LE_CREDIT_CON_REQ: failure frees the channel. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	g_lp_send_err = ENOBUFS;
	ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_SPSM_EATT,
	    NG_HCI_LINK_LE_PUBLIC, NG_L2CAP_L2CA_IDTYPE_LE));
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);

	/* --- CREDIT_CON_REQ (ECBFC): failure frees the channel. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	g_lp_send_err = ENOBUFS;
	ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_SPSM_EATT,
	    NG_HCI_LINK_LE_PUBLIC, NG_L2CAP_L2CA_IDTYPE_ECBFC));
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);

	/* --- CREDIT_RECONFIG_REQ: failure clears the guard, keeps chan. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 247, 65, 8, 512, 512);
	scid = ch->scid;
	g_lp_send_err = ENOBUFS;
	ATF_REQUIRE_EQ(0, l2ca_reconfig(ch, 600, 300));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) != NULL);
	ATF_CHECK_EQ(0, ch->reconfig_pending);		/* guard cleared */
	drain_tx(con);
}

/* ====================================================================== */
/* Command timeout (RTX) fan-out -- ng_l2cap_process_command_timeout      */
/* Core Spec Vol 3 Part A §6.2.  Covers the request codes not exercised   */
/* by the existing rtx_* cases: CON_REQ group and CREDIT_RECONFIG_REQ.    */
/* ====================================================================== */
ATF_TC_WITHOUT_HEAD(command_timeout_fan_out);
ATF_TC_BODY(command_timeout_fan_out, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid;

	/* --- CON_REQ (BR/EDR) RTX expiry -> con_rsp(TIMEOUT) + free. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ATF_REQUIRE_EQ(0, l2ca_con_req(0x0001, NG_HCI_LINK_ACL,
	    NG_L2CAP_L2CA_IDTYPE_BREDR));
	scid = TAILQ_FIRST(&con->cmd_list)->ch->scid;
	ATF_CHECK_EQ(1, callouts_pending());
	ATF_CHECK_EQ(1, fire_callouts());
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_BREDR) == NULL);
	drain_tx(con);

	/* --- CREDIT_CON_REQ (ECBFC) RTX expiry -> con_rsp(TIMEOUT). --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_SPSM_EATT,
	    NG_HCI_LINK_LE_PUBLIC, NG_L2CAP_L2CA_IDTYPE_ECBFC));
	scid = TAILQ_FIRST(&con->cmd_list)->ch->scid;
	ATF_CHECK_EQ(1, callouts_pending());
	ATF_CHECK_EQ(1, fire_callouts());
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);
	drain_tx(con);

	/* --- CREDIT_RECONFIG_REQ RTX expiry -> guard cleared, chan kept. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0071,
	    247, 247, 65, 8, 512, 512);
	scid = ch->scid;
	ATF_REQUIRE_EQ(0, l2ca_reconfig(ch, 600, 300));
	ATF_CHECK_EQ(1, ch->reconfig_pending);
	ATF_CHECK_EQ(1, callouts_pending());
	ATF_CHECK_EQ(1, fire_callouts());
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) != NULL);
	ATF_CHECK_EQ(0, ch->reconfig_pending);
	drain_tx(con);
}

/*
 * ng_l2cap_con_fail flushes each queued command through its type-specific
 * arm.  The existing con_fail test covers CON_REQ/CFG_REQ/WRITE/DISCON_REQ/
 * ECHO_REQ/INFO_REQ; this one covers the remaining arms: CON_RSP, the credit
 * request/response codes, CMD_REJ, DISCON_RSP, and the parameter-update codes.
 */
ATF_TC_WITHOUT_HEAD(con_fail_credit_and_rsp_codes);
ATF_TC_BODY(con_fail_credit_and_rsp_codes, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	c1, c2, c3;
	ng_l2cap_cmd_p	cmd;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	c1 = ng_l2cap_new_chan(&g_l2cap, con, BT_ASSIGNED_L2CAP_SPSM_EATT,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	c2 = ng_l2cap_new_chan(&g_l2cap, con, BT_ASSIGNED_L2CAP_SPSM_EATT,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	c3 = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(c1 && c2 && c3);

	/* CON_RSP -> l2ca_con_rsp_rsp(result). */
	cmd = ng_l2cap_new_cmd(con, c3, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_CONNECTION_RSP, 0x1);
	ng_l2cap_link_cmd(con, cmd);
	/* LE_CREDIT_CON_REQ -> l2ca_con_rsp(result). */
	cmd = ng_l2cap_new_cmd(con, c1, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x2);
	ng_l2cap_link_cmd(con, cmd);
	/* CREDIT_CON_REQ -> l2ca_con_rsp(result). */
	cmd = ng_l2cap_new_cmd(con, c2, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ, 0x3);
	ng_l2cap_link_cmd(con, cmd);
	/* LE_CREDIT_CON_RSP -> break (terminal). */
	cmd = ng_l2cap_new_cmd(con, NULL, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP, 0x4);
	ng_l2cap_link_cmd(con, cmd);
	/* FLOW_CONTROL_CREDIT -> break. */
	cmd = ng_l2cap_new_cmd(con, NULL, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT, 0x5);
	ng_l2cap_link_cmd(con, cmd);
	/* CREDIT_CON_RSP -> break. */
	cmd = ng_l2cap_new_cmd(con, NULL, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP, 0x6);
	ng_l2cap_link_cmd(con, cmd);
	/* CREDIT_RECONFIG_RSP -> break. */
	cmd = ng_l2cap_new_cmd(con, NULL, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP, 0x7);
	ng_l2cap_link_cmd(con, cmd);
	/* CMD_REJ -> break. */
	cmd = ng_l2cap_new_cmd(con, NULL, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_REJECT, 0x8);
	ng_l2cap_link_cmd(con, cmd);
	/* DISCON_RSP -> break. */
	cmd = ng_l2cap_new_cmd(con, NULL, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_DISCONNECT_RSP, 0x9);
	ng_l2cap_link_cmd(con, cmd);
	/* CMD_PARAM_UPDATE_RESPONSE -> break. */
	cmd = ng_l2cap_new_cmd(con, NULL, ng_l2cap_get_ident(con),
	    BT_CORE63_L2CAP_CMD_PARAM_UPDATE_RSP, 0xa);
	ng_l2cap_link_cmd(con, cmd);

	ng_l2cap_con_fail(con, NG_L2CAP_TIMEOUT);

	ATF_CHECK(LIST_EMPTY(&g_l2cap.con_list));
	ATF_CHECK(LIST_EMPTY(&g_l2cap.chan_list));
}

/* ====================================================================== */
/* Allocation-failure (fault injection) reject arms -- §4.22/§4.25.       */
/* The g_kmalloc_budget / g_mbuf_budget knobs force ng_l2cap_new_chan(),   */
/* ng_l2cap_new_cmd() (kernel malloc) or the response-PDU MGETHDR (mbuf)   */
/* to return NULL, driving the ENOMEM/ENOBUFS/NO_RESOURCES arms that are   */
/* otherwise unreachable.                                                  */
/* ====================================================================== */
ATF_TC_WITHOUT_HEAD(fault_alloc_le_credit_con_req);
ATF_TC_BODY(fault_alloc_le_credit_con_req, tc)
{
	ng_l2cap_con_p	con;

	/* --- reject path, response-command new_cmd() fails -> ENOMEM. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	g_kmalloc_budget = 0;				/* fail all kmalloc */
	feed_le_credit_con_req(con, 0x47, 0x0080, 0x0045,
	    10, 120, 4);				/* bad MTU -> reject */
	ATF_CHECK_EQ(0, g_nframes);			/* no response emitted */
	drain_tx(con);

	/* --- reject path, response-PDU MGETHDR mbuf fails -> ENOBUFS. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	g_mbuf_budget = 1;				/* rx mbuf ok, aux fails */
	feed_le_credit_con_req(con, 0x48, 0x0080, 0x0045,
	    10, 120, 4);
	ATF_CHECK_EQ(0, g_nframes);
	drain_tx(con);

	/* --- success path, ng_l2cap_new_chan() fails -> NO_RESOURCES. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	g_kmalloc_budget = 0;				/* new_chan() -> NULL */
	feed_le_credit_con_req(con, 0x49, 0x0080, 0x0045,
	    120, 120, 4);				/* valid params */
	ATF_CHECK(ng_l2cap_chan_by_dcid(&g_l2cap, 0x0045,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);		/* no channel opened */
	drain_tx(con);
}

ATF_TC_WITHOUT_HEAD(fault_alloc_ecbfc_con_req);
ATF_TC_BODY(fault_alloc_ecbfc_con_req, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	req[12];

	/* --- ECBFC per-channel ng_l2cap_new_chan() fails -> NO_RESOURCES. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5); w16(req, 8, 0x0050);
	g_kmalloc_budget = 0;				/* every alloc fails */
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x57, req, 10);
	ATF_CHECK(ng_l2cap_chan_by_dcid(&g_l2cap, 0x0050,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);
	drain_tx(con);

	/* --- ECBFC reject-path response MGETHDR fails -> ENOBUFS. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, /*encryption*/0);	/* -> reject */
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5); w16(req, 8, 0x0050);
	g_mbuf_budget = 1;				/* rx ok, aux fails */
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x58, req, 10);
	ATF_CHECK_EQ(0, g_nframes);
	drain_tx(con);

	/* Allocate the first of two channels, then fail the second allocation. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5);
	w16(req, 8, 0x0050); w16(req, 10, 0x0051);
	g_kmalloc_budget = 1;
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x59, req, sizeof(req));
	ATF_CHECK(ng_l2cap_chan_by_dcid(&g_l2cap, 0x0050,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);
	ATF_CHECK(ng_l2cap_chan_by_dcid(&g_l2cap, 0x0051,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC) == NULL);
	drain_tx(con);

	/* Both channels allocate, but the response command allocation fails. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5);
	w16(req, 8, 0x0050); w16(req, 10, 0x0051);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x5a, req, sizeof(req));
	{
		ng_l2cap_chan_p a, b;

		a = ng_l2cap_chan_by_dcid(&g_l2cap, 0x0050,
		    NG_L2CAP_L2CA_IDTYPE_ECBFC);
		b = ng_l2cap_chan_by_dcid(&g_l2cap, 0x0051,
		    NG_L2CAP_L2CA_IDTYPE_ECBFC);
		ATF_REQUIRE(a != NULL && b != NULL);
		ATF_REQUIRE_EQ(0, l2ca_con_rsp_req(a->scid,
		    NG_HCI_LINK_LE_PUBLIC, 0x5a, BT_CORE63_L2CAP_RESULT_SUCCESS));
		g_kmalloc_budget = 0;
		ATF_CHECK_EQ(ENOMEM, l2ca_con_rsp_req(b->scid,
		    NG_HCI_LINK_LE_PUBLIC, 0x5a, BT_CORE63_L2CAP_RESULT_SUCCESS));
	}
	ATF_CHECK(LIST_EMPTY(&g_l2cap.chan_list));
	drain_tx(con);

	/* A successful decode whose response mbuf fails also rolls all back. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5);
	w16(req, 8, 0x0050); w16(req, 10, 0x0051);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x5b, req, sizeof(req));
	{
		ng_l2cap_chan_p a, b;

		a = ng_l2cap_chan_by_dcid(&g_l2cap, 0x0050,
		    NG_L2CAP_L2CA_IDTYPE_ECBFC);
		b = ng_l2cap_chan_by_dcid(&g_l2cap, 0x0051,
		    NG_L2CAP_L2CA_IDTYPE_ECBFC);
		ATF_REQUIRE(a != NULL && b != NULL);
		ATF_REQUIRE_EQ(0, l2ca_con_rsp_req(a->scid,
		    NG_HCI_LINK_LE_PUBLIC, 0x5b, BT_CORE63_L2CAP_RESULT_SUCCESS));
		g_mbuf_budget = 0;
		ATF_CHECK_EQ(ENOBUFS, l2ca_con_rsp_req(b->scid,
		    NG_HCI_LINK_LE_PUBLIC, 0x5b, BT_CORE63_L2CAP_RESULT_SUCCESS));
	}
	ATF_CHECK(LIST_EMPTY(&g_l2cap.chan_list));
	drain_tx(con);

	/* Upper-hook delivery failure rejects the entire atomic channel group. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	g_l2cap.l2c = NULL;
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5);
	w16(req, 8, 0x0050); w16(req, 10, 0x0051);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x5c, req, sizeof(req));
	ATF_CHECK(LIST_EMPTY(&g_l2cap.chan_list));
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_NO_RESOURCES,
	    frame_le16(&g_frames[0], 10));
	drain_tx(con);

	/* First ConInd succeeds, then the second fails.  Atomic rollback must
	 * issue DisconInd for the already-delivered first channel before free. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(req, 0, BT_ASSIGNED_L2CAP_SPSM_EATT);
	w16(req, 2, 200); w16(req, 4, 200); w16(req, 6, 5);
	w16(req, 8, 0x0050); w16(req, 10, 0x0051);
	g_con_ind_fail_after = 1;
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ,
	    0x5d, req, sizeof(req));
	ATF_CHECK(LIST_EMPTY(&g_l2cap.chan_list));
	ATF_CHECK_EQ(NGM_L2CAP_L2CA_DISCON_IND, g_last_msg_cmd);
	ATF_CHECK_EQ(NG_L2CAP_L2CA_IDTYPE_ECBFC, g_discon_idtype);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_NO_RESOURCES,
	    frame_le16(&g_frames[0], 10));
	drain_tx(con);
}

/* ====================================================================== */
/* L2CA_* request validation rejects -- ng_l2cap_ulpi.c                   */
/* Every upper-layer request handler first rejects a wrong-size message   */
/* (EMSGSIZE), an unknown local CID (ENOENT), or a wrong channel state    */
/* (EINVAL).  These are the L2CA_* input-validation arms (Core Spec Vol 3 */
/* Part A §4/§7 primitive parameter checking).                            */
/* ====================================================================== */
ATF_TC_WITHOUT_HEAD(ulpi_request_validation_rejects);
ATF_TC_BODY(ulpi_request_validation_rejects, tc)
{
	ng_l2cap_con_p			con;
	ng_l2cap_chan_p			ch;
	struct ng_mesg			*msg;
	ng_l2cap_l2ca_con_rsp_ip	crip;
	ng_l2cap_l2ca_cfg_ip		cfip;
	ng_l2cap_l2ca_cfg_rsp_ip	crspip;
	ng_l2cap_l2ca_discon_ip		dip;
	ng_l2cap_l2ca_ping_ip		pip;
	ng_l2cap_l2ca_get_info_ip	giip;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	memset(&crip, 0, sizeof(crip));
	memset(&cfip, 0, sizeof(cfip));
	memset(&crspip, 0, sizeof(crspip));
	memset(&dip, 0, sizeof(dip));
	memset(&pip, 0, sizeof(pip));
	memset(&giip, 0, sizeof(giip));

	/* ---- L2CA_ConnectRsp ---- */
	/* EMSGSIZE: truncated message. */
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CON_RSP, &crip, 1);
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_con_rsp_req(&g_l2cap, msg));
	(free)(msg);
	/* ENOENT: unknown local CID. */
	memset(&crip, 0, sizeof(crip));
	bcopy(&g_addr, &crip.bdaddr, sizeof(crip.bdaddr));
	crip.linktype = NG_HCI_LINK_ACL;
	crip.lcid = 0x004e;
	crip.result = BT_CORE63_L2CAP_RESULT_SUCCESS;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CON_RSP, &crip, sizeof(crip));
	ATF_CHECK_EQ(ENOENT, ng_l2cap_l2ca_con_rsp_req(&g_l2cap, msg));
	(free)(msg);
	/* EINVAL: channel exists but not in W4_L2CA_CON_RSP. */
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ch->state = NG_L2CAP_OPEN;
	crip.lcid = ch->scid;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CON_RSP, &crip, sizeof(crip));
	ATF_CHECK_EQ(EINVAL, ng_l2cap_l2ca_con_rsp_req(&g_l2cap, msg));
	(free)(msg);

	/* ---- L2CA_Config ---- */
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CFG, &cfip, 1);
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_cfg_req(&g_l2cap, msg));
	(free)(msg);
	memset(&cfip, 0, sizeof(cfip));
	cfip.lcid = 0x004e;				/* unknown */
	cfip.imtu = 0x0030;
	bcopy(ng_l2cap_default_flow(), &cfip.oflow, sizeof(cfip.oflow));
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CFG, &cfip, sizeof(cfip));
	ATF_CHECK_EQ(ENOENT, ng_l2cap_l2ca_cfg_req(&g_l2cap, msg));
	(free)(msg);
	/* EINVAL: not OPEN/CONFIG (channel is W4_L2CAP_CON_RSP). */
	ch->state = NG_L2CAP_W4_L2CAP_CON_RSP;
	cfip.lcid = ch->scid;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CFG, &cfip, sizeof(cfip));
	ATF_CHECK_EQ(EINVAL, ng_l2cap_l2ca_cfg_req(&g_l2cap, msg));
	(free)(msg);

	/* ---- L2CA_ConfigRsp ---- */
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CFG_RSP, &crspip, 1);
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_cfg_rsp_req(&g_l2cap, msg));
	(free)(msg);
	memset(&crspip, 0, sizeof(crspip));
	crspip.lcid = 0x004e;				/* unknown */
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CFG_RSP, &crspip, sizeof(crspip));
	ATF_CHECK_EQ(ENOENT, ng_l2cap_l2ca_cfg_rsp_req(&g_l2cap, msg));
	(free)(msg);
	/* EINVAL: not in CONFIG (still W4_L2CAP_CON_RSP). */
	crspip.lcid = ch->scid;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CFG_RSP, &crspip, sizeof(crspip));
	ATF_CHECK_EQ(EINVAL, ng_l2cap_l2ca_cfg_rsp_req(&g_l2cap, msg));
	(free)(msg);

	/* ---- L2CA_Disconnect ---- */
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_DISCON, &dip, 1);
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_discon_req(&g_l2cap, msg));
	(free)(msg);
	memset(&dip, 0, sizeof(dip));
	dip.lcid = 0x004e;				/* unknown */
	dip.idtype = NG_L2CAP_L2CA_IDTYPE_BREDR;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_DISCON, &dip, sizeof(dip));
	ATF_CHECK_EQ(ENOENT, ng_l2cap_l2ca_discon_req(&g_l2cap, msg));
	(free)(msg);

	/* ---- L2CA_Ping ---- */
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_PING, &pip, 1);
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_ping_req(&g_l2cap, msg));
	(free)(msg);

	/* ---- L2CA_GetInfo ---- */
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_GET_INFO, &giip, 1);
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_get_info_req(&g_l2cap, msg));
	(free)(msg);

	drain_tx(con);
}

/* ====================================================================== */
/* BR/EDR classic signalling -- Core Spec Vol 3 Part A Section 4          */
/*                                                                        */
/* Everything below drives the classic (CID 0x0001) command machinery in  */
/* ng_l2cap_evnt.c that the LE/credit cases never touch: ConnectReq,       */
/* Config Req/Rsp (option TLV parser get_next_l2cap_opt), DisconnectReq,   */
/* Echo, Info Req/Rsp, CommandReject, and the send_l2cap_* emitters.  A    */
/* BR/EDR connection has linktype NG_HCI_LINK_ACL so ng_l2cap_receive()    */
/* routes CID 0x0001 to ng_l2cap_process_signal_cmd().                     */
/* ====================================================================== */

/* Feed a raw signalling C-frame (bytes are the command(s) after the L2CAP
 * header) so multi-command / short-command framing edges can be built. */
static void
feed_sig_raw(ng_l2cap_con_p con, u_int16_t sig_cid, const u_int8_t *cmd,
    int clen)
{
	struct mbuf	*m;
	ng_l2cap_hdr_t	*lh;

	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	lh = (ng_l2cap_hdr_t *)m->m_data;
	lh->length = htole16((u_int16_t)clen);
	lh->dcid = htole16(sig_cid);
	if (clen > 0)
		memcpy(m->m_data + 4, cmd, (size_t)clen);
	m->m_len = m->m_pkthdr.len = 4 + clen;
	con->rx_pkt = m;
	(void)ng_l2cap_receive(con);
}

static struct mbuf *
mk_acl_fragment(ng_l2cap_con_p con, u_int16_t pb, u_int16_t declared_len,
    const u_int8_t *payload, int plen)
{
	struct mbuf		*m;
	ng_hci_acldata_pkt_t	*ah;

	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	ah = (ng_hci_acldata_pkt_t *)m->m_data;
	ah->con_handle = htole16(NG_HCI_MK_CON_HANDLE(con->con_handle, pb, 0));
	ah->length = htole16(declared_len);
	if (plen > 0)
		memcpy(m->m_data + sizeof(*ah), payload, (size_t)plen);
	m->m_len = m->m_pkthdr.len = sizeof(*ah) + plen;
	return (m);
}

/* Index of the last emitted signalling frame; -1 if none. */
static int
last_frame(void)
{

	return (g_nframes - 1);
}

/*
 * Exercise the outer L2CAP receive dispatcher itself.  Most data-plane tests
 * intentionally enter at ng_l2cap_l2ca_receive(), so keep the framing errors
 * and the default-CID dispatch here as a separate protocol-boundary matrix.
 */
ATF_TC_WITHOUT_HEAD(receive_outer_framing_matrix);
ATF_TC_BODY(receive_outer_framing_matrix, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	struct mbuf	*m;
	ng_l2cap_hdr_t	*lh;
	u_int8_t	cmd[4], multi_cmd[8], sdu[6] = { 4, 0, 1, 2, 3, 4 };
	u_int8_t	oversize[BT_CORE63_L2CAP_MTU_MIN_BR_EDR + 1];

	/* A packet shorter than the outer header is rejected and reclaimed. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	m->m_len = m->m_pkthdr.len = 3;
	con->rx_pkt = m;
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_receive(con));
	ATF_CHECK(con->rx_pkt == NULL);
	drain_tx(con);

	/* A syntactically complete header must describe the exact payload size. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	lh = mtod(m, ng_l2cap_hdr_t *);
	lh->length = htole16(2);
	lh->dcid = htole16(BT_CORE63_L2CAP_CID_SIGNAL);
	m->m_len = m->m_pkthdr.len = sizeof(*lh);
	con->rx_pkt = m;
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_receive(con));
	ATF_CHECK(con->rx_pkt == NULL);
	drain_tx(con);

	/* A dynamic CID takes the dispatcher's default arm and reaches L2CA RX. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0071,
	    247, 247, 10, 10, 512, 512);
	m = ng_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	lh = mtod(m, ng_l2cap_hdr_t *);
	lh->length = htole16(sizeof(sdu));
	lh->dcid = htole16(ch->scid);
	memcpy(m->m_data + sizeof(*lh), sdu, sizeof(sdu));
	m->m_len = m->m_pkthdr.len = sizeof(*lh) + sizeof(sdu);
	con->rx_pkt = m;
	ATF_CHECK_EQ(0, ng_l2cap_receive(con));
	ATF_CHECK_EQ(1, g_ndata);
	drain_tx(con);

	/* BR/EDR-only fixed CIDs are rejected before either decoder receives
	 * their payload when the bearer is LE-U. */
	for (int le_link = NG_HCI_LINK_LE_PUBLIC;
	    le_link <= NG_HCI_LINK_LE_RANDOM; le_link++) {
		reset_all();
		con = mk_con(le_link, 1);
		feed_sig_raw(con, BT_CORE63_L2CAP_CID_SIGNAL, cmd, 0);
		ATF_CHECK(con->rx_pkt == NULL);
		feed_sig_raw(con, BT_CORE63_L2CAP_CID_CONNECTIONLESS, cmd, 0);
		ATF_CHECK(con->rx_pkt == NULL);
		drain_tx(con);
	}

	/* Empty, short, and length-overrun LE signalling C-frames are dropped. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	con->rx_pkt = NULL;
	ATF_CHECK_EQ(0, ng_l2cap_process_lesignal_cmd(con));
	feed_sig_raw(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, cmd, 0);
	ATF_CHECK(con->rx_pkt == NULL);
	cmd[0] = BT_CORE63_L2CAP_CMD_REJECT;
	cmd[1] = 0x45;
	feed_sig_raw(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, cmd, 2);
	ATF_CHECK(con->rx_pkt == NULL);
	cmd[2] = 3;
	cmd[3] = 0;
	feed_sig_raw(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, cmd, sizeof(cmd));
	ATF_CHECK(con->rx_pkt == NULL);
	drain_tx(con);

	/* The classic signalling parser applies the same length-overrun guard. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	feed_sig_raw(con, BT_CORE63_L2CAP_CID_SIGNAL, cmd, sizeof(cmd));
	ATF_CHECK(con->rx_pkt == NULL);
	drain_tx(con);

	/* A complete C-frame beyond the BR/EDR signalling MTU produces exactly
	 * one MTU-exceeded reject before its command body is decoded. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	memset(oversize, 0, sizeof(oversize));
	oversize[0] = BT_CORE63_L2CAP_CMD_CONNECTION_REQ;
	oversize[1] = 0x66;
	feed_sig_raw(con, BT_CORE63_L2CAP_CID_SIGNAL, oversize, sizeof(oversize));
	ATF_CHECK(con->rx_pkt == NULL);
	ATF_CHECK_EQ(1, g_nframes);
	drain_tx(con);

	/* Two adjacent command headers require the parser's m_split remainder
	 * path; unknown zero-length commands are safely rejected independently. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	memset(multi_cmd, 0, sizeof(multi_cmd));
	multi_cmd[0] = 0xff;
	multi_cmd[1] = 0x67;
	multi_cmd[4] = 0xfe;
	multi_cmd[5] = 0x68;
	feed_sig_raw(con, BT_CORE63_L2CAP_CID_SIGNAL, multi_cmd, sizeof(multi_cmd));
	ATF_CHECK(con->rx_pkt == NULL);
	ATF_CHECK_EQ(2, g_nframes);
	drain_tx(con);
}

ATF_TC_WITHOUT_HEAD(acl_continuation_length_mismatch_drops_reassembly);
ATF_TC_BODY(acl_continuation_length_mismatch_drops_reassembly, tc)
{
	ng_l2cap_con_p	con;
	struct mbuf	*m;
	u_int8_t	start[6], cont[2], full[8];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);

	w16(start, 0, 4);			/* L2CAP payload length */
	w16(start, 2, BT_CORE63_L2CAP_CID_SIGNAL);
	start[4] = BT_CORE63_L2CAP_CMD_ECHO_REQ;
	start[5] = 0x72;

	m = mk_acl_fragment(con, NG_HCI_PACKET_START, sizeof(start),
	    start, sizeof(start));
	ATF_CHECK_EQ(0, ng_l2cap_lp_receive(&g_l2cap, m));
	ATF_REQUIRE(con->rx_pkt != NULL);
	ATF_CHECK_EQ(2, con->rx_pkt_len);

	cont[0] = 0x00;
	cont[1] = 0x00;
	m = mk_acl_fragment(con, NG_HCI_PACKET_FRAGMENT, 1, cont, sizeof(cont));
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_lp_receive(&g_l2cap, m));
	ATF_CHECK(con->rx_pkt == NULL);
	ATF_CHECK_EQ(0, con->rx_pkt_len);
	ATF_CHECK_EQ(0, g_nframes);

	w16(full, 0, 4);
	w16(full, 2, BT_CORE63_L2CAP_CID_SIGNAL);
	full[4] = BT_CORE63_L2CAP_CMD_ECHO_REQ;
	full[5] = 0x73;
	full[6] = 0x00;
	full[7] = 0x00;
	m = mk_acl_fragment(con, NG_HCI_PACKET_START, sizeof(full),
	    full, sizeof(full));
	ATF_CHECK_EQ(0, ng_l2cap_lp_receive(&g_l2cap, m));
	ATF_REQUIRE_EQ(1, g_nframes);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECHO_RSP, g_frames[0].data[0]);
	ATF_CHECK_EQ(0x73, g_frames[0].data[1]);
	drain_tx(con);
}

/*
 * Section 4.2 / Table 4.6: inbound L2CAP_ConnectReq.  A valid dynamic Source
 * CID + PSM creates a channel in W4_L2CA_CON_RSP and raises L2CA_ConnectInd
 * (0x81) to the upper layer; no response PDU is emitted yet (the stack waits
 * for the upper-layer L2CA_ConnectRsp).
 */
ATF_TC_WITHOUT_HEAD(bredr_con_req_success);
ATF_TC_BODY(bredr_con_req_success, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);

	w16(p, 0, 0x0001);		/* PSM = SDP */
	w16(p, 2, 0x0040);		/* peer Source CID (dynamic) */
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x11, p,
	    sizeof(p));

	/* A BR/EDR channel now exists, dcid == peer's scid, awaiting upper. */
	ch = ng_l2cap_chan_by_dcid(&g_l2cap, 0x0040,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CA_CON_RSP, ch->state);
	ATF_CHECK_EQ(0x11, ch->ident);
	ATF_CHECK_EQ(NGM_L2CAP_L2CA_CON_IND, g_last_msg_cmd);
	ATF_CHECK_EQ(0, g_nframes);		/* no PDU emitted yet */

	drain_tx(con);
}

/*
 * Section 4.2: a Source CID below the dynamic range (< 0x0040) for a BR/EDR
 * dynamic channel is invalid -> L2CAP_ConnectRsp with result
 * BT_CORE63_L2CAP_RESULT_INVALID_SOURCE_CID (0x0006, Table 4.6).  Encoded PDU:
 * code=CON_RSP(0x03), ident echoed, dcid=0, scid=peer scid, result=0x0006.
 */
ATF_TC_WITHOUT_HEAD(bredr_con_req_invalid_scid);
ATF_TC_BODY(bredr_con_req_invalid_scid, tc)
{
	ng_l2cap_con_p	con;
	int		f;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);

	w16(p, 0, 0x0001);
	w16(p, 2, 0x0010);		/* below BT_CORE63_L2CAP_CID_DYNAMIC_FIRST */
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x12, p,
	    sizeof(p));

	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONNECTION_RSP, g_frames[f].data[0]);	/* 0x03 */
	ATF_CHECK_EQ(0x12, g_frames[f].data[1]);		/* ident */
	ATF_CHECK_EQ(0x0010, frame_le16(&g_frames[f], 6));	/* scid */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_INVALID_SOURCE_CID,
	    frame_le16(&g_frames[f], 8));			/* result */
	/* No channel created. */
	ATF_CHECK(ng_l2cap_chan_by_dcid(&g_l2cap, 0x0010,
	    NG_L2CAP_L2CA_IDTYPE_BREDR) == NULL);

	drain_tx(con);
}

/*
 * Section 4.2: a ConnectReq addressed to the fixed ATT CID (0x0004) is routed
 * to an ATT-type channel (scid==dcid==0x0004), bypassing the dynamic-CID
 * range check.  con_ind is raised.
 */
ATF_TC_WITHOUT_HEAD(bredr_con_req_att_cid);
ATF_TC_BODY(bredr_con_req_att_cid, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);

	w16(p, 0, 0x001f);			/* PSM */
	w16(p, 2, BT_CORE63_L2CAP_CID_ATT);		/* scid = 0x0004 */
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x13, p,
	    sizeof(p));

	ch = ng_l2cap_chan_by_conhandle(&g_l2cap, BT_CORE63_L2CAP_CID_ATT,
	    con->con_handle);
	ATF_REQUIRE(ch != NULL);
	ATF_CHECK_EQ(NG_L2CAP_L2CA_IDTYPE_ATT, ch->idtype);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CID_ATT, ch->dcid);
	ATF_CHECK_EQ(NGM_L2CAP_L2CA_CON_IND, g_last_msg_cmd);

	drain_tx(con);
}

/*
 * Section 4.2: if L2CA_ConnectInd cannot be delivered (upstream hook down,
 * con_ind -> ENOTCONN) the request is rejected with PSM_NOT_SUPPORTED
 * (0x0002) and the half-built channel is freed.
 */
ATF_TC_WITHOUT_HEAD(bredr_con_req_ind_failure);
ATF_TC_BODY(bredr_con_req_ind_failure, tc)
{
	ng_l2cap_con_p	con;
	int		f;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_l2cap.l2c = NULL;			/* con_ind will fail */

	w16(p, 0, 0x0003);			/* RFCOMM PSM */
	w16(p, 2, 0x0044);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x14, p,
	    sizeof(p));

	g_l2cap.l2c = (hook_p)&g_l2cap;		/* restore for send path */
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONNECTION_RSP, g_frames[f].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_PSM_NOT_SUPPORTED, frame_le16(&g_frames[f], 8));
	/* Channel was freed. */
	ATF_CHECK(ng_l2cap_chan_by_dcid(&g_l2cap, 0x0044,
	    NG_L2CAP_L2CA_IDTYPE_BREDR) == NULL);

	drain_tx(con);
}

/*
 * Section 4.4 + 5.1: inbound L2CAP_ConfigReq with a well-formed MTU option and
 * no continuation flag.  The option value is applied (ch->omtu) and, since all
 * options parsed cleanly, L2CA_ConfigInd (0x85) is raised -- no ConfigRsp is
 * emitted by the stack itself (the upper layer answers).
 */
ATF_TC_WITHOUT_HEAD(bredr_cfg_req_mtu_option);
ATF_TC_BODY(bredr_cfg_req_mtu_option, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	p[8];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->dcid = 0x0080;
	ch->state = NG_L2CAP_CONFIG;

	w16(p, 0, ch->scid);			/* dcid = our scid */
	w16(p, 2, 0x0000);			/* flags: no C-flag */
	p[4] = BT_CORE63_L2CAP_OPTION_MTU;		/* option type 0x01 */
	p[5] = NG_L2CAP_OPT_MTU_SIZE;		/* length 2 */
	w16(p, 6, 0x00a0);			/* MTU = 160 */
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x21, p,
	    sizeof(p));

	ATF_CHECK_EQ(0x00a0, ch->omtu);		/* Section 5.1 */
	ATF_CHECK_EQ(NGM_L2CAP_L2CA_CFG_IND, g_last_msg_cmd);
	ATF_CHECK_EQ(NG_L2CAP_CONFIG, ch->state);

	drain_tx(con);
}

/*
 * Section 5.2 / 5.3: FLUSH_TIMO and QoS options parse and apply.  A HINT
 * (top-bit-set) unknown option type is silently skipped (Section 5, "hint"
 * bit).  All clean -> ConfigInd.
 */
ATF_TC_WITHOUT_HEAD(bredr_cfg_req_flush_qos_hint);
ATF_TC_BODY(bredr_cfg_req_flush_qos_hint, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	p[64];
	int		n;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->state = NG_L2CAP_OPEN;		/* triggers reconfig reset arm */

	memset(p, 0, sizeof(p));
	w16(p, 0, ch->scid);
	w16(p, 2, 0x0000);
	n = 4;
	/* FLUSH_TIMO option (Section 5.2). */
	p[n++] = BT_CORE63_L2CAP_OPTION_FLUSH_TIMEOUT;
	p[n++] = NG_L2CAP_OPT_FLUSH_TIMO_SIZE;
	w16(p, n, 0x1234); n += 2;
	/* QoS option (Section 5.3), 22-byte flow spec. */
	p[n++] = BT_CORE63_L2CAP_OPTION_QOS;
	p[n++] = (u_int8_t)sizeof(ng_l2cap_flow_t);
	n += (int)sizeof(ng_l2cap_flow_t);
	/* HINT unknown option (type high bit set) -- must be skipped. */
	p[n++] = (u_int8_t)(0x20 | BT_CORE63_L2CAP_OPTION_HINT);
	p[n++] = 0x02;
	w16(p, n, 0xbeef); n += 2;

	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x22, p, n);

	ATF_CHECK_EQ(0x1234, ch->flush_timo);
	ATF_CHECK_EQ(NG_L2CAP_CONFIG, ch->state);	/* OPEN->CONFIG */
	ATF_CHECK_EQ(NGM_L2CAP_L2CA_CFG_IND, g_last_msg_cmd);

	drain_tx(con);
}

/*
 * Section 4.4: continuation ("C") flag set in a ConfigReq means "more options
 * to follow".  The stack answers with an empty, success ConfigRsp (result
 * 0x0000) and waits -- it does NOT raise ConfigInd yet.
 */
ATF_TC_WITHOUT_HEAD(bredr_cfg_req_cflag_empty_rsp);
ATF_TC_BODY(bredr_cfg_req_cflag_empty_rsp, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	int		f;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->dcid = 0x0081;
	ch->state = NG_L2CAP_CONFIG;

	w16(p, 0, ch->scid);
	w16(p, 2, BT_CORE63_L2CAP_OPTION_CONTINUATION);	/* C flag */
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x23, p,
	    sizeof(p));

	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONFIG_RSP, g_frames[f].data[0]);	/* 0x05 */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, frame_le16(&g_frames[f], 8));
	ATF_CHECK_EQ(0, g_nmsg);		/* no ConfigInd */

	drain_tx(con);
}

/*
 * Section 4.4: an unknown, non-hint option makes the stack answer ConfigRsp
 * with result BT_CORE63_L2CAP_CONFIG_UNKNOWN_OPTION (0x0003), echoing the offending option.
 * A malformed known option (bad length) yields BT_CORE63_L2CAP_CONFIG_REJECT (0x0002).
 */
ATF_TC_WITHOUT_HEAD(bredr_cfg_req_option_reject_arms);
ATF_TC_BODY(bredr_cfg_req_option_reject_arms, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	int		f;
	u_int8_t	p[16];

	/* --- unknown option (type 0x10, no hint) -> UNKNOWN_OPTION --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->state = NG_L2CAP_CONFIG;
	w16(p, 0, ch->scid);
	w16(p, 2, 0x0000);
	p[4] = 0x10;			/* unknown, hint bit clear */
	p[5] = 0x02;
	w16(p, 6, 0x0000);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x24, p, 8);
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONFIG_RSP, g_frames[f].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CONFIG_UNKNOWN_OPTION, frame_le16(&g_frames[f], 8));
	drain_tx(con);

	/* --- malformed MTU option (declared length 3) -> REJECT --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->state = NG_L2CAP_CONFIG;
	w16(p, 0, ch->scid);
	w16(p, 2, 0x0000);
	p[4] = BT_CORE63_L2CAP_OPTION_MTU;
	p[5] = 0x03;			/* wrong: MTU option is 2 bytes */
	p[6] = 0; p[7] = 0; p[8] = 0;
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x25, p, 9);
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONFIG_RSP, g_frames[f].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CONFIG_REJECT, frame_le16(&g_frames[f], 8));
	drain_tx(con);
}

/*
 * Section 4.4: a ConfigReq for an unknown channel, or one in an invalid state,
 * is answered with L2CAP_CommandReject / reason INVALID_CID (0x0002).
 */
ATF_TC_WITHOUT_HEAD(bredr_cfg_req_reject_cid_state);
ATF_TC_BODY(bredr_cfg_req_reject_cid_state, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	int		f;
	u_int8_t	p[4];

	/* --- unknown CID --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	w16(p, 0, 0x00fe);			/* no such channel */
	w16(p, 2, 0x0000);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x26, p,
	    sizeof(p));
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_frames[f].data[0]);	/* 0x01 */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_INVALID_CID, frame_le16(&g_frames[f], 4));
	drain_tx(con);

	/* --- wrong state (W4_L2CAP_CON_RSP) --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->state = NG_L2CAP_W4_L2CAP_CON_RSP;
	w16(p, 0, ch->scid);
	w16(p, 2, 0x0000);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x27, p,
	    sizeof(p));
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_frames[f].data[0]);
	drain_tx(con);
}

/* Build an OPEN BR/EDR channel with a pending, RTX-armed CFG_REQ command,
 * as if L2CA_Config had just been issued.  Returns the ident. */
static u_int8_t
setup_pending_cfg_req(ng_l2cap_con_p con, ng_l2cap_chan_p *chp)
{
	ng_l2cap_chan_p	ch;

	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->dcid = 0x0090;
	ch->state = NG_L2CAP_CONFIG;
	ch->le_psm = 0;
	ATF_REQUIRE_EQ(0, l2ca_cfg_req(ch, 0x0030));
	*chp = ch;
	return (first_cmd_ident(con));
}

/*
 * Section 4.5: inbound L2CAP_ConfigRsp for our pending CFG_REQ.  A clean,
 * no-C-flag response with an MTU option applies ch->imtu, cancels the RTX
 * timer, and reports L2CA_ConfigRsp up; the command is consumed.
 */
ATF_TC_WITHOUT_HEAD(bredr_cfg_rsp_success);
ATF_TC_BODY(bredr_cfg_rsp_success, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	ident;
	u_int8_t	p[10];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ident = setup_pending_cfg_req(con, &ch);
	ATF_CHECK_EQ(1, callouts_pending());		/* RTX armed */

	w16(p, 0, ch->scid);			/* scid echoed */
	w16(p, 2, 0x0000);			/* flags: no C-flag */
	w16(p, 4, BT_CORE63_L2CAP_RESULT_SUCCESS);		/* result */
	p[6] = BT_CORE63_L2CAP_OPTION_MTU;
	p[7] = NG_L2CAP_OPT_MTU_SIZE;
	w16(p, 8, 0x0200);			/* imtu = 512 */
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, ident, p,
	    sizeof(p));

	ATF_CHECK_EQ(0x0200, ch->imtu);		/* Section 5.1 */
	ATF_CHECK_EQ(0, callouts_pending());	/* RTX cancelled */
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));	/* command consumed */

	drain_tx(con);
}

/*
 * Section 4.5: a ConfigRsp with the C flag set means the peer will send more;
 * the stack keeps the command and re-arms the RTX timer instead of completing.
 */
ATF_TC_WITHOUT_HEAD(bredr_cfg_rsp_cflag_waits);
ATF_TC_BODY(bredr_cfg_rsp_cflag_waits, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	ident;
	u_int8_t	p[6];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ident = setup_pending_cfg_req(con, &ch);

	w16(p, 0, ch->scid);
	w16(p, 2, BT_CORE63_L2CAP_OPTION_CONTINUATION);	/* C flag */
	w16(p, 4, BT_CORE63_L2CAP_RESULT_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, ident, p,
	    sizeof(p));

	ATF_CHECK_EQ(1, callouts_pending());	/* RTX re-armed */
	ATF_CHECK(!TAILQ_EMPTY(&con->cmd_list));	/* command kept */

	drain_tx(con);
}

/*
 * Section 4.5: a broken options block in a ConfigRsp aborts parsing; the stack
 * reports result NG_L2CAP_UNKNOWN and completes without waiting for more.  An
 * ident with no matching pending CFG_REQ yields nothing but an error return;
 * an scid that does not match the pending channel is CommandReject/INVALID_CID.
 */
ATF_TC_WITHOUT_HEAD(bredr_cfg_rsp_error_arms);
ATF_TC_BODY(bredr_cfg_rsp_error_arms, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	ident;
	int		f;
	u_int8_t	p[10];

	/* --- broken option (declared length overruns) -> UNKNOWN, done --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ident = setup_pending_cfg_req(con, &ch);
	w16(p, 0, ch->scid);
	w16(p, 2, 0x0000);
	w16(p, 4, BT_CORE63_L2CAP_RESULT_SUCCESS);
	p[6] = BT_CORE63_L2CAP_OPTION_MTU;
	p[7] = 0x02;
	p[8] = 0x00;			/* only 1 byte of a 2-byte value */
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, ident, p, 9);
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));	/* completed */
	drain_tx(con);

	/* --- scid mismatch -> CommandReject INVALID_CID --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ident = setup_pending_cfg_req(con, &ch);
	w16(p, 0, (u_int16_t)(ch->scid ^ 0x1));	/* wrong scid */
	w16(p, 2, 0x0000);
	w16(p, 4, BT_CORE63_L2CAP_RESULT_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, ident, p, 6);
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_frames[f].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_INVALID_CID, frame_le16(&g_frames[f], 4));
	drain_tx(con);

	/* --- unknown ident (no pending CFG_REQ) -> silently ignored --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	w16(p, 0, 0x0040);
	w16(p, 2, 0x0000);
	w16(p, 4, BT_CORE63_L2CAP_RESULT_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, 0x7f, p, 6);
	ATF_CHECK_EQ(0, g_nframes);
	drain_tx(con);
}

/*
 * Section 4.6/4.7: inbound L2CAP_DisconnectReq on an OPEN channel raises
 * L2CA_DisconnectInd, tears the channel down, and emits DisconnectRsp echoing
 * the CID pair.  Mismatched CIDs / unknown channel -> CommandReject.
 */
ATF_TC_WITHOUT_HEAD(bredr_discon_req_matrix);
ATF_TC_BODY(bredr_discon_req_matrix, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	scid, dcid;
	int		f;
	u_int8_t	p[4];

	/* --- success --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->dcid = 0x0091;
	ch->state = NG_L2CAP_OPEN;
	scid = ch->scid;
	dcid = ch->dcid;
	w16(p, 0, scid);		/* req.dcid = our scid */
	w16(p, 2, dcid);		/* req.scid = our dcid */
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, 0x31, p,
	    sizeof(p));
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_DISCONNECT_RSP, g_frames[f].data[0]);	/* 0x07 */
	ATF_CHECK_EQ(scid, frame_le16(&g_frames[f], 4));	/* dcid */
	ATF_CHECK_EQ(dcid, frame_le16(&g_frames[f], 6));	/* scid */
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_BREDR) == NULL);		/* freed */
	drain_tx(con);

	/* --- unknown channel -> reject --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	w16(p, 0, 0x00ee);
	w16(p, 2, 0x00ef);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, 0x32, p,
	    sizeof(p));
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_frames[f].data[0]);
	drain_tx(con);

	/* --- CID mismatch (channel exists, req.scid wrong) -> reject --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->dcid = 0x0092;
	ch->state = NG_L2CAP_OPEN;
	w16(p, 0, ch->scid);
	w16(p, 2, 0x00cd);		/* != ch->dcid */
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, 0x33, p,
	    sizeof(p));
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_frames[f].data[0]);
	drain_tx(con);
}

/*
 * Section 4.8/4.9: an inbound EchoReq is answered with an EchoRsp carrying the
 * same data.  An EchoRsp matching our pending EchoReq (from L2CA_Ping) reports
 * the ping result up and consumes the command; an unmatched EchoRsp is ignored.
 */
ATF_TC_WITHOUT_HEAD(bredr_echo_req_and_rsp);
ATF_TC_BODY(bredr_echo_req_and_rsp, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	ident;
	int		f;
	u_int8_t	data[4] = { 0xde, 0xad, 0xbe, 0xef };

	/* --- EchoReq -> EchoRsp echoing payload --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECHO_REQ, 0x41, data,
	    sizeof(data));
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECHO_RSP, g_frames[f].data[0]);	/* 0x09 */
	ATF_CHECK_EQ(0x41, g_frames[f].data[1]);
	ATF_CHECK_EQ(0, memcmp(&g_frames[f].data[4], data, sizeof(data)));
	drain_tx(con);

	/* --- EchoRsp for our pending EchoReq (L2CA_Ping) --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ATF_REQUIRE_EQ(0, l2ca_ping_req());
	ident = first_cmd_ident(con);
	ATF_CHECK_EQ(1, callouts_pending());
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECHO_RSP, ident, data,
	    sizeof(data));
	ATF_CHECK_EQ(0, callouts_pending());	/* RTX cancelled */
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);

	/* --- EchoRsp with no matching pending request -> ignored --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECHO_RSP, 0x7e, data,
	    sizeof(data));
	ATF_CHECK_EQ(0, g_nframes);
	drain_tx(con);
}

/*
 * Section 4.10/4.11/4.12: InfoReq answers.  Connectionless MTU -> success +
 * BT_CORE63_L2CAP_MTU_DEFAULT_BR_EDR (672).  Extended Features -> 4-byte mask advertising
 * "Fixed Channels" (bit 7 == 0x00000080, Section 4.12).  Fixed Channels ->
 * 8-byte map with signalling+connectionless (0x06).  Unknown type ->
 * BT_CORE63_L2CAP_INFO_NOT_SUPPORTED.
 */
ATF_TC_WITHOUT_HEAD(bredr_info_req_types);
ATF_TC_BODY(bredr_info_req_types, tc)
{
	ng_l2cap_con_p	con;
	int		f;
	u_int8_t	p[2];

	/* --- Connectionless MTU --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	w16(p, 0, BT_CORE63_L2CAP_INFO_CONNECTIONLESS_MTU);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_REQ, 0x51, p,
	    sizeof(p));
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_INFO_RSP, g_frames[f].data[0]);	/* 0x0b */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_INFO_CONNECTIONLESS_MTU, frame_le16(&g_frames[f], 4));
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, frame_le16(&g_frames[f], 6));
	ATF_CHECK_EQ(BT_CORE63_L2CAP_MTU_DEFAULT_BR_EDR, frame_le16(&g_frames[f], 8));
	drain_tx(con);

	/* --- Extended Features mask --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	w16(p, 0, BT_CORE63_L2CAP_INFO_EXTENDED_FEATURES);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_REQ, 0x52, p,
	    sizeof(p));
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_INFO_EXTENDED_FEATURES, frame_le16(&g_frames[f], 4));
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, frame_le16(&g_frames[f], 6));
	/* 4-byte little-endian feature mask == 0x00000080. */
	ATF_CHECK_EQ(0x80, g_frames[f].data[8]);
	ATF_CHECK_EQ(0x00, g_frames[f].data[9]);
	ATF_CHECK_EQ(0x00, g_frames[f].data[10]);
	ATF_CHECK_EQ(0x00, g_frames[f].data[11]);
	drain_tx(con);

	/* --- Fixed Channels bitmap --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	w16(p, 0, BT_CORE63_L2CAP_INFO_FIXED_CHANNELS);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_REQ, 0x53, p,
	    sizeof(p));
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_INFO_FIXED_CHANNELS, frame_le16(&g_frames[f], 4));
	ATF_CHECK_EQ(0x06, g_frames[f].data[8]);	/* CID 1 + CID 2 */
	drain_tx(con);

	/* --- unknown info type -> NOT_SUPPORTED --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	w16(p, 0, 0x00ff);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_REQ, 0x54, p,
	    sizeof(p));
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_INFO_RSP, g_frames[f].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_INFO_NOT_SUPPORTED, frame_le16(&g_frames[f], 6));
	drain_tx(con);
}

/*
 * Section 4.11: inbound InfoRsp for our pending InfoReq (from L2CA_GetInfo).
 * Connectionless-MTU success carrying a 2-byte MTU completes the request; a
 * bad-length MTU payload and an unmatched ident are the error arms.
 */
ATF_TC_WITHOUT_HEAD(bredr_info_rsp_matrix);
ATF_TC_BODY(bredr_info_rsp_matrix, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	ident;
	u_int8_t	p[6];

	/* --- success, 2-byte connectionless MTU --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ATF_REQUIRE_EQ(0, l2ca_get_info_req(NG_HCI_LINK_ACL));
	ident = first_cmd_ident(con);
	w16(p, 0, BT_CORE63_L2CAP_INFO_CONNECTIONLESS_MTU);
	w16(p, 2, BT_CORE63_L2CAP_RESULT_SUCCESS);
	w16(p, 4, 0x02a0);			/* MTU value */
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_RSP, ident, p,
	    sizeof(p));
	ATF_CHECK_EQ(0, callouts_pending());	/* completed */
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);

	/* --- success but malformed MTU length (0 bytes of info) --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ATF_REQUIRE_EQ(0, l2ca_get_info_req(NG_HCI_LINK_ACL));
	ident = first_cmd_ident(con);
	w16(p, 0, BT_CORE63_L2CAP_INFO_CONNECTIONLESS_MTU);
	w16(p, 2, BT_CORE63_L2CAP_RESULT_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_RSP, ident, p, 4);
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));	/* still completes */
	drain_tx(con);

	/* --- unmatched ident -> ENOENT, nothing consumed --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ATF_REQUIRE_EQ(0, l2ca_get_info_req(NG_HCI_LINK_ACL));
	w16(p, 0, BT_CORE63_L2CAP_INFO_CONNECTIONLESS_MTU);
	w16(p, 2, BT_CORE63_L2CAP_RESULT_SUCCESS);
	w16(p, 4, 0x0100);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_RSP, 0x7d, p,
	    sizeof(p));
	ATF_CHECK(!TAILQ_EMPTY(&con->cmd_list));	/* untouched */
	drain_tx(con);
}

/*
 * Section 4.1: inbound L2CAP_CommandReject dispatches on the code of the
 * pending command it answers.  Drive each arm (CON_REQ, CFG_REQ, DISCON_REQ,
 * ECHO_REQ, INFO_REQ) plus the "no such ident" arm.  Reason carried is
 * BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD (0x0000).
 */
ATF_TC_WITHOUT_HEAD(bredr_cmd_rej_dispatch);
ATF_TC_BODY(bredr_cmd_rej_dispatch, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	ident;
	u_int8_t	p[2];

	w16(p, 0, BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD);

	/* --- reject of our CON_REQ: channel torn down --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ATF_REQUIRE_EQ(0, l2ca_con_req(0x0001, NG_HCI_LINK_ACL,
	    NG_L2CAP_L2CA_IDTYPE_BREDR));
	ident = first_cmd_ident(con);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, ident, p,
	    sizeof(p));
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	ATF_CHECK_EQ(0, callouts_pending());
	drain_tx(con);

	/* --- reject of our CFG_REQ --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ident = setup_pending_cfg_req(con, &ch);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, ident, p,
	    sizeof(p));
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);

	/* --- reject of our DISCON_REQ --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->dcid = 0x0093;
	ch->state = NG_L2CAP_OPEN;
	ATF_REQUIRE_EQ(0, l2ca_discon_req(ch, NG_L2CAP_L2CA_IDTYPE_BREDR));
	ident = first_cmd_ident(con);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, ident, p,
	    sizeof(p));
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);

	/* --- reject of our ECHO_REQ (L2CA_Ping) --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ATF_REQUIRE_EQ(0, l2ca_ping_req());
	ident = first_cmd_ident(con);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, ident, p,
	    sizeof(p));
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);

	/* --- reject of our INFO_REQ (L2CA_GetInfo) --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ATF_REQUIRE_EQ(0, l2ca_get_info_req(NG_HCI_LINK_ACL));
	ident = first_cmd_ident(con);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, ident, p,
	    sizeof(p));
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);

	/* --- reject with no matching pending ident -> ignored --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, 0x7c, p,
	    sizeof(p));
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);
}

/*
 * Section 4: framing of the signalling C-frame in ng_l2cap_process_signal_cmd.
 * (a) a command header shorter than 4 bytes -> the whole C-frame is dropped;
 * (b) two commands packed in one C-frame are both processed (the m_split
 *     continuation path) -- here two EchoReqs yield two EchoRsps;
 * (c) an unknown command code -> CommandReject / NOT_UNDERSTOOD.
 */
ATF_TC_WITHOUT_HEAD(bredr_signal_framing);
ATF_TC_BODY(bredr_signal_framing, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	raw[64];
	int		n, f;

	/* --- (a) truncated command header (< 4 bytes) --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	raw[0] = BT_CORE63_L2CAP_CMD_ECHO_REQ;
	raw[1] = 0x61;			/* only 2 bytes -- no length field */
	feed_sig_raw(con, BT_CORE63_L2CAP_CID_SIGNAL, raw, 2);
	ATF_CHECK_EQ(0, g_nframes);	/* dropped, nothing emitted */
	drain_tx(con);

	/* --- (b) two EchoReqs in one C-frame --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	n = 0;
	raw[n++] = BT_CORE63_L2CAP_CMD_ECHO_REQ; raw[n++] = 0x62;
	raw[n++] = 0x01; raw[n++] = 0x00;		/* length 1 */
	raw[n++] = 0xaa;
	raw[n++] = BT_CORE63_L2CAP_CMD_ECHO_REQ; raw[n++] = 0x63;
	raw[n++] = 0x01; raw[n++] = 0x00;		/* length 1 */
	raw[n++] = 0xbb;
	feed_sig_raw(con, BT_CORE63_L2CAP_CID_SIGNAL, raw, n);
	ATF_CHECK_EQ(2, g_nframes);			/* two EchoRsps */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECHO_RSP, g_frames[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECHO_RSP, g_frames[1].data[0]);
	ATF_CHECK_EQ(0x62, g_frames[0].data[1]);
	ATF_CHECK_EQ(0x63, g_frames[1].data[1]);
	drain_tx(con);

	/* --- (c) unknown command code -> CommandReject NOT_UNDERSTOOD --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	n = 0;
	raw[n++] = 0x7f;			/* undefined signalling code */
	raw[n++] = 0x64;
	raw[n++] = 0x00; raw[n++] = 0x00;	/* length 0 */
	feed_sig_raw(con, BT_CORE63_L2CAP_CID_SIGNAL, raw, n);
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_frames[f].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD, frame_le16(&g_frames[f], 4));
	drain_tx(con);

	/* --- (d) BR/EDR signalling is forbidden on an LE logical link. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECHO_REQ, 0x65,
	    NULL, 0);
	ATF_CHECK_EQ(0, g_nframes);
	drain_tx(con);

	/* --- (e) a BR/EDR C-frame above MTUsig is rejected as one unit. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	memset(raw, 0, 49);
	raw[0] = BT_CORE63_L2CAP_CMD_ECHO_REQ;
	raw[1] = 0x66;
	raw[2] = 45;
	feed_sig_raw(con, BT_CORE63_L2CAP_CID_SIGNAL, raw, 49);
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_frames[f].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_SIGNAL_MTU_EXCEEDED,
	    frame_le16(&g_frames[f], 4));
	drain_tx(con);

	/* --- (f) LE signalling permits exactly one command per C-frame. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	n = 0;
	raw[n++] = BT_CORE63_L2CAP_CMD_REJECT; raw[n++] = 0x67;
	raw[n++] = 0x02; raw[n++] = 0x00;
	raw[n++] = 0x00; raw[n++] = 0x00;
	raw[n++] = BT_CORE63_L2CAP_CMD_DISCONNECT_REQ; raw[n++] = 0x68;
	raw[n++] = 0x04; raw[n++] = 0x00;
	memset(raw + n, 0, 4); n += 4;
	feed_sig_raw(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, raw, n);
	ATF_REQUIRE(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_frames[last_frame()].data[0]);
	drain_tx(con);

	/* --- (g) exercise the LE dispatcher arms for reject and disconnect. --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	memset(raw, 0, 4);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, 0x69,
	    raw, 2);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, 0x6a,
	    raw, 4);
	drain_tx(con);
}

/* ====================================================================== */
/* ulpi.c upper-layer indication primitives (driven directly)            */
/* ====================================================================== */

/*
 * ng_l2cap_l2ca_encryption_change: reports an HCI encryption-change up as
 * NGM_L2CAP_L2CA_ENC_CHANGE (0x92).  The idtype field depends on the channel:
 * a fixed ATT channel reports IDTYPE_ATT with lcid==con_handle; a dynamic
 * BR/EDR channel reports IDTYPE_BREDR with lcid==scid.  With the upstream hook
 * down the call returns ENOTCONN.
 */
ATF_TC_WITHOUT_HEAD(ulpi_encryption_change);
ATF_TC_BODY(ulpi_encryption_change, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch, att;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);

	/* Dynamic BR/EDR channel. */
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ATF_CHECK_EQ(0, ng_l2cap_l2ca_encryption_change(ch, 0x0000));
	ATF_CHECK_EQ(NGM_L2CAP_L2CA_ENC_CHANGE, g_last_msg_cmd);

	/* Fixed ATT channel (scid == ATT CID). */
	att = ng_l2cap_new_chan(&g_l2cap, con, 0x001f,
	    NG_L2CAP_L2CA_IDTYPE_ATT);
	ATF_REQUIRE(att != NULL);
	ATF_CHECK_EQ(0, ng_l2cap_l2ca_encryption_change(att, 0x0001));
	ATF_CHECK_EQ(NGM_L2CAP_L2CA_ENC_CHANGE, g_last_msg_cmd);

	/* Hook down -> ENOTCONN. */
	g_l2cap.l2c = NULL;
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_encryption_change(ch, 0));
	g_l2cap.l2c = (hook_p)&g_l2cap;

	drain_tx(con);
}

/*
 * ng_l2cap_l2ca_qos_ind raises NGM_L2CAP_L2CA_QOS_IND (0x86) carrying the
 * remote address; hook-down returns ENOTCONN.  ng_l2cap_l2ca_cfg_ind's
 * hook-down arm returns ENOTCONN as well.
 */
ATF_TC_WITHOUT_HEAD(ulpi_qos_and_cfg_ind);
ATF_TC_BODY(ulpi_qos_and_cfg_ind, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);

	ATF_CHECK_EQ(0, ng_l2cap_l2ca_qos_ind(ch));
	ATF_CHECK_EQ(NGM_L2CAP_L2CA_QOS_IND, g_last_msg_cmd);

	g_l2cap.l2c = NULL;
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_qos_ind(ch));
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_cfg_ind(ch));
	g_l2cap.l2c = (hook_p)&g_l2cap;

	drain_tx(con);
}

/*
 * ng_l2cap_chan_by_conhandle: L2CA_Disconnect with idtype ATT looks the fixed
 * ATT channel up by (ATT CID, connection handle) and frees it directly without
 * a Disconnection Request (Section 4 fixed channels are not disconnected on
 * the L2CAP signalling channel).
 */
ATF_TC_WITHOUT_HEAD(ulpi_chan_by_conhandle_att_discon);
ATF_TC_BODY(ulpi_chan_by_conhandle_att_discon, tc)
{
	ng_l2cap_con_p		con;
	ng_l2cap_chan_p		ch;
	ng_l2cap_l2ca_discon_ip	ip;
	struct ng_mesg		*msg;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x001f,
	    NG_L2CAP_L2CA_IDTYPE_ATT);
	ATF_REQUIRE(ch != NULL);
	ATF_CHECK(ng_l2cap_chan_by_conhandle(&g_l2cap, BT_CORE63_L2CAP_CID_ATT,
	    con->con_handle) == ch);

	memset(&ip, 0, sizeof(ip));
	ip.lcid = con->con_handle;		/* lcid carries con_handle */
	ip.idtype = NG_L2CAP_L2CA_IDTYPE_ATT;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_DISCON, &ip, sizeof(ip));
	ATF_CHECK_EQ(0, ng_l2cap_l2ca_discon_req(&g_l2cap, msg));
	(free)(msg);

	/* Channel gone; a second lookup misses (exercises the not-found arm). */
	ATF_CHECK(ng_l2cap_chan_by_conhandle(&g_l2cap, BT_CORE63_L2CAP_CID_ATT,
	    con->con_handle) == NULL);
	memset(&ip, 0, sizeof(ip));
	ip.lcid = con->con_handle;
	ip.idtype = NG_L2CAP_L2CA_IDTYPE_ATT;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_DISCON, &ip, sizeof(ip));
	ATF_CHECK_EQ(EINVAL, ng_l2cap_l2ca_discon_req(&g_l2cap, msg));
	(free)(msg);

	drain_tx(con);
}

/* ====================================================================== */
/* misc.c: hook-info, refcount lifecycle, timer arm/disarm               */
/* ====================================================================== */

/*
 * ng_l2cap_send_hook_info early-returns when node/hook are invalid, when the
 * HCI hook is absent, or when the local BD_ADDR is still all-zero; only with a
 * valid node+hook, an HCI hook and a non-zero address does it emit
 * NGM_L2CAP_NODE_HOOK_INFO (0x409).
 */
ATF_TC_WITHOUT_HEAD(misc_send_hook_info);
ATF_TC_BODY(misc_send_hook_info, tc)
{
	node_p	node;
	hook_p	hook;

	reset_all();
	node = g_l2cap.node;
	hook = (hook_p)&g_l2cap;

	/* NULL node / NULL hook -> silent return, no message. */
	ng_l2cap_send_hook_info(NULL, hook, NULL, 0);
	ng_l2cap_send_hook_info(node, NULL, NULL, 0);
	ATF_CHECK_EQ(0, g_nmsg);

	/* HCI hook absent -> return. */
	g_l2cap.hci = NULL;
	ng_l2cap_send_hook_info(node, hook, NULL, 0);
	ATF_CHECK_EQ(0, g_nmsg);

	/* HCI hook present but BD_ADDR all-zero -> return. */
	g_l2cap.hci = (hook_p)&g_l2cap;
	memset(&g_l2cap.bdaddr, 0, sizeof(g_l2cap.bdaddr));
	ng_l2cap_send_hook_info(node, hook, NULL, 0);
	ATF_CHECK_EQ(0, g_nmsg);

	/* Fully valid -> HOOK_INFO emitted. */
	g_l2cap.bdaddr.b[0] = 0x11;
	ng_l2cap_send_hook_info(node, hook, NULL, 0);
	ATF_CHECK_EQ(1, g_nmsg);
	ATF_CHECK_EQ(NGM_L2CAP_NODE_HOOK_INFO, g_last_msg_cmd);
}

/*
 * ng_l2cap_con_ref / ng_l2cap_con_unref auto-disconnect-timer interplay
 * (Section 4-independent local resource management): on the last unref of an
 * OPEN, OUTGOING connection with discon_timo>0 the auto-disconnect timer is
 * armed; a subsequent ref cancels it.  A ref while the timer is armed but the
 * connection is not in the OPEN/OUTGOING shape hits the "bad auto disconnect"
 * guard; an unref below zero is clamped.
 */
ATF_TC_WITHOUT_HEAD(misc_con_ref_lifecycle);
ATF_TC_BODY(misc_con_ref_lifecycle, tc)
{
	ng_l2cap_con_p	con;

	reset_all();
	g_l2cap.discon_timo = 5;
	con = mk_con(NG_HCI_LINK_ACL, 1);
	con->state = NG_L2CAP_CON_OPEN;
	con->flags |= NG_L2CAP_CON_OUTGOING;
	con->refcnt = 1;

	/* Last unref -> auto-disconnect timer armed. */
	ng_l2cap_con_unref(con);
	ATF_CHECK_EQ(0, con->refcnt);
	ATF_CHECK((con->flags & NG_L2CAP_CON_AUTO_DISCON_TIMO) != 0);
	ATF_CHECK_EQ(1, callouts_pending());

	/* ref -> timer cancelled. */
	ng_l2cap_con_ref(con);
	ATF_CHECK_EQ(1, con->refcnt);
	ATF_CHECK((con->flags & NG_L2CAP_CON_AUTO_DISCON_TIMO) == 0);
	ATF_CHECK_EQ(0, callouts_pending());

	/* ref with AUTO_DISCON_TIMO set but wrong state -> guard arm. */
	con->flags |= NG_L2CAP_CON_AUTO_DISCON_TIMO;
	con->state = NG_L2CAP_CON_CLOSED;
	ng_l2cap_con_ref(con);
	ATF_CHECK((con->flags & NG_L2CAP_CON_AUTO_DISCON_TIMO) != 0);
	con->flags &= ~NG_L2CAP_CON_AUTO_DISCON_TIMO;

	/* unref below zero -> clamped to zero with alert. */
	con->refcnt = 0;
	ng_l2cap_con_unref(con);
	ATF_CHECK_EQ(0, con->refcnt);

	con->state = NG_L2CAP_CON_OPEN;		/* let free_con clean up */
	drain_tx(con);
}

/*
 * ng_l2cap_lp_timeout / lp_untimeout / discon_timeout / discon_untimeout arm
 * and disarm the per-connection callout and reject double-arm / no-arm /
 * already-fired (ETIMEDOUT) transitions.
 */
ATF_TC_WITHOUT_HEAD(misc_timer_arm_disarm);
ATF_TC_BODY(misc_timer_arm_disarm, tc)
{
	ng_l2cap_con_p	con;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);

	/* LP timeout: arm, double-arm guard, disarm. */
	ATF_CHECK_EQ(0, ng_l2cap_lp_timeout(con));
	ATF_CHECK((con->flags & NG_L2CAP_CON_LP_TIMO) != 0);
	ATF_CHECK_EQ(1, callouts_pending());
	ATF_CHECK_EQ(0, ng_l2cap_lp_timeout(con));	/* invalid re-arm */
	ATF_CHECK_EQ(0, ng_l2cap_lp_untimeout(con));	/* disarm */
	ATF_CHECK((con->flags & NG_L2CAP_CON_LP_TIMO) == 0);
	ATF_CHECK_EQ(0, ng_l2cap_lp_untimeout(con));	/* no-timeout guard */

	/* LP untimeout when flagged but callout not pending -> ETIMEDOUT. */
	con->flags |= NG_L2CAP_CON_LP_TIMO;
	ATF_CHECK_EQ(ETIMEDOUT, ng_l2cap_lp_untimeout(con));
	con->flags &= ~NG_L2CAP_CON_LP_TIMO;

	/* discon timeout: arm, double-arm guard, disarm, no-arm guard. */
	ATF_CHECK_EQ(0, ng_l2cap_discon_timeout(con));
	ATF_CHECK((con->flags & NG_L2CAP_CON_AUTO_DISCON_TIMO) != 0);
	ATF_CHECK_EQ(0, ng_l2cap_discon_timeout(con));	/* invalid re-arm */
	ATF_CHECK_EQ(0, ng_l2cap_discon_untimeout(con));
	ATF_CHECK_EQ(0, ng_l2cap_discon_untimeout(con));	/* no-timeout */

	/* discon untimeout when flagged but not pending -> ETIMEDOUT. */
	con->flags |= NG_L2CAP_CON_AUTO_DISCON_TIMO;
	ATF_CHECK_EQ(ETIMEDOUT, ng_l2cap_discon_untimeout(con));
	con->flags &= ~NG_L2CAP_CON_AUTO_DISCON_TIMO;

	drain_tx(con);
}

/*
 * ng_l2cap_free_con with an armed auto-disconnect timer, a queued TX packet,
 * an RX packet, an attached channel and a pending command exercises every
 * cleanup arm including the "timeout pending!" alert path.
 */
ATF_TC_WITHOUT_HEAD(misc_free_con_full_cleanup);
ATF_TC_BODY(misc_free_con_full_cleanup, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);

	/* Attach a channel with a pending CFG_REQ command + RTX. */
	ch = ng_l2cap_new_chan(&g_l2cap, con, 0x0001,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	ATF_REQUIRE(ch != NULL);
	ch->dcid = 0x0094;
	ch->state = NG_L2CAP_CONFIG;
	ch->le_psm = 0;
	ATF_REQUIRE_EQ(0, l2ca_cfg_req(ch, 0x0030));

	/* Queue a TX placeholder and an RX packet. */
	con->tx_pkt = ng_mbuf_alloc();
	con->rx_pkt = ng_mbuf_alloc();
	con->rx_pkt->m_len = con->rx_pkt->m_pkthdr.len = 4;

	/* Force the "timeout pending" alert arm. */
	con->flags |= NG_L2CAP_CON_AUTO_DISCON_TIMO;

	ng_l2cap_free_con(con);
	/* Connection gone from the list. */
	ATF_CHECK(LIST_EMPTY(&g_l2cap.con_list));
}

/* ====================================================================== */
/* LE Connection Parameter Update -- Vol 3 Part A §4.20                   */
/* ====================================================================== */

/*
 * §4.20: the Connection Parameter Update Request (code 0x12, LE signalling
 * CID 0x0005) carries Interval_Min/Max, Peripheral_Latency and Timeout.
 * In-range parameters (validated against Vol 6 Part B §2.4.2.16) are ACCEPTED
 * (result 0x0000) and forwarded to HCI; a short payload or an out-of-range
 * parameter is REJECTED (result 0x0001).  A malformed fixed-length request
 * receives Command Reject.  The Response (code 0x13) matching our pending
 * request consumes that command.
 */
ATF_TC_WITHOUT_HEAD(le_param_update_req_rsp);
ATF_TC_BODY(le_param_update_req_rsp, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_cmd_p	cmd;
	int		f;
	u_int8_t	p[8];

	/* --- accepted: interval 6/6, latency 0, timeout 100 --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(p, 0, 6);				/* interval_min */
	w16(p, 2, 6);				/* interval_max */
	w16(p, 4, 0);				/* latency */
	w16(p, 6, 100);				/* timeout */
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL,
	    BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ, 0x71, p, sizeof(p));
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_PARAM_UPDATE_RSP,
	    g_frames[f].data[0]);				/* 0x13 */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_PARAM_UPDATE_ACCEPT,
	    frame_le16(&g_frames[f], 4));			/* result 0 */
	drain_tx(con);

	/* --- rejected: interval_min below minimum (5) --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(p, 0, 5);				/* < 6 -> out of range */
	w16(p, 2, 6);
	w16(p, 4, 0);
	w16(p, 6, 100);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL,
	    BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ, 0x72, p, sizeof(p));
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_PARAM_UPDATE_REJECT,
	    frame_le16(&g_frames[f], 4));			/* result 1 */
	drain_tx(con);

	/* --- malformed: truncated fixed-size payload (< 8 bytes) --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL,
	    BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ, 0x73, p, 4);
	ATF_REQUIRE(g_nframes >= 1);
	f = last_frame();
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_frames[f].data[0]);
	ATF_CHECK_EQ(0x73, g_frames[f].data[1]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD,
	    frame_le16(&g_frames[f], 4));
	drain_tx(con);

	/* --- Response matching our pending request -> consumed --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	cmd = ng_l2cap_new_cmd(con, NULL, 0x74,
	    BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ, 0);
	ATF_REQUIRE(cmd != NULL);
	ng_l2cap_link_cmd(con, cmd);
	ng_l2cap_command_timeout(cmd, 3);	/* mark PENDING + arm RTX */
	ATF_CHECK_EQ(1, callouts_pending());
	w16(p, 0, BT_CORE63_L2CAP_PARAM_UPDATE_ACCEPT);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL,
	    BT_CORE63_L2CAP_CMD_PARAM_UPDATE_RSP, 0x74, p, 2);
	ATF_CHECK_EQ(0, callouts_pending());	/* RTX cancelled */
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));	/* command consumed */
	drain_tx(con);

	/* --- Response with no matching pending request -> ignored --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(p, 0, BT_CORE63_L2CAP_PARAM_UPDATE_ACCEPT);
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL,
	    BT_CORE63_L2CAP_CMD_PARAM_UPDATE_RSP, 0x75, p, 2);
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);
}

/*
 * §4.2: a ConnectReq that cannot allocate a channel (kernel malloc exhausted)
 * takes the BT_CORE63_L2CAP_RESULT_NO_RESOURCES arm; here the reject command itself also
 * fails to allocate, so no channel is created and no PDU escapes -- this drives
 * the ch==NULL branch of process_con_req and the new_cmd==NULL branch of
 * send_l2cap_con_rej.
 */
ATF_TC_WITHOUT_HEAD(bredr_con_req_no_resources);
ATF_TC_BODY(bredr_con_req_no_resources, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_kmalloc_budget = 0;			/* every kernel malloc fails */

	w16(p, 0, 0x0001);
	w16(p, 2, 0x0045);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x76, p,
	    sizeof(p));

	g_kmalloc_budget = -1;
	ATF_CHECK(ng_l2cap_chan_by_dcid(&g_l2cap, 0x0045,
	    NG_L2CAP_L2CA_IDTYPE_BREDR) == NULL);
	ATF_CHECK_EQ(0, g_nframes);

	drain_tx(con);
}

/* ====================================================================== */
/* m_pullup() failure arms -- Core Spec Vol 3 Part A framing (ENOBUFS)     */
/* ====================================================================== */

/*
 * Drive one signalling C-frame with a short m_len (so the kernel's
 * NG_L2CAP_M_PULLUP wrapper actually calls m_pullup) and arm the Nth pullup
 * along the decode path to fail.  Asserts the target pullup was the one that
 * fired (g_pullup_calls == nth), that the packet was reclaimed (rx_pkt NULL),
 * and that no PDU escaped -- i.e. the ENOBUFS/error arm was taken.
 */
static void
pullup_sig_case(ng_l2cap_con_p con, u_int16_t cid, u_int8_t code,
    u_int8_t ident, int plen, int nth)
{
	u_int8_t	p[64];

	memset(p, 0, sizeof(p));
	if (plen > (int)sizeof(p))
		plen = sizeof(p);
	g_nframes = 0;
	g_short_mlen = 0;
	g_pullup_calls = 0;
	g_pullup_fail_at = nth;
	feed_sig(con, cid, code, ident, p, plen);
	ATF_CHECK_EQ(nth, g_pullup_calls);	/* target pullup fired */
	ATF_CHECK(con->rx_pkt == NULL);		/* packet reclaimed */
	ATF_CHECK_EQ(0, g_nframes);		/* nothing emitted */
	g_short_mlen = -1;
	g_pullup_fail_at = -1;
}

/*
 * §4: the two framing pullups in ng_l2cap_receive (L2CAP header) and in
 * ng_l2cap_process_signal_cmd / ng_l2cap_process_lesignal_cmd (command
 * header) fail -> ENOBUFS.
 */
ATF_TC_WITHOUT_HEAD(pullup_fail_framing);
ATF_TC_BODY(pullup_fail_framing, tc)
{
	ng_l2cap_con_p	con;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	/* ng_l2cap_receive() L2CAP-header pullup (first pullup on the path). */
	pullup_sig_case(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x41, 8, 1);
	/* ng_l2cap_process_signal_cmd() command-header pullup (second). */
	pullup_sig_case(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x42, 8, 2);
	drain_tx(con);

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	/* ng_l2cap_process_lesignal_cmd() command-header pullup (second). */
	pullup_sig_case(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ,
	    0x43, 14, 2);
	drain_tx(con);
}

/*
 * §4: each BR/EDR signalling decoder pulls its command parameters up as its
 * first action; force that pullup (third on the path) to fail -> the decoder
 * takes its ENOBUFS arm.
 */
ATF_TC_WITHOUT_HEAD(pullup_fail_bredr_decoders);
ATF_TC_BODY(pullup_fail_bredr_decoders, tc)
{
	ng_l2cap_con_p	con;
	/*
	 * Most decoders pull up as their first action, so any payload >= the
	 * command-parameter size reaches the pullup.  The three ECBFC decoders
	 * that carry a variable CID list validate cmd_length *before* the
	 * pullup, so they need an exact valid length (fixed cp + one CID) to
	 * reach it: CREDIT_CON_REQ 8+2, CREDIT_CON_RSP 8+2, RECONFIG_REQ 4+2.
	 */
	static const struct { u_int8_t code; int plen; } cases[] = {
		{ BT_CORE63_L2CAP_CMD_REJECT, 40 },
		{ BT_CORE63_L2CAP_CMD_CONNECTION_REQ, sizeof(ng_l2cap_con_req_cp) },
		{ BT_CORE63_L2CAP_CMD_CONNECTION_RSP, sizeof(ng_l2cap_con_rsp_cp) },
		{ BT_CORE63_L2CAP_CMD_CONFIG_REQ, 40 }, { BT_CORE63_L2CAP_CMD_CONFIG_RSP, 40 },
		{ BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, sizeof(ng_l2cap_discon_req_cp) },
		{ BT_CORE63_L2CAP_CMD_DISCONNECT_RSP, sizeof(ng_l2cap_discon_rsp_cp) },
		{ BT_CORE63_L2CAP_CMD_INFO_REQ, sizeof(ng_l2cap_info_req_cp) },
		{ BT_CORE63_L2CAP_CMD_INFO_RSP, 40 },
		{ BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT,
		    sizeof(ng_l2cap_flow_control_credit_cp) },
		{ BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ, 10 }, { BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP, 10 },
		{ BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ, 6 },
		{ BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP,
		    sizeof(ng_l2cap_credit_reconfig_rsp_cp) },
	};
	unsigned	i;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	for (i = 0; i < nitems(cases); i++)
		pullup_sig_case(con, BT_CORE63_L2CAP_CID_SIGNAL, cases[i].code,
		    (u_int8_t)(0x50 + i), cases[i].plen, 3);
	drain_tx(con);
}

/*
 * §4.22/§4.23: the two LE-only credit decoders (LE Credit Based Connection
 * Request/Response) pull their parameters up first; force that failure.
 */
ATF_TC_WITHOUT_HEAD(pullup_fail_le_decoders);
ATF_TC_BODY(pullup_fail_le_decoders, tc)
{
	ng_l2cap_con_p	con;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	pullup_sig_case(con, BT_CORE63_L2CAP_CID_LE_SIGNAL,
	    BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x60,
	    sizeof(ng_l2cap_le_credit_con_req_cp), 3);
	pullup_sig_case(con, BT_CORE63_L2CAP_CID_LE_SIGNAL,
	    BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP, 0x61,
	    sizeof(ng_l2cap_le_credit_con_rsp_cp), 3);
	drain_tx(con);
}

/*
 * §3.2/§3.4.3: the data-plane pullups.  write_req (L2CA header) and
 * l2ca_receive (L2CAP header) are the first pullup on their path;
 * l2ca_clt_receive is reached through ng_l2cap_receive (second pullup); the
 * LE CoC first-K-frame SDU-Length pullup is the second on the receive path.
 */
ATF_TC_WITHOUT_HEAD(pullup_fail_data_paths);
ATF_TC_BODY(pullup_fail_data_paths, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	sdu[8];

	/* ng_l2cap_l2ca_write_req(): L2CA data header pullup. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);
	memset(sdu, 0, sizeof(sdu));
	g_short_mlen = 0;
	g_pullup_calls = 0;
	g_pullup_fail_at = 1;
	ATF_CHECK_EQ(ENOBUFS, do_write(con, ch, sdu, sizeof(sdu)));
	ATF_CHECK_EQ(1, g_pullup_calls);
	g_short_mlen = -1;
	g_pullup_fail_at = -1;
	drain_tx(con);

	/* ng_l2cap_l2ca_receive(): L2CAP header pullup. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);
	g_short_mlen = 0;
	g_pullup_calls = 0;
	g_pullup_fail_at = 1;
	ATF_CHECK_EQ(ENOBUFS, feed_data(con, ch->scid, sdu, sizeof(sdu)));
	ATF_CHECK_EQ(1, g_pullup_calls);
	g_short_mlen = -1;
	g_pullup_fail_at = -1;
	drain_tx(con);

	/* LE CoC first-K-frame SDU-Length pullup (second on the receive path). */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);
	g_short_mlen = 0;
	g_pullup_calls = 0;
	g_pullup_fail_at = 2;
	ATF_CHECK_EQ(ENOBUFS, feed_data(con, ch->scid, sdu, sizeof(sdu)));
	ATF_CHECK_EQ(2, g_pullup_calls);
	g_short_mlen = -1;
	g_pullup_fail_at = -1;
	drain_tx(con);

	/* ng_l2cap_l2ca_clt_receive(): CLT header pullup (via ng_l2cap_receive). */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	pullup_sig_case(con, BT_CORE63_L2CAP_CID_CONNECTIONLESS, 0, 0x00, 8, 2);
	drain_tx(con);
}

/* ====================================================================== */
/* Response-PDU allocation failure arms (cmd->aux == NULL / new_cmd NULL)  */
/* ====================================================================== */

/*
 * Every send_l2cap_* helper first allocates a command descriptor (kernel
 * malloc) and then the response PDU mbuf (MGETHDR).  Because the two use
 * different allocators, g_mbuf_budget == 1 lets the fed rx mbuf succeed but
 * fails the response MGETHDR, so new_cmd succeeds yet cmd->aux stays NULL --
 * driving the ENOBUFS arm without disturbing the decode that precedes it.
 */
ATF_TC_WITHOUT_HEAD(alloc_fail_send_helpers);
ATF_TC_BODY(alloc_fail_send_helpers, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	p[8];

	memset(p, 0, sizeof(p));

	/* send_l2cap_reject: unknown BR/EDR signalling code -> CommandReject. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_mbuf_budget = 1;			/* rx ok, response aux fails */
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, 0x7f, 0x41, p, 4);
	g_mbuf_budget = -1;
	ATF_CHECK_EQ(0, g_nframes);
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);

	/* send_l2cap_reject on the LE signalling channel (unknown code). */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	g_mbuf_budget = 1;
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, 0x7f, 0x42, p, 4);
	g_mbuf_budget = -1;
	ATF_CHECK_EQ(0, g_nframes);
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);

	/* send_l2cap_con_rej: ConnectReq with an invalid Source CID. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	w16(p, 0, 0x0001);			/* psm */
	w16(p, 2, 0x0001);			/* scid < BT_CORE63_L2CAP_CID_DYNAMIC_FIRST */
	g_mbuf_budget = 1;
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x43, p, 4);
	g_mbuf_budget = -1;
	ATF_CHECK_EQ(0, g_nframes);
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);

	/* send_l2cap_param_urs: LE Connection Parameter Update Request. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	w16(p, 0, 6); w16(p, 2, 12); w16(p, 4, 0); w16(p, 6, 100);
	g_mbuf_budget = 1;
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL,
	    BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ, 0x44, p, 8);
	g_mbuf_budget = -1;
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	drain_tx(con);
}

/*
 * §4.10/§4.12: process_info_req builds the Information Response PDU via
 * MGETHDR for each info type.  Failing that mbuf reaches the per-type
 * cmd->aux == NULL breaks and the shared ENOBUFS arm.
 */
ATF_TC_WITHOUT_HEAD(alloc_fail_info_req);
ATF_TC_BODY(alloc_fail_info_req, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	p[2];
	static const u_int16_t types[] = {
		BT_CORE63_L2CAP_INFO_CONNECTIONLESS_MTU, BT_CORE63_L2CAP_INFO_EXTENDED_FEATURES,
		BT_CORE63_L2CAP_INFO_FIXED_CHANNELS, 0x00ff /* unknown -> default */
	};
	unsigned	i;

	for (i = 0; i < nitems(types); i++) {
		reset_all();
		con = mk_con(NG_HCI_LINK_ACL, 1);
		w16(p, 0, types[i]);
		g_mbuf_budget = 1;		/* rx ok, response MGETHDR fails */
		feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_REQ,
		    (u_int8_t)(0x50 + i), p, 2);
		g_mbuf_budget = -1;
		ATF_CHECK_EQ(0, g_nframes);
		ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
		drain_tx(con);
	}
}

/*
 * §4.22: a fully valid LE Credit Based Connection Request that passes every
 * check, opens the channel and allocates its command, but then fails to
 * allocate the success-response PDU -- the cmd->aux == NULL arm that unwinds
 * the freshly opened channel.
 */
ATF_TC_WITHOUT_HEAD(alloc_fail_le_coc_success_rsp);
ATF_TC_BODY(alloc_fail_le_coc_success_rsp, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	p[10];

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);	/* encrypted */
	w16(p, 0, 0x0080);			/* upper-layer SPSM */
	w16(p, 2, 0x0041);			/* scid (valid dynamic) */
	w16(p, 4, 247);				/* mtu >= 23 */
	w16(p, 6, 247);				/* mps in range */
	w16(p, 8, 10);				/* initial credits > 0 */
	feed_sig(con, BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ,
	    0x55, p, sizeof(p));
	{
		ng_l2cap_chan_p ch;

		ch = ng_l2cap_chan_by_dcid(&g_l2cap, 0x0041,
		    NG_L2CAP_L2CA_IDTYPE_LE);
		ATF_REQUIRE(ch != NULL);
		g_mbuf_budget = 0;
		ATF_CHECK_EQ(ENOBUFS, l2ca_con_rsp_req(ch->scid,
		    NG_HCI_LINK_LE_PUBLIC, 0x55, BT_CORE63_L2CAP_RESULT_SUCCESS));
	}
	g_mbuf_budget = -1;
	/* Channel was opened then torn down; none should remain. */
	ATF_CHECK(ng_l2cap_chan_by_dcid(&g_l2cap, 0x0041,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);
	ATF_CHECK_EQ(0, g_nframes);
	drain_tx(con);
}

/*
 * L2CA request paths from the upper layer (ping / get_info / disconnect):
 * new_cmd failure (kernel malloc) and response-PDU failure (MGETHDR) arms,
 * plus the pre-connection LP_ConnectReq branch and its error/return arms,
 * and the request-size validation rejects.
 */
ATF_TC_WITHOUT_HEAD(alloc_fail_request_paths);
ATF_TC_BODY(alloc_fail_request_paths, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;

	/* --- L2CA_Ping validation rejects (no connection needed) --- */
	reset_all();
	{
		ng_l2cap_l2ca_ping_ip	ip;
		struct ng_mesg		*msg;

		/* echo_size overflows the message body -> EMSGSIZE */
		memset(&ip, 0, sizeof(ip));
		bcopy(&g_addr, &ip.bdaddr, sizeof(ip.bdaddr));
			ip.echo_size = 200;
			msg = mk_l2ca_msg(NGM_L2CAP_L2CA_PING, &ip, sizeof(ip));
			ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_ping_req(&g_l2cap, msg));
			(free)(msg);

			/* oversized echo is rejected before trusting the body length */
			ip.echo_size = NG_L2CAP_MAX_ECHO_SIZE + 1;
			msg = mk_l2ca_msg(NGM_L2CAP_L2CA_PING, &ip, sizeof(ip));
			ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_ping_req(&g_l2cap, msg));
			(free)(msg);

			/* arglen smaller than the fixed header -> EMSGSIZE */
			msg = mk_l2ca_msg(NGM_L2CAP_L2CA_PING, &ip, sizeof(ip) - 1);
			ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_ping_req(&g_l2cap, msg));
			(free)(msg);
		}

	/* --- L2CA_Ping: con exists, new_cmd then aux failure --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_kmalloc_budget = 0;			/* new_cmd fails -> ENOMEM */
	ATF_CHECK_EQ(ENOMEM, l2ca_ping_req());
	g_kmalloc_budget = -1;
	g_mbuf_budget = 0;			/* echo_req PDU MGETHDR fails */
	ATF_CHECK_EQ(ENOBUFS, l2ca_ping_req());
	g_mbuf_budget = -1;
	drain_tx(con);

	/* --- L2CA_Ping: no con -> LP_ConnectReq creates it, then succeeds --- */
	reset_all();
	g_lp_con_req_make = 1;
	ATF_CHECK_EQ(0, l2ca_ping_req());
	con = ng_l2cap_con_by_addr(&g_l2cap, &g_addr, NG_HCI_LINK_ACL);
	ATF_REQUIRE(con != NULL);
	drain_tx(con);

	/* --- L2CA_Ping: LP_ConnectReq itself fails --- */
	reset_all();
	g_lp_con_req_err = EHOSTUNREACH;
	ATF_CHECK_EQ(EHOSTUNREACH, l2ca_ping_req());

	/* --- L2CA_GetInfo: new_cmd then aux failure (con exists) --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_kmalloc_budget = 0;
	ATF_CHECK_EQ(ENOMEM, l2ca_get_info_req(NG_HCI_LINK_ACL));
	g_kmalloc_budget = -1;
	g_mbuf_budget = 0;
	ATF_CHECK_EQ(ENOBUFS, l2ca_get_info_req(NG_HCI_LINK_ACL));
	g_mbuf_budget = -1;
	drain_tx(con);

	/* --- L2CA_GetInfo: no con -> LP path, and LP error --- */
	reset_all();
	g_lp_con_req_make = 1;
	ATF_CHECK_EQ(0, l2ca_get_info_req(NG_HCI_LINK_ACL));
	con = ng_l2cap_con_by_addr(&g_l2cap, &g_addr, NG_HCI_LINK_ACL);
	ATF_REQUIRE(con != NULL);
	drain_tx(con);
	reset_all();
	g_lp_con_req_err = EHOSTUNREACH;
	ATF_CHECK_EQ(EHOSTUNREACH, l2ca_get_info_req(NG_HCI_LINK_ACL));

	/* --- L2CA_Disconnect: new_cmd then aux failure on an OPEN channel --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);
	g_kmalloc_budget = 0;			/* new_cmd fails -> ENOMEM */
	ATF_CHECK_EQ(ENOMEM, l2ca_discon_req(ch, NG_L2CAP_L2CA_IDTYPE_LE));
	g_kmalloc_budget = -1;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);
	g_mbuf_budget = 0;			/* discon_req PDU MGETHDR fails */
	ATF_CHECK_EQ(ENOBUFS, l2ca_discon_req(ch, NG_L2CAP_L2CA_IDTYPE_LE));
	g_mbuf_budget = -1;
	drain_tx(con);

	/* --- L2CA_Disconnect: channel in a non-disconnectable state --- */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);
	ch->state = NG_L2CAP_CLOSED;
	ATF_CHECK_EQ(EINVAL, l2ca_discon_req(ch, NG_L2CAP_L2CA_IDTYPE_LE));
	drain_tx(con);

	/* --- L2CA_EnableCLT: wrong argument length --- */
	reset_all();
	{
		ng_l2cap_l2ca_enable_clt_ip	ip;
		struct ng_mesg			*msg;

		memset(&ip, 0, sizeof(ip));
		msg = mk_l2ca_msg(0, &ip, sizeof(ip) - 1);
		ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_enable_clt(&g_l2cap, msg));
		(free)(msg);
	}
}

/* ====================================================================== */
/* Tractable reachable arms -- request validation & state machine          */
/* ====================================================================== */

/* Issue an L2CA_ConnectRsp (upper -> L2CAP accept/reject of an incoming con). */
static int
l2ca_con_rsp_req(u_int16_t lcid, u_int8_t linktype, u_int8_t ident,
    u_int16_t result)
{
	ng_l2cap_l2ca_con_rsp_ip	ip;
	struct ng_mesg			*msg;
	int				 err;

	memset(&ip, 0, sizeof(ip));
	bcopy(&g_addr, &ip.bdaddr, sizeof(ip.bdaddr));
	ip.ident = ident;
	ip.linktype = linktype;
	ip.lcid = lcid;
	ip.result = result;
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CON_RSP, &ip, sizeof(ip));
	err = ng_l2cap_l2ca_con_rsp_req(&g_l2cap, msg);
	(free)(msg);
	return (err);
}

/*
 * §4.2: L2CA_Connect request from the upper layer -- message-size reject, the
 * pre-connection LP_ConnectReq branch (and its error return), and the
 * channel/command/PDU allocation-failure arms.
 */
ATF_TC_WITHOUT_HEAD(con_req_validation_faults);
ATF_TC_BODY(con_req_validation_faults, tc)
{
	ng_l2cap_con_p	con;
	struct ng_mesg	*msg;
	ng_l2cap_l2ca_con_ip	ip;

	/* arglen mismatch -> EMSGSIZE */
	reset_all();
	memset(&ip, 0, sizeof(ip));
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_CON, &ip, sizeof(ip) - 1);
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_con_req(&g_l2cap, msg));
	(free)(msg);

	/* no con -> LP_ConnectReq creates it, connect proceeds */
	reset_all();
	g_lp_con_req_make = 1;
	ATF_CHECK_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_PSM_SDP, NG_HCI_LINK_ACL,
	    NG_L2CAP_L2CA_IDTYPE_BREDR));
	con = ng_l2cap_con_by_addr(&g_l2cap, &g_addr, NG_HCI_LINK_ACL);
	ATF_REQUIRE(con != NULL);
	drain_tx(con);

	/* no con -> LP_ConnectReq itself fails */
	reset_all();
	g_lp_con_req_err = EHOSTUNREACH;
	ATF_CHECK_EQ(EHOSTUNREACH, l2ca_con_req(BT_ASSIGNED_L2CAP_PSM_SDP,
	    NG_HCI_LINK_ACL, NG_L2CAP_L2CA_IDTYPE_BREDR));

	/* con exists: new_chan failure -> ENOMEM */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_kmalloc_budget = 0;
	ATF_CHECK_EQ(ENOMEM, l2ca_con_req(BT_ASSIGNED_L2CAP_PSM_SDP, NG_HCI_LINK_ACL,
	    NG_L2CAP_L2CA_IDTYPE_BREDR));
	g_kmalloc_budget = -1;
	drain_tx(con);

	/* con exists: new_cmd failure (new_chan ok) -> ENOMEM */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_kmalloc_budget = 1;			/* new_chan ok, new_cmd fails */
	ATF_CHECK_EQ(ENOMEM, l2ca_con_req(BT_ASSIGNED_L2CAP_PSM_SDP, NG_HCI_LINK_ACL,
	    NG_L2CAP_L2CA_IDTYPE_BREDR));
	g_kmalloc_budget = -1;
	drain_tx(con);

	/* con exists: PDU (aux) allocation failure -> ENOBUFS */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_mbuf_budget = 0;			/* con_req PDU MGETHDR fails */
	ATF_CHECK_EQ(ENOBUFS, l2ca_con_req(BT_ASSIGNED_L2CAP_PSM_SDP, NG_HCI_LINK_ACL,
	    NG_L2CAP_L2CA_IDTYPE_BREDR));
	g_mbuf_budget = -1;
	drain_tx(con);
}

/*
 * §4.3: L2CA_ConnectRsp request from the upper layer answering an incoming
 * L2CAP_ConnectReq.  Drives the fixed-CID reject, unknown-channel, wrong-state
 * and result (SUCCESS/PENDING/failure) arms plus the command/PDU faults.
 */
ATF_TC_WITHOUT_HEAD(con_rsp_req_paths);
ATF_TC_BODY(con_rsp_req_paths, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	p[4];
	u_int16_t	scid;

	/* Fixed CID (ATT) is never valid on this path -> EINVAL */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ATF_CHECK_EQ(EINVAL, l2ca_con_rsp_req(BT_CORE63_L2CAP_CID_ATT,
	    NG_HCI_LINK_ACL, 0x10, BT_CORE63_L2CAP_RESULT_SUCCESS));

	/* Unknown channel -> ENOENT */
	ATF_CHECK_EQ(ENOENT, l2ca_con_rsp_req(0x0050, NG_HCI_LINK_ACL,
	    0x11, BT_CORE63_L2CAP_RESULT_SUCCESS));
	drain_tx(con);

	/*
	 * Feed an incoming ConnectReq to create a channel in
	 * W4_L2CA_CON_RSP, then accept it with SUCCESS.
	 */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	w16(p, 0, BT_ASSIGNED_L2CAP_PSM_SDP);
	w16(p, 2, 0x0045);			/* peer scid (becomes dcid) */
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x20, p, 4);
	ch = LIST_FIRST(&g_l2cap.chan_list);
	ATF_REQUIRE(ch != NULL);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CA_CON_RSP, ch->state);
	scid = ch->scid;

	/* Wrong state: accept twice -- second time channel is CONFIG. */
	ATF_CHECK_EQ(0, l2ca_con_rsp_req(scid, NG_HCI_LINK_ACL, 0x20,
	    BT_CORE63_L2CAP_RESULT_SUCCESS));
	ATF_CHECK_EQ(NG_L2CAP_CONFIG, ch->state);
	ATF_CHECK_EQ(EINVAL, l2ca_con_rsp_req(scid, NG_HCI_LINK_ACL, 0x20,
	    BT_CORE63_L2CAP_RESULT_SUCCESS));
	drain_tx(con);

	/* PENDING keeps the channel in W4_L2CA_CON_RSP. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x21, p, 4);
	ch = LIST_FIRST(&g_l2cap.chan_list);
	ATF_REQUIRE(ch != NULL);
	scid = ch->scid;
	ATF_CHECK_EQ(0, l2ca_con_rsp_req(scid, NG_HCI_LINK_ACL, 0x21,
	    BT_CORE63_L2CAP_RESULT_PENDING));
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CA_CON_RSP, ch->state);
	drain_tx(con);

	/* A non-success result frees the channel (default arm). */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x22, p, 4);
	ch = LIST_FIRST(&g_l2cap.chan_list);
	ATF_REQUIRE(ch != NULL);
	scid = ch->scid;
	ATF_CHECK_EQ(0, l2ca_con_rsp_req(scid, NG_HCI_LINK_ACL, 0x22,
	    BT_CORE63_L2CAP_RESULT_NO_RESOURCES));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, scid,
	    NG_L2CAP_L2CA_IDTYPE_BREDR) == NULL);
	drain_tx(con);

	/* new_cmd failure on the accept path -> ENOMEM (channel freed). */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x23, p, 4);
	ch = LIST_FIRST(&g_l2cap.chan_list);
	ATF_REQUIRE(ch != NULL);
	scid = ch->scid;
	g_kmalloc_budget = 0;
	ATF_CHECK_EQ(ENOMEM, l2ca_con_rsp_req(scid, NG_HCI_LINK_ACL, 0x23,
	    BT_CORE63_L2CAP_RESULT_SUCCESS));
	g_kmalloc_budget = -1;
	drain_tx(con);

	/* PDU (aux) failure on the accept path -> ENOBUFS. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x24, p, 4);
	ch = LIST_FIRST(&g_l2cap.chan_list);
	ATF_REQUIRE(ch != NULL);
	scid = ch->scid;
	g_mbuf_budget = 0;
	ATF_CHECK_EQ(ENOBUFS, l2ca_con_rsp_req(scid, NG_HCI_LINK_ACL, 0x24,
	    BT_CORE63_L2CAP_RESULT_SUCCESS));
	g_mbuf_budget = -1;
	drain_tx(con);
}

/*
 * §2.1 fixed channels: ng_l2cap_l2ca_receive rewrites the destination CID to
 * the connection handle for the ATT (0x0004) and SMP (0x0006) fixed channels
 * and delivers the payload upstream with the idtype prefix, bypassing credit
 * reassembly.
 */
ATF_TC_WITHOUT_HEAD(receive_att_smp_fixed_channels);
ATF_TC_BODY(receive_att_smp_fixed_channels, tc)
{
	ng_l2cap_con_p	con;
	u_int8_t	pdu[4] = { 0xde, 0xad, 0xbe, 0xef };

	/* ATT fixed channel */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	(void)mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ATT, BT_CORE63_L2CAP_CID_ATT,
	    0, 0, 0, 0, 512, 512);
	ATF_CHECK_EQ(0, feed_data(con, BT_CORE63_L2CAP_CID_ATT, pdu, sizeof(pdu)));
	ATF_REQUIRE_EQ(1, g_ndata);
	ATF_CHECK_EQ(NG_L2CAP_L2CA_IDTYPE_ATT,
	    (u_int16_t)(g_data[0].data[0] | (g_data[0].data[1] << 8)));
	drain_tx(con);

	/* SMP fixed channel */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	(void)mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_SMP, BT_CORE63_L2CAP_CID_SMP,
	    0, 0, 0, 0, 512, 512);
	ATF_CHECK_EQ(0, feed_data(con, BT_CORE63_L2CAP_CID_SMP, pdu, sizeof(pdu)));
	ATF_REQUIRE_EQ(1, g_ndata);
	ATF_CHECK_EQ(NG_L2CAP_L2CA_IDTYPE_SMP,
	    (u_int16_t)(g_data[0].data[0] | (g_data[0].data[1] << 8)));
	drain_tx(con);
}

/*
 * §4.3: an incoming L2CAP_ConnectRsp with result PENDING starts the ERTX
 * timer and keeps the request pending; a following SUCCESS response then
 * completes the channel into CONFIG state.
 */
ATF_TC_WITHOUT_HEAD(con_rsp_pending_then_success);
ATF_TC_BODY(con_rsp_pending_then_success, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	ident;
	u_int8_t	p[8];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	/* Outbound BR/EDR connect -> queues CON_REQ, con_wakeup arms RTX. */
	ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_PSM_SDP, NG_HCI_LINK_ACL,
	    NG_L2CAP_L2CA_IDTYPE_BREDR));
	ch = LIST_FIRST(&g_l2cap.chan_list);
	ATF_REQUIRE(ch != NULL);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_CON_RSP, ch->state);
	ident = first_cmd_ident(con);
	ATF_CHECK_EQ(1, callouts_pending());		/* RTX armed */

	/* ConnectRsp PENDING: dcid=dcid, scid=ch->scid -> ERTX re-armed. */
	w16(p, 0, 0x0055);				/* dcid */
	w16(p, 2, ch->scid);				/* scid */
	w16(p, 4, BT_CORE63_L2CAP_RESULT_PENDING);
	w16(p, 6, 0);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, ident, p, 8);
	ATF_CHECK_EQ(1, callouts_pending());		/* ERTX pending */
	ATF_CHECK_EQ(0x0055, ch->dcid);

	/* ConnectRsp SUCCESS: completes channel to CONFIG. */
	w16(p, 4, BT_CORE63_L2CAP_RESULT_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, ident, p, 8);
	ATF_CHECK_EQ(NG_L2CAP_CONFIG, ch->state);
	drain_tx(con);
}

/*
 * §4.27: L2CA_Reconfig request from the upper layer -- message-size reject,
 * the below-minimum parameter reject, and the command/PDU allocation faults.
 */
ATF_TC_WITHOUT_HEAD(reconfig_req_more_arms);
ATF_TC_BODY(reconfig_req_more_arms, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	struct ng_mesg	*msg;
	ng_l2cap_l2ca_reconfig_ip	ip;

	/* arglen mismatch -> EMSGSIZE */
	reset_all();
	memset(&ip, 0, sizeof(ip));
	msg = mk_l2ca_msg(NGM_L2CAP_L2CA_RECONFIG, &ip, sizeof(ip) - 1);
	ATF_CHECK_EQ(EMSGSIZE, ng_l2cap_l2ca_reconfig_req(&g_l2cap, msg));
	(free)(msg);

	/* mps below the ECBFC minimum (mtu kept >= imtu) -> EINVAL */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0041,
	    247, 247, 5, 5, 0, 512);
	ATF_CHECK_EQ(EINVAL, l2ca_reconfig(ch, BT_CORE63_L2CAP_MTU_MIN_ECREDIT, 1));
	drain_tx(con);

	/* new_cmd failure on a valid request -> ENOMEM */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0041,
	    247, 247, 5, 5, 0, 512);
	g_kmalloc_budget = 0;
	ATF_CHECK_EQ(ENOMEM, l2ca_reconfig(ch, 200, 200));
	g_kmalloc_budget = -1;
	drain_tx(con);

	/* PDU (aux) failure on a valid request -> ENOBUFS */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0041,
	    247, 247, 5, 5, 0, 512);
	g_mbuf_budget = 0;
	ATF_CHECK_EQ(ENOBUFS, l2ca_reconfig(ch, 200, 200));
	g_mbuf_budget = -1;
	drain_tx(con);
}

/*
 * §2.1: L2CA encryption-change notification builds its op with an idtype/lcid
 * that depends on channel kind: con_handle for the ATT/SMP fixed channels,
 * scid for dynamic BR/EDR / LE channels.
 */
ATF_TC_WITHOUT_HEAD(encryption_change_idtypes);
ATF_TC_BODY(encryption_change_idtypes, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ATT, BT_CORE63_L2CAP_CID_ATT,
	    0, 0, 0, 0, 512, 512);
	ATF_CHECK_EQ(0, ng_l2cap_l2ca_encryption_change(ch, 0));
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_SMP, BT_CORE63_L2CAP_CID_SMP,
	    0, 0, 0, 0, 512, 512);
	ATF_CHECK_EQ(0, ng_l2cap_l2ca_encryption_change(ch, 0));
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);
	ATF_CHECK_EQ(0, ng_l2cap_l2ca_encryption_change(ch, 0));
	drain_tx(con);
}

/*
 * §4.6: an incoming L2CAP_DisconnectReq whose response PDU cannot be
 * allocated takes the cmd->aux == NULL arm (the channel is already torn
 * down at that point).
 */
ATF_TC_WITHOUT_HEAD(discon_req_rsp_alloc_fail);
ATF_TC_BODY(discon_req_rsp_alloc_fail, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	p[4];

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0055,
	    0, 0, 0, 0, 672, 672);
	w16(p, 0, ch->scid);			/* dcid: channel to close */
	w16(p, 2, ch->dcid);			/* scid: peer's CID */
	g_mbuf_budget = 1;			/* rx ok, DisconRsp aux fails */
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, 0x30, p, 4);
	g_mbuf_budget = -1;
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, 0x0055,
	    NG_L2CAP_L2CA_IDTYPE_BREDR) == NULL);
	drain_tx(con);
}

/*
 * Every "send to the upper/control layer" primitive first checks that its
 * outbound hook (l2c for data/confirmations, ctl for ping/get_info) is
 * connected and valid, returning ENOTCONN otherwise.  Driving each with the
 * hook detached covers that guard arm across the whole family.
 */
ATF_TC_WITHOUT_HEAD(upper_hook_enotconn);
ATF_TC_BODY(upper_hook_enotconn, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);

	g_l2cap.l2c = NULL;			/* data/confirmation hook down */
	g_l2cap.ctl = NULL;			/* control hook down */

	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_con_rsp(ch, 0, 0, 0));
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_con_rsp_rsp(ch, 0, 0));
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_cfg_rsp(ch, 0, 0));
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_cfg_rsp_rsp(ch, 0, 0));
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_discon_rsp(ch, 0, 0));
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_write_rsp(ch, 0, 0, 0));
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_con_ind(ch));
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_cfg_ind(ch));
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_qos_ind(ch));
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_discon_ind(ch));
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_encryption_change(ch, 0));
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_ping_rsp(con, 0, 0, NULL));
	ATF_CHECK_EQ(ENOTCONN, ng_l2cap_l2ca_get_info_rsp(con, 0, 0, NULL));

	drain_tx(con);
}

/*
 * §4.8/§4.10: L2CA_Ping and L2CA_GetInfo responses that actually carry echo /
 * info payload exercise the "data != NULL && size > 0" copy-back branches.
 */
ATF_TC_WITHOUT_HEAD(ping_get_info_rsp_with_data);
ATF_TC_BODY(ping_get_info_rsp_with_data, tc)
{
	ng_l2cap_con_p	con;
	struct mbuf	*d;

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	g_l2cap.ctl = (hook_p)&g_l2cap;		/* control hook up */

	d = ng_mbuf_alloc();
	ATF_REQUIRE(d != NULL);
	d->m_len = d->m_pkthdr.len = 8;
	memset(d->m_data, 0xa5, 8);
	ATF_CHECK_EQ(0, ng_l2cap_l2ca_ping_rsp(con, 0x99, BT_CORE63_L2CAP_RESULT_SUCCESS, d));

	d = ng_mbuf_alloc();
	ATF_REQUIRE(d != NULL);
	d->m_len = d->m_pkthdr.len = 8;
	memset(d->m_data, 0x5a, 8);
	ATF_CHECK_EQ(0, ng_l2cap_l2ca_get_info_rsp(con, 0x99,
	    BT_CORE63_L2CAP_RESULT_SUCCESS, d));

	drain_tx(con);
}

/*
 * §3.4.3 / §10.1: the receive-side credit data-plane disconnect triggers --
 * a K-frame arriving with zero local credits, a K-frame whose payload exceeds
 * local MPS, a first K-frame whose declared SDU length exceeds the channel
 * MTU, and an SDU reassembly that overflows the declared length.  Each SHALL
 * disconnect the channel.
 */
ATF_TC_WITHOUT_HEAD(receive_credit_disconnects);
ATF_TC_BODY(receive_credit_disconnects, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	buf[32];

	memset(buf, 0, sizeof(buf));

	/* Zero local credits -> EPROTO, channel disconnected. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    23, 23, 0, 5, 512, 512);		/* credits_local = 0 */
	ATF_CHECK_EQ(EPROTO, feed_data(con, ch->scid, buf, 6));
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, 0x0041,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);
	drain_tx(con);

	/* K-frame payload exceeds local MPS -> EMSGSIZE, disconnected. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    23, 23, 5, 5, 512, 512);		/* mps_local = 23 */
	ATF_CHECK_EQ(EMSGSIZE, feed_data(con, ch->scid, buf, 30));
	drain_tx(con);

	/* First-frame SDU length exceeds channel MTU -> EMSGSIZE. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    23, 23, 5, 5, 10, 512);		/* imtu = 10 */
	w16(buf, 0, 1000);			/* SDU-Length far above imtu */
	ATF_CHECK_EQ(EMSGSIZE, feed_data(con, ch->scid, buf, 8));
	drain_tx(con);

	/* Overflow wholly within the first K-frame -> EMSGSIZE. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    23, 23, 5, 5, 512, 512);
	w16(buf, 0, 4);				/* declare four SDU octets */
	ATF_CHECK_EQ(EMSGSIZE, feed_data(con, ch->scid, buf, 8)); /* supply six */
	ATF_CHECK(ng_l2cap_chan_by_scid(&g_l2cap, 0x0041,
	    NG_L2CAP_L2CA_IDTYPE_LE) == NULL);
	drain_tx(con);

	/* SDU reassembly overflow across two K-frames -> EMSGSIZE. */
	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    23, 23, 5, 5, 512, 512);
	w16(buf, 0, 4);				/* declare SDU-Length 4 */
	ATF_CHECK_EQ(0, feed_data(con, ch->scid, buf, 4));  /* got 2, want 4 */
	memset(buf, 0, sizeof(buf));
	ATF_CHECK_EQ(EMSGSIZE, feed_data(con, ch->scid, buf, 10)); /* overflow */
	drain_tx(con);
}

/*
 * §2.1: BR/EDR dynamic-channel receive (non credit-based) -- successful
 * upstream delivery with the BR/EDR idtype, the over-MTU reject, and the
 * disconnected-hook reject.
 */
ATF_TC_WITHOUT_HEAD(receive_bredr_and_hook);
ATF_TC_BODY(receive_bredr_and_hook, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int8_t	pdu[16];

	memset(pdu, 0x33, sizeof(pdu));

	/* Successful BR/EDR delivery (mps_local == 0 -> no credit path). */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0055,
	    0, 0, 0, 0, 672, 672);
	ATF_CHECK_EQ(0, feed_data(con, ch->scid, pdu, 8));
	ATF_REQUIRE_EQ(1, g_ndata);
	ATF_CHECK_EQ(NG_L2CAP_L2CA_IDTYPE_BREDR,
	    (u_int16_t)(g_data[0].data[0] | (g_data[0].data[1] << 8)));
	drain_tx(con);

	/* Payload larger than imtu -> EMSGSIZE. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0055,
	    0, 0, 0, 0, 10, 672);		/* imtu = 10 */
	ATF_CHECK_EQ(EMSGSIZE, feed_data(con, ch->scid, pdu, 12));
	drain_tx(con);

	/* Upstream data hook detached -> ENOTCONN. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0055,
	    0, 0, 0, 0, 672, 672);
	g_l2cap.l2c = NULL;
	ATF_CHECK_EQ(ENOTCONN, feed_data(con, ch->scid, pdu, 8));
	drain_tx(con);
}

/*
 * Table 4.2: the Enhanced Credit Based signalling codes are valid on the
 * BR/EDR signalling CID 0x0001 as well as the LE CID 0x0005.  Driving an
 * ECBFC Connect and Reconfigure over a BR/EDR (ACL) link exercises the
 * "linktype == ACL -> SIGNAL_CID" side of con_wakeup's CID selection, which
 * the LE-only credit tests never reach.
 */
ATF_TC_WITHOUT_HEAD(con_wakeup_bredr_credit_dispatch);
ATF_TC_BODY(con_wakeup_bredr_credit_dispatch, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;

	/* ECBFC Connect Request dispatched over BR/EDR SIGNAL_CID. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_SPSM_EATT, NG_HCI_LINK_ACL,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC));
	ATF_CHECK(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CID_SIGNAL, g_frames[0].dcid);
	drain_tx(con);

	/* ECBFC Reconfigure Request dispatched over BR/EDR SIGNAL_CID. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_ECBFC, 0x0055,
	    247, 247, 5, 5, 0, 512);
	ATF_REQUIRE_EQ(0, l2ca_reconfig(ch, 200, 200));
	ATF_CHECK(g_nframes >= 1);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CID_SIGNAL, g_frames[0].dcid);
	drain_tx(con);
}

/*
 * Companion to upper_hook_enotconn: the hook is UP but the netgraph message
 * allocation (NG_MKMESSAGE) fails, driving the "msg == NULL -> ENOMEM" arm
 * that every *_rsp / *_ind confirmation carries.
 */
ATF_TC_WITHOUT_HEAD(upper_msg_alloc_fail);
ATF_TC_BODY(upper_msg_alloc_fail, tc)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;

	reset_all();
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_LE, 0x0041,
	    247, 23, 65, 5, 512, 512);
	g_l2cap.ctl = (hook_p)&g_l2cap;		/* both hooks UP */

	g_mkmsg_budget = 0;			/* every NG_MKMESSAGE fails */
	ATF_CHECK_EQ(ENOMEM, ng_l2cap_l2ca_con_rsp(ch, 0, 0, 0));
	ATF_CHECK_EQ(ENOMEM, ng_l2cap_l2ca_con_rsp_rsp(ch, 0, 0));
	ATF_CHECK_EQ(ENOMEM, ng_l2cap_l2ca_cfg_rsp(ch, 0, 0));
	ATF_CHECK_EQ(ENOMEM, ng_l2cap_l2ca_cfg_rsp_rsp(ch, 0, 0));
	ATF_CHECK_EQ(ENOMEM, ng_l2cap_l2ca_discon_rsp(ch, 0, 0));
	ATF_CHECK_EQ(ENOMEM, ng_l2cap_l2ca_write_rsp(ch, 0, 0, 0));
	ATF_CHECK_EQ(ENOMEM, ng_l2cap_l2ca_con_ind(ch));
	ATF_CHECK_EQ(ENOMEM, ng_l2cap_l2ca_cfg_ind(ch));
	ATF_CHECK_EQ(ENOMEM, ng_l2cap_l2ca_qos_ind(ch));
	ATF_CHECK_EQ(ENOMEM, ng_l2cap_l2ca_discon_ind(ch));
	ATF_CHECK_EQ(ENOMEM, ng_l2cap_l2ca_encryption_change(ch, 0));
	ATF_CHECK_EQ(ENOMEM, ng_l2cap_l2ca_ping_rsp(con, 0, 0, NULL));
	ATF_CHECK_EQ(ENOMEM, ng_l2cap_l2ca_get_info_rsp(con, 0, 0, NULL));
	g_mkmsg_budget = -1;

	drain_tx(con);
}

ATF_TC_WITHOUT_HEAD(misc_and_timeout_guard_edges);
ATF_TC_BODY(misc_and_timeout_guard_edges, tc)
{
	ng_l2cap_con_p con;
	ng_l2cap_cmd_p cmd;
	struct mbuf *m;
	int arg;

	reset_all();

	/* HOOK_INFO allocation failure follows its explicit ENOMEM arm. */
	g_l2cap.hci = (hook_p)&g_l2cap;
	g_l2cap.bdaddr = g_addr;
	g_mkmsg_budget = 0;
	ng_l2cap_send_hook_info(g_l2cap.node, g_l2cap.l2c, NULL, 0);
	ATF_CHECK_EQ(0, g_nmsg);
	g_mkmsg_budget = -1;

	/* Connection descriptor allocation failure is non-destructive. */
	g_kmalloc_budget = 0;
	ATF_CHECK(ng_l2cap_new_con(&g_l2cap, &g_addr,
	    NG_HCI_LINK_ACL) == NULL);
	g_kmalloc_budget = -1;

	/* Timeout delivery rejects an invalid node, handle, then identifier. */
	ng_l2cap_process_command_timeout(NULL, NULL, NULL, 0);
	ng_l2cap_process_command_timeout(g_l2cap.node, NULL, NULL, 0x1234);
	con = mk_con(NG_HCI_LINK_ACL, 1);
	arg = (0x55 << 16) | con->con_handle;
	ng_l2cap_process_command_timeout(g_l2cap.node, NULL, NULL, arg);

	/* Command timers reject no-arm, duplicate-arm, and already-fired states. */
	cmd = ng_l2cap_new_cmd(con, NULL, 0x55, BT_CORE63_L2CAP_CMD_ECHO_REQ, 0);
	ATF_REQUIRE(cmd != NULL);
	ATF_CHECK_EQ(0, ng_l2cap_command_untimeout(cmd));
	ATF_CHECK_EQ(0, ng_l2cap_command_timeout(cmd, 3));
	ATF_CHECK_EQ(0, ng_l2cap_command_timeout(cmd, 3));
	cmd->timo.c_pending = 0;
	ATF_CHECK_EQ(ETIMEDOUT, ng_l2cap_command_untimeout(cmd));
	cmd->flags &= ~NG_L2CAP_CMD_PENDING;
	callout_forget(&cmd->timo);
	ng_l2cap_free_cmd(cmd);

	/* Wakeup consumes terminal parameter-update and unknown commands. */
	cmd = ng_l2cap_new_cmd(con, NULL, 0x56,
	    BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ, 0);
	ATF_REQUIRE(cmd != NULL);
	m = ng_mbuf_alloc(); ATF_REQUIRE(m != NULL);
	m->m_len = m->m_pkthdr.len = 1; cmd->aux = m;
	ng_l2cap_link_cmd(con, cmd);
	ng_l2cap_con_wakeup(con);
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));
	cmd = ng_l2cap_new_cmd(con, NULL, 0x57, 0xff, 0);
	ATF_REQUIRE(cmd != NULL);
	m = ng_mbuf_alloc(); ATF_REQUIRE(m != NULL);
	m->m_len = m->m_pkthdr.len = 1; cmd->aux = m;
	ng_l2cap_link_cmd(con, cmd);
	ng_l2cap_con_wakeup(con);
	ATF_CHECK(TAILQ_EMPTY(&con->cmd_list));

	/* free_con cancels and frees a still-pending command itself. */
	cmd = ng_l2cap_new_cmd(con, NULL, 0x58, BT_CORE63_L2CAP_CMD_ECHO_REQ, 0);
	ATF_REQUIRE(cmd != NULL);
	ng_l2cap_link_cmd(con, cmd);
	ATF_REQUIRE_EQ(0, ng_l2cap_command_timeout(cmd, 3));
	ng_l2cap_free_con(con);
	ATF_CHECK(LIST_EMPTY(&g_l2cap.con_list));

	/* con_fail accepts terminal credit/update commands and unknown codes. */
	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	for (int code = 0; code < 4; code++) {
		static const uint8_t codes[] = { BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT,
		    BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ,
		    BT_CORE63_L2CAP_CMD_PARAM_UPDATE_RSP, 0xff };

		cmd = ng_l2cap_new_cmd(con, NULL, (uint8_t)(0x60 + code),
		    codes[code], 0);
		ATF_REQUIRE(cmd != NULL);
		ng_l2cap_link_cmd(con, cmd);
	}
	ng_l2cap_con_fail(con, NG_L2CAP_TIMEOUT);
	ATF_CHECK(LIST_EMPTY(&g_l2cap.con_list));
}

ATF_TC_WITHOUT_HEAD(fixed_channel_upper_write_and_response);
ATF_TC_BODY(fixed_channel_upper_write_and_response, tc)
{
	static const struct {
		uint16_t cid;
		uint16_t idtype;
	} cases[] = {
		{ BT_CORE63_L2CAP_CID_ATT, NG_L2CAP_L2CA_IDTYPE_ATT },
		{ BT_CORE63_L2CAP_CID_SMP, NG_L2CAP_L2CA_IDTYPE_SMP },
	};
	ng_l2cap_con_p con;
	ng_l2cap_chan_p ch;
	ng_l2cap_l2ca_hdr_t *h;
	struct mbuf *m;

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		reset_all();
		con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
		ch = ng_l2cap_new_chan(&g_l2cap, con, 0, cases[i].idtype);
		ATF_REQUIRE(ch != NULL);
		ch->scid = cases[i].cid;
		ch->dcid = cases[i].cid;
		ch->state = NG_L2CAP_OPEN;
		ch->imtu = ch->omtu = 512;

		ATF_CHECK_EQ(0, ng_l2cap_l2ca_con_rsp(ch, 0x1234,
		    BT_CORE63_L2CAP_RESULT_SUCCESS, 0));

		m = ng_mbuf_alloc();
		ATF_REQUIRE(m != NULL);
		h = (ng_l2cap_l2ca_hdr_t *)m->m_data;
		memset(h, 0, sizeof(*h));
		h->token = 0x5678;
		h->length = 1;
		h->lcid = con->con_handle;
		h->idtype = cases[i].idtype;
		m->m_data[sizeof(*h)] = 0xaa;
		m->m_len = m->m_pkthdr.len = sizeof(*h) + 1;
		ATF_CHECK_EQ(0, ng_l2cap_l2ca_write_req(&g_l2cap, m));
		ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, g_write_result);
		drain_tx(con);
	}
}

/* Complete the classic response-side reject and option matrices. */
ATF_TC_WITHOUT_HEAD(classic_response_error_completion);
ATF_TC_BODY(classic_response_error_completion, tc)
{
	ng_l2cap_con_p con;
	ng_l2cap_chan_p ch;
	u_int8_t ident, p[40];
	u_int16_t scid, dcid;

	/* A response without a pending Connection Request is ignored. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	memset(p, 0, 8);
	w16(p, 0, 0x0055);
	w16(p, 2, 0x0040);
	w16(p, 4, BT_CORE63_L2CAP_RESULT_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, 0x70, p, 8);
	drain_tx(con);

	/* Invalid channel state and mismatched SCID each produce a reject. */
	for (int arm = 0; arm < 2; arm++) {
		reset_all();
		con = mk_con(NG_HCI_LINK_ACL, 1);
		ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_PSM_SDP,
		    NG_HCI_LINK_ACL, NG_L2CAP_L2CA_IDTYPE_BREDR));
		ch = LIST_FIRST(&g_l2cap.chan_list);
		ATF_REQUIRE(ch != NULL);
		ident = first_cmd_ident(con);
		memset(p, 0, 8);
		w16(p, 0, 0x0055);
		w16(p, 2, arm == 0 ? ch->scid : (u_int16_t)(ch->scid + 1));
		w16(p, 4, BT_CORE63_L2CAP_RESULT_SUCCESS);
		if (arm == 0)
			ch->state = NG_L2CAP_OPEN;
		feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, ident,
		    p, 8);
		drain_tx(con);
	}

	/* Dynamic CIDs below 0x0040 are invalid for pending and success. */
	for (int arm = 0; arm < 2; arm++) {
		reset_all();
		con = mk_con(NG_HCI_LINK_ACL, 1);
		ATF_REQUIRE_EQ(0, l2ca_con_req(BT_ASSIGNED_L2CAP_PSM_SDP,
		    NG_HCI_LINK_ACL, NG_L2CAP_L2CA_IDTYPE_BREDR));
		ch = LIST_FIRST(&g_l2cap.chan_list);
		ATF_REQUIRE(ch != NULL);
		ident = first_cmd_ident(con);
		memset(p, 0, 8);
		w16(p, 0, 1);
		w16(p, 2, ch->scid);
		w16(p, 4, arm == 0 ? BT_CORE63_L2CAP_RESULT_PENDING : BT_CORE63_L2CAP_RESULT_SUCCESS);
		feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, ident,
		    p, 8);
		drain_tx(con);
	}

	/* Exercise every successfully parsed ConfigRsp option selector, then an
	 * invalid-state reject and an upstream-delivery failure. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ident = setup_pending_cfg_req(con, &ch);
	w16(p, 0, ch->scid); w16(p, 2, 0); w16(p, 4, BT_CORE63_L2CAP_RESULT_SUCCESS);
	p[6] = BT_CORE63_L2CAP_OPTION_FLUSH_TIMEOUT; p[7] = NG_L2CAP_OPT_FLUSH_TIMO_SIZE;
	w16(p, 8, 0x1234);
	p[10] = BT_CORE63_L2CAP_OPTION_QOS; p[11] = NG_L2CAP_OPT_QOS_SIZE;
	memset(p + 12, 0x11, NG_L2CAP_OPT_QOS_SIZE);
	p[12 + NG_L2CAP_OPT_QOS_SIZE] = 0x80 | 0x7e; /* unknown hint */
	p[13 + NG_L2CAP_OPT_QOS_SIZE] = 0;
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, ident, p,
	    14 + NG_L2CAP_OPT_QOS_SIZE);
	ATF_CHECK_EQ(0x1234, ch->flush_timo);
	drain_tx(con);

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ident = setup_pending_cfg_req(con, &ch);
	ch->state = NG_L2CAP_OPEN;
	w16(p, 0, ch->scid); w16(p, 2, 0); w16(p, 4, BT_CORE63_L2CAP_RESULT_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, ident, p, 6);
	drain_tx(con);

	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	ident = setup_pending_cfg_req(con, &ch);
	g_l2cap.l2c = NULL;
	w16(p, 0, ch->scid); w16(p, 2, 0); w16(p, 4, BT_CORE63_L2CAP_RESULT_SUCCESS);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, ident, p, 6);
	drain_tx(con);

	/* Disconnect responses reject absent commands, bad state and bad CIDs. */
	reset_all();
	con = mk_con(NG_HCI_LINK_ACL, 1);
	w16(p, 0, 0x0055); w16(p, 2, 0x0040);
	feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_RSP, 0x71, p, 4);
	drain_tx(con);

	for (int arm = 0; arm < 2; arm++) {
		reset_all();
		con = mk_con(NG_HCI_LINK_ACL, 1);
		ch = mk_open_chan(con, NG_L2CAP_L2CA_IDTYPE_BREDR, 0x0055,
		    0, 0, 0, 0, 672, 672);
		scid = ch->scid; dcid = ch->dcid;
		ATF_REQUIRE_EQ(0, l2ca_discon_req(ch,
		    NG_L2CAP_L2CA_IDTYPE_BREDR));
		ident = first_cmd_ident(con);
		w16(p, 0, arm == 0 ? dcid : (u_int16_t)(dcid + 1));
		w16(p, 2, scid);
		if (arm == 0)
			ch->state = NG_L2CAP_OPEN;
		feed_sig(con, BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_RSP, ident,
		    p, 4);
		drain_tx(con);
	}
}

/* ====================================================================== */

ATF_TP_ADD_TCS(tp)
{

	/* m_pullup() failure arms */
	ATF_TP_ADD_TC(tp, pullup_fail_framing);
	ATF_TP_ADD_TC(tp, pullup_fail_bredr_decoders);
	ATF_TP_ADD_TC(tp, pullup_fail_le_decoders);
	ATF_TP_ADD_TC(tp, pullup_fail_data_paths);

	/* response-PDU allocation failure arms */
	ATF_TP_ADD_TC(tp, alloc_fail_send_helpers);
	ATF_TP_ADD_TC(tp, alloc_fail_info_req);
	ATF_TP_ADD_TC(tp, alloc_fail_le_coc_success_rsp);
	ATF_TP_ADD_TC(tp, alloc_fail_request_paths);

	/* tractable reachable request/state-machine arms */
	ATF_TP_ADD_TC(tp, con_req_validation_faults);
	ATF_TP_ADD_TC(tp, con_rsp_req_paths);
	ATF_TP_ADD_TC(tp, receive_att_smp_fixed_channels);
	ATF_TP_ADD_TC(tp, con_rsp_pending_then_success);
	ATF_TP_ADD_TC(tp, reconfig_req_more_arms);
	ATF_TP_ADD_TC(tp, encryption_change_idtypes);
	ATF_TP_ADD_TC(tp, discon_req_rsp_alloc_fail);
	ATF_TP_ADD_TC(tp, upper_hook_enotconn);
	ATF_TP_ADD_TC(tp, upper_msg_alloc_fail);
	ATF_TP_ADD_TC(tp, misc_and_timeout_guard_edges);
	ATF_TP_ADD_TC(tp, fixed_channel_upper_write_and_response);
	ATF_TP_ADD_TC(tp, classic_response_error_completion);
	ATF_TP_ADD_TC(tp, ping_get_info_rsp_with_data);
	ATF_TP_ADD_TC(tp, receive_credit_disconnects);
	ATF_TP_ADD_TC(tp, receive_bredr_and_hook);
	ATF_TP_ADD_TC(tp, con_wakeup_bredr_credit_dispatch);

	/* TX segmentation size classes */
	ATF_TP_ADD_TC(tp, tx_zero_length_sdu);
	ATF_TP_ADD_TC(tp, tx_exactly_mps_single_frame);
	ATF_TP_ADD_TC(tp, tx_mps_plus_one_two_frames);
	ATF_TP_ADD_TC(tp, tx_many_frames_credit_decrement);
	ATF_TP_ADD_TC(tp, tx_omtu_boundary);
	ATF_TP_ADD_TC(tp, tx_sequential_writes_chaining);
	ATF_TP_ADD_TC(tp, tx_mps_below_two_einval);
	ATF_TP_ADD_TC(tp, tx_wrong_state_ehostdown);
	ATF_TP_ADD_TC(tp, tx_unknown_channel_enoent);
	ATF_TP_ADD_TC(tp, tx_lcid_too_small_einval);
	ATF_TP_ADD_TC(tp, tx_length_mismatch_emsgsize);
	ATF_TP_ADD_TC(tp, tx_header_too_small_emsgsize);
	ATF_TP_ADD_TC(tp, tx_lp_send_fail_no_resources);
	ATF_TP_ADD_TC(tp, tx_bredr_non_coc_write);
	ATF_TP_ADD_TC(tp, tx_clt_broadcast_write);

	/* RX reassembly size classes */
	ATF_TP_ADD_TC(tp, rx_single_frame_complete);
	ATF_TP_ADD_TC(tp, rx_exact_mtu_accepted);
	ATF_TP_ADD_TC(tp, rx_many_kframes_reassembled);
	ATF_TP_ADD_TC(tp, rx_first_kframe_too_short_disconnects);
	ATF_TP_ADD_TC(tp, rx_replenish_exact_value);
	ATF_TP_ADD_TC(tp, rx_wrong_state_ehostdown);
	ATF_TP_ADD_TC(tp, rx_unknown_channel_enoent);

	/* ECRED per-channel accounting + reconfigure */
	ATF_TP_ADD_TC(tp, ecred_per_channel_independent_credits);
	ATF_TP_ADD_TC(tp, reconfig_req_queues_command);
	ATF_TP_ADD_TC(tp, reconfig_req_validation);
	ATF_TP_ADD_TC(tp, reconfig_req_concurrent_ebusy);
	ATF_TP_ADD_TC(tp, reconfig_initiator_applies_on_success);
	ATF_TP_ADD_TC(tp, reconfig_incoming_changes_tx_segmentation);
	ATF_TP_ADD_TC(tp, reconfig_incoming_unencrypted_rejected);

	/* State machine */
	ATF_TP_ADD_TC(tp, sm_outbound_bredr_connect_config);
	ATF_TP_ADD_TC(tp, sm_disconnect_req_then_rsp);

	/* RTX/ERTX guard timers */
	ATF_TP_ADD_TC(tp, rtx_cfg_req_timeout);
	ATF_TP_ADD_TC(tp, rtx_discon_req_timeout_frees);
	ATF_TP_ADD_TC(tp, rtx_ping_req_timeout);
	ATF_TP_ADD_TC(tp, rtx_get_info_req_timeout);

	/* Inbound accept / config-rsp / connection failure */
	ATF_TP_ADD_TC(tp, con_rsp_req_accept);
	ATF_TP_ADD_TC(tp, cfg_rsp_req_completes_out);
	ATF_TP_ADD_TC(tp, con_fail_flushes_all_commands);

	/* Connect fan-out + CLT + enable */
	ATF_TP_ADD_TC(tp, con_req_idtype_fan_out);
	ATF_TP_ADD_TC(tp, con_req_lp_send_failure_frees_channel);
	ATF_TP_ADD_TC(tp, clt_receive_and_enable_gate);
	ATF_TP_ADD_TC(tp, clt_receive_rejection_matrix);
	ATF_TP_ADD_TC(tp, cfg_request_fault_completion);
	ATF_TP_ADD_TC(tp, credit_and_fixed_channel_fault_completion);
	ATF_TP_ADD_TC(tp, clt_on_le_link_dropped);
	ATF_TP_ADD_TC(tp, enable_clt_all_selectors);

	/* LE Credit Based (0x14/0x15) signalling -- Vol 3 Part A §4.22 */
	ATF_TP_ADD_TC(tp, le_coc_con_req_success);
	ATF_TP_ADD_TC(tp, le_coc_con_req_reject_params_scid);
	ATF_TP_ADD_TC(tp, le_coc_con_req_reject_spsm_enc);
	ATF_TP_ADD_TC(tp, le_coc_con_rsp_success);
	ATF_TP_ADD_TC(tp, le_coc_con_rsp_failure_and_invalid);

	/* Enhanced Credit Based (0x17/0x18) signalling -- Vol 3 Part A §4.25 */
	ATF_TP_ADD_TC(tp, ecbfc_con_req_success_multi);
	ATF_TP_ADD_TC(tp, ecbfc_con_req_reject_arms);
	ATF_TP_ADD_TC(tp, ecbfc_con_req_bad_cid_list);
	ATF_TP_ADD_TC(tp, ecbfc_con_rsp_success);
	ATF_TP_ADD_TC(tp, ecbfc_con_rsp_error_arms);

	/* Flow Control Credit (0x16) -- Vol 3 Part A §4.24 / §10.1 */
	ATF_TP_ADD_TC(tp, flow_credit_zero_and_unknown_ignored);
	ATF_TP_ADD_TC(tp, flow_credit_overflow_disconnects);
	ATF_TP_ADD_TC(tp, flow_credit_max_no_disconnect);
	ATF_TP_ADD_TC(tp, flow_credit_max_plus_one_disconnects);
	ATF_TP_ADD_TC(tp, flow_credit_bredr_replenish);
	ATF_TP_ADD_TC(tp, tx_mid_sdu_credit_exhaustion_stalls);

	/* Credit Based Reconfigure (0x19/0x1A) -- Vol 3 Part A §4.27 */
	ATF_TP_ADD_TC(tp, reconfig_req_result_arms);
	ATF_TP_ADD_TC(tp, reconfig_req_too_many_dcids);
	ATF_TP_ADD_TC(tp, reconfig_req_mps_reduction_multi);
	ATF_TP_ADD_TC(tp, reconfig_req_bad_list_len);
	ATF_TP_ADD_TC(tp, reconfig_rsp_failure_and_mismatch);

	/* cmds.c dispatch: lp_send-failure + RTX timeout + con_fail fan-out */
	ATF_TP_ADD_TC(tp, con_wakeup_lp_send_failures);
	ATF_TP_ADD_TC(tp, command_timeout_fan_out);
	ATF_TP_ADD_TC(tp, con_fail_credit_and_rsp_codes);

	/* Allocation-failure (fault injection) reject arms */
	ATF_TP_ADD_TC(tp, fault_alloc_le_credit_con_req);
	ATF_TP_ADD_TC(tp, fault_alloc_ecbfc_con_req);

	/* ulpi.c L2CA_* request validation rejects */
	ATF_TP_ADD_TC(tp, ulpi_request_validation_rejects);

	/* BR/EDR classic ConnectReq -- Vol 3 Part A §4.2 */
	ATF_TP_ADD_TC(tp, bredr_con_req_success);
	ATF_TP_ADD_TC(tp, bredr_con_req_invalid_scid);
	ATF_TP_ADD_TC(tp, bredr_con_req_att_cid);
	ATF_TP_ADD_TC(tp, bredr_con_req_ind_failure);

	/* BR/EDR classic Config Req/Rsp + option TLV parser -- §4.4/4.5/5 */
	ATF_TP_ADD_TC(tp, bredr_cfg_req_mtu_option);
	ATF_TP_ADD_TC(tp, bredr_cfg_req_flush_qos_hint);
	ATF_TP_ADD_TC(tp, bredr_cfg_req_cflag_empty_rsp);
	ATF_TP_ADD_TC(tp, bredr_cfg_req_option_reject_arms);
	ATF_TP_ADD_TC(tp, bredr_cfg_req_reject_cid_state);
	ATF_TP_ADD_TC(tp, bredr_cfg_rsp_success);
	ATF_TP_ADD_TC(tp, bredr_cfg_rsp_cflag_waits);
	ATF_TP_ADD_TC(tp, bredr_cfg_rsp_error_arms);

	/* BR/EDR classic Disconnect / Echo / Info / CommandReject -- §4.6-4.12 */
	ATF_TP_ADD_TC(tp, receive_outer_framing_matrix);
	ATF_TP_ADD_TC(tp, acl_continuation_length_mismatch_drops_reassembly);
	ATF_TP_ADD_TC(tp, bredr_discon_req_matrix);
	ATF_TP_ADD_TC(tp, bredr_echo_req_and_rsp);
	ATF_TP_ADD_TC(tp, bredr_info_req_types);
	ATF_TP_ADD_TC(tp, bredr_info_rsp_matrix);
	ATF_TP_ADD_TC(tp, bredr_cmd_rej_dispatch);
	ATF_TP_ADD_TC(tp, bredr_signal_framing);

	/* ulpi.c upper-layer indication primitives (direct) */
	ATF_TP_ADD_TC(tp, ulpi_encryption_change);
	ATF_TP_ADD_TC(tp, ulpi_qos_and_cfg_ind);
	ATF_TP_ADD_TC(tp, ulpi_chan_by_conhandle_att_discon);

	/* misc.c hook-info + refcount + timer arm/disarm + free_con */
	ATF_TP_ADD_TC(tp, misc_send_hook_info);
	ATF_TP_ADD_TC(tp, misc_con_ref_lifecycle);
	ATF_TP_ADD_TC(tp, misc_timer_arm_disarm);
	ATF_TP_ADD_TC(tp, misc_free_con_full_cleanup);

	/* LE Connection Parameter Update -- Vol 3 Part A §4.20 */
	ATF_TP_ADD_TC(tp, le_param_update_req_rsp);
	ATF_TP_ADD_TC(tp, bredr_con_req_no_resources);

	return (atf_no_error());
}
