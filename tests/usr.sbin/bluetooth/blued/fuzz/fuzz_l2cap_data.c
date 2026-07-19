/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the kernel L2CAP *data plane* -- LE Credit Based
 * (CoC) / Enhanced Credit Based (ECBFC) K-frame reassembly and credit
 * accounting.
 *
 * Target TUs (all #include'd, not compiled separately):
 *   sys/netgraph/bluetooth/l2cap/ng_l2cap_misc.c   channel/con allocators
 *   sys/netgraph/bluetooth/l2cap/ng_l2cap_cmds.c   segmentation + timers
 *   sys/netgraph/bluetooth/l2cap/ng_l2cap_ulpi.c   ng_l2cap_l2ca_receive()
 *   sys/netgraph/bluetooth/l2cap/ng_l2cap_evnt.c   signalling decoders
 *
 * ng_l2cap_l2ca_receive() (ng_l2cap_ulpi.c) is where an over-the-air
 * L2CAP DATA PDU / K-frame enters the credit data path: it credit-gates
 * the frame, strips the L2CAP header, reads the 2-byte SDU-Length prefix
 * on the first K-frame, reassembles continuation K-frames into ch->rx_sdu
 * and delivers the completed SDU upstream (Core Spec Vol 3 Part A Sections
 * 3.4.3, 10.1).  Every gate there -- zero local credits, payload > local
 * MPS, SDU length > MTU, reassembly overflow -- tears the channel down.
 *
 * This harness reuses l2cap_data_test.c's userspace shim (a flat,
 * malloc-backed struct mbuf; kernel malloc/free mapped onto calloc/free;
 * a loopback ng_l2cap_lp_send() that captures emitted frames; a manually
 * fireable fake-callout registry; NG_SEND_* capture sinks) so the four
 * kernel TUs compile and link with no fake-header tree.
 *
 * LLVMFuzzerInitialize is a no-op: because a received K-frame can free the
 * channel (any of the disconnect gates above), the connection + open
 * credit-based channel are (re)built fresh every iteration, then the fuzz
 * input is split into a sequence of K-frames fed one at a time so multi-
 * segment reassembly + running credit accounting are driven.  The whole
 * connection is torn down with the real ng_l2cap_free_con() each iteration
 * so ASan sees no leak.
 *
 * Build/run: see fuzz/Makefile (L2CAP_DATA_*).  Needs only -I${SRCTOP}/sys
 * and -I of the l2cap source dir so the #includes resolve.
 *
 * Reference: Core Spec Vol 3 Part A (L2CAP), Sections 3.4, 4.22-4.26, 10.1.
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/queue.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>	/* real ng_l2cap_var.h debug macros expand to printf */
#include <stdlib.h>
#include <string.h>
#include <strings.h>

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

#define NG_NODE_NAME(n)		"l2cap_fz"
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
 * The 1-arg libc calls (free(p) / malloc(n)) do NOT match these 2-/3-param
 * macros, so libc's own allocators stay untouched.
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
static void	ng_fz_capture_msg(struct ng_mesg *msg);
static void	ng_fz_capture_data(struct mbuf *m);

#define NG_SEND_MSG_HOOK(error, node, msg, hook, flags)	do {		\
	(error) = 0;							\
	ng_fz_capture_msg((msg));					\
	(free)((msg));							\
	(msg) = NULL;							\
} while (0)

#define NG_SEND_DATA_ONLY(error, hook, m)	do {			\
	(error) = 0;							\
	ng_fz_capture_data((m));					\
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
/* Capture sinks (inert: we only need them to consume + free).            */
/* ---------------------------------------------------------------------- */
static void
ng_fz_capture_msg(struct ng_mesg *msg)
{

	(void)msg;
}

static void
ng_fz_capture_data(struct mbuf *m)
{

	(void)m;
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
		return (0);
	c->c_pending = 0;
	callout_forget(c);
	return (1);
}

int
ng_uncallout_drain(struct callout *c, node_p node)
{

	return (ng_uncallout(c, node));
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
 * Loopback ng_l2cap_lp_send(): drop the emitted frame, then leave a
 * placeholder ACL mbuf in con->tx_pkt so con_wakeup's save/restore chaining
 * runs exactly as in the kernel.  The caller-owned data mbuf is consumed.
 */
int
ng_l2cap_lp_send(ng_l2cap_con_p con, u_int16_t dcid, struct mbuf *m)
{
	struct mbuf	*ph;

	(void)dcid;
	m_freem(m);

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

static bdaddr_t	g_addr = { { 1, 2, 3, 4, 5, 6 } };

static void
reset_all(void)
{

	g_ncallouts = 0;
	memset(&g_l2cap, 0, sizeof(g_l2cap));
	g_l2cap.node = (node_p)&g_l2cap;	/* NG_NODE_PRIVATE -> l2cap */
	g_l2cap.l2c = (hook_p)&g_l2cap;		/* upstream hook connected */
	LIST_INIT(&g_l2cap.con_list);
	LIST_INIT(&g_l2cap.chan_list);
}

static ng_l2cap_con_p
mk_con(u_int8_t linktype, u_int8_t encryption)
{
	ng_l2cap_con_p	con;

	con = ng_l2cap_new_con(&g_l2cap, &g_addr, linktype);
	if (con == NULL)
		return (NULL);
	con->encryption = encryption;
	con->state = NG_L2CAP_CON_OPEN;
	return (con);
}

/* Create an OPEN credit-based channel with fully-populated flow params. */
static ng_l2cap_chan_p
mk_open_chan(ng_l2cap_con_p con, int idtype, u_int16_t dcid,
    u_int16_t mps_local, u_int16_t mps_remote,
    u_int16_t credits_local, u_int16_t credits_remote,
    u_int16_t imtu, u_int16_t omtu)
{
	ng_l2cap_chan_p	ch;

	ch = ng_l2cap_new_chan(&g_l2cap, con, NG_L2CAP_PSM_EATT, idtype);
	if (ch == NULL)
		return (NULL);
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

/*
 * Drain the placeholder ACL packets our loopback ng_l2cap_lp_send() parks in
 * con->tx_pkt, mirroring the real ACL layer completing the transmit and
 * clearing the queue.  Without this the per-frame placeholders (e.g. from an
 * RX credit-replenish FLOW_CONTROL_CREDIT) accumulate across frames since
 * lp_send overwrites the pointer.
 */
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

/* Drive a raw L2CAP DATA frame (K-frame) into the receive path. */
static void
feed_kframe(ng_l2cap_con_p con, u_int16_t dcid, const u_int8_t *payload,
    int plen)
{
	struct mbuf	*m;
	ng_l2cap_hdr_t	*h;

	m = ng_mbuf_alloc();
	if (m == NULL)
		return;
	h = (ng_l2cap_hdr_t *)m->m_data;
	h->length = htole16((u_int16_t)plen);
	h->dcid = htole16(dcid);
	if (plen > 0)
		memcpy(m->m_data + sizeof(*h), payload, (size_t)plen);
	m->m_len = m->m_pkthdr.len = (int)sizeof(*h) + plen;
	con->rx_pkt = m;
	(void)ng_l2cap_l2ca_receive(con);	/* frees con->rx_pkt on every path */
	drain_tx(con);
}

/* Local-MPS choices spanning the LE minimum up to the CoC local MPS. */
static const u_int16_t	g_mps_tab[4] = { 23, 64, 247, 512 };

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	ng_l2cap_con_p	con;
	ng_l2cap_chan_p	ch;
	u_int16_t	 scid;
	u_int16_t	 mps_local, credits_local, imtu;
	uint8_t		 cfg;
	int		 idtype = NG_L2CAP_L2CA_IDTYPE_LE;

	reset_all();

	if (size < 1)
		return (0);

	/*
	 * cfg byte tunes the channel so the fuzzer reaches every RX gate:
	 *   bit1..2  -> local MPS (23/64/247/512) : payload>MPS disconnect
	 *   bit3..6  -> local credits (0..15)     : zero-credit + exhaustion
	 *   bit7     -> small (32) vs large (512) MTU : SDU-len>MTU disconnect
	 */
	cfg = data[0];
	data++;
	size--;

	mps_local = g_mps_tab[(cfg >> 1) & 0x03];
	credits_local = (u_int16_t)((cfg >> 3) & 0x0f);
	imtu = (cfg & 0x80) ? 32 : 512;

	con = mk_con(NG_HCI_LINK_LE_PUBLIC, 1);
	if (con == NULL)
		return (0);
	ch = mk_open_chan(con, idtype, 0x0041, mps_local, 247,
	    credits_local, 8, imtu, 512);
	if (ch == NULL) {
		ng_l2cap_free_con(con);
		return (0);
	}
	scid = ch->scid;

	/*
	 * Feed the rest of the input as a sequence of length-prefixed K-frames
	 * ([len][len bytes]...), each pushed through ng_l2cap_l2ca_receive() so
	 * the running reassembly + credit state carries across frames.  A frame
	 * may tear the channel down (a disconnect gate); stop feeding once the
	 * channel is gone.
	 */
	while (size > 0) {
		u_int16_t	flen = data[0];

		data++;
		size--;
		if (flen > size)
			flen = (u_int16_t)size;
		if (ng_l2cap_chan_by_scid(&g_l2cap, scid, idtype) == NULL)
			break;
		feed_kframe(con, scid, data, (int)flen);
		data += flen;
		size -= flen;
	}

	/* Real, complete teardown: frees channels, cmd_list, rx/tx, the con. */
	ng_l2cap_free_con(con);
	return (0);
}
