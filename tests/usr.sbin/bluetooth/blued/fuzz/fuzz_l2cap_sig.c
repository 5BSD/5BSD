/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the kernel L2CAP signalling command decoders.
 *
 * Target: sys/netgraph/bluetooth/l2cap/ng_l2cap_evnt.c
 *
 * ng_l2cap_receive() is where every untrusted, over-the-air L2CAP
 * signalling C-frame (CID 0x0001 BR/EDR, CID 0x0005 LE) enters the
 * stack.  It length-gates the C-frame, then dispatches to a family of
 * static process_*() handlers that parse connection/config/disconnect/
 * echo/info requests and the LE + Enhanced Credit Based flow-control
 * commands (Core Spec Vol 3 Part A Section 4).  Every one of those
 * handlers is `static`, so the only way to reach them is to compile the
 * translation unit itself -- this file #includes "ng_l2cap_evnt.c".
 *
 * The kernel TU pulls in kernel-only headers (sys/systm.h, sys/mbuf.h,
 * netgraph/netgraph.h, ng_l2cap_var.h, ...) and references ~30 netgraph
 * externs that do not exist in user space.  Rather than maintain a tree
 * of fake headers, this harness neutralises each kernel-only header by
 * predefining its include guard, then supplies user-space replacements:
 *
 *   - a flat, malloc-backed struct mbuf and the handful of mbuf ops the
 *     decoders use (m_pullup/m_adj/m_copydata/m_split/m_cat/mtod/MGETHDR);
 *   - trimmed netgraph/l2cap descriptor structs (ng_l2cap{,_con,_chan,
 *     _cmd}) holding only the fields the decoders touch, with the
 *     NG_L2CAP_* debug macros compiled to no-ops;
 *   - inert SDT probe macros;
 *   - stubs for every response/allocation/lookup extern, backed by small
 *     per-iteration channel/command registries so the accept paths
 *     (channel creation, con_ind, success responses) are exercised and
 *     nothing leaks under ASan.
 *
 * The real UAPI netgraph/bluetooth/include/ng_l2cap.h (PDU structs and
 * constants) and ng_l2cap_cmds.h (the _ng_l2cap_* response builders) are
 * used unchanged, as are sys/endian.h and sys/queue.h.
 *
 * Build/run: see fuzz/Makefile and fuzz/README.md.  Only -I${SRCTOP}/sys
 * and -I of the l2cap source dir (so the #include resolves) are needed.
 *
 * Reference: Core Spec Vol 3 Part A (L2CAP), Sections 4.20-4.27.
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/queue.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/*
 * Real UAPI: PDU layouts (ng_l2cap_hdr_t, ng_l2cap_cmd_hdr_t, the *_cp
 * structs), command opcodes, result codes, CID/PSM/MTU constants,
 * ng_l2cap_flow_t and the bluetooth_l2cap_*_timeout() prototypes.
 * ng_l2cap.h needs bdaddr_t from ng_hci.h, which needs ng_bluetooth.h.
 */
#include <netgraph/bluetooth/include/ng_bluetooth.h>
#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>

/* Harness-only control octet; these are not L2CAP wire flags. */
#define FUZZ_CTRL_CID_LE		0x01
#define FUZZ_CTRL_CORRUPT_SHIFT		1
#define FUZZ_CTRL_CORRUPT_MASK		0x03
#define FUZZ_CTRL_ATTACH_HOOK		0x08

/*
 * Neutralise the kernel-only headers that ng_l2cap_evnt.c includes by
 * predefining their include guards.  ng_l2cap_cmds.h is deliberately NOT
 * neutralised -- its _ng_l2cap_* response builders are real macros we
 * keep.  sys/param.h, sys/endian.h and sys/queue.h are left real too.
 */
#define _SYS_SYSTM_H_
#define _SYS_KERNEL_H_
#define _SYS_MALLOC_H_
#define _SYS_MBUF_H_
#define _SYS_SDT_H
#define _NETGRAPH_NETGRAPH_H_
#define _NETGRAPH_NG_MESSAGE_H_
#define _NETGRAPH_L2CAP_VAR_H_
#define _NETGRAPH_L2CAP_EVNT_H_
#define _NETGRAPH_L2CAP_LLPI_H_
#define _NETGRAPH_L2CAP_ULPI_H_
#define _NETGRAPH_L2CAP_MISC_H_

/* ----- netgraph glue types (normally netgraph/netgraph.h) ------------- */
typedef void *	node_p;
typedef void *	hook_p;

#define NG_NODE_NAME(n)		"fuzz"

/* ----- SDT probes: compile to nothing (normally sys/sdt.h) ------------ */
#define SDT_PROVIDER_DECLARE(prov)			struct __sdt_hack
#define SDT_PROBE_DECLARE(prov, mod, func, name)	struct __sdt_hack
#define SDT_PROBE_DEFINE2(prov, mod, func, name, a0, a1) \
							struct __sdt_hack
#define SDT_PROBE_DEFINE3(prov, mod, func, name, a0, a1, a2) \
							struct __sdt_hack
#define SDT_PROBE3(prov, mod, func, name, a0, a1, a2)	do { } while (0)

/* ----- malloc/mbuf tunables (normally sys/malloc.h, sys/mbuf.h) ------- */
#define M_NOWAIT	0x0001
#define MT_DATA		1

/*
 * Flat, malloc-backed mbuf.  No chaining: a single contiguous store is
 * all the signalling decoders need, and it keeps ASan's job simple.
 */
#define NG_FUZZ_MBUF_STORE	1024

struct mbuf {
	int		m_len;
	struct {
		int	len;
	}		m_pkthdr;
	unsigned char  *m_data;
	unsigned char	m_store[NG_FUZZ_MBUF_STORE];
};

static struct mbuf *
ng_fuzz_mbuf_alloc(void)
{
	struct mbuf	*m;

	m = calloc(1, sizeof(*m));
	if (m != NULL)
		m->m_data = m->m_store;
	return (m);
}

static void
m_freem(struct mbuf *m)
{

	free(m);
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
	/* Not enough contiguous data: real m_pullup frees on failure. */
	m_freem(m);
	return (NULL);
}

#define NG_L2CAP_M_PULLUP(m, s)	do {			\
	if ((m)->m_len < (int)(s))			\
		(m) = m_pullup((m), (int)(s));		\
} while (0)

static void
m_adj(struct mbuf *m, int n)
{

	if (m == NULL)
		return;
	if (n < 0)			/* only the strip-header path is used */
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
	n = ng_fuzz_mbuf_alloc();
	if (n == NULL)
		return (NULL);
	memcpy(n->m_store, m->m_data + off, (size_t)tail);
	n->m_data = n->m_store;
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
	room = NG_FUZZ_MBUF_STORE - (int)(m->m_data - m->m_store) - m->m_len;
	cp = n->m_len;
	if (cp > room)
		cp = room;
	if (cp > 0)
		memcpy(m->m_data + m->m_len, n->m_data, (size_t)cp);
	m->m_len += cp;
	m->m_pkthdr.len += cp;
	m_freem(n);
}

#define mtod(m, t)		((t)((m)->m_data))
#define MGETHDR(m, how, type)	((m) = ng_fuzz_mbuf_alloc())

/* ----- netgraph/l2cap descriptor structs (normally ng_l2cap_var.h) ---- */

/* Debug macros dereference l2cap->debug in the real header; make no-ops. */
#define NG_L2CAP_ALERT(...)	do { } while (0)
#define NG_L2CAP_ERR(...)	do { } while (0)
#define NG_L2CAP_WARN(...)	do { } while (0)
#define NG_L2CAP_INFO(...)	do { } while (0)

/* Constants that live in ng_l2cap_var.h (not the UAPI header). */
#define NG_L2CAP_NULL_IDENT		0x00
#define NG_L2CAP_FIRST_IDENT		0x01
#define NG_L2CAP_CMD_PENDING		(1 << 0)
#define NG_L2CAP_LE_COC_LOCAL_MTU	512
#define NG_L2CAP_LE_COC_LOCAL_MPS	247
#define NG_L2CAP_LE_COC_INITIAL_CREDITS	65

typedef struct ng_l2cap {
	node_p		node;
	hook_p		l2c;		/* NULL => unknown-PSM rejection path */
} ng_l2cap_t;
typedef ng_l2cap_t *	ng_l2cap_p;

typedef struct ng_l2cap_con {
	ng_l2cap_p	 l2cap;
	u_int16_t	 con_handle;
	u_int8_t	 linktype;	/* NG_HCI_LINK_ACL / _LE_PUBLIC ... */
	u_int8_t	 encryption;	/* 1 so CoC/ECBFC reach param checks */
	u_int8_t	 role;		/* NG_HCI_ROLE_MASTER(0) => Central; the
					 * conn-param-update handler gates on it */
	struct mbuf	*rx_pkt;
} ng_l2cap_con_t;
typedef ng_l2cap_con_t *	ng_l2cap_con_p;

typedef struct ng_l2cap_chan {
	ng_l2cap_con_p	 con;
	u_int16_t	 state;
	u_int8_t	 cfg_state;
	u_int8_t	 ident;
	u_int16_t	 psm;
	u_int16_t	 scid;
	u_int16_t	 dcid;
	u_int16_t	 idtype;
	u_int16_t	 imtu;
	ng_l2cap_flow_t	 iflow;
	u_int16_t	 omtu;
	ng_l2cap_flow_t	 oflow;
	u_int16_t	 flush_timo;
	u_int16_t	 mps;
	u_int16_t	 mps_remote;
	u_int16_t	 credits_local;
	u_int16_t	 credits_remote;
	u_int16_t	 le_psm;
	struct mbuf	*tx_sdu_pending;
	u_int32_t	 tx_pending_token;
	u_int16_t	 tx_pending_len;
	u_int8_t	 ecbfc_group_count;
	u_int8_t	 ecbfc_group_index;
	u_int8_t	 ecbfc_response_seen;
	u_int16_t	 ecbfc_response_result;
	u_int16_t	 pending_imtu;
	u_int16_t	 pending_mps;
	u_int8_t	 reconfig_pending;
	struct ng_l2cap_chan	*reg_next;	/* harness registry link */
} ng_l2cap_chan_t;
typedef ng_l2cap_chan_t *	ng_l2cap_chan_p;

typedef struct ng_l2cap_cmd {
	ng_l2cap_con_p	 con;
	ng_l2cap_chan_p	 ch;
	u_int16_t	 flags;
	u_int8_t	 code;
	u_int8_t	 ident;
	u_int32_t	 token;
	struct mbuf	*aux;
	struct ng_l2cap_cmd	*reg_next;	/* harness registry link */
} ng_l2cap_cmd_t;
typedef ng_l2cap_cmd_t *	ng_l2cap_cmd_p;

/* ---------------------------------------------------------------------- */
/*
 * Per-iteration channel and command registries.  new_chan / new_cmd push
 * onto these; the accept paths look channels up and set state; link_cmd
 * hands a command to the (stubbed) transmit queue; lp_deliver drains it.
 * Whatever survives is freed at the end of each fuzz iteration so ASan
 * sees no leaks.
 */
static ng_l2cap_chan_p	g_chan_head;
static ng_l2cap_cmd_p	g_cmd_head;	/* commands linked but not delivered */
static u_int16_t	g_next_scid;

static void
ng_fuzz_chan_unlink(ng_l2cap_chan_p ch)
{
	ng_l2cap_chan_p	*pp;

	for (pp = &g_chan_head; *pp != NULL; pp = &(*pp)->reg_next) {
		if (*pp == ch) {
			*pp = ch->reg_next;
			ch->reg_next = NULL;
			return;
		}
	}
}

static void
ng_fuzz_cmd_free(ng_l2cap_cmd_p cmd)
{

	if (cmd == NULL)
		return;
	NG_FREE_M(cmd->aux);
	free(cmd);
}

static void
ng_fuzz_drain(void)
{
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	while ((cmd = g_cmd_head) != NULL) {
		g_cmd_head = cmd->reg_next;
		ng_fuzz_cmd_free(cmd);
	}
	while ((ch = g_chan_head) != NULL) {
		g_chan_head = ch->reg_next;
		NG_FREE_M(ch->tx_sdu_pending);
		free(ch);
	}
}

/* ----- allocation / queue stubs -------------------------------------- */

static ng_l2cap_chan_p
ng_l2cap_new_chan(ng_l2cap_p l2cap, ng_l2cap_con_p con, u_int16_t psm,
    int idtype)
{
	ng_l2cap_chan_p	ch;

	(void)l2cap;
	ch = calloc(1, sizeof(*ch));
	if (ch == NULL)
		return (NULL);
	ch->con = con;
	ch->psm = psm;
	ch->idtype = (u_int16_t)idtype;
	if (g_next_scid < NG_L2CAP_FIRST_CID)
		g_next_scid = NG_L2CAP_FIRST_CID;
	ch->scid = g_next_scid++;
	ch->reg_next = g_chan_head;
	g_chan_head = ch;
	return (ch);
}

static void
ng_l2cap_free_chan(ng_l2cap_chan_p ch)
{

	if (ch == NULL)
		return;
	ng_fuzz_chan_unlink(ch);
	NG_FREE_M(ch->tx_sdu_pending);
	free(ch);
}

static ng_l2cap_chan_p
ng_l2cap_chan_by_scid(ng_l2cap_p l2cap, u_int16_t scid, int idtype)
{
	ng_l2cap_chan_p	ch;

	(void)l2cap;
	for (ch = g_chan_head; ch != NULL; ch = ch->reg_next)
		if (ch->scid == scid && ch->idtype == (u_int16_t)idtype)
			return (ch);
	return (NULL);
}

static ng_l2cap_chan_p
ng_l2cap_chan_by_dcid(ng_l2cap_p l2cap, u_int16_t dcid, int idtype)
{
	ng_l2cap_chan_p	ch;

	(void)l2cap;
	for (ch = g_chan_head; ch != NULL; ch = ch->reg_next)
		if (ch->dcid == dcid && ch->idtype == (u_int16_t)idtype)
			return (ch);
	return (NULL);
}

static ng_l2cap_chan_p
ng_l2cap_chan_by_scid_con(ng_l2cap_con_p con, u_int16_t scid, int idtype)
{
	ng_l2cap_chan_p	ch;

	for (ch = g_chan_head; ch != NULL; ch = ch->reg_next)
		if (ch->con == con && ch->scid == scid &&
		    ch->idtype == (u_int16_t)idtype)
			return (ch);
	return (NULL);
}

static ng_l2cap_chan_p
ng_l2cap_chan_by_dcid_con(ng_l2cap_con_p con, u_int16_t dcid, int idtype)
{
	ng_l2cap_chan_p	ch;

	for (ch = g_chan_head; ch != NULL; ch = ch->reg_next)
		if (ch->con == con && ch->dcid == dcid &&
		    ch->idtype == (u_int16_t)idtype)
			return (ch);
	return (NULL);
}

static ng_l2cap_cmd_p
ng_l2cap_new_cmd(ng_l2cap_con_p con, ng_l2cap_chan_p ch, u_int8_t ident,
    u_int8_t code, u_int32_t token)
{
	ng_l2cap_cmd_p	cmd;

	cmd = calloc(1, sizeof(*cmd));
	if (cmd == NULL)
		return (NULL);
	cmd->con = con;
	cmd->ch = ch;
	cmd->ident = ident;
	cmd->code = code;
	cmd->token = token;
	cmd->aux = NULL;
	return (cmd);
}

static void
ng_fuzz_cmd_unlink(ng_l2cap_cmd_p cmd)
{
	ng_l2cap_cmd_p	*pp;

	for (pp = &g_cmd_head; *pp != NULL; pp = &(*pp)->reg_next) {
		if (*pp == cmd) {
			*pp = cmd->reg_next;
			cmd->reg_next = NULL;
			return;
		}
	}
}

static void
ng_l2cap_free_cmd(ng_l2cap_cmd_p cmd)
{

	if (cmd == NULL)
		return;
	ng_fuzz_cmd_unlink(cmd);
	ng_fuzz_cmd_free(cmd);
}

static void
ng_l2cap_link_cmd(ng_l2cap_con_p con, ng_l2cap_cmd_p cmd)
{

	(void)con;
	if (cmd == NULL)
		return;
	cmd->reg_next = g_cmd_head;
	g_cmd_head = cmd;
}

static void
ng_l2cap_unlink_cmd(ng_l2cap_cmd_p cmd)
{

	ng_fuzz_cmd_unlink(cmd);
}

static void
ng_l2cap_lp_deliver(ng_l2cap_con_p con)
{
	ng_l2cap_cmd_p	cmd;

	(void)con;
	/* "Transmit" and free every queued command and its payload. */
	while ((cmd = g_cmd_head) != NULL) {
		g_cmd_head = cmd->reg_next;
		ng_fuzz_cmd_free(cmd);
	}
}

/* ----- lookup / timer / upper-layer stubs ---------------------------- */

static ng_l2cap_cmd_p
ng_l2cap_cmd_by_ident(ng_l2cap_con_p con, u_int8_t ident)
{

	(void)con;
	(void)ident;
	return (NULL);		/* no outstanding requests in the fuzzer */
}

static int
ng_l2cap_command_untimeout(ng_l2cap_cmd_p cmd)
{

	(void)cmd;
	return (0);
}

static int
ng_l2cap_command_timeout(ng_l2cap_cmd_p cmd, int timo)
{

	(void)cmd;
	(void)timo;
	return (0);
}

static u_int8_t
ng_l2cap_get_ident(ng_l2cap_con_p con)
{

	(void)con;
	return (NG_L2CAP_FIRST_IDENT);
}

static struct mbuf *
ng_l2cap_prepend(struct mbuf *m, size_t size)
{
	int	head, need;

	if (m == NULL)
		return (NULL);
	head = (int)(m->m_data - m->m_store);
	need = (int)size;
	if (head >= need) {
		m->m_data -= need;
	} else {
		if (m->m_len + need > NG_FUZZ_MBUF_STORE) {
			m_freem(m);
			return (NULL);
		}
		memmove(m->m_store + need, m->m_data, (size_t)m->m_len);
		m->m_data = m->m_store;
	}
	m->m_len += need;
	m->m_pkthdr.len += need;
	return (m);
}

static void
ng_l2cap_lp_con_update(ng_l2cap_con_p con, u_int16_t imin, u_int16_t imax,
    u_int16_t latency, u_int16_t timeout)
{

	(void)con;
	(void)imin;
	(void)imax;
	(void)latency;
	(void)timeout;
}

static int
ng_l2cap_l2ca_con_ind(ng_l2cap_chan_p ch)
{

	(void)ch;
	return (0);
}

static int
ng_l2cap_l2ca_con_rsp(ng_l2cap_chan_p ch, u_int32_t token, u_int16_t result,
    u_int16_t status)
{

	(void)ch;
	(void)token;
	(void)result;
	(void)status;
	return (0);
}

static int
ng_l2cap_l2ca_discon_ind(ng_l2cap_chan_p ch)
{

	(void)ch;
	return (0);
}

static int
ng_l2cap_l2ca_discon_rsp(ng_l2cap_chan_p ch, u_int32_t token, u_int16_t result)
{

	(void)ch;
	(void)token;
	(void)result;
	return (0);
}

static int
ng_l2cap_l2ca_write_rsp(ng_l2cap_chan_p ch, u_int32_t token,
    u_int16_t result, u_int16_t length)
{

	(void)ch;
	(void)token;
	(void)result;
	(void)length;
	return (0);
}

int
ng_l2cap_le_coc_tx_frags(ng_l2cap_con_p con, ng_l2cap_chan_p ch,
    struct mbuf *frag, u_int16_t mps, u_int32_t token, u_int16_t sdu_len)
{

	(void)con;
	(void)ch;
	(void)mps;
	(void)token;
	(void)sdu_len;
	NG_FREE_M(frag);
	return (0);
}

static int
ng_l2cap_l2ca_cfg_rsp(ng_l2cap_chan_p ch, u_int32_t token, u_int16_t result)
{

	(void)ch;
	(void)token;
	(void)result;
	return (0);
}

static int
ng_l2cap_l2ca_cfg_ind(ng_l2cap_chan_p ch)
{

	(void)ch;
	return (0);
}

static int
ng_l2cap_l2ca_ping_rsp(ng_l2cap_con_p con, u_int32_t token, u_int16_t result,
    struct mbuf *m)
{

	(void)con;
	(void)token;
	(void)result;
	NG_FREE_M(m);
	return (0);
}

static int
ng_l2cap_l2ca_get_info_rsp(ng_l2cap_con_p con, u_int32_t token,
    u_int16_t result, struct mbuf *m)
{

	(void)con;
	(void)token;
	(void)result;
	NG_FREE_M(m);
	return (0);
}

static int
ng_l2cap_l2ca_receive(ng_l2cap_con_p con)
{

	NG_FREE_M(con->rx_pkt);
	return (0);
}

static int
ng_l2cap_l2ca_clt_receive(ng_l2cap_con_p con)
{

	NG_FREE_M(con->rx_pkt);
	return (0);
}

uint32_t
bluetooth_l2cap_rtx_timeout(void)
{

	return (0);
}

uint32_t
bluetooth_l2cap_ertx_timeout(void)
{

	return (0);
}

/* ---------------------------------------------------------------------- */
/* The code under test.  Brings in every static process_*() decoder. */
#include "ng_l2cap_evnt.c"
/* ---------------------------------------------------------------------- */

#define NG_FUZZ_L2CAP_HDR	4	/* sizeof(ng_l2cap_hdr_t) */
#define NG_FUZZ_CMD_HDR		4	/* sizeof(ng_l2cap_cmd_hdr_t) */
#define NG_FUZZ_MAX_PAYLOAD	512

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ng_l2cap		l2cap;
	struct ng_l2cap_con	con;
	struct mbuf		*m;
	ng_l2cap_hdr_t		*lh;
	ng_l2cap_cmd_hdr_t	*ch;
	size_t			 payload;
	uint16_t		 lh_len, cmd_len;
	uint8_t			 code, ident, ctrl, cid_sel, corrupt;

	if (size < 3)
		return (0);

	/*
	 * Header selector bytes:
	 *   data[0] = signalling command code (full 0x00-0xff dispatch surface)
	 *   data[1] = command ident
	 *   data[2] = control:
	 *		bit0    -> BR/EDR (0) vs LE (1) signalling CID
	 *		bit1..2 -> length-field corruption mode (exercise gates)
	 *		bit3    -> l2c hook connected (reach forward-any-PSM path)
	 */
	code = data[0];
	ident = data[1];
	ctrl = data[2];
	data += 3;
	size -= 3;

	cid_sel = ctrl & FUZZ_CTRL_CID_LE;
	corrupt = (ctrl >> FUZZ_CTRL_CORRUPT_SHIFT) &
	    FUZZ_CTRL_CORRUPT_MASK;

	payload = size;
	if (payload > NG_FUZZ_MAX_PAYLOAD)
		payload = NG_FUZZ_MAX_PAYLOAD;

	m = ng_fuzz_mbuf_alloc();
	if (m == NULL)
		return (0);

	memset(&l2cap, 0, sizeof(l2cap));
	memset(&con, 0, sizeof(con));
	l2cap.node = NULL;
	l2cap.l2c = (ctrl & FUZZ_CTRL_ATTACH_HOOK) ? (hook_p)&l2cap : NULL;
	con.l2cap = &l2cap;
	con.con_handle = 0x000b;
	con.encryption = 1;
	con.linktype = cid_sel ? NG_HCI_LINK_LE_PUBLIC : NG_HCI_LINK_ACL;
	con.rx_pkt = m;

	/* Build: L2CAP header | command header | fuzz payload. */
	cmd_len = (uint16_t)payload;
	lh_len = (uint16_t)(NG_FUZZ_CMD_HDR + payload);

	/* Optionally corrupt the declared lengths to hit the length gates. */
	switch (corrupt) {
	case 1:					/* command claims more than present */
		cmd_len = (uint16_t)(payload + 4);
		break;
	case 2:					/* L2CAP payload length mismatch */
		lh_len = (uint16_t)(lh_len ^ 0x0001);
		break;
	case 3:					/* command shorter -> trailing data */
		cmd_len = (uint16_t)(payload > 0 ? payload - 1 : 0);
		break;
	default:
		break;
	}

	lh = (ng_l2cap_hdr_t *)m->m_store;
	lh->length = htole16(lh_len);
	lh->dcid = htole16(cid_sel ? NG_L2CAP_LESIGNAL_CID :
	    NG_L2CAP_SIGNAL_CID);

	ch = (ng_l2cap_cmd_hdr_t *)(m->m_store + NG_FUZZ_L2CAP_HDR);
	ch->code = code;
	ch->ident = ident;
	ch->length = htole16(cmd_len);

	if (payload > 0)
		memcpy(m->m_store + NG_FUZZ_L2CAP_HDR + NG_FUZZ_CMD_HDR, data,
		    payload);

	m->m_data = m->m_store;
	m->m_len = m->m_pkthdr.len =
	    (int)(NG_FUZZ_L2CAP_HDR + NG_FUZZ_CMD_HDR + payload);

	/* Fresh registries every iteration. */
	g_chan_head = NULL;
	g_cmd_head = NULL;
	g_next_scid = NG_L2CAP_FIRST_CID;

	(void)ng_l2cap_receive(&con);	/* frees con.rx_pkt on every path */

	/* Free any channels/commands the decoders left behind. */
	ng_fuzz_drain();

	return (0);
}
