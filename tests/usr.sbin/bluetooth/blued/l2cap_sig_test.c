/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Assertion-based (known-answer) ATF tests for the kernel L2CAP signalling
 * command decoders in sys/netgraph/bluetooth/l2cap/ng_l2cap_evnt.c.
 *
 * Where the fuzzer (fuzz/fuzz_l2cap_sig.c) only proves the decoders do not
 * crash on arbitrary input, this program feeds a *specific* signalling
 * C-frame into ng_l2cap_receive() and asserts the *specific* response PDU
 * the decoder is required to emit by the Core Spec Vol 3 Part A (L2CAP
 * signalling).  Expected response bytes are hand-encoded from the spec
 * (/usr/src/bluetooth-specs/Core_Specification_6_3.txt), cited per case;
 * they are NEVER captured from the decoder's current output.
 *
 * Technique: reuse the fuzzer's proven shim.  We #include the kernel TU
 * ng_l2cap_evnt.c to reach the static process_*() handlers, neutralise the
 * kernel-only headers by predefining their include guards, and supply a
 * userspace malloc-backed mbuf plus the ~30 netgraph stubs.  The one crucial
 * change over the fuzzer: ng_l2cap_link_cmd() CAPTURES the fully-built
 * response PDU (cmd->aux bytes) into a global registry instead of dropping
 * it, so each test can assert the exact bytes/fields of the reply.
 *
 * A response PDU as captured begins at the L2CAP command header
 * (code, ident, length) -- the outer L2CAP header (length, dcid) is
 * prepended by a lower layer and is not part of what these handlers build.
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

#include <atf-c.h>

#include "spec_l2cap_core63_oracles.h"

/* Real UAPI: PDU layouts, opcodes, result codes, CID/PSM/MTU constants. */
#include <netgraph/bluetooth/include/ng_bluetooth.h>
#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>

/* Neutralise kernel-only headers ng_l2cap_evnt.c includes. */
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

#define NG_NODE_NAME(n)		"l2cap_ut"

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

#define NG_FUZZ_MBUF_STORE	1024

static int g_mbuf_alloc_fail;

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

	if (g_mbuf_alloc_fail > 0) {
		g_mbuf_alloc_fail--;
		return (NULL);
	}
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

#define NG_L2CAP_ALERT(...)	do { } while (0)
#define NG_L2CAP_ERR(...)	do { } while (0)
#define NG_L2CAP_WARN(...)	do { } while (0)
#define NG_L2CAP_INFO(...)	do { } while (0)

#define NG_L2CAP_NULL_IDENT		0x00
#define NG_L2CAP_FIRST_IDENT		0x01
#define NG_L2CAP_CMD_PENDING		(1 << 0)
#define NG_L2CAP_LE_COC_LOCAL_MTU	512
#define NG_L2CAP_LE_COC_LOCAL_MPS	247
#define NG_L2CAP_LE_COC_INITIAL_CREDITS	65

typedef struct ng_l2cap {
	node_p		node;
	hook_p		l2c;
	u_int64_t	ecbfc_group_id;
} ng_l2cap_t;
typedef ng_l2cap_t *	ng_l2cap_p;

typedef struct ng_l2cap_con {
	ng_l2cap_p	 l2cap;
	u_int16_t	 con_handle;
	u_int8_t	 linktype;
	u_int8_t	 encryption;
	u_int8_t	 role;		/* local role (NG_HCI_ROLE_MASTER/SLAVE) */
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
	struct mbuf	*rx_sdu;
	u_int16_t	 rx_sdu_len;
	u_int16_t	 rx_sdu_got;
	struct mbuf	*tx_sdu_pending;
	u_int32_t	 tx_pending_token;
	u_int16_t	 tx_pending_len;
	u_int64_t	 ecbfc_group_id;
	u_int8_t	 ecbfc_group_count;
	u_int8_t	 ecbfc_group_index;
	u_int8_t	 ecbfc_response_seen;
	u_int16_t	 ecbfc_response_result;
	u_int16_t	 pending_imtu;
	u_int16_t	 pending_mps;
	u_int8_t	 reconfig_pending;
	struct ng_l2cap_chan	*reg_next;
} ng_l2cap_chan_t;
typedef ng_l2cap_chan_t *	ng_l2cap_chan_p;

typedef struct ng_l2cap_cmd {
	ng_l2cap_con_p	 con;
	ng_l2cap_chan_p	 ch;
	u_int16_t	 flags;
	u_int8_t	 code;
	u_int8_t	 ident;
	u_int32_t	 token;
	u_int64_t	 ecbfc_group_id;
	struct mbuf	*aux;
	struct ng_l2cap_cmd	*reg_next;
} ng_l2cap_cmd_t;
typedef ng_l2cap_cmd_t *	ng_l2cap_cmd_p;

/* ---------------------------------------------------------------------- */
/* Per-test channel/command registries (mirrors the fuzzer). */
static ng_l2cap_chan_p	g_chan_head;
static ng_l2cap_cmd_p	g_cmd_head;
static u_int16_t	g_next_scid;

/*
 * Test knobs: force ng_l2cap_l2ca_con_ind() to fail so the con_req reject
 * paths (PSM-not-supported / no-resources) can be reached single-shot.
 */
static int		g_con_ind_error;
static int		g_chan_alloc_fail;
static int		g_cmd_alloc_fail;

/* ---------------------------------------------------------------------- */
/*
 * Captured response PDUs.  A capture is the exact byte string the decoder
 * committed to the transmit queue via ng_l2cap_link_cmd(), starting at the
 * L2CAP command header.
 */
struct captured_pdu {
	u_int8_t	code;	/* cmd->code (redundant with data[0]) */
	u_int8_t	ident;	/* cmd->ident */
	int		len;
	u_int8_t	data[600];
};
#define MAX_CAPTURES	16
static struct captured_pdu	g_caps[MAX_CAPTURES];
static int			g_ncaps;

static void
reset_captures(void)
{

	memset(g_caps, 0, sizeof(g_caps));
	g_ncaps = 0;
}

static u_int16_t
cap_le16(const struct captured_pdu *c, int off)
{

	return ((u_int16_t)(c->data[off] | (c->data[off + 1] << 8)));
}

static u_int32_t
cap_le32(const struct captured_pdu *c, int off)
{

	return ((u_int32_t)c->data[off] | ((u_int32_t)c->data[off + 1] << 8) |
	    ((u_int32_t)c->data[off + 2] << 16) |
	    ((u_int32_t)c->data[off + 3] << 24));
}

/* ----- allocation / queue stubs -------------------------------------- */

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

static ng_l2cap_chan_p
ng_l2cap_new_chan(ng_l2cap_p l2cap, ng_l2cap_con_p con, u_int16_t psm,
    int idtype)
{
	ng_l2cap_chan_p	ch;

	(void)l2cap;
	if (g_chan_alloc_fail > 0) {
		g_chan_alloc_fail--;
		return (NULL);
	}
	ch = calloc(1, sizeof(*ch));
	if (ch == NULL)
		return (NULL);
	ch->con = con;
	ch->psm = psm;
	ch->idtype = (u_int16_t)idtype;
	if (g_next_scid < BT_CORE63_L2CAP_CID_DYNAMIC_FIRST)
		g_next_scid = BT_CORE63_L2CAP_CID_DYNAMIC_FIRST;
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
	ng_l2cap_chan_p ch;

	for (ch = g_chan_head; ch != NULL; ch = ch->reg_next)
		if (ch->con == con && ch->scid == scid &&
		    ch->idtype == (u_int16_t)idtype)
			return (ch);
	return (NULL);
}

static ng_l2cap_chan_p
ng_l2cap_chan_by_dcid_con(ng_l2cap_con_p con, u_int16_t dcid, int idtype)
{
	ng_l2cap_chan_p ch;

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

	if (g_cmd_alloc_fail > 0) {
		g_cmd_alloc_fail--;
		return (NULL);
	}
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

/*
 * The known-answer hook: capture the emitted PDU, then queue it.  Every
 * response path builds cmd->aux fully before calling link_cmd, so aux holds
 * the complete on-wire signalling command here.
 */
static void
ng_l2cap_link_cmd(ng_l2cap_con_p con, ng_l2cap_cmd_p cmd)
{

	(void)con;
	if (cmd == NULL)
		return;
	if (cmd->aux != NULL && g_ncaps < MAX_CAPTURES) {
		struct captured_pdu	*c = &g_caps[g_ncaps++];
		int			 n = cmd->aux->m_len;

		if (n > (int)sizeof(c->data))
			n = (int)sizeof(c->data);
		c->code = cmd->code;
		c->ident = cmd->ident;
		c->len = n;
		memcpy(c->data, cmd->aux->m_data, (size_t)n);
	}
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
	return (NULL);		/* no outstanding requests (see category B) */
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
	return (g_con_ind_error);
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

/* ====================================================================== */
/* Test harness helpers                                                   */
/* ====================================================================== */

static struct ng_l2cap		g_l2cap;
static struct ng_l2cap_con	g_con;

/* Reset all global state and configure the connection under test. */
static void
setup_con(u_int8_t linktype, int hook_connected, u_int8_t encryption)
{

	reset_captures();
	memset(&g_l2cap, 0, sizeof(g_l2cap));
	memset(&g_con, 0, sizeof(g_con));
	g_l2cap.node = NULL;
	g_l2cap.l2c = hook_connected ? (hook_p)&g_l2cap : NULL;
	g_con.l2cap = &g_l2cap;
	g_con.con_handle = 0x000b;
	g_con.encryption = encryption;
	g_con.linktype = linktype;
	g_chan_head = NULL;
	g_cmd_head = NULL;
	g_next_scid = BT_CORE63_L2CAP_CID_DYNAMIC_FIRST;
	g_con_ind_error = 0;
	g_mbuf_alloc_fail = 0;
	g_chan_alloc_fail = 0;
	g_cmd_alloc_fail = 0;
}

/* Register a channel directly into the registry with chosen fields. */
static ng_l2cap_chan_p
register_chan(u_int16_t scid, u_int16_t dcid, u_int16_t state, int idtype)
{
	ng_l2cap_chan_p	ch;

	ch = calloc(1, sizeof(*ch));
	ATF_REQUIRE(ch != NULL);
	ch->con = &g_con;
	ch->scid = scid;
	ch->dcid = dcid;
	ch->state = state;
	ch->idtype = (u_int16_t)idtype;
	ch->reg_next = g_chan_head;
	g_chan_head = ch;
	return (ch);
}

/*
 * Build one L2CAP C-frame and drive it through ng_l2cap_receive().
 *
 *   dcid            outer L2CAP CID (BT_CORE63_L2CAP_CID_SIGNAL / _LESIGNAL_CID)
 *   code, ident     signalling command header
 *   payload/plen    command parameter bytes
 *   cmd_len_field   value to write in the command-header length field
 *                   (-1 => auto = plen)
 *   l2cap_len_field value to write in the outer L2CAP length field
 *                   (-1 => auto = 4 + plen, the spec-correct value)
 */
static void
feed(u_int16_t dcid, u_int8_t code, u_int8_t ident,
    const u_int8_t *payload, int plen, int cmd_len_field, int l2cap_len_field)
{
	struct mbuf		*m;
	ng_l2cap_hdr_t		*lh;
	ng_l2cap_cmd_hdr_t	*chh;
	int			 cmd_len, l2len;

	m = ng_fuzz_mbuf_alloc();
	ATF_REQUIRE(m != NULL);

	cmd_len = (cmd_len_field < 0) ? plen : cmd_len_field;
	l2len = (l2cap_len_field < 0) ? (4 + plen) : l2cap_len_field;

	lh = (ng_l2cap_hdr_t *)m->m_store;
	lh->length = htole16((u_int16_t)l2len);
	lh->dcid = htole16(dcid);

	chh = (ng_l2cap_cmd_hdr_t *)(m->m_store + 4);
	chh->code = code;
	chh->ident = ident;
	chh->length = htole16((u_int16_t)cmd_len);

	if (plen > 0)
		memcpy(m->m_store + 8, payload, (size_t)plen);

	m->m_data = m->m_store;
	m->m_len = m->m_pkthdr.len = 8 + plen;

	g_con.rx_pkt = m;
	(void)ng_l2cap_receive(&g_con);
}

/* Convenience: well-formed frame (auto length fields). */
static void
feed_ok(u_int16_t dcid, u_int8_t code, u_int8_t ident,
    const u_int8_t *payload, int plen)
{

	feed(dcid, code, ident, payload, plen, -1, -1);
}

/* le16 into a little-endian byte pair */
#define LE16(v)		(u_int8_t)((v) & 0xff), (u_int8_t)(((v) >> 8) & 0xff)

/* ====================================================================== */
/* Command Reject (0x01) -- Core Spec Vol 3 Part A Section 4.1            */
/* ====================================================================== */

/*
 * Unknown command code on the BR/EDR signalling channel: the receiver
 * "shall always send [an L2CAP_COMMAND_REJECT_RSP] in response to
 * unidentified signaling packets" (Vol 3 Part A Section 4.1), with Reason
 * 0x0000 "Command not understood" (Table 4.3) and NO Reason Data
 * (Table 4.4).  Identifier shall match the rejected command.
 */
ATF_TC_WITHOUT_HEAD(cmd_reject_unknown_code_bredr);
ATF_TC_BODY(cmd_reject_unknown_code_bredr, tc)
{
	setup_con(NG_HCI_LINK_ACL, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, 0xff, 0x42, NULL, 0);

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_caps[0].data[0]);	/* code 0x01 */
	ATF_CHECK_EQ(0x42, g_caps[0].data[1]);			/* ident echo */
	ATF_CHECK_EQ(2, cap_le16(&g_caps[0], 2));		/* length = 2 */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD, cap_le16(&g_caps[0], 4));
	ATF_CHECK_EQ(6, g_caps[0].len);				/* no Reason Data */
}

/*
 * Same on the LE signalling channel (CID 0x0005): unknown code routes to
 * the lesignal default and shall also emit a Command Reject (Section 4.1).
 */
ATF_TC_WITHOUT_HEAD(cmd_reject_unknown_code_le);
ATF_TC_BODY(cmd_reject_unknown_code_le, tc)
{
	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, 0xfe, 0x7b, NULL, 0);

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x7b, g_caps[0].data[1]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD, cap_le16(&g_caps[0], 4));
}

/*
 * "only one command per C-frame shall be sent over fixed channel CID
 * 0x0005" (Vol 3 Part A Section 4).  A LE C-frame whose declared command
 * length leaves trailing bytes shall be rejected with Command Reject.
 */
ATF_TC_WITHOUT_HEAD(cmd_reject_le_multiple_commands);
ATF_TC_BODY(cmd_reject_le_multiple_commands, tc)
{
	/* 8-byte payload but command claims only 2 -> 6 trailing bytes. */
	static const u_int8_t p[8] = { 0 };

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	feed(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ, 0x33,
	    p, 8, /*cmd_len*/2, /*l2cap_len*/ 4 + 8);

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x33, g_caps[0].data[1]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD, cap_le16(&g_caps[0], 4));
}

ATF_TC_WITHOUT_HEAD(cmd_reject_bredr_fixed_command_trailing_payload);
ATF_TC_BODY(cmd_reject_bredr_fixed_command_trailing_payload, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0001), LE16(0x0040), 0xaa, 0xbb
	};

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x34, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x34, g_caps[0].data[1]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD, cap_le16(&g_caps[0], 4));
	ATF_CHECK(g_chan_head == NULL);
}

ATF_TC_WITHOUT_HEAD(cmd_reject_le_fixed_command_trailing_payload);
ATF_TC_BODY(cmd_reject_le_fixed_command_trailing_payload, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0018), LE16(0x0028), LE16(0x0000), LE16(0x01f4),
		0xaa, 0xbb
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ,
	    0x35, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x35, g_caps[0].data[1]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD, cap_le16(&g_caps[0], 4));
}

/*
 * Malformed: outer L2CAP payload-length field mismatches the actual frame
 * size.  ng_l2cap_receive() shall silently drop (no response emitted).
 */
ATF_TC_WITHOUT_HEAD(malformed_l2cap_length_mismatch_dropped);
ATF_TC_BODY(malformed_l2cap_length_mismatch_dropped, tc)
{
	setup_con(NG_HCI_LINK_ACL, 0, 1);
	/* Claim L2CAP length 0x0009 while the real payload is 4 bytes. */
	feed(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECHO_REQ, 0x01, NULL, 0,
	    -1, /*l2cap_len*/ 9);

	ATF_CHECK_EQ(0, g_ncaps);
}

/*
 * BR/EDR signalling CID 0x0001 is not valid on an LE-U link; such a frame
 * shall be dropped without a response (Vol 3 Part A Section 4).
 */
ATF_TC_WITHOUT_HEAD(bredr_signal_cid_on_le_link_dropped);
ATF_TC_BODY(bredr_signal_cid_on_le_link_dropped, tc)
{
	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECHO_REQ, 0x01, NULL, 0);

	ATF_CHECK_EQ(0, g_ncaps);
}

/*
 * Oversized C-frame on the BR/EDR signalling channel.  "All L2CAP
 * implementations shall support the reception of C-frames with a payload size
 * that does not exceed the signaling MTU. ... If a device receives a C-frame
 * that exceeds its MTUsig then it shall send an L2CAP_COMMAND_REJECT_RSP
 * packet containing the supported MTUsig" (Vol 3 Part A Section 4).  For an
 * ACL-U link MTUsig is 48 octets (Table 4.1).  The Reason is 0x0001 "Signaling
 * MTU Exceeded" (Table 4.3) with a 2-octet Reason Data equal to the actual
 * MTUsig (Table 4.4); the identifier matches the first command in the packet
 * (Section 4.1) and the frame is discarded.
 */
ATF_TC_WITHOUT_HEAD(cmd_reject_oversized_cframe_bredr);
ATF_TC_BODY(cmd_reject_oversized_cframe_bredr, tc)
{
	/* 60-byte param -> C-frame payload = 4 + 60 = 64 > MTUsig (48). */
	static const u_int8_t p[60] = { 0 };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECHO_REQ, 0x55, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_caps[0].data[0]);	/* code 0x01 */
	ATF_CHECK_EQ(0x55, g_caps[0].data[1]);			/* first ident */
	ATF_CHECK_EQ(4, cap_le16(&g_caps[0], 2));		/* reason + MTU */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_SIGNAL_MTU_EXCEEDED, cap_le16(&g_caps[0], 4));
	ATF_CHECK_EQ(NG_L2CAP_MTU_MINIMUM, cap_le16(&g_caps[0], 6)); /* 48 */
	ATF_CHECK_EQ(8, g_caps[0].len);				/* 4 + reason + mtu */

	/* Frame discarded: no channel state left behind. */
	ATF_CHECK(g_chan_head == NULL);
}

/* LE signalling has its own mandatory MTUsig of 23 octets (Table 4.1). */
ATF_TC_WITHOUT_HEAD(cmd_reject_oversized_cframe_le);
ATF_TC_BODY(cmd_reject_oversized_cframe_le, tc)
{
	static const u_int8_t p[20] = { 0 };	/* C-frame = 24 > 23 */

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x56,
	    p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x56, g_caps[0].data[1]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_SIGNAL_MTU_EXCEEDED, cap_le16(&g_caps[0], 4));
	ATF_CHECK_EQ(NG_L2CAP_MTU_LE_MINIMUM, cap_le16(&g_caps[0], 6));
}

/* ====================================================================== */
/* Connection Request/Response (0x02/0x03) -- Sections 4.2/4.3           */
/* ====================================================================== */

/*
 * L2CAP_CONNECTION_REQ with a Source CID below the dynamic range
 * (< 0x0040).  The Source CID "shall be from the dynamically allocated
 * range" (Section 4.2), so the receiver refuses with an
 * L2CAP_CONNECTION_RSP whose Result is 0x0006 "Connection refused -
 * Invalid Source CID" (Section 4.3).  DCID = 0 (no channel allocated),
 * SCID copied from the request.
 */
ATF_TC_WITHOUT_HEAD(con_req_invalid_source_cid);
ATF_TC_BODY(con_req_invalid_source_cid, tc)
{
	/* psm=0x0001 (SDP), scid=0x0003 (invalid, < 0x0040) */
	static const u_int8_t p[] = { LE16(0x0001), LE16(0x0003) };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x05, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONNECTION_RSP, g_caps[0].data[0]);	/* 0x03 */
	ATF_CHECK_EQ(0x05, g_caps[0].data[1]);			/* ident echo */
	ATF_CHECK_EQ(8, cap_le16(&g_caps[0], 2));		/* length = 8 */
	ATF_CHECK_EQ(0x0000, cap_le16(&g_caps[0], 4));		/* DCID = 0 */
	ATF_CHECK_EQ(0x0003, cap_le16(&g_caps[0], 6));		/* SCID echo */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_INVALID_SOURCE_CID, cap_le16(&g_caps[0], 8));
	ATF_CHECK_EQ(NG_L2CAP_NO_INFO, cap_le16(&g_caps[0], 10));/* status */
}

/*
 * L2CAP_CONNECTION_REQ for a PSM the upper layer refuses (con_ind fails
 * with a non-ENOMEM error): the decoder replies with an
 * L2CAP_CONNECTION_RSP, Result 0x0002 "Connection refused - PSM not
 * supported" (Section 4.3).  DCID = the locally allocated channel scid,
 * SCID copied from the request.
 */
ATF_TC_WITHOUT_HEAD(con_req_psm_not_supported);
ATF_TC_BODY(con_req_psm_not_supported, tc)
{
	/* psm=0x0001, scid=0x0045 (valid dynamic CID) */
	static const u_int8_t p[] = { LE16(0x0001), LE16(0x0045) };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	g_con_ind_error = EPERM;	/* force upper-layer refusal */
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x06, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONNECTION_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x06, g_caps[0].data[1]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CID_DYNAMIC_FIRST, cap_le16(&g_caps[0], 4));  /* DCID */
	ATF_CHECK_EQ(0x0045, cap_le16(&g_caps[0], 6));		   /* SCID */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_PSM_NOT_SUPPORTED, cap_le16(&g_caps[0], 8));
}

/*
 * L2CAP_CONNECTION_REQ that reuses a Source CID already allocated to another
 * channel on this connection.  Per Vol 3 Part A Section 4.3 the Source CID
 * "shall not be already allocated to a different channel on the device
 * sending the response"; otherwise the receiver refuses with an
 * L2CAP_CONNECTION_RSP whose Result is 0x0007 "Connection refused - Source
 * CID already allocated" (Table 4.6) and does NOT create a duplicate channel.
 * DCID = 0 (no new channel allocated), SCID copied from the request.
 */
ATF_TC_WITHOUT_HEAD(con_req_source_cid_already_allocated);
ATF_TC_BODY(con_req_source_cid_already_allocated, tc)
{
	/* psm=0x0001 (SDP), scid=0x0045 (valid dynamic CID) */
	static const u_int8_t p[] = { LE16(0x0001), LE16(0x0045) };
	ng_l2cap_chan_p	ch;
	int		nchan;

	setup_con(NG_HCI_LINK_ACL, 0, 1);

	/*
	 * First Connection Request: upper layer accepts (con_ind returns 0),
	 * so a channel with peer SCID 0x0045 is created and no response PDU is
	 * emitted yet (the L2CAP_CONNECTION_RSP is driven later by the ULP).
	 */
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x10, p, sizeof(p));
	ATF_REQUIRE_EQ(0, g_ncaps);

	nchan = 0;
	for (ch = g_chan_head; ch != NULL; ch = ch->reg_next)
		if (ch->dcid == 0x0045)
			nchan++;
	ATF_REQUIRE_EQ(1, nchan);

	/*
	 * Second Connection Request reusing SCID 0x0045: must be refused with
	 * result 0x0007 and must NOT create a second channel.
	 */
	reset_captures();
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x11, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONNECTION_RSP, g_caps[0].data[0]);	/* 0x03 */
	ATF_CHECK_EQ(0x11, g_caps[0].data[1]);			/* ident echo */
	ATF_CHECK_EQ(8, cap_le16(&g_caps[0], 2));		/* length = 8 */
	ATF_CHECK_EQ(0x0000, cap_le16(&g_caps[0], 4));		/* DCID = 0 */
	ATF_CHECK_EQ(0x0045, cap_le16(&g_caps[0], 6));		/* SCID echo */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SOURCE_CID_ALLOCATED, cap_le16(&g_caps[0], 8));
	ATF_CHECK_EQ(NG_L2CAP_NO_INFO, cap_le16(&g_caps[0], 10));/* status */

	/* No duplicate channel created for the reused SCID. */
	nchan = 0;
	for (ch = g_chan_head; ch != NULL; ch = ch->reg_next)
		if (ch->dcid == 0x0045)
			nchan++;
	ATF_CHECK_EQ(1, nchan);
}

/* ====================================================================== */
/* Configuration Request/Response (0x04/0x05) -- Sections 4.4/4.5, 5     */
/* ====================================================================== */

/*
 * L2CAP_CONFIGURATION_REQ for a channel that does not exist: "If a command
 * refers to an invalid channel then the Reason code 0x0002 will be
 * returned" via an L2CAP_COMMAND_REJECT_RSP (Section 4.1).
 */
ATF_TC_WITHOUT_HEAD(cfg_req_unknown_channel_reject);
ATF_TC_BODY(cfg_req_unknown_channel_reject, tc)
{
	/* dcid=0x0055, flags=0 (no options) */
	static const u_int8_t p[] = { LE16(0x0055), LE16(0x0000) };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x09, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x09, g_caps[0].data[1]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_INVALID_CID, cap_le16(&g_caps[0], 4));
	ATF_CHECK_EQ(10, g_caps[0].len);	/* 4 hdr + reason + 4 CID */
}

/*
 * Regression guard: the Invalid-CID Command Reject packs the two CID
 * endpoints in spec order.  Per Vol 3 Part A Section 4.1
 * (text under Table 4.4): the 4-octet Reason Data is "the local (first) and
 * remote (second) channel endpoints ... The local endpoint is the
 * destination CID from the rejected command.  ... If the rejected command
 * contains only one of the channel endpoints, the other one shall be
 * replaced by the null CID 0x0000."
 * The rejected L2CAP_CONFIGURATION_REQ carries only a Destination CID
 * (0x0055 here), which is the LOCAL endpoint, so the spec-correct Reason
 * Data is: local=0x0055 (octets 6-7), remote=0x0000 (octets 8-9).
 */
ATF_TC_WITHOUT_HEAD(cfg_req_reject_cid_order_spec);
ATF_TC_HEAD(cfg_req_reject_cid_order_spec, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Invalid-CID Command Reject endpoint ordering per Vol 3 Part A "
	    "Sec 4.1: local(dest-from-rejected) first, remote second.");
}
ATF_TC_BODY(cfg_req_reject_cid_order_spec, tc)
{
	static const u_int8_t p[] = { LE16(0x0055), LE16(0x0000) };

	/*
	 * Regression guard: the Invalid-CID Command Reject packs the local
	 * endpoint (destination CID from the rejected command) first and the
	 * remote (source CID) second, per Core Spec Vol 3 Part A §4.1 Table 4.4.
	 */
	setup_con(NG_HCI_LINK_ACL, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x09, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_INVALID_CID, cap_le16(&g_caps[0], 4));
	/* spec: local endpoint first = the rejected command's DCID = 0x0055 */
	ATF_CHECK_EQ(0x0055, cap_le16(&g_caps[0], 6));
	/* spec: remote endpoint second = null CID 0x0000 */
	ATF_CHECK_EQ(0x0000, cap_le16(&g_caps[0], 8));
}

/*
 * L2CAP_CONFIGURATION_REQ with the Continuation (C) flag set and a valid
 * MTU option.  With C set, "More L2CAP_CONFIGURATION_RSP packets will
 * follow" (Section 4.5): the decoder answers immediately with a positive
 * (Result 0x0000) Config Response echoing the local SCID and Flags = 0,
 * carrying no options.
 */
ATF_TC_WITHOUT_HEAD(cfg_req_cflag_success);
ATF_TC_BODY(cfg_req_cflag_success, tc)
{
	/* dcid=0x0060, flags=C(0x0001), MTU option [type=1,len=2,mtu=0x02a0] */
	static const u_int8_t p[] = {
		LE16(0x0060), LE16(0x0001),
		BT_CORE63_L2CAP_OPTION_MTU, 0x02, LE16(0x02a0)
	};

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	/* channel scid must equal the request's dcid (0x0060) */
	(void)register_chan(0x0060, 0x0071, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x0a, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONFIG_RSP, g_caps[0].data[0]);	/* 0x05 */
	ATF_CHECK_EQ(0x0a, g_caps[0].data[1]);
	ATF_CHECK_EQ(6, cap_le16(&g_caps[0], 2));		/* length = 6 */
	ATF_CHECK_EQ(0x0071, cap_le16(&g_caps[0], 4));		/* SCID=ch dcid */
	ATF_CHECK_EQ(0x0000, cap_le16(&g_caps[0], 6));		/* Flags */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, cap_le16(&g_caps[0], 8));	/* Result */
}

/*
 * L2CAP_CONFIGURATION_REQ carrying an unknown option whose type MSB is 0
 * (not a hint).  Per Section 5 "the recipient shall refuse the entire
 * configuration request", and Section 4.5: Result 0x0003 "unknown options"
 * with the offending option echoed back in the response.
 */
ATF_TC_WITHOUT_HEAD(cfg_req_unknown_option);
ATF_TC_BODY(cfg_req_unknown_option, tc)
{
	/* dcid=0x0060, flags=0, unknown option type=0x10 len=2 data=aa bb */
	static const u_int8_t p[] = {
		LE16(0x0060), LE16(0x0000),
		0x10, 0x02, 0xaa, 0xbb
	};

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	(void)register_chan(0x0060, 0x0071, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x0b, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONFIG_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x0b, g_caps[0].data[1]);
	ATF_CHECK_EQ(0x0071, cap_le16(&g_caps[0], 4));		/* SCID */
	ATF_CHECK_EQ(0x0000, cap_le16(&g_caps[0], 6));		/* Flags */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CONFIG_UNKNOWN_OPTION, cap_le16(&g_caps[0], 8));
	/* Offending option echoed: type,len,data */
	ATF_REQUIRE(g_caps[0].len >= 14);
	ATF_CHECK_EQ(0x10, g_caps[0].data[10]);
	ATF_CHECK_EQ(0x02, g_caps[0].data[11]);
	ATF_CHECK_EQ(0xaa, g_caps[0].data[12]);
	ATF_CHECK_EQ(0xbb, g_caps[0].data[13]);
}

/* ====================================================================== */
/* Disconnection Request/Response (0x06/0x07) -- Sections 4.6/4.7        */
/* ====================================================================== */

/*
 * L2CAP_DISCONNECTION_REQ for a DCID the receiver does not recognize:
 * "an L2CAP_COMMAND_REJECT_RSP packet with 'invalid CID' result code shall
 * be sent in response" (Section 4.6).
 */
ATF_TC_WITHOUT_HEAD(discon_req_unknown_channel_reject);
ATF_TC_BODY(discon_req_unknown_channel_reject, tc)
{
	/* dcid=0x0080, scid=0x0090 */
	static const u_int8_t p[] = { LE16(0x0080), LE16(0x0090) };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, 0x0c, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x0c, g_caps[0].data[1]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_INVALID_CID, cap_le16(&g_caps[0], 4));
}

/*
 * L2CAP_DISCONNECTION_REQ that matches an open channel: reply with
 * L2CAP_DISCONNECTION_RSP whose DCID and SCID "shall match those of the
 * corresponding L2CAP_DISCONNECTION_REQ" (Section 4.7): DCID then SCID.
 */
ATF_TC_WITHOUT_HEAD(discon_req_match_response);
ATF_TC_BODY(discon_req_match_response, tc)
{
	/* request dcid=0x0075 (our scid), scid=0x0090 (our dcid) */
	static const u_int8_t p[] = { LE16(0x0075), LE16(0x0090) };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	(void)register_chan(0x0075, 0x0090, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, 0x0d, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_DISCONNECT_RSP, g_caps[0].data[0]);	/* 0x07 */
	ATF_CHECK_EQ(0x0d, g_caps[0].data[1]);
	ATF_CHECK_EQ(4, cap_le16(&g_caps[0], 2));		/* length = 4 */
	ATF_CHECK_EQ(0x0075, cap_le16(&g_caps[0], 4));		/* DCID */
	ATF_CHECK_EQ(0x0090, cap_le16(&g_caps[0], 6));		/* SCID */
}

/* ====================================================================== */
/* Echo Request/Response (0x08/0x09) -- Sections 4.8/4.9                 */
/* ====================================================================== */

/*
 * "L2CAP entities shall respond to a valid L2CAP_ECHO_REQ packet with an
 * L2CAP_ECHO_RSP packet" (Section 4.8).  Identifier shall match; the Echo
 * Data may be echoed (Section 4.9) -- this stack echoes it verbatim.
 */
ATF_TC_WITHOUT_HEAD(echo_req_response);
ATF_TC_BODY(echo_req_response, tc)
{
	static const u_int8_t p[] = { 0xde, 0xad, 0xbe, 0xef };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECHO_REQ, 0x11, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECHO_RSP, g_caps[0].data[0]);	/* 0x09 */
	ATF_CHECK_EQ(0x11, g_caps[0].data[1]);			/* ident echo */
	ATF_CHECK_EQ(4, cap_le16(&g_caps[0], 2));		/* length = 4 */
	ATF_REQUIRE_EQ(8, g_caps[0].len);
	ATF_CHECK_EQ(0, memcmp(&g_caps[0].data[4], p, sizeof(p)));
}

/* ====================================================================== */
/* Information Request/Response (0x0a/0x0b) -- Sections 4.10-4.13        */
/* ====================================================================== */

/*
 * InfoType 0x0001 (Connectionless MTU): Info Response, Result 0x0000
 * "Success" (Table 4.10), Info = 2-octet connectionless MTU (Table 4.11).
 */
ATF_TC_WITHOUT_HEAD(info_req_connless_mtu);
ATF_TC_BODY(info_req_connless_mtu, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_INFO_CONNECTIONLESS_MTU) };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_REQ, 0x20, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_INFO_RSP, g_caps[0].data[0]);	/* 0x0b */
	ATF_CHECK_EQ(0x20, g_caps[0].data[1]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_INFO_CONNECTIONLESS_MTU, cap_le16(&g_caps[0], 4));
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, cap_le16(&g_caps[0], 6));
	ATF_CHECK_EQ(NG_L2CAP_MTU_DEFAULT, cap_le16(&g_caps[0], 8));
}

/*
 * InfoType 0x0003 (Fixed channels supported over BR/EDR): Result 0x0000
 * plus an 8-octet bitmap (Table 4.11).  Per Section 4.13/Table 4.13, the
 * L2CAP Signaling channel bit (octet 0 bit 1) is mandatory; this stack also
 * advertises Connectionless reception (octet 0 bit 2) => octet 0 == 0x06.
 */
ATF_TC_WITHOUT_HEAD(info_req_fixed_channels);
ATF_TC_BODY(info_req_fixed_channels, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_INFO_FIXED_CHANNELS) };
	int i;

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_REQ, 0x21, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_INFO_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_INFO_FIXED_CHANNELS, cap_le16(&g_caps[0], 4));
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, cap_le16(&g_caps[0], 6));
	ATF_REQUIRE_EQ(8 + 8, g_caps[0].len);	/* hdr(4)+type(2)+res(2)+8 */
	ATF_CHECK_EQ(0x06, g_caps[0].data[8]);	/* octet 0: bits 1,2 set */
	for (i = 1; i < 8; i++)
		ATF_CHECK_EQ(0x00, g_caps[0].data[8 + i]);
}

/*
 * Regression guard: InfoType 0x0002 (Extended features supported).  Per
 * Vol 3 Part A Section 4.12 Table 4.12, "Fixed Channels
 * supported over BR/EDR" is feature No. 7 -> octet 0, bit 7, i.e. the
 * 32-bit little-endian feature mask value 0x00000080.  Bit 3 (mask value
 * 0x00000008) is "Enhanced Retransmission mode", which this stack does not
 * implement.
 */
ATF_TC_WITHOUT_HEAD(info_req_extended_features_mask_spec);
ATF_TC_HEAD(info_req_extended_features_mask_spec, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Extended feature mask Fixed-Channels bit is octet0/bit7 "
	    "(0x00000080) per Vol 3 Part A Sec 4.12 Table 4.12.");
}
ATF_TC_BODY(info_req_extended_features_mask_spec, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_INFO_EXTENDED_FEATURES) };

	/*
	 * Regression guard: the Extended Features mask advertises Fixed Channels
	 * (bit 7, 0x00000080) per Core Spec Vol 3 Part A §4.12 Table 4.12 -- not
	 * bit 3 (0x00000008 = Enhanced Retransmission mode, unimplemented).
	 */
	setup_con(NG_HCI_LINK_ACL, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_REQ, 0x22, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_INFO_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_INFO_EXTENDED_FEATURES, cap_le16(&g_caps[0], 4));
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, cap_le16(&g_caps[0], 6));
	ATF_REQUIRE(g_caps[0].len >= 12);
	ATF_CHECK_EQ(0x00000080, cap_le32(&g_caps[0], 8));
}

/*
 * Unsupported InfoType: Info Response with Result 0x0001 "Not supported"
 * (Table 4.10) and no Info data.
 */
ATF_TC_WITHOUT_HEAD(info_req_unknown_type_not_supported);
ATF_TC_BODY(info_req_unknown_type_not_supported, tc)
{
	static const u_int8_t p[] = { LE16(0x00ff) };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_REQ, 0x23, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_INFO_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x00ff, cap_le16(&g_caps[0], 4));		/* type echo */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_INFO_NOT_SUPPORTED, cap_le16(&g_caps[0], 6));
	ATF_CHECK_EQ(8, g_caps[0].len);				/* no Info */
}

/* ====================================================================== */
/* LE Connection Parameter Update (0x12/0x13) -- Sections 4.20/4.21      */
/* ====================================================================== */

/*
 * Valid L2CAP_CONNECTION_PARAMETER_UPDATE_REQ -> Response Result 0x0000
 * "Connection Parameters accepted" (Table 4.14).
 */
ATF_TC_WITHOUT_HEAD(le_param_update_accept);
ATF_TC_BODY(le_param_update_accept, tc)
{
	/* imin=16, imax=32, latency=0, timeout=100 (all in range) */
	static const u_int8_t p[] = {
		LE16(16), LE16(32), LE16(0), LE16(100)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ,
	    0x30, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_PARAM_UPDATE_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x30, g_caps[0].data[1]);
	ATF_CHECK_EQ(2, cap_le16(&g_caps[0], 2));		/* length = 2 */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_PARAM_UPDATE_ACCEPT, cap_le16(&g_caps[0], 4));
}

/*
 * A payload shorter than the fixed 8-octet parameter block is malformed,
 * so it receives Command Reject / Command not understood (Section 4.1).
 */
ATF_TC_WITHOUT_HEAD(le_param_update_reject_short);
ATF_TC_BODY(le_param_update_reject_short, tc)
{
	static const u_int8_t p[] = { LE16(16), LE16(32) };	/* only 4 */

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ,
	    0x31, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x31, g_caps[0].data[1]);
	ATF_CHECK_EQ(2, cap_le16(&g_caps[0], 2));
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD, cap_le16(&g_caps[0], 4));
}

/*
 * Out-of-range Interval_Min (< 6, i.e. < 7.5ms; Vol 6 Part B §2.4.2.16) ->
 * Response Result 0x0001 "rejected".
 */
ATF_TC_WITHOUT_HEAD(le_param_update_reject_range);
ATF_TC_BODY(le_param_update_reject_range, tc)
{
	/* imin=2 (invalid), imax=32, latency=0, timeout=100 */
	static const u_int8_t p[] = {
		LE16(2), LE16(32), LE16(0), LE16(100)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ,
	    0x32, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_PARAM_UPDATE_REJECT, cap_le16(&g_caps[0], 4));
}

/*
 * §4.20: "This command shall only be sent from the Peripheral to the Central
 * ... If a Peripheral's Host receives an L2CAP_CONNECTION_PARAMETER_UPDATE_REQ
 * packet it shall respond with an L2CAP_COMMAND_REJECT_RSP packet with reason
 * 0x0000 (Command not understood)."  With the local role = Peripheral
 * (NG_HCI_ROLE_SLAVE) an otherwise perfectly valid request MUST be answered
 * with a Command Reject, NOT a Connection Parameter Update Response, and the
 * parameters must NOT be forwarded to HCI.
 */
ATF_TC_WITHOUT_HEAD(le_param_update_wrong_role_rejected);
ATF_TC_BODY(le_param_update_wrong_role_rejected, tc)
{
	/* imin=16, imax=32, latency=0, timeout=100 (all in range) */
	static const u_int8_t p[] = {
		LE16(16), LE16(32), LE16(0), LE16(100)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	g_con.role = NG_HCI_ROLE_SLAVE;		/* we are the Peripheral */
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ,
	    0x34, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	/* Command Reject (0x01), not a Param Update Response (0x13). */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x34, g_caps[0].data[1]);			/* ident echo */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD, cap_le16(&g_caps[0], 4));
}

/*
 * §4.20 accept arm with the role made explicit: local role = Central
 * (NG_HCI_ROLE_MASTER) means we are the legitimate recipient, so a valid
 * request is processed and answered with a Connection Parameter Update
 * Response of Result 0x0000 "accepted".
 */
ATF_TC_WITHOUT_HEAD(le_param_update_central_role_accepted);
ATF_TC_BODY(le_param_update_central_role_accepted, tc)
{
	static const u_int8_t p[] = {
		LE16(16), LE16(32), LE16(0), LE16(100)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	g_con.role = NG_HCI_ROLE_MASTER;	/* we are the Central */
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ,
	    0x35, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_PARAM_UPDATE_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x35, g_caps[0].data[1]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_PARAM_UPDATE_ACCEPT, cap_le16(&g_caps[0], 4));
}

/* ====================================================================== */
/* LE Credit Based Connection (0x14/0x15) -- Sections 4.22/4.23         */
/* ====================================================================== */

/*
 * A valid request is held pending until the upper-layer listener answers;
 * hook presence alone must not emit success.
 */
ATF_TC_WITHOUT_HEAD(le_credit_con_req_success);
ATF_TC_BODY(le_credit_con_req_success, tc)
{
	/* Initial Credits=0 is explicitly legal for LE CoC (Section 4.22). */
	static const u_int8_t p[] = {
		LE16(0x0080), LE16(0x0045),
		LE16(128), LE16(128), LE16(0)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x40,
	    p, sizeof(p));

	ATF_CHECK_EQ(0, g_ncaps);
	ATF_REQUIRE(g_chan_head != NULL);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CA_CON_RSP, g_chan_head->state);
}

/* EATT SPSM 0x0027 is valid only with Enhanced Credit Based Flow Control. */
ATF_TC_WITHOUT_HEAD(le_credit_con_req_eatt_requires_ecbfc);
ATF_TC_BODY(le_credit_con_req_eatt_requires_ecbfc, tc)
{
	static const u_int8_t p[] = {
		LE16(NG_L2CAP_PSM_EATT), LE16(0x0045),
		LE16(128), LE16(128), LE16(4)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x46,
	    p, sizeof(p));
	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_SPSM_NOT_SUPPORTED,
	    cap_le16(&g_caps[0], 12));
}

/*
 * Unsupported SPSM (no matching service and no l2c hook): Result 0x0002
 * "Connection refused - SPSM not supported" (Table 4.16).
 */
ATF_TC_WITHOUT_HEAD(le_credit_con_req_spsm_unsupported);
ATF_TC_BODY(le_credit_con_req_spsm_unsupported, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0035), LE16(0x0045), LE16(128), LE16(128), LE16(4)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0 /* no hook */, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x41,
	    p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_SPSM_NOT_SUPPORTED, cap_le16(&g_caps[0], 12));
}

/*
 * MTU below the LE minimum of 23 octets (Section 4.22): Result 0x000B
 * "unacceptable parameters" (Table 4.16).
 */
ATF_TC_WITHOUT_HEAD(le_credit_con_req_unacceptable_params);
ATF_TC_BODY(le_credit_con_req_unacceptable_params, tc)
{
	/* mtu=16 (< 23) */
	static const u_int8_t p[] = {
		LE16(0x0080), LE16(0x0045),
		LE16(16), LE16(128), LE16(4)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x42,
	    p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_UNACCEPTABLE_PARAMS,
	    cap_le16(&g_caps[0], 12));
}

/*
 * Source CID outside the dynamic range (< 0x0040): Result 0x0009
 * "invalid Source CID" (Table 4.16).
 */
ATF_TC_WITHOUT_HEAD(le_credit_con_req_invalid_scid);
ATF_TC_BODY(le_credit_con_req_invalid_scid, tc)
{
	/* scid=0x0010 (invalid) */
	static const u_int8_t p[] = {
		LE16(0x0080), LE16(0x0010),
		LE16(128), LE16(128), LE16(4)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x43,
	    p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_INVALID_SOURCE_CID, cap_le16(&g_caps[0], 12));
}

/*
 * Link not encrypted: Result 0x0008 "insufficient encryption"
 * (Table 4.16).  (Local hardening policy; the value is a spec result code.)
 */
ATF_TC_WITHOUT_HEAD(le_credit_con_req_insufficient_encryption);
ATF_TC_BODY(le_credit_con_req_insufficient_encryption, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0080), LE16(0x0045),
		LE16(128), LE16(128), LE16(4)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 0 /* not encrypted */);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x44,
	    p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_INSUFF_ENCRYPTION, cap_le16(&g_caps[0], 12));
}

/* ====================================================================== */
/* Flow Control Credit (0x16) -- Section 4.24                            */
/* ====================================================================== */

/*
 * "The credit value field shall be a number between 1 and 65535"
 * (Section 4.24).  A zero-credit packet shall be ignored (no response,
 * no state change).
 */
ATF_TC_WITHOUT_HEAD(flow_control_credit_zero_ignored);
ATF_TC_BODY(flow_control_credit_zero_ignored, tc)
{
	static const u_int8_t p[] = { LE16(0x0045), LE16(0) };

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT, 0x50,
	    p, sizeof(p));

	ATF_CHECK_EQ(0, g_ncaps);
}

/*
 * Credit for a CID that maps to no channel: silently ignored.
 */
ATF_TC_WITHOUT_HEAD(flow_control_credit_unknown_channel_ignored);
ATF_TC_BODY(flow_control_credit_unknown_channel_ignored, tc)
{
	static const u_int8_t p[] = { LE16(0x0099), LE16(5) };

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT, 0x51,
	    p, sizeof(p));

	ATF_CHECK_EQ(0, g_ncaps);
}

/*
 * Valid credit for a known channel (looked up by the packet CID == our
 * DCID, Section 4.24): the remote credit counter increments by the credit
 * value.  No signalling response is emitted.
 */
ATF_TC_WITHOUT_HEAD(flow_control_credit_valid_increments);
ATF_TC_BODY(flow_control_credit_valid_increments, tc)
{
	static const u_int8_t p[] = { LE16(0x0045), LE16(5) };
	ng_l2cap_chan_p ch;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	ch = register_chan(0x0041, 0x0045, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	ch->credits_remote = 10;
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT, 0x52,
	    p, sizeof(p));

	ATF_CHECK_EQ(0, g_ncaps);
	ATF_CHECK_EQ(15, ch->credits_remote);
}

/* A peer CID is scoped to its logical link, not globally to the node. */
ATF_TC_WITHOUT_HEAD(flow_control_credit_connection_scoped);
ATF_TC_BODY(flow_control_credit_connection_scoped, tc)
{
	static const u_int8_t p[] = { LE16(0x0045), LE16(5) };
	struct ng_l2cap_con other;
	ng_l2cap_chan_p target, same_cid_other;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	target = register_chan(0x0041, 0x0045, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	target->credits_remote = 10;
	same_cid_other = register_chan(0x0042, 0x0045, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	other = g_con;
	other.con_handle++;
	same_cid_other->con = &other;
	same_cid_other->credits_remote = 20;

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_FLOW_CONTROL_CREDIT, 0x53,
	    p, sizeof(p));

	ATF_CHECK_EQ(15, target->credits_remote);
	ATF_CHECK_EQ_MSG(20, same_cid_other->credits_remote,
	    "credit leaked to a channel on another logical link");
}

/* ====================================================================== */
/* Enhanced Credit Based Connection (0x17/0x18) -- Sections 4.25/4.26    */
/* ====================================================================== */

/*
 * A valid ECBFC request creates the whole CID group pending; no atomic
 * success response is emitted until every upper-layer listener accepts.
 */
ATF_TC_WITHOUT_HEAD(ecred_con_req_success);
ATF_TC_BODY(ecred_con_req_success, tc)
{
	/* le_psm=EATT, mtu=128, mps=128, credits=4, scids=[0x45,0x46] */
	static const u_int8_t p[] = {
		LE16(NG_L2CAP_PSM_EATT), LE16(128), LE16(128), LE16(4),
		LE16(0x0045), LE16(0x0046)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ, 0x60,
	    p, sizeof(p));

	ATF_CHECK_EQ(0, g_ncaps);
	ATF_REQUIRE(g_chan_head != NULL && g_chan_head->reg_next != NULL);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CA_CON_RSP, g_chan_head->state);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CA_CON_RSP,
	    g_chan_head->reg_next->state);
}

/*
 * ECBFC request with MTU below the 64-octet minimum (Section 4.25):
 * Result 0x000B "unacceptable parameters" (Table 4.17); all DCIDs 0x0000.
 */
ATF_TC_WITHOUT_HEAD(ecred_con_req_unacceptable_params);
ATF_TC_BODY(ecred_con_req_unacceptable_params, tc)
{
	/* mtu=16 (< 64), one scid */
	static const u_int8_t p[] = {
		LE16(NG_L2CAP_PSM_EATT), LE16(16), LE16(128), LE16(4),
		LE16(0x0045)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ, 0x61,
	    p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_UNACCEPTABLE_PARAMS,
	    cap_le16(&g_caps[0], 10));
	ATF_CHECK_EQ(0x0000, cap_le16(&g_caps[0], 12));		/* DCID = 0 */
}

/*
 * ECBFC request too short to hold the fixed header plus one Source CID
 * (Section 4.25 requires the CID list be 2-10 octets): the frame is
 * dropped, no response.
 */
ATF_TC_WITHOUT_HEAD(ecred_con_req_too_short_dropped);
ATF_TC_BODY(ecred_con_req_too_short_dropped, tc)
{
	/* fixed header only (8 bytes), zero Source CIDs */
	static const u_int8_t p[] = {
		LE16(NG_L2CAP_PSM_EATT), LE16(128), LE16(128), LE16(4)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ, 0x62,
	    p, sizeof(p));

	ATF_CHECK_EQ(0, g_ncaps);
}

/* ====================================================================== */
/* ECBFC Reconfigure (0x19/0x1a) -- Sections 4.27/4.28                   */
/* ====================================================================== */

/*
 * Reconfigure request naming a DCID that is not an open ECBFC channel:
 * Result 0x0003 "one or more Destination CIDs invalid" (Table 4.18).
 */
ATF_TC_WITHOUT_HEAD(ecred_reconfig_req_invalid_dcid);
ATF_TC_BODY(ecred_reconfig_req_invalid_dcid, tc)
{
	/* mtu=128, mps=128, dcid=0x0045 (no such channel) */
	static const u_int8_t p[] = { LE16(128), LE16(128), LE16(0x0045) };

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ, 0x70,
	    p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP, g_caps[0].data[0]); /* 0x1a */
	ATF_CHECK_EQ(0x70, g_caps[0].data[1]);
	ATF_CHECK_EQ(2, cap_le16(&g_caps[0], 2));		/* length = 2 */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RECONFIG_INVALID_DCID, cap_le16(&g_caps[0], 4));
}

/*
 * Valid reconfigure raising the MTU on one open ECBFC channel:
 * Result 0x0000 "Reconfiguration successful" (Table 4.18); the channel's
 * outgoing MTU is updated to the requested value.
 */
ATF_TC_WITHOUT_HEAD(ecred_reconfig_req_success);
ATF_TC_BODY(ecred_reconfig_req_success, tc)
{
	/* new mtu=256, mps=256, dcid=0x0045 */
	static const u_int8_t p[] = { LE16(256), LE16(256), LE16(0x0045) };
	ng_l2cap_chan_p ch;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	ch = register_chan(0x0041, 0x0045, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	ch->omtu = 128;
	ch->mps_remote = 128;
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ, 0x71,
	    p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RECONFIG_SUCCESS, cap_le16(&g_caps[0], 4));
	ATF_CHECK_EQ(256, ch->omtu);
}

/*
 * Reconfigure attempting to REDUCE the MTU (256 -> 128): Result 0x0001
 * "reduction in size of MTU not allowed" (Table 4.18).
 */
ATF_TC_WITHOUT_HEAD(ecred_reconfig_req_mtu_reduction);
ATF_TC_BODY(ecred_reconfig_req_mtu_reduction, tc)
{
	/* new mtu=128 (< current 256) */
	static const u_int8_t p[] = { LE16(128), LE16(256), LE16(0x0045) };
	ng_l2cap_chan_p ch;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 0, 1);
	ch = register_chan(0x0041, 0x0045, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	ch->omtu = 256;
	ch->mps_remote = 256;
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ, 0x72,
	    p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RECONFIG_MTU_REDUCTION, cap_le16(&g_caps[0], 4));
}

/* ====================================================================== */
/* Config Request option-negotiation matrix -- §5.1 / Table 5.1           */
/* ====================================================================== */

/* Helper: drive a Config Request carrying a single raw option blob. */
static void
feed_cfg_req_opt(u_int16_t dcid, u_int16_t flags, u_int8_t ident,
    const u_int8_t *opt, int optlen)
{
	u_int8_t	buf[128];

	buf[0] = (u_int8_t)(dcid & 0xff);
	buf[1] = (u_int8_t)(dcid >> 8);
	buf[2] = (u_int8_t)(flags & 0xff);
	buf[3] = (u_int8_t)(flags >> 8);
	if (optlen > 0)
		memcpy(buf + 4, opt, (size_t)optlen);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_REQ, ident, buf, 4 + optlen);
}

/*
 * §5.1 / Table 5.1: a well-formed QoS option (type 0x03, length 22) is parsed
 * and accepted.  With the C flag set the decoder answers with a positive
 * (Result 0x0000) Config Response.  Exercises the QOS arm of the option parser.
 */
ATF_TC_WITHOUT_HEAD(cfg_req_qos_option_accepted);
ATF_TC_BODY(cfg_req_qos_option_accepted, tc)
{
	u_int8_t	opt[2 + 22];

	memset(opt, 0, sizeof(opt));
	opt[0] = BT_CORE63_L2CAP_OPTION_QOS;
	opt[1] = BT_CORE63_L2CAP_OPTION_QOS_VALUE_SIZE;		/* 22 */

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	(void)register_chan(0x0060, 0x0071, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	feed_cfg_req_opt(0x0060, 0x0001 /* C flag */, 0x20, opt, sizeof(opt));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONFIG_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, cap_le16(&g_caps[0], 8));
}

/*
 * §5.1: a Flush Timeout option (type 0x02, length 2) is parsed and accepted.
 */
ATF_TC_WITHOUT_HEAD(cfg_req_flush_option_accepted);
ATF_TC_BODY(cfg_req_flush_option_accepted, tc)
{
	u_int8_t	opt[] = { BT_CORE63_L2CAP_OPTION_FLUSH_TIMEOUT, 0x02, 0xff, 0xff };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	(void)register_chan(0x0060, 0x0071, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	feed_cfg_req_opt(0x0060, 0x0001, 0x21, opt, sizeof(opt));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONFIG_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, cap_le16(&g_caps[0], 8));
}

/*
 * §5.1: an MTU option with a wrong Length (4, must be 2) is malformed; the
 * decoder rejects the whole request with Result "Reject" (Table 5.2).
 */
ATF_TC_WITHOUT_HEAD(cfg_req_mtu_bad_length_reject);
ATF_TC_BODY(cfg_req_mtu_bad_length_reject, tc)
{
	u_int8_t	opt[] = { BT_CORE63_L2CAP_OPTION_MTU, 0x04, 0xa0, 0x02, 0x00, 0x00 };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	(void)register_chan(0x0060, 0x0071, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	feed_cfg_req_opt(0x0060, 0x0000, 0x22, opt, sizeof(opt));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONFIG_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CONFIG_REJECT, cap_le16(&g_caps[0], 8));
}

/*
 * §5.1: a QoS option with a wrong Length (4, must be 22) is malformed -> the
 * request is rejected with Result "Reject".
 */
ATF_TC_WITHOUT_HEAD(cfg_req_qos_bad_length_reject);
ATF_TC_BODY(cfg_req_qos_bad_length_reject, tc)
{
	u_int8_t	opt[] = { BT_CORE63_L2CAP_OPTION_QOS, 0x04, 0, 0, 0, 0 };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	(void)register_chan(0x0060, 0x0071, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	feed_cfg_req_opt(0x0060, 0x0000, 0x23, opt, sizeof(opt));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CONFIG_REJECT, cap_le16(&g_caps[0], 8));
}

/*
 * §5.1: an unknown option with the hint bit (MSB of Type) SET must be silently
 * ignored, not rejected.  With the C flag set the decoder still answers with a
 * positive Config Response.  Exercises the hint arm of the option parser.
 */
ATF_TC_WITHOUT_HEAD(cfg_req_hint_option_ignored);
ATF_TC_BODY(cfg_req_hint_option_ignored, tc)
{
	/* type = 0x80 | 0x10 (hint bit set), length 2, two value bytes. */
	u_int8_t	opt[] = { 0x90, 0x02, 0xaa, 0xbb };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	(void)register_chan(0x0060, 0x0071, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	feed_cfg_req_opt(0x0060, 0x0001, 0x24, opt, sizeof(opt));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONFIG_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, cap_le16(&g_caps[0], 8));
}

/*
 * §5.1: a hint option whose declared Length exceeds the option bytes present
 * is malformed even though it is a hint -> rejected with Result "Reject".
 */
ATF_TC_WITHOUT_HEAD(cfg_req_hint_option_bad_length_reject);
ATF_TC_BODY(cfg_req_hint_option_bad_length_reject, tc)
{
	/* hint type 0x90, claims length 10 but only 2 value bytes follow. */
	u_int8_t	opt[] = { 0x90, 0x0a, 0xaa, 0xbb };

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	(void)register_chan(0x0060, 0x0071, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	feed_cfg_req_opt(0x0060, 0x0000, 0x25, opt, sizeof(opt));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CONFIG_REJECT, cap_le16(&g_caps[0], 8));
}

/*
 * §5.1: an option tail shorter than the 2-octet option header is a truncated
 * options field -> the request is rejected with Result "Reject".
 */
ATF_TC_WITHOUT_HEAD(cfg_req_option_header_truncated_reject);
ATF_TC_BODY(cfg_req_option_header_truncated_reject, tc)
{
	u_int8_t	opt[] = { BT_CORE63_L2CAP_OPTION_MTU };	/* 1 byte: no length */

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	(void)register_chan(0x0060, 0x0071, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	feed_cfg_req_opt(0x0060, 0x0000, 0x26, opt, sizeof(opt));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CONFIG_REJECT, cap_le16(&g_caps[0], 8));
}

/* ====================================================================== */
/* Enhanced Credit Based Connection Request (0x17) source-CID list bounds  */
/* ====================================================================== */

/*
 * §4.25: the Enhanced Credit Based Connection Request Source CID list must be
 * an even octet count of 2..10 (1..5 CIDs).  A request carrying 6 Source CIDs
 * (a 12-octet list) exceeds the maximum and MUST be rejected before decode --
 * the on-stack scids[5] array must never be indexed at [5].  The decoder drops
 * the malformed request.  On LE the resulting 24-octet C-frame first exceeds
 * the mandatory 23-octet MTUsig, so the outer signalling guard rejects it
 * before the variable CID decoder can index the fixed array.
 */
ATF_TC_WITHOUT_HEAD(ecred_con_req_too_many_scids);
ATF_TC_BODY(ecred_con_req_too_many_scids, tc)
{
	/* le_psm, mtu, mps, credits, then SIX source CIDs (12 octets). */
	static const u_int8_t p[] = {
		LE16(NG_L2CAP_PSM_EATT), LE16(64), LE16(64), LE16(4),
		LE16(0x0041), LE16(0x0042), LE16(0x0043),
		LE16(0x0044), LE16(0x0045), LE16(0x0046)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ, 0x50,
	    p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_caps[0].data[0]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_SIGNAL_MTU_EXCEEDED, cap_le16(&g_caps[0], 4));
	ATF_CHECK_EQ(NG_L2CAP_MTU_LE_MINIMUM, cap_le16(&g_caps[0], 6));
}

/*
 * §4.25: an ODD Source CID list length is also malformed (CIDs are 2 octets
 * each).  A request whose list is 3 octets long MUST be rejected before decode
 * rather than parsed as a truncated CID.
 */
ATF_TC_WITHOUT_HEAD(ecred_con_req_odd_scid_list);
ATF_TC_BODY(ecred_con_req_odd_scid_list, tc)
{
	/* le_psm, mtu, mps, credits (8 octets) + a 3-octet (odd) CID tail. */
	static const u_int8_t p[] = {
		LE16(NG_L2CAP_PSM_EATT), LE16(64), LE16(64), LE16(4),
		0x41, 0x00, 0x42
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ, 0x51,
	    p, sizeof(p));

	ATF_CHECK_EQ(0, g_ncaps);
}

/* ====================================================================== */
/* Config Request unknown-option length validation -- §5.1                 */
/* ====================================================================== */

/*
 * §5.1: an unrecognised non-hint configuration option is echoed back in the
 * Config Response with Result "Unknown Option".  A hostile peer can set the
 * option's Length field far larger than the option value bytes actually
 * present.  The decoder must NOT advertise (nor copy) more bytes than are
 * really there: the emitted Config Response's command Length field must equal
 * the real payload it carries.  (Regression: using the attacker's Length
 * verbatim inflates m_pkthdr.len and over-reads past the received option.)
 */
ATF_TC_WITHOUT_HEAD(cfg_req_unknown_option_bogus_length);
ATF_TC_BODY(cfg_req_unknown_option_bogus_length, tc)
{
	/*
	 * dcid=0x0060, flags=0, unknown option type=0x10 with a claimed
	 * length of 0xff but only 2 value bytes (aa bb) actually present.
	 */
	static const u_int8_t p[] = {
		LE16(0x0060), LE16(0x0000),
		0x10, 0xff, 0xaa, 0xbb
	};
	u_int16_t	rsp_len;

	setup_con(NG_HCI_LINK_ACL, 0, 1);
	(void)register_chan(0x0060, 0x0071, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x0c, p, sizeof(p));

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_CONFIG_RSP, g_caps[0].data[0]);
	ATF_CHECK_EQ(0x0c, g_caps[0].data[1]);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CONFIG_UNKNOWN_OPTION, cap_le16(&g_caps[0], 8));

	/*
	 * The command Length field (offset 2) counts every byte after the
	 * 4-octet L2CAP command header.  The regression is that the peer's
	 * bogus option Length (0xff) inflated it: the decoder advertised (and,
	 * in the kernel, m_cat-copied) far more bytes than were received.  The
	 * fix clamps the echoed option to the value bytes actually present, so
	 * the Length field must not exceed the bytes truly carried
	 * (g_caps[0].len - 4).  Concretely: Config-Rsp fixed part (6) + option
	 * header (2) + the 2 real value bytes = 10.
	 */
	rsp_len = cap_le16(&g_caps[0], 2);
	ATF_CHECK(rsp_len <= (u_int16_t)(g_caps[0].len - 4));
	ATF_CHECK_EQ(10, rsp_len);
	/* The offending option type is still echoed back (§5.1). */
	ATF_CHECK_EQ(0x10, g_caps[0].data[10]);
}

/* ====================================================================== */

ATF_TC_WITHOUT_HEAD(signal_allocation_failure_matrix);
ATF_TC_BODY(signal_allocation_failure_matrix, tc)
{
	static const u_int8_t coc[] = {
		LE16(0x0080), LE16(0x0045),
		LE16(128), LE16(128), LE16(4)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	g_cmd_alloc_fail = 1;
	ATF_CHECK_EQ(ENOMEM, send_l2cap_reject(&g_con, 1, 0, 0, 0, 0));
	g_cmd_alloc_fail = 1;
	ATF_CHECK_EQ(ENOMEM, send_l2cap_con_rej(&g_con, 1, 1, 2, 0));
	g_cmd_alloc_fail = 1;
	ATF_CHECK_EQ(ENOMEM, send_l2cap_cfg_rsp(&g_con, 1, 1, 0, NULL));
	g_cmd_alloc_fail = 1;
	ATF_CHECK_EQ(ENOMEM, send_l2cap_param_urs(&g_con, 1, 0));

	g_mbuf_alloc_fail = 1;
	ATF_CHECK_EQ(ENOBUFS, send_l2cap_reject(&g_con, 2, 0, 0, 0, 0));
	g_mbuf_alloc_fail = 1;
	ATF_CHECK_EQ(ENOBUFS, send_l2cap_con_rej(&g_con, 2, 1, 2, 0));
	g_mbuf_alloc_fail = 1;
	ATF_CHECK_EQ(ENOBUFS, send_l2cap_cfg_rsp(&g_con, 2, 1, 0, NULL));
	g_mbuf_alloc_fail = 1;
	ATF_CHECK_EQ(ENOBUFS, send_l2cap_param_urs(&g_con, 2, 0));

	/* A channel-allocation failure becomes a wire-level NO_RESOURCES reply. */
	g_chan_alloc_fail = 1;
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ,
	    0x71, coc, sizeof(coc));
	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_MSG(BT_CORE63_L2CAP_CREDIT_NO_RESOURCES ==
	    cap_le16(&g_caps[0], 12), "unexpected LE CoC result %#x",
	    cap_le16(&g_caps[0], 12));
}

ATF_TC_WITHOUT_HEAD(response_opcode_no_pending_matrix);
ATF_TC_BODY(response_opcode_no_pending_matrix, tc)
{
	static const struct {
		u_int16_t cid;
		u_int8_t code;
		u_int8_t payload[10];
		u_int8_t len;
	} cases[] = {
		{ BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT,
		    { LE16(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD) }, 2 },
		{ BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP,
		    { LE16(0x0040), LE16(0x0041), LE16(0), LE16(0) }, 8 },
		{ BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP,
		    { LE16(0x0040), LE16(0), LE16(0) }, 6 },
		{ BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_RSP,
		    { LE16(0x0040), LE16(0x0041) }, 4 },
		{ BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECHO_RSP, { 0 }, 0 },
		{ BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_RSP,
		    { LE16(BT_CORE63_L2CAP_INFO_CONNECTIONLESS_MTU), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS) }, 4 },
		{ BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
		    { LE16(128), LE16(64), LE16(4), LE16(0) }, 8 },
		{ BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP,
		    { LE16(0) }, 2 },
		{ BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT,
		    { LE16(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD) }, 2 },
		{ BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_RSP,
		    { LE16(0x0040), LE16(0x0041) }, 4 },
		{ BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
		    { LE16(128), LE16(64), LE16(4), LE16(0) }, 8 },
		{ BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP,
		    { LE16(0) }, 2 },
	};
	size_t i;

	/* Unsolicited responses are parsed and discarded without state changes. */
	for (i = 0; i < nitems(cases); i++) {
		setup_con(cases[i].cid == BT_CORE63_L2CAP_CID_SIGNAL ?
		    NG_HCI_LINK_ACL : NG_HCI_LINK_LE_PUBLIC, 0, 1);
		feed_ok(cases[i].cid, cases[i].code, (u_int8_t)(0x80 + i),
		    cases[i].payload, cases[i].len);
		ATF_CHECK_EQ_MSG(NULL, g_con.rx_pkt,
		    "case %zu left the receive mbuf owned", i);
		ATF_CHECK_EQ(0, g_ncaps);
	}
}

/* ====================================================================== */

ATF_TP_ADD_TCS(tp)
{
	/* Command Reject (0x01) */
	ATF_TP_ADD_TC(tp, cmd_reject_unknown_code_bredr);
	ATF_TP_ADD_TC(tp, cmd_reject_unknown_code_le);
	ATF_TP_ADD_TC(tp, cmd_reject_le_multiple_commands);
	ATF_TP_ADD_TC(tp, cmd_reject_bredr_fixed_command_trailing_payload);
	ATF_TP_ADD_TC(tp, cmd_reject_le_fixed_command_trailing_payload);
	ATF_TP_ADD_TC(tp, cmd_reject_oversized_cframe_bredr);
	ATF_TP_ADD_TC(tp, cmd_reject_oversized_cframe_le);
	ATF_TP_ADD_TC(tp, malformed_l2cap_length_mismatch_dropped);
	ATF_TP_ADD_TC(tp, bredr_signal_cid_on_le_link_dropped);

	/* Connection Request/Response (0x02/0x03) */
	ATF_TP_ADD_TC(tp, con_req_invalid_source_cid);
	ATF_TP_ADD_TC(tp, con_req_psm_not_supported);
	ATF_TP_ADD_TC(tp, con_req_source_cid_already_allocated);

	/* Configuration Request/Response (0x04/0x05) */
	ATF_TP_ADD_TC(tp, cfg_req_unknown_channel_reject);
	ATF_TP_ADD_TC(tp, cfg_req_reject_cid_order_spec);
	ATF_TP_ADD_TC(tp, cfg_req_cflag_success);
	ATF_TP_ADD_TC(tp, cfg_req_unknown_option);

	/* Disconnection Request/Response (0x06/0x07) */
	ATF_TP_ADD_TC(tp, discon_req_unknown_channel_reject);
	ATF_TP_ADD_TC(tp, discon_req_match_response);

	/* Echo Request/Response (0x08/0x09) */
	ATF_TP_ADD_TC(tp, echo_req_response);

	/* Information Request/Response (0x0a/0x0b) */
	ATF_TP_ADD_TC(tp, info_req_connless_mtu);
	ATF_TP_ADD_TC(tp, info_req_fixed_channels);
	ATF_TP_ADD_TC(tp, info_req_extended_features_mask_spec);
	ATF_TP_ADD_TC(tp, info_req_unknown_type_not_supported);

	/* LE Connection Parameter Update (0x12/0x13) */
	ATF_TP_ADD_TC(tp, le_param_update_accept);
	ATF_TP_ADD_TC(tp, le_param_update_reject_short);
	ATF_TP_ADD_TC(tp, le_param_update_reject_range);
	ATF_TP_ADD_TC(tp, le_param_update_wrong_role_rejected);
	ATF_TP_ADD_TC(tp, le_param_update_central_role_accepted);

	/* LE Credit Based Connection (0x14/0x15) */
	ATF_TP_ADD_TC(tp, le_credit_con_req_success);
	ATF_TP_ADD_TC(tp, le_credit_con_req_eatt_requires_ecbfc);
	ATF_TP_ADD_TC(tp, le_credit_con_req_spsm_unsupported);
	ATF_TP_ADD_TC(tp, le_credit_con_req_unacceptable_params);
	ATF_TP_ADD_TC(tp, le_credit_con_req_invalid_scid);
	ATF_TP_ADD_TC(tp, le_credit_con_req_insufficient_encryption);

	/* Flow Control Credit (0x16) */
	ATF_TP_ADD_TC(tp, flow_control_credit_zero_ignored);
	ATF_TP_ADD_TC(tp, flow_control_credit_unknown_channel_ignored);
	ATF_TP_ADD_TC(tp, flow_control_credit_valid_increments);
	ATF_TP_ADD_TC(tp, flow_control_credit_connection_scoped);

	/* Enhanced Credit Based Connection (0x17/0x18) */
	ATF_TP_ADD_TC(tp, ecred_con_req_success);
	ATF_TP_ADD_TC(tp, ecred_con_req_unacceptable_params);
	ATF_TP_ADD_TC(tp, ecred_con_req_too_short_dropped);
	ATF_TP_ADD_TC(tp, ecred_con_req_too_many_scids);
	ATF_TP_ADD_TC(tp, ecred_con_req_odd_scid_list);

	/* Config Request unknown-option length validation (§5.1) */
	ATF_TP_ADD_TC(tp, cfg_req_unknown_option_bogus_length);

	/* Config Request option-negotiation matrix (§5.1) */
	ATF_TP_ADD_TC(tp, cfg_req_qos_option_accepted);
	ATF_TP_ADD_TC(tp, cfg_req_flush_option_accepted);
	ATF_TP_ADD_TC(tp, cfg_req_mtu_bad_length_reject);
	ATF_TP_ADD_TC(tp, cfg_req_qos_bad_length_reject);
	ATF_TP_ADD_TC(tp, cfg_req_hint_option_ignored);
	ATF_TP_ADD_TC(tp, cfg_req_hint_option_bad_length_reject);
	ATF_TP_ADD_TC(tp, cfg_req_option_header_truncated_reject);

	/* ECBFC Reconfigure (0x19/0x1a) */
	ATF_TP_ADD_TC(tp, ecred_reconfig_req_invalid_dcid);
	ATF_TP_ADD_TC(tp, ecred_reconfig_req_success);
	ATF_TP_ADD_TC(tp, ecred_reconfig_req_mtu_reduction);
	ATF_TP_ADD_TC(tp, signal_allocation_failure_matrix);
	ATF_TP_ADD_TC(tp, response_opcode_no_pending_matrix);

	return (atf_no_error());
}
