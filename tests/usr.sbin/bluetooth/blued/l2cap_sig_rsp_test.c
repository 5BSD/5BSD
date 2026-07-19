/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Assertion-based (known-answer) ATF tests for the kernel L2CAP signalling
 * *response* handlers in sys/netgraph/bluetooth/l2cap/ng_l2cap_evnt.c.
 *
 * The companion program l2cap_sig_test.c exercises the *request* decoders,
 * which build and emit a reply PDU single-shot.  The ten RESPONSE handlers
 *
 *     process_cmd_rej           (L2CAP_COMMAND_REJECT_RSP,      code 0x01)
 *     process_cmd_urs           (L2CAP_CONN_PARAM_UPDATE_RSP,   code 0x13)
 *     process_con_rsp           (L2CAP_CONNECTION_RSP,          code 0x03)
 *     process_cfg_rsp           (L2CAP_CONFIGURATION_RSP,       code 0x05)
 *     process_discon_rsp        (L2CAP_DISCONNECTION_RSP,       code 0x07)
 *     process_echo_rsp          (L2CAP_ECHO_RSP,                code 0x09)
 *     process_info_rsp          (L2CAP_INFORMATION_RSP,         code 0x0b)
 *     process_le_credit_con_rsp (L2CAP_LE_CREDIT_BASED_CON_RSP, code 0x15)
 *     process_credit_con_rsp    (L2CAP_CREDIT_BASED_CON_RSP,    code 0x18)
 *     process_credit_reconfig_rsp(L2CAP_CREDIT_BASED_RECONF_RSP,code 0x1a)
 *
 * cannot be reached single-shot, because each one first calls
 * ng_l2cap_cmd_by_ident() to find the OUTSTANDING request we sent and
 * early-returns when none exists.  l2cap_sig_test.c stubs that lookup to
 * always return NULL, so it only proves the early return.
 *
 * This program supplies the missing multi-step state: before feeding a
 * response C-frame it seeds a matching outstanding command with
 * ng_l2cap_new_cmd()+ng_l2cap_link_cmd() and (where the handler dereferences
 * it) a channel with the matching scid/dcid/state.  ng_l2cap_cmd_by_ident()
 * here searches that seeded registry.  Each case then asserts the handler's
 * result-processing: channel state transition, the LP_ConnectCfm /
 * ConfigCfm / DisconCfm delivered to the upper layer (captured via the
 * l2ca_* stubs), the RTX/ERTX timeout-callout cancel/restart, and the
 * command being dequeued/freed.  Expected behaviour is taken from the Core
 * Spec Vol 3 Part A (/usr/src/bluetooth-specs/Core_Specification_6_3.txt),
 * cited per case, NEVER captured from the decoder's current output.
 *
 * Technique/shim is inherited from l2cap_sig_test.c: #include the kernel TU
 * ng_l2cap_evnt.c to reach the static process_*() handlers, neutralise the
 * kernel-only headers via their include guards, and supply a userspace
 * malloc-backed mbuf plus netgraph stubs.  The stubs here additionally
 * RECORD the upper-layer notifications and the free/timeout calls so each
 * test can assert them.
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
	u_int8_t	 test_freed;		/* test-only: set by free_chan */
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
	u_int8_t	 test_freed;		/* test-only: set by free_cmd */
	struct ng_l2cap_cmd	*reg_next;
} ng_l2cap_cmd_t;
typedef ng_l2cap_cmd_t *	ng_l2cap_cmd_p;

/* ---------------------------------------------------------------------- */
/* Per-test channel/command registries (mirrors the fuzzer). */
static ng_l2cap_chan_p	g_chan_head;
static ng_l2cap_cmd_p	g_cmd_head;
static u_int16_t	g_next_scid;

static int		g_con_ind_error;

/* ---------------------------------------------------------------------- */
/*
 * Captured emitted PDUs (used only by the reject/mismatch cases that build a
 * L2CAP_CommandRej).  Same capture mechanism as l2cap_sig_test.c.
 */
struct captured_pdu {
	u_int8_t	code;
	u_int8_t	ident;
	int		len;
	u_int8_t	data[600];
};
#define MAX_CAPTURES	16
static struct captured_pdu	g_caps[MAX_CAPTURES];
static int			g_ncaps;

static u_int16_t
cap_le16(const struct captured_pdu *c, int off)
{

	return ((u_int16_t)(c->data[off] | (c->data[off + 1] << 8)));
}

/* ---------------------------------------------------------------------- */
/*
 * Recorded upper-layer notifications.  Each of the L2CA_* confirm/indication
 * stubs writes its arguments here so a test can assert the result code and
 * token the handler forwarded.
 */
struct ul_rec {
	int		n;		/* number of calls */
	ng_l2cap_chan_p	ch;
	ng_l2cap_con_p	con;
	u_int32_t	token;
	u_int16_t	result;
	u_int16_t	status;
};
static struct ul_rec	r_con_rsp;	/* ng_l2cap_l2ca_con_rsp */
static struct ul_rec	r_cfg_rsp;	/* ng_l2cap_l2ca_cfg_rsp */
static struct ul_rec	r_discon_rsp;	/* ng_l2cap_l2ca_discon_rsp */
static struct ul_rec	r_ping_rsp;	/* ng_l2cap_l2ca_ping_rsp */
static struct ul_rec	r_info_rsp;	/* ng_l2cap_l2ca_get_info_rsp */

/* Return-value knobs so the error paths of the L2CA_* stubs are reachable. */
static int		g_con_rsp_ret;
static int		g_cfg_rsp_ret;
static int		g_discon_rsp_ret;
static int		g_ping_rsp_ret;
static int		g_info_rsp_ret;

/* Timer-callout accounting. */
static int		g_untimeout_ret;	/* forced return of untimeout */
static int		g_untimeout_n;		/* # of untimeout calls */
static int		g_timeout_n;		/* # of (re)start-timeout calls */

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

/*
 * Test-only free: unlink from the registry and MARK the descriptor freed,
 * but intentionally leak the memory so a case can still inspect the final
 * state / freed-flag after the handler returns.  A fresh short-lived test
 * process makes the leak irrelevant.
 */
static void
ng_l2cap_free_chan(ng_l2cap_chan_p ch)
{

	if (ch == NULL)
		return;
	ng_fuzz_chan_unlink(ch);
	ch->test_freed = 1;
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

/* Test-only free: unlink + mark, memory intentionally leaked (see above). */
static void
ng_l2cap_free_cmd(ng_l2cap_cmd_p cmd)
{

	if (cmd == NULL)
		return;
	ng_fuzz_cmd_unlink(cmd);
	cmd->test_freed = 1;
}

/*
 * Capture the emitted PDU (built into cmd->aux) then queue it.  Seeded
 * outstanding commands have aux == NULL and are simply linked.
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

/*
 * The crucial difference from l2cap_sig_test.c: return the seeded
 * outstanding command matching @ident instead of always NULL.
 */
static ng_l2cap_cmd_p
ng_l2cap_cmd_by_ident(ng_l2cap_con_p con, u_int8_t ident)
{
	ng_l2cap_cmd_p	cmd;

	for (cmd = g_cmd_head; cmd != NULL; cmd = cmd->reg_next)
		if (cmd->con == con && cmd->ident == ident)
			return (cmd);
	return (NULL);
}

static int
ng_l2cap_command_untimeout(ng_l2cap_cmd_p cmd)
{

	(void)cmd;
	g_untimeout_n++;
	return (g_untimeout_ret);
}

static int
ng_l2cap_command_timeout(ng_l2cap_cmd_p cmd, int timo)
{

	(void)cmd;
	(void)timo;
	g_timeout_n++;
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

	r_con_rsp.n++;
	r_con_rsp.ch = ch;
	r_con_rsp.token = token;
	r_con_rsp.result = result;
	r_con_rsp.status = status;
	return (g_con_rsp_ret);
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

	r_discon_rsp.n++;
	r_discon_rsp.ch = ch;
	r_discon_rsp.token = token;
	r_discon_rsp.result = result;
	return (g_discon_rsp_ret);
}

static int
ng_l2cap_l2ca_cfg_rsp(ng_l2cap_chan_p ch, u_int32_t token, u_int16_t result)
{

	r_cfg_rsp.n++;
	r_cfg_rsp.ch = ch;
	r_cfg_rsp.token = token;
	r_cfg_rsp.result = result;
	return (g_cfg_rsp_ret);
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

	r_ping_rsp.n++;
	r_ping_rsp.con = con;
	r_ping_rsp.token = token;
	r_ping_rsp.result = result;
	NG_FREE_M(m);
	return (g_ping_rsp_ret);
}

static int
ng_l2cap_l2ca_get_info_rsp(ng_l2cap_con_p con, u_int32_t token,
    u_int16_t result, struct mbuf *m)
{

	r_info_rsp.n++;
	r_info_rsp.con = con;
	r_info_rsp.token = token;
	r_info_rsp.result = result;
	NG_FREE_M(m);
	return (g_info_rsp_ret);
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

	return (3);
}

uint32_t
bluetooth_l2cap_ertx_timeout(void)
{

	return (7);
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

	memset(g_caps, 0, sizeof(g_caps));
	g_ncaps = 0;
	memset(&r_con_rsp, 0, sizeof(r_con_rsp));
	memset(&r_cfg_rsp, 0, sizeof(r_cfg_rsp));
	memset(&r_discon_rsp, 0, sizeof(r_discon_rsp));
	memset(&r_ping_rsp, 0, sizeof(r_ping_rsp));
	memset(&r_info_rsp, 0, sizeof(r_info_rsp));
	g_con_rsp_ret = g_cfg_rsp_ret = g_discon_rsp_ret = 0;
	g_ping_rsp_ret = g_info_rsp_ret = 0;
	g_untimeout_ret = 0;
	g_untimeout_n = 0;
	g_timeout_n = 0;

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
 * Seed an OUTSTANDING command the way ng_l2cap_l2ca_*_req() would after
 * transmitting a request: allocate, set flags, link into the tx queue.  aux
 * is NULL so ng_l2cap_link_cmd() just queues it (no capture).
 */
static ng_l2cap_cmd_p
seed_cmd(ng_l2cap_chan_p ch, u_int8_t ident, u_int8_t code, u_int32_t token,
    u_int16_t flags)
{
	ng_l2cap_cmd_p	cmd;

	cmd = ng_l2cap_new_cmd(&g_con, ch, ident, code, token);
	ATF_REQUIRE(cmd != NULL);
	cmd->flags = flags;
	ng_l2cap_link_cmd(&g_con, cmd);
	return (cmd);
}

/*
 * Build one L2CAP C-frame and drive it through ng_l2cap_receive().
 * See l2cap_sig_test.c feed() for the length-field semantics.
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

static void
feed_ok(u_int16_t dcid, u_int8_t code, u_int8_t ident,
    const u_int8_t *payload, int plen)
{

	feed(dcid, code, ident, payload, plen, -1, -1);
}

/* Assert the single captured PDU is a Command Reject with @reason. */
static void
expect_cmd_rej(u_int8_t ident, u_int16_t reason)
{

	ATF_REQUIRE_EQ(1, g_ncaps);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CMD_REJECT, g_caps[0].data[0]);
	ATF_CHECK_EQ(ident, g_caps[0].data[1]);
	ATF_CHECK_EQ(reason, cap_le16(&g_caps[0], 4));
}

/* le16 into a little-endian byte pair */
#define LE16(v)		(u_int8_t)((v) & 0xff), (u_int8_t)(((v) >> 8) & 0xff)

/* ====================================================================== */
/* L2CAP_COMMAND_REJECT_RSP (0x01) -- Core Spec Vol 3 Part A Section 4.1  */
/* ====================================================================== */

/*
 * Command Reject for a pending L2CAP_CONNECTION_REQ.  Section 4.1: the
 * rejecting peer returns the request's Identifier; our side matches the
 * outstanding command by that Identifier and reports the failure up.  The
 * decoder maps a rejected CON_REQ to an L2CA_ConnectCfm carrying the reject
 * Reason and tears the half-open channel down.
 */
ATF_TC_WITHOUT_HEAD(cmd_rej_con_req_bredr);
ATF_TC_BODY(cmd_rej_con_req_bredr, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_REJECT_INVALID_CID) };
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x31, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0xaa, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, 0x31, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);			/* RTX cancelled */
	ATF_CHECK_EQ(1, r_con_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_INVALID_CID, r_con_rsp.result);
	ATF_CHECK_EQ(0xaa, r_con_rsp.token);
	ATF_CHECK(ch->test_freed);			/* channel torn down */
	ATF_CHECK(cmd->test_freed);			/* command dequeued */
}

/*
 * Command Reject for a pending L2CAP_CONFIGURATION_REQ (Section 4.1): the
 * decoder maps it to an L2CA_ConfigCfm carrying the Reason.  Unlike CON_REQ,
 * the channel is NOT freed (configuration reject does not close the channel).
 */
ATF_TC_WITHOUT_HEAD(cmd_rej_cfg_req_bredr);
ATF_TC_BODY(cmd_rej_cfg_req_bredr, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD) };
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0042, 0x0056, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x32, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0xbb, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, 0x32, p, sizeof(p));

	ATF_CHECK_EQ(1, r_cfg_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD, r_cfg_rsp.result);
	ATF_CHECK_EQ(0, r_con_rsp.n);
	ATF_CHECK(!ch->test_freed);
	ATF_CHECK(cmd->test_freed);
}

/*
 * Command Reject for a pending L2CAP_DISCONNECTION_REQ (Section 4.1): mapped
 * to L2CA_DisconnectCfm with the Reason; the channel is freed.
 */
ATF_TC_WITHOUT_HEAD(cmd_rej_discon_req_bredr);
ATF_TC_BODY(cmd_rej_discon_req_bredr, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_REJECT_INVALID_CID) };
	ng_l2cap_chan_p	ch;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0043, 0x0057, NG_L2CAP_W4_L2CAP_DISCON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	(void)seed_cmd(ch, 0x33, BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, 0xcc, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, 0x33, p, sizeof(p));

	ATF_CHECK_EQ(1, r_discon_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_INVALID_CID, r_discon_rsp.result);
	ATF_CHECK(ch->test_freed);
}

/*
 * Command Reject for a pending L2CAP_ECHO_REQ (Section 4.1): mapped to an
 * L2CA_PingCfm carrying the Reason (no channel involved).
 */
ATF_TC_WITHOUT_HEAD(cmd_rej_echo_req_bredr);
ATF_TC_BODY(cmd_rej_echo_req_bredr, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD) };
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	cmd = seed_cmd(NULL, 0x34, BT_CORE63_L2CAP_CMD_ECHO_REQ, 0xdd, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, 0x34, p, sizeof(p));

	ATF_CHECK_EQ(1, r_ping_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD, r_ping_rsp.result);
	ATF_CHECK_EQ(0xdd, r_ping_rsp.token);
	ATF_CHECK(cmd->test_freed);
}

/*
 * Command Reject for a pending L2CAP_INFORMATION_REQ (Section 4.1): mapped to
 * an L2CA_GetInfoCfm carrying the Reason.
 */
ATF_TC_WITHOUT_HEAD(cmd_rej_info_req_bredr);
ATF_TC_BODY(cmd_rej_info_req_bredr, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD) };
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	cmd = seed_cmd(NULL, 0x35, BT_CORE63_L2CAP_CMD_INFO_REQ, 0xee, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, 0x35, p, sizeof(p));

	ATF_CHECK_EQ(1, r_info_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD, r_info_rsp.result);
	ATF_CHECK(cmd->test_freed);
}

/*
 * Command Reject arriving after the RTX guard timer already fired: the
 * decoder must IGNORE the late reject (the request has already been failed
 * by timeout).  It detects this because ng_l2cap_command_untimeout() reports
 * the callout could not be stopped (returns non-zero), so it leaves the
 * command in place and delivers nothing.  (Section 4.1 return semantics.)
 */
ATF_TC_WITHOUT_HEAD(cmd_rej_timeout_ignored);
ATF_TC_BODY(cmd_rej_timeout_ignored, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_REJECT_INVALID_CID) };
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0044, 0x0058, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x36, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x11, NG_L2CAP_CMD_PENDING);
	g_untimeout_ret = ETIMEDOUT;

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, 0x36, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);
	ATF_CHECK_EQ(0, r_con_rsp.n);		/* nothing delivered */
	ATF_CHECK(!ch->test_freed);
	ATF_CHECK(!cmd->test_freed);		/* command left in place */
}

/*
 * Command Reject is valid on the LE signalling channel (CID 0x0005) too --
 * Vol 3 Part A Table 4.2 lists code 0x01 on both 0x0001 and 0x0005.  Reject
 * of a pending LE Credit Based Connection Request maps to L2CA_ConnectCfm.
 */
ATF_TC_WITHOUT_HEAD(cmd_rej_le_credit_le);
ATF_TC_BODY(cmd_rej_le_credit_le, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD) };
	ng_l2cap_chan_p	ch;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0045, 0x0050, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	(void)seed_cmd(ch, 0x37, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x22,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_REJECT, 0x37, p, sizeof(p));

	ATF_CHECK_EQ(1, r_con_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_REJECT_NOT_UNDERSTOOD, r_con_rsp.result);
	ATF_CHECK(ch->test_freed);
}

/* ====================================================================== */
/* L2CAP_CONNECTION_PARAMETER_UPDATE_RSP (0x13) -- Section 4.21 (LE)      */
/* ====================================================================== */

/*
 * A Connection Parameter Update Response acknowledges our earlier Request
 * (Section 4.21, sent Peripheral->Central).  With the RTX timer pending, the
 * decoder cancels it and dequeues the outstanding command.  No upper-layer
 * confirm PDU is defined for this command in this stack.
 */
ATF_TC_WITHOUT_HEAD(cmd_urs_match_pending_le);
ATF_TC_BODY(cmd_urs_match_pending_le, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_PARAM_UPDATE_ACCEPT) };
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	cmd = seed_cmd(NULL, 0x40, BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ, 0x33,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_PARAM_UPDATE_RSP,
	    0x40, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);		/* pending => RTX cancelled */
	ATF_CHECK(cmd->test_freed);
}

/*
 * Same, but the outstanding command has no PENDING flag set (its RTX guard
 * was never armed): the decoder must NOT touch the callout, only dequeue the
 * command.  (Section 4.21; guards the flags & PENDING branch.)
 */
ATF_TC_WITHOUT_HEAD(cmd_urs_match_no_pending_flag_le);
ATF_TC_BODY(cmd_urs_match_no_pending_flag_le, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_PARAM_UPDATE_ACCEPT) };
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	cmd = seed_cmd(NULL, 0x41, BT_CORE63_L2CAP_CMD_PARAM_UPDATE_REQ, 0x34, 0);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_PARAM_UPDATE_RSP,
	    0x41, p, sizeof(p));

	ATF_CHECK_EQ(0, g_untimeout_n);		/* no pending => no cancel */
	ATF_CHECK(cmd->test_freed);
}

/*
 * Parameter Update Response with no matching outstanding Request: the decoder
 * silently discards it (Section 4.21; the early ng_l2cap_cmd_by_ident() miss).
 */
ATF_TC_WITHOUT_HEAD(cmd_urs_no_match_le);
ATF_TC_BODY(cmd_urs_no_match_le, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_PARAM_UPDATE_ACCEPT) };

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_PARAM_UPDATE_RSP,
	    0x42, p, sizeof(p));

	ATF_CHECK_EQ(0, g_untimeout_n);
	ATF_CHECK_EQ(0, g_ncaps);
}

/*
 * A Parameter Update Response whose Identifier collides with an unrelated
 * pending command must NOT complete it.  cmd_by_ident() matches by Identifier
 * alone (Vol 3 Part A §4); only a command whose code is the Parameter Update
 * Request this response answers may be consumed.  Dropping the
 * cmd->code == CMD_PARAM_UPDATE_REQUEST check would let this response free a
 * colliding Connection Request.  Correct behaviour: ignored, command intact.
 */
ATF_TC_WITHOUT_HEAD(cmd_urs_ident_collides_con_req_le);
ATF_TC_BODY(cmd_urs_ident_collides_con_req_le, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_PARAM_UPDATE_ACCEPT) };
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	cmd = seed_cmd(NULL, 0x43, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x5a, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_PARAM_UPDATE_RSP,
	    0x43, p, sizeof(p));

	ATF_CHECK_EQ(0, g_untimeout_n);		/* RTX not cancelled */
	ATF_CHECK(!cmd->test_freed);		/* CON_REQ left intact */
}

/* ====================================================================== */
/* L2CAP_CONNECTION_RSP (0x03) -- Section 4.3 (BR/EDR)                    */
/* ====================================================================== */

/*
 * Positive L2CAP_CONNECTION_RSP, Result 0x0000 "Connection successful"
 * (Section 4.3, Table 4.6).  A logical channel is established: the decoder
 * cancels the RTX timer, records the peer's Destination CID, moves the
 * channel from W4_L2CAP_CON_RSP to CONFIG (the next step is configuration),
 * confirms success up, and dequeues the command.
 */
ATF_TC_WITHOUT_HEAD(con_rsp_success_bredr);
ATF_TC_BODY(con_rsp_success_bredr, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0055), LE16(0x0041), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS), LE16(0x0000)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x50, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x77, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, 0x50, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);
	ATF_CHECK_EQ(0x0055, ch->dcid);			/* peer DCID recorded */
	ATF_CHECK_EQ(NG_L2CAP_CONFIG, ch->state);	/* -> CONFIG */
	ATF_CHECK_EQ(1, r_con_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, r_con_rsp.result);
	ATF_CHECK_EQ(0x77, r_con_rsp.token);
	ATF_CHECK(!ch->test_freed);
	ATF_CHECK(cmd->test_freed);
}

/*
 * Positive L2CAP_CONNECTION_RSP for a fixed-CID bearer (SCID == ATT CID
 * 0x0004): fixed-channel bearers have no configuration phase, so the decoder
 * moves straight to OPEN rather than CONFIG.  (Section 4.3 success; stack
 * fixed-channel special-case.)
 */
ATF_TC_WITHOUT_HEAD(con_rsp_success_att_open);
ATF_TC_BODY(con_rsp_success_att_open, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0060), LE16(BT_CORE63_L2CAP_CID_ATT),
		LE16(BT_CORE63_L2CAP_RESULT_SUCCESS), LE16(0x0000)
	};
	ng_l2cap_chan_p	ch;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(BT_CORE63_L2CAP_CID_ATT, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_ATT);
	(void)seed_cmd(ch, 0x51, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x00, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, 0x51, p, sizeof(p));

	ATF_CHECK_EQ(0x0060, ch->dcid);
	ATF_CHECK_EQ(NG_L2CAP_OPEN, ch->state);		/* fixed-CID -> OPEN */
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, r_con_rsp.result);
}

/*
 * Negative L2CAP_CONNECTION_RSP, Result 0x0002 "Connection refused - PSM not
 * supported" (Section 4.3, Table 4.6).  The decoder forwards the failure
 * result up and closes the half-open channel.
 */
ATF_TC_WITHOUT_HEAD(con_rsp_refused_psm);
ATF_TC_BODY(con_rsp_refused_psm, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0000), LE16(0x0041),
		LE16(BT_CORE63_L2CAP_RESULT_PSM_NOT_SUPPORTED), LE16(0x0000)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x52, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x78, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, 0x52, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);
	ATF_CHECK_EQ(1, r_con_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_PSM_NOT_SUPPORTED, r_con_rsp.result);
	ATF_CHECK(ch->test_freed);			/* channel closed */
	ATF_CHECK(cmd->test_freed);
}

/*
 * L2CAP_CONNECTION_RSP, Result 0x0001 "Connection pending" (Section 4.3,
 * Table 4.6): "If the device sends [...] result code 'pending', then it
 * shall subsequently send another L2CAP_CONNECTION_RSP."  The decoder keeps
 * the outstanding command, restarts the (longer) ERTX timer, records the
 * tentative DCID, and forwards the pending status up -- the channel stays in
 * W4_L2CAP_CON_RSP awaiting the final response.
 */
ATF_TC_WITHOUT_HEAD(con_rsp_pending);
ATF_TC_BODY(con_rsp_pending, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0055), LE16(0x0041),
		LE16(BT_CORE63_L2CAP_RESULT_PENDING), LE16(0x0001)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x53, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x79, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, 0x53, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);			/* RTX cancelled ... */
	ATF_CHECK_EQ(1, g_timeout_n);			/* ... ERTX restarted */
	ATF_CHECK_EQ(0x0055, ch->dcid);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_CON_RSP, ch->state); /* still waiting */
	ATF_CHECK_EQ(1, r_con_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_PENDING, r_con_rsp.result);
	ATF_CHECK_EQ(0x0001, r_con_rsp.status);
	ATF_CHECK(!ch->test_freed);
	ATF_CHECK(!cmd->test_freed);			/* command retained */
}

/*
 * L2CAP_CONNECTION_RSP, Result "Pending" with Destination CID 0x0000.
 * §4.3 / Table 4.6: a Pending response need not yet carry the final DCID, so
 * a DCID of 0x0000 is legal and MUST be accepted -- the command is retained
 * and the channel stays in W4_L2CAP_CON_RSP.  (Kills a mutation dropping the
 * `dcid != 0 &&` allowance, which would reject a legal pending DCID of 0.)
 */
ATF_TC_WITHOUT_HEAD(con_rsp_pending_dcid_zero);
ATF_TC_BODY(con_rsp_pending_dcid_zero, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0000), LE16(0x0041),
		LE16(BT_CORE63_L2CAP_RESULT_PENDING), LE16(0x0001)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x55, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x79, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, 0x55, p, sizeof(p));

	/* Accepted as pending: channel and command retained, still waiting. */
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_CON_RSP, ch->state);
	ATF_CHECK_EQ(1, r_con_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_PENDING, r_con_rsp.result);
	ATF_CHECK(!ch->test_freed);
	ATF_CHECK(!cmd->test_freed);
}

/*
 * L2CAP_CONNECTION_RSP whose channel is not in W4_L2CAP_CON_RSP is
 * unexpected: the decoder rejects it with a Command Reject, Reason 0x0002
 * "Invalid CID in request" (Section 4.1), and delivers no confirm.
 */
ATF_TC_WITHOUT_HEAD(con_rsp_state_mismatch_reject);
ATF_TC_BODY(con_rsp_state_mismatch_reject, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0055), LE16(0x0041), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS), LE16(0x0000)
	};
	ng_l2cap_chan_p	ch;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0000, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	(void)seed_cmd(ch, 0x54, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x00, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, 0x54, p, sizeof(p));

	expect_cmd_rej(0x54, BT_CORE63_L2CAP_REJECT_INVALID_CID);
	ATF_CHECK_EQ(0, r_con_rsp.n);
}

/*
 * L2CAP_CONNECTION_RSP whose SCID does not match the outstanding command's
 * channel: also rejected with Command Reject / Invalid CID (Section 4.1).
 */
ATF_TC_WITHOUT_HEAD(con_rsp_cid_mismatch_reject);
ATF_TC_BODY(con_rsp_cid_mismatch_reject, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0055), LE16(0x0099), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS), LE16(0x0000)
	};
	ng_l2cap_chan_p	ch;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	(void)seed_cmd(ch, 0x55, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x00, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, 0x55, p, sizeof(p));

	expect_cmd_rej(0x55, BT_CORE63_L2CAP_REJECT_INVALID_CID);
	ATF_CHECK_EQ(0, r_con_rsp.n);
}

/*
 * Positive L2CAP_CONNECTION_RSP whose Destination CID is outside the
 * dynamically allocated range: Section 4.3 requires the DCID to be from the
 * dynamic range, so "A logical channel is established [...] unless the DCID
 * field is outside of the dynamically allocated range."  The decoder refuses
 * to open, dequeues the command, and rejects with Command Reject.
 */
ATF_TC_WITHOUT_HEAD(con_rsp_success_invalid_dcid);
ATF_TC_BODY(con_rsp_success_invalid_dcid, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0003), LE16(0x0041), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS), LE16(0x0000)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x56, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x00, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, 0x56, p, sizeof(p));

	expect_cmd_rej(0x56, BT_CORE63_L2CAP_REJECT_INVALID_CID);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_CON_RSP, ch->state); /* not opened */
	ATF_CHECK_EQ(0, r_con_rsp.n);
	ATF_CHECK(cmd->test_freed);
}

/* ====================================================================== */
/* L2CAP_CONFIGURATION_RSP (0x05) -- Section 4.5 (BR/EDR)                 */
/* ====================================================================== */

/*
 * Positive L2CAP_CONFIGURATION_RSP, Result 0x0000 "Success" (Section 4.5,
 * Table 4.9), carrying an MTU option.  The decoder applies the accepted MTU
 * to the channel's incoming MTU, cancels the RTX timer, confirms success up,
 * and dequeues the command.
 */
ATF_TC_WITHOUT_HEAD(cfg_rsp_success_bredr);
ATF_TC_BODY(cfg_rsp_success_bredr, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0041), LE16(0x0000), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS),
		BT_CORE63_L2CAP_OPTION_MTU, 0x02, LE16(0x0200)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x60, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x81, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, 0x60, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);
	ATF_CHECK_EQ(0x0200, ch->imtu);			/* accepted MTU applied */
	ATF_CHECK_EQ(1, r_cfg_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, r_cfg_rsp.result);
	ATF_CHECK(!ch->test_freed);
	ATF_CHECK(cmd->test_freed);
}

/*
 * Negative L2CAP_CONFIGURATION_RSP, Result 0x0001 "Failure - unacceptable
 * parameters" (Section 4.5, Table 4.9).  The decoder forwards the failure
 * result to the upper layer and dequeues the command.
 */
ATF_TC_WITHOUT_HEAD(cfg_rsp_unacceptable);
ATF_TC_BODY(cfg_rsp_unacceptable, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0041), LE16(0x0000), LE16(0x0001)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x61, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x82, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, 0x61, p, sizeof(p));

	ATF_CHECK_EQ(1, r_cfg_rsp.n);
	ATF_CHECK_EQ(0x0001, r_cfg_rsp.result);
	ATF_CHECK(cmd->test_freed);
}

/*
 * L2CAP_CONFIGURATION_RSP with the Continuation (C) flag set (Section 4.5):
 * "More L2CAP_CONFIGURATION_RSP packets will follow."  The decoder restarts
 * the RTX timer and KEEPS the outstanding command, delivering no confirm yet.
 */
ATF_TC_WITHOUT_HEAD(cfg_rsp_cflag_restart);
ATF_TC_BODY(cfg_rsp_cflag_restart, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0041), LE16(BT_CORE63_L2CAP_OPTION_CONTINUATION), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x62, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x83, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, 0x62, p, sizeof(p));

	ATF_CHECK_EQ(1, g_timeout_n);			/* RTX restarted */
	ATF_CHECK_EQ(0, r_cfg_rsp.n);			/* no confirm yet */
	ATF_CHECK(!cmd->test_freed);			/* command retained */
}

/*
 * L2CAP_CONFIGURATION_RSP whose SCID does not match the outstanding
 * command's channel: rejected with Command Reject / Invalid CID (Section 4.1).
 */
ATF_TC_WITHOUT_HEAD(cfg_rsp_cid_mismatch_reject);
ATF_TC_BODY(cfg_rsp_cid_mismatch_reject, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0099), LE16(0x0000), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS)
	};
	ng_l2cap_chan_p	ch;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	(void)seed_cmd(ch, 0x63, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x00, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, 0x63, p, sizeof(p));

	expect_cmd_rej(0x63, BT_CORE63_L2CAP_REJECT_INVALID_CID);
	ATF_CHECK_EQ(0, r_cfg_rsp.n);
}

/*
 * L2CAP_CONFIGURATION_RSP for a channel not in CONFIG state: rejected with
 * Command Reject / Invalid CID (Section 4.1).
 */
ATF_TC_WITHOUT_HEAD(cfg_rsp_state_mismatch_reject);
ATF_TC_BODY(cfg_rsp_state_mismatch_reject, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0041), LE16(0x0000), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS)
	};
	ng_l2cap_chan_p	ch;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	(void)seed_cmd(ch, 0x64, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x00, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, 0x64, p, sizeof(p));

	expect_cmd_rej(0x64, BT_CORE63_L2CAP_REJECT_INVALID_CID);
	ATF_CHECK_EQ(0, r_cfg_rsp.n);
}

/*
 * L2CAP_CONFIGURATION_RSP whose option list is unparseable (an unknown,
 * non-hint option): the decoder cannot interpret the response, so it stops
 * waiting for more options and reports it up with result "unknown" rather
 * than blindly succeeding.  (Section 4.5 / Section 5 option handling.)
 */
ATF_TC_WITHOUT_HEAD(cfg_rsp_bad_option);
ATF_TC_BODY(cfg_rsp_bad_option, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0041), LE16(0x0000), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS),
		0x10, 0x02, 0xaa, 0xbb		/* unknown non-hint option */
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_CONFIG,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x65, BT_CORE63_L2CAP_CMD_CONFIG_REQ, 0x84, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, 0x65, p, sizeof(p));

	ATF_CHECK_EQ(1, r_cfg_rsp.n);
	ATF_CHECK_EQ(NG_L2CAP_UNKNOWN, r_cfg_rsp.result);
	ATF_CHECK(cmd->test_freed);
}

/* ====================================================================== */
/* L2CAP_DISCONNECTION_RSP (0x07) -- Section 4.7 (BR/EDR + LE)            */
/* ====================================================================== */

/*
 * L2CAP_DISCONNECTION_RSP whose DCID and SCID match the outstanding
 * L2CAP_DISCONNECTION_REQ (Section 4.7): the channel is confirmed closed.
 * The decoder cancels the RTX timer, confirms disconnect success up, and
 * frees the channel.
 */
ATF_TC_WITHOUT_HEAD(discon_rsp_match_bredr);
ATF_TC_BODY(discon_rsp_match_bredr, tc)
{
	static const u_int8_t p[] = { LE16(0x0055), LE16(0x0041) };
	ng_l2cap_chan_p	ch;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_W4_L2CAP_DISCON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	(void)seed_cmd(ch, 0x70, BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, 0x91, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_RSP, 0x70, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);
	ATF_CHECK_EQ(1, r_discon_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, r_discon_rsp.result);
	ATF_CHECK_EQ(0x91, r_discon_rsp.token);
	ATF_CHECK(ch->test_freed);
}

/*
 * L2CAP_DISCONNECTION_RSP with no matching outstanding request: silently
 * ignored (Section 4.7; the ng_l2cap_cmd_by_ident() miss).
 */
ATF_TC_WITHOUT_HEAD(discon_rsp_no_match);
ATF_TC_BODY(discon_rsp_no_match, tc)
{
	static const u_int8_t p[] = { LE16(0x0055), LE16(0x0041) };

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_RSP, 0x71, p, sizeof(p));

	ATF_CHECK_EQ(0, r_discon_rsp.n);
	ATF_CHECK_EQ(0, g_untimeout_n);
}

/*
 * L2CAP_DISCONNECTION_RSP for a channel not in W4_L2CAP_DISCON_RSP: the
 * decoder ignores the unexpected response and delivers nothing (Section 4.7).
 */
ATF_TC_WITHOUT_HEAD(discon_rsp_state_mismatch);
ATF_TC_BODY(discon_rsp_state_mismatch, tc)
{
	static const u_int8_t p[] = { LE16(0x0055), LE16(0x0041) };
	ng_l2cap_chan_p	ch;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	(void)seed_cmd(ch, 0x72, BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, 0x00, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_RSP, 0x72, p, sizeof(p));

	ATF_CHECK_EQ(0, r_discon_rsp.n);
	ATF_CHECK(!ch->test_freed);
}

/*
 * L2CAP_DISCONNECTION_RSP whose CIDs do not match the outstanding request's
 * channel: ignored, nothing delivered (Section 4.7).
 */
ATF_TC_WITHOUT_HEAD(discon_rsp_cid_mismatch);
ATF_TC_BODY(discon_rsp_cid_mismatch, tc)
{
	static const u_int8_t p[] = { LE16(0x0099), LE16(0x0041) };
	ng_l2cap_chan_p	ch;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_W4_L2CAP_DISCON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	(void)seed_cmd(ch, 0x73, BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, 0x00, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_RSP, 0x73, p, sizeof(p));

	ATF_CHECK_EQ(0, r_discon_rsp.n);
	ATF_CHECK(!ch->test_freed);
}

/*
 * L2CAP_DISCONNECTION_RSP is valid on the LE signalling channel (CID 0x0005)
 * too (Vol 3 Part A Table 4.2).  A matching response closes an LE channel.
 */
ATF_TC_WITHOUT_HEAD(discon_rsp_match_le);
ATF_TC_BODY(discon_rsp_match_le, tc)
{
	static const u_int8_t p[] = { LE16(0x0050), LE16(0x0045) };
	ng_l2cap_chan_p	ch;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0045, 0x0050, NG_L2CAP_W4_L2CAP_DISCON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	(void)seed_cmd(ch, 0x74, BT_CORE63_L2CAP_CMD_DISCONNECT_REQ, 0x92, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_RSP, 0x74, p, sizeof(p));

	ATF_CHECK_EQ(1, r_discon_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, r_discon_rsp.result);
	ATF_CHECK(ch->test_freed);
}

/* ====================================================================== */
/* L2CAP_ECHO_RSP (0x09) -- Section 4.9 (BR/EDR)                          */
/* ====================================================================== */

/*
 * L2CAP_ECHO_RSP matching an outstanding L2CAP_ECHO_REQ (Section 4.9): the
 * decoder cancels the RTX timer, delivers an L2CA_PingCfm (Result success)
 * carrying the echoed data, and dequeues the command.
 */
ATF_TC_WITHOUT_HEAD(echo_rsp_match);
ATF_TC_BODY(echo_rsp_match, tc)
{
	static const u_int8_t p[] = { 0xde, 0xad, 0xbe, 0xef };
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	cmd = seed_cmd(NULL, 0x80, BT_CORE63_L2CAP_CMD_ECHO_REQ, 0x93, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECHO_RSP, 0x80, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);
	ATF_CHECK_EQ(1, r_ping_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, r_ping_rsp.result);
	ATF_CHECK_EQ(0x93, r_ping_rsp.token);
	ATF_CHECK(cmd->test_freed);
}

/*
 * L2CAP_ECHO_RSP with no matching outstanding request: silently discarded
 * (Section 4.9; the ng_l2cap_cmd_by_ident() miss).
 */
ATF_TC_WITHOUT_HEAD(echo_rsp_no_match);
ATF_TC_BODY(echo_rsp_no_match, tc)
{
	static const u_int8_t p[] = { 0x01, 0x02 };

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECHO_RSP, 0x81, p, sizeof(p));

	ATF_CHECK_EQ(0, r_ping_rsp.n);
	ATF_CHECK_EQ(0, g_untimeout_n);
}

/*
 * L2CAP_ECHO_RSP whose Identifier collides with an unrelated pending command
 * (here a Connection Request) must NOT complete that command.  A response is
 * matched to an outstanding request by Identifier (Vol 3 Part A §4), but an
 * Echo Response may only answer a pending Echo Request; the handler's
 * cmd->code == ECHO_REQ check enforces that.  Dropping it would let an
 * EchoRsp free/complete a colliding CON_REQ.  Correct behaviour: the EchoRsp
 * is ignored -- no L2CA_PingCfm, the CON_REQ command stays intact.
 */
ATF_TC_WITHOUT_HEAD(echo_rsp_ident_collides_con_req);
ATF_TC_BODY(echo_rsp_ident_collides_con_req, tc)
{
	static const u_int8_t p[] = { 0xde, 0xad };
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x88, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x5a, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECHO_RSP, 0x88, p, sizeof(p));

	ATF_CHECK_EQ(0, r_ping_rsp.n);		/* no PingCfm delivered */
	ATF_CHECK_EQ(0, g_untimeout_n);		/* RTX not cancelled */
	ATF_CHECK(!cmd->test_freed);		/* CON_REQ left intact */
}

/*
 * L2CAP_ECHO_RSP arriving after the RTX timer already fired: the late
 * response is ignored (the ping already failed by timeout), the command is
 * left in place, and no L2CA_PingCfm is delivered.  (Section 4.9.)
 */
ATF_TC_WITHOUT_HEAD(echo_rsp_timeout_ignored);
ATF_TC_BODY(echo_rsp_timeout_ignored, tc)
{
	static const u_int8_t p[] = { 0x01, 0x02 };
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	cmd = seed_cmd(NULL, 0x82, BT_CORE63_L2CAP_CMD_ECHO_REQ, 0x00, NG_L2CAP_CMD_PENDING);
	g_untimeout_ret = ETIMEDOUT;

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECHO_RSP, 0x82, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);
	ATF_CHECK_EQ(0, r_ping_rsp.n);
	ATF_CHECK(!cmd->test_freed);
}

/* ====================================================================== */
/* L2CAP_INFORMATION_RSP (0x0B) -- Section 4.11 (BR/EDR)                  */
/* ====================================================================== */

/*
 * L2CAP_INFORMATION_RSP, InfoType Connectionless MTU, Result 0x0000
 * "Success" (Section 4.11, Table 4.13) with a 2-octet MTU payload.  The
 * decoder cancels the RTX timer, delivers L2CA_GetInfoCfm(success) up, and
 * dequeues the command.
 */
ATF_TC_WITHOUT_HEAD(info_rsp_connless_mtu_success);
ATF_TC_BODY(info_rsp_connless_mtu_success, tc)
{
	static const u_int8_t p[] = {
		LE16(BT_CORE63_L2CAP_INFO_CONNECTIONLESS_MTU), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS), LE16(0x02a0)
	};
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	cmd = seed_cmd(NULL, 0x90, BT_CORE63_L2CAP_CMD_INFO_REQ, 0x94, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_RSP, 0x90, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);
	ATF_CHECK_EQ(1, r_info_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, r_info_rsp.result);
	ATF_CHECK_EQ(0x94, r_info_rsp.token);
	ATF_CHECK(cmd->test_freed);
}

/*
 * L2CAP_INFORMATION_RSP, Result 0x0001 "Not supported" (Section 4.11,
 * Table 4.13): the failure result is forwarded up verbatim.
 */
ATF_TC_WITHOUT_HEAD(info_rsp_not_supported);
ATF_TC_BODY(info_rsp_not_supported, tc)
{
	static const u_int8_t p[] = {
		LE16(BT_CORE63_L2CAP_INFO_EXTENDED_FEATURES), LE16(BT_CORE63_L2CAP_INFO_NOT_SUPPORTED)
	};
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	cmd = seed_cmd(NULL, 0x91, BT_CORE63_L2CAP_CMD_INFO_REQ, 0x95, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_RSP, 0x91, p, sizeof(p));

	ATF_CHECK_EQ(1, r_info_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_INFO_NOT_SUPPORTED, r_info_rsp.result);
	ATF_CHECK(cmd->test_freed);
}

/*
 * L2CAP_INFORMATION_RSP with no matching outstanding request: discarded
 * (Section 4.11; ng_l2cap_cmd_by_ident() miss).
 */
ATF_TC_WITHOUT_HEAD(info_rsp_no_match);
ATF_TC_BODY(info_rsp_no_match, tc)
{
	static const u_int8_t p[] = {
		LE16(BT_CORE63_L2CAP_INFO_CONNECTIONLESS_MTU), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS), LE16(0x02a0)
	};

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_RSP, 0x92, p, sizeof(p));

	ATF_CHECK_EQ(0, r_info_rsp.n);
	ATF_CHECK_EQ(0, g_untimeout_n);
}

/*
 * L2CAP_INFORMATION_RSP, Connectionless MTU, Result success but a malformed
 * (non-2-octet) Info payload: the decoder cannot trust the value, so it
 * downgrades the result reported up to "unknown" (Section 4.11 requires a
 * 2-octet connectionless MTU in the Info field).
 */
ATF_TC_WITHOUT_HEAD(info_rsp_connless_bad_len);
ATF_TC_BODY(info_rsp_connless_bad_len, tc)
{
	static const u_int8_t p[] = {
		LE16(BT_CORE63_L2CAP_INFO_CONNECTIONLESS_MTU), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS),
		0x01, 0x02, 0x03, 0x04		/* 4-octet info, not 2 */
	};
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	cmd = seed_cmd(NULL, 0x93, BT_CORE63_L2CAP_CMD_INFO_REQ, 0x00, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_RSP, 0x93, p, sizeof(p));

	ATF_CHECK_EQ(1, r_info_rsp.n);
	ATF_CHECK_EQ(NG_L2CAP_UNKNOWN, r_info_rsp.result);
	ATF_CHECK(cmd->test_freed);
}

/* ====================================================================== */
/* L2CAP_LE_CREDIT_BASED_CONNECTION_RSP (0x15) -- Section 4.23 (LE)       */
/* ====================================================================== */

/*
 * LE Credit Based Connection Response, Result 0x0000 "Connection successful"
 * (Section 4.23, Table 4.16).  The decoder validates the peer's parameters,
 * records DCID/MTU/MPS/credits, opens the channel, confirms success up, and
 * dequeues the command.
 */
ATF_TC_WITHOUT_HEAD(le_credit_con_rsp_success);
ATF_TC_BODY(le_credit_con_rsp_success, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0050),			/* DCID */
		LE16(64),			/* MTU  */
		LE16(64),			/* MPS  */
		LE16(0),			/* legal zero initial credits */
		LE16(BT_CORE63_L2CAP_CREDIT_SUCCESS)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0045, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	cmd = seed_cmd(ch, 0xa0, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x96,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP,
	    0xa0, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);
	ATF_CHECK_EQ(0x0050, ch->dcid);
	ATF_CHECK_EQ(64, ch->omtu);
	ATF_CHECK_EQ(64, ch->mps_remote);
	ATF_CHECK_EQ(0, ch->credits_remote);
	ATF_CHECK_EQ(NG_L2CAP_OPEN, ch->state);
	ATF_CHECK_EQ(1, r_con_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, r_con_rsp.result);
	ATF_CHECK(!ch->test_freed);
	ATF_CHECK(cmd->test_freed);
}

/*
 * LE Credit Based Connection Response, Result 0x0002 "SPSM not supported"
 * (Section 4.23, Table 4.16).  The decoder forwards the reject result up and
 * frees the channel.
 */
ATF_TC_WITHOUT_HEAD(le_credit_con_rsp_refused);
ATF_TC_BODY(le_credit_con_rsp_refused, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0000), LE16(0), LE16(0), LE16(0),
		LE16(BT_CORE63_L2CAP_CREDIT_SPSM_NOT_SUPPORTED)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0045, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	cmd = seed_cmd(ch, 0xa1, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x97,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP,
	    0xa1, p, sizeof(p));

	ATF_CHECK_EQ(1, r_con_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_SPSM_NOT_SUPPORTED, r_con_rsp.result);
	ATF_CHECK(ch->test_freed);
	ATF_CHECK(cmd->test_freed);
}

/*
 * LE Credit Based Connection Response claiming success but with an MTU below
 * the LE minimum (23): Section 4.23 requires MTU/MPS >= 23, so the decoder
 * rejects the malformed success, tears the channel down, and delivers no
 * success confirm.
 */
ATF_TC_WITHOUT_HEAD(le_credit_con_rsp_success_bad_params);
ATF_TC_BODY(le_credit_con_rsp_success_bad_params, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0050), LE16(10), LE16(64), LE16(10),
		LE16(BT_CORE63_L2CAP_CREDIT_SUCCESS)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0045, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	cmd = seed_cmd(ch, 0xa2, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x00,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP,
	    0xa2, p, sizeof(p));

	ATF_CHECK_EQ(0, r_con_rsp.n);			/* no success confirm */
	ATF_CHECK(ch->test_freed);
	ATF_CHECK(cmd->test_freed);
	ATF_CHECK(ch->state != NG_L2CAP_OPEN);
}

/*
 * LE Credit Based Connection Response reporting Success but carrying an MPS
 * above the §4.22 maximum (65533).  MPS 65534 is out of range, so the
 * initiator MUST reject the response and tear the pending channel down rather
 * than open it.  (Kills a `mps > 65533` -> `mps > 65535` weakening of the
 * response-side parameter validation.)
 */
ATF_TC_WITHOUT_HEAD(le_credit_con_rsp_bad_mps);
ATF_TC_BODY(le_credit_con_rsp_bad_mps, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0050), LE16(64), LE16(65534), LE16(10),
		LE16(BT_CORE63_L2CAP_CREDIT_SUCCESS)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0045, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	cmd = seed_cmd(ch, 0xa4, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x00,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP,
	    0xa4, p, sizeof(p));

	ATF_CHECK_EQ(0, r_con_rsp.n);			/* no success confirm */
	ATF_CHECK(ch->test_freed);
	ATF_CHECK(cmd->test_freed);
	ATF_CHECK(ch->state != NG_L2CAP_OPEN);
}

/*
 * LE Credit Based Connection Response with no matching outstanding request:
 * discarded (Section 4.23; ng_l2cap_cmd_by_ident() miss).
 */
ATF_TC_WITHOUT_HEAD(le_credit_con_rsp_no_match);
ATF_TC_BODY(le_credit_con_rsp_no_match, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0050), LE16(64), LE16(64), LE16(10),
		LE16(BT_CORE63_L2CAP_CREDIT_SUCCESS)
	};

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP,
	    0xa3, p, sizeof(p));

	ATF_CHECK_EQ(0, r_con_rsp.n);
	ATF_CHECK_EQ(0, g_untimeout_n);
}

/*
 * LE Credit Based Connection Response whose outstanding command's channel is
 * not awaiting a connection response (wrong state): the decoder treats it as
 * unexpected and does nothing -- notably it does NOT cancel a timer or
 * deliver a confirm.  (Section 4.23 state check.)
 */
ATF_TC_WITHOUT_HEAD(le_credit_con_rsp_bad_state);
ATF_TC_BODY(le_credit_con_rsp_bad_state, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0050), LE16(64), LE16(64), LE16(10),
		LE16(BT_CORE63_L2CAP_CREDIT_SUCCESS)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0045, 0x0000, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	cmd = seed_cmd(ch, 0xa4, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_REQ, 0x00,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP,
	    0xa4, p, sizeof(p));

	ATF_CHECK_EQ(0, g_untimeout_n);
	ATF_CHECK_EQ(0, r_con_rsp.n);
	ATF_CHECK(!ch->test_freed);
	ATF_CHECK(!cmd->test_freed);
}

/* ====================================================================== */
/* L2CAP_CREDIT_BASED_CONNECTION_RSP (0x18) -- Section 4.26 (BR/EDR + LE) */
/* ====================================================================== */

/*
 * Enhanced Credit Based Connection Response, Result 0x0000 "All connections
 * successful" (Section 4.26, Table 4.20).  With one Destination CID, the
 * decoder records the peer parameters, opens the channel, confirms success
 * up, and dequeues the command.  Fed on the LE signalling channel.
 */
ATF_TC_WITHOUT_HEAD(credit_con_rsp_success_le);
ATF_TC_BODY(credit_con_rsp_success_le, tc)
{
	static const u_int8_t p[] = {
		LE16(64),			/* MTU */
		LE16(64),			/* MPS */
		LE16(5),			/* initial credits */
		LE16(BT_CORE63_L2CAP_CREDIT_SUCCESS),	/* result */
		LE16(0x0050)			/* one DCID */
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0046, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	cmd = seed_cmd(ch, 0xb0, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ, 0x98,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    0xb0, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);
	ATF_CHECK_EQ(0x0050, ch->dcid);
	ATF_CHECK_EQ(64, ch->omtu);
	ATF_CHECK_EQ(NG_L2CAP_OPEN, ch->state);
	ATF_CHECK_EQ(1, r_con_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_RESULT_SUCCESS, r_con_rsp.result);
	ATF_CHECK(cmd->test_freed);
}

/*
 * Enhanced Credit Based Connection Response, Result 0x0004 "All connections
 * refused - no resources available" (Section 4.26, Table 4.20), on the
 * BR/EDR signalling channel (code 0x18 is valid on both CIDs).  The reject
 * result is forwarded up and the channel is freed.
 */
ATF_TC_WITHOUT_HEAD(credit_con_rsp_all_refused_bredr);
ATF_TC_BODY(credit_con_rsp_all_refused_bredr, tc)
{
	static const u_int8_t p[] = {
		LE16(0), LE16(0), LE16(0),
		LE16(BT_CORE63_L2CAP_CREDIT_NO_RESOURCES),
		LE16(0x0000)			/* DCID field present but null */
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0046, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	cmd = seed_cmd(ch, 0xb1, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ, 0x99,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    0xb1, p, sizeof(p));

	ATF_CHECK_EQ(1, r_con_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CREDIT_NO_RESOURCES, r_con_rsp.result);
	ATF_CHECK(ch->test_freed);
	ATF_CHECK(cmd->test_freed);
}

/*
 * Enhanced Credit Based Connection Response claiming success but whose first
 * Destination CID is below the dynamic range: the decoder rejects the
 * malformed success (a valid DCID is required, Section 4.26), reporting an
 * L2CA_ConnectCfm with a reject result and freeing the channel.
 */
ATF_TC_WITHOUT_HEAD(credit_con_rsp_success_invalid_dcid);
ATF_TC_BODY(credit_con_rsp_success_invalid_dcid, tc)
{
	static const u_int8_t p[] = {
		LE16(64), LE16(64), LE16(5),
		LE16(BT_CORE63_L2CAP_CREDIT_SUCCESS),
		LE16(0x0003)			/* DCID < FIRST_CID */
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0046, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	cmd = seed_cmd(ch, 0xb2, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ, 0x00,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    0xb2, p, sizeof(p));

	ATF_CHECK_EQ(1, r_con_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CONFIG_REJECT, r_con_rsp.result);
	ATF_CHECK(ch->test_freed);
	ATF_CHECK(ch->state != NG_L2CAP_OPEN);
	ATF_CHECK(cmd->test_freed);
}

/*
 * The local ECBFC initiator path sends one SCID per request.  A success
 * response with more than one DCID is therefore not the response to the
 * command we sent; do not open the pending channel and silently ignore the
 * extra peer CID.
 */
ATF_TC_WITHOUT_HEAD(credit_con_rsp_success_extra_dcid);
ATF_TC_BODY(credit_con_rsp_success_extra_dcid, tc)
{
	static const u_int8_t p[] = {
		LE16(64), LE16(64), LE16(5),
		LE16(BT_CORE63_L2CAP_CREDIT_SUCCESS),
		LE16(0x0050), LE16(0x0051)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0046, 0x0000, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	cmd = seed_cmd(ch, 0xb5, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ, 0x00,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    0xb5, p, sizeof(p));

	ATF_CHECK_EQ(0, r_con_rsp.n);
	ATF_CHECK(ch->test_freed);
	ATF_CHECK(ch->state != NG_L2CAP_OPEN);
	ATF_CHECK(cmd->test_freed);
}

/* Reusing an ECBFC DCID invalidates both the original and new channels. */
ATF_TC_WITHOUT_HEAD(credit_con_rsp_reused_dcid_invalidates_both);
ATF_TC_BODY(credit_con_rsp_reused_dcid_invalidates_both, tc)
{
	static const u_int8_t p[] = {
		LE16(64), LE16(64), LE16(5),
		LE16(BT_CORE63_L2CAP_CREDIT_SUCCESS), LE16(0x0050)
	};
	ng_l2cap_chan_p pending, original;
	ng_l2cap_cmd_p cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	pending = register_chan(0x0046, 0x0000,
	    NG_L2CAP_W4_L2CAP_CON_RSP, NG_L2CAP_L2CA_IDTYPE_ECBFC);
	cmd = seed_cmd(pending, 0xb4, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ, 0x9a,
	    NG_L2CAP_CMD_PENDING);
	original = register_chan(0x0047, 0x0050, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    0xb4, p, sizeof(p));

	ATF_CHECK(original->test_freed);
	ATF_CHECK(pending->test_freed);
	ATF_CHECK(cmd->test_freed);
	ATF_CHECK_EQ(1, r_con_rsp.n);
	ATF_CHECK_EQ(BT_CORE63_L2CAP_CONFIG_REJECT, r_con_rsp.result);
}

/*
 * Enhanced Credit Based Connection Response whose channel is in the wrong
 * state: unexpected, so the decoder does nothing (no timer cancel, no
 * confirm).  (Section 4.26 state check.)
 */
ATF_TC_WITHOUT_HEAD(credit_con_rsp_bad_state);
ATF_TC_BODY(credit_con_rsp_bad_state, tc)
{
	static const u_int8_t p[] = {
		LE16(64), LE16(64), LE16(5),
		LE16(BT_CORE63_L2CAP_CREDIT_SUCCESS), LE16(0x0050)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0046, 0x0000, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	cmd = seed_cmd(ch, 0xb3, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_REQ, 0x00,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    0xb3, p, sizeof(p));

	ATF_CHECK_EQ(0, g_untimeout_n);
	ATF_CHECK_EQ(0, r_con_rsp.n);
	ATF_CHECK(!ch->test_freed);
	ATF_CHECK(!cmd->test_freed);
}

/* ====================================================================== */
/* L2CAP_CREDIT_BASED_RECONFIGURE_RSP (0x1A) -- Section 4.28 (BR/EDR + LE)*/
/* ====================================================================== */

/*
 * Credit Based Reconfigure Response, Result 0x0000 "Reconfiguration
 * successful" (Section 4.28, Table 4.18): the pending MTU/MPS values we
 * requested now take effect.  The decoder clears the reconfig-pending guard,
 * applies pending_imtu/pending_mps, cancels the RTX timer, and dequeues the
 * command.  Fed on LE signalling.
 */
ATF_TC_WITHOUT_HEAD(reconfig_rsp_success_le);
ATF_TC_BODY(reconfig_rsp_success_le, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_RECONFIG_SUCCESS) };
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0046, 0x0050, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	ch->imtu = 50;
	ch->mps = 40;
	ch->pending_imtu = 100;
	ch->pending_mps = 80;
	ch->reconfig_pending = 1;
	cmd = seed_cmd(ch, 0xc0, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ, 0x9a,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP,
	    0xc0, p, sizeof(p));

	ATF_CHECK_EQ(1, g_untimeout_n);
	ATF_CHECK_EQ(0, ch->reconfig_pending);
	ATF_CHECK_EQ(100, ch->imtu);			/* pending applied */
	ATF_CHECK_EQ(80, ch->mps);
	ATF_CHECK(cmd->test_freed);
}

/*
 * Credit Based Reconfigure Response, non-zero Result (e.g. 0x0001, "reduction
 * in size of MTU not allowed", Section 4.28 Table 4.18): the peer rejected
 * our reconfiguration, so the pending values are DISCARDED -- imtu/mps stay
 * at their pre-request values -- and the reconfig-pending guard is cleared.
 * Fed on BR/EDR signalling (code 0x1A valid on both CIDs).
 */
ATF_TC_WITHOUT_HEAD(reconfig_rsp_failure_bredr);
ATF_TC_BODY(reconfig_rsp_failure_bredr, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_RECONFIG_MTU_REDUCTION) };
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0046, 0x0050, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	ch->imtu = 50;
	ch->mps = 40;
	ch->pending_imtu = 100;
	ch->pending_mps = 80;
	ch->reconfig_pending = 1;
	cmd = seed_cmd(ch, 0xc1, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ, 0x9b,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP,
	    0xc1, p, sizeof(p));

	ATF_CHECK_EQ(0, ch->reconfig_pending);		/* guard cleared */
	ATF_CHECK_EQ(50, ch->imtu);			/* pending discarded */
	ATF_CHECK_EQ(40, ch->mps);
	ATF_CHECK(cmd->test_freed);
}

/*
 * Credit Based Reconfigure Response with no matching outstanding request:
 * silently ignored (Section 4.28; ng_l2cap_cmd_by_ident() miss).
 */
ATF_TC_WITHOUT_HEAD(reconfig_rsp_no_match);
ATF_TC_BODY(reconfig_rsp_no_match, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_RECONFIG_SUCCESS) };

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP,
	    0xc2, p, sizeof(p));

	ATF_CHECK_EQ(0, g_untimeout_n);
	ATF_CHECK_EQ(0, g_ncaps);
}

/*
 * Credit Based Reconfigure Response (success) for a command whose RTX guard
 * was never armed (no PENDING flag): the pending values are still applied,
 * but the decoder must NOT touch the callout.  (Section 4.28; guards the
 * flags & PENDING branch.)
 */
ATF_TC_WITHOUT_HEAD(reconfig_rsp_success_no_pending_flag);
ATF_TC_BODY(reconfig_rsp_success_no_pending_flag, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_RECONFIG_SUCCESS) };
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0046, 0x0050, NG_L2CAP_OPEN,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	ch->imtu = 50;
	ch->mps = 40;
	ch->pending_imtu = 100;
	ch->pending_mps = 80;
	ch->reconfig_pending = 1;
	cmd = seed_cmd(ch, 0xc3, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_REQ, 0x00, 0);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP,
	    0xc3, p, sizeof(p));

	ATF_CHECK_EQ(0, g_untimeout_n);			/* no pending => no cancel */
	ATF_CHECK_EQ(100, ch->imtu);			/* pending still applied */
	ATF_CHECK_EQ(80, ch->mps);
	ATF_CHECK(cmd->test_freed);
}

/* ====================================================================== */
/* Response Identifier collides with a DIFFERENT outstanding request       */
/* ====================================================================== */

/*
 * ng_l2cap_cmd_by_ident() matches an outstanding command purely by its
 * Identifier (Section 4: "the Identifier ... matches ... an outstanding
 * request").  Idents are allocated uniquely across ALL outstanding commands,
 * so a well-behaved peer never reuses one.  A hostile/broken peer, however,
 * can echo the Identifier of one of our pending requests back inside a
 * response of a DIFFERENT type.  Two failure classes result unless each
 * response decoder verifies the matched command's opcode:
 *
 *   (a) the matched request owns NO channel (INFO_REQ / ECHO_REQ,
 *       cmd->ch == NULL): a con/cfg/discon response decoder that then
 *       dereferences cmd->ch is a remotely triggerable NULL dereference
 *       (kernel panic); and
 *   (b) the matched request owns a channel but is a different operation:
 *       the decoder would wrongly complete/free that command and mutate
 *       its channel.
 *
 * The fix requires cmd->code to equal the request opcode the response
 * answers; a mismatch is treated as "no matching request" (silent ignore).
 */

/* (a) CONNECTION_RSP (0x03) ident == a pending INFO_REQ (channel-less). */
ATF_TC_WITHOUT_HEAD(con_rsp_ident_channelless_cmd);
ATF_TC_BODY(con_rsp_ident_channelless_cmd, tc)
{
	static const u_int8_t p[] = {
		LE16(0x0055), LE16(0x0041), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS), LE16(0x0000)
	};
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	/* Outstanding INFO_REQ: pending, but owns no channel. */
	cmd = seed_cmd(NULL, 0x48, BT_CORE63_L2CAP_CMD_INFO_REQ, 0xa1,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONNECTION_RSP, 0x48, p, sizeof(p));

	/* No crash; code mismatch => unmatched => nothing emitted or up. */
	ATF_CHECK_EQ(0, g_ncaps);
	ATF_CHECK_EQ(0, r_con_rsp.n);
	ATF_CHECK_EQ(0, g_untimeout_n);
	ATF_CHECK(!cmd->test_freed);		/* INFO_REQ left intact */
}

/* (a) CONFIGURATION_RSP (0x05) ident == a pending ECHO_REQ (channel-less). */
ATF_TC_WITHOUT_HEAD(cfg_rsp_ident_channelless_cmd);
ATF_TC_BODY(cfg_rsp_ident_channelless_cmd, tc)
{
	/* cfg_rsp_cp: scid, flags, result (no options). */
	static const u_int8_t p[] = {
		LE16(0x0041), LE16(0x0000), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS)
	};
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	cmd = seed_cmd(NULL, 0x49, BT_CORE63_L2CAP_CMD_ECHO_REQ, 0xa2,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_CONFIG_RSP, 0x49, p, sizeof(p));

	ATF_CHECK_EQ(0, g_ncaps);
	ATF_CHECK_EQ(0, r_cfg_rsp.n);
	ATF_CHECK(!cmd->test_freed);
}

/* (a) DISCONNECTION_RSP (0x07) ident == a pending INFO_REQ (channel-less). */
ATF_TC_WITHOUT_HEAD(discon_rsp_ident_channelless_cmd);
ATF_TC_BODY(discon_rsp_ident_channelless_cmd, tc)
{
	/* discon_rsp_cp: dcid, scid. */
	static const u_int8_t p[] = { LE16(0x0055), LE16(0x0041) };
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	cmd = seed_cmd(NULL, 0x4a, BT_CORE63_L2CAP_CMD_INFO_REQ, 0xa3,
	    NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_DISCONNECT_RSP, 0x4a, p, sizeof(p));

	ATF_CHECK_EQ(0, r_discon_rsp.n);
	ATF_CHECK(!cmd->test_freed);		/* INFO_REQ left intact */
}

/*
 * (b) CREDIT_BASED_RECONFIGURE_RSP (0x1A) whose Identifier collides with a
 * pending CONNECTION_REQ (which DOES own a channel).  Section 4.28: the
 * response must pair only with a Reconfigure Request.  Without the opcode
 * check the decoder would clear the wrong channel's reconfig guard, apply
 * the (unrelated) pending MTU/MPS to it, cancel its RTX timer, and free the
 * CON_REQ command -- corrupting a half-open connection.  The decoder must
 * instead ignore the response and leave the CON_REQ untouched.
 */
ATF_TC_WITHOUT_HEAD(reconfig_rsp_ident_collides_con_req);
ATF_TC_BODY(reconfig_rsp_ident_collides_con_req, tc)
{
	static const u_int8_t p[] = { LE16(BT_CORE63_L2CAP_RECONFIG_SUCCESS) };
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	ch->imtu = 100;
	ch->mps = 80;
	ch->pending_imtu = 999;		/* would be applied if mis-paired */
	ch->pending_mps = 888;
	ch->reconfig_pending = 1;
	cmd = seed_cmd(ch, 0x60, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x5a, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_RECONFIG_RSP,
	    0x60, p, sizeof(p));

	ATF_CHECK_EQ(0, g_untimeout_n);		/* RTX not cancelled */
	ATF_CHECK_EQ(100, ch->imtu);		/* channel NOT mutated */
	ATF_CHECK_EQ(80, ch->mps);
	ATF_CHECK_EQ(1, ch->reconfig_pending);	/* guard untouched */
	ATF_CHECK(!cmd->test_freed);		/* CON_REQ left intact */
}

/*
 * (b) INFORMATION_RSP (0x0B) whose Identifier collides with a pending
 * CONNECTION_REQ.  Section 4.11: it must pair only with an Information
 * Request.  Without the opcode check the decoder cancels the CON_REQ's
 * timer, dequeues/frees it, and delivers a spurious L2CA_GetInfo confirm on
 * the CON_REQ's token.  The decoder must ignore it and leave the CON_REQ.
 */
ATF_TC_WITHOUT_HEAD(info_rsp_ident_collides_con_req);
ATF_TC_BODY(info_rsp_ident_collides_con_req, tc)
{
	/* info_rsp_cp: type, result, then payload. */
	static const u_int8_t p[] = {
		LE16(BT_CORE63_L2CAP_INFO_CONNECTIONLESS_MTU), LE16(BT_CORE63_L2CAP_RESULT_SUCCESS), LE16(0x02a0)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_ACL, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_BREDR);
	cmd = seed_cmd(ch, 0x61, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x5b, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_SIGNAL, BT_CORE63_L2CAP_CMD_INFO_RSP, 0x61, p, sizeof(p));

	ATF_CHECK_EQ(0, g_untimeout_n);		/* RTX not cancelled */
	ATF_CHECK_EQ(0, r_info_rsp.n);		/* no spurious confirm */
	ATF_CHECK(!cmd->test_freed);		/* CON_REQ left intact */
	ATF_CHECK(!ch->test_freed);
}

/*
 * (b) LE_CREDIT_BASED_CONNECTION_RSP (0x15) whose Identifier collides with a
 * pending CONNECTION_REQ (which owns a channel).  Section 4.23: the response
 * must pair only with an LE Credit Based Connection Request.  Without the
 * opcode check the decoder would cancel the CON_REQ's RTX timer, apply the
 * response's DCID/MTU/MPS/credits to the wrong channel and free the CON_REQ.
 * The decoder must instead treat the opcode mismatch as "no matching request"
 * and leave the CON_REQ untouched.
 */
ATF_TC_WITHOUT_HEAD(le_credit_con_rsp_ident_collides_con_req);
ATF_TC_BODY(le_credit_con_rsp_ident_collides_con_req, tc)
{
	/* le_credit_con_rsp_cp: dcid, mtu, mps, credits, result. */
	static const u_int8_t p[] = {
		LE16(0x0050), LE16(64), LE16(64), LE16(10),
		LE16(BT_CORE63_L2CAP_CREDIT_SUCCESS)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_LE);
	ch->omtu = 100;
	cmd = seed_cmd(ch, 0x40, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x5c, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_LE_CREDIT_CONNECTION_RSP,
	    0x40, p, sizeof(p));

	ATF_CHECK_EQ(0, g_untimeout_n);		/* RTX not cancelled */
	ATF_CHECK_EQ(0x0055, ch->dcid);		/* channel NOT mutated */
	ATF_CHECK_EQ(100, ch->omtu);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_CON_RSP, ch->state);
	ATF_CHECK_EQ(0, r_con_rsp.n);		/* no spurious confirm */
	ATF_CHECK(!cmd->test_freed);		/* CON_REQ left intact */
	ATF_CHECK(!ch->test_freed);
}

/*
 * (b) L2CAP_CREDIT_BASED_CONNECTION_RSP (0x18) whose Identifier collides with a
 * pending CONNECTION_REQ.  Section 4.26: it must pair only with an Enhanced
 * Credit Based Connection Request.  Same failure class as above; the decoder
 * must leave the CON_REQ and its channel untouched.
 */
ATF_TC_WITHOUT_HEAD(credit_con_rsp_ident_collides_con_req);
ATF_TC_BODY(credit_con_rsp_ident_collides_con_req, tc)
{
	/* credit_con_rsp_cp: mtu, mps, credits, result, then one DCID. */
	static const u_int8_t p[] = {
		LE16(64), LE16(64), LE16(10),
		LE16(BT_CORE63_L2CAP_CREDIT_SUCCESS), LE16(0x0050)
	};
	ng_l2cap_chan_p	ch;
	ng_l2cap_cmd_p	cmd;

	setup_con(NG_HCI_LINK_LE_PUBLIC, 1, 1);
	ch = register_chan(0x0041, 0x0055, NG_L2CAP_W4_L2CAP_CON_RSP,
	    NG_L2CAP_L2CA_IDTYPE_ECBFC);
	ch->omtu = 100;
	cmd = seed_cmd(ch, 0x40, BT_CORE63_L2CAP_CMD_CONNECTION_REQ, 0x5d, NG_L2CAP_CMD_PENDING);

	feed_ok(BT_CORE63_L2CAP_CID_LE_SIGNAL, BT_CORE63_L2CAP_CMD_ECREDIT_CONNECTION_RSP,
	    0x40, p, sizeof(p));

	ATF_CHECK_EQ(0, g_untimeout_n);		/* RTX not cancelled */
	ATF_CHECK_EQ(0x0055, ch->dcid);		/* channel NOT mutated */
	ATF_CHECK_EQ(100, ch->omtu);
	ATF_CHECK_EQ(NG_L2CAP_W4_L2CAP_CON_RSP, ch->state);
	ATF_CHECK_EQ(0, r_con_rsp.n);		/* no spurious confirm */
	ATF_CHECK(!cmd->test_freed);		/* CON_REQ left intact */
	ATF_CHECK(!ch->test_freed);
}

/* ====================================================================== */
/* Test program                                                           */
/* ====================================================================== */

ATF_TP_ADD_TCS(tp)
{
	/* Command Reject (0x01) -- Section 4.1 */
	ATF_TP_ADD_TC(tp, cmd_rej_con_req_bredr);
	ATF_TP_ADD_TC(tp, cmd_rej_cfg_req_bredr);
	ATF_TP_ADD_TC(tp, cmd_rej_discon_req_bredr);
	ATF_TP_ADD_TC(tp, cmd_rej_echo_req_bredr);
	ATF_TP_ADD_TC(tp, cmd_rej_info_req_bredr);
	ATF_TP_ADD_TC(tp, cmd_rej_timeout_ignored);
	ATF_TP_ADD_TC(tp, cmd_rej_le_credit_le);

	/* Connection Parameter Update Response (0x13) -- Section 4.21 */
	ATF_TP_ADD_TC(tp, cmd_urs_match_pending_le);
	ATF_TP_ADD_TC(tp, cmd_urs_match_no_pending_flag_le);
	ATF_TP_ADD_TC(tp, cmd_urs_no_match_le);
	ATF_TP_ADD_TC(tp, cmd_urs_ident_collides_con_req_le);

	/* Connection Response (0x03) -- Section 4.3 */
	ATF_TP_ADD_TC(tp, con_rsp_success_bredr);
	ATF_TP_ADD_TC(tp, con_rsp_success_att_open);
	ATF_TP_ADD_TC(tp, con_rsp_refused_psm);
	ATF_TP_ADD_TC(tp, con_rsp_pending);
	ATF_TP_ADD_TC(tp, con_rsp_pending_dcid_zero);
	ATF_TP_ADD_TC(tp, con_rsp_state_mismatch_reject);
	ATF_TP_ADD_TC(tp, con_rsp_cid_mismatch_reject);
	ATF_TP_ADD_TC(tp, con_rsp_success_invalid_dcid);
	ATF_TP_ADD_TC(tp, con_rsp_ident_channelless_cmd);
	ATF_TP_ADD_TC(tp, cfg_rsp_ident_channelless_cmd);
	ATF_TP_ADD_TC(tp, discon_rsp_ident_channelless_cmd);
	ATF_TP_ADD_TC(tp, reconfig_rsp_ident_collides_con_req);
	ATF_TP_ADD_TC(tp, info_rsp_ident_collides_con_req);

	/* Configuration Response (0x05) -- Section 4.5 */
	ATF_TP_ADD_TC(tp, cfg_rsp_success_bredr);
	ATF_TP_ADD_TC(tp, cfg_rsp_unacceptable);
	ATF_TP_ADD_TC(tp, cfg_rsp_cflag_restart);
	ATF_TP_ADD_TC(tp, cfg_rsp_cid_mismatch_reject);
	ATF_TP_ADD_TC(tp, cfg_rsp_state_mismatch_reject);
	ATF_TP_ADD_TC(tp, cfg_rsp_bad_option);

	/* Disconnection Response (0x07) -- Section 4.7 */
	ATF_TP_ADD_TC(tp, discon_rsp_match_bredr);
	ATF_TP_ADD_TC(tp, discon_rsp_no_match);
	ATF_TP_ADD_TC(tp, discon_rsp_state_mismatch);
	ATF_TP_ADD_TC(tp, discon_rsp_cid_mismatch);
	ATF_TP_ADD_TC(tp, discon_rsp_match_le);

	/* Echo Response (0x09) -- Section 4.9 */
	ATF_TP_ADD_TC(tp, echo_rsp_match);
	ATF_TP_ADD_TC(tp, echo_rsp_no_match);
	ATF_TP_ADD_TC(tp, echo_rsp_ident_collides_con_req);
	ATF_TP_ADD_TC(tp, echo_rsp_timeout_ignored);

	/* Information Response (0x0B) -- Section 4.11 */
	ATF_TP_ADD_TC(tp, info_rsp_connless_mtu_success);
	ATF_TP_ADD_TC(tp, info_rsp_not_supported);
	ATF_TP_ADD_TC(tp, info_rsp_no_match);
	ATF_TP_ADD_TC(tp, info_rsp_connless_bad_len);

	/* LE Credit Based Connection Response (0x15) -- Section 4.23 */
	ATF_TP_ADD_TC(tp, le_credit_con_rsp_success);
	ATF_TP_ADD_TC(tp, le_credit_con_rsp_refused);
	ATF_TP_ADD_TC(tp, le_credit_con_rsp_success_bad_params);
	ATF_TP_ADD_TC(tp, le_credit_con_rsp_bad_mps);
	ATF_TP_ADD_TC(tp, le_credit_con_rsp_no_match);
	ATF_TP_ADD_TC(tp, le_credit_con_rsp_bad_state);
	ATF_TP_ADD_TC(tp, le_credit_con_rsp_ident_collides_con_req);

	/* Enhanced Credit Based Connection Response (0x18) -- Section 4.26 */
	ATF_TP_ADD_TC(tp, credit_con_rsp_success_le);
	ATF_TP_ADD_TC(tp, credit_con_rsp_all_refused_bredr);
	ATF_TP_ADD_TC(tp, credit_con_rsp_success_invalid_dcid);
	ATF_TP_ADD_TC(tp, credit_con_rsp_success_extra_dcid);
	ATF_TP_ADD_TC(tp, credit_con_rsp_reused_dcid_invalidates_both);
	ATF_TP_ADD_TC(tp, credit_con_rsp_bad_state);
	ATF_TP_ADD_TC(tp, credit_con_rsp_ident_collides_con_req);

	/* Credit Based Reconfigure Response (0x1A) -- Section 4.28 */
	ATF_TP_ADD_TC(tp, reconfig_rsp_success_le);
	ATF_TP_ADD_TC(tp, reconfig_rsp_failure_bredr);
	ATF_TP_ADD_TC(tp, reconfig_rsp_no_match);
	ATF_TP_ADD_TC(tp, reconfig_rsp_success_no_pending_flag);

	return (atf_no_error());
}
