/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Assertion-based ATF tests for the kernel HCI LE Create Connection build
 * path in sys/netgraph/bluetooth/hci/ng_hci_ulpi.c (the initiating role).
 *
 * Focus: LE privacy for the initiator.  Core Spec Vol 4 Part E Section
 * 7.8.12 (LE Create Connection) defines Own_Address_Type where 0x02/0x03
 * request a Resolvable Private Address from the local IRK in the resolving
 * list (falling back to public/random), and Peer_Address_Type where the
 * identity types 0x00 (public) and 0x01 (random) let controller-based
 * address resolution resolve a bonded peer's Resolvable Private Address
 * (Vol 6 Part B Link Layer privacy; Vol 3 Part C Section 10.7).  The
 * initiator MUST carry the supplied Own_Address_Type through to the
 * emitted command and set Peer_Address_Type to the peer's identity type.
 *
 * Technique (mirrors hci_le_role_test.c / l2cap_sig_test.c): #include the
 * kernel TU ng_hci_ulpi.c to reach ng_hci_lp_con_req().  Kernel-only
 * headers are neutralised via their include guards; a userspace
 * malloc-backed mbuf and a small set of test doubles for the misc/cmds
 * helpers stand in for the netgraph machinery.  The real ng_hci_var.h
 * unit/connection descriptors and ng_hci.h command layouts are intact, so
 * the emitted HCI_LE_Create_Connection command is parsed against the spec
 * byte layout rather than against the current output.
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/queue.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <atf-c.h>

/* Real UAPI: command param layouts, opcodes, link types, con states. */
#include <netgraph/bluetooth/include/ng_bluetooth.h>
#include <netgraph/bluetooth/include/ng_hci.h>

#include "spec_hci_privacy_kernel_oracles.h"

/* Neutralise kernel-only headers that ng_hci_ulpi.c includes. */
#define _SYS_SYSTM_H_
#define _SYS_KERNEL_H_
#define _SYS_MALLOC_H_
#define _SYS_MBUF_H_
#define _SYS_SDT_H
#define _NETGRAPH_NETGRAPH_H_
#define _NETGRAPH_NG_MESSAGE_H_

/* ----- netgraph glue types (normally netgraph/netgraph.h) ------------- */
typedef void *	node_p;
typedef void *	hook_p;
typedef void *	item_p;

#define NG_NODE_NAME(n)		"hci_ut"
#define NG_NODE_PRIVATE(n)	((void *)(n))
#define NG_NODE_NOT_VALID(n)	(0)
#define NG_HOOK_IS_VALID(h)	((h) != NULL)
#define NG_HOOK_NOT_VALID(h)	(1)
#define NG_HOOK_NAME(h)		"hook"

/* struct callout: ng_hci_var.h embeds one in the unit and each con. */
struct callout { void *_c; };

/* ----- SDT probes: compile to nothing (normally sys/sdt.h) ------------ */
#define SDT_PROVIDER_DECLARE(p)				struct __sdt_hack
#define SDT_PROBE_DEFINE1(p, m, f, n, a0)		struct __sdt_hack
#define SDT_PROBE_DEFINE2(p, m, f, n, a0, a1)		struct __sdt_hack
#define SDT_PROBE_DEFINE3(p, m, f, n, a0, a1, a2)	struct __sdt_hack
#define SDT_PROBE_DEFINE4(p, m, f, n, a0, a1, a2, a3)	struct __sdt_hack
#define SDT_PROBE1(p, m, f, n, a0)			do { } while (0)
#define SDT_PROBE2(p, m, f, n, a0, a1)			do { } while (0)
#define SDT_PROBE3(p, m, f, n, a0, a1, a2)		do { } while (0)
#define SDT_PROBE4(p, m, f, n, a0, a1, a2, a3)		do { } while (0)

/* ----- malloc/mbuf tunables (normally sys/malloc.h, sys/mbuf.h) ------- */
#define M_NOWAIT	0x0001
#define M_ZERO		0x0100
#define MT_DATA		1

#define NG_UT_MBUF_STORE	1024

struct mbuf {
	int		 m_len;
	struct {
		int	 len;
	}		 m_pkthdr;
	unsigned char	*m_data;
	struct mbuf	*m_nextpkt;	/* referenced by NG_BT_MBUFQ macros */
	unsigned char	 m_store[NG_UT_MBUF_STORE];
};

static int g_fail_mbuf;
static int g_fail_msg;

static struct mbuf *
ut_mbuf_alloc(void)
{
	struct mbuf	*m;

	if (g_fail_mbuf)
		return (NULL);
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

#define mtod(m, t)		((t)((m)->m_data))
#define MGETHDR(m, how, type)	((m) = ut_mbuf_alloc())

/* ----- netgraph message / item glue (normally ng_message.h) ---------- */
struct ng_mesg {
	struct {
		int	arglen;
	}	header;
	char	data[512];
};

#define NG_MKMESSAGE(msg, ck, cmd, len, fl)				\
	((msg) = g_fail_msg ? (g_fail_msg = 0, (struct ng_mesg *)NULL) : \
	calloc(1, sizeof(struct ng_mesg)))
#define NG_FREE_MSG(msg)	do { free(msg); (msg) = NULL; } while (0)
#define NG_SEND_MSG_HOOK(err, node, msg, hook, fl) \
	do { (err) = 0; free(msg); (msg) = NULL; } while (0)
#define NG_SEND_DATA_ONLY(err, hook, m)		do { (err) = 0; NG_FREE_M(m); } while (0)
#define NG_FREE_ITEM(i)		do { } while (0)
#define NG_FWD_ITEM_HOOK(err, i, hook)		do { (err) = 0; } while (0)
#define NGI_M(i)		((struct mbuf *)NULL)
#define NGI_MSG(i)		((struct ng_mesg *)(i))
#define _NGI_MSG(i)		(*(struct ng_mesg **)(i))
#define NGI_GET_MSG(i, m)	do { (m) = NULL; } while (0)

/* NGM_HCI_COOKIE comes from ng_hci.h; M_NETGRAPH_HCI from ng_hci_var.h. */

/* Full definition of struct ng_item so NG_BT_ITEMQ_* macros compile. */
struct ng_item { STAILQ_ENTRY(ng_item) el_next; };

static void getmicrotime(struct timeval *tv) { if (tv) { tv->tv_sec = 0; tv->tv_usec = 0; } }

/* ---------------------------------------------------------------------- */
/* Bring in the real unit/connection descriptors and command layouts. */
#include <netgraph/bluetooth/hci/ng_hci_var.h>
#include <netgraph/bluetooth/hci/ng_hci_cmds.h>
#include <netgraph/bluetooth/hci/ng_hci_evnt.h>
#include <netgraph/bluetooth/hci/ng_hci_ulpi.h>
#include <netgraph/bluetooth/hci/ng_hci_misc.h>

/* ----- test-double state ---------------------------------------------- */
static ng_hci_unit_con_p	g_new_con;	/* last con from ng_hci_new_con */
static int			g_cmd_sent;	/* ng_hci_send_command calls */
static int			g_fail_new_con;
static int			g_cmd_error;

static void
ut_reset(void)
{
	g_new_con = NULL;
	g_cmd_sent = 0;
	g_fail_new_con = 0;
	g_fail_mbuf = 0;
	g_fail_msg = 0;
	g_cmd_error = 0;
}

/* ----- misc.c doubles ------------------------------------------------- */
ng_hci_unit_con_p
ng_hci_new_con(ng_hci_unit_p unit, int link_type)
{
	ng_hci_unit_con_p	con;

	if (g_fail_new_con)
		return (NULL);
	con = calloc(1, sizeof(*con));
	ATF_REQUIRE(con != NULL);
	con->unit = unit;
	con->state = NG_HCI_CON_CLOSED;
	con->link_type = link_type;
	con->con_handle = unit->fake_con_handle++;
	LIST_INSERT_HEAD(&unit->con_list, con, next);
	g_new_con = con;
	return (con);
}

void
ng_hci_free_con(ng_hci_unit_con_p con)
{

	LIST_REMOVE(con, next);
	if (con == g_new_con)
		g_new_con = NULL;
	free(con);
}

ng_hci_unit_con_p
ng_hci_con_by_handle(ng_hci_unit_p unit, int con_handle)
{
	ng_hci_unit_con_p	con;

	LIST_FOREACH(con, &unit->con_list, next)
		if (con->con_handle == con_handle)
			return (con);
	return (NULL);
}

ng_hci_unit_con_p
ng_hci_con_by_bdaddr(ng_hci_unit_p unit, bdaddr_p bdaddr, int link_type)
{
	ng_hci_unit_con_p	con;

	LIST_FOREACH(con, &unit->con_list, next)
		if (con->link_type == link_type &&
		    bcmp(&con->bdaddr, bdaddr, sizeof(bdaddr_t)) == 0)
			return (con);
	return (NULL);
}

int  ng_hci_con_timeout(ng_hci_unit_con_p con)
{ con->flags |= NG_HCI_CON_TIMEOUT_PENDING; return (0); }
int  ng_hci_con_untimeout(ng_hci_unit_con_p con)
{ con->flags &= ~NG_HCI_CON_TIMEOUT_PENDING; return (0); }

ng_hci_neighbor_p ng_hci_new_neighbor(ng_hci_unit_p unit) { (void)unit; return (NULL); }
ng_hci_neighbor_p ng_hci_get_neighbor(ng_hci_unit_p u, bdaddr_p b, int t)
{ (void)u; (void)b; (void)t; return (NULL); }
void ng_hci_mtap(ng_hci_unit_p u, struct mbuf *m) { (void)u; (void)m; }

/* ----- cmds.c doubles ------------------------------------------------- */
int ng_hci_send_command(ng_hci_unit_p unit)
{ (void)unit; g_cmd_sent++; return (g_cmd_error); }
int ng_hci_process_command_complete(ng_hci_unit_p u, struct mbuf *m)
{ (void)u; NG_FREE_M(m); return (0); }
int ng_hci_process_command_status(ng_hci_unit_p u, struct mbuf *m)
{ (void)u; NG_FREE_M(m); return (0); }

/* ---------------------------------------------------------------------- */
/* The kernel TU under test. */
#include "ng_hci_ulpi.c"

/* ---------------------------------------------------------------------- */
static ng_hci_unit_t *
ut_unit_new(void)
{
	ng_hci_unit_t	*unit;

	unit = calloc(1, sizeof(*unit));
	ATF_REQUIRE(unit != NULL);
	LIST_INIT(&unit->con_list);
	LIST_INIT(&unit->neighbors);
	NG_BT_MBUFQ_INIT(&unit->cmdq, NG_HCI_CMD_QUEUE_LEN);
	unit->fake_con_handle = 0x0f00;
	unit->state = NG_HCI_UNIT_READY;	/* passes the readiness gate */
	/* Exercise diagnostics alongside each ULPI state transition. */
	unit->debug = NG_HCI_INFO_LEVEL;
	return (unit);
}

/*
 * Build an LP_ConnectReq message carrying an LE Create Connection request.
 * link_type selects the peer identity type (LE_PUBLIC/LE_RANDOM); bdaddr is
 * the peer identity address; own selects Own_Address_Type.
 */
static struct ng_mesg *
ut_lp_con_req(uint16_t link_type, const uint8_t addr[6], uint8_t own)
{
	struct ng_mesg		*msg;
	ng_hci_lp_con_req_ep	*ep;

	msg = calloc(1, sizeof(*msg));
	ATF_REQUIRE(msg != NULL);
	msg->header.arglen = sizeof(*ep);
	ep = (ng_hci_lp_con_req_ep *)msg->data;
	ep->link_type = link_type;
	bcopy(addr, &ep->bdaddr, sizeof(ep->bdaddr));
	ep->con_handle = 0;
	ep->own_address_type = own;
	return (msg);
}

static struct ng_mesg *
ut_lp_con_rsp(uint16_t link_type, const bdaddr_t *addr, uint8_t status)
{
	struct ng_mesg *msg;
	ng_hci_lp_con_rsp_ep *ep;

	msg = calloc(1, sizeof(*msg));
	ATF_REQUIRE(msg != NULL);
	msg->header.arglen = sizeof(*ep);
	ep = (ng_hci_lp_con_rsp_ep *)msg->data;
	ep->link_type = link_type;
	ep->bdaddr = *addr;
	ep->status = status;
	return (msg);
}

/*
 * Parse the single command mbuf the initiator enqueued on unit->cmdq and
 * validate it is an HCI_LE_Create_Connection command.  The layout follows
 * ng_hci_cmd_pkt_t (type,opcode,length) + ng_hci_le_create_connection_cp,
 * matching Core Spec Vol 4 Part E Section 7.8.12.
 */
static void
ut_get_create_conn(ng_hci_unit_t *unit, ng_hci_le_create_connection_cp *cp_out)
{
	struct mbuf		*m = NULL;
	ng_hci_cmd_pkt_t	 hdr;
	ng_hci_le_create_connection_cp	cp;

	ATF_REQUIRE_EQ(1, NG_BT_MBUFQ_LEN(&unit->cmdq));
	NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, m);
	ATF_REQUIRE(m != NULL);
	ATF_REQUIRE(m->m_len >= (int)(sizeof(hdr) + sizeof(cp)));

	memcpy(&hdr, m->m_data, sizeof(hdr));
	ATF_CHECK_EQ(BT_HK_SPEC_HCI_COMMAND_PACKET, hdr.type);
	ATF_CHECK_EQ(BT_HK_SPEC_OP_LE_CREATE_CONNECTION,
	    le16toh(hdr.opcode));
	ATF_CHECK_EQ(sizeof(cp), hdr.length);

	memcpy(&cp, m->m_data + sizeof(hdr), sizeof(cp));
	*cp_out = cp;
	NG_FREE_M(m);
}

static const uint8_t	peer_id_addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

/*
 * Privacy-enabled initiator: Own_Address_Type 0x02 (RPA, fall back to
 * public) with a public identity peer address.  The emitted command MUST
 * carry Own_Address_Type 0x02 and Peer_Address_Type 0x00 (public identity)
 * so controller-based address resolution can target the bonded peer's RPA.
 * Core Spec Vol 4 Part E Section 7.8.12.
 */
ATF_TC_WITHOUT_HEAD(le_create_conn_own_rpa_public_identity);
ATF_TC_BODY(le_create_conn_own_rpa_public_identity, tc)
{
	ng_hci_unit_t			*unit = ut_unit_new();
	struct ng_mesg			*msg;
	ng_hci_le_create_connection_cp	 cp;

	ut_reset();
	msg = ut_lp_con_req(NG_HCI_LINK_LE_PUBLIC, peer_id_addr,
	    BT_HK_SPEC_OWN_RPA_PUBLIC_FALLBACK);

	ATF_REQUIRE_EQ(0, ng_hci_lp_con_req(unit, (item_p)msg, NULL));

	ut_get_create_conn(unit, &cp);
	/* Keystone: the supplied Own_Address_Type is threaded through. */
	ATF_CHECK_EQ(BT_HK_SPEC_OWN_RPA_PUBLIC_FALLBACK,
	    cp.own_address_type);
	/* Public identity peer type for the resolving-list path. */
	ATF_CHECK_EQ(BT_HK_SPEC_PEER_PUBLIC_IDENTITY, cp.peer_addr_type);
	ATF_CHECK_EQ(0, memcmp(&cp.peer_addr, peer_id_addr, sizeof(peer_id_addr)));

	free(msg);
}

/*
 * Privacy-enabled initiator with a random identity peer: Own_Address_Type
 * 0x03 (RPA, fall back to random) and a random identity peer address MUST
 * yield Own_Address_Type 0x03 and Peer_Address_Type 0x01 (random identity).
 * Core Spec Vol 4 Part E Section 7.8.12.
 */
ATF_TC_WITHOUT_HEAD(le_create_conn_own_rpa_random_identity);
ATF_TC_BODY(le_create_conn_own_rpa_random_identity, tc)
{
	ng_hci_unit_t			*unit = ut_unit_new();
	struct ng_mesg			*msg;
	ng_hci_le_create_connection_cp	 cp;

	ut_reset();
	msg = ut_lp_con_req(NG_HCI_LINK_LE_RANDOM, peer_id_addr,
	    BT_HK_SPEC_OWN_RPA_RANDOM_FALLBACK);

	ATF_REQUIRE_EQ(0, ng_hci_lp_con_req(unit, (item_p)msg, NULL));

	ut_get_create_conn(unit, &cp);
	ATF_CHECK_EQ(BT_HK_SPEC_OWN_RPA_RANDOM_FALLBACK,
	    cp.own_address_type);
	ATF_CHECK_EQ(BT_HK_SPEC_PEER_RANDOM_IDENTITY, cp.peer_addr_type);
	ATF_CHECK_EQ(0, memcmp(&cp.peer_addr, peer_id_addr, sizeof(peer_id_addr)));

	free(msg);
}

/*
 * Non-privacy default: Own_Address_Type 0x00 (public device address) with a
 * public peer.  Proves the legacy path is unchanged -- Own_Address_Type
 * 0x00, Peer_Address_Type 0x00.  Core Spec Vol 4 Part E Section 7.8.12.
 */
ATF_TC_WITHOUT_HEAD(le_create_conn_own_public_default);
ATF_TC_BODY(le_create_conn_own_public_default, tc)
{
	ng_hci_unit_t			*unit = ut_unit_new();
	struct ng_mesg			*msg;
	ng_hci_le_create_connection_cp	 cp;

	ut_reset();
	msg = ut_lp_con_req(NG_HCI_LINK_LE_PUBLIC, peer_id_addr,
	    BT_HK_SPEC_OWN_PUBLIC);

	ATF_REQUIRE_EQ(0, ng_hci_lp_con_req(unit, (item_p)msg, NULL));

	ut_get_create_conn(unit, &cp);
	ATF_CHECK_EQ(BT_HK_SPEC_OWN_PUBLIC, cp.own_address_type);
	ATF_CHECK_EQ(BT_HK_SPEC_PEER_PUBLIC_IDENTITY, cp.peer_addr_type);

	free(msg);
}

ATF_TC_WITHOUT_HEAD(lp_connect_dispatch_and_acl_states);
ATF_TC_BODY(lp_connect_dispatch_and_acl_states, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p con;
	struct ng_mesg *msg;
	struct mbuf *queued;

	unit = ut_unit_new();
	ut_reset();

	msg = ut_lp_con_req(NG_HCI_LINK_LE_PUBLIC, peer_id_addr, 0);
	unit->state = 0;
	ATF_CHECK_EQ(ENXIO, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);
	unit->state = NG_HCI_UNIT_READY;

	msg = ut_lp_con_req(NG_HCI_LINK_LE_PUBLIC, peer_id_addr, 0);
	msg->header.arglen = 0;
	ATF_CHECK_EQ(EMSGSIZE, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);

	msg = ut_lp_con_req(NG_HCI_LINK_SCO, peer_id_addr, 0);
	unit->sco = (hook_p)(uintptr_t)1;
	ATF_CHECK_EQ(EINVAL, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);

	msg = ut_lp_con_req(0xffff, peer_id_addr, 0);
	ATF_CHECK_EQ(EINVAL, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);

	msg = ut_lp_con_req(NG_HCI_LINK_ISO_CIS, peer_id_addr, 0);
	ATF_CHECK_EQ(ENOENT, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);

	/* Create a classic ACL, then drive every existing-descriptor state. */
	msg = ut_lp_con_req(NG_HCI_LINK_ACL, peer_id_addr, 0);
	ATF_REQUIRE_EQ(0, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);
	con = g_new_con;
	ATF_REQUIRE(con != NULL);
	NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
	ATF_REQUIRE(queued != NULL);
	NG_FREE_M(queued);

	con->state = NG_HCI_CON_W4_LP_CON_RSP;
	msg = ut_lp_con_req(NG_HCI_LINK_ACL, peer_id_addr, 0);
	ATF_CHECK_EQ(EALREADY, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);
	con->state = NG_HCI_CON_W4_CONN_COMPLETE;
	msg = ut_lp_con_req(NG_HCI_LINK_ACL, peer_id_addr, 0);
	ATF_CHECK_EQ(0, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);
	con->state = NG_HCI_CON_OPEN;
	msg = ut_lp_con_req(NG_HCI_LINK_ACL, peer_id_addr, 0);
	ATF_CHECK_EQ(0, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);
	con->state = 0xff;
	msg = ut_lp_con_req(NG_HCI_LINK_ACL, peer_id_addr, 0);
	ATF_CHECK_EQ(EINVAL, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);

	ng_hci_free_con(con);
	free(unit);
}

ATF_TC_WITHOUT_HEAD(ulpi_request_and_notification_matrix);
ATF_TC_BODY(ulpi_request_and_notification_matrix, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p con;
	struct ng_mesg *msg;
	struct mbuf *queued;
	uint8_t uclass[3] = { 1, 2, 3 };

	unit = ut_unit_new();
	ut_reset();
	con = ng_hci_new_con(unit, NG_HCI_LINK_ACL);
	con->state = NG_HCI_CON_OPEN;
	bcopy(peer_id_addr, &con->bdaddr, sizeof(con->bdaddr));
	con->flags = NG_HCI_CON_NOTIFY_ACL | NG_HCI_CON_NOTIFY_SCO |
	    NG_HCI_CON_NOTIFY_ISO;
	unit->acl = (hook_p)(uintptr_t)1;

	/* Existing OPEN ACL/LE descriptors immediately confirm to a valid source
	 * hook; verify both the forwarded-message and allocation-failure arms. */
	msg = ut_lp_con_req(NG_HCI_LINK_ACL, peer_id_addr, 0);
	ATF_CHECK_EQ(0, ng_hci_lp_con_req(unit, (item_p)msg, unit->acl));
	free(msg);
	msg = ut_lp_con_req(NG_HCI_LINK_ACL, peer_id_addr, 0);
	g_fail_msg = 1;
	ATF_CHECK_EQ(ENOMEM, ng_hci_lp_con_req(unit, (item_p)msg, unit->acl));
	free(msg);
	con->link_type = NG_HCI_LINK_LE_PUBLIC;
	msg = ut_lp_con_req(NG_HCI_LINK_LE_PUBLIC, peer_id_addr, 0);
	ATF_CHECK_EQ(0, ng_hci_lp_con_req(unit, (item_p)msg, unit->acl));
	free(msg);
	msg = ut_lp_con_req(NG_HCI_LINK_LE_PUBLIC, peer_id_addr, 0);
	g_fail_msg = 1;
	ATF_CHECK_EQ(ENOMEM, ng_hci_lp_con_req(unit, (item_p)msg, unit->acl));
	free(msg);
	con->link_type = NG_HCI_LINK_ACL;
	unit->acl = NULL;

	/* Complete valid command requests enqueue their corresponding HCI PDU. */
	msg = calloc(1, sizeof(*msg));
	ATF_REQUIRE(msg != NULL);
	msg->header.arglen = sizeof(ng_hci_lp_discon_req_ep);
	((ng_hci_lp_discon_req_ep *)msg->data)->con_handle = con->con_handle;
	((ng_hci_lp_discon_req_ep *)msg->data)->reason =
	    NG_HCI_ERROR_USER_ENDED_CON;
	ATF_CHECK_EQ(0, ng_hci_lp_discon_req(unit, (item_p)msg, NULL));
	free(msg);

	msg = calloc(1, sizeof(*msg));
	ATF_REQUIRE(msg != NULL);
	msg->header.arglen = sizeof(ng_hci_lp_con_update_ep);
	((ng_hci_lp_con_update_ep *)msg->data)->con_handle = con->con_handle;
	ATF_CHECK_EQ(0, ng_hci_lp_con_update(unit, (item_p)msg, NULL));
	free(msg);

	msg = calloc(1, sizeof(*msg));
	ATF_REQUIRE(msg != NULL);
	msg->header.arglen = sizeof(ng_hci_lp_qos_req_ep);
	((ng_hci_lp_qos_req_ep *)msg->data)->con_handle = con->con_handle;
	ATF_CHECK_EQ(0, ng_hci_lp_qos_req(unit, (item_p)msg, NULL));
	free(msg);
	ATF_CHECK_EQ(3, NG_BT_MBUFQ_LEN(&unit->cmdq));
	while (NG_BT_MBUFQ_LEN(&unit->cmdq) != 0) {
		NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
		NG_FREE_M(queued);
	}

	/* Every upper notification family, with absent-hook fallbacks. */
	con->flags = NG_HCI_CON_NOTIFY_ACL | NG_HCI_CON_NOTIFY_SCO |
	    NG_HCI_CON_NOTIFY_ISO;
	ATF_CHECK_EQ(0, ng_hci_lp_con_cfm(con, 0));
	ATF_CHECK_EQ(0, ng_hci_lp_enc_change(con, 0));
	ATF_CHECK_EQ(ENOTCONN, ng_hci_lp_con_ind(con, uclass));
	ATF_CHECK_EQ(0, ng_hci_lp_discon_ind(con,
	    NG_HCI_ERROR_USER_ENDED_CON));
	con->flags = NG_HCI_CON_NOTIFY_ACL | NG_HCI_CON_NOTIFY_SCO;
	ATF_CHECK_EQ(0, ng_hci_lp_qos_cfm(con, 0));
	ATF_CHECK_EQ(0, ng_hci_lp_qos_ind(con));

	con->link_type = NG_HCI_LINK_SCO;
	ATF_CHECK_EQ(ENOTCONN, ng_hci_lp_con_ind(con, uclass));
	ATF_CHECK_EQ(0, ng_hci_lp_discon_ind(con, 0));
	con->link_type = NG_HCI_LINK_ISO_CIS;
	ATF_CHECK_EQ(0, ng_hci_lp_discon_ind(con, 0));
	con->link_type = NG_HCI_LINK_LE_PUBLIC;
	ATF_CHECK_EQ(0, ng_hci_lp_discon_ind(con, 0));

	/* Connect response: LE no-descriptor success and classic accept path. */
	msg = calloc(1, sizeof(*msg));
	ATF_REQUIRE(msg != NULL);
	msg->header.arglen = sizeof(ng_hci_lp_con_rsp_ep);
	((ng_hci_lp_con_rsp_ep *)msg->data)->link_type = NG_HCI_LINK_LE_RANDOM;
	ATF_CHECK_EQ(0, ng_hci_lp_con_rsp(unit, (item_p)msg, NULL));
	free(msg);

	con->link_type = NG_HCI_LINK_ACL;
	con->state = NG_HCI_CON_W4_LP_CON_RSP;
	con->flags |= NG_HCI_CON_TIMEOUT_PENDING;
	msg = calloc(1, sizeof(*msg));
	ATF_REQUIRE(msg != NULL);
	msg->header.arglen = sizeof(ng_hci_lp_con_rsp_ep);
	((ng_hci_lp_con_rsp_ep *)msg->data)->link_type = NG_HCI_LINK_ACL;
	((ng_hci_lp_con_rsp_ep *)msg->data)->status = 0;
	((ng_hci_lp_con_rsp_ep *)msg->data)->bdaddr = con->bdaddr;
	ATF_CHECK_EQ(0, ng_hci_lp_con_rsp(unit, (item_p)msg, unit->acl));
	free(msg);
	while (NG_BT_MBUFQ_LEN(&unit->cmdq) != 0) {
		NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
		NG_FREE_M(queued);
	}

	ng_hci_free_con(con);
	free(unit);
}

ATF_TC_WITHOUT_HEAD(sco_and_connection_timeout_matrix);
ATF_TC_BODY(sco_and_connection_timeout_matrix, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p acl, sco, con;
	struct ng_mesg *msg;
	struct mbuf *queued;

	unit = ut_unit_new();
	ut_reset();
	msg = ut_lp_con_req(NG_HCI_LINK_SCO, peer_id_addr, 0);
	ATF_CHECK_EQ(ENOENT, ng_hci_lp_sco_con_req(unit, (item_p)msg, NULL));
	free(msg);

	acl = ng_hci_new_con(unit, NG_HCI_LINK_ACL);
	acl->state = NG_HCI_CON_OPEN;
	bcopy(peer_id_addr, &acl->bdaddr, sizeof(acl->bdaddr));
	unit->features[1] = NG_HCI_LMP_HV2_PKT | NG_HCI_LMP_HV3_PKT;
	unit->packet_mask = 0xffff;
	msg = ut_lp_con_req(NG_HCI_LINK_SCO, peer_id_addr, 0);
	ATF_REQUIRE_EQ(0, ng_hci_lp_sco_con_req(unit, (item_p)msg, NULL));
	free(msg);
	sco = g_new_con;
	ATF_REQUIRE(sco != NULL);
	ATF_CHECK_EQ(NG_HCI_CON_W4_CONN_COMPLETE, sco->state);
	ATF_CHECK((sco->flags & NG_HCI_CON_NOTIFY_SCO) != 0);
	NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
	ATF_REQUIRE(queued != NULL);
	NG_FREE_M(queued);

	msg = ut_lp_con_req(NG_HCI_LINK_SCO, peer_id_addr, 0);
	ATF_CHECK_EQ(0, ng_hci_lp_sco_con_req(unit, (item_p)msg, NULL));
	free(msg);
	sco->state = NG_HCI_CON_W4_LP_CON_RSP;
	msg = ut_lp_con_req(NG_HCI_LINK_SCO, peer_id_addr, 0);
	ATF_CHECK_EQ(EALREADY, ng_hci_lp_sco_con_req(unit, (item_p)msg, NULL));
	free(msg);
	ng_hci_free_con(sco);
	ng_hci_free_con(acl);

	/* Timeout callback: missing, unarmed, incoming, outgoing, bad state. */
	ng_hci_process_con_timeout((node_p)unit, NULL, NULL, 0x7fff);
	con = ng_hci_new_con(unit, NG_HCI_LINK_ACL);
	con->state = NG_HCI_CON_OPEN;
	ng_hci_process_con_timeout((node_p)unit, NULL, NULL, con->con_handle);
	ATF_CHECK(ng_hci_con_by_handle(unit, con->con_handle) == con);
	ng_hci_free_con(con);

	con = ng_hci_new_con(unit, NG_HCI_LINK_ACL);
	con->state = NG_HCI_CON_W4_LP_CON_RSP;
	con->flags = NG_HCI_CON_TIMEOUT_PENDING;
	ng_hci_process_con_timeout((node_p)unit, NULL, NULL, con->con_handle);
	ATF_CHECK(g_new_con == NULL);

	con = ng_hci_new_con(unit, NG_HCI_LINK_ACL);
	con->state = NG_HCI_CON_W4_CONN_COMPLETE;
	con->flags = NG_HCI_CON_TIMEOUT_PENDING | NG_HCI_CON_NOTIFY_ACL;
	ng_hci_process_con_timeout((node_p)unit, NULL, NULL, con->con_handle);
	ATF_CHECK(g_new_con == NULL);

	con = ng_hci_new_con(unit, NG_HCI_LINK_ACL);
	con->state = NG_HCI_CON_OPEN;
	con->flags = NG_HCI_CON_TIMEOUT_PENDING;
	ng_hci_process_con_timeout((node_p)unit, NULL, NULL, con->con_handle);
	ATF_CHECK(ng_hci_con_by_handle(unit, con->con_handle) == con);
	ng_hci_free_con(con);
	free(unit);
}

ATF_TC_WITHOUT_HEAD(ulpi_request_validation_matrix);
ATF_TC_BODY(ulpi_request_validation_matrix, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p con;
	struct ng_mesg *msg;
	uint16_t handle;

	unit = ut_unit_new();
	con = ng_hci_new_con(unit, NG_HCI_LINK_ACL);
	con->state = NG_HCI_CON_OPEN;
	handle = con->con_handle;

#define RUN_REQ_ERRORS(_type, _fn, _missing_error) do {                      \
	msg = calloc(1, sizeof(*msg));                                        \
	ATF_REQUIRE(msg != NULL);                                             \
	msg->header.arglen = sizeof(_type);                                   \
	((_type *)msg->data)->con_handle = handle;                            \
	unit->state = 0;                                                      \
	ATF_CHECK_EQ(ENXIO, _fn(unit, (item_p)msg, NULL));                    \
	free(msg);                                                            \
	unit->state = NG_HCI_UNIT_READY;                                      \
	msg = calloc(1, sizeof(*msg));                                        \
	ATF_REQUIRE(msg != NULL);                                             \
	ATF_CHECK_EQ(EMSGSIZE, _fn(unit, (item_p)msg, NULL));                 \
	free(msg);                                                            \
	msg = calloc(1, sizeof(*msg));                                        \
	ATF_REQUIRE(msg != NULL);                                             \
	msg->header.arglen = sizeof(_type);                                   \
	((_type *)msg->data)->con_handle = 0x7fff;                            \
	ATF_CHECK_EQ((_missing_error), _fn(unit, (item_p)msg, NULL));         \
	free(msg);                                                            \
	msg = calloc(1, sizeof(*msg));                                        \
	ATF_REQUIRE(msg != NULL);                                             \
	msg->header.arglen = sizeof(_type);                                   \
	((_type *)msg->data)->con_handle = handle;                            \
	con->state = NG_HCI_CON_W4_CONN_COMPLETE;                             \
	ATF_CHECK_EQ(EINVAL, _fn(unit, (item_p)msg, NULL));                   \
	free(msg);                                                            \
	con->state = NG_HCI_CON_OPEN;                                         \
} while (0)

	RUN_REQ_ERRORS(ng_hci_lp_discon_req_ep, ng_hci_lp_discon_req, ENOENT);
	RUN_REQ_ERRORS(ng_hci_lp_con_update_ep, ng_hci_lp_con_update, ENOENT);
	RUN_REQ_ERRORS(ng_hci_lp_qos_req_ep, ng_hci_lp_qos_req, EINVAL);
#undef RUN_REQ_ERRORS

	ng_hci_free_con(con);
	free(unit);
}

ATF_TC_WITHOUT_HEAD(connect_response_link_matrix);
ATF_TC_BODY(connect_response_link_matrix, tc)
{
	static const uint16_t links[] = { NG_HCI_LINK_LE_PUBLIC,
	    NG_HCI_LINK_ISO_CIS };
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p con;
	struct ng_mesg *msg;
	struct mbuf *queued;
	bdaddr_t addr;

	unit = ut_unit_new();
	bcopy(peer_id_addr, &addr, sizeof(addr));
	unit->features[0] = NG_HCI_LMP_SWITCH;
	unit->role_switch = 1;

	/* Classic accept, duplicate accept, and losing reject race. */
	con = ng_hci_new_con(unit, NG_HCI_LINK_ACL);
	con->state = NG_HCI_CON_W4_LP_CON_RSP;
	con->flags = NG_HCI_CON_TIMEOUT_PENDING;
	con->bdaddr = addr;
	msg = ut_lp_con_rsp(NG_HCI_LINK_ACL, &addr, 0);
	ATF_REQUIRE_EQ(0, ng_hci_lp_con_rsp(unit, (item_p)msg, NULL));
	free(msg);
	ATF_CHECK_EQ(NG_HCI_CON_W4_CONN_COMPLETE, con->state);
	NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
	ATF_REQUIRE(queued != NULL);
	NG_FREE_M(queued);
	msg = ut_lp_con_rsp(NG_HCI_LINK_ACL, &addr, 0);
	ATF_CHECK_EQ(0, ng_hci_lp_con_rsp(unit, (item_p)msg, NULL));
	free(msg);
	msg = ut_lp_con_rsp(NG_HCI_LINK_ACL, &addr, 1);
	ATF_CHECK_EQ(EPERM, ng_hci_lp_con_rsp(unit, (item_p)msg, NULL));
	free(msg);
	ng_hci_free_con(con);

	/* Classic rejection emits Reject Connection and destroys the pending con. */
	con = ng_hci_new_con(unit, NG_HCI_LINK_ACL);
	con->state = NG_HCI_CON_W4_LP_CON_RSP;
	con->flags = NG_HCI_CON_TIMEOUT_PENDING;
	con->bdaddr = addr;
	msg = ut_lp_con_rsp(NG_HCI_LINK_ACL, &addr, 0x0d);
	ATF_REQUIRE_EQ(0, ng_hci_lp_con_rsp(unit, (item_p)msg, NULL));
	free(msg);
	ATF_CHECK(g_new_con == NULL);
	NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
	ATF_REQUIRE(queued != NULL);
	NG_FREE_M(queued);

	/* LE and ISO pending descriptors each cover accept and reject semantics. */
	for (size_t i = 0; i < nitems(links); i++) {
		for (int reject = 0; reject < 2; reject++) {
			con = ng_hci_new_con(unit, links[i]);
			con->state = NG_HCI_CON_W4_LP_CON_RSP;
			con->flags = NG_HCI_CON_TIMEOUT_PENDING;
			con->bdaddr = addr;
			if (links[i] == NG_HCI_LINK_ISO_CIS)
				con->con_handle = (uint16_t)(0x80 + i);
			msg = ut_lp_con_rsp(links[i], &addr,
			    reject ? 0x0d : 0);
			if (links[i] == NG_HCI_LINK_ISO_CIS)
				((ng_hci_lp_con_rsp_ep *)msg->data)->con_handle =
				    con->con_handle;
			ATF_REQUIRE_EQ(0, ng_hci_lp_con_rsp(unit,
			    (item_p)msg, NULL));
			free(msg);
			if (links[i] == NG_HCI_LINK_ISO_CIS) {
				NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
				ATF_REQUIRE(queued != NULL);
				NG_FREE_M(queued);
			}
			if (!reject)
				ng_hci_free_con(con);
			else
				ATF_CHECK(g_new_con == NULL);
		}
	}
	free(unit);
}

ATF_TC_WITHOUT_HEAD(valid_upstream_notification_matrix);
ATF_TC_BODY(valid_upstream_notification_matrix, tc)
{
	static const uint16_t links[] = { NG_HCI_LINK_ACL, NG_HCI_LINK_LE_PUBLIC,
	    NG_HCI_LINK_SCO, NG_HCI_LINK_ISO_CIS };
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p con;
	uint8_t uclass[3] = { 1, 2, 3 };

	unit = ut_unit_new();
	unit->acl = (hook_p)(uintptr_t)1;
	unit->sco = (hook_p)(uintptr_t)2;
	unit->iso = (hook_p)(uintptr_t)3;
	for (size_t i = 0; i < nitems(links); i++) {
		con = ng_hci_new_con(unit, links[i]);
		con->state = NG_HCI_CON_OPEN;
		con->flags = NG_HCI_CON_NOTIFY_ACL | NG_HCI_CON_NOTIFY_SCO |
		    NG_HCI_CON_NOTIFY_ISO;
		ATF_CHECK_EQ(0, ng_hci_lp_con_cfm(con, (int)i));
		ATF_CHECK_EQ(0, ng_hci_lp_enc_change(con, (int)i));
		ATF_CHECK_EQ(0, ng_hci_lp_con_ind(con, uclass));
		con->flags = NG_HCI_CON_NOTIFY_ACL | NG_HCI_CON_NOTIFY_SCO;
		ATF_CHECK_EQ(0, ng_hci_lp_qos_cfm(con, (int)i));
		ATF_CHECK_EQ(0, ng_hci_lp_qos_ind(con));
		ATF_CHECK_EQ(0, ng_hci_lp_discon_ind(con, (int)i));
		ng_hci_free_con(con);
	}
	free(unit);
}

ATF_TC_WITHOUT_HEAD(cis_create_command_and_state);
ATF_TC_BODY(cis_create_command_and_state, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p acl, cis;
	struct ng_mesg *msg;
	struct mbuf *m;
	ng_hci_cmd_pkt_t hdr;
	uint16_t cis_handle, acl_handle;

	unit = ut_unit_new();
	ut_reset();
	acl = ng_hci_new_con(unit, NG_HCI_LINK_LE_PUBLIC);
	ATF_REQUIRE(acl != NULL);
	bcopy(peer_id_addr, &acl->bdaddr, sizeof(acl->bdaddr));
	acl->state = NG_HCI_CON_OPEN;
	acl->con_handle = 0x0042;

	msg = ut_lp_con_req(NG_HCI_LINK_ISO_CIS, peer_id_addr, 0);
	((ng_hci_lp_con_req_ep *)msg->data)->con_handle = 0x0123;
	ATF_REQUIRE_EQ(0, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	ATF_CHECK_EQ(g_cmd_sent, 1);
	cis = g_new_con;
	ATF_REQUIRE(cis != NULL);
	ATF_CHECK_EQ(cis->link_type, NG_HCI_LINK_ISO_CIS);
	ATF_CHECK_EQ(cis->con_handle, 0x0123);
	ATF_CHECK_EQ(cis->state, NG_HCI_CON_W4_CONN_COMPLETE);
	ATF_CHECK((cis->flags & NG_HCI_CON_NOTIFY_ISO) != 0);
	ATF_CHECK((cis->flags & NG_HCI_CON_TIMEOUT_PENDING) != 0);

	ATF_REQUIRE_EQ(NG_BT_MBUFQ_LEN(&unit->cmdq), 1);
	NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, m);
	ATF_REQUIRE(m != NULL);
	ATF_REQUIRE(m->m_len >= (int)(sizeof(hdr) +
	    BT_HK_SPEC_CREATE_CIS_PARAM_LEN_ONE));
	memcpy(&hdr, m->m_data, sizeof(hdr));
	ATF_CHECK_EQ(BT_HK_SPEC_HCI_COMMAND_PACKET, hdr.type);
	ATF_CHECK_EQ(le16toh(hdr.opcode), BT_HK_SPEC_OP_LE_CREATE_CIS);
	ATF_CHECK_EQ(BT_HK_SPEC_CREATE_CIS_PARAM_LEN_ONE, hdr.length);
	ATF_CHECK_EQ(m->m_data[sizeof(hdr)],
	    BT_HK_SPEC_CREATE_CIS_COUNT_ONE);
	memcpy(&cis_handle, m->m_data + sizeof(hdr) + 1, sizeof(cis_handle));
	memcpy(&acl_handle, m->m_data + sizeof(hdr) + 3, sizeof(acl_handle));
	ATF_CHECK_EQ(le16toh(cis_handle), 0x0123);
	ATF_CHECK_EQ(le16toh(acl_handle), 0x0042);
	NG_FREE_M(m);
	free(msg);
	ng_hci_free_con(cis);
	ng_hci_free_con(acl);
	free(unit);
}

ATF_TC_WITHOUT_HEAD(cis_create_fault_cleanup_matrix);
ATF_TC_BODY(cis_create_fault_cleanup_matrix, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p acl;
	struct ng_mesg *msg;
	int expected[] = { ENOMEM, ENOBUFS, EIO };
	size_t i;

	for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
		unit = ut_unit_new();
		ut_reset();
		acl = ng_hci_new_con(unit, NG_HCI_LINK_LE_RANDOM);
		ATF_REQUIRE(acl != NULL);
		bcopy(peer_id_addr, &acl->bdaddr, sizeof(acl->bdaddr));
		acl->state = NG_HCI_CON_OPEN;
		acl->con_handle = 0x0043;
		if (i == 0)
			g_fail_new_con = 1;
		else if (i == 1)
			g_fail_mbuf = 1;
		else
			g_cmd_error = EIO;
		msg = ut_lp_con_req(NG_HCI_LINK_ISO_CIS, peer_id_addr, 0);
		((ng_hci_lp_con_req_ep *)msg->data)->con_handle = 0x0124;
		ATF_CHECK_EQ(expected[i],
		    ng_hci_lp_con_req(unit, (item_p)msg, NULL));
		ATF_CHECK_EQ(NG_BT_MBUFQ_LEN(&unit->cmdq), 0);
		ATF_CHECK(ng_hci_con_by_handle(unit, 0x0124) == NULL);
		free(msg);
		g_fail_new_con = g_fail_mbuf = g_cmd_error = 0;
		ng_hci_free_con(acl);
		free(unit);
	}
}

ATF_TC_WITHOUT_HEAD(upstream_message_allocation_failures);
ATF_TC_BODY(upstream_message_allocation_failures, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p con;
	uint8_t uclass[3] = { 1, 2, 3 };

	unit = ut_unit_new();
	ut_reset();
	unit->acl = (hook_p)(uintptr_t)1;
	unit->sco = (hook_p)(uintptr_t)2;
	unit->iso = (hook_p)(uintptr_t)3;
	con = ng_hci_new_con(unit, NG_HCI_LINK_ACL);
	con->state = NG_HCI_CON_OPEN;
	con->flags = NG_HCI_CON_NOTIFY_ACL | NG_HCI_CON_NOTIFY_SCO |
	    NG_HCI_CON_NOTIFY_ISO;

	g_fail_msg = 1;
	ATF_CHECK_EQ(0, ng_hci_lp_con_cfm(con, 0));
	con->flags = NG_HCI_CON_NOTIFY_ACL | NG_HCI_CON_NOTIFY_SCO;
	g_fail_msg = 1;
	ATF_CHECK_EQ(0, ng_hci_lp_enc_change(con, 0));
	con->flags = NG_HCI_CON_NOTIFY_ACL | NG_HCI_CON_NOTIFY_SCO;
	g_fail_msg = 1;
	ATF_CHECK_EQ(ENOMEM, ng_hci_lp_con_ind(con, uclass));
	g_fail_msg = 1;
	ATF_CHECK_EQ(0, ng_hci_lp_qos_cfm(con, 0));
	g_fail_msg = 1;
	ATF_CHECK_EQ(ENOMEM, ng_hci_lp_qos_ind(con));
	g_fail_msg = 1;
	ATF_CHECK_EQ(ENOMEM, ng_hci_lp_discon_ind(con, 0));

	con->link_type = NG_HCI_LINK_SCO;
	g_fail_msg = 1;
	ATF_CHECK_EQ(ENOMEM, ng_hci_lp_discon_ind(con, 0));
	con->link_type = NG_HCI_LINK_ISO_CIS;
	g_fail_msg = 1;
	ATF_CHECK_EQ(ENOMEM, ng_hci_lp_discon_ind(con, 0));

	ng_hci_free_con(con);
	free(unit);
}

ATF_TC_WITHOUT_HEAD(connection_request_fault_and_state_matrix);
ATF_TC_BODY(connection_request_fault_and_state_matrix, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p acl, con;
	struct ng_mesg *msg;
	struct mbuf *queued;
	uint8_t other_addr[6] = { 6, 5, 4, 3, 2, 1 };

	unit = ut_unit_new();
	ut_reset();
	unit->packet_mask = 0xffff;

	/* Classic ACL descriptor and command allocation failures. */
	g_fail_new_con = 1;
	msg = ut_lp_con_req(NG_HCI_LINK_ACL, peer_id_addr, 0);
	ATF_CHECK_EQ(ENOMEM, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);
	g_fail_new_con = 0;
	g_fail_mbuf = 1;
	msg = ut_lp_con_req(NG_HCI_LINK_ACL, peer_id_addr, 0);
	ATF_CHECK_EQ(ENOBUFS, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);
	g_fail_mbuf = 0;

	/* Optional 3/5-slot and role-switch command fields, plus SCO notifier. */
	unit->features[0] = NG_HCI_LMP_3SLOT | NG_HCI_LMP_5SLOT |
	    NG_HCI_LMP_SWITCH;
	unit->role_switch = 1;
	unit->acl = (hook_p)(uintptr_t)1;
	msg = ut_lp_con_req(NG_HCI_LINK_ACL, peer_id_addr, 0);
	ATF_REQUIRE_EQ(0, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);
	acl = g_new_con;
	ATF_REQUIRE(acl != NULL);
	ATF_CHECK((acl->flags & NG_HCI_CON_NOTIFY_SCO) != 0);
	NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
	ATF_REQUIRE(queued != NULL);
	NG_FREE_M(queued);
	acl->state = NG_HCI_CON_OPEN;

	/* SCO descriptor/mbuf failures and the conservative HV1 fallback. */
	g_fail_new_con = 1;
	msg = ut_lp_con_req(NG_HCI_LINK_SCO, peer_id_addr, 0);
	ATF_CHECK_EQ(ENOMEM, ng_hci_lp_sco_con_req(unit, (item_p)msg, NULL));
	free(msg);
	g_fail_new_con = 0;
	g_fail_mbuf = 1;
	msg = ut_lp_con_req(NG_HCI_LINK_SCO, peer_id_addr, 0);
	ATF_CHECK_EQ(ENOBUFS, ng_hci_lp_sco_con_req(unit, (item_p)msg, NULL));
	free(msg);
	g_fail_mbuf = 0;
	unit->features[1] = 0;
	unit->packet_mask = 0;
	msg = ut_lp_con_req(NG_HCI_LINK_SCO, peer_id_addr, 0);
	ATF_REQUIRE_EQ(0, ng_hci_lp_sco_con_req(unit, (item_p)msg, NULL));
	free(msg);
	con = g_new_con;
	ATF_REQUIRE(con != NULL && con != acl);
	NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
	ATF_REQUIRE(queued != NULL);
	NG_FREE_M(queued);
	ng_hci_free_con(con);

	/* LE validates invalid direct dispatch, allocation failures, pending
	 * initiator exclusion, and every existing-descriptor state. */
	msg = ut_lp_con_req(NG_HCI_LINK_LE_PUBLIC, other_addr, 0);
	ATF_CHECK_EQ(0, ng_hci_lp_le_con_req(unit, (item_p)msg, NULL,
	    NG_HCI_LINK_ACL));
	free(msg);
	con = g_new_con;
	ATF_REQUIRE(con != NULL && con != acl);
	NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
	ATF_REQUIRE(queued != NULL);
	NG_FREE_M(queued);
	ng_hci_free_con(con);

	g_fail_new_con = 1;
	msg = ut_lp_con_req(NG_HCI_LINK_LE_PUBLIC, other_addr, 0);
	ATF_CHECK_EQ(ENOMEM, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);
	g_fail_new_con = 0;
	g_fail_mbuf = 1;
	msg = ut_lp_con_req(NG_HCI_LINK_LE_PUBLIC, other_addr, 0);
	ATF_CHECK_EQ(ENOBUFS, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);
	g_fail_mbuf = 0;

	con = ng_hci_new_con(unit, NG_HCI_LINK_LE_RANDOM);
	con->state = NG_HCI_CON_W4_CONN_COMPLETE;
	bcopy(other_addr, &con->bdaddr, sizeof(con->bdaddr));
	msg = ut_lp_con_req(NG_HCI_LINK_LE_PUBLIC, peer_id_addr, 0);
	ATF_CHECK_EQ(EBUSY, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);
	ng_hci_free_con(con);

	con = ng_hci_new_con(unit, NG_HCI_LINK_LE_PUBLIC);
	bcopy(other_addr, &con->bdaddr, sizeof(con->bdaddr));
	con->state = NG_HCI_CON_W4_LP_CON_RSP;
	msg = ut_lp_con_req(NG_HCI_LINK_LE_PUBLIC, other_addr, 0);
	ATF_CHECK_EQ(EALREADY, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);
	con->state = NG_HCI_CON_W4_CONN_COMPLETE;
	unit->sco = (hook_p)(uintptr_t)2;
	msg = ut_lp_con_req(NG_HCI_LINK_LE_PUBLIC, other_addr, 0);
	ATF_CHECK_EQ(0, ng_hci_lp_con_req(unit, (item_p)msg, unit->sco));
	free(msg);
	ATF_CHECK((con->flags & NG_HCI_CON_NOTIFY_SCO) != 0);
	con->state = 0xff;
	msg = ut_lp_con_req(NG_HCI_LINK_LE_PUBLIC, other_addr, 0);
	ATF_CHECK_EQ(EINVAL, ng_hci_lp_con_req(unit, (item_p)msg, NULL));
	free(msg);

	ng_hci_free_con(con);
	ng_hci_free_con(acl);
	free(unit);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, le_create_conn_own_rpa_public_identity);
	ATF_TP_ADD_TC(tp, le_create_conn_own_rpa_random_identity);
	ATF_TP_ADD_TC(tp, le_create_conn_own_public_default);
	ATF_TP_ADD_TC(tp, lp_connect_dispatch_and_acl_states);
	ATF_TP_ADD_TC(tp, ulpi_request_and_notification_matrix);
	ATF_TP_ADD_TC(tp, sco_and_connection_timeout_matrix);
	ATF_TP_ADD_TC(tp, ulpi_request_validation_matrix);
	ATF_TP_ADD_TC(tp, connect_response_link_matrix);
	ATF_TP_ADD_TC(tp, valid_upstream_notification_matrix);
	ATF_TP_ADD_TC(tp, cis_create_command_and_state);
	ATF_TP_ADD_TC(tp, cis_create_fault_cleanup_matrix);
	ATF_TP_ADD_TC(tp, upstream_message_allocation_failures);
	ATF_TP_ADD_TC(tp, connection_request_fault_and_state_matrix);

	return (atf_no_error());
}
