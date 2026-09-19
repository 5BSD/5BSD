/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Assertion-based ATF tests for the kernel HCI LE Connection Complete
 * handlers in sys/netgraph/bluetooth/hci/ng_hci_evnt.c.
 *
 * Focus: the connection descriptor's local role (con->role) MUST be
 * populated from the event's Role field at connection-establishment time.
 * Core Spec Vol 4 Part E 7.7.65.1 (LE Connection Complete), 7.7.65.10 (LE
 * Enhanced Connection Complete) and 7.7.65.41 (v2) all carry a Role field
 * (0x00 = Central, 0x01 = Peripheral).  L2CAP 4.20 (Connection Parameter
 * Update Request may only be sent by the Peripheral) trusts con->role, so
 * a Peripheral link whose role is left at the M_ZERO default (0 = Central)
 * breaks that check.
 *
 * Technique (mirrors l2cap_sig_test.c): #include the kernel TU
 * ng_hci_evnt.c to reach the static le_connection_complete() /
 * le_enh_connection_complete() handlers.  Kernel-only headers are
 * neutralised via their include guards; a userspace malloc-backed mbuf and
 * a small set of test doubles for the misc/ulpi helpers stand in for the
 * netgraph machinery.  The real ng_hci_var.h connection descriptor (which
 * contains the con->role field under test) is kept intact.
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

/* Real UAPI: event param layouts, opcodes, link types, con states. */
#include <netgraph/bluetooth/include/ng_bluetooth.h>
#include <netgraph/bluetooth/include/ng_hci.h>

#include "spec_hci_le_role_oracles.h"

/* Neutralise kernel-only headers that ng_hci_evnt.c includes. */
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
#define NG_NODE_PRIVATE(n)	(NULL)
#define NG_NODE_NOT_VALID(n)	(0)
#define NG_HOOK_IS_VALID(h)	((h) != NULL)
#define NG_HOOK_NOT_VALID(h)	((h) == NULL)
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

static struct mbuf *
ut_mbuf_alloc(void)
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
m_dup(struct mbuf *m, int how)
{

	(void)how;
	(void)m;
	return (NULL);
}

#define mtod(m, t)		((t)((m)->m_data))
#define MGETHDR(m, how, type)	((m) = ut_mbuf_alloc())

/* ----- netgraph message / item glue (normally ng_message.h) ---------- */
struct ng_mesg {
	struct {
		int	arglen;
	}	header;
	char	data[512];
};

static int g_message_alloc_fail;
static int g_send_msg_error;

#define NG_MKMESSAGE(msg, ck, cmd, len, fl) \
	((msg) = g_message_alloc_fail ? NULL : calloc(1, sizeof(struct ng_mesg)))
#define NG_FREE_MSG(msg)	do { free(msg); (msg) = NULL; } while (0)
#define NG_SEND_MSG_HOOK(err, node, msg, hook, fl) \
	do { (err) = g_send_msg_error; free(msg); (msg) = NULL; } while (0)
#define NG_SEND_DATA_ONLY(err, hook, m)		do { (err) = 0; NG_FREE_M(m); } while (0)
#define NG_FREE_ITEM(i)		do { \
	struct ng_item *_item = (struct ng_item *)(i); \
	if (_item != NULL) { NG_FREE_M(_item->m); free(_item); (i) = NULL; } \
} while (0)
#define NG_FWD_ITEM_HOOK(err, i, hook)		do { \
	(err) = 0; NG_FREE_ITEM(i); \
} while (0)
#define NGI_M(i)		(((struct ng_item *)(i))->m)
#define NGI_MSG(i)		((struct ng_mesg *)(i))
#define _NGI_MSG(i)		(*(struct ng_mesg **)(i))
#define NGI_GET_MSG(i, m)	do { (m) = NULL; } while (0)

/* NGM_HCI_COOKIE comes from ng_hci.h; M_NETGRAPH_HCI from ng_hci_var.h. */

/* Full definition of struct ng_item so NG_BT_ITEMQ_* macros compile. */
struct ng_item {
	STAILQ_ENTRY(ng_item) el_next;
	struct mbuf *m;
};

static void getmicrotime(struct timeval *tv) { if (tv) { tv->tv_sec = 0; tv->tv_usec = 0; } }

/* ---------------------------------------------------------------------- */
/* Bring in the real connection descriptor (con->role lives here). */
#include <netgraph/bluetooth/hci/ng_hci_var.h>
/* Real prototypes for the misc/ulpi/cmds helpers we provide doubles for. */
#include <netgraph/bluetooth/hci/ng_hci_cmds.h>
#include <netgraph/bluetooth/hci/ng_hci_evnt.h>
#include <netgraph/bluetooth/hci/ng_hci_ulpi.h>
#include <netgraph/bluetooth/hci/ng_hci_misc.h>

/* ----- test-double state ---------------------------------------------- */
static ng_hci_unit_con_p	g_new_con;	/* last con from ng_hci_new_con */
static ng_hci_neighbor_p	g_new_neighbor;
static int			g_neighbor_count;
static int			g_neighbor_alloc_fail;
static int			g_freed;	/* ng_hci_free_con call count */
static int			g_con_ind_calls;
static int			g_con_cfm_calls;
static int			g_last_cfm_status;
static int			g_discon_ind_calls;
static int			g_last_discon_reason;

static void
ut_reset(void)
{
	g_new_con = NULL;
	g_new_neighbor = NULL;
	g_neighbor_count = 0;
	g_neighbor_alloc_fail = 0;
	g_freed = 0;
	g_con_ind_calls = 0;
	g_con_cfm_calls = 0;
	g_last_cfm_status = -1;
	g_discon_ind_calls = 0;
	g_last_discon_reason = -1;
	g_message_alloc_fail = 0;
	g_send_msg_error = 0;
}

/* ----- misc.c doubles ------------------------------------------------- */
ng_hci_unit_con_p
ng_hci_new_con(ng_hci_unit_p unit, int link_type)
{
	ng_hci_unit_con_p	con;

	con = calloc(1, sizeof(*con));
	ATF_REQUIRE(con != NULL);
	con->unit = unit;
	con->state = NG_HCI_CON_CLOSED;
	con->link_type = link_type;
	con->con_handle = unit->fake_con_handle++;
	NG_BT_ITEMQ_INIT(&con->conq, 32);
	LIST_INSERT_HEAD(&unit->con_list, con, next);
	g_new_con = con;
	return (con);
}

void
ng_hci_free_con(ng_hci_unit_con_p con)
{

	LIST_REMOVE(con, next);
	g_freed++;
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

ng_hci_neighbor_p
ng_hci_new_neighbor(ng_hci_unit_p unit)
{
	ng_hci_neighbor_p n;

	if (g_neighbor_alloc_fail)
		return (NULL);
	n = calloc(1, sizeof(*n));
	ATF_REQUIRE(n != NULL);
	LIST_INSERT_HEAD(&unit->neighbors, n, next);
	g_new_neighbor = n;
	g_neighbor_count++;
	return (n);
}

ng_hci_neighbor_p
ng_hci_get_neighbor(ng_hci_unit_p unit, bdaddr_p bdaddr, int link_type)
{
	ng_hci_neighbor_p n;

	LIST_FOREACH(n, &unit->neighbors, next)
		if (n->addrtype == link_type &&
		    bcmp(&n->bdaddr, bdaddr, sizeof(*bdaddr)) == 0)
			return (n);
	return (NULL);
}
void ng_hci_mtap(ng_hci_unit_p u, struct mbuf *m) { (void)u; (void)m; }

/* ----- ulpi.c doubles ------------------------------------------------- */
int
ng_hci_lp_con_ind(ng_hci_unit_con_p con, u_int8_t *uclass)
{ (void)con; (void)uclass; g_con_ind_calls++; return (0); }

int
ng_hci_lp_con_cfm(ng_hci_unit_con_p con, int status)
{ (void)con; g_con_cfm_calls++; g_last_cfm_status = status; return (0); }

int ng_hci_lp_discon_ind(ng_hci_unit_con_p con, int reason)
{
	(void)con;
	g_discon_ind_calls++;
	g_last_discon_reason = reason;
	return (0);
}
int ng_hci_lp_enc_change(ng_hci_unit_con_p con, int status)
{ (void)con; (void)status; return (0); }
int ng_hci_lp_qos_cfm(ng_hci_unit_con_p con, int status)
{ (void)con; (void)status; return (0); }
int ng_hci_lp_qos_ind(ng_hci_unit_con_p con) { (void)con; return (0); }

/* ----- cmds.c doubles ------------------------------------------------- */
int ng_hci_send_command(ng_hci_unit_p unit) { (void)unit; return (0); }
int ng_hci_process_command_complete(ng_hci_unit_p u, struct mbuf *m)
{ (void)u; NG_FREE_M(m); return (0); }
int ng_hci_process_command_status(ng_hci_unit_p u, struct mbuf *m)
{ (void)u; NG_FREE_M(m); return (0); }

/* ---------------------------------------------------------------------- */
/* The kernel TU under test. */
#include "ng_hci_evnt.c"

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
	unit->debug = NG_HCI_INFO_LEVEL;
	return (unit);
}

/* Build an mbuf holding a raw event payload (post event-header). */
static struct mbuf *
ut_event(const void *buf, int len)
{
	struct mbuf	*m;

	m = ut_mbuf_alloc();
	ATF_REQUIRE(m != NULL);
	memcpy(m->m_store, buf, (size_t)len);
	m->m_data = m->m_store;
	m->m_len = m->m_pkthdr.len = len;
	return (m);
}

static void
ut_unit_free(ng_hci_unit_t *unit)
{
	ng_hci_unit_con_p con;
	ng_hci_neighbor_p n;
	struct mbuf *queued;

	while (NG_BT_MBUFQ_LEN(&unit->cmdq) != 0) {
		NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
		NG_FREE_M(queued);
	}
	while ((con = LIST_FIRST(&unit->con_list)) != NULL)
		ng_hci_free_con(con);
	while ((n = LIST_FIRST(&unit->neighbors)) != NULL) {
		LIST_REMOVE(n, next);
		free(n);
	}
	free(unit);
}

/*
 * LE Connection Complete (7.7.65.1) payload, minus the LE-meta subevent
 * byte (le_event() strips that before dispatch):
 *   status(1) handle(2,le) role(1) addr_type(1) addr(6)
 *   interval(2) latency(2) supervision_timeout(2) clock_accuracy(1) = 18
 */
static void
build_le_con_compl(unsigned char *o, uint8_t status, uint16_t handle,
    uint8_t role, uint8_t addr_type, const uint8_t addr[6])
{
	memset(o, 0, BT_HR_SPEC_CONN_COMPLETE_PARAM_LEN);
	o[0] = status;
	o[1] = handle & 0xff;
	o[2] = (handle >> 8) & 0xff;
	o[3] = role;
	o[4] = addr_type;
	memcpy(&o[5], addr, 6);
}

static const uint8_t	peer_addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

/*
 * Incoming (Peripheral) LE connection: no pre-existing descriptor.  The
 * handler creates one; con->role MUST reflect the event's Role field.
 */
ATF_TC_WITHOUT_HEAD(le_con_compl_incoming_peripheral_role);
ATF_TC_BODY(le_con_compl_incoming_peripheral_role, tc)
{
	ng_hci_unit_t	*unit = ut_unit_new();
	unsigned char	 buf[BT_HR_SPEC_CONN_COMPLETE_PARAM_LEN];
	struct mbuf	*ev;

	ut_reset();
	/* Core 6.3 Vol 4 Part E §7.7.65.1: Role 0x01 is Peripheral. */
	build_le_con_compl(buf, BT_HR_SPEC_STATUS_SUCCESS, 0x0040,
	    BT_HR_SPEC_ROLE_PERIPHERAL, BT_HR_SPEC_ADDR_PUBLIC,
	    peer_addr);
	ev = ut_event(buf, sizeof(buf));

	ATF_REQUIRE_EQ(0, le_connection_complete(unit, ev));
	ATF_REQUIRE(g_new_con != NULL);
	ATF_CHECK_EQ(NG_HCI_CON_OPEN, g_new_con->state);
	ATF_CHECK_EQ(NG_HCI_LINK_LE_PUBLIC, g_new_con->link_type);
	/* The keystone assertion: role decoded and stored. */
	ATF_CHECK_EQ(BT_HR_SPEC_ROLE_PERIPHERAL, g_new_con->role);
}

/*
 * Host-initiated (Central) LE connection: a descriptor already exists in
 * W4_CONN_COMPLETE.  con->role MUST be updated to the event's Role.
 */
ATF_TC_WITHOUT_HEAD(le_con_compl_existing_central_role);
ATF_TC_BODY(le_con_compl_existing_central_role, tc)
{
	ng_hci_unit_t		*unit = ut_unit_new();
	ng_hci_unit_con_p	 con;
	unsigned char		 buf[BT_HR_SPEC_CONN_COMPLETE_PARAM_LEN];
	struct mbuf		*ev;

	ut_reset();
	con = ng_hci_new_con(unit, NG_HCI_LINK_LE_PUBLIC);
	con->state = NG_HCI_CON_W4_CONN_COMPLETE;
	con->role = 0xee;			/* poison to prove a write */
	bcopy(peer_addr, &con->bdaddr, sizeof(con->bdaddr));

	/* Core 6.3 Vol 4 Part E §7.7.65.1: Role 0x00 is Central. */
	build_le_con_compl(buf, BT_HR_SPEC_STATUS_SUCCESS, 0x0040,
	    BT_HR_SPEC_ROLE_CENTRAL, BT_HR_SPEC_ADDR_PUBLIC,
	    peer_addr);
	ev = ut_event(buf, sizeof(buf));

	ATF_REQUIRE_EQ(0, le_connection_complete(unit, ev));
	ATF_CHECK_EQ(0, g_freed);		/* success: not freed */
	ATF_CHECK_EQ(NG_HCI_CON_OPEN, con->state);
	ATF_CHECK_EQ(BT_HR_SPEC_ROLE_CENTRAL, con->role);
}

/*
 * LE Enhanced Connection Complete (7.7.65.10): Peripheral role must also be
 * stored via the shared le_con_compl_common() path.
 */
ATF_TC_WITHOUT_HEAD(le_enh_con_compl_peripheral_role);
ATF_TC_BODY(le_enh_con_compl_peripheral_role, tc)
{
	ng_hci_unit_t	*unit = ut_unit_new();
	unsigned char	 buf[BT_HR_SPEC_ENH_CONN_COMPLETE_PARAM_LEN];
	struct mbuf	*ev;

	ut_reset();
	/*
	 * Enhanced layout: status(1) handle(2) role(1) peer_addr_type(1)
	 * peer_addr(6) local_rpa(6) peer_rpa(6) interval(2) latency(2)
	 * timeout(2) clock_accuracy(1).  We only need through peer_addr.
	 */
	/* Core 6.3 Vol 4 Part E §7.7.65.10 exact Role/address fields. */
	memset(buf, 0, sizeof(buf));
	buf[0] = BT_HR_SPEC_STATUS_SUCCESS;
	buf[1] = 0x40; buf[2] = 0x00;	/* handle */
	buf[3] = BT_HR_SPEC_ROLE_PERIPHERAL;
	buf[4] = BT_HR_SPEC_ADDR_RANDOM;
	memcpy(&buf[5], peer_addr, 6);

	ev = ut_event(buf, sizeof(buf));

	ATF_REQUIRE_EQ(0, le_enh_connection_complete(unit, ev));
	ATF_REQUIRE(g_new_con != NULL);
	ATF_CHECK_EQ(NG_HCI_LINK_LE_RANDOM, g_new_con->link_type);
	ATF_CHECK_EQ(BT_HR_SPEC_ROLE_PERIPHERAL, g_new_con->role);
}

ATF_TC_WITHOUT_HEAD(event_dispatch_malformed_sweep);
ATF_TC_BODY(event_dispatch_malformed_sweep, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_event_pkt_t hdr;
	struct mbuf *event;
	unsigned char packet[sizeof(hdr) + 1];
	unsigned char byte = 0;

	unit = ut_unit_new();
	ut_reset();

	/* A short packet must be rejected before the event code is read. */
	event = ut_event(&byte, 1);
	ATF_CHECK_EQ(ENOBUFS, ng_hci_process_event(unit, event));

	/* A complete header that advertises absent parameters is truncated. */
	memset(&hdr, 0, sizeof(hdr));
	/* Implementation parser contract; Core §5.4.4 supplies framing. */
	hdr.event = BT_HR_SPEC_EVENT_LE_META;
	hdr.length = 1;
	event = ut_event((const unsigned char *)&hdr, sizeof(hdr));
	ATF_CHECK_EQ(EMSGSIZE, ng_hci_process_event(unit, event));

	/* Bytes beyond the declared parameter length are not another event. */
	memset(&hdr, 0, sizeof(hdr));
	hdr.event = BT_HR_SPEC_EVENT_VENDOR;
	hdr.length = 0;
	memcpy(packet, &hdr, sizeof(hdr));
	packet[sizeof(hdr)] = 0xa5;
	event = ut_event(packet, sizeof(packet));
	ATF_CHECK_EQ(EMSGSIZE, ng_hci_process_event(unit, event));

	/*
	 * Sweep the complete one-octet event namespace with empty payloads.
	 * Every known post-processing arm reaches its own length guard, while
	 * ignored and vendor events exercise the intentional consume path.
	 */
	for (int code = 0; code <= UINT8_MAX; code++) {
		memset(&hdr, 0, sizeof(hdr));
		hdr.event = (uint8_t)code;
		event = ut_event((const unsigned char *)&hdr, sizeof(hdr));
		(void)ng_hci_process_event(unit, event);
	}

	/* Repeat at the LE-meta layer so every standardized subevent guard runs. */
	for (int subevent = 0; subevent <= UINT8_MAX; subevent++) {
		memset(&hdr, 0, sizeof(hdr));
		hdr.event = BT_HR_SPEC_EVENT_LE_META;
		hdr.length = 1;
		memcpy(packet, &hdr, sizeof(hdr));
		packet[sizeof(hdr)] = (uint8_t)subevent;
		event = ut_event(packet, sizeof(packet));
		(void)ng_hci_process_event(unit, event);
	}

	ATF_CHECK(LIST_EMPTY(&unit->con_list));
	free(unit);
}

ATF_TC_WITHOUT_HEAD(le_subevent_padded_sweep);
ATF_TC_BODY(le_subevent_padded_sweep, tc)
{
	/* Implementation robustness contract for Core §7.7.65 decoders. */
	unsigned char payload[256];

	/*
	 * A zero-filled maximum-size parameter block is structurally complete
	 * for every fixed LE meta event and gives variable-count events a safe
	 * count of zero.  This drives the actual handler bodies beyond the
	 * short-packet guards covered by event_dispatch_malformed_sweep.
	 */
	for (int subevent = 0; subevent <= UINT8_MAX; subevent++) {
		ng_hci_unit_t *unit;
		ng_hci_unit_con_p con;
		struct mbuf *event;
		struct mbuf *queued;

		unit = ut_unit_new();
		unit->debug = NG_HCI_INFO_LEVEL;
		con = ng_hci_new_con(unit, NG_HCI_LINK_LE_PUBLIC);
		con->con_handle = 0;
		con->state = NG_HCI_CON_OPEN;
		memset(payload, 0, sizeof(payload));
		payload[0] = (uint8_t)subevent;
		event = ut_event(payload, sizeof(payload));
		(void)le_event(unit, event);
		while (NG_BT_MBUFQ_LEN(&unit->cmdq) != 0) {
			NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
			NG_FREE_M(queued);
		}
		while ((con = LIST_FIRST(&unit->con_list)) != NULL)
			ng_hci_free_con(con);
		free(unit);
	}
}

ATF_TC_WITHOUT_HEAD(le_subevent_operand_mutation_sweep);
ATF_TC_BODY(le_subevent_operand_mutation_sweep, tc)
{
	/* Implementation robustness contract for Core §7.7.65 decoders. */
	unsigned char payload[256];

	/*
	 * The padded sweep above establishes the all-zero baseline for every
	 * standardized and reserved LE subevent.  That intentionally leaves many
	 * independent operands one-sided: status, handle, count, flags, and the
	 * individual fields of variable-length reports are all zero.  Flip one
	 * byte at a time, retaining a structurally bounded packet, so short-
	 * circuit guards can observe their other outcome without combining unsafe
	 * count fields with arbitrary trailing data.
	 */
	for (int subevent = 0; subevent <= UINT8_MAX; subevent++) {
		for (size_t byte = 1; byte < sizeof(payload); byte++) {
			ng_hci_unit_t *unit;
			ng_hci_unit_con_p con;
			struct mbuf *queued;

			ut_reset();
			unit = ut_unit_new();
			con = ng_hci_new_con(unit, NG_HCI_LINK_LE_PUBLIC);
			con->con_handle = 0;
			con->state = NG_HCI_CON_OPEN;
			memset(payload, 0, sizeof(payload));
			payload[0] = (uint8_t)subevent;
			payload[byte] = 0xff;
			(void)le_event(unit, ut_event(payload, sizeof(payload)));
			while (NG_BT_MBUFQ_LEN(&unit->cmdq) != 0) {
				NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
				NG_FREE_M(queued);
			}
			while ((con = LIST_FIRST(&unit->con_list)) != NULL)
				ng_hci_free_con(con);
			free(unit);
		}
	}
}

ATF_TC_WITHOUT_HEAD(le_advertising_neighbor_lifecycle);
ATF_TC_BODY(le_advertising_neighbor_lifecycle, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_neighbor_p n;
	unsigned char payload[1 + 1 + 1 + 6 + 1 + UINT8_MAX + 1];
	int off;

	unit = ut_unit_new();
	ut_reset();

	/* Core 6.3 Vol 4 Part E §7.7.65.2 legacy report layout. */
	off = 0;
	payload[off++] = 1;		/* number of reports */
	payload[off++] = 0;		/* event type */
	payload[off++] = BT_HR_SPEC_ADDR_PUBLIC;
	memcpy(&payload[off], peer_addr, sizeof(peer_addr));
	off += sizeof(peer_addr);
	payload[off++] = 3;
	payload[off++] = 0x02;
	payload[off++] = 0x01;
	payload[off++] = 0x06;
	payload[off++] = 0xd8;		/* RSSI */
	ATF_REQUIRE_EQ(0, le_advertizing_report(unit, ut_event(payload, off)));
	ATF_REQUIRE(g_new_neighbor != NULL);
	n = g_new_neighbor;
	ATF_CHECK_EQ(1, g_neighbor_count);
	ATF_CHECK_EQ(NG_HCI_LINK_LE_PUBLIC, n->addrtype);
	ATF_CHECK_EQ(3, n->extinq_size);
	ATF_CHECK_EQ(0, memcmp(n->extinq_data, "\x02\x01\x06", 3));
	ATF_CHECK_EQ(0xd8, n->page_scan_mode);

	/* A resolved public identity address remains public, not random. */
	off = 0;
	payload[off++] = 1;
	payload[off++] = 0;
	payload[off++] = BT_HR_SPEC_ADDR_PUBLIC_IDENTITY;
	memcpy(&payload[off], peer_addr, sizeof(peer_addr));
	off += sizeof(peer_addr);
	payload[off++] = 0;
	payload[off++] = 0xd7;
	ATF_REQUIRE_EQ(0, le_advertizing_report(unit, ut_event(payload, off)));
	ATF_CHECK_EQ_MSG(1, g_neighbor_count,
	    "public identity report must update the public neighbor");
	ATF_CHECK_EQ(NG_HCI_LINK_LE_PUBLIC, n->addrtype);

	/* A repeat report updates the same entry at the legacy 31-byte limit. */
	off = 0;
	payload[off++] = 1;
	payload[off++] = 4;
	payload[off++] = 0;
	memcpy(&payload[off], peer_addr, sizeof(peer_addr));
	off += sizeof(peer_addr);
	payload[off++] = BT_HR_SPEC_LEGACY_ADV_DATA_MAX;
	for (int i = 0; i < BT_HR_SPEC_LEGACY_ADV_DATA_MAX; i++)
		payload[off++] = (unsigned char)i;
	payload[off++] = 0xa5;
	ATF_REQUIRE_EQ(0, le_advertizing_report(unit, ut_event(payload, off)));
	ATF_CHECK_EQ(1, g_neighbor_count);
	ATF_CHECK_EQ(BT_HR_SPEC_LEGACY_ADV_DATA_MAX, n->extinq_size);
	ATF_CHECK_EQ(0, n->extinq_data[0]);
	ATF_CHECK_EQ(30, n->extinq_data[30]);
	ATF_CHECK_EQ(0xa5, n->page_scan_mode);

	/* Truncated fixed and variable report fields are consumed safely. */
	payload[0] = 1;
	ATF_REQUIRE_EQ(EMSGSIZE,
	    le_advertizing_report(unit, ut_event(payload, 2)));
	off = 0;
	payload[off++] = 1;
	payload[off++] = 0;
	payload[off++] = 1;
	memcpy(&payload[off], peer_addr, sizeof(peer_addr));
	off += sizeof(peer_addr);
	payload[off++] = 5;
	payload[off++] = 0x01;
	ATF_REQUIRE_EQ(EMSGSIZE,
	    le_advertizing_report(unit, ut_event(payload, off)));

	ut_unit_free(unit);
}

ATF_TC_WITHOUT_HEAD(classic_inquiry_neighbor_lifecycle);
ATF_TC_BODY(classic_inquiry_neighbor_lifecycle, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_neighbor_p n;
	ng_hci_ext_inquiry_result_ep ext;
	unsigned char payload[15];
	uint16_t clock;

	unit = ut_unit_new();
	ut_reset();

	/* Core 6.3 Vol 4 Part E §7.7.2 exact counted inquiry layout. */
	memset(payload, 0, sizeof(payload));
	payload[0] = 1;
	memcpy(&payload[1], peer_addr, sizeof(peer_addr));
	payload[7] = 2;
	payload[8] = 3;
	payload[9] = 4;
	payload[10] = 0x11;
	payload[11] = 0x22;
	payload[12] = 0x33;
	clock = htole16(0x4567);
	memcpy(&payload[13], &clock, sizeof(clock));
	ATF_REQUIRE_EQ(0, inquiry_result(unit, ut_event(payload,
	    sizeof(payload))));
	ATF_REQUIRE(g_new_neighbor != NULL);
	n = g_new_neighbor;
	ATF_CHECK_EQ(NG_HCI_LINK_ACL, n->addrtype);
	ATF_CHECK_EQ(2, n->page_scan_rep_mode);
	ATF_CHECK_EQ(4, n->page_scan_mode);
	ATF_CHECK_EQ(0x4567, n->clock_offset);

	/* RSSI form updates the same cache entry and clears reserved scan mode. */
	payload[7] = 5;
	payload[8] = 0xaa;
	payload[9] = 0x44;
	payload[10] = 0x55;
	payload[11] = 0x66;
	clock = htole16(0x1234);
	memcpy(&payload[12], &clock, sizeof(clock));
	payload[14] = 0xc0;
	ATF_REQUIRE_EQ(0, inquiry_result_with_rssi(unit, ut_event(payload,
	    sizeof(payload))));
	ATF_CHECK_EQ(1, g_neighbor_count);
	ATF_CHECK_EQ(5, n->page_scan_rep_mode);
	ATF_CHECK_EQ(0, n->page_scan_mode);
	ATF_CHECK_EQ(0x1234, n->clock_offset);

	/* Core §7.7.38 assigns a 240-octet Extended Inquiry Response. */
	memset(&ext, 0, sizeof(ext));
	ext.num_responses = 1;
	memcpy(&ext.bdaddr, peer_addr, sizeof(peer_addr));
	ext.page_scan_rep_mode = 7;
	ext.clock_offset = htole16(0x7788);
	for (size_t i = 0; i < sizeof(ext.ext_inquiry_response); i++)
		ext.ext_inquiry_response[i] = (unsigned char)i;
	ATF_REQUIRE_EQ(0, ext_inquiry_result(unit,
	    ut_event((const unsigned char *)&ext, sizeof(ext))));
	ATF_CHECK_EQ(1, g_neighbor_count);
	ATF_CHECK_EQ(7, n->page_scan_rep_mode);
	ATF_CHECK_EQ(0x7788, n->clock_offset);
	ATF_CHECK_EQ(sizeof(ext.ext_inquiry_response), n->extinq_size);
	ATF_CHECK_EQ(BT_HR_SPEC_EXT_INQUIRY_DATA_LEN - 1,
	    n->extinq_data[BT_HR_SPEC_EXT_INQUIRY_DATA_LEN - 1]);

	/* Counted-response truncation rejects before indexed record reads. */
	payload[0] = 1;
	ATF_REQUIRE_EQ(EMSGSIZE, inquiry_result(unit, ut_event(payload, 2)));
	ATF_REQUIRE_EQ(EMSGSIZE,
	    inquiry_result_with_rssi(unit, ut_event(payload, 2)));

	/* Allocation failures are still surfaced after a complete event. */
	memset(&ext.bdaddr, 0x99, sizeof(ext.bdaddr));
	g_neighbor_alloc_fail = 1;
	ATF_CHECK_EQ(ENOMEM, ext_inquiry_result(unit,
	    ut_event((const unsigned char *)&ext, sizeof(ext))));
	g_neighbor_alloc_fail = 0;

	ut_unit_free(unit);
}

ATF_TC_WITHOUT_HEAD(classic_connection_event_lifecycle);
ATF_TC_BODY(classic_connection_event_lifecycle, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p con, sco;
	ng_hci_con_req_ep request;
	ng_hci_con_compl_ep complete;
	ng_hci_sync_con_compl_ep sync;
	ng_hci_encryption_change_ep enc;
	ng_hci_encryption_change_v2_ep enc2;
	ng_hci_read_remote_features_compl_ep features;
	ng_hci_qos_setup_compl_ep qos;
	ng_hci_discon_compl_ep disconnect;
	bdaddr_t other;

	ut_reset();
	unit = ut_unit_new();
	unit->features[0] = NG_HCI_LMP_SWITCH | NG_HCI_LMP_HOLD_MODE |
	    NG_HCI_LMP_SNIFF_MODE;
	unit->features[1] = NG_HCI_LMP_PARK_MODE;
	unit->role_switch = 1;
	unit->link_policy_mask = 0xffff;

	/* Core 6.3 Vol 4 Part E §7.7.4 Connection Request layout. */
	memset(&request, 0, sizeof(request));
	memcpy(&request.bdaddr, peer_addr, sizeof(peer_addr));
	request.link_type = NG_HCI_LINK_ACL;
	request.uclass[0] = 1;
	ATF_REQUIRE_EQ(0, con_req(unit,
	    ut_event((const unsigned char *)&request, sizeof(request))));
	con = g_new_con;
	ATF_REQUIRE(con != NULL);
	ATF_CHECK_EQ(NG_HCI_CON_W4_LP_CON_RSP, con->state);
	ATF_CHECK(con->flags & NG_HCI_CON_TIMEOUT_PENDING);
	ATF_CHECK_EQ(1, g_con_ind_calls);
	ATF_REQUIRE_EQ(0, con_req(unit,
	    ut_event((const unsigned char *)&request, sizeof(request))));
	ATF_CHECK_EQ(1, g_con_ind_calls);
	ng_hci_free_con(con);

	/* A successful raw ACL completion creates an open link and policy cmd. */
	memset(&complete, 0, sizeof(complete));
	memcpy(&complete.bdaddr, peer_addr, sizeof(peer_addr));
	complete.con_handle = htole16(0x81);
	complete.link_type = NG_HCI_LINK_ACL;
	complete.encryption_mode = NG_HCI_ENCRYPTION_MODE_NONE;
	ATF_REQUIRE_EQ(0, con_compl(unit,
	    ut_event((const unsigned char *)&complete, sizeof(complete))));
	con = ng_hci_con_by_handle(unit, 0x81);
	ATF_REQUIRE(con != NULL);
	ATF_CHECK_EQ(NG_HCI_CON_OPEN, con->state);
	ATF_CHECK_EQ(1, NG_BT_MBUFQ_LEN(&unit->cmdq));

	/* Classic ACL encryption selects P2P, AES-CCM, and disabled modes. */
	memset(&enc, 0, sizeof(enc));
	enc.con_handle = htole16(0x81);
	enc.encryption_enable = 1;
	ATF_REQUIRE_EQ(0, encryption_change(unit,
	    ut_event((const unsigned char *)&enc, sizeof(enc))));
	ATF_CHECK_EQ(NG_HCI_ENCRYPTION_MODE_P2P, con->encryption_mode);
	enc.encryption_enable = 2;
	ATF_REQUIRE_EQ(0, encryption_change(unit,
	    ut_event((const unsigned char *)&enc, sizeof(enc))));
	ATF_CHECK_EQ(NG_HCI_ENCRYPTION_MODE_AES_CCM, con->encryption_mode);
	enc.encryption_enable = 0;
	ATF_REQUIRE_EQ(0, encryption_change(unit,
	    ut_event((const unsigned char *)&enc, sizeof(enc))));
	ATF_CHECK_EQ(NG_HCI_ENCRYPTION_MODE_NONE, con->encryption_mode);

	/* V2 records key size; failures clear stale encrypted state. */
	memset(&enc2, 0, sizeof(enc2));
	enc2.con_handle = htole16(0x81);
	enc2.encryption_enable = 2;
	enc2.encryption_key_size = 16;
	ATF_REQUIRE_EQ(0, encryption_change_v2(unit,
	    ut_event((const unsigned char *)&enc2, sizeof(enc2))));
	ATF_CHECK_EQ(16, con->encryption_key_size);
	enc2.status = 5;
	ATF_REQUIRE_EQ(0, encryption_change_v2(unit,
	    ut_event((const unsigned char *)&enc2, sizeof(enc2))));
	ATF_CHECK_EQ(NG_HCI_ENCRYPTION_MODE_NONE, con->encryption_mode);

	/* Successful remote features populate the matching neighbor cache. */
	memset(&features, 0, sizeof(features));
	features.con_handle = htole16(0x81);
	for (size_t i = 0; i < sizeof(features.features); i++)
		features.features[i] = (unsigned char)(0xa0 + i);
	ATF_REQUIRE_EQ(0, read_remote_features_compl(unit,
	    ut_event((const unsigned char *)&features, sizeof(features))));
	ATF_REQUIRE(g_new_neighbor != NULL);
	ATF_CHECK_EQ(0, memcmp(g_new_neighbor->features, features.features,
	    sizeof(features.features)));
	features.con_handle = htole16(0x99);
	ATF_CHECK_EQ(ENOENT, read_remote_features_compl(unit,
	    ut_event((const unsigned char *)&features, sizeof(features))));

	/* QoS accepts only an open ACL connection. */
	memset(&qos, 0, sizeof(qos));
	qos.con_handle = htole16(0x81);
	ATF_CHECK_EQ(0, qos_setup_compl(unit,
	    ut_event((const unsigned char *)&qos, sizeof(qos))));
	con->state = NG_HCI_CON_CLOSED;
	ATF_CHECK_EQ(EINVAL, qos_setup_compl(unit,
	    ut_event((const unsigned char *)&qos, sizeof(qos))));
	con->state = NG_HCI_CON_OPEN;
	qos.con_handle = htole16(0x99);
	ATF_CHECK_EQ(ENOENT, qos_setup_compl(unit,
	    ut_event((const unsigned char *)&qos, sizeof(qos))));

	/* Missing-handle and SCO encryption are rejected. */
	enc.status = 0;
	enc.encryption_enable = 1;
	enc.con_handle = htole16(0x99);
	ATF_CHECK_EQ(ENOENT, encryption_change(unit,
	    ut_event((const unsigned char *)&enc, sizeof(enc))));
	sco = ng_hci_new_con(unit, NG_HCI_LINK_SCO);
	sco->con_handle = 0x82;
	sco->state = NG_HCI_CON_OPEN;
	enc.con_handle = htole16(0x82);
	ATF_CHECK_EQ(EINVAL, encryption_change(unit,
	    ut_event((const unsigned char *)&enc, sizeof(enc))));
	qos.con_handle = htole16(0x82);
	ATF_CHECK_EQ(EINVAL, qos_setup_compl(unit,
	    ut_event((const unsigned char *)&qos, sizeof(qos))));
	ng_hci_free_con(sco);

	/* Synchronous completion creates SCO links; failed pending links free. */
	memset(&sync, 0, sizeof(sync));
	memcpy(&sync.bdaddr, peer_addr, sizeof(peer_addr));
	sync.con_handle = htole16(0x83);
	ATF_REQUIRE_EQ(0, sync_con_compl(unit,
	    ut_event((const unsigned char *)&sync, sizeof(sync))));
	sco = ng_hci_con_by_handle(unit, 0x83);
	ATF_REQUIRE(sco != NULL);
	ATF_CHECK_EQ(NG_HCI_CON_OPEN, sco->state);
	ng_hci_free_con(sco);
	memset(&other, 0x55, sizeof(other));
	sco = ng_hci_new_con(unit, NG_HCI_LINK_SCO);
	sco->state = NG_HCI_CON_W4_CONN_COMPLETE;
	sco->flags |= NG_HCI_CON_TIMEOUT_PENDING;
	sco->bdaddr = other;
	sync.status = 0x0d;
	sync.bdaddr = other;
	ATF_REQUIRE_EQ(0, sync_con_compl(unit,
	    ut_event((const unsigned char *)&sync, sizeof(sync))));
	ATF_CHECK(ng_hci_con_by_bdaddr(unit, &other, NG_HCI_LINK_SCO) == NULL);

	/* Failed pending ACL completion and successful disconnect both clean up. */
	memset(&other, 0x66, sizeof(other));
	sco = ng_hci_new_con(unit, NG_HCI_LINK_ACL);
	sco->state = NG_HCI_CON_W4_CONN_COMPLETE;
	sco->flags |= NG_HCI_CON_TIMEOUT_PENDING;
	sco->bdaddr = other;
	complete.status = BT_HR_SPEC_ERR_PAGE_TIMEOUT;
	complete.bdaddr = other;
	ATF_REQUIRE_EQ(0, con_compl(unit,
	    ut_event((const unsigned char *)&complete, sizeof(complete))));
	ATF_CHECK(ng_hci_con_by_bdaddr(unit, &other, NG_HCI_LINK_ACL) == NULL);

	memset(&disconnect, 0, sizeof(disconnect));
	disconnect.con_handle = htole16(0x81);
	disconnect.reason = BT_HR_SPEC_REASON_REMOTE_USER_TERM;
	con->flags |= NG_HCI_CON_TIMEOUT_PENDING;
	ATF_REQUIRE_EQ(0, discon_compl(unit,
	    ut_event((const unsigned char *)&disconnect, sizeof(disconnect))));
	ATF_CHECK(ng_hci_con_by_handle(unit, 0x81) == NULL);
	ATF_CHECK_EQ(BT_HR_SPEC_REASON_REMOTE_USER_TERM, g_last_discon_reason);
	ATF_CHECK_EQ(ENOENT, discon_compl(unit,
	    ut_event((const unsigned char *)&disconnect, sizeof(disconnect))));

	ut_unit_free(unit);
}

static struct mbuf *
ut_le_typed_event(uint8_t subevent, const void *params, size_t params_len)
{
	unsigned char payload[1 + sizeof(ng_hci_le_cis_established_ep)];

	ATF_REQUIRE(params_len <= sizeof(payload) - 1);
	payload[0] = subevent;
	memcpy(&payload[1], params, params_len);
	return (ut_event(payload, (int)params_len + 1));
}

ATF_TC_WITHOUT_HEAD(le_cis_lifecycle_matrix);
ATF_TC_BODY(le_cis_lifecycle_matrix, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p con, acl;
	ng_hci_le_cis_established_ep established;
	ng_hci_le_cis_request_ep request;
	bdaddr_t expected;

	/* Core 6.3 Vol 4 Part E §7.7.65.25/.26 CIS event layouts. */
	ut_reset();
	unit = ut_unit_new();
	memset(&established, 0, sizeof(established));
	established.connection_handle = htole16(0x44);

	/* A successful completion opens the pending CIS and cancels timeout. */
	con = ng_hci_new_con(unit, NG_HCI_LINK_ISO_CIS);
	con->con_handle = 0x44;
	con->state = NG_HCI_CON_W4_LP_CON_RSP;
	con->flags = NG_HCI_CON_NOTIFY_ISO | NG_HCI_CON_TIMEOUT_PENDING;
	le_event(unit, ut_le_typed_event(BT_HR_SPEC_SUBEVENT_CIS_ESTABLISHED,
	    &established, sizeof(established)));
	ATF_CHECK_EQ(NG_HCI_CON_OPEN, con->state);
	ATF_CHECK_EQ(0, con->flags & NG_HCI_CON_TIMEOUT_PENDING);
	ATF_CHECK_EQ(1, g_con_cfm_calls);
	ATF_CHECK_EQ(0, g_last_cfm_status);
	ng_hci_free_con(con);

	/* A failed completion confirms the controller status and frees it. */
	con = ng_hci_new_con(unit, NG_HCI_LINK_ISO_CIS);
	con->con_handle = 0x44;
	con->flags = NG_HCI_CON_TIMEOUT_PENDING;
	established.status = BT_HR_SPEC_ERR_CONN_FAILED_ESTABLISH;
	le_event(unit, ut_le_typed_event(BT_HR_SPEC_SUBEVENT_CIS_ESTABLISHED,
	    &established, sizeof(established)));
	ATF_CHECK_EQ(2, g_con_cfm_calls);
	ATF_CHECK_EQ(BT_HR_SPEC_ERR_CONN_FAILED_ESTABLISH, g_last_cfm_status);
	ATF_CHECK(LIST_EMPTY(&unit->con_list));

	/* An unsolicited completion falls back to the open ACL peer address. */
	acl = ng_hci_new_con(unit, NG_HCI_LINK_LE_RANDOM);
	acl->con_handle = 0x20;
	acl->state = NG_HCI_CON_OPEN;
	memcpy(&acl->bdaddr, peer_addr, sizeof(peer_addr));
	expected = acl->bdaddr;
	established.status = BT_HR_SPEC_STATUS_SUCCESS;
	established.connection_handle = htole16(0x45);
	le_event(unit, ut_le_typed_event(BT_HR_SPEC_SUBEVENT_CIS_ESTABLISHED,
	    &established, sizeof(established)));
	con = ng_hci_con_by_handle(unit, 0x45);
	ATF_REQUIRE(con != NULL);
	ATF_CHECK_EQ(NG_HCI_CON_OPEN, con->state);
	ATF_CHECK_EQ(NG_HCI_LINK_ISO_CIS, con->link_type);
	ATF_CHECK_EQ(0, bcmp(&expected, &con->bdaddr, sizeof(expected)));
	ATF_CHECK(con->flags & NG_HCI_CON_NOTIFY_ISO);

	/* With an ISO hook, a request creates a pending descriptor. */
	memset(&request, 0, sizeof(request));
	request.acl_connection_handle = htole16(0x20);
	request.cis_connection_handle = htole16(0x46);
	request.cig_id = 7;
	request.cis_id = 8;
	unit->iso = (hook_p)(uintptr_t)1;
	le_event(unit, ut_le_typed_event(BT_HR_SPEC_SUBEVENT_CIS_REQUEST,
	    &request, sizeof(request)));
	con = ng_hci_con_by_handle(unit, 0x46);
	ATF_REQUIRE(con != NULL);
	ATF_CHECK_EQ(NG_HCI_CON_W4_LP_CON_RSP, con->state);
	ATF_CHECK(con->flags & NG_HCI_CON_TIMEOUT_PENDING);
	ATF_CHECK_EQ(0, bcmp(&expected, &con->bdaddr, sizeof(expected)));

	/* Without a consumer, the controller receives an immediate reject. */
	unit->iso = NULL;
	request.cis_connection_handle = htole16(0x47);
	le_event(unit, ut_le_typed_event(BT_HR_SPEC_SUBEVENT_CIS_REQUEST,
	    &request, sizeof(request)));
	ATF_CHECK_EQ(1, NG_BT_MBUFQ_LEN(&unit->cmdq));
	ATF_CHECK(ng_hci_con_by_handle(unit, 0x47) == NULL);

	/* Delivery failure removes pending state and queues a controller reject. */
	unit->iso = (hook_p)(uintptr_t)1;
	request.cis_connection_handle = htole16(0x48);
	g_send_msg_error = EIO;
	le_event(unit, ut_le_typed_event(BT_HR_SPEC_SUBEVENT_CIS_REQUEST,
	    &request, sizeof(request)));
	g_send_msg_error = 0;
	ATF_CHECK(ng_hci_con_by_handle(unit, 0x48) == NULL);
	ATF_CHECK_EQ(2, NG_BT_MBUFQ_LEN(&unit->cmdq));

	/* Allocation failure follows the limited-resources rejection path. */
	request.cis_connection_handle = htole16(0x49);
	g_message_alloc_fail = 1;
	le_event(unit, ut_le_typed_event(BT_HR_SPEC_SUBEVENT_CIS_REQUEST,
	    &request, sizeof(request)));
	g_message_alloc_fail = 0;
	ATF_CHECK(ng_hci_con_by_handle(unit, 0x49) == NULL);
	ATF_CHECK_EQ(3, NG_BT_MBUFQ_LEN(&unit->cmdq));

	ut_unit_free(unit);
}

ATF_TC_WITHOUT_HEAD(le_big_bis_lifecycle_matrix);
ATF_TC_BODY(le_big_bis_lifecycle_matrix, tc)
{
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p con, keep;
	ng_hci_le_create_big_compl_ep create;
	ng_hci_le_big_sync_est_ep sync;
	ng_hci_le_terminate_big_compl_ep terminate;
	ng_hci_le_big_sync_lost_ep lost;
	unsigned char params[sizeof(create) + 2 * sizeof(uint16_t)];
	uint16_t handles[2];

	/* Core 6.3 Vol 4 Part E §7.7.65.27-.30 BIG/BIS event layouts. */
	ut_reset();
	unit = ut_unit_new();
	memset(&create, 0, sizeof(create));
	create.big_handle = 9;
	create.num_bis = 2;
	handles[0] = htole16(0x60);
	handles[1] = htole16(0x61);
	memcpy(params, &create, sizeof(create));
	memcpy(params + sizeof(create), handles, sizeof(handles));
	le_event(unit, ut_le_typed_event(BT_HR_SPEC_SUBEVENT_CREATE_BIG_COMPLETE,
	    params, sizeof(params)));
	ATF_CHECK_EQ(2, g_con_cfm_calls);
	for (int handle = 0x60; handle <= 0x61; handle++) {
		con = ng_hci_con_by_handle(unit, handle);
		ATF_REQUIRE(con != NULL);
		ATF_CHECK_EQ(NG_HCI_LINK_ISO_BIS, con->link_type);
		ATF_CHECK_EQ(NG_HCI_CON_OPEN, con->state);
		ATF_CHECK_EQ(9, con->big_handle);
		ATF_CHECK(con->flags & NG_HCI_CON_NOTIFY_ISO);
	}

	/* Other BIGs and non-BIS descriptors survive targeted termination. */
	keep = ng_hci_new_con(unit, NG_HCI_LINK_ISO_BIS);
	keep->con_handle = 0x62;
	keep->big_handle = 10;
	con = ng_hci_new_con(unit, NG_HCI_LINK_LE_PUBLIC);
	con->con_handle = 0x20;
	terminate.big_handle = 9;
	terminate.reason = BT_HR_SPEC_REASON_LOCAL_HOST_TERM;
	le_event(unit, ut_le_typed_event(BT_HR_SPEC_SUBEVENT_TERMINATE_BIG_COMPLETE,
	    &terminate, sizeof(terminate)));
	ATF_CHECK_EQ(2, g_discon_ind_calls);
	ATF_CHECK_EQ(BT_HR_SPEC_REASON_LOCAL_HOST_TERM, g_last_discon_reason);
	ATF_CHECK(ng_hci_con_by_handle(unit, 0x60) == NULL);
	ATF_CHECK(ng_hci_con_by_handle(unit, 0x61) == NULL);
	ATF_CHECK_EQ(keep, ng_hci_con_by_handle(unit, 0x62));
	ATF_CHECK(ng_hci_con_by_handle(unit, 0x20) != NULL);

	/* BIG Sync Established has the same variable BIS handle lifecycle. */
	memset(&sync, 0, sizeof(sync));
	sync.big_handle = 11;
	sync.num_bis = 2;
	handles[0] = htole16(0x70);
	handles[1] = htole16(0x71);
	memcpy(params, &sync, sizeof(sync));
	memcpy(params + sizeof(sync), handles, sizeof(handles));
	le_event(unit, ut_le_typed_event(BT_HR_SPEC_SUBEVENT_BIG_SYNC_ESTABLISHED,
	    params, sizeof(sync) + sizeof(handles)));
	ATF_CHECK_EQ(4, g_con_cfm_calls);
	ATF_CHECK_EQ(11, ng_hci_con_by_handle(unit, 0x70)->big_handle);
	ATF_CHECK_EQ(11, ng_hci_con_by_handle(unit, 0x71)->big_handle);

	con = ng_hci_con_by_handle(unit, 0x70);
	con->flags |= NG_HCI_CON_TIMEOUT_PENDING;
	lost.big_handle = 11;
	lost.reason = BT_HR_SPEC_REASON_CONN_TIMEOUT;
	le_event(unit, ut_le_typed_event(BT_HR_SPEC_SUBEVENT_BIG_SYNC_LOST,
	    &lost, sizeof(lost)));
	ATF_CHECK_EQ(4, g_discon_ind_calls);
	ATF_CHECK_EQ(BT_HR_SPEC_REASON_CONN_TIMEOUT, g_last_discon_reason);
	ATF_CHECK(ng_hci_con_by_handle(unit, 0x70) == NULL);
	ATF_CHECK(ng_hci_con_by_handle(unit, 0x71) == NULL);

	/* Controller failure and truncated handle arrays create no BIS links. */
	create.status = 1;
	create.big_handle = 12;
	create.num_bis = 1;
	le_event(unit, ut_le_typed_event(BT_HR_SPEC_SUBEVENT_CREATE_BIG_COMPLETE,
	    &create, sizeof(create)));
	create.status = 0;
	le_event(unit, ut_le_typed_event(BT_HR_SPEC_SUBEVENT_CREATE_BIG_COMPLETE,
	    &create, sizeof(create)));
	ATF_CHECK(ng_hci_con_by_handle(unit, 0) == NULL);

	ut_unit_free(unit);
}

ATF_TC_WITHOUT_HEAD(classic_event_padded_matrix);
ATF_TC_BODY(classic_event_padded_matrix, tc)
{
	/* Implementation robustness contract for Core §7.7 event decoders. */
	typedef int (*event_handler_t)(ng_hci_unit_p, struct mbuf *);
	static event_handler_t const handlers[] = {
		inquiry_result,
		inquiry_result_with_rssi,
		ext_inquiry_result,
		con_compl,
		con_req,
		discon_compl,
		encryption_change,
		encryption_change_v2,
		sync_con_compl,
		read_remote_features_compl,
		qos_setup_compl,
		hardware_error,
		role_change,
		num_compl_pkts,
		mode_change,
		data_buffer_overflow,
		read_clock_offset_compl,
		qos_violation,
		page_scan_mode_change,
		page_scan_rep_mode_change,
	};
	unsigned char payload[256];

	memset(payload, 0, sizeof(payload));
	for (size_t i = 0; i < sizeof(handlers) / sizeof(handlers[0]); i++) {
		ng_hci_unit_t *unit;
		ng_hci_unit_con_p con;
		struct mbuf *event, *queued;

		unit = ut_unit_new();
		unit->debug = NG_HCI_INFO_LEVEL;
		con = ng_hci_new_con(unit, NG_HCI_LINK_ACL);
		con->con_handle = 0;
		con->state = NG_HCI_CON_OPEN;
		event = ut_event(payload, sizeof(payload));
		(void)handlers[i](unit, event);
		while (NG_BT_MBUFQ_LEN(&unit->cmdq) != 0) {
			NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
			NG_FREE_M(queued);
		}
		while ((con = LIST_FIRST(&unit->con_list)) != NULL)
			ng_hci_free_con(con);
		free(unit);
	}
}

ATF_TC_WITHOUT_HEAD(classic_event_operand_mutation_matrix);
ATF_TC_BODY(classic_event_operand_mutation_matrix, tc)
{
	/* Implementation robustness contract for Core §7.7 event decoders. */
	typedef int (*event_handler_t)(ng_hci_unit_p, struct mbuf *);
	static event_handler_t const handlers[] = {
		inquiry_result, inquiry_result_with_rssi, ext_inquiry_result,
		con_compl, con_req, discon_compl, encryption_change,
		encryption_change_v2, sync_con_compl, read_remote_features_compl,
		qos_setup_compl, hardware_error, role_change, num_compl_pkts,
		mode_change, data_buffer_overflow, read_clock_offset_compl,
		qos_violation, page_scan_mode_change, page_scan_rep_mode_change,
	};
	unsigned char payload[256];

	/* Exercise each predicate operand independently after the zero baseline. */
	for (size_t h = 0; h < nitems(handlers); h++) {
		for (size_t byte = 0; byte < sizeof(payload); byte++) {
			ng_hci_unit_t *unit;
			ng_hci_unit_con_p con;
			struct mbuf *queued;

			ut_reset();
			unit = ut_unit_new();
			con = ng_hci_new_con(unit, NG_HCI_LINK_ACL);
			con->con_handle = 0;
			con->state = NG_HCI_CON_OPEN;
			memset(payload, 0, sizeof(payload));
			payload[byte] = 0xff;
			(void)handlers[h](unit, ut_event(payload, sizeof(payload)));
			while (NG_BT_MBUFQ_LEN(&unit->cmdq) != 0) {
				NG_BT_MBUFQ_DEQUEUE(&unit->cmdq, queued);
				NG_FREE_M(queued);
			}
			while ((con = LIST_FIRST(&unit->con_list)) != NULL)
				ng_hci_free_con(con);
			free(unit);
		}
	}
}

static void
queue_test_item(ng_hci_unit_con_p con, int len)
{
	struct ng_item *item;

	item = calloc(1, sizeof(*item));
	ATF_REQUIRE(item != NULL);
	item->m = ut_mbuf_alloc();
	ATF_REQUIRE(item->m != NULL);
	item->m->m_len = item->m->m_pkthdr.len = len;
	NG_BT_ITEMQ_ENQUEUE(&con->conq, item);
}

ATF_TC_WITHOUT_HEAD(data_queue_and_flow_control_matrix);
ATF_TC_BODY(data_queue_and_flow_control_matrix, tc)
{
	/* Core Vol 4 Part E §5.4.2 flow control plus local queue policy. */
	static const int links[] = { NG_HCI_LINK_ACL, NG_HCI_LINK_SCO,
	    NG_HCI_LINK_LE_PUBLIC, NG_HCI_LINK_ISO_CIS };
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p con;

	unit = ut_unit_new();
	unit->state = NG_HCI_UNIT_READY;
	unit->drv = (hook_p)(uintptr_t)1;
	unit->acl = (hook_p)(uintptr_t)2;
	unit->sco = (hook_p)(uintptr_t)3;
	unit->iso = (hook_p)(uintptr_t)4;
	NG_HCI_BUFF_ACL_SET(unit->buffer, 2, 251, 2);
	NG_HCI_BUFF_SCO_SET(unit->buffer, 1, 60, 1);
	NG_HCI_BUFF_LE_SET(unit->buffer, 1, 251, 1);
	NG_HCI_BUFF_ISO_SET(unit->buffer, 1, 251, 1);
	for (size_t i = 0; i < nitems(links); i++) {
		con = ng_hci_new_con(unit, links[i]);
		con->state = NG_HCI_CON_OPEN;
		queue_test_item(con, 20 + (int)i);
	}
	ng_hci_send_data(unit);
	LIST_FOREACH(con, &unit->con_list, next) {
		ATF_CHECK_EQ(0, NG_BT_ITEMQ_LEN(&con->conq));
		ATF_CHECK_EQ(1, con->pending);
	}

	/* Driver loss consumes the failed item and reports a zero completion. */
	con = LIST_FIRST(&unit->con_list);
	ATF_REQUIRE(con != NULL);
	con->link_type = NG_HCI_LINK_ACL;
	queue_test_item(con, 10);
	unit->drv = NULL;
	ATF_CHECK_EQ(0, send_data_packets(unit, NG_HCI_LINK_ACL, 1));
	ATF_CHECK_EQ(0, NG_BT_ITEMQ_LEN(&con->conq));
	ATF_CHECK_EQ(0, sync_con_queue(unit, con, 0));
	unit->acl = NULL;
	ATF_CHECK_EQ(ENOTCONN, sync_con_queue(unit, con, 0));

	while ((con = LIST_FIRST(&unit->con_list)) != NULL)
		ng_hci_free_con(con);
	free(unit);
}

ATF_TC_WITHOUT_HEAD(completed_packets_accounting_matrix);
ATF_TC_BODY(completed_packets_accounting_matrix, tc)
{
	static const int links[] = { NG_HCI_LINK_ACL, NG_HCI_LINK_SCO,
	    NG_HCI_LINK_LE_PUBLIC, NG_HCI_LINK_ISO_CIS };
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p cons[nitems(links)];
	unsigned char payload[BT_HR_SPEC_COMPLETED_COUNT_LEN +
	    5 * BT_HR_SPEC_COMPLETED_RECORD_LEN];
	uint16_t value;
	int off;

	/* Core 6.3 Vol 4 Part E §7.7.19 count/handle/credit records. */
	ut_reset();
	unit = ut_unit_new();
	NG_HCI_BUFF_ACL_SET(unit->buffer, 8, 251, 0);
	NG_HCI_BUFF_SCO_SET(unit->buffer, 8, 60, 0);
	NG_HCI_BUFF_LE_SET(unit->buffer, 8, 251, 0);
	NG_HCI_BUFF_ISO_SET(unit->buffer, 8, 251, 0);
	for (size_t i = 0; i < nitems(links); i++) {
		cons[i] = ng_hci_new_con(unit, links[i]);
		cons[i]->con_handle = 0x90 + (int)i;
		cons[i]->pending = 3;
	}

	off = 0;
	payload[off++] = 5;
	for (int i = 0; i < 5; i++) {
		value = htole16(0x90 + i); /* last handle intentionally missing */
		memcpy(&payload[off], &value, sizeof(value));
		off += sizeof(value);
		value = htole16(2);
		memcpy(&payload[off], &value, sizeof(value));
		off += sizeof(value);
	}
	ATF_REQUIRE_EQ(0, num_compl_pkts(unit, ut_event(payload, off)));
	for (size_t i = 0; i < nitems(cons); i++)
		ATF_CHECK_EQ(1, cons[i]->pending);
	ATF_CHECK_EQ(2, unit->buffer.acl_free);
	ATF_CHECK_EQ(2, unit->buffer.sco_free);
	ATF_CHECK_EQ(2, unit->buffer.le_free);
	ATF_CHECK_EQ(2, unit->buffer.iso_free);

	/* Over-completion clamps pending and credits only outstanding packets. */
	payload[0] = 1;
	value = htole16(0x90);
	memcpy(&payload[1], &value, sizeof(value));
	value = htole16(7);
	memcpy(&payload[3], &value, sizeof(value));
	ATF_REQUIRE_EQ(0, num_compl_pkts(unit, ut_event(payload, 5)));
	ATF_CHECK_EQ(0, cons[0]->pending);
	ATF_CHECK_EQ(3, unit->buffer.acl_free);

	/* Controllers without ISO buffers account ISO packets against ACL. */
	unit->buffer.iso_pkts = 0;
	cons[3]->pending = 1;
	value = htole16(0x93);
	memcpy(&payload[1], &value, sizeof(value));
	value = htole16(1);
	memcpy(&payload[3], &value, sizeof(value));
	ATF_REQUIRE_EQ(0, num_compl_pkts(unit, ut_event(payload, 5)));
	ATF_CHECK_EQ(0, cons[3]->pending);
	ATF_CHECK_EQ(4, unit->buffer.acl_free);

	/* A declared but truncated handle tuple is rejected before processing. */
	payload[0] = 1;
	ATF_REQUIRE_EQ(EMSGSIZE, num_compl_pkts(unit, ut_event(payload, 2)));

	ut_unit_free(unit);
}

ATF_TC_WITHOUT_HEAD(classic_status_and_handle_error_matrix);
ATF_TC_BODY(classic_status_and_handle_error_matrix, tc)
{
	/* Core §7.7 status/handle fields plus implementation error policy. */
	ng_hci_discon_compl_ep discon = { 0 };
	ng_hci_read_remote_features_compl_ep features = { 0 };
	ng_hci_qos_setup_compl_ep qos = { 0 };
	ng_hci_role_change_ep role = { 0 };
	ng_hci_mode_change_ep mode = { 0 };
	ng_hci_read_clock_offset_compl_ep clock = { 0 };
	ng_hci_qos_violation_ep violation = { 0 };
	ng_hci_unit_t *unit;
	ng_hci_unit_con_p con;
	uint8_t overflow;

	ut_reset();
	unit = ut_unit_new();

	/* Successful status with an unknown handle must never mutate state. */
	discon.con_handle = htole16(0x321);
	ATF_CHECK_EQ(ENOENT, discon_compl(unit,
	    ut_event(&discon, sizeof(discon))));
	ATF_CHECK_EQ(ENOENT, encryption_change_common(unit, NULL, 0x321, 0,
	    1));

	con = ng_hci_new_con(unit, NG_HCI_LINK_SCO);
	con->con_handle = 0x40;
	ATF_CHECK_EQ(EINVAL, encryption_change_common(unit, con, 0x40, 0, 1));
	con->link_type = NG_HCI_LINK_ACL;
	ATF_CHECK_EQ(0, encryption_change_common(unit, con, 0x40, 0, 0));
	ATF_CHECK_EQ(NG_HCI_ENCRYPTION_MODE_NONE, con->encryption_mode);
	ATF_CHECK_EQ(0, encryption_change_common(unit, con, 0x40, 0, 2));
	ATF_CHECK_EQ(NG_HCI_ENCRYPTION_MODE_AES_CCM, con->encryption_mode);
	ATF_CHECK_EQ(0, encryption_change_common(unit, con, 0x40, 0, 1));
	ATF_CHECK_EQ(NG_HCI_ENCRYPTION_MODE_P2P, con->encryption_mode);
	ATF_CHECK_EQ(0, encryption_change_common(unit, con, 0x40, 1, 1));
	ATF_CHECK_EQ(NG_HCI_ENCRYPTION_MODE_NONE, con->encryption_mode);
	con->link_type = NG_HCI_LINK_LE_RANDOM;
	ATF_CHECK_EQ(0, encryption_change_common(unit, con, 0x40, 0, 1));
	ATF_CHECK_EQ(NG_HCI_ENCRYPTION_MODE_AES_CCM, con->encryption_mode);

	features.con_handle = htole16(0x321);
	ATF_CHECK_EQ(ENOENT, read_remote_features_compl(unit,
	    ut_event(&features, sizeof(features))));
	features.con_handle = htole16(0x40);
	g_neighbor_alloc_fail = 1;
	ATF_CHECK_EQ(ENOMEM, read_remote_features_compl(unit,
	    ut_event(&features, sizeof(features))));
	g_neighbor_alloc_fail = 0;
	features.status = 1;
	ATF_CHECK_EQ(0, read_remote_features_compl(unit,
	    ut_event(&features, sizeof(features))));

	qos.con_handle = htole16(0x321);
	ATF_CHECK_EQ(ENOENT, qos_setup_compl(unit, ut_event(&qos, sizeof(qos))));
	qos.con_handle = htole16(0x40);
	ATF_CHECK_EQ(EINVAL, qos_setup_compl(unit, ut_event(&qos, sizeof(qos))));
	con->link_type = NG_HCI_LINK_ACL;
	con->state = NG_HCI_CON_CLOSED;
	ATF_CHECK_EQ(EINVAL, qos_setup_compl(unit, ut_event(&qos, sizeof(qos))));
	con->state = NG_HCI_CON_OPEN;
	ATF_CHECK_EQ(0, qos_setup_compl(unit, ut_event(&qos, sizeof(qos))));

	ATF_CHECK_EQ(0, role_change(unit, ut_event(&role, sizeof(role))));
	role.status = 1;
	ATF_CHECK_EQ(0, role_change(unit, ut_event(&role, sizeof(role))));

	mode.con_handle = htole16(0x321);
	ATF_CHECK_EQ(ENOENT, mode_change(unit, ut_event(&mode, sizeof(mode))));
	mode.con_handle = htole16(0x40);
	con->link_type = NG_HCI_LINK_SCO;
	ATF_CHECK_EQ(EINVAL, mode_change(unit, ut_event(&mode, sizeof(mode))));
	con->link_type = NG_HCI_LINK_ACL;
	mode.unit_mode = 2;
	ATF_CHECK_EQ(0, mode_change(unit, ut_event(&mode, sizeof(mode))));
	ATF_CHECK_EQ(2, con->mode);
	mode.status = 1;
	ATF_CHECK_EQ(0, mode_change(unit, ut_event(&mode, sizeof(mode))));

	for (overflow = 0; overflow < 4; overflow++)
		ATF_CHECK_EQ(0, data_buffer_overflow(unit,
		    ut_event(&overflow, sizeof(overflow))));

	clock.con_handle = htole16(0x321);
	ATF_CHECK_EQ(ENOENT, read_clock_offset_compl(unit,
	    ut_event(&clock, sizeof(clock))));
	clock.con_handle = htole16(0x40);
	g_neighbor_alloc_fail = 1;
	ATF_CHECK_EQ(ENOMEM, read_clock_offset_compl(unit,
	    ut_event(&clock, sizeof(clock))));
	g_neighbor_alloc_fail = 0;
	clock.status = 1;
	ATF_CHECK_EQ(0, read_clock_offset_compl(unit,
	    ut_event(&clock, sizeof(clock))));

	violation.con_handle = htole16(0x321);
	ATF_CHECK_EQ(ENOENT, qos_violation(unit,
	    ut_event(&violation, sizeof(violation))));
	violation.con_handle = htole16(0x40);
	con->link_type = NG_HCI_LINK_SCO;
	ATF_CHECK_EQ(EINVAL, qos_violation(unit,
	    ut_event(&violation, sizeof(violation))));
	con->link_type = NG_HCI_LINK_ACL;
	con->state = NG_HCI_CON_CLOSED;
	ATF_CHECK_EQ(EINVAL, qos_violation(unit,
	    ut_event(&violation, sizeof(violation))));
	con->state = NG_HCI_CON_OPEN;
	ATF_CHECK_EQ(0, qos_violation(unit,
	    ut_event(&violation, sizeof(violation))));

	ut_unit_free(unit);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, le_con_compl_incoming_peripheral_role);
	ATF_TP_ADD_TC(tp, le_con_compl_existing_central_role);
	ATF_TP_ADD_TC(tp, le_enh_con_compl_peripheral_role);
	ATF_TP_ADD_TC(tp, event_dispatch_malformed_sweep);
	ATF_TP_ADD_TC(tp, le_subevent_padded_sweep);
	ATF_TP_ADD_TC(tp, le_subevent_operand_mutation_sweep);
	ATF_TP_ADD_TC(tp, le_advertising_neighbor_lifecycle);
	ATF_TP_ADD_TC(tp, classic_inquiry_neighbor_lifecycle);
	ATF_TP_ADD_TC(tp, classic_connection_event_lifecycle);
	ATF_TP_ADD_TC(tp, le_cis_lifecycle_matrix);
	ATF_TP_ADD_TC(tp, le_big_bis_lifecycle_matrix);
	ATF_TP_ADD_TC(tp, classic_event_padded_matrix);
	ATF_TP_ADD_TC(tp, classic_event_operand_mutation_matrix);
	ATF_TP_ADD_TC(tp, data_queue_and_flow_control_matrix);
	ATF_TP_ADD_TC(tp, completed_packets_accounting_matrix);
	ATF_TP_ADD_TC(tp, classic_status_and_handle_error_matrix);

	return (atf_no_error());
}
