/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Regression tests for the blued HCI-core correctness findings:
 *
 *   40 — Command-Status wrappers must request a 4-byte rparam so bt_devreq
 *        copies the ng_hci_command_status_ep and the status byte is delivered
 *        (rlen >= 4); a nonzero controller status is then reported as failure.
 *   42 — hci_mesh_adv_burst on an extended controller disables the set before
 *        reprogramming parameters (else Command Disallowed wedges the bearer),
 *        and uses a mesh handle distinct from the 0x00/0x01 sets already in use.
 *   48 — hci_fd_closed releases the per-fd lock slot so a reused fd reclaims a
 *        dedicated mutex slot rather than degrading to a hashed one.
 *   143 — hci_le_set_host_feature encodes and reports status correctly, so the
 *         CIS/subrating host-support bits are reachable.
 *
 * The controller commands are interposed at link time (-Wl,--wrap=bt_devreq),
 * exactly like hci_conform_test.c.  The wrap models the two reply flavours:
 * for a Command Complete it copies the mock status into rparam[0]; for a
 * Command Status it copies the 4-byte ng_hci_command_status_ep *only when the
 * caller asked for >= 4 rparam bytes*, mirroring lib/libbluetooth/hci.c.
 */

#include <atf-c.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "ble_util.h"

/* Stub globals required by the hci_*.c logging macros. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

#define FD	3

#define MAXCMD	16
static struct {
	int		ncmd;
	uint16_t	opcode[MAXCMD];
	uint8_t		cp0[MAXCMD];	/* first command parameter octet */
	uint8_t		cp2[MAXCMD];	/* third command parameter octet */
	uint16_t	rlen[MAXCMD];	/* rparam length the caller requested */
	uint8_t		rev[MAXCMD];	/* r->event the caller requested */
	uint8_t		mock_status;	/* status the controller returns */
} W;

int __wrap_bt_devreq(int s, struct bt_devreq *r, time_t to);

int
__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to)
{
	int i;

	(void)s;
	(void)to;

	i = W.ncmd;
	if (i < MAXCMD) {
		const uint8_t *cp = r->cparam;

		W.opcode[i] = r->opcode;
		W.cp0[i] = (cp != NULL && r->clen >= 1) ? cp[0] : 0;
		W.cp2[i] = (cp != NULL && r->clen >= 3) ? cp[2] : 0;
		W.rlen[i] = (uint16_t)r->rlen;
		W.rev[i] = r->event;
		W.ncmd++;
	}

	if (r->rparam == NULL || r->rlen == 0)
		return (0);

	if (r->event == NG_HCI_EVENT_COMMAND_STATUS) {
		/*
		 * bt_devreq copies the 4-byte Command Status event into rparam
		 * only if rlen >= 4; otherwise it copies nothing (finding 40).
		 */
		if (r->rlen >= (int)sizeof(ng_hci_command_status_ep)) {
			ng_hci_command_status_ep ep;

			memset(&ep, 0, sizeof(ep));
			ep.status = W.mock_status;
			memcpy(r->rparam, &ep, sizeof(ep));
		}
		/* rlen < 4: leave rparam untouched (the historical bug). */
	} else {
		memset(r->rparam, 0, r->rlen);
		((uint8_t *)r->rparam)[0] = W.mock_status;
	}
	return (0);
}

static void
mock_reset(void)
{

	memset(&W, 0, sizeof(W));
}

/* ================================================================
 * Finding 40 — Command-Status wrapper delivers the status byte.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cmd_status_rlen_and_status);
ATF_TC_BODY(cmd_status_rlen_and_status, tc)
{
	int rc;

	/* Accepted command (status 0x00) succeeds. */
	mock_reset();
	W.mock_status = 0x00;
	rc = hci_le_connection_update(FD, 0x0040, 0x0018, 0x0028, 0x0000,
	    0x0064);
	ATF_CHECK_EQ_MSG(0, rc, "accepted conn-update must return 0");
	ATF_REQUIRE(W.ncmd >= 1);
	ATF_CHECK_EQ_MSG(NG_HCI_EVENT_COMMAND_STATUS, W.rev[0],
	    "conn-update waits on a Command Status event");
	ATF_CHECK_MSG(W.rlen[0] >= 4,
	    "rparam must be >= 4 bytes so bt_devreq copies the status "
	    "(got rlen=%u)", W.rlen[0]);

	/* Rejected command (nonzero status) is reported as failure. */
	mock_reset();
	W.mock_status = 0x0C;	/* Command Disallowed */
	rc = hci_le_connection_update(FD, 0x0040, 0x0018, 0x0028, 0x0000,
	    0x0064);
	ATF_CHECK_EQ_MSG(-1, rc,
	    "a nonzero Command Status must be reported as -1");
}

/* ================================================================
 * Finding 143 — LE Set Host Feature encodes and checks status.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(set_host_feature_encode);
ATF_TC_BODY(set_host_feature_encode, tc)
{
	int rc;

	mock_reset();
	W.mock_status = 0x00;
	rc = hci_le_set_host_feature(FD, 32 /* CIS host support */, 0x01);
	ATF_CHECK_EQ_MSG(0, rc, "set host feature must succeed on status 0");
	ATF_REQUIRE(W.ncmd >= 1);
	ATF_CHECK_EQ(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_HOST_FEATURE), W.opcode[0]);
	ATF_CHECK_EQ_MSG(32, W.cp0[0], "bit_number octet");

	mock_reset();
	W.mock_status = 0x11;	/* Unsupported Feature */
	rc = hci_le_set_host_feature(FD, 38, 0x01);
	ATF_CHECK_EQ_MSG(-1, rc, "nonzero status must fail");
}

/* ================================================================
 * Finding 42 — mesh adv burst disables the set first and uses a
 * distinct handle (0x02, not the 0x00/0x01 sets already in use).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_adv_burst_disable_and_handle);
ATF_TC_BODY(mesh_adv_burst_disable_and_handle, tc)
{
	static const uint8_t ad[] = { 0x03, 0x2a, 0xAB, 0xCD };
	uint16_t enable_ocf = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_ADV_ENABLE);
	uint16_t params_ocf = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_ADV_PARAMS);
	int i, rc;

	ATF_CHECK_EQ_MSG(0x02, MESH_ADV_HANDLE,
	    "mesh handle must not collide with the 0x00/0x01 sets");

	mock_reset();
	W.mock_status = 0x00;
	rc = hci_mesh_adv_burst(FD, LE_FEAT_EXT_ADVERTISING, ad, sizeof(ad));
	ATF_CHECK_EQ(0, rc);
	ATF_REQUIRE_MSG(W.ncmd >= 2, "expected disable + params + data + enable");

	/* First command must be Set Ext Adv Enable with enable=0, handle 0x02. */
	ATF_CHECK_EQ_MSG(enable_ocf, W.opcode[0],
	    "first command must disable the set");
	ATF_CHECK_EQ_MSG(0x00, W.cp0[0], "disable: enable octet must be 0");
	ATF_CHECK_EQ_MSG(MESH_ADV_HANDLE, W.cp2[0],
	    "disable: handle octet must be the mesh handle");

	/* Set Ext Adv Params must follow, and every set command uses 0x02. */
	{
		bool saw_params = false, saw_final_enable = false;

		for (i = 1; i < W.ncmd; i++) {
			if (W.opcode[i] == params_ocf) {
				saw_params = true;
				ATF_CHECK_EQ_MSG(MESH_ADV_HANDLE, W.cp0[i],
				    "params: adv handle octet");
			}
			if (W.opcode[i] == enable_ocf && W.cp0[i] == 0x01) {
				saw_final_enable = true;
				ATF_CHECK_EQ_MSG(MESH_ADV_HANDLE, W.cp2[i],
				    "enable: handle octet");
			}
		}
		ATF_CHECK_MSG(saw_params, "Set Ext Adv Params must be issued");
		ATF_CHECK_MSG(saw_final_enable,
		    "the set must finally be enabled");
	}
}

/* ================================================================
 * Finding 48 — hci_fd_closed frees the per-fd lock slot for reuse.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fd_closed_releases_lock_slot);
ATF_TC_BODY(fd_closed_releases_lock_slot, tc)
{
	pthread_mutex_t *m_first, *m_reused;

	/*
	 * Claim a dedicated slot for a distinctive fd, forget it, then a new
	 * fd must be able to reclaim that very slot (same mutex pointer).
	 */
	m_first = hci_devreq_mutex(101);
	ATF_REQUIRE(m_first != NULL);

	hci_fd_closed(101);

	m_reused = hci_devreq_mutex(202);
	ATF_CHECK_EQ_MSG(m_first, m_reused,
	    "a reused fd must reclaim the freed lock slot");

	/* Forgetting the scan-state slot for an unknown fd is a safe no-op. */
	hci_scan_forget_fd(999);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, cmd_status_rlen_and_status);
	ATF_TP_ADD_TC(tp, set_host_feature_encode);
	ATF_TP_ADD_TC(tp, mesh_adv_burst_disable_and_handle);
	ATF_TP_ADD_TC(tp, fd_closed_releases_lock_slot);

	return (atf_no_error());
}
