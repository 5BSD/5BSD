/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Residual branch-coverage for the ATT *client* request helpers in att.c.
 *
 * The client helpers each emit LOG_ATT() trace whose _BLUED_LOG() body is
 * gated on `blued_verbose >= level` and branches again on
 * `blued_daemonized` (syslog vs stderr) plus the syslog priority select.
 * These are real, reachable branches on the daemon's -vv trace path.  This
 * suite drives each client helper once per opcode with a canned server
 * response primed into the socket, at -vv verbosity in both the foreground
 * (stderr) and daemonized (syslog) configurations, to cover them.
 *
 * The response opcodes primed here are the mandated response PDUs from the
 * Bluetooth Core Specification, Vol 3 Part F (Attribute Protocol)
 * Section 3.4.  A SOCK_SEQPACKET socketpair stands in for the L2CAP ATT
 * channel: a response written from the peer end is queued on the client's
 * receive side, so the helper's blocking recv(2) returns it immediately.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <atf-c.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "hci_log.h"
#include "spec_att_client_oracles.h"

#include "test_common.h"

static void
assert_att_client_wire_contract(void)
{
	ATF_CHECK_EQ(BT_CORE63_ATT_OP_MTU_RSP, ATT_OP_MTU_RSP);
	ATF_CHECK_EQ(BT_CORE63_ATT_OP_FIND_INFO_RSP, ATT_OP_FIND_INFO_RSP);
	ATF_CHECK_EQ(BT_CORE63_ATT_OP_FIND_BY_TYPE_VALUE_RSP,
	    ATT_OP_FIND_BY_TYPE_VALUE_RSP);
	ATF_CHECK_EQ(BT_CORE63_ATT_OP_READ_BY_TYPE_RSP,
	    ATT_OP_READ_BY_TYPE_RSP);
	ATF_CHECK_EQ(BT_CORE63_ATT_OP_READ_RSP, ATT_OP_READ_RSP);
	ATF_CHECK_EQ(BT_CORE63_ATT_OP_READ_BLOB_RSP, ATT_OP_READ_BLOB_RSP);
	ATF_CHECK_EQ(BT_CORE63_ATT_OP_READ_MULTIPLE_RSP,
	    ATT_OP_READ_MULTIPLE_RSP);
	ATF_CHECK_EQ(BT_CORE63_ATT_OP_READ_BY_GROUP_TYPE_RSP,
	    ATT_OP_READ_BY_GROUP_TYPE_RSP);
	ATF_CHECK_EQ(BT_CORE63_ATT_OP_WRITE_RSP, ATT_OP_WRITE_RSP);
	ATF_CHECK_EQ(BT_CORE63_ATT_OP_PREPARE_WRITE_RSP,
	    ATT_OP_PREPARE_WRITE_RSP);
	ATF_CHECK_EQ(BT_CORE63_ATT_OP_EXECUTE_WRITE_RSP,
	    ATT_OP_EXECUTE_WRITE_RSP);
	ATF_CHECK_EQ(BT_CORE63_ATT_OP_HANDLE_NOTIFY, ATT_OP_HANDLE_NOTIFY);
	ATF_CHECK_EQ(BT_CORE63_ATT_OP_READ_MULTIPLE_VARIABLE_RSP,
	    ATT_OP_READ_MULTIPLE_VARIABLE_RSP);
	ATF_CHECK_EQ(BT_CORE63_EATT_MIN_MTU, ATT_EATT_MIN_MTU);
}

int att_test_eatt_mtu(int, uint16_t *, uint16_t *);
int
att_test_eatt_mtu(int fd __unused, uint16_t *imtu, uint16_t *omtu)
{

	*imtu = *omtu = ATT_EATT_MIN_MTU;
	return (0);
}

static void
cli_pair(struct att_conn *ac, int *peer)
{
	int fds[2];

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(ac, 0, sizeof(*ac));
	ac->fd = fds[0];
	ac->bearer_fd = -1;
	ac->mtu = 247;
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	*peer = fds[1];
}

static void
cli_cleanup(struct att_conn *ac, int peer)
{

	free(ac->buf);
	ac->buf = NULL;
	if (ac->fd >= 0)
		close(ac->fd);
	if (peer >= 0)
		close(peer);
}

/* Queue a server response onto the client's receive side. */
static void
prime(int peer, const uint8_t *pdu, size_t len)
{

	ATF_REQUIRE(send(peer, pdu, len, MSG_EOR) == (ssize_t)len);
}

/*
 * Drive every client helper once, each with its mandated success response
 * primed.  Called at -vv with each blued_daemonized setting.
 */
static void
run_client_battery(struct att_conn *ac, int peer)
{
	uint8_t rsp[64];
	uint8_t obuf[64];
	size_t outlen;
	/* Generic valid attribute-handle sentinels, not assigned values. */
	uint16_t handles[2] = { 0x0003, 0x0005 };

	/* Exchange MTU: ATT_MTU_RSP (0x03). */
	ac->mtu_exchanged = false;
	rsp[0] = BT_CORE63_ATT_OP_MTU_RSP; put_le16(rsp + 1, 200);
	prime(peer, rsp, 3);
	(void)att_exchange_mtu(ac, 200);

	/* Read: ATT_READ_RSP (0x0B). */
	rsp[0] = BT_CORE63_ATT_OP_READ_RSP; rsp[1] = 0xAA; rsp[2] = 0xBB;
	prime(peer, rsp, 3);
	(void)att_read(ac, 0x0003, obuf, sizeof(obuf), &outlen);

	/* Read Blob: ATT_READ_BLOB_RSP (0x0D). */
	rsp[0] = BT_CORE63_ATT_OP_READ_BLOB_RSP; rsp[1] = 0xCC;
	prime(peer, rsp, 2);
	(void)att_read_blob(ac, 0x0003, 2, obuf, sizeof(obuf), &outlen);

	/* Write Request: ATT_WRITE_RSP (0x13). */
	rsp[0] = BT_CORE63_ATT_OP_WRITE_RSP;
	prime(peer, rsp, 1);
	(void)att_write_req(ac, 0x0003, "\x01\x02", 2);

	/* Write Command: no response is generated. */
	(void)att_write_cmd(ac, 0x0003, "\x09", 1);

	/* Find Information: ATT_FIND_INFO_RSP (0x05), format 1 (16-bit). */
	rsp[0] = BT_CORE63_ATT_OP_FIND_INFO_RSP; rsp[1] = 0x01;
	put_le16(rsp + 2, 0x0003);
	put_le16(rsp + 4, BT_ASSIGNED_UUID_DEVICE_NAME);
	prime(peer, rsp, 6);
	(void)att_find_info(ac, 0x0001, 0xFFFF, obuf, sizeof(obuf), &outlen);

	/* Read By Type: ATT_READ_BY_TYPE_RSP (0x09), 4-octet entries. */
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_TYPE_RSP; rsp[1] = 0x04;
	put_le16(rsp + 2, 0x0003); put_le16(rsp + 4, 0x1234);
	prime(peer, rsp, 6);
	(void)att_read_by_type(ac, 0x0001, 0xFFFF,
	    BT_ASSIGNED_UUID_CHARACTERISTIC, obuf, sizeof(obuf),
	    &outlen);

	/* Read By Group Type: ATT_READ_BY_GROUP_TYPE_RSP (0x11). */
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_GROUP_TYPE_RSP; rsp[1] = 0x06;
	put_le16(rsp + 2, 0x0001); put_le16(rsp + 4, 0x0009);
	put_le16(rsp + 6, BT_ASSIGNED_UUID_GAP_SERVICE);
	prime(peer, rsp, 8);
	(void)att_read_by_group_type(ac, 0x0001, 0xFFFF,
	    BT_ASSIGNED_UUID_PRIMARY_SERVICE, obuf,
	    sizeof(obuf), &outlen);

	/* Find By Type Value: ATT_FIND_BY_TYPE_VALUE_RSP (0x07). */
	rsp[0] = BT_CORE63_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
	put_le16(rsp + 1, 0x0001); put_le16(rsp + 3, 0x0009);
	prime(peer, rsp, 5);
	(void)att_find_by_type_value(ac, 0x0001, 0xFFFF,
	    BT_ASSIGNED_UUID_PRIMARY_SERVICE, "\x00\x18", 2,
	    obuf, sizeof(obuf), &outlen);

	/* Read Multiple: ATT_READ_MULTIPLE_RSP (0x0F). */
	rsp[0] = BT_CORE63_ATT_OP_READ_MULTIPLE_RSP;
	rsp[1] = 0x01; rsp[2] = 0x02;
	prime(peer, rsp, 3);
	(void)att_read_multiple(ac, handles, 2, obuf, sizeof(obuf), &outlen);

	/* Read Multiple Variable: ATT_READ_MULTIPLE_VARIABLE_RSP (0x21). */
	rsp[0] = BT_CORE63_ATT_OP_READ_MULTIPLE_VARIABLE_RSP;
	put_le16(rsp + 1, 1); rsp[3] = 0x02;
	prime(peer, rsp, 4);
	(void)att_read_multiple_variable(ac, handles, 2, obuf, sizeof(obuf),
	    &outlen);

	/* Prepare Write: ATT_PREPARE_WRITE_RSP (0x17), echoes handle/offset. */
	rsp[0] = BT_CORE63_ATT_OP_PREPARE_WRITE_RSP;
	put_le16(rsp + 1, 0x0003); put_le16(rsp + 3, 0x0000); rsp[5] = 0x01;
	prime(peer, rsp, 6);
	(void)att_prepare_write(ac, 0x0003, 0, "\x01", 1);

	/* Execute Write: ATT_EXECUTE_WRITE_RSP (0x19). */
	rsp[0] = BT_CORE63_ATT_OP_EXECUTE_WRITE_RSP;
	prime(peer, rsp, 1);
	(void)att_execute_write(ac, 0x01);

	/* Write Long: one Prepare (server echoes handle/offset/value) then
	 * Execute (Vol 3 Part F 3.4.6.1/3.4.6.3). */
	rsp[0] = BT_CORE63_ATT_OP_PREPARE_WRITE_RSP;
	put_le16(rsp + 1, 0x0003); put_le16(rsp + 3, 0x0000);
	rsp[5] = 0x07; rsp[6] = 0x08; rsp[7] = 0x09;	/* echoed value */
	prime(peer, rsp, 8);
	rsp[0] = BT_CORE63_ATT_OP_EXECUTE_WRITE_RSP;
	prime(peer, rsp, 1);
	(void)att_write_long(ac, 0x0003, "\x07\x08\x09", 3);

	/* Confirm: unacknowledged, just sends. */
	(void)att_confirm(ac);

	/* Receive an unsolicited notification. */
	rsp[0] = BT_CORE63_ATT_OP_HANDLE_NOTIFY;
	put_le16(rsp + 1, 0x0003); rsp[3] = 0x55;
	prime(peer, rsp, 4);
	(void)att_recv(ac, obuf, sizeof(obuf), &outlen);
}

ATF_TC_WITHOUT_HEAD(client_battery_stderr);
ATF_TC_BODY(client_battery_stderr, tc)
{
	struct att_conn ac;
	int peer;

	assert_att_client_wire_contract();
	cli_pair(&ac, &peer);
	atomic_store(&blued_verbose, 2);
	blued_daemonized = 0;
	run_client_battery(&ac, peer);
	atomic_store(&blued_verbose, 0);
	cli_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(client_battery_syslog);
ATF_TC_BODY(client_battery_syslog, tc)
{
	struct att_conn ac;
	int peer;

	assert_att_client_wire_contract();
	cli_pair(&ac, &peer);
	atomic_store(&blued_verbose, 2);
	blued_daemonized = 1;
	run_client_battery(&ac, peer);
	atomic_store(&blued_verbose, 0);
	blued_daemonized = 0;
	cli_cleanup(&ac, peer);
}

/*
 * EATT bearer helpers (Core Spec Vol 3 Part G Section 5.3): least-loaded
 * bearer selection, open-with-all-connect-failing, and teardown.  These are
 * driven directly (no live L2CAP transport) with the bearer array populated
 * by hand; the connect path uses the test's ble_coc_connect stub which
 * always fails, exercising the "bearer connect failed" trace and the
 * clamp-to-max arm.
 */
ATF_TC_WITHOUT_HEAD(eatt_helpers);
ATF_TC_BODY(eatt_helpers, tc)
{
	struct att_conn ac;
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	int sel;
	int fds[2];

	assert_att_client_wire_contract();
	signal(SIGPIPE, SIG_IGN);
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	ac.bearer_fd = -1;
	atomic_store(&blued_verbose, 2);

	/* Open with count > ATT_MAX_EATT_BEARERS: clamps, all connects fail
	 * (stub returns -1) -> zero bearers opened. */
	blued_daemonized = 0;
	ATF_CHECK_EQ(0, att_open_eatt(&ac, NULL, addr, 0, ATT_MAX_EATT_BEARERS + 5));
	blued_daemonized = 1;
	ATF_CHECK_EQ(0, att_open_eatt(&ac, NULL, addr, 0, 2));
	blued_daemonized = 0;

	/* Select only an idle bearer; ATT permits one outstanding request per
	 * bearer, so a bearer with pending != 0 must not be reused. */
	memset(&ac.eatt, 0, sizeof(ac.eatt));
	ac.eatt_count = 3;
	ac.eatt[0].active = false;		/* skipped: inactive */
	ac.eatt[0].fd = 10;
	ac.eatt[1].active = true;  ac.eatt[1].fd = 11; ac.eatt[1].pending = 2;
	ac.eatt[2].active = true;  ac.eatt[2].fd = 12; ac.eatt[2].pending = 1;
	sel = att_eatt_select_bearer(&ac);	/* both EATT bearers are busy */
	ATF_CHECK_EQ(-1, sel);
	ATF_CHECK_EQ(EBUSY, errno);
	ATF_CHECK_EQ(1, ac.eatt[2].pending);

	ac.eatt[2].pending = 0;
	sel = att_eatt_select_bearer(&ac);	/* idle bearer == fd 12 */
	ATF_CHECK_EQ(12, sel);
	ATF_CHECK_EQ(1, ac.eatt[2].pending);	/* selection reserved bearer */

	/* fd < 0 skip arm + no active bearer -> primary fallback. */
	ac.eatt[1].active = false;
	ac.eatt[2].active = false;
	ac.eatt[0].active = true; ac.eatt[0].fd = -1;	/* active but fd<0 */
	ac.fd = 99;
	ATF_CHECK_EQ(99, att_eatt_select_bearer(&ac));	/* fallback to primary */

	/* att_eatt_accept: max-bearers-reached rejection (no accept issued). */
	memset(&ac.eatt, 0, sizeof(ac.eatt));
	ac.eatt_count = ATT_MAX_EATT_BEARERS;
	ATF_CHECK_EQ(-1, att_eatt_accept(&ac, -1));
	ATF_CHECK_EQ(ENOSPC, errno);

	/* att_eatt_accept: accept4() failure on a bad listen fd. */
	ac.eatt_count = 0;
	ATF_CHECK_EQ(-1, att_eatt_accept(&ac, -1));

	/* att_eatt_accept: success via a fake CoC with an injected 64-byte MTU. */
	{
		struct sockaddr_un un;
		int lfd, cfd;

		lfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
		ATF_REQUIRE(lfd >= 0);
		memset(&un, 0, sizeof(un));
		un.sun_family = AF_UNIX;
		strlcpy(un.sun_path, "att_eatt_cov.sock", sizeof(un.sun_path));
		(void)unlink(un.sun_path);
		ATF_REQUIRE(bind(lfd, (struct sockaddr *)&un, sizeof(un)) == 0);
		ATF_REQUIRE(listen(lfd, 1) == 0);
		cfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
		ATF_REQUIRE(cfd >= 0);
		ATF_REQUIRE(connect(cfd, (struct sockaddr *)&un,
		    sizeof(un)) == 0);
		ac.eatt_count = 0;
		ATF_CHECK_EQ(0, att_eatt_accept(&ac, lfd));
		ATF_CHECK_EQ(1, ac.eatt_count);
		ATF_CHECK_EQ(ATT_EATT_MIN_MTU, ac.eatt[0].mtu);
		close(cfd);
		close(lfd);
		(void)unlink(un.sun_path);
	}

	/* Teardown closes any real bearer fds. */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(&ac.eatt, 0, sizeof(ac.eatt));
	ac.eatt_count = 1;
	ac.eatt[0].active = true;
	ac.eatt[0].fd = fds[0];
	ac.fd = -1;
	ac.buf = NULL;
	att_close_eatt(&ac);
	ATF_CHECK_EQ(0, ac.eatt_count);
	close(fds[1]);

	atomic_store(&blued_verbose, 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, client_battery_stderr);
	ATF_TP_ADD_TC(tp, client_battery_syslog);
	ATF_TP_ADD_TC(tp, eatt_helpers);

	return (atf_no_error());
}
