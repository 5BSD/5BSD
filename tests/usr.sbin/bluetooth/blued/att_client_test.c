/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the ATT *client* senders in att.c.
 *
 * blued acts as a GATT central issuing ATT requests to an untrusted
 * peripheral.  Each sender in att.c builds a request PDU, transmits it,
 * waits for the matching response (skipping unsolicited notifications and
 * confirming indications along the way), and parses the reply.  These
 * tests exercise that request/response machinery — including every ATT
 * error-code path, truncated / wrong-opcode / oversized responses,
 * MTU-boundary handling, multi-PDU interleaving, and the EATT bearer
 * selection logic — by scripting a peer over a SOCK_SEQPACKET socketpair
 * standing in for the L2CAP ATT channel (CID 0x0004).
 *
 * Mechanics: the daemon-side fd is O_NONBLOCK, so a recv() with nothing
 * left queued returns EAGAIN and the sender unwinds rather than blocking.
 * Response datagrams are preloaded with MSG_EOR, which this platform
 * preserves as distinct SEQPACKET boundaries (queued sends WITHOUT MSG_EOR
 * coalesce here, so MSG_EOR is used throughout to deliver multiple PDUs).
 *
 * ORACLE: every expected byte / return value is hand-derived from the
 * Bluetooth Core Specification v6.x, Vol 3 Part F (ATT), with a section
 * citation per assertion group.  No expected value is captured from the
 * implementation's own output.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Provide a custom ble_coc_connect so the EATT tests can open real
 * (socketpair-backed) bearers.  Must be defined before test_common.h,
 * which otherwise supplies a stub that always fails.
 */
#define TEST_CUSTOM_BLE_COC_CONNECT
#define TEST_CUSTOM_BLE_ECBFC_CONNECT

#include "att.h"
#include "att_server.h"
#include "spec_oracles.h"

/* Independent protocol values generated from Core 6.3 and Assigned Numbers. */
#define ATTCL_ENUM(name, value) ATTCL_##name = value,
enum {
	BT_CORE63_ATT_ORACLES(ATTCL_ENUM)
	BT_CORE63_ATT_ERROR_ORACLES(ATTCL_ENUM)
	BT_CORE63_L2CAP_CID_ORACLES(ATTCL_ENUM)
	BT_ASSIGNED_EATT_PSM_ORACLES(ATTCL_ENUM)
};
#undef ATTCL_ENUM

enum {
	ATTCL_HANDLE_MIN = 0x0001,
	ATTCL_HANDLE_MAX = 0xffff,
	ATTCL_FIXTURE_HANDLE_3 = 0x0003,
	ATTCL_FIXTURE_HANDLE_4 = 0x0004,
	ATTCL_FIXTURE_HANDLE_6 = 0x0006,
	ATTCL_FIXTURE_HANDLE_7 = 0x0007,
	ATTCL_FIXTURE_HANDLE_9 = 0x0009,
	ATTCL_FIXTURE_NOTIFY_HANDLE = 0x0010,
	ATTCL_FIXTURE_INDICATE_HANDLE = 0x0020,
	ATTCL_FIXTURE_WRONG_HANDLE = 0x0099,
	ATTCL_FIXTURE_FAR_HANDLE = 0xf000,
	ATTCL_FIXTURE_VENDOR_TYPE = 0x1234,
	/* Local request-loop hardening limit; not a Core-mandated value. */
	ATTCL_LOCAL_UNSOLICITED_LIMIT = 16,
	/* Local buffer-sized fixture used to exercise the heap allocation path. */
	ATTCL_LOCAL_INLINE_PDU_CAPACITY = 517,
};

int att_test_eatt_mtu(int, uint16_t *, uint16_t *);
int
att_test_eatt_mtu(int fd __unused, uint16_t *imtu, uint16_t *omtu)
{

	*imtu = *omtu = BT_CORE63_EATT_MIN_MTU;
	return (0);
}
#include "ble_util.h"
#include "hci_log.h"
#include "hci_util.h"

/* ---- custom CoC connector: hands back socketpair-backed EATT bearers ---- */
int	ble_coc_connect(const uint8_t *, const uint8_t *, uint8_t, uint16_t,
	    uint16_t);

static int g_coc_fail_after = 1000;	/* fail the Nth (0-based) connect */
static int g_coc_calls;
static int g_coc_peer[ATT_MAX_EATT_BEARERS];	/* peer ends of bearers */
static int g_coc_npeer;

static void
coc_reset(void)
{

	g_coc_fail_after = 1000;
	g_coc_calls = 0;
	for (int i = 0; i < g_coc_npeer; i++)
		if (g_coc_peer[i] >= 0)
			close(g_coc_peer[i]);
	g_coc_npeer = 0;
}

int
ble_coc_connect(const uint8_t *local_addr __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused,
    uint16_t psm __unused, uint16_t mtu __unused)
{
	int fds[2];

	if (g_coc_calls++ >= g_coc_fail_after) {
		errno = ECONNREFUSED;
		return (-1);
	}
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) < 0)
		return (-1);
	(void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
	g_coc_peer[g_coc_npeer++] = fds[1];
	return (fds[0]);
}

int
ble_ecbfc_connect(const uint8_t *local_addr __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused,
    uint16_t psm, uint16_t mtu __unused, int count, int *out)
{
	int i;

	ATF_CHECK_EQ(psm, ATTCL_NG_L2CAP_PSM_EATT);
	for (i = 0; i < count; i++) {
		out[i] = ble_coc_connect(NULL, NULL, 0, psm, 0);
		if (out[i] < 0)
			break;
	}
	return (i);
}

#include "test_common.h"

/* ================================================================
 * Mock helper: att_conn on a nonblocking socketpair.
 * ================================================================ */

static void
cl_pair(struct att_conn *ac, int *peer_fd)
{
	int fds[2];

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	ATF_REQUIRE(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	memset(ac, 0, sizeof(*ac));
	ac->fd = fds[0];
	ac->bearer_fd = -1;
	ac->mtu = ATTCL_LOCAL_INLINE_PDU_CAPACITY;
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	for (int i = 0; i < ATT_MAX_EATT_BEARERS; i++)
		ac->eatt[i].fd = -1;
	*peer_fd = fds[1];
}

static void
cl_cleanup(struct att_conn *ac, int peer_fd)
{

	att_close_eatt(ac);
	free(ac->buf);
	ac->buf = NULL;
	if (ac->fd >= 0)
		close(ac->fd);
	if (peer_fd >= 0)
		close(peer_fd);
	coc_reset();
}

/* Preload one response datagram (MSG_EOR keeps SEQPACKET boundaries). */
static void
cl_preload(int peer_fd, const uint8_t *pdu, size_t len)
{

	ATF_REQUIRE(send(peer_fd, pdu, len, MSG_EOR) == (ssize_t)len);
}

/* Build a 5-byte ATT Error Response (Core Spec Vol 3 Part F 3.4.1.1). */
static void
mk_error(uint8_t *out, uint8_t req_op, uint16_t handle, uint8_t code)
{

	out[0] = ATTCL_ATT_OP_ERROR_RSP;
	out[1] = req_op;
	put_le16(out + 2, handle);
	out[4] = code;
}

/* ================================================================
 * Exchange MTU (Core Spec Vol 3 Part F 3.4.2)
 * Effective ATT_MTU = min(client Rx MTU, server Rx MTU), floor 23.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_mtu_server_smaller);
ATF_TC_BODY(test_cl_mtu_server_smaller, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[3];

	cl_pair(&ac, &peer);

	/* Server advertises 100; client asks 200 -> effective 100. */
	rsp[0] = ATTCL_ATT_OP_MTU_RSP;
	put_le16(rsp + 1, 100);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_exchange_mtu(&ac, 200);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ_MSG(ac.mtu, 100, "effective MTU must be min(200,100)=100");
	ATF_CHECK(ac.mtu_exchanged);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_mtu_client_smaller);
ATF_TC_BODY(test_cl_mtu_client_smaller, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[3];

	cl_pair(&ac, &peer);

	/* Server advertises 500; client asks 250 -> effective 250. */
	rsp[0] = ATTCL_ATT_OP_MTU_RSP;
	put_le16(rsp + 1, 500);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_exchange_mtu(&ac, 250);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ_MSG(ac.mtu, 250, "effective MTU must be min(250,500)=250");

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_mtu_client_floor);
ATF_TC_BODY(test_cl_mtu_client_floor, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[3], req[3];

	cl_pair(&ac, &peer);

	/*
	 * Client requests below the 23-octet default; sender must floor
	 * the advertised client Rx MTU to 23 (Core Spec Vol 3 Part F
	 * 3.4.2.1 — ATT_MTU is at least the default 23).
	 */
	rsp[0] = ATTCL_ATT_OP_MTU_RSP;
	put_le16(rsp + 1, 512);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_exchange_mtu(&ac, 5);
	ATF_CHECK_EQ(ret, 0);
	/* effective = min(23, 512) = 23 */
	ATF_CHECK_EQ_MSG(ac.mtu, BT_CORE63_ATT_DEFAULT_MTU,
	    "sub-default client MTU must be floored to 23");

	/* The transmitted MTU_REQ must have carried 23, not 5. */
	ATF_REQUIRE(recv(peer, req, sizeof(req), MSG_DONTWAIT) == 3);
	ATF_CHECK_EQ(req[0], ATTCL_ATT_OP_MTU_REQ);
	ATF_CHECK_EQ_MSG(get_le16(req + 1), BT_CORE63_ATT_DEFAULT_MTU,
	    "client Rx MTU field must be floored to 23");

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_mtu_already);
ATF_TC_BODY(test_cl_mtu_already, tc)
{
	struct att_conn ac;
	int peer, ret;

	cl_pair(&ac, &peer);
	ac.mtu_exchanged = true;

	/* Only one MTU exchange per bearer (Core Spec Vol 3 Part F 3.4.2). */
	ret = att_exchange_mtu(&ac, 200);
	ATF_CHECK_EQ_MSG(ret, -1, "second MTU exchange must be refused");
	ATF_CHECK_EQ(errno, EALREADY);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_mtu_wrong_opcode);
ATF_TC_BODY(test_cl_mtu_wrong_opcode, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[3];

	cl_pair(&ac, &peer);

	/* A non-MTU_RSP opcode is a protocol violation -> failure. */
	rsp[0] = ATTCL_ATT_OP_READ_RSP;
	put_le16(rsp + 1, 100);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_exchange_mtu(&ac, 200);
	ATF_CHECK_EQ_MSG(ret, -1, "wrong response opcode must fail");
	ATF_CHECK(!ac.mtu_exchanged);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_mtu_error_rsp);
ATF_TC_BODY(test_cl_mtu_error_rsp, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5];

	cl_pair(&ac, &peer);

	/* Server rejects MTU_REQ with REQUEST_NOT_SUPPORTED (3.4.1.1). */
	mk_error(rsp, ATTCL_ATT_OP_MTU_REQ, 0x0000, ATTCL_ATT_ERR_REQ_NOT_SUPPORTED);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_exchange_mtu(&ac, 200);
	ATF_CHECK_EQ_MSG(ret, -1, "error response must fail the exchange");

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * att_request internal machinery, driven via att_exchange_mtu
 * (which returns a clean -1 on any transport failure).
 * ================================================================ */

/* A Handle Value Notification before the response is skipped (3.4.7.1). */
ATF_TC_WITHOUT_HEAD(test_cl_skip_notification);
ATF_TC_BODY(test_cl_skip_notification, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t ntf[5], rsp[3];

	cl_pair(&ac, &peer);

	ntf[0] = ATTCL_ATT_OP_HANDLE_NOTIFY;
	put_le16(ntf + 1, ATTCL_FIXTURE_NOTIFY_HANDLE);
	ntf[3] = 0xAB; ntf[4] = 0xCD;
	cl_preload(peer, ntf, sizeof(ntf));

	rsp[0] = ATTCL_ATT_OP_MTU_RSP;
	put_le16(rsp + 1, 200);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_exchange_mtu(&ac, 200);
	ATF_CHECK_EQ_MSG(ret, 0, "notification before response must be skipped");
	ATF_CHECK_EQ(ac.mtu, 200);

	cl_cleanup(&ac, peer);
}

/* An indication is confirmed and skipped (Core Spec Vol 3 Part F 3.4.7.2). */
ATF_TC_WITHOUT_HEAD(test_cl_skip_indication);
ATF_TC_BODY(test_cl_skip_indication, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t ind[5], rsp[3];

	cl_pair(&ac, &peer);

	ind[0] = ATTCL_ATT_OP_HANDLE_IND;
	put_le16(ind + 1, ATTCL_FIXTURE_INDICATE_HANDLE);
	ind[3] = 0x11; ind[4] = 0x22;
	cl_preload(peer, ind, sizeof(ind));

	rsp[0] = ATTCL_ATT_OP_MTU_RSP;
	put_le16(rsp + 1, 150);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_exchange_mtu(&ac, 200);
	ATF_CHECK_EQ_MSG(ret, 0, "indication must be confirmed then skipped");
	ATF_CHECK_EQ(ac.mtu, 150);

	/* The client must have transmitted a Handle Value Confirmation. */
	{
		uint8_t seen_cfm = 0;
		ssize_t n;
		uint8_t b[8];

		while ((n = recv(peer, b, sizeof(b), MSG_DONTWAIT)) > 0) {
			if (b[0] == ATTCL_ATT_OP_HANDLE_CFM)
				seen_cfm = 1;
		}
		ATF_CHECK_MSG(seen_cfm,
		    "client must send Handle Value Confirmation (0x1E)");
	}

	cl_cleanup(&ac, peer);
}

/* A flood of notifications must terminate the wait (bounded skip). */
ATF_TC_WITHOUT_HEAD(test_cl_too_many_unsolicited);
ATF_TC_BODY(test_cl_too_many_unsolicited, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t ntf[5];

	cl_pair(&ac, &peer);

	ntf[0] = ATTCL_ATT_OP_HANDLE_NOTIFY;
	put_le16(ntf + 1, ATTCL_FIXTURE_NOTIFY_HANDLE);
	ntf[3] = 0; ntf[4] = 0;
	/* The local bounded-skip limit is isolated from Core wire semantics. */
	for (int i = 0; i < ATTCL_LOCAL_UNSOLICITED_LIMIT; i++)
		cl_preload(peer, ntf, sizeof(ntf));

	ret = att_exchange_mtu(&ac, 200);
	ATF_CHECK_EQ_MSG(ret, -1,
	    "an unsolicited-PDU flood must abort the request");

	cl_cleanup(&ac, peer);
}

/* Peer closing the channel is reported as a failure (not a hang). */
ATF_TC_WITHOUT_HEAD(test_cl_conn_closed);
ATF_TC_BODY(test_cl_conn_closed, tc)
{
	struct att_conn ac;
	int peer, ret;

	cl_pair(&ac, &peer);
	close(peer);
	peer = -1;

	ret = att_exchange_mtu(&ac, 200);
	ATF_CHECK_EQ_MSG(ret, -1, "closed channel must fail the request");

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Read Request (Core Spec Vol 3 Part F 3.4.4.3)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_read_ok);
ATF_TC_BODY(test_cl_read_ok, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5], out[16];
	size_t outlen = 99;

	cl_pair(&ac, &peer);

	rsp[0] = ATTCL_ATT_OP_READ_RSP;
	rsp[1] = 0xDE; rsp[2] = 0xAD; rsp[3] = 0xBE; rsp[4] = 0xEF;
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read(&ac, ATTCL_FIXTURE_HANDLE_3, out, sizeof(out), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ_MSG(outlen, 4, "Read Response value is PDU length - 1");
	ATF_CHECK_EQ(memcmp(out, "\xDE\xAD\xBE\xEF", 4), 0);

	/* The transmitted request must be READ_REQ(handle). */
	{
		uint8_t req[8];
		ATF_REQUIRE(recv(peer, req, sizeof(req), MSG_DONTWAIT) == 3);
		ATF_CHECK_EQ(req[0], ATTCL_ATT_OP_READ_REQ);
		ATF_CHECK_EQ(get_le16(req + 1), ATTCL_FIXTURE_HANDLE_3);
	}

	cl_cleanup(&ac, peer);
}

/* Oversized value is truncated to the caller's buffer, never over-run. */
ATF_TC_WITHOUT_HEAD(test_cl_read_truncate_to_buf);
ATF_TC_BODY(test_cl_read_truncate_to_buf, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[11], out[4];
	size_t outlen = 0;

	cl_pair(&ac, &peer);

	rsp[0] = ATTCL_ATT_OP_READ_RSP;
	memset(rsp + 1, 0x5A, 10);		/* 10-byte value */
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read(&ac, ATTCL_FIXTURE_HANDLE_3, out, sizeof(out), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ_MSG(outlen, 4, "value must be clamped to caller buflen");

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_read_err_not_permitted);
ATF_TC_BODY(test_cl_read_err_not_permitted, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5], out[8];

	cl_pair(&ac, &peer);

	mk_error(rsp, ATTCL_ATT_OP_READ_REQ, ATTCL_FIXTURE_HANDLE_3, ATTCL_ATT_ERR_READ_NOT_PERMITTED);
	cl_preload(peer, rsp, sizeof(rsp));

	/* On an ATT error response the sender surfaces the error code. */
	ret = att_read(&ac, ATTCL_FIXTURE_HANDLE_3, out, sizeof(out), NULL);
	ATF_CHECK_EQ_MSG(ret, ATTCL_ATT_ERR_READ_NOT_PERMITTED,
	    "Read Not Permitted (0x02) must be reported");

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_read_wrong_opcode);
ATF_TC_BODY(test_cl_read_wrong_opcode, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[3], out[8];

	cl_pair(&ac, &peer);

	/* A Write Response to a Read Request is a protocol violation. */
	rsp[0] = ATTCL_ATT_OP_WRITE_RSP;
	rsp[1] = 0; rsp[2] = 0;
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read(&ac, ATTCL_FIXTURE_HANDLE_3, out, sizeof(out), NULL);
	ATF_CHECK_EQ_MSG(ret, -1, "mismatched response opcode must fail");

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Read Blob Request (Core Spec Vol 3 Part F 3.4.4.5)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_read_blob_ok);
ATF_TC_BODY(test_cl_read_blob_ok, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[6], out[16];
	size_t outlen = 0;

	cl_pair(&ac, &peer);

	rsp[0] = ATTCL_ATT_OP_READ_BLOB_RSP;
	memcpy(rsp + 1, "\x01\x02\x03\x04\x05", 5);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_blob(&ac, ATTCL_FIXTURE_HANDLE_6, 3, out, sizeof(out), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(outlen, 5);
	ATF_CHECK_EQ(memcmp(out, "\x01\x02\x03\x04\x05", 5), 0);

	/* Request layout: opcode + handle + offset. */
	{
		uint8_t req[8];
		ATF_REQUIRE(recv(peer, req, sizeof(req), MSG_DONTWAIT) == 5);
		ATF_CHECK_EQ(req[0], ATTCL_ATT_OP_READ_BLOB_REQ);
		ATF_CHECK_EQ(get_le16(req + 1), ATTCL_FIXTURE_HANDLE_6);
		ATF_CHECK_EQ(get_le16(req + 3), 3);
	}

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_read_blob_err);
ATF_TC_BODY(test_cl_read_blob_err, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5], out[8];

	cl_pair(&ac, &peer);

	/* Reading beyond a short value -> Invalid Offset (0x07). */
	mk_error(rsp, ATTCL_ATT_OP_READ_BLOB_REQ, ATTCL_FIXTURE_HANDLE_6, ATTCL_ATT_ERR_INVALID_OFFSET);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_blob(&ac, ATTCL_FIXTURE_HANDLE_6, 99, out, sizeof(out), NULL);
	ATF_CHECK_EQ(ret, ATTCL_ATT_ERR_INVALID_OFFSET);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_read_blob_wrong_opcode);
ATF_TC_BODY(test_cl_read_blob_wrong_opcode, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[3], out[8];

	cl_pair(&ac, &peer);
	rsp[0] = ATTCL_ATT_OP_READ_RSP;	/* not READ_BLOB_RSP */
	rsp[1] = 0; rsp[2] = 0;
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_blob(&ac, ATTCL_FIXTURE_HANDLE_6, 0, out, sizeof(out), NULL);
	ATF_CHECK_EQ(ret, -1);

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Write Request (Core Spec Vol 3 Part F 3.4.5.1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_write_req_ok);
ATF_TC_BODY(test_cl_write_req_ok, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[1];

	cl_pair(&ac, &peer);

	rsp[0] = ATTCL_ATT_OP_WRITE_RSP;
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_write_req(&ac, ATTCL_FIXTURE_HANDLE_6, "\xAA\xBB\xCC\xDD", 4);
	ATF_CHECK_EQ(ret, 0);

	/* Request must be WRITE_REQ(handle, value). */
	{
		uint8_t req[16];
		ssize_t n = recv(peer, req, sizeof(req), MSG_DONTWAIT);
		ATF_REQUIRE(n == 7);
		ATF_CHECK_EQ(req[0], ATTCL_ATT_OP_WRITE_REQ);
		ATF_CHECK_EQ(get_le16(req + 1), ATTCL_FIXTURE_HANDLE_6);
		ATF_CHECK_EQ(memcmp(req + 3, "\xAA\xBB\xCC\xDD", 4), 0);
	}

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_write_req_err);
ATF_TC_BODY(test_cl_write_req_err, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5];

	cl_pair(&ac, &peer);

	mk_error(rsp, ATTCL_ATT_OP_WRITE_REQ, ATTCL_FIXTURE_HANDLE_3, ATTCL_ATT_ERR_WRITE_NOT_PERMITTED);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_write_req(&ac, ATTCL_FIXTURE_HANDLE_3, "\x00", 1);
	ATF_CHECK_EQ(ret, ATTCL_ATT_ERR_WRITE_NOT_PERMITTED);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_write_req_too_big);
ATF_TC_BODY(test_cl_write_req_too_big, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t data[64];

	cl_pair(&ac, &peer);
	ac.mtu = BT_CORE63_ATT_DEFAULT_MTU;		/* 23 -> max write value 20 */
	memset(data, 0x7F, sizeof(data));

	/* 3 + 40 > 23: must be rejected locally with EMSGSIZE. */
	ret = att_write_req(&ac, ATTCL_FIXTURE_HANDLE_6, data, 40);
	ATF_CHECK_EQ_MSG(ret, -1, "over-MTU write must be refused");
	ATF_CHECK_EQ(errno, EMSGSIZE);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_write_req_wrong_opcode);
ATF_TC_BODY(test_cl_write_req_wrong_opcode, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[2];

	cl_pair(&ac, &peer);
	rsp[0] = ATTCL_ATT_OP_READ_RSP;	/* not WRITE_RSP */
	rsp[1] = 0;
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_write_req(&ac, ATTCL_FIXTURE_HANDLE_6, "\x01", 1);
	ATF_CHECK_EQ(ret, -1);

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Write Command (Core Spec Vol 3 Part F 3.4.5.3) — no response
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_write_cmd_ok);
ATF_TC_BODY(test_cl_write_cmd_ok, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t req[16];
	ssize_t n;

	cl_pair(&ac, &peer);

	ret = att_write_cmd(&ac, ATTCL_FIXTURE_HANDLE_6, "\x01\x02\x03", 3);
	ATF_CHECK_EQ(ret, 0);

	n = recv(peer, req, sizeof(req), MSG_DONTWAIT);
	ATF_REQUIRE(n == 6);
	ATF_CHECK_EQ(req[0], ATTCL_ATT_OP_WRITE_CMD);
	ATF_CHECK_EQ(get_le16(req + 1), ATTCL_FIXTURE_HANDLE_6);
	ATF_CHECK_EQ(memcmp(req + 3, "\x01\x02\x03", 3), 0);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_write_cmd_too_big);
ATF_TC_BODY(test_cl_write_cmd_too_big, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t data[64];

	cl_pair(&ac, &peer);
	ac.mtu = BT_CORE63_ATT_DEFAULT_MTU;
	memset(data, 0x22, sizeof(data));

	ret = att_write_cmd(&ac, ATTCL_FIXTURE_HANDLE_6, data, 40);
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);

	cl_cleanup(&ac, peer);
}

/* Large-MTU command uses the heap PDU path (pdulen > ATT_PDU_BUF_SIZE). */
ATF_TC_WITHOUT_HEAD(test_cl_write_cmd_heap);
ATF_TC_BODY(test_cl_write_cmd_heap, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t data[600];
	uint8_t req[700];

	cl_pair(&ac, &peer);
	ac.mtu = 640;			/* > ATT_PDU_BUF_SIZE (517) */
	memset(data, 0x33, sizeof(data));

	ret = att_write_cmd(&ac, ATTCL_FIXTURE_HANDLE_6, data, sizeof(data));
	ATF_CHECK_EQ(ret, 0);

	ATF_REQUIRE(recv(peer, req, sizeof(req), MSG_DONTWAIT) ==
	    3 + (ssize_t)sizeof(data));
	ATF_CHECK_EQ(req[0], ATTCL_ATT_OP_WRITE_CMD);

	cl_cleanup(&ac, peer);
}

/* Send failure surfaces as -1 (channel torn down under the sender). */
ATF_TC_WITHOUT_HEAD(test_cl_write_cmd_send_fail);
ATF_TC_BODY(test_cl_write_cmd_send_fail, tc)
{
	struct att_conn ac;
	int peer, ret;

	cl_pair(&ac, &peer);
	close(ac.fd);
	ac.fd = -1;			/* send() -> EBADF */

	ret = att_write_cmd(&ac, ATTCL_FIXTURE_HANDLE_6, "\x01", 1);
	ATF_CHECK_EQ_MSG(ret, -1, "send on a dead fd must fail");

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Find By Type Value (Core Spec Vol 3 Part F 3.4.3.3)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_find_by_type_value_ok);
ATF_TC_BODY(test_cl_find_by_type_value_ok, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[1 + 4], out[32];
	size_t outlen = 0;

	cl_pair(&ac, &peer);

	rsp[0] = ATTCL_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
	put_le16(rsp + 1, ATTCL_FIXTURE_HANDLE_4);	/* found handle */
	put_le16(rsp + 3, ATTCL_FIXTURE_HANDLE_7);	/* group end handle */
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_find_by_type_value(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX,
	    BT_ASSIGNED_UUID_PRIMARY_SERVICE, "\xE0\xFF", 2, out, sizeof(out), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(outlen, 4);
	ATF_CHECK_EQ(get_le16(out), ATTCL_FIXTURE_HANDLE_4);
	ATF_CHECK_EQ(get_le16(out + 2), ATTCL_FIXTURE_HANDLE_7);

	cl_cleanup(&ac, peer);
}

/* ATTR_NOT_FOUND is the normal end-of-search: success with zero output. */
ATF_TC_WITHOUT_HEAD(test_cl_find_by_type_value_notfound);
ATF_TC_BODY(test_cl_find_by_type_value_notfound, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5], out[32];
	size_t outlen = 99;

	cl_pair(&ac, &peer);

	mk_error(rsp, ATTCL_ATT_OP_FIND_BY_TYPE_VALUE_REQ, ATTCL_HANDLE_MIN,
	    ATTCL_ATT_ERR_ATTR_NOT_FOUND);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_find_by_type_value(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX, BT_ASSIGNED_UUID_PRIMARY_SERVICE,
	    "\xE0\xFF", 2, out, sizeof(out), &outlen);
	ATF_CHECK_EQ_MSG(ret, 0, "ATTR_NOT_FOUND ends the search cleanly");
	ATF_CHECK_EQ(outlen, 0);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_find_by_type_value_other_err);
ATF_TC_BODY(test_cl_find_by_type_value_other_err, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5], out[32];

	cl_pair(&ac, &peer);

	mk_error(rsp, ATTCL_ATT_OP_FIND_BY_TYPE_VALUE_REQ, ATTCL_HANDLE_MIN,
	    ATTCL_ATT_ERR_INVALID_HANDLE);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_find_by_type_value(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX, BT_ASSIGNED_UUID_PRIMARY_SERVICE,
	    "\xE0\xFF", 2, out, sizeof(out), NULL);
	ATF_CHECK_EQ_MSG(ret, ATTCL_ATT_ERR_INVALID_HANDLE,
	    "a non-ATTR_NOT_FOUND error is surfaced");

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_find_by_type_value_too_big);
ATF_TC_BODY(test_cl_find_by_type_value_too_big, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t out[8], val[64];

	cl_pair(&ac, &peer);
	ac.mtu = BT_CORE63_ATT_DEFAULT_MTU;
	memset(val, 0, sizeof(val));

	/* 7 + 40 > 23 -> EMSGSIZE. */
	ret = att_find_by_type_value(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX, BT_ASSIGNED_UUID_PRIMARY_SERVICE,
	    val, 40, out, sizeof(out), NULL);
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Read Multiple (Core Spec Vol 3 Part F 3.4.4.7)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_read_multiple_ok);
ATF_TC_BODY(test_cl_read_multiple_ok, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[1 + 6], out[32], req[16];
	size_t outlen = 0;
	uint16_t handles[3] = { ATTCL_FIXTURE_HANDLE_3, ATTCL_FIXTURE_HANDLE_6, ATTCL_FIXTURE_HANDLE_9 };

	cl_pair(&ac, &peer);

	rsp[0] = ATTCL_ATT_OP_READ_MULTIPLE_RSP;
	memcpy(rsp + 1, "\xAA\xBB\xCC\xDD\xEE\xFF", 6);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_multiple(&ac, handles, 3, out, sizeof(out), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(outlen, 6);

	/* Request: opcode + three little-endian handles. */
	ATF_REQUIRE(recv(peer, req, sizeof(req), MSG_DONTWAIT) == 7);
	ATF_CHECK_EQ(req[0], ATTCL_ATT_OP_READ_MULTIPLE_REQ);
	ATF_CHECK_EQ(get_le16(req + 1), ATTCL_FIXTURE_HANDLE_3);
	ATF_CHECK_EQ(get_le16(req + 3), ATTCL_FIXTURE_HANDLE_6);
	ATF_CHECK_EQ(get_le16(req + 5), ATTCL_FIXTURE_HANDLE_9);

	cl_cleanup(&ac, peer);
}

/* Fewer than two handles is invalid (3.4.4.7 requires "a set of two or more"). */
ATF_TC_WITHOUT_HEAD(test_cl_read_multiple_too_few);
ATF_TC_BODY(test_cl_read_multiple_too_few, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t out[8];
	uint16_t handles[1] = { ATTCL_FIXTURE_HANDLE_3 };

	cl_pair(&ac, &peer);

	ret = att_read_multiple(&ac, handles, 1, out, sizeof(out), NULL);
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ(errno, EINVAL);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_read_multiple_err);
ATF_TC_BODY(test_cl_read_multiple_err, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5], out[8];
	uint16_t handles[2] = { ATTCL_FIXTURE_HANDLE_3, ATTCL_FIXTURE_FAR_HANDLE };

	cl_pair(&ac, &peer);

	mk_error(rsp, ATTCL_ATT_OP_READ_MULTIPLE_REQ, ATTCL_FIXTURE_FAR_HANDLE,
	    ATTCL_ATT_ERR_INVALID_HANDLE);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_multiple(&ac, handles, 2, out, sizeof(out), NULL);
	ATF_CHECK_EQ(ret, ATTCL_ATT_ERR_INVALID_HANDLE);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_read_multiple_wrong_opcode);
ATF_TC_BODY(test_cl_read_multiple_wrong_opcode, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[3], out[8];
	uint16_t handles[2] = { ATTCL_FIXTURE_HANDLE_3, ATTCL_FIXTURE_HANDLE_6 };

	cl_pair(&ac, &peer);
	rsp[0] = ATTCL_ATT_OP_READ_RSP;
	rsp[1] = 0; rsp[2] = 0;
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_multiple(&ac, handles, 2, out, sizeof(out), NULL);
	ATF_CHECK_EQ(ret, -1);

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Read Multiple Variable (Core Spec Vol 3 Part F 3.4.4.11, BT 5.2+)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_read_multiple_var_ok);
ATF_TC_BODY(test_cl_read_multiple_var_ok, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[1 + 2 + 2 + 2 + 3], out[32], req[16];
	size_t outlen = 0;
	uint16_t handles[2] = { ATTCL_FIXTURE_HANDLE_3, ATTCL_FIXTURE_HANDLE_6 };

	cl_pair(&ac, &peer);

	/* Response: opcode || {len(2)||value}* */
	rsp[0] = ATTCL_ATT_OP_READ_MULTIPLE_VARIABLE_RSP;
	put_le16(rsp + 1, 2);
	rsp[3] = 0x11; rsp[4] = 0x22;
	put_le16(rsp + 5, 3);
	rsp[7] = 0x33; rsp[8] = 0x44; rsp[9] = 0x55;
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_multiple_variable(&ac, handles, 2, out, sizeof(out),
	    &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ_MSG(outlen, 9, "payload is two length-prefixed values");
	ATF_CHECK_EQ(get_le16(out), 2);

	ATF_REQUIRE(recv(peer, req, sizeof(req), MSG_DONTWAIT) == 5);
	ATF_CHECK_EQ(req[0], ATTCL_ATT_OP_READ_MULTIPLE_VARIABLE_REQ);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_read_multiple_var_too_few);
ATF_TC_BODY(test_cl_read_multiple_var_too_few, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t out[8];
	uint16_t handles[1] = { ATTCL_FIXTURE_HANDLE_3 };

	cl_pair(&ac, &peer);

	ret = att_read_multiple_variable(&ac, handles, 1, out, sizeof(out),
	    NULL);
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ(errno, EINVAL);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_read_multiple_var_err);
ATF_TC_BODY(test_cl_read_multiple_var_err, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5], out[8];
	uint16_t handles[2] = { ATTCL_FIXTURE_HANDLE_3, ATTCL_FIXTURE_HANDLE_6 };

	cl_pair(&ac, &peer);

	mk_error(rsp, ATTCL_ATT_OP_READ_MULTIPLE_VARIABLE_REQ, ATTCL_FIXTURE_HANDLE_6,
	    ATTCL_ATT_ERR_INSUFF_AUTHEN);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_multiple_variable(&ac, handles, 2, out, sizeof(out),
	    NULL);
	ATF_CHECK_EQ(ret, ATTCL_ATT_ERR_INSUFF_AUTHEN);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_read_multiple_var_wrong_opcode);
ATF_TC_BODY(test_cl_read_multiple_var_wrong_opcode, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[3], out[8];
	uint16_t handles[2] = { ATTCL_FIXTURE_HANDLE_3, ATTCL_FIXTURE_HANDLE_6 };

	cl_pair(&ac, &peer);
	rsp[0] = ATTCL_ATT_OP_READ_MULTIPLE_RSP;	/* not the _VARIABLE_ variant */
	rsp[1] = 0; rsp[2] = 0;
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_multiple_variable(&ac, handles, 2, out, sizeof(out),
	    NULL);
	ATF_CHECK_EQ(ret, -1);

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Find Information (Core Spec Vol 3 Part F 3.4.3.1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_find_info_ok);
ATF_TC_BODY(test_cl_find_info_ok, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[1 + 1 + 4], out[32];
	size_t outlen = 0;

	cl_pair(&ac, &peer);

	rsp[0] = ATTCL_ATT_OP_FIND_INFO_RSP;
	rsp[1] = BT_CORE63_ATT_FIND_INFO_FORMAT_UUID16;
	put_le16(rsp + 2, ATTCL_FIXTURE_HANDLE_7);
	put_le16(rsp + 4, BT_ASSIGNED_UUID_CCCD);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_find_info(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX, out, sizeof(out), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ_MSG(outlen, 5, "format byte + one 4-byte entry");
	ATF_CHECK_EQ(out[0], BT_CORE63_ATT_FIND_INFO_FORMAT_UUID16);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_find_info_notfound);
ATF_TC_BODY(test_cl_find_info_notfound, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5], out[32];
	size_t outlen = 99;

	cl_pair(&ac, &peer);

	mk_error(rsp, ATTCL_ATT_OP_FIND_INFO_REQ, ATTCL_HANDLE_MIN, ATTCL_ATT_ERR_ATTR_NOT_FOUND);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_find_info(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX, out, sizeof(out), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(outlen, 0);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_find_info_wrong_opcode);
ATF_TC_BODY(test_cl_find_info_wrong_opcode, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[2], out[32];

	cl_pair(&ac, &peer);
	rsp[0] = ATTCL_ATT_OP_READ_RSP;
	rsp[1] = 0;
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_find_info(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX, out, sizeof(out), NULL);
	ATF_CHECK_EQ(ret, -1);

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Read By Type (Core Spec Vol 3 Part F 3.4.4.1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_read_by_type_err);
ATF_TC_BODY(test_cl_read_by_type_err, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5], out[32];

	cl_pair(&ac, &peer);

	mk_error(rsp, ATTCL_ATT_OP_READ_BY_TYPE_REQ, ATTCL_HANDLE_MIN,
	    ATTCL_ATT_ERR_INSUFF_ENCRYPTION);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_by_type(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX, BT_ASSIGNED_UUID_CHARACTERISTIC, out, sizeof(out),
	    NULL);
	ATF_CHECK_EQ(ret, ATTCL_ATT_ERR_INSUFF_ENCRYPTION);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_read_by_type_wrong_opcode);
ATF_TC_BODY(test_cl_read_by_type_wrong_opcode, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[2], out[32];

	cl_pair(&ac, &peer);
	rsp[0] = ATTCL_ATT_OP_FIND_INFO_RSP;
	rsp[1] = 1;
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_by_type(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX, BT_ASSIGNED_UUID_CHARACTERISTIC, out, sizeof(out),
	    NULL);
	ATF_CHECK_EQ(ret, -1);

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Read By Type with a 128-bit UUID (Core Spec Vol 3 Part F 3.4.4.1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_read_by_type128_ok);
ATF_TC_BODY(test_cl_read_by_type128_ok, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[1 + 1 + 4], out[32], req[32];
	size_t outlen = 0;
	static const uint8_t uuid[16] = {
		0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09,
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
	};

	cl_pair(&ac, &peer);

	rsp[0] = ATTCL_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 4;			/* attr_data_len: handle(2)+value(2) */
	put_le16(rsp + 2, ATTCL_FIXTURE_NOTIFY_HANDLE);
	put_le16(rsp + 4, ATTCL_FIXTURE_VENDOR_TYPE);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_by_type_uuid128(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX, uuid, out,
	    sizeof(out), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(outlen, 5);

	/* Request is a 21-byte PDU: opcode + start + end + 16-byte UUID. */
	ATF_REQUIRE(recv(peer, req, sizeof(req), MSG_DONTWAIT) == 21);
	ATF_CHECK_EQ(req[0], ATTCL_ATT_OP_READ_BY_TYPE_REQ);
	ATF_CHECK_EQ(get_le16(req + 1), ATTCL_HANDLE_MIN);
	ATF_CHECK_EQ(get_le16(req + 3), ATTCL_HANDLE_MAX);
	ATF_CHECK_EQ(memcmp(req + 5, uuid, 16), 0);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_read_by_type128_notfound);
ATF_TC_BODY(test_cl_read_by_type128_notfound, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5], out[32];
	size_t outlen = 99;
	static const uint8_t uuid[16] = { 0 };

	cl_pair(&ac, &peer);

	mk_error(rsp, ATTCL_ATT_OP_READ_BY_TYPE_REQ, ATTCL_HANDLE_MIN, ATTCL_ATT_ERR_ATTR_NOT_FOUND);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_by_type_uuid128(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX, uuid, out,
	    sizeof(out), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(outlen, 0);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_read_by_type128_err);
ATF_TC_BODY(test_cl_read_by_type128_err, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5], out[32];
	static const uint8_t uuid[16] = { 0 };

	cl_pair(&ac, &peer);

	mk_error(rsp, ATTCL_ATT_OP_READ_BY_TYPE_REQ, ATTCL_HANDLE_MIN,
	    ATTCL_ATT_ERR_READ_NOT_PERMITTED);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_by_type_uuid128(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX, uuid, out,
	    sizeof(out), NULL);
	ATF_CHECK_EQ(ret, ATTCL_ATT_ERR_READ_NOT_PERMITTED);

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Read By Group Type (Core Spec Vol 3 Part F 3.4.4.9)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_read_by_group_wrong_opcode);
ATF_TC_BODY(test_cl_read_by_group_wrong_opcode, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[2], out[32];

	cl_pair(&ac, &peer);
	rsp[0] = ATTCL_ATT_OP_READ_BY_TYPE_RSP;	/* not GROUP_TYPE_RSP */
	rsp[1] = 6;
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_by_group_type(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX,
	    BT_ASSIGNED_UUID_PRIMARY_SERVICE, out, sizeof(out), NULL);
	ATF_CHECK_EQ(ret, -1);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_read_by_group_err);
ATF_TC_BODY(test_cl_read_by_group_err, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5], out[32];

	cl_pair(&ac, &peer);

	mk_error(rsp, ATTCL_ATT_OP_READ_BY_GROUP_TYPE_REQ, ATTCL_HANDLE_MIN,
	    ATTCL_ATT_ERR_UNSUPPORTED_GROUP_TYPE);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_read_by_group_type(&ac, ATTCL_HANDLE_MIN, ATTCL_HANDLE_MAX, ATTCL_FIXTURE_VENDOR_TYPE, out,
	    sizeof(out), NULL);
	ATF_CHECK_EQ(ret, ATTCL_ATT_ERR_UNSUPPORTED_GROUP_TYPE);

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Prepare / Execute Write (Core Spec Vol 3 Part F 3.4.6)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_prepare_write_ok);
ATF_TC_BODY(test_cl_prepare_write_ok, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5 + 4], req[16];

	cl_pair(&ac, &peer);

	/* Server echoes handle, offset AND value (3.4.6.1). */
	rsp[0] = ATTCL_ATT_OP_PREPARE_WRITE_RSP;
	put_le16(rsp + 1, ATTCL_FIXTURE_HANDLE_6);
	put_le16(rsp + 3, 2);
	memcpy(rsp + 5, "\xDE\xAD\xBE\xEF", 4);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_prepare_write(&ac, ATTCL_FIXTURE_HANDLE_6, 2, "\xDE\xAD\xBE\xEF", 4);
	ATF_CHECK_EQ(ret, 0);

	ATF_REQUIRE(recv(peer, req, sizeof(req), MSG_DONTWAIT) == 9);
	ATF_CHECK_EQ(req[0], ATTCL_ATT_OP_PREPARE_WRITE_REQ);
	ATF_CHECK_EQ(get_le16(req + 1), ATTCL_FIXTURE_HANDLE_6);
	ATF_CHECK_EQ(get_le16(req + 3), 2);

	cl_cleanup(&ac, peer);
}

/* A handle/offset echo mismatch is a protocol violation (3.4.6.1). */
ATF_TC_WITHOUT_HEAD(test_cl_prepare_write_echo_mismatch);
ATF_TC_BODY(test_cl_prepare_write_echo_mismatch, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5 + 4];

	cl_pair(&ac, &peer);

	rsp[0] = ATTCL_ATT_OP_PREPARE_WRITE_RSP;
	put_le16(rsp + 1, ATTCL_FIXTURE_WRONG_HANDLE);	/* wrong handle */
	put_le16(rsp + 3, 2);
	memcpy(rsp + 5, "\xDE\xAD\xBE\xEF", 4);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_prepare_write(&ac, ATTCL_FIXTURE_HANDLE_6, 2, "\xDE\xAD\xBE\xEF", 4);
	ATF_CHECK_EQ_MSG(ret, -1, "echoed handle mismatch must fail");

	cl_cleanup(&ac, peer);
}

/*
 * A value echo mismatch means the server corrupted the queued write; the
 * client cancels all prepared writes (Execute Write flags=0x00) and fails.
 */
ATF_TC_WITHOUT_HEAD(test_cl_prepare_write_value_mismatch);
ATF_TC_BODY(test_cl_prepare_write_value_mismatch, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5 + 4], ersp[1], seen[16];
	ssize_t n;
	uint8_t saw_cancel = 0;

	cl_pair(&ac, &peer);

	rsp[0] = ATTCL_ATT_OP_PREPARE_WRITE_RSP;
	put_le16(rsp + 1, ATTCL_FIXTURE_HANDLE_6);
	put_le16(rsp + 3, 2);
	memcpy(rsp + 5, "\x00\x00\x00\x00", 4);	/* value differs */
	cl_preload(peer, rsp, sizeof(rsp));

	/* The cancel that follows will itself await an Execute Write Rsp. */
	ersp[0] = ATTCL_ATT_OP_EXECUTE_WRITE_RSP;
	cl_preload(peer, ersp, sizeof(ersp));

	ret = att_prepare_write(&ac, ATTCL_FIXTURE_HANDLE_6, 2, "\xDE\xAD\xBE\xEF", 4);
	ATF_CHECK_EQ_MSG(ret, -1, "value echo mismatch must fail");

	/* The client must have issued a cancel (Execute Write, flags 0). */
	while ((n = recv(peer, seen, sizeof(seen), MSG_DONTWAIT)) > 0) {
		if (n >= 2 && seen[0] == ATTCL_ATT_OP_EXECUTE_WRITE_REQ &&
		    seen[1] == 0x00)
			saw_cancel = 1;
	}
	ATF_CHECK_MSG(saw_cancel, "value mismatch must trigger a cancel");

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_prepare_write_err);
ATF_TC_BODY(test_cl_prepare_write_err, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5];

	cl_pair(&ac, &peer);

	mk_error(rsp, ATTCL_ATT_OP_PREPARE_WRITE_REQ, ATTCL_FIXTURE_HANDLE_6,
	    ATTCL_ATT_ERR_PREPARE_QUEUE_FULL);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_prepare_write(&ac, ATTCL_FIXTURE_HANDLE_6, 0, "\x01", 1);
	ATF_CHECK_EQ(ret, ATTCL_ATT_ERR_PREPARE_QUEUE_FULL);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_prepare_write_too_big);
ATF_TC_BODY(test_cl_prepare_write_too_big, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t data[64];

	cl_pair(&ac, &peer);
	ac.mtu = BT_CORE63_ATT_DEFAULT_MTU;
	memset(data, 0, sizeof(data));

	/* 5 + 40 > 23 -> EMSGSIZE. */
	ret = att_prepare_write(&ac, ATTCL_FIXTURE_HANDLE_6, 0, data, 40);
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_execute_write_ok);
ATF_TC_BODY(test_cl_execute_write_ok, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[1], req[4];

	cl_pair(&ac, &peer);

	rsp[0] = ATTCL_ATT_OP_EXECUTE_WRITE_RSP;
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_execute_write(&ac, BT_CORE63_ATT_EXECUTE_COMMIT);
	ATF_CHECK_EQ(ret, 0);

	ATF_REQUIRE(recv(peer, req, sizeof(req), MSG_DONTWAIT) == 2);
	ATF_CHECK_EQ(req[0], ATTCL_ATT_OP_EXECUTE_WRITE_REQ);
	ATF_CHECK_EQ_MSG(req[1], BT_CORE63_ATT_EXECUTE_COMMIT,
	    "Core 6.3 Table 3.35: write all pending prepared values");

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_execute_write_wrong_opcode);
ATF_TC_BODY(test_cl_execute_write_wrong_opcode, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[1];

	cl_pair(&ac, &peer);
	rsp[0] = ATTCL_ATT_OP_WRITE_RSP;	/* not EXECUTE_WRITE_RSP */
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_execute_write(&ac, BT_CORE63_ATT_EXECUTE_CANCEL);
	ATF_CHECK_EQ(ret, -1);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_execute_write_err);
ATF_TC_BODY(test_cl_execute_write_err, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t rsp[5];

	cl_pair(&ac, &peer);

	mk_error(rsp, ATTCL_ATT_OP_EXECUTE_WRITE_REQ, ATTCL_FIXTURE_HANDLE_6,
	    ATTCL_ATT_ERR_INVALID_OFFSET);
	cl_preload(peer, rsp, sizeof(rsp));

	ret = att_execute_write(&ac, BT_CORE63_ATT_EXECUTE_COMMIT);
	ATF_CHECK_EQ(ret, ATTCL_ATT_ERR_INVALID_OFFSET);

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Write Long (convenience wrapper — Core Spec Vol 3 Part F 3.4.6)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_write_long_two_chunks);
ATF_TC_BODY(test_cl_write_long_two_chunks, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t data[30];
	uint8_t pr1[5 + 18], pr2[5 + 12], er[1];

	cl_pair(&ac, &peer);
	ac.mtu = BT_CORE63_ATT_DEFAULT_MTU;		/* chunkmax = 23 - 5 = 18 */
	for (int i = 0; i < 30; i++)
		data[i] = (uint8_t)i;

	/* First prepare: offset 0, 18 bytes; echoed back verbatim. */
	pr1[0] = ATTCL_ATT_OP_PREPARE_WRITE_RSP;
	put_le16(pr1 + 1, ATTCL_FIXTURE_HANDLE_6);
	put_le16(pr1 + 3, 0);
	memcpy(pr1 + 5, data, 18);
	cl_preload(peer, pr1, sizeof(pr1));

	/* Second prepare: offset 18, remaining 12 bytes. */
	pr2[0] = ATTCL_ATT_OP_PREPARE_WRITE_RSP;
	put_le16(pr2 + 1, ATTCL_FIXTURE_HANDLE_6);
	put_le16(pr2 + 3, 18);
	memcpy(pr2 + 5, data + 18, 12);
	cl_preload(peer, pr2, sizeof(pr2));

	/* Execute Write response. */
	er[0] = ATTCL_ATT_OP_EXECUTE_WRITE_RSP;
	cl_preload(peer, er, sizeof(er));

	ret = att_write_long(&ac, ATTCL_FIXTURE_HANDLE_6, data, sizeof(data));
	ATF_CHECK_EQ_MSG(ret, 0, "two-chunk long write must succeed");

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_write_long_too_long);
ATF_TC_BODY(test_cl_write_long_too_long, tc)
{
	struct att_conn ac;
	int peer, ret;
	static uint8_t data[65536 + 1];

	cl_pair(&ac, &peer);

	/* Offset field is 16-bit, so > ATTCL_HANDLE_MAX is unrepresentable (3.4.6.1). */
	ret = att_write_long(&ac, ATTCL_FIXTURE_HANDLE_6, data, sizeof(data));
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ(errno, EINVAL);

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * att_recv / att_confirm (Core Spec Vol 3 Part F 3.4.7)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cl_recv_notification);
ATF_TC_BODY(test_cl_recv_notification, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t ntf[5], buf[32];
	size_t outlen = 0;

	cl_pair(&ac, &peer);

	ntf[0] = ATTCL_ATT_OP_HANDLE_NOTIFY;
	put_le16(ntf + 1, ATTCL_FIXTURE_HANDLE_6);
	ntf[3] = 0xAB; ntf[4] = 0xCD;
	cl_preload(peer, ntf, sizeof(ntf));

	ret = att_recv(&ac, buf, sizeof(buf), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(outlen, 5);
	ATF_CHECK_EQ(buf[0], ATTCL_ATT_OP_HANDLE_NOTIFY);
	ATF_CHECK_EQ(get_le16(buf + 1), ATTCL_FIXTURE_HANDLE_6);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_recv_closed);
ATF_TC_BODY(test_cl_recv_closed, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t buf[32];

	cl_pair(&ac, &peer);
	close(peer);
	peer = -1;

	ret = att_recv(&ac, buf, sizeof(buf), NULL);
	ATF_CHECK_EQ_MSG(ret, -1, "EOF on the channel must be reported");
	ATF_CHECK_EQ(errno, ECONNRESET);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_confirm);
ATF_TC_BODY(test_cl_confirm, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t got[4];

	cl_pair(&ac, &peer);

	ret = att_confirm(&ac);
	ATF_CHECK_EQ(ret, 0);

	/* Handle Value Confirmation is a single-octet PDU (0x1E). */
	ATF_REQUIRE(recv(peer, got, sizeof(got), MSG_DONTWAIT) == 1);
	ATF_CHECK_EQ(got[0], ATTCL_ATT_OP_HANDLE_CFM);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_cl_confirm_send_fail);
ATF_TC_BODY(test_cl_confirm_send_fail, tc)
{
	struct att_conn ac;
	int peer, ret;

	cl_pair(&ac, &peer);
	close(ac.fd);
	ac.fd = -1;

	ret = att_confirm(&ac);
	ATF_CHECK_EQ(ret, -1);

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * EATT bearers (Core Spec Vol 3 Part G 5.3)
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(test_cl_eatt_reject_unencrypted);
ATF_TC_BODY(test_cl_eatt_reject_unencrypted, tc)
{
	struct att_conn ac;
	uint8_t addr[6] = { 0 };
	int peer;

	cl_pair(&ac, &peer);
	ATF_CHECK_EQ(att_open_eatt(&ac, NULL, addr, 0, 1), 0);
	ATF_CHECK_EQ(errno, EPERM);
	ATF_CHECK_EQ(ac.eatt_count, 0);
	cl_cleanup(&ac, peer);
}

/* Open several EATT bearers; a request then rides an EATT bearer. */
ATF_TC_WITHOUT_HEAD(test_cl_eatt_open_and_request);
ATF_TC_BODY(test_cl_eatt_open_and_request, tc)
{
	struct att_conn ac;
	int peer, ret, opened;
	uint8_t addr[6] = { 0 };
	uint8_t rsp[5], out[16];
	size_t outlen = 0;

	cl_pair(&ac, &peer);
	ac.encrypted = true;

	/* Open 3 bearers (socketpair-backed via the custom CoC connector). */
	opened = att_open_eatt(&ac, NULL, addr, 0, 3);
	ATF_CHECK_EQ_MSG(opened, 3, "all requested EATT bearers must open");
	ATF_CHECK_EQ(ac.eatt_count, 3);
	/* CoC MTU is unavailable on a socketpair -> EATT minimum 64. */
	ATF_CHECK_EQ(ac.eatt[0].mtu, BT_CORE63_EATT_MIN_MTU);

	/*
	 * A Read Request must now be multiplexed onto an EATT bearer.
	 * The least-loaded selector picks bearer 0 first; preload its peer.
	 */
	rsp[0] = ATTCL_ATT_OP_READ_RSP;
	rsp[1] = 0x42;
	ATF_REQUIRE(send(g_coc_peer[0], rsp, 2, MSG_EOR) == 2);

	ret = att_read(&ac, ATTCL_FIXTURE_HANDLE_6, out, sizeof(out), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(outlen, 1);
	ATF_CHECK_EQ(out[0], 0x42);
	/* pending count must return to zero after the response. */
	ATF_CHECK_EQ_MSG(ac.eatt[0].pending, 0,
	    "bearer pending count must be balanced");

	cl_cleanup(&ac, peer);
}

/* count is clamped to ATT_MAX_EATT_BEARERS. */
ATF_TC_WITHOUT_HEAD(test_cl_eatt_open_clamped);
ATF_TC_BODY(test_cl_eatt_open_clamped, tc)
{
	struct att_conn ac;
	int peer, opened;
	uint8_t addr[6] = { 0 };

	cl_pair(&ac, &peer);
	ac.encrypted = true;

	opened = att_open_eatt(&ac, NULL, addr, 0, ATT_MAX_EATT_BEARERS + 4);
	ATF_CHECK_EQ_MSG(opened, ATT_MAX_EATT_BEARERS,
	    "open count must be clamped to the maximum");

	cl_cleanup(&ac, peer);
}

/* A CoC connect failure stops opening further bearers. */
ATF_TC_WITHOUT_HEAD(test_cl_eatt_open_partial);
ATF_TC_BODY(test_cl_eatt_open_partial, tc)
{
	struct att_conn ac;
	int peer, opened;
	uint8_t addr[6] = { 0 };

	cl_pair(&ac, &peer);
	ac.encrypted = true;
	g_coc_fail_after = 2;		/* 3rd connect fails */

	opened = att_open_eatt(&ac, NULL, addr, 0, 5);
	ATF_CHECK_EQ_MSG(opened, 2, "opening stops at the first failure");
	ATF_CHECK_EQ(ac.eatt_count, 2);

	cl_cleanup(&ac, peer);
}

/* att_eatt_accept: bearer table full is rejected. */
ATF_TC_WITHOUT_HEAD(test_cl_eatt_accept_full);
ATF_TC_BODY(test_cl_eatt_accept_full, tc)
{
	struct att_conn ac;
	int peer, ret;

	cl_pair(&ac, &peer);
	ac.eatt_count = ATT_MAX_EATT_BEARERS;

	ret = att_eatt_accept(&ac, ac.fd);
	ATF_CHECK_EQ_MSG(ret, -1, "accept must fail when the table is full");
	ATF_CHECK_EQ(errno, ENOSPC);

	cl_cleanup(&ac, peer);
}

/* att_eatt_accept: accept4 failure (no pending connection) -> -1. */
ATF_TC_WITHOUT_HEAD(test_cl_eatt_accept_fail);
ATF_TC_BODY(test_cl_eatt_accept_fail, tc)
{
	struct att_conn ac;
	int peer, ret, lfd;
	struct sockaddr_un sun;

	cl_pair(&ac, &peer);

	lfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	ATF_REQUIRE(lfd >= 0);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "eatt_accept_fail.sock");
	(void)unlink(sun.sun_path);
	ATF_REQUIRE(bind(lfd, (struct sockaddr *)&sun, sizeof(sun)) == 0);
	ATF_REQUIRE(listen(lfd, 1) == 0);
	ATF_REQUIRE(fcntl(lfd, F_SETFL, O_NONBLOCK) == 0);

	/* No client is connecting -> accept4 returns EAGAIN -> -1. */
	ret = att_eatt_accept(&ac, lfd);
	ATF_CHECK_EQ_MSG(ret, -1, "accept with no pending peer must fail");

	close(lfd);
	(void)unlink(sun.sun_path);
	cl_cleanup(&ac, peer);
}

/* att_eatt_accept: a pending connection is accepted as a new bearer. */
ATF_TC_WITHOUT_HEAD(test_cl_eatt_accept_ok);
ATF_TC_BODY(test_cl_eatt_accept_ok, tc)
{
	struct att_conn ac;
	int peer, ret, lfd, cfd;
	struct sockaddr_un sun;

	cl_pair(&ac, &peer);

	lfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	ATF_REQUIRE(lfd >= 0);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "eatt_accept_ok.sock");
	(void)unlink(sun.sun_path);
	ATF_REQUIRE(bind(lfd, (struct sockaddr *)&sun, sizeof(sun)) == 0);
	ATF_REQUIRE(listen(lfd, 1) == 0);

	cfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE(connect(cfd, (struct sockaddr *)&sun, sizeof(sun)) == 0);

	ret = att_eatt_accept(&ac, lfd);
	ATF_CHECK_EQ_MSG(ret, 0, "a pending EATT connection must be accepted");
	ATF_CHECK_EQ(ac.eatt_count, 1);
	ATF_CHECK_EQ_MSG(ac.eatt[0].mtu, BT_CORE63_EATT_MIN_MTU,
	    "no CoC MTU on a unix socket -> EATT minimum 64");

	close(cfd);
	close(lfd);
	(void)unlink(sun.sun_path);
	cl_cleanup(&ac, peer);
}

/*
 * Regression: a bounded unsolicited-PDU flood must report a clean transport
 * failure.  There is no ATT Error Response in this path, so request senders
 * such as att_read() must return -1 rather than surfacing a stale/uninitialised
 * att_error.code value.
 */
ATF_TC_WITHOUT_HEAD(test_cl_flood_return_is_clean_fail);
ATF_TC_BODY(test_cl_flood_return_is_clean_fail, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t ntf[5], out[8];

	cl_pair(&ac, &peer);

	ntf[0] = ATTCL_ATT_OP_HANDLE_NOTIFY;
	put_le16(ntf + 1, ATTCL_FIXTURE_HANDLE_6);
	ntf[3] = 0; ntf[4] = 0;
	for (int i = 0; i < ATTCL_LOCAL_UNSOLICITED_LIMIT; i++)
		cl_preload(peer, ntf, sizeof(ntf));

	ret = att_read(&ac, ATTCL_FIXTURE_HANDLE_6, out, sizeof(out), NULL);
	ATF_CHECK_EQ_MSG(ret, -1,
	    "flood abort must be a clean -1, not a fabricated ATT error code");

	cl_cleanup(&ac, peer);
}

/*
 * A truncated (4-octet) ATT Error Response must NOT be parsed as a valid
 * error.  Core Spec Vol 3 Part F §3.4.1.1 fixes the Error Response at 5
 * octets (opcode, request opcode, attribute handle, error code); a 4-octet
 * PDU lacks the Error Code field and is malformed.  A client that accepts it
 * would surface a fabricated error code read from beyond the received bytes.
 * The contract-correct result is a clean transport failure (-1), never a
 * (stale) 0..255 error code.  (Kills an `n >= 5` -> `n >= 4` weakening.)
 */
ATF_TC_WITHOUT_HEAD(test_cl_read_truncated_error);
ATF_TC_BODY(test_cl_read_truncated_error, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t bad[4], out[8];

	cl_pair(&ac, &peer);

	/* Error Response opcode + request opcode + handle, but NO error code. */
	bad[0] = ATTCL_ATT_OP_ERROR_RSP;
	bad[1] = ATTCL_ATT_OP_READ_REQ;
	put_le16(bad + 2, ATTCL_FIXTURE_HANDLE_3);
	cl_preload(peer, bad, sizeof(bad));

	ret = att_read(&ac, ATTCL_FIXTURE_HANDLE_3, out, sizeof(out), NULL);
	ATF_CHECK_EQ_MSG(ret, -1,
	    "a 4-octet (truncated) Error Response must be a clean -1, not a "
	    "fabricated ATT error code");

	cl_cleanup(&ac, peer);
}

/* ================================================================
 * ATF TEST PLAN
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* Exchange MTU */
	ATF_TP_ADD_TC(tp, test_cl_mtu_server_smaller);
	ATF_TP_ADD_TC(tp, test_cl_mtu_client_smaller);
	ATF_TP_ADD_TC(tp, test_cl_mtu_client_floor);
	ATF_TP_ADD_TC(tp, test_cl_mtu_already);
	ATF_TP_ADD_TC(tp, test_cl_mtu_wrong_opcode);
	ATF_TP_ADD_TC(tp, test_cl_mtu_error_rsp);

	/* att_request machinery */
	ATF_TP_ADD_TC(tp, test_cl_skip_notification);
	ATF_TP_ADD_TC(tp, test_cl_skip_indication);
	ATF_TP_ADD_TC(tp, test_cl_too_many_unsolicited);
	ATF_TP_ADD_TC(tp, test_cl_conn_closed);

	/* Read / Read Blob */
	ATF_TP_ADD_TC(tp, test_cl_read_ok);
	ATF_TP_ADD_TC(tp, test_cl_read_truncate_to_buf);
	ATF_TP_ADD_TC(tp, test_cl_read_err_not_permitted);
	ATF_TP_ADD_TC(tp, test_cl_read_truncated_error);
	ATF_TP_ADD_TC(tp, test_cl_read_wrong_opcode);
	ATF_TP_ADD_TC(tp, test_cl_read_blob_ok);
	ATF_TP_ADD_TC(tp, test_cl_read_blob_err);
	ATF_TP_ADD_TC(tp, test_cl_read_blob_wrong_opcode);

	/* Write Req / Write Cmd */
	ATF_TP_ADD_TC(tp, test_cl_write_req_ok);
	ATF_TP_ADD_TC(tp, test_cl_write_req_err);
	ATF_TP_ADD_TC(tp, test_cl_write_req_too_big);
	ATF_TP_ADD_TC(tp, test_cl_write_req_wrong_opcode);
	ATF_TP_ADD_TC(tp, test_cl_write_cmd_ok);
	ATF_TP_ADD_TC(tp, test_cl_write_cmd_too_big);
	ATF_TP_ADD_TC(tp, test_cl_write_cmd_heap);
	ATF_TP_ADD_TC(tp, test_cl_write_cmd_send_fail);

	/* Find By Type Value */
	ATF_TP_ADD_TC(tp, test_cl_find_by_type_value_ok);
	ATF_TP_ADD_TC(tp, test_cl_find_by_type_value_notfound);
	ATF_TP_ADD_TC(tp, test_cl_find_by_type_value_other_err);
	ATF_TP_ADD_TC(tp, test_cl_find_by_type_value_too_big);

	/* Read Multiple / Read Multiple Variable */
	ATF_TP_ADD_TC(tp, test_cl_read_multiple_ok);
	ATF_TP_ADD_TC(tp, test_cl_read_multiple_too_few);
	ATF_TP_ADD_TC(tp, test_cl_read_multiple_err);
	ATF_TP_ADD_TC(tp, test_cl_read_multiple_wrong_opcode);
	ATF_TP_ADD_TC(tp, test_cl_read_multiple_var_ok);
	ATF_TP_ADD_TC(tp, test_cl_read_multiple_var_too_few);
	ATF_TP_ADD_TC(tp, test_cl_read_multiple_var_err);
	ATF_TP_ADD_TC(tp, test_cl_read_multiple_var_wrong_opcode);

	/* Find Info / Read By Type / Read By Group Type */
	ATF_TP_ADD_TC(tp, test_cl_find_info_ok);
	ATF_TP_ADD_TC(tp, test_cl_find_info_notfound);
	ATF_TP_ADD_TC(tp, test_cl_find_info_wrong_opcode);
	ATF_TP_ADD_TC(tp, test_cl_read_by_type_err);
	ATF_TP_ADD_TC(tp, test_cl_read_by_type_wrong_opcode);
	ATF_TP_ADD_TC(tp, test_cl_read_by_type128_ok);
	ATF_TP_ADD_TC(tp, test_cl_read_by_type128_notfound);
	ATF_TP_ADD_TC(tp, test_cl_read_by_type128_err);
	ATF_TP_ADD_TC(tp, test_cl_read_by_group_wrong_opcode);
	ATF_TP_ADD_TC(tp, test_cl_read_by_group_err);

	/* Prepare / Execute / Long Write */
	ATF_TP_ADD_TC(tp, test_cl_prepare_write_ok);
	ATF_TP_ADD_TC(tp, test_cl_prepare_write_echo_mismatch);
	ATF_TP_ADD_TC(tp, test_cl_prepare_write_value_mismatch);
	ATF_TP_ADD_TC(tp, test_cl_prepare_write_err);
	ATF_TP_ADD_TC(tp, test_cl_prepare_write_too_big);
	ATF_TP_ADD_TC(tp, test_cl_execute_write_ok);
	ATF_TP_ADD_TC(tp, test_cl_execute_write_wrong_opcode);
	ATF_TP_ADD_TC(tp, test_cl_execute_write_err);
	ATF_TP_ADD_TC(tp, test_cl_write_long_two_chunks);
	ATF_TP_ADD_TC(tp, test_cl_write_long_too_long);

	/* recv / confirm */
	ATF_TP_ADD_TC(tp, test_cl_recv_notification);
	ATF_TP_ADD_TC(tp, test_cl_recv_closed);
	ATF_TP_ADD_TC(tp, test_cl_confirm);
	ATF_TP_ADD_TC(tp, test_cl_confirm_send_fail);

	/* EATT */
	ATF_TP_ADD_TC(tp, test_cl_eatt_reject_unencrypted);
	ATF_TP_ADD_TC(tp, test_cl_eatt_open_and_request);
	ATF_TP_ADD_TC(tp, test_cl_eatt_open_clamped);
	ATF_TP_ADD_TC(tp, test_cl_eatt_open_partial);
	ATF_TP_ADD_TC(tp, test_cl_eatt_accept_full);
	ATF_TP_ADD_TC(tp, test_cl_eatt_accept_fail);
	ATF_TP_ADD_TC(tp, test_cl_eatt_accept_ok);

	/* Marked finding */
	ATF_TP_ADD_TC(tp, test_cl_flood_return_is_clean_fail);

	return (atf_no_error());
}
