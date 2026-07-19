/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Deep branch-coverage tests for the ATT *client* senders in att.c that the
 * existing att_client_test.c / att_test.c suites leave uncovered:
 *
 *   - att_close() teardown;
 *   - att_open_fd() connect-failure path (a pre-connected AF_UNIX fd cannot
 *     be connected to an L2CAP address);
 *   - Exchange MTU: malformed response and small-server-MTU floor;
 *   - the "response longer than caller buffer" truncation clamp in every
 *     raw-payload sender (Read Blob, Find Info, Read By Type[/uuid128],
 *     Read By Group, Find By Type Value, Read Multiple[/variable]);
 *   - malformed / short / wrong-opcode responses for each sender;
 *   - Write Request oversize (reqlen > stack buffer with a large MTU);
 *   - Write Command: heap path for a large PDU, EATT bearer selection,
 *     no-EATT primary path, and the send-failure free;
 *   - Read Multiple[/variable] request-length rejection;
 *   - Prepare Write echo mismatch and Write Long execute-phase failure;
 *   - att_recv() EAGAIN and peer-closed, att_confirm() send failure;
 *   - att_request() notification / indication interleave, the indication
 *     flood cap, and peer-closed-mid-request.
 *
 * ORACLE: expected effective MTU, error codes and truncation lengths are
 * hand-derived from the Bluetooth Core Specification (ATT = Vol 3 Part F),
 * cited per group; never captured from the implementation's output.
 *
 * Mechanics mirror att_client_test.c: the daemon-side fd is O_NONBLOCK so a
 * recv() with nothing queued returns EAGAIN and the sender unwinds; server
 * replies are pre-queued as distinct SEQPACKET datagrams (MSG_EOR).
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "gatt.h"
#include "hci_log.h"

#include "test_common.h"
#include "spec_att_client_oracles.h"

/* ================================================================
 * Mock helpers
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
	ac->mtu = 517;
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	for (int i = 0; i < ATT_MAX_EATT_BEARERS; i++)
		ac->eatt[i].fd = -1;
	*peer_fd = fds[1];
}

static void
cl_cleanup(struct att_conn *ac, int peer_fd)
{

	free(ac->buf);
	ac->buf = NULL;
	if (ac->fd >= 0)
		close(ac->fd);
	if (peer_fd >= 0)
		close(peer_fd);
}

static void
cl_preload(int peer_fd, const uint8_t *pdu, size_t len)
{

	ATF_REQUIRE(send(peer_fd, pdu, len, MSG_EOR) == (ssize_t)len);
}

static int unsolicited_count, unsolicited_fd;
static uint8_t unsolicited_opcode;

static void
cl_unsolicited(struct att_conn *ac __unused, int fd, const uint8_t *pdu,
    size_t len, void *arg __unused)
{

	if (len != 0) {
		unsolicited_count++;
		unsolicited_fd = fd;
		unsolicited_opcode = pdu[0];
	}
}

/* ================================================================
 * att_close() teardown (att.c 153-164).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_att_close);
ATF_TC_BODY(test_att_close, tc)
{
	struct att_conn ac;
	int peer;

	cl_pair(&ac, &peer);
	ac.prep_queue.count = 3;
	att_close(&ac);
	ATF_CHECK_EQ_MSG(ac.fd, -1, "att_close clears the fd");
	ATF_CHECK_MSG(ac.buf == NULL, "att_close frees and clears the buffer");
	ATF_CHECK_EQ(ac.prep_queue.count, 0);
	close(peer);
}

/* ================================================================
 * att_open_fd() connect-failure (att.c 130-131): connecting an already
 * connected AF_UNIX socket to an L2CAP address fails.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_att_open_fd_connect_fail);
ATF_TC_BODY(test_att_open_fd_connect_fail, tc)
{
	struct att_conn ac;
	int fds[2];
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	ATF_CHECK_EQ_MSG(att_open_fd(&ac, fds[0], NULL, 0, addr, 0), -1,
	    "connect() on a connected AF_UNIX fd must fail");
	close(fds[0]);
	close(fds[1]);
}

/* ================================================================
 * Exchange MTU malformed + small-server floor (att.c 358-367).
 * Core Spec Vol 3 Part F 3.4.2: effective MTU = min(client,server), >= 23.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_mtu_bad_response);
ATF_TC_BODY(test_mtu_bad_response, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[3];

	cl_pair(&ac, &peer);
	/* Wrong opcode in the MTU response -> EPROTO (att.c 358). */
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_RSP;
	put_le16(rsp + 1, 100);
	cl_preload(peer, rsp, sizeof(rsp));
	ATF_CHECK_EQ(att_exchange_mtu(&ac, 200), -1);
	ATF_CHECK_EQ(errno, EPROTO);
	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_mtu_server_below_floor);
ATF_TC_BODY(test_mtu_server_below_floor, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[3];

	cl_pair(&ac, &peer);
	/* Server advertises 10; floor raises the effective MTU to 23. */
	rsp[0] = BT_CORE63_WIRE_ATT_OP_MTU_RSP;
	put_le16(rsp + 1, 10);
	cl_preload(peer, rsp, sizeof(rsp));
	ATF_CHECK_EQ(att_exchange_mtu(&ac, 200), 0);
	ATF_CHECK_EQ_MSG(ac.mtu, ATT_DEFAULT_MTU,
	    "effective MTU floored to 23 (att.c 366-367)");
	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Response-longer-than-buffer truncation clamp for each raw-payload sender.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_payload_truncation_clamps);
ATF_TC_BODY(test_payload_truncation_clamps, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[64];
	uint8_t small[2];
	size_t outlen;
	uint16_t handles[2] = { 0x0003, 0x0005 };
	uint8_t u128[16] = { 0 };

	/* Read Blob (att.c 439). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_BLOB_RSP;
	memset(rsp + 1, 0xAA, 20);
	cl_preload(peer, rsp, 21);
	ATF_CHECK_EQ(att_read_blob(&ac, 3, 0, small, sizeof(small), &outlen), 0);
	ATF_CHECK_EQ_MSG(outlen, sizeof(small), "read blob clamps to buflen");
	cl_cleanup(&ac, peer);

	/* Find Info (att.c 886). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_FIND_INFO_RSP;
	rsp[1] = 1;
	memset(rsp + 2, 0xBB, 20);
	cl_preload(peer, rsp, 22);
	ATF_CHECK_EQ(att_find_info(&ac, 1, 0xFFFF, small, sizeof(small),
	    &outlen), -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);
	cl_cleanup(&ac, peer);

	/* Read By Type (att.c 929). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 6;
	memset(rsp + 2, 0xCC, 18);
	cl_preload(peer, rsp, 20);
	ATF_CHECK_EQ(att_read_by_type(&ac, 1, 0xFFFF, 0x2803, small,
	    sizeof(small), &outlen), -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);
	cl_cleanup(&ac, peer);

	/* Read By Type (128-bit) (att.c 972). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 6;
	memset(rsp + 2, 0xDD, 18);
	cl_preload(peer, rsp, 20);
	ATF_CHECK_EQ(att_read_by_type_uuid128(&ac, 1, 0xFFFF, u128, small,
	    sizeof(small), &outlen), -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);
	cl_cleanup(&ac, peer);

	/* Read By Group Type (att.c 1015). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 6;
	memset(rsp + 2, 0xEE, 18);
	cl_preload(peer, rsp, 20);
	ATF_CHECK_EQ(att_read_by_group_type(&ac, 1, 0xFFFF, 0x2800, small,
	    sizeof(small), &outlen), -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);
	cl_cleanup(&ac, peer);

	/* Find By Type Value (att.c 604). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
	memset(rsp + 1, 0x11, 20);
	cl_preload(peer, rsp, 21);
	ATF_CHECK_EQ(att_find_by_type_value(&ac, 1, 0xFFFF, 0x2800, "\x00\x18",
	    2, small, sizeof(small), &outlen), -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);
	cl_cleanup(&ac, peer);

	/* Read Multiple (att.c 653). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_RSP;
	memset(rsp + 1, 0x22, 20);
	cl_preload(peer, rsp, 21);
	ATF_CHECK_EQ(att_read_multiple(&ac, handles, 2, small, sizeof(small),
	    &outlen), 0);
	ATF_CHECK_EQ(outlen, sizeof(small));
	cl_cleanup(&ac, peer);

	/* Read Multiple Variable (att.c 705). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_RSP;
	memset(rsp + 1, 0x33, 20);
	cl_preload(peer, rsp, 21);
	ATF_CHECK_EQ(att_read_multiple_variable(&ac, handles, 2, small,
	    sizeof(small), &outlen), 0);
	ATF_CHECK_EQ(outlen, sizeof(small));
	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Short / wrong-opcode responses -> EPROTO for each sender.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_malformed_responses);
ATF_TC_BODY(test_malformed_responses, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[8], buf[32];
	size_t outlen;
	uint16_t handles[2] = { 0x0003, 0x0005 };
	uint8_t u128[16] = { 0 };

	/* Find Info: correct opcode but n < 2 (att.c 879). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_FIND_INFO_RSP;
	cl_preload(peer, rsp, 1);
	ATF_CHECK_EQ(att_find_info(&ac, 1, 0xFFFF, buf, sizeof(buf), &outlen),
	    -1);
	ATF_CHECK_EQ(errno, EPROTO);
	cl_cleanup(&ac, peer);

	/* Read By Type: n < 2 (att.c 922). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_RSP;
	cl_preload(peer, rsp, 1);
	ATF_CHECK_EQ(att_read_by_type(&ac, 1, 0xFFFF, 0x2803, buf, sizeof(buf),
	    &outlen), -1);
	cl_cleanup(&ac, peer);

	/* Read By Type 128: wrong opcode (att.c 966). */
	cl_pair(&ac, &peer);
	/* Set the Table 3.2 Command Flag on ERROR_RSP to make a bad opcode. */
	rsp[0] = BT_CORE63_WIRE_ATT_OP_ERROR_RSP | ATT_OPCODE_COMMAND_FLAG;
	cl_preload(peer, rsp, 2);
	ATF_CHECK_EQ(att_read_by_type_uuid128(&ac, 1, 0xFFFF, u128, buf,
	    sizeof(buf), &outlen), -1);
	cl_cleanup(&ac, peer);

	/* Read By Group: n < 2 (att.c 1008). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	cl_preload(peer, rsp, 1);
	ATF_CHECK_EQ(att_read_by_group_type(&ac, 1, 0xFFFF, 0x2800, buf,
	    sizeof(buf), &outlen), -1);
	cl_cleanup(&ac, peer);

	/* Find By Type Value: n < 5 (att.c 597). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
	cl_preload(peer, rsp, 1);
	ATF_CHECK_EQ(att_find_by_type_value(&ac, 1, 0xFFFF, 0x2800, "\x00\x18",
	    2, buf, sizeof(buf), &outlen), -1);
	cl_cleanup(&ac, peer);

	/* Read Multiple: wrong opcode (att.c 646). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_RSP;
	cl_preload(peer, rsp, 3);
	ATF_CHECK_EQ(att_read_multiple(&ac, handles, 2, buf, sizeof(buf),
	    &outlen), -1);
	cl_cleanup(&ac, peer);

	/* Read Multiple Variable: wrong opcode (att.c 698). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_RSP;
	cl_preload(peer, rsp, 3);
	ATF_CHECK_EQ(att_read_multiple_variable(&ac, handles, 2, buf,
	    sizeof(buf), &outlen), -1);
	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Write Request oversize with a large MTU (att.c 464, second clause).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_write_req_oversize);
ATF_TC_BODY(test_write_req_oversize, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t data[550];

	cl_pair(&ac, &peer);
	ac.mtu = 600;	/* > 517 so the stack-buffer clause is the trigger */
	memset(data, 0x5A, sizeof(data));
	ATF_CHECK_EQ_MSG(att_write_req(&ac, 3, data, sizeof(data)), -1,
	    "reqlen 553 > stack buffer 517 -> EMSGSIZE");
	ATF_CHECK_EQ(errno, EMSGSIZE);
	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Write Command: heap path (large PDU), primary/EATT bearer, send failure.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_write_cmd_paths);
ATF_TC_BODY(test_write_cmd_paths, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t data[550];

	/* No EATT: primary bearer path (att.c 534), small PDU. */
	cl_pair(&ac, &peer);
	ATF_CHECK_EQ(att_write_cmd(&ac, 3, "\x01\x02", 2), 0);
	cl_cleanup(&ac, peer);

	/* Large PDU -> heap allocation path (att.c 515-521). */
	cl_pair(&ac, &peer);
	ac.mtu = 600;
	memset(data, 0x33, sizeof(data));
	ATF_CHECK_EQ_MSG(att_write_cmd(&ac, 3, data, sizeof(data)), 0,
	    "553-byte Write Command uses the heap buffer");
	cl_cleanup(&ac, peer);

	/* Large PDU + closed peer -> send fails and frees the heap buffer. */
	cl_pair(&ac, &peer);
	ac.mtu = 600;
	close(peer);
	ATF_CHECK_EQ_MSG(att_write_cmd(&ac, 3, data, sizeof(data)), -1,
	    "send failure frees the heap PDU (att.c 540-541)");
	free(ac.buf);
	ac.buf = NULL;
	close(ac.fd);
}

ATF_TC_WITHOUT_HEAD(test_write_cmd_prefers_largest_bearer);
ATF_TC_BODY(test_write_cmd_prefers_largest_bearer, tc)
{
	struct att_conn ac;
	int peer, ebfd[2];

	cl_pair(&ac, &peer);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ebfd) == 0);
	/* The fixed bearer has MTU 517; this EATT bearer has only MTU 100. */
	ac.eatt_count = 1;
	ac.eatt[0].fd = ebfd[0];
	ac.eatt[0].active = true;
	ac.eatt[0].mtu = 100;

	ATF_CHECK_EQ(att_write_cmd(&ac, 3, "\x09\x09", 2), 0);
	/* Stable Write Commands pin the highest-capacity ordering domain. */
	{
		uint8_t got[8];
		ssize_t n = recv(peer, got, sizeof(got), MSG_DONTWAIT);
		ATF_CHECK_MSG(n == 5, "write cmd routed to fixed bearer, got %zd",
		    n);
		n = recv(ebfd[1], got, sizeof(got), MSG_DONTWAIT);
		ATF_CHECK_MSG(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
		    "smaller EATT bearer must remain unused, got %zd", n);
	}
	ac.eatt_count = 0;	/* avoid double close via att_close_eatt */
	ac.eatt[0].fd = -1;
	close(ebfd[0]);
	close(ebfd[1]);
	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Read Multiple[/variable] request-length rejection (att.c 633 / 685).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_read_multiple_reqlen);
ATF_TC_BODY(test_read_multiple_reqlen, tc)
{
	struct att_conn ac;
	int peer;
	uint16_t handles[12];
	uint8_t buf[32];
	size_t outlen;

	for (int i = 0; i < 12; i++)
		handles[i] = 0x0003 + i;

	cl_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;	/* 23: reqlen 25 > mtu -> EINVAL */
	ATF_CHECK_EQ(att_read_multiple(&ac, handles, 12, buf, sizeof(buf),
	    &outlen), -1);
	ATF_CHECK_EQ(errno, EINVAL);
	ATF_CHECK_EQ(att_read_multiple_variable(&ac, handles, 12, buf,
	    sizeof(buf), &outlen), -1);
	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Prepare Write echo mismatch (att.c 748-753) and wrong opcode (742).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_prepare_write_echo);
ATF_TC_BODY(test_prepare_write_echo, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[16];

	/* Wrong opcode. */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_WRITE_RSP;
	cl_preload(peer, rsp, 1);
	ATF_CHECK_EQ(att_prepare_write(&ac, 3, 0, "\xAA", 1), -1);
	cl_cleanup(&ac, peer);

	/* Correct opcode but wrong echoed handle. */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP;
	put_le16(rsp + 1, 0x0099);	/* != requested handle 3 */
	put_le16(rsp + 3, 0);
	rsp[5] = 0xAA;
	cl_preload(peer, rsp, 6);
	ATF_CHECK_EQ_MSG(att_prepare_write(&ac, 3, 0, "\xAA", 1), -1,
	    "prepare-write echo handle mismatch -> EPROTO");
	cl_cleanup(&ac, peer);
}

/* ================================================================
 * Write Long: execute-phase failure propagates (att.c 843-845).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_write_long_execute_fail);
ATF_TC_BODY(test_write_long_execute_fail, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t prep[16], err[5];
	uint8_t data[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

	cl_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;	/* chunkmax 18 -> single prepare */

	/* Prepare Write response echoing handle/offset/value exactly. */
	prep[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP;
	put_le16(prep + 1, 3);
	put_le16(prep + 3, 0);
	memcpy(prep + 5, data, 4);
	cl_preload(peer, prep, 9);
	/* Execute Write returns an ATT error -> write_long returns it (845). */
	err[0] = BT_CORE63_WIRE_ATT_OP_ERROR_RSP;
	err[1] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ;
	put_le16(err + 2, 0);
	err[4] = BT_CORE63_WIRE_ATT_ERR_UNLIKELY_ERROR;
	cl_preload(peer, err, 5);

	ATF_CHECK_EQ_MSG(att_write_long(&ac, 3, data, 4),
	    BT_CORE63_WIRE_ATT_ERR_UNLIKELY_ERROR,
	    "execute-phase error code propagates out of write_long");
	cl_cleanup(&ac, peer);
}

/* ================================================================
 * att_recv() EAGAIN + peer-closed, att_confirm() send failure.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_recv_and_confirm);
ATF_TC_BODY(test_recv_and_confirm, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[32];
	size_t outlen;

	/* Nothing queued -> recv EAGAIN -> -1 (att.c 1034-1036). */
	cl_pair(&ac, &peer);
	ATF_CHECK_EQ(att_recv(&ac, buf, sizeof(buf), &outlen), -1);
	cl_cleanup(&ac, peer);

	/* Peer closed -> recv returns 0 -> ECONNRESET (att.c 1037-1040). */
	cl_pair(&ac, &peer);
	close(peer);
	peer = -1;
	ATF_CHECK_EQ(att_recv(&ac, buf, sizeof(buf), &outlen), -1);
	ATF_CHECK_EQ(errno, ECONNRESET);
	cl_cleanup(&ac, peer);

	/* Confirm send failure (att.c 1064-1065). */
	cl_pair(&ac, &peer);
	close(peer);
	peer = -1;
	ATF_CHECK_EQ_MSG(att_confirm(&ac), -1, "confirm send failure -> -1");
	cl_cleanup(&ac, peer);
}

/* ================================================================
 * att_request(): notification / indication interleave, indication flood,
 * and peer-closed-mid-request (att.c 225-294).
 * Core Spec Vol 3 Part F 3.4.7.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_request_interleave);
ATF_TC_BODY(test_request_interleave, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t ntf[4], ind[4], rsp[3];
	size_t outlen;
	uint8_t out[8];

	cl_pair(&ac, &peer);

	/* A notification then an indication then the real Read Response. */
	ntf[0] = BT_CORE63_WIRE_ATT_OP_HANDLE_NOTIFY;
	put_le16(ntf + 1, 0x0003);
	ntf[3] = 0x00;
	cl_preload(peer, ntf, 4);

	ind[0] = BT_CORE63_WIRE_ATT_OP_HANDLE_IND;
	put_le16(ind + 1, 0x0003);
	ind[3] = 0x00;
	cl_preload(peer, ind, 4);

	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_RSP;
	rsp[1] = 0x42;
	rsp[2] = 0x43;
	cl_preload(peer, rsp, 3);

	ATF_CHECK_EQ_MSG(att_read(&ac, 3, out, sizeof(out), &outlen), 0,
	    "unsolicited PDUs are skipped, real response is returned");
	ATF_CHECK_EQ(outlen, 2);
	/* The client must have sent a Handle Value Confirmation for the ind. */
	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_request_indication_flood);
ATF_TC_BODY(test_request_indication_flood, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t ind[4], out[8];
	size_t outlen;

	cl_pair(&ac, &peer);
	ind[0] = BT_CORE63_WIRE_ATT_OP_HANDLE_IND;
	put_le16(ind + 1, 0x0003);
	ind[3] = 0x00;
	/* 16 indications exhausts the skip budget -> EBADMSG (att.c 277-288). */
	for (int i = 0; i < 16; i++)
		cl_preload(peer, ind, 4);

	ATF_CHECK_EQ(att_read(&ac, 3, out, sizeof(out), &outlen), -1);
	ATF_CHECK_EQ_MSG(errno, EBADMSG,
	    "indication flood returns clean transport failure, not ae.code");
	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_request_notification_flood);
ATF_TC_BODY(test_request_notification_flood, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t ntf[4], out[8];
	size_t outlen;

	cl_pair(&ac, &peer);
	ntf[0] = BT_CORE63_WIRE_ATT_OP_HANDLE_NOTIFY;
	put_le16(ntf + 1, 0x0003);
	ntf[3] = 0x00;
	for (int i = 0; i < 16; i++)
		cl_preload(peer, ntf, 4);

	ATF_CHECK_EQ(att_read(&ac, 3, out, sizeof(out), &outlen), -1);
	ATF_CHECK_EQ_MSG(errno, EBADMSG,
	    "notification flood returns EBADMSG (regression: ae was unset)");
	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_request_peer_closed);
ATF_TC_BODY(test_request_peer_closed, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t out[8];
	size_t outlen;

	cl_pair(&ac, &peer);
	/* Peer half-closes its write side: our send succeeds, recv sees EOF. */
	ATF_REQUIRE(shutdown(peer, SHUT_WR) == 0);
	ATF_CHECK_EQ(att_read(&ac, 3, out, sizeof(out), &outlen), -1);
	ATF_CHECK_EQ_MSG(errno, ECONNRESET,
	    "peer EOF mid-request -> ECONNRESET (att.c 246-249)");
	cl_cleanup(&ac, peer);
}

/*
 * Bearer-selection fallback when att_eatt_select_bearer() yields no usable
 * bearer and the primary fd is invalid (att.c 197-198 / 533-534): the
 * defensive "fd = ac->fd" reassignment followed by a failing send.
 */
ATF_TC_WITHOUT_HEAD(test_bearer_fallback_degenerate);
ATF_TC_BODY(test_bearer_fallback_degenerate, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t out[8];
	size_t outlen;

	cl_pair(&ac, &peer);
	close(ac.fd);
	ac.fd = -1;			/* primary bearer invalid */
	ac.eatt_count = 1;		/* one EATT bearer ... */
	ac.eatt[0].active = false;	/* ... but inactive -> select < 0 */
	ac.eatt[0].fd = -1;

	/* Write Command: select_bearer() < 0 -> fd = ac->fd = -1 -> send -1. */
	ATF_CHECK_EQ(att_write_cmd(&ac, 3, "\x01", 1), -1);
	/* att_request(): same fallback then failing send. */
	ATF_CHECK_EQ(att_read(&ac, 3, out, sizeof(out), &outlen), -1);

	free(ac.buf);
	ac.buf = NULL;
	close(peer);
}

/*
 * outlen == NULL success arm for every raw-payload sender (att.c: the
 * "if (outlen != NULL)" false branch is otherwise never taken).
 */
ATF_TC_WITHOUT_HEAD(test_senders_null_outlen);
ATF_TC_BODY(test_senders_null_outlen, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[8], buf[32];
	uint16_t handles[2] = { 3, 5 };
	uint8_t u128[16] = { 0 };

#define OK_RSP(op, n)	do { rsp[0] = (op); memset(rsp + 1, 0xA5, (n) - 1); \
			    cl_preload(peer, rsp, (n)); } while (0)

	cl_pair(&ac, &peer);
	OK_RSP(BT_CORE63_WIRE_ATT_OP_READ_BLOB_RSP, 4);
	ATF_CHECK_EQ(att_read_blob(&ac, 3, 0, buf, sizeof(buf), NULL), 0);
	cl_cleanup(&ac, peer);

	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_FIND_INFO_RSP;
	rsp[1] = 1;
	put_le16(rsp + 2, 1);
	put_le16(rsp + 4, 0x2800);
	cl_preload(peer, rsp, 6);
	ATF_CHECK_EQ(att_find_info(&ac, 1, 0xFFFF, buf, sizeof(buf), NULL), 0);
	cl_cleanup(&ac, peer);

	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 2;
	put_le16(rsp + 2, 1);
	cl_preload(peer, rsp, 4);
	ATF_CHECK_EQ(att_read_by_type(&ac, 1, 0xFFFF, 0x2803, buf, sizeof(buf),
	    NULL), 0);
	cl_cleanup(&ac, peer);

	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 2;
	put_le16(rsp + 2, 1);
	cl_preload(peer, rsp, 4);
	ATF_CHECK_EQ(att_read_by_type_uuid128(&ac, 1, 0xFFFF, u128, buf,
	    sizeof(buf), NULL), 0);
	cl_cleanup(&ac, peer);

	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 4;
	put_le16(rsp + 2, 1);
	put_le16(rsp + 4, 1);
	cl_preload(peer, rsp, 6);
	ATF_CHECK_EQ(att_read_by_group_type(&ac, 1, 0xFFFF, 0x2800, buf,
	    sizeof(buf), NULL), 0);
	cl_cleanup(&ac, peer);

	cl_pair(&ac, &peer);
	OK_RSP(BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_RSP, 5);
	ATF_CHECK_EQ(att_find_by_type_value(&ac, 1, 0xFFFF, 0x2800, "\x00\x18",
	    2, buf, sizeof(buf), NULL), 0);
	cl_cleanup(&ac, peer);

	cl_pair(&ac, &peer);
	OK_RSP(BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_RSP, 4);
	ATF_CHECK_EQ(att_read_multiple(&ac, handles, 2, buf, sizeof(buf), NULL),
	    0);
	cl_cleanup(&ac, peer);

	cl_pair(&ac, &peer);
	OK_RSP(BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_RSP, 4);
	ATF_CHECK_EQ(att_read_multiple_variable(&ac, handles, 2, buf,
	    sizeof(buf), NULL), 0);
	cl_cleanup(&ac, peer);
#undef OK_RSP
}

/*
 * Non-EPROTO transport failure arm: with nothing queued the nonblocking
 * recv() returns EAGAIN, so att_request() returns -1 with errno != EPROTO
 * and each sender takes the "errno == EPROTO ? ae.code : -1" false branch.
 */
ATF_TC_WITHOUT_HEAD(test_senders_transport_failure);
ATF_TC_BODY(test_senders_transport_failure, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[32];
	size_t outlen;
	uint16_t handles[2] = { 3, 5 };
	uint8_t u128[16] = { 0 };

#define NORSP(expr)	do { cl_pair(&ac, &peer); \
			    ATF_CHECK_EQ((expr), -1); \
			    cl_cleanup(&ac, peer); } while (0)

	NORSP(att_read_blob(&ac, 3, 0, buf, sizeof(buf), &outlen));
	NORSP(att_write_req(&ac, 3, "\x01", 1));
	NORSP(att_find_info(&ac, 1, 0xFFFF, buf, sizeof(buf), &outlen));
	NORSP(att_read_by_type(&ac, 1, 0xFFFF, 0x2803, buf, sizeof(buf),
	    &outlen));
	NORSP(att_read_by_type_uuid128(&ac, 1, 0xFFFF, u128, buf, sizeof(buf),
	    &outlen));
	NORSP(att_read_by_group_type(&ac, 1, 0xFFFF, 0x2800, buf, sizeof(buf),
	    &outlen));
	NORSP(att_find_by_type_value(&ac, 1, 0xFFFF, 0x2800, "\x00\x18", 2, buf,
	    sizeof(buf), &outlen));
	NORSP(att_read_multiple(&ac, handles, 2, buf, sizeof(buf), &outlen));
	NORSP(att_read_multiple_variable(&ac, handles, 2, buf, sizeof(buf),
	    &outlen));
	NORSP(att_prepare_write(&ac, 3, 0, "\xAA", 1));
	NORSP(att_execute_write(&ac, 0x01));
#undef NORSP
}

/*
 * ATTR_NOT_FOUND is treated as an empty result (return 0, outlen 0) by the
 * discovery senders (att.c 589/871/914/957/1000).
 */
ATF_TC_WITHOUT_HEAD(test_senders_attr_not_found);
ATF_TC_BODY(test_senders_attr_not_found, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[32];
	size_t outlen;
	uint8_t u128[16] = { 0 };

#define NF(reqop, expr)	do { \
	uint8_t e[5]; \
	cl_pair(&ac, &peer); \
	e[0] = BT_CORE63_WIRE_ATT_OP_ERROR_RSP; e[1] = (reqop); put_le16(e + 2, 1); \
	e[4] = BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND; cl_preload(peer, e, 5); \
	outlen = 99; \
	ATF_CHECK_EQ((expr), 0); \
	ATF_CHECK_EQ_MSG(outlen, 0, "ATTR_NOT_FOUND -> empty result"); \
	cl_cleanup(&ac, peer); } while (0)

	NF(BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ,
	    att_find_info(&ac, 1, 0xFFFF, buf, sizeof(buf), &outlen));
	NF(BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ,
	    att_read_by_type(&ac, 1, 0xFFFF, 0x2803, buf, sizeof(buf), &outlen));
	NF(BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ,
	    att_read_by_type_uuid128(&ac, 1, 0xFFFF, u128, buf, sizeof(buf),
	    &outlen));
	NF(BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ,
	    att_read_by_group_type(&ac, 1, 0xFFFF, 0x2800, buf, sizeof(buf),
	    &outlen));
	NF(BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ,
	    att_find_by_type_value(&ac, 1, 0xFFFF, 0x2800, "\x00\x18", 2, buf,
	    sizeof(buf), &outlen));
#undef NF
}

/* A Multiple Handle Value Notification interleaved before the response is
 * skipped like a plain notification (att.c 255-256). */
ATF_TC_WITHOUT_HEAD(test_request_multi_ntf_skip);
ATF_TC_BODY(test_request_multi_ntf_skip, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t mn[8], rsp[3], out[8];
	size_t outlen;

	cl_pair(&ac, &peer);
	mn[0] = BT_CORE63_WIRE_ATT_OP_MULTIPLE_HANDLE_VALUE_NTF;
	put_le16(mn + 1, 3);
	put_le16(mn + 3, 1);
	mn[5] = 0x00;
	cl_preload(peer, mn, 6);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_RSP;
	rsp[1] = 0x77;
	rsp[2] = 0x88;
	cl_preload(peer, rsp, 3);
	ATF_CHECK_EQ_MSG(att_read(&ac, 3, out, sizeof(out), &outlen), 0,
	    "Multiple Handle Value Notification is skipped");
	cl_cleanup(&ac, peer);
}

/*
 * att_request() over an EATT bearer: the bearer is selected, its pending
 * count is bumped for the outstanding request and decremented once the
 * response arrives (att.c 195-197, 297-305).
 */
ATF_TC_WITHOUT_HEAD(test_request_over_eatt_bearer);
ATF_TC_BODY(test_request_over_eatt_bearer, tc)
{
	struct att_conn ac;
	int peer, eb[2];
	uint8_t rsp[3], out[8];
	size_t outlen;

	cl_pair(&ac, &peer);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, eb) == 0);
	ATF_REQUIRE(fcntl(eb[0], F_SETFL, O_NONBLOCK) == 0);
	ac.eatt_count = 1;
	ac.eatt[0].fd = eb[0];
	ac.eatt[0].active = true;
	ac.eatt[0].mtu = 100;
	ac.eatt[0].pending = 0;

	/* Response is delivered on the EATT bearer, not the primary. */
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_RSP;
	rsp[1] = 0xA1;
	rsp[2] = 0xB2;
	ATF_REQUIRE(send(eb[1], rsp, 3, MSG_EOR) == 3);

	ATF_CHECK_EQ(att_read(&ac, 3, out, sizeof(out), &outlen), 0);
	ATF_CHECK_EQ(outlen, 2);
	ATF_CHECK_EQ_MSG(ac.eatt[0].pending, 0,
	    "pending bumped for the request then decremented on the response");

	ac.eatt_count = 0;
	ac.eatt[0].fd = -1;
	close(eb[0]);
	close(eb[1]);
	cl_cleanup(&ac, peer);
}

/* Assorted client-sender guards: short MTU response, request-count limits,
 * prepare-write oversize, and prepare-write offset/value echo mismatches. */
ATF_TC_WITHOUT_HEAD(test_client_sender_guards);
ATF_TC_BODY(test_client_sender_guards, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[16], buf[32];
	size_t outlen;
	uint16_t handles[300];

	/* MTU response too short: n < 3 (att.c 358). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_MTU_RSP;
	rsp[1] = 0x64;
	cl_preload(peer, rsp, 2);	/* only 2 bytes */
	ATF_CHECK_EQ(att_exchange_mtu(&ac, 200), -1);
	ATF_CHECK_EQ(errno, EPROTO);
	cl_cleanup(&ac, peer);

	/* Read Multiple count < 2 and count too large (att.c 627 / 679). */
	for (int i = 0; i < 300; i++)
		handles[i] = 3 + i;
	cl_pair(&ac, &peer);
	ATF_CHECK_EQ(att_read_multiple(&ac, handles, 1, buf, sizeof(buf),
	    &outlen), -1);
	ATF_CHECK_EQ(errno, EINVAL);
	ATF_CHECK_EQ(att_read_multiple(&ac, handles, 300, buf, sizeof(buf),
	    &outlen), -1);
	ATF_CHECK_EQ(att_read_multiple_variable(&ac, handles, 1, buf,
	    sizeof(buf), &outlen), -1);
	ATF_CHECK_EQ(att_read_multiple_variable(&ac, handles, 300, buf,
	    sizeof(buf), &outlen), -1);
	cl_cleanup(&ac, peer);

	/* Prepare Write oversize: reqlen > MTU (att.c 728). */
	cl_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;	/* 23: 5 + 20 = 25 > 23 */
	{
		uint8_t data[20];
		memset(data, 0x5A, sizeof(data));
		ATF_CHECK_EQ(att_prepare_write(&ac, 3, 0, data, sizeof(data)),
		    -1);
		ATF_CHECK_EQ(errno, EMSGSIZE);
	}
	cl_cleanup(&ac, peer);

	/* Prepare Write offset echo mismatch (att.c 748-749). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP;
	put_le16(rsp + 1, 3);		/* correct handle */
	put_le16(rsp + 3, 0x0009);	/* wrong offset (requested 0) */
	rsp[5] = 0xAA;
	cl_preload(peer, rsp, 6);
	ATF_CHECK_EQ(att_prepare_write(&ac, 3, 0, "\xAA", 1), -1);
	cl_cleanup(&ac, peer);

	/* Prepare Write value echo mismatch -> cancel + EPROTO (att.c 761). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP;
	put_le16(rsp + 1, 3);
	put_le16(rsp + 3, 0);
	rsp[5] = 0xFF;			/* wrong value (requested 0xAA) */
	cl_preload(peer, rsp, 6);
	/* The mismatch triggers an Execute Write (cancel); answer it. */
	{
		uint8_t ex[1] = { BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_RSP };
		cl_preload(peer, ex, 1);
	}
	ATF_CHECK_EQ(att_prepare_write(&ac, 3, 0, "\xAA", 1), -1);
	cl_cleanup(&ac, peer);
}

/*
 * Finding 1: att_eatt_select_bearer() charges pending++ per selection.  A
 * Write Command (Core Spec Vol 3 Part F §3.4.5.3) has no response phase, so
 * that charge is never repaid on the success path -- pre-fix, pending grew by
 * one per command and the bearer looked permanently "most loaded", starving
 * the least-loaded selector.  Post-fix, pending returns to baseline.
 */
ATF_TC_WITHOUT_HEAD(test_write_cmd_pending_no_leak);
ATF_TC_BODY(test_write_cmd_pending_no_leak, tc)
{
	struct att_conn ac;
	int peer, eb[2];

	cl_pair(&ac, &peer);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, eb) == 0);
	ac.eatt_count = 1;
	ac.eatt[0].fd = eb[0];
	ac.eatt[0].active = true;
	ac.eatt[0].mtu = 100;
	ac.eatt[0].pending = 0;

	for (int i = 0; i < 8; i++)
		ATF_CHECK_EQ(att_write_cmd(&ac, 3, "\x01\x02", 2), 0);

	ATF_CHECK_EQ_MSG(ac.eatt[0].pending, 0,
	    "Write Command has no response; pending must return to baseline "
	    "(pre-fix grew by one per command)");

	ac.eatt_count = 0;
	ac.eatt[0].fd = -1;
	close(eb[0]);
	close(eb[1]);
	cl_cleanup(&ac, peer);
}

/*
 * Finding 1: an errored request must also release the bearer slot it
 * reserved.  att_request()'s transport-error early returns (here a recv()
 * EAGAIN, since nothing is queued on the nonblocking bearer) previously
 * skipped the pending-- and leaked the counter.
 */
ATF_TC_WITHOUT_HEAD(test_request_error_pending_restored);
ATF_TC_BODY(test_request_error_pending_restored, tc)
{
	struct att_conn ac;
	int peer, eb[2];
	uint8_t out[8];
	size_t outlen;

	cl_pair(&ac, &peer);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, eb) == 0);
	ATF_REQUIRE(fcntl(eb[0], F_SETFL, O_NONBLOCK) == 0);
	ac.eatt_count = 1;
	ac.eatt[0].fd = eb[0];
	ac.eatt[0].active = true;
	ac.eatt[0].mtu = 100;
	ac.eatt[0].pending = 0;

	/* No response queued on the bearer: recv() -> EAGAIN -> -1. */
	ATF_CHECK_EQ(att_read(&ac, 3, out, sizeof(out), &outlen), -1);
	ATF_CHECK_EQ_MSG(ac.eatt[0].pending, 0,
	    "an errored request must release the bearer slot it reserved "
	    "(pre-fix leaked pending on the transport-error path)");

	ac.eatt_count = 0;
	ac.eatt[0].fd = -1;
	close(eb[0]);
	close(eb[1]);
	cl_cleanup(&ac, peer);
}

/*
 * Finding 2: Prepare Write Response value-echo integrity check.  Core Spec
 * Vol 3 Part F §3.4.6.2 requires the response Part Attribute Value to equal
 * the value in the request, so the response must carry the FULL echoed value.
 * A server that returns a truncated echo (fewer value octets than were
 * written) must be rejected -- pre-fix the memcmp was guarded by
 * "n >= 5 + len", so a short echo bypassed the check and was accepted.
 */
ATF_TC_WITHOUT_HEAD(test_prepare_write_short_echo);
ATF_TC_BODY(test_prepare_write_short_echo, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[8];

	cl_pair(&ac, &peer);
	/* Requested value is 2 octets; server echoes only 1 (truncated). */
	rsp[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP;
	put_le16(rsp + 1, 3);		/* correct handle */
	put_le16(rsp + 3, 0);		/* correct offset */
	rsp[5] = 0xAA;			/* only 1 of the 2 value octets */
	cl_preload(peer, rsp, 6);	/* n == 6 < 5 + 2 */
	/* Rejection cancels the queue via Execute Write; answer it. */
	{
		uint8_t ex[1] = { BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_RSP };
		cl_preload(peer, ex, 1);
	}
	ATF_CHECK_EQ_MSG(att_prepare_write(&ac, 3, 0, "\xAA\xBB", 2), -1,
	    "truncated value echo must be rejected (Vol 3 Part F 3.4.6.2)");
	ATF_CHECK_EQ(errno, EPROTO);
	cl_cleanup(&ac, peer);
}

/* Fixed-size ATT responses and Prepare Write echoes have exact PDU sizes. */
ATF_TC_WITHOUT_HEAD(test_response_trailing_octets_rejected);
ATF_TC_BODY(test_response_trailing_octets_rejected, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[8];

	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_MTU_RSP;
	put_le16(rsp + 1, 100);
	rsp[3] = 0xff;
	cl_preload(peer, rsp, 4);
	ATF_CHECK_EQ(-1, att_exchange_mtu(&ac, 100));
	ATF_CHECK_EQ(EPROTO, errno);
	cl_cleanup(&ac, peer);

	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_WRITE_RSP;
	rsp[1] = 0xff;
	cl_preload(peer, rsp, 2);
	ATF_CHECK_EQ(-1, att_write_req(&ac, 3, "\xaa", 1));
	ATF_CHECK_EQ(EPROTO, errno);
	cl_cleanup(&ac, peer);

	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_RSP;
	rsp[1] = 0xff;
	cl_preload(peer, rsp, 2);
	ATF_CHECK_EQ(-1, att_execute_write(&ac, 0));
	ATF_CHECK_EQ(EPROTO, errno);
	cl_cleanup(&ac, peer);

	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP;
	put_le16(rsp + 1, 3);
	put_le16(rsp + 3, 0);
	rsp[5] = 0xaa;
	rsp[6] = 0xff;
	cl_preload(peer, rsp, 7);
	/* The mismatch path cancels the prepared-write queue. */
	rsp[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_RSP;
	cl_preload(peer, rsp, 1);
	ATF_CHECK_EQ(-1, att_prepare_write(&ac, 3, 0, "\xaa", 1));
	ATF_CHECK_EQ(EPROTO, errno);
	cl_cleanup(&ac, peer);
}

/*
 * Finding 5: Service Changed indications must be matched by the
 * characteristic's value handle, not by length alone (Core Spec Vol 3 Part G
 * §2.5.2 identifies Service Changed by the characteristic).  The daemon's
 * hogp_event_loop_once() previously treated ANY 4-byte indication on ANY
 * handle as Service Changed and invalidated the cached GATT handles; the
 * decision now runs through gatt_indication_is_service_changed().
 */
ATF_TC_WITHOUT_HEAD(test_service_changed_match_by_handle);
ATF_TC_BODY(test_service_changed_match_by_handle, tc)
{
	/* Recorded Service Changed value handle from discovery. */
	const uint16_t sc = 0x0013;

	/* A 4-byte indication on the recorded handle IS Service Changed. */
	ATF_CHECK_MSG(gatt_indication_is_service_changed(sc, 0x0013, 4),
	    "4-byte indication on the Service Changed handle must match");

	/*
	 * A 4-byte indication on any OTHER handle must NOT be treated as
	 * Service Changed -- this is the regression: length-only matching
	 * would (wrongly) invalidate the handle cache here.
	 */
	ATF_CHECK_MSG(!gatt_indication_is_service_changed(sc, 0x0020, 4),
	    "4-byte indication on a non-Service-Changed handle must NOT match");

	/* No recorded handle (characteristic absent) never matches. */
	ATF_CHECK_MSG(!gatt_indication_is_service_changed(0, 0x0013, 4),
	    "zero recorded handle must never match");

	/* Right handle but wrong length is not a Service Changed value. */
	ATF_CHECK_MSG(!gatt_indication_is_service_changed(sc, 0x0013, 2),
	    "a non-4-byte indication is not a Service Changed value");
}

/* ================================================================
 * Residual decoder-tail arms:
 *   - success-path outlen==NULL for att_read and att_recv;
 *   - the outlen==NULL branch inside each ATTR_NOT_FOUND early return;
 *   - wrong-opcode (correct-length) response rejection;
 *   - Find By Type Value / Prepare Write reqlen>MTU (EMSGSIZE);
 *   - att_close() on an already-closed conn (fd < 0);
 *   - att_eatt_select_bearer skipping an inactive bearer;
 *   - a 4-byte (short) ATT Error Response reaching the sender's
 *     opcode check instead of being treated as an error.
 * Oracle: Core Spec Vol 3 Part F 3.4 (error codes / PDU lengths).
 * ================================================================ */

/* Build an ATT Error Response (Vol 3 Part F 3.4.1.1). */
static void
dc_err(uint8_t *out, uint8_t reqop, uint16_t handle, uint8_t code)
{
	out[0] = BT_CORE63_WIRE_ATT_OP_ERROR_RSP;
	out[1] = reqop;
	put_le16(out + 2, handle);
	out[4] = code;
}

/*
 * Preload one response datagram on a FRESH socketpair, invoke the caller's
 * expression, and tear down.  Each sub-check gets its own bearer so an
 * unread request datagram from a prior call cannot perturb the next recv
 * (SEQPACKET ordering on a shared pair is otherwise fragile).
 */
#define ONE_SHOT(preload_stmt, call_expr, expect)			\
	do {								\
		struct att_conn ac__;					\
		int peer__;						\
		cl_pair(&ac__, &peer__);				\
		{ struct att_conn *ac = &ac__; int peer = peer__;	\
		  preload_stmt; (void)ac; (void)peer; }			\
		{ struct att_conn *ac = &ac__;				\
		  ATF_CHECK_EQ(call_expr, expect); (void)ac; }		\
		cl_cleanup(&ac__, peer__);				\
	} while (0)

ATF_TC_WITHOUT_HEAD(test_read_recv_null_outlen);
ATF_TC_BODY(test_read_recv_null_outlen, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[4], ntf[4];
	uint8_t buf[64];

	/* att_read() success with outlen == NULL (att.c ~436). */
	cl_pair(&ac, &peer);
	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_RSP;
	rsp[1] = 0xAA; rsp[2] = 0xBB; rsp[3] = 0xCC;
	cl_preload(peer, rsp, sizeof(rsp));
	ATF_CHECK_EQ(att_read(&ac, 3, buf, sizeof(buf), NULL), 0);

	/* att_recv() success with outlen == NULL (att.c ~1098). */
	ntf[0] = BT_CORE63_WIRE_ATT_OP_HANDLE_NOTIFY;
	ntf[1] = 0x03; ntf[2] = 0x00; ntf[3] = 0x42;
	cl_preload(peer, ntf, sizeof(ntf));
	ATF_CHECK_EQ(att_recv(&ac, buf, sizeof(buf), NULL), 0);
	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_attr_not_found_null_outlen);
ATF_TC_BODY(test_attr_not_found_null_outlen, tc)
{
	uint8_t e[5];
	uint8_t buf[64];
	uint8_t u128[16] = { 0 };

	/*
	 * ATTR_NOT_FOUND (0x0A) collapses to an empty success result; with
	 * outlen == NULL the *outlen store is skipped.  A fresh bearer per
	 * call keeps SEQPACKET framing clean.
	 */
	dc_err(e, BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ, 1, BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND);
	ONE_SHOT(cl_preload(peer, e, sizeof(e)),
	    att_find_info(ac, 1, 0xFFFF, buf, sizeof(buf), NULL), 0);

	dc_err(e, BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ, 1, BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND);
	ONE_SHOT(cl_preload(peer, e, sizeof(e)),
	    att_read_by_type(ac, 1, 0xFFFF, 0x2803, buf, sizeof(buf), NULL), 0);

	dc_err(e, BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ, 1, BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND);
	ONE_SHOT(cl_preload(peer, e, sizeof(e)),
	    att_read_by_type_uuid128(ac, 1, 0xFFFF, u128, buf, sizeof(buf),
	    NULL), 0);

	dc_err(e, BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ, 1, BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND);
	ONE_SHOT(cl_preload(peer, e, sizeof(e)),
	    att_read_by_group_type(ac, 1, 0xFFFF, 0x2800, buf, sizeof(buf),
	    NULL), 0);

	dc_err(e, BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ, 1, BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND);
	ONE_SHOT(cl_preload(peer, e, sizeof(e)),
	    att_find_by_type_value(ac, 1, 0xFFFF, 0x2800, "\x00\x18", 2, buf,
	    sizeof(buf), NULL), 0);
}

ATF_TC_WITHOUT_HEAD(test_wrong_opcode_responses);
ATF_TC_BODY(test_wrong_opcode_responses, tc)
{
	uint8_t rsp[8];
	uint8_t buf[64];
	size_t outlen;

	/*
	 * A response whose opcode is neither an Error Response nor the
	 * expected *_RSP (but of valid length) must be rejected with EPROTO
	 * (Vol 3 Part F 3.4: response opcode must match the request).
	 */
	memset(rsp, 0, sizeof(rsp));
	rsp[0] = 0x55;

	ONE_SHOT(cl_preload(peer, rsp, sizeof(rsp)),
	    att_find_by_type_value(ac, 1, 0xFFFF, 0x2800, "\x00\x18", 2, buf,
	    sizeof(buf), &outlen), -1);
	ONE_SHOT(cl_preload(peer, rsp, sizeof(rsp)),
	    att_read_by_type(ac, 1, 0xFFFF, 0x2803, buf, sizeof(buf), &outlen),
	    -1);
	ONE_SHOT(cl_preload(peer, rsp, sizeof(rsp)),
	    att_read_by_group_type(ac, 1, 0xFFFF, 0x2800, buf, sizeof(buf),
	    &outlen), -1);
	ONE_SHOT(cl_preload(peer, rsp, sizeof(rsp)),
	    att_find_info(ac, 1, 0xFFFF, buf, sizeof(buf), &outlen), -1);
	ONE_SHOT(cl_preload(peer, rsp, sizeof(rsp)),
	    att_prepare_write(ac, 3, 0, "\xAA", 1), -1);
}

ATF_TC_WITHOUT_HEAD(test_reqlen_over_mtu);
ATF_TC_BODY(test_reqlen_over_mtu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[64];
	uint8_t big[64];
	size_t outlen;

	/* reqlen > ac->mtu -> EMSGSIZE (Vol 3 Part F: PDU must fit the MTU). */
	cl_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;		/* 23 */
	memset(big, 0x11, sizeof(big));

	/* Find By Type Value: reqlen = 7 + vlen; vlen 40 -> 47 > 23. */
	ATF_CHECK_EQ(att_find_by_type_value(&ac, 1, 0xFFFF, 0x2800, big, 40,
	    buf, sizeof(buf), &outlen), -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);

	/* Prepare Write: reqlen = 5 + len; len 40 -> 45 > 23. */
	ATF_CHECK_EQ(att_prepare_write(&ac, 3, 0, big, 40), -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_close_already_closed);
ATF_TC_BODY(test_close_already_closed, tc)
{
	struct att_conn ac;

	/* att_close() on a conn whose fd is already -1 (att.c ~157). */
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	ac.bearer_fd = -1;
	ac.buf = malloc(16);
	ATF_REQUIRE(ac.buf != NULL);
	att_close(&ac);
	ATF_CHECK_MSG(ac.buf == NULL, "att_close frees buf even with fd<0");
	ATF_CHECK_EQ(ac.fd, -1);
}

ATF_TC_WITHOUT_HEAD(test_select_skips_inactive_bearer);
ATF_TC_BODY(test_select_skips_inactive_bearer, tc)
{
	struct att_conn ac;
	int a[2], b[2];

	/*
	 * att_eatt_select_bearer must skip a bearer that is inactive or has
	 * fd < 0 (Vol 3 Part G 5.3 least-loaded selection over *active*
	 * bearers) and return the remaining active bearer's fd.
	 */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, a) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, b) == 0);
	memset(&ac, 0, sizeof(ac));
	ac.fd = -1;
	ac.eatt_count = 3;
	ac.eatt[0].fd = a[0];
	ac.eatt[0].active = false;		/* inactive -> skipped */
	ac.eatt[1].fd = -1;			/* active but fd<0 -> skipped */
	ac.eatt[1].active = true;
	ac.eatt[2].fd = b[0];
	ac.eatt[2].active = true;
	ATF_CHECK_EQ_MSG(att_eatt_select_bearer(&ac), b[0],
	    "selector skips inactive and fd<0 bearers, returns the active one");
	close(a[0]); close(a[1]); close(b[0]); close(b[1]);
}

ATF_TC_WITHOUT_HEAD(test_short_error_response);
ATF_TC_BODY(test_short_error_response, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t shorterr[4];
	uint8_t buf[64];

	/*
	 * A 4-byte PDU opening with the Error Response opcode is too short to
	 * be a valid Error Response (which is 5 bytes, Vol 3 Part F 3.4.1.1),
	 * so att_request() rejects it as a bearer protocol fault.  EPROTO is
	 * reserved for a well-formed, correlated ATT Error Response.
	 */
	cl_pair(&ac, &peer);
	shorterr[0] = BT_CORE63_WIRE_ATT_OP_ERROR_RSP;
	shorterr[1] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	shorterr[2] = 0x03; shorterr[3] = 0x00;		/* only 4 bytes */
	cl_preload(peer, shorterr, sizeof(shorterr));
	ATF_CHECK_EQ(att_read(&ac, 3, buf, sizeof(buf), NULL), -1);
	ATF_CHECK_EQ(errno, EBADMSG);
	ATF_CHECK(ac.failed);
	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_reqlen_over_bufsize);
ATF_TC_BODY(test_reqlen_over_bufsize, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[64];
	uint8_t big[600];
	size_t outlen;

	/*
	 * With a large MTU the request still must fit the PDU staging buffer
	 * (ATT_PDU_BUF_SIZE = 517).  reqlen > sizeof(req) -> EMSGSIZE even
	 * though reqlen <= MTU (this is the second operand of the guard).
	 */
	cl_pair(&ac, &peer);
	ac.mtu = 600;				/* > ATT_PDU_BUF_SIZE */
	memset(big, 0x22, sizeof(big));

	/* Find By Type Value: reqlen = 7 + 520 = 527 > 517. */
	ATF_CHECK_EQ(att_find_by_type_value(&ac, 1, 0xFFFF, 0x2800, big, 520,
	    buf, sizeof(buf), &outlen), -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);

	/* Prepare Write: reqlen = 5 + 520 = 525 > 517. */
	ATF_CHECK_EQ(att_prepare_write(&ac, 3, 0, big, 520), -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);

	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_short_valid_opcode_responses);
ATF_TC_BODY(test_short_valid_opcode_responses, tc)
{
	uint8_t rsp[4];
	uint8_t buf[64];
	size_t outlen;

	/*
	 * A response carrying the correct opcode but fewer than the minimum
	 * bytes is malformed (Vol 3 Part F 3.4): Prepare Write Response needs
	 * >= 5 bytes; Read By Type Response needs >= 2.  These exercise the
	 * length (second) operand of each opcode/length guard.
	 */
	rsp[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP;	/* only 3 bytes (< 5) */
	rsp[1] = 0x03; rsp[2] = 0x00;
	ONE_SHOT(cl_preload(peer, rsp, 3),
	    att_prepare_write(ac, 3, 0, "\xAA", 1), -1);

	rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_RSP;	/* only 1 byte (< 2) */
	ONE_SHOT(cl_preload(peer, rsp, 1),
	    att_read_by_type(ac, 1, 0xFFFF, 0x2803, buf, sizeof(buf), &outlen),
	    -1);

	/* Same short Read By Type Response via the 128-bit-UUID variant. */
	{
		uint8_t u128[16] = { 0 };
		rsp[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_RSP;
		ONE_SHOT(cl_preload(peer, rsp, 1),
		    att_read_by_type_uuid128(ac, 1, 0xFFFF, u128, buf,
		    sizeof(buf), &outlen), -1);
	}
}

ATF_TC_WITHOUT_HEAD(test_find_info_other_error);
ATF_TC_BODY(test_find_info_other_error, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t e[5];
	uint8_t buf[64];
	size_t outlen;

	/*
	 * An EPROTO Error Response whose code is NOT Attribute Not Found is
	 * returned to the caller as that error code (Vol 3 Part F 3.4.1.1),
	 * exercising the "errno == EPROTO ? ae.code" true arm distinct from
	 * the ATTR_NOT_FOUND empty-result collapse.
	 */
	cl_pair(&ac, &peer);
	dc_err(e, BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ, 5, BT_CORE63_WIRE_ATT_ERR_INVALID_HANDLE);
	cl_preload(peer, e, sizeof(e));
	ATF_CHECK_EQ(att_find_info(&ac, 1, 0xFFFF, buf, sizeof(buf), &outlen),
	    BT_CORE63_WIRE_ATT_ERR_INVALID_HANDLE);
	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_bearer_release_no_match);
ATF_TC_BODY(test_bearer_release_no_match, tc)
{
	struct att_conn ac;
	int peer;

	/*
	 * When EATT bearers exist but all are inactive, att_request /
	 * att_write_cmd fall back to the primary bearer; releasing the
	 * primary fd hits att_eatt_bearer_release's "fd == ac->fd" early
	 * return (att.c ~183), leaving every EATT bearer's pending count
	 * untouched (Core Spec Vol 3 Part G 5.3 load accounting).
	 */
	cl_pair(&ac, &peer);
	ac.eatt_count = 1;
	ac.eatt[0].fd = 0x7fff;			/* never equals the primary fd */
	ac.eatt[0].active = false;		/* inactive -> select skips it */
	ac.eatt[0].pending = 0;
	/* Write Command takes the select+release path with no response. */
	ATF_CHECK_EQ(att_write_cmd(&ac, 0x0003, "\x01", 1), 0);
	ATF_CHECK_EQ_MSG(ac.eatt[0].pending, 0,
	    "primary-bearer release must not touch an EATT bearer's counter");
	ac.eatt_count = 0;			/* fd was a sentinel, not real */
	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_error_response_opcode_correlation);
ATF_TC_BODY(test_error_response_opcode_correlation, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t e[5], buf[8];

	cl_pair(&ac, &peer);
	dc_err(e, BT_CORE63_WIRE_ATT_OP_WRITE_REQ, 3, BT_CORE63_WIRE_ATT_ERR_INVALID_HANDLE);
	cl_preload(peer, e, sizeof(e));
	ATF_CHECK_EQ(att_read(&ac, 3, buf, sizeof(buf), NULL), -1);
	ATF_CHECK_EQ(errno, EBADMSG);
	ATF_CHECK_MSG(ac.failed,
	    "an Error Response for another request invalidates this bearer");
	cl_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_eatt_failure_isolated);
ATF_TC_BODY(test_eatt_failure_isolated, tc)
{
	struct att_conn ac;
	int peer, ep[2];
	uint8_t rsp[2] = { BT_CORE63_WIRE_ATT_OP_READ_RSP, 0x5a };
	uint8_t buf[8];
	size_t outlen;

	cl_pair(&ac, &peer);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ep));
	ac.eatt[0].fd = ep[0];
	ac.eatt[0].mtu = ATT_DEFAULT_MTU;
	ac.eatt[0].active = true;
	ac.eatt_count = 1;
	ATF_REQUIRE_EQ(0, shutdown(ep[1], SHUT_WR));
	ATF_CHECK_EQ(att_read(&ac, 3, buf, sizeof(buf), &outlen), -1);
	ATF_CHECK_MSG(!ac.failed, "EATT failure must not poison the primary");
	ATF_CHECK_EQ(ac.eatt_count, 0);

	cl_preload(peer, rsp, sizeof(rsp));
	ATF_CHECK_EQ(att_read(&ac, 3, buf, sizeof(buf), &outlen), 0);
	ATF_CHECK_EQ(outlen, 1u);
	ATF_CHECK_EQ(buf[0], 0x5a);
	close(ep[1]);
	cl_cleanup(&ac, peer);
}

/* Unsolicited EATT traffic and indication confirmation stay on that bearer. */
ATF_TC_WITHOUT_HEAD(test_eatt_recv_confirm_bearer);
ATF_TC_BODY(test_eatt_recv_confirm_bearer, tc)
{
	struct att_conn ac;
	uint8_t pdu[4] = { BT_CORE63_WIRE_ATT_OP_HANDLE_IND, 0x34, 0x12, 0xaa };
	uint8_t buf[8], confirm;
	size_t len;
	int fixed_peer, ep[2];

	cl_pair(&ac, &fixed_peer);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ep));
	ATF_REQUIRE_EQ((ssize_t)sizeof(pdu),
	    send(ep[1], pdu, sizeof(pdu), MSG_EOR));
	ATF_REQUIRE_EQ(0,
	    att_recv_bearer(&ac, ep[0], buf, sizeof(buf), &len));
	ATF_CHECK_EQ(len, sizeof(pdu));
	ATF_CHECK_EQ(memcmp(buf, pdu, sizeof(pdu)), 0);
	ATF_REQUIRE_EQ(0, att_confirm_bearer(&ac, ep[0]));
	ATF_REQUIRE_EQ(1, recv(ep[1], &confirm, sizeof(confirm), 0));
	ATF_CHECK_EQ(confirm, BT_CORE63_WIRE_ATT_OP_HANDLE_CFM);

	close(ep[0]);
	close(ep[1]);
	cl_cleanup(&ac, fixed_peer);
}

/* EATT notifications interleaved before a response must be processed. */
ATF_TC_WITHOUT_HEAD(test_eatt_request_delivers_notification);
ATF_TC_BODY(test_eatt_request_delivers_notification, tc)
{
	struct att_conn ac;
	uint8_t ntf[] = { BT_CORE63_WIRE_ATT_OP_HANDLE_NOTIFY, 0x34, 0x12, 0xaa };
	uint8_t rsp[] = { BT_CORE63_WIRE_ATT_OP_READ_RSP, 0x5a };
	uint8_t value[4];
	size_t outlen;
	int fixed_peer, ep[2];

	cl_pair(&ac, &fixed_peer);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ep));
	ac.eatt[0].fd = ep[0];
	ac.eatt[0].mtu = ATT_DEFAULT_MTU;
	ac.eatt[0].active = true;
	ac.eatt_count = 1;
	unsolicited_count = 0;
	unsolicited_fd = -1;
	unsolicited_opcode = 0;
	att_set_unsolicited_handler(&ac, cl_unsolicited, NULL);
	for (int i = 0; i < 20; i++)
		cl_preload(ep[1], ntf, sizeof(ntf));
	cl_preload(ep[1], rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(0, att_read(&ac, 3, value, sizeof(value), &outlen));
	ATF_CHECK_EQ(unsolicited_count, 20);
	ATF_CHECK_EQ(unsolicited_fd, ep[0]);
	ATF_CHECK_EQ(unsolicited_opcode, BT_CORE63_WIRE_ATT_OP_HANDLE_NOTIFY);

	ac.eatt_count = 0;
	close(ep[0]);
	close(ep[1]);
	cl_cleanup(&ac, fixed_peer);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test_bearer_release_no_match);
	ATF_TP_ADD_TC(tp, test_error_response_opcode_correlation);
	ATF_TP_ADD_TC(tp, test_eatt_failure_isolated);
	ATF_TP_ADD_TC(tp, test_eatt_recv_confirm_bearer);
	ATF_TP_ADD_TC(tp, test_eatt_request_delivers_notification);
	ATF_TP_ADD_TC(tp, test_reqlen_over_bufsize);
	ATF_TP_ADD_TC(tp, test_short_valid_opcode_responses);
	ATF_TP_ADD_TC(tp, test_find_info_other_error);
	ATF_TP_ADD_TC(tp, test_read_recv_null_outlen);
	ATF_TP_ADD_TC(tp, test_attr_not_found_null_outlen);
	ATF_TP_ADD_TC(tp, test_wrong_opcode_responses);
	ATF_TP_ADD_TC(tp, test_reqlen_over_mtu);
	ATF_TP_ADD_TC(tp, test_close_already_closed);
	ATF_TP_ADD_TC(tp, test_select_skips_inactive_bearer);
	ATF_TP_ADD_TC(tp, test_short_error_response);
	ATF_TP_ADD_TC(tp, test_service_changed_match_by_handle);
	ATF_TP_ADD_TC(tp, test_write_cmd_pending_no_leak);
	ATF_TP_ADD_TC(tp, test_request_error_pending_restored);
	ATF_TP_ADD_TC(tp, test_prepare_write_short_echo);
	ATF_TP_ADD_TC(tp, test_response_trailing_octets_rejected);
	ATF_TP_ADD_TC(tp, test_client_sender_guards);
	ATF_TP_ADD_TC(tp, test_request_over_eatt_bearer);
	ATF_TP_ADD_TC(tp, test_senders_null_outlen);
	ATF_TP_ADD_TC(tp, test_senders_transport_failure);
	ATF_TP_ADD_TC(tp, test_senders_attr_not_found);
	ATF_TP_ADD_TC(tp, test_request_multi_ntf_skip);
	ATF_TP_ADD_TC(tp, test_bearer_fallback_degenerate);
	ATF_TP_ADD_TC(tp, test_att_close);
	ATF_TP_ADD_TC(tp, test_att_open_fd_connect_fail);
	ATF_TP_ADD_TC(tp, test_mtu_bad_response);
	ATF_TP_ADD_TC(tp, test_mtu_server_below_floor);
	ATF_TP_ADD_TC(tp, test_payload_truncation_clamps);
	ATF_TP_ADD_TC(tp, test_malformed_responses);
	ATF_TP_ADD_TC(tp, test_write_req_oversize);
	ATF_TP_ADD_TC(tp, test_write_cmd_paths);
	ATF_TP_ADD_TC(tp, test_write_cmd_prefers_largest_bearer);
	ATF_TP_ADD_TC(tp, test_read_multiple_reqlen);
	ATF_TP_ADD_TC(tp, test_prepare_write_echo);
	ATF_TP_ADD_TC(tp, test_write_long_execute_fail);
	ATF_TP_ADD_TC(tp, test_recv_and_confirm);
	ATF_TP_ADD_TC(tp, test_request_interleave);
	ATF_TP_ADD_TC(tp, test_request_indication_flood);
	ATF_TP_ADD_TC(tp, test_request_notification_flood);
	ATF_TP_ADD_TC(tp, test_request_peer_closed);

	return (atf_no_error());
}
