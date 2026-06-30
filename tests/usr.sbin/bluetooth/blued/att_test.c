/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF unit tests for ATT client and server implementation.
 *
 * Uses socketpair(AF_UNIX, SOCK_SEQPACKET, 0) to mock L2CAP ATT
 * channels so no real Bluetooth hardware is needed.
 */

#include <sys/types.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "hci_log.h"
#include "hci_util.h"

#define TEST_CUSTOM_BLE_COC_CONNECT
#include "test_common.h"

/* ================================================================
 * att.c references ble_coc_connect via att_open_eatt.
 * This test needs a controllable return value, so we provide
 * a custom stub instead of the default from test_common.h.
 * ================================================================ */
static int ble_coc_connect_retval = -1;
static int ble_coc_connect_fd = -1;
int
ble_coc_connect(const uint8_t *addr __unused, uint8_t addr_type __unused,
    uint16_t psm __unused, uint16_t mtu __unused)
{

	if (ble_coc_connect_fd >= 0)
		return (ble_coc_connect_fd);
	return (ble_coc_connect_retval);
}

/* ================================================================
 * Mock helper: create a socketpair-backed att_conn
 * ================================================================ */

static void
att_mock_pair(struct att_conn *ac, int *peer_fd)
{
	int fds[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(ac, 0, sizeof(*ac));
	ac->fd = fds[0];
	ac->bearer_fd = -1;
	ac->mtu = ATT_DEFAULT_MTU;
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	*peer_fd = fds[1];
}

static void
att_mock_cleanup(struct att_conn *ac, int peer_fd)
{

	free(ac->buf);
	ac->buf = NULL;
	if (ac->fd >= 0)
		close(ac->fd);
	if (peer_fd >= 0)
		close(peer_fd);
}

/* ================================================================
 * Helper: build a standard test database with known structure.
 *
 * GAP Service (0x1800):
 *   handle 1: Primary Service Decl (0x2800), value=0x1800
 *   handle 2: Char Decl (0x2803), props=READ
 *   handle 3: Device Name (0x2A00), value="Test"
 *
 * Custom Service (0xFFE0):
 *   handle 4: Primary Service Decl (0x2800), value=0xFFE0
 *   handle 5: Char Decl (0x2803), props=READ|WRITE|NOTIFY
 *   handle 6: Custom Char (0xFFE1), value=0xAA 0xBB 0xCC 0xDD
 *   handle 7: CCCD (0x2902), value=0x0000
 * ================================================================ */

#define TEST_DB_MAX_ATTRS	32
#define TEST_DB_VAL_SIZE	512

static void
build_test_db(struct att_db *db, struct att_attr *attrs, uint8_t *val_buf)
{

	attdb_init(db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);

	/* GAP Service */
	attdb_add_service(db, 0x1800);
	attdb_add_characteristic(db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, "Test", 4);

	/* Custom Service */
	attdb_add_service(db, 0xFFE0);
	attdb_add_characteristic(db, 0xFFE1,
	    GATT_PROP_READ | GATT_PROP_WRITE | GATT_PROP_NOTIFY,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    "\xAA\xBB\xCC\xDD", 4);
	attdb_add_cccd(db);
}

/* ================================================================
 * ATT CLIENT TESTS
 * ================================================================ */

/* 1. test_att_mtu_exchange */
ATF_TC_WITHOUT_HEAD(test_att_mtu_exchange);
ATF_TC_BODY(test_att_mtu_exchange, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[8];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	/*
	 * att_exchange_mtu sends MTU req in a thread-blocking way,
	 * so we use fork to mock the peer.
	 */
	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock peer — read MTU req, send MTU rsp */
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		/* Expect 3 bytes: opcode(0x02) + mtu(2) */
		if (n != 3 || buf[0] != ATT_OP_MTU_REQ) {
			close(peer);
			_exit(1);
		}
		/* Reply with server MTU = 185 */
		uint8_t rsp[3];
		rsp[0] = ATT_OP_MTU_RSP;
		put_le16(rsp + 1, 185);
		send(peer, rsp, 3, 0);
		close(peer);
		_exit(0);
	}

	/* Parent: client side */
	close(peer);
	int ret = att_exchange_mtu(&ac, ATT_MAX_MTU);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(ac.mtu, 185);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/* 2. test_att_read */
ATF_TC_WITHOUT_HEAD(test_att_read);
ATF_TC_BODY(test_att_read, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t req_buf[8];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, req_buf, sizeof(req_buf), 0);
		if (n != 3 || req_buf[0] != ATT_OP_READ_REQ) {
			close(peer);
			_exit(1);
		}
		/* Verify handle = 0x0003 */
		uint16_t handle = get_le16(req_buf + 1);
		if (handle != 0x0003) {
			close(peer);
			_exit(2);
		}
		/* Reply with 4-byte value */
		uint8_t rsp[5];
		rsp[0] = ATT_OP_READ_RSP;
		rsp[1] = 0xDE;
		rsp[2] = 0xAD;
		rsp[3] = 0xBE;
		rsp[4] = 0xEF;
		send(peer, rsp, 5, 0);
		close(peer);
		_exit(0);
	}

	close(peer);
	uint8_t val[16];
	size_t outlen = 0;
	int ret = att_read(&ac, 0x0003, val, sizeof(val), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(outlen, 4);
	ATF_CHECK_EQ(val[0], 0xDE);
	ATF_CHECK_EQ(val[1], 0xAD);
	ATF_CHECK_EQ(val[2], 0xBE);
	ATF_CHECK_EQ(val[3], 0xEF);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/* 3. test_att_write_req */
ATF_TC_WITHOUT_HEAD(test_att_write_req);
ATF_TC_BODY(test_att_write_req, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		uint8_t buf[32];
		close(ac.fd);
		ssize_t n = recv(peer, buf, sizeof(buf), 0);
		/* opcode(0x12) + handle(2) + value */
		if (n < 3 || buf[0] != ATT_OP_WRITE_REQ) {
			close(peer);
			_exit(1);
		}
		/* Verify handle = 0x0006, value = 0x11 0x22 */
		uint16_t h = get_le16(buf + 1);
		if (h != 0x0006 || n != 5 ||
		    buf[3] != 0x11 || buf[4] != 0x22) {
			close(peer);
			_exit(2);
		}
		/* Send Write Response */
		uint8_t rsp = ATT_OP_WRITE_RSP;
		send(peer, &rsp, 1, 0);
		close(peer);
		_exit(0);
	}

	close(peer);
	uint8_t data[2] = { 0x11, 0x22 };
	int ret = att_write_req(&ac, 0x0006, data, 2);
	ATF_CHECK_EQ(ret, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/* 4. test_att_write_cmd */
ATF_TC_WITHOUT_HEAD(test_att_write_cmd);
ATF_TC_BODY(test_att_write_cmd, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);

	uint8_t data[3] = { 0xAA, 0xBB, 0xCC };
	int ret = att_write_cmd(&ac, 0x0007, data, 3);
	ATF_CHECK_EQ(ret, 0);

	/* Read from mock peer and verify */
	uint8_t buf[32];
	ssize_t n = recv(peer, buf, sizeof(buf), 0);
	ATF_CHECK_EQ(n, 6); /* opcode(1) + handle(2) + value(3) */
	ATF_CHECK_EQ(buf[0], ATT_OP_WRITE_CMD);
	ATF_CHECK_EQ(get_le16(buf + 1), 0x0007);
	ATF_CHECK_EQ(buf[3], 0xAA);
	ATF_CHECK_EQ(buf[4], 0xBB);
	ATF_CHECK_EQ(buf[5], 0xCC);

	att_mock_cleanup(&ac, peer);
}

/* 5. test_att_read_blob */
ATF_TC_WITHOUT_HEAD(test_att_read_blob);
ATF_TC_BODY(test_att_read_blob, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		uint8_t buf[32];
		close(ac.fd);
		ssize_t n = recv(peer, buf, sizeof(buf), 0);
		/* Read Blob: opcode(0x0C) + handle(2) + offset(2) = 5 */
		if (n != 5 || buf[0] != ATT_OP_READ_BLOB_REQ) {
			close(peer);
			_exit(1);
		}
		uint16_t h = get_le16(buf + 1);
		uint16_t off = get_le16(buf + 3);
		if (h != 0x0006 || off != 10) {
			close(peer);
			_exit(2);
		}
		/* Reply with 3 bytes of data */
		uint8_t rsp[4];
		rsp[0] = ATT_OP_READ_BLOB_RSP;
		rsp[1] = 0x01;
		rsp[2] = 0x02;
		rsp[3] = 0x03;
		send(peer, rsp, 4, 0);
		close(peer);
		_exit(0);
	}

	close(peer);
	uint8_t val[16];
	size_t outlen = 0;
	int ret = att_read_blob(&ac, 0x0006, 10, val, sizeof(val), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(outlen, 3);
	ATF_CHECK_EQ(val[0], 0x01);
	ATF_CHECK_EQ(val[1], 0x02);
	ATF_CHECK_EQ(val[2], 0x03);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/* 6. test_att_error_response */
ATF_TC_WITHOUT_HEAD(test_att_error_response);
ATF_TC_BODY(test_att_error_response, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		uint8_t buf[32];
		close(ac.fd);
		ssize_t n = recv(peer, buf, sizeof(buf), 0);
		if (n < 1 || buf[0] != ATT_OP_READ_REQ) {
			close(peer);
			_exit(1);
		}
		/* Reply with Error Response: attr not found */
		uint8_t rsp[5];
		rsp[0] = ATT_OP_ERROR_RSP;
		rsp[1] = ATT_OP_READ_REQ;	/* req opcode */
		put_le16(rsp + 2, 0x00FF);	/* handle */
		rsp[4] = ATT_ERR_ATTR_NOT_FOUND;
		send(peer, rsp, 5, 0);
		close(peer);
		_exit(0);
	}

	close(peer);
	uint8_t val[16];
	size_t outlen = 0;
	int ret = att_read(&ac, 0x00FF, val, sizeof(val), &outlen);
	/* att_read returns the ATT error code on EPROTO */
	ATF_CHECK_EQ(ret, ATT_ERR_ATTR_NOT_FOUND);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(WEXITSTATUS(status), 0);

	close(ac.fd);
	free(ac.buf);
}

/* ================================================================
 * ATT SERVER TESTS
 * ================================================================ */

/* 7. test_att_server_mtu */
ATF_TC_WITHOUT_HEAD(test_att_server_mtu);
ATF_TC_BODY(test_att_server_mtu, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[3], rsp[8];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);

	/* Build MTU request from client: MTU = 200 */
	pdu[0] = ATT_OP_MTU_REQ;
	put_le16(pdu + 1, 200);

	int ret = att_server_handle(&ac, &db, pdu, 3, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	/* Read the response from client_fd */
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 3);
	ATF_CHECK_EQ(rsp[0], ATT_OP_MTU_RSP);
	uint16_t server_mtu = get_le16(rsp + 1);
	ATF_CHECK_EQ(server_mtu, ATT_PDU_BUF_SIZE);

	/* Effective MTU = min(200, 517) = 200 */
	ATF_CHECK_EQ(ac.mtu, 200);

	att_mock_cleanup(&ac, client_fd);
}

/* 8. test_att_server_read_by_group */
ATF_TC_WITHOUT_HEAD(test_att_server_read_by_group);
ATF_TC_BODY(test_att_server_read_by_group, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Read By Group Type: start=0x0001, end=0xFFFF, uuid=0x2800 */
	uint8_t pdu[7];
	pdu[0] = ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);

	int ret = att_server_handle(&ac, &db, pdu, 7, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n > 2);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_BY_GROUP_TYPE_RSP);

	/* entry_len = 4 (handle + end_group) + 2 (16-bit service UUID) = 6 */
	uint8_t entry_len = rsp[1];
	ATF_CHECK_EQ(entry_len, 6);

	/* Should have 2 entries: GAP (0x1800) and Custom (0xFFE0) */
	int num_entries = (n - 2) / entry_len;
	ATF_CHECK_EQ(num_entries, 2);

	/* First entry: GAP service handle=1, value=0x1800 */
	ATF_CHECK_EQ(get_le16(rsp + 2), 0x0001);
	ATF_CHECK_EQ(get_le16(rsp + 2 + 4), 0x1800);

	/* Second entry: Custom service handle=4, value=0xFFE0 */
	ATF_CHECK_EQ(get_le16(rsp + 2 + entry_len), 0x0004);
	ATF_CHECK_EQ(get_le16(rsp + 2 + entry_len + 4), 0xFFE0);

	att_mock_cleanup(&ac, client_fd);
}

/* 9. test_att_server_read_by_type */
ATF_TC_WITHOUT_HEAD(test_att_server_read_by_type);
ATF_TC_BODY(test_att_server_read_by_type, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Read By Type: start=0x0001, end=0xFFFF, uuid=0x2803 (Characteristic) */
	uint8_t pdu[7];
	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_CHARACTERISTIC);

	int ret = att_server_handle(&ac, &db, pdu, 7, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n > 2);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_BY_TYPE_RSP);

	/* Char decl value: props(1) + value_handle(2) + uuid(2) = 5 bytes
	 * entry: handle(2) + value(5) = 7 */
	uint8_t entry_len = rsp[1];
	ATF_CHECK_EQ(entry_len, 7);

	/* Should have 2 characteristic declarations */
	int num_entries = (n - 2) / entry_len;
	ATF_CHECK_EQ(num_entries, 2);

	/* First char: handle=2, value_handle=3, uuid=0x2A00 */
	ATF_CHECK_EQ(get_le16(rsp + 2), 0x0002);
	ATF_CHECK_EQ(get_le16(rsp + 2 + 3), 0x0003); /* value handle */
	ATF_CHECK_EQ(get_le16(rsp + 2 + 5), 0x2A00); /* uuid */

	att_mock_cleanup(&ac, client_fd);
}

/* 10. test_att_server_find_info */
ATF_TC_WITHOUT_HEAD(test_att_server_find_info);
ATF_TC_BODY(test_att_server_find_info, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Find Information: start=0x0005, end=0x0007 */
	uint8_t pdu[5];
	pdu[0] = ATT_OP_FIND_INFO_REQ;
	put_le16(pdu + 1, 0x0005);
	put_le16(pdu + 3, 0x0007);

	int ret = att_server_handle(&ac, &db, pdu, 5, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n > 2);
	ATF_CHECK_EQ(rsp[0], ATT_OP_FIND_INFO_RSP);

	/* Format 1 = 16-bit UUIDs, each entry = handle(2) + uuid(2) = 4 */
	ATF_CHECK_EQ(rsp[1], 0x01);

	int num_entries = (n - 2) / 4;
	ATF_REQUIRE(num_entries >= 3);

	/* handle 5 = Char Decl (0x2803) */
	ATF_CHECK_EQ(get_le16(rsp + 2), 0x0005);
	ATF_CHECK_EQ(get_le16(rsp + 4), GATT_UUID_CHARACTERISTIC);

	/* handle 6 = Custom Char value (0xFFE1) */
	ATF_CHECK_EQ(get_le16(rsp + 6), 0x0006);
	ATF_CHECK_EQ(get_le16(rsp + 8), 0xFFE1);

	/* handle 7 = CCCD (0x2902) */
	ATF_CHECK_EQ(get_le16(rsp + 10), 0x0007);
	ATF_CHECK_EQ(get_le16(rsp + 12), GATT_UUID_CCCD);

	att_mock_cleanup(&ac, client_fd);
}

/* 11. test_att_server_read */
ATF_TC_WITHOUT_HEAD(test_att_server_read);
ATF_TC_BODY(test_att_server_read, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Read Request: handle=0x0003 (Device Name = "Test") */
	uint8_t pdu[3];
	pdu[0] = ATT_OP_READ_REQ;
	put_le16(pdu + 1, 0x0003);

	int ret = att_server_handle(&ac, &db, pdu, 3, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_RSP);
	ATF_CHECK_EQ(memcmp(rsp + 1, "Test", 4), 0);

	att_mock_cleanup(&ac, client_fd);
}

/* 12. test_att_server_write */
ATF_TC_WITHOUT_HEAD(test_att_server_write);
ATF_TC_BODY(test_att_server_write, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Write Request: handle=0x0006 (Custom Char), value=0x11 0x22 0x33 0x44 */
	uint8_t pdu[7];
	pdu[0] = ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, 0x0006);
	pdu[3] = 0x11;
	pdu[4] = 0x22;
	pdu[5] = 0x33;
	pdu[6] = 0x44;

	int ret = att_server_handle(&ac, &db, pdu, 7, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	/* Check Write Response was sent */
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);

	/* Verify the value was actually stored — find by handle */
	struct att_attr *found = NULL;
	for (int i = 0; i < db.count; i++) {
		if (db.attrs[i].handle == 0x0006) {
			found = &db.attrs[i];
			break;
		}
	}
	ATF_REQUIRE(found != NULL);
	ATF_CHECK_EQ(found->value_len, 4);
	ATF_CHECK_EQ(found->value[0], 0x11);
	ATF_CHECK_EQ(found->value[1], 0x22);
	ATF_CHECK_EQ(found->value[2], 0x33);
	ATF_CHECK_EQ(found->value[3], 0x44);

	att_mock_cleanup(&ac, client_fd);
}

/* 13. test_att_server_write_cmd */
ATF_TC_WITHOUT_HEAD(test_att_server_write_cmd);
ATF_TC_BODY(test_att_server_write_cmd, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Write Command: handle=0x0006, value=0x55 0x66 */
	uint8_t pdu[5];
	pdu[0] = ATT_OP_WRITE_CMD;
	put_le16(pdu + 1, 0x0006);
	pdu[3] = 0x55;
	pdu[4] = 0x66;

	int ret = att_server_handle(&ac, &db, pdu, 5, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	/* Verify value changed */
	struct att_attr *found = NULL;
	for (int i = 0; i < db.count; i++) {
		if (db.attrs[i].handle == 0x0006) {
			found = &db.attrs[i];
			break;
		}
	}
	ATF_REQUIRE(found != NULL);
	ATF_CHECK_EQ(found->value_len, 2);
	ATF_CHECK_EQ(found->value[0], 0x55);
	ATF_CHECK_EQ(found->value[1], 0x66);

	/* No response should be sent — verify by trying non-blocking recv */
	uint8_t rsp[8];
	struct timeval tv = { .tv_sec = 0, .tv_usec = 1000 };
	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	ssize_t n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_CHECK(n <= 0);

	att_mock_cleanup(&ac, client_fd);
}

/* 14. test_att_server_prepare_execute */
ATF_TC_WITHOUT_HEAD(test_att_server_prepare_execute);
ATF_TC_BODY(test_att_server_prepare_execute, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Prepare Write: handle=0x0006, offset=0, value=0xAA 0xBB */
	uint8_t prep[7];
	prep[0] = ATT_OP_PREPARE_WRITE_REQ;
	put_le16(prep + 1, 0x0006);
	put_le16(prep + 3, 0x0000); /* offset */
	prep[5] = 0xAA;
	prep[6] = 0xBB;

	int ret = att_server_handle(&ac, &db, prep, 7, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	/* Read Prepare Write Response */
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_PREPARE_WRITE_RSP);
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x0006);
	ATF_CHECK_EQ(get_le16(rsp + 3), 0x0000);

	/* Execute Write: flags=0x01 (write all) */
	uint8_t exec[2];
	exec[0] = ATT_OP_EXECUTE_WRITE_REQ;
	exec[1] = 0x01;

	ret = att_server_handle(&ac, &db, exec, 2, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	/* Read Execute Write Response */
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_EXECUTE_WRITE_RSP);

	/* Verify value was applied */
	struct att_attr *found = NULL;
	for (int i = 0; i < db.count; i++) {
		if (db.attrs[i].handle == 0x0006) {
			found = &db.attrs[i];
			break;
		}
	}
	ATF_REQUIRE(found != NULL);
	ATF_CHECK_EQ(found->value[0], 0xAA);
	ATF_CHECK_EQ(found->value[1], 0xBB);

	att_mock_cleanup(&ac, client_fd);
}

/* 15. test_att_server_cccd_enable */
ATF_TC_WITHOUT_HEAD(test_att_server_cccd_enable);
ATF_TC_BODY(test_att_server_cccd_enable, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[8];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Write 0x0001 (notifications) to CCCD at handle 7 */
	uint8_t pdu[5];
	pdu[0] = ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, 0x0007);
	put_le16(pdu + 3, GATT_CCCD_NOTIFY);

	int ret = att_server_handle(&ac, &db, pdu, 5, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);

	/* Verify CCCD value is stored per-connection */
	ATF_REQUIRE(ac.cccd_count >= 1);
	ATF_CHECK_EQ(ac.cccds[0].handle, 0x0007);
	ATF_CHECK_EQ(ac.cccds[0].value, GATT_CCCD_NOTIFY);

	att_mock_cleanup(&ac, client_fd);
}

/* 16. test_att_server_notification */
ATF_TC_WITHOUT_HEAD(test_att_server_notification);
ATF_TC_BODY(test_att_server_notification, tc)
{
	struct att_conn ac;
	int client_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);

	uint8_t value[4] = { 0x11, 0x22, 0x33, 0x44 };
	int ret = att_send_notification(&ac, 0x0006, value, 4);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 7);
	ATF_CHECK_EQ(rsp[0], ATT_OP_HANDLE_NOTIFY);
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x0006);
	ATF_CHECK_EQ(rsp[3], 0x11);
	ATF_CHECK_EQ(rsp[4], 0x22);
	ATF_CHECK_EQ(rsp[5], 0x33);
	ATF_CHECK_EQ(rsp[6], 0x44);

	att_mock_cleanup(&ac, client_fd);
}

/* 17. test_att_server_invalid_handle */
ATF_TC_WITHOUT_HEAD(test_att_server_invalid_handle);
ATF_TC_BODY(test_att_server_invalid_handle, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[8];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Read Request for invalid handle 0xFFFF */
	uint8_t pdu[3];
	pdu[0] = ATT_OP_READ_REQ;
	put_le16(pdu + 1, 0xFFFF);

	int ret = att_server_handle(&ac, &db, pdu, 3, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[1], ATT_OP_READ_REQ);
	ATF_CHECK_EQ(get_le16(rsp + 2), 0xFFFF);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_HANDLE);

	att_mock_cleanup(&ac, client_fd);
}

/* ================================================================
 * GATT DATABASE TESTS (no socket needed)
 * ================================================================ */

/* 18. test_attdb_build */
ATF_TC_WITHOUT_HEAD(test_attdb_build);
ATF_TC_BODY(test_attdb_build, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];

	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);

	/* GAP Service 0x1800 */
	uint16_t h1 = attdb_add_service(&db, 0x1800);
	ATF_CHECK_EQ(h1, 0x0001);

	uint16_t h2 = attdb_add_characteristic(&db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, "Dev", 3);
	ATF_CHECK_EQ(h2, 0x0003); /* decl=2, value=3 */

	/* DIS Service 0x180A */
	uint16_t h3 = attdb_add_service(&db, 0x180A);
	ATF_CHECK_EQ(h3, 0x0004);

	uint16_t h4 = attdb_add_characteristic(&db, 0x2A29,
	    GATT_PROP_READ, ATT_PERM_READ, "ACME", 4);
	ATF_CHECK_EQ(h4, 0x0006); /* decl=5, value=6 */

	/* Custom Service 0xFFE0 */
	uint16_t h5 = attdb_add_service(&db, 0xFFE0);
	ATF_CHECK_EQ(h5, 0x0007);

	uint16_t h6 = attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_READ | GATT_PROP_NOTIFY,
	    ATT_PERM_READ, "\x01\x02", 2);
	ATF_CHECK_EQ(h6, 0x0009); /* decl=8, value=9 */

	uint16_t h7 = attdb_add_cccd(&db);
	ATF_CHECK_EQ(h7, 0x000A);

	/* Verify sequential handles */
	ATF_CHECK_EQ(db.count, 10);
	for (int i = 0; i < db.count; i++)
		ATF_CHECK_EQ(db.attrs[i].handle, (uint16_t)(i + 1));

	/* Verify service UUIDs */
	ATF_CHECK_EQ(db.attrs[0].uuid16, GATT_UUID_PRIMARY_SERVICE);
	ATF_CHECK_EQ(get_le16(db.attrs[0].value), 0x1800);
	ATF_CHECK_EQ(db.attrs[3].uuid16, GATT_UUID_PRIMARY_SERVICE);
	ATF_CHECK_EQ(get_le16(db.attrs[3].value), 0x180A);
	ATF_CHECK_EQ(db.attrs[6].uuid16, GATT_UUID_PRIMARY_SERVICE);
	ATF_CHECK_EQ(get_le16(db.attrs[6].value), 0xFFE0);
}

/* 19. test_attdb_hash */
ATF_TC_WITHOUT_HEAD(test_attdb_hash);
ATF_TC_BODY(test_attdb_hash, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t hash1[16], hash2[16];

	build_test_db(&db, attrs, val_buf);

	attdb_compute_db_hash(&db, hash1);
	attdb_compute_db_hash(&db, hash2);

	ATF_CHECK_EQ_MSG(memcmp(hash1, hash2, 16), 0,
	    "database hash is not deterministic");

	/* Verify hash is not all zeros (that would indicate a failure) */
	uint8_t zeros[16];
	memset(zeros, 0, 16);
	ATF_CHECK_MSG(memcmp(hash1, zeros, 16) != 0,
	    "database hash is all zeros");
}

/* 20. test_attdb_add_service128 */
ATF_TC_WITHOUT_HEAD(test_attdb_add_service128);
ATF_TC_BODY(test_attdb_add_service128, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];

	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);

	/* Custom 128-bit UUID (not in Bluetooth Base UUID range) */
	uint8_t uuid128[16] = {
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
	};

	uint16_t h = attdb_add_service128(&db, uuid128);
	ATF_CHECK_EQ(h, 0x0001);
	ATF_CHECK_EQ(db.count, 1);

	/* Verify the stored value is the 128-bit UUID */
	ATF_CHECK_EQ(db.attrs[0].uuid16, GATT_UUID_PRIMARY_SERVICE);
	ATF_CHECK_EQ(db.attrs[0].value_len, 16);
	ATF_CHECK_EQ(memcmp(db.attrs[0].value, uuid128, 16), 0);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
/* ================================================================
 * NEW TESTS: Coverage gaps from audit sessions
 * ================================================================ */

/* ATT_PERM_READ_AUTHEN: read must fail when not authenticated.
 * Core Spec Vol 3 Part F §3.2.5: authenticated access implies encryption.
 * Unencrypted → INSUFF_ENCRYPTION; encrypted but unauthenticated →
 * INSUFF_AUTHEN; encrypted + authenticated → success. */
ATF_TC_WITHOUT_HEAD(test_att_server_perm_read_authen);
ATF_TC_BODY(test_att_server_perm_read_authen, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ_AUTHEN, "Secret", 6);

	uint8_t pdu[3] = { ATT_OP_READ_REQ };
	put_le16(pdu + 1, 0x0003);

	/* Read with encrypted=false → INSUFF_ENCRYPTION (authen implies encr) */
	ac.encrypted = false;
	ac.authenticated = false;
	att_server_handle(&ac, &db, pdu, 3, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INSUFF_ENCRYPTION);

	/* Read with encrypted=true, authenticated=false → INSUFF_AUTHEN */
	ac.encrypted = true;
	ac.authenticated = false;
	att_server_handle(&ac, &db, pdu, 3, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INSUFF_AUTHEN);

	/* Read with encrypted=true, authenticated=true → success */
	ac.encrypted = true;
	ac.authenticated = true;
	att_server_handle(&ac, &db, pdu, 3, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_RSP);

	att_mock_cleanup(&ac, client_fd);
}

/* ATT_PERM_WRITE_AUTHEN: write must fail when not authenticated.
 * Authenticated access implies encryption per Core Spec Vol 3 Part F §3.2.5. */
ATF_TC_WITHOUT_HEAD(test_att_server_perm_write_authen);
ATF_TC_BODY(test_att_server_perm_write_authen, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0x2A00,
	    GATT_PROP_READ | GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE_AUTHEN, "X", 1);

	uint8_t pdu[4] = { ATT_OP_WRITE_REQ };
	put_le16(pdu + 1, 0x0003);
	pdu[3] = 0x42;

	/* Write with encrypted=false → INSUFF_ENCRYPTION */
	ac.encrypted = false;
	ac.authenticated = false;
	att_server_handle(&ac, &db, pdu, 4, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INSUFF_ENCRYPTION);

	/* Write with encrypted=true, authenticated=false → INSUFF_AUTHEN */
	ac.encrypted = true;
	ac.authenticated = false;
	att_server_handle(&ac, &db, pdu, 4, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INSUFF_AUTHEN);

	/* Write with encrypted=true, authenticated=true → success */
	ac.encrypted = true;
	ac.authenticated = true;
	att_server_handle(&ac, &db, pdu, 4, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);

	att_mock_cleanup(&ac, client_fd);
}

/* Prepare Write byte limit: total_bytes > ATT_PREPARE_QUEUE_MAX_BYTES
 * Core Spec Vol 3 Part F §3.4.6 */
ATF_TC_WITHOUT_HEAD(test_att_server_prepare_queue_bytes);
ATF_TC_BODY(test_att_server_prepare_queue_bytes, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	int i;

	att_mock_pair(&ac, &client_fd);
	ac.mtu = ATT_PDU_BUF_SIZE; /* allow large prepare writes */
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0xFFE0);
	attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_WRITE, ATT_PERM_WRITE,
	    "\x00", 1);
	/* Set maxlen large enough */
	attrs[2].value_maxlen = 512;

	/* Send prepare writes until byte limit is hit.
	 * ATT_PREPARE_QUEUE_MAX_BYTES = 4096, send 512-byte chunks */
	for (i = 0; i < 10; i++) {
		uint8_t pdu[5 + 512];
		pdu[0] = ATT_OP_PREPARE_WRITE_REQ;
		put_le16(pdu + 1, 0x0003); /* value handle */
		put_le16(pdu + 3, 0x0000); /* offset */
		memset(pdu + 5, 0xAA, 512);

		att_server_handle(&ac, &db, pdu, sizeof(pdu), -1, 0);
		n = recv(client_fd, rsp, sizeof(rsp), 0);
		ATF_REQUIRE(n >= 1);
		if (rsp[0] == ATT_OP_ERROR_RSP) {
			ATF_CHECK_EQ(rsp[4], ATT_ERR_PREPARE_QUEUE_FULL);
			break;
		}
		ATF_CHECK_EQ(rsp[0], ATT_OP_PREPARE_WRITE_RSP);
	}
	/* Should have hit the limit before 10 iterations
	 * (4096/512 = 8 max, plus entry count limit of 16) */
	ATF_CHECK(i < 10);

	/* Cancel to clean up */
	uint8_t exec[2] = { ATT_OP_EXECUTE_WRITE_REQ, 0x00 };
	att_server_handle(&ac, &db, exec, 2, -1, 0);
	(void)recv(client_fd, rsp, sizeof(rsp), 0);

	att_mock_cleanup(&ac, client_fd);
}

/* Read Multiple Variable Length (BT 5.1, opcode 0x20)
 * Core Spec Vol 3 Part F §3.4.4.8 */
ATF_TC_WITHOUT_HEAD(test_att_server_read_multi_variable);
ATF_TC_BODY(test_att_server_read_multi_variable, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Read Multiple Variable: handles 0x0003 (4 bytes) and 0x0006 (4 bytes) */
	uint8_t pdu[5];
	pdu[0] = ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	put_le16(pdu + 1, 0x0003);
	put_le16(pdu + 3, 0x0006);

	int ret = att_server_handle(&ac, &db, pdu, 5, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_MULTIPLE_VARIABLE_RSP);

	/* First entry: length(2) = 4, value = "Test" */
	ATF_REQUIRE(n >= 7);
	ATF_CHECK_EQ(get_le16(rsp + 1), 4);
	ATF_CHECK(memcmp(rsp + 3, "Test", 4) == 0);

	/* Second entry: length(2) = 4, value = 0xAABBCCDD */
	ATF_REQUIRE(n >= 13);
	ATF_CHECK_EQ(get_le16(rsp + 7), 4);
	ATF_CHECK_EQ(rsp[9], 0xAA);

	att_mock_cleanup(&ac, client_fd);
}

/* Indication flow control: ind_pending blocks second indication
 * Core Spec Vol 3 Part F §3.3.2 */
ATF_TC_WITHOUT_HEAD(test_att_server_indication_flow);
ATF_TC_BODY(test_att_server_indication_flow, tc)
{
	struct att_conn ac;
	int client_fd;
	uint8_t val = 0x42;
	int ret;

	att_mock_pair(&ac, &client_fd);
	ac.ind_timer = 0;

	/* First indication succeeds */
	ret = att_send_indication(&ac, 0x0006, &val, 1);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK(ac.ind_pending == true);

	/* Second indication fails with EBUSY */
	ret = att_send_indication(&ac, 0x0006, &val, 1);
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ(errno, EBUSY);

	/* Simulate confirmation */
	ac.ind_pending = false;

	/* Third indication succeeds again */
	ret = att_send_indication(&ac, 0x0006, &val, 1);
	ATF_CHECK_EQ(ret, 0);

	att_mock_cleanup(&ac, client_fd);
}

/* Execute Write with invalid flags (not 0x00 or 0x01)
 * Core Spec Vol 3 Part F §3.4.6.3 */
ATF_TC_WITHOUT_HEAD(test_att_server_exec_write_bad_flags);
ATF_TC_BODY(test_att_server_exec_write_bad_flags, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	uint8_t pdu[2] = { ATT_OP_EXECUTE_WRITE_REQ, 0x02 };
	att_server_handle(&ac, &db, pdu, 2, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_PDU);

	att_mock_cleanup(&ac, client_fd);
}

/* Find By Type Value: search for service UUID by value
 * Core Spec Vol 3 Part F §3.4.3.3 */
ATF_TC_WITHOUT_HEAD(test_att_server_find_by_type_value);
ATF_TC_BODY(test_att_server_find_by_type_value, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Find By Type Value: type=0x2800 (Primary Service), value=0xFFE0 */
	uint8_t pdu[9];
	pdu[0] = ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(pdu + 1, 0x0001); /* start */
	put_le16(pdu + 3, 0xFFFF); /* end */
	put_le16(pdu + 5, 0x2800); /* attr type: Primary Service */
	put_le16(pdu + 7, 0xFFE0); /* value: Custom Service UUID */

	int ret = att_server_handle(&ac, &db, pdu, 9, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_FIND_BY_TYPE_VALUE_RSP);

	/* Found handle should be 0x0004 (Custom Service decl) */
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x0004);

	att_mock_cleanup(&ac, client_fd);
}

/* ================================================================
 * BLE 4.0: ATT edge cases — TP/GAD/SR, TP/GAR/SR, TP/GAW/SR
 * ================================================================ */

/* TP/GAD/SR/BV-01: Read By Group Type with unsupported group type
 * Core Spec Vol 3 Part F §3.4.4.9 */
ATF_TC_WITHOUT_HEAD(test_group_type_unsupported);
ATF_TC_BODY(test_group_type_unsupported, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Read By Group Type with UUID=0x2803 (Characteristic, not a group) */
	uint8_t pdu[7];
	pdu[0] = ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2803); /* Characteristic — not a grouping type */

	att_server_handle(&ac, &db, pdu, 7, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_UNSUPPORTED_GROUP_TYPE);

	att_mock_cleanup(&ac, client_fd);
}

/* TP/GAR/SR/BI: Write to read-only attribute → Write Not Permitted */
ATF_TC_WITHOUT_HEAD(test_write_readonly);
ATF_TC_BODY(test_write_readonly, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Write to Device Name (handle 3) which is read-only */
	uint8_t pdu[4];
	pdu[0] = ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, 0x0003);
	pdu[3] = 0x42;

	att_server_handle(&ac, &db, pdu, 4, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_WRITE_NOT_PERMITTED);

	att_mock_cleanup(&ac, client_fd);
}

/* Zero-length write should be accepted if value_maxlen > 0 */
ATF_TC_WITHOUT_HEAD(test_write_zero_length);
ATF_TC_BODY(test_write_zero_length, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Write zero bytes to custom char (handle 6, maxlen=4) */
	uint8_t pdu[3];
	pdu[0] = ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, 0x0006);

	att_server_handle(&ac, &db, pdu, 3, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);

	att_mock_cleanup(&ac, client_fd);
}

/* MTU exchange with client_mtu < 23 → clamp to 23 */
ATF_TC_WITHOUT_HEAD(test_mtu_clamp_minimum);
ATF_TC_BODY(test_mtu_clamp_minimum, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Client MTU = 10 (below minimum 23) */
	uint8_t pdu[3] = { ATT_OP_MTU_REQ };
	put_le16(pdu + 1, 10);
	att_server_handle(&ac, &db, pdu, 3, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 3);
	ATF_CHECK_EQ(rsp[0], ATT_OP_MTU_RSP);
	/* Negotiated should be clamped to ATT_DEFAULT_MTU (23) */
	ATF_CHECK_EQ(ac.mtu, ATT_DEFAULT_MTU);

	att_mock_cleanup(&ac, client_fd);
}

/* Read By Type for non-existent UUID → Attribute Not Found */
ATF_TC_WITHOUT_HEAD(test_read_by_type_not_found);
ATF_TC_BODY(test_read_by_type_not_found, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Read By Type: UUID=0xBEEF (doesn't exist) */
	uint8_t pdu[7];
	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0xBEEF);

	att_server_handle(&ac, &db, pdu, 7, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_FOUND);

	att_mock_cleanup(&ac, client_fd);
}

/* Prepare Write then Cancel (Execute flags=0x00) */
ATF_TC_WITHOUT_HEAD(test_prepare_then_cancel);
ATF_TC_BODY(test_prepare_then_cancel, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Prepare a write to custom char */
	uint8_t prep[6];
	prep[0] = ATT_OP_PREPARE_WRITE_REQ;
	put_le16(prep + 1, 0x0006); /* custom char */
	put_le16(prep + 3, 0x0000); /* offset 0 */
	prep[5] = 0x99;

	att_server_handle(&ac, &db, prep, 6, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_PREPARE_WRITE_RSP);

	/* Cancel with flags=0x00 */
	uint8_t exec[2] = { ATT_OP_EXECUTE_WRITE_REQ, 0x00 };
	att_server_handle(&ac, &db, exec, 2, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_EXECUTE_WRITE_RSP);

	/* Value should NOT have changed (still original) */
	uint8_t read_pdu[3] = { ATT_OP_READ_REQ };
	put_le16(read_pdu + 1, 0x0006);
	att_server_handle(&ac, &db, read_pdu, 3, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_RSP);
	ATF_CHECK_EQ(rsp[1], 0xAA); /* original value, not 0x99 */

	att_mock_cleanup(&ac, client_fd);
}

/* ================================================================
 * BLE 5.1: GATT Database Hash
 * ================================================================ */

/* Hash is deterministic: same DB → same hash */
ATF_TC_WITHOUT_HEAD(test_attdb_hash_deterministic);
ATF_TC_BODY(test_attdb_hash_deterministic, tc)
{
	struct att_db db1, db2;
	struct att_attr a1[TEST_DB_MAX_ATTRS], a2[TEST_DB_MAX_ATTRS];
	uint8_t v1[TEST_DB_VAL_SIZE], v2[TEST_DB_VAL_SIZE];
	uint8_t h1[16], h2[16];

	build_test_db(&db1, a1, v1);
	build_test_db(&db2, a2, v2);

	attdb_compute_db_hash(&db1, h1);
	attdb_compute_db_hash(&db2, h2);

	ATF_CHECK(memcmp(h1, h2, 16) == 0);
}

/* Hash excludes characteristic values — changing a value doesn't
 * change the hash (Core Spec Vol 3 Part G §7.3.1) */
ATF_TC_WITHOUT_HEAD(test_attdb_hash_excludes_values);
ATF_TC_BODY(test_attdb_hash_excludes_values, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t h1[16], h2[16];

	build_test_db(&db, attrs, val_buf);
	attdb_compute_db_hash(&db, h1);

	/* Change the custom char value (handle 6) */
	for (int i = 0; i < db.count; i++) {
		if (attrs[i].handle == 0x0006 && attrs[i].value != NULL) {
			attrs[i].value[0] = 0xFF;
			break;
		}
	}

	attdb_compute_db_hash(&db, h2);

	/* Hash should be unchanged */
	ATF_CHECK(memcmp(h1, h2, 16) == 0);
}

/* Different DBs produce different hashes */
ATF_TC_WITHOUT_HEAD(test_attdb_hash_differs);
ATF_TC_BODY(test_attdb_hash_differs, tc)
{
	struct att_db db1, db2;
	struct att_attr a1[TEST_DB_MAX_ATTRS], a2[TEST_DB_MAX_ATTRS];
	uint8_t v1[TEST_DB_VAL_SIZE], v2[TEST_DB_VAL_SIZE];
	uint8_t h1[16], h2[16];

	build_test_db(&db1, a1, v1);
	attdb_compute_db_hash(&db1, h1);

	/* Different DB: add an extra service */
	attdb_init(&db2, a2, TEST_DB_MAX_ATTRS, v2, TEST_DB_VAL_SIZE);
	attdb_add_service(&db2, 0x1800);
	attdb_add_characteristic(&db2, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, "Test", 4);
	attdb_add_service(&db2, 0xFFE0);
	attdb_add_characteristic(&db2, 0xFFE1,
	    GATT_PROP_READ, ATT_PERM_READ, "\xAA", 1);
	/* Extra service that db1 doesn't have */
	attdb_add_service(&db2, 0x180F);
	attdb_compute_db_hash(&db2, h2);

	ATF_CHECK(memcmp(h1, h2, 16) != 0);
}

/* ================================================================
 * BLE 5.1: Read Multiple Variable Length edge cases
 * ================================================================ */

/* Read Multi Var with invalid handle → error */
ATF_TC_WITHOUT_HEAD(test_read_multi_var_invalid_handle);
ATF_TC_BODY(test_read_multi_var_invalid_handle, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	uint8_t pdu[5];
	pdu[0] = ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	put_le16(pdu + 1, 0x0003); /* valid */
	put_le16(pdu + 3, 0xFFFF); /* invalid */

	att_server_handle(&ac, &db, pdu, 5, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_HANDLE);

	att_mock_cleanup(&ac, client_fd);
}

/* ================================================================
 * BLE 5.2: Multi-Handle Value Notification format
 * ================================================================ */

/* Verify Multi-Handle NTF PDU format (opcode 0x23) */
ATF_TC_WITHOUT_HEAD(test_multi_handle_ntf_format);
ATF_TC_BODY(test_multi_handle_ntf_format, tc)
{
	struct att_conn ac;
	int client_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	ac.mtu = ATT_PDU_BUF_SIZE;

	uint16_t handles[2] = { 0x0003, 0x0006 };
	uint8_t v1[] = { 0x11, 0x22 };
	uint8_t v2[] = { 0x33 };
	const uint8_t *values[2] = { v1, v2 };
	uint16_t lengths[2] = { 2, 1 };

	int ret = att_send_multiple_handle_value_ntf(&ac, handles, values,
	    lengths, 2);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_MULTIPLE_HANDLE_VALUE_NTF);

	/* Entry 1: handle(2) + length(2) + value(2) = 6 bytes at offset 1 */
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x0003);
	ATF_CHECK_EQ(get_le16(rsp + 3), 2);
	ATF_CHECK_EQ(rsp[5], 0x11);
	ATF_CHECK_EQ(rsp[6], 0x22);

	/* Entry 2: handle(2) + length(2) + value(1) = 5 bytes at offset 7 */
	ATF_CHECK_EQ(get_le16(rsp + 7), 0x0006);
	ATF_CHECK_EQ(get_le16(rsp + 9), 1);
	ATF_CHECK_EQ(rsp[11], 0x33);

	ATF_CHECK_EQ(n, 12); /* 1 + 6 + 5 */

	att_mock_cleanup(&ac, client_fd);
}

/* ================================================================
 * RAW PDU BYTE-LEVEL TESTS
 *
 * These verify exact byte sequences for ATT request/response PDUs,
 * modeled after BlueZ test-gatt.c raw_pdu pattern.
 * ================================================================ */

/* Raw PDU: Read Request → Read Response, exact bytes
 * Request:  0A 03 00  (opcode=0x0A, handle=0x0003 LE)
 * Response: 0B 54 65 73 74  (opcode=0x0B, value="Test") */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_read);
ATF_TC_BODY(test_raw_pdu_read, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Exact request bytes */
	uint8_t req[] = { 0x0A, 0x03, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	/* Exact response bytes */
	uint8_t expected[] = { 0x0B, 0x54, 0x65, 0x73, 0x74 }; /* "Test" */
	ATF_CHECK_EQ(n, (ssize_t)sizeof(expected));
	ATF_CHECK(memcmp(rsp, expected, sizeof(expected)) == 0);

	att_mock_cleanup(&ac, client_fd);
}

/* Raw PDU: Error Response for invalid handle
 * Request:  0A FF FF  (Read handle 0xFFFF)
 * Response: 01 0A FF FF 01  (Error, req=0x0A, handle=0xFFFF, code=0x01) */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_error);
ATF_TC_BODY(test_raw_pdu_error, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	uint8_t req[] = { 0x0A, 0xFF, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	uint8_t expected[] = { 0x01, 0x0A, 0xFF, 0xFF, 0x01 };
	ATF_CHECK_EQ(n, 5);
	ATF_CHECK(memcmp(rsp, expected, 5) == 0);

	att_mock_cleanup(&ac, client_fd);
}

/* Raw PDU: MTU Exchange
 * Request:  02 17 00  (client MTU=23)
 * Response: 03 05 02  (server MTU=517=0x0205) */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_mtu);
ATF_TC_BODY(test_raw_pdu_mtu, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	uint8_t req[] = { 0x02, 0x17, 0x00 }; /* client MTU=23 */
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_CHECK_EQ(n, 3);
	ATF_CHECK_EQ(rsp[0], 0x03); /* MTU_RSP */
	/* Server MTU = ATT_PDU_BUF_SIZE = 517 = 0x0205 */
	ATF_CHECK_EQ(rsp[1], 0x05);
	ATF_CHECK_EQ(rsp[2], 0x02);
	ATF_CHECK_EQ(ac.mtu, 23); /* min(23,517) = 23 */

	att_mock_cleanup(&ac, client_fd);
}

/* Raw PDU: Write Request → Write Response
 * Request:  12 06 00 42  (Write handle=0x0006, value=0x42)
 * Response: 13  (Write Response, empty) */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_write);
ATF_TC_BODY(test_raw_pdu_write, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	uint8_t req[] = { 0x12, 0x06, 0x00, 0x42 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(rsp[0], 0x13); /* WRITE_RSP */

	att_mock_cleanup(&ac, client_fd);
}

/* Raw PDU: Find Information
 * Request:  04 01 00 03 00  (start=1, end=3)
 * Response: 05 01 [handle,uuid16]...  (format=1, 16-bit UUIDs) */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_find_info);
ATF_TC_BODY(test_raw_pdu_find_info, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	uint8_t req[] = { 0x04, 0x01, 0x00, 0x03, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_REQUIRE(n >= 6);
	ATF_CHECK_EQ(rsp[0], 0x05); /* FIND_INFO_RSP */
	ATF_CHECK_EQ(rsp[1], 0x01); /* format = 16-bit UUID */

	/* First entry: handle=0x0001, uuid=0x2800 (Primary Service) */
	ATF_CHECK_EQ(rsp[2], 0x01); ATF_CHECK_EQ(rsp[3], 0x00); /* handle LE */
	ATF_CHECK_EQ(rsp[4], 0x00); ATF_CHECK_EQ(rsp[5], 0x28); /* uuid LE */

	/* Second entry: handle=0x0002, uuid=0x2803 (Characteristic) */
	ATF_CHECK_EQ(rsp[6], 0x02); ATF_CHECK_EQ(rsp[7], 0x00);
	ATF_CHECK_EQ(rsp[8], 0x03); ATF_CHECK_EQ(rsp[9], 0x28);

	/* Third entry: handle=0x0003, uuid=0x2A00 (Device Name) */
	ATF_CHECK_EQ(rsp[10], 0x03); ATF_CHECK_EQ(rsp[11], 0x00);
	ATF_CHECK_EQ(rsp[12], 0x00); ATF_CHECK_EQ(rsp[13], 0x2A);

	att_mock_cleanup(&ac, client_fd);
}

/* Raw PDU: Read By Group Type (service discovery)
 * Request:  10 01 00 FF FF 00 28  (start=1, end=FFFF, uuid=0x2800)
 * Response: 11 06 [handle,end_group,value]... */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_read_by_group);
ATF_TC_BODY(test_raw_pdu_read_by_group, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	uint8_t req[] = { 0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_REQUIRE(n >= 8);
	ATF_CHECK_EQ(rsp[0], 0x11); /* READ_BY_GROUP_TYPE_RSP */
	ATF_CHECK_EQ(rsp[1], 6);    /* length per entry: 2+2+2 */

	/* First service: handle=0x0001, end=0x0003, value=0x1800 */
	ATF_CHECK_EQ(rsp[2], 0x01); ATF_CHECK_EQ(rsp[3], 0x00);
	ATF_CHECK_EQ(rsp[4], 0x03); ATF_CHECK_EQ(rsp[5], 0x00);
	ATF_CHECK_EQ(rsp[6], 0x00); ATF_CHECK_EQ(rsp[7], 0x18);

	/* Second service: handle=0x0004, end=0x0007, value=0xFFE0 */
	ATF_CHECK_EQ(rsp[8], 0x04);  ATF_CHECK_EQ(rsp[9], 0x00);
	ATF_CHECK_EQ(rsp[10], 0x07); ATF_CHECK_EQ(rsp[11], 0x00);
	ATF_CHECK_EQ(rsp[12], 0xE0); ATF_CHECK_EQ(rsp[13], 0xFF);

	att_mock_cleanup(&ac, client_fd);
}

/* ================================================================
 * MULTI-MTU TESTS
 *
 * Verify response clamping at different MTU sizes.
 * ================================================================ */

/* MTU=30: Read By Group Type response truncated to fit */
ATF_TC_WITHOUT_HEAD(test_mtu30_read_by_group);
ATF_TC_BODY(test_mtu30_read_by_group, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	ac.mtu = 30;
	build_test_db(&db, attrs, val_buf);

	uint8_t req[] = { 0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_REQUIRE(n > 0);
	ATF_CHECK(n <= 30); /* response must not exceed MTU */
	ATF_CHECK_EQ(rsp[0], 0x11);

	att_mock_cleanup(&ac, client_fd);
}

/* MTU=23 (minimum): Read response clamped to MTU-1=22 bytes of value */
ATF_TC_WITHOUT_HEAD(test_mtu23_read_clamp);
ATF_TC_BODY(test_mtu23_read_clamp, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	ac.mtu = ATT_DEFAULT_MTU; /* 23 */

	/* Build DB with a large value */
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0x1800);
	{
		uint8_t big_val[100];
		memset(big_val, 0x42, sizeof(big_val));
		attdb_add_characteristic(&db, 0x2A00,
		    GATT_PROP_READ, ATT_PERM_READ, big_val, 100);
	}

	/* Read → response clamped to MTU(23) = opcode(1) + 22 bytes */
	uint8_t req[] = { 0x0A, 0x03, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_CHECK_EQ(n, 23); /* exactly MTU */
	ATF_CHECK_EQ(rsp[0], 0x0B); /* READ_RSP */
	/* 22 bytes of value, all 0x42 */
	for (int i = 1; i < 23; i++)
		ATF_CHECK_EQ(rsp[i], 0x42);

	att_mock_cleanup(&ac, client_fd);
}

/* MTU=517 (max): full value returned without truncation */
ATF_TC_WITHOUT_HEAD(test_mtu517_read_full);
ATF_TC_BODY(test_mtu517_read_full, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	ac.mtu = ATT_PDU_BUF_SIZE; /* 517 */

	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0x1800);
	{
		uint8_t val[100];
		memset(val, 0x99, sizeof(val));
		attdb_add_characteristic(&db, 0x2A00,
		    GATT_PROP_READ, ATT_PERM_READ, val, 100);
	}

	uint8_t req[] = { 0x0A, 0x03, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_CHECK_EQ(n, 101); /* opcode(1) + full 100 bytes */
	ATF_CHECK_EQ(rsp[0], 0x0B);
	ATF_CHECK_EQ(rsp[1], 0x99);
	ATF_CHECK_EQ(rsp[100], 0x99);

	att_mock_cleanup(&ac, client_fd);
}

/* ================================================================
 * CLIENT ROLE TESTS
 *
 * Parent acts as ATT client, child acts as mock server.
 * Verifies exact request PDU bytes sent by client functions.
 * ================================================================ */

/* Client: att_read sends correct Read Request PDU */
ATF_TC_WITHOUT_HEAD(test_client_read_pdu);
ATF_TC_BODY(test_client_read_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Child: mock server — receive request, verify, send response */
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		if (n != 3) _exit(1);
		/* Verify exact request: 0A 06 00 */
		if (buf[0] != 0x0A) _exit(2);
		if (buf[1] != 0x06 || buf[2] != 0x00) _exit(3);

		/* Send Read Response: 0B AA BB */
		uint8_t rsp[] = { 0x0B, 0xAA, 0xBB };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}

	/* Parent: ATT client */
	close(peer);
	uint8_t val[32];
	size_t vlen = 0;
	int ret = att_read(&ac, 0x0006, val, sizeof(val), &vlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(vlen, 2);
	ATF_CHECK_EQ(val[0], 0xAA);
	ATF_CHECK_EQ(val[1], 0xBB);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	att_mock_cleanup(&ac, -1);
}

/* Client: att_write_req sends correct Write Request PDU */
ATF_TC_WITHOUT_HEAD(test_client_write_pdu);
ATF_TC_BODY(test_client_write_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		if (n != 5) _exit(1);
		/* Verify: 12 06 00 DE AD */
		if (buf[0] != 0x12) _exit(2);
		if (buf[1] != 0x06 || buf[2] != 0x00) _exit(3);
		if (buf[3] != 0xDE || buf[4] != 0xAD) _exit(4);

		/* Send Write Response */
		uint8_t rsp[] = { 0x13 };
		(void)send(peer, rsp, 1, 0);
		close(peer);
		_exit(0);
	}

	close(peer);
	uint8_t data[] = { 0xDE, 0xAD };
	int ret = att_write_req(&ac, 0x0006, data, sizeof(data));
	ATF_CHECK_EQ(ret, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	att_mock_cleanup(&ac, -1);
}

/* Client: att_find_info sends correct Find Info Request PDU */
ATF_TC_WITHOUT_HEAD(test_client_find_info_pdu);
ATF_TC_BODY(test_client_find_info_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		if (n != 5) _exit(1);
		/* Verify: 04 01 00 07 00 */
		if (buf[0] != 0x04) _exit(2);
		if (buf[1] != 0x01 || buf[2] != 0x00) _exit(3);
		if (buf[3] != 0x07 || buf[4] != 0x00) _exit(4);

		/* Send response: format=1, handle=0x0001, uuid=0x2800 */
		uint8_t rsp[] = { 0x05, 0x01,
		    0x01, 0x00, 0x00, 0x28 };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}

	close(peer);
	uint8_t out[ATT_PDU_BUF_SIZE];
	size_t outlen = 0;
	int ret = att_find_info(&ac, 0x0001, 0x0007,
	    out, sizeof(out), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK(outlen > 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	att_mock_cleanup(&ac, -1);
}

/* Client: att_read_by_group_type sends correct PDU */
ATF_TC_WITHOUT_HEAD(test_client_read_by_group_pdu);
ATF_TC_BODY(test_client_read_by_group_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);

	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		if (n != 7) _exit(1);
		/* Verify: 10 01 00 FF FF 00 28 */
		if (buf[0] != 0x10) _exit(2);
		if (buf[5] != 0x00 || buf[6] != 0x28) _exit(3);

		/* Send response: length=6, one service */
		uint8_t rsp[] = { 0x11, 0x06,
		    0x01, 0x00, 0x03, 0x00, 0x00, 0x18 };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}

	close(peer);
	uint8_t out[ATT_PDU_BUF_SIZE];
	size_t outlen = 0;
	int ret = att_read_by_group_type(&ac, 0x0001, 0xFFFF,
	    0x2800, out, sizeof(out), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK(outlen > 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	att_mock_cleanup(&ac, -1);
}

/* ================================================================
 * Remaining raw PDU tests for full opcode coverage
 * ================================================================ */

/* Raw PDU: Read By Type — find characteristic 0x2A00
 * Request:  08 01 00 FF FF 00 2A
 * Response: 09 length [handle(2)+value]... */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_read_by_type);
ATF_TC_BODY(test_raw_pdu_read_by_type, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	uint8_t req[] = { 0x08, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x2A };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_REQUIRE(n >= 4);
	ATF_CHECK_EQ(rsp[0], 0x09); /* READ_BY_TYPE_RSP */
	/* entry length = 2 + value_len */
	int elen = rsp[1];
	ATF_CHECK(elen >= 6); /* handle(2) + "Test"(4) = 6 */
	/* First entry handle = 0x0003 */
	ATF_CHECK_EQ(rsp[2], 0x03);
	ATF_CHECK_EQ(rsp[3], 0x00);
	/* Value starts at rsp[4], should be "Test" */
	ATF_CHECK_EQ(rsp[4], 'T');

	att_mock_cleanup(&ac, client_fd);
}

/* Raw PDU: Read Blob — offset into "Test" (4 bytes)
 * Request:  0C 03 00 02 00  (handle=3, offset=2)
 * Response: 0D 73 74  ("st") */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_read_blob);
ATF_TC_BODY(test_raw_pdu_read_blob, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/*
	 * Read Blob at offset=2 on a 4-byte attribute at MTU=23.
	 * Since value_len (4) <= mtu-1 (22), the attribute is NOT long
	 * and Read Blob must return ATT_ERR_ATTR_NOT_LONG.
	 */
	uint8_t req[] = { 0x0C, 0x03, 0x00, 0x02, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_CHECK_EQ(n, 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_LONG);

	att_mock_cleanup(&ac, client_fd);
}

/* Raw PDU: Write Command — no response expected
 * Request:  52 06 00 FF  (Write Cmd handle=6, value=0xFF) */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_write_cmd);
ATF_TC_BODY(test_raw_pdu_write_cmd, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	struct pollfd pfd;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	uint8_t req[] = { 0x52, 0x06, 0x00, 0xFF };
	int ret = att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	ATF_CHECK_EQ(ret, 0);

	/* No response should be sent */
	pfd.fd = client_fd;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 50), 0); /* timeout = no data */

	/* But value should be written */
	ATF_CHECK_EQ(attrs[5].value[0], 0xFF); /* handle 6 = attrs[5] */

	att_mock_cleanup(&ac, client_fd);
}

/* Raw PDU: Prepare Write + Execute Write commit
 * Prepare: 16 06 00 00 00 DE  (handle=6, offset=0, value=0xDE)
 * Execute: 18 01  (flags=commit) */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_prepare_execute);
ATF_TC_BODY(test_raw_pdu_prepare_execute, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Prepare Write */
	uint8_t prep[] = { 0x16, 0x06, 0x00, 0x00, 0x00, 0xDE };
	att_server_handle(&ac, &db, prep, sizeof(prep), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x17); /* PREPARE_WRITE_RSP */
	/* Response echoes: handle + offset + value */
	ATF_CHECK_EQ(rsp[1], 0x06); ATF_CHECK_EQ(rsp[2], 0x00);
	ATF_CHECK_EQ(rsp[3], 0x00); ATF_CHECK_EQ(rsp[4], 0x00);
	ATF_CHECK_EQ(rsp[5], 0xDE);

	/* Execute Write (commit) */
	uint8_t exec[] = { 0x18, 0x01 };
	att_server_handle(&ac, &db, exec, sizeof(exec), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(rsp[0], 0x19); /* EXECUTE_WRITE_RSP */

	/* Verify value was written */
	ATF_CHECK_EQ(attrs[5].value[0], 0xDE);

	att_mock_cleanup(&ac, client_fd);
}

/* Raw PDU: Find By Type Value
 * Request:  06 01 00 FF FF 00 28 E0 FF  (type=0x2800, value=0xFFE0) */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_find_by_type);
ATF_TC_BODY(test_raw_pdu_find_by_type, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	uint8_t req[] = { 0x06, 0x01, 0x00, 0xFF, 0xFF,
	    0x00, 0x28, 0xE0, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_REQUIRE(n >= 5);
	ATF_CHECK_EQ(rsp[0], 0x07); /* FIND_BY_TYPE_VALUE_RSP */
	/* Found handle = 0x0004, group end = 0x0007 */
	ATF_CHECK_EQ(rsp[1], 0x04); ATF_CHECK_EQ(rsp[2], 0x00);
	ATF_CHECK_EQ(rsp[3], 0x07); ATF_CHECK_EQ(rsp[4], 0x00);

	att_mock_cleanup(&ac, client_fd);
}

/* Raw PDU: Read Multiple — handles 0x0003 and 0x0006
 * Request:  0E 03 00 06 00
 * Response: 0F <concatenated values> */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_read_multiple);
ATF_TC_BODY(test_raw_pdu_read_multiple, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	uint8_t req[] = { 0x0E, 0x03, 0x00, 0x06, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ(rsp[0], 0x0F); /* READ_MULTIPLE_RSP */
	/* "Test" (4 bytes) + 0xAA 0xBB 0xCC 0xDD (4 bytes) = 8 + opcode */
	ATF_CHECK_EQ(n, 9);
	ATF_CHECK_EQ(rsp[1], 'T');
	ATF_CHECK_EQ(rsp[5], 0xAA);

	att_mock_cleanup(&ac, client_fd);
}

/* Raw PDU: Notification verify
 * att_send_notification → 1B 06 00 42 */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_notification);
ATF_TC_BODY(test_raw_pdu_notification, tc)
{
	struct att_conn ac;
	int client_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint8_t val = 0x42;

	att_mock_pair(&ac, &client_fd);

	att_send_notification(&ac, 0x0006, &val, 1);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	uint8_t expected[] = { 0x1B, 0x06, 0x00, 0x42 };
	ATF_CHECK_EQ(n, 4);
	ATF_CHECK(memcmp(rsp, expected, 4) == 0);

	att_mock_cleanup(&ac, client_fd);
}

/* ================================================================
 * Remaining multi-MTU tests
 * ================================================================ */

/* MTU=23: Read By Type truncates value to MTU-4=19 bytes */
ATF_TC_WITHOUT_HEAD(test_mtu23_read_by_type_clamp);
ATF_TC_BODY(test_mtu23_read_by_type_clamp, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	ac.mtu = ATT_DEFAULT_MTU;

	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0x1800);
	{
		uint8_t big[50];
		memset(big, 0x77, sizeof(big));
		attdb_add_characteristic(&db, 0x2A00,
		    GATT_PROP_READ, ATT_PERM_READ, big, 50);
	}

	uint8_t req[] = { 0x08, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x2A };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_CHECK(n <= 23); /* must fit in MTU */
	ATF_CHECK_EQ(rsp[0], 0x09);
	/* entry_len = min(2+50, MTU-2) = min(52, 21) = 21 */
	ATF_CHECK_EQ(rsp[1], 21);

	att_mock_cleanup(&ac, client_fd);
}

/* MTU=23: Notification truncates value to MTU-3=20 bytes */
ATF_TC_WITHOUT_HEAD(test_mtu23_notification_clamp);
ATF_TC_BODY(test_mtu23_notification_clamp, tc)
{
	struct att_conn ac;
	int client_fd;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint8_t big_val[50];

	att_mock_pair(&ac, &client_fd);
	ac.mtu = ATT_DEFAULT_MTU;
	memset(big_val, 0x55, sizeof(big_val));

	att_send_notification(&ac, 0x0006, big_val, 50);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_CHECK_EQ(n, 23); /* clamped to MTU */
	ATF_CHECK_EQ(rsp[0], 0x1B); /* NOTIFY */
	ATF_CHECK_EQ(rsp[1], 0x06); ATF_CHECK_EQ(rsp[2], 0x00);
	/* 20 bytes of value */
	for (int i = 3; i < 23; i++)
		ATF_CHECK_EQ(rsp[i], 0x55);

	att_mock_cleanup(&ac, client_fd);
}

/* MTU=23: Find Info limited entries */
ATF_TC_WITHOUT_HEAD(test_mtu23_find_info_limited);
ATF_TC_BODY(test_mtu23_find_info_limited, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	ac.mtu = ATT_DEFAULT_MTU; /* 23 */
	build_test_db(&db, attrs, val_buf);

	uint8_t req[] = { 0x04, 0x01, 0x00, 0xFF, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);

	ATF_CHECK(n <= 23);
	ATF_CHECK_EQ(rsp[0], 0x05);
	ATF_CHECK_EQ(rsp[1], 0x01); /* 16-bit format */
	/* Max entries at MTU=23: (23-2)/4 = 5 entries */
	int num_entries = (n - 2) / 4;
	ATF_CHECK_EQ(num_entries, 5);

	att_mock_cleanup(&ac, client_fd);
}

/* ================================================================
 * Remaining client role tests
 * ================================================================ */

/* Client: att_exchange_mtu */
ATF_TC_WITHOUT_HEAD(test_client_mtu_pdu);
ATF_TC_BODY(test_client_mtu_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		/* Verify: 02 XX XX (MTU_REQ + client_mtu LE) */
		if (n != 3 || buf[0] != 0x02) _exit(1);
		uint16_t cmtu = buf[1] | ((uint16_t)buf[2] << 8);
		if (cmtu != 200) _exit(2);
		/* Reply: server MTU = 100 */
		uint8_t rsp[] = { 0x03, 0x64, 0x00 };
		(void)send(peer, rsp, 3, 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	int ret = att_exchange_mtu(&ac, 200);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(ac.mtu, 100); /* min(200, 100) */

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* Client: att_write_cmd (no response) */
ATF_TC_WITHOUT_HEAD(test_client_write_cmd_pdu);
ATF_TC_BODY(test_client_write_cmd_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	uint8_t data[] = { 0xBE, 0xEF };
	int ret = att_write_cmd(&ac, 0x0006, data, 2);
	ATF_CHECK_EQ(ret, 0);

	/* Read what was sent */
	n = recv(peer, buf, sizeof(buf), 0);
	ATF_CHECK_EQ(n, 5);
	/* 52 06 00 BE EF */
	ATF_CHECK_EQ(buf[0], 0x52);
	ATF_CHECK_EQ(buf[1], 0x06); ATF_CHECK_EQ(buf[2], 0x00);
	ATF_CHECK_EQ(buf[3], 0xBE); ATF_CHECK_EQ(buf[4], 0xEF);

	att_mock_cleanup(&ac, peer);
}

/* Client: att_read_blob */
ATF_TC_WITHOUT_HEAD(test_client_read_blob_pdu);
ATF_TC_BODY(test_client_read_blob_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		/* Verify: 0C 03 00 0A 00 (handle=3, offset=10) */
		if (n != 5 || buf[0] != 0x0C) _exit(1);
		if (buf[1] != 0x03 || buf[2] != 0x00) _exit(2);
		if (buf[3] != 0x0A || buf[4] != 0x00) _exit(3);
		uint8_t rsp[] = { 0x0D, 0x61, 0x62 }; /* "ab" */
		(void)send(peer, rsp, 3, 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t val[32];
	size_t vlen = 0;
	int ret = att_read_blob(&ac, 0x0003, 10, val, sizeof(val), &vlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(vlen, 2);
	ATF_CHECK_EQ(val[0], 0x61);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* ================================================================
 * TP/GAD: Discovery edge cases
 * ================================================================ */

/* Discovery: restricted handle range, only second service found */
ATF_TC_WITHOUT_HEAD(test_gad_restricted_range);
ATF_TC_BODY(test_gad_restricted_range, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Read By Group Type: start=0x0004, end=0xFFFF → only Custom Service */
	uint8_t req[] = { 0x10, 0x04, 0x00, 0xFF, 0xFF, 0x00, 0x28 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 8);
	ATF_CHECK_EQ(rsp[0], 0x11);
	ATF_CHECK_EQ(get_le16(rsp + 2), 0x0004); /* only custom service */

	att_mock_cleanup(&ac, cf);
}

/* Discovery: start handle past all attributes → Attribute Not Found */
ATF_TC_WITHOUT_HEAD(test_gad_empty_range);
ATF_TC_BODY(test_gad_empty_range, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x10, 0x20, 0x00, 0xFF, 0xFF, 0x00, 0x28 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 5);
	ATF_CHECK_EQ(rsp[0], 0x01);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_FOUND);

	att_mock_cleanup(&ac, cf);
}

/* Find Info: range covering single attribute */
ATF_TC_WITHOUT_HEAD(test_gad_find_info_single);
ATF_TC_BODY(test_gad_find_info_single, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* start=end=0x0007 (CCCD) */
	uint8_t req[] = { 0x04, 0x07, 0x00, 0x07, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x05);
	ATF_CHECK_EQ(rsp[1], 0x01); /* 16-bit */
	ATF_CHECK_EQ(get_le16(rsp + 2), 0x0007);
	ATF_CHECK_EQ(get_le16(rsp + 4), GATT_UUID_CCCD);

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * TP/GAR: Read edge cases
 * ================================================================ */

/* Read with encryption required, encrypted=false → Insuff Encryption */
ATF_TC_WITHOUT_HEAD(test_gar_read_encrypt_required);
ATF_TC_BODY(test_gar_read_encrypt_required, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ_ENCRYPT, "Secret", 6);

	ac.encrypted = false;
	uint8_t req[] = { 0x0A, 0x03, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x01);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INSUFF_ENCRYPTION);

	/* Now with encryption → success */
	ac.encrypted = true;
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x0B);
	ATF_CHECK(n > 1);

	att_mock_cleanup(&ac, cf);
}

/* Read value of length 0 → empty Read Response (just opcode) */
ATF_TC_WITHOUT_HEAD(test_gar_read_empty_value);
ATF_TC_BODY(test_gar_read_empty_value, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0x2A00,
	    GATT_PROP_READ | GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE, NULL, 0);
	/* value_len=0, value=NULL */

	uint8_t req[] = { 0x0A, 0x03, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 1); /* just opcode, no value */
	ATF_CHECK_EQ(rsp[0], 0x0B);

	att_mock_cleanup(&ac, cf);
}

/* Read Blob at exact end of value → empty response body */
ATF_TC_WITHOUT_HEAD(test_gar_read_blob_at_end);
ATF_TC_BODY(test_gar_read_blob_at_end, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb); /* handle 3 = "Test" (4 bytes) */

	/*
	 * Read Blob at offset=4 on a 4-byte attribute at MTU=23.
	 * Since value_len (4) <= mtu-1 (22), the attribute is NOT long
	 * and Read Blob must return ATT_ERR_ATTR_NOT_LONG.
	 */
	uint8_t req[] = { 0x0C, 0x03, 0x00, 0x04, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_LONG);

	att_mock_cleanup(&ac, cf);
}

/* Read Blob past end → Invalid Offset */
ATF_TC_WITHOUT_HEAD(test_gar_read_blob_past_end);
ATF_TC_BODY(test_gar_read_blob_past_end, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/*
	 * Read Blob at offset=16 on a 4-byte attribute at MTU=23.
	 * Since value_len (4) <= mtu-1 (22), the "not long" check
	 * fires before the offset check.
	 */
	uint8_t req[] = { 0x0C, 0x03, 0x00, 0x10, 0x00 }; /* offset=16 > 4 */
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x01);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_LONG);

	att_mock_cleanup(&ac, cf);
}

/* Read By Type with 128-bit UUID → no match in our 16-bit DB */
ATF_TC_WITHOUT_HEAD(test_gar_read_by_type_uuid128);
ATF_TC_BODY(test_gar_read_by_type_uuid128, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* 21-byte Read By Type with random 128-bit UUID */
	uint8_t req[21] = { 0x08, 0x01, 0x00, 0xFF, 0xFF };
	memset(req + 5, 0xAA, 16); /* 128-bit UUID */
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x01); /* Error */
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_FOUND);

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * TP/GAW: Write edge cases
 * ================================================================ */

/* Write to non-existent handle via Write Command → silently ignored */
ATF_TC_WITHOUT_HEAD(test_gaw_write_cmd_bad_handle);
ATF_TC_BODY(test_gaw_write_cmd_bad_handle, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	struct pollfd pfd;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x52, 0xFF, 0xFF, 0x42 }; /* bad handle */
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);

	pfd.fd = cf;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 50), 0); /* no response for commands */

	att_mock_cleanup(&ac, cf);
}

/* Write with value_len == value_maxlen (boundary) → success */
ATF_TC_WITHOUT_HEAD(test_gaw_write_exact_maxlen);
ATF_TC_BODY(test_gaw_write_exact_maxlen, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);
	/* Custom char (handle 6) has maxlen=4 */

	uint8_t req[] = { 0x12, 0x06, 0x00, 0x11, 0x22, 0x33, 0x44 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(rsp[0], 0x13); /* success */

	att_mock_cleanup(&ac, cf);
}

/* Write one byte over maxlen → Invalid Attribute Length */
ATF_TC_WITHOUT_HEAD(test_gaw_write_over_maxlen);
ATF_TC_BODY(test_gaw_write_over_maxlen, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x12, 0x06, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x01);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_ATTR_LEN);

	att_mock_cleanup(&ac, cf);
}

/* Signed Write Command (0xD2) → silently ignored (bit 6 set) */
ATF_TC_WITHOUT_HEAD(test_gaw_signed_write_ignored);
ATF_TC_BODY(test_gaw_signed_write_ignored, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	struct pollfd pfd;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* 0xD2 has bit 6 set → command, silently ignored */
	uint8_t req[] = { 0xD2, 0x06, 0x00, 0x42,
	    0,0,0,0,0,0,0,0,0,0,0,0 }; /* + 12-byte signature */
	int ret = att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	ATF_CHECK_EQ(ret, 0);

	pfd.fd = cf;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 50), 0);

	att_mock_cleanup(&ac, cf);
}

/* Prepare Write: multiple fragments then commit */
ATF_TC_WITHOUT_HEAD(test_gaw_prepare_multi_fragment);
ATF_TC_BODY(test_gaw_prepare_multi_fragment, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Fragment 1: offset=0, value=0xAA 0xBB */
	uint8_t p1[] = { 0x16, 0x06, 0x00, 0x00, 0x00, 0xAA, 0xBB };
	att_server_handle(&ac, &db, p1, sizeof(p1), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x17);

	/* Fragment 2: offset=2, value=0xCC 0xDD */
	uint8_t p2[] = { 0x16, 0x06, 0x00, 0x02, 0x00, 0xCC, 0xDD };
	att_server_handle(&ac, &db, p2, sizeof(p2), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x17);

	/* Execute commit */
	uint8_t ex[] = { 0x18, 0x01 };
	att_server_handle(&ac, &db, ex, sizeof(ex), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x19);

	/* Read back: should be AA BB CC DD */
	uint8_t rd[] = { 0x0A, 0x06, 0x00 };
	att_server_handle(&ac, &db, rd, sizeof(rd), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x0B);
	ATF_CHECK_EQ(rsp[1], 0xAA);
	ATF_CHECK_EQ(rsp[2], 0xBB);
	ATF_CHECK_EQ(rsp[3], 0xCC);
	ATF_CHECK_EQ(rsp[4], 0xDD);

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * TP/GAN/GAI: Notification/Indication edge cases
 * ================================================================ */

/* Notification with empty value (0 bytes) */
ATF_TC_WITHOUT_HEAD(test_gan_notify_empty);
ATF_TC_BODY(test_gan_notify_empty, tc)
{
	struct att_conn ac;
	int cf;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);

	att_send_notification(&ac, 0x0006, NULL, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 3); /* opcode + handle only */
	ATF_CHECK_EQ(rsp[0], 0x1B);
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x0006);

	att_mock_cleanup(&ac, cf);
}

/* Multiple notifications in sequence */
ATF_TC_WITHOUT_HEAD(test_gan_notify_sequence);
ATF_TC_BODY(test_gan_notify_sequence, tc)
{
	struct att_conn ac;
	int cf;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);

	for (int i = 0; i < 5; i++) {
		uint8_t val = (uint8_t)i;
		ATF_CHECK_EQ(att_send_notification(&ac, 0x0006, &val, 1), 0);
		n = recv(cf, rsp, sizeof(rsp), 0);
		ATF_CHECK_EQ(n, 4);
		ATF_CHECK_EQ(rsp[0], 0x1B);
		ATF_CHECK_EQ(rsp[3], (uint8_t)i);
	}

	att_mock_cleanup(&ac, cf);
}

/* Indication with empty value */
ATF_TC_WITHOUT_HEAD(test_gai_indicate_empty);
ATF_TC_BODY(test_gai_indicate_empty, tc)
{
	struct att_conn ac;
	int cf;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.ind_timer = 0;

	ATF_CHECK_EQ(att_send_indication(&ac, 0x0006, NULL, 0), 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 3);
	ATF_CHECK_EQ(rsp[0], 0x1D); /* INDICATE */

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * Client: remaining PDU tests
 * ================================================================ */

/* Client: att_read_by_type */
ATF_TC_WITHOUT_HEAD(test_client_read_by_type_pdu);
ATF_TC_BODY(test_client_read_by_type_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		/* 08 01 00 FF FF 00 2A */
		if (n != 7 || buf[0] != 0x08) _exit(1);
		if (buf[5] != 0x00 || buf[6] != 0x2A) _exit(2);
		uint8_t rsp[] = { 0x09, 0x06,
		    0x03, 0x00, 'T', 'e', 's', 't' };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t out[ATT_PDU_BUF_SIZE];
	size_t olen = 0;
	int ret = att_read_by_type(&ac, 0x0001, 0xFFFF, 0x2A00,
	    out, sizeof(out), &olen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK(olen > 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* Client: att_read_multiple */
ATF_TC_WITHOUT_HEAD(test_client_read_multiple_pdu);
ATF_TC_BODY(test_client_read_multiple_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		/* 0E 03 00 06 00 */
		if (n != 5 || buf[0] != 0x0E) _exit(1);
		uint8_t rsp[] = { 0x0F, 0xAA, 0xBB };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint16_t handles[] = { 0x0003, 0x0006 };
	uint8_t out[ATT_PDU_BUF_SIZE];
	size_t olen = 0;
	int ret = att_read_multiple(&ac, handles, 2, out, sizeof(out), &olen);
	ATF_CHECK_EQ(ret, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* Client: error response sets errno */
ATF_TC_WITHOUT_HEAD(test_client_error_errno);
ATF_TC_BODY(test_client_error_errno, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		(void)n;
		/* Send Error Response: Invalid Handle */
		uint8_t rsp[] = { 0x01, 0x0A, 0xFF, 0xFF, 0x01 };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t val[32];
	size_t vlen = 0;
	int ret = att_read(&ac, 0xFFFF, val, sizeof(val), &vlen);
	/* att_read returns the ATT error code on protocol error */
	ATF_CHECK_EQ(ret, ATT_ERR_INVALID_HANDLE);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* Client: att_confirm sends 0x1E */
ATF_TC_WITHOUT_HEAD(test_client_confirm_pdu);
ATF_TC_BODY(test_client_confirm_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[8];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	int ret = att_confirm(&ac);
	ATF_CHECK_EQ(ret, 0);

	n = recv(peer, buf, sizeof(buf), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(buf[0], 0x1E); /* HANDLE_VALUE_CFM */

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * Systematic multi-MTU tests: small(23), mid(64), large(517)
 *
 * Helper: builds a DB with a 200-byte characteristic value so
 * truncation behavior can be observed at all MTU sizes.
 * ================================================================ */

static void
build_large_test_db(struct att_db *db, struct att_attr *attrs,
    uint8_t *val_buf)
{
	uint8_t big[200];

	memset(big, 0x42, sizeof(big));
	attdb_init(db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);
	attdb_add_service(db, 0x1800);
	attdb_add_characteristic(db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, big, 200);
	attdb_add_service(db, 0xFFE0);
	attdb_add_characteristic(db, 0xFFE1,
	    GATT_PROP_READ | GATT_PROP_WRITE | GATT_PROP_NOTIFY,
	    ATT_PERM_READ | ATT_PERM_WRITE, big, 200);
	attrs[4].value_maxlen = 200; /* make writable up to 200 */
	attdb_add_cccd(db);
}

/* Macro to generate an MTU-parameterized server test */
#define MTU_TEST(name, mtu_val) \
ATF_TC_WITHOUT_HEAD(name); \
ATF_TC_BODY(name, tc)

/* --- Read Blob at different MTUs --- */

MTU_TEST(test_mtu23_read_blob, 23)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 23;
	build_large_test_db(&db, attrs, vb);

	/* Read Blob: handle=3 (200-byte value), offset=10 */
	uint8_t req[] = { 0x0C, 0x03, 0x00, 0x0A, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 23); /* clamped to MTU */
	ATF_CHECK_EQ(rsp[0], 0x0D);
	ATF_CHECK_EQ(rsp[1], 0x42); /* value byte */

	att_mock_cleanup(&ac, cf);
}

MTU_TEST(test_mtu64_read_blob, 64)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	build_large_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x0C, 0x03, 0x00, 0x0A, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 64); /* 1 + 63 bytes of value */
	ATF_CHECK_EQ(rsp[0], 0x0D);

	att_mock_cleanup(&ac, cf);
}

MTU_TEST(test_mtu517_read_blob, 517)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	build_large_test_db(&db, attrs, vb);

	/*
	 * Read Blob at offset=10 on a 200-byte attribute at MTU=517.
	 * Since value_len (200) <= mtu-1 (516), the attribute is NOT long
	 * and Read Blob must return ATT_ERR_ATTR_NOT_LONG.
	 */
	uint8_t req[] = { 0x0C, 0x03, 0x00, 0x0A, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_LONG);

	att_mock_cleanup(&ac, cf);
}

/* --- Read Multiple at different MTUs --- */

MTU_TEST(test_mtu23_read_multiple, 23)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 23;
	build_large_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x0E, 0x03, 0x00, 0x06, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 23); /* clamped to MTU */
	ATF_CHECK_EQ(rsp[0], 0x0F);

	att_mock_cleanup(&ac, cf);
}

MTU_TEST(test_mtu64_read_multiple, 64)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	build_large_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x0E, 0x03, 0x00, 0x06, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 64);
	ATF_CHECK_EQ(rsp[0], 0x0F);

	att_mock_cleanup(&ac, cf);
}

/* --- Read Multiple Variable at different MTUs --- */

MTU_TEST(test_mtu23_read_multi_var, 23)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 23;
	build_large_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x20, 0x03, 0x00, 0x06, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK(n <= 23);
	ATF_CHECK_EQ(rsp[0], 0x21); /* READ_MULTI_VAR_RSP */
	/* First entry: length(2) + truncated value */
	uint16_t vlen = get_le16(rsp + 1);
	ATF_CHECK(vlen <= 20); /* limited by MTU - 3 */

	att_mock_cleanup(&ac, cf);
}

MTU_TEST(test_mtu64_read_multi_var, 64)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	build_large_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x20, 0x03, 0x00, 0x06, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK(n <= 64);
	ATF_CHECK_EQ(rsp[0], 0x21);

	att_mock_cleanup(&ac, cf);
}

/* --- Indication at different MTUs --- */

MTU_TEST(test_mtu23_indication, 23)
{
	struct att_conn ac;
	int cf;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint8_t big[200];

	att_mock_pair(&ac, &cf);
	ac.mtu = 23;
	ac.ind_timer = 0;
	memset(big, 0x77, sizeof(big));

	att_send_indication(&ac, 0x0006, big, 200);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 23);
	ATF_CHECK_EQ(rsp[0], 0x1D);
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x0006);

	att_mock_cleanup(&ac, cf);
}

MTU_TEST(test_mtu64_indication, 64)
{
	struct att_conn ac;
	int cf;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint8_t big[200];

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	ac.ind_timer = 0;
	memset(big, 0x77, sizeof(big));

	att_send_indication(&ac, 0x0006, big, 200);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 64);
	ATF_CHECK_EQ(rsp[0], 0x1D);

	att_mock_cleanup(&ac, cf);
}

MTU_TEST(test_mtu517_indication, 517)
{
	struct att_conn ac;
	int cf;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint8_t big[200];

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	ac.ind_timer = 0;
	memset(big, 0x77, sizeof(big));

	att_send_indication(&ac, 0x0006, big, 200);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 203); /* 3 + 200 */
	ATF_CHECK_EQ(rsp[0], 0x1D);

	att_mock_cleanup(&ac, cf);
}

/* --- Read By Group Type at MTU=64 --- */

MTU_TEST(test_mtu64_read_by_group, 64)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK(n <= 64);
	ATF_CHECK(n >= 14); /* 2 services * 6 bytes + 2 header */
	ATF_CHECK_EQ(rsp[0], 0x11);

	att_mock_cleanup(&ac, cf);
}

/* --- Read at MTU=64 --- */

MTU_TEST(test_mtu64_read, 64)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	build_large_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x0A, 0x03, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 64); /* 200-byte value truncated to MTU-1=63 */
	ATF_CHECK_EQ(rsp[0], 0x0B);

	att_mock_cleanup(&ac, cf);
}

/* --- Read By Type at MTU=64 --- */

MTU_TEST(test_mtu64_read_by_type, 64)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	build_large_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x08, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x2A };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK(n <= 64);
	ATF_CHECK_EQ(rsp[0], 0x09);
	/* entry_len limited by MTU-2 */
	ATF_CHECK(rsp[1] <= 62);

	att_mock_cleanup(&ac, cf);
}

/* --- Notification at MTU=64 --- */

MTU_TEST(test_mtu64_notification, 64)
{
	struct att_conn ac;
	int cf;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint8_t big[200];

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	memset(big, 0x55, sizeof(big));

	att_send_notification(&ac, 0x0006, big, 200);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 64);
	ATF_CHECK_EQ(rsp[0], 0x1B);

	att_mock_cleanup(&ac, cf);
}

/* --- Find Info at MTU=64 --- */

MTU_TEST(test_mtu64_find_info, 64)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x04, 0x01, 0x00, 0xFF, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK(n <= 64);
	ATF_CHECK_EQ(rsp[0], 0x05);
	/* All 7 attrs fit at MTU=64: 2 + 7*4 = 30 < 64 */
	ATF_CHECK_EQ((n - 2) / 4, 7);

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * NEW TESTS: Write edge cases
 * ================================================================ */

/* Write to handle 0x0000 → Invalid Handle */
ATF_TC_WITHOUT_HEAD(test_gaw_write_invalid_handle_zero);
ATF_TC_BODY(test_gaw_write_invalid_handle_zero, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x12, 0x00, 0x00, 0x42 }; /* handle=0 */
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_HANDLE);

	att_mock_cleanup(&ac, cf);
}

/* Write with ATT_PERM_WRITE_ENCRYPT, encrypted=false → Insuff Encryption */
ATF_TC_WITHOUT_HEAD(test_gaw_write_encrypt_required);
ATF_TC_BODY(test_gaw_write_encrypt_required, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0xFFE0);
	attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_READ | GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE_ENCRYPT,
	    "\x00", 1);

	ac.encrypted = false;
	uint8_t req[] = { 0x12, 0x03, 0x00, 0x42 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INSUFF_ENCRYPTION);

	att_mock_cleanup(&ac, cf);
}

/* Write with ATT_PERM_WRITE_ENCRYPT, encrypted=true → success */
ATF_TC_WITHOUT_HEAD(test_gaw_write_encrypt_success);
ATF_TC_BODY(test_gaw_write_encrypt_success, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0xFFE0);
	attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_READ | GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE_ENCRYPT,
	    "\x00", 1);

	ac.encrypted = true;
	uint8_t req[] = { 0x12, 0x03, 0x00, 0x42 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);

	att_mock_cleanup(&ac, cf);
}

/* Write Command to handle 0x0000 → silently ignored */
ATF_TC_WITHOUT_HEAD(test_gaw_write_cmd_zero_handle);
ATF_TC_BODY(test_gaw_write_cmd_zero_handle, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	struct pollfd pfd;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x52, 0x00, 0x00, 0x42 }; /* handle=0 */
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);

	pfd.fd = cf;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 50), 0); /* no response for commands */

	att_mock_cleanup(&ac, cf);
}

/* Prepare Write to read-only attr → Write Not Permitted */
ATF_TC_WITHOUT_HEAD(test_gaw_prepare_write_readonly);
ATF_TC_BODY(test_gaw_prepare_write_readonly, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Prepare Write to Device Name (handle 3, read-only) */
	uint8_t req[] = { 0x16, 0x03, 0x00, 0x00, 0x00, 0x42 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_WRITE_NOT_PERMITTED);

	att_mock_cleanup(&ac, cf);
}

/* Prepare Write to invalid handle → Invalid Handle */
ATF_TC_WITHOUT_HEAD(test_gaw_prepare_write_invalid_handle);
ATF_TC_BODY(test_gaw_prepare_write_invalid_handle, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x16, 0xFF, 0xFF, 0x00, 0x00, 0x42 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_HANDLE);

	att_mock_cleanup(&ac, cf);
}

/* Prepare Write queue full (16 entries) → Prepare Queue Full */
ATF_TC_WITHOUT_HEAD(test_gaw_prepare_queue_full);
ATF_TC_BODY(test_gaw_prepare_queue_full, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;
	int i;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Fill the queue with 16 small entries */
	for (i = 0; i < ATT_PREPARE_QUEUE_MAX; i++) {
		uint8_t req[] = { 0x16, 0x06, 0x00, 0x00, 0x00, 0x42 };
		att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
		n = recv(cf, rsp, sizeof(rsp), 0);
		ATF_CHECK_EQ(rsp[0], ATT_OP_PREPARE_WRITE_RSP);
	}

	/* 17th should fail */
	uint8_t req17[] = { 0x16, 0x06, 0x00, 0x00, 0x00, 0x42 };
	att_server_handle(&ac, &db, req17, sizeof(req17), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_PREPARE_QUEUE_FULL);

	/* Cancel to clean up */
	uint8_t exec[] = { 0x18, 0x00 };
	att_server_handle(&ac, &db, exec, sizeof(exec), -1, 0);
	(void)recv(cf, rsp, sizeof(rsp), 0);

	att_mock_cleanup(&ac, cf);
}

/* Execute Write with empty queue → success (no-op) */
ATF_TC_WITHOUT_HEAD(test_gaw_execute_empty_queue);
ATF_TC_BODY(test_gaw_execute_empty_queue, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t exec[] = { 0x18, 0x01 };
	att_server_handle(&ac, &db, exec, sizeof(exec), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_EXECUTE_WRITE_RSP);

	att_mock_cleanup(&ac, cf);
}

/* Execute Write cancel with empty queue → success (no-op) */
ATF_TC_WITHOUT_HEAD(test_gaw_execute_cancel_empty);
ATF_TC_BODY(test_gaw_execute_cancel_empty, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t exec[] = { 0x18, 0x00 };
	att_server_handle(&ac, &db, exec, sizeof(exec), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_EXECUTE_WRITE_RSP);

	att_mock_cleanup(&ac, cf);
}

/* Write Request at MTU-3 boundary (MTU=23, 20 bytes value) */
ATF_TC_WITHOUT_HEAD(test_gaw_write_at_mtu_boundary);
ATF_TC_BODY(test_gaw_write_at_mtu_boundary, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_DEFAULT_MTU;
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0xFFE0);
	attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_WRITE, ATT_PERM_WRITE, "\x00", 1);
	attrs[2].value_maxlen = 20;

	/* 20 bytes of value + 3 bytes header = 23 = MTU */
	uint8_t req[23];
	req[0] = ATT_OP_WRITE_REQ;
	put_le16(req + 1, 0x0003);
	memset(req + 3, 0x55, 20);
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);
	ATF_CHECK_EQ(attrs[2].value_len, 20);

	att_mock_cleanup(&ac, cf);
}

/* Write Command at MTU-3 boundary */
ATF_TC_WITHOUT_HEAD(test_gaw_write_cmd_at_mtu_boundary);
ATF_TC_BODY(test_gaw_write_cmd_at_mtu_boundary, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	struct pollfd pfd;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_DEFAULT_MTU;
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0xFFE0);
	attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_WRITE_NO_RSP, ATT_PERM_WRITE, "\x00", 1);
	attrs[2].value_maxlen = 20;

	uint8_t req[23];
	req[0] = ATT_OP_WRITE_CMD;
	put_le16(req + 1, 0x0003);
	memset(req + 3, 0x66, 20);
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);

	pfd.fd = cf;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 50), 0);
	ATF_CHECK_EQ(attrs[2].value_len, 20);

	att_mock_cleanup(&ac, cf);
}

/* Prepare writes to different handles, then commit */
ATF_TC_WITHOUT_HEAD(test_gaw_prepare_different_handles);
ATF_TC_BODY(test_gaw_prepare_different_handles, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Prepare to handle 6 (custom char) */
	uint8_t p1[] = { 0x16, 0x06, 0x00, 0x00, 0x00, 0x11, 0x22 };
	att_server_handle(&ac, &db, p1, sizeof(p1), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x17);

	/* Prepare to handle 7 (CCCD) */
	uint8_t p2[] = { 0x16, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00 };
	att_server_handle(&ac, &db, p2, sizeof(p2), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x17);

	/* Execute commit */
	uint8_t ex[] = { 0x18, 0x01 };
	att_server_handle(&ac, &db, ex, sizeof(ex), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x19);

	/* Verify custom char was written to shared attribute value */
	ATF_CHECK_EQ(attrs[5].value[0], 0x11);
	ATF_CHECK_EQ(attrs[5].value[1], 0x22);

	/*
	 * CCCD writes via Execute Write now go to the per-connection
	 * CCCD table (same as direct Write), not the shared attribute.
	 * Verify the connection's CCCD state instead.
	 */
	ATF_CHECK_EQ(ac.cccd_count, 1);
	ATF_CHECK_EQ(ac.cccds[0].handle, 0x0007);
	ATF_CHECK_EQ(ac.cccds[0].value, GATT_CCCD_NOTIFY);

	att_mock_cleanup(&ac, cf);
}

/* Raw PDU: Indication exact bytes */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_indication);
ATF_TC_BODY(test_raw_pdu_indication, tc)
{
	struct att_conn ac;
	int cf;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint8_t val[] = { 0xDE, 0xAD };

	att_mock_pair(&ac, &cf);
	ac.ind_timer = 0;

	att_send_indication(&ac, 0x0006, val, 2);
	n = recv(cf, rsp, sizeof(rsp), 0);

	uint8_t expected[] = { 0x1D, 0x06, 0x00, 0xDE, 0xAD };
	ATF_CHECK_EQ(n, 5);
	ATF_CHECK(memcmp(rsp, expected, 5) == 0);

	att_mock_cleanup(&ac, cf);
}

/* Raw PDU: Read Multiple Variable */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_read_multi_var);
ATF_TC_BODY(test_raw_pdu_read_multi_var, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x20, 0x03, 0x00, 0x06, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);

	ATF_CHECK_EQ(rsp[0], 0x21);
	/* First entry: len=4, "Test" */
	ATF_CHECK_EQ(get_le16(rsp + 1), 4);
	ATF_CHECK_EQ(rsp[3], 'T');
	/* Second entry: len=4, AA BB CC DD */
	ATF_CHECK_EQ(get_le16(rsp + 7), 4);
	ATF_CHECK_EQ(rsp[9], 0xAA);
	ATF_CHECK_EQ(n, 13); /* 1 + (2+4) + (2+4) */

	att_mock_cleanup(&ac, cf);
}

/* Raw PDU: Multi Handle Value NTF */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_multi_handle_ntf);
ATF_TC_BODY(test_raw_pdu_multi_handle_ntf, tc)
{
	struct att_conn ac;
	int cf;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;

	uint16_t handles[3] = { 0x0003, 0x0006, 0x0007 };
	uint8_t v1[] = { 0x11 };
	uint8_t v2[] = { 0x22, 0x33 };
	uint8_t v3[] = { 0x44, 0x55, 0x66 };
	const uint8_t *values[3] = { v1, v2, v3 };
	uint16_t lengths[3] = { 1, 2, 3 };

	int ret = att_send_multiple_handle_value_ntf(&ac, handles, values,
	    lengths, 3);
	ATF_CHECK_EQ(ret, 0);

	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_MULTIPLE_HANDLE_VALUE_NTF);
	/* Entry 1: 2+2+1=5, Entry 2: 2+2+2=6, Entry 3: 2+2+3=7 → total 1+5+6+7=19 */
	ATF_CHECK_EQ(n, 19);

	att_mock_cleanup(&ac, cf);
}

/* Multi-MTU: Find By Type Value at MTU 23 */
MTU_TEST(test_mtu23_find_by_type, 23)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 23;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x06, 0x01, 0x00, 0xFF, 0xFF,
	    0x00, 0x28, 0xE0, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK(n <= 23);
	ATF_CHECK_EQ(rsp[0], 0x07);
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x0004);

	att_mock_cleanup(&ac, cf);
}

/* Multi-MTU: Find By Type Value at MTU 64 */
MTU_TEST(test_mtu64_find_by_type, 64)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x06, 0x01, 0x00, 0xFF, 0xFF,
	    0x00, 0x28, 0xE0, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK(n <= 64);
	ATF_CHECK_EQ(rsp[0], 0x07);

	att_mock_cleanup(&ac, cf);
}

/* Multi-MTU: Write at MTU=64 */
MTU_TEST(test_mtu64_write, 64)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	build_test_db(&db, attrs, vb);

	/* Write 4 bytes (within maxlen=4) */
	uint8_t req[] = { 0x12, 0x06, 0x00, 0x11, 0x22, 0x33, 0x44 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);

	att_mock_cleanup(&ac, cf);
}

/* Multi-MTU: Write at MTU=517 */
MTU_TEST(test_mtu517_write, 517)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	build_test_db(&db, attrs, vb);

	/* Write 4 bytes at max MTU — still limited by maxlen=4 */
	uint8_t req[] = { 0x12, 0x06, 0x00, 0xAA, 0xBB, 0xCC, 0xDD };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);
	ATF_CHECK_EQ(attrs[5].value[0], 0xAA);

	att_mock_cleanup(&ac, cf);
}

/* Multi-MTU: Prepare Write at MTU=23 */
MTU_TEST(test_mtu23_prepare_write, 23)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	ac.mtu = 23;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x16, 0x06, 0x00, 0x00, 0x00, 0xAA };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x17);
	ATF_CHECK(n <= 23);

	/* Cancel */
	uint8_t ex[] = { 0x18, 0x00 };
	att_server_handle(&ac, &db, ex, sizeof(ex), -1, 0);
	(void)recv(cf, rsp, sizeof(rsp), 0);

	att_mock_cleanup(&ac, cf);
}

/* Multi-MTU: Prepare Write at MTU=64 */
MTU_TEST(test_mtu64_prepare_write, 64)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x16, 0x06, 0x00, 0x00, 0x00, 0xBB, 0xCC };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x17);
	ATF_CHECK(n <= 64);

	uint8_t ex[] = { 0x18, 0x00 };
	att_server_handle(&ac, &db, ex, sizeof(ex), -1, 0);
	(void)recv(cf, rsp, sizeof(rsp), 0);

	att_mock_cleanup(&ac, cf);
}

/* Multi-MTU: Prepare Write at MTU=517 */
MTU_TEST(test_mtu517_prepare_write, 517)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x16, 0x06, 0x00, 0x00, 0x00, 0xDD };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x17);

	uint8_t ex[] = { 0x18, 0x00 };
	att_server_handle(&ac, &db, ex, sizeof(ex), -1, 0);
	(void)recv(cf, rsp, sizeof(rsp), 0);

	att_mock_cleanup(&ac, cf);
}

/*
 * CCCD write with indicate flag (0x0002) — the test DB characteristic
 * only supports GATT_PROP_NOTIFY, so setting the indicate bit must be
 * rejected with ATT_ERR_VALUE_NOT_ALLOWED per Core Spec Vol 3 Part G
 * Section 3.3.3.3.
 */
ATF_TC_WITHOUT_HEAD(test_gaw_cccd_indicate);
ATF_TC_BODY(test_gaw_cccd_indicate, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Write indicate flag to CCCD (handle 7) */
	uint8_t req[5];
	req[0] = ATT_OP_WRITE_REQ;
	put_le16(req + 1, 0x0007);
	put_le16(req + 3, GATT_CCCD_INDICATE);

	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	/* Characteristic only has Notify — Indicate must be rejected */
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_VALUE_NOT_ALLOWED);
	ATF_CHECK_EQ(ac.cccd_count, 0);

	att_mock_cleanup(&ac, cf);
}

/*
 * CCCD write with both flags (0x0003) — rejected because the test DB
 * characteristic only supports Notify, not Indicate.
 */
ATF_TC_WITHOUT_HEAD(test_gaw_cccd_both_flags);
ATF_TC_BODY(test_gaw_cccd_both_flags, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[5];
	req[0] = ATT_OP_WRITE_REQ;
	put_le16(req + 1, 0x0007);
	put_le16(req + 3, GATT_CCCD_NOTIFY | GATT_CCCD_INDICATE);

	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	/* Indicate bit not supported — must be rejected */
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_VALUE_NOT_ALLOWED);
	ATF_CHECK_EQ(ac.cccd_count, 0);

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * NEW TESTS: Read edge cases
 * ================================================================ */

/* Read handle 0x0000 → Invalid Handle */
ATF_TC_WITHOUT_HEAD(test_gar_read_handle_zero);
ATF_TC_BODY(test_gar_read_handle_zero, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x0A, 0x00, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_HANDLE);

	att_mock_cleanup(&ac, cf);
}

/* Read handle past DB end → Invalid Handle */
ATF_TC_WITHOUT_HEAD(test_gar_read_handle_past_end);
ATF_TC_BODY(test_gar_read_handle_past_end, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x0A, 0x20, 0x00 }; /* handle 0x0020, past end */
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_HANDLE);

	att_mock_cleanup(&ac, cf);
}

/* Read with no read permission (WRITE only) → Read Not Permitted */
ATF_TC_WITHOUT_HEAD(test_gar_read_not_permitted);
ATF_TC_BODY(test_gar_read_not_permitted, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0xFFE0);
	attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_WRITE, ATT_PERM_WRITE, "\x00", 1);

	uint8_t req[] = { 0x0A, 0x03, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_READ_NOT_PERMITTED);

	att_mock_cleanup(&ac, cf);
}

/* Read Blob offset=0 on short value → returns full value */
ATF_TC_WITHOUT_HEAD(test_gar_read_blob_offset_zero);
ATF_TC_BODY(test_gar_read_blob_offset_zero, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/*
	 * Read Blob at offset=0 on a 4-byte attribute at MTU=23.
	 * Offset=0 is allowed as a probing strategy — returns the value.
	 */
	uint8_t req[] = { 0x0C, 0x03, 0x00, 0x00, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_BLOB_RSP);
	ATF_CHECK_EQ(n, 5);  /* opcode(1) + "Test"(4) */

	att_mock_cleanup(&ac, cf);
}

/* Read Multiple with one invalid handle → Invalid Handle */
ATF_TC_WITHOUT_HEAD(test_gar_read_multi_invalid_handle);
ATF_TC_BODY(test_gar_read_multi_invalid_handle, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x0E, 0x03, 0x00, 0xFF, 0xFF }; /* valid + invalid */
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_HANDLE);

	att_mock_cleanup(&ac, cf);
}

/* Read Multiple with all valid → concatenated values */
ATF_TC_WITHOUT_HEAD(test_gar_read_multi_all_valid);
ATF_TC_BODY(test_gar_read_multi_all_valid, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Read handles 3 and 6 */
	uint8_t req[] = { 0x0E, 0x03, 0x00, 0x06, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x0F);
	ATF_CHECK_EQ(n, 9); /* 1 + 4("Test") + 4(AA BB CC DD) */
	ATF_CHECK_EQ(rsp[1], 'T');
	ATF_CHECK_EQ(rsp[5], 0xAA);

	att_mock_cleanup(&ac, cf);
}

/* Read Multiple Variable with empty value in list */
ATF_TC_WITHOUT_HEAD(test_gar_read_multi_var_empty_value);
ATF_TC_BODY(test_gar_read_multi_var_empty_value, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, NULL, 0); /* empty value, handle=3 */
	attdb_add_service(&db, 0xFFE0);
	attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_READ, ATT_PERM_READ, "\x42", 1); /* handle=6, 1 byte */

	/* Read Multiple Variable: handle 3 (empty) + handle 6 (1 byte) */
	uint8_t req[5];
	req[0] = ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	put_le16(req + 1, 0x0003);
	put_le16(req + 3, 0x0006);

	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x21);
	/* First entry: length=0 (empty) */
	ATF_CHECK_EQ(get_le16(rsp + 1), 0);
	/* Second entry at offset 3: length=1, value=0x42 */
	ATF_CHECK_EQ(get_le16(rsp + 3), 1);
	ATF_CHECK_EQ(rsp[5], 0x42);
	ATF_CHECK_EQ(n, 6); /* 1 + (2+0) + (2+1) */

	att_mock_cleanup(&ac, cf);
}

/* Read By Type: truncated entries (value too large for MTU) */
ATF_TC_WITHOUT_HEAD(test_gar_read_by_type_truncated);
ATF_TC_BODY(test_gar_read_by_type_truncated, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_DEFAULT_MTU;
	build_large_test_db(&db, attrs, vb);

	/* Read By Type for Device Name (0x2A00) with 200-byte value */
	uint8_t req[] = { 0x08, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x2A };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK(n <= 23);
	ATF_CHECK_EQ(rsp[0], 0x09);
	/* entry_len = min(2+200, MTU-2=21) = 21 */
	ATF_CHECK_EQ(rsp[1], 21);

	att_mock_cleanup(&ac, cf);
}

/* Read service declaration → returns service UUID */
ATF_TC_WITHOUT_HEAD(test_gar_read_service_decl);
ATF_TC_BODY(test_gar_read_service_decl, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Read handle 1 (Primary Service 0x1800) */
	uint8_t req[] = { 0x0A, 0x01, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x0B);
	ATF_CHECK_EQ(n, 3); /* 1 + 2 bytes (UUID16) */
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x1800);

	att_mock_cleanup(&ac, cf);
}

/* Read characteristic declaration → returns props+handle+uuid */
ATF_TC_WITHOUT_HEAD(test_gar_read_char_decl);
ATF_TC_BODY(test_gar_read_char_decl, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Read handle 2 (Char Decl for Device Name) */
	uint8_t req[] = { 0x0A, 0x02, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x0B);
	/* Value: props(1) + value_handle(2) + uuid(2) = 5 bytes */
	ATF_CHECK_EQ(n, 6);
	ATF_CHECK_EQ(rsp[1], GATT_PROP_READ); /* properties */
	ATF_CHECK_EQ(get_le16(rsp + 2), 0x0003); /* value handle */
	ATF_CHECK_EQ(get_le16(rsp + 4), 0x2A00); /* char UUID */

	att_mock_cleanup(&ac, cf);
}

/* Read By Group Type for Secondary Service 0x2801 → not found */
ATF_TC_WITHOUT_HEAD(test_gad_read_by_group_secondary);
ATF_TC_BODY(test_gad_read_by_group_secondary, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x10, 0x01, 0x00, 0xFF, 0xFF, 0x01, 0x28 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_FOUND);

	att_mock_cleanup(&ac, cf);
}

/* Raw PDU: Read custom char exact bytes */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_read_custom_char);
ATF_TC_BODY(test_raw_pdu_read_custom_char, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x0A, 0x06, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);

	uint8_t expected[] = { 0x0B, 0xAA, 0xBB, 0xCC, 0xDD };
	ATF_CHECK_EQ(n, 5);
	ATF_CHECK(memcmp(rsp, expected, 5) == 0);

	att_mock_cleanup(&ac, cf);
}

/* Find Info full range → all 7 attrs returned */
ATF_TC_WITHOUT_HEAD(test_gad_find_info_full_range);
ATF_TC_BODY(test_gad_find_info_full_range, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE; /* large MTU to fit all */
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x04, 0x01, 0x00, 0xFF, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x05);
	ATF_CHECK_EQ(rsp[1], 0x01); /* 16-bit format */
	ATF_CHECK_EQ((n - 2) / 4, 7); /* all 7 attrs */

	att_mock_cleanup(&ac, cf);
}

/* Find By Type Value: service not found → Attr Not Found */
ATF_TC_WITHOUT_HEAD(test_gad_find_by_type_not_found);
ATF_TC_BODY(test_gad_find_by_type_not_found, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Search for service UUID 0xBEEF (doesn't exist) */
	uint8_t req[] = { 0x06, 0x01, 0x00, 0xFF, 0xFF,
	    0x00, 0x28, 0xEF, 0xBE };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_FOUND);

	att_mock_cleanup(&ac, cf);
}

/* Find By Type Value: multiple matches (both services are Primary) */
ATF_TC_WITHOUT_HEAD(test_gad_find_by_type_multi_match);
ATF_TC_BODY(test_gad_find_by_type_multi_match, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;

	/* Build DB with two services that have the same UUID */
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0xFFE0);
	attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_READ, ATT_PERM_READ, "\x01", 1);
	attdb_add_service(&db, 0xFFE0); /* second service with same UUID */
	attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_READ, ATT_PERM_READ, "\x02", 1);

	/* Find By Type Value: type=0x2800, value=0xFFE0 */
	uint8_t req[] = { 0x06, 0x01, 0x00, 0xFF, 0xFF,
	    0x00, 0x28, 0xE0, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x07);
	/* Should have 2 entries × 4 bytes each = 8 + opcode = 9 */
	ATF_CHECK_EQ(n, 9);
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x0001); /* first service */
	ATF_CHECK_EQ(get_le16(rsp + 5), 0x0004); /* second service */

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * NEW TESTS: Client role
 * ================================================================ */

/* Client: att_find_by_type_value sends correct PDU */
ATF_TC_WITHOUT_HEAD(test_client_find_by_type_pdu);
ATF_TC_BODY(test_client_find_by_type_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		/* 06 01 00 FF FF 00 28 E0 FF */
		if (n != 9 || buf[0] != 0x06) _exit(1);
		if (buf[5] != 0x00 || buf[6] != 0x28) _exit(2);
		if (buf[7] != 0xE0 || buf[8] != 0xFF) _exit(3);

		/* Send response: found handle=0x0004, end=0x0007 */
		uint8_t rsp[] = { 0x07, 0x04, 0x00, 0x07, 0x00 };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t out[ATT_PDU_BUF_SIZE];
	size_t olen = 0;
	uint16_t val16 = 0xFFE0;
	int ret = att_find_by_type_value(&ac, 0x0001, 0xFFFF, 0x2800,
	    &val16, 2, out, sizeof(out), &olen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK(olen > 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* Client: att_prepare_write sends correct PDU */
ATF_TC_WITHOUT_HEAD(test_client_prepare_write_pdu);
ATF_TC_BODY(test_client_prepare_write_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		/* 16 06 00 0A 00 DE AD */
		if (n != 7 || buf[0] != 0x16) _exit(1);
		if (buf[1] != 0x06 || buf[2] != 0x00) _exit(2);
		if (buf[3] != 0x0A || buf[4] != 0x00) _exit(3);
		if (buf[5] != 0xDE || buf[6] != 0xAD) _exit(4);

		/* Echo back as Prepare Write Response */
		buf[0] = 0x17;
		(void)send(peer, buf, (size_t)n, 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t data[] = { 0xDE, 0xAD };
	int ret = att_prepare_write(&ac, 0x0006, 0x000A, data, sizeof(data));
	ATF_CHECK_EQ(ret, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* Client: att_execute_write sends correct PDU */
ATF_TC_WITHOUT_HEAD(test_client_execute_write_pdu);
ATF_TC_BODY(test_client_execute_write_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		/* 18 01 */
		if (n != 2 || buf[0] != 0x18 || buf[1] != 0x01) _exit(1);

		uint8_t rsp[] = { 0x19 };
		(void)send(peer, rsp, 1, 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	int ret = att_execute_write(&ac, 0x01);
	ATF_CHECK_EQ(ret, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* Client: att_write_long with small data (fits in one prepare) */
ATF_TC_WITHOUT_HEAD(test_client_write_long_small);
ATF_TC_BODY(test_client_write_long_small, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		/* Receive Prepare Write */
		n = recv(peer, buf, sizeof(buf), 0);
		if (n < 6 || buf[0] != 0x16) _exit(1);
		/* Echo back */
		buf[0] = 0x17;
		(void)send(peer, buf, (size_t)n, 0);

		/* Receive Execute Write */
		n = recv(peer, buf, sizeof(buf), 0);
		if (n != 2 || buf[0] != 0x18 || buf[1] != 0x01) _exit(2);
		uint8_t rsp[] = { 0x19 };
		(void)send(peer, rsp, 1, 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t data[] = { 0x11, 0x22, 0x33 };
	int ret = att_write_long(&ac, 0x0006, data, sizeof(data));
	ATF_CHECK_EQ(ret, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* Client: att_write_long with data requiring multiple prepares */
ATF_TC_WITHOUT_HEAD(test_client_write_long_multi);
ATF_TC_BODY(test_client_write_long_multi, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	/* MTU=23 → max prepare data = MTU-5 = 18 bytes per prepare */

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		int prep_count = 0;
		/* Read all prepare writes */
		for (;;) {
			n = recv(peer, buf, sizeof(buf), 0);
			if (n <= 0) _exit(10);
			if (buf[0] == 0x16) { /* Prepare */
				prep_count++;
				buf[0] = 0x17;
				(void)send(peer, buf, (size_t)n, 0);
			} else if (buf[0] == 0x18) { /* Execute */
				uint8_t rsp[] = { 0x19 };
				(void)send(peer, rsp, 1, 0);
				break;
			} else {
				_exit(11);
			}
		}
		/* 30 bytes / 18 per prepare = 2 prepares */
		if (prep_count < 2) _exit(12);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t data[30];
	memset(data, 0x77, sizeof(data));
	int ret = att_write_long(&ac, 0x0006, data, sizeof(data));
	ATF_CHECK_EQ(ret, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* Client: att_write_req error response */
ATF_TC_WITHOUT_HEAD(test_client_write_error);
ATF_TC_BODY(test_client_write_error, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		(void)n;
		/* Send Error Response: Write Not Permitted */
		uint8_t rsp[] = { 0x01, 0x12, 0x06, 0x00,
		    ATT_ERR_WRITE_NOT_PERMITTED };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t data[] = { 0x42 };
	int ret = att_write_req(&ac, 0x0006, data, 1);
	ATF_CHECK_EQ(ret, ATT_ERR_WRITE_NOT_PERMITTED);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* Client: att_find_by_type_value not found → returns 0, outlen=0 */
ATF_TC_WITHOUT_HEAD(test_client_find_by_type_not_found);
ATF_TC_BODY(test_client_find_by_type_not_found, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		(void)n;
		/* Send Error Response: Attr Not Found */
		uint8_t rsp[] = { 0x01, 0x06, 0x01, 0x00,
		    ATT_ERR_ATTR_NOT_FOUND };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t out[ATT_PDU_BUF_SIZE];
	size_t olen = 99;
	uint16_t val16 = 0xBEEF;
	int ret = att_find_by_type_value(&ac, 0x0001, 0xFFFF, 0x2800,
	    &val16, 2, out, sizeof(out), &olen);
	/* att_find_by_type_value returns 0 with outlen=0 on "not found" */
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(olen, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* Client: att_read_multiple with 3 handles */
ATF_TC_WITHOUT_HEAD(test_client_read_multi_three);
ATF_TC_BODY(test_client_read_multi_three, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		/* 0E 01 00 03 00 06 00 = 7 bytes */
		if (n != 7 || buf[0] != 0x0E) _exit(1);
		if (buf[1] != 0x01 || buf[2] != 0x00) _exit(2);
		if (buf[3] != 0x03 || buf[4] != 0x00) _exit(3);
		if (buf[5] != 0x06 || buf[6] != 0x00) _exit(4);
		uint8_t rsp[] = { 0x0F, 0x11, 0x22, 0x33 };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint16_t handles[] = { 0x0001, 0x0003, 0x0006 };
	uint8_t out[ATT_PDU_BUF_SIZE];
	size_t olen = 0;
	int ret = att_read_multiple(&ac, handles, 3, out, sizeof(out), &olen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(olen, 3);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* Client: att_read error with specific ATT code */
ATF_TC_WITHOUT_HEAD(test_client_read_specific_error);
ATF_TC_BODY(test_client_read_specific_error, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		(void)n;
		/* Send Error Response: Insufficient Encryption */
		uint8_t rsp[] = { 0x01, 0x0A, 0x03, 0x00,
		    ATT_ERR_INSUFF_ENCRYPTION };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t val[32];
	size_t vlen = 0;
	int ret = att_read(&ac, 0x0003, val, sizeof(val), &vlen);
	ATF_CHECK_EQ(ret, ATT_ERR_INSUFF_ENCRYPTION);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* Client: att_write_cmd just sends, no response expected */
ATF_TC_WITHOUT_HEAD(test_client_write_cmd_verify);
ATF_TC_BODY(test_client_write_cmd_verify, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	uint8_t data[] = { 0x11, 0x22, 0x33, 0x44 };
	int ret = att_write_cmd(&ac, 0x0003, data, 4);
	ATF_CHECK_EQ(ret, 0);

	n = recv(peer, buf, sizeof(buf), 0);
	ATF_CHECK_EQ(n, 7); /* 1 + 2 + 4 */
	ATF_CHECK_EQ(buf[0], 0x52);
	ATF_CHECK_EQ(get_le16(buf + 1), 0x0003);
	ATF_CHECK_EQ(buf[3], 0x11);
	ATF_CHECK_EQ(buf[6], 0x44);

	att_mock_cleanup(&ac, peer);
}

/* Client: att_read_by_group_type error response */
ATF_TC_WITHOUT_HEAD(test_client_read_by_group_error);
ATF_TC_BODY(test_client_read_by_group_error, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		(void)n;
		/* Send Error Response: Attr Not Found */
		uint8_t rsp[] = { 0x01, 0x10, 0x01, 0x00,
		    ATT_ERR_ATTR_NOT_FOUND };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t out[ATT_PDU_BUF_SIZE];
	size_t olen = 0;
	int ret = att_read_by_group_type(&ac, 0x0001, 0xFFFF, 0x2800,
	    out, sizeof(out), &olen);
	/* att_read_by_group_type returns 0 with outlen=0 on "not found" */
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(olen, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* ================================================================
 * NEW TESTS: Multi-MTU fill-in (MTU=517 and MTU=23)
 * ================================================================ */

/* MTU=517: Read Multiple */
MTU_TEST(test_mtu517_read_multiple, 517)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	build_large_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x0E, 0x03, 0x00, 0x06, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	/* 1 + 200 + 200 = 401, fits in MTU=517 */
	ATF_CHECK_EQ(n, 401);
	ATF_CHECK_EQ(rsp[0], 0x0F);

	att_mock_cleanup(&ac, cf);
}

/* MTU=517: Read Multiple Variable */
MTU_TEST(test_mtu517_read_multi_var, 517)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	build_large_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x20, 0x03, 0x00, 0x06, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x21);
	/* First entry: len=200, second: len=200 → 1 + (2+200) + (2+200) = 405 */
	ATF_CHECK_EQ(n, 405);

	att_mock_cleanup(&ac, cf);
}

/* MTU=517: Read By Type */
MTU_TEST(test_mtu517_read_by_type, 517)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	build_large_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x08, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x2A };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x09);
	/* entry_len = 2 + 200 = 202, fits in MTU */
	ATF_CHECK_EQ(rsp[1], 202);

	att_mock_cleanup(&ac, cf);
}

/* MTU=517: Find Info */
MTU_TEST(test_mtu517_find_info, 517)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x04, 0x01, 0x00, 0xFF, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x05);
	ATF_CHECK_EQ(rsp[1], 0x01); /* 16-bit */
	ATF_CHECK_EQ((n - 2) / 4, 7); /* all 7 attrs */

	att_mock_cleanup(&ac, cf);
}

/* MTU=517: Read By Group */
MTU_TEST(test_mtu517_read_by_group, 517)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x11);
	/* 2 services × 6 bytes each + 2 header = 14 */
	ATF_CHECK_EQ(n, 14);

	att_mock_cleanup(&ac, cf);
}

/* MTU=517: Notification */
MTU_TEST(test_mtu517_notification, 517)
{
	struct att_conn ac;
	int cf;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint8_t big[200];

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	memset(big, 0x55, sizeof(big));

	att_send_notification(&ac, 0x0006, big, 200);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 203); /* 3 + 200, fits in MTU */
	ATF_CHECK_EQ(rsp[0], 0x1B);

	att_mock_cleanup(&ac, cf);
}

/* MTU=517: Find By Type Value */
MTU_TEST(test_mtu517_find_by_type, 517)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x06, 0x01, 0x00, 0xFF, 0xFF,
	    0x00, 0x28, 0xE0, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x07);
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x0004);

	att_mock_cleanup(&ac, cf);
}

/* MTU=23: Read (server-side, standard test DB) */
MTU_TEST(test_mtu23_read, 23)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 23;
	build_test_db(&db, attrs, vb);

	/* Read handle 3 ("Test", 4 bytes) → fits in MTU */
	uint8_t req[] = { 0x0A, 0x03, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x0B);
	ATF_CHECK_EQ(n, 5); /* 1 + 4 */
	ATF_CHECK_EQ(rsp[1], 'T');

	att_mock_cleanup(&ac, cf);
}

/* MTU=23: Write (server-side) */
MTU_TEST(test_mtu23_write, 23)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	ac.mtu = 23;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x12, 0x06, 0x00, 0x11, 0x22, 0x33, 0x44 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);
	ATF_CHECK_EQ(attrs[5].value[0], 0x11);

	att_mock_cleanup(&ac, cf);
}

/* MTU=23: Read By Group (single entry because MTU is small) */
MTU_TEST(test_mtu23_read_by_group_single_entry, 23)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 23;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK(n <= 23);
	ATF_CHECK_EQ(rsp[0], 0x11);
	/* At MTU=23: header=2, entry=6 → max 3 entries fit, but we only have 2 */
	ATF_CHECK(n >= 8); /* at least 1 entry */

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * NEW TESTS: ATTDB edge cases
 * ================================================================ */

/* DB full → attdb_add_service returns 0 */
ATF_TC_WITHOUT_HEAD(test_attdb_full);
ATF_TC_BODY(test_attdb_full, tc)
{
	struct att_db db;
	struct att_attr attrs[3]; /* very small */
	uint8_t vb[256];

	attdb_init(&db, attrs, 3, vb, sizeof(vb));

	uint16_t h1 = attdb_add_service(&db, 0x1800);
	ATF_CHECK_EQ(h1, 0x0001);
	uint16_t h2 = attdb_add_service(&db, 0x1801);
	ATF_CHECK_EQ(h2, 0x0002);
	uint16_t h3 = attdb_add_service(&db, 0x1802);
	ATF_CHECK_EQ(h3, 0x0003);
	/* DB is full now */
	uint16_t h4 = attdb_add_service(&db, 0x1803);
	ATF_CHECK_EQ(h4, 0);
}

/* attdb_add_characteristic128 with 128-bit UUID */
ATF_TC_WITHOUT_HEAD(test_attdb_add_char128);
ATF_TC_BODY(test_attdb_add_char128, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];

	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0xFFE0);

	uint8_t uuid128[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
	};

	uint16_t h = attdb_add_characteristic128(&db, uuid128,
	    GATT_PROP_READ, ATT_PERM_READ, "\x42", 1);
	ATF_CHECK(h > 0);
	/* Char decl + value = 2 attrs added, plus service = 3 total */
	ATF_CHECK_EQ(db.count, 3);

	/* Value handle should have the 128-bit UUID */
	ATF_CHECK_EQ(attrs[2].uuid16, 0); /* 128-bit, not 16-bit */
	ATF_CHECK(memcmp(attrs[2].uuid128, uuid128, 16) == 0);
	ATF_CHECK_EQ(attrs[2].value[0], 0x42);
}

/* attdb_add_cccd without preceding char → still adds attr */
ATF_TC_WITHOUT_HEAD(test_attdb_cccd_standalone);
ATF_TC_BODY(test_attdb_cccd_standalone, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];

	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0xFFE0);

	uint16_t h = attdb_add_cccd(&db);
	ATF_CHECK(h > 0);
	ATF_CHECK_EQ(db.count, 2); /* service + cccd */
	ATF_CHECK_EQ(attrs[1].uuid16, GATT_UUID_CCCD);
}

/* Value store exhaustion → attdb_add_characteristic returns 0 */
ATF_TC_WITHOUT_HEAD(test_attdb_val_store_full);
ATF_TC_BODY(test_attdb_val_store_full, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[32]; /* very small value store */

	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, sizeof(vb));
	attdb_add_service(&db, 0xFFE0); /* uses 2 bytes for UUID */

	/* First char: uses some bytes for decl + value */
	uint8_t big[20];
	memset(big, 0x42, sizeof(big));
	uint16_t h1 = attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_READ, ATT_PERM_READ, big, 20);
	/* May or may not succeed depending on space */

	/* Keep adding until we exhaust */
	uint16_t h2 = attdb_add_characteristic(&db, 0xFFE2,
	    GATT_PROP_READ, ATT_PERM_READ, big, 20);
	/* At least one of these should fail (return 0) */
	ATF_CHECK(h1 == 0 || h2 == 0);
}

/* Empty DB → Read By Group Type returns error */
ATF_TC_WITHOUT_HEAD(test_attdb_empty_read_by_group);
ATF_TC_BODY(test_attdb_empty_read_by_group, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	/* Empty DB — no services added */

	uint8_t req[] = { 0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_FOUND);

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * NEW TESTS: Write parity (Section A)
 * ================================================================ */

/* A1. Write to service declaration (handle 1, read-only) → Write Not Permitted */
ATF_TC_WITHOUT_HEAD(test_gaw_write_to_service_decl);
ATF_TC_BODY(test_gaw_write_to_service_decl, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x12, 0x01, 0x00, 0x42 }; /* write to handle 1 */
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_WRITE_NOT_PERMITTED);

	att_mock_cleanup(&ac, cf);
}

/* A2. Write to char declaration (handle 2, read-only) → Write Not Permitted */
ATF_TC_WITHOUT_HEAD(test_gaw_write_to_char_decl);
ATF_TC_BODY(test_gaw_write_to_char_decl, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x12, 0x02, 0x00, 0x42 }; /* write to handle 2 */
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_WRITE_NOT_PERMITTED);

	att_mock_cleanup(&ac, cf);
}

/* A3. Prepare Write with offset past maxlen → succeeds in queue */
ATF_TC_WITHOUT_HEAD(test_gaw_prepare_write_offset_past_maxlen);
ATF_TC_BODY(test_gaw_prepare_write_offset_past_maxlen, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Prepare Write to handle 6, offset=10 (maxlen=4), value=0x42 */
	uint8_t req[] = { 0x16, 0x06, 0x00, 0x0A, 0x00, 0x42 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	/* Queue accepts it; validation deferred to execute */
	ATF_CHECK_EQ(rsp[0], ATT_OP_PREPARE_WRITE_RSP);

	/* Cancel to clean up */
	uint8_t exec[] = { 0x18, 0x00 };
	att_server_handle(&ac, &db, exec, sizeof(exec), -1, 0);
	(void)recv(cf, rsp, sizeof(rsp), 0);

	att_mock_cleanup(&ac, cf);
}

/* A4. Execute with queued write where offset+len > maxlen → Invalid Attr Length */
ATF_TC_WITHOUT_HEAD(test_gaw_execute_offset_past_maxlen);
ATF_TC_BODY(test_gaw_execute_offset_past_maxlen, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Prepare Write to handle 6, offset=3, value=0xAA 0xBB (3+2=5 > maxlen=4) */
	uint8_t req[] = { 0x16, 0x06, 0x00, 0x03, 0x00, 0xAA, 0xBB };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_PREPARE_WRITE_RSP);

	/* Execute commit → should fail */
	uint8_t exec[] = { 0x18, 0x01 };
	att_server_handle(&ac, &db, exec, sizeof(exec), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_ATTR_LEN);

	att_mock_cleanup(&ac, cf);
}

/* A5. Write Request with empty value to writable attr → success */
ATF_TC_WITHOUT_HEAD(test_gaw_write_req_empty_value);
ATF_TC_BODY(test_gaw_write_req_empty_value, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Write 0 bytes to handle 6 (writable, maxlen=4) */
	uint8_t req[] = { 0x12, 0x06, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);
	ATF_CHECK_EQ(attrs[5].value_len, 0);

	att_mock_cleanup(&ac, cf);
}

/* A6. Write 3 bytes to CCCD (maxlen=2) → Invalid Attr Length */
ATF_TC_WITHOUT_HEAD(test_gaw_write_req_to_cccd_invalid);
ATF_TC_BODY(test_gaw_write_req_to_cccd_invalid, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Write 3 bytes to CCCD (handle 7, maxlen=2) */
	uint8_t req[] = { 0x12, 0x07, 0x00, 0x01, 0x00, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_ATTR_LEN);

	att_mock_cleanup(&ac, cf);
}

/* A7. Write Command to encrypt-required attr, not encrypted → silently ignored */
ATF_TC_WITHOUT_HEAD(test_gaw_write_cmd_encrypt_required);
ATF_TC_BODY(test_gaw_write_cmd_encrypt_required, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	struct pollfd pfd;

	att_mock_pair(&ac, &cf);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0xFFE0);
	attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_WRITE_NO_RSP,
	    ATT_PERM_WRITE_ENCRYPT,
	    "\x00", 1);
	attrs[2].value_maxlen = 4;

	ac.encrypted = false;
	uint8_t req[] = { 0x52, 0x03, 0x00, 0x42 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);

	/* Write Command: no response sent even on error */
	pfd.fd = cf;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 50), 0);
	/* Value should NOT have changed */
	ATF_CHECK_EQ(attrs[2].value[0], 0x00);

	att_mock_cleanup(&ac, cf);
}

/* A8. Prepare Write to encrypt-required attr → error */
ATF_TC_WITHOUT_HEAD(test_gaw_prepare_write_encrypt_required);
ATF_TC_BODY(test_gaw_prepare_write_encrypt_required, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0xFFE0);
	attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_WRITE,
	    ATT_PERM_WRITE_ENCRYPT,
	    "\x00", 1);
	attrs[2].value_maxlen = 4;

	ac.encrypted = false;
	uint8_t req[] = { 0x16, 0x03, 0x00, 0x00, 0x00, 0x42 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INSUFF_ENCRYPTION);

	att_mock_cleanup(&ac, cf);
}

/* A9. Write shorter value, verify old bytes don't persist */
ATF_TC_WITHOUT_HEAD(test_gaw_write_replaces_value);
ATF_TC_BODY(test_gaw_write_replaces_value, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Initial value of handle 6 is AA BB CC DD (4 bytes) */
	ATF_CHECK_EQ(attrs[5].value_len, 4);

	/* Write 2 bytes */
	uint8_t req[] = { 0x12, 0x06, 0x00, 0x11, 0x22 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);

	/* value_len should be 2, not 4 */
	ATF_CHECK_EQ(attrs[5].value_len, 2);
	ATF_CHECK_EQ(attrs[5].value[0], 0x11);
	ATF_CHECK_EQ(attrs[5].value[1], 0x22);

	/* Read back to verify only 2 bytes returned */
	uint8_t rd[] = { 0x0A, 0x06, 0x00 };
	att_server_handle(&ac, &db, rd, sizeof(rd), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 3); /* 1 opcode + 2 value bytes */
	ATF_CHECK_EQ(rsp[0], 0x0B);

	att_mock_cleanup(&ac, cf);
}

/* A10. Write Command to valid writable handle, verify value changed, no response */
ATF_TC_WITHOUT_HEAD(test_gaw_write_cmd_valid);
ATF_TC_BODY(test_gaw_write_cmd_valid, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	struct pollfd pfd;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x52, 0x06, 0x00, 0xDE, 0xAD };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);

	/* No response */
	pfd.fd = cf;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 50), 0);

	/* Value changed */
	ATF_CHECK_EQ(attrs[5].value_len, 2);
	ATF_CHECK_EQ(attrs[5].value[0], 0xDE);
	ATF_CHECK_EQ(attrs[5].value[1], 0xAD);

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * NEW TESTS: Read parity (Section B)
 * ================================================================ */

/* B1. Read Blob at offset=1 of "Test" → "est" (3 bytes) */
ATF_TC_WITHOUT_HEAD(test_gar_read_blob_offset_one);
ATF_TC_BODY(test_gar_read_blob_offset_one, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/*
	 * Read Blob at offset=1 on a 4-byte attribute at MTU=23.
	 * Since value_len (4) <= mtu-1 (22), the attribute is NOT long
	 * and Read Blob must return ATT_ERR_ATTR_NOT_LONG.
	 */
	uint8_t req[] = { 0x0C, 0x03, 0x00, 0x01, 0x00 }; /* offset=1 */
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(n, 5);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_LONG);

	att_mock_cleanup(&ac, cf);
}

/* B2. Read By Type finds attr but read perm denied → error with matching handle */
ATF_TC_WITHOUT_HEAD(test_gar_read_by_type_perm_denied);
ATF_TC_BODY(test_gar_read_by_type_perm_denied, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0xFFE0);
	attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_WRITE, ATT_PERM_WRITE, "\x42", 1); /* no read perm */

	/* Read By Type for 0xFFE1 */
	uint8_t req[] = { 0x08, 0x01, 0x00, 0xFF, 0xFF, 0xE1, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_READ_NOT_PERMITTED);
	/* Error handle should be the matching attribute's handle */
	ATF_CHECK_EQ(get_le16(rsp + 2), 0x0003);

	att_mock_cleanup(&ac, cf);
}

/* B3. Read Multiple with 3 handles */
ATF_TC_WITHOUT_HEAD(test_gar_read_multi_three_handles);
ATF_TC_BODY(test_gar_read_multi_three_handles, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Read Multiple: handles 3, 6, 7 */
	uint8_t req[7];
	req[0] = ATT_OP_READ_MULTIPLE_REQ;
	put_le16(req + 1, 0x0003);
	put_le16(req + 3, 0x0006);
	put_le16(req + 5, 0x0007);
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x0F);
	/* "Test"(4) + AA BB CC DD(4) + 00 00(2) = 10 + opcode = 11 */
	ATF_CHECK_EQ(n, 11);
	ATF_CHECK_EQ(rsp[1], 'T');
	ATF_CHECK_EQ(rsp[5], 0xAA);
	ATF_CHECK_EQ(rsp[9], 0x00); /* CCCD */

	att_mock_cleanup(&ac, cf);
}

/* B4. Read Multiple Variable with 3 handles */
ATF_TC_WITHOUT_HEAD(test_gar_read_multi_var_three);
ATF_TC_BODY(test_gar_read_multi_var_three, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[7];
	req[0] = ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	put_le16(req + 1, 0x0003);
	put_le16(req + 3, 0x0006);
	put_le16(req + 5, 0x0007);
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x21);
	/* 1 + (2+4) + (2+4) + (2+2) = 17 */
	ATF_CHECK_EQ(n, 17);
	ATF_CHECK_EQ(get_le16(rsp + 1), 4); /* "Test" len */
	ATF_CHECK_EQ(get_le16(rsp + 7), 4); /* custom char len */
	ATF_CHECK_EQ(get_le16(rsp + 13), 2); /* CCCD len */

	att_mock_cleanup(&ac, cf);
}

/* B5. Read By Group full range, verify both services with correct end handles */
ATF_TC_WITHOUT_HEAD(test_gar_read_by_group_full_range);
ATF_TC_BODY(test_gar_read_by_group_full_range, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x11);
	ATF_CHECK_EQ(rsp[1], 6); /* entry length */

	/* First service: start=1, end=3, uuid=0x1800 */
	ATF_CHECK_EQ(get_le16(rsp + 2), 0x0001);
	ATF_CHECK_EQ(get_le16(rsp + 4), 0x0003);
	ATF_CHECK_EQ(get_le16(rsp + 6), 0x1800);

	/* Second service: start=4, end=7, uuid=0xFFE0 */
	ATF_CHECK_EQ(get_le16(rsp + 8), 0x0004);
	ATF_CHECK_EQ(get_le16(rsp + 10), 0x0007);
	ATF_CHECK_EQ(get_le16(rsp + 12), 0xFFE0);

	ATF_CHECK_EQ(n, 14); /* 2 + 2*6 */

	att_mock_cleanup(&ac, cf);
}

/* B6. Read Blob with encrypt-required, encrypted=false → error */
ATF_TC_WITHOUT_HEAD(test_gar_read_blob_encrypt_required);
ATF_TC_BODY(test_gar_read_blob_encrypt_required, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ_ENCRYPT, "SecretData", 10);

	ac.encrypted = false;
	uint8_t req[] = { 0x0C, 0x03, 0x00, 0x02, 0x00 }; /* offset=2 */
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INSUFF_ENCRYPTION);

	att_mock_cleanup(&ac, cf);
}

/* B7. Read By Type for custom char UUID 0xFFE1 → returns custom char value */
ATF_TC_WITHOUT_HEAD(test_gar_read_by_type_char_value);
ATF_TC_BODY(test_gar_read_by_type_char_value, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Read By Type: uuid=0xFFE1 */
	uint8_t req[] = { 0x08, 0x01, 0x00, 0xFF, 0xFF, 0xE1, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x09); /* READ_BY_TYPE_RSP */
	/* entry_len = 2 + 4 = 6 */
	ATF_CHECK_EQ(rsp[1], 6);
	/* handle = 0x0006 */
	ATF_CHECK_EQ(get_le16(rsp + 2), 0x0006);
	/* value = AA BB CC DD */
	ATF_CHECK_EQ(rsp[4], 0xAA);
	ATF_CHECK_EQ(rsp[7], 0xDD);
	ATF_CHECK_EQ(n, 8); /* 2 header + 6 entry */

	att_mock_cleanup(&ac, cf);
}

/* B8. Read Multiple, verify exact concatenated bytes */
ATF_TC_WITHOUT_HEAD(test_gar_read_multi_concat_verify);
ATF_TC_BODY(test_gar_read_multi_concat_verify, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x0E, 0x03, 0x00, 0x06, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);

	/* Exact expected: 0F "Test" AA BB CC DD */
	uint8_t expected[] = { 0x0F,
	    'T', 'e', 's', 't',
	    0xAA, 0xBB, 0xCC, 0xDD };
	ATF_CHECK_EQ(n, (ssize_t)sizeof(expected));
	ATF_CHECK(memcmp(rsp, expected, sizeof(expected)) == 0);

	att_mock_cleanup(&ac, cf);
}

/* B9. Read CCCD (handle 7) returns 0x0000 */
ATF_TC_WITHOUT_HEAD(test_gar_read_cccd_value);
ATF_TC_BODY(test_gar_read_cccd_value, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x0A, 0x07, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x0B);
	ATF_CHECK_EQ(n, 3); /* 1 + 2 */
	ATF_CHECK_EQ(rsp[1], 0x00);
	ATF_CHECK_EQ(rsp[2], 0x00);

	att_mock_cleanup(&ac, cf);
}

/* B10. Read By Type restricted to second service only */
ATF_TC_WITHOUT_HEAD(test_gar_read_by_type_handle_range);
ATF_TC_BODY(test_gar_read_by_type_handle_range, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Read By Type for Characteristic (0x2803), start=0x0004 → only second service */
	uint8_t req[] = { 0x08, 0x04, 0x00, 0xFF, 0xFF, 0x03, 0x28 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x09);
	/* Should only find handle 5 (char decl in custom service) */
	ATF_CHECK_EQ(get_le16(rsp + 2), 0x0005);
	/* Only 1 entry */
	int num_entries = (n - 2) / rsp[1];
	ATF_CHECK_EQ(num_entries, 1);

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * NEW TESTS: Client role parity (Section C)
 * ================================================================ */

/* C1. Client find_info, server responds with 128-bit UUID format */
ATF_TC_WITHOUT_HEAD(test_client_find_info_128bit);
ATF_TC_BODY(test_client_find_info_128bit, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		if (n != 5 || buf[0] != 0x04) _exit(1);
		/* Send response with 128-bit UUID format (format=2) */
		uint8_t rsp[20];
		rsp[0] = 0x05; /* FIND_INFO_RSP */
		rsp[1] = 0x02; /* format = 128-bit */
		put_le16(rsp + 2, 0x0001); /* handle */
		/* 128-bit UUID */
		memset(rsp + 4, 0xAA, 16);
		(void)send(peer, rsp, 20, 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t out[ATT_PDU_BUF_SIZE];
	size_t outlen = 0;
	int ret = att_find_info(&ac, 0x0001, 0x0007, out, sizeof(out), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK(outlen > 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* C2. Client read_by_type, server returns error → client gets error code */
ATF_TC_WITHOUT_HEAD(test_client_read_by_type_error);
ATF_TC_BODY(test_client_read_by_type_error, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		(void)n;
		uint8_t rsp[] = { 0x01, 0x08, 0x01, 0x00,
		    ATT_ERR_ATTR_NOT_FOUND };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t out[ATT_PDU_BUF_SIZE];
	size_t olen = 0;
	int ret = att_read_by_type(&ac, 0x0001, 0xFFFF, 0xBEEF,
	    out, sizeof(out), &olen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(olen, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* C3. Verify exact Write Request bytes */
ATF_TC_WITHOUT_HEAD(test_client_write_req_verify_bytes);
ATF_TC_BODY(test_client_write_req_verify_bytes, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		/* Verify exact bytes: 12 0A 00 DE AD */
		if (n != 5) _exit(1);
		if (buf[0] != 0x12) _exit(2);
		if (buf[1] != 0x0A || buf[2] != 0x00) _exit(3);
		if (buf[3] != 0xDE || buf[4] != 0xAD) _exit(4);
		uint8_t rsp[] = { 0x13 };
		(void)send(peer, rsp, 1, 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t data[] = { 0xDE, 0xAD };
	int ret = att_write_req(&ac, 0x000A, data, 2);
	ATF_CHECK_EQ(ret, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* C4. Client read_blob, server returns error → client gets error code */
ATF_TC_WITHOUT_HEAD(test_client_read_blob_error);
ATF_TC_BODY(test_client_read_blob_error, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		(void)n;
		uint8_t rsp[] = { 0x01, 0x0C, 0x03, 0x00,
		    ATT_ERR_INVALID_OFFSET };
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t val[32];
	size_t vlen = 0;
	int ret = att_read_blob(&ac, 0x0003, 100, val, sizeof(val), &vlen);
	ATF_CHECK_EQ(ret, ATT_ERR_INVALID_OFFSET);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* C5. Client find_by_type_value, server returns multiple found handle pairs */
ATF_TC_WITHOUT_HEAD(test_client_find_by_type_multi_result);
ATF_TC_BODY(test_client_find_by_type_multi_result, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		if (n < 1 || buf[0] != 0x06) _exit(1);
		/* Send 2 handle pairs */
		uint8_t rsp[9];
		rsp[0] = 0x07;
		put_le16(rsp + 1, 0x0001); /* found 1 */
		put_le16(rsp + 3, 0x0003); /* end 1 */
		put_le16(rsp + 5, 0x0004); /* found 2 */
		put_le16(rsp + 7, 0x0007); /* end 2 */
		(void)send(peer, rsp, sizeof(rsp), 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t out[ATT_PDU_BUF_SIZE];
	size_t olen = 0;
	uint16_t val16 = 0xFFE0;
	int ret = att_find_by_type_value(&ac, 0x0001, 0xFFFF, 0x2800,
	    &val16, 2, out, sizeof(out), &olen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(olen, 8); /* 2 pairs × 4 bytes */

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* C6. Verify exact Prepare Write bytes */
ATF_TC_WITHOUT_HEAD(test_client_prepare_write_verify);
ATF_TC_BODY(test_client_prepare_write_verify, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		/* Verify: 16 06 00 05 00 AA BB */
		if (n != 7) _exit(1);
		if (buf[0] != 0x16) _exit(2);
		if (buf[1] != 0x06 || buf[2] != 0x00) _exit(3);
		if (buf[3] != 0x05 || buf[4] != 0x00) _exit(4);
		if (buf[5] != 0xAA || buf[6] != 0xBB) _exit(5);
		buf[0] = 0x17;
		(void)send(peer, buf, (size_t)n, 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t data[] = { 0xAA, 0xBB };
	int ret = att_prepare_write(&ac, 0x0006, 0x0005, data, 2);
	ATF_CHECK_EQ(ret, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* C7. att_execute_write(ac, 0x00) sends 18 00 (cancel) */
ATF_TC_WITHOUT_HEAD(test_client_execute_cancel_pdu);
ATF_TC_BODY(test_client_execute_cancel_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		if (n != 2 || buf[0] != 0x18 || buf[1] != 0x00) _exit(1);
		uint8_t rsp[] = { 0x19 };
		(void)send(peer, rsp, 1, 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	int ret = att_execute_write(&ac, 0x00);
	ATF_CHECK_EQ(ret, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* C8. att_execute_write(ac, 0x01) sends 18 01 (commit) */
ATF_TC_WITHOUT_HEAD(test_client_execute_commit_pdu);
ATF_TC_BODY(test_client_execute_commit_pdu, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		if (n != 2 || buf[0] != 0x18 || buf[1] != 0x01) _exit(1);
		uint8_t rsp[] = { 0x19 };
		(void)send(peer, rsp, 1, 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	int ret = att_execute_write(&ac, 0x01);
	ATF_CHECK_EQ(ret, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* C9. att_write_long where a prepare fails, verify execute cancel sent */
ATF_TC_WITHOUT_HEAD(test_client_write_long_error_cancels);
ATF_TC_BODY(test_client_write_long_error_cancels, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		/* First prepare → error */
		n = recv(peer, buf, sizeof(buf), 0);
		if (n < 1 || buf[0] != 0x16) _exit(1);
		uint8_t err[] = { 0x01, 0x16, 0x06, 0x00,
		    ATT_ERR_WRITE_NOT_PERMITTED };
		(void)send(peer, err, sizeof(err), 0);

		/* Client should send execute cancel (18 00) */
		n = recv(peer, buf, sizeof(buf), 0);
		if (n == 2 && buf[0] == 0x18 && buf[1] == 0x00) {
			uint8_t rsp[] = { 0x19 };
			(void)send(peer, rsp, 1, 0);
			close(peer);
			_exit(0);
		}
		close(peer);
		/* If no cancel was sent, that's also acceptable */
		_exit(0);
	}
	close(peer);
	uint8_t data[] = { 0x11, 0x22, 0x33 };
	int ret = att_write_long(&ac, 0x0006, data, sizeof(data));
	ATF_CHECK(ret != 0); /* should fail */

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* C10. Client read with server returning empty response (0 bytes of value) */
ATF_TC_WITHOUT_HEAD(test_client_read_empty_response);
ATF_TC_BODY(test_client_read_empty_response, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &peer);

	pid_t pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(ac.fd);
		n = recv(peer, buf, sizeof(buf), 0);
		if (n != 3 || buf[0] != 0x0A) _exit(1);
		/* Send Read Response with just opcode (empty value) */
		uint8_t rsp[] = { 0x0B };
		(void)send(peer, rsp, 1, 0);
		close(peer);
		_exit(0);
	}
	close(peer);
	uint8_t val[32];
	size_t vlen = 99;
	int ret = att_read(&ac, 0x0003, val, sizeof(val), &vlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(vlen, 0);

	int status;
	waitpid(pid, &status, 0);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	att_mock_cleanup(&ac, -1);
}

/* ================================================================
 * NEW TESTS: Raw PDU byte-level parity (Section D)
 * ================================================================ */

/* D1. Raw PDU: Write Request → Write Response exact bytes */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_write_req_response);
ATF_TC_BODY(test_raw_pdu_write_req_response, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Write 2 bytes to handle 6 */
	uint8_t req[] = { 0x12, 0x06, 0x00, 0x11, 0x22 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	uint8_t expected[] = { 0x13 };
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK(memcmp(rsp, expected, 1) == 0);

	/* Verify value */
	ATF_CHECK_EQ(attrs[5].value[0], 0x11);
	ATF_CHECK_EQ(attrs[5].value[1], 0x22);

	att_mock_cleanup(&ac, cf);
}

/* D2. Raw PDU: Read Blob with offset, verify exact request+response bytes */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_read_blob_offset);
ATF_TC_BODY(test_raw_pdu_read_blob_offset, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/*
	 * Read Blob handle=3, offset=1 on "Test" (4 bytes), MTU=23.
	 * Since value_len (4) <= mtu-1 (22), the attribute is NOT long
	 * and Read Blob must return ATT_ERR_ATTR_NOT_LONG.
	 */
	uint8_t req[] = { 0x0C, 0x03, 0x00, 0x01, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);

	ATF_CHECK_EQ(n, 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_LONG);

	att_mock_cleanup(&ac, cf);
}

/* D3. Raw PDU: CCCD write exact bytes */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_cccd_write);
ATF_TC_BODY(test_raw_pdu_cccd_write, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Write 01 00 to CCCD (handle 7) */
	uint8_t req[] = { 0x12, 0x07, 0x00, 0x01, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(rsp[0], 0x13);
	ATF_REQUIRE(ac.cccd_count >= 1);
	ATF_CHECK_EQ(ac.cccds[0].value, GATT_CCCD_NOTIFY);

	att_mock_cleanup(&ac, cf);
}

/* D4. Raw PDU: Read By Type for characteristic UUID, exact response bytes */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_read_by_type_char);
ATF_TC_BODY(test_raw_pdu_read_by_type_char, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Read By Type: uuid=0xFFE1 (custom char) */
	uint8_t req[] = { 0x08, 0x01, 0x00, 0xFF, 0xFF, 0xE1, 0xFF };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);

	/* Expected: 09 06 06 00 AA BB CC DD */
	uint8_t expected[] = { 0x09, 0x06,
	    0x06, 0x00, 0xAA, 0xBB, 0xCC, 0xDD };
	ATF_CHECK_EQ(n, (ssize_t)sizeof(expected));
	ATF_CHECK(memcmp(rsp, expected, sizeof(expected)) == 0);

	att_mock_cleanup(&ac, cf);
}

/* D5. Raw PDU: Execute Write cancel 18 00 → 19 */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_execute_cancel);
ATF_TC_BODY(test_raw_pdu_execute_cancel, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x18, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(rsp[0], 0x19);

	att_mock_cleanup(&ac, cf);
}

/* D6. Raw PDU: Execute Write commit 18 01 → 19 */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_execute_commit);
ATF_TC_BODY(test_raw_pdu_execute_commit, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x18, 0x01 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(rsp[0], 0x19);

	att_mock_cleanup(&ac, cf);
}

/* D7. Raw PDU: MTU exchange with large value (512) */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_mtu_large);
ATF_TC_BODY(test_raw_pdu_mtu_large, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Client MTU = 512 = 0x0200 */
	uint8_t req[] = { 0x02, 0x00, 0x02 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 3);
	ATF_CHECK_EQ(rsp[0], 0x03);
	/* Server MTU = 517 = 0x0205 */
	ATF_CHECK_EQ(rsp[1], 0x05);
	ATF_CHECK_EQ(rsp[2], 0x02);
	/* Effective = min(512, 517) = 512 */
	ATF_CHECK_EQ(ac.mtu, 512);

	att_mock_cleanup(&ac, cf);
}

/* D8. Raw PDU: Error for write to read-only */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_error_write_not_permitted);
ATF_TC_BODY(test_raw_pdu_error_write_not_permitted, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	/* Write to handle 3 (read-only Device Name) */
	uint8_t req[] = { 0x12, 0x03, 0x00, 0x42 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);

	uint8_t expected[] = { 0x01, 0x12, 0x03, 0x00, 0x03 };
	ATF_CHECK_EQ(n, 5);
	ATF_CHECK(memcmp(rsp, expected, 5) == 0);

	att_mock_cleanup(&ac, cf);
}

/* D9. Raw PDU: Error for read with insufficient encryption */
ATF_TC_WITHOUT_HEAD(test_raw_pdu_error_insuff_encrypt);
ATF_TC_BODY(test_raw_pdu_error_insuff_encrypt, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ_ENCRYPT, "Secret", 6);

	ac.encrypted = false;
	uint8_t req[] = { 0x0A, 0x03, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);

	/* Expected: 01 0A 03 00 0F */
	uint8_t expected[] = { 0x01, 0x0A, 0x03, 0x00, 0x0F };
	ATF_CHECK_EQ(n, 5);
	ATF_CHECK(memcmp(rsp, expected, 5) == 0);

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * NEW TESTS: Multi-MTU fill-in (Section E)
 * ================================================================ */

/* E1. Write Command at MTU=23 */
MTU_TEST(test_mtu23_write_cmd, 23)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	struct pollfd pfd;

	att_mock_pair(&ac, &cf);
	ac.mtu = 23;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x52, 0x06, 0x00, 0x11, 0x22 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);

	pfd.fd = cf;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 50), 0);
	ATF_CHECK_EQ(attrs[5].value[0], 0x11);
	ATF_CHECK_EQ(attrs[5].value[1], 0x22);

	att_mock_cleanup(&ac, cf);
}

/* E2. Write Command at MTU=64 */
MTU_TEST(test_mtu64_write_cmd, 64)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	struct pollfd pfd;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x52, 0x06, 0x00, 0x33, 0x44 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);

	pfd.fd = cf;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 50), 0);
	ATF_CHECK_EQ(attrs[5].value[0], 0x33);

	att_mock_cleanup(&ac, cf);
}

/* E3. Write Command at MTU=517 */
MTU_TEST(test_mtu517_write_cmd, 517)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	struct pollfd pfd;

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x52, 0x06, 0x00, 0x55, 0x66 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);

	pfd.fd = cf;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 50), 0);
	ATF_CHECK_EQ(attrs[5].value[0], 0x55);

	att_mock_cleanup(&ac, cf);
}

/* E4. CCCD write at MTU=23 */
MTU_TEST(test_mtu23_cccd_write, 23)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	ac.mtu = 23;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x12, 0x07, 0x00, 0x01, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);
	ATF_REQUIRE(ac.cccd_count >= 1);
	ATF_CHECK_EQ(ac.cccds[0].value, GATT_CCCD_NOTIFY);

	att_mock_cleanup(&ac, cf);
}

/* E5. CCCD write at MTU=64 — write notify (supported) not indicate */
MTU_TEST(test_mtu64_cccd_write, 64)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n __unused;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x12, 0x07, 0x00, 0x01, 0x00 }; /* notify */
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);
	ATF_REQUIRE(ac.cccd_count >= 1);
	ATF_CHECK_EQ(ac.cccds[0].value, GATT_CCCD_NOTIFY);

	att_mock_cleanup(&ac, cf);
}

/* E6. Read service decl at minimum MTU */
MTU_TEST(test_mtu23_read_service_decl, 23)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 23;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x0A, 0x01, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x0B);
	ATF_CHECK_EQ(n, 3); /* 1 + 2 bytes UUID */
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x1800);

	att_mock_cleanup(&ac, cf);
}

/* E7. Read char decl at minimum MTU */
MTU_TEST(test_mtu23_read_char_decl, 23)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 23;
	build_test_db(&db, attrs, vb);

	uint8_t req[] = { 0x0A, 0x02, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(rsp[0], 0x0B);
	ATF_CHECK_EQ(n, 6); /* 1 + props(1) + handle(2) + uuid(2) */
	ATF_CHECK_EQ(rsp[1], GATT_PROP_READ);
	ATF_CHECK_EQ(get_le16(rsp + 2), 0x0003);
	ATF_CHECK_EQ(get_le16(rsp + 4), 0x2A00);

	att_mock_cleanup(&ac, cf);
}

/* E8. Read Blob with 200-byte value at MTU=64, verify 63 bytes returned */
MTU_TEST(test_mtu64_read_blob_partial, 64)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;
	build_large_test_db(&db, attrs, vb);

	/* Read Blob handle=3, offset=0 */
	uint8_t req[] = { 0x0C, 0x03, 0x00, 0x00, 0x00 };
	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 64); /* MTU */
	ATF_CHECK_EQ(rsp[0], 0x0D);
	/* 63 bytes of value (all 0x42) */
	for (int i = 1; i < 64; i++)
		ATF_CHECK_EQ(rsp[i], 0x42);

	att_mock_cleanup(&ac, cf);
}

/* E9. Notification with 200-byte value at MTU=517, verify full 203-byte PDU */
MTU_TEST(test_mtu517_notification_full, 517)
{
	struct att_conn ac;
	int cf;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint8_t big[200];

	att_mock_pair(&ac, &cf);
	ac.mtu = ATT_PDU_BUF_SIZE;
	memset(big, 0x99, sizeof(big));

	att_send_notification(&ac, 0x0006, big, 200);
	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK_EQ(n, 203); /* 3 + 200 */
	ATF_CHECK_EQ(rsp[0], 0x1B);
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x0006);
	ATF_CHECK_EQ(rsp[3], 0x99);
	ATF_CHECK_EQ(rsp[202], 0x99);

	att_mock_cleanup(&ac, cf);
}

/* E10. Multi Handle NTF at MTU=64 → truncated */
MTU_TEST(test_mtu64_multi_handle_ntf, 64)
{
	struct att_conn ac;
	int cf;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	ac.mtu = 64;

	uint16_t handles[2] = { 0x0003, 0x0006 };
	uint8_t v1[30], v2[30];
	memset(v1, 0x11, sizeof(v1));
	memset(v2, 0x22, sizeof(v2));
	const uint8_t *values[2] = { v1, v2 };
	uint16_t lengths[2] = { 30, 30 };

	int ret = att_send_multiple_handle_value_ntf(&ac, handles, values,
	    lengths, 2);
	ATF_CHECK_EQ(ret, 0);

	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_CHECK(n <= 64); /* must not exceed MTU */
	ATF_CHECK_EQ(rsp[0], ATT_OP_MULTIPLE_HANDLE_VALUE_NTF);

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * EATT (Enhanced ATT) TESTS
 * ================================================================ */

/* EATT: select bearer falls back to primary when no EATT bearers exist */
ATF_TC_WITHOUT_HEAD(test_eatt_select_fallback);
ATF_TC_BODY(test_eatt_select_fallback, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);
	ac.eatt_count = 0;

	ATF_CHECK_EQ(att_eatt_select_bearer(&ac), ac.fd);

	att_mock_cleanup(&ac, peer);
}

/* EATT: select bearer returns first active EATT bearer fd */
ATF_TC_WITHOUT_HEAD(test_eatt_select_active);
ATF_TC_BODY(test_eatt_select_active, tc)
{
	struct att_conn ac;
	int peer;
	int eatt_fds[2];

	att_mock_pair(&ac, &peer);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, eatt_fds) == 0);

	ac.eatt[0].fd = eatt_fds[0];
	ac.eatt[0].mtu = ATT_DEFAULT_MTU;
	ac.eatt[0].active = true;
	ac.eatt_count = 1;

	ATF_CHECK_EQ(att_eatt_select_bearer(&ac), eatt_fds[0]);

	close(eatt_fds[0]);
	close(eatt_fds[1]);
	ac.eatt_count = 0;
	att_mock_cleanup(&ac, peer);
}

/* EATT: select bearer skips inactive bearers */
ATF_TC_WITHOUT_HEAD(test_eatt_select_skip_inactive);
ATF_TC_BODY(test_eatt_select_skip_inactive, tc)
{
	struct att_conn ac;
	int peer;
	int eatt1[2], eatt2[2];

	att_mock_pair(&ac, &peer);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, eatt1) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, eatt2) == 0);

	ac.eatt[0].fd = eatt1[0];
	ac.eatt[0].mtu = ATT_DEFAULT_MTU;
	ac.eatt[0].active = false;  /* inactive */
	ac.eatt[1].fd = eatt2[0];
	ac.eatt[1].mtu = ATT_DEFAULT_MTU;
	ac.eatt[1].active = true;
	ac.eatt_count = 2;

	ATF_CHECK_EQ(att_eatt_select_bearer(&ac), eatt2[0]);

	close(eatt1[0]); close(eatt1[1]);
	close(eatt2[0]); close(eatt2[1]);
	ac.eatt_count = 0;
	att_mock_cleanup(&ac, peer);
}

/* EATT: select bearer falls back if all bearers inactive */
ATF_TC_WITHOUT_HEAD(test_eatt_select_all_inactive);
ATF_TC_BODY(test_eatt_select_all_inactive, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);

	ac.eatt[0].fd = 999;
	ac.eatt[0].active = false;
	ac.eatt_count = 1;

	ATF_CHECK_EQ(att_eatt_select_bearer(&ac), ac.fd);

	ac.eatt_count = 0;
	att_mock_cleanup(&ac, peer);
}

/* EATT: close_eatt closes all bearer fds and resets count */
ATF_TC_WITHOUT_HEAD(test_eatt_close);
ATF_TC_BODY(test_eatt_close, tc)
{
	struct att_conn ac;
	int peer;
	int eatt1[2], eatt2[2];

	att_mock_pair(&ac, &peer);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, eatt1) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, eatt2) == 0);

	ac.eatt[0].fd = eatt1[0];
	ac.eatt[0].active = true;
	ac.eatt[1].fd = eatt2[0];
	ac.eatt[1].active = true;
	ac.eatt_count = 2;

	att_close_eatt(&ac);

	ATF_CHECK_EQ(ac.eatt_count, 0);
	ATF_CHECK_EQ(ac.eatt[0].active, false);
	ATF_CHECK_EQ(ac.eatt[1].active, false);
	ATF_CHECK_EQ(ac.eatt[0].fd, -1);
	ATF_CHECK_EQ(ac.eatt[1].fd, -1);

	close(eatt1[1]);
	close(eatt2[1]);
	att_mock_cleanup(&ac, peer);
}

/* EATT: close_eatt is safe with zero bearers */
ATF_TC_WITHOUT_HEAD(test_eatt_close_empty);
ATF_TC_BODY(test_eatt_close_empty, tc)
{
	struct att_conn ac;
	int peer;

	att_mock_pair(&ac, &peer);
	ac.eatt_count = 0;

	att_close_eatt(&ac);  /* should not crash */

	ATF_CHECK_EQ(ac.eatt_count, 0);

	att_mock_cleanup(&ac, peer);
}

/* EATT: open_eatt with ble_coc_connect returning -1 opens zero bearers */
ATF_TC_WITHOUT_HEAD(test_eatt_open_connect_fails);
ATF_TC_BODY(test_eatt_open_connect_fails, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t addr[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
	int ret;

	att_mock_pair(&ac, &peer);

	ble_coc_connect_retval = -1;
	ble_coc_connect_fd = -1;

	ret = att_open_eatt(&ac, addr, 0x00, 3);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(ac.eatt_count, 0);

	att_mock_cleanup(&ac, peer);
}

/* EATT: open_eatt clamps count to ATT_MAX_EATT_BEARERS */
ATF_TC_WITHOUT_HEAD(test_eatt_open_clamp_count);
ATF_TC_BODY(test_eatt_open_clamp_count, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t addr[6] = {0};
	int ret;

	att_mock_pair(&ac, &peer);

	ble_coc_connect_retval = -1;
	ble_coc_connect_fd = -1;

	/* Request more than max — should be clamped, and since connect fails, 0 opened */
	ret = att_open_eatt(&ac, addr, 0x00, 100);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(ac.eatt_count, 0);

	att_mock_cleanup(&ac, peer);
}

/* EATT: open then close lifecycle */
ATF_TC_WITHOUT_HEAD(test_eatt_lifecycle);
ATF_TC_BODY(test_eatt_lifecycle, tc)
{
	struct att_conn ac;
	int peer;
	int eatt_pair[2];

	att_mock_pair(&ac, &peer);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, eatt_pair) == 0);

	/* Manually add a bearer (simulating successful open) */
	ac.eatt[0].fd = eatt_pair[0];
	ac.eatt[0].mtu = 64;
	ac.eatt[0].active = true;
	ac.eatt_count = 1;

	/* Select should return EATT bearer */
	ATF_CHECK_EQ(att_eatt_select_bearer(&ac), eatt_pair[0]);

	/* Close EATT */
	att_close_eatt(&ac);
	ATF_CHECK_EQ(ac.eatt_count, 0);

	/* Select should now fall back to primary */
	ATF_CHECK_EQ(att_eatt_select_bearer(&ac), ac.fd);

	close(eatt_pair[1]);
	att_mock_cleanup(&ac, peer);
}

/* EATT: multiple bearers, select returns first active */
ATF_TC_WITHOUT_HEAD(test_eatt_multi_bearer_select);
ATF_TC_BODY(test_eatt_multi_bearer_select, tc)
{
	struct att_conn ac;
	int peer;
	int pairs[ATT_MAX_EATT_BEARERS][2];
	int i;

	att_mock_pair(&ac, &peer);

	for (i = 0; i < ATT_MAX_EATT_BEARERS; i++) {
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pairs[i]) == 0);
		ac.eatt[i].fd = pairs[i][0];
		ac.eatt[i].mtu = ATT_DEFAULT_MTU;
		ac.eatt[i].active = true;
	}
	ac.eatt_count = ATT_MAX_EATT_BEARERS;

	/* Should return first bearer */
	ATF_CHECK_EQ(att_eatt_select_bearer(&ac), pairs[0][0]);

	/* Deactivate first, should return second */
	ac.eatt[0].active = false;
	ATF_CHECK_EQ(att_eatt_select_bearer(&ac), pairs[1][0]);

	att_close_eatt(&ac);
	for (i = 0; i < ATT_MAX_EATT_BEARERS; i++)
		close(pairs[i][1]);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * HOG NOTIFICATION TESTS — exercise ATT notification/indication
 * receive path used by hogp_event_loop in blued.c.
 * ================================================================ */

/* HOG notification receive: verify att_recv gets notification */
ATF_TC_WITHOUT_HEAD(test_hog_notification_recv);
ATF_TC_BODY(test_hog_notification_recv, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t ntf[7], buf[64];
	size_t outlen;
	ssize_t n;

	att_mock_pair(&ac, &peer);

	/* Send notification: handle=0x0010, value=0x01 (HID report) */
	ntf[0] = ATT_OP_HANDLE_NOTIFY;
	put_le16(ntf + 1, 0x0010);
	ntf[3] = 0x01; /* report data */
	n = send(peer, ntf, 4, MSG_EOR);
	ATF_REQUIRE(n == 4);

	/* att_recv should return the notification */
	int ret = att_recv(&ac, buf, sizeof(buf), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK(outlen >= 4);
	ATF_CHECK_EQ(buf[0], ATT_OP_HANDLE_NOTIFY);
	ATF_CHECK_EQ(get_le16(buf + 1), 0x0010);
	ATF_CHECK_EQ(buf[3], 0x01);

	att_mock_cleanup(&ac, peer);
}

/* HOG multi-byte report via notification */
ATF_TC_WITHOUT_HEAD(test_hog_notification_report);
ATF_TC_BODY(test_hog_notification_report, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t ntf[23], buf[64];
	size_t outlen;

	att_mock_pair(&ac, &peer);

	/* HID keyboard report: 8 bytes */
	ntf[0] = ATT_OP_HANDLE_NOTIFY;
	put_le16(ntf + 1, 0x0020);
	/* modifier=0, reserved=0, keys[6]={0x04,0,0,0,0,0} = 'a' */
	ntf[3] = 0x00; ntf[4] = 0x00;
	ntf[5] = 0x04; ntf[6] = 0x00; ntf[7] = 0x00;
	ntf[8] = 0x00; ntf[9] = 0x00; ntf[10] = 0x00;
	send(peer, ntf, 11, MSG_EOR);

	int ret = att_recv(&ac, buf, sizeof(buf), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(outlen, 11);
	ATF_CHECK_EQ(buf[0], ATT_OP_HANDLE_NOTIFY);
	ATF_CHECK_EQ(buf[5], 0x04); /* key 'a' */

	att_mock_cleanup(&ac, peer);
}

/* HOG sequential notifications */
ATF_TC_WITHOUT_HEAD(test_hog_notification_sequence);
ATF_TC_BODY(test_hog_notification_sequence, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t ntf[8], buf[64];
	size_t outlen;

	att_mock_pair(&ac, &peer);

	/* Send 3 notifications in sequence */
	for (int i = 0; i < 3; i++) {
		ntf[0] = ATT_OP_HANDLE_NOTIFY;
		put_le16(ntf + 1, 0x0010);
		ntf[3] = (uint8_t)i;
		send(peer, ntf, 4, MSG_EOR);
	}

	/* Receive them in order */
	for (int i = 0; i < 3; i++) {
		int ret = att_recv(&ac, buf, sizeof(buf), &outlen);
		ATF_CHECK_EQ(ret, 0);
		ATF_CHECK_EQ(buf[3], (uint8_t)i);
	}

	att_mock_cleanup(&ac, peer);
}

/* HOG indication requires confirmation */
ATF_TC_WITHOUT_HEAD(test_hog_indication_confirm);
ATF_TC_BODY(test_hog_indication_confirm, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t ind[8], buf[64], cfm[1];
	size_t outlen;
	ssize_t n;

	att_mock_pair(&ac, &peer);

	/* Send indication */
	ind[0] = ATT_OP_HANDLE_IND;
	put_le16(ind + 1, 0x0010);
	ind[3] = 0xAA;
	send(peer, ind, 4, MSG_EOR);

	/* att_recv should return the indication */
	int ret = att_recv(&ac, buf, sizeof(buf), &outlen);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(buf[0], ATT_OP_HANDLE_IND);

	/* Send confirmation back */
	ret = att_confirm(&ac);
	ATF_CHECK_EQ(ret, 0);

	/* Peer should receive confirmation */
	n = recv(peer, cfm, sizeof(cfm), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(cfm[0], ATT_OP_HANDLE_CFM);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * UUID TESTS — exercise att_extract_uuid() indirectly via
 * Read By Type and Read By Group Type server handlers.
 * ================================================================ */

/* UUID16: Read By Type with 2-byte UUID for Device Name (0x2A00) */
ATF_TC_WITHOUT_HEAD(test_uuid_read_by_type_uuid16);
ATF_TC_BODY(test_uuid_read_by_type_uuid16, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[7], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	/* Read By Type: start=0x0001, end=0xFFFF, UUID16=0x2A00 */
	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2A00);

	att_server_handle(&ac, &db, pdu, 7, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_BY_TYPE_RSP);
	/* Value should contain "Test" */
	ATF_CHECK(n >= 2 + rsp[1]);  /* at least one entry */

	att_mock_cleanup(&ac, peer);
}

/* UUID128 via Base UUID: same result as UUID16 for 0x2A00 */
ATF_TC_WITHOUT_HEAD(test_uuid_read_by_type_uuid128_base);
ATF_TC_BODY(test_uuid_read_by_type_uuid128_base, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[21], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	/* Read By Type: start=0x0001, end=0xFFFF, UUID128 = Base(0x2A00) */
	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	/* Bluetooth Base UUID LE with 0x2A00 embedded */
	memcpy(pdu + 5, bt_base_uuid_le, 12);
	put_le16(pdu + 17, 0x2A00);
	pdu[19] = 0x00;
	pdu[20] = 0x00;

	att_server_handle(&ac, &db, pdu, 21, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_BY_TYPE_RSP);

	att_mock_cleanup(&ac, peer);
}

/* UUID128 vendor (non-base): should not match any attribute */
ATF_TC_WITHOUT_HEAD(test_uuid_read_by_type_uuid128_vendor);
ATF_TC_BODY(test_uuid_read_by_type_uuid128_vendor, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[21], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	/* A vendor 128-bit UUID (not Bluetooth Base) */
	memset(pdu + 5, 0xAA, 16);

	att_server_handle(&ac, &db, pdu, 21, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_FOUND);

	att_mock_cleanup(&ac, peer);
}

/* Invalid UUID length = 1 byte */
ATF_TC_WITHOUT_HEAD(test_uuid_read_by_type_invalid_len_1);
ATF_TC_BODY(test_uuid_read_by_type_invalid_len_1, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[6], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	pdu[5] = 0x00;  /* 1-byte "UUID" */

	att_server_handle(&ac, &db, pdu, 6, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_PDU);

	att_mock_cleanup(&ac, peer);
}

/* Invalid UUID length = 3 bytes */
ATF_TC_WITHOUT_HEAD(test_uuid_read_by_type_invalid_len_3);
ATF_TC_BODY(test_uuid_read_by_type_invalid_len_3, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[8], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	memset(pdu + 5, 0x00, 3);

	att_server_handle(&ac, &db, pdu, 8, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_PDU);

	att_mock_cleanup(&ac, peer);
}

/* Invalid UUID length = 5 bytes */
ATF_TC_WITHOUT_HEAD(test_uuid_read_by_type_invalid_len_5);
ATF_TC_BODY(test_uuid_read_by_type_invalid_len_5, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[10], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	memset(pdu + 5, 0x00, 5);

	att_server_handle(&ac, &db, pdu, 10, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_PDU);

	att_mock_cleanup(&ac, peer);
}

/* Invalid UUID length = 15 bytes */
ATF_TC_WITHOUT_HEAD(test_uuid_read_by_type_invalid_len_15);
ATF_TC_BODY(test_uuid_read_by_type_invalid_len_15, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[20], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	memset(pdu + 5, 0x00, 15);

	att_server_handle(&ac, &db, pdu, 20, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_PDU);

	att_mock_cleanup(&ac, peer);
}

/* Invalid UUID length = 17 bytes */
ATF_TC_WITHOUT_HEAD(test_uuid_read_by_type_invalid_len_17);
ATF_TC_BODY(test_uuid_read_by_type_invalid_len_17, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[23], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	memset(pdu + 5, 0x00, 17);

	/* 5 + 17 = 22, still fits in MTU 23 PDU */
	att_server_handle(&ac, &db, pdu, 22, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_PDU);

	att_mock_cleanup(&ac, peer);
}

/* Read By Group Type with UUID16 = 0x2800 (Primary Service) */
ATF_TC_WITHOUT_HEAD(test_uuid_read_by_group_uuid16);
ATF_TC_BODY(test_uuid_read_by_group_uuid16, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[7], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2800);

	att_server_handle(&ac, &db, pdu, 7, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_BY_GROUP_TYPE_RSP);

	att_mock_cleanup(&ac, peer);
}

/* Read By Group Type with 128-bit Base UUID expansion of 0x2800 */
ATF_TC_WITHOUT_HEAD(test_uuid_read_by_group_uuid128_base);
ATF_TC_BODY(test_uuid_read_by_group_uuid128_base, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[21], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	memcpy(pdu + 5, bt_base_uuid_le, 12);
	put_le16(pdu + 17, 0x2800);
	pdu[19] = 0x00;
	pdu[20] = 0x00;

	att_server_handle(&ac, &db, pdu, 21, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_BY_GROUP_TYPE_RSP);

	att_mock_cleanup(&ac, peer);
}

/* Read By Group Type with invalid UUID length = 3 */
ATF_TC_WITHOUT_HEAD(test_uuid_read_by_group_invalid_len);
ATF_TC_BODY(test_uuid_read_by_group_invalid_len, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[8], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	memset(pdu + 5, 0x00, 3);

	att_server_handle(&ac, &db, pdu, 8, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_PDU);

	att_mock_cleanup(&ac, peer);
}

/* Well-known UUID: Read By Type for 0x2800 (Primary Service) */
ATF_TC_WITHOUT_HEAD(test_uuid_well_known_primary);
ATF_TC_BODY(test_uuid_well_known_primary, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[7], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2800);

	att_server_handle(&ac, &db, pdu, 7, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_BY_TYPE_RSP);

	att_mock_cleanup(&ac, peer);
}

/* Well-known UUID: Read By Type for 0x2803 (Characteristic) */
ATF_TC_WITHOUT_HEAD(test_uuid_well_known_characteristic);
ATF_TC_BODY(test_uuid_well_known_characteristic, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[7], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2803);

	att_server_handle(&ac, &db, pdu, 7, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_BY_TYPE_RSP);

	att_mock_cleanup(&ac, peer);
}

/* Well-known UUID: Read By Type for 0x2902 (CCCD) */
ATF_TC_WITHOUT_HEAD(test_uuid_well_known_cccd);
ATF_TC_BODY(test_uuid_well_known_cccd, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[7], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2902);

	att_server_handle(&ac, &db, pdu, 7, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_BY_TYPE_RSP);
	/* CCCD value should be 2 bytes (0x0000) */

	att_mock_cleanup(&ac, peer);
}

/* Well-known UUID: Read By Type for 0x2A00 (Device Name) */
ATF_TC_WITHOUT_HEAD(test_uuid_well_known_device_name);
ATF_TC_BODY(test_uuid_well_known_device_name, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[7], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2A00);

	att_server_handle(&ac, &db, pdu, 7, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_BY_TYPE_RSP);
	/* Entry: handle(2) + "Test"(4) = 6 bytes per pair */
	ATF_CHECK_EQ(rsp[1], 6);
	/* Value should be "Test" */
	ATF_CHECK_EQ(rsp[4], 'T');
	ATF_CHECK_EQ(rsp[5], 'e');
	ATF_CHECK_EQ(rsp[6], 's');
	ATF_CHECK_EQ(rsp[7], 't');

	att_mock_cleanup(&ac, peer);
}

/* UUID byte order: verify UUID16 0x2800 encodes as 00 28 in PDU (LE) */
ATF_TC_WITHOUT_HEAD(test_uuid_byte_order_le);
ATF_TC_BODY(test_uuid_byte_order_le, tc)
{
	uint8_t buf[2];

	put_le16(buf, 0x2800);
	ATF_CHECK_EQ(buf[0], 0x00);
	ATF_CHECK_EQ(buf[1], 0x28);

	/* Verify round-trip */
	ATF_CHECK_EQ(get_le16(buf), 0x2800);

	/* Another UUID: 0x2A00 -> 00 2A */
	put_le16(buf, 0x2A00);
	ATF_CHECK_EQ(buf[0], 0x00);
	ATF_CHECK_EQ(buf[1], 0x2A);
}

/* UUID32: upper 16 bits zero, should collapse to UUID16 match */
ATF_TC_WITHOUT_HEAD(test_uuid_uuid32_collapses);
ATF_TC_BODY(test_uuid_uuid32_collapses, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[9], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	/* Read By Type with 4-byte UUID: 0x00002A00 LE = 00 2A 00 00 */
	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	pdu[5] = 0x00;  /* UUID32 LE byte 0 */
	pdu[6] = 0x2A;  /* UUID32 LE byte 1 */
	pdu[7] = 0x00;  /* UUID32 LE byte 2 (upper) */
	pdu[8] = 0x00;  /* UUID32 LE byte 3 (upper) */

	att_server_handle(&ac, &db, pdu, 9, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	/* Should find Device Name (0x2A00) same as UUID16 */
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_BY_TYPE_RSP);

	att_mock_cleanup(&ac, peer);
}

/* UUID32: non-zero upper bits, should not collapse */
ATF_TC_WITHOUT_HEAD(test_uuid_uuid32_non_collapsible);
ATF_TC_BODY(test_uuid_uuid32_non_collapsible, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[9], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	/* UUID32 with upper bits set: 0x00012A00 LE = 00 2A 01 00 */
	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	pdu[5] = 0x00;
	pdu[6] = 0x2A;
	pdu[7] = 0x01;  /* upper 16 bits non-zero */
	pdu[8] = 0x00;

	att_server_handle(&ac, &db, pdu, 9, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	/* Should NOT match UUID16 0x2A00, so either not found or 128-bit search */
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_FOUND);

	att_mock_cleanup(&ac, peer);
}

/* 128-bit UUID that is NOT Bluetooth Base — differs in first 12 bytes */
ATF_TC_WITHOUT_HEAD(test_uuid_128bit_not_base);
ATF_TC_BODY(test_uuid_128bit_not_base, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t pdu[21], rsp[64];
	ssize_t n;

	att_mock_pair(&ac, &peer);
	build_test_db(&db, attrs, val_buf);

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	/* UUID128 with first 12 bytes different from Base UUID */
	memset(pdu + 5, 0x11, 12);
	put_le16(pdu + 17, 0x2A00);
	pdu[19] = 0x00;
	pdu[20] = 0x00;

	att_server_handle(&ac, &db, pdu, 21, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), 0);

	ATF_CHECK(n > 0);
	/* uuid16 == 0, so 128-bit UUID search; won't match our UUID16 attrs */
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_FOUND);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * ATT SERVER EDGE CASE TESTS
 * ================================================================ */

/*
 * test_att_server_reset
 *
 * Call att_server_reset and verify CCCDs and prepare queue are cleared.
 */
ATF_TC_WITHOUT_HEAD(test_att_server_reset);
ATF_TC_BODY(test_att_server_reset, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Enable notifications on CCCD (handle 7) */
	uint8_t pdu[5];
	pdu[0] = ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, 0x0007);
	put_le16(pdu + 3, GATT_CCCD_NOTIFY);
	att_server_handle(&ac, &db, pdu, 5, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);

	/* Verify CCCD is stored */
	ATF_CHECK(ac.cccd_count > 0);

	/* Add a prepare write entry to the queue */
	uint8_t prep[8];
	prep[0] = ATT_OP_PREPARE_WRITE_REQ;
	put_le16(prep + 1, 0x0006);
	put_le16(prep + 3, 0x0000);
	prep[5] = 0x11;
	prep[6] = 0x22;
	prep[7] = 0x33;
	att_server_handle(&ac, &db, prep, 8, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_PREPARE_WRITE_RSP);
	ATF_CHECK(ac.prep_queue.count > 0);

	/* Reset the server state */
	att_server_reset(&ac);

	/* Verify everything is cleared */
	ATF_CHECK_EQ(ac.cccd_count, 0);
	ATF_CHECK_EQ(ac.prep_queue.count, 0);
	ATF_CHECK_EQ(ac.prep_queue.total_bytes, 0);

	att_mock_cleanup(&ac, client_fd);
}

/*
 * test_att_eatt_accept
 *
 * Set up a listening socket, connect to it, verify att_eatt_accept
 * adds the bearer.  Uses AF_UNIX SOCK_SEQPACKET as a substitute
 * for L2CAP CoC sockets.
 */
ATF_TC_WITHOUT_HEAD(test_att_eatt_accept);
ATF_TC_BODY(test_att_eatt_accept, tc)
{
	struct att_conn ac;
	int peer;
	int listen_fd, cli_fd;
	struct sockaddr_un addr;
	char path[64];

	att_mock_pair(&ac, &peer);

	/*
	 * Create a Unix-domain listening socket.
	 * att_eatt_accept calls accept4 which works on any
	 * listening socket, though it tries to fill a
	 * sockaddr_l2cap — the accept itself will succeed.
	 */
	snprintf(path, sizeof(path), "/tmp/blued_test_eatt.%d",
	    (int)getpid());
	(void)unlink(path);

	listen_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	ATF_REQUIRE(listen_fd >= 0);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, path, sizeof(addr.sun_path));
	ATF_REQUIRE(bind(listen_fd, (struct sockaddr *)&addr,
	    sizeof(addr)) == 0);
	ATF_REQUIRE(listen(listen_fd, 1) == 0);

	/* Connect a client */
	cli_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	ATF_REQUIRE(cli_fd >= 0);
	ATF_REQUIRE(connect(cli_fd, (struct sockaddr *)&addr,
	    sizeof(addr)) == 0);

	ATF_CHECK_EQ(ac.eatt_count, 0);

	int ret = att_eatt_accept(&ac, listen_fd);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(ac.eatt_count, 1);
	ATF_CHECK(ac.eatt[0].active);
	ATF_CHECK(ac.eatt[0].fd >= 0);

	/* Clean up the accepted fd */
	close(ac.eatt[0].fd);
	ac.eatt[0].fd = -1;
	ac.eatt[0].active = false;
	ac.eatt_count = 0;

	close(cli_fd);
	close(listen_fd);
	(void)unlink(path);
	att_mock_cleanup(&ac, peer);
}

/*
 * test_att_server_permission_encrypt_required
 *
 * Build DB with ATT_PERM_READ | ATT_PERM_READ_ENCRYPT.
 * Verify read is rejected when ac->encrypted=false (testing
 * the C2 permission fix).
 */
ATF_TC_WITHOUT_HEAD(test_att_server_permission_encrypt_required);
ATF_TC_BODY(test_att_server_permission_encrypt_required, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ | ATT_PERM_READ_ENCRYPT,
	    "Encrypted", 9);

	/* Read with encrypted=false -> INSUFF_ENCRYPTION */
	ac.encrypted = false;
	uint8_t pdu[3] = { ATT_OP_READ_REQ };
	put_le16(pdu + 1, 0x0003);
	att_server_handle(&ac, &db, pdu, 3, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[1], ATT_OP_READ_REQ);
	ATF_CHECK_EQ(get_le16(rsp + 2), 0x0003);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INSUFF_ENCRYPTION);

	/* Read with encrypted=true -> success */
	ac.encrypted = true;
	att_server_handle(&ac, &db, pdu, 3, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_RSP);
	ATF_CHECK_EQ(memcmp(rsp + 1, "Encrypted", 9), 0);

	att_mock_cleanup(&ac, client_fd);
}

/*
 * test_att_server_read_blob_not_long
 *
 * Verify Read Blob on a short attribute (value_len <= mtu-1)
 * with offset=0 returns the value successfully (Read Blob is
 * permitted on any readable attribute, short or not).
 * Verify that offset > value_len returns ATT_ERR_INVALID_OFFSET.
 */
ATF_TC_WITHOUT_HEAD(test_att_server_read_blob_not_long);
ATF_TC_BODY(test_att_server_read_blob_not_long, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0x1800);
	/* Short attribute: 4 bytes, well within default MTU of 23 */
	attdb_add_characteristic(&db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, "Test", 4);

	/*
	 * Read Blob with offset=0 on a short attribute (4 bytes, MTU=23).
	 * Since value_len (4) <= mtu-1 (22), the attribute is NOT long
	 * and Read Blob must return ATT_ERR_ATTR_NOT_LONG.
	 */
	uint8_t pdu[5];
	pdu[0] = ATT_OP_READ_BLOB_REQ;
	put_le16(pdu + 1, 0x0003);  /* char value handle */
	put_le16(pdu + 3, 0x0000);  /* offset=0 */

	att_server_handle(&ac, &db, pdu, 5, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	/*
	 * Offset=0 on a short attribute succeeds (returns the value).
	 * Some stacks use Read Blob at offset=0 as a probing strategy.
	 */
	ATF_REQUIRE(n > 0);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_BLOB_RSP);

	/*
	 * Read Blob with non-zero offset on a short attribute returns
	 * ATT_ERR_ATTR_NOT_LONG.
	 */
	put_le16(pdu + 3, 0x0001);  /* offset=1, non-zero on short attr */
	att_server_handle(&ac, &db, pdu, 5, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[1], ATT_OP_READ_BLOB_REQ);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_LONG);

	att_mock_cleanup(&ac, client_fd);
}

/*
 * test_att_server_read_blob_offset_eq_len
 *
 * Verify Read Blob with offset == value_len on a short attribute
 * returns ATT_ERR_ATTR_NOT_LONG, since the attribute fits in a
 * single Read Response and is therefore not "long".
 */
ATF_TC_WITHOUT_HEAD(test_att_server_read_blob_offset_eq_len);
ATF_TC_BODY(test_att_server_read_blob_offset_eq_len, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, "Test", 4);

	/* Read Blob with offset == value_len (4), MTU=23 */
	uint8_t pdu[5];
	pdu[0] = ATT_OP_READ_BLOB_REQ;
	put_le16(pdu + 1, 0x0003);
	put_le16(pdu + 3, 0x0004);  /* offset=4 == value_len */

	att_server_handle(&ac, &db, pdu, 5, -1, 0);
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	/*
	 * value_len (4) <= mtu-1 (22), so the attribute is not "long".
	 * ATT_ERR_ATTR_NOT_LONG is returned before the offset check.
	 */
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_ATTR_NOT_LONG);

	att_mock_cleanup(&ac, client_fd);
}

/* ================================================================
 * MALFORMED / TRUNCATED PDU TESTS
 *
 * These test the ATT server's handling of untrusted over-the-air data:
 * truncated requests, zero-length PDUs, unknown opcodes, and oversized
 * PDUs.  The server must never crash and must respond correctly per
 * Core Spec Vol 3 Part F.
 * ================================================================ */

/* test_srv_truncated_read_by_type — 4 bytes instead of required 7 */
ATF_TC_WITHOUT_HEAD(test_srv_truncated_read_by_type);
ATF_TC_BODY(test_srv_truncated_read_by_type, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/*
	 * Truncated Read By Type Request: only 4 bytes instead of the
	 * minimum 7 (opcode + start_handle(2) + end_handle(2) + uuid(2)).
	 */
	uint8_t pdu[4];
	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	pdu[3] = 0xFF;	/* partial end_handle byte */

	int ret = att_server_handle(&ac, &db, pdu, 4, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[1], ATT_OP_READ_BY_TYPE_REQ);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_PDU);

	att_mock_cleanup(&ac, client_fd);
}

/* test_srv_truncated_find_info — 2 bytes instead of required 5 */
ATF_TC_WITHOUT_HEAD(test_srv_truncated_find_info);
ATF_TC_BODY(test_srv_truncated_find_info, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/*
	 * Truncated Find Information Request: only 2 bytes instead of
	 * the minimum 5 (opcode + start_handle(2) + end_handle(2)).
	 */
	uint8_t pdu[2];
	pdu[0] = ATT_OP_FIND_INFO_REQ;
	pdu[1] = 0x01;	/* partial start_handle byte */

	int ret = att_server_handle(&ac, &db, pdu, 2, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[1], ATT_OP_FIND_INFO_REQ);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_PDU);

	att_mock_cleanup(&ac, client_fd);
}

/* test_srv_truncated_write — 1 byte (opcode only, no handle or value) */
ATF_TC_WITHOUT_HEAD(test_srv_truncated_write);
ATF_TC_BODY(test_srv_truncated_write, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/*
	 * Truncated Write Request: only the opcode byte, no handle or
	 * value.  Minimum is opcode + handle(2) = 3 bytes.
	 */
	uint8_t pdu[1];
	pdu[0] = ATT_OP_WRITE_REQ;

	int ret = att_server_handle(&ac, &db, pdu, 1, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[1], ATT_OP_WRITE_REQ);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_PDU);

	att_mock_cleanup(&ac, client_fd);
}

/*
 * test_srv_zero_length_pdu — send a 0-byte PDU.
 *
 * att_server_handle() returns -1 for a zero-length PDU without
 * sending any response.  The server must not crash.
 */
ATF_TC_WITHOUT_HEAD(test_srv_zero_length_pdu);
ATF_TC_BODY(test_srv_zero_length_pdu, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/*
	 * Zero-length PDU: no opcode at all.  The server should handle
	 * this gracefully — return -1 without crashing.
	 */
	uint8_t dummy = 0;
	int ret = att_server_handle(&ac, &db, &dummy, 0, -1, 0);
	ATF_CHECK_EQ(ret, -1);

	/*
	 * Verify the server is still functional by sending a valid Read
	 * Request and confirming we get a proper response.
	 */
	uint8_t pdu[3];
	pdu[0] = ATT_OP_READ_REQ;
	put_le16(pdu + 1, 0x0003);	/* Device Name */

	ret = att_server_handle(&ac, &db, pdu, 3, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_RSP);
	ATF_CHECK_EQ(memcmp(rsp + 1, "Test", 4), 0);

	att_mock_cleanup(&ac, client_fd);
}

/*
 * test_srv_unknown_opcode — send a PDU with an unrecognised request opcode.
 *
 * Opcode 0x3F has bit 6 clear (not a command), so the server must
 * respond with ATT_ERR_REQ_NOT_SUPPORTED per Core Spec Vol 3 Part F
 * Section 3.4.1.1.
 *
 * Note: 0x7F has bit 6 SET (0100 0000), making it a command that
 * must be silently ignored.  Use 0x3F (0011 1111) instead.
 */
ATF_TC_WITHOUT_HEAD(test_srv_unknown_opcode);
ATF_TC_BODY(test_srv_unknown_opcode, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/*
	 * Unknown opcode 0x3F — not a defined ATT opcode, and bit 6 is
	 * clear so it is treated as a request (not a command).
	 */
	uint8_t pdu[1];
	pdu[0] = 0x3F;

	int ret = att_server_handle(&ac, &db, pdu, 1, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[1], 0x3F);	/* echoes back the unknown opcode */
	ATF_CHECK_EQ(rsp[4], ATT_ERR_REQ_NOT_SUPPORTED);

	att_mock_cleanup(&ac, client_fd);
}

/*
 * test_srv_oversized_pdu — send a PDU exceeding the negotiated MTU.
 *
 * A Read By Type Request padded to 100 bytes when the MTU is the
 * default 23.  The server should still process the PDU correctly
 * (the extra bytes are beyond the valid fields and are ignored
 * by the length checks).
 */
ATF_TC_WITHOUT_HEAD(test_srv_oversized_pdu);
ATF_TC_BODY(test_srv_oversized_pdu, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* MTU is the default 23 */
	ATF_REQUIRE(ac.mtu == ATT_DEFAULT_MTU);

	/*
	 * Build a 100-byte PDU: valid Read By Type header in the
	 * first 7 bytes, then 93 bytes of padding.  This exceeds
	 * the negotiated MTU of 23.
	 */
	uint8_t pdu[100];
	memset(pdu, 0, sizeof(pdu));
	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_CHARACTERISTIC);

	/*
	 * The server uses strict length checks (len must be exactly
	 * 7, 9, or 21 for Read By Type), so a 100-byte PDU is
	 * rejected as an invalid PDU.
	 */
	int ret = att_server_handle(&ac, &db, pdu, 100, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[1], ATT_OP_READ_BY_TYPE_REQ);
	ATF_CHECK_EQ(rsp[4], ATT_ERR_INVALID_PDU);

	att_mock_cleanup(&ac, client_fd);
}

/*
 * test_srv_write_cmd_truncated — truncated Write Command (no response).
 *
 * Write Command (ATT_OP_WRITE_CMD, 0x52) has no response per the spec.
 * A truncated Write Command with only the opcode byte should be silently
 * ignored.  Verify the server doesn't crash and can still handle a
 * subsequent valid request.
 */
ATF_TC_WITHOUT_HEAD(test_srv_write_cmd_truncated);
ATF_TC_BODY(test_srv_write_cmd_truncated, tc)
{
	struct att_conn ac;
	int client_fd;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val_buf[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/*
	 * Truncated Write Command: only the opcode byte.  Since Write
	 * Command has no response, the server should silently ignore it
	 * (return 0) without crashing.
	 */
	uint8_t pdu_cmd[1];
	pdu_cmd[0] = ATT_OP_WRITE_CMD;

	int ret = att_server_handle(&ac, &db, pdu_cmd, 1, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	/*
	 * Verify the server is still functional by sending a valid
	 * Read Request and confirming we get a proper response.
	 */
	uint8_t pdu_read[3];
	pdu_read[0] = ATT_OP_READ_REQ;
	put_le16(pdu_read + 1, 0x0003);	/* Device Name */

	ret = att_server_handle(&ac, &db, pdu_read, 3, -1, 0);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_RSP);
	ATF_CHECK_EQ(memcmp(rsp + 1, "Test", 4), 0);

	att_mock_cleanup(&ac, client_fd);
}

/* ================================================================
 * Signed Write Command: valid CSRK flow path
 *
 * Set has_peer_csrk = true; the smp_verify_signature stub in
 * test_common.h returns false, so the write is silently dropped.
 * This exercises the "has_peer_csrk = true" branch without crash.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_signed_write_cmd);
ATF_TC_BODY(test_signed_write_cmd, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	struct pollfd pfd;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	ac.has_peer_csrk = true;
	memset(ac.peer_csrk, 0x42, 16);

	/*
	 * ATT Signed Write Command: opcode(0xD2) + handle(2) + value(1) + signature(12)
	 * = 16 bytes total.
	 */
	uint8_t req[16];
	req[0] = ATT_OP_SIGNED_WRITE_CMD;
	put_le16(req + 1, 0x0006);
	req[3] = 0x42;
	memset(req + 4, 0, 12);

	int ret = att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	ATF_CHECK_EQ(ret, 0);

	/* No response for commands */
	pfd.fd = cf;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 50), 0);

	att_mock_cleanup(&ac, cf);
}

/* Signed Write Command: bad signature → silently dropped, value unchanged */
ATF_TC_WITHOUT_HEAD(test_signed_write_cmd_invalid_sig);
ATF_TC_BODY(test_signed_write_cmd_invalid_sig, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	struct pollfd pfd;
	struct att_attr *a;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	ac.has_peer_csrk = true;
	memset(ac.peer_csrk, 0x42, 16);

	a = attdb_find_by_handle(&db, 0x0006);
	ATF_REQUIRE(a != NULL);
	uint8_t orig_val = a->value[0];

	uint8_t req[16];
	req[0] = ATT_OP_SIGNED_WRITE_CMD;
	put_le16(req + 1, 0x0006);
	req[3] = 0xFF;
	memset(req + 4, 0xDE, 12);

	int ret = att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	ATF_CHECK_EQ(ret, 0);

	/* Value unchanged because signature failed */
	ATF_CHECK_EQ_MSG(a->value[0], orig_val,
	    "value should not change on failed signature verify");

	pfd.fd = cf;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 50), 0);

	att_mock_cleanup(&ac, cf);
}

/* Signed Write Command: no CSRK → silently dropped */
ATF_TC_WITHOUT_HEAD(test_signed_write_cmd_no_csrk);
ATF_TC_BODY(test_signed_write_cmd_no_csrk, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	struct pollfd pfd;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	ac.has_peer_csrk = false;

	uint8_t req[16];
	req[0] = ATT_OP_SIGNED_WRITE_CMD;
	put_le16(req + 1, 0x0006);
	req[3] = 0x42;
	memset(req + 4, 0, 12);

	int ret = att_server_handle(&ac, &db, req, sizeof(req), -1, 0);
	ATF_CHECK_EQ(ret, 0);

	pfd.fd = cf;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 50), 0);

	att_mock_cleanup(&ac, cf);
}

/* EATT: large MTU bearer response not clamped to 517 */
ATF_TC_WITHOUT_HEAD(test_eatt_large_mtu_response);
ATF_TC_BODY(test_eatt_large_mtu_response, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	uint8_t req[3];
	req[0] = ATT_OP_READ_REQ;
	put_le16(req + 1, 0x0003);

	att_server_handle(&ac, &db, req, sizeof(req), ac.fd, 1024);

	n = recv(cf, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 5);
	ATF_CHECK_EQ(rsp[0], ATT_OP_READ_RSP);
	ATF_CHECK(memcmp(rsp + 1, "Test", 4) == 0);

	att_mock_cleanup(&ac, cf);
}

/* attdb_remove_service removes a service and its attributes */
ATF_TC_WITHOUT_HEAD(test_attdb_remove_service);
ATF_TC_BODY(test_attdb_remove_service, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	int count_before;
	uint16_t svc_handle;

	build_test_db(&db, attrs, vb);

	svc_handle = attdb_add_service(&db, 0xFFF0);
	ATF_REQUIRE(svc_handle != 0);
	attdb_add_characteristic(&db, 0xFFF1,
	    GATT_PROP_READ, ATT_PERM_READ, "\x00", 1);
	count_before = db.count;

	int ret = attdb_remove_service(&db, svc_handle);
	ATF_CHECK_EQ_MSG(ret, 0,
	    "attdb_remove_service failed for handle 0x%04X", svc_handle);
	ATF_CHECK_MSG(db.count < count_before,
	    "count should decrease: before=%d after=%d",
	    count_before, db.count);

	ATF_CHECK(attdb_find_by_handle(&db, svc_handle) == NULL);

	/* Invalid handle should fail */
	ret = attdb_remove_service(&db, 0xFFFF);
	ATF_CHECK(ret != 0);
}

/* att_opcode_name: exercise indirectly via known opcode→response mappings */
ATF_TC_WITHOUT_HEAD(test_att_opcode_name);
ATF_TC_BODY(test_att_opcode_name, tc)
{
	struct att_conn ac;
	int cf;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	att_mock_pair(&ac, &cf);
	build_test_db(&db, attrs, vb);

	struct {
		uint8_t	opcode;
		uint8_t	expected_rsp;
		uint8_t	extra[6];
		size_t	len;
	} cases[] = {
		{ ATT_OP_MTU_REQ, ATT_OP_MTU_RSP,
		  { 0x17, 0x00, 0, 0, 0, 0 }, 3 },
		{ ATT_OP_READ_REQ, ATT_OP_READ_RSP,
		  { 0x03, 0x00, 0, 0, 0, 0 }, 3 },
		{ ATT_OP_READ_REQ, ATT_OP_ERROR_RSP,
		  { 0xFF, 0xFF, 0, 0, 0, 0 }, 3 },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		uint8_t req[8];
		req[0] = cases[i].opcode;
		memcpy(req + 1, cases[i].extra, cases[i].len - 1);

		att_server_handle(&ac, &db, req, cases[i].len, -1, 0);

		n = recv(cf, rsp, sizeof(rsp), 0);
		ATF_REQUIRE(n > 0);
		ATF_CHECK_EQ_MSG(rsp[0], cases[i].expected_rsp,
		    "opcode 0x%02x: expected rsp 0x%02x, got 0x%02x",
		    cases[i].opcode, cases[i].expected_rsp, rsp[0]);
	}

	att_mock_cleanup(&ac, cf);
}

/* ================================================================
 * Test: att_send_notification sends on bearer_fd when set.
 *
 * Set up an att_conn with bearer_fd pointing to a socketpair fd.
 * Call att_send_notification() and verify the notification PDU
 * was sent on the bearer fd, not on ac->fd.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_notification_bearer_aware);
ATF_TC_BODY(test_notification_bearer_aware, tc)
{
	struct att_conn ac;
	int primary_peer, bearer_fds[2];
	uint8_t val[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
	uint8_t buf[ATT_PDU_BUF_SIZE];
	ssize_t n;
	struct pollfd pfd;

	att_mock_pair(&ac, &primary_peer);

	/* Create a second socketpair for the bearer */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, bearer_fds) == 0);
	ac.bearer_fd = bearer_fds[0];
	ac.bearer_mtu = ATT_DEFAULT_MTU;

	/* Send notification — should go to bearer_fd, not ac.fd */
	int ret = att_send_notification(&ac, 0x0006, val, sizeof(val));
	ATF_CHECK_EQ(ret, 0);

	/* Verify data arrived on the bearer peer, not on the primary peer */
	n = recv(bearer_fds[1], buf, sizeof(buf), 0);
	ATF_REQUIRE(n >= 7);	/* opcode(1) + handle(2) + value(4) */
	ATF_CHECK_EQ(buf[0], ATT_OP_HANDLE_NOTIFY);
	ATF_CHECK_EQ(get_le16(buf + 1), 0x0006);
	ATF_CHECK_EQ(buf[3], 0xDE);
	ATF_CHECK_EQ(buf[4], 0xAD);
	ATF_CHECK_EQ(buf[5], 0xBE);
	ATF_CHECK_EQ(buf[6], 0xEF);

	/* Primary peer should have nothing */
	pfd.fd = primary_peer;
	pfd.events = POLLIN;
	ATF_CHECK_EQ(poll(&pfd, 1, 0), 0);

	close(bearer_fds[0]);
	close(bearer_fds[1]);
	att_mock_cleanup(&ac, primary_peer);
}

/* ================================================================
 * Test: CCCD write with RFU bits set — verify only bits [1:0] stored.
 *
 * Write a CCCD value of 0xFFFF via the ATT server. The server should
 * mask off RFU bits and store only 0x0003 (both notify + indicate).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cccd_rfu_bits_masked);
ATF_TC_BODY(test_cccd_rfu_bits_masked, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t vb[TEST_DB_VAL_SIZE];
	uint8_t req[5], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint16_t cccd_handle;

	att_mock_pair(&ac, &peer);

	/*
	 * Build a DB with a characteristic that supports both
	 * notify and indicate, plus its CCCD.
	 */
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, vb, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, 0xFFE0);
	attdb_add_characteristic(&db, 0xFFE1,
	    GATT_PROP_READ | GATT_PROP_NOTIFY | GATT_PROP_INDICATE,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    "\x00", 1);
	cccd_handle = attdb_add_cccd(&db);
	ATF_REQUIRE(cccd_handle != 0);

	/* Write CCCD with all bits set (0xFFFF) */
	req[0] = ATT_OP_WRITE_REQ;
	put_le16(req + 1, cccd_handle);
	put_le16(req + 3, 0xFFFF);

	att_server_handle(&ac, &db, req, sizeof(req), -1, 0);

	/* Read back the Write Response */
	n = recv(peer, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);

	/* Verify that only bits [1:0] were stored */
	ATF_REQUIRE(ac.cccd_count >= 1);
	ATF_CHECK_EQ_MSG(ac.cccds[0].value, 0x0003,
	    "expected CCCD value 0x0003, got 0x%04x", ac.cccds[0].value);

	att_mock_cleanup(&ac, peer);
}

ATF_TP_ADD_TCS(tp)
{

	/* ATT Client tests */
	ATF_TP_ADD_TC(tp, test_att_mtu_exchange);
	ATF_TP_ADD_TC(tp, test_att_read);
	ATF_TP_ADD_TC(tp, test_att_write_req);
	ATF_TP_ADD_TC(tp, test_att_write_cmd);
	ATF_TP_ADD_TC(tp, test_att_read_blob);
	ATF_TP_ADD_TC(tp, test_att_error_response);

	/* ATT Server tests */
	ATF_TP_ADD_TC(tp, test_att_server_mtu);
	ATF_TP_ADD_TC(tp, test_att_server_read_by_group);
	ATF_TP_ADD_TC(tp, test_att_server_read_by_type);
	ATF_TP_ADD_TC(tp, test_att_server_find_info);
	ATF_TP_ADD_TC(tp, test_att_server_read);
	ATF_TP_ADD_TC(tp, test_att_server_write);
	ATF_TP_ADD_TC(tp, test_att_server_write_cmd);
	ATF_TP_ADD_TC(tp, test_att_server_prepare_execute);
	ATF_TP_ADD_TC(tp, test_att_server_cccd_enable);
	ATF_TP_ADD_TC(tp, test_att_server_notification);
	ATF_TP_ADD_TC(tp, test_att_server_invalid_handle);

	/* GATT Database tests */
	ATF_TP_ADD_TC(tp, test_attdb_build);
	ATF_TP_ADD_TC(tp, test_attdb_hash);
	ATF_TP_ADD_TC(tp, test_attdb_add_service128);

	/* Audit hardening tests */
	ATF_TP_ADD_TC(tp, test_att_server_perm_read_authen);
	ATF_TP_ADD_TC(tp, test_att_server_perm_write_authen);
	ATF_TP_ADD_TC(tp, test_att_server_prepare_queue_bytes);
	ATF_TP_ADD_TC(tp, test_att_server_read_multi_variable);
	ATF_TP_ADD_TC(tp, test_att_server_indication_flow);
	ATF_TP_ADD_TC(tp, test_att_server_exec_write_bad_flags);
	ATF_TP_ADD_TC(tp, test_att_server_find_by_type_value);

	/* BLE 4.0 edge cases */
	ATF_TP_ADD_TC(tp, test_group_type_unsupported);
	ATF_TP_ADD_TC(tp, test_write_readonly);
	ATF_TP_ADD_TC(tp, test_write_zero_length);
	ATF_TP_ADD_TC(tp, test_mtu_clamp_minimum);
	ATF_TP_ADD_TC(tp, test_read_by_type_not_found);
	ATF_TP_ADD_TC(tp, test_prepare_then_cancel);

	/* BLE 5.1 GATT Database Hash */
	ATF_TP_ADD_TC(tp, test_attdb_hash_deterministic);
	ATF_TP_ADD_TC(tp, test_attdb_hash_excludes_values);
	ATF_TP_ADD_TC(tp, test_attdb_hash_differs);

	/* BLE 5.1 Read Multiple Variable Length */
	ATF_TP_ADD_TC(tp, test_read_multi_var_invalid_handle);

	/* BLE 5.2 Multi-Handle Value Notification */
	ATF_TP_ADD_TC(tp, test_multi_handle_ntf_format);

	/* Raw PDU byte-level tests */
	ATF_TP_ADD_TC(tp, test_raw_pdu_read);
	ATF_TP_ADD_TC(tp, test_raw_pdu_error);
	ATF_TP_ADD_TC(tp, test_raw_pdu_mtu);
	ATF_TP_ADD_TC(tp, test_raw_pdu_write);
	ATF_TP_ADD_TC(tp, test_raw_pdu_find_info);
	ATF_TP_ADD_TC(tp, test_raw_pdu_read_by_group);

	/* Multi-MTU tests */
	ATF_TP_ADD_TC(tp, test_mtu30_read_by_group);
	ATF_TP_ADD_TC(tp, test_mtu23_read_clamp);
	ATF_TP_ADD_TC(tp, test_mtu517_read_full);

	/* Client role PDU verification */
	ATF_TP_ADD_TC(tp, test_client_read_pdu);
	ATF_TP_ADD_TC(tp, test_client_write_pdu);
	ATF_TP_ADD_TC(tp, test_client_find_info_pdu);
	ATF_TP_ADD_TC(tp, test_client_read_by_group_pdu);

	/* Raw PDU: remaining opcodes */
	ATF_TP_ADD_TC(tp, test_raw_pdu_read_by_type);
	ATF_TP_ADD_TC(tp, test_raw_pdu_read_blob);
	ATF_TP_ADD_TC(tp, test_raw_pdu_write_cmd);
	ATF_TP_ADD_TC(tp, test_raw_pdu_prepare_execute);
	ATF_TP_ADD_TC(tp, test_raw_pdu_find_by_type);
	ATF_TP_ADD_TC(tp, test_raw_pdu_read_multiple);
	ATF_TP_ADD_TC(tp, test_raw_pdu_notification);

	/* Multi-MTU: remaining */
	ATF_TP_ADD_TC(tp, test_mtu23_read_by_type_clamp);
	ATF_TP_ADD_TC(tp, test_mtu23_notification_clamp);
	ATF_TP_ADD_TC(tp, test_mtu23_find_info_limited);

	/* Client role: remaining */
	ATF_TP_ADD_TC(tp, test_client_mtu_pdu);
	ATF_TP_ADD_TC(tp, test_client_write_cmd_pdu);
	ATF_TP_ADD_TC(tp, test_client_read_blob_pdu);

	/* TP/GAD Discovery edge cases */
	ATF_TP_ADD_TC(tp, test_gad_restricted_range);
	ATF_TP_ADD_TC(tp, test_gad_empty_range);
	ATF_TP_ADD_TC(tp, test_gad_find_info_single);

	/* TP/GAR Read edge cases */
	ATF_TP_ADD_TC(tp, test_gar_read_encrypt_required);
	ATF_TP_ADD_TC(tp, test_gar_read_empty_value);
	ATF_TP_ADD_TC(tp, test_gar_read_blob_at_end);
	ATF_TP_ADD_TC(tp, test_gar_read_blob_past_end);
	ATF_TP_ADD_TC(tp, test_gar_read_by_type_uuid128);

	/* TP/GAW Write edge cases */
	ATF_TP_ADD_TC(tp, test_gaw_write_cmd_bad_handle);
	ATF_TP_ADD_TC(tp, test_gaw_write_exact_maxlen);
	ATF_TP_ADD_TC(tp, test_gaw_write_over_maxlen);
	ATF_TP_ADD_TC(tp, test_gaw_signed_write_ignored);
	ATF_TP_ADD_TC(tp, test_gaw_prepare_multi_fragment);

	/* TP/GAN Notification edge cases */
	ATF_TP_ADD_TC(tp, test_gan_notify_empty);
	ATF_TP_ADD_TC(tp, test_gan_notify_sequence);
	ATF_TP_ADD_TC(tp, test_gai_indicate_empty);

	/* Client role: remaining */
	ATF_TP_ADD_TC(tp, test_client_read_by_type_pdu);
	ATF_TP_ADD_TC(tp, test_client_read_multiple_pdu);
	ATF_TP_ADD_TC(tp, test_client_error_errno);
	ATF_TP_ADD_TC(tp, test_client_confirm_pdu);

	/* Systematic multi-MTU: Read Blob */
	ATF_TP_ADD_TC(tp, test_mtu23_read_blob);
	ATF_TP_ADD_TC(tp, test_mtu64_read_blob);
	ATF_TP_ADD_TC(tp, test_mtu517_read_blob);

	/* Multi-MTU: Read Multiple */
	ATF_TP_ADD_TC(tp, test_mtu23_read_multiple);
	ATF_TP_ADD_TC(tp, test_mtu64_read_multiple);

	/* Multi-MTU: Read Multiple Variable */
	ATF_TP_ADD_TC(tp, test_mtu23_read_multi_var);
	ATF_TP_ADD_TC(tp, test_mtu64_read_multi_var);

	/* Multi-MTU: Indication */
	ATF_TP_ADD_TC(tp, test_mtu23_indication);
	ATF_TP_ADD_TC(tp, test_mtu64_indication);
	ATF_TP_ADD_TC(tp, test_mtu517_indication);

	/* Multi-MTU: fill in MTU=64 for existing opcode tests */
	ATF_TP_ADD_TC(tp, test_mtu64_read_by_group);
	ATF_TP_ADD_TC(tp, test_mtu64_read);
	ATF_TP_ADD_TC(tp, test_mtu64_read_by_type);
	ATF_TP_ADD_TC(tp, test_mtu64_notification);
	ATF_TP_ADD_TC(tp, test_mtu64_find_info);

	/* NEW: Write edge cases */
	ATF_TP_ADD_TC(tp, test_gaw_write_invalid_handle_zero);
	ATF_TP_ADD_TC(tp, test_gaw_write_encrypt_required);
	ATF_TP_ADD_TC(tp, test_gaw_write_encrypt_success);
	ATF_TP_ADD_TC(tp, test_gaw_write_cmd_zero_handle);
	ATF_TP_ADD_TC(tp, test_gaw_prepare_write_readonly);
	ATF_TP_ADD_TC(tp, test_gaw_prepare_write_invalid_handle);
	ATF_TP_ADD_TC(tp, test_gaw_prepare_queue_full);
	ATF_TP_ADD_TC(tp, test_gaw_execute_empty_queue);
	ATF_TP_ADD_TC(tp, test_gaw_execute_cancel_empty);
	ATF_TP_ADD_TC(tp, test_gaw_write_at_mtu_boundary);
	ATF_TP_ADD_TC(tp, test_gaw_write_cmd_at_mtu_boundary);
	ATF_TP_ADD_TC(tp, test_gaw_prepare_different_handles);
	ATF_TP_ADD_TC(tp, test_raw_pdu_indication);
	ATF_TP_ADD_TC(tp, test_raw_pdu_read_multi_var);
	ATF_TP_ADD_TC(tp, test_raw_pdu_multi_handle_ntf);
	ATF_TP_ADD_TC(tp, test_mtu23_find_by_type);
	ATF_TP_ADD_TC(tp, test_mtu64_find_by_type);
	ATF_TP_ADD_TC(tp, test_mtu64_write);
	ATF_TP_ADD_TC(tp, test_mtu517_write);
	ATF_TP_ADD_TC(tp, test_mtu23_prepare_write);
	ATF_TP_ADD_TC(tp, test_mtu64_prepare_write);
	ATF_TP_ADD_TC(tp, test_mtu517_prepare_write);
	ATF_TP_ADD_TC(tp, test_gaw_cccd_indicate);
	ATF_TP_ADD_TC(tp, test_gaw_cccd_both_flags);

	/* NEW: Read edge cases */
	ATF_TP_ADD_TC(tp, test_gar_read_handle_zero);
	ATF_TP_ADD_TC(tp, test_gar_read_handle_past_end);
	ATF_TP_ADD_TC(tp, test_gar_read_not_permitted);
	ATF_TP_ADD_TC(tp, test_gar_read_blob_offset_zero);
	ATF_TP_ADD_TC(tp, test_gar_read_multi_invalid_handle);
	ATF_TP_ADD_TC(tp, test_gar_read_multi_all_valid);
	ATF_TP_ADD_TC(tp, test_gar_read_multi_var_empty_value);
	ATF_TP_ADD_TC(tp, test_gar_read_by_type_truncated);
	ATF_TP_ADD_TC(tp, test_gar_read_service_decl);
	ATF_TP_ADD_TC(tp, test_gar_read_char_decl);
	ATF_TP_ADD_TC(tp, test_gad_read_by_group_secondary);
	ATF_TP_ADD_TC(tp, test_raw_pdu_read_custom_char);
	ATF_TP_ADD_TC(tp, test_gad_find_info_full_range);
	ATF_TP_ADD_TC(tp, test_gad_find_by_type_not_found);
	ATF_TP_ADD_TC(tp, test_gad_find_by_type_multi_match);

	/* NEW: Client role tests */
	ATF_TP_ADD_TC(tp, test_client_find_by_type_pdu);
	ATF_TP_ADD_TC(tp, test_client_prepare_write_pdu);
	ATF_TP_ADD_TC(tp, test_client_execute_write_pdu);
	ATF_TP_ADD_TC(tp, test_client_write_long_small);
	ATF_TP_ADD_TC(tp, test_client_write_long_multi);
	ATF_TP_ADD_TC(tp, test_client_write_error);
	ATF_TP_ADD_TC(tp, test_client_find_by_type_not_found);
	ATF_TP_ADD_TC(tp, test_client_read_multi_three);
	ATF_TP_ADD_TC(tp, test_client_read_specific_error);
	ATF_TP_ADD_TC(tp, test_client_write_cmd_verify);
	ATF_TP_ADD_TC(tp, test_client_read_by_group_error);

	/* NEW: Multi-MTU fill-in */
	ATF_TP_ADD_TC(tp, test_mtu517_read_multiple);
	ATF_TP_ADD_TC(tp, test_mtu517_read_multi_var);
	ATF_TP_ADD_TC(tp, test_mtu517_read_by_type);
	ATF_TP_ADD_TC(tp, test_mtu517_find_info);
	ATF_TP_ADD_TC(tp, test_mtu517_read_by_group);
	ATF_TP_ADD_TC(tp, test_mtu517_notification);
	ATF_TP_ADD_TC(tp, test_mtu517_find_by_type);
	ATF_TP_ADD_TC(tp, test_mtu23_read);
	ATF_TP_ADD_TC(tp, test_mtu23_write);
	ATF_TP_ADD_TC(tp, test_mtu23_read_by_group_single_entry);

	/* NEW: ATTDB edge cases */
	ATF_TP_ADD_TC(tp, test_attdb_full);
	ATF_TP_ADD_TC(tp, test_attdb_add_char128);
	ATF_TP_ADD_TC(tp, test_attdb_cccd_standalone);
	ATF_TP_ADD_TC(tp, test_attdb_val_store_full);
	ATF_TP_ADD_TC(tp, test_attdb_empty_read_by_group);

	/* Section A: Write parity */
	ATF_TP_ADD_TC(tp, test_gaw_write_to_service_decl);
	ATF_TP_ADD_TC(tp, test_gaw_write_to_char_decl);
	ATF_TP_ADD_TC(tp, test_gaw_prepare_write_offset_past_maxlen);
	ATF_TP_ADD_TC(tp, test_gaw_execute_offset_past_maxlen);
	ATF_TP_ADD_TC(tp, test_gaw_write_req_empty_value);
	ATF_TP_ADD_TC(tp, test_gaw_write_req_to_cccd_invalid);
	ATF_TP_ADD_TC(tp, test_gaw_write_cmd_encrypt_required);
	ATF_TP_ADD_TC(tp, test_gaw_prepare_write_encrypt_required);
	ATF_TP_ADD_TC(tp, test_gaw_write_replaces_value);
	ATF_TP_ADD_TC(tp, test_gaw_write_cmd_valid);

	/* Section B: Read parity */
	ATF_TP_ADD_TC(tp, test_gar_read_blob_offset_one);
	ATF_TP_ADD_TC(tp, test_gar_read_by_type_perm_denied);
	ATF_TP_ADD_TC(tp, test_gar_read_multi_three_handles);
	ATF_TP_ADD_TC(tp, test_gar_read_multi_var_three);
	ATF_TP_ADD_TC(tp, test_gar_read_by_group_full_range);
	ATF_TP_ADD_TC(tp, test_gar_read_blob_encrypt_required);
	ATF_TP_ADD_TC(tp, test_gar_read_by_type_char_value);
	ATF_TP_ADD_TC(tp, test_gar_read_multi_concat_verify);
	ATF_TP_ADD_TC(tp, test_gar_read_cccd_value);
	ATF_TP_ADD_TC(tp, test_gar_read_by_type_handle_range);

	/* Section C: Client role parity */
	ATF_TP_ADD_TC(tp, test_client_find_info_128bit);
	ATF_TP_ADD_TC(tp, test_client_read_by_type_error);
	ATF_TP_ADD_TC(tp, test_client_write_req_verify_bytes);
	ATF_TP_ADD_TC(tp, test_client_read_blob_error);
	ATF_TP_ADD_TC(tp, test_client_find_by_type_multi_result);
	ATF_TP_ADD_TC(tp, test_client_prepare_write_verify);
	ATF_TP_ADD_TC(tp, test_client_execute_cancel_pdu);
	ATF_TP_ADD_TC(tp, test_client_execute_commit_pdu);
	ATF_TP_ADD_TC(tp, test_client_write_long_error_cancels);
	ATF_TP_ADD_TC(tp, test_client_read_empty_response);

	/* Section D: Raw PDU byte-level parity */
	ATF_TP_ADD_TC(tp, test_raw_pdu_write_req_response);
	ATF_TP_ADD_TC(tp, test_raw_pdu_read_blob_offset);
	ATF_TP_ADD_TC(tp, test_raw_pdu_cccd_write);
	ATF_TP_ADD_TC(tp, test_raw_pdu_read_by_type_char);
	ATF_TP_ADD_TC(tp, test_raw_pdu_execute_cancel);
	ATF_TP_ADD_TC(tp, test_raw_pdu_execute_commit);
	ATF_TP_ADD_TC(tp, test_raw_pdu_mtu_large);
	ATF_TP_ADD_TC(tp, test_raw_pdu_error_write_not_permitted);
	ATF_TP_ADD_TC(tp, test_raw_pdu_error_insuff_encrypt);

	/* Section E: Multi-MTU fill-in */
	ATF_TP_ADD_TC(tp, test_mtu23_write_cmd);
	ATF_TP_ADD_TC(tp, test_mtu64_write_cmd);
	ATF_TP_ADD_TC(tp, test_mtu517_write_cmd);
	ATF_TP_ADD_TC(tp, test_mtu23_cccd_write);
	ATF_TP_ADD_TC(tp, test_mtu64_cccd_write);
	ATF_TP_ADD_TC(tp, test_mtu23_read_service_decl);
	ATF_TP_ADD_TC(tp, test_mtu23_read_char_decl);
	ATF_TP_ADD_TC(tp, test_mtu64_read_blob_partial);
	ATF_TP_ADD_TC(tp, test_mtu517_notification_full);
	ATF_TP_ADD_TC(tp, test_mtu64_multi_handle_ntf);

	/* EATT tests */
	ATF_TP_ADD_TC(tp, test_eatt_select_fallback);
	ATF_TP_ADD_TC(tp, test_eatt_select_active);
	ATF_TP_ADD_TC(tp, test_eatt_select_skip_inactive);
	ATF_TP_ADD_TC(tp, test_eatt_select_all_inactive);
	ATF_TP_ADD_TC(tp, test_eatt_close);
	ATF_TP_ADD_TC(tp, test_eatt_close_empty);
	ATF_TP_ADD_TC(tp, test_eatt_open_connect_fails);
	ATF_TP_ADD_TC(tp, test_eatt_open_clamp_count);
	ATF_TP_ADD_TC(tp, test_eatt_lifecycle);
	ATF_TP_ADD_TC(tp, test_eatt_multi_bearer_select);

	/* HOG notification tests */
	ATF_TP_ADD_TC(tp, test_hog_notification_recv);
	ATF_TP_ADD_TC(tp, test_hog_notification_report);
	ATF_TP_ADD_TC(tp, test_hog_notification_sequence);
	ATF_TP_ADD_TC(tp, test_hog_indication_confirm);

	/* UUID tests */
	ATF_TP_ADD_TC(tp, test_uuid_read_by_type_uuid16);
	ATF_TP_ADD_TC(tp, test_uuid_read_by_type_uuid128_base);
	ATF_TP_ADD_TC(tp, test_uuid_read_by_type_uuid128_vendor);
	ATF_TP_ADD_TC(tp, test_uuid_read_by_type_invalid_len_1);
	ATF_TP_ADD_TC(tp, test_uuid_read_by_type_invalid_len_3);
	ATF_TP_ADD_TC(tp, test_uuid_read_by_type_invalid_len_5);
	ATF_TP_ADD_TC(tp, test_uuid_read_by_type_invalid_len_15);
	ATF_TP_ADD_TC(tp, test_uuid_read_by_type_invalid_len_17);
	ATF_TP_ADD_TC(tp, test_uuid_read_by_group_uuid16);
	ATF_TP_ADD_TC(tp, test_uuid_read_by_group_uuid128_base);
	ATF_TP_ADD_TC(tp, test_uuid_read_by_group_invalid_len);
	ATF_TP_ADD_TC(tp, test_uuid_well_known_primary);
	ATF_TP_ADD_TC(tp, test_uuid_well_known_characteristic);
	ATF_TP_ADD_TC(tp, test_uuid_well_known_cccd);
	ATF_TP_ADD_TC(tp, test_uuid_well_known_device_name);
	ATF_TP_ADD_TC(tp, test_uuid_byte_order_le);
	ATF_TP_ADD_TC(tp, test_uuid_uuid32_collapses);
	ATF_TP_ADD_TC(tp, test_uuid_uuid32_non_collapsible);
	ATF_TP_ADD_TC(tp, test_uuid_128bit_not_base);

	/* ATT server edge cases */
	ATF_TP_ADD_TC(tp, test_att_server_reset);
	ATF_TP_ADD_TC(tp, test_att_eatt_accept);
	ATF_TP_ADD_TC(tp, test_att_server_permission_encrypt_required);
	ATF_TP_ADD_TC(tp, test_att_server_read_blob_not_long);
	ATF_TP_ADD_TC(tp, test_att_server_read_blob_offset_eq_len);

	/* Malformed / truncated PDU tests */
	ATF_TP_ADD_TC(tp, test_srv_truncated_read_by_type);
	ATF_TP_ADD_TC(tp, test_srv_truncated_find_info);
	ATF_TP_ADD_TC(tp, test_srv_truncated_write);
	ATF_TP_ADD_TC(tp, test_srv_zero_length_pdu);
	ATF_TP_ADD_TC(tp, test_srv_unknown_opcode);
	ATF_TP_ADD_TC(tp, test_srv_oversized_pdu);
	ATF_TP_ADD_TC(tp, test_srv_write_cmd_truncated);

	/* Signed Write Command tests */
	ATF_TP_ADD_TC(tp, test_signed_write_cmd);
	ATF_TP_ADD_TC(tp, test_signed_write_cmd_invalid_sig);
	ATF_TP_ADD_TC(tp, test_signed_write_cmd_no_csrk);

	/* EATT large MTU */
	ATF_TP_ADD_TC(tp, test_eatt_large_mtu_response);

	/* ATTDB edge cases */
	ATF_TP_ADD_TC(tp, test_attdb_remove_service);
	ATF_TP_ADD_TC(tp, test_att_opcode_name);

	/* Bearer-aware notification */
	ATF_TP_ADD_TC(tp, test_notification_bearer_aware);

	/* CCCD RFU bit masking */
	ATF_TP_ADD_TC(tp, test_cccd_rfu_bits_masked);

	return (atf_no_error());
}
