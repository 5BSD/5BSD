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
#include <sys/socket.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
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

/* ================================================================
 * Stubs for external symbols referenced by att.c / att_server.c
 * but not needed for ATT-only tests.
 * ================================================================ */

/* ble_util.h globals */
int blued_verbose;
int blued_daemonized;

/* hci_log.c stubs */
bool
hci_log_enabled(void)
{

	return (false);
}

void
hci_log_l2cap(uint16_t con_handle __unused, uint16_t cid __unused,
    const uint8_t *data __unused, uint16_t len __unused,
    bool incoming __unused)
{
}

void
hci_log_packet(uint8_t type __unused, const uint8_t *data __unused,
    uint16_t len __unused, bool incoming __unused)
{
}

/* att.c references ble_coc_connect via att_open_eatt */
int
ble_coc_connect(const uint8_t *addr __unused, uint8_t addr_type __unused,
    uint16_t psm __unused, uint16_t mtu __unused)
{

	return (-1);
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

	int ret = att_server_handle(&ac, &db, pdu, 3);
	ATF_CHECK_EQ(ret, 0);

	/* Read the response from client_fd */
	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 3);
	ATF_CHECK_EQ(rsp[0], ATT_OP_MTU_RSP);
	uint16_t server_mtu = get_le16(rsp + 1);
	ATF_CHECK_EQ(server_mtu, ATT_MAX_MTU);

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
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Read By Group Type: start=0x0001, end=0xFFFF, uuid=0x2800 */
	uint8_t pdu[7];
	pdu[0] = ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);

	int ret = att_server_handle(&ac, &db, pdu, 7);
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
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Read By Type: start=0x0001, end=0xFFFF, uuid=0x2803 (Characteristic) */
	uint8_t pdu[7];
	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_CHARACTERISTIC);

	int ret = att_server_handle(&ac, &db, pdu, 7);
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
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Find Information: start=0x0005, end=0x0007 */
	uint8_t pdu[5];
	pdu[0] = ATT_OP_FIND_INFO_REQ;
	put_le16(pdu + 1, 0x0005);
	put_le16(pdu + 3, 0x0007);

	int ret = att_server_handle(&ac, &db, pdu, 5);
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
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	att_mock_pair(&ac, &client_fd);
	build_test_db(&db, attrs, val_buf);

	/* Read Request: handle=0x0003 (Device Name = "Test") */
	uint8_t pdu[3];
	pdu[0] = ATT_OP_READ_REQ;
	put_le16(pdu + 1, 0x0003);

	int ret = att_server_handle(&ac, &db, pdu, 3);
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
	uint8_t rsp[ATT_MAX_MTU];
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

	int ret = att_server_handle(&ac, &db, pdu, 7);
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

	int ret = att_server_handle(&ac, &db, pdu, 5);
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
	uint8_t rsp[ATT_MAX_MTU];
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

	int ret = att_server_handle(&ac, &db, prep, 7);
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

	ret = att_server_handle(&ac, &db, exec, 2);
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

	int ret = att_server_handle(&ac, &db, pdu, 5);
	ATF_CHECK_EQ(ret, 0);

	n = recv(client_fd, rsp, sizeof(rsp), 0);
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], ATT_OP_WRITE_RSP);

	/* Verify CCCD value is stored */
	struct att_attr *cccd = NULL;
	for (int i = 0; i < db.count; i++) {
		if (db.attrs[i].handle == 0x0007) {
			cccd = &db.attrs[i];
			break;
		}
	}
	ATF_REQUIRE(cccd != NULL);
	ATF_CHECK_EQ(get_le16(cccd->value), GATT_CCCD_NOTIFY);

	att_mock_cleanup(&ac, client_fd);
}

/* 16. test_att_server_notification */
ATF_TC_WITHOUT_HEAD(test_att_server_notification);
ATF_TC_BODY(test_att_server_notification, tc)
{
	struct att_conn ac;
	int client_fd;
	uint8_t rsp[ATT_MAX_MTU];
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

	int ret = att_server_handle(&ac, &db, pdu, 3);
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

	return (atf_no_error());
}
