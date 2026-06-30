/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATT server unit tests.
 *
 * Tests the GATT database construction and ATT PDU handling without
 * any real Bluetooth hardware.  Uses a mock att_conn with a pipe(2)
 * pair instead of a real L2CAP socket.
 *
 * Build: cc -o test_att_server test_att_server.c ../att_server.c
 *        -I.. -I/usr/src/sys -lcrypto && ./test_att_server
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

/* Stubs */
int blued_verbose = 0;
int blued_daemonized = 0;

int hci_log_enabled(void) { return 0; }
void hci_log_l2cap(uint16_t h __unused, uint16_t c __unused,
    const void *d __unused, uint16_t l __unused, bool rx __unused) {}

/* DTrace probe stubs */
void __dtrace_blued___att__recv(int o __unused, int l __unused) {}
void __dtrace_blued___att__send(int o __unused, int l __unused) {}
int __dtraceenabled_blued___att__recv(void) { return 0; }
int __dtraceenabled_blued___att__send(void) { return 0; }

#include "att.h"
#include "att_server.h"
#include "ble_util.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
	tests_run++; \
	printf("  %-55s ", name); \
} while (0)

#define PASS() do { \
	tests_passed++; \
	printf("PASS\n"); \
} while (0)

#define FAIL(msg) do { \
	printf("FAIL: %s\n", msg); \
} while (0)

/* Build a test GATT database */
static struct att_attr test_attrs[32];
static uint8_t test_val_buf[512];
static struct att_db test_db;

/* Mock ATT connection using a pipe */
static struct att_conn test_ac;
static int mock_fds[2]; /* [0]=read side, [1]=write side (ac->fd) */
static uint8_t response_buf[ATT_MAX_MTU];
static ssize_t response_len;

static void
setup(void)
{
	socketpair(AF_UNIX, SOCK_STREAM, 0, mock_fds);
	/* Make read side non-blocking so we can check responses */
	fcntl(mock_fds[0], F_SETFL, O_NONBLOCK);
	memset(&test_ac, 0, sizeof(test_ac));
	test_ac.fd = mock_fds[1]; /* ATT server writes to this end */
	test_ac.mtu = ATT_DEFAULT_MTU; /* 23 */
	test_ac.ind_timer = 0;

	attdb_init(&test_db, test_attrs, 32, test_val_buf, sizeof(test_val_buf));
	/* GAP Service */
	attdb_add_service(&test_db, 0x1800);
	attdb_add_characteristic(&test_db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, "Test", 4);
	/* Custom service with write */
	attdb_add_service(&test_db, 0xFFE0);
	attdb_add_characteristic(&test_db, 0xFFE1,
	    GATT_PROP_READ | GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    "\x00", 1);
	attdb_add_cccd(&test_db);
}

static void
teardown(void)
{
	close(mock_fds[0]);
	close(mock_fds[1]);
}

/* Read the response that att_server_handle wrote to the pipe */
static void
read_response(void)
{
	response_len = read(mock_fds[0], response_buf, sizeof(response_buf));
}

static void
test_mtu_exchange(void)
{
	uint8_t req[3] = { ATT_OP_MTU_REQ, 0x00, 0x02 }; /* client MTU=512 */

	TEST("MTU Exchange — client=512, server=517");
	att_server_handle(&test_ac, &test_db, req, sizeof(req));
	read_response();
	if (response_len != 3 || response_buf[0] != ATT_OP_MTU_RSP) {
		FAIL("wrong response");
		return;
	}
	uint16_t server_mtu = get_le16(response_buf + 1);
	if (server_mtu != ATT_MAX_MTU) {
		FAIL("server MTU != 517");
		return;
	}
	/* Negotiated = min(512, 517) = 512 */
	if (test_ac.mtu != 512) {
		char msg[64];
		snprintf(msg, sizeof(msg), "negotiated MTU=%d, expected 512",
		    test_ac.mtu);
		FAIL(msg);
		return;
	}
	PASS();
	/* Reset MTU for subsequent tests */
	test_ac.mtu = ATT_DEFAULT_MTU;
}

static void
test_find_info_valid(void)
{
	uint8_t req[5];

	TEST("Find Info — valid handle range 0x0001-0xFFFF");
	req[0] = ATT_OP_FIND_INFO_REQ;
	put_le16(req + 1, 0x0001);
	put_le16(req + 3, 0xFFFF);
	att_server_handle(&test_ac, &test_db, req, sizeof(req));
	read_response();
	if (response_len < 6 || response_buf[0] != ATT_OP_FIND_INFO_RSP) {
		FAIL("expected Find Info Response");
		return;
	}
	if (response_buf[1] != 0x01 && response_buf[1] != 0x02) {
		FAIL("invalid format byte");
		return;
	}
	PASS();
}

static void
test_find_info_invalid_handle(void)
{
	uint8_t req[5];

	TEST("Find Info — start=0x0000 → Invalid Handle");
	req[0] = ATT_OP_FIND_INFO_REQ;
	put_le16(req + 1, 0x0000);
	put_le16(req + 3, 0xFFFF);
	att_server_handle(&test_ac, &test_db, req, sizeof(req));
	read_response();
	if (response_len != 5 || response_buf[0] != ATT_OP_ERROR_RSP) {
		FAIL("expected Error Response");
		return;
	}
	if (response_buf[4] != ATT_ERR_INVALID_HANDLE) {
		FAIL("wrong error code");
		return;
	}
	PASS();
}

static void
test_find_info_reversed_range(void)
{
	uint8_t req[5];

	TEST("Find Info — start > end → Invalid Handle");
	req[0] = ATT_OP_FIND_INFO_REQ;
	put_le16(req + 1, 0x0010);
	put_le16(req + 3, 0x0001);
	att_server_handle(&test_ac, &test_db, req, sizeof(req));
	read_response();
	if (response_buf[0] != ATT_OP_ERROR_RSP ||
	    response_buf[4] != ATT_ERR_INVALID_HANDLE) {
		FAIL("expected Invalid Handle error");
		return;
	}
	PASS();
}

static void
test_read_valid(void)
{
	uint8_t req[3];

	TEST("Read Request — GAP Device Name (handle 0x0003)");
	req[0] = ATT_OP_READ_REQ;
	put_le16(req + 1, 0x0003); /* value handle of first char */
	att_server_handle(&test_ac, &test_db, req, sizeof(req));
	read_response();
	if (response_len < 2 || response_buf[0] != ATT_OP_READ_RSP) {
		FAIL("expected Read Response");
		return;
	}
	if (response_len != 5 || memcmp(response_buf + 1, "Test", 4) != 0) {
		FAIL("value mismatch");
		return;
	}
	PASS();
}

static void
test_read_invalid_handle(void)
{
	uint8_t req[3];

	TEST("Read Request — invalid handle 0xFFFF → error");
	req[0] = ATT_OP_READ_REQ;
	put_le16(req + 1, 0xFFFF);
	att_server_handle(&test_ac, &test_db, req, sizeof(req));
	read_response();
	if (response_buf[0] != ATT_OP_ERROR_RSP ||
	    response_buf[4] != ATT_ERR_INVALID_HANDLE) {
		FAIL("expected Invalid Handle error");
		return;
	}
	PASS();
}

static void
test_write_valid(void)
{
	uint8_t req[4];

	TEST("Write Request — write 0x42 to custom char");
	req[0] = ATT_OP_WRITE_REQ;
	put_le16(req + 1, 0x0006); /* value handle of custom char */
	req[3] = 0x42;
	att_server_handle(&test_ac, &test_db, req, sizeof(req));
	read_response();
	if (response_len != 1 || response_buf[0] != ATT_OP_WRITE_RSP) {
		FAIL("expected Write Response");
		return;
	}
	/* Verify the value was written */
	struct att_attr *a = NULL;
	for (int i = 0; i < test_db.count; i++) {
		if (test_db.attrs[i].handle == 0x0006) {
			a = &test_db.attrs[i];
			break;
		}
	}
	if (a == NULL || a->value[0] != 0x42) {
		FAIL("value not written");
		return;
	}
	PASS();
}

static void
test_write_too_long(void)
{
	uint8_t req[5];

	TEST("Write Request — value too long → Invalid Attr Length");
	req[0] = ATT_OP_WRITE_REQ;
	put_le16(req + 1, 0x0006);
	req[3] = 0x01;
	req[4] = 0x02; /* 2 bytes but maxlen=1 */
	att_server_handle(&test_ac, &test_db, req, sizeof(req));
	read_response();
	if (response_buf[0] != ATT_OP_ERROR_RSP ||
	    response_buf[4] != ATT_ERR_INVALID_ATTR_LEN) {
		FAIL("expected Invalid Attribute Length error");
		return;
	}
	PASS();
}

static void
test_unknown_opcode(void)
{
	uint8_t req[1] = { 0xBF }; /* unknown request (bit 6 clear) */

	TEST("Unknown opcode 0xBF → Request Not Supported");
	att_server_handle(&test_ac, &test_db, req, sizeof(req));
	read_response();
	if (response_buf[0] != ATT_OP_ERROR_RSP ||
	    response_buf[4] != ATT_ERR_REQ_NOT_SUPPORTED) {
		FAIL("expected Request Not Supported");
		return;
	}
	PASS();
}

static void
test_command_ignored(void)
{
	uint8_t req[1] = { 0xFF }; /* unknown command (bit 6 set) */

	TEST("Unknown command 0xFF — silently ignored");
	int ret = att_server_handle(&test_ac, &test_db, req, sizeof(req));
	/* Should return 0 (no error, no response) */
	if (ret != 0) {
		FAIL("expected return 0");
		return;
	}
	PASS();
}

static void
test_execute_write_bad_flags(void)
{
	uint8_t req[2];

	TEST("Execute Write — invalid flags 0x02 → Invalid PDU");
	req[0] = ATT_OP_EXECUTE_WRITE_REQ;
	req[1] = 0x02;
	att_server_handle(&test_ac, &test_db, req, sizeof(req));
	read_response();
	if (response_buf[0] != ATT_OP_ERROR_RSP ||
	    response_buf[4] != ATT_ERR_INVALID_PDU) {
		FAIL("expected Invalid PDU error");
		return;
	}
	PASS();
}

static void
test_pdu_too_short(void)
{
	uint8_t req[2]; /* Find Info needs 5 bytes */

	TEST("Find Info — PDU too short (2 bytes) → Invalid PDU");
	req[0] = ATT_OP_FIND_INFO_REQ;
	req[1] = 0x00;
	att_server_handle(&test_ac, &test_db, req, 2);
	read_response();
	if (response_buf[0] != ATT_OP_ERROR_RSP ||
	    response_buf[4] != ATT_ERR_INVALID_PDU) {
		FAIL("expected Invalid PDU error");
		return;
	}
	PASS();
}

int
main(void)
{
	printf("ATT Server Unit Tests\n");
	printf("=====================\n\n");

	setup();

	test_mtu_exchange();
	test_find_info_valid();
	test_find_info_invalid_handle();
	test_find_info_reversed_range();
	test_read_valid();
	test_read_invalid_handle();
	test_write_valid();
	test_write_too_long();
	test_unknown_opcode();
	test_command_ignored();
	test_execute_write_bad_flags();
	test_pdu_too_short();

	teardown();

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return (tests_passed == tests_run ? 0 : 1);
}
