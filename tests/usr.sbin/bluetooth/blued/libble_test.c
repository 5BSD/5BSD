/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF unit tests for libble (lib/libble).
 *
 * Tests protocol serialization, response parsing, callback dispatch,
 * error handling, and API contracts.  Uses socketpair(2) to mock the
 * daemon side — no running blued required.
 */

#include <sys/socket.h>

#include <atf-c.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "ble.h"

/* ================================================================
 * Helpers
 * ================================================================ */

static ble_ctx_t *
make_mock_ctx(int *daemon_fd)
{
	int sp[2];
	ble_ctx_t *ctx;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	*daemon_fd = sp[1];
	return (ctx);
}

static void
mock_send(int fd, const char *line)
{
	char buf[1024];
	int len;

	len = snprintf(buf, sizeof(buf), "%s\n", line);
	ATF_REQUIRE(send(fd, buf, (size_t)len, 0) == len);
}

static ssize_t
mock_recv(int fd, char *buf, size_t bufsz)
{
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	ssize_t n;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	n = recv(fd, buf, bufsz - 1, 0);
	if (n > 0)
		buf[n] = '\0';
	return (n);
}

/* ================================================================
 * SCAN: verify parsed fields, not just count
 * ================================================================ */
static ble_scan_result_t last_scan;
static int scan_count;

static void
scan_cb(const ble_scan_result_t *r, void *arg __unused)
{
	scan_count++;
	last_scan = *r;
}

ATF_TC_WITHOUT_HEAD(test_scan_parses_fields);
ATF_TC_BODY(test_scan_parses_fields, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	char cmd[256];

	ctx = make_mock_ctx(&dfd);
	scan_count = 0;

	ATF_CHECK_EQ(ble_scan(ctx, scan_cb, NULL), 0);
	mock_recv(dfd, cmd, sizeof(cmd));
	ATF_CHECK_MSG(strstr(cmd, "SCAN") != NULL, "cmd: %s", cmd);

	mock_send(dfd, "SCANNING");
	mock_send(dfd, "DEVICE [ubt0] aa:bb:cc:dd:ee:ff random rssi=-45 name=TestDevice mfr=0x004C svcs=0x180F");
	mock_send(dfd, "END");
	ATF_CHECK_EQ(ble_process(ctx), 0);

	ATF_CHECK_EQ(scan_count, 1);
	ATF_CHECK_EQ(last_scan.addr.addr_type, 1);  /* random */
	ATF_CHECK_EQ(last_scan.rssi, -45);
	ATF_CHECK_MSG(strcmp(last_scan.name, "TestDevice") == 0,
	    "name: '%s'", last_scan.name);
	ATF_CHECK_EQ(last_scan.mfr_id, 0x004C);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_scan_public_addr_type);
ATF_TC_BODY(test_scan_public_addr_type, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	char cmd[256];

	ctx = make_mock_ctx(&dfd);
	scan_count = 0;

	ble_scan(ctx, scan_cb, NULL);
	mock_recv(dfd, cmd, sizeof(cmd));

	mock_send(dfd, "SCANNING");
	mock_send(dfd, "DEVICE [ubt0] 11:22:33:44:55:66 public rssi=-80 name= mfr=0xFFFF svcs=");
	mock_send(dfd, "END");
	ble_process(ctx);

	ATF_CHECK_EQ(scan_count, 1);
	ATF_CHECK_EQ(last_scan.addr.addr_type, 0);  /* public */
	ATF_CHECK_EQ(last_scan.rssi, -80);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_scan_while_pending_rejected);
ATF_TC_BODY(test_scan_while_pending_rejected, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	char tmp[256];

	ctx = make_mock_ctx(&dfd);

	/* First scan succeeds, registers callback */
	ATF_CHECK_EQ(ble_scan(ctx, scan_cb, NULL), 0);
	mock_recv(dfd, tmp, sizeof(tmp));  /* drain the SCAN command */

	/* Second scan before first completes — must reject */
	ATF_CHECK_EQ(ble_scan(ctx, scan_cb, NULL), -1);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * CONNECT: verify protocol string format
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_connect_random);
ATF_TC_BODY(test_connect_random, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);
	addr.addr_type = 1;

	ATF_CHECK_EQ(ble_connect(ctx, &addr, NULL, NULL), 0);
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "CONNECT") != NULL, "cmd: %s", cmd);
	ATF_CHECK_MSG(strstr(cmd, "random") != NULL,
	    "expected random type: %s", cmd);

	close(dfd);
	ble_close(ctx);
}

static void
dummy_connect_cb(const ble_addr_t *a __unused, int e __unused,
    void *arg __unused) {}

ATF_TC_WITHOUT_HEAD(test_connect_while_pending_rejected);
ATF_TC_BODY(test_connect_while_pending_rejected, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));

	ATF_CHECK_EQ(ble_connect(ctx, &addr, dummy_connect_cb, NULL), 0);
	ATF_CHECK_EQ(ble_connect(ctx, &addr, dummy_connect_cb, NULL), -1);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_connect_name);
ATF_TC_BODY(test_connect_name, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	char cmd[256];

	ctx = make_mock_ctx(&dfd);

	ATF_CHECK_EQ(ble_connect_name(ctx, "Kory's iPod", NULL, NULL), 0);
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "CONNECT_NAME") != NULL, "cmd: %s", cmd);
	ATF_CHECK_MSG(strstr(cmd, "Kory's iPod") != NULL,
	    "expected device name in: %s", cmd);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * WRITE: verify hex encoding
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_write_hex_encoding);
ATF_TC_BODY(test_write_hex_encoding, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	uint8_t val[] = { 0x01, 0xAB, 0xFF, 0x00 };
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("11:22:33:44:55:66", &ba);
	memcpy(addr.addr, &ba, 6);

	ATF_CHECK_EQ(ble_write(ctx, &addr, 0x0025, val, 4), 0);
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "WRITE") != NULL, "cmd: %s", cmd);
	ATF_CHECK_MSG(strstr(cmd, "0x0025") != NULL, "handle: %s", cmd);
	ATF_CHECK_MSG(strstr(cmd, "01ABFF00") != NULL,
	    "hex: %s", cmd);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * SUBSCRIBE + NOTIFY: verify handle and value bytes
 * ================================================================ */
static ble_addr_t notify_addr;
static uint16_t notify_handle;
static uint8_t notify_value[64];
static uint16_t notify_len;
static int notify_count;

static void
notify_cb(const ble_addr_t *addr, uint16_t handle,
    const uint8_t *value, uint16_t len, void *arg __unused)
{
	notify_count++;
	notify_addr = *addr;
	notify_handle = handle;
	if (len <= sizeof(notify_value)) {
		memcpy(notify_value, value, len);
		notify_len = len;
	}
}

ATF_TC_WITHOUT_HEAD(test_notify_parses_handle_and_value);
ATF_TC_BODY(test_notify_parses_handle_and_value, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char tmp[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	ble_subscribe(ctx, &addr, 0x0025, notify_cb, NULL);
	mock_recv(dfd, tmp, sizeof(tmp));

	notify_count = 0;
	mock_send(dfd, "OK SUBSCRIBE 0x0025");
	mock_send(dfd, "EVENT NOTIFY aa:bb:cc:dd:ee:ff 0x0025 DEADBEEF");
	ble_process(ctx);

	ATF_CHECK_EQ(notify_count, 1);
	ATF_CHECK_EQ(notify_handle, 0x0025);
	ATF_CHECK_EQ(notify_len, 4);
	ATF_CHECK_EQ(notify_value[0], 0xDE);
	ATF_CHECK_EQ(notify_value[1], 0xAD);
	ATF_CHECK_EQ(notify_value[2], 0xBE);
	ATF_CHECK_EQ(notify_value[3], 0xEF);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_notify_empty_value);
ATF_TC_BODY(test_notify_empty_value, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char tmp[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	ble_subscribe(ctx, &addr, 0x0010, notify_cb, NULL);
	mock_recv(dfd, tmp, sizeof(tmp));

	notify_count = 0;
	notify_len = 99;
	mock_send(dfd, "OK SUBSCRIBE 0x0010");
	mock_send(dfd, "EVENT NOTIFY aa:bb:cc:dd:ee:ff 0x0010");
	ble_process(ctx);

	ATF_CHECK_EQ(notify_count, 1);
	ATF_CHECK_EQ(notify_handle, 0x0010);
	ATF_CHECK_EQ(notify_len, 0);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * DISCOVER: verify parsed services and characteristics
 * ================================================================ */
static int disc_nsvc, disc_nchar;
static ble_service_t disc_svcs[16];
static ble_characteristic_t disc_chars[64];

static void
disc_cb(const ble_addr_t *addr __unused,
    const ble_service_t *svcs, int nsvc,
    const ble_characteristic_t *chars, int nchar, void *arg __unused)
{
	disc_nsvc = nsvc;
	disc_nchar = nchar;
	if (nsvc > 0 && nsvc <= 16)
		memcpy(disc_svcs, svcs, nsvc * sizeof(svcs[0]));
	if (nchar > 0 && nchar <= 64)
		memcpy(disc_chars, chars, nchar * sizeof(chars[0]));
}

ATF_TC_WITHOUT_HEAD(test_discover_parses_service_and_char);
ATF_TC_BODY(test_discover_parses_service_and_char, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	disc_nsvc = 0;
	disc_nchar = 0;

	ATF_CHECK_EQ(ble_discover(ctx, &addr, disc_cb, NULL), 0);
	mock_recv(dfd, cmd, sizeof(cmd));

	mock_send(dfd, "DISCOVER aa:bb:cc:dd:ee:ff");
	mock_send(dfd, "  service uuid=0x1800 handles=0x0001-0x0005");
	mock_send(dfd, "    char uuid=0x2A00 handle=0x0003 props=read");
	mock_send(dfd, "  service uuid=0x180F handles=0x0010-0x0013");
	mock_send(dfd, "    char uuid=0x2A19 handle=0x0012 props=read|notify");
	mock_send(dfd, "END");
	ble_process(ctx);

	/* Verify service count and fields */
	ATF_CHECK_EQ(disc_nsvc, 2);
	ATF_CHECK_EQ(disc_svcs[0].uuid.uuid16, 0x1800);
	ATF_CHECK_EQ(disc_svcs[0].start_handle, 0x0001);
	ATF_CHECK_EQ(disc_svcs[0].end_handle, 0x0005);
	ATF_CHECK_EQ(disc_svcs[1].uuid.uuid16, 0x180F);
	ATF_CHECK_EQ(disc_svcs[1].start_handle, 0x0010);

	/* Verify characteristic count and fields */
	ATF_CHECK_EQ(disc_nchar, 2);
	ATF_CHECK_EQ(disc_chars[0].uuid.uuid16, 0x2A00);
	ATF_CHECK_EQ(disc_chars[0].handle, 0x0003);
	ATF_CHECK_EQ(disc_chars[0].properties, BLE_PROP_READ);
	ATF_CHECK_EQ(disc_chars[1].uuid.uuid16, 0x2A19);
	ATF_CHECK_EQ(disc_chars[1].handle, 0x0012);
	ATF_CHECK_EQ(disc_chars[1].properties,
	    BLE_PROP_READ | BLE_PROP_NOTIFY);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_discover_empty);
ATF_TC_BODY(test_discover_empty, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("11:22:33:44:55:66", &ba);
	memcpy(addr.addr, &ba, 6);

	disc_nsvc = 99;
	disc_nchar = 99;

	ble_discover(ctx, &addr, disc_cb, NULL);
	mock_recv(dfd, cmd, sizeof(cmd));

	mock_send(dfd, "DISCOVER 11:22:33:44:55:66");
	mock_send(dfd, "END");
	ble_process(ctx);

	ATF_CHECK_EQ(disc_nsvc, 0);
	ATF_CHECK_EQ(disc_nchar, 0);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_discover_error);
ATF_TC_BODY(test_discover_error, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("11:22:33:44:55:66", &ba);
	memcpy(addr.addr, &ba, 6);

	disc_nsvc = 99;

	ble_discover(ctx, &addr, disc_cb, NULL);
	mock_recv(dfd, cmd, sizeof(cmd));

	mock_send(dfd, "ERROR device not connected");
	ble_process(ctx);

	/* Error callback should fire with zero results */
	ATF_CHECK_EQ(disc_nsvc, 0);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_discover_while_pending_rejected);
ATF_TC_BODY(test_discover_while_pending_rejected, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char tmp[256];

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));

	ATF_CHECK_EQ(ble_discover(ctx, &addr, disc_cb, NULL), 0);
	mock_recv(dfd, tmp, sizeof(tmp));
	ATF_CHECK_EQ(ble_discover(ctx, &addr, disc_cb, NULL), -1);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * ADD_SERVICE: verify handle return
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_add_service_returns_handle);
ATF_TC_BODY(test_add_service_returns_handle, tc)
{
	ble_ctx_t *ctx;
	ble_uuid_t uuid;
	uint16_t handle;
	int dfd;
	char cmd[256];

	ctx = make_mock_ctx(&dfd);
	memset(&uuid, 0, sizeof(uuid));
	uuid.uuid16 = 0xFFE0;
	handle = 0;

	ATF_CHECK_EQ(ble_add_service(ctx, &uuid, &handle), 0);
	mock_recv(dfd, cmd, sizeof(cmd));
	ATF_CHECK_MSG(strstr(cmd, "0xFFE0") != NULL, "uuid: %s", cmd);

	mock_send(dfd, "OK ADD_SERVICE handle=0x0020 uuid=0xFFE0");
	ble_process(ctx);

	ATF_CHECK_EQ(handle, 0x0020);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * ble_command() raw API
 * ================================================================ */
static int cmd_line_count;
static bool cmd_saw_terminal;
static int cmd_terminal_status;
static char cmd_lines[8][256];

static void
cmd_cb(const char *line, bool terminal, int status, void *arg __unused)
{
	if (cmd_line_count < 8)
		strlcpy(cmd_lines[cmd_line_count], line,
		    sizeof(cmd_lines[0]));
	cmd_line_count++;
	if (terminal) {
		cmd_saw_terminal = true;
		cmd_terminal_status = status;
	}
}

ATF_TC_WITHOUT_HEAD(test_command_oneshot_ok);
ATF_TC_BODY(test_command_oneshot_ok, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	char cmd[256];

	ctx = make_mock_ctx(&dfd);
	cmd_line_count = 0;
	cmd_saw_terminal = false;

	ble_command(ctx, "STATUS", cmd_cb, NULL, 0);
	mock_recv(dfd, cmd, sizeof(cmd));

	mock_send(dfd, "STATUS adapters=1 connections=0");
	ble_process(ctx);

	ATF_CHECK_EQ(cmd_line_count, 1);
	ATF_CHECK(cmd_saw_terminal);
	ATF_CHECK_EQ(cmd_terminal_status, 1);
	ATF_CHECK_MSG(strstr(cmd_lines[0], "adapters=1") != NULL,
	    "line: %s", cmd_lines[0]);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_command_multiline_content);
ATF_TC_BODY(test_command_multiline_content, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	char cmd[256];

	ctx = make_mock_ctx(&dfd);
	cmd_line_count = 0;

	ble_command(ctx, "LIST", cmd_cb, NULL, 0);
	mock_recv(dfd, cmd, sizeof(cmd));

	mock_send(dfd, "LIST");
	mock_send(dfd, "aa:bb:cc:dd:ee:ff state=2 handle=0040 role=central encrypted=1 authenticated=0 key_size=16 name=MyKeyboard");
	mock_send(dfd, "END");
	ble_process(ctx);

	ATF_CHECK_EQ(cmd_line_count, 3);
	ATF_CHECK_MSG(strstr(cmd_lines[0], "LIST") != NULL,
	    "line 0: %s", cmd_lines[0]);
	ATF_CHECK_MSG(strstr(cmd_lines[1], "role=central") != NULL,
	    "line 1: %s", cmd_lines[1]);
	ATF_CHECK_MSG(strstr(cmd_lines[1], "encrypted=1") != NULL,
	    "line 1 encrypted: %s", cmd_lines[1]);
	ATF_CHECK_MSG(strstr(cmd_lines[1], "name=MyKeyboard") != NULL,
	    "line 1 name: %s", cmd_lines[1]);
	ATF_CHECK_MSG(strcmp(cmd_lines[2], "END") == 0,
	    "line 2: %s", cmd_lines[2]);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_command_error_status);
ATF_TC_BODY(test_command_error_status, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	char cmd[256];

	ctx = make_mock_ctx(&dfd);
	cmd_line_count = 0;
	cmd_saw_terminal = false;
	cmd_terminal_status = 0;

	ble_command(ctx, "READ 11:22:33:44:55:66 0x9999", cmd_cb, NULL, 0);
	mock_recv(dfd, cmd, sizeof(cmd));

	mock_send(dfd, "ERROR device not connected");
	ble_process(ctx);

	ATF_CHECK_EQ(cmd_line_count, 1);
	ATF_CHECK(cmd_saw_terminal);
	ATF_CHECK_EQ(cmd_terminal_status, -1);
	ATF_CHECK_MSG(strstr(cmd_lines[0], "not connected") != NULL,
	    "error: %s", cmd_lines[0]);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_command_streaming);
ATF_TC_BODY(test_command_streaming, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	char cmd[256];

	ctx = make_mock_ctx(&dfd);
	cmd_line_count = 0;
	cmd_saw_terminal = false;

	/* Streaming: callback should NOT be cleared on terminal */
	ble_command(ctx, "SUBSCRIBE aa:bb:cc:dd:ee:ff 0x0025",
	    cmd_cb, NULL, BLE_CMD_STREAMING);
	mock_recv(dfd, cmd, sizeof(cmd));

	mock_send(dfd, "OK SUBSCRIBE 0x0025");
	ble_process(ctx);

	/* Terminal received, but streaming keeps callback alive */
	ATF_CHECK_EQ(cmd_line_count, 1);
	ATF_CHECK(cmd_saw_terminal);

	/* Send more data — should still be received */
	cmd_line_count = 0;
	mock_send(dfd, "EVENT NOTIFY aa:bb:cc:dd:ee:ff 0x0025 CAFE");
	ble_process(ctx);
	ATF_CHECK_EQ(cmd_line_count, 1);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * ble_on_line: unsolicited events
 * ================================================================ */
static int unsol_count;
static char unsol_line[256];

static void
unsol_cb(const char *line, bool terminal __unused, int status __unused,
    void *arg __unused)
{
	unsol_count++;
	strlcpy(unsol_line, line, sizeof(unsol_line));
}

ATF_TC_WITHOUT_HEAD(test_on_line_receives_events);
ATF_TC_BODY(test_on_line_receives_events, tc)
{
	ble_ctx_t *ctx;
	int dfd;

	ctx = make_mock_ctx(&dfd);
	unsol_count = 0;

	ble_on_line(ctx, unsol_cb, NULL);

	mock_send(dfd, "EVENT PASSKEY_DISPLAY aa:bb:cc:dd:ee:ff 123456");
	ble_process(ctx);

	ATF_CHECK_EQ(unsol_count, 1);
	ATF_CHECK_MSG(strstr(unsol_line, "PASSKEY_DISPLAY") != NULL,
	    "line: %s", unsol_line);
	ATF_CHECK_MSG(strstr(unsol_line, "123456") != NULL,
	    "passkey: %s", unsol_line);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * READ battery: verify DISCOVER+READ chain
 * ================================================================ */
static int bat_read_called;
static uint8_t bat_level;
static int bat_error;

static void
bat_cb(const ble_addr_t *addr __unused, uint16_t handle __unused,
    const uint8_t *value, uint16_t len, int error, void *arg __unused)
{
	bat_read_called = 1;
	bat_error = error;
	if (len > 0 && value != NULL)
		bat_level = value[0];
}

ATF_TC_WITHOUT_HEAD(test_read_battery_chain);
ATF_TC_BODY(test_read_battery_chain, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	bat_read_called = 0;
	bat_level = 0;

	ATF_CHECK_EQ(ble_read_battery(ctx, &addr, bat_cb, NULL), 0);

	/* Step 1: library sends DISCOVER */
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "DISCOVER") != NULL, "step1: %s", cmd);

	/* Mock: Battery Service with Battery Level char */
	mock_send(dfd, "DISCOVER aa:bb:cc:dd:ee:ff");
	mock_send(dfd, "  service uuid=0x180F handles=0x0020-0x0023");
	mock_send(dfd, "    char uuid=0x2A19 handle=0x0022 props=read");
	mock_send(dfd, "END");
	ble_process(ctx);

	/* Step 2: library sends READ for the resolved handle */
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "READ") != NULL, "step2: %s", cmd);
	ATF_CHECK_MSG(strstr(cmd, "0x0022") != NULL,
	    "wrong handle: %s", cmd);

	/* Mock: battery level = 85 (0x55) */
	mock_send(dfd, "OK READ 0x0022 len=1 value=55");
	ble_process(ctx);

	ATF_CHECK_EQ(bat_read_called, 1);
	ATF_CHECK_EQ(bat_error, 0);
	ATF_CHECK_EQ(bat_level, 0x55);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_read_battery_not_found);
ATF_TC_BODY(test_read_battery_not_found, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	bat_read_called = 0;
	bat_error = 0;

	ble_read_battery(ctx, &addr, bat_cb, NULL);
	mock_recv(dfd, cmd, sizeof(cmd));

	/* No Battery Service in discover results */
	mock_send(dfd, "DISCOVER aa:bb:cc:dd:ee:ff");
	mock_send(dfd, "  service uuid=0x1800 handles=0x0001-0x0005");
	mock_send(dfd, "    char uuid=0x2A00 handle=0x0003 props=read");
	mock_send(dfd, "END");
	ble_process(ctx);

	/* Should report error — no Battery Level char found */
	ATF_CHECK_EQ(bat_read_called, 1);
	ATF_CHECK_EQ(bat_error, -1);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * Connection lost
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_connection_lost);
ATF_TC_BODY(test_connection_lost, tc)
{
	ble_ctx_t *ctx;
	int dfd;

	ctx = make_mock_ctx(&dfd);
	close(dfd);
	ATF_CHECK_EQ(ble_process(ctx), -1);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_connection_lost_mid_command);
ATF_TC_BODY(test_connection_lost_mid_command, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	char cmd[256];

	ctx = make_mock_ctx(&dfd);
	cmd_line_count = 0;

	ble_command(ctx, "DISCOVER 11:22:33:44:55:66", cmd_cb, NULL, 0);
	mock_recv(dfd, cmd, sizeof(cmd));

	/* Send partial response then close */
	mock_send(dfd, "DISCOVER 11:22:33:44:55:66");
	ble_process(ctx);
	ATF_CHECK_EQ(cmd_line_count, 1);

	close(dfd);
	ATF_CHECK_EQ(ble_process(ctx), -1);

	ble_close(ctx);
}

/* ================================================================
 * ble_addr_str formatting
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_addr_str);
ATF_TC_BODY(test_addr_str, tc)
{
	ble_addr_t addr;
	char buf[18];
	bdaddr_t ba;

	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	ble_addr_str(&addr, buf);
	ATF_CHECK_MSG(strcasecmp(buf, "aa:bb:cc:dd:ee:ff") == 0,
	    "got: %s", buf);
}

/* ================================================================
 * SET_VALUE: verify hex encoding
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_set_value);
ATF_TC_BODY(test_set_value, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	char cmd[256];
	uint8_t val[] = { 0xCA, 0xFE };

	ctx = make_mock_ctx(&dfd);

	ATF_CHECK_EQ(ble_set_value(ctx, 0x000A, val, 2), 0);
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "SET_VALUE") != NULL, "cmd: %s", cmd);
	ATF_CHECK_MSG(strstr(cmd, "0x000A") != NULL, "handle: %s", cmd);
	ATF_CHECK_MSG(strstr(cmd, "CAFE") != NULL, "hex: %s", cmd);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * PASSKEY_REPLY: verify format
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_passkey_reply);
ATF_TC_BODY(test_passkey_reply, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	ATF_CHECK_EQ(ble_passkey_reply(ctx, &addr, 123456), 0);
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "PASSKEY_REPLY") != NULL, "cmd: %s", cmd);
	ATF_CHECK_MSG(strstr(cmd, "123456") != NULL, "passkey: %s", cmd);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * DISCONNECT: verify format
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_disconnect);
ATF_TC_BODY(test_disconnect, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("11:22:33:44:55:66", &ba);
	memcpy(addr.addr, &ba, 6);

	ATF_CHECK_EQ(ble_disconnect(ctx, &addr), 0);
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "DISCONNECT") != NULL, "cmd: %s", cmd);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * READ while pending rejected
 * ================================================================ */
static void
dummy_read_cb(const ble_addr_t *a __unused, uint16_t h __unused,
    const uint8_t *v __unused, uint16_t l __unused, int e __unused,
    void *arg __unused) {}

ATF_TC_WITHOUT_HEAD(test_read_while_pending_rejected);
ATF_TC_BODY(test_read_while_pending_rejected, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char tmp[256];

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));

	ATF_CHECK_EQ(ble_read(ctx, &addr, 0x0001, dummy_read_cb, NULL), 0);
	mock_recv(dfd, tmp, sizeof(tmp));
	ATF_CHECK_EQ(ble_read(ctx, &addr, 0x0002, dummy_read_cb, NULL), -1);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * UNSUBSCRIBE: verify format
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_unsubscribe);
ATF_TC_BODY(test_unsubscribe, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	ATF_CHECK_EQ(ble_unsubscribe(ctx, &addr, 0x0025), 0);
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "UNSUBSCRIBE") != NULL, "cmd: %s", cmd);
	ATF_CHECK_MSG(strstr(cmd, "0x0025") != NULL, "handle: %s", cmd);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * REMOVE_SERVICE: verify format
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_remove_service);
ATF_TC_BODY(test_remove_service, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	char cmd[256];

	ctx = make_mock_ctx(&dfd);

	ATF_CHECK_EQ(ble_remove_service(ctx, 0x0020), 0);
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "REMOVE_SERVICE") != NULL, "cmd: %s", cmd);
	ATF_CHECK_MSG(strstr(cmd, "0x0020") != NULL, "handle: %s", cmd);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * NUMCMP_REPLY: verify yes/no format
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_numcmp_reply_yes);
ATF_TC_BODY(test_numcmp_reply_yes, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	ATF_CHECK_EQ(ble_numcmp_reply(ctx, &addr, true), 0);
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "NUMCMP_REPLY") != NULL, "cmd: %s", cmd);
	ATF_CHECK_MSG(strstr(cmd, "yes") != NULL, "expected yes: %s", cmd);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_numcmp_reply_no);
ATF_TC_BODY(test_numcmp_reply_no, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	ATF_CHECK_EQ(ble_numcmp_reply(ctx, &addr, false), 0);
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "no") != NULL, "expected no: %s", cmd);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * EVENT WRITE: verify ble_on_write callback fires
 * ================================================================ */
static int write_req_count;
static uint16_t write_req_handle;
static uint8_t write_req_value[64];
static uint16_t write_req_len;

static void
write_req_cb(uint16_t handle, const uint8_t *value, uint16_t len,
    void *arg __unused)
{
	write_req_count++;
	write_req_handle = handle;
	if (len <= sizeof(write_req_value)) {
		memcpy(write_req_value, value, len);
		write_req_len = len;
	}
}

ATF_TC_WITHOUT_HEAD(test_on_write_event);
ATF_TC_BODY(test_on_write_event, tc)
{
	ble_ctx_t *ctx;
	int dfd;

	ctx = make_mock_ctx(&dfd);
	write_req_count = 0;

	ble_on_write(ctx, write_req_cb, NULL);

	mock_send(dfd, "EVENT WRITE 0x000A BEEF");
	ble_process(ctx);

	ATF_CHECK_EQ(write_req_count, 1);
	ATF_CHECK_EQ(write_req_handle, 0x000A);
	ATF_CHECK_EQ(write_req_len, 2);
	ATF_CHECK_EQ(write_req_value[0], 0xBE);
	ATF_CHECK_EQ(write_req_value[1], 0xEF);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * Pairing event callbacks
 * ================================================================ */
static int passkey_display_count;
static uint32_t passkey_display_value;

static void
passkey_display_cb(const ble_addr_t *addr __unused, uint32_t passkey,
    void *arg __unused)
{
	passkey_display_count++;
	passkey_display_value = passkey;
}

ATF_TC_WITHOUT_HEAD(test_passkey_display_event);
ATF_TC_BODY(test_passkey_display_event, tc)
{
	ble_ctx_t *ctx;
	int dfd;

	ctx = make_mock_ctx(&dfd);
	passkey_display_count = 0;

	ble_on_passkey_display(ctx, passkey_display_cb, NULL);

	mock_send(dfd, "EVENT PASSKEY_DISPLAY aa:bb:cc:dd:ee:ff 042069");
	ble_process(ctx);

	ATF_CHECK_EQ(passkey_display_count, 1);
	ATF_CHECK_EQ(passkey_display_value, 42069);

	close(dfd);
	ble_close(ctx);
}

static int passkey_input_count;

static void
passkey_input_cb(const ble_addr_t *addr __unused, void *arg __unused)
{
	passkey_input_count++;
}

ATF_TC_WITHOUT_HEAD(test_passkey_input_event);
ATF_TC_BODY(test_passkey_input_event, tc)
{
	ble_ctx_t *ctx;
	int dfd;

	ctx = make_mock_ctx(&dfd);
	passkey_input_count = 0;

	ble_on_passkey_input(ctx, passkey_input_cb, NULL);

	mock_send(dfd, "EVENT PASSKEY_INPUT aa:bb:cc:dd:ee:ff");
	ble_process(ctx);

	ATF_CHECK_EQ(passkey_input_count, 1);

	close(dfd);
	ble_close(ctx);
}

static int numcmp_event_count;
static uint32_t numcmp_event_value;

static void
numcmp_event_cb(const ble_addr_t *addr __unused, uint32_t value,
    void *arg __unused)
{
	numcmp_event_count++;
	numcmp_event_value = value;
}

ATF_TC_WITHOUT_HEAD(test_numcmp_request_event);
ATF_TC_BODY(test_numcmp_request_event, tc)
{
	ble_ctx_t *ctx;
	int dfd;

	ctx = make_mock_ctx(&dfd);
	numcmp_event_count = 0;

	ble_on_numcmp(ctx, numcmp_event_cb, NULL);

	mock_send(dfd, "EVENT NUMCMP_REQUEST aa:bb:cc:dd:ee:ff 987654");
	ble_process(ctx);

	ATF_CHECK_EQ(numcmp_event_count, 1);
	ATF_CHECK_EQ(numcmp_event_value, 987654);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * ADD_CHAR with value: verify hex encoding
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_add_char_with_value);
ATF_TC_BODY(test_add_char_with_value, tc)
{
	ble_ctx_t *ctx;
	ble_uuid_t uuid;
	int dfd;
	char cmd[256];
	uint8_t val[] = { 0x48, 0x65, 0x6C };  /* "Hel" */

	ctx = make_mock_ctx(&dfd);
	memset(&uuid, 0, sizeof(uuid));
	uuid.uuid16 = 0xFFE1;

	ATF_CHECK_EQ(ble_add_characteristic(ctx, 0x0020, &uuid,
	    BLE_PROP_READ | BLE_PROP_WRITE, BLE_PERM_READ | BLE_PERM_WRITE,
	    val, 3, NULL), 0);
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "ADD_CHAR") != NULL, "cmd: %s", cmd);
	ATF_CHECK_MSG(strstr(cmd, "0xFFE1") != NULL, "uuid: %s", cmd);
	ATF_CHECK_MSG(strstr(cmd, "48656C") != NULL, "value hex: %s", cmd);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * Partial line buffering: data arrives without trailing \n
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_partial_line_buffering);
ATF_TC_BODY(test_partial_line_buffering, tc)
{
	ble_ctx_t *ctx;
	int dfd;

	ctx = make_mock_ctx(&dfd);
	cmd_line_count = 0;
	cmd_saw_terminal = false;

	ble_command(ctx, "STATUS", cmd_cb, NULL, 0);
	{
		char tmp[256];
		mock_recv(dfd, tmp, sizeof(tmp));
	}

	/* Send partial data (no newline) */
	ATF_REQUIRE(send(dfd, "STATUS adapters=", 16, 0) == 16);
	ble_process(ctx);
	ATF_CHECK_EQ(cmd_line_count, 0);  /* no complete line yet */

	/* Send the rest */
	ATF_REQUIRE(send(dfd, "1 connections=0\n", 16, 0) == 16);
	ble_process(ctx);
	ATF_CHECK_EQ(cmd_line_count, 1);
	ATF_CHECK(cmd_saw_terminal);
	ATF_CHECK_MSG(strstr(cmd_lines[0], "adapters=1") != NULL,
	    "reassembled: %s", cmd_lines[0]);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * ERROR dispatch to connect_cb
 * ================================================================ */
static int connect_error_code;
static int connect_cb_called;

static void
connect_err_cb(const ble_addr_t *addr __unused, int error, void *arg __unused)
{
	connect_cb_called = 1;
	connect_error_code = error;
}

ATF_TC_WITHOUT_HEAD(test_error_dispatches_to_connect_cb);
ATF_TC_BODY(test_error_dispatches_to_connect_cb, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char tmp[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	connect_cb_called = 0;
	connect_error_code = 0;

	ble_connect(ctx, &addr, connect_err_cb, NULL);
	mock_recv(dfd, tmp, sizeof(tmp));

	mock_send(dfd, "ERROR already connected");
	ble_process(ctx);

	ATF_CHECK_EQ(connect_cb_called, 1);
	ATF_CHECK_EQ(connect_error_code, -1);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * ERROR dispatch to read_cb
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_error_dispatches_to_read_cb);
ATF_TC_BODY(test_error_dispatches_to_read_cb, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char tmp[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	bat_read_called = 0;
	bat_error = 0;

	ble_read(ctx, &addr, 0x0003, bat_cb, NULL);
	mock_recv(dfd, tmp, sizeof(tmp));

	mock_send(dfd, "ERROR read failed");
	ble_process(ctx);

	ATF_CHECK_EQ(bat_read_called, 1);
	ATF_CHECK_EQ(bat_error, -1);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * Passkey boundary: 0 (min) and 999999 (max)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_passkey_boundary_zero);
ATF_TC_BODY(test_passkey_boundary_zero, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	ATF_CHECK_EQ(ble_passkey_reply(ctx, &addr, 0), 0);
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, " 0") != NULL, "passkey 0: %s", cmd);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_passkey_boundary_max);
ATF_TC_BODY(test_passkey_boundary_max, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	ATF_CHECK_EQ(ble_passkey_reply(ctx, &addr, 999999), 0);
	ATF_REQUIRE(mock_recv(dfd, cmd, sizeof(cmd)) > 0);
	ATF_CHECK_MSG(strstr(cmd, "999999") != NULL,
	    "passkey max: %s", cmd);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * Discover with properties: verify all property flags parse
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_discover_all_properties);
ATF_TC_BODY(test_discover_all_properties, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char cmd[256];
	bdaddr_t ba;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	bt_aton("AA:BB:CC:DD:EE:FF", &ba);
	memcpy(addr.addr, &ba, 6);

	disc_nsvc = 0;
	disc_nchar = 0;

	ble_discover(ctx, &addr, disc_cb, NULL);
	mock_recv(dfd, cmd, sizeof(cmd));

	mock_send(dfd, "DISCOVER aa:bb:cc:dd:ee:ff");
	mock_send(dfd, "  service uuid=0xFFE0 handles=0x0010-0x0020");
	mock_send(dfd, "    char uuid=0xFFE1 handle=0x0012 props=read|write|notify|indicate|write_no_rsp|broadcast|auth_signed");
	mock_send(dfd, "END");
	ble_process(ctx);

	ATF_CHECK_EQ(disc_nchar, 1);
	ATF_CHECK_EQ(disc_chars[0].properties & BLE_PROP_READ, BLE_PROP_READ);
	ATF_CHECK_EQ(disc_chars[0].properties & BLE_PROP_WRITE, BLE_PROP_WRITE);
	ATF_CHECK_EQ(disc_chars[0].properties & BLE_PROP_NOTIFY, BLE_PROP_NOTIFY);
	ATF_CHECK_EQ(disc_chars[0].properties & BLE_PROP_INDICATE, BLE_PROP_INDICATE);
	ATF_CHECK_EQ(disc_chars[0].properties & BLE_PROP_WRITE_NO_RSP, BLE_PROP_WRITE_NO_RSP);
	ATF_CHECK_EQ(disc_chars[0].properties & BLE_PROP_BROADCAST, BLE_PROP_BROADCAST);
	ATF_CHECK_EQ(disc_chars[0].properties & BLE_PROP_AUTH_SIGNED_WRITE, BLE_PROP_AUTH_SIGNED_WRITE);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* Scan */
	ATF_TP_ADD_TC(tp, test_scan_parses_fields);
	ATF_TP_ADD_TC(tp, test_scan_public_addr_type);
	ATF_TP_ADD_TC(tp, test_scan_while_pending_rejected);

	/* Connect */
	ATF_TP_ADD_TC(tp, test_connect_random);
	ATF_TP_ADD_TC(tp, test_connect_while_pending_rejected);
	ATF_TP_ADD_TC(tp, test_connect_name);

	/* Write */
	ATF_TP_ADD_TC(tp, test_write_hex_encoding);

	/* Notify */
	ATF_TP_ADD_TC(tp, test_notify_parses_handle_and_value);
	ATF_TP_ADD_TC(tp, test_notify_empty_value);

	/* Discover */
	ATF_TP_ADD_TC(tp, test_discover_parses_service_and_char);
	ATF_TP_ADD_TC(tp, test_discover_empty);
	ATF_TP_ADD_TC(tp, test_discover_error);
	ATF_TP_ADD_TC(tp, test_discover_while_pending_rejected);

	/* Add service */
	ATF_TP_ADD_TC(tp, test_add_service_returns_handle);

	/* Raw command API */
	ATF_TP_ADD_TC(tp, test_command_oneshot_ok);
	ATF_TP_ADD_TC(tp, test_command_multiline_content);
	ATF_TP_ADD_TC(tp, test_command_error_status);
	ATF_TP_ADD_TC(tp, test_command_streaming);

	/* Unsolicited events */
	ATF_TP_ADD_TC(tp, test_on_line_receives_events);

	/* Battery (DISCOVER+READ chain) */
	ATF_TP_ADD_TC(tp, test_read_battery_chain);
	ATF_TP_ADD_TC(tp, test_read_battery_not_found);

	/* Error handling */
	ATF_TP_ADD_TC(tp, test_connection_lost);
	ATF_TP_ADD_TC(tp, test_connection_lost_mid_command);
	ATF_TP_ADD_TC(tp, test_read_while_pending_rejected);

	/* Utilities */
	ATF_TP_ADD_TC(tp, test_addr_str);
	ATF_TP_ADD_TC(tp, test_set_value);
	ATF_TP_ADD_TC(tp, test_passkey_reply);
	ATF_TP_ADD_TC(tp, test_disconnect);
	ATF_TP_ADD_TC(tp, test_unsubscribe);
	ATF_TP_ADD_TC(tp, test_remove_service);

	/* Numeric comparison */
	ATF_TP_ADD_TC(tp, test_numcmp_reply_yes);
	ATF_TP_ADD_TC(tp, test_numcmp_reply_no);

	/* EVENT WRITE */
	ATF_TP_ADD_TC(tp, test_on_write_event);

	/* Pairing event callbacks */
	ATF_TP_ADD_TC(tp, test_passkey_display_event);
	ATF_TP_ADD_TC(tp, test_passkey_input_event);
	ATF_TP_ADD_TC(tp, test_numcmp_request_event);

	/* ADD_CHAR with value */
	ATF_TP_ADD_TC(tp, test_add_char_with_value);

	/* Partial line buffering */
	ATF_TP_ADD_TC(tp, test_partial_line_buffering);

	/* Error dispatch */
	ATF_TP_ADD_TC(tp, test_error_dispatches_to_connect_cb);
	ATF_TP_ADD_TC(tp, test_error_dispatches_to_read_cb);

	/* Passkey boundaries */
	ATF_TP_ADD_TC(tp, test_passkey_boundary_zero);
	ATF_TP_ADD_TC(tp, test_passkey_boundary_max);

	/* Property parsing */
	ATF_TP_ADD_TC(tp, test_discover_all_properties);

	return (atf_no_error());
}
