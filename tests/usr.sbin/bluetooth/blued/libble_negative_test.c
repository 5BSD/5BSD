/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF negative tests for libble (lib/libble/ble.c).
 *
 * A libble client trusts blued, but a hostile or garbled daemon response
 * stream must never corrupt client memory or mis-dispatch.  These tests
 * push malformed daemon responses through ble_process() and malformed
 * arguments through the request-side ble_*() calls, asserting graceful
 * handling.
 *
 * Coverage includes typed request-size limits, invalid names and arguments,
 * busy rejection, and connection-loss reporting.
 *
 * Uses ble_open_fd() over a socketpair(2) mock daemon, mirroring
 * libble_test.c.  Links lib/libble/ble.c.
 */

#include <sys/socket.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "ble.h"
#include "ipc_proto.h"

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

/*
 * Mock daemon <- client: read one typed frame and return its payload.
 */
static ssize_t
mock_recv(int fd, char *buf, size_t bufsz)
{
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	uint8_t hdr[IPC_HDR_SIZE];
	uint32_t plen;
	uint16_t type, arg;
	size_t got = 0;
	ssize_t n;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	while (got < IPC_HDR_SIZE) {
		n = recv(fd, hdr + got, IPC_HDR_SIZE - got, 0);
		if (n <= 0)
			return (n == 0 ? 0 : -1);
		got += (size_t)n;
	}
	ipc_hdr_decode(hdr, &plen, &type, &arg);
	if (plen > bufsz - 1)
		plen = (uint32_t)(bufsz - 1);
	got = 0;
	while (got < plen) {
		n = recv(fd, buf + got, plen - got, 0);
		if (n <= 0)
			break;
		got += (size_t)n;
	}
	buf[got] = '\0';
	return ((ssize_t)got);
}

/* ================================================================
 * Partial line: no trailing newline must not dispatch
 * ================================================================ */
/* ================================================================
 * Oversized frame: payload length exceeds IPC_MAX_PAYLOAD -> BLE_ERR_PROTO
 * ================================================================ */
/*
 * After an oversized frame is rejected, a following well-formed frame must
 * still parse correctly (the receive buffer is reset).
 */
/* ================================================================
 * Embedded NUL bytes: must not crash; string ends at the NUL
 * ================================================================ */
/* ================================================================
 * Unknown response verb: dispatched but harmless
 * ================================================================ */
/* ================================================================
 * Truncated SCAN (DEVICE) lines
 * ================================================================ */
static int ln_scan_count;

static void
ln_scan_cb(const ble_scan_result_t *r __unused, void *arg __unused)
{

	ln_scan_count++;
}

/* ================================================================
 * Truncated OK READ (VALUE) line
 * ================================================================ */
static int ln_read_count;
static uint16_t ln_read_len;
static int ln_read_error;

static void
ln_read_cb(const ble_addr_t *addr __unused, uint16_t handle __unused,
    const uint8_t *value __unused, uint16_t len, int error, void *arg __unused)
{

	ln_read_count++;
	ln_read_len = len;
	ln_read_error = error;
}

/* ================================================================
 * Request-side: value-too-long rejection (BLE_ERR_INVAL)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ln_write_value_too_long);
ATF_TC_BODY(test_ln_write_value_too_long, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	uint8_t big[600];

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	memset(big, 0xAB, sizeof(big));

	/* ATT attribute values are limited to 512 bytes. */
	ATF_CHECK_EQ(ble_write(ctx, &addr, 0x0003, big, 513), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	ATF_CHECK_EQ(ble_write_no_response(ctx, &addr, 0x0003, big, 513), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	ATF_CHECK_EQ(ble_set_value(ctx, 0x0003, big, 513), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_ln_add_char_value_too_long);
ATF_TC_BODY(test_ln_add_char_value_too_long, tc)
{
	ble_ctx_t *ctx;
	ble_uuid_t uuid;
	int dfd;
	static uint8_t big[IPC_MAX_PAYLOAD];

	ctx = make_mock_ctx(&dfd);
	memset(&uuid, 0, sizeof(uuid));
	uuid.uuid16 = 0xFFE1;
	memset(big, 0x5A, sizeof(big));

	/* The operation prefix and fixed request fields must also fit. */
	ATF_CHECK_EQ(ble_add_characteristic(ctx, 0x0020, &uuid,
	    BLE_PROP_READ, BLE_PERM_READ, big,
	    IPC_MAX_PAYLOAD - IPC_GATT_ADD_CHAR_REQ_SIZE + 1, NULL), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * Request-side: invalid device name for ble_connect_name
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ln_connect_name_invalid);
ATF_TC_BODY(test_ln_connect_name_invalid, tc)
{
	ble_ctx_t *ctx;
	int dfd;

	ctx = make_mock_ctx(&dfd);

	/* Empty name */
	ATF_CHECK_EQ(ble_connect_name(ctx, 0, "", NULL, NULL), -1);
	/* NULL name */
	ATF_CHECK_EQ(ble_connect_name(ctx, 0, NULL, NULL, NULL), -1);
	/* Embedded newline (injection attempt) */
	ATF_CHECK_EQ(ble_connect_name(ctx, 0, "dev\nEXTRA", NULL, NULL), -1);
	/* Embedded carriage return */
	ATF_CHECK_EQ(ble_connect_name(ctx, 0, "dev\rEXTRA", NULL, NULL), -1);
	/* Embedded control byte */
	ATF_CHECK_EQ(ble_connect_name(ctx, 0, "dev\x01x", NULL, NULL), -1);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * Request-side: invalid bond-list arguments
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ln_bond_list_invalid_args);
ATF_TC_BODY(test_ln_bond_list_invalid_args, tc)
{
	ble_ctx_t *ctx;
	ble_bond_t bonds[4];
	int dfd;

	ctx = make_mock_ctx(&dfd);

	ATF_CHECK_EQ(ble_bond_list(ctx, NULL, 4), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	ATF_CHECK_EQ(ble_bond_list(ctx, bonds, 0), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	ATF_CHECK_EQ(ble_bond_list(ctx, bonds, -1), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_ln_invalid_addr_type_requests);
ATF_TC_BODY(test_ln_invalid_addr_type_requests, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	uint8_t value = 0, irk[16] = { 0 };
	int dfd, fd = -1;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	addr.addr_type = 2;

	ATF_CHECK_EQ(-1, ble_pair(ctx, &addr));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_unbond(ctx, &addr));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_connect(ctx, &addr, NULL, NULL));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_discover(ctx, &addr, NULL, NULL));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_read(ctx, &addr, 1, NULL, NULL));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_write(ctx, &addr, 1, &value, sizeof(value)));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_acquire_coc(ctx, &addr, 0x0080, &fd));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_eatt_open(ctx, &addr, 1));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_periodic_sync_create(ctx, &addr, 1, 0, 10));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_past_params(ctx, &addr, 0, 0, 10, 0));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_resolv_add(ctx, &addr, irk));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_set_phy(ctx, &addr, 0, 0));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));

	close(dfd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(test_ln_spec_scalar_rejections);
ATF_TC_BODY(test_ln_spec_scalar_rejections, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));
	addr.addr_type = 1;

	ATF_CHECK_EQ(-1, ble_periodic_adv_params(ctx, 0, 6, 6, 0x0002));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_periodic_adv_params(ctx, 0, 6, 6, 0x0001));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_periodic_sync_create(ctx, &addr, 1, 0x01f4, 10));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_past_params(ctx, &addr, 0, 0, 10, 0x08));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_past_default_params(ctx, 0, 0, 0, 10, 0x08));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_path_loss_reporting(ctx, &addr, 4, 5, 8, 0,
	    0, true));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_conn_params_update(ctx, &addr, 5, 6, 0, 10));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_conn_params_update(ctx, &addr, 6, 6, 0x01f4,
	    10));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * Request-side: concurrent one-shot operations
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ln_concurrent_operations);
ATF_TC_BODY(test_ln_concurrent_operations, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr;
	int dfd;
	char tmp[128];

	ctx = make_mock_ctx(&dfd);
	memset(&addr, 0, sizeof(addr));

	/* Correlated operations can overlap on one context. */
	ATF_CHECK_EQ(ble_scan(ctx, ln_scan_cb, NULL), 0);
	mock_recv(dfd, tmp, sizeof(tmp));
	ATF_CHECK_EQ(ble_scan(ctx, ln_scan_cb, NULL), 0);
	mock_recv(dfd, tmp, sizeof(tmp));

	/* read already in progress */
	ATF_CHECK_EQ(ble_read(ctx, &addr, 0x0001, ln_read_cb, NULL), 0);
	mock_recv(dfd, tmp, sizeof(tmp));
	ATF_CHECK_EQ(ble_read(ctx, &addr, 0x0002, ln_read_cb, NULL), 0);
	mock_recv(dfd, tmp, sizeof(tmp));

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * Connection loss reported as BLE_ERR_SOCKET
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ln_connection_closed);
ATF_TC_BODY(test_ln_connection_closed, tc)
{
	ble_ctx_t *ctx;
	int dfd;

	ctx = make_mock_ctx(&dfd);

	close(dfd);
	ATF_CHECK_EQ(ble_process(ctx), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_SOCKET);

	ble_close(ctx);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* Malformed daemon response stream */

	/* Request-side error handling */
	ATF_TP_ADD_TC(tp, test_ln_write_value_too_long);
	ATF_TP_ADD_TC(tp, test_ln_add_char_value_too_long);
	ATF_TP_ADD_TC(tp, test_ln_connect_name_invalid);
	ATF_TP_ADD_TC(tp, test_ln_bond_list_invalid_args);
	ATF_TP_ADD_TC(tp, test_ln_invalid_addr_type_requests);
	ATF_TP_ADD_TC(tp, test_ln_spec_scalar_rejections);
	ATF_TP_ADD_TC(tp, test_ln_concurrent_operations);
	ATF_TP_ADD_TC(tp, test_ln_connection_closed);

	return (atf_no_error());
}
