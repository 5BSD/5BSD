/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Regression guards for recently fixed libble (lib/libble/ble.c) bugs.
 * One focused case per finding so a re-break is caught.
 *
 * Covers the typed request-side attribute-value limit for local and remote
 * writes.  The Bluetooth maximum is accepted and a larger value is rejected
 * with BLE_ERR_INVAL.
 *
 * The adv_data.c adv_name2str over-read guard needs the hccontrol link
 * set (adv_data.c + hci_manufacturer2str stub, -I hccontrol) which does
 * not combine with the libble link set; it lives in adv_regression_test.c.
 */

#include <sys/socket.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ble.h"
#include "ipc_proto.h"

static ble_ctx_t *
open_pair(int *daemon_fd)
{
	int sp[2];
	ble_ctx_t *ctx;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	*daemon_fd = sp[1];
	return (ctx);
}

/* Local value boundary. */
ATF_TC_WITHOUT_HEAD(test_set_value_too_long);
ATF_TC_BODY(test_set_value_too_long, tc)
{
	int dfd;
	ble_ctx_t *ctx = open_pair(&dfd);
	uint8_t big[513];

	memset(big, 0xAB, sizeof(big));
	ATF_CHECK_EQ(ble_set_value(ctx, 0x000A, big, sizeof(big)), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	close(dfd);
	ble_close(ctx);
}

/* A value that fits must still succeed (send goes to the socketpair). */
ATF_TC_WITHOUT_HEAD(test_set_value_ok);
ATF_TC_BODY(test_set_value_ok, tc)
{
	int dfd;
	ble_ctx_t *ctx = open_pair(&dfd);
	uint8_t val[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

	ATF_CHECK_EQ(ble_set_value(ctx, 0x000A, val, sizeof(val)), 0);
	ATF_CHECK(ble_errno(ctx) != BLE_ERR_INVAL);

	close(dfd);
	ble_close(ctx);
}

/* Remote write boundary. */
ATF_TC_WITHOUT_HEAD(test_write_too_long);
ATF_TC_BODY(test_write_too_long, tc)
{
	int dfd;
	ble_ctx_t *ctx = open_pair(&dfd);
	ble_addr_t addr;
	uint8_t big[513];

	memset(&addr, 0, sizeof(addr));
	memset(big, 0x11, sizeof(big));

	ATF_CHECK_EQ(ble_write(ctx, &addr, 0x0025, big, sizeof(big)), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	close(dfd);
	ble_close(ctx);
}

/* A short write must succeed and not report INVAL. */
ATF_TC_WITHOUT_HEAD(test_write_ok);
ATF_TC_BODY(test_write_ok, tc)
{
	int dfd;
	ble_ctx_t *ctx = open_pair(&dfd);
	ble_addr_t addr;
	uint8_t val[4] = { 0x01, 0x02, 0x03, 0x04 };

	memset(&addr, 0, sizeof(addr));
	ATF_CHECK_EQ(ble_write(ctx, &addr, 0x0025, val, sizeof(val)), 0);
	ATF_CHECK(ble_errno(ctx) != BLE_ERR_INVAL);

	close(dfd);
	ble_close(ctx);
}

/* ================================================================
 * Registration
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_set_value_too_long);
	ATF_TP_ADD_TC(tp, test_set_value_ok);
	ATF_TP_ADD_TC(tp, test_write_too_long);
	ATF_TP_ADD_TC(tp, test_write_ok);

	return (atf_no_error());
}
