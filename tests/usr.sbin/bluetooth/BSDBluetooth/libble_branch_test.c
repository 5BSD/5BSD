/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/* Protocol-independent branch tests for libble lifecycle and I/O failures. */

#include <sys/socket.h>

#include <atf-c.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "ble.h"

ATF_TC_WITHOUT_HEAD(branch_lifecycle_misc);
ATF_TC_BODY(branch_lifecycle_misc, tc)
{
	ble_ctx_t *ctx;

	ble_close(NULL);

	ctx = ble_open_fd(-1);
	ATF_REQUIRE(ctx != NULL);
	ATF_CHECK_EQ(ble_fd(ctx), -1);
	ATF_CHECK_EQ(ble_get_mtu(ctx), 0);
	ATF_CHECK(!ble_is_connected(ctx));
	ble_close(ctx);

	ctx = ble_open(NULL);
	if (ctx != NULL)
		ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(branch_process_recv_error);
ATF_TC_BODY(branch_process_recv_error, tc)
{
	ble_ctx_t *ctx;
	int fd;

	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	ctx = ble_open_fd(fd);
	ATF_REQUIRE(ctx != NULL);

	ATF_CHECK_EQ(ble_process(ctx), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_SOCKET);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(branch_bond_list_send_fail);
ATF_TC_BODY(branch_bond_list_send_fail, tc)
{
	ble_bond_t bonds[4];
	ble_ctx_t *ctx;
	int sp[2];

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	(void)close(sp[0]);
	(void)close(sp[1]);

	memset(bonds, 0, sizeof(bonds));
	ATF_CHECK_EQ(ble_bond_list(ctx, bonds, 4), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_SOCKET);
	ble_close(ctx);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, branch_lifecycle_misc);
	ATF_TP_ADD_TC(tp, branch_process_recv_error);
	ATF_TP_ADD_TC(tp, branch_bond_list_send_fail);

	return (atf_no_error());
}
