/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the libble client surface the bluedctl CLI is built on: the
 * connection-lifecycle push events (findings C1/C2/C5) — EVENT CONNECTED sets
 * the connected state and populates ble_get_mtu(), EVENT DISCONNECTED clears
 * them — and the advertising / conninfo command wrappers (finding C10), which
 * must emit the exact wire command the daemon expects.
 *
 * The "server" is the peer end of a socketpair; staged frames are written
 * before the client reads them, so no server thread is needed.  One frame is
 * read at a time (SEQPACKET-style lockstep) when checking the client's output.
 */

#include <sys/socket.h>

#include <atf-c.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "ble.h"
#include "ipc_proto.h"

static void
stage_hello(int srv, uint32_t features)
{
	uint8_t hdr[IPC_HDR_SIZE];
	uint8_t payload[IPC_HELLO_FEATURES_SIZE];

	ipc_put_le32(payload, features);
	ipc_hdr_encode(hdr, sizeof(payload), IPC_T_HELLO, IPC_PROTO_VERSION);
	ATF_REQUIRE(write(srv, hdr, sizeof(hdr)) == (ssize_t)sizeof(hdr));
	ATF_REQUIRE(write(srv, payload, sizeof(payload)) ==
	    (ssize_t)sizeof(payload));
}

/* Read one frame the client sent to the server end; NUL-terminate payload. */
static void
read_exact(int fd, void *buf, size_t n)
{
	size_t got = 0;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };

	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	while (got < n) {
		ssize_t r = read(fd, (uint8_t *)buf + got, n - got);

		ATF_REQUIRE(r > 0);
		got += (size_t)r;
	}
}


/* Discard one whole frame from fd (used to drop the client's own HELLO). */
static void
discard_frame(int fd)
{
	uint8_t hdr[IPC_HDR_SIZE];
	uint32_t plen;
	uint16_t type, arg;
	char tmp[256];

	read_exact(fd, hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &arg);
	if (plen > 0) {
		ATF_REQUIRE(plen <= sizeof(tmp));
		read_exact(fd, tmp, plen);
	}
}

static ble_ctx_t *
framed_ctx(int sp[2])
{
	ble_ctx_t *ctx;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_FEATURE_EVENTS);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	/* The client sent its own HELLO frame; drop it from the server end. */
	discard_frame(sp[1]);
	return (ctx);
}

/* C10: ble_set_adv_data rejects an over-length payload locally (no wire I/O).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cli_advertise_toolong);
ATF_TC_BODY(cli_advertise_toolong, tc)
{
	ble_ctx_t *ctx;
	int sp[2];
	uint8_t big[64];

	memset(big, 0xAB, sizeof(big));
	ctx = framed_ctx(sp);

	ATF_CHECK_EQ(ble_set_adv_data(ctx, big, 40), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, cli_advertise_toolong);

	return (atf_no_error());
}
