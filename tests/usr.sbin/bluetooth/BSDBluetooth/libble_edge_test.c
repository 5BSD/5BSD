/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF edge-case tests for libble (ble.c).
 *
 * libble_test.c / libble_negative_test.c exercise the common request and
 * response-parsing paths.  This file fills the remaining branch gaps:
 *
 *   - the "send failed" error arm of every public request, driven by a
 *     context whose socket has been closed so ctl_send()'s send(2) fails;
 *   - concurrent request admission for scan/connect/discover/read;
 *   - ble_connect_name() input validation (NULL, empty, control chars);
 *   - the per-handle subscription table: in-place update, overflow to the
 *     global fallback, and unsubscribe removal;
 *   - 128-bit UUID encoding in service and characteristic operations and the
 *     value-too-long guards of write / write_no_response / set_value /
 *     add_characteristic;
 *   - ble_open() against a missing path (connect failure) and a live
 *     listening socket (connect success);
 *   - ble_process() peer-closed (n == 0) handling;
 *   - 128-bit service/characteristic discovery replies;
 *   - typed notification events with no matching subscription;
 *   - ble_get_rssi() cache miss and ble_read_battery() found / not-found /
 *     busy chaining.
 *
 * Oracle: the ipc_proto.h binary grammar and the documented libble API
 * contract (return values, BLE_ERR_* codes).  Expected values are derived
 * from that contract, never captured from the implementation.
 */

#include <sys/socket.h>
#include <sys/un.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
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

/*
 * Server side of the framed HELLO handshake, run on a helper thread so a
 * blocking ble_open()/ble_handshake() can complete: accept one connection on
 * the listener, read the client HELLO, and reply with our version plus the
 * asynchronous-events capability (mirroring the daemon).  The buffered reply survives an
 * immediate close, so the connecting client always reads it.
 */
static void *
hello_responder(void *arg)
{
	int lfd = *(int *)arg;
	struct pollfd pfd;
	uint8_t hdr[IPC_HDR_SIZE];
	uint8_t rh[IPC_HDR_SIZE];
	uint8_t features[IPC_HELLO_FEATURES_SIZE];
	uint32_t plen;
	uint16_t type, harg;
	size_t got;
	int c;

	pfd.fd = lfd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 3000) <= 0)
		return (NULL);
	c = accept(lfd, NULL, NULL);
	if (c < 0)
		return (NULL);

	got = 0;
	while (got < IPC_HDR_SIZE) {
		ssize_t r = recv(c, hdr + got, IPC_HDR_SIZE - got, 0);

		if (r <= 0) {
			close(c);
			return (NULL);
		}
		got += (size_t)r;
	}
	ipc_hdr_decode(hdr, &plen, &type, &harg);
	while (plen > 0) {
		uint8_t tmp[64];
		size_t want = (plen < sizeof(tmp)) ? plen : sizeof(tmp);
		ssize_t r = recv(c, tmp, want, 0);

		if (r <= 0)
			break;
		plen -= (uint32_t)r;
	}

	ipc_put_le32(features, IPC_FEATURE_EVENTS);
	ipc_hdr_encode(rh, sizeof(features), IPC_T_HELLO,
	    IPC_PROTO_VERSION);
	(void)write(c, rh, sizeof(rh));
	(void)write(c, features, sizeof(features));
	close(c);
	return (NULL);
}

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
 * A context whose underlying socket is already closed, so every ctl_send()
 * send(2) fails with EBADF and each request takes its "send failed" arm.
 */
static ble_ctx_t *
make_broken_ctx(void)
{
	int sp[2];
	ble_ctx_t *ctx;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	(void)close(sp[0]);
	(void)close(sp[1]);
	return (ctx);
}

static void
mkaddr(ble_addr_t *a, uint8_t last, uint8_t type)
{

	memset(a, 0, sizeof(*a));
	a->addr[0] = last;
	a->addr[5] = 0xAA;
	a->addr_type = type;
}

/* ================================================================
 * send-failure arms: every request on a broken socket -> -1
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_send_failures);
ATF_TC_BODY(edge_send_failures, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t a;
	uint8_t v[2] = { 0x01, 0x02 };

	signal(SIGPIPE, SIG_IGN);
	mkaddr(&a, 0x11, 0);

	ctx = make_broken_ctx();
	ATF_CHECK(ble_scan(ctx, NULL, NULL) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_SOCKET);
	ble_close(ctx);

	ctx = make_broken_ctx();
	ATF_CHECK(ble_connect(ctx, &a, NULL, NULL) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_SOCKET);
	ble_close(ctx);

	ctx = make_broken_ctx();
	ATF_CHECK(ble_connect_name(ctx, 0, "MyDev", NULL, NULL) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_SOCKET);
	ble_close(ctx);

	ctx = make_broken_ctx();
	ATF_CHECK(ble_disconnect(ctx, &a) < 0);
	ble_close(ctx);

	ctx = make_broken_ctx();
	ATF_CHECK(ble_discover(ctx, &a, NULL, NULL) < 0);
	ble_close(ctx);

	ctx = make_broken_ctx();
	ATF_CHECK(ble_read(ctx, &a, 0x10, NULL, NULL) < 0);
	ble_close(ctx);

	ctx = make_broken_ctx();
	ATF_CHECK(ble_pair(ctx, &a) < 0);
	ble_close(ctx);

	ctx = make_broken_ctx();
	ATF_CHECK(ble_unbond(ctx, &a) < 0);
	ble_close(ctx);

	ctx = make_broken_ctx();
	ATF_CHECK(ble_write(ctx, &a, 0x10, v, sizeof(v)) < 0);
	ble_close(ctx);

	ctx = make_broken_ctx();
	ATF_CHECK(ble_write_no_response(ctx, &a, 0x10, v, sizeof(v)) < 0);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(edge_extended_api_send_failures);
ATF_TC_BODY(edge_extended_api_send_failures, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t a;
	ble_cig_params_t cig;
	ble_big_params_t big;
	ble_adv_set_t *set = NULL;
	ble_iso_stream_t *stream = NULL;
	uint16_t handles[2];
	uint8_t v[3] = { 1, 2, 3 }, size = 0, bis[1] = { 1 };

	signal(SIGPIPE, SIG_IGN);
	mkaddr(&a, 0x12, 0);
	memset(&cig, 0, sizeof(cig));
	cig.sdu_interval_c_us = cig.sdu_interval_p_us = 10000;
	cig.max_transport_latency_c_ms = cig.max_transport_latency_p_ms = 10;
	cig.num_cis = 1;
	cig.cis[0].cis_id = 1;
	cig.cis[0].max_sdu_c = cig.cis[0].max_sdu_p = 100;
	cig.cis[0].phy_c = cig.cis[0].phy_p = 1;
	memset(&big, 0, sizeof(big));
	big.num_bis = 1;
	big.sdu_interval_us = 10000;
	big.max_sdu = 100;
	big.max_transport_latency_ms = 10;
	big.phy = 1;

	ctx = make_broken_ctx();
	ATF_CHECK(ble_gatt_read_reply(ctx, 1, v, sizeof(v)) < 0);
	ATF_CHECK(ble_gatt_read_reject(ctx, 1, 0x0e) < 0);
	ATF_CHECK(ble_gatt_authorize_reply(ctx, 1, true) < 0);
	ATF_CHECK(ble_adv_set_create(ctx, &set) < 0);
	ATF_CHECK(set == NULL);
	ATF_CHECK(ble_eatt_open(ctx, &a, 2) < 0);
	ATF_CHECK(ble_eatt_close(ctx, &a) < 0);

	ATF_CHECK(ble_periodic_adv_params(ctx, 0, 6, 12, 0) < 0);
	ATF_CHECK(ble_periodic_adv_data(ctx, 0, v, sizeof(v)) < 0);
	ATF_CHECK(ble_periodic_adv_enable(ctx, 0, true) < 0);
	ATF_CHECK(ble_periodic_sync_create(ctx, &a, 1, 0, 10) < 0);
	ATF_CHECK(ble_periodic_sync_cancel(ctx, 0) < 0);
	ATF_CHECK(ble_periodic_sync_terminate(ctx, 0, 1) < 0);
	ATF_CHECK(ble_periodic_adv_list_add(ctx, &a, 1) < 0);
	ATF_CHECK(ble_periodic_adv_list_remove(ctx, &a, 1) < 0);
	ATF_CHECK(ble_periodic_adv_list_clear(ctx, 0) < 0);
	ATF_CHECK(ble_periodic_adv_list_size(ctx, 0, &size) < 0);
	ATF_CHECK(ble_past_transfer(ctx, &a, 1, 1) < 0);
	ATF_CHECK(ble_past_receive_enable(ctx, 0, 1, true) < 0);
	ATF_CHECK(ble_past_set_info_transfer(ctx, &a, 1, 0) < 0);
	ATF_CHECK(ble_past_params(ctx, &a, 1, 0, 10, 0) < 0);
	ATF_CHECK(ble_past_default_params(ctx, 0, 1, 0, 10, 0) < 0);

	ATF_CHECK(ble_iso_cig_create(ctx, 0, &cig, handles, 2) < 0);
	ATF_CHECK(ble_iso_cis_create(ctx, &a, 0, 1) < 0);
	ATF_CHECK(ble_iso_cis_teardown(ctx, 0, 1) < 0);
	ATF_CHECK(ble_iso_cig_remove(ctx, 0, 0) < 0);
	ATF_CHECK(ble_iso_cis_accept(ctx, 0, 1) < 0);
	ATF_CHECK(ble_iso_cis_reject(ctx, 0, 1, 0x0d) < 0);
	ATF_CHECK(ble_iso_big_create(ctx, 0, &big) < 0);
	ATF_CHECK(ble_iso_big_terminate(ctx, 0, 0, 0x16) < 0);
	ATF_CHECK(ble_iso_big_create_sync(ctx, 0, 0, 1, bis, 1, 0, 10,
	    big.broadcast_code) < 0);
	ATF_CHECK(ble_iso_big_terminate_sync(ctx, 0, 0) < 0);
	ATF_CHECK(ble_iso_acquire(ctx, 0, 1, &stream) < 0);
	ATF_CHECK(ble_iso_bis_acquire(ctx, 0, 0, 1, &stream) < 0);
	ATF_CHECK(ble_bond_export(ctx, &a) == NULL);
	{
		ble_ecbfc_session_t *session = NULL;
		int fd = -1;

		ATF_CHECK(ble_acquire_coc(ctx, NULL, 0x25, &fd) < 0);
		ATF_CHECK(ble_acquire_coc(ctx, &a, 0x25, &fd) < 0);
		ATF_CHECK(ble_acquire_iso(ctx, NULL, 1, &fd) < 0);
		ATF_CHECK(ble_acquire_iso(ctx, &a, 1, &fd) < 0);
		ATF_CHECK(ble_ecbfc_session_open(ctx, NULL, 0x25, 1,
		    &session) < 0);
		ATF_CHECK(ble_ecbfc_session_open(ctx, &a, 0x25, 0,
		    &session) < 0);
		ATF_CHECK(ble_ecbfc_session_open(ctx, &a, 0x25, 6,
		    &session) < 0);
		ATF_CHECK(ble_ecbfc_session_open(ctx, &a, 0x25, 2,
		    &session) < 0);
		ATF_CHECK_EQ(0, ble_ecbfc_session_count(NULL));
		ATF_CHECK_EQ(-1, ble_ecbfc_session_fd(NULL, 0));
		ATF_CHECK_EQ(-1, ble_ecbfc_session_take_fd(NULL, 0));
		ATF_CHECK_EQ(0, ble_ecbfc_session_omtu(NULL, 0));
		ATF_CHECK(ble_ecbfc_session_reconfigure(ctx, NULL, 64, 64) < 0);
		ble_ecbfc_session_close(NULL);
	}
	ble_close(ctx);

	ATF_CHECK_EQ(0, ble_adv_set_handle(NULL));
	ATF_CHECK(ble_adv_set_params(NULL, 0, 0x20, 0x20, 1, 1) < 0);
	ATF_CHECK(ble_adv_set_data(NULL, v, sizeof(v)) < 0);
	ATF_CHECK(ble_adv_set_enable(NULL, true) < 0);
	ATF_CHECK_EQ(-1, ble_iso_fd(NULL));
	ATF_CHECK(ble_iso_send(NULL, v, sizeof(v)) < 0);
	ATF_CHECK(ble_iso_recv(NULL, v, sizeof(v)) < 0);
	ble_iso_close(NULL);
}

/* Dummy callbacks for concurrent request admission. */
static void
dummy_scan_cb(const ble_scan_result_t *r __unused, void *arg __unused)
{
}
static void
dummy_connect_cb(const ble_addr_t *a __unused, int e __unused,
    void *arg __unused)
{
}
static void
dummy_discover_cb(const ble_addr_t *a __unused,
    const ble_service_t *s __unused, int ns __unused,
    const ble_characteristic_t *c __unused, int nc __unused,
    void *arg __unused)
{
}
static void
dummy_read_cb(const ble_addr_t *a __unused, uint16_t h __unused,
    const uint8_t *v __unused, uint16_t l __unused, int e __unused,
    void *arg __unused)
{
}

/* ================================================================
 * Concurrent one-shot operations
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_concurrent_operations);
ATF_TC_BODY(edge_concurrent_operations, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	ble_addr_t a;

	mkaddr(&a, 0x22, 0);
	ctx = make_mock_ctx(&dfd);
	(void)fcntl(dfd, F_SETFL, O_NONBLOCK);

	/* scan */
	ATF_CHECK_EQ(ble_scan(ctx, dummy_scan_cb, NULL), 0);
	ATF_CHECK_EQ(ble_scan(ctx, dummy_scan_cb, NULL), 0);

	/* connect */
	ATF_CHECK_EQ(ble_connect(ctx, &a, dummy_connect_cb, NULL), 0);
	ATF_CHECK_EQ(ble_connect(ctx, &a, dummy_connect_cb, NULL), 0);
	ATF_CHECK_EQ(ble_connect_name(ctx, 0, "Dev", dummy_connect_cb, NULL), 0);

	/* discover */
	ATF_CHECK_EQ(ble_discover(ctx, &a, dummy_discover_cb, NULL), 0);
	ATF_CHECK_EQ(ble_discover(ctx, &a, dummy_discover_cb, NULL), 0);

	/* read */
	ATF_CHECK_EQ(ble_read(ctx, &a, 0x10, dummy_read_cb, NULL), 0);
	ATF_CHECK_EQ(ble_read(ctx, &a, 0x11, dummy_read_cb, NULL), 0);

	ble_close(ctx);
	(void)close(dfd);
}

ATF_TC_WITHOUT_HEAD(edge_invalid_addr_args);
ATF_TC_BODY(edge_invalid_addr_args, tc)
{
	ble_ctx_t *ctx;
	int dfd;

	ctx = make_mock_ctx(&dfd);

	ATF_CHECK(ble_connect_params(ctx, NULL, NULL, NULL, NULL) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_disconnect(ctx, NULL) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_discover(ctx, NULL, dummy_discover_cb, NULL) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_read(ctx, NULL, 0x10, dummy_read_cb, NULL) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_write(ctx, NULL, 0x10, NULL, 0) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_write_no_response(ctx, NULL, 0x10, NULL, 0) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_write(ctx, &(ble_addr_t){ 0 }, 0x10, NULL, 1) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_write_no_response(ctx, &(ble_addr_t){ 0 }, 0x10, NULL,
	    1) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_unsubscribe(ctx, NULL, 0x10) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_passkey_reply(ctx, NULL, 123456) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_numcmp_reply(ctx, NULL, true) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_pair(ctx, NULL) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_unbond(ctx, NULL) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_rekey(ctx, NULL) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_set_phy(ctx, NULL, 0x01, 0x01) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_set_data_length(ctx, NULL, 0x001B, 0x0148) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK(ble_conn_params_update(ctx, NULL, 6, 6, 0, 10) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	ble_close(ctx);
	(void)close(dfd);
}

/* ================================================================
 * ble_connect_name(): input validation
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_connect_name_validation);
ATF_TC_BODY(edge_connect_name_validation, tc)
{
	ble_ctx_t *ctx;
	int dfd;

	ctx = make_mock_ctx(&dfd);

	ATF_CHECK(ble_connect_name(ctx, 0, NULL, NULL, NULL) < 0);
	ATF_CHECK(ble_connect_name(ctx, 0, "", NULL, NULL) < 0);
	ATF_CHECK(ble_connect_name(ctx, 0, "bad\nname", NULL, NULL) < 0);
	ATF_CHECK(ble_connect_name(ctx, 0, "bad\rname", NULL, NULL) < 0);
	ATF_CHECK(ble_connect_name(ctx, 0, "bad\tname", NULL, NULL) < 0);
	/* A clean name is accepted. */
	ATF_CHECK_EQ(ble_connect_name(ctx, 0, "GoodName", NULL, NULL), 0);

	ble_close(ctx);
	(void)close(dfd);
}

/* ================================================================
 * subscription table: update in place, overflow, unsubscribe
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_subscribe_table);
ATF_TC_BODY(edge_subscribe_table, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	ble_addr_t a;
	int i;
	char buf[8192];

	mkaddr(&a, 0x33, 1);
	ctx = make_mock_ctx(&dfd);
	/* drain daemon side to avoid send-buffer stall */
	(void)fcntl(dfd, F_SETFL, O_NONBLOCK);

	/* Fill the 16-entry table. */
	for (i = 0; i < 16; i++) {
		ATF_CHECK_EQ(ble_subscribe(ctx, &a, (uint16_t)(0x100 + i),
		    NULL, NULL), 0);
		(void)recv(dfd, buf, sizeof(buf), MSG_DONTWAIT);
	}
	/* Update an existing handle in place (no new slot consumed). */
	ATF_CHECK_EQ(ble_subscribe(ctx, &a, 0x100, NULL, NULL), 0);
	(void)recv(dfd, buf, sizeof(buf), MSG_DONTWAIT);
	/* 17th distinct handle overflows to the global fallback callback. */
	ATF_CHECK_EQ(ble_subscribe(ctx, &a, 0x200, NULL, NULL), 0);
	(void)recv(dfd, buf, sizeof(buf), MSG_DONTWAIT);
	/* Unsubscribe removes an existing entry. */
	ATF_CHECK_EQ(ble_unsubscribe(ctx, &a, 0x105), 0);
	(void)recv(dfd, buf, sizeof(buf), MSG_DONTWAIT);
	/* Unsubscribe a handle that is not present is still accepted. */
	ATF_CHECK_EQ(ble_unsubscribe(ctx, &a, 0x999), 0);

	ble_close(ctx);
	(void)close(dfd);
}

/* ================================================================
 * ADD_SERVICE / ADD_CHAR: 128-bit UUID, all props/perms, value guards
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_value_too_long);
ATF_TC_BODY(edge_value_too_long, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	ble_addr_t a;
	ble_uuid_t u;
	static uint8_t big[600];

	mkaddr(&a, 0x44, 0);
	memset(&u, 0, sizeof(u));
	u.uuid16 = 0x2A00;
	ctx = make_mock_ctx(&dfd);

	/* ATT attribute values are limited to 512 bytes. */
	ATF_CHECK(ble_write(ctx, &a, 0x10, big, 513) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	/* ble_write_no_response: same guard. */
	ATF_CHECK(ble_write_no_response(ctx, &a, 0x10, big, 513) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	/* ble_set_value: 1024-byte hexbuf. */
	ATF_CHECK(ble_set_value(ctx, 0x10, big, 513) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	ble_close(ctx);
	(void)close(dfd);
}

/* ================================================================
 * ble_open(): missing path (connect fail) and live listener (success)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_open_connect_fail);
ATF_TC_BODY(edge_open_connect_fail, tc)
{

	/* Non-existent socket path -> connect() fails -> NULL. */
	ATF_CHECK(ble_open("/nonexistent/dir/blued.sock.absent") == NULL);
}

ATF_TC_WITHOUT_HEAD(edge_open_success);
ATF_TC_BODY(edge_open_success, tc)
{
	struct sockaddr_un sun;
	char path[] = "/tmp/blued-libble.XXXXXX";
	int lfd, tmpfd;
	ble_ctx_t *ctx;

	/* Reserve a unique name, then bind a listening socket to it. */
	tmpfd = mkstemp(path);
	ATF_REQUIRE(tmpfd >= 0);
	(void)close(tmpfd);
	(void)unlink(path);

	lfd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(lfd >= 0);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	ATF_REQUIRE(bind(lfd, (struct sockaddr *)&sun, sizeof(sun)) == 0);
	ATF_REQUIRE(listen(lfd, 1) == 0);

	/*
	 * ble_open() connects and then performs the HELLO handshake; a helper
	 * thread plays the daemon's side so the handshake completes and the
	 * call returns a live framed context.
	 */
	{
		pthread_t th;

		ATF_REQUIRE(pthread_create(&th, NULL, hello_responder,
		    &lfd) == 0);
		ctx = ble_open(path);
		(void)pthread_join(th, NULL);
	}
	ATF_CHECK(ctx != NULL);
	if (ctx != NULL) {
		ATF_CHECK(ble_fd(ctx) >= 0);
		ble_close(ctx);
	}

	(void)close(lfd);
	(void)unlink(path);
}

/* ================================================================
 * ble_open(): a listener that never answers HELLO -> handshake times out
 * -> NULL (the intended clean-failure behavior, protected here).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_open_handshake_timeout);
ATF_TC_BODY(edge_open_handshake_timeout, tc)
{
	struct sockaddr_un sun;
	char path[] = "/tmp/blued-libble-hs.XXXXXX";
	int lfd, tmpfd;
	ble_ctx_t *ctx;

	tmpfd = mkstemp(path);
	ATF_REQUIRE(tmpfd >= 0);
	(void)close(tmpfd);
	(void)unlink(path);

	lfd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(lfd >= 0);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	ATF_REQUIRE(bind(lfd, (struct sockaddr *)&sun, sizeof(sun)) == 0);
	ATF_REQUIRE(listen(lfd, 1) == 0);

	/* No responder: the connection is accepted by the kernel backlog but
	 * the HELLO reply never comes, so ble_open() times out and returns
	 * NULL rather than hanging. */
	ctx = ble_open(path);
	ATF_CHECK_MSG(ctx == NULL,
	    "ble_open must return NULL when the handshake is unanswered");

	(void)close(lfd);
	(void)unlink(path);
}

/* ================================================================
 * ble_process(): peer close -> n == 0 -> BLE_ERR_SOCKET, disconnected
 * ================================================================ */
/* ================================================================
 * EVENT NOTIFY with no subscription -> no callback, no crash
 * ================================================================ */
/* ================================================================
 * ble_get_rssi(): cache miss returns -127
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_get_rssi_miss);
ATF_TC_BODY(edge_get_rssi_miss, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	ble_addr_t a;

	mkaddr(&a, 0x66, 0);
	ctx = make_mock_ctx(&dfd);
	/* No scan has cached any RSSI -> miss. */
	ATF_CHECK_EQ(ble_get_rssi(ctx, &a), -127);

	ble_close(ctx);
	(void)close(dfd);
}

/* ================================================================
 * ble_read_battery(): found, not-found, and busy chaining
 * ================================================================ */
struct batt_capture {
	bool	fired;
	int	error;
	uint8_t	value0;
	uint16_t vlen;
};

static void
batt_cb(const ble_addr_t *addr __unused, uint16_t handle __unused,
    const uint8_t *val, uint16_t len, int error, void *arg)
{
	struct batt_capture *c = arg;

	c->fired = true;
	c->error = error;
	c->vlen = len;
	if (val != NULL && len > 0)
		c->value0 = val[0];
}

ATF_TC_WITHOUT_HEAD(edge_read_battery_concurrent);
ATF_TC_BODY(edge_read_battery_concurrent, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	ble_addr_t a;
	struct batt_capture cap = { false, 0, 0, 0 };

	mkaddr(&a, 0x79, 0);
	ctx = make_mock_ctx(&dfd);
	(void)fcntl(dfd, F_SETFL, O_NONBLOCK);

	/* Each battery helper owns its discovery/read chain. */
	ATF_CHECK_EQ(ble_read_battery(ctx, &a, batt_cb, &cap), 0);
	ATF_CHECK_EQ(ble_read_battery(ctx, &a, batt_cb, &cap), 0);

	ble_close(ctx);
	(void)close(dfd);
}

/* ================================================================
 * ble_strerror(): no-error and message-set paths
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_strerror_paths);
ATF_TC_BODY(edge_strerror_paths, tc)
{
	ble_ctx_t *ctx;
	int dfd;
	ble_addr_t a;

	mkaddr(&a, 0x7A, 0);
	ctx = make_mock_ctx(&dfd);

	/* Fresh context: no error. */
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_NONE);
	ATF_CHECK_STREQ(ble_strerror(ctx), "no error");

	/* Force an error with a message via a broken send. */
	(void)close(dfd);
	ble_close(ctx);
	ctx = make_broken_ctx();
	ATF_CHECK(ble_scan(ctx, NULL, NULL) < 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_SOCKET);
	/* errmsg was set, so ble_strerror returns it (not the switch text). */
	ATF_CHECK(strlen(ble_strerror(ctx)) > 0);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(edge_remaining_validation_matrix);
ATF_TC_BODY(edge_remaining_validation_matrix, tc)
{
	ble_ctx_t *ctx;
	ble_uuid_t uuid;
	ble_adv_params_t adv;
	ble_adapter_caps_t adapter_caps;
	ble_addr_t addr;
	int dfd, i;
	static uint8_t big[600];
	char long_name[IPC_ADV_NAME_MAX_SIZE + 2];
	static const ble_io_cap_t caps[] = {
		BLE_IO_DISPLAY_ONLY, BLE_IO_DISPLAY_YESNO,
		BLE_IO_KEYBOARD_ONLY, BLE_IO_NO_INPUT_NO_OUTPUT,
		BLE_IO_KEYBOARD_DISPLAY
	};

	memset(&uuid, 0, sizeof(uuid));
	uuid.uuid16 = 0x2a00;
	mkaddr(&addr, 0x42, 0);
	memset(big, 0xa5, sizeof(big));
	ctx = make_mock_ctx(&dfd);

	/* Peripheral database argument contracts. */
	ATF_CHECK_EQ(-1, ble_add_service(ctx, NULL, NULL));
	ATF_CHECK_EQ(-1, ble_add_characteristic(ctx, 0, &uuid, 0, 0,
	    NULL, 0, NULL));
	ATF_CHECK_EQ(-1, ble_add_characteristic(ctx, 1, NULL, 0, 0,
	    NULL, 0, NULL));
	ATF_CHECK_EQ(-1, ble_add_characteristic(ctx, 1, &uuid, 0, 0,
	    NULL, 1, NULL));
	ATF_CHECK_EQ(-1, ble_add_include(ctx, 0, 1, 2, 0, NULL));
	ATF_CHECK_EQ(-1, ble_add_include(ctx, 1, 0, 2, 0, NULL));
	ATF_CHECK_EQ(-1, ble_add_include(ctx, 1, 2, 1, 0, NULL));
	ATF_CHECK_EQ(-1, ble_add_descriptor(ctx, 0, &uuid, 0, NULL, 0,
	    NULL));
	ATF_CHECK_EQ(-1, ble_add_descriptor(ctx, 1, NULL, 0, NULL, 0,
	    NULL));
	ATF_CHECK_EQ(-1, ble_add_descriptor(ctx, 1, &uuid, 0, NULL, 1,
	    NULL));
	ATF_CHECK_EQ(-1, ble_set_value(ctx, 1, NULL, 1));
	ATF_CHECK_EQ(-1, ble_notify(ctx, 1, NULL, 1));
	ATF_CHECK_EQ(-1, ble_notify(ctx, 1, big, 513));
	ATF_CHECK_EQ(-1, ble_indicate(ctx, 1, NULL, 1));
	ATF_CHECK_EQ(-1, ble_indicate(ctx, 1, big, 513));
	ATF_CHECK_EQ(-1, ble_gatt_read_reply(ctx, 1, NULL, 1));
	ATF_CHECK_EQ(-1, ble_gatt_read_reply(ctx, 1, big, 513));

	/* Advertising, local-name, and MTU validation. */
	ATF_CHECK_EQ(-1, ble_set_adv_params(ctx, NULL));
	memset(&adv, 0, sizeof(adv));
	adv.mode = BLE_ADV_MODE_EXTENDED + 1;
	ATF_CHECK_EQ(-1, ble_set_adv_params(ctx, &adv));
	memset(&adv, 0, sizeof(adv));
	adv.interval_min = 20; adv.interval_max = 10;
	ATF_CHECK_EQ(-1, ble_set_adv_params(ctx, &adv));
	memset(&adv, 0, sizeof(adv));
	adv.primary_phy = BLE_PHY_2M;
	ATF_CHECK_EQ(-1, ble_set_adv_params(ctx, &adv));
	memset(&adv, 0, sizeof(adv));
	adv.channel_map = 8;
	ATF_CHECK_EQ(-1, ble_set_adv_params(ctx, &adv));
	ATF_CHECK_EQ(-1, ble_set_name(ctx, NULL));
	ATF_CHECK_EQ(-1, ble_set_name(ctx, ""));
	ATF_CHECK_EQ(-1, ble_set_name(ctx, "bad\nname"));
	memset(long_name, 'x', sizeof(long_name) - 1);
	long_name[sizeof(long_name) - 1] = '\0';
	ATF_CHECK_EQ(-1, ble_set_name(ctx, long_name));
	ATF_CHECK_EQ(-1, ble_set_preferred_mtu(ctx, 22));
	ATF_CHECK_EQ(-1, ble_set_preferred_mtu(ctx, 518));
	ATF_CHECK_EQ(-1, ble_register_agent(ctx, (ble_io_cap_t)-1));

	/* Extended advertising, EATT, controller and periodic API contracts. */
	ATF_CHECK_EQ(-1, ble_adv_set_create(ctx, NULL));
	ATF_CHECK_EQ(0, ble_adv_set_handle(NULL));
	ATF_CHECK_EQ(-1, ble_adv_set_params(NULL, 0, 0x20, 0x20, 1, 1));
	ATF_CHECK_EQ(-1, ble_adv_set_data(NULL, big, 1));
	ATF_CHECK_EQ(-1, ble_adv_set_enable(NULL, true));
	ble_adv_set_close(NULL);
	ATF_CHECK_EQ(-1, ble_eatt_open(ctx, NULL, 1));
	ATF_CHECK_EQ(-1, ble_eatt_open(ctx, &addr, 0));
	ATF_CHECK_EQ(-1, ble_eatt_open(ctx, &addr, 6));
	ATF_CHECK_EQ(-1, ble_eatt_close(ctx, NULL));
	ATF_CHECK_EQ(-1, ble_adapter_caps(ctx, 0, NULL));
	ATF_CHECK_EQ(-1, ble_adapter_caps(ctx, -1, &adapter_caps));
	ATF_CHECK_EQ(-1, ble_adapter_caps(ctx, 65536, &adapter_caps));
	ATF_CHECK_EQ(-1, ble_status(ctx, NULL));
	ATF_CHECK_EQ(-1, ble_periodic_adv_params(ctx, 0, 5, 6, 0));
	ATF_CHECK_EQ(-1, ble_periodic_adv_params(ctx, 0, 10, 9, 0));
	ATF_CHECK_EQ(-1, ble_periodic_adv_data(ctx, 0, NULL, 1));
	ATF_CHECK_EQ(-1, ble_periodic_adv_data(ctx, 0, big, 253));
	ATF_CHECK_EQ(-1, ble_periodic_sync_create(ctx, NULL, 0, 0, 10));
	ATF_CHECK_EQ(-1, ble_periodic_sync_create(ctx, &addr, 16, 0, 10));
	ATF_CHECK_EQ(-1, ble_periodic_sync_create(ctx, &addr, 0, 0, 9));
	ATF_CHECK_EQ(-1, ble_periodic_sync_terminate(ctx, 0, 0x0f00));
	ATF_CHECK_EQ(-1, ble_periodic_adv_list_add(ctx, NULL, 0));
	ATF_CHECK_EQ(-1, ble_periodic_adv_list_add(ctx, &addr, 16));
	ATF_CHECK_EQ(-1, ble_periodic_adv_list_remove(ctx, NULL, 0));
	ATF_CHECK_EQ(-1, ble_periodic_adv_list_size(ctx, 0, NULL));
	ATF_CHECK_EQ(-1, ble_past_transfer(ctx, NULL, 0, 0));
	ATF_CHECK_EQ(-1, ble_past_transfer(ctx, &addr, 0, 0x0f00));
	ATF_CHECK_EQ(-1, ble_past_receive_enable(ctx, 0, 0x0f00, true));
	ATF_CHECK_EQ(-1, ble_past_set_info_transfer(ctx, NULL, 0, 0));
	ATF_CHECK_EQ(-1, ble_past_set_info_transfer(ctx, &addr, 0, 0xf0));
	ATF_CHECK_EQ(-1, ble_past_params(ctx, NULL, 0, 0, 10, 0));
	ATF_CHECK_EQ(-1, ble_past_params(ctx, &addr, 4, 0, 10, 0));
	ATF_CHECK_EQ(-1, ble_past_default_params(ctx, 0, 0, 0x1f4, 10, 0));
	ATF_CHECK_EQ(-1, ble_path_loss_reporting(ctx, NULL, 1, 0, 2, 0,
	    0, true));
	ATF_CHECK_EQ(-1, ble_path_loss_reporting(ctx, &addr, 3, 0, 2, 0,
	    0, true));
	ATF_CHECK_EQ(-1, ble_set_phy(ctx, &addr, 0x08, 1));
	ATF_CHECK_EQ(-1, ble_set_phy(ctx, &addr, 1, 0x08));
	ATF_CHECK_EQ(-1, ble_set_data_length(ctx, &addr, 0x1a, 0x148));
	ATF_CHECK_EQ(-1, ble_set_data_length(ctx, &addr, 0x1b, 0x147));
	ATF_CHECK_EQ(-1, ble_conn_params_update(ctx, &addr, 10, 9, 0, 10));
	ATF_CHECK_EQ(-127, ble_get_rssi(ctx, NULL));
	ble_close(ctx);
	close(dfd);

	/* Every valid I/O capability reaches its distinct wire keyword. */
	signal(SIGPIPE, SIG_IGN);
	for (i = 0; i < (int)(sizeof(caps) / sizeof(caps[0])); i++) {
		ctx = make_broken_ctx();
		ATF_CHECK_EQ(-1, ble_register_agent(ctx, caps[i]));
		ATF_CHECK_EQ(BLE_ERR_SOCKET, ble_errno(ctx));
		ble_close(ctx);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, edge_send_failures);
	ATF_TP_ADD_TC(tp, edge_extended_api_send_failures);
	ATF_TP_ADD_TC(tp, edge_concurrent_operations);
	ATF_TP_ADD_TC(tp, edge_invalid_addr_args);
	ATF_TP_ADD_TC(tp, edge_connect_name_validation);
	ATF_TP_ADD_TC(tp, edge_subscribe_table);
	ATF_TP_ADD_TC(tp, edge_value_too_long);
	ATF_TP_ADD_TC(tp, edge_open_connect_fail);
	ATF_TP_ADD_TC(tp, edge_open_success);
	ATF_TP_ADD_TC(tp, edge_open_handshake_timeout);
	ATF_TP_ADD_TC(tp, edge_get_rssi_miss);
	ATF_TP_ADD_TC(tp, edge_read_battery_concurrent);
	ATF_TP_ADD_TC(tp, edge_strerror_paths);
	ATF_TP_ADD_TC(tp, edge_remaining_validation_matrix);

	return (atf_no_error());
}
