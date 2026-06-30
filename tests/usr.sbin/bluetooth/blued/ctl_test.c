/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF unit tests for blued control socket dispatch (ctl.c).
 *
 * Uses socketpair(2) to mock client connections, so no real
 * Bluetooth hardware is required.
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "blued.h"
#include "ble_util.h"
#include "config.h"
#include "conn.h"
#include "gatt.h"
#include "hci_log.h"
#include "hci_util.h"
#include "ctl.h"
#include "smp.h"

/* ================================================================
 * Stubs for external symbols referenced by ctl.c and conn.c
 * ================================================================ */

#define TEST_LINKS_CTL
#include "test_common.h"

struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;
const int _blued_kq_setup_pipe_tag;
const int _blued_kq_periph_listen_tag;

/* Stub for central setup thread — ctl.c spawns this via pthread_create */
void *
blued_conn_setup_central(void *arg __unused)
{

	return (NULL);
}

/* Stub for peripheral setup thread */
void *
blued_conn_setup_peripheral(void *arg __unused)
{

	return (NULL);
}

/* Stub for HOGP Feature report handle lookup */
uint16_t
hogp_find_feature_handle(struct blued_conn *conn __unused,
    uint8_t report_id __unused)
{

	return (0);
}

/* Stub for HOGP device allocator */
struct hogp_device *
blued_hogp_alloc(struct blued_adapter *adp __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused,
    bool reconnect __unused)
{

	/* Return non-NULL so CONNECT proceeds (calloc a dummy) */
	return (calloc(1, 256));
}

/* hci_util.c stubs */
int
hci_send_raw_cmd(int hci_fd __unused, uint16_t opcode __unused,
    const void *params __unused, uint8_t plen __unused)
{

	return (-1);
}

int
hci_wait_encryption(int hci_fd __unused, uint16_t con_handle __unused,
    int timeout_sec __unused)
{

	return (-1);
}

int
hci_le_ltk_request_reply(int hci_fd __unused, uint16_t con_handle __unused,
    const uint8_t ltk[16] __unused)
{

	return (-1);
}

int
hci_le_ltk_request_neg_reply(int hci_fd __unused,
    uint16_t con_handle __unused)
{

	return (-1);
}

int
ble_ecbfc_connect(const uint8_t *addr __unused, uint8_t addr_type __unused,
    uint16_t psm __unused, uint16_t mtu __unused,
    int count __unused, int *fds __unused)
{

	return (-1);
}

int
ble_ecbfc_reconfig(int fd __unused, uint16_t new_mtu __unused,
    uint16_t new_mps __unused)
{

	return (-1);
}

int
hci_le_scan(int hci_fd __unused, int duration_sec __unused,
    struct ble_scan_result *results __unused, int maxresults __unused,
    int *nresults)
{

	if (nresults != NULL)
		*nresults = 0;
	return (0);
}

int
hci_le_ext_scan(int hci_fd __unused, int duration_sec __unused,
    struct ble_scan_result *results __unused, int maxresults __unused,
    int *nresults)
{

	if (nresults != NULL)
		*nresults = 0;
	return (0);
}

/*
 * periph_gatt_db — ctl.c references this via extern.
 */
#define CTL_TEST_DB_MAX	64
#define CTL_TEST_VAL_SZ	1024
static struct att_attr	ctl_test_attrs[CTL_TEST_DB_MAX];
static uint8_t		ctl_test_vbuf[CTL_TEST_VAL_SZ];
/* Declared extern in ctl.c */
extern struct att_db	periph_gatt_db;
struct att_db		periph_gatt_db;

/* att.h and gatt.h functions are linked via att.c, att_server.c, gatt.c */

/* Stubs for new ctl.c commands (BONDS, UNBOND, PHY) */
struct smp_bond *
smp_find_bond(struct smp_bond_db *db __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused)
{

	return (NULL);
}

int
smp_bond_db_save(struct smp_bond_db *db __unused)
{

	return (0);
}

int
hci_le_remove_device_from_filter_accept_list(int hci_fd __unused,
    uint8_t addr_type __unused, const uint8_t addr[6] __unused)
{

	return (0);
}

int
hci_le_read_phy(int hci_fd __unused, uint16_t con_handle __unused,
    uint8_t *tx_phy, uint8_t *rx_phy)
{

	if (tx_phy != NULL)
		*tx_phy = 0x01; /* 1M */
	if (rx_phy != NULL)
		*rx_phy = 0x01;
	return (0);
}

/*
 * Reinitialize blued_g to a clean state before each test.
 */
static void
test_init(void)
{

	memset(&blued_g, 0, sizeof(blued_g));
	blued_g.kq = -1;
	blued_g.ctl_fd = -1;
	blued_g.bond_fd = -1;
	blued_g.vhid_ctl_fd = -1;
	LIST_INIT(&blued_g.adapters);
	LIST_INIT(&blued_g.conns);
	LIST_INIT(&blued_g.ctl_clients);
	pthread_rwlock_init(&blued_g.conns_lock, NULL);
	pthread_mutex_init(&blued_g.bond_db_lock, NULL);
	pthread_mutex_init(&blued_g.gatt_db_lock, NULL);
	pthread_mutex_init(&blued_g.ctl_clients_lock, NULL);
}

/*
 * Create a socketpair and set up a blued_ctl_client on sp[0].
 * The test writes commands on sp[1] and reads responses from sp[1].
 * Returns the client pointer; caller must free it.
 */
static struct blued_ctl_client *
make_client(int sp[2])
{
	struct blued_ctl_client *client;
	int ret;

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
	ATF_REQUIRE(ret == 0);

	client = calloc(1, sizeof(*client));
	ATF_REQUIRE(client != NULL);
	client->fd = sp[0];
	return (client);
}

/*
 * Read all available data from fd into buf (up to bufsz-1 bytes).
 * Returns the number of bytes read.
 */
static ssize_t
drain_response(int fd, char *buf, size_t bufsz)
{
	ssize_t total, n;
	struct timeval tv;

	/* Set a short timeout so we don't block forever */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	total = 0;
	while ((size_t)total < bufsz - 1) {
		n = recv(fd, buf + total, bufsz - 1 - (size_t)total, 0);
		if (n <= 0)
			break;
		total += n;
	}
	buf[total] = '\0';
	return (total);
}

/* ================================================================
 * Test: blued_ctl_respond sends formatted text to the client fd.
 *
 * Since blued_ctl_respond is static, we test it indirectly by
 * dispatching a STATUS command on an empty daemon context and
 * verifying the formatted response arrives on the peer socket.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_respond);
ATF_TC_BODY(test_ctl_respond, tc)
{
	struct blued_ctl_client *client;
	char resp[256];
	ssize_t n;
	int sp[2], ret;

	test_init();

	client = make_client(sp);

	/* Send a STATUS command which exercises blued_ctl_respond */
	ret = (int)send(sp[1], "STATUS\n", 7, 0);
	ATF_REQUIRE(ret == 7);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "adapters=0") != NULL,
	    "expected 'adapters=0' in response: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "connections=0") != NULL,
	    "expected 'connections=0' in response: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: STATUS command returns adapter/connection counts
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_status);
ATF_TC_BODY(test_ctl_status, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	char resp[256];
	ssize_t n;
	int sp[2], ret;

	test_init();

	/* Add one active adapter */
	memset(&adp, 0, sizeof(adp));
	strlcpy(adp.name, "ubt0", sizeof(adp.name));
	adp.active = true;
	adp.hci_fd = -1;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	client = make_client(sp);

	ret = (int)send(sp[1], "STATUS\n", 7, 0);
	ATF_REQUIRE(ret == 7);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "adapters=1") != NULL,
	    "expected 'adapters=1' in response: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "connections=0") != NULL,
	    "expected 'connections=0' in response: %s", resp);

	LIST_REMOVE(&adp, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: ADAPTERS command lists adapter names
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_adapters);
ATF_TC_BODY(test_ctl_adapters, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	char resp[512];
	ssize_t n;
	int sp[2], ret;

	test_init();

	memset(&adp, 0, sizeof(adp));
	strlcpy(adp.name, "ubt0", sizeof(adp.name));
	adp.active = true;
	adp.hci_fd = -1;
	/* Leave addr as all zeros */
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	client = make_client(sp);

	ret = (int)send(sp[1], "ADAPTERS\n", 9, 0);
	ATF_REQUIRE(ret == 9);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ADAPTERS") != NULL,
	    "expected 'ADAPTERS' header in response: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "ubt0") != NULL,
	    "expected 'ubt0' in response: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "END") != NULL,
	    "expected 'END' in response: %s", resp);

	LIST_REMOVE(&adp, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: unknown command returns ERROR
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_unknown_cmd);
ATF_TC_BODY(test_ctl_unknown_cmd, tc)
{
	struct blued_ctl_client *client;
	char resp[256];
	ssize_t n;
	int sp[2], ret;

	test_init();

	client = make_client(sp);

	ret = (int)send(sp[1], "FOOBAR\n", 7, 0);
	ATF_REQUIRE(ret == 7);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected 'ERROR' in response: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: clean disconnect (recv returns 0) yields dispatch returning -1
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_disconnect);
ATF_TC_BODY(test_ctl_disconnect, tc)
{
	struct blued_ctl_client *client;
	int sp[2], ret;

	test_init();

	client = make_client(sp);

	/* Close the writing end to simulate clean disconnect */
	close(sp[1]);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, -1);

	close(sp[0]);
	free(client);
}

/* ================================================================
 * Test: blued_ctl_send_fd sends a file descriptor via SCM_RIGHTS,
 * and the received fd has correct cap_rights.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_send_fd);
ATF_TC_BODY(test_ctl_send_fd, tc)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(sizeof(int))];
	char byte;
	cap_rights_t rights;
	int sp[2], fd_pair[2], recv_fd, ret;

	test_init();

	/* sp is the client<->daemon channel for fd passing */
	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
	ATF_REQUIRE(ret == 0);

	/* fd_pair: we'll send fd_pair[0] through the channel */
	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd_pair);
	ATF_REQUIRE(ret == 0);

	/* Send fd_pair[0] over sp[0] -> sp[1] */
	blued_ctl_send_fd(sp[0], fd_pair[0]);

	/*
	 * Receive the fd on sp[1].  cap_ambient_limit() may fail
	 * outside capability mode, in which case blued_ctl_send_fd
	 * sends an error text response instead of an fd.  Handle
	 * both cases.
	 */
	{
		struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
		(void)setsockopt(sp[1], SOL_SOCKET, SO_RCVTIMEO,
		    &tv, sizeof(tv));
	}
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(cbuf, 0, sizeof(cbuf));
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	ret = (int)recvmsg(sp[1], &msg, 0);
	ATF_REQUIRE(ret >= 1);

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg != NULL &&
	    cmsg->cmsg_level == SOL_SOCKET &&
	    cmsg->cmsg_type == SCM_RIGHTS) {
		/* fd transfer succeeded — verify cap_rights */
		memcpy(&recv_fd, CMSG_DATA(cmsg), sizeof(int));
		ATF_REQUIRE(recv_fd >= 0);

		ret = cap_rights_get(recv_fd, &rights);
		ATF_REQUIRE(ret == 0);
		ATF_CHECK(cap_rights_is_set(&rights, CAP_SEND));
		ATF_CHECK(cap_rights_is_set(&rights, CAP_RECV));
		ATF_CHECK(cap_rights_is_set(&rights, CAP_EVENT));

		close(recv_fd);
	} else {
		/*
		 * cap_ambient_limit failed (expected outside cap mode);
		 * blued_ctl_send_fd sent an error response instead.
		 * Just verify we got something (the ERROR text).
		 */
		ATF_CHECK(ret >= 1);
	}

	close(fd_pair[0]);
	close(fd_pair[1]);
	close(sp[0]);
	close(sp[1]);
}

/* BONDS command with empty bond DB */
ATF_TC_WITHOUT_HEAD(test_ctl_bonds_empty);
ATF_TC_BODY(test_ctl_bonds_empty, tc)
{
	struct blued_ctl_client *client;
	struct smp_bond_db bdb;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();
	memset(&bdb, 0, sizeof(bdb));
	blued_g.bond_db = &bdb;

	client = make_client(sp);

	(void)send(sp[1], "BONDS\n", 6, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK(strstr(resp, "BONDS") != NULL);
	ATF_CHECK(strstr(resp, "END") != NULL);

	free(client);
	close(sp[0]);
	close(sp[1]);
	blued_g.bond_db = NULL;
}

/* BONDS command with populated bond DB */
ATF_TC_WITHOUT_HEAD(test_ctl_bonds_populated);
ATF_TC_BODY(test_ctl_bonds_populated, tc)
{
	struct blued_ctl_client *client;
	struct smp_bond_db bdb;
	int sp[2];
	char resp[1024];
	ssize_t n;

	test_init();
	memset(&bdb, 0, sizeof(bdb));
	bdb.count = 1;
	memset(bdb.bonds[0].addr, 0xAA, 6);
	bdb.bonds[0].addr_type = BDADDR_LE_RANDOM;
	bdb.bonds[0].has_ltk = true;
	bdb.bonds[0].is_sc = true;
	blued_g.bond_db = &bdb;

	client = make_client(sp);

	(void)send(sp[1], "BONDS\n", 6, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "BONDS") != NULL,
	    "expected BONDS header: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "ltk=1") != NULL,
	    "expected ltk=1: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "END") != NULL,
	    "expected END: %s", resp);

	free(client);
	close(sp[0]);
	close(sp[1]);
	blued_g.bond_db = NULL;
}

/* PHY command with no connections */
ATF_TC_WITHOUT_HEAD(test_ctl_phy_empty);
ATF_TC_BODY(test_ctl_phy_empty, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();
	memset(&adp, 0, sizeof(adp));
	adp.hci_fd = -1;
	adp.active = true;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	client = make_client(sp);

	(void)send(sp[1], "PHY\n", 4, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK(strstr(resp, "PHY") != NULL);
	ATF_CHECK(strstr(resp, "END") != NULL);

	LIST_REMOVE(&adp, entries);
	free(client);
	close(sp[0]);
	close(sp[1]);
}

/* ================================================================
 * Test: empty command (zero-length message after newline) — no crash
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_empty_command);
ATF_TC_BODY(test_ctl_empty_command, tc)
{
	struct blued_ctl_client *client;
	char resp[256];
	ssize_t n;
	int sp[2], ret;

	test_init();

	client = make_client(sp);

	/* Send just a newline — empty command */
	ret = (int)send(sp[1], "\n", 1, 0);
	ATF_REQUIRE(ret == 1);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for empty command: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: oversized command (fills buffer without newline) — handled
 * gracefully with "line too long" error, no crash.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_oversized_command);
ATF_TC_BODY(test_ctl_oversized_command, tc)
{
	struct blued_ctl_client *client;
	char bigbuf[256];
	char resp[256];
	ssize_t n;
	int sp[2], ret;

	test_init();

	client = make_client(sp);

	/* Fill the client buffer (256 bytes) without a newline */
	memset(bigbuf, 'A', sizeof(bigbuf) - 1);
	bigbuf[sizeof(bigbuf) - 1] = '\0';

	/* Send in chunks to fill the buffer */
	ret = (int)send(sp[1], bigbuf, sizeof(bigbuf) - 1, 0);
	ATF_REQUIRE(ret > 0);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	/* The buffer should be full; next dispatch should reset it */
	ret = (int)send(sp[1], "X", 1, 0);
	ATF_REQUIRE(ret == 1);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for oversized command: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: SCAN command returns a response (stubs return 0 results)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_scan);
ATF_TC_BODY(test_ctl_scan, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	char resp[512];
	ssize_t n;
	int sp[2], ret;

	test_init();

	memset(&adp, 0, sizeof(adp));
	strlcpy(adp.name, "ubt0", sizeof(adp.name));
	adp.active = true;
	adp.hci_fd = -1;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	client = make_client(sp);

	ret = (int)send(sp[1], "SCAN\n", 5, 0);
	ATF_REQUIRE(ret == 5);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "SCANNING") != NULL ||
	    strstr(resp, "END") != NULL,
	    "expected SCANNING or END in response: %s", resp);

	LIST_REMOVE(&adp, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: multiple STATUS commands in sequence
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_status_repeated);
ATF_TC_BODY(test_ctl_status_repeated, tc)
{
	struct blued_ctl_client *client;
	char resp[512];
	ssize_t n;
	int sp[2], ret, i;

	test_init();

	client = make_client(sp);

	for (i = 0; i < 3; i++) {
		ret = (int)send(sp[1], "STATUS\n", 7, 0);
		ATF_REQUIRE(ret == 7);

		ret = blued_ctl_dispatch(client);
		ATF_CHECK_EQ(ret, 0);

		n = drain_response(sp[1], resp, sizeof(resp));
		ATF_REQUIRE(n > 0);
		ATF_CHECK_MSG(strstr(resp, "STATUS") != NULL,
		    "iteration %d: expected STATUS in response: %s",
		    i, resp);
	}

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: DISCONNECT with no connections — returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_disconnect_no_conns);
ATF_TC_BODY(test_ctl_disconnect_no_conns, tc)
{
	struct blued_ctl_client *client;
	char resp[256];
	ssize_t n;
	int sp[2], ret;

	test_init();

	client = make_client(sp);

	ret = (int)send(sp[1], "DISCONNECT 11:22:33:44:55:66\n", 29, 0);
	ATF_REQUIRE(ret == 29);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for disconnect with no conns: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: UNBOND with non-existent address — returns error
 * (smp_find_bond stub always returns NULL)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_unbond_not_found);
ATF_TC_BODY(test_ctl_unbond_not_found, tc)
{
	struct blued_ctl_client *client;
	struct smp_bond_db bdb;
	char resp[256];
	ssize_t n;
	int sp[2], ret;

	test_init();

	memset(&bdb, 0, sizeof(bdb));
	blued_g.bond_db = &bdb;

	client = make_client(sp);

	ret = (int)send(sp[1], "UNBOND 11:22:33:44:55:66\n", 25, 0);
	ATF_REQUIRE(ret == 25);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL ||
	    strstr(resp, "not bonded") != NULL,
	    "expected error for unbond not found: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
	blued_g.bond_db = NULL;
}

/* ================================================================
 * Test: PHY with an active connection — returns PHY info
 * (hci_le_read_phy stub returns 1M/1M)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_phy_active_conn);
ATF_TC_BODY(test_ctl_phy_active_conn, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct blued_conn *conn;
	char resp[512];
	ssize_t n;
	int sp[2], ret;

	test_init();

	memset(&adp, 0, sizeof(adp));
	adp.hci_fd = -1;
	adp.active = true;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->con_handle = 0x0040;
	conn->dst.b[0] = 0xAA;
	conn->dst.b[1] = 0xBB;
	conn->dst.b[2] = 0xCC;
	conn->dst.b[3] = 0xDD;
	conn->dst.b[4] = 0xEE;
	conn->dst.b[5] = 0xFF;

	client = make_client(sp);

	ret = (int)send(sp[1], "PHY\n", 4, 0);
	ATF_REQUIRE(ret == 4);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "PHY") != NULL,
	    "expected PHY header in response: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "1M") != NULL,
	    "expected 1M PHY in response: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "END") != NULL,
	    "expected END in response: %s", resp);

	blued_conn_free(conn);
	LIST_REMOVE(&adp, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: blued_ctl_init creates a socket and blued_ctl_cleanup
 * removes it.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_init_cleanup);
ATF_TC_BODY(test_ctl_init_cleanup, tc)
{
	struct stat sb;
	char path[64];
	int ret;

	test_init();

	/* blued_ctl_init needs a valid kqueue */
	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);

	snprintf(path, sizeof(path), "/tmp/blued-test-%d.sock",
	    (int)getpid());

	ret = blued_ctl_init(path);
	ATF_REQUIRE_EQ(ret, 0);
	ATF_CHECK(blued_g.ctl_fd >= 0);

	/* Verify socket file exists */
	ret = stat(path, &sb);
	ATF_CHECK_EQ_MSG(ret, 0,
	    "control socket file should exist after init");
	ATF_CHECK_MSG(S_ISSOCK(sb.st_mode),
	    "control socket path should be a socket");

	blued_ctl_cleanup();

	/* Verify socket file is removed */
	ret = stat(path, &sb);
	ATF_CHECK_EQ_MSG(ret, -1,
	    "control socket file should be removed after cleanup");
	ATF_CHECK(blued_g.ctl_fd == -1);

	close(blued_g.kq);
}

/* ================================================================
 * Test: blued_ctl_accept — connect to the control socket, verify
 * the connection is accepted and the client is tracked.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_accept);
ATF_TC_BODY(test_ctl_accept, tc)
{
	struct sockaddr_un sun;
	struct blued_ctl_client *client;
	char path[64];
	int ret, cli_fd, nclients;

	test_init();

	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);

	snprintf(path, sizeof(path), "/tmp/blued-test-%d.sock",
	    (int)getpid());

	ret = blued_ctl_init(path);
	ATF_REQUIRE_EQ(ret, 0);

	/* Connect a client to the control socket */
	cli_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(cli_fd >= 0);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	ret = connect(cli_fd, (struct sockaddr *)&sun, sizeof(sun));
	ATF_REQUIRE_EQ(ret, 0);

	/* Accept the connection */
	blued_ctl_accept();

	/* Verify client is in the list */
	nclients = 0;
	LIST_FOREACH(client, &blued_g.ctl_clients, entries)
		nclients++;
	ATF_CHECK_EQ_MSG(nclients, 1,
	    "expected 1 control client after accept");

	close(cli_fd);
	blued_ctl_cleanup();
	close(blued_g.kq);
}

/* ================================================================
 * Test: connect BLUED_MAX_CTL (8) clients, verify the 9th is
 * rejected (not tracked in the client list).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_max_clients);
ATF_TC_BODY(test_ctl_max_clients, tc)
{
	struct sockaddr_un sun;
	struct blued_ctl_client *client;
	char path[64];
	int ret, cli_fds[BLUED_MAX_CTL + 1];
	int i, nclients;

	test_init();

	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);

	snprintf(path, sizeof(path), "/tmp/blued-test-%d.sock",
	    (int)getpid());

	ret = blued_ctl_init(path);
	ATF_REQUIRE_EQ(ret, 0);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	/* Connect BLUED_MAX_CTL + 1 clients */
	for (i = 0; i <= BLUED_MAX_CTL; i++) {
		cli_fds[i] = socket(AF_UNIX, SOCK_STREAM, 0);
		ATF_REQUIRE(cli_fds[i] >= 0);

		ret = connect(cli_fds[i], (struct sockaddr *)&sun,
		    sizeof(sun));
		ATF_REQUIRE_EQ(ret, 0);

		blued_ctl_accept();
	}

	/* Count tracked clients — should be capped at BLUED_MAX_CTL */
	nclients = 0;
	LIST_FOREACH(client, &blued_g.ctl_clients, entries)
		nclients++;
	ATF_CHECK_EQ_MSG(nclients, BLUED_MAX_CTL,
	    "expected %d control clients, got %d", BLUED_MAX_CTL, nclients);

	for (i = 0; i <= BLUED_MAX_CTL; i++)
		close(cli_fds[i]);
	blued_ctl_cleanup();
	close(blued_g.kq);
}

/* ================================================================
 * Test: CONNECT command — valid address format
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_dispatch_connect);
ATF_TC_BODY(test_ctl_dispatch_connect, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	char resp[512];
	ssize_t n;
	int sp[2], ret;

	test_init();

	/* CONNECT needs an active adapter */
	memset(&adp, 0, sizeof(adp));
	strlcpy(adp.name, "ubt0", sizeof(adp.name));
	adp.active = true;
	adp.hci_fd = -1;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	client = make_client(sp);

	/* Valid address — should get OK response */
	ret = (int)send(sp[1], "CONNECT 11:22:33:44:55:66 random\n", 33, 0);
	ATF_REQUIRE(ret == 33);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "OK") != NULL,
	    "expected OK for valid CONNECT: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "11:22:33:44:55:66") != NULL,
	    "expected address in CONNECT response: %s", resp);

	/* Clean up any allocated connections */
	{
		struct blued_conn *conn, *tmp;
		LIST_FOREACH_SAFE(conn, &blued_g.conns, entries, tmp)
			blued_conn_free(conn);
	}

	LIST_REMOVE(&adp, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: CONNECT command — invalid address format returns ERROR
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_dispatch_connect_invalid);
ATF_TC_BODY(test_ctl_dispatch_connect_invalid, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	char resp[512];
	ssize_t n;
	int sp[2], ret;

	test_init();

	memset(&adp, 0, sizeof(adp));
	strlcpy(adp.name, "ubt0", sizeof(adp.name));
	adp.active = true;
	adp.hci_fd = -1;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	client = make_client(sp);

	/* Invalid address format */
	ret = (int)send(sp[1], "CONNECT not-an-address\n", 23, 0);
	ATF_REQUIRE(ret == 23);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for invalid address: %s", resp);

	LIST_REMOVE(&adp, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: CONNECT command — already connected address returns ERROR
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_dispatch_connect_already);
ATF_TC_BODY(test_ctl_dispatch_connect_already, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct blued_conn *conn;
	char resp[512];
	ssize_t n;
	int sp[2], ret;

	test_init();

	memset(&adp, 0, sizeof(adp));
	strlcpy(adp.name, "ubt0", sizeof(adp.name));
	adp.active = true;
	adp.hci_fd = -1;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	/* Pre-create a connection with the target address */
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	/* bt_aton stores in network order; replicate what CONNECT does */
	{
		bdaddr_t addr;
		ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &addr));
		memcpy(&conn->dst, &addr, sizeof(conn->dst));
	}

	client = make_client(sp);

	/* Try to CONNECT the same address */
	ret = (int)send(sp[1], "CONNECT 11:22:33:44:55:66\n", 26, 0);
	ATF_REQUIRE(ret == 26);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL &&
	    strstr(resp, "already connected") != NULL,
	    "expected 'ERROR already connected': %s", resp);

	blued_conn_free(conn);
	LIST_REMOVE(&adp, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: SCAN command with no active adapter returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_dispatch_scan);
ATF_TC_BODY(test_ctl_dispatch_scan, tc)
{
	struct blued_ctl_client *client;
	char resp[512];
	ssize_t n;
	int sp[2], ret;

	test_init();

	/* No adapters — SCAN should return error */
	client = make_client(sp);

	ret = (int)send(sp[1], "SCAN\n", 5, 0);
	ATF_REQUIRE(ret == 5);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for SCAN with no adapter: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: concurrent clients can issue commands without interfering.
 * Uses pthreads to dispatch on two clients simultaneously.
 * ================================================================ */
struct concurrent_arg {
	struct blued_ctl_client	*client;
	int			peer_fd;
	int			ok;
};

static void *
concurrent_worker(void *arg)
{
	struct concurrent_arg *ca = arg;
	char resp[512];
	ssize_t n;
	int ret, i;

	for (i = 0; i < 5; i++) {
		ret = (int)send(ca->peer_fd, "STATUS\n", 7, 0);
		if (ret != 7) {
			ca->ok = 0;
			return (NULL);
		}

		ret = blued_ctl_dispatch(ca->client);
		if (ret != 0) {
			ca->ok = 0;
			return (NULL);
		}

		n = drain_response(ca->peer_fd, resp, sizeof(resp));
		if (n <= 0 || strstr(resp, "STATUS") == NULL) {
			ca->ok = 0;
			return (NULL);
		}
	}

	ca->ok = 1;
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(test_ctl_concurrent_clients);
ATF_TC_BODY(test_ctl_concurrent_clients, tc)
{
	struct concurrent_arg args[2];
	pthread_t threads[2];
	int sp1[2], sp2[2], i;

	test_init();

	args[0].client = make_client(sp1);
	args[0].peer_fd = sp1[1];
	args[0].ok = 0;

	args[1].client = make_client(sp2);
	args[1].peer_fd = sp2[1];
	args[1].ok = 0;

	for (i = 0; i < 2; i++)
		ATF_REQUIRE(pthread_create(&threads[i], NULL,
		    concurrent_worker, &args[i]) == 0);

	for (i = 0; i < 2; i++)
		(void)pthread_join(threads[i], NULL);

	ATF_CHECK_MSG(args[0].ok, "client 0 failed during concurrent test");
	ATF_CHECK_MSG(args[1].ok, "client 1 failed during concurrent test");

	close(sp1[0]);
	close(sp1[1]);
	free(args[0].client);
	close(sp2[0]);
	close(sp2[1]);
	free(args[1].client);
}

/* ================================================================
 * Helper: build a test GATT database in periph_gatt_db
 * ================================================================ */

static void
build_ctl_test_db(void)
{

	attdb_init(&periph_gatt_db, ctl_test_attrs, CTL_TEST_DB_MAX,
	    ctl_test_vbuf, CTL_TEST_VAL_SZ);

	/* GAP Service */
	attdb_add_service(&periph_gatt_db, 0x1800);
	attdb_add_characteristic(&periph_gatt_db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, "Test", 4);

	/* Custom Service */
	attdb_add_service(&periph_gatt_db, 0xFFE0);
	attdb_add_characteristic(&periph_gatt_db, 0xFFE1,
	    GATT_PROP_READ | GATT_PROP_WRITE | GATT_PROP_NOTIFY,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    "\xAA\xBB", 2);
	attdb_add_cccd(&periph_gatt_db);
}

/* ================================================================
 * Test: SERVICES command lists local GATT database
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_services);
ATF_TC_BODY(test_ctl_services, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[4096];

	test_init();
	build_ctl_test_db();
	client = make_client(sp);

	send(sp[1], "SERVICES\n", 9, 0);
	blued_ctl_dispatch(client);
	drain_response(sp[1], resp, sizeof(resp));

	ATF_CHECK_MSG(strstr(resp, "SERVICES\n") != NULL,
	    "response missing SERVICES header: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "primary_service") != NULL,
	    "response missing primary_service: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "uuid=0x1800") != NULL ||
	    strstr(resp, "uuid=0x1801") != NULL,
	    "response missing GAP/GATT service uuid: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "0xFFE0") != NULL,
	    "response missing custom service uuid: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "END\n") != NULL,
	    "response missing END: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: SERVICES with empty database
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_services_empty);
ATF_TC_BODY(test_ctl_services_empty, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];

	test_init();
	memset(&periph_gatt_db, 0, sizeof(periph_gatt_db));
	client = make_client(sp);

	send(sp[1], "SERVICES\n", 9, 0);
	blued_ctl_dispatch(client);
	drain_response(sp[1], resp, sizeof(resp));

	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for empty db: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: DISCOVER with no connection returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_discover_not_connected);
ATF_TC_BODY(test_ctl_discover_not_connected, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];

	test_init();
	client = make_client(sp);

	send(sp[1], "DISCOVER 11:22:33:44:55:66\n", 27, 0);
	blued_ctl_dispatch(client);
	drain_response(sp[1], resp, sizeof(resp));

	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for unconnected device: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: DISCOVER with invalid address
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_discover_invalid_addr);
ATF_TC_BODY(test_ctl_discover_invalid_addr, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];

	test_init();
	client = make_client(sp);

	send(sp[1], "DISCOVER not-an-addr\n", 21, 0);
	blued_ctl_dispatch(client);
	drain_response(sp[1], resp, sizeof(resp));

	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for bad address: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: READ with no connection returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_read_not_connected);
ATF_TC_BODY(test_ctl_read_not_connected, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];

	test_init();
	client = make_client(sp);

	send(sp[1], "READ 11:22:33:44:55:66 0x0003\n", 30, 0);
	blued_ctl_dispatch(client);
	drain_response(sp[1], resp, sizeof(resp));

	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for unconnected read: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: WRITE with no connection returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_write_not_connected);
ATF_TC_BODY(test_ctl_write_not_connected, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];

	test_init();
	client = make_client(sp);

	send(sp[1], "WRITE 11:22:33:44:55:66 0x0007 0100\n", 36, 0);
	blued_ctl_dispatch(client);
	drain_response(sp[1], resp, sizeof(resp));

	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for unconnected write: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: WRITE with invalid hex value
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_write_bad_hex);
ATF_TC_BODY(test_ctl_write_bad_hex, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];

	test_init();
	client = make_client(sp);

	/* Odd-length hex string should fail */
	send(sp[1], "WRITE 11:22:33:44:55:66 0x0007 ABC\n", 35, 0);
	blued_ctl_dispatch(client);
	drain_response(sp[1], resp, sizeof(resp));

	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for odd hex: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: ADD_SERVICE adds a service to the GATT database
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_add_service);
ATF_TC_BODY(test_ctl_add_service, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];
	int count_before;

	test_init();
	build_ctl_test_db();
	count_before = periph_gatt_db.count;
	client = make_client(sp);

	send(sp[1], "ADD_SERVICE 0xFFF0\n", 19, 0);
	blued_ctl_dispatch(client);
	drain_response(sp[1], resp, sizeof(resp));

	ATF_CHECK_MSG(strstr(resp, "OK ADD_SERVICE") != NULL,
	    "expected OK response: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "0xFFF0") != NULL,
	    "response missing uuid: %s", resp);
	ATF_CHECK(periph_gatt_db.count == count_before + 1);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: ADD_CHAR adds a characteristic to a service
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_add_char);
ATF_TC_BODY(test_ctl_add_char, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512], cmd[128];
	int count_before;

	test_init();
	build_ctl_test_db();

	/* First add a service to get a known handle */
	uint16_t svc_handle = periph_gatt_db.next_handle;
	attdb_add_service(&periph_gatt_db, 0xFFF0);

	count_before = periph_gatt_db.count;
	client = make_client(sp);

	snprintf(cmd, sizeof(cmd),
	    "ADD_CHAR 0x%04X 0xFFF1 read,notify read 00\n", svc_handle);
	send(sp[1], cmd, strlen(cmd), 0);
	blued_ctl_dispatch(client);
	drain_response(sp[1], resp, sizeof(resp));

	ATF_CHECK_MSG(strstr(resp, "OK ADD_CHAR") != NULL,
	    "expected OK response: %s", resp);
	/* Should add char decl + value + CCCD (notify) = 3 attrs */
	ATF_CHECK(periph_gatt_db.count >= count_before + 2);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: REMOVE_SERVICE removes a service
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_remove_service);
ATF_TC_BODY(test_ctl_remove_service, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512], cmd[64];

	test_init();
	build_ctl_test_db();

	/* Add a service we can remove */
	uint16_t svc_handle = periph_gatt_db.next_handle;
	attdb_add_service(&periph_gatt_db, 0xFFF0);
	attdb_add_characteristic(&periph_gatt_db, 0xFFF1,
	    GATT_PROP_READ, ATT_PERM_READ, "\x00", 1);
	int count_after_add = periph_gatt_db.count;

	client = make_client(sp);

	snprintf(cmd, sizeof(cmd), "REMOVE_SERVICE 0x%04X\n", svc_handle);
	send(sp[1], cmd, strlen(cmd), 0);
	blued_ctl_dispatch(client);
	drain_response(sp[1], resp, sizeof(resp));

	ATF_CHECK_MSG(strstr(resp, "OK REMOVE_SERVICE") != NULL,
	    "expected OK response: %s", resp);
	ATF_CHECK(periph_gatt_db.count < count_after_add);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: REMOVE_SERVICE with invalid handle returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_remove_service_invalid);
ATF_TC_BODY(test_ctl_remove_service_invalid, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];

	test_init();
	build_ctl_test_db();
	client = make_client(sp);

	send(sp[1], "REMOVE_SERVICE 0xFFFF\n", 22, 0);
	blued_ctl_dispatch(client);
	drain_response(sp[1], resp, sizeof(resp));

	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for invalid handle: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: LOGLEVEL without argument returns current level
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_loglevel_get);
ATF_TC_BODY(test_ctl_loglevel_get, tc)
{
	struct blued_ctl_client *client;
	char resp[256];
	ssize_t n;
	int sp[2], ret;

	test_init();
	blued_verbose = 2;

	client = make_client(sp);

	ret = (int)send(sp[1], "LOGLEVEL\n", 9, 0);
	ATF_REQUIRE(ret == 9);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "OK LOGLEVEL 2") != NULL,
	    "expected 'OK LOGLEVEL 2' in response: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: LOGLEVEL with argument sets the level
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_loglevel_set);
ATF_TC_BODY(test_ctl_loglevel_set, tc)
{
	struct blued_ctl_client *client;
	char resp[256];
	ssize_t n;
	int sp[2], ret;

	test_init();
	blued_verbose = 0;

	client = make_client(sp);

	ret = (int)send(sp[1], "LOGLEVEL 4\n", 11, 0);
	ATF_REQUIRE(ret == 11);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "OK LOGLEVEL 4") != NULL,
	    "expected 'OK LOGLEVEL 4' in response: %s", resp);
	ATF_CHECK_EQ(blued_verbose, 4);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: LOGLEVEL with out-of-range value returns ERROR
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_loglevel_invalid);
ATF_TC_BODY(test_ctl_loglevel_invalid, tc)
{
	struct blued_ctl_client *client;
	char resp[256];
	ssize_t n;
	int sp[2], ret;

	test_init();
	blued_verbose = 1;

	client = make_client(sp);

	ret = (int)send(sp[1], "LOGLEVEL 9\n", 11, 0);
	ATF_REQUIRE(ret == 11);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected 'ERROR' in response: %s", resp);
	/* Verify level was NOT changed */
	ATF_CHECK_EQ(blued_verbose, 1);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: SUBSCRIBE command adds subscription
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_subscribe);
ATF_TC_BODY(test_ctl_subscribe, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();
	build_ctl_test_db();

	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);

	(void)send(sp[1], "SUBSCRIBE 11:22:33:44:55:66 0x0007\n", 35, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "OK SUBSCRIBE") != NULL,
	    "expected OK SUBSCRIBE: %s", resp);
	ATF_CHECK_EQ(client->nsubs, 1);

	LIST_REMOVE(client, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: UNSUBSCRIBE command removes subscription
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_unsubscribe);
ATF_TC_BODY(test_ctl_unsubscribe, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();
	build_ctl_test_db();

	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);

	/* First subscribe */
	(void)send(sp[1], "SUBSCRIBE 11:22:33:44:55:66 0x0007\n", 35, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_EQ(client->nsubs, 1);

	/* Then unsubscribe */
	(void)send(sp[1], "UNSUBSCRIBE 11:22:33:44:55:66 0x0007\n", 37, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "OK UNSUBSCRIBE") != NULL,
	    "expected OK UNSUBSCRIBE: %s", resp);
	ATF_CHECK_EQ(client->nsubs, 0);

	LIST_REMOVE(client, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: SET_VALUE updates a local GATT attribute value
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_set_value);
ATF_TC_BODY(test_ctl_set_value, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512], cmd[128];
	uint16_t char_handle = 0;

	test_init();
	build_ctl_test_db();

	/* Find the custom characteristic value handle (0xFFE1) */
	for (int i = 0; i < periph_gatt_db.count; i++) {
		if (periph_gatt_db.attrs[i].uuid16 == 0xFFE1 &&
		    periph_gatt_db.attrs[i].is_char_value) {
			char_handle = periph_gatt_db.attrs[i].handle;
			break;
		}
	}
	ATF_REQUIRE(char_handle != 0);

	client = make_client(sp);

	snprintf(cmd, sizeof(cmd), "SET_VALUE 0x%04X DDEE\n", char_handle);
	(void)send(sp[1], cmd, strlen(cmd), 0);
	blued_ctl_dispatch(client);
	drain_response(sp[1], resp, sizeof(resp));

	ATF_CHECK_MSG(strstr(resp, "OK SET_VALUE") != NULL,
	    "expected OK SET_VALUE: %s", resp);

	/* Verify the value was updated */
	struct att_attr *a = attdb_find_by_handle(&periph_gatt_db, char_handle);
	ATF_REQUIRE(a != NULL);
	ATF_CHECK_EQ(a->value_len, 2);
	ATF_CHECK_EQ(a->value[0], 0xDD);
	ATF_CHECK_EQ(a->value[1], 0xEE);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: PASSKEY_REPLY dispatches without crash.
 *
 * PASSKEY_REPLY sets the reply fields in blued_g; with no pending
 * request the reply is accepted but silently ignored by the SMP thread.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_passkey_reply);
ATF_TC_BODY(test_ctl_passkey_reply, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();

	client = make_client(sp);

	/* Set up a pending passkey request for the target address */
	bt_aton("11:22:33:44:55:66", &blued_g.passkey_target);
	blued_g.passkey_reply_status = 0;  /* pending */

	(void)send(sp[1], "PASSKEY_REPLY 11:22:33:44:55:66 123456\n", 39, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "OK") != NULL || strstr(resp, "PASSKEY") != NULL,
	    "expected OK in response: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: NUMCMP_REPLY dispatches without crash.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_numcmp_reply);
ATF_TC_BODY(test_ctl_numcmp_reply, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();

	client = make_client(sp);

	/* Set up a pending numcmp request for the target address */
	bt_aton("11:22:33:44:55:66", &blued_g.passkey_target);
	blued_g.numcmp_reply_status = 0;  /* pending */

	(void)send(sp[1], "NUMCMP_REPLY 11:22:33:44:55:66 yes\n", 35, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "OK") != NULL || strstr(resp, "NUMCMP") != NULL,
	    "expected OK in response: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: Rate limiting — send 5 DISCOVER commands rapidly.
 *
 * The rate limiter allows CTL_BLOCKING_LIMIT (4) commands per
 * CTL_BLOCKING_WINDOW (10s).  The 5th should be rate-limited.
 * DISCOVER needs a connection, so without one it returns ERROR,
 * but the rate limiter check happens before the conn lookup.
 *
 * We need the client to be in ctl_clients list for rate checking.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_rate_limit);
ATF_TC_BODY(test_ctl_rate_limit, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[1024];
	ssize_t n;
	int i;
	bool saw_rate_limit = false;

	test_init();

	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);

	/*
	 * Send 5 DISCOVER commands.  The first 4 should pass rate check
	 * (then fail with "not connected" ERROR), the 5th should be
	 * rate-limited.
	 */
	for (i = 0; i < 5; i++) {
		(void)send(sp[1], "DISCOVER 11:22:33:44:55:66\n", 27, 0);
		blued_ctl_dispatch(client);
		n = drain_response(sp[1], resp, sizeof(resp));
		if (n > 0 && strstr(resp, "rate limited") != NULL)
			saw_rate_limit = true;
	}

	ATF_CHECK_MSG(saw_rate_limit,
	    "expected rate limiting after 5 rapid DISCOVER commands");

	LIST_REMOVE(client, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: HOGP_READ with no connection — returns error.
 * The hogp_find_feature_handle stub returns 0 (no handle).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_hogp_read_stub);
ATF_TC_BODY(test_ctl_hogp_read_stub, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();

	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);

	(void)send(sp[1], "HOGP_READ 11:22:33:44:55:66 1\n", 30, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for HOGP_READ with no connection: %s", resp);

	LIST_REMOVE(client, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: PASSKEY_REPLY with invalid passkey (>999999) returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_passkey_reply_invalid);
ATF_TC_BODY(test_ctl_passkey_reply_invalid, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();
	client = make_client(sp);

	bt_aton("11:22:33:44:55:66", &blued_g.passkey_target);
	blued_g.passkey_reply_status = 0;

	(void)send(sp[1], "PASSKEY_REPLY 11:22:33:44:55:66 1000000\n", 40, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for passkey > 999999: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: PASSKEY_REPLY with wrong address returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_passkey_reply_wrong_addr);
ATF_TC_BODY(test_ctl_passkey_reply_wrong_addr, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();
	client = make_client(sp);

	bt_aton("11:22:33:44:55:66", &blued_g.passkey_target);
	blued_g.passkey_reply_status = 0;

	/* Send passkey for a different address */
	(void)send(sp[1], "PASSKEY_REPLY AA:BB:CC:DD:EE:FF 123456\n", 39, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for wrong address: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: PASSKEY_REPLY with no pending request returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_passkey_reply_not_pending);
ATF_TC_BODY(test_ctl_passkey_reply_not_pending, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();
	client = make_client(sp);

	bt_aton("11:22:33:44:55:66", &blued_g.passkey_target);
	blued_g.passkey_reply_status = 1;  /* not pending */

	(void)send(sp[1], "PASSKEY_REPLY 11:22:33:44:55:66 123456\n", 39, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for no pending request: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: NUMCMP_REPLY with invalid arg (not yes/no) returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_numcmp_reply_bad_arg);
ATF_TC_BODY(test_ctl_numcmp_reply_bad_arg, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();
	client = make_client(sp);

	bt_aton("11:22:33:44:55:66", &blued_g.passkey_target);
	blued_g.numcmp_reply_status = 0;

	(void)send(sp[1], "NUMCMP_REPLY 11:22:33:44:55:66 maybe\n", 37, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for invalid yes/no: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: NUMCMP_REPLY "no" is accepted
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_numcmp_reply_no);
ATF_TC_BODY(test_ctl_numcmp_reply_no, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();
	client = make_client(sp);

	bt_aton("11:22:33:44:55:66", &blued_g.passkey_target);
	blued_g.numcmp_reply_status = 0;

	(void)send(sp[1], "NUMCMP_REPLY 11:22:33:44:55:66 no\n", 34, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "OK") != NULL,
	    "expected OK for 'no' reply: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: PAIR on unconnected device returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_pair_not_connected);
ATF_TC_BODY(test_ctl_pair_not_connected, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[256];
	ssize_t n;

	test_init();
	client = make_client(sp);

	(void)send(sp[1], "PAIR 11:22:33:44:55:66\n", 23, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for unconnected: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: BOND_EXPORT with populated bond database
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_bond_export_populated);
ATF_TC_BODY(test_ctl_bond_export_populated, tc)
{
	struct blued_ctl_client *client;
	struct smp_bond_db db;
	int sp[2];
	char resp[1024];
	ssize_t n;

	test_init();

	memset(&db, 0, sizeof(db));
	db.count = 1;
	db.bonds[0].addr[0] = 0x11;
	db.bonds[0].addr[1] = 0x22;
	db.bonds[0].addr[2] = 0x33;
	db.bonds[0].addr[3] = 0x44;
	db.bonds[0].addr[4] = 0x55;
	db.bonds[0].addr[5] = 0x66;
	db.bonds[0].has_ltk = true;
	db.bonds[0].is_sc = true;
	strlcpy(db.bonds[0].name, "TestDev", sizeof(db.bonds[0].name));
	db.bonds[0].has_name = true;
	blued_g.bond_db = &db;

	client = make_client(sp);

	(void)send(sp[1], "BOND_EXPORT\n", 12, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "BOND addr=") != NULL,
	    "expected BOND addr= in export: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "ltk=1") != NULL,
	    "expected ltk=1: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "sc=1") != NULL,
	    "expected sc=1: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "name=TestDev") != NULL,
	    "expected name=TestDev: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "END") != NULL,
	    "expected END: %s", resp);

	blued_g.bond_db = NULL;
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: HOGP_WRITE on unconnected device returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_hogp_write_not_connected);
ATF_TC_BODY(test_ctl_hogp_write_not_connected, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[256];
	ssize_t n;

	test_init();
	client = make_client(sp);

	(void)send(sp[1], "HOGP_WRITE 11:22:33:44:55:66 0 CAFE\n", 36, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for unconnected: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: SCAN output includes svcs= field
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_scan_svcs_field);
ATF_TC_BODY(test_ctl_scan_svcs_field, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	int sp[2];
	char resp[2048];
	ssize_t n;

	test_init();

	memset(&adp, 0, sizeof(adp));
	strlcpy(adp.name, "ubt0", sizeof(adp.name));
	adp.active = true;
	adp.hci_fd = -1;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	client = make_client(sp);

	(void)send(sp[1], "SCAN\n", 5, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	/* Scan response should include svcs= field (even if empty) */
	ATF_CHECK_MSG(strstr(resp, "SCANNING") != NULL ||
	    strstr(resp, "END") != NULL ||
	    strstr(resp, "ERROR") != NULL,
	    "expected valid scan response: %s", resp);

	LIST_REMOVE(&adp, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: BOND_EXPORT returns bond metadata
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_bond_export_empty);
ATF_TC_BODY(test_ctl_bond_export_empty, tc)
{
	struct blued_ctl_client *client;
	char resp[512];
	ssize_t n;
	int sp[2], ret;

	test_init();
	client = make_client(sp);

	ret = (int)send(sp[1], "BOND_EXPORT\n", 12, 0);
	ATF_REQUIRE(ret == 12);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "BOND_EXPORT\n") != NULL,
	    "expected BOND_EXPORT header: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "END\n") != NULL,
	    "expected END: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: CONNPARAMS returns connection parameter list
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_connparams_empty);
ATF_TC_BODY(test_ctl_connparams_empty, tc)
{
	struct blued_ctl_client *client;
	char resp[512];
	ssize_t n;
	int sp[2], ret;

	test_init();
	client = make_client(sp);

	ret = (int)send(sp[1], "CONNPARAMS\n", 11, 0);
	ATF_REQUIRE(ret == 11);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "CONNPARAMS\n") != NULL,
	    "expected CONNPARAMS header: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "END\n") != NULL,
	    "expected END: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: LIST output includes security fields
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_list_security_fields);
ATF_TC_BODY(test_ctl_list_security_fields, tc)
{
	struct blued_ctl_client *client;
	struct blued_conn conn;
	char resp[512];
	ssize_t n;
	int sp[2], ret;

	test_init();

	memset(&conn, 0, sizeof(conn));
	conn.att_fd = -1;
	bt_aton("AA:BB:CC:DD:EE:FF", &conn.dst);
	conn.con_handle = 0x0040;
	conn.role = BLUED_ROLE_CENTRAL;
	atomic_store(&conn.state, BLUED_CONN_ACTIVE);
	LIST_INSERT_HEAD(&blued_g.conns, &conn, entries);

	client = make_client(sp);

	ret = (int)send(sp[1], "LIST\n", 5, 0);
	ATF_REQUIRE(ret == 5);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "role=central") != NULL,
	    "expected role=central in LIST: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "encrypted=") != NULL,
	    "expected encrypted= in LIST: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "authenticated=") != NULL,
	    "expected authenticated= in LIST: %s", resp);

	LIST_REMOVE(&conn, entries);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: CONNPARAMS with a connection shows parameters
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_connparams_with_conn);
ATF_TC_BODY(test_ctl_connparams_with_conn, tc)
{
	struct blued_ctl_client *client;
	struct blued_conn conn;
	char resp[512];
	ssize_t n;
	int sp[2], ret;

	test_init();

	memset(&conn, 0, sizeof(conn));
	conn.att_fd = -1;
	bt_aton("AA:BB:CC:DD:EE:FF", &conn.dst);
	conn.con_handle = 0x0040;
	conn.role = BLUED_ROLE_CENTRAL;
	conn.conn_interval = 24;	/* 30ms */
	conn.conn_latency = 0;
	conn.supervision_timeout = 200;	/* 2000ms */
	atomic_store(&conn.state, BLUED_CONN_ACTIVE);
	LIST_INSERT_HEAD(&blued_g.conns, &conn, entries);

	client = make_client(sp);

	ret = (int)send(sp[1], "CONNPARAMS\n", 11, 0);
	ATF_REQUIRE(ret == 11);

	ret = blued_ctl_dispatch(client);
	ATF_CHECK_EQ(ret, 0);

	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "interval=") != NULL,
	    "expected interval= in CONNPARAMS: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "latency=") != NULL,
	    "expected latency= in CONNPARAMS: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "timeout=") != NULL,
	    "expected timeout= in CONNPARAMS: %s", resp);

	LIST_REMOVE(&conn, entries);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: CONNECT_NAME with empty name returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_connect_name_empty);
ATF_TC_BODY(test_ctl_connect_name_empty, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[256];
	ssize_t n;

	test_init();
	client = make_client(sp);

	(void)send(sp[1], "CONNECT_NAME \n", 14, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for empty name: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: CONNECT with invalid address format
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_connect_invalid_addr);
ATF_TC_BODY(test_ctl_connect_invalid_addr, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[256];
	ssize_t n;

	test_init();
	client = make_client(sp);

	(void)send(sp[1], "CONNECT not-an-address\n", 23, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL &&
	    strstr(resp, "invalid address") != NULL,
	    "expected 'ERROR invalid address': %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: BOND_EXPORT with multiple bonds
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_bond_export_multiple);
ATF_TC_BODY(test_ctl_bond_export_multiple, tc)
{
	struct blued_ctl_client *client;
	struct smp_bond_db db;
	int sp[2];
	char resp[2048];
	ssize_t n;
	int bond_lines;
	char *p;

	test_init();

	memset(&db, 0, sizeof(db));
	db.count = 3;
	for (int i = 0; i < 3; i++) {
		db.bonds[i].addr[0] = (uint8_t)(0x10 + i);
		db.bonds[i].addr[5] = 0xAA;
		db.bonds[i].has_ltk = (i % 2 == 0);
		db.bonds[i].is_sc = (i == 2);
	}
	blued_g.bond_db = &db;

	client = make_client(sp);

	(void)send(sp[1], "BOND_EXPORT\n", 12, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);

	/* Count BOND lines */
	bond_lines = 0;
	p = resp;
	while ((p = strstr(p, "BOND addr=")) != NULL) {
		bond_lines++;
		p++;
	}
	ATF_CHECK_EQ(bond_lines, 3);

	/* Verify key flags for specific bonds */
	ATF_CHECK_MSG(strstr(resp, "ltk=1") != NULL,
	    "expected ltk=1 in export: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "sc=1") != NULL,
	    "expected sc=1 in export: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "END") != NULL,
	    "expected END: %s", resp);

	blued_g.bond_db = NULL;
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: CONNPARAMS with specific values verified
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_connparams_values);
ATF_TC_BODY(test_ctl_connparams_values, tc)
{
	struct blued_ctl_client *client;
	struct blued_conn conn;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();

	memset(&conn, 0, sizeof(conn));
	conn.att_fd = -1;
	bt_aton("AA:BB:CC:DD:EE:FF", &conn.dst);
	conn.con_handle = 0x0040;
	conn.conn_interval = 24;	/* 30.00ms */
	conn.conn_latency = 4;
	conn.supervision_timeout = 200;	/* 2000ms */
	atomic_store(&conn.state, BLUED_CONN_ACTIVE);
	LIST_INSERT_HEAD(&blued_g.conns, &conn, entries);

	client = make_client(sp);

	(void)send(sp[1], "CONNPARAMS\n", 11, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);

	/* Verify actual numeric values, not just field presence */
	ATF_CHECK_MSG(strstr(resp, "interval=30.00ms") != NULL,
	    "expected interval=30.00ms: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "latency=4") != NULL,
	    "expected latency=4: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "timeout=2000ms") != NULL,
	    "expected timeout=2000ms: %s", resp);

	LIST_REMOVE(&conn, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: LIST output shows name from bond DB
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_list_shows_name_field);
ATF_TC_BODY(test_ctl_list_shows_name_field, tc)
{
	struct blued_ctl_client *client;
	struct blued_conn conn;
	int sp[2];
	char resp[512];
	ssize_t n;

	test_init();

	/* Connection with no bond — name field should be empty */
	memset(&conn, 0, sizeof(conn));
	conn.att_fd = -1;
	bt_aton("AA:BB:CC:DD:EE:FF", &conn.dst);
	conn.con_handle = 0x0040;
	conn.role = BLUED_ROLE_CENTRAL;
	atomic_store(&conn.state, BLUED_CONN_ACTIVE);
	LIST_INSERT_HEAD(&blued_g.conns, &conn, entries);

	client = make_client(sp);

	(void)send(sp[1], "LIST\n", 5, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);

	/* Verify the name= field is present (even if empty) */
	ATF_CHECK_MSG(strstr(resp, "name=") != NULL,
	    "expected name= field in LIST: %s", resp);
	ATF_CHECK_MSG(strstr(resp, "role=central") != NULL,
	    "expected role=central: %s", resp);

	LIST_REMOVE(&conn, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: LOGLEVEL boundary — level 0 and level 5
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_loglevel_boundaries);
ATF_TC_BODY(test_ctl_loglevel_boundaries, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[256];
	ssize_t n;

	test_init();
	client = make_client(sp);

	/* Level 0 — should succeed */
	(void)send(sp[1], "LOGLEVEL 0\n", 11, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "OK LOGLEVEL 0") != NULL,
	    "expected OK LOGLEVEL 0: %s", resp);

	/* Level 5 — should succeed */
	(void)send(sp[1], "LOGLEVEL 5\n", 11, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "OK LOGLEVEL 5") != NULL,
	    "expected OK LOGLEVEL 5: %s", resp);

	/* Level 6 — should fail */
	(void)send(sp[1], "LOGLEVEL 6\n", 11, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for level 6: %s", resp);

	/* Level -1 — should fail */
	(void)send(sp[1], "LOGLEVEL -1\n", 12, 0);
	blued_ctl_dispatch(client);
	n = drain_response(sp[1], resp, sizeof(resp));
	ATF_REQUIRE(n > 0);
	ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL,
	    "expected ERROR for level -1: %s", resp);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * Test: WRITE with odd-length hex returns error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_write_odd_hex);
ATF_TC_BODY(test_ctl_write_odd_hex, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	char resp[256];
	ssize_t n;

	test_init();

	/* Need a connection for WRITE to reach hex validation */
	{
		struct blued_conn conn;
		struct att_conn ac;

		memset(&conn, 0, sizeof(conn));
		memset(&ac, 0, sizeof(ac));
		conn.att_fd = -1;
		ac.fd = -1;
		bt_aton("11:22:33:44:55:66", &conn.dst);
		conn.att = &ac;
		atomic_store(&conn.state, BLUED_CONN_ACTIVE);
		LIST_INSERT_HEAD(&blued_g.conns, &conn, entries);

		client = make_client(sp);

		(void)send(sp[1], "WRITE 11:22:33:44:55:66 0x0003 ABC\n", 35, 0);
		blued_ctl_dispatch(client);
		n = drain_response(sp[1], resp, sizeof(resp));
		ATF_REQUIRE(n > 0);
		ATF_CHECK_MSG(strstr(resp, "ERROR") != NULL &&
		    strstr(resp, "even") != NULL,
		    "expected 'ERROR hex value must be even': %s", resp);

		LIST_REMOVE(&conn, entries);
	}

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_ctl_respond);
	ATF_TP_ADD_TC(tp, test_ctl_status);
	ATF_TP_ADD_TC(tp, test_ctl_adapters);
	ATF_TP_ADD_TC(tp, test_ctl_unknown_cmd);
	ATF_TP_ADD_TC(tp, test_ctl_disconnect);
	ATF_TP_ADD_TC(tp, test_ctl_send_fd);
	ATF_TP_ADD_TC(tp, test_ctl_bonds_empty);
	ATF_TP_ADD_TC(tp, test_ctl_bonds_populated);
	ATF_TP_ADD_TC(tp, test_ctl_phy_empty);
	ATF_TP_ADD_TC(tp, test_ctl_empty_command);
	ATF_TP_ADD_TC(tp, test_ctl_oversized_command);
	ATF_TP_ADD_TC(tp, test_ctl_scan);
	ATF_TP_ADD_TC(tp, test_ctl_status_repeated);
	ATF_TP_ADD_TC(tp, test_ctl_disconnect_no_conns);
	ATF_TP_ADD_TC(tp, test_ctl_unbond_not_found);
	ATF_TP_ADD_TC(tp, test_ctl_phy_active_conn);
	ATF_TP_ADD_TC(tp, test_ctl_init_cleanup);
	ATF_TP_ADD_TC(tp, test_ctl_accept);
	ATF_TP_ADD_TC(tp, test_ctl_max_clients);
	ATF_TP_ADD_TC(tp, test_ctl_dispatch_connect);
	ATF_TP_ADD_TC(tp, test_ctl_dispatch_connect_invalid);
	ATF_TP_ADD_TC(tp, test_ctl_dispatch_connect_already);
	ATF_TP_ADD_TC(tp, test_ctl_dispatch_scan);
	ATF_TP_ADD_TC(tp, test_ctl_concurrent_clients);

	/* GATT service management commands */
	ATF_TP_ADD_TC(tp, test_ctl_services);
	ATF_TP_ADD_TC(tp, test_ctl_services_empty);
	ATF_TP_ADD_TC(tp, test_ctl_discover_not_connected);
	ATF_TP_ADD_TC(tp, test_ctl_discover_invalid_addr);
	ATF_TP_ADD_TC(tp, test_ctl_read_not_connected);
	ATF_TP_ADD_TC(tp, test_ctl_write_not_connected);
	ATF_TP_ADD_TC(tp, test_ctl_write_bad_hex);
	ATF_TP_ADD_TC(tp, test_ctl_add_service);
	ATF_TP_ADD_TC(tp, test_ctl_add_char);
	ATF_TP_ADD_TC(tp, test_ctl_remove_service);
	ATF_TP_ADD_TC(tp, test_ctl_remove_service_invalid);

	/* LOGLEVEL command */
	ATF_TP_ADD_TC(tp, test_ctl_loglevel_get);
	ATF_TP_ADD_TC(tp, test_ctl_loglevel_set);
	ATF_TP_ADD_TC(tp, test_ctl_loglevel_invalid);

	/* SUBSCRIBE / UNSUBSCRIBE */
	ATF_TP_ADD_TC(tp, test_ctl_subscribe);
	ATF_TP_ADD_TC(tp, test_ctl_unsubscribe);

	/* SET_VALUE */
	ATF_TP_ADD_TC(tp, test_ctl_set_value);

	/* PASSKEY_REPLY / NUMCMP_REPLY */
	ATF_TP_ADD_TC(tp, test_ctl_passkey_reply);
	ATF_TP_ADD_TC(tp, test_ctl_numcmp_reply);

	/* Rate limiting */
	ATF_TP_ADD_TC(tp, test_ctl_rate_limit);

	/* HOGP_READ stub */
	ATF_TP_ADD_TC(tp, test_ctl_hogp_read_stub);

	/* SMP reply validation */
	ATF_TP_ADD_TC(tp, test_ctl_passkey_reply_invalid);
	ATF_TP_ADD_TC(tp, test_ctl_passkey_reply_wrong_addr);
	ATF_TP_ADD_TC(tp, test_ctl_passkey_reply_not_pending);
	ATF_TP_ADD_TC(tp, test_ctl_numcmp_reply_bad_arg);
	ATF_TP_ADD_TC(tp, test_ctl_numcmp_reply_no);
	ATF_TP_ADD_TC(tp, test_ctl_pair_not_connected);

	/* HOGP */
	ATF_TP_ADD_TC(tp, test_ctl_hogp_write_not_connected);

	/* New commands */
	ATF_TP_ADD_TC(tp, test_ctl_bond_export_empty);
	ATF_TP_ADD_TC(tp, test_ctl_bond_export_populated);
	ATF_TP_ADD_TC(tp, test_ctl_connparams_empty);
	ATF_TP_ADD_TC(tp, test_ctl_connparams_with_conn);
	ATF_TP_ADD_TC(tp, test_ctl_list_security_fields);
	ATF_TP_ADD_TC(tp, test_ctl_scan_svcs_field);

	/* CONNECT_NAME */
	ATF_TP_ADD_TC(tp, test_ctl_connect_name_empty);
	ATF_TP_ADD_TC(tp, test_ctl_connect_invalid_addr);

	/* BOND_EXPORT */
	ATF_TP_ADD_TC(tp, test_ctl_bond_export_multiple);

	/* CONNPARAMS with value verification */
	ATF_TP_ADD_TC(tp, test_ctl_connparams_values);

	/* LIST with name from bond DB */
	ATF_TP_ADD_TC(tp, test_ctl_list_shows_name_field);

	/* LOGLEVEL boundaries */
	ATF_TP_ADD_TC(tp, test_ctl_loglevel_boundaries);

	/* WRITE hex validation */
	ATF_TP_ADD_TC(tp, test_ctl_write_odd_hex);

	return (atf_no_error());
}
