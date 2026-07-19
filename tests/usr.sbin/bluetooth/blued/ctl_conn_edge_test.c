/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF edge-case tests for the blued connection lifecycle primitives.
 * These cover allocation, lookup, state transitions, registration, and
 * owned ATT cleanup directly through conn.c.
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
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
#include "blued_internal.h"
#include "ble_util.h"
#include "config.h"
#include "conn.h"
#include "gatt.h"
#include "hci_log.h"
#include "hci_util.h"
#include "ctl.h"
#include "ctl_internal.h"
#include "smp.h"

/* ================================================================
 * Stubs for external symbols referenced by ctl.c / ctl_conn.c /
 * ctl_gatt.c / conn.c.  Mirrors ctl_test.c so the same link set builds.
 * ================================================================ */

#define TEST_LINKS_CTL
#define TEST_CUSTOM_BLE_ECBFC_CONNECT
#include "test_common.h"

struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;
const int _blued_kq_acquire_tag;
const int _blued_kq_setup_pipe_tag;

void blued_conn_disconnect(struct blued_conn *conn __unused) {}
void blued_ind_arm_timeout(struct blued_conn *conn __unused) {}
void blued_periph_readvertise(void) {}
void blued_idle_disarm(struct blued_conn *conn __unused) {}
void blued_ind_disarm_timeout(struct blued_conn *conn __unused) {}

void *
blued_conn_setup_central(void *arg __unused)
{
	return (NULL);
}

int
blued_central_start_pairing(struct hogp_device *dev __unused,
    struct blued_conn *conn __unused)
{
	return (-1);
}

void *
blued_conn_setup_peripheral(void *arg __unused)
{
	return (NULL);
}

uint16_t
hogp_find_feature_handle(struct blued_conn *conn __unused,
    uint8_t report_id __unused)
{
	return (0);
}

struct hogp_device *
blued_hogp_alloc(struct blued_adapter *adp __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused,
    bool reconnect __unused)
{
	return (calloc(1, 256));
}

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
hci_le_ltk_request_neg_reply(int hci_fd __unused, uint16_t con_handle __unused)
{
	return (-1);
}

int
ble_ecbfc_connect(const uint8_t *local_addr __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused,
    uint16_t psm __unused, uint16_t mtu __unused,
    int count __unused, int *fds __unused)
{
	return (-1);
}

int
ble_iso_connect(const uint8_t *src __unused, const uint8_t *addr __unused,
    uint8_t addr_type __unused, uint16_t cis_handle __unused,
    uint16_t mtu __unused)
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
    int *nresults, uint8_t scanning_phys __unused)
{
	if (nresults != NULL)
		*nresults = 0;
	return (0);
}

extern struct att_db	periph_gatt_db;
struct att_db		periph_gatt_db;

struct smp_bond *
smp_find_bond(struct smp_bond_db *db __unused, const uint8_t *addr __unused,
    uint8_t addr_type __unused)
{
	return (NULL);
}

int
smp_bond_db_save(struct smp_bond_db *db __unused)
{
	return (0);
}

void
smp_bond_save_cccds(struct smp_bond *bond __unused,
    const struct att_conn *ac __unused)
{
}

int
smp_open(struct smp_conn *sc __unused, const uint8_t *addr __unused,
    uint8_t addr_type __unused, const uint8_t *local_addr __unused,
    uint8_t local_addr_type __unused, int hci_fd __unused,
    uint16_t con_handle __unused, struct smp_bond_db *db __unused)
{
	return (-1);
}

void
smp_close(struct smp_conn *sc __unused)
{
}

int
smp_pair(struct smp_conn *sc __unused)
{
	return (-1);
}

int
hci_le_remove_device_from_filter_accept_list(int hci_fd __unused,
    uint8_t addr_type __unused, const uint8_t addr[6] __unused)
{
	return (0);
}

void
blued_reslist_sync_remove(int hci_fd __unused, const uint8_t addr[6] __unused,
    uint8_t addr_type __unused)
{
}

int
hci_le_read_phy(int hci_fd __unused, uint16_t con_handle __unused,
    uint8_t *tx_phy, uint8_t *rx_phy)
{
	if (tx_phy != NULL)
		*tx_phy = 0x01;
	if (rx_phy != NULL)
		*rx_phy = 0x01;
	return (0);
}

/* ================================================================
 * Harness helpers
 * ================================================================ */
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

/* ================================================================
 * conn.c — direct unit tests
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_conn_set_state_transitions);
ATF_TC_BODY(edge_conn_set_state_transitions, tc)
{
	struct blued_conn conn;

	memset(&conn, 0, sizeof(conn));
	conn.con_handle = 0x0040;
	conn.state = BLUED_CONN_IDLE;

	/* No-op transition (same state) returns early. */
	blued_conn_set_state(&conn, BLUED_CONN_IDLE);
	ATF_CHECK_EQ(atomic_load(&conn.state), BLUED_CONN_IDLE);

	/* Walk every named state, plus an out-of-range value. */
	blued_conn_set_state(&conn, BLUED_CONN_CONNECTING);
	blued_conn_set_state(&conn, BLUED_CONN_ACTIVE);
	blued_conn_set_state(&conn, BLUED_CONN_RECONNECTING);
	blued_conn_set_state(&conn, 99);	/* "UNKNOWN" name */
	ATF_CHECK_EQ(atomic_load(&conn.state), 99);
}

ATF_TC_WITHOUT_HEAD(edge_conn_alloc_free_and_by_addr);
ATF_TC_BODY(edge_conn_alloc_free_and_by_addr, tc)
{
	struct blued_conn *c;
	struct blued_adapter adapter = { .index = 0 };
	bdaddr_t addr, other;

	test_init();
	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &addr));
	ATF_REQUIRE(bt_aton("aa:bb:cc:dd:ee:ff", &other));

	c = blued_conn_alloc();
	ATF_REQUIRE(c != NULL);
	memcpy(&c->dst, &addr, sizeof(c->dst));
	c->adapter = &adapter;
	c->addr_type = BDADDR_LE_PUBLIC;

	/* by_addr hit and miss. */
	ATF_CHECK(blued_conn_by_peer(&adapter, &addr, BDADDR_LE_PUBLIC) == c);
	ATF_CHECK(blued_conn_by_peer(&adapter, &other, BDADDR_LE_PUBLIC) == NULL);

	blued_conn_free(c);
	/* After free the address is no longer found. */
	ATF_CHECK(blued_conn_by_peer(&adapter, &addr, BDADDR_LE_PUBLIC) == NULL);
}

ATF_TC_WITHOUT_HEAD(edge_conn_alloc_limit);
ATF_TC_BODY(edge_conn_alloc_limit, tc)
{
	struct blued_conn *conns[BLUED_MAX_CONNS];
	struct blued_conn *over;
	int i;

	test_init();
	for (i = 0; i < BLUED_MAX_CONNS; i++) {
		conns[i] = blued_conn_alloc();
		ATF_REQUIRE(conns[i] != NULL);
	}
	/* One past the limit fails with ENOSPC. */
	errno = 0;
	over = blued_conn_alloc();
	ATF_CHECK(over == NULL);
	ATF_CHECK_EQ(errno, ENOSPC);

	for (i = 0; i < BLUED_MAX_CONNS; i++)
		blued_conn_free(conns[i]);
}

ATF_TC_WITHOUT_HEAD(edge_conn_register);
ATF_TC_BODY(edge_conn_register, tc)
{
	struct blued_conn *c;
	int kq, sv[2];

	test_init();

	/* att_fd < 0 -> immediate failure. */
	c = blued_conn_alloc();
	ATF_REQUIRE(c != NULL);
	c->att_fd = -1;
	ATF_CHECK(blued_conn_register(c) < 0);

	/* Registration against a bad kqueue fd fails at kevent(). */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	c->att_fd = sv[0];
	blued_g.kq = -1;
	ATF_CHECK(blued_conn_register(c) < 0);

	/* Registration against a real kqueue succeeds. */
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	blued_g.kq = kq;
	ATF_CHECK_EQ(blued_conn_register(c), 0);

	close(kq);
	close(sv[0]);
	close(sv[1]);
	blued_conn_free(c);
}

ATF_TC_WITHOUT_HEAD(edge_conn_free_att_owned);
ATF_TC_BODY(edge_conn_free_att_owned, tc)
{
	struct blued_conn *c;
	struct att_conn *ac;

	test_init();
	c = blued_conn_alloc();
	ATF_REQUIRE(c != NULL);

	/* Peripheral-style conn: att_owned with an fd and a buffer. */
	ac = calloc(1, sizeof(*ac));
	ATF_REQUIRE(ac != NULL);
	ac->fd = -1;			/* no real fd to close */
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	c->att_owned = ac;

	/* free must release att_owned (fd, buffer, struct) without leaking. */
	blued_conn_free(c);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, edge_conn_set_state_transitions);
	ATF_TP_ADD_TC(tp, edge_conn_alloc_free_and_by_addr);
	ATF_TP_ADD_TC(tp, edge_conn_alloc_limit);
	ATF_TP_ADD_TC(tp, edge_conn_register);
	ATF_TP_ADD_TC(tp, edge_conn_free_att_owned);

	return (atf_no_error());
}
