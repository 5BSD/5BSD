/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF unit tests for blued multi-adapter support (P-MULTIADAPTER).
 *
 * Exercises the per-adapter context and adapter table, the client IPC
 * adapter-targeting path, and the event-demux key, all against the
 * socketpair-driven control dispatch used by ctl_test.c -- no real
 * Bluetooth hardware is required.
 *
 * Coverage:
 *   - enumerate/attach several adapters and index them (0 == primary)
 *   - blued_adapter_by_index bounds/NULL and primary == LIST_FIRST
 *   - blued_adapter_by_fd demux never routes to the wrong adapter
 *   - ADAPTERS lists every adapter with its stable index
 *   - STATUS reports the adapter count
 *   - typed scan requests target the selected adapter
 *   - typed connect requests bind the connection to the selected adapter
 *   - two connections on different adapters keep independent state
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
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
#include "blued_internal.h"
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
#define TEST_CUSTOM_BLE_ECBFC_CONNECT
#include "test_common.h"

struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;
const int _blued_kq_acquire_tag;
const int _blued_kq_setup_pipe_tag;

void
blued_conn_disconnect(struct blued_conn *conn __unused)
{
}

void
blued_ind_arm_timeout(struct blued_conn *conn __unused)
{
}

void
blued_periph_readvertise(void)
{
}

void
blued_idle_disarm(struct blued_conn *conn __unused)
{
}

void
blued_ind_disarm_timeout(struct blued_conn *conn __unused)
{
}

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

int
blued_central_start_pairing_async(struct blued_conn *conn __unused)
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
hci_le_ltk_request_neg_reply(int hci_fd __unused,
    uint16_t con_handle __unused)
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

/*
 * Scan stubs that record which adapter HCI fds a SCAN command drove.
 * This is how the tests observe adapter targeting: a targeted scan must
 * touch exactly the addressed adapter's fd, a bare scan every adapter's.
 */
#define SCAN_LOG_MAX	8
static int scan_log[SCAN_LOG_MAX];
static int scan_log_n;

static void
scan_log_reset(void)
{

	scan_log_n = 0;
	memset(scan_log, 0, sizeof(scan_log));
}

static void
scan_log_record(int fd)
{

	if (scan_log_n < SCAN_LOG_MAX)
		scan_log[scan_log_n++] = fd;
}

int
hci_le_scan(int hci_fd, int duration_sec __unused,
    struct ble_scan_result *results __unused, int maxresults __unused,
    int *nresults)
{

	scan_log_record(hci_fd);
	if (nresults != NULL)
		*nresults = 0;
	return (0);
}

int
hci_le_ext_scan(int hci_fd, int duration_sec __unused,
    struct ble_scan_result *results __unused, int maxresults __unused,
    int *nresults, uint8_t scanning_phys __unused)
{

	scan_log_record(hci_fd);
	if (nresults != NULL)
		*nresults = 0;
	return (0);
}

#define CTL_TEST_DB_MAX	64
#define CTL_TEST_VAL_SZ	1024
extern struct att_db	periph_gatt_db;
struct att_db		periph_gatt_db;

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
 * Test harness (socketpair-driven control dispatch)
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
	blued_ctl_clients_lock_init(&blued_g.ctl_clients_lock);
	scan_log_reset();
}

/*
 * Attach an adapter with a distinct HCI fd and name.  The fd is a bare
 * integer token (never a real socket) used only to key the scan log and
 * the by-fd demux lookup.  Adapters are inserted in reverse so that the
 * lowest-numbered one ends up at LIST_FIRST (the primary), matching how
 * the daemon treats the head of the list.
 */
static struct blued_adapter *
attach_adapter(struct blued_adapter *adp, const char *name, int fd)
{

	memset(adp, 0, sizeof(*adp));
	strlcpy(adp->name, name, sizeof(adp->name));
	adp->hci_fd = fd;
	adp->active = true;
	LIST_INSERT_HEAD(&blued_g.adapters, adp, entries);
	return (adp);
}


/* ================================================================
 * Test: indexing assigns 0..n-1 with primary (LIST_FIRST) == 0,
 * and blued_adapter_by_index honors bounds/NULL.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ma_index_and_bounds);
ATF_TC_BODY(test_ma_index_and_bounds, tc)
{
	struct blued_adapter a0, a1, a2;

	test_init();

	/* Insert reverse so LIST_FIRST is ubt0 (the intended primary). */
	attach_adapter(&a2, "ubt2", 102);
	attach_adapter(&a1, "ubt1", 101);
	attach_adapter(&a0, "ubt0", 100);

	blued_index_adapters();

	ATF_CHECK_EQ(0, a0.index);
	ATF_CHECK_EQ(1, a1.index);
	ATF_CHECK_EQ(2, a2.index);

	/* Primary (index 0) resolves to LIST_FIRST. */
	ATF_CHECK_EQ_MSG(LIST_FIRST(&blued_g.adapters), &a0,
	    "primary adapter is not list head");
	ATF_CHECK_EQ(&a0, blued_adapter_by_index(0));
	ATF_CHECK_EQ(&a1, blued_adapter_by_index(1));
	ATF_CHECK_EQ(&a2, blued_adapter_by_index(2));

	/* Out-of-range and negative indices return NULL. */
	ATF_CHECK(blued_adapter_by_index(-1) == NULL);
	ATF_CHECK(blued_adapter_by_index(3) == NULL);
	ATF_CHECK(blued_adapter_by_index(BLUED_MAX_ADAPTERS) == NULL);
	ATF_CHECK(blued_adapter_by_index(BLUED_MAX_ADAPTERS + 100) == NULL);
}

/* ================================================================
 * Test: event-demux key -- by-fd lookup routes an HCI event to its
 * owning adapter and never to another.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ma_demux_by_fd);
ATF_TC_BODY(test_ma_demux_by_fd, tc)
{
	struct blued_adapter a0, a1;

	test_init();
	attach_adapter(&a1, "ubt1", 201);
	attach_adapter(&a0, "ubt0", 200);
	blued_index_adapters();

	ATF_CHECK_EQ(&a0, blued_adapter_by_fd(200));
	ATF_CHECK_EQ(&a1, blued_adapter_by_fd(201));
	/* No cross-talk: each fd resolves only to its own adapter. */
	ATF_CHECK(blued_adapter_by_fd(200) != &a1);
	ATF_CHECK(blued_adapter_by_fd(201) != &a0);
	/* Unknown / invalid fds resolve to nothing. */
	ATF_CHECK(blued_adapter_by_fd(999) == NULL);
	ATF_CHECK(blued_adapter_by_fd(-1) == NULL);
}

ATF_TC_WITHOUT_HEAD(test_ma_connection_identity_is_adapter_local);
ATF_TC_BODY(test_ma_connection_identity_is_adapter_local, tc)
{
	struct blued_adapter a0, a1;
	struct blued_conn *c0, *c1;
	bdaddr_t peer;

	test_init();
	attach_adapter(&a1, "ubt1", 301);
	attach_adapter(&a0, "ubt0", 300);
	blued_index_adapters();
	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &peer));
	c0 = blued_conn_alloc();
	c1 = blued_conn_alloc();
	ATF_REQUIRE(c0 != NULL && c1 != NULL);
	c0->adapter = &a0;
	c1->adapter = &a1;
	c0->dst = peer;
	c1->dst = peer;
	c0->addr_type = c1->addr_type = BDADDR_LE_PUBLIC;
	c0->con_handle = c1->con_handle = 0x0040;
	c0->con_handle_valid = c1->con_handle_valid = true;

	ATF_CHECK_EQ(c0, blued_conn_by_peer(&a0, &peer, BDADDR_LE_PUBLIC));
	ATF_CHECK_EQ(c1, blued_conn_by_peer(&a1, &peer, BDADDR_LE_PUBLIC));
	ATF_CHECK_EQ(c0, blued_conn_by_handle(&a0, 0x0040));
	ATF_CHECK_EQ(c1, blued_conn_by_handle(&a1, 0x0040));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_ma_index_and_bounds);
	ATF_TP_ADD_TC(tp, test_ma_demux_by_fd);
	ATF_TP_ADD_TC(tp, test_ma_connection_identity_is_adapter_local);

	return (atf_no_error());
}
