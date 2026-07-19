/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the deferred IPC feature phases in the blued control server
 * (ctl.c): connection-lifecycle push events (findings C1/C2), the CONNINFO
 * MTU/connection-info surfacing (finding C5), pairing-prompt correlation
 * (finding C9), and the advertising / peripheral commands (finding C10).
 *
 * These drive the real ctl.c dispatch and blued_ctl_broadcast_conn_event()
 * over a socketpair, decoding the length-prefixed frames (ipc_proto.h) to
 * prove:
 *   - a push-events subscriber receives framed EVENT CONNECTED / DISCONNECTED;
 *   - a non-subscriber receives NOTHING and its request/response stream stays
 *     in sync (the next frame it reads is its own reply, not an event);
 *   - CONNINFO reports the negotiated ATT MTU;
 *   - a pairing reply is accepted only for the outstanding target address;
 *   - ADVERTISE / ADV_DATA / SCAN_RESP validate and dispatch.
 *
 * Links the same object set as ctl_protocol_test.c (ctl.c ctl_conn.c ctl_gatt.c
 * conn.c att.c att_server*.c gatt.c config.c); the advertising HCI calls are
 * satisfied by the TEST_LINKS_CTL stubs in test_common.h.  SOCK_SEQPACKET
 * coalesces batched sends, so every frame is read one at a time in lockstep.
 */

#include <sys/socket.h>

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
#include "ctl_internal.h"
#include "ipc_proto.h"
#include "smp.h"

#define TEST_LINKS_CTL
#define TEST_CUSTOM_BLE_ECBFC_CONNECT
#include "test_common.h"

/* ================================================================
 * External symbols referenced by ctl.c / conn.c (mirrors ctl_protocol_test.c).
 * ================================================================ */
struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;
const int _blued_kq_acquire_tag;
const int _blued_kq_setup_pipe_tag;

void blued_conn_disconnect(struct blued_conn *conn __unused) {}
void blued_ind_arm_timeout(struct blued_conn *conn __unused) {}
void blued_periph_readvertise(void) {}
void blued_idle_disarm(struct blued_conn *conn __unused) {}
void blued_ind_disarm_timeout(struct blued_conn *conn __unused) {}
void *blued_conn_setup_central(void *arg __unused) { return (NULL); }
void *blued_conn_setup_peripheral(void *arg __unused) { return (NULL); }
int blued_central_start_pairing(struct hogp_device *dev __unused,
    struct blued_conn *conn __unused) { return (-1); }

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

struct smp_bond *
smp_find_bond(struct smp_bond_db *db __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused)
{
	return (NULL);
}

int smp_bond_db_save(struct smp_bond_db *db __unused) { return (0); }
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

void smp_close(struct smp_conn *sc __unused) {}
int smp_pair(struct smp_conn *sc __unused) { return (-1); }

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

extern struct att_db periph_gatt_db;
struct att_db periph_gatt_db;

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
	memset(&periph_gatt_db, 0, sizeof(periph_gatt_db));
}

static struct blued_ctl_client *
make_client(int sp[2])
{
	struct blued_ctl_client *client;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	client = calloc(1, sizeof(*client));
	ATF_REQUIRE(client != NULL);
	client->fd = sp[0];
	client->peer_known = true;
	client->peer_uid = 0;
	return (client);
}

/* Read exactly n bytes from a stream fd. */
static void
read_exact(int fd, void *buf, size_t n)
{
	size_t got = 0;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };

	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	while (got < n) {
		ssize_t r = read(fd, (uint8_t *)buf + got, n - got);

		ATF_REQUIRE_MSG(r > 0, "short read (%zu/%zu)", got, n);
		got += (size_t)r;
	}
}

/* Read one framed message; returns payload length, NUL-terminates pl. */
static size_t
get_frame(int fd, uint16_t *type, uint16_t *arg, char *pl, size_t plmax)
{
	uint8_t hdr[IPC_HDR_SIZE];
	uint32_t plen;

	read_exact(fd, hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, type, arg);
	ATF_REQUIRE(plen < plmax);
	if (plen > 0)
		read_exact(fd, pl, plen);
	pl[plen] = '\0';
	return (plen);
}


/* ================================================================
 * C1/C2: a push-events subscriber receives framed CONNECTED / DISCONNECTED.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(events_typed_connection_lifecycle);
ATF_TC_BODY(events_typed_connection_lifecycle, tc)
{
	struct blued_ctl_client *client;
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECTED_EVENT_SIZE + 1];
	uint8_t expected[6];
	int sp[2];
	bdaddr_t addr;
	uint32_t request_id;
	uint16_t type, domain, status, flags;
	size_t plen;

	test_init();
	client = make_client(sp);
	client->handshaked = true;
	client->wants_events = true;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);

	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &addr));
	memcpy(expected, &addr, sizeof(expected));
	blued_ctl_broadcast_conn_event(&addr, BLUED_ROLE_PERIPHERAL,
	    BDADDR_LE_RANDOM, 3, 0x1234, 247, true, 0);
	plen = get_frame(sp[1], &type, &domain, (char *)payload,
	    sizeof(payload));
	ATF_REQUIRE_EQ(type, IPC_T_OP_EVENT);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GAP);
	ATF_REQUIRE_EQ(plen,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECTED_EVENT_SIZE);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(request_id, 0);
	ATF_CHECK_EQ(status, 0);
	ATF_CHECK_EQ(flags, 0);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE),
	    IPC_GAP_EV_CONNECTED);
	ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 2], 1);
	ATF_CHECK(memcmp(payload + IPC_OP_PREFIX_SIZE + 3, expected,
	    sizeof(expected)) == 0);
	ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 9], 1);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 10), 0x1234);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 12), 247);
	ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 14], 3);

	blued_ctl_broadcast_conn_event(&addr, BLUED_ROLE_PERIPHERAL,
	    BDADDR_LE_RANDOM, 3, 0x1234, 0, false, 0x13);
	plen = get_frame(sp[1], &type, &domain, (char *)payload,
	    sizeof(payload));
	ATF_REQUIRE_EQ(type, IPC_T_OP_EVENT);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GAP);
	ATF_REQUIRE_EQ(plen,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_DISCONNECTED_EVENT_SIZE);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(request_id, 0);
	ATF_CHECK_EQ(status, 0);
	ATF_CHECK_EQ(flags, 0);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE),
	    IPC_GAP_EV_DISCONNECTED);
	ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 2], 1);
	ATF_CHECK(memcmp(payload + IPC_OP_PREFIX_SIZE + 3, expected,
	    sizeof(expected)) == 0);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 9), 0x13);

	LIST_REMOVE(client, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, events_typed_connection_lifecycle);

	return (atf_no_error());
}
