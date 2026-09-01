/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Real-IPC LOOPBACK integration test for the mesh advertising bearer
 * (broker step C).
 *
 * The two independently-built halves of the bearer are linked into ONE binary
 * and made to talk to each other over a REAL AF_UNIX socketpair -- no
 * hand-rolled framing stands in for either peer:
 *
 *   - blued's side is the REAL ctl.c mesh-bearer verb handling: the HELLO
 *     feature negotiation, MESH_ADV_SUBSCRIBE / MESH_ADV_SEND dispatch, the
 *     receive-side leak-filter demux (blued_mesh_demux_report) and the
 *     subscriber push path (blued_ctl_broadcast_mesh_adv).  Only the two HCI
 *     seams are captured (hci_mesh_adv_burst records the AD bytes that would
 *     hit the radio; hci_le_mesh_scan_set records the scanner toggles).
 *
 *   - meshd's side is the REAL meshd_bearer_blued.c client: the
 *     blocking HELLO+SUBSCRIBE handshake (meshd_blued_attach), the outbound
 *     class->adtype tx sink (meshd_blued_tx) and the inbound EVENT MESH_ADV
 *     receive pump (meshd_blued_pump_rx).  The three RX seams
 *     meshd_bearer_rx / meshd_beacon_rx / meshd_provisioner_recv are
 *     link-wrapped so the test observes exactly which seam each AD type
 *     reaches on the far side of the wire.
 *
 * What the loopback proves, over real socket I/O in both directions:
 *
 *   1. Inbound: a synthetic LE adv report carrying a mesh AD field is fed to
 *      the real blued demux, which emits EVENT MESH_ADV across the socket; the
 *      real meshd pump decodes it and dispatches to the correct RX seam by AD
 *      type (0x2A->bearer_rx, 0x2B->beacon_rx, 0x29->provisioner_recv).  The
 *      PDU bytes delivered to the seam == the bytes fed into the report.
 *
 *   2. Outbound: the real meshd tx sink sends a PDU; the wire carries
 *      MESH_ADV_SEND <adtype> <hex>; the real blued side validates the adtype
 *      and the captured HCI seam records the exact [len][adtype][pdu] burst.
 *      The PDU bytes out == the bytes the client handed its sink.  One
 *      round-trip per class (NET/BEACON/PROV).
 *
 *   3. Negatives that must hold across the real wire: a non-mesh adtype is
 *      rejected by blued and never reaches the radio; a non-mesh AD field in a
 *      report is NOT delivered to any subscriber (the leak filter holds); an
 *      unprivileged peer's MESH_ADV_SEND is refused before the radio.
 *
 * The blued verb dispatch does a blocking recv per frame, and the meshd
 * handshake blocks waiting for the HELLO reply, so the handshake window is
 * driven from a helper thread (the blued responder) while the main thread runs
 * the meshd client; after the handshake everything proceeds in lockstep (one
 * blued dispatch per meshd frame), which keeps the HCI-capture assertions
 * deterministic.
 */

#include <sys/types.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
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
#include "ipc_proto.h"
#include "smp.h"

/* meshd (client half) */
#include "mesh_test_heap.h"
#include "meshd.h"
#include "meshd_bearer_blued.h"

/*
 * Link the real ctl.c and provide capturing implementations of the mesh-bearer
 * HCI seam (rather than the pass-through defaults in test_common.h) so the
 * loopback can assert the exact advertising AD bytes that would reach the radio
 * and the always-on-scanner toggles.
 */
#define TEST_LINKS_CTL
#define TEST_CUSTOM_MESH_HCI
#define TEST_CUSTOM_BLE_ECBFC_CONNECT
#include "test_common.h"

struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;
const int _blued_kq_acquire_tag;
const int _blued_kq_setup_pipe_tag;

/* ================================================================
 * Captured blued-side HCI seam (the "radio").
 * ================================================================ */
static struct {
	int		burst_calls;
	uint8_t		burst_ad[64];
	uint8_t		burst_adlen;
	int		scan_on_calls;
	int		scan_off_calls;
	int		scan_error;
	bool		scan_last_on;
} mesh_cap;

static void
mesh_cap_reset(void)
{

	memset(&mesh_cap, 0, sizeof(mesh_cap));
}

int
hci_mesh_adv_burst(int hci_fd __unused, uint64_t le_features __unused,
    const uint8_t *ad, uint8_t adlen)
{

	mesh_cap.burst_calls++;
	mesh_cap.burst_adlen = adlen;
	if (adlen > sizeof(mesh_cap.burst_ad))
		adlen = sizeof(mesh_cap.burst_ad);
	memcpy(mesh_cap.burst_ad, ad, adlen);
	return (0);
}

int
hci_le_mesh_scan_set(int hci_fd __unused, uint64_t le_features __unused,
    bool on)
{

	mesh_cap.scan_last_on = on;
	if (on)
		mesh_cap.scan_on_calls++;
	else
		mesh_cap.scan_off_calls++;
	return (mesh_cap.scan_error);
}

/* ================================================================
 * meshd-side RX seams (link --wrap): observe which seam each AD type reaches
 * and capture the delivered PDU bytes for byte-for-byte comparison.
 * ================================================================ */
static int wrap_net_calls, wrap_beacon_calls, wrap_prov_calls;
static uint8_t wrap_last[64];
static size_t wrap_last_len;

static void
wrap_reset(void)
{
	wrap_net_calls = wrap_beacon_calls = wrap_prov_calls = 0;
	wrap_last_len = 0;
	memset(wrap_last, 0, sizeof(wrap_last));
}

int __wrap_meshd_bearer_rx(struct meshd_node *nd, const uint8_t *pdu,
    size_t len);
int __wrap_meshd_beacon_rx(struct meshd_node *nd, const uint8_t *pdu,
    size_t len);
int __wrap_meshd_provisioner_recv(struct meshd_node *nd, const uint8_t *pkt,
    size_t len, uint64_t now);

int
__wrap_meshd_bearer_rx(struct meshd_node *nd __unused, const uint8_t *pdu,
    size_t len)
{
	wrap_net_calls++;
	wrap_last_len = len > sizeof(wrap_last) ? sizeof(wrap_last) : len;
	memcpy(wrap_last, pdu, wrap_last_len);
	return (1);
}

int
__wrap_meshd_beacon_rx(struct meshd_node *nd __unused, const uint8_t *pdu,
    size_t len)
{
	wrap_beacon_calls++;
	wrap_last_len = len > sizeof(wrap_last) ? sizeof(wrap_last) : len;
	memcpy(wrap_last, pdu, wrap_last_len);
	return (1);
}

int
__wrap_meshd_provisioner_recv(struct meshd_node *nd __unused,
    const uint8_t *pkt, size_t len, uint64_t now __unused)
{
	wrap_prov_calls++;
	wrap_last_len = len > sizeof(wrap_last) ? sizeof(wrap_last) : len;
	memcpy(wrap_last, pkt, wrap_last_len);
	return (0);
}

/* ================================================================
 * File-specific stubs to satisfy the real ctl.c link set (ctl.c, ctl_conn.c,
 * ctl_gatt.c, conn.c, att*.c, gatt.c, config.c, adv_builder.c).  These mirror
 * ctl_test.c's stubs; none of them is on the mesh path.  The adv/scan/adapter
 * and bond-migrate seams come from test_common.h (default pass-throughs).
 * ================================================================ */
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
    uint16_t psm __unused, uint16_t mtu __unused, int count __unused,
    int *fds __unused)
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

/* periph_gatt_db -- referenced via extern by ctl.c. */
extern struct att_db	periph_gatt_db;
struct att_db		periph_gatt_db;

struct smp_bond *
smp_find_bond(struct smp_bond_db *db __unused, const uint8_t *addr __unused,
    uint8_t addr_type __unused)
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
 * Test harness.
 * ================================================================ */

/* Reinitialize blued_g to a clean state before each test. */
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
}

/* One active, non-connectable adv adapter so SEND/SUBSCRIBE reach the seam. */
static void
mesh_adapter_init(struct blued_adapter *adp, uint64_t le_features)
{

	memset(adp, 0, sizeof(*adp));
	adp->hci_fd = -1;
	adp->active = true;
	adp->le_features = le_features;
	LIST_INSERT_HEAD(&blued_g.adapters, adp, entries);
}

/*
 * The blued responder pump.  blued_ctl_dispatch() does one blocking recv per
 * call and processes every complete frame buffered; loop it until the client
 * becomes a mesh subscriber, i.e. until the real HELLO + MESH_ADV_SUBSCRIBE
 * handshake the meshd client drives has completed.  Runs on a helper thread so
 * it can answer HELLO while meshd_blued_attach() blocks on the reply.
 */
static void *
blued_handshake_pump(void *arg)
{
	struct blued_ctl_client *client = arg;

	while (!client->mesh_sub) {
		if (blued_ctl_dispatch(client) < 0)
			break;
	}
	return (NULL);
}

/*
 * Read exactly one server->client frame from the meshd end (nonblocking fd
 * after attach); poll up to ~1s.  Returns 0 on success.
 */
static int
wire_recv_frame(int fd, uint16_t *type, uint16_t *arg, char *pl, size_t plmax)
{
	uint8_t hdr[IPC_HDR_SIZE];
	uint32_t plen;
	size_t off;

	off = 0;
	while (off < IPC_HDR_SIZE) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t r;

		if (poll(&pfd, 1, 1000) <= 0)
			return (-1);
		r = recv(fd, hdr + off, IPC_HDR_SIZE - off, 0);
		if (r <= 0) {
			if (r < 0 && (errno == EAGAIN || errno == EINTR))
				continue;
			return (-1);
		}
		off += (size_t)r;
	}
	ipc_hdr_decode(hdr, &plen, type, arg);
	if (plen >= plmax)
		return (-1);
	off = 0;
	while (off < plen) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t r;

		if (poll(&pfd, 1, 1000) <= 0)
			return (-1);
		r = recv(fd, (uint8_t *)pl + off, plen - off, 0);
		if (r <= 0) {
			if (r < 0 && (errno == EAGAIN || errno == EINTR))
				continue;
			return (-1);
		}
		off += (size_t)r;
	}
	pl[plen] = '\0';
	return (0);
}

/* Send one correlated operation from the meshd end of the real socket. */
static void
wire_send_operation(int fd, uint32_t request_id, uint16_t domain,
    const uint8_t *body, size_t body_len)
{
	uint8_t hdr[IPC_HDR_SIZE];
	uint8_t payload[IPC_MAX_PAYLOAD];
	size_t off, len;
	ssize_t n;

	ATF_REQUIRE(body_len <= sizeof(payload) - IPC_OP_PREFIX_SIZE);
	ipc_op_prefix_encode(payload, request_id, IPC_ERR_NONE, 0);
	memcpy(payload + IPC_OP_PREFIX_SIZE, body, body_len);
	len = IPC_OP_PREFIX_SIZE + body_len;
	ipc_hdr_encode(hdr, (uint32_t)len, IPC_T_OP_REQ, domain);
	for (off = 0; off < sizeof(hdr); off += (size_t)n) {
		n = write(fd, hdr + off, sizeof(hdr) - off);
		ATF_REQUIRE_MSG(n > 0, "header write failed: %s", strerror(errno));
	}
	for (off = 0; off < len; off += (size_t)n) {
		n = write(fd, payload + off, len - off);
		ATF_REQUIRE_MSG(n > 0, "payload write failed: %s", strerror(errno));
	}
}

static void
wire_expect_reply(int fd, uint16_t domain, uint16_t expected_status)
{
	uint8_t payload[256];
	uint16_t type, arg, status, flags;
	uint32_t request_id;

	ATF_REQUIRE_EQ(0, wire_recv_frame(fd, &type, &arg,
	    (char *)payload, sizeof(payload)));
	ATF_CHECK_EQ(IPC_T_OP_REPLY, type);
	ATF_CHECK_EQ(domain, arg);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK(request_id != 0);
	ATF_CHECK_EQ(expected_status, status);
	ATF_CHECK_EQ(0, flags);
}

/*
 * Stand up the loopback: a real socketpair with a real blued_ctl_client on
 * sv[0] (inserted into blued_g.ctl_clients, privileged) and the real meshd
 * bearer client attached to sv[1].  Runs the genuine HELLO + SUBSCRIBE
 * handshake across the wire from a helper thread.  On return the meshd client
 * is a live, subscribed mesh bearer and the blued client has wants_mesh +
 * mesh_sub set by the real verb handlers.
 */
static void
loop_connect(struct blued_ctl_client **clientp, struct meshd_blued *bc,
    int sv[2])
{
	struct blued_ctl_client *client;
	pthread_t th;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));

	client = calloc(1, sizeof(*client));
	ATF_REQUIRE(client != NULL);
	client->fd = sv[0];
	client->peer_known = true;		/* privileged local peer */
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);

	meshd_blued_init(bc, NULL);		/* no path: reconnect stays down */

	ATF_REQUIRE_EQ(0, pthread_create(&th, NULL, blued_handshake_pump,
	    client));
	ATF_REQUIRE_EQ(0, meshd_blued_attach(bc, sv[1]));
	ATF_REQUIRE_EQ(0, pthread_join(th, NULL));

	/* The real HELLO negotiation + subscribe both crossed the wire. */
	ATF_CHECK(client->handshaked);
	ATF_CHECK(client->wants_mesh);
	ATF_CHECK(client->wants_events);	/* mesh-bearer implies push-events */
	ATF_CHECK(client->mesh_sub);
	ATF_CHECK(meshd_blued_fd(bc) >= 0);

	*clientp = client;
}

static void
loop_teardown(struct blued_ctl_client *client, struct meshd_blued *bc,
    int sv[2])
{

	meshd_blued_close(bc);			/* closes sv[1] */
	if (client != NULL) {
		LIST_REMOVE(client, entries);
		close(client->fd);		/* sv[0] */
		free(client);
	}
	(void)sv;
}

/* ================================================================
 * Test 1: the handshake itself crosses a real socket.
 *
 * loop_connect() runs the genuine two-sided HELLO + MESH_ADV_SUBSCRIBE.  The
 * subscribe also refs the always-on scanner, so the captured HCI scan seam must
 * have been turned on exactly once across the wire.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(broker_loop_handshake);
ATF_TC_BODY(broker_loop_handshake, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct meshd_blued bc;
	int sv[2];

	test_init();
	mesh_cap_reset();
	mesh_adapter_init(&adp, 0);

	loop_connect(&client, &bc, sv);

	/* First subscriber turned the mesh scanner on, once. */
	ATF_CHECK_EQ(1, mesh_cap.scan_on_calls);
	ATF_CHECK(mesh_cap.scan_last_on);
	ATF_CHECK_EQ(0, mesh_cap.scan_off_calls);

	loop_teardown(client, &bc, sv);
	LIST_REMOVE(&adp, entries);
}

ATF_TC_WITHOUT_HEAD(broker_loop_handshake_subscribe_failure);
ATF_TC_BODY(broker_loop_handshake_subscribe_failure, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct meshd_blued bc;
	pthread_t th;
	int sv[2];

	test_init();
	mesh_cap_reset();
	mesh_cap.scan_error = -1;
	mesh_adapter_init(&adp, 0);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	client = calloc(1, sizeof(*client));
	ATF_REQUIRE(client != NULL);
	client->fd = sv[0];
	client->peer_known = true;
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	meshd_blued_init(&bc, NULL);
	ATF_REQUIRE_EQ(0, pthread_create(&th, NULL, blued_handshake_pump,
	    client));
	ATF_CHECK_EQ(-1, meshd_blued_attach(&bc, sv[1]));
	ATF_REQUIRE_EQ(0, pthread_join(th, NULL));
	ATF_CHECK_EQ(-1, meshd_blued_fd(&bc));
	ATF_CHECK(!client->mesh_sub);
	ATF_CHECK_EQ(1, mesh_cap.scan_on_calls);
	LIST_REMOVE(client, entries);
	close(client->fd);
	free(client);
	LIST_REMOVE(&adp, entries);
}

/* ================================================================
 * Test 2: INBOUND round-trip.  A synthetic adv report with one mesh AD field
 * runs through the REAL blued demux -> EVENT MESH_ADV over the wire -> the REAL
 * meshd pump -> the correct RX seam by AD type.  The PDU bytes delivered to the
 * seam equal the bytes fed into the report (byte-for-byte, across the socket).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(broker_loop_inbound_roundtrip);
ATF_TC_BODY(broker_loop_inbound_roundtrip, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct meshd_blued bc;
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	int sv[2];
	/* [04 2A 01 02 03] Mesh Message (0x2A), pdu = 01 02 03 */
	static const uint8_t net_ad[] = { 0x04, 0x2A, 0x01, 0x02, 0x03 };
	/* [03 2B AA BB] Secure Network beacon (0x2B), pdu = AA BB */
	static const uint8_t beacon_ad[] = { 0x03, 0x2B, 0xAA, 0xBB };
	/* [05 29 DE AD BE EF] PB-ADV provisioning (0x29), pdu = DE AD BE EF */
	static const uint8_t prov_ad[] = { 0x05, 0x29, 0xDE, 0xAD, 0xBE, 0xEF };

	test_init();
	mesh_cap_reset();
	mesh_adapter_init(&adp, 0);
	meshd_config_defaults(&cfg);
	cfg.unicast_addr = 0x0001;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	loop_connect(&client, &bc, sv);

	/* 0x2A -> meshd_bearer_rx; delivered bytes == fed bytes. */
	wrap_reset();
	blued_mesh_demux_report(net_ad, sizeof(net_ad));
	ATF_CHECK_EQ(1, meshd_blued_pump_rx(&bc, nd, NULL, 0));
	ATF_CHECK_EQ(1, wrap_net_calls);
	ATF_CHECK_EQ(0, wrap_beacon_calls + wrap_prov_calls);
	ATF_CHECK_EQ(3, (int)wrap_last_len);
	ATF_CHECK_EQ(0, memcmp(wrap_last, &net_ad[2], 3));

	/* 0x2B -> meshd_beacon_rx; bytes preserved. */
	wrap_reset();
	blued_mesh_demux_report(beacon_ad, sizeof(beacon_ad));
	ATF_CHECK_EQ(1, meshd_blued_pump_rx(&bc, nd, NULL, 0));
	ATF_CHECK_EQ(1, wrap_beacon_calls);
	ATF_CHECK_EQ(0, wrap_net_calls + wrap_prov_calls);
	ATF_CHECK_EQ(2, (int)wrap_last_len);
	ATF_CHECK_EQ(0, memcmp(wrap_last, &beacon_ad[2], 2));

	/* 0x29 -> meshd_provisioner_recv; bytes preserved. */
	wrap_reset();
	blued_mesh_demux_report(prov_ad, sizeof(prov_ad));
	ATF_CHECK_EQ(1, meshd_blued_pump_rx(&bc, nd, NULL, 0));
	ATF_CHECK_EQ(1, wrap_prov_calls);
	ATF_CHECK_EQ(0, wrap_net_calls + wrap_beacon_calls);
	ATF_CHECK_EQ(4, (int)wrap_last_len);
	ATF_CHECK_EQ(0, memcmp(wrap_last, &prov_ad[2], 4));

	loop_teardown(client, &bc, sv);
	LIST_REMOVE(&adp, entries);
}

/* ================================================================
 * Test 3: INBOUND leak filter holds across the wire.  A report mixing a mesh
 * AD field (0x2A) with non-mesh fields (Flags, Complete Local Name) delivers
 * EXACTLY the mesh PDU and nothing else; a report with only non-mesh AD emits
 * no event at all (the meshd pump sees nothing to dispatch).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(broker_loop_inbound_leak_filter);
ATF_TC_BODY(broker_loop_inbound_leak_filter, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct meshd_blued bc;
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	int sv[2];
	/* [02 01 06] Flags, [03 2A AA BB] Mesh Message, [04 09 41 42 43] name */
	static const uint8_t mixed[] = {
		0x02, 0x01, 0x06,
		0x03, 0x2A, 0xAA, 0xBB,
		0x04, 0x09, 0x41, 0x42, 0x43,
	};
	/* Only non-mesh AD (manufacturer data + tx power). */
	static const uint8_t nonmesh[] = {
		0x03, 0xFF, 0x11, 0x22,
		0x02, 0x0A, 0x00,
	};

	test_init();
	mesh_cap_reset();
	mesh_adapter_init(&adp, 0);
	meshd_config_defaults(&cfg);
	cfg.unicast_addr = 0x0001;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	loop_connect(&client, &bc, sv);

	/* Mixed report: exactly one PDU (AA BB) reaches bearer_rx; name dropped. */
	wrap_reset();
	blued_mesh_demux_report(mixed, sizeof(mixed));
	ATF_CHECK_EQ(1, meshd_blued_pump_rx(&bc, nd, NULL, 0));
	ATF_CHECK_EQ(1, wrap_net_calls);
	ATF_CHECK_EQ(0, wrap_beacon_calls + wrap_prov_calls);
	ATF_CHECK_EQ(2, (int)wrap_last_len);
	ATF_CHECK_EQ(0xAA, wrap_last[0]);
	ATF_CHECK_EQ(0xBB, wrap_last[1]);

	/* Non-mesh-only report: nothing crosses the wire, nothing dispatches. */
	wrap_reset();
	blued_mesh_demux_report(nonmesh, sizeof(nonmesh));
	ATF_CHECK_EQ(0, meshd_blued_pump_rx(&bc, nd, NULL, 0));
	ATF_CHECK_EQ(0, wrap_net_calls + wrap_beacon_calls + wrap_prov_calls);

	loop_teardown(client, &bc, sv);
	LIST_REMOVE(&adp, entries);
}

/* ================================================================
 * Test 4: OUTBOUND round-trip.  The REAL meshd tx sink sends a PDU per class;
 * the wire carries MESH_ADV_SEND <adtype> <hex>; the REAL blued side validates
 * the adtype and the captured radio seam records the exact [len][adtype][pdu]
 * burst.  The transmitted PDU bytes equal the bytes handed to the sink.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(broker_loop_outbound_roundtrip);
ATF_TC_BODY(broker_loop_outbound_roundtrip, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct meshd_blued bc;
	int sv[2];
	static const struct {
		enum meshd_pdu_class cls;
		uint8_t adtype;
		uint8_t pdu[4];
		size_t len;
	} vectors[] = {
		{ MESHD_PDU_NET, 0x2A, { 0x01, 0x02, 0x03 }, 3 },
		{ MESHD_PDU_BEACON, 0x2B, { 0xAA, 0xBB }, 2 },
		{ MESHD_PDU_PROV, 0x29, { 0xDE, 0xAD, 0xBE, 0xEF }, 4 },
	};
	size_t i;

	test_init();
	mesh_cap_reset();
	mesh_adapter_init(&adp, 0);
	loop_connect(&client, &bc, sv);

	for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		int before = mesh_cap.burst_calls;

		ATF_REQUIRE_EQ(0, meshd_blued_tx(&bc, vectors[i].cls,
		    vectors[i].pdu, vectors[i].len));
		ATF_REQUIRE_EQ(0, blued_ctl_dispatch(client));
		wire_expect_reply(meshd_blued_fd(&bc), IPC_OP_DOMAIN_MESH,
		    IPC_ERR_NONE);
		ATF_CHECK_EQ(before + 1, mesh_cap.burst_calls);
		ATF_CHECK_EQ((int)vectors[i].len + 2,
		    (int)mesh_cap.burst_adlen);
		ATF_CHECK_EQ((int)vectors[i].len + 1, mesh_cap.burst_ad[0]);
		ATF_CHECK_EQ(vectors[i].adtype, mesh_cap.burst_ad[1]);
		ATF_CHECK_EQ(0, memcmp(mesh_cap.burst_ad + 2,
		    vectors[i].pdu, vectors[i].len));
	}

	loop_teardown(client, &bc, sv);
	LIST_REMOVE(&adp, entries);
}

/* ================================================================
 * Test 5: OUTBOUND negatives across the wire.
 *   - A non-mesh adtype (raw MESH_ADV_SEND 01 ...) is rejected by blued and
 *     never reaches the radio (the real meshd sink can only emit mesh adtypes,
 *     so this is driven as a raw frame over the same real socket).
 *   - An unprivileged peer's real MESH_ADV_SEND is refused before the radio.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(broker_loop_outbound_rejections);
ATF_TC_BODY(broker_loop_outbound_rejections, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct meshd_blued bc;
	uint8_t request[IPC_MESH_ADV_REQ_HDR_SIZE + 1];
	static const uint8_t pdu[] = { 0x11, 0x22 };
	int sv[2];

	test_init();
	mesh_cap_reset();
	mesh_adapter_init(&adp, 0);
	loop_connect(&client, &bc, sv);

	/* A syntactically complete non-mesh AD type must not reach the radio. */
	ipc_put_le16(request, IPC_MESH_ADV_SEND);
	request[2] = 0x01;
	request[3] = IPC_MESH_ADAPTER_DEFAULT;
	request[4] = 1;
	request[5] = 0;
	request[IPC_MESH_ADV_REQ_HDR_SIZE] = 0x06;
	wire_send_operation(meshd_blued_fd(&bc), 0x4001,
	    IPC_OP_DOMAIN_MESH, request, sizeof(request));
	ATF_REQUIRE_EQ(0, blued_ctl_dispatch(client));
	wire_expect_reply(meshd_blued_fd(&bc), IPC_OP_DOMAIN_MESH,
	    IPC_ERR_INVAL);
	ATF_CHECK_EQ(0, mesh_cap.burst_calls);

	/* Negotiation alone does not authorize a non-root peer to transmit. */
	client->peer_uid = 1000;
	ATF_REQUIRE_EQ(0, meshd_blued_tx(&bc, MESHD_PDU_NET, pdu,
	    sizeof(pdu)));
	ATF_REQUIRE_EQ(0, blued_ctl_dispatch(client));
	wire_expect_reply(meshd_blued_fd(&bc), IPC_OP_DOMAIN_MESH,
	    IPC_ERR_PERM);
	ATF_CHECK_EQ(0, mesh_cap.burst_calls);

	loop_teardown(client, &bc, sv);
	LIST_REMOVE(&adp, entries);
}

/* ================================================================
 * Finding 77: meshd_blued_pump_rx must keep its frame-reassembly buffer
 * consistent as it drains several queued frames back-to-back.  The
 * frame_done: memmove that compacts the buffer between frames is the site of
 * the size_t underflow the fix guards; draining two concatenated EVENT frames
 * in one pump exercises that compaction and must dispatch both without
 * corrupting the buffer.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(broker_loop_pump_multiframe);
ATF_TC_BODY(broker_loop_pump_multiframe, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct meshd_blued bc;
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	int sv[2], r;
	static const uint8_t net_ad[] = { 0x04, 0x2A, 0x01, 0x02, 0x03 };
	static const uint8_t beacon_ad[] = { 0x03, 0x2B, 0xAA, 0xBB };

	test_init();
	mesh_cap_reset();
	mesh_adapter_init(&adp, 0);
	meshd_config_defaults(&cfg);
	cfg.unicast_addr = 0x0001;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	loop_connect(&client, &bc, sv);

	/* Queue two EVENT frames, then drain them with pump calls; the buffer
	 * compaction between frames must stay consistent (no underflow). */
	wrap_reset();
	blued_mesh_demux_report(net_ad, sizeof(net_ad));
	blued_mesh_demux_report(beacon_ad, sizeof(beacon_ad));
	do {
		r = meshd_blued_pump_rx(&bc, nd, NULL, 0);
		ATF_CHECK(r >= 0);
	} while (r == 1 && wrap_net_calls + wrap_beacon_calls < 2);
	ATF_CHECK_EQ(1, wrap_net_calls);
	ATF_CHECK_EQ(1, wrap_beacon_calls);
	ATF_CHECK_EQ(0, (int)bc.rxn);	/* both frames fully consumed */

	loop_teardown(client, &bc, sv);
	LIST_REMOVE(&adp, entries);
}

/* ================================================================
 * Finding 80: a single failing GATT proxy link must not abort the ADV
 * broadcast of a mesh PDU.  A subscribed-but-unusable proxy link (its
 * mbw_proxy_tx fails) must fail only that link; the NET PDU must still reach
 * the radio bearer.  Before the fix meshd_blued_tx returned -1 on the first
 * proxy failure, dropping the PDU network-wide.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(broker_loop_proxy_failure_still_broadcasts);
ATF_TC_BODY(broker_loop_proxy_failure_still_broadcasts, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct meshd_blued bc;
	static const uint8_t pdu[] = { 0x01, 0x02, 0x03 };
	int sv[2], before;

	test_init();
	mesh_cap_reset();
	mesh_adapter_init(&adp, 0);
	loop_connect(&client, &bc, sv);

	/* A subscribed proxy link whose transmit path is guaranteed to fail
	 * (an invalid MTU makes mbw_proxy_tx return -1 with no side effects). */
	strlcpy(bc.proxy[0].addr, "00:11:22:33:44:55", sizeof(bc.proxy[0].addr));
	bc.proxy[0].addr_type = 0;
	bc.proxy[0].adapter_index = 0;
	bc.proxy[0].mtu = 0;			/* < MESHD_PBGATT_MIN_MTU */
	bc.proxy[0].data_in = 0x0010;
	bc.proxy[0].subscribed = 1;
	bc.proxy[0].active = 1;

	before = mesh_cap.burst_calls;
	ATF_REQUIRE_EQ(0, meshd_blued_tx(&bc, MESHD_PDU_NET, pdu, sizeof(pdu)));
	ATF_REQUIRE_EQ(0, blued_ctl_dispatch(client));
	wire_expect_reply(meshd_blued_fd(&bc), IPC_OP_DOMAIN_MESH,
	    IPC_ERR_NONE);
	/* The radio ADV burst still happened despite the proxy link failure. */
	ATF_CHECK_EQ(before + 1, mesh_cap.burst_calls);

	loop_teardown(client, &bc, sv);
	LIST_REMOVE(&adp, entries);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, broker_loop_handshake);
	ATF_TP_ADD_TC(tp, broker_loop_handshake_subscribe_failure);
	ATF_TP_ADD_TC(tp, broker_loop_inbound_roundtrip);
	ATF_TP_ADD_TC(tp, broker_loop_inbound_leak_filter);
	ATF_TP_ADD_TC(tp, broker_loop_outbound_roundtrip);
	ATF_TP_ADD_TC(tp, broker_loop_outbound_rejections);
	ATF_TP_ADD_TC(tp, broker_loop_pump_multiframe);
	ATF_TP_ADD_TC(tp, broker_loop_proxy_failure_still_broadcasts);

	return (atf_no_error());
}
