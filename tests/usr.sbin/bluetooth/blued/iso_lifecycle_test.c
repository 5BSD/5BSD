/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Lifecycle tests for the LE Isochronous (ISO) operator surface: the per-stream
 * state machine (iso.c) and its control verbs (ctl_iso.c).  These assert
 * BEHAVIOUR and STATE TRANSITIONS -- not captured command bytes; the on-wire
 * encoding is covered by iso_control_test / iso_transport_test.
 *
 * The HCI ISO encoders and the kernel ISO opener are interposed with recording
 * stubs, so a verb's HCI side effect and a teardown's REVERSE ORDER (remove
 * data paths -> disconnect / terminate -> remove CIG) are observable without
 * hardware.  Async completion is driven by calling the same iso_on_*()
 * event seams the daemon's HCI event handler calls, exactly reproducing the
 * verb-sends-command / event-completes-it chaining.
 *
 * Core Spec 6.x Vol 4 Part E (ISO HCI): §7.8.97-.111, events §7.7.65.25-.30.
 */

#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "ble_util.h"
#include "blued.h"
#include "conn.h"
#include "ctl.h"
#include "ctl_internal.h"
#include "hci_util.h"
#include "hci_internal.h"
#include "iso.h"

/* Globals the logging macros and iso.c reference. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;
atomic_bool blued_shutting_down = 0;
struct blued_ctx blued_g;

/* ================================================================
 * Recording stubs.
 * ================================================================ */

/* Ordered call log: which HCI/opener primitives fired, in order. */
enum {
	C_SETUP_PATH = 1, C_REMOVE_PATH, C_DISCONNECT, C_REMOVE_CIG,
	C_CREATE_CIS, C_ACCEPT, C_REJECT, C_CREATE_BIG, C_TERM_BIG,
	C_CREATE_SYNC, C_TERM_SYNC, C_ISO_CONNECT,
};
static int calllog[256];
static int ncall;
static int fail_next;		/* nonzero -> next encoder returns -1 once */
static int setup_count_override;	/* -1 uses the requested CIS count */
static int setup_paths_override;	/* -1 uses the normal direction count */
static int setup_path_fail_direction;	/* -1 means no per-direction failure */
static bool iso_connect_fail;
static uint8_t frame_buf[IPC_MAX_PAYLOAD];
static size_t frame_len;
static uint16_t frame_type;
static uint16_t frame_domain;
static int fd_handouts;
static bool ctl_tx_room;
static bool ctl_fd_send_fail;
static struct blued_ctl_client event_client;
static struct blued_adapter test_adp;
static struct blued_conn test_conn;
static bool conn_present;
static bool fail_calloc;
static int calloc_calls_until_fail;

void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t, size_t);

void *
__wrap_calloc(size_t count, size_t size)
{

	if (fail_calloc) {
		fail_calloc = false;
		return (NULL);
	}
	if (calloc_calls_until_fail == 0) {
		calloc_calls_until_fail = -1;
		return (NULL);
	}
	if (calloc_calls_until_fail > 0)
		calloc_calls_until_fail--;
	return (__real_calloc(count, size));
}

static void
logc(int c)
{

	if (ncall < (int)(sizeof(calllog) / sizeof(calllog[0])))
		calllog[ncall++] = c;
}

static bool
took_fail(void)
{

	if (fail_next) {
		fail_next = 0;
		return (true);
	}
	return (false);
}

/* Index in the call log of the first occurrence of c, or -1. */
static int
idx_of(int c)
{
	int i;

	for (i = 0; i < ncall; i++)
		if (calllog[i] == c)
			return (i);
	return (-1);
}

static int
count_of(int c)
{
	int i, n = 0;

	for (i = 0; i < ncall; i++)
		if (calllog[i] == c)
			n++;
	return (n);
}

static void
reset(void)
{

	blued_iso_reset();
	ncall = 0;
	fail_next = 0;
	setup_count_override = -1;
	setup_paths_override = -1;
	setup_path_fail_direction = -1;
	iso_connect_fail = false;
	frame_len = 0;
	frame_type = 0;
	frame_domain = 0;
	fd_handouts = 0;
	ctl_tx_room = true;
	ctl_fd_send_fail = false;
	memset(&test_adp, 0, sizeof(test_adp));
	test_adp.hci_fd = 7;
	test_adp.index = 0;
	test_adp.powered = true;
	test_adp.le_features = LE_FEAT_CIS_CENTRAL | LE_FEAT_CIS_PERIPH |
	    LE_FEAT_ISO_BROADCASTER | LE_FEAT_ISO_SYNC_RECEIVER;
	memset(&test_conn, 0, sizeof(test_conn));
	test_conn.con_handle = 0x0020;
	conn_present = true;
	fail_calloc = false;
	calloc_calls_until_fail = -1;
}

static bool
frame_is_iso_event(uint16_t event)
{

	return (frame_type == IPC_T_OP_EVENT &&
	    frame_domain == IPC_OP_DOMAIN_ISO &&
	    frame_len == IPC_OP_PREFIX_SIZE + IPC_ISO_EVENT_SIZE &&
	    ipc_get_le16(frame_buf + IPC_OP_PREFIX_SIZE) == event);
}

int
ctl_send_frame(struct blued_ctl_client *client __unused, uint16_t type,
    uint16_t arg, const void *payload, size_t len)
{

	ATF_REQUIRE(len <= sizeof(frame_buf));
	frame_type = type;
	frame_domain = arg;
	frame_len = len;
	if (len != 0)
		memcpy(frame_buf, payload, len);
	return (0);
}

bool
ctl_tx_has_room(const struct blued_ctl_client *client __unused,
    size_t need __unused)
{

	return (ctl_tx_room);
}

int
ctl_send_fd_to_client(struct blued_ctl_client *client __unused,
    int fd __unused)
{

	if (ctl_fd_send_fail) {
		errno = ENOBUFS;
		return (-1);
	}
	fd_handouts++;
	return (0);
}

void
blued_ctl_send_fd(int client_fd __unused, int fd __unused)
{

	fd_handouts++;
}

static void
capture_iso_event(uint16_t event, const bdaddr_t *addr, uint8_t addr_type,
    uint16_t cis_handle, uint8_t cig_id, uint8_t cis_id, uint16_t mtu)
{
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_ISO_EVENT_SIZE] = { 0 };
	uint8_t *body = payload + IPC_OP_PREFIX_SIZE;

	ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, event);
	body[2] = addr_type;
	memcpy(body + 3, addr, sizeof(*addr));
	ipc_put_le16(body + 9, cis_handle);
	if (event == IPC_ISO_EV_CIS_REQUEST) {
		body[11] = cig_id;
		body[12] = cis_id;
	} else
		ipc_put_le16(body + 11, mtu);
	ctl_send_frame(&event_client, IPC_T_OP_EVENT, IPC_OP_DOMAIN_ISO,
	    payload, sizeof(payload));
}

void
blued_ctl_iso_cis_request(struct blued_adapter *adp __unused,
    const bdaddr_t *addr, uint8_t addr_type,
    uint16_t cis_handle, uint8_t cig_id, uint8_t cis_id)
{
	capture_iso_event(IPC_ISO_EV_CIS_REQUEST, addr, addr_type, cis_handle,
	    cig_id, cis_id, 0);
}

void
blued_ctl_iso_established(struct blued_adapter *adp __unused,
    const bdaddr_t *addr, uint8_t addr_type,
    uint16_t cis_handle, uint16_t mtu)
{
	capture_iso_event(IPC_ISO_EV_ESTABLISHED, addr, addr_type, cis_handle,
	    0, 0, mtu);
}

/* Finding 116: capture the CIS-failure event (status carried in the mtu slot). */
void
blued_ctl_iso_failed(struct blued_adapter *adp __unused,
    const bdaddr_t *addr, uint8_t addr_type,
    uint16_t cis_handle, uint8_t status)
{
	capture_iso_event(IPC_ISO_EV_FAILED, addr, addr_type, cis_handle,
	    0, 0, status);
}

/* iso_lifecycle_test does not link ctl.c; provide the lock initialiser. */
void
blued_ctl_clients_lock_init(pthread_mutex_t *m)
{
	pthread_mutexattr_t attr;

	if (pthread_mutexattr_init(&attr) != 0) {
		(void)pthread_mutex_init(m, NULL);
		return;
	}
	(void)pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	(void)pthread_mutex_init(m, &attr);
	(void)pthread_mutexattr_destroy(&attr);
}

void
ctl_send_op_ack(struct blued_ctl_client *client, uint16_t domain)
{
	uint8_t reply[IPC_OP_PREFIX_SIZE];

	ipc_op_prefix_encode(reply, client->active_request_id, IPC_ERR_NONE, 0);
	ctl_send_frame(client, IPC_T_OP_REPLY, domain, reply, sizeof(reply));
}

void
ctl_send_op_error(struct blued_ctl_client *client, uint16_t domain,
    uint16_t error, const char *message __unused)
{
	uint8_t reply[IPC_OP_PREFIX_SIZE];

	ipc_op_prefix_encode(reply, client->active_request_id, error, 0);
	ctl_send_frame(client, IPC_T_OP_REPLY, domain, reply, sizeof(reply));
}

/* ---- conn.c seams ---- */

struct blued_conn *
blued_conn_by_peer(const struct blued_adapter *adapter __unused,
    const bdaddr_t *addr __unused, uint8_t addr_type __unused)
{

	return (conn_present ? &test_conn : NULL);
}

struct blued_adapter *
blued_adapter_by_index(int idx)
{

	return (idx == 0 ? &test_adp : NULL);
}

struct blued_adapter *
blued_adapter_by_index_powered(int idx)
{
	struct blued_adapter *adp = blued_adapter_by_index(idx);

	return (adp != NULL && adp->active && adp->powered &&
	    !adp->power_quiescing ? adp : NULL);
}

/* ---- HCI ISO encoder + opener seams ---- */

int
hci_le_setup_cig(int fd __unused, uint8_t cig_id,
    uint32_t sdu_c __unused, uint32_t sdu_p __unused, uint8_t sca __unused,
    uint8_t packing __unused, uint8_t framing __unused,
    uint16_t lat_c __unused, uint16_t lat_p __unused, uint8_t cis_count,
    const struct hci_cis_param *cises __unused, uint8_t *out_cig_id,
    uint8_t *out_cis_count, uint16_t *out_cis_handles)
{
	uint8_t i;

	if (took_fail())
		return (-1);
	if (out_cig_id != NULL)
		*out_cig_id = cig_id;
	if (out_cis_count != NULL)
		*out_cis_count = setup_count_override >= 0 ?
		    (uint8_t)setup_count_override : cis_count;
	for (i = 0; i < cis_count; i++)
		out_cis_handles[i] = (uint16_t)(0x0010 + i);
	return (0);
}

int
hci_le_create_cis(int fd __unused, uint8_t cis_count __unused,
    const uint16_t *cis_handles __unused, const uint16_t *acl_handles __unused)
{

	logc(C_CREATE_CIS);
	return (took_fail() ? -1 : 0);
}

int
hci_le_remove_cig(int fd __unused, uint8_t cig_id __unused)
{

	logc(C_REMOVE_CIG);
	return (took_fail() ? -1 : 0);
}

int
hci_le_accept_cis_request(int fd __unused, uint16_t h __unused)
{

	logc(C_ACCEPT);
	return (took_fail() ? -1 : 0);
}

int
hci_le_reject_cis_request(int fd __unused, uint16_t h __unused,
    uint8_t reason __unused)
{

	logc(C_REJECT);
	return (took_fail() ? -1 : 0);
}

int
hci_le_create_big(int fd __unused, uint8_t big __unused, uint8_t adv __unused,
    uint8_t num_bis __unused, uint32_t sdu __unused, uint16_t msdu __unused,
    uint16_t lat __unused, uint8_t rtn __unused, uint8_t phy __unused,
    uint8_t pack __unused, uint8_t fram __unused, uint8_t enc __unused,
    const uint8_t bcode[16] __unused)
{

	logc(C_CREATE_BIG);
	return (took_fail() ? -1 : 0);
}

int
hci_le_terminate_big(int fd __unused, uint8_t big __unused,
    uint8_t reason __unused)
{

	logc(C_TERM_BIG);
	return (took_fail() ? -1 : 0);
}

int
hci_le_big_create_sync(int fd __unused, uint8_t big __unused,
    uint16_t sync __unused, uint8_t enc __unused,
    const uint8_t bcode[16] __unused, uint8_t mse __unused,
    uint16_t timeout __unused, uint8_t num_bis __unused,
    const uint8_t *idx __unused)
{

	logc(C_CREATE_SYNC);
	return (took_fail() ? -1 : 0);
}

int
hci_le_big_terminate_sync(int fd __unused, uint8_t big __unused)
{

	logc(C_TERM_SYNC);
	return (took_fail() ? -1 : 0);
}

int
hci_le_setup_iso_hci_path(int fd __unused, uint16_t h __unused,
    uint8_t direction)
{

	logc(C_SETUP_PATH);
	if (setup_paths_override == 0)
		return (-1);
	if (setup_path_fail_direction == direction)
		return (-1);
	if (took_fail())
		return (-1);
	return (0);
}

int
hci_le_setup_iso_stream_paths(int fd __unused, uint16_t h __unused,
    enum hci_iso_stream_kind kind)
{

	logc(C_SETUP_PATH);
	if (setup_paths_override >= 0)
		return (setup_paths_override);
	if (took_fail())
		return (0);
	/* CIS sets both directions; a BIS sets one. */
	return (kind == HCI_ISO_STREAM_CIS ? 2 : 1);
}

int
hci_le_remove_iso_data_path(int fd __unused, uint16_t h __unused,
    uint8_t dir __unused)
{

	logc(C_REMOVE_PATH);
	return (0);
}

int
hci_disconnect(int fd __unused, uint16_t h __unused, uint8_t reason __unused)
{

	logc(C_DISCONNECT);
	return (took_fail() ? -1 : 0);
}

int
ble_iso_connect(const uint8_t *src __unused, const uint8_t *addr __unused,
    uint8_t addr_type __unused, uint16_t handle __unused, uint16_t mtu __unused)
{

	logc(C_ISO_CONNECT);
	if (iso_connect_fail)
		return (-1);
	return (open("/dev/null", O_RDONLY));
}

/* ================================================================
 * Fixtures.
 * ================================================================ */

static void
env_init(void)
{

	memset(&blued_g, 0, sizeof(blued_g));
	/* Exercise the enabled diagnostic configuration as well as the default
	 * quiet daemon mode.  LOG_ISO() guards are production branches: operators
	 * routinely enable level 1/2 while diagnosing an LE Audio link. */
	atomic_store(&blued_verbose, 2);
	/* Exercise the syslog route used by a daemonized service.  A dedicated
	 * defensive matrix below restores the stderr route, so both runtime
	 * configurations remain covered. */
	blued_daemonized = 1;
	LIST_INIT(&blued_g.conns);
	LIST_INIT(&blued_g.ctl_clients);
	pthread_rwlock_init(&blued_g.conns_lock, NULL);
	blued_ctl_clients_lock_init(&blued_g.ctl_clients_lock);
	reset();
	memset(&event_client, 0, sizeof(event_client));
	event_client.wants_events = true;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, &event_client, entries);
}

/* Provision a one-CIS CIG and return its allocated CIS handle. */
static uint16_t
make_cig(void)
{
	struct hci_cis_param cis = {
		.cis_id = 1, .max_sdu_c_to_p = 240, .max_sdu_p_to_c = 0,
		.phy_c_to_p = 2, .phy_p_to_c = 1, .rtn_c_to_p = 3,
		.rtn_p_to_c = 0,
	};
	uint16_t handles[4];
	uint8_t count = 0;

	ATF_REQUIRE_EQ(0, blued_iso_cig_create(&test_adp, 0, 1000, 1000, 0, 0,
	    0, 10, 10, &cis, 1, handles, &count));
	ATF_REQUIRE_EQ(1, count);
	return (handles[0]);
}

/* ================================================================
 * Central CIS: full lifecycle CIG -> CIS -> established -> acquire -> teardown.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cis_central_full_lifecycle);
ATF_TC_BODY(cis_central_full_lifecycle, tc)
{
	uint16_t h;
	int fd;

	env_init();
	/* A complete central lifecycle is also supported from an operator's
	 * foreground diagnostic session, rather than only as a daemon service. */
	blued_daemonized = 0;
	h = make_cig();
	ATF_CHECK_EQ(1, blued_iso_stream_count());
	ATF_CHECK_EQ(ISO_ST_CIG_CONFIGURED, blued_iso_stream_state(&test_adp, h));

	/* Create CIS: issues LE Create CIS (Command Status), returns creating. */
	ATF_CHECK_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	ATF_CHECK_EQ(ISO_ST_CREATING, blued_iso_stream_state(&test_adp, h));
	ATF_CHECK(idx_of(C_CREATE_CIS) >= 0);

	/* Async completion: CIS Established (status 0) stands up both paths. */
	iso_on_cis_established(&test_adp, h, 0);
	ATF_CHECK_EQ(ISO_ST_PATHS_UP, blued_iso_stream_state(&test_adp, h));
	ATF_CHECK(idx_of(C_SETUP_PATH) >= 0);
	ATF_CHECK(frame_is_iso_event(IPC_ISO_EV_ESTABLISHED));

	/* A transient ISO socket failure leaves paths usable for a retry. */
	iso_connect_fail = true;
	ATF_CHECK_EQ(-1, blued_iso_acquire_fd(&test_adp, h));
	ATF_CHECK_EQ(ISO_ST_PATHS_UP, blued_iso_stream_state(&test_adp, h));
	iso_connect_fail = false;
	/* Acquire: fd handout opens the kernel ISO socket, stream HANDED_OFF. */
	fd = blued_iso_acquire_fd(&test_adp, h);
	ATF_CHECK(fd >= 0);
	if (fd >= 0)
		close(fd);
	ATF_CHECK_EQ(ISO_ST_HANDED_OFF, blued_iso_stream_state(&test_adp, h));

	/* Teardown: reverse of setup, then the stream is gone. */
	ATF_CHECK_EQ(0, blued_iso_cis_teardown(&test_adp, h, 0x13));
	ATF_CHECK_EQ(ISO_ST_TEARDOWN,
	    blued_iso_stream_state(&test_adp, h));
	iso_on_cis_disconnected(&test_adp, h, 0x13);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
	ATF_CHECK_EQ(-1, blued_iso_stream_state(&test_adp, h));

	/* Reverse order: remove path < disconnect < remove CIG. */
	ATF_CHECK(idx_of(C_REMOVE_PATH) >= 0);
	ATF_CHECK(idx_of(C_REMOVE_PATH) < idx_of(C_DISCONNECT));
	ATF_CHECK(idx_of(C_DISCONNECT) < idx_of(C_REMOVE_CIG));
}

/* Pre-registered client gets the fd pushed the moment the stream establishes. */
ATF_TC_WITHOUT_HEAD(cis_central_push_on_establish);
ATF_TC_BODY(cis_central_push_on_establish, tc)
{
	uint16_t h;

	env_init();
	h = make_cig();
	ATF_CHECK_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, 42 /* client fd */, true));
	iso_on_cis_established(&test_adp, h, 0);
	ATF_CHECK_EQ(1, fd_handouts);
	ATF_CHECK_EQ(ISO_ST_HANDED_OFF, blued_iso_stream_state(&test_adp, h));
}

/* A failed opportunistic fd handout must leave the established stream
 * available for a later ISO_ACQUIRE retry. */
ATF_TC_WITHOUT_HEAD(cis_push_handout_failure_is_retryable);
ATF_TC_BODY(cis_push_handout_failure_is_retryable, tc)
{
	uint16_t h;
	int fd;

	env_init();
	h = make_cig();
	ATF_REQUIRE_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, 42, true));
	iso_connect_fail = true;
	iso_on_cis_established(&test_adp, h, 0);
	ATF_CHECK_EQ(ISO_ST_PATHS_UP, blued_iso_stream_state(&test_adp, h));
	iso_connect_fail = false;
	fd = blued_iso_acquire_fd(&test_adp, h);
	ATF_CHECK(fd >= 0);
	if (fd >= 0)
		close(fd);
	ATF_CHECK_EQ(ISO_ST_HANDED_OFF, blued_iso_stream_state(&test_adp, h));
	ATF_CHECK_EQ(0, blued_iso_cis_teardown(&test_adp, h, 0x13));
}

/* Nonzero establish status: free the stream, remove the orphan CIG, ISO_LOST. */
ATF_TC_WITHOUT_HEAD(cis_partial_setup_failure);
ATF_TC_BODY(cis_partial_setup_failure, tc)
{
	uint16_t h;

	env_init();
	h = make_cig();
	ATF_CHECK_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));

	iso_on_cis_established(&test_adp, h, 0x3E /* connection failed */);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
	ATF_CHECK(idx_of(C_REMOVE_CIG) >= 0);
}

/*
 * Finding 116: a CIS establishment failure must emit an ISO failure event to
 * the requester, not just silently drop the stream — otherwise a client that
 * issued ISO_CIS_CREATE waits forever.  The last frame the daemon pushed must
 * be IPC_ISO_EV_FAILED carrying the HCI status.
 */
ATF_TC_WITHOUT_HEAD(cis_establish_failure_emits_event);
ATF_TC_BODY(cis_establish_failure_emits_event, tc)
{
	uint16_t h;

	env_init();
	h = make_cig();
	ATF_CHECK_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));

	iso_on_cis_established(&test_adp, h, 0x3E /* connection failed */);
	ATF_CHECK(frame_is_iso_event(IPC_ISO_EV_FAILED));
	/* Status 0x3E is carried in the u16 field at body[11]. */
	ATF_CHECK_EQ(0x3E, ipc_get_le16(frame_buf + IPC_OP_PREFIX_SIZE + 11));
}

/*
 * Finding 116 (data-path branch): a CIS the controller established but whose
 * host data path could not be brought up is also a failed establishment for
 * the requester and must emit the failure event (status 0).
 */
ATF_TC_WITHOUT_HEAD(cis_datapath_failure_emits_event);
ATF_TC_BODY(cis_datapath_failure_emits_event, tc)
{
	uint16_t h;

	env_init();
	h = make_cig();
	ATF_CHECK_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));

	setup_paths_override = 0;	/* host data path fails to come up */
	iso_on_cis_established(&test_adp, h, 0 /* controller says OK */);
	setup_paths_override = -1;
	ATF_CHECK(frame_is_iso_event(IPC_ISO_EV_FAILED));
}

/* A failed CIS only removes its CIG after the last sibling CIS is gone. */
ATF_TC_WITHOUT_HEAD(cis_failure_keeps_cig_for_configured_sibling);
ATF_TC_BODY(cis_failure_keeps_cig_for_configured_sibling, tc)
{
	struct hci_cis_param cises[2] = {
		{ .cis_id = 1, .max_sdu_c_to_p = 120, .phy_c_to_p = 2 },
		{ .cis_id = 2, .max_sdu_c_to_p = 120, .phy_c_to_p = 2 },
	};
	uint16_t handles[2];
	uint8_t count = 0;

	env_init();
	ATF_REQUIRE_EQ(0, blued_iso_cig_create(&test_adp, 8, 1000, 1000, 0,
	    0, 0, 10, 10, cises, 2, handles, &count));
	ATF_REQUIRE_EQ(2, count);
	ATF_REQUIRE_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 8, 1, -1, false));
	iso_on_cis_established(&test_adp, handles[0], 0x3e);
	ATF_CHECK_EQ(1, blued_iso_stream_count());
	ATF_CHECK_EQ(-1, idx_of(C_REMOVE_CIG));

	ATF_REQUIRE_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 8, 2, -1, false));
	iso_on_cis_established(&test_adp, handles[1], 0x3e);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
	ATF_CHECK(idx_of(C_REMOVE_CIG) >= 0);
}

/* Create CIS command-status failure keeps the CIG configured for later removal. */
ATF_TC_WITHOUT_HEAD(cis_create_command_error);
ATF_TC_BODY(cis_create_command_error, tc)
{
	uint16_t h;

	env_init();
	h = make_cig();
	fail_next = 1;
	ATF_CHECK_EQ(-1, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	/* Stream still parked in CIG_CONFIGURED; removable via ISO_REMOVE_CIG. */
	ATF_CHECK_EQ(ISO_ST_CIG_CONFIGURED, blued_iso_stream_state(&test_adp, h));
	ATF_CHECK_EQ(0, blued_iso_cig_remove(&test_adp, 0));
	ATF_CHECK_EQ(0, blued_iso_stream_count());
	ATF_CHECK(idx_of(C_REMOVE_CIG) >= 0);
}

/* Peer-initiated CIS loss frees the stream and emits ISO_LOST. */
ATF_TC_WITHOUT_HEAD(cis_peer_disconnect);
ATF_TC_BODY(cis_peer_disconnect, tc)
{
	uint16_t h;

	env_init();
	h = make_cig();
	ATF_CHECK_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	iso_on_cis_established(&test_adp, h, 0);

	iso_on_cis_disconnected(&test_adp, h, 0x13);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
	/* Already gone: a following teardown is a clean no-op, not a crash. */
	ATF_CHECK_EQ(-1, blued_iso_cis_teardown(&test_adp, h, 0x13));
}

/* Self-initiated teardown must NOT emit ISO_LOST, and a trailing peer
 * Disconnection Complete for the same handle is a harmless no-op. */
ATF_TC_WITHOUT_HEAD(cis_teardown_no_spurious_lost);
ATF_TC_BODY(cis_teardown_no_spurious_lost, tc)
{
	uint16_t h;

	env_init();
	h = make_cig();
	ATF_CHECK_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	iso_on_cis_established(&test_adp, h, 0);

	ATF_CHECK_EQ(0, blued_iso_cis_teardown(&test_adp, h, 0x13));

	/* Controller's own Disconnection Complete arrives afterwards. */
	iso_on_cis_disconnected(&test_adp, h, 0x16);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
}

/* Two CIS share a CIG: the CIG is removed only when its LAST CIS is torn down. */
ATF_TC_WITHOUT_HEAD(cig_removed_only_after_last_cis);
ATF_TC_BODY(cig_removed_only_after_last_cis, tc)
{
	struct hci_cis_param cises[2] = {
		{ .cis_id = 1, .max_sdu_c_to_p = 120, .phy_c_to_p = 2,
		  .phy_p_to_c = 1 },
		{ .cis_id = 2, .max_sdu_c_to_p = 120, .phy_c_to_p = 2,
		  .phy_p_to_c = 1 },
	};
	uint16_t handles[2];
	uint8_t count = 0;

	env_init();
	ATF_REQUIRE_EQ(0, blued_iso_cig_create(&test_adp, 3, 1000, 1000, 0, 0,
	    0, 10, 10, cises, 2, handles, &count));
	ATF_CHECK_EQ(2, count);
	ATF_REQUIRE_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 3, 1, -1, false));
	ATF_REQUIRE_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 3, 2, -1, false));
	iso_on_cis_established(&test_adp, handles[0], 0);
	iso_on_cis_established(&test_adp, handles[1], 0);
	ncall = 0;
	ATF_CHECK_EQ(-1, blued_iso_cig_remove(&test_adp, 3));
	ATF_CHECK_EQ(-1, idx_of(C_REMOVE_CIG));

	ATF_CHECK_EQ(0, blued_iso_cis_teardown(&test_adp, handles[0], 0x13));
	iso_on_cis_disconnected(&test_adp, handles[0], 0x13);
	ATF_CHECK_EQ(-1, idx_of(C_REMOVE_CIG));	/* one CIS still on the CIG */
	ATF_CHECK_EQ(1, blued_iso_stream_count());

	ATF_CHECK_EQ(0, blued_iso_cis_teardown(&test_adp, handles[1], 0x13));
	iso_on_cis_disconnected(&test_adp, handles[1], 0x13);
	ATF_CHECK(idx_of(C_REMOVE_CIG) >= 0);	/* now the last one is gone */
	ATF_CHECK_EQ(0, blued_iso_stream_count());
}

/* ================================================================
 * Peripheral CIS: request -> accept -> established, and request -> reject.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cis_peripheral_accept);
ATF_TC_BODY(cis_peripheral_accept, tc)
{
	uint16_t cis_h = 0x0033;

	env_init();
	/* Inbound procedure accept is observable in foreground diagnostics too. */
	blued_daemonized = 0;
	iso_on_cis_request(&test_adp, 0x0020, cis_h, 5, 1);
	ATF_CHECK_EQ(1, blued_iso_stream_count());
	ATF_CHECK_EQ(ISO_ST_REQUESTED, blued_iso_stream_state(&test_adp, cis_h));
	ATF_CHECK(frame_is_iso_event(IPC_ISO_EV_CIS_REQUEST));

	ATF_CHECK_EQ(0, blued_iso_cis_accept(&test_adp, cis_h));
	ATF_CHECK_EQ(ISO_ST_CREATING, blued_iso_stream_state(&test_adp, cis_h));
	ATF_CHECK(idx_of(C_ACCEPT) >= 0);
	/* A live CIS in CREATING is neither requestable nor rejectable again. */
	ATF_CHECK_EQ(-1, blued_iso_cis_accept(&test_adp, cis_h));
	ATF_CHECK_EQ(-1, blued_iso_cis_reject(&test_adp, cis_h, 0x0d));

	iso_on_cis_established(&test_adp, cis_h, 0);
	ATF_CHECK_EQ(ISO_ST_PATHS_UP, blued_iso_stream_state(&test_adp, cis_h));

	/* Torn down as any CIS. */
	ncall = 0;
	ATF_CHECK_EQ(0, blued_iso_cis_teardown(&test_adp, cis_h, 0x13));
	iso_on_cis_disconnected(&test_adp, cis_h, 0x13);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
	ATF_CHECK_EQ(-1, idx_of(C_REMOVE_CIG));
}

ATF_TC_WITHOUT_HEAD(cis_peripheral_reject);
ATF_TC_BODY(cis_peripheral_reject, tc)
{
	uint16_t cis_h = 0x0034;

	env_init();
	blued_daemonized = 0;
	iso_on_cis_request(&test_adp, 0x0020, cis_h, 5, 1);
	ATF_CHECK_EQ(0, blued_iso_cis_reject(&test_adp, cis_h, 0x0D));
	ATF_CHECK(idx_of(C_REJECT) >= 0);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
	/* Accepting after reject fails cleanly. */
	ATF_CHECK_EQ(-1, blued_iso_cis_accept(&test_adp, cis_h));
}

/* ================================================================
 * BIS source: create -> Create BIG Complete -> acquire -> terminate.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bis_source_lifecycle);
ATF_TC_BODY(bis_source_lifecycle, tc)
{
	/* Two BIS handles in the Create BIG Complete event (LE order). */
	uint8_t bis[4] = { 0x00, 0x01, 0x01, 0x01 };	/* 0x0100, 0x0101 */
	int fd;

	env_init();
	/* Exercise broadcaster lifecycle messages through the foreground route. */
	blued_daemonized = 0;
	ATF_CHECK_EQ(0, blued_iso_big_create(&test_adp, 1, 0, 2, 10000, 120,
	    10, 2, 2, 0, 0, 0, NULL));
	/* BIS handles are unknown until the event; the stream exists as CREATING. */
	ATF_CHECK_EQ(1, blued_iso_stream_count());

	/* One controller data-path setup can fail while another BIS path comes up;
	 * the partial group is not usable and its one live path is unwound. */
	fail_next = 1;
	iso_on_big_complete(&test_adp, 1, 0, 2, bis);
	ATF_CHECK_EQ(2, count_of(C_SETUP_PATH));
	ATF_CHECK_EQ(1, count_of(C_REMOVE_PATH));
	ATF_CHECK_EQ(1, count_of(C_TERM_BIG));
	ATF_CHECK_EQ(ISO_ST_TEARDOWN,
	    blued_iso_stream_state(&test_adp, 0x0100));
	ATF_CHECK_EQ(-1, blued_iso_acquire_bis_fd(&test_adp, 1, 1));
	iso_on_big_terminated(&test_adp, 1, 0x13);
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	/* A later complete retry exposes both BISes. */
	ncall = 0;
	ATF_REQUIRE_EQ(0, blued_iso_big_create(&test_adp, 1, 0, 2, 10000, 120,
	    10, 2, 2, 0, 0, 0, NULL));
	iso_on_big_complete(&test_adp, 1, 0, 2, bis);
	ATF_CHECK_EQ(ISO_ST_PATHS_UP, blued_iso_stream_state(&test_adp, 0x0100));
	ATF_CHECK_EQ(ISO_ST_PATHS_UP, blued_iso_stream_state(&test_adp, 0x0101));
	/* A BIS handle is visible through the generic handle lookup, but a CIS
	 * Disconnection Complete must not tear down a broadcast stream. */
	iso_on_cis_disconnected(&test_adp, 0x0100, 0x13);
	ATF_CHECK_EQ(ISO_ST_PATHS_UP,
	    blued_iso_stream_state(&test_adp, 0x0100));

	iso_connect_fail = true;
	ATF_CHECK_EQ(-1, blued_iso_acquire_bis_fd(&test_adp, 1, 1));
	ATF_CHECK_EQ(ISO_ST_PATHS_UP, blued_iso_stream_state(&test_adp, 0x0101));
	iso_connect_fail = false;
	fd = blued_iso_acquire_bis_fd(&test_adp, 1, 1);	/* the 2nd BIS */
	ATF_CHECK(fd >= 0);
	if (fd >= 0)
		close(fd);
	/* Handed-off streams remain acquirable, but bounds stay enforced. */
	fd = blued_iso_acquire_bis_fd(&test_adp, 1, 1);
	ATF_CHECK(fd >= 0);
	if (fd >= 0)
		close(fd);
	ATF_CHECK_EQ(-1, blued_iso_acquire_bis_fd(&test_adp, 1, 2));

	ATF_CHECK_EQ(0, blued_iso_big_terminate(&test_adp, 1, 0x13));
	iso_on_big_terminated(&test_adp, 1, 0x13);
	ATF_CHECK(idx_of(C_REMOVE_PATH) >= 0);
	ATF_CHECK(idx_of(C_REMOVE_PATH) < idx_of(C_TERM_BIG));
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	/* A malformed controller event with no BIS-handle array does not dereference
	 * the absent payload; the stream remains safely terminable. */
	ATF_REQUIRE_EQ(0, blued_iso_big_create(&test_adp, 8, 0, 1, 10000, 120,
	    10, 2, 2, 0, 0, 0, NULL));
	iso_on_big_complete(&test_adp, 8, 0, 1, NULL);
	ATF_CHECK_EQ(-1, blued_iso_big_terminate(&test_adp, 8, 0x13));
	iso_on_big_terminated(&test_adp, 8, 0x13);
	/* Trailing Terminate BIG Complete for the same handle is a no-op. */
	iso_on_big_terminated(&test_adp, 1, 0x13);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
}

/* BIS source establish failure frees the stream and emits ISO_LOST. */
ATF_TC_WITHOUT_HEAD(bis_source_establish_failure);
ATF_TC_BODY(bis_source_establish_failure, tc)
{

	env_init();
	ATF_CHECK_EQ(0, blued_iso_big_create(&test_adp, 2, 0, 1, 10000, 120,
	    10, 2, 2, 0, 0, 0, NULL));
	iso_on_big_complete(&test_adp, 2, 0x42, 0, NULL);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
}

/* ================================================================
 * BIS sink: create sync -> BIG Sync Established -> acquire -> sync lost.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bis_sink_lifecycle);
ATF_TC_BODY(bis_sink_lifecycle, tc)
{
	uint8_t indices[1] = { 1 };
	uint8_t bis[2] = { 0x05, 0x01 };	/* 0x0105 */
	int fd;

	env_init();
	/* Exercise synchronized-receiver lifecycle messages through foreground
	 * diagnostics; source tests above continue to cover daemonized logging. */
	blued_daemonized = 0;
	ATF_CHECK_EQ(0, blued_iso_big_create_sync(&test_adp, 4, 0x0044,
	    indices, 1, 0, 100, 0, NULL));
	ATF_CHECK_EQ(1, blued_iso_stream_count());

	iso_on_big_sync_established(&test_adp, 4, 0, 1, bis);
	ATF_CHECK_EQ(ISO_ST_PATHS_UP, blued_iso_stream_state(&test_adp, 0x0105));

	fd = blued_iso_acquire_bis_fd(&test_adp, 4, 0);
	ATF_CHECK(fd >= 0);
	if (fd >= 0)
		close(fd);

	/* Peer/broadcaster loss: BIG Sync Lost frees the sink + ISO_LOST. */
	iso_on_big_sync_lost(&test_adp, 4, 0x3D);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
}

/* Explicit sink termination reverses setup and frees the stream. */
ATF_TC_WITHOUT_HEAD(bis_sink_terminate);
ATF_TC_BODY(bis_sink_terminate, tc)
{
	uint8_t indices[1] = { 0 };
	uint8_t bis[2] = { 0x06, 0x01 };

	env_init();
	ATF_CHECK_EQ(0, blued_iso_big_create_sync(&test_adp, 5, 0x0055,
	    indices, 1, 0, 100, 0, NULL));
	iso_on_big_sync_established(&test_adp, 5, 0, 1, bis);

	ATF_CHECK_EQ(0, blued_iso_big_terminate_sync(&test_adp, 5));
	ATF_CHECK(idx_of(C_REMOVE_PATH) >= 0);
	ATF_CHECK(idx_of(C_REMOVE_PATH) < idx_of(C_TERM_SYNC));
	ATF_CHECK_EQ(0, blued_iso_stream_count());
}

/* Controller/daemon down: the sweep tears every stream down, no leak. */
ATF_TC_WITHOUT_HEAD(sweep_frees_everything);
ATF_TC_BODY(sweep_frees_everything, tc)
{
	uint8_t indices[1] = { 0 };

	env_init();
	(void)make_cig();
	ATF_CHECK_EQ(0, blued_iso_big_create(&test_adp, 1, 0, 1, 10000, 120,
	    10, 2, 2, 0, 0, 0, NULL));
	ATF_CHECK_EQ(0, blued_iso_big_create_sync(&test_adp, 2, 0x0044,
	    indices, 1, 0, 100, 0, NULL));
	/* Include an inbound peripheral CIS: adapter shutdown must disconnect both
	 * central and peripheral CIS roles before unlinking their registry state. */
	iso_on_cis_request(&test_adp, 0x0020, 0x0033, 1, 1);
	ATF_CHECK_EQ(4, blued_iso_stream_count());

	blued_iso_sweep_adapter(&test_adp);
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	/* A daemon-wide sweep is also used during global controller shutdown. */
	ATF_REQUIRE_EQ(0, blued_iso_big_create_sync(&test_adp, 3, 0x0045,
	    indices, 1, 0, 100, 0, NULL));
	blued_iso_sweep_adapter(NULL);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
}

/* A Central-owned CIG must not consume same-numbered inbound Peripheral CIS
 * records, whether they belong to this controller or another controller. */
ATF_TC_WITHOUT_HEAD(cig_remove_and_sweep_preserve_foreign_adapter);
ATF_TC_BODY(cig_remove_and_sweep_preserve_foreign_adapter, tc)
{
	struct blued_adapter adp2;
	struct hci_cis_param cis = {
		.cis_id = 3, .max_sdu_c_to_p = 120, .phy_c_to_p = 1,
	};
	uint16_t handles[1];
	uint8_t count = 0;

	env_init();
	memset(&adp2, 0, sizeof(adp2));
	adp2.hci_fd = 8;
	adp2.index = 1;

	iso_on_cis_request(&adp2, 0x0021, 0x0041, 6, 1);
	iso_on_cis_request(&test_adp, 0x0020, 0x0042, 6, 2);
	ATF_REQUIRE_EQ(0, blued_iso_cig_create(&test_adp, 6, 1000, 1000, 0,
	    0, 0, 10, 10, &cis, 1, handles, &count));
	ATF_REQUIRE_EQ(3, blued_iso_stream_count());

	ATF_CHECK_EQ(0, blued_iso_cig_remove(&test_adp, 6));
	ATF_CHECK_EQ(2, blued_iso_stream_count());
	ATF_CHECK_EQ(ISO_ST_REQUESTED,
	    blued_iso_stream_state(&test_adp, 0x0042));
	ATF_CHECK_EQ(ISO_ST_REQUESTED,
	    blued_iso_stream_state(&adp2, 0x0041));

	/* A per-adapter sweep likewise leaves another controller's stream live. */
	ncall = 0;
	blued_iso_sweep_adapter(&test_adp);
	ATF_CHECK_EQ(1, blued_iso_stream_count());
	ATF_CHECK(idx_of(C_REJECT) >= 0);
	blued_iso_sweep_adapter(&adp2);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
	ATF_CHECK(idx_of(C_REJECT) >= 0);
}

ATF_TC_WITHOUT_HEAD(adapter_local_handles_do_not_collide);
ATF_TC_BODY(adapter_local_handles_do_not_collide, tc)
{
	struct blued_adapter adp2;
	struct hci_cis_param cis = {
		.cis_id = 1, .max_sdu_c_to_p = 120, .phy_c_to_p = 1,
	};
	uint16_t h0[1], h1[1];
	uint8_t n0 = 0, n1 = 0;

	env_init();
	memset(&test_adp, 0, sizeof(test_adp));
	memset(&adp2, 0, sizeof(adp2));
	test_adp.index = 0;
	test_adp.hci_fd = 10;
	adp2.index = 1;
	adp2.hci_fd = 11;
	ATF_REQUIRE_EQ(0, blued_iso_cig_create(&test_adp, 0, 1000, 1000,
	    0, 0, 0, 10, 10, &cis, 1, h0, &n0));
	ATF_REQUIRE_EQ(0, blued_iso_cig_create(&adp2, 0, 1000, 1000,
	    0, 0, 0, 10, 10, &cis, 1, h1, &n1));
	ATF_REQUIRE_EQ(h0[0], h1[0]);
	ATF_CHECK_EQ(ISO_ST_CIG_CONFIGURED,
	    blued_iso_stream_state(&test_adp, h0[0]));
	ATF_CHECK_EQ(ISO_ST_CIG_CONFIGURED,
	    blued_iso_stream_state(&adp2, h1[0]));
	ATF_REQUIRE_EQ(0, blued_iso_cig_remove(&test_adp, 0));
	ATF_CHECK_EQ(-1, blued_iso_stream_state(&test_adp, h0[0]));
	ATF_CHECK_EQ(ISO_ST_CIG_CONFIGURED,
	    blued_iso_stream_state(&adp2, h1[0]));
	blued_iso_reset();
}

ATF_TC_WITHOUT_HEAD(command_failure_and_count_matrix);
ATF_TC_BODY(command_failure_and_count_matrix, tc)
{
	struct hci_cis_param cis = {
		.cis_id = 1, .max_sdu_c_to_p = 120,
		.phy_c_to_p = 2, .phy_p_to_c = 1,
	};
	uint16_t handles[2] = { 0 };
	uint8_t count = 0, bis = 1, code[16] = { 0 };

	env_init();
	fail_next = 1;
	ATF_CHECK_EQ(-1, blued_iso_cig_create(&test_adp, 1, 1000, 1000, 0,
	    0, 0, 10, 10, &cis, 1, handles, &count));
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	/* A response count inconsistent with the request rolls the CIG back. */
	setup_count_override = 2;
	ATF_CHECK_EQ(-1, blued_iso_cig_create(&test_adp, 1, 1000, 1000, 0,
	    0, 0, 10, 10, &cis, 1, handles, &count));
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
	ATF_CHECK(idx_of(C_REMOVE_CIG) >= 0);
	blued_iso_reset();
	setup_count_override = -1;

	/* A second-record allocation failure is also an atomic rollback. */
	{
		struct hci_cis_param pair[2] = { cis, cis };

		pair[1].cis_id = 2;
		ncall = 0;
		calloc_calls_until_fail = 1;
		ATF_CHECK_EQ(-1, blued_iso_cig_create(&test_adp, 1, 1000,
		    1000, 0, 0, 0, 10, 10, pair, 2, handles, &count));
		ATF_CHECK_EQ(0, count);
		ATF_CHECK_EQ(0, blued_iso_stream_count());
		ATF_CHECK(idx_of(C_REMOVE_CIG) >= 0);
	}
	ATF_REQUIRE_EQ(0, blued_iso_cig_create(&test_adp, 1, 1000, 1000, 0,
	    0, 0, 10, 10, &cis, 1, handles, &count));
	ATF_CHECK_EQ(-1, blued_iso_cig_create(&test_adp, 1, 1000, 1000, 0,
	    0, 0, 10, 10, &cis, 1, handles, &count));
	ATF_CHECK_EQ(1, blued_iso_stream_count());
	ATF_REQUIRE_EQ(0, blued_iso_cig_remove(&test_adp, 1));

	ATF_REQUIRE_EQ(0, blued_iso_big_create(&test_adp, 2, 0, 1, 1000,
	    120, 10, 1, 1, 0, 0, 0, code));
	ATF_CHECK_EQ(-1, blued_iso_big_create_sync(&test_adp, 2, 0x40, &bis,
	    1, 1, 100, 0, code));
	ATF_CHECK_EQ(1, blued_iso_stream_count());
	ATF_REQUIRE_EQ(0, blued_iso_big_terminate(&test_adp, 2, 0x13));
	iso_on_big_terminated(&test_adp, 2, 0x13);

	/* Each asynchronous creation verb propagates its HCI command failure. */
	fail_next = 1;
	ATF_CHECK_EQ(-1, blued_iso_big_create(&test_adp, 2, 0, 1, 1000, 120,
	    10, 1, 1, 0, 0, 0, code));
	ATF_CHECK_EQ(0, blued_iso_stream_count());
	fail_next = 1;
	ATF_CHECK_EQ(-1, blued_iso_big_create_sync(&test_adp, 3, 0x40, &bis,
	    1, 1, 100, 0, code));
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	/* A failed peripheral accept leaves the request available for rejection. */
	iso_on_cis_request(&test_adp, 0x0020, 0x0035, 5, 1);
	fail_next = 1;
	ATF_CHECK_EQ(-1, blued_iso_cis_accept(&test_adp, 0x0035));
	ATF_CHECK_EQ(ISO_ST_REQUESTED,
	    blued_iso_stream_state(&test_adp, 0x0035));
	ATF_CHECK_EQ(0, blued_iso_cis_reject(&test_adp, 0x0035, 0x0d));
}

ATF_TC_WITHOUT_HEAD(defensive_state_completion);
ATF_TC_BODY(defensive_state_completion, tc)
{
	struct hci_cis_param cis;
	uint8_t bis = 1, code[16] = { 0 };
	uint16_t h;

	env_init();
	/* Retain coverage of the non-daemon diagnostic route. */
	blued_daemonized = 0;
	memset(&cis, 0, sizeof(cis));
	ATF_CHECK_EQ(-1, blued_iso_cig_create(NULL, 0, 0, 0, 0, 0, 0, 0,
	    0, NULL, 0, NULL, NULL));
	/* Exercise every independent input guard with a real adapter; the NULL
	 * case above intentionally short-circuits before these protocol bounds. */
	ATF_CHECK_EQ(-1, blued_iso_cig_create(&test_adp, 0, 0, 0, 0, 0, 0, 0,
	    0, NULL, 1, NULL, NULL));
	ATF_CHECK_EQ(-1, blued_iso_cig_create(&test_adp, 0, 0, 0, 0, 0, 0, 0,
	    0, &cis, 0, NULL, NULL));
	ATF_CHECK_EQ(-1, blued_iso_cig_create(&test_adp, 0, 0, 0, 0, 0, 0, 0,
	    0, &cis, 17, NULL, NULL));
	ATF_CHECK_EQ(-1, blued_iso_cis_create(NULL, NULL, 0, 0, 0, -1,
	    false));
	/* Check the independent peer-pointer guard (the NULL-adapter case above
	 * deliberately short-circuits before it). */
	ATF_CHECK_EQ(-1, blued_iso_cis_create(&test_adp, NULL,
	    BDADDR_LE_PUBLIC, 0, 0, -1, false));
	/* Result arrays are optional API outputs.  A caller interested only in
	 * configuring the CIG must not need to provide either one. */
	ATF_REQUIRE_EQ(0, blued_iso_cig_create(&test_adp, 0, 1000, 1000, 0,
	    0, 0, 10, 10, &cis, 1, NULL, NULL));
	blued_iso_reset();
	ATF_CHECK_EQ(-1, blued_iso_cig_remove(NULL, 0));
	ATF_CHECK_EQ(-1, blued_iso_cis_accept(NULL, 0));
	ATF_CHECK_EQ(-1, blued_iso_cis_reject(NULL, 0, 0));
	ATF_CHECK_EQ(-1, blued_iso_big_create(NULL, 0, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0, code));
	ATF_CHECK_EQ(-1, blued_iso_big_create(&test_adp, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0, 0, code));
	ATF_CHECK_EQ(-1, blued_iso_big_create(&test_adp, 0, 0,
	    ISO_MAX_BIS + 1, 0, 0, 0, 0, 0, 0, 0, 0, code));
	ATF_CHECK_EQ(-1, blued_iso_big_create_sync(NULL, 0, 0, NULL, 0, 0,
	    0, 0, code));
	ATF_CHECK_EQ(-1, blued_iso_big_create_sync(&test_adp, 0, 0, NULL, 1,
	    0, 0, 0, code));
	ATF_CHECK_EQ(-1, blued_iso_big_create_sync(&test_adp, 0, 0, &bis, 0,
	    0, 0, 0, code));
	ATF_CHECK_EQ(-1, blued_iso_big_create_sync(&test_adp, 0, 0, &bis,
	    ISO_MAX_BIS + 1, 0, 0, 0, code));
	ATF_CHECK_EQ(-1, blued_iso_big_terminate(NULL, 0, 0));
	ATF_CHECK_EQ(-1, blued_iso_big_terminate_sync(NULL, 0));
	ATF_CHECK_EQ(-1, blued_iso_acquire_fd(&test_adp, 0xffff));
	ATF_CHECK_EQ(-1, blued_iso_acquire_bis_fd(&test_adp, 0xff, 0));
	ATF_CHECK_EQ(-1, blued_iso_cis_teardown(&test_adp, 0xffff, 0));

	/* Registry lookups must skip a live BIS when a CIS-only operation is
	 * requested.  An unknown local CIG is not forwarded to the controller. */
	ATF_REQUIRE_EQ(0, blued_iso_big_create(&test_adp, 0x7e, 0, 1, 1000,
	    60, 10, 1, 1, 0, 0, 0, NULL));
	ATF_CHECK_EQ(-1, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	ATF_CHECK_EQ(-1, blued_iso_cig_remove(&test_adp, 0));
	ATF_CHECK_EQ(0, blued_iso_big_terminate(&test_adp, 0x7e, 0x13));
	iso_on_big_terminated(&test_adp, 0x7e, 0x13);

	/* Missing registry entries are harmless for every asynchronous event. */
	iso_on_cis_established(&test_adp, 0xffff, 0);
	iso_on_big_complete(&test_adp, 0xfe, 0, 0, NULL);
	iso_on_big_sync_established(&test_adp, 0xfd, 0, 0, NULL);
	iso_on_cis_disconnected(&test_adp, 0xffff, 0);
	iso_on_big_sync_lost(&test_adp, 0xfc, 0);
	iso_on_big_terminated(&test_adp, 0xfb, 0);

	/* A duplicate peripheral request is ignored without replacing state. */
	iso_on_cis_request(&test_adp, 0x20, 0x40, 1, 1);
	iso_on_cis_request(&test_adp, 0x20, 0x40, 1, 1);
	ATF_CHECK_EQ(1, blued_iso_stream_count());
	blued_iso_reset();

	/* Connected peer but no configured CIG/CIS.  A locally unknown CIG is
	 * rejected without issuing a controller command. */
	ATF_CHECK_EQ(-1, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 9, 9, -1, false));
	ATF_CHECK_EQ(-1, blued_iso_cig_remove(&test_adp, 9));

	/* A source cannot be terminated through the sink verb, nor vice versa. */
	ATF_REQUIRE_EQ(0, blued_iso_big_create(&test_adp, 2, 0, 1, 1000, 60,
	    10, 1, 1, 0, 0, 0, code));
	ATF_CHECK_EQ(-1, blued_iso_big_terminate_sync(&test_adp, 2));
	ATF_REQUIRE_EQ(0, blued_iso_big_terminate(&test_adp, 2, 0x13));
	ATF_REQUIRE_EQ(0, blued_iso_big_create_sync(&test_adp, 3, 0x30, &bis,
	    1, 1, 100, 0, code));
	ATF_CHECK_EQ(-1, blued_iso_big_terminate(&test_adp, 3, 0x13));
	ATF_REQUIRE_EQ(0, blued_iso_big_terminate_sync(&test_adp, 3));

	/* Established streams with no usable controller data path fail closed. */
	h = make_cig();
	ATF_REQUIRE_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	setup_paths_override = 0;
	iso_on_cis_established(&test_adp, h, 0);
	ATF_CHECK_EQ(ISO_ST_TEARDOWN,
	    blued_iso_stream_state(&test_adp, h));
	iso_on_cis_disconnected(&test_adp, h, 0x13);
	ATF_CHECK_EQ(-1, blued_iso_stream_state(&test_adp, h));
	setup_paths_override = -1;
	/* A controller-reported CIS establish failure releases the final CIG
	 * reference as well as the stream, so callers cannot retain a stale CIG. */
	blued_iso_reset();
	h = make_cig();
	ATF_REQUIRE_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	iso_on_cis_established(&test_adp, h, 0x3e);
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	ATF_REQUIRE_EQ(0, blued_iso_big_create(&test_adp, 4, 0, 1, 1000, 60,
	    10, 1, 1, 0, 0, 0, code));
	setup_paths_override = 0;
	iso_on_big_complete(&test_adp, 4, 0, 1,
	    (const uint8_t[]){ 0x44, 0x00 });
	iso_on_big_terminated(&test_adp, 4, 0x13);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
}

/* A failed controller teardown command must not make the daemon forget an
 * object which may still exist in the controller.  Retaining the registry
 * entry makes every operation retryable and prevents handle reuse races. */
ATF_TC_WITHOUT_HEAD(teardown_command_failure_is_retryable);
ATF_TC_BODY(teardown_command_failure_is_retryable, tc)
{
	uint8_t bis_index = 1, bis_handle[2] = { 0x05, 0x01 };
	uint16_t h;

	env_init();

	h = make_cig();
	fail_next = 1;
	ATF_CHECK_EQ(-1, blued_iso_cig_remove(&test_adp, 0));
	ATF_CHECK_EQ(ISO_ST_CIG_CONFIGURED,
	    blued_iso_stream_state(&test_adp, h));
	ATF_CHECK_EQ(0, blued_iso_cig_remove(&test_adp, 0));
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	ATF_REQUIRE_EQ(0, blued_iso_big_create(&test_adp, 2, 0, 1, 1000,
	    120, 10, 1, 1, 0, 0, 0, NULL));
	fail_next = 1;
	ATF_CHECK_EQ(-1, blued_iso_big_terminate(&test_adp, 2, 0x13));
	ATF_CHECK_EQ(1, blued_iso_stream_count());
	ATF_CHECK_EQ(0, blued_iso_big_terminate(&test_adp, 2, 0x13));
	/* Command Status is not termination completion: keep the handle reserved,
	 * and ignore a stale/duplicate Create BIG Complete in this window. */
	ATF_CHECK_EQ(-1, blued_iso_big_create(&test_adp, 2, 0, 1, 1000,
	    120, 10, 1, 1, 0, 0, 0, NULL));
	iso_on_big_complete(&test_adp, 2, 0x44, 1, bis_handle);
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	ATF_REQUIRE_EQ(0, blued_iso_big_create(&test_adp, 2, 0, 1, 1000,
	    120, 10, 1, 1, 0, 0, 0, NULL));
	iso_on_big_complete(&test_adp, 2, 0, 1, bis_handle);
	ATF_CHECK_EQ(1, blued_iso_stream_count());
	fail_next = 1;
	ATF_CHECK_EQ(-1, blued_iso_big_terminate(&test_adp, 2, 0x13));
	ATF_CHECK_EQ(ISO_ST_ESTABLISHED,
	    blued_iso_stream_state(&test_adp, 0x0105));
	ATF_CHECK_EQ(1, count_of(C_REMOVE_PATH));
	ATF_CHECK_EQ(0, blued_iso_big_terminate(&test_adp, 2, 0x13));
	ATF_CHECK_EQ(1, count_of(C_REMOVE_PATH));
	iso_on_big_terminated(&test_adp, 2, 0x13);
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	ATF_REQUIRE_EQ(0, blued_iso_big_create_sync(&test_adp, 3, 0x40,
	    &bis_index, 1, 1, 100, 0, NULL));
	iso_on_big_sync_established(&test_adp, 3, 0, 1, bis_handle);
	fail_next = 1;
	ATF_CHECK_EQ(-1, blued_iso_big_terminate_sync(&test_adp, 3));
	ATF_CHECK_EQ(1, blued_iso_stream_count());
	ATF_CHECK_EQ(ISO_ST_ESTABLISHED,
	    blued_iso_stream_state(&test_adp, 0x0105));
	ATF_CHECK_EQ(0, blued_iso_big_terminate_sync(&test_adp, 3));
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	iso_on_cis_request(&test_adp, 0x0020, 0x0035, 5, 1);
	fail_next = 1;
	ATF_CHECK_EQ(-1, blued_iso_cis_reject(&test_adp, 0x0035, 0x0d));
	ATF_CHECK_EQ(ISO_ST_REQUESTED,
	    blued_iso_stream_state(&test_adp, 0x0035));
	ATF_CHECK_EQ(0, blued_iso_cis_reject(&test_adp, 0x0035, 0x0d));
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	h = make_cig();
	ATF_REQUIRE_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	iso_on_cis_established(&test_adp, h, 0);
	fail_next = 1;
	ATF_CHECK_EQ(-1, blued_iso_cis_teardown(&test_adp, h, 0x13));
	ATF_CHECK_EQ(ISO_ST_ESTABLISHED,
	    blued_iso_stream_state(&test_adp, h));
	ATF_CHECK_EQ(0, blued_iso_cis_teardown(&test_adp, h, 0x13));
	iso_on_cis_established(&test_adp, h, 0);
	ATF_CHECK_EQ(ISO_ST_TEARDOWN,
	    blued_iso_stream_state(&test_adp, h));
	iso_on_cis_disconnected(&test_adp, h, 0x13);
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	h = make_cig();
	ATF_REQUIRE_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	setup_path_fail_direction = HCI_ISO_DIR_OUTPUT;
	iso_on_cis_established(&test_adp, h, 0);
	ATF_CHECK_EQ(ISO_ST_PATHS_UP,
	    blued_iso_stream_state(&test_adp, h));
	ncall = 0;
	ATF_CHECK_EQ(0, blued_iso_cis_teardown(&test_adp, h, 0x13));
	ATF_CHECK_EQ(1, count_of(C_REMOVE_PATH));
	iso_on_cis_disconnected(&test_adp, h, 0x13);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
}

ATF_TC_WITHOUT_HEAD(remaining_registry_and_fault_paths);
ATF_TC_BODY(remaining_registry_and_fault_paths, tc)
{
	struct hci_cis_param cis = { .cis_id = 1, .max_sdu_c_to_p = 60,
	    .phy_c_to_p = 1 };
	uint8_t code[16] = { 0 }, bis = 1;
	uint8_t handles_le[2 * ISO_MAX_BIS];
	uint16_t handles[2], h;
	uint8_t count;

	env_init();
	/* This matrix deliberately drives uncommon error and cleanup paths.  Run
	 * them through the foreground diagnostic sink as well: blued supports both
	 * service-managed syslog and an operator's foreground invocation. */
	blued_daemonized = 0;
	/* Each iso_alloc() caller propagates allocation exhaustion. */
	fail_calloc = true;
	ATF_CHECK_EQ(-1, blued_iso_cig_create(&test_adp, 0, 1000, 1000, 0,
	    0, 0, 10, 10, &cis, 1, handles, &count));
	fail_calloc = true;
	ATF_CHECK_EQ(-1, blued_iso_big_create(&test_adp, 1, 0, 1, 1000, 60,
	    10, 1, 1, 0, 0, 0, code));
	fail_calloc = true;
	ATF_CHECK_EQ(-1, blued_iso_big_create_sync(&test_adp, 1, 0x20, &bis,
	    1, 1, 100, 0, code));
	fail_calloc = true;
	iso_on_cis_request(&test_adp, 0x20, 0x30, 1, 1);
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	/* A configured CIS cannot be acquired before paths exist; a missing ACL
	 * and a second Create in the CREATING state both fail explicitly. */
	h = make_cig();
	ATF_CHECK_EQ(-1, blued_iso_acquire_fd(&test_adp, h));
	conn_present = false;
	ATF_CHECK_EQ(-1, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	conn_present = true;
	ATF_REQUIRE_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	ATF_CHECK_EQ(-1, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	blued_iso_reset();

	/* Populate the best-effort peer lookup arm on an inbound CIS request. */
	test_conn.adapter = &test_adp;
	test_conn.con_handle = 0x20;
	test_conn.addr_type = BDADDR_LE_RANDOM;
	memset(&test_conn.dst, 0x5a, sizeof(test_conn.dst));
	LIST_INSERT_HEAD(&blued_g.conns, &test_conn, entries);
	iso_on_cis_request(&test_adp, 0x20, 0x31, 1, 1);
	LIST_REMOVE(&test_conn, entries);
	blued_iso_reset();

	/* An inbound CIS may arrive before the matching ACL record is visible, or
	 * while another adapter's ACL record is present.  It must remain tracked
	 * but must not inherit identity information from either nonmatching link. */
	test_conn.adapter = NULL;
	test_conn.con_handle = 0x20;
	LIST_INSERT_HEAD(&blued_g.conns, &test_conn, entries);
	iso_on_cis_request(&test_adp, 0x20, 0x32, 1, 2);
	LIST_REMOVE(&test_conn, entries);
	blued_iso_reset();
	test_conn.adapter = &test_adp;
	test_conn.con_handle = 0x21;
	LIST_INSERT_HEAD(&blued_g.conns, &test_conn, entries);
	iso_on_cis_request(&test_adp, 0x20, 0x33, 1, 3);
	LIST_REMOVE(&test_conn, entries);
	blued_iso_reset();

	/* Wrong-role and pre-establishment BIS operations are rejected. */
	ATF_REQUIRE_EQ(0, blued_iso_big_create(&test_adp, 2, 0, 1, 1000, 60,
	    10, 1, 1, 0, 0, 0, code));
	ATF_CHECK_EQ(-1, blued_iso_acquire_bis_fd(&test_adp, 2, 0));
	iso_on_big_sync_lost(&test_adp, 2, 0x13);
	memset(handles_le, 0, sizeof(handles_le));
	for (unsigned i = 0; i < ISO_MAX_BIS; i++)
		handles_le[2 * i] = (uint8_t)(0x40 + i);
	iso_on_big_complete(&test_adp, 2, 0, ISO_MAX_BIS + 1, handles_le);
	ATF_CHECK_EQ(-1, blued_iso_cis_teardown(&test_adp, 0x40, 0x13));
	iso_on_cis_disconnected(&test_adp, 0x40, 0x13);
	iso_on_big_terminated(&test_adp, 2, 0x13);
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	/* A sink ignores the source termination event, then handles sync loss. */
	ATF_REQUIRE_EQ(0, blued_iso_big_create_sync(&test_adp, 3, 0x30, &bis,
	    1, 1, 100, 0, code));
	iso_on_big_sync_established(&test_adp, 3, 0, 1,
	    (const uint8_t[]){ 0x50, 0x00 });
	iso_on_big_terminated(&test_adp, 3, 0x13);
	iso_on_big_sync_lost(&test_adp, 3, 0x13);
	ATF_CHECK_EQ(0, blued_iso_stream_count());
}

/* Multiple ISO procedures may coexist on one controller.  A lookup must walk
 * past a stream with the right broad class but a different procedure identity,
 * and past an inbound CIS while resolving an outbound CIG. */
ATF_TC_WITHOUT_HEAD(registry_identity_and_role_collision_matrix);
ATF_TC_BODY(registry_identity_and_role_collision_matrix, tc)
{
	struct hci_cis_param first = { .cis_id = 1, .max_sdu_c_to_p = 60,
	    .phy_c_to_p = 1 };
	struct hci_cis_param second = { .cis_id = 2, .max_sdu_c_to_p = 60,
	    .phy_c_to_p = 1 };
	uint8_t bis = 1, code[16] = { 0 };
	uint16_t handles[1];
	uint8_t count;

	env_init();
	/* Both configured CIGs use the test controller's same synthetic handle.
	 * Their CIG/CIS identity, rather than list position, selects the stream. */
	ATF_REQUIRE_EQ(0, blued_iso_cig_create(&test_adp, 4, 1000, 1000, 0,
	    0, 0, 10, 10, &first, 1, handles, &count));
	ATF_REQUIRE_EQ(0, blued_iso_cig_create(&test_adp, 5, 1000, 1000, 0,
	    0, 0, 10, 10, &second, 1, handles, &count));
	/* A request for the impossible CIG-4/CIS-2 pair must not select either
	 * neighboring stream. */
	ATF_CHECK_EQ(-1, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 4, 2, -1, false));
	/* An inbound CIS is a distinct role and must also be skipped. */
	iso_on_cis_request(&test_adp, 0x0020, 0x0040, 9, 1);
	ATF_CHECK_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 5, 2, -1, false));
	ATF_CHECK_EQ(ISO_ST_CREATING,
	    blued_iso_stream_state(&test_adp, handles[0]));

	/* Source and synchronized-sink BIGs can coexist too.  Wrong-role commands
	 * must not accidentally select a same-controller BIG with a different ID. */
	ATF_REQUIRE_EQ(0, blued_iso_big_create(&test_adp, 7, 0, 1, 1000, 60,
	    10, 1, 1, 0, 0, 0, code));
	ATF_REQUIRE_EQ(0, blued_iso_big_create_sync(&test_adp, 8, 0x30, &bis,
	    1, 1, 100, 0, code));
	ATF_CHECK_EQ(-1, blued_iso_big_terminate(&test_adp, 8, 0x13));
	ATF_CHECK_EQ(-1, blued_iso_big_terminate_sync(&test_adp, 7));
	ATF_CHECK_EQ(0, blued_iso_big_terminate(&test_adp, 7, 0x13));
	ATF_CHECK_EQ(0, blued_iso_big_terminate_sync(&test_adp, 8));
	blued_iso_reset();
}

ATF_TC_WITHOUT_HEAD(typed_iso_opcode_and_guard_sweep);
ATF_TC_BODY(typed_iso_opcode_and_guard_sweep, tc)
{
	struct blued_ctl_client client;
	uint8_t body[4];
	uint32_t request_id;
	uint16_t status, flags;
	int opcode;

	reset();
	memset(&client, 0, sizeof(client));
	client.fd = 9;
	client.peer_known = true;
	client.peer_uid = 0;
	client.active_request_id = 0x12345678;
	test_adp.active = true;
	for (opcode = IPC_ISO_CIG_CREATE; opcode <= IPC_ISO_CONNECT_ACQUIRE;
	    opcode++) {
		memset(body, 0, sizeof(body));
		ipc_put_le16(body, (uint16_t)opcode);
		frame_len = 0;
		ctl_iso_process_typed(&client, body, sizeof(body));
		ATF_REQUIRE_EQ(IPC_T_OP_REPLY, frame_type);
		ATF_REQUIRE_EQ(IPC_OP_DOMAIN_ISO, frame_domain);
		ATF_REQUIRE(frame_len >= IPC_OP_PREFIX_SIZE);
		ipc_op_prefix_decode(frame_buf, &request_id, &status, &flags);
		ATF_CHECK_EQ(client.active_request_id, request_id);
	}

	client.peer_uid = 1000;
	ctl_iso_process_typed(&client, body, sizeof(body));
	ipc_op_prefix_decode(frame_buf, &request_id, &status, &flags);
	ATF_CHECK_EQ(IPC_ERR_PERM, status);
	client.peer_uid = 0;
	client.peer_known = false;
	ctl_iso_process_typed(&client, body, sizeof(body));
	ipc_op_prefix_decode(frame_buf, &request_id, &status, &flags);
	ATF_CHECK_EQ(IPC_ERR_PERM, status);
	client.peer_known = true;
	ctl_iso_process_typed(&client, body, 3);
	ipc_op_prefix_decode(frame_buf, &request_id, &status, &flags);
	ATF_CHECK_EQ(IPC_ERR_PROTO, status);
	ipc_put_le16(body + 2, IPC_OP_FLAGS_RESERVED_MASK);
	ctl_iso_process_typed(&client, body, sizeof(body));
	ipc_op_prefix_decode(frame_buf, &request_id, &status, &flags);
	ATF_CHECK_EQ(IPC_ERR_INVAL, status);
	ipc_put_le16(body + 2, 0);
	test_adp.active = false;
	ctl_iso_process_typed(&client, body, sizeof(body));
	ipc_op_prefix_decode(frame_buf, &request_id, &status, &flags);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, status);
	test_adp.active = true;
	/* A syntactically valid adapter index with no registered adapter takes
	 * the distinct NULL-adapter arm of the lookup guard. */
	ipc_put_le16(body + 2, 1u << IPC_OP_ADAPTER_SHIFT);
	ctl_iso_process_typed(&client, body, sizeof(body));
	ipc_op_prefix_decode(frame_buf, &request_id, &status, &flags);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, status);
}

static uint16_t
typed_iso_status(struct blued_ctl_client *client, uint8_t *body, size_t len)
{
	uint32_t request_id;
	uint16_t status, flags;

	frame_len = 0;
	ctl_iso_process_typed(client, body, len);
	ATF_REQUIRE_EQ(IPC_T_OP_REPLY, frame_type);
	ATF_REQUIRE_EQ(IPC_OP_DOMAIN_ISO, frame_domain);
	ATF_REQUIRE(frame_len >= IPC_OP_PREFIX_SIZE);
	ipc_op_prefix_decode(frame_buf, &request_id, &status, &flags);
	ATF_CHECK_EQ(client->active_request_id, request_id);
	ATF_CHECK_EQ(0, flags);
	return (status);
}

/* Async completion errors are controller-originated inputs, not merely command
 * failures.  Verify each owner is unlinked and an fd-open failure remains
 * retryable while the ISO path stays established. */
ATF_TC_WITHOUT_HEAD(async_completion_failure_matrix);
ATF_TC_BODY(async_completion_failure_matrix, tc)
{
	uint8_t bis = 1, code[16] = { 0 };
	uint16_t h;
	int fd;

	env_init();
	/* Controller-originated completion errors must remain equally observable
	 * when the daemon is run interactively for link diagnosis. */
	blued_daemonized = 0;
	ATF_REQUIRE_EQ(0, blued_iso_big_create(&test_adp, 0x31, 0, 1, 1000,
	    60, 10, 1, 1, 0, 0, 0, code));
	iso_on_big_complete(&test_adp, 0x31, 0x3e, 0, NULL);
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	ATF_REQUIRE_EQ(0, blued_iso_big_create_sync(&test_adp, 0x32, 0x40,
	    &bis, 1, 1, 100, 0, code));
	iso_on_big_sync_established(&test_adp, 0x32, 0x3e, 0, NULL);
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	/* A successful BIG event with zero BIS handles cannot stand up a path. */
	ATF_REQUIRE_EQ(0, blued_iso_big_create(&test_adp, 0x33, 0, 1, 1000,
	    60, 10, 1, 1, 0, 0, 0, code));
	iso_on_big_complete(&test_adp, 0x33, 0, 0, NULL);
	iso_on_big_terminated(&test_adp, 0x33, 0x13);
	ATF_CHECK_EQ(0, blued_iso_stream_count());

	h = make_cig();
	ATF_REQUIRE_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	iso_on_cis_established(&test_adp, h, 0);
	iso_connect_fail = true;
	ATF_CHECK_EQ(-1, blued_iso_acquire_fd(&test_adp, h));
	ATF_CHECK_EQ(ISO_ST_PATHS_UP, blued_iso_stream_state(&test_adp, h));
	iso_connect_fail = false;
	fd = blued_iso_acquire_fd(&test_adp, h);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(0, blued_iso_cis_teardown(&test_adp, h, 0x13));
}

ATF_TC_WITHOUT_HEAD(typed_iso_valid_operation_matrix);
ATF_TC_BODY(typed_iso_valid_operation_matrix, tc)
{
	struct blued_ctl_client client;
	uint8_t body[64], *cis;
	size_t len;

	env_init();
	memset(&client, 0, sizeof(client));
	client.fd = 9;
	client.peer_known = true;
	client.peer_uid = 0;
	client.wants_fdpass = true;
	client.active_request_id = 0x23456789;
	test_adp.active = true;

	/* Create a one-stream CIG and then its CIS. */
	len = IPC_ISO_CIG_REQ_HDR_SIZE + IPC_ISO_CIS_PARAM_SIZE;
	memset(body, 0, len);
	ipc_put_le16(body, IPC_ISO_CIG_CREATE);
	body[4] = 1;
	body[5] = 1;
	ipc_put_le16(body + 10, 5);
	ipc_put_le16(body + 12, 5);
	ipc_put_le32(body + 14, 10000);
	ipc_put_le32(body + 18, 10000);
	cis = body + IPC_ISO_CIG_REQ_HDR_SIZE;
	cis[0] = 2;
	cis[1] = 1;
	cis[2] = 1;
	ipc_put_le16(cis + 6, 120);
	ipc_put_le16(cis + 8, 120);
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body, len));
	ATF_CHECK_EQ(1, frame_buf[IPC_OP_PREFIX_SIZE + 2]);

	memset(body, 0, IPC_ISO_CIS_CREATE_REQ_SIZE);
	ipc_put_le16(body, IPC_ISO_CIS_CREATE);
	body[11] = 1;
	body[12] = 2;
	body[13] = 1;
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body,
	    IPC_ISO_CIS_CREATE_REQ_SIZE));
	/* The controller completes CIS creation asynchronously.  Once paths are
	 * established, the typed ISO_ACQUIRE verb must hand the client the data
	 * path fd (Core Spec Vol 4 Part E §7.7.65.25). */
	iso_on_cis_established(&test_adp, 0x0010, 0);
	memset(body, 0, IPC_ISO_SIMPLE_REQ_SIZE);
	ipc_put_le16(body, IPC_ISO_ACQUIRE);
	ipc_put_le16(body + 4, 0x0010);
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body,
	    IPC_ISO_SIMPLE_REQ_SIZE));
	ATF_CHECK_EQ(2, fd_handouts);

	/* Exercise every simple lifecycle verb through its typed decoder. */
	static const uint16_t simple_ops[] = {
		IPC_ISO_CIS_ACCEPT, IPC_ISO_CIS_REJECT,
		IPC_ISO_CIS_TEARDOWN, IPC_ISO_CIG_REMOVE,
	};
	for (size_t i = 0; i < sizeof(simple_ops) / sizeof(simple_ops[0]); i++) {
		memset(body, 0, IPC_ISO_SIMPLE_REQ_SIZE);
		ipc_put_le16(body, simple_ops[i]);
		ipc_put_le16(body + 4, 0x0010);
		body[6] = 0x13;
		(void)typed_iso_status(&client, body, IPC_ISO_SIMPLE_REQ_SIZE);
	}
	iso_on_cis_disconnected(&test_adp, 0x0010, 0x13);
	/* The same typed CIS verb also supports a static-random peer and pull-only
	 * acquisition.  This must not implicitly hand an fd to the control client. */
	(void)make_cig();
	memset(body, 0, IPC_ISO_CIS_CREATE_REQ_SIZE);
	ipc_put_le16(body, IPC_ISO_CIS_CREATE);
	body[4] = 1;                 /* SMP/LE wire type: static random */
	body[11] = 0;                /* CIG 0 from make_cig() */
	body[12] = 1;
	body[13] = 0;                /* pull, rather than push-on-establish */
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body,
	    IPC_ISO_CIS_CREATE_REQ_SIZE));
	iso_on_cis_established(&test_adp, 0x0010, 0);
	ATF_CHECK_EQ(0, blued_iso_cis_teardown(&test_adp, 0x0010, 0x13));
	iso_on_cis_disconnected(&test_adp, 0x0010, 0x13);
	/* Cover successful simple-operation dispatches as well as the negative
	 * matrix above: a configured CIG can be removed, and an inbound CIS can
	 * be explicitly accepted or rejected by the privileged operator. */
	(void)make_cig();
	memset(body, 0, IPC_ISO_SIMPLE_REQ_SIZE);
	ipc_put_le16(body, IPC_ISO_CIG_REMOVE);
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body,
	    IPC_ISO_SIMPLE_REQ_SIZE));
	iso_on_cis_request(&test_adp, 0x0020, 0x0034, 5, 1);
	memset(body, 0, IPC_ISO_SIMPLE_REQ_SIZE);
	ipc_put_le16(body, IPC_ISO_CIS_ACCEPT);
	ipc_put_le16(body + 4, 0x0034);
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body,
	    IPC_ISO_SIMPLE_REQ_SIZE));
	iso_on_cis_request(&test_adp, 0x0020, 0x0035, 5, 2);
	memset(body, 0, IPC_ISO_SIMPLE_REQ_SIZE);
	ipc_put_le16(body, IPC_ISO_CIS_REJECT);
	ipc_put_le16(body + 4, 0x0035);
	body[6] = 0x0d;
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body,
	    IPC_ISO_SIMPLE_REQ_SIZE));

	memset(body, 0, IPC_ISO_BIG_REQ_SIZE);
	ipc_put_le16(body, IPC_ISO_BIG_CREATE);
	body[4] = 3;
	body[6] = 1;
	body[8] = 1;
	ipc_put_le32(body + 14, 10000);
	ipc_put_le16(body + 18, 120);
	ipc_put_le16(body + 20, 10);
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body,
	    IPC_ISO_BIG_REQ_SIZE));
	iso_on_big_complete(&test_adp, 3, 0, 1,
	    (const uint8_t[]){ 0x00, 0x01 });
	memset(body, 0, IPC_ISO_SIMPLE_REQ_SIZE);
	ipc_put_le16(body, IPC_ISO_BIS_ACQUIRE);
	body[4] = 3;
	body[5] = 0;
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body,
	    IPC_ISO_SIMPLE_REQ_SIZE));
	ATF_CHECK_EQ(3, fd_handouts);
	memset(body, 0, IPC_ISO_SIMPLE_REQ_SIZE);
	ipc_put_le16(body, IPC_ISO_BIG_TERMINATE);
	body[4] = 3;
	body[5] = 0x13;
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body,
	    IPC_ISO_SIMPLE_REQ_SIZE));

	memset(body, 0, IPC_ISO_BIG_SYNC_REQ_SIZE);
	ipc_put_le16(body, IPC_ISO_BIG_SYNC_CREATE);
	body[4] = 4;
	body[5] = 1;
	ipc_put_le16(body + 8, 0x0044);
	ipc_put_le16(body + 10, 100);
	body[12] = 1;
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body,
	    IPC_ISO_BIG_SYNC_REQ_SIZE));
	memset(body, 0, IPC_ISO_SIMPLE_REQ_SIZE);
	ipc_put_le16(body, IPC_ISO_BIG_SYNC_TERMINATE);
	body[4] = 4;
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body,
	    IPC_ISO_SIMPLE_REQ_SIZE));

	/* CONNECT_ACQUIRE reaches the successful fd handout path. */
	memset(body, 0, IPC_ISO_CONNECT_ACQUIRE_REQ_SIZE);
	ipc_put_le16(body, IPC_ISO_CONNECT_ACQUIRE);
	ipc_put_le16(body + 12, 0x0040);
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body,
	    IPC_ISO_CONNECT_ACQUIRE_REQ_SIZE));
	body[4] = 1;                 /* static-random peer address */
	ATF_CHECK_EQ(IPC_ERR_NONE, typed_iso_status(&client, body,
	    IPC_ISO_CONNECT_ACQUIRE_REQ_SIZE));
	ATF_CHECK_EQ(5, fd_handouts);
}

ATF_TC_WITHOUT_HEAD(typed_iso_acquire_tx_full_no_handout);
ATF_TC_BODY(typed_iso_acquire_tx_full_no_handout, tc)
{
	struct blued_ctl_client client;
	uint8_t body[IPC_ISO_SIMPLE_REQ_SIZE] = { 0 };
	uint16_t h;

	env_init();
	memset(&client, 0, sizeof(client));
	client.fd = 9;
	client.peer_known = true;
	client.peer_uid = 0;
	client.wants_fdpass = true;
	client.active_request_id = 0x13572468;
	test_adp.active = true;

	h = make_cig();
	ATF_REQUIRE_EQ(0, blued_iso_cis_create(&test_adp, &test_conn.dst,
	    BDADDR_LE_PUBLIC, 0, 1, -1, false));
	iso_on_cis_established(&test_adp, h, 0);
	ATF_REQUIRE_EQ(ISO_ST_PATHS_UP, blued_iso_stream_state(&test_adp, h));
	ncall = 0;
	fd_handouts = 0;
	ctl_tx_room = false;

	ipc_put_le16(body, IPC_ISO_ACQUIRE);
	ipc_put_le16(body + 4, h);
	ATF_CHECK_EQ(IPC_ERR_IO, typed_iso_status(&client, body, sizeof(body)));
	ATF_CHECK_EQ(0, fd_handouts);
	ATF_CHECK_EQ(0, count_of(C_ISO_CONNECT));
	ATF_CHECK_EQ(ISO_ST_PATHS_UP, blued_iso_stream_state(&test_adp, h));
}

ATF_TC_WITHOUT_HEAD(typed_iso_operand_mutation_matrix);
ATF_TC_BODY(typed_iso_operand_mutation_matrix, tc)
{
	static const struct {
		uint16_t opcode;
		size_t len;
	} ops[] = {
		{ IPC_ISO_CIG_CREATE, IPC_ISO_CIG_REQ_HDR_SIZE +
		    IPC_ISO_CIS_PARAM_SIZE },
		{ IPC_ISO_CIS_CREATE, IPC_ISO_CIS_CREATE_REQ_SIZE },
		{ IPC_ISO_CIS_ACCEPT, IPC_ISO_SIMPLE_REQ_SIZE },
		{ IPC_ISO_CIS_REJECT, IPC_ISO_SIMPLE_REQ_SIZE },
		{ IPC_ISO_CIS_TEARDOWN, IPC_ISO_SIMPLE_REQ_SIZE },
		{ IPC_ISO_CIG_REMOVE, IPC_ISO_SIMPLE_REQ_SIZE },
		{ IPC_ISO_BIG_CREATE, IPC_ISO_BIG_REQ_SIZE },
		{ IPC_ISO_BIG_TERMINATE, IPC_ISO_SIMPLE_REQ_SIZE },
		{ IPC_ISO_BIG_SYNC_CREATE, IPC_ISO_BIG_SYNC_REQ_SIZE },
		{ IPC_ISO_BIG_SYNC_TERMINATE, IPC_ISO_SIMPLE_REQ_SIZE },
		{ IPC_ISO_CONNECT_ACQUIRE, IPC_ISO_CONNECT_ACQUIRE_REQ_SIZE },
	};
	uint8_t body[64];
	size_t i, byte;

	/* Each request stays well-sized while only one semantic operand changes. */
	for (i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
		for (byte = 2; byte < ops[i].len; byte++) {
			struct blued_ctl_client client;

			env_init();
			memset(&client, 0, sizeof(client));
			client.fd = 9;
			client.peer_known = true;
			client.peer_uid = 0;
			client.active_request_id = 0x31415926;
			test_adp.active = true;
			memset(body, 0, sizeof(body));
			ipc_put_le16(body, ops[i].opcode);
			body[byte] = 0xff;
			(void)typed_iso_status(&client, body, ops[i].len);
		}
	}
}

/* Exercise acquire parsing after the fd-passing policy gate, rather than
 * merely rejecting every malformed request before its ISO operands are read. */
ATF_TC_WITHOUT_HEAD(typed_iso_acquire_parser_matrix);
ATF_TC_BODY(typed_iso_acquire_parser_matrix, tc)
{
	struct blued_ctl_client client;
	uint8_t body[IPC_ISO_CONNECT_ACQUIRE_REQ_SIZE] = { 0 };

	env_init();
	memset(&client, 0, sizeof(client));
	client.fd = 9;
	client.peer_known = true;
	client.peer_uid = 0;
	client.wants_fdpass = true;
	client.active_request_id = 0x27182818;
	test_adp.active = true;

	/* Validly shaped acquire with no established stream is Not Found. */
	ipc_put_le16(body, IPC_ISO_ACQUIRE);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, typed_iso_status(&client, body,
	    IPC_ISO_SIMPLE_REQ_SIZE));
	/* Both stream-acquire verbs reject a truncated simple request. */
	ATF_CHECK_EQ(IPC_ERR_PROTO, typed_iso_status(&client, body, 4));
	ipc_put_le16(body, IPC_ISO_BIS_ACQUIRE);
	ATF_CHECK_EQ(IPC_ERR_PROTO, typed_iso_status(&client, body, 4));

	/* CONNECT_ACQUIRE has independent type and reserved-field validation. */
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_ISO_CONNECT_ACQUIRE);
	body[4] = 2;
	ATF_CHECK_EQ(IPC_ERR_PROTO, typed_iso_status(&client, body,
	    IPC_ISO_CONNECT_ACQUIRE_REQ_SIZE));
	body[4] = 0;
	body[11] = 1;
	ATF_CHECK_EQ(IPC_ERR_PROTO, typed_iso_status(&client, body,
	    IPC_ISO_CONNECT_ACQUIRE_REQ_SIZE));
	body[11] = 0;
	ipc_put_le16(body + 14, 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, typed_iso_status(&client, body,
	    IPC_ISO_CONNECT_ACQUIRE_REQ_SIZE));

	/* An opcode outside the ISO domain's defined range is explicit Unknown. */
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, 0xffff);
	ATF_CHECK_EQ(IPC_ERR_UNKNOWN_CMD, typed_iso_status(&client, body, 4));
}

/* The CIG request has a fixed header plus a per-CIS tail.  Check each
 * independently specified reserved/count operand before handing valid input
 * to the controller, and surface a controller command failure as IPC I/O. */
ATF_TC_WITHOUT_HEAD(typed_iso_cig_parser_matrix);
ATF_TC_BODY(typed_iso_cig_parser_matrix, tc)
{
	struct blued_ctl_client client;
	uint8_t body[IPC_ISO_CIG_REQ_HDR_SIZE + IPC_ISO_CIS_PARAM_SIZE];
	uint8_t *cis;
	size_t len = sizeof(body);

	env_init();
	memset(&client, 0, sizeof(client));
	client.fd = 9;
	client.peer_known = true;
	client.peer_uid = 0;
	client.active_request_id = 0x31415927;
	test_adp.active = true;

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_ISO_CIG_CREATE);
	body[4] = 6;
	body[5] = 1;
	ipc_put_le16(body + 10, 5);
	ipc_put_le16(body + 12, 5);
	ipc_put_le32(body + 14, 0x0000ff);
	ipc_put_le32(body + 18, 0x0000ff);
	cis = body + IPC_ISO_CIG_REQ_HDR_SIZE;
	cis[0] = 1;
	cis[1] = cis[2] = 1;
	ipc_put_le16(cis + 6, 120);
	ipc_put_le16(cis + 8, 120);

	body[5] = 0;
	ATF_CHECK_EQ(IPC_ERR_PROTO, typed_iso_status(&client, body, len));
	body[5] = 1;
	body[9] = 1;
	ATF_CHECK_EQ(IPC_ERR_PROTO, typed_iso_status(&client, body, len));
	body[9] = 0;
	ipc_put_le16(body + 22, 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, typed_iso_status(&client, body, len));
	ipc_put_le16(body + 22, 0);
	cis[5] = 1;
	ATF_CHECK_EQ(IPC_ERR_INVAL, typed_iso_status(&client, body, len));
	cis[5] = 0;
	test_adp.le_features &= ~LE_FEAT_CIS_CENTRAL;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, typed_iso_status(&client, body, len));
	test_adp.le_features |= LE_FEAT_CIS_CENTRAL;

	fail_next = 1;
	ATF_CHECK_EQ(IPC_ERR_IO, typed_iso_status(&client, body, len));
}

ATF_TC_WITHOUT_HEAD(typed_iso_spec_range_rejections);
ATF_TC_BODY(typed_iso_spec_range_rejections, tc)
{
	struct blued_ctl_client client;
	uint8_t body[IPC_ISO_BIG_REQ_SIZE];
	uint8_t *cis;
	size_t len;

	env_init();
	memset(&client, 0, sizeof(client));
	client.fd = 9;
	client.peer_known = true;
	client.peer_uid = 0;
	client.active_request_id = 0x31415928;
	test_adp.active = true;

	len = IPC_ISO_CIG_REQ_HDR_SIZE + IPC_ISO_CIS_PARAM_SIZE;
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_ISO_CIG_CREATE);
	body[4] = 1;
	body[5] = 1;
	body[6] = 0;
	body[7] = 0;
	body[8] = 0;
	ipc_put_le16(body + 10, 5);
	ipc_put_le16(body + 12, 5);
	ipc_put_le32(body + 14, 0x0000ff);
	ipc_put_le32(body + 18, 0x0000ff);
	cis = body + IPC_ISO_CIG_REQ_HDR_SIZE;
	cis[0] = 1;
	cis[1] = 1;
	cis[2] = 1;
	ipc_put_le16(cis + 6, 120);
	ipc_put_le16(cis + 8, 120);
	body[4] = 0xf0;
	ATF_CHECK_EQ(IPC_ERR_INVAL, typed_iso_status(&client, body, len));
	body[4] = 1;
	ipc_put_le32(body + 14, 0x0000fe);
	ATF_CHECK_EQ(IPC_ERR_INVAL, typed_iso_status(&client, body, len));
	ipc_put_le32(body + 14, 0x0000ff);
	body[7] = 2;
	ATF_CHECK_EQ(IPC_ERR_INVAL, typed_iso_status(&client, body, len));
	body[7] = 0;
	cis[1] = 0;
	ATF_CHECK_EQ(IPC_ERR_INVAL, typed_iso_status(&client, body, len));

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_ISO_BIG_CREATE);
	body[4] = 1;
	body[5] = 1;
	body[6] = 1;
	body[8] = 1;
	ipc_put_le32(body + 14, 0x0000ff);
	ipc_put_le16(body + 18, 120);
	ipc_put_le16(body + 20, 5);
	body[4] = 0xf0;
	ATF_CHECK_EQ(IPC_ERR_INVAL, typed_iso_status(&client, body,
	    IPC_ISO_BIG_REQ_SIZE));
	body[4] = 1;
	body[6] = 9;
	ATF_CHECK_EQ(IPC_ERR_INVAL, typed_iso_status(&client, body,
	    IPC_ISO_BIG_REQ_SIZE));
	body[6] = 1;
	body[7] = 0x1f;
	ATF_CHECK_EQ(IPC_ERR_INVAL, typed_iso_status(&client, body,
	    IPC_ISO_BIG_REQ_SIZE));
	body[7] = 0;
	body[9] = 2;
	ATF_CHECK_EQ(IPC_ERR_INVAL, typed_iso_status(&client, body,
	    IPC_ISO_BIG_REQ_SIZE));

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_ISO_BIG_SYNC_CREATE);
	body[4] = 1;
	body[5] = 2;
	body[6] = 0;
	body[7] = 0;
	ipc_put_le16(body + 8, 0x0044);
	ipc_put_le16(body + 10, 10);
	body[12] = 1;
	body[13] = 2;
	body[5] = 9;
	ATF_CHECK_EQ(IPC_ERR_PROTO, typed_iso_status(&client, body,
	    IPC_ISO_BIG_SYNC_REQ_SIZE));
	body[5] = 2;
	ipc_put_le16(body + 8, 0x0f00);
	ATF_CHECK_EQ(IPC_ERR_INVAL, typed_iso_status(&client, body,
	    IPC_ISO_BIG_SYNC_REQ_SIZE));
	ipc_put_le16(body + 8, 0x0044);
	body[13] = 1;
	ATF_CHECK_EQ(IPC_ERR_INVAL, typed_iso_status(&client, body,
	    IPC_ISO_BIG_SYNC_REQ_SIZE));

	ATF_CHECK_EQ(0, blued_iso_stream_count());
}

/*
 * finding 57: CIG CIS RTN is a full octet in LE Set CIG Parameters; values
 * 0x10-0x1e are spec-legal (matching the BIG path) and must not be rejected
 * with IPC_ERR_INVAL.  0x1f (> 0x1e) is out of range and still rejected.
 */
ATF_TC_WITHOUT_HEAD(typed_iso_cig_rtn_range);
ATF_TC_BODY(typed_iso_cig_rtn_range, tc)
{
	struct blued_ctl_client client;
	uint8_t body[64], *cis;
	size_t len;

	env_init();
	memset(&client, 0, sizeof(client));
	client.fd = 9;
	client.peer_known = true;
	client.peer_uid = 0;
	client.active_request_id = 0x1;
	test_adp.active = true;

	len = IPC_ISO_CIG_REQ_HDR_SIZE + IPC_ISO_CIS_PARAM_SIZE;
	memset(body, 0, len);
	ipc_put_le16(body, IPC_ISO_CIG_CREATE);
	body[4] = 1;			/* CIG id */
	body[5] = 1;			/* CIS count */
	ipc_put_le16(body + 10, 5);	/* max transport latency c->p */
	ipc_put_le16(body + 12, 5);	/* max transport latency p->c */
	ipc_put_le32(body + 14, 10000);	/* SDU interval c->p */
	ipc_put_le32(body + 18, 10000);	/* SDU interval p->c */
	cis = body + IPC_ISO_CIG_REQ_HDR_SIZE;
	cis[0] = 2;			/* CIS id */
	cis[1] = 1;			/* PHY c->p */
	cis[2] = 1;			/* PHY p->c */
	cis[3] = 0x14;			/* RTN c->p = 20 (legal, <= 0x1e) */
	cis[4] = 0x14;			/* RTN p->c = 20 (legal, <= 0x1e) */
	ipc_put_le16(cis + 6, 120);
	ipc_put_le16(cis + 8, 120);
	/* Legal RTN must pass validation (no longer IPC_ERR_INVAL). */
	ATF_CHECK(typed_iso_status(&client, body, len) != IPC_ERR_INVAL);

	/* RTN 0x1f is out of range and rejected at validation. */
	cis[3] = 0x1f;
	ATF_CHECK_EQ(IPC_ERR_INVAL, typed_iso_status(&client, body, len));
	cis[3] = 0x14;
	cis[4] = 0x1f;
	ATF_CHECK_EQ(IPC_ERR_INVAL, typed_iso_status(&client, body, len));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, typed_iso_cig_rtn_range);
	ATF_TP_ADD_TC(tp, cis_central_full_lifecycle);
	ATF_TP_ADD_TC(tp, cis_central_push_on_establish);
	ATF_TP_ADD_TC(tp, cis_push_handout_failure_is_retryable);
	ATF_TP_ADD_TC(tp, cis_partial_setup_failure);
	ATF_TP_ADD_TC(tp, cis_establish_failure_emits_event);
	ATF_TP_ADD_TC(tp, cis_datapath_failure_emits_event);
	ATF_TP_ADD_TC(tp, cis_failure_keeps_cig_for_configured_sibling);
	ATF_TP_ADD_TC(tp, cis_create_command_error);
	ATF_TP_ADD_TC(tp, cis_peer_disconnect);
	ATF_TP_ADD_TC(tp, cis_teardown_no_spurious_lost);
	ATF_TP_ADD_TC(tp, cig_removed_only_after_last_cis);
	ATF_TP_ADD_TC(tp, cis_peripheral_accept);
	ATF_TP_ADD_TC(tp, cis_peripheral_reject);
	ATF_TP_ADD_TC(tp, bis_source_lifecycle);
	ATF_TP_ADD_TC(tp, bis_source_establish_failure);
	ATF_TP_ADD_TC(tp, bis_sink_lifecycle);
	ATF_TP_ADD_TC(tp, bis_sink_terminate);
	ATF_TP_ADD_TC(tp, sweep_frees_everything);
	ATF_TP_ADD_TC(tp, cig_remove_and_sweep_preserve_foreign_adapter);
	ATF_TP_ADD_TC(tp, adapter_local_handles_do_not_collide);
	ATF_TP_ADD_TC(tp, command_failure_and_count_matrix);
	ATF_TP_ADD_TC(tp, teardown_command_failure_is_retryable);
	ATF_TP_ADD_TC(tp, defensive_state_completion);
	ATF_TP_ADD_TC(tp, remaining_registry_and_fault_paths);
	ATF_TP_ADD_TC(tp, registry_identity_and_role_collision_matrix);
	ATF_TP_ADD_TC(tp, typed_iso_opcode_and_guard_sweep);
	ATF_TP_ADD_TC(tp, async_completion_failure_matrix);
	ATF_TP_ADD_TC(tp, typed_iso_valid_operation_matrix);
	ATF_TP_ADD_TC(tp, typed_iso_acquire_tx_full_no_handout);
	ATF_TP_ADD_TC(tp, typed_iso_operand_mutation_matrix);
	ATF_TP_ADD_TC(tp, typed_iso_acquire_parser_matrix);
	ATF_TP_ADD_TC(tp, typed_iso_cig_parser_matrix);
	ATF_TP_ADD_TC(tp, typed_iso_spec_range_rejections);
	return (atf_no_error());
}
