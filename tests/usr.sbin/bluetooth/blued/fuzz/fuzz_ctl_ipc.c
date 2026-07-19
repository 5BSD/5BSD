/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the blued framed control protocol
 * (ctl.c / ctl_conn.c / ctl_gatt.c).
 *
 * The control socket parses untrusted local frames.  This harness drives arbitrary
 * bytes through blued_ctl_dispatch() — the real per-client entry point —
 * over a socketpair standing in for an accepted control connection.  It
 * exercises frame reassembly, envelope validation and typed payload decoders.
 * ASan/UBSan catch any out-of-bounds access or UB.
 *
 * blued_ctl_dispatch() needs the daemon global state (blued_g) and a
 * modest stub set to satisfy the ctl/conn/att/gatt object graph; those
 * are the same stubs ctl_test.c uses.  The daemon context is initialized
 * once with no adapters and no connections, so every operation resolves
 * quickly without blocking on real BLE I/O.
 *
 * Reference: usr.sbin/bluetooth/blued/ctl.c.
 * Link set: ctl.c ctl_conn.c ctl_gatt.c conn.c att.c att_server.c
 *   att_server_dispatch.c att_server_notify.c att_server_hash.c gatt.c
 *   config.c  (+ -lbluetooth -lcrypto -lpthread).
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "att.h"
#include "att_server.h"
#include "blued.h"
#include "ble_util.h"
#include "conn.h"
#include "gatt.h"
#include "ctl.h"
#include "smp.h"

#define TEST_LINKS_CTL
#include "test_common.h"

/* ================================================================
 * Daemon globals and stubs (identical set to ctl_test.c)
 * ================================================================ */

struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;
const int _blued_kq_acquire_tag;
const int _blued_kq_setup_pipe_tag;

#define CTL_FUZZ_DB_MAX	64
#define CTL_FUZZ_VAL_SZ	1024
static struct att_attr	fuzz_attrs[CTL_FUZZ_DB_MAX];
static uint8_t		fuzz_vbuf[CTL_FUZZ_VAL_SZ];
struct att_db		periph_gatt_db;

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

/*
 * ISO/central/resolving-list seams reached only by uncalled ctl handler
 * branches (no adapter or connection exists in the fuzz context).  Stub them
 * so no real BLE I/O is attempted; signatures track ctl_test.c.
 */
int
ble_iso_connect(const uint8_t *src __unused, const uint8_t *addr __unused,
    uint8_t addr_type __unused, uint16_t cis_handle __unused,
    uint16_t mtu __unused)
{

	return (-1);
}

int
blued_central_start_pairing(struct hogp_device *dev __unused,
    struct blued_conn *conn __unused)
{

	return (-1);
}

void
blued_reslist_sync_remove(int hci_fd __unused, const uint8_t addr[6] __unused,
    uint8_t addr_type __unused)
{
}

/* ================================================================
 * One-time daemon context init; per-input GATT DB reset
 * ================================================================ */

static int
set_nonblock(int fd)
{
	int fl = fcntl(fd, F_GETFL, 0);

	if (fl < 0)
		return (-1);
	return (fcntl(fd, F_SETFL, fl | O_NONBLOCK));
}

static void
ctx_init_once(void)
{
	static bool done;

	if (done)
		return;
	done = true;

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

int
LLVMFuzzerInitialize(int *argc __unused, char ***argv __unused)
{

	ctx_init_once();
	return (0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct blued_ctl_client *client;
	int sp[2];
	size_t off = 0;
	int guard = 0;
	char sink[512];

	ctx_init_once();

	/* Fresh, empty GATT database each input so mutating commands
	 * (ADD_SERVICE/ADD_CHAR/SET_VALUE/REMOVE_SERVICE) stay bounded and
	 * deterministic across runs. */
	attdb_init(&periph_gatt_db, fuzz_attrs, CTL_FUZZ_DB_MAX,
	    fuzz_vbuf, CTL_FUZZ_VAL_SZ);

	if (size > 4096)
		size = 4096;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0)
		return (0);
	(void)set_nonblock(sp[0]);
	(void)set_nonblock(sp[1]);

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		close(sp[0]);
		close(sp[1]);
		return (0);
	}
	client->fd = sp[0];

	/*
	 * Push the fuzz bytes to the peer end and let the dispatcher consume
	 * them.  Drain the response side when the send buffer backs up so a
	 * payload larger than the socket buffer cannot stall us.
	 */
	while (off < size && guard++ < 200000) {
		ssize_t w = send(sp[1], data + off, size - off, MSG_DONTWAIT);

		if (w > 0)
			off += (size_t)w;
		(void)blued_ctl_dispatch(client);
		if (w <= 0)
			(void)recv(sp[1], sink, sizeof(sink), MSG_DONTWAIT);
	}
	/* Final drain of any buffered trailing frame. */
	(void)blued_ctl_dispatch(client);

	free(client);
	close(sp[0]);
	close(sp[1]);
	return (0);
}
