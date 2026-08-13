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
#include "blued_devmgr.h"
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

int ptap_ctl_internal_completion(void);
int ptap_ctl_cleanup_bound(void);

/* ================================================================
 * Stubs for external symbols referenced by ctl.c and conn.c
 * ================================================================ */

#define TEST_LINKS_CTL
/*
 * Provide capturing implementations of the advertising/connection parameter
 * HCI seam so the SET_ADV_PARAMS / CONNPARAMS_UPDATE / SET_PHY / SET_DATA_LEN
 * operation tests can assert the parameters decoded from typed payloads and
 * the resulting structured status.
 */
#define TEST_CUSTOM_ADVCONN_HCI
/*
 * Provide capturing implementations of the adapter-setting + parameterised-scan
 * seam (POWER / DISCOVERABLE / PAIRABLE / SET_NAME and filtered SCAN) so the
 * operation tests can assert the mapped settings/parameters and filtering.
 */
#define TEST_CUSTOM_ADAPTER_SCAN
/*
 * Provide capturing implementations of the mesh-bearer HCI seam (broker step
 * C) so the MESH_ADV_SEND test can assert the emitted advertising AD bytes and
 * the subscribe/unsubscribe tests can assert the always-on-scanner toggles
 * in addition to the structured operation status.
 */
#define TEST_CUSTOM_MESH_HCI
/*
 * Supply capturing implementations of the PC4 bond import/export seam
 * (smp_bond_*_record / smp_bond_db_import / blued_reslist_sync_add) below,
 * rather than the default no-op stubs in test_common.h, so the BOND_EXPORT /
 * BOND_IMPORT operation tests can drive and observe the wiring.
 */
#define TEST_CUSTOM_BOND_MIGRATE
#define TEST_CUSTOM_CTL_PRIVACY_OOB
#define TEST_CUSTOM_PRIVACY
#define TEST_CUSTOM_EXT_ADV_REGISTRY
#define TEST_CUSTOM_PRIMARY_ADV_CACHE
#define TEST_CUSTOM_BLE_ECBFC_CONNECT
#include "test_common.h"

struct blued_ctx blued_g;
const int _blued_kq_ctl_tag;
const int _blued_kq_acquire_tag;
const int _blued_kq_setup_pipe_tag;
uint8_t blued_local_irk[16];
bool blued_has_local_irk;

static struct {
	int calls;
	int fd[BLUED_MAX_ADAPTERS * 3];
	bool on[BLUED_MAX_ADAPTERS * 3];
	int fail_fd;
	int l2cap_calls;
	uint8_t l2cap_type;
} privacy_cap;

int
blued_privacy_set(int hci_fd, bool on)
{
	int i = privacy_cap.calls++;

	if ((size_t)i < nitems(privacy_cap.fd)) {
		privacy_cap.fd[i] = hci_fd;
		privacy_cap.on[i] = on;
	}
	return (hci_fd == privacy_cap.fail_fd ? -1 : 0);
}

int
blued_adapter_set_privacy(struct blued_adapter *adp, bool on)
{

	return (blued_privacy_set(adp->hci_fd, on));
}

int
blued_ext_adv_set_track(struct blued_adapter *adp, uint8_t handle,
    uint16_t props, uint32_t imin, uint32_t imax, uint8_t own,
    uint8_t filter, uint8_t pphy, uint8_t sphy, uint8_t channels,
    int8_t txpower, uint8_t peer_type, const uint8_t *peer)
{
	struct blued_ext_adv_set *set = NULL;

	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
		if (!adp->ext_adv_sets[i].used) {
			set = &adp->ext_adv_sets[i];
			break;
		}
	if (set == NULL)
		return (-1);
	memset(set, 0, sizeof(*set));
	set->used = set->configured = true;
	set->handle = handle;
	set->event_props = props;
	set->interval_min = imin;
	set->interval_max = imax;
	set->own_addr_type = own;
	set->filter_policy = filter;
	set->primary_phy = pphy;
	set->secondary_phy = sphy;
	set->channel_map = channels;
	set->tx_power = txpower;
	set->peer_addr_type = peer_type;
	if (peer != NULL)
		memcpy(set->peer_addr, peer, sizeof(set->peer_addr));
	return (0);
}

bool
blued_ext_adv_set_used(const struct blued_adapter *adp, uint8_t handle)
{

	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
		if (adp->ext_adv_sets[i].used &&
		    adp->ext_adv_sets[i].handle == handle)
			return (true);
	return (false);
}

void
blued_ext_adv_set_enabled(struct blued_adapter *adp, uint8_t handle, bool on)
{

	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
		if (adp->ext_adv_sets[i].used &&
		    adp->ext_adv_sets[i].handle == handle)
			adp->ext_adv_sets[i].enabled = on;
}

void
blued_ext_adv_set_untrack(struct blued_adapter *adp, uint8_t handle)
{

	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
		if (adp->ext_adv_sets[i].used &&
		    adp->ext_adv_sets[i].handle == handle)
			memset(&adp->ext_adv_sets[i], 0,
			    sizeof(adp->ext_adv_sets[i]));
}

void
hci_l2cap_set_own_address_type(uint8_t type)
{

	privacy_cap.l2cap_calls++;
	privacy_cap.l2cap_type = type;
}

int
hci_le_set_rpa_timeout(int hci_fd __unused, uint16_t timeout_sec __unused)
{

	return (test_hci_rpa_timeout_rc);
}

extern int ctl_test_disconnect_calls;
int ctl_test_disconnect_calls;

/* Captured parameters from the advertising/connection HCI seam. */
static struct {
	int			adv_calls;
	struct hci_adv_config	adv_cfg;
	int			connupd_calls, connupd_rc;
	uint16_t		connupd_handle, connupd_min, connupd_max;
	uint16_t		connupd_latency, connupd_timeout;
	int			setphy_calls;
	uint16_t		setphy_handle;
	uint8_t			setphy_all, setphy_tx, setphy_rx;
	int			setdlen_calls;
	uint16_t		setdlen_handle, setdlen_octets, setdlen_time;
	int			setphy_rc, setdlen_rc;
} advconn_cap;

/* Captured parameters and failures for the path-loss control seam. */
static struct {
	int	params_calls, enable_calls;
	int	params_rc, enable_rc;
	uint16_t handle, min_time;
	uint8_t	high, high_hyst, low, low_hyst, enable;
} pathloss_cap;

/*
 * Captured state for the mesh-bearer HCI seam (broker step C).  mesh_adv_burst
 * records the last transmitted AD structure so a test can assert the exact
 * [len][adtype][pdu] bytes; mesh_scan tracks the always-on-scanner enable/
 * disable calls so the subscriber-refcount tests can assert the scanner stays
 * on while subscribed and stops on unsubscribe.  burst_rc lets a test force a
 * controller error to exercise the FIFO backlog / IPC_ERR_BUSY path.
 */
static struct {
	int		burst_calls;
	uint8_t		burst_ad[64];
	uint8_t		burst_adlen;
	int		burst_rc;
	int		scan_calls;
	int		scan_rc;
	int		scan_on_calls;
	int		scan_off_calls;
	bool		scan_last_on;
} mesh_cap;

int
hci_mesh_adv_burst(int hci_fd __unused, uint64_t le_features __unused,
    const uint8_t *ad, uint8_t adlen)
{

	mesh_cap.burst_calls++;
	if (mesh_cap.burst_rc != 0)
		return (mesh_cap.burst_rc);
	mesh_cap.burst_adlen = adlen;
	if (adlen > sizeof(mesh_cap.burst_ad))
		adlen = sizeof(mesh_cap.burst_ad);
	memcpy(mesh_cap.burst_ad, ad, adlen);
	return (advconn_cap.connupd_rc);
}

int
hci_le_mesh_scan_set(int hci_fd __unused, uint64_t le_features __unused,
    bool on)
{

	mesh_cap.scan_calls++;
	mesh_cap.scan_last_on = on;
	if (on)
		mesh_cap.scan_on_calls++;
	else
		mesh_cap.scan_off_calls++;
	return (mesh_cap.scan_rc);
}

int
hci_adv_configure(int hci_fd __unused, uint64_t le_features,
    struct hci_adv_config *cfg)
{

	advconn_cap.adv_calls++;
	advconn_cap.adv_cfg = *cfg;
	cfg->used_extended = (le_features & LE_FEAT_EXT_ADVERTISING) != 0 &&
	    cfg->mode != HCI_ADV_MODE_LEGACY;
	return (0);
}

static int periodic_hci_fd;
static int periodic_hci_rc;
static int periodic_con_handle_rc;
static uint16_t periodic_last_handle;

void blued_periodic_sync_lost(struct blued_adapter *, uint16_t);
void
blued_periodic_sync_lost(struct blued_adapter *adp __unused,
    uint16_t handle __unused)
{
}

/* Periodic advertising control verbs are unit-tested through the same ctl
 * seam; HCI encoding itself is covered by hci_periodic_df_test. */
int
hci_le_set_periodic_adv_params(int fd, uint8_t handle __unused,
    uint16_t min __unused, uint16_t max __unused, uint16_t props __unused)
{
	periodic_hci_fd = fd;
	return (periodic_hci_rc);
}
int
hci_le_set_periodic_adv_data(int fd __unused, uint8_t handle __unused,
    const uint8_t *data __unused, uint8_t len __unused)
{
	return (periodic_hci_rc);
}
int
hci_le_set_periodic_adv_enable(int fd __unused, uint8_t enable __unused,
    uint8_t handle __unused)
{
	return (periodic_hci_rc);
}
int
hci_le_periodic_adv_create_sync(int fd __unused, uint8_t options __unused,
    uint8_t sid __unused, uint8_t type __unused, const uint8_t addr[6] __unused,
    uint16_t skip __unused, uint16_t timeout __unused)
{
	return (periodic_hci_rc);
}
int
hci_le_periodic_adv_create_sync_cancel(int fd __unused)
{
	return (periodic_hci_rc);
}
int
hci_le_periodic_adv_terminate_sync(int fd __unused, uint16_t handle __unused)
{
	return (periodic_hci_rc);
}
int
hci_le_add_dev_to_periodic_adv_list(int fd __unused, uint8_t type __unused,
    const uint8_t addr[6] __unused, uint8_t sid __unused)
{
	return (periodic_hci_rc);
}
int
hci_le_remove_dev_from_periodic_adv_list(int fd __unused, uint8_t type __unused,
    const uint8_t addr[6] __unused, uint8_t sid __unused)
{
	return (periodic_hci_rc);
}
int
hci_le_clear_periodic_adv_list(int fd __unused)
{
	return (periodic_hci_rc);
}
int
hci_le_read_periodic_adv_list_size(int fd __unused, uint8_t *size)
{
	*size = 8;
	return (periodic_hci_rc);
}

int
hci_le_set_periodic_adv_receive_enable(int fd __unused,
    uint16_t handle __unused, uint8_t enable __unused)
{
	return (periodic_hci_rc);
}

int
hci_get_con_handle(int fd __unused, const uint8_t addr[6] __unused,
    uint16_t *handle)
{
	*handle = 1;
	return (periodic_con_handle_rc);
}

int
hci_le_periodic_adv_sync_transfer(int fd __unused, uint16_t con_handle,
    uint16_t service_data __unused, uint16_t sync_handle __unused)
{
	periodic_last_handle = con_handle;
	return (periodic_hci_rc);
}
int
hci_le_periodic_adv_set_info_transfer(int fd __unused,
    uint16_t con_handle, uint16_t service_data __unused,
    uint8_t adv_handle __unused)
{
	periodic_last_handle = con_handle;
	return (periodic_hci_rc);
}
int
hci_le_set_past_params(int fd __unused, uint16_t con_handle,
    uint8_t mode __unused, uint16_t skip __unused, uint16_t timeout __unused,
    uint8_t cte __unused)
{
	periodic_last_handle = con_handle;
	return (periodic_hci_rc);
}
int
hci_le_set_default_past_params(int fd __unused, uint8_t mode __unused,
    uint16_t skip __unused, uint16_t timeout __unused, uint8_t cte __unused)
{
	return (periodic_hci_rc);
}
int
hci_le_set_path_loss_reporting_params(int fd __unused, uint16_t handle,
	uint8_t high, uint8_t high_hyst, uint8_t low, uint8_t low_hyst,
	uint16_t min)
{

	pathloss_cap.params_calls++;
	pathloss_cap.handle = handle;
	pathloss_cap.high = high;
	pathloss_cap.high_hyst = high_hyst;
	pathloss_cap.low = low;
	pathloss_cap.low_hyst = low_hyst;
	pathloss_cap.min_time = min;
	return (pathloss_cap.params_rc);
}
int
hci_le_set_path_loss_reporting_enable(int fd __unused, uint16_t handle,
	uint8_t enable)
{

	pathloss_cap.enable_calls++;
	pathloss_cap.handle = handle;
	pathloss_cap.enable = enable;
	return (pathloss_cap.enable_rc);
}

int
hci_le_connection_update(int hci_fd __unused, uint16_t handle,
    uint16_t interval_min, uint16_t interval_max, uint16_t latency,
    uint16_t timeout)
{

	advconn_cap.connupd_calls++;
	advconn_cap.connupd_handle = handle;
	advconn_cap.connupd_min = interval_min;
	advconn_cap.connupd_max = interval_max;
	advconn_cap.connupd_latency = latency;
	advconn_cap.connupd_timeout = timeout;
	return (advconn_cap.connupd_rc);
}

bool
l2cap_conn_param_use_hci_update(uint64_t local_features)
{

	return ((local_features & LE_FEAT_CONN_PARAM_REQ) != 0);
}

int
hci_le_set_phy(int hci_fd __unused, uint16_t con_handle, uint8_t all_phys,
    uint8_t tx_phys, uint8_t rx_phys, uint16_t phy_options __unused)
{

	advconn_cap.setphy_calls++;
	advconn_cap.setphy_handle = con_handle;
	advconn_cap.setphy_all = all_phys;
	advconn_cap.setphy_tx = tx_phys;
	advconn_cap.setphy_rx = rx_phys;
	return (advconn_cap.setphy_rc);
}

int
hci_le_set_data_length(int hci_fd __unused, uint16_t con_handle,
    uint16_t tx_octets, uint16_t tx_time)
{

	advconn_cap.setdlen_calls++;
	advconn_cap.setdlen_handle = con_handle;
	advconn_cap.setdlen_octets = tx_octets;
	advconn_cap.setdlen_time = tx_time;
	return (advconn_cap.setdlen_rc);
}

/*
 * Operator adapter-setting seam (POWER / DISCOVERABLE / PAIRABLE / SET_NAME).
 * blued_pairable and the blued_adapter_set_* / blued_set_device_name daemon
 * helpers live in blued.c, which the ctl link set does not include; provide the
 * global and capturing stubs so the operation tests can assert the decoded
 * settings and structured results.
 */
atomic_bool blued_pairable = true;

int	blued_adapter_set_power(struct blued_adapter *adp, bool on);
int	blued_adapter_set_discoverable(struct blued_adapter *adp, bool enable,
	    bool limited, unsigned int timeout_sec);
void	blued_primary_adv_cache(struct blued_adapter *, bool,
	    const uint8_t *, uint8_t);
int	blued_set_device_name(const char *name);

static struct {
	int		power_calls;
	bool		power_on;
	int		power_rc;
	int		disc_calls;
	bool		disc_enable, disc_limited;
	unsigned int	disc_timeout;
	int		disc_rc;
	int		name_calls;
	char		name_last[64];
	int		name_rc;
	int		scan_ex_calls;
	struct hci_scan_params scan_params;
	struct ble_scan_result scan_results[8];
	int		scan_nresults;
	int		scan_rc, ext_scan_rc;
} adap_cap;

static void
adap_cap_reset(void)
{

	memset(&adap_cap, 0, sizeof(adap_cap));
}

int
blued_adapter_set_power(struct blued_adapter *adp, bool on)
{

	adap_cap.power_calls++;
	adap_cap.power_on = on;
	if (adap_cap.power_rc == 0 && adp != NULL)
		adp->powered = on;
	return (adap_cap.power_rc);
}

int
blued_adapter_set_discoverable(struct blued_adapter *adp, bool enable,
    bool limited, unsigned int timeout_sec)
{

	adap_cap.disc_calls++;
	adap_cap.disc_enable = enable;
	adap_cap.disc_limited = limited;
	adap_cap.disc_timeout = timeout_sec;
	if (adap_cap.disc_rc == 0 && adp != NULL)
		adp->discoverable = enable;
	return (adap_cap.disc_rc);
}

void
blued_primary_adv_cache(struct blued_adapter *adp __unused,
    bool scan_rsp __unused, const uint8_t *data __unused, uint8_t len __unused)
{
}

int
blued_set_device_name(const char *name)
{

	adap_cap.name_calls++;
	strlcpy(adap_cap.name_last, name, sizeof(adap_cap.name_last));
	return (adap_cap.name_rc);
}

/*
 * Parameterised SCAN seam: capture the mapped hci_scan_params and return the
 * primed results so a filtered-SCAN test can assert both the emitted parameters
 * and the post-scan result filtering.
 */
int
hci_le_scan_ex(int hci_fd __unused, int duration_sec __unused,
    const struct hci_scan_params *params, struct ble_scan_result *results,
    int maxresults, int *nresults)
{
	int i, c;

	adap_cap.scan_ex_calls++;
	adap_cap.scan_params = *params;
	c = adap_cap.scan_nresults < maxresults ? adap_cap.scan_nresults :
	    maxresults;
	for (i = 0; i < c; i++)
		results[i] = adap_cap.scan_results[i];
	if (nresults != NULL)
		*nresults = c;
	return (adap_cap.scan_rc);
}

int
hci_le_ext_scan_ex(int hci_fd __unused, int duration_sec __unused,
    const struct hci_scan_params *params, struct ble_scan_result *results,
    int maxresults, int *nresults, uint8_t scanning_phys __unused)
{
	int rc;

	if (adap_cap.ext_scan_rc != 0)
		return (adap_cap.ext_scan_rc);
	rc = hci_le_scan_ex(hci_fd, duration_sec, params, results, maxresults,
	    nresults);
	return (rc);
}

/*
 * hci_scan.c helpers referenced by ctl_conn.c but not linked here.  The default
 * filler and the result-filter predicate are faithful to the real
 * implementations (whose byte/predicate correctness is covered by
 * ctl_adapter_scan_test); the filtered SCAN operation test uses the predicate.
 */
void
hci_scan_params_default(struct hci_scan_params *p)
{

	p->active = 1;
	p->interval = 160;
	p->window = 80;
	p->filter_policy = 0;
	p->filter_dup = 1;
}

bool
ble_scan_result_match(const struct ble_scan_result *sr,
    const struct ble_scan_filter *f)
{

	if (f == NULL)
		return (true);
	if (f->has_rssi && sr->rssi < f->rssi_min)
		return (false);
	if (f->has_name &&
	    (!sr->has_name || strstr(sr->name, f->name_sub) == NULL))
		return (false);
	if (f->has_uuid) {
		int i;

		for (i = 0; i < sr->num_svc_uuids; i++)
			if (sr->svc_uuids[i] == f->uuid16)
				return (true);
		return (false);
	}
	return (true);
}

/* Stubs for blued_event.c functions used by ctl_conn.c and ctl_gatt.c */
void
blued_conn_disconnect(struct blued_conn *conn __unused)
{
	ctl_test_disconnect_calls++;
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
static int ctl_test_hogp_fail_errno;

struct hogp_device *
blued_hogp_alloc(struct blued_adapter *adp __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused,
    bool reconnect __unused)
{

	if (ctl_test_hogp_fail_errno != 0) {
		errno = ctl_test_hogp_fail_errno;
		return (NULL);
	}
	/* Return non-NULL so CONNECT proceeds (calloc a dummy) */
	return (calloc(1, 256));
}

/* hci_util.c stubs */
static int ctl_test_smp_open_rc = -1;
static int ctl_test_smp_pair_rc = -1;
static int ctl_test_wait_encryption_rc = -1;

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

	return (ctl_test_wait_encryption_rc);
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

/*
 * Controllable CoC/ISO openers for the capability-broker acquire tests.
 * A test primes mock_broker_fds[] with real (socketpair) descriptors so the
 * broker handout path can be driven end-to-end without a controller; the
 * default (mock_broker_navail == 0) preserves the legacy "open failed"
 * behavior the ECBFC_CONNECT tests expect.
 */
static int	mock_broker_fds[5];
static int	mock_broker_navail;	/* number of primed fds; 0 => fail */

int
ble_ecbfc_connect(const uint8_t *local_addr __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused,
    uint16_t psm __unused, uint16_t mtu __unused,
    int count, int *fds)
{
	int i, n;

	if (mock_broker_navail <= 0 || fds == NULL)
		return (-1);
	n = (count < mock_broker_navail) ? count : mock_broker_navail;
	for (i = 0; i < n; i++)
		fds[i] = mock_broker_fds[i];
	return (n);
}

int
ble_iso_connect(const uint8_t *src __unused, const uint8_t *addr __unused,
    uint8_t addr_type __unused, uint16_t cis_handle __unused,
    uint16_t mtu __unused)
{

	if (mock_broker_navail <= 0)
		return (-1);
	return (mock_broker_fds[0]);
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
/*
 * Controllable bond lookup: defaults to NULL (device not bonded) so every
 * existing test keeps its behavior; a REKEY test primes ctl_test_found_bond to
 * model an already-bonded peer.
 */
static struct smp_bond *ctl_test_found_bond;

struct smp_bond *
smp_find_bond(struct smp_bond_db *db __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused)
{

	return (ctl_test_found_bond);
}

/*
 * Controllable re-pair stub for the REKEY operation.  ctl.c is not linked with
 * blued_central.c in this test, so the start-pairing helper is mocked: the
 * return code is primed per-test and the call is counted so a test can assert
 * REKEY actually initiated SMP on a bonded, connected central.
 */
static int	ctl_test_start_pairing_rc;
static int	ctl_test_start_pairing_calls;
static int	ctl_test_bond_save_rc;

int
blued_central_start_pairing(struct hogp_device *dev __unused,
    struct blued_conn *conn __unused)
{

	ctl_test_start_pairing_calls++;
	return (ctl_test_start_pairing_rc);
}

/*
 * Finding 33: REKEY/PAIR now dispatch pairing to a worker via
 * blued_central_start_pairing_async().  The stub drives the sync stub inline so
 * the existing REKEY/PAIR assertions (start_pairing_rc -> IPC_ERR_IO/NONE) keep
 * their meaning; the real daemon runs it on a detached thread.
 */
int
blued_central_start_pairing_async(struct blued_conn *conn)
{

	if (conn == NULL || conn->hogp == NULL)
		return (-1);
	return (blued_central_start_pairing(conn->hogp, conn));
}

int
smp_bond_db_save(struct smp_bond_db *db __unused)
{

	return (ctl_test_bond_save_rc);
}

/*
 * PC4 bond import/export seam.  ctl.c is not linked with smp_keys.c here, so the
 * record (de)serializer and the DB inserter are mocked and controllable: this
 * lets the dispatch/privilege/reslist wiring be asserted without real crypto or
 * a bond file.  The record-level serialization + validation is covered directly
 * against the real smp_keys.c in bond_migrate_test.
 */
static int	ctl_test_import_rc = 1;		/* 1 append, 0 replace, -1 full */
static bool	ctl_test_import_valid = true;	/* smp_bond_import_record ok */
static bool	ctl_test_import_has_irk;		/* imported bond carries IRK */
static int	ctl_test_reslist_add_calls;
static int	ctl_test_resolv_clear_rc;
static int	ctl_test_resolv_add_rc;
static int	ctl_test_resolv_remove_rc;
static int	ctl_test_set_privacy_mode_rc;	/* finding 122 */
static int	ctl_test_resolv_remove_calls;	/* finding 122: rollback counter */
static int	ctl_test_oob_generate_rc;

/* Finding 135: Filter Accept List handler mocks/stubs. */
static int	ctl_test_accept_add_rc;
static int	ctl_test_accept_add_calls;
static int	ctl_test_accept_remove_calls;
static int	ctl_test_acceptlist_record_calls;
static int	ctl_test_acceptlist_forget_calls;
static int	ctl_test_acceptlist_clear_calls;
static uint32_t	ctl_test_acceptlist_snapshot_count;
/* Finding 138: runtime resolving-list persistence stubs. */
static int	ctl_test_runtime_resolv_record_calls;
static int	ctl_test_runtime_resolv_forget_calls;
static int	ctl_test_runtime_resolv_clear_calls;

size_t
smp_bond_export_record(const struct smp_bond *bond __unused, uint8_t *out,
    size_t outsz)
{

	if (out == NULL || outsz < SMP_BOND_REC_LEN)
		return (0);
	memset(out, 0, SMP_BOND_REC_LEN);
	memcpy(out, SMP_BOND_REC_MAGIC, SMP_BOND_REC_MAGIC_LEN);
	return (SMP_BOND_REC_LEN);
}

int
smp_bond_import_record(const uint8_t *rec __unused, size_t len __unused,
    struct smp_bond *out)
{

	if (!ctl_test_import_valid)
		return (-1);
	memset(out, 0, sizeof(*out));
	out->addr_type = BDADDR_LE_PUBLIC;
	out->has_irk = ctl_test_import_has_irk;
	return (0);
}

int
smp_bond_db_import(struct smp_bond_db *db __unused,
    const struct smp_bond *bond __unused)
{

	return (ctl_test_import_rc);
}

void
blued_reslist_sync_add(int hci_fd __unused, const struct smp_bond *bond __unused)
{

	ctl_test_reslist_add_calls++;
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

	return (ctl_test_smp_open_rc);
}

void
smp_close(struct smp_conn *sc __unused)
{
}

int
smp_pair(struct smp_conn *sc __unused)
{

	return (ctl_test_smp_pair_rc);
}

/* smp_verify_signature provided by test_common.h */

int
hci_le_remove_device_from_filter_accept_list(int hci_fd __unused,
    uint8_t addr_type __unused, const uint8_t addr[6] __unused)
{

	ctl_test_accept_remove_calls++;
	return (0);
}

int
hci_le_add_device_to_filter_accept_list(int hci_fd __unused,
    uint8_t addr_type __unused, const uint8_t addr[6] __unused)
{

	ctl_test_accept_add_calls++;
	return (ctl_test_accept_add_rc);
}

/* Finding 135: blued.c accept-list shadow stubs. */
int
blued_acceptlist_record(const uint8_t addr[6] __unused,
    uint8_t addr_type __unused)
{

	ctl_test_acceptlist_record_calls++;
	return (1);
}

int
blued_acceptlist_forget(const uint8_t addr[6] __unused,
    uint8_t addr_type __unused)
{

	ctl_test_acceptlist_forget_calls++;
	return (1);
}

void
blued_acceptlist_clear_all(void)
{

	ctl_test_acceptlist_clear_calls++;
}

uint32_t
blued_acceptlist_snapshot(struct blued_persist_accept_entry *out, uint32_t max)
{
	uint32_t n = ctl_test_acceptlist_snapshot_count;

	if (n > max)
		n = max;
	if (out != NULL)
		memset(out, 0, n * sizeof(out[0]));
	return (n);
}

/* Finding 138: blued.c runtime resolving-list persistence stubs. */
void
blued_runtime_resolv_record(const uint8_t addr[6] __unused,
    uint8_t addr_type __unused, const uint8_t irk[16] __unused)
{

	ctl_test_runtime_resolv_record_calls++;
}

void
blued_runtime_resolv_forget(const uint8_t addr[6] __unused,
    uint8_t addr_type __unused)
{

	ctl_test_runtime_resolv_forget_calls++;
}

void
blued_runtime_resolv_clear(void)
{

	ctl_test_runtime_resolv_clear_calls++;
}

/* Finding 137: in-memory blued_persist gattsrv artifact for the DB replay. */
static struct blued_persist_gatt_srv_attr
    ctl_test_gattsrv[BLUED_PERSIST_MAX_GATTSRV_ATTRS];
static uint32_t	ctl_test_gattsrv_count;
static int	ctl_test_gattsrv_save_calls;

int
blued_persist_gattsrv_save(int dirfd __unused,
    const struct blued_persist_gatt_srv_attr *attrs, uint32_t nattrs)
{

	if (nattrs > BLUED_PERSIST_MAX_GATTSRV_ATTRS)
		nattrs = BLUED_PERSIST_MAX_GATTSRV_ATTRS;
	if (nattrs > 0)
		memcpy(ctl_test_gattsrv, attrs, nattrs * sizeof(attrs[0]));
	ctl_test_gattsrv_count = nattrs;
	ctl_test_gattsrv_save_calls++;
	return (0);
}

int
blued_persist_gattsrv_load(int dirfd __unused,
    struct blued_persist_gatt_srv_attr *attrs, uint32_t *nattrs)
{

	if (ctl_test_gattsrv_count == 0)
		return (-1);
	memcpy(attrs, ctl_test_gattsrv,
	    ctl_test_gattsrv_count * sizeof(attrs[0]));
	*nattrs = ctl_test_gattsrv_count;
	return (0);
}

void
blued_reslist_sync_remove(int hci_fd __unused, const uint8_t addr[6] __unused,
    uint8_t addr_type __unused)
{
}

int
blued_reslist_add(struct blued_reslist *rl, const uint8_t addr[6],
    uint8_t addr_type)
{
	int i;

	if (rl == NULL || addr == NULL)
		return (0);
	if (blued_reslist_contains(rl, addr, addr_type))
		return (0);
	if (rl->count >= BLUED_RESLIST_MAX)
		return (0);
	i = rl->count++;
	memcpy(rl->ent[i].addr, addr, 6);
	rl->ent[i].addr_type = addr_type;
	return (1);
}

int
blued_reslist_remove(struct blued_reslist *rl, const uint8_t addr[6],
    uint8_t addr_type)
{
	int i;

	if (rl == NULL || addr == NULL)
		return (0);
	for (i = 0; i < rl->count; i++) {
		if (rl->ent[i].addr_type == addr_type &&
		    memcmp(rl->ent[i].addr, addr, 6) == 0) {
			if (i != rl->count - 1)
				rl->ent[i] = rl->ent[rl->count - 1];
			rl->count--;
			return (1);
		}
	}
	return (0);
}

bool
blued_reslist_contains(const struct blued_reslist *rl, const uint8_t addr[6],
    uint8_t addr_type)
{
	int i;

	if (rl == NULL || addr == NULL)
		return (false);
	for (i = 0; i < rl->count; i++) {
		if (rl->ent[i].addr_type == addr_type &&
		    memcmp(rl->ent[i].addr, addr, 6) == 0)
			return (true);
	}
	return (false);
}

int
hci_le_set_addr_resolution_enable(int hci_fd __unused, uint8_t enable __unused)
{

	return (0);
}

int
hci_le_clear_resolving_list(int hci_fd __unused)
{

	if (ctl_test_resolv_clear_rc != 0)
		return (ctl_test_resolv_clear_rc);
	return (0);
}

int
hci_le_add_dev_resolving_list(int hci_fd __unused, uint8_t addr_type __unused,
    const uint8_t addr[6] __unused, const uint8_t peer_irk[16] __unused,
    const uint8_t local_irk[16] __unused)
{

	return (ctl_test_resolv_add_rc);
}

int
hci_le_remove_dev_resolving_list(int hci_fd __unused,
    uint8_t addr_type __unused, const uint8_t addr[6] __unused)
{

	ctl_test_resolv_remove_calls++;
	return (ctl_test_resolv_remove_rc);
}

int
hci_le_set_privacy_mode(int hci_fd __unused, uint8_t addr_type __unused,
    const uint8_t addr[6] __unused, uint8_t mode __unused)
{

	return (ctl_test_set_privacy_mode_rc);
}

int
smp_sc_oob_generate_local(uint8_t confirm[16], uint8_t random[16],
    uint8_t pkx_le[32])
{
	if (ctl_test_oob_generate_rc != 0)
		return (ctl_test_oob_generate_rc);

	memset(confirm, 0x11, 16);
	memset(random, 0x22, 16);
	memset(pkx_le, 0x33, 32);
	return (0);
}

void
smp_sc_oob_clear_local(void)
{
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
	blued_ctl_clients_lock_init(&blued_g.ctl_clients_lock);
	ctl_test_smp_open_rc = -1;
	ctl_test_smp_pair_rc = -1;
	ctl_test_wait_encryption_rc = -1;
	ctl_test_found_bond = NULL;
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
	client->peer_known = true;
	client->peer_uid = 0;
	return (client);
}

static void ipc_handshake(struct blued_ctl_client *, int, uint16_t,
    uint32_t, char *, size_t);
static void ipc_send_raw(int, uint16_t, uint16_t, const void *, size_t);
static uint32_t ipc_test_request_id;
static uint16_t dispatch_domain_request(struct blued_ctl_client *, int,
    uint16_t, const uint8_t *, size_t);
static void *ctl_att_discovery_responder(void *);

static void
build_ctl_test_db(void)
{
	attdb_init(&periph_gatt_db, ctl_test_attrs, CTL_TEST_DB_MAX,
	    ctl_test_vbuf, CTL_TEST_VAL_SZ);
	attdb_add_service(&periph_gatt_db, 0x1800);
	attdb_add_characteristic(&periph_gatt_db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, "Test", 4);
	attdb_add_service(&periph_gatt_db, 0xFFE0);
	attdb_add_characteristic(&periph_gatt_db, 0xFFE1,
	    GATT_PROP_READ | GATT_PROP_WRITE | GATT_PROP_NOTIFY,
	    ATT_PERM_READ | ATT_PERM_WRITE, "\xAA\xBB", 2);
	attdb_add_cccd(&periph_gatt_db);
}

ATF_TC_WITHOUT_HEAD(test_ctl_tx_queue_backpressure);
ATF_TC_BODY(test_ctl_tx_queue_backpressure, tc)
{
	struct blued_ctl_client client;
	uint8_t payload[8192], drain[16384];
	int sp[2], sndbuf, flags, fd;
	ssize_t n;

	test_init();
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	sndbuf = 1024;
	ATF_REQUIRE_EQ(0, setsockopt(sp[0], SOL_SOCKET, SO_SNDBUF,
	    &sndbuf, sizeof(sndbuf)));
	flags = fcntl(sp[0], F_GETFL);
	ATF_REQUIRE(flags >= 0);
	ATF_REQUIRE_EQ(0, fcntl(sp[0], F_SETFL, flags | O_NONBLOCK));
	flags = fcntl(sp[1], F_GETFL);
	ATF_REQUIRE(flags >= 0);
	ATF_REQUIRE_EQ(0, fcntl(sp[1], F_SETFL, flags | O_NONBLOCK));

	memset(&client, 0, sizeof(client));
	client.fd = sp[0];
	STAILQ_INIT(&client.txq);
	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);
	client.kq_registered = true;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, &client, entries);
	memset(payload, 0x5a, sizeof(payload));

	/* Fill the socket until a complete or partial frame remains queued. */
	for (int i = 0; i < 256 && client.tx_queued == 0; i++)
		ATF_REQUIRE_EQ(0, ctl_send_frame(&client, IPC_T_OP_EVENT, i,
		    payload, sizeof(payload)));
	ATF_REQUIRE(client.tx_queued > 0);
	ATF_CHECK(client.tx_write_enabled);
	ATF_CHECK_EQ(0, blued_ctl_flush(&client));
	/* A kqueue registration failure must leave the queue intact and avoid
	 * claiming that a write watch was installed.  The next explicit flush is
	 * still able to make progress, so this is a recoverable notification
	 * failure rather than a lost control frame. */
	{
		int saved_kq = blued_g.kq;

		blued_g.kq = -1;
		client.tx_write_enabled = false;
		ATF_CHECK_EQ(0, blued_ctl_flush(&client));
		ATF_CHECK(!client.tx_write_enabled);
		blued_g.kq = saved_kq;
	}

	/* Alternating peer drains and flushes eventually preserves all framing. */
	for (int i = 0; i < 2048 && client.tx_queued != 0; i++) {
		do {
			n = recv(sp[1], drain, sizeof(drain), 0);
		} while (n > 0);
		ATF_REQUIRE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
		ATF_REQUIRE_EQ(0, blued_ctl_flush(&client));
	}
	ATF_CHECK_EQ(0, client.tx_queued);
	ATF_CHECK(!client.tx_write_enabled);

	/* Descriptor handoff closes the daemon's duplicate after sendmsg. */
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	blued_ctl_send_fd(client.fd, fd);
	ATF_CHECK(fcntl(fd, F_GETFD) >= 0);
	close(fd);

	/* Client teardown owns and closes descriptors still queued in backpressure. */
	for (int i = 0; i < 256 && client.tx_queued == 0; i++)
		ATF_REQUIRE_EQ(0, ctl_send_frame(&client, IPC_T_OP_EVENT, i,
		    payload, sizeof(payload)));
	ATF_REQUIRE(client.tx_queued > 0);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	blued_ctl_send_fd(client.fd, fd);
	blued_ctl_client_fini(&client);
	ATF_CHECK(fcntl(fd, F_GETFD) >= 0);
	close(fd);
	ATF_CHECK_EQ(0, client.tx_queued);

	LIST_REMOVE(&client, entries);
	close(blued_g.kq);
	close(sp[0]);
	close(sp[1]);

	/* Invalid state and bounded-queue overflow fail closed. */
	memset(&client, 0, sizeof(client));
	client.fd = -1;
	STAILQ_INIT(&client.txq);
	ATF_CHECK_EQ(-1, ctl_send_frame(NULL, IPC_T_OP_EVENT, 0, NULL, 0));
	client.tx_error = true;
	ATF_CHECK_EQ(-1, ctl_send_frame(&client, IPC_T_OP_EVENT, 0, NULL, 0));
	client.tx_error = false;
	client.tx_queued = BLUED_CTL_TX_MAX;
	errno = 0;
	ATF_CHECK_EQ(-1, ctl_send_frame(&client, IPC_T_OP_EVENT, 0, NULL, 0));
	ATF_CHECK(client.tx_error);

	/* A closed peer exercises the permanent send failure path. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	memset(&client, 0, sizeof(client));
	client.fd = sp[0];
	STAILQ_INIT(&client.txq);
	close(sp[1]);
	ATF_CHECK_EQ(-1, ctl_send_frame(&client, IPC_T_OP_EVENT, 0, NULL, 0));
	ATF_CHECK(client.tx_error);
	blued_ctl_client_fini(&client);
	close(sp[0]);
}

/* ================================================================
 * Test: blued_ctl_respond sends formatted text to the client fd.
 *
 * Since blued_ctl_respond is static, we test it indirectly by
 * dispatching a STATUS command on an empty daemon context and
 * verifying the formatted response arrives on the peer socket.
 * ================================================================ */
/* ================================================================
 * Test: STATUS command returns adapter/connection counts
 * ================================================================ */
/* ================================================================
 * Test: ADAPTERS command lists adapter names
 * ================================================================ */
/* ================================================================
 * Test: unknown command returns ERROR
 * ================================================================ */
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
	struct blued_ctl_client *client;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(sizeof(int))];
	char byte;
	cap_rights_t rights;
	int sp[2], fd_pair[2], recv_fd, ret;

	test_init();

	/* sp is the client<->daemon channel for fd passing. */
	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);

	/* fd_pair: we'll send fd_pair[0] through the channel */
	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd_pair);
	ATF_REQUIRE(ret == 0);

	/* Send fd_pair[0] over sp[0] -> sp[1] */
	blued_ctl_send_fd(sp[0], fd_pair[0]);

	/* Receive the queued descriptor on the client side. */
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
	ATF_REQUIRE(cmsg != NULL);
	ATF_REQUIRE_EQ(cmsg->cmsg_level, SOL_SOCKET);
	ATF_REQUIRE_EQ(cmsg->cmsg_type, SCM_RIGHTS);
	memcpy(&recv_fd, CMSG_DATA(cmsg), sizeof(int));
	ATF_REQUIRE(recv_fd >= 0);

	ret = cap_rights_get(recv_fd, &rights);
	ATF_REQUIRE(ret == 0);
	ATF_CHECK(cap_rights_is_set(&rights, CAP_SEND));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_RECV));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_EVENT));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_SETSOCKOPT));
	close(recv_fd);

	/* ECBFC handouts retain only the extra right needed by
	 * ble_ecbfc_session_reconfigure(3). */
	ATF_REQUIRE_EQ(ctl_send_ecbfc_fd_to_client(client, fd_pair[0]), 0);
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(cbuf, 0, sizeof(cbuf));
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	ATF_REQUIRE(recvmsg(sp[1], &msg, 0) >= 1);
	cmsg = CMSG_FIRSTHDR(&msg);
	ATF_REQUIRE(cmsg != NULL);
	memcpy(&recv_fd, CMSG_DATA(cmsg), sizeof(recv_fd));
	ATF_REQUIRE_EQ(cap_rights_get(recv_fd, &rights), 0);
	ATF_CHECK(cap_rights_is_set(&rights, CAP_SEND));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_RECV));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_EVENT));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_SETSOCKOPT));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_CONNECT));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_BIND));
	close(recv_fd);

	close(fd_pair[0]);
	close(fd_pair[1]);
	close(sp[0]);
	close(sp[1]);
	LIST_REMOVE(client, entries);
	free(client);
}

/* BONDS command with empty bond DB */
/* BONDS command with populated bond DB */
/* PHY command with no connections */
/* ================================================================
 * Test: empty command (zero-length message after newline) — no crash
 * ================================================================ */
/* ================================================================
 * Test: an oversized frame (payload length exceeding IPC_MAX_PAYLOAD) is
 * handled gracefully — the daemon replies with an IPC_ERR_PROTO error frame
 * and resets its receive buffer, no crash.
 * ================================================================ */
/* ================================================================
 * Test: SCAN command returns a response (stubs return 0 results)
 * ================================================================ */
/* ================================================================
 * Test: multiple STATUS commands in sequence
 * ================================================================ */
/* ================================================================
 * Test: DISCONNECT with no connections — returns error
 * ================================================================ */
/* ================================================================
 * Test: UNBOND with non-existent address — returns error
 * (smp_find_bond stub always returns NULL)
 * ================================================================ */
/* ================================================================
 * Test: PHY with an active connection — returns PHY info
 * (hci_le_read_phy stub returns 1M/1M)
 * ================================================================ */
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

/* A second daemon must not unlink and replace a live control endpoint. */
ATF_TC_WITHOUT_HEAD(test_ctl_init_preserves_live_socket);
ATF_TC_BODY(test_ctl_init_preserves_live_socket, tc)
{
	struct stat before, after;
	char path[64];

	test_init();
	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);
	snprintf(path, sizeof(path), "/tmp/blued-live-%d.sock",
	    (int)getpid());
	ATF_REQUIRE_EQ(0, blued_ctl_init(path));
	ATF_REQUIRE_EQ(0, lstat(path, &before));

	errno = 0;
	ATF_CHECK_EQ(-1, blued_ctl_init(path));
	ATF_CHECK(errno == EADDRINUSE || errno == EAGAIN);
	ATF_REQUIRE_EQ(0, lstat(path, &after));
	ATF_CHECK_EQ(before.st_dev, after.st_dev);
	ATF_CHECK_EQ(before.st_ino, after.st_ino);

	blued_ctl_cleanup();
	close(blued_g.kq);
}

/* The asynchronous GATT pool executes ATT I/O and emits correlated replies. */
ATF_TC_WITHOUT_HEAD(test_ctl_gatt_worker_io);
ATF_TC_BODY(test_ctl_gatt_worker_io, tc)
{
	struct blued_adapter adp;
	struct blued_ctl_client *client;
	struct blued_conn *conn;
	struct att_conn att;
	bdaddr_t addr;
	char feat[128], path[64];
	uint8_t body[IPC_GATT_VALUE_REQ_SIZE + 4];
	uint8_t read_rsp[] = { ATT_OP_READ_RSP, 0x11, 0x22, 0x33 };
	uint8_t write_rsp[] = { ATT_OP_WRITE_RSP };
	uint16_t status;
	int sp[2], att_pair[2];
	pthread_t discovery_responder;

	test_init();
	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);
	snprintf(path, sizeof(path), "/tmp/blued-gatt-worker-%d.sock",
	    (int)getpid());
	ATF_REQUIRE_EQ(0, blued_ctl_init(path));

	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.powered = true;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &addr));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, att_pair));
	memset(&att, 0, sizeof(att));
	att.fd = att_pair[0];
	att.mtu = 185;
	att.buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(att.buf != NULL);
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->adapter = &adp;
	conn->dst = addr;
	conn->addr_type = BDADDR_LE_PUBLIC;
	conn->att = &att;
	conn->att_fd = att.fd;

	client = make_client(sp);
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS,
	    feat, sizeof(feat));

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_READ);
	body[4] = 0;	/* IPC public; conn stores BDADDR_LE_PUBLIC */
	memcpy(body + 5, &addr, sizeof(addr));
	ipc_put_le16(body + 12, 0x0025);
	ATF_REQUIRE_EQ((ssize_t)sizeof(read_rsp), send(att_pair[1], read_rsp,
	    sizeof(read_rsp), 0));
	status = dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_GATT,
	    body, IPC_GATT_REQ_SIZE);
	ATF_CHECK_EQ_MSG(IPC_ERR_NONE, status, "read status=%u", status);
	ATF_CHECK(!atomic_load(&conn->att_op_busy));

	ipc_put_le16(body, IPC_GATT_WRITE);
	ipc_put_le16(body + 14, 3);
	body[16] = 0xaa; body[17] = 0xbb; body[18] = 0xcc;
	ATF_REQUIRE_EQ((ssize_t)sizeof(write_rsp), send(att_pair[1], write_rsp,
	    sizeof(write_rsp), 0));
	status = dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_GATT,
	    body, IPC_GATT_VALUE_REQ_SIZE + 3);
	ATF_CHECK_EQ_MSG(IPC_ERR_NONE, status, "write status=%u", status);

	ipc_put_le16(body, IPC_GATT_WRITE_CMD);
	body[16] = 0x5a;
	ipc_put_le16(body + 14, 1);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_VALUE_REQ_SIZE + 1));
	{
		uint8_t command[ATT_MAX_MTU];
		int saw_write_cmd = 0;

		for (int i = 0; i < 3; i++) {
			ATF_REQUIRE(recv(att_pair[1], command, sizeof(command), 0) > 0);
			if (command[0] == ATT_OP_WRITE_CMD)
				saw_write_cmd++;
		}
		ATF_CHECK_EQ(1, saw_write_cmd);
	}

	/* A service and characteristic are emitted as correlated typed events. */
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_DISCOVER);
	body[4] = 0;	/* IPC public; conn stores BDADDR_LE_PUBLIC */
	memcpy(body + 5, &addr, sizeof(addr));
	ATF_REQUIRE_EQ(0, pthread_create(&discovery_responder, NULL,
	    ctl_att_discovery_responder, &att_pair[1]));
	{
		uint8_t req[IPC_OP_PREFIX_SIZE + IPC_GATT_REQ_SIZE];
		uint32_t request_id = ++ipc_test_request_id;

		ipc_op_prefix_encode(req, request_id, 0, 0);
		memcpy(req + IPC_OP_PREFIX_SIZE, body, IPC_GATT_REQ_SIZE);
		ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_GATT, req,
		    sizeof(req));
		ATF_REQUIRE_EQ(0, blued_ctl_dispatch(client));
		for (int i = 0; i < 1000 && atomic_load(&conn->att_op_busy); i++)
			usleep(1000);
		ATF_CHECK(!atomic_load(&conn->att_op_busy));
	}
	ATF_REQUIRE_EQ(0, pthread_join(discovery_responder, NULL));

	blued_ctl_cleanup();
	conn->att = NULL;
	blued_conn_free(conn);
	LIST_REMOVE(&adp, entries);
	close(att_pair[0]);
	close(att_pair[1]);
	free(att.buf);
	close(sp[1]);
	close(blued_g.kq);
}

static int ctl_test_discovery_records;

struct ctl_att_retry_exchange {
	int fd;
	const uint8_t *first;
	size_t first_len;
	const uint8_t *second;
	size_t second_len;
};

static void *
ctl_att_retry_responder(void *arg)
{
	struct ctl_att_retry_exchange *x = arg;
	uint8_t request[ATT_MAX_MTU];

	if (recv(x->fd, request, sizeof(request), 0) > 0)
		(void)send(x->fd, x->first, x->first_len, 0);
	if (x->second_len != 0 &&
	    recv(x->fd, request, sizeof(request), 0) > 0)
		(void)send(x->fd, x->second, x->second_len, 0);
	return (NULL);
}

static void *
ctl_att_discovery_responder(void *arg)
{
	int fd = *(int *)arg;
	uint8_t req[ATT_MAX_MTU], rsp[16];
	int groups = 0, chars = 0;
	ssize_t n;

	while ((n = recv(fd, req, sizeof(req), 0)) > 0) {
		if (req[0] == ATT_OP_READ_BY_GROUP_TYPE_REQ && groups++ == 0) {
			static const uint8_t service[] = {
				ATT_OP_READ_BY_GROUP_TYPE_RSP, 6,
				0x01, 0x00, 0x05, 0x00, 0x0f, 0x18
			};
			(void)send(fd, service, sizeof(service), 0);
			continue;
		}
		if (req[0] == ATT_OP_READ_BY_TYPE_REQ && chars++ == 0) {
			static const uint8_t characteristic[] = {
				ATT_OP_READ_BY_TYPE_RSP, 7, 0x02, 0x00,
				GATT_PROP_READ, 0x03, 0x00, 0x19, 0x2a
			};
			(void)send(fd, characteristic, sizeof(characteristic), 0);
			continue;
		}
		memset(rsp, 0, sizeof(rsp));
		rsp[0] = ATT_OP_ERROR_RSP;
		rsp[1] = req[0];
		if (n >= 3) {
			rsp[2] = req[1];
			rsp[3] = req[2];
		}
		rsp[4] = ATT_ERR_ATTR_NOT_FOUND;
		(void)send(fd, rsp, 5, 0);
		if (req[0] == ATT_OP_READ_BY_TYPE_REQ && chars > 1)
			break;
	}
	return (NULL);
}

static void
ctl_test_discovery_cb(const struct gatt_service *service,
    const struct gatt_char *characteristic, void *arg __unused)
{

	if (service != NULL || characteristic != NULL)
		ctl_test_discovery_records++;
}

ATF_TC_WITHOUT_HEAD(test_ctl_gatt_security_retry);
ATF_TC_BODY(test_ctl_gatt_security_retry, tc)
{
	struct blued_adapter adp;
	struct blued_conn *conn;
	struct att_conn att;
	struct smp_bond bond;
	bdaddr_t addr;
	uint8_t value[16];
	size_t value_len;
	struct ctl_att_retry_exchange exchange;
	pthread_t responder;
	int att_pair[2];
	static const uint8_t read_auth[] = { ATT_OP_ERROR_RSP, ATT_OP_READ_REQ,
	    0x25, 0x00, ATT_ERR_INSUFF_AUTHEN };
	static const uint8_t read_ok[] = { ATT_OP_READ_RSP, 0xaa, 0xbb };
	static const uint8_t write_auth[] = { ATT_OP_ERROR_RSP, ATT_OP_WRITE_REQ,
	    0x25, 0x00, ATT_ERR_INSUFF_ENCRYPTION };
	static const uint8_t write_ok[] = { ATT_OP_WRITE_RSP };
	static const uint8_t discover_auth[] = { ATT_OP_ERROR_RSP,
	    ATT_OP_READ_BY_GROUP_TYPE_REQ, 0x01, 0x00,
	    ATT_ERR_INSUFF_ENC_KEY_SIZE };
	static const uint8_t discover_done[] = { ATT_OP_ERROR_RSP,
	    ATT_OP_READ_BY_GROUP_TYPE_REQ, 0x01, 0x00, ATT_ERR_ATTR_NOT_FOUND };
	static const uint8_t discover_invalid[] = { ATT_OP_ERROR_RSP,
	    ATT_OP_READ_BY_GROUP_TYPE_REQ, 0x01, 0x00, ATT_ERR_INVALID_HANDLE };

	test_init();
	build_ctl_test_db();
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.powered = true;
	adp.hci_fd = 17;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &addr));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, att_pair));
	memset(&att, 0, sizeof(att));
	att.fd = att_pair[0];
	att.mtu = 185;
	att.buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(att.buf != NULL);
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->adapter = &adp;
	conn->dst = addr;
	conn->addr_type = 1;
	conn->con_handle = 0x42;
	conn->con_handle_valid = true;
	conn->att = &att;
	conn->att_fd = att.fd;

	memset(&bond, 0, sizeof(bond));
	bond.is_mitm = true;
	ctl_test_found_bond = &bond;
	ctl_test_smp_open_rc = 0;
	ctl_test_smp_pair_rc = 0;
	ctl_test_wait_encryption_rc = 0;
	exchange = (struct ctl_att_retry_exchange){ att_pair[1], read_auth,
	    sizeof(read_auth), read_ok, sizeof(read_ok) };
	ATF_REQUIRE_EQ(0, pthread_create(&responder, NULL,
	    ctl_att_retry_responder, &exchange));
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_gatt_read_result(conn, 0, &addr, 1, 0x25,
	    value, sizeof(value), &value_len));
	ATF_REQUIRE_EQ(0, pthread_join(responder, NULL));
	ATF_CHECK_EQ(2, value_len);
	ATF_CHECK(att.encrypted);
	ATF_CHECK(att.authenticated);
	ATF_CHECK_EQ(16, att.enc_key_size);

	att.encrypted = false;
	exchange = (struct ctl_att_retry_exchange){ att_pair[1], write_auth,
	    sizeof(write_auth), write_ok, sizeof(write_ok) };
	ATF_REQUIRE_EQ(0, pthread_create(&responder, NULL,
	    ctl_att_retry_responder, &exchange));
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_gatt_write_result(conn, 0, &addr, 1, 0x25,
	    value, 2, false));
	ATF_REQUIRE_EQ(0, pthread_join(responder, NULL));

	/* Encryption elevation does not imply MITM authentication.  A Just Works
	 * bond may satisfy an encrypted attribute but must leave authenticated
	 * clear (Core Spec Vol 3 Part H security properties). */
	bond.is_mitm = false;
	att.encrypted = false;
	att.authenticated = false;
	exchange = (struct ctl_att_retry_exchange){ att_pair[1], read_auth,
	    sizeof(read_auth), read_ok, sizeof(read_ok) };
	ATF_REQUIRE_EQ(0, pthread_create(&responder, NULL,
	    ctl_att_retry_responder, &exchange));
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_gatt_read_result(conn, 0, &addr, 1, 0x25,
	    value, sizeof(value), &value_len));
	ATF_REQUIRE_EQ(0, pthread_join(responder, NULL));
	ATF_CHECK(att.encrypted);
	ATF_CHECK(!att.authenticated);
	bond.is_mitm = true;

	att.encrypted = false;
	exchange = (struct ctl_att_retry_exchange){ att_pair[1], discover_auth,
	    sizeof(discover_auth), discover_done, sizeof(discover_done) };
	ATF_REQUIRE_EQ(0, pthread_create(&responder, NULL,
	    ctl_att_retry_responder, &exchange));
	ctl_test_discovery_records = 0;
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_gatt_discover_result(conn, 0, &addr, 1,
	    ctl_test_discovery_cb, NULL));
	ATF_REQUIRE_EQ(0, pthread_join(responder, NULL));
	ATF_CHECK_EQ(0, ctl_test_discovery_records);

	/* A non-security discovery error is reported directly; it must restore the
	 * ATT timeout rather than attempting an unrelated SMP retry. */
	exchange = (struct ctl_att_retry_exchange){ att_pair[1], discover_invalid,
	    sizeof(discover_invalid), NULL, 0 };
	ATF_REQUIRE_EQ(0, pthread_create(&responder, NULL,
	    ctl_att_retry_responder, &exchange));
	ATF_CHECK_EQ(IPC_ERR_IO, ctl_gatt_discover_result(conn, 0, &addr, 1,
	    ctl_test_discovery_cb, NULL));
	ATF_REQUIRE_EQ(0, pthread_join(responder, NULL));

	/* A failed elevation returns a bounded I/O error without retrying. */
	ctl_test_smp_open_rc = -1;
	ATF_REQUIRE_EQ((ssize_t)sizeof(read_auth),
	    send(att_pair[1], read_auth, sizeof(read_auth), 0));
	ATF_CHECK_EQ(IPC_ERR_IO, ctl_gatt_read_result(conn, 0, &addr, 1, 0x25,
	    value, sizeof(value), &value_len));
	/* Every elevation stage may fail independently.  In each case the first
	 * ATT security error is returned as a bounded control I/O failure and no
	 * second ATT request is issued. */
	ctl_test_smp_open_rc = 0;
	ctl_test_smp_pair_rc = -1;
	ATF_REQUIRE_EQ((ssize_t)sizeof(read_auth),
	    send(att_pair[1], read_auth, sizeof(read_auth), 0));
	ATF_CHECK_EQ(IPC_ERR_IO, ctl_gatt_read_result(conn, 0, &addr, 1, 0x25,
	    value, sizeof(value), &value_len));
	ctl_test_smp_pair_rc = 0;
	ctl_test_wait_encryption_rc = -1;
	ATF_REQUIRE_EQ((ssize_t)sizeof(read_auth),
	    send(att_pair[1], read_auth, sizeof(read_auth), 0));
	ATF_CHECK_EQ(IPC_ERR_IO, ctl_gatt_read_result(conn, 0, &addr, 1, 0x25,
	    value, sizeof(value), &value_len));
	ctl_test_wait_encryption_rc = 0;
	/*
	 * Finding 90: the worker operates on the admitted conn, not an address
	 * re-lookup, so a NULL job_conn (or one whose att is gone) is the
	 * NOT_CONN case.
	 */
	ATF_CHECK_EQ(IPC_ERR_NOT_CONN, ctl_gatt_read_result(NULL, 0, &addr, 1,
	    0x25, value, sizeof(value), &value_len));

	conn->att = NULL;
	blued_conn_free(conn);
	LIST_REMOVE(&adp, entries);
	close(att_pair[0]); close(att_pair[1]);
	free(att.buf);
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
/* ================================================================
 * Test: CONNECT command — invalid address format returns ERROR
 * ================================================================ */
/* ================================================================
 * Test: CONNECT command — already connected address returns ERROR
 * ================================================================ */
/* ================================================================
 * Test: SCAN command with no active adapter returns error
 * ================================================================ */
/* ================================================================
 * Test: concurrent clients can issue commands without interfering.
 * Uses pthreads to dispatch on two clients simultaneously.
 * ================================================================ */
/* ================================================================
 * Test: SERVICES command lists local GATT database
 * ================================================================ */
/* ================================================================
 * Test: SERVICES with empty database
 * ================================================================ */
/* ================================================================
 * Test: DISCOVER with no connection returns error
 * ================================================================ */
/* ================================================================
 * Test: DISCOVER with invalid address
 * ================================================================ */
/* ================================================================
 * Test: READ with no connection returns error
 * ================================================================ */
/* ================================================================
 * Test: WRITE with no connection returns error
 * ================================================================ */
/* ================================================================
 * Test: WRITE with invalid hex value
 * ================================================================ */
/* ================================================================
 * Test: ADD_SERVICE adds a service to the GATT database
 * ================================================================ */
/* ================================================================
 * Test: ADD_CHAR adds a characteristic to a service
 * ================================================================ */
/* ================================================================
 * Test: ADD_CHAR parses the dynamic/authorize app-backing flags and
 * records them (with the owner) on the value attribute.
 * ================================================================ */
/* ================================================================
 * Test: ADD_CHAR rejects appending to a service after another service starts
 * ================================================================ */
/* ================================================================
 * Test: ADD_INCLUDE adds an Included Service declaration to a service
 * ================================================================ */
/* ================================================================
 * Test: ADD_INCLUDE rejects self-includes and caller-forged service ranges
 * ================================================================ */
/* ================================================================
 * Test: ADD_CHAR rolls back if an auto-CCCD cannot be allocated
 * ================================================================ */
/* ================================================================
 * Test: READ_REPLY / AUTHORIZE_REPLY with nothing pending are recognised
 * and rejected cleanly (no crash, well-formed error).
 * ================================================================ */
/* ================================================================
 * Test: end-to-end dynamic-read round-trip through the ctl path — a peer
 * read on an app-owned dynamic characteristic is deferred, and READ_REPLY
 * completes the withheld ATT Read Response on the bearer with the app bytes.
 * ================================================================ */
/* ================================================================
 * Test: REMOVE_SERVICE removes a service
 * ================================================================ */
/* ================================================================
 * Test: REMOVE_SERVICE with invalid handle returns error
 * ================================================================ */
/* ================================================================
 * Test: LOGLEVEL without argument returns current level
 * ================================================================ */
/* ================================================================
 * Test: LOGLEVEL with argument sets the level
 * ================================================================ */
/* ================================================================
 * Test: LOGLEVEL with out-of-range value returns ERROR
 * ================================================================ */
/* ================================================================
 * Test: SUBSCRIBE command adds subscription
 * ================================================================ */
/* ================================================================
 * Test: UNSUBSCRIBE command removes subscription
 * ================================================================ */
/* ================================================================
 * Test: SET_VALUE updates a local GATT attribute value
 * ================================================================ */
/* ================================================================
 * Test: PASSKEY_REPLY dispatches without crash.
 *
 * PASSKEY_REPLY sets the reply fields in blued_g; with no pending
 * request the reply is accepted but silently ignored by the SMP thread.
 * ================================================================ */
/* ================================================================
 * Test: NUMCMP_REPLY dispatches without crash.
 * ================================================================ */
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
/* ================================================================
 * F16: SCAN is a blocking operation (it stalls the single-threaded event
 * loop for a scan window) and must be subject to the same per-client
 * rate limiter as DISCOVER, so an unprivileged client cannot wedge the
 * daemon by repeating it.
 * ================================================================ */
/* ================================================================
 * F13: the operation dispatcher holds gatt_db_lock while setting a value.
 * The handler must not re-acquire that non-recursive
 * mutex (which would self-deadlock the single-threaded daemon and then
 * double-unlock on return).  SET_VALUE must complete and leave the mutex
 * free and lockable — proof the lock is taken and released exactly once.
 * ================================================================ */
/* ================================================================
 * Test: HOGP_READ with no connection — returns error.
 * The hogp_find_feature_handle stub returns 0 (no handle).
 * ================================================================ */
/* ================================================================
 * Test: PASSKEY_REPLY with invalid passkey (>999999) returns error
 * ================================================================ */
/* ================================================================
 * Test: PASSKEY_REPLY with wrong address returns error
 * ================================================================ */
/* ================================================================
 * Test: PASSKEY_REPLY with no pending request returns error
 * ================================================================ */
/* ================================================================
 * Test: NUMCMP_REPLY with invalid arg (not yes/no) returns error
 * ================================================================ */
/* ================================================================
 * Test: NUMCMP_REPLY "no" is accepted
 * ================================================================ */
/* ================================================================
 * Test: PAIR on unconnected device returns error
 * ================================================================ */
/* ================================================================
 * REKEY (BLE key refresh / controlled re-bond) ctl surface.
 * ================================================================ */

/* Insert a connected central-role peer into the global connection list. */
/* REKEY with a malformed address is rejected before any lookup. */
/* REKEY on a device with no live connection is rejected. */
/*
 * REKEY on a connected-but-unbonded peer is rejected: a refresh replaces an
 * existing bond, it is not a first pairing.
 */
/*
 * REKEY on a peripheral-role connection is rejected: only the central owns
 * SMP initiation.
 */
/*
 * REKEY on a bonded, connected central initiates a fresh SMP exchange and
 * reports success.
 */
/* A failed re-pair surfaces an error (old bond is untouched by the daemon). */
/* ================================================================
 * Test: BOND_EXPORT with populated bond database
 * ================================================================ */
/* ================================================================
 * PC4: BOND_EXPORT <addr> / BOND_IMPORT dispatch, privilege, and
 * resolving-list wiring.  The record (de)serializer is mocked here (see the
 * smp_bond_*_record stubs above); the real serialization + validation is
 * covered in bond_migrate_test.  These assert the ctl-layer contract only, and
 * NEVER print key bytes.
 * ================================================================ */

/* A privileged peer can pull a full key-bearing record for a known bond. */
/* An unprivileged peer is refused the key-bearing export (IPC_ERR_PERM). */
/* An unprivileged peer cannot import (the dispatcher privilege gate). */
/* A privileged import of an IRK-bearing bond programs the resolving list. */
/* A record the validator rejects leaves the DB untouched and adds no IRK. */
/* A full DB rejects an appended import with a typed capacity error. */
/* ================================================================
 * Test: HOGP_WRITE on unconnected device returns error
 * ================================================================ */
/* ================================================================
 * Test: SCAN output includes svcs= field
 * ================================================================ */
/* ================================================================
 * Test: BOND_EXPORT returns bond metadata
 * ================================================================ */
/* ================================================================
 * Test: CONNPARAMS returns connection parameter list
 * ================================================================ */
/* ================================================================
 * Test: LIST output includes security fields
 * ================================================================ */
/* ================================================================
 * Test: CONNPARAMS with a connection shows parameters
 * ================================================================ */
/* ================================================================
 * Test: CONNECT_NAME with empty name returns error
 * ================================================================ */
/* ================================================================
 * Test: CONNECT with invalid address format
 * ================================================================ */
/* ================================================================
 * Test: BOND_EXPORT with multiple bonds
 * ================================================================ */
/* ================================================================
 * Test: CONNPARAMS with specific values verified
 * ================================================================ */
/* ================================================================
 * Test: LIST output shows name from bond DB
 * ================================================================ */
/* ================================================================
 * Test: LOGLEVEL boundary — level 0 and level 5
 * ================================================================ */
/* ================================================================
 * Test: WRITE with odd-length hex returns error
 * ================================================================ */
/* ================================================================
 * Framed binary protocol (ipc_proto.h) — server side.
 *
 * These drive blued_ctl_dispatch() with length-prefixed HELLO/CMD frames
 * and decode the framed replies, exercising the handshake, feature
 * negotiation, privilege tiers (getpeereid-based), and event opt-in gating.
 * ================================================================ */

/* Send a framed message to the daemon (as a client would). */
static void
ipc_send(int fd, uint16_t type, uint16_t arg, const char *pl)
{
	uint8_t hdr[IPC_HDR_SIZE];
	size_t plen = (pl != NULL) ? strlen(pl) : 0;

	ipc_hdr_encode(hdr, (uint32_t)plen, type, arg);
	ATF_REQUIRE(send(fd, hdr, sizeof(hdr), 0) == (ssize_t)sizeof(hdr));
	if (plen > 0)
		ATF_REQUIRE(send(fd, pl, plen, 0) == (ssize_t)plen);
}

static void
ipc_send_raw(int fd, uint16_t type, uint16_t arg, const void *pl, size_t plen)
{
	uint8_t hdr[IPC_HDR_SIZE];

	ipc_hdr_encode(hdr, (uint32_t)plen, type, arg);
	ATF_REQUIRE(send(fd, hdr, sizeof(hdr), 0) == (ssize_t)sizeof(hdr));
	if (plen > 0)
		ATF_REQUIRE(send(fd, pl, plen, 0) == (ssize_t)plen);
}

/* Read exactly n bytes from a socket (handles short reads). */
static void
ipc_read_exact(int fd, void *buf, size_t n)
{
	size_t got = 0;

	while (got < n) {
		ssize_t r = recv(fd, (uint8_t *)buf + got, n - got, 0);

		ATF_REQUIRE(r > 0);
		got += (size_t)r;
	}
}

/* Receive one framed reply; returns payload length, NUL-terminates pl. */
static size_t
ipc_recv(int fd, uint16_t *type, uint16_t *arg, char *pl, size_t plmax)
{
	uint8_t hdr[IPC_HDR_SIZE];
	uint32_t plen;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	ipc_read_exact(fd, hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, type, arg);
	ATF_REQUIRE(plen < plmax);
	if (plen > 0)
		ipc_read_exact(fd, pl, plen);
	pl[plen] = '\0';
	return (plen);
}

static uint32_t ipc_test_request_id = 0x40000000u;

static uint32_t
ipc_send_ctl_operation(int fd, uint16_t opcode, uint16_t flags,
    uint32_t arg0, uint32_t arg1)
{
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_CTL_REQ_SIZE];
	uint32_t request_id;

	request_id = ++ipc_test_request_id;
	ipc_op_prefix_encode(request, request_id, IPC_ERR_NONE, 0);
	ipc_ctl_req_encode(request + IPC_OP_PREFIX_SIZE, opcode, flags, arg0,
	    arg1);
	ipc_send_raw(fd, IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL, request,
	    sizeof(request));
	return (request_id);
}

static size_t
ipc_recv_operation(int fd, uint16_t domain, uint32_t expected_id,
    uint16_t expected_status, void *body, size_t body_size)
{
	char frame[IPC_MAX_PAYLOAD + 1];
	uint32_t request_id;
	uint16_t type, arg, status, flags;
	size_t body_len, plen;

	plen = ipc_recv(fd, &type, &arg, frame, sizeof(frame));
	ATF_REQUIRE_EQ(type, IPC_T_OP_REPLY);
	ATF_REQUIRE_EQ(arg, domain);
	ATF_REQUIRE(plen >= IPC_OP_PREFIX_SIZE);
	ipc_op_prefix_decode((const uint8_t *)frame, &request_id, &status,
	    &flags);
	ATF_CHECK_EQ(request_id, expected_id);
	ATF_CHECK_EQ(status, expected_status);
	ATF_CHECK_EQ(flags, 0);
	body_len = plen - IPC_OP_PREFIX_SIZE;
	ATF_REQUIRE(body_len <= body_size);
	if (body_len != 0)
		memcpy(body, frame + IPC_OP_PREFIX_SIZE, body_len);
	return (body_len);
}

/* Drive a HELLO handshake; returns the accepted-features payload via feat. */
static void
ipc_handshake(struct blued_ctl_client *client, int peer, uint16_t version,
    uint32_t req_features, char *feat, size_t featsz)
{
	uint8_t request[IPC_HELLO_FEATURES_SIZE];
	uint16_t type, arg;

	ATF_REQUIRE(featsz > IPC_HELLO_FEATURES_SIZE);
	ipc_put_le32(request, req_features);
	ipc_send_raw(peer, IPC_T_HELLO, version, request, sizeof(request));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	(void)ipc_recv(peer, &type, &arg, feat, featsz);
	ATF_CHECK_EQ(type, IPC_T_HELLO);
	ATF_CHECK_EQ(arg, IPC_PROTO_VERSION);
	ATF_CHECK(client->handshaked);
}

/* HELLO with a matching version + push-events feature is accepted. */
ATF_TC_WITHOUT_HEAD(test_ipc_hello_match);
ATF_TC_BODY(test_ipc_hello_match, tc)
{
	struct blued_ctl_client *client;
	char feat[128];
	int sp[2];

	test_init();
	client = make_client(sp);

	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS, feat, sizeof(feat));
	ATF_CHECK((ipc_get_le32((const uint8_t *)feat) &
	    IPC_FEATURE_EVENTS) != 0);
	ATF_CHECK(client->wants_events);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* HELLO with a mismatched major version yields a clean IPC_ERR_PROTO frame. */
ATF_TC_WITHOUT_HEAD(test_ipc_hello_version_mismatch);
ATF_TC_BODY(test_ipc_hello_version_mismatch, tc)
{
	struct blued_ctl_client *client;
	char pl[128];
	uint16_t type, arg;
	int sp[2];

	test_init();
	client = make_client(sp);

	ipc_send(sp[1], IPC_T_HELLO, IPC_PROTO_VERSION + 99, "");
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	(void)ipc_recv(sp[1], &type, &arg, pl, sizeof(pl));
	ATF_CHECK_EQ(type, IPC_T_ERROR);
	ATF_CHECK_EQ(arg, IPC_ERR_PROTO);
	ATF_CHECK(!client->handshaked);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* Feature negotiation: an unknown feature is dropped from the accepted set. */
ATF_TC_WITHOUT_HEAD(test_ipc_feature_negotiation);
ATF_TC_BODY(test_ipc_feature_negotiation, tc)
{
	struct blued_ctl_client *client;
	char feat[128];
	int sp[2];

	test_init();
	client = make_client(sp);

	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS | 0x80000000u, feat, sizeof(feat));
	ATF_CHECK_EQ(ipc_get_le32((const uint8_t *)feat), IPC_FEATURE_EVENTS);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* A privileged (uid 0) peer may issue a state-mutating command. */
/* An unprivileged peer is denied a state-mutating command, allowed a query. */
/* A peer without known credentials is denied mutation, allowed a query. */
/*
 * Event gating (finding C8, server side): a framed client that did NOT opt
 * into push-events receives no unsolicited event frame, while one that did
 * receives it — so a non-opted-in client's stream never desyncs.
 */
ATF_TC_WITHOUT_HEAD(test_ipc_event_optin_gating);
ATF_TC_BODY(test_ipc_event_optin_gating, tc)
{
	struct blued_ctl_client *cli_on, *cli_off;
	struct blued_adapter adapter = { .index = 0 };
	struct blued_conn conn = { .adapter = &adapter };
	char feat[128], pl[256];
	uint16_t type, arg;
	uint8_t val[2] = { 0xAB, 0xCD };
	bdaddr_t addr;
	int spon[2], spoff[2];
	ssize_t n;

	test_init();
	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &addr));
	conn.dst = addr;
	conn.addr_type = 0;

	/* Opted-in client. */
	cli_on = make_client(spon);
	ipc_handshake(cli_on, spon[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS, feat, sizeof(feat));
	LIST_INSERT_HEAD(&blued_g.ctl_clients, cli_on, entries);
	memcpy(&cli_on->subs[0].addr, &addr, sizeof(addr));
	cli_on->subs[0].handle = 0x0007;
	cli_on->nsubs = 1;

	/* Framed client that did NOT request push-events. */
	cli_off = make_client(spoff);
	ipc_handshake(cli_off, spoff[1], IPC_PROTO_VERSION, 0, feat,
	    sizeof(feat));
	LIST_INSERT_HEAD(&blued_g.ctl_clients, cli_off, entries);
	memcpy(&cli_off->subs[0].addr, &addr, sizeof(addr));
	cli_off->subs[0].handle = 0x0007;
	cli_off->nsubs = 1;
	ATF_CHECK(!cli_off->wants_events);

	blued_ctl_notify_value(&conn, 0x0007, val, sizeof(val), 23);

	/* Opted-in client receives a typed GATT notification event. */
	n = (ssize_t)ipc_recv(spon[1], &type, &arg, pl, sizeof(pl));
	ATF_CHECK_EQ(type, IPC_T_OP_EVENT);
	ATF_CHECK_EQ(arg, IPC_OP_DOMAIN_GATT);
	ATF_REQUIRE_EQ(n, IPC_OP_PREFIX_SIZE + IPC_GATT_NOTIFY_EVENT_SIZE +
	    sizeof(val));
	ATF_CHECK_EQ(ipc_get_le32((uint8_t *)pl), 0);
	ATF_CHECK_EQ(ipc_get_le16((uint8_t *)pl + IPC_OP_PREFIX_SIZE),
	    IPC_GATT_EV_NOTIFY);
	ATF_CHECK_EQ(ipc_get_le16((uint8_t *)pl + IPC_OP_PREFIX_SIZE + 9),
	    0x0007);
	ATF_CHECK_EQ(ipc_get_le16((uint8_t *)pl + IPC_OP_PREFIX_SIZE + 11),
	    sizeof(val));
	ATF_CHECK_EQ(ipc_get_le16((uint8_t *)pl + IPC_OP_PREFIX_SIZE + 14),
	    23);
	ATF_CHECK(memcmp((uint8_t *)pl + IPC_OP_PREFIX_SIZE +
	    IPC_GATT_NOTIFY_EVENT_SIZE, val, sizeof(val)) == 0);

	/* Non-opted-in client receives nothing (would-be desync avoided). */
	{
		uint8_t junk[8];
		struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };

		(void)setsockopt(spoff[1], SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv));
		n = recv(spoff[1], junk, sizeof(junk), 0);
		ATF_CHECK_MSG(n <= 0,
		    "non-opted-in client must receive no event bytes, got %zd",
		    n);
	}

	LIST_REMOVE(cli_on, entries);
	LIST_REMOVE(cli_off, entries);
	close(spon[0]);
	close(spon[1]);
	close(spoff[0]);
	close(spoff[1]);
	free(cli_on);
	free(cli_off);
}

/* Framing round-trip through dispatch: an embedded-NUL CMD payload is framed
 * by length, and the reply is a proper frame. */
/* Typed STATUS bypasses command-string parsing and returns a binary payload. */
ATF_TC_WITHOUT_HEAD(test_ipc_typed_status);
ATF_TC_BODY(test_ipc_typed_status, tc)
{
	struct blued_ctl_client *client;
	char feat[128], pl[IPC_STATUS_REPLY_SIZE + 1];
	uint16_t adapters, connections, clients, flags;
	uint32_t request_id;
	size_t plen;
	int sp[2];

	test_init();
	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	blued_g.periph_active = true;

	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS, feat, sizeof(feat));

	request_id = ipc_send_ctl_operation(sp[1], IPC_CTL_STATUS, 0, 0, 0);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv_operation(sp[1], IPC_OP_DOMAIN_CTL, request_id,
	    IPC_ERR_NONE, pl, sizeof(pl));
	ATF_REQUIRE_EQ(plen, IPC_STATUS_REPLY_SIZE);

	ipc_status_reply_decode((const uint8_t *)pl, &adapters, &connections,
	    &clients, &flags);
	ATF_CHECK_EQ(adapters, 0);
	ATF_CHECK_EQ(connections, 0);
	ATF_CHECK_EQ(clients, 1);
	ATF_CHECK((flags & IPC_STATUS_F_PERIPH_ACTIVE) != 0);

	LIST_REMOVE(client, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* Typed ADAPTER_CAPS returns the fixed binary adapter-capability payload. */
ATF_TC_WITHOUT_HEAD(test_ipc_typed_adapter_caps);
ATF_TC_BODY(test_ipc_typed_adapter_caps, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	char feat[128], pl[IPC_ADAPTER_CAPS_REPLY_SIZE + 1], name[16];
	uint8_t addr[6], addr_type, powered;
	uint16_t index;
	uint32_t request_id;
	uint64_t le_features;
	size_t plen;
	int sp[2], pending_fd[2];
	struct blued_conn pending_conn;
	struct att_conn pending_att;
	uint8_t pending_value = 0x5a;

	test_init();
	/* Deferred dynamic-GATT replies must validate locally before looking up a
	 * pending peripheral request, and a well-formed reply without a matching
	 * pending request must not be reported as success. */
	ATF_CHECK_EQ(IPC_ERR_INVAL,
	    ctl_gatt_read_reply_result(7, 0, NULL, 0));
	ATF_CHECK_EQ(IPC_ERR_INVAL,
	    ctl_gatt_read_reply_result(7, 1, NULL, 1));
	ATF_CHECK_EQ(IPC_ERR_INVAL,
	    ctl_gatt_read_reply_result(7, 1, NULL, ATT_PDU_BUF_SIZE + 1));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND,
	    ctl_gatt_read_reply_result(7, 1, NULL, 0));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_read_reject_result(7, 0, 1));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_read_reject_result(7, 1, 0));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_read_reject_result(7, 1, 1));
	ATF_CHECK_EQ(IPC_ERR_INVAL,
	    ctl_gatt_authorize_reply_result(7, 0, true));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND,
	    ctl_gatt_authorize_reply_result(7, 1, false));

	/* A matching deferred read is routed only to its owning peripheral
	 * connection, emits the ATT response, and consumes that pending slot. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pending_fd));
	memset(&pending_conn, 0, sizeof(pending_conn));
	memset(&pending_att, 0, sizeof(pending_att));
	pending_conn.role = BLUED_ROLE_PERIPHERAL;
	pending_conn.att = &pending_att;
	pending_att.fd = pending_fd[0];
	pending_att.mtu = ATT_DEFAULT_MTU;
	pending_att.pending.kind = ATT_PEND_READ;
	pending_att.pending.handle = 0x0042;
	pending_att.pending.owner_fd = 7;
	pending_att.pending.bearer_fd = -1;
	pending_att.pending.bearer_mtu = ATT_DEFAULT_MTU;
	/* Deferred ATT operations are bound both to the owning IPC client and to
	 * their pending kind; a different client or reply verb cannot consume it. */
	LIST_INSERT_HEAD(&blued_g.conns, &pending_conn, entries);
	pending_att.pending.owner_fd = 8;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND,
	    ctl_gatt_read_reply_result(7, 0x0042, &pending_value, 1));
	pending_att.pending.owner_fd = 7;
	ATF_CHECK_EQ(IPC_ERR_NONE,
	    ctl_gatt_read_reply_result(7, 0x0042, &pending_value, 1));
	ATF_CHECK(!att_server_pending_active(&pending_att));
	pending_att.pending.kind = ATT_PEND_READ;
	pending_att.pending.handle = 0x0043;
	pending_att.pending.owner_fd = 7;
	pending_att.pending.bearer_fd = -1;
	pending_att.pending.bearer_mtu = ATT_DEFAULT_MTU;
	ATF_CHECK_EQ(IPC_ERR_NONE,
	    ctl_gatt_read_reject_result(7, 0x0043, ATT_ERR_READ_NOT_PERMITTED));
	ATF_CHECK(!att_server_pending_active(&pending_att));
	pending_att.pending.kind = ATT_PEND_AUTH_READ;
	pending_att.pending.handle = 0x0044;
	pending_att.pending.owner_fd = 7;
	pending_att.pending.bearer_fd = -1;
	pending_att.pending.bearer_mtu = ATT_DEFAULT_MTU;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND,
	    ctl_gatt_read_reply_result(7, 0x0044, &pending_value, 1));
	ATF_CHECK_EQ(IPC_ERR_NONE,
	    ctl_gatt_authorize_reply_result(7, 0x0044, false));
	ATF_CHECK(!att_server_pending_active(&pending_att));
	LIST_REMOVE(&pending_conn, entries);
	close(pending_fd[0]);
	close(pending_fd[1]);
	memset(&adp, 0, sizeof(adp));
	adp.index = 2;
	strlcpy(adp.name, "ubt2", sizeof(adp.name));
	ATF_REQUIRE(bt_aton("01:02:03:04:05:06", &adp.addr));
	adp.active = true;
	adp.powered = true;
	adp.hci_fd = -1;
	adp.le_features = LE_FEAT_PERIODIC_ADV | LE_FEAT_PAST_SENDER |
	    LE_FEAT_PATH_LOSS_MONITORING;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS, feat, sizeof(feat));

	request_id = ipc_send_ctl_operation(sp[1], IPC_CTL_ADAPTER_CAPS, 0,
	    2, 0);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv_operation(sp[1], IPC_OP_DOMAIN_CTL, request_id,
	    IPC_ERR_NONE, pl, sizeof(pl));
	ATF_REQUIRE_EQ(plen, IPC_ADAPTER_CAPS_REPLY_SIZE);

	ipc_adapter_caps_reply_decode((const uint8_t *)pl, &index, name,
	    addr, &addr_type, &powered, &le_features);
	name[sizeof(name) - 1] = '\0';
	ATF_CHECK_EQ(index, 2);
	ATF_CHECK_STREQ(name, "ubt2");
	ATF_CHECK_EQ(memcmp(addr, &adp.addr, 6), 0);
	ATF_CHECK_EQ(addr_type, 0);
	ATF_CHECK_EQ(powered, 1);
	ATF_CHECK_EQ(le_features, adp.le_features);

	LIST_REMOVE(client, entries);
	LIST_REMOVE(&adp, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_ipc_periodic_routes_adapter);
ATF_TC_BODY(test_ipc_periodic_routes_adapter, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp0, adp2;
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_PERIODIC_PARAMS_REQ_SIZE] = { 0 };
	uint8_t *body = request + IPC_OP_PREFIX_SIZE;
	char feat[128];
	uint32_t request_id;
	int sp[2];

	test_init();
	memset(&adp0, 0, sizeof(adp0));
	memset(&adp2, 0, sizeof(adp2));
	adp0.index = 0;
	adp0.hci_fd = 10;
	adp0.active = true;
	adp0.powered = true;
	adp0.le_features = LE_FEAT_PERIODIC_ADV;
	adp2.index = 2;
	adp2.hci_fd = 42;
	adp2.active = true;
	adp2.powered = true;
	adp2.le_features = LE_FEAT_PERIODIC_ADV;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp0, entries);
	LIST_INSERT_HEAD(&blued_g.adapters, &adp2, entries);
	client = make_client(sp);
	client->peer_known = true;
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, 0, feat, sizeof(feat));

	request_id = ++ipc_test_request_id;
	ipc_op_prefix_encode(request, request_id, 0, 0);
	ipc_put_le16(body, IPC_PERIODIC_ADV_PARAMS);
	ipc_put_le16(body + 2, 2u << IPC_OP_ADAPTER_SHIFT);
	ipc_put_le16(body + 4, 6);
	ipc_put_le16(body + 6, 12);
	periodic_hci_fd = -1;
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_PERIODIC, request,
	    sizeof(request));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	ATF_CHECK_EQ(ipc_recv_operation(sp[1], IPC_OP_DOMAIN_PERIODIC,
	    request_id, IPC_ERR_NONE, NULL, 0), 0);
	ATF_CHECK_EQ(periodic_hci_fd, 42);

	LIST_REMOVE(client, entries);
	LIST_REMOVE(&adp2, entries);
	LIST_REMOVE(&adp0, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

static void
expect_typed_ctl_error(struct blued_ctl_client *client, int peer_fd,
    uint16_t opcode, uint16_t flags, uint32_t arg0, uint32_t arg1,
    uint16_t want_err)
{
	char pl[64];
	uint32_t request_id;
	size_t plen;

	request_id = ipc_send_ctl_operation(peer_fd, opcode, flags, arg0, arg1);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv_operation(peer_fd, IPC_OP_DOMAIN_CTL, request_id,
	    want_err, pl, sizeof(pl));
	ATF_REQUIRE(plen > 0);
}

static uint16_t
dispatch_domain_request(struct blued_ctl_client *client, int peer_fd,
    uint16_t domain, const uint8_t *body, size_t body_len)
{
	uint8_t req[IPC_OP_PREFIX_SIZE + 512], reply[2048];
	uint32_t request_id, got_id;
	uint16_t type, got_domain, status, flags;
	size_t plen;

	/* Operations require a completed HELLO handshake (finding 35). */
	client->handshaked = true;
	ATF_REQUIRE(body_len <= sizeof(req) - IPC_OP_PREFIX_SIZE);
	request_id = ++ipc_test_request_id;
	ipc_op_prefix_encode(req, request_id, 0, 0);
	memcpy(req + IPC_OP_PREFIX_SIZE, body, body_len);
	ipc_send_raw(peer_fd, IPC_T_OP_REQ, domain, req,
	    IPC_OP_PREFIX_SIZE + body_len);
	ATF_REQUIRE_EQ(0, blued_ctl_dispatch(client));
	plen = ipc_recv(peer_fd, &type, &got_domain, reply, sizeof(reply));
	ATF_REQUIRE_EQ(IPC_T_OP_REPLY, type);
	ATF_REQUIRE_EQ(domain, got_domain);
	ATF_REQUIRE(plen >= IPC_OP_PREFIX_SIZE);
	ipc_op_prefix_decode(reply, &got_id, &status, &flags);
	ATF_REQUIRE_EQ(request_id, got_id);
	ATF_REQUIRE_EQ(0, flags);
	return (status);
}

static uint16_t
dispatch_gatt_handle_request(struct blued_ctl_client *client, int peer_fd,
    const uint8_t *body, size_t body_len, uint16_t *result_handle)
{
	uint8_t req[IPC_OP_PREFIX_SIZE + 128], reply[256];
	uint32_t request_id, got_id;
	uint16_t type, domain, status, flags;
	size_t plen;

	/* Operations require a completed HELLO handshake (finding 35). */
	client->handshaked = true;
	ATF_REQUIRE(body_len <= sizeof(req) - IPC_OP_PREFIX_SIZE);
	request_id = ++ipc_test_request_id;
	ipc_op_prefix_encode(req, request_id, 0, 0);
	memcpy(req + IPC_OP_PREFIX_SIZE, body, body_len);
	ipc_send_raw(peer_fd, IPC_T_OP_REQ, IPC_OP_DOMAIN_GATT, req,
	    IPC_OP_PREFIX_SIZE + body_len);
	ATF_REQUIRE_EQ(0, blued_ctl_dispatch(client));
	plen = ipc_recv(peer_fd, &type, &domain, reply, sizeof(reply));
	ATF_REQUIRE_EQ(IPC_T_OP_REPLY, type);
	ATF_REQUIRE_EQ(IPC_OP_DOMAIN_GATT, domain);
	ATF_REQUIRE(plen >= IPC_OP_PREFIX_SIZE);
	ipc_op_prefix_decode(reply, &got_id, &status, &flags);
	ATF_REQUIRE_EQ(request_id, got_id);
	ATF_REQUIRE_EQ(0, flags);
	if (result_handle != NULL && status == IPC_ERR_NONE &&
	    plen == IPC_OP_PREFIX_SIZE + IPC_GATT_HANDLE_REPLY_SIZE)
		*result_handle = ipc_get_le16(reply + IPC_OP_PREFIX_SIZE + 2);
	return (status);
}

ATF_TC_WITHOUT_HEAD(test_ipc_typed_control_validation);
ATF_TC_BODY(test_ipc_typed_control_validation, tc)
{
	struct blued_adapter adp;
	struct blued_ctl_client *client;
	char feat[128], pl[64];
	uint8_t req[IPC_OP_PREFIX_SIZE + 1];
	uint32_t request_id;
	size_t plen;
	int sp[2];

	test_init();
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.powered = true;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS, feat, sizeof(feat));

	request_id = ++ipc_test_request_id;
	ipc_op_prefix_encode(req, request_id, IPC_ERR_NONE, 0);
	req[IPC_OP_PREFIX_SIZE] = 0;
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL, req, sizeof(req));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv_operation(sp[1], IPC_OP_DOMAIN_CTL, request_id,
	    IPC_ERR_PROTO, pl, sizeof(pl));
	ATF_REQUIRE(plen > 0);

	client->peer_uid = 1000;
	expect_typed_ctl_error(client, sp[1], IPC_CTL_SET_MTU, 0,
	    ATT_DEFAULT_MTU, 0, IPC_ERR_PERM);
	client->peer_uid = 0;

	expect_typed_ctl_error(client, sp[1], IPC_CTL_SET_MTU,
	    IPC_CTL_F_BOOL, ATT_DEFAULT_MTU, 0, IPC_ERR_INVAL);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_SET_MTU,
	    0, ATT_DEFAULT_MTU, 1, IPC_ERR_INVAL);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_GATT_BEGIN,
	    0, 1, 0, IPC_ERR_INVAL);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_POWER,
	    IPC_CTL_F_BOOL, 2, 0, IPC_ERR_INVAL);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_POWER,
	    IPC_CTL_F_BOOL, 1, 1, IPC_ERR_INVAL);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_ADVERTISE,
	    IPC_CTL_F_BOOL, 1, 1, IPC_ERR_INVAL);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_DISCOVERABLE,
	    IPC_CTL_F_BOOL, 2, 0, IPC_ERR_INVAL);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_PAIRABLE,
	    IPC_CTL_F_BOOL, 2, 0, IPC_ERR_INVAL);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_RPA_TIMEOUT,
	    0, 900, 1, IPC_ERR_INVAL);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_RPA_TIMEOUT,
	    IPC_CTL_F_BOOL, 900, 0, IPC_ERR_INVAL);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_RPA_TIMEOUT,
	    0x8000, 900, 0, IPC_ERR_INVAL);

	LIST_REMOVE(client, entries);
	LIST_REMOVE(&adp, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_ipc_typed_control_set_mtu);
ATF_TC_BODY(test_ipc_typed_control_set_mtu, tc)
{
	struct blued_ctl_client *client;
	char feat[128], pl[IPC_CTL_REPLY_SIZE + 1];
	uint16_t opcode, flags;
	uint32_t request_id, value;
	size_t plen;
	int sp[2];

	test_init();
	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS, feat, sizeof(feat));

	request_id = ipc_send_ctl_operation(sp[1], IPC_CTL_SET_MTU, 0, 247, 0);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv_operation(sp[1], IPC_OP_DOMAIN_CTL, request_id,
	    IPC_ERR_NONE, pl, sizeof(pl));
	ATF_REQUIRE_EQ(plen, IPC_CTL_REPLY_SIZE);
	ipc_ctl_reply_decode((const uint8_t *)pl, &opcode, &flags, &value);
	ATF_CHECK_EQ(opcode, IPC_CTL_SET_MTU);
	ATF_CHECK_EQ(flags, 0);
	ATF_CHECK_EQ(value, 247);
	ATF_CHECK_EQ(blued_g.att_preferred_mtu, 247);

	LIST_REMOVE(client, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_ipc_correlated_control);
ATF_TC_BODY(test_ipc_correlated_control, tc)
{
	struct blued_ctl_client *client;
	char feat[128], pl[128];
	uint8_t req[IPC_OP_PREFIX_SIZE + IPC_CTL_REQ_SIZE];
	uint32_t request_id, value;
	uint16_t type, arg, status, opflags, opcode, flags;
	size_t plen;
	int sp[2];

	test_init();
	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    0, feat, sizeof(feat));

	ipc_op_prefix_encode(req, 0x10203040u, 0, 0);
	ipc_ctl_req_encode(req + IPC_OP_PREFIX_SIZE, IPC_CTL_SET_MTU, 0,
	    247, 0);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL, req, sizeof(req));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv(sp[1], &type, &arg, pl, sizeof(pl));
	ATF_REQUIRE_EQ(type, IPC_T_OP_REPLY);
	ATF_REQUIRE_EQ(arg, IPC_OP_DOMAIN_CTL);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_CTL_REPLY_SIZE);
	ipc_op_prefix_decode((const uint8_t *)pl, &request_id, &status,
	    &opflags);
	ATF_CHECK_EQ(request_id, 0x10203040u);
	ATF_CHECK_EQ(status, IPC_ERR_NONE);
	ATF_CHECK_EQ(opflags, 0);
	ipc_ctl_reply_decode((const uint8_t *)pl + IPC_OP_PREFIX_SIZE, &opcode,
	    &flags, &value);
	ATF_CHECK_EQ(opcode, IPC_CTL_SET_MTU);
	ATF_CHECK_EQ(value, 247);

	ipc_op_prefix_encode(req, 0x50607080u, 0, 0);
	ipc_ctl_req_encode(req + IPC_OP_PREFIX_SIZE, IPC_CTL_SET_MTU, 0,
	    1, 0);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL, req, sizeof(req));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv(sp[1], &type, &arg, pl, sizeof(pl));
	ATF_REQUIRE(plen >= IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(type, IPC_T_OP_REPLY);
	ipc_op_prefix_decode((const uint8_t *)pl, &request_id, &status,
	    &opflags);
	ATF_CHECK_EQ(request_id, 0x50607080u);
	ATF_CHECK_EQ(status, IPC_ERR_INVAL);

	LIST_REMOVE(client, entries);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_ipc_correlated_gatt_database);
ATF_TC_BODY(test_ipc_correlated_gatt_database, tc)
{
	struct blued_ctl_client *client;
	struct att_attr *attr;
	char feat[128], reply[128];
	uint8_t req[IPC_OP_PREFIX_SIZE + IPC_GATT_ADD_CHAR_REQ_SIZE + 2];
	const uint8_t value[] = { 0xab, 0xcd };
	uint32_t request_id;
	uint16_t type, domain, status, flags, service_handle, char_handle;
	size_t plen;
	int sp[2];

	test_init();
	build_ctl_test_db();
	client = make_client(sp);
	client->peer_known = true;
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    0, feat, sizeof(feat));

	memset(req, 0, sizeof(req));
	ipc_op_prefix_encode(req, 0x71000001u, 0, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE, IPC_GATT_ADD_SERVICE);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 14, 0x1815);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_GATT, req,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_ADD_SERVICE_REQ_SIZE);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv(sp[1], &type, &domain, reply, sizeof(reply));
	ATF_REQUIRE_EQ(type, IPC_T_OP_REPLY);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GATT);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GATT_HANDLE_REPLY_SIZE);
	ipc_op_prefix_decode((const uint8_t *)reply, &request_id, &status,
	    &flags);
	ATF_CHECK_EQ(request_id, 0x71000001u);
	ATF_CHECK_EQ(status, IPC_ERR_NONE);
	ATF_CHECK_EQ(ipc_get_le16((const uint8_t *)reply + IPC_OP_PREFIX_SIZE),
	    IPC_GATT_ADD_SERVICE);
	service_handle = ipc_get_le16((const uint8_t *)reply +
	    IPC_OP_PREFIX_SIZE + 2);
	ATF_REQUIRE(service_handle != 0);

	memset(req, 0, sizeof(req));
	ipc_op_prefix_encode(req, 0x71000002u, 0, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE, IPC_GATT_ADD_CHARACTERISTIC);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 12, service_handle);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 14, 0x2a56);
	req[IPC_OP_PREFIX_SIZE + 32] = GATT_PROP_READ | GATT_PROP_NOTIFY;
	req[IPC_OP_PREFIX_SIZE + 33] = ATT_PERM_READ;
	req[IPC_OP_PREFIX_SIZE + 34] = ATT_ATTR_F_DYNAMIC;
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 36, sizeof(value));
	memcpy(req + IPC_OP_PREFIX_SIZE + IPC_GATT_ADD_CHAR_REQ_SIZE, value,
	    sizeof(value));
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_GATT, req,
	    sizeof(req));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv(sp[1], &type, &domain, reply, sizeof(reply));
	ATF_REQUIRE_EQ(type, IPC_T_OP_REPLY);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GATT_HANDLE_REPLY_SIZE);
	ipc_op_prefix_decode((const uint8_t *)reply, &request_id, &status,
	    &flags);
	ATF_CHECK_EQ(request_id, 0x71000002u);
	ATF_CHECK_EQ(status, IPC_ERR_NONE);
	char_handle = ipc_get_le16((const uint8_t *)reply +
	    IPC_OP_PREFIX_SIZE + 2);
	attr = attdb_find_by_handle(&periph_gatt_db, char_handle);
	ATF_REQUIRE(attr != NULL);
	ATF_CHECK(attr->is_char_value);
	ATF_CHECK_EQ(attr->owner_fd, client->fd);
	ATF_CHECK_EQ(attr->flags, ATT_ATTR_F_DYNAMIC);
	ATF_CHECK_EQ(attr->value_len, sizeof(value));
	ATF_CHECK(memcmp(attr->value, value, sizeof(value)) == 0);

	LIST_REMOVE(client, entries);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_ipc_correlated_security);
ATF_TC_BODY(test_ipc_correlated_security, tc)
{
	struct blued_ctl_client *client;
	struct blued_conn *conn;
	bdaddr_t addr;
	char feat[128], reply[128];
	uint8_t req[IPC_OP_PREFIX_SIZE + IPC_SECURITY_OOB_SC_REQ_SIZE];
	struct smp_oob_legacy legacy_oob;
	struct smp_oob_sc sc_oob;
	bool has_legacy, has_sc;
	uint32_t request_id;
	uint16_t type, domain, status, flags;
	size_t plen;
	int sp[2];

	test_init();
	client = make_client(sp);
	client->peer_known = true;
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS, feat, sizeof(feat));
	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &addr));
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->dst = addr;
	conn->addr_type = BDADDR_LE_PUBLIC;
	conn->passkey_reply_status = 0;
	memset(req, 0, sizeof(req));
	ipc_op_prefix_encode(req, 0x73000001u, 0, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE, IPC_SECURITY_PASSKEY_REPLY);
	memcpy(req + IPC_OP_PREFIX_SIZE + 5, &addr, sizeof(addr));
	ipc_put_le32(req + IPC_OP_PREFIX_SIZE + 12, 123456);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_SECURITY, req,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_PASSKEY_REQ_SIZE);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv(sp[1], &type, &domain, reply, sizeof(reply));
	ATF_REQUIRE(plen >= IPC_OP_PREFIX_SIZE);
	ATF_CHECK_EQ(type, IPC_T_OP_REPLY);
	ATF_CHECK_EQ(domain, IPC_OP_DOMAIN_SECURITY);
	ipc_op_prefix_decode((const uint8_t *)reply, &request_id, &status,
	    &flags);
	ATF_CHECK_EQ(request_id, 0x73000001u);
	ATF_CHECK_EQ(status, IPC_ERR_NONE);
	ATF_CHECK_EQ(conn->passkey_reply, 123456);
	ATF_CHECK_EQ(conn->passkey_reply_status, 1);

	memset(req, 0, sizeof(req));
	ipc_op_prefix_encode(req, 0x73000002u, 0, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE, IPC_SECURITY_SET_POLICY);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 12,
	    IPC_SECURITY_POLICY_F_MITM | IPC_SECURITY_POLICY_F_KEY_SIZE);
	req[IPC_OP_PREFIX_SIZE + 14] = 1;
	req[IPC_OP_PREFIX_SIZE + 20] = 12;
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_SECURITY, req,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_POLICY_REQ_SIZE);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv(sp[1], &type, &domain, reply, sizeof(reply));
	ATF_REQUIRE(plen >= IPC_OP_PREFIX_SIZE);
	ipc_op_prefix_decode((const uint8_t *)reply, &request_id, &status,
	    &flags);
	ATF_CHECK_EQ(status, IPC_ERR_NONE);
	ATF_CHECK(blued_cfg.mitm);
	ATF_CHECK_EQ(blued_cfg.min_key_size, 12);

	memset(req, 0, sizeof(req));
	ipc_op_prefix_encode(req, 0x73000003u, 0, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE, IPC_SECURITY_GET_POLICY);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_SECURITY, req,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_REQ_SIZE);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv(sp[1], &type, &domain, reply, sizeof(reply));
	ATF_REQUIRE_EQ(plen,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_POLICY_REPLY_SIZE);
	ipc_op_prefix_decode((const uint8_t *)reply, &request_id, &status,
	    &flags);
	ATF_CHECK_EQ(status, IPC_ERR_NONE);
	ATF_CHECK_EQ((uint8_t)reply[IPC_OP_PREFIX_SIZE + 2], 1);
	ATF_CHECK_EQ((uint8_t)reply[IPC_OP_PREFIX_SIZE + 8], 12);

	memset(req, 0, sizeof(req));
	ipc_op_prefix_encode(req, 0x73000004u, 0, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE,
	    IPC_SECURITY_OOB_INJECT_LEGACY);
	memcpy(req + IPC_OP_PREFIX_SIZE + 5, &addr, sizeof(addr));
	for (size_t i = 0; i < 16; i++)
		req[IPC_OP_PREFIX_SIZE + 12 + i] = (uint8_t)(0xa0 + i);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_SECURITY, req,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_OOB_LEGACY_REQ_SIZE);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv(sp[1], &type, &domain, reply, sizeof(reply));
	ATF_REQUIRE(plen >= IPC_OP_PREFIX_SIZE);
	ipc_op_prefix_decode((const uint8_t *)reply, &request_id, &status,
	    &flags);
	ATF_CHECK_EQ(request_id, 0x73000004u);
	ATF_CHECK_EQ(status, IPC_ERR_NONE);
	ATF_REQUIRE(blued_oob_take((const uint8_t *)&addr, &legacy_oob,
	    &has_legacy, &sc_oob, &has_sc));
	ATF_CHECK(has_legacy);
	ATF_CHECK(!has_sc);
	ATF_CHECK(memcmp(legacy_oob.tk,
	    req + IPC_OP_PREFIX_SIZE + 12, 16) == 0);

	/* Generate local SC-OOB material, then merge it into an injected peer. */
	memset(req, 0, sizeof(req));
	ipc_op_prefix_encode(req, 0x73000005u, 0, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE, IPC_SECURITY_OOB_GENERATE);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_SECURITY, req,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_REQ_SIZE);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv(sp[1], &type, &domain, reply, sizeof(reply));
	ATF_REQUIRE_EQ(plen,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_OOB_REPLY_SIZE);
	ipc_op_prefix_decode((const uint8_t *)reply, &request_id, &status,
	    &flags);
	ATF_CHECK_EQ(status, IPC_ERR_NONE);
	ATF_CHECK_EQ(0, memcmp(reply + IPC_OP_PREFIX_SIZE + 2,
	    "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11", 16));

	memset(req, 0, sizeof(req));
	ipc_op_prefix_encode(req, 0x73000006u, 0, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE, IPC_SECURITY_OOB_INJECT_SC);
	memcpy(req + IPC_OP_PREFIX_SIZE + 5, &addr, sizeof(addr));
	memset(req + IPC_OP_PREFIX_SIZE + 12, 0x44, 16);
	memset(req + IPC_OP_PREFIX_SIZE + 28, 0x55, 16);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_SECURITY, req,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_OOB_SC_REQ_SIZE);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv(sp[1], &type, &domain, reply, sizeof(reply));
	ATF_REQUIRE(plen >= IPC_OP_PREFIX_SIZE);
	ipc_op_prefix_decode((const uint8_t *)reply, &request_id, &status,
	    &flags);
	ATF_CHECK_EQ(status, IPC_ERR_NONE);
	ATF_REQUIRE(blued_oob_take((const uint8_t *)&addr, &legacy_oob,
	    &has_legacy, &sc_oob, &has_sc));
	ATF_CHECK(!has_legacy);
	ATF_CHECK(has_sc);
	for (size_t i = 0; i < 16; i++) {
		ATF_CHECK_EQ(0x44, sc_oob.confirm[i]);
		ATF_CHECK_EQ(0x55, sc_oob.random[i]);
		ATF_CHECK_EQ(0x22, sc_oob.local_random[i]);
	}

	LIST_REMOVE(client, entries);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

static void
expect_correlated_gap_error(struct blued_ctl_client *client, int peer,
    const uint8_t *req, size_t reqlen, uint32_t expected_id,
    uint16_t expected_status)
{
	char reply[128];
	uint32_t request_id;
	uint16_t type, domain, status, flags;
	size_t plen;

	ipc_send_raw(peer, IPC_T_OP_REQ, IPC_OP_DOMAIN_GAP, req, reqlen);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv(peer, &type, &domain, reply, sizeof(reply));
	ATF_REQUIRE(plen >= IPC_OP_PREFIX_SIZE);
	ATF_CHECK_EQ(type, IPC_T_OP_REPLY);
	ATF_CHECK_EQ(domain, IPC_OP_DOMAIN_GAP);
	ipc_op_prefix_decode((const uint8_t *)reply, &request_id, &status,
	    &flags);
	ATF_CHECK_EQ(request_id, expected_id);
	ATF_CHECK_EQ(status, expected_status);
	ATF_CHECK_EQ(flags, 0);
}

ATF_TC_WITHOUT_HEAD(test_ipc_correlated_gap_disconnect);
ATF_TC_BODY(test_ipc_correlated_gap_disconnect, tc)
{
	struct blued_ctl_client *client;
	const uint8_t address[6] = { 1, 2, 3, 4, 5, 6 };
	char feat[128];
	uint8_t req[IPC_OP_PREFIX_SIZE + IPC_GAP_SCAN_REQ_SIZE];
	int sp[2];

	test_init();
	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    0, feat, sizeof(feat));
	ipc_op_prefix_encode(req, 0x11223344u, 0, 0);
	ipc_gap_req_encode(req + IPC_OP_PREFIX_SIZE, IPC_GAP_DISCONNECT, 0,
	    1, address, 0);
	expect_correlated_gap_error(client, sp[1], req,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_REQ_SIZE, 0x11223344u,
	    IPC_ERR_NOT_FOUND);

	ipc_op_prefix_encode(req, 0x11223345u, 0, 0);
	ipc_gap_req_encode(req + IPC_OP_PREFIX_SIZE, IPC_GAP_SET_PHY, 0, 1,
	    address, 0);
	req[IPC_OP_PREFIX_SIZE + 12] = 1;
	req[IPC_OP_PREFIX_SIZE + 13] = 2;
	expect_correlated_gap_error(client, sp[1], req,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_PHY_REQ_SIZE, 0x11223345u,
	    IPC_ERR_NOT_FOUND);

	ipc_op_prefix_encode(req, 0x11223346u, 0, 0);
	ipc_gap_req_encode(req + IPC_OP_PREFIX_SIZE, IPC_GAP_SET_DATA_LEN, 0, 1,
	    address, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 12, 0x00fb);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 14, 0x4290);
	expect_correlated_gap_error(client, sp[1], req,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_DATA_LEN_REQ_SIZE, 0x11223346u,
	    IPC_ERR_NOT_FOUND);

	ipc_op_prefix_encode(req, 0x11223347u, 0, 0);
	ipc_gap_req_encode(req + IPC_OP_PREFIX_SIZE, IPC_GAP_CONN_UPDATE, 0, 1,
	    address, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 12, 6);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 14, 12);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 16, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 18, 200);
	expect_correlated_gap_error(client, sp[1], req,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_CONN_UPDATE_REQ_SIZE, 0x11223347u,
	    IPC_ERR_NOT_FOUND);

	ipc_op_prefix_encode(req, 0x11223348u, 0, 0);
	ipc_gap_req_encode(req + IPC_OP_PREFIX_SIZE, IPC_GAP_CONNECT,
	    IPC_GAP_F_CONN_PARAMS | IPC_GAP_F_PHY, 1, address, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 12, 6);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 14, 12);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 16, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 18, 200);
	req[IPC_OP_PREFIX_SIZE + 20] = 1;
	req[IPC_OP_PREFIX_SIZE + 21] = 2;
	expect_correlated_gap_error(client, sp[1], req,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECT_REQ_SIZE, 0x11223348u,
	    IPC_ERR_NOT_FOUND);

	memset(req, 0, sizeof(req));
	ipc_op_prefix_encode(req, 0x11223349u, 0, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE, IPC_GAP_SCAN);
	req[IPC_OP_PREFIX_SIZE + 10] = (uint8_t)INT8_MIN;
	expect_correlated_gap_error(client, sp[1], req,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_SCAN_REQ_SIZE, 0x11223349u,
	    IPC_ERR_NOT_FOUND);

	LIST_REMOVE(client, entries);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_ipc_typed_control_runtime_settings);
ATF_TC_BODY(test_ipc_typed_control_runtime_settings, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp, adp2;
	char feat[128], pl[IPC_CTL_REPLY_SIZE + 1];
	uint16_t opcode, flags;
	uint32_t request_id, value;
	size_t plen;
	int sp[2];
	static const struct {
		uint16_t opcode, flags;
		uint32_t arg0, arg1;
	} lifecycle[] = {
		{ IPC_CTL_POWER, IPC_CTL_F_BOOL, 1, 0 },
		{ IPC_CTL_PRIVACY, IPC_CTL_F_BOOL, 1, 0 },
		{ IPC_CTL_GATT_BEGIN, 0, 0, 0 },
		{ IPC_CTL_GATT_ROLLBACK, 0, 0, 0 },
		{ IPC_CTL_GATT_BEGIN, 0, 0, 0 },
		{ IPC_CTL_GATT_COMMIT, 0, 0, 0 },
	};

	test_init();
	build_ctl_test_db();
	adap_cap_reset();
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.powered = true;
	adp.hci_fd = 40;
	memset(&adp2, 0, sizeof(adp2));
	adp2.index = 1;
	adp2.active = true;
	adp2.powered = true;
	adp2.hci_fd = 41;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp2, entries);
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	memset(&privacy_cap, 0, sizeof(privacy_cap));
	privacy_cap.fail_fd = INT_MIN;
	blued_g.periph_active = true;
	atomic_store(&blued_pairable, true);

	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS, feat, sizeof(feat));

	for (size_t i = 0; i < nitems(lifecycle); i++) {
		request_id = ipc_send_ctl_operation(sp[1], lifecycle[i].opcode,
		    lifecycle[i].flags, lifecycle[i].arg0, lifecycle[i].arg1);
		ATF_REQUIRE_EQ(0, blued_ctl_dispatch(client));
		plen = ipc_recv_operation(sp[1], IPC_OP_DOMAIN_CTL, request_id,
		    IPC_ERR_NONE, pl, sizeof(pl));
		ATF_REQUIRE_EQ(IPC_CTL_REPLY_SIZE, plen);
		ipc_ctl_reply_decode((const uint8_t *)pl, &opcode, &flags, &value);
		ATF_CHECK_EQ(lifecycle[i].opcode, opcode);
	}
	ATF_CHECK(adp.powered);
	ATF_CHECK(adp.privacy);
	ATF_CHECK(adp2.privacy);
	ATF_CHECK(blued_cfg.privacy);
	ATF_CHECK_EQ(2, privacy_cap.calls);
	ATF_CHECK_EQ(1, privacy_cap.l2cap_calls);
	ATF_CHECK_EQ(0x03, privacy_cap.l2cap_type);

	/* Transaction and controller failures retain precise error taxonomy. */
	expect_typed_ctl_error(client, sp[1], IPC_CTL_GATT_COMMIT, 0, 0, 0,
	    IPC_ERR_NOT_FOUND);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_GATT_ROLLBACK, 0, 0, 0,
	    IPC_ERR_NOT_FOUND);
	adap_cap.power_rc = -1;
	expect_typed_ctl_error(client, sp[1], IPC_CTL_POWER, IPC_CTL_F_BOOL,
	    0, 0, IPC_ERR_IO);
	adap_cap.power_rc = 0;
	adap_cap.disc_rc = -1;
	expect_typed_ctl_error(client, sp[1], IPC_CTL_DISCOVERABLE,
	    IPC_CTL_F_BOOL, 0, 0, IPC_ERR_IO);
	adap_cap.disc_rc = 0;
	/* Adapter 1 failure rolls adapter 0 back and does not publish globals. */
	privacy_cap.calls = 0;
	privacy_cap.l2cap_calls = 0;
	privacy_cap.fail_fd = 41;
	expect_typed_ctl_error(client, sp[1], IPC_CTL_PRIVACY,
	    IPC_CTL_F_BOOL, 0, 0, IPC_ERR_IO);
	ATF_CHECK(blued_cfg.privacy);
	ATF_CHECK(adp.privacy);
	ATF_CHECK(adp2.privacy);
	ATF_CHECK_EQ(0, privacy_cap.l2cap_calls);
	ATF_CHECK_EQ(3, privacy_cap.calls);
	ATF_CHECK_EQ(40, privacy_cap.fd[0]);
	ATF_CHECK_EQ(41, privacy_cap.fd[1]);
	ATF_CHECK_EQ(40, privacy_cap.fd[2]);
	ATF_CHECK(privacy_cap.on[2]);
	privacy_cap.fail_fd = INT_MIN;
	test_hci_rpa_timeout_rc = -1;
	expect_typed_ctl_error(client, sp[1], IPC_CTL_RPA_TIMEOUT, 0,
	    900, 0, IPC_ERR_IO);
	test_hci_rpa_timeout_rc = 0;
	adp.adv_configured = true;
	adp.adv_use_extended = true;
	test_hci_ext_adv_enable_rc = -1;
	expect_typed_ctl_error(client, sp[1], IPC_CTL_ADVERTISE,
	    IPC_CTL_F_BOOL, 1, 0, IPC_ERR_IO);
	test_hci_ext_adv_enable_rc = 0;
	adp.adv_configured = false;
	adp.le_features = 0;
	test_hci_adv_enable_rc = -1;
	expect_typed_ctl_error(client, sp[1], IPC_CTL_ADVERTISE,
	    IPC_CTL_F_BOOL, 1, 0, IPC_ERR_IO);
	test_hci_adv_enable_rc = 0;
	blued_g.periph_active = false;
	expect_typed_ctl_error(client, sp[1], IPC_CTL_ADVERTISE,
	    IPC_CTL_F_BOOL, 1, 0, IPC_ERR_PERM);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_DISCOVERABLE,
	    IPC_CTL_F_BOOL, 1, 0, IPC_ERR_PERM);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_DISCOVERABLE,
	    IPC_CTL_F_BOOL | 0x8000, 1, 30, IPC_ERR_INVAL);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_DISCOVERABLE,
	    IPC_CTL_F_BOOL | IPC_CTL_F_LIMITED, 0, 0, IPC_ERR_INVAL);
	blued_g.periph_active = true;
	expect_typed_ctl_error(client, sp[1], IPC_CTL_POWER,
	    IPC_CTL_F_BOOL | IPC_CTL_F_ADAPTER, 1, UINT32_MAX, IPC_ERR_INVAL);
	LIST_REMOVE(&adp, entries);
	LIST_REMOVE(&adp2, entries);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_POWER, IPC_CTL_F_BOOL,
	    1, 0, IPC_ERR_NOT_FOUND);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_PRIVACY, IPC_CTL_F_BOOL,
	    1, 0, IPC_ERR_NOT_FOUND);
	expect_typed_ctl_error(client, sp[1], IPC_CTL_RPA_TIMEOUT, 0,
	    900, 0, IPC_ERR_NOT_FOUND);
	LIST_INSERT_HEAD(&blued_g.adapters, &adp2, entries);
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	expect_typed_ctl_error(client, sp[1], 0xffff, 0, 0, 0,
	    IPC_ERR_UNKNOWN_CMD);

	request_id = ipc_send_ctl_operation(sp[1], IPC_CTL_ADVERTISE,
	    IPC_CTL_F_BOOL, 1, 0);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv_operation(sp[1], IPC_OP_DOMAIN_CTL, request_id,
	    IPC_ERR_NONE, pl, sizeof(pl));
	ATF_REQUIRE_EQ(plen, IPC_CTL_REPLY_SIZE);
	ipc_ctl_reply_decode((const uint8_t *)pl, &opcode, &flags, &value);
	ATF_CHECK_EQ(opcode, IPC_CTL_ADVERTISE);
	ATF_CHECK_EQ(flags, IPC_CTL_F_BOOL);
	ATF_CHECK_EQ(value, 1);

	request_id = ipc_send_ctl_operation(sp[1], IPC_CTL_DISCOVERABLE,
	    IPC_CTL_F_BOOL | IPC_CTL_F_LIMITED, 1, 45);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv_operation(sp[1], IPC_OP_DOMAIN_CTL, request_id,
	    IPC_ERR_NONE, pl, sizeof(pl));
	ATF_REQUIRE_EQ(plen, IPC_CTL_REPLY_SIZE);
	ipc_ctl_reply_decode((const uint8_t *)pl, &opcode, &flags, &value);
	ATF_CHECK_EQ(opcode, IPC_CTL_DISCOVERABLE);
	ATF_CHECK_EQ(flags, IPC_CTL_F_BOOL | IPC_CTL_F_LIMITED);
	ATF_CHECK_EQ(value, 1);
	ATF_CHECK_EQ(adap_cap.disc_calls, 2);
	ATF_CHECK(adap_cap.disc_enable);
	ATF_CHECK(adap_cap.disc_limited);
	ATF_CHECK_EQ(adap_cap.disc_timeout, 45);

	request_id = ipc_send_ctl_operation(sp[1], IPC_CTL_PAIRABLE,
	    IPC_CTL_F_BOOL, 0, 0);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv_operation(sp[1], IPC_OP_DOMAIN_CTL, request_id,
	    IPC_ERR_NONE, pl, sizeof(pl));
	ATF_REQUIRE_EQ(plen, IPC_CTL_REPLY_SIZE);
	ipc_ctl_reply_decode((const uint8_t *)pl, &opcode, &flags, &value);
	ATF_CHECK_EQ(opcode, IPC_CTL_PAIRABLE);
	ATF_CHECK_EQ(flags, IPC_CTL_F_BOOL);
	ATF_CHECK_EQ(value, 0);
	ATF_CHECK(!atomic_load(&blued_pairable));

	request_id = ipc_send_ctl_operation(sp[1], IPC_CTL_RPA_TIMEOUT, 0,
	    900, 0);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv_operation(sp[1], IPC_OP_DOMAIN_CTL, request_id,
	    IPC_ERR_NONE, pl, sizeof(pl));
	ATF_REQUIRE_EQ(plen, IPC_CTL_REPLY_SIZE);
	ipc_ctl_reply_decode((const uint8_t *)pl, &opcode, &flags, &value);
	ATF_CHECK_EQ(opcode, IPC_CTL_RPA_TIMEOUT);
	ATF_CHECK_EQ(flags, 0);
	ATF_CHECK_EQ(value, 900);
	ATF_CHECK_EQ(blued_cfg.rpa_timeout, 900);

	LIST_REMOVE(client, entries);
	LIST_REMOVE(&adp, entries);
	LIST_REMOVE(&adp2, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/*
 * Capability broker (fd-passing) — ACQUIRE_COC / ACQUIRE_ISO.
 *
 * These drive the broker operations over the framed protocol and assert the
 * security envelope: only a privileged, fd-passing client is handed a data
 * socket, and the handed fd is capability-limited (CAP_SEND|CAP_RECV|CAP_EVENT)
 * per blued_ctl_send_fd.
 */

/*
 * Read one framed reply into pl and, when the daemon's fd handout follows,
 * receive the SCM_RIGHTS descriptor via recvmsg.  Returns the received fd, or
 * -1 if no fd was delivered.
 */
static int
broker_recv_fd(int fd)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(sizeof(int))];
	char byte;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	int recv_fd = -1;

	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(cbuf, 0, sizeof(cbuf));
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	if (recvmsg(fd, &msg, 0) < 1)
		return (-1);
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg != NULL && cmsg->cmsg_level == SOL_SOCKET &&
	    cmsg->cmsg_type == SCM_RIGHTS)
		memcpy(&recv_fd, CMSG_DATA(cmsg), sizeof(int));
	return (recv_fd);
}

/* A privileged fd-passing client receives a real, cap-limited CoC socket. */
ATF_TC_WITHOUT_HEAD(test_ctl_acquire_coc_typed);
ATF_TC_BODY(test_ctl_acquire_coc_typed, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	uint8_t req[IPC_OP_PREFIX_SIZE + IPC_L2CAP_REQ_SIZE];
	uint8_t reply[IPC_MAX_PAYLOAD + 1];
	char feat[128];
	uint32_t request_id;
	uint16_t type, domain, status, flags;
	size_t plen;
	int channel[2], recv_fd, sp[2];

	test_init();
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.powered = true;
	adp.hci_fd = 42;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_FDPASS,
	    feat, sizeof(feat));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, channel) == 0);
	mock_broker_fds[0] = channel[1];
	mock_broker_navail = 1;

	memset(req, 0, sizeof(req));
	request_id = 0x74000001u;
	ipc_op_prefix_encode(req, request_id, 0, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE, IPC_L2CAP_ACQUIRE_COC);
	req[IPC_OP_PREFIX_SIZE + 11] = 1;
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 12, 0x0081);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_L2CAP, req,
	    sizeof(req));
	ATF_REQUIRE_EQ(0, blued_ctl_dispatch(client));
	plen = ipc_recv(sp[1], &type, &domain, (char *)reply, sizeof(reply));
	ATF_REQUIRE_EQ(IPC_T_OP_REPLY, type);
	ATF_REQUIRE_EQ(IPC_OP_DOMAIN_L2CAP, domain);
	ATF_REQUIRE_EQ_MSG(IPC_OP_PREFIX_SIZE + IPC_L2CAP_ACQUIRE_REPLY_SIZE,
	    plen, "unexpected L2CAP acquire reply length %zu", plen);
	ipc_op_prefix_decode(reply, &request_id, &status, &flags);
	ATF_CHECK_EQ(IPC_ERR_NONE, status);
	ATF_CHECK_EQ(IPC_L2CAP_ACQUIRE_COC,
	    ipc_get_le16(reply + IPC_OP_PREFIX_SIZE));
	ATF_CHECK_EQ(1, reply[IPC_OP_PREFIX_SIZE + 2]);
	recv_fd = broker_recv_fd(sp[1]);
	ATF_REQUIRE(recv_fd >= 0);

	close(recv_fd);
	close(channel[0]);
	mock_broker_navail = 0;
	LIST_REMOVE(client, entries);
	LIST_REMOVE(&adp, entries);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/* A privileged client that did NOT negotiate fd-passing is denied. */
/* An unprivileged fd-passing client is denied the broker handout. */
/* A privileged fd-passing client acquires an ISO socket for a live handle. */
/* ================================================================
 * Per-characteristic GATT data-path acquire — ACQUIRE_NOTIFY / ACQUIRE_WRITE
 * (the common GATT-characteristic AcquireNotify/AcquireWrite pattern; Core Spec Vol 3
 * Part G notify/write).  A privileged fd-passing client is handed a direct,
 * capability-scoped SEQPACKET fd: notification VALUES flow daemon->client as
 * one datagram each, and the client's writes become ATT Write PDUs to the
 * characteristic.  The suite asserts the fd/MTU handout, notification-to-fd
 * routing (right characteristic only), write-fd-to-ATT-PDU, the fd-passing +
 * privilege gate, single-acquire enforcement, and teardown on every path.
 * ================================================================ */

/* The fixed peer address every acquire test connects to. */
#define ACQ_ADDR "11:22:33:44:55:66"

/*
 * Stand up a privileged fd-passing client plus a connected peer whose ATT
 * bearer's primary fd is one end of a socketpair; the test reads emitted ATT
 * PDUs from *att_peer_out.  blued_g.kq is a live kqueue so the acquire fd can
 * be registered.  Returns the client (freed by the caller together with the
 * conn/att teardown).
 */
static struct blued_ctl_client *
acq_setup(int sp[2], struct blued_conn **conn_out, struct att_conn *att,
    int att_pair[2], uint16_t mtu)
{
	struct blued_ctl_client *client;
	char feat[128];
	bdaddr_t addr;

	if (blued_g.kq < 0)
		blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);

	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_FDPASS,
	    feat, sizeof(feat));
	client->peer_known = true;
	client->peer_uid = 0;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, att_pair) == 0);
	memset(att, 0, sizeof(*att));
	att->fd = att_pair[0];
	att->mtu = mtu;

	*conn_out = blued_conn_alloc();
	ATF_REQUIRE(*conn_out != NULL);
	ATF_REQUIRE(bt_aton(ACQ_ADDR, &addr));
	memcpy(&(*conn_out)->dst, &addr, sizeof((*conn_out)->dst));
	(*conn_out)->addr_type = BDADDR_LE_PUBLIC;
	(*conn_out)->att = att;
	return (client);
}

/* daemon-side fd of the (only) active acquire, or -1. */
static int
acq_count(void)
{
	struct ctl_acquire *acq;
	int n = 0;

	LIST_FOREACH(acq, &blued_g.ctl_acquires, entries)
		n++;
	return (n);
}

/* ACQUIRE_NOTIFY hands a cap-limited fd carrying the negotiated MTU. */
ATF_TC_WITHOUT_HEAD(test_ctl_acquire_notify_typed);
ATF_TC_BODY(test_ctl_acquire_notify_typed, tc)
{
	struct blued_ctl_client *client;
	struct blued_conn *conn;
	struct att_conn att;
	bdaddr_t addr;
	uint8_t req[IPC_OP_PREFIX_SIZE + IPC_GATT_REQ_SIZE];
	uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_GATT_ACQUIRE_REPLY_SIZE + 1];
	uint32_t request_id;
	uint16_t type, domain, status, flags;
	size_t plen;
	int sp[2], att_pair[2], recv_fd;

	test_init();
	client = acq_setup(sp, &conn, &att, att_pair, 185);
	ATF_REQUIRE(bt_aton(ACQ_ADDR, &addr));
	memset(req, 0, sizeof(req));
	ipc_op_prefix_encode(req, 0x72000001u, 0, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE, IPC_GATT_ACQUIRE_NOTIFY);
	memcpy(req + IPC_OP_PREFIX_SIZE + 5, &addr, sizeof(addr));
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 12, 0x0010);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_GATT, req, sizeof(req));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	plen = ipc_recv(sp[1], &type, &domain, reply, sizeof(reply));
	ATF_REQUIRE_EQ(type, IPC_T_OP_REPLY);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GATT);
	ATF_REQUIRE_EQ(plen,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_ACQUIRE_REPLY_SIZE);
	ipc_op_prefix_decode(reply, &request_id, &status, &flags);
	ATF_CHECK_EQ(request_id, 0x72000001u);
	ATF_CHECK_EQ(status, IPC_ERR_NONE);
	ATF_CHECK_EQ(flags, 0);
	ATF_CHECK_EQ(ipc_get_le16(reply + IPC_OP_PREFIX_SIZE),
	    IPC_GATT_ACQUIRE_NOTIFY);
	ATF_CHECK_EQ(ipc_get_le16(reply + IPC_OP_PREFIX_SIZE + 2), 185);
	recv_fd = broker_recv_fd(sp[1]);
	ATF_REQUIRE(recv_fd >= 0);
	ATF_CHECK_EQ(acq_count(), 1);

	close(recv_fd);
	conn->att = NULL;
	blued_conn_free(conn);
	close(att_pair[0]);
	close(att_pair[1]);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_ctl_acquire_notify_tx_full_no_leak);
ATF_TC_BODY(test_ctl_acquire_notify_tx_full_no_leak, tc)
{
	struct blued_ctl_client *client;
	struct blued_conn *conn;
	struct att_conn att;
	bdaddr_t addr;
	uint8_t req[IPC_OP_PREFIX_SIZE + IPC_GATT_REQ_SIZE];
	int sp[2], att_pair[2];

	test_init();
	client = acq_setup(sp, &conn, &att, att_pair, 185);
	ATF_REQUIRE(bt_aton(ACQ_ADDR, &addr));
	client->tx_queued = BLUED_CTL_TX_MAX;

	memset(req, 0, sizeof(req));
	ipc_op_prefix_encode(req, 0x72000011u, 0, 0);
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE, IPC_GATT_ACQUIRE_NOTIFY);
	memcpy(req + IPC_OP_PREFIX_SIZE + 5, &addr, sizeof(addr));
	ipc_put_le16(req + IPC_OP_PREFIX_SIZE + 12, 0x0010);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_GATT, req,
	    sizeof(req));

	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	ATF_CHECK_EQ_MSG(acq_count(), 0,
	    "failed fd handout must not leave a daemon-side acquire");

	conn->att = NULL;
	blued_conn_free(conn);
	blued_ctl_client_fini(client);
	close(att_pair[0]);
	close(att_pair[1]);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_ctl_acquire_data_and_teardown_matrix);
ATF_TC_BODY(test_ctl_acquire_data_and_teardown_matrix, tc)
{
	struct blued_adapter adp;
	struct blued_conn *conn;
	struct blued_ctl_client owner, other;
	struct ctl_acquire *acq;
	struct att_conn att;
	struct kevent ev;
	bdaddr_t addr;
	uint8_t value[] = { 0x11, 0x22, 0x33, 0x44 };
	uint8_t pdu[32];
	int data[2], attfd[2];
	ssize_t n;

	test_init();
	memset(&adp, 0, sizeof(adp));
	adp.active = true;
	adp.powered = true;
	adp.index = 0;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	ATF_REQUIRE(bt_aton(ACQ_ADDR, &addr));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, attfd));
	memset(&att, 0, sizeof(att));
	att.fd = attfd[0];
	att.mtu = 7;                 /* write payload cap is four octets */
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->adapter = &adp;
	conn->dst = addr;
	conn->addr_type = 1;
	conn->att = &att;
	memset(&owner, 0, sizeof(owner));
	memset(&other, 0, sizeof(other));

	/* Unknown kqueue identifiers are ignored. */
	memset(&ev, 0, sizeof(ev));
	ev.ident = 0x7fffffff;
	ctl_acquire_dispatch(&ev);

	/* A NOTIFY acquire routes matching values and drains client writes. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, data));
	acq = calloc(1, sizeof(*acq));
	ATF_REQUIRE(acq != NULL);
	acq->daemon_fd = data[0]; acq->client = &owner;
	acq->addr = addr; acq->adapter_index = 0;
	acq->addr_type = BDADDR_LE_PUBLIC;
	acq->handle = 0x20; acq->dir = CTL_ACQ_NOTIFY; acq->mtu = 7;
	LIST_INSERT_HEAD(&blued_g.ctl_acquires, acq, entries);
	blued_ctl_notify_value(conn, 0x20, value, sizeof(value), 23);
	ATF_REQUIRE_EQ((ssize_t)sizeof(value), recv(data[1], pdu, sizeof(pdu), 0));
	ATF_CHECK_EQ(0, memcmp(pdu, value, sizeof(value)));
	ATF_REQUIRE_EQ((ssize_t)sizeof(value),
	    send(data[1], value, sizeof(value), 0));
	ev.ident = data[0]; ev.flags = 0;
	ctl_acquire_dispatch(&ev);   /* NOTIFY direction discards client data */
	ev.flags = EV_EOF;
	ctl_acquire_dispatch(&ev);
	ATF_CHECK(LIST_EMPTY(&blued_g.ctl_acquires));
	close(data[1]);

	/* WRITE acquire turns one datagram into a bounded ATT Write Command. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, data));
	acq = calloc(1, sizeof(*acq));
	ATF_REQUIRE(acq != NULL);
	acq->daemon_fd = data[0]; acq->client = &owner;
	acq->addr = addr; acq->adapter_index = 0;
	acq->addr_type = BDADDR_LE_PUBLIC;
	acq->handle = 0x1234; acq->dir = CTL_ACQ_WRITE; acq->mtu = 7;
	LIST_INSERT_HEAD(&blued_g.ctl_acquires, acq, entries);
	ATF_REQUIRE_EQ((ssize_t)sizeof(value),
	    send(data[1], value, sizeof(value), 0));
	ev.ident = data[0]; ev.flags = 0;
	ctl_acquire_dispatch(&ev);
	n = recv(attfd[1], pdu, sizeof(pdu), 0);
	ATF_REQUIRE(n >= 3);
	ATF_CHECK_EQ(ATT_OP_WRITE_CMD, pdu[0]);
	ATF_CHECK_EQ(0x34, pdu[1]);
	ATF_CHECK_EQ(0x12, pdu[2]);

	/* Nonmatching client teardown preserves it; owner teardown removes it. */
	ctl_acquire_client_gone(&other);
	ATF_CHECK(!LIST_EMPTY(&blued_g.ctl_acquires));
	ctl_acquire_client_gone(&owner);
	ATF_CHECK(LIST_EMPTY(&blued_g.ctl_acquires));
	close(data[1]);

	/* Peer-disconnect matching and nonmatching arms. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, data));
	acq = calloc(1, sizeof(*acq));
	ATF_REQUIRE(acq != NULL);
	acq->daemon_fd = data[0]; acq->client = &owner;
	acq->addr = addr; acq->adapter_index = 0;
	acq->addr_type = BDADDR_LE_PUBLIC;
	LIST_INSERT_HEAD(&blued_g.ctl_acquires, acq, entries);
	conn->addr_type = BDADDR_LE_RANDOM;
	ctl_acquire_conn_gone(conn);
	ATF_CHECK(!LIST_EMPTY(&blued_g.ctl_acquires));
	conn->addr_type = BDADDR_LE_PUBLIC;
	ctl_acquire_conn_gone(conn);
	ATF_CHECK(LIST_EMPTY(&blued_g.ctl_acquires));
	close(data[1]);

	conn->att = NULL;
	blued_conn_free(conn);
	LIST_REMOVE(&adp, entries);
	close(attfd[0]);
	close(attfd[1]);
}

/* A peer notification arrives as one SEQPACKET datagram on the acquired fd,
 * and only for the acquired characteristic (no cross-char delivery). */
/* A client write on the ACQUIRE_WRITE fd becomes an ATT Write PDU to the char,
 * bounded to the negotiated MTU (payload <= mtu-3). */
/* The fd-passing + privilege gate: a client missing either is denied with
 * IPC_ERR_PERM before any socketpair is created. */
/* Only one acquire per (conn, char, direction); a second is rejected. */
/* Teardown frees the socketpair and unroutes on every path: client-close
 * (EV_EOF), explicit client-gone, and peer-disconnect. */
/* ================================================================
 * Advertising / connection parameter operations.
 *
 * These assert that each operation decodes its typed payload and calls the HCI
 * seam with the correctly mapped parameters (captured in advconn_cap), and
 * that out-of-range / malformed inputs are rejected before any HCI call.
 * ================================================================ */

/* Insert an active adapter with the given LE features; returns via *adp. */
/* Create a live connection (con_handle set) bound to adp; caller frees. */
static struct blued_conn *
path_loss_conn_setup(struct blued_adapter *adp, const char *addr,
    uint64_t features, uint16_t handle)
{
	struct blued_conn *conn;

	test_init();
	memset(adp, 0, sizeof(*adp));
	adp->index = 0;
	adp->hci_fd = 17;
	adp->active = true;
	adp->powered = true;
	adp->le_features = features;
	LIST_INSERT_HEAD(&blued_g.adapters, adp, entries);
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	ATF_REQUIRE(bt_aton(addr, &conn->dst));
	conn->addr_type = 1;
	conn->con_handle = handle;
	conn->con_handle_valid = true;
	conn->adapter = adp;
	memset(&pathloss_cap, 0, sizeof(pathloss_cap));
	return (conn);
}

static void
path_loss_conn_cleanup(struct blued_adapter *adp, struct blued_conn *conn)
{

	blued_conn_free(conn);
	LIST_REMOVE(adp, entries);
}

ATF_TC_WITHOUT_HEAD(test_ctl_path_loss_success);
ATF_TC_BODY(test_ctl_path_loss_success, tc)
{
	struct blued_adapter adp;
	struct blued_conn *conn;

	conn = path_loss_conn_setup(&adp, "11:22:33:44:55:66",
	    LE_FEAT_PATH_LOSS_MONITORING, 0x0000);
	ATF_CHECK_EQ(ctl_path_loss_result(0, &conn->dst, 1, 0x20, 0x02,
	    0x60, 0x04, 0x1234, true), IPC_ERR_NONE);
	ATF_CHECK_EQ(pathloss_cap.params_calls, 1);
	ATF_CHECK_EQ(pathloss_cap.enable_calls, 1);
	ATF_CHECK_EQ(pathloss_cap.handle, 0x0000);
	ATF_CHECK_EQ(pathloss_cap.high, 0x60);
	ATF_CHECK_EQ(pathloss_cap.high_hyst, 0x04);
	ATF_CHECK_EQ(pathloss_cap.low, 0x20);
	ATF_CHECK_EQ(pathloss_cap.low_hyst, 0x02);
	ATF_CHECK_EQ(pathloss_cap.min_time, 0x1234);
	ATF_CHECK_EQ(pathloss_cap.enable, 1);
	path_loss_conn_cleanup(&adp, conn);
}

ATF_TC_WITHOUT_HEAD(test_ctl_path_loss_validation_and_capability);
ATF_TC_BODY(test_ctl_path_loss_validation_and_capability, tc)
{
	struct blued_adapter adp;
	struct blued_conn *conn;
	bdaddr_t missing;

	conn = path_loss_conn_setup(&adp, "11:22:33:44:55:66", 0, 0x0040);
	ATF_CHECK_EQ(ctl_path_loss_result(0, &conn->dst, 1, 0x61, 0,
	    0x60, 0, 1, true), IPC_ERR_INVAL);
	ATF_CHECK_EQ(pathloss_cap.params_calls, 0);
	ATF_CHECK_EQ(ctl_path_loss_result(0, &conn->dst, 1, 0x20, 0,
	    0x60, 0, 1, true), IPC_ERR_NOT_FOUND);
	ATF_CHECK_EQ(pathloss_cap.params_calls, 0);
	ATF_REQUIRE(bt_aton("aa:bb:cc:dd:ee:ff", &missing));
	ATF_CHECK_EQ(ctl_path_loss_result(0, &missing, 1, 0x20, 0,
	    0x60, 0, 1, true), IPC_ERR_NOT_FOUND);
	ATF_CHECK_EQ(pathloss_cap.params_calls, 0);
	path_loss_conn_cleanup(&adp, conn);
}

ATF_TC_WITHOUT_HEAD(test_ctl_path_loss_hci_failures);
ATF_TC_BODY(test_ctl_path_loss_hci_failures, tc)
{
	struct blued_adapter adp;
	struct blued_conn *conn;

	conn = path_loss_conn_setup(&adp, "11:22:33:44:55:66",
	    LE_FEAT_PATH_LOSS_MONITORING, 0x0040);
	pathloss_cap.params_rc = -1;
	ATF_CHECK_EQ(ctl_path_loss_result(0, &conn->dst, 1, 0x20, 0,
	    0x60, 0, 1, true), IPC_ERR_IO);
	ATF_CHECK_EQ(pathloss_cap.params_calls, 1);
	ATF_CHECK_EQ(pathloss_cap.enable_calls, 0);

	memset(&pathloss_cap, 0, sizeof(pathloss_cap));
	pathloss_cap.enable_rc = -1;
	ATF_CHECK_EQ(ctl_path_loss_result(0, &conn->dst, 1, 0x20, 0,
	    0x60, 0, 1, false), IPC_ERR_IO);
	ATF_CHECK_EQ(pathloss_cap.params_calls, 1);
	ATF_CHECK_EQ(pathloss_cap.enable_calls, 1);
	ATF_CHECK_EQ(pathloss_cap.enable, 0);
	path_loss_conn_cleanup(&adp, conn);
}

/* ================================================================
 * Operator adapter settings: POWER / DISCOVERABLE / PAIRABLE / SET_NAME
 * ================================================================ */
/* ================================================================
 * Runtime pairing agent (the common pairing-agent model)
 * ================================================================ */

/*
 * REGISTER_AGENT requires the push-events feature: a client that never
 * negotiated events could not receive a prompt and would stall the pairing.
 */
/*
 * A registered agent's IO capability overrides the static config for this
 * daemon's pairings; UNREGISTER restores the static fallback.
 */
/* An unrecognised IO-capability keyword is rejected. */
/*
 * A pairing prompt routes to the registered agent alone — a second
 * push-events client that is not the agent never sees it.
 */
/*
 * With no agent registered, routing reports "not delivered" so the caller
 * falls back to the legacy broadcast (unchanged behaviour).
 */
/*
 * The agent's reply drives the SMP responder's passkey input: the reply operation
 * transitions the shared pending state the SMP thread consumes.
 */
/*
 * A disconnecting agent is unregistered so no stale agent strands future
 * pairings: the IO cap falls back to the static default.
 */
/* ================================================================
 * Atomic GATT-application registration (the common GATT-application model)
 * ================================================================ */

/* Compute the current DB hash for before/after comparison. */
/*
 * GATT_BEGIN/ADD.../GATT_COMMIT: staged services are invisible in the live DB
 * until commit, then all appear together; the DB hash changes only at commit.
 */
/* GATT_ROLLBACK discards the staged build; the live DB is unchanged. */
/* A staging error mid-transaction auto-rolls-back; the live DB is untouched. */
/*
 * A second client cannot mutate the DB while another owns an open transaction,
 * and the owner disconnecting frees the transaction so others can proceed.
 */
/* ================================================================
 * Mesh bearer (broker step C): the three privileged operations, the receive-side
 * leak filter, and the always-on-scanner refcount.  These drive the real
 * ctl.c dispatch and assert emitted advertising AD bytes / delivered EVENT
 * MESH_ADV frames (via the capturing mesh HCI seam), never captured text.
 * ================================================================ */

/* Build one non-connectable adv adapter, active, with the given features. */
/* HELLO with mesh-bearer auto-negotiates push-events (EVENT MESH_ADV). */
ATF_TC_WITHOUT_HEAD(test_ctl_mesh_hello_implies_events);
ATF_TC_BODY(test_ctl_mesh_hello_implies_events, tc)
{
	struct blued_ctl_client *client;
	char feat[128];
	int sp[2];

	test_init();
	client = make_client(sp);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_MESH,
	    feat, sizeof(feat));
	ATF_CHECK((ipc_get_le32((const uint8_t *)feat) & IPC_FEATURE_MESH) != 0);
	ATF_CHECK((ipc_get_le32((const uint8_t *)feat) & IPC_FEATURE_EVENTS) != 0);
	ATF_CHECK(client->wants_mesh);
	ATF_CHECK(client->wants_events);

	close(sp[0]);
	close(sp[1]);
	free(client);
}

/*
 * MESH_ADV_SEND validates the AD type (mesh-only) and emits the exact single
 * AD structure [len][adtype][pdu]; a non-mesh adtype / bad hex is rejected and
 * never reaches the radio.
 */
/* MESH_ADV_SEND is denied to an unprivileged peer and to a non-mesh client. */
/*
 * Receive-side leak filter: a report with a mesh AD field (0x2A) plus a
 * non-mesh field (0x09 Complete Local Name) yields exactly one EVENT MESH_ADV
 * to each subscriber (the name is dropped); a non-subscriber gets nothing; a
 * report with only non-mesh AD yields no event at all.
 */
/*
 * A malformed AD length (declared field runs past the buffer) must not
 * over-read and must not emit a bogus event.
 */
ATF_TC_WITHOUT_HEAD(test_ctl_mesh_rx_malformed_ad);
ATF_TC_BODY(test_ctl_mesh_rx_malformed_ad, tc)
{
	struct blued_ctl_client *sub;
	char feat[128];
	int sps[2];
	ssize_t n;
	uint8_t junk[8];
	struct timeval tv = { .tv_sec = 0, .tv_usec = 150000 };
	/* Field claims length 0x20 but only 3 bytes remain. */
	static const uint8_t bad[] = { 0x20, 0x2A, 0xAA };

	test_init();
	sub = make_client(sps);
	ipc_handshake(sub, sps[1], IPC_PROTO_VERSION, IPC_FEATURE_MESH,
	    feat, sizeof(feat));
	sub->mesh_sub = true;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, sub, entries);

	blued_mesh_demux_report(bad, sizeof(bad));

	(void)setsockopt(sps[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	n = recv(sps[1], junk, sizeof(junk), 0);
	ATF_CHECK_MSG(n <= 0,
	    "malformed AD must not emit an event, got %zd bytes", n);

	LIST_REMOVE(sub, entries);
	close(sps[0]); close(sps[1]); free(sub);
}

ATF_TC_WITHOUT_HEAD(test_ctl_mesh_typed_full_matrix);
ATF_TC_BODY(test_ctl_mesh_typed_full_matrix, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter active, inactive;
	uint8_t body[IPC_MESH_ADV_REQ_HDR_SIZE + MESH_ADV_PDU_MAX];
	int sp[2];

	test_init();
	memset(&mesh_cap, 0, sizeof(mesh_cap));
	memset(&active, 0, sizeof(active));
	memset(&inactive, 0, sizeof(inactive));
	active.active = true;
	active.index = 2;
	active.hci_fd = 42;
	inactive.index = 3;
	inactive.hci_fd = 43;
	LIST_INSERT_HEAD(&blued_g.adapters, &inactive, entries);
	LIST_INSERT_HEAD(&blued_g.adapters, &active, entries);
	client = make_client(sp);
	client->peer_uid = 0;

	/* Minimum-size and feature-negotiation guards. */
	memset(body, 0, sizeof(body));
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, 1));
	ipc_put_le16(body, IPC_MESH_SUBSCRIBE);
	ATF_CHECK_EQ(IPC_ERR_PERM, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, IPC_MESH_REQ_SIZE));
	client->wants_mesh = true;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, IPC_MESH_REQ_SIZE + 1));
	/* Mesh negotiation does not confer the privilege needed to transmit or
	 * subscribe.  Keep this distinct from the feature-negotiation denial. */
	client->peer_uid = 1000;
	ATF_CHECK_EQ(IPC_ERR_PERM, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, IPC_MESH_REQ_SIZE));
	client->peer_uid = 0;

	/* Subscribe/unsubscribe are idempotent and drive active adapters only. */
	mesh_cap.scan_rc = -1;
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, IPC_MESH_REQ_SIZE));
	ATF_CHECK(!client->mesh_sub);
	mesh_cap.scan_rc = 0;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, IPC_MESH_REQ_SIZE));
	ATF_CHECK(client->mesh_sub);
	blued_mesh_scan_resume();
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, IPC_MESH_REQ_SIZE));
	ipc_put_le16(body, IPC_MESH_UNSUBSCRIBE);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, IPC_MESH_REQ_SIZE));
	ATF_CHECK(!client->mesh_sub);
	blued_mesh_scan_resume();
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, IPC_MESH_REQ_SIZE));
	ATF_CHECK(mesh_cap.scan_on_calls > 0);
	ATF_CHECK(mesh_cap.scan_off_calls > 0);

	/* Unknown and truncated advertising operations. */
	ipc_put_le16(body, 0xffff);
	ATF_CHECK_EQ(IPC_ERR_UNKNOWN_CMD, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, IPC_MESH_REQ_SIZE));
	ipc_put_le16(body, IPC_MESH_ADV_SEND);
	ATF_CHECK_EQ(IPC_ERR_UNKNOWN_CMD, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, IPC_MESH_ADV_REQ_HDR_SIZE - 1));

	/* Exercise every advertising validation operand. */
	body[2] = 0x2a;
	body[3] = IPC_MESH_ADAPTER_DEFAULT;
	body[4] = 1;
	body[5] = 1;
	body[6] = 0xaa;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, 7));
	body[5] = 0;
	body[4] = 0;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, IPC_MESH_ADV_REQ_HDR_SIZE));
	body[4] = MESH_ADV_PDU_MAX + 1;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, sizeof(body)));
	body[4] = 2;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, 7));
	body[4] = 1;
	body[2] = 0x09;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, 7));

	/* Explicit missing adapter, then default and explicit successes. */
	body[2] = 0x2a;
	body[3] = 99;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, 7));
	/* The default-adapter lookup must also reject an all-inactive set. */
	active.active = false;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, 7));
	active.active = true;
	body[3] = IPC_MESH_ADAPTER_DEFAULT;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, 7));
	ATF_CHECK_EQ(0x2a, mesh_cap.burst_ad[1]);
	ATF_CHECK_EQ(0xaa, mesh_cap.burst_ad[2]);
	body[3] = 2;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, 7));

	/* Controller failure retains a bounded backlog; recovery drains it. */
	mesh_cap.burst_rc = -1;
	for (int i = 0; i < 16; i++)
		ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_MESH, body, 7));
	ATF_CHECK_EQ(IPC_ERR_BUSY, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, 7));
	mesh_cap.burst_rc = 0;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_MESH, body, 7));

	LIST_REMOVE(&active, entries);
	LIST_REMOVE(&inactive, entries);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_ctl_reset_owner_lifecycle);
ATF_TC_BODY(test_ctl_reset_owner_lifecycle, tc)
{

	test_init();
	build_ctl_test_db();
	ATF_REQUIRE(periph_gatt_db.count > 2);
	periph_gatt_db.attrs[0].owner_fd = 77;
	periph_gatt_db.attrs[1].owner_fd = 12;
	periph_gatt_db.attrs[2].owner_fd = 77;
	blued_ctl_reset_owner(77);
	ATF_CHECK_EQ(-1, periph_gatt_db.attrs[0].owner_fd);
	ATF_CHECK_EQ(12, periph_gatt_db.attrs[1].owner_fd);
	ATF_CHECK_EQ(-1, periph_gatt_db.attrs[2].owner_fd);
	/* Repeating the disconnect cleanup is harmless and covers empty arms. */
	blued_ctl_reset_owner(77);
}

/*
 * Scanner refcount: the first subscribe turns the mesh scanner on and it stays
 * on across a client SCAN burst and a second subscriber; only the last
 * unsubscribe turns it off, and it is never left stuck-on.
 */
/*
 * A subscriber that disconnects without unsubscribing releases its scanner
 * refcount (implicit unsubscribe), so the scanner is never left stuck-on.
 */
/*
 * Bounded burst FIFO: while the controller errors, sends back up until the
 * FIFO is full (IPC_ERR_BUSY); once the controller recovers the backlog
 * drains on the next send (no overflow, no wedge).
 */
/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ctl_gatt_result_matrix);
ATF_TC_BODY(test_ctl_gatt_result_matrix, tc)
{
	struct blued_ctl_client client;
	struct blued_conn *notify_conn;
	struct att_conn notify_att;
	bdaddr_t addr;
	uint8_t value[] = { 0x11, 0x22 };
	uint8_t large_value[250] = { 0 };
	uint8_t oversized_value[ATT_PDU_BUF_SIZE + 1] = { 0 };
	uint8_t uuid128[16] = { 1 };
	uint16_t service, committed_service, characteristic, descriptor;
	uint16_t indicate_characteristic;
	uint16_t cccd_handle = 0, service_changed_cccd = 0;
	size_t value_len;
	int capacity_i, error, notify_pair[2], sent;

	test_init();
	build_ctl_test_db();
	memset(&client, 0, sizeof(client));
	memset(&addr, 0, sizeof(addr));

	/* Finding 90: job_conn is the first argument; NULL is the NOT_CONN case. */
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_read_result(NULL, 0, NULL, 0, 1,
	    value, sizeof(value), &value_len));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_read_result(NULL, 0, &addr, 0, 0,
	    value, sizeof(value), &value_len));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_read_result(NULL, 0, &addr, 0, 1,
	    NULL, sizeof(value), &value_len));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_read_result(NULL, 0, &addr, 0, 1,
	    value, sizeof(value), NULL));
	ATF_CHECK_EQ(IPC_ERR_NOT_CONN, ctl_gatt_read_result(NULL, 0, &addr, 0, 1,
	    value, sizeof(value), &value_len));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_write_result(NULL, 0, NULL, 0, 1,
	    value, sizeof(value), false));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_write_result(NULL, 0, &addr, 0, 0,
	    value, sizeof(value), false));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_write_result(NULL, 0, &addr, 0, 1,
	    NULL, 1, false));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_write_result(NULL, 0, &addr, 0, 1,
	    oversized_value, sizeof(oversized_value), false));
	ATF_CHECK_EQ(IPC_ERR_NOT_CONN, ctl_gatt_write_result(NULL, 0, &addr, 0, 1,
	    value, sizeof(value), false));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_discover_result(NULL, 0, NULL, 0,
	    NULL, NULL));

	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_subscribe_result(NULL, -1, 0, 0,
	    NULL, 0, 1, true));

	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_commit_result(10));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_rollback_result(10));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_begin_result(10));
	ATF_CHECK_EQ(IPC_ERR_BUSY, ctl_gatt_begin_result(11));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_commit_result(11));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_service_result(10, 0, NULL,
	    &service));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_service_result(10, 0x1800,
	    NULL, &service));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_service_result(10, 0x1810,
	    NULL, NULL));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(10, 0x1810,
	    NULL, &service));
	committed_service = service;
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_char_result(10, service,
	    0x2a35, NULL, GATT_PROP_READ | GATT_PROP_NOTIFY, ATT_PERM_READ, 0,
	    value, sizeof(value), &characteristic));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_desc_result(10,
	    characteristic, 0x2901, NULL, ATT_PERM_READ, value, sizeof(value),
	    &descriptor));
	ATF_CHECK(descriptor > characteristic);
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_commit_result(10));

	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_set_value_result(10, 0, value,
	    sizeof(value)));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_set_value_result(10, characteristic,
	    NULL, 1));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_set_value_result(10, 0xffff,
	    value, sizeof(value)));
	ATF_CHECK_EQ(IPC_ERR_PERM, ctl_gatt_set_value_result(11, characteristic,
	    value, sizeof(value)));
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_gatt_set_value_result(10, characteristic,
	    value, sizeof(value)));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_char_result(10, service, 0,
	    NULL, 0, 0, 0, NULL, 0, &characteristic));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_char_result(10, service,
	    0x2a36, NULL, 0, 0x80, 0, NULL, 0, &characteristic));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_char_result(10, service,
	    0x2a36, NULL, 0, 0, 0x80, NULL, 0, &characteristic));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_char_result(10, 0, 0x2a36,
	    NULL, GATT_PROP_READ, ATT_PERM_READ, 0, NULL, 0, &characteristic));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_char_result(10, service,
	    0x2a36, NULL, GATT_PROP_READ, ATT_PERM_READ, 0, NULL, 1,
	    &characteristic));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_char_result(10, service,
	    0x2a36, NULL, GATT_PROP_READ, ATT_PERM_READ, 0, NULL, 0, NULL));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_add_char_result(10, 0xffff,
	    0x2a36, NULL, GATT_PROP_READ, ATT_PERM_READ, 0, NULL, 0,
	    &characteristic));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_desc_result(10, 0, 0x2901,
	    NULL, 0, NULL, 0, &descriptor));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_desc_result(10, characteristic,
	    0x2901, NULL, ATT_PERM_READ, NULL, 0, NULL));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_desc_result(10, characteristic,
	    0x2901, NULL, ATT_PERM_READ, NULL, 1, &descriptor));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_add_desc_result(10, 0xffff,
	    0x2901, NULL, 0, NULL, 0, &descriptor));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_include_result(10, 0, 0, 0,
	    0, &descriptor));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_include_result(10, service,
	    service, service, 0, NULL));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_include_result(10, service,
	    (uint16_t)(service + 1), service, 0, &descriptor));

	sent = -1;
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_notify_result(0, value,
	    sizeof(value), false, &sent));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_notify_result(characteristic, NULL,
	    1, false, &sent));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_notify_result(characteristic,
	    oversized_value, sizeof(oversized_value), false, &sent));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_notify_result(0xffff, value,
	    sizeof(value), false, &sent));
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_gatt_notify_result(characteristic, value,
	    sizeof(value), false, &sent));
	ATF_CHECK_EQ(0, sent);
	service = attdb_add_service(&periph_gatt_db, 0x1801);
	ATF_REQUIRE(service != 0);
	descriptor = attdb_add_characteristic(&periph_gatt_db, 0x2A05,
	    GATT_PROP_INDICATE, ATT_PERM_READ, NULL, 0);
	ATF_REQUIRE(descriptor != 0);
	ATF_REQUIRE(attdb_add_cccd(&periph_gatt_db) != 0);

	/* Deliver through an active peripheral ATT bearer with the generated CCCD
	 * enabled.  This covers subscription lookup and the real notify send. */
	for (int i = 0; i < periph_gatt_db.count; i++)
		if (periph_gatt_db.attrs[i].uuid16 == GATT_UUID_CCCD &&
		    i > 0 && periph_gatt_db.attrs[i - 1].handle == characteristic) {
			cccd_handle = periph_gatt_db.attrs[i].handle;
			break;
		}
	ATF_REQUIRE(cccd_handle != 0);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, notify_pair));
	memset(&notify_att, 0, sizeof(notify_att));
	notify_att.fd = notify_pair[0];
	notify_att.bearer_fd = -1;
	notify_att.mtu = 185;
	notify_att.cccd_count = 1;
	notify_att.cccds[0].handle = cccd_handle;
	notify_att.cccds[0].value = GATT_CCCD_NOTIFY;
	notify_conn = blued_conn_alloc();
	ATF_REQUIRE(notify_conn != NULL);
	notify_conn->role = BLUED_ROLE_PERIPHERAL;
	notify_conn->att = &notify_att;
	notify_conn->gatt_db = &periph_gatt_db;
	atomic_store(&notify_conn->state, BLUED_CONN_ACTIVE);
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_gatt_notify_result(characteristic, value,
	    sizeof(value), false, &sent));
	ATF_CHECK_EQ(1, sent);
	/* A real bearer must still be active and subscribed before a server
	 * notification is emitted. */
	atomic_store(&notify_conn->state, BLUED_CONN_CONNECTING);
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_gatt_notify_result(characteristic, value,
	    sizeof(value), false, &sent));
	ATF_CHECK_EQ(0, sent);
	atomic_store(&notify_conn->state, BLUED_CONN_ACTIVE);
	notify_att.cccds[0].value = 0;
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_gatt_notify_result(characteristic, value,
	    sizeof(value), false, &sent));
	ATF_CHECK_EQ(0, sent);
	notify_att.cccds[0].value = GATT_CCCD_NOTIFY;
	notify_conn->role = BLUED_ROLE_CENTRAL;
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_gatt_notify_result(characteristic, value,
	    sizeof(value), false, &sent));
	ATF_CHECK_EQ(0, sent);
	notify_conn->role = BLUED_ROLE_PERIPHERAL;

	/* A database mutation on a robust-caching peer with Service Changed
	 * indications enabled invalidates change awareness and emits 0x2A05. */
	for (int i = 0; i + 1 < periph_gatt_db.count; i++)
		if (periph_gatt_db.attrs[i].uuid16 == 0x2A05 &&
		    periph_gatt_db.attrs[i].is_char_value &&
		    periph_gatt_db.attrs[i + 1].uuid16 == GATT_UUID_CCCD) {
			service_changed_cccd = periph_gatt_db.attrs[i + 1].handle;
			break;
		}
	ATF_REQUIRE(service_changed_cccd != 0);
	notify_att.robust_caching = true;
	notify_att.change_aware = true;
	notify_att.cccd_count = 2;
	notify_att.cccds[1].handle = service_changed_cccd;
	notify_att.cccds[1].value = GATT_CCCD_INDICATE;
	indicate_characteristic = descriptor;
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(10, 0x1825,
	    NULL, &service));
	ATF_CHECK(!notify_att.change_aware);
	notify_att.ind_pending = false;
	cccd_handle = 0;
	for (int i = 0; i < periph_gatt_db.count; i++)
		if (periph_gatt_db.attrs[i].uuid16 == GATT_UUID_CCCD &&
		    i > 0 && periph_gatt_db.attrs[i - 1].handle ==
		    indicate_characteristic) {
			cccd_handle = periph_gatt_db.attrs[i].handle;
			break;
		}
	ATF_REQUIRE(cccd_handle != 0);
	notify_att.cccds[0].handle = cccd_handle;
	notify_att.cccds[0].value = GATT_CCCD_INDICATE;
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_gatt_notify_result(indicate_characteristic,
	    value, sizeof(value), true, &sent));
	ATF_CHECK_EQ(1, sent);
	notify_conn->att = NULL;
	blued_conn_free(notify_conn);
	close(notify_pair[0]);
	close(notify_pair[1]);

	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_begin_result(20));
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(20, 0, uuid128,
	    &service));
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_gatt_rollback_result(20));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(20, 0,
	    uuid128, &service));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_char_result(20, service, 0,
	    uuid128, GATT_PROP_READ, ATT_PERM_READ, ATT_ATTR_F_DYNAMIC, NULL, 0,
	    &characteristic));
	uuid128[0] = 2;
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_desc_result(20,
	    characteristic, 0, uuid128, ATT_PERM_READ, NULL, 0, &descriptor));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_begin_result(21));
	ctl_gatt_txn_client_gone(21);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_rollback_result(21));

	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_remove_service_result(10, 0));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND,
	    ctl_gatt_remove_service_result(10, 0xffff));
	ATF_CHECK_EQ(IPC_ERR_NONE,
	    ctl_gatt_remove_service_result(10, committed_service));

	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_read_reply_result(10, 0, value,
	    sizeof(value)));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_read_reply_result(10, 1, value,
	    sizeof(value)));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_read_reject_result(10, 0, 1));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_read_reject_result(10, 1, 1));
	ATF_CHECK_EQ(IPC_ERR_INVAL,
	    ctl_gatt_authorize_reply_result(10, 0, true));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND,
	    ctl_gatt_authorize_reply_result(10, 1, true));

	/* A complete staged Include declaration, with derived end/UUID checks. */
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_begin_result(30));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(30, 0x1811,
	    NULL, &service));
	committed_service = service;
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(30, 0x1812,
	    NULL, &characteristic));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_include_result(30,
	    characteristic, committed_service, committed_service, 0x1811,
	    &descriptor));
	ATF_CHECK(descriptor > characteristic);
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_commit_result(30));

	/* The dynamic control API creates primary services, while a restored or
	 * provider-owned database may contain secondary services.  Exercise the
	 * same append and include validation against that valid GATT shape: the
	 * primary service includes a completed secondary service (§3.1). */
	{
		struct att_attr *secondary_attr;
		uint16_t secondary, primary, secondary_char, include_handle;
		uint16_t service128, primary128, char128, ignored;
		uint8_t include_uuid128[16] = { 0x42 };

		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(31, 0x1814,
		    NULL, &secondary));
		secondary_attr = attdb_find_by_handle(&periph_gatt_db, secondary);
		ATF_REQUIRE(secondary_attr != NULL);
		secondary_attr->uuid16 = GATT_UUID_SECONDARY_SERVICE;
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_char_result(31, secondary,
		    0x2a56, NULL, GATT_PROP_READ, ATT_PERM_READ, 0, NULL, 0,
		    &secondary_char));
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(31, 0x1815,
		    NULL, &primary));
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_include_result(31, primary,
		    secondary, (uint16_t)(primary - 1), 0, &include_handle));
		ATF_CHECK(include_handle > primary);

		/* An Include declaration names a distinct completed service (§3.2).
		 * Reject declaration/value handles, a self-reference, an end handle
		 * other than the included service's derived range, and a mismatched
		 * 16-bit UUID. */
		ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_add_include_result(31, primary,
		    primary, primary, 0, &ignored));
		ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_add_include_result(31,
		    secondary_char, secondary, (uint16_t)(primary - 1), 0, &ignored));
		ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_add_include_result(31, primary,
		    secondary_char, secondary_char, 0, &ignored));
		ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_include_result(31, primary,
		    secondary, secondary, 0, &ignored));
		ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_include_result(31, primary,
		    secondary, (uint16_t)(primary - 1), 0x1815, &ignored));

		/* For a 128-bit included service, the Include value has no 16-bit UUID
		 * field; supplying one is therefore invalid (GATT §3.2). */
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(31, 0,
		    include_uuid128, &service128));
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_char_result(31, service128,
		    0x2a5a, NULL, GATT_PROP_READ, ATT_PERM_READ, 0, NULL, 0,
		    &char128));
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(31, 0x181b,
		    NULL, &primary128));
		ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_add_include_result(31, primary128,
		    service128, (uint16_t)(primary128 - 1), 0x181b, &ignored));
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_include_result(31,
		    primary128, service128, (uint16_t)(primary128 - 1), 0,
		    &include_handle));
		ATF_CHECK(include_handle > primary128);
		ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_add_include_result(31,
		    0xffff, secondary, (uint16_t)(primary - 1), 0, &ignored));
		ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_add_include_result(31, primary,
		    0xffff, 0xffff, 0, &ignored));
		ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_add_include_result(31, primary,
		    secondary, (uint16_t)(primary - 1), 0, &ignored));
		ATF_CHECK(char128 > service128);
	}

	/* A live DB mutation fans out Service Changed only to active peripheral
	 * bearers that enabled its CCCD.  Other simultaneously connected peers are
	 * ordinary, standards-valid states and must be skipped without affecting
	 * robust-caching invalidation or the eligible peer. */
	{
		struct blued_conn *central, *no_att, *inactive, *disabled;
		struct att_conn central_att, inactive_att, disabled_att;

		memset(&central_att, 0, sizeof(central_att));
		memset(&inactive_att, 0, sizeof(inactive_att));
		memset(&disabled_att, 0, sizeof(disabled_att));
		central = blued_conn_alloc();
		no_att = blued_conn_alloc();
		inactive = blued_conn_alloc();
		disabled = blued_conn_alloc();
		ATF_REQUIRE(central != NULL && no_att != NULL && inactive != NULL &&
		    disabled != NULL);
		central->role = BLUED_ROLE_CENTRAL;
		central->att = &central_att;
		atomic_store(&central->state, BLUED_CONN_ACTIVE);
		no_att->role = BLUED_ROLE_PERIPHERAL;
		inactive->role = BLUED_ROLE_PERIPHERAL;
		inactive->att = &inactive_att;
		atomic_store(&inactive->state, BLUED_CONN_CONNECTING);
		disabled->role = BLUED_ROLE_PERIPHERAL;
		disabled->att = &disabled_att;
		disabled_att.robust_caching = true;
		disabled_att.change_aware = true;
		atomic_store(&disabled->state, BLUED_CONN_ACTIVE);
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(32, 0x1816,
		    NULL, &service));
		ATF_CHECK(!disabled_att.change_aware);
		central->att = NULL;
		inactive->att = NULL;
		disabled->att = NULL;
		blued_conn_free(central);
		blued_conn_free(no_att);
		blued_conn_free(inactive);
		blued_conn_free(disabled);
	}

	/* Database Hash (GATT §2.3) is normally supplied by the Generic Attribute
	 * Service provider rather than the dynamic-control API.  A subsequent live
	 * mutation must refresh its 16-byte value before Service Changed fanout. */
	{
		uint8_t zero_hash[16] = { 0 };
		uint16_t ga_service, db_hash;

		ga_service = attdb_add_service(&periph_gatt_db, 0x1801);
		ATF_REQUIRE(ga_service != 0);
		db_hash = attdb_add_characteristic(&periph_gatt_db, 0x2b2a,
		    GATT_PROP_READ, ATT_PERM_READ, zero_hash, sizeof(zero_hash));
		ATF_REQUIRE(db_hash != 0);
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(33, 0x1817,
		    NULL, &service));
		ATF_CHECK(memcmp(attdb_find_by_handle(&periph_gatt_db, db_hash)->value,
		    zero_hash, sizeof(zero_hash)) != 0);
	}

	/* GATT service ranges are contiguous.  Once a later service declaration
	 * exists, no characteristic or descriptor may be appended into the prior
	 * range (§3.1); reject both forms without altering the database. */
	{
		uint16_t first, second, first_char, ignored;

		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(34, 0x1818,
		    NULL, &first));
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_char_result(34, first,
		    0x2a57, NULL, GATT_PROP_READ, ATT_PERM_READ, 0, NULL, 0,
		    &first_char));
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(34, 0x1819,
		    NULL, &second));
		ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_add_char_result(34, first,
		    0x2a58, NULL, GATT_PROP_READ, ATT_PERM_READ, 0, NULL, 0,
		    &ignored));
		ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_add_desc_result(34,
		    first_char, 0x2901, NULL, ATT_PERM_READ, NULL, 0, &ignored));
		ATF_CHECK(second > first);
	}

	/* A dynamic/provider-supplied characteristic can intentionally have no
	 * local backing value.  Control SET_VALUE must reject it instead of
	 * manufacturing storage outside the provider's declared capacity. */
	{
		uint16_t dynamic_service, dynamic_char;

		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(35, 0x181a,
		    NULL, &dynamic_service));
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_char_result(35,
		    dynamic_service, 0x2a59, NULL, GATT_PROP_READ, ATT_PERM_READ,
		    ATT_ATTR_F_DYNAMIC, NULL, 0, &dynamic_char));
		ATF_CHECK_EQ(IPC_ERR_TOOBIG, ctl_gatt_set_value_result(35,
		    dynamic_char, value, sizeof(value)));
	}

	/* Transaction ownership blocks every mutating GATT verb uniformly. */
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_begin_result(40));
	ATF_CHECK_EQ(IPC_ERR_BUSY, ctl_gatt_add_service_result(41, 0x1820,
	    NULL, &service));
	ATF_CHECK_EQ(IPC_ERR_BUSY, ctl_gatt_add_char_result(41, 1, 0x2a40,
	    NULL, GATT_PROP_READ, ATT_PERM_READ, 0, NULL, 0,
	    &characteristic));
	ATF_CHECK_EQ(IPC_ERR_BUSY, ctl_gatt_add_include_result(41, 1, 2, 2,
	    0, &descriptor));
	ATF_CHECK_EQ(IPC_ERR_BUSY, ctl_gatt_add_desc_result(41, 1, 0x2901,
	    NULL, ATT_PERM_READ, NULL, 0, &descriptor));
	ATF_CHECK_EQ(IPC_ERR_BUSY, ctl_gatt_remove_service_result(41, 1));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_rollback_result(40));

	/* A failed staged removal aborts the transaction, preserving the live
	 * database and preventing a later commit of a partially validated build. */
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_begin_result(42));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_remove_service_result(42,
	    0xffff));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_rollback_result(42));

	/* Value bounds distinguish invalid protocol size from attribute capacity. */
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_gatt_set_value_result(10,
	    characteristic, value, ATT_PDU_BUF_SIZE + 1));
	ATF_CHECK_EQ(IPC_ERR_TOOBIG, ctl_gatt_set_value_result(10,
	    committed_service, value, sizeof(value)));

	/* Exhausted staged databases roll back atomically and discard the txn. */
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_begin_result(50));
	error = IPC_ERR_NONE;
	for (capacity_i = 0;
	    capacity_i < CTL_TEST_DB_MAX && error == IPC_ERR_NONE; capacity_i++)
		error = ctl_gatt_add_service_result(50,
		    (uint16_t)(0x1900 + capacity_i),
		    NULL, &service);
	ATF_CHECK_EQ(IPC_ERR_TOOBIG, error);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_rollback_result(50));

	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(51, 0x1822,
	    NULL, &service));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_begin_result(51));
	error = IPC_ERR_NONE;
	for (capacity_i = 0;
	    capacity_i < CTL_TEST_DB_MAX && error == IPC_ERR_NONE; capacity_i++)
		error = ctl_gatt_add_char_result(51, service,
		    (uint16_t)(0x2b00 + capacity_i), NULL, GATT_PROP_READ,
		    ATT_PERM_READ,
		    0, large_value, sizeof(large_value), &characteristic);
	ATF_CHECK_EQ(IPC_ERR_TOOBIG, error);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_rollback_result(51));

	/* Leave exactly two attribute slots: declaration/value fit, CCCD does not. */
	while (periph_gatt_db.count + 4 <= periph_gatt_db.max) {
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_char_result(52, service,
		    (uint16_t)(0x2c00 + periph_gatt_db.count), NULL,
		    GATT_PROP_READ, ATT_PERM_READ, 0, NULL, 0,
		    &characteristic));
	}
	if (periph_gatt_db.max - periph_gatt_db.count == 3)
		ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_desc_result(52,
		    characteristic, 0x2901, NULL, ATT_PERM_READ, NULL, 0,
		    &descriptor));
	ATF_REQUIRE_EQ(2, periph_gatt_db.max - periph_gatt_db.count);
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_begin_result(52));
	ATF_CHECK_EQ(IPC_ERR_TOOBIG, ctl_gatt_add_char_result(52, service,
	    0x2a43, NULL, GATT_PROP_NOTIFY, ATT_PERM_READ, 0, NULL, 0,
	    &characteristic));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_gatt_rollback_result(52));
}

/*
 * Finding 137: a runtime-added local GATT service is serialized to the gattsrv
 * persist artifact on mutation, and replayed into a freshly built periph_gatt_db
 * at startup (simulating a restart) with its original handle and value, marked
 * with the CTL_GATT_OWNER_PERSISTED sentinel so it re-persists and is served as
 * a static attribute.
 */
ATF_TC_WITHOUT_HEAD(test_gatt_runtime_db_persist);
ATF_TC_BODY(test_gatt_runtime_db_persist, tc)
{
	uint8_t value[] = { 0xDE, 0xAD, 0xBE, 0xEF };
	uint16_t service = 0, characteristic = 0;
	int svc_idx = -1, val_idx = -1;

	test_init();
	build_ctl_test_db();
	ctl_gatt_set_base_count();	/* built-in/config high-water mark */
	blued_g.persist_dirfd = 0;	/* >= 0 so persistence proceeds */
	ctl_test_gattsrv_count = 0;
	ctl_test_gattsrv_save_calls = 0;

	/* A runtime add (owner_fd 61) mutates the live DB and persists it. */
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_service_result(61, 0x1810,
	    NULL, &service));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_add_char_result(61, service,
	    0x2A35, NULL, GATT_PROP_READ, ATT_PERM_READ, 0, value, sizeof(value),
	    &characteristic));
	ATF_CHECK(ctl_test_gattsrv_save_calls > 0);
	ATF_CHECK(ctl_test_gattsrv_count >= 2);

	/* Simulate a restart: rebuild the base DB, then replay the artifact. */
	build_ctl_test_db();
	{
		uint32_t before = (uint32_t)periph_gatt_db.count;

		ctl_gatt_load_persisted_services(0);
		ATF_CHECK(periph_gatt_db.count > (int)before);
	}
	for (int i = 0; i < periph_gatt_db.count; i++) {
		if (periph_gatt_db.attrs[i].handle == service)
			svc_idx = i;
		if (periph_gatt_db.attrs[i].handle == characteristic &&
		    periph_gatt_db.attrs[i].is_char_value)
			val_idx = i;
	}
	ATF_REQUIRE(svc_idx >= 0);
	/* Primary Service declaration (0x2800) whose value is the 0x1810 UUID. */
	ATF_CHECK_EQ(0x2800, periph_gatt_db.attrs[svc_idx].uuid16);
	ATF_REQUIRE_EQ(2, periph_gatt_db.attrs[svc_idx].value_len);
	ATF_CHECK_EQ(0x10, periph_gatt_db.attrs[svc_idx].value[0]);
	ATF_CHECK_EQ(0x18, periph_gatt_db.attrs[svc_idx].value[1]);
	ATF_CHECK_EQ(CTL_GATT_OWNER_PERSISTED,
	    periph_gatt_db.attrs[svc_idx].owner_fd);
	ATF_REQUIRE(val_idx >= 0);
	ATF_CHECK_EQ(0x2A35, periph_gatt_db.attrs[val_idx].uuid16);
	ATF_CHECK_EQ(sizeof(value), periph_gatt_db.attrs[val_idx].value_len);
	ATF_CHECK_EQ(0, memcmp(periph_gatt_db.attrs[val_idx].value, value,
	    sizeof(value)));

	blued_g.persist_dirfd = -1;
}

ATF_TC_WITHOUT_HEAD(test_ctl_gatt_staged_remove_service_changed_range);
ATF_TC_BODY(test_ctl_gatt_staged_remove_service_changed_range, tc)
{
	struct blued_conn *conn;
	struct att_conn att;
	uint8_t pdu[16];
	uint16_t removed_service, removed_char, survivor_service;
	uint16_t gatt_service, service_changed, service_changed_cccd;
	int sp[2];
	ssize_t n;

	test_init();
	build_ctl_test_db();
	removed_service = attdb_add_service(&periph_gatt_db, 0x1821);
	ATF_REQUIRE(removed_service != 0);
	removed_char = attdb_add_characteristic(&periph_gatt_db, 0x2a60,
	    GATT_PROP_READ, ATT_PERM_READ, NULL, 0);
	ATF_REQUIRE(removed_char != 0);
	survivor_service = attdb_add_service(&periph_gatt_db, 0x1822);
	ATF_REQUIRE(survivor_service != 0);
	gatt_service = attdb_add_service(&periph_gatt_db, 0x1801);
	ATF_REQUIRE(gatt_service != 0);
	service_changed = attdb_add_characteristic(&periph_gatt_db, 0x2a05,
	    GATT_PROP_INDICATE, ATT_PERM_READ, NULL, 0);
	ATF_REQUIRE(service_changed != 0);
	service_changed_cccd = attdb_add_cccd(&periph_gatt_db);
	ATF_REQUIRE(service_changed_cccd != 0);

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp));
	memset(&att, 0, sizeof(att));
	att.fd = sp[0];
	att.bearer_fd = -1;
	att.mtu = 185;
	att.robust_caching = true;
	att.change_aware = true;
	att.cccd_count = 1;
	att.cccds[0].handle = service_changed_cccd;
	att.cccds[0].value = GATT_CCCD_INDICATE;

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->role = BLUED_ROLE_PERIPHERAL;
	conn->att = &att;
	conn->gatt_db = &periph_gatt_db;
	atomic_store(&conn->state, BLUED_CONN_ACTIVE);

	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_begin_result(70));
	ATF_REQUIRE_EQ(IPC_ERR_NONE,
	    ctl_gatt_remove_service_result(70, removed_service));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_gatt_commit_result(70));

	n = recv(sp[1], pdu, sizeof(pdu), 0);
	ATF_REQUIRE_EQ(7, n);
	ATF_CHECK_EQ(ATT_OP_HANDLE_IND, pdu[0]);
	ATF_CHECK_EQ(service_changed, get_le16(pdu + 1));
	ATF_CHECK_EQ(removed_service, get_le16(pdu + 3));
	ATF_CHECK_EQ(0xffff, get_le16(pdu + 5));
	ATF_CHECK(!att.change_aware);

	conn->att = NULL;
	blued_conn_free(conn);
	close(sp[0]);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(test_ctl_gatt_conn_gone_purges_peer_routes);
ATF_TC_BODY(test_ctl_gatt_conn_gone_purges_peer_routes, tc)
{
	struct blued_ctl_client first, second;
	struct blued_adapter adp;
	struct blued_conn conn;
	bdaddr_t peer, other;

	test_init();
	memset(&first, 0, sizeof(first));
	memset(&second, 0, sizeof(second));
	memset(&adp, 0, sizeof(adp));
	memset(&conn, 0, sizeof(conn));
	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &peer));
	ATF_REQUIRE(bt_aton("aa:bb:cc:dd:ee:ff", &other));
	adp.index = 2;
	conn.adapter = &adp;
	conn.dst = peer;
	conn.addr_type = BDADDR_LE_PUBLIC;

	first.subs[0] = (struct ctl_subscription){ .addr = peer,
	    .handle = 0x20, .cccd_handle = 0x21,
	    .addr_type = BDADDR_LE_PUBLIC,
	    .adapter_index = 2 };
	first.subs[1] = (struct ctl_subscription){ .addr = other,
	    .handle = 0x30, .cccd_handle = 0x31,
	    .addr_type = BDADDR_LE_PUBLIC,
	    .adapter_index = 2 };
	first.nsubs = 2;
	second.subs[0] = (struct ctl_subscription){ .addr = peer,
	    .handle = 0x40, .cccd_handle = 0x41,
	    .addr_type = BDADDR_LE_RANDOM,
	    .adapter_index = 2 };
	second.subs[1] = (struct ctl_subscription){ .addr = peer,
	    .handle = 0x50, .cccd_handle = 0x51,
	    .addr_type = BDADDR_LE_PUBLIC,
	    .adapter_index = 2 };
	second.subs[2] = (struct ctl_subscription){ .addr = peer,
	    .handle = 0x60, .cccd_handle = 0x61,
	    .addr_type = BDADDR_LE_PUBLIC,
	    .adapter_index = 3 };
	second.nsubs = 3;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, &first, entries);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, &second, entries);

	/* Physical teardown has no usable ATT bearer and must only purge routes. */
	ctl_gatt_conn_gone(&conn);
	ATF_CHECK_EQ(1, first.nsubs);
	ATF_CHECK_EQ(0, memcmp(&first.subs[0].addr, &other, sizeof(other)));
	ATF_CHECK_EQ(2, second.nsubs);
	ATF_CHECK_EQ(BDADDR_LE_RANDOM, second.subs[0].addr_type);
	ATF_CHECK_EQ(3, second.subs[1].adapter_index);

	LIST_REMOVE(&second, entries);
	LIST_REMOVE(&first, entries);
}

struct ctl_cccd_notify_exchange {
	int			fd;
	struct blued_conn	*conn;
	bool			injected;
};

/*
 * Model a server which emits its first value after accepting CCCD=Notify but
 * before returning the Write Response.  This ordering is legal and is the
 * narrow interval in which a post-response-only local route loses the value.
 */
static void *
ctl_cccd_notify_responder(void *arg)
{
	struct ctl_cccd_notify_exchange *x = arg;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	uint8_t req[ATT_MAX_MTU], rsp[16];
	ssize_t n;

	(void)setsockopt(x->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	while ((n = recv(x->fd, req, sizeof(req), 0)) > 0) {
		size_t rsplen;

		memset(rsp, 0, sizeof(rsp));
		switch (req[0]) {
		case ATT_OP_READ_BY_GROUP_TYPE_REQ:
			if (get_le16(req + 1) == 1) {
				/* Mesh Proxy service, handles 1..5. */
				memcpy(rsp, (const uint8_t[]){
				    ATT_OP_READ_BY_GROUP_TYPE_RSP, 6,
				    0x01, 0x00, 0x05, 0x00, 0x28, 0x18 }, 8);
				rsplen = 8;
			} else {
				memcpy(rsp, (const uint8_t[]){ ATT_OP_ERROR_RSP,
				    ATT_OP_READ_BY_GROUP_TYPE_REQ, req[1], req[2],
				    ATT_ERR_ATTR_NOT_FOUND }, 5);
				rsplen = 5;
			}
			break;
		case ATT_OP_READ_BY_TYPE_REQ:
			if (get_le16(req + 1) == 1) {
				memcpy(rsp, (const uint8_t[]){
				    ATT_OP_READ_BY_TYPE_RSP, 7, 0x02, 0x00,
				    GATT_PROP_NOTIFY, 0x03, 0x00, 0xdd, 0x2a }, 9);
				rsplen = 9;
			} else {
				memcpy(rsp, (const uint8_t[]){ ATT_OP_ERROR_RSP,
				    ATT_OP_READ_BY_TYPE_REQ, req[1], req[2],
				    ATT_ERR_ATTR_NOT_FOUND }, 5);
				rsplen = 5;
			}
			break;
		case ATT_OP_FIND_INFO_REQ:
			if (get_le16(req + 1) == 4) {
				memcpy(rsp, (const uint8_t[]){ ATT_OP_FIND_INFO_RSP, 1,
				    0x04, 0x00, 0x02, 0x29 }, 6);
				rsplen = 6;
			} else {
				memcpy(rsp, (const uint8_t[]){ ATT_OP_ERROR_RSP,
				    ATT_OP_FIND_INFO_REQ, req[1], req[2],
				    ATT_ERR_ATTR_NOT_FOUND }, 5);
				rsplen = 5;
			}
			break;
		case ATT_OP_WRITE_REQ: {
			static const uint8_t value[] = { 0xa5, 0x5a };

			if (n >= 5 && get_le16(req + 1) == 4 &&
			    get_le16(req + 3) == GATT_CCCD_NOTIFY) {
				blued_ctl_notify_value(x->conn, 3, value,
				    sizeof(value), 23);
				x->injected = true;
			}
			rsp[0] = ATT_OP_WRITE_RSP;
			rsplen = 1;
			(void)send(x->fd, rsp, rsplen, 0);
			return (NULL);
		}
		default:
			return (NULL);
		}
		(void)send(x->fd, rsp, rsplen, 0);
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(test_ctl_gatt_subscribe_routes_before_cccd_response);
ATF_TC_BODY(test_ctl_gatt_subscribe_routes_before_cccd_response, tc)
{
	struct ctl_cccd_notify_exchange exchange;
	struct blued_adapter adp;
	struct blued_ctl_client *client;
	struct blued_conn *conn;
	struct att_conn att;
	bdaddr_t peer;
	char payload[128];
	uint16_t type, arg;
	int att_pair[2], ctl_pair[2], status;
	pthread_t responder;
	size_t len;

	test_init();
	memset(&adp, 0, sizeof(adp));
	memset(&att, 0, sizeof(att));
	adp.index = 0;
	adp.active = true;
	adp.powered = true;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &peer));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, att_pair));
	att.fd = att_pair[0];
	att.bearer_fd = -1;
	att.mtu = 23;
	att.buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(att.buf != NULL);
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->adapter = &adp;
	conn->dst = peer;
	conn->addr_type = BDADDR_LE_PUBLIC;
	conn->att = &att;
	conn->att_fd = att.fd;

	client = make_client(ctl_pair);
	client->generation = 77;
	client->wants_events = true;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	memset(&exchange, 0, sizeof(exchange));
	exchange.fd = att_pair[1];
	exchange.conn = conn;
	ATF_REQUIRE_EQ(0, pthread_create(&responder, NULL,
	    ctl_cccd_notify_responder, &exchange));
	status = ctl_gatt_subscribe_result(conn, client->fd, client->generation,
	    0, &peer, BDADDR_LE_PUBLIC, 3, true);
	ATF_REQUIRE_EQ_MSG(IPC_ERR_NONE, status, "subscribe status=%d", status);
	ATF_REQUIRE_EQ(0, pthread_join(responder, NULL));
	ATF_CHECK(exchange.injected);
	ATF_REQUIRE_EQ(1, client->nsubs);
	ATF_CHECK(!client->subs[0].pending);

	len = ipc_recv(ctl_pair[1], &type, &arg, payload, sizeof(payload));
	ATF_CHECK_EQ(IPC_T_OP_EVENT, type);
	ATF_CHECK_EQ(IPC_OP_DOMAIN_GATT, arg);
	ATF_REQUIRE_EQ(IPC_OP_PREFIX_SIZE + IPC_GATT_NOTIFY_EVENT_SIZE + 2, len);
	ATF_CHECK_EQ(IPC_GATT_EV_NOTIFY,
	    ipc_get_le16((uint8_t *)payload + IPC_OP_PREFIX_SIZE));
	ATF_CHECK_EQ(3, ipc_get_le16((uint8_t *)payload + IPC_OP_PREFIX_SIZE + 9));
	ATF_CHECK_EQ(0xa5, (uint8_t)payload[IPC_OP_PREFIX_SIZE +
	    IPC_GATT_NOTIFY_EVENT_SIZE]);

	LIST_REMOVE(client, entries);
	LIST_REMOVE(&adp, entries);
	conn->att = NULL;
	blued_conn_free(conn);
	blued_ctl_client_fini(client);
	free(client);
	free(att.buf);
	close(att_pair[0]);
	close(att_pair[1]);
	close(ctl_pair[0]);
	close(ctl_pair[1]);
}

struct ctl_cccd_exit_exchange {
	int		fd;
	ssize_t		request_len;
	uint8_t		request[ATT_MAX_MTU];
};

static void *
ctl_cccd_exit_responder(void *arg)
{
	struct ctl_cccd_exit_exchange *x = arg;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	uint8_t rsp = ATT_OP_WRITE_RSP;

	(void)setsockopt(x->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	x->request_len = recv(x->fd, x->request, sizeof(x->request), 0);
	if (x->request_len > 0)
		(void)send(x->fd, &rsp, sizeof(rsp), 0);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(test_ctl_gatt_client_exit_cccd_ownership);
ATF_TC_BODY(test_ctl_gatt_client_exit_cccd_ownership, tc)
{
	struct ctl_cccd_exit_exchange exchange;
	struct blued_ctl_client first, last;
	struct blued_adapter adp;
	struct blued_conn *conn;
	struct att_conn att;
	struct timeval tv = { .tv_sec = 0, .tv_usec = 20000 };
	bdaddr_t peer, gone;
	char path[64];
	uint8_t unexpected[8];
	int att_pair[2];
	pthread_t responder;

	test_init();
	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);
	snprintf(path, sizeof(path), "/tmp/blued-gatt-exit-%d.sock",
	    (int)getpid());
	ATF_REQUIRE_EQ(0, blued_ctl_init(path));
	memset(&first, 0, sizeof(first));
	memset(&last, 0, sizeof(last));
	memset(&adp, 0, sizeof(adp));
	memset(&att, 0, sizeof(att));
	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &peer));
	ATF_REQUIRE(bt_aton("aa:bb:cc:dd:ee:ff", &gone));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, att_pair));
	adp.index = 2;
	adp.active = true;
	adp.powered = true;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	att.fd = att_pair[0];
	att.mtu = 23;
	att.buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(att.buf != NULL);
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->adapter = &adp;
	conn->dst = peer;
	conn->addr_type = 1;
	conn->att = &att;
	conn->att_fd = att.fd;

	first.fd = 80;
	first.generation = 1;
	first.subs[0] = (struct ctl_subscription){ .addr = peer,
	    .handle = 0x20, .cccd_handle = 0x21,
	    .cccd_value = GATT_CCCD_NOTIFY, .addr_type = 1,
	    .adapter_index = 2 };
	/* A vanished peer exercises the disconnected, best-effort arm. */
	first.subs[1] = (struct ctl_subscription){ .addr = gone,
	    .handle = 0x30, .cccd_handle = 0x31,
	    .cccd_value = GATT_CCCD_NOTIFY, .addr_type = 1,
	    .adapter_index = 2 };
	first.nsubs = 2;
	last.fd = 81;
	last.generation = 2;
	last.subs[0] = first.subs[0];
	last.nsubs = 1;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, &first, entries);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, &last, entries);

	/* Departing one of two owners must preserve the shared peer CCCD. */
	LIST_REMOVE(&first, entries);
	ctl_gatt_client_gone(&first);
	ATF_CHECK_EQ(0, first.nsubs);
	(void)setsockopt(att_pair[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	errno = 0;
	ATF_CHECK_EQ(-1, recv(att_pair[1], unexpected, sizeof(unexpected), 0));
	ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);

	/* The final owner queues one serialized Write Request of 0x0000. */
	LIST_REMOVE(&last, entries);
	memset(&exchange, 0, sizeof(exchange));
	exchange.fd = att_pair[1];
	ATF_REQUIRE_EQ(0, pthread_create(&responder, NULL,
	    ctl_cccd_exit_responder, &exchange));
	ctl_gatt_client_gone(&last);
	ATF_REQUIRE_EQ(0, pthread_join(responder, NULL));
	for (int i = 0; i < 1000 && atomic_load(&conn->att_ops_active) != 0; i++)
		usleep(1000);
	ATF_CHECK_EQ(0, last.nsubs);
	ATF_REQUIRE_EQ(5, exchange.request_len);
	ATF_CHECK_EQ(ATT_OP_WRITE_REQ, exchange.request[0]);
	ATF_CHECK_EQ(0x21, get_le16(exchange.request + 1));
	ATF_CHECK_EQ(0, get_le16(exchange.request + 3));
	ATF_CHECK_EQ(0, atomic_load(&conn->att_ops_active));

	blued_ctl_cleanup();
	conn->att = NULL;
	blued_conn_free(conn);
	LIST_REMOVE(&adp, entries);
	free(att.buf);
	close(att_pair[0]);
	close(att_pair[1]);
	close(blued_g.kq);
}

ATF_TC_WITHOUT_HEAD(test_ctl_gatt_client_exit_cleanup_bound);
ATF_TC_BODY(test_ctl_gatt_client_exit_cleanup_bound, tc)
{
	test_init();
	ATF_CHECK_EQ(0, ptap_ctl_cleanup_bound());
}


ATF_TC_WITHOUT_HEAD(test_typed_domain_opcode_sweep);
ATF_TC_WITHOUT_HEAD(test_typed_gatt_server_matrix);
ATF_TC_BODY(test_typed_gatt_server_matrix, tc)
{
	struct blued_ctl_client *client;
	char feat[128];
	uint8_t body[IPC_GATT_ADD_CHAR_REQ_SIZE + 4];
	uint16_t service, included, characteristic, descriptor;
	int sp[2];

	test_init();
	build_ctl_test_db();
	client = make_client(sp);
	client->peer_known = true;
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS,
	    feat, sizeof(feat));

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_ADD_SERVICE);
	ipc_put_le16(body + 14, 0x1815);
	ATF_REQUIRE_EQ(IPC_ERR_NONE, dispatch_gatt_handle_request(client,
	    sp[1], body, IPC_GATT_ADD_SERVICE_REQ_SIZE, &service));
	ATF_REQUIRE(service != 0);

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_ADD_SERVICE);
	ipc_put_le16(body + 14, 0x1816);
	ATF_REQUIRE_EQ(IPC_ERR_NONE, dispatch_gatt_handle_request(client,
	    sp[1], body, IPC_GATT_ADD_SERVICE_REQ_SIZE, &included));
	ATF_REQUIRE(included != 0);

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_ADD_CHARACTERISTIC);
	ipc_put_le16(body + 12, included);
	ipc_put_le16(body + 14, 0x2a56);
	body[32] = GATT_PROP_READ | GATT_PROP_NOTIFY;
	body[33] = ATT_PERM_READ | ATT_PERM_WRITE;
	body[34] = ATT_ATTR_F_DYNAMIC;
	ipc_put_le16(body + 36, 2);
	body[IPC_GATT_ADD_CHAR_REQ_SIZE] = 0xaa;
	body[IPC_GATT_ADD_CHAR_REQ_SIZE + 1] = 0xbb;
	ATF_REQUIRE_EQ(IPC_ERR_NONE, dispatch_gatt_handle_request(client,
	    sp[1], body, IPC_GATT_ADD_CHAR_REQ_SIZE + 2, &characteristic));
	ATF_REQUIRE(characteristic != 0);

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_ADD_INCLUDE);
	ipc_put_le16(body + 12, included);
	ipc_put_le16(body + 14, service);
	ipc_put_le16(body + 16, service);
	ipc_put_le16(body + 18, 0x1815);
	(void)dispatch_gatt_handle_request(client, sp[1], body,
	    IPC_GATT_ADD_INCLUDE_REQ_SIZE, &descriptor);

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_ADD_DESCRIPTOR);
	ipc_put_le16(body + 12, included);
	ipc_put_le16(body + 14, 0x2901);
	body[32] = ATT_PERM_READ;
	ipc_put_le16(body + 34, 2);
	body[IPC_GATT_ADD_DESC_REQ_SIZE] = 'o';
	body[IPC_GATT_ADD_DESC_REQ_SIZE + 1] = 'k';
	(void)dispatch_gatt_handle_request(client, sp[1], body,
	    IPC_GATT_ADD_DESC_REQ_SIZE + 2, &descriptor);

	/* Value, notification, and dynamic-decision opcodes reach their helpers. */
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_SET_VALUE);
	ipc_put_le16(body + 12, characteristic);
	ipc_put_le16(body + 14, 1); body[16] = 0x5a;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_VALUE_REQ_SIZE + 1));
	for (uint16_t op = IPC_GATT_NOTIFY; op <= IPC_GATT_INDICATE; op++) {
		ipc_put_le16(body, op);
		(void)dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_GATT,
		    body, IPC_GATT_VALUE_REQ_SIZE + 1);
	}
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_READ_REPLY);
	ipc_put_le16(body + 12, characteristic);
	ipc_put_le16(body + 14, 1); body[16] = 1;
	(void)dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_GATT, body,
	    IPC_GATT_VALUE_REQ_SIZE + 1);
	ipc_put_le16(body, IPC_GATT_READ_REJECT); body[14] = 1;
	(void)dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_GATT, body,
	    IPC_GATT_DECISION_REQ_SIZE);
	ipc_put_le16(body, IPC_GATT_AUTHORIZE_REPLY); body[14] = 1;
	(void)dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_GATT, body,
	    IPC_GATT_DECISION_REQ_SIZE);

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_REMOVE_SERVICE);
	ipc_put_le16(body + 12, service);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_REQ_SIZE));

	/* Common validation, privilege, unknown-opcode and length diagnostics. */
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, 1));
	body[2] = 1;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_REQ_SIZE));
	body[2] = 0; body[3] = 0;
	ipc_put_le16(body, 0xffff);
	ATF_CHECK_EQ(IPC_ERR_UNKNOWN_CMD, dispatch_domain_request(client,
	    sp[1], IPC_OP_DOMAIN_GATT, body, IPC_GATT_REQ_SIZE));
	ipc_put_le16(body, IPC_GATT_WRITE);
	client->peer_uid = 1000;
	ATF_CHECK_EQ(IPC_ERR_PERM, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_REQ_SIZE));

	LIST_REMOVE(client, entries);
	blued_ctl_client_fini(client);
	close(sp[0]); close(sp[1]); free(client);
}

ATF_TC_BODY(test_typed_domain_opcode_sweep, tc)
{
	static const struct {
		uint16_t domain, first, last;
	} sweeps[] = {
		{ IPC_OP_DOMAIN_GAP, IPC_GAP_DISCONNECT,
		    IPC_GAP_GET_CONNECTIONS },
		{ IPC_OP_DOMAIN_GATT, IPC_GATT_READ, IPC_GATT_ACQUIRE_WRITE },
		{ IPC_OP_DOMAIN_SECURITY, IPC_SECURITY_PAIR,
		    IPC_SECURITY_BOND_IMPORT },
		{ IPC_OP_DOMAIN_ADV, IPC_ADV_SET_PARAMS,
		    IPC_ADV_SET_HANDLE_REMOVE },
		{ IPC_OP_DOMAIN_PERIODIC, IPC_PERIODIC_ADV_PARAMS,
		    IPC_PERIODIC_PAST_DEFAULT_PARAMS },
		{ IPC_OP_DOMAIN_L2CAP, IPC_L2CAP_ACQUIRE_COC,
		    IPC_L2CAP_EATT_CLOSE },
		{ IPC_OP_DOMAIN_MESH, IPC_MESH_SUBSCRIBE, IPC_MESH_ADV_SEND },
	};
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	char feat[128];
	uint8_t body[512];
	int sp[2], opcode;

	test_init();
	build_ctl_test_db();
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.powered = true;
	adp.hci_fd = 42;
	adp.le_features = UINT64_MAX;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	client = make_client(sp);
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS | IPC_FEATURE_MESH, feat, sizeof(feat));

	/* GAP has a 12-byte common prefix; the extra byte makes every arm reject. */
	for (opcode = IPC_GAP_DISCONNECT; opcode <= IPC_GAP_GET_CONNECTIONS;
	    opcode++) {
		memset(body, 0, 13);
		ipc_put_le16(body, (uint16_t)opcode);
		(void)dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_GAP,
		    body, 13);
	}

	/* A nonzero handle passes the common GATT validator into each opcode arm. */
	for (opcode = IPC_GATT_READ; opcode <= IPC_GATT_ACQUIRE_WRITE; opcode++) {
		memset(body, 0, 15);
		ipc_put_le16(body, (uint16_t)opcode);
		ipc_put_le16(body + 12, 1);
		(void)dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_GATT,
		    body, 15);
	}

	for (opcode = IPC_SECURITY_PAIR; opcode <= IPC_SECURITY_BOND_IMPORT;
	    opcode++) {
		memset(body, 0, 13);
		ipc_put_le16(body, (uint16_t)opcode);
		(void)dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_SECURITY,
		    body, 13);
	}

	/* ADV switches before its opcode-specific size checks. */
	for (opcode = IPC_ADV_SET_PARAMS; opcode <= IPC_ADV_SET_HANDLE_REMOVE;
	    opcode++) {
		memset(body, 0, 4);
		ipc_put_le16(body, (uint16_t)opcode);
		(void)dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_ADV,
		    body, 4);
	}

	for (opcode = IPC_PERIODIC_ADV_PARAMS;
	    opcode <= IPC_PERIODIC_PAST_DEFAULT_PARAMS; opcode++) {
		memset(body, 0, 4);
		ipc_put_le16(body, (uint16_t)opcode);
		(void)dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_PERIODIC,
		    body, 4);
	}

	for (opcode = IPC_L2CAP_ACQUIRE_COC; opcode <= IPC_L2CAP_EATT_CLOSE;
	    opcode++) {
		memset(body, 0, IPC_L2CAP_REQ_SIZE);
		ipc_put_le16(body, (uint16_t)opcode);
		(void)dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_L2CAP,
		    body, IPC_L2CAP_REQ_SIZE);
	}

	/* Start from a minimally valid shape, then mutate exactly one byte.  The
	 * older all-zero/all-ones sweeps below tend to stop at the first term of
	 * a compound guard; this matrix makes later operands independently
	 * observable to source-based branch coverage. */
	for (int domain = IPC_OP_DOMAIN_GAP;
	    domain <= IPC_OP_DOMAIN_SECURITY; domain++) {
		int first, last;

		if (domain == IPC_OP_DOMAIN_GAP) {
			first = IPC_GAP_DISCONNECT;
			last = IPC_GAP_GET_CONNECTIONS;
			adp.active = false; /* successful validation remains inert */
		} else if (domain == IPC_OP_DOMAIN_GATT) {
			first = IPC_GATT_READ;
			last = IPC_GATT_ACQUIRE_WRITE;
		} else {
			first = IPC_SECURITY_PAIR;
			last = IPC_SECURITY_BOND_IMPORT;
		}
		for (opcode = first; opcode <= last; opcode++) {
			size_t len;

			if (domain == IPC_OP_DOMAIN_GAP) {
				switch (opcode) {
				case IPC_GAP_SET_PHY: len = IPC_GAP_PHY_REQ_SIZE; break;
				case IPC_GAP_SET_DATA_LEN:
					len = IPC_GAP_DATA_LEN_REQ_SIZE; break;
				case IPC_GAP_CONN_UPDATE:
				case IPC_GAP_PATH_LOSS:
					len = IPC_GAP_CONN_UPDATE_REQ_SIZE; break;
				case IPC_GAP_CONNECT: len = IPC_GAP_CONNECT_REQ_SIZE; break;
				case IPC_GAP_SCAN: len = IPC_GAP_SCAN_REQ_SIZE; break;
				case IPC_GAP_CONNECT_NAME:
					len = IPC_GAP_CONNECT_NAME_REQ_SIZE; break;
				default: len = IPC_GAP_REQ_SIZE; break;
				}
			} else if (domain == IPC_OP_DOMAIN_GATT) {
				switch (opcode) {
				case IPC_GATT_WRITE: case IPC_GATT_WRITE_CMD:
				case IPC_GATT_READ_REPLY: case IPC_GATT_SET_VALUE:
				case IPC_GATT_NOTIFY: case IPC_GATT_INDICATE:
					len = IPC_GATT_VALUE_REQ_SIZE; break;
				case IPC_GATT_READ_REJECT:
				case IPC_GATT_AUTHORIZE_REPLY:
					len = IPC_GATT_DECISION_REQ_SIZE; break;
				case IPC_GATT_ADD_SERVICE:
					len = IPC_GATT_ADD_SERVICE_REQ_SIZE; break;
				case IPC_GATT_ADD_CHARACTERISTIC:
					len = IPC_GATT_ADD_CHAR_REQ_SIZE; break;
				case IPC_GATT_ADD_INCLUDE:
					len = IPC_GATT_ADD_INCLUDE_REQ_SIZE; break;
				case IPC_GATT_ADD_DESCRIPTOR:
					len = IPC_GATT_ADD_DESC_REQ_SIZE; break;
				default: len = IPC_GATT_REQ_SIZE; break;
				}
			} else {
				switch (opcode) {
				case IPC_SECURITY_PASSKEY_REPLY:
					len = IPC_SECURITY_PASSKEY_REQ_SIZE; break;
				case IPC_SECURITY_NUMCMP_REPLY:
					len = IPC_SECURITY_DECISION_REQ_SIZE; break;
				case IPC_SECURITY_REGISTER_AGENT:
					len = IPC_SECURITY_AGENT_REQ_SIZE; break;
				case IPC_SECURITY_SET_POLICY:
					len = IPC_SECURITY_POLICY_REQ_SIZE; break;
				case IPC_SECURITY_OOB_INJECT_SC:
					len = IPC_SECURITY_OOB_SC_REQ_SIZE; break;
				case IPC_SECURITY_OOB_INJECT_LEGACY:
					len = IPC_SECURITY_OOB_LEGACY_REQ_SIZE; break;
				case IPC_SECURITY_OOB_CLEAR:
					len = IPC_SECURITY_OOB_CLEAR_REQ_SIZE; break;
				case IPC_SECURITY_RESOLV_ADD:
				case IPC_SECURITY_RESOLV_REMOVE:
				case IPC_SECURITY_RESOLV_CLEAR:
					len = IPC_SECURITY_RESOLV_REQ_SIZE; break;
				case IPC_SECURITY_BOND_IMPORT:
					len = IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE; break;
				default: len = IPC_SECURITY_REQ_SIZE; break;
				}
			}
			memset(body, 0, len);
			ipc_put_le16(body, (uint16_t)opcode);
			if (domain == IPC_OP_DOMAIN_GATT &&
			    opcode != IPC_GATT_DISCOVER &&
			    opcode != IPC_GATT_ADD_SERVICE)
				ipc_put_le16(body + 12, 1);
			if (domain == IPC_OP_DOMAIN_GAP &&
			    opcode == IPC_GAP_CONNECT_NAME)
				body[4] = 'x';
			if (domain == IPC_OP_DOMAIN_SECURITY &&
			    opcode == IPC_SECURITY_SET_POLICY)
				ipc_put_le16(body + 12,
				    IPC_SECURITY_POLICY_F_MITM);
			for (size_t off = 2; off < len; off++) {
				uint8_t saved = body[off];

				for (unsigned vi = 0; vi < 3; vi++) {
					body[off] = vi == 0 ? 1 : vi == 1 ? 2 : 0xff;
					(void)dispatch_domain_request(client, sp[1],
					    (uint16_t)domain, body, len);
				}
				body[off] = saved;
			}
		}
		if (domain == IPC_OP_DOMAIN_GAP)
			adp.active = true;
	}

	/* Typed controller validation and transaction-state error replies. */
	ipc_ctl_req_encode(body, IPC_CTL_STATUS, IPC_CTL_F_BOOL, 0, 0);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_CTL, body, IPC_CTL_REQ_SIZE));
	ipc_ctl_req_encode(body, IPC_CTL_ADAPTER_CAPS, 0, 0, 1);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_CTL, body, IPC_CTL_REQ_SIZE));
	ipc_ctl_req_encode(body, IPC_CTL_PRIVACY, IPC_CTL_F_BOOL, 2, 0);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_CTL, body, IPC_CTL_REQ_SIZE));
	ipc_ctl_req_encode(body, IPC_CTL_GATT_BEGIN, 0, 1, 0);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_CTL, body, IPC_CTL_REQ_SIZE));
	ipc_ctl_req_encode(body, IPC_CTL_GATT_COMMIT, 0, 1, 0);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_CTL, body, IPC_CTL_REQ_SIZE));
	ipc_ctl_req_encode(body, IPC_CTL_GATT_ROLLBACK, 0, 1, 0);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_CTL, body, IPC_CTL_REQ_SIZE));
	ipc_ctl_req_encode(body, IPC_CTL_GATT_COMMIT, 0, 0, 0);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_CTL, body, IPC_CTL_REQ_SIZE));
	ipc_ctl_req_encode(body, IPC_CTL_GATT_BEGIN, 0, 0, 0);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_CTL, body, IPC_CTL_REQ_SIZE));
	ATF_CHECK_EQ(IPC_ERR_BUSY, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_CTL, body, IPC_CTL_REQ_SIZE));
	ipc_ctl_req_encode(body, IPC_CTL_GATT_ROLLBACK, 0, 0, 0);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_CTL, body, IPC_CTL_REQ_SIZE));
	adp.active = false;
	ipc_ctl_req_encode(body, IPC_CTL_ADVERTISE, IPC_CTL_F_BOOL, 1, 0);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_CTL, body, IPC_CTL_REQ_SIZE));
	adp.active = true;

	client->wants_mesh = true;
	for (opcode = IPC_MESH_SUBSCRIBE; opcode <= IPC_MESH_ADV_SEND; opcode++) {
		memset(body, 0, 3);
		ipc_put_le16(body, (uint16_t)opcode);
		(void)dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_MESH,
		    body, 3);
	}
	memset(body, 0, 4);
	(void)dispatch_domain_request(client, sp[1], 0x7fff, body, 4);

	/* Cross every typed opcode with every short payload length.  This keeps
	 * validation coverage systematic when request layouts grow: exact-size
	 * arms, one-byte truncations, optional tails and reserved fields all get
	 * exercised without hand-maintaining a case per opcode. */
	ATF_REQUIRE(fcntl(sp[1], F_SETFL, O_NONBLOCK) == 0);
	for (size_t si = 0; si < nitems(sweeps); si++) {
		for (opcode = sweeps[si].first; opcode <= sweeps[si].last;
		    opcode++) {
			for (size_t len = 0; len <= 64; len++) {
				for (unsigned pattern = 0; pattern < 3; pattern++) {
					ssize_t n;

					for (size_t bi = 0; bi < len; bi++)
						body[bi] = pattern == 0 ? 0 :
						    pattern == 1 ? 0xff : (uint8_t)bi;
					if (len >= 2)
						ipc_put_le16(body, (uint16_t)opcode);
					(void)dispatch_domain_request(client, sp[1],
					    sweeps[si].domain, body, len);
					do {
						n = recv(sp[1], body, sizeof(body), 0);
					} while (n > 0);
				}
			}
		}
	}

	LIST_REMOVE(client, entries);
	LIST_REMOVE(&adp, entries);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_typed_security_valid_matrix);
ATF_TC_BODY(test_typed_security_valid_matrix, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct blued_conn *conn;
	struct att_conn att;
	struct smp_bond_db bond_db;
	char feat[128];
	uint8_t body[512];
	int sp[2];

	test_init();
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.powered = true;
	adp.hci_fd = 42;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->adapter = &adp;
	conn->addr_type = BDADDR_LE_PUBLIC;
	conn->role = BLUED_ROLE_CENTRAL;
	memset(&att, 0, sizeof(att));
	att.encrypted = 1;
	att.authenticated = 1;
	att.enc_key_size = 16;
	conn->att = &att;
	memset(&bond_db, 0, sizeof(bond_db));
	bond_db.count = 2;
	bond_db.bonds[0].addr_type = BDADDR_LE_PUBLIC;
	bond_db.bonds[0].has_ltk = true;
	bond_db.bonds[0].has_irk = true;
	bond_db.bonds[0].has_csrk = true;
	bond_db.bonds[0].has_link_key = true;
	bond_db.bonds[0].is_sc = true;
	bond_db.bonds[0].is_mitm = true;
	bond_db.bonds[0].has_name = true;
	bond_db.bonds[0].key_size = 16;
	strlcpy(bond_db.bonds[0].name, "typed-security",
	    sizeof(bond_db.bonds[0].name));
	bond_db.bonds[1].addr_type = BDADDR_LE_RANDOM;
	memset(bond_db.bonds[1].addr, 0x44,
	    sizeof(bond_db.bonds[1].addr));
	memset(&adp.reslist, 0, sizeof(adp.reslist));
	ATF_REQUIRE_EQ(1, blued_reslist_add(&adp.reslist,
	    bond_db.bonds[0].addr, bond_db.bonds[0].addr_type));
	client = make_client(sp);
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS,
	    feat, sizeof(feat));

	/* Absence and controller failures are observable through the wire API. */
	memset(body, 0, IPC_SECURITY_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_UNBOND);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	ipc_put_le16(body, IPC_SECURITY_REKEY);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));

	ipc_put_le16(body, IPC_SECURITY_OOB_GENERATE);
	ctl_test_oob_generate_rc = -1;
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	ctl_test_oob_generate_rc = 0;

	/* Fill the eight-entry peer OOB cache, observe saturation, then clear it. */
	for (int i = 0; i < 9; i++) {
		memset(body, 0, IPC_SECURITY_OOB_LEGACY_REQ_SIZE);
		ipc_put_le16(body, IPC_SECURITY_OOB_INJECT_LEGACY);
		body[5] = (uint8_t)(i + 1);
		ATF_CHECK_EQ(i < 8 ? IPC_ERR_NONE : IPC_ERR_BUSY,
		    dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_SECURITY, body,
		    IPC_SECURITY_OOB_LEGACY_REQ_SIZE));
	}
	memset(body, 0, IPC_SECURITY_OOB_CLEAR_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_OOB_CLEAR);
	body[5] = 1;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_OOB_CLEAR_REQ_SIZE));
	body[12] = IPC_SECURITY_OOB_CLEAR_F_ALL;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_OOB_CLEAR_REQ_SIZE));

	memset(body, 0, IPC_SECURITY_RESOLV_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_RESOLV_ADD);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_RESOLV_REQ_SIZE));
	body[12] = IPC_SECURITY_RESOLV_F_IRK;
	ctl_test_resolv_add_rc = -1;
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_RESOLV_REQ_SIZE));
	ctl_test_resolv_add_rc = 0;
	/*
	 * Finding 122: RESOLV_ADD whose Set Privacy Mode step fails must NOT be
	 * reported as success, and the just-added resolving-list entry must be
	 * rolled back (removed) so the shadow and controller stay consistent.
	 */
	ctl_test_set_privacy_mode_rc = -1;
	ctl_test_resolv_remove_calls = 0;
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_RESOLV_REQ_SIZE));
	ATF_CHECK(ctl_test_resolv_remove_calls > 0);
	ctl_test_set_privacy_mode_rc = 0;
	body[12] = 0;
	ipc_put_le16(body, IPC_SECURITY_RESOLV_REMOVE);
	ctl_test_resolv_remove_rc = -1;
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_RESOLV_REQ_SIZE));
	ctl_test_resolv_remove_rc = 0;
	ipc_put_le16(body, IPC_SECURITY_RESOLV_CLEAR);
	ctl_test_resolv_clear_rc = -1;
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_RESOLV_REQ_SIZE));
	ctl_test_resolv_clear_rc = 0;
	LIST_REMOVE(&adp, entries);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_RESOLV_REQ_SIZE));
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	/* Connection-dependent verbs still take their complete valid shape. */
	for (int opcode = IPC_SECURITY_PAIR; opcode <= IPC_SECURITY_REKEY;
	    opcode++) {
		size_t len = IPC_SECURITY_REQ_SIZE;

		if (opcode == IPC_SECURITY_PASSKEY_REPLY)
			len = IPC_SECURITY_PASSKEY_REQ_SIZE;
		else if (opcode == IPC_SECURITY_NUMCMP_REPLY ||
		    opcode == IPC_SECURITY_REGISTER_AGENT)
			len = IPC_SECURITY_AGENT_REQ_SIZE;
		memset(body, 0, len);
		ipc_put_le16(body, (uint16_t)opcode);
		if (opcode == IPC_SECURITY_REGISTER_AGENT)
			body[12] = 4;
		(void)dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_SECURITY, body, len);
	}
	blued_g.bond_db = &bond_db;
	ctl_test_found_bond = &bond_db.bonds[0];
	ctl_test_bond_save_rc = 0;

	/* Exact agent-reply shapes drive success and already-replied outcomes. */
	conn->passkey_reply_status = 0;
	memset(body, 0, IPC_SECURITY_PASSKEY_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_PASSKEY_REPLY);
	ipc_put_le32(body + 12, 654321);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_PASSKEY_REQ_SIZE));
	ATF_CHECK_EQ(654321u, conn->passkey_reply);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_PASSKEY_REQ_SIZE));
	conn->numcmp_reply_status = 0;
	memset(body, 0, IPC_SECURITY_DECISION_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_NUMCMP_REPLY);
	body[12] = 1;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_DECISION_REQ_SIZE));
	ATF_CHECK(conn->numcmp_reply);

	/* A bonded central rekey propagates both pairing failure and success. */
	conn->hogp = (struct hogp_device *)(uintptr_t)1;
	memset(body, 0, IPC_SECURITY_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_REKEY);
	ctl_test_start_pairing_rc = -1;
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	ctl_test_start_pairing_rc = 0;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));

	/* Read-only replies exercise their structured success payloads. */
	for (int opcode = IPC_SECURITY_GET_POLICY;
	    opcode <= IPC_SECURITY_GET_INFO; opcode++) {
		memset(body, 0, IPC_SECURITY_REQ_SIZE);
		ipc_put_le16(body, (uint16_t)opcode);
		(void)dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE);
	}

	memset(body, 0, IPC_SECURITY_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_OOB_GENERATE);
	(void)dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_SECURITY,
	    body, IPC_SECURITY_REQ_SIZE);

	memset(body, 0xa5, IPC_SECURITY_OOB_SC_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_OOB_INJECT_SC);
	ipc_put_le16(body + 2, 0);
	body[4] = 0;
	body[11] = 0;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_OOB_SC_REQ_SIZE));

	memset(body, 0, IPC_SECURITY_OOB_CLEAR_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_OOB_CLEAR);
	body[12] = IPC_SECURITY_OOB_CLEAR_F_ALL;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_OOB_CLEAR_REQ_SIZE));

	/* Resolve an IRK from the bond, then repeat with a supplied IRK. */
	memset(body, 0, IPC_SECURITY_RESOLV_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_RESOLV_ADD);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_RESOLV_REQ_SIZE));

	/* Add with a supplied IRK, remove it, then clear the controller list. */
	for (int opcode = IPC_SECURITY_RESOLV_ADD;
	    opcode <= IPC_SECURITY_RESOLV_CLEAR; opcode++) {
		memset(body, 0, IPC_SECURITY_RESOLV_REQ_SIZE);
		ipc_put_le16(body, (uint16_t)opcode);
		if (opcode == IPC_SECURITY_RESOLV_ADD) {
			body[12] = IPC_SECURITY_RESOLV_F_IRK;
			memset(body + 16, 0x5a, 16);
		}
		ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_RESOLV_REQ_SIZE));
	}

	for (int opcode = IPC_SECURITY_BOND_LIST;
	    opcode <= IPC_SECURITY_RESOLV_LIST; opcode++) {
		memset(body, 0, IPC_SECURITY_REQ_SIZE);
		ipc_put_le16(body, (uint16_t)opcode);
		ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	}

	/* Export the populated record, then verify transactional unbond rollback. */
	memset(body, 0, IPC_SECURITY_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_BOND_EXPORT);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	ipc_put_le16(body, IPC_SECURITY_UNBOND);
	ctl_test_bond_save_rc = -1;
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	ATF_CHECK_EQ(2, bond_db.count);
	ctl_test_bond_save_rc = 0;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	ATF_CHECK_EQ(1, bond_db.count);

	/* Protocol and privilege failures plus a complete policy update. */
	memset(body, 0, sizeof(body));
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, 1));
	ipc_put_le16(body, IPC_SECURITY_PAIR);
	client->peer_uid = 1000;
	ATF_CHECK_EQ(IPC_ERR_PERM, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	client->peer_uid = 0;
	ipc_put_le16(body + 2, 1);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));

	memset(body, 0, IPC_SECURITY_POLICY_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_SET_POLICY);
	ipc_put_le16(body + 12, IPC_SECURITY_POLICY_F_ALL);
	body[14] = 1; body[15] = 1; body[16] = 2; body[17] = 1;
	body[18] = 4; body[19] = 3; body[20] = 16; body[21] = 7;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_POLICY_REQ_SIZE));
	ATF_CHECK(blued_cfg.mitm);
	ATF_CHECK(blued_cfg.bondable);
	ATF_CHECK_EQ(2, blued_cfg.sc_mode);
	ATF_CHECK(blued_cfg.keypress);
	ATF_CHECK_EQ(4, blued_cfg.io_capability);
	ATF_CHECK_EQ(3, blued_cfg.min_pairing_security);
	ATF_CHECK_EQ(16, blued_cfg.min_key_size);
	ATF_CHECK_EQ(7, blued_cfg.key_dist);
	body[20] = 6;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_POLICY_REQ_SIZE));

	/* A valid encoded import reaches duplicate/full database handling. */
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_SECURITY_BOND_IMPORT);
	{
		size_t record_len = smp_bond_export_record(&bond_db.bonds[0],
		    body + IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE,
		    sizeof(body) - IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE);
		if (record_len != 0) {
			ipc_put_le16(body + 12, (uint16_t)record_len);
			ctl_test_import_rc = -1;
			ATF_CHECK_EQ(IPC_ERR_BUSY, dispatch_domain_request(client,
			    sp[1], IPC_OP_DOMAIN_SECURITY, body,
			    IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE + record_len));
			ctl_test_import_rc = 1;
			ctl_test_import_has_irk = true;
			ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client,
			    sp[1], IPC_OP_DOMAIN_SECURITY, body,
			    IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE + record_len));
			ATF_CHECK(ctl_test_reslist_add_calls > 0);
			ctl_test_import_has_irk = false;
		}
	}
	ipc_put_le16(body, 0x7fff);
	ATF_CHECK_EQ(IPC_ERR_UNKNOWN_CMD, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));

	/*
	 * Finding 135: Filter Accept List verbs.  ADD/REMOVE program every
	 * powered adapter and update the persisted shadow; a controller failure
	 * surfaces as IPC_ERR_IO; CLEAR drops only the runtime entries; LIST
	 * returns the shadow snapshot.
	 */
	ctl_test_accept_add_rc = 0;
	ctl_test_accept_add_calls = ctl_test_accept_remove_calls = 0;
	ctl_test_acceptlist_record_calls = ctl_test_acceptlist_forget_calls = 0;
	ctl_test_acceptlist_clear_calls = 0;
	memset(body, 0, IPC_SECURITY_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_ACCEPT_ADD);
	body[5] = 0x77;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	ATF_CHECK(ctl_test_accept_add_calls > 0);
	ATF_CHECK(ctl_test_acceptlist_record_calls > 0);

	ctl_test_accept_add_rc = -1;	/* controller add fails */
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	ctl_test_accept_add_rc = 0;

	ipc_put_le16(body, IPC_SECURITY_ACCEPT_REMOVE);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	ATF_CHECK(ctl_test_accept_remove_calls > 0);
	ATF_CHECK(ctl_test_acceptlist_forget_calls > 0);

	ipc_put_le16(body, IPC_SECURITY_ACCEPT_CLEAR);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	ATF_CHECK(ctl_test_acceptlist_clear_calls > 0);

	/* LIST returns the snapshot count on the wire. */
	ctl_test_acceptlist_snapshot_count = 3;
	{
		uint8_t req[IPC_OP_PREFIX_SIZE + IPC_SECURITY_REQ_SIZE];
		uint8_t reply[512];
		uint16_t type, dom;
		size_t plen;

		client->handshaked = true;
		memset(req, 0, sizeof(req));
		ipc_op_prefix_encode(req, ++ipc_test_request_id, 0, 0);
		ipc_put_le16(req + IPC_OP_PREFIX_SIZE, IPC_SECURITY_ACCEPT_LIST);
		ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_SECURITY, req,
		    sizeof(req));
		ATF_REQUIRE_EQ(0, blued_ctl_dispatch(client));
		plen = ipc_recv(sp[1], &type, &dom, reply, sizeof(reply));
		ATF_CHECK_EQ(IPC_T_OP_REPLY, type);
		ATF_CHECK_EQ(IPC_OP_DOMAIN_SECURITY, dom);
		ATF_REQUIRE(plen >= IPC_OP_PREFIX_SIZE +
		    IPC_SECURITY_ACCEPT_REPLY_HDR_SIZE);
		ATF_CHECK_EQ(IPC_SECURITY_ACCEPT_LIST,
		    ipc_get_le16(reply + IPC_OP_PREFIX_SIZE));
		ATF_CHECK_EQ(3, ipc_get_le16(reply + IPC_OP_PREFIX_SIZE + 2));
	}
	ctl_test_acceptlist_snapshot_count = 0;

	/*
	 * Finding 138: a RESOLV_ADD carrying a client-supplied IRK persists a
	 * runtime entry; REMOVE forgets it; CLEAR drops all runtime entries.
	 */
	ctl_test_runtime_resolv_record_calls = 0;
	ctl_test_runtime_resolv_forget_calls = 0;
	ctl_test_runtime_resolv_clear_calls = 0;
	memset(body, 0, IPC_SECURITY_RESOLV_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_RESOLV_ADD);
	body[12] = IPC_SECURITY_RESOLV_F_IRK;
	memset(body + 16, 0x5a, 16);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_RESOLV_REQ_SIZE));
	ATF_CHECK(ctl_test_runtime_resolv_record_calls > 0);
	ipc_put_le16(body, IPC_SECURITY_RESOLV_REMOVE);
	body[12] = 0;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_RESOLV_REQ_SIZE));
	ATF_CHECK(ctl_test_runtime_resolv_forget_calls > 0);
	ipc_put_le16(body, IPC_SECURITY_RESOLV_CLEAR);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_RESOLV_REQ_SIZE));
	ATF_CHECK(ctl_test_runtime_resolv_clear_calls > 0);

	/* No active adapter -> accept-list ADD reports NOT_FOUND. */
	adp.active = false;
	ipc_put_le16(body, IPC_SECURITY_ACCEPT_ADD);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	adp.active = true;

	/* Exercise every connection-state arm of the typed EATT broker. */
	memset(body, 0, IPC_L2CAP_REQ_SIZE);
	ipc_put_le16(body, IPC_L2CAP_EATT_OPEN);
	body[11] = 1;
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_L2CAP, body, IPC_L2CAP_REQ_SIZE));
	att.eatt_count = 1;
	ATF_CHECK_EQ(IPC_ERR_BUSY, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_L2CAP, body, IPC_L2CAP_REQ_SIZE));
	att.eatt_count = 0;
	att.encrypted = 0;
	ATF_CHECK_EQ(IPC_ERR_PERM, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_L2CAP, body, IPC_L2CAP_REQ_SIZE));
	att.encrypted = 1;
	ipc_put_le16(body, IPC_L2CAP_EATT_CLOSE);
	body[11] = 0;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_L2CAP, body, IPC_L2CAP_REQ_SIZE));

	LIST_REMOVE(client, entries);
	conn->att = NULL;
	blued_conn_free(conn);
	blued_g.bond_db = NULL;
	ctl_test_found_bond = NULL;
	LIST_REMOVE(&adp, entries);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_typed_validation_operand_matrix);
ATF_TC_BODY(test_typed_validation_operand_matrix, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	char feat[128];
	uint8_t body[512];
	uint16_t policy_fields[] = {
		IPC_SECURITY_POLICY_F_MITM,
		IPC_SECURITY_POLICY_F_BONDING,
		IPC_SECURITY_POLICY_F_SC,
		IPC_SECURITY_POLICY_F_KEYPRESS,
		IPC_SECURITY_POLICY_F_IO_CAP,
		IPC_SECURITY_POLICY_F_MIN_SEC,
		IPC_SECURITY_POLICY_F_KEY_SIZE,
		IPC_SECURITY_POLICY_F_KEY_DIST,
	};
	int sp[2];

	test_init();
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.hci_fd = 17;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	client = make_client(sp);
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS,
	    feat, sizeof(feat));

	/* Isolate every common typed-GATT guard. */
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_READ);
	ipc_put_le16(body + 12, 1);
	ipc_put_le16(body + 2, 1);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_REQ_SIZE));
	ipc_put_le16(body + 2, 0);
	body[4] = 2;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_REQ_SIZE));
	body[4] = 0;
	body[11] = BLUED_MAX_ADAPTERS;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_REQ_SIZE));
	body[11] = 0;
	ipc_put_le16(body + 12, 0);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_REQ_SIZE));
	ipc_put_le16(body + 12, 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_REQ_SIZE - 1));
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_REQ_SIZE + 1));
	ipc_put_le16(body, IPC_GATT_DISCOVER);
	ipc_put_le16(body + 12, 0);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_REQ_SIZE + 1));

	/* Value-bearing requests: minimum size, declared limit, and exact tail. */
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_WRITE);
	ipc_put_le16(body + 12, 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_VALUE_REQ_SIZE - 1));
	ipc_put_le16(body + 14, ATT_PDU_BUF_SIZE + 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_VALUE_REQ_SIZE));
	ipc_put_le16(body + 14, 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_VALUE_REQ_SIZE));

	/* Characteristic and descriptor tails isolate every compound operand. */
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_ADD_CHARACTERISTIC);
	ipc_put_le16(body + 12, 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_ADD_CHAR_REQ_SIZE - 1));
	ipc_put_le16(body + 36, ATT_PDU_BUF_SIZE + 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_ADD_CHAR_REQ_SIZE));
	ipc_put_le16(body + 36, 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_ADD_CHAR_REQ_SIZE));
	ipc_put_le16(body + 36, 0);
	body[35] = 1;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_ADD_CHAR_REQ_SIZE));

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_ADD_DESCRIPTOR);
	ipc_put_le16(body + 12, 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_ADD_DESC_REQ_SIZE - 1));
	body[33] = 1;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_ADD_DESC_REQ_SIZE));
	body[33] = 0;
	ipc_put_le16(body + 34, ATT_PDU_BUF_SIZE + 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_ADD_DESC_REQ_SIZE));
	ipc_put_le16(body + 34, 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_ADD_DESC_REQ_SIZE));

	/* Decision requests distinguish opcode-dependent value semantics. */
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_AUTHORIZE_REPLY);
	ipc_put_le16(body + 12, 1);
	body[14] = 2;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_DECISION_REQ_SIZE));
	ipc_put_le16(body, IPC_GATT_READ_REJECT);
	body[14] = 0;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, IPC_GATT_DECISION_REQ_SIZE));

	/* Common security guards and the opcode-specific size/value guards. */
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_SECURITY_PAIR);
	ipc_put_le16(body + 2, 1);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	ipc_put_le16(body + 2, 0);
	body[4] = 2;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	body[4] = 0;
	body[11] = BLUED_MAX_ADAPTERS;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	body[11] = 0;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE + 1));

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_SECURITY_PASSKEY_REPLY);
	ipc_put_le32(body + 12, 1000000);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_PASSKEY_REQ_SIZE));
	ipc_put_le16(body, IPC_SECURITY_NUMCMP_REPLY);
	body[12] = 2;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_DECISION_REQ_SIZE));
	ipc_put_le16(body, IPC_SECURITY_REGISTER_AGENT);
	body[12] = 5;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_AGENT_REQ_SIZE));

	/* Every SET_POLICY operand is independently the failing operand. */
	for (size_t i = 0; i < nitems(policy_fields); i++) {
		memset(body, 0, IPC_SECURITY_POLICY_REQ_SIZE);
		ipc_put_le16(body, IPC_SECURITY_SET_POLICY);
		ipc_put_le16(body + 12, policy_fields[i]);
		switch (policy_fields[i]) {
		case IPC_SECURITY_POLICY_F_MITM: body[14] = 2; break;
		case IPC_SECURITY_POLICY_F_BONDING: body[15] = 2; break;
		case IPC_SECURITY_POLICY_F_SC: body[16] = 3; break;
		case IPC_SECURITY_POLICY_F_KEYPRESS: body[17] = 2; break;
		case IPC_SECURITY_POLICY_F_IO_CAP: body[18] = 5; break;
		case IPC_SECURITY_POLICY_F_MIN_SEC: body[19] = 4; break;
		case IPC_SECURITY_POLICY_F_KEY_SIZE: body[20] = 6; break;
		case IPC_SECURITY_POLICY_F_KEY_DIST: body[21] = 8; break;
		}
		ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_POLICY_REQ_SIZE));
	}
	memset(body, 0, IPC_SECURITY_POLICY_REQ_SIZE);
	ipc_put_le16(body, IPC_SECURITY_SET_POLICY);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_POLICY_REQ_SIZE));
	ipc_put_le16(body + 12, IPC_SECURITY_POLICY_F_ALL + 1);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_POLICY_REQ_SIZE));
	ipc_put_le16(body + 12, IPC_SECURITY_POLICY_F_MITM);
	body[14] = 1;
	ipc_put_le16(body + 22, 1);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_POLICY_REQ_SIZE));

	/* Typed GAP common and per-opcode compound guards. */
	memset(body, 0, sizeof(body));
	ipc_gap_req_encode(body, IPC_GAP_DISCONNECT, 0, 0,
	    (const uint8_t *)&(bdaddr_t){{0}}, 0);
	body[4] = 2;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_REQ_SIZE));
	body[4] = 0;
	body[11] = BLUED_MAX_ADAPTERS;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_REQ_SIZE));
	body[11] = 0;
	ipc_put_le16(body + 2, 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_REQ_SIZE));
	ipc_put_le16(body + 2, 0);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_REQ_SIZE + 1));

	memset(body, 0, IPC_GAP_CONNECTION_REQ_SIZE);
	ipc_put_le16(body, IPC_GAP_GET_CONNECTIONS);
	ipc_put_le16(body + 2, 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_CONNECTION_REQ_SIZE));
	ipc_put_le16(body + 2, 0);
	body[5] = 1;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_CONNECTION_REQ_SIZE));

	memset(body, 0, IPC_GAP_PATH_LOSS_REQ_SIZE);
	ipc_gap_req_encode(body, IPC_GAP_PATH_LOSS, 0, 0,
	    (const uint8_t *)&(bdaddr_t){{0}}, 0);
	body[18] = 2;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_PATH_LOSS_REQ_SIZE));
	body[18] = 0;
	body[19] = 1;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_PATH_LOSS_REQ_SIZE));

	memset(body, 0, IPC_GAP_CONNECT_REQ_SIZE);
	ipc_gap_req_encode(body, IPC_GAP_CONNECT, 0x8000, 0,
	    (const uint8_t *)&(bdaddr_t){{0}}, 0);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_CONNECT_REQ_SIZE));
	ipc_put_le16(body + 2, 0);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_CONNECT_REQ_SIZE - 1));

	LIST_REMOVE(client, entries);
	LIST_REMOVE(&adp, entries);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_typed_gap_valid_matrix);
ATF_TC_BODY(test_typed_gap_valid_matrix, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp, other_adp;
	struct blued_conn *conn;
	struct blued_conn *created;
	struct blued_conn *fill[BLUED_MAX_CONNS];
	struct att_conn att;
	struct ctl_connect_params connect_params;
	struct ctl_scan_params scan_params;
	bdaddr_t new_addr, found_addr, missing_addr;
	char feat[128];
	uint8_t body[64], addr[6];
	uint8_t scan_req[IPC_OP_PREFIX_SIZE + IPC_GAP_SCAN_REQ_SIZE];
	uint8_t scan_reply[256];
	uint32_t request_id, got_id;
	uint16_t type, domain, status, flags, nadp, nconn, nclients, status_flags;
	uint8_t found_type;
	size_t plen;
	int sp[2], nfill;

	test_init();
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.powered = true;
	adp.hci_fd = 17;
	adp.le_features = UINT64_MAX;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &conn->dst));
	memcpy(addr, &conn->dst, sizeof(addr));
	conn->addr_type = 1;
	conn->adapter = &adp;
	conn->con_handle = 0x40;
	conn->con_handle_valid = true;
	conn->role = BLUED_ROLE_PERIPHERAL;
	conn->conn_interval = 12;
	conn->conn_latency = 1;
	conn->supervision_timeout = 200;
	atomic_store(&conn->state, BLUED_CONN_ACTIVE);
	memset(&att, 0, sizeof(att));
	att.mtu = 185;
	att.encrypted = 1;
	att.authenticated = 1;
	att.enc_key_size = 16;
	conn->att = &att;

	client = make_client(sp);
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS,
	    feat, sizeof(feat));

	/* Serialize scan events at both UUID-count bounds and a named result. */
	adap_cap_reset();
	adap_cap.scan_nresults = 3;
	for (int i = 0; i < adap_cap.scan_nresults; i++) {
		adap_cap.scan_results[i].addr_type = (i & 1) != 0 ?
		    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
		memset(adap_cap.scan_results[i].addr, i + 1, 6);
		adap_cap.scan_results[i].rssi = -20 - i;
		adap_cap.scan_results[i].mfr_id = (uint16_t)(0x100 + i);
	}
	adap_cap.scan_results[0].num_svc_uuids = -1;
	adap_cap.scan_results[1].num_svc_uuids = 12;
	for (int i = 0; i < 8; i++)
		adap_cap.scan_results[1].svc_uuids[i] = (uint16_t)(0x1800 + i);
	adap_cap.scan_results[2].num_svc_uuids = 1;
	adap_cap.scan_results[2].svc_uuids[0] = 0x180f;
	adap_cap.scan_results[2].has_name = true;
	memset(adap_cap.scan_results[2].name, 'n',
	    sizeof(adap_cap.scan_results[2].name));
	memset(body, 0, IPC_GAP_SCAN_REQ_SIZE);
	ipc_put_le16(body, IPC_GAP_SCAN);
	ipc_put_le16(body + 4, 16);
	ipc_put_le16(body + 6, 16);
	body[10] = (uint8_t)-127;
	request_id = ++ipc_test_request_id;
	ipc_op_prefix_encode(scan_req, request_id, 0, 0);
	memcpy(scan_req + IPC_OP_PREFIX_SIZE, body, IPC_GAP_SCAN_REQ_SIZE);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_GAP, scan_req,
	    sizeof(scan_req));
	ATF_REQUIRE_EQ(0, blued_ctl_dispatch(client));
	for (int i = 0; i < 3; i++) {
		plen = ipc_recv(sp[1], &type, &domain, (char *)scan_reply,
		    sizeof(scan_reply));
		ATF_REQUIRE_EQ(IPC_T_OP_EVENT, type);
		ATF_REQUIRE_EQ(IPC_OP_DOMAIN_GAP, domain);
		ATF_REQUIRE(plen >= IPC_OP_PREFIX_SIZE);
		ipc_op_prefix_decode(scan_reply, &got_id, &status, &flags);
		ATF_CHECK_EQ(request_id, got_id);
		ATF_CHECK_EQ(IPC_ERR_NONE, status);
	}
	plen = ipc_recv(sp[1], &type, &domain, (char *)scan_reply,
	    sizeof(scan_reply));
	ATF_REQUIRE_EQ(IPC_T_OP_REPLY, type);
	ATF_REQUIRE_EQ(IPC_OP_DOMAIN_GAP, domain);
	ipc_op_prefix_decode(scan_reply, &got_id, &status, &flags);
	ATF_CHECK_EQ(request_id, got_id);
	ATF_CHECK_EQ(IPC_ERR_NONE, status);

	memset(body, 0, IPC_GAP_PHY_REQ_SIZE);
	ipc_gap_req_encode(body, IPC_GAP_SET_PHY, 0, 0, addr, 0);
	body[12] = 1;
	body[13] = 2;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_PHY_REQ_SIZE));

	memset(body, 0, IPC_GAP_DATA_LEN_REQ_SIZE);
	ipc_gap_req_encode(body, IPC_GAP_SET_DATA_LEN, 0, 0, addr, 0);
	ipc_put_le16(body + 12, 100);
	ipc_put_le16(body + 14, 1000);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_DATA_LEN_REQ_SIZE));

	memset(body, 0, IPC_GAP_CONN_UPDATE_REQ_SIZE);
	ipc_gap_req_encode(body, IPC_GAP_CONN_UPDATE, 0, 0, addr, 0);
	ipc_put_le16(body + 12, 6);
	ipc_put_le16(body + 14, 12);
	ipc_put_le16(body + 16, 0);
	ipc_put_le16(body + 18, 200);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_CONN_UPDATE_REQ_SIZE));

	memset(body, 0, IPC_GAP_PATH_LOSS_REQ_SIZE);
	ipc_gap_req_encode(body, IPC_GAP_PATH_LOSS, 0, 0, addr, 0);
	body[12] = 0x20;
	body[13] = 2;
	body[14] = 0x60;
	body[15] = 4;
	ipc_put_le16(body + 16, 10);
	body[18] = 1;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_PATH_LOSS_REQ_SIZE));

	/* Snapshot serializes connection, security, role, MTU, and timing. */
	memset(body, 0, IPC_GAP_CONNECTION_REQ_SIZE);
	ipc_put_le16(body, IPC_GAP_GET_CONNECTIONS);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_CONNECTION_REQ_SIZE));

	/* A complete connect request reaches the existing-connection result. */
	memset(body, 0, IPC_GAP_CONNECT_REQ_SIZE);
	ipc_gap_req_encode(body, IPC_GAP_CONNECT,
	    IPC_GAP_F_CONN_PARAMS | IPC_GAP_F_PHY, 0, addr, 0);
	ipc_put_le16(body + 12, 6);
	ipc_put_le16(body + 14, 12);
	ipc_put_le16(body + 16, 0);
	ipc_put_le16(body + 18, 200);
	body[20] = 1;
	body[21] = 1;
	(void)dispatch_domain_request(client, sp[1], IPC_OP_DOMAIN_GAP,
	    body, IPC_GAP_CONNECT_REQ_SIZE);

	/* Direct result APIs cover validation and the no-live-handle states. */
	ctl_status_snapshot(&nadp, &nconn, &nclients, &status_flags);
	ATF_CHECK_EQ(1, nadp);
	ATF_CHECK(nconn >= 1);
	ATF_CHECK_EQ(1, nclients);
	adp.active = false;
	ctl_status_snapshot(&nadp, &nconn, &nclients, &status_flags);
	ATF_CHECK_EQ(0, nadp);
	adp.active = true;
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_set_phy_result(0, &conn->dst, 1,
	    0x80, 1));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_set_data_len_result(0, &conn->dst, 1,
	    1, 1));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connparams_update_result(0, &conn->dst,
	    1, 20, 10, 0, 100));
	conn->con_handle = 0;
	conn->con_handle_valid = false;
	ATF_CHECK_EQ(IPC_ERR_NOT_CONN, ctl_set_phy_result(0, &conn->dst, 1,
	    1, 1));
	ATF_CHECK_EQ(IPC_ERR_NOT_CONN, ctl_set_data_len_result(0, &conn->dst, 1,
	    100, 1000));
	ATF_CHECK_EQ(IPC_ERR_NOT_CONN, ctl_connparams_update_result(0,
	    &conn->dst, 1, 6, 12, 0, 100));
	conn->con_handle = 0x40;
	conn->con_handle_valid = true;
	adp.le_features = 0;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_path_loss_result(0, &conn->dst, 1,
	    1, 0, 2, 0, 1, true));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connparams_update_result(0, &conn->dst,
	    1, 6, 12, 0, 100));
	adp.le_features = UINT64_MAX;
	advconn_cap.connupd_rc = -1;
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connparams_update_result(0,
	    &conn->dst, 1, 6, 12, 0, 100));
	advconn_cap.connupd_rc = 0;
	/* HCI LE Set PHY permits either preference mask to be zero.  In that
	 * case all_phys requests the controller retain that direction's current
	 * PHY, per Core Spec Vol 2 Part E, LE Set PHY. */
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_set_phy_result(0, &conn->dst, 1, 0, 0));
	ATF_CHECK_EQ(0x03, advconn_cap.setphy_all);
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_set_phy_result(0, &conn->dst, 1, 0, 1));
	ATF_CHECK_EQ(0x01, advconn_cap.setphy_all);
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_set_phy_result(0, &conn->dst, 1, 1, 0));
	ATF_CHECK_EQ(0x02, advconn_cap.setphy_all);

	/* Complete direct connection-management validation/error mapping. */
	memset(&missing_addr, 0x55, sizeof(missing_addr));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connect_result(&missing_addr, 7, &adp,
	    NULL));
	memset(&connect_params, 0, sizeof(connect_params));
	connect_params.has_conn_params = true;
	connect_params.interval_min = 5;
	connect_params.interval_max = 12;
	connect_params.timeout = 100;
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connect_result(&missing_addr,
	    BDADDR_LE_PUBLIC, &adp, &connect_params));
	connect_params.interval_min = 6;
	connect_params.interval_max = 0x0c81;
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connect_result(&missing_addr,
	    BDADDR_LE_PUBLIC, &adp, &connect_params));
	connect_params.interval_min = 12;
	connect_params.interval_max = 6;
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connect_result(&missing_addr,
	    BDADDR_LE_PUBLIC, &adp, &connect_params));
	connect_params.interval_max = 6;
	connect_params.interval_min = 6;
	connect_params.timeout = 9;
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connect_result(&missing_addr,
	    BDADDR_LE_PUBLIC, &adp, &connect_params));
	memset(&connect_params, 0, sizeof(connect_params));
	connect_params.has_phy = true;
	connect_params.tx_phys = 0x80;
	connect_params.rx_phys = 1;
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connect_result(&missing_addr,
	    BDADDR_LE_PUBLIC, &adp, &connect_params));
	connect_params.tx_phys = 1;
	connect_params.rx_phys = 0x80;
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connect_result(&missing_addr,
	    BDADDR_LE_PUBLIC, &adp, &connect_params));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_set_data_len_result(0, &conn->dst, 1,
	    0x001b, 0x0147));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_set_data_len_result(0, &conn->dst, 1,
	    0x00fc, 0x0148));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_set_data_len_result(0, &conn->dst, 1,
	    0x001b, 0x4291));
	adp.active = false;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_connect_result(&missing_addr,
	    BDADDR_LE_PUBLIC, NULL, NULL));
	adp.active = true;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_set_phy_result(0, &missing_addr,
	    BDADDR_LE_PUBLIC, 1, 1));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_set_data_len_result(0, &missing_addr,
	    BDADDR_LE_PUBLIC, 100, 1000));
	advconn_cap.setphy_rc = -1;
	ATF_CHECK_EQ(IPC_ERR_IO, ctl_set_phy_result(0, &conn->dst, 1, 1, 1));
	advconn_cap.setphy_rc = 0;
	advconn_cap.setdlen_rc = -1;
	ATF_CHECK_EQ(IPC_ERR_IO, ctl_set_data_len_result(0, &conn->dst, 1,
	    100, 1000));
	advconn_cap.setdlen_rc = 0;
	blued_conn_set_state(conn, BLUED_CONN_CONNECTING);
	ATF_CHECK_EQ(IPC_ERR_BUSY, ctl_disconnect_result(0, &conn->dst, 1));
	blued_conn_set_state(conn, BLUED_CONN_ACTIVE);
	conn->reconnect = true;
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_disconnect_result(0, &conn->dst, 1));
	ATF_CHECK(!conn->reconnect);
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connect_name_result(NULL, &adp,
	    &found_addr, &found_type));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connect_name_result("", &adp,
	    &found_addr, &found_type));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connect_name_result(
	    "01234567890123456789012345678901", &adp, &found_addr,
	    &found_type));
	adp.active = false;
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connect_name_result("named-peer", &adp,
	    &found_addr, &found_type));
	adp.active = true;
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connect_name_result("named-peer", &adp,
	    NULL, &found_type));
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_connect_name_result("named-peer", &adp,
	    &found_addr, NULL));
	ctl_test_hogp_fail_errno = ENOSPC;
	ATF_CHECK_EQ(IPC_ERR_BUSY, ctl_connect_result(&missing_addr,
	    BDADDR_LE_PUBLIC, &adp, NULL));
	ctl_test_hogp_fail_errno = 0;
	for (nfill = 0; nfill < BLUED_MAX_CONNS; nfill++) {
		fill[nfill] = blued_conn_alloc();
		if (fill[nfill] == NULL)
			break;
	}
	ATF_CHECK_EQ(IPC_ERR_NOMEM, ctl_connect_result(&missing_addr,
	    BDADDR_LE_PUBLIC, &adp, NULL));
	while (nfill > 0)
		blued_conn_free(fill[--nfill]);

	/* Successful direct connect preserves requested parameters and PHY. */
	memset(&new_addr, 0x77, sizeof(new_addr));
	memset(&connect_params, 0, sizeof(connect_params));
	connect_params.has_conn_params = true;
	connect_params.interval_min = 6;
	connect_params.interval_max = 12;
	connect_params.latency = 1;
	connect_params.timeout = 100;
	connect_params.has_phy = true;
	connect_params.tx_phys = 1;
	connect_params.rx_phys = 2;
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_connect_result(&new_addr,
	    BDADDR_LE_RANDOM, &adp, &connect_params));
	created = blued_conn_by_peer(&adp, &new_addr, BDADDR_LE_RANDOM);
	ATF_REQUIRE(created != NULL);
	ATF_CHECK(created->has_req_conn_params);
	ATF_CHECK(created->has_req_phy);
	free(created->hogp);
	created->hogp = NULL;
	blued_conn_free(created);
	blued_conn_unref(created);

	/* Name discovery feeds its exact-match result into the same connect path. */
	adap_cap_reset();
	adap_cap.scan_nresults = 1;
	memset(adap_cap.scan_results[0].addr, 0x66, 6);
	adap_cap.scan_results[0].addr_type = BDADDR_LE_PUBLIC;
	adap_cap.scan_results[0].has_name = true;
	strlcpy(adap_cap.scan_results[0].name, "named-peer",
	    sizeof(adap_cap.scan_results[0].name));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_connect_name_result("named-peer", &adp,
	    &found_addr, &found_type));
	ATF_CHECK_EQ(BDADDR_LE_PUBLIC, found_type);
	created = blued_conn_by_peer(&adp, &found_addr, found_type);
	ATF_REQUIRE(created != NULL);
	free(created->hogp);
	created->hogp = NULL;
	blued_conn_free(created);
	blued_conn_unref(created);

	/* Name resolution must ignore unnamed and non-matching advertisements
	 * before accepting a case-insensitive complete-name match. */
	adap_cap_reset();
	adap_cap.scan_nresults = 4;
	memset(adap_cap.scan_results[0].addr, 0x31, 6);
	adap_cap.scan_results[0].addr_type = BDADDR_LE_PUBLIC;
	memset(adap_cap.scan_results[1].addr, 0x32, 6);
	adap_cap.scan_results[1].addr_type = BDADDR_LE_PUBLIC;
	adap_cap.scan_results[1].has_name = true;
	strlcpy(adap_cap.scan_results[1].name, "other-peer",
	    sizeof(adap_cap.scan_results[1].name));
	memset(adap_cap.scan_results[2].addr, 0x33, 6);
	adap_cap.scan_results[2].addr_type = BDADDR_LE_RANDOM;
	adap_cap.scan_results[2].has_name = true;
	strlcpy(adap_cap.scan_results[2].name, "case-peer",
	    sizeof(adap_cap.scan_results[2].name));
	/* A later duplicate must not replace the first matching peer selected
	 * from this scan burst. */
	memset(adap_cap.scan_results[3].addr, 0x34, 6);
	adap_cap.scan_results[3].addr_type = BDADDR_LE_PUBLIC;
	adap_cap.scan_results[3].has_name = true;
	strlcpy(adap_cap.scan_results[3].name, "case-peer",
	    sizeof(adap_cap.scan_results[3].name));
	ATF_REQUIRE_EQ(IPC_ERR_NONE, ctl_connect_name_result("case-peer", &adp,
	    &found_addr, &found_type));
	ATF_CHECK_EQ(BDADDR_LE_RANDOM, found_type);
	ATF_CHECK_EQ(0x33, ((const uint8_t *)&found_addr)[0]);
	created = blued_conn_by_peer(&adp, &found_addr, found_type);
	ATF_REQUIRE(created != NULL);
	free(created->hogp);
	created->hogp = NULL;
	blued_conn_free(created);
	blued_conn_unref(created);

	adap_cap_reset();
	adap_cap.scan_nresults = 2;
	adap_cap.scan_results[0].num_svc_uuids = 1;
	adap_cap.scan_results[0].svc_uuids[0] = 0x180f;
	adap_cap.scan_results[0].rssi = -30;
	adap_cap.scan_results[0].has_name = true;
	strlcpy(adap_cap.scan_results[0].name, "sensor-one",
	    sizeof(adap_cap.scan_results[0].name));
	adap_cap.scan_results[1].rssi = -100;
	memset(&scan_params, 0, sizeof(scan_params));
	scan_params.uuid16 = 0x180f;
	scan_params.rssi_min = -40;
	strlcpy(scan_params.name_sub, "sensor",
	    sizeof(scan_params.name_sub));
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_scan_result(&scan_params, &adp, NULL,
	    NULL));

	memset(&scan_params, 0, sizeof(scan_params));
	scan_params.interval = 3;
	ATF_CHECK_EQ(IPC_ERR_INVAL, ctl_scan_result(&scan_params, &adp, NULL,
	    NULL));

	/* Scan traversal, extended fallback, and hard-failure arms. */
	memset(&scan_params, 0, sizeof(scan_params));
	scan_params.rssi_min = INT8_MIN;
	adp.active = false;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_scan_result(&scan_params, NULL,
	    NULL, NULL));
	adp.active = true;
	memset(&other_adp, 0, sizeof(other_adp));
	other_adp.active = true;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_scan_result(&scan_params,
	    &other_adp, NULL, NULL));
	adap_cap_reset();
	adap_cap.ext_scan_rc = -1;
	adap_cap.scan_nresults = 1;
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_scan_result(&scan_params, &adp, NULL,
	    NULL));
	adap_cap_reset();
	adap_cap.ext_scan_rc = -1;
	adap_cap.scan_rc = -1;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_scan_result(&scan_params, &adp,
	    NULL, NULL));
	/* The compact API permits default scan parameters.  Cover that path and
	 * the no-dedup mapping independently of the filtered-scan case above. */
	adap_cap_reset();
	adap_cap.scan_nresults = 1;
	adp.le_features = LE_FEAT_EXT_ADVERTISING; /* no coded-PHY support */
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_scan_result(NULL, &adp, NULL, NULL));
	memset(&scan_params, 0, sizeof(scan_params));
	scan_params.rssi_min = INT8_MIN;
	scan_params.no_dedup = true;
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_scan_result(&scan_params, &adp, NULL,
	    NULL));
	ATF_CHECK_EQ(0, adap_cap.scan_params.filter_dup);
	/* Controllers without extended advertising support use the legacy LE
	 * scan command directly; this is a normal interoperable fallback, not an
	 * extended-scan failure path. */
	adp.le_features = 0;
	ATF_CHECK_EQ(IPC_ERR_NONE, ctl_scan_result(&scan_params, &adp, NULL,
	    NULL));
	adp.le_features = UINT64_MAX;
	adap_cap_reset();
	adap_cap.ext_scan_rc = -1;
	adap_cap.scan_rc = -1;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_connect_name_result("scan-io-fails",
	    &adp, &found_addr, &found_type));
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, ctl_connect_name_result("scan-fails",
	    &adp, &found_addr, &found_type));
	adap_cap_reset();
	adap_cap.scan_nresults = 1;
	memcpy(adap_cap.scan_results[0].addr, &conn->dst, 6);
	adap_cap.scan_results[0].addr_type = conn->addr_type;
	adap_cap.scan_results[0].has_name = true;
	strlcpy(adap_cap.scan_results[0].name, "already-connected",
	    sizeof(adap_cap.scan_results[0].name));
	ATF_CHECK_EQ(IPC_ERR_BUSY, ctl_connect_name_result("already-connected",
	    &adp, &found_addr, &found_type));
	conn->con_handle = 0;
	conn->con_handle_valid = false;
	ATF_CHECK_EQ(IPC_ERR_NOT_CONN, ctl_path_loss_result(0, &conn->dst, 1,
	    1, 0, 2, 0, 1, true));
	conn->con_handle = 0x40;
	conn->con_handle_valid = true;

	/* Typed GAP protocol, privilege, correlation, and error reply matrix. */
	memset(body, 0, sizeof(body));
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, 1));
	ipc_gap_req_encode(body, IPC_GAP_SET_PHY, 0, 0, addr, 0);
	client->peer_uid = 1000;
	ATF_CHECK_EQ(IPC_ERR_PERM, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_PHY_REQ_SIZE));
	client->peer_uid = 0;

	memset(body, 0, IPC_GAP_CONNECT_NAME_REQ_SIZE);
	ipc_put_le16(body, IPC_GAP_CONNECT_NAME);
	strlcpy((char *)body + 4, "missing-peer", 32);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_CONNECT_NAME_REQ_SIZE));
	body[4] = '\0';
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_CONNECT_NAME_REQ_SIZE));

	memset(body, 0, IPC_GAP_REQ_SIZE);
	ipc_gap_req_encode(body, IPC_GAP_SET_PHY, 0, 2, addr, 0);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_REQ_SIZE));
	ipc_gap_req_encode(body, 0x7fff, 0, 1, addr, 0);
	ATF_CHECK_EQ(IPC_ERR_UNKNOWN_CMD, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_REQ_SIZE));

	memset(body, 0, IPC_GAP_PATH_LOSS_REQ_SIZE);
	ipc_gap_req_encode(body, IPC_GAP_PATH_LOSS, 0, 0, addr, 0);
	body[18] = 1;
	adp.le_features = 0;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_PATH_LOSS_REQ_SIZE));
	adp.le_features = UINT64_MAX;
	body[19] = 1;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_PATH_LOSS_REQ_SIZE));

	memset(body, 0, IPC_GAP_CONNECTION_REQ_SIZE);
	ipc_put_le16(body, IPC_GAP_GET_CONNECTIONS);
	ipc_put_le16(body + 2, 1);
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GAP, body, IPC_GAP_CONNECTION_REQ_SIZE));

	LIST_REMOVE(client, entries);
	conn->att = NULL;
	blued_conn_free(conn);
	LIST_REMOVE(&adp, entries);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_ctl_event_notification_matrix);
ATF_TC_BODY(test_ctl_event_notification_matrix, tc)
{
	struct blued_ctl_client *client, *unprivileged;
	struct blued_adapter adp;
	struct blued_conn *conn;
	struct att_conn att;
	bdaddr_t addr;
	char feat[128];
	uint8_t value[] = { 1, 2, 3 };
	uint8_t mesh_ad[] = { 3, 0x2a, 0xaa, 0xbb, 2, 0x09, 'x',
	    5, 0x29, 1 };
	int sp[2], unprivileged_sp[2];

	test_init();
	/* Exercise enabled ctl diagnostic guards while this broad matrix already
	 * drives connection, ISO, mesh, and pairing-event routing. */
	atomic_store(&blued_verbose, 2);
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.hci_fd = 17;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &addr));
	conn->dst = addr;
	conn->addr_type = 1;
	conn->adapter = &adp;
	memset(&att, 0, sizeof(att));
	conn->att = &att;

	client = make_client(sp);
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS | IPC_FEATURE_MESH, feat, sizeof(feat));
	/* Security prompts are intentionally delivered only to root-owned event
	 * clients (or the registered pairing agent). */
	unprivileged = make_client(unprivileged_sp);
	unprivileged->peer_uid = 1000;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, unprivileged, entries);
	ipc_handshake(unprivileged, unprivileged_sp[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS, feat, sizeof(feat));

	client->nsubs = 1;
	client->subs[0].addr = addr;
	client->subs[0].addr_type = 1;
	client->subs[0].adapter_index = 0;
	client->subs[0].handle = 0x20;
	blued_ctl_notify_value(NULL, 0x20, value, sizeof(value), 23);
	blued_ctl_notify_value(conn, 0x20, value, sizeof(value), 23);
	blued_ctl_notify_write(client->fd, 0x20, value, sizeof(value));
	blued_ctl_notify_write(-1, 0x20, value, sizeof(value));
	blued_ctl_notify_read(client->fd, 0x20, 4);
	blued_ctl_notify_read(-1, 0x20, 4);
	blued_ctl_notify_authorize(client->fd, 0x20, false, &att);
	blued_ctl_notify_authorize(client->fd, 0x20, true, NULL);

	blued_ctl_broadcast_conn_event(&addr, BLUED_ROLE_PERIPHERAL, 1, 0,
	    0x40, 185, true, 0);
	blued_ctl_broadcast_conn_event(&addr, BLUED_ROLE_CENTRAL, 1, 0,
	    0x40, 0, false, 0x13);
	blued_ctl_iso_cis_request(&adp, &addr, 1, 0x40, 2, 3);
	blued_ctl_iso_established(&adp, &addr, 1, 0x40, 120);

	client->mesh_sub = true;
	blued_ctl_broadcast_mesh_adv(0x2a, value, sizeof(value));
	blued_ctl_broadcast_mesh_adv(0x2a, value, MESH_ADV_PDU_MAX + 1);
	blued_mesh_demux_report(mesh_ad, sizeof(mesh_ad));
	blued_mesh_demux_report(NULL, 0);
	blued_ctl_client_mesh_gone(client);
	blued_ctl_client_mesh_gone(NULL);

	/* With no registered agent these use the legacy event broadcast path. */
	blued_ctl_passkey_display(&addr, 123456);
	blued_ctl_passkey_input(&addr);
	blued_ctl_numcmp_request(&addr, 654321);
	blued_ctl_keypress(&addr, 2);
	ATF_CHECK_EQ(blued_cfg.io_capability,
	    blued_ctl_effective_io_cap(blued_cfg.io_capability));

	LIST_REMOVE(unprivileged, entries);
	blued_ctl_client_fini(unprivileged);
	close(unprivileged_sp[0]);
	close(unprivileged_sp[1]);
	free(unprivileged);
	LIST_REMOVE(client, entries);
	conn->att = NULL;
	blued_conn_free(conn);
	LIST_REMOVE(&adp, entries);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_ctl_gatt_event_value_bounds);
ATF_TC_BODY(test_ctl_gatt_event_value_bounds, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct blued_conn *conn;
	bdaddr_t addr;
	char feat[128];
	uint8_t oversized[ATT_PDU_BUF_SIZE + 1] = { 0 };
	uint8_t junk[16];
	struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
	int sp[2];
	ssize_t n;

	test_init();
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);

	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &addr));
	conn->dst = addr;
	conn->addr_type = 1;
	conn->adapter = &adp;

	client = make_client(sp);
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS,
	    feat, sizeof(feat));
	ATF_REQUIRE_EQ(0, setsockopt(sp[1], SOL_SOCKET, SO_RCVTIMEO, &tv,
	    sizeof(tv)));

	client->nsubs = 1;
	client->subs[0].addr = addr;
	client->subs[0].addr_type = 1;
	client->subs[0].adapter_index = 0;
	client->subs[0].handle = 0x20;
	blued_ctl_notify_value(conn, 0x20, oversized, sizeof(oversized), 517);
	n = recv(sp[1], junk, sizeof(junk), 0);
	ATF_CHECK_EQ(-1, n);
	ATF_CHECK_EQ(EAGAIN, errno);

	blued_ctl_notify_write(client->fd, 0x20, oversized,
	    sizeof(oversized));
	n = recv(sp[1], junk, sizeof(junk), 0);
	ATF_CHECK_EQ(-1, n);
	ATF_CHECK_EQ(EAGAIN, errno);

	LIST_REMOVE(client, entries);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
	blued_conn_free(conn);
	LIST_REMOVE(&adp, entries);
}

/* Runtime pairing agent: verify the agent capability override and both
 * cleanup paths through the real typed SECURITY dispatcher. */
ATF_TC_WITHOUT_HEAD(test_ctl_pairing_agent_lifecycle);
ATF_TC_BODY(test_ctl_pairing_agent_lifecycle, tc)
{
	struct blued_ctl_client *client;
	uint8_t body[IPC_SECURITY_AGENT_REQ_SIZE];
	int sp[2];

	test_init();
	client = make_client(sp);
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_SECURITY_REGISTER_AGENT);
	body[12] = SMP_IO_DISPLAY_ONLY;

	/* An agent that did not negotiate event delivery is unusable. */
	ATF_CHECK_EQ(IPC_ERR_PERM, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, sizeof(body)));
	ATF_CHECK_EQ(blued_cfg.io_capability,
	    blued_ctl_effective_io_cap(blued_cfg.io_capability));

	client->wants_events = true;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, sizeof(body)));
	ATF_CHECK_EQ(SMP_IO_DISPLAY_ONLY,
	    blued_ctl_effective_io_cap(blued_cfg.io_capability));
	/* Explicit unregister restores the configured fallback. */
	ipc_put_le16(body, IPC_SECURITY_UNREGISTER_AGENT);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_REQ_SIZE));
	ATF_CHECK_EQ(blued_cfg.io_capability,
	    blued_ctl_effective_io_cap(blued_cfg.io_capability));

	/* Re-register, then let client teardown clear the stale agent fd. */
	ipc_put_le16(body, IPC_SECURITY_REGISTER_AGENT);
	body[12] = SMP_IO_KEYBOARD_ONLY;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, IPC_SECURITY_AGENT_REQ_SIZE));
	/* A registered agent receives pairing events exclusively.  Place this
	 * after the request/reply exchanges so its asynchronous event cannot be
	 * mistaken for a dispatcher reply by the helper above. */
	{
		bdaddr_t addr;

		ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &addr));
		blued_ctl_passkey_display(&addr, 123456);
	}
	blued_ctl_reset_owner(client->fd);
	blued_ctl_client_fini(client);
	ATF_CHECK_EQ(blued_cfg.io_capability,
	    blued_ctl_effective_io_cap(blued_cfg.io_capability));
	LIST_REMOVE(client, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_typed_advertising_valid_lifecycle);
ATF_TC_BODY(test_typed_advertising_valid_lifecycle, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	char feat[128];
	uint8_t body[64];
	int sp[2];

	test_init();
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.powered = true;
	adp.hci_fd = 42;
	adp.le_features = LE_FEAT_EXT_ADVERTISING;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	blued_g.periph_active = true;
	client = make_client(sp);
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS,
	    feat, sizeof(feat));

	memset(body, 0, IPC_ADV_PARAMS_REQ_SIZE);
	ipc_put_le16(body, IPC_ADV_SET_PARAMS);
	body[6] = 7;
	body[8] = 1;
	body[9] = 1;
	ipc_put_le32(body + 20, 0x20);
	ipc_put_le32(body + 24, 0x40);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_PARAMS_REQ_SIZE));
	ATF_CHECK(adp.adv_configured);

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_ADV_SET_NAME);
	memcpy(body + IPC_ADV_NAME_REQ_HDR_SIZE, "mesh-node", 9);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_NAME_REQ_HDR_SIZE + 9));
	ATF_CHECK_STREQ("mesh-node", adap_cap.name_last);

	for (int opcode = IPC_ADV_SET_DATA;
	    opcode <= IPC_ADV_SET_SCAN_RESPONSE; opcode++) {
		memset(body, 0, sizeof(body));
		ipc_put_le16(body, (uint16_t)opcode);
		ipc_put_le16(body + 4, 3);
		body[IPC_ADV_DATA_REQ_HDR_SIZE + 0] = 2;
		body[IPC_ADV_DATA_REQ_HDR_SIZE + 1] = 1;
		body[IPC_ADV_DATA_REQ_HDR_SIZE + 2] = 6;
		ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_ADV, body, IPC_ADV_DATA_REQ_HDR_SIZE + 3));
	}

	memset(body, 0, IPC_ADV_SET_CREATE_REQ_SIZE);
	ipc_put_le16(body, IPC_ADV_SET_CREATE);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_SET_CREATE_REQ_SIZE));

	memset(body, 0, IPC_ADV_SET_PARAMS_REQ_SIZE);
	ipc_put_le16(body, IPC_ADV_SET_HANDLE_PARAMS);
	body[4] = 1;
	body[5] = 1;
	body[6] = 1;
	ipc_put_le32(body + 12, 0x20);
	ipc_put_le32(body + 16, 0x40);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_SET_PARAMS_REQ_SIZE));

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_ADV_SET_HANDLE_DATA);
	body[4] = 1;
	body[5] = 3;
	body[8] = 2;
	body[9] = 1;
	body[10] = 6;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_SET_DATA_REQ_HDR_SIZE + 3));

	memset(body, 0, IPC_ADV_SET_STATE_REQ_SIZE);
	ipc_put_le16(body, IPC_ADV_SET_HANDLE_ENABLE);
	body[4] = 1;
	body[5] = 1;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_SET_STATE_REQ_SIZE));
	body[5] = 0;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_SET_STATE_REQ_SIZE));

	memset(body, 0, IPC_ADV_SET_STATE_REQ_SIZE);
	ipc_put_le16(body, IPC_ADV_SET_HANDLE_REMOVE);
	body[4] = 1;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_SET_STATE_REQ_SIZE));

	LIST_REMOVE(client, entries);
	LIST_REMOVE(&adp, entries);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_typed_periodic_valid_matrix);
ATF_TC_BODY(test_typed_periodic_valid_matrix, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct blued_conn *public_conn, *random_conn;
	char feat[128];
	uint8_t body[300];
	int sp[2], opcode;

	test_init();
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.powered = true;
	adp.hci_fd = 42;
	adp.le_features = LE_FEAT_PERIODIC_ADV | LE_FEAT_PAST_SENDER |
	    LE_FEAT_PAST_RECIPIENT;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	public_conn = blued_conn_alloc();
	random_conn = blued_conn_alloc();
	ATF_REQUIRE(public_conn != NULL && random_conn != NULL);
	public_conn->adapter = &adp;
	public_conn->addr_type = BDADDR_LE_PUBLIC;
	public_conn->con_handle = 0x0123;
	public_conn->con_handle_valid = true;
	random_conn->adapter = &adp;
	random_conn->addr_type = BDADDR_LE_RANDOM;
	random_conn->con_handle = 0x0456;
	random_conn->con_handle_valid = true;
	client = make_client(sp);
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS,
	    feat, sizeof(feat));

	memset(body, 0, IPC_PERIODIC_PARAMS_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_ADV_PARAMS);
	ipc_put_le16(body + 4, 6);
	ipc_put_le16(body + 6, 10);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PARAMS_REQ_SIZE));

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_PERIODIC_ADV_DATA);
	ipc_put_le16(body + 4, 3);
	body[8] = 1; body[9] = 2; body[10] = 3;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_DATA_REQ_HDR_SIZE + 3));

	memset(body, 0, IPC_PERIODIC_STATE_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_ADV_ENABLE);
	body[4] = 1;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_STATE_REQ_SIZE));

	memset(body, 0, IPC_PERIODIC_SYNC_CREATE_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_SYNC_CREATE);
	body[11] = 1;
	ipc_put_le16(body + 14, 10);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_SYNC_CREATE_REQ_SIZE));

	for (opcode = IPC_PERIODIC_SYNC_CANCEL;
	    opcode <= IPC_PERIODIC_SYNC_TERMINATE; opcode++) {
		size_t len = opcode == IPC_PERIODIC_SYNC_CANCEL ?
		    IPC_PERIODIC_SIMPLE_REQ_SIZE : IPC_PERIODIC_STATE_REQ_SIZE;
		memset(body, 0, len);
		ipc_put_le16(body, (uint16_t)opcode);
		if (opcode == IPC_PERIODIC_SYNC_TERMINATE)
			ipc_put_le16(body + 4, 1);
		ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_PERIODIC, body, len));
	}

	for (opcode = IPC_PERIODIC_LIST_ADD;
	    opcode <= IPC_PERIODIC_LIST_REMOVE; opcode++) {
		memset(body, 0, IPC_PERIODIC_PEER_REQ_SIZE);
		ipc_put_le16(body, (uint16_t)opcode);
		body[11] = 1;
		ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PEER_REQ_SIZE));
	}
	for (opcode = IPC_PERIODIC_LIST_CLEAR;
	    opcode <= IPC_PERIODIC_LIST_SIZE; opcode++) {
		memset(body, 0, IPC_PERIODIC_SIMPLE_REQ_SIZE);
		ipc_put_le16(body, (uint16_t)opcode);
		ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_SIMPLE_REQ_SIZE));
	}

	memset(body, 0, IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_PAST_TRANSFER);
	ipc_put_le16(body + 12, 1);
	ipc_put_le16(body + 14, 1);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE));
	ATF_CHECK_EQ(0x0123, periodic_last_handle);
	/* Identical address octets with random type must select the random link. */
	body[4] = 1;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE));
	ATF_CHECK_EQ(0x0456, periodic_last_handle);
	body[4] = 0;
	ipc_put_le16(body, IPC_PERIODIC_PAST_SET_INFO);
	body[14] = 0;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE));

	memset(body, 0, IPC_PERIODIC_PAST_PARAMS_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_PAST_PARAMS);
	ipc_put_le16(body + 16, 10);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PAST_PARAMS_REQ_SIZE));

	memset(body, 0, IPC_PERIODIC_STATE_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_PAST_RECEIVE);
	ipc_put_le16(body + 4, 1);
	body[6] = 1;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_STATE_REQ_SIZE));

	memset(body, 0, IPC_PERIODIC_PAST_DEFAULT_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_PAST_DEFAULT_PARAMS);
	ipc_put_le16(body + 8, 10);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PAST_DEFAULT_REQ_SIZE));

	/* Every valid controller verb maps a negative HCI completion to IO. */
	periodic_hci_rc = -1;
	memset(body, 0, IPC_PERIODIC_PARAMS_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_ADV_PARAMS);
	ipc_put_le16(body + 4, 6); ipc_put_le16(body + 6, 10);
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PARAMS_REQ_SIZE));
	memset(body, 0, IPC_PERIODIC_DATA_REQ_HDR_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_ADV_DATA);
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_DATA_REQ_HDR_SIZE));
	memset(body, 0, IPC_PERIODIC_STATE_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_ADV_ENABLE);
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_STATE_REQ_SIZE));
	memset(body, 0, IPC_PERIODIC_SYNC_CREATE_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_SYNC_CREATE);
	ipc_put_le16(body + 14, 10);
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_SYNC_CREATE_REQ_SIZE));
	for (opcode = IPC_PERIODIC_SYNC_CANCEL;
	    opcode <= IPC_PERIODIC_SYNC_TERMINATE; opcode++) {
		size_t len = opcode == IPC_PERIODIC_SYNC_CANCEL ?
		    IPC_PERIODIC_SIMPLE_REQ_SIZE : IPC_PERIODIC_STATE_REQ_SIZE;
		memset(body, 0, len);
		ipc_put_le16(body, (uint16_t)opcode);
		ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_PERIODIC, body, len));
	}
	for (opcode = IPC_PERIODIC_LIST_ADD;
	    opcode <= IPC_PERIODIC_LIST_REMOVE; opcode++) {
		memset(body, 0, IPC_PERIODIC_PEER_REQ_SIZE);
		ipc_put_le16(body, (uint16_t)opcode);
		ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PEER_REQ_SIZE));
	}
	for (opcode = IPC_PERIODIC_LIST_CLEAR;
	    opcode <= IPC_PERIODIC_LIST_SIZE; opcode++) {
		memset(body, 0, IPC_PERIODIC_SIMPLE_REQ_SIZE);
		ipc_put_le16(body, (uint16_t)opcode);
		ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
		    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_SIMPLE_REQ_SIZE));
	}
	memset(body, 0, IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_PAST_TRANSFER);
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE));
	ipc_put_le16(body, IPC_PERIODIC_PAST_SET_INFO);
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE));
	memset(body, 0, IPC_PERIODIC_PAST_PARAMS_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_PAST_PARAMS);
	ipc_put_le16(body + 16, 10);
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PAST_PARAMS_REQ_SIZE));
	memset(body, 0, IPC_PERIODIC_STATE_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_PAST_RECEIVE);
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_STATE_REQ_SIZE));
	memset(body, 0, IPC_PERIODIC_PAST_DEFAULT_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_PAST_DEFAULT_PARAMS);
	ipc_put_le16(body + 8, 10);
	ATF_CHECK_EQ(IPC_ERR_IO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PAST_DEFAULT_REQ_SIZE));
	periodic_hci_rc = 0;

	/* PAST distinguishes a missing connection from missing feature bits. */
	public_conn->con_handle_valid = false;
	memset(body, 0, IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_PAST_TRANSFER);
	ATF_CHECK_EQ(IPC_ERR_NOT_CONN, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE));
	public_conn->con_handle_valid = true;
	adp.le_features = LE_FEAT_PERIODIC_ADV;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PAST_TRANSFER_REQ_SIZE));

	LIST_REMOVE(client, entries);
	LIST_REMOVE(&adp, entries);
	blued_conn_free(public_conn);
	blued_conn_free(random_conn);
	blued_ctl_client_fini(client);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

ATF_TC_WITHOUT_HEAD(test_ipc_framing_guard_matrix);
ATF_TC_BODY(test_ipc_framing_guard_matrix, tc)
{
	struct blued_ctl_client *client;
	uint8_t prefix[IPC_OP_PREFIX_SIZE], hdr[IPC_HDR_SIZE], both[16];
	char reply[256];
	uint16_t type, arg;
	int flags, sp[2];

	test_init();
	client = make_client(sp);
	/* Operations require a completed HELLO handshake (finding 35). */
	client->handshaked = true;

	/* A short operation envelope and every invalid prefix field fail closed. */
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL, NULL, 0);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	(void)ipc_recv(sp[1], &type, &arg, reply, sizeof(reply));
	ATF_CHECK_EQ(type, IPC_T_ERROR);
	ATF_CHECK_EQ(arg, IPC_ERR_PROTO);

	ipc_op_prefix_encode(prefix, 0, 0, 0);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL, prefix,
	    sizeof(prefix));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	(void)ipc_recv(sp[1], &type, &arg, reply, sizeof(reply));
	ATF_CHECK_EQ(type, IPC_T_ERROR);

	ipc_op_prefix_encode(prefix, 1, IPC_ERR_IO, 0);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL, prefix,
	    sizeof(prefix));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	(void)ipc_recv(sp[1], &type, &arg, reply, sizeof(reply));
	ATF_CHECK_EQ(type, IPC_T_ERROR);

	ipc_op_prefix_encode(prefix, 2, 0, 1);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL, prefix,
	    sizeof(prefix));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	(void)ipc_recv(sp[1], &type, &arg, reply, sizeof(reply));
	ATF_CHECK_EQ(type, IPC_T_ERROR);

	/* Valid envelope with an unknown domain preserves request correlation. */
	ipc_op_prefix_encode(prefix, 3, 0, 0);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, UINT16_MAX, prefix, sizeof(prefix));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	(void)ipc_recv(sp[1], &type, &arg, reply, sizeof(reply));
	ATF_CHECK_EQ(type, IPC_T_OP_REPLY);
	ATF_CHECK_EQ(arg, UINT16_MAX);

	/* Unsupported post-handshake frame types receive a protocol error. */
	ipc_send_raw(sp[1], IPC_T_ERROR, 0, NULL, 0);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	(void)ipc_recv(sp[1], &type, &arg, reply, sizeof(reply));
	ATF_CHECK_EQ(type, IPC_T_ERROR);

	/* Two frames in one recv exercise the decoder's remainder compaction. */
	ipc_hdr_encode(both, 0, IPC_T_ERROR, 0);
	ipc_hdr_encode(both + IPC_HDR_SIZE, 0, IPC_T_OP_REPLY, 0);
	ATF_REQUIRE_EQ((ssize_t)(2 * IPC_HDR_SIZE),
	    write(sp[1], both, 2 * IPC_HDR_SIZE));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	(void)ipc_recv(sp[1], &type, &arg, reply, sizeof(reply));
	ATF_CHECK_EQ(type, IPC_T_ERROR);
	(void)ipc_recv(sp[1], &type, &arg, reply, sizeof(reply));
	ATF_CHECK_EQ(type, IPC_T_ERROR);

	/* Both oversized-frame checks reset the receive buffer deterministically. */
	client->rxlen = sizeof(client->rxbuf);
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	(void)ipc_recv(sp[1], &type, &arg, reply, sizeof(reply));
	ATF_CHECK_EQ(arg, IPC_ERR_PROTO);
	ipc_hdr_encode(hdr, IPC_MAX_PAYLOAD + 1, IPC_T_OP_REQ, 0);
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), write(sp[1], hdr, sizeof(hdr)));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	(void)ipc_recv(sp[1], &type, &arg, reply, sizeof(reply));
	ATF_CHECK_EQ(arg, IPC_ERR_PROTO);

	/* Empty nonblocking input is not mistaken for disconnect or corruption. */
	flags = fcntl(client->fd, F_GETFL);
	ATF_REQUIRE(flags >= 0);
	ATF_REQUIRE_EQ(0, fcntl(client->fd, F_SETFL, flags | O_NONBLOCK));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);

	blued_ctl_client_fini(client);
	close(sp[0]); close(sp[1]); free(client);
}

ATF_TC_WITHOUT_HEAD(test_typed_adv_periodic_l2cap_guards);
ATF_TC_BODY(test_typed_adv_periodic_l2cap_guards, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	char feat[128];
	uint8_t body[300];
	int sp[2];

	test_init();
	client = make_client(sp);
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS | IPC_FEATURE_FDPASS, feat, sizeof(feat));

	/* Advertising permission, framing, flags, resources, and ownership. */
	client->peer_uid = 1000;
	memset(body, 0, sizeof(body));
	ATF_CHECK_EQ(IPC_ERR_PERM, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, 2));
	client->peer_uid = 0;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, 2));
	ipc_put_le16(body + 2, 1);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, 4));

	memset(body, 0, IPC_ADV_PARAMS_REQ_SIZE);
	ipc_put_le16(body, IPC_ADV_SET_PARAMS);
	body[6] = 7; body[8] = 1; body[9] = 1;
	ipc_put_le32(body + 20, 0x20); ipc_put_le32(body + 24, 0x40);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_PARAMS_REQ_SIZE));
	memset(&adp, 0, sizeof(adp));
	adp.active = true; adp.powered = true;
	adp.index = 0; adp.hci_fd = 42;
	adp.le_features = LE_FEAT_EXT_ADVERTISING | LE_FEAT_PERIODIC_ADV;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	ATF_CHECK_EQ(IPC_ERR_PERM, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_PARAMS_REQ_SIZE));
	body[8] = 2;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_PARAMS_REQ_SIZE));

	memset(body, 0, IPC_ADV_SET_PARAMS_REQ_SIZE);
	ipc_put_le16(body, IPC_ADV_SET_HANDLE_PARAMS); body[4] = 99;
	ipc_put_le32(body + 12, 0x20); ipc_put_le32(body + 16, 0x40);
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_SET_PARAMS_REQ_SIZE));
	memset(body, 0, IPC_ADV_SET_DATA_REQ_HDR_SIZE);
	ipc_put_le16(body, IPC_ADV_SET_HANDLE_DATA); body[4] = 99;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_SET_DATA_REQ_HDR_SIZE));
	memset(body, 0, IPC_ADV_SET_STATE_REQ_SIZE);
	ipc_put_le16(body, IPC_ADV_SET_HANDLE_ENABLE); body[4] = 99;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_SET_STATE_REQ_SIZE));
	ipc_put_le16(body, UINT16_MAX);
	ATF_CHECK_EQ(IPC_ERR_UNKNOWN_CMD, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_ADV, body, IPC_ADV_SET_STATE_REQ_SIZE));

	/* Periodic feature routing and per-opcode semantic bounds. */
	client->peer_uid = 1000;
	ATF_CHECK_EQ(IPC_ERR_PERM, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, 2));
	client->peer_uid = 0;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, 2));
	memset(body, 0, 4); ipc_put_le16(body + 2, UINT16_MAX);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, 4));
	memset(body, 0, IPC_PERIODIC_PARAMS_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_ADV_PARAMS);
	ipc_put_le16(body + 4, 5); ipc_put_le16(body + 6, 4);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PARAMS_REQ_SIZE));
	memset(body, 0, IPC_PERIODIC_SYNC_CREATE_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_SYNC_CREATE); body[4] = 2;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_SYNC_CREATE_REQ_SIZE));
	memset(body, 0, IPC_PERIODIC_STATE_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_SYNC_TERMINATE);
	ipc_put_le16(body + 4, 0x0f00);
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_STATE_REQ_SIZE));
	memset(body, 0, IPC_PERIODIC_PEER_REQ_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_LIST_ADD); body[4] = 2;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, IPC_PERIODIC_PEER_REQ_SIZE));
	memset(body, 0, 4); ipc_put_le16(body, UINT16_MAX);
	ATF_CHECK_EQ(IPC_ERR_UNKNOWN_CMD, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_PERIODIC, body, 4));

	/* L2CAP acquire/EATT validation without needing an RF controller. */
	client->peer_uid = 1000;
	ATF_CHECK_EQ(IPC_ERR_PERM, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_L2CAP, body, 2));
	client->peer_uid = 0;
	ATF_CHECK_EQ(IPC_ERR_PROTO, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_L2CAP, body, 2));
	memset(body, 0, IPC_L2CAP_REQ_SIZE);
	ipc_put_le16(body, IPC_L2CAP_ACQUIRE_COC); body[4] = 2;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_L2CAP, body, IPC_L2CAP_REQ_SIZE));
	body[4] = 0; body[11] = 0;
	ATF_CHECK_EQ(IPC_ERR_INVAL, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_L2CAP, body, IPC_L2CAP_REQ_SIZE));
	ipc_put_le16(body, IPC_L2CAP_EATT_OPEN); body[11] = 1;
	ATF_CHECK_EQ(IPC_ERR_NOT_CONN, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_L2CAP, body, IPC_L2CAP_REQ_SIZE));
	ipc_put_le16(body, IPC_L2CAP_EATT_CLOSE); body[11] = 0;
	ATF_CHECK_EQ(IPC_ERR_NOT_CONN, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_L2CAP, body, IPC_L2CAP_REQ_SIZE));
	ipc_put_le16(body, UINT16_MAX);
	ATF_CHECK_EQ(IPC_ERR_UNKNOWN_CMD, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_L2CAP, body, IPC_L2CAP_REQ_SIZE));

	LIST_REMOVE(client, entries);
	LIST_REMOVE(&adp, entries);
	blued_ctl_client_fini(client);
	close(sp[0]); close(sp[1]); free(client);
}

ATF_TC_WITHOUT_HEAD(test_ctl_internal_whitebox_completion);
ATF_TC_BODY(test_ctl_internal_whitebox_completion, tc)
{

	test_init();
	ATF_CHECK_EQ(0, ptap_ctl_internal_completion());
}

/*
 * finding 35: an OP_REQ from a client that never completed the HELLO
 * handshake is rejected with IPC_T_ERROR/IPC_ERR_PROTO and never dispatched;
 * after a successful handshake the same request is accepted.
 */
ATF_TC_WITHOUT_HEAD(test_finding35_handshake_gate);
ATF_TC_BODY(test_finding35_handshake_gate, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	char feat[128], reply[128];
	uint8_t req[IPC_OP_PREFIX_SIZE + IPC_CTL_REQ_SIZE];
	uint16_t type, arg;
	int sp[2];

	test_init();
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.powered = true;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	client = make_client(sp);
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ATF_CHECK(!client->handshaked);

	/* Unhandshaked OP_REQ (STATUS) is rejected before dispatch. */
	memset(req, 0, sizeof(req));
	ipc_op_prefix_encode(req, 0x11111111u, 0, 0);
	ipc_ctl_req_encode(req + IPC_OP_PREFIX_SIZE, IPC_CTL_STATUS, 0, 0, 0);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL, req, sizeof(req));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	(void)ipc_recv(sp[1], &type, &arg, reply, sizeof(reply));
	ATF_CHECK_EQ(type, IPC_T_ERROR);
	ATF_CHECK_EQ(arg, IPC_ERR_PROTO);
	ATF_CHECK(!client->handshaked);

	/* After a HELLO handshake, the same request is dispatched. */
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS,
	    feat, sizeof(feat));
	ipc_op_prefix_encode(req, 0x22222222u, 0, 0);
	ipc_ctl_req_encode(req + IPC_OP_PREFIX_SIZE, IPC_CTL_STATUS, 0, 0, 0);
	ipc_send_raw(sp[1], IPC_T_OP_REQ, IPC_OP_DOMAIN_CTL, req, sizeof(req));
	ATF_CHECK_EQ(blued_ctl_dispatch(client), 0);
	(void)ipc_recv(sp[1], &type, &arg, reply, sizeof(reply));
	ATF_CHECK_EQ(type, IPC_T_OP_REPLY);
	ATF_CHECK_EQ(arg, IPC_OP_DOMAIN_CTL);

	LIST_REMOVE(client, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/*
 * finding 28: the security event body carries the adapter index and the peer
 * address type, derived from the live connection, so a random-address peer can
 * be answered.  Layout: [event u16][adapter u8][addr_type u8][addr[6]][value].
 */
ATF_TC_WITHOUT_HEAD(test_finding28_security_event_layout);
ATF_TC_BODY(test_finding28_security_event_layout, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct blued_conn *conn;
	char feat[128], pl[128];
	bdaddr_t addr;
	uint16_t type, arg;
	size_t plen;
	int sp[2];

	test_init();
	ATF_REQUIRE(bt_aton("aa:bb:cc:dd:ee:ff", &addr));
	memset(&adp, 0, sizeof(adp));
	adp.index = 3;
	adp.active = true;
	adp.powered = true;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->adapter = &adp;
	conn->dst = addr;
	conn->addr_type = BDADDR_LE_RANDOM;

	client = make_client(sp);
	client->wants_events = true;
	client->peer_known = true;
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS,
	    feat, sizeof(feat));

	blued_ctl_passkey_display(&addr, 123456);

	plen = ipc_recv(sp[1], &type, &arg, pl, sizeof(pl));
	ATF_CHECK_EQ(type, IPC_T_OP_EVENT);
	ATF_CHECK_EQ(arg, IPC_OP_DOMAIN_SECURITY);
	ATF_REQUIRE_EQ(plen,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_PASSKEY_EVENT_SIZE);
	{
		const uint8_t *body = (const uint8_t *)pl + IPC_OP_PREFIX_SIZE;

		ATF_CHECK_EQ(ipc_get_le16(body), IPC_SECURITY_EV_PASSKEY_DISPLAY);
		ATF_CHECK_EQ(body[2], 3);	/* adapter_index */
		ATF_CHECK_EQ(body[3], 1);	/* addr_type: random -> IPC 1 */
		ATF_CHECK(memcmp(body + 4, &addr, sizeof(addr)) == 0);
		ATF_CHECK_EQ(ipc_get_le32(body + 10), 123456u);
	}

	LIST_REMOVE(client, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/*
 * finding 31: a wildcard SUBSCRIBE (all-zero address, handle 0) registers a
 * "monitor all connections" route, and blued_ctl_notify_value then mirrors a
 * notification of any handle to the monitoring client.
 */
ATF_TC_WITHOUT_HEAD(test_finding31_wildcard_subscribe);
ATF_TC_BODY(test_finding31_wildcard_subscribe, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct blued_conn conn;
	uint8_t body[IPC_GATT_REQ_SIZE], val[3] = { 0x01, 0x02, 0x03 };
	char feat[128], pl[128];
	bdaddr_t addr;
	uint16_t type, arg;
	size_t plen;
	int sp[2];

	test_init();
	ATF_REQUIRE(bt_aton("01:02:03:04:05:06", &addr));
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	client = make_client(sp);
	client->wants_events = true;
	client->peer_known = true;
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS,
	    feat, sizeof(feat));

	/* Wildcard subscribe: opcode only, address and handle all zero. */
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_SUBSCRIBE);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, sizeof(body)));
	ATF_CHECK_EQ(client->nsubs, 1);
	ATF_CHECK_EQ(client->subs[0].handle, 0);

	/* A notification of an arbitrary handle reaches the monitor. */
	memset(&conn, 0, sizeof(conn));
	conn.adapter = &adp;
	conn.dst = addr;
	conn.addr_type = BDADDR_LE_PUBLIC;
	blued_ctl_notify_value(&conn, 0x0020, val, sizeof(val), 23);

	plen = ipc_recv(sp[1], &type, &arg, pl, sizeof(pl));
	ATF_CHECK_EQ(type, IPC_T_OP_EVENT);
	ATF_CHECK_EQ(arg, IPC_OP_DOMAIN_GATT);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GATT_NOTIFY_EVENT_SIZE +
	    sizeof(val));
	ATF_CHECK_EQ(ipc_get_le16((const uint8_t *)pl + IPC_OP_PREFIX_SIZE + 9),
	    0x0020);

	/* Wildcard unsubscribe removes the monitor route. */
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GATT_UNSUBSCRIBE);
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_GATT, body, sizeof(body)));
	ATF_CHECK_EQ(client->nsubs, 0);

	LIST_REMOVE(client, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/*
 * finding 37: IPC_SECURITY_PAIR initiates pairing rather than reporting a bare
 * "connection exists" success.  No connection -> NOT_CONN; an unencrypted
 * peripheral link cannot self-initiate -> PERM; an already-encrypted link ->
 * NONE (already secure).
 */
ATF_TC_WITHOUT_HEAD(test_finding37_pair_initiates);
ATF_TC_BODY(test_finding37_pair_initiates, tc)
{
	struct blued_ctl_client *client;
	struct blued_adapter adp;
	struct blued_conn *conn;
	struct att_conn att;
	uint8_t body[IPC_SECURITY_REQ_SIZE];
	bdaddr_t addr;
	int sp[2];

	test_init();
	ATF_REQUIRE(bt_aton("0a:0b:0c:0d:0e:0f", &addr));
	memset(&adp, 0, sizeof(adp));
	adp.index = 0;
	adp.active = true;
	adp.powered = true;
	LIST_INSERT_HEAD(&blued_g.adapters, &adp, entries);
	client = make_client(sp);
	client->peer_known = true;
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);

	/* No connection for this peer: NOT_CONN. */
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_SECURITY_PAIR);
	memcpy(body + 5, &addr, sizeof(addr));
	ATF_CHECK_EQ(IPC_ERR_NOT_CONN, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, sizeof(body)));

	/* Unencrypted peripheral link cannot self-initiate pairing: PERM. */
	memset(&att, 0, sizeof(att));
	att.fd = -1;
	att.encrypted = false;
	conn = blued_conn_alloc();
	ATF_REQUIRE(conn != NULL);
	conn->adapter = &adp;
	conn->dst = addr;
	conn->addr_type = BDADDR_LE_PUBLIC;
	conn->role = BLUED_ROLE_PERIPHERAL;
	conn->att = &att;
	ATF_CHECK_EQ(IPC_ERR_PERM, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, sizeof(body)));

	/* Already-encrypted link: nothing to do, reported as success. */
	att.encrypted = true;
	ATF_CHECK_EQ(IPC_ERR_NONE, dispatch_domain_request(client, sp[1],
	    IPC_OP_DOMAIN_SECURITY, body, sizeof(body)));

	conn->att = NULL;
	LIST_REMOVE(client, entries);
	close(sp[0]);
	close(sp[1]);
	free(client);
}

/*
 * Finding 30/88 (lock-reacquisition class).  ctl_clients_lock is initialised
 * recursive so a dispatch that holds it across the verb handler survives a
 * helper that re-acquires it (DISCONNECT/STATUS/POWER paths).  These wrappers
 * carry no_thread_safety_analysis because the whole point is an intentional
 * same-thread nested lock the static analyser would otherwise reject.
 */
static int tsa_lock(void) __attribute__((no_thread_safety_analysis));
static int
tsa_lock(void)
{
	return (pthread_mutex_lock(&blued_g.ctl_clients_lock));
}

static int tsa_unlock(void) __attribute__((no_thread_safety_analysis));
static int
tsa_unlock(void)
{
	return (pthread_mutex_unlock(&blued_g.ctl_clients_lock));
}

static void *ctl_lock_trylock_probe(void *arg)
    __attribute__((no_thread_safety_analysis));
static void *
ctl_lock_trylock_probe(void *arg)
{
	int *rc = arg;

	*rc = pthread_mutex_trylock(&blued_g.ctl_clients_lock);
	if (*rc == 0)
		(void)pthread_mutex_unlock(&blued_g.ctl_clients_lock);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(dispatch_lock_recursive_holds_across_reacquire);
ATF_TC_BODY(dispatch_lock_recursive_holds_across_reacquire, tc)
{
	pthread_t probe;
	int rc;

	test_init();

	/* Outer acquire (as dispatch does before running a verb handler). */
	ATF_REQUIRE_EQ(0, tsa_lock());
	/*
	 * Inner re-acquire (as a DISCONNECT/STATUS/POWER helper does).  On a
	 * plain ERRORCHECK mutex this would return EDEADLK; recursion returns 0.
	 */
	ATF_CHECK_EQ(0, tsa_lock());
	/* The inner unlock must NOT release the mutex — the original bug. */
	ATF_CHECK_EQ(0, tsa_unlock());

	rc = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&probe, NULL,
	    ctl_lock_trylock_probe, &rc));
	ATF_REQUIRE_EQ(0, pthread_join(probe, NULL));
	/* Still held by this thread: another thread's trylock must fail. */
	ATF_CHECK(rc != 0);

	/* Outer unlock now truly releases it. */
	ATF_CHECK_EQ(0, tsa_unlock());
	rc = -1;
	ATF_REQUIRE_EQ(0, pthread_create(&probe, NULL,
	    ctl_lock_trylock_probe, &rc));
	ATF_REQUIRE_EQ(0, pthread_join(probe, NULL));
	ATF_CHECK_EQ(0, rc);
}

/*
 * Finding 30/88: a dispatch-reachable helper that re-acquires ctl_clients_lock
 * (here blued_ctl_broadcast_conn_event, on the DISCONNECT path) must complete
 * and deliver its frame while the caller already holds the lock — proving the
 * critical section is not shredded by the inner lock/unlock.
 */
ATF_TC_WITHOUT_HEAD(dispatch_broadcast_under_held_lock);
ATF_TC_BODY(dispatch_broadcast_under_held_lock, tc)
{
	struct blued_ctl_client *client;
	int sp[2];
	uint8_t feat[8] = { 0 };
	bdaddr_t addr;
	uint8_t payload[IPC_MAX_PAYLOAD];
	uint16_t type, arg;
	ssize_t len;

	test_init();
	memset(&addr, 0x11, sizeof(addr));
	client = make_client(sp);
	client->peer_uid = 0;
	LIST_INSERT_HEAD(&blued_g.ctl_clients, client, entries);
	ipc_handshake(client, sp[1], IPC_PROTO_VERSION,
	    IPC_FEATURE_EVENTS, feat, sizeof(feat));

	/* Simulate dispatch holding the lock across the verb handler. */
	ATF_REQUIRE_EQ(0, tsa_lock());
	blued_ctl_broadcast_conn_event(&addr, BLUED_ROLE_CENTRAL, 1, 0,
	    0x40, 0, false, 0x13);
	/* The lock must still be held (recursion preserved it). */
	{
		int trc;
		pthread_t probe;

		trc = 0;
		ATF_REQUIRE_EQ(0, pthread_create(&probe, NULL,
		    ctl_lock_trylock_probe, &trc));
		ATF_REQUIRE_EQ(0, pthread_join(probe, NULL));
		ATF_CHECK(trc != 0);
	}
	ATF_REQUIRE_EQ(0, tsa_unlock());

	/* The DISCONNECTED event was actually delivered to the subscriber. */
	len = ipc_recv(sp[1], &type, &arg, payload, sizeof(payload));
	ATF_CHECK(len > 0);
	ATF_CHECK_EQ(IPC_T_OP_EVENT, type);
	ATF_CHECK_EQ(IPC_OP_DOMAIN_GAP, arg);
	ATF_CHECK_EQ(IPC_GAP_EV_DISCONNECTED,
	    ipc_get_le16((uint8_t *)payload + IPC_OP_PREFIX_SIZE));

	LIST_REMOVE(client, entries);
	close(sp[0]);
	close(sp[1]);
	blued_ctl_client_fini(client);
	free(client);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, dispatch_lock_recursive_holds_across_reacquire);
	ATF_TP_ADD_TC(tp, dispatch_broadcast_under_held_lock);
	ATF_TP_ADD_TC(tp, test_ipc_hello_match);
	ATF_TP_ADD_TC(tp, test_ipc_hello_version_mismatch);
	ATF_TP_ADD_TC(tp, test_ipc_feature_negotiation);
	ATF_TP_ADD_TC(tp, test_ipc_event_optin_gating);
	ATF_TP_ADD_TC(tp, test_ipc_typed_status);
	ATF_TP_ADD_TC(tp, test_ipc_typed_adapter_caps);
	ATF_TP_ADD_TC(tp, test_ipc_periodic_routes_adapter);
	ATF_TP_ADD_TC(tp, test_ipc_typed_control_validation);
	ATF_TP_ADD_TC(tp, test_ipc_typed_control_set_mtu);
	ATF_TP_ADD_TC(tp, test_ipc_correlated_control);
	ATF_TP_ADD_TC(tp, test_ipc_correlated_gatt_database);
	ATF_TP_ADD_TC(tp, test_ipc_correlated_security);
	ATF_TP_ADD_TC(tp, test_ipc_correlated_gap_disconnect);
	ATF_TP_ADD_TC(tp, test_ipc_typed_control_runtime_settings);

	/* Capability broker (fd-passing): ACQUIRE_COC / ACQUIRE_ISO */
	ATF_TP_ADD_TC(tp, test_ctl_acquire_coc_typed);

	/* Per-characteristic GATT data-path acquire (AcquireNotify/AcquireWrite) */
	ATF_TP_ADD_TC(tp, test_ctl_acquire_notify_typed);
	ATF_TP_ADD_TC(tp, test_ctl_acquire_notify_tx_full_no_leak);
	ATF_TP_ADD_TC(tp, test_ctl_acquire_data_and_teardown_matrix);

	ATF_TP_ADD_TC(tp, test_ctl_disconnect);
	ATF_TP_ADD_TC(tp, test_ctl_send_fd);
	ATF_TP_ADD_TC(tp, test_ctl_tx_queue_backpressure);
	ATF_TP_ADD_TC(tp, test_ctl_init_cleanup);
	ATF_TP_ADD_TC(tp, test_ctl_init_preserves_live_socket);
	ATF_TP_ADD_TC(tp, test_ctl_gatt_worker_io);
	ATF_TP_ADD_TC(tp, test_ctl_gatt_security_retry);
	ATF_TP_ADD_TC(tp, test_ctl_accept);
	ATF_TP_ADD_TC(tp, test_ctl_max_clients);

	/* GATT service management commands */
	ATF_TP_ADD_TC(tp, test_ctl_gatt_result_matrix);
	ATF_TP_ADD_TC(tp, test_gatt_runtime_db_persist);
	ATF_TP_ADD_TC(tp, test_ctl_gatt_staged_remove_service_changed_range);
	ATF_TP_ADD_TC(tp, test_ctl_gatt_conn_gone_purges_peer_routes);
	ATF_TP_ADD_TC(tp, test_ctl_gatt_subscribe_routes_before_cccd_response);
	ATF_TP_ADD_TC(tp, test_ctl_gatt_client_exit_cccd_ownership);
	ATF_TP_ADD_TC(tp, test_ctl_gatt_client_exit_cleanup_bound);
	ATF_TP_ADD_TC(tp, test_typed_domain_opcode_sweep);
	ATF_TP_ADD_TC(tp, test_typed_gatt_server_matrix);
	ATF_TP_ADD_TC(tp, test_typed_security_valid_matrix);
	ATF_TP_ADD_TC(tp, test_typed_validation_operand_matrix);
	ATF_TP_ADD_TC(tp, test_typed_gap_valid_matrix);
	ATF_TP_ADD_TC(tp, test_ctl_event_notification_matrix);
	ATF_TP_ADD_TC(tp, test_ctl_gatt_event_value_bounds);
	ATF_TP_ADD_TC(tp, test_ctl_pairing_agent_lifecycle);
	ATF_TP_ADD_TC(tp, test_typed_advertising_valid_lifecycle);
	ATF_TP_ADD_TC(tp, test_typed_periodic_valid_matrix);

	/* LOGLEVEL command */

	/* SUBSCRIBE / UNSUBSCRIBE */

	/* SET_VALUE */

	/* PASSKEY_REPLY / NUMCMP_REPLY */

	/* Rate limiting */

	/* HOGP_READ stub */

	/* SMP reply validation */

	/* REKEY (BLE key refresh) ctl surface */

	/* HOGP */

	/* New commands */

	/* CONNECT_NAME */

	/* BOND_EXPORT */

	/* CONNPARAMS with value verification */

	/* LIST with name from bond DB */

	/* LOGLEVEL boundaries */

	/* WRITE hex validation */

	/* Advertising / connection parameter operations */
	ATF_TP_ADD_TC(tp, test_ctl_path_loss_success);
	ATF_TP_ADD_TC(tp, test_ctl_path_loss_validation_and_capability);
	ATF_TP_ADD_TC(tp, test_ctl_path_loss_hci_failures);

	/* Runtime pairing agent (the common pairing-agent model) */

	/* Atomic GATT-application registration (the common GATT-application model) */

	/* Mesh bearer (broker step C). */
	ATF_TP_ADD_TC(tp, test_ctl_mesh_hello_implies_events);
	ATF_TP_ADD_TC(tp, test_ctl_mesh_rx_malformed_ad);
	ATF_TP_ADD_TC(tp, test_ctl_mesh_typed_full_matrix);
	ATF_TP_ADD_TC(tp, test_ctl_reset_owner_lifecycle);
	ATF_TP_ADD_TC(tp, test_ipc_framing_guard_matrix);
	ATF_TP_ADD_TC(tp, test_typed_adv_periodic_l2cap_guards);
	ATF_TP_ADD_TC(tp, test_ctl_internal_whitebox_completion);
	ATF_TP_ADD_TC(tp, test_finding35_handshake_gate);
	ATF_TP_ADD_TC(tp, test_finding28_security_event_layout);
	ATF_TP_ADD_TC(tp, test_finding31_wildcard_subscribe);
	ATF_TP_ADD_TC(tp, test_finding37_pair_initiates);

	return (atf_no_error());
}
