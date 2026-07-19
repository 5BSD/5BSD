/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_TEST_COMMON_H_
#define _BLUED_TEST_COMMON_H_

/*
 * Common stub definitions shared across blued ATF test programs.
 *
 * Each test binary is a separate executable, so it is safe to define
 * (not just declare) globals and functions here -- only one copy of
 * each symbol will exist per binary.
 *
 * Only stubs that are identical in 3+ test files belong here.
 * File-specific stubs remain in their respective test files.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ================================================================
 * Fork-based SMP test recv() guard timeout
 *
 * The SMP pairing tests fork a mock peer and drive the handshake over a
 * socketpair with SO_RCVTIMEO-bounded recv()s.  Under parallel kyua the
 * peer (or the in-process DUT) can be scheduled seconds late, so the guard
 * must be generous enough to absorb scheduler latency without tripping on a
 * correct-but-slow exchange.  It stays bounded (not blocking forever), so a
 * genuine deadlock still fails the case within the guard; kyua's per-test
 * timeout is the outer backstop.  Tests that assert the SMP state machine's
 * OWN protocol timeout use their own (short) values, not this guard.
 * ================================================================ */
#define SMP_TEST_IO_TIMEO_SEC	30

#include "ble_util.h"
#include "blued_devmgr.h"
#include "hci_log.h"

/* ================================================================
 * ble_util.h globals
 * ================================================================ */
/*
 * Globals — declared extern in ble_util.h / blued.h.
 * Tests that include blued.h will have the extern visible already;
 * for others, provide an extern declaration to satisfy -Wmissing-variable-declarations.
 */
#ifndef _BLUED_H_
extern atomic_bool blued_shutting_down;
#endif

atomic_int blued_verbose;
int blued_daemonized;
atomic_bool blued_shutting_down;
extern bool test_hci_log_on;
extern unsigned int test_hci_log_l2cap_calls;
bool test_hci_log_on;
unsigned int test_hci_log_l2cap_calls;

/* ================================================================
 * hci_log.c stubs -- no-op implementations for test builds
 * ================================================================ */
bool
hci_log_enabled(void)
{

	return (test_hci_log_on);
}

void
hci_log_l2cap(uint16_t con_handle __unused, uint16_t cid __unused,
    const uint8_t *data __unused, size_t len __unused,
    bool incoming __unused)
{

	test_hci_log_l2cap_calls++;
}

void
hci_log_packet(uint8_t type __unused, const uint8_t *data __unused,
    uint16_t len __unused, bool incoming __unused)
{
}

/* ================================================================
 * ble_coc_connect stub -- returns -1 (no CoC support in tests)
 *
 * Define TEST_CUSTOM_BLE_COC_CONNECT before including this header
 * to provide your own ble_coc_connect implementation.
 * ================================================================ */
#ifndef TEST_CUSTOM_BLE_COC_CONNECT
/* Prototype — not in any header, declared ad-hoc in att.c */
int	ble_coc_connect(const uint8_t *, const uint8_t *, uint8_t, uint16_t,
	    uint16_t);

int
ble_coc_connect(const uint8_t *local_addr __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused,
    uint16_t psm __unused, uint16_t mtu __unused)
{

	return (-1);
}
#endif

/* Default enhanced connector for ATT-only tests without an L2CAP seam. */
#ifndef TEST_CUSTOM_BLE_ECBFC_CONNECT
int	ble_ecbfc_connect(const uint8_t *, const uint8_t *, uint8_t,
	    uint16_t, uint16_t, int, int *);

int
ble_ecbfc_connect(const uint8_t *local_addr __unused,
    const uint8_t *addr __unused, uint8_t addr_type __unused,
    uint16_t psm __unused, uint16_t mtu __unused, int count __unused,
    int *fds __unused)
{

	return (0);
}
#endif

/* ================================================================
 * ctl.h stubs -- no ctl socket in tests
 * ================================================================ */
#include "ctl.h"
#include "smp.h"

/* smp_verify_signature stub -- only for tests not linking real smp.c.
 * Define TEST_LINKS_SMP before including this header to suppress. */
#ifndef TEST_LINKS_SMP
bool
smp_verify_signature(const uint8_t csrk[16] __unused,
    const uint8_t *msg __unused, size_t msg_len __unused,
    const uint8_t mac[8] __unused, uint32_t counter __unused)
{
	return (false);
}
#endif

/*
 * ctl notify stubs -- only for tests that do NOT link the real ctl.c.
 * Define TEST_LINKS_CTL before including this header to suppress.  A test that
 * needs to observe these calls (e.g. platform_test) defines
 * TEST_CUSTOM_CTL_NOTIFY and provides its own capturing implementations.
 */
#if !defined(TEST_LINKS_CTL) && !defined(TEST_CUSTOM_CTL_NOTIFY)
struct att_conn;

void
blued_ctl_notify_value(struct blued_conn *conn __unused, uint16_t handle __unused,
    const uint8_t *value __unused, uint16_t len __unused,
    uint16_t bearer_mtu __unused)
{
}

void
blued_ctl_notify_write(int owner_fd __unused, uint16_t handle __unused,
    const uint8_t *value __unused, uint16_t len __unused)
{
}

void
blued_ctl_notify_read(int owner_fd __unused, uint16_t handle __unused,
    uint16_t offset __unused)
{
}

void
blued_ctl_notify_authorize(int owner_fd __unused, uint16_t handle __unused,
    bool is_write __unused, const struct att_conn *ac __unused)
{
}
#endif

/*
 * Advertising HCI stubs for tests that link the real ctl.c: the ADVERTISE /
 * ADV_DATA / SCAN_RESP commands (finding C10) call these, but the ctl test
 * link set does not include hci_adv.c.  Return success so the command handlers
 * reach their OK path.  Only defined when TEST_LINKS_CTL is set, so tests that
 * link the real hci_adv.c do not collide.
 */
#ifdef TEST_LINKS_CTL
#include "hci_util.h"
#include "config.h"

/* Per-translation-unit controller failures used by ctl white-box tests. */
static int test_hci_adv_enable_rc;
static int test_hci_ext_adv_enable_rc;
static int test_blued_privacy_set_rc;
static int test_hci_rpa_timeout_rc;

/*
 * Static daemon config instance (normally defined in blued.c).  ctl.c consults
 * blued_cfg for the privacy own-address default (SET_ADV_PARAMS) and the RPA
 * timeout; the ctl test link set does not include blued.c, so provide it here.
 */
extern struct blued_config blued_cfg;
struct blued_config blued_cfg;

int
hci_le_set_advertise_enable(int hci_fd __unused, bool enable __unused)
{

	return (test_hci_adv_enable_rc);
}

int
hci_le_set_ext_adv_enable(int hci_fd __unused, uint8_t enable __unused,
    uint8_t handle __unused)
{

	return (test_hci_ext_adv_enable_rc);
}

int
hci_le_set_advertising_data(int hci_fd __unused, const uint8_t *data __unused,
    uint8_t len __unused)
{

	return (0);
}

int
hci_le_set_ext_adv_data(int hci_fd __unused, uint8_t handle __unused,
    const uint8_t *data __unused, uint8_t len __unused)
{

	return (0);
}

int
hci_le_set_ext_adv_params_phy(int fd __unused, uint8_t handle __unused,
    uint16_t props __unused, uint32_t min __unused, uint32_t max __unused,
    uint8_t own __unused, uint8_t filter __unused, uint8_t primary __unused,
    uint8_t secondary __unused)
{
	return (0);
}

int
hci_le_remove_adv_set(int fd __unused, uint8_t handle __unused)
{
	return (0);
}

int
hci_le_set_scan_response_data(int hci_fd __unused, const uint8_t *data __unused,
    uint8_t len __unused)
{

	return (0);
}

int
hci_le_set_ext_scan_response_data(int fd __unused, uint8_t handle __unused,
    const uint8_t *data __unused, uint8_t len __unused)
{

	return (0);
}

/*
 * Mesh bearer (broker step C) HCI seam.  The MESH_ADV_SEND / MESH_ADV_SUBSCRIBE
 * operations in ctl.c call these, but the ctl test link set does not include
 * hci_adv.c / hci_scan.c.  Default pass-through stubs let the handlers reach
 * their OK path; a test that wants to observe the emitted AD bytes / scanner
 * toggles defines TEST_CUSTOM_MESH_HCI and supplies capturing implementations.
 */
#ifndef TEST_CUSTOM_MESH_HCI
int
hci_mesh_adv_burst(int hci_fd __unused, uint64_t le_features __unused,
    const uint8_t *ad __unused, uint8_t adlen __unused)
{

	return (0);
}

int
hci_le_mesh_scan_set(int hci_fd __unused, uint64_t le_features __unused,
    bool on __unused)
{

	return (0);
}
#endif /* TEST_CUSTOM_MESH_HCI */

/*
 * Advertising/connection parameter HCI stubs for tests that link the real
 * ctl.c/ctl_conn.c (SET_ADV_PARAMS, CONNPARAMS_UPDATE, SET_PHY, SET_DATA_LEN)
 * but not the real hci_adv.c/hci_conn.c.  A test that wants to observe the
 * mapped parameters defines TEST_CUSTOM_ADVCONN_HCI and provides capturing
 * implementations instead.
 */
#ifndef TEST_CUSTOM_ADVCONN_HCI
int
hci_adv_configure(int hci_fd __unused, uint64_t le_features __unused,
    struct hci_adv_config *cfg)
{

	cfg->used_extended = (le_features & LE_FEAT_EXT_ADVERTISING) != 0 &&
	    cfg->mode != HCI_ADV_MODE_LEGACY;
	return (0);
}

int
hci_le_connection_update(int hci_fd __unused, uint16_t handle __unused,
    uint16_t interval_min __unused, uint16_t interval_max __unused,
    uint16_t latency __unused, uint16_t timeout __unused)
{

	return (0);
}

bool
l2cap_conn_param_use_hci_update(uint64_t local_features)
{

	return ((local_features & LE_FEAT_CONN_PARAM_REQ) != 0);
}

int
hci_le_set_phy(int hci_fd __unused, uint16_t con_handle __unused,
    uint8_t all_phys __unused, uint8_t tx_phys __unused,
    uint8_t rx_phys __unused, uint16_t phy_options __unused)
{

	return (0);
}

int
hci_le_set_data_length(int hci_fd __unused, uint16_t con_handle __unused,
    uint16_t tx_octets __unused, uint16_t tx_time __unused)
{

	return (0);
}

/* Periodic-advertising control seam; HCI byte layouts are tested separately. */
int
hci_le_set_periodic_adv_params(int fd __unused, uint8_t handle __unused,
    uint16_t min __unused, uint16_t max __unused, uint16_t props __unused)
{
	return (0);
}

int
hci_le_set_periodic_adv_data(int fd __unused, uint8_t handle __unused,
    const uint8_t *data __unused, uint8_t len __unused)
{
	return (0);
}

int
hci_le_set_periodic_adv_enable(int fd __unused, uint8_t enable __unused,
    uint8_t handle __unused)
{
	return (0);
}

int
hci_le_periodic_adv_create_sync(int fd __unused, uint8_t options __unused,
    uint8_t sid __unused, uint8_t type __unused,
    const uint8_t addr[6] __unused, uint16_t skip __unused,
    uint16_t timeout __unused)
{
	return (0);
}

int
hci_le_periodic_adv_create_sync_cancel(int fd __unused)
{
	return (0);
}

int
hci_le_periodic_adv_terminate_sync(int fd __unused, uint16_t handle __unused)
{
	return (0);
}

int
hci_le_add_dev_to_periodic_adv_list(int fd __unused, uint8_t type __unused,
    const uint8_t addr[6] __unused, uint8_t sid __unused)
{
	return (0);
}

int
hci_le_remove_dev_from_periodic_adv_list(int fd __unused, uint8_t type __unused,
    const uint8_t addr[6] __unused, uint8_t sid __unused)
{
	return (0);
}

int
hci_le_clear_periodic_adv_list(int fd __unused)
{
	return (0);
}

int
hci_le_read_periodic_adv_list_size(int fd __unused, uint8_t *size)
{
	if (size != NULL)
		*size = 8;
	return (0);
}

int
hci_le_set_periodic_adv_receive_enable(int fd __unused,
    uint16_t handle __unused, uint8_t enable __unused)
{
	return (0);
}

int
hci_get_con_handle(int fd __unused, const uint8_t addr[6] __unused,
    uint16_t *handle)
{
	*handle = 1;
	return (0);
}

int
hci_le_periodic_adv_sync_transfer(int fd __unused, uint16_t con_handle __unused,
    uint16_t service_data __unused, uint16_t sync_handle __unused)
{
	return (0);
}
int
hci_le_periodic_adv_set_info_transfer(int fd __unused,
    uint16_t con_handle __unused, uint16_t service_data __unused,
    uint8_t adv_handle __unused)
{
	return (0);
}
int
hci_le_set_past_params(int fd __unused, uint16_t con_handle __unused,
    uint8_t mode __unused, uint16_t skip __unused, uint16_t timeout __unused,
    uint8_t cte __unused)
{
	return (0);
}
int
hci_le_set_default_past_params(int fd __unused, uint8_t mode __unused,
    uint16_t skip __unused, uint16_t timeout __unused, uint8_t cte __unused)
{
	return (0);
}
int
hci_le_set_path_loss_reporting_params(int fd __unused, uint16_t handle __unused,
    uint8_t high __unused, uint8_t high_hyst __unused, uint8_t low __unused,
    uint8_t low_hyst __unused, uint16_t min __unused)
{
	return (0);
}
int
hci_le_set_path_loss_reporting_enable(int fd __unused, uint16_t handle __unused,
    uint8_t enable __unused)
{
	return (0);
}
#endif /* TEST_CUSTOM_ADVCONN_HCI */

/*
 * Runtime privacy / RPA-timeout seam for tests that link the real ctl.c
 * (PRIVACY / RPA_TIMEOUT operations) but not blued.c / hci_privacy.c.  A test that
 * wants to observe the toggle defines TEST_CUSTOM_PRIVACY and supplies its own.
 */
#ifndef TEST_CUSTOM_PRIVACY
int
blued_privacy_set(int hci_fd __unused, bool on __unused)
{

	return (test_blued_privacy_set_rc);
}

int
blued_adapter_set_privacy(struct blued_adapter *adp, bool on)
{

	return (blued_privacy_set(adp != NULL ? adp->hci_fd : -1, on));
}

int
hci_le_set_rpa_timeout(int hci_fd __unused, uint16_t timeout_sec __unused)
{

	return (test_hci_rpa_timeout_rc);
}
#endif /* TEST_CUSTOM_PRIVACY */

/*
 * Non-primary extended-advertising registry seam.  ctl.c owns client-facing
 * handles but the production registry lives in blued.c; white-box ctl tests
 * that do not link blued.c use this state-faithful adapter-local substitute.
 */
#if defined(TEST_LINKS_CTL) && !defined(TEST_CUSTOM_EXT_ADV_REGISTRY)
int
blued_ext_adv_set_track(struct blued_adapter *adp, uint8_t handle,
    uint16_t props, uint32_t imin, uint32_t imax, uint8_t own,
    uint8_t filter, uint8_t pphy, uint8_t sphy, uint8_t channels,
    int8_t txpower, uint8_t peer_type, const uint8_t *peer)
{
	struct blued_ext_adv_set *set = NULL;

	if (adp == NULL || handle == 0)
		return (-1);
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
		if (adp->ext_adv_sets[i].used &&
		    adp->ext_adv_sets[i].handle == handle) {
			set = &adp->ext_adv_sets[i];
			break;
		}
	for (size_t i = 0; set == NULL && i < nitems(adp->ext_adv_sets); i++)
		if (!adp->ext_adv_sets[i].used)
			set = &adp->ext_adv_sets[i];
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

	if (adp == NULL)
		return (false);
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
		if (adp->ext_adv_sets[i].used &&
		    adp->ext_adv_sets[i].handle == handle)
			return (true);
	return (false);
}

void
blued_ext_adv_set_enabled(struct blued_adapter *adp, uint8_t handle, bool on)
{

	if (adp == NULL)
		return;
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
		if (adp->ext_adv_sets[i].used &&
		    adp->ext_adv_sets[i].handle == handle)
			adp->ext_adv_sets[i].enabled = on;
}

void
blued_ext_adv_set_untrack(struct blued_adapter *adp, uint8_t handle)
{

	if (adp == NULL)
		return;
	for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++)
		if (adp->ext_adv_sets[i].used &&
		    adp->ext_adv_sets[i].handle == handle)
			memset(&adp->ext_adv_sets[i], 0,
			    sizeof(adp->ext_adv_sets[i]));
}
#endif

#ifdef TEST_LINKS_CTL
#ifndef TEST_CUSTOM_PRIMARY_ADV_CACHE
void
blued_primary_adv_cache(struct blued_adapter *adp __unused,
    bool scan_rsp __unused, const uint8_t *data __unused, uint8_t len __unused)
{
}
#endif

int
blued_set_rpa_timeout(int timeout_sec)
{
	struct blued_adapter *adp;

	if (timeout_sec < 1 || timeout_sec > 3600)
		return (-1);
	LIST_FOREACH(adp, &blued_g.adapters, entries)
		if (adp->active && hci_le_set_rpa_timeout(adp->hci_fd,
		    (uint16_t)timeout_sec) < 0)
			return (-1);
	blued_cfg.rpa_timeout = timeout_sec;
	return (0);
}

int
blued_adv_set_privacy_prepare(struct blued_adapter *adp __unused,
    uint8_t handle __unused)
{

	return (0);
}
#endif

/*
 * Operator adapter-setting + parameterised-scan seam for tests that link the
 * real ctl.c/ctl_conn.c (POWER / DISCOVERABLE / PAIRABLE / SET_NAME and the
 * filtered SCAN path) but not blued.c/hci_scan.c.  Default pass-through stubs so
 * the handlers reach their success path; a test that wants to observe the mapped
 * settings/parameters defines TEST_CUSTOM_ADAPTER_SCAN and supplies capturing
 * implementations instead.
 */
#ifndef TEST_CUSTOM_ADAPTER_SCAN
atomic_bool blued_pairable = true;

int	blued_adapter_set_power(struct blued_adapter *adp, bool on);
int	blued_adapter_set_discoverable(struct blued_adapter *adp, bool enable,
	    bool limited, unsigned int timeout_sec);
int	blued_set_device_name(const char *name);

int
blued_adapter_set_power(struct blued_adapter *adp, bool on)
{

	if (adp != NULL)
		adp->powered = on;
	return (0);
}

int
blued_adapter_set_discoverable(struct blued_adapter *adp, bool enable,
    bool limited __unused, unsigned int timeout_sec __unused)
{

	if (adp != NULL)
		adp->discoverable = enable;
	return (0);
}

int
blued_set_device_name(const char *name __unused)
{

	return (0);
}

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
ble_scan_result_match(const struct ble_scan_result *sr __unused,
    const struct ble_scan_filter *f __unused)
{

	return (true);
}

/*
 * The parameterised scan entry points forward to the classic hci_le_scan() /
 * hci_le_ext_scan() the test already stubs, so a test that primes scan results
 * through those also reaches the parameterized scan entry points.
 */
int
hci_le_scan_ex(int hci_fd, int duration_sec,
    const struct hci_scan_params *params __unused,
    struct ble_scan_result *results, int maxresults, int *nresults)
{

	return (hci_le_scan(hci_fd, duration_sec, results, maxresults,
	    nresults));
}

int
hci_le_ext_scan_ex(int hci_fd, int duration_sec,
    const struct hci_scan_params *params __unused,
    struct ble_scan_result *results, int maxresults, int *nresults,
    uint8_t scanning_phys)
{

	return (hci_le_ext_scan(hci_fd, duration_sec, results, maxresults,
	    nresults, scanning_phys));
}
#endif /* TEST_CUSTOM_ADAPTER_SCAN */

/*
 * PC4 bond import/export seam.  ctl.c's BOND_EXPORT / BOND_IMPORT operations
 * call the smp_keys.c record (de)serializer + DB inserter and blued.c's
 * resolving-list add.  Tests that link ctl.c but neither smp_keys.c nor blued.c
 * get these default stubs so the daemon object links; a test that exercises the
 * operations (ctl_test) defines TEST_CUSTOM_BOND_MIGRATE and supplies capturing
 * implementations instead.
 */
#ifndef TEST_CUSTOM_BOND_MIGRATE
size_t
smp_bond_export_record(const struct smp_bond *bond __unused, uint8_t *out,
    size_t outsz)
{

	if (out == NULL || outsz < SMP_BOND_REC_LEN)
		return (0);
	memset(out, 0, SMP_BOND_REC_LEN);
	return (SMP_BOND_REC_LEN);
}

int
smp_bond_import_record(const uint8_t *rec __unused, size_t len __unused,
    struct smp_bond *out __unused)
{

	return (-1);
}

int
smp_bond_db_import(struct smp_bond_db *db __unused,
    const struct smp_bond *bond __unused)
{

	return (1);
}

void
blued_reslist_sync_add(int hci_fd __unused, const struct smp_bond *bond __unused)
{
}
#endif /* TEST_CUSTOM_BOND_MIGRATE */

#endif /* TEST_LINKS_CTL */

/* Typed ISO operation seam for tests that link ctl.c without the ISO engine. */
#if defined(TEST_LINKS_CTL) && !defined(TEST_LINKS_CTL_ISO)
struct blued_ctl_client;

void	ctl_iso_process_typed(struct blued_ctl_client *client,
	    const uint8_t *payload, size_t plen);

void
ctl_iso_process_typed(struct blued_ctl_client *client __unused,
    const uint8_t *payload __unused, size_t plen __unused)
{
}
#endif

#endif /* _BLUED_TEST_COMMON_H_ */
