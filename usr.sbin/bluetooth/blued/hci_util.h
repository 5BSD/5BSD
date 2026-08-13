/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_HCI_UTIL_H_
#define _BLUED_HCI_UTIL_H_

#include <stdint.h>
#include <stdbool.h>

/*
 * Core 6.3 Vol 4 Part E §7.7.65.13 Address_Type 0xFF means that an
 * extended advertising report supplies no device address.  Preserve that
 * distinction in ble_scan_result.addr_type so callers cannot mistake an
 * anonymous report for a public peer.
 */
#define BLE_SCAN_ADDR_ANONYMOUS		0xFF

/* Core 6.3 Vol 4 Part E §7.8.10 Own_Address_Type values. */
#define BLUED_HCI_OWN_ADDR_PUBLIC		0x00
#define BLUED_HCI_OWN_ADDR_RANDOM		0x01
#define BLUED_HCI_OWN_ADDR_RPA_PUBLIC_FALLBACK	0x02
#define BLUED_HCI_OWN_ADDR_RPA_RANDOM_FALLBACK	0x03

/* Core 6.3 Vol 4 Part E §§7.8.5 and 7.8.53 advertising values. */
#define BLUED_HCI_ADV_TYPE_UNDIRECTED		0x00
#define BLUED_HCI_ADV_TYPE_DIRECTED_HIGH		0x01
#define BLUED_HCI_ADV_TYPE_DIRECTED_LOW		0x04
#define BLUED_HCI_EXT_ADV_PROP_CONNECTABLE	0x0001
#define BLUED_HCI_EXT_ADV_PROP_SCANNABLE		0x0002
#define BLUED_HCI_EXT_ADV_PROP_DIRECTED		0x0004
#define BLUED_HCI_EXT_ADV_PROP_HIGH_DUTY_DIRECTED 0x0008
#define BLUED_HCI_EXT_ADV_PROP_LEGACY		0x0010
#define BLUED_HCI_EXT_ADV_PROP_ANONYMOUS		0x0020

/*
 * BLE scan result entry.
 */
struct ble_scan_result {
	uint8_t		addr[6];
	uint8_t		addr_type;	/* BDADDR_LE_* or BLE_SCAN_ADDR_ANONYMOUS */
	int8_t		rssi;
	char		name[32];	/* from AD Complete/Short Local Name */
	bool		has_name;
	bool		name_complete;	/* Complete Local Name, not shortened */
	uint16_t	mfr_id;		/* manufacturer company ID, 0xFFFF = none */
	uint16_t	svc_uuids[8];	/* 16-bit service UUIDs */
	int		num_svc_uuids;
};

#define BLE_MAX_SCAN_RESULTS	64

/*
 * Scan parameter seam (Core Spec Vol 4 Part E §7.8.10 LE Set Scan Parameters,
 * §7.8.64 LE Set Extended Scan Parameters, §7.8.11/§7.8.65 Scan Enable).
 * Normalizes the operator-tunable scan knobs so ctl SCAN can drive them and a
 * conformance test can assert the emitted command bytes.  intervals/windows are
 * in units of 0.625 ms (valid range 0x0004-0x4000); active selects active vs
 * passive scanning; filter_policy 0 = accept all, 1 = accept-list only;
 * filter_dup enables controller-side duplicate filtering.  hci_scan_params_default()
 * fills the historical defaults (active, 100 ms interval, 50 ms window, dedup on).
 */
struct hci_scan_params {
	uint8_t		active;		/* 1 = active scan, 0 = passive */
	uint16_t	interval;	/* units of 0.625 ms */
	uint16_t	window;		/* units of 0.625 ms */
	uint8_t		filter_policy;	/* 0 = accept all, 1 = accept-list */
	uint8_t		filter_dup;	/* 1 = filter duplicates */
};

/*
 * Post-scan result filter (parity with the common discovery-filter model UUIDs/RSSI +
 * NimBLE app-side filtering).  Applied to parsed advertising reports before
 * they are reported to the client.  A field is inactive unless its has_* flag
 * is set; an all-clear filter matches every device.
 */
struct ble_scan_filter {
	bool		has_uuid;
	uint16_t	uuid16;		/* require this 16-bit service UUID */
	bool		has_rssi;
	int8_t		rssi_min;	/* drop reports weaker than this */
	bool		has_name;
	char		name_sub[32];	/* require this substring in the name */
};

/*
 * Advertising configuration seam.
 *
 * Normalized set of advertising knobs an operator can request, decoupled from
 * the two wire encodings (legacy LE Set Advertising Parameters, Core Spec Vol 4
 * Part E §7.8.5; extended LE Set Extended Advertising Parameters, §7.8.53).
 * hci_adv_configure() validates the request, selects the legacy or extended
 * path (honouring the controller's LE_FEAT_EXT_ADVERTISING), and issues the
 * matching command.  The ctl SET_ADV_PARAMS verb fills this from text; the
 * conformance test fills it directly and asserts the emitted command bytes.
 */
enum hci_adv_mode {
	HCI_ADV_MODE_AUTO = 0,	/* extended when the controller supports it */
	HCI_ADV_MODE_LEGACY,	/* force legacy advertising PDUs */
	HCI_ADV_MODE_EXTENDED,	/* extended, falling back to legacy if absent */
};

/* Normalized advertising type (§7.8.5 Advertising_Type / §7.8.53 props). */
enum hci_adv_kind {
	HCI_ADV_CONN_UND = 0,	/* connectable undirected (ADV_IND) */
	HCI_ADV_CONN_DIR_HIGH,	/* connectable directed, high duty cycle */
	HCI_ADV_CONN_DIR_LOW,	/* connectable directed, low duty cycle */
	HCI_ADV_SCAN_UND,	/* scannable undirected (ADV_SCAN_IND) */
	HCI_ADV_NONCONN_UND,	/* non-connectable undirected (ADV_NONCONN_IND) */
};

struct hci_adv_config {
	enum hci_adv_mode	mode;
	enum hci_adv_kind	kind;
	uint32_t		interval_min;	/* units of 0.625 ms */
	uint32_t		interval_max;	/* units of 0.625 ms */
	uint8_t			channel_map;	/* bit0=ch37 bit1=ch38 bit2=ch39 */
	int8_t			tx_power;	/* extended only; 0x7F = no pref */
	uint8_t			own_addr_type;	/* 0x00-0x03 */
	uint8_t			filter_policy;
	uint8_t			primary_phy;	/* extended: 1=1M 3=Coded */
	uint8_t			secondary_phy;	/* extended: 1=1M 2=2M 3=Coded */
	bool			has_peer;	/* directed target present */
	uint8_t			peer_addr_type;	/* directed only */
	uint8_t			peer_addr[6];	/* directed only */
	bool			used_extended;	/* OUT: extended path was taken */
};

/* hci_util.c — central mode */
int	hci_open(const char *adapter);
int	hci_get_bdaddr(int hci_fd, uint8_t *bdaddr);
int	hci_get_con_handle(int hci_fd, const uint8_t *remote_addr,
	    uint16_t *handle);
int	hci_le_scan(int hci_fd, int duration_sec,
	    struct ble_scan_result *results, int maxresults, int *nresults);
/*
 * Scan with explicit parameters (active/passive, interval, window,
 * filter policy, duplicate filtering).  hci_le_scan() is the thin default
 * wrapper.  hci_le_set_scan_params()/hci_le_set_ext_scan_params() issue only
 * the parameter-set command (for conformance byte assertions); they validate
 * the request and reject out-of-range values before any I/O (errno EINVAL).
 */
void	hci_scan_params_default(struct hci_scan_params *p);
int	hci_le_scan_ex(int hci_fd, int duration_sec,
	    const struct hci_scan_params *params,
	    struct ble_scan_result *results, int maxresults, int *nresults);
int	hci_le_set_scan_params(int hci_fd, const struct hci_scan_params *params);
int	hci_le_set_ext_scan_params(int hci_fd,
	    const struct hci_scan_params *params, uint8_t scanning_phys);
int	hci_le_set_scan_enable(int hci_fd, uint8_t enable, uint8_t filter_dup);
/*
 * True when a parsed advertising report satisfies every active clause of the
 * post-scan filter (UUID / RSSI floor / name substring).  A NULL or all-clear
 * filter matches everything.
 */
bool	ble_scan_result_match(const struct ble_scan_result *sr,
	    const struct ble_scan_filter *f);
int	hci_wait_encryption(int hci_fd, uint16_t con_handle, int timeout_sec);

/* hci_util.c — peripheral mode (advertising + LTK) */
int	hci_le_set_advertising_params(int hci_fd, uint16_t interval_min,
	    uint16_t interval_max, uint8_t adv_type,
	    uint8_t own_addr_type, uint8_t filter_policy);
int	hci_le_set_advertising_params_dir(int hci_fd, uint16_t interval_min,
	    uint16_t interval_max, uint8_t adv_type,
	    uint8_t own_addr_type, uint8_t filter_policy,
	    uint8_t direct_address_type, const uint8_t *direct_address);
int	hci_le_set_advertising_params_full(int hci_fd, uint16_t interval_min,
	    uint16_t interval_max, uint8_t adv_type,
	    uint8_t own_addr_type, uint8_t filter_policy, uint8_t channel_map,
	    uint8_t direct_address_type, const uint8_t *direct_address);
/*
 * Validate a normalized advertising request, choose legacy vs extended, and
 * issue the matching HCI command.  Core Spec Vol 4 Part E §7.8.5 / §7.8.53.
 */
int	hci_adv_configure(int hci_fd, uint64_t le_features,
	    struct hci_adv_config *cfg);
int	hci_le_set_advertising_data(int hci_fd, const uint8_t *data,
	    uint8_t len);
int	hci_le_set_scan_response_data(int hci_fd, const uint8_t *data,
	    uint8_t len);
int	hci_le_set_advertise_enable(int hci_fd, bool enable);
int	hci_le_ltk_request_reply(int hci_fd, uint16_t con_handle,
	    const uint8_t ltk[16]);
int	hci_le_ltk_request_neg_reply(int hci_fd, uint16_t con_handle);
int	ble_build_adv_data(uint8_t *buf, size_t buflen, const char *name,
	    const uint16_t *uuids, int nuuids);
/*
 * Build advertising data with an explicit Flags AD value (Core Spec CSS Part A
 * §1.3): bit0 = LE Limited Discoverable, bit1 = LE General Discoverable,
 * bit2 = BR/EDR Not Supported.  ble_build_adv_data() is the general-discoverable
 * (0x06) wrapper.
 */
int	ble_build_adv_data_flags(uint8_t *buf, size_t buflen, uint8_t flags,
	    const char *name, const uint16_t *uuids, int nuuids);

/* AD Flags bits (Core Spec CSS Part A §1.3). */
#define AD_FLAG_LIMITED_DISC	0x01
#define AD_FLAG_GENERAL_DISC	0x02
#define AD_FLAG_BREDR_NOT_SUPP	0x04

/* hci_util.c — HCI init and feature detection (Phase 2.5) */
int	hci_reset(int hci_fd);
int	hci_node_init(int hci_fd);
int	hci_write_le_host_support(int hci_fd, uint8_t le_host,
	    uint8_t simultaneous);
int	hci_le_read_local_features(int hci_fd, uint64_t *features);
int	hci_set_event_mask(int hci_fd, uint64_t mask);
uint64_t	hci_le_default_event_mask(uint64_t features);
int	hci_le_set_event_mask(int hci_fd, uint64_t mask);
int	hci_le_connection_update(int hci_fd, uint16_t handle,
	    uint16_t interval_min, uint16_t interval_max,
	    uint16_t latency, uint16_t timeout);
int	l2cap_conn_param_update_req(const uint8_t *local_addr,
	    const uint8_t *peer_addr, uint8_t peer_addr_type,
	    uint16_t interval_min, uint16_t interval_max,
	    uint16_t latency, uint16_t timeout);
bool	l2cap_conn_param_use_hci_update(uint64_t local_features);

/* LE feature bits (Core Spec Vol 6 Part B Section 4.6) */
#define LE_FEAT_ENCRYPTION		(1ULL << 0)
#define LE_FEAT_CONN_PARAM_REQ		(1ULL << 1)
#define LE_FEAT_EXT_REJECT_IND		(1ULL << 2)
#define LE_FEAT_PERIPH_INIT_FEAT_XCHG	(1ULL << 3)
#define LE_FEAT_LE_PING			(1ULL << 4)
#define LE_FEAT_DATA_LENGTH_EXT		(1ULL << 5)
#define LE_FEAT_LL_PRIVACY		(1ULL << 6)
#define LE_FEAT_EXT_SCANNER_FILTER	(1ULL << 7)
#define LE_FEAT_2M_PHY			(1ULL << 8)
#define LE_FEAT_CODED_PHY		(1ULL << 11)
#define LE_FEAT_EXT_ADVERTISING		(1ULL << 12)
#define LE_FEAT_PERIODIC_ADV		(1ULL << 13)
	/* Core Vol 6 Part B §4.6.23/.24: PAST roles are distinct. */
#define LE_FEAT_PAST_SENDER		(1ULL << 24)
#define LE_FEAT_PAST_RECIPIENT		(1ULL << 25)
#define LE_FEAT_CIS_CENTRAL		(1ULL << 28)
#define LE_FEAT_CIS_PERIPH		(1ULL << 29)
#define LE_FEAT_ISO_BROADCASTER		(1ULL << 30)
#define LE_FEAT_ISO_SYNC_RECEIVER	(1ULL << 31)
#define LE_FEAT_POWER_CONTROL		(1ULL << 33)
#define LE_FEAT_PATH_LOSS_MONITORING	(1ULL << 35)
#define LE_FEAT_CONN_SUBRATING		(1ULL << 37)	/* BT 5.3 — see note in blued_central.c */

/* LE event mask bits (Core Spec Vol 4 Part E Section 7.8.1) */
#define LE_EVTMASK_CONN_COMPLETE	(1ULL << 0)
#define LE_EVTMASK_ADV_REPORT		(1ULL << 1)
#define LE_EVTMASK_CONN_UPDATE		(1ULL << 2)
#define LE_EVTMASK_READ_REMOTE_FEAT	(1ULL << 3)
#define LE_EVTMASK_LTK_REQUEST		(1ULL << 4)
#define LE_EVTMASK_DATA_LENGTH_CHANGE	(1ULL << 6)
#define LE_EVTMASK_ENH_CONN_COMPLETE	(1ULL << 9)
#define LE_EVTMASK_PHY_UPDATE_COMPL	(1ULL << 11)
#define LE_EVTMASK_EXT_ADV_REPORT	(1ULL << 12)
#define LE_EVTMASK_PER_ADV_SYNC_EST	(1ULL << 13)
#define LE_EVTMASK_PER_ADV_REPORT	(1ULL << 14)
#define LE_EVTMASK_PER_ADV_SYNC_LOST	(1ULL << 15)
#define LE_EVTMASK_SCAN_TIMEOUT		(1ULL << 16)  /* subevent 0x11 */
#define LE_EVTMASK_ADV_SET_TERM		(1ULL << 17)
#define LE_EVTMASK_SCAN_REQ_RCVD	(1ULL << 18)  /* subevent 0x13 */
#define LE_EVTMASK_CHAN_SEL_ALGO	(1ULL << 19)  /* subevent 0x14 */
#define LE_EVTMASK_PATH_LOSS_THRESH	(1ULL << 31)  /* subevent 0x20 */
#define LE_EVTMASK_TX_POWER_REPORT	(1ULL << 32)  /* subevent 0x21 */
#define LE_EVTMASK_BIGINFO_ADV_REP	(1ULL << 33)  /* subevent 0x22 */
#define LE_EVTMASK_PER_ADV_SYNC_XFER	(1ULL << 23)
#define LE_EVTMASK_CIS_ESTABLISHED	(1ULL << 24)
#define LE_EVTMASK_CIS_REQUEST		(1ULL << 25)
#define LE_EVTMASK_CREATE_BIG_COMPL	(1ULL << 26)
#define LE_EVTMASK_TERM_BIG_COMPL	(1ULL << 27)
#define LE_EVTMASK_BIG_SYNC_EST	(1ULL << 28)
#define LE_EVTMASK_BIG_SYNC_LOST	(1ULL << 29)
#define LE_EVTMASK_SUBRATE_CHANGE	(1ULL << 34)

/* hci_util.c — LE Privacy / Resolving List (Phase 2A) */
int	hci_le_clear_resolving_list(int hci_fd);
int	hci_le_add_dev_resolving_list(int hci_fd, uint8_t addr_type,
	    const uint8_t addr[6], const uint8_t peer_irk[16],
	    const uint8_t local_irk[16]);
int	hci_le_remove_dev_resolving_list(int hci_fd, uint8_t addr_type,
	    const uint8_t addr[6]);
int	hci_le_set_addr_resolution_enable(int hci_fd, uint8_t enable);
int	hci_le_set_privacy_mode(int hci_fd, uint8_t addr_type,
	    const uint8_t addr[6], uint8_t mode);
int	hci_le_set_rpa_timeout(int hci_fd, uint16_t timeout_sec);
int	hci_le_set_random_address(int hci_fd, const uint8_t addr[6]);

/* hci_util.c — LE Extended Advertising (Phase 2B) */
int	hci_le_set_ext_adv_params(int hci_fd, uint8_t handle,
	    uint16_t event_props, uint32_t interval_min,
	    uint32_t interval_max, uint8_t own_addr_type,
	    uint8_t filter_policy);
int	hci_le_set_ext_adv_params_phy(int hci_fd, uint8_t handle,
	    uint16_t event_props, uint32_t interval_min,
	    uint32_t interval_max, uint8_t own_addr_type,
	    uint8_t filter_policy, uint8_t primary_phy,
	    uint8_t secondary_phy);
int	hci_le_set_ext_adv_params_dir(int hci_fd, uint8_t handle,
	    uint16_t event_props, uint32_t interval_min,
	    uint32_t interval_max, uint8_t own_addr_type,
	    uint8_t filter_policy, uint8_t primary_phy,
	    uint8_t secondary_phy, uint8_t peer_address_type,
	    const uint8_t *peer_address);
int	hci_le_set_ext_adv_params_full(int hci_fd, uint8_t handle,
	    uint16_t event_props, uint32_t interval_min,
	    uint32_t interval_max, uint8_t own_addr_type,
	    uint8_t filter_policy, uint8_t primary_phy,
	    uint8_t secondary_phy, uint8_t channel_map, int8_t tx_power,
	    uint8_t peer_address_type, const uint8_t *peer_address);
int	hci_le_set_ext_adv_data(int hci_fd, uint8_t handle,
	    const uint8_t *data, uint8_t len);
int	hci_le_set_ext_adv_enable(int hci_fd, uint8_t enable,
	    uint8_t handle);
int	hci_le_remove_adv_set(int hci_fd, uint8_t handle);

/*
 * Mesh bearer (broker step C): transmit one non-connectable, non-scannable
 * advertising burst carrying the caller-built AD structure(s) in `ad`
 * (already framed as [len][adtype][pdu...]).  Uses a dedicated mesh adv set
 * (handle MESH_ADV_HANDLE) on extended-advertising controllers so it
 * coexists with blued's own adv set, falling back to legacy adv on BT-4.0
 * controllers.  Returns 0 on success, -1 on a controller error.  The caller
 * (ctl.c) has already validated the AD type; this is a dumb transmit.
 */
/*
 * Dedicated mesh adv set handle.  Must not collide with blued's own
 * connectable set (0x00) or the peripheral Coded-PHY set (0x01); see
 * blued.c Coded-PHY advertising.  Uses 0x02 (finding 42).
 */
#define MESH_ADV_HANDLE		0x02	/* mesh adv set; 0x00/0x01 are in use */
int	hci_mesh_adv_burst(int hci_fd, uint64_t le_features,
	    const uint8_t *ad, uint8_t adlen);

/*
 * Mesh bearer (broker step C): enable/disable an always-on PASSIVE scan with
 * duplicate filtering OFF (the flooding bearer legitimately re-sends repeated
 * PDUs, which a dup filter would swallow).  on=true programs and enables the
 * scan; on=false disables it.  Returns 0 on success, -1 on a controller error.
 */
int	hci_le_mesh_scan_set(int hci_fd, uint64_t le_features, bool on);

/* hci_util.c — LE Extended Advertising management (BT 5.0) */
int	hci_le_set_adv_set_random_address(int fd, uint8_t handle,
	    const uint8_t addr[6]);
int	hci_le_set_ext_scan_response_data(int fd, uint8_t handle,
	    const uint8_t *data, uint8_t len);
int	hci_le_read_max_adv_data_length(int fd, uint16_t *max_len);
int	hci_le_read_num_supported_adv_sets(int fd, uint8_t *num_sets);
int	hci_le_clear_adv_sets(int fd);

/* hci_util.c — LE Data Length Extension (Phase 1A) */
int	hci_le_set_data_length(int hci_fd, uint16_t con_handle,
	    uint16_t tx_octets, uint16_t tx_time);
int	hci_le_write_suggested_default_data_length(int hci_fd,
	    uint16_t tx_octets, uint16_t tx_time);

/* hci_util.c — LE PHY (Phase 1B) */
int	hci_le_set_default_phy(int hci_fd, uint8_t all_phys,
	    uint8_t tx_phys, uint8_t rx_phys);
int	hci_le_set_phy(int hci_fd, uint16_t con_handle, uint8_t all_phys,
	    uint8_t tx_phys, uint8_t rx_phys, uint16_t phy_options);
int	hci_le_read_phy(int hci_fd, uint16_t con_handle,
	    uint8_t *tx_phy, uint8_t *rx_phy);

/* hci_util.c — LE Filter Accept List (Phase 3) */
int	hci_le_clear_filter_accept_list(int hci_fd);
int	hci_le_add_device_to_filter_accept_list(int hci_fd,
	    uint8_t addr_type, const uint8_t addr[6]);
int	hci_le_remove_device_from_filter_accept_list(int hci_fd,
	    uint8_t addr_type, const uint8_t addr[6]);

/* hci_util.c — LE Host Feature / Connection Cancel (Phase 3) */
int	hci_le_set_host_feature(int hci_fd, uint8_t bit_number,
	    uint8_t bit_value);
int	hci_le_create_connection_cancel(int hci_fd);

/* hci_util.c — LE Extended Scanning (Phase 4) */
int	hci_le_ext_scan(int hci_fd, int duration_sec,
	    struct ble_scan_result *results, int maxresults, int *nresults,
	    uint8_t scanning_phys);
int	hci_le_ext_scan_ex(int hci_fd, int duration_sec,
	    const struct hci_scan_params *params,
	    struct ble_scan_result *results, int maxresults, int *nresults,
	    uint8_t scanning_phys);

/* hci_util.c — LE Periodic Advertising (BT 5.0) */
#define HCI_PERIODIC_ADV_PROP_INCLUDE_TX_POWER	0x0040u
int	hci_le_set_periodic_adv_params(int hci_fd, uint8_t handle,
	    uint16_t interval_min, uint16_t interval_max,
	    uint16_t properties);
int	hci_le_set_periodic_adv_data(int hci_fd, uint8_t handle,
	    const uint8_t *data, uint8_t len);
int	hci_le_set_periodic_adv_enable(int hci_fd, uint8_t enable,
	    uint8_t handle);
int	hci_le_periodic_adv_create_sync(int hci_fd, uint8_t options,
	    uint8_t adv_sid, uint8_t addr_type, const uint8_t addr[6],
	    uint16_t skip, uint16_t sync_timeout);
int	hci_le_periodic_adv_create_sync_cancel(int hci_fd);
int	hci_le_periodic_adv_terminate_sync(int hci_fd,
	    uint16_t sync_handle);
int	hci_le_add_dev_to_periodic_adv_list(int hci_fd,
	    uint8_t addr_type, const uint8_t addr[6], uint8_t adv_sid);
int	hci_le_remove_dev_from_periodic_adv_list(int hci_fd,
	    uint8_t addr_type, const uint8_t addr[6], uint8_t adv_sid);
int	hci_le_clear_periodic_adv_list(int hci_fd);
int	hci_le_read_periodic_adv_list_size(int hci_fd, uint8_t *size);

/* hci_util.c — LE PAST (BT 5.1) */
int	hci_le_set_periodic_adv_receive_enable(int hci_fd,
	    uint16_t sync_handle, uint8_t enable);
int	hci_le_periodic_adv_sync_transfer(int hci_fd,
	    uint16_t con_handle, uint16_t service_data,
	    uint16_t sync_handle);
int	hci_le_periodic_adv_set_info_transfer(int hci_fd,
	    uint16_t con_handle, uint16_t service_data,
	    uint8_t adv_handle);
int	hci_le_set_past_params(int hci_fd, uint16_t con_handle,
	    uint8_t mode, uint16_t skip, uint16_t sync_timeout,
	    uint8_t cte_type);
int	hci_le_set_default_past_params(int hci_fd, uint8_t mode,
	    uint16_t skip, uint16_t sync_timeout, uint8_t cte_type);

/* hci_util.c — LE Direction Finding (BT 5.1) */
int	hci_le_set_connless_cte_tx_params(int hci_fd,
	    uint8_t adv_handle, uint8_t cte_length, uint8_t cte_type,
	    uint8_t cte_count, uint8_t switching_pattern_len,
	    const uint8_t *antenna_ids);
int	hci_le_set_connless_cte_tx_enable(int hci_fd,
	    uint8_t adv_handle, uint8_t enable);
int	hci_le_set_connless_iq_sampling_enable(int hci_fd,
	    uint16_t sync_handle, uint8_t enable, uint8_t slot_durations,
	    uint8_t max_sampled_ctes, uint8_t switching_pattern_len,
	    const uint8_t *antenna_ids);
int	hci_le_set_conn_cte_rx_params(int hci_fd,
	    uint16_t conn_handle, uint8_t enable, uint8_t slot_durations,
	    uint8_t switching_pattern_len, const uint8_t *antenna_ids);
int	hci_le_set_conn_cte_tx_params(int hci_fd,
	    uint16_t conn_handle, uint8_t cte_types,
	    uint8_t switching_pattern_len, const uint8_t *antenna_ids);
int	hci_le_conn_cte_req_enable(int hci_fd,
	    uint16_t conn_handle, uint8_t enable,
	    uint16_t cte_req_interval, uint8_t cte_length,
	    uint8_t cte_type);
int	hci_le_conn_cte_rsp_enable(int hci_fd,
	    uint16_t conn_handle, uint8_t enable);
int	hci_le_read_antenna_info(int hci_fd,
	    uint8_t *supported_switching_rates, uint8_t *num_antennae,
	    uint8_t *max_switching_pattern_len, uint8_t *max_cte_length);

/* LE feature bits — Direction Finding (Core Spec Vol 6 Part B §4.6 Table 4.9) */
#define LE_FEAT_CONN_CTE_REQ		(1ULL << 17)
#define LE_FEAT_CONN_CTE_RSP		(1ULL << 18)
#define LE_FEAT_CONNLESS_CTE_TX		(1ULL << 19)
#define LE_FEAT_CONNLESS_CTE_RX		(1ULL << 20)

/* LE event mask bits — Direction Finding */
#define LE_EVTMASK_CONNLESS_IQ_REPORT	(1ULL << 20)  /* subevent 0x15 */
#define LE_EVTMASK_CONN_IQ_REPORT	(1ULL << 21)  /* subevent 0x16 */
#define LE_EVTMASK_CTE_REQ_FAILED	(1ULL << 22)  /* subevent 0x17 */

/* hci_util.c — LE Connection Subrating (BT 5.3) */
int	hci_le_set_default_subrate(int hci_fd, uint16_t min_subrate,
	    uint16_t max_subrate, uint16_t max_latency,
	    uint16_t cont_num, uint16_t timeout);
int	hci_le_subrate_request(int hci_fd, uint16_t con_handle,
	    uint16_t min_subrate, uint16_t max_subrate,
	    uint16_t max_latency, uint16_t cont_num, uint16_t timeout);

/* hci_util.c — LE Power Control (BT 5.2) */
int	hci_le_enhanced_read_tx_power_level(int hci_fd,
	    uint16_t con_handle, uint8_t phy, int8_t *cur_level,
	    int8_t *max_level);
int	hci_le_read_remote_tx_power_level(int hci_fd,
	    uint16_t con_handle, uint8_t phy);
int	hci_le_set_path_loss_reporting_params(int hci_fd,
	    uint16_t con_handle, uint8_t high_thresh, uint8_t high_hyst,
	    uint8_t low_thresh, uint8_t low_hyst, uint16_t min_time);
int	hci_le_set_path_loss_reporting_enable(int hci_fd,
	    uint16_t con_handle, uint8_t enable);
int	hci_le_set_tx_power_reporting_enable(int hci_fd,
	    uint16_t con_handle, uint8_t local_enable,
	    uint8_t remote_enable);

/* hci_util.c — LE Extended Create Connection (BT 5.0) */
int	hci_le_ext_create_connection(int hci_fd, uint8_t filter,
	    uint8_t own_addr, uint8_t peer_addr_type,
	    const uint8_t peer_addr[6], uint8_t phys,
	    const void *phy_params, size_t phy_len);

/* hci_util.c — LE ISO Channels (BT 5.2) */
int	hci_le_read_buffer_size_v2(int hci_fd, uint16_t *acl_len,
	    uint8_t *acl_num, uint16_t *iso_len, uint8_t *iso_num);
int	hci_le_read_iso_tx_sync(int hci_fd, uint16_t con_handle,
	    uint16_t *packet_seq, uint32_t *timestamp, uint32_t *offset);
int	hci_le_set_cig_params(int hci_fd, uint8_t cig_id,
	    uint32_t sdu_interval_c, uint32_t sdu_interval_p,
	    uint8_t worst_case_sca, uint8_t packing, uint8_t framing,
	    uint16_t max_transport_latency_c, uint16_t max_transport_latency_p,
	    uint8_t cis_count, const void *cis_params, size_t cis_params_len,
	    uint8_t *out_cig_id, uint8_t *out_cis_count,
	    uint16_t *out_cis_handles);
struct hci_le_cig_params_test_cis {
	uint8_t		cis_id;
	uint8_t		nse;
	uint16_t	max_sdu_c_to_p;
	uint16_t	max_sdu_p_to_c;
	uint16_t	max_pdu_c_to_p;
	uint16_t	max_pdu_p_to_c;
	uint8_t		phy_c_to_p;
	uint8_t		phy_p_to_c;
	uint8_t		bn_c_to_p;
	uint8_t		bn_p_to_c;
};
int	hci_le_set_cig_params_test(int hci_fd, uint8_t cig_id,
	    uint32_t sdu_interval_c, uint32_t sdu_interval_p,
	    uint8_t ft_c_to_p, uint8_t ft_p_to_c, uint16_t iso_interval,
	    uint8_t worst_case_sca, uint8_t packing, uint8_t framing,
	    uint8_t cis_count, const struct hci_le_cig_params_test_cis *cis,
	    uint8_t *out_cig_id, uint8_t *out_cis_count,
	    uint16_t *out_cis_handles);
int	hci_le_create_cis(int hci_fd, uint8_t cis_count,
	    const uint16_t *cis_handles, const uint16_t *acl_handles);
int	hci_le_remove_cig(int hci_fd, uint8_t cig_id);
int	hci_le_accept_cis_request(int hci_fd, uint16_t con_handle);
int	hci_le_reject_cis_request(int hci_fd, uint16_t con_handle,
	    uint8_t reason);
int	hci_le_create_big(int hci_fd, uint8_t big_handle, uint8_t adv_handle,
	    uint8_t num_bis, uint32_t sdu_interval, uint16_t max_sdu,
	    uint16_t max_transport_latency, uint8_t rtn, uint8_t phy,
	    uint8_t packing, uint8_t framing, uint8_t encryption,
	    const uint8_t broadcast_code[16]);
int	hci_le_create_big_test(int hci_fd, uint8_t big_handle,
	    uint8_t adv_handle, uint8_t num_bis, uint32_t sdu_interval,
	    uint16_t iso_interval, uint8_t nse, uint16_t max_sdu,
	    uint16_t max_pdu, uint8_t phy, uint8_t packing, uint8_t framing,
	    uint8_t bn, uint8_t irc, uint8_t pto, uint8_t encryption,
	    const uint8_t broadcast_code[16]);
int	hci_le_terminate_big(int hci_fd, uint8_t big_handle, uint8_t reason);
int	hci_le_big_create_sync(int hci_fd, uint8_t big_handle,
	    uint16_t sync_handle, uint8_t encryption,
	    const uint8_t broadcast_code[16], uint8_t mse,
	    uint16_t big_sync_timeout, uint8_t num_bis,
	    const uint8_t *bis_indices);
int	hci_le_big_terminate_sync(int hci_fd, uint8_t big_handle);
int	hci_le_setup_iso_data_path(int hci_fd, uint16_t con_handle,
	    uint8_t direction, uint8_t path_id, const uint8_t codec_id[5],
	    uint32_t controller_delay, uint8_t codec_config_len,
	    const uint8_t *codec_config);
int	hci_le_remove_iso_data_path(int hci_fd, uint16_t con_handle,
	    uint8_t direction);
int	hci_le_request_peer_sca(int hci_fd, uint16_t con_handle);
int	hci_le_read_iso_link_quality(int hci_fd, uint16_t con_handle,
	    uint32_t *tx_unacked, uint32_t *tx_flushed,
	    uint32_t *tx_last_subevent, uint32_t *retransmitted,
	    uint32_t *crc_error, uint32_t *rx_unreceived,
	    uint32_t *duplicate);

/* hci_util.c — LE Ping / Authenticated Payload Timeout (BT 4.1) */
int	hci_le_read_auth_payload_timeout(int fd, uint16_t con_handle,
	    uint16_t *timeout);
int	hci_le_write_auth_payload_timeout(int fd, uint16_t con_handle,
	    uint16_t timeout);

/* hci_util.c — Set Min Encryption Key Size (BT 5.3, HC&Baseband) */
int	hci_set_min_enc_key_size(int fd, uint8_t key_size);

/* hci_util.c — HCI Disconnect */
int	hci_disconnect(int hci_fd, uint16_t con_handle, uint8_t reason);

/* hci_util.c — raw HCI command (bypasses bt_devreq) */
int	hci_send_raw_cmd(int hci_fd, uint16_t opcode, const void *params,
	    uint8_t plen);

/* hci_util.c — LE CoC (Connection-Oriented Channel) initiation */
void	hci_l2cap_set_own_address_type(uint8_t own_addr_type);
int	ble_coc_connect(const uint8_t *local_addr, const uint8_t *addr,
	    uint8_t addr_type, uint16_t psm, uint16_t mtu);

/* hci_util.c — ECBFC (Enhanced Credit Based Flow Control, BT 5.2) */
int	ble_ecbfc_connect(const uint8_t *local_addr, const uint8_t *addr,
	    uint8_t addr_type, uint16_t psm, uint16_t mtu, int count, int *fds);
int	ble_ecbfc_reconfig(int fd, uint16_t new_mtu, uint16_t new_mps);

/* hci_util.c — ISO (CIS/BIS) data-path socket for an established stream */
int	ble_iso_connect(const uint8_t *src, const uint8_t *addr,
	    uint8_t addr_type, uint16_t cis_handle, uint16_t mtu);

/*
 * Invalidate the per-fd HCI lock slot and scan-state slot when an adapter's
 * raw HCI socket is closed, so a later reused fd number does not inherit stale
 * state.  Call immediately before close(hci_fd).  (finding 48)
 */
void	hci_fd_closed(int fd);
void	hci_scan_forget_fd(int hci_fd);

#endif /* _BLUED_HCI_UTIL_H_ */
