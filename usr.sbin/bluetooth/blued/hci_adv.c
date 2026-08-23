/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI advertising commands for blued.
 *
 * Legacy advertising (BT 4.0), extended advertising (BT 5.0),
 * periodic advertising (BT 5.0), and direction finding CTE (BT 5.1).
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <netgraph/bluetooth/include/ng_btsocket.h>

#include "ble_util.h"
#include "blued_probes.h"
#include "hci_log.h"
#include "hci_util.h"
#include "hci_internal.h"

/* AD type codes for advertising data building */
#define AD_TYPE_FLAGS			0x01
#define AD_TYPE_UUID16_INCOMPLETE	0x02
#define AD_TYPE_UUID16_COMPLETE		0x03
#define AD_TYPE_SHORT_LOCAL_NAME		0x08
#define AD_TYPE_COMPLETE_LOCAL_NAME	0x09

/* ----------------------------------------------------------------
 * Legacy Advertising (BT 4.0)
 * ---------------------------------------------------------------- */

/*
 * Legacy advertising types that are directed (ADV_DIRECT_IND) and therefore
 * require a Peer_Address to target (Core Spec Vol 4 Part E §7.8.5,
 * Advertising_Type table): 0x01 = high duty cycle, 0x04 = low duty cycle.
 */
static bool
hci_adv_handle_valid(uint8_t handle)
{

	return (handle <= 0xef);
}

static bool
adv_type_is_directed(uint8_t adv_type)
{

	return (adv_type == BLUED_HCI_ADV_TYPE_DIRECTED_HIGH ||
	    adv_type == BLUED_HCI_ADV_TYPE_DIRECTED_LOW);
}

/*
 * LE Set Advertising Parameters (directed-capable).
 * interval_min/max are in units of 0.625ms (e.g. 0x0800 = 1.28s).
 * adv_type: 0x00 = ADV_IND (connectable undirected), 0x01/0x04 =
 * ADV_DIRECT_IND (high/low duty cycle).
 *
 * When adv_type is a directed type the Peer_Address / Peer_Address_Type
 * fields carry the target device address (Core Spec Vol 4 Part E §7.8.5);
 * they are ignored by the controller for undirected types.
 */
int
hci_le_set_advertising_params_full(int hci_fd, uint16_t interval_min,
    uint16_t interval_max, uint8_t adv_type,
    uint8_t own_addr_type, uint8_t filter_policy, uint8_t channel_map,
    uint8_t direct_address_type, const uint8_t *direct_address)
{
	struct bt_devreq r;
	ng_hci_le_set_advertising_parameters_cp	cp;
	ng_hci_le_set_advertising_parameters_rp	rp;

	/*
	 * Core Spec Vol 4 Part E §7.8.5: the only interval constraints are the
	 * 0x0020-0x4000 range and Min <= Max.  There is no advertising-type
	 * dependent floor: the old BT-4.0 "0x00A0 for non-connectable/
	 * scannable" recommendation is a GAP guideline, not an HCI constraint,
	 * so rejecting it here would refuse spec-legal commands.
	 */
	if (interval_min < 0x0020 || interval_max > 0x4000 ||
	    interval_min > interval_max) {
		errno = EINVAL;
		return (-1);
	}
	if (adv_type > 0x04 || own_addr_type > 0x03 ||
	    filter_policy > 0x03 ||
	    (adv_type_is_directed(adv_type) && direct_address_type > 0x01)) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Advertising_Channel_Map is a 3-bit mask (bit0=ch37 bit1=ch38
	 * bit2=ch39); at least one primary channel must be enabled.
	 */
	if ((channel_map & ~0x07) != 0 || (channel_map & 0x07) == 0) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * A directed advertising type has no meaning without a target
	 * (Core Spec Vol 4 Part E §7.8.5): reject rather than emit a command
	 * with an all-zero Peer_Address.
	 */
	if (adv_type_is_directed(adv_type) && direct_address == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertising_interval_min = htole16(interval_min);
	cp.advertising_interval_max = htole16(interval_max);
	cp.advertising_type = adv_type;
	cp.own_address_type = own_addr_type;
	if (adv_type_is_directed(adv_type)) {
		cp.direct_address_type = direct_address_type;
		memcpy(&cp.direct_address, direct_address, 6);
	}
	cp.advertising_channel_map = channel_map;
	cp.advertising_filter_policy = filter_policy;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_ADVERTISING_PARAMETERS);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "set advertising params interval=%d-%d type=%d chan=0x%x",
	    interval_min, interval_max, adv_type, channel_map);

	return (0);
}

/*
 * LE Set Advertising Parameters (directed-capable) — all-channels wrapper.
 */
int
hci_le_set_advertising_params_dir(int hci_fd, uint16_t interval_min,
    uint16_t interval_max, uint8_t adv_type,
    uint8_t own_addr_type, uint8_t filter_policy,
    uint8_t direct_address_type, const uint8_t *direct_address)
{

	return (hci_le_set_advertising_params_full(hci_fd, interval_min,
	    interval_max, adv_type, own_addr_type, filter_policy, 0x07,
	    direct_address_type, direct_address));
}

/*
 * LE Set Advertising Parameters — undirected convenience wrapper.
 * adv_type 0x00 = ADV_IND (connectable undirected).
 */
int
hci_le_set_advertising_params(int hci_fd, uint16_t interval_min,
    uint16_t interval_max, uint8_t adv_type,
    uint8_t own_addr_type, uint8_t filter_policy)
{

	return (hci_le_set_advertising_params_dir(hci_fd, interval_min,
	    interval_max, adv_type, own_addr_type, filter_policy, 0, NULL));
}

/*
 * LE Set Advertising Data.
 * data/len is the raw AD structure payload (max 31 bytes).
 */
int
hci_le_set_advertising_data(int hci_fd, const uint8_t *data, uint8_t len)
{
	struct bt_devreq r;
	ng_hci_le_set_advertising_data_cp	cp;
	ng_hci_le_set_advertising_data_rp	rp;

	if (len > NG_HCI_ADVERTISING_DATA_SIZE ||
	    (len > 0 && data == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertising_data_length = len;
	if (len > 0)
		memcpy(cp.advertising_data, data, len);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_ADVERTISING_DATA);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * LE Set Scan Response Data (Core Spec Vol 4 Part E §7.8.8).
 * Used with legacy advertising (ADV_IND, ADV_SCAN_IND).
 */
int
hci_le_set_scan_response_data(int hci_fd, const uint8_t *data, uint8_t len)
{
	struct bt_devreq r;
	ng_hci_le_set_scan_response_data_cp	cp;
	ng_hci_le_set_scan_response_data_rp	rp;

	if (len > NG_HCI_ADVERTISING_DATA_SIZE ||
	    (len > 0 && data == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.scan_response_data_length = len;
	if (len > 0)
		memcpy(cp.scan_response_data, data, len);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_SCAN_RESPONSE_DATA);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * LE Set Advertise Enable / Disable.
 */
int
hci_le_set_advertise_enable(int hci_fd, bool enable)
{
	struct bt_devreq r;
	ng_hci_le_set_advertise_enable_cp	cp;
	ng_hci_le_set_advertise_enable_rp	rp;

	memset(&cp, 0, sizeof(cp));
	cp.advertising_enable = enable ? 1 : 0;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_ADVERTISE_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		errno = EIO;
		return (-1);
	}
	/* Legacy advertising set is implicit handle 0. */
	BLUED_PROBE_GAP_ADV_ENABLE(enable ? 1 : 0, 0);
	return (0);
}

/*
 * Build BLE advertising data with Flags, Local Name, and 16-bit UUID list.
 * Returns the number of bytes written, or -1 on error.
 */
int
ble_build_adv_data(uint8_t *buf, size_t buflen, const char *name,
    const uint16_t *uuids, int nuuids)
{

	/* Default: LE General Discoverable + BR/EDR Not Supported. */
	return (ble_build_adv_data_flags(buf, buflen,
	    AD_FLAG_GENERAL_DISC | AD_FLAG_BREDR_NOT_SUPP, name, uuids, nuuids));
}

int
ble_build_adv_data_flags(uint8_t *buf, size_t buflen, uint8_t flags,
    const char *name, const uint16_t *uuids, int nuuids)
{
	uint8_t *p = buf;
	size_t namelen;

	if (buflen < 3)
		return (-1);

	/* Flags AD (Core Spec CSS Part A §1.3). */
	*p++ = 2;		/* length */
	*p++ = AD_TYPE_FLAGS;
	*p++ = flags;

	/* Local Name */
	if (name != NULL) {
		size_t fulllen = strlen(name);
		uint8_t name_type;

		namelen = fulllen;
		if ((size_t)(p - buf) + 2 + namelen > buflen) {
			if ((size_t)(p - buf) + 2 >= buflen)
				namelen = 0;
			else
				namelen = buflen - (p - buf) - 2;
		}

		/* Use Shortened Local Name if truncated */
		name_type = (namelen < fulllen) ?
		    AD_TYPE_SHORT_LOCAL_NAME : AD_TYPE_COMPLETE_LOCAL_NAME;

		if (namelen > 0) {
			*p++ = (uint8_t)(1 + namelen);
			*p++ = name_type;
			memcpy(p, name, namelen);
			p += namelen;
		}
	}

	/* 16-bit UUID list */
	if (nuuids > 0) {
		size_t avail = buflen - (size_t)(p - buf);
		int fit;

		if (avail >= 2 + 2 * (size_t)nuuids) {
			/* Full list fits */
			fit = nuuids;
			*p++ = (uint8_t)(1 + 2 * fit);
			*p++ = AD_TYPE_UUID16_COMPLETE;
		} else if (avail >= 4) {
			/* Partial list: include as many as fit (CSS Part A §1.1) */
			fit = (int)((avail - 2) / 2);
			*p++ = (uint8_t)(1 + 2 * fit);
			*p++ = AD_TYPE_UUID16_INCOMPLETE;
		} else {
			fit = 0;
		}
		for (int i = 0; i < fit; i++) {
			*p++ = (uint8_t)(uuids[i] & 0xFF);
			*p++ = (uint8_t)(uuids[i] >> 8);
		}
	}

	return ((int)(p - buf));
}

/* ----------------------------------------------------------------
 * LE Extended Advertising (BT 5.0)
 * Core Spec Vol 4 Part E Sections 7.8.53-7.8.60
 * ---------------------------------------------------------------- */

/*
 * Extended advertising event property bit for a directed advertising event
 * (Core Spec Vol 4 Part E §7.8.53, Advertising_Event_Properties: bit 2 =
 * "Directed advertising").  A directed event requires a Peer_Address.
 */
/*
 * Set Extended Advertising Parameters (v1), directed-capable.
 * Explicit PHY selection; primary_phy: 1=1M, 3=Coded, secondary_phy: 1=1M,
 * 2=2M, 3=Coded.
 *
 * When advertising_event_properties requests a directed event (bit 2) the
 * Peer_Address / Peer_Address_Type fields carry the target device address
 * (Core Spec Vol 4 Part E §7.8.53); they are ignored for undirected events.
 */
int
hci_le_set_ext_adv_params_full(int hci_fd, uint8_t handle,
    uint16_t event_props, uint32_t interval_min,
    uint32_t interval_max, uint8_t own_addr_type,
    uint8_t filter_policy, uint8_t primary_phy,
    uint8_t secondary_phy, uint8_t channel_map, int8_t tx_power,
    uint8_t peer_address_type, const uint8_t *peer_address)
{
	struct bt_devreq r;
	ng_hci_le_set_ext_adv_params_cp cp;
	ng_hci_le_set_ext_adv_params_rp rp;

	/* Core Spec Vol 4 Part E §7.8.53: valid range 0x000020-0xFFFFFF */
	if (!hci_adv_handle_valid(handle) ||
	    interval_min < 0x000020 || interval_max > 0xFFFFFF ||
	    interval_min > interval_max) {
		errno = EINVAL;
		return (-1);
	}
	if (own_addr_type > 0x03 || filter_policy > 0x03 ||
	    (event_props & BLUED_HCI_EXT_ADV_PROP_DIRECTED &&
	    peer_address_type > 0x01) ||
	    (primary_phy != 0x01 && primary_phy != 0x03) ||
	    (secondary_phy < 0x01 || secondary_phy > 0x03) ||
	    (tx_power < -127 || (tx_power > 20 && tx_power != 0x7f))) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Finding H-M4: Core Spec Vol 4 Part E §7.8.53 forbids the high-duty-
	 * cycle directed bit (bit 3) with extended-PDU advertising (the "use
	 * legacy PDUs" bit 4 clear).  High-duty directed only exists for legacy
	 * ADV_DIRECT_IND.  Reject the combination host-side with a clear error
	 * rather than emitting a command the controller must reject.
	 */
	if ((event_props & BLUED_HCI_EXT_ADV_PROP_HIGH_DUTY_DIRECTED) &&
	    !(event_props & BLUED_HCI_EXT_ADV_PROP_LEGACY)) {
		errno = EINVAL;
		return (-1);
	}

	/* Primary_Advertising_Channel_Map: 3-bit mask, at least one channel. */
	if ((channel_map & ~0x07) != 0 || (channel_map & 0x07) == 0) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * A directed extended-advertising event has no meaning without a
	 * target (Core Spec Vol 4 Part E §7.8.53): reject rather than emit a
	 * command with an all-zero Peer_Address.
	 */
	if ((event_props & BLUED_HCI_EXT_ADV_PROP_DIRECTED) &&
	    peer_address == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertising_handle = handle;
	cp.advertising_event_properties = htole16(event_props);
	cp.primary_advertising_interval_min[0] = interval_min & 0xFF;
	cp.primary_advertising_interval_min[1] = (interval_min >> 8) & 0xFF;
	cp.primary_advertising_interval_min[2] = (interval_min >> 16) & 0xFF;
	cp.primary_advertising_interval_max[0] = interval_max & 0xFF;
	cp.primary_advertising_interval_max[1] = (interval_max >> 8) & 0xFF;
	cp.primary_advertising_interval_max[2] = (interval_max >> 16) & 0xFF;
	cp.primary_advertising_channel_map = channel_map;
	cp.own_address_type = own_addr_type;
	if (event_props & BLUED_HCI_EXT_ADV_PROP_DIRECTED) {
		cp.peer_address_type = peer_address_type;
		memcpy(&cp.peer_address, peer_address, 6);
	}
	cp.advertising_filter_policy = filter_policy;
	cp.advertising_tx_power = (uint8_t)tx_power;
	cp.primary_advertising_phy = primary_phy;
	cp.secondary_advertising_phy = secondary_phy;

	memset(&rp, 0, sizeof(rp));	/* Finding H-H3 */
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_ADV_PARAMS);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	/* Finding H-H3: a short CC that never carried status/selected_tx_power
	 * must not be accepted as success. */
	if ((size_t)r.rlen < sizeof(rp) || rp.status != 0x00) {
		LOG_HCI(1, "LE Set Ext Adv Params failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "ext adv params set: handle=%d tx_power=%d phy=%d/%d",
	    handle, rp.selected_tx_power, primary_phy, secondary_phy);
	return (0);
}

/*
 * Set Extended Advertising Parameters (v1), directed-capable — all-channels,
 * host-has-no-preference TX power wrapper.
 */
int
hci_le_set_ext_adv_params_dir(int hci_fd, uint8_t handle,
    uint16_t event_props, uint32_t interval_min,
    uint32_t interval_max, uint8_t own_addr_type,
    uint8_t filter_policy, uint8_t primary_phy,
    uint8_t secondary_phy, uint8_t peer_address_type,
    const uint8_t *peer_address)
{

	return (hci_le_set_ext_adv_params_full(hci_fd, handle, event_props,
	    interval_min, interval_max, own_addr_type, filter_policy,
	    primary_phy, secondary_phy, 0x07, 0x7F, peer_address_type,
	    peer_address));
}

/*
 * Set Extended Advertising Parameters (v1) with explicit PHY selection —
 * undirected wrapper (no Peer_Address).
 */
int
hci_le_set_ext_adv_params_phy(int hci_fd, uint8_t handle,
    uint16_t event_props, uint32_t interval_min,
    uint32_t interval_max, uint8_t own_addr_type,
    uint8_t filter_policy, uint8_t primary_phy,
    uint8_t secondary_phy)
{

	return (hci_le_set_ext_adv_params_dir(hci_fd, handle, event_props,
	    interval_min, interval_max, own_addr_type, filter_policy,
	    primary_phy, secondary_phy, 0, NULL));
}

/*
 * Convenience wrapper — defaults to 1M/1M PHY.
 */
int
hci_le_set_ext_adv_params(int hci_fd, uint8_t handle,
    uint16_t event_props, uint32_t interval_min,
    uint32_t interval_max, uint8_t own_addr_type,
    uint8_t filter_policy)
{

	return (hci_le_set_ext_adv_params_phy(hci_fd, handle,
	    event_props, interval_min, interval_max,
	    own_addr_type, filter_policy, 0x01, 0x01));
}

/*
 * Extended-advertising handle used for the single operator-configurable
 * advertising set (multi-set is a separate item).
 */
#define ADV_CFG_HANDLE			0x00

/*
 * Map a normalized advertising kind to the legacy Advertising_Type value
 * (Core Spec Vol 4 Part E §7.8.5, table of Advertising_Type).  Returns true
 * and stores the value, or false if the kind is directed (handled by the
 * caller through the *_dir field) — directed kinds still map to a type here.
 */
static uint8_t
adv_kind_to_legacy_type(enum hci_adv_kind kind)
{

	switch (kind) {
	case HCI_ADV_CONN_DIR_HIGH:	return (0x01); /* ADV_DIRECT_IND high */
	case HCI_ADV_SCAN_UND:		return (0x02); /* ADV_SCAN_IND */
	case HCI_ADV_NONCONN_UND:	return (0x03); /* ADV_NONCONN_IND */
	case HCI_ADV_CONN_DIR_LOW:	return (0x04); /* ADV_DIRECT_IND low */
	case HCI_ADV_CONN_UND:
	default:			return (0x00); /* ADV_IND */
	}
}

/*
 * Map a normalized advertising kind to extended Advertising_Event_Properties
 * bits (Core Spec Vol 4 Part E §7.8.53): bit0=connectable, bit1=scannable,
 * bit2=directed, bit3=high-duty-cycle directed.  These are non-legacy PDUs, so
 * PHY / TX power selection is meaningful (bit4 "use legacy PDUs" is not set).
 */
static uint16_t
adv_kind_to_ext_props(enum hci_adv_kind kind)
{

	/*
	 * These kinds are the legacy advertising PDU shapes.  On an extended
	 * controller they MUST carry the "use legacy PDUs" bit: without it a
	 * connectable extended set is non-scannable (rejects scan-response
	 * data) and a scannable extended set carries no advertising data, so
	 * the standard adv-data + scan-response plumbing (device name, UUIDs)
	 * fails with Invalid HCI Command Parameters.  With the LEGACY bit the
	 * property values match the legacy PDU types (ADV_IND=0x13,
	 * ADV_SCAN_IND=0x12, ADV_NONCONN_IND=0x10, ADV_DIRECT_IND low=0x15 /
	 * high=0x1D), where connectable+scannable coexist as they do on the
	 * wire.  (Large-payload extended advertising uses the adv-set path,
	 * not this legacy-shaped configure.)
	 */
	switch (kind) {
	case HCI_ADV_CONN_DIR_HIGH:
		return (BLUED_HCI_EXT_ADV_PROP_LEGACY |
		    BLUED_HCI_EXT_ADV_PROP_CONNECTABLE |
		    BLUED_HCI_EXT_ADV_PROP_DIRECTED |
		    BLUED_HCI_EXT_ADV_PROP_HIGH_DUTY_DIRECTED);
	case HCI_ADV_CONN_DIR_LOW:
		return (BLUED_HCI_EXT_ADV_PROP_LEGACY |
		    BLUED_HCI_EXT_ADV_PROP_CONNECTABLE |
		    BLUED_HCI_EXT_ADV_PROP_DIRECTED);
	case HCI_ADV_SCAN_UND:
		return (BLUED_HCI_EXT_ADV_PROP_LEGACY |
		    BLUED_HCI_EXT_ADV_PROP_SCANNABLE);
	case HCI_ADV_NONCONN_UND:
		return (BLUED_HCI_EXT_ADV_PROP_LEGACY);
	case HCI_ADV_CONN_UND:
	default:
		return (BLUED_HCI_EXT_ADV_PROP_LEGACY |
		    BLUED_HCI_EXT_ADV_PROP_CONNECTABLE |
		    BLUED_HCI_EXT_ADV_PROP_SCANNABLE);
	}
}

static bool
adv_kind_is_directed(enum hci_adv_kind kind)
{

	return (kind == HCI_ADV_CONN_DIR_HIGH || kind == HCI_ADV_CONN_DIR_LOW);
}

int
hci_adv_configure(int hci_fd, uint64_t le_features, struct hci_adv_config *cfg)
{
	bool have_ext = (le_features & LE_FEAT_EXT_ADVERTISING) != 0;
	bool use_ext;

	/* A directed advertising kind requires a target address. */
	if (adv_kind_is_directed(cfg->kind) && !cfg->has_peer) {
		errno = EINVAL;
		return (-1);
	}
	if (cfg->own_addr_type > 0x03) {
		errno = EINVAL;
		return (-1);
	}
	if ((cfg->channel_map & ~0x07) != 0 || (cfg->channel_map & 0x07) == 0) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Extended-vs-legacy selection.  EXTENDED and AUTO both fall back to
	 * legacy when the controller lacks LE_FEAT_EXT_ADVERTISING; LEGACY is
	 * always legacy.
	 */
	switch (cfg->mode) {
	case HCI_ADV_MODE_LEGACY:	use_ext = false;		break;
	case HCI_ADV_MODE_EXTENDED:	use_ext = have_ext;		break;
	case HCI_ADV_MODE_AUTO:
	default:			use_ext = have_ext;		break;
	}
	cfg->used_extended = use_ext;

	if (use_ext) {
		/* PHY selection only meaningful on the extended path. */
		if (cfg->primary_phy != 0x01 && cfg->primary_phy != 0x03) {
			errno = EINVAL;
			return (-1);
		}
		if (cfg->secondary_phy != 0x01 && cfg->secondary_phy != 0x02 &&
		    cfg->secondary_phy != 0x03) {
			errno = EINVAL;
			return (-1);
		}
		return (hci_le_set_ext_adv_params_full(hci_fd, ADV_CFG_HANDLE,
		    adv_kind_to_ext_props(cfg->kind), cfg->interval_min,
		    cfg->interval_max, cfg->own_addr_type, cfg->filter_policy,
		    cfg->primary_phy, cfg->secondary_phy, cfg->channel_map,
		    cfg->tx_power, cfg->peer_addr_type,
		    cfg->has_peer ? cfg->peer_addr : NULL));
	}

	/*
	 * Legacy path: the 16-bit interval field cannot express the extended
	 * 24-bit range, so an out-of-range value is rejected here rather than
	 * silently truncated.
	 */
	if (cfg->interval_min > 0xFFFF || cfg->interval_max > 0xFFFF) {
		errno = EINVAL;
		return (-1);
	}
	return (hci_le_set_advertising_params_full(hci_fd,
	    (uint16_t)cfg->interval_min, (uint16_t)cfg->interval_max,
	    adv_kind_to_legacy_type(cfg->kind), cfg->own_addr_type,
	    cfg->filter_policy, cfg->channel_map, cfg->peer_addr_type,
	    cfg->has_peer ? cfg->peer_addr : NULL));
}

/*
 * Set Extended Advertising Data (complete, single operation).
 * data can be up to 251 bytes.
 *
 * The Core Spec (Vol 4 Part E §7.8.54) allows up to 254 bytes for
 * non-connectable, non-scannable extended advertising PDUs.  We use
 * the conservative limit of 251 (NG_HCI_LE_EXT_ADV_DATA_MAX) for
 * all advertising types for simplicity, avoiding the need to check
 * the event properties to determine the exact maximum.
 */
/*
 * Upper bound on host-originated extended advertising data.  The controller's
 * true limit is Max_Advertising_Data_Length (Core Spec Vol 4 Part E §7.8.57,
 * up to 1650); we cap the host side at that spec maximum and let the controller
 * reject anything it cannot store.
 */
#define BLUED_HCI_EXT_ADV_DATA_TOTAL_MAX	1650

/* Issue a single LE Set Extended Advertising Data command with one Operation. */
static int
hci_le_set_ext_adv_data_op(int hci_fd, uint8_t handle, uint8_t operation,
    const uint8_t *data, uint8_t len)
{
	struct bt_devreq r;
	ng_hci_le_set_ext_adv_data_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.advertising_handle = handle;
	cp.operation = operation;
	cp.fragment_preference = 0x01;	/* controller should not fragment further */
	cp.advertising_data_length = len;
	if (len > 0)
		memcpy(cp.advertising_data, data, len);

	memset(&rp, 0, sizeof(rp));	/* Finding H-H3 */
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_ADV_DATA);
	r.cparam = &cp;
	/* Only send the actual data, not the full 251-byte buffer */
	r.clen = 4 + len;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if ((size_t)r.rlen < sizeof(rp) || rp.status != 0x00) {
		LOG_HCI(1, "LE Set Ext Adv Data failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	return (0);
}

int
hci_le_set_ext_adv_data(int hci_fd, uint8_t handle,
    const uint8_t *data, uint16_t len)
{
	const uint16_t frag_max = NG_HCI_LE_EXT_ADV_DATA_MAX;	/* 251 */
	uint16_t off;

	if (!hci_adv_handle_valid(handle) ||
	    len > BLUED_HCI_EXT_ADV_DATA_TOTAL_MAX ||
	    (len > 0 && data == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	/* Single-command fast path: Operation 0x03 (complete data). */
	if (len <= frag_max)
		return (hci_le_set_ext_adv_data_op(hci_fd, handle, 0x03,
		    data, (uint8_t)len));

	/*
	 * Finding H-M6: data too large for one HCI command must be delivered as
	 * an ordered fragment sequence (Core Spec Vol 4 Part E §7.8.54):
	 * Operation 0x01 (first fragment), 0x00 (intermediate), 0x02 (last).
	 * Each fragment carries at most NG_HCI_LE_EXT_ADV_DATA_MAX octets.
	 */
	off = 0;
	while (off < len) {
		uint16_t chunk = len - off;
		uint8_t op;

		if (chunk > frag_max)
			chunk = frag_max;
		if (off == 0)
			op = 0x01;			/* first */
		else if ((uint16_t)(off + chunk) >= len)
			op = 0x02;			/* last */
		else
			op = 0x00;			/* intermediate */
		if (hci_le_set_ext_adv_data_op(hci_fd, handle, op,
		    data + off, (uint8_t)chunk) < 0)
			return (-1);
		off = (uint16_t)(off + chunk);
	}
	return (0);
}

/*
 * Enable/disable a single extended advertising set.
 */
int
hci_le_set_ext_adv_enable(int hci_fd, uint8_t enable, uint8_t handle)
{
	struct bt_devreq r;
	uint8_t cp[6]; /* enable(1) + num_sets(1) + handle(1) + duration(2) + max_events(1) */
	ng_hci_status_rp rp;

	if (enable > 0x01 || !hci_adv_handle_valid(handle)) {
		errno = EINVAL;
		return (-1);
	}

	memset(cp, 0, sizeof(cp));
	cp[0] = enable;
	cp[1] = 1;		/* num_sets */
	cp[2] = handle;		/* Advertising_Handle */
	/* cp[3..4] = duration 0 (indefinite), cp[5] = max_events 0 (unlimited) */

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_ADV_ENABLE);
	r.cparam = cp;
	r.clen = 6;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Ext Adv Enable failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	BLUED_PROBE_GAP_ADV_ENABLE(enable, handle);
	LOG_HCI(1, "ext advertising %s, handle=%d",
	    enable ? "enabled" : "disabled", handle);
	return (0);
}

/*
 * Enable an extended advertising set for a BOUNDED number of advertising
 * events (Max_Extended_Advertising_Events, §7.8.56).  When the controller has
 * sent max_events advertising events it stops the set and generates LE
 * Advertising Set Terminated, which lets a caller air one queued PDU at a time
 * (the mesh bearer) instead of advertising the last PDU indefinitely.
 * max_events must be non-zero.
 */
int
hci_le_set_ext_adv_enable_burst(int hci_fd, uint8_t handle, uint8_t max_events)
{
	struct bt_devreq r;
	uint8_t cp[6];
	ng_hci_status_rp rp;

	if (!hci_adv_handle_valid(handle) || max_events == 0) {
		errno = EINVAL;
		return (-1);
	}

	memset(cp, 0, sizeof(cp));
	cp[0] = 0x01;		/* enable */
	cp[1] = 1;		/* num_sets */
	cp[2] = handle;		/* Advertising_Handle */
	/* cp[3..4] = duration 0 (bounded by max_events instead) */
	cp[5] = max_events;	/* Max_Extended_Advertising_Events */

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_ADV_ENABLE);
	r.cparam = cp;
	r.clen = 6;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Ext Adv Enable (burst) failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	BLUED_PROBE_GAP_ADV_ENABLE(0x01, handle);
	return (0);
}

int
hci_le_remove_adv_set(int hci_fd, uint8_t handle)
{
	struct bt_devreq r;
	ng_hci_le_remove_adv_set_cp cp;
	ng_hci_status_rp rp;

	if (!hci_adv_handle_valid(handle)) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertising_handle = handle;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_REMOVE_ADV_SET);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		warnx("hci_le_remove_adv_set: controller status 0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * Mesh bearer (broker step C): one non-connectable, non-scannable advertising
 * burst carrying the caller-built AD structure [len][adtype][pdu...].
 *
 * Extended controllers get a dedicated mesh adv set (MESH_ADV_HANDLE) that
 * coexists with blued's own set (ADV_CFG_HANDLE), advertising legacy PDUs on
 * the primary channels (Core Spec Vol 4 Part E §7.8.53 event-properties bit4
 * "use legacy PDUs", no connectable/scannable bits).  BT-4.0 controllers fall
 * back to the single legacy adv resource (ADV_NONCONN_IND).  The AD type has
 * already been validated upstream; this is a dumb transmit.
 */
#define MESH_ADV_EXT_PROPS	0x0010	/* legacy PDUs, non-conn, non-scan */
#define MESH_ADV_INTERVAL	0x00A0	/* 160 * 0.625ms = 100ms */
#define MESH_ADV_TX_COPIES	3	/* advertising events per queued PDU */
#define MESH_ADV_CHANNELS	0x07	/* primary channels 37/38/39 */
int
hci_mesh_adv_burst(int hci_fd, uint64_t le_features, const uint8_t *ad,
    uint8_t adlen)
{
	bool have_ext = (le_features & LE_FEAT_EXT_ADVERTISING) != 0;

	if (ad == NULL || adlen == 0 || adlen > 31) {
		errno = EINVAL;
		return (-1);
	}

	if (have_ext) {
		/*
		 * Set Extended Advertising Parameters is Command Disallowed
		 * (§7.8.53) while the set is enabled, so the previous burst
		 * would permanently wedge the mesh bearer.  Disable the set
		 * first; an Unknown Advertising Identifier error on the very
		 * first burst (set not yet created) is expected and ignored.
		 * (finding 42)
		 */
		(void)hci_le_set_ext_adv_enable(hci_fd, 0x00, MESH_ADV_HANDLE);
		if (hci_le_set_ext_adv_params_full(hci_fd, MESH_ADV_HANDLE,
		    MESH_ADV_EXT_PROPS, MESH_ADV_INTERVAL, MESH_ADV_INTERVAL,
		    0x00 /* public own address */, 0x00 /* no allowlist */,
		    0x01 /* primary PHY 1M */, 0x01 /* secondary PHY 1M */,
		    MESH_ADV_CHANNELS, 0x7F /* no tx-power preference */,
		    0x00, NULL) < 0)
			return (-1);
		if (hci_le_set_ext_adv_data(hci_fd, MESH_ADV_HANDLE, ad,
		    adlen) < 0)
			return (-1);
		/*
		 * Air this PDU a bounded number of times, then stop and fire
		 * Advertising Set Terminated.  Previously max_events was 0
		 * (advertise forever), so a back-to-back burst of distinct mesh
		 * PDUs reprogrammed the single set before any but the last aired,
		 * and the final PDU rebroadcast indefinitely.  The caller paces
		 * the FIFO on the Terminated event, airing one PDU at a time.
		 */
		return (hci_le_set_ext_adv_enable_burst(hci_fd, MESH_ADV_HANDLE,
		    MESH_ADV_TX_COPIES));
	}

	/*
	 * Legacy (non-extended) controllers have a single advertising set that
	 * mesh and the daemon's own connectable advertising cannot share.  Set
	 * Advertising Parameters is Command Disallowed (§7.8.5) while advertising
	 * is enabled, so if blued's own connectable advertising is on this burst
	 * fails -- deliberately.  We do NOT force-disable the daemon's own
	 * advertising to make room (that would silently make the peripheral
	 * unconnectable while adp->adv_enabled still read true); on a legacy
	 * controller "own advertising wins" and mesh TX is simply unavailable
	 * while advertising.  A central-only node (no own advertising) works.
	 */
	if (hci_le_set_advertising_params_full(hci_fd, MESH_ADV_INTERVAL,
	    MESH_ADV_INTERVAL, 0x03 /* ADV_NONCONN_IND */, 0x00, 0x00,
	    MESH_ADV_CHANNELS, 0x00, NULL) < 0)
		return (-1);
	if (hci_le_set_advertising_data(hci_fd, ad, adlen) < 0)
		return (-1);
	return (hci_le_set_advertise_enable(hci_fd, true));
}

/*
 * LE Set Advertising Set Random Address — assign a random address to
 * an advertising set.
 * Core Spec Vol 4 Part E Section 7.8.52 (OCF 0x0035).
 */
int
hci_le_set_adv_set_random_address(int fd, uint8_t handle,
    const uint8_t addr[6])
{
	struct bt_devreq r;
	ng_hci_le_set_adv_set_random_addr_cp cp;
	ng_hci_status_rp rp;

	if (!hci_adv_handle_valid(handle) || addr == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertising_handle = handle;
	memcpy(&cp.random_address, addr, 6);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_ADV_SET_RANDOM_ADDR);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Adv Set Random Address failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "adv set %d random address set", handle);
	return (0);
}

/*
 * LE Set Extended Scan Response Data — set scan response data for an
 * extended advertising set.  Same struct layout as Set Extended
 * Advertising Data.
 * Core Spec Vol 4 Part E Section 7.8.55 (OCF 0x0038).
 */
int
hci_le_set_ext_scan_response_data(int fd, uint8_t handle,
    const uint8_t *data, uint8_t len)
{
	struct bt_devreq r;
	ng_hci_le_set_ext_scan_rsp_data_cp cp;
	ng_hci_status_rp rp;

	if (!hci_adv_handle_valid(handle) ||
	    len > NG_HCI_LE_EXT_ADV_DATA_MAX ||
	    (len > 0 && data == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertising_handle = handle;
	cp.operation = 0x03;		/* complete data */
	cp.fragment_preference = 0x01;	/* don't fragment */
	cp.advertising_data_length = len;
	if (len > 0)
		memcpy(cp.advertising_data, data, len);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_SCAN_RSP_DATA);
	r.cparam = &cp;
	/* Only send the actual data, not the full 251-byte buffer */
	r.clen = 4 + len;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Ext Scan Response Data failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * LE Read Maximum Advertising Data Length — query the controller's
 * maximum supported advertising data length.
 * Core Spec Vol 4 Part E Section 7.8.57 (OCF 0x003A).
 */
int
hci_le_read_max_adv_data_length(int fd, uint16_t *max_len)
{
	struct bt_devreq r;
	ng_hci_le_read_max_adv_data_length_rp rp;

	/* Guard the out-parameter like the sibling read encoders (#34). */
	if (max_len == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&rp, 0, sizeof(rp));	/* Finding H-H3 */
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_MAX_ADV_DATA_LENGTH);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(fd, &r, 5) < 0)
		return (-1);
	/* Finding H-H3: reject a short/absent CC before trusting the length. */
	if ((size_t)r.rlen < sizeof(rp) || rp.status != 0x00) {
		LOG_HCI(1, "LE Read Max Adv Data Length failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}

	*max_len = le16toh(rp.max_adv_data_length);
	LOG_HCI(1, "max advertising data length: %u", *max_len);
	return (0);
}

/*
 * LE Read Number of Supported Advertising Sets — query how many
 * advertising sets the controller supports.
 * Core Spec Vol 4 Part E Section 7.8.58 (OCF 0x003B).
 */
int
hci_le_read_num_supported_adv_sets(int fd, uint8_t *num_sets)
{
	struct bt_devreq r;
	ng_hci_le_read_num_supported_adv_sets_rp rp;

	/* Guard the out-parameter like the sibling read encoders (#34). */
	if (num_sets == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&rp, 0, sizeof(rp));	/* Finding H-H3 */
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_NUM_SUPPORTED_ADV_SETS);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(fd, &r, 5) < 0)
		return (-1);
	/* Finding H-H3: reject a short/absent CC before trusting the count. */
	if ((size_t)r.rlen < sizeof(rp) || rp.status != 0x00) {
		LOG_HCI(1, "LE Read Num Supported Adv Sets failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}

	*num_sets = rp.num_supported_adv_sets;
	LOG_HCI(1, "supported advertising sets: %u", *num_sets);
	return (0);
}

/*
 * LE Clear Advertising Sets — remove all advertising sets from the
 * controller.
 * Core Spec Vol 4 Part E Section 7.8.60 (OCF 0x003D).
 */
int
hci_le_clear_adv_sets(int fd)
{
	struct bt_devreq r;
	ng_hci_status_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CLEAR_ADV_SETS);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Clear Adv Sets failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "advertising sets cleared");
	return (0);
}

/* ----------------------------------------------------------------
 * LE Periodic Advertising (BT 5.0)
 * Core Spec Vol 4 Part E Sections 7.8.61-7.8.73
 * ---------------------------------------------------------------- */

/*
 * LE Set Periodic Advertising Parameters v1.
 * Core Spec Vol 4 Part E Section 7.8.61 (OCF 0x003E).
 * interval_min/max in units of 1.25ms (range 0x0006-0xFFFF).
 */
int
hci_le_set_periodic_adv_params(int hci_fd, uint8_t handle,
    uint16_t interval_min, uint16_t interval_max, uint16_t properties)
{
	struct bt_devreq r;
	ng_hci_le_set_periodic_adv_params_cp cp;
	ng_hci_le_set_periodic_adv_params_rp rp;

	/*
	 * Validate interval range per Core Spec Vol 4 Part E 7.8.61:
	 * Range 0x0006-0xFFFF (7.5ms - 81.91875s in 1.25ms units).
	 * interval_min must not exceed interval_max.
	 */
	if (!hci_adv_handle_valid(handle) ||
	    interval_min < 0x0006 || interval_max < 0x0006 ||
	    interval_min > interval_max ||
	    (properties & ~HCI_PERIODIC_ADV_PROP_INCLUDE_TX_POWER) != 0) {
		LOG_HCI(1, "periodic adv params: invalid interval "
		    "(%d-%d)", interval_min, interval_max);
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertising_handle = handle;
	cp.periodic_adv_interval_min = htole16(interval_min);
	cp.periodic_adv_interval_max = htole16(interval_max);
	cp.periodic_adv_properties = htole16(properties);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PERIODIC_ADV_PARAMS);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Periodic Adv Params failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv params set: handle=%d interval=%d-%d",
	    handle, interval_min, interval_max);
	return (0);
}

/*
 * LE Set Periodic Advertising Data.
 * Core Spec Vol 4 Part E Section 7.8.62 (OCF 0x003F).
 * Sends complete data in a single operation (max 252 bytes).
 */
int
hci_le_set_periodic_adv_data(int hci_fd, uint8_t handle,
    const uint8_t *data, uint8_t len)
{
	struct bt_devreq r;
	ng_hci_le_set_periodic_adv_data_cp cp;
	ng_hci_le_set_periodic_adv_data_rp rp;

	if (!hci_adv_handle_valid(handle) ||
	    len > NG_HCI_LE_PERIODIC_ADV_DATA_MAX ||
	    (len > 0 && data == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertising_handle = handle;
	cp.operation = 0x03;		/* complete data */
	cp.advertising_data_length = len;
	if (len > 0)
		memcpy(cp.advertising_data, data, len);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PERIODIC_ADV_DATA);
	r.cparam = &cp;
	/* Only send the actual data, not the full 252-byte buffer */
	r.clen = 3 + len;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Periodic Adv Data failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * LE Set Periodic Advertising Enable.
 * Core Spec Vol 4 Part E Section 7.8.63 (OCF 0x0040).
 */
int
hci_le_set_periodic_adv_enable(int hci_fd, uint8_t enable, uint8_t handle)
{
	struct bt_devreq r;
	ng_hci_le_set_periodic_adv_enable_cp cp;
	ng_hci_le_set_periodic_adv_enable_rp rp;

	if (enable > 0x01 || !hci_adv_handle_valid(handle)) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.enable = enable;
	cp.advertising_handle = handle;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PERIODIC_ADV_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Periodic Adv Enable failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic advertising %s, handle=%d",
	    enable ? "enabled" : "disabled", handle);
	return (0);
}

/*
 * LE Periodic Advertising Create Sync.
 * Core Spec Vol 4 Part E Section 7.8.67 (OCF 0x0044).
 * Returns Command Status; result arrives via LE Periodic
 * Advertising Sync Established event.
 */
int
hci_le_periodic_adv_create_sync(int hci_fd, uint8_t options,
    uint8_t adv_sid, uint8_t addr_type, const uint8_t addr[6],
    uint16_t skip, uint16_t sync_timeout)
{
	struct bt_devreq r;
	ng_hci_le_periodic_adv_create_sync_cp cp;
	ng_hci_command_status_ep rp;	/* 4-byte Command Status event (finding 40) */

	if ((options & ~0x07) != 0 || adv_sid > 0x0f ||
	    addr_type > 0x01 || addr == NULL ||
	    skip > 0x01f3 || sync_timeout < 0x000a ||
	    sync_timeout > 0x4000) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.options = options;
	cp.advertising_sid = adv_sid;
	cp.advertiser_address_type = addr_type;
	memcpy(&cp.advertiser_address, addr, 6);
	cp.skip = htole16(skip);
	cp.sync_timeout = htole16(sync_timeout);
	cp.sync_cte_type = 0;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_PERIODIC_ADV_CREATE_SYNC);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Periodic Adv Create Sync failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv sync create requested: sid=%d skip=%d "
	    "timeout=%d", adv_sid, skip, sync_timeout);
	return (0);
}

/*
 * LE Periodic Advertising Create Sync Cancel.
 * Core Spec Vol 4 Part E Section 7.8.68 (OCF 0x0045).
 */
int
hci_le_periodic_adv_create_sync_cancel(int hci_fd)
{
	struct bt_devreq r;
	ng_hci_le_periodic_adv_create_sync_cancel_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_PERIODIC_ADV_CREATE_SYNC_CANCEL);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Periodic Adv Create Sync Cancel failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv sync create cancelled");
	return (0);
}

/*
 * LE Periodic Advertising Terminate Sync.
 * Core Spec Vol 4 Part E Section 7.8.69 (OCF 0x0046).
 */
int
hci_le_periodic_adv_terminate_sync(int hci_fd, uint16_t sync_handle)
{
	struct bt_devreq r;
	ng_hci_le_periodic_adv_terminate_sync_cp cp;
	ng_hci_le_periodic_adv_terminate_sync_rp rp;

	if (sync_handle > 0x0eff) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.sync_handle = htole16(sync_handle);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_PERIODIC_ADV_TERMINATE_SYNC);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Periodic Adv Terminate Sync failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv sync terminated: handle=%04x", sync_handle);
	return (0);
}

/*
 * LE Add Device To Periodic Advertiser List.
 * Core Spec Vol 4 Part E Section 7.8.70 (OCF 0x0047).
 */
int
hci_le_add_dev_to_periodic_adv_list(int hci_fd, uint8_t addr_type,
    const uint8_t addr[6], uint8_t adv_sid)
{
	struct bt_devreq r;
	ng_hci_le_add_dev_periodic_adv_list_cp cp;
	ng_hci_le_add_dev_periodic_adv_list_rp rp;

	if (addr_type > 0x01 || addr == NULL || adv_sid > 0x0f) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertiser_address_type = addr_type;
	memcpy(&cp.advertiser_address, addr, 6);
	cp.advertising_sid = adv_sid;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_ADD_DEV_PERIODIC_ADV_LIST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Add Dev To Periodic Adv List failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "added device to periodic adv list, sid=%d", adv_sid);
	return (0);
}

/*
 * LE Remove Device From Periodic Advertiser List.
 * Core Spec Vol 4 Part E Section 7.8.71 (OCF 0x0048).
 */
int
hci_le_remove_dev_from_periodic_adv_list(int hci_fd, uint8_t addr_type,
    const uint8_t addr[6], uint8_t adv_sid)
{
	struct bt_devreq r;
	ng_hci_le_remove_dev_periodic_adv_list_cp cp;
	ng_hci_le_remove_dev_periodic_adv_list_rp rp;

	if (addr_type > 0x01 || addr == NULL || adv_sid > 0x0f) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertiser_address_type = addr_type;
	memcpy(&cp.advertiser_address, addr, 6);
	cp.advertising_sid = adv_sid;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_REMOVE_DEV_PERIODIC_ADV_LIST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Remove Dev From Periodic Adv List failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "removed device from periodic adv list, sid=%d", adv_sid);
	return (0);
}

/*
 * LE Clear Periodic Advertiser List.
 * Core Spec Vol 4 Part E Section 7.8.72 (OCF 0x0049).
 */
int
hci_le_clear_periodic_adv_list(int hci_fd)
{
	struct bt_devreq r;
	ng_hci_le_clear_periodic_adv_list_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CLEAR_PERIODIC_ADV_LIST);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Clear Periodic Adv List failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic advertiser list cleared");
	return (0);
}

/*
 * LE Read Periodic Advertiser List Size.
 * Core Spec Vol 4 Part E Section 7.8.73 (OCF 0x004A).
 */
int
hci_le_read_periodic_adv_list_size(int hci_fd, uint8_t *size)
{
	struct bt_devreq r;
	ng_hci_le_read_periodic_adv_list_size_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_PERIODIC_ADV_LIST_SIZE);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Read Periodic Adv List Size failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}

	if (size != NULL)
		*size = rp.periodic_advertiser_list_size;
	LOG_HCI(1, "periodic adv list size: %d",
	    rp.periodic_advertiser_list_size);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Periodic Advertising Sync Transfer — PAST (BT 5.1)
 * Core Spec Vol 4 Part E Sections 7.8.88-7.8.92
 * ---------------------------------------------------------------- */

/*
 * LE Set Periodic Advertising Receive Enable.
 * Core Spec Vol 4 Part E Section 7.8.88 (OCF 0x0059).
 */
int
hci_le_set_periodic_adv_receive_enable(int hci_fd, uint16_t sync_handle,
    uint8_t enable)
{
	struct bt_devreq r;
	ng_hci_le_set_periodic_adv_rcv_enable_cp cp;
	ng_hci_le_set_periodic_adv_rcv_enable_rp rp;

	if (sync_handle > 0x0eff || enable > 0x01) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.sync_handle = htole16(sync_handle);
	cp.enable = enable;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PERIODIC_ADV_RCV_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Periodic Adv Receive Enable failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv receive %s, sync_handle=%04x",
	    enable ? "enabled" : "disabled", sync_handle);
	return (0);
}

/*
 * LE Periodic Advertising Sync Transfer.
 * Core Spec Vol 4 Part E Section 7.8.89 (OCF 0x005A).
 * Sends sync info for an existing periodic advertising train
 * to a connected peer.
 */
int
hci_le_periodic_adv_sync_transfer(int hci_fd, uint16_t con_handle,
    uint16_t service_data, uint16_t sync_handle)
{
	struct bt_devreq r;
	ng_hci_le_periodic_adv_sync_transfer_cp cp;
	ng_hci_le_periodic_adv_sync_transfer_rp rp;

	if (con_handle > 0x0eff || sync_handle > 0x0eff) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.service_data = htole16(service_data);
	cp.sync_handle = htole16(sync_handle);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_PERIODIC_ADV_SYNC_TRANSFER);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Periodic Adv Sync Transfer failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv sync transferred: con=%04x sync=%04x",
	    con_handle, sync_handle);
	return (0);
}

/*
 * LE Periodic Advertising Set Info Transfer.
 * Core Spec Vol 4 Part E Section 7.8.90 (OCF 0x005B).
 * Sends sync info for a local periodic advertising set
 * to a connected peer.
 */
int
hci_le_periodic_adv_set_info_transfer(int hci_fd, uint16_t con_handle,
    uint16_t service_data, uint8_t adv_handle)
{
	struct bt_devreq r;
	ng_hci_le_periodic_adv_set_info_transfer_cp cp;
	ng_hci_le_periodic_adv_set_info_transfer_rp rp;

	if (con_handle > 0x0eff || !hci_adv_handle_valid(adv_handle)) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.service_data = htole16(service_data);
	cp.advertising_handle = adv_handle;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_PERIODIC_ADV_SET_INFO_TRANSFER);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Periodic Adv Set Info Transfer failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "periodic adv set info transferred: con=%04x adv=%d",
	    con_handle, adv_handle);
	return (0);
}

/*
 * LE Set Periodic Advertising Sync Transfer Parameters.
 * Core Spec Vol 4 Part E Section 7.8.91 (OCF 0x005C).
 * Configures PAST reception on a per-connection basis.
 */
int
hci_le_set_past_params(int hci_fd, uint16_t con_handle, uint8_t mode,
    uint16_t skip, uint16_t sync_timeout, uint8_t cte_type)
{
	struct bt_devreq r;
	ng_hci_le_set_past_params_cp cp;
	ng_hci_le_set_past_params_rp rp;

	if (con_handle > 0x0eff || mode > 0x03 || skip > 0x01f3 ||
	    sync_timeout < 0x000a || sync_timeout > 0x4000 ||
	    (cte_type & ~0x17) != 0) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.mode = mode;
	cp.skip = htole16(skip);
	cp.sync_timeout = htole16(sync_timeout);
	cp.cte_type = cte_type;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PAST_PARAMS);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set PAST Params failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "PAST params set: con=%04x mode=%d skip=%d timeout=%d",
	    con_handle, mode, skip, sync_timeout);
	return (0);
}

/*
 * LE Set Default Periodic Advertising Sync Transfer Parameters.
 * Core Spec Vol 4 Part E Section 7.8.92 (OCF 0x005D).
 * Configures default PAST reception for all future connections.
 */
int
hci_le_set_default_past_params(int hci_fd, uint8_t mode, uint16_t skip,
    uint16_t sync_timeout, uint8_t cte_type)
{
	struct bt_devreq r;
	ng_hci_le_set_default_past_params_cp cp;
	ng_hci_le_set_default_past_params_rp rp;

	if (mode > 0x03 || skip > 0x01f3 ||
	    sync_timeout < 0x000a || sync_timeout > 0x4000 ||
	    (cte_type & ~0x17) != 0) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.mode = mode;
	cp.skip = htole16(skip);
	cp.sync_timeout = htole16(sync_timeout);
	cp.cte_type = cte_type;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_DEFAULT_PAST_PARAMS);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Default PAST Params failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "default PAST params set: mode=%d skip=%d timeout=%d",
	    mode, skip, sync_timeout);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Direction Finding (BT 5.1)
 * Core Spec Vol 4 Part E Sections 7.8.80-7.8.87
 * ---------------------------------------------------------------- */

/*
 * LE Set Connectionless CTE Transmit Parameters.
 * Core Spec Vol 4 Part E Section 7.8.80 (OCF 0x0051).
 * Configures CTE parameters for connectionless advertising.
 */
int
hci_le_set_connless_cte_tx_params(int hci_fd, uint8_t adv_handle,
    uint8_t cte_length, uint8_t cte_type, uint8_t cte_count,
    uint8_t switching_pattern_len, const uint8_t *antenna_ids)
{
	struct bt_devreq r;
	uint8_t buf[sizeof(ng_hci_le_set_connless_cte_tx_params_cp) + 75];
	ng_hci_le_set_connless_cte_tx_params_cp *cp;
	ng_hci_le_set_connless_cte_tx_params_rp rp;
	size_t clen;

	if (adv_handle > 0xef || cte_length < 2 || cte_length > 20 ||
	    cte_type > 2 || cte_count < 1 || cte_count > 16 ||
	    switching_pattern_len < 2 || switching_pattern_len > 75 ||
	    antenna_ids == NULL) {
		errno = EINVAL;
		return (-1);
	}

	cp = (ng_hci_le_set_connless_cte_tx_params_cp *)buf;
	memset(buf, 0, sizeof(buf));
	cp->advertising_handle = adv_handle;
	cp->cte_length = cte_length;
	cp->cte_type = cte_type;
	cp->cte_count = cte_count;
	cp->switching_pattern_length = switching_pattern_len;
	if (switching_pattern_len > 0 && antenna_ids != NULL)
		memcpy(buf + sizeof(*cp), antenna_ids, switching_pattern_len);
	clen = sizeof(*cp) + switching_pattern_len;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_CONNLESS_CTE_TX_PARAMS);
	r.cparam = buf;
	r.clen = clen;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Connless CTE TX Params failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "connless CTE TX params set: adv_handle=%d cte_len=%d "
	    "type=%d count=%d", adv_handle, cte_length, cte_type, cte_count);
	return (0);
}

/*
 * LE Set Connectionless CTE Transmit Enable.
 * Core Spec Vol 4 Part E Section 7.8.81 (OCF 0x0052).
 */
int
hci_le_set_connless_cte_tx_enable(int hci_fd, uint8_t adv_handle,
    uint8_t enable)
{
	struct bt_devreq r;
	ng_hci_le_set_connless_cte_tx_enable_cp cp;
	ng_hci_le_set_connless_cte_tx_enable_rp rp;

	if (adv_handle > 0xef || enable > 1) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.advertising_handle = adv_handle;
	cp.cte_enable = enable;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_CONNLESS_CTE_TX_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Connless CTE TX Enable failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "connless CTE TX %s, adv_handle=%d",
	    enable ? "enabled" : "disabled", adv_handle);
	return (0);
}

/*
 * LE Set Connectionless IQ Sampling Enable.
 * Core Spec Vol 4 Part E Section 7.8.82 (OCF 0x0053).
 */
int
hci_le_set_connless_iq_sampling_enable(int hci_fd, uint16_t sync_handle,
    uint8_t enable, uint8_t slot_durations, uint8_t max_sampled_ctes,
    uint8_t switching_pattern_len, const uint8_t *antenna_ids)
{
	struct bt_devreq r;
	uint8_t buf[sizeof(ng_hci_le_set_connless_iq_sampling_enable_cp) + 75];
	ng_hci_le_set_connless_iq_sampling_enable_cp *cp;
	ng_hci_le_set_connless_iq_sampling_enable_rp rp;
	size_t clen;

	if (sync_handle > 0x0eff || enable > 1 ||
	    switching_pattern_len > 75 ||
	    (enable != 0 && (slot_durations < 1 || slot_durations > 2 ||
	    max_sampled_ctes > 16 || switching_pattern_len < 2 ||
	    antenna_ids == NULL))) {
		errno = EINVAL;
		return (-1);
	}

	cp = (ng_hci_le_set_connless_iq_sampling_enable_cp *)buf;
	memset(buf, 0, sizeof(buf));
	cp->sync_handle = htole16(sync_handle);
	cp->sampling_enable = enable;
	cp->slot_durations = slot_durations;
	cp->max_sampled_ctes = max_sampled_ctes;
	cp->switching_pattern_length = switching_pattern_len;
	if (switching_pattern_len > 0 && antenna_ids != NULL)
		memcpy(buf + sizeof(*cp), antenna_ids, switching_pattern_len);
	clen = sizeof(*cp) + switching_pattern_len;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_CONNLESS_IQ_SAMPLING_ENABLE);
	r.cparam = buf;
	r.clen = clen;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Connless IQ Sampling Enable failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "connless IQ sampling %s, sync_handle=%04x",
	    enable ? "enabled" : "disabled", sync_handle);
	return (0);
}

/*
 * LE Set Connection CTE Receive Parameters.
 * Core Spec Vol 4 Part E Section 7.8.83 (OCF 0x0054).
 */
int
hci_le_set_conn_cte_rx_params(int hci_fd, uint16_t conn_handle,
    uint8_t enable, uint8_t slot_durations, uint8_t switching_pattern_len,
    const uint8_t *antenna_ids)
{
	struct bt_devreq r;
	uint8_t buf[sizeof(ng_hci_le_set_conn_cte_rx_params_cp) + 75];
	ng_hci_le_set_conn_cte_rx_params_cp *cp;
	ng_hci_le_set_conn_cte_rx_params_rp rp;
	size_t clen;

	if (conn_handle > 0x0eff || enable > 1 ||
	    switching_pattern_len > 75 ||
	    (enable != 0 && (slot_durations < 1 || slot_durations > 2 ||
	    switching_pattern_len < 2 || antenna_ids == NULL))) {
		errno = EINVAL;
		return (-1);
	}

	cp = (ng_hci_le_set_conn_cte_rx_params_cp *)buf;
	memset(buf, 0, sizeof(buf));
	cp->connection_handle = htole16(conn_handle);
	cp->sampling_enable = enable;
	cp->slot_durations = slot_durations;
	cp->switching_pattern_length = switching_pattern_len;
	if (switching_pattern_len > 0 && antenna_ids != NULL)
		memcpy(buf + sizeof(*cp), antenna_ids, switching_pattern_len);
	clen = sizeof(*cp) + switching_pattern_len;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_CONN_CTE_RX_PARAMS);
	r.cparam = buf;
	r.clen = clen;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Conn CTE RX Params failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "conn CTE RX params set: handle=%04x enable=%d",
	    conn_handle, enable);
	return (0);
}

/*
 * LE Set Connection CTE Transmit Parameters.
 * Core Spec Vol 4 Part E Section 7.8.84 (OCF 0x0055).
 */
int
hci_le_set_conn_cte_tx_params(int hci_fd, uint16_t conn_handle,
    uint8_t cte_types, uint8_t switching_pattern_len,
    const uint8_t *antenna_ids)
{
	struct bt_devreq r;
	uint8_t buf[sizeof(ng_hci_le_set_conn_cte_tx_params_cp) + 75];
	ng_hci_le_set_conn_cte_tx_params_cp *cp;
	ng_hci_le_set_conn_cte_tx_params_rp rp;
	size_t clen;

	if (conn_handle > 0x0eff || (cte_types & ~0x07) != 0 ||
	    switching_pattern_len < 2 || switching_pattern_len > 75 ||
	    antenna_ids == NULL) {
		errno = EINVAL;
		return (-1);
	}

	cp = (ng_hci_le_set_conn_cte_tx_params_cp *)buf;
	memset(buf, 0, sizeof(buf));
	cp->connection_handle = htole16(conn_handle);
	cp->cte_types = cte_types;
	cp->switching_pattern_length = switching_pattern_len;
	if (switching_pattern_len > 0 && antenna_ids != NULL)
		memcpy(buf + sizeof(*cp), antenna_ids, switching_pattern_len);
	clen = sizeof(*cp) + switching_pattern_len;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_CONN_CTE_TX_PARAMS);
	r.cparam = buf;
	r.clen = clen;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Conn CTE TX Params failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "conn CTE TX params set: handle=%04x cte_types=0x%02x",
	    conn_handle, cte_types);
	return (0);
}

/*
 * LE Connection CTE Request Enable.
 * Core Spec Vol 4 Part E Section 7.8.85 (OCF 0x0056).
 */
int
hci_le_conn_cte_req_enable(int hci_fd, uint16_t conn_handle,
    uint8_t enable, uint16_t cte_req_interval, uint8_t cte_length,
    uint8_t cte_type)
{
	struct bt_devreq r;
	ng_hci_le_conn_cte_req_enable_cp cp;
	ng_hci_le_conn_cte_req_enable_rp rp;

	if (conn_handle > 0x0eff || enable > 1 ||
	    (enable != 0 && (cte_length < 2 || cte_length > 20 ||
	    cte_type > 2))) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(conn_handle);
	cp.enable = enable;
	cp.cte_request_interval = htole16(cte_req_interval);
	cp.requested_cte_length = cte_length;
	cp.requested_cte_type = cte_type;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CONN_CTE_REQ_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Conn CTE Request Enable failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "conn CTE request %s: handle=%04x interval=%d",
	    enable ? "enabled" : "disabled", conn_handle, cte_req_interval);
	return (0);
}

/*
 * LE Connection CTE Response Enable.
 * Core Spec Vol 4 Part E Section 7.8.86 (OCF 0x0057).
 */
int
hci_le_conn_cte_rsp_enable(int hci_fd, uint16_t conn_handle,
    uint8_t enable)
{
	struct bt_devreq r;
	ng_hci_le_conn_cte_rsp_enable_cp cp;
	ng_hci_le_conn_cte_rsp_enable_rp rp;

	if (conn_handle > 0x0eff || enable > 1) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(conn_handle);
	cp.enable = enable;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CONN_CTE_RSP_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Conn CTE Response Enable failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "conn CTE response %s: handle=%04x",
	    enable ? "enabled" : "disabled", conn_handle);
	return (0);
}

/*
 * LE Read Antenna Information.
 * Core Spec Vol 4 Part E Section 7.8.87 (OCF 0x0058).
 * Returns the controller's antenna switching capabilities.
 */
int
hci_le_read_antenna_info(int hci_fd, uint8_t *supported_switching_rates,
    uint8_t *num_antennae, uint8_t *max_switching_pattern_len,
    uint8_t *max_cte_length)
{
	struct bt_devreq r;
	ng_hci_le_read_antenna_information_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_ANTENNA_INFORMATION);
	r.cparam = NULL;
	r.clen = 0;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Read Antenna Information failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}

	if (supported_switching_rates != NULL)
		*supported_switching_rates =
		    rp.supported_switching_sampling_rates;
	if (num_antennae != NULL)
		*num_antennae = rp.num_antennae;
	if (max_switching_pattern_len != NULL)
		*max_switching_pattern_len = rp.max_switching_pattern_length;
	if (max_cte_length != NULL)
		*max_cte_length = rp.max_cte_length;

	LOG_HCI(1, "antenna info: rates=0x%02x antennae=%d max_pattern=%d "
	    "max_cte_len=%d", rp.supported_switching_sampling_rates,
	    rp.num_antennae, rp.max_switching_pattern_length,
	    rp.max_cte_length);
	return (0);
}
