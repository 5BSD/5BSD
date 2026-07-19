/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI privacy and filter list commands for blued.
 *
 * Resolving List management, address resolution, RPA timeout,
 * privacy mode, and Filter Accept List (formerly White List).
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

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

/* ----------------------------------------------------------------
 * LE Privacy — Resolving List management
 * Core Spec Vol 4 Part E Sections 7.8.38-7.8.45, 7.8.77
 * ---------------------------------------------------------------- */

int
hci_le_set_random_address(int hci_fd, const uint8_t addr[6])
{
	struct bt_devreq r;
	ng_hci_le_set_random_address_cp_ cp;
	ng_hci_status_rp rp;

	if (addr == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.random_address, addr, sizeof(cp.random_address));
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_RANDOM_ADDRESS);
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

int
hci_le_clear_resolving_list(int hci_fd)
{
	struct bt_devreq r;
	ng_hci_status_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CLEAR_RESOLVING_LIST);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Clear Resolving List failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "resolving list cleared");
	return (0);
}

int
hci_le_add_dev_resolving_list(int hci_fd, uint8_t addr_type,
    const uint8_t addr[6], const uint8_t peer_irk[16],
    const uint8_t local_irk[16])
{
	struct bt_devreq r;
	ng_hci_le_add_dev_resolving_list_cp cp;
	ng_hci_status_rp rp;

	if (addr_type > 0x01 || addr == NULL ||
	    peer_irk == NULL || local_irk == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.peer_identity_addr_type = addr_type;
	memcpy(&cp.peer_identity_addr, addr, 6);
	memcpy(cp.peer_irk, peer_irk, 16);
	memcpy(cp.local_irk, local_irk, 16);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_ADD_DEV_RESOLVING_LIST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Add Dev Resolving List failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	/* One identity/IRK entry programmed into the controller resolving list. */
	BLUED_PROBE_PRIVACY_RESLIST_LOAD(1);
	LOG_HCI(1, "added device to resolving list, addr_type=%d", addr_type);
	return (0);
}

/*
 * LE Remove Device From Resolving List — drop one identity/IRK entry.
 * Core Spec Vol 4 Part E §7.8.39 (OCF 0x0028).  Used on unbond so a forgotten
 * peer's IRK does not linger in the controller resolving list.  Address
 * resolution must be disabled by the caller before mutating the list
 * (§7.8.38).
 */
int
hci_le_remove_dev_resolving_list(int hci_fd, uint8_t addr_type,
    const uint8_t addr[6])
{
	struct bt_devreq r;
	ng_hci_le_remove_dev_resolving_list_cp cp;
	ng_hci_status_rp rp;

	if (addr_type > 0x01 || addr == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.peer_identity_addr_type = addr_type;
	memcpy(&cp.peer_identity_addr, addr, 6);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_REMOVE_DEV_RESOLVING_LIST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Remove Dev Resolving List failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "removed device from resolving list, addr_type=%d",
	    addr_type);
	return (0);
}

int
hci_le_set_addr_resolution_enable(int hci_fd, uint8_t enable)
{
	struct bt_devreq r;
	ng_hci_le_set_addr_resolution_enable_cp cp;
	ng_hci_status_rp rp;

	if (enable > 0x01) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.enable = enable;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_ADDR_RESOLUTION_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Addr Resolution Enable failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "address resolution %s", enable ? "enabled" : "disabled");
	return (0);
}

int
hci_le_set_privacy_mode(int hci_fd, uint8_t addr_type,
    const uint8_t addr[6], uint8_t mode)
{
	struct bt_devreq r;
	ng_hci_le_set_privacy_mode_cp cp;
	ng_hci_status_rp rp;

	if (addr_type > 0x01 || addr == NULL || mode > 0x01) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.peer_identity_addr_type = addr_type;
	memcpy(&cp.peer_identity_addr, addr, 6);
	cp.privacy_mode = mode;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PRIVACY_MODE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Privacy Mode failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	return (0);
}

int
hci_le_set_rpa_timeout(int hci_fd, uint16_t timeout_sec)
{
	struct bt_devreq r;
	ng_hci_le_set_rpa_timeout_cp cp;
	ng_hci_status_rp rp;

	/* Core Spec Vol 4 Part E §7.8.45: range is 1..0x0E10 (3600) seconds */
	if (timeout_sec < 1 || timeout_sec > 0x0E10) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.rpa_timeout = htole16(timeout_sec);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_RPA_TIMEOUT);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set RPA Timeout failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "RPA timeout set to %d seconds", timeout_sec);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Filter Accept List management
 * Core Spec Vol 4 Part E Sections 7.8.14-7.8.17
 * (ng_hci.h uses pre-5.3 "White List" naming)
 * ---------------------------------------------------------------- */

/*
 * LE Clear Filter Accept List — remove all entries.
 * Core Spec Vol 4 Part E Section 7.8.15 (OCF 0x0010).
 */
int
hci_le_clear_filter_accept_list(int hci_fd)
{
	struct bt_devreq r;
	ng_hci_status_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CLEAR_WHITE_LIST);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Clear Filter Accept List failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "filter accept list cleared");
	return (0);
}

/*
 * LE Add Device To Filter Accept List.
 * Core Spec Vol 4 Part E Section 7.8.16 (OCF 0x0011).
 * addr_type: 0x00 = public, 0x01 = random.
 */
int
hci_le_add_device_to_filter_accept_list(int hci_fd, uint8_t addr_type,
    const uint8_t addr[6])
{
	struct bt_devreq r;
	ng_hci_le_add_device_to_white_list_cp cp;
	ng_hci_status_rp rp;

	if (addr_type > 0x01 || addr == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.address_type = addr_type;
	memcpy(&cp.address, addr, 6);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_ADD_DEVICE_TO_WHITE_LIST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Add Device To Filter Accept List failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "added device to filter accept list, addr_type=%d",
	    addr_type);
	return (0);
}

/*
 * LE Remove Device From Filter Accept List.
 * Core Spec Vol 4 Part E Section 7.8.17 (OCF 0x0012).
 */
int
hci_le_remove_device_from_filter_accept_list(int hci_fd, uint8_t addr_type,
    const uint8_t addr[6])
{
	struct bt_devreq r;
	ng_hci_le_remove_device_from_white_list_cp cp;
	ng_hci_status_rp rp;

	if (addr_type > 0x01 || addr == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.address_type = addr_type;
	memcpy(&cp.address, addr, 6);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_REMOVE_DEVICE_FROM_WHITE_LIST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Remove Device From Filter Accept List failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "removed device from filter accept list, addr_type=%d",
	    addr_type);
	return (0);
}
