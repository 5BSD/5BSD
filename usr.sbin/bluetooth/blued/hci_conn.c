/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI connection commands for blued.
 *
 * Connection update, data length, PHY, extended create connection,
 * connection subrating, power control, LE CoC, and ECBFC.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netgraph/bluetooth/include/ng_btsocket.h>

#include "ble_util.h"
#include "hci_log.h"
#include "hci_util.h"
#include "hci_internal.h"

static _Atomic uint8_t l2cap_own_address_type;

/* Core Vol 4 Part E §7.8.50 and §7.8.66 PHY-selection bit assignments. */
#define HCI_LE_PHY_1M		0x01
#define HCI_LE_PHY_2M		0x02
#define HCI_LE_PHY_CODED	0x04
#define HCI_LE_PHY_MASK		(HCI_LE_PHY_1M | HCI_LE_PHY_2M | \
				 HCI_LE_PHY_CODED)
#define HCI_LE_ALL_PHYS_TX_NO_PREFERENCE	0x01
#define HCI_LE_ALL_PHYS_RX_NO_PREFERENCE	0x02
#define HCI_LE_ALL_PHYS_MASK	(HCI_LE_ALL_PHYS_TX_NO_PREFERENCE | \
				 HCI_LE_ALL_PHYS_RX_NO_PREFERENCE)

static bool
hci_le_phy_params_valid(uint8_t all_phys, uint8_t tx_phys, uint8_t rx_phys)
{

	if ((all_phys & ~HCI_LE_ALL_PHYS_MASK) != 0 ||
	    (tx_phys & ~HCI_LE_PHY_MASK) != 0 ||
	    (rx_phys & ~HCI_LE_PHY_MASK) != 0)
		return (false);
	if ((all_phys & HCI_LE_ALL_PHYS_TX_NO_PREFERENCE) == 0 && tx_phys == 0)
		return (false);
	if ((all_phys & HCI_LE_ALL_PHYS_RX_NO_PREFERENCE) == 0 && rx_phys == 0)
		return (false);
	return (true);
}

static bool
hci_le_subrate_params_valid(uint16_t min_subrate, uint16_t max_subrate,
    uint16_t max_latency, uint16_t cont_num, uint16_t timeout)
{

	if (min_subrate < 0x0001 || min_subrate > 0x01F4 ||
	    max_subrate < 0x0001 || max_subrate > 0x01F4 ||
	    min_subrate > max_subrate ||
	    max_latency > 0x01F3 || cont_num > 0x01F3 ||
	    cont_num >= max_subrate ||
	    timeout < 0x000A || timeout > 0x0C80)
		return (false);
	if ((uint32_t)max_subrate * ((uint32_t)max_latency + 1) > 500)
		return (false);
	return (true);
}

void
hci_l2cap_set_own_address_type(uint8_t own_addr_type)
{

	if (own_addr_type <= 0x03)
		atomic_store(&l2cap_own_address_type, own_addr_type);
}

/* ----------------------------------------------------------------
 * LE Connection Update
 * ---------------------------------------------------------------- */

/*
 * LE Connection Update — request new connection parameters.
 * Core Spec Vol 4 Part E Section 7.8.18 (OCF 0x0013).
 * Returns Command Status; result arrives via LE Connection
 * Update Complete event.
 */
int
hci_le_connection_update(int hci_fd, uint16_t handle,
    uint16_t interval_min, uint16_t interval_max,
    uint16_t latency, uint16_t timeout)
{
	struct bt_devreq r;
	ng_hci_le_connection_update_cp cp;
	ng_hci_status_rp rp;

	/*
	 * Host-side parameter validation per Core Spec Vol 4
	 * Part E Section 7.8.18.
	 */
	if (handle > 0x0EFF) {
		errno = EINVAL;
		return (-1);
	}
	if (interval_min < 0x0006 || interval_min > 0x0C80 ||
	    interval_max < 0x0006 || interval_max > 0x0C80 ||
	    interval_min > interval_max) {
		LOG_HCI(1, "conn update: invalid interval "
		    "(%d-%d)", interval_min, interval_max);
		errno = EINVAL;
		return (-1);
	}
	if (latency > 0x01F3) {
		LOG_HCI(1, "conn update: invalid latency %d", latency);
		errno = EINVAL;
		return (-1);
	}
	if (timeout < 0x000A || timeout > 0x0C80) {
		LOG_HCI(1, "conn update: invalid timeout %d", timeout);
		errno = EINVAL;
		return (-1);
	}
	/*
	 * Timeout(10ms) * 10 > Interval_Max(1.25ms) * (1+Lat) * 2
	 * i.e. Timeout * 4 > Interval_Max * (1 + Latency)
	 */
	if ((uint32_t)timeout * 4 <= (uint32_t)interval_max *
	    (1 + (uint32_t)latency)) {
		LOG_HCI(1, "conn update: timeout too short for "
		    "latency/interval");
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(handle);
	cp.conn_interval_min = htole16(interval_min);
	cp.conn_interval_max = htole16(interval_max);
	cp.conn_latency = htole16(latency);
	cp.supervision_timeout = htole16(timeout);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CONNECTION_UPDATE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Connection Update failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "connection update requested: interval=%d-%d "
	    "latency=%d timeout=%d",
	    interval_min, interval_max, latency, timeout);
	return (0);
}

/*
 * Decide whether the connection-parameter update should be driven with the
 * HCI LE Connection Update command.
 *
 * The HCI LE Connection Update path only works when the Connection Parameters
 * Request Link Layer procedure is available (LE feature bit 1,
 * LE_FEAT_CONN_PARAM_REQ; Core Spec Vol 6 Part B §4.6.2).  On such a
 * controller the command is honoured for both central and peripheral roles —
 * the controller runs LL_CONNECTION_PARAM_REQ.  Without the feature the HCI
 * command is central-only, so a peripheral must instead use the L2CAP
 * Connection Parameter Update Request signaling procedure (Core Spec Vol 3
 * Part A §4.20).
 */
bool
l2cap_conn_param_use_hci_update(uint64_t local_features)
{

	return ((local_features & LE_FEAT_CONN_PARAM_REQ) != 0);
}

/*
 * Send a connection-parameter update as peripheral.
 * Core Spec Vol 3 Part A §4.20 / Vol 6 Part B §4.6.2.
 *
 * Gated on the Connection Parameters Request procedure
 * (LE_FEAT_CONN_PARAM_REQ): when the local controller supports it we issue
 * HCI_LE_Connection_Update and the controller runs the LL procedure for
 * either role.  When it is absent the proper mechanism is the L2CAP
 * Connection Parameter Update Request on the LE signaling CID 0x0005, but
 * FreeBSD's ng_l2cap does not expose the LE signaling channel to user-space
 * sockets (the SOCK_SEQPACKET layer only surfaces the fixed CID 0x0004 ATT
 * and CID 0x0006 SMP channels).  We therefore decline rather than emit a
 * central-only HCI command that the controller would reject.
 */
int
l2cap_conn_param_update_req(const uint8_t *local_addr,
    const uint8_t *peer_addr, uint8_t peer_addr_type __unused,
    uint16_t interval_min, uint16_t interval_max,
    uint16_t latency, uint16_t timeout)
{
	uint64_t local_features = 0;
	uint16_t con_handle;
	int hci_fd;
	char adapter[16];

	/*
	 * Find the adapter for this local address.  Try each ubt
	 * device until one matches, falling back to ubt0.
	 */
	{
		int i;
		bool found = false;

		for (i = 0; i < 8; i++) {
			uint8_t bdaddr[6];

			snprintf(adapter, sizeof(adapter), "ubt%d", i);
			hci_fd = hci_open(adapter);
			if (hci_fd < 0)
				continue;
			if (hci_get_bdaddr(hci_fd, bdaddr) == 0 &&
			    memcmp(bdaddr, local_addr, 6) == 0) {
				found = true;
				break;
			}
			close(hci_fd);
		}
		if (!found) {
			/* Fallback to ubt0 */
			hci_fd = hci_open("ubt0");
		}
	}

	if (hci_fd < 0)
		return (-1);

	if (hci_get_con_handle(hci_fd, peer_addr, &con_handle) < 0) {
		close(hci_fd);
		return (-1);
	}

	/*
	 * Feature-gate the HCI path (Core Spec Vol 6 Part B §4.6.2).  A failed
	 * feature read is treated as "unsupported": we conservatively fall back
	 * rather than issue a command the controller may reject.
	 */
	if (hci_le_read_local_features(hci_fd, &local_features) < 0)
		local_features = 0;

	if (!l2cap_conn_param_use_hci_update(local_features)) {
		LOG_HCI(1, "conn param update: LL Connection Parameters "
		    "Request unsupported (LE feature bit 1 clear); L2CAP "
		    "signaling fallback (Vol 3 Part A 4.20) not available "
		    "from user space -- declining");
		close(hci_fd);
		errno = ENOTSUP;
		return (-1);
	}

	LOG_HCI(1, "conn param update: handle=%04x interval=%d-%d "
	    "latency=%d timeout=%d",
	    con_handle, interval_min, interval_max, latency, timeout);

	if (hci_le_connection_update(hci_fd, con_handle,
	    interval_min, interval_max, latency, timeout) < 0) {
		close(hci_fd);
		return (-1);
	}

	close(hci_fd);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Data Length Extension
 * ---------------------------------------------------------------- */

/*
 * LE Set Data Length — request maximum link-layer PDU size for a
 * connection.  tx_octets: 0x001B-0x00FB, tx_time: 0x0148-0x4290.
 * Core Spec Vol 4 Part E Section 7.8.33 (OCF 0x0022).
 */
int
hci_le_set_data_length(int hci_fd, uint16_t con_handle,
    uint16_t tx_octets, uint16_t tx_time)
{
	struct bt_devreq r;

	if (con_handle > 0x0EFF ||
	    tx_octets < 0x001B || tx_octets > 0x00FB ||
	    tx_time < 0x0148 || tx_time > 0x4290) {
		errno = EINVAL;
		return (-1);
	}

	ng_hci_le_set_data_length_cp cp;
	ng_hci_le_set_data_length_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.tx_octets = htole16(tx_octets);
	cp.tx_time = htole16(tx_time);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_DATA_LENGTH);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Data Length failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE data length set: tx_octets=%d tx_time=%d",
	    tx_octets, tx_time);
	return (0);
}

/*
 * LE Write Suggested Default Data Length — set defaults for new
 * connections.  Core Spec Vol 4 Part E Section 7.8.35 (OCF 0x0024).
 */
int
hci_le_write_suggested_default_data_length(int hci_fd,
    uint16_t tx_octets, uint16_t tx_time)
{
	struct bt_devreq r;

	if (tx_octets < 0x001B || tx_octets > 0x00FB ||
	    tx_time < 0x0148 || tx_time > 0x4290) {
		errno = EINVAL;
		return (-1);
	}

	ng_hci_le_write_suggested_data_length_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.suggested_max_tx_octets = htole16(tx_octets);
	cp.suggested_max_tx_time = htole16(tx_time);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_WRITE_SUGGESTED_DATA_LENGTH);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Write Suggested Default Data Length failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE default data length set: tx_octets=%d tx_time=%d",
	    tx_octets, tx_time);
	return (0);
}

/* ----------------------------------------------------------------
 * LE PHY
 * ---------------------------------------------------------------- */

/*
 * LE Set Default PHY — set preferred PHY for future connections.
 * Core Spec Vol 4 Part E Section 7.8.48 (OCF 0x0031).
 */
int
hci_le_set_default_phy(int hci_fd, uint8_t all_phys,
    uint8_t tx_phys, uint8_t rx_phys)
{
	struct bt_devreq r;
	ng_hci_le_set_default_phy_cp cp;
	ng_hci_status_rp rp;

	if (!hci_le_phy_params_valid(all_phys, tx_phys, rx_phys)) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.all_phys = all_phys;
	cp.tx_phys = tx_phys;
	cp.rx_phys = rx_phys;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_DEFAULT_PHY);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Default PHY failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE default PHY set: all=%02x tx=%02x rx=%02x",
	    all_phys, tx_phys, rx_phys);
	return (0);
}

/*
 * LE Set PHY — request PHY change on an active connection.
 * Returns Command Status (not Complete).  PHY change result
 * arrives later as LE PHY Update Complete event (subevent 0x0C).
 * Core Spec Vol 4 Part E Section 7.8.49 (OCF 0x0032).
 */
int
hci_le_set_phy(int hci_fd, uint16_t con_handle, uint8_t all_phys,
    uint8_t tx_phys, uint8_t rx_phys, uint16_t phy_options)
{
	struct bt_devreq r;
	ng_hci_le_set_phy_cp cp;
	ng_hci_status_rp rp;

	if (con_handle > 0x0EFF ||
	    !hci_le_phy_params_valid(all_phys, tx_phys, rx_phys) ||
	    (phy_options & ~0x0003) != 0 || phy_options == 0x0003) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.all_phys = all_phys;
	cp.tx_phys = tx_phys;
	cp.rx_phys = rx_phys;
	cp.phy_options = htole16(phy_options);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PHY);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set PHY failed, status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE PHY change requested: tx=%02x rx=%02x",
	    tx_phys, rx_phys);
	return (0);
}

/*
 * LE Read PHY — read current TX/RX PHY for a connection.
 * Core Spec Vol 4 Part E Section 7.8.47 (OCF 0x0030).
 */
int
hci_le_read_phy(int hci_fd, uint16_t con_handle,
    uint8_t *tx_phy, uint8_t *rx_phy)
{
	struct bt_devreq r;
	ng_hci_le_read_phy_cp cp;
	ng_hci_le_read_phy_rp rp;

	if (con_handle > 0x0EFF) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_PHY);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Read PHY failed, status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}

	if (tx_phy != NULL)
		*tx_phy = rp.tx_phy;
	if (rx_phy != NULL)
		*rx_phy = rp.rx_phy;

	LOG_HCI(1, "LE PHY: tx=%d rx=%d", rp.tx_phy, rp.rx_phy);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Set Host Feature / Create Connection Cancel
 * ---------------------------------------------------------------- */

/*
 * LE Set Host Feature — announce host-side feature support to
 * the controller.  Core Spec Vol 4 Part E Section 7.8.115 (OCF 0x0074).
 * bit_number: feature bit index, bit_value: 0=disable, 1=enable.
 */
int
hci_le_set_host_feature(int hci_fd, uint8_t bit_number, uint8_t bit_value)
{
	struct bt_devreq r;
	ng_hci_le_set_host_feature_cp cp;
	ng_hci_status_rp rp;

	memset(&cp, 0, sizeof(cp));
	cp.bit_number = bit_number;
	cp.bit_value = bit_value;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_HOST_FEATURE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Host Feature failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE host feature bit %d set to %d", bit_number, bit_value);
	return (0);
}

/*
 * LE Create Connection Cancel — abort a pending LE connection attempt.
 * Core Spec Vol 4 Part E Section 7.8.13 (OCF 0x000E).
 * No parameters.  Returns status only.
 */
int
hci_le_create_connection_cancel(int hci_fd)
{
	struct bt_devreq r;
	ng_hci_status_rp rp;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CREATE_CONNECTION_CANCEL);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Create Connection Cancel failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "LE connection creation cancelled");
	return (0);
}

/* ----------------------------------------------------------------
 * LE Connection Subrating (BT 5.3)
 * Core Spec Vol 4 Part E Sections 7.8.123-7.8.124
 * ---------------------------------------------------------------- */

/*
 * LE Set Default Subrate — set default subrate parameters for
 * all future connections.
 * Core Spec Vol 4 Part E Section 7.8.123 (OCF 0x007D).
 */
int
hci_le_set_default_subrate(int hci_fd, uint16_t min_subrate,
    uint16_t max_subrate, uint16_t max_latency, uint16_t cont_num,
    uint16_t timeout)
{
	struct bt_devreq r;
	ng_hci_le_set_default_subrate_cp cp;
	ng_hci_le_set_default_subrate_rp rp;

	if (!hci_le_subrate_params_valid(min_subrate, max_subrate,
	    max_latency, cont_num, timeout)) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.subrate_min = htole16(min_subrate);
	cp.subrate_max = htole16(max_subrate);
	cp.max_latency = htole16(max_latency);
	cp.continuation_number = htole16(cont_num);
	cp.supervision_timeout = htole16(timeout);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_DEFAULT_SUBRATE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Default Subrate failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "default subrate set: min=%d max=%d latency=%d "
	    "cont=%d timeout=%d", min_subrate, max_subrate,
	    max_latency, cont_num, timeout);
	return (0);
}

/*
 * LE Subrate Request — request subrate change on an active connection.
 * Returns Command Status; result arrives via LE Subrate Change event.
 * Core Spec Vol 4 Part E Section 7.8.124 (OCF 0x007E).
 */
int
hci_le_subrate_request(int hci_fd, uint16_t con_handle,
    uint16_t min_subrate, uint16_t max_subrate, uint16_t max_latency,
    uint16_t cont_num, uint16_t timeout)
{
	struct bt_devreq r;
	ng_hci_le_subrate_request_cp cp;
	ng_hci_status_rp rp;

	if (con_handle > 0x0EFF ||
	    !hci_le_subrate_params_valid(min_subrate, max_subrate,
	    max_latency, cont_num, timeout)) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.subrate_min = htole16(min_subrate);
	cp.subrate_max = htole16(max_subrate);
	cp.max_latency = htole16(max_latency);
	cp.continuation_number = htole16(cont_num);
	cp.supervision_timeout = htole16(timeout);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SUBRATE_REQUEST);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Subrate Request failed, status=0x%02x",
		    rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "subrate requested: con=%04x min=%d max=%d",
	    con_handle, min_subrate, max_subrate);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Power Control (BT 5.2)
 * Core Spec Vol 4 Part E Sections 7.8.117-7.8.121
 * ---------------------------------------------------------------- */

/*
 * LE Enhanced Read Transmit Power Level.
 * Core Spec Vol 4 Part E Section 7.8.117 (OCF 0x0076).
 * phy: 1=1M, 2=2M, 3=Coded S=8, 4=Coded S=2.
 */
int
hci_le_enhanced_read_tx_power_level(int hci_fd, uint16_t con_handle,
    uint8_t phy, int8_t *cur_level, int8_t *max_level)
{
	struct bt_devreq r;
	ng_hci_le_enh_read_tx_power_cp cp;
	ng_hci_le_enh_read_tx_power_rp rp;

	/*
	 * PHY is an enumerated field: 0x01=1M, 0x02=2M, 0x03=Coded S=8,
	 * 0x04=Coded S=2.  0x00 and 0x05+ are RFU and must be rejected
	 * before any I/O (Core Spec Vol 4 Part E §7.8.117).
	 */
	if (con_handle > 0x0EFF || phy < 0x01 || phy > 0x04) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.phy = phy;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_ENH_READ_TX_POWER_LEVEL);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Enhanced Read TX Power Level failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}

	if (cur_level != NULL)
		*cur_level = rp.current_tx_power_level;
	if (max_level != NULL)
		*max_level = rp.max_tx_power_level;
	LOG_HCI(1, "LE TX power: phy=%d cur=%d dBm max=%d dBm",
	    phy, rp.current_tx_power_level, rp.max_tx_power_level);
	return (0);
}

/*
 * LE Read Remote Transmit Power Level.
 * Core Spec Vol 4 Part E Section 7.8.118 (OCF 0x0077).
 * Returns Command Status; result arrives via LE Transmit
 * Power Reporting event.
 */
int
hci_le_read_remote_tx_power_level(int hci_fd, uint16_t con_handle,
    uint8_t phy)
{
	struct bt_devreq r;
	ng_hci_le_read_remote_tx_power_cp cp;
	ng_hci_status_rp rp;

	/*
	 * PHY is an enumerated field: 0x01=1M, 0x02=2M, 0x03=Coded S=8,
	 * 0x04=Coded S=2.  0x00 and 0x05+ are RFU and must be rejected
	 * before any I/O (Core Spec Vol 4 Part E §7.8.118).
	 */
	if (con_handle > 0x0EFF || phy < 0x01 || phy > 0x04) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.phy = phy;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_REMOTE_TX_POWER_LEVEL);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Read Remote TX Power Level failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "remote TX power read requested: con=%04x phy=%d",
	    con_handle, phy);
	return (0);
}

/*
 * LE Set Path Loss Reporting Parameters.
 * Core Spec Vol 4 Part E Section 7.8.119 (OCF 0x0078).
 * Thresholds and hysteresis in dB; min_time in connection events.
 */
int
hci_le_set_path_loss_reporting_params(int hci_fd, uint16_t con_handle,
    uint8_t high_thresh, uint8_t high_hyst, uint8_t low_thresh,
    uint8_t low_hyst, uint16_t min_time)
{
	struct bt_devreq r;
	ng_hci_le_set_path_loss_reporting_params_cp cp;
	ng_hci_le_set_path_loss_reporting_params_rp rp;

	/*
	 * Core Spec Vol 4 Part E §7.8.119 lists four malformed path-loss
	 * zone configurations that must be rejected as Invalid HCI Command
	 * Parameters.  Validate with widened arithmetic before touching the
	 * controller so the host never emits an impossible zone map.
	 */
	if (con_handle > 0x0EFF ||
	    high_thresh < low_thresh ||
	    (uint16_t)high_thresh + (uint16_t)high_hyst > 0xff ||
	    high_thresh < high_hyst ||
	    low_thresh < low_hyst ||
	    (uint16_t)low_thresh + (uint16_t)low_hyst >
	    (uint16_t)high_thresh - (uint16_t)high_hyst) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.high_threshold = high_thresh;
	cp.high_hysteresis = high_hyst;
	cp.low_threshold = low_thresh;
	cp.low_hysteresis = low_hyst;
	cp.min_time_spent = htole16(min_time);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PATH_LOSS_REPORTING_PARAMS);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Path Loss Reporting Params failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "path loss params set: con=%04x high=%d/%d low=%d/%d "
	    "min_time=%d", con_handle, high_thresh, high_hyst,
	    low_thresh, low_hyst, min_time);
	return (0);
}

/*
 * LE Set Path Loss Reporting Enable.
 * Core Spec Vol 4 Part E Section 7.8.120 (OCF 0x0079).
 */
int
hci_le_set_path_loss_reporting_enable(int hci_fd, uint16_t con_handle,
    uint8_t enable)
{
	struct bt_devreq r;
	ng_hci_le_set_path_loss_reporting_enable_cp cp;
	ng_hci_le_set_path_loss_reporting_enable_rp rp;

	/*
	 * Enable is a boolean: 0x00=disabled, 0x01=enabled.  Values other
	 * than 0x00/0x01 are RFU and must be rejected before any I/O
	 * (Core Spec Vol 4 Part E §7.8.120).
	 */
	if (con_handle > 0x0EFF || enable > 0x01) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.enable = enable;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PATH_LOSS_REPORTING_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set Path Loss Reporting Enable failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "path loss reporting %s, con=%04x",
	    enable ? "enabled" : "disabled", con_handle);
	return (0);
}

/*
 * LE Set Transmit Power Reporting Enable.
 * Core Spec Vol 4 Part E Section 7.8.121 (OCF 0x007A).
 */
int
hci_le_set_tx_power_reporting_enable(int hci_fd, uint16_t con_handle,
    uint8_t local_enable, uint8_t remote_enable)
{
	struct bt_devreq r;
	ng_hci_le_set_tx_power_reporting_enable_cp cp;
	ng_hci_le_set_tx_power_reporting_enable_rp rp;

	/*
	 * Local_Enable and Remote_Enable are booleans: 0x00=disabled,
	 * 0x01=enabled.  Values other than 0x00/0x01 are RFU and must be
	 * rejected before any I/O (Core Spec Vol 4 Part E §7.8.121).
	 */
	if (con_handle > 0x0EFF ||
	    local_enable > 0x01 || remote_enable > 0x01) {
		errno = EINVAL;
		return (-1);
	}

	memset(&cp, 0, sizeof(cp));
	cp.connection_handle = htole16(con_handle);
	cp.local_enable = local_enable;
	cp.remote_enable = remote_enable;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_TX_POWER_REPORTING_ENABLE);
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Set TX Power Reporting Enable failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "TX power reporting: con=%04x local=%d remote=%d",
	    con_handle, local_enable, remote_enable);
	return (0);
}

/* ----------------------------------------------------------------
 * LE Extended Create Connection (BT 5.0)
 * Core Spec Vol 4 Part E Section 7.8.66
 * ---------------------------------------------------------------- */

/*
 * LE Extended Create Connection v1.
 * Core Spec Vol 4 Part E Section 7.8.66 (OCF 0x0043).
 *
 * phys is a bitmask (bit0=1M, bit1=2M, bit2=Coded).
 * phy_params points to popcount(phys) copies of
 * ng_hci_le_ext_create_conn_phy_t, already in little-endian.
 * phy_len is the total byte length of that array.
 *
 * Returns Command Status; result arrives via LE Enhanced
 * Connection Complete event.
 */
int
hci_le_ext_create_connection(int hci_fd, uint8_t filter,
    uint8_t own_addr, uint8_t peer_addr_type,
    const uint8_t peer_addr[6], uint8_t phys,
    const void *phy_params, size_t phy_len)
{
	struct bt_devreq r;
	uint8_t buf[sizeof(ng_hci_le_ext_create_connection_cp) +
	    3 * sizeof(ng_hci_le_ext_create_conn_phy_t)];
	ng_hci_le_ext_create_connection_cp *cp;
	ng_hci_status_rp rp;
	size_t cplen, expected_phy_len;
	unsigned int phy_count;

	phy_count = ((phys & HCI_LE_PHY_1M) != 0) +
	    ((phys & HCI_LE_PHY_2M) != 0) +
	    ((phys & HCI_LE_PHY_CODED) != 0);
	expected_phy_len = phy_count * sizeof(ng_hci_le_ext_create_conn_phy_t);
	if (filter > 1 || own_addr > 3 || peer_addr_type > 1 ||
	    peer_addr == NULL || (phys & ~HCI_LE_PHY_MASK) != 0 ||
	    (phys & (HCI_LE_PHY_1M | HCI_LE_PHY_CODED)) == 0 ||
	    phy_len != expected_phy_len ||
	    phy_params == NULL) {
		errno = EINVAL;
		return (-1);
	}
	cplen = sizeof(*cp) + phy_len;

	memset(buf, 0, sizeof(buf));
	cp = (ng_hci_le_ext_create_connection_cp *)buf;
	cp->initiator_filter_policy = filter;
	cp->own_address_type = own_addr;
	cp->peer_address_type = peer_addr_type;
	memcpy(&cp->peer_address, peer_addr, 6);
	cp->initiating_phys = phys;
	memcpy(buf + sizeof(*cp), phy_params, phy_len);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_EXT_CREATE_CONNECTION);
	r.cparam = buf;
	r.clen = cplen;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_STATUS;

	if (hci_devreq_logged(hci_fd, &r, 5) < 0)
		return (-1);
	if (rp.status != 0x00) {
		LOG_HCI(1, "LE Extended Create Connection failed, "
		    "status=0x%02x", rp.status);
		errno = EIO;
		return (-1);
	}
	LOG_HCI(1, "extended connection create requested: phys=0x%02x",
	    phys);
	return (0);
}

/* ----------------------------------------------------------------
 * LE CoC (Connection-Oriented Channel) Initiation
 * ---------------------------------------------------------------- */

/*
 * Initiate an LE CoC connection to the specified peer.
 *
 * Creates an L2CAP SOCK_SEQPACKET socket, binds to BDADDR_ANY with
 * LE address type, sets l2cap_psm to the LE PSM, and connects to the
 * remote device.
 *
 * Returns the connected socket fd on success, -1 on failure.
 */
int
ble_coc_connect(const uint8_t *local_addr, const uint8_t *addr,
    uint8_t addr_type, uint16_t psm, uint16_t mtu)
{
	struct sockaddr_l2cap bind_sa, con_sa;
	struct timeval tv;
	int fd, optval;

	fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
	    BLUETOOTH_PROTO_L2CAP);
	if (fd < 0) {
		LOG_L2C(1, "LE CoC: socket() failed: %s", strerror(errno));
		return (-1);
	}
	{
		uint8_t own_addr_type = atomic_load(&l2cap_own_address_type);

		if (setsockopt(fd, SOL_L2CAP, SO_L2CAP_OWN_ADDR_TYPE,
		    &own_addr_type, sizeof(own_addr_type)) < 0) {
			close(fd);
			return (-1);
		}
	}

	/* Bind to BDADDR_ANY with LE address type */
	memset(&bind_sa, 0, sizeof(bind_sa));
	bind_sa.l2cap_len = sizeof(bind_sa);
	bind_sa.l2cap_family = AF_BLUETOOTH;
	if (local_addr != NULL)
		memcpy(&bind_sa.l2cap_bdaddr, local_addr,
		    sizeof(bind_sa.l2cap_bdaddr));
	bind_sa.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;

	/* Set desired incoming MTU before connect */
	if (mtu > 0) {
		optval = mtu;
		setsockopt(fd, SOL_L2CAP, SO_L2CAP_IMTU, &optval,
		    sizeof(optval));
	}

	if (bind(fd, (struct sockaddr *)&bind_sa, sizeof(bind_sa)) < 0) {
		LOG_L2C(1, "LE CoC: bind() failed: %s", strerror(errno));
		close(fd);
		return (-1);
	}

	/* Connect to remote device with LE PSM */
	memset(&con_sa, 0, sizeof(con_sa));
	con_sa.l2cap_len = sizeof(con_sa);
	con_sa.l2cap_family = AF_BLUETOOTH;
	memcpy(&con_sa.l2cap_bdaddr, addr, sizeof(con_sa.l2cap_bdaddr));
	con_sa.l2cap_psm = htole16(psm);
	con_sa.l2cap_cid = 0;		/* dynamic allocation */
	con_sa.l2cap_bdaddr_type = addr_type;

	if (connect(fd, (struct sockaddr *)&con_sa, sizeof(con_sa)) < 0) {
		LOG_L2C(1, "LE CoC: connect() failed: psm=%d %s",
		    psm, strerror(errno));
		close(fd);
		return (-1);
	}

	/* Set receive timeout for CoC data transfers */
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	/* Enable SO_NOSIGPIPE to avoid SIGPIPE on broken connections */
	optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval));

	LOG_L2C(1, "LE CoC connected: fd=%d psm=%d addr_type=%d",
	    fd, psm, addr_type);

	return (fd);
}

/*
 * ble_ecbfc_connect — Open multiple L2CAP CoC channels using Enhanced
 * Credit Based Flow Control (BT 5.2, Core Spec Vol 3 Part A §4.25).
 */
int
ble_ecbfc_connect(const uint8_t *local_addr, const uint8_t *addr,
    uint8_t addr_type, uint16_t psm, uint16_t mtu, int count, int *fds)
{
	int i, opened;

	if (count < 1 || count > 5 || fds == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (mtu == 0)
		mtu = 512;	/* NG_L2CAP_LE_COC_LOCAL_MTU default */

	opened = 0;
	for (i = 0; i < count; i++) {
		struct sockaddr_l2cap bind_sa, con_sa;
		struct timeval tv;
		int fd, optval, ecbfc;

		fd = socket(PF_BLUETOOTH,
		    SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
		    BLUETOOTH_PROTO_L2CAP);
		if (fd < 0) {
			LOG_L2C(1, "ECBFC: socket() failed: %s",
			    strerror(errno));
			break;
		}
		{
			uint8_t own_addr_type =
			    atomic_load(&l2cap_own_address_type);

			if (setsockopt(fd, SOL_L2CAP, SO_L2CAP_OWN_ADDR_TYPE,
			    &own_addr_type, sizeof(own_addr_type)) < 0) {
				close(fd);
				break;
			}
		}

		/* Set ECBFC mode before connect */
		ecbfc = 1;
		if (setsockopt(fd, SOL_L2CAP, SO_L2CAP_ECBFC,
		    &ecbfc, sizeof(ecbfc)) < 0) {
			LOG_L2C(1, "ECBFC: setsockopt SO_L2CAP_ECBFC: %s",
			    strerror(errno));
			close(fd);
			break;
		}
		/* PSM 0x0027 is the fixed EATT SPSM.  GATT 5.3.2 requires the
		 * underlying ACL to be encrypted before this channel is created. */
		if (psm == 0x0027) {
			int encrypted = 1;

			if (setsockopt(fd, SOL_L2CAP, SO_L2CAP_ENCRYPTED,
			    &encrypted, sizeof(encrypted)) < 0) {
				close(fd);
				break;
			}
		}

		/* Set desired incoming MTU */
		optval = mtu;
		setsockopt(fd, SOL_L2CAP, SO_L2CAP_IMTU, &optval,
		    sizeof(optval));

		/* Bind to BDADDR_ANY with LE address type */
		memset(&bind_sa, 0, sizeof(bind_sa));
		bind_sa.l2cap_len = sizeof(bind_sa);
		bind_sa.l2cap_family = AF_BLUETOOTH;
		if (local_addr != NULL)
			memcpy(&bind_sa.l2cap_bdaddr, local_addr,
			    sizeof(bind_sa.l2cap_bdaddr));
		bind_sa.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;

		if (bind(fd, (struct sockaddr *)&bind_sa,
		    sizeof(bind_sa)) < 0) {
			LOG_L2C(1, "ECBFC: bind() failed: %s",
			    strerror(errno));
			close(fd);
			break;
		}

		/* Connect to remote device with LE PSM */
		memset(&con_sa, 0, sizeof(con_sa));
		con_sa.l2cap_len = sizeof(con_sa);
		con_sa.l2cap_family = AF_BLUETOOTH;
		memcpy(&con_sa.l2cap_bdaddr, addr,
		    sizeof(con_sa.l2cap_bdaddr));
		con_sa.l2cap_psm = htole16(psm);
		con_sa.l2cap_cid = 0;		/* dynamic allocation */
		con_sa.l2cap_bdaddr_type = addr_type;

		if (connect(fd, (struct sockaddr *)&con_sa,
		    sizeof(con_sa)) < 0) {
			LOG_L2C(1, "ECBFC: connect() failed: psm=%d %s",
			    psm, strerror(errno));
			close(fd);
			break;
		}

		/* Set receive timeout */
		tv.tv_sec = 30;
		tv.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

		/* Enable SO_NOSIGPIPE */
		optval = 1;
		setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &optval,
		    sizeof(optval));

		fds[opened] = fd;
		opened++;

		LOG_L2C(1, "ECBFC: channel %d connected, fd=%d psm=%d "
		    "mtu=%d addr_type=%d", i, fd, psm, mtu, addr_type);
	}

	LOG_L2C(1, "ECBFC: %d/%d channels opened", opened, count);

	return (opened);
}

/*
 * ble_ecbfc_reconfig — Reconfigure MTU/MPS on an existing ECBFC channel.
 */
int
ble_ecbfc_reconfig(int fd, uint16_t new_mtu, uint16_t new_mps)
{
	struct l2cap_reconfig_param rp;

	rp.mtu = new_mtu;
	rp.mps = new_mps;

	if (setsockopt(fd, SOL_L2CAP, SO_L2CAP_RECONFIG,
	    &rp, sizeof(rp)) < 0) {
		LOG_L2C(1, "ECBFC reconfig failed: mtu=%d mps=%d: %s",
		    new_mtu, new_mps, strerror(errno));
		return (-1);
	}

	LOG_L2C(1, "ECBFC reconfig sent: fd=%d mtu=%d mps=%d",
	    fd, new_mtu, new_mps);

	return (0);
}

/*
 * Open a data-path socket for an established ISO stream (CIS or BIS).
 *
 * The controller has already established the stream and assigned it a
 * connection handle; this only opens the kernel ISO socket keyed by
 * (adapter src bdaddr, cis_handle) so its connected fd can be handed to a
 * broker client.  Mirrors ble_coc_connect but uses SOCK_SEQPACKET on
 * BLUETOOTH_PROTO_ISO and a sockaddr_iso addressed by the CIS/BIS handle.
 *
 * src may be NULL/BDADDR_ANY to bind to any adapter.  Returns the connected
 * socket fd on success, -1 on failure.
 */
int
ble_iso_connect(const uint8_t *src, const uint8_t *addr, uint8_t addr_type,
    uint16_t cis_handle, uint16_t mtu)
{
	struct sockaddr_iso bind_sa, con_sa;
	int fd, optval;

	fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
	    BLUETOOTH_PROTO_ISO);
	if (fd < 0) {
		LOG_HCI(1, "ISO: socket() failed: %s", strerror(errno));
		return (-1);
	}

	/* Bind to the adapter src bdaddr (BDADDR_ANY selects any adapter). */
	memset(&bind_sa, 0, sizeof(bind_sa));
	bind_sa.iso_len = sizeof(bind_sa);
	bind_sa.iso_family = AF_BLUETOOTH;
	bind_sa.iso_bdaddr_type = BDADDR_LE_PUBLIC;
	if (src != NULL)
		memcpy(&bind_sa.iso_bdaddr, src, sizeof(bind_sa.iso_bdaddr));

	if (bind(fd, (struct sockaddr *)&bind_sa, sizeof(bind_sa)) < 0) {
		LOG_HCI(1, "ISO: bind() failed: %s", strerror(errno));
		close(fd);
		return (-1);
	}

	/*
	 * Connect keys the pcb to the already-established stream by its
	 * connection handle; iso_bdaddr identifies the remote (CIS) or is the
	 * broadcast source (BIS).
	 */
	memset(&con_sa, 0, sizeof(con_sa));
	con_sa.iso_len = sizeof(con_sa);
	con_sa.iso_family = AF_BLUETOOTH;
	con_sa.iso_cis_handle = cis_handle;
	if (addr != NULL)
		memcpy(&con_sa.iso_bdaddr, addr, sizeof(con_sa.iso_bdaddr));
	con_sa.iso_bdaddr_type = addr_type;

	if (connect(fd, (struct sockaddr *)&con_sa, sizeof(con_sa)) < 0) {
		LOG_HCI(1, "ISO: connect() failed: handle=0x%04x %s",
		    cis_handle, strerror(errno));
		close(fd);
		return (-1);
	}

	/* Avoid SIGPIPE if the stream drops mid-write. */
	optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval));

	/*
	 * The ISO SDU size is fixed by the controller when the stream is
	 * established (SO_ISO_MTU is query-only), so mtu is advisory only and
	 * used here purely for the diagnostic trace.
	 */
	LOG_HCI(1, "ISO connected: fd=%d handle=0x%04x addr_type=%d mtu=%d",
	    fd, cis_handle, addr_type, mtu);

	return (fd);
}
