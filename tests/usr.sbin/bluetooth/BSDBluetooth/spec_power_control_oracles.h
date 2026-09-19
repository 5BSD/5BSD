/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Independent Bluetooth Core 6.3 LE Power Control wire oracles.
 * No production Bluetooth header is included.
 */

#ifndef TESTS_BLUETOOTH_SPEC_POWER_CONTROL_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_POWER_CONTROL_ORACLES_H

#include <stdint.h>

/* Core 6.3 Vol 4 Part E §§7.8.117-7.8.121: complete HCI opcodes. */
#define BT_POWER_SPEC_OP_ENH_READ_TX_POWER	0x2076
#define BT_POWER_SPEC_OP_READ_REMOTE_TX_POWER	0x2077
#define BT_POWER_SPEC_OP_SET_PATH_LOSS_PARAMS	0x2078
#define BT_POWER_SPEC_OP_SET_PATH_LOSS_ENABLE	0x2079
#define BT_POWER_SPEC_OP_SET_TX_POWER_ENABLE	0x207a

/* Core 6.3 Vol 4 Part E §1.3 and the command parameter tables. */
#define BT_POWER_SPEC_STATUS_SUCCESS		0x00
#define BT_POWER_SPEC_STATUS_COMMAND_DISALLOWED	0x0c
#define BT_POWER_SPEC_PHY_1M			0x01
#define BT_POWER_SPEC_PHY_2M			0x02
#define BT_POWER_SPEC_PHY_CODED_S8		0x03
#define BT_POWER_SPEC_PHY_CODED_S2		0x04
#define BT_POWER_SPEC_DISABLED			0x00
#define BT_POWER_SPEC_ENABLED			0x01

/* Core 6.3 Vol 4 Part E §§7.7.65.32-7.7.65.33. */
#define BT_POWER_SPEC_SUBEVENT_PATH_LOSS	0x20
#define BT_POWER_SPEC_SUBEVENT_TX_POWER		0x21
#define BT_POWER_SPEC_REASON_REMOTE_CHANGED	0x01
#define BT_POWER_SPEC_ZONE_HIGH			0x02
#define BT_POWER_SPEC_FLAG_AT_MINIMUM		0x01

/* Core 6.3 Vol 4 Part A §2 and Vol 4 Part E §7.7.65. */
#define BT_POWER_SPEC_HCI_EVENT_PACKET		0x04
#define BT_POWER_SPEC_EVENT_LE_META		0x3e

static const uint8_t bt_power_spec_cp_handle40_phy2m[] = {
	0x40, 0x00, BT_POWER_SPEC_PHY_2M
};
static const uint8_t bt_power_spec_cp_handle40_phy1m[] = {
	0x40, 0x00, BT_POWER_SPEC_PHY_1M
};
static const uint8_t bt_power_spec_cp_path_loss[] = {
	0x40, 0x00, 0x40, 0x04, 0x10, 0x04, 0x0a, 0x00
};
static const uint8_t bt_power_spec_path_loss_event[] = {
	BT_POWER_SPEC_HCI_EVENT_PACKET, BT_POWER_SPEC_EVENT_LE_META, 0x05,
	BT_POWER_SPEC_SUBEVENT_PATH_LOSS, 0x40, 0x00, 0x2a,
	BT_POWER_SPEC_ZONE_HIGH
};
static const uint8_t bt_power_spec_tx_power_event[] = {
	BT_POWER_SPEC_HCI_EVENT_PACKET, BT_POWER_SPEC_EVENT_LE_META, 0x09,
	BT_POWER_SPEC_SUBEVENT_TX_POWER, BT_POWER_SPEC_STATUS_SUCCESS,
	0x40, 0x00, BT_POWER_SPEC_REASON_REMOTE_CHANGED, BT_POWER_SPEC_PHY_1M,
	0xe2, BT_POWER_SPEC_FLAG_AT_MINIMUM, 0x05
};

#endif /* TESTS_BLUETOOTH_SPEC_POWER_CONTROL_ORACLES_H */
