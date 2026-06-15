/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BTLED_HCI_UTIL_H_
#define _BTLED_HCI_UTIL_H_

#include <stdint.h>
#include <stdbool.h>

/*
 * BLE scan result entry.
 */
struct ble_scan_result {
	uint8_t		addr[6];
	uint8_t		addr_type;	/* BDADDR_LE_PUBLIC or BDADDR_LE_RANDOM */
	int8_t		rssi;
	char		name[32];	/* from AD Complete/Short Local Name */
	bool		has_name;
};

#define BLE_MAX_SCAN_RESULTS	64

/* hci_util.c — central mode */
int	hci_open(const char *adapter);
int	hci_get_bdaddr(int hci_fd, uint8_t *bdaddr);
int	hci_get_con_handle(int hci_fd, const uint8_t *remote_addr,
	    uint16_t *handle);
int	hci_le_scan(int hci_fd, int duration_sec,
	    struct ble_scan_result *results, int maxresults, int *nresults);
int	hci_wait_encryption(int hci_fd, uint16_t con_handle, int timeout_sec);

/* hci_util.c — peripheral mode (advertising + LTK) */
int	hci_le_set_advertising_params(int hci_fd, uint16_t interval_min,
	    uint16_t interval_max, uint8_t adv_type);
int	hci_le_set_advertising_data(int hci_fd, const uint8_t *data,
	    uint8_t len);
int	hci_le_set_advertise_enable(int hci_fd, bool enable);
int	hci_le_ltk_request_reply(int hci_fd, uint16_t con_handle,
	    const uint8_t ltk[16]);
int	hci_le_ltk_request_neg_reply(int hci_fd, uint16_t con_handle);
int	ble_build_adv_data(uint8_t *buf, size_t buflen, const char *name,
	    const uint16_t *uuids, int nuuids);

#endif /* _BTLED_HCI_UTIL_H_ */
