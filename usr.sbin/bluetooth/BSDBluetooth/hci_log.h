/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_HCI_LOG_H_
#define _BLUED_HCI_LOG_H_

#include <stdbool.h>
#include <stdint.h>

/*
 * HCI packet logger.
 *
 * Writes raw HCI packets to a file in BTSnoop format, which can be
 * opened in Wireshark for analysis.  Enabled via blued -L <file>.
 *
 * BTSnoop format reference: RFC-like format used by Android and
 * other Bluetooth stacks.  Header: "btsnoop\0" + version(4) + datalink(4).
 * Each record: original_length(4) + included_length(4) + flags(4)
 * + drops(4) + timestamp_us(8) + data.
 */

void	hci_log_open(const char *path);
void	hci_log_close(void);
bool	hci_log_enabled(void);
void	hci_log_packet(uint8_t type, const uint8_t *data, uint16_t len,
	    bool incoming);
void	hci_log_l2cap(uint16_t con_handle, uint16_t cid,
	    const uint8_t *data, size_t len, bool incoming);

/* HCI packet type indicators for BTSnoop flags */
#define HCI_LOG_CMD	0x01
#define HCI_LOG_ACL	0x02
#define HCI_LOG_SCO	0x03
#define HCI_LOG_EVT	0x04
#define HCI_LOG_ISO	0x05

#endif /* _BLUED_HCI_LOG_H_ */
