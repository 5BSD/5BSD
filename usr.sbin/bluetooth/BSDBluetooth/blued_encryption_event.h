/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_ENCRYPTION_EVENT_H_
#define _BLUED_ENCRYPTION_EVENT_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include "hci_internal.h"

/*
 * Bluetooth Core 6.3 Vol 4, Part E, Section 7.7.8.
 *
 * Version 1 has four parameter octets; version 2 adds Encryption_Key_Size.
 * For LE, Encryption_Enabled is ON only at 0x01 and Encryption_Key_Size in
 * the v2 event shall be ignored.  The negotiated SMP bond remains blued's
 * key-size authority.
 */
struct blued_encryption_change {
	uint16_t	handle;
	uint8_t	status;
	uint8_t	encryption_enabled;
	uint8_t	version;
};

static inline uint16_t
blued_encryption_event_le16(const uint8_t *p)
{

	return ((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline int
blued_parse_encryption_change(const uint8_t *buf, size_t len,
    struct blued_encryption_change *out)
{
	size_t expected_len;
	uint8_t version;
	uint16_t handle;

	if (buf == NULL || out == NULL || len < 3 ||
	    buf[0] != NG_HCI_EVENT_PKT)
		return (-1);
	if (buf[1] == NG_HCI_EVENT_ENCRYPTION_CHANGE) {
		expected_len = 7;
		version = 1;
	} else if (buf[1] == NG_HCI_EVENT_ENCRYPTION_CHANGE_V2) {
		expected_len = 8;
		version = 2;
	} else
		return (-1);
	if (len != expected_len || buf[2] != expected_len - 3)
		return (-1);

	handle = blued_encryption_event_le16(buf + 4);
	if (handle > BLUED_HCI_CONNECTION_HANDLE_MAX)
		return (-1);

	out->status = buf[3];
	out->handle = handle;
	out->encryption_enabled = buf[6];
	out->version = version;
	return (0);
}

static inline bool
blued_encryption_change_is_le_on(const struct blued_encryption_change *event)
{

	return (event != NULL && event->status == 0 &&
	    event->encryption_enabled == 0x01);
}

/* Unknown migrated bond metadata is not evidence of maximum key strength. */
static inline uint8_t
blued_encryption_change_effective_key_size(uint8_t bond_key_size)
{

	if (bond_key_size >= BLUED_HCI_ENCRYPTION_KEY_SIZE_MIN &&
	    bond_key_size <= BLUED_HCI_ENCRYPTION_KEY_SIZE_MAX)
		return (bond_key_size);
	return (BLUED_HCI_ENCRYPTION_KEY_SIZE_MIN);
}

#endif /* _BLUED_ENCRYPTION_EVENT_H_ */
