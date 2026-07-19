/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_HOGP_BOOT_H_
#define _BLUED_HOGP_BOOT_H_

/* Bluetooth SIG Assigned Numbers, GATT Characteristics. */
#define UUID_PROTOCOL_MODE		0x2A4E
#define UUID_BOOT_KB_INPUT_REPORT	0x2A22
#define UUID_BOOT_MOUSE_INPUT_REPORT	0x2A33

/* HID Service 1.1 §2.4.1.1, Table 2.2. */
#define HID_PROTOCOL_BOOT		0x00
#define HID_PROTOCOL_REPORT		0x01

struct att_conn;
struct gatt_char;

int	hogp_enter_boot_protocol(struct att_conn *att,
	    const struct gatt_char *chars, int nchars);

#endif /* _BLUED_HOGP_BOOT_H_ */
