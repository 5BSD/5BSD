/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_HOGP_BOOT_H_
#define _BLUED_HOGP_BOOT_H_

#include <stdint.h>

/* Bluetooth SIG Assigned Numbers, GATT Characteristics. */
#define UUID_PROTOCOL_MODE		0x2A4E
#define UUID_BOOT_KB_INPUT_REPORT	0x2A22
#define UUID_BOOT_MOUSE_INPUT_REPORT	0x2A33

/* HID Service 1.1 §2.4.1.1, Table 2.2. */
#define HID_PROTOCOL_BOOT		0x00
#define HID_PROTOCOL_REPORT		0x01

/*
 * Upper bound on the Protocol Mode characteristics tracked for one device:
 * HIDS §2.4 permits only one per HID Service, so this is the HID Service
 * instance limit (hogp_report.h HOGP_MAX_HID_INSTANCES).
 */
#define HOGP_MAX_PROTOCOL_MODE_HANDLES	4

struct att_conn;
struct gatt_char;

int	hogp_collect_protocol_mode_handles(const struct gatt_char *chars,
	    int nchars, uint16_t *out, int maxout, int *nout);
int	hogp_enter_boot_protocol_handles(struct att_conn *att,
	    const uint16_t *handles, int nhandles);
int	hogp_enter_boot_protocol(struct att_conn *att,
	    const struct gatt_char *chars, int nchars);

#endif /* _BLUED_HOGP_BOOT_H_ */
