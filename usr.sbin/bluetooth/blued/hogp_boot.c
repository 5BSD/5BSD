/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#include <errno.h>
#include <stdint.h>

#include "att.h"
#include "gatt.h"
#include "hogp_boot.h"

/*
 * HOGP 1.1 §4.11 requires a Boot Host to write Boot Protocol Mode to
 * every HID Service after connection establishment.  Fail closed if the
 * characteristic is absent or the write cannot be issued.
 */
int
hogp_enter_boot_protocol(struct att_conn *att, const struct gatt_char *chars,
    int nchars)
{
	uint8_t mode = HID_PROTOCOL_BOOT;
	int i;

	if (att == NULL || chars == NULL || nchars < 0)
		return (EINVAL);
	for (i = 0; i < nchars; i++) {
		if (chars[i].uuid16 != UUID_PROTOCOL_MODE)
			continue;
		if (att_write_cmd(att, chars[i].value_handle, &mode,
		    sizeof(mode)) != 0)
			return (EIO);
		return (0);
	}
	return (ENOENT);
}
