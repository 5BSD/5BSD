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
 * Collect the Protocol Mode characteristic value handles out of one HID
 * Service instance's characteristic array, appending to `out'.
 *
 * HIDS §2.4 line 642: "Only a single instance of this characteristic shall
 * exist as part of the HID Service", so at most one handle comes out of any
 * one instance.  The multiplicity that matters is across HID Services, which
 * is why the caller accumulates across instances rather than this function
 * looping for more than one per call.
 *
 * Returns 0 on success, EINVAL on a bad argument, ENOSPC if `out' is full.
 */
int
hogp_collect_protocol_mode_handles(const struct gatt_char *chars, int nchars,
    uint16_t *out, int maxout, int *nout)
{
	int i, n;

	if (chars == NULL || nchars < 0 || out == NULL || nout == NULL ||
	    maxout <= 0 || *nout < 0 || *nout > maxout)
		return (EINVAL);
	n = *nout;
	for (i = 0; i < nchars; i++) {
		if (chars[i].uuid16 != UUID_PROTOCOL_MODE)
			continue;
		if (n >= maxout) {
			*nout = n;
			return (ENOSPC);
		}
		out[n++] = chars[i].value_handle;
	}
	*nout = n;
	return (0);
}

/*
 * HOGP 1.1 §4.11 (text line 1187): "The Boot Host shall write to the Protocol
 * Mode characteristic for each HID Service on the GATT Server and set the
 * characteristic value to the defined value for Boot Protocol Mode following
 * connection establishment."  HIDS Table 2.2 line 662 makes it load-bearing:
 * "A HID Service shall only enter Boot Protocol Mode after this value has been
 * written."
 *
 * The "for each HID Service" part is the caller's obligation and cannot be
 * satisfied from one instance's characteristic array; pass the handles
 * accumulated across every discovered HID Service instance (see
 * hogp_collect_protocol_mode_handles()).  Fail closed if there is no Protocol
 * Mode characteristic at all or a write cannot be issued.
 *
 * Note the role dimension: this is a Boot Host action.  HOGP §2.3 lines
 * 575/577 make Boot Host and Report Host mutually exclusive, and §4.11 line
 * 1189 states there are no requirements on a Report Host to use the Protocol
 * Mode characteristic, so nothing may write Report Protocol Mode on a
 * connection where this runs.
 */
int
hogp_enter_boot_protocol_handles(struct att_conn *att, const uint16_t *handles,
    int nhandles)
{
	uint8_t mode = HID_PROTOCOL_BOOT;
	int i, found = 0;

	if (att == NULL || handles == NULL || nhandles < 0)
		return (EINVAL);
	for (i = 0; i < nhandles; i++) {
		if (handles[i] == 0)
			continue;
		if (att_write_cmd(att, handles[i], &mode, sizeof(mode)) != 0)
			return (EIO);
		found = 1;
	}
	return (found ? 0 : ENOENT);
}

/*
 * Single-HID-Service convenience form: collect this instance's Protocol Mode
 * handle and write Boot Protocol Mode to it.
 */
int
hogp_enter_boot_protocol(struct att_conn *att, const struct gatt_char *chars,
    int nchars)
{
	uint16_t handles[HOGP_MAX_PROTOCOL_MODE_HANDLES];
	int n = 0, ret;

	if (att == NULL || chars == NULL || nchars < 0)
		return (EINVAL);
	ret = hogp_collect_protocol_mode_handles(chars, nchars, handles,
	    (int)(sizeof(handles) / sizeof(handles[0])), &n);
	if (ret != 0 && ret != ENOSPC)
		return (ret);
	return (hogp_enter_boot_protocol_handles(att, handles, n));
}
