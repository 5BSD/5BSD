/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BTLED_BLE_UTIL_H_
#define _BTLED_BLE_UTIL_H_

#include <stdint.h>
#include <stdio.h>

static inline void
put_le16(uint8_t *p, uint16_t v)
{
	p[0] = v & 0xFF;
	p[1] = (v >> 8) & 0xFF;
}

static inline uint16_t
get_le16(const uint8_t *p)
{
	return ((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/*
 * Debug logging.  Gated by btled_debug (set from -d flag).
 * Errors use warnx() unconditionally.
 */
extern int btled_debug;

#define DBG(fmt, ...) do { \
	if (btled_debug) \
		fprintf(stderr, "btled: " fmt "\n", ##__VA_ARGS__); \
} while (0)

#endif /* _BTLED_BLE_UTIL_H_ */
