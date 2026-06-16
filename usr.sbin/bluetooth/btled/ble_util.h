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
#include <syslog.h>

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
 * Structured logging with per-layer prefixes and verbosity levels.
 *
 * Level 0: errors only (warnx/errx, always on)
 * Level 1: informational (-d or -v) — connection events, state changes
 * Level 2: trace (-vv) — every PDU, hex dumps, crypto steps
 *
 * The old btled_debug / DBG() interface is preserved for backward
 * compatibility: -d sets btled_verbose = 1.
 */
extern int btled_verbose;	/* 0, 1, or 2 */
extern int btled_daemonized;	/* 1 if running as daemon (use syslog) */

/* Backward compat */
#define btled_debug	(btled_verbose > 0)

#define _BTLED_LOG(layer, lvl, fmt, ...) do {			\
	if (btled_verbose >= (lvl)) {				\
		if (btled_daemonized)				\
			syslog(LOG_INFO, "[" layer "] "		\
			    fmt, ##__VA_ARGS__);			\
		else						\
			fprintf(stderr, "btled[" layer "]: "	\
			    fmt "\n", ##__VA_ARGS__);		\
	}							\
} while (0)

/* Per-layer logging macros.  Use level 1 for important events,
 * level 2 for per-PDU trace output. */
#define LOG_HCI(lvl, fmt, ...)	_BTLED_LOG("HCI",  lvl, fmt, ##__VA_ARGS__)
#define LOG_L2C(lvl, fmt, ...)	_BTLED_LOG("L2CAP",lvl, fmt, ##__VA_ARGS__)
#define LOG_ATT(lvl, fmt, ...)	_BTLED_LOG("ATT",  lvl, fmt, ##__VA_ARGS__)
#define LOG_SMP(lvl, fmt, ...)	_BTLED_LOG("SMP",  lvl, fmt, ##__VA_ARGS__)
#define LOG_GATT(lvl, fmt, ...)	_BTLED_LOG("GATT", lvl, fmt, ##__VA_ARGS__)
#define LOG_HOGP(lvl, fmt, ...)	_BTLED_LOG("HOGP", lvl, fmt, ##__VA_ARGS__)

/* Hex dump helper for trace-level (level 2) logging */
static inline void
btled_hexdump(const char *layer, const char *label,
    const uint8_t *data, size_t len)
{
	if (btled_verbose < 2)
		return;
	fprintf(stderr, "btled[%s]: %s (%zu bytes):", layer, label, len);
	for (size_t i = 0; i < len; i++)
		fprintf(stderr, " %02x", data[i]);
	fprintf(stderr, "\n");
}

/* Legacy macro — maps to generic level-1 logging */
#define DBG(fmt, ...) do { \
	if (btled_verbose >= 1) \
		fprintf(stderr, "btled: " fmt "\n", ##__VA_ARGS__); \
} while (0)

#endif /* _BTLED_BLE_UTIL_H_ */
