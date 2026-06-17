/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_BLE_UTIL_H_
#define _BLUED_BLE_UTIL_H_

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
 * Bluetooth Base UUID in little-endian wire format (first 12 bytes).
 * Full Base UUID: 00000000-0000-1000-8000-00805F9B34FB
 * LE wire order:  FB 34 9B 5F 80 00 00 80 00 10 00 00 [uuid32_le]
 */
static const uint8_t bt_base_uuid_le[12] = {
	0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00,
	0x00, 0x80, 0x00, 0x10, 0x00, 0x00
};

/*
 * Structured logging with per-layer prefixes and verbosity levels.
 *
 * Level 0: errors only (warnx/errx, always on)
 * Level 1: informational (-d or -v) — connection events, state changes
 * Level 2: trace (-vv) — every PDU, hex dumps, crypto steps
 *
 * The old blued_debug / DBG() interface is preserved for backward
 * compatibility: -d sets blued_verbose = 1.
 */
extern int blued_verbose;	/* 0, 1, or 2 */
extern int blued_daemonized;	/* 1 if running as daemon (use syslog) */

/* Backward compat */
#define blued_debug	(blued_verbose > 0)

#define _BLUED_LOG(layer, lvl, fmt, ...) do {			\
	if (blued_verbose >= (lvl)) {				\
		if (blued_daemonized)				\
			syslog((lvl) >= 2 ? LOG_DEBUG : LOG_INFO, \
			    "[" layer "] "			\
			    fmt, ##__VA_ARGS__);			\
		else						\
			fprintf(stderr, "blued[" layer "]: "	\
			    fmt "\n", ##__VA_ARGS__);		\
	}							\
} while (0)

/*
 * Security audit logging.  Always emitted to syslog (LOG_AUTH facility)
 * regardless of verbosity, because security events must be auditable.
 * Also printed to stderr when verbose.
 */
#define BLUED_LOG_SECURITY(fmt, ...) do {			\
	syslog(LOG_AUTH | LOG_NOTICE, "blued[SEC]: "		\
	    fmt, ##__VA_ARGS__);				\
	if (blued_verbose >= 1)					\
		fprintf(stderr, "blued[SEC]: "			\
		    fmt "\n", ##__VA_ARGS__);			\
} while (0)

/* Per-layer logging macros.  Use level 1 for important events,
 * level 2 for per-PDU trace output. */
#define LOG_HCI(lvl, fmt, ...)	_BLUED_LOG("HCI",  lvl, fmt, ##__VA_ARGS__)
#define LOG_L2C(lvl, fmt, ...)	_BLUED_LOG("L2CAP",lvl, fmt, ##__VA_ARGS__)
#define LOG_ATT(lvl, fmt, ...)	_BLUED_LOG("ATT",  lvl, fmt, ##__VA_ARGS__)
#define LOG_SMP(lvl, fmt, ...)	_BLUED_LOG("SMP",  lvl, fmt, ##__VA_ARGS__)
#define LOG_GATT(lvl, fmt, ...)	_BLUED_LOG("GATT", lvl, fmt, ##__VA_ARGS__)
#define LOG_HOGP(lvl, fmt, ...)	_BLUED_LOG("HOGP", lvl, fmt, ##__VA_ARGS__)

/* Hex dump helper for trace-level (level 2) logging */
static inline void
blued_hexdump(const char *layer, const char *label,
    const uint8_t *data, size_t len)
{
	size_t i;

	if (blued_verbose < 2)
		return;
	if (blued_daemonized)
		return;		/* stderr goes nowhere when daemonized */
	fprintf(stderr, "blued[%s]: %s (%zu bytes):", layer, label, len);
	for (i = 0; i < len; i++)
		fprintf(stderr, " %02x", data[i]);
	fprintf(stderr, "\n");
}

/* Legacy macro — maps to generic level-1 logging */
#define DBG(fmt, ...) do { \
	if (blued_verbose >= 1) \
		fprintf(stderr, "blued: " fmt "\n", ##__VA_ARGS__); \
} while (0)

#endif /* _BLUED_BLE_UTIL_H_ */
