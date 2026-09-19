/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Device-manager policy for blued.
 *
 * Bridges persisted operational state (blued_persist) into live daemon
 * policy: a known-device table applied from the device cache, the GATT
 * robust-caching reuse decision applied from the GATT cache, the auto-connect
 * reconnect policy with bounded backoff, and a shadow of the controller
 * resolving list so add-on-bond / remove-on-unbond stay in sync with the
 * controller's finite list.  Everything here is pure policy over
 * caller-owned storage: no sockets, no globals, so it is unit-testable and the
 * daemon keeps ownership of the live buffers and the HCI transport.
 */

#ifndef _BLUED_DEVMGR_H_
#define _BLUED_DEVMGR_H_

#include <stdbool.h>
#include <stdint.h>

#include "blued_persist.h"

/* Live known-device entry flags. */
#define BLUED_KNOWN_BONDED	0x01	/* a bond exists for this device */
#define BLUED_KNOWN_AUTOCONN	0x02	/* reconnect-on-startup policy set */
#define BLUED_KNOWN_HOGP	0x04	/* HID-over-GATT peer */
#define BLUED_KNOWN_IDENTITY	0x08	/* identity_addr valid (RPA resolved) */

struct blued_known_device {
	uint8_t		addr[6];
	uint8_t		addr_type;
	uint8_t		flags;
	uint8_t		identity_addr[6];
	uint8_t		identity_addr_type;
	char		name[32];
	int64_t		last_seen;
};

#define BLUED_DEVTABLE_MAX	BLUED_PERSIST_MAX_DEVICES

struct blued_devtable {
	struct blued_known_device devs[BLUED_DEVTABLE_MAX];
	int		count;
};

/*
 * Apply a loaded persisted device cache into the live table.  Rebuilds the
 * table from scratch (idempotent across repeated applies), skips duplicate
 * records, and clamps to capacity so a hostile/oversized count cannot overflow
 * the table.  Returns the number of live entries.  A NULL/zero input clears
 * the table.
 */
int	blued_devtable_apply(struct blued_devtable *t,
	    const struct blued_persist_device *devs, uint32_t ndev);

struct blued_known_device *blued_devtable_find(struct blued_devtable *t,
	    const uint8_t addr[6], uint8_t addr_type);

/* ----------------------------------------------------------------
 * GATT robust-caching reuse decision (PC8).
 * ---------------------------------------------------------------- */

/*
 * Core Spec Vol 3 Part G §2.5.2: true when the loaded GATT cache holds an
 * entry for this peer whose stored Database Hash equals the freshly read one,
 * so the cached handles may be reused and rediscovery skipped.  An absent
 * entry or a hash mismatch returns false (fall back to rediscovery).
 */
bool	blued_gattcache_reuse(const struct blued_persist_gatt_device *devs,
	    uint32_t ndev, const uint8_t addr[6], uint8_t addr_type,
	    const uint8_t fresh_hash[16]);

/* ----------------------------------------------------------------
 * Auto-connect reconnect policy (PC6).
 * ---------------------------------------------------------------- */

/*
 * Bounded exponential backoff: the next delay is min(cur*2, max), floored at 1
 * second so a background initiator can never busy-spin and capped so it never
 * runs away.
 */
int	blued_autoconn_backoff_next(int cur, int max);

struct blued_autoconn {
	uint8_t		addr[6];
	uint8_t		addr_type;
	int		attempts;	/* retries consumed so far */
	int		delay;		/* current backoff (seconds) */
};

/*
 * Consume one retry from a device's background-reconnect budget.  Returns true
 * (and advances delay via the bounded backoff) while another attempt is
 * permitted, false once max_attempts is reached -- so retries are always
 * bounded and never infinite.
 */
bool	blued_autoconn_retry(struct blued_autoconn *a, int max_delay,
	    int max_attempts);

/*
 * Collect the auto-connect candidates (bonded devices flagged auto-connect)
 * from the live table into out[] (up to max).  Returns the candidate count.
 */
int	blued_devtable_autoconnect(const struct blued_devtable *t,
	    struct blued_autoconn *out, int max);

/* ----------------------------------------------------------------
 * Resolving-list lifecycle shadow (PC10).
 * ---------------------------------------------------------------- */

/* Bounded to a conservative controller resolving-list depth. */
#define BLUED_RESLIST_MAX	16

struct blued_reslist_entry {
	uint8_t		addr[6];
	uint8_t		addr_type;
};
struct blued_reslist {
	struct blued_reslist_entry ent[BLUED_RESLIST_MAX];
	int		count;
};

/*
 * Record a peer identity in the resolving-list shadow.  Returns 1 when newly
 * recorded (the caller must then issue the HCI add), 0 when already present
 * (idempotent) or when the shadow is full (bounded to the controller depth).
 */
int	blued_reslist_add(struct blued_reslist *rl, const uint8_t addr[6],
	    uint8_t addr_type);

/*
 * Drop a peer identity from the resolving-list shadow.  Returns 1 when it was
 * present and is now removed (the caller must then issue the HCI remove), 0
 * when it was absent (idempotent).
 */
int	blued_reslist_remove(struct blued_reslist *rl, const uint8_t addr[6],
	    uint8_t addr_type);

bool	blued_reslist_contains(const struct blued_reslist *rl,
	    const uint8_t addr[6], uint8_t addr_type);

#endif /* _BLUED_DEVMGR_H_ */
