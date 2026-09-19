/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Device-manager policy for blued (see blued_devmgr.h).
 */

#include <string.h>

#include "blued_devmgr.h"

static bool
addr_eq(const uint8_t a[6], uint8_t at, const uint8_t b[6], uint8_t bt)
{

	return (at == bt && memcmp(a, b, 6) == 0);
}

int
blued_devtable_apply(struct blued_devtable *t,
    const struct blued_persist_device *devs, uint32_t ndev)
{
	uint32_t i;

	if (t == NULL)
		return (0);

	/*
	 * Rebuild from scratch so a reload cannot leave stale entries behind
	 * and a repeated apply is idempotent.  The persist loader has already
	 * rejected corrupt/wrong-version files (CRC + version gate), so a
	 * record reaching here is structurally valid; we still clamp the count
	 * and drop duplicates before trusting it.
	 */
	memset(t, 0, sizeof(*t));
	if (devs == NULL || ndev == 0)
		return (0);
	if (ndev > BLUED_DEVTABLE_MAX)
		ndev = BLUED_DEVTABLE_MAX;

	for (i = 0; i < ndev; i++) {
		const struct blued_persist_device *pd = &devs[i];
		struct blued_known_device *kd;

		if (blued_devtable_find(t, pd->addr, pd->addr_type) != NULL)
			continue;	/* skip duplicate identities */

		kd = &t->devs[t->count];
		memset(kd, 0, sizeof(*kd));
		memcpy(kd->addr, pd->addr, 6);
		kd->addr_type = pd->addr_type;
		kd->last_seen = pd->last_seen;
		if (pd->bonded)
			kd->flags |= BLUED_KNOWN_BONDED;
		if (pd->auto_connect)
			kd->flags |= BLUED_KNOWN_AUTOCONN;
		if (pd->is_hogp)
			kd->flags |= BLUED_KNOWN_HOGP;
		if (pd->has_identity) {
			kd->flags |= BLUED_KNOWN_IDENTITY;
			memcpy(kd->identity_addr, pd->identity_addr, 6);
			kd->identity_addr_type = pd->identity_addr_type;
		}
		if (pd->has_name)
			strlcpy(kd->name, pd->name, sizeof(kd->name));
		t->count++;
	}
	return (t->count);
}

struct blued_known_device *
blued_devtable_find(struct blued_devtable *t, const uint8_t addr[6],
    uint8_t addr_type)
{
	int i;

	if (t == NULL)
		return (NULL);
	for (i = 0; i < t->count; i++) {
		if (addr_eq(t->devs[i].addr, t->devs[i].addr_type,
		    addr, addr_type))
			return (&t->devs[i]);
	}
	return (NULL);
}

bool
blued_gattcache_reuse(const struct blued_persist_gatt_device *devs,
    uint32_t ndev, const uint8_t addr[6], uint8_t addr_type,
    const uint8_t fresh_hash[16])
{
	uint32_t i;

	if (devs == NULL || fresh_hash == NULL)
		return (false);
	if (ndev > BLUED_PERSIST_MAX_GATT_DEVICES)
		ndev = BLUED_PERSIST_MAX_GATT_DEVICES;

	for (i = 0; i < ndev; i++) {
		const struct blued_persist_gatt_device *g = &devs[i];

		if (!addr_eq(g->addr, g->addr_type, addr, addr_type))
			continue;
		return (blued_persist_gatt_hash_matches(g, fresh_hash));
	}
	return (false);
}

int
blued_autoconn_backoff_next(int cur, int max)
{
	long n;

	if (max < 1)
		max = 1;
	if (cur < 1)
		return (1);	/* floor: never busy-spin */
	n = (long)cur * 2;
	if (n > max)
		n = max;
	return ((int)n);
}

bool
blued_autoconn_retry(struct blued_autoconn *a, int max_delay, int max_attempts)
{

	if (a == NULL || max_attempts < 1)
		return (false);
	if (a->attempts >= max_attempts)
		return (false);	/* budget exhausted: bounded, never infinite */
	a->attempts++;
	if (a->delay < 1)
		a->delay = 1;
	else
		a->delay = blued_autoconn_backoff_next(a->delay, max_delay);
	return (true);
}

int
blued_devtable_autoconnect(const struct blued_devtable *t,
    struct blued_autoconn *out, int max)
{
	int i, n = 0;

	if (t == NULL || out == NULL || max <= 0)
		return (0);
	for (i = 0; i < t->count && n < max; i++) {
		const struct blued_known_device *kd = &t->devs[i];

		/* Only bonded devices explicitly flagged auto-connect. */
		if ((kd->flags & BLUED_KNOWN_AUTOCONN) == 0)
			continue;
		if ((kd->flags & BLUED_KNOWN_BONDED) == 0)
			continue;
		memset(&out[n], 0, sizeof(out[n]));
		memcpy(out[n].addr, kd->addr, 6);
		out[n].addr_type = kd->addr_type;
		n++;
	}
	return (n);
}

int
blued_reslist_add(struct blued_reslist *rl, const uint8_t addr[6],
    uint8_t addr_type)
{

	if (rl == NULL)
		return (0);
	if (blued_reslist_contains(rl, addr, addr_type))
		return (0);	/* idempotent */
	if (rl->count >= BLUED_RESLIST_MAX)
		return (0);	/* bounded to controller depth */
	memcpy(rl->ent[rl->count].addr, addr, 6);
	rl->ent[rl->count].addr_type = addr_type;
	rl->count++;
	return (1);
}

int
blued_reslist_remove(struct blued_reslist *rl, const uint8_t addr[6],
    uint8_t addr_type)
{
	int i;

	if (rl == NULL)
		return (0);
	for (i = 0; i < rl->count; i++) {
		if (!addr_eq(rl->ent[i].addr, rl->ent[i].addr_type,
		    addr, addr_type))
			continue;
		if (i < rl->count - 1)
			memmove(&rl->ent[i], &rl->ent[i + 1],
			    (rl->count - i - 1) * sizeof(rl->ent[0]));
		rl->count--;
		memset(&rl->ent[rl->count], 0, sizeof(rl->ent[rl->count]));
		return (1);
	}
	return (0);	/* idempotent: absent */
}

bool
blued_reslist_contains(const struct blued_reslist *rl, const uint8_t addr[6],
    uint8_t addr_type)
{
	int i;

	if (rl == NULL)
		return (false);
	for (i = 0; i < rl->count; i++) {
		if (addr_eq(rl->ent[i].addr, rl->ent[i].addr_type,
		    addr, addr_type))
			return (true);
	}
	return (false);
}
