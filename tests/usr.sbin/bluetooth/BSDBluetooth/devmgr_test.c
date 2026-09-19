/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Tests for the device-manager policy layer (blued_devmgr) that applies
 * persisted operational state to live daemon policy:
 *   PC8  — the device cache is applied into a live known-device table, and a
 *          restored GATT cache short-circuits rediscovery on a Database Hash
 *          match (and falls back to rediscovery on a mismatch);
 *   PC6  — auto-connect candidate selection and bounded-backoff retry;
 *   PC10 — the resolving-list shadow tracks bond/unbond add/remove idempotently
 *          and bounded to the controller list depth.
 */

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "blued_devmgr.h"

/* ================================================================
 * PC8: device-cache apply into the live known-device table.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(pc8_devcache_apply_populates_live_table);
ATF_TC_BODY(pc8_devcache_apply_populates_live_table, tc)
{
	struct blued_persist_device in[2];
	struct blued_devtable t;
	struct blued_known_device *kd;
	int n;

	memset(in, 0, sizeof(in));
	memcpy(in[0].addr, "\x01\x02\x03\x04\x05\x06", 6);
	in[0].addr_type = 1;
	in[0].has_name = 1;
	strlcpy(in[0].name, "Keyboard", sizeof(in[0].name));
	in[0].is_hogp = 1;
	in[0].bonded = 1;
	in[0].auto_connect = 1;
	in[0].last_seen = 1234567890;

	memcpy(in[1].addr, "\xAA\xBB\xCC\x40\x00\x00", 6);
	in[1].addr_type = 2;
	in[1].has_identity = 1;
	memcpy(in[1].identity_addr, "\x11\x22\x33\x44\x55\x66", 6);
	in[1].identity_addr_type = 1;

	n = blued_devtable_apply(&t, in, 2);
	ATF_CHECK_EQ(2, n);

	/* A cached device is present in the live table after a load. */
	kd = blued_devtable_find(&t,
	    (const uint8_t *)"\x01\x02\x03\x04\x05\x06", 1);
	ATF_REQUIRE(kd != NULL);
	ATF_CHECK_STREQ("Keyboard", kd->name);
	ATF_CHECK_EQ(1234567890, kd->last_seen);
	ATF_CHECK((kd->flags & BLUED_KNOWN_BONDED) != 0);
	ATF_CHECK((kd->flags & BLUED_KNOWN_AUTOCONN) != 0);
	ATF_CHECK((kd->flags & BLUED_KNOWN_HOGP) != 0);

	kd = blued_devtable_find(&t,
	    (const uint8_t *)"\xAA\xBB\xCC\x40\x00\x00", 2);
	ATF_REQUIRE(kd != NULL);
	ATF_CHECK((kd->flags & BLUED_KNOWN_IDENTITY) != 0);
	ATF_CHECK_EQ(0, memcmp(kd->identity_addr,
	    "\x11\x22\x33\x44\x55\x66", 6));

	/* Wrong address type is a miss. */
	ATF_CHECK(blued_devtable_find(&t,
	    (const uint8_t *)"\x01\x02\x03\x04\x05\x06", 2) == NULL);
}

ATF_TC_WITHOUT_HEAD(pc8_devcache_apply_is_idempotent_and_guarded);
ATF_TC_BODY(pc8_devcache_apply_is_idempotent_and_guarded, tc)
{
	struct blued_persist_device in[3];
	struct blued_devtable t;

	memset(in, 0, sizeof(in));
	in[0].addr_type = in[1].addr_type = in[2].addr_type = 1;
	memcpy(in[0].addr, "\x0A\x00\x00\x00\x00\x01", 6);
	/* Two duplicate identities collapse to one live entry. */
	memcpy(in[1].addr, "\x0A\x00\x00\x00\x00\x02", 6);
	memcpy(in[2].addr, "\x0A\x00\x00\x00\x00\x02", 6);

	ATF_CHECK_EQ(2, blued_devtable_apply(&t, in, 3));

	/* Re-applying rebuilds from scratch (no stale accumulation). */
	ATF_CHECK_EQ(2, blued_devtable_apply(&t, in, 3));

	/* A zero/NULL load clears the table (partial load cannot poison). */
	ATF_CHECK_EQ(0, blued_devtable_apply(&t, NULL, 0));
	ATF_CHECK_EQ(0, t.count);
}

/* A count exceeding the table capacity is clamped, never overflowing it. */
ATF_TC_WITHOUT_HEAD(pc8_devcache_apply_clamps_to_capacity);
ATF_TC_BODY(pc8_devcache_apply_clamps_to_capacity, tc)
{
	static struct blued_persist_device full[BLUED_DEVTABLE_MAX];
	struct blued_devtable t;
	int i;

	memset(full, 0, sizeof(full));
	for (i = 0; i < BLUED_DEVTABLE_MAX; i++) {
		full[i].addr_type = 1;
		full[i].addr[0] = (uint8_t)i;
		full[i].addr[1] = (uint8_t)(i >> 8);
	}

	/* An over-large count is clamped to the capacity of the buffer. */
	ATF_CHECK_EQ(BLUED_DEVTABLE_MAX,
	    blued_devtable_apply(&t, full, BLUED_DEVTABLE_MAX + 1000u));
	ATF_CHECK_EQ(BLUED_DEVTABLE_MAX, t.count);
}

/* ================================================================
 * PC8: restored GATT cache short-circuits vs. invalidates on DB Hash.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(pc8_gattcache_reuse_follows_db_hash);
ATF_TC_BODY(pc8_gattcache_reuse_follows_db_hash, tc)
{
	struct blued_persist_gatt_device g[1];
	uint8_t same[16], diff[16];

	memset(g, 0, sizeof(g));
	memcpy(g[0].addr, "\xDE\xAD\xBE\xEF\x00\x01", 6);
	g[0].addr_type = 1;
	g[0].has_db_hash = 1;
	memset(same, 0x5A, sizeof(same));
	memcpy(g[0].db_hash, same, 16);

	/* Matching hash for the right peer -> reuse (skip rediscovery). */
	ATF_CHECK(blued_gattcache_reuse(g, 1,
	    (const uint8_t *)"\xDE\xAD\xBE\xEF\x00\x01", 1, same));

	/* Changed hash -> invalidate (fall back to rediscovery). */
	memcpy(diff, same, sizeof(diff));
	diff[3] ^= 0xFF;
	ATF_CHECK(!blued_gattcache_reuse(g, 1,
	    (const uint8_t *)"\xDE\xAD\xBE\xEF\x00\x01", 1, diff));

	/* Unknown peer -> no reuse. */
	ATF_CHECK(!blued_gattcache_reuse(g, 1,
	    (const uint8_t *)"\x00\x00\x00\x00\x00\x00", 1, same));

	/* Entry without a stored hash -> never reused. */
	g[0].has_db_hash = 0;
	ATF_CHECK(!blued_gattcache_reuse(g, 1,
	    (const uint8_t *)"\xDE\xAD\xBE\xEF\x00\x01", 1, same));
}

/* ================================================================
 * PC6: bounded exponential backoff.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(pc6_backoff_is_bounded);
ATF_TC_BODY(pc6_backoff_is_bounded, tc)
{
	int d;

	/* Floor at 1s so a background initiator never busy-spins. */
	ATF_CHECK_EQ(1, blued_autoconn_backoff_next(0, 60));
	ATF_CHECK_EQ(1, blued_autoconn_backoff_next(-5, 60));

	/* Doubles until it reaches the cap, then stays capped. */
	d = 1;
	d = blued_autoconn_backoff_next(d, 10);	ATF_CHECK_EQ(2, d);
	d = blued_autoconn_backoff_next(d, 10);	ATF_CHECK_EQ(4, d);
	d = blued_autoconn_backoff_next(d, 10);	ATF_CHECK_EQ(8, d);
	d = blued_autoconn_backoff_next(d, 10);	ATF_CHECK_EQ(10, d);
	d = blued_autoconn_backoff_next(d, 10);	ATF_CHECK_EQ(10, d);
}

ATF_TC_WITHOUT_HEAD(pc6_retry_budget_is_bounded);
ATF_TC_BODY(pc6_retry_budget_is_bounded, tc)
{
	struct blued_autoconn a;
	int tries = 0;

	memset(&a, 0, sizeof(a));
	while (blued_autoconn_retry(&a, 30, 4)) {
		tries++;
		ATF_CHECK(a.delay >= 1);	/* never zero -> never busy-spin */
		ATF_CHECK(a.delay <= 30);	/* never runs away */
	}
	/* Exactly max_attempts retries, then the budget is exhausted. */
	ATF_CHECK_EQ(4, tries);
	ATF_CHECK_EQ(4, a.attempts);
	/* Further calls stay false -> no infinite retry. */
	ATF_CHECK(!blued_autoconn_retry(&a, 30, 4));
}

/* ================================================================
 * PC6: only bonded + auto-connect-flagged devices are candidates.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(pc6_autoconnect_candidate_selection);
ATF_TC_BODY(pc6_autoconnect_candidate_selection, tc)
{
	struct blued_persist_device in[3];
	struct blued_devtable t;
	struct blued_autoconn out[8];
	int n;

	memset(in, 0, sizeof(in));
	/* bonded + auto -> candidate */
	memcpy(in[0].addr, "\x01\x00\x00\x00\x00\x01", 6);
	in[0].addr_type = 1; in[0].bonded = 1; in[0].auto_connect = 1;
	/* bonded but not auto -> excluded */
	memcpy(in[1].addr, "\x01\x00\x00\x00\x00\x02", 6);
	in[1].addr_type = 1; in[1].bonded = 1; in[1].auto_connect = 0;
	/* auto but not bonded -> excluded */
	memcpy(in[2].addr, "\x01\x00\x00\x00\x00\x03", 6);
	in[2].addr_type = 1; in[2].bonded = 0; in[2].auto_connect = 1;

	ATF_REQUIRE_EQ(3, blued_devtable_apply(&t, in, 3));

	n = blued_devtable_autoconnect(&t, out, 8);
	ATF_CHECK_EQ(1, n);
	ATF_CHECK_EQ(0, memcmp(out[0].addr, "\x01\x00\x00\x00\x00\x01", 6));

	/* The output is bounded by the caller's array size. */
	ATF_CHECK_EQ(0, blued_devtable_autoconnect(&t, out, 0));
}

/* ================================================================
 * PC10: resolving-list shadow add/remove idempotent + bounded.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(pc10_reslist_add_remove_idempotent);
ATF_TC_BODY(pc10_reslist_add_remove_idempotent, tc)
{
	struct blued_reslist rl, other;
	const uint8_t a[6] = { 1, 2, 3, 4, 5, 6 };
	const uint8_t b[6] = { 9, 9, 9, 9, 9, 9 };

	memset(&rl, 0, sizeof(rl));
	memset(&other, 0, sizeof(other));

	/* New bond with an IRK: add returns 1 (caller issues the HCI add). */
	ATF_CHECK_EQ(1, blued_reslist_add(&rl, a, 1));
	ATF_CHECK(blued_reslist_contains(&rl, a, 1));
	ATF_CHECK_EQ(1, rl.count);

	/* Each controller mirror independently requires the same HCI add/remove. */
	ATF_CHECK_EQ(1, blued_reslist_add(&other, a, 1));
	ATF_CHECK_EQ(1, other.count);

	/* Re-adding the same peer is idempotent (no duplicate HCI add). */
	ATF_CHECK_EQ(0, blued_reslist_add(&rl, a, 1));
	ATF_CHECK_EQ(1, rl.count);

	/* Different address type is a distinct identity. */
	ATF_CHECK_EQ(1, blued_reslist_add(&rl, a, 0));
	ATF_CHECK_EQ(2, rl.count);

	/* Unbond: remove returns 1 the first time, 0 (idempotent) after. */
	ATF_CHECK_EQ(1, blued_reslist_remove(&rl, a, 1));
	ATF_CHECK(!blued_reslist_contains(&rl, a, 1));
	ATF_CHECK(blued_reslist_contains(&other, a, 1));
	ATF_CHECK_EQ(1, blued_reslist_remove(&other, a, 1));
	ATF_CHECK_EQ(0, blued_reslist_remove(&rl, a, 1));

	/* Removing an absent peer is a no-op. */
	ATF_CHECK_EQ(0, blued_reslist_remove(&rl, b, 1));
}

ATF_TC_WITHOUT_HEAD(pc10_reslist_is_bounded_to_controller_depth);
ATF_TC_BODY(pc10_reslist_is_bounded_to_controller_depth, tc)
{
	struct blued_reslist rl;
	uint8_t addr[6];
	int i;

	memset(&rl, 0, sizeof(rl));
	memset(addr, 0, sizeof(addr));

	/* Fill to capacity: every add is accepted. */
	for (i = 0; i < BLUED_RESLIST_MAX; i++) {
		addr[5] = (uint8_t)i;
		ATF_CHECK_EQ(1, blued_reslist_add(&rl, addr, 0));
	}
	ATF_CHECK_EQ(BLUED_RESLIST_MAX, rl.count);

	/* One past capacity is refused (bounded, no overflow). */
	addr[5] = (uint8_t)BLUED_RESLIST_MAX;
	ATF_CHECK_EQ(0, blued_reslist_add(&rl, addr, 0));
	ATF_CHECK_EQ(BLUED_RESLIST_MAX, rl.count);

	/* After freeing a slot a new peer fits again. */
	addr[5] = 0;
	ATF_CHECK_EQ(1, blued_reslist_remove(&rl, addr, 0));
	addr[5] = (uint8_t)BLUED_RESLIST_MAX;
	ATF_CHECK_EQ(1, blued_reslist_add(&rl, addr, 0));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, pc8_devcache_apply_populates_live_table);
	ATF_TP_ADD_TC(tp, pc8_devcache_apply_is_idempotent_and_guarded);
	ATF_TP_ADD_TC(tp, pc8_devcache_apply_clamps_to_capacity);
	ATF_TP_ADD_TC(tp, pc8_gattcache_reuse_follows_db_hash);
	ATF_TP_ADD_TC(tp, pc6_backoff_is_bounded);
	ATF_TP_ADD_TC(tp, pc6_retry_budget_is_bounded);
	ATF_TP_ADD_TC(tp, pc6_autoconnect_candidate_selection);
	ATF_TP_ADD_TC(tp, pc10_reslist_add_remove_idempotent);
	ATF_TP_ADD_TC(tp, pc10_reslist_is_bounded_to_controller_depth);

	return (atf_no_error());
}
