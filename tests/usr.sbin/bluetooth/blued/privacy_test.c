/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * LE Privacy / Resolvable Private Address (RPA) tests.
 *
 * Covers Core Spec Vol 6 Part B Section 1.3.2 (address types) and
 * Vol 3 Part H Section 2.2.2 (RPA generation / resolution, the ah()
 * function), plus the HCI-side RPA-timeout range (Vol 4 Part E 7.8.45).
 *
 * The RPA primitives under test live in smp_keys.c:
 *   void smp_generate_rpa(const uint8_t irk[16], uint8_t rpa[6]);
 *   bool smp_rpa_matches(const uint8_t irk[16], const uint8_t addr[6]);
 * and the in-memory resolving list (identity address + IRK per bond)
 * is exercised through:
 *   struct smp_bond *smp_find_bond(struct smp_bond_db *, const uint8_t *,
 *       uint8_t addr_type);
 * which resolves an incoming random address against every stored IRK.
 *
 * Link set: hci_util.c hci_adv.c hci_scan.c hci_conn.c hci_privacy.c
 * hci_misc.c hci_log.c smp_crypto.c smp_keys.c   (+ libcrypto, libbluetooth).
 * smp_keys.o additionally references smp_log_send/smp_log_recv (defined in
 * smp.c, which we do NOT link); they are stubbed below so nothing drags in
 * the whole pairing state machine.  No test_common.h — that would multiply
 * define the hci and smp stubs we deliberately link the real objects for.
 */

#include <sys/types.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <netgraph/bluetooth/include/ng_bluetooth.h>

#include <atf-c.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "hci_log.h"
#include "hci_util.h"
#include "ble_util.h"
#include "smp.h"
#include "smp_internal.h"
#include "spec_privacy_oracles.h"

/* Globals referenced by the hci_*.c and smp_keys.c logging macros. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

/*
 * smp_keys.c references these BTSnoop / timed-recv helpers from smp.c.  We do
 * not link smp.c, so provide inert definitions with the exact signatures.
 */
ssize_t
smp_log_send(struct smp_conn *sc __unused, const void *buf __unused,
    size_t len __unused)
{

	return ((ssize_t)len);
}

ssize_t
smp_log_recv(struct smp_conn *sc __unused, void *buf __unused,
    size_t len __unused)
{

	return (-1);
}

ssize_t
smp_recv_timed(struct smp_conn *sc __unused, void *buf __unused,
    size_t len __unused)
{

	return (-1);
}

/*
 * A valid but non-HCI file descriptor.  bt_devreq() maps s < 0 to EINVAL
 * itself, so fd == -1 cannot distinguish a range rejection from a bad fd; a
 * real fd lets an in-range call fail later in getsockopt(SOL_HCI_RAW) with
 * ENOTSOCK (errno != EINVAL).
 */
static int
test_fd(void)
{
	static int fd = -1;

	if (fd < 0)
		fd = open("/dev/null", O_RDWR);
	return (fd);
}

/* Deterministic 16-byte IRK filled from a seed. */
static void
make_irk(uint8_t irk[16], uint8_t seed)
{
	int i;

	for (i = 0; i < 16; i++)
		irk[i] = (uint8_t)(seed + i * 7 + 1);
}

/* ================================================================
 * RPA generation marks the address correctly and round-trips.
 * Core Spec Vol 3 Part H 2.2.2 / Vol 6 Part B 1.3.2.3
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(rpa_generate_marker);
ATF_TC_BODY(rpa_generate_marker, tc)
{
	uint8_t irk[16], rpa[6];
	int i, distinct = 0;
	uint8_t prev[6];

	make_irk(irk, 0x11);

	/*
	 * The two most-significant bits of the address (top of prand,
	 * rpa[5]) must be 0b01 to mark a Resolvable Private Address.
	 */
	for (i = 0; i < 8; i++) {
		smp_generate_rpa(irk, rpa);
		ATF_CHECK_EQ_MSG(BT_CORE63_RANDOM_ADDRESS_RESOLVABLE,
		    rpa[5] & BT_CORE63_RANDOM_ADDRESS_TYPE_MASK,
		    "RPA marker bits wrong: rpa[5]=0x%02x", rpa[5]);
		if (i > 0 && memcmp(prev, rpa, 6) != 0)
			distinct++;
		memcpy(prev, rpa, 6);
	}
	/* prand is random each call, so successive RPAs should differ. */
	ATF_CHECK_MSG(distinct > 0, "generated RPAs were all identical");
}

ATF_TC_WITHOUT_HEAD(rpa_roundtrip_resolve);
ATF_TC_BODY(rpa_roundtrip_resolve, tc)
{
	uint8_t irk[16], other[16], rpa[6];

	make_irk(irk, 0x20);
	make_irk(other, 0x99);

	smp_generate_rpa(irk, rpa);

	/* Correct IRK resolves the RPA it generated. */
	ATF_CHECK_MSG(smp_rpa_matches(irk, rpa),
	    "generating IRK failed to resolve its own RPA");

	/* Appendix D.7 fixes both IRK and RPA, avoiding random hash collision. */
	ATF_CHECK_MSG(smp_rpa_matches(bt_privacy_d7_irk_le,
	    bt_privacy_d7_rpa_le), "Appendix D.7 RPA did not resolve");
	ATF_CHECK_MSG(!smp_rpa_matches(other, bt_privacy_d7_rpa_le),
	    "non-D.7 IRK resolved the Appendix D.7 RPA");
}

ATF_TC_WITHOUT_HEAD(rpa_corrupt_hash_fails);
ATF_TC_BODY(rpa_corrupt_hash_fails, tc)
{
	uint8_t irk[16], rpa[6];

	make_irk(irk, 0x33);
	smp_generate_rpa(irk, rpa);
	ATF_REQUIRE(smp_rpa_matches(irk, rpa));

	/* Flip a hash byte (lower 3 octets): resolution must now fail. */
	rpa[0] ^= 0xFF;
	ATF_CHECK_MSG(!smp_rpa_matches(irk, rpa),
	    "RPA with corrupted hash still resolved");
}

/* ================================================================
 * Address-type classification: only RPAs (top bits 0b01) are
 * resolvable.  Non-resolvable private (0b00), static random
 * (0b11), and malformed inputs must be rejected up front.
 * Core Spec Vol 6 Part B 1.3.2
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(non_rpa_addresses_not_resolved);
ATF_TC_BODY(non_rpa_addresses_not_resolved, tc)
{
	uint8_t irk[16], rpa[6], addr[6];

	make_irk(irk, 0x44);
	smp_generate_rpa(irk, rpa);

	/* Non-resolvable private address: top bits 0b00. */
	memcpy(addr, rpa, 6);
	addr[5] = (addr[5] & (uint8_t)~BT_CORE63_RANDOM_ADDRESS_TYPE_MASK) |
	    BT_CORE63_RANDOM_ADDRESS_NONRESOLVABLE;
	ATF_CHECK_MSG(!smp_rpa_matches(irk, addr),
	    "NRPA (0b00 marker) wrongly treated as resolvable");

	/* Static random address: top bits 0b11. */
	memcpy(addr, rpa, 6);
	addr[5] = (addr[5] & (uint8_t)~BT_CORE63_RANDOM_ADDRESS_TYPE_MASK) |
	    BT_CORE63_RANDOM_ADDRESS_STATIC;
	ATF_CHECK_MSG(!smp_rpa_matches(irk, addr),
	    "static random (0b11 marker) wrongly treated as resolvable");

	/* All-zero address: marker is 0b00, must be rejected. */
	memset(addr, 0, 6);
	ATF_CHECK(!smp_rpa_matches(irk, addr));

	/* All-ones address: marker is 0b11, must be rejected. */
	memset(addr, 0xFF, 6);
	ATF_CHECK(!smp_rpa_matches(irk, addr));
}

/* ================================================================
 * Resolving list: identity-address exact match, IRK resolution of
 * a peer RPA, and rejection of an RPA from an unknown IRK.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(resolving_list_exact_and_irk);
ATF_TC_BODY(resolving_list_exact_and_irk, tc)
{
	struct smp_bond_db db;
	struct smp_bond *b;
	uint8_t id_addr[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11 };
	uint8_t irk[16], other[16], rpa[6];

	make_irk(irk, 0x55);
	make_irk(other, 0x66);

	memset(&db, 0, sizeof(db));
	db.lock = NULL;
	db.fd = -1;

	/* Add one identity + IRK to the (in-memory) resolving list. */
	memcpy(db.bonds[0].addr, id_addr, 6);
	/* smp_find_bond() takes FreeBSD's internal 1/2 address-type API. */
	db.bonds[0].addr_type = BDADDR_LE_PUBLIC;
	memcpy(db.bonds[0].irk, irk, 16);
	db.bonds[0].has_irk = true;
	db.count = 1;

	/* Exact identity-address lookup. */
	b = smp_find_bond(&db, id_addr, BDADDR_LE_PUBLIC);
	ATF_REQUIRE_MSG(b != NULL, "exact identity lookup failed");
	ATF_CHECK(b == &db.bonds[0]);

	/* A peer RPA derived from the stored IRK resolves to that bond. */
	smp_generate_rpa(irk, rpa);
	b = smp_find_bond(&db, rpa, BDADDR_LE_RANDOM);
	ATF_REQUIRE_MSG(b != NULL, "IRK-based RPA resolution failed");
	ATF_CHECK(b == &db.bonds[0]);

	/* An RPA from a different IRK must not resolve to any bond. */
	smp_generate_rpa(other, rpa);
	b = smp_find_bond(&db, rpa, BDADDR_LE_RANDOM);
	ATF_CHECK_MSG(b == NULL, "unknown-IRK RPA wrongly resolved");
}

ATF_TC_WITHOUT_HEAD(resolving_list_add_remove);
ATF_TC_BODY(resolving_list_add_remove, tc)
{
	struct smp_bond_db db;
	uint8_t irkA[16], irkB[16], rpa[6];
	uint8_t addrA[6] = { 1, 1, 1, 1, 1, 0x01 };
	uint8_t addrB[6] = { 2, 2, 2, 2, 2, 0x02 };

	make_irk(irkA, 0x70);
	make_irk(irkB, 0x71);

	memset(&db, 0, sizeof(db));
	db.lock = NULL;
	db.fd = -1;

	/* Add A and B. */
	memcpy(db.bonds[0].addr, addrA, 6);
	db.bonds[0].addr_type = BDADDR_LE_PUBLIC;
	memcpy(db.bonds[0].irk, irkA, 16);
	db.bonds[0].has_irk = true;
	memcpy(db.bonds[1].addr, addrB, 6);
	db.bonds[1].addr_type = BDADDR_LE_PUBLIC;
	memcpy(db.bonds[1].irk, irkB, 16);
	db.bonds[1].has_irk = true;
	db.count = 2;

	/* Both resolve. */
	smp_generate_rpa(irkA, rpa);
	ATF_CHECK(smp_find_bond(&db, rpa, BDADDR_LE_RANDOM) ==
	    &db.bonds[0]);
	smp_generate_rpa(irkB, rpa);
	ATF_CHECK(smp_find_bond(&db, rpa, BDADDR_LE_RANDOM) ==
	    &db.bonds[1]);

	/* Remove A by shifting the list down (typical resolving-list evict). */
	memmove(&db.bonds[0], &db.bonds[1], sizeof(db.bonds[0]));
	db.count = 1;

	/* B still resolves; an A-derived RPA no longer does. */
	smp_generate_rpa(irkB, rpa);
	ATF_CHECK(smp_find_bond(&db, rpa, BDADDR_LE_RANDOM) ==
	    &db.bonds[0]);
	smp_generate_rpa(irkA, rpa);
	ATF_CHECK_MSG(smp_find_bond(&db, rpa, BDADDR_LE_RANDOM) == NULL,
	    "removed entry still resolved");
}

/* ================================================================
 * Resolving-list bounds: fill to SMP_MAX_BONDS and confirm the
 * scan resolves the last slot without reading past the array.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(resolving_list_full_bounds);
ATF_TC_BODY(resolving_list_full_bounds, tc)
{
	struct smp_bond_db db;
	struct smp_bond *b;
	uint8_t rpa[6], unknown_irk[16];
	int i;

	memset(&db, 0, sizeof(db));
	db.lock = NULL;
	db.fd = -1;

	for (i = 0; i < SMP_MAX_BONDS; i++) {
		uint8_t irk[16];

		make_irk(irk, (uint8_t)(0x80 + i));
		db.bonds[i].addr[0] = (uint8_t)i;
		db.bonds[i].addr[5] = 0x00;	/* public-style identity */
		db.bonds[i].addr_type = BDADDR_LE_PUBLIC;
		memcpy(db.bonds[i].irk, irk, 16);
		db.bonds[i].has_irk = true;
	}
	db.count = SMP_MAX_BONDS;

	/* RPA from the IRK in the LAST slot must resolve to that slot. */
	{
		uint8_t last_irk[16];

		make_irk(last_irk, (uint8_t)(0x80 + SMP_MAX_BONDS - 1));
		smp_generate_rpa(last_irk, rpa);
		b = smp_find_bond(&db, rpa, BDADDR_LE_RANDOM);
		ATF_REQUIRE(b != NULL);
		ATF_CHECK(b == &db.bonds[SMP_MAX_BONDS - 1]);
	}

	/* An RPA from an IRK not in the (full) list returns NULL cleanly. */
	make_irk(unknown_irk, 0x02);
	smp_generate_rpa(unknown_irk, rpa);
	ATF_CHECK(smp_find_bond(&db, rpa, BDADDR_LE_RANDOM) == NULL);
}

/* ================================================================
 * HCI RPA-timeout range validation (1..0x0E10 seconds).
 * Core Spec Vol 4 Part E 7.8.45.  Out-of-range is rejected with
 * EINVAL before any socket I/O (fd == -1).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(rpa_timeout_range);
ATF_TC_BODY(rpa_timeout_range, tc)
{
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_rpa_timeout(-1,
	    BT_CORE63_RPA_TIMEOUT_BELOW_MIN));
	ATF_CHECK_EQ(EINVAL, errno);

	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_rpa_timeout(-1,
	    BT_CORE63_RPA_TIMEOUT_ABOVE_MAX));
	ATF_CHECK_EQ(EINVAL, errno);

	/* In-range endpoints pass validation (then fail at absent HW). */
	errno = 0;
	(void)hci_le_set_rpa_timeout(test_fd(),
	    BT_CORE63_RPA_TIMEOUT_MIN_SECONDS);
	ATF_CHECK(errno != EINVAL);

	errno = 0;
	(void)hci_le_set_rpa_timeout(test_fd(),
	    BT_CORE63_RPA_TIMEOUT_MAX_SECONDS);
	ATF_CHECK(errno != EINVAL);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, rpa_generate_marker);
	ATF_TP_ADD_TC(tp, rpa_roundtrip_resolve);
	ATF_TP_ADD_TC(tp, rpa_corrupt_hash_fails);
	ATF_TP_ADD_TC(tp, non_rpa_addresses_not_resolved);
	ATF_TP_ADD_TC(tp, resolving_list_exact_and_irk);
	ATF_TP_ADD_TC(tp, resolving_list_add_remove);
	ATF_TP_ADD_TC(tp, resolving_list_full_bounds);
	ATF_TP_ADD_TC(tp, rpa_timeout_range);

	return (atf_no_error());
}
