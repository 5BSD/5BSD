/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF edge-case tests for the SMP key-distribution, bonding, privacy (RPA),
 * cross-transport key derivation (CTKD) and bond-database persistence code
 * in smp_keys.c.
 *
 * These exercise branches that the happy-path pairing tests do not reach:
 * key-distribution bit combinations, bond lookup (exact + IRK/RPA resolved
 * + miss), CTKD gating (legacy / no-MITM / CT2 vs non-CT2), RPA generation
 * and resolution against the Core Spec test vector, CCCD save/restore, and
 * the bond-DB save/load round-trip plus its malformed-file rejection paths.
 *
 * Oracle: values are taken from the Core Spec (Vol 3 Part H) and hand
 * derived, cited per assertion.  Notably the RPA/ah check uses the D.7
 * "ah random address hash functions" sample data.
 *
 * Most functions here are called directly (no mock peer).  Where a socket
 * is needed (smp_receive_peer_keys / smp_distribute_init_keys), a
 * SOCK_SEQPACKET socketpair mocks the L2CAP SMP channel; PDUs are exchanged
 * one datagram at a time because AF_UNIX SEQPACKET coalesces queued sends on
 * this platform.
 *
 * Links with: smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
 * Extra libs: -lcrypto (OpenSSL) -lpthread (bond_db lock type)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "att.h"
#include "att_server.h"
#include "hci_log.h"
#include "hci_util.h"
#include "smp.h"
#include "smp_internal.h"
#include "spec_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif
#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
#endif

/*
 * Independent daemon storage-contract values.  These are intentionally not
 * derived from smp.h: changing the public bounded-storage contract must make
 * the tests fail until the expected migration/policy is reviewed.
 */
#define TEST_IMPL_BOND_CAPACITY	32
#define TEST_IMPL_CCCD_CAPACITY	16
#define TEST_IMPL_ATT_CCCD_CAPACITY	32
#define TEST_IMPL_REPORT_CAPACITY	16
#define TEST_IMPL_BOND_MAGIC	"BONDE"
#define TEST_IMPL_BOND_MAGIC_LEN	5
#define TEST_IMPL_BOND_V4	4
#define TEST_IMPL_BOND_V5	5
#define TEST_IMPL_BOND_SALT_LEN	16
#define TEST_IMPL_BOND_IV_LEN	12
#define TEST_IMPL_BOND_TAG_LEN	16
#define TEST_IMPL_BOND_REC_MAGIC	"BREC"
#define TEST_IMPL_BOND_REC_MAGIC_LEN	4
#define TEST_IMPL_BOND_REC_VERSION	1
#define TEST_IMPL_BOND_REC_HEADER_LEN	12

/* ================================================================
 * Stubs for external symbols referenced by smp.c (hci_util.c).
 * ================================================================ */
int
hci_send_raw_cmd(int hci_fd __unused, uint16_t opcode __unused,
    const void *params __unused, uint8_t plen __unused)
{

	return (0);
}

int
hci_wait_encryption(int hci_fd __unused, uint16_t con_handle __unused,
    int timeout_sec __unused)
{

	return (0);
}

int
hci_le_ltk_request_reply(int hci_fd __unused, uint16_t con_handle __unused,
    const uint8_t ltk[16] __unused)
{

	return (0);
}

int
hci_le_ltk_request_neg_reply(int hci_fd __unused, uint16_t con_handle __unused)
{

	return (0);
}

/* ================================================================
 * Core Spec Vol 3 Part H, D.7 "ah random address hash functions".
 *
 *   IRK   = ec0234a3 57c8ad05 341010a6 0a397d9b   (MSB-first)
 *   prand = 0x708194                              (24-bit)
 *   ah    = 0x0dfbaa
 *
 * The implementation stores keys and addresses little-endian (byte[0] =
 * LSB), so the IRK is the MSB-first spec value reversed, prand's LSB (0x94)
 * lands at addr[3], and the ah output (0x0dfbaa, LSB-first aa fb 0d) lands
 * at addr[0..2].  addr[5] = 0x70 has its top two bits = 01, i.e. it is a
 * well-formed RPA marker.
 *
 * RPA layout in this code base (smp_generate_rpa): rpa[0..2] = hash(ah),
 * rpa[3..5] = prand.
 * ================================================================ */
static uint8_t spec_irk_le[16];
static uint8_t spec_rpa[6];

static void
core_hex_le(uint8_t *out, const char *hex, size_t len)
{
	size_t i;
	unsigned int byte;

	for (i = 0; i < len; i++) {
		ATF_REQUIRE_EQ(1, sscanf(hex + 2 * i, "%02x", &byte));
		out[len - 1 - i] = (uint8_t)byte;
	}
}

/* Load the generated Core 6.3 Vol 3 Part H Appendix D.7 sample. */
static void
load_core_d7(void)
{
	uint8_t prand[16], ah[3];

	core_hex_le(spec_irk_le, BT_CORE63_SMP_D7_IRK_HEX,
	    sizeof(spec_irk_le));
	core_hex_le(prand, BT_CORE63_SMP_D7_PRAND_HEX, sizeof(prand));
	core_hex_le(ah, BT_CORE63_SMP_D7_AH_HEX, sizeof(ah));
	memcpy(spec_rpa, ah, sizeof(ah));
	memcpy(spec_rpa + sizeof(ah), prand, 3);
}

static const uint8_t addr_a[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
static const uint8_t addr_b[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x0F };

static uint8_t rpa_random_values[16][3];
static unsigned int rpa_random_count;
static unsigned int rpa_random_next;

static int
rpa_random_sequence(uint8_t *buf, size_t len)
{

	if (len != 3 || rpa_random_next >= rpa_random_count) {
		errno = EIO;
		return (-1);
	}
	memcpy(buf, rpa_random_values[rpa_random_next++], 3);
	return (0);
}

/* ================================================================
 * CTKD gating (smp_ctkd_derive_link_key).
 * Core Spec Vol 3 Part H Section 2.4.2.4.
 * ================================================================ */

/* Legacy bond (is_sc = false): CTKD is only defined for SC LTKs -> -1. */
ATF_TC_WITHOUT_HEAD(test_ctkd_not_sc);
ATF_TC_BODY(test_ctkd_not_sc, tc)
{
	struct smp_bond b;

	memset(&b, 0, sizeof(b));
	b.is_sc = false;
	b.has_ltk = true;
	b.is_mitm = true;

	ATF_CHECK_EQ_MSG(smp_ctkd_derive_link_key(&b, true), -1,
	    "CTKD must reject non-SC bond");
	ATF_CHECK(!b.has_link_key);
}

/* SC bond but no LTK present -> -1 (nothing to derive from). */
ATF_TC_WITHOUT_HEAD(test_ctkd_no_ltk);
ATF_TC_BODY(test_ctkd_no_ltk, tc)
{
	struct smp_bond b;

	memset(&b, 0, sizeof(b));
	b.is_sc = true;
	b.has_ltk = false;
	b.is_mitm = true;

	ATF_CHECK_EQ(smp_ctkd_derive_link_key(&b, false), -1);
	ATF_CHECK(!b.has_link_key);
}

/*
 * SC + LTK but Just Works (is_mitm = false): CTKD shall NOT produce a
 * cross-transport key from an unauthenticated LE link.  Returns 0 (success,
 * no-op) and leaves has_link_key clear.
 */
ATF_TC_WITHOUT_HEAD(test_ctkd_not_mitm);
ATF_TC_BODY(test_ctkd_not_mitm, tc)
{
	struct smp_bond b;

	memset(&b, 0, sizeof(b));
	b.is_sc = true;
	b.has_ltk = true;
	b.is_mitm = false;
	memset(b.ltk, 0x42, 16);

	ATF_CHECK_EQ_MSG(smp_ctkd_derive_link_key(&b, true), 0,
	    "CTKD on non-MITM bond returns success but does nothing");
	ATF_CHECK_MSG(!b.has_link_key,
	    "unauthenticated LE link must not yield a BR/EDR link key");
}

/*
 * SC + LTK + MITM: CTKD derives a link key.  The CT2=1 path uses h7(SALT,LTK)
 * and the CT2=0 path uses h6(LTK,"tmp1"); the two produce different
 * intermediate keys and therefore different link keys (spec 2.4.2.4).
 */
ATF_TC_WITHOUT_HEAD(test_ctkd_ct2_vs_legacy_differ);
ATF_TC_BODY(test_ctkd_ct2_vs_legacy_differ, tc)
{
	struct smp_bond b_ct2, b_h6;
	uint8_t expected_ct2[16], expected_h6[16];

	memset(&b_ct2, 0, sizeof(b_ct2));
	b_ct2.is_sc = b_ct2.has_ltk = b_ct2.is_mitm = true;
	/* Core Appendix D.9/D.10 deliberately use the same LTK. */
	core_hex_le(b_ct2.ltk, BT_CORE63_SMP_D9_LTK_HEX,
	    sizeof(b_ct2.ltk));
	core_hex_le(expected_ct2, BT_CORE63_SMP_D9_LINK_KEY_HEX,
	    sizeof(expected_ct2));
	core_hex_le(expected_h6, BT_CORE63_SMP_D10_LINK_KEY_HEX,
	    sizeof(expected_h6));
	b_h6 = b_ct2;

	ATF_CHECK_EQ(smp_ctkd_derive_link_key(&b_ct2, true), 0);
	ATF_CHECK_EQ(smp_ctkd_derive_link_key(&b_h6, false), 0);
	ATF_CHECK(b_ct2.has_link_key);
	ATF_CHECK(b_h6.has_link_key);
	ATF_CHECK_MSG(memcmp(b_ct2.link_key, expected_ct2, 16) == 0,
	    "CT2=1 must match the generated Appendix D.9 h7 link key");
	ATF_CHECK_MSG(memcmp(b_h6.link_key, expected_h6, 16) == 0,
	    "CT2=0 must match the generated Appendix D.10 h6 link key");
}

/* ================================================================
 * RPA resolution and generation (smp_rpa_matches / smp_generate_rpa).
 * Core Spec Vol 3 Part H Section 2.2.2, test vector D.7.
 * ================================================================ */

/* The D.7 sample IRK resolves its sample RPA. */
ATF_TC_WITHOUT_HEAD(test_rpa_matches_spec_vector);
ATF_TC_BODY(test_rpa_matches_spec_vector, tc)
{

	load_core_d7();
	ATF_CHECK_MSG(smp_rpa_matches(spec_irk_le, spec_rpa),
	    "D.7 IRK must resolve its sample RPA (ah=0x0dfbaa)");
}

/* A non-resolvable / static address (top two bits of MSB != 01) is rejected
 * outright without any IRK computation. */
ATF_TC_WITHOUT_HEAD(test_rpa_matches_non_rpa);
ATF_TC_BODY(test_rpa_matches_non_rpa, tc)
{
	uint8_t static_addr[6];

	load_core_d7();
	memcpy(static_addr, spec_rpa, 6);
	static_addr[5] = BT_CORE63_RANDOM_ADDRESS_STATIC;
	ATF_CHECK(!smp_rpa_matches(spec_irk_le, static_addr));

	static_addr[5] = BT_CORE63_RANDOM_ADDRESS_NONRESOLVABLE;
	ATF_CHECK(!smp_rpa_matches(spec_irk_le, static_addr));
}

/* A well-formed RPA that was generated from a different IRK does not match. */
ATF_TC_WITHOUT_HEAD(test_rpa_matches_wrong_irk);
ATF_TC_BODY(test_rpa_matches_wrong_irk, tc)
{
	uint8_t other_irk[16];

	load_core_d7();
	memset(other_irk, 0x55, sizeof(other_irk));
	ATF_CHECK_MSG(!smp_rpa_matches(other_irk, spec_rpa),
	    "wrong IRK must not resolve the D.7 RPA");
}

/* smp_generate_rpa produces a marker-correct RPA that its own IRK resolves,
 * and that a different IRK does not. */
ATF_TC_WITHOUT_HEAD(test_generate_rpa_roundtrip);
ATF_TC_BODY(test_generate_rpa_roundtrip, tc)
{
	uint8_t irk[16], other[16], rpa[6], rpa2[6];

	memset(irk, 0x3C, sizeof(irk));
	memset(other, 0xA5, sizeof(other));
	memset(rpa_random_values, 0, sizeof(rpa_random_values));
	/*
	 * Vol 6 Part B §1.3.2.2: two deterministic, non-forbidden 22-bit
	 * prand samples.  The generator must replace their top two bits with
	 * the generated resolvable-private subtype 01.
	 */
	rpa_random_values[0][0] = 0x34;
	rpa_random_values[0][1] = 0x12;
	rpa_random_values[0][2] = 0x85;
	rpa_random_values[1][0] = 0x78;
	rpa_random_values[1][1] = 0x56;
	rpa_random_values[1][2] = 0xaa;
	rpa_random_count = 2;
	rpa_random_next = 0;
	smp_rpa_random_hook = rpa_random_sequence;

	ATF_REQUIRE_EQ(smp_generate_rpa(irk, rpa), 0);

	/* MSB top two bits must be 01 (Core Spec 2.2.2 RPA marker). */
	ATF_CHECK_EQ_MSG((rpa[5] & BT_CORE63_RANDOM_ADDRESS_TYPE_MASK),
	    BT_CORE63_RANDOM_ADDRESS_RESOLVABLE,
	    "generated RPA MSB top bits must be 01");
	ATF_CHECK_MSG(smp_rpa_matches(irk, rpa),
	    "generated RPA must resolve against its own IRK");
	ATF_CHECK_MSG(!smp_rpa_matches(other, rpa),
	    "generated RPA must not resolve against a different IRK");

	ATF_REQUIRE_EQ(smp_generate_rpa(irk, rpa2), 0);
	smp_rpa_random_hook = NULL;
	ATF_CHECK_EQ(rpa_random_next, 2);
	ATF_CHECK_EQ(memcmp(rpa + 3, rpa_random_values[0], 2), 0);
	ATF_CHECK_EQ(rpa[5],
	    (rpa_random_values[0][2] &
	    ~BT_CORE63_RANDOM_ADDRESS_TYPE_MASK) |
	    BT_CORE63_RANDOM_ADDRESS_RESOLVABLE);
	ATF_CHECK_EQ(memcmp(rpa2 + 3, rpa_random_values[1], 2), 0);
	ATF_CHECK_EQ(rpa2[5],
	    (rpa_random_values[1][2] &
	    ~BT_CORE63_RANDOM_ADDRESS_TYPE_MASK) |
	    BT_CORE63_RANDOM_ADDRESS_RESOLVABLE);
	ATF_CHECK_MSG(memcmp(rpa, rpa2, sizeof(rpa)) != 0,
	    "distinct independent prand samples must produce distinct RPAs");
}

/*
 * Vol 6 Part B Section 1.3.2.2 forbids an RPA prand whose 22 random bits
 * are all zero or all one.  Feed both forbidden values followed by a valid
 * value and verify generation retries rather than emitting either one.
 */
ATF_TC_WITHOUT_HEAD(test_generate_rpa_retries_forbidden_prand);
ATF_TC_BODY(test_generate_rpa_retries_forbidden_prand, tc)
{
	uint8_t irk[16], rpa[6];

	memset(irk, 0x3c, sizeof(irk));
	memset(rpa_random_values, 0, sizeof(rpa_random_values));
	/* First candidate: all 22 random bits zero. */
	rpa_random_values[0][0] = 0x00;
	rpa_random_values[0][1] = 0x00;
	rpa_random_values[0][2] = 0x00;
	/* Second candidate: all 22 random bits one (top two bits are ignored). */
	rpa_random_values[1][0] = 0xff;
	rpa_random_values[1][1] = 0xff;
	rpa_random_values[1][2] = 0xff;
	/* Third candidate has both zero and one bits in its random portion. */
	rpa_random_values[2][0] = 0x34;
	rpa_random_values[2][1] = 0x12;
	rpa_random_values[2][2] = 0x85;
	rpa_random_count = 3;
	rpa_random_next = 0;
	smp_rpa_random_hook = rpa_random_sequence;

	ATF_REQUIRE_EQ(smp_generate_rpa(irk, rpa), 0);
	smp_rpa_random_hook = NULL;
	ATF_CHECK_EQ_MSG(rpa_random_next, 3,
	    "both forbidden prand candidates must be rejected");
	ATF_CHECK_EQ(rpa[3], 0x34);
	ATF_CHECK_EQ(rpa[4], 0x12);
	ATF_CHECK_EQ(rpa[5],
	    (rpa_random_values[2][2] &
	    ~BT_CORE63_RANDOM_ADDRESS_TYPE_MASK) |
	    BT_CORE63_RANDOM_ADDRESS_RESOLVABLE);
	ATF_CHECK(smp_rpa_matches(irk, rpa));
}

/* A persistently broken entropy source must fail without changing output. */
ATF_TC_WITHOUT_HEAD(test_generate_rpa_forbidden_prand_bound);
ATF_TC_BODY(test_generate_rpa_forbidden_prand_bound, tc)
{
	uint8_t irk[16], rpa[6], before[6];

	memset(irk, 0x3c, sizeof(irk));
	memset(rpa, 0xa5, sizeof(rpa));
	memcpy(before, rpa, sizeof(before));
	memset(rpa_random_values, 0, sizeof(rpa_random_values));
	rpa_random_count = (unsigned int)(sizeof(rpa_random_values) /
	    sizeof(rpa_random_values[0]));
	rpa_random_next = 0;
	smp_rpa_random_hook = rpa_random_sequence;
	errno = 0;

	ATF_CHECK_EQ(smp_generate_rpa(irk, rpa), -1);
	smp_rpa_random_hook = NULL;
	ATF_CHECK_EQ(errno, EAGAIN);
	ATF_CHECK_EQ(rpa_random_next, rpa_random_count);
	ATF_CHECK_EQ(memcmp(rpa, before, sizeof(rpa)), 0);
}

/* ================================================================
 * Bond lookup (smp_find_bond): exact / miss / IRK-resolved.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_find_bond_exact_and_miss);
ATF_TC_BODY(test_find_bond_exact_and_miss, tc)
{
	struct smp_bond_db db;
	struct smp_bond *hit;
	uint8_t wrong[6];

	memset(&db, 0, sizeof(db));
	db.fd = -1;
	db.count = 2;
	memcpy(db.bonds[0].addr, addr_a, 6);
	db.bonds[0].addr_type = BDADDR_LE_PUBLIC;
	memcpy(db.bonds[1].addr, addr_b, 6);
	db.bonds[1].addr_type = BDADDR_LE_PUBLIC;

	hit = smp_find_bond(&db, addr_b, BDADDR_LE_PUBLIC);
	ATF_REQUIRE_MSG(hit != NULL, "exact match must be found");
	ATF_CHECK(memcmp(hit->addr, addr_b, 6) == 0);

	/* Right address, wrong type -> miss. */
	ATF_CHECK_EQ(smp_find_bond(&db, addr_a, BDADDR_LE_RANDOM), NULL);

	/* Unknown address -> miss. */
	memset(wrong, 0x77, sizeof(wrong));
	ATF_CHECK_EQ(smp_find_bond(&db, wrong, BDADDR_LE_PUBLIC), NULL);
}

/* A random (RPA) address is resolved to a bonded device by its stored IRK. */
ATF_TC_WITHOUT_HEAD(test_find_bond_rpa_resolved);
ATF_TC_BODY(test_find_bond_rpa_resolved, tc)
{
	struct smp_bond_db db;
	struct smp_bond *hit;
	uint8_t nomatch[6];

	load_core_d7();
	memset(&db, 0, sizeof(db));
	db.fd = -1;
	db.count = 1;
	/* Stored identity address is public; the connection uses an RPA. */
	memcpy(db.bonds[0].addr, addr_a, 6);
	db.bonds[0].addr_type = BDADDR_LE_PUBLIC;
	memcpy(db.bonds[0].irk, spec_irk_le, 16);
	db.bonds[0].has_irk = true;

	hit = smp_find_bond(&db, spec_rpa, BDADDR_LE_RANDOM);
	ATF_REQUIRE_MSG(hit != NULL, "RPA must resolve via stored IRK");
	ATF_CHECK(memcmp(hit->addr, addr_a, 6) == 0);

	/* A random address that resolves to no stored IRK -> miss. */
	memcpy(nomatch, spec_rpa, 6);
	nomatch[0] ^= 0xFF;	/* corrupt the hash so ah() no longer matches */
	ATF_CHECK_EQ_MSG(smp_find_bond(&db, nomatch, BDADDR_LE_RANDOM), NULL,
	    "unresolvable RPA must miss");
}

/* ================================================================
 * smp_ensure_local_irk: NULL db, generation, idempotence.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ensure_local_irk);
ATF_TC_BODY(test_ensure_local_irk, tc)
{
	struct smp_bond_db db;
	pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	char path[] = "/tmp/blued_test_irk.XXXXXX";
	int fd;
	uint8_t saved[16];
	uint8_t controller_irk[16];

	/* NULL db must not crash. */
	ATF_CHECK_EQ(smp_ensure_local_irk(NULL), -1);

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	memset(&db, 0, sizeof(db));
	db.fd = fd;
	db.lock = &lock;
	db.has_local_irk = false;

	ATF_REQUIRE_EQ(smp_ensure_local_irk(&db), 0);
	ATF_CHECK_MSG(db.has_local_irk, "IRK must be generated on first use");
	memcpy(saved, db.local_irk, 16);

	/* Second call is a no-op: the IRK must not change. */
	ATF_REQUIRE_EQ(smp_ensure_local_irk(&db), 0);
	ATF_CHECK(db.has_local_irk);
	ATF_CHECK_MSG(memcmp(saved, db.local_irk, 16) == 0,
	    "existing local IRK must be preserved");

	/* Controller privacy must use the exact IRK distributed by SMP. */
	memset(controller_irk, 0, sizeof(controller_irk));
	ATF_CHECK_EQ(0, smp_local_irk_get(&db, controller_irk));
	ATF_CHECK_EQ(memcmp(controller_irk, db.local_irk, 16), 0);
	ATF_CHECK_EQ(-1, smp_local_irk_get(NULL, controller_irk));
	ATF_CHECK_EQ(-1, smp_local_irk_get(&db, NULL));

	close(fd);
	unlink(path);
	pthread_mutex_destroy(&lock);
}

/* ================================================================
 * smp_bond_db_store: NULL, append, in-place update, full-DB eviction.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_db_store_append_update);
ATF_TC_BODY(test_bond_db_store_append_update, tc)
{
	struct smp_bond_db db;
	struct smp_bond b;
	pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	char path[] = "/tmp/blued_test_store.XXXXXX";
	int fd;

	/* NULL db must fail without dereferencing either operand. */
	memset(&b, 0, sizeof(b));
	ATF_CHECK_EQ(smp_bond_db_store(NULL, &b), -1);

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	memset(&db, 0, sizeof(db));
	db.fd = fd;
	db.lock = &lock;

	/* Append. */
	memcpy(b.addr, addr_a, 6);
	b.addr_type = BDADDR_LE_PUBLIC;
	memset(b.ltk, 0x01, 16);
	b.has_ltk = true;
	ATF_REQUIRE_EQ(smp_bond_db_store(&db, &b), 0);
	ATF_REQUIRE_EQ(db.count, 1);
	ATF_CHECK_EQ(memcmp(&db.bonds[0], &b, sizeof(b)), 0);

	/* Second, different device -> append. */
	memcpy(b.addr, addr_b, 6);
	memset(b.ltk, 0x02, 16);
	ATF_REQUIRE_EQ(smp_bond_db_store(&db, &b), 0);
	ATF_REQUIRE_EQ(db.count, 2);
	ATF_CHECK_EQ(memcmp(&db.bonds[1], &b, sizeof(b)), 0);

	/* Same device (addr_b) again -> in-place update, count unchanged. */
	memset(b.ltk, 0x03, 16);
	ATF_REQUIRE_EQ(smp_bond_db_store(&db, &b), 0);
	ATF_CHECK_EQ_MSG(db.count, 2, "re-bond of same device must not append");
	ATF_CHECK_EQ(memcmp(&db.bonds[1], &b, sizeof(b)), 0);

	close(fd);
	unlink(path);
	pthread_mutex_destroy(&lock);
}

ATF_TC_WITHOUT_HEAD(test_bond_db_store_evict_when_full);
ATF_TC_BODY(test_bond_db_store_evict_when_full, tc)
{
	struct smp_bond_db db;
	struct smp_bond b;
	pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	char path[] = "/tmp/blued_test_evict.XXXXXX";
	int fd, i;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	memset(&db, 0, sizeof(db));
	db.fd = fd;
	db.lock = &lock;
	ATF_REQUIRE_EQ(SMP_MAX_BONDS, TEST_IMPL_BOND_CAPACITY);

	/* Fill the independent 32-record daemon contract. */
	for (i = 0; i < TEST_IMPL_BOND_CAPACITY; i++) {
		memset(&b, 0, sizeof(b));
		b.addr[0] = (uint8_t)i;
		b.addr_type = BDADDR_LE_PUBLIC;
		b.has_ltk = true;
		ATF_REQUIRE_EQ(smp_bond_db_store(&db, &b), 0);
	}
	ATF_REQUIRE_EQ(db.count, TEST_IMPL_BOND_CAPACITY);
	ATF_REQUIRE_EQ(db.bonds[0].addr[0], 0);

	/* One more distinct device must evict the oldest (FIFO). */
	memset(&b, 0, sizeof(b));
	b.addr[0] = 0xFE;
	b.addr_type = BDADDR_LE_PUBLIC;
	b.has_ltk = true;
	ATF_REQUIRE_EQ(smp_bond_db_store(&db, &b), 0);

	ATF_CHECK_EQ_MSG(db.count, TEST_IMPL_BOND_CAPACITY,
	    "count stays capped at the independent 32-record contract");
	ATF_CHECK_EQ_MSG(db.bonds[0].addr[0], 1,
	    "oldest bond (index 0) must be evicted, shifting the rest down");
	for (i = 0; i < TEST_IMPL_BOND_CAPACITY - 1; i++)
		ATF_CHECK_EQ(db.bonds[i].addr[0], (uint8_t)(i + 1));
	ATF_CHECK_EQ(db.bonds[TEST_IMPL_BOND_CAPACITY - 1].addr[0], 0xFE);

	close(fd);
	unlink(path);
	pthread_mutex_destroy(&lock);
}

/* ================================================================
 * Bond DB persistence: save refuses without an fd; v5 round-trip;
 * malformed files are rejected without loading bonds.
 * ================================================================ */

/* smp_bond_db_save with fd < 0 must fail rather than write plaintext. */
ATF_TC_WITHOUT_HEAD(test_bond_db_save_no_fd);
ATF_TC_BODY(test_bond_db_save_no_fd, tc)
{
	struct smp_bond_db db;

	memset(&db, 0, sizeof(db));
	db.fd = -1;
	ATF_CHECK_EQ_MSG(smp_bond_db_save(&db), -1,
	    "save without a backing fd must be refused");
}

/* Invalid in-memory bounds and a truncated atomic basename must fail closed
 * before touching storage. */
ATF_TC_WITHOUT_HEAD(test_bond_db_save_metadata_guards);
ATF_TC_BODY(test_bond_db_save_metadata_guards, tc)
{
	struct smp_bond_db db;
	char long_name[sizeof(db.file_name) + 1];

	memset(&db, 0, sizeof(db));
	db.fd = 0;
	db.count = -1;
	db.dir_fd = 0;
	strlcpy(db.file_name, "bonds", sizeof(db.file_name));
	ATF_CHECK_EQ(-1, smp_bond_db_save(&db));
	ATF_REQUIRE_EQ(SMP_MAX_BONDS, TEST_IMPL_BOND_CAPACITY);
	db.count = TEST_IMPL_BOND_CAPACITY + 1;
	ATF_CHECK_EQ(-1, smp_bond_db_save(&db));
	ATF_CHECK_EQ(-1, smp_bond_db_save(NULL));

	memset(long_name, 'x', sizeof(long_name) - 1);
	long_name[sizeof(long_name) - 1] = '\0';
	smp_bond_db_set_atomic(&db, 0, long_name);
	ATF_CHECK_EQ(-1, db.dir_fd);
	ATF_CHECK_EQ(0, db.file_name[0]);
}

/*
 * Encrypted v5 round-trip: store bonds (+ a local IRK), save, then load into
 * a fresh db from the same fd.  Bonds and the local IRK must survive.
 */
ATF_TC_WITHOUT_HEAD(test_bond_db_v4_roundtrip);
ATF_TC_BODY(test_bond_db_v4_roundtrip, tc)
{
	struct smp_bond_db db, db2;
	struct smp_bond b;
	pthread_mutex_t lock;
	char dir[] = "/tmp/blued_test_rt.XXXXXX";
	char path[256];
	int dirfd, fd, i;

	load_core_d7();
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	snprintf(path, sizeof(path), "%s/bonds", dir);
	dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(dirfd >= 0);
	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	ATF_REQUIRE(fd >= 0);

	memset(&db, 0, sizeof(db));
	ATF_REQUIRE_EQ(pthread_mutex_init(&lock, NULL), 0);
	db.lock = &lock;
	db.fd = fd;
	smp_bond_db_set_atomic(&db, dirfd, path);
	memcpy(db.local_irk, spec_irk_le, 16);
	db.has_local_irk = true;

	memset(&b, 0, sizeof(b));
	memcpy(b.addr, addr_a, 6);
	b.addr_type = BDADDR_LE_RANDOM;
	for (i = 0; i < 16; i++)
		b.ltk[i] = (uint8_t)(0xa0 + i);
	b.has_ltk = true;
	b.is_sc = true;
	b.is_mitm = true;
	b.key_size = BT_CORE63_SMP_MAX_KEY_SIZE;
	memcpy(b.irk, spec_irk_le, 16);
	b.has_irk = true;
	ATF_REQUIRE_EQ(smp_bond_db_store(&db, &b), 0);
	ATF_REQUIRE_EQ(db.count, 1);

	ATF_REQUIRE_EQ_MSG(smp_bond_db_save(&db), 0, "v5 save must succeed");

	close(fd);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	memset(&db2, 0, sizeof(db2));
	smp_bond_db_set_atomic(&db2, dirfd, path);
	ATF_CHECK_EQ_MSG(smp_bond_db_load(&db2, fd), 0, "v5 load must succeed");
	ATF_CHECK_EQ_MSG(db2.count, 1, "one bond must round-trip");
	if (db2.count == 1)
		ATF_CHECK_EQ_MSG(memcmp(&db2.bonds[0], &b, sizeof(b)), 0,
		    "every persisted bond field must round-trip byte-for-byte");
	ATF_CHECK_MSG(db2.has_local_irk, "local IRK must round-trip");
	ATF_CHECK(memcmp(db2.local_irk, spec_irk_le, 16) == 0);

	close(fd);
	pthread_mutex_destroy(&lock);
	unlink(path);
	strlcat(path, ".key", sizeof(path));
	unlink(path);
	close(dirfd);
	rmdir(dir);
}

/* Helper: write bytes at offset 0, truncate to len, load into a fresh db. */
static int
load_raw(const uint8_t *buf, size_t len, struct smp_bond_db *db)
{
	char path[] = "/tmp/blued_test_raw.XXXXXX";
	int fd, r;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	if (len > 0)
		ATF_REQUIRE(pwrite(fd, buf, len, 0) == (ssize_t)len);
	ATF_REQUIRE(ftruncate(fd, (off_t)len) == 0);

	memset(db, 0, sizeof(*db));
	r = smp_bond_db_load(db, fd);
	close(fd);
	unlink(path);
	return (r);
}

static int craft_load_v4_tampered(struct smp_bond_db *);

/* Garbage fails closed; only a truly empty new database is accepted. */
ATF_TC_WITHOUT_HEAD(test_bond_db_load_garbage);
ATF_TC_BODY(test_bond_db_load_garbage, tc)
{
	struct smp_bond_db db;
	uint8_t garbage[16];

	memset(garbage, 0x5A, sizeof(garbage));
	ATF_CHECK_EQ(load_raw(garbage, sizeof(garbage), &db), -1);
	ATF_CHECK_EQ(db.count, 0);

	/* Truly empty file. */
	ATF_CHECK_EQ(load_raw(garbage, 0, &db), 0);
	ATF_CHECK_EQ(db.count, 0);
}


/* "BONDE" with a truncated version field -> refuse, count 0, no error. */
ATF_TC_WITHOUT_HEAD(test_bond_db_load_trunc_enc_header);
ATF_TC_BODY(test_bond_db_load_trunc_enc_header, tc)
{
	struct smp_bond_db db;
	uint8_t buf[TEST_IMPL_BOND_MAGIC_LEN + 2];

	memcpy(buf, TEST_IMPL_BOND_MAGIC, TEST_IMPL_BOND_MAGIC_LEN);
	buf[TEST_IMPL_BOND_MAGIC_LEN] = TEST_IMPL_BOND_V4;
	buf[TEST_IMPL_BOND_MAGIC_LEN + 1] = 0;
	ATF_CHECK_EQ(load_raw(buf, sizeof(buf), &db), -1);
	ATF_CHECK_EQ(db.count, 0);
}

/* "BONDE" with an unknown encrypted version -> count 0. */
ATF_TC_WITHOUT_HEAD(test_bond_db_load_unknown_version);
ATF_TC_BODY(test_bond_db_load_unknown_version, tc)
{
	struct smp_bond_db db;
	uint8_t buf[64];
	uint32_t ver = htole32(TEST_IMPL_BOND_V5 + 94);

	memset(buf, 0, sizeof(buf));
	memcpy(buf, TEST_IMPL_BOND_MAGIC, TEST_IMPL_BOND_MAGIC_LEN);
	memcpy(buf + TEST_IMPL_BOND_MAGIC_LEN, &ver, 4);
	ATF_CHECK_EQ(load_raw(buf, sizeof(buf), &db), -1);
	ATF_CHECK_EQ(db.count, 0);
}

/* v4 header claiming a zero-length ciphertext is rejected -> count 0. */
ATF_TC_WITHOUT_HEAD(test_bond_db_load_v4_zero_ctlen);
ATF_TC_BODY(test_bond_db_load_v4_zero_ctlen, tc)
{
	struct smp_bond_db db;
	/* "BONDE"(5) + version(4) + salt(16) + iv(12) + tag(16) + ct_len(4) */
	uint8_t buf[TEST_IMPL_BOND_MAGIC_LEN + 4 +
	    TEST_IMPL_BOND_SALT_LEN + TEST_IMPL_BOND_IV_LEN +
	    TEST_IMPL_BOND_TAG_LEN + 4];
	uint32_t ver = htole32(TEST_IMPL_BOND_V4), ctlen = htole32(0);

	memset(buf, 0, sizeof(buf));
	memcpy(buf, TEST_IMPL_BOND_MAGIC, TEST_IMPL_BOND_MAGIC_LEN);
	memcpy(buf + TEST_IMPL_BOND_MAGIC_LEN, &ver, 4);
	/* ct_len = 0 at the tail of the v4 header */
	memcpy(buf + TEST_IMPL_BOND_MAGIC_LEN + 4 +
	    TEST_IMPL_BOND_SALT_LEN + TEST_IMPL_BOND_IV_LEN +
	    TEST_IMPL_BOND_TAG_LEN, &ctlen, 4);
	ATF_CHECK_EQ(load_raw(buf, sizeof(buf), &db), -1);
	ATF_CHECK_EQ(db.count, 0);
}

/* v4 header with a valid-looking length but garbage ciphertext fails GCM
 * authentication and loads no bonds. */
ATF_TC_WITHOUT_HEAD(test_bond_db_load_v4_bad_ciphertext);
ATF_TC_BODY(test_bond_db_load_v4_bad_ciphertext, tc)
{
	struct smp_bond_db db;

	ATF_CHECK_EQ(craft_load_v4_tampered(&db), -1);
	ATF_CHECK_EQ(db.count, 0);
}

/*
 * Encrypted-format truncation / bad-ciphertext arms.  These never need the
 * real per-machine key: a truncated header or an unauthenticated ciphertext
 * is rejected before or during decryption, so smp_bond_db_load returns 0 with
 * db.count == 0 (Core Spec has no on-disk format; oracle is the code's own
 * documented "start fresh on corrupt" contract).  The version field is set
 * to the sole supported v4 format.
 */
#define ENC_PUT_VER(buf, v) do {					\
	uint32_t _v = htole32(v);					\
	memcpy((buf), TEST_IMPL_BOND_MAGIC,				\
	    TEST_IMPL_BOND_MAGIC_LEN);					\
	memcpy((buf) + TEST_IMPL_BOND_MAGIC_LEN, &_v, 4);		\
} while (0)


/* v4 header claims 48 bytes (salt16+iv12+tag16+len4) but only 20 present. */
ATF_TC_WITHOUT_HEAD(test_bond_db_load_v4_trunc_header);
ATF_TC_BODY(test_bond_db_load_v4_trunc_header, tc)
{
	struct smp_bond_db db;
	uint8_t buf[TEST_IMPL_BOND_MAGIC_LEN + 4 + 20];

	memset(buf, 0, sizeof(buf));
	ENC_PUT_VER(buf, TEST_IMPL_BOND_V4);
	ATF_CHECK_EQ(load_raw(buf, sizeof(buf), &db), -1);
	ATF_CHECK_EQ(db.count, 0);
}

/* v4 with ct_len 64 but only 16 ciphertext bytes present -> truncated ct. */
ATF_TC_WITHOUT_HEAD(test_bond_db_load_v4_trunc_ct);
ATF_TC_BODY(test_bond_db_load_v4_trunc_ct, tc)
{
	struct smp_bond_db db;
	uint8_t buf[TEST_IMPL_BOND_MAGIC_LEN + 4 +
	    TEST_IMPL_BOND_SALT_LEN + TEST_IMPL_BOND_IV_LEN +
	    TEST_IMPL_BOND_TAG_LEN + 4 + 16];
	uint32_t ctlen = htole32(64);

	memset(buf, 0x44, sizeof(buf));
	ENC_PUT_VER(buf, TEST_IMPL_BOND_V4);
	memcpy(buf + TEST_IMPL_BOND_MAGIC_LEN + 4 +
	    TEST_IMPL_BOND_SALT_LEN + TEST_IMPL_BOND_IV_LEN +
	    TEST_IMPL_BOND_TAG_LEN, &ctlen, 4);
	ATF_CHECK_EQ(load_raw(buf, sizeof(buf), &db), -1);
	ATF_CHECK_EQ(db.count, 0);
}

/* ================================================================
 * Post-decrypt payload-parse arms of smp_bond_db_load.  These need a v4
 * file whose ciphertext actually decrypts, so the fixture creates the same
 * owner-only sibling key used by production and derives the file key as
 * PBKDF2-HMAC-SHA256(database_secret, file_salt, 100000, 32).  We craft the
 * decrypted payload byte-for-byte to steer count bounds and IRK-trailer arms
 * that the round-trip cannot.  The ciphertext remains version 4 to cover the
 * supported migration parser while using the current secret architecture.
 * ================================================================ */
#define V4_SALTLEN	16
#define V4_IVLEN	12
#define V4_TAGLEN	16
#define V4_KEYLEN	32
#define V4_ITER		100000

/* Reproduce bond_db_derive_key() using a per-database random secret. */
static int
craft_derive_key(const uint8_t secret[V4_KEYLEN],
    const uint8_t salt[V4_SALTLEN], uint8_t key[V4_KEYLEN])
{
	if (PKCS5_PBKDF2_HMAC((const char *)secret, V4_KEYLEN, salt,
	    V4_SALTLEN, V4_ITER,
	    EVP_sha256(), V4_KEYLEN, key) != 1)
		return (-1);
	return (0);
}

/* Encrypt a crafted plaintext into a v4 file and load it. */
static int
craft_load_v4_internal(const uint8_t *pt, size_t pt_len,
    struct smp_bond_db *db, bool tamper)
{
	uint8_t salt[V4_SALTLEN], iv[V4_IVLEN], tag[V4_TAGLEN], key[V4_KEYLEN];
	uint8_t secret[V4_KEYLEN];
	uint8_t *file, *ct;
	size_t hdr, total;
	uint32_t ver = htole32(TEST_IMPL_BOND_V4);
	uint32_t ctlen = htole32((uint32_t)pt_len);
	EVP_CIPHER_CTX *ctx;
	int outl, finl, rc;
	char path[] = "/tmp/blued_craft_v4.XXXXXX";
	char key_name[sizeof("blued_craft_v4.XXXXXX.key")];
	const char *name;
	int dirfd, fd, keyfd;

	arc4random_buf(salt, sizeof(salt));
	arc4random_buf(iv, sizeof(iv));
	arc4random_buf(secret, sizeof(secret));
	ATF_REQUIRE_EQ(0, craft_derive_key(secret, salt, key));

	ct = malloc(pt_len ? pt_len : 1);
	ATF_REQUIRE(ct != NULL);
	ctx = EVP_CIPHER_CTX_new();
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) == 1);
	ATF_REQUIRE(EVP_EncryptUpdate(ctx, ct, &outl, pt, (int)pt_len) == 1);
	ATF_REQUIRE(EVP_EncryptFinal_ex(ctx, ct + outl, &finl) == 1);
	ATF_REQUIRE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
	    V4_TAGLEN, tag) == 1);
	EVP_CIPHER_CTX_free(ctx);
	if (tamper) {
		ATF_REQUIRE(pt_len > 0);
		ct[0] ^= 0x01;
	}

	hdr = TEST_IMPL_BOND_MAGIC_LEN + 4 + V4_SALTLEN + V4_IVLEN +
	    V4_TAGLEN + 4;
	total = hdr + pt_len;
	file = malloc(total);
	ATF_REQUIRE(file != NULL);
	memcpy(file, TEST_IMPL_BOND_MAGIC, TEST_IMPL_BOND_MAGIC_LEN);
	memcpy(file + TEST_IMPL_BOND_MAGIC_LEN, &ver, 4);
	memcpy(file + TEST_IMPL_BOND_MAGIC_LEN + 4, salt, V4_SALTLEN);
	memcpy(file + TEST_IMPL_BOND_MAGIC_LEN + 4 + V4_SALTLEN, iv,
	    V4_IVLEN);
	memcpy(file + TEST_IMPL_BOND_MAGIC_LEN + 4 + V4_SALTLEN +
	    V4_IVLEN, tag, V4_TAGLEN);
	memcpy(file + TEST_IMPL_BOND_MAGIC_LEN + 4 + V4_SALTLEN +
	    V4_IVLEN + V4_TAGLEN, &ctlen, 4);
	memcpy(file + hdr, ct, pt_len);

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	name = path + strlen("/tmp/");
	ATF_REQUIRE(snprintf(key_name, sizeof(key_name), "%s.key", name) > 0);
	dirfd = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(dirfd >= 0);
	keyfd = openat(dirfd, key_name,
	    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	ATF_REQUIRE(keyfd >= 0);
	ATF_REQUIRE_EQ((ssize_t)sizeof(secret),
	    write(keyfd, secret, sizeof(secret)));
	ATF_REQUIRE_EQ(0, fsync(keyfd));
	ATF_REQUIRE_EQ(0, close(keyfd));
	ATF_REQUIRE(pwrite(fd, file, total, 0) == (ssize_t)total);
	ATF_REQUIRE(ftruncate(fd, (off_t)total) == 0);
	free(ct);
	free(file);
	explicit_bzero(secret, sizeof(secret));
	explicit_bzero(key, sizeof(key));

	memset(db, 0, sizeof(*db));
	smp_bond_db_set_atomic(db, dirfd, name);
	rc = smp_bond_db_load(db, fd);
	close(fd);
	ATF_REQUIRE_EQ(0, unlinkat(dirfd, key_name, 0));
	ATF_REQUIRE_EQ(0, unlinkat(dirfd, name, 0));
	close(dirfd);
	return (rc);
}

static int
craft_load_v4(const uint8_t *pt, size_t pt_len, struct smp_bond_db *db)
{

	return (craft_load_v4_internal(pt, pt_len, db, false));
}

static int
craft_load_v4_tampered(struct smp_bond_db *db)
{
	uint8_t plaintext[32];

	memset(plaintext, 0xa5, sizeof(plaintext));
	return (craft_load_v4_internal(plaintext, sizeof(plaintext), db, true));
}

/* Self-test: does our crafted key decrypt inside the daemon code? */
static bool
payload_key_available(void)
{
	struct smp_bond_db db;
	uint8_t pt[8 + sizeof(struct smp_bond) + 1];
	struct smp_bond b;
	uint32_t count = htole32(1);
	uint32_t record_size = htole32(sizeof(struct smp_bond));

	memset(pt, 0, sizeof(pt));
	memcpy(pt, &count, 4);
	memcpy(pt + 4, &record_size, 4);
	memset(&b, 0, sizeof(b));
	b.addr[0] = 0xAA;
	b.addr[1] = 0xBB;
	memcpy(pt + 8, &b, sizeof(b));
	if (craft_load_v4(pt, sizeof(pt), &db) != 0)
		return (false);
	return (db.count == 1 &&
	    memcmp(&db.bonds[0], &b, sizeof(b)) == 0);
}

/* A count larger than SMP_MAX_BONDS is malformed and must be rejected. */
ATF_TC_WITHOUT_HEAD(test_bond_db_load_count_reject);
ATF_TC_BODY(test_bond_db_load_count_reject, tc)
{
	struct smp_bond_db db;
	size_t bsz = sizeof(struct smp_bond);
	size_t pt_len = 8 + (size_t)TEST_IMPL_BOND_CAPACITY * bsz + 1;
	uint8_t *pt;
	uint32_t count = htole32(TEST_IMPL_BOND_CAPACITY + 1);
	uint32_t record_size = htole32(sizeof(struct smp_bond));
	int i;

	ATF_REQUIRE_MSG(payload_key_available(),
	    "current per-database key fixture must decrypt");
	ATF_REQUIRE_EQ(SMP_MAX_BONDS, TEST_IMPL_BOND_CAPACITY);
	pt = calloc(1, pt_len);
	ATF_REQUIRE(pt != NULL);
	memcpy(pt, &count, 4);
	memcpy(pt + 4, &record_size, 4);
	/* Give each bond a non-size-like first word (addr[0]=0xA0+i). */
	for (i = 0; i < TEST_IMPL_BOND_CAPACITY; i++)
		pt[8 + (size_t)i * bsz] = (uint8_t)(0xA0 + i);
	ATF_CHECK_EQ(-1, craft_load_v4(pt, pt_len, &db));
	ATF_CHECK_EQ_MSG(0, db.count,
	    "an over-large count must be rejected");
	free(pt);
}

/* count larger than the available bond bytes -> payload too small, reject. */
ATF_TC_WITHOUT_HEAD(test_bond_db_load_payload_too_small);
ATF_TC_BODY(test_bond_db_load_payload_too_small, tc)
{
	struct smp_bond_db db;
	uint8_t pt[9] = { 0 };
	uint32_t count = htole32(1);	/* minimum nonempty claim, no record */
	uint32_t record_size = htole32(sizeof(struct smp_bond));

	ATF_REQUIRE_MSG(payload_key_available(),
	    "current per-database key fixture must decrypt");
	memcpy(pt, &count, 4);
	memcpy(pt + 4, &record_size, 4);
	ATF_CHECK_EQ(-1, craft_load_v4(pt, sizeof(pt), &db));
	ATF_CHECK_EQ_MSG(0, db.count,
	    "a payload too small for the claimed count must load no bonds");
}

/* Decrypted payload shorter than a single count field -> reject. */
ATF_TC_WITHOUT_HEAD(test_bond_db_load_payload_runt);
ATF_TC_BODY(test_bond_db_load_payload_runt, tc)
{
	struct smp_bond_db db;
	uint8_t pt[2] = { 0x01, 0x00 };

	ATF_REQUIRE_MSG(payload_key_available(),
	    "current per-database key fixture must decrypt");
	ATF_CHECK_EQ(-1, craft_load_v4(pt, sizeof(pt), &db));
	ATF_CHECK_EQ_MSG(0, db.count, "a runt payload must load no bonds");
}


/* IRK trailer present but its flag byte is zero -> no local IRK adopted. */
ATF_TC_WITHOUT_HEAD(test_bond_db_load_irk_trailer_absent);
ATF_TC_BODY(test_bond_db_load_irk_trailer_absent, tc)
{
	struct smp_bond_db db;
	struct smp_bond expected;
	size_t bsz = sizeof(struct smp_bond);
	size_t pt_len = 8 + bsz + 1;	/* header + one bond + zero flag */
	uint8_t *pt;
	uint32_t count = htole32(1);
	uint32_t record_size = htole32(sizeof(struct smp_bond));

	ATF_REQUIRE_MSG(payload_key_available(),
	    "current per-database key fixture must decrypt");
	memset(&expected, 0, sizeof(expected));
	expected.addr[0] = 0xd9;
	pt = calloc(1, pt_len);
	ATF_REQUIRE(pt != NULL);
	memcpy(pt, &count, 4);
	memcpy(pt + 4, &record_size, 4);
	pt[8] = 0xD9;			/* bond addr[0] */
	pt[pt_len - 1] = 0x00;		/* has_local_irk = 0 */
	ATF_CHECK_EQ(0, craft_load_v4(pt, pt_len, &db));
	ATF_CHECK_EQ(1, db.count);
	ATF_CHECK_EQ(memcmp(&db.bonds[0], &expected, sizeof(expected)), 0);
	ATF_CHECK_MSG(!db.has_local_irk,
	    "a zero IRK-trailer flag must leave has_local_irk false");
	ATF_CHECK_EQ(memcmp(db.local_irk, (uint8_t[16]){0}, 16), 0);
	free(pt);
}

/* ================================================================
 * smp_receive_peer_keys: identity-address (random type) and signing info
 * parse into the bond; a short/absent PDU stops the loop.
 * ================================================================ */
static void
kv_setup(struct smp_conn *sc, struct smp_bond_db *db, int fds[2])
{
	signal(SIGPIPE, SIG_IGN);
	/* Key-distribution diagnostics are used in the daemon as well as during
	 * foreground pairing; exercise the syslog branch on real SMP PDUs. */
	atomic_store(&blued_verbose, 2);
	blued_daemonized = 1;
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(db, 0, sizeof(*db));
	db->fd = -1;
	memset(sc, 0, sizeof(*sc));
	sc->fd = fds[0];
	sc->hci_fd = -1;
	memcpy(sc->local_addr, addr_a, 6);
	sc->local_addr_type = BDADDR_LE_PUBLIC;
	memcpy(sc->remote_addr, addr_b, 6);
	sc->remote_addr_type = BDADDR_LE_PUBLIC;
	sc->bond_db = db;
	{
		struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
		setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
}

struct identity_sender {
	int		fd;
	uint8_t		id_info[17];
	uint8_t		id_addr[8];
	ssize_t		info_sent;
	ssize_t		addr_sent;
};

static void *
send_identity_pair(void *arg)
{
	struct identity_sender *sender = arg;
	const struct timespec pause = { .tv_nsec = 10000000 };

	sender->info_sent = send(sender->fd, sender->id_info,
	    sizeof(sender->id_info), MSG_EOR);
	(void)nanosleep(&pause, NULL);
	sender->addr_sent = send(sender->fd, sender->id_addr,
	    sizeof(sender->id_addr), MSG_EOR);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(test_receive_peer_keys_id_and_sign);
ATF_TC_BODY(test_receive_peer_keys_id_and_sign, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	struct smp_bond bond;
	struct identity_sender sender;
	pthread_t sender_thread;
	int fds[2];
	uint8_t id_info[17], id_addr[8], sign[17], csrk[16];
	const uint8_t rpa_id[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x76 };

	kv_setup(&sc, &db, fds);
	memset(&bond, 0, sizeof(bond));

	/* Identity Address Information with random type (pdu[1]==0x01). */
	id_info[0] = BT_CORE63_SMP_IDENTITY_INFORMATION_OPCODE;
	memset(id_info + 1, 0x4a, 16);
	id_addr[0] = BT_CORE63_SMP_IDENTITY_ADDRESS_INFO_OPCODE;
	id_addr[1] = BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM;
	memcpy(id_addr + 2, rpa_id, 6);
	memset(&sender, 0, sizeof(sender));
	sender.fd = fds[1];
	memcpy(sender.id_info, id_info, sizeof(id_info));
	memcpy(sender.id_addr, id_addr, sizeof(id_addr));
	ATF_REQUIRE_EQ(0, pthread_create(&sender_thread, NULL,
	    send_identity_pair, &sender));
	ATF_REQUIRE_EQ(0, smp_receive_peer_keys(&sc, &bond,
	    BT_CORE63_SMP_KEY_DIST_ID_KEY, true));
	ATF_REQUIRE_EQ(0, pthread_join(sender_thread, NULL));
	ATF_REQUIRE_EQ((ssize_t)sizeof(id_info), sender.info_sent);
	ATF_REQUIRE_EQ((ssize_t)sizeof(id_addr), sender.addr_sent);
	ATF_CHECK_EQ_MSG(bond.addr_type, BDADDR_LE_RANDOM,
	    "random identity address type must be mapped");
	ATF_CHECK(memcmp(bond.addr, rpa_id, 6) == 0);

	/* Signing Information (CSRK). */
	memset(csrk, 0x6D, sizeof(csrk));
	sign[0] = BT_CORE63_LEGACY_SMP_SIGNING_OPCODE;
	memcpy(sign + 1, csrk, 16);
	ATF_REQUIRE(send(fds[1], sign, sizeof(sign), 0) ==
	    (ssize_t)sizeof(sign));
	ATF_REQUIRE_EQ(0, smp_receive_peer_keys(&sc, &bond,
	    BT_CORE63_SMP_KEY_DIST_PREVIOUSLY_USED_MASK, true));
	ATF_CHECK_MSG(bond.has_csrk, "CSRK must be stored");
	ATF_CHECK(memcmp(bond.csrk, csrk, 16) == 0);

	close(fds[0]);
	close(fds[1]);
}

/* Core Vol 3 Part H §3.6.5 permits only public (0x00) and static random (0x01). */
ATF_TC_WITHOUT_HEAD(test_receive_peer_keys_reserved_id_addr_type);
ATF_TC_BODY(test_receive_peer_keys_reserved_id_addr_type, tc)
{
	static const uint8_t invalid_types[] = {
		BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM + 1,
		UINT8_MAX
	};
	struct smp_conn sc;
	struct smp_bond_db db;
	struct smp_bond bond;
	struct smp_bond before;
	struct identity_sender sender;
	uint8_t expected_addr[6];
	pthread_t sender_thread;
	int fds[2];
	size_t i;

	for (i = 0; i < sizeof(invalid_types) / sizeof(invalid_types[0]); i++) {
		kv_setup(&sc, &db, fds);
		memset(&bond, 0, sizeof(bond));
		memset(expected_addr, 0xa5, sizeof(expected_addr));
		memcpy(bond.addr, expected_addr, sizeof(bond.addr));
		memset(bond.irk, 0xa6, sizeof(bond.irk));
		bond.has_irk = true;
		before = bond;
		memset(&sender, 0, sizeof(sender));
		sender.fd = fds[1];
		sender.id_info[0] =
		    BT_CORE63_SMP_IDENTITY_INFORMATION_OPCODE;
		memset(sender.id_info + 1, 0x4a, 16);
		sender.id_addr[0] =
		    BT_CORE63_SMP_IDENTITY_ADDRESS_INFO_OPCODE;
		sender.id_addr[1] = invalid_types[i];
		memset(sender.id_addr + 2, 0x55, 6);

		ATF_REQUIRE_EQ(0, pthread_create(&sender_thread, NULL,
		    send_identity_pair, &sender));
		ATF_CHECK_EQ(-1, smp_receive_peer_keys(&sc, &bond,
		    SMP_KEY_DIST_ID_KEY, true));
		ATF_REQUIRE_EQ(0, pthread_join(sender_thread, NULL));
		ATF_CHECK_EQ(memcmp(bond.addr, expected_addr,
		    sizeof(expected_addr)), 0);
		ATF_CHECK_EQ_MSG(memcmp(&bond, &before, sizeof(bond)), 0,
		    "rejected key sequence must not partially mutate the bond");

		close(fds[0]);
		close(fds[1]);
	}
}

/* expected > 0 but nothing arrives: the recv times out, the loop breaks,
 * and nothing is parsed. */
ATF_TC_WITHOUT_HEAD(test_receive_peer_keys_timeout_break);
ATF_TC_BODY(test_receive_peer_keys_timeout_break, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	struct smp_bond bond, before;
	int fds[2];
	struct timeval tv = { .tv_sec = 0, .tv_usec = 150000 };

	kv_setup(&sc, &db, fds);
	setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	memset(&bond, 0xa5, sizeof(bond));
	bond.has_irk = false;
	bond.has_csrk = false;
	before = bond;

	ATF_CHECK_EQ(-1, smp_receive_peer_keys(&sc, &bond,
	    BT_CORE63_SMP_KEY_DIST_ID_KEY |
	    BT_CORE63_SMP_KEY_DIST_PREVIOUSLY_USED_MASK, true));
	ATF_CHECK_EQ_MSG(memcmp(&bond, &before, sizeof(bond)), 0,
	    "timeout must not partially mutate the bond transaction");

	close(fds[0]);
	close(fds[1]);
}

/* A detached transport is possible during link teardown.  The receive helper
 * must tolerate the failed timeout setup and failed read without modifying
 * partially accumulated key material. */
ATF_TC_WITHOUT_HEAD(test_receive_peer_keys_invalid_transport);
ATF_TC_BODY(test_receive_peer_keys_invalid_transport, tc)
{
	struct smp_conn sc;
	struct smp_bond bond, before;

	memset(&sc, 0, sizeof(sc));
	memset(&bond, 0, sizeof(bond));
	sc.fd = -1;
	bond.has_irk = true;
	memset(bond.irk, 0x5a, sizeof(bond.irk));
	before = bond;
	ATF_CHECK_EQ(-1, smp_receive_peer_keys(&sc, &bond,
	    BT_CORE63_SMP_KEY_DIST_PREVIOUSLY_USED_MASK, true));
	ATF_CHECK_EQ_MSG(memcmp(&bond, &before, sizeof(bond)), 0,
	    "detached transport must leave every bond byte unchanged");
}

/* ================================================================
 * smp_distribute_init_keys: exact LE legacy and Secure Connections key
 * distribution sequences from Core 6.3 Vol 3, Part H, Sections 2.4.3.1,
 * 2.4.3.2, and 3.6.1.  Expected masks and command codes come only from
 * the generated specification oracle.
 * ================================================================ */
static int
drain_opcodes(int peer_fd, uint8_t *seen, int max)
{
	uint8_t buf[64];
	ssize_t n;
	int count = 0;

	(void)fcntl(peer_fd, F_SETFL, O_NONBLOCK);
	while ((n = recv(peer_fd, buf, sizeof(buf), 0)) > 0 && count < max)
		seen[count++] = buf[0];
	return (count);
}

ATF_TC_WITHOUT_HEAD(test_distribute_init_keys_legacy_all);
ATF_TC_BODY(test_distribute_init_keys_legacy_all, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int fds[2];
	char path[] = "/tmp/blued_test_dist.XXXXXX";
	int bfd;
	uint8_t preq[7], pres[7];
	uint8_t seen[16];
	int nseen;

	kv_setup(&sc, &db, fds);
	bfd = mkstemp(path);
	ATF_REQUIRE(bfd >= 0);
	db.fd = bfd;			/* allow smp_ensure_local_irk to save */

	memset(preq, 0, 7);
	memset(pres, 0, 7);
	/* Figure 3.11 EncKey+IdKey request, independently generated. */
	preq[5] = pres[5] = BT_CORE63_SMP_KEY_DIST_ENC_KEY |
	    BT_CORE63_SMP_KEY_DIST_ID_KEY;

	smp_distribute_init_keys(&sc, preq, pres, false);	/* legacy */

	nseen = drain_opcodes(fds[1], seen, 16);
	ATF_REQUIRE_EQ(4, nseen);
	ATF_CHECK_EQ(BT_CORE63_SMP_ENCRYPTION_INFORMATION_OPCODE, seen[0]);
	ATF_CHECK_EQ(BT_CORE63_SMP_CENTRAL_IDENTIFICATION_OPCODE, seen[1]);
	ATF_CHECK_EQ(BT_CORE63_SMP_IDENTITY_INFORMATION_OPCODE, seen[2]);
	ATF_CHECK_EQ(BT_CORE63_SMP_IDENTITY_ADDRESS_INFO_OPCODE, seen[3]);

	close(fds[0]);
	close(fds[1]);
	close(bfd);
	unlink(path);
}

ATF_TC_WITHOUT_HEAD(test_distribute_init_keys_sc_skips_enc);
ATF_TC_BODY(test_distribute_init_keys_sc_skips_enc, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int fds[2];
	char path[] = "/tmp/blued_test_dist2.XXXXXX";
	int bfd;
	uint8_t preq[7], pres[7];
	uint8_t seen[16];
	int nseen;

	kv_setup(&sc, &db, fds);
	bfd = mkstemp(path);
	ATF_REQUIRE(bfd >= 0);
	db.fd = bfd;

	memset(preq, 0, 7);
	memset(pres, 0, 7);
	/* EncKey is deliberately requested: Section 3.6.1 says SC ignores it. */
	preq[5] = pres[5] = BT_CORE63_SMP_KEY_DIST_ENC_KEY |
	    BT_CORE63_SMP_KEY_DIST_ID_KEY;

	smp_distribute_init_keys(&sc, preq, pres, true);	/* SC */

	nseen = drain_opcodes(fds[1], seen, 16);
	ATF_REQUIRE_EQ(2, nseen);
	ATF_CHECK_EQ(BT_CORE63_SMP_IDENTITY_INFORMATION_OPCODE, seen[0]);
	ATF_CHECK_EQ(BT_CORE63_SMP_IDENTITY_ADDRESS_INFO_OPCODE, seen[1]);

	close(fds[0]);
	close(fds[1]);
	close(bfd);
	unlink(path);
}

/*
 * The Identity Address Information AddrType octet must be the SMP wire
 * encoding (Core Spec Vol 3 Part H §3.6.5: 0x00 = public, 0x01 = static
 * random), NOT the internal BDADDR_LE_* enum (PUBLIC=1, RANDOM=2).  Drive
 * smp_distribute_init_keys with each local address type and capture the
 * Identity Address Information PDU.  Before the fix a RANDOM identity was
 * emitted as 0x02 (invalid; a peer reads it as public) and a PUBLIC
 * identity as 0x01 (a peer reads it as random).
 */
static uint8_t
capture_id_addr_type(uint8_t local_type)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int fds[2];
	char path[] = "/tmp/blued_test_dist3.XXXXXX";
	int bfd;
	uint8_t preq[7], pres[7];
	uint8_t buf[64];
	ssize_t n;
	uint8_t at = 0xFF;

	kv_setup(&sc, &db, fds);
	sc.local_addr_type = local_type;
	bfd = mkstemp(path);
	ATF_REQUIRE(bfd >= 0);
	db.fd = bfd;

	memset(preq, 0, 7);
	memset(pres, 0, 7);
	preq[5] = pres[5] = SMP_KEY_DIST_ID_KEY;

	smp_distribute_init_keys(&sc, preq, pres, true);

	(void)fcntl(fds[1], F_SETFL, O_NONBLOCK);
	while ((n = recv(fds[1], buf, sizeof(buf), 0)) > 0) {
		if (n >= 8 && buf[0] == SMP_IDENTITY_ADDRESS_INFO)
			at = buf[1];
	}

	close(fds[0]);
	close(fds[1]);
	close(bfd);
	unlink(path);
	return (at);
}

ATF_TC_WITHOUT_HEAD(test_distribute_id_addr_type_wire_encoding);
ATF_TC_BODY(test_distribute_id_addr_type_wire_encoding, tc)
{
	ATF_CHECK_EQ_MSG(capture_id_addr_type(BDADDR_LE_PUBLIC),
	    BT_CORE63_SMP_ID_ADDR_PUBLIC,
	    "public identity address must be distributed as AddrType 0x00");
	ATF_CHECK_EQ_MSG(capture_id_addr_type(BDADDR_LE_RANDOM),
	    BT_CORE63_SMP_ID_ADDR_STATIC_RANDOM,
	    "random identity address must be distributed as AddrType 0x01");
}

/* ================================================================
 * CCCD save/restore for bonded devices.
 * Core Spec Vol 3 Part G Section 2.4.5.1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_bond_cccds_save_restore);
ATF_TC_BODY(test_bond_cccds_save_restore, tc)
{
	struct smp_bond bond;
	struct att_conn ac;

	/* Each independently-null argument must be harmless. */
	smp_bond_save_cccds(NULL, NULL);
	smp_bond_restore_cccds(NULL, NULL);
	memset(&bond, 0, sizeof(bond));
	memset(&ac, 0, sizeof(ac));
	smp_bond_save_cccds(&bond, NULL);
	smp_bond_save_cccds(NULL, &ac);
	smp_bond_restore_cccds(&bond, NULL);
	smp_bond_restore_cccds(NULL, &ac);

	memset(&bond, 0, sizeof(bond));
	memset(&ac, 0, sizeof(ac));

	/* Mixed zero / non-zero CCCD values; only non-zero are persisted. */
	ac.cccds[0].handle = 0x0010;
	ac.cccds[0].value = BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED;
	ac.cccds[1].handle = 0x0020;
	ac.cccds[1].value = BT_CORE63_GATT_CCCD_DISABLED;
	ac.cccds[2].handle = 0x0030;
	ac.cccds[2].value = BT_CORE63_GATT_CCCD_INDICATIONS_ENABLED;
	ac.cccd_count = 3;

	smp_bond_save_cccds(&bond, &ac);
	ATF_CHECK_EQ_MSG(bond.num_cccds, 2,
	    "only non-zero CCCD values are saved");
	ATF_CHECK_EQ(bond.cccds[0].handle, 0x0010);
	ATF_CHECK_EQ(bond.cccds[0].value,
	    BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);
	ATF_CHECK_EQ(bond.cccds[1].handle, 0x0030);
	ATF_CHECK_EQ(bond.cccds[1].value,
	    BT_CORE63_GATT_CCCD_INDICATIONS_ENABLED);

	/* Restore into a fresh connection state. */
	{
		struct att_conn ac2;

		memset(&ac2, 0, sizeof(ac2));
		smp_bond_restore_cccds(&bond, &ac2);
		ATF_CHECK_EQ(ac2.cccd_count, 2);
		ATF_CHECK_EQ(memcmp(ac2.cccds, bond.cccds,
		    2 * sizeof(bond.cccds[0])), 0);
	}
}

/* Save caps at SMP_MAX_CCCDS when more non-zero entries are present. */
ATF_TC_WITHOUT_HEAD(test_bond_cccds_save_overflow);
ATF_TC_BODY(test_bond_cccds_save_overflow, tc)
{
	struct smp_bond bond;
	struct att_conn ac;
	int i;

	memset(&bond, 0, sizeof(bond));
	memset(&ac, 0, sizeof(ac));
	ATF_REQUIRE_EQ(SMP_MAX_CCCDS, TEST_IMPL_CCCD_CAPACITY);
	ATF_REQUIRE_EQ(ATT_MAX_CCCDS_PER_CONN,
	    TEST_IMPL_ATT_CCCD_CAPACITY);

	for (i = 0; i < TEST_IMPL_ATT_CCCD_CAPACITY; i++) {
		ac.cccds[i].handle = (uint16_t)(0x0100 + i);
		ac.cccds[i].value =
		    BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED;
	}
	ac.cccd_count = TEST_IMPL_ATT_CCCD_CAPACITY;

	smp_bond_save_cccds(&bond, &ac);
	ATF_CHECK_EQ_MSG(bond.num_cccds, TEST_IMPL_CCCD_CAPACITY,
	    "saved CCCD count must be capped at the 16-entry bond contract");
	for (i = 0; i < TEST_IMPL_CCCD_CAPACITY; i++) {
		ATF_CHECK_EQ(bond.cccds[i].handle, (uint16_t)(0x0100 + i));
		ATF_CHECK_EQ(bond.cccds[i].value,
		    BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);
	}
}

/* ================================================================ */
/*
 * K4: smp_bond_restore_cccds() must bound its copy by the physical array
 * size SMP_MAX_CCCDS, not by the untrusted uint8_t num_cccds.  A bond with a
 * num_cccds larger than the array (corrupt/hand-crafted record) would
 * otherwise over-read bond->cccds[].  Restore must copy at most
 * SMP_MAX_CCCDS entries and not fault.
 */
ATF_TC_WITHOUT_HEAD(test_bond_restore_cccds_overread_clamped);
ATF_TC_BODY(test_bond_restore_cccds_overread_clamped, tc)
{
	struct smp_bond bond;
	struct att_conn ac;
	int i;

	memset(&bond, 0, sizeof(bond));
	memset(&ac, 0, sizeof(ac));
	ATF_REQUIRE_EQ(SMP_MAX_CCCDS, TEST_IMPL_CCCD_CAPACITY);
	ATF_REQUIRE_EQ(ATT_MAX_CCCDS_PER_CONN,
	    TEST_IMPL_ATT_CCCD_CAPACITY);

	/* Fill the real array; every entry non-zero so it would be copied. */
	for (i = 0; i < TEST_IMPL_CCCD_CAPACITY; i++) {
		bond.cccds[i].handle = (uint16_t)(0x0100 + i);
		bond.cccds[i].value =
		    BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED;
	}
	/* Lie: claim far more CCCDs than the array physically holds. */
	bond.num_cccds = UINT8_MAX;

	smp_bond_restore_cccds(&bond, &ac);

	ATF_CHECK_EQ_MSG(ac.cccd_count, TEST_IMPL_CCCD_CAPACITY,
	    "restore must clamp an untrusted count to exactly 16 entries");
	ATF_CHECK_EQ(memcmp(ac.cccds, bond.cccds,
	    TEST_IMPL_CCCD_CAPACITY * sizeof(bond.cccds[0])), 0);
}

/*
 * P10: smp_bond_persist_sign_counter() must write an advanced Signed-Write
 * replay counter back into the matching bond (keyed by CSRK) and persist it,
 * so the replay window survives reconnect (Core Spec Vol 3 Part H §2.4.5 /
 * erratum 26047).  A strictly-newer counter updates and saves; an equal or
 * older counter must NOT roll the stored value backwards.
 */
ATF_TC_WITHOUT_HEAD(test_persist_sign_counter);
ATF_TC_BODY(test_persist_sign_counter, tc)
{
	struct smp_bond_db db, db2;
	struct smp_bond b;
	pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	uint8_t csrk[16];
	char dir[] = "/tmp/blued_test_sc.XXXXXX";
	char path[256];
	int dirfd, fd, i;

	for (i = 0; i < 16; i++)
		csrk[i] = (uint8_t)(0x40 + i);

	ATF_REQUIRE(mkdtemp(dir) != NULL);
	snprintf(path, sizeof(path), "%s/bonds", dir);
	dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(dirfd >= 0);
	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	ATF_REQUIRE(fd >= 0);

	memset(&db, 0, sizeof(db));
	db.lock = &lock;
	db.fd = fd;
	smp_bond_db_set_atomic(&db, dirfd, path);

	memset(&b, 0, sizeof(b));
	memcpy(b.addr, addr_a, 6);
	b.addr_type = BDADDR_LE_RANDOM;
	memset(b.ltk, 0x5A, 16);
	b.has_ltk = true;
	memcpy(b.csrk, csrk, 16);
	b.has_csrk = true;
	b.peer_sign_counter = 5;
	ATF_REQUIRE_EQ(smp_bond_db_store(&db, &b), 0);
	ATF_REQUIRE_EQ(db.count, 1);

	/* Newer counter: must advance and persist. */
	ATF_REQUIRE_EQ(smp_bond_persist_sign_counter(&db, csrk, 42), 0);
	ATF_CHECK_EQ_MSG(db.bonds[0].peer_sign_counter, 42,
	    "newer counter must be written into the bond");
	b.peer_sign_counter = 42;

	/* Older/equal counter: must NOT roll backwards. */
	ATF_REQUIRE_EQ(smp_bond_persist_sign_counter(&db, csrk, 42), 0);
	ATF_REQUIRE_EQ(smp_bond_persist_sign_counter(&db, csrk, 10), 0);
	ATF_CHECK_EQ_MSG(db.bonds[0].peer_sign_counter, 42,
	    "older counter must not overwrite a newer stored value");

	/* Unknown CSRK: no-op, no crash. */
	{
		uint8_t other[16];
		memset(other, 0xFF, sizeof(other));
		ATF_REQUIRE_EQ(smp_bond_persist_sign_counter(&db, other, 999), 0);
		ATF_CHECK_EQ(db.bonds[0].peer_sign_counter, 42);
	}

	/* The advanced counter must survive a save/load round-trip. */
	close(fd);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	memset(&db2, 0, sizeof(db2));
	smp_bond_db_set_atomic(&db2, dirfd, path);
	ATF_REQUIRE_EQ(smp_bond_db_load(&db2, fd), 0);
	ATF_REQUIRE_EQ(db2.count, 1);
	ATF_CHECK_EQ_MSG(memcmp(&db2.bonds[0], &b, sizeof(b)), 0,
	    "only the advanced counter changes and the whole bond persists");

	ATF_CHECK_EQ(smp_bond_persist_sign_counter(NULL, csrk, 1), -1);

	close(fd);
	pthread_mutex_destroy(&lock);
	unlink(path);
	strlcat(path, ".key", sizeof(path));
	unlink(path);
	close(dirfd);
	rmdir(dir);
}

/* Every in-memory bond mutation must roll back when atomic persistence fails. */
ATF_TC_WITHOUT_HEAD(test_bond_mutation_flush_rollbacks);
ATF_TC_BODY(test_bond_mutation_flush_rollbacks, tc)
{
	struct smp_bond_db db;
	struct smp_bond incoming, before, counter_before;
	struct smp_bond full_before[TEST_IMPL_BOND_CAPACITY];
	pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	uint8_t csrk[16];
	int deadfd, i;

	deadfd = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(deadfd >= 0);
	memset(&db, 0, sizeof(db));
	db.fd = -1;
	db.lock = &lock;
	ATF_REQUIRE_EQ(SMP_MAX_BONDS, TEST_IMPL_BOND_CAPACITY);
	smp_bond_db_set_atomic(&db, deadfd, "bonds");
	close(deadfd); /* all flushes now fail at openat(2) */

	ATF_CHECK_EQ(-1, smp_ensure_local_irk(&db));
	ATF_CHECK(!db.has_local_irk);
	ATF_CHECK(memcmp(db.local_irk, (uint8_t[16]){0}, 16) == 0);

	memset(&incoming, 0, sizeof(incoming));
	memcpy(incoming.addr, addr_a, 6);
	incoming.addr_type = BDADDR_LE_RANDOM;
	incoming.has_ltk = true;
	memset(incoming.ltk, 0x44, sizeof(incoming.ltk));
	ATF_CHECK_EQ(-1, smp_bond_db_store(&db, &incoming));
	ATF_CHECK_EQ(0, db.count);

	/* Import has its own append-and-flush path.  A failed import must remove
	 * the tentative record and scrub it before reporting -2 to the caller. */
	ATF_CHECK_EQ(-2, smp_bond_db_import(&db, &incoming));
	ATF_CHECK_EQ(0, db.count);
	ATF_CHECK(memcmp(&db.bonds[0], (uint8_t[sizeof(db.bonds[0])]){0},
	    sizeof(db.bonds[0])) == 0);

	/* Existing-record refresh restores every old key field. */
	db.count = 1;
	db.bonds[0] = incoming;
	memset(db.bonds[0].ltk, 0x11, sizeof(db.bonds[0].ltk));
	before = db.bonds[0];
	ATF_CHECK_EQ(-1, smp_bond_db_store(&db, &incoming));
	ATF_CHECK(memcmp(&db.bonds[0], &before, sizeof(before)) == 0);

	/* Full-database eviction restores the original ordering and oldest bond. */
	for (i = 0; i < TEST_IMPL_BOND_CAPACITY; i++) {
		db.bonds[i] = before;
		db.bonds[i].addr[0] = (uint8_t)i;
	}
	db.count = TEST_IMPL_BOND_CAPACITY;
	memcpy(full_before, db.bonds, sizeof(full_before));
	incoming.addr[0] = 0xee;
	ATF_CHECK_EQ(-1, smp_bond_db_store(&db, &incoming));
	ATF_CHECK_EQ(TEST_IMPL_BOND_CAPACITY, db.count);
	ATF_CHECK_EQ_MSG(memcmp(db.bonds, full_before,
	    sizeof(full_before)), 0,
	    "failed full-database eviction must restore every record and order");

	/* Counter advancement and explicit commit both restore their old value. */
	db.count = 1;
	db.bonds[0] = full_before[0];
	memset(csrk, 0x5a, sizeof(csrk));
	memcpy(db.bonds[0].csrk, csrk, sizeof(csrk));
	db.bonds[0].has_csrk = true;
	db.bonds[0].peer_sign_counter = 7;
	counter_before = db.bonds[0];
	ATF_CHECK_EQ(-1, smp_bond_persist_sign_counter(&db, csrk, 8));
	ATF_CHECK_EQ(memcmp(&db.bonds[0], &counter_before,
	    sizeof(counter_before)), 0);
	before = db.bonds[0];
	db.bonds[0].ltk[0] ^= 0xff;
	ATF_CHECK_EQ(-1, smp_bond_db_commit_bond(&db, &db.bonds[0], &before));
	ATF_CHECK(memcmp(&db.bonds[0], &before, sizeof(before)) == 0);

	/* The replace-keys facade inherits the same rollback contract. */
	incoming = before;
	incoming.ltk[0] ^= 0xaa;
	ATF_CHECK_EQ(-1, smp_bond_db_replace_keys(&db, &incoming));
	ATF_CHECK(memcmp(&db.bonds[0], &before, sizeof(before)) == 0);

	/* Commit rejects each independently absent required operand before it can
	 * attempt persistence or mutate the in-memory bond. */
	ATF_CHECK_EQ(-1, smp_bond_db_commit_bond(NULL, &db.bonds[0], &before));
	ATF_CHECK_EQ(-1, smp_bond_db_commit_bond(&db, NULL, &before));
	ATF_CHECK_EQ(-1, smp_bond_db_commit_bond(&db, &db.bonds[0], NULL));
	pthread_mutex_destroy(&lock);
}

/*
 * K-low: the IdKey distribution branch must guard on bond_db != NULL like the
 * sibling SignKey branch.  With no bond DB there is no local IRK, and the
 * pre-fix code dereferenced sc->bond_db->local_irk unconditionally, faulting.
 * Drive smp_distribute_init_keys() with bond_db == NULL and the IdKey bit set:
 * it must not crash and must emit NO Identity Information PDU.
 */
ATF_TC_WITHOUT_HEAD(test_distribute_init_keys_null_bonddb);
ATF_TC_BODY(test_distribute_init_keys_null_bonddb, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int fds[2];
	uint8_t preq[7], pres[7];
	uint8_t seen[16];
	int nseen;

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	{
		struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
		setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
	memset(&sc, 0, sizeof(sc));
	sc.fd = fds[0];
	sc.hci_fd = -1;
	memcpy(sc.local_addr, addr_a, 6);
	sc.local_addr_type = BDADDR_LE_PUBLIC;
	memcpy(sc.remote_addr, addr_b, 6);
	sc.remote_addr_type = BDADDR_LE_PUBLIC;
	sc.bond_db = NULL;			/* the crash condition */

	memset(preq, 0, 7);
	memset(pres, 0, 7);
	preq[5] = pres[5] = BT_CORE63_SMP_KEY_DIST_ID_KEY;

	/* Must return without dereferencing the NULL bond_db. */
	ATF_CHECK_EQ(smp_distribute_init_keys(&sc, preq, pres, false), -1);

	nseen = drain_opcodes(fds[1], seen, 16);
	ATF_CHECK_EQ_MSG(nseen, 0,
	    "with no bond DB, no key-distribution PDU may be emitted");

	/* A present DB whose generated IRK cannot be persisted is equally unsafe
	 * to distribute: the peer must not receive an identity we cannot retain. */
	memset(&db, 0, sizeof(db));
	db.fd = -1;
	smp_bond_db_set_atomic(&db, STDIN_FILENO, "bonds");
	sc.bond_db = &db;
	ATF_CHECK_EQ(smp_distribute_init_keys(&sc, preq, pres, false), -1);
	nseen = drain_opcodes(fds[1], seen, 16);
	ATF_CHECK_EQ_MSG(nseen, 0,
	    "an unpersistable IRK must produce no key-distribution PDU");
	ATF_CHECK(!db.has_local_irk);

	close(fds[0]);
	close(fds[1]);
}

ATF_TC_WITHOUT_HEAD(test_bond_record_public_input_guards);
static void
check_record_rejected_without_output(const uint8_t *record, size_t len)
{
	struct smp_bond decoded, before;

	memset(&decoded, 0xa5, sizeof(decoded));
	before = decoded;
	ATF_CHECK_EQ(smp_bond_import_record(record, len, &decoded), -1);
	ATF_CHECK_EQ_MSG(memcmp(&decoded, &before, sizeof(decoded)), 0,
	    "rejected portable record must not partially mutate output");
}

ATF_TC_BODY(test_bond_record_public_input_guards, tc)
{
	struct smp_bond bond, decoded;
	struct smp_bond_db db;
	uint8_t rec[TEST_IMPL_BOND_REC_HEADER_LEN + sizeof(struct smp_bond)];
	uint8_t csrk[16];

	memset(&bond, 0, sizeof(bond));
	memset(&decoded, 0, sizeof(decoded));
	memset(&db, 0, sizeof(db));
	memset(rec, 0, sizeof(rec));
	memset(csrk, 0, sizeof(csrk));
	ATF_REQUIRE_EQ(SMP_BOND_REC_MAGIC_LEN,
	    TEST_IMPL_BOND_REC_MAGIC_LEN);
	ATF_REQUIRE_EQ(SMP_BOND_REC_VERSION, TEST_IMPL_BOND_REC_VERSION);
	ATF_REQUIRE_EQ(SMP_BOND_REC_HDR, TEST_IMPL_BOND_REC_HEADER_LEN);
	ATF_REQUIRE_EQ(SMP_BOND_REC_LEN, sizeof(rec));
	ATF_REQUIRE_EQ(SMP_MAX_BONDS, TEST_IMPL_BOND_CAPACITY);
	ATF_REQUIRE_EQ(SMP_MAX_CCCDS, TEST_IMPL_CCCD_CAPACITY);
	/* Export must not write through absent or undersized output storage. */
	ATF_CHECK_EQ(0, smp_bond_export_record(NULL, rec, sizeof(rec)));
	ATF_CHECK_EQ(0, smp_bond_export_record(&bond, NULL, sizeof(rec)));
	ATF_CHECK_EQ(0, smp_bond_export_record(&bond, rec, sizeof(rec) - 1));
	/* Import must reject absent record/output operands before parsing. */
	ATF_CHECK_EQ(-1, smp_bond_import_record(NULL, sizeof(rec), &decoded));
	ATF_CHECK_EQ(-1, smp_bond_import_record(rec, sizeof(rec), NULL));
	ATF_CHECK_EQ(-1, smp_bond_db_import(NULL, &bond));
	ATF_CHECK_EQ(-1, smp_bond_db_import(&db, NULL));
	ATF_CHECK_EQ(-1, smp_bond_persist_sign_counter(NULL, csrk, 1));
	ATF_CHECK_EQ(-1, smp_bond_persist_sign_counter(&db, NULL, 1));
	bond.addr[0] = 1;
	db.count = TEST_IMPL_BOND_CAPACITY;
	ATF_CHECK_EQ(-1, smp_bond_db_import(&db, &bond));
	db.count = 0;
	bond.addr[0] = 0;

	/* Starting from a valid portable record, each on-record validation gate
	 * rejects corruption before an in-memory bond can be installed. */
	bond.addr_type = BDADDR_LE_PUBLIC;
	ATF_REQUIRE_EQ(sizeof(rec), smp_bond_export_record(&bond, rec,
	    sizeof(rec)));
	ATF_CHECK_EQ(memcmp(rec, TEST_IMPL_BOND_REC_MAGIC,
	    TEST_IMPL_BOND_REC_MAGIC_LEN), 0);
	rec[0] ^= 0xff;
	check_record_rejected_without_output(rec, sizeof(rec));
	ATF_REQUIRE_EQ(sizeof(rec), smp_bond_export_record(&bond, rec,
	    sizeof(rec)));
	memset(rec + TEST_IMPL_BOND_REC_MAGIC_LEN, 0, 4);
	check_record_rejected_without_output(rec, sizeof(rec));
	ATF_REQUIRE_EQ(sizeof(rec), smp_bond_export_record(&bond, rec,
	    sizeof(rec)));
	memset(rec + TEST_IMPL_BOND_REC_MAGIC_LEN + 4, 0, 4);
	check_record_rejected_without_output(rec, sizeof(rec));
	ATF_REQUIRE_EQ(sizeof(rec), smp_bond_export_record(&bond, rec,
	    sizeof(rec)));
	rec[TEST_IMPL_BOND_REC_HEADER_LEN +
	    offsetof(struct smp_bond, has_ltk)] = 2;
	check_record_rejected_without_output(rec, sizeof(rec));
	ATF_REQUIRE_EQ(sizeof(rec), smp_bond_export_record(&bond, rec,
	    sizeof(rec)));
	rec[TEST_IMPL_BOND_REC_HEADER_LEN +
	    offsetof(struct smp_bond, addr_type)] = UINT8_MAX;
	check_record_rejected_without_output(rec, sizeof(rec));
	ATF_REQUIRE_EQ(sizeof(rec), smp_bond_export_record(&bond, rec,
	    sizeof(rec)));
	rec[TEST_IMPL_BOND_REC_HEADER_LEN +
	    offsetof(struct smp_bond, key_size)] =
	    BT_CORE63_SMP_MIN_KEY_SIZE - 1;
	check_record_rejected_without_output(rec, sizeof(rec));
	ATF_REQUIRE_EQ(sizeof(rec), smp_bond_export_record(&bond, rec,
	    sizeof(rec)));
	rec[TEST_IMPL_BOND_REC_HEADER_LEN +
	    offsetof(struct smp_bond, num_cccds)] =
	    TEST_IMPL_CCCD_CAPACITY + 1;
	check_record_rejected_without_output(rec, sizeof(rec));
	ATF_REQUIRE_EQ(sizeof(rec), smp_bond_export_record(&bond, rec,
	    sizeof(rec)));
	rec[TEST_IMPL_BOND_REC_HEADER_LEN +
	    offsetof(struct smp_bond, num_reports)] =
	    TEST_IMPL_REPORT_CAPACITY + 1;
	check_record_rejected_without_output(rec, sizeof(rec));
}

/* ================================================================
 * SR3: bond-store fail-closed identity root + atomic persistence.
 * ================================================================ */

/* An empty/whitespace identity root must fail closed; a real one is accepted. */
ATF_TC_WITHOUT_HEAD(test_bond_identity_root_fail_closed);
ATF_TC_BODY(test_bond_identity_root_fail_closed, tc)
{
	static const char invalid[] = {
		'\0', ' ', '\t', '\n', '\r', '\f', '\v'
	};
	size_t i;

	ATF_CHECK_EQ(smp_bond_identity_root_ok(NULL, 0), -1);
	ATF_CHECK_EQ(smp_bond_identity_root_ok("", 0), -1);
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
		ATF_CHECK_EQ_MSG(smp_bond_identity_root_ok(&invalid[i], 1), -1,
		    "single-byte whitespace/NUL case %zu must fail", i);
	ATF_CHECK_EQ(smp_bond_identity_root_ok(" \t\r\n\f\v\0", 7), -1);

	ATF_CHECK_EQ(smp_bond_identity_root_ok("uuid", 4), 0);
	/* A hostuuid with a trailing newline is still a usable root. */
	ATF_CHECK_EQ(smp_bond_identity_root_ok("2f8e0a11\n", 9), 0);
	ATF_CHECK_EQ(smp_bond_identity_root_ok("\t2f8e0a11\r\n", 11), 0);
}

/*
 * Atomic bond-DB write: a good save produces a complete file (no torn state,
 * no stray temp); a failed save leaves the prior good bond file intact.
 */
ATF_TC_WITHOUT_HEAD(test_bond_db_atomic_write_preserves_prior);
ATF_TC_BODY(test_bond_db_atomic_write_preserves_prior, tc)
{
	char dir[] = "/tmp/blued_bond_atomic.XXXXXX";
	char fpath[256], tpath[256];
	struct smp_bond_db db, db2;
	struct smp_bond b, good_bond;
	struct stat st, st_after;
	uint8_t *prior_file, *after_file;
	int dir_fd, fd, rfd, bad;

	ATF_REQUIRE(mkdtemp(dir) != NULL);
	snprintf(fpath, sizeof(fpath), "%s/bonds", dir);
	snprintf(tpath, sizeof(tpath), "%s/bonds.tmp", dir);

	dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(dir_fd >= 0);
	fd = open(fpath, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	ATF_REQUIRE(fd >= 0);

	memset(&db, 0, sizeof(db));
	db.fd = fd;
	smp_bond_db_set_atomic(&db, dir_fd, fpath);
	ATF_REQUIRE_EQ(db.dir_fd, dir_fd);
	ATF_CHECK(strcmp(db.file_name, "bonds") == 0);

	/* Good save (one bond) through the atomic path. */
	memset(&b, 0, sizeof(b));
	memcpy(b.addr, addr_a, 6);
	b.addr_type = BDADDR_LE_PUBLIC;
	memset(b.ltk, 0x5C, 16);
	b.has_ltk = true;
	ATF_REQUIRE_EQ(smp_bond_db_store(&db, &b), 0);
	ATF_REQUIRE_EQ(db.count, 1);
	good_bond = b;

	rfd = open(fpath, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(rfd >= 0);
	ATF_REQUIRE_EQ(fstat(rfd, &st), 0);
	ATF_REQUIRE(st.st_size > 0);
	prior_file = malloc((size_t)st.st_size);
	ATF_REQUIRE(prior_file != NULL);
	ATF_REQUIRE_EQ(pread(rfd, prior_file, (size_t)st.st_size, 0),
	    st.st_size);
	memset(&db2, 0, sizeof(db2));
	smp_bond_db_set_atomic(&db2, dir_fd, fpath);
	ATF_REQUIRE_EQ(smp_bond_db_load(&db2, rfd), 0);
	ATF_CHECK_EQ_MSG(db2.count, 1, "good atomic save must load one bond");
	ATF_CHECK_EQ(memcmp(&db2.bonds[0], &good_bond,
	    sizeof(good_bond)), 0);
	close(rfd);

	ATF_CHECK_MSG(stat(tpath, &st) != 0,
	    "atomic save must not leave a .tmp file");

	/*
	 * Simulate an interrupted save: aim dir_fd at a closed fd so the temp
	 * openat() fails (EBADF -- root-proof).  The save must fail and leave
	 * the prior good bond file byte-for-byte intact.
	 */
	bad = dup(dir_fd);
	ATF_REQUIRE(bad >= 0);
	close(bad);
	db.dir_fd = bad;
	memcpy(b.addr, addr_b, 6);
	ATF_CHECK_EQ(smp_bond_db_store(&db, &b), -1);
	ATF_CHECK_EQ_MSG(db.count, 1,
	    "failed save must roll back the in-memory mutation");
	ATF_CHECK_EQ(memcmp(&db.bonds[0], &good_bond,
	    sizeof(good_bond)), 0);
	ATF_CHECK_EQ(memcmp(&db.bonds[1],
	    (uint8_t[sizeof(db.bonds[1])]){0}, sizeof(db.bonds[1])), 0);
	db.dir_fd = dir_fd;		/* restore */

	rfd = open(fpath, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(rfd >= 0);
	ATF_REQUIRE_EQ(fstat(rfd, &st_after), 0);
	ATF_REQUIRE_EQ(st_after.st_size, st.st_size);
	after_file = malloc((size_t)st_after.st_size);
	ATF_REQUIRE(after_file != NULL);
	ATF_REQUIRE_EQ(pread(rfd, after_file, (size_t)st_after.st_size, 0),
	    st_after.st_size);
	ATF_CHECK_EQ_MSG(memcmp(after_file, prior_file,
	    (size_t)st.st_size), 0,
	    "failed atomic save must preserve every encrypted-file byte");
	memset(&db2, 0, sizeof(db2));
	smp_bond_db_set_atomic(&db2, dir_fd, fpath);
	ATF_REQUIRE_EQ(smp_bond_db_load(&db2, rfd), 0);
	ATF_CHECK_EQ_MSG(db2.count, 1,
	    "failed save must leave prior good file intact (1 bond)");
	if (db2.count == 1)
		ATF_CHECK_EQ(memcmp(&db2.bonds[0], &good_bond,
		    sizeof(good_bond)), 0);
	close(rfd);
	ATF_CHECK_MSG(stat(tpath, &st_after) != 0,
	    "failed atomic save must not leave a .tmp file");
	free(after_file);
	free(prior_file);

	close(fd);
	close(dir_fd);
	unlink(fpath);
	strlcat(fpath, ".key", sizeof(fpath));
	unlink(fpath);
	rmdir(dir);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_bond_identity_root_fail_closed);
	ATF_TP_ADD_TC(tp, test_bond_db_atomic_write_preserves_prior);
	ATF_TP_ADD_TC(tp, test_ctkd_not_sc);
	ATF_TP_ADD_TC(tp, test_ctkd_no_ltk);
	ATF_TP_ADD_TC(tp, test_ctkd_not_mitm);
	ATF_TP_ADD_TC(tp, test_ctkd_ct2_vs_legacy_differ);
	ATF_TP_ADD_TC(tp, test_rpa_matches_spec_vector);
	ATF_TP_ADD_TC(tp, test_rpa_matches_non_rpa);
	ATF_TP_ADD_TC(tp, test_rpa_matches_wrong_irk);
	ATF_TP_ADD_TC(tp, test_generate_rpa_roundtrip);
	ATF_TP_ADD_TC(tp, test_generate_rpa_retries_forbidden_prand);
	ATF_TP_ADD_TC(tp, test_generate_rpa_forbidden_prand_bound);
	ATF_TP_ADD_TC(tp, test_find_bond_exact_and_miss);
	ATF_TP_ADD_TC(tp, test_find_bond_rpa_resolved);
	ATF_TP_ADD_TC(tp, test_ensure_local_irk);
	ATF_TP_ADD_TC(tp, test_bond_db_store_append_update);
	ATF_TP_ADD_TC(tp, test_bond_db_store_evict_when_full);
	ATF_TP_ADD_TC(tp, test_bond_db_save_no_fd);
	ATF_TP_ADD_TC(tp, test_bond_db_save_metadata_guards);
	ATF_TP_ADD_TC(tp, test_bond_db_v4_roundtrip);
	ATF_TP_ADD_TC(tp, test_bond_db_load_garbage);
	ATF_TP_ADD_TC(tp, test_bond_db_load_trunc_enc_header);
	ATF_TP_ADD_TC(tp, test_bond_db_load_unknown_version);
	ATF_TP_ADD_TC(tp, test_bond_db_load_v4_zero_ctlen);
	ATF_TP_ADD_TC(tp, test_bond_db_load_v4_bad_ciphertext);
	ATF_TP_ADD_TC(tp, test_bond_db_load_v4_trunc_header);
	ATF_TP_ADD_TC(tp, test_bond_db_load_v4_trunc_ct);
	ATF_TP_ADD_TC(tp, test_bond_db_load_count_reject);
	ATF_TP_ADD_TC(tp, test_bond_db_load_payload_too_small);
	ATF_TP_ADD_TC(tp, test_bond_db_load_payload_runt);
	ATF_TP_ADD_TC(tp, test_bond_db_load_irk_trailer_absent);
	ATF_TP_ADD_TC(tp, test_receive_peer_keys_id_and_sign);
	ATF_TP_ADD_TC(tp, test_receive_peer_keys_reserved_id_addr_type);
	ATF_TP_ADD_TC(tp, test_receive_peer_keys_timeout_break);
	ATF_TP_ADD_TC(tp, test_receive_peer_keys_invalid_transport);
	ATF_TP_ADD_TC(tp, test_distribute_init_keys_legacy_all);
	ATF_TP_ADD_TC(tp, test_distribute_init_keys_sc_skips_enc);
	ATF_TP_ADD_TC(tp, test_distribute_id_addr_type_wire_encoding);
	ATF_TP_ADD_TC(tp, test_bond_cccds_save_restore);
	ATF_TP_ADD_TC(tp, test_bond_cccds_save_overflow);
	ATF_TP_ADD_TC(tp, test_bond_restore_cccds_overread_clamped);
	ATF_TP_ADD_TC(tp, test_persist_sign_counter);
	ATF_TP_ADD_TC(tp, test_bond_mutation_flush_rollbacks);
	ATF_TP_ADD_TC(tp, test_distribute_init_keys_null_bonddb);
	ATF_TP_ADD_TC(tp, test_bond_record_public_input_guards);

	return (atf_no_error());
}
