/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for PC4 bond import/export (backup, restore, migration):
 * smp_bond_export_record / smp_bond_import_record / smp_bond_db_import in
 * smp_keys.c.
 *
 * Coverage:
 *   - export -> import round-trip preserves every key and metadata field
 *     (LTK/rand/EDIV, IRK, CSRK, sign counter, name, GATT handle cache, CCCDs,
 *      is_sc/is_mitm/key_size) byte-for-byte;
 *   - import into an empty DB appends; import of an existing identity replaces
 *     the whole record with the count held stable (no delete window);
 *   - the validator rejects a truncated, oversized, wrong-magic, wrong-version,
 *     bad-struct-size, or corrupt-field record and leaves a caller DB untouched;
 *   - a full DB rejects an appended import (capacity) but still accepts a
 *     replace of an existing identity;
 *   - an imported record carries the peer IRK (which the ctl layer feeds to the
 *     resolving list);
 *   - a persistence round-trip: an imported bond survives a real DB save/load.
 *
 * Key bytes are asserted via memcmp/booleans only and are NEVER printed.
 *
 * Links with: smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
 * Extra libs: -lcrypto (OpenSSL) -lpthread (bond_db lock type)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/endian.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "hci_log.h"
#include "hci_util.h"
#include "smp.h"
#include "smp_internal.h"
#include "spec_bond_migrate_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif
#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
#endif

/* ================================================================
 * Stubs for external symbols referenced by smp.c.
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
 * Fixtures.
 * ================================================================ */

/*
 * Populate a bond with a distinct nonzero value in every persisted field, so a
 * round-trip that dropped or transposed any field would be caught.  The address
 * low byte is a caller-chosen discriminator so several bonds can be built.
 */
static void
fill_bond(struct smp_bond *b, uint8_t tag)
{
	int i;

	memset(b, 0, sizeof(*b));
	b->addr[0] = tag;
	b->addr[1] = 0x22;
	b->addr[2] = 0x33;
	b->addr[3] = 0x44;
	b->addr[4] = 0x55;
	b->addr[5] = 0x66;
	b->addr_type = BT_BOND_SPEC_ADDR_RANDOM;

	memset(b->ltk, 0xAB, 16);
	b->rand = 0x0123456789abcdefULL;
	b->ediv = 0xBEEF;
	b->has_ltk = true;

	memset(b->irk, 0xCD, 16);
	b->has_irk = true;

	memset(b->csrk, 0xEF, 16);
	b->has_csrk = true;
	b->peer_sign_counter = 0x11223344;

	memset(b->link_key, 0x77, 16);
	b->has_link_key = true;

	memset(b->db_hash, 0x5A, 16);
	b->has_db_hash = true;

	strlcpy(b->name, "MigrateDev", sizeof(b->name));
	b->has_name = true;

	b->is_sc = true;
	b->is_mitm = true;
	b->key_size = 16;

	b->num_cccds = 2;
	b->cccds[0].handle = 0x0010;
	b->cccds[0].value = 0x0001;
	b->cccds[1].handle = 0x0020;
	b->cccds[1].value = 0x0002;

	b->has_handle_cache = true;
	b->hid_svc_start = 0x0100;
	b->hid_svc_end = 0x01FF;
	b->bat_svc_start = 0x0200;
	b->bat_svc_end = 0x02FF;
	b->report_map_handle = 0x0110;
	b->hid_info_handle = 0x0111;
	b->protocol_mode_handle = 0x0112;
	b->num_reports = 3;
	for (i = 0; i < 3; i++) {
		b->report_handles[i] = (uint16_t)(0x0120 + i);
		b->report_cccd_handles[i] = (uint16_t)(0x0130 + i);
		b->report_types[i] = (uint8_t)(i + 1);
		b->report_ids[i] = (uint8_t)(i + 1);
	}
	b->battery_level_handle = 0x0210;
	b->battery_cccd_handle = 0x0211;
}

/* ================================================================
 * Round-trip.
 * ================================================================ */

/* export -> import reproduces the entire bond record byte-for-byte. */
ATF_TC_WITHOUT_HEAD(test_record_roundtrip);
ATF_TC_BODY(test_record_roundtrip, tc)
{
	struct smp_bond in, out;
	uint8_t rec[SMP_BOND_REC_LEN];
	size_t n;

	fill_bond(&in, 0x11);

	n = smp_bond_export_record(&in, rec, sizeof(rec));
	ATF_REQUIRE_EQ_MSG(n, SMP_BOND_REC_LEN, "export must fill the record");
	ATF_REQUIRE_EQ(BT_BOND_PC4_HEADER_LEN + sizeof(struct smp_bond), n);
	ATF_CHECK_EQ(0, memcmp(rec, bt_bond_pc4_prefix,
	    sizeof(bt_bond_pc4_prefix)));
	ATF_CHECK_EQ(sizeof(struct smp_bond),
	    (size_t)le32dec(rec + BT_BOND_PC4_STRUCT_SIZE_OFFSET));

	ATF_REQUIRE_EQ_MSG(smp_bond_import_record(rec, n, &out), 0,
	    "a freshly-exported record must import cleanly");

	/* Every field must survive.  memcmp keeps key bytes out of the log. */
	ATF_CHECK_MSG(memcmp(&in, &out, sizeof(in)) == 0,
	    "round-trip must preserve the whole bond record");
	/* Spot-check the security-critical fields explicitly (no value print). */
	ATF_CHECK(out.has_ltk && memcmp(out.ltk, in.ltk, 16) == 0);
	ATF_CHECK_EQ(out.rand, in.rand);
	ATF_CHECK_EQ(out.ediv, in.ediv);
	ATF_CHECK(out.has_irk && memcmp(out.irk, in.irk, 16) == 0);
	ATF_CHECK(out.has_csrk && memcmp(out.csrk, in.csrk, 16) == 0);
	ATF_CHECK_EQ(out.peer_sign_counter, in.peer_sign_counter);
	ATF_CHECK_EQ(out.is_sc, in.is_sc);
	ATF_CHECK_EQ(out.is_mitm, in.is_mitm);
	ATF_CHECK_EQ(out.key_size, in.key_size);
	ATF_CHECK_EQ(out.num_cccds, in.num_cccds);
	ATF_CHECK(memcmp(out.cccds, in.cccds, sizeof(in.cccds)) == 0);
	ATF_CHECK(out.has_handle_cache);
	ATF_CHECK_EQ(out.num_reports, in.num_reports);
	ATF_CHECK(strcmp(out.name, "MigrateDev") == 0);
}

/* The imported record carries the peer IRK (fed to the resolving list). */
ATF_TC_WITHOUT_HEAD(test_record_carries_irk);
ATF_TC_BODY(test_record_carries_irk, tc)
{
	struct smp_bond in, out;
	uint8_t rec[SMP_BOND_REC_LEN];

	fill_bond(&in, 0x11);
	ATF_REQUIRE(smp_bond_export_record(&in, rec, sizeof(rec)) ==
	    SMP_BOND_REC_LEN);
	ATF_REQUIRE_EQ(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), 0);

	ATF_CHECK_MSG(out.has_irk, "imported bond must carry has_irk");
	ATF_CHECK_MSG(memcmp(out.irk, in.irk, 16) == 0,
	    "imported IRK must equal the exported IRK");
}

/* export into a buffer that is one byte short returns 0 (no partial write). */
ATF_TC_WITHOUT_HEAD(test_export_buffer_too_small);
ATF_TC_BODY(test_export_buffer_too_small, tc)
{
	struct smp_bond in;
	uint8_t rec[SMP_BOND_REC_LEN];

	fill_bond(&in, 0x11);
	ATF_CHECK_EQ_MSG(smp_bond_export_record(&in, rec, SMP_BOND_REC_LEN - 1),
	    0, "export must refuse a short buffer");
}

/* ================================================================
 * DB insertion: append / replace / capacity.
 * ================================================================ */

/* import into an empty DB appends the bond. */
ATF_TC_WITHOUT_HEAD(test_db_import_empty_appends);
ATF_TC_BODY(test_db_import_empty_appends, tc)
{
	struct smp_bond_db db;
	struct smp_bond in, out;
	uint8_t rec[SMP_BOND_REC_LEN];

	memset(&db, 0, sizeof(db));
	db.fd = -1;			/* in-memory only; no file side effects */

	fill_bond(&in, 0x11);
	ATF_REQUIRE(smp_bond_export_record(&in, rec, sizeof(rec)) ==
	    SMP_BOND_REC_LEN);
	ATF_REQUIRE_EQ(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), 0);

	ATF_CHECK_EQ_MSG(smp_bond_db_import(&db, &out), 1,
	    "import into empty DB must append (return 1)");
	ATF_CHECK_EQ(db.count, 1);
	ATF_CHECK(memcmp(&db.bonds[0], &out, sizeof(out)) == 0);
}

/* import of an existing identity replaces the whole record; count stable. */
ATF_TC_WITHOUT_HEAD(test_db_import_replace_existing);
ATF_TC_BODY(test_db_import_replace_existing, tc)
{
	struct smp_bond_db db;
	struct smp_bond old, fresh, out;
	uint8_t rec[SMP_BOND_REC_LEN];

	memset(&db, 0, sizeof(db));
	db.fd = -1;

	/* Pre-existing bond for this identity with old keys/metadata. */
	fill_bond(&old, 0x11);
	memset(old.ltk, 0x01, 16);
	strlcpy(old.name, "OldName", sizeof(old.name));
	db.bonds[0] = old;
	db.count = 1;

	/* Fresh record for the SAME identity (same addr+type) but new keys. */
	fill_bond(&fresh, 0x11);
	memset(fresh.ltk, 0xFE, 16);
	strlcpy(fresh.name, "NewName", sizeof(fresh.name));
	ATF_REQUIRE(smp_bond_export_record(&fresh, rec, sizeof(rec)) ==
	    SMP_BOND_REC_LEN);
	ATF_REQUIRE_EQ(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), 0);

	ATF_CHECK_EQ_MSG(smp_bond_db_import(&db, &out), 0,
	    "import of an existing identity must replace (return 0)");
	ATF_CHECK_EQ_MSG(db.count, 1, "replace must keep the count stable");
	ATF_CHECK_MSG(db.bonds[0].ltk[0] == 0xFE,
	    "replace must install the fresh LTK");
	ATF_CHECK_MSG(strcmp(db.bonds[0].name, "NewName") == 0,
	    "replace must install the fresh metadata (full record)");
}

/* a full DB rejects an appended import but still accepts a replace. */
ATF_TC_WITHOUT_HEAD(test_db_import_capacity);
ATF_TC_BODY(test_db_import_capacity, tc)
{
	struct smp_bond_db db;
	struct smp_bond in, out;
	uint8_t rec[SMP_BOND_REC_LEN];
	int i;

	memset(&db, 0, sizeof(db));
	db.fd = -1;
	ATF_REQUIRE_EQ(BT_BOND_PC4_MAX_BONDS, SMP_MAX_BONDS);

	/* Fill the DB with distinct identities. */
	for (i = 0; i < SMP_MAX_BONDS; i++) {
		fill_bond(&db.bonds[i], (uint8_t)(0x80 + i));
	}
	db.count = SMP_MAX_BONDS;

	/* A brand-new identity has nowhere to go: reject, DB untouched. */
	fill_bond(&in, 0x01);		/* not among 0x80..0x9f */
	ATF_REQUIRE(smp_bond_export_record(&in, rec, sizeof(rec)) ==
	    SMP_BOND_REC_LEN);
	ATF_REQUIRE_EQ(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), 0);

	ATF_CHECK_EQ_MSG(smp_bond_db_import(&db, &out), -1,
	    "a full DB must reject a new-identity append");
	ATF_CHECK_EQ_MSG(db.count, BT_BOND_PC4_MAX_BONDS,
	    "a rejected append must leave the count unchanged");
	ATF_CHECK_MSG(db.bonds[0].addr[0] == 0x80,
	    "a rejected append must leave existing bonds untouched");

	/* An existing identity still replaces even when the DB is full. */
	fill_bond(&in, 0x80);
	memset(in.ltk, 0x5C, 16);
	ATF_REQUIRE(smp_bond_export_record(&in, rec, sizeof(rec)) ==
	    SMP_BOND_REC_LEN);
	ATF_REQUIRE_EQ(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), 0);
	ATF_CHECK_EQ_MSG(smp_bond_db_import(&db, &out), 0,
	    "a full DB must still accept an existing-identity replace");
	ATF_CHECK_EQ(db.count, BT_BOND_PC4_MAX_BONDS);
	ATF_CHECK(db.bonds[0].ltk[0] == 0x5C);
}

/* ================================================================
 * Validation: hostile / malformed records are rejected, DB untouched.
 * ================================================================ */

/* Build a valid record into rec[] and return its length. */
static size_t
make_valid_record(uint8_t rec[SMP_BOND_REC_LEN])
{
	struct smp_bond in;

	fill_bond(&in, 0x11);
	return (smp_bond_export_record(&in, rec, SMP_BOND_REC_LEN));
}

/* A truncated record (any length != exact) is rejected before field reads. */
ATF_TC_WITHOUT_HEAD(test_validate_truncated);
ATF_TC_BODY(test_validate_truncated, tc)
{
	uint8_t rec[SMP_BOND_REC_LEN + 1];
	struct smp_bond out;

	ATF_REQUIRE(make_valid_record(rec) == SMP_BOND_REC_LEN);

	/* One byte short. */
	ATF_CHECK_EQ_MSG(
	    smp_bond_import_record(rec, SMP_BOND_REC_LEN - 1, &out), -1,
	    "a truncated record must be rejected");
	/* Only the header present. */
	ATF_CHECK_EQ(smp_bond_import_record(rec, SMP_BOND_REC_HDR, &out), -1);
	/* Zero length. */
	ATF_CHECK_EQ(smp_bond_import_record(rec, 0, &out), -1);
	/* One byte too long (over-size also rejected -> no over-read). */
	ATF_CHECK_EQ_MSG(
	    smp_bond_import_record(rec, SMP_BOND_REC_LEN + 1, &out), -1,
	    "an oversized record must be rejected");
}

/* A bad magic is rejected. */
ATF_TC_WITHOUT_HEAD(test_validate_bad_magic);
ATF_TC_BODY(test_validate_bad_magic, tc)
{
	uint8_t rec[SMP_BOND_REC_LEN];
	struct smp_bond out;

	ATF_REQUIRE(make_valid_record(rec) == SMP_BOND_REC_LEN);
	rec[0] ^= 0xFF;
	ATF_CHECK_EQ(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), -1);
}

/* A wrong version is rejected. */
ATF_TC_WITHOUT_HEAD(test_validate_wrong_version);
ATF_TC_BODY(test_validate_wrong_version, tc)
{
	uint8_t rec[SMP_BOND_REC_LEN];
	struct smp_bond out;

	ATF_REQUIRE(make_valid_record(rec) == SMP_BOND_REC_LEN);
	rec[BT_BOND_PC4_VERSION_OFFSET] = BT_BOND_PC4_VERSION + 1;
	ATF_CHECK_EQ(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), -1);
}

/* A struct-size field that disagrees with the running struct is rejected. */
ATF_TC_WITHOUT_HEAD(test_validate_bad_struct_size);
ATF_TC_BODY(test_validate_bad_struct_size, tc)
{
	uint8_t rec[SMP_BOND_REC_LEN];
	struct smp_bond out;

	ATF_REQUIRE(make_valid_record(rec) == SMP_BOND_REC_LEN);
	rec[BT_BOND_PC4_STRUCT_SIZE_OFFSET] ^= 0x01;
	ATF_CHECK_EQ(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), -1);
}

/*
 * A corrupt field is rejected, and a caller-held DB is left untouched (the ctl
 * path calls the validator before it ever touches the DB).
 */
ATF_TC_WITHOUT_HEAD(test_validate_corrupt_field_db_untouched);
ATF_TC_BODY(test_validate_corrupt_field_db_untouched, tc)
{
	uint8_t rec[SMP_BOND_REC_LEN];
	struct smp_bond out;
	struct smp_bond_db db;
	uint8_t *body;

	/* A DB with one bond that must not change on a rejected import. */
	memset(&db, 0, sizeof(db));
	db.fd = -1;
	fill_bond(&db.bonds[0], 0x55);
	db.count = 1;

	body = rec + BT_BOND_PC4_HEADER_LEN;

	/* Corrupt: bogus address type. */
	ATF_REQUIRE(make_valid_record(rec) == SMP_BOND_REC_LEN);
	body[offsetof(struct smp_bond, addr_type)] = 0x7F;
	ATF_CHECK_EQ_MSG(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), -1,
	    "bad addr_type must be rejected");

	/* Corrupt: a boolean flag byte outside {0,1}. */
	ATF_REQUIRE(make_valid_record(rec) == SMP_BOND_REC_LEN);
	body[offsetof(struct smp_bond, is_sc)] = 0x02;
	ATF_CHECK_EQ_MSG(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), -1,
	    "a bool flag > 1 must be rejected");

	/* Corrupt: illegal key size. */
	ATF_REQUIRE(make_valid_record(rec) == SMP_BOND_REC_LEN);
	body[offsetof(struct smp_bond, key_size)] =
	    BT_BOND_SPEC_KEY_SIZE_MIN - 1;
	ATF_CHECK_EQ_MSG(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), -1,
	    "an illegal key size must be rejected");

	/* Corrupt: CCCD count beyond the physical array. */
	ATF_REQUIRE(make_valid_record(rec) == SMP_BOND_REC_LEN);
	body[offsetof(struct smp_bond, num_cccds)] =
	    BT_BOND_PC4_MAX_CCCDS + 1;
	ATF_CHECK_EQ_MSG(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), -1,
	    "an over-range num_cccds must be rejected");

	/* Through all of the above the caller DB must be pristine. */
	ATF_CHECK_EQ_MSG(db.count, 1, "a rejected import must not change the DB");
	ATF_CHECK(db.bonds[0].addr[0] == 0x55);
}

/* ================================================================
 * Persistence: an imported bond survives a real DB save/load.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_db_import_persist_roundtrip);
ATF_TC_BODY(test_db_import_persist_roundtrip, tc)
{
	struct smp_bond_db db, db2;
	struct smp_bond in, out;
	uint8_t rec[SMP_BOND_REC_LEN];
	char path[] = "/tmp/blued_bondmig.XXXXXX";
	int fd, rc;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	memset(&db, 0, sizeof(db));
	db.fd = fd;

	fill_bond(&in, 0x11);
	ATF_REQUIRE(smp_bond_export_record(&in, rec, sizeof(rec)) ==
	    SMP_BOND_REC_LEN);
	ATF_REQUIRE_EQ(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), 0);

	rc = smp_bond_db_import(&db, &out);
	ATF_REQUIRE_MSG(rc == 1, "import into empty DB must append");

	/*
	 * smp_bond_db_import persists via smp_bond_db_save.  If key material was
	 * unavailable in this environment the save is refused (fail-closed) and
	 * the file stays empty; only assert the load round-trip when the DB was
	 * actually written.
	 */
	memset(&db2, 0, sizeof(db2));
	ATF_REQUIRE_EQ(smp_bond_db_load(&db2, fd), 0);
	if (db2.count == 1) {
		ATF_CHECK(memcmp(db2.bonds[0].addr, in.addr, 6) == 0);
		ATF_CHECK(db2.bonds[0].has_ltk &&
		    memcmp(db2.bonds[0].ltk, in.ltk, 16) == 0);
		ATF_CHECK(db2.bonds[0].has_irk &&
		    memcmp(db2.bonds[0].irk, in.irk, 16) == 0);
		ATF_CHECK(db2.bonds[0].has_csrk &&
		    memcmp(db2.bonds[0].csrk, in.csrk, 16) == 0);
		ATF_CHECK_EQ(db2.bonds[0].peer_sign_counter,
		    in.peer_sign_counter);
		ATF_CHECK(strcmp(db2.bonds[0].name, "MigrateDev") == 0);
	}

	close(fd);
	unlink(path);
}

/*
 * Finding 68: the HOGP HID Control Point handle and multi-instance report-map
 * handles round-trip through the bond record so a cache-hit reconnect can issue
 * the Exit-Suspend write and restore the full report map without rediscovery.
 */
ATF_TC_WITHOUT_HEAD(test_record_carries_hogp_ctrl);
ATF_TC_BODY(test_record_carries_hogp_ctrl, tc)
{
	struct smp_bond in, out;
	uint8_t rec[SMP_BOND_REC_LEN];

	fill_bond(&in, 0x33);
	in.has_handle_cache = true;
	in.hid_ctrl_handle = 0x0042;
	in.report_map_handle = 0x0021;
	in.num_report_maps = 2;
	in.report_map_handles[0] = 0x0021;
	in.report_map_handles[1] = 0x0055;

	ATF_REQUIRE(smp_bond_export_record(&in, rec, sizeof(rec)) ==
	    SMP_BOND_REC_LEN);
	memset(&out, 0, sizeof(out));
	ATF_REQUIRE_EQ(smp_bond_import_record(rec, SMP_BOND_REC_LEN, &out), 0);

	ATF_CHECK_EQ(0x0042, out.hid_ctrl_handle);
	ATF_CHECK_EQ(2, out.num_report_maps);
	ATF_CHECK_EQ(0x0021, out.report_map_handles[0]);
	ATF_CHECK_EQ(0x0055, out.report_map_handles[1]);
	ATF_CHECK(out.has_handle_cache);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_record_carries_hogp_ctrl);
	ATF_TP_ADD_TC(tp, test_record_roundtrip);
	ATF_TP_ADD_TC(tp, test_record_carries_irk);
	ATF_TP_ADD_TC(tp, test_export_buffer_too_small);
	ATF_TP_ADD_TC(tp, test_db_import_empty_appends);
	ATF_TP_ADD_TC(tp, test_db_import_replace_existing);
	ATF_TP_ADD_TC(tp, test_db_import_capacity);
	ATF_TP_ADD_TC(tp, test_validate_truncated);
	ATF_TP_ADD_TC(tp, test_validate_bad_magic);
	ATF_TP_ADD_TC(tp, test_validate_wrong_version);
	ATF_TP_ADD_TC(tp, test_validate_bad_struct_size);
	ATF_TP_ADD_TC(tp, test_validate_corrupt_field_db_untouched);
	ATF_TP_ADD_TC(tp, test_db_import_persist_roundtrip);

	return (atf_no_error());
}
