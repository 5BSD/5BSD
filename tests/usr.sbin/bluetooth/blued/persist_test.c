/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Tests for the operational-state persistence engine (blued_persist).
 *
 * For every artifact: populate -> save -> simulate restart (fresh load) and
 * assert the restored state matches; a corrupt / truncated / wrong-magic /
 * wrong-version file is rejected safely (defaults, no crash/overflow); the GATT-cache
 * reuse-vs-invalidate decision follows the Database Hash; and a partial temp
 * file never replaces a good file (atomic-write crash safety).
 *
 * Each test case creates a private, guaranteed-empty directory under its
 * working directory and uses that (opened as a fd) as the persist directory,
 * so the artifacts are isolated from every other case and from whatever the
 * program happens to be run in.
 */

#include <sys/stat.h>

#include <atf-c.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blued_persist.h"
#include "config.h"

/*
 * write/read wrap seam.
 *
 * Each direction has a "skip" count of calls to pass through untouched,
 * followed by a "fault" count of calls failed with a chosen errno.  The skip
 * count is what lets a fault be aimed at a SPECIFIC IO loop: an engine save
 * issues one write for the 28-byte header and then one for the payload, and
 * a load likewise reads the header first, so
 *
 *	skip = 0	-> the fault lands on the header loop
 *	skip = 1	-> the fault lands on the payload loop
 *
 * Without the skip, faulting N calls only ever exercises the header loops:
 * two EINTRs were both consumed there and the payload retry arms in
 * blued_persist.c were never entered at all.
 *
 * With errno EINTR the engine's short-IO loops must retry transparently; with
 * a hard errno (EIO) the save must fail and leave the committed file intact.
 */
ssize_t __real_write(int, const void *, size_t);
ssize_t __real_read(int, void *, size_t);
ssize_t __wrap_write(int, const void *, size_t);
ssize_t __wrap_read(int, void *, size_t);

static int write_skip_pending;
static int read_skip_pending;
static int eintr_writes_pending;
static int eintr_reads_pending;
static int fault_write_errno = EINTR;
static int fault_read_errno = EINTR;

/* Aim the next fault at the Nth following write/read (0 == the very next). */
static void
fault_writes(int skip, int count, int err)
{

	write_skip_pending = skip;
	eintr_writes_pending = count;
	fault_write_errno = err;
}

static void
fault_reads(int skip, int count, int err)
{

	read_skip_pending = skip;
	eintr_reads_pending = count;
	fault_read_errno = err;
}

ssize_t
__wrap_write(int fd, const void *buf, size_t len)
{

	if (write_skip_pending > 0) {
		write_skip_pending--;
		return (__real_write(fd, buf, len));
	}
	if (eintr_writes_pending > 0) {
		eintr_writes_pending--;
		errno = fault_write_errno;
		return (-1);
	}
	return (__real_write(fd, buf, len));
}

ssize_t
__wrap_read(int fd, void *buf, size_t len)
{

	if (read_skip_pending > 0) {
		read_skip_pending--;
		return (__real_read(fd, buf, len));
	}
	if (eintr_reads_pending > 0) {
		eintr_reads_pending--;
		errno = fault_read_errno;
		return (-1);
	}
	return (__real_read(fd, buf, len));
}

/*
 * Open this test case's private persist directory.
 *
 * Using the cwd directly made the suite cwd-dependent: every case dropped its
 * artifacts ("settings", "gattcache", ...) into the shared directory, so
 * running the program twice in one place — or from the objdir, which already
 * holds a stale "settings" — made the reject-when-absent cases (e.g.
 * missing_file_rejected) find a leftover file and pass/fail on history rather
 * than on behaviour.  Each case body is its own process, so a directory
 * created lazily on first use here is private to that case and guaranteed
 * empty; it is still made under the cwd so kyua's per-test work directory
 * reaps it.
 */
static int
open_cwd_dir(void)
{
	static char dir[] = "blued-persist.XXXXXX";
	static bool made;
	int fd;

	if (!made) {
		ATF_REQUIRE_MSG(mkdtemp(dir) != NULL,
		    "mkdtemp: %s", strerror(errno));
		made = true;
	}
	fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	return (fd);
}

/* ================================================================
 * CRC32 sanity: known vector and change detection.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(crc32_known_vector);
ATF_TC_BODY(crc32_known_vector, tc)
{
	/* CRC-32/ISO-HDLC of "123456789" is 0xCBF43926. */
	uint32_t c = blued_persist_crc32(0, "123456789", 9);

	ATF_CHECK_EQ_MSG(0xCBF43926u, c, "crc=%08x", c);
	ATF_CHECK(blued_persist_crc32(0, "A", 1) !=
	    blued_persist_crc32(0, "B", 1));
}

/* ================================================================
 * Adapter settings: round trip.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(settings_round_trip);
ATF_TC_BODY(settings_round_trip, tc)
{
	struct blued_persist_settings s, r;
	int d = open_cwd_dir();

	memset(&s, 0, sizeof(s));
	strlcpy(s.name, "blued-adapter", sizeof(s.name));
	s.privacy = 1;
	s.privacy_mode = 1;
	s.discoverable = 1;
	s.connectable = 1;
	s.io_capability = 4;
	s.bondable = 1;
	s.sc_mode = BLUED_SC_ON;
	s.min_key_size = 16;
	s.conn_interval_min = 24;
	s.conn_interval_max = 40;
	s.conn_latency = 0;
	s.supervision_timeout = 42;
	s.rpa_timeout = 900;

	ATF_REQUIRE_EQ(0, blued_persist_settings_save(d, &s));

	/* Fresh load == simulate restart. */
	memset(&r, 0xAA, sizeof(r));
	ATF_REQUIRE_EQ(0, blued_persist_settings_load(d, &r));
	ATF_CHECK_STREQ("blued-adapter", r.name);
	ATF_CHECK_EQ(1, r.privacy);
	ATF_CHECK_EQ(1, r.privacy_mode);
	ATF_CHECK_EQ(1, r.discoverable);
	ATF_CHECK_EQ(4, r.io_capability);
	ATF_CHECK_EQ(16, r.min_key_size);
	ATF_CHECK_EQ(24, r.conn_interval_min);
	ATF_CHECK_EQ(40, r.conn_interval_max);
	ATF_CHECK_EQ(42, r.supervision_timeout);
	ATF_CHECK_EQ(900, r.rpa_timeout);
	close(d);
}

/* ================================================================
 * EINTR mid-save / mid-load: the short-IO loops retry, not fail.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(save_load_eintr_retry);
ATF_TC_BODY(save_load_eintr_retry, tc)
{
	struct blued_persist_settings s, r;
	int d = open_cwd_dir();

	memset(&s, 0, sizeof(s));
	strlcpy(s.name, "eintr-adapter", sizeof(s.name));
	s.privacy = 1;
	s.io_capability = 3;
	s.min_key_size = 16;
	s.rpa_timeout = 300;

	/*
	 * Arm 1: interrupt the very first write (the HEADER write) twice.
	 * Exercises persist_write_all's EINTR retry on the header.
	 */
	fault_writes(0, 2, EINTR);
	ATF_REQUIRE_EQ(0, blued_persist_settings_save(d, &s));
	ATF_CHECK_EQ(0, eintr_writes_pending);

	memset(&r, 0xAA, sizeof(r));
	fault_reads(0, 2, EINTR);
	ATF_REQUIRE_EQ(0, blued_persist_settings_load(d, &r));
	ATF_CHECK_EQ(0, eintr_reads_pending);
	ATF_CHECK_STREQ("eintr-adapter", r.name);

	/*
	 * Arm 2: let the header IO through and land the EINTR on the PAYLOAD
	 * loop specifically.  Previously both injected EINTRs were swallowed
	 * by the header loops, so the payload retry arms — persist_write_all's
	 * loop for the records buffer and blued_persist_load_records' second
	 * "while ((uint32_t)off < payload_len)" read loop with its
	 * "if (errno == EINTR) continue" — were never entered; deleting either
	 * EINTR continue left this case green.
	 */
	strlcpy(s.name, "eintr-payload", sizeof(s.name));
	s.rpa_timeout = 301;
	fault_writes(1, 2, EINTR);	/* skip header write, fault payload */
	ATF_REQUIRE_EQ(0, blued_persist_settings_save(d, &s));
	ATF_CHECK_EQ(0, eintr_writes_pending);
	ATF_CHECK_EQ(0, write_skip_pending);

	memset(&r, 0xAA, sizeof(r));
	fault_reads(1, 2, EINTR);	/* skip header read, fault payload */
	ATF_REQUIRE_EQ(0, blued_persist_settings_load(d, &r));
	ATF_CHECK_EQ(0, eintr_reads_pending);
	ATF_CHECK_EQ(0, read_skip_pending);

	ATF_CHECK_STREQ("eintr-payload", r.name);
	ATF_CHECK_EQ(1, r.privacy);
	ATF_CHECK_EQ(3, r.io_capability);
	ATF_CHECK_EQ(16, r.min_key_size);
	ATF_CHECK_EQ(301, r.rpa_timeout);
	close(d);
}

/* ================================================================
 * Device cache: round trip, including RPA-resolved identity.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(devcache_round_trip);
ATF_TC_BODY(devcache_round_trip, tc)
{
	struct blued_persist_device in[2], out[BLUED_PERSIST_MAX_DEVICES];
	struct blued_persist_device *f;
	uint32_t n = 0;
	int d = open_cwd_dir();

	memset(in, 0, sizeof(in));
	memcpy(in[0].addr, "\x01\x02\x03\x04\x05\x06", 6);
	in[0].addr_type = 1;
	in[0].has_name = 1;
	strlcpy(in[0].name, "Keyboard", sizeof(in[0].name));
	in[0].is_hogp = 1;
	in[0].auto_connect = 1;
	in[0].bonded = 1;
	in[0].has_appearance = 1;
	in[0].appearance = 0x03C1;	/* HID Keyboard */
	in[0].last_seen = 1234567890;

	memcpy(in[1].addr, "\xAA\xBB\xCC\x40\x00\x00", 6);
	in[1].addr_type = 2;		/* random */
	in[1].has_identity = 1;
	memcpy(in[1].identity_addr, "\x11\x22\x33\x44\x55\x66", 6);
	in[1].identity_addr_type = 1;

	ATF_REQUIRE_EQ(0, blued_persist_devcache_save(d, in, 2));

	memset(out, 0xEE, sizeof(out));
	ATF_REQUIRE_EQ(0, blued_persist_devcache_load(d, out, &n));
	ATF_REQUIRE_EQ(2, n);

	f = blued_persist_devcache_find(out, n,
	    (const uint8_t *)"\x01\x02\x03\x04\x05\x06", 1);
	ATF_REQUIRE(f != NULL);
	ATF_CHECK_STREQ("Keyboard", f->name);
	ATF_CHECK_EQ(1, f->is_hogp);
	ATF_CHECK_EQ(0x03C1, f->appearance);
	ATF_CHECK_EQ(1234567890, f->last_seen);

	f = blued_persist_devcache_find(out, n,
	    (const uint8_t *)"\xAA\xBB\xCC\x40\x00\x00", 2);
	ATF_REQUIRE(f != NULL);
	ATF_CHECK_EQ(1, f->has_identity);
	ATF_CHECK_EQ(0, memcmp(f->identity_addr,
	    "\x11\x22\x33\x44\x55\x66", 6));
	close(d);
}

/* ================================================================
 * GATT cache: round trip + reuse-vs-invalidate on DB Hash.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(gattcache_hash_reuse_invalidate);
ATF_TC_BODY(gattcache_hash_reuse_invalidate, tc)
{
	struct blued_persist_gatt_device in[1], out[BLUED_PERSIST_MAX_GATT_DEVICES];
	struct blued_persist_gatt_device *g;
	uint8_t same_hash[16], diff_hash[16];
	uint32_t n = 0;
	int d = open_cwd_dir();

	memset(in, 0, sizeof(in));
	memcpy(in[0].addr, "\xDE\xAD\xBE\xEF\x00\x01", 6);
	in[0].addr_type = 1;
	in[0].has_db_hash = 1;
	memset(same_hash, 0x5A, sizeof(same_hash));
	memcpy(in[0].db_hash, same_hash, 16);
	in[0].nattrs = 2;
	in[0].attrs[0].handle = 0x0010;
	in[0].attrs[0].group_end = 0x0015;
	in[0].attrs[0].uuid16 = 0x1812;	/* HID service */
	in[0].attrs[0].type = BLUED_PERSIST_ATTR_SERVICE;
	in[0].attrs[1].handle = 0x0012;
	in[0].attrs[1].value_handle = 0x0013;
	in[0].attrs[1].uuid16 = 0x2A4D;	/* Report */
	in[0].attrs[1].type = BLUED_PERSIST_ATTR_CHAR;
	in[0].attrs[1].properties = 0x12;

	ATF_REQUIRE_EQ(0, blued_persist_gattcache_save(d, in, 1));

	memset(out, 0, sizeof(out));
	ATF_REQUIRE_EQ(0, blued_persist_gattcache_load(d, out, &n));
	ATF_REQUIRE_EQ(1, n);

	g = blued_persist_gattcache_find(out, n,
	    (const uint8_t *)"\xDE\xAD\xBE\xEF\x00\x01", 1);
	ATF_REQUIRE(g != NULL);
	ATF_CHECK_EQ(2, g->nattrs);
	ATF_CHECK_EQ(0x0013, g->attrs[1].value_handle);

	/* Matching hash -> reuse cached handles (skip rediscovery). */
	ATF_CHECK(blued_persist_gatt_hash_matches(g, same_hash));

	/* Changed hash -> invalidate + rediscover. */
	memset(diff_hash, 0x5A, sizeof(diff_hash));
	diff_hash[7] ^= 0xFF;
	ATF_CHECK(!blued_persist_gatt_hash_matches(g, diff_hash));

	/* An entry without a stored hash is never reused. */
	g->has_db_hash = 0;
	ATF_CHECK(!blued_persist_gatt_hash_matches(g, same_hash));
	close(d);
}

/* ================================================================
 * Advertising configuration: round trip.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(advconfig_round_trip);
ATF_TC_BODY(advconfig_round_trip, tc)
{
	struct blued_persist_adv_set in[1], out[BLUED_PERSIST_MAX_ADV_SETS];
	uint32_t n = 0;
	int d = open_cwd_dir();

	memset(in, 0, sizeof(in));
	in[0].handle = 0;
	in[0].enabled = 1;
	in[0].own_addr_type = 0x02;	/* RPA */
	in[0].adv_props = 0x0013;
	in[0].interval_min = 0x00A0;
	in[0].interval_max = 0x00A0;
	in[0].adv_data_len = 5;
	in[0].adv_data[0] = 0x04;
	in[0].adv_data[1] = 0x09;	/* Complete Local Name */
	in[0].adv_data[2] = 'A';
	in[0].adv_data[3] = 'B';
	in[0].adv_data[4] = 'C';
	in[0].scan_rsp_len = 3;
	in[0].scan_rsp[0] = 0x02;
	in[0].scan_rsp[1] = 0x09;
	in[0].scan_rsp[2] = 'X';

	ATF_REQUIRE_EQ(0, blued_persist_advconfig_save(d, in, 1));

	memset(out, 0, sizeof(out));
	ATF_REQUIRE_EQ(0, blued_persist_advconfig_load(d, out, &n));
	ATF_REQUIRE_EQ(1, n);
	ATF_CHECK_EQ(1, out[0].enabled);
	ATF_CHECK_EQ(0x02, out[0].own_addr_type);
	ATF_CHECK_EQ(0x0013, out[0].adv_props);
	ATF_CHECK_EQ(5, out[0].adv_data_len);
	ATF_CHECK_EQ(0, memcmp(out[0].adv_data, in[0].adv_data, 5));
	ATF_CHECK_EQ(3, out[0].scan_rsp_len);
	close(d);
}

/* ================================================================
 * Missing file -> reject (caller uses defaults).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(missing_file_rejected);
ATF_TC_BODY(missing_file_rejected, tc)
{
	struct blued_persist_settings r;
	int d = open_cwd_dir();

	memset(&r, 0x55, sizeof(r));
	ATF_CHECK_EQ(-1, blued_persist_settings_load(d, &r));
	close(d);
}

/* ================================================================
 * Corrupt CRC -> reject.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(corrupt_crc_rejected);
ATF_TC_BODY(corrupt_crc_rejected, tc)
{
	struct blued_persist_settings s, r;
	uint8_t byte;
	int d = open_cwd_dir();
	int f;

	memset(&s, 0, sizeof(s));
	strlcpy(s.name, "victim", sizeof(s.name));
	ATF_REQUIRE_EQ(0, blued_persist_settings_save(d, &s));

	/* Flip a payload byte (past the header) without fixing the CRC. */
	f = openat(d, BLUED_PERSIST_SETTINGS_FILE, O_RDWR);
	ATF_REQUIRE(f >= 0);
	ATF_REQUIRE_EQ(1, pread(f, &byte, 1, BLUED_PERSIST_HDR_SIZE));
	byte ^= 0xFF;
	ATF_REQUIRE_EQ(1, pwrite(f, &byte, 1, BLUED_PERSIST_HDR_SIZE));
	close(f);

	ATF_CHECK_EQ(-1, blued_persist_settings_load(d, &r));
	close(d);
}

/* ================================================================
 * Truncated file -> reject (no over-read).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(truncated_file_rejected);
ATF_TC_BODY(truncated_file_rejected, tc)
{
	struct blued_persist_device in[3], out[BLUED_PERSIST_MAX_DEVICES];
	uint32_t n = 99;	/* poisoned: the loader must zero it on entry */
	int d = open_cwd_dir();
	int f;

	memset(in, 0, sizeof(in));
	in[0].addr_type = in[1].addr_type = in[2].addr_type = 1;
	ATF_REQUIRE_EQ(0, blued_persist_devcache_save(d, in, 3));

	/* Chop the payload mid-record. */
	f = openat(d, BLUED_PERSIST_DEVCACHE_FILE, O_RDWR);
	ATF_REQUIRE(f >= 0);
	ATF_REQUIRE_EQ(0, ftruncate(f, BLUED_PERSIST_HDR_SIZE + 4));
	close(f);

	ATF_CHECK_EQ(-1, blued_persist_devcache_load(d, out, &n));
	/*
	 * n was poisoned to 99: this pins the entry-time "*count_out = 0"
	 * contract in blued_persist_load_records.  With n pre-set to 0 the
	 * assertion held even if that zeroing were deleted, leaving a caller
	 * to walk a stale count over an unwritten array.
	 */
	ATF_CHECK_EQ(0, n);
	close(d);
}

/* ================================================================
 * Wrong magic / unknown version -> reject.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(wrong_magic_and_version_rejected);
ATF_TC_BODY(wrong_magic_and_version_rejected, tc)
{
	struct blued_persist_settings s, r;
	uint32_t n = 99;	/* poisoned: the loader must zero it on entry */
	int d = open_cwd_dir();

	memset(&s, 0, sizeof(s));

	/*
	 * Save under the settings name but a foreign magic, at the CURRENT
	 * version and record size so the MAGIC is the only thing wrong.
	 *
	 * The fixture used to be written at version 1 while the live schema
	 * is BLUED_PERSIST_SETTINGS_VERSION (4).  Magic and version are
	 * independent rejections in blued_persist_load_records, so the
	 * version mismatch alone produced the expected -1 and deleting the
	 * "memcmp(hdr + HDR_MAGIC_OFF, magic, HDR_MAGIC_LEN)" check left the
	 * case green.  Now only that memcmp can reject this file.
	 */
	ATF_REQUIRE_EQ(0, blued_persist_save_records(d,
	    BLUED_PERSIST_SETTINGS_FILE, "XXXXXXXX",
	    BLUED_PERSIST_SETTINGS_VERSION, (uint32_t)sizeof(s), 1, &s));
	ATF_CHECK_EQ(-1, blued_persist_settings_load(d, &r));

	/* Save with the right magic but a future version. */
	ATF_REQUIRE_EQ(0, blued_persist_save_records(d,
	    BLUED_PERSIST_SETTINGS_FILE, BLUED_PERSIST_SETTINGS_MAGIC,
	    99, (uint32_t)sizeof(s), 1, &s));
	ATF_CHECK_EQ(-1, blued_persist_load_records(d,
	    BLUED_PERSIST_SETTINGS_FILE, BLUED_PERSIST_SETTINGS_MAGIC,
	    BLUED_PERSIST_SETTINGS_VERSION, (uint32_t)sizeof(s), 1, &r,
	    &n, NULL));
	ATF_CHECK_EQ(0, n);
	close(d);
}


/* ================================================================
 * Count clamping: a file with more records than the caller's array
 * loads only up to the array bound (no overflow).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(count_clamped_to_array);
ATF_TC_BODY(count_clamped_to_array, tc)
{
	struct blued_persist_device in[5], out[3];
	uint32_t n = 99;
	int d = open_cwd_dir();

	memset(in, 0, sizeof(in));
	ATF_REQUIRE_EQ(0, blued_persist_save_records(d, "manydev",
	    BLUED_PERSIST_DEVCACHE_MAGIC, BLUED_PERSIST_DEVCACHE_VERSION,
	    (uint32_t)sizeof(in[0]), 5, in));

	/* Load into a 3-slot array: must clamp to 3, not write 5. */
	ATF_REQUIRE_EQ(0, blued_persist_load_records(d, "manydev",
	    BLUED_PERSIST_DEVCACHE_MAGIC, BLUED_PERSIST_DEVCACHE_VERSION,
	    (uint32_t)sizeof(out[0]), 3, out, &n, NULL));
	ATF_CHECK_EQ(3, n);
	close(d);
}

/*
 * Count staging siblings ("<name>.tmp.XXXXXX") left in the persist directory.
 * The engine stages via mkostempsat(dirfd, "<name>.tmp.XXXXXX"), so the
 * leftover it must clean up never has a name a test can predict.
 */
static int
count_temp_siblings(int dirfd, const char *name)
{
	char prefix[64];
	struct dirent *de;
	DIR *dp;
	size_t plen;
	int dup_fd, n = 0;

	plen = (size_t)snprintf(prefix, sizeof(prefix), "%s.tmp.", name);
	ATF_REQUIRE(plen < sizeof(prefix));

	dup_fd = dup(dirfd);
	ATF_REQUIRE(dup_fd >= 0);
	dp = fdopendir(dup_fd);
	ATF_REQUIRE(dp != NULL);
	rewinddir(dp);
	while ((de = readdir(dp)) != NULL) {
		if (strncmp(de->d_name, prefix, plen) == 0)
			n++;
	}
	(void)closedir(dp);
	return (n);
}

/* ================================================================
 * Atomic-write crash safety: a save that fails mid-write must not
 * replace or damage the committed file, and must leave no staging
 * sibling behind.
 *
 * The old body created a hand-made "settings.tmp" and asserted the
 * loader ignored it.  That could not fail: the engine stages via
 * mkostempsat() with a ".tmp.XXXXXX" suffix (so "settings.tmp" is not
 * a name it ever uses) and the loader openat()s only the exact target
 * name, so both arms were true under any implementation.  Drive the
 * real failure through the __wrap_write seam instead.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(atomic_partial_temp_ignored);
ATF_TC_BODY(atomic_partial_temp_ignored, tc)
{
	struct blued_persist_settings good, bad, r;
	int d = open_cwd_dir();

	/* Commit a good file. */
	memset(&good, 0, sizeof(good));
	strlcpy(good.name, "committed", sizeof(good.name));
	good.min_key_size = 16;
	good.rpa_timeout = 900;
	ATF_REQUIRE_EQ(0, blued_persist_settings_save(d, &good));
	ATF_REQUIRE_EQ(0, count_temp_siblings(d,
	    BLUED_PERSIST_SETTINGS_FILE));

	/*
	 * Now fail the PAYLOAD write with a hard error (skip the header
	 * write, fault the next one).  blued_persist_save_records must take
	 * its "goto fail" path: close the staging fd, unlinkat() the staging
	 * file, and return -1 without ever renaming over the live name.
	 */
	memset(&bad, 0, sizeof(bad));
	strlcpy(bad.name, "should-never-land", sizeof(bad.name));
	bad.min_key_size = 7;
	fault_writes(1, 1, EIO);
	ATF_CHECK_EQ(-1, blued_persist_settings_save(d, &bad));
	fault_writes(0, 0, EINTR);

	/* The previously committed file still loads, with its old contents. */
	memset(&r, 0xAA, sizeof(r));
	ATF_REQUIRE_EQ(0, blued_persist_settings_load(d, &r));
	ATF_CHECK_STREQ("committed", r.name);
	ATF_CHECK_EQ(16, r.min_key_size);
	ATF_CHECK_EQ(900, r.rpa_timeout);

	/* And no staging sibling survived the failed save. */
	ATF_CHECK_EQ_MSG(0,
	    count_temp_siblings(d, BLUED_PERSIST_SETTINGS_FILE),
	    "a failed save must unlink its staging file");

	/* A subsequent successful save still commits cleanly. */
	strlcpy(good.name, "committed2", sizeof(good.name));
	ATF_REQUIRE_EQ(0, blued_persist_settings_save(d, &good));
	ATF_REQUIRE_EQ(0, blued_persist_settings_load(d, &r));
	ATF_CHECK_STREQ("committed2", r.name);
	ATF_CHECK_EQ(0, count_temp_siblings(d,
	    BLUED_PERSIST_SETTINGS_FILE));
	close(d);
}

/* ================================================================
 * Finding 140: the preferred ATT MTU is persisted in the settings
 * artifact (v4 schema) and survives a restart round trip.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(settings_preferred_mtu_round_trip);
ATF_TC_BODY(settings_preferred_mtu_round_trip, tc)
{
	struct blued_persist_settings s, r;
	int d = open_cwd_dir();

	memset(&s, 0, sizeof(s));
	strlcpy(s.name, "mtu-adapter", sizeof(s.name));
	s.preferred_mtu = 512;
	s.conn_interval_min = 6;
	s.conn_interval_max = 12;
	s.conn_latency = 4;
	s.supervision_timeout = 500;

	ATF_REQUIRE_EQ(0, blued_persist_settings_save(d, &s));

	memset(&r, 0xAA, sizeof(r));
	ATF_REQUIRE_EQ(0, blued_persist_settings_load(d, &r));
	ATF_CHECK_EQ(512, r.preferred_mtu);
	ATF_CHECK_EQ(6, r.conn_interval_min);
	ATF_CHECK_EQ(12, r.conn_interval_max);
	ATF_CHECK_EQ(500, r.supervision_timeout);
	close(d);
}

/* ================================================================
 * Finding 139/141: multiple advertising sets (not just a single
 * hardcoded handle-0 record) are persisted, and each set's payload
 * bytes (adv_data/scan_rsp) round-trip rather than being written as
 * zeros.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(advconfig_multi_set_round_trip);
ATF_TC_BODY(advconfig_multi_set_round_trip, tc)
{
	struct blued_persist_adv_set in[3], out[BLUED_PERSIST_MAX_ADV_SETS];
	uint32_t n = 0;
	int d = open_cwd_dir();

	memset(in, 0, sizeof(in));
	/* Legacy/primary set 0 with a real advertising payload. */
	in[0].handle = 0;
	in[0].enabled = 1;
	in[0].adv_props = 0x0013;
	in[0].adv_data_len = 4;
	in[0].adv_data[0] = 0x03;
	in[0].adv_data[1] = 0x03;	/* Complete 16-bit UUIDs */
	in[0].adv_data[2] = 0x12;
	in[0].adv_data[3] = 0x18;	/* HID (0x1812) */
	in[0].scan_rsp_len = 2;
	in[0].scan_rsp[0] = 0x01;
	in[0].scan_rsp[1] = 0x09;
	/* Two extended sets on distinct handles. */
	in[1].handle = 2;
	in[1].enabled = 1;
	in[1].adv_props = 0x0000;
	in[1].own_addr_type = 0x03;
	in[2].handle = 3;
	in[2].enabled = 0;
	in[2].adv_props = 0x0001;

	ATF_REQUIRE_EQ(0, blued_persist_advconfig_save(d, in, 3));

	memset(out, 0, sizeof(out));
	ATF_REQUIRE_EQ(0, blued_persist_advconfig_load(d, out, &n));
	ATF_REQUIRE_EQ(3, n);
	ATF_CHECK_EQ(0, out[0].handle);
	ATF_CHECK_EQ(4, out[0].adv_data_len);
	ATF_CHECK_EQ(0, memcmp(out[0].adv_data, in[0].adv_data, 4));
	ATF_CHECK_EQ(2, out[0].scan_rsp_len);
	ATF_CHECK_EQ(2, out[1].handle);
	ATF_CHECK_EQ(0x03, out[1].own_addr_type);
	ATF_CHECK_EQ(3, out[2].handle);
	ATF_CHECK_EQ(0, out[2].enabled);
	close(d);
}

/* ================================================================
 * Finding 138: runtime resolving-list IRK entries round-trip and a
 * simulated restart reloads exactly what was saved (with the IRK).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(resolv_round_trip);
ATF_TC_BODY(resolv_round_trip, tc)
{
	struct blued_persist_resolv_entry in[2], out[BLUED_PERSIST_MAX_RESOLV];
	uint32_t n = 0;
	int d = open_cwd_dir();

	memset(in, 0, sizeof(in));
	memcpy(in[0].addr, "\x01\x02\x03\x04\x05\x06", 6);
	in[0].addr_type = 1;
	memset(in[0].irk, 0x11, sizeof(in[0].irk));
	memcpy(in[1].addr, "\xAA\xBB\xCC\xDD\xEE\xFF", 6);
	in[1].addr_type = 0;
	memset(in[1].irk, 0x22, sizeof(in[1].irk));

	ATF_REQUIRE_EQ(0, blued_persist_resolv_save(d, in, 2));

	/* Fresh load == simulate restart. */
	memset(out, 0xEE, sizeof(out));
	ATF_REQUIRE_EQ(0, blued_persist_resolv_load(d, out, &n));
	ATF_REQUIRE_EQ(2, n);
	ATF_CHECK_EQ(0, memcmp(out[0].addr, "\x01\x02\x03\x04\x05\x06", 6));
	ATF_CHECK_EQ(1, out[0].addr_type);
	ATF_CHECK_EQ(0x11, out[0].irk[0]);
	ATF_CHECK_EQ(0x11, out[0].irk[15]);
	ATF_CHECK_EQ(0, memcmp(out[1].addr, "\xAA\xBB\xCC\xDD\xEE\xFF", 6));
	ATF_CHECK_EQ(0x22, out[1].irk[7]);

	/* Missing file -> reject (defaults). */
	(void)unlinkat(d, BLUED_PERSIST_RESOLV_FILE, 0);
	n = 99;
	ATF_CHECK_EQ(-1, blued_persist_resolv_load(d, out, &n));
	ATF_CHECK_EQ(0, n);
	close(d);
}

/* ================================================================
 * Finding 135: runtime Filter Accept List entries round-trip and a
 * simulated restart reloads exactly what was saved.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(acceptlist_round_trip);
ATF_TC_BODY(acceptlist_round_trip, tc)
{
	struct blued_persist_accept_entry in[3], out[BLUED_PERSIST_MAX_ACCEPT];
	uint32_t n = 0;
	int d = open_cwd_dir();

	memset(in, 0, sizeof(in));
	memcpy(in[0].addr, "\x10\x20\x30\x40\x50\x60", 6);
	in[0].addr_type = 0;
	memcpy(in[1].addr, "\x11\x21\x31\x41\x51\x61", 6);
	in[1].addr_type = 1;
	memcpy(in[2].addr, "\x12\x22\x32\x42\x52\x62", 6);
	in[2].addr_type = 1;

	ATF_REQUIRE_EQ(0, blued_persist_accept_save(d, in, 3));

	memset(out, 0xEE, sizeof(out));
	ATF_REQUIRE_EQ(0, blued_persist_accept_load(d, out, &n));
	ATF_REQUIRE_EQ(3, n);
	ATF_CHECK_EQ(0, memcmp(out[0].addr, "\x10\x20\x30\x40\x50\x60", 6));
	ATF_CHECK_EQ(0, out[0].addr_type);
	ATF_CHECK_EQ(1, out[1].addr_type);
	ATF_CHECK_EQ(0, memcmp(out[2].addr, "\x12\x22\x32\x42\x52\x62", 6));
	close(d);
}

/* ================================================================
 * Finding 137: runtime-added local GATT server attributes round-trip
 * (flat rows + inline value) and reload after a simulated restart.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(gattsrv_round_trip);
ATF_TC_BODY(gattsrv_round_trip, tc)
{
	struct blued_persist_gatt_srv_attr in[3];
	struct blued_persist_gatt_srv_attr out[BLUED_PERSIST_MAX_GATTSRV_ATTRS];
	uint32_t n = 0;
	int d = open_cwd_dir();

	memset(in, 0, sizeof(in));
	/* Service declaration. */
	in[0].handle = 0x0040;
	in[0].uuid16 = 0x180F;
	in[0].end_group_handle = 0x0043;
	/* Characteristic value attr with an inline value. */
	in[1].handle = 0x0042;
	in[1].uuid16 = 0x2A19;
	in[1].perms = 0x01;
	in[1].is_char_value = 1;
	in[1].value_len = 2;
	in[1].value_maxlen = 2;
	in[1].value[0] = 0x64;
	in[1].value[1] = 0x00;
	/* Descriptor (CUD). */
	in[2].handle = 0x0043;
	in[2].uuid16 = 0x2901;
	in[2].perms = 0x01;
	in[2].value_len = 3;
	memcpy(in[2].value, "abc", 3);

	ATF_REQUIRE_EQ(0, blued_persist_gattsrv_save(d, in, 3));

	memset(out, 0, sizeof(out));
	ATF_REQUIRE_EQ(0, blued_persist_gattsrv_load(d, out, &n));
	ATF_REQUIRE_EQ(3, n);
	ATF_CHECK_EQ(0x0040, out[0].handle);
	ATF_CHECK_EQ(0x180F, out[0].uuid16);
	ATF_CHECK_EQ(0x0043, out[0].end_group_handle);
	ATF_CHECK_EQ(0x2A19, out[1].uuid16);
	ATF_CHECK_EQ(1, out[1].is_char_value);
	ATF_CHECK_EQ(2, out[1].value_len);
	ATF_CHECK_EQ(0x64, out[1].value[0]);
	ATF_CHECK_EQ(0x2901, out[2].uuid16);
	ATF_CHECK_EQ(3, out[2].value_len);
	ATF_CHECK_EQ(0, memcmp(out[2].value, "abc", 3));

	/*
	 * A value_len from a corrupt / hostile file that exceeds the physical
	 * buffer is clamped on load (blued_persist.c, blued_persist_gattsrv_load:
	 * "if (attrs[i].value_len > BLUED_PERSIST_GATTSRV_VALLEN)
	 *      attrs[i].value_len = BLUED_PERSIST_GATTSRV_VALLEN;").
	 *
	 * That is a real memory-safety bound — every consumer copies
	 * value_len bytes out of a BLUED_PERSIST_GATTSRV_VALLEN-byte array —
	 * and it previously had only a comment announcing an assertion that
	 * was never written.  Stage the record through the generic writer so
	 * the oversized length reaches the typed loader intact.
	 */
	in[1].value_len = 0xFFFF;
	in[2].value_len = BLUED_PERSIST_GATTSRV_VALLEN + 1;
	ATF_REQUIRE_EQ(0, blued_persist_save_records(d,
	    BLUED_PERSIST_GATTSRV_FILE, BLUED_PERSIST_GATTSRV_MAGIC,
	    BLUED_PERSIST_GATTSRV_VERSION, (uint32_t)sizeof(in[0]), 3, in));

	memset(out, 0, sizeof(out));
	n = 0;
	ATF_REQUIRE_EQ(0, blued_persist_gattsrv_load(d, out, &n));
	ATF_REQUIRE_EQ(3, n);
	ATF_CHECK_EQ_MSG(BLUED_PERSIST_GATTSRV_VALLEN, out[1].value_len,
	    "an over-range value_len must be clamped to the buffer size");
	ATF_CHECK_EQ_MSG(BLUED_PERSIST_GATTSRV_VALLEN, out[2].value_len,
	    "a value_len one past the buffer must be clamped");
	/* An in-range length is left exactly as stored. */
	ATF_CHECK_EQ(0, out[0].value_len);

	close(d);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, resolv_round_trip);
	ATF_TP_ADD_TC(tp, acceptlist_round_trip);
	ATF_TP_ADD_TC(tp, gattsrv_round_trip);
	ATF_TP_ADD_TC(tp, settings_preferred_mtu_round_trip);
	ATF_TP_ADD_TC(tp, advconfig_multi_set_round_trip);
	ATF_TP_ADD_TC(tp, crc32_known_vector);
	ATF_TP_ADD_TC(tp, settings_round_trip);
	ATF_TP_ADD_TC(tp, save_load_eintr_retry);
	ATF_TP_ADD_TC(tp, devcache_round_trip);
	ATF_TP_ADD_TC(tp, gattcache_hash_reuse_invalidate);
	ATF_TP_ADD_TC(tp, advconfig_round_trip);
	ATF_TP_ADD_TC(tp, missing_file_rejected);
	ATF_TP_ADD_TC(tp, corrupt_crc_rejected);
	ATF_TP_ADD_TC(tp, truncated_file_rejected);
	ATF_TP_ADD_TC(tp, wrong_magic_and_version_rejected);
	ATF_TP_ADD_TC(tp, count_clamped_to_array);
	ATF_TP_ADD_TC(tp, atomic_partial_temp_ignored);

	return (atf_no_error());
}
