/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Operational-state persistence engine for blued.
 *
 * See blued_persist.h for the frame format and the trust model.  The engine
 * mirrors the bond database (smp_keys.c) conventions: a versioned header, a
 * exact-schema validation, bounded/clamped loads, and 0600
 * permissions.  Unlike the bond database it writes atomically (temp + fsync +
 * renameat) and, because the state here is non-secret, it protects integrity
 * with a CRC32 rather than authenticated encryption.
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blued_persist.h"

/*
 * Frame header field offsets (little-endian on disk):
 *   [0]  magic[8]
 *   [8]  uint16 version
 *   [10] uint16 flags        (reserved, 0)
 *   [12] uint32 record_size  (bytes per record as written)
 *   [16] uint32 count        (number of records)
 *   [20] uint32 payload_len  (== record_size * count)
 *   [24] uint32 crc32        (over bytes [0..23] and the payload)
 *   [28] payload
 */
#define HDR_MAGIC_OFF	0
#define HDR_VERSION_OFF	8
#define HDR_FLAGS_OFF	10
#define HDR_RECSZ_OFF	12
#define HDR_COUNT_OFF	16
#define HDR_PLEN_OFF	20
#define HDR_CRC_OFF	24
#define HDR_MAGIC_LEN	8

/* ================================================================
 * CRC32 (IEEE 802.3, reflected polynomial 0xEDB88320).
 * ================================================================ */
uint32_t
blued_persist_crc32(uint32_t crc, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t i;
	int k;

	crc = ~crc;
	for (i = 0; i < len; i++) {
		crc ^= p[i];
		for (k = 0; k < 8; k++)
			crc = (crc >> 1) ^ (0xEDB88320u & (~(crc & 1) + 1));
	}
	return (~crc);
}

/* ================================================================
 * Full read/write helpers (loop over short I/O).
 * ================================================================ */
static int
persist_write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t off = 0;
	ssize_t n;

	while (off < len) {
		n = write(fd, p + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (n == 0)
			return (-1);
		off += (size_t)n;
	}
	return (0);
}

/* ================================================================
 * Generic framed save: temp file + fsync + atomic renameat.
 * ================================================================ */
int
blued_persist_save_records(int dirfd, const char *name, const char *magic,
    uint16_t version, uint32_t record_size, uint32_t count,
    const void *records)
{
	uint8_t hdr[BLUED_PERSIST_HDR_SIZE];
	char tmpname[128];
	uint64_t payload_len;
	uint32_t crc;
	int fd, r;

	if (dirfd < 0 || record_size == 0)
		return (-1);

	/* Guard the payload size against overflow and the defensive cap. */
	payload_len = (uint64_t)record_size * (uint64_t)count;
	if (payload_len > BLUED_PERSIST_MAX_PAYLOAD)
		return (-1);

	memset(hdr, 0, sizeof(hdr));
	memcpy(hdr + HDR_MAGIC_OFF, magic, HDR_MAGIC_LEN);
	le16enc(hdr + HDR_VERSION_OFF, version);
	le16enc(hdr + HDR_FLAGS_OFF, 0);
	le32enc(hdr + HDR_RECSZ_OFF, record_size);
	le32enc(hdr + HDR_COUNT_OFF, count);
	le32enc(hdr + HDR_PLEN_OFF, (uint32_t)payload_len);

	/* CRC over the header (excluding the crc field) then the payload. */
	crc = blued_persist_crc32(0, hdr, HDR_CRC_OFF);
	if (payload_len > 0)
		crc = blued_persist_crc32(crc, records, (size_t)payload_len);
	le32enc(hdr + HDR_CRC_OFF, crc);

	r = snprintf(tmpname, sizeof(tmpname), "%s.tmp.XXXXXX", name);
	if (r < 0 || (size_t)r >= sizeof(tmpname))
		return (-1);

	/* A unique O_EXCL-created sibling prevents concurrent saves from
	 * truncating or unlinking each other's staging file. */
	fd = mkostempsat(dirfd, tmpname, 0, O_CLOEXEC | O_CLOFORK);
	if (fd < 0)
		return (-1);
	(void)fchmod(fd, 0600);

	if (persist_write_all(fd, hdr, sizeof(hdr)) != 0)
		goto fail;
	if (payload_len > 0 &&
	    persist_write_all(fd, records, (size_t)payload_len) != 0)
		goto fail;
	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		(void)unlinkat(dirfd, tmpname, 0);
		return (-1);
	}

	/* Atomic replace, then flush the directory entry. */
	if (renameat(dirfd, tmpname, dirfd, name) != 0) {
		(void)unlinkat(dirfd, tmpname, 0);
		return (-1);
	}
	return (fsync(dirfd));

fail:
	(void)close(fd);
	(void)unlinkat(dirfd, tmpname, 0);
	return (-1);
}

/* ================================================================
 * Generic framed load with validation, CRC check, and count clamping.
 * ================================================================ */
int
blued_persist_load_records(int dirfd, const char *name, const char *magic,
    uint16_t current_version, uint32_t current_record_size, uint32_t max_count,
    void *records_out, uint32_t *count_out, uint16_t *version_out)
{
	uint8_t hdr[BLUED_PERSIST_HDR_SIZE];
	uint8_t *payload = NULL;
	uint8_t *out = records_out;
	uint16_t version;
	uint32_t rec_size, count, payload_len, stored_crc, calc_crc;
	uint32_t keep;
	struct stat st;
	ssize_t n;
	off_t off;
	int fd;

	if (count_out != NULL)
		*count_out = 0;
	if (version_out != NULL)
		*version_out = 0;
	if (dirfd < 0 || current_record_size == 0 || records_out == NULL)
		return (-1);

	fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return (-1);	/* absent -> caller uses defaults */
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
	    st.st_uid != geteuid())
		goto reject;

	/* Header. */
	n = read(fd, hdr, sizeof(hdr));
	if (n != (ssize_t)sizeof(hdr))
		goto reject;

	if (memcmp(hdr + HDR_MAGIC_OFF, magic, HDR_MAGIC_LEN) != 0)
		goto reject;

	version = le16dec(hdr + HDR_VERSION_OFF);
	rec_size = le32dec(hdr + HDR_RECSZ_OFF);
	count = le32dec(hdr + HDR_COUNT_OFF);
	payload_len = le32dec(hdr + HDR_PLEN_OFF);
	stored_crc = le32dec(hdr + HDR_CRC_OFF);

	if (version != current_version || rec_size != current_record_size)
		goto reject;

	/* record_size / count / payload_len must be consistent and bounded. */
	if (rec_size == 0 || rec_size > BLUED_PERSIST_MAX_PAYLOAD)
		goto reject;
	if (payload_len > BLUED_PERSIST_MAX_PAYLOAD)
		goto reject;
	if ((uint64_t)rec_size * (uint64_t)count != (uint64_t)payload_len)
		goto reject;
	if (st.st_size !=
	    (off_t)(BLUED_PERSIST_HDR_SIZE + payload_len))
		goto reject;

	payload = malloc(payload_len > 0 ? payload_len : 1);
	if (payload == NULL)
		goto reject;

	off = 0;
	while ((uint32_t)off < payload_len) {
		n = read(fd, payload + off, payload_len - (uint32_t)off);
		if (n <= 0)
			goto reject;	/* truncated payload */
		off += n;
	}

	/* Integrity: CRC over header (sans crc field) + payload. */
	calc_crc = blued_persist_crc32(0, hdr, HDR_CRC_OFF);
	if (payload_len > 0)
		calc_crc = blued_persist_crc32(calc_crc, payload, payload_len);
	if (calc_crc != stored_crc)
		goto reject;

	/* Never write past the caller's array: clamp to max_count. */
	keep = count;
	if (keep > max_count)
		keep = max_count;
	memset(out, 0, (size_t)max_count * current_record_size);
	memcpy(out, payload, (size_t)keep * current_record_size);

	free(payload);
	(void)close(fd);
	if (count_out != NULL)
		*count_out = keep;
	if (version_out != NULL)
		*version_out = version;
	return (0);

reject:
	free(payload);
	(void)close(fd);
	return (-1);
}

/* ================================================================
 * Typed artifact wrappers.
 * ================================================================ */
int
blued_persist_settings_save(int dirfd, const struct blued_persist_settings *s)
{
	return (blued_persist_save_records(dirfd, BLUED_PERSIST_SETTINGS_FILE,
	    BLUED_PERSIST_SETTINGS_MAGIC, BLUED_PERSIST_SETTINGS_VERSION,
	    (uint32_t)sizeof(*s), 1, s));
}

int
blued_persist_settings_load(int dirfd, struct blued_persist_settings *s)
{
	uint32_t n = 0;

	if (blued_persist_load_records(dirfd, BLUED_PERSIST_SETTINGS_FILE,
	    BLUED_PERSIST_SETTINGS_MAGIC, BLUED_PERSIST_SETTINGS_VERSION,
	    (uint32_t)sizeof(*s), 1, s, &n, NULL) != 0)
		return (-1);
	if (n != 1)
		return (-1);
	/* Defensive: keep the persisted name NUL-terminated. */
	s->name[sizeof(s->name) - 1] = '\0';
	return (0);
}

int
blued_persist_devcache_save(int dirfd,
    const struct blued_persist_device *devs, uint32_t ndevs)
{
	if (ndevs > BLUED_PERSIST_MAX_DEVICES)
		ndevs = BLUED_PERSIST_MAX_DEVICES;
	return (blued_persist_save_records(dirfd, BLUED_PERSIST_DEVCACHE_FILE,
	    BLUED_PERSIST_DEVCACHE_MAGIC, BLUED_PERSIST_DEVCACHE_VERSION,
	    (uint32_t)sizeof(devs[0]), ndevs, devs));
}

int
blued_persist_devcache_load(int dirfd, struct blued_persist_device *devs,
    uint32_t *ndevs)
{
	uint32_t i;

	if (blued_persist_load_records(dirfd, BLUED_PERSIST_DEVCACHE_FILE,
	    BLUED_PERSIST_DEVCACHE_MAGIC, BLUED_PERSIST_DEVCACHE_VERSION,
	    (uint32_t)sizeof(devs[0]), BLUED_PERSIST_MAX_DEVICES, devs,
	    ndevs, NULL) != 0)
		return (-1);
	for (i = 0; i < *ndevs; i++)
		devs[i].name[sizeof(devs[i].name) - 1] = '\0';
	return (0);
}

int
blued_persist_gattcache_save(int dirfd,
    const struct blued_persist_gatt_device *devs, uint32_t ndevs)
{
	if (ndevs > BLUED_PERSIST_MAX_GATT_DEVICES)
		ndevs = BLUED_PERSIST_MAX_GATT_DEVICES;
	return (blued_persist_save_records(dirfd, BLUED_PERSIST_GATTCACHE_FILE,
	    BLUED_PERSIST_GATTCACHE_MAGIC, BLUED_PERSIST_GATTCACHE_VERSION,
	    (uint32_t)sizeof(devs[0]), ndevs, devs));
}

int
blued_persist_gattcache_load(int dirfd,
    struct blued_persist_gatt_device *devs, uint32_t *ndevs)
{
	uint32_t i;

	if (blued_persist_load_records(dirfd, BLUED_PERSIST_GATTCACHE_FILE,
	    BLUED_PERSIST_GATTCACHE_MAGIC, BLUED_PERSIST_GATTCACHE_VERSION,
	    (uint32_t)sizeof(devs[0]), BLUED_PERSIST_MAX_GATT_DEVICES, devs,
	    ndevs, NULL) != 0)
		return (-1);
	/*
	 * Clamp each device's attribute count to the physical array size: a
	 * corrupt or migrated record could carry nattrs beyond the array and
	 * later over-read attrs[] (mirrors the bond-DB CCCD clamp).
	 */
	for (i = 0; i < *ndevs; i++) {
		if (devs[i].nattrs > BLUED_PERSIST_MAX_GATT_ATTRS)
			devs[i].nattrs = BLUED_PERSIST_MAX_GATT_ATTRS;
	}
	return (0);
}

int
blued_persist_advconfig_save(int dirfd,
    const struct blued_persist_adv_set *sets, uint32_t nsets)
{
	if (nsets > BLUED_PERSIST_MAX_ADV_SETS)
		nsets = BLUED_PERSIST_MAX_ADV_SETS;
	return (blued_persist_save_records(dirfd, BLUED_PERSIST_ADVCONFIG_FILE,
	    BLUED_PERSIST_ADVCONFIG_MAGIC, BLUED_PERSIST_ADVCONFIG_VERSION,
	    (uint32_t)sizeof(sets[0]), nsets, sets));
}

int
blued_persist_advconfig_load(int dirfd, struct blued_persist_adv_set *sets,
    uint32_t *nsets)
{
	uint32_t i;

	if (blued_persist_load_records(dirfd, BLUED_PERSIST_ADVCONFIG_FILE,
	    BLUED_PERSIST_ADVCONFIG_MAGIC, BLUED_PERSIST_ADVCONFIG_VERSION,
	    (uint32_t)sizeof(sets[0]), BLUED_PERSIST_MAX_ADV_SETS, sets,
	    nsets, NULL) != 0)
		return (-1);
	/* Clamp advertising/scan-response lengths to their buffers. */
	for (i = 0; i < *nsets; i++) {
		if (sets[i].adv_data_len > sizeof(sets[i].adv_data))
			sets[i].adv_data_len = sizeof(sets[i].adv_data);
		if (sets[i].scan_rsp_len > sizeof(sets[i].scan_rsp))
			sets[i].scan_rsp_len = sizeof(sets[i].scan_rsp);
	}
	return (0);
}

int
blued_persist_resolv_save(int dirfd,
    const struct blued_persist_resolv_entry *ents, uint32_t nents)
{
	if (nents > BLUED_PERSIST_MAX_RESOLV)
		nents = BLUED_PERSIST_MAX_RESOLV;
	return (blued_persist_save_records(dirfd, BLUED_PERSIST_RESOLV_FILE,
	    BLUED_PERSIST_RESOLV_MAGIC, BLUED_PERSIST_RESOLV_VERSION,
	    (uint32_t)sizeof(ents[0]), nents, ents));
}

int
blued_persist_resolv_load(int dirfd, struct blued_persist_resolv_entry *ents,
    uint32_t *nents)
{
	return (blued_persist_load_records(dirfd, BLUED_PERSIST_RESOLV_FILE,
	    BLUED_PERSIST_RESOLV_MAGIC, BLUED_PERSIST_RESOLV_VERSION,
	    (uint32_t)sizeof(ents[0]), BLUED_PERSIST_MAX_RESOLV, ents,
	    nents, NULL));
}

int
blued_persist_accept_save(int dirfd,
    const struct blued_persist_accept_entry *ents, uint32_t nents)
{
	if (nents > BLUED_PERSIST_MAX_ACCEPT)
		nents = BLUED_PERSIST_MAX_ACCEPT;
	return (blued_persist_save_records(dirfd, BLUED_PERSIST_ACCEPT_FILE,
	    BLUED_PERSIST_ACCEPT_MAGIC, BLUED_PERSIST_ACCEPT_VERSION,
	    (uint32_t)sizeof(ents[0]), nents, ents));
}

int
blued_persist_accept_load(int dirfd, struct blued_persist_accept_entry *ents,
    uint32_t *nents)
{
	return (blued_persist_load_records(dirfd, BLUED_PERSIST_ACCEPT_FILE,
	    BLUED_PERSIST_ACCEPT_MAGIC, BLUED_PERSIST_ACCEPT_VERSION,
	    (uint32_t)sizeof(ents[0]), BLUED_PERSIST_MAX_ACCEPT, ents,
	    nents, NULL));
}

int
blued_persist_gattsrv_save(int dirfd,
    const struct blued_persist_gatt_srv_attr *attrs, uint32_t nattrs)
{
	if (nattrs > BLUED_PERSIST_MAX_GATTSRV_ATTRS)
		nattrs = BLUED_PERSIST_MAX_GATTSRV_ATTRS;
	return (blued_persist_save_records(dirfd, BLUED_PERSIST_GATTSRV_FILE,
	    BLUED_PERSIST_GATTSRV_MAGIC, BLUED_PERSIST_GATTSRV_VERSION,
	    (uint32_t)sizeof(attrs[0]), nattrs, attrs));
}

int
blued_persist_gattsrv_load(int dirfd,
    struct blued_persist_gatt_srv_attr *attrs, uint32_t *nattrs)
{
	uint32_t i;

	if (blued_persist_load_records(dirfd, BLUED_PERSIST_GATTSRV_FILE,
	    BLUED_PERSIST_GATTSRV_MAGIC, BLUED_PERSIST_GATTSRV_VERSION,
	    (uint32_t)sizeof(attrs[0]), BLUED_PERSIST_MAX_GATTSRV_ATTRS, attrs,
	    nattrs, NULL) != 0)
		return (-1);
	/* Clamp each stored value length to the physical buffer. */
	for (i = 0; i < *nattrs; i++) {
		if (attrs[i].value_len > BLUED_PERSIST_GATTSRV_VALLEN)
			attrs[i].value_len = BLUED_PERSIST_GATTSRV_VALLEN;
	}
	return (0);
}

/* ================================================================
 * Helpers.
 * ================================================================ */
int
blued_persist_open_dir(const char *path)
{
	struct stat sb;
	int fd;

	if (path == NULL)
		return (-1);
	if (mkdir(path, 0700) != 0 && errno != EEXIST)
		return (-1);
	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_CLOFORK |
	    O_NOFOLLOW);
	if (fd < 0)
		return (-1);
	if (fstat(fd, &sb) != 0 || !S_ISDIR(sb.st_mode) ||
	    sb.st_uid != geteuid() || fchmod(fd, 0700) != 0) {
		(void)close(fd);
		errno = EPERM;
		return (-1);
	}
	return (fd);
}

bool
blued_persist_gatt_hash_matches(const struct blued_persist_gatt_device *d,
    const uint8_t db_hash[16])
{
	if (d == NULL || !d->has_db_hash)
		return (false);
	return (memcmp(d->db_hash, db_hash, 16) == 0);
}

struct blued_persist_device *
blued_persist_devcache_find(struct blued_persist_device *devs, uint32_t ndevs,
    const uint8_t addr[6], uint8_t addr_type)
{
	uint32_t i;

	for (i = 0; i < ndevs; i++) {
		if (devs[i].addr_type == addr_type &&
		    memcmp(devs[i].addr, addr, 6) == 0)
			return (&devs[i]);
	}
	return (NULL);
}

struct blued_persist_gatt_device *
blued_persist_gattcache_find(struct blued_persist_gatt_device *devs,
    uint32_t ndevs, const uint8_t addr[6], uint8_t addr_type)
{
	uint32_t i;

	for (i = 0; i < ndevs; i++) {
		if (devs[i].addr_type == addr_type &&
		    memcmp(devs[i].addr, addr, 6) == 0)
			return (&devs[i]);
	}
	return (NULL);
}
