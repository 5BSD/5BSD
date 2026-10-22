/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_DEST_IMAGE_H_
#define _BHYVE_MIGRATION_DEST_IMAGE_H_

/*
 * Durable destination state for controller-loss reconstruction.
 *
 * A fresh-migration destination that opts in writes one HDI1 image of the
 * committed paused guest (RAM plus the complete DEV_STATE blob) into its
 * private recovery directory and holds a per-attempt controller lock before
 * it publishes durable STAGED. COMMIT is sent only after STAGED, so a source
 * can begin retirement only for an attempt whose image is already durable.
 *
 * A successor process may reconstruct the attempt only when all of these
 * hold: it acquires the controller lock (no earlier controller for this
 * attempt is alive), the HMR2 destination phase is exactly STAGED (RELEASED
 * precedes every resume, so the guest cannot have executed from this image),
 * the exact previous incarnation has an affirmative kernel retirement
 * witness, and the new incarnation is published durably as HDS1 before any
 * guest state is loaded. Missing names, PIDs, devices, or VM objects are
 * never treated as retirement. RELEASED/RUNNING attempts are quarantined:
 * the destination may already have run and the image may be stale.
 *
 * Reconstruction does not authorize execution. The successor still runs the
 * authenticated HMX1/HXR1 recovery protocol and resumes only after the source
 * proves durable retirement. It never resumes a source.
 */

#include <sys/endian.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sha256.h>

#include "migration_recovery.h"

#define MIGRATION_DEST_BINDING_SIZE		184U
#define MIGRATION_DEST_IMAGE_HEADER_SIZE	256U
#define MIGRATION_DEST_IMAGE_TRAILER_SIZE	32U
#define MIGRATION_DEST_IMAGE_PAGE		4096U
#define MIGRATION_DEST_IMAGE_CHUNK		(1024U * 1024U)
#define MIGRATION_DEST_IMAGE_MAX_DEV		(512U * 1024U * 1024U)
#define MIGRATION_DEST_IMAGE_MAX_RAM		(1ULL << 52)
#define MIGRATION_DEST_SUCCESSOR_SIZE		128U

struct migration_dest_geometry {
	uint64_t lowmem_length;
	uint64_t highmem_base;
	uint64_t highmem_length;
};

/* Map [gpa, gpa + length) of the guest into this process, or return NULL. */
typedef void *(*migration_dest_map_t)(void *, uint64_t, size_t);

struct migration_dest_successor {
	uint32_t generation;
	uint16_t previous_vmid;
	uint64_t previous_epoch;
	uint16_t current_vmid;
	uint64_t current_epoch;
};

/* Kernel operations are injected so every refusal can be tested offline. */
struct migration_dest_reconstruct_ops {
	/* 0: the exact lifetime is retired. EBUSY: still live. Other: error. */
	int (*retired)(void *, uint16_t, uint64_t);
	/* Atomic name + exact-identity destruction request; 0 or errno. */
	int (*destroy)(void *, const char *, uint16_t, uint64_t);
};

struct migration_dest_reconstruction {
	int controller;		/* attempt controller lock, held for lifetime */
	struct migration_recovery_record record;	/* exact STAGED binding */
	struct migration_dest_geometry geometry;
	uint64_t dev_length;
	struct migration_dest_successor successor;	/* durable HDS1 */
};

static inline void
migration_dest_stem(const uint8_t challenge[32], char stem[67])
{
	static const char hex[] = "0123456789abcdef";

	stem[0] = 'd';
	stem[1] = '-';
	for (size_t i = 0; i < 32; i++) {
		stem[2 + 2 * i] = hex[challenge[i] >> 4];
		stem[3 + 2 * i] = hex[challenge[i] & 15];
	}
	stem[66] = '\0';
}

/* Parse the 64-digit lowercase operator form of an attempt challenge. */
static inline int
migration_dest_challenge_parse(const char *text, uint8_t challenge[32])
{
	uint8_t value[32];

	if (text == NULL || challenge == NULL || strlen(text) != 64)
		return (EINVAL);
	for (size_t i = 0; i < 64; i++) {
		char c = text[i];
		unsigned digit;

		if (c >= '0' && c <= '9')
			digit = (unsigned)(c - '0');
		else if (c >= 'a' && c <= 'f')
			digit = (unsigned)(c - 'a') + 10;
		else
			return (EINVAL);
		if ((i & 1) == 0)
			value[i / 2] = (uint8_t)(digit << 4);
		else
			value[i / 2] |= (uint8_t)digit;
	}
	if (memcmp(value, (const uint8_t[32]){0}, 32) == 0)
		return (EINVAL);
	memcpy(challenge, value, 32);
	return (0);
}

/* Attempt binding: HMR2 bytes 8..191, independent of the recorded phase. */
static inline int
migration_dest_binding(const struct migration_recovery_record *record,
    uint8_t binding[MIGRATION_DEST_BINDING_SIZE])
{
	struct migration_recovery_record staged;
	uint8_t wire[MIGRATION_RECOVERY_SIZE];
	int error;

	if (record == NULL || binding == NULL)
		return (EINVAL);
	staged = *record;
	staged.phase = MIGRATION_REC_DEST_STAGED;
	error = migration_recovery_encode(&staged, wire);
	if (error != 0)
		return (error);
	memcpy(binding, wire + 8, MIGRATION_DEST_BINDING_SIZE);
	return (0);
}

static inline int
migration_dest_binding_record(const uint8_t binding[MIGRATION_DEST_BINDING_SIZE],
    struct migration_recovery_record *record)
{
	uint8_t wire[MIGRATION_RECOVERY_SIZE] = {0};
	SHA256_CTX hash;

	memcpy(wire, "HMR2", 4);
	le16enc(wire + 4, 2);
	le16enc(wire + 6, MIGRATION_REC_DEST_STAGED);
	memcpy(wire + 8, binding, MIGRATION_DEST_BINDING_SIZE);
	SHA256_Init(&hash);
	SHA256_Update(&hash, wire, 192);
	SHA256_Final(wire + 192, &hash);
	/* Canonical decode rejects any invalid identity, session or pin. */
	return (migration_recovery_decode(wire, sizeof(wire), record));
}

static inline int
migration_dest_binding_digest(const struct migration_recovery_record *record,
    uint8_t digest[32])
{
	uint8_t binding[MIGRATION_DEST_BINDING_SIZE];
	SHA256_CTX hash;
	int error;

	error = migration_dest_binding(record, binding);
	if (error != 0)
		return (error);
	SHA256_Init(&hash);
	SHA256_Update(&hash, binding, sizeof(binding));
	SHA256_Final(digest, &hash);
	return (0);
}

static inline bool
migration_dest_geometry_valid(const struct migration_dest_geometry *g)
{
	if (g == NULL || g->lowmem_length == 0 ||
	    g->lowmem_length % MIGRATION_DEST_IMAGE_PAGE != 0 ||
	    g->highmem_length % MIGRATION_DEST_IMAGE_PAGE != 0 ||
	    g->highmem_base % MIGRATION_DEST_IMAGE_PAGE != 0)
		return (false);
	/* Bound guest RAM so every file-size computation is exact. */
	if (g->lowmem_length > MIGRATION_DEST_IMAGE_MAX_RAM ||
	    g->highmem_length > MIGRATION_DEST_IMAGE_MAX_RAM - g->lowmem_length)
		return (false);
	if (g->highmem_length == 0)
		return (g->highmem_base == 0);
	return (g->highmem_base >= g->lowmem_length &&
	    g->highmem_length <= UINT64_MAX - g->highmem_base);
}

static inline bool
migration_dest_identity_valid(uint16_t vmid, uint64_t epoch)
{
	return (vmid != 0 && vmid < HYPERTRACE_MAX_VMS && epoch != 0);
}

/* ---- Controller lock ---------------------------------------------------- */

/* The original controller creates the lock before durable image/STAGED and
 * keeps it for its process lifetime. A successor opens the existing inode and
 * fails with EBUSY while any earlier controller for this attempt is alive.
 * Never unlink this lock: a replacement inode would admit two owners. */
static inline int
migration_dest_controller_lock_at(int dirfd, const uint8_t challenge[32],
    bool create, int *result)
{
	char stem[67], name[96];
	int fd, error;

	if (challenge == NULL || result == NULL ||
	    memcmp(challenge, (const uint8_t[32]){0}, 32) == 0)
		return (EINVAL);
	error = migration_recovery_file_check(dirfd, true);
	if (error != 0)
		return (error);
	migration_dest_stem(challenge, stem);
	snprintf(name, sizeof(name), "%s.controller", stem);
	fd = openat(dirfd, name, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC |
	    (create ? O_CREAT | O_EXCL : 0), 0600);
	if (fd < 0)
		return (errno);
	error = migration_recovery_file_check(fd, false);
	if (error == 0 && flock(fd, LOCK_EX | LOCK_NB) != 0)
		error = errno == EWOULDBLOCK ? EBUSY : errno;
	if (error == 0 && create && fsync(fd) != 0)
		error = errno;
	if (error == 0 && create && fsync(dirfd) != 0)
		error = errno;
	if (error != 0) {
		close(fd);
		return (error);
	}
	*result = fd;
	return (0);
}

/* ---- HDI1 image ------------------------------------------------------------ */

static inline int
migration_dest_image_header_encode(const struct migration_recovery_record *record,
    const struct migration_dest_geometry *g, uint64_t dev_length,
    uint8_t wire[MIGRATION_DEST_IMAGE_HEADER_SIZE])
{
	SHA256_CTX hash;
	int error;

	if (wire == NULL || !migration_dest_geometry_valid(g) || dev_length == 0 ||
	    dev_length > MIGRATION_DEST_IMAGE_MAX_DEV)
		return (EINVAL);
	memset(wire, 0, MIGRATION_DEST_IMAGE_HEADER_SIZE);
	memcpy(wire, "HDI1", 4);
	le16enc(wire + 4, 1);
	error = migration_dest_binding(record, wire + 8);
	if (error != 0)
		return (error);
	le64enc(wire + 192, g->lowmem_length);
	le64enc(wire + 200, g->highmem_base);
	le64enc(wire + 208, g->highmem_length);
	le64enc(wire + 216, dev_length);
	SHA256_Init(&hash);
	SHA256_Update(&hash, wire, 224);
	SHA256_Final(wire + 224, &hash);
	return (0);
}

static inline int
migration_dest_image_header_decode(const uint8_t *wire, size_t length,
    struct migration_recovery_record *record, struct migration_dest_geometry *g,
    uint64_t *dev_length)
{
	struct migration_recovery_record candidate;
	struct migration_dest_geometry geometry;
	uint8_t canonical[MIGRATION_DEST_IMAGE_HEADER_SIZE];
	uint64_t dev;

	if (wire == NULL || record == NULL || g == NULL || dev_length == NULL)
		return (EINVAL);
	if (length != MIGRATION_DEST_IMAGE_HEADER_SIZE)
		return (EPROTO);
	if (migration_dest_binding_record(wire + 8, &candidate) != 0)
		return (EPROTO);
	geometry.lowmem_length = le64dec(wire + 192);
	geometry.highmem_base = le64dec(wire + 200);
	geometry.highmem_length = le64dec(wire + 208);
	dev = le64dec(wire + 216);
	if (migration_dest_image_header_encode(&candidate, &geometry, dev,
	    canonical) != 0 || memcmp(canonical, wire, sizeof(canonical)) != 0)
		return (EPROTO);
	*record = candidate;
	*g = geometry;
	*dev_length = dev;
	return (0);
}

static inline int
migration_dest_write_all(int fd, const void *buffer, size_t length,
    SHA256_CTX *hash)
{
	const uint8_t *bytes = buffer;
	size_t used = 0;
	ssize_t n;

	if (hash != NULL)
		SHA256_Update(hash, buffer, length);
	while (used < length) {
		n = write(fd, bytes + used, length - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return (n < 0 ? errno : EIO);
		used += (size_t)n;
	}
	return (0);
}

static inline int
migration_dest_read_all(int fd, void *buffer, size_t length, SHA256_CTX *hash)
{
	uint8_t *bytes = buffer;
	size_t used = 0;
	ssize_t n;

	while (used < length) {
		n = read(fd, bytes + used, length - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return (errno);
		if (n == 0)
			return (EPROTO);
		used += (size_t)n;
	}
	if (hash != NULL)
		SHA256_Update(hash, buffer, length);
	return (0);
}

static inline int
migration_dest_region_write(int fd, uint64_t gpa, uint64_t length,
    migration_dest_map_t map, void *arg, SHA256_CTX *hash)
{
	while (length != 0) {
		size_t chunk = length > MIGRATION_DEST_IMAGE_CHUNK ?
		    MIGRATION_DEST_IMAGE_CHUNK : (size_t)length;
		void *host = map(arg, gpa, chunk);
		int error;

		if (host == NULL)
			return (EFAULT);
		error = migration_dest_write_all(fd, host, chunk, hash);
		if (error != 0)
			return (error);
		gpa += chunk;
		length -= chunk;
	}
	return (0);
}

static inline int
migration_dest_region_read(int fd, uint64_t gpa, uint64_t length,
    migration_dest_map_t map, void *arg, SHA256_CTX *hash)
{
	while (length != 0) {
		size_t chunk = length > MIGRATION_DEST_IMAGE_CHUNK ?
		    MIGRATION_DEST_IMAGE_CHUNK : (size_t)length;
		void *host = map(arg, gpa, chunk);
		int error;

		if (host == NULL)
			return (EFAULT);
		error = migration_dest_read_all(fd, host, chunk, hash);
		if (error != 0)
			return (error);
		gpa += chunk;
		length -= chunk;
	}
	return (0);
}

/* Publish the image for one STAGED binding. The caller holds the attempt
 * controller lock, so no other writer exists; an existing image is refused
 * rather than replaced. Durable rename and directory sync precede success. */
static inline int
migration_dest_image_write_at(int dirfd,
    const struct migration_recovery_record *record,
    const struct migration_dest_geometry *g, migration_dest_map_t map,
    void *arg, const uint8_t *dev, size_t dev_length)
{
	uint8_t header[MIGRATION_DEST_IMAGE_HEADER_SIZE];
	uint8_t digest[32];
	char stem[67], name[96], temporary[128] = {0};
	struct stat st;
	SHA256_CTX hash;
	int fd = -1, error;

	if (record == NULL || map == NULL || dev == NULL)
		return (EINVAL);
	error = migration_dest_image_header_encode(record, g, dev_length, header);
	if (error != 0)
		return (error);
	/* Only the exact DEV_STATE bound by COMMIT may be preserved. */
	SHA256_Init(&hash);
	SHA256_Update(&hash, dev, dev_length);
	SHA256_Final(digest, &hash);
	if (memcmp(digest, record->state_digest, 32) != 0)
		return (ESTALE);
	error = migration_recovery_file_check(dirfd, true);
	if (error != 0)
		return (error);
	migration_dest_stem(record->challenge, stem);
	snprintf(name, sizeof(name), "%s.image", stem);
	if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0)
		return (EEXIST);
	if (errno != ENOENT)
		return (errno);
	snprintf(temporary, sizeof(temporary), "%s.image.tmp.%08x%08x", stem,
	    arc4random(), arc4random());
	fd = openat(dirfd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, 0600);
	if (fd < 0) {
		temporary[0] = '\0';
		return (errno);
	}
	SHA256_Init(&hash);
	error = migration_dest_write_all(fd, header, sizeof(header), &hash);
	if (error == 0)
		error = migration_dest_region_write(fd, 0, g->lowmem_length, map,
		    arg, &hash);
	if (error == 0 && g->highmem_length != 0)
		error = migration_dest_region_write(fd, g->highmem_base,
		    g->highmem_length, map, arg, &hash);
	if (error == 0)
		error = migration_dest_write_all(fd, dev, dev_length, &hash);
	if (error == 0) {
		SHA256_Final(digest, &hash);
		error = migration_dest_write_all(fd, digest, sizeof(digest), NULL);
	}
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	fd = -1;
	if (error == 0 && renameat(dirfd, temporary, dirfd, name) != 0)
		error = errno;
	if (error == 0)
		temporary[0] = '\0';
	/* A visible image without a durable directory entry is not success;
	 * the caller aborts before STAGED, which makes the image unusable. */
	if (error == 0 && fsync(dirfd) != 0)
		error = errno;
	if (temporary[0] != '\0')
		(void)unlinkat(dirfd, temporary, 0);
	return (error);
}

static inline int
migration_dest_image_open(int dirfd, const uint8_t challenge[32], int *result)
{
	char stem[67], name[96];
	int fd, error;

	error = migration_recovery_file_check(dirfd, true);
	if (error != 0)
		return (error);
	migration_dest_stem(challenge, stem);
	snprintf(name, sizeof(name), "%s.image", stem);
	fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno);
	error = migration_recovery_file_check(fd, false);
	if (error != 0) {
		close(fd);
		return (error);
	}
	*result = fd;
	return (0);
}

/* Validate the header only: the exact attempt and its sizes. */
static inline int
migration_dest_image_header_at(int dirfd, const uint8_t challenge[32],
    struct migration_recovery_record *record, struct migration_dest_geometry *g,
    uint64_t *dev_length)
{
	uint8_t header[MIGRATION_DEST_IMAGE_HEADER_SIZE];
	struct migration_recovery_record candidate;
	struct migration_dest_geometry geometry;
	uint64_t dev;
	struct stat st;
	int fd, error;

	if (challenge == NULL || record == NULL || g == NULL || dev_length == NULL)
		return (EINVAL);
	error = migration_dest_image_open(dirfd, challenge, &fd);
	if (error != 0)
		return (error);
	error = migration_dest_read_all(fd, header, sizeof(header), NULL);
	if (error == 0)
		error = migration_dest_image_header_decode(header, sizeof(header),
		    &candidate, &geometry, &dev);
	if (error == 0 && memcmp(candidate.challenge, challenge, 32) != 0)
		error = ESTALE;
	if (error == 0 && fstat(fd, &st) != 0)
		error = errno;
	if (error == 0 && (uint64_t)st.st_size != MIGRATION_DEST_IMAGE_HEADER_SIZE +
	    geometry.lowmem_length + geometry.highmem_length + dev +
	    MIGRATION_DEST_IMAGE_TRAILER_SIZE)
		error = EPROTO;
	close(fd);
	if (error != 0)
		return (error);
	*record = candidate;
	*g = geometry;
	*dev_length = dev;
	return (0);
}

/* Load guest RAM and DEV_STATE. The whole-file digest and the COMMIT state
 * digest must both match before the caller may install anything. On error,
 * guest memory may contain partial data and must not be resumed. */
static inline int
migration_dest_image_load_at(int dirfd,
    const struct migration_recovery_record *expected,
    const struct migration_dest_geometry *g, migration_dest_map_t map,
    void *arg, uint8_t **dev_out, size_t *dev_length_out)
{
	uint8_t header[MIGRATION_DEST_IMAGE_HEADER_SIZE];
	uint8_t expected_header[MIGRATION_DEST_IMAGE_HEADER_SIZE];
	uint8_t digest[32], trailer[32], extra;
	struct migration_recovery_record candidate;
	struct migration_dest_geometry geometry;
	uint64_t dev_length;
	uint8_t *dev = NULL;
	SHA256_CTX hash, state;
	ssize_t n;
	int fd, error;

	if (expected == NULL || g == NULL || map == NULL || dev_out == NULL ||
	    dev_length_out == NULL)
		return (EINVAL);
	error = migration_dest_image_open(dirfd, expected->challenge, &fd);
	if (error != 0)
		return (error);
	SHA256_Init(&hash);
	error = migration_dest_read_all(fd, header, sizeof(header), &hash);
	if (error == 0)
		error = migration_dest_image_header_decode(header, sizeof(header),
		    &candidate, &geometry, &dev_length);
	/* Compare the complete attempt and local geometry, not only sizes. */
	if (error == 0 && (migration_dest_image_header_encode(expected, g,
	    dev_length, expected_header) != 0 ||
	    memcmp(expected_header, header, sizeof(header)) != 0))
		error = ESTALE;
	if (error == 0)
		error = migration_dest_region_read(fd, 0, g->lowmem_length, map, arg,
		    &hash);
	if (error == 0 && g->highmem_length != 0)
		error = migration_dest_region_read(fd, g->highmem_base,
		    g->highmem_length, map, arg, &hash);
	if (error == 0) {
		dev = malloc((size_t)dev_length);
		if (dev == NULL)
			error = ENOMEM;
	}
	if (error == 0)
		error = migration_dest_read_all(fd, dev, (size_t)dev_length, &hash);
	if (error == 0)
		error = migration_dest_read_all(fd, trailer, sizeof(trailer), NULL);
	if (error == 0) {
		do {
			n = read(fd, &extra, 1);
		} while (n < 0 && errno == EINTR);
		if (n != 0)
			error = n < 0 ? errno : EPROTO;
	}
	if (error == 0) {
		SHA256_Final(digest, &hash);
		if (memcmp(digest, trailer, sizeof(digest)) != 0)
			error = EPROTO;
	}
	if (error == 0) {
		SHA256_Init(&state);
		SHA256_Update(&state, dev, (size_t)dev_length);
		SHA256_Final(digest, &state);
		if (memcmp(digest, expected->state_digest, 32) != 0)
			error = ESTALE;
	}
	close(fd);
	if (error != 0) {
		free(dev);
		return (error);
	}
	*dev_out = dev;
	*dev_length_out = (size_t)dev_length;
	return (0);
}

/* After RELEASED and a successful resume the image is obsolete: no successor
 * may reconstruct a RELEASED attempt. Removal is housekeeping, not authority. */
static inline int
migration_dest_image_retire_at(int dirfd, const uint8_t challenge[32])
{
	char stem[67], name[96];
	int error = 0;

	migration_dest_stem(challenge, stem);
	snprintf(name, sizeof(name), "%s.image", stem);
	if (unlinkat(dirfd, name, 0) != 0 && errno != ENOENT)
		error = errno;
	if (fsync(dirfd) != 0 && error == 0)
		error = errno;
	return (error);
}

/* ---- HDS1 successor record ------------------------------------------------ */

static inline bool
migration_dest_successor_valid(const struct migration_dest_successor *s)
{
	return (s != NULL && s->generation != 0 &&
	    migration_dest_identity_valid(s->previous_vmid, s->previous_epoch) &&
	    migration_dest_identity_valid(s->current_vmid, s->current_epoch) &&
	    !(s->previous_vmid == s->current_vmid &&
	    s->previous_epoch == s->current_epoch));
}

static inline int
migration_dest_successor_encode(const uint8_t binding_digest[32],
    const struct migration_dest_successor *s,
    uint8_t wire[MIGRATION_DEST_SUCCESSOR_SIZE])
{
	SHA256_CTX hash;

	if (binding_digest == NULL || wire == NULL ||
	    !migration_dest_successor_valid(s))
		return (EINVAL);
	memset(wire, 0, MIGRATION_DEST_SUCCESSOR_SIZE);
	memcpy(wire, "HDS1", 4);
	le16enc(wire + 4, 1);
	memcpy(wire + 8, binding_digest, 32);
	le32enc(wire + 40, s->generation);
	le16enc(wire + 48, s->previous_vmid);
	le64enc(wire + 56, s->previous_epoch);
	le16enc(wire + 64, s->current_vmid);
	le64enc(wire + 72, s->current_epoch);
	SHA256_Init(&hash);
	SHA256_Update(&hash, wire, 96);
	SHA256_Final(wire + 96, &hash);
	return (0);
}

static inline int
migration_dest_successor_decode(const uint8_t *wire, size_t length,
    const uint8_t binding_digest[32], struct migration_dest_successor *s)
{
	struct migration_dest_successor candidate;
	uint8_t canonical[MIGRATION_DEST_SUCCESSOR_SIZE];

	if (wire == NULL || binding_digest == NULL || s == NULL)
		return (EINVAL);
	if (length != MIGRATION_DEST_SUCCESSOR_SIZE)
		return (EPROTO);
	candidate.generation = le32dec(wire + 40);
	candidate.previous_vmid = le16dec(wire + 48);
	candidate.previous_epoch = le64dec(wire + 56);
	candidate.current_vmid = le16dec(wire + 64);
	candidate.current_epoch = le64dec(wire + 72);
	if (migration_dest_successor_encode(wire + 8, &candidate, canonical) != 0 ||
	    memcmp(canonical, wire, sizeof(canonical)) != 0)
		return (EPROTO);
	if (memcmp(wire + 8, binding_digest, 32) != 0)
		return (ESTALE);
	*s = candidate;
	return (0);
}

/* Returns 0 with a record, ENOENT when no successor was ever published. */
static inline int
migration_dest_successor_load_at(int dirfd, const uint8_t challenge[32],
    const uint8_t binding_digest[32], struct migration_dest_successor *s)
{
	uint8_t wire[MIGRATION_DEST_SUCCESSOR_SIZE + 1];
	char stem[67], name[96];
	size_t used = 0;
	ssize_t n;
	int fd, error;

	error = migration_recovery_file_check(dirfd, true);
	if (error != 0)
		return (error);
	migration_dest_stem(challenge, stem);
	snprintf(name, sizeof(name), "%s.successor", stem);
	fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return (errno);
	error = migration_recovery_file_check(fd, false);
	while (error == 0 && used < sizeof(wire)) {
		n = read(fd, wire + used, sizeof(wire) - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			error = errno;
			break;
		}
		if (n == 0)
			break;
		used += (size_t)n;
	}
	if (error == 0)
		error = migration_dest_successor_decode(wire, used, binding_digest, s);
	/* Retry must finish uncertain durability of an earlier publication. */
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	close(fd);
	return (error);
}

/* Atomically replace the successor record under the controller lock. */
static inline int
migration_dest_successor_store_at(int dirfd, const uint8_t challenge[32],
    const uint8_t binding_digest[32], const struct migration_dest_successor *s)
{
	uint8_t wire[MIGRATION_DEST_SUCCESSOR_SIZE];
	char stem[67], name[96], temporary[128] = {0};
	int fd, error;

	error = migration_dest_successor_encode(binding_digest, s, wire);
	if (error != 0)
		return (error);
	error = migration_recovery_file_check(dirfd, true);
	if (error != 0)
		return (error);
	migration_dest_stem(challenge, stem);
	snprintf(name, sizeof(name), "%s.successor", stem);
	snprintf(temporary, sizeof(temporary), "%s.successor.tmp.%08x%08x", stem,
	    arc4random(), arc4random());
	fd = openat(dirfd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, 0600);
	if (fd < 0)
		return (errno);
	error = migration_dest_write_all(fd, wire, sizeof(wire), NULL);
	if (error == 0 && fsync(fd) != 0)
		error = errno;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error == 0 && renameat(dirfd, temporary, dirfd, name) != 0)
		error = errno;
	if (error == 0)
		temporary[0] = '\0';
	if (error == 0 && fsync(dirfd) != 0)
		error = errno;
	if (temporary[0] != '\0')
		(void)unlinkat(dirfd, temporary, 0);
	return (error);
}

/* ---- Reconstruction admission -------------------------------------------- */

/*
 * Admit one successor for an attempt. On success the caller owns
 * out->controller for its process lifetime, out->successor names the new
 * incarnation durably, and out->record is the exact STAGED attempt. The
 * caller must then load and verify the image into the new incarnation, keep
 * its startup fence held, and resume only through authenticated recovery.
 *
 * Errors: EBUSY (a controller or the previous incarnation is still live, or
 * the new context is the previous incarnation), ENOENT (no preserved
 * attempt), ENOTRECOVERABLE (RELEASED/RUNNING: the guest may have executed),
 * ESTALE/EPROTO (mismatched or corrupt evidence), and kernel witness errors.
 */
static inline int
migration_dest_reconstruct_begin(int dirfd, const uint8_t challenge[32],
    const char *name, uint16_t vmid, uint64_t epoch,
    const struct migration_dest_reconstruct_ops *ops, void *arg,
    struct migration_dest_reconstruction *out)
{
	struct migration_dest_reconstruction result;
	struct hypertrace_session_record source;
	uint8_t digest[32];
	uint16_t phase, previous_vmid;
	uint64_t previous_epoch;
	int error, controller = -1;

	if (challenge == NULL || ops == NULL || ops->retired == NULL ||
	    ops->destroy == NULL || out == NULL ||
	    !migration_dest_identity_valid(vmid, epoch) ||
	    (name != NULL && name[0] == '\0'))
		return (EINVAL);
	memset(&result, 0, sizeof(result));
	result.controller = -1;
	error = migration_dest_controller_lock_at(dirfd, challenge, false,
	    &controller);
	if (error != 0)
		return (error);
	error = migration_dest_image_header_at(dirfd, challenge, &result.record,
	    &result.geometry, &result.dev_length);
	if (error != 0)
		goto fail;
	/* STAGED is published only after the image; COMMIT only after STAGED.
	 * Without STAGED the source cannot have begun retirement. */
	error = migration_recovery_load_at(dirfd, &result.record, &phase);
	if (error != 0)
		goto fail;
	if (phase != MIGRATION_REC_DEST_STAGED) {
		error = phase == MIGRATION_REC_DEST_RELEASED ||
		    phase == MIGRATION_REC_DEST_RUNNING ? ENOTRECOVERABLE : EPROTO;
		goto fail;
	}
	error = migration_dest_binding_digest(&result.record, digest);
	if (error != 0)
		goto fail;
	error = migration_dest_successor_load_at(dirfd, challenge, digest,
	    &result.successor);
	if (error == ENOENT) {
		result.successor.generation = 0;
		previous_vmid = result.record.destination_vmid;
		previous_epoch = result.record.destination_epoch;
		error = 0;
	} else if (error == 0) {
		if (result.successor.generation == UINT32_MAX) {
			error = EOVERFLOW;
			goto fail;
		}
		previous_vmid = result.successor.current_vmid;
		previous_epoch = result.successor.current_epoch;
	} else
		goto fail;
	if (hypertrace_session_record_decode(result.record.session,
	    sizeof(result.record.session), &source) != 0) {
		error = EPROTO;
		goto fail;
	}
	/* The new context must be a distinct lifetime from every bound one. */
	if ((vmid == previous_vmid && epoch == previous_epoch) ||
	    (vmid == result.record.destination_vmid &&
	    epoch == result.record.destination_epoch) ||
	    (vmid == source.vmid && epoch == source.epoch)) {
		error = EBUSY;
		goto fail;
	}
	error = ops->retired(arg, previous_vmid, previous_epoch);
	if (error == EBUSY && name != NULL) {
		/* The name is only a lookup hint: the kernel checks the exact
		 * journal-bound lifetime atomically with scheduling destruction. */
		error = ops->destroy(arg, name, previous_vmid, previous_epoch);
		if (error == 0)
			error = ops->retired(arg, previous_vmid, previous_epoch);
	}
	if (error != 0)
		goto fail;
	/* Publish the new incarnation before any state can be loaded into it,
	 * so a later successor knows exactly which lifetime to retire. */
	result.successor.generation++;
	result.successor.previous_vmid = previous_vmid;
	result.successor.previous_epoch = previous_epoch;
	result.successor.current_vmid = vmid;
	result.successor.current_epoch = epoch;
	error = migration_dest_successor_store_at(dirfd, challenge, digest,
	    &result.successor);
	if (error != 0)
		goto fail;
	result.controller = controller;
	*out = result;
	return (0);
fail:
	close(controller);
	return (error);
}
#endif
