/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/endian.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <logcmp.h>
#include <logcmp_server.h>

#include "logd_probes.h"
#include "store.h"

#define	STORE_FILE		"active.segment"
#define	STORE_FILE_MAGIC	0x4c534547U	/* LSEG */
#define	STORE_RECORD_MAGIC	0x4c524543U	/* LREC */
#define	STORE_VERSION		1U
#define	STORE_FILE_HEADER	32U
#define	STORE_RECORD_HEADER	24U
#define	STORE_BODY_HEADER	4U
#define	STORE_LABEL_MAX		63U

#define	STORE_LABEL_COUNTERS	128U

struct store_label_count {
	char		label[STORE_LABEL_MAX + 1];
	uint64_t	count;
};

struct logcmp_store {
	int		fd;
	int		dirfd;
	uint64_t	generation;
	uint64_t	segment_limit;
	uint32_t	max_segments;
	off_t		offset;
	uint64_t	retention_max_age_ns;
	uint64_t	retention_max_bytes;
	uint64_t	pruned_segments;
	uint64_t	pruned_records;
	uint8_t		privacy_key[LOGCMP_STORE_PRIVACY_KEY_SIZE];
	size_t		nlabel_counts;
	struct store_label_count label_counts[STORE_LABEL_COUNTERS];
	size_t		nreclaimed;
	char		reclaimed[LOGCMP_STORE_RECLAIMED_MAX][STORE_LABEL_MAX + 1];
};

/*
 * A label is reclaimed when its owning bundle has been retired (see
 * logcmp_store_reclaim_label).  The set is small and linear-scanned; a reclaimed
 * label's records are treated as absent by every read path below.
 */
static bool
label_reclaimed(const struct logcmp_store *store, const char *label)
{
	size_t i;

	for (i = 0; i < store->nreclaimed; i++)
		if (strcmp(store->reclaimed[i], label) == 0)
			return (true);
	return (false);
}

static int
harden_file(int fd)
{
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_PREAD, CAP_PWRITE,
	    CAP_SEEK, CAP_FSTAT, CAP_FTRUNCATE, CAP_FSYNC, CAP_FCNTL);
	return (cap_rights_limit(fd, &rights) == -1 ||
	    cap_fcntls_limit(fd, CAP_FCNTL_GETFL | CAP_FCNTL_SETFL) == -1 ||
	    cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

static int
harden_reader(int fd)
{
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_READ, CAP_PREAD, CAP_SEEK, CAP_FSTAT);
	return (cap_rights_limit(fd, &rights) == -1 ||
	    cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

static uint32_t
crc32c_update(uint32_t crc, const void *buffer, size_t length)
{
	const uint8_t *bytes;
	size_t i;
	unsigned bit;

	bytes = buffer;
	crc = ~crc;
	for (i = 0; i < length; i++) {
		crc ^= bytes[i];
		for (bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^
			    (UINT32_C(0x82f63b78) & (0U - (crc & 1U)));
	}
	return (~crc);
}

static int
full_pread(int fd, void *buffer, size_t length, off_t offset, size_t *readp)
{
	uint8_t *cursor;
	ssize_t amount;
	size_t done;

	cursor = buffer;
	done = 0;
	while (done < length) {
		amount = pread(fd, cursor + done, length - done, offset + done);
		if (amount == 0)
			break;
		if (amount == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		done += (size_t)amount;
	}
	*readp = done;
	return (0);
}

static int
full_writev(int fd, struct iovec *iov, int iovcnt)
{
	ssize_t amount;
	int first;

	first = 0;
	while (first < iovcnt) {
		amount = writev(fd, &iov[first], iovcnt - first);
		if (amount == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (amount == 0) {
			errno = EIO;
			return (-1);
		}
		while (first < iovcnt && amount >= (ssize_t)iov[first].iov_len) {
			amount -= (ssize_t)iov[first].iov_len;
			first++;
		}
		if (first < iovcnt && amount != 0) {
			iov[first].iov_base = (uint8_t *)iov[first].iov_base + amount;
			iov[first].iov_len -= (size_t)amount;
		}
	}
	return (0);
}

static int
write_file_header(int fd, uint64_t generation)
{
	uint8_t header[STORE_FILE_HEADER];
	struct timespec now;
	struct iovec iov;

	memset(header, 0, sizeof(header));
	le32enc(header, STORE_FILE_MAGIC);
	le16enc(header + 4, STORE_VERSION);
	le16enc(header + 6, STORE_FILE_HEADER);
	le64enc(header + 8, generation);
	if (clock_gettime(CLOCK_REALTIME, &now) == -1)
		return (-1);
	le64enc(header + 16, (uint64_t)now.tv_sec * UINT64_C(1000000000) +
	    (uint64_t)now.tv_nsec);
	le32enc(header + 24, crc32c_update(0, header, 24));
	iov.iov_base = header;
	iov.iov_len = sizeof(header);
	return (full_writev(fd, &iov, 1));
}

static int
read_file_header(int fd, uint64_t *generationp)
{
	uint8_t header[STORE_FILE_HEADER];
	size_t amount;

	if (full_pread(fd, header, sizeof(header), 0, &amount) == -1)
		return (-1);
	if (amount != sizeof(header) || le32dec(header) != STORE_FILE_MAGIC ||
	    le16dec(header + 4) != STORE_VERSION ||
	    le16dec(header + 6) != STORE_FILE_HEADER ||
	    le32dec(header + 24) != crc32c_update(0, header, 24)) {
		errno = EILSEQ;
		return (-1);
	}
	*generationp = le64dec(header + 8);
	if (*generationp == 0) {
		errno = EILSEQ;
		return (-1);
	}
	return (0);
}

static int
recover_tail(int fd, off_t size, off_t *offsetp)
{
	uint8_t header[STORE_RECORD_HEADER];
	uint8_t *body;
	uint32_t body_length, checksum;
	off_t offset;
	size_t amount;

	offset = STORE_FILE_HEADER;
	while (offset < size) {
		if (full_pread(fd, header, sizeof(header), offset, &amount) == -1)
			return (-1);
		if (amount < sizeof(header))
			goto truncate_tail;
		body_length = le32dec(header + 8);
		if (le32dec(header) != STORE_RECORD_MAGIC ||
		    le16dec(header + 4) != STORE_VERSION ||
		    le16dec(header + 6) != STORE_RECORD_HEADER ||
		    body_length < STORE_BODY_HEADER ||
		    body_length > STORE_LABEL_MAX + STORE_BODY_HEADER +
		    LOGCMP_MAX_RECORD || le32dec(header + 16) != 0 ||
		    le32dec(header + 20) != 0) {
			errno = EILSEQ;
			return (-1);
		}
		if ((uint64_t)offset + sizeof(header) + body_length >
		    (uint64_t)size)
			goto truncate_tail;
		body = malloc(body_length);
		if (body == NULL)
			return (-1);
		if (full_pread(fd, body, body_length, offset + sizeof(header),
		    &amount) == -1) {
			free(body);
			return (-1);
		}
		checksum = crc32c_update(0, body, body_length);
		if (amount != body_length || checksum != le32dec(header + 12) ||
		    le16dec(body) == 0 || le16dec(body) > STORE_LABEL_MAX ||
		    le16dec(body + 2) != 0 ||
		    (size_t)le16dec(body) + STORE_BODY_HEADER >= body_length ||
		    logcmp_validate_record((const void *)(body + STORE_BODY_HEADER +
		    le16dec(body)), body_length - STORE_BODY_HEADER -
		    le16dec(body)) == -1) {
			free(body);
			errno = EILSEQ;
			return (-1);
		}
		free(body);
		offset += sizeof(header) + body_length;
	}
	*offsetp = offset;
	return (0);

truncate_tail:
	if (ftruncate(fd, offset) == -1)
		return (-1);
	*offsetp = offset;
	return (0);
}

static bool
valid_label(const char *label, size_t *lengthp)
{
	size_t length, i;

	if (label == NULL)
		return (false);
	length = strnlen(label, STORE_LABEL_MAX + 1);
	if (length == 0 || length > STORE_LABEL_MAX)
		return (false);
	for (i = 0; i < length; i++)
		if ((unsigned char)label[i] < 0x20 || label[i] == 0x7f)
			return (false);
	*lengthp = length;
	return (true);
}

static bool
segment_name_generation(const char *name, uint64_t *generation)
{
	char expected[64];
	uintmax_t value;
	int consumed;

	consumed = 0;
	if (sscanf(name, "segment-%20ju.log%n", &value, &consumed) != 1 ||
	    consumed == 0 || name[consumed] != '\0' || value == 0 ||
	    snprintf(expected, sizeof(expected), "segment-%020ju.log", value) >=
	    (int)sizeof(expected) || strcmp(name, expected) != 0)
		return (false);
	*generation = (uint64_t)value;
	return (true);
}

static int
highest_completed_generation(int dirfd, uint64_t *generationp)
{
	struct dirent *entry;
	DIR *directory;
	uint64_t generation, highest;
	int duplicate, error;

	duplicate = openat(dirfd, ".",
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (duplicate == -1)
		return (-1);
	directory = fdopendir(duplicate);
	if (directory == NULL) {
		error = errno;
		close(duplicate);
		return (errno = error, -1);
	}
	highest = 0;
	for (;;) {
		errno = 0;
		entry = readdir(directory);
		if (entry == NULL)
			break;
		if (segment_name_generation(entry->d_name, &generation) &&
		    generation > highest)
			highest = generation;
	}
	error = errno;
	closedir(directory);
	if (error != 0)
		return (errno = error, -1);
	*generationp = highest;
	return (0);
}

/*
 * Move an unrecoverable active segment aside so a single corrupt record (or a
 * stale/rewound generation) left by an unclean shutdown does not prevent the
 * logging plane from starting.  The segment is renamed to a unique
 * "active.segment.corrupt.<seq>" name and preserved for post-mortem.
 *
 * This is the owner's policy hook, not the store's: logcmp_store_open() surfaces
 * corruption as EILSEQ (see store.h), and the owner calls this and then reopens,
 * which creates a fresh active segment.  Operates purely on the borrowed
 * directory descriptor by name, so it needs no open store handle (the failed
 * open already closed its descriptor).  ENOENT (nothing to quarantine) is
 * success.
 */
int
logcmp_store_quarantine(int dirfd)
{
	char name[80];
	uintmax_t sequence;
	int error;

	for (sequence = 0;; sequence++) {
		if (snprintf(name, sizeof(name), STORE_FILE ".corrupt.%020ju",
		    sequence) >= (int)sizeof(name))
			return (errno = EOVERFLOW, -1);
		if (faccessat(dirfd, name, F_OK, AT_SYMLINK_NOFOLLOW) == -1) {
			if (errno == ENOENT)
				break;
			return (-1);
		}
		if (sequence == UINTMAX_MAX)
			return (errno = EEXIST, -1);
	}
	if (renameat(dirfd, STORE_FILE, dirfd, name) == -1) {
		if (errno == ENOENT)
			return (0);
		error = errno != 0 ? errno : EIO;
		return (errno = error, -1);
	}
	if (fsync(dirfd) == -1) {
		error = errno != 0 ? errno : EIO;
		return (errno = error, -1);
	}
	return (0);
}

static int
create_active(struct logcmp_store *store, uint64_t generation)
{
	int error;

	if (generation == 0)
		return (errno = EOVERFLOW, -1);
	store->fd = openat(store->dirfd, STORE_FILE,
	    O_RDWR | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC | O_NOFOLLOW,
	    0600);
	if (store->fd == -1)
		return (-1);
	if (harden_file(store->fd) == -1 ||
	    write_file_header(store->fd, generation) == -1 ||
	    fdatasync(store->fd) == -1 || fsync(store->dirfd) == -1) {
		error = errno != 0 ? errno : EIO;
		close(store->fd);
		store->fd = -1;
		(void)unlinkat(store->dirfd, STORE_FILE, 0);
		errno = error;
		return (-1);
	}
	store->generation = generation;
	store->offset = STORE_FILE_HEADER;
	return (0);
}

static int
prune_segments(struct logcmp_store *store)
{
	struct dirent *entry;
	DIR *directory;
	uint64_t generation, threshold;
	int duplicate, error;

	if (store->generation <= store->max_segments)
		return (0);
	threshold = store->generation - store->max_segments;
	duplicate = openat(store->dirfd, ".",
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (duplicate == -1)
		return (-1);
	directory = fdopendir(duplicate);
	if (directory == NULL) {
		error = errno;
		close(duplicate);
		return (errno = error, -1);
	}
	for (;;) {
		errno = 0;
		entry = readdir(directory);
		if (entry == NULL)
			break;
		if (!segment_name_generation(entry->d_name, &generation) ||
		    generation >= threshold)
			continue;
		if (unlinkat(store->dirfd, entry->d_name, 0) == -1 &&
		    errno != ENOENT) {
			error = errno;
			closedir(directory);
			return (errno = error, -1);
		}
	}
	error = errno;
	closedir(directory);
	return (error == 0 ? 0 : (errno = error, -1));
}

static void
private_hash(const uint8_t key[LOGCMP_STORE_PRIVACY_KEY_SIZE],
    const void *value, size_t value_length,
    char output[LOGCMP_PRIVATE_HASH_LENGTH + 1])
{
	static const char hex[] = "0123456789abcdef";
	SHA256_CTX context;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	size_t i;

	SHA256_Init(&context);
	SHA256_Update(&context, key, LOGCMP_STORE_PRIVACY_KEY_SIZE);
	SHA256_Update(&context, value, value_length);
	SHA256_Final(digest, &context);
	memcpy(output, "<private:", 9);
	for (i = 0; i < 16; i++) {
		output[9 + i * 2] = hex[digest[i] >> 4];
		output[10 + i * 2] = hex[digest[i] & 0x0f];
	}
	output[41] = '>';
	output[42] = '\0';
	explicit_bzero(digest, sizeof(digest));
	explicit_bzero(&context, sizeof(context));
}

int
logcmp_record_redact(const struct logcmp_record *record, size_t length,
    const uint8_t key[LOGCMP_STORE_PRIVACY_KEY_SIZE], void *output,
    size_t capacity, size_t *lengthp)
{
	static const char hidden[] = "<private>";
	char hashed[LOGCMP_PRIVATE_HASH_LENGTH + 1];
	struct logcmp_attribute_wire source_attribute, target_attribute;
	struct logcmp_record *target;
	const uint8_t *source, *source_end, *value;
	uint8_t *cursor;
	const char *replacement;
	size_t prefix, target_length, replacement_length, i;

	if (record == NULL || key == NULL || output == NULL || lengthp == NULL ||
	    logcmp_validate_record(record, length) == -1) {
		if (errno == 0)
			errno = EINVAL;
		return (-1);
	}
	prefix = sizeof(*record) + record->subsystem_length +
	    record->category_length + record->event_name_length;
	target_length = prefix + (record->message_privacy ==
	    LOGCMP_PRIVACY_PUBLIC ? record->message_length :
	    record->message_privacy == LOGCMP_PRIVACY_PRIVATE_HASH ?
	    LOGCMP_PRIVATE_HASH_LENGTH : sizeof(hidden) - 1);
	source = (const uint8_t *)record + prefix + record->message_length;
	source_end = source + record->attributes_length;
	for (i = 0; i < record->attribute_count; i++) {
		memcpy(&source_attribute, source, sizeof(source_attribute));
		source += sizeof(source_attribute) + source_attribute.key_length;
		replacement_length = source_attribute.privacy ==
		    LOGCMP_PRIVACY_PUBLIC ? source_attribute.value_length :
		    source_attribute.privacy == LOGCMP_PRIVACY_PRIVATE_HASH ?
		    LOGCMP_PRIVATE_HASH_LENGTH : sizeof(hidden) - 1;
		target_length += sizeof(source_attribute) +
		    source_attribute.key_length + replacement_length;
		source += source_attribute.value_length;
	}
	if (source != source_end || target_length > capacity) {
		errno = target_length > capacity ? EMSGSIZE : EPROTO;
		return (-1);
	}
	memcpy(output, record, prefix);
	target = output;
	cursor = (uint8_t *)output + prefix;
	if (record->message_privacy == LOGCMP_PRIVACY_PUBLIC) {
		memcpy(cursor, (const uint8_t *)record + prefix,
		    record->message_length);
		cursor += record->message_length;
	} else {
		if (record->message_privacy == LOGCMP_PRIVACY_PRIVATE_HASH) {
			private_hash(key, (const uint8_t *)record + prefix,
			    record->message_length, hashed);
			replacement = hashed;
		} else
			replacement = hidden;
		replacement_length = strlen(replacement);
		memcpy(cursor, replacement, replacement_length);
		cursor += replacement_length;
		target->message_length = replacement_length;
	}
	source = (const uint8_t *)record + prefix + record->message_length;
	for (i = 0; i < record->attribute_count; i++) {
		memcpy(&source_attribute, source, sizeof(source_attribute));
		source += sizeof(source_attribute);
		memcpy(cursor, &source_attribute, sizeof(source_attribute));
		memcpy(&target_attribute, cursor, sizeof(target_attribute));
		cursor += sizeof(target_attribute);
		memcpy(cursor, source, source_attribute.key_length);
		cursor += source_attribute.key_length;
		source += source_attribute.key_length;
		value = source;
		if (source_attribute.privacy == LOGCMP_PRIVACY_PUBLIC) {
			replacement_length = source_attribute.value_length;
			memcpy(cursor, value, replacement_length);
		} else {
			if (source_attribute.privacy ==
			    LOGCMP_PRIVACY_PRIVATE_HASH) {
				private_hash(key, value,
				    source_attribute.value_length, hashed);
				replacement = hashed;
			} else
				replacement = hidden;
			replacement_length = strlen(replacement);
			target_attribute.type = LOGCMP_ATTR_STRING;
			target_attribute.value_length = replacement_length;
			memcpy(cursor - source_attribute.key_length -
			    sizeof(target_attribute), &target_attribute,
			    sizeof(target_attribute));
			memcpy(cursor, replacement, replacement_length);
		}
		cursor += replacement_length;
		source += source_attribute.value_length;
	}
	target->attributes_length = cursor - ((uint8_t *)target + prefix +
	    target->message_length);
	*lengthp = cursor - (uint8_t *)output;
	if (logcmp_validate_record(target, *lengthp) == -1)
		return (-1);
	return (0);
}

int
logcmp_store_open(int dirfd, uint64_t segment_limit, uint32_t max_segments,
    struct logcmp_store **storep)
{
	struct logcmp_store *store;
	struct stat status;
	uint64_t completed_generation;
	int error, flags;

	if (dirfd < 0 || storep == NULL || segment_limit <
	    LOGCMP_STORE_SEGMENT_MIN || segment_limit > LOGCMP_STORE_SEGMENT_MAX ||
	    max_segments < LOGCMP_STORE_SEGMENTS_MIN ||
	    max_segments > LOGCMP_STORE_SEGMENTS_MAX) {
		errno = EINVAL;
		return (-1);
	}
	store = calloc(1, sizeof(*store));
	if (store == NULL)
		return (-1);
	store->fd = -1;
	store->dirfd = dirfd;
	arc4random_buf(store->privacy_key, sizeof(store->privacy_key));
	if (highest_completed_generation(dirfd, &completed_generation) == -1)
		goto fail;
	store->fd = openat(dirfd, STORE_FILE,
	    O_RDWR | O_CLOEXEC | O_NOFOLLOW);
	if (store->fd == -1 && errno == ENOENT) {
		if (completed_generation == UINT64_MAX) {
			errno = EOVERFLOW;
			goto fail;
		}
		if (create_active(store, completed_generation + 1) == -1)
			goto fail;
		goto opened;
	}
	if (store->fd == -1)
		goto fail;
	if (fstat(store->fd, &status) == -1 || !S_ISREG(status.st_mode))
		goto fail;
	flags = fcntl(store->fd, F_GETFL);
	if (flags == -1 || fcntl(store->fd, F_SETFL, flags | O_APPEND) == -1 ||
	    harden_file(store->fd) == -1)
		goto fail;
	if (status.st_size == 0) {
		if (completed_generation == UINT64_MAX) {
			errno = EOVERFLOW;
			goto fail;
		}
		store->generation = completed_generation + 1;
		if (write_file_header(store->fd, store->generation) == -1 ||
		    fdatasync(store->fd) == -1 || fsync(dirfd) == -1)
			goto fail;
		store->offset = STORE_FILE_HEADER;
	} else {
		error = 0;
		if (status.st_size < STORE_FILE_HEADER)
			error = EILSEQ;
		else if (read_file_header(store->fd, &store->generation) == -1)
			error = errno != 0 ? errno : EILSEQ;
		else if (store->generation <= completed_generation)
			error = EILSEQ;
		else if (recover_tail(store->fd, status.st_size,
		    &store->offset) == -1)
			error = errno != 0 ? errno : EILSEQ;
		/*
		 * EILSEQ here means the active segment is unrecoverable: a
		 * complete record failing CRC/validate, a torn header, or a
		 * stale/rewound generation.  recover_tail already truncated any
		 * incomplete final record (the ordinary crash window), so this
		 * is genuine corruption.  The store surfaces it as EILSEQ; the
		 * owner decides policy (quarantine and reopen via
		 * logcmp_store_quarantine(), per store.h) rather than the store
		 * silently discarding data.  Real I/O errors (any other errno)
		 * are equally fatal here.
		 */
		if (error != 0) {
			errno = error;
			goto fail;
		}
	}
opened:
	store->segment_limit = segment_limit;
	store->max_segments = max_segments;
	if (prune_segments(store) == -1)
		goto fail;
	*storep = store;
	return (0);

fail:
	error = errno != 0 ? errno : EIO;
	if (store->fd >= 0)
		close(store->fd);
	explicit_bzero(store->privacy_key, sizeof(store->privacy_key));
	free(store);
	errno = error;
	return (-1);
}

static int
rotate_segment(struct logcmp_store *store)
{
	char name[64];

	if (snprintf(name, sizeof(name), "segment-%020ju.log",
	    (uintmax_t)store->generation) >= (int)sizeof(name)) {
		errno = EOVERFLOW;
		return (-1);
	}
	if (fdatasync(store->fd) == -1 || close(store->fd) == -1) {
		LOGD_PROBE_ROTATE(store->generation,
		    errno != 0 ? errno : EIO);
		store->fd = -1;
		return (-1);
	}
	store->fd = -1;
	if (renameat(store->dirfd, STORE_FILE, store->dirfd, name) == -1) {
		LOGD_PROBE_ROTATE(store->generation,
		    errno != 0 ? errno : EIO);
		return (-1);
	}
	if (fsync(store->dirfd) == -1 || store->generation == UINT64_MAX ||
	    create_active(store, store->generation + 1) == -1)
		return (-1);
	if (prune_segments(store) == -1) {
		LOGD_PROBE_ROTATE(store->generation,
		    errno != 0 ? errno : EIO);
		return (-1);
	}
	LOGD_PROBE_ROTATE(store->generation, 0);
	return (0);
}

/*
 * Track the number of records persisted per label so an attaching session can
 * seed its accepted counter with the total already durably held for that
 * consumer.  The table is bounded; a label that overflows it simply stops
 * contributing to the persisted total (the counter degrades, it never lies
 * high).
 */
static void
store_label_bump(struct logcmp_store *store, const char *label)
{
	size_t i;

	for (i = 0; i < store->nlabel_counts; i++)
		if (strcmp(store->label_counts[i].label, label) == 0) {
			store->label_counts[i].count++;
			return;
		}
	if (store->nlabel_counts >= STORE_LABEL_COUNTERS)
		return;
	strlcpy(store->label_counts[i].label, label,
	    sizeof(store->label_counts[i].label));
	store->label_counts[i].count = 1;
	store->nlabel_counts++;
}

uint64_t
logcmp_store_label_count(const struct logcmp_store *store, const char *label)
{
	size_t i;

	if (store == NULL || label == NULL || label_reclaimed(store, label))
		return (0);
	for (i = 0; i < store->nlabel_counts; i++)
		if (strcmp(store->label_counts[i].label, label) == 0)
			return (store->label_counts[i].count);
	return (0);
}

int
logcmp_store_reclaim_label(struct logcmp_store *store, const char *label)
{
	size_t label_length;

	if (store == NULL || !valid_label(label, &label_length))
		return (errno = EINVAL, -1);
	/*
	 * Idempotent: the retirement push (and any future reconciliation sweep)
	 * can both fire for the same label, and a label that never logged still
	 * reclaims cleanly.
	 */
	if (label_reclaimed(store, label)) {
		LOGD_PROBE_RECLAIM(label, (uint64_t)store->nreclaimed, 0);
		return (0);
	}
	if (store->nreclaimed >= LOGCMP_STORE_RECLAIMED_MAX) {
		LOGD_PROBE_RECLAIM(label, (uint64_t)store->nreclaimed, ENOSPC);
		return (errno = ENOSPC, -1);
	}
	strlcpy(store->reclaimed[store->nreclaimed], label,
	    sizeof(store->reclaimed[store->nreclaimed]));
	store->nreclaimed++;
	LOGD_PROBE_RECLAIM(label, (uint64_t)store->nreclaimed, 0);
	return (0);
}

int
logcmp_store_append(struct logcmp_store *store, const char *label,
    const struct logcmp_record *record, size_t length, bool durable)
{
	uint8_t redacted[LOGCMP_MAX_RECORD], header[STORE_RECORD_HEADER];
	uint8_t body_header[STORE_BODY_HEADER];
	struct iovec iov[4];
	size_t label_length, redacted_length;
	uint32_t checksum;
	uint64_t entry_length;

	if (store == NULL || store->fd < 0 ||
	    !valid_label(label, &label_length))
		return (errno = EINVAL, -1);
	if (logcmp_record_redact(record, length, store->privacy_key, redacted,
	    sizeof(redacted), &redacted_length) == -1)
		return (-1);
	entry_length = STORE_RECORD_HEADER + STORE_BODY_HEADER + label_length +
	    redacted_length;
	if (store->offset > STORE_FILE_HEADER && (uint64_t)store->offset +
	    entry_length > store->segment_limit && rotate_segment(store) == -1)
		return (-1);
	memset(body_header, 0, sizeof(body_header));
	le16enc(body_header, label_length);
	checksum = crc32c_update(0, body_header, sizeof(body_header));
	checksum = crc32c_update(checksum, label, label_length);
	checksum = crc32c_update(checksum, redacted, redacted_length);
	memset(header, 0, sizeof(header));
	le32enc(header, STORE_RECORD_MAGIC);
	le16enc(header + 4, STORE_VERSION);
	le16enc(header + 6, STORE_RECORD_HEADER);
	le32enc(header + 8, STORE_BODY_HEADER + label_length + redacted_length);
	le32enc(header + 12, checksum);
	iov[0] = (struct iovec){ .iov_base = header, .iov_len = sizeof(header) };
	iov[1] = (struct iovec){ .iov_base = body_header,
	    .iov_len = sizeof(body_header) };
	iov[2] = (struct iovec){ .iov_base = __DECONST(void *, label),
	    .iov_len = label_length };
	iov[3] = (struct iovec){ .iov_base = redacted,
	    .iov_len = redacted_length };
	if (full_writev(store->fd, iov, nitems(iov)) == -1) {
		LOGD_PROBE_PERSIST(label, store->generation, store->offset,
		    redacted_length, errno != 0 ? errno : EIO);
		return (-1);
	}
	store->offset += (off_t)entry_length;
	store_label_bump(store, label);
	if (durable && fdatasync(store->fd) == -1) {
		LOGD_PROBE_PERSIST(label, store->generation, store->offset,
		    redacted_length, errno != 0 ? errno : EIO);
		return (-1);
	}
	LOGD_PROBE_PERSIST(label, store->generation, store->offset,
	    redacted_length, 0);
	return (0);
}

int
logcmp_store_flush(struct logcmp_store *store)
{

	if (store == NULL || store->fd < 0) {
		errno = EINVAL;
		return (-1);
	}
	return (fdatasync(store->fd));
}

/*
 * Apply the optional QUERY filter to a record whose label and severity have
 * already been checked by the caller.  This only narrows the caller's own-label
 * result set; it can never admit a record the label test rejected.  Empty
 * fields are "no constraint" so a zeroed filter matches everything.
 */
static bool
record_matches_filter(const struct logcmp_record *record,
    const struct logcmp_query_filter *filter)
{
	const char *subsystem, *category;

	if (filter == NULL)
		return (true);
	if (filter->from_ns != 0 && record->timestamp_ns < filter->from_ns)
		return (false);
	if (filter->to_ns != 0 && record->timestamp_ns > filter->to_ns)
		return (false);
	subsystem = (const char *)(const void *)(record + 1);
	category = subsystem + record->subsystem_length;
	if (filter->subsystem_length != 0) {
		if ((filter->match_flags &
		    LOGCMP_QUERY_MATCH_SUBSYSTEM_EXACT) != 0) {
			if (record->subsystem_length != filter->subsystem_length ||
			    memcmp(subsystem, filter->subsystem,
			    filter->subsystem_length) != 0)
				return (false);
		} else if (record->subsystem_length < filter->subsystem_length ||
		    memmem(subsystem, record->subsystem_length,
		    filter->subsystem, filter->subsystem_length) == NULL)
			return (false);
	}
	if (filter->category_length != 0) {
		if ((filter->match_flags &
		    LOGCMP_QUERY_MATCH_CATEGORY_EXACT) != 0) {
			if (record->category_length != filter->category_length ||
			    memcmp(category, filter->category,
			    filter->category_length) != 0)
				return (false);
		} else if (record->category_length < filter->category_length ||
		    memmem(category, record->category_length,
		    filter->category, filter->category_length) == NULL)
			return (false);
	}
	return (true);
}

int
logcmp_store_query_next_filtered(struct logcmp_store *store, const char *label,
    uint32_t minimum_severity, const struct logcmp_query_filter *filter,
    struct logcmp_store_cursor *cursor,
    void *record_buffer, size_t capacity, size_t *record_length)
{
	uint8_t header[STORE_RECORD_HEADER];
	uint8_t body[STORE_BODY_HEADER + STORE_LABEL_MAX + LOGCMP_MAX_RECORD];
	const struct logcmp_record *record;
	struct stat status;
	uint64_t file_generation, generation, oldest;
	uint32_t body_length;
	char name[64];
	size_t amount, label_length, stored_label_length;
	size_t scanned_bytes;
	off_t offset;
	int fd, error;
	unsigned scanned_records, scanned_segments;

	if (store == NULL || store->fd < 0 || cursor == NULL ||
	    record_buffer == NULL || record_length == NULL ||
	    capacity < sizeof(struct logcmp_record) ||
	    minimum_severity > LOGCMP_SEVERITY_FATAL + 3 ||
	    !valid_label(label, &label_length))
		return (errno = EINVAL, -1);
	*record_length = 0;
	scanned_bytes = 0;
	scanned_records = 0;
	scanned_segments = 0;
	/*
	 * A retired (reclaimed) label's records are logically gone: report EOF
	 * without scanning.  This narrows -- never widens -- the caller's own-label
	 * scope, so it can never expose another label's data, and it is idempotent.
	 */
	if (label_reclaimed(store, label)) {
		cursor->generation = store->generation;
		cursor->offset = (uint64_t)store->offset;
		LOGD_PROBE_QUERY_FILTER(label, 0, 0, LOGCMP_STORE_QUERY_EOF);
		return (LOGCMP_STORE_QUERY_EOF);
	}
	oldest = store->generation > store->max_segments ?
	    store->generation - store->max_segments : 1;
	if (cursor->generation == 0) {
		if (cursor->offset != 0)
			return (errno = EINVAL, -1);
		generation = oldest;
		offset = STORE_FILE_HEADER;
	} else {
		if (cursor->generation < oldest)
			return (errno = ESTALE, -1);
		if (cursor->generation > store->generation ||
		    cursor->offset < STORE_FILE_HEADER || cursor->offset > OFF_MAX)
			return (errno = EINVAL, -1);
		generation = cursor->generation;
		offset = (off_t)cursor->offset;
	}
	for (; generation <= store->generation; generation++) {
		if (scanned_segments == LOGCMP_STORE_QUERY_SEGMENT_BUDGET) {
			cursor->generation = generation;
			cursor->offset = (uint64_t)offset;
			return (LOGCMP_STORE_QUERY_CONTINUE);
		}
		scanned_segments++;
		if (generation == store->generation)
			strlcpy(name, STORE_FILE, sizeof(name));
		else if (snprintf(name, sizeof(name), "segment-%020ju.log",
		    (uintmax_t)generation) >= (int)sizeof(name))
			return (errno = EOVERFLOW, -1);
		fd = openat(store->dirfd, name,
		    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (fd == -1) {
			if (errno == ENOENT && generation < store->generation) {
				offset = STORE_FILE_HEADER;
				continue;
			}
			return (-1);
		}
		if (harden_reader(fd) == -1 || fstat(fd, &status) == -1 ||
		    !S_ISREG(status.st_mode) ||
		    read_file_header(fd, &file_generation) == -1) {
			error = errno != 0 ? errno : EILSEQ;
			close(fd);
			return (errno = error, -1);
		}
		if (file_generation != generation) {
			close(fd);
			return (errno = EILSEQ, -1);
		}
		if (offset > status.st_size) {
			close(fd);
			return (errno = EINVAL, -1);
		}
		while (offset < status.st_size) {
			if (full_pread(fd, header, sizeof(header), offset,
			    &amount) == -1)
				goto read_fail;
			if (amount != sizeof(header) ||
			    le32dec(header) != STORE_RECORD_MAGIC ||
			    le16dec(header + 4) != STORE_VERSION ||
			    le16dec(header + 6) != STORE_RECORD_HEADER ||
			    le32dec(header + 16) != 0 || le32dec(header + 20) != 0)
				goto corrupt;
			body_length = le32dec(header + 8);
			if (body_length < STORE_BODY_HEADER ||
			    body_length > sizeof(body) ||
			    (uint64_t)offset + sizeof(header) + body_length >
			    (uint64_t)status.st_size)
				goto corrupt;
			/*
			 * Do not let one no-match query monopolize the storage manager.
			 * Leave the cursor at this record so the next slice validates and
			 * consumes it.  At least one record is always processed.
			 */
			if (scanned_records != 0 &&
			    scanned_bytes + body_length >
			    LOGCMP_STORE_QUERY_BYTE_BUDGET) {
				cursor->generation = generation;
				cursor->offset = (uint64_t)offset;
				close(fd);
				return (LOGCMP_STORE_QUERY_CONTINUE);
			}
			if (full_pread(fd, body, body_length,
			    offset + sizeof(header), &amount) == -1)
				goto read_fail;
			stored_label_length = le16dec(body);
			if (amount != body_length || le16dec(body + 2) != 0 ||
			    stored_label_length == 0 ||
			    stored_label_length > STORE_LABEL_MAX ||
			    STORE_BODY_HEADER + stored_label_length >= body_length ||
			    le32dec(header + 12) != crc32c_update(0, body,
			    body_length))
				goto corrupt;
			record = (const void *)(body + STORE_BODY_HEADER +
			    stored_label_length);
			amount = body_length - STORE_BODY_HEADER -
			    stored_label_length;
			if (logcmp_validate_record(record, amount) == -1)
				goto corrupt;
			offset += sizeof(header) + body_length;
			scanned_records++;
			scanned_bytes += body_length;
			if (stored_label_length != label_length ||
			    memcmp(body + STORE_BODY_HEADER, label, label_length) != 0 ||
			    (minimum_severity != 0 &&
			    record->severity < minimum_severity) ||
			    !record_matches_filter(record, filter)) {
				cursor->generation = generation;
				cursor->offset = (uint64_t)offset;
				if (scanned_records ==
				    LOGCMP_STORE_QUERY_RECORD_BUDGET) {
					close(fd);
					return (LOGCMP_STORE_QUERY_CONTINUE);
				}
				continue;
			}
			if (amount > capacity) {
				close(fd);
				return (errno = EMSGSIZE, -1);
			}
			memcpy(record_buffer, record, amount);
			*record_length = amount;
			cursor->generation = generation;
			cursor->offset = (uint64_t)offset;
			close(fd);
			LOGD_PROBE_QUERY_FILTER(label, scanned_records, 1,
			    LOGCMP_STORE_QUERY_RECORD);
			return (LOGCMP_STORE_QUERY_RECORD);
		}
		close(fd);
		offset = STORE_FILE_HEADER;
	}
	cursor->generation = store->generation;
	cursor->offset = (uint64_t)store->offset;
	LOGD_PROBE_QUERY_FILTER(label, scanned_records, 0,
	    LOGCMP_STORE_QUERY_EOF);
	return (LOGCMP_STORE_QUERY_EOF);

corrupt:
	error = EILSEQ;
	close(fd);
	return (errno = error, -1);
read_fail:
	error = errno != 0 ? errno : EIO;
	close(fd);
	return (errno = error, -1);
}

int
logcmp_store_query_next(struct logcmp_store *store, const char *label,
    uint32_t minimum_severity, struct logcmp_store_cursor *cursor,
    void *record_buffer, size_t capacity, size_t *record_length)
{

	return (logcmp_store_query_next_filtered(store, label, minimum_severity,
	    NULL, cursor, record_buffer, capacity, record_length));
}

void
logcmp_store_set_retention(struct logcmp_store *store, uint64_t max_age_s,
    uint64_t max_bytes)
{

	if (store == NULL)
		return;
	store->retention_max_age_ns = max_age_s > UINT64_MAX / UINT64_C(1000000000)
	    ? UINT64_MAX : max_age_s * UINT64_C(1000000000);
	store->retention_max_bytes = max_bytes;
}

uint64_t
logcmp_store_pruned_segments(const struct logcmp_store *store)
{

	return (store != NULL ? store->pruned_segments : 0);
}

uint64_t
logcmp_store_pruned_records(const struct logcmp_store *store)
{

	return (store != NULL ? store->pruned_records : 0);
}

struct retention_entry {
	uint64_t	generation;
	uint64_t	mtime_ns;
	uint64_t	size;
};

static int
retention_entry_cmp(const void *a, const void *b)
{
	const struct retention_entry *ea = a, *eb = b;

	if (ea->generation < eb->generation)
		return (-1);
	if (ea->generation > eb->generation)
		return (1);
	return (0);
}

/*
 * Best-effort count of the whole records in a completed segment, for the
 * retention__prune probe only.  Walks record headers structurally and stops at
 * the first inconsistency or short read; it never fails the prune.
 */
static uint64_t
retention_count_records(int dirfd, const char *name)
{
	uint8_t header[STORE_RECORD_HEADER];
	struct stat status;
	uint64_t records;
	uint32_t body_length;
	off_t offset;
	size_t amount;
	int fd;

	fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1)
		return (0);
	if (fstat(fd, &status) == -1 || !S_ISREG(status.st_mode)) {
		close(fd);
		return (0);
	}
	records = 0;
	offset = STORE_FILE_HEADER;
	while (offset < status.st_size) {
		if (full_pread(fd, header, sizeof(header), offset, &amount) == -1 ||
		    amount != sizeof(header) ||
		    le32dec(header) != STORE_RECORD_MAGIC)
			break;
		body_length = le32dec(header + 8);
		if (body_length < STORE_BODY_HEADER ||
		    (uint64_t)offset + sizeof(header) + body_length >
		    (uint64_t)status.st_size)
			break;
		offset += sizeof(header) + body_length;
		records++;
	}
	close(fd);
	return (records);
}

static int
retention_prune_one(struct logcmp_store *store,
    const struct retention_entry *entry, int reason)
{
	char name[64];
	uint64_t records;

	if (snprintf(name, sizeof(name), "segment-%020ju.log",
	    (uintmax_t)entry->generation) >= (int)sizeof(name))
		return (errno = EOVERFLOW, -1);
	records = retention_count_records(store->dirfd, name);
	if (unlinkat(store->dirfd, name, 0) == -1) {
		if (errno == ENOENT)
			return (0);
		LOGD_PROBE_RETENTION(entry->generation, records, entry->size,
		    reason == LOGCMP_STORE_RETENTION_AGE ? -reason : reason);
		return (-1);
	}
	store->pruned_segments++;
	store->pruned_records += records;
	LOGD_PROBE_RETENTION(entry->generation, records, entry->size, reason);
	return (0);
}

/*
 * Enforce the configured retention policy.  Prunes oldest completed segments
 * whose age exceeds retention_max_age, then, if the whole store (active segment
 * included in the byte accounting) still exceeds retention_max_bytes, prunes
 * oldest completed segments until it no longer does.  Never touches the active
 * segment (only "segment-*.log" completed files are candidates) and only ever
 * removes whole segments, so no partial record is ever dropped.  A pruned
 * segment's records were, by definition, outside policy.
 */
int
logcmp_store_enforce_retention(struct logcmp_store *store)
{
	struct retention_entry *entries;
	struct dirent *entry;
	struct stat status;
	DIR *directory;
	struct timespec now;
	uint64_t generation, now_ns, total;
	size_t count, capacity, i;
	int duplicate, error;

	if (store == NULL || store->fd < 0)
		return (errno = EINVAL, -1);
	if (store->retention_max_age_ns == 0 && store->retention_max_bytes == 0)
		return (0);
	if (clock_gettime(CLOCK_REALTIME, &now) == -1)
		return (-1);
	now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
	    (uint64_t)now.tv_nsec;
	duplicate = openat(store->dirfd, ".",
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (duplicate == -1)
		return (-1);
	directory = fdopendir(duplicate);
	if (directory == NULL) {
		error = errno;
		close(duplicate);
		return (errno = error, -1);
	}
	entries = NULL;
	count = 0;
	capacity = 0;
	/* The active segment counts toward the store's total size. */
	total = store->offset > 0 ? (uint64_t)store->offset : 0;
	for (;;) {
		errno = 0;
		entry = readdir(directory);
		if (entry == NULL)
			break;
		if (!segment_name_generation(entry->d_name, &generation) ||
		    generation >= store->generation)
			continue;
		if (fstatat(store->dirfd, entry->d_name, &status,
		    AT_SYMLINK_NOFOLLOW) == -1) {
			if (errno == ENOENT)
				continue;
			error = errno;
			goto fail;
		}
		if (!S_ISREG(status.st_mode))
			continue;
		if (count == capacity) {
			struct retention_entry *grown;
			size_t next = capacity == 0 ? 16 : capacity * 2;

			grown = reallocarray(entries, next, sizeof(*entries));
			if (grown == NULL) {
				error = errno;
				goto fail;
			}
			entries = grown;
			capacity = next;
		}
		entries[count].generation = generation;
		entries[count].mtime_ns = (uint64_t)status.st_mtim.tv_sec *
		    UINT64_C(1000000000) + (uint64_t)status.st_mtim.tv_nsec;
		entries[count].size = (uint64_t)status.st_size;
		total += entries[count].size;
		count++;
	}
	if (errno != 0) {
		error = errno;
		goto fail;
	}
	closedir(directory);
	if (count == 0)
		return (0);
	qsort(entries, count, sizeof(*entries), retention_entry_cmp);
	i = 0;
	/* Age pass: oldest first, stop at the first segment within policy. */
	if (store->retention_max_age_ns != 0) {
		for (; i < count; i++) {
			if (now_ns <= entries[i].mtime_ns ||
			    now_ns - entries[i].mtime_ns <=
			    store->retention_max_age_ns)
				break;
			if (retention_prune_one(store, &entries[i],
			    LOGCMP_STORE_RETENTION_AGE) == -1) {
				error = errno;
				free(entries);
				return (errno = error, -1);
			}
			total -= MIN(total, entries[i].size);
		}
	}
	/* Size pass: keep pruning oldest completed segments over budget. */
	if (store->retention_max_bytes != 0) {
		for (; i < count && total > store->retention_max_bytes; i++) {
			if (retention_prune_one(store, &entries[i],
			    LOGCMP_STORE_RETENTION_SIZE) == -1) {
				error = errno;
				free(entries);
				return (errno = error, -1);
			}
			total -= MIN(total, entries[i].size);
		}
	}
	free(entries);
	return (0);

fail:
	closedir(directory);
	free(entries);
	return (errno = error, -1);
}

uint64_t
logcmp_store_generation(const struct logcmp_store *store)
{

	return (store != NULL ? store->generation : 0);
}

off_t
logcmp_store_offset(const struct logcmp_store *store)
{

	return (store != NULL ? store->offset : -1);
}

void
logcmp_store_close(struct logcmp_store *store)
{

	if (store == NULL)
		return;
	if (store->fd >= 0)
		close(store->fd);
	explicit_bzero(store->privacy_key, sizeof(store->privacy_key));
	free(store);
}
