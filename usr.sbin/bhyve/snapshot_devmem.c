/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "snapshot_devmem.h"

#define	DEVMEM_MAGIC		UINT64_C(0x00314d4544564842) /* "BHVDEM1\0" */
#define	DEVMEM_VERSION		1U
#define	DEVMEM_HEADER_SIZE	32U
#define	DEVMEM_ENTRY_SIZE	40U
#define	DEVMEM_IO_CHUNK		(1024U * 1024U)

struct devmem_entry {
	char name[BHYVE_DEVMEM_NAME_SIZE];
	uint64_t length;
	uint64_t offset;
	uint64_t digest;
};

static bool
devmem_ranges_overlap(const void *first, size_t first_length,
    const void *second, size_t second_length)
{
	uintptr_t first_start, second_start;

	if (first_length == 0 || second_length == 0)
		return (false);
	if (first == NULL || second == NULL)
		return (true);
	first_start = (uintptr_t)first;
	second_start = (uintptr_t)second;
	if (first_start > UINTPTR_MAX - (first_length - 1) ||
	    second_start > UINTPTR_MAX - (second_length - 1))
		return (true);
	return (first_start <= second_start + second_length - 1 &&
	    second_start <= first_start + first_length - 1);
}

static int
devmem_pread_all(int fd, void *buffer, size_t length, off_t offset)
{
	uint8_t *cursor;
	ssize_t done;

	cursor = buffer;
	while (length != 0) {
		done = pread(fd, cursor, length, offset);
		if (done < 0) {
			if (errno == EINTR)
				continue;
			return (errno);
		}
		if (done == 0)
			return (EIO);
		cursor += done;
		length -= (size_t)done;
		offset += done;
	}
	return (0);
}

static int
devmem_pwrite_all(int fd, const void *buffer, size_t length, off_t offset)
{
	const uint8_t *cursor;
	ssize_t done;

	cursor = buffer;
	while (length != 0) {
		done = pwrite(fd, cursor, length, offset);
		if (done < 0) {
			if (errno == EINTR)
				continue;
			return (errno);
		}
		if (done == 0)
			return (EIO);
		cursor += done;
		length -= (size_t)done;
		offset += done;
	}
	return (0);
}

static uint64_t
devmem_digest_update(uint64_t digest, const uint8_t *bytes, size_t length)
{

	for (size_t i = 0; i < length; i++) {
		digest ^= bytes[i];
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

static uint64_t
devmem_digest_memory(const void *memory, size_t length)
{

	return (devmem_digest_update(UINT64_C(14695981039346656037),
	    memory, length));
}

static int
devmem_validate_regions(const struct bhyve_devmem_region *regions,
    size_t count)
{
	size_t metadata_size;

	if (count != 0 && regions == NULL)
		return (EINVAL);
	if (count > UINT32_MAX ||
	    count > (SIZE_MAX - DEVMEM_HEADER_SIZE) / DEVMEM_ENTRY_SIZE ||
	    count > SIZE_MAX / sizeof(*regions))
		return (E2BIG);
	metadata_size = count * sizeof(*regions);
	for (size_t i = 0; i < count; i++) {
		if (regions[i].host_base == NULL || regions[i].length == 0 ||
		    memchr(regions[i].name, '\0',
		    sizeof(regions[i].name)) == NULL ||
		    regions[i].name[0] == '\0' ||
		    devmem_ranges_overlap(regions, metadata_size,
		    regions[i].host_base, regions[i].length))
			return (EINVAL);
		for (size_t j = 0; j < i; j++) {
			if (strcmp(regions[i].name, regions[j].name) == 0)
				return (EEXIST);
			if (devmem_ranges_overlap(regions[i].host_base,
			    regions[i].length, regions[j].host_base,
			    regions[j].length))
				return (EINVAL);
		}
	}
	return (0);
}

static int
devmem_region_compare(const void *left, const void *right)
{
	const struct bhyve_devmem_region *a, *b;

	a = left;
	b = right;
	return (strcmp(a->name, b->name));
}

int
bhyve_devmem_snapshot_save(int fd, off_t normal_memory_size,
    const struct bhyve_devmem_region *regions, size_t region_count,
    size_t *extension_size)
{
	struct bhyve_devmem_region *ordered;
	struct devmem_entry *entries;
	uint8_t header[DEVMEM_HEADER_SIZE], raw[DEVMEM_ENTRY_SIZE];
	uint64_t cursor, total;
	size_t table_size;
	int error;

	if (fd < 0 || normal_memory_size < 0 || extension_size == NULL)
		return (EINVAL);
	*extension_size = 0;
	error = devmem_validate_regions(regions, region_count);
	if (error != 0 || region_count == 0)
		return (error);

	table_size = region_count * DEVMEM_ENTRY_SIZE;
	cursor = DEVMEM_HEADER_SIZE + table_size;
	ordered = malloc(region_count * sizeof(*ordered));
	entries = calloc(region_count, sizeof(*entries));
	if (ordered == NULL || entries == NULL) {
		error = ENOMEM;
		goto done;
	}
	memcpy(ordered, regions, region_count * sizeof(*ordered));
	qsort(ordered, region_count, sizeof(*ordered), devmem_region_compare);
	for (size_t i = 0; i < region_count; i++) {
		if (ordered[i].length > UINT64_MAX - cursor) {
			error = EOVERFLOW;
			goto done;
		}
		strlcpy(entries[i].name, ordered[i].name,
		    sizeof(entries[i].name));
		entries[i].length = ordered[i].length;
		entries[i].offset = cursor;
		entries[i].digest = devmem_digest_memory(ordered[i].host_base,
		    ordered[i].length);
		cursor += ordered[i].length;
	}
	total = cursor;
	if (total > SIZE_MAX || total > (uint64_t)INT64_MAX ||
	    (uint64_t)normal_memory_size >
	    (uint64_t)INT64_MAX - total) {
		error = EOVERFLOW;
		goto done;
	}

	memset(header, 0, sizeof(header));
	le64enc(header + 0, DEVMEM_MAGIC);
	le16enc(header + 8, DEVMEM_VERSION);
	le16enc(header + 10, DEVMEM_HEADER_SIZE);
	le16enc(header + 12, DEVMEM_ENTRY_SIZE);
	le32enc(header + 16, (uint32_t)region_count);
	le64enc(header + 24, total);
	error = devmem_pwrite_all(fd, header, sizeof(header),
	    normal_memory_size);
	if (error != 0)
		goto done;
	for (size_t i = 0; i < region_count; i++) {
		memset(raw, 0, sizeof(raw));
		memcpy(raw, entries[i].name, sizeof(entries[i].name));
		le64enc(raw + 16, entries[i].length);
		le64enc(raw + 24, entries[i].offset);
		le64enc(raw + 32, entries[i].digest);
		error = devmem_pwrite_all(fd, raw, sizeof(raw),
		    normal_memory_size + DEVMEM_HEADER_SIZE +
		    (off_t)(i * DEVMEM_ENTRY_SIZE));
		if (error != 0)
			goto done;
		error = devmem_pwrite_all(fd, ordered[i].host_base,
		    ordered[i].length, normal_memory_size + entries[i].offset);
		if (error != 0)
			goto done;
	}
	*extension_size = (size_t)total;
	error = 0;
done:
	free(entries);
	free(ordered);
	return (error);
}

static const struct bhyve_devmem_region *
devmem_find_region(const struct bhyve_devmem_region *regions, size_t count,
    const char *name)
{

	for (size_t i = 0; i < count; i++) {
		if (strcmp(regions[i].name, name) == 0)
			return (&regions[i]);
	}
	return (NULL);
}

static int
devmem_digest_file(int fd, off_t offset, uint64_t length, uint64_t *result)
{
	uint8_t *buffer;
	uint64_t digest;
	size_t chunk;
	int error;

	buffer = malloc(DEVMEM_IO_CHUNK);
	if (buffer == NULL)
		return (ENOMEM);
	digest = UINT64_C(14695981039346656037);
	error = 0;
	while (length != 0) {
		chunk = length > DEVMEM_IO_CHUNK ? DEVMEM_IO_CHUNK :
		    (size_t)length;
		error = devmem_pread_all(fd, buffer, chunk, offset);
		if (error != 0)
			break;
		digest = devmem_digest_update(digest, buffer, chunk);
		offset += chunk;
		length -= chunk;
	}
	free(buffer);
	*result = digest;
	return (error);
}

static int
devmem_snapshot_load(int fd, off_t normal_memory_size,
    off_t file_size, const struct bhyve_devmem_region *regions,
    size_t region_count, bool restore)
{
	const struct bhyve_devmem_region **targets;
	struct devmem_entry *entries;
	uint8_t **payloads;
	uint8_t header[DEVMEM_HEADER_SIZE], raw[DEVMEM_ENTRY_SIZE];
	uint64_t extension_length, digest, previous_end;
	uint32_t count;
	int error;

	if (fd < 0 || normal_memory_size < 0 ||
	    file_size < normal_memory_size)
		return (EINVAL);
	error = devmem_validate_regions(regions, region_count);
	if (error != 0)
		return (error);
	if (file_size == normal_memory_size)
		return (region_count == 0 ? 0 : ENOENT);
	if (file_size - normal_memory_size < DEVMEM_HEADER_SIZE)
		return (EPROTO);
	error = devmem_pread_all(fd, header, sizeof(header),
	    normal_memory_size);
	if (error != 0)
		return (error);
	count = le32dec(header + 16);
	extension_length = le64dec(header + 24);
	if (le64dec(header + 0) != DEVMEM_MAGIC ||
	    le16dec(header + 8) != DEVMEM_VERSION ||
	    le16dec(header + 10) != DEVMEM_HEADER_SIZE ||
	    le16dec(header + 12) != DEVMEM_ENTRY_SIZE ||
	    le16dec(header + 14) != 0 || le32dec(header + 20) != 0 ||
	    count == 0 ||
	    count != region_count ||
	    extension_length != (uint64_t)(file_size - normal_memory_size) ||
	    count > (extension_length - DEVMEM_HEADER_SIZE) /
	    DEVMEM_ENTRY_SIZE)
		return (EPROTO);

	entries = calloc(count, sizeof(*entries));
	targets = calloc(count, sizeof(*targets));
	payloads = restore ? calloc(count, sizeof(*payloads)) : NULL;
	if ((count != 0 && entries == NULL) ||
	    (count != 0 && targets == NULL) ||
	    (restore && count != 0 && payloads == NULL)) {
		error = ENOMEM;
		goto done;
	}
	previous_end = DEVMEM_HEADER_SIZE +
	    (uint64_t)count * DEVMEM_ENTRY_SIZE;
	for (uint32_t i = 0; i < count; i++) {
		error = devmem_pread_all(fd, raw, sizeof(raw),
		    normal_memory_size + DEVMEM_HEADER_SIZE +
		    (off_t)i * DEVMEM_ENTRY_SIZE);
		if (error != 0)
			goto done;
		memcpy(entries[i].name, raw, sizeof(entries[i].name));
		char *terminator = memchr(entries[i].name, '\0',
		    sizeof(entries[i].name));
		if (terminator == NULL || entries[i].name[0] == '\0') {
			error = EPROTO;
			goto done;
		}
		for (char *padding = terminator + 1;
		    padding < entries[i].name + sizeof(entries[i].name);
		    padding++) {
			if (*padding != '\0') {
				error = EPROTO;
				goto done;
			}
		}
		entries[i].length = le64dec(raw + 16);
		entries[i].offset = le64dec(raw + 24);
		entries[i].digest = le64dec(raw + 32);
		targets[i] = devmem_find_region(regions, region_count,
		    entries[i].name);
		if (targets[i] == NULL ||
		    targets[i]->length != entries[i].length ||
		    entries[i].length == 0 ||
		    entries[i].offset != previous_end ||
		    entries[i].offset > extension_length ||
		    entries[i].length > extension_length - entries[i].offset) {
			error = EPROTO;
			goto done;
		}
		if (i != 0 &&
		    strcmp(entries[i - 1].name, entries[i].name) >= 0) {
			error = EPROTO;
			goto done;
		}
		previous_end += entries[i].length;
	}
	if (previous_end != extension_length) {
		error = EPROTO;
		goto done;
	}

	if (!restore) {
		/* Validate every payload without changing destination memory. */
		for (uint32_t i = 0; i < count; i++) {
			error = devmem_digest_file(fd,
			    normal_memory_size + entries[i].offset,
			    entries[i].length, &digest);
			if (error != 0)
				goto done;
			if (digest != entries[i].digest) {
				error = EPROTO;
				goto done;
			}
		}
	} else {
		for (uint32_t i = 0; i < count; i++) {
			payloads[i] = malloc(targets[i]->length);
			if (payloads[i] == NULL) {
				error = ENOMEM;
				goto done;
			}
			error = devmem_pread_all(fd, payloads[i],
			    targets[i]->length,
			    normal_memory_size + entries[i].offset);
			if (error != 0)
				goto done;
			digest = devmem_digest_memory(payloads[i],
			    targets[i]->length);
			if (digest != entries[i].digest) {
				error = EPROTO;
				goto done;
			}
		}
		for (uint32_t i = 0; i < count; i++)
			memcpy(targets[i]->host_base, payloads[i],
			    targets[i]->length);
	}
	error = 0;
done:
	if (payloads != NULL)
		for (uint32_t i = 0; i < count; i++)
			free(payloads[i]);
	free(payloads);
	free(targets);
	free(entries);
	return (error);
}

int
bhyve_devmem_snapshot_validate(int fd, off_t normal_memory_size,
    off_t file_size, const struct bhyve_devmem_region *regions,
    size_t region_count)
{

	return (devmem_snapshot_load(fd, normal_memory_size, file_size, regions,
	    region_count, false));
}

int
bhyve_devmem_snapshot_restore(int fd, off_t normal_memory_size,
    off_t file_size, const struct bhyve_devmem_region *regions,
    size_t region_count)
{

	return (devmem_snapshot_load(fd, normal_memory_size, file_size, regions,
	    region_count, true));
}
