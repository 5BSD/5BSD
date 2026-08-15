/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_balloon_host.h"
#include "virtio_state_range.h"

static bool
virtio_balloon_tracker_overlaps(
    const struct virtio_balloon_page_tracker *tracker, const void *buffer,
    size_t length)
{

	return (virtio_state_ranges_overlap(tracker, sizeof(*tracker), buffer,
	    length) ||
	    virtio_state_ranges_overlap(tracker->vbpt_bitmap,
	    tracker->vbpt_bitmap_size, buffer, length));
}

static bool
virtio_balloon_iov_result_invalid(const struct iovec *iov, size_t niov,
    const void *result, size_t result_size)
{
	size_t iov_size;

	if (niov > BHYVE_BALLOON_MAX_IOV ||
	    niov > SIZE_MAX / sizeof(*iov))
		return (true);
	iov_size = niov * sizeof(*iov);
	if (virtio_state_ranges_overlap(iov, iov_size, result, result_size))
		return (true);
	for (size_t i = 0; i < niov; i++) {
		if (virtio_state_ranges_overlap(iov[i].iov_base, iov[i].iov_len,
		    result, result_size))
			return (true);
	}
	return (false);
}

static int
virtio_balloon_tracker_index(const struct virtio_balloon_page_tracker *tracker,
    uint64_t gpa, size_t *index)
{
	uint64_t page;

	if (gpa % BHYVE_BALLOON_PAGE_SIZE != 0)
		return (EINVAL);
	if (gpa < tracker->vbpt_lowmem_size)
		page = gpa / BHYVE_BALLOON_PAGE_SIZE;
	else if (gpa >= tracker->vbpt_highmem_base &&
	    gpa - tracker->vbpt_highmem_base < tracker->vbpt_highmem_size)
		page = tracker->vbpt_lowmem_size / BHYVE_BALLOON_PAGE_SIZE +
		    (gpa - tracker->vbpt_highmem_base) /
		    BHYVE_BALLOON_PAGE_SIZE;
	else
		return (EFAULT);
	if (page > SIZE_MAX)
		return (EOVERFLOW);
	*index = (size_t)page;
	return (0);
}

static bool
virtio_balloon_tracker_page_complete(
    const struct virtio_balloon_page_tracker *tracker, uint64_t gpa)
{
	uint64_t first, offset;
	size_t index;

	first = rounddown2(gpa, tracker->vbpt_host_page_size);
	for (offset = 0; offset < tracker->vbpt_host_page_size;
	    offset += BHYVE_BALLOON_PAGE_SIZE) {
		if (virtio_balloon_tracker_index(tracker, first + offset,
		    &index) != 0 ||
		    (tracker->vbpt_bitmap[index / 8] &
		    (uint8_t)(1U << (index % 8))) == 0)
			return (false);
	}
	return (true);
}

int
virtio_balloon_tracker_required(uint64_t lowmem_size, uint64_t highmem_base,
    uint64_t highmem_size, size_t *required)
{
	uint64_t pages;

	if (required == NULL ||
	    lowmem_size % BHYVE_BALLOON_PAGE_SIZE != 0 ||
	    highmem_base % BHYVE_BALLOON_PAGE_SIZE != 0 ||
	    highmem_size % BHYVE_BALLOON_PAGE_SIZE != 0 ||
	    (highmem_size != 0 && (highmem_base < lowmem_size ||
	    highmem_base > UINT64_MAX - highmem_size)))
		return (EINVAL);
	pages = lowmem_size / BHYVE_BALLOON_PAGE_SIZE;
	if (pages > UINT64_MAX -
	    highmem_size / BHYVE_BALLOON_PAGE_SIZE)
		return (EOVERFLOW);
	pages += highmem_size / BHYVE_BALLOON_PAGE_SIZE;
	if (pages > SIZE_MAX - 7)
		return (EOVERFLOW);
	*required = ((size_t)pages + 7) / 8;
	return (0);
}

int
virtio_balloon_tracker_init(struct virtio_balloon_page_tracker *tracker,
    uint64_t lowmem_size, uint64_t highmem_base, uint64_t highmem_size,
    size_t host_page_size, uint8_t *bitmap, size_t bitmap_size)
{
	size_t required;
	int error;

	if (tracker == NULL || host_page_size < BHYVE_BALLOON_PAGE_SIZE ||
	    !powerof2(host_page_size) ||
	    host_page_size % BHYVE_BALLOON_PAGE_SIZE != 0 ||
	    lowmem_size % host_page_size != 0 ||
	    (highmem_size != 0 && (highmem_base % host_page_size != 0 ||
	    highmem_size % host_page_size != 0)))
		return (EINVAL);
	error = virtio_balloon_tracker_required(lowmem_size, highmem_base,
	    highmem_size, &required);
	if (error != 0)
		return (error);
	if ((required != 0 && bitmap == NULL) || bitmap_size < required)
		return (EINVAL);
	if (virtio_state_ranges_overlap(tracker, sizeof(*tracker), bitmap,
	    required))
		return (EINVAL);
	memset(tracker, 0, sizeof(*tracker));
	tracker->vbpt_lowmem_size = lowmem_size;
	tracker->vbpt_highmem_base = highmem_base;
	tracker->vbpt_highmem_size = highmem_size;
	tracker->vbpt_host_page_size = host_page_size;
	tracker->vbpt_bitmap = bitmap;
	tracker->vbpt_bitmap_size = required;
	if (required != 0)
		memset(bitmap, 0, required);
	return (0);
}

int
virtio_balloon_tracker_inflate_transition(
    struct virtio_balloon_page_tracker *tracker,
    uint64_t gpa, uint64_t *discard_gpa, size_t *discard_len, bool *ready,
    bool *changed)
{
	uint64_t first;
	size_t index;
	int error;

	if (tracker == NULL || discard_gpa == NULL || discard_len == NULL ||
	    ready == NULL || changed == NULL || tracker->vbpt_bitmap == NULL)
		return (EINVAL);
	if (virtio_balloon_tracker_overlaps(tracker, discard_gpa,
	    sizeof(*discard_gpa)) ||
	    virtio_balloon_tracker_overlaps(tracker, discard_len,
	    sizeof(*discard_len)) ||
	    virtio_balloon_tracker_overlaps(tracker, ready, sizeof(*ready)) ||
	    virtio_balloon_tracker_overlaps(tracker, changed,
	    sizeof(*changed)) ||
	    virtio_state_ranges_overlap(discard_gpa, sizeof(*discard_gpa),
	    discard_len, sizeof(*discard_len)) ||
	    virtio_state_ranges_overlap(discard_gpa, sizeof(*discard_gpa),
	    ready, sizeof(*ready)) ||
	    virtio_state_ranges_overlap(discard_gpa, sizeof(*discard_gpa),
	    changed, sizeof(*changed)) ||
	    virtio_state_ranges_overlap(discard_len, sizeof(*discard_len),
	    ready, sizeof(*ready)) ||
	    virtio_state_ranges_overlap(discard_len, sizeof(*discard_len),
	    changed, sizeof(*changed)) ||
	    virtio_state_ranges_overlap(ready, sizeof(*ready), changed,
	    sizeof(*changed)))
		return (EINVAL);
	error = virtio_balloon_tracker_index(tracker, gpa, &index);
	if (error != 0)
		return (error);
	*changed = (tracker->vbpt_bitmap[index / 8] &
	    (uint8_t)(1U << (index % 8))) == 0;
	tracker->vbpt_bitmap[index / 8] |= (uint8_t)(1U << (index % 8));

	/*
	 * A driver is not supposed to inflate a page which is already in the
	 * balloon, but treating a duplicate as an idempotent request is safer
	 * than replaying the host discard operation.  In particular, once all
	 * guest pages in a larger host page are owned, page_complete() remains
	 * true forever and used to report the same host extent for every
	 * duplicate PFN.
	 */
	if (!*changed) {
		*ready = false;
		*discard_gpa = 0;
		*discard_len = 0;
		return (0);
	}
	if (!virtio_balloon_tracker_page_complete(tracker, gpa)) {
		*ready = false;
		*discard_gpa = 0;
		*discard_len = 0;
		return (0);
	}
	first = rounddown2(gpa, tracker->vbpt_host_page_size);
	*ready = true;
	*discard_gpa = first;
	*discard_len = tracker->vbpt_host_page_size;
	return (0);
}

int
virtio_balloon_tracker_inflate(struct virtio_balloon_page_tracker *tracker,
    uint64_t gpa, uint64_t *discard_gpa, size_t *discard_len, bool *ready)
{
	bool changed;

	return (virtio_balloon_tracker_inflate_transition(tracker, gpa,
	    discard_gpa, discard_len, ready, &changed));
}

int
virtio_balloon_tracker_deflate_transition(
    struct virtio_balloon_page_tracker *tracker,
    uint64_t gpa, uint64_t *undiscard_gpa, size_t *undiscard_len,
    bool *changed)
{
	bool was_complete;
	size_t index;
	int error;

	if (tracker == NULL || tracker->vbpt_bitmap == NULL ||
	    undiscard_gpa == NULL || undiscard_len == NULL || changed == NULL)
		return (EINVAL);
	if (virtio_balloon_tracker_overlaps(tracker, undiscard_gpa,
	    sizeof(*undiscard_gpa)) ||
	    virtio_balloon_tracker_overlaps(tracker, undiscard_len,
	    sizeof(*undiscard_len)) ||
	    virtio_balloon_tracker_overlaps(tracker, changed,
	    sizeof(*changed)) ||
	    virtio_state_ranges_overlap(undiscard_gpa,
	    sizeof(*undiscard_gpa), undiscard_len, sizeof(*undiscard_len)) ||
	    virtio_state_ranges_overlap(undiscard_gpa,
	    sizeof(*undiscard_gpa), changed, sizeof(*changed)) ||
	    virtio_state_ranges_overlap(undiscard_len,
	    sizeof(*undiscard_len), changed, sizeof(*changed)))
		return (EINVAL);
	error = virtio_balloon_tracker_index(tracker, gpa, &index);
	if (error != 0)
		return (error);
	*changed = (tracker->vbpt_bitmap[index / 8] &
	    (uint8_t)(1U << (index % 8))) != 0;
	was_complete = virtio_balloon_tracker_page_complete(tracker, gpa);
	tracker->vbpt_bitmap[index / 8] &=
	    (uint8_t)~(uint8_t)(1U << (index % 8));
	if (was_complete) {
		*undiscard_gpa = rounddown2(gpa,
		    tracker->vbpt_host_page_size);
		*undiscard_len = tracker->vbpt_host_page_size;
	} else {
		*undiscard_gpa = 0;
		*undiscard_len = 0;
	}
	return (0);
}

int
virtio_balloon_tracker_deflate(struct virtio_balloon_page_tracker *tracker,
    uint64_t gpa, uint64_t *undiscard_gpa, size_t *undiscard_len)
{
	bool changed;

	return (virtio_balloon_tracker_deflate_transition(tracker, gpa,
	    undiscard_gpa, undiscard_len, &changed));
}

static int
virtio_balloon_tracker_release_region(
    const struct virtio_balloon_page_tracker *tracker, uint64_t base,
    uint64_t length, size_t first_page, virtio_balloon_range_cb release,
    void *arg)
{
	uint64_t gpa;
	size_t byte, end_page, group, page, pages_per_host;
	uint8_t bits;
	int error;

	pages_per_host = tracker->vbpt_host_page_size /
	    BHYVE_BALLOON_PAGE_SIZE;
	end_page = first_page +
	    (size_t)(length / BHYVE_BALLOON_PAGE_SIZE);
	page = first_page;
	while (page < end_page) {
		byte = page / 8;
		bits = tracker->vbpt_bitmap[byte] &
		    (uint8_t)(UINT8_MAX << (page % 8));
		while (bits == 0) {
			page = (byte + 1) * 8;
			if (page >= end_page)
				return (0);
			byte++;
			bits = tracker->vbpt_bitmap[byte];
		}
		page = byte * 8 + (size_t)(__builtin_ffs((int)bits) - 1);
		if (page >= end_page)
			break;
		group = first_page +
		    ((page - first_page) / pages_per_host) * pages_per_host;
		gpa = base + (uint64_t)(group - first_page) *
		    BHYVE_BALLOON_PAGE_SIZE;
		if (!virtio_balloon_tracker_page_complete(tracker, gpa)) {
			page = group + pages_per_host;
			continue;
		}
		error = release(arg, gpa, tracker->vbpt_host_page_size);
		if (error != 0)
			return (error);
		page = group + pages_per_host;
	}
	return (0);
}

int
virtio_balloon_tracker_release_all(
    struct virtio_balloon_page_tracker *tracker,
    virtio_balloon_range_cb release, void *arg)
{
	int error;

	if (tracker == NULL || release == NULL ||
	    (tracker->vbpt_bitmap_size != 0 &&
	    tracker->vbpt_bitmap == NULL) ||
	    tracker->vbpt_host_page_size < BHYVE_BALLOON_PAGE_SIZE)
		return (EINVAL);
	/*
	 * Host discard cancellation is idempotent, but bitmap publication is
	 * transactional.  If a later range fails, retain every ownership bit;
	 * a subsequent reset retries all complete host pages, including any
	 * already cancelled by this attempt.  Partially inflated host pages
	 * were never discarded and require no host operation.
	 */
	error = virtio_balloon_tracker_release_region(tracker, 0,
	    tracker->vbpt_lowmem_size, 0, release, arg);
	if (error == 0)
		error = virtio_balloon_tracker_release_region(tracker,
		    tracker->vbpt_highmem_base, tracker->vbpt_highmem_size,
		    (size_t)(tracker->vbpt_lowmem_size /
		    BHYVE_BALLOON_PAGE_SIZE), release, arg);
	if (error == 0 && tracker->vbpt_bitmap_size != 0)
		memset(tracker->vbpt_bitmap, 0, tracker->vbpt_bitmap_size);
	return (error);
}

int
virtio_balloon_accounting_init(struct virtio_balloon_accounting *accounting,
    uint64_t ram_bytes, uint32_t target_pages)
{
	uint64_t total_pages;

	if (accounting == NULL ||
	    ram_bytes % BHYVE_BALLOON_PAGE_SIZE != 0)
		return (EINVAL);
	total_pages = ram_bytes / BHYVE_BALLOON_PAGE_SIZE;
	if (total_pages > UINT32_MAX || target_pages > total_pages)
		return (ERANGE);
	memset(accounting, 0, sizeof(*accounting));
	accounting->vba_total_pages = (uint32_t)total_pages;
	accounting->vba_target_pages = target_pages;
	return (0);
}

int
virtio_balloon_accounting_set_target(
    struct virtio_balloon_accounting *accounting, uint32_t target_pages,
    bool *changed)
{

	if (accounting == NULL || changed == NULL)
		return (EINVAL);
	if (virtio_state_ranges_overlap(accounting, sizeof(*accounting),
	    changed, sizeof(*changed)))
		return (EINVAL);
	if (target_pages > accounting->vba_total_pages)
		return (ERANGE);
	*changed = accounting->vba_target_pages != target_pages;
	accounting->vba_target_pages = target_pages;
	return (0);
}

int
virtio_balloon_accounting_set_actual(
    struct virtio_balloon_accounting *accounting, uint32_t actual_pages)
{

	if (accounting == NULL)
		return (EINVAL);
	if (actual_pages > accounting->vba_total_pages)
		return (ERANGE);
	accounting->vba_actual_pages = actual_pages;
	return (0);
}

void
virtio_balloon_accounting_reset(struct virtio_balloon_accounting *accounting)
{

	if (accounting != NULL)
		accounting->vba_actual_pages = 0;
}

int
virtio_balloon_parse_stats(const struct iovec *iov, size_t niov,
    struct virtio_balloon_stats *result)
{
	struct virtio_balloon_stats current;
	uint8_t encoded[BHYVE_BALLOON_STAT_SIZE];
	size_t i, offset, total;

	if ((iov == NULL && niov != 0) || result == NULL)
		return (EINVAL);
	if (virtio_balloon_iov_result_invalid(iov, niov, result,
	    sizeof(*result)))
		return (EINVAL);
	total = 0;
	for (i = 0; i < niov; i++) {
		if (iov[i].iov_len != 0 && iov[i].iov_base == NULL)
			return (EINVAL);
		if (total > SIZE_MAX - iov[i].iov_len)
			return (EOVERFLOW);
		total += iov[i].iov_len;
	}
	if (total == 0 || total % BHYVE_BALLOON_STAT_SIZE != 0)
		return (EINVAL);
	if (total / BHYVE_BALLOON_STAT_SIZE >
	    BHYVE_BALLOON_STATS_MAX_ENTRIES)
		return (E2BIG);

	memset(&current, 0, sizeof(current));
	i = 0;
	offset = 0;
	while (current.vbs_entries < total / BHYVE_BALLOON_STAT_SIZE) {
		size_t copied;
		uint16_t tag;

		copied = 0;
		while (copied < sizeof(encoded)) {
			size_t available, count;

			while (i < niov && offset == iov[i].iov_len) {
				i++;
				offset = 0;
			}
			if (i == niov)
				return (EINVAL);
			available = iov[i].iov_len - offset;
			count = MIN(available, sizeof(encoded) - copied);
			memcpy(encoded + copied,
			    (const uint8_t *)iov[i].iov_base + offset, count);
			copied += count;
			offset += count;
		}
		tag = le16dec(encoded);
		if (tag < BHYVE_BALLOON_STAT_COUNT) {
			current.vbs_value[tag] = le64dec(encoded + 2);
			current.vbs_present |= (uint16_t)(1U << tag);
		} else {
			current.vbs_ignored++;
		}
		current.vbs_entries++;
	}
	*result = current;
	return (0);
}

int
virtio_balloon_process_pfns(const struct iovec *iov, size_t niov,
    virtio_balloon_pfn_cb callback, void *arg,
    struct virtio_balloon_pfn_result *result)
{
	struct virtio_balloon_pfn_result current;
	uint8_t encoded[sizeof(uint32_t)];
	uint64_t gpa;
	size_t i, offset, total;
	uint32_t pfn;
	int error;

	if ((iov == NULL && niov != 0) || callback == NULL || result == NULL)
		return (EINVAL);
	if (virtio_balloon_iov_result_invalid(iov, niov, result,
	    sizeof(*result)))
		return (EINVAL);
	total = 0;
	for (i = 0; i < niov; i++) {
		if (iov[i].iov_len != 0 && iov[i].iov_base == NULL)
			return (EINVAL);
		if (total > SIZE_MAX - iov[i].iov_len)
			return (EOVERFLOW);
		total += iov[i].iov_len;
	}
	if (total == 0 || total % sizeof(uint32_t) != 0)
		return (EINVAL);
	if (total > BHYVE_BALLOON_REQUEST_MAX)
		return (E2BIG);

	memset(&current, 0, sizeof(current));
	i = 0;
	offset = 0;
	while (current.vbpr_seen < total / sizeof(uint32_t)) {
		size_t copied;

		copied = 0;
		while (copied < sizeof(encoded)) {
			size_t available, count;

			while (i < niov && offset == iov[i].iov_len) {
				i++;
				offset = 0;
			}
			if (i == niov)
				return (EINVAL);
			available = iov[i].iov_len - offset;
			count = MIN(available, sizeof(encoded) - copied);
			memcpy(encoded + copied,
			    (const uint8_t *)iov[i].iov_base + offset, count);
			copied += count;
			offset += count;
		}
		pfn = le32dec(encoded);
		gpa = (uint64_t)pfn << BHYVE_BALLOON_PFN_SHIFT;
		error = callback(arg, gpa);
		current.vbpr_seen++;
		if (error == 0)
			current.vbpr_accepted++;
		else
			current.vbpr_rejected++;
	}
	*result = current;
	return (0);
}
