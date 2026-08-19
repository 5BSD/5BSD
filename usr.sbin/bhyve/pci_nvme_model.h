/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _PCI_NVME_MODEL_H_
#define _PCI_NVME_MODEL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * NVMe submission-tail and completion-head doorbells contain an absolute
 * queue index, not a count of entries.  Queue fullness is a host-software
 * invariant and cannot be inferred by comparing that index with the number
 * of currently free entries, especially after the ring wraps.
 */
static inline bool
pci_nvme_doorbell_value_valid(uint32_t queue_size, uint64_t value)
{

	return (queue_size != 0 && value < queue_size);
}

static inline bool
pci_nvme_mmio_range_valid(uint64_t offset, int size, uint64_t limit)
{

	return ((size == 1 || size == 2 || size == 4 || size == 8) &&
	    offset <= limit && (uint64_t)size <= limit - offset);
}

static inline bool
pci_nvme_doorbell_access_valid(uint64_t bell_offset, int size,
    uint32_t queue_count)
{
	uint64_t bytes;

	if (size != 4 || (bell_offset & UINT64_C(3)) != 0)
		return (false);
	bytes = ((uint64_t)queue_count + 1) * 2 * sizeof(uint32_t);
	return (bell_offset <= bytes && sizeof(uint32_t) <=
	    bytes - bell_offset);
}

static inline bool
pci_nvme_prp1_valid(uint64_t prp1)
{

	return ((prp1 & UINT64_C(3)) == 0);
}

static inline bool
pci_nvme_queue_base_valid(uint64_t address, uint32_t page_size)
{

	if (page_size == 0 || (page_size & (page_size - 1U)) != 0)
		return (false);
	return ((address & (page_size - 1U)) == 0);
}

static inline bool
pci_nvme_log_offset_valid(uint64_t offset)
{

	/* NVMe log-page offsets are expressed on a dword boundary. */
	return ((offset & (sizeof(uint32_t) - 1U)) == 0);
}

static inline bool
pci_nvme_prp2_valid(uint64_t prp2, uint64_t remaining, uint32_t page_size)
{

	if (page_size == 0 || (page_size & (page_size - 1U)) != 0)
		return (false);
	if (remaining <= page_size)
		return ((prp2 & (page_size - 1U)) == 0);
	return ((prp2 & (sizeof(uint64_t) - 1U)) == 0);
}

static inline size_t
pci_nvme_prp_list_bytes(uint64_t address, uint32_t page_size)
{

	if (page_size == 0 || (page_size & (page_size - 1U)) != 0 ||
	    (address & (sizeof(uint64_t) - 1U)) != 0)
		return (0);
	return (page_size - (address & (page_size - 1U)));
}

static inline bool
pci_nvme_command_copies_to_guest(bool is_write)
{

	return (!is_write);
}

static inline size_t
pci_nvme_dsm_range_bytes(uint8_t zero_based_range_count)
{

	return ((size_t)zero_based_range_count + 1U) * 16U;
}

/* Convert an NVMe DSM LBA count without performing the shift in 32 bits. */
static inline bool
pci_nvme_dsm_length_bytes(uint32_t lba_count, unsigned int sector_shift,
    size_t *result)
{
	uint64_t bytes;

	if (result == NULL || sector_shift >= 64 ||
	    (sector_shift != 0 &&
	    (uint64_t)lba_count > (UINT64_MAX >> sector_shift)))
		return (false);
	bytes = (uint64_t)lba_count << sector_shift;
	if (bytes > SIZE_MAX)
		return (false);
	*result = (size_t)bytes;
	return (true);
}

/*
 * Start an asynchronous DSM deletion from the compacted non-empty range
 * array.  The original first descriptor is not necessarily the first range
 * that requests deallocation.
 */
static inline bool
pci_nvme_dsm_cursor_initialize(size_t compacted_count,
    uint64_t first_offset, size_t first_length, uint64_t *offset,
    size_t *length)
{

	if (compacted_count == 0 || first_length == 0 || offset == NULL ||
	    length == NULL)
		return (false);
	*offset = first_offset;
	*length = first_length;
	return (true);
}

static inline uint16_t
pci_nvme_status_with_phase(uint16_t status, bool phase)
{

	return ((status & ~UINT16_C(1)) | (phase ? UINT16_C(1) : 0));
}

static inline uint32_t
pci_nvme_ring_advance(uint32_t index, uint32_t size, bool *wrapped)
{

	if (wrapped != NULL)
		*wrapped = size != 0 && index + 1U == size;
	return (size != 0 && index + 1U == size ? 0 : index + 1U);
}

static inline bool
pci_nvme_completion_queue_full(uint32_t head, uint32_t tail, uint32_t size)
{

	return (size < 2 || head >= size || tail >= size ||
	    (tail + 1U) % size == head);
}

static inline bool
pci_nvme_reset_must_defer(uint32_t pending_ios, uint32_t active_handlers)
{

	return (pending_ios != 0 || active_handlers != 0);
}

/*
 * Checkpoint-record admission checks.  These carry the accept/reject
 * decisions of the pci_nvme snapshot codec so they can be exercised by the
 * rootless model tests; the codec itself must not restate them inline.
 */

/*
 * The controller publishes the IO queue arrays once at instance creation
 * with max_queues+1 slots; Set Features (Number of Queues) can only narrow
 * the advertised counts.  A record claiming more queues than the destination
 * arrays hold must be rejected before any queue slot is decoded.
 */
static inline bool
pci_nvme_snapshot_queue_counts_valid(uint32_t num_squeues,
    uint32_t num_cqueues, uint32_t max_queues)
{

	return (max_queues != 0 &&
	    num_squeues >= 1 && num_squeues <= max_queues &&
	    num_cqueues >= 1 && num_cqueues <= max_queues);
}

/*
 * A created queue needs at least two entries and ring indexes inside the
 * ring.  A never-created queue is all zeroes, while a deleted queue may
 * retain its stale geometry with a NULL base; both decode with
 * present == false.
 */
static inline bool
pci_nvme_snapshot_queue_shape_valid(bool present, uint32_t size,
    uint16_t head, uint16_t tail, uint32_t max_qentries)
{

	if (size > max_qentries)
		return (false);
	if (present && size < 2)
		return (false);
	if (size == 0)
		return (head == 0 && tail == 0);
	return (head < size && tail < size);
}

/*
 * Deferred completions only exist for a created completion queue and are
 * bounded by the fail-closed overflow limit the device enforces at run time.
 */
static inline bool
pci_nvme_snapshot_pending_cqes_valid(bool present, uint32_t pending_count,
    uint32_t limit)
{

	if (!present)
		return (pending_count == 0);
	return (pending_count <= limit);
}

/*
 * Checkpoint pause drains the backend and the vCPU fence empties the
 * doorbell handlers, so a truthful record carries no in-flight work.  A
 * record claiming otherwise was cut across an un-drained device and cannot
 * be restored: the requests it implies were never serialized.
 */
static inline bool
pci_nvme_snapshot_quiesced_valid(uint32_t pending_ios,
    uint32_t active_handlers, bool reset_pending)
{

	return (pending_ios == 0 && active_handlers == 0 && !reset_pending);
}

#endif /* _PCI_NVME_MODEL_H_ */
