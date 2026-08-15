/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#ifndef _DEV_VMM_VMM_SNAPSHOT_ENVELOPE_H_
#define	_DEV_VMM_VMM_SNAPSHOT_ENVELOPE_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#define	VMM_SNAPSHOT_ENVELOPE_MAGIC	UINT32_C(0x32534d56) /* "VMS2" */
#define	VMM_SNAPSHOT_ENVELOPE_VERSION	1U
#define	VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE	32U
#define	VMM_SNAPSHOT_SECTION_HEADER_SIZE	24U

#define	VMM_SNAPSHOT_ENVELOPE_F_NONE	0U
#define	VMM_SNAPSHOT_ENVELOPE_F_VALID	VMM_SNAPSHOT_ENVELOPE_F_NONE

/* An unknown section with this bit set makes the record unrestorable. */
#define	VMM_SNAPSHOT_SECTION_F_CRITICAL	UINT16_C(0x0001)
#define	VMM_SNAPSHOT_SECTION_F_VALID	VMM_SNAPSHOT_SECTION_F_CRITICAL

struct vmm_snapshot_envelope_builder {
	uint8_t		*buffer;
	size_t		capacity;
	size_t		length;
	uint32_t	section_count;
	uint32_t	last_instance;
	uint16_t	last_type;
	bool		has_last;
	bool		finalized;
};

struct vmm_snapshot_section {
	uint16_t	type;
	uint16_t	flags;
	uint32_t	instance;
	const uint8_t	*payload;
	uint32_t	payload_length;
};

struct vmm_snapshot_envelope_reader {
	const uint8_t	*buffer;
	size_t		length;
	size_t		cursor;
	uint32_t	section_count;
	uint32_t	sections_read;
};

/*
 * The range helpers do not dereference their arguments.  A zero-length
 * range is valid even with a NULL base and never overlaps.  A non-empty
 * wrapping or NULL range is invalid; overlap returns false for one so a
 * caller must not mistake an unrepresentable range for a valid disjoint one.
 */
bool	vmm_snapshot_range_valid(const void *, size_t);
bool	vmm_snapshot_ranges_overlap(const void *, size_t, const void *, size_t);

int	vmm_snapshot_envelope_builder_init(
	    struct vmm_snapshot_envelope_builder *, void *, size_t);
int	vmm_snapshot_envelope_add(struct vmm_snapshot_envelope_builder *,
	    uint16_t, uint16_t, uint32_t, const void *, size_t);
int	vmm_snapshot_envelope_finalize(struct vmm_snapshot_envelope_builder *,
	    size_t *);

int	vmm_snapshot_envelope_reader_init(
	    struct vmm_snapshot_envelope_reader *, const void *, size_t);
int	vmm_snapshot_envelope_next(struct vmm_snapshot_envelope_reader *,
	    struct vmm_snapshot_section *);
int	vmm_snapshot_section_skip_unknown(
	    const struct vmm_snapshot_section *);

/*
 * A reader exposes payload views into the supplied byte array.  Its owner must
 * keep that array immutable for the reader's lifetime.  In particular, an
 * ioctl implementation must copy user bytes into kernel-owned staging before
 * initializing a reader; validation is not a substitute for that ownership
 * transfer.
 */

#endif /* _DEV_VMM_VMM_SNAPSHOT_ENVELOPE_H_ */
