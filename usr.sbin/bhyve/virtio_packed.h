/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_VIRTIO_PACKED_H_
#define	_BHYVE_VIRTIO_PACKED_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	VIRTIO_PACKED_DESC_F_AVAIL	(1U << 7)
#define	VIRTIO_PACKED_DESC_F_USED	(1U << 15)
#define	VIRTIO_PACKED_EVENT_F_ENABLE	0U
#define	VIRTIO_PACKED_EVENT_F_DISABLE	1U
#define	VIRTIO_PACKED_EVENT_F_DESC	2U
#define	VIRTIO_PACKED_EVENT_OFFSET_MASK	0x7fffU
#define	VIRTIO_PACKED_EVENT_WRAP	0x8000U
#define	VIRTIO_PACKED_QUEUE_SIZE_MAX	32768U
#define	VIRTIO_PACKED_WRAP_AVAIL	0x01U
#define	VIRTIO_PACKED_WRAP_USED		0x02U
#define	VIRTIO_PACKED_WRAP_SAVED	0x04U
#define	VIRTIO_PACKED_WRAP_VALID	0x07U

/*
 * These structures describe little-endian wire storage.  Callers must use
 * explicit endian conversion when reading or publishing individual fields.
 */
struct virtio_packed_desc {
	uint64_t address;
	uint32_t length;
	uint16_t id;
	uint16_t flags;
};

struct virtio_packed_event {
	uint16_t off_wrap;
	uint16_t flags;
};

struct virtio_packed_position {
	uint16_t offset;
	bool wrap;
};

_Static_assert(sizeof(struct virtio_packed_desc) == 16,
    "VirtIO packed descriptor wire size");
_Static_assert(offsetof(struct virtio_packed_desc, length) == 8,
    "VirtIO packed descriptor length offset");
_Static_assert(offsetof(struct virtio_packed_desc, id) == 12,
    "VirtIO packed descriptor id offset");
_Static_assert(offsetof(struct virtio_packed_desc, flags) == 14,
    "VirtIO packed descriptor flags offset");
_Static_assert(sizeof(struct virtio_packed_event) == 4,
    "VirtIO packed event wire size");

bool	vi_packed_desc_available(uint16_t, bool);
bool	vi_packed_event_flags_valid(uint16_t);
int	vi_packed_advance(uint16_t *, bool *, uint16_t, uint16_t);
int	vi_packed_event_encode(uint16_t, bool, uint16_t, uint16_t *);
int	vi_packed_need_event(struct virtio_packed_position,
	    struct virtio_packed_position, struct virtio_packed_position,
	    uint16_t, bool *);
uint8_t	vi_packed_wraps_encode(bool, bool, bool);
int	vi_packed_wraps_decode(uint8_t, bool *, bool *, bool *);
int	vi_packed_cursors_validate(uint16_t, uint16_t, uint16_t, uint16_t);

#endif
