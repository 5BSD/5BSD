/*
 * Byte-oriented helpers for document-derived VirtIO test vectors.
 *
 * This file deliberately does not include a FreeBSD or bhyve header.  Tests
 * use these helpers with offsets and sizes from virtio_1_4_spec.h so a
 * production C structure cannot define the stimulus that is fed back to the
 * implementation under test.
 */
#ifndef _VIRTIO_1_4_WIRE_H_
#define _VIRTIO_1_4_WIRE_H_

#include <stdint.h>

static inline uint16_t
virtio14_load_le16(const uint8_t *p)
{

	return ((uint16_t)p[0] | (uint16_t)p[1] << 8);
}

static inline uint32_t
virtio14_load_le32(const uint8_t *p)
{

	return ((uint32_t)p[0] | (uint32_t)p[1] << 8 |
	    (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24);
}

static inline uint64_t
virtio14_load_le64(const uint8_t *p)
{

	return ((uint64_t)virtio14_load_le32(p) |
	    (uint64_t)virtio14_load_le32(p + 4) << 32);
}

static inline void
virtio14_store_le16(uint8_t *p, uint16_t value)
{

	p[0] = value;
	p[1] = value >> 8;
}

static inline void
virtio14_store_le32(uint8_t *p, uint32_t value)
{

	p[0] = value;
	p[1] = value >> 8;
	p[2] = value >> 16;
	p[3] = value >> 24;
}

static inline void
virtio14_store_le64(uint8_t *p, uint64_t value)
{

	virtio14_store_le32(p, value);
	virtio14_store_le32(p + 4, value >> 32);
}

#endif /* _VIRTIO_1_4_WIRE_H_ */
