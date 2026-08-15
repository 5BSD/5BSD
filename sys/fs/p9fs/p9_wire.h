/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Small, allocation-free helpers for the 9P wire format.
 *
 * Keep this header usable by both the kernel implementation and rootless
 * conformance tests.  The 9P transport carries little-endian integers
 * regardless of the host byte order.
 */

#ifndef _FS_P9FS_P9_WIRE_H_
#define _FS_P9FS_P9_WIRE_H_

#include <sys/types.h>

#define	P9_WIRE_HEADER_SIZE	7U

static __inline int
p9_wire_range_valid(size_t offset, size_t limit, size_t length)
{

	return (offset <= limit && length <= limit - offset);
}

static __inline int
p9_wire_response_length_valid(uint32_t received, uint32_t capacity,
    int32_t declared)
{

	return (received >= P9_WIRE_HEADER_SIZE && received <= capacity &&
	    declared >= (int32_t)P9_WIRE_HEADER_SIZE &&
	    (uint32_t)declared == received);
}

static __inline uint16_t
p9_wire_load_le16(const void *source)
{
	const uint8_t *p;

	p = source;
	return ((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static __inline uint32_t
p9_wire_load_le32(const void *source)
{
	const uint8_t *p;

	p = source;
	return ((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static __inline uint64_t
p9_wire_load_le64(const void *source)
{
	const uint8_t *p;

	p = source;
	return ((uint64_t)p9_wire_load_le32(p) |
	    ((uint64_t)p9_wire_load_le32(p + 4) << 32));
}

static __inline void
p9_wire_store_le16(void *destination, uint16_t value)
{
	uint8_t *p;

	p = destination;
	p[0] = (uint8_t)value;
	p[1] = (uint8_t)(value >> 8);
}

static __inline void
p9_wire_store_le32(void *destination, uint32_t value)
{
	uint8_t *p;

	p = destination;
	p[0] = (uint8_t)value;
	p[1] = (uint8_t)(value >> 8);
	p[2] = (uint8_t)(value >> 16);
	p[3] = (uint8_t)(value >> 24);
}

static __inline void
p9_wire_store_le64(void *destination, uint64_t value)
{
	uint8_t *p;

	p = destination;
	p9_wire_store_le32(p, (uint32_t)value);
	p9_wire_store_le32(p + 4, (uint32_t)(value >> 32));
}

#endif /* _FS_P9FS_P9_WIRE_H_ */
