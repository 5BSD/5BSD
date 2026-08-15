/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Fixed-width encoding helpers for portable bhyve save-state records.
 */

#ifndef _BHYVE_SNAPSHOT_PORTABLE_H_
#define	_BHYVE_SNAPSHOT_PORTABLE_H_

#include <sys/types.h>

static inline uint16_t
snapshot_load_le16(const uint8_t bytes[2])
{

	return ((uint16_t)bytes[0] | (uint16_t)bytes[1] << 8);
}

static inline uint32_t
snapshot_load_le32(const uint8_t bytes[4])
{

	return ((uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
	    (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24);
}

static inline uint64_t
snapshot_load_le64(const uint8_t bytes[8])
{

	return ((uint64_t)snapshot_load_le32(bytes) |
	    (uint64_t)snapshot_load_le32(bytes + 4) << 32);
}

static inline void
snapshot_store_le16(uint8_t bytes[2], uint16_t value)
{

	bytes[0] = value;
	bytes[1] = value >> 8;
}

static inline void
snapshot_store_le32(uint8_t bytes[4], uint32_t value)
{

	bytes[0] = value;
	bytes[1] = value >> 8;
	bytes[2] = value >> 16;
	bytes[3] = value >> 24;
}

static inline void
snapshot_store_le64(uint8_t bytes[8], uint64_t value)
{

	snapshot_store_le32(bytes, value);
	snapshot_store_le32(bytes + 4, value >> 32);
}

#endif /* _BHYVE_SNAPSHOT_PORTABLE_H_ */
