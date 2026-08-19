/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Portable qemu-fwcfg checkpoint record definitions and validation helpers.
 */

#ifndef _BHYVE_QEMU_FWCFG_SNAPSHOT_H_
#define	_BHYVE_QEMU_FWCFG_SNAPSHOT_H_

#include <sys/types.h>

#include <stdbool.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "snapshot_portable.h"

#define	QEMU_FWCFG_SNAPSHOT_NAME	"qemu-fwcfg"
#define	QEMU_FWCFG_SNAPSHOT_MAGIC	UINT32_C(0x47434651) /* QFCG */
#define	QEMU_FWCFG_SNAPSHOT_VERSION	UINT32_C(1)
#define	QEMU_FWCFG_SNAPSHOT_DIGEST_SIZE	32U
#define	QEMU_FWCFG_SNAPSHOT_WIRE_SIZE	48U

struct qemu_fwcfg_snapshot_state {
	uint16_t selector;
	uint32_t data_offset;
	uint8_t catalog_digest[QEMU_FWCFG_SNAPSHOT_DIGEST_SIZE];
};

static inline bool
qemu_fwcfg_snapshot_cursor_valid(bool item_present, uint32_t item_size,
    uint32_t data_offset)
{

	/* Reads from a missing selector never advance the cursor. */
	return (item_present ? data_offset <= item_size : data_offset == 0);
}

static inline int
qemu_fwcfg_snapshot_decode(const void *record, size_t record_size,
    struct qemu_fwcfg_snapshot_state *state)
{
	const uint8_t *wire;

	if (record == NULL || state == NULL ||
	    record_size != QEMU_FWCFG_SNAPSHOT_WIRE_SIZE)
		return (EINVAL);
	wire = record;
	if (snapshot_load_le32(wire) != QEMU_FWCFG_SNAPSHOT_MAGIC ||
	    snapshot_load_le32(wire + 4) != QEMU_FWCFG_SNAPSHOT_VERSION ||
	    snapshot_load_le16(wire + 10) != 0)
		return (EINVAL);
	state->selector = snapshot_load_le16(wire + 8);
	state->data_offset = snapshot_load_le32(wire + 12);
	memcpy(state->catalog_digest, wire + 16,
	    sizeof(state->catalog_digest));
	return (0);
}

#endif /* _BHYVE_QEMU_FWCFG_SNAPSHOT_H_ */
