/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _TPM_INTF_CRB_MODEL_H_
#define _TPM_INTF_CRB_MODEL_H_

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

/* Decode a little-endian sub-word MMIO write into its 32-bit register. */
static inline int
tpm_crb_control_write_decode(uint64_t value, size_t byte_offset, int size,
    uint32_t *decoded)
{
	uint32_t mask;

	if (decoded == NULL || (size != 1 && size != 2 && size != 4) ||
	    byte_offset >= sizeof(*decoded) ||
	    (size_t)size > sizeof(*decoded) - byte_offset ||
	    (byte_offset & ((size_t)size - 1)) != 0)
		return (EINVAL);
	mask = size == 4 ? UINT32_MAX :
	    (UINT32_C(1) << ((unsigned int)size * 8)) - 1;
	*decoded = ((uint32_t)value & mask) << (byte_offset * 8);
	return (0);
}

#endif /* _TPM_INTF_CRB_MODEL_H_ */
