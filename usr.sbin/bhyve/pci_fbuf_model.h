/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#ifndef _PCI_FBUF_MODEL_H_
#define	_PCI_FBUF_MODEL_H_

#include <stdbool.h>
#include <stdint.h>

#define	PCI_FBUF_REG_SIZE	128U
#define	PCI_FBUF_REG_FBSIZE	0U
#define	PCI_FBUF_REG_WIDTH	4U
#define	PCI_FBUF_REG_HEIGHT	6U
#define	PCI_FBUF_REG_DEPTH	8U
#define	PCI_FBUF_REG_REFRESH	10U

static inline bool
pci_fbuf_register_access_valid(uint64_t offset, int size)
{

	if (size != 1 && size != 2 && size != 4 && size != 8)
		return (false);
	return (offset <= PCI_FBUF_REG_SIZE &&
	    (uint64_t)size <= PCI_FBUF_REG_SIZE - offset);
}

/* BAR0 is an explicitly little-endian byte array, including unaligned I/O. */
static inline bool
pci_fbuf_register_read(const uint8_t registers[PCI_FBUF_REG_SIZE],
    uint64_t offset, int size, uint64_t *value)
{
	uint64_t result;

	if (registers == NULL || value == NULL ||
	    !pci_fbuf_register_access_valid(offset, size))
		return (false);
	result = 0;
	for (int i = 0; i < size; i++)
		result |= (uint64_t)registers[offset + (uint64_t)i] << (i * 8);
	*value = result;
	return (true);
}

static inline bool
pci_fbuf_register_write(uint8_t registers[PCI_FBUF_REG_SIZE],
    uint64_t offset, int size, uint64_t value)
{

	if (registers == NULL ||
	    !pci_fbuf_register_access_valid(offset, size))
		return (false);
	for (int i = 0; i < size; i++)
		registers[offset + (uint64_t)i] = value >> (i * 8);
	return (true);
}

#endif /* _PCI_FBUF_MODEL_H_ */
