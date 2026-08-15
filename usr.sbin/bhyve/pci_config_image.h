/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#ifndef _PCI_CONFIG_IMAGE_H_
#define	_PCI_CONFIG_IMAGE_H_

#include <sys/endian.h>

#include <stdint.h>

/*
 * PCI configuration space is a little-endian byte image.  Keep byte order and
 * alignment handling here so transports and tests do not recreate it with
 * native integer pointer casts.
 */
static __inline void
pci_config_image_store8(uint8_t *image, int offset, uint8_t value)
{
	image[offset] = value;
}

static __inline void
pci_config_image_store16(uint8_t *image, int offset, uint16_t value)
{
	le16enc(image + offset, value);
}

static __inline void
pci_config_image_store32(uint8_t *image, int offset, uint32_t value)
{
	le32enc(image + offset, value);
}

static __inline uint8_t
pci_config_image_load8(const uint8_t *image, int offset)
{
	return (image[offset]);
}

static __inline uint16_t
pci_config_image_load16(const uint8_t *image, int offset)
{
	return (le16dec(image + offset));
}

static __inline uint32_t
pci_config_image_load32(const uint8_t *image, int offset)
{
	return (le32dec(image + offset));
}

#endif /* !_PCI_CONFIG_IMAGE_H_ */
