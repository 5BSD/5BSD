/*
 * Link support for device tests which compile a PCI device model directly.
 *
 * The common-core test compiles the production virtio.c implementation and
 * independently verifies it.  Device-composition tests intentionally do not
 * pull in that whole core, so provide only the symbol required by their
 * config-read callback.
 */
#ifndef VIRTIO_CONFIG_READ_TEST_SUPPORT_H
#define VIRTIO_CONFIG_READ_TEST_SUPPORT_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

int vi_config_read_le(const void *, size_t, int, int, uint32_t *);

int
vi_config_read_le(const void *config, size_t config_size, int offset, int size,
    uint32_t *value)
{
	const uint8_t *bytes;

	if (config == NULL || value == NULL || offset < 0 ||
	    (size != 1 && size != 2 && size != 4) ||
	    (size_t)offset > config_size ||
	    (size_t)size > config_size - (size_t)offset)
		return (EINVAL);

	bytes = (const uint8_t *)config + offset;
	switch (size) {
	case 1:
		*value = bytes[0];
		break;
	case 2:
		*value = (uint32_t)bytes[0] |
		    ((uint32_t)bytes[1] << 8);
		break;
	case 4:
		*value = (uint32_t)bytes[0] |
		    ((uint32_t)bytes[1] << 8) |
		    ((uint32_t)bytes[2] << 16) |
		    ((uint32_t)bytes[3] << 24);
		break;
	}
	return (0);
}

#endif
