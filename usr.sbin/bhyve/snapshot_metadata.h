/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_SNAPSHOT_METADATA_H_
#define	_BHYVE_SNAPSHOT_METADATA_H_

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>

/*
 * Decode one canonical fixed-width hexadecimal metadata field.  Prefixes,
 * signs, whitespace, short values, and trailing bytes are deliberately not
 * part of the checkpoint grammar.
 */
static inline int
vm_snapshot_parse_fixed_hex(const char *string, size_t digits,
    uint64_t maximum, uint64_t *value)
{
	uint64_t parsed;
	unsigned int nibble;
	char c;

	if (string == NULL || value == NULL || digits == 0 || digits > 16)
		return (EINVAL);
	parsed = 0;
	for (size_t i = 0; i < digits; i++) {
		c = string[i];
		if (c >= '0' && c <= '9')
			nibble = (unsigned int)(c - '0');
		else if (c >= 'a' && c <= 'f')
			nibble = (unsigned int)(c - 'a') + 10;
		else if (c >= 'A' && c <= 'F')
			nibble = (unsigned int)(c - 'A') + 10;
		else
			return (EINVAL);
		if (nibble > maximum || parsed > (maximum - nibble) / 16)
			return (ERANGE);
		parsed = parsed * 16 + nibble;
	}
	if (string[digits] != '\0')
		return (EINVAL);
	*value = parsed;
	return (0);
}

#endif /* _BHYVE_SNAPSHOT_METADATA_H_ */
