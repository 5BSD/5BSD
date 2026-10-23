/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _USB_MOUSE_MODEL_H_
#define _USB_MOUSE_MODEL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * The absolute-axis report descriptor advertises a signed 16-bit logical
 * range of [0, 32767].  Clamp host coordinates before scaling: window-system
 * pointer events can transiently be outside the framebuffer during resize or
 * pointer capture transitions.
 */
#define UMOUSE_AXIS_MAX INT16_MAX

static inline int16_t
umouse_scale_axis(int coordinate, int extent)
{
	int64_t scaled;

	if (extent <= 0 || coordinate <= 0)
		return (0);
	if (coordinate >= extent)
		return (UMOUSE_AXIS_MAX);
	scaled = (int64_t)UMOUSE_AXIS_MAX * coordinate / extent;
	return ((int16_t)scaled);
}

/* Encode only bytes backed by the data TRB, including odd byte counts. */
static inline size_t
umouse_string_descriptor_encode(const char *str, bool language,
    uint8_t type, uint8_t *output, size_t capacity)
{
	size_t full_length, written;

	full_length = language ? 4 : 2 + strlen(str) * 2;
	written = capacity < full_length ? capacity : full_length;
	for (size_t i = 0; i < written; i++) {
		if (i == 0)
			output[i] = (uint8_t)full_length;
		else if (i == 1)
			output[i] = type;
		else if (language)
			output[i] = (uint8_t)str[i - 2];
		else
			output[i] = (i & 1) == 0 ?
			    (uint8_t)str[(i - 2) / 2] : 0;
	}
	return (written);
}

#endif /* _USB_MOUSE_MODEL_H_ */
