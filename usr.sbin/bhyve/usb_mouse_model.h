/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _USB_MOUSE_MODEL_H_
#define _USB_MOUSE_MODEL_H_

#include <stdint.h>

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

#endif /* _USB_MOUSE_MODEL_H_ */
