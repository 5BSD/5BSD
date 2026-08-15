/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015 Tycho Nightingale <tycho.nightingale@pluribusnetworks.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "bhyvegc.h"

struct bhyvegc {
	struct bhyvegc_image	*gc_image;
	int raw;
};

struct bhyvegc *
bhyvegc_init(int width, int height, void *fbaddr)
{
	struct bhyvegc *gc;
	struct bhyvegc_image *gc_image;
	size_t pixels;

	/*
	 * The image dimensions are also exposed through the 16-bit RFB wire
	 * format, and several consumers retain the byte count in an unsigned
	 * int.  Enforce those interface limits here, before either an owned
	 * allocation or an externally-backed image can acquire an unusable
	 * geometry.
	 */
	if (width <= 0 || height <= 0 || width > UINT16_MAX ||
	    height > UINT16_MAX ||
	    (size_t)width > SIZE_MAX / (size_t)height) {
		errno = EINVAL;
		return (NULL);
	}
	pixels = (size_t)width * (size_t)height;
	if (pixels > SIZE_MAX / sizeof(uint32_t) ||
	    pixels > UINT_MAX / sizeof(uint32_t)) {
		errno = EOVERFLOW;
		return (NULL);
	}

	gc = calloc(1, sizeof (struct bhyvegc));
	if (gc == NULL)
		return (NULL);

	gc_image = calloc(1, sizeof(struct bhyvegc_image));
	if (gc_image == NULL) {
		free(gc);
		return (NULL);
	}
	gc_image->width = width;
	gc_image->height = height;
	if (fbaddr) {
		gc_image->data = fbaddr;
		gc->raw = 1;
	} else {
		gc_image->data = calloc(pixels, sizeof(uint32_t));
		if (gc_image->data == NULL) {
			free(gc_image);
			free(gc);
			return (NULL);
		}
		gc->raw = 0;
	}

	gc->gc_image = gc_image;

	return (gc);
}

void
bhyvegc_set_fbaddr(struct bhyvegc *gc, void *fbaddr)
{
	if (gc == NULL || gc->gc_image == NULL || fbaddr == NULL)
		return;
	if (!gc->raw && gc->gc_image->data != NULL)
		free(gc->gc_image->data);
	gc->raw = 1;
	gc->gc_image->data = fbaddr;
}

void
bhyvegc_resize(struct bhyvegc *gc, int width, int height)
{
	struct bhyvegc_image *gc_image;
	uint32_t *replacement;
	size_t pixels;

	if (gc == NULL || gc->gc_image == NULL || width <= 0 || height <= 0 ||
	    width > UINT16_MAX || height > UINT16_MAX ||
	    (size_t)width > SIZE_MAX / (size_t)height)
		return;
	pixels = (size_t)width * (size_t)height;
	if (pixels > SIZE_MAX / sizeof(uint32_t) ||
	    pixels > UINT_MAX / sizeof(uint32_t))
		return;

	gc_image = gc->gc_image;
	if (!gc->raw) {
		replacement = reallocarray(gc_image->data, pixels,
		    sizeof(uint32_t));
		if (replacement == NULL)
			return;
		gc_image->data = replacement;
		memset(gc_image->data, 0, pixels * sizeof(uint32_t));
	}
	gc_image->width = width;
	gc_image->height = height;
}

struct bhyvegc_image *
bhyvegc_get_image(struct bhyvegc *gc)
{
	if (gc == NULL)
		return (NULL);

	return (gc->gc_image);
}
