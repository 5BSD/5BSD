/*	$NetBSD: data.c,v 1.8 2000/04/02 11:10:53 augustss Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1999 Lennart Augustsson <augustss@netbsd.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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

#include <sys/param.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <dev/usb/usb_ioctl.h>
#include "usbhid.h"
#include "usbvar.h"

int32_t
hid_get_data(const void *p, const hid_item_t *h)
{
	const uint8_t *buf;
	uint64_t data;
	uint32_t hsize, shift, bytes, i, mask, value;

	buf = p;
	if (h->report_ID > 0)
		buf++;
	hsize = h->report_size;
	if (hsize == 0)
		return (0);
	if (hsize > 32)
		hsize = 32;

	buf += h->pos / 8;
	shift = h->pos % 8;
	bytes = (shift + hsize + 7) / 8;
	/* An unaligned 32-bit field can occupy five bytes. */
	data = 0;
	for (i = 0; i < bytes; i++)
		data |= (uint64_t)buf[i] << (i * 8);
	mask = UINT32_MAX >> (32 - hsize);
	value = (data >> shift) & mask;
	if ((h->logical_minimum < 0 || h->logical_maximum < 0) &&
	    (value & (UINT32_C(1) << (hsize - 1))) != 0)
		value |= ~mask;
	return ((int32_t)value);
}

void
hid_set_data(void *p, const hid_item_t *h, int32_t data)
{
	uint8_t *buf;
	uint64_t mask, value;
	uint32_t hsize, shift, bytes, i;

	buf = p;
	if (h->report_ID > 0)
		*buf++ = h->report_ID & 0xff;
	hsize = h->report_size;
	if (hsize == 0)
		return;
	/* Match the getter's limit and the width of the value argument. */
	if (hsize > 32)
		hsize = 32;

	buf += h->pos / 8;
	shift = h->pos % 8;
	bytes = (shift + hsize + 7) / 8;
	mask = (UINT64_C(1) << hsize) - 1;
	value = ((uint32_t)data & mask) << shift;
	mask <<= shift;
	for (i = 0; i < bytes; i++)
		buf[i] = (buf[i] & ~(mask >> (i * 8))) |
		    ((value >> (i * 8)) & 0xff);
}

int
hid_get_report(int fd, enum hid_kind k, unsigned char *data, unsigned int size)
{
	struct usb_gen_descriptor ugd;

	memset(&ugd, 0, sizeof(ugd));
	ugd.ugd_data = data;
	ugd.ugd_maxlen = size;
	ugd.ugd_report_type = k + 1;
	return (ioctl(fd, USB_GET_REPORT, &ugd));
}

int
hid_set_report(int fd, enum hid_kind k, unsigned char *data, unsigned int size)
{
	struct usb_gen_descriptor ugd;

	memset(&ugd, 0, sizeof(ugd));
	ugd.ugd_data = data;
	ugd.ugd_maxlen = size;
	ugd.ugd_report_type = k + 1;
	return (ioctl(fd, USB_SET_REPORT, &ugd));
}
