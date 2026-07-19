/*-
 * adv_data.c
 *
 * SPDX-License-Identifier: BSD-2-Clause

 * Copyright (c) 2020 Marc Veldman <marc@bumblingdork.com>
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <uuid.h>
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include "hccontrol.h"

static char* const adv_data2str(int len, uint8_t* data, char* buffer,
	int size);
static char* const adv_name2str(int len, uint8_t* advdata, char* buffer,
	int size);
static char* const adv_uuid2str(int datalen, uint8_t* data, char* buffer,
	int size);
static char* const adv_flags2str(int datalen, uint8_t* data, char* buffer,
	int size);
static char* const adv_appearance2str(int datalen, uint8_t* data,
	char* buffer, int size);
static char* const adv_cod2str(int datalen, uint8_t* data, char* buffer,
	int size);

void dump_adv_data(int len, uint8_t* advdata)
{
	int n=0;
	fprintf(stdout, "\tADV Data: ");
	for (n = 0; n < len; n++) {
		fprintf(stdout, "%02x ", advdata[n]);
	}
	fprintf(stdout, "\n");
}

void print_adv_data(int len, uint8_t* advdata)
{
	int n=0;
	while(n < len)
	{
		char buffer[2048];
		uint8_t datalen = advdata[n];
		/*
		 * An AD structure occupies 1 + datalen octets from offset n
		 * (the Length octet itself, then datalen octets of Type +
		 * Data).  The bound must therefore account for the Length
		 * octet: requiring n + 1 + datalen <= len.  Omitting the +1
		 * let a structure whose Length runs exactly to the end of the
		 * buffer pass, after which the Type/Data reads ran one or more
		 * octets past the end (heap-buffer-overflow).
		 */
		if (datalen == 0 || n + 1 + datalen > len) {
			fprintf(stderr, "Invalid advertising data length at offset %d\n", n);
			break;
		}
		uint8_t datatype = advdata[++n];
		/* Skip type */ 
		++n;
		datalen--;
		switch (datatype) {
			case 0x01:
				fprintf(stdout,
					"\tFlags: %s\n",
					adv_flags2str(
						datalen,
						&advdata[n],
						buffer,
						sizeof(buffer)));
				break;
			case 0x02:
				fprintf(stdout,
					"\tIncomplete list of service"
					" class UUIDs (16-bit): %s\n",
					adv_data2str(
						datalen,
						&advdata[n],
						buffer,
						sizeof(buffer)));
				break;
			case 0x03:
				fprintf(stdout,
					"\tComplete list of service "
					"class UUIDs (16-bit): %s\n",
					adv_data2str(
						datalen,
						&advdata[n],
						buffer,
						sizeof(buffer)));
				break;
			case 0x07:
				fprintf(stdout,
					"\tComplete list of service "
					"class UUIDs (128 bit): %s\n",
					adv_uuid2str(
						datalen,
						&advdata[n],
						buffer,
						sizeof(buffer)));
				break;
			case 0x08:
				fprintf(stdout,
					"\tShortened local name: %s\n",
					adv_name2str(
						datalen,
						&advdata[n],
						buffer,
						sizeof(buffer)));
				break;
			case 0x09:
				fprintf(stdout,
					"\tComplete local name: %s\n",
					adv_name2str(
						datalen,
						&advdata[n],
						buffer,
						sizeof(buffer)));
				break;
			case 0x0a:
				/*
				 * Tx Power is a single signed octet.  A
				 * malformed structure with Length 1 (type byte
				 * only, no data) leaves datalen == 0 and n past
				 * the payload, so guard the read to avoid a
				 * heap-buffer-overflow of advdata[n].
				 */
				if (datalen < 1) {
					fprintf(stdout,
						"\tTx Power level: (no data)\n");
					break;
				}
				fprintf(stdout,
					"\tTx Power level: %d dBm\n",
						(int8_t)advdata[n]);
				break;
			case 0x0d:
				fprintf(stdout,
					"\tClass of device: %s\n",
					adv_cod2str(
						datalen,
						&advdata[n],
						buffer,
						sizeof(buffer)));
				break;
			case 0x16:
				fprintf(stdout,
					"\tService data: %s\n",
					adv_data2str(
						datalen,
						&advdata[n],
						buffer,
						sizeof(buffer)));
				break;
			case 0x19:
				fprintf(stdout,
					"\tAppearance: %s\n",
					adv_appearance2str(
						datalen,
						&advdata[n],
						buffer,
						sizeof(buffer)));
				break;
			case 0xff:
				if (datalen < 2) {
					fprintf(stdout,
					    "\tManufacturer specific data "
					    "(too short): %s\n",
					    adv_data2str(datalen,
					    &advdata[n], buffer,
					    sizeof(buffer)));
					break;
				}
				fprintf(stdout,
					"\tManufacturer: %s\n",
			       		hci_manufacturer2str(
						advdata[n]|advdata[n+1]<<8));
				fprintf(stdout,
					"\tManufacturer specific data: %s\n",
					adv_data2str(
						datalen-2,
						&advdata[n+2],
						buffer,
						sizeof(buffer)));
				break;
			default:
				fprintf(stdout,
					"\tUNKNOWN datatype: %02x data %s\n",
					datatype,
					adv_data2str(
						datalen,
						&advdata[n],
						buffer,
						sizeof(buffer)));
		}
		n += datalen;
	}
}

static char* const adv_data2str(int datalen, uint8_t* data, char* buffer,
	int size)
{
        int i = 0;
	char tmpbuf[5];

	if (buffer == NULL)
		return NULL;

	memset(buffer, 0, size);

	while(i < datalen) {
		(void)snprintf(tmpbuf, sizeof(tmpbuf), "%02x ", data[i]);
		/* Check if buffer is full */
		if (strlcat(buffer, tmpbuf, size) > size)
			break;
		i++;
	}
	return buffer;
}

static char* const adv_name2str(int datalen, uint8_t* data, char* buffer,
	int size)
{
	int n;

	if (buffer == NULL)
		return NULL;
	if (size <= 0)
		return buffer;

	/*
	 * The name field is raw advertising bytes and is NOT NUL
	 * terminated.  strlcpy() would scan the source to its NUL to
	 * compute a return value, reading past the buffer -- an
	 * out-of-bounds read of attacker-controlled data.  Copy exactly
	 * min(datalen, size-1) bytes and terminate ourselves.
	 */
	n = datalen;
	if (n < 0)
		n = 0;
	if (n > size - 1)
		n = size - 1;
	memcpy(buffer, data, (size_t)n);
	buffer[n] = '\0';
	return buffer;
}

static char* const adv_uuid2str(int datalen, uint8_t* data, char* buffer,
	int size)
{
	int i;
	uuid_t uuid;
	uint32_t ustatus;
	char* tmpstr;

	if (buffer == NULL)
		return NULL;

	memset(buffer, 0, size);
	if (datalen < 16)
		return buffer;
	uuid.time_low = le32dec(data+12);
	uuid.time_mid = le16dec(data+10);
	uuid.time_hi_and_version = le16dec(data+8);
	uuid.clock_seq_hi_and_reserved = data[7];
	uuid.clock_seq_low = data[6];
	for(i = 0; i < _UUID_NODE_LEN; i++){
		uuid.node[i] = data[5 - i];
	}
	uuid_to_string(&uuid, &tmpstr, &ustatus);
	if(ustatus == uuid_s_ok) {
		strlcpy(buffer, tmpstr, size);
	}
	free(tmpstr);

	return buffer;
}

/*
 * Decode the Flags AD type (Core Specification Supplement Part A S1.3, also
 * Core Spec Vol 3 Part C S11).  The first octet carries the discoverability
 * and BR/EDR capability bits.  Print the raw byte plus the decoded bit names
 * so unknown/reserved bits remain visible.
 */
static char* const adv_flags2str(int datalen, uint8_t* data, char* buffer,
	int size)
{
	static const char* const names[] = {
		"LE Limited Discoverable Mode",		 /* bit 0 */
		"LE General Discoverable Mode",		 /* bit 1 */
		"BR/EDR Not Supported",			 /* bit 2 */
		"Simultaneous LE and BR/EDR (Controller)", /* bit 3 */
		"Simultaneous LE and BR/EDR (Host)",	 /* bit 4 */
	};
	uint8_t flags;
	int bit, first;
	char tmp[64];

	if (buffer == NULL)
		return NULL;
	if (size <= 0)
		return buffer;
	memset(buffer, 0, size);
	if (datalen < 1)
		return buffer;

	flags = data[0];
	(void)snprintf(tmp, sizeof(tmp), "0x%02x [", flags);
	strlcat(buffer, tmp, size);
	first = 1;
	for (bit = 0; bit < 8; bit++) {
		if ((flags & (1 << bit)) == 0)
			continue;
		if (!first)
			strlcat(buffer, ", ", size);
		first = 0;
		if (bit < (int)(sizeof(names) / sizeof(names[0])))
			strlcat(buffer, names[bit], size);
		else {
			(void)snprintf(tmp, sizeof(tmp), "bit %d", bit);
			strlcat(buffer, tmp, size);
		}
	}
	strlcat(buffer, "]", size);
	return buffer;
}

/*
 * Decode the Appearance AD type: a 16-bit value transmitted little-endian
 * whose upper 10 bits are the category and lower 6 bits the subcategory
 * (Core Spec Vol 3 Part C S12.2 / Assigned Numbers).
 */
static char* const adv_appearance2str(int datalen, uint8_t* data,
	char* buffer, int size)
{
	static const struct {
		uint16_t	cat;
		const char*	name;
	} cats[] = {
		{ 0x000, "Unknown" },
		{ 0x001, "Phone" },
		{ 0x002, "Computer" },
		{ 0x003, "Watch" },
		{ 0x004, "Clock" },
		{ 0x005, "Display" },
		{ 0x006, "Remote Control" },
		{ 0x007, "Eye-glasses" },
		{ 0x008, "Tag" },
		{ 0x009, "Keyring" },
		{ 0x00a, "Media Player" },
		{ 0x00b, "Barcode Scanner" },
		{ 0x00c, "Thermometer" },
		{ 0x00d, "Heart Rate Sensor" },
		{ 0x00e, "Blood Pressure" },
		{ 0x00f, "Human Interface Device" },
		{ 0x010, "Glucose Meter" },
		{ 0x011, "Running Walking Sensor" },
		{ 0x012, "Cycling" },
	};
	uint16_t value, category, sub;
	const char* name = NULL;
	char tmp[96];
	size_t i;

	if (buffer == NULL)
		return NULL;
	if (size <= 0)
		return buffer;
	memset(buffer, 0, size);
	if (datalen < 2)
		return buffer;

	value = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
	category = value >> 6;
	sub = value & 0x3f;
	for (i = 0; i < sizeof(cats) / sizeof(cats[0]); i++) {
		if (cats[i].cat == category) {
			name = cats[i].name;
			break;
		}
	}
	(void)snprintf(tmp, sizeof(tmp),
	    "0x%04x (category 0x%03x: %s, subcategory 0x%02x)",
	    value, category, name != NULL ? name : "Reserved", sub);
	strlcat(buffer, tmp, size);
	return buffer;
}

/*
 * Decode the Class of Device AD type: 3 octets transmitted little-endian
 * encoding the BR/EDR device class.  The Major Device Class is bits 8-12
 * (Assigned Numbers / Baseband).
 */
static char* const adv_cod2str(int datalen, uint8_t* data, char* buffer,
	int size)
{
	static const char* const major[] = {
		"Miscellaneous",		/* 0x00 */
		"Computer",			/* 0x01 */
		"Phone",			/* 0x02 */
		"LAN/Network Access Point",	/* 0x03 */
		"Audio/Video",			/* 0x04 */
		"Peripheral",			/* 0x05 */
		"Imaging",			/* 0x06 */
		"Wearable",			/* 0x07 */
		"Toy",				/* 0x08 */
		"Health",			/* 0x09 */
	};
	uint32_t cod;
	unsigned int mc;
	const char* name;
	char tmp[80];

	if (buffer == NULL)
		return NULL;
	if (size <= 0)
		return buffer;
	memset(buffer, 0, size);
	if (datalen < 3)
		return buffer;

	cod = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
	    ((uint32_t)data[2] << 16);
	mc = (cod >> 8) & 0x1f;
	if (mc < sizeof(major) / sizeof(major[0]))
		name = major[mc];
	else if (mc == 0x1f)
		name = "Uncategorized";
	else
		name = "Reserved";
	(void)snprintf(tmp, sizeof(tmp), "0x%06x (Major Device Class: %s)",
	    cod, name);
	strlcat(buffer, tmp, size);
	return buffer;
}
