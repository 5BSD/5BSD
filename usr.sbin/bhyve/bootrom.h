/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015 Neel Natu <neel@freebsd.org>
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

#ifndef	_BOOTROM_H_
#define	_BOOTROM_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "config.h"

struct vmctx;

void init_bootrom(struct vmctx *ctx);
enum {
	/*
	 * The allocation's bytes are generated per VM instance (for example
	 * the random VM generation ID) instead of being reconstructed from
	 * configuration, so they are excluded from the ROM identity that live
	 * migration compares between separately started endpoints.
	 */
	BOOTROM_ALLOC_INSTANCE = 0x40,
	BOOTROM_ALLOC_TOP = 0x80,
	_FORCE_INT = INT_MIN,
};
struct bootrom_range {
	size_t	offset;		/* Offset within the VM_BOOTROM segment. */
	size_t	length;
};
#define	BOOTROM_MAX_INSTANCE_RANGES	4
int bootrom_alloc(struct vmctx *ctx, size_t len, int prot, int flags,
    char **region_out, uint64_t *gpa_out);
size_t bootrom_instance_ranges(const struct bootrom_range **rangesp);
bool bootrom_boot(void);
int bootrom_loadrom(struct vmctx *ctx);

#endif
