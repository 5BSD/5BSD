/*-
 * Copyright (c) 2019 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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

#ifndef _SYS_MBUFID_H_
#define _SYS_MBUFID_H_

#ifdef _KERNEL
#include <sys/param.h>
#include <sys/systm.h>
#else
#include <stddef.h>
#endif /* _KERNEL */

#include <sys/_mbufid.h>

#define MBUFID_MAGIC_NUMBER 0xFEEDFACEul

/* The private packet-provenance wire format reserves the all-zero ID for
 * packets sent before a guest receives its node identity. */
static __inline int
mbufid_isempty(const mbufid_t *id)
{
	if (id == NULL)
		return (1);
	if (id->mid_hostid != 0 || id->mid_msgid != 0 || id->mid_magic != 0)
		return (0);
	for (size_t i = 0; i < sizeof(id->__mid_pad); i++)
		if (id->__mid_pad[i] != 0)
			return (0);
	return (1);
}

static __inline int
mbufid_iscanonical(const mbufid_t *id)
{
	if (id == NULL)
		return (0);
	if (id->mid_hostid == 0 || id->mid_msgid == 0 ||
	    id->mid_magic != MBUFID_MAGIC_NUMBER)
		return (0);
	for (size_t i = 0; i < sizeof(id->__mid_pad); i++)
		if (id->__mid_pad[i] != 0)
			return (0);
	return (1);
}

/* A V2 record is either empty, a fresh local claim awaiting a host stamp,
 * or a stamped claim. Shape alone never authenticates the stamped form. */
static __inline int
mbufid_v2_isempty(const mbufid_v2_t *id)
{
	return (id != NULL && mbufid_isempty(&id->mv2_id) &&
	    id->mv2_epoch == 0 && id->mv2_stamp == 0);
}

static __inline int
mbufid_v2_isfresh(const mbufid_v2_t *id)
{
	return (id != NULL && mbufid_iscanonical(&id->mv2_id) &&
	    id->mv2_epoch == 0 && id->mv2_stamp == 0);
}

static __inline int
mbufid_v2_isstamped(const mbufid_v2_t *id)
{
	return (id != NULL && mbufid_iscanonical(&id->mv2_id) &&
	    id->mv2_epoch != 0 && id->mv2_stamp != 0);
}


void mbufid_generate(mbufid_t *mbufidp);
int mbufid_origin_ready(void);
int mbufid_isvalid(mbufid_t *mbufidp);

#ifdef _KERNEL
void mbufid_assert_sanity(mbufid_t *);
uint64_t mbufid_origin_epoch(void);
void mbufid_origin_epoch_set(uint64_t);
int mbufid_v2_stamp(mbufid_v2_t *, uint64_t);
int mbufid_v2_verify(const mbufid_v2_t *);
int mbufid_v2_make_host(mbufid_v2_t *);
void mbufid_v2_vm_epoch_publish(uint16_t, uint64_t);
void mbufid_v2_vm_epoch_revoke(uint16_t, uint64_t);
int mbufid_v2_vm_epoch_current(uint16_t, uint64_t);
#endif /* _KERNEL */

#endif
