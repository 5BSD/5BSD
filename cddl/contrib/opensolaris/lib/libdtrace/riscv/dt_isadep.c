/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Howard Su
 * Copyright 2015 George V. Neville-Neil
 * Copyright 2015 Ruslan Bukin <br@bsdpad.com>
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>

#include <dt_impl.h>
#include <dt_pid.h>

#if !defined(sun)
#include <libproc_compat.h>
#endif

static uint8_t *
dt_riscv_read_text(struct ps_prochandle *P, const GElf_Sym *symp)
{
	uint8_t *text;

	if ((text = malloc(symp->st_size)) == NULL) {
		dt_dprintf("malloc() failed\n");
		return (NULL);
	}
	if (Pread(P, text, symp->st_size, symp->st_value) != symp->st_size) {
		dt_dprintf("Pread() failed\n");
		free(text);
		return (NULL);
	}
	return (text);
}

/* Returns the size of the instruction at off, or 0 past the end. */
static size_t
dt_riscv_fetch(const uint8_t *text, size_t len, size_t off, uint32_t *instr)
{
	uint16_t half[2];

	if (off + 2 > len)
		return (0);
	memcpy(&half[0], text + off, 2);
	if ((half[0] & 3) != 3) {
		*instr = half[0];
		return (2);
	}
	if (off + 4 > len)
		return (0);
	memcpy(&half[1], text + off + 2, 2);
	*instr = half[0] | (uint32_t)half[1] << 16;
	return (4);
}

static int64_t
dt_riscv_cj_offset(uint16_t c)
{
	uint64_t imm;

	imm = ((c >> 1) & 0x800) | ((c >> 7) & 0x10) | ((c >> 1) & 0x300) |
	    ((c << 2) & 0x400) | ((c >> 1) & 0x40) | ((c << 1) & 0x80) |
	    ((c >> 2) & 0xe) | ((c << 3) & 0x20);
	return ((int64_t)(imm << 52) >> 52);
}

static int64_t
dt_riscv_j_offset(uint32_t instr)
{
	uint64_t imm;

	imm = ((instr >> 11) & 0x100000) | (instr & 0xff000) |
	    ((instr >> 9) & 0x800) | ((instr >> 20) & 0x7fe);
	return ((int64_t)(imm << 43) >> 43);
}

/*ARGSUSED*/
int
dt_pid_create_entry_probe(struct ps_prochandle *P, dtrace_hdl_t *dtp,
    fasttrap_probe_spec_t *ftp, const GElf_Sym *symp)
{

	ftp->ftps_type = DTFTP_ENTRY;
	ftp->ftps_pc = (uintptr_t)symp->st_value;
	ftp->ftps_size = (size_t)symp->st_size;
	ftp->ftps_noffs = 1;
	ftp->ftps_offs[0] = 0;

	if (ioctl(dtp->dt_ftfd, FASTTRAPIOC_MAKEPROBE, ftp) != 0) {
		dt_dprintf("fasttrap probe creation ioctl failed: %s\n",
		    strerror(errno));
		return (dt_set_errno(dtp, errno));
	}

	return (1);
}

int
dt_pid_create_return_probe(struct ps_prochandle *P, dtrace_hdl_t *dtp,
    fasttrap_probe_spec_t *ftp, const GElf_Sym *symp, uint64_t *stret)
{

	uint8_t *text;
	uintptr_t dest, pc;
	uint32_t instr;
	size_t i, size;
	uint16_t c;

	if (symp->st_size == 0)
		return (DT_PROC_ERR);

	if ((text = dt_riscv_read_text(P, symp)) == NULL)
		return (DT_PROC_ERR);

	ftp->ftps_type = DTFTP_RETURN;
	ftp->ftps_pc = (uintptr_t)symp->st_value;
	ftp->ftps_size = (size_t)symp->st_size;
	ftp->ftps_noffs = 0;

	for (i = 0; i < symp->st_size; i += size) {
		pc = symp->st_value + i;
		size = dt_riscv_fetch(text, symp->st_size, i, &instr);
		if (size == 0)
			break;
		c = (uint16_t)instr;

		if (size == 2) {
			if ((c & 0xe003) == 0xa001) {
				/* A c.j out of the function is a tail call. */
				dest = pc + dt_riscv_cj_offset(c);
				if (dest >= symp->st_value &&
				    dest < symp->st_value + symp->st_size)
					continue;
			} else if ((c & 0xf07f) != 0x8002 || (c & 0x0f80) == 0) {
				/* Not c.jr.  It may stay in the function. */
				continue;
			}
		} else if ((instr & 0xfff) == 0x06f) {
			/* A j out of the function is a tail call. */
			dest = pc + dt_riscv_j_offset(instr);
			if (dest >= symp->st_value &&
			    dest < symp->st_value + symp->st_size)
				continue;
		} else if ((instr & 0xfff) != 0x067) {
			/* Not jalr x0.  It may stay in the function. */
			continue;
		}

		dt_dprintf("return at offset %zx\n", i);
		ftp->ftps_offs[ftp->ftps_noffs++] = i;
	}

	free(text);
	if (ftp->ftps_noffs > 0) {
		if (ioctl(dtp->dt_ftfd, FASTTRAPIOC_MAKEPROBE, ftp) != 0) {
			dt_dprintf("fasttrap probe creation ioctl failed: %s\n",
			    strerror(errno));
			return (dt_set_errno(dtp, errno));
		}
	}

	return (ftp->ftps_noffs);
}

/*ARGSUSED*/
int
dt_pid_create_offset_probe(struct ps_prochandle *P, dtrace_hdl_t *dtp,
    fasttrap_probe_spec_t *ftp, const GElf_Sym *symp, ulong_t off)
{

	if (!ALIGNED_POINTER(off, 2))
		return (DT_PROC_ALIGN);

	ftp->ftps_type = DTFTP_OFFSETS;
	ftp->ftps_pc = (uintptr_t)symp->st_value;
	ftp->ftps_size = (size_t)symp->st_size;
	ftp->ftps_noffs = 1;
	ftp->ftps_offs[0] = off;

	if (ioctl(dtp->dt_ftfd, FASTTRAPIOC_MAKEPROBE, ftp) != 0) {
		dt_dprintf("fasttrap probe creation ioctl failed: %s\n",
		    strerror(errno));
		return (dt_set_errno(dtp, errno));
	}

	return (1);
}

/*ARGSUSED*/
int
dt_pid_create_glob_offset_probes(struct ps_prochandle *P, dtrace_hdl_t *dtp,
    fasttrap_probe_spec_t *ftp, const GElf_Sym *symp, const char *pattern)
{
	uint8_t *text;
	uint32_t instr;
	ulong_t i;
	size_t size;

	if ((text = dt_riscv_read_text(P, symp)) == NULL)
		return (DT_PROC_ERR);

	ftp->ftps_type = DTFTP_OFFSETS;
	ftp->ftps_pc = (uintptr_t)symp->st_value;
	ftp->ftps_size = (size_t)symp->st_size;
	ftp->ftps_noffs = 0;

	/*
	 * If we're matching against everything, just iterate through each
	 * instruction in the function, otherwise look for matching offset
	 * names by constructing the string and comparing it against the
	 * pattern.  Instructions are two or four bytes, so walk them.
	 */
	for (i = 0; i < symp->st_size; i += size) {
		char name[sizeof (i) * 2 + 1];

		size = dt_riscv_fetch(text, symp->st_size, i, &instr);
		if (size == 0)
			break;
		(void) sprintf(name, "%lx", i);
		if (strcmp("*", pattern) == 0 || gmatch(name, pattern))
			ftp->ftps_offs[ftp->ftps_noffs++] = i;
	}
	free(text);

	if (ioctl(dtp->dt_ftfd, FASTTRAPIOC_MAKEPROBE, ftp) != 0) {
		dt_dprintf("fasttrap probe creation ioctl failed: %s\n",
		    strerror(errno));
		return (dt_set_errno(dtp, errno));
	}

	return (ftp->ftps_noffs);
}
