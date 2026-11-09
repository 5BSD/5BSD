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
 */

#ifndef	_FASTTRAP_ISA_H
#define	_FASTTRAP_ISA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * brk #0xdd0 marks a tracepoint.  brk #0xdd1 ends the out-of-line sequence
 * in a thread's scratch space, as an absolute branch back to the program
 * would have to clobber a register.  The immediates are BRK_IMM_FASTTRAP_*
 * in machine/armreg.h.
 */
#define	FASTTRAP_SUNWDTRACE_SIZE	64
#define	FASTTRAP_INSTR			0xd421ba00
#define	FASTTRAP_RET_INSTR		0xd421ba20

typedef uint32_t	fasttrap_instr_t;

typedef struct fasttrap_machtp {
	fasttrap_instr_t	ftmt_orig;	/* original instruction */
	fasttrap_instr_t	ftmt_instr;	/* instruction to run out of line */
	uintptr_t		ftmt_dest;	/* branch target or adr value */
	uint8_t			ftmt_type;	/* emulation type */
	uint8_t			ftmt_reg;	/* tested or written register */
	uint8_t			ftmt_cond;	/* b.cond condition */
	uint8_t			ftmt_bit;	/* tbz/tbnz bit */
	uint8_t			ftmt_invert;	/* cbnz/tbnz */
	uint8_t			ftmt_size;	/* literal size in bytes */
} fasttrap_machtp_t;

#define	ftt_orig	ftt_mtp.ftmt_orig
#define	ftt_instr	ftt_mtp.ftmt_instr
#define	ftt_dest	ftt_mtp.ftmt_dest
#define	ftt_type	ftt_mtp.ftmt_type
#define	ftt_reg		ftt_mtp.ftmt_reg
#define	ftt_cond	ftt_mtp.ftmt_cond
#define	ftt_bit		ftt_mtp.ftmt_bit
#define	ftt_invert	ftt_mtp.ftmt_invert
#define	ftt_size	ftt_mtp.ftmt_size

#define	FASTTRAP_T_COMMON	0x00	/* execute out of line */
#define	FASTTRAP_T_NOP		0x01
#define	FASTTRAP_T_B		0x02
#define	FASTTRAP_T_BL		0x03
#define	FASTTRAP_T_BCOND	0x04
#define	FASTTRAP_T_CBZ		0x05
#define	FASTTRAP_T_TBZ		0x06
#define	FASTTRAP_T_ADR		0x07
#define	FASTTRAP_T_RET		0x08	/* br and ret */
#define	FASTTRAP_T_BLR		0x09
#define	FASTTRAP_T_LDR_LIT	0x0a	/* out of line, literal copied */
#define	FASTTRAP_T_RET_AUTH	0x0b	/* out of line autixsp, then ret */
#define	FASTTRAP_T_BR_AUTH	0x0c	/* out of line autix*, then br */
#define	FASTTRAP_T_BLR_AUTH	0x0d	/* out of line autix*, then blr */

struct thread;
struct trapframe;
extern void fasttrap_sendsig(struct thread *, struct trapframe *);

#define	FASTTRAP_AFRAMES		3
#define	FASTTRAP_RETURN_AFRAMES		4
#define	FASTTRAP_ENTRY_AFRAMES		3
#define	FASTTRAP_OFFSET_AFRAMES		3

#ifdef	__cplusplus
}
#endif

#endif	/* _FASTTRAP_ISA_H */
