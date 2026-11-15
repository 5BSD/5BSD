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
 * A tracepoint is an ebreak the size of the instruction it replaces, and
 * another ebreak ends the out-of-line sequence in a thread's scratch space.
 * The two are told apart by the program counter, since ebreak has no operand.
 */
#define	FASTTRAP_SUNWDTRACE_SIZE	64
#define	FASTTRAP_INSTR			0x00100073	/* ebreak */
#define	FASTTRAP_C_INSTR		0x9002		/* c.ebreak */

typedef uint32_t	fasttrap_instr_t;

typedef struct fasttrap_machtp {
	fasttrap_instr_t	ftmt_instr;	/* original instruction */
	uintptr_t		ftmt_dest;	/* branch target or auipc value */
	int64_t			ftmt_imm;	/* jalr offset */
	uint8_t			ftmt_type;	/* emulation type */
	uint8_t			ftmt_size;	/* instruction size in bytes */
	uint8_t			ftmt_rd;	/* destination register */
	uint8_t			ftmt_rs1;	/* first source register */
	uint8_t			ftmt_rs2;	/* second source register */
	uint8_t			ftmt_cond;	/* branch funct3 */
} fasttrap_machtp_t;

#define	ftt_instr	ftt_mtp.ftmt_instr
#define	ftt_dest	ftt_mtp.ftmt_dest
#define	ftt_imm		ftt_mtp.ftmt_imm
#define	ftt_type	ftt_mtp.ftmt_type
#define	ftt_size	ftt_mtp.ftmt_size
#define	ftt_rd		ftt_mtp.ftmt_rd
#define	ftt_rs1		ftt_mtp.ftmt_rs1
#define	ftt_rs2		ftt_mtp.ftmt_rs2
#define	ftt_cond	ftt_mtp.ftmt_cond

#define	FASTTRAP_T_COMMON	0x00	/* execute out of line */
#define	FASTTRAP_T_NOP		0x01
#define	FASTTRAP_T_JAL		0x02
#define	FASTTRAP_T_JALR		0x03
#define	FASTTRAP_T_BRANCH	0x04
#define	FASTTRAP_T_AUIPC	0x05

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
