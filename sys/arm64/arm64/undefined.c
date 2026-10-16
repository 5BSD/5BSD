/*-
 * Copyright (c) 2017 Andrew Turner
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/signal.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>

#include <machine/atomic.h>
#include <machine/frame.h>
#define _MD_WANT_SWAPWORD
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/undefined.h>
#include <machine/vmparam.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>

MALLOC_DEFINE(M_UNDEF, "undefhandler", "Undefined instruction handler data");


struct undef_handler {
	LIST_ENTRY(undef_handler) uh_link;
	undef_handler_t		uh_handler;
};

/* System instruction handlers, e.g. msr, mrs, sys */
struct sys_handler {
	LIST_ENTRY(sys_handler) sys_link;
	undef_sys_handler_t	sys_handler;
};

/*
 * Create the undefined instruction handler lists.
 * This allows us to handle instructions that will trap.
 */
LIST_HEAD(, sys_handler) sys_handlers = LIST_HEAD_INITIALIZER(sys_handler);
LIST_HEAD(, undef_handler) undef_handlers =
    LIST_HEAD_INITIALIZER(undef_handlers);

void
undef_init(void)
{
}

void *
install_undef_handler(undef_handler_t func)
{
	struct undef_handler *uh;

	uh = malloc(sizeof(*uh), M_UNDEF, M_WAITOK);
	uh->uh_handler = func;
	LIST_INSERT_HEAD(&undef_handlers, uh, uh_link);

	return (uh);
}


void
remove_undef_handler(void *handle)
{
	struct undef_handler *uh;

	uh = handle;
	LIST_REMOVE(uh, uh_link);
	free(handle, M_UNDEF);
}

void
install_sys_handler(undef_sys_handler_t func)
{
	struct sys_handler *sysh;

	sysh = malloc(sizeof(*sysh), M_UNDEF, M_WAITOK);
	sysh->sys_handler = func;
	LIST_INSERT_HEAD(&sys_handlers, sysh, sys_link);
}

bool
undef_sys(uint64_t esr, struct trapframe *frame)
{
	struct sys_handler *sysh;

	LIST_FOREACH(sysh, &sys_handlers, sys_link) {
		if (sysh->sys_handler(esr, frame))
			return (true);
	}

	return (false);
}

static bool
undef_sys_insn(struct trapframe *frame, uint32_t insn)
{
	uint64_t esr;
	bool read;

#define	MRS_MASK			0xfff00000
#define	MRS_VALUE			0xd5300000
#define	MSR_REG_VALUE			0xd5100000
#define	MSR_IMM_VALUE			0xd5000000
#define	MRS_REGISTER(insn)		((insn) & 0x0000001f)
#define	 MRS_Op0_SHIFT			19
#define	 MRS_Op0_MASK			0x00180000
#define	 MRS_Op1_SHIFT			16
#define	 MRS_Op1_MASK			0x00070000
#define	 MRS_CRn_SHIFT			12
#define	 MRS_CRn_MASK			0x0000f000
#define	 MRS_CRm_SHIFT			8
#define	 MRS_CRm_MASK			0x00000f00
#define	 MRS_Op2_SHIFT			5
#define	 MRS_Op2_MASK			0x000000e0

	read = false;
	switch (insn & MRS_MASK) {
	case MRS_VALUE:
		read = true;
		break;
	case MSR_REG_VALUE:
		break;
	case MSR_IMM_VALUE:
		/*
		 * MSR (immediate) needs special handling. The
		 * source register is always 31 (xzr), CRn is 4,
		 * and op0 is hard coded as 0.
		 */
		if (MRS_REGISTER(insn) != 31)
			return (false);
		if ((insn & MRS_CRn_MASK) >> MRS_CRn_SHIFT != 4)
			return (false);
		if ((insn & MRS_Op0_MASK) >> MRS_Op0_SHIFT != 0)
			return (false);
		break;
	default:
		return (false);
	}

	/* Create a fake EXCP_MSR esr value */
	esr = EXCP_MSR << ESR_ELx_EC_SHIFT;
	esr |= ESR_ELx_IL;
	esr |= __ISS_MSR_REG(
	    (insn & MRS_Op0_MASK) >> MRS_Op0_SHIFT,
	    (insn & MRS_Op1_MASK) >> MRS_Op1_SHIFT,
	    (insn & MRS_CRn_MASK) >> MRS_CRn_SHIFT,
	    (insn & MRS_CRm_MASK) >> MRS_CRm_SHIFT,
	    (insn & MRS_Op2_MASK) >> MRS_Op2_SHIFT);
	esr |= MRS_REGISTER(insn) << ISS_MSR_Rt_SHIFT;
	if (read)
		esr |= ISS_MSR_DIR;

#undef MRS_MASK
#undef MRS_VALUE
#undef MSR_REG_VALUE
#undef MSR_IMM_VALUE
#undef MRS_REGISTER
#undef MRS_Op0_SHIFT
#undef MRS_Op0_MASK
#undef MRS_Op1_SHIFT
#undef MRS_Op1_MASK
#undef MRS_CRn_SHIFT
#undef MRS_CRn_MASK
#undef MRS_CRm_SHIFT
#undef MRS_CRm_MASK
#undef MRS_Op2_SHIFT
#undef MRS_Op2_MASK

	return (undef_sys(esr, frame));
}

int
undef_insn(struct trapframe *frame)
{
	struct undef_handler *uh;
	uint32_t insn;
	int ret;

	ret = fueword32((uint32_t *)frame->tf_elr, &insn);
	/* Raise a SIGILL if we are unable to read the instruction */
	if (ret != 0)
		return (0);


	if (undef_sys_insn(frame, insn))
		return (1);

	LIST_FOREACH(uh, &undef_handlers, uh_link) {
		ret = uh->uh_handler(frame->tf_elr, insn, frame, frame->tf_esr);
		if (ret)
			return (1);
	}

	return (0);
}
