/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 *
 * Portions Copyright 2006-2008 John Birrell jb@freebsd.org
 * Portions Copyright 2013 Justin Hibbits jhibbits@freebsd.org
 * Portions Copyright 2013 Howard Su howardsu@freebsd.org
 * Portions Copyright 2015 Ruslan Bukin <br@bsdpad.com>
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>

#include <sys/dtrace.h>

#include "fbt.h"

#define	FBT_PATCHVAL	DTRACE_PATCHVAL
#define	FBT_AFRAMES	4

int
fbt_invop(uintptr_t addr, struct trapframe *frame, uintptr_t rval)
{
	solaris_cpu_t *cpu;
	fbt_probe_t *fbt;

	cpu = &solaris_cpu[curcpu];
	fbt = fbt_probetab[FBT_ADDR2NDX(addr)];

	for (; fbt != NULL; fbt = fbt->fbtp_hashnext) {
		if ((uintptr_t)fbt->fbtp_patchpoint != addr)
			continue;

		cpu->cpu_dtrace_caller = addr;

		if (fbt->fbtp_roffset == 0) {
			dtrace_probe(fbt->fbtp_id, frame->tf_x[0],
			    frame->tf_x[1], frame->tf_x[2],
			    frame->tf_x[3], frame->tf_x[4]);
		} else {
			dtrace_probe(fbt->fbtp_id, fbt->fbtp_roffset, rval,
			    0, 0, 0);
		}
		cpu->cpu_dtrace_caller = 0;
		return (fbt->fbtp_savedval);
	}

	return (0);
}

void
fbt_patch_tracepoint(fbt_probe_t *fbt, fbt_patchval_t val)
{
	void *addr;

	if (!arm64_get_writable_addr(fbt->fbtp_patchpoint, &addr))
		panic("%s: Unable to write new instruction", __func__);

	*(fbt_patchval_t *)addr = val;
	cpu_icache_sync_range(fbt->fbtp_patchpoint, 4);
}

int
fbt_provide_module_function(linker_file_t lf, int symindx,
    linker_symval_t *symval, void *opaque)
{
	fbt_probe_t *fbt, *retfbt;
	uint32_t *target, *start;
	uint32_t *instr, *limit;
	const char *name;
	char *modname;
	int offs;

	modname = opaque;
	name = symval->name;

	/* Check if function is excluded from instrumentation */
	if (fbt_excluded(name))
		return (0);

	/*
	 * Instrumenting certain exception handling functions can lead to FBT
	 * recursion, so exclude from instrumentation.  The other exception
	 * entry points, and fork_trampoline, run while sp_el0 holds the user
	 * stack pointer instead of the thread's stack canary: a probe there
	 * faults on the canary load in every function it calls, the fault
	 * handler included, until the kernel stack overflows.  A fault in
	 * probe context that DTrace does not claim, such as a kernel mapping
	 * caught mid break-before-make, reaches data_abort() and
	 * pmap_klookup(): a probe there recurses into dtrace_probe().
	 */
	if (strncmp(name, "handle_el", 9) == 0 ||
	    strcmp(name, "handle_empty_exception") == 0 ||
	    strcmp(name, "fork_trampoline") == 0 ||
	    strcmp(name, "do_el1h_sync") == 0 ||
	    strcmp(name, "data_abort") == 0 ||
	    strcmp(name, "pmap_klookup") == 0)
		return (0);

	/*
	 * A break-before-make update leaves a kernel mapping invalid while
	 * it flushes the TLB.  data_abort() takes a fault on it for that
	 * update in progress and retries, so a probe inside the window that
	 * touches memory behind the mapping, DTrace state included, faults
	 * and retries forever and the update never completes.
	 */
	if (strncmp(name, "pmap_update_", 12) == 0 ||
	    strncmp(name, "pmap_s1_invalidate", 18) == 0 ||
	    strncmp(name, "pmap_invalidate_", 16) == 0 ||
	    strncmp(name, "pmap_tlbi_", 10) == 0)
		return (0);

	instr = (uint32_t *)(symval->value);
	limit = (uint32_t *)(symval->value + symval->size);

	/*
	 * Ignore any bti instruction at the start of the function
	 * we need to keep it there for any indirect branches calling
	 * the function on Armv8.5+
	 */
	if ((*instr & BTI_MASK) == BTI_INSTR)
		instr++;

	/*
	 * If the first instruction is a nop it's a specially marked
	 * asm function. We only support a nop first as it's not a normal
	 * part of the function prologue.
	 */
	if (*instr == NOP_INSTR)
		goto found;

	/* Look for stp (pre-indexed) or sub operation */
	for (; instr < limit; instr++) {
		/*
		 * Functions start with "stp xt1, xt2, [xn, <const>]!" or
		 * "sub sp, sp, <const>".
		 *
		 * Sometimes the compiler will have a sub instruction that is
		 * not of the above type so don't stop if we see one.
		 */
		if ((*instr & LDP_STP_MASK) == STP_64) {
			/*
			 * Assume any other store of this type means we are
			 * past the function prologue.
			 */
			if (((*instr >> ADDR_SHIFT) & ADDR_MASK) == 31)
				break;
		} else if ((*instr & SUB_MASK) == SUB_INSTR &&
		    ((*instr >> SUB_RD_SHIFT) & SUB_R_MASK) == 31 &&
		    ((*instr >> SUB_RN_SHIFT) & SUB_R_MASK) == 31)
			break;
	}
found:
	if (instr >= limit)
		return (0);

	fbt = malloc(sizeof (fbt_probe_t), M_FBT, M_WAITOK | M_ZERO);
	fbt->fbtp_name = name;
	fbt->fbtp_id = dtrace_probe_create(fbt_id, modname,
	    name, FBT_ENTRY, FBT_AFRAMES, fbt);
	fbt->fbtp_patchpoint = instr;
	fbt->fbtp_ctl = lf;
	fbt->fbtp_loadcnt = lf->loadcnt;
	fbt->fbtp_savedval = *instr;
	fbt->fbtp_patchval = FBT_PATCHVAL;
	if ((*instr & SUB_MASK) == SUB_INSTR)
		fbt->fbtp_rval = DTRACE_INVOP_SUB;
	else
		fbt->fbtp_rval = DTRACE_INVOP_STP;
	fbt->fbtp_symindx = symindx;

	fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
	fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;

	lf->fbt_nentries++;

	retfbt = NULL;
again:
	for (; instr < limit; instr++) {
		if (*instr == RET_INSTR)
			break;
		else if ((*instr & B_MASK) == B_INSTR) {
			offs = (*instr & B_DATA_MASK);
			target = instr + offs;
			start = (uint32_t *)symval->value;
			if (target >= limit || target < start)
				break;
		}
	}

	if (instr >= limit)
		return (0);

	/*
	 * We have a winner!
	 */
	fbt = malloc(sizeof (fbt_probe_t), M_FBT, M_WAITOK | M_ZERO);
	fbt->fbtp_name = name;
	if (retfbt == NULL) {
		fbt->fbtp_id = dtrace_probe_create(fbt_id, modname,
		    name, FBT_RETURN, FBT_AFRAMES, fbt);
	} else {
		retfbt->fbtp_probenext = fbt;
		fbt->fbtp_id = retfbt->fbtp_id;
	}
	retfbt = fbt;

	fbt->fbtp_patchpoint = instr;
	fbt->fbtp_ctl = lf;
	fbt->fbtp_loadcnt = lf->loadcnt;
	fbt->fbtp_symindx = symindx;
	if ((*instr & B_MASK) == B_INSTR)
		fbt->fbtp_rval = DTRACE_INVOP_B;
	else
		fbt->fbtp_rval = DTRACE_INVOP_RET;
	fbt->fbtp_roffset = (uintptr_t)instr - (uintptr_t)symval->value;
	fbt->fbtp_savedval = *instr;
	fbt->fbtp_patchval = FBT_PATCHVAL;
	fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
	fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;

	lf->fbt_nentries++;

	instr++;
	goto again;
}
