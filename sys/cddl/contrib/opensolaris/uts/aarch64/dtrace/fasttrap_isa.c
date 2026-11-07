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
 * CDDL HEADER END
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * AArch64 instructions are all four bytes, so a tracepoint is a brk that
 * replaces one instruction.  Anything that depends on its own address is
 * emulated here.  The rest runs from the thread's scratch space, followed by
 * a second brk, as no absolute branch can return to the program without
 * clobbering a register:
 *
 *	+0	the instruction
 *	+4	brk #BRK_IMM_FASTTRAP_RETURN
 *	+16	copy of the literal, for a rewritten ldr (literal)
 *
 * A signal delivered before the second brk would run its handler with the
 * thread's scratch space in use, and the handler could hit a tracepoint of
 * its own.  fasttrap_sendsig() moves the thread out of scratch space first.
 *
 * AArch32 processes are not supported.
 */

#include <sys/fasttrap_isa.h>
#include <sys/fasttrap_impl.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <cddl/dev/dtrace/dtrace_cddl.h>
#include <sys/proc.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/rmlock.h>
#include <sys/sx.h>
#include <sys/sysent.h>

#include <machine/armreg.h>
#include <machine/frame.h>

#define	FASTTRAP_NOP		0xd503201f
#define	FASTTRAP_AUTIASP	0xd50323bf
#define	FASTTRAP_AUTIBSP	0xd50323ff
#define	FASTTRAP_CLREX		0xd503305f

#define	FASTTRAP_SCR_RET	4	/* offset of the second brk */
#define	FASTTRAP_SCR_LIT	16	/* offset of a copied literal */

/* How far before a tracepoint to look for an open exclusive sequence. */
#define	FASTTRAP_EXCL_WINDOW	16

#define	OP_RD(x)		((x) & 0x1f)
#define	OP_RN(x)		(((x) >> 5) & 0x1f)

static inline uintptr_t
fasttrap_sext(uint64_t value, int bits)
{

	return ((uintptr_t)((int64_t)(value << (64 - bits)) >> (64 - bits)));
}

/* Register 31 reads as zero in every instruction emulated here. */
static uint64_t
fasttrap_getreg(struct trapframe *tf, u_int reg)
{

	if (reg < nitems(tf->tf_x))
		return (tf->tf_x[reg]);
	return (reg == 30 ? tf->tf_lr : 0);
}

static void
fasttrap_setreg(struct trapframe *tf, u_int reg, uint64_t value)
{

	if (reg < nitems(tf->tf_x))
		tf->tf_x[reg] = value;
	else if (reg == 30)
		tf->tf_lr = value;
}

static bool
fasttrap_is_exclusive(uint32_t instr)
{

	if ((instr & 0x3f800000) != 0x08000000)
		return (false);
	/* With a 32-bit size, o1 selects casp rather than a pair. */
	return ((instr & 0x80200000) != 0x00200000);
}

/*
 * The exception taken at a tracepoint clears the exclusive monitor, so a
 * tracepoint between a load-exclusive and its store-exclusive would make the
 * store fail every time around the loop.
 */
static bool
fasttrap_in_exclusive(proc_t *p, uintptr_t pc)
{
	uint32_t instr;
	int i;

	for (i = 1; i <= FASTTRAP_EXCL_WINDOW; i++) {
		if (uread(p, &instr, 4, pc - i * 4) != 0)
			return (false);
		if (instr == FASTTRAP_CLREX)
			return (false);
		if (fasttrap_is_exclusive(instr))
			return ((instr & (1u << 22)) != 0);
	}
	return (false);
}

static int
fasttrap_decode(fasttrap_tracepoint_t *tp, uint32_t instr, uintptr_t pc)
{
	uint64_t imm;
	u_int opc, op3, op4, rn;

	tp->ftt_type = FASTTRAP_T_COMMON;
	tp->ftt_instr = instr;

	/* udf, and the instructions that take an exception. */
	if ((instr & 0xffff0000) == 0 || (instr & 0xff000000) == 0xd4000000)
		return (-1);
	if (fasttrap_is_exclusive(instr))
		return (-1);

	if (instr == FASTTRAP_NOP || (instr & 0xffffff3f) == 0xd503241f) {
		/* nop, and bti in any of its forms. */
		tp->ftt_type = FASTTRAP_T_NOP;
	} else if ((instr & 0x7c000000) == 0x14000000) {
		tp->ftt_type = (instr >> 31) != 0 ? FASTTRAP_T_BL :
		    FASTTRAP_T_B;
		tp->ftt_dest = pc + (fasttrap_sext(instr, 26) << 2);
	} else if ((instr & 0xff000000) == 0x54000000) {
		tp->ftt_type = FASTTRAP_T_BCOND;
		tp->ftt_cond = instr & 0xf;
		tp->ftt_dest = pc + (fasttrap_sext(instr >> 5, 19) << 2);
	} else if ((instr & 0x7e000000) == 0x34000000) {
		tp->ftt_type = FASTTRAP_T_CBZ;
		tp->ftt_reg = OP_RD(instr);
		tp->ftt_bit = (instr >> 31) != 0 ? 64 : 32;
		tp->ftt_invert = (instr >> 24) & 1;
		tp->ftt_dest = pc + (fasttrap_sext(instr >> 5, 19) << 2);
	} else if ((instr & 0x7e000000) == 0x36000000) {
		tp->ftt_type = FASTTRAP_T_TBZ;
		tp->ftt_reg = OP_RD(instr);
		tp->ftt_bit = ((instr >> 26) & 0x20) | ((instr >> 19) & 0x1f);
		tp->ftt_invert = (instr >> 24) & 1;
		tp->ftt_dest = pc + (fasttrap_sext(instr >> 5, 14) << 2);
	} else if ((instr & 0x1f000000) == 0x10000000) {
		imm = ((instr >> 3) & 0x1ffffc) | ((instr >> 29) & 3);
		tp->ftt_type = FASTTRAP_T_ADR;
		tp->ftt_reg = OP_RD(instr);
		if ((instr >> 31) != 0)
			tp->ftt_dest = (pc & ~(uintptr_t)0xfff) +
			    (fasttrap_sext(imm, 21) << 12);
		else
			tp->ftt_dest = pc + fasttrap_sext(imm, 21);
	} else if ((instr & 0x3b000000) == 0x18000000) {
		/*
		 * Every other literal load is rewritten to find a copy of
		 * its literal in scratch space, which also covers the SIMD
		 * registers the kernel has no saved state for here.
		 */
		opc = instr >> 30;
		if ((instr & (1u << 26)) == 0) {
			if (opc == 3) {
				/* prfm is only a hint. */
				tp->ftt_type = FASTTRAP_T_NOP;
				return (0);
			}
			tp->ftt_size = opc == 1 ? 8 : 4;
		} else {
			if (opc == 3)
				return (-1);
			tp->ftt_size = 4 << opc;
		}
		tp->ftt_type = FASTTRAP_T_LDR_LIT;
		tp->ftt_dest = pc + (fasttrap_sext(instr >> 5, 19) << 2);
		tp->ftt_instr = (instr & 0xff00001f) |
		    ((FASTTRAP_SCR_LIT / 4) << 5);
	} else if ((instr & 0xfe1f0000) == 0xd61f0000) {
		opc = (instr >> 21) & 0xf;
		op3 = (instr >> 10) & 0x3f;
		op4 = instr & 0x1f;
		rn = OP_RN(instr);
		if (op3 == 0 && op4 == 0 && opc <= 2) {
			tp->ftt_type = opc == 1 ? FASTTRAP_T_BLR :
			    FASTTRAP_T_RET;
			tp->ftt_reg = rn;
		} else if (opc == 2 && (op3 == 2 || op3 == 3) && rn == 31 &&
		    op4 == 31) {
			/* retaa and retab authenticate lr out of line. */
			tp->ftt_type = FASTTRAP_T_RET_AUTH;
			tp->ftt_instr = op3 == 2 ? FASTTRAP_AUTIASP :
			    FASTTRAP_AUTIBSP;
		} else {
			/*
			 * The other authenticated branches would leave their
			 * register authenticated if run in two steps.
			 */
			return (-1);
		}
	}

	return (0);
}

int
fasttrap_tracepoint_install(proc_t *p, fasttrap_tracepoint_t *tp)
{
	fasttrap_instr_t instr = FASTTRAP_INSTR;

	if (uwrite(p, &instr, 4, tp->ftt_pc) != 0)
		return (-1);

	return (0);
}

int
fasttrap_tracepoint_remove(proc_t *p, fasttrap_tracepoint_t *tp)
{
	uint32_t instr;

	/*
	 * Distinguish between read or write failures and a changed
	 * instruction.
	 */
	if (uread(p, &instr, 4, tp->ftt_pc) != 0)
		return (0);
	if (instr != FASTTRAP_INSTR)
		return (0);
	if (uwrite(p, &tp->ftt_orig, 4, tp->ftt_pc) != 0)
		return (-1);

	return (0);
}

int
fasttrap_tracepoint_init(proc_t *p, fasttrap_tracepoint_t *tp, uintptr_t pc,
    fasttrap_probe_type_t type)
{
	uint32_t instr;

	if (SV_PROC_FLAG(p, SV_ILP32) != 0)
		return (-1);

	/*
	 * Read the instruction at the given address out of the process's
	 * address space. We don't have to worry about a debugger
	 * changing this instruction before we overwrite it with our trap
	 * instruction since P_PR_LOCK is set.
	 */
	if (uread(p, &instr, 4, pc) != 0)
		return (-1);
	if (fasttrap_in_exclusive(p, pc))
		return (-1);

	tp->ftt_orig = instr;
	return (fasttrap_decode(tp, instr, pc));
}

static uint64_t
fasttrap_anarg(struct trapframe *tf, int argno)
{
	uint64_t value;

	/* The first 8 arguments are in registers. */
	if (argno < 8)
		return (tf->tf_x[argno]);

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	value = dtrace_fuword64((void *)(tf->tf_sp +
	    (argno - 8) * sizeof (uint64_t)));
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT | CPU_DTRACE_BADADDR);

	return (value);
}

uint64_t
fasttrap_pid_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
    int aframes)
{

	return (fasttrap_anarg(curthread->td_frame, argno));
}

uint64_t
fasttrap_usdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
    int aframes)
{
	fasttrap_probe_t *probe = parg;

	if (probe->ftp_argmap != NULL && argno < probe->ftp_nargs)
		argno = probe->ftp_argmap[argno];
	return (fasttrap_anarg(curthread->td_frame, argno));
}

static void
fasttrap_usdt_args(fasttrap_probe_t *probe, struct trapframe *tf, int argc,
    uintptr_t *argv)
{
	int i, x, cap = MIN(argc, probe->ftp_nargs);

	for (i = 0; i < cap; i++) {
		x = probe->ftp_argmap[i];

		if (x < 8)
			argv[i] = tf->tf_x[x];
		else
			argv[i] = fuword64((void *)(tf->tf_sp +
			    (x - 8) * sizeof (uint64_t)));
	}

	for (; i < argc; i++)
		argv[i] = 0;
}

static void
fasttrap_return_common(struct trapframe *tf, uintptr_t pc, pid_t pid,
    uintptr_t new_pc)
{
	struct rm_priotracker tracker;
	fasttrap_tracepoint_t *tp;
	fasttrap_bucket_t *bucket;
	fasttrap_id_t *id;

	rm_rlock(&fasttrap_tp_lock, &tracker);
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
		    tp->ftt_proc->ftpc_acount != 0)
			break;
	}

	/*
	 * Don't sweat it if we can't find the tracepoint again; unlike
	 * when we're in fasttrap_pid_probe(), finding the tracepoint here
	 * is not essential to the correct execution of the process.
	 */
	if (tp == NULL) {
		rm_runlock(&fasttrap_tp_lock, &tracker);
		return;
	}

	for (id = tp->ftt_retids; id != NULL; id = id->fti_next) {
		/* A branch within the function is not a return. */
		if (new_pc - id->fti_probe->ftp_faddr <
		    id->fti_probe->ftp_fsize)
			continue;

		dtrace_probe(id->fti_probe->ftp_id,
		    pc - id->fti_probe->ftp_faddr,
		    tf->tf_x[0], tf->tf_x[1], 0, 0);
	}
	rm_runlock(&fasttrap_tp_lock, &tracker);
}

static bool
fasttrap_cond_true(uint64_t spsr, u_int cond)
{
	bool n, z, c, v, res;

	n = (spsr & PSR_N) != 0;
	z = (spsr & PSR_Z) != 0;
	c = (spsr & PSR_C) != 0;
	v = (spsr & PSR_V) != 0;

	switch (cond >> 1) {
	case 0:
		res = z;
		break;
	case 1:
		res = c;
		break;
	case 2:
		res = n;
		break;
	case 3:
		res = v;
		break;
	case 4:
		res = c && !z;
		break;
	case 5:
		res = n == v;
		break;
	case 6:
		res = n == v && !z;
		break;
	default:
		res = true;
		break;
	}

	return ((cond & 1) != 0 && cond != 0xf ? !res : res);
}

static void
fasttrap_sigsegv(proc_t *p, kthread_t *t, uintptr_t addr)
{
	ksiginfo_t ksi;

	ksiginfo_init(&ksi);
	ksi.ksi_signo = SIGSEGV;
	ksi.ksi_code = SEGV_MAPERR;
	ksi.ksi_addr = (caddr_t)addr;
	PROC_LOCK(p);
	(void)tdksignal(t, SIGSEGV, &ksi);
	PROC_UNLOCK(p);
}

static void
fasttrap_clear_thread(void)
{

	curthread->t_dtrace_ft = 0;
	curthread->t_dtrace_pc = 0;
	curthread->t_dtrace_npc = 0;
	curthread->t_dtrace_scrpc = 0;
	curthread->t_dtrace_astpc = 0;
}

int
fasttrap_pid_probe(struct trapframe *tf)
{
	struct rm_priotracker tracker;
	proc_t *p = curproc, *pp;
	uint64_t gen;
	uintptr_t pc, new_pc;
	fasttrap_bucket_t *bucket;
	fasttrap_tracepoint_t *tp, tp_local;
	fasttrap_scrspace_t *scrspace;
	pid_t pid;
	dtrace_icookie_t cookie;
	uint_t is_enabled = 0;
	uint32_t scratch[2];
	uint8_t literal[16];
	uint64_t value;
	bool taken;

	pc = tf->tf_elr;
	fasttrap_clear_thread();

	/*
	 * Treat a child created by a call to vfork(2) as if it were its
	 * parent. We know that there's only one thread of control in such a
	 * process: this one.
	 */
	pp = p;
	sx_slock(&proctree_lock);
	while (pp->p_vmspace == pp->p_pptr->p_vmspace)
		pp = pp->p_pptr;
	pid = pp->p_pid;
	if (pp != p) {
		PROC_LOCK(pp);
		if ((pp->p_flag & P_WEXIT) != 0) {
			/*
			 * This can happen if the child was created with
			 * rfork(2).  Userspace tracing cannot work reliably in
			 * such a scenario, but we can at least try.
			 */
			PROC_UNLOCK(pp);
			sx_sunlock(&proctree_lock);
			return (-1);
		}
		_PHOLD(pp);
		PROC_UNLOCK(pp);
	}
	sx_sunlock(&proctree_lock);

	rm_rlock(&fasttrap_tp_lock, &tracker);

	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	/*
	 * Lookup the tracepoint that the process just hit.
	 */
	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
		    tp->ftt_proc->ftpc_acount != 0)
			break;
	}

	/*
	 * If we couldn't find a matching tracepoint, either a tracepoint has
	 * been inserted without using the pid<pid> ioctl interface (see
	 * fasttrap_ioctl), or somehow we have mislaid this tracepoint.
	 */
	if (tp == NULL) {
		rm_runlock(&fasttrap_tp_lock, &tracker);
		gen = atomic_load_acq_64(&pp->p_fasttrap_tp_gen);
		if (pp != p)
			PRELE(pp);
		if (curthread->t_fasttrap_tp_gen != gen) {
			/*
			 * At least one tracepoint associated with this PID has
			 * been removed from the table since the brk was taken.
			 * Speculate that we hit a tracepoint that has since
			 * been removed, and retry the instruction.
			 */
			curthread->t_fasttrap_tp_gen = gen;
			return (0);
		}
		return (-1);
	}
	if (pp != p)
		PRELE(pp);

	if (tp->ftt_ids != NULL) {
		fasttrap_id_t *id;

		for (id = tp->ftt_ids; id != NULL; id = id->fti_next) {
			fasttrap_probe_t *probe = id->fti_probe;

			if (id->fti_ptype == DTFTP_ENTRY) {
				/*
				 * We note that this was an entry
				 * probe to help ustack() find the
				 * first caller.
				 */
				cookie = dtrace_interrupt_disable();
				DTRACE_CPUFLAG_SET(CPU_DTRACE_ENTRY);
				dtrace_probe(probe->ftp_id, tf->tf_x[0],
				    tf->tf_x[1], tf->tf_x[2], tf->tf_x[3],
				    tf->tf_x[4]);
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_ENTRY);
				dtrace_interrupt_enable(cookie);
			} else if (id->fti_ptype == DTFTP_IS_ENABLED) {
				/*
				 * Note that in this case, we don't
				 * call dtrace_probe() since it's only
				 * an artificial probe meant to change
				 * the flow of control so that it
				 * encounters the true probe.
				 */
				is_enabled = 1;
			} else if (probe->ftp_argmap == NULL) {
				dtrace_probe(probe->ftp_id, tf->tf_x[0],
				    tf->tf_x[1], tf->tf_x[2], tf->tf_x[3],
				    tf->tf_x[4]);
			} else {
				uintptr_t t[5];

				fasttrap_usdt_args(probe, tf,
				    sizeof (t) / sizeof (t[0]), t);

				dtrace_probe(probe->ftp_id, t[0], t[1],
				    t[2], t[3], t[4]);
			}
		}
	}

	/*
	 * We're about to do a bunch of work so we cache a local copy of
	 * the tracepoint to emulate the instruction, and then find the
	 * tracepoint again later if we need to light up any return probes.
	 */
	tp_local = *tp;
	rm_runlock(&fasttrap_tp_lock, &tracker);
	tp = &tp_local;

	/*
	 * An is-enabled site was rewritten by the linker to set x0 to zero,
	 * or to a ret if it was a tail call, which still has to return.
	 */
	if (is_enabled) {
		tf->tf_x[0] = 1;
		new_pc = tp->ftt_type == FASTTRAP_T_RET ? tf->tf_lr : pc + 4;
		goto done;
	}

	new_pc = pc + 4;

	switch (tp->ftt_type) {
	case FASTTRAP_T_NOP:
		break;
	case FASTTRAP_T_B:
		new_pc = tp->ftt_dest;
		break;
	case FASTTRAP_T_BL:
		tf->tf_lr = pc + 4;
		new_pc = tp->ftt_dest;
		break;
	case FASTTRAP_T_BCOND:
		if (fasttrap_cond_true(tf->tf_spsr, tp->ftt_cond))
			new_pc = tp->ftt_dest;
		break;
	case FASTTRAP_T_CBZ:
		value = fasttrap_getreg(tf, tp->ftt_reg);
		if (tp->ftt_bit == 32)
			value = (uint32_t)value;
		taken = value == 0;
		if (taken != (tp->ftt_invert != 0))
			new_pc = tp->ftt_dest;
		break;
	case FASTTRAP_T_TBZ:
		value = fasttrap_getreg(tf, tp->ftt_reg);
		taken = (value & (1ul << tp->ftt_bit)) == 0;
		if (taken != (tp->ftt_invert != 0))
			new_pc = tp->ftt_dest;
		break;
	case FASTTRAP_T_ADR:
		fasttrap_setreg(tf, tp->ftt_reg, tp->ftt_dest);
		break;
	case FASTTRAP_T_RET:
		new_pc = fasttrap_getreg(tf, tp->ftt_reg);
		break;
	case FASTTRAP_T_BLR:
		new_pc = fasttrap_getreg(tf, tp->ftt_reg);
		tf->tf_lr = pc + 4;
		break;
	case FASTTRAP_T_COMMON:
	case FASTTRAP_T_LDR_LIT:
	case FASTTRAP_T_RET_AUTH:
		scrspace = fasttrap_scraddr(curthread, tp->ftt_proc);
		if (scrspace == NULL) {
			/*
			 * We failed to allocate scratch space for this thread.
			 * Try to write the original instruction back out and
			 * reset the pc.
			 */
			if (uwrite(p, &tp->ftt_orig, 4, pc) != 0)
				fasttrap_sigtrap(p, curthread, pc);
			new_pc = pc;
			break;
		}
		scratch[0] = tp->ftt_instr;
		scratch[1] = FASTTRAP_RET_INSTR;
		if (tp->ftt_type == FASTTRAP_T_LDR_LIT) {
			if (copyin((void *)tp->ftt_dest, literal,
			    tp->ftt_size) != 0) {
				fasttrap_sigsegv(p, curthread, tp->ftt_dest);
				new_pc = pc;
				break;
			}
			if (uwrite(p, literal, tp->ftt_size,
			    scrspace->ftss_addr + FASTTRAP_SCR_LIT) != 0) {
				fasttrap_sigtrap(p, curthread, pc);
				new_pc = pc;
				break;
			}
		}
		if (uwrite(p, scratch, sizeof (scratch),
		    scrspace->ftss_addr) != 0) {
			fasttrap_sigtrap(p, curthread, pc);
			new_pc = pc;
			break;
		}
		curthread->t_dtrace_pc = pc;
		curthread->t_dtrace_npc = pc + 4;
		curthread->t_dtrace_scrpc = scrspace->ftss_addr;
		curthread->t_dtrace_ret = tp->ftt_type == FASTTRAP_T_RET_AUTH;
		curthread->t_dtrace_on = 1;
		tf->tf_spsr &= ~PSR_BTYPE;
		tf->tf_elr = scrspace->ftss_addr;
		return (0);
	}

done:
	/*
	 * If there were no return probes when we first found the tracepoint,
	 * we should feel no obligation to honor any return probes that were
	 * subsequently enabled -- they'll just have to wait until the next
	 * time around.
	 */
	if (tp->ftt_retids != NULL && new_pc != pc)
		fasttrap_return_common(tf, pc, pid, new_pc);

	tf->tf_spsr &= ~PSR_BTYPE;
	tf->tf_elr = new_pc;

	return (0);
}

int
fasttrap_return_probe(struct trapframe *tf)
{
	proc_t *p = curproc;
	struct thread *td = curthread;
	uintptr_t pc, new_pc;
	pid_t pid;

	if (!td->t_dtrace_on ||
	    tf->tf_elr != td->t_dtrace_scrpc + FASTTRAP_SCR_RET)
		return (-1);

	pc = td->t_dtrace_pc;
	new_pc = td->t_dtrace_ret ? tf->tf_lr : td->t_dtrace_npc;
	fasttrap_clear_thread();

	/* A vfork(2) child shares its parent's tracepoints. */
	sx_slock(&proctree_lock);
	while (p->p_vmspace == p->p_pptr->p_vmspace)
		p = p->p_pptr;
	pid = p->p_pid;
	sx_sunlock(&proctree_lock);

	fasttrap_return_common(tf, pc, pid, new_pc);
	tf->tf_elr = new_pc;

	return (0);
}

/*
 * Called with the proc lock held before a signal frame is built.  A thread
 * that has yet to run its displaced instruction goes back to the tracepoint
 * and takes it again once the handler returns, firing its probes twice; one
 * that has run it moves on.  Return probes would need the proctree lock, so
 * the second case misses them.
 */
void
fasttrap_sendsig(struct thread *td, struct trapframe *tf)
{

	if (!td->t_dtrace_on)
		return;

	if (tf->tf_elr == td->t_dtrace_scrpc) {
		tf->tf_elr = td->t_dtrace_pc;
		fasttrap_clear_thread();
	} else if (tf->tf_elr == td->t_dtrace_scrpc + FASTTRAP_SCR_RET) {
		tf->tf_elr = td->t_dtrace_ret ? tf->tf_lr : td->t_dtrace_npc;
		fasttrap_clear_thread();
	}
}
