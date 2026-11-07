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
 * A tracepoint is an ebreak of the size of the instruction it replaces.
 * Instructions that depend on the program counter are emulated here; the rest
 * run from the thread's scratch space, followed by a second ebreak, as an
 * absolute branch back to the program would clobber a register.
 *
 * A signal delivered before the second ebreak would run its handler with the
 * thread's scratch space in use, and the handler could hit a tracepoint of
 * its own, so fasttrap_sendsig() moves the thread out of scratch space first.
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

#include <machine/frame.h>
#include <machine/riscvreg.h>

#define	OP_MASK(x)	((x) & 0x7f)
#define	OP_RD(x)	(((x) >> 7) & 0x1f)
#define	OP_FUNCT3(x)	(((x) >> 12) & 7)
#define	OP_RS1(x)	(((x) >> 15) & 0x1f)
#define	OP_RS2(x)	(((x) >> 20) & 0x1f)
#define	OP_FUNCT5(x)	((x) >> 27)

#define	OP_BRANCH	0x63
#define	OP_JALR		0x67
#define	OP_JAL		0x6f
#define	OP_AUIPC	0x17
#define	OP_SYSTEM	0x73
#define	OP_AMO		0x2f
#define	OP_AMO_LR	2
#define	OP_AMO_SC	3

/* How far before a tracepoint to look for an open lr/sc sequence. */
#define	FASTTRAP_EXCL_WINDOW	16

static inline uintptr_t
fasttrap_sext(uint64_t value, int bits)
{

	return ((uintptr_t)((int64_t)(value << (64 - bits)) >> (64 - bits)));
}

/* x0 reads as zero and ignores writes. */
static uint64_t *
fasttrap_regp(struct trapframe *tf, u_int reg)
{

	if (reg == 1)
		return (&tf->tf_ra);
	if (reg == 2)
		return (&tf->tf_sp);
	if (reg == 3)
		return (&tf->tf_gp);
	if (reg == 4)
		return (&tf->tf_tp);
	if (reg >= 5 && reg <= 7)
		return (&tf->tf_t[reg - 5]);
	if (reg == 8 || reg == 9)
		return (&tf->tf_s[reg - 8]);
	if (reg >= 10 && reg <= 17)
		return (&tf->tf_a[reg - 10]);
	if (reg >= 18 && reg <= 27)
		return (&tf->tf_s[reg - 16]);
	if (reg >= 28 && reg <= 31)
		return (&tf->tf_t[reg - 25]);
	return (NULL);
}

static uint64_t
fasttrap_getreg(struct trapframe *tf, u_int reg)
{
	uint64_t *p;

	p = fasttrap_regp(tf, reg);
	return (p != NULL ? *p : 0);
}

static void
fasttrap_setreg(struct trapframe *tf, u_int reg, uint64_t value)
{
	uint64_t *p;

	p = fasttrap_regp(tf, reg);
	if (p != NULL)
		*p = value;
}

static int
fasttrap_fetch(proc_t *p, uintptr_t pc, uint32_t *instr, uint8_t *size)
{
	uint16_t half;

	if (uread(p, &half, 2, pc) != 0)
		return (-1);
	*instr = half;
	*size = 2;
	if ((half & 3) == 3) {
		if (uread(p, &half, 2, pc + 2) != 0)
			return (-1);
		*instr |= (uint32_t)half << 16;
		*size = 4;
	}
	return (0);
}

/*
 * The exception taken at a tracepoint invalidates a reservation, so a
 * tracepoint between lr and sc would make the sc fail every time around the
 * loop.  The instructions before pc are of unknown size, so look at every
 * halfword and accept the odd false match.
 */
static bool
fasttrap_in_reservation(proc_t *p, uintptr_t pc)
{
	uint16_t half[2];
	uint32_t instr;
	int i;

	for (i = 1; i <= FASTTRAP_EXCL_WINDOW * 2; i++) {
		if (uread(p, half, sizeof (half), pc - i * 2) != 0)
			return (false);
		instr = half[0] | (uint32_t)half[1] << 16;
		if (OP_MASK(instr) != OP_AMO)
			continue;
		if (OP_FUNCT5(instr) == OP_AMO_SC)
			return (false);
		if (OP_FUNCT5(instr) == OP_AMO_LR)
			return (true);
	}
	return (false);
}

static int
fasttrap_decode_c(fasttrap_tracepoint_t *tp, uint16_t c, uintptr_t pc)
{
	uint64_t imm;
	u_int funct3, rd, rs2;

	funct3 = c >> 13;
	rd = (c >> 7) & 0x1f;
	rs2 = (c >> 2) & 0x1f;

	if (c == 0)
		return (-1);

	if ((c & 3) == 1 && funct3 == 0 && rd == 0 && ((c >> 2) & 0x1f) == 0 &&
	    (c & (1 << 12)) == 0) {
		tp->ftt_type = FASTTRAP_T_NOP;
	} else if ((c & 3) == 1 && funct3 == 5) {
		/* c.j */
		imm = ((c >> 1) & 0x800) | ((c >> 7) & 0x10) |
		    ((c >> 1) & 0x300) | ((c << 2) & 0x400) |
		    ((c >> 1) & 0x40) | ((c << 1) & 0x80) |
		    ((c >> 2) & 0xe) | ((c << 3) & 0x20);
		tp->ftt_type = FASTTRAP_T_JAL;
		tp->ftt_rd = 0;
		tp->ftt_dest = pc + fasttrap_sext(imm, 12);
	} else if ((c & 3) == 1 && funct3 >= 6) {
		/* c.beqz and c.bnez */
		imm = ((c >> 4) & 0x100) | ((c >> 7) & 0x18) |
		    ((c << 1) & 0xc0) | ((c >> 2) & 0x6) | ((c << 3) & 0x20);
		tp->ftt_type = FASTTRAP_T_BRANCH;
		tp->ftt_cond = funct3 - 6;
		tp->ftt_rs1 = 8 + ((c >> 7) & 7);
		tp->ftt_rs2 = 0;
		tp->ftt_dest = pc + fasttrap_sext(imm, 9);
	} else if ((c & 3) == 2 && funct3 == 4 && rs2 == 0) {
		if ((c & (1 << 12)) != 0 && rd == 0)
			return (-1);	/* c.ebreak */
		if (rd == 0)
			return (-1);	/* reserved */
		/* c.jr and c.jalr */
		tp->ftt_type = FASTTRAP_T_JALR;
		tp->ftt_rd = (c & (1 << 12)) != 0 ? 1 : 0;
		tp->ftt_rs1 = rd;
		tp->ftt_imm = 0;
	}
	return (0);
}

static int
fasttrap_decode(fasttrap_tracepoint_t *tp, uint32_t instr, uintptr_t pc)
{
	uint64_t imm;

	tp->ftt_type = FASTTRAP_T_COMMON;

	if (tp->ftt_size == 2)
		return (fasttrap_decode_c(tp, instr, pc));

	switch (OP_MASK(instr)) {
	case OP_JAL:
		imm = ((instr >> 11) & 0x100000) | (instr & 0xff000) |
		    ((instr >> 9) & 0x800) | ((instr >> 20) & 0x7fe);
		tp->ftt_type = FASTTRAP_T_JAL;
		tp->ftt_rd = OP_RD(instr);
		tp->ftt_dest = pc + fasttrap_sext(imm, 21);
		break;
	case OP_JALR:
		if (OP_FUNCT3(instr) != 0)
			return (-1);
		tp->ftt_type = FASTTRAP_T_JALR;
		tp->ftt_rd = OP_RD(instr);
		tp->ftt_rs1 = OP_RS1(instr);
		tp->ftt_imm = fasttrap_sext(instr >> 20, 12);
		break;
	case OP_BRANCH:
		if (OP_FUNCT3(instr) == 2 || OP_FUNCT3(instr) == 3)
			return (-1);
		imm = ((instr >> 19) & 0x1000) | ((instr << 4) & 0x800) |
		    ((instr >> 20) & 0x7e0) | ((instr >> 7) & 0x1e);
		tp->ftt_type = FASTTRAP_T_BRANCH;
		tp->ftt_cond = OP_FUNCT3(instr);
		tp->ftt_rs1 = OP_RS1(instr);
		tp->ftt_rs2 = OP_RS2(instr);
		tp->ftt_dest = pc + fasttrap_sext(imm, 13);
		break;
	case OP_AUIPC:
		tp->ftt_type = FASTTRAP_T_AUIPC;
		tp->ftt_rd = OP_RD(instr);
		tp->ftt_dest = pc + fasttrap_sext(instr & 0xfffff000, 32);
		break;
	case OP_SYSTEM:
		/* ecall and ebreak take an exception of their own. */
		if (OP_FUNCT3(instr) == 0)
			return (-1);
		break;
	case OP_AMO:
		if (OP_FUNCT5(instr) == OP_AMO_LR ||
		    OP_FUNCT5(instr) == OP_AMO_SC)
			return (-1);
		break;
	}
	return (0);
}

int
fasttrap_tracepoint_install(proc_t *p, fasttrap_tracepoint_t *tp)
{
	uint32_t instr;
	uint16_t half;

	if (tp->ftt_size == 2) {
		half = FASTTRAP_C_INSTR;
		return (uwrite(p, &half, 2, tp->ftt_pc) != 0 ? -1 : 0);
	}
	instr = FASTTRAP_INSTR;
	return (uwrite(p, &instr, 4, tp->ftt_pc) != 0 ? -1 : 0);
}

int
fasttrap_tracepoint_remove(proc_t *p, fasttrap_tracepoint_t *tp)
{
	uint32_t instr;
	uint8_t size;

	/*
	 * Distinguish between read or write failures and a changed
	 * instruction.
	 */
	if (fasttrap_fetch(p, tp->ftt_pc, &instr, &size) != 0)
		return (0);
	if (instr != (tp->ftt_size == 2 ? FASTTRAP_C_INSTR : FASTTRAP_INSTR))
		return (0);
	if (uwrite(p, &tp->ftt_instr, tp->ftt_size, tp->ftt_pc) != 0)
		return (-1);

	return (0);
}

int
fasttrap_tracepoint_init(proc_t *p, fasttrap_tracepoint_t *tp, uintptr_t pc,
    fasttrap_probe_type_t type)
{
	uint32_t instr;
	uint8_t size;

	/*
	 * Read the instruction at the given address out of the process's
	 * address space. We don't have to worry about a debugger
	 * changing this instruction before we overwrite it with our trap
	 * instruction since P_PR_LOCK is set.
	 */
	if (fasttrap_fetch(p, pc, &instr, &size) != 0)
		return (-1);
	if (fasttrap_in_reservation(p, pc))
		return (-1);

	tp->ftt_instr = instr;
	tp->ftt_size = size;
	return (fasttrap_decode(tp, instr, pc));
}

static uint64_t
fasttrap_anarg(struct trapframe *tf, int argno)
{
	uint64_t value;

	/* The first 8 arguments are in registers. */
	if (argno < 8)
		return (tf->tf_a[argno]);

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
			argv[i] = tf->tf_a[x];
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
		    tf->tf_a[0], tf->tf_a[1], 0, 0);
	}
	rm_runlock(&fasttrap_tp_lock, &tracker);
}

static bool
fasttrap_branch_taken(u_int cond, uint64_t a, uint64_t b)
{

	switch (cond) {
	case 0:
		return (a == b);
	case 1:
		return (a != b);
	case 4:
		return ((int64_t)a < (int64_t)b);
	case 5:
		return ((int64_t)a >= (int64_t)b);
	case 6:
		return (a < b);
	default:
		return (a >= b);
	}
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
fasttrap_return_probe(struct trapframe *tf)
{
	proc_t *p = curproc;
	struct thread *td = curthread;
	uintptr_t pc, new_pc;
	pid_t pid;

	if (!td->t_dtrace_on || tf->tf_sepc != td->t_dtrace_astpc)
		return (-1);

	pc = td->t_dtrace_pc;
	new_pc = td->t_dtrace_npc;
	fasttrap_clear_thread();

	/* A vfork(2) child shares its parent's tracepoints. */
	sx_slock(&proctree_lock);
	while (p->p_vmspace == p->p_pptr->p_vmspace)
		p = p->p_pptr;
	pid = p->p_pid;
	sx_sunlock(&proctree_lock);

	fasttrap_return_common(tf, pc, pid, new_pc);
	tf->tf_sepc = new_pc;

	return (0);
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
	uint8_t scratch[8];
	uint32_t ebreak = FASTTRAP_INSTR;

	/* ebreak has no operand, so the pc tells the two kinds apart. */
	if (curthread->t_dtrace_on && tf->tf_sepc == curthread->t_dtrace_astpc)
		return (fasttrap_return_probe(tf));

	pc = tf->tf_sepc;
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
			 * been removed from the table since the ebreak was
			 * taken.  Speculate that we hit a tracepoint that has
			 * since been removed, and retry the instruction.
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
				dtrace_probe(probe->ftp_id, tf->tf_a[0],
				    tf->tf_a[1], tf->tf_a[2], tf->tf_a[3],
				    tf->tf_a[4]);
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
				dtrace_probe(probe->ftp_id, tf->tf_a[0],
				    tf->tf_a[1], tf->tf_a[2], tf->tf_a[3],
				    tf->tf_a[4]);
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

	/* An is-enabled site was rewritten by the linker to clear a0. */
	if (is_enabled) {
		tf->tf_a[0] = 1;
		new_pc = pc + tp->ftt_size;
		goto done;
	}

	new_pc = pc + tp->ftt_size;

	switch (tp->ftt_type) {
	case FASTTRAP_T_NOP:
		break;
	case FASTTRAP_T_JAL:
		fasttrap_setreg(tf, tp->ftt_rd, pc + tp->ftt_size);
		new_pc = tp->ftt_dest;
		break;
	case FASTTRAP_T_JALR:
		new_pc = (fasttrap_getreg(tf, tp->ftt_rs1) + tp->ftt_imm) &
		    ~(uintptr_t)1;
		fasttrap_setreg(tf, tp->ftt_rd, pc + tp->ftt_size);
		break;
	case FASTTRAP_T_BRANCH:
		if (fasttrap_branch_taken(tp->ftt_cond,
		    fasttrap_getreg(tf, tp->ftt_rs1),
		    fasttrap_getreg(tf, tp->ftt_rs2)))
			new_pc = tp->ftt_dest;
		break;
	case FASTTRAP_T_AUIPC:
		fasttrap_setreg(tf, tp->ftt_rd, tp->ftt_dest);
		break;
	case FASTTRAP_T_COMMON:
		scrspace = fasttrap_scraddr(curthread, tp->ftt_proc);
		if (scrspace == NULL) {
			/*
			 * We failed to allocate scratch space for this thread.
			 * Try to write the original instruction back out and
			 * reset the pc.
			 */
			if (uwrite(p, &tp->ftt_instr, tp->ftt_size, pc) != 0)
				fasttrap_sigtrap(p, curthread, pc);
			new_pc = pc;
			break;
		}
		memcpy(scratch, &tp->ftt_instr, tp->ftt_size);
		memcpy(scratch + tp->ftt_size, &ebreak, sizeof (ebreak));
		if (uwrite(p, scratch, tp->ftt_size + sizeof (ebreak),
		    scrspace->ftss_addr) != 0) {
			fasttrap_sigtrap(p, curthread, pc);
			new_pc = pc;
			break;
		}
		curthread->t_dtrace_pc = pc;
		curthread->t_dtrace_npc = pc + tp->ftt_size;
		curthread->t_dtrace_scrpc = scrspace->ftss_addr;
		curthread->t_dtrace_astpc = scrspace->ftss_addr + tp->ftt_size;
		curthread->t_dtrace_on = 1;
		tf->tf_sepc = scrspace->ftss_addr;
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

	tf->tf_sepc = new_pc;

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

	if (tf->tf_sepc == td->t_dtrace_scrpc) {
		tf->tf_sepc = td->t_dtrace_pc;
		fasttrap_clear_thread();
	} else if (tf->tf_sepc == td->t_dtrace_astpc) {
		tf->tf_sepc = td->t_dtrace_npc;
		fasttrap_clear_thread();
	}
}
