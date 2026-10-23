/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux/RISC-V LP64D signal frame and register restoration. */

#include <sys/param.h>
#include <sys/imgact.h>
#include <sys/ktr.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/reg.h>
#include <sys/signalvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>

#include <vm/vm_param.h>

#include <machine/frame.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/riscvreg.h>
#include <machine/vector.h>

#include <riscv/linux/linux.h>
#include <riscv/linux/linux_proto.h>
#include <riscv/linux/linux_sigframe.h>
#include <compat/linux/linux.h>
#include <compat/linux/linux_signal.h>
#include <compat/linux/linux_util.h>

extern uintptr_t __user_rt_sigreturn;
void linux_rt_sendsig(sig_t, ksiginfo_t *, sigset_t *);

/* Linux/RISC-V LP64D ucontext offsets are part of the user ABI. */
CTASSERT(sizeof(struct linux_pt_regset) == 256);
CTASSERT(sizeof(struct l_riscv_fp_state) == 272);
CTASSERT(offsetof(struct l_sigcontext, ext.hdr) == 776);
CTASSERT(sizeof(struct l_rt_sigframe) == 1088);
CTASSERT(offsetof(struct l_rt_sigframe, uc.uc_sc.ext.hdr) +
    sizeof(struct l_riscv_ctx_hdr) == sizeof(struct l_rt_sigframe));

static void
linux_regset_from_frame(const struct trapframe *tf,
    struct linux_pt_regset *regs)
{
	regs->pc = tf->tf_sepc;
	regs->ra = tf->tf_ra;
	regs->sp = tf->tf_sp;
	regs->gp = tf->tf_gp;
	regs->tp = tf->tf_tp;
	memcpy(regs->t0, tf->tf_t, sizeof(regs->t0));
	memcpy(regs->s0, tf->tf_s, sizeof(regs->s0));
	memcpy(regs->a, tf->tf_a, sizeof(regs->a));
	memcpy(regs->s2, tf->tf_s + 2, sizeof(regs->s2));
	memcpy(regs->t3, tf->tf_t + 3, sizeof(regs->t3));
}

static void
linux_regset_to_frame(const struct linux_pt_regset *regs,
    struct trapframe *tf)
{
	tf->tf_sepc = regs->pc;
	tf->tf_ra = regs->ra;
	tf->tf_sp = regs->sp;
	tf->tf_gp = regs->gp;
	tf->tf_tp = regs->tp;
	memcpy(tf->tf_t, regs->t0, sizeof(regs->t0));
	memcpy(tf->tf_s, regs->s0, sizeof(regs->s0));
	memcpy(tf->tf_a, regs->a, sizeof(regs->a));
	memcpy(tf->tf_s + 2, regs->s2, sizeof(regs->s2));
	memcpy(tf->tf_t + 3, regs->t3, sizeof(regs->t3));
}

int
linux_rt_sigreturn(struct thread *td, struct linux_rt_sigreturn_args *args)
{
	struct l_riscv_vector_state vs;
	struct l_riscv_ctx_hdr end;
	struct l_rt_sigframe frame;
	struct trapframe *tf;
	struct fpreg fp;
	struct pcb *pcb;
	stack_t ss;
	sigset_t mask;
	void *vstate;
	uintptr_t addr;
	size_t vsize;
	int error, i;

	(void)args;
	tf = td->td_frame;
	addr = tf->tf_sp;
	if (!__is_aligned(addr, 16) ||
	    addr >= td->td_proc->p_sysent->sv_maxuser)
		return (EINVAL);
	error = copyin((const void *)addr, &frame, sizeof(frame));
	if (error != 0)
		return (error);
	if (frame.uc.uc_sc.regs.pc >= td->td_proc->p_sysent->sv_maxuser ||
	    frame.uc.uc_sc.regs.sp >= td->td_proc->p_sysent->sv_maxuser)
		return (EINVAL);
	pcb = td->td_pcb;
	vstate = NULL;
	if (frame.uc.uc_sc.ext.reserved != 0)
		return (EINVAL);
	if (frame.uc.uc_sc.ext.hdr.magic == LINUX_RISCV_V_MAGIC) {
		vsize = vector_get_size();
		if (!has_vector || vsize == 0 ||
		    frame.uc.uc_sc.ext.hdr.size !=
		    sizeof(struct l_riscv_ctx_hdr) + sizeof(vs) + vsize)
			return (EINVAL);
		error = copyin((const void *)(addr + sizeof(frame)), &vs,
		    sizeof(vs));
		if (error != 0 || vs.vlenb != vsize / 32)
			return (EINVAL);
		error = copyin((const void *)(addr + sizeof(frame) + sizeof(vs) +
		    vsize), &end, sizeof(end));
		if (error != 0 || end.magic != 0 || end.size != 0)
			return (EINVAL);
		vstate = malloc(vsize, M_LINUX, M_WAITOK);
		error = copyin((const void *)(uintptr_t)vs.datap, vstate,
		    vsize);
		if (error != 0) {
			free(vstate, M_LINUX);
			return (error);
		}
	} else if (frame.uc.uc_sc.ext.hdr.magic != 0 ||
	    frame.uc.uc_sc.ext.hdr.size != 0)
		return (EINVAL);
	if ((frame.uc.uc_stack.ss_flags &
	    ~(LINUX_SS_ONSTACK | LINUX_SS_DISABLE)) != 0 ||
	    (frame.uc.uc_stack.ss_flags &
	    (LINUX_SS_ONSTACK | LINUX_SS_DISABLE)) ==
	    (LINUX_SS_ONSTACK | LINUX_SS_DISABLE)) {
		free(vstate, M_LINUX);
		return (EINVAL);
	}
	if (vstate != NULL) {
		if (pcb->pcb_vsaved == NULL)
			vector_state_init(td);
		memcpy(pcb->pcb_vsaved, vstate, vsize);
		free(vstate, M_LINUX);
		pcb->pcb_vstart = vs.vstart;
		pcb->pcb_vl = vs.vl;
		pcb->pcb_vtype = vs.vtype;
		pcb->pcb_vcsr = vs.vcsr;
		pcb->pcb_vsflags |= PCB_VS_STARTED;
		tf->tf_sstatus = (tf->tf_sstatus & ~SSTATUS_VS_MASK) |
		    SSTATUS_VS_CLEAN;
	}

	memset(&fp, 0, sizeof(fp));
	for (i = 0; i < 32; i++)
		fp.fp_x[i][0] = frame.uc.uc_sc.fp.f[i];
	fp.fp_fcsr = frame.uc.uc_sc.fp.fcsr;
	set_fpregs(td, &fp);
	linux_regset_to_frame(&frame.uc.uc_sc.regs, tf);
	ss.ss_sp = PTRIN(frame.uc.uc_stack.ss_sp);
	ss.ss_size = frame.uc.uc_stack.ss_size;
	ss.ss_flags = linux_to_bsd_sigaltstack(frame.uc.uc_stack.ss_flags);
	if (sigonstack(tf->tf_sp)) {
		if (ss.ss_sp != td->td_sigstk.ss_sp ||
		    ss.ss_size != td->td_sigstk.ss_size ||
		    (td->td_pflags & TDP_ALTSTACK) == 0)
			return (EINVAL);
	} else {
		error = kern_sigaltstack(td, &ss, NULL);
		if (error != 0)
			return (error);
	}
	linux_to_bsd_sigset(&frame.uc.uc_sigmask, &mask);
	kern_sigprocmask(td, SIG_SETMASK, &mask, NULL, 0);
	return (EJUSTRETURN);
}

void
linux_rt_sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct l_riscv_vector_state *vs;
	struct l_riscv_ctx_hdr *end;
	struct l_rt_sigframe *frame;
	struct trapframe *tf;
	struct sigacts *psp;
	struct thread *td;
	struct fpreg fpreg;
	struct pcb *pcb;
	struct proc *p;
	uintptr_t addr;
	size_t vsize, framesz;
	int i, sig, onstack;

	td = curthread;
	p = td->td_proc;
	PROC_LOCK_ASSERT(p, MA_OWNED);
	psp = p->p_sigacts;
	mtx_assert(&psp->ps_mtx, MA_OWNED);
	tf = td->td_frame;
	pcb = td->td_pcb;
	sig = ksi->ksi_signo;
	onstack = sigonstack(tf->tf_sp);
	vsize = pcb->pcb_vsaved == NULL ? 0 : vector_get_size();
	framesz = sizeof(*frame) +
	    (vsize == 0 ? 0 : sizeof(*vs) + vsize + sizeof(*end));
	if ((td->td_pflags & TDP_ALTSTACK) != 0 && !onstack &&
	    SIGISMEMBER(psp->ps_sigonstack, sig))
		addr = (uintptr_t)td->td_sigstk.ss_sp + td->td_sigstk.ss_size;
	else
		addr = tf->tf_sp;
	addr = (addr - framesz) & ~(uintptr_t)15;
	frame = malloc(framesz, M_LINUX, M_NOWAIT | M_ZERO);
	if (frame == NULL) {
		mtx_unlock(&psp->ps_mtx);
		sigexit(td, SIGILL);
	}
	linux_regset_from_frame(tf, &frame->uc.uc_sc.regs);
	fill_fpregs(td, &fpreg);
	for (i = 0; i < 32; i++)
		frame->uc.uc_sc.fp.f[i] = fpreg.fp_x[i][0];
	frame->uc.uc_sc.fp.fcsr = fpreg.fp_fcsr;
	if (vsize != 0) {
		vector_state_store(td);
		frame->uc.uc_sc.ext.hdr.magic = LINUX_RISCV_V_MAGIC;
		frame->uc.uc_sc.ext.hdr.size = sizeof(*end) + sizeof(*vs) +
		    vsize;
		vs = (struct l_riscv_vector_state *)(frame + 1);
		vs->vstart = pcb->pcb_vstart;
		vs->vl = pcb->pcb_vl;
		vs->vtype = pcb->pcb_vtype;
		vs->vcsr = pcb->pcb_vcsr;
		vs->vlenb = vsize / 32;
		vs->datap = addr + sizeof(*frame) + sizeof(*vs);
		memcpy(vs + 1, pcb->pcb_vsaved, vsize);
		end = (struct l_riscv_ctx_hdr *)((char *)(vs + 1) + vsize);
		end->magic = end->size = 0;
	}
	sig = bsd_to_linux_signal(sig);
	siginfo_to_lsiginfo(&ksi->ksi_info, &frame->info, sig);
	bsd_to_linux_sigset(mask, &frame->uc.uc_sigmask);
	frame->uc.uc_stack.ss_sp = PTROUT(td->td_sigstk.ss_sp);
	frame->uc.uc_stack.ss_size = td->td_sigstk.ss_size;
	frame->uc.uc_stack.ss_flags = (td->td_pflags & TDP_ALTSTACK) != 0 ?
	    (onstack ? LINUX_SS_ONSTACK : 0) : LINUX_SS_DISABLE;
	mtx_unlock(&psp->ps_mtx);
	PROC_UNLOCK(p);
	if (copyout(frame, (void *)addr, framesz) != 0) {
		free(frame, M_LINUX);
		PROC_LOCK(p);
		sigexit(td, SIGILL);
	}
	free(frame, M_LINUX);
	tf->tf_a[0] = sig;
	tf->tf_a[1] = addr + offsetof(struct l_rt_sigframe, info);
	tf->tf_a[2] = addr + offsetof(struct l_rt_sigframe, uc);
	tf->tf_sepc = (uintptr_t)catcher;
	tf->tf_sp = addr;
	tf->tf_ra = __user_rt_sigreturn;
	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
}
