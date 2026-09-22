/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/signalvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/uio.h>

#include <machine/cpufunc.h>
#include <machine/fpu.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/psl.h>
#include <machine/reg.h>
#include <machine/segments.h>
#include <machine/specialreg.h>
#include <machine/tss.h>

#include <amd64/linux/linux.h>
#include <amd64/linux/linux_proto.h>

#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_util.h>

#define L_PEEKUSER   3
#define L_POKEUSER   6
#define L_ARCH_PRCTL 30
#define L_GETREGS    12
#define L_SETREGS    13
#define L_GETFPREGS  14
#define L_SETFPREGS  15
#define L_GETREGSET  0x4204
#define L_SETREGSET  0x4205
#define L_PRSTATUS   1
#define L_PRFPREG    2
#define L_XSTATE     0x202
#define L_IOPERM     0x201
#define L_RSEQ_CONF  0x420f

#define L_GETSIGMASK 0x420a
#define L_SETSIGMASK 0x420b

struct linux_register_io {
	struct linux_ptrace_args *args;
	void *buffer;
	bool entered;
};

/* P2_PTRACEREQ remains held while user memory is accessed. */
static int
linux_regcopy(struct thread *target, void *user, void *buf, size_t len,
    bool writing)
{
	int error;

	PROC_UNLOCK(target->td_proc);
	error = writing ? copyin(user, buf, len) : copyout(buf, user, len);
	PROC_LOCK(target->td_proc);
	return (error);
}

static void
linux_read_gpr(struct thread *target, struct linux_pt_regset *lr,
    struct reg *br)
{
	proc_read_regs(target, br);
	bsd_to_linux_regset(br, lr);
	/* Linux debuggers use the Linux selectors to identify 64-bit mode. */
	if (br->r_cs == _ucodesel)
		lr->cs = 0x33;
	if (br->r_ss == _udatasel)
		lr->ss = 0x2b;
	lr->fs_base = target->td_pcb->pcb_fsbase;
	lr->gs_base = target->td_pcb->pcb_gsbase;
	lr->orig_rax = (target->td_dbgflags & (TDB_SCE | TDB_SCX)) != 0 ?
	    target->td_sa.code :
	    (l_ulong)-1;
}

static int
linux_write_gpr(struct thread *target, struct linux_pt_regset *lr,
    struct reg *br)
{
	struct pcb *pcb;
	register_t oldflags;
	int error;

	lr->cs = (uint16_t)lr->cs;
	lr->ss = (uint16_t)lr->ss;
	lr->ds = (uint16_t)lr->ds;
	lr->es = (uint16_t)lr->es;
	lr->fs = (uint16_t)lr->fs;
	lr->gs = (uint16_t)lr->gs;
	/* Linux permits only user selectors and user FS/GS bases. */
	if (lr->fs_base >= target->td_proc->p_sysent->sv_maxuser ||
	    lr->gs_base >= target->td_proc->p_sysent->sv_maxuser ||
	    (lr->cs & 3) != 3 || (lr->ss & 3) != 3 ||
	    (lr->ds != 0 && (lr->ds & 3) != 3) ||
	    (lr->es != 0 && (lr->es & 3) != 3) ||
	    (lr->fs != 0 && (lr->fs & 3) != 3) ||
	    (lr->gs != 0 && (lr->gs & 3) != 3))
		return (EIO);
	oldflags = br->r_rflags;
	linux_to_bsd_regset(br, lr);
	if (lr->cs == 0x33)
		br->r_cs = _ucodesel;
	if (lr->ss == 0x2b)
		br->r_ss = _udatasel;
	/* Linux ignores writes to privileged/reserved EFLAGS bits. */
	br->r_rflags = (oldflags & ~0x54dd5UL) | (lr->eflags & 0x54dd5UL);
	br->r_rax = lr->rax;
	/* Linux changes the syscall to execute through orig_rax. */
	if ((target->td_dbgflags & TDB_SCE) != 0)
		br->r_rax = lr->orig_rax;
	error = proc_write_regs(target, br);
	if (error != 0)
		return (error);
	pcb = target->td_pcb;
	pcb->pcb_fsbase = lr->fs_base;
	pcb->pcb_gsbase = lr->gs_base;
	target->td_frame->tf_ds = lr->ds;
	target->td_frame->tf_es = lr->es;
	target->td_frame->tf_fs = lr->fs;
	target->td_frame->tf_gs = lr->gs;
	target->td_frame->tf_flags |= TF_HASSEGS;
	set_pcb_flags(pcb, PCB_FULL_IRET);
	if ((target->td_dbgflags & (TDB_SCE | TDB_SCX)) != 0)
		target->td_sa.code = lr->orig_rax;
	target->td_dbgflags |= TDB_USERWR;
	return (0);
}

static int
linux_write_debugreg(struct thread *target, struct dbreg *dr, unsigned int n,
    uint64_t value)
{
	struct linux_emuldata *em = em_find(target);
	static const unsigned int lengths[] = { 1, 2, 8, 4 };
	uint64_t control, address;
	unsigned int i, type, len;
	int error;

	if (n == 4 || n == 5)
		return (EIO);
	if (n < 4 && value >= target->td_proc->p_sysent->sv_maxuser)
		return (EINVAL);
	if (n < 4)
		dr->dr[n] = value;
	if (!em->ptrace_dr6_set &&
	    (target->td_pcb->pcb_flags & PCB_DBREGS) == 0)
		dr->dr[6] = 0xffff0ff0;
	if (n == 6)
		dr->dr[6] = (uint32_t)value;
	control = n == 7 ? value : em->ptrace_dr7;
	/* Only enable validated user watchpoints in the physical DR7. */
	dr->dr[7] = 0;
	for (i = 0; i < 4; i++) {
		if (((control >> (i * 2)) & 3) == 0)
			continue;
		type = (control >> (16 + i * 4)) & 3;
		len = lengths[(control >> (18 + i * 4)) & 3];
		address = dr->dr[i];
		if (type == 2 || (type == 0 && len != 1) ||
		    (address & (len - 1)) != 0 ||
		    address >= target->td_proc->p_sysent->sv_maxuser ||
		    len > target->td_proc->p_sysent->sv_maxuser - address)
			return (EINVAL);
		dr->dr[7] |= control &
		    ((3ULL << (i * 2)) | (15ULL << (16 + i * 4)));
	}
	error = proc_write_dbregs(target, dr);
	if (error != 0)
		return (error);
	if (n == 6) {
		em->ptrace_dr6_high = value & ~0xffffffffULL;
		em->ptrace_dr6_set = true;
	}
	if (n == 7)
		em->ptrace_dr7 = value;
	target->td_dbgflags |= TDB_USERWR;
	return (0);
}

/* Linux64 struct user has 848 bytes before its eight debug registers. */
static int
linux_user_access(struct thread *target, struct linux_ptrace_args *a)
{
	struct linux_pt_regset lr;
	struct reg br;
	struct dbreg dr;
	struct linux_emuldata *em;
	uint64_t value;
	unsigned int n;
	int error;

	if ((a->addr & 7) != 0 || a->addr >= 928)
		return (EIO);
	if (a->addr < sizeof(lr)) {
		linux_read_gpr(target, &lr, &br);
		if (a->req == L_POKEUSER) {
			memcpy((char *)&lr + a->addr, &a->data, 8);
			return (linux_write_gpr(target, &lr, &br));
		}
		memcpy(&value, (char *)&lr + a->addr, 8);
	} else if (a->addr >= 848 && a->addr <= 904) {
		n = (a->addr - 848) / 8;
		error = proc_read_dbregs(target, &dr);
		if (error != 0)
			return (error);
		if (a->req == L_POKEUSER)
			return (linux_write_debugreg(target, &dr, n, a->data));
		em = em_find(target);
		value = dr.dr[n];
		if (n == 7)
			value = em->ptrace_dr7;
		if (n == 6)
			value |= em->ptrace_dr6_high;
		if (n == 6 && (target->td_pcb->pcb_flags & PCB_DBREGS) == 0)
			value = 0xffff0ff0;
	} else {
		if (a->req == L_POKEUSER)
			return (EIO);
		value = 0;
	}
	return (linux_regcopy(target, (void *)a->data, &value, 8, false));
}

static int
linux_ptrace_arch_prctl(struct thread *target, struct linux_ptrace_args *a)
{
	struct linux_pt_regset lr;
	struct reg br;
	uint64_t value;

	linux_read_gpr(target, &lr, &br);
	switch (a->data) {
	case LINUX_ARCH_GET_FS:
	case LINUX_ARCH_GET_GS:
		value = a->data == LINUX_ARCH_GET_FS ? lr.fs_base : lr.gs_base;
		return (
		    linux_regcopy(target, (void *)a->addr, &value, 8, false));
	case LINUX_ARCH_SET_FS:
	case LINUX_ARCH_SET_GS:
		if (a->addr >= target->td_proc->p_sysent->sv_maxuser)
			return (EPERM);
		if (a->data == LINUX_ARCH_SET_FS)
			lr.fs_base = a->addr;
		else
			lr.gs_base = a->addr;
		return (linux_write_gpr(target, &lr, &br));
	default:
		return (EINVAL);
	}
}

static int
linux_register_access(struct thread *target, void *arg)
{
	struct linux_register_io *io = arg;
	struct linux_ptrace_args *a = io->args;
	struct linux_pt_regset lr;
	struct fpreg *fp = io->buffer;
	struct reg br;
	struct iovec iov;
	l_sigset_t lmask;
	sigset_t mask;
	struct linux_emuldata *em;
	struct {
		uint64_t pointer;
		uint32_t size, signature, flags, pad;
	} conf;
	struct envxmm *env;
	uint64_t *words;
	char *source;
	size_t size, len, off;
	unsigned int cpuid[4], i;
	int error, note;
	bool writing, regset;

	io->entered = true;
	if (SV_PROC_ABI(target->td_proc) != SV_ABI_LINUX ||
	    SV_PROC_FLAG(target->td_proc, SV_ILP32))
		return (EIO);
	if (a->req == L_GETSIGMASK || a->req == L_SETSIGMASK) {
		if (a->addr != sizeof(lmask))
			return (EINVAL);
		if (a->req == L_GETSIGMASK) {
			mask = (target->td_pflags & TDP_OLDMASK) != 0 ?
			    target->td_oldsigmask :
			    target->td_sigmask;
			bsd_to_linux_sigset(&mask, &lmask);
			return (linux_regcopy(target, (void *)a->data, &lmask,
			    sizeof(lmask), false));
		}
		error = linux_regcopy(target, (void *)a->data, &lmask,
		    sizeof(lmask), true);
		if (error != 0)
			return (error);
		linux_to_bsd_sigset(&lmask, &mask);
		error = kern_sigprocmask(target, SIG_SETMASK, &mask, NULL,
		    SIGPROCMASK_PROC_LOCKED);
		if (error == 0)
			target->td_pflags &= ~TDP_OLDMASK;
		return (error);
	}
	if (a->req == L_RSEQ_CONF) {
		em = em_find(target);
		memset(&conf, 0, sizeof(conf));
		conf.pointer = em->rseq_addr;
		conf.size = em->rseq_len;
		conf.signature = em->rseq_sig;
		error = linux_regcopy(target, (void *)a->data, &conf,
		    MIN(a->addr, sizeof(conf)), false);
		if (error == 0)
			curthread->td_retval[0] = sizeof(conf);
		return (error);
	}
	if (a->req == L_PEEKUSER || a->req == L_POKEUSER)
		return (linux_user_access(target, a));
	if (a->req == L_ARCH_PRCTL)
		return (linux_ptrace_arch_prctl(target, a));
	regset = a->req == L_GETREGSET || a->req == L_SETREGSET;
	writing = a->req == L_SETREGS || a->req == L_SETFPREGS ||
	    a->req == L_SETREGSET;
	note = regset ?
	    a->addr :
	    (a->req == L_GETREGS || a->req == L_SETREGS ? L_PRSTATUS :
							  L_PRFPREG);
	if (regset) {
		error = linux_regcopy(target, (void *)a->data, &iov,
		    sizeof(iov), true);
		if (error != 0)
			return (error);
	} else {
		iov.iov_base = (void *)a->data;
		iov.iov_len = note == L_PRSTATUS ? sizeof(lr) : sizeof(*fp);
	}
	if (note != L_PRSTATUS && note != L_PRFPREG && note != L_XSTATE &&
	    note != L_IOPERM)
		return (EINVAL);
	if ((note == L_XSTATE || note == L_IOPERM) && writing)
		return (EINVAL);
	if (note == L_XSTATE && !use_xsave)
		return (ENODEV);
	if (note == L_IOPERM) {
		if (target->td_pcb->pcb_tssp == NULL)
			return (ENXIO);
		source = (char *)&target->td_pcb->pcb_tssp[1];
		for (i = 0; i < IOPAGES * PAGE_SIZE; i++)
			if ((unsigned char)source[i] != 0xff)
				break;
		if (i == IOPAGES * PAGE_SIZE)
			return (ENXIO);
	}
	size = note == L_IOPERM ? IOPAGES * PAGE_SIZE :
	    note == L_PRSTATUS	? sizeof(lr) :
	    note == L_PRFPREG	? sizeof(*fp) :
				  cpu_max_ext_state_size;
	if (iov.iov_len % 8 != 0)
		return (EINVAL);
	len = MIN(iov.iov_len, size);
	if (writing && note == L_PRFPREG && len != sizeof(*fp))
		return (EINVAL);
	if (note == L_IOPERM) {
		memcpy(io->buffer, &target->td_pcb->pcb_tssp[1], len);
		error = linux_regcopy(target, iov.iov_base, io->buffer, len,
		    false);
	} else if (note == L_PRSTATUS) {
		linux_read_gpr(target, &lr, &br);
		if (!writing) {
			error = linux_regcopy(target, iov.iov_base, &lr, len,
			    false);
		} else {
			/* Linux commits each GPR word before fetching the next.
			 */
			error = 0;
			for (off = 0; off < len; off += sizeof(l_ulong)) {
				error = linux_regcopy(target,
				    (char *)iov.iov_base + off,
				    (char *)&lr + off, sizeof(l_ulong), true);
				if (error != 0)
					break;
				error = linux_write_gpr(target, &lr, &br);
				if (error != 0)
					break;
			}
		}
	} else {
		error = proc_read_fpregs(target, fp);
		if (error != 0)
			return (error);
		if (note == L_XSTATE) {
			/* Rebuild a standard XSAVE image without reserved
			 * bytes. */
			source = (char *)get_pcb_user_save_td(target);
			words = io->buffer;
			words[X86_XSTATE_XCR0_OFFSET / 8] = xsave_mask;
			words[512 / 8] = *(uint64_t *)(source + 512) &
			    xsave_mask;
			for (i = 2; i < 63; i++) {
				if ((xsave_mask & (1ULL << i)) == 0)
					continue;
				cpuid_count(0xd, i, cpuid);
				if (cpuid[1] <= size &&
				    cpuid[0] <= size - cpuid[1])
					memcpy((char *)io->buffer + cpuid[1],
					    source + cpuid[1], cpuid[0]);
			}
		}
		error = linux_regcopy(target, iov.iov_base, io->buffer, len,
		    writing);
		if (error == 0 && writing && len != 0) {
			env = (struct envxmm *)fp;
			if ((env->en_mxcsr & ~cpu_mxcsr_mask) != 0)
				return (EINVAL);
			error = proc_write_fpregs(target, fp);
			if (error == 0)
				target->td_dbgflags |= TDB_USERWR;
		}
	}
	if (error == 0 && regset) {
		iov.iov_len = len;
		error = linux_regcopy(target, (void *)a->data, &iov,
		    sizeof(iov), false);
	}
	return (error);
}

int
linux_ptrace_registers(struct thread *td, struct linux_ptrace_args *args)
{
	struct linux_register_io io;
	struct ptrace_kern_access access;
	int error;

	CTASSERT(sizeof(struct fpreg) == 512);
	CTASSERT(sizeof(struct linux_pt_regset) == 216);
	io.args = args;
	io.entered = false;
	io.buffer = malloc(MAX(IOPAGES * PAGE_SIZE, cpu_max_ext_state_size),
	    M_TEMP, M_WAITOK | M_ZERO);
	access.access = linux_register_access;
	access.arg = &io;
	error = kern_ptrace(td, PT_KERN_ACCESS, (pid_t)args->pid, &access, 0);
	free(io.buffer, M_TEMP);
	return (
	    error == EBUSY || (error == EPERM && !io.entered) ? ESRCH : error);
}
