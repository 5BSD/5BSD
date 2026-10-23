/* SPDX-License-Identifier: BSD-2-Clause */

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/reg.h>
#include <sys/sysent.h>

#include <vm/vm_param.h>

#include <riscv/linux/linux.h>
#include <riscv/linux/linux_proto.h>
#include <compat/linux/linux_fork.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_util.h>

#define LINUX_ARCH_RISCV64 0xc00000f3

int
linux_set_upcall(struct thread *td, register_t stack)
{
	if (stack != 0)
		td->td_frame->tf_sp = stack;
	td->td_frame->tf_a[0] = 0;
	return (0);
}

int
linux_set_cloned_tls(struct thread *td, void *desc)
{
	if ((uintptr_t)desc >= td->td_proc->p_sysent->sv_maxuser)
		return (EPERM);
	/* Linux's tp is the supplied value, without FreeBSD's TP_OFFSET. */
	td->td_frame->tf_tp = (uintptr_t)desc;
	return (0);
}

void
bsd_to_linux_regset(const struct reg *b, struct linux_pt_regset *l)
{
	l->pc = b->sepc;
	l->ra = b->ra;
	l->sp = b->sp;
	l->gp = b->gp;
	l->tp = b->tp;
	memcpy(l->t0, b->t, sizeof(l->t0));
	memcpy(l->s0, b->s, sizeof(l->s0));
	memcpy(l->a, b->a, sizeof(l->a));
	memcpy(l->s2, b->s + 2, sizeof(l->s2));
	memcpy(l->t3, b->t + 3, sizeof(l->t3));
}

void
linux_to_bsd_regset(struct reg *b, const struct linux_pt_regset *l)
{
	b->sepc = l->pc;
	b->ra = l->ra;
	b->sp = l->sp;
	b->gp = l->gp;
	b->tp = l->tp;
	memcpy(b->t, l->t0, sizeof(l->t0));
	memcpy(b->s, l->s0, sizeof(l->s0));
	memcpy(b->a, l->a, sizeof(l->a));
	memcpy(b->s + 2, l->s2, sizeof(l->s2));
	memcpy(b->t + 3, l->t3, sizeof(l->t3));
	/* User mode status bits remain controlled by the native ptrace path. */
	b->sstatus = 0;
}

void
linux_ptrace_get_syscall_info_machdep(const struct reg *reg,
    struct syscall_info *si)
{
	si->arch = LINUX_ARCH_RISCV64;
	si->instruction_pointer = reg->sepc;
	si->stack_pointer = reg->sp;
}

int
linux_ptrace_getregs_machdep(struct thread *td __unused, pid_t pid __unused,
    struct linux_pt_regset *regs __unused)
{
	return (0);
}

int
linux_ptrace_peekuser(struct thread *td __unused, pid_t pid __unused,
    void *addr __unused, void *data __unused)
{
	return (EINVAL);
}

int
linux_ptrace_pokeuser(struct thread *td __unused, pid_t pid __unused,
    void *addr __unused, void *data __unused)
{
	return (EINVAL);
}
