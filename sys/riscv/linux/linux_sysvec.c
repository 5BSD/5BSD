/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1994-1996 Søren Schmidt
 * Copyright (c) 2018 Turing Robotic Industries Inc.
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

#define	__ELF_WORD_SIZE	64

#include <sys/param.h>
#include <sys/elf.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/stddef.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

#include <riscv/linux/linux.h>
#include <riscv/linux/linux_proto.h>
#include <compat/linux/linux_elf.h>
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_fork.h>
#include <compat/linux/linux_ioctl.h>
#include <compat/linux/linux_mib.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_signal.h>
#include <compat/linux/linux_util.h>
#include <compat/linux/linux_vdso.h>

#include <riscv/linux/linux_sigframe.h>

#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/pmap.h>
#include <machine/riscvreg.h>
#include <machine/vector.h>

MODULE_VERSION(linux64elf, 1);

static u_long linux_elf_hwcap_zero;

#define	LINUX_VDSOPAGE_SIZE	PAGE_SIZE * 2

static int linux_szsigcode;
static vm_object_t linux_vdso_obj;
static char *linux_vdso_mapping;
extern char _binary_linux_vdso_so_o_start;
extern char _binary_linux_vdso_so_o_end;
static vm_offset_t linux_vdso_base;

extern struct sysent linux_sysent[LINUX_SYS_MAXSYSCALL];
extern const char *linux_syscallnames[];

SET_DECLARE(linux_ioctl_handler_set, struct linux_ioctl_handler);

static void	linux_vdso_install(const void *param);
static void	linux_vdso_deinstall(const void *param);
static void	linux_vdso_reloc(char *mapping, Elf_Addr offset);
static void	linux_set_syscall_retval(struct thread *td, int error);
static int	linux_fetch_syscall_args(struct thread *td);
static void	linux_exec_setregs(struct thread *td, struct image_params *imgp,
		    uintptr_t stack);
static void	linux_exec_sysvec_init(void *param);
static int	linux_on_exec_vmspace(struct proc *p,
		    struct image_params *imgp);

LINUX_VDSO_SYM_CHAR(linux_platform);
LINUX_VDSO_SYM_INTPTR(kern_timekeep_base);
LINUX_VDSO_SYM_INTPTR(__user_rt_sigreturn);

static int
linux_fetch_syscall_args(struct thread *td)
{
	struct proc *p;
	struct syscall_args *sa;
	register_t *ap;

	p = td->td_proc;
	ap = td->td_frame->tf_a;
	sa = &td->td_sa;

	sa->code = td->td_frame->tf_a[7];
	sa->original_code = sa->code;

	if (sa->code >= p->p_sysent->sv_size)
		sa->callp = &nosys_sysent;
	else
		sa->callp = &p->p_sysent->sv_table[sa->code];

	KASSERT(sa->callp->sy_narg <= nitems(sa->args),
	    ("Linux RISC-V syscall %d has too many arguments", sa->code));
	memcpy(sa->args, ap, nitems(sa->args) * sizeof(register_t));

	td->td_retval[0] = 0;
	return (0);
}

static void
linux_set_syscall_retval(struct thread *td, int error)
{

	if (error == 0)
		td->td_frame->tf_a[0] = td->td_retval[0];
	else if (error == ERESTART)
		td->td_frame->tf_sepc -= 4;
	else if (error != EJUSTRETURN)
		td->td_frame->tf_a[0] = bsd_to_linux_errno(error);
}

void
linux64_arch_copyout_auxargs(struct image_params *imgp, Elf_Auxinfo **pos)
{

	AUXARGS_ENTRY((*pos), LINUX_AT_SYSINFO_EHDR, linux_vdso_base);
	AUXARGS_ENTRY((*pos), LINUX_AT_HWCAP, *imgp->sysent->sv_hwcap);
	AUXARGS_ENTRY((*pos), LINUX_AT_HWCAP2, *imgp->sysent->sv_hwcap2);
	AUXARGS_ENTRY((*pos), LINUX_AT_HWCAP3, *imgp->sysent->sv_hwcap3);
	AUXARGS_ENTRY((*pos), LINUX_AT_HWCAP4, *imgp->sysent->sv_hwcap4);
	AUXARGS_ENTRY((*pos), LINUX_AT_PLATFORM, PTROUT(linux_platform));
}

/*
 * Reset registers to default values on exec.
 */
static void
linux_exec_setregs(struct thread *td, struct image_params *imgp,
    uintptr_t stack)
{
	struct trapframe *regs = td->td_frame;
	struct pcb *pcb = td->td_pcb;

	memset(regs, 0, sizeof(*regs));
	/* A static Linux _start receives a null rtld_fini in a0. */
	regs->tf_a[0] = 0;
	regs->tf_sp = STACKALIGN(stack);
	regs->tf_sepc = imgp->entry_addr;
	regs->tf_ra = imgp->entry_addr;
	pcb->pcb_fpflags &= ~PCB_FP_STARTED;
}

extern void linux_rt_sendsig(sig_t, ksiginfo_t *, sigset_t *);

struct sysentvec elf_linux_sysvec = {
	.sv_size	= LINUX_SYS_MAXSYSCALL,
	.sv_table	= linux_sysent,
	.sv_fixup	= __elfN(freebsd_fixup),
	.sv_sendsig	= linux_rt_sendsig,
	.sv_sigcode	= &_binary_linux_vdso_so_o_start,
	.sv_szsigcode	= &linux_szsigcode,
	.sv_name	= "Linux ELF64",
	.sv_coredump	= elf64_coredump,
	.sv_elf_core_osabi = ELFOSABI_NONE,
	.sv_elf_core_abi_vendor = LINUX_ABI_VENDOR,
	.sv_elf_core_prepare_notes = linux64_prepare_notes,
	.sv_minsigstksz	= LINUX_MINSIGSTKSZ,
	.sv_minuser	= VM_MIN_ADDRESS,
	.sv_maxuser	= 0,	/* Filled in for the active pmap mode. */
	.sv_usrstack	= 0,
	.sv_psstrings	= 0,
	.sv_psstringssz	= sizeof(struct ps_strings),
	.sv_stackprot	= VM_PROT_READ | VM_PROT_WRITE,
	.sv_copyout_auxargs = __linuxN(copyout_auxargs),
	.sv_copyout_strings = __linuxN(copyout_strings),
	.sv_setregs	= linux_exec_setregs,
	.sv_fixlimit	= NULL,
	.sv_maxssiz	= NULL,
	.sv_flags	= SV_ABI_LINUX | SV_LP64 | SV_SHP | SV_SIG_DISCIGN |
	    SV_SIG_WAITNDQ | SV_TIMEKEEP,
	.sv_set_syscall_retval = linux_set_syscall_retval,
	.sv_fetch_syscall_args = linux_fetch_syscall_args,
	.sv_syscallnames = linux_syscallnames,
	.sv_shared_page_base = 0,
	.sv_shared_page_len = PAGE_SIZE,
	.sv_schedtail	= linux_schedtail,
	.sv_thread_detach = linux_thread_detach,
	.sv_trap	= NULL,
	.sv_hwcap	= &elf_hwcap,
	.sv_hwcap2	= &linux_elf_hwcap_zero,
	.sv_hwcap3	= &linux_elf_hwcap_zero,
	.sv_hwcap4	= &linux_elf_hwcap_zero,
	.sv_onexec	= linux_on_exec_vmspace,
	.sv_onexit	= linux_on_exit,
	.sv_ontdexit	= linux_thread_dtor,
	.sv_setid_allowed = &linux_setid_allowed_query,
};

static int
linux_on_exec_vmspace(struct proc *p, struct image_params *imgp)
{
	int error;

	error = linux_map_vdso(p, linux_vdso_obj, linux_vdso_base,
	    LINUX_VDSOPAGE_SIZE, imgp);
	if (error == 0)
		error = linux_on_exec(p, imgp);
	return (error);
}

/*
 * linux_vdso_install() and linux_exec_sysvec_init() must be called
 * after exec_sysvec_init() which is SI_SUB_EXEC (SI_ORDER_ANY).
 */
static void
linux_exec_sysvec_init(void *param)
{
	l_uintptr_t *ktimekeep_base;
	struct sysentvec *sv;
	ptrdiff_t tkoff;

	sv = param;
	if (has_vector)
		sv->sv_minsigstksz += sizeof(struct l_riscv_vector_state) +
		    vector_get_size() + sizeof(struct l_riscv_ctx_hdr);
	/* Fill timekeep_base */
	exec_sysvec_init(sv);

	tkoff = kern_timekeep_base - linux_vdso_base;
	ktimekeep_base = (l_uintptr_t *)(linux_vdso_mapping + tkoff);
	*ktimekeep_base = sv->sv_shared_page_base + sv->sv_timekeep_offset;
}
SYSINIT(elf_linux_exec_sysvec_init, SI_SUB_EXEC + 1, SI_ORDER_ANY,
    linux_exec_sysvec_init, &elf_linux_sysvec);

static void
linux_vdso_install(const void *param)
{
	char *vdso_start = &_binary_linux_vdso_so_o_start;
	char *vdso_end = &_binary_linux_vdso_so_o_end;
	vm_offset_t maxuser;

	linux_szsigcode = vdso_end - vdso_start;
	MPASS(linux_szsigcode <= LINUX_VDSOPAGE_SIZE);

	maxuser = pmap_mode == PMAP_MODE_SV39 ?
	    VM_MAX_USER_ADDRESS_SV39 : VM_MAX_USER_ADDRESS_SV48;
	linux_vdso_base = maxuser - LINUX_VDSOPAGE_SIZE;
	elf_linux_sysvec.sv_maxuser = maxuser;
	elf_linux_sysvec.sv_shared_page_base = linux_vdso_base - PAGE_SIZE;
	elf_linux_sysvec.sv_usrstack = elf_linux_sysvec.sv_shared_page_base;
	elf_linux_sysvec.sv_psstrings = elf_linux_sysvec.sv_usrstack -
	    sizeof(struct ps_strings);

	__elfN(linux_vdso_fixup)(vdso_start, linux_vdso_base);

	linux_vdso_obj = __elfN(linux_shared_page_init)
	    (&linux_vdso_mapping, LINUX_VDSOPAGE_SIZE);
	bcopy(vdso_start, linux_vdso_mapping, linux_szsigcode);

	linux_vdso_reloc(linux_vdso_mapping, linux_vdso_base);
}
SYSINIT(elf_linux_vdso_init, SI_SUB_EXEC + 1, SI_ORDER_FIRST,
    linux_vdso_install, NULL);

static void
linux_vdso_deinstall(const void *param)
{

	__elfN(linux_shared_page_fini)(linux_vdso_obj,
	    linux_vdso_mapping, LINUX_VDSOPAGE_SIZE);
}
SYSUNINIT(elf_linux_vdso_uninit, SI_SUB_EXEC, SI_ORDER_FIRST,
    linux_vdso_deinstall, NULL);

static void
linux_vdso_reloc(char *mapping, Elf_Addr offset)
{
	Elf_Size rtype, symidx;
	const Elf_Rela *rela;
	const Elf_Shdr *shdr;
	const Elf_Ehdr *ehdr;
	Elf_Addr *where;
	Elf_Addr addr, addend;
	int i, relacnt;

	MPASS(offset != 0);

	relacnt = 0;
	ehdr = (const Elf_Ehdr *)mapping;
	shdr = (const Elf_Shdr *)(mapping + ehdr->e_shoff);
	for (i = 0; i < ehdr->e_shnum; i++)
	{
		switch (shdr[i].sh_type) {
		case SHT_REL:
			printf("Linux RISC-V vDSO: unexpected Rel section\n");
			break;
		case SHT_RELA:
			rela = (const Elf_Rela *)(mapping + shdr[i].sh_offset);
			relacnt = shdr[i].sh_size / sizeof(*rela);
		}
	}

	for (i = 0; i < relacnt; i++, rela++) {
		where = (Elf_Addr *)(mapping + rela->r_offset);
		addend = rela->r_addend;
		rtype = ELF_R_TYPE(rela->r_info);
		symidx = ELF_R_SYM(rela->r_info);

		switch (rtype) {
		case R_RISCV_NONE:	/* none */
			break;

		case R_RISCV_RELATIVE:	/* B + A */
			addr = (Elf_Addr)(mapping + addend);
			if (*where != addr)
				*where = addr;
			break;
		default:
			printf("Linux RISC-V vDSO: unexpected relocation type %ld, "
			    "symbol index %ld\n", rtype, symidx);
		}
	}
}

static const Elf_Brandnote linux64_brandnote = {
	.hdr.n_namesz	= sizeof(GNU_ABI_VENDOR),
	.hdr.n_descsz	= 16,
	.hdr.n_type	= 1,
	.vendor		= GNU_ABI_VENDOR,
	.flags		= BN_TRANSLATE_OSREL,
	.trans_osrel	= linux_trans_osrel
};

static const Elf64_Brandinfo linux_glibc2brand = {
	.brand		= ELFOSABI_LINUX,
	.machine	= EM_RISCV,
	.compat_3_brand	= "Linux",
	.interp_path	= "/lib/ld-linux-riscv64-lp64d.so.1",
	.sysvec		= &elf_linux_sysvec,
	.interp_newpath	= NULL,
	.brand_note	= &linux64_brandnote,
	.flags		= BI_CAN_EXEC_DYN | BI_BRAND_NOTE
};

const Elf64_Brandinfo *linux_brandlist[] = {
	&linux_glibc2brand,
	NULL
};

static int
linux64_elf_modevent(module_t mod, int type, void *data)
{
	const Elf64_Brandinfo **brandinfo;
	struct linux_ioctl_handler **lihp;
	int error;

	error = 0;
	switch(type) {
	case MOD_LOAD:
		for (brandinfo = &linux_brandlist[0]; *brandinfo != NULL;
		    ++brandinfo)
			if (elf64_insert_brand_entry(*brandinfo) < 0)
				error = EINVAL;
		if (error == 0) {
			SET_FOREACH(lihp, linux_ioctl_handler_set)
				linux_ioctl_register_handler(*lihp);
			stclohz = (stathz ? stathz : hz);
			if (bootverbose)
				printf("Linux riscv ELF exec handler installed\n");
		}
		break;
	case MOD_UNLOAD:
		if (linux_perf_inuse())
			error = EBUSY;
		for (brandinfo = &linux_brandlist[0]; *brandinfo != NULL;
		    ++brandinfo)
			if (elf64_brand_inuse(*brandinfo))
				error = EBUSY;
		if (error == 0) {
			for (brandinfo = &linux_brandlist[0];
			    *brandinfo != NULL; ++brandinfo)
				if (elf64_remove_brand_entry(*brandinfo) < 0)
					error = EINVAL;
		}
		if (error == 0) {
			SET_FOREACH(lihp, linux_ioctl_handler_set)
				linux_ioctl_unregister_handler(*lihp);
			if (bootverbose)
				printf("Linux riscv ELF exec handler removed\n");
		} else
			printf("Could not deinstall Linux riscv ELF interpreter entry\n");
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (error);
}

static moduledata_t linux64_elf_mod = {
	"linux64elf",
	linux64_elf_modevent,
	0
};

DECLARE_MODULE_TIED(linux64elf, linux64_elf_mod, SI_SUB_EXEC, SI_ORDER_ANY);
MODULE_DEPEND(linux64elf, linux_common, 1, 1, 1);
FEATURE(linux64, "RISC-V Linux 64bit support");
