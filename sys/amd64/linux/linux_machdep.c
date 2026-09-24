/*-
 * Copyright (c) 2004 Tim J. Robbins
 * Copyright (c) 2002 Doug Rabson
 * Copyright (c) 2000 Marcel Moolenaar
 * All rights reserved.
 * Copyright (c) 2013 Dmitry Chagin <dchagin@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/ktr.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/mman.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/sx.h>
#include <sys/syscallsubr.h>
#include <sys/vnode.h>

#include <machine/fpu.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/segments.h>
#include <machine/specialreg.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>
#include <vm/vm_param.h>

#include <x86/ifunc.h>
#include <x86/reg.h>
#include <x86/sysarch.h>

#include <amd64/linux/linux.h>
#include <amd64/linux/linux_proto.h>
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_fork.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_mmap.h>
#include <compat/linux/linux_util.h>

#define	LINUX_ARCH_AMD64		0xc000003e

int
linux_set_upcall(struct thread *td, register_t stack)
{

	if (stack)
		td->td_frame->tf_rsp = stack;

	/*
	 * The newly created Linux thread returns
	 * to the user space by the same path that a parent does.
	 */
	td->td_frame->tf_rax = 0;
	return (0);
}

int
linux_iopl(struct thread *td, struct linux_iopl_args *args)
{
	l_uint old_level;
	int error;

	LINUX_CTR(iopl);

	if (args->level > 3)
		return (EINVAL);
	old_level = (td->td_frame->tf_rflags & PSL_IOPL) / (PSL_IOPL / 3);
	if (args->level > old_level) {
		if ((error = priv_check(td, PRIV_IO)) != 0)
			return (error);
		if ((error = securelevel_gt(td->td_ucred, 0)) != 0)
			return (error);
	}
	td->td_frame->tf_rflags = (td->td_frame->tf_rflags & ~PSL_IOPL) |
	    (args->level * (PSL_IOPL / 3));

	return (0);
}

int
linux_ioperm(struct thread *td, struct linux_ioperm_args *args)
{
	struct i386_ioperm_args iargs;

	if (args->num == 0 || args->from >= 65536 ||
	    args->num > 65536 - args->from)
		return (EINVAL);
	iargs.start = args->from;
	iargs.length = args->num;
	iargs.enable = args->turn_on != 0;
	return (amd64_set_ioperm(td, &iargs));
}

#define	LINUX_LDT_ENTRIES	8192
#define	LINUX_LDT_ENTRY_SIZE	8

struct linux_ldt_info {
	l_uint entry_number;
	l_uint base_addr;
	l_uint limit;
	l_uint flags;
};

int
linux_modify_ldt(struct thread *td, struct linux_modify_ldt_args *args)
{
	struct linux_ldt_info info;
	struct i386_ldt_args largs;
	struct user_segment_descriptor desc;
	char zeros[128] = { 0 };
	size_t count;
	l_uint contents;
	bool empty, not_present;
	int error;

	switch (args->func) {
	case 0: /* Read the process LDT. */
		count = MIN(args->bytecount,
		    LINUX_LDT_ENTRIES * LINUX_LDT_ENTRY_SIZE);
		return (amd64_get_ldt_bytes(td, args->ptr, count));
	case 2: /* Read the all-zero default LDT. */
		count = MIN(args->bytecount, sizeof(zeros));
		error = copyout(zeros, args->ptr, count);
		if (error == 0)
			td->td_retval[0] = count;
		return (error);
	case 1: /* Legacy write. */
	case 0x11: /* Modern write. */
		break;
	default:
		return (ENOSYS);
	}
	if (args->bytecount != sizeof(info))
		return (EINVAL);
	error = copyin(args->ptr, &info, sizeof(info));
	if (error != 0)
		return (error);
	if (info.entry_number >= LINUX_LDT_ENTRIES)
		return (EINVAL);
	contents = (info.flags >> 1) & 3;
	not_present = ((info.flags >> 5) & 1) != 0;
	if (contents == 3 && (args->func == 1 || !not_present))
		return (EINVAL);
	empty = (args->func == 1 && info.base_addr == 0 && info.limit == 0) ||
	    (info.base_addr == 0 && info.limit == 0 &&
	    (info.flags & 0x7f) == (8 | 32));
	largs.start = info.entry_number;
	largs.descs = &desc;
	largs.num = 1;
	if (empty) {
		error = amd64_set_ldt_linux(td, &largs, NULL);
	} else {
		bzero(&desc, sizeof(desc));
		desc.sd_lolimit = info.limit & 0xffff;
		desc.sd_hilimit = (info.limit >> 16) & 0xf;
		desc.sd_lobase = info.base_addr & 0xffffff;
		desc.sd_hibase = info.base_addr >> 24;
		desc.sd_type = SDT_MEMRO | (((info.flags >> 3) & 1) ^ 1) << 1 |
		    contents << 2;
		desc.sd_dpl = SEL_UPL;
		desc.sd_p = !not_present;
		desc.sd_xx = args->func == 1 ? 0 : (info.flags >> 6) & 1;
		desc.sd_long = 0;
		desc.sd_def32 = info.flags & 1;
		desc.sd_gran = (info.flags >> 4) & 1;
		error = amd64_set_ldt_linux(td, &largs, &desc);
	}
	if (error == EACCES)
		return (EINVAL);
	if (error == 0)
		td->td_retval[0] = 0;
	return (error);
}

int
linux_pause(struct thread *td, struct linux_pause_args *args)
{
	struct proc *p = td->td_proc;
	sigset_t sigmask;

	LINUX_CTR(pause);

	PROC_LOCK(p);
	sigmask = td->td_sigmask;
	PROC_UNLOCK(p);
	return (kern_sigsuspend(td, sigmask));
}

/*
 * ARCH_REQ_XCOMP_PERM: Linux takes a component *number*, returns EINVAL
 * for numbers it does not know about and EOPNOTSUPP for every component
 * that is not dynamically enabled.  Only XTILEDATA (AMX, which also pulls
 * in XTILECFG) is dynamic; asking for x87/SSE/AVX is EOPNOTSUPP on Linux
 * too, they are always enabled and have no permission entry.  We have no
 * per-process permission model, so AMX is "permitted" iff the kernel saves
 * it (xsave_mask); glibc >= 2.39 probes this on AMX machines and falls
 * back cleanly on EOPNOTSUPP.
 */
static int
linux_arch_req_xcomp_perm(l_ulong idx)
{
	uint64_t requested;

	if (idx >= LINUX_XFEATURE_MAX)
		return (EINVAL);
	if (idx != LINUX_XFEATURE_XTILEDATA)
		return (EOPNOTSUPP);
	requested = LINUX_XFEATURE_MASK_XTILE;
	if (!use_xsave || (xsave_mask & requested) != requested)
		return (EOPNOTSUPP);
	return (0);
}

/*
 * ARCH_SHSTK_*: shadow stacks are never enabled for a Linux process here,
 * so mirror the Linux answers for a kernel with CET compiled in but no
 * usable hardware: STATUS reports no features, LOCK of nothing succeeds,
 * ENABLE/DISABLE of a known feature is EOPNOTSUPP and everything else is
 * EINVAL (UNLOCK is reserved for ptrace).
 */
static int
linux_arch_shstk(struct thread *td, l_int code, l_ulong arg)
{
	l_ulong features;

	switch (code) {
	case LINUX_ARCH_SHSTK_STATUS:
		features = 0;
		return (copyout(&features, PTRIN(arg), sizeof(features)));
	case LINUX_ARCH_SHSTK_LOCK:
		return (0);
	case LINUX_ARCH_SHSTK_UNLOCK:
		return (EINVAL);
	case LINUX_ARCH_SHSTK_ENABLE:
	case LINUX_ARCH_SHSTK_DISABLE:
		if (bitcount64(arg) > 1)
			return (EINVAL);
		if ((arg & (LINUX_ARCH_SHSTK_SHSTK | LINUX_ARCH_SHSTK_WRSS)) != 0)
			return (EOPNOTSUPP);
		return (EINVAL);
	}
	return (EINVAL);
}


int
linux_remap_file_pages(struct thread *td,
    struct linux_remap_file_pages_args *args)
{
	vm_offset_t start;
	vm_size_t size;
	int rv;

	if (args->prot != 0)
		return (EINVAL);
	start = trunc_page(args->start);
	size = trunc_page(args->size);
	if (size == 0 || start + size <= start ||
	    args->pgoff + atop(size) < args->pgoff ||
	    args->pgoff > (INT64_MAX >> PAGE_SHIFT))
		return (EINVAL);
	if (linux_range_sealed(td, start, size))
		return (EPERM);
	rv = vm_map_remap_file_pages(&td->td_proc->p_vmspace->vm_map,
	    start, size, (vm_ooffset_t)args->pgoff << PAGE_SHIFT);
	if (rv != KERN_SUCCESS)
		return (rv == KERN_PROTECTION_FAILURE ? EACCES : EINVAL);
	if ((args->flags & LINUX_MAP_NONBLOCK) == 0)
		linux_mmap_populate(td, start, size, PROT_READ);
	return (0);
}

int
linux_arch_prctl(struct thread *td, struct linux_arch_prctl_args *args)
{
	unsigned long long cet[3];
	struct pcb *pcb;
	l_ulong val;
	int error;

	pcb = td->td_pcb;
	LINUX_CTR2(arch_prctl, "0x%x, %p", args->code, args->addr);

	switch (args->code) {
	case LINUX_ARCH_SET_GS:
		if (args->addr < VM_MAXUSER_ADDRESS) {
			update_pcb_bases(pcb);
			pcb->pcb_gsbase = args->addr;
			td->td_frame->tf_gs = _ugssel;
			error = 0;
		} else
			error = EPERM;
		break;
	case LINUX_ARCH_SET_FS:
		if (args->addr < VM_MAXUSER_ADDRESS) {
			update_pcb_bases(pcb);
			pcb->pcb_fsbase = args->addr;
			td->td_frame->tf_fs = _ufssel;
			error = 0;
		} else
			error = EPERM;
		break;
	case LINUX_ARCH_GET_FS:
		error = copyout(&pcb->pcb_fsbase, PTRIN(args->addr),
		    sizeof(args->addr));
		break;
	case LINUX_ARCH_GET_GS:
		error = copyout(&pcb->pcb_gsbase, PTRIN(args->addr),
		    sizeof(args->addr));
		break;
	case LINUX_ARCH_CET_STATUS:
		memset(cet, 0, sizeof(cet));
		error = copyout(&cet, PTRIN(args->addr), sizeof(cet));
		break;
	case LINUX_ARCH_GET_CPUID:
		/* CPUID faulting is never armed for a Linux process. */
		td->td_retval[0] = 1;
		error = 0;
		break;
	case LINUX_ARCH_SET_CPUID:
		/* Linux without CPUID faulting support. */
		error = ENODEV;
		break;
	case LINUX_ARCH_GET_XCOMP_SUPP:
	case LINUX_ARCH_GET_XCOMP_PERM:
	case LINUX_ARCH_GET_XCOMP_GUEST_PERM:
		val = use_xsave ? xsave_mask :
		    (XFEATURE_ENABLED_X87 | XFEATURE_ENABLED_SSE);
		error = copyout(&val, PTRIN(args->addr), sizeof(val));
		break;
	case LINUX_ARCH_REQ_XCOMP_PERM:
	case LINUX_ARCH_REQ_XCOMP_GUEST_PERM:
		error = linux_arch_req_xcomp_perm(args->addr);
		break;
	case LINUX_ARCH_MAP_VDSO_32:
	case LINUX_ARCH_MAP_VDSO_64:
		/* The vDSO is always mapped already. */
		error = EEXIST;
		break;
	case LINUX_ARCH_MAP_VDSO_X32:
		/* No x32 ABI. */
		error = EINVAL;
		break;
	case LINUX_ARCH_GET_UNTAG_MASK:
		/* LAM is never enabled: all address bits are significant. */
		val = ~(l_ulong)0;
		error = copyout(&val, PTRIN(args->addr), sizeof(val));
		break;
	case LINUX_ARCH_GET_MAX_TAG_BITS:
		val = 0;
		error = copyout(&val, PTRIN(args->addr), sizeof(val));
		break;
	case LINUX_ARCH_ENABLE_TAGGED_ADDR:
		error = ENODEV;
		break;
	case LINUX_ARCH_FORCE_TAGGED_SVA:
		/* Forbids enabling LAM, which is impossible anyway. */
		error = 0;
		break;
	case LINUX_ARCH_SHSTK_ENABLE:
	case LINUX_ARCH_SHSTK_DISABLE:
	case LINUX_ARCH_SHSTK_LOCK:
	case LINUX_ARCH_SHSTK_UNLOCK:
	case LINUX_ARCH_SHSTK_STATUS:
		error = linux_arch_shstk(td, args->code, args->addr);
		break;
	default:
		linux_msg(td, "unsupported arch_prctl code %#x", args->code);
		error = EINVAL;
	}
	return (error);
}

/*
 * Memory protection keys.
 *
 * FreeBSD has no key allocator: keys are a userland resource and the kernel
 * only records key->range assignments (pmap_pkru_set()).  Linux allocates
 * keys per mm, so keep the allocation map in the process emuldata.  PKRU
 * itself is per-thread user register state living in the XSAVE area.
 */

#define	LINUX_PKEY_MAP(pem)	((pem)->pkeys_map ^ 1)

static bool
linux_pkeys_enabled(void)
{

	return (use_xsave && (cpu_stdext_feature2 & CPUID_STDEXT2_PKU) != 0 &&
	    (xsave_mask & XFEATURE_ENABLED_PKRU) != 0);
}

static bool
linux_pkey_is_allocated(struct linux_pemuldata *pem, int pkey)
{

	if (pkey < 0 || pkey >= LINUX_PKEY_MAX)
		return (false);
	return ((LINUX_PKEY_MAP(pem) & (1U << pkey)) != 0);
}

/*
 * Update the calling thread's PKRU: the value is part of the thread's user
 * FPU state, so edit it in the saved XSAVE area (after syncing the live
 * registers into it) and reload the registers if the thread owns the FPU.
 */
static void
linux_pkru_update(struct thread *td, uint32_t clear, uint32_t set)
{
	struct savefpu *sa;
	struct xstate_hdr *hdr;
	uint32_t *pkru;
	size_t off;
	int owned;

	off = xsave_area_offset(xsave_mask, XFEATURE_ENABLED_PKRU, false,
	    false);
	critical_enter();
	owned = fpugetregs(td);
	sa = get_pcb_user_save_td(td);
	hdr = (struct xstate_hdr *)(sa + 1);
	pkru = (uint32_t *)((char *)sa + off);
	if ((hdr->xstate_bv & XFEATURE_ENABLED_PKRU) == 0) {
		/* Component in its initial state: PKRU == 0. */
		*pkru = 0;
		hdr->xstate_bv |= XFEATURE_ENABLED_PKRU;
	}
	*pkru = (*pkru & ~clear) | set;
	if (owned == _MC_FPOWNED_FPU) {
		fpurestore(sa);
	} else if (td == curthread) {
		/*
		 * The save area is reloaded on the next #NM or context
		 * switch; PKRU is consulted before either happens, so
		 * update the live register as well.
		 */
		wrpkru(*pkru);
	}
	critical_exit();
}

int
linux_pkey_alloc(struct thread *td, struct linux_pkey_alloc_args *args)
{
	struct linux_pemuldata *pem;
	uint32_t map;
	int pkey;

	/* No flags are defined. */
	if (args->flags != 0)
		return (EINVAL);
	if ((args->init_val & ~(l_ulong)LINUX_PKEY_ACCESS_MASK) != 0)
		return (EINVAL);
	/* pkey_alloc(2): ENOSPC when the CPU/OS does not support keys. */
	if (!linux_pkeys_enabled())
		return (ENOSPC);

	pem = pem_find(td->td_proc);
	LINUX_PEM_XLOCK(pem);
	map = LINUX_PKEY_MAP(pem);
	if (map == (1U << LINUX_PKEY_MAX) - 1) {
		LINUX_PEM_XUNLOCK(pem);
		return (ENOSPC);
	}
	pkey = ffs(~map) - 1;
	pem->pkeys_map = (map | (1U << pkey)) ^ 1;
	LINUX_PEM_XUNLOCK(pem);

	/* Initial access rights apply to the calling thread only. */
	linux_pkru_update(td,
	    LINUX_PKEY_ACCESS_MASK << (pkey * LINUX_PKRU_BITS_PER_PKEY),
	    (args->init_val & LINUX_PKEY_ACCESS_MASK) <<
	    (pkey * LINUX_PKRU_BITS_PER_PKEY));
	td->td_retval[0] = pkey;
	return (0);
}

int
linux_pkey_free(struct thread *td, struct linux_pkey_free_args *args)
{
	struct linux_pemuldata *pem;

	if (!linux_pkeys_enabled())
		return (EINVAL);
	pem = pem_find(td->td_proc);
	LINUX_PEM_XLOCK(pem);
	if (!linux_pkey_is_allocated(pem, args->pkey)) {
		LINUX_PEM_XUNLOCK(pem);
		return (EINVAL);
	}
	/*
	 * Like Linux, only release the number: mappings keep the key and
	 * PKRU is untouched (documented pkey_free(2) pitfall).
	 */
	pem->pkeys_map = (LINUX_PKEY_MAP(pem) & ~(1U << args->pkey)) ^ 1;
	LINUX_PEM_XUNLOCK(pem);
	return (0);
}

int
linux_pkey_mprotect(struct thread *td, struct linux_pkey_mprotect_args *args)
{
	struct linux_pemuldata *pem;
	vm_map_t map;
	pmap_t pmap;
	vm_offset_t start, end;
	int error;

	/* Same argument policy as Linux do_mprotect_pkey(). */
	if ((args->start & PAGE_MASK) != 0)
		return (EINVAL);
	if (args->len == 0)
		return (0);
	start = args->start;
	end = round_page(start + args->len);
	if (end <= start)
		return (ENOMEM);
	if (args->pkey == -1)
		return (linux_mprotect_common(td, start, end - start,
		    args->prot));
	if (!linux_pkeys_enabled())
		return (EINVAL);

	/*
	 * Hold the emuldata shared across the whole operation so that the
	 * key cannot be freed between the check and the assignment (Linux
	 * holds mmap_lock for both).
	 */
	pem = pem_find(td->td_proc);
	LINUX_PEM_SLOCK(pem);
	if (!linux_pkey_is_allocated(pem, args->pkey)) {
		error = EINVAL;
		goto out;
	}
	error = linux_mprotect_common(td, start, end - start, args->prot);
	if (error != 0)
		goto out;

	/*
	 * Keys are a property of the mapping, as on Linux: no
	 * AMD64_PKRU_PERSIST, so unmapping drops the assignment and a new
	 * mapping at the same address gets key 0.  Read-lock the map to
	 * synchronise with pmap_vmspace_copy() on fork, as sysarch(2) does.
	 */
	map = &td->td_proc->p_vmspace->vm_map;
	pmap = vmspace_pmap(td->td_proc->p_vmspace);
	vm_map_lock_read(map);
	if (!vm_map_check_boundary(map, start, end)) {
		/* Concurrently unmapped after mprotect. */
		error = ENOMEM;
	} else if (args->pkey == 0) {
		error = pmap_pkru_clear(pmap, start, end);
	} else {
		error = pmap_pkru_set(pmap, start, end, args->pkey, 0);
	}
	vm_map_unlock_read(map);
	if (error == ENOTSUP)
		error = EINVAL;
out:
	LINUX_PEM_SUNLOCK(pem);
	return (error);
}

/*
 * restart_syscall(2) is only meant to be invoked by the kernel to restart
 * a call interrupted by a stop signal; a direct call from userland runs the
 * default do_no_restart_syscall() on Linux, which fails with EINTR.
 */
int
linux_restart_syscall(struct thread *td, struct linux_restart_syscall_args *args)
{

	return (EINTR);
}

int
linux_set_cloned_tls(struct thread *td, void *desc)
{
	struct pcb *pcb;

	if ((uint64_t)desc >= VM_MAXUSER_ADDRESS)
		return (EPERM);

	pcb = td->td_pcb;
	update_pcb_bases(pcb);
	pcb->pcb_fsbase = (register_t)desc;
	td->td_frame->tf_fs = _ufssel;

	return (0);
}

int futex_xchgl_nosmap(int oparg, uint32_t *uaddr, int *oldval);
int futex_xchgl_smap(int oparg, uint32_t *uaddr, int *oldval);
DEFINE_IFUNC(, int, futex_xchgl, (int, uint32_t *, int *))
{

	return ((cpu_stdext_feature & CPUID_STDEXT_SMAP) != 0 ?
	    futex_xchgl_smap : futex_xchgl_nosmap);
}

int futex_addl_nosmap(int oparg, uint32_t *uaddr, int *oldval);
int futex_addl_smap(int oparg, uint32_t *uaddr, int *oldval);
DEFINE_IFUNC(, int, futex_addl, (int, uint32_t *, int *))
{

	return ((cpu_stdext_feature & CPUID_STDEXT_SMAP) != 0 ?
	    futex_addl_smap : futex_addl_nosmap);
}

int futex_orl_nosmap(int oparg, uint32_t *uaddr, int *oldval);
int futex_orl_smap(int oparg, uint32_t *uaddr, int *oldval);
DEFINE_IFUNC(, int, futex_orl, (int, uint32_t *, int *))
{

	return ((cpu_stdext_feature & CPUID_STDEXT_SMAP) != 0 ?
	    futex_orl_smap : futex_orl_nosmap);
}

int futex_andl_nosmap(int oparg, uint32_t *uaddr, int *oldval);
int futex_andl_smap(int oparg, uint32_t *uaddr, int *oldval);
DEFINE_IFUNC(, int, futex_andl, (int, uint32_t *, int *))
{

	return ((cpu_stdext_feature & CPUID_STDEXT_SMAP) != 0 ?
	    futex_andl_smap : futex_andl_nosmap);
}

int futex_xorl_nosmap(int oparg, uint32_t *uaddr, int *oldval);
int futex_xorl_smap(int oparg, uint32_t *uaddr, int *oldval);
DEFINE_IFUNC(, int, futex_xorl, (int, uint32_t *, int *))
{

	return ((cpu_stdext_feature & CPUID_STDEXT_SMAP) != 0 ?
	    futex_xorl_smap : futex_xorl_nosmap);
}

void
bsd_to_linux_regset(const struct reg *b_reg, struct linux_pt_regset *l_regset)
{

	l_regset->r15 = b_reg->r_r15;
	l_regset->r14 = b_reg->r_r14;
	l_regset->r13 = b_reg->r_r13;
	l_regset->r12 = b_reg->r_r12;
	l_regset->rbp = b_reg->r_rbp;
	l_regset->rbx = b_reg->r_rbx;
	l_regset->r11 = b_reg->r_r11;
	l_regset->r10 = b_reg->r_r10;
	l_regset->r9 = b_reg->r_r9;
	l_regset->r8 = b_reg->r_r8;
	l_regset->rax = b_reg->r_rax;
	l_regset->rcx = b_reg->r_rcx;
	l_regset->rdx = b_reg->r_rdx;
	l_regset->rsi = b_reg->r_rsi;
	l_regset->rdi = b_reg->r_rdi;
	l_regset->orig_rax = b_reg->r_rax;
	l_regset->rip = b_reg->r_rip;
	l_regset->cs = b_reg->r_cs;
	l_regset->eflags = b_reg->r_rflags;
	l_regset->rsp = b_reg->r_rsp;
	l_regset->ss = b_reg->r_ss;
	l_regset->fs_base = 0;
	l_regset->gs_base = 0;
	l_regset->ds = b_reg->r_ds;
	l_regset->es = b_reg->r_es;
	l_regset->fs = b_reg->r_fs;
	l_regset->gs = b_reg->r_gs;
}

void
linux_to_bsd_regset(struct reg *b_reg, const struct linux_pt_regset *l_regset)
{

	b_reg->r_r15 = l_regset->r15;
	b_reg->r_r14 = l_regset->r14;
	b_reg->r_r13 = l_regset->r13;
	b_reg->r_r12 = l_regset->r12;
	b_reg->r_rbp = l_regset->rbp;
	b_reg->r_rbx = l_regset->rbx;
	b_reg->r_r11 = l_regset->r11;
	b_reg->r_r10 = l_regset->r10;
	b_reg->r_r9 = l_regset->r9;
	b_reg->r_r8 = l_regset->r8;
	b_reg->r_rax = l_regset->rax;
	b_reg->r_rcx = l_regset->rcx;
	b_reg->r_rdx = l_regset->rdx;
	b_reg->r_rsi = l_regset->rsi;
	b_reg->r_rdi = l_regset->rdi;
	b_reg->r_rax = l_regset->orig_rax;
	b_reg->r_rip = l_regset->rip;
	b_reg->r_cs = l_regset->cs;
	b_reg->r_rflags = l_regset->eflags;
	b_reg->r_rsp = l_regset->rsp;
	b_reg->r_ss = l_regset->ss;
	b_reg->r_ds = l_regset->ds;
	b_reg->r_es = l_regset->es;
	b_reg->r_fs = l_regset->fs;
	b_reg->r_gs = l_regset->gs;
}

void
linux_ptrace_get_syscall_info_machdep(const struct reg *reg,
    struct syscall_info *si)
{

	si->arch = LINUX_ARCH_AMD64;
	si->instruction_pointer = reg->r_rip;
	si->stack_pointer = reg->r_rsp;
}

int
linux_ptrace_getregs_machdep(struct thread *td, pid_t pid,
    struct linux_pt_regset *l_regset)
{
	struct ptrace_lwpinfo lwpinfo;
	struct pcb *pcb;
	int error;

	pcb = td->td_pcb;
	if (td == curthread)
		update_pcb_bases(pcb);

	l_regset->fs_base = pcb->pcb_fsbase;
	l_regset->gs_base = pcb->pcb_gsbase;

	error = kern_ptrace(td, PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo));
	if (error != 0) {
		linux_msg(td, "PT_LWPINFO failed with error %d", error);
		return (error);
	}
	if ((lwpinfo.pl_flags & (PL_FLAG_SCE | PL_FLAG_SCX)) != 0) {
		/*
		 * In Linux, the syscall number - passed to the syscall
		 * as rax - is preserved in orig_rax; rax gets overwritten
		 * with syscall return value.
		 */
		l_regset->orig_rax = lwpinfo.pl_syscall_code;
	}

	return (0);
}

#define	LINUX_URO(a,m) ((uintptr_t)a == offsetof(struct linux_pt_regset, m))

int
linux_ptrace_peekuser(struct thread *td, pid_t pid, void *addr, void *data)
{
	struct linux_pt_regset reg;
	struct reg b_reg;
	uint64_t val;
	int error;

	if ((uintptr_t)addr & (sizeof(data) -1) || (uintptr_t)addr < 0)
		return (EIO);
	if ((uintptr_t)addr >= sizeof(struct linux_pt_regset)) {
		LINUX_RATELIMIT_MSG_OPT1("PTRACE_PEEKUSER offset %ld "
		    "not implemented; returning EINVAL", (uintptr_t)addr);
		return (EINVAL);
	}

	if (LINUX_URO(addr, fs_base))
		return (kern_ptrace(td, PT_GETFSBASE, pid, data, 0));
	if (LINUX_URO(addr, gs_base))
		return (kern_ptrace(td, PT_GETGSBASE, pid, data, 0));
	if ((error = kern_ptrace(td, PT_GETREGS, pid, &b_reg, 0)) != 0)
		return (error);
	bsd_to_linux_regset(&b_reg, &reg);
	val = *(&reg.r15 + ((uintptr_t)addr / sizeof(reg.r15)));
	return (copyout(&val, data, sizeof(val)));
}

static inline bool
linux_invalid_selector(u_short val)
{

	return (val != 0 && ISPL(val) != SEL_UPL);
}

struct linux_segreg_off {
	uintptr_t	reg;
	bool		is0;
};

const struct linux_segreg_off linux_segregs_off[] = {
	{
		.reg = offsetof(struct linux_pt_regset, gs),
		.is0 = true,
	},
	{
		.reg = offsetof(struct linux_pt_regset, fs),
		.is0 = true,
	},
	{
		.reg = offsetof(struct linux_pt_regset, ds),
		.is0 = true,
	},
	{
		.reg = offsetof(struct linux_pt_regset, es),
		.is0 = true,
	},
	{
		.reg = offsetof(struct linux_pt_regset, cs),
		.is0 = false,
	},
	{
		.reg = offsetof(struct linux_pt_regset, ss),
		.is0 = false,
	},
};

int
linux_ptrace_pokeuser(struct thread *td, pid_t pid, void *addr, void *data)
{
	struct linux_pt_regset reg;
	struct reg b_reg, b_reg1;
	int error, i;

	if ((uintptr_t)addr & (sizeof(data) -1) || (uintptr_t)addr < 0)
		return (EIO);
	if ((uintptr_t)addr >= sizeof(struct linux_pt_regset)) {
		LINUX_RATELIMIT_MSG_OPT1("PTRACE_POKEUSER offset %ld "
		    "not implemented; returning EINVAL", (uintptr_t)addr);
		return (EINVAL);
	}

	if (LINUX_URO(addr, fs_base))
		return (kern_ptrace(td, PT_SETFSBASE, pid, data, 0));
	if (LINUX_URO(addr, gs_base))
		return (kern_ptrace(td, PT_SETGSBASE, pid, data, 0));
	for (i = 0; i < nitems(linux_segregs_off); i++) {
		if ((uintptr_t)addr == linux_segregs_off[i].reg) {
			if (linux_invalid_selector((uintptr_t)data))
				return (EIO);
			if (!linux_segregs_off[i].is0 && (uintptr_t)data == 0)
				return (EIO);
		}
	}
	if ((error = kern_ptrace(td, PT_GETREGS, pid, &b_reg, 0)) != 0)
		return (error);
	bsd_to_linux_regset(&b_reg, &reg);
	*(&reg.r15 + ((uintptr_t)addr / sizeof(reg.r15))) = (uint64_t)data;
	linux_to_bsd_regset(&b_reg1, &reg);
	b_reg1.r_err = b_reg.r_err;
	b_reg1.r_trapno = b_reg.r_trapno;
	return (kern_ptrace(td, PT_SETREGS, pid, &b_reg, 0));
}
#undef LINUX_URO
