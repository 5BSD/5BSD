/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Dmitry Chagin <dchagin@FreeBSD.org>
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
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/mutex.h>
#include <sys/sysent.h>
#include <sys/pcpu.h>
#include <sys/signalvar.h>
#include <compat/linux/linux_emul.h>

#if defined(__amd64__) && !defined(COMPAT_LINUX32)
#include <machine/frame.h>
#endif

#ifdef COMPAT_LINUX32
#include <machine/../linux32/linux.h>
#include <machine/../linux32/linux32_proto.h>
#else
#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#endif


enum linux_rseq_cpu_id_state {
	LINUX_RSEQ_CPU_ID_UNINITIALIZED			= -1,
	LINUX_RSEQ_CPU_ID_REGISTRATION_FAILED		= -2,
};

enum linux_rseq_flags {
	LINUX_RSEQ_FLAG_UNREGISTER			= (1 << 0),
	/* Accepted even when the optional slice extension is unavailable. */
	LINUX_RSEQ_FLAG_SLICE_EXT_DEFAULT_ON		= (1 << 1),
};

enum linux_rseq_cs_flags_bit {
	LINUX_RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT	= 0,
	LINUX_RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT	= 1,
	LINUX_RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT	= 2,
};

enum linux_rseq_cs_flags {
	LINUX_RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT	=
		(1U << LINUX_RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT),
	LINUX_RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL	=
		(1U << LINUX_RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT),
	LINUX_RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE	=
		(1U << LINUX_RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT),
};

struct linux_rseq_cs {
	uint32_t version;
	uint32_t flags;
	uint64_t start_ip;
	uint64_t post_commit_offset;
	uint64_t abort_ip;
} __attribute__((aligned(4 * sizeof(uint64_t))));

struct linux_rseq {
	uint32_t cpu_id_start;
	uint32_t cpu_id;
	uint64_t rseq_cs;
	uint32_t flags;
	uint32_t node_id;
	uint32_t mm_cid;
	uint32_t pad;
} __attribute__((aligned(4 * sizeof(uint64_t))));

#if defined(__amd64__) && !defined(COMPAT_LINUX32)

static int
linux_rseq_set_u32(struct linux_rseq *area, size_t off, uint32_t value)
{

	return (copyout(&value, (char *)area + off, sizeof(value)));
}

static int
linux_rseq_set_u64(struct linux_rseq *area, size_t off, uint64_t value)
{

	return (copyout(&value, (char *)area + off, sizeof(value)));
}

/*
 * Called only for a scheduler event or a signal about to be delivered.
 * The descriptor can be cleared by userspace after its commit instruction.
 */
static bool
linux_rseq_fixup(struct thread *td, struct linux_emuldata *em)
{
	struct linux_rseq_cs cs;
	struct linux_rseq *area;
	uint64_t csaddr, ip;
	uint32_t sig;

	area = (struct linux_rseq *)em->rseq_addr;
	if (copyin(&area->rseq_cs, &csaddr, sizeof(csaddr)) != 0)
		return (false);
	if (csaddr == 0)
		return (true);
	if (copyin((void *)(uintptr_t)csaddr, &cs, sizeof(cs)) != 0)
		return (false);
	ip = td->td_frame->tf_rip;
	if (linux_rseq_set_u64(area, offsetof(struct linux_rseq, rseq_cs),
	    0) != 0)
		return (false);
	if (ip - cs.start_ip >= cs.post_commit_offset)
		return (true);
	if (cs.version != 0 || cs.flags != 0 || cs.abort_ip < 4 ||
	    cs.abort_ip >= td->td_proc->p_sysent->sv_maxuser ||
	    cs.abort_ip - cs.start_ip < cs.post_commit_offset ||
	    copyin((void *)(uintptr_t)(cs.abort_ip - 4), &sig,
	    sizeof(sig)) != 0 || sig != em->rseq_sig)
		return (false);
	td->td_frame->tf_rip = cs.abort_ip;
	return (true);
}

static bool
linux_rseq_update_cpu(struct thread *td, struct linux_emuldata *em)
{
	struct linux_rseq *area;
	uint32_t cpu, node;

	area = (struct linux_rseq *)em->rseq_addr;
	cpu = td->td_oncpu;
	node = cpuid_to_pcpu[cpu]->pc_domain;
	return (linux_rseq_set_u32(area,
	    offsetof(struct linux_rseq, cpu_id_start), cpu) == 0 &&
	    linux_rseq_set_u32(area,
	    offsetof(struct linux_rseq, cpu_id), cpu) == 0 &&
	    linux_rseq_set_u32(area,
	    offsetof(struct linux_rseq, node_id), node) == 0 &&
	    linux_rseq_set_u32(area,
	    offsetof(struct linux_rseq, mm_cid), cpu) == 0);
}

static void
linux_rseq_ast(struct thread *td, int asts __unused)
{
	struct linux_emuldata *em;
	bool switched;

	em = em_find(td);
	if (em == NULL || em->rseq_addr == 0)
		return;
	switched = em->rseq_switch_pending;
	em->rseq_switch_pending = false;
	if ((switched && !linux_rseq_fixup(td, em)) ||
	    !linux_rseq_update_cpu(td, em)) {
		PROC_LOCK(td->td_proc);
		sigexit(td, SIGSEGV);
	}
}

static void
linux_rseq_ast_init(void *arg __unused)
{

	ast_register(TDA_MOD1, ASTR_ASTF_REQUIRED, 0, linux_rseq_ast);
}
SYSINIT(linux_rseq_ast, SI_SUB_KLD, SI_ORDER_MIDDLE, linux_rseq_ast_init,
    NULL);

static void
linux_rseq_ast_uninit(void *arg __unused)
{

	ast_deregister(TDA_MOD1);
}
SYSUNINIT(linux_rseq_ast, SI_SUB_KLD, SI_ORDER_MIDDLE,
    linux_rseq_ast_uninit, NULL);

/* The caller has released the process and sigacts locks. */
void
linux_rseq_signal(struct thread *td)
{
	struct linux_emuldata *em;

	em = em_find(td);
	if (em != NULL && em->rseq_addr != 0 && !linux_rseq_fixup(td, em)) {
		PROC_LOCK(td->td_proc);
		sigexit(td, SIGSEGV);
	}
}

int
linux_rseq(struct thread *td, struct linux_rseq_args *args)
{
	struct linux_emuldata *em;
	struct linux_rseq *area;
	uintptr_t addr;
	int error;

	em = em_find(td);
	if (em == NULL)
		return (EINVAL);
	area = args->rseq;
	addr = (uintptr_t)area;
	if ((args->flags & LINUX_RSEQ_FLAG_UNREGISTER) != 0) {
		if (args->flags != LINUX_RSEQ_FLAG_UNREGISTER ||
		    em->rseq_addr == 0 || em->rseq_addr != addr ||
		    em->rseq_len != args->rseq_len)
			return (EINVAL);
		if (em->rseq_sig != args->sig)
			return (EPERM);
		if ((error = linux_rseq_set_u32(area,
		    offsetof(struct linux_rseq, cpu_id_start), 0)) != 0 ||
		    (error = linux_rseq_set_u32(area,
		    offsetof(struct linux_rseq, cpu_id), (uint32_t)-1)) != 0 ||
		    (error = linux_rseq_set_u32(area,
		    offsetof(struct linux_rseq, node_id), 0)) != 0 ||
		    (error = linux_rseq_set_u32(area,
		    offsetof(struct linux_rseq, mm_cid), 0)) != 0)
			return (error);
		em->rseq_addr = 0;
		em->rseq_len = 0;
		em->rseq_sig = 0;
		em->rseq_switch_pending = false;
		return (0);
	}
	if ((args->flags & ~LINUX_RSEQ_FLAG_SLICE_EXT_DEFAULT_ON) != 0)
		return (EINVAL);
	if (em->rseq_addr != 0) {
		if (em->rseq_addr != addr || em->rseq_len != args->rseq_len)
			return (EINVAL);
		return (em->rseq_sig != args->sig ? EPERM : EBUSY);
	}
	if (args->rseq_len < 32 || (addr & 31) != 0)
		return (EINVAL);
	if (addr > td->td_proc->p_sysent->sv_maxuser ||
	    args->rseq_len > td->td_proc->p_sysent->sv_maxuser - addr)
		return (EFAULT);
	if ((error = linux_rseq_set_u64(area,
	    offsetof(struct linux_rseq, rseq_cs), 0)) != 0 ||
	    (error = linux_rseq_set_u32(area,
	    offsetof(struct linux_rseq, flags), 0)) != 0 ||
	    (error = linux_rseq_set_u32(area,
	    offsetof(struct linux_rseq, cpu_id_start), (uint32_t)-1)) != 0 ||
	    (error = linux_rseq_set_u32(area,
	    offsetof(struct linux_rseq, cpu_id), (uint32_t)-1)) != 0 ||
	    (error = linux_rseq_set_u32(area,
	    offsetof(struct linux_rseq, node_id), 0)) != 0 ||
	    (error = linux_rseq_set_u32(area,
	    offsetof(struct linux_rseq, mm_cid), 0)) != 0)
		return (error);
	em->rseq_len = args->rseq_len;
	em->rseq_sig = args->sig;
	em->rseq_addr = addr;
	em->rseq_switch_pending = false;
	ast_sched(td, TDA_MOD1);
	return (0);
}

/* mi_switch() calls this after the thread resumes, without its thread lock. */
void
linux_rseq_schedswitch(struct thread *td)
{
	struct linux_emuldata *em;

	em = em_find(td);
	if (em == NULL || em->rseq_addr == 0)
		return;
	em->rseq_switch_pending = true;
	ast_sched(td, TDA_MOD1);
}

#else
int
linux_rseq(struct thread *td __unused, struct linux_rseq_args *args __unused)
{

	return (ENOSYS);
}
#endif
