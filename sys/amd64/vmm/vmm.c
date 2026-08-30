/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_bhyve_snapshot.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/sched.h>
#include <sys/sleepqueue.h>
#include <sys/smp.h>
#include <sys/sx.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_pager.h>
#include <vm/vm_kern.h>
#include <vm/vnode_pager.h>
#include <vm/swap_pager.h>
#include <vm/uma.h>

#include <machine/cpu.h>
#include <machine/pcb.h>
#include <machine/smp.h>
#include <machine/md_var.h>
#include <x86/psl.h>
#include <x86/apicreg.h>
#include <x86/clock.h>
#include <x86/ifunc.h>

#include <machine/vmm.h>
#include <machine/vmm_instruction_emul.h>
#include <machine/vmm_snapshot.h>

#include <dev/vmm/vmm_dev.h>
#include <dev/vmm/vmm_event_coordinator.h>
#include <dev/vmm/vmm_ktr.h>
#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_startup_entry_owner.h>
#include <dev/vmm/vmm_startup_handshake.h>
#include <dev/vmm/vmm_startup_mode.h>
#ifdef BHYVE_SNAPSHOT
#include <dev/vmm/vmm_snapshot_envelope.h>
#endif
#include <dev/vmm/vmm_vm.h>

#include "vmm_ioport.h"
#include "vmm_event_state.h"
#include "vmm_intinfo.h"
#ifdef BHYVE_SNAPSHOT
#include "vmm_snapshot_x86_transaction.h"
#endif
#include "vmm_host.h"
#include "vmm_mem.h"
#include "vmm_util.h"
#include "vatpic.h"
#include "vatpit.h"
#include "vhpet.h"
#include "vioapic.h"
#include "vlapic.h"
#include "vpmtmr.h"
#include "vrtc.h"
#include "vpvclock.h"
#include "vmm_stat.h"
#include "vmm_lapic.h"
#include "x86.h"

#include "io/ppt.h"
#include "io/iommu.h"

struct vlapic;

#define	VMM_CTR0(vcpu, format)						\
	VCPU_CTR0((vcpu)->vm, (vcpu)->vcpuid, format)

#define	VMM_CTR1(vcpu, format, p1)					\
	VCPU_CTR1((vcpu)->vm, (vcpu)->vcpuid, format, p1)

#define	VMM_CTR2(vcpu, format, p1, p2)					\
	VCPU_CTR2((vcpu)->vm, (vcpu)->vcpuid, format, p1, p2)

#define	VMM_CTR3(vcpu, format, p1, p2, p3)				\
	VCPU_CTR3((vcpu)->vm, (vcpu)->vcpuid, format, p1, p2, p3)

#define	VMM_CTR4(vcpu, format, p1, p2, p3, p4)				\
	VCPU_CTR4((vcpu)->vm, (vcpu)->vcpuid, format, p1, p2, p3, p4)

/*
 * Pending event ownership is independent of the vCPU run-state lock.  In
 * particular, the HLT path holds vcpu->mtx while inspecting events.  Never
 * acquire vcpu->mtx while event_mtx is held; publishers release event_mtx
 * before notifying the run-state owner.
 */
#define	vcpu_event_lock(vcpu)	mtx_lock_spin(&(vcpu)->event_mtx)
#define	vcpu_event_unlock(vcpu)	mtx_unlock_spin(&(vcpu)->event_mtx)
#define	vcpu_event_assert(vcpu)	mtx_assert(&(vcpu)->event_mtx, MA_OWNED)

/* Private transient adapter bits, never architectural or serialized. */
#define	VM_EVENT_DEFERRED_NMI	UINT64_C(1)
#define	VM_EVENT_DEFERRED_EXTINT	UINT64_C(2)
#define	VM_EVENT_DEFERRED_VALID	(VM_EVENT_DEFERRED_NMI | \
				 VM_EVENT_DEFERRED_EXTINT)

static inline void vcpu_event_generation_advance_locked(struct vcpu *);
static bool vm_event_output_overlaps_owner(struct vm *, const void *,
    size_t);

void
vm_event_checkpoint_deferred_apply(void *arg, uint16_t vcpuid,
    uint64_t deferred_mask)
{
	struct vcpu *vcpu;
	struct vm *vm;

	vm = arg;
	if (vm == NULL || vcpuid >= vm_get_maxcpus(vm) ||
	    (deferred_mask & ~VM_EVENT_DEFERRED_VALID) != 0 ||
	    deferred_mask == 0)
		panic("%s: invalid deferred event %#jx for vCPU %u", __func__,
		    (uintmax_t)deferred_mask, vcpuid);
	vcpu = vm_vcpu(vm, vcpuid);
	if (vcpu == NULL)
		panic("%s: missing deferred-event vCPU %u", __func__, vcpuid);

	/* Coordinator ingress lock precedes the pending-event owner lock. */
	vcpu_event_lock(vcpu);
	if ((deferred_mask & VM_EVENT_DEFERRED_NMI) != 0)
		vcpu->nmi_pending = 1;
	if ((deferred_mask & VM_EVENT_DEFERRED_EXTINT) != 0)
		vcpu->extint_pending = 1;
	vcpu_event_generation_advance_locked(vcpu);
	vcpu_event_unlock(vcpu);
}

static void
vm_event_generation_advance(struct vm *vm)
{
	uint64_t generation;

	generation = atomic_load_acq_64(&vm->event_generation);
	for (;;) {
		if (generation == UINT64_MAX)
			panic("%s: event generation exhausted", __func__);
		if (atomic_fcmpset_rel_64(&vm->event_generation, &generation,
		    generation + 1))
			break;
	}
}

static inline void
vcpu_event_generation_advance_locked(struct vcpu *vcpu)
{

	vcpu_event_assert(vcpu);
	vm_event_generation_advance(vcpu->vm);
}

static void
vm_event_publisher_exit_checked(struct vcpu *vcpu,
    struct vmm_event_ingress_ticket *ticket)
{
	int error;

	error = vmm_event_coordinator_publisher_exit(
	    vm_event_coordinator(vcpu->vm), vcpu->vcpuid, ticket);
	if (error != 0)
		panic("%s: lost event publisher credential: %d", __func__, error);
}

static void	vmmops_panic(void);

static void
vmmops_panic(void)
{
	panic("vmm_ops func called when !vmm_is_intel() && !vmm_is_svm()");
}

#define	DEFINE_VMMOPS_IFUNC(ret_type, opname, args)			\
    DEFINE_IFUNC(, ret_type, vmmops_##opname, args)			\
    {									\
    	if (vmm_is_intel())						\
    		return (vmm_ops_intel.opname);				\
    	else if (vmm_is_svm())						\
    		return (vmm_ops_amd.opname);				\
    	else								\
    		return ((ret_type (*)args)vmmops_panic);		\
    }

DEFINE_VMMOPS_IFUNC(int, modinit, (int ipinum))
DEFINE_VMMOPS_IFUNC(int, modcleanup, (void))
DEFINE_VMMOPS_IFUNC(void, modsuspend, (void))
DEFINE_VMMOPS_IFUNC(void, modresume, (void))
DEFINE_VMMOPS_IFUNC(void *, init, (struct vm *vm, struct pmap *pmap))
DEFINE_VMMOPS_IFUNC(int, run, (void *vcpui, register_t rip, struct pmap *pmap,
    struct vm_eventinfo *info,
    struct vmm_startup_entry_owner *entry_owner))
DEFINE_VMMOPS_IFUNC(int, handle_internal_exit, (void *vcpui))
DEFINE_VMMOPS_IFUNC(void, cleanup, (void *vmi))
DEFINE_VMMOPS_IFUNC(void *, vcpu_init, (void *vmi, struct vcpu *vcpu,
    int vcpu_id))
DEFINE_VMMOPS_IFUNC(bool, startup_kernel_actions_ready, (void))
DEFINE_VMMOPS_IFUNC(int, vcpu_startup_event_step, (void *vcpui,
    enum vmm_startup_dispatch_result *result))
DEFINE_VMMOPS_IFUNC(int, vcpu_event_cleanup_check, (void *vcpui))
DEFINE_VMMOPS_IFUNC(int, vcpu_event_cleanup, (void *vcpui))
DEFINE_VMMOPS_IFUNC(void, vcpu_cleanup, (void *vcpui))
DEFINE_VMMOPS_IFUNC(int, getreg, (void *vcpui, int num, uint64_t *retval))
DEFINE_VMMOPS_IFUNC(int, setreg, (void *vcpui, int num, uint64_t val))
DEFINE_VMMOPS_IFUNC(int, getdesc, (void *vcpui, int num, struct seg_desc *desc))
DEFINE_VMMOPS_IFUNC(int, setdesc, (void *vcpui, int num, struct seg_desc *desc))
DEFINE_VMMOPS_IFUNC(int, getcap, (void *vcpui, int num, int *retval))
DEFINE_VMMOPS_IFUNC(int, setcap, (void *vcpui, int num, int val))
DEFINE_VMMOPS_IFUNC(int, get_cpu_compat, (void *vcpui,
    struct vm_cpu_compat *compat))
DEFINE_VMMOPS_IFUNC(struct vmspace *, vmspace_alloc, (vm_offset_t min,
    vm_offset_t max))
DEFINE_VMMOPS_IFUNC(void, vmspace_free, (struct vmspace *vmspace))
DEFINE_VMMOPS_IFUNC(struct vlapic *, vlapic_init, (void *vcpui))
DEFINE_VMMOPS_IFUNC(void, vlapic_cleanup, (struct vlapic *vlapic))
#ifdef BHYVE_SNAPSHOT
DEFINE_VMMOPS_IFUNC(int, vm_snapshot, (void *vmi,
    struct vm_snapshot_meta *meta))
DEFINE_VMMOPS_IFUNC(int, vcpu_snapshot, (void *vcpui,
    struct vm_snapshot_meta *meta))
DEFINE_VMMOPS_IFUNC(int, vm_snapshot_complete, (void *vmi,
    struct vm_snapshot_meta *meta, int status))
DEFINE_VMMOPS_IFUNC(int, restore_tsc, (void *vcpui, uint64_t now))
#endif

SDT_PROVIDER_DEFINE(vmm);

/*
 * Internal exits are consumed entirely by the architecture backend and are
 * therefore invisible to the userspace vm_run() loop.  Keep this probe in the
 * architecture-neutral VMM namespace so nested-VMX/SVM handling can be
 * observed without making consumers depend on a backend-private structure.
 */
SDT_PROBE_DEFINE2(vmm, kernel, internal_exit, handled,
    "struct vcpu *", "int");

/*
 * VMM control-plane lifecycle probes (distinct from the vmx/svm exit-tracing
 * probes above).  These observe the security-relevant guest lifecycle and,
 * most notably, PCI passthrough — assigning a physical, DMA-capable device to
 * a guest, which hands hardware and an IOMMU domain to the VM.
 */
SDT_PROBE_DEFINE2(vmm, kernel, vm_create, create, "char *", "int");
SDT_PROBE_DEFINE1(vmm, kernel, vm_destroy, destroy, "char *");
SDT_PROBE_DEFINE5(vmm, kernel, vm_assign_pptdev, passthru__assign,
    "char *", "int", "int", "int", "int");
SDT_PROBE_DEFINE5(vmm, kernel, vm_unassign_pptdev, passthru__unassign,
    "char *", "int", "int", "int", "int");

static MALLOC_DEFINE(M_VM, "vm", "vm");

/* statistics */
static VMM_STAT(VCPU_TOTAL_RUNTIME, "vcpu total runtime");

SYSCTL_DECL(_hw_vmm);

/*
 * Halt the guest if all vcpus are executing a HLT instruction with
 * interrupts disabled.
 */
static int halt_detection_enabled = 1;
SYSCTL_INT(_hw_vmm, OID_AUTO, halt_detection, CTLFLAG_RDTUN,
    &halt_detection_enabled, 0,
    "Halt VM if all vcpus execute HLT with interrupts disabled");

static int trace_guest_exceptions;
SYSCTL_INT(_hw_vmm, OID_AUTO, trace_guest_exceptions, CTLFLAG_RDTUN,
    &trace_guest_exceptions, 0,
    "Trap into hypervisor on all guest exceptions and reflect them back");

static int trap_wbinvd;
SYSCTL_INT(_hw_vmm, OID_AUTO, trap_wbinvd, CTLFLAG_RDTUN, &trap_wbinvd, 0,
    "WBINVD triggers a VM-exit");

/* global statistics */
VMM_STAT(VCPU_MIGRATIONS, "vcpu migration across host cpus");
VMM_STAT(VMEXIT_COUNT, "total number of vm exits");
VMM_STAT(VMEXIT_EXTINT, "vm exits due to external interrupt");
VMM_STAT(VMEXIT_EXTINT_INVALID,
    "external-interrupt vm exits with invalid interruption information");
VMM_STAT(VMEXIT_HLT, "number of times hlt was intercepted");
VMM_STAT(VMEXIT_CR_ACCESS, "number of times %cr access was intercepted");
VMM_STAT(VMEXIT_RDMSR, "number of times rdmsr was intercepted");
VMM_STAT(VMEXIT_WRMSR, "number of times wrmsr was intercepted");
VMM_STAT(VMEXIT_MTRAP, "number of monitor trap exits");
VMM_STAT(VMEXIT_PAUSE, "number of times pause was intercepted");
VMM_STAT(VMEXIT_INTR_WINDOW, "vm exits due to interrupt window opening");
VMM_STAT(VMEXIT_NMI_WINDOW, "vm exits due to nmi window opening");
VMM_STAT(VMEXIT_INOUT, "number of times in/out was intercepted");
VMM_STAT(VMEXIT_CPUID, "number of times cpuid was intercepted");
VMM_STAT(VMEXIT_NESTED_FAULT, "vm exits due to nested page fault");
VMM_STAT(VMEXIT_INST_EMUL, "vm exits for instruction emulation");
VMM_STAT(VMEXIT_UNKNOWN, "number of vm exits for unknown reason");
VMM_STAT(VMEXIT_ASTPENDING, "number of times astpending at exit");
VMM_STAT(VMEXIT_REQIDLE, "number of times idle requested at exit");
VMM_STAT(VMEXIT_USERSPACE, "number of vm exits handled in userspace");
VMM_STAT(VMEXIT_RENDEZVOUS, "number of times rendezvous pending at exit");
VMM_STAT(VMEXIT_EXCEPTION, "number of vm exits due to exceptions");

static void
vcpu_cleanup(struct vcpu *vcpu, bool destroy)
{
	vmmops_vlapic_cleanup(vcpu->vlapic);
	vmmops_vcpu_cleanup(vcpu->cookie);
	vcpu->cookie = NULL;
	if (destroy) {
		vmm_stat_free(vcpu->stats);
		fpu_save_area_free(vcpu->guestfpu);
		mtx_destroy(&vcpu->event_mtx);
		vcpu_lock_destroy(vcpu);
		free(vcpu, M_VM);
	}
}

static int
vm_vcpu_event_cleanup(struct vm *vm)
{
	int error, i;

	/*
	 * Event-owner cleanup may call into a VM-wide coordinator.  Prove every
	 * target is frozen before the first architecture callback so an invalid
	 * caller cannot partially release a multi-vCPU lifetime.
	 */
	for (i = 0; i < vm->maxcpus; i++) {
		if (vm->vcpu[i] != NULL &&
		    vcpu_get_state(vm->vcpu[i], NULL) != VCPU_FROZEN)
			return (EBUSY);
	}
	for (i = 0; i < vm->maxcpus; i++) {
		if (vm->vcpu[i] == NULL)
			continue;
		error = vmmops_vcpu_event_cleanup_check(
		    vm->vcpu[i]->cookie);
		if (error != 0)
			return (error);
	}
	for (i = 0; i < vm->maxcpus; i++) {
		if (vm->vcpu[i] == NULL)
			continue;
		error = vmmops_vcpu_event_cleanup(vm->vcpu[i]->cookie);
		if (error != 0)
			panic("%s: event owner changed after preflight on vCPU %d: %d",
			    __func__, i, error);
	}
	return (0);
}

static struct vcpu *
vcpu_alloc(struct vm *vm, int vcpu_id)
{
	struct vcpu *vcpu;

	KASSERT(vcpu_id >= 0 && vcpu_id < vm->maxcpus,
	    ("vcpu_init: invalid vcpu %d", vcpu_id));

	vcpu = malloc(sizeof(*vcpu), M_VM, M_WAITOK | M_ZERO);
	vcpu_lock_init(vcpu);
	mtx_init(&vcpu->event_mtx, "vcpu event", NULL, MTX_SPIN);
	vcpu->state = VCPU_IDLE;
	vcpu->hostcpu = NOCPU;
	vcpu->vcpuid = vcpu_id;
	vcpu->vm = vm;
	vcpu->guestfpu = fpu_save_area_alloc();
	vcpu->stats = vmm_stat_alloc();
	vcpu->tsc_offset = 0;
	return (vcpu);
}

static void
vcpu_init(struct vcpu *vcpu)
{
	vcpu->cookie = vmmops_vcpu_init(vcpu->vm->cookie, vcpu, vcpu->vcpuid);
	vcpu->vlapic = vmmops_vlapic_init(vcpu->cookie);
	vm_set_x2apic_state(vcpu, X2APIC_DISABLED);
	vcpu->reqidle = 0;
	vcpu->exitintinfo = 0;
	vcpu->nmi_pending = 0;
	vcpu->extint_pending = 0;
	vcpu->exception_pending = 0;
	vcpu->exception_injecting = 0;
	vcpu->exc_class = VM_EXCEPTION_NONE;
	vm_event_generation_advance(vcpu->vm);
	vcpu->guest_xcr0 = XFEATURE_ENABLED_X87;
	fpu_save_area_reset(vcpu->guestfpu);
	vmm_stat_init(vcpu->stats);
}

int
vcpu_trace_exceptions(struct vcpu *vcpu)
{
	return (trace_guest_exceptions);
}

int
vcpu_trap_wbinvd(struct vcpu *vcpu)
{
	return (trap_wbinvd);
}

struct vm_exit *
vm_exitinfo(struct vcpu *vcpu)
{
	return (&vcpu->exitinfo);
}

cpuset_t *
vm_exitinfo_cpuset(struct vcpu *vcpu)
{
	return (&vcpu->exitinfo_cpuset);
}

int
vmm_modinit(void)
{
	int error;

	if (!vmm_is_hw_supported())
		return (ENXIO);

	vmm_host_state_init();

	vmm_ipinum = lapic_ipi_alloc(pti ? &IDTVEC(justreturn1_pti) :
	    &IDTVEC(justreturn));
	if (vmm_ipinum < 0)
		vmm_ipinum = IPI_AST;

	vmm_suspend_p = vmmops_modsuspend;
	vmm_resume_p = vmmops_modresume;

	error = vmmops_modinit(vmm_ipinum);
	if (error != 0) {
		/*
		 * Backend initialization never became externally usable.  Undo
		 * the common publications and the common interrupt allocation so
		 * a rejected module load cannot leave callable VMM hooks or lose
		 * an IPI vector.  Backend-private partial setup is rolled back by
		 * the backend before it returns an error.
		 */
		vmm_suspend_p = NULL;
		vmm_resume_p = NULL;
		if (vmm_ipinum != IPI_AST)
			lapic_ipi_free(vmm_ipinum);
		vmm_ipinum = IPI_AST;
	}
	return (error);
}

int
vmm_modcleanup(void)
{
	vmm_suspend_p = NULL;
	vmm_resume_p = NULL;
	iommu_cleanup();
	if (vmm_ipinum != IPI_AST)
		lapic_ipi_free(vmm_ipinum);
	return (vmmops_modcleanup());
}

static void
vm_init(struct vm *vm, bool create)
{
	vm->cookie = vmmops_init(vm, vmspace_pmap(vm_vmspace(vm)));
	vm->iommu = NULL;
	vm->vioapic = vioapic_init(vm);
	vm->vhpet = vhpet_init(vm);
	vm->vatpic = vatpic_init(vm);
	vm->vatpit = vatpit_init(vm);
	vm->vpmtmr = vpmtmr_init(vm);
	if (create) {
		vm->vrtc = vrtc_init(vm);
		vm->vpvclock = vpvclock_init(vm);
	}

	CPU_ZERO(&vm->active_cpus);
	CPU_ZERO(&vm->debug_cpus);
	CPU_ZERO(&vm->startup_cpus);

	vm->suspend = 0;
	CPU_ZERO(&vm->suspended_cpus);

	if (!create) {
		for (int i = 0; i < vm->maxcpus; i++) {
			if (vm->vcpu[i] != NULL)
				vcpu_init(vm->vcpu[i]);
		}
	}
}

struct vcpu *
vm_alloc_vcpu(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= vm_get_maxcpus(vm))
		return (NULL);

	vcpu = (struct vcpu *)
	    atomic_load_acq_ptr((uintptr_t *)&vm->vcpu[vcpuid]);
	if (__predict_true(vcpu != NULL))
		return (vcpu);

	sx_xlock(&vm->vcpus_init_lock);
	vcpu = vm->vcpu[vcpuid];
	if (vcpu == NULL && !vm->dying) {
		vcpu = vcpu_alloc(vm, vcpuid);
		vcpu_init(vcpu);

		/*
		 * Ensure vCPU is fully created before updating pointer
		 * to permit unlocked reads above.
		 */
		atomic_store_rel_ptr((uintptr_t *)&vm->vcpu[vcpuid],
		    (uintptr_t)vcpu);
	}
	sx_xunlock(&vm->vcpus_init_lock);
	return (vcpu);
}

int
vm_create(const char *name, struct vm **retvm)
{
	struct vm *vm;
	int error;

	vm = malloc(sizeof(struct vm), M_VM, M_WAITOK | M_ZERO);
	vm->sockets = 1;
	vm->cores = 1;		/* XXX backwards compatibility */
	vm->threads = 1;	/* XXX backwards compatibility */
	error = vm_event_coordinator_init(vm, vm_maxcpu);
	if (error != 0) {
		free(vm, M_VM);
		return (error);
	}
	error = vm_mem_init(&vm->mem, 0, VM_MAXUSER_ADDRESS_LA48);
	if (error != 0) {
		vm_event_coordinator_cleanup(vm);
		free(vm, M_VM);
		return (error);
	}
	strcpy(vm->name, name);
	mtx_init(&vm->rendezvous_mtx, "vm rendezvous lock", 0, MTX_DEF);
	sx_init(&vm->vcpus_init_lock, "vm vcpus");
	vm->vcpu = malloc(sizeof(*vm->vcpu) * vm->maxcpus, M_VM, M_WAITOK |
	    M_ZERO);

	vm_init(vm, true);

	*retvm = vm;
	SDT_PROBE2(vmm, kernel, vm_create, create, vm->name, 0);
	return (0);
}

static int
vm_cleanup(struct vm *vm, bool destroy)
{
	int error;

	if (destroy)
		vm_xlock_memsegs(vm);
	else
		vm_assert_memseg_xlocked(vm);

	error = ppt_unassign_all(vm);
	if (error != 0) {
		if (destroy)
			vm_unlock_memsegs(vm);
		return (error);
	}

	if (vm->iommu != NULL)
		iommu_destroy_domain(vm->iommu);

	if (destroy) {
		vrtc_cleanup(vm->vrtc);
		vpvclock_cleanup(vm->vpvclock);
		vm->vpvclock = NULL;
	} else
		vrtc_reset(vm->vrtc);
	vpmtmr_cleanup(vm->vpmtmr);
	vatpit_cleanup(vm->vatpit);
	vhpet_cleanup(vm->vhpet);
	vatpic_cleanup(vm->vatpic);
	vioapic_cleanup(vm->vioapic);

	for (int i = 0; i < vm->maxcpus; i++) {
		if (vm->vcpu[i] != NULL)
			vcpu_cleanup(vm->vcpu[i], destroy);
	}

	vmmops_cleanup(vm->cookie);

	vm_mem_cleanup(vm);

	if (destroy) {
		vm_mem_destroy(vm);

		free(vm->vcpu, M_VM);
		sx_destroy(&vm->vcpus_init_lock);
		mtx_destroy(&vm->rendezvous_mtx);
	}
	return (0);
}

int
vm_destroy_preflight(struct vm *vm)
{
	int error;

	/*
	 * Passthrough teardown is the only recoverable part of vm_cleanup().
	 * Do it while the VM device still exists so an IOMMU detach failure can
	 * be returned instead of panicking after VM bookkeeping is destroyed.
	 */
	vm_xlock_memsegs(vm);
	error = ppt_unassign_all(vm);
	vm_unlock_memsegs(vm);
	return (error);
}

void
vm_destroy(struct vm *vm)
{
	int error;

	SDT_PROBE1(vmm, kernel, vm_destroy, destroy, vm->name);
	error = vm_vcpu_event_cleanup(vm);
	if (error != 0)
		panic("%s: cannot release architecture event owner: %d",
		    __func__, error);
	vm_event_coordinator_cleanup(vm);
	error = vm_cleanup(vm, true);
	if (error != 0)
		panic("%s: cannot tear down passthrough devices: %d", __func__,
		    error);
	free(vm, M_VM);
}

int
vm_reset(struct vm *vm)
{
	int error;

	error = vm_vcpu_event_cleanup(vm);
	if (error != 0)
		return (error);
	error = vm_event_coordinator_reset(vm);
	if (error != 0)
		return (error);
	error = vm_cleanup(vm, false);
	if (error != 0)
		return (error);
	vm_init(vm, false);
	return (0);
}

int
vm_map_mmio(struct vm *vm, vm_paddr_t gpa, size_t len, vm_paddr_t hpa)
{
	return (vmm_mmio_alloc(vm_vmspace(vm), gpa, len, hpa));
}

int
vm_unmap_mmio(struct vm *vm, vm_paddr_t gpa, size_t len)
{

	vmm_mmio_free(vm_vmspace(vm), gpa, len);
	return (0);
}

static int
vm_iommu_unmap(struct vm *vm);

static int
vm_iommu_map(struct vm *vm)
{
	pmap_t pmap;
	vm_paddr_t gpa, hpa;
	struct vm_mem_map *mm;
	int error, i;

	sx_assert(&vm->mem.mem_segs_lock, SX_LOCKED);

	pmap = vmspace_pmap(vm_vmspace(vm));
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm->mem.mem_maps[i];
		if (!vm_memseg_sysmem(vm, mm->segid))
			continue;

		KASSERT((mm->flags & VM_MEMMAP_F_IOMMU) == 0,
		    ("iommu map found invalid memmap %#lx/%#lx/%#x",
		    mm->gpa, mm->len, mm->flags));
		if ((mm->flags & VM_MEMMAP_F_WIRED) == 0)
			continue;
		/*
		 * Mark the complete segment before installing its page mappings so
		 * that a failure below has a single, idempotent rollback path.  The
		 * mapping wrapper validates that each successful call consumed the
		 * whole PAGE_SIZE request.
		 */
		mm->flags |= VM_MEMMAP_F_IOMMU;

		for (gpa = mm->gpa; gpa < mm->gpa + mm->len; gpa += PAGE_SIZE) {
			hpa = pmap_extract(pmap, gpa);

			/*
			 * All mappings in the vmm vmspace must be
			 * present since they are managed by vmm in this way.
			 * Because we are in pass-through mode, the
			 * mappings must also be wired.  This implies
			 * that all pages must be mapped and wired,
			 * allowing to use pmap_extract() and avoiding the
			 * need to use vm_gpa_hold_global().
			 *
			 * This could change if/when we start
			 * supporting page faults on IOMMU maps.
			 */
			KASSERT(vm_page_wired(PHYS_TO_VM_PAGE(hpa)),
			    ("vm_iommu_map: vm %p gpa %jx hpa %jx not wired",
			    vm, (uintmax_t)gpa, (uintmax_t)hpa));

			error = iommu_create_mapping(vm->iommu, gpa, hpa, PAGE_SIZE);
			if (error != 0)
				goto rollback;
		}
	}

	error = iommu_invalidate_tlb(vm->iommu);
	if (error != 0)
		goto rollback;
	return (0);

rollback:
	/*
	 * Do not leave an assigned device with a partial DMA view of guest
	 * memory.  vm_iommu_unmap() clears every segment marked above and
	 * invalidates the same domain before the caller unwinds the assignment.
	 */
	(void)vm_iommu_unmap(vm);
	return (error);
}

static int
vm_iommu_unmap(struct vm *vm)
{
	vm_paddr_t gpa;
	struct vm_mem_map *mm;
	int error, first_error, i;

	sx_assert(&vm->mem.mem_segs_lock, SX_LOCKED);
	first_error = 0;

	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm->mem.mem_maps[i];
		if (!vm_memseg_sysmem(vm, mm->segid))
			continue;

		if ((mm->flags & VM_MEMMAP_F_IOMMU) == 0)
			continue;
		KASSERT((mm->flags & VM_MEMMAP_F_WIRED) != 0,
		    ("iommu unmap found invalid memmap %#lx/%#lx/%#x",
		    mm->gpa, mm->len, mm->flags));

		for (gpa = mm->gpa; gpa < mm->gpa + mm->len; gpa += PAGE_SIZE) {
			KASSERT(vm_page_wired(PHYS_TO_VM_PAGE(pmap_extract(
			    vmspace_pmap(vm_vmspace(vm)), gpa))),
			    ("vm_iommu_unmap: vm %p gpa %jx not wired",
			    vm, (uintmax_t)gpa));
			error = iommu_remove_mapping(vm->iommu, gpa, PAGE_SIZE);
			if (error != 0 && first_error == 0)
				first_error = error;
		}
		/* The domain is destroyed after the final device is detached. */
		mm->flags &= ~VM_MEMMAP_F_IOMMU;
	}

	/*
	 * Invalidate the cached translations associated with the domain
	 * from which pages were removed.
	 */
	error = iommu_invalidate_tlb(vm->iommu);
	return (first_error != 0 ? first_error : error);
}

int
vm_unassign_pptdev(struct vm *vm, int bus, int slot, int func)
{
	int error, unassign_error;

	unassign_error = ppt_unassign_device(vm, bus, slot, func);
	if (unassign_error != 0 && ppt_assigned_devices(vm) != 0) {
		SDT_PROBE5(vmm, kernel, vm_unassign_pptdev, passthru__unassign,
		    vm->name, bus, slot, func, unassign_error);
		return (unassign_error);
	}

	if (ppt_assigned_devices(vm) == 0 && vm->iommu != NULL) {
		error = vm_iommu_unmap(vm);
		/*
		 * A domain is per active passthrough assignment.  Destroy it even
		 * after an unmap error: no device remains attached to it and retaining
		 * it would make the next assignment hit vm_assign_pptdev()'s NULL
		 * invariant with stale translation state.
		 */
		iommu_destroy_domain(vm->iommu);
		vm->iommu = NULL;
	} else
		error = 0;

	SDT_PROBE5(vmm, kernel, vm_unassign_pptdev, passthru__unassign, vm->name,
	    bus, slot, func, (unassign_error != 0 ? unassign_error : error));
	return (unassign_error != 0 ? unassign_error : error);
}

int
vm_assign_pptdev(struct vm *vm, int bus, int slot, int func)
{
	int error;
	vm_paddr_t maxaddr;
	bool map = false;

	/* Set up the IOMMU to do the 'gpa' to 'hpa' translation */
	if (ppt_assigned_devices(vm) == 0) {
		KASSERT(vm->iommu == NULL,
		    ("vm_assign_pptdev: iommu must be NULL"));
		maxaddr = vmm_sysmem_maxaddr(vm);
		vm->iommu = iommu_create_domain(maxaddr);
		if (vm->iommu == NULL)
			return (ENXIO);
		map = true;
	}

	error = ppt_assign_device(vm, bus, slot, func);
	if (error != 0) {
		if (map) {
			iommu_destroy_domain(vm->iommu);
			vm->iommu = NULL;
		}
		return (error);
	}
	if (map) {
		error = vm_iommu_map(vm);
		if (error != 0)
			(void)vm_unassign_pptdev(vm, bus, slot, func);
	}
	SDT_PROBE5(vmm, kernel, vm_assign_pptdev, passthru__assign, vm->name,
	    bus, slot, func, error);
	return (error);
}

int
vm_get_register(struct vcpu *vcpu, int reg, uint64_t *retval)
{
	/* Negative values represent VM control structure fields. */
	if (reg >= VM_REG_LAST)
		return (EINVAL);

	return (vmmops_getreg(vcpu->cookie, reg, retval));
}

int
vm_set_register(struct vcpu *vcpu, int reg, uint64_t val)
{
	int error;

	/* Negative values represent VM control structure fields. */
	if (reg >= VM_REG_LAST)
		return (EINVAL);

	error = vmmops_setreg(vcpu->cookie, reg, val);
	if (error || reg != VM_REG_GUEST_RIP)
		return (error);

	vm_set_nextrip(vcpu, val);
	return (0);
}

void
vm_set_nextrip(struct vcpu *vcpu, uint64_t val)
{

	/*
	 * Synchronize only the machine-independent next-run cache.  A machine
	 * dependent backend may use this after it has transactionally restored
	 * an architectural RIP without going through vmmops_setreg() again.
	 */
	VMM_CTR1(vcpu, "Setting nextrip to %#lx", val);
	vcpu->nextrip = val;
}

int
vm_get_instruction_completion(struct vcpu *vcpu, uint64_t *rip,
    uint32_t *inst_length, uint64_t *nextrip)
{

	if (vcpu == NULL || rip == NULL || inst_length == NULL ||
	    nextrip == NULL || vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EINVAL);
	/*
	 * The architecture-neutral decoder owns this tuple.  In particular,
	 * instruction length in a hardware EPT exit can be zero or undefined;
	 * exitinfo.inst_length is updated by the common decoder before the
	 * frozen machine-dependent continuation is re-entered.
	 */
	*rip = vcpu->exitinfo.rip;
	*inst_length = vcpu->exitinfo.inst_length;
	*nextrip = vcpu->nextrip;
	return (0);
}

static bool
is_descriptor_table(int reg)
{

	switch (reg) {
	case VM_REG_GUEST_IDTR:
	case VM_REG_GUEST_GDTR:
		return (true);
	default:
		return (false);
	}
}

static bool
is_segment_register(int reg)
{

	switch (reg) {
	case VM_REG_GUEST_ES:
	case VM_REG_GUEST_CS:
	case VM_REG_GUEST_SS:
	case VM_REG_GUEST_DS:
	case VM_REG_GUEST_FS:
	case VM_REG_GUEST_GS:
	case VM_REG_GUEST_TR:
	case VM_REG_GUEST_LDTR:
		return (true);
	default:
		return (false);
	}
}

int
vm_get_seg_desc(struct vcpu *vcpu, int reg, struct seg_desc *desc)
{

	if (!is_segment_register(reg) && !is_descriptor_table(reg))
		return (EINVAL);

	return (vmmops_getdesc(vcpu->cookie, reg, desc));
}

int
vm_set_seg_desc(struct vcpu *vcpu, int reg, struct seg_desc *desc)
{

	if (!is_segment_register(reg) && !is_descriptor_table(reg))
		return (EINVAL);

	return (vmmops_setdesc(vcpu->cookie, reg, desc));
}

static void
restore_guest_fpustate(struct vcpu *vcpu)
{

	/* flush host state to the pcb */
	fpuexit(curthread);

	/* restore guest FPU state */
	fpu_enable();
	fpurestore(vcpu->guestfpu);

	/* restore guest XCR0 if XSAVE is enabled in the host */
	if (rcr4() & CR4_XSAVE)
		load_xcr(0, vcpu->guest_xcr0);

	/*
	 * The FPU is now "dirty" with the guest's state so disable
	 * the FPU to trap any access by the host.
	 */
	fpu_disable();
}

static void
save_guest_fpustate(struct vcpu *vcpu)
{

	if ((rcr0() & CR0_TS) == 0)
		panic("fpu emulation not enabled in host!");

	/* save guest XCR0 and restore host XCR0 */
	if (rcr4() & CR4_XSAVE) {
		vcpu->guest_xcr0 = rxcr(0);
		load_xcr(0, vmm_get_host_xcr0());
	}

	/* save guest FPU state */
	fpu_enable();
	fpusave(vcpu->guestfpu);
	fpu_disable();
}

static VMM_STAT(VCPU_IDLE_TICKS, "number of ticks vcpu was idle");

static void
vcpu_require_state(struct vcpu *vcpu, enum vcpu_state newstate)
{
	int error;

	if ((error = vcpu_set_state(vcpu, newstate, false)) != 0)
		panic("Error %d setting state to %d\n", error, newstate);
}

static void
vcpu_require_state_locked(struct vcpu *vcpu, enum vcpu_state newstate)
{
	int error;

	if ((error = vcpu_set_state_locked(vcpu, newstate, false)) != 0)
		panic("Error %d setting state to %d", error, newstate);
}

/*
 * Emulate a guest 'hlt' by sleeping until the vcpu is ready to run.
 */
static int
vm_handle_hlt(struct vcpu *vcpu, bool intr_disabled, bool *retu)
{
	struct vm *vm = vcpu->vm;
	const char *wmesg;
	struct thread *td;
	int error, t, vcpuid, vcpu_halted, vm_halted;

	vcpuid = vcpu->vcpuid;
	vcpu_halted = 0;
	vm_halted = 0;
	error = 0;
	td = curthread;

	KASSERT(!CPU_ISSET(vcpuid, &vm->halted_cpus), ("vcpu already halted"));

	vcpu_lock(vcpu);
	while (1) {
		/*
		 * Do a final check for pending NMI or interrupts before
		 * really putting this thread to sleep. Also check for
		 * software events that would cause this vcpu to wakeup.
		 *
		 * These interrupts/events could have happened after the
		 * vcpu returned from vmmops_run() and before it acquired the
		 * vcpu lock above.
		 */
		if (vm->rendezvous_func != NULL || vm->suspend || vcpu->reqidle)
			break;
		if (vm_nmi_pending(vcpu))
			break;
		if (!intr_disabled) {
			if (vm_extint_pending(vcpu) ||
			    vlapic_pending_intr(vcpu->vlapic, NULL)) {
				break;
			}
		}

		/* Don't go to sleep if the vcpu thread needs to yield */
		if (vcpu_should_yield(vcpu))
			break;

		if (vcpu_debugged(vcpu))
			break;

		/*
		 * Some Linux guests implement "halt" by having all vcpus
		 * execute HLT with interrupts disabled. 'halted_cpus' keeps
		 * track of the vcpus that have entered this state. When all
		 * vcpus enter the halted state the virtual machine is halted.
		 */
		if (intr_disabled) {
			wmesg = "vmhalt";
			VMM_CTR0(vcpu, "Halted");
			if (!vcpu_halted && halt_detection_enabled) {
				vcpu_halted = 1;
				CPU_SET_ATOMIC(vcpuid, &vm->halted_cpus);
			}
			if (CPU_CMP(&vm->halted_cpus, &vm->active_cpus) == 0) {
				vm_halted = 1;
				break;
			}
		} else {
			wmesg = "vmidle";
		}

		t = ticks;
		vcpu_require_state_locked(vcpu, VCPU_SLEEPING);
		/*
		 * XXX msleep_spin() cannot be interrupted by signals so
		 * wake up periodically to check pending signals.
		 */
		msleep_spin(vcpu, &vcpu->mtx, wmesg, hz);
		vcpu_require_state_locked(vcpu, VCPU_FROZEN);
		vmm_stat_incr(vcpu, VCPU_IDLE_TICKS, ticks - t);
		if (td_ast_pending(td, TDA_SUSPEND)) {
			vcpu_unlock(vcpu);
			error = thread_check_susp(td, false);
			if (error != 0) {
				if (vcpu_halted) {
					CPU_CLR_ATOMIC(vcpuid,
					    &vm->halted_cpus);
				}
				return (error);
			}
			vcpu_lock(vcpu);
		}
	}

	if (vcpu_halted)
		CPU_CLR_ATOMIC(vcpuid, &vm->halted_cpus);

	vcpu_unlock(vcpu);

	if (vm_halted)
		vm_suspend(vm, VM_SUSPEND_HALT);

	return (0);
}

static int
vm_handle_paging(struct vcpu *vcpu, bool *retu)
{
	struct vm *vm = vcpu->vm;
	int rv, ftype;
	struct vm_map *map;
	struct vm_exit *vme;

	vme = &vcpu->exitinfo;

	KASSERT(vme->inst_length == 0, ("%s: invalid inst_length %d",
	    __func__, vme->inst_length));

	ftype = vme->u.paging.fault_type;
	KASSERT(ftype == VM_PROT_READ ||
	    ftype == VM_PROT_WRITE || ftype == VM_PROT_EXECUTE,
	    ("vm_handle_paging: invalid fault_type %d", ftype));

	if (ftype == VM_PROT_READ || ftype == VM_PROT_WRITE) {
		rv = pmap_emulate_accessed_dirty(vmspace_pmap(vm_vmspace(vm)),
		    vme->u.paging.gpa, ftype);
		if (rv == 0) {
			VMM_CTR2(vcpu, "%s bit emulation for gpa %#lx",
			    ftype == VM_PROT_READ ? "accessed" : "dirty",
			    vme->u.paging.gpa);
			goto done;
		}
	}

	map = &vm_vmspace(vm)->vm_map;
	rv = vm_fault(map, vme->u.paging.gpa, ftype, VM_FAULT_NORMAL, NULL);

	VMM_CTR3(vcpu, "vm_handle_paging rv = %d, gpa = %#lx, "
	    "ftype = %d", rv, vme->u.paging.gpa, ftype);

	if (rv != KERN_SUCCESS)
		return (EFAULT);
done:
	return (0);
}

static int
vm_handle_internal_exit(struct vcpu *vcpu)
{
	int error;

	KASSERT(vcpu_get_state(vcpu, NULL) == VCPU_FROZEN,
	    ("%s: vCPU is not frozen", __func__));
	KASSERT(vcpu->exitinfo.inst_length == 0,
	    ("%s: invalid inst_length %d", __func__,
	    vcpu->exitinfo.inst_length));

	error = vmmops_handle_internal_exit(vcpu->cookie);
	VMM_CTR1(vcpu, "internal frozen-vCPU handler returned %d", error);
	SDT_PROBE2(vmm, kernel, internal_exit, handled, vcpu, error);
	return (error);
}

static int
vm_handle_inst_emul(struct vcpu *vcpu, bool *retu)
{
	struct vie *vie;
	struct vm_exit *vme;
	uint64_t gla, gpa, cs_base;
	struct vm_guest_paging *paging;
	mem_region_read_t mread;
	mem_region_write_t mwrite;
	enum vm_cpu_mode cpu_mode;
	int cs_d, error, fault;

	vme = &vcpu->exitinfo;

	KASSERT(vme->inst_length == 0, ("%s: invalid inst_length %d",
	    __func__, vme->inst_length));

	gla = vme->u.inst_emul.gla;
	gpa = vme->u.inst_emul.gpa;
	cs_base = vme->u.inst_emul.cs_base;
	cs_d = vme->u.inst_emul.cs_d;
	vie = &vme->u.inst_emul.vie;
	paging = &vme->u.inst_emul.paging;
	cpu_mode = paging->cpu_mode;

	VMM_CTR1(vcpu, "inst_emul fault accessing gpa %#lx", gpa);

	/* Fetch, decode and emulate the faulting instruction */
	if (vie->num_valid == 0) {
		error = vmm_fetch_instruction(vcpu, paging, vme->rip + cs_base,
		    VIE_INST_SIZE, vie, &fault);
	} else {
		/*
		 * The instruction bytes have already been copied into 'vie'
		 */
		error = fault = 0;
	}
	if (error || fault)
		return (error);

	if (vmm_decode_instruction(vcpu, gla, cpu_mode, cs_d, vie) != 0) {
		VMM_CTR1(vcpu, "Error decoding instruction at %#lx",
		    vme->rip + cs_base);
		*retu = true;	    /* dump instruction bytes in userspace */
		return (0);
	}

	/*
	 * Update 'nextrip' based on the length of the emulated instruction.
	 */
	vme->inst_length = vie->num_processed;
	vcpu->nextrip += vie->num_processed;
	VMM_CTR1(vcpu, "nextrip updated to %#lx after instruction decoding",
	    vcpu->nextrip);

	/* return to userland unless this is an in-kernel emulated device */
	if (gpa >= DEFAULT_APIC_BASE && gpa < DEFAULT_APIC_BASE + PAGE_SIZE) {
		mread = lapic_mmio_read;
		mwrite = lapic_mmio_write;
	} else if (gpa >= VIOAPIC_BASE && gpa < VIOAPIC_BASE + VIOAPIC_SIZE) {
		mread = vioapic_mmio_read;
		mwrite = vioapic_mmio_write;
	} else if (gpa >= VHPET_BASE && gpa < VHPET_BASE + VHPET_SIZE) {
		mread = vhpet_mmio_read;
		mwrite = vhpet_mmio_write;
	} else {
		*retu = true;
		return (0);
	}

	error = vmm_emulate_instruction(vcpu, gpa, vie, paging, mread, mwrite,
	    retu);

	return (error);
}

static int
vm_handle_suspend(struct vcpu *vcpu, bool *retu)
{
	struct vm *vm = vcpu->vm;
	int error, i;
	struct thread *td;

	error = 0;
	td = curthread;

	CPU_SET_ATOMIC(vcpu->vcpuid, &vm->suspended_cpus);

	/*
	 * Wait until all 'active_cpus' have suspended themselves.
	 *
	 * Since a VM may be suspended at any time including when one or
	 * more vcpus are doing a rendezvous we need to call the rendezvous
	 * handler while we are waiting to prevent a deadlock.
	 */
	vcpu_lock(vcpu);
	while (error == 0) {
		if (CPU_CMP(&vm->suspended_cpus, &vm->active_cpus) == 0) {
			VMM_CTR0(vcpu, "All vcpus suspended");
			break;
		}

		if (vm->rendezvous_func == NULL) {
			VMM_CTR0(vcpu, "Sleeping during suspend");
			vcpu_require_state_locked(vcpu, VCPU_SLEEPING);
			msleep_spin(vcpu, &vcpu->mtx, "vmsusp", hz);
			vcpu_require_state_locked(vcpu, VCPU_FROZEN);
			if (td_ast_pending(td, TDA_SUSPEND)) {
				vcpu_unlock(vcpu);
				error = thread_check_susp(td, false);
				vcpu_lock(vcpu);
			}
		} else {
			VMM_CTR0(vcpu, "Rendezvous during suspend");
			vcpu_unlock(vcpu);
			error = vm_handle_rendezvous(vcpu);
			vcpu_lock(vcpu);
		}
	}
	vcpu_unlock(vcpu);

	/*
	 * Wakeup the other sleeping vcpus and return to userspace.
	 */
	for (i = 0; i < vm->maxcpus; i++) {
		if (CPU_ISSET(i, &vm->suspended_cpus)) {
			vcpu_notify_event(vm_vcpu(vm, i));
		}
	}

	*retu = true;
	return (error);
}

static int
vm_handle_reqidle(struct vcpu *vcpu, bool *retu)
{
	vcpu_lock(vcpu);
	KASSERT(vcpu->reqidle, ("invalid vcpu reqidle %d", vcpu->reqidle));
	vcpu->reqidle = 0;
	vcpu_unlock(vcpu);
	*retu = true;
	return (0);
}

/*
 * Resolve one kernel-owned startup event while the target is frozen, before
 * looking at its wait-for-SIPI predicate.  In particular, a SIPI published to
 * a prestarted AP must not leave that AP asleep behind the old startup mask.
 *
 * This is intentionally only the common frozen dispatcher/admission edge.
 * vm_run() retains a stack-owned entry owner only for an ENTER_GUEST
	 * admission, and passes it to the machine backend.  Ordinary L1 VMX and
	 * initial, resumed, and hot L2 VMX consume the owner at their real
	 * hardware-entry/no-entry boundaries.  Backends that have not completed
	 * that conversion keep their readiness callback false.
 */
static int
vm_startup_kernel_entry_action(struct vcpu *vcpu,
    enum vmm_startup_entry_action *action,
    struct vmm_startup_entry_admission *admissionp)
{
	struct vmm_startup_entry_admission admission;
	struct vmm_startup_entry_snapshot before, after;
	enum vmm_startup_dispatch_result dispatch;
	uint64_t generation_before, generation_after;
	int error;

	if (vcpu == NULL || action == NULL || admissionp == NULL)
		return (EINVAL);
	/*
	 * An admission is meaningful only for ENTER_GUEST.  Clear the output before
	 * any early replay, wait, or lifecycle disposition so no caller can reuse a
	 * prior stack value as an entry authorization.
	 */
	memset(admissionp, 0, sizeof(*admissionp));
	error = vcpu_startup_entry_observation(vcpu, &before,
	    &generation_before);
	if (error != 0)
		return (error);
	error = vmm_startup_entry_pre_dispatch(&before, action);
	if (error != 0 || *action != VMM_STARTUP_ENTRY_DISPATCH)
		return (error);
	error = vmmops_vcpu_startup_event_step(vcpu->cookie, &dispatch);
	if (error != 0)
		return (error);
	error = vcpu_startup_entry_observation(vcpu, &after,
	    &generation_after);
	if (error != 0)
		return (error);
	memset(&admission, 0, sizeof(admission));
	error = vmm_startup_entry_dispatch_admit(&before, &after, dispatch,
	    generation_before, generation_after, &admission);
	if (error != 0)
		return (error);
	*action = admission.action;
	*admissionp = admission;
	return (0);
}

/*
 * Sleep a prestarted AP without entering guest context.  rendezvous_mtx and
 * the vCPU spin owner jointly close the startup predicate-to-enqueue window;
 * publishers clear startup_cpus under rendezvous_mtx and notify through the
 * same vCPU owner after releasing it.  The raw sleepqueue is interruptible,
 * so signals do not require the historical one-second polling workaround.
 */
static int
vm_handle_startup_wait(struct vcpu *vcpu, bool *retu)
{
	struct thread *td;
	struct vm *vm;
	bool debugged, rendezvous, reqidle, suspended, waiting;
	int error;

	vm = vcpu->vm;
	td = curthread;
	*retu = false;
	for (;;) {
		mtx_lock(&vm->rendezvous_mtx);
		vcpu_lock(vcpu);
		waiting = CPU_ISSET(vcpu->vcpuid, &vm->startup_cpus);
		rendezvous = vm->rendezvous_func != NULL;
		suspended = vm->suspend != VM_SUSPEND_NONE;
		reqidle = vcpu->reqidle != 0;
		debugged = vcpu_debugged(vcpu);
		if (!waiting || rendezvous || suspended || reqidle ||
		    debugged) {
			vcpu_unlock(vcpu);
			mtx_unlock(&vm->rendezvous_mtx);
			/*
			 * Lifecycle requests observed in the same snapshot take
			 * precedence over a concurrently accepted SIPI.  Returning on
			 * !waiting first could otherwise re-enter the machine-dependent
			 * run path once before servicing an already-pending rendezvous,
			 * suspend, reqidle, or debugger request.
			 */
			if (rendezvous) {
				error = vm_handle_rendezvous(vcpu);
				if (error != 0)
					return (error);
				continue;
			}
			if (suspended) {
				vm_exit_suspended(vcpu, vcpu->nextrip);
				return (vm_handle_suspend(vcpu, retu));
			}
			if (reqidle) {
				vm_exit_reqidle(vcpu, vcpu->nextrip);
				return (vm_handle_reqidle(vcpu, retu));
			}
			if (debugged) {
				vm_exit_debug(vcpu, vcpu->nextrip);
				*retu = true;
				return (0);
			}
			KASSERT(!waiting,
			    ("%s: no startup-wait disposition", __func__));
			return (0);
		}

		sleepq_lock(vcpu);
		sleepq_add(vcpu, NULL, "vmstart", SLEEPQ_SLEEP |
		    SLEEPQ_INTERRUPTIBLE, 0);
		vcpu_require_state_locked(vcpu, VCPU_SLEEPING);
		mtx_unlock(&vm->rendezvous_mtx);
		vcpu_unlock(vcpu);
		DROP_GIANT();
		/* Interruptibility is carried by SLEEPQ_INTERRUPTIBLE, not pri. */
		error = sleepq_wait_sig(vcpu, 0);
		PICKUP_GIANT();
		vcpu_lock(vcpu);
		vcpu_require_state_locked(vcpu, VCPU_FROZEN);
		vcpu_unlock(vcpu);
		if (error != 0)
			return (error);
		if (td_ast_pending(td, TDA_SUSPEND)) {
			error = thread_check_susp(td, false);
			if (error != 0)
				return (error);
		}
		/* A wake requests a complete predicate replay. */
	}
}

static int
vm_handle_db(struct vcpu *vcpu, struct vm_exit *vme, bool *retu)
{
	int error, fault;
	uint64_t rsp;
	uint64_t rflags;
	struct vm_copyinfo copyinfo[2];

	*retu = true;
	if (!vme->u.dbg.pushf_intercept || vme->u.dbg.tf_shadow_val != 0) {
		return (0);
	}

	vm_get_register(vcpu, VM_REG_GUEST_RSP, &rsp);
	error = vm_copy_setup(vcpu, &vme->u.dbg.paging, rsp, sizeof(uint64_t),
	    VM_PROT_RW, copyinfo, nitems(copyinfo), &fault);
	if (error != 0 || fault != 0) {
		*retu = false;
		return (EINVAL);
	}

	/* Read pushed rflags value from top of stack. */
	vm_copyin(copyinfo, &rflags, sizeof(uint64_t));

	/* Clear TF bit. */
	rflags &= ~(PSL_T);

	/* Write updated value back to memory. */
	vm_copyout(&rflags, copyinfo, sizeof(uint64_t));
	vm_copy_teardown(copyinfo, nitems(copyinfo));

	return (0);
}

void
vm_exit_suspended(struct vcpu *vcpu, uint64_t rip)
{
	struct vm *vm = vcpu->vm;
	struct vm_exit *vmexit;

	KASSERT(vm->suspend > VM_SUSPEND_NONE && vm->suspend < VM_SUSPEND_LAST,
	    ("vm_exit_suspended: invalid suspend type %u", vm->suspend));

	vmexit = vm_exitinfo(vcpu);
	vmexit->rip = rip;
	vmexit->inst_length = 0;
	vmexit->exitcode = VM_EXITCODE_SUSPENDED;
	vmexit->u.suspended.how = vm->suspend;
}

void
vm_exit_debug(struct vcpu *vcpu, uint64_t rip)
{
	struct vm_exit *vmexit;

	vmexit = vm_exitinfo(vcpu);
	vmexit->rip = rip;
	vmexit->inst_length = 0;
	vmexit->exitcode = VM_EXITCODE_DEBUG;
}

void
vm_exit_rendezvous(struct vcpu *vcpu, uint64_t rip)
{
	struct vm_exit *vmexit;

	vmexit = vm_exitinfo(vcpu);
	vmexit->rip = rip;
	vmexit->inst_length = 0;
	vmexit->exitcode = VM_EXITCODE_RENDEZVOUS;
	vmm_stat_incr(vcpu, VMEXIT_RENDEZVOUS, 1);
}

void
vm_exit_reqidle(struct vcpu *vcpu, uint64_t rip)
{
	struct vm_exit *vmexit;

	vmexit = vm_exitinfo(vcpu);
	vmexit->rip = rip;
	vmexit->inst_length = 0;
	vmexit->exitcode = VM_EXITCODE_REQIDLE;
	vmm_stat_incr(vcpu, VMEXIT_REQIDLE, 1);
}

void
vm_exit_astpending(struct vcpu *vcpu, uint64_t rip)
{
	struct vm_exit *vmexit;

	vmexit = vm_exitinfo(vcpu);
	vmexit->rip = rip;
	vmexit->inst_length = 0;
	vmexit->exitcode = VM_EXITCODE_BOGUS;
	vmm_stat_incr(vcpu, VMEXIT_ASTPENDING, 1);
}

/*
 * A pvclock MSR write was recorded during exit emulation (inside the critical
 * section) and its guest-page publish is deferred.  Bounce out of the arch run
 * loop with a BOGUS exit so vm_run() reaches vpvclock_commit() after
 * critical_exit(); userspace treats BOGUS as "just re-enter", so the publish
 * lands before the guest executes another instruction.
 */
void
vm_exit_pvclock(struct vcpu *vcpu, uint64_t rip)
{
	struct vm_exit *vmexit;

	vmexit = vm_exitinfo(vcpu);
	vmexit->rip = rip;
	vmexit->inst_length = 0;
	vmexit->exitcode = VM_EXITCODE_BOGUS;
}

int
vm_run(struct vcpu *vcpu)
{
	struct vm *vm = vcpu->vm;
	struct vm_eventinfo evinfo;
	struct vmm_startup_entry_admission startup_admission;
	struct vmm_startup_entry_loop_result startup_result;
	struct vmm_startup_entry_owner startup_owner;
	struct vmm_startup_event_run_token startup_token;
	struct vmm_startup_handshake_status startup_status;
	enum vmm_startup_entry_action startup_action;
	int error, vcpuid;
	struct pcb *pcb;
	uint64_t tscval;
	struct vm_exit *vme;
	bool retu, intr_disabled, startup_owner_active;
	pmap_t pmap;

	vcpuid = vcpu->vcpuid;

	if (!CPU_ISSET(vcpuid, &vm->active_cpus))
		return (EINVAL);

	if (CPU_ISSET(vcpuid, &vm->suspended_cpus))
		return (EINVAL);

	error = vm_startup_execution_status(vm, &startup_status);
	if (error != 0)
		return (error);

	pmap = vmspace_pmap(vm_vmspace(vm));
	vme = &vcpu->exitinfo;
	evinfo.rptr = &vm->rendezvous_req_cpus;
	evinfo.sptr = &vm->suspend;
	evinfo.iptr = &vcpu->reqidle;
restart:
	/*
	 * Both the startup gate and the machine-dependent run path can fail
	 * before assigning a userspace disposition.  Initialize it at the common
	 * restart boundary so the diagnostic tail never depends on a callee
	 * having touched stack state.
	 */
	retu = false;
	startup_owner_active = false;
	memset(&startup_admission, 0, sizeof(startup_admission));
	memset(&startup_owner, 0, sizeof(startup_owner));
	if (startup_status.mode.owner == VMM_STARTUP_OWNER_KERNEL) {
		error = vm_startup_kernel_entry_action(vcpu, &startup_action,
		    &startup_admission);
		if (error != 0)
			goto done;
		if (startup_action == VMM_STARTUP_ENTRY_REPLAY)
			goto restart;
		if (startup_action != VMM_STARTUP_ENTRY_ENTER_GUEST)
			error = vm_handle_startup_wait(vcpu, &retu);
		if (error != 0 || retu)
			goto done;
		if (startup_action != VMM_STARTUP_ENTRY_ENTER_GUEST)
			goto restart;
		error = vcpu_startup_event_run_token_capture(vcpu,
		    &startup_token);
		if (error != 0)
			goto done;
		error = vmm_startup_entry_owner_admit(&startup_token,
		    &startup_admission, &startup_owner);
		if (error != 0)
			goto done;
		startup_owner_active = true;
	}
	/*
	 * A machine-dependent run error bypasses exit dispatch but still reaches
	 * the common diagnostic below.  Initialize the userspace disposition at
	 * every restart so an adapter error cannot expose stale stack state to
	 * tracing (and a prior in-kernel iteration cannot leak its disposition).
	 */
	if (startup_owner_active) {
		error = vmm_startup_entry_owner_enter_critical(&startup_owner);
		if (error != 0)
			/*
			 * Admission has already consumed a coordinator token.  There is
			 * no return-safe cleanup path before the owner has entered the
			 * critical/FPU/retirement sequence; jumping to done would strand
			 * that token and permit a later startup operation to observe an
			 * ambiguous owner.  This transition can fail only if the
			 * just-admitted stack-owned state violates its own contract, so
			 * treat it like the later owner-transition failures.
			 */
			panic("%s: invalid startup owner before critical entry", __func__);
	}
	critical_enter();

	KASSERT(!CPU_ISSET(curcpu, &pmap->pm_active),
	    ("vm_run: absurd pm_active"));

	tscval = rdtsc();

	pcb = PCPU_GET(curpcb);
	set_pcb_flags(pcb, PCB_FULL_IRET);

	if (startup_owner_active &&
	    vmm_startup_entry_owner_restore_guest_fpu(&startup_owner) != 0)
		panic("%s: invalid startup owner before guest FPU restore", __func__);
	restore_guest_fpustate(vcpu);

	if (startup_owner_active &&
	    vmm_startup_entry_owner_publish_running(&startup_owner) != 0)
		panic("%s: invalid startup owner before VCPU_RUNNING", __func__);
	vcpu_require_state(vcpu, VCPU_RUNNING);
	error = vmmops_run(vcpu->cookie, vcpu->nextrip, pmap, &evinfo,
	    startup_owner_active ? &startup_owner : NULL);
	vcpu_require_state(vcpu, VCPU_FROZEN);
	if (startup_owner_active) {
		/*
		 * A backend that has not consumed the owner cannot leave a live
		 * RUNNING/RECHECK transaction on the stack.  This is presently the
		 * expected fail-closed outcome while backend conversion is staged.
		 */
		if (startup_owner.phase == VMM_STARTUP_ENTRY_OWNER_RUNNING ||
		    startup_owner.phase == VMM_STARTUP_ENTRY_OWNER_RECHECK) {
			int owner_error;

			owner_error = error == 0 ? EPROTO : error;
			if (vmm_startup_entry_owner_fail_before_entry(&startup_owner,
			    owner_error, &startup_result) != 0)
				panic("%s: unconsumed startup owner", __func__);
		}
		if (startup_owner.phase != VMM_STARTUP_ENTRY_OWNER_RETURNABLE)
			panic("%s: backend returned with live startup owner", __func__);
		if (vmm_startup_entry_owner_publish_frozen(&startup_owner) != 0)
			panic("%s: invalid startup owner after VCPU_FROZEN", __func__);
	}

	save_guest_fpustate(vcpu);
	if (startup_owner_active &&
	    vmm_startup_entry_owner_save_guest_fpu(&startup_owner) != 0)
		panic("%s: invalid startup owner after guest FPU save", __func__);

	vmm_stat_incr(vcpu, VCPU_TOTAL_RUNTIME, rdtsc() - tscval);

	critical_exit();

	/*
	 * Publish any pvclock state the guest programmed via MSR writes during
	 * this exit.  The MSR handlers run inside the critical section above
	 * and may only record state; the sleepable guest-page mapping happens
	 * here, before the loop can re-enter vmmops_run (the arch run loops
	 * guarantee a return to this point whenever a publish is pending).
	 */
	vpvclock_commit(vcpu);
	if (startup_owner_active) {
		if (vmm_startup_entry_owner_exit_critical(&startup_owner) != 0 ||
		    vcpu_startup_entry_owner_retire(vcpu, &startup_owner,
		    &startup_result) != 0)
			panic("%s: startup owner retirement failed", __func__);
		switch (startup_result.action) {
		case VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT:
		case VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT:
			error = 0;
			break;
		case VMM_STARTUP_ENTRY_LOOP_REPLAY:
			error = EAGAIN;
			break;
		case VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR:
			error = startup_result.error;
			break;
		default:
			panic("%s: invalid startup owner result", __func__);
		}
	}
	if (startup_owner_active && error == EAGAIN)
		goto restart;

	if (error == 0) {
		vcpu->nextrip = vme->rip + vme->inst_length;
		switch (vme->exitcode) {
		case VM_EXITCODE_REQIDLE:
			error = vm_handle_reqidle(vcpu, &retu);
			break;
		case VM_EXITCODE_SUSPENDED:
			error = vm_handle_suspend(vcpu, &retu);
			break;
		case VM_EXITCODE_IOAPIC_EOI:
			vioapic_process_eoi(vm, vme->u.ioapic_eoi.vector);
			break;
		case VM_EXITCODE_RENDEZVOUS:
			error = vm_handle_rendezvous(vcpu);
			break;
		case VM_EXITCODE_HLT:
			intr_disabled = ((vme->u.hlt.rflags & PSL_I) == 0);
			error = vm_handle_hlt(vcpu, intr_disabled, &retu);
			break;
		case VM_EXITCODE_PAGING:
			error = vm_handle_paging(vcpu, &retu);
			break;
		case VM_EXITCODE_VMM_INTERNAL:
			error = vm_handle_internal_exit(vcpu);
			break;
		case VM_EXITCODE_INST_EMUL:
			error = vm_handle_inst_emul(vcpu, &retu);
			break;
		case VM_EXITCODE_INOUT:
		case VM_EXITCODE_INOUT_STR:
			error = vm_handle_inout(vcpu, vme, &retu);
			break;
		case VM_EXITCODE_DB:
			error = vm_handle_db(vcpu, vme, &retu);
			break;
		case VM_EXITCODE_MONITOR:
		case VM_EXITCODE_MWAIT:
		case VM_EXITCODE_VMINSN:
			vm_inject_ud(vcpu);
			break;
		default:
			retu = true;	/* handled in userland */
			break;
		}
	}

	/*
	 * VM_EXITCODE_INST_EMUL could access the apic which could transform the
	 * exit code into VM_EXITCODE_IPI.
	 */
	if (error == 0 && vme->exitcode == VM_EXITCODE_IPI)
		error = vm_handle_ipi(vcpu, vme, &retu);

	if (error == 0 && retu == false)
		goto restart;

done:
	vmm_stat_incr(vcpu, VMEXIT_USERSPACE, 1);
	VMM_CTR2(vcpu, "retu %d/%d", error, vme->exitcode);

	return (error);
}

struct vm_restart_plan {
	enum vcpu_state state;
	uint64_t rip;
};

static int
vm_restart_instruction_prepare(struct vcpu *vcpu,
    struct vm_restart_plan *plan)
{
	int error;

	plan->state = vcpu_get_state(vcpu, NULL);
	plan->rip = 0;
	if (plan->state == VCPU_RUNNING)
		return (0);
	if (plan->state != VCPU_FROZEN)
		return (EBUSY);
	error = vm_get_register(vcpu, VM_REG_GUEST_RIP, &plan->rip);
	return (error);
}

static void
vm_restart_instruction_apply(struct vcpu *vcpu,
    const struct vm_restart_plan *plan)
{

	if (plan->state == VCPU_RUNNING) {
		/*
		 * When a vcpu is "running" the next instruction is determined
		 * by adding 'rip' and 'inst_length' in the vcpu's 'exitinfo'.
		 * Thus setting 'inst_length' to zero will cause the current
		 * instruction to be restarted.
		 */
		vcpu->exitinfo.inst_length = 0;
		VMM_CTR1(vcpu, "restarting instruction at %#lx by "
		    "setting inst_length to zero", vcpu->exitinfo.rip);
	} else {
		/*
		 * When a vcpu is "frozen" it is outside the critical section
		 * around vmmops_run() and 'nextrip' points to the next
		 * instruction. Thus instruction restart is achieved by setting
		 * 'nextrip' to the vcpu's %rip.
		 */
		VMM_CTR2(vcpu, "restarting instruction by updating "
		    "nextrip from %#lx to %#lx", vcpu->nextrip, plan->rip);
		vcpu->nextrip = plan->rip;
	}
}

int
vm_restart_instruction(struct vcpu *vcpu)
{
	struct vm_restart_plan plan;
	int error;

	error = vm_restart_instruction_prepare(vcpu, &plan);
	if (error != 0)
		return (error);
	vm_restart_instruction_apply(vcpu, &plan);
	return (0);
}

int
vm_exit_intinfo(struct vcpu *vcpu, uint64_t info)
{
	struct vmm_event_ingress_ticket ticket;
	int error;
	int type, vector;

	if (info & VM_INTINFO_VALID) {
		type = info & VM_INTINFO_TYPE;
		vector = info & 0xff;
		if (type == VM_INTINFO_NMI && vector != IDT_NMI)
			return (EINVAL);
		if (type == VM_INTINFO_HWEXCEPTION && vector >= 32)
			return (EINVAL);
		if (info & VM_INTINFO_RSVD)
			return (EINVAL);
	} else {
		info = 0;
	}
	memset(&ticket, 0, sizeof(ticket));
	error = vmm_event_coordinator_publisher_enter(
	    vm_event_coordinator(vcpu->vm), vcpu->vcpuid, &ticket);
	if (error != 0)
		return (error);
	VMM_CTR2(vcpu, "%s: info1(%#lx)", __func__, info);
	vcpu_event_lock(vcpu);
	vcpu->exitintinfo = info;
	vcpu_event_generation_advance_locked(vcpu);
	vcpu_event_unlock(vcpu);
	vm_event_publisher_exit_checked(vcpu, &ticket);
	return (0);
}

static uint64_t
vcpu_exception_intinfo_locked(struct vcpu *vcpu)
{
	uint64_t info = 0;

	vcpu_event_assert(vcpu);
	if (vcpu->exception_pending) {
		info = vcpu->exc_vector & 0xff;
		info |= VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION;
		if (vcpu->exc_errcode_valid) {
			info |= VM_INTINFO_DEL_ERRCODE;
			info |= (uint64_t)vcpu->exc_errcode << 32;
		}
	}
	return (info);
}

static int
vm_entry_intinfo_peek_locked(struct vcpu *vcpu,
    struct vm_intinfo_snapshot *snapshot)
{
	struct vm_intinfo_plan plan;
	uint64_t info1, info2;
	int error;

	vcpu_event_assert(vcpu);
	info1 = vcpu->exitintinfo;
	info2 = vcpu_exception_intinfo_locked(vcpu);
	snapshot->exitintinfo = info1;
	snapshot->exception = info2;
	if (vcpu->exception_pending != 0) {
		if (vcpu->exc_class <= VM_EXCEPTION_NONE ||
		    vcpu->exc_class >= VM_EXCEPTION_CLASS_LAST)
			return (EINVAL);
		snapshot->exception_class = vcpu->exc_class;
	} else {
		if (vcpu->exc_class != VM_EXCEPTION_NONE)
			return (EINVAL);
		snapshot->exception_class = VM_EXCEPTION_NONE;
	}
	error = vm_intinfo_plan(info1, info2, &plan);
	if (error != 0)
		return (error);
	snapshot->entry = plan.entry;
	snapshot->valid = plan.valid;
	snapshot->triple_fault = plan.triple_fault;
	return (0);
}

int
vm_entry_intinfo_peek(struct vcpu *vcpu,
    struct vm_intinfo_snapshot *snapshot)
{
	struct vm_intinfo_snapshot candidate;
	int error;

	if (vcpu == NULL || snapshot == NULL)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	vcpu_event_lock(vcpu);
	error = vm_entry_intinfo_peek_locked(vcpu, &candidate);
	vcpu_event_unlock(vcpu);
	if (error == 0)
		*snapshot = candidate;
	return (error);
}

static void
vm_entry_intinfo_consume_locked(struct vcpu *vcpu,
    const struct vm_intinfo_snapshot *snapshot, uint64_t *exceptionp,
    int *vectorp)
{
	uint64_t exception;

	vcpu_event_assert(vcpu);
	exception = snapshot->exception;
	vcpu->exitintinfo = 0;
	*vectorp = vcpu->exc_vector;
	if ((exception & VM_INTINFO_VALID) != 0) {
		vcpu->exception_pending = 0;
		vcpu->exc_vector = 0;
		vcpu->exc_class = VM_EXCEPTION_NONE;
		vcpu->exc_errcode_valid = 0;
		vcpu->exc_errcode = 0;
	}
	vcpu_event_generation_advance_locked(vcpu);
	*exceptionp = exception;
}

int
vm_entry_intinfo_commit(struct vcpu *vcpu,
    const struct vm_intinfo_snapshot *snapshot)
{
	struct vm_intinfo_snapshot current;
	uint64_t exception;
	int error, vector __diagused;
	bool triple_fault, valid;

	if (vcpu == NULL || snapshot == NULL)
		return (EINVAL);
	memset(&current, 0, sizeof(current));
	vcpu_event_lock(vcpu);
	error = vm_entry_intinfo_peek_locked(vcpu, &current);
	if (error != 0)
		goto done;
	if (snapshot->exitintinfo != current.exitintinfo ||
	    snapshot->exception != current.exception ||
	    snapshot->exception_class != current.exception_class ||
	    snapshot->entry != current.entry ||
	    snapshot->valid != current.valid ||
	    snapshot->triple_fault != current.triple_fault) {
		error = EAGAIN;
		goto done;
	}

	vm_entry_intinfo_consume_locked(vcpu, snapshot, &exception, &vector);
	triple_fault = snapshot->triple_fault;
	valid = snapshot->valid;
	error = 0;
done:
	vcpu_event_unlock(vcpu);
	if (error != 0)
		return (error);
	if ((exception & VM_INTINFO_VALID) != 0)
		VMM_CTR2(vcpu, "Exception %d delivered: %#lx", vector,
		    exception);
	if (triple_fault) {
		VMM_CTR2(vcpu, "triple fault: info1(%#lx), info2(%#lx)",
		    snapshot->exitintinfo, snapshot->exception);
		vm_suspend(vcpu->vm, VM_SUSPEND_TRIPLEFAULT);
	}
	if (valid) {
		VMM_CTR4(vcpu, "%s: info1(%#lx), info2(%#lx), "
		    "retinfo(%#lx)", __func__, snapshot->exitintinfo,
		    snapshot->exception, snapshot->entry);
	}
	return (0);
}

int
vm_entry_intinfo(struct vcpu *vcpu, uint64_t *retinfo)
{
	struct vm_intinfo_snapshot snapshot;
	uint64_t exception;
	int error, vector __diagused;
	bool triple_fault, valid;

	if (retinfo == NULL)
		return (0);

	/*
	 * The compatibility helper has no error channel: its return value is the
	 * event-valid bit.  Keep peek and consumption under one lock so an async
	 * exception publisher cannot turn a recoverable EAGAIN into an ambiguous
	 * boolean result.  An internally invalid value is left untouched and the
	 * caller enters without consuming it; the transactional nested path uses
	 * the error-returning peek/commit API directly.
	 */
	memset(&snapshot, 0, sizeof(snapshot));
	vcpu_event_lock(vcpu);
	error = vm_entry_intinfo_peek_locked(vcpu, &snapshot);
	if (error == 0) {
		vm_entry_intinfo_consume_locked(vcpu, &snapshot, &exception,
		    &vector);
		triple_fault = snapshot.triple_fault;
		valid = snapshot.valid;
	}
	vcpu_event_unlock(vcpu);
	if (error != 0) {
		VMM_CTR2(vcpu, "%s: invalid pending event transaction %d",
		    __func__, error);
		return (0);
	}
	if ((exception & VM_INTINFO_VALID) != 0)
		VMM_CTR2(vcpu, "Exception %d delivered: %#lx", vector,
		    exception);
	if (triple_fault) {
		VMM_CTR2(vcpu, "triple fault: info1(%#lx), info2(%#lx)",
		    snapshot.exitintinfo, snapshot.exception);
		vm_suspend(vcpu->vm, VM_SUSPEND_TRIPLEFAULT);
	}
	if (valid) {
		VMM_CTR4(vcpu, "%s: info1(%#lx), info2(%#lx), "
		    "retinfo(%#lx)", __func__, snapshot.exitintinfo,
		    snapshot.exception, snapshot.entry);
	}
	*retinfo = snapshot.entry;
	return (valid);
}

int
vm_get_intinfo(struct vcpu *vcpu, uint64_t *info1, uint64_t *info2)
{
	if (vcpu == NULL || info1 == NULL || info2 == NULL)
		return (EINVAL);
	vcpu_event_lock(vcpu);
	*info1 = vcpu->exitintinfo;
	*info2 = vcpu_exception_intinfo_locked(vcpu);
	vcpu_event_unlock(vcpu);
	return (0);
}

static int
vm_event_state_capture_locked(struct vcpu *vcpu,
    struct vmm_event_state *candidate)
{

	vcpu_event_assert(vcpu);
	memset(candidate, 0, sizeof(*candidate));
	if (vcpu->exception_injecting != 0)
		return (EBUSY);
	candidate->exitintinfo = vcpu->exitintinfo;
	if (vcpu->nmi_pending != 0)
		candidate->flags |= VMM_EVENT_STATE_F_NMI_PENDING;
	if (vcpu->extint_pending != 0)
		candidate->flags |= VMM_EVENT_STATE_F_EXTINT_PENDING;
	if (vcpu->exception_pending != 0) {
		candidate->flags |= VMM_EVENT_STATE_F_EXCEPTION_PENDING;
		candidate->exception_vector = vcpu->exc_vector;
		switch (vcpu->exc_class) {
		case VM_EXCEPTION_FAULT:
			candidate->exception_class = VMM_EVENT_EXCEPTION_FAULT;
			break;
		case VM_EXCEPTION_TRAP:
			candidate->exception_class = VMM_EVENT_EXCEPTION_TRAP;
			break;
		case VM_EXCEPTION_ICEBP:
			candidate->exception_class = VMM_EVENT_EXCEPTION_ICEBP;
			break;
		case VM_EXCEPTION_TASK_SWITCH:
			candidate->exception_class =
			    VMM_EVENT_EXCEPTION_TASK_SWITCH;
			break;
		default:
			return (EINVAL);
		}
		if (vcpu->exc_errcode_valid != 0) {
			candidate->flags |= VMM_EVENT_STATE_F_EXCEPTION_ERROR;
			candidate->exception_error = vcpu->exc_errcode;
		}
	}
	return (0);
}

int
vm_event_state_compare_clear(struct vcpu *vcpu,
    const struct vmm_event_state *expected)
{
	struct vmm_event_ingress_ticket ticket;
	struct vmm_event_state current, expected_copy;
	int error;

	if (vcpu == NULL || expected == NULL)
		return (EINVAL);
	if (vm_event_output_overlaps_owner(vcpu->vm, expected,
	    sizeof(*expected)))
		return (EINVAL);
	expected_copy = *expected;
	error = vmm_event_state_validate(&expected_copy);
	if (error != 0)
		return (error);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);

	memset(&ticket, 0, sizeof(ticket));
	error = vmm_event_coordinator_publisher_enter(
	    vm_event_coordinator(vcpu->vm), vcpu->vcpuid, &ticket);
	if (error != 0)
		return (error);

	vcpu_event_lock(vcpu);
	error = vm_event_state_capture_locked(vcpu, &current);
	if (error == 0 && !vmm_event_state_equal(&current, &expected_copy))
		error = EAGAIN;
	if (error == 0) {
		vcpu->exitintinfo = 0;
		vcpu->nmi_pending = 0;
		vcpu->extint_pending = 0;
		vcpu->exception_pending = 0;
		vcpu->exception_injecting = 0;
		vcpu->exc_vector = 0;
		vcpu->exc_class = VM_EXCEPTION_NONE;
		vcpu->exc_errcode_valid = 0;
		vcpu->exc_errcode = 0;
		vcpu_event_generation_advance_locked(vcpu);
	}
	vcpu_event_unlock(vcpu);
	vm_event_publisher_exit_checked(vcpu, &ticket);
	return (error);
}

int
vm_event_state_capture(struct vcpu *vcpu, struct vmm_event_state *state)
{
	struct vmm_event_state candidate;
	int error;

	if (vcpu == NULL || state == NULL)
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);

	memset(&candidate, 0, sizeof(candidate));
	vcpu_event_lock(vcpu);
	error = vm_event_state_capture_locked(vcpu, &candidate);
	vcpu_event_unlock(vcpu);

	if (error == 0)
		error = vmm_event_state_validate(&candidate);
	if (error == 0)
		*state = candidate;
	return (error);
}

static bool
vm_event_output_overlaps_owner(struct vm *vm, const void *base, size_t length)
{
	struct vcpu *vcpu;
	uint16_t i, maxcpus;

	if (vmm_event_ranges_overlap(base, length, vm, sizeof(*vm)))
		return (true);
	maxcpus = vm_get_maxcpus(vm);
	for (i = 0; i < maxcpus; i++) {
		vcpu = vm_vcpu(vm, i);
		if (vcpu != NULL && vmm_event_ranges_overlap(base, length,
		    vcpu, sizeof(*vcpu)))
			return (true);
	}
	return (false);
}

int
vm_event_state_capture_all(struct vm *vm, uint32_t *instances,
    struct vmm_event_state *states, size_t capacity, size_t *countp)
{
	struct vmm_event_state *candidates;
	struct vcpu *vcpu;
	size_t count, index, instances_length, states_length;
	uint64_t generation;
	uint16_t i, maxcpus;
	int error;

	if (vm == NULL || countp == NULL || !sx_xlocked(&vm->vcpus_init_lock))
		return (EINVAL);
	count = 0;
	maxcpus = vm_get_maxcpus(vm);
	for (i = 0; i < maxcpus; i++) {
		vcpu = vm_vcpu(vm, i);
		if (vcpu == NULL)
			continue;
		if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
			return (EBUSY);
		count++;
	}
	if (count > capacity)
		return (E2BIG);
	if (count != 0 && (instances == NULL || states == NULL))
		return (EINVAL);
	instances_length = count * sizeof(*instances);
	states_length = count * sizeof(*states);
	if (!vmm_event_range_valid(instances, instances_length) ||
	    !vmm_event_range_valid(states, states_length) ||
	    !vmm_event_range_valid(countp, sizeof(*countp)) ||
	    vmm_event_ranges_overlap(instances, instances_length, states,
	    states_length) || vmm_event_ranges_overlap(instances,
	    instances_length, countp, sizeof(*countp)) ||
	    vmm_event_ranges_overlap(states, states_length, countp,
	    sizeof(*countp)) || vm_event_output_overlaps_owner(vm, instances,
	    instances_length) || vm_event_output_overlaps_owner(vm, states,
	    states_length) || vm_event_output_overlaps_owner(vm, countp,
	    sizeof(*countp)))
		return (EINVAL);

	candidates = NULL;
	if (count != 0) {
		candidates = mallocarray(count, sizeof(*candidates), M_VM,
		    M_NOWAIT | M_ZERO);
		if (candidates == NULL)
			return (ENOMEM);
	}
	/*
	 * The generation reads define this capture's linearization interval.
	 * They detect an event publisher that overlaps the per-vCPU captures;
	 * they do not quiesce a publisher after the final read.  A checkpoint
	 * coordinator must therefore keep external event ingress quiesced from
	 * successful capture through checkpoint publication or source teardown.
	 */
	generation = atomic_load_acq_64(&vm->event_generation);
	error = 0;
	index = 0;
	for (i = 0; i < maxcpus; i++) {
		vcpu = vm_vcpu(vm, i);
		if (vcpu == NULL)
			continue;
		error = vm_event_state_capture(vcpu, &candidates[index]);
		if (error != 0)
			break;
		index++;
	}
	if (error == 0)
		error = vmm_event_capture_commit_validate(generation,
		    atomic_load_acq_64(&vm->event_generation), count, index);
	if (error != 0) {
		if (candidates != NULL) {
			explicit_bzero(candidates,
			    malloc_usable_size(candidates));
			free(candidates, M_VM);
		}
		return (error);
	}

	index = 0;
	for (i = 0; i < maxcpus; i++) {
		if (vm_vcpu(vm, i) != NULL)
			instances[index++] = i;
	}
	if (states_length != 0)
		memcpy(states, candidates, states_length);
	*countp = count;
	if (candidates != NULL) {
		explicit_bzero(candidates, malloc_usable_size(candidates));
		free(candidates, M_VM);
	}
	return (0);
}

int
vm_event_state_restore(struct vcpu *vcpu,
    const struct vmm_event_state *state)
{
	enum vm_exception_class exception_class;
	struct vmm_event_ingress_ticket ticket;
	int error;

	if (vcpu == NULL || state == NULL)
		return (EINVAL);
	error = vmm_event_state_validate(state);
	if (error != 0)
		return (error);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);

	switch (state->exception_class) {
	case VMM_EVENT_EXCEPTION_NONE:
		exception_class = VM_EXCEPTION_NONE;
		break;
	case VMM_EVENT_EXCEPTION_FAULT:
		exception_class = VM_EXCEPTION_FAULT;
		break;
	case VMM_EVENT_EXCEPTION_TRAP:
		exception_class = VM_EXCEPTION_TRAP;
		break;
	case VMM_EVENT_EXCEPTION_ICEBP:
		exception_class = VM_EXCEPTION_ICEBP;
		break;
	case VMM_EVENT_EXCEPTION_TASK_SWITCH:
		exception_class = VM_EXCEPTION_TASK_SWITCH;
		break;
	default:
		return (EINVAL);
	}
	memset(&ticket, 0, sizeof(ticket));
	error = vmm_event_coordinator_publisher_enter(
	    vm_event_coordinator(vcpu->vm), vcpu->vcpuid, &ticket);
	if (error != 0)
		return (error);

	vcpu_event_lock(vcpu);
	/*
	 * Restore is an ownership transfer, not an unconditional assignment.
	 * Never discard a destination event which arrived after the caller's
	 * preflight.  The all-vCPU VMS2 path performs the same check again under
	 * every destination event lock before its atomic publication.
	 */
	if (vcpu->exception_injecting != 0 ||
	    vcpu->exception_pending != 0 || vcpu->nmi_pending != 0 ||
	    vcpu->extint_pending != 0 || vcpu->exitintinfo != 0) {
		vcpu_event_unlock(vcpu);
		vm_event_publisher_exit_checked(vcpu, &ticket);
		return (EBUSY);
	}
	vcpu->exitintinfo = state->exitintinfo;
	vcpu->nmi_pending =
	    (state->flags & VMM_EVENT_STATE_F_NMI_PENDING) != 0;
	vcpu->extint_pending =
	    (state->flags & VMM_EVENT_STATE_F_EXTINT_PENDING) != 0;
	vcpu->exception_pending =
	    (state->flags & VMM_EVENT_STATE_F_EXCEPTION_PENDING) != 0;
	vcpu->exception_injecting = 0;
	vcpu->exc_vector = state->exception_vector;
	vcpu->exc_class = exception_class;
	vcpu->exc_errcode_valid =
	    (state->flags & VMM_EVENT_STATE_F_EXCEPTION_ERROR) != 0;
	vcpu->exc_errcode = state->exception_error;
	vcpu_event_generation_advance_locked(vcpu);
	vcpu_event_unlock(vcpu);
	vm_event_publisher_exit_checked(vcpu, &ticket);
	return (0);
}

int
vm_inject_exception_class(struct vcpu *vcpu, int vector, int errcode_valid,
    uint32_t errcode, int restart_instruction,
    enum vm_exception_class exception_class)
{
	struct vm_restart_plan restart_plan;
	struct vmm_event_ingress_ticket ticket;
	uint64_t regval;
	int error, pending_vector __diagused;

	if (vector < 0 || vector >= 32 ||
	    exception_class <= VM_EXCEPTION_NONE ||
	    exception_class >= VM_EXCEPTION_CLASS_LAST ||
	    ((exception_class == VM_EXCEPTION_ICEBP ||
	    exception_class == VM_EXCEPTION_TASK_SWITCH) && vector != IDT_DB))
		return (EINVAL);

	/*
	 * A double fault exception should never be injected directly into
	 * the guest. It is a derived exception that results from specific
	 * combinations of nested faults.
	 */
	if (vector == IDT_DF)
		return (EINVAL);

	memset(&ticket, 0, sizeof(ticket));
	error = vmm_event_coordinator_publisher_enter(
	    vm_event_coordinator(vcpu->vm), vcpu->vcpuid, &ticket);
	if (error != 0)
		return (error);

	vcpu_event_lock(vcpu);
	if (vcpu->exception_pending || vcpu->exception_injecting) {
		pending_vector = vcpu->exc_vector;
		(void)pending_vector;
		vcpu_event_unlock(vcpu);
		VMM_CTR2(vcpu, "Unable to inject exception %d due to "
		    "pending exception %d", vector, pending_vector);
		vm_event_publisher_exit_checked(vcpu, &ticket);
		return (EBUSY);
	}
	vcpu->exception_injecting = 1;
	vcpu_event_generation_advance_locked(vcpu);
	vcpu_event_unlock(vcpu);

	if (errcode_valid) {
		/*
		 * Exceptions don't deliver an error code in real mode.
		 */
		error = vm_get_register(vcpu, VM_REG_GUEST_CR0, &regval);
		if (error != 0)
			goto abort;
		if (!(regval & CR0_PE))
			errcode_valid = 0;
	}
	if (restart_instruction) {
		error = vm_restart_instruction_prepare(vcpu, &restart_plan);
		if (error != 0)
			goto abort;
	}

	/*
	 * From section 26.6.1 "Interruptibility State" in Intel SDM:
	 *
	 * Event blocking by "STI" or "MOV SS" is cleared after guest executes
	 * one instruction or incurs an exception.
	 */
	error = vm_set_register(vcpu, VM_REG_GUEST_INTR_SHADOW, 0);
	if (error != 0)
		goto abort;

	if (restart_instruction)
		vm_restart_instruction_apply(vcpu, &restart_plan);

	vcpu_event_lock(vcpu);
	KASSERT(vcpu->exception_injecting != 0 &&
	    vcpu->exception_pending == 0,
	    ("%s: exception producer serialization lost", __func__));
	vcpu->exc_vector = vector;
	vcpu->exc_class = exception_class;
	vcpu->exc_errcode = errcode;
	vcpu->exc_errcode_valid = errcode_valid;
	vcpu->exception_pending = 1;
	vcpu->exception_injecting = 0;
	vcpu_event_generation_advance_locked(vcpu);
	vcpu_event_unlock(vcpu);
	vm_event_publisher_exit_checked(vcpu, &ticket);
	VMM_CTR1(vcpu, "Exception %d pending", vector);
	return (0);

abort:
	/*
	 * Do not strand the private producer reservation when a machine backend
	 * rejects a prerequisite operation.  Only discard the reservation if it
	 * is still exactly the unpublished owner acquired above; an unexpected
	 * published owner is preserved and reported as a state conflict.
	 */
	vcpu_event_lock(vcpu);
	if (vcpu->exception_injecting != 0 &&
	    vcpu->exception_pending == 0) {
		vcpu->exception_injecting = 0;
		vcpu_event_generation_advance_locked(vcpu);
	} else {
		error = EBUSY;
	}
	vcpu_event_unlock(vcpu);
	vm_event_publisher_exit_checked(vcpu, &ticket);
	VMM_CTR2(vcpu, "%s: exception producer rollback error %d", __func__,
	    error);
	return (error);
}

int
vm_inject_exception(struct vcpu *vcpu, int vector, int errcode_valid,
    uint32_t errcode, int restart_instruction)
{
	enum vm_exception_class exception_class;

	/* Architecture adapters use vm_inject_exception_class() for mixed #DB. */
	if (vector == IDT_BP || vector == IDT_OF || vector == IDT_DB)
		exception_class = VM_EXCEPTION_TRAP;
	else
		exception_class = VM_EXCEPTION_FAULT;
	return (vm_inject_exception_class(vcpu, vector, errcode_valid, errcode,
	    restart_instruction, exception_class));
}

void
vm_inject_fault(struct vcpu *vcpu, int vector, int errcode_valid, int errcode)
{
	int error, restart_instruction;

	restart_instruction = 1;

	error = vm_inject_exception_class(vcpu, vector, errcode_valid,
	    errcode, restart_instruction, VM_EXCEPTION_FAULT);
	if (error != 0)
		panic("vm_inject_exception error %d", error);
}

void
vm_inject_pf(struct vcpu *vcpu, int error_code, uint64_t cr2)
{
	int error;

	VMM_CTR2(vcpu, "Injecting page fault: error_code %#x, cr2 %#lx",
	    error_code, cr2);

	error = vm_set_register(vcpu, VM_REG_GUEST_CR2, cr2);
	if (error != 0)
		panic("vm_set_register(cr2) error %d", error);

	vm_inject_fault(vcpu, IDT_PF, 1, error_code);
}

static VMM_STAT(VCPU_NMI_COUNT, "number of NMIs delivered to vcpu");

int
vm_inject_nmi(struct vcpu *vcpu)
{
	struct vmm_event_ingress_ticket ticket;
	bool deferred;
	int error;

	memset(&ticket, 0, sizeof(ticket));
	deferred = false;
	error = vmm_event_coordinator_publisher_enter_or_defer(
	    vm_event_coordinator(vcpu->vm), vcpu->vcpuid, &ticket,
	    VM_EVENT_DEFERRED_NMI, VM_EVENT_DEFERRED_VALID, &deferred);
	if (error != 0 || deferred)
		return (error);

	vcpu_event_lock(vcpu);
	vcpu->nmi_pending = 1;
	vcpu_event_generation_advance_locked(vcpu);
	vcpu_event_unlock(vcpu);
	vm_event_publisher_exit_checked(vcpu, &ticket);
	vcpu_notify_event(vcpu);
	return (0);
}

int
vm_nmi_pending(struct vcpu *vcpu)
{
	int pending;

	vcpu_event_lock(vcpu);
	pending = vcpu->nmi_pending;
	vcpu_event_unlock(vcpu);
	return (pending);
}

void
vm_nmi_clear(struct vcpu *vcpu)
{
	vcpu_event_lock(vcpu);
	if (vcpu->nmi_pending == 0)
		panic("vm_nmi_clear: inconsistent nmi_pending state");

	vcpu->nmi_pending = 0;
	vcpu_event_generation_advance_locked(vcpu);
	vcpu_event_unlock(vcpu);
	vmm_stat_incr(vcpu, VCPU_NMI_COUNT, 1);
}

static VMM_STAT(VCPU_EXTINT_COUNT, "number of ExtINTs delivered to vcpu");

int
vm_inject_extint(struct vcpu *vcpu)
{
	struct vmm_event_ingress_ticket ticket;
	bool deferred;
	int error;

	memset(&ticket, 0, sizeof(ticket));
	deferred = false;
	error = vmm_event_coordinator_publisher_enter_or_defer(
	    vm_event_coordinator(vcpu->vm), vcpu->vcpuid, &ticket,
	    VM_EVENT_DEFERRED_EXTINT, VM_EVENT_DEFERRED_VALID, &deferred);
	if (error != 0 || deferred)
		return (error);

	vcpu_event_lock(vcpu);
	vcpu->extint_pending = 1;
	vcpu_event_generation_advance_locked(vcpu);
	vcpu_event_unlock(vcpu);
	vm_event_publisher_exit_checked(vcpu, &ticket);
	vcpu_notify_event(vcpu);
	return (0);
}

int
vm_extint_pending(struct vcpu *vcpu)
{
	int pending;

	vcpu_event_lock(vcpu);
	pending = vcpu->extint_pending;
	vcpu_event_unlock(vcpu);
	return (pending);
}

void
vm_extint_clear(struct vcpu *vcpu)
{
	vcpu_event_lock(vcpu);
	if (vcpu->extint_pending == 0)
		panic("vm_extint_clear: inconsistent extint_pending state");

	vcpu->extint_pending = 0;
	vcpu_event_generation_advance_locked(vcpu);
	vcpu_event_unlock(vcpu);
	vmm_stat_incr(vcpu, VCPU_EXTINT_COUNT, 1);
}

int
vm_get_capability(struct vcpu *vcpu, int type, int *retval)
{
	if (type < 0 || type >= VM_CAP_MAX)
		return (EINVAL);

	return (vmmops_getcap(vcpu->cookie, type, retval));
}

int
vm_get_cpuid(struct vcpu *vcpu, uint32_t flags, uint32_t *eax, uint32_t *ebx,
    uint32_t *ecx, uint32_t *edx)
{
	uint64_t rax, rbx, rcx, rdx;
	int error;

	if ((flags & ~VM_CPUID_F_VALID) != 0 || eax == NULL || ebx == NULL ||
	    ecx == NULL || edx == NULL)
		return (EINVAL);
	rax = *eax;
	rbx = *ebx;
	rcx = *ecx;
	rdx = *edx;
	if ((flags & VM_CPUID_F_BASELINE) != 0)
		error = x86_emulate_cpuid_baseline(vcpu, &rax, &rbx, &rcx,
		    &rdx);
	else
		error = x86_emulate_cpuid(vcpu, &rax, &rbx, &rcx, &rdx);
	if (error == 0)
		return (EOPNOTSUPP);
	*eax = (uint32_t)rax;
	*ebx = (uint32_t)rbx;
	*ecx = (uint32_t)rcx;
	*edx = (uint32_t)rdx;
	return (0);
}

int
vm_get_cpu_compat(struct vcpu *vcpu, struct vm_cpu_compat *compat)
{
	const struct xsave_limits *limits;
	struct vm_cpu_compat candidate;
	int error;

	if (vcpu == NULL || compat == NULL)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.version = VM_CPU_COMPAT_VERSION;
	limits = vmm_get_xsave_limits();
	if (limits->xsave_enabled) {
		candidate.xcr0_allowed = limits->xcr0_allowed;
		candidate.xsave_max_size = limits->xsave_max_size;
	}
	candidate.x2apic_state = vcpu->x2apic_state;
	candidate.tsc_frequency = tsc_freq;
	error = vmmops_get_cpu_compat(vcpu->cookie, &candidate);
	if (error != 0)
		return (error);
	if (candidate.version != VM_CPU_COMPAT_VERSION ||
	    (candidate.flags & ~VM_CPU_COMPAT_F_VALID) != 0 ||
	    candidate.x2apic_state > X2APIC_ENABLED ||
	    candidate.tsc_frequency == 0)
		return (EPROTO);
	*compat = candidate;
	return (0);
}

int
vm_set_capability(struct vcpu *vcpu, int type, int val)
{
	if (type < 0 || type >= VM_CAP_MAX)
		return (EINVAL);

	return (vmmops_setcap(vcpu->cookie, type, val));
}

struct vlapic *
vm_lapic(struct vcpu *vcpu)
{
	return (vcpu->vlapic);
}

struct vioapic *
vm_ioapic(struct vm *vm)
{

	return (vm->vioapic);
}

struct vhpet *
vm_hpet(struct vm *vm)
{

	return (vm->vhpet);
}

bool
vmm_is_pptdev(int bus, int slot, int func)
{
	int b, f, i, n, s;
	char *val, *cp, *cp2;
	bool found;

	/*
	 * XXX
	 * The length of an environment variable is limited to 128 bytes which
	 * puts an upper limit on the number of passthru devices that may be
	 * specified using a single environment variable.
	 *
	 * Work around this by scanning multiple environment variable
	 * names instead of a single one - yuck!
	 */
	const char *names[] = { "pptdevs", "pptdevs2", "pptdevs3", NULL };

	/* set pptdevs="1/2/3 4/5/6 7/8/9 10/11/12" */
	found = false;
	for (i = 0; names[i] != NULL && !found; i++) {
		cp = val = kern_getenv(names[i]);
		while (cp != NULL && *cp != '\0') {
			if ((cp2 = strchr(cp, ' ')) != NULL)
				*cp2 = '\0';

			n = sscanf(cp, "%d/%d/%d", &b, &s, &f);
			if (n == 3 && bus == b && slot == s && func == f) {
				found = true;
				break;
			}

			if (cp2 != NULL)
				*cp2++ = ' ';

			cp = cp2;
		}
		freeenv(val);
	}
	return (found);
}

void *
vm_iommu_domain(struct vm *vm)
{

	return (vm->iommu);
}

/*
 * Returns the subset of vCPUs in tostart that are awaiting startup.
 * These vCPUs are also marked as no longer awaiting startup.
 */
cpuset_t
vm_start_cpus(struct vm *vm, const cpuset_t *tostart)
{
	cpuset_t set;
	int vcpuid;

	mtx_lock(&vm->rendezvous_mtx);
	CPU_AND(&set, &vm->startup_cpus, tostart);
	CPU_ANDNOT(&vm->startup_cpus, &vm->startup_cpus, &set);
	mtx_unlock(&vm->rendezvous_mtx);

	/*
	 * A kernel-owned startup target may already be asleep in
	 * vm_handle_startup_wait().  Notify only after dropping rendezvous_mtx:
	 * the waiter acquires the vCPU owner while holding rendezvous_mtx, so this
	 * order closes the predicate-to-enqueue race without reversing the common
	 * rendezvous_mtx -> vCPU owner order.  Historical userspace-owned startup
	 * normally has no sleeping target, making the notification harmless there.
	 */
	CPU_FOREACH_ISSET(vcpuid, &set) {
		KASSERT(vm_vcpu(vm, vcpuid) != NULL,
		    ("%s: missing startup target %d", __func__, vcpuid));
		vcpu_notify_event(vm_vcpu(vm, vcpuid));
	}
	return (set);
}

void
vm_publish_startup_wait(struct vm *vm, const cpuset_t *targets,
    const cpuset_t *waiting)
{
	cpuset_t bounded, invalid;

	/*
	 * Replace membership for exactly the supplied targets.  This primitive
	 * deliberately does not notify vCPU threads: its INIT caller follows
	 * publication with a target rendezvous, while inactive targets have no
	 * running thread to wake.  A different caller must provide an equivalent
	 * wake/serialization contract rather than treating this as a general
	 * scheduler interface.
	 */
	CPU_ANDNOT(&invalid, waiting, targets);
	KASSERT(CPU_EMPTY(&invalid),
	    ("%s: waiting vCPU is not a target", __func__));
	CPU_AND(&bounded, waiting, targets);
	mtx_lock(&vm->rendezvous_mtx);
	CPU_ANDNOT(&vm->startup_cpus, &vm->startup_cpus, targets);
	CPU_OR(&vm->startup_cpus, &vm->startup_cpus, &bounded);
	mtx_unlock(&vm->rendezvous_mtx);
}

void
vm_publish_startup_wait_rendezvous(struct vcpu *vcpu, bool waiting)
{
	struct vm *vm;

	KASSERT(vcpu != NULL, ("%s: missing vCPU", __func__));
	vm = vcpu_vm(vcpu);
	mtx_assert(&vm->rendezvous_mtx, MA_OWNED);
	/*
	 * The rendezvous participant is the target vCPU and is already awake.
	 * Therefore clearing wait-for-SIPI here needs no separate notification.
	 * Callers outside a target rendezvous must use the locking publication
	 * interfaces instead of acquiring this lock recursively.
	 */
	if (waiting)
		CPU_SET(vcpu_vcpuid(vcpu), &vm->startup_cpus);
	else
		CPU_CLR(vcpu_vcpuid(vcpu), &vm->startup_cpus);
}

int
vm_get_x2apic_state(struct vcpu *vcpu, enum x2apic_state *state)
{
	*state = vcpu->x2apic_state;

	return (0);
}

int
vm_set_x2apic_state(struct vcpu *vcpu, enum x2apic_state state)
{
	if (state >= X2APIC_STATE_LAST)
		return (EINVAL);

	vcpu->x2apic_state = state;

	vlapic_set_x2apic_state(vcpu, state);

	return (0);
}

void
vcpu_notify_lapic(struct vcpu *vcpu)
{
	vcpu_lock(vcpu);
	if (vcpu->state == VCPU_RUNNING && vcpu->hostcpu != curcpu)
		vlapic_post_intr(vcpu->vlapic, vcpu->hostcpu, vmm_ipinum);
	else
		vcpu_notify_event_locked(vcpu);
	vcpu_unlock(vcpu);
}

int
vm_apicid2vcpuid(struct vm *vm, int apicid)
{
	/*
	 * XXX apic id is assumed to be numerically identical to vcpu id
	 */
	return (apicid);
}

int
vm_smp_rendezvous(struct vcpu *vcpu, cpuset_t dest,
    vm_rendezvous_func_t func, void *arg)
{
	struct vm *vm = vcpu->vm;
	int error, i;

	/*
	 * Enforce that this function is called without any locks
	 */
	WITNESS_WARN(WARN_PANIC, NULL, "vm_smp_rendezvous");

restart:
	mtx_lock(&vm->rendezvous_mtx);
	if (vm->rendezvous_func != NULL) {
		/*
		 * If a rendezvous is already in progress then we need to
		 * call the rendezvous handler in case this 'vcpu' is one
		 * of the targets of the rendezvous.
		 */
		VMM_CTR0(vcpu, "Rendezvous already in progress");
		mtx_unlock(&vm->rendezvous_mtx);
		error = vm_handle_rendezvous(vcpu);
		if (error != 0)
			return (error);
		goto restart;
	}
	KASSERT(vm->rendezvous_func == NULL, ("vm_smp_rendezvous: previous "
	    "rendezvous is still in progress"));

	VMM_CTR0(vcpu, "Initiating rendezvous");
	vm->rendezvous_req_cpus = dest;
	CPU_ZERO(&vm->rendezvous_done_cpus);
	vm->rendezvous_arg = arg;
	vm->rendezvous_func = func;
	mtx_unlock(&vm->rendezvous_mtx);

	/*
	 * Wake up any sleeping vcpus and trigger a VM-exit in any running
	 * vcpus so they handle the rendezvous as soon as possible.
	 */
	for (i = 0; i < vm->maxcpus; i++) {
		if (CPU_ISSET(i, &dest))
			vcpu_notify_event(vm_vcpu(vm, i));
	}

	return (vm_handle_rendezvous(vcpu));
}

struct vatpic *
vm_atpic(struct vm *vm)
{
	return (vm->vatpic);
}

struct vatpit *
vm_atpit(struct vm *vm)
{
	return (vm->vatpit);
}

struct vpmtmr *
vm_pmtmr(struct vm *vm)
{

	return (vm->vpmtmr);
}

struct vrtc *
vm_rtc(struct vm *vm)
{

	return (vm->vrtc);
}

struct vpvclock *
vm_pvclock(struct vm *vm)
{

	return (vm->vpvclock);
}

uint64_t
vm_get_tsc_offset(struct vcpu *vcpu)
{

	return (vcpu->tsc_offset);
}

enum vm_reg_name
vm_segment_name(int seg)
{
	static enum vm_reg_name seg_names[] = {
		VM_REG_GUEST_ES,
		VM_REG_GUEST_CS,
		VM_REG_GUEST_SS,
		VM_REG_GUEST_DS,
		VM_REG_GUEST_FS,
		VM_REG_GUEST_GS
	};

	KASSERT(seg >= 0 && seg < nitems(seg_names),
	    ("%s: invalid segment encoding %d", __func__, seg));
	return (seg_names[seg]);
}

void
vm_copy_teardown(struct vm_copyinfo *copyinfo, int num_copyinfo)
{
	int idx;

	for (idx = 0; idx < num_copyinfo; idx++) {
		if (copyinfo[idx].cookie != NULL)
			vm_gpa_release(copyinfo[idx].cookie);
	}
	bzero(copyinfo, num_copyinfo * sizeof(struct vm_copyinfo));
}

int
vm_copy_setup(struct vcpu *vcpu, struct vm_guest_paging *paging,
    uint64_t gla, size_t len, int prot, struct vm_copyinfo *copyinfo,
    int num_copyinfo, int *fault)
{
	int error, idx, nused;
	size_t n, off, remaining;
	void *hva, *cookie;
	uint64_t gpa;

	bzero(copyinfo, sizeof(struct vm_copyinfo) * num_copyinfo);

	nused = 0;
	remaining = len;
	while (remaining > 0) {
		if (nused >= num_copyinfo)
			return (EFAULT);
		error = vm_gla2gpa(vcpu, paging, gla, prot, &gpa, fault);
		if (error || *fault)
			return (error);
		off = gpa & PAGE_MASK;
		n = min(remaining, PAGE_SIZE - off);
		copyinfo[nused].gpa = gpa;
		copyinfo[nused].len = n;
		remaining -= n;
		gla += n;
		nused++;
	}

	for (idx = 0; idx < nused; idx++) {
		hva = vm_gpa_hold(vcpu, copyinfo[idx].gpa,
		    copyinfo[idx].len, prot, &cookie);
		if (hva == NULL)
			break;
		copyinfo[idx].hva = hva;
		copyinfo[idx].cookie = cookie;
	}

	if (idx != nused) {
		vm_copy_teardown(copyinfo, num_copyinfo);
		return (EFAULT);
	} else {
		*fault = 0;
		return (0);
	}
}

void
vm_copyin(struct vm_copyinfo *copyinfo, void *kaddr, size_t len)
{
	char *dst;
	int idx;

	dst = kaddr;
	idx = 0;
	while (len > 0) {
		bcopy(copyinfo[idx].hva, dst, copyinfo[idx].len);
		len -= copyinfo[idx].len;
		dst += copyinfo[idx].len;
		idx++;
	}
}

void
vm_copyout(const void *kaddr, struct vm_copyinfo *copyinfo, size_t len)
{
	const char *src;
	int idx;

	src = kaddr;
	idx = 0;
	while (len > 0) {
		bcopy(src, copyinfo[idx].hva, copyinfo[idx].len);
		len -= copyinfo[idx].len;
		src += copyinfo[idx].len;
		idx++;
	}
}

/*
 * Return the amount of in-use and wired memory for the VM. Since
 * these are global stats, only return the values with for vCPU 0
 */
VMM_STAT_DECLARE(VMM_MEM_RESIDENT);
VMM_STAT_DECLARE(VMM_MEM_WIRED);

static void
vm_get_rescnt(struct vcpu *vcpu, struct vmm_stat_type *stat)
{

	if (vcpu->vcpuid == 0) {
		vmm_stat_set(vcpu, VMM_MEM_RESIDENT, PAGE_SIZE *
		    vmspace_resident_count(vm_vmspace(vcpu->vm)));
	}
}

static void
vm_get_wiredcnt(struct vcpu *vcpu, struct vmm_stat_type *stat)
{

	if (vcpu->vcpuid == 0) {
		vmm_stat_set(vcpu, VMM_MEM_WIRED, PAGE_SIZE *
		    pmap_wired_count(vmspace_pmap(vm_vmspace(vcpu->vm))));
	}
}

VMM_STAT_FUNC(VMM_MEM_RESIDENT, "Resident memory", vm_get_rescnt);
VMM_STAT_FUNC(VMM_MEM_WIRED, "Wired memory", vm_get_wiredcnt);

#ifdef BHYVE_SNAPSHOT
/*
 * Serialize the guest FPU/XSAVE save area.  Callers hold the vCPU frozen,
 * so vcpu->guestfpu is the authoritative register file written by
 * save_guest_fpustate() when the vCPU last stopped running, and the image
 * matches the host's XSAVE configuration (use_xsave/xsave_mask/
 * cpu_max_ext_state_size) that fpusave() used to produce it.
 */
static int
vm_snapshot_x86_fpu_capture(struct vcpu *vcpu,
    struct vmm_snapshot_vcpu_x86_fpu *fpu)
{
	size_t area_length;

	memset(fpu, 0, sizeof(*fpu));
	if (use_xsave) {
		area_length = cpu_max_ext_state_size;
		if (area_length < VMM_SNAPSHOT_X86_FPU_XSTATE_MIN ||
		    area_length > VMM_SNAPSHOT_X86_FPU_AREA_MAX)
			return (EOPNOTSUPP);
		fpu->flags = VMM_SNAPSHOT_X86_FPU_F_XSAVE;
		fpu->xsave_bitmap = xsave_mask;
	} else {
		area_length = sizeof(struct savefpu);
	}
	fpu->area_length = area_length;
	memcpy(fpu->area, vcpu->guestfpu, area_length);
	/*
	 * Fail closed rather than emit a record the codec cannot prove.  In
	 * particular, a host xsave_mask carrying a supervisor (IA32_XSS)
	 * component rejects the checkpoint here until the record format
	 * explicitly supports supervisor state; see the record definition in
	 * vmm_snapshot_x86_state.h.
	 */
	return (vmm_snapshot_vcpu_x86_fpu_validate(fpu));
}

/*
 * Land a validated FPU record where the runtime actually loads guest
 * vector state: the guestfpu save area consumed by restore_guest_fpustate()
 * on the next vCPU entry.  Restore preflight already proved the image fits
 * the destination and that XSTATE_BV is covered by the destination's
 * xsave_mask, so this publication step cannot fail.
 */
static void
vm_snapshot_x86_fpu_land(struct vcpu *vcpu,
    const struct vmm_snapshot_vcpu_x86_fpu *fpu)
{
	struct xstate_hdr *hdr;
	uint8_t *dst;
	size_t copy_length, dst_size;

	dst = (uint8_t *)vcpu->guestfpu;
	dst_size = use_xsave ? cpu_max_ext_state_size :
	    sizeof(struct savefpu);
	copy_length = fpu->area_length;
	if (copy_length > dst_size) {
		/*
		 * Preflight admits an image larger than the destination only
		 * when XSTATE_BV is confined to x87/SSE; the legacy region
		 * then carries the complete architectural state.
		 */
		copy_length = dst_size;
	}
	memcpy(dst, fpu->area, copy_length);
	if (dst_size > copy_length)
		memset(dst + copy_length, 0, dst_size - copy_length);
	if (use_xsave && (fpu->flags & VMM_SNAPSHOT_X86_FPU_F_XSAVE) == 0) {
		/*
		 * Synthesize a standard-format XSAVE header for a bare
		 * FXSAVE image from a non-XSAVE source.
		 */
		hdr = (struct xstate_hdr *)(void *)
		    (dst + sizeof(struct savefpu));
		hdr->xstate_bv = XFEATURE_ENABLED_X87 | XFEATURE_ENABLED_SSE;
	}
}

struct vmm_snapshot_x86_restore_entry {
	struct vcpu *vcpu;
	struct vmm_snapshot_x86_vcpu_stage stage;
	struct vmm_event_state event;
	enum vm_exception_class exception_class;
};

struct vmm_snapshot_x86_restore_plan {
	struct vm *vm;
	uint32_t count;
	uint64_t event_generation;
	bool committed;
	cpuset_t startup_cpus;
	cpuset_t destination_startup_cpus;
	struct vmm_snapshot_x86_restore_entry entries[];
};

int
vm_snapshot_x86_capture_all(struct vm *vm,
    struct vmm_snapshot_x86_vcpu_stage *stage, size_t capacity,
    struct vmm_snapshot_x86_transaction *transaction)
{
	struct vmm_snapshot_x86_transaction transaction_candidate;
	struct vmm_snapshot_x86_vcpu_stage *stage_candidates;
	struct vmm_event_state *events;
	struct vcpu *vcpu;
	cpuset_t startup_cpus;
	uint32_t *instances;
	size_t count, index, stage_length;
	uint64_t generation, now;
	uint16_t i, maxcpus;
	int error;

	if (vm == NULL || transaction == NULL ||
	    !sx_xlocked(&vm->vcpus_init_lock) ||
	    !vmm_snapshot_range_valid(transaction, sizeof(*transaction)))
		return (EINVAL);
	count = 0;
	maxcpus = vm_get_maxcpus(vm);
	for (i = 0; i < maxcpus; i++) {
		vcpu = vm_vcpu(vm, i);
		if (vcpu == NULL)
			continue;
		if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
			return (EBUSY);
		count++;
	}
	if (count > capacity || count > SIZE_MAX / sizeof(*stage))
		return (E2BIG);
	stage_length = count * sizeof(*stage);
	if (!vmm_snapshot_range_valid(stage, stage_length) ||
	    vmm_snapshot_ranges_overlap(stage, stage_length, transaction,
	    sizeof(*transaction)) || vm_event_output_overlaps_owner(vm, stage,
	    stage_length) || vm_event_output_overlaps_owner(vm, transaction,
	    sizeof(*transaction)))
		return (EINVAL);

	stage_candidates = NULL;
	events = NULL;
	instances = NULL;
	if (count != 0) {
		stage_candidates = mallocarray(count, sizeof(*stage_candidates),
		    M_VM, M_NOWAIT | M_ZERO);
		events = mallocarray(count, sizeof(*events), M_VM,
		    M_NOWAIT | M_ZERO);
		instances = mallocarray(count, sizeof(*instances), M_VM,
		    M_NOWAIT | M_ZERO);
		if (stage_candidates == NULL || events == NULL ||
		    instances == NULL) {
			error = ENOMEM;
			goto done;
		}
	}
	generation = atomic_load_acq_64(&vm->event_generation);
	index = 0;
	error = vm_event_state_capture_all(vm, instances, events, count, &index);
	if (error != 0)
		goto done;
	/*
	 * startup_cpus is published under rendezvous_mtx.  All vCPUs being
	 * frozen prevents an architectural INIT/SIPI transition, but it does
	 * not make an unlocked cpuset read valid.  Capture one owner-protected
	 * value and use it for every sparse vCPU record.
	 */
	mtx_lock(&vm->rendezvous_mtx);
	CPU_COPY(&vm->startup_cpus, &startup_cpus);
	mtx_unlock(&vm->rendezvous_mtx);
	now = rdtsc();
	for (index = 0; index < count; index++) {
		i = instances[index];
		vcpu = vm_vcpu(vm, i);
		stage_candidates[index].instance = i;
		if (CPU_ISSET(i, &startup_cpus))
			stage_candidates[index].common.flags |=
			    VMM_SNAPSHOT_VCPU_F_STARTUP_WAIT;
		stage_candidates[index].common.next_pc = vcpu->nextrip;
		stage_candidates[index].x86.x2apic_state = vcpu->x2apic_state;
		stage_candidates[index].x86.guest_xcr0 = vcpu->guest_xcr0;
		stage_candidates[index].x86.absolute_tsc =
		    now + vcpu->tsc_offset;
		error = vm_snapshot_x86_fpu_capture(vcpu,
		    &stage_candidates[index].fpu);
		if (error != 0)
			goto done;
		error = vmm_snapshot_vcpu_x86_event_from_runtime(&events[index],
		    &stage_candidates[index].x86);
		if (error != 0)
			goto done;
	}
	error = vmm_event_capture_commit_validate(generation,
	    atomic_load_acq_64(&vm->event_generation), count, index);
	if (error != 0)
		goto done;
	transaction_candidate = (struct vmm_snapshot_x86_transaction) {
		.vm = {
			.max_vcpus = maxcpus,
			.vcpu_count = count,
		},
		.vcpu_count = count,
	};
	if (stage_length != 0)
		memcpy(stage, stage_candidates, stage_length);
	*transaction = transaction_candidate;
done:
	if (instances != NULL)
		free(instances, M_VM);
	if (events != NULL) {
		explicit_bzero(events, malloc_usable_size(events));
		free(events, M_VM);
	}
	if (stage_candidates != NULL) {
		explicit_bzero(stage_candidates,
		    malloc_usable_size(stage_candidates));
		free(stage_candidates, M_VM);
	}
	return (error);
}

static int
vm_event_exception_class_prepare(
    enum vmm_event_exception_class source,
    enum vm_exception_class *destination)
{

	switch (source) {
	case VMM_EVENT_EXCEPTION_NONE:
		*destination = VM_EXCEPTION_NONE;
		break;
	case VMM_EVENT_EXCEPTION_FAULT:
		*destination = VM_EXCEPTION_FAULT;
		break;
	case VMM_EVENT_EXCEPTION_TRAP:
		*destination = VM_EXCEPTION_TRAP;
		break;
	case VMM_EVENT_EXCEPTION_ICEBP:
		*destination = VM_EXCEPTION_ICEBP;
		break;
	case VMM_EVENT_EXCEPTION_TASK_SWITCH:
		*destination = VM_EXCEPTION_TASK_SWITCH;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
vm_snapshot_x86_restore_plan_create(struct vm *vm,
    const struct vmm_snapshot_x86_transaction *transaction,
    const struct vmm_snapshot_x86_vcpu_stage *stage, size_t capacity,
    struct vmm_snapshot_x86_restore_plan **planp)
{
	struct vmm_snapshot_x86_transaction transaction_candidate;
	struct vmm_snapshot_x86_restore_plan *plan;
	struct vmm_snapshot_x86_vcpu_stage *stage_candidates;
	struct vcpu *vcpu;
	const struct xsave_limits *xsave_limits;
	uint32_t *instances;
	uint8_t *lapic_modes;
	size_t count, index, plan_size, stage_length;
	uint16_t i, maxcpus;
	int error;
	bool lapic_x2apic;
	uint64_t generation;

	if (vm == NULL || transaction == NULL || planp == NULL ||
	    !sx_xlocked(&vm->vcpus_init_lock) ||
	    !vmm_snapshot_range_valid(transaction, sizeof(*transaction)) ||
	    !vmm_snapshot_range_valid(planp, sizeof(*planp)))
		return (EINVAL);
	transaction_candidate = *transaction;
	count = transaction_candidate.vcpu_count;
	maxcpus = vm_get_maxcpus(vm);
	if (transaction_candidate.vm.max_vcpus != maxcpus ||
	    transaction_candidate.vm.vcpu_count != count || count > maxcpus)
		return (EINVAL);
	if (count > capacity || count > SIZE_MAX / sizeof(*stage) ||
	    count > (SIZE_MAX - sizeof(*plan)) / sizeof(plan->entries[0]))
		return (E2BIG);
	stage_length = count * sizeof(*stage);
	if (!vmm_snapshot_range_valid(stage, stage_length) ||
	    vmm_snapshot_ranges_overlap(transaction, sizeof(*transaction),
	    stage, stage_length) ||
	    vmm_snapshot_ranges_overlap(transaction, sizeof(*transaction),
	    planp, sizeof(*planp)) || vmm_snapshot_ranges_overlap(stage,
	    stage_length, planp, sizeof(*planp)) ||
	    vm_event_output_overlaps_owner(vm, transaction,
	    sizeof(*transaction)) || vm_event_output_overlaps_owner(vm, stage,
	    stage_length) || vm_event_output_overlaps_owner(vm, planp,
	    sizeof(*planp)))
		return (EINVAL);

	plan_size = sizeof(*plan) + count * sizeof(plan->entries[0]);
	plan = malloc(plan_size, M_VM, M_NOWAIT | M_ZERO);
	instances = NULL;
	lapic_modes = NULL;
	stage_candidates = NULL;
	if (plan == NULL)
		return (ENOMEM);
	if (count != 0) {
		instances = mallocarray(count, sizeof(*instances), M_VM,
		    M_NOWAIT | M_ZERO);
		stage_candidates = mallocarray(count,
		    sizeof(*stage_candidates), M_VM, M_NOWAIT | M_ZERO);
		lapic_modes = mallocarray(count, sizeof(*lapic_modes), M_VM,
		    M_NOWAIT | M_ZERO);
		if (instances == NULL || stage_candidates == NULL ||
		    lapic_modes == NULL) {
			error = ENOMEM;
			goto fail;
		}
		memcpy(stage_candidates, stage, stage_length);
	}

	index = 0;
	for (i = 0; i < maxcpus; i++) {
		vcpu = vm_vcpu(vm, i);
		if (vcpu == NULL)
			continue;
		if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN) {
			error = EBUSY;
			goto fail;
		}
		if (index >= count) {
			error = EINVAL;
			goto fail;
		}
		instances[index++] = i;
		lapic_modes[index - 1] = (vlapic_get_apicbase(vm_lapic(vcpu)) &
		    APICBASE_X2APIC) != 0;
	}
	if (index != count) {
		error = EINVAL;
		goto fail;
	}
	error = vmm_snapshot_x86_transaction_restore_preflight(
	    &transaction_candidate, stage_candidates, count, maxcpus,
	    instances, lapic_modes, count);
	if (error != 0)
		goto fail;
	xsave_limits = vmm_get_xsave_limits();
	for (index = 0; index < count; index++) {
		error = vmm_snapshot_x86_xcr0_validate(
		    stage_candidates[index].x86.guest_xcr0,
		    xsave_limits->xcr0_allowed,
		    xsave_limits->xsave_enabled != 0);
		if (error != 0)
			goto fail;
		/*
		 * Capability-mismatch admission for the guest FPU image runs
		 * against the destination the runtime will actually reload:
		 * fail closed here, before any guestfpu mutation at commit.
		 */
		error = vmm_snapshot_vcpu_x86_fpu_restore_validate(
		    &stage_candidates[index].fpu, use_xsave != 0, xsave_mask,
		    use_xsave ? cpu_max_ext_state_size :
		    sizeof(struct savefpu));
		if (error != 0)
			goto fail;
	}

	plan->vm = vm;
	plan->count = count;
	CPU_ZERO(&plan->startup_cpus);
	/*
	 * Bind the immutable plan to the destination startup owner it will
	 * replace.  Frozen vCPUs prohibit guest execution, but management and
	 * startup publishers still use rendezvous_mtx independently of run state.
	 * A later change must make commit retry rather than silently discard an
	 * accepted INIT/SIPI transition.
	 */
	mtx_lock(&vm->rendezvous_mtx);
	CPU_COPY(&vm->startup_cpus, &plan->destination_startup_cpus);
	mtx_unlock(&vm->rendezvous_mtx);
	for (index = 0; index < count; index++) {
		plan->entries[index].vcpu = vm_vcpu(vm, instances[index]);
		plan->entries[index].stage = stage_candidates[index];
		error = vmm_snapshot_vcpu_x86_event_to_runtime(
		    &plan->entries[index].stage.x86,
		    &plan->entries[index].event);
		if (error != 0)
			goto fail;
		error = vm_event_exception_class_prepare(
		    plan->entries[index].event.exception_class,
		    &plan->entries[index].exception_class);
		if (error != 0)
			goto fail;
		lapic_x2apic = lapic_modes[index] != 0;
		if (lapic_x2apic !=
		    (plan->entries[index].stage.x86.x2apic_state ==
		    X2APIC_ENABLED)) {
			error = EINVAL;
			goto fail;
		}
		if ((plan->entries[index].stage.common.flags &
		    VMM_SNAPSHOT_VCPU_F_STARTUP_WAIT) != 0)
			CPU_SET(instances[index], &plan->startup_cpus);
	}
	/*
	 * A restore must not discard an event already owned by the destination.
	 * The two generation reads close the gaps between the individual event
	 * locks.  A later publisher is detected again under all locks at commit.
	 */
	generation = atomic_load_acq_64(&vm->event_generation);
	error = 0;
	for (index = 0; index < count; index++) {
		vcpu = plan->entries[index].vcpu;
		vcpu_event_lock(vcpu);
		if (vcpu->exception_injecting != 0 ||
		    vcpu->exception_pending != 0 || vcpu->nmi_pending != 0 ||
		    vcpu->extint_pending != 0 || vcpu->exitintinfo != 0)
			error = EBUSY;
		vcpu_event_unlock(vcpu);
		if (error != 0)
			goto fail;
	}
	if (atomic_load_acq_64(&vm->event_generation) != generation) {
		error = EAGAIN;
		goto fail;
	}
	plan->event_generation = generation;
	if (stage_candidates != NULL) {
		explicit_bzero(stage_candidates,
		    malloc_usable_size(stage_candidates));
		free(stage_candidates, M_VM);
	}
	if (lapic_modes != NULL)
		free(lapic_modes, M_VM);
	if (instances != NULL)
		free(instances, M_VM);
	*planp = plan;
	return (0);

fail:
	if (stage_candidates != NULL) {
		explicit_bzero(stage_candidates,
		    malloc_usable_size(stage_candidates));
		free(stage_candidates, M_VM);
	}
	if (lapic_modes != NULL)
		free(lapic_modes, M_VM);
	if (instances != NULL)
		free(instances, M_VM);
	/* Clear the allocator's complete extent, including size-class slack. */
	explicit_bzero(plan, malloc_usable_size(plan));
	free(plan, M_VM);
	return (error);
}

static void
vm_event_state_publish_locked(struct vcpu *vcpu,
    const struct vmm_event_state *event,
    enum vm_exception_class exception_class)
{

	vcpu_event_assert(vcpu);
	vcpu->exitintinfo = event->exitintinfo;
	vcpu->nmi_pending =
	    (event->flags & VMM_EVENT_STATE_F_NMI_PENDING) != 0;
	vcpu->extint_pending =
	    (event->flags & VMM_EVENT_STATE_F_EXTINT_PENDING) != 0;
	vcpu->exception_pending =
	    (event->flags & VMM_EVENT_STATE_F_EXCEPTION_PENDING) != 0;
	vcpu->exception_injecting = 0;
	vcpu->exc_vector = event->exception_vector;
	vcpu->exc_class = exception_class;
	vcpu->exc_errcode_valid =
	    (event->flags & VMM_EVENT_STATE_F_EXCEPTION_ERROR) != 0;
	vcpu->exc_errcode = event->exception_error;
	vcpu_event_generation_advance_locked(vcpu);
}

int
vm_snapshot_x86_restore_plan_commit(struct vm *vm,
    struct vmm_snapshot_x86_restore_plan *plan)
{
	struct vmm_snapshot_x86_restore_entry *entry;
	struct vcpu *vcpu;
	size_t count, index, plan_size;
	uint16_t i, maxcpus;
	bool lapic_x2apic;

	if (vm == NULL || plan == NULL ||
	    !vmm_snapshot_range_valid(plan, sizeof(*plan)))
		return (EINVAL);
	if (plan->vm != vm || !sx_xlocked(&vm->vcpus_init_lock) ||
	    plan->count > vm_get_maxcpus(vm))
		return (EINVAL);
	plan_size = sizeof(*plan) +
	    plan->count * sizeof(plan->entries[0]);
	if (!vmm_snapshot_range_valid(plan, plan_size))
		return (EINVAL);
	maxcpus = vm_get_maxcpus(vm);
	count = 0;
	for (i = 0; i < maxcpus; i++) {
		vcpu = vm_vcpu(vm, i);
		if (vcpu == NULL)
			continue;
		if (count >= plan->count ||
		    plan->entries[count].stage.instance != i ||
		    plan->entries[count].vcpu != vcpu)
			return (EINVAL);
		count++;
	}
	if (count != plan->count)
		return (EINVAL);
	for (index = 0; index < plan->count; index++) {
		entry = &plan->entries[index];
		if (entry->vcpu != vm_vcpu(vm, entry->stage.instance) ||
		    vcpu_get_state(entry->vcpu, NULL) != VCPU_FROZEN)
			return (EBUSY);
		lapic_x2apic = (vlapic_get_apicbase(vm_lapic(entry->vcpu)) &
		    APICBASE_X2APIC) != 0;
		if (lapic_x2apic != (entry->stage.x86.x2apic_state ==
		    X2APIC_ENABLED))
			return (EINVAL);
	}

	/*
	 * Lock ordering is rendezvous owner, then ascending vCPU event owner.
	 * No event publisher acquires rendezvous_mtx while holding event_mtx.
	 * Every fallible conversion and destination/backend check happened while
	 * constructing the immutable plan; after the reservation recheck below,
	 * publication contains no operation which can fail.
	 */
	mtx_lock(&vm->rendezvous_mtx);
	if (plan->committed) {
		mtx_unlock(&vm->rendezvous_mtx);
		return (EALREADY);
	}
	if (CPU_CMP(&vm->startup_cpus,
	    &plan->destination_startup_cpus) != 0) {
		mtx_unlock(&vm->rendezvous_mtx);
		return (EAGAIN);
	}
	for (index = 0; index < plan->count; index++)
		vcpu_event_lock(plan->entries[index].vcpu);
	if (atomic_load_acq_64(&vm->event_generation) !=
	    plan->event_generation)
		goto changed;
	for (index = 0; index < plan->count; index++) {
		if (plan->entries[index].vcpu->exception_injecting != 0)
			goto busy;
	}

	CPU_COPY(&plan->startup_cpus, &vm->startup_cpus);
	for (index = 0; index < plan->count; index++) {
		entry = &plan->entries[index];
		/* The already-restored LAPIC image was mode-checked at preflight. */
		entry->vcpu->x2apic_state =
		    (enum x2apic_state)entry->stage.x86.x2apic_state;
		entry->vcpu->guest_xcr0 = entry->stage.x86.guest_xcr0;
		vm_snapshot_x86_fpu_land(entry->vcpu, &entry->stage.fpu);
		entry->vcpu->nextrip = entry->stage.common.next_pc;
		/* vm_restore_time() converts this absolute value to an offset. */
		entry->vcpu->tsc_offset = entry->stage.x86.absolute_tsc;
		vm_event_state_publish_locked(entry->vcpu, &entry->event,
		    entry->exception_class);
	}
	plan->committed = true;
	for (index = plan->count; index != 0; index--)
		vcpu_event_unlock(plan->entries[index - 1].vcpu);
	mtx_unlock(&vm->rendezvous_mtx);
	return (0);

changed:
	for (index = plan->count; index != 0; index--)
		vcpu_event_unlock(plan->entries[index - 1].vcpu);
	mtx_unlock(&vm->rendezvous_mtx);
	return (EAGAIN);

busy:
	for (index = plan->count; index != 0; index--)
		vcpu_event_unlock(plan->entries[index - 1].vcpu);
	mtx_unlock(&vm->rendezvous_mtx);
	return (EBUSY);
}

void
vm_snapshot_x86_restore_plan_free(
    struct vmm_snapshot_x86_restore_plan *plan)
{
	size_t plan_size;

	if (plan == NULL)
		return;
	/* The allocator owns the extent; teardown must not trust mutable count. */
	plan_size = malloc_usable_size(plan);
	explicit_bzero(plan, plan_size);
	free(plan, M_VM);
}

static int
vm_snapshot_vm(struct vm *vm, struct vm_snapshot_meta *meta)
{
	struct vmm_snapshot_x86_restore_plan *plan;
	struct vmm_snapshot_x86_transaction transaction;
	struct vmm_snapshot_x86_vcpu_stage *stage;
	uint8_t *wire;
	size_t length, written;
	uint16_t maxcpus;
	int error;

	maxcpus = vm_get_maxcpus(vm);
	stage = NULL;
	wire = NULL;
	plan = NULL;
	length = meta->buffer.buf_rem;
	if (maxcpus != 0) {
		stage = mallocarray(maxcpus, sizeof(*stage), M_VM,
		    M_NOWAIT | M_ZERO);
		if (stage == NULL)
			return (ENOMEM);
	}

	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = vm_snapshot_x86_capture_all(vm, stage, maxcpus,
		    &transaction);
		if (error != 0)
			goto done;
		error = vmm_snapshot_x86_transaction_size(
		    transaction.vcpu_count, &length);
		if (error != 0)
			goto done;
		if (length > meta->buffer.buf_rem) {
			error = E2BIG;
			goto done;
		}
		wire = malloc(length, M_VM, M_NOWAIT | M_ZERO);
		if (wire == NULL) {
			error = ENOMEM;
			goto done;
		}
		written = 0;
		error = vmm_snapshot_x86_transaction_encode(&transaction, stage,
		    maxcpus, wire, length, &written);
		if (error != 0)
			goto done;
		/*
		 * The guest FPU sections make the encoded extent
		 * source-dependent; the size query is a capacity bound and
		 * the encoder reports the exact emitted length.
		 */
		if (written > length) {
			error = EPROTO;
			goto done;
		}
		error = vm_snapshot_buf(wire, written, meta);
		goto done;
	}

	/*
	 * The current kernel-common record is exactly one canonical VMS2
	 * envelope.  Bound allocation by the destination topology before
	 * copying any untrusted bytes from userspace.
	 */
	error = vmm_snapshot_x86_transaction_size(maxcpus, &written);
	if (error != 0)
		goto done;
	if (length > written ||
	    length < VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VM_COMMON_SIZE) {
		error = EINVAL;
		goto done;
	}
	wire = malloc(length, M_VM, M_NOWAIT | M_ZERO);
	if (wire == NULL) {
		error = ENOMEM;
		goto done;
	}
	error = vm_snapshot_buf(wire, length, meta);
	if (error != 0)
		goto done;
	error = vmm_snapshot_x86_transaction_decode(wire, length, stage,
	    maxcpus, &transaction);
	if (error != 0)
		goto done;
	error = vm_snapshot_x86_restore_plan_create(vm, &transaction, stage,
	    maxcpus, &plan);
	if (error != 0)
		goto done;
	error = vm_snapshot_x86_restore_plan_commit(vm, plan);

done:
	vm_snapshot_x86_restore_plan_free(plan);
	if (wire != NULL) {
		explicit_bzero(wire, malloc_usable_size(wire));
		free(wire, M_VM);
	}
	if (stage != NULL) {
		explicit_bzero(stage, malloc_usable_size(stage));
		free(stage, M_VM);
	}
	return (error);
}

static int
vm_snapshot_vcpu(struct vm *vm, struct vm_snapshot_meta *meta)
{
	int complete_error, error;
	struct vcpu *vcpu;
	uint16_t i, maxcpus;

	error = 0;

	error = vmmops_vm_snapshot(vm->cookie, meta);
	if (error != 0) {
		printf("%s: failed to snapshot VM-wide architecture data; "
		    "error: %d\n", __func__, error);
		goto done;
	}
	maxcpus = vm_get_maxcpus(vm);
	for (i = 0; i < maxcpus; i++) {
		vcpu = vm->vcpu[i];
		if (vcpu == NULL)
			continue;

		error = vmmops_vcpu_snapshot(vcpu->cookie, meta);
		if (error != 0) {
			printf("%s: failed to snapshot vmcs/vmcb data for "
			       "vCPU: %d; error: %d\n", __func__, i, error);
			goto done;
		}
	}

done:
	complete_error = vmmops_vm_snapshot_complete(vm->cookie, meta,
	    error);
	if (error == 0)
		error = complete_error;
	return (error);
}

/*
 * Save kernel-side structures to user-space for snapshotting.
 */
int
vm_snapshot_req(struct vm *vm, struct vm_snapshot_meta *meta)
{
	int ret;

	/*
	 * VM_SNAPSHOT_VALIDATE is a userspace codec operation.  Reject it (and
	 * every unknown value) before dispatching to architecture or device
	 * callbacks, some of which allocate transactional restore state before
	 * their first buffer access.
	 */
	if (meta == NULL || !vm_snapshot_op_is_kernel(meta->op))
		return (EINVAL);
	/* Reject malformed selectors before changing any VM transaction state. */
	switch (meta->dev_req) {
	case STRUCT_VMCX:
	case STRUCT_VM:
	case STRUCT_VIOAPIC:
	case STRUCT_VLAPIC:
	case STRUCT_VHPET:
	case STRUCT_VATPIC:
	case STRUCT_VATPIT:
	case STRUCT_VPMTMR:
	case STRUCT_VRTC:
		break;
	default:
		printf("%s: failed to find the requested type %#x\n", __func__,
		    meta->dev_req);
		return (EINVAL);
	}

	/*
	 * Snapshot ioctls freeze all vCPUs, but a dirty-log ticket also binds
	 * backend collection and copyout ordering.  Revoke it before either save
	 * or restore dispatch.  Do not retain mem_segs_lock across arbitrary
	 * architecture/device snapshot callbacks.
	 */
	vm_xlock_memsegs(vm);
	ret = vm_mem_dirty_log_invalidate(vm);
	vm_unlock_memsegs(vm);
	KASSERT(ret == 0 || ret == EOVERFLOW,
	    ("%s: invalid dirty-log owner state %d", __func__, ret));
	ret = 0;

	switch (meta->dev_req) {
	case STRUCT_VMCX:
		ret = vm_snapshot_vcpu(vm, meta);
		break;
	case STRUCT_VM:
		ret = vm_snapshot_vm(vm, meta);
		break;
	case STRUCT_VIOAPIC:
		ret = vioapic_snapshot(vm_ioapic(vm), meta);
		break;
	case STRUCT_VLAPIC:
		ret = vlapic_snapshot(vm, meta);
		break;
	case STRUCT_VHPET:
		ret = vhpet_snapshot(vm_hpet(vm), meta);
		break;
	case STRUCT_VATPIC:
		ret = vatpic_snapshot(vm_atpic(vm), meta);
		break;
	case STRUCT_VATPIT:
		ret = vatpit_snapshot(vm_atpit(vm), meta);
		break;
	case STRUCT_VPMTMR:
		ret = vpmtmr_snapshot(vm_pmtmr(vm), meta);
		break;
	case STRUCT_VRTC:
		ret = vrtc_snapshot(vm_rtc(vm), meta);
		break;
	default:
		KASSERT(0, ("%s: validated snapshot selector %#x", __func__,
		    meta->dev_req));
		ret = EINVAL;
	}
	return (ret);
}

void
vm_set_tsc_offset(struct vcpu *vcpu, uint64_t offset)
{
	vcpu->tsc_offset = offset;
	/*
	 * A change to the guest-visible TSC invalidates any paravirtual clock
	 * page, but this function runs in fragile contexts (e.g. between
	 * VMPTRLD/VMCLEAR during a TSC restore) where the memseg lock cannot be
	 * taken.  The pvclock page is instead republished from the well-defined
	 * safe points: initial enable and guest MSR_TSC writes (arch WRMSR
	 * handlers) and vCPU resume / migration restore (vm_restore_time()).
	 */
}

int
vm_restore_time(struct vm *vm)
{
	int error;
	uint64_t now;
	struct vcpu *vcpu;
	uint16_t i, maxcpus;

	now = rdtsc();

	error = vhpet_restore_time(vm_hpet(vm));
	if (error)
		return (error);

	maxcpus = vm_get_maxcpus(vm);
	for (i = 0; i < maxcpus; i++) {
		vcpu = vm->vcpu[i];
		if (vcpu == NULL)
			continue;

		error = vmmops_restore_tsc(vcpu->cookie,
		    vcpu->tsc_offset - now);
		if (error)
			return (error);

		/*
		 * After a migration/restore the guest TSC has been rebased on
		 * the new host: republish each vCPU's paravirtual clock page so
		 * the guest recomputes time from the restored tsc_timestamp and
		 * its read algorithm does not observe time going backwards.
		 * No-op for vCPUs that have not enabled pvclock.  This is
		 * ioctl context with the vCPUs frozen, not the critical
		 * section inside vm_run(), so commit the publish directly.
		 */
		vpvclock_vcpu_update(vcpu);
		vpvclock_commit(vcpu);
	}

	return (0);
}
#endif
