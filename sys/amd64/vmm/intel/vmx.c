/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 * Copyright (c) 2018 Joyent, Inc.
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

#include <sys/endian.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/smp.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/reg.h>
#include <sys/smr.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>

#include <machine/psl.h>
#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/segments.h>
#include <machine/smp.h>
#include <machine/specialreg.h>
#include <machine/vmparam.h>

#include <machine/vmm.h>
#include <machine/vmm_instruction_emul.h>
#include <machine/vmm_snapshot.h>

#include <dev/vmm/vmm_dev.h>
#include <dev/vmm/vmm_ktr.h>
#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_startup_entry_owner.h>
#include <dev/vmm/vmm_vm.h>

#include "vmm_lapic.h"
#include "vmm_exception.h"
#include "vmm_host.h"
#include "vmm_ioport.h"
#include "vmm_stat.h"
#include "vmm_x86_startup_backend.h"
#include "vmm_x86_startup_finalizer.h"
#include "vmm_x86_startup_machine.h"
#include "x86_cpuid.h"
#include "vatpic.h"
#include "vlapic.h"
#include "vlapic_priv.h"
#include "vpvclock.h"

#include "ept.h"
#include "vmx_cpufunc.h"
#include "vmx.h"
#include "vmx_nested_bitmap.h"
#include "vmx_nested_cold_ept.h"
#include "vmx_nested_cold_reflect.h"
#include "vmx_nested_control_msr.h"
#include "vmx_nested_control_capabilities_intel.h"
#include "vmx_nested_checkpoint.h"
#include "vmx_nested_ept_root.h"
#include "vmx_nested_ept_runtime.h"
#include "vmx_nested_entry_event.h"
#include "vmx_nested_guest_memory_intel.h"
#include "vmx_nested_attempt.h"
#include "vmx_nested_owner_outcome.h"
#include "vmx_nested_hardware_entry.h"
#include "vmx_nested_hot_ept.h"
#include "vmx_nested_hot_exit.h"
#include "vmx_nested_exposure.h"
#include "vmx_nested_instruction_gate.h"
#include "vmx_nested_instruction_publish.h"
#include "vmx_nested_instruction_runtime.h"
#include "vmx_nested_l1_restore.h"
#include "vmx_nested_apic_priority.h"
#include "vmx_nested_l2_access.h"
#include "vmx_nested_l2_access_intel.h"
#include "vmx_nested_l2_continuation_state.h"
#include "vmx_nested_l2_freeze.h"
#include "vmx_nested_l2_rebuild.h"
#include "vmx_nested_l2_thaw.h"
#include "vmx_nested_msr_state.h"
#include "vmx_nested_refreeze.h"
#include "vmx_nested_restore_transaction.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs02_program.h"
#include "vmx_nested_vmcs02_resources_intel.h"
#include "vmx_nested_vmcs.h"
#include "vmx_nested_vmcs_registry_state.h"
#include "vmx_msr.h"
#include "x86.h"
#include "vmx_controls.h"
#include "io/ppt.h"

#define	VMX_EXIT_REASON_BASIC_MASK	UINT32_C(0xffff)

#define	PINBASED_CTLS_ONE_SETTING					\
	(PINBASED_EXTINT_EXITING	|				\
	 PINBASED_NMI_EXITING		|				\
	 PINBASED_VIRTUAL_NMI)
#define	PINBASED_CTLS_ZERO_SETTING	0

#define PROCBASED_CTLS_WINDOW_SETTING					\
	(PROCBASED_INT_WINDOW_EXITING	|				\
	 PROCBASED_NMI_WINDOW_EXITING)

#define	PROCBASED_CTLS_ONE_SETTING					\
	(PROCBASED_SECONDARY_CONTROLS	|				\
	 PROCBASED_MWAIT_EXITING	|				\
	 PROCBASED_MONITOR_EXITING	|				\
	 PROCBASED_IO_EXITING		|				\
	 PROCBASED_MSR_BITMAPS		|				\
	 PROCBASED_CTLS_WINDOW_SETTING	|				\
	 PROCBASED_CR8_LOAD_EXITING	|				\
	 PROCBASED_CR8_STORE_EXITING)
#define	PROCBASED_CTLS_ZERO_SETTING	\
	(PROCBASED_CR3_LOAD_EXITING |	\
	PROCBASED_CR3_STORE_EXITING |	\
	PROCBASED_IO_BITMAPS)

#define	PROCBASED_CTLS2_ONE_SETTING	PROCBASED2_ENABLE_EPT
#define	PROCBASED_CTLS2_ZERO_SETTING	0

#define	VM_EXIT_CTLS_ONE_SETTING					\
	(VM_EXIT_SAVE_DEBUG_CONTROLS		|			\
	VM_EXIT_HOST_LMA			|			\
	VM_EXIT_SAVE_EFER			|			\
	VM_EXIT_LOAD_EFER			|			\
	VM_EXIT_ACKNOWLEDGE_INTERRUPT)

#define	VM_EXIT_CTLS_ZERO_SETTING	0

#define	VM_ENTRY_CTLS_ONE_SETTING					\
	(VM_ENTRY_LOAD_DEBUG_CONTROLS		|			\
	VM_ENTRY_LOAD_EFER)

#define	VM_ENTRY_CTLS_ZERO_SETTING					\
	(VM_ENTRY_INTO_SMM			|			\
	VM_ENTRY_DEACTIVATE_DUAL_MONITOR)

#define	HANDLED		1
#define	UNHANDLED	0

static MALLOC_DEFINE(M_VMX, "vmx", "vmx");

#ifdef BHYVE_SNAPSHOT
static void vmx_nested_snapshot_restore_free(
    struct vmx_nested_snapshot_restore *);
static int vmx_nested_msr_workspace_stage(
    const struct vmx_nested_capabilities *,
    struct vmx_nested_msr_workspace *, struct vmx_nested_msr_entry **);
#endif
static int vmx_nested_msr_workspace_ensure(struct vmx_vcpu *,
    const struct vmx_nested_capabilities *, bool);

static const struct vmx_nested_ept_cache_ops vmx_nested_ept_cache_ops = {
	.create = vmx_nested_ept_root_create,
	.destroy = vmx_nested_ept_root_destroy,
	.invalidate = vmx_nested_ept_root_invalidate,
};
static MALLOC_DEFINE(M_VLAPIC, "vlapic", "vlapic");

bool vmx_have_msr_tsc_aux;

SYSCTL_DECL(_hw_vmm);
SYSCTL_NODE(_hw_vmm, OID_AUTO, vmx, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    NULL);

int vmxon_enabled[MAXCPU];
static int vmxon_error[MAXCPU];
static bool vmxon_resume[MAXCPU];
static uint8_t *vmxon_region;

static uint32_t pinbased_ctls, procbased_ctls, procbased_ctls2;
static uint32_t exit_ctls, entry_ctls;
static struct vmx_nested_vmcs02_capabilities vmx_nested_hardware_controls;
static struct vmx_nested_capabilities vmx_nested_virtual_capabilities;

/*
 * The destination-local VPID owner records residency by logical CPU.  Keep
 * its deliberately architecture-independent wire-free representation, but
 * fail the kernel build if amd64 grows beyond the reviewed private bound.
 * A silent runtime EINVAL after scheduling on a newly representable CPU is
 * not an acceptable compatibility policy.
 */
CTASSERT(MAXCPU <= VMX_NESTED_VPID_CPU_LIMIT);

/*
 * Nested VMX is an explicit host policy.  Keep it disabled by default while
 * live Intel qualification is in progress; a guest must additionally enable
 * the VM-wide VM_CAP_NESTED_VMX CPU-model setting before CPUID, VMX MSRs, or
 * instructions become visible.
 */
static int nested_vmx_allowed;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, nested, CTLFLAG_RDTUN,
    &nested_vmx_allowed, 0,
    "Permit explicitly configured guests to use nested VMX");

/*
 * VPID/INVVPID has a complete model and destination-local runtime owner, but
 * remains behind a second boot-time gate until the Intel live qualification
 * group passes.  This tunable changes the nested guest ABI and therefore must
 * not be writable after vmm initialization.
 */
static int nested_vpid_qualification;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, nested_vpid, CTLFLAG_RDTUN,
    &nested_vpid_qualification, 0,
    "Expose nested VPID/INVVPID for explicit live qualification");

static int
vmx_nested_guest_exposure_validate(void)
{

	return (vmx_nested_exposure_policy_validate(
	    &vmx_nested_virtual_capabilities, nested_vmx_allowed != 0));
}

static bool
vmx_nested_guest_enabled(struct vmx *vmx)
{

	return ((atomic_load_acq_int(&vmx->nested_vmx_exposure) &
	    VMX_NESTED_EXPOSURE_ENABLED) != 0);
}

static int
vmx_nested_guest_configure(struct vmx *vmx, bool enabled)
{
	u_int new_state, state;
	int error;

	if (enabled) {
		error = vmx_nested_guest_exposure_validate();
		if (error != 0)
			return (error);
	}

	state = atomic_load_acq_int(&vmx->nested_vmx_exposure);
	for (;;) {
		error = vmx_nested_exposure_configure(state, enabled,
		    &new_state);
		if (error != 0)
			return (error);
		if (new_state == state)
			return (0);
		if (atomic_fcmpset_int(&vmx->nested_vmx_exposure, &state,
		    new_state))
			return (0);
	}
}

static void
vmx_nested_guest_config_lock(struct vmx *vmx)
{
	u_int new_state, state;
	int error;

	state = atomic_load_acq_int(&vmx->nested_vmx_exposure);
	for (;;) {
		error = vmx_nested_exposure_lock(state, &new_state);
		if (error != 0)
			panic("%s: corrupt exposure state %#x", __func__, state);
		if (new_state == state)
			return;
		if (atomic_fcmpset_int(&vmx->nested_vmx_exposure, &state,
		    new_state))
			return;
	}
}

static uint64_t cr0_ones_mask, cr0_zeros_mask;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, cr0_ones_mask, CTLFLAG_RD,
	     &cr0_ones_mask, 0, NULL);
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, cr0_zeros_mask, CTLFLAG_RD,
	     &cr0_zeros_mask, 0, NULL);

static uint64_t cr4_ones_mask, cr4_zeros_mask;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, cr4_ones_mask, CTLFLAG_RD,
	     &cr4_ones_mask, 0, NULL);
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, cr4_zeros_mask, CTLFLAG_RD,
	     &cr4_zeros_mask, 0, NULL);

static int vmx_initialized;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, initialized, CTLFLAG_RD,
	   &vmx_initialized, 0, "Intel VMX initialized");

/*
 * Optional capabilities
 */
static SYSCTL_NODE(_hw_vmm_vmx, OID_AUTO, cap,
    CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    NULL);

static int cap_halt_exit;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, halt_exit, CTLFLAG_RD, &cap_halt_exit, 0,
    "HLT triggers a VM-exit");

static int cap_pause_exit;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, pause_exit, CTLFLAG_RD, &cap_pause_exit,
    0, "PAUSE triggers a VM-exit");

static int cap_wbinvd_exit;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, wbinvd_exit, CTLFLAG_RD, &cap_wbinvd_exit,
    0, "WBINVD triggers a VM-exit");

static int cap_rdpid;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, rdpid, CTLFLAG_RD, &cap_rdpid, 0,
    "Guests are allowed to use RDPID");

static int cap_rdtscp;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, rdtscp, CTLFLAG_RD, &cap_rdtscp, 0,
    "Guests are allowed to use RDTSCP");

static int cap_unrestricted_guest;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, unrestricted_guest, CTLFLAG_RD,
    &cap_unrestricted_guest, 0, "Unrestricted guests");

static int cap_monitor_trap;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, monitor_trap, CTLFLAG_RD,
    &cap_monitor_trap, 0, "Monitor trap flag");

static int cap_invpcid;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, invpcid, CTLFLAG_RD, &cap_invpcid,
    0, "Guests are allowed to use INVPCID");

static int tpr_shadowing;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, tpr_shadowing,
    CTLFLAG_RDTUN | CTLFLAG_NOFETCH,
    &tpr_shadowing, 0, "TPR shadowing support");

static int virtual_interrupt_delivery;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, virtual_interrupt_delivery,
    CTLFLAG_RDTUN | CTLFLAG_NOFETCH,
    &virtual_interrupt_delivery, 0, "APICv virtual interrupt delivery support");

static int posted_interrupts;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, posted_interrupts,
    CTLFLAG_RDTUN | CTLFLAG_NOFETCH,
    &posted_interrupts, 0, "APICv posted interrupt support");

static int pirvec = -1;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, posted_interrupt_vector, CTLFLAG_RD,
    &pirvec, 0, "APICv posted interrupt vector");

static struct unrhdr *vpid_unr;
static u_int vpid_alloc_failed;
SYSCTL_UINT(_hw_vmm_vmx, OID_AUTO, vpid_alloc_failed, CTLFLAG_RD,
	    &vpid_alloc_failed, 0, NULL);

int guest_l1d_flush;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, l1d_flush, CTLFLAG_RDTUN | CTLFLAG_NOFETCH,
    &guest_l1d_flush, 0, NULL);
int guest_l1d_flush_sw;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, l1d_flush_sw, CTLFLAG_RDTUN | CTLFLAG_NOFETCH,
    &guest_l1d_flush_sw, 0, NULL);

static struct msr_entry msr_load_list[1] __aligned(16);

/*
 * The definitions of SDT probes for VMX.
 */

SDT_PROBE_DEFINE3(vmm, vmx, exit, entry,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, taskswitch,
    "struct vmx *", "int", "struct vm_exit *", "struct vm_task_switch *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, craccess,
    "struct vmx *", "int", "struct vm_exit *", "uint64_t");

SDT_PROBE_DEFINE4(vmm, vmx, exit, rdmsr,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t");

SDT_PROBE_DEFINE5(vmm, vmx, exit, wrmsr,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t", "uint64_t");

SDT_PROBE_DEFINE3(vmm, vmx, exit, halt,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, mtrap,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, pause,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, intrwindow,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, interrupt,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t");

SDT_PROBE_DEFINE3(vmm, vmx, exit, nmiwindow,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, inout,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, cpuid,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE5(vmm, vmx, exit, exception,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t", "int");

SDT_PROBE_DEFINE5(vmm, vmx, exit, nestedfault,
    "struct vmx *", "int", "struct vm_exit *", "uint64_t", "uint64_t");

SDT_PROBE_DEFINE4(vmm, vmx, exit, mmiofault,
    "struct vmx *", "int", "struct vm_exit *", "uint64_t");

SDT_PROBE_DEFINE3(vmm, vmx, exit, eoi,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, apicaccess,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, apicwrite,
    "struct vmx *", "int", "struct vm_exit *", "struct vlapic *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, xsetbv,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, monitor,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, mwait,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, vminsn,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, unknown,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t");

SDT_PROBE_DEFINE4(vmm, vmx, exit, return,
    "struct vmx *", "int", "struct vm_exit *", "int");

SDT_PROBE_DEFINE5(vmm, vmx, nested, entry,
    "struct vmx *", "int", "uint64_t", "uint64_t", "int");

SDT_PROBE_DEFINE5(vmm, vmx, nested, vmexit,
    "struct vmx *", "int", "uint64_t", "uint64_t", "uint32_t");

SDT_PROBE_DEFINE5(vmm, vmx, nested, failure,
    "struct vmx *", "int", "int", "uint32_t", "uint32_t");

/* A deliberate policy/lifecycle refusal, distinct from a VMX failure. */
SDT_PROBE_DEFINE5(vmm, vmx, nested, withheld,
    "struct vmx *", "int", "int", "uint32_t", "uint32_t");

SDT_PROBE_DEFINE5(vmm, vmx, nested, restore,
    "struct vmx *", "int", "uint32_t", "uint32_t", "uint32_t");

/*
 * Use the last page below 4GB as the APIC access address. This address is
 * occupied by the boot firmware so it is guaranteed that it will not conflict
 * with a page in system memory.
 */
#define	APIC_ACCESS_ADDRESS	0xFFFFF000

static int vmx_getdesc(void *vcpui, int reg, struct seg_desc *desc);
static int vmx_getreg(void *vcpui, int reg, uint64_t *retval);
static int vmx_setdesc(void *vcpui, int reg, struct seg_desc *desc);
static int vmx_setreg(void *vcpui, int reg, uint64_t val);
static uint64_t vmx_get_guest_reg(struct vmx_vcpu *, int);
static int vmx_nested_l0_refreeze_commit_frozen_intel(
    struct vmx_vcpu *);
static int vmx_nested_commit_late_entry_handoff(struct vmx_vcpu *);
static int vmx_nested_failed_entry_msrs_prepare(struct vmx_vcpu *,
    const struct vmx_nested_vmcs02_id *,
    const struct vmx_nested_failed_entry_state_plan *,
    const struct vmx_nested_failed_entry_state_plan **,
    const struct vmx_nested_software_msrs **);
static int vmx_nested_l0_thaw_cancel_intel(struct vmx_vcpu *);
static int vmx_nested_mtf_snapshot_intel(
    const struct vm_intinfo_snapshot *,
    struct vmx_nested_mtf_event_snapshot *);
static void vmx_nested_software_msrs_capture(const struct vmx_vcpu *,
    struct vmx_nested_software_msrs *);
static int vmx_run_nested(struct vmx_vcpu *, register_t, pmap_t,
    struct vm_eventinfo *, enum vmx_nested_run_target,
    struct vmm_startup_entry_owner *);
static void vmx_paging_info(struct vm_guest_paging *);
static int vmxctx_setreg(struct vmxctx *vmxctx, int reg, uint64_t val);
static void vmx_inject_pir(struct vlapic *vlapic);
#ifdef BHYVE_SNAPSHOT
static int vmx_restore_tsc(void *vcpui, uint64_t now);
#endif

static inline bool
host_has_rdpid(void)
{
	return ((cpu_stdext_feature2 & CPUID_STDEXT2_RDPID) != 0);
}

static inline bool
host_has_rdtscp(void)
{
	return ((amd_feature & AMDID_RDTSCP) != 0);
}

#ifdef KTR
static const char *
exit_reason_to_str(int reason)
{
	static char reasonbuf[32];

	switch (reason) {
	case EXIT_REASON_EXCEPTION:
		return "exception";
	case EXIT_REASON_EXT_INTR:
		return "extint";
	case EXIT_REASON_TRIPLE_FAULT:
		return "triplefault";
	case EXIT_REASON_INIT:
		return "init";
	case EXIT_REASON_SIPI:
		return "sipi";
	case EXIT_REASON_IO_SMI:
		return "iosmi";
	case EXIT_REASON_SMI:
		return "smi";
	case EXIT_REASON_INTR_WINDOW:
		return "intrwindow";
	case EXIT_REASON_NMI_WINDOW:
		return "nmiwindow";
	case EXIT_REASON_TASK_SWITCH:
		return "taskswitch";
	case EXIT_REASON_CPUID:
		return "cpuid";
	case EXIT_REASON_GETSEC:
		return "getsec";
	case EXIT_REASON_HLT:
		return "hlt";
	case EXIT_REASON_INVD:
		return "invd";
	case EXIT_REASON_INVLPG:
		return "invlpg";
	case EXIT_REASON_RDPMC:
		return "rdpmc";
	case EXIT_REASON_RDTSC:
		return "rdtsc";
	case EXIT_REASON_RSM:
		return "rsm";
	case EXIT_REASON_VMCALL:
		return "vmcall";
	case EXIT_REASON_VMCLEAR:
		return "vmclear";
	case EXIT_REASON_VMLAUNCH:
		return "vmlaunch";
	case EXIT_REASON_VMPTRLD:
		return "vmptrld";
	case EXIT_REASON_VMPTRST:
		return "vmptrst";
	case EXIT_REASON_VMREAD:
		return "vmread";
	case EXIT_REASON_VMRESUME:
		return "vmresume";
	case EXIT_REASON_VMWRITE:
		return "vmwrite";
	case EXIT_REASON_VMXOFF:
		return "vmxoff";
	case EXIT_REASON_VMXON:
		return "vmxon";
	case EXIT_REASON_CR_ACCESS:
		return "craccess";
	case EXIT_REASON_DR_ACCESS:
		return "draccess";
	case EXIT_REASON_INOUT:
		return "inout";
	case EXIT_REASON_RDMSR:
		return "rdmsr";
	case EXIT_REASON_WRMSR:
		return "wrmsr";
	case EXIT_REASON_INVAL_VMCS:
		return "invalvmcs";
	case EXIT_REASON_INVAL_MSR:
		return "invalmsr";
	case EXIT_REASON_MWAIT:
		return "mwait";
	case EXIT_REASON_MTF:
		return "mtf";
	case EXIT_REASON_MONITOR:
		return "monitor";
	case EXIT_REASON_PAUSE:
		return "pause";
	case EXIT_REASON_MCE_DURING_ENTRY:
		return "mce-during-entry";
	case EXIT_REASON_TPR:
		return "tpr";
	case EXIT_REASON_APIC_ACCESS:
		return "apic-access";
	case EXIT_REASON_GDTR_IDTR:
		return "gdtridtr";
	case EXIT_REASON_LDTR_TR:
		return "ldtrtr";
	case EXIT_REASON_EPT_FAULT:
		return "eptfault";
	case EXIT_REASON_EPT_MISCONFIG:
		return "eptmisconfig";
	case EXIT_REASON_INVEPT:
		return "invept";
	case EXIT_REASON_RDTSCP:
		return "rdtscp";
	case EXIT_REASON_VMX_PREEMPT:
		return "vmxpreempt";
	case EXIT_REASON_INVVPID:
		return "invvpid";
	case EXIT_REASON_WBINVD:
		return "wbinvd";
	case EXIT_REASON_XSETBV:
		return "xsetbv";
	case EXIT_REASON_APIC_WRITE:
		return "apic-write";
	default:
		snprintf(reasonbuf, sizeof(reasonbuf), "%d", reason);
		return (reasonbuf);
	}
}
#endif	/* KTR */

static int
vmx_allow_x2apic_msrs(struct vmx *vmx)
{
	int i, error;

	error = 0;

	/*
	 * Allow readonly access to the following x2APIC MSRs from the guest.
	 */
	error += guest_msr_ro(vmx, MSR_APIC_ID);
	error += guest_msr_ro(vmx, MSR_APIC_VERSION);
	error += guest_msr_ro(vmx, MSR_APIC_LDR);
	error += guest_msr_ro(vmx, MSR_APIC_SVR);

	for (i = 0; i < 8; i++)
		error += guest_msr_ro(vmx, MSR_APIC_ISR0 + i);

	for (i = 0; i < 8; i++)
		error += guest_msr_ro(vmx, MSR_APIC_TMR0 + i);

	for (i = 0; i < 8; i++)
		error += guest_msr_ro(vmx, MSR_APIC_IRR0 + i);

	error += guest_msr_ro(vmx, MSR_APIC_ESR);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_TIMER);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_THERMAL);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_PCINT);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_LINT0);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_LINT1);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_ERROR);
	error += guest_msr_ro(vmx, MSR_APIC_ICR_TIMER);
	error += guest_msr_ro(vmx, MSR_APIC_DCR_TIMER);
	error += guest_msr_ro(vmx, MSR_APIC_ICR);

	/*
	 * Allow TPR, EOI and SELF_IPI MSRs to be read and written by the guest.
	 *
	 * These registers get special treatment described in the section
	 * "Virtualizing MSR-Based APIC Accesses".
	 */
	error += guest_msr_rw(vmx, MSR_APIC_TPR);
	error += guest_msr_rw(vmx, MSR_APIC_EOI);
	error += guest_msr_rw(vmx, MSR_APIC_SELF_IPI);

	return (error);
}

u_long
vmx_fix_cr0(u_long cr0)
{

	return ((cr0 | cr0_ones_mask) & ~cr0_zeros_mask);
}

u_long
vmx_fix_cr4(u_long cr4)
{

	return ((cr4 | cr4_ones_mask) & ~cr4_zeros_mask);
}

static void
vpid_free(int vpid)
{
	if (vpid < 0 || vpid > 0xffff)
		panic("vpid_free: invalid vpid %d", vpid);

	/*
	 * VPIDs [0,vm_maxcpu] are special and are not allocated from
	 * the unit number allocator.
	 */

	if (vpid > vm_maxcpu)
		free_unr(vpid_unr, vpid);
}

static uint16_t
vpid_alloc(int vcpuid)
{
	int x;

	/*
	 * If the "enable vpid" execution control is not enabled then the
	 * VPID is required to be 0 for all vcpus.
	 */
	if ((procbased_ctls2 & PROCBASED2_ENABLE_VPID) == 0)
		return (0);

	/*
	 * Try to allocate a unique VPID for each from the unit number
	 * allocator.
	 */
	x = alloc_unr(vpid_unr);

	if (x == -1) {
		atomic_add_int(&vpid_alloc_failed, 1);

		/*
		 * If the unit number allocator does not have enough unique
		 * VPIDs then we need to allocate from the [1,vm_maxcpu] range.
		 *
		 * These VPIDs are not be unique across VMs but this does not
		 * affect correctness because the combined mappings are also
		 * tagged with the EP4TA which is unique for each VM.
		 *
		 * It is still sub-optimal because the invvpid will invalidate
		 * combined mappings for a particular VPID across all EP4TAs.
		 */
		return (vcpuid + 1);
	}

	return (x);
}

static int
vmx_nested_vpid_allocate(void *arg __unused, uint16_t *vpid)
{
	int value;

	if (vpid == NULL)
		return (EINVAL);
	if ((procbased_ctls2 & PROCBASED2_ENABLE_VPID) == 0)
		return (ENOTSUP);
	value = alloc_unr(vpid_unr);
	if (value == -1) {
		atomic_add_int(&vpid_alloc_failed, 1);
		return (ENOSPC);
	}
	/*
	 * Unlike VMCS01, VMCS02 must never use the shared overflow
	 * namespace.  alloc_unr() is bounded to the unique range.
	 */
	KASSERT(value > vm_maxcpu && value <= UINT16_MAX,
	    ("%s: allocator returned non-unique VPID %d", __func__, value));
	*vpid = value;
	return (0);
}

static void
vmx_nested_vpid_release(void *arg __unused, uint16_t vpid)
{

	vpid_free(vpid);
}

static const struct vmx_nested_vpid_owner_ops vmx_nested_vpid_ops = {
	.allocate = vmx_nested_vpid_allocate,
	.release = vmx_nested_vpid_release,
};

static int
vmx_nested_vpid_ensure(struct vmx_vcpu *vcpu)
{

	if (vcpu == NULL ||
	    vmx_nested_vpid_owner_validate(&vcpu->nested_vpid_owner) != 0)
		return (EINVAL);
	/*
	 * VPID is an optional acceleration.  A VMCS01 running without VPID
	 * must still be able to run an untagged VMCS02 when the virtual
	 * capability policy also withholds VPID from L1.
	 */
	if (vcpu->state.vpid == 0)
		return (!vcpu->nested_vpid_owner.active &&
		    !vmx_nested_vpid_owner_flush_required(
		    &vcpu->nested_vpid_owner) ? 0 : EPROTO);
	return (vmx_nested_vpid_owner_acquire(&vcpu->nested_vpid_owner,
	    vcpu->state.vpid, &vmx_nested_vpid_ops, NULL));
}

static void
vpid_init(void)
{
	/*
	 * VPID 0 is required when the "enable VPID" execution control is
	 * disabled.
	 *
	 * VPIDs [1,vm_maxcpu] are used as the "overflow namespace" when the
	 * unit number allocator does not have sufficient unique VPIDs to
	 * satisfy the allocation.
	 *
	 * The remaining VPIDs are managed by the unit number allocator.
	 */
	vpid_unr = new_unrhdr(vm_maxcpu + 1, 0xffff, NULL);
}

static void
vmx_disable(void *arg __unused)
{
	struct invvpid_desc invvpid_desc = { 0 };
	struct invept_desc invept_desc = { 0 };

	if (vmxon_enabled[curcpu]) {
		/*
		 * See sections 25.3.3.3 and 25.3.3.4 in Intel Vol 3b.
		 *
		 * VMXON or VMXOFF are not required to invalidate any TLB
		 * caching structures. This prevents potential retention of
		 * cached information in the TLB between distinct VMX episodes.
		 */
		invvpid(INVVPID_TYPE_ALL_CONTEXTS, invvpid_desc);
		invept(INVEPT_TYPE_ALL_CONTEXTS, invept_desc);
		vmxoff();
	}
	vmxon_enabled[curcpu] = 0;
	load_cr4(rcr4() & ~CR4_VMXE);
}

static int
vmx_modcleanup(void)
{

	if (pirvec >= 0) {
		lapic_ipi_free(pirvec);
		pirvec = -1;
	}
	/*
	 * A later module load must not reuse a freed vector when replacement
	 * allocation is unavailable.  Keep the normal-unload state identical to
	 * the failed-initialization rollback below.
	 */
	posted_interrupts = 0;

	if (vpid_unr != NULL) {
		delete_unrhdr(vpid_unr);
		vpid_unr = NULL;
	}

	if (nmi_flush_l1d_sw == 1)
		nmi_flush_l1d_sw = 0;

	smp_rendezvous(NULL, vmx_disable, NULL, NULL);

	if (vmxon_region != NULL) {
		kmem_free(vmxon_region, (mp_maxid + 1) * PAGE_SIZE);
		vmxon_region = NULL;
	}
	/* The read-only status sysctl must not describe a released backend. */
	vmx_initialized = 0;

	return (0);
}

static void
vmx_enable(void *arg __unused)
{
	int error;
	uint64_t feature_control;

	/* Record the result of this attempt, not a prior VMX episode. */
	vmxon_enabled[curcpu] = 0;
	vmxon_error[curcpu] = 0;

	feature_control = rdmsr(MSR_IA32_FEATURE_CONTROL);
	if ((feature_control & IA32_FEATURE_CONTROL_LOCK) == 0 ||
	    (feature_control & IA32_FEATURE_CONTROL_VMX_EN) == 0) {
		wrmsr(MSR_IA32_FEATURE_CONTROL,
		    feature_control | IA32_FEATURE_CONTROL_VMX_EN |
		    IA32_FEATURE_CONTROL_LOCK);
	}

	load_cr4(rcr4() | CR4_VMXE);

	*(uint32_t *)&vmxon_region[curcpu * PAGE_SIZE] = vmx_revision();
	error = vmxon(&vmxon_region[curcpu * PAGE_SIZE]);
	if (error == 0) {
		vmxon_enabled[curcpu] = 1;
	} else {
		vmxon_error[curcpu] = error;
		load_cr4(rcr4() & ~CR4_VMXE);
	}
}

static void
vmx_modsuspend(void)
{

	vmxon_resume[curcpu] = vmxon_enabled[curcpu] != 0;
	if (vmxon_resume[curcpu])
		vmx_disable(NULL);
}

static void
vmx_modresume(void)
{

	if (vmxon_resume[curcpu]) {
		vmx_enable(NULL);
		if (!vmxon_enabled[curcpu])
			panic("%s: VMXON failed on CPU %d: %d", __func__, curcpu,
			    vmxon_error[curcpu]);
	}
	vmxon_resume[curcpu] = false;
}

static int
vmx_modinit(int ipinum)
{
	struct vmx_nested_capability_policy_input nested_policy;
	int cpu, error;
	uint64_t basic, fixed0, fixed1, feature_control;
	uint32_t tmp, procbased2_vid_bits;

	/* Reject inconsistent experimental policy before allocating resources. */
	if (nested_vpid_qualification != 0 && nested_vmx_allowed == 0) {
		printf("vmx_modinit: hw.vmm.vmx.nested_vpid requires "
		    "hw.vmm.vmx.nested=1\n");
		return (EINVAL);
	}

	/* CPUID.1:ECX[bit 5] must be 1 for processor to support VMX */
	if (!(cpu_feature2 & CPUID2_VMX)) {
		printf("vmx_modinit: processor does not support VMX "
		    "operation\n");
		return (ENXIO);
	}

	/*
	 * Verify that MSR_IA32_FEATURE_CONTROL lock and VMXON enable bits
	 * are set (bits 0 and 2 respectively).
	 */
	feature_control = rdmsr(MSR_IA32_FEATURE_CONTROL);
	if ((feature_control & IA32_FEATURE_CONTROL_LOCK) == 1 &&
	    (feature_control & IA32_FEATURE_CONTROL_VMX_EN) == 0) {
		printf("vmx_modinit: VMX operation disabled by BIOS\n");
		return (ENXIO);
	}

	/*
	 * Verify capabilities MSR_VMX_BASIC:
	 * - bit 54 indicates support for INS/OUTS decoding
	 */
	basic = rdmsr(MSR_VMX_BASIC);
	if ((basic & (1UL << 54)) == 0) {
		printf("vmx_modinit: processor does not support desired basic "
		    "capabilities\n");
		return (EINVAL);
	}
	error = vmx_nested_control_capabilities_intel_read(
	    &vmx_nested_hardware_controls);
	if (error != 0) {
		printf("vmx_modinit: invalid hardware VMX control "
		    "capabilities\n");
		return (error);
	}

	/* Check support for primary processor-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
			       MSR_VMX_TRUE_PROCBASED_CTLS,
			       PROCBASED_CTLS_ONE_SETTING,
			       PROCBASED_CTLS_ZERO_SETTING, &procbased_ctls);
	if (error) {
		printf("vmx_modinit: processor does not support desired "
		    "primary processor-based controls\n");
		return (error);
	}

	/* Clear the processor-based ctl bits that are set on demand */
	procbased_ctls &= ~PROCBASED_CTLS_WINDOW_SETTING;

	/* Check support for secondary processor-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
			       MSR_VMX_PROCBASED_CTLS2,
			       PROCBASED_CTLS2_ONE_SETTING,
			       PROCBASED_CTLS2_ZERO_SETTING, &procbased_ctls2);
	if (error) {
		printf("vmx_modinit: processor does not support desired "
		    "secondary processor-based controls\n");
		return (error);
	}

	/* Check support for VPID */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2, MSR_VMX_PROCBASED_CTLS2,
			       PROCBASED2_ENABLE_VPID, 0, &tmp);
	if (error == 0)
		procbased_ctls2 |= PROCBASED2_ENABLE_VPID;

	/* Check support for pin-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PINBASED_CTLS,
			       MSR_VMX_TRUE_PINBASED_CTLS,
			       PINBASED_CTLS_ONE_SETTING,
			       PINBASED_CTLS_ZERO_SETTING, &pinbased_ctls);
	if (error) {
		printf("vmx_modinit: processor does not support desired "
		    "pin-based controls\n");
		return (error);
	}

	/* Check support for VM-exit controls */
	error = vmx_set_ctlreg(MSR_VMX_EXIT_CTLS, MSR_VMX_TRUE_EXIT_CTLS,
			       VM_EXIT_CTLS_ONE_SETTING,
			       VM_EXIT_CTLS_ZERO_SETTING,
			       &exit_ctls);
	if (error) {
		printf("vmx_modinit: processor does not support desired "
		    "exit controls\n");
		return (error);
	}

	/* Check support for VM-entry controls */
	error = vmx_set_ctlreg(MSR_VMX_ENTRY_CTLS, MSR_VMX_TRUE_ENTRY_CTLS,
	    VM_ENTRY_CTLS_ONE_SETTING, VM_ENTRY_CTLS_ZERO_SETTING,
	    &entry_ctls);
	if (error) {
		printf("vmx_modinit: processor does not support desired "
		    "entry controls\n");
		return (error);
	}

	/*
	 * Check support for optional features by testing them
	 * as individual bits
	 */
	cap_halt_exit = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
					MSR_VMX_TRUE_PROCBASED_CTLS,
					PROCBASED_HLT_EXITING, 0,
					&tmp) == 0);

	cap_monitor_trap = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
					MSR_VMX_PROCBASED_CTLS,
					PROCBASED_MTF, 0,
					&tmp) == 0);

	cap_pause_exit = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
					 MSR_VMX_TRUE_PROCBASED_CTLS,
					 PROCBASED_PAUSE_EXITING, 0,
					 &tmp) == 0);

	cap_wbinvd_exit = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
					MSR_VMX_PROCBASED_CTLS2,
					PROCBASED2_WBINVD_EXITING,
					0,
					&tmp) == 0);

	/*
	 * Check support for RDPID and/or RDTSCP.
	 *
	 * Support a pass-through-based implementation of these via the
	 * "enable RDTSCP" VM-execution control and the "RDTSC exiting"
	 * VM-execution control.
	 *
	 * The "enable RDTSCP" VM-execution control applies to both RDPID
	 * and RDTSCP (see SDM volume 3, section 25.3, "Changes to
	 * Instruction Behavior in VMX Non-root operation"); this is why
	 * only this VM-execution control needs to be enabled in order to
	 * enable passing through whichever of RDPID and/or RDTSCP are
	 * supported by the host.
	 *
	 * The "RDTSC exiting" VM-execution control applies to both RDTSC
	 * and RDTSCP (again, per SDM volume 3, section 25.3), and is
	 * already set up for RDTSC and RDTSCP pass-through by the current
	 * implementation of RDTSC.
	 *
	 * Although RDPID and RDTSCP are optional capabilities, since there
	 * does not currently seem to be a use case for enabling/disabling
	 * these via libvmmapi, choose not to support this and, instead,
	 * just statically always enable or always disable this support
	 * across all vCPUs on all VMs. (Note that there may be some
	 * complications to providing this functionality, e.g., the MSR
	 * bitmap is currently per-VM rather than per-vCPU while the
	 * capability API wants to be able to control capabilities on a
	 * per-vCPU basis).
	 */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
			       MSR_VMX_PROCBASED_CTLS2,
			       PROCBASED2_ENABLE_RDTSCP, 0, &tmp);
	cap_rdpid = error == 0 && host_has_rdpid();
	cap_rdtscp = error == 0 && host_has_rdtscp();
	if (cap_rdpid || cap_rdtscp) {
		procbased_ctls2 |= PROCBASED2_ENABLE_RDTSCP;
		vmx_have_msr_tsc_aux = true;
	}

	cap_unrestricted_guest = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
					MSR_VMX_PROCBASED_CTLS2,
					PROCBASED2_UNRESTRICTED_GUEST, 0,
				        &tmp) == 0);

	cap_invpcid = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
	    MSR_VMX_PROCBASED_CTLS2, PROCBASED2_ENABLE_INVPCID, 0,
	    &tmp) == 0);

	/*
	 * Check support for TPR shadow.
	 */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
	    MSR_VMX_TRUE_PROCBASED_CTLS, PROCBASED_USE_TPR_SHADOW, 0,
	    &tmp);
	if (error == 0) {
		tpr_shadowing = 1;
#ifndef BURN_BRIDGES
		TUNABLE_INT_FETCH("hw.vmm.vmx.use_tpr_shadowing",
		    &tpr_shadowing);
#endif
		TUNABLE_INT_FETCH("hw.vmm.vmx.cap.tpr_shadowing",
		    &tpr_shadowing);
	}

	if (tpr_shadowing) {
		procbased_ctls |= PROCBASED_USE_TPR_SHADOW;
		procbased_ctls &= ~PROCBASED_CR8_LOAD_EXITING;
		procbased_ctls &= ~PROCBASED_CR8_STORE_EXITING;
	}

	/*
	 * Check support for virtual interrupt delivery.
	 */
	procbased2_vid_bits = (PROCBASED2_VIRTUALIZE_APIC_ACCESSES |
	    PROCBASED2_VIRTUALIZE_X2APIC_MODE |
	    PROCBASED2_APIC_REGISTER_VIRTUALIZATION |
	    PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY);

	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2, MSR_VMX_PROCBASED_CTLS2,
	    procbased2_vid_bits, 0, &tmp);
	if (error == 0 && tpr_shadowing) {
		virtual_interrupt_delivery = 1;
#ifndef BURN_BRIDGES
		TUNABLE_INT_FETCH("hw.vmm.vmx.use_apic_vid",
		    &virtual_interrupt_delivery);
#endif
		TUNABLE_INT_FETCH("hw.vmm.vmx.cap.virtual_interrupt_delivery",
		    &virtual_interrupt_delivery);
	}

	if (virtual_interrupt_delivery) {
		procbased_ctls |= PROCBASED_USE_TPR_SHADOW;
		procbased_ctls2 |= procbased2_vid_bits;
		procbased_ctls2 &= ~PROCBASED2_VIRTUALIZE_X2APIC_MODE;

		/*
		 * Check for Posted Interrupts only if Virtual Interrupt
		 * Delivery is enabled.
		 */
		error = vmx_set_ctlreg(MSR_VMX_PINBASED_CTLS,
		    MSR_VMX_TRUE_PINBASED_CTLS, PINBASED_POSTED_INTERRUPT, 0,
		    &tmp);
		if (error == 0) {
			pirvec = lapic_ipi_alloc(pti ? &IDTVEC(justreturn1_pti) :
			    &IDTVEC(justreturn));
			if (pirvec < 0) {
				if (bootverbose) {
					printf("vmx_modinit: unable to "
					    "allocate posted interrupt "
					    "vector\n");
				}
			} else {
				posted_interrupts = 1;
#ifndef BURN_BRIDGES
				TUNABLE_INT_FETCH("hw.vmm.vmx.use_apic_pir",
				    &posted_interrupts);
#endif
				TUNABLE_INT_FETCH("hw.vmm.vmx.cap.posted_interrupts",
				    &posted_interrupts);
			}
		}
	}

	if (posted_interrupts)
		    pinbased_ctls |= PINBASED_POSTED_INTERRUPT;

	/*
	 * Preserve one immutable hardware capability contract for nested
	 * entry composition.  The ordinary control setup above selects
	 * policy values; this check ensures those values remain a valid
	 * subset of the raw architectural MSRs cached for VMCS02.
	 */
	if (!vmx_nested_control_valid(pinbased_ctls,
	    vmx_nested_hardware_controls.pinbased) ||
	    !vmx_nested_control_valid(procbased_ctls,
	    vmx_nested_hardware_controls.primary) ||
	    !vmx_nested_control_valid(procbased_ctls2,
	    vmx_nested_hardware_controls.secondary) ||
	    !vmx_nested_control_valid(exit_ctls,
	    vmx_nested_hardware_controls.vmexit) ||
	    !vmx_nested_control_valid(entry_ctls,
	    vmx_nested_hardware_controls.vmentry)) {
		printf("vmx_modinit: selected VMX controls exceed hardware "
		    "capabilities\n");
		error = EINVAL;
		goto fail;
	}

	/* Initialize EPT */
	error = ept_init(ipinum);
	if (error) {
		printf("vmx_modinit: ept initialization failed (%d)\n", error);
		goto fail;
	}

	guest_l1d_flush = (cpu_ia32_arch_caps &
	    IA32_ARCH_CAP_SKIP_L1DFL_VMENTRY) == 0;
#ifndef BURN_BRIDGES
	TUNABLE_INT_FETCH("hw.vmm.l1d_flush", &guest_l1d_flush);
#endif
	TUNABLE_INT_FETCH("hw.vmm.vmx.l1d_flush", &guest_l1d_flush);

	/*
	 * L1D cache flush is enabled.  Use IA32_FLUSH_CMD MSR when
	 * available.  Otherwise fall back to the software flush
	 * method which loads enough data from the kernel text to
	 * flush existing L1D content, both on VMX entry and on NMI
	 * return.
	 */
	if (guest_l1d_flush) {
		if ((cpu_stdext_feature3 & CPUID_STDEXT3_L1D_FLUSH) == 0) {
			guest_l1d_flush_sw = 1;
#ifndef BURN_BRIDGES
			TUNABLE_INT_FETCH("hw.vmm.l1d_flush_sw",
			    &guest_l1d_flush_sw);
#endif
			TUNABLE_INT_FETCH("hw.vmm.vmx.l1d_flush_sw",
			    &guest_l1d_flush_sw);
		}
		if (guest_l1d_flush_sw) {
			if (nmi_flush_l1d_sw <= 1)
				nmi_flush_l1d_sw = 1;
		} else {
			msr_load_list[0].index = MSR_IA32_FLUSH_CMD;
			msr_load_list[0].val = IA32_FLUSH_CMD_L1D;
		}
	}

	/*
	 * Stash the cr0 and cr4 bits that must be fixed to 0 or 1
	 */
	fixed0 = rdmsr(MSR_VMX_CR0_FIXED0);
	fixed1 = rdmsr(MSR_VMX_CR0_FIXED1);
	cr0_ones_mask = fixed0 & fixed1;
	cr0_zeros_mask = ~fixed0 & ~fixed1;

	/*
	 * CR0_PE and CR0_PG can be set to zero in VMX non-root operation
	 * if unrestricted guest execution is allowed.
	 */
	if (cap_unrestricted_guest)
		cr0_ones_mask &= ~(CR0_PG | CR0_PE);

	/*
	 * Do not allow the guest to set CR0_NW or CR0_CD.
	 */
	cr0_zeros_mask |= (CR0_NW | CR0_CD);

	fixed0 = rdmsr(MSR_VMX_CR4_FIXED0);
	fixed1 = rdmsr(MSR_VMX_CR4_FIXED1);
	cr4_ones_mask = fixed0 & fixed1;
	cr4_zeros_mask = ~fixed0 & ~fixed1;

	/*
	 * Construct one immutable virtual contract from the hardware ceiling.
	 * It intentionally remains unadvertised until the exposure gate is
	 * complete, but every instruction handoff and VMCS12 registry will use
	 * this exact value rather than a test-only or per-entry policy.
	 */
	memset(&nested_policy, 0, sizeof(nested_policy));
	/*
	 * EPT02 is currently represented by an LA48 user vmspace.  Do not
	 * advertise a nested physical-address width whose highest L2 GPA the
	 * composed pmap cannot index, even when newer hardware implements a
	 * wider MAXPHYADDR.  A future wider root must raise both limits in one
	 * change.
	 */
	error = vmx_nested_capabilities_limit_physical_width(
	    MIN(cpu_maxphyaddr, 52), VM_MAXUSER_ADDRESS_LA48,
	    &nested_policy.physical_address_width);
	if (error != 0) {
		printf("vmx_modinit: cannot bound nested physical-address "
		    "width: %d\n", error);
		goto fail;
	}
	/*
	 * Derive the nested architectural width from the virtual CPUID policy,
	 * not directly from the host ceiling.  In particular, an LA57-capable
	 * host must not let an L1 select 57-bit host or guest state while leaf 7
	 * hides LA57 from that same L1.
	 */
	nested_policy.linear_address_width = x86_cpuid_linear_address_width(
	    x86_cpuid_guest_stdext2(cpu_stdext_feature2));
	/*
	 * Pending-debug RTM state is valid only when the same virtual CPUID
	 * contract presented to L1 enumerates RTM.  Record that non-VMX input
	 * in the migration-stable nested capability image rather than consulting
	 * destination hardware during VM entry or restore.
	 */
	if ((cpu_stdext_feature & CPUID_STDEXT_RTM) != 0)
		nested_policy.guest_features |= VMX_NESTED_GUEST_F_RTM;
	if (nested_vpid_qualification != 0) {
		nested_policy.policy_flags |=
		    VMX_NESTED_POLICY_F_QUALIFY_VPID;
	}
	nested_policy.pinbased = vmx_nested_hardware_controls.pinbased;
	nested_policy.primary = vmx_nested_hardware_controls.primary;
	nested_policy.secondary = vmx_nested_hardware_controls.secondary;
	nested_policy.vmexit = vmx_nested_hardware_controls.vmexit;
	nested_policy.vmentry = vmx_nested_hardware_controls.vmentry;
	nested_policy.cr0_fixed0 = rdmsr(MSR_VMX_CR0_FIXED0);
	nested_policy.cr0_fixed1 = rdmsr(MSR_VMX_CR0_FIXED1);
	nested_policy.cr4_fixed0 = fixed0;
	nested_policy.cr4_fixed1 = fixed1;
	nested_policy.ept_vpid = rdmsr(MSR_VMX_EPT_VPID_CAP);
	nested_policy.misc = rdmsr(MSR_VMX_MISC);
	nested_policy.debugctl_allowed = UINT64_MAX;
	error = vmx_nested_capabilities_build(&nested_policy,
	    &vmx_nested_virtual_capabilities);
	if (error != 0) {
		printf("vmx_modinit: cannot construct virtual nested-VMX "
		    "capability policy: %d\n", error);
		goto fail;
	}

	vpid_init();

	vmx_msr_init();

	/* enable VMX operation */
	vmxon_region = kmem_malloc((mp_maxid + 1) * PAGE_SIZE,
	    M_WAITOK | M_ZERO);
	smp_rendezvous(NULL, vmx_enable, NULL, NULL);
	CPU_FOREACH(cpu) {
		if (vmxon_enabled[cpu])
			continue;
		printf("vmx_modinit: VMXON failed on CPU %d: %d\n", cpu,
		    vmxon_error[cpu]);
		error = ENXIO;
		goto fail_vmxon;
	}

	vmx_initialized = 1;

	return (0);

fail_vmxon:
	smp_rendezvous(NULL, vmx_disable, NULL, NULL);
	kmem_free(vmxon_region, (mp_maxid + 1) * PAGE_SIZE);
	vmxon_region = NULL;
	bzero(vmxon_error, sizeof(vmxon_error));
	bzero(vmxon_resume, sizeof(vmxon_resume));
	delete_unrhdr(vpid_unr);
	vpid_unr = NULL;

fail:
	/*
	 * Posted-interrupt allocation precedes several hardware and policy
	 * validations.  No common cleanup callback is installed for a backend
	 * whose module initialization failed, so undo every module-global state
	 * mutation performed before returning the original error.  In
	 * particular, capability-policy construction can fail after software
	 * L1D-flush support has made the NMI path active; leaving that bit set
	 * would make a later module load inherit state from this failed attempt.
	 */
	if (pirvec >= 0) {
		lapic_ipi_free(pirvec);
		pirvec = -1;
	}
	posted_interrupts = 0;
	if (nmi_flush_l1d_sw == 1)
		nmi_flush_l1d_sw = 0;
	return (error);
}

static void
vmx_trigger_hostintr(int vector)
{
	uintptr_t func;
	struct gate_descriptor *gd;

	gd = &idt[vector];

	KASSERT(vector >= 32 && vector <= 255, ("vmx_trigger_hostintr: "
	    "invalid vector %d", vector));
	KASSERT(gd->gd_p == 1, ("gate descriptor for vector %d not present",
	    vector));
	KASSERT(gd->gd_type == SDT_SYSIGT, ("gate descriptor for vector %d "
	    "has invalid type %d", vector, gd->gd_type));
	KASSERT(gd->gd_dpl == SEL_KPL, ("gate descriptor for vector %d "
	    "has invalid dpl %d", vector, gd->gd_dpl));
	KASSERT(gd->gd_selector == GSEL(GCODE_SEL, SEL_KPL), ("gate descriptor "
	    "for vector %d has invalid selector %d", vector, gd->gd_selector));
	KASSERT(gd->gd_ist == 0, ("gate descriptor for vector %d has invalid "
	    "IST %d", vector, gd->gd_ist));

	func = ((long)gd->gd_hioffset << 16 | gd->gd_looffset);
	vmx_call_isr(func);
}

static int
vmx_setup_cr_shadow(int which, struct vmcs *vmcs, uint32_t initial)
{
	int error, mask_ident, shadow_ident;
	uint64_t mask_value;

	if (which != 0 && which != 4)
		panic("vmx_setup_cr_shadow: unknown cr%d", which);

	if (which == 0) {
		mask_ident = VMCS_CR0_MASK;
		mask_value = cr0_ones_mask | cr0_zeros_mask;
		shadow_ident = VMCS_CR0_SHADOW;
	} else {
		mask_ident = VMCS_CR4_MASK;
		mask_value = cr4_ones_mask | cr4_zeros_mask;
		shadow_ident = VMCS_CR4_SHADOW;
	}

	error = vmcs_setreg(vmcs, 0, VMCS_IDENT(mask_ident), mask_value);
	if (error)
		return (error);

	error = vmcs_setreg(vmcs, 0, VMCS_IDENT(shadow_ident), initial);
	if (error)
		return (error);

	return (0);
}
#define	vmx_setup_cr0_shadow(vmcs,init)	vmx_setup_cr_shadow(0, (vmcs), (init))
#define	vmx_setup_cr4_shadow(vmcs,init)	vmx_setup_cr_shadow(4, (vmcs), (init))

static void *
vmx_init(struct vm *vm, pmap_t pmap)
{
	int error __diagused;
	struct vmx *vmx;

	vmx = malloc(sizeof(struct vmx), M_VMX, M_WAITOK | M_ZERO);
	vmx->vm = vm;
	sx_init(&vmx->nested_vmcs_sx, "nested VMCS");
	error = vmx_nested_vmcs_registry_init(&vmx->nested_vmcs_registry,
	    &vmx_nested_virtual_capabilities,
	    VMX_NESTED_VMCS_REGISTRY_LIMIT);
	if (error != 0)
		panic("%s: cannot initialize nested VMCS registry: %d",
		    __func__, error);

	vmx->eptp = eptp(vtophys((vm_offset_t)pmap->pm_pmltop));

	/*
	 * Clean up EPTP-tagged guest physical and combined mappings
	 *
	 * VMX transitions are not required to invalidate any guest physical
	 * mappings. So, it may be possible for stale guest physical mappings
	 * to be present in the processor TLBs.
	 *
	 * Combined mappings for this EP4TA are also invalidated for all VPIDs.
	 */
	ept_invalidate_mappings(vmx->eptp);

	vmx->msr_bitmap = malloc_aligned(PAGE_SIZE, PAGE_SIZE, M_VMX,
	    M_WAITOK | M_ZERO);
	msr_bitmap_initialize(vmx->msr_bitmap);

	/*
	 * It is safe to allow direct access to MSR_GSBASE and MSR_FSBASE.
	 * The guest FSBASE and GSBASE are saved and restored during
	 * vm-exit and vm-entry respectively. The host FSBASE and GSBASE are
	 * always restored from the vmcs host state area on vm-exit.
	 *
	 * The SYSENTER_CS/ESP/EIP MSRs are identical to FS/GSBASE in
	 * how they are saved/restored so can be directly accessed by the
	 * guest.
	 *
	 * MSR_EFER is saved and restored in the guest VMCS area on a
	 * VM exit and entry respectively. It is also restored from the
	 * host VMCS area on a VM exit.
	 *
	 * The TSC MSR is exposed read-only. Writes are disallowed as
	 * that will impact the host TSC.  If the guest does a write
	 * the "use TSC offsetting" execution control is enabled and the
	 * difference between the host TSC and the guest TSC is written
	 * into the TSC offset in the VMCS.
	 *
	 * Guest TSC_AUX support is enabled if any of guest RDPID and/or
	 * guest RDTSCP support are enabled (since, as per Table 2-2 in SDM
	 * volume 4, TSC_AUX is supported if any of RDPID and/or RDTSCP are
	 * supported). If guest TSC_AUX support is enabled, TSC_AUX is
	 * exposed read-only so that the VMM can do one fewer MSR read per
	 * exit than if this register were exposed read-write; the guest
	 * restore value can be updated during guest writes (expected to be
	 * rare) instead of during all exits (common).
	 */
	if (guest_msr_rw(vmx, MSR_GSBASE) ||
	    guest_msr_rw(vmx, MSR_FSBASE) ||
	    guest_msr_rw(vmx, MSR_SYSENTER_CS_MSR) ||
	    guest_msr_rw(vmx, MSR_SYSENTER_ESP_MSR) ||
	    guest_msr_rw(vmx, MSR_SYSENTER_EIP_MSR) ||
	    guest_msr_rw(vmx, MSR_EFER) ||
	    guest_msr_ro(vmx, MSR_TSC) ||
	    ((cap_rdpid || cap_rdtscp) && guest_msr_ro(vmx, MSR_TSC_AUX)))
		panic("vmx_init: error setting guest msr access");

	if (virtual_interrupt_delivery) {
		error = vm_map_mmio(vm, DEFAULT_APIC_BASE, PAGE_SIZE,
		    APIC_ACCESS_ADDRESS);
		/* vmx_init() cannot propagate an error to the common VM owner. */
		if (error != 0)
			panic("%s: cannot map APIC-access page: %d", __func__,
			    error);
	}

	vmx->pmap = pmap;
	return (vmx);
}

static void *
vmx_vcpu_init(void *vmi, struct vcpu *vcpu1, int vcpuid)
{
	struct vmx *vmx = vmi;
	struct vmcs *vmcs;
	struct vmx_vcpu *vcpu;
	uint32_t exc_bitmap;
	uint16_t vpid;
	int error;

	vpid = vpid_alloc(vcpuid);

	vcpu = malloc(sizeof(*vcpu), M_VMX, M_WAITOK | M_ZERO);
	vcpu->vmx = vmx;
	vcpu->vcpu = vcpu1;
	vcpu->vcpuid = vcpuid;
	vmx_nested_context_init(&vcpu->nested);
	vmx_nested_control_msr_init(&vcpu->nested_control_msrs);
	vmx_nested_entry_runtime_init(&vcpu->nested_entry_runtime);
	vmx_nested_l0_continuation_init(&vcpu->nested_l0_continuation);
	vmx_nested_mtf_owner_init(&vcpu->nested_mtf_owner);
	vmx_nested_startup_dispatch_init(&vcpu->nested_startup_dispatch);
	vmx_nested_l2_thaw_staged_init(&vcpu->nested_l2_thaw_staged);
	vmx_nested_refreeze_staged_init(&vcpu->nested_refreeze_staged);
	vmx_nested_msr_workspace_init(&vcpu->nested_msr_workspace);
	vmx_nested_exit_msr_transaction_init(
	    &vcpu->nested_exit_msr_transaction);
	vcpu->nested_ept_backend.min_address = 0;
	vcpu->nested_ept_backend.max_address = VM_MAXUSER_ADDRESS_LA48;
	vmx_nested_ept_binding_init(&vcpu->nested_ept_binding);
	error = vmx_nested_ept_cache_init(&vcpu->nested_ept_cache,
	    vcpu->nested_ept_entries, nitems(vcpu->nested_ept_entries),
	    &vmx_nested_ept_cache_ops, &vcpu->nested_ept_backend);
	if (error != 0)
		panic("%s: cannot initialize nested EPT root cache: %d",
		    __func__, error);
	vcpu->vmcs = malloc_aligned(sizeof(*vmcs), PAGE_SIZE, M_VMX,
	    M_WAITOK | M_ZERO);
	vcpu->nested_vmcs02 = malloc_aligned(sizeof(*vmcs), PAGE_SIZE, M_VMX,
	    M_WAITOK | M_ZERO);
	vmx_nested_vmcs02_intel_init(&vcpu->nested_vmcs02_intel,
	    vcpu->vmcs, vcpu->nested_vmcs02);
	vmx_nested_vmcs02_lease_owner_init(&vcpu->nested_vmcs02_leases);
	vmx_nested_vpid_owner_init(&vcpu->nested_vpid_owner);
	vcpu->nested_vmcs_scratch = malloc(VMX_NESTED_VMCS_REGION_SIZE,
	    M_VMX, M_WAITOK | M_ZERO);
	vcpu->nested_msr_bitmap = malloc_aligned(VMX_NESTED_MSR_BITMAP_SIZE,
	    VMX_NESTED_MSR_BITMAP_SIZE, M_VMX,
	    M_WAITOK | M_ZERO);
	vcpu->nested_l1_msr_bitmap = malloc_aligned(VMX_NESTED_MSR_BITMAP_SIZE,
	    VMX_NESTED_MSR_BITMAP_SIZE,
	    M_VMX, M_WAITOK | M_ZERO);
	vcpu->nested_msr_bitmap_scratch = malloc_aligned(
	    VMX_NESTED_MSR_BITMAP_SIZE, VMX_NESTED_MSR_BITMAP_SIZE,
	    M_VMX, M_WAITOK | M_ZERO);
	vcpu->nested_l1_io_bitmap = malloc_aligned(
	    VMX_NESTED_IO_BITMAP_SIZE, PAGE_SIZE, M_VMX, M_WAITOK | M_ZERO);
	vcpu->nested_l1_io_bitmap_scratch = malloc_aligned(
	    VMX_NESTED_IO_BITMAP_SIZE, PAGE_SIZE, M_VMX, M_WAITOK | M_ZERO);
	vcpu->apic_page = malloc_aligned(PAGE_SIZE, PAGE_SIZE, M_VMX,
	    M_WAITOK | M_ZERO);
	vcpu->pir_desc = malloc_aligned(sizeof(*vcpu->pir_desc), 64, M_VMX,
	    M_WAITOK | M_ZERO);

	vmcs = vcpu->vmcs;
	vmcs->identifier = vmx_revision();
	error = vmclear(vmcs);
	if (error != 0) {
		panic("vmx_init: vmclear error %d on vcpu %d\n",
		    error, vcpuid);
	}

	vmx_msr_guest_init(vmx, vcpu);

	error = vmcs_init(vmcs);
	if (error != 0)
		panic("%s: vmcs_init failed: %d", __func__, error);

	VMPTRLD(vmcs);
	error = 0;
	error += vmwrite(VMCS_HOST_RSP, (u_long)&vcpu->ctx);
	error += vmwrite(VMCS_EPTP, vmx->eptp);
	error += vmwrite(VMCS_PIN_BASED_CTLS, pinbased_ctls);
	error += vmwrite(VMCS_PRI_PROC_BASED_CTLS, procbased_ctls);
	if (vcpu_trap_wbinvd(vcpu->vcpu)) {
		KASSERT(cap_wbinvd_exit, ("WBINVD trap not available"));
		procbased_ctls2 |= PROCBASED2_WBINVD_EXITING;
	}
	error += vmwrite(VMCS_SEC_PROC_BASED_CTLS, procbased_ctls2);
	error += vmwrite(VMCS_EXIT_CTLS, exit_ctls);
	error += vmwrite(VMCS_ENTRY_CTLS, entry_ctls);
	error += vmwrite(VMCS_MSR_BITMAP, vtophys(vmx->msr_bitmap));
	error += vmwrite(VMCS_VPID, vpid);

	if (guest_l1d_flush && !guest_l1d_flush_sw) {
		vmcs_write(VMCS_ENTRY_MSR_LOAD, pmap_kextract(
			(vm_offset_t)&msr_load_list[0]));
		vmcs_write(VMCS_ENTRY_MSR_LOAD_COUNT,
		    nitems(msr_load_list));
		vmcs_write(VMCS_EXIT_MSR_STORE, 0);
		vmcs_write(VMCS_EXIT_MSR_STORE_COUNT, 0);
	}

	/* exception bitmap */
	if (vcpu_trace_exceptions(vcpu->vcpu))
		exc_bitmap = 0xffffffff;
	else
		exc_bitmap = 1 << IDT_MC;
	error += vmwrite(VMCS_EXCEPTION_BITMAP, exc_bitmap);

	vcpu->ctx.guest_dr6 = DBREG_DR6_RESERVED1;
	error += vmwrite(VMCS_GUEST_DR7, DBREG_DR7_RESERVED1);

	if (tpr_shadowing) {
		error += vmwrite(VMCS_VIRTUAL_APIC, vtophys(vcpu->apic_page));
	}

	if (virtual_interrupt_delivery) {
		error += vmwrite(VMCS_APIC_ACCESS, APIC_ACCESS_ADDRESS);
		error += vmwrite(VMCS_EOI_EXIT0, 0);
		error += vmwrite(VMCS_EOI_EXIT1, 0);
		error += vmwrite(VMCS_EOI_EXIT2, 0);
		error += vmwrite(VMCS_EOI_EXIT3, 0);
	}
	if (posted_interrupts) {
		error += vmwrite(VMCS_PIR_VECTOR, pirvec);
		error += vmwrite(VMCS_PIR_DESC, vtophys(vcpu->pir_desc));
	}
	VMCLEAR(vmcs);
	if (error != 0)
		panic("%s: cannot program initial VMCS: %d", __func__, error);

	vcpu->cap.set = 0;
	vcpu->cap.set |= cap_rdpid != 0 ? 1 << VM_CAP_RDPID : 0;
	vcpu->cap.set |= cap_rdtscp != 0 ? 1 << VM_CAP_RDTSCP : 0;
	vcpu->cap.proc_ctls = procbased_ctls;
	vcpu->cap.proc_ctls2 = procbased_ctls2;
	vcpu->cap.exc_bitmap = exc_bitmap;

	vcpu->state.nextrip = ~0;
	vcpu->state.lastcpu = NOCPU;
	vcpu->state.vpid = vpid;

	/*
	 * Set up the CR0/4 shadows, and init the read shadow
	 * to the power-on register value from the Intel Sys Arch.
	 *  CR0 - 0x60000010
	 *  CR4 - 0
	 */
	error = vmx_setup_cr0_shadow(vmcs, 0x60000010);
	if (error != 0)
		panic("vmx_setup_cr0_shadow %d", error);

	error = vmx_setup_cr4_shadow(vmcs, 0);
	if (error != 0)
		panic("vmx_setup_cr4_shadow %d", error);

	vcpu->ctx.pmap = vmx->pmap;

	return (vcpu);
}

static int
vmx_handle_cpuid(struct vmx_vcpu *vcpu, struct vmxctx *vmxctx)
{
	int handled;

	handled = x86_emulate_cpuid(vcpu->vcpu, (uint64_t *)&vmxctx->guest_rax,
	    (uint64_t *)&vmxctx->guest_rbx, (uint64_t *)&vmxctx->guest_rcx,
	    (uint64_t *)&vmxctx->guest_rdx);
	return (handled);
}

static int
vmx_nested_instruction_operation(uint32_t reason,
    enum vmx_nested_instruction_operation *operation)
{

	if (operation == NULL)
		return (EINVAL);
	switch (reason) {
	case EXIT_REASON_VMCLEAR:
		*operation = VMX_NESTED_INSTRUCTION_VMCLEAR;
		break;
	case EXIT_REASON_VMLAUNCH:
		*operation = VMX_NESTED_INSTRUCTION_VMLAUNCH;
		break;
	case EXIT_REASON_VMPTRLD:
		*operation = VMX_NESTED_INSTRUCTION_VMPTRLD;
		break;
	case EXIT_REASON_VMPTRST:
		*operation = VMX_NESTED_INSTRUCTION_VMPTRST;
		break;
	case EXIT_REASON_VMREAD:
		*operation = VMX_NESTED_INSTRUCTION_VMREAD;
		break;
	case EXIT_REASON_VMRESUME:
		*operation = VMX_NESTED_INSTRUCTION_VMRESUME;
		break;
	case EXIT_REASON_VMWRITE:
		*operation = VMX_NESTED_INSTRUCTION_VMWRITE;
		break;
	case EXIT_REASON_VMXOFF:
		*operation = VMX_NESTED_INSTRUCTION_VMXOFF;
		break;
	case EXIT_REASON_VMXON:
		*operation = VMX_NESTED_INSTRUCTION_VMXON;
		break;
	case EXIT_REASON_INVEPT:
		*operation = VMX_NESTED_INSTRUCTION_INVEPT;
		break;
	case EXIT_REASON_INVVPID:
		*operation = VMX_NESTED_INSTRUCTION_INVVPID;
		break;
	default:
		return (ENOENT);
	}
	return (0);
}

/*
 * Capture an L1 VMX instruction while VMCS01 is current.  The pure capture
 * layer performs all guest-visible decoding and permission classification;
 * the context publisher alone assigns machine state and generation identity.
 *
 * This adapter is compiled before exposure but cannot claim an exit until the
 * fail-closed implementation-stage predicate succeeds.  VMX instructions
 * executed by L2 are deliberately excluded: they require VMCS12 exit-policy
 * routing, not L1 instruction emulation.
 */
static int
vmx_nested_capture_instruction_exit(struct vmx_vcpu *vcpu,
    struct vm_exit *vmexit, uint32_t reason, uint64_t qualification)
{
	static const int segment_registers[6] = {
		VM_REG_GUEST_ES,
		VM_REG_GUEST_CS,
		VM_REG_GUEST_SS,
		VM_REG_GUEST_DS,
		VM_REG_GUEST_FS,
		VM_REG_GUEST_GS,
	};
	struct vmx_nested_instruction_capture_input input;
	struct vmx_nested_instruction_capture_result capture;
	struct vmx_nested_instruction_handoff_id id;
	struct vm_guest_paging paging;
	struct seg_desc descriptor;
	uint64_t interruptibility, mask;
	unsigned int i;
	int error;

	if (vmx_nested_guest_exposure_validate() != 0 ||
	    !vmx_nested_guest_enabled(vcpu->vmx))
		return (UNHANDLED);
	/*
	 * L2 VMX instructions are exits from VMCS02 and must be routed with
	 * the rest of the captured L2 exit.  Until that owner runs before
	 * this L1 adapter, fail closed as a host-visible VMX exit rather than
	 * falling through to VM_EXITCODE_VMINSN, which would incorrectly
	 * inject #UD into L2.
	 */
	if (vcpu->nested.phase != VMX_NESTED_CONTEXT_ROOT)
		goto host_error;
	memset(&input, 0, sizeof(input));
	input.capabilities = vmx_nested_virtual_capabilities;
	error = vmx_nested_instruction_operation(reason, &input.operation);
	if (error == ENOENT)
		return (UNHANDLED);
	if (error != 0)
		goto host_error;
	for (i = 0; i < nitems(input.registers); i++)
		input.registers[i] = vmx_get_guest_reg(vcpu, i);
	for (i = 0; i < nitems(input.segments); i++) {
		error = vmcs_getdesc(vcpu->vmcs, 1, segment_registers[i],
		    &descriptor);
		if (error != 0)
			goto host_error;
		input.segments[i].base = descriptor.base;
		input.segments[i].limit = descriptor.limit;
		input.segments[i].type = SEG_DESC_TYPE(descriptor.access) &
		    0xf;
		input.segments[i].unusable =
		    SEG_DESC_UNUSABLE(descriptor.access) != 0;
		input.segments[i].default_big =
		    SEG_DESC_DEF32(descriptor.access) != 0;
	}
	vmx_paging_info(&paging);
	input.displacement = qualification;
	mask = vmcs_read(VMCS_CR0_MASK);
	error = vmx_nested_visible_control_register(
	    vmcs_read(VMCS_GUEST_CR0), mask,
	    vmcs_read(VMCS_CR0_SHADOW), &input.cr0);
	if (error != 0)
		goto host_error;
	mask = vmcs_read(VMCS_CR4_MASK);
	error = vmx_nested_visible_control_register(
	    vmcs_read(VMCS_GUEST_CR4), mask,
	    vmcs_read(VMCS_CR4_SHADOW), &input.cr4);
	if (error != 0)
		goto host_error;
	input.rflags = vmcs_read(VMCS_GUEST_RFLAGS);
	input.feature_control =
	    vcpu->nested_control_msrs.feature_control;
	input.instruction_information =
	    vmcs_read(VMCS_EXIT_INSTRUCTION_INFO);
	input.instruction_length = vmexit->inst_length;
	input.cpl = paging.cpl;
	input.mode64 = paging.cpu_mode == CPU_MODE_64BIT;
	interruptibility = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	input.movss_blocked = (interruptibility &
	    VMCS_INTERRUPTIBILITY_MOVSS_BLOCKING) != 0;

	error = vmx_nested_instruction_capture_publish(&vcpu->nested,
	    &input, &capture, &id);
	if (error != 0)
		goto host_error;
	switch (capture.disposition) {
	case VMX_NESTED_INSTRUCTION_CAPTURE_REQUEST:
		vmexit->exitcode = VM_EXITCODE_VMM_INTERNAL;
		vmexit->inst_length = 0;
		return (UNHANDLED);
	case VMX_NESTED_INSTRUCTION_CAPTURE_UD:
		vm_inject_ud(vcpu->vcpu);
		break;
	case VMX_NESTED_INSTRUCTION_CAPTURE_GP:
		vm_inject_gp(vcpu->vcpu);
		break;
	case VMX_NESTED_INSTRUCTION_CAPTURE_SS:
		vm_inject_fault(vcpu->vcpu, IDT_SS, 1,
		    capture.exception_error);
		break;
	default:
		return (UNHANDLED);
	}
	/* Faulting VMX instructions restart after the injected exception. */
	vmexit->inst_length = 0;
	return (HANDLED);

host_error:
	/*
	 * A decoder, VMCS access, or handoff publication failure is an L0
	 * implementation failure.  Never disguise it as an unsupported guest
	 * VMX instruction: the generic VMINSN path injects #UD.  Preserve the
	 * hardware exit reason for diagnostics and force the VMM process to
	 * stop through its existing fatal VMX-exit path.
	 */
	vmexit->exitcode = VM_EXITCODE_VMX;
	vmexit->inst_length = 0;
	vmexit->u.vmx.status = VM_FAIL_INVALID;
	vmexit->u.vmx.inst_type = 0;
	vmexit->u.vmx.inst_error = 0;
	return (UNHANDLED);
}

static __inline void
vmx_run_trace(struct vmx_vcpu *vcpu)
{
	VMX_CTR1(vcpu, "Resume execution at %#lx", vmcs_guest_rip());
}

static __inline void
vmx_exit_trace(struct vmx_vcpu *vcpu, uint64_t rip, uint32_t exit_reason,
    int handled)
{
	VMX_CTR3(vcpu, "%s %s vmexit at 0x%0lx",
		 handled ? "handled" : "unhandled",
		 exit_reason_to_str(exit_reason), rip);
}

static __inline void
vmx_astpending_trace(struct vmx_vcpu *vcpu, uint64_t rip)
{
	VMX_CTR1(vcpu, "astpending vmexit at 0x%0lx", rip);
}

static VMM_STAT_INTEL(VCPU_INVVPID_SAVED, "Number of vpid invalidations saved");
static VMM_STAT_INTEL(VCPU_INVVPID_DONE, "Number of vpid invalidations done");
static VMM_STAT_INTEL(VCPU_NESTED_INVVPID_DONE,
    "Number of nested effective-vpid invalidations done");

static int
vmx_nested_vpid_flush(struct vmx_vcpu *vcpu,
    const struct vmx_nested_vpid_plan *plan)
{
	struct invvpid_desc descriptor;
	bool flush_required;
	int error;

	if (vcpu == NULL || plan == NULL || curthread->td_critnest == 0)
		return (EINVAL);
	error = vmx_nested_vpid_owner_validate(&vcpu->nested_vpid_owner);
	if (error != 0)
		return (error);
	if (plan->hardware_vpid == 0)
		return (!vcpu->nested_vpid_owner.active &&
		    !plan->flush_effective_context &&
		    !vmx_nested_vpid_owner_flush_required(
		    &vcpu->nested_vpid_owner) ? 0 : EINVAL);
	if (!vcpu->nested_vpid_owner.active ||
	    plan->hardware_vpid !=
	    vcpu->nested_vpid_owner.effective_vpid)
		return (EINVAL);
	/*
	 * A VPID12 transition changes the address-space identity represented
	 * by the one destination-local VPID02.  Revoke residency on every CPU
	 * before completing the invalidation on this final pinned CPU.  Other
	 * CPUs will invalidate lazily before they next run this vCPU.
	 */
	if (plan->flush_effective_context) {
		error = vmx_nested_vpid_owner_request_flush(
		    &vcpu->nested_vpid_owner);
		if (error != 0)
			return (error);
	}
	error = vmx_nested_vpid_owner_flush_required_on_cpu(
	    &vcpu->nested_vpid_owner, curcpu, &flush_required);
	if (error != 0)
		return (error);
	if (!flush_required)
		return (0);

	/*
	 * A VPID can be reused after an earlier vCPU is destroyed, and VPID
	 * translations are logical-processor local.  Consume the transition
	 * plan on the final pinned CPU immediately before programming VMCS02.
	 * Current composition conservatively requests this at every L2 entry;
	 * a future residency optimization must retain the same per-CPU reuse
	 * guarantee before it may suppress an invalidation.
	 */
	memset(&descriptor, 0, sizeof(descriptor));
	descriptor.vpid = plan->hardware_vpid;
	invvpid(INVVPID_TYPE_SINGLE_CONTEXT, descriptor);
	if (vmx_nested_vpid_owner_flush_complete_on_cpu(
	    &vcpu->nested_vpid_owner, curcpu) != 0)
		panic("%s: invalid nested VPID owner after flush", __func__);
	vmm_stat_incr(vcpu->vcpu, VCPU_NESTED_INVVPID_DONE, 1);
	return (0);
}

/*
 * Invalidate guest mappings identified by its vpid from the TLB.
 */
static __inline void
vmx_invvpid(struct vmx *vmx, struct vmx_vcpu *vcpu, pmap_t pmap, int running)
{
	struct vmxstate *vmxstate;
	struct invvpid_desc invvpid_desc;

	vmxstate = &vcpu->state;
	if (vmxstate->vpid == 0)
		return;

	if (!running) {
		/*
		 * Set the 'lastcpu' to an invalid host cpu.
		 *
		 * This will invalidate TLB entries tagged with the vcpu's
		 * vpid the next time it runs via vmx_set_pcpu_defaults().
		 */
		vmxstate->lastcpu = NOCPU;
		return;
	}

	KASSERT(curthread->td_critnest > 0, ("%s: vcpu %d running outside "
	    "critical section", __func__, vcpu->vcpuid));

	/*
	 * Invalidate all mappings tagged with 'vpid'
	 *
	 * We do this because this vcpu was executing on a different host
	 * cpu when it last ran. We do not track whether it invalidated
	 * mappings associated with its 'vpid' during that run. So we must
	 * assume that the mappings associated with 'vpid' on 'curcpu' are
	 * stale and invalidate them.
	 *
	 * Note that we incur this penalty only when the scheduler chooses to
	 * move the thread associated with this vcpu between host cpus.
	 *
	 * Note also that this will invalidate mappings tagged with 'vpid'
	 * for "all" EP4TAs.
	 */
	if (atomic_load_long(&pmap->pm_eptgen) == vmx->eptgen[curcpu]) {
		invvpid_desc._res1 = 0;
		invvpid_desc._res2 = 0;
		invvpid_desc.vpid = vmxstate->vpid;
		invvpid_desc.linear_addr = 0;
		invvpid(INVVPID_TYPE_SINGLE_CONTEXT, invvpid_desc);
		vmm_stat_incr(vcpu->vcpu, VCPU_INVVPID_DONE, 1);
	} else {
		/*
		 * The invvpid can be skipped if an invept is going to
		 * be performed before entering the guest. The invept
		 * will invalidate combined mappings tagged with
		 * 'vmx->eptp' for all vpids.
		 */
		vmm_stat_incr(vcpu->vcpu, VCPU_INVVPID_SAVED, 1);
	}
}

static void
vmx_set_pcpu_defaults(struct vmx *vmx, struct vmx_vcpu *vcpu, pmap_t pmap)
{
	struct vmxstate *vmxstate;

	vmxstate = &vcpu->state;
	if (vmxstate->lastcpu == curcpu)
		return;

	vmxstate->lastcpu = curcpu;

	vmm_stat_incr(vcpu->vcpu, VCPU_MIGRATIONS, 1);

	vmcs_write(VMCS_HOST_TR_BASE, vmm_get_host_trbase());
	vmcs_write(VMCS_HOST_GDTR_BASE, vmm_get_host_gdtrbase());
	vmcs_write(VMCS_HOST_GS_BASE, vmm_get_host_gsbase());
	vmx_invvpid(vmx, vcpu, pmap, 1);
}

/*
 * We depend on 'procbased_ctls' to have the Interrupt Window Exiting bit set.
 */
CTASSERT((PROCBASED_CTLS_ONE_SETTING & PROCBASED_INT_WINDOW_EXITING) != 0);

static void __inline
vmx_set_int_window_exiting(struct vmx_vcpu *vcpu)
{

	if ((vcpu->cap.proc_ctls & PROCBASED_INT_WINDOW_EXITING) == 0) {
		vcpu->cap.proc_ctls |= PROCBASED_INT_WINDOW_EXITING;
		vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vcpu->cap.proc_ctls);
		VMX_CTR0(vcpu, "Enabling interrupt window exiting");
	}
}

static void __inline
vmx_clear_int_window_exiting(struct vmx_vcpu *vcpu)
{

	KASSERT((vcpu->cap.proc_ctls & PROCBASED_INT_WINDOW_EXITING) != 0,
	    ("intr_window_exiting not set: %#x", vcpu->cap.proc_ctls));
	vcpu->cap.proc_ctls &= ~PROCBASED_INT_WINDOW_EXITING;
	vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vcpu->cap.proc_ctls);
	VMX_CTR0(vcpu, "Disabling interrupt window exiting");
}

static void __inline
vmx_set_nmi_window_exiting(struct vmx_vcpu *vcpu)
{

	if ((vcpu->cap.proc_ctls & PROCBASED_NMI_WINDOW_EXITING) == 0) {
		vcpu->cap.proc_ctls |= PROCBASED_NMI_WINDOW_EXITING;
		vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vcpu->cap.proc_ctls);
		VMX_CTR0(vcpu, "Enabling NMI window exiting");
	}
}

static void __inline
vmx_clear_nmi_window_exiting(struct vmx_vcpu *vcpu)
{

	KASSERT((vcpu->cap.proc_ctls & PROCBASED_NMI_WINDOW_EXITING) != 0,
	    ("nmi_window_exiting not set %#x", vcpu->cap.proc_ctls));
	vcpu->cap.proc_ctls &= ~PROCBASED_NMI_WINDOW_EXITING;
	vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vcpu->cap.proc_ctls);
	VMX_CTR0(vcpu, "Disabling NMI window exiting");
}

int
vmx_set_tsc_offset(struct vmx_vcpu *vcpu, uint64_t offset)
{
	int error;

	if ((vcpu->cap.proc_ctls & PROCBASED_TSC_OFFSET) == 0) {
		vcpu->cap.proc_ctls |= PROCBASED_TSC_OFFSET;
		vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vcpu->cap.proc_ctls);
		VMX_CTR0(vcpu, "Enabling TSC offsetting");
	}

	error = vmwrite(VMCS_TSC_OFFSET, offset);
#ifdef BHYVE_SNAPSHOT
	if (error == 0)
		vm_set_tsc_offset(vcpu->vcpu, offset);
#endif
	return (error);
}

/*
 * Complete an intercepted L2 IA32_TSC write which L1 chose not to intercept.
 * Architecturally this changes L1's TSC offset.  While guest mode is active,
 * however, VMCS02 must retain VMCS12's L2 offset/scaling composition.  The
 * nested preemption-timer deadline is also expressed in L1 virtual-TSC
 * ticks, so reload its remaining value from the unchanged deadline.
 */
int
vmx_nested_write_tsc(struct vmx_vcpu *vcpu, uint64_t value)
{
	struct vmx_nested_tsc_write_input input;
	struct vmx_nested_tsc_write_plan plan;
	uint32_t vmcs01_primary, vmcs02_primary;
	int error;

	if (vcpu == NULL || !vcpu->nested_vmcs02_plan_valid ||
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    vcpu->nested_tsc_aux_residency !=
	    VMX_NESTED_TSC_AUX_L2_PAUSED ||
	    !vcpu->nested_vmcs02_intel.launch.current ||
	    curthread->td_critnest == 0)
		return (EINVAL);

	memset(&input, 0, sizeof(input));
	input.current = vcpu->nested_entry_environment.tsc;
	input.timer = vcpu->nested_vmcs02_plan.image.preemption_timer;
	input.write_host_tsc = rdtsc();
	input.timer_host_tsc = rdtsc();
	input.target_tsc = value;
	input.timer_rate =
	    vcpu->nested_vmcs02_plan.image.preemption_timer_rate;
	input.timer_enabled =
	    vcpu->nested_vmcs02_plan.image.preemption_timer_enabled;
	error = vmx_nested_tsc_write_plan(&input, &plan);
	if (error != 0)
		return (error);
	if (plan.composed.vmcs02_multiplier !=
	    vcpu->nested_vmcs02_plan.image.tsc.vmcs02_multiplier ||
	    plan.composed.vmcs01_multiplier !=
	    vcpu->nested_vmcs02_plan.image.tsc.vmcs01_multiplier ||
	    plan.composed.vmcs02_scaling_enabled !=
	    vcpu->nested_vmcs02_plan.image.tsc.vmcs02_scaling_enabled ||
	    plan.composed.vmcs01_scaling_enabled !=
	    vcpu->nested_vmcs02_plan.image.tsc.vmcs01_scaling_enabled)
		return (EPROTO);

	vmcs02_primary =
	    vcpu->nested_vmcs02_plan.image.controls.primary |
	    PROCBASED_TSC_OFFSET;
	vmcs01_primary = vcpu->cap.proc_ctls | PROCBASED_TSC_OFFSET;
	error = vmx_nested_vmcs02_intel_write_tsc(
	    &vcpu->nested_vmcs02_intel,
	    &vcpu->nested_vmcs02_plan.id,
	    vcpu->nested_entry_runtime.resource_generation,
	    plan.composed.vmcs02_offset, vmcs02_primary,
	    input.timer_enabled,
	    input.timer_enabled ? plan.timer.remaining : 0,
	    plan.composed.vmcs01_offset, vmcs01_primary);
	if (error != 0)
		return (error);

	vcpu->nested_entry_environment.tsc = plan.updated;
	vcpu->nested_vmcs02_plan.image.tsc = plan.composed;
	vcpu->nested_vmcs02_plan.image.controls.primary = vmcs02_primary;
	if (input.timer_enabled)
		vcpu->nested_vmcs02_plan.image.preemption_timer = plan.timer;
	vcpu->cap.proc_ctls = vmcs01_primary;
#ifdef BHYVE_SNAPSHOT
	vm_set_tsc_offset(vcpu->vcpu, plan.composed.vmcs01_offset);
#endif
	return (0);
}

#define	NMI_BLOCKING	(VMCS_INTERRUPTIBILITY_NMI_BLOCKING |		\
			 VMCS_INTERRUPTIBILITY_MOVSS_BLOCKING)
#define	HWINTR_BLOCKING	(VMCS_INTERRUPTIBILITY_STI_BLOCKING |		\
			 VMCS_INTERRUPTIBILITY_MOVSS_BLOCKING)

static void
vmx_inject_nmi(struct vmx_vcpu *vcpu)
{
	uint32_t gi __diagused, info;

	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	KASSERT((gi & NMI_BLOCKING) == 0, ("vmx_inject_nmi: invalid guest "
	    "interruptibility-state %#x", gi));

	info = vmcs_read(VMCS_ENTRY_INTR_INFO);
	KASSERT((info & VMCS_INTR_VALID) == 0, ("vmx_inject_nmi: invalid "
	    "VM-entry interruption information %#x", info));

	/*
	 * Inject the virtual NMI. The vector must be the NMI IDT entry
	 * or the VMCS entry check will fail.
	 */
	info = IDT_NMI | VMCS_INTR_T_NMI | VMCS_INTR_VALID;
	vmcs_write(VMCS_ENTRY_INTR_INFO, info);

	VMX_CTR0(vcpu, "Injecting vNMI");

	/* Clear the request */
	vm_nmi_clear(vcpu->vcpu);
}

static void
vmx_inject_interrupts(struct vmx_vcpu *vcpu, struct vlapic *vlapic,
    uint64_t guestrip)
{
	int vector, need_nmi_exiting, extint_pending;
	uint64_t rflags, entryinfo;
	uint32_t gi, info;

	if (vcpu->cap.set & (1 << VM_CAP_MASK_HWINTR)) {
		return;
	}

	if (vcpu->state.nextrip != guestrip) {
		gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
		if (gi & HWINTR_BLOCKING) {
			VMX_CTR2(vcpu, "Guest interrupt blocking "
			    "cleared due to rip change: %#lx/%#lx",
			    vcpu->state.nextrip, guestrip);
			gi &= ~HWINTR_BLOCKING;
			vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
		}
	}

	if (vm_entry_intinfo(vcpu->vcpu, &entryinfo)) {
		KASSERT((entryinfo & VMCS_INTR_VALID) != 0, ("%s: entry "
		    "intinfo is not valid: %#lx", __func__, entryinfo));

		info = vmcs_read(VMCS_ENTRY_INTR_INFO);
		KASSERT((info & VMCS_INTR_VALID) == 0, ("%s: cannot inject "
		     "pending exception: %#lx/%#x", __func__, entryinfo, info));

		info = entryinfo;
		vector = info & 0xff;
		if (vector == IDT_BP || vector == IDT_OF) {
			/*
			 * VT-x requires #BP and #OF to be injected as software
			 * exceptions.
			 */
			info &= ~VMCS_INTR_T_MASK;
			info |= VMCS_INTR_T_SWEXCEPTION;
		}

		if (info & VMCS_INTR_DEL_ERRCODE)
			vmcs_write(VMCS_ENTRY_EXCEPTION_ERROR, entryinfo >> 32);

		vmcs_write(VMCS_ENTRY_INTR_INFO, info);
	}

	if (vm_nmi_pending(vcpu->vcpu)) {
		/*
		 * If there are no conditions blocking NMI injection then
		 * inject it directly here otherwise enable "NMI window
		 * exiting" to inject it as soon as we can.
		 *
		 * We also check for STI_BLOCKING because some implementations
		 * don't allow NMI injection in this case. If we are running
		 * on a processor that doesn't have this restriction it will
		 * immediately exit and the NMI will be injected in the
		 * "NMI window exiting" handler.
		 */
		need_nmi_exiting = 1;
		gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
		if ((gi & (HWINTR_BLOCKING | NMI_BLOCKING)) == 0) {
			info = vmcs_read(VMCS_ENTRY_INTR_INFO);
			if ((info & VMCS_INTR_VALID) == 0) {
				vmx_inject_nmi(vcpu);
				need_nmi_exiting = 0;
			} else {
				VMX_CTR1(vcpu, "Cannot inject NMI "
				    "due to VM-entry intr info %#x", info);
			}
		} else {
			VMX_CTR1(vcpu, "Cannot inject NMI due to "
			    "Guest Interruptibility-state %#x", gi);
		}

		if (need_nmi_exiting)
			vmx_set_nmi_window_exiting(vcpu);
	}

	extint_pending = vm_extint_pending(vcpu->vcpu);

	if (!extint_pending && virtual_interrupt_delivery) {
		vmx_inject_pir(vlapic);
		return;
	}

	/*
	 * If interrupt-window exiting is already in effect then don't bother
	 * checking for pending interrupts. This is just an optimization and
	 * not needed for correctness.
	 */
	if ((vcpu->cap.proc_ctls & PROCBASED_INT_WINDOW_EXITING) != 0) {
		VMX_CTR0(vcpu, "Skip interrupt injection due to "
		    "pending int_window_exiting");
		return;
	}

	if (!extint_pending) {
		/* Ask the local apic for a vector to inject */
		if (!vlapic_pending_intr(vlapic, &vector))
			return;

		/*
		 * From the Intel SDM, Volume 3, Section "Maskable
		 * Hardware Interrupts":
		 * - maskable interrupt vectors [16,255] can be delivered
		 *   through the local APIC.
		*/
		KASSERT(vector >= 16 && vector <= 255,
		    ("invalid vector %d from local APIC", vector));
	} else {
		/* Ask the legacy pic for a vector to inject */
		vatpic_pending_intr(vcpu->vmx->vm, &vector);

		/*
		 * From the Intel SDM, Volume 3, Section "Maskable
		 * Hardware Interrupts":
		 * - maskable interrupt vectors [0,255] can be delivered
		 *   through the INTR pin.
		 */
		KASSERT(vector >= 0 && vector <= 255,
		    ("invalid vector %d from INTR", vector));
	}

	/* Check RFLAGS.IF and the interruptibility state of the guest */
	rflags = vmcs_read(VMCS_GUEST_RFLAGS);
	if ((rflags & PSL_I) == 0) {
		VMX_CTR2(vcpu, "Cannot inject vector %d due to "
		    "rflags %#lx", vector, rflags);
		goto cantinject;
	}

	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	if (gi & HWINTR_BLOCKING) {
		VMX_CTR2(vcpu, "Cannot inject vector %d due to "
		    "Guest Interruptibility-state %#x", vector, gi);
		goto cantinject;
	}

	info = vmcs_read(VMCS_ENTRY_INTR_INFO);
	if (info & VMCS_INTR_VALID) {
		/*
		 * This is expected and could happen for multiple reasons:
		 * - A vectoring VM-entry was aborted due to astpending
		 * - A VM-exit happened during event injection.
		 * - An exception was injected above.
		 * - An NMI was injected above or after "NMI window exiting"
		 */
		VMX_CTR2(vcpu, "Cannot inject vector %d due to "
		    "VM-entry intr info %#x", vector, info);
		goto cantinject;
	}

	/* Inject the interrupt */
	info = VMCS_INTR_T_HWINTR | VMCS_INTR_VALID;
	info |= vector;
	vmcs_write(VMCS_ENTRY_INTR_INFO, info);

	if (!extint_pending) {
		/* Update the Local APIC ISR */
		vlapic_intr_accepted(vlapic, vector);
	} else {
		vm_extint_clear(vcpu->vcpu);
		vatpic_intr_accepted(vcpu->vmx->vm, vector);

		/*
		 * After we accepted the current ExtINT the PIC may
		 * have posted another one.  If that is the case, set
		 * the Interrupt Window Exiting execution control so
		 * we can inject that one too.
		 *
		 * Also, interrupt window exiting allows us to inject any
		 * pending APIC vector that was preempted by the ExtINT
		 * as soon as possible. This applies both for the software
		 * emulated vlapic and the hardware assisted virtual APIC.
		 */
		vmx_set_int_window_exiting(vcpu);
	}

	VMX_CTR1(vcpu, "Injecting hwintr at vector %d", vector);

	return;

cantinject:
	/*
	 * Set the Interrupt Window Exiting execution control so we can inject
	 * the interrupt as soon as blocking condition goes away.
	 */
	vmx_set_int_window_exiting(vcpu);
}

/*
 * If the Virtual NMIs execution control is '1' then the logical processor
 * tracks virtual-NMI blocking in the Guest Interruptibility-state field of
 * the VMCS. An IRET instruction in VMX non-root operation will remove any
 * virtual-NMI blocking.
 *
 * This unblocking occurs even if the IRET causes a fault. In this case the
 * hypervisor needs to restore virtual-NMI blocking before resuming the guest.
 */
static void
vmx_restore_nmi_blocking(struct vmx_vcpu *vcpu)
{
	uint32_t gi;

	VMX_CTR0(vcpu, "Restore Virtual-NMI blocking");
	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	gi |= VMCS_INTERRUPTIBILITY_NMI_BLOCKING;
	vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
}

static void
vmx_clear_nmi_blocking(struct vmx_vcpu *vcpu)
{
	uint32_t gi;

	VMX_CTR0(vcpu, "Clear Virtual-NMI blocking");
	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	gi &= ~VMCS_INTERRUPTIBILITY_NMI_BLOCKING;
	vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
}

static void
vmx_assert_nmi_blocking(struct vmx_vcpu *vcpu)
{
	uint32_t gi __diagused;

	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	KASSERT(gi & VMCS_INTERRUPTIBILITY_NMI_BLOCKING,
	    ("NMI blocking is not in effect %#x", gi));
}

static int
vmx_emulate_xsetbv(struct vmx *vmx, struct vmx_vcpu *vcpu,
    struct vm_exit *vmexit)
{
	struct vmxctx *vmxctx;
	uint64_t xcrval;
	const struct xsave_limits *limits;

	vmxctx = &vcpu->ctx;
	limits = vmm_get_xsave_limits();

	/*
	 * Note that the processor raises a GP# fault on its own if
	 * xsetbv is executed for CPL != 0, so we do not have to
	 * emulate that fault here.
	 */

	/* Only xcr0 is supported. */
	if (vmxctx->guest_rcx != 0) {
		vm_inject_gp(vcpu->vcpu);
		return (HANDLED);
	}

	/* We only handle xcr0 if both the host and guest have XSAVE enabled. */
	if (!limits->xsave_enabled || !(vmcs_read(VMCS_GUEST_CR4) & CR4_XSAVE)) {
		vm_inject_ud(vcpu->vcpu);
		return (HANDLED);
	}

	xcrval = vmxctx->guest_rdx << 32 | (vmxctx->guest_rax & 0xffffffff);
	if ((xcrval & ~limits->xcr0_allowed) != 0) {
		vm_inject_gp(vcpu->vcpu);
		return (HANDLED);
	}

	if (!(xcrval & XFEATURE_ENABLED_X87)) {
		vm_inject_gp(vcpu->vcpu);
		return (HANDLED);
	}

	/* AVX (YMM_Hi128) requires SSE. */
	if (xcrval & XFEATURE_ENABLED_AVX &&
	    (xcrval & XFEATURE_AVX) != XFEATURE_AVX) {
		vm_inject_gp(vcpu->vcpu);
		return (HANDLED);
	}

	/*
	 * AVX512 requires base AVX (YMM_Hi128) as well as OpMask,
	 * ZMM_Hi256, and Hi16_ZMM.
	 */
	if (xcrval & XFEATURE_AVX512 &&
	    (xcrval & (XFEATURE_AVX512 | XFEATURE_AVX)) !=
	    (XFEATURE_AVX512 | XFEATURE_AVX)) {
		vm_inject_gp(vcpu->vcpu);
		return (HANDLED);
	}

	/*
	 * Intel MPX requires both bound register state flags to be
	 * set.
	 */
	if (((xcrval & XFEATURE_ENABLED_BNDREGS) != 0) !=
	    ((xcrval & XFEATURE_ENABLED_BNDCSR) != 0)) {
		vm_inject_gp(vcpu->vcpu);
		return (HANDLED);
	}

	/*
	 * This runs "inside" vmrun() with the guest's FPU state, so
	 * modifying xcr0 directly modifies the guest's xcr0, not the
	 * host's.
	 */
	load_xcr(0, xcrval);
	return (HANDLED);
}

static uint64_t
vmx_get_guest_reg(struct vmx_vcpu *vcpu, int ident)
{
	const struct vmxctx *vmxctx;

	vmxctx = &vcpu->ctx;

	switch (ident) {
	case 0:
		return (vmxctx->guest_rax);
	case 1:
		return (vmxctx->guest_rcx);
	case 2:
		return (vmxctx->guest_rdx);
	case 3:
		return (vmxctx->guest_rbx);
	case 4:
		return (vmcs_read(VMCS_GUEST_RSP));
	case 5:
		return (vmxctx->guest_rbp);
	case 6:
		return (vmxctx->guest_rsi);
	case 7:
		return (vmxctx->guest_rdi);
	case 8:
		return (vmxctx->guest_r8);
	case 9:
		return (vmxctx->guest_r9);
	case 10:
		return (vmxctx->guest_r10);
	case 11:
		return (vmxctx->guest_r11);
	case 12:
		return (vmxctx->guest_r12);
	case 13:
		return (vmxctx->guest_r13);
	case 14:
		return (vmxctx->guest_r14);
	case 15:
		return (vmxctx->guest_r15);
	default:
		panic("invalid vmx register %d", ident);
	}
}

static void
vmx_set_guest_reg(struct vmx_vcpu *vcpu, int ident, uint64_t regval)
{
	struct vmxctx *vmxctx;

	vmxctx = &vcpu->ctx;

	switch (ident) {
	case 0:
		vmxctx->guest_rax = regval;
		break;
	case 1:
		vmxctx->guest_rcx = regval;
		break;
	case 2:
		vmxctx->guest_rdx = regval;
		break;
	case 3:
		vmxctx->guest_rbx = regval;
		break;
	case 4:
		vmcs_write(VMCS_GUEST_RSP, regval);
		break;
	case 5:
		vmxctx->guest_rbp = regval;
		break;
	case 6:
		vmxctx->guest_rsi = regval;
		break;
	case 7:
		vmxctx->guest_rdi = regval;
		break;
	case 8:
		vmxctx->guest_r8 = regval;
		break;
	case 9:
		vmxctx->guest_r9 = regval;
		break;
	case 10:
		vmxctx->guest_r10 = regval;
		break;
	case 11:
		vmxctx->guest_r11 = regval;
		break;
	case 12:
		vmxctx->guest_r12 = regval;
		break;
	case 13:
		vmxctx->guest_r13 = regval;
		break;
	case 14:
		vmxctx->guest_r14 = regval;
		break;
	case 15:
		vmxctx->guest_r15 = regval;
		break;
	default:
		panic("invalid vmx register %d", ident);
	}
}

static int
vmx_emulate_cr0_access(struct vmx_vcpu *vcpu, uint64_t exitqual)
{
	uint64_t crval, regval;

	/* We only handle mov to %cr0 at this time */
	if ((exitqual & 0xf0) != 0x00)
		return (UNHANDLED);

	regval = vmx_get_guest_reg(vcpu, (exitqual >> 8) & 0xf);

	vmcs_write(VMCS_CR0_SHADOW, regval);

	crval = regval | cr0_ones_mask;
	crval &= ~cr0_zeros_mask;
	vmcs_write(VMCS_GUEST_CR0, crval);

	if (regval & CR0_PG) {
		uint64_t efer, entry_ctls;

		/*
		 * If CR0.PG is 1 and EFER.LME is 1 then EFER.LMA and
		 * the "IA-32e mode guest" bit in VM-entry control must be
		 * equal.
		 */
		efer = vmcs_read(VMCS_GUEST_IA32_EFER);
		if (efer & EFER_LME) {
			efer |= EFER_LMA;
			vmcs_write(VMCS_GUEST_IA32_EFER, efer);
			entry_ctls = vmcs_read(VMCS_ENTRY_CTLS);
			entry_ctls |= VM_ENTRY_GUEST_LMA;
			vmcs_write(VMCS_ENTRY_CTLS, entry_ctls);
		}
	}

	return (HANDLED);
}

static int
vmx_emulate_cr4_access(struct vmx_vcpu *vcpu, uint64_t exitqual)
{
	uint64_t crval, regval;

	/* We only handle mov to %cr4 at this time */
	if ((exitqual & 0xf0) != 0x00)
		return (UNHANDLED);

	regval = vmx_get_guest_reg(vcpu, (exitqual >> 8) & 0xf);

	vmcs_write(VMCS_CR4_SHADOW, regval);

	crval = regval | cr4_ones_mask;
	crval &= ~cr4_zeros_mask;
	vmcs_write(VMCS_GUEST_CR4, crval);

	return (HANDLED);
}

static int
vmx_emulate_cr8_access(struct vmx *vmx, struct vmx_vcpu *vcpu,
    uint64_t exitqual)
{
	struct vlapic *vlapic;
	uint64_t cr8;
	int regnum;

	/* We only handle mov %cr8 to/from a register at this time. */
	if ((exitqual & 0xe0) != 0x00) {
		return (UNHANDLED);
	}

	vlapic = vm_lapic(vcpu->vcpu);
	regnum = (exitqual >> 8) & 0xf;
	if (exitqual & 0x10) {
		cr8 = vlapic_get_cr8(vlapic);
		vmx_set_guest_reg(vcpu, regnum, cr8);
	} else {
		cr8 = vmx_get_guest_reg(vcpu, regnum);
		vlapic_set_cr8(vlapic, cr8);
	}

	return (HANDLED);
}

/*
 * From section "Guest Register State" in the Intel SDM: CPL = SS.DPL
 */
static int
vmx_cpl(void)
{
	uint32_t ssar;

	ssar = vmcs_read(VMCS_GUEST_SS_ACCESS_RIGHTS);
	return ((ssar >> 5) & 0x3);
}

static enum vm_cpu_mode
vmx_cpu_mode(void)
{
	uint32_t csar;

	if (vmcs_read(VMCS_GUEST_IA32_EFER) & EFER_LMA) {
		csar = vmcs_read(VMCS_GUEST_CS_ACCESS_RIGHTS);
		if (csar & 0x2000)
			return (CPU_MODE_64BIT);	/* CS.L = 1 */
		else
			return (CPU_MODE_COMPATIBILITY);
	} else if (vmcs_read(VMCS_GUEST_CR0) & CR0_PE) {
		return (CPU_MODE_PROTECTED);
	} else {
		return (CPU_MODE_REAL);
	}
}

static enum vm_paging_mode
vmx_paging_mode(void)
{
	uint64_t cr4;

	if (!(vmcs_read(VMCS_GUEST_CR0) & CR0_PG))
		return (PAGING_MODE_FLAT);
	cr4 = vmcs_read(VMCS_GUEST_CR4);
	if (!(cr4 & CR4_PAE))
		return (PAGING_MODE_32);
	if (vmcs_read(VMCS_GUEST_IA32_EFER) & EFER_LME) {
		if (!(cr4 & CR4_LA57))
			return (PAGING_MODE_64);
		return (PAGING_MODE_64_LA57);
	} else
		return (PAGING_MODE_PAE);
}

static uint64_t
inout_str_index(struct vmx_vcpu *vcpu, int in)
{
	uint64_t val;
	int error __diagused;
	enum vm_reg_name reg;

	reg = in ? VM_REG_GUEST_RDI : VM_REG_GUEST_RSI;
	error = vmx_getreg(vcpu, reg, &val);
	KASSERT(error == 0, ("%s: vmx_getreg error %d", __func__, error));
	return (val);
}

static uint64_t
inout_str_count(struct vmx_vcpu *vcpu, int rep)
{
	uint64_t val;
	int error __diagused;

	if (rep) {
		error = vmx_getreg(vcpu, VM_REG_GUEST_RCX, &val);
		KASSERT(!error, ("%s: vmx_getreg error %d", __func__, error));
	} else {
		val = 1;
	}
	return (val);
}

static int
inout_str_addrsize(uint32_t inst_info)
{
	uint32_t size;

	size = (inst_info >> 7) & 0x7;
	switch (size) {
	case 0:
		return (2);	/* 16 bit */
	case 1:
		return (4);	/* 32 bit */
	case 2:
		return (8);	/* 64 bit */
	default:
		panic("%s: invalid size encoding %d", __func__, size);
	}
}

static void
inout_str_seginfo(struct vmx_vcpu *vcpu, uint32_t inst_info, int in,
    struct vm_inout_str *vis)
{
	int error __diagused, s;

	if (in) {
		vis->seg_name = VM_REG_GUEST_ES;
	} else {
		s = (inst_info >> 15) & 0x7;
		vis->seg_name = vm_segment_name(s);
	}

	error = vmx_getdesc(vcpu, vis->seg_name, &vis->seg_desc);
	KASSERT(error == 0, ("%s: vmx_getdesc error %d", __func__, error));
}

static void
vmx_paging_info(struct vm_guest_paging *paging)
{
	paging->cr3 = vmcs_guest_cr3();
	paging->cpl = vmx_cpl();
	paging->cpu_mode = vmx_cpu_mode();
	paging->paging_mode = vmx_paging_mode();
}

static void
vmexit_inst_emul(struct vm_exit *vmexit, uint64_t gpa, uint64_t gla)
{
	struct vm_guest_paging *paging;
	uint32_t csar;

	paging = &vmexit->u.inst_emul.paging;

	vmexit->exitcode = VM_EXITCODE_INST_EMUL;
	vmexit->inst_length = 0;
	vmexit->u.inst_emul.gpa = gpa;
	vmexit->u.inst_emul.gla = gla;
	vmx_paging_info(paging);
	switch (paging->cpu_mode) {
	case CPU_MODE_REAL:
		vmexit->u.inst_emul.cs_base = vmcs_read(VMCS_GUEST_CS_BASE);
		vmexit->u.inst_emul.cs_d = 0;
		break;
	case CPU_MODE_PROTECTED:
	case CPU_MODE_COMPATIBILITY:
		vmexit->u.inst_emul.cs_base = vmcs_read(VMCS_GUEST_CS_BASE);
		csar = vmcs_read(VMCS_GUEST_CS_ACCESS_RIGHTS);
		vmexit->u.inst_emul.cs_d = SEG_DESC_DEF32(csar);
		break;
	default:
		vmexit->u.inst_emul.cs_base = 0;
		vmexit->u.inst_emul.cs_d = 0;
		break;
	}
	vie_init(&vmexit->u.inst_emul.vie, NULL, 0);
}

static int
ept_fault_type(uint64_t ept_qual)
{
	int fault_type;

	if (ept_qual & EPT_VIOLATION_DATA_WRITE)
		fault_type = VM_PROT_WRITE;
	else if (ept_qual & EPT_VIOLATION_INST_FETCH)
		fault_type = VM_PROT_EXECUTE;
	else
		fault_type= VM_PROT_READ;

	return (fault_type);
}

static bool
ept_emulation_fault(uint64_t ept_qual)
{
	int read, write;

	/* EPT fault on an instruction fetch doesn't make sense here */
	if (ept_qual & EPT_VIOLATION_INST_FETCH)
		return (false);

	/* EPT fault must be a read fault or a write fault */
	read = ept_qual & EPT_VIOLATION_DATA_READ ? 1 : 0;
	write = ept_qual & EPT_VIOLATION_DATA_WRITE ? 1 : 0;
	if ((read | write) == 0)
		return (false);

	/*
	 * The EPT violation must have been caused by accessing a
	 * guest-physical address that is a translation of a guest-linear
	 * address.
	 */
	if ((ept_qual & EPT_VIOLATION_GLA_VALID) == 0 ||
	    (ept_qual & EPT_VIOLATION_XLAT_VALID) == 0) {
		return (false);
	}

	return (true);
}

static __inline int
apic_access_virtualization(struct vmx_vcpu *vcpu)
{
	uint32_t proc_ctls2;

	proc_ctls2 = vcpu->cap.proc_ctls2;
	return ((proc_ctls2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES) ? 1 : 0);
}

static __inline int
x2apic_virtualization(struct vmx_vcpu *vcpu)
{
	uint32_t proc_ctls2;

	proc_ctls2 = vcpu->cap.proc_ctls2;
	return ((proc_ctls2 & PROCBASED2_VIRTUALIZE_X2APIC_MODE) ? 1 : 0);
}

static int
vmx_handle_apic_write(struct vmx_vcpu *vcpu, struct vlapic *vlapic,
    uint64_t qual)
{
	int error, handled, offset;
	uint32_t *apic_regs, vector;
	bool retu;

	handled = HANDLED;
	offset = APIC_WRITE_OFFSET(qual);

	if (!apic_access_virtualization(vcpu)) {
		/*
		 * In general there should not be any APIC write VM-exits
		 * unless APIC-access virtualization is enabled.
		 *
		 * However self-IPI virtualization can legitimately trigger
		 * an APIC-write VM-exit so treat it specially.
		 */
		if (x2apic_virtualization(vcpu) &&
		    offset == APIC_OFFSET_SELF_IPI) {
			apic_regs = (uint32_t *)(vlapic->apic_page);
			vector = apic_regs[APIC_OFFSET_SELF_IPI / 4];
			vlapic_self_ipi_handler(vlapic, vector);
			return (HANDLED);
		} else
			return (UNHANDLED);
	}

	switch (offset) {
	case APIC_OFFSET_ID:
		vlapic_id_write_handler(vlapic);
		break;
	case APIC_OFFSET_LDR:
		vlapic_ldr_write_handler(vlapic);
		break;
	case APIC_OFFSET_DFR:
		vlapic_dfr_write_handler(vlapic);
		break;
	case APIC_OFFSET_SVR:
		vlapic_svr_write_handler(vlapic);
		break;
	case APIC_OFFSET_ESR:
		vlapic_esr_write_handler(vlapic);
		break;
	case APIC_OFFSET_ICR_LOW:
		retu = false;
		error = vlapic_icrlo_write_handler(vlapic, &retu);
		if (error != 0 || retu)
			handled = UNHANDLED;
		break;
	case APIC_OFFSET_CMCI_LVT:
	case APIC_OFFSET_TIMER_LVT ... APIC_OFFSET_ERROR_LVT:
		vlapic_lvt_write_handler(vlapic, offset);
		break;
	case APIC_OFFSET_TIMER_ICR:
		vlapic_icrtmr_write_handler(vlapic);
		break;
	case APIC_OFFSET_TIMER_DCR:
		vlapic_dcr_write_handler(vlapic);
		break;
	default:
		handled = UNHANDLED;
		break;
	}
	return (handled);
}

static bool
apic_access_fault(struct vmx_vcpu *vcpu, uint64_t gpa)
{

	if (apic_access_virtualization(vcpu) &&
	    (gpa >= DEFAULT_APIC_BASE && gpa < DEFAULT_APIC_BASE + PAGE_SIZE))
		return (true);
	else
		return (false);
}

static int
vmx_handle_apic_access(struct vmx_vcpu *vcpu, struct vm_exit *vmexit)
{
	uint64_t qual;
	int access_type, offset, allowed;

	if (!apic_access_virtualization(vcpu))
		return (UNHANDLED);

	qual = vmexit->u.vmx.exit_qualification;
	access_type = APIC_ACCESS_TYPE(qual);
	offset = APIC_ACCESS_OFFSET(qual);

	allowed = 0;
	if (access_type == 0) {
		/*
		 * Read data access to the following registers is expected.
		 */
		switch (offset) {
		case APIC_OFFSET_APR:
		case APIC_OFFSET_PPR:
		case APIC_OFFSET_RRR:
		case APIC_OFFSET_CMCI_LVT:
		case APIC_OFFSET_TIMER_CCR:
			allowed = 1;
			break;
		default:
			break;
		}
	} else if (access_type == 1) {
		/*
		 * Write data access to the following registers is expected.
		 */
		switch (offset) {
		case APIC_OFFSET_VER:
		case APIC_OFFSET_APR:
		case APIC_OFFSET_PPR:
		case APIC_OFFSET_RRR:
		case APIC_OFFSET_ISR0 ... APIC_OFFSET_ISR7:
		case APIC_OFFSET_TMR0 ... APIC_OFFSET_TMR7:
		case APIC_OFFSET_IRR0 ... APIC_OFFSET_IRR7:
		case APIC_OFFSET_CMCI_LVT:
		case APIC_OFFSET_TIMER_CCR:
			allowed = 1;
			break;
		default:
			break;
		}
	}

	if (allowed) {
		vmexit_inst_emul(vmexit, DEFAULT_APIC_BASE + offset,
		    VIE_INVALID_GLA);
	}

	/*
	 * Regardless of whether the APIC-access is allowed this handler
	 * always returns UNHANDLED:
	 * - if the access is allowed then it is handled by emulating the
	 *   instruction that caused the VM-exit (outside the critical section)
	 * - if the access is not allowed then it will be converted to an
	 *   exitcode of VM_EXITCODE_VMX and will be dealt with in userland.
	 */
	return (UNHANDLED);
}

static enum task_switch_reason
vmx_task_switch_reason(uint64_t qual)
{
	int reason;

	reason = (qual >> 30) & 0x3;
	switch (reason) {
	case 0:
		return (TSR_CALL);
	case 1:
		return (TSR_IRET);
	case 2:
		return (TSR_JMP);
	case 3:
		return (TSR_IDT_GATE);
	default:
		panic("%s: invalid reason %d", __func__, reason);
	}
}

static int
vmx_nested_rdmsr(struct vmx_vcpu *vcpu, u_int num, uint64_t *value,
    bool *handled, bool *completed)
{
	uint64_t candidate;
	int error;

	*handled = false;
	*completed = false;
	if (vmx_nested_guest_exposure_validate() != 0 ||
	    !vmx_nested_guest_enabled(vcpu->vmx))
		return (0);
	error = vmx_nested_control_msr_read(
	    &vmx_nested_virtual_capabilities, &vcpu->nested_control_msrs,
	    num, &candidate);
	if (error == ENOENT)
		return (0);
	*handled = true;
	if (error != 0) {
		vm_inject_gp(vcpu->vcpu);
		return (0);
	}
	*value = candidate;
	*completed = true;
	return (0);
}

static int
vmx_nested_wrmsr(struct vmx_vcpu *vcpu, u_int num, uint64_t value,
    bool *handled)
{
	int error;

	*handled = false;
	if (vmx_nested_guest_exposure_validate() != 0 ||
	    !vmx_nested_guest_enabled(vcpu->vmx))
		return (0);
	error = vmx_nested_control_msr_write(
	    &vmx_nested_virtual_capabilities, &vcpu->nested_control_msrs,
	    num, value);
	if (error == ENOENT)
		return (0);
	*handled = true;
	if (error != 0)
		vm_inject_gp(vcpu->vcpu);
	return (0);
}

static int
emulate_wrmsr(struct vmx_vcpu *vcpu, u_int num, uint64_t val, bool *retu)
{
	bool handled;
	int error;

	error = vmx_nested_wrmsr(vcpu, num, val, &handled);
	if (error != 0 || handled)
		return (error);
	if (lapic_msr(num))
		error = lapic_wrmsr(vcpu->vcpu, num, val, retu);
	else
		error = vmx_wrmsr(vcpu, num, val, retu);

	return (error);
}

static int
emulate_rdmsr(struct vmx_vcpu *vcpu, u_int num, bool *retu)
{
	struct vmxctx *vmxctx;
	uint64_t result;
	uint32_t eax, edx;
	bool completed, handled;
	int error;

	error = vmx_nested_rdmsr(vcpu, num, &result, &handled, &completed);
	if (error != 0)
		return (error);
	if (handled && !completed)
		return (0);
	if (!handled && lapic_msr(num))
		error = lapic_rdmsr(vcpu->vcpu, num, &result, retu);
	else if (!handled)
		error = vmx_rdmsr(vcpu, num, &result, retu);

	if (error == 0) {
		eax = result;
		vmxctx = &vcpu->ctx;
		error = vmxctx_setreg(vmxctx, VM_REG_GUEST_RAX, eax);
		KASSERT(error == 0, ("vmxctx_setreg(rax) error %d", error));

		edx = result >> 32;
		error = vmxctx_setreg(vmxctx, VM_REG_GUEST_RDX, edx);
		KASSERT(error == 0, ("vmxctx_setreg(rdx) error %d", error));
	}

	return (error);
}

static int
vmx_exit_process(struct vmx *vmx, struct vmx_vcpu *vcpu, struct vm_exit *vmexit)
{
	enum vm_exception_class exception_class;
	int error, errcode, errcode_valid, handled, in;
	struct vmxctx *vmxctx;
	struct vlapic *vlapic;
	struct vm_inout_str *vis;
	struct vm_task_switch *ts;
	uint32_t eax, ecx, edx, idtvec_info, idtvec_err, intr_info, inst_info;
	uint32_t intr_type, intr_vec, reason;
	uint64_t dr7, exitintinfo, qual, gpa;
#ifdef KDTRACE_HOOKS
	int vcpuid;
#endif
	bool retu;

	CTASSERT((PINBASED_CTLS_ONE_SETTING & PINBASED_VIRTUAL_NMI) != 0);
	CTASSERT((PINBASED_CTLS_ONE_SETTING & PINBASED_NMI_EXITING) != 0);

	handled = UNHANDLED;
	vmxctx = &vcpu->ctx;
#ifdef KDTRACE_HOOKS
	vcpuid = vcpu->vcpuid;
#endif

	qual = vmexit->u.vmx.exit_qualification;
	reason = vmexit->u.vmx.exit_reason;
	vmexit->exitcode = VM_EXITCODE_BOGUS;

	vmm_stat_incr(vcpu->vcpu, VMEXIT_COUNT, 1);
	SDT_PROBE3(vmm, vmx, exit, entry, vmx, vcpuid, vmexit);

	/*
	 * VM-entry failures during or after loading guest state.
	 *
	 * These VM-exits are uncommon but must be handled specially
	 * as most VM-exit fields are not populated as usual.
	 */
	if (__predict_false(reason == EXIT_REASON_MCE_DURING_ENTRY)) {
		VMX_CTR0(vcpu, "Handling MCE during VM-entry");
		__asm __volatile("int $18");
		return (1);
	}

	/*
	 * VM exits that can be triggered during event delivery need to
	 * be handled specially by re-injecting the event if the IDT
	 * vectoring information field's valid bit is set.
	 *
	 * See "Information for VM Exits During Event Delivery" in Intel SDM
	 * for details.
	 */
	idtvec_info = vmcs_idt_vectoring_info();
	if (idtvec_info & VMCS_IDT_VEC_VALID) {
		idtvec_info &= ~(1 << 12); /* clear undefined bit */
		exitintinfo = idtvec_info;
		if (idtvec_info & VMCS_IDT_VEC_ERRCODE_VALID) {
			idtvec_err = vmcs_idt_vectoring_err();
			exitintinfo |= (uint64_t)idtvec_err << 32;
		}
		error = vm_exit_intinfo(vcpu->vcpu, exitintinfo);
		KASSERT(error == 0, ("%s: vm_set_intinfo error %d",
		    __func__, error));

		/*
		 * If 'virtual NMIs' are being used and the VM-exit
		 * happened while injecting an NMI during the previous
		 * VM-entry, then clear "blocking by NMI" in the
		 * Guest Interruptibility-State so the NMI can be
		 * reinjected on the subsequent VM-entry.
		 *
		 * However, if the NMI was being delivered through a task
		 * gate, then the new task must start execution with NMIs
		 * blocked so don't clear NMI blocking in this case.
		 */
		intr_type = idtvec_info & VMCS_INTR_T_MASK;
		if (intr_type == VMCS_INTR_T_NMI) {
			if (reason != EXIT_REASON_TASK_SWITCH)
				vmx_clear_nmi_blocking(vcpu);
			else
				vmx_assert_nmi_blocking(vcpu);
		}

		/*
		 * Update VM-entry instruction length if the event being
		 * delivered was a software interrupt or software exception.
		 */
		if (intr_type == VMCS_INTR_T_SWINTR ||
		    intr_type == VMCS_INTR_T_PRIV_SWEXCEPTION ||
		    intr_type == VMCS_INTR_T_SWEXCEPTION) {
			vmcs_write(VMCS_ENTRY_INST_LENGTH, vmexit->inst_length);
		}
	}

	switch (reason) {
	case EXIT_REASON_TASK_SWITCH:
		ts = &vmexit->u.task_switch;
		ts->tsssel = qual & 0xffff;
		ts->reason = vmx_task_switch_reason(qual);
		ts->ext = 0;
		ts->errcode_valid = 0;
		vmx_paging_info(&ts->paging);
		/*
		 * If the task switch was due to a CALL, JMP, IRET, software
		 * interrupt (INT n) or software exception (INT3, INTO),
		 * then the saved %rip references the instruction that caused
		 * the task switch. The instruction length field in the VMCS
		 * is valid in this case.
		 *
		 * In all other cases (e.g., NMI, hardware exception) the
		 * saved %rip is one that would have been saved in the old TSS
		 * had the task switch completed normally so the instruction
		 * length field is not needed in this case and is explicitly
		 * set to 0.
		 */
		if (ts->reason == TSR_IDT_GATE) {
			KASSERT(idtvec_info & VMCS_IDT_VEC_VALID,
			    ("invalid idtvec_info %#x for IDT task switch",
			    idtvec_info));
			intr_type = idtvec_info & VMCS_INTR_T_MASK;
			if (intr_type != VMCS_INTR_T_SWINTR &&
			    intr_type != VMCS_INTR_T_SWEXCEPTION &&
			    intr_type != VMCS_INTR_T_PRIV_SWEXCEPTION) {
				/* Task switch triggered by external event */
				ts->ext = 1;
				vmexit->inst_length = 0;
				if (idtvec_info & VMCS_IDT_VEC_ERRCODE_VALID) {
					ts->errcode_valid = 1;
					ts->errcode = vmcs_idt_vectoring_err();
				}
			}
		}
		vmexit->exitcode = VM_EXITCODE_TASK_SWITCH;
		SDT_PROBE4(vmm, vmx, exit, taskswitch, vmx, vcpuid, vmexit, ts);
		VMX_CTR4(vcpu, "task switch reason %d, tss 0x%04x, "
		    "%s errcode 0x%016lx", ts->reason, ts->tsssel,
		    ts->ext ? "external" : "internal",
		    ((uint64_t)ts->errcode << 32) | ts->errcode_valid);
		break;
	case EXIT_REASON_CR_ACCESS:
		vmm_stat_incr(vcpu->vcpu, VMEXIT_CR_ACCESS, 1);
		SDT_PROBE4(vmm, vmx, exit, craccess, vmx, vcpuid, vmexit, qual);
		switch (qual & 0xf) {
		case 0:
			handled = vmx_emulate_cr0_access(vcpu, qual);
			break;
		case 4:
			handled = vmx_emulate_cr4_access(vcpu, qual);
			break;
		case 8:
			handled = vmx_emulate_cr8_access(vmx, vcpu, qual);
			break;
		}
		break;
	case EXIT_REASON_RDMSR:
		vmm_stat_incr(vcpu->vcpu, VMEXIT_RDMSR, 1);
		retu = false;
		ecx = vmxctx->guest_rcx;
		VMX_CTR1(vcpu, "rdmsr 0x%08x", ecx);
		SDT_PROBE4(vmm, vmx, exit, rdmsr, vmx, vcpuid, vmexit, ecx);
		error = emulate_rdmsr(vcpu, ecx, &retu);
		if (error) {
			vmexit->exitcode = VM_EXITCODE_RDMSR;
			vmexit->u.msr.code = ecx;
		} else if (!retu) {
			handled = HANDLED;
		} else {
			/* Return to userspace with a valid exitcode */
			KASSERT(vmexit->exitcode != VM_EXITCODE_BOGUS,
			    ("emulate_rdmsr retu with bogus exitcode"));
		}
		break;
	case EXIT_REASON_WRMSR:
		vmm_stat_incr(vcpu->vcpu, VMEXIT_WRMSR, 1);
		retu = false;
		eax = vmxctx->guest_rax;
		ecx = vmxctx->guest_rcx;
		edx = vmxctx->guest_rdx;
		VMX_CTR2(vcpu, "wrmsr 0x%08x value 0x%016lx",
		    ecx, (uint64_t)edx << 32 | eax);
		SDT_PROBE5(vmm, vmx, exit, wrmsr, vmx, vmexit, vcpuid, ecx,
		    (uint64_t)edx << 32 | eax);
		error = emulate_wrmsr(vcpu, ecx, (uint64_t)edx << 32 | eax,
		    &retu);
		if (error) {
			vmexit->exitcode = VM_EXITCODE_WRMSR;
			vmexit->u.msr.code = ecx;
			vmexit->u.msr.wval = (uint64_t)edx << 32 | eax;
		} else if (!retu) {
			handled = HANDLED;
		} else {
			/* Return to userspace with a valid exitcode */
			KASSERT(vmexit->exitcode != VM_EXITCODE_BOGUS,
			    ("emulate_wrmsr retu with bogus exitcode"));
		}
		break;
	case EXIT_REASON_HLT:
		vmm_stat_incr(vcpu->vcpu, VMEXIT_HLT, 1);
		SDT_PROBE3(vmm, vmx, exit, halt, vmx, vcpuid, vmexit);
		vmexit->exitcode = VM_EXITCODE_HLT;
		vmexit->u.hlt.rflags = vmcs_read(VMCS_GUEST_RFLAGS);
		if (virtual_interrupt_delivery)
			vmexit->u.hlt.intr_status =
			    vmcs_read(VMCS_GUEST_INTR_STATUS);
		else
			vmexit->u.hlt.intr_status = 0;
		break;
	case EXIT_REASON_MTF:
		vmm_stat_incr(vcpu->vcpu, VMEXIT_MTRAP, 1);
		SDT_PROBE3(vmm, vmx, exit, mtrap, vmx, vcpuid, vmexit);
		vmexit->exitcode = VM_EXITCODE_MTRAP;
		vmexit->inst_length = 0;
		break;
	case EXIT_REASON_PAUSE:
		vmm_stat_incr(vcpu->vcpu, VMEXIT_PAUSE, 1);
		SDT_PROBE3(vmm, vmx, exit, pause, vmx, vcpuid, vmexit);
		vmexit->exitcode = VM_EXITCODE_PAUSE;
		break;
	case EXIT_REASON_INTR_WINDOW:
		vmm_stat_incr(vcpu->vcpu, VMEXIT_INTR_WINDOW, 1);
		SDT_PROBE3(vmm, vmx, exit, intrwindow, vmx, vcpuid, vmexit);
		vmx_clear_int_window_exiting(vcpu);
		return (1);
	case EXIT_REASON_EXT_INTR:
		/*
		 * External interrupts serve only to cause VM exits and allow
		 * the host interrupt handler to run.
		 *
		 * If this external interrupt triggers a virtual interrupt
		 * to a VM, then that state will be recorded by the
		 * host interrupt handler in the VM's softc. We will inject
		 * this virtual interrupt during the subsequent VM enter.
		 */
		intr_info = vmcs_read(VMCS_EXIT_INTR_INFO);
		SDT_PROBE4(vmm, vmx, exit, interrupt,
		    vmx, vcpuid, vmexit, intr_info);

		/*
		 * Intel normally supplies valid interruption information for an
		 * external-interrupt exit.  Some VMware Fusion configurations have
		 * produced a record without it; retain the established narrow
		 * compatibility behavior, but account for it separately so it cannot
		 * be mistaken for an ordinary handled host interrupt.
		 */
		if ((intr_info & VMCS_INTR_VALID) == 0) {
			vmm_stat_incr(vcpu->vcpu, VMEXIT_EXTINT_INVALID, 1);
			return (1);
		}
		KASSERT((intr_info & VMCS_INTR_VALID) != 0 &&
		    (intr_info & VMCS_INTR_T_MASK) == VMCS_INTR_T_HWINTR,
		    ("VM exit interruption info invalid: %#x", intr_info));
		vmx_trigger_hostintr(intr_info & 0xff);

		/*
		 * This is special. We want to treat this as an 'handled'
		 * VM-exit but not increment the instruction pointer.
		 */
		vmm_stat_incr(vcpu->vcpu, VMEXIT_EXTINT, 1);
		return (1);
	case EXIT_REASON_NMI_WINDOW:
		SDT_PROBE3(vmm, vmx, exit, nmiwindow, vmx, vcpuid, vmexit);
		/* Exit to allow the pending virtual NMI to be injected */
		if (vm_nmi_pending(vcpu->vcpu))
			vmx_inject_nmi(vcpu);
		vmx_clear_nmi_window_exiting(vcpu);
		vmm_stat_incr(vcpu->vcpu, VMEXIT_NMI_WINDOW, 1);
		return (1);
	case EXIT_REASON_INOUT:
		vmm_stat_incr(vcpu->vcpu, VMEXIT_INOUT, 1);
		vmexit->exitcode = VM_EXITCODE_INOUT;
		vmexit->u.inout.bytes = (qual & 0x7) + 1;
		vmexit->u.inout.in = in = (qual & 0x8) ? 1 : 0;
		vmexit->u.inout.string = (qual & 0x10) ? 1 : 0;
		vmexit->u.inout.rep = (qual & 0x20) ? 1 : 0;
		vmexit->u.inout.port = (uint16_t)(qual >> 16);
		vmexit->u.inout.eax = (uint32_t)(vmxctx->guest_rax);
		if (vmexit->u.inout.string) {
			inst_info = vmcs_read(VMCS_EXIT_INSTRUCTION_INFO);
			vmexit->exitcode = VM_EXITCODE_INOUT_STR;
			vis = &vmexit->u.inout_str;
			vmx_paging_info(&vis->paging);
			vis->rflags = vmcs_read(VMCS_GUEST_RFLAGS);
			vis->cr0 = vmcs_read(VMCS_GUEST_CR0);
			vis->index = inout_str_index(vcpu, in);
			vis->count = inout_str_count(vcpu, vis->inout.rep);
			vis->addrsize = inout_str_addrsize(inst_info);
			vis->cs_d = 0;
			vis->cs_base = 0;
			inout_str_seginfo(vcpu, inst_info, in, vis);
		}
		SDT_PROBE3(vmm, vmx, exit, inout, vmx, vcpuid, vmexit);
		break;
	case EXIT_REASON_CPUID:
		vmm_stat_incr(vcpu->vcpu, VMEXIT_CPUID, 1);
		SDT_PROBE3(vmm, vmx, exit, cpuid, vmx, vcpuid, vmexit);
		handled = vmx_handle_cpuid(vcpu, vmxctx);
		break;
	case EXIT_REASON_EXCEPTION:
		vmm_stat_incr(vcpu->vcpu, VMEXIT_EXCEPTION, 1);
		intr_info = vmcs_read(VMCS_EXIT_INTR_INFO);
		KASSERT((intr_info & VMCS_INTR_VALID) != 0,
		    ("VM exit interruption info invalid: %#x", intr_info));

		intr_vec = intr_info & 0xff;
		intr_type = intr_info & VMCS_INTR_T_MASK;

		/*
		 * If Virtual NMIs control is 1 and the VM-exit is due to a
		 * fault encountered during the execution of IRET then we must
		 * restore the state of "virtual-NMI blocking" before resuming
		 * the guest.
		 *
		 * See "Resuming Guest Software after Handling an Exception".
		 * See "Information for VM Exits Due to Vectored Events".
		 */
		if ((idtvec_info & VMCS_IDT_VEC_VALID) == 0 &&
		    (intr_vec != IDT_DF) &&
		    (intr_info & EXIT_QUAL_NMIUDTI) != 0)
			vmx_restore_nmi_blocking(vcpu);

		/*
		 * The NMI has already been handled in vmx_exit_handle_nmi().
		 */
		if (intr_type == VMCS_INTR_T_NMI)
			return (1);

		/*
		 * Call the machine check handler by hand. Also don't reflect
		 * the machine check back into the guest.
		 */
		if (intr_vec == IDT_MC) {
			VMX_CTR0(vcpu, "Vectoring to MCE handler");
			__asm __volatile("int $18");
			return (1);
		}

		/*
		 * If the hypervisor has requested user exits for
		 * debug exceptions, bounce them out to userland.
		 */
		if (intr_type == VMCS_INTR_T_SWEXCEPTION && intr_vec == IDT_BP &&
		    (vcpu->cap.set & (1 << VM_CAP_BPT_EXIT))) {
			vmexit->exitcode = VM_EXITCODE_BPT;
			vmexit->u.bpt.inst_length = vmexit->inst_length;
			vmexit->inst_length = 0;
			break;
		}

		if (intr_vec == IDT_PF) {
			error = vmxctx_setreg(vmxctx, VM_REG_GUEST_CR2, qual);
			KASSERT(error == 0, ("%s: vmxctx_setreg(cr2) error %d",
			    __func__, error));
		}

		/*
		 * Software exceptions exhibit trap-like behavior. This in
		 * turn requires populating the VM-entry instruction length
		 * so that the %rip in the trap frame is past the INT3/INTO
		 * instruction.
		 */
		if (intr_type == VMCS_INTR_T_SWEXCEPTION ||
		    intr_type == VMCS_INTR_T_PRIV_SWEXCEPTION)
			vmcs_write(VMCS_ENTRY_INST_LENGTH, vmexit->inst_length);

		/* Reflect all other exceptions back into the guest */
		errcode_valid = errcode = 0;
		if (intr_info & VMCS_INTR_DEL_ERRCODE) {
			errcode_valid = 1;
			errcode = vmcs_read(VMCS_EXIT_INTR_ERRCODE);
		}
		VMX_CTR2(vcpu, "Reflecting exception %d/%#x into "
		    "the guest", intr_vec, errcode);
		SDT_PROBE5(vmm, vmx, exit, exception,
		    vmx, vcpuid, vmexit, intr_vec, errcode);
		if (intr_vec == IDT_DB) {
			if (intr_type == VMCS_INTR_T_PRIV_SWEXCEPTION) {
				exception_class = VM_EXCEPTION_ICEBP;
			} else {
				dr7 = vmcs_read(VMCS_GUEST_DR7);
				/*
				 * VMX exit qualification supplies current #DB causes;
				 * BT is taken from the guest DR6 image because Intel
				 * does not include it in that qualification.
				 */
				exception_class = vm_debug_exception_class(qual |
				    (vmxctx->guest_dr6 & DBREG_DR6_BT), dr7);
			}
		} else if (intr_vec == IDT_BP || intr_vec == IDT_OF) {
			exception_class = VM_EXCEPTION_TRAP;
		} else {
			exception_class = VM_EXCEPTION_FAULT;
		}
		error = vm_inject_exception_class(vcpu->vcpu, intr_vec,
		    errcode_valid, errcode, 0, exception_class);
		KASSERT(error == 0, ("%s: vm_inject_exception error %d",
		    __func__, error));
		return (1);

	case EXIT_REASON_EPT_FAULT:
		/*
		 * If 'gpa' lies within the address space allocated to
		 * memory then this must be a nested page fault otherwise
		 * this must be an instruction that accesses MMIO space.
		 */
		gpa = vmcs_gpa();
		if (vm_mem_allocated(vcpu->vcpu, gpa) ||
		    ppt_is_mmio(vmx->vm, gpa) || apic_access_fault(vcpu, gpa)) {
			vmexit->exitcode = VM_EXITCODE_PAGING;
			vmexit->inst_length = 0;
			vmexit->u.paging.gpa = gpa;
			vmexit->u.paging.fault_type = ept_fault_type(qual);
			vmm_stat_incr(vcpu->vcpu, VMEXIT_NESTED_FAULT, 1);
			SDT_PROBE5(vmm, vmx, exit, nestedfault,
			    vmx, vcpuid, vmexit, gpa, qual);
		} else if (ept_emulation_fault(qual)) {
			vmexit_inst_emul(vmexit, gpa, vmcs_gla());
			vmm_stat_incr(vcpu->vcpu, VMEXIT_INST_EMUL, 1);
			SDT_PROBE4(vmm, vmx, exit, mmiofault,
			    vmx, vcpuid, vmexit, gpa);
		}
		/*
		 * If Virtual NMIs control is 1 and the VM-exit is due to an
		 * EPT fault during the execution of IRET then we must restore
		 * the state of "virtual-NMI blocking" before resuming.
		 *
		 * See description of "NMI unblocking due to IRET" in
		 * "Exit Qualification for EPT Violations".
		 */
		if ((idtvec_info & VMCS_IDT_VEC_VALID) == 0 &&
		    (qual & EXIT_QUAL_NMIUDTI) != 0)
			vmx_restore_nmi_blocking(vcpu);
		break;
	case EXIT_REASON_VIRTUALIZED_EOI:
		vmexit->exitcode = VM_EXITCODE_IOAPIC_EOI;
		vmexit->u.ioapic_eoi.vector = qual & 0xFF;
		SDT_PROBE3(vmm, vmx, exit, eoi, vmx, vcpuid, vmexit);
		vmexit->inst_length = 0;	/* trap-like */
		break;
	case EXIT_REASON_APIC_ACCESS:
		SDT_PROBE3(vmm, vmx, exit, apicaccess, vmx, vcpuid, vmexit);
		handled = vmx_handle_apic_access(vcpu, vmexit);
		break;
	case EXIT_REASON_APIC_WRITE:
		/*
		 * APIC-write VM exit is trap-like so the %rip is already
		 * pointing to the next instruction.
		 */
		vmexit->inst_length = 0;
		vlapic = vm_lapic(vcpu->vcpu);
		SDT_PROBE4(vmm, vmx, exit, apicwrite,
		    vmx, vcpuid, vmexit, vlapic);
		handled = vmx_handle_apic_write(vcpu, vlapic, qual);
		break;
	case EXIT_REASON_XSETBV:
		SDT_PROBE3(vmm, vmx, exit, xsetbv, vmx, vcpuid, vmexit);
		handled = vmx_emulate_xsetbv(vmx, vcpu, vmexit);
		break;
	case EXIT_REASON_MONITOR:
		SDT_PROBE3(vmm, vmx, exit, monitor, vmx, vcpuid, vmexit);
		vmexit->exitcode = VM_EXITCODE_MONITOR;
		break;
	case EXIT_REASON_MWAIT:
		SDT_PROBE3(vmm, vmx, exit, mwait, vmx, vcpuid, vmexit);
		vmexit->exitcode = VM_EXITCODE_MWAIT;
		break;
	case EXIT_REASON_TPR:
		vlapic = vm_lapic(vcpu->vcpu);
		vlapic_sync_tpr(vlapic);
		vmexit->inst_length = 0;
		handled = HANDLED;
		break;
	case EXIT_REASON_VMX_PREEMPT:
		/*
		 * VMCS02 uses the hardware preemption timer only on behalf of
		 * L1.  Nested exit routing records whether that timer belongs to
		 * L1 and reflects it after this L0 bookkeeping pass.  Treat the
		 * trap-like exit as handled here so a valid L1 timer expiration is
		 * not reported through the unknown-exit path before reflection.
		 */
		vmexit->inst_length = 0;
		handled = HANDLED;
		break;
	case EXIT_REASON_VMCALL:
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
	case EXIT_REASON_INVEPT:
	case EXIT_REASON_INVVPID:
		SDT_PROBE3(vmm, vmx, exit, vminsn, vmx, vcpuid, vmexit);
		handled = vmx_nested_capture_instruction_exit(vcpu, vmexit,
		    reason, qual);
		if (vmexit->exitcode == VM_EXITCODE_BOGUS)
			vmexit->exitcode = VM_EXITCODE_VMINSN;
		break;
	case EXIT_REASON_INVD:
	case EXIT_REASON_WBINVD:
		/* ignore exit */
		handled = HANDLED;
		break;
	default:
		SDT_PROBE4(vmm, vmx, exit, unknown,
		    vmx, vcpuid, vmexit, reason);
		vmm_stat_incr(vcpu->vcpu, VMEXIT_UNKNOWN, 1);
		break;
	}

	if (handled) {
		/*
		 * It is possible that control is returned to userland
		 * even though we were able to handle the VM exit in the
		 * kernel.
		 *
		 * In such a case we want to make sure that the userland
		 * restarts guest execution at the instruction *after*
		 * the one we just processed. Therefore we update the
		 * guest rip in the VMCS and in 'vmexit'.
		 */
		vmexit->rip += vmexit->inst_length;
		vmexit->inst_length = 0;
		vmcs_write(VMCS_GUEST_RIP, vmexit->rip);
	} else {
		if (vmexit->exitcode == VM_EXITCODE_BOGUS) {
			/*
			 * If this VM exit was not claimed by anybody then
			 * treat it as a generic VMX exit.
			 */
			vmexit->exitcode = VM_EXITCODE_VMX;
			vmexit->u.vmx.status = VM_SUCCESS;
			vmexit->u.vmx.inst_type = 0;
			vmexit->u.vmx.inst_error = 0;
		} else {
			/*
			 * The exitcode and collateral have been populated.
			 * The VM exit will be processed further in userland.
			 */
		}
	}

	SDT_PROBE4(vmm, vmx, exit, return,
	    vmx, vcpuid, vmexit, handled);
	return (handled);
}

static __inline void
vmx_exit_inst_error(struct vmxctx *vmxctx, int rc, struct vm_exit *vmexit)
{

	KASSERT(vmxctx->inst_fail_status != VM_SUCCESS,
	    ("vmx_exit_inst_error: invalid inst_fail_status %d",
	    vmxctx->inst_fail_status));

	vmexit->inst_length = 0;
	vmexit->exitcode = VM_EXITCODE_VMX;
	vmexit->u.vmx.status = vmxctx->inst_fail_status;
	vmexit->u.vmx.inst_error = vmcs_instruction_error();
	vmexit->u.vmx.exit_reason = ~0;
	vmexit->u.vmx.exit_qualification = ~0;

	switch (rc) {
	case VMX_VMRESUME_ERROR:
	case VMX_VMLAUNCH_ERROR:
		vmexit->u.vmx.inst_type = rc;
		break;
	default:
		panic("vm_exit_inst_error: vmx_enter_guest returned %d", rc);
	}
}

/*
 * If the NMI-exiting VM execution control is set to '1' then an NMI in
 * non-root operation causes a VM-exit. NMI blocking is in effect so it is
 * sufficient to simply vector to the NMI handler via a software interrupt.
 * However, this must be done before maskable interrupts are enabled
 * otherwise the "iret" issued by an interrupt handler will incorrectly
 * clear NMI blocking.
 */
static __inline void
vmx_exit_handle_nmi(struct vmx_vcpu *vcpu, struct vm_exit *vmexit)
{
	uint32_t intr_info;

	KASSERT((read_rflags() & PSL_I) == 0, ("interrupts enabled"));

	if (vmexit->u.vmx.exit_reason != EXIT_REASON_EXCEPTION)
		return;

	intr_info = vmcs_read(VMCS_EXIT_INTR_INFO);
	KASSERT((intr_info & VMCS_INTR_VALID) != 0,
	    ("VM exit interruption info invalid: %#x", intr_info));

	if ((intr_info & VMCS_INTR_T_MASK) == VMCS_INTR_T_NMI) {
		KASSERT((intr_info & 0xff) == IDT_NMI, ("VM exit due "
		    "to NMI has invalid vector: %#x", intr_info));
		VMX_CTR0(vcpu, "Vectoring to NMI handler");
		__asm __volatile("int $2");
	}
}

static __inline void
vmx_dr_enter_guest(struct vmxctx *vmxctx)
{
	register_t rflags;

	/* Save host control debug registers. */
	vmxctx->host_dr7 = rdr7();
	vmxctx->host_debugctl = rdmsr(MSR_DEBUGCTLMSR);

	/*
	 * Disable debugging in DR7 and DEBUGCTL to avoid triggering
	 * exceptions in the host based on the guest DRx values.  The
	 * guest DR7 and DEBUGCTL are saved/restored in the VMCS.
	 */
	load_dr7(0);
	wrmsr(MSR_DEBUGCTLMSR, 0);

	/*
	 * Disable single stepping the kernel to avoid corrupting the
	 * guest DR6.  A debugger might still be able to corrupt the
	 * guest DR6 by setting a breakpoint after this point and then
	 * single stepping.
	 */
	rflags = read_rflags();
	vmxctx->host_tf = rflags & PSL_T;
	write_rflags(rflags & ~PSL_T);

	/* Save host debug registers. */
	vmxctx->host_dr0 = rdr0();
	vmxctx->host_dr1 = rdr1();
	vmxctx->host_dr2 = rdr2();
	vmxctx->host_dr3 = rdr3();
	vmxctx->host_dr6 = rdr6();

	/* Restore guest debug registers. */
	load_dr0(vmxctx->guest_dr0);
	load_dr1(vmxctx->guest_dr1);
	load_dr2(vmxctx->guest_dr2);
	load_dr3(vmxctx->guest_dr3);
	load_dr6(vmxctx->guest_dr6);
}

static __inline void
vmx_dr_leave_guest(struct vmxctx *vmxctx)
{

	/* Save guest debug registers. */
	vmxctx->guest_dr0 = rdr0();
	vmxctx->guest_dr1 = rdr1();
	vmxctx->guest_dr2 = rdr2();
	vmxctx->guest_dr3 = rdr3();
	vmxctx->guest_dr6 = rdr6();

	/*
	 * Restore host debug registers.  Restore DR7, DEBUGCTL, and
	 * PSL_T last.
	 */
	load_dr0(vmxctx->host_dr0);
	load_dr1(vmxctx->host_dr1);
	load_dr2(vmxctx->host_dr2);
	load_dr3(vmxctx->host_dr3);
	load_dr6(vmxctx->host_dr6);
	wrmsr(MSR_DEBUGCTLMSR, vmxctx->host_debugctl);
	load_dr7(vmxctx->host_dr7);
	write_rflags(read_rflags() | vmxctx->host_tf);
}

static __inline void
vmx_pmap_activate(struct vmx *vmx, pmap_t pmap)
{
	long eptgen;
	int cpu;

	cpu = curcpu;

	CPU_SET_ATOMIC(cpu, &pmap->pm_active);
	smr_enter(pmap->pm_eptsmr);
	eptgen = atomic_load_long(&pmap->pm_eptgen);
	if (eptgen != vmx->eptgen[cpu]) {
		vmx->eptgen[cpu] = eptgen;
		invept(INVEPT_TYPE_SINGLE_CONTEXT,
		    (struct invept_desc){ .eptp = vmx->eptp, ._res = 0 });
	}
}

static __inline void
vmx_pmap_deactivate(struct vmx *vmx, pmap_t pmap)
{
	smr_exit(pmap->pm_eptsmr);
	CPU_CLR_ATOMIC(curcpu, &pmap->pm_active);
}

struct vmx_nested_run_pmap {
	pmap_t outer;
	void *composed_root;
	bool composed;
};

static int
vmx_nested_run_pmap_prepare(struct vmx_vcpu *vcpu, pmap_t outer,
    struct vmx_nested_run_pmap *run_pmap)
{
	struct vmx_nested_run_pmap candidate;
	void *root;
	int error;

	if (vcpu == NULL || outer == NULL || run_pmap == NULL ||
	    !vcpu->nested_vmcs02_plan_valid)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.outer = outer;
	if (!vcpu->nested_vmcs02_plan.image.ept_enabled) {
		*run_pmap = candidate;
		return (0);
	}
	if (!vcpu->nested_ept_binding.active ||
	    vcpu->nested_vmcs02_resources.eptp02 == 0)
		return (EPROTO);
	error = vmx_nested_ept_binding_resolve(&vcpu->nested_ept_cache,
	    &vcpu->nested_ept_binding,
	    &vcpu->nested_vmcs02_plan.image.ept, &root);
	if (error != 0)
		return (error);
	if (vmx_nested_ept_root_eptp(root) !=
	    vcpu->nested_vmcs02_resources.eptp02)
		return (ESTALE);
	candidate.composed_root = root;
	candidate.composed = true;
	*run_pmap = candidate;
	return (0);
}

static __inline void
vmx_nested_run_pmap_activate(struct vmx *vmx,
    const struct vmx_nested_run_pmap *run_pmap)
{

	if (run_pmap->composed)
		vmx_nested_ept_root_activate(run_pmap->composed_root);
	else
		vmx_pmap_activate(vmx, run_pmap->outer);
}

static __inline void
vmx_nested_run_pmap_deactivate(struct vmx *vmx,
    const struct vmx_nested_run_pmap *run_pmap)
{

	if (run_pmap->composed)
		vmx_nested_ept_root_deactivate(run_pmap->composed_root);
	else
		vmx_pmap_deactivate(vmx, run_pmap->outer);
}

static int
vmx_nested_run_select_intel(const struct vmx_vcpu *vcpu,
    enum vmx_nested_run_target *target)
{
	struct vmx_nested_run_input input;

	if (vcpu == NULL || target == NULL)
		return (EINVAL);
	memset(&input, 0, sizeof(input));
	input.context_phase = vcpu->nested.phase;
	input.runtime_state = vcpu->nested_entry_runtime.state;
	input.continuation_state = vcpu->nested_l0_continuation.state;
	input.thaw_state = vcpu->nested_l2_thaw_staged.state;
	input.refreeze_state = vcpu->nested_refreeze_staged.state;
	input.plan_valid = vcpu->nested_vmcs02_plan_valid;
	input.thaw_resources_valid = vcpu->nested_thaw_resources_valid;
	input.internal_pending =
	    vcpu->nested.internal.kind != VMX_NESTED_INTERNAL_NONE;
	input.rollback_failed =
	    vcpu->nested_entry_runtime.rollback_failed ||
	    vcpu->nested_l0_continuation.rollback_failed ||
	    vcpu->nested_l2_thaw_staged.state ==
	    VMX_NESTED_L2_THAW_STAGED_POISONED ||
	    vcpu->nested_refreeze_staged.state ==
	    VMX_NESTED_REFREEZE_POISONED;
	return (vmx_nested_run_select(&input, target));
}

static int
vmx_run(void *vcpui, register_t rip, pmap_t pmap, struct vm_eventinfo *evinfo,
    struct vmm_startup_entry_owner *entry_owner)
{
	enum vmx_nested_run_target nested_target;
	struct vmm_startup_entry_runtime_result owner_runtime;
	struct vmm_startup_entry_loop_result owner_result;
	int error, rc, handled, launched;
	struct vmx *vmx;
	struct vmx_vcpu *vcpu;
	struct vmxctx *vmxctx;
	struct vmcs *vmcs;
	struct vm_exit *vmexit;
	struct vlapic *vlapic;
	uint32_t exit_reason;
	struct region_descriptor gdtr, idtr;
	uint16_t ldt_sel;
	bool owner_guard_declined;

	vcpu = vcpui;
	vmx = vcpu->vmx;
	/*
	 * Freeze the VM-wide CPU model before the first guest instruction.
	 * A concurrent configuration operation either wins before this
	 * atomic transition or observes the locked state and fails.
	 */
	vmx_nested_guest_config_lock(vmx);
	vmcs = vcpu->vmcs;
	vmxctx = &vcpu->ctx;
	vlapic = vm_lapic(vcpu->vcpu);
	vmexit = vm_exitinfo(vcpu->vcpu);
	launched = 0;
	owner_guard_declined = false;

	KASSERT(vmxctx->pmap == pmap,
	    ("pmap %p different than ctx pmap %p", pmap, vmxctx->pmap));
	rc = vmx_nested_run_select_intel(vcpu, &nested_target);
	if (rc != 0)
		return (rc);
	if (nested_target == VMX_NESTED_RUN_INTERNAL) {
		/*
		 * The preceding frozen handler may have published a follow-on
		 * operation.  Re-present it to vmm.c without loading a VMCS,
		 * entering guest MSRs, or advancing the architectural RIP.
		 * Retained transactions can be retryable, so preserve the
		 * ordinary run-loop lifecycle boundary before redispatching
		 * them.
		 */
		if (vcpu_suspended(evinfo)) {
			vm_exit_suspended(vcpu->vcpu, rip);
			goto software_exit;
		}
		if (vcpu_rendezvous_pending(vcpu->vcpu, evinfo)) {
			vm_exit_rendezvous(vcpu->vcpu, rip);
			goto software_exit;
		}
		if (vcpu_reqidle(evinfo)) {
			vm_exit_reqidle(vcpu->vcpu, rip);
			goto software_exit;
		}
		if (vcpu_should_yield(vcpu->vcpu)) {
			vm_exit_astpending(vcpu->vcpu, rip);
			vmx_astpending_trace(vcpu, rip);
			goto software_exit;
		}
		if (vcpu_debugged(vcpu->vcpu)) {
			vm_exit_debug(vcpu->vcpu, rip);
			goto software_exit;
		}
		vmexit->rip = rip;
		vmexit->inst_length = 0;
		vmexit->exitcode = VM_EXITCODE_VMM_INTERNAL;
		goto software_exit;
	}
	if (nested_target != VMX_NESTED_RUN_L1) {
		/*
		 * Do not rely solely on instruction emulation having hidden VMX
		 * from this CPU model.  A restored, stale, or otherwise malformed
		 * private nested state must not be sufficient to select VMCS02.
		 * Recheck both the immutable VM-wide guest choice and the host
		 * implementation-stage gate at the final transition into the
		 * nested run path.  This is intentionally redundant with the
		 * capability and instruction gates: this boundary owns actual L2
		 * residency and therefore has to fail closed on its own.
		 */
		if (!vmx_nested_guest_enabled(vmx))
			return (EOPNOTSUPP);
		error = vmx_nested_guest_exposure_validate();
		if (error != 0)
			return (error);
		return (vmx_run_nested(vcpu, rip, pmap, evinfo,
		    nested_target, entry_owner));
	}

	error = 0;
	vmx_msr_guest_enter(vcpu);

	VMPTRLD(vmcs);

	/*
	 * XXX
	 * We do this every time because we may setup the virtual machine
	 * from a different process than the one that actually runs it.
	 *
	 * If the life of a virtual machine was spent entirely in the context
	 * of a single process we could do this once in vmx_init().
	 */
	vmcs_write(VMCS_HOST_CR3, rcr3());

	vmcs_write(VMCS_GUEST_RIP, rip);
	vmx_set_pcpu_defaults(vmx, vcpu, pmap);
	do {
		KASSERT(vmcs_guest_rip() == rip, ("%s: vmcs guest rip mismatch "
		    "%#lx/%#lx", __func__, vmcs_guest_rip(), rip));

		handled = UNHANDLED;
		/*
		 * Interrupts are disabled from this point on until the
		 * guest starts executing. This is done for the following
		 * reasons:
		 *
		 * If an AST is asserted on this thread after the check below,
		 * then the IPI_AST notification will not be lost, because it
		 * will cause a VM exit due to external interrupt as soon as
		 * the guest state is loaded.
		 *
		 * A posted interrupt after 'vmx_inject_interrupts()' will
		 * not be "lost" because it will be held pending in the host
		 * APIC because interrupts are disabled. The pending interrupt
		 * will be recognized as soon as the guest state is loaded.
		 *
		 * The same reasoning applies to the IPI generated by
		 * pmap_invalidate_ept().
		 */
		disable_intr();
		vmx_inject_interrupts(vcpu, vlapic, rip);

		/*
		 * Check for vcpu suspension after injecting events because
		 * vmx_inject_interrupts() can suspend the vcpu due to a
		 * triple fault.
		 */
		if (vcpu_suspended(evinfo)) {
			enable_intr();
			vm_exit_suspended(vcpu->vcpu, rip);
			if (entry_owner != NULL &&
			    vmm_startup_entry_owner_software_exit(entry_owner,
			    &owner_result) != 0)
				panic("%s: suspended startup owner", __func__);
			break;
		}

		if (vcpu_rendezvous_pending(vcpu->vcpu, evinfo)) {
			enable_intr();
			vm_exit_rendezvous(vcpu->vcpu, rip);
			if (entry_owner != NULL &&
			    vmm_startup_entry_owner_software_exit(entry_owner,
			    &owner_result) != 0)
				panic("%s: rendezvous startup owner", __func__);
			break;
		}

		if (vcpu_reqidle(evinfo)) {
			enable_intr();
			vm_exit_reqidle(vcpu->vcpu, rip);
			if (entry_owner != NULL &&
			    vmm_startup_entry_owner_software_exit(entry_owner,
			    &owner_result) != 0)
				panic("%s: reqidle startup owner", __func__);
			break;
		}

		if (vcpu_should_yield(vcpu->vcpu)) {
			enable_intr();
			vm_exit_astpending(vcpu->vcpu, rip);
			vmx_astpending_trace(vcpu, rip);
			handled = HANDLED;
			if (entry_owner != NULL &&
			    vmm_startup_entry_owner_software_exit(entry_owner,
			    &owner_result) != 0)
				panic("%s: yield startup owner", __func__);
			break;
		}

		if (vcpu_debugged(vcpu->vcpu)) {
			enable_intr();
			vm_exit_debug(vcpu->vcpu, rip);
			if (entry_owner != NULL &&
			    vmm_startup_entry_owner_software_exit(entry_owner,
			    &owner_result) != 0)
				panic("%s: debug startup owner", __func__);
			break;
		}

		/*
		 * A pvclock MSR write emulated on the previous iteration
		 * deferred its guest-page publish; return to vm_run() so it
		 * can commit outside the critical section before the guest
		 * runs again.
		 */
		if (vpvclock_pending(vcpu->vcpu)) {
			enable_intr();
			vm_exit_pvclock(vcpu->vcpu, rip);
			if (entry_owner != NULL &&
			    vmm_startup_entry_owner_software_exit(entry_owner,
			    &owner_result) != 0)
				panic("%s: pvclock startup owner", __func__);
			break;
		}

		/*
		 * If TPR Shadowing is enabled, the TPR Threshold
		 * must be updated right before entering the guest.
		 */
		if (tpr_shadowing && !virtual_interrupt_delivery) {
			if ((vcpu->cap.proc_ctls & PROCBASED_USE_TPR_SHADOW) != 0) {
				vmcs_write(VMCS_TPR_THRESHOLD, vlapic_get_cr8(vlapic));
			}
		}

		/*
		 * VM exits restore the base address but not the
		 * limits of GDTR and IDTR.  The VMCS only stores the
		 * base address, so VM exits set the limits to 0xffff.
		 * Save and restore the full GDTR and IDTR to restore
		 * the limits.
		 *
		 * The VMCS does not save the LDTR at all, and VM
		 * exits clear LDTR as if a NULL selector were loaded.
		 * The userspace hypervisor probably doesn't use a
		 * LDT, but save and restore it to be safe.
		 */
		sgdt(&gdtr);
		sidt(&idtr);
		ldt_sel = sldt();

		/*
		 * The TSC_AUX MSR must be saved/restored while interrupts
		 * are disabled so that it is not possible for the guest
		 * TSC_AUX MSR value to be overwritten by the resume
		 * portion of the IPI_SUSPEND codepath. This is why the
		 * transition of this MSR is handled separately from those
		 * handled by vmx_msr_guest_{enter,exit}(), which are ok to
		 * be transitioned with preemption disabled but interrupts
		 * enabled.
		 *
		 * These vmx_msr_guest_{enter,exit}_tsc_aux() calls can be
		 * anywhere in this loop so long as they happen with
		 * interrupts disabled. This location is chosen for
		 * simplicity.
		 */
		vmx_msr_guest_enter_tsc_aux(vmx, vcpu);

		vmx_dr_enter_guest(vmxctx);

		/*
		 * Mark the EPT as active on this host CPU and invalidate
		 * EPTP-tagged TLB entries if required.
		 */
		vmx_pmap_activate(vmx, pmap);
		if (entry_owner != NULL) {
			/*
			 * VMLAUNCH/VMRESUME can fail before any guest instruction
			 * executes.  Keep the common owner pending until the return
			 * classification below proves a VM exit, rather than counting
			 * an instruction failure as guest residency.
			 */
			error = vcpu_startup_entry_owner_guard_before_attempt(vcpu->vcpu,
			    entry_owner, &owner_runtime);
			if (error != 0 || owner_runtime.action !=
			    VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST) {
				vmx_pmap_deactivate(vmx, pmap);
				vmx_dr_leave_guest(vmxctx);
				vmx_msr_guest_exit_tsc_aux(vmx, vcpu);
				bare_lgdt(&gdtr);
				lidt(&idtr);
				lldt(ldt_sel);
				enable_intr();
				if (error == 0 &&
				    vmm_startup_entry_owner_resolve_deferred(entry_owner,
				    0, &owner_result) != 0)
					panic("%s: invalid declined VMX startup owner",
					    __func__);
				owner_guard_declined = true;
				break;
			}
		}

		vmx_run_trace(vcpu);
		rc = vmx_enter_guest(vmxctx, vmx, launched);

		vmx_pmap_deactivate(vmx, pmap);
		vmx_dr_leave_guest(vmxctx);
		vmx_msr_guest_exit_tsc_aux(vmx, vcpu);

		bare_lgdt(&gdtr);
		lidt(&idtr);
		lldt(ldt_sel);

		/* Collect some information for VM exit processing */
		vmexit->rip = rip = vmcs_guest_rip();
		vmexit->inst_length = vmexit_instruction_length();
		vmexit->u.vmx.exit_reason = exit_reason = vmcs_exit_reason();
		vmexit->u.vmx.exit_qualification = vmcs_exit_qualification();

		/* Update 'nextrip' */
		vcpu->state.nextrip = rip;

		if (rc == VMX_GUEST_VMEXIT) {
			if (entry_owner != NULL &&
			    vmm_startup_entry_owner_commit_attempt(entry_owner) != 0)
				panic("%s: VMX startup owner did not commit entry",
				    __func__);
			vmx_exit_handle_nmi(vcpu, vmexit);
			enable_intr();
			handled = vmx_exit_process(vmx, vcpu, vmexit);
		} else {
			enable_intr();
			vmx_exit_inst_error(vmxctx, rc, vmexit);
			if (entry_owner != NULL &&
			    vmm_startup_entry_owner_abort_attempt(entry_owner,
			    &owner_result) != 0)
				panic("%s: VMX startup owner did not abort entry",
				    __func__);
		}
		if (rc == VMX_GUEST_VMEXIT && entry_owner != NULL &&
		    vmm_startup_entry_owner_guard_after(entry_owner,
		    handled != 0, 0, handled != 0 ? NULL : &owner_result) != 0)
			panic("%s: invalid startup owner after VM entry", __func__);
		/*
		 * VMLAUNCH marks a VMCS launched only when it actually enters and
		 * returns through a VM exit.  VMfail leaves an unlaunched VMCS
		 * unlaunched, so a future in-kernel retry must not turn that retry
		 * into VMRESUME merely because the instruction was attempted.
		 */
		if (rc == VMX_GUEST_VMEXIT)
			launched = 1;
		vmx_exit_trace(vcpu, rip, exit_reason, handled);
		rip = vmexit->rip;
	} while (handled);

	/*
	 * If a VM exit has been handled then the exitcode must be BOGUS
	 * If a VM exit is not handled then the exitcode must not be BOGUS
	 */
	if (!owner_guard_declined &&
	    ((handled && vmexit->exitcode != VM_EXITCODE_BOGUS) ||
	    (!handled && vmexit->exitcode == VM_EXITCODE_BOGUS))) {
		panic("Mismatch between handled (%d) and exitcode (%d)",
		      handled, vmexit->exitcode);
	}

	VMX_CTR1(vcpu, "returning from vmx_run: exitcode %d",
	    vmexit->exitcode);

	VMCLEAR(vmcs);
	vmx_msr_guest_exit(vcpu);

	return (error);

software_exit:
	if (entry_owner != NULL &&
	    vmm_startup_entry_owner_software_exit(entry_owner,
	    &owner_result) != 0)
		panic("%s: internal startup owner", __func__);
	return (0);
}

enum vmx_nested_prepared_entry_release {
	VMX_NESTED_PREPARED_ENTRY_CANCEL,
	VMX_NESTED_PREPARED_ENTRY_COMPLETE,
};

static void
vmx_nested_prepared_values_clear(struct vmx_vcpu *vcpu)
{
	int error;

	if (vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1)
		panic("%s: clearing state with TSC_AUX residency %u", __func__,
		    vcpu->nested_tsc_aux_residency);
	memset(&vcpu->nested_vmcs12_snapshot, 0,
	    sizeof(vcpu->nested_vmcs12_snapshot));
	memset(&vcpu->nested_entry_environment, 0,
	    sizeof(vcpu->nested_entry_environment));
	memset(&vcpu->nested_vmcs02_plan, 0,
	    sizeof(vcpu->nested_vmcs02_plan));
	memset(&vcpu->nested_l1_software_msrs, 0,
	    sizeof(vcpu->nested_l1_software_msrs));
	memset(&vcpu->nested_l2_software_msrs, 0,
	    sizeof(vcpu->nested_l2_software_msrs));
	memset(&vcpu->nested_vmcs02_resources, 0,
	    sizeof(vcpu->nested_vmcs02_resources));
	if (vcpu->nested_exit_msr_transaction.state !=
	    VMX_NESTED_EXIT_MSR_TRANSACTION_IDLE) {
		if (vcpu->nested_exit_msr_transaction.state !=
		    VMX_NESTED_EXIT_MSR_TRANSACTION_COMMITTED &&
		    vcpu->nested_exit_msr_transaction.state !=
		    VMX_NESTED_EXIT_MSR_TRANSACTION_ABORTED)
			panic("%s: clearing active exit MSR transaction %u",
			    __func__,
			    vcpu->nested_exit_msr_transaction.state);
		error = vmx_nested_exit_msr_transaction_reset(
		    &vcpu->nested_exit_msr_transaction);
		if (error != 0)
			panic("%s: cannot reset exit MSR transaction: %d",
			    __func__, error);
	}
	memset(&vcpu->nested_exit_msr_plan, 0,
	    sizeof(vcpu->nested_exit_msr_plan));
	memset(&vcpu->nested_failed_entry_msr_plan, 0,
	    sizeof(vcpu->nested_failed_entry_msr_plan));
	memset(&vcpu->nested_exit_msr_software, 0,
	    sizeof(vcpu->nested_exit_msr_software));
	vcpu->nested_exit_msr_plan_valid = false;
	vcpu->nested_failed_entry_msr_plan_valid = false;
	explicit_bzero(vcpu->nested_l1_io_bitmap,
	    VMX_NESTED_IO_BITMAP_SIZE);
	explicit_bzero(vcpu->nested_l1_io_bitmap_scratch,
	    VMX_NESTED_IO_BITMAP_SIZE);
	explicit_bzero(vcpu->nested_l1_msr_bitmap,
	    VMX_NESTED_MSR_BITMAP_SIZE);
	explicit_bzero(vcpu->nested_msr_bitmap_scratch,
	    VMX_NESTED_MSR_BITMAP_SIZE);
	vcpu->nested_msr_generation = 0;
	vcpu->nested_entry_msr_count = 0;
	vcpu->nested_vmcs02_plan_valid = false;
	vcpu->nested_tsc_aux_rollback_residency =
	    VMX_NESTED_TSC_AUX_L1;
}

static void
vmx_nested_prepared_entry_release(struct vmx_vcpu *vcpu,
    enum vmx_nested_prepared_entry_release disposition)
{
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (vcpu == NULL || !vcpu->nested_vmcs02_plan_valid)
		panic("%s: no prepared nested entry", __func__);
	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		panic("%s: vCPU is not frozen", __func__);
	if (vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_RESOURCES)
		panic("%s: nested entry is not releasable: %u", __func__,
		    vcpu->nested_entry_runtime.state);
	if (!vcpu->nested_msr_workspace.active ||
	    vcpu->nested_msr_generation == 0)
		panic("%s: nested MSR workspace is not retained", __func__);
	if (vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE)
		panic("%s: L2 software MSRs remain installed", __func__);
	if (vcpu->nested_hardware_msr_count != 0)
		panic("%s: stale nested hardware MSR rollback count %u",
		    __func__, vcpu->nested_hardware_msr_count);
	if (vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1)
		panic("%s: TSC_AUX is not resident in L1: %u", __func__,
		    vcpu->nested_tsc_aux_residency);
	if (!((disposition == VMX_NESTED_PREPARED_ENTRY_CANCEL &&
	    vcpu->nested.phase == VMX_NESTED_CONTEXT_ENTRY_PENDING) ||
	    (disposition == VMX_NESTED_PREPARED_ENTRY_COMPLETE &&
	    (vcpu->nested.phase == VMX_NESTED_CONTEXT_ROOT ||
	    vcpu->nested.phase == VMX_NESTED_CONTEXT_ABORTED))))
		panic("%s: context phase %u does not match release disposition %u",
		    __func__, vcpu->nested.phase, disposition);

	id = &vcpu->nested_vmcs02_plan.id;
	error = vmx_nested_vmcs02_resources_intel_release(vcpu,
	    &vcpu->nested_vmcs02_resources);
	if (error != 0)
		panic("%s: cannot release nested VMCS02 resources: %d",
		    __func__, error);
	error = vmx_nested_msr_workspace_end(&vcpu->nested_msr_workspace,
	    vcpu->nested_msr_generation);
	if (error != 0)
		panic("%s: cannot release nested MSR workspace: %d", __func__,
		    error);
	error = vmx_nested_entry_runtime_release(
	    &vcpu->nested_entry_runtime, id);
	if (error != 0)
		panic("%s: cannot release nested entry runtime: %d", __func__,
		    error);
	if (disposition == VMX_NESTED_PREPARED_ENTRY_CANCEL) {
		error = vmx_nested_context_cancel_entry(&vcpu->nested, id);
		if (error != 0)
			panic("%s: cannot cancel prepared nested entry: %d",
			    __func__, error);
	}

	vmx_nested_prepared_values_clear(vcpu);
}

static void
vmx_nested_prepared_entry_discard(struct vmx_vcpu *vcpu)
{

	vmx_nested_prepared_entry_release(vcpu,
	    VMX_NESTED_PREPARED_ENTRY_CANCEL);
}

static void
vmx_nested_completed_entry_release(struct vmx_vcpu *vcpu)
{

	vmx_nested_prepared_entry_release(vcpu,
	    VMX_NESTED_PREPARED_ENTRY_COMPLETE);
}

static void
vmx_nested_cold_reflected_entry_release(struct vmx_vcpu *vcpu)
{
	int error;

	if (vcpu == NULL || !vcpu->nested_vmcs02_plan_valid ||
	    !vcpu->nested_l2_portable_valid)
		panic("%s: no retained cold reflected entry", __func__);
	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		panic("%s: vCPU is not frozen", __func__);
	if (!((vcpu->nested.phase == VMX_NESTED_CONTEXT_ROOT ||
	    vcpu->nested.phase == VMX_NESTED_CONTEXT_ABORTED) &&
	    vcpu->nested.internal.kind == VMX_NESTED_INTERNAL_NONE &&
	    vcpu->nested_entry_runtime.state ==
	    VMX_NESTED_ENTRY_RUNTIME_IDLE &&
	    vcpu->nested_l0_continuation.state ==
	    VMX_NESTED_L0_CONTINUATION_IDLE))
		panic("%s: cold reflected ownership was not committed", __func__);
	if (vcpu->nested_vmcs02_leases.active ||
	    vcpu->nested_ept_binding.active ||
	    vcpu->nested_vmcs02_intel.transaction_active ||
	    vcpu->nested_vmcs02_intel.launch.current ||
	    vcpu->nested_thaw_resources_valid)
		panic("%s: cold reflected entry retains hardware resources",
		    __func__);
	if (vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_count != 0 ||
	    vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1)
		panic("%s: cold reflected entry retains hardware MSR ownership",
		    __func__);
	if (!vcpu->nested_msr_workspace.active ||
	    vcpu->nested_msr_generation == 0)
		panic("%s: cold reflected MSR workspace is not retained",
		    __func__);

	error = vmx_nested_msr_workspace_end(&vcpu->nested_msr_workspace,
	    vcpu->nested_msr_generation);
	if (error != 0)
		panic("%s: cannot release cold reflected MSR workspace: %d",
		    __func__, error);
	memset(&vcpu->nested_l2_portable, 0,
	    sizeof(vcpu->nested_l2_portable));
	vcpu->nested_l2_portable_valid = false;
	vmx_nested_prepared_values_clear(vcpu);
}

static void
vmx_nested_cold_continuation_discard(struct vmx_vcpu *vcpu)
{
	int error;

	if (!(vcpu->nested_l0_continuation.state ==
	    VMX_NESTED_L0_CONTINUATION_COLD &&
	    vcpu->nested_entry_runtime.state ==
	    VMX_NESTED_ENTRY_RUNTIME_L0_COLD &&
	    vcpu->nested_l2_portable_valid &&
	    vcpu->nested_vmcs02_plan_valid))
		panic("%s: nested L2 is not a complete cold continuation",
		    __func__);
	if (vcpu->nested_vmcs02_leases.active ||
	    vcpu->nested_ept_binding.active ||
	    vcpu->nested_vmcs02_intel.transaction_active ||
	    vcpu->nested_vmcs02_intel.launch.current)
		panic("%s: cold continuation retains hardware resources",
		    __func__);
	if (vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_count != 0 ||
	    vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1)
		panic("%s: cold continuation retains hardware MSR ownership",
		    __func__);
	error = vmx_nested_msr_workspace_end(&vcpu->nested_msr_workspace,
	    vcpu->nested_msr_generation);
	if (error != 0)
		panic("%s: cannot release cold MSR workspace: %d", __func__,
		    error);
	error = vmx_nested_l0_continuation_discard_cold(
	    &vcpu->nested_l0_continuation, &vcpu->nested_entry_runtime,
	    &vcpu->nested_l2_portable, true);
	if (error != 0)
		panic("%s: cannot discard cold continuation: %d", __func__,
		    error);
	vcpu->nested_l2_portable_valid = false;
	vmx_nested_prepared_values_clear(vcpu);
}

static int
vmx_startup_claim_begin(void *arg, struct vmm_startup_event_claim *claim)
{
	struct vmx_vcpu *vcpu;

	vcpu = arg;
	return (vcpu_startup_event_claim_begin(vcpu->vcpu, claim));
}

static int
vmx_startup_claim_check(void *arg,
    const struct vmm_startup_event_claim *claim)
{
	struct vmx_vcpu *vcpu;

	vcpu = arg;
	return (vcpu_startup_event_claim_check(vcpu->vcpu, claim));
}

static int
vmx_startup_claim_finish(void *arg, struct vmm_startup_event_claim *claim)
{
	struct vmx_vcpu *vcpu;

	vcpu = arg;
	return (vcpu_startup_event_claim_finish(vcpu->vcpu, claim));
}

static int
vmx_startup_claim_abort(void *arg, struct vmm_startup_event_claim *claim)
{
	struct vmx_vcpu *vcpu;

	vcpu = arg;
	return (vcpu_startup_event_claim_abort(vcpu->vcpu, claim));
}

static int
vmx_startup_derive(void *arg, const struct vmm_startup_event_claim *claim,
    struct vmx_nested_startup_input *input)
{
	struct vmx_vcpu *vcpu;
	enum vmx_nested_startup_kind kind;

	vcpu = arg;
	if (vcpu == NULL || claim == NULL || input == NULL ||
	    vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN ||
	    claim->vcpuid != (uint32_t)vcpu_vcpuid(vcpu->vcpu))
		return (EINVAL);
	switch (claim->kind) {
	case VMM_STARTUP_EVENT_INIT:
		kind = VMX_NESTED_STARTUP_INIT;
		break;
	case VMM_STARTUP_EVENT_SIPI:
		kind = VMX_NESTED_STARTUP_SIPI;
		break;
	default:
		return (EINVAL);
	}
	return (vmx_nested_startup_input_from_frozen_target(kind,
	    claim->vector, &vcpu->nested, &vcpu->nested_l0_continuation,
	    &vcpu->nested_entry_runtime, &vcpu->nested_l2_portable,
	    vcpu->nested_l2_portable_valid, input));
}

/*
 * Private, transient binding for the staged L0 startup transaction.  This
 * contains host pointers and must never enter save state or a userspace ABI.
 */
struct vmx_startup_l0_binding {
	struct vmx_vcpu *vcpu;
	struct vmm_x86_startup_backend backend;
};

static int
vmx_startup_raw_getreg(void *arg, enum vm_reg_name reg, uint64_t *value)
{

	return (vmx_getreg(arg, reg, value));
}

static int
vmx_startup_raw_setreg(void *arg, enum vm_reg_name reg, uint64_t value)
{

	return (vmx_setreg(arg, reg, value));
}

static int
vmx_startup_raw_getdesc(void *arg, enum vm_reg_name reg,
    struct seg_desc *desc)
{

	return (vmx_getdesc(arg, reg, desc));
}

static int
vmx_startup_raw_setdesc(void *arg, enum vm_reg_name reg,
    const struct seg_desc *desc)
{
	struct seg_desc candidate;

	candidate = *desc;
	return (vmx_setdesc(arg, reg, &candidate));
}

static int
vmx_startup_machine_getreg(void *arg, enum vmm_x86_startup_register reg,
    uint64_t *value)
{
	struct vmx_startup_l0_binding *binding;

	binding = arg;
	return (vmm_x86_startup_backend_getreg(&binding->backend, reg, value));
}

static int
vmx_startup_machine_setreg(void *arg, enum vmm_x86_startup_register reg,
    uint64_t value)
{
	struct vmx_startup_l0_binding *binding;

	binding = arg;
	return (vmm_x86_startup_backend_setreg(&binding->backend, reg, value));
}

static int
vmx_startup_machine_getdesc(void *arg,
    enum vmm_x86_startup_descriptor desc,
    struct vmm_x86_startup_desc *value)
{
	struct vmx_startup_l0_binding *binding;

	binding = arg;
	return (vmm_x86_startup_backend_getdesc(&binding->backend, desc,
	    value));
}

static int
vmx_startup_machine_setdesc(void *arg,
    enum vmm_x86_startup_descriptor desc,
    const struct vmm_x86_startup_desc *value)
{
	struct vmx_startup_l0_binding *binding;

	binding = arg;
	return (vmm_x86_startup_backend_setdesc(&binding->backend, desc,
	    value));
}

static int
vmx_startup_event_capture(void *arg, struct vmm_event_state *state)
{
	struct vmx_startup_l0_binding *binding;

	binding = arg;
	return (vm_event_state_capture(binding->vcpu->vcpu, state));
}

static int
vmx_startup_event_compare_clear(void *arg,
    const struct vmm_event_state *state)
{
	struct vmx_startup_l0_binding *binding;

	binding = arg;
	return (vm_event_state_compare_clear(binding->vcpu->vcpu, state));
}

static void
vmx_startup_reset_nested(void *arg)
{
	struct vmx_startup_l0_binding *binding;
	int error;

	binding = arg;
	/*
	 * INIT ends the current nested execution environment.  Unreferenced
	 * EPT02 roots are still destination-local translations derived from
	 * the old L1 EPT tables; retaining them across the architectural reset
	 * could revive translations that the restarted guest never invalidated.
	 * Root destruction may release a vmspace and is therefore not an
	 * infallible, nonblocking finalizer operation.  The future activation
	 * path must destroy this derived cache during its fallible preparation
	 * phase, before committing the pending event.  Loss of an unreferenced
	 * derived cache is safe if the later event comparison rejects the
	 * transaction.  The production activation gate remains closed until
	 * that preparation step and its installed evidence exist.
	 */
	error = vmx_nested_ept_cache_empty(
	    &binding->vcpu->nested_ept_cache);
	if (__predict_false(error != 0))
		panic("%s: nested EPT cache reached finalizer: %d",
		    __func__, error);
	/*
	 * VPID02 is destination-local nested runtime ownership.  The INIT
	 * preflight proves that no provider callback is active, and release is
	 * then infallible because the allocator callback itself returns void.
	 * Consume it before resetting the architectural nested context so no
	 * scarce tag or deferred invalidation survives that reset.
	 */
	error = vmx_nested_vpid_owner_release(
	    &binding->vcpu->nested_vpid_owner, &vmx_nested_vpid_ops, NULL);
	if (__predict_false(error != 0))
		panic("%s: preflighted nested VPID release failed: %d", __func__,
		    error);
	error = vmx_nested_context_reset(&binding->vcpu->nested, true);
	if (__predict_false(error != 0))
		panic("%s: preflighted nested reset failed: %d", __func__,
		    error);
}

static void
vmx_startup_reset_lapic(void *arg)
{
	struct vmx_startup_l0_binding *binding;

	binding = arg;
	vlapic_reset_startup(binding->vcpu->vcpu);
}

static void
vmx_startup_retire_translation_residency(void *arg)
{
	struct vmx_startup_l0_binding *binding;

	binding = arg;
	vmx_invvpid(binding->vcpu->vmx, binding->vcpu, NULL, 0);
}

static void
vmx_startup_set_nextrip(void *arg, uint64_t nextrip)
{
	struct vmx_startup_l0_binding *binding;

	binding = arg;
	vm_set_nextrip(binding->vcpu->vcpu, nextrip);
}

static void
vmx_startup_publish_wait(void *arg, bool waiting)
{
	struct vmx_startup_l0_binding *binding;
	cpuset_t targets, waiters;

	binding = arg;
	CPU_ZERO(&targets);
	CPU_ZERO(&waiters);
	CPU_SET(binding->vcpu->vcpuid, &targets);
	if (waiting)
		CPU_SET(binding->vcpu->vcpuid, &waiters);
	vm_publish_startup_wait(vcpu_vm(binding->vcpu->vcpu), &targets,
	    &waiters);
}

static const struct vmm_x86_startup_backend_ops vmx_startup_backend_ops = {
	.getreg = vmx_startup_raw_getreg,
	.setreg = vmx_startup_raw_setreg,
	.getdesc = vmx_startup_raw_getdesc,
	.setdesc = vmx_startup_raw_setdesc,
};

static const struct vmm_x86_startup_machine_ops vmx_startup_machine_ops = {
	.getreg = vmx_startup_machine_getreg,
	.setreg = vmx_startup_machine_setreg,
	.getdesc = vmx_startup_machine_getdesc,
	.setdesc = vmx_startup_machine_setdesc,
	.event_capture = vmx_startup_event_capture,
	.event_compare_clear = vmx_startup_event_compare_clear,
};

static const struct vmm_x86_startup_finalizer_ops
vmx_startup_finalizer_ops = {
	.reset_nested = vmx_startup_reset_nested,
	.reset_lapic = vmx_startup_reset_lapic,
	.retire_translation_residency =
	    vmx_startup_retire_translation_residency,
	.set_nextrip = vmx_startup_set_nextrip,
	.publish_startup_wait = vmx_startup_publish_wait,
};

static int
vmx_startup_l0_binding_prepare(struct vmx_vcpu *vcpu,
    enum vmx_nested_startup_kind kind, uint8_t vector,
    struct vmx_startup_l0_binding *binding,
    struct vmm_x86_startup_transaction_input *input,
    struct vmm_x86_startup_finalizer *finalizer,
    uint32_t *processor_signature)
{
	struct vmx_startup_l0_binding binding_candidate;
	struct vmm_x86_startup_finalizer_plan finalizer_plan;
	struct vmm_x86_startup_transaction_input input_candidate;
	uint64_t rax, rbx, rcx, rdx;
	uint32_t signature_candidate;
	int error;

	if (vcpu == NULL || binding == NULL || input == NULL ||
	    finalizer == NULL || processor_signature == NULL ||
	    (kind != VMX_NESTED_STARTUP_INIT &&
	    kind != VMX_NESTED_STARTUP_SIPI) ||
	    (kind == VMX_NESTED_STARTUP_INIT && vector != 0) ||
	    !vmm_x86_startup_finalizer_consumed(finalizer) ||
	    vmx_nested_state_ranges_overlap(binding, sizeof(*binding), input,
	    sizeof(*input)) || vmx_nested_state_ranges_overlap(binding,
	    sizeof(*binding), finalizer, sizeof(*finalizer)) ||
	    vmx_nested_state_ranges_overlap(binding, sizeof(*binding),
	    processor_signature, sizeof(*processor_signature)) ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), finalizer,
	    sizeof(*finalizer)) || vmx_nested_state_ranges_overlap(input,
	    sizeof(*input), processor_signature, sizeof(*processor_signature)) ||
	    vmx_nested_state_ranges_overlap(finalizer, sizeof(*finalizer),
	    processor_signature, sizeof(*processor_signature)))
		return (EINVAL);
	memset(&binding_candidate, 0, sizeof(binding_candidate));
	memset(&input_candidate, 0, sizeof(input_candidate));
	input_candidate.kind = kind == VMX_NESTED_STARTUP_INIT ?
	    VMM_STARTUP_EVENT_INIT : VMM_STARTUP_EVENT_SIPI;
	input_candidate.vector = vector;
	input_candidate.bootstrap_processor =
	    (vlapic_get_apicbase(vm_lapic(vcpu->vcpu)) & APICBASE_BSP) != 0;
	error = vmm_x86_startup_finalizer_plan(&input_candidate,
	    &finalizer_plan);
	if (error != 0)
		return (error);
	binding_candidate.vcpu = vcpu;
	error = vmm_x86_startup_backend_init(&binding_candidate.backend,
	    &vmx_startup_backend_ops, vcpu);
	if (error != 0)
		return (error);
	if (vmx_startup_machine_ops.getreg == NULL ||
	    vmx_startup_machine_ops.setreg == NULL ||
	    vmx_startup_machine_ops.getdesc == NULL ||
	    vmx_startup_machine_ops.setdesc == NULL ||
	    vmx_startup_machine_ops.event_capture == NULL ||
	    vmx_startup_machine_ops.event_compare_clear == NULL)
		return (EPROTO);
	rax = CPUID_0000_0001;
	rbx = rcx = rdx = 0;
	error = x86_emulate_cpuid(vcpu->vcpu, &rax, &rbx, &rcx, &rdx);
	if (error != 0)
		return (error);
	if (rax > UINT32_MAX)
		return (EPROTO);
	signature_candidate = (uint32_t)rax;
	/*
	 * Bind the identity-bearing finalizer directly to its caller-owned
	 * storage.  All remaining publications are infallible plain values, so
	 * an error above preserves every output and success publishes a coherent
	 * set without copying the finalizer's storage cookie.
	 */
	error = vmm_x86_startup_finalizer_init(&vmx_startup_finalizer_ops,
	    binding, &finalizer_plan, finalizer);
	if (error != 0)
		return (error);
	*binding = binding_candidate;
	*input = input_candidate;
	*processor_signature = signature_candidate;
	return (0);
}

static int
vmx_nested_prepared_owner_validate(const struct vmx_vcpu *vcpu)
{
	int error;

	if (vcpu == NULL)
		return (EINVAL);
	error = vmx_nested_msr_workspace_validate(
	    &vcpu->nested_msr_workspace);
	if (error != 0)
		return (error);
	if (!vcpu->nested_vmcs02_plan_valid) {
		if (vcpu->nested_msr_workspace.active ||
		    vcpu->nested_msr_generation != 0 ||
		    vcpu->nested_entry_msr_count != 0)
			return (EPROTO);
		return (0);
	}
	if (!vcpu->nested_msr_workspace.active ||
	    vcpu->nested_msr_generation == 0 ||
	    vcpu->nested_msr_generation !=
	    vcpu->nested_msr_workspace.generation ||
	    vcpu->nested_entry_msr_count >
	    vcpu->nested_msr_workspace.capacity ||
	    (vcpu->nested_entry_msr_count != 0 &&
	    vcpu->nested_entry_msr_count !=
	    vcpu->nested_vmcs12_snapshot.controls.entry_msr_load_count) ||
	    !vmx_nested_vmcs02_id_valid(&vcpu->nested_vmcs02_plan.id) ||
	    !vmx_nested_vmcs02_id_equal(&vcpu->nested_vmcs02_plan.id,
	    &vcpu->nested_vmcs02_plan.image.id) ||
	    vcpu->nested_vmcs02_plan.vmentry.disposition !=
	    VMX_NESTED_VMENTRY_READY)
		return (EPROTO);
	return (0);
}

static int
vmx_nested_ept_cache_owner_quiesce(const struct vmx_vcpu *vcpu)
{

	if (vcpu == NULL)
		return (EINVAL);
	if (vcpu->nested_ept_cache.entries != vcpu->nested_ept_entries ||
	    vcpu->nested_ept_cache.capacity !=
	    nitems(vcpu->nested_ept_entries) ||
	    vcpu->nested_ept_cache.ops.create !=
	    vmx_nested_ept_cache_ops.create ||
	    vcpu->nested_ept_cache.ops.destroy !=
	    vmx_nested_ept_cache_ops.destroy ||
	    vcpu->nested_ept_cache.ops.invalidate !=
	    vmx_nested_ept_cache_ops.invalidate ||
	    vcpu->nested_ept_cache.arg != &vcpu->nested_ept_backend ||
	    vcpu->nested_ept_backend.min_address != 0 ||
	    vcpu->nested_ept_backend.max_address !=
	    VM_MAXUSER_ADDRESS_LA48)
		return (EPROTO);
	return (vmx_nested_ept_cache_quiesce(&vcpu->nested_ept_cache));
}

static int
vmx_startup_preflight_owner_error(
    struct vmx_nested_l0_startup_preflight *preflight, uint64_t blocker,
    int error)
{

	if (preflight == NULL || blocker == 0 ||
	    (blocker & (blocker - 1)) != 0 ||
	    (blocker & ~VMX_NESTED_L0_STARTUP_BLOCKERS) != 0)
		return (EINVAL);
	if (error == 0)
		return (0);
	if (error != EBUSY)
		return (error);
	preflight->blockers |= blocker;
	return (0);
}

static int
vmx_startup_l0_owner_preflight(void *arg,
    enum vmx_nested_startup_kind kind,
    uint8_t vector)
{
	struct vmx_nested_l0_startup_preflight preflight;
	struct vmx_vcpu *vcpu;
	bool registry_owner_active;
	int error;

	vcpu = arg;
	if (vcpu == NULL ||
	    vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN ||
	    (kind != VMX_NESTED_STARTUP_INIT &&
	    kind != VMX_NESTED_STARTUP_SIPI) ||
	    (kind == VMX_NESTED_STARTUP_INIT && vector != 0))
		return (EINVAL);

	memset(&preflight, 0, sizeof(preflight));
	preflight.version = VMX_NESTED_L0_STARTUP_PREFLIGHT_VERSION;
	preflight.kind = kind;
	preflight.context_generation = vcpu->nested.state_generation;
	error = vmx_startup_preflight_owner_error(&preflight,
	    VMX_NESTED_L0_STARTUP_CONTEXT,
	    vmx_nested_context_quiesce(&vcpu->nested));
	if (error != 0)
		return (error);
	if (vcpu->nested.phase != VMX_NESTED_CONTEXT_ROOT ||
	    vcpu->nested.machine.vmxon)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_CONTEXT;
	error = vmx_nested_l0_continuation_validate(
	    &vcpu->nested_l0_continuation);
	if (error != 0)
		return (error);
	if (vcpu->nested_l0_continuation.state !=
	    VMX_NESTED_L0_CONTINUATION_IDLE)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_CONTINUATION;
	error = vmx_nested_entry_runtime_validate(&vcpu->nested_entry_runtime);
	if (error != 0)
		return (error);
	if (vcpu->nested_entry_runtime.state != VMX_NESTED_ENTRY_RUNTIME_IDLE)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_RUNTIME;
	error = vmx_nested_mtf_owner_validate(&vcpu->nested_mtf_owner);
	if (error != 0)
		return (error);
	if (vcpu->nested_mtf_owner.pending)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_MTF;
	if (vcpu->nested_l2_thaw_staged.state <
	    VMX_NESTED_L2_THAW_STAGED_IDLE ||
	    vcpu->nested_l2_thaw_staged.state >
	    VMX_NESTED_L2_THAW_STAGED_POISONED ||
	    vcpu->nested_refreeze_staged.state < VMX_NESTED_REFREEZE_IDLE ||
	    vcpu->nested_refreeze_staged.state >
	    VMX_NESTED_REFREEZE_POISONED)
		return (EPROTO);
	if (vcpu->nested_l2_thaw_staged.state !=
	    VMX_NESTED_L2_THAW_STAGED_IDLE ||
	    vcpu->nested_thaw_resources_valid)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_THAW;
	if (vcpu->nested_refreeze_staged.state != VMX_NESTED_REFREEZE_IDLE)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_REFREEZE;
	if (vcpu->nested_l2_portable_valid)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_PORTABLE;
	error = vmx_startup_preflight_owner_error(&preflight,
	    VMX_NESTED_L0_STARTUP_VMCS02,
	    vmx_nested_vmcs02_intel_inactive_validate(
		&vcpu->nested_vmcs02_intel));
	if (error != 0)
		return (error);
	error = vmx_nested_ept_binding_validate(&vcpu->nested_ept_binding);
	if (error != 0)
		return (error);
	if (vcpu->nested_ept_binding.active)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_EPT;
	error = vmx_startup_preflight_owner_error(&preflight,
	    VMX_NESTED_L0_STARTUP_EPT,
	    vmx_nested_ept_cache_owner_quiesce(vcpu));
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs02_lease_owner_validate(
	    &vcpu->nested_vmcs02_leases);
	if (error != 0)
		return (error);
	if (vcpu->nested_vmcs02_leases.active ||
	    vcpu->nested_vmcs02_leases.callback_active ||
	    vcpu->nested_vmcs02_leases.count != 0)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_LEASES;
	error = vmx_nested_msr_workspace_validate(
	    &vcpu->nested_msr_workspace);
	if (error != 0)
		return (error);
	error = vmx_nested_prepared_owner_validate(vcpu);
	if (error != 0)
		return (error);
	if (vcpu->nested_msr_workspace.active)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_WORKSPACE;
	error = vmx_nested_exit_msr_transaction_validate(
	    &vcpu->nested_exit_msr_transaction);
	if (error != 0)
		return (error);
	if (vcpu->nested_exit_msr_transaction.state !=
	    VMX_NESTED_EXIT_MSR_TRANSACTION_IDLE)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_EXIT_MSR;
	if (vcpu->nested_vmcs02_plan_valid ||
	    vcpu->nested_exit_msr_plan_valid ||
	    vcpu->nested_failed_entry_msr_plan_valid ||
	    vcpu->nested_msr_generation != 0 ||
	    vcpu->nested_entry_msr_count != 0)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_PREPARED;
	if (vcpu->nested_hardware_msr_transition <
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_transition >
	    VMX_NESTED_HARDWARE_MSR_EXIT ||
	    vcpu->nested_tsc_aux_residency < VMX_NESTED_TSC_AUX_L1 ||
	    vcpu->nested_tsc_aux_residency > VMX_NESTED_TSC_AUX_L2_PAUSED ||
	    vcpu->nested_tsc_aux_rollback_residency <
	    VMX_NESTED_TSC_AUX_L1 ||
	    vcpu->nested_tsc_aux_rollback_residency >
	    VMX_NESTED_TSC_AUX_L2_PAUSED)
		return (EPROTO);
	if (vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_count != 0 ||
	    vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1 ||
	    vcpu->nested_tsc_aux_rollback_residency !=
	    VMX_NESTED_TSC_AUX_L1)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_HARDWARE_MSR;
	error = vmx_nested_vpid_owner_validate(&vcpu->nested_vpid_owner);
	if (error != 0)
		return (error);
	if (vcpu->nested_vpid_owner.callback_active ||
	    (kind == VMX_NESTED_STARTUP_SIPI &&
	    (vcpu->nested_vpid_owner.active ||
	    vcpu->nested_vpid_owner.pending_flush)))
		preflight.blockers |= VMX_NESTED_L0_STARTUP_VPID;
	if (vcpu->nested_hot_failure_detached)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_HOT_FAILURE;
	registry_owner_active = false;
	sx_slock(&vcpu->vmx->nested_vmcs_sx);
	error = vmx_nested_vmcs_registry_owner_active(
	    &vcpu->vmx->nested_vmcs_registry, vcpu->vcpuid,
	    &registry_owner_active);
	sx_sunlock(&vcpu->vmx->nested_vmcs_sx);
	if (error != 0)
		return (error);
	if (registry_owner_active)
		preflight.blockers |= VMX_NESTED_L0_STARTUP_VMCS_REGISTRY;
	return (vmx_nested_l0_startup_preflight_validate(&preflight));
}

static int
vmx_startup_prepare_l0(void *arg, enum vmx_nested_startup_kind kind,
    uint8_t vector)
{
	struct vmx_vcpu *vcpu;
	int error;

	error = vmx_startup_l0_owner_preflight(arg, kind, vector);
	if (error != 0)
		return (error);
	if (kind == VMX_NESTED_STARTUP_SIPI)
		return (0);
	vcpu = arg;
	/*
	 * INIT discards nested architectural execution.  Retire only quiescent
	 * EPT02 roots here, in the explicitly fallible preparation callback;
	 * the later architectural apply callback remains all-or-nothing.  The
	 * cache is derived destination-local state, and destruction is therefore
	 * safe across an apply rejection and idempotent on retry.  SIPI preserves
	 * it because SIPI does not reset nested execution.
	 */
	error = vmx_nested_ept_cache_destroy(&vcpu->nested_ept_cache);
	if (error != 0)
		return (error);
	return (vmx_nested_ept_cache_empty(&vcpu->nested_ept_cache) == 0 ?
	    0 : EIO);
}

static enum vmx_nested_startup_machine_disposition
vmx_startup_apply_l0(void *arg, enum vmx_nested_startup_kind kind,
    uint8_t vector, int *errorp)
{
	struct vmx_startup_l0_binding binding;
	struct vmm_x86_startup_finalizer finalizer;
	struct vmm_x86_startup_transaction_input input;
	struct vmm_x86_startup_transaction_result result;
	struct vmx_vcpu *vcpu;
	uint32_t processor_signature;
	int error;

	if (errorp == NULL)
		return (VMX_NESTED_STARTUP_MACHINE_FAIL_STOP);
	*errorp = EPROTO;
	error = vmx_startup_l0_owner_preflight(arg, kind, vector);
	if (error != 0) {
		*errorp = error;
		return (error == EAGAIN || error == EBUSY ?
		    VMX_NESTED_STARTUP_MACHINE_RETRY :
		    VMX_NESTED_STARTUP_MACHINE_FAIL_STOP);
	}
	vcpu = arg;
	memset(&binding, 0, sizeof(binding));
	memset(&input, 0, sizeof(input));
	memset(&finalizer, 0, sizeof(finalizer));
	memset(&result, 0, sizeof(result));
	processor_signature = 0;
	error = vmx_startup_l0_binding_prepare(vcpu, kind, vector, &binding,
	    &input, &finalizer, &processor_signature);
	if (error != 0) {
		*errorp = error;
		return (VMX_NESTED_STARTUP_MACHINE_FAIL_STOP);
	}
	/*
	 * Execute the complete, preflighted frozen-vCPU mutation through the
	 * common x86 transaction.  It captures every writable architectural
	 * field, verifies every setter, rolls back on a fallible failure, and
	 * performs the no-fail finalizer only after commit.  The disposition
	 * keeps retryable arbitration distinct from an ownership failure.
	 *
	 * The explicit bhyve startup-management handshake selects this path.  The
	 * backend readiness callback is true only after the complete run-owner and
	 * frozen-target transactions have been wired.
	 */
	error = vmm_x86_startup_machine_execute(&input, processor_signature,
	    &vmx_startup_machine_ops, &binding, &finalizer, &result);
	*errorp = error;
	return (vmx_nested_startup_machine_disposition(error, &result));
}

static int
vmx_startup_commit_active_l2(void *arg,
    const struct vmx_nested_startup_plan *plan)
{
	struct vmx_vcpu *vcpu;

	vcpu = arg;
	if (vcpu == NULL ||
	    vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		return (EINVAL);
	return (vmx_nested_cold_startup_commit(&vcpu->nested,
	    &vcpu->nested_l0_continuation, &vcpu->nested_entry_runtime,
	    &vcpu->nested_l2_portable, plan));
}

static const struct vmx_nested_startup_dispatch_ops
vmx_startup_dispatch_ops = {
	.claim_begin = vmx_startup_claim_begin,
	.claim_check = vmx_startup_claim_check,
	.claim_abort = vmx_startup_claim_abort,
	.derive = vmx_startup_derive,
	.transaction = {
		.prepare_l0 = vmx_startup_prepare_l0,
		.apply_l0 = vmx_startup_apply_l0,
		.commit_active_l2 = vmx_startup_commit_active_l2,
		.claim_finish = vmx_startup_claim_finish,
	},
};

static int
vmx_vcpu_event_cleanup_check(void *vcpui)
{
	struct vmx_vcpu *vcpu;

	vcpu = vcpui;
	return (vmx_nested_startup_dispatch_cleanup_check(
	    &vcpu->nested_startup_dispatch, &vmx_startup_dispatch_ops, vcpu));
}

static bool
vmx_startup_kernel_actions_ready(void)
{

	/*
	 * The frozen-target INIT/SIPI transaction, ordinary VMCS01 entry, and every
	 * initial, resumed, and hot VMCS02 entry/no-entry edge now consume the common
	 * startup owner synchronously.  bhyve still selects this path explicitly;
	 * historical VM_RUN therefore retains userspace-owned IPI delivery.
	 */
	return (true);
}

static int
vmx_vcpu_startup_event_step(void *vcpui,
    enum vmm_startup_dispatch_result *result)
{
	struct vmx_vcpu *vcpu;
	enum vmx_nested_startup_dispatch_result private_result;
	int error;

	if (vcpui == NULL || result == NULL)
		return (EINVAL);
	vcpu = vcpui;
	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	error = vmx_nested_startup_dispatch_step(
	    &vcpu->nested_startup_dispatch, &vmx_startup_dispatch_ops, vcpu,
	    &private_result);
	if (error != 0)
		return (error);
	switch (private_result) {
	case VMX_NESTED_STARTUP_DISPATCH_IDLE:
		*result = VMM_STARTUP_DISPATCH_IDLE;
		break;
	case VMX_NESTED_STARTUP_DISPATCH_RETAINED:
		*result = VMM_STARTUP_DISPATCH_RETAINED;
		break;
	case VMX_NESTED_STARTUP_DISPATCH_CONSUMED:
		*result = VMM_STARTUP_DISPATCH_CONSUMED;
		break;
	default:
		return (EPROTO);
	}
	return (0);
}

static int
vmx_vcpu_event_cleanup(void *vcpui)
{
	struct vmx_vcpu *vcpu;

	vcpu = vcpui;
	return (vmx_nested_startup_dispatch_cleanup(
	    &vcpu->nested_startup_dispatch, &vmx_startup_dispatch_ops, vcpu));
}

static void
vmx_vcpu_cleanup(void *vcpui)
{
	struct vmx_vcpu *vcpu = vcpui;
	int error;

	/*
	 * Teardown owns the frozen vCPU and intentionally abandons nested
	 * execution, pending handoffs, and unconsumed results.  A callback or
	 * hardware apply must never remain active after vm_run() returns.
	 */
	error = vmx_nested_startup_dispatch_validate(
	    &vcpu->nested_startup_dispatch);
	if (error != 0 || vcpu->nested_startup_dispatch.state !=
	    VMX_NESTED_STARTUP_DISPATCH_EMPTY)
		panic("%s: nested startup dispatch still active: state %u "
		    "error %d", __func__, vcpu->nested_startup_dispatch.state,
		    error);
	if (vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_count != 0 ||
	    vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1)
		panic("%s: nested hardware MSR transition still active: "
		    "transition %d count %u TSC_AUX residency %u", __func__,
		    vcpu->nested_hardware_msr_transition,
		    vcpu->nested_hardware_msr_count,
		    vcpu->nested_tsc_aux_residency);
	if (vcpu->nested_refreeze_staged.state !=
	    VMX_NESTED_REFREEZE_IDLE) {
		if (vcpu->nested_refreeze_staged.state !=
		    VMX_NESTED_REFREEZE_DETACHED ||
		    vcpu->nested.internal.kind !=
		    VMX_NESTED_INTERNAL_REFREEZE)
			panic("%s: invalid staged nested refreeze at teardown: "
			    "stage %u internal %u", __func__,
			    vcpu->nested_refreeze_staged.state,
			    vcpu->nested.internal.kind);
		error = vmx_nested_l0_refreeze_commit_frozen_intel(vcpu);
		if (error != 0)
			panic("%s: cannot complete staged nested refreeze: %d",
			    __func__, error);
		/*
		 * A retry refreeze publishes a cold continuation which teardown
		 * may abandon.  A late failed entry has already crossed the
		 * destructive detach boundary, so finish its architectural L1
		 * transaction before releasing the retained portable owner.
		 */
		if (vcpu->nested.internal.kind ==
		    VMX_NESTED_INTERNAL_LATE_VMENTRY) {
			error = vmx_nested_commit_late_entry_handoff(vcpu);
			if (error != 0)
				panic("%s: cannot commit late nested entry "
				    "failure: %d", __func__, error);
		} else {
			vmx_nested_internal_init(&vcpu->nested.internal);
		}
	}
	if (vcpu->nested.internal.kind ==
	    VMX_NESTED_INTERNAL_LATE_VMENTRY) {
		error = vmx_nested_commit_late_entry_handoff(vcpu);
		if (error != 0)
			panic("%s: cannot finish pending late nested entry "
			    "failure: %d", __func__, error);
	}
	if (vcpu->nested_l2_thaw_staged.state !=
	    VMX_NESTED_L2_THAW_STAGED_IDLE ||
	    vcpu->nested_thaw_resources_valid) {
		if (vcpu->nested_l2_thaw_staged.state !=
		    VMX_NESTED_L2_THAW_STAGED_PREPARED ||
		    !vcpu->nested_thaw_resources_valid ||
		    vcpu->nested_l0_continuation.state !=
		    VMX_NESTED_L0_CONTINUATION_THAWING ||
		    vcpu->nested_entry_runtime.state !=
		    VMX_NESTED_ENTRY_RUNTIME_L0_THAWING)
			panic("%s: invalid staged nested thaw at teardown: "
			    "stage %u resources %d continuation %u "
			    "runtime %u", __func__,
			    vcpu->nested_l2_thaw_staged.state,
			    vcpu->nested_thaw_resources_valid,
			    vcpu->nested_l0_continuation.state,
			    vcpu->nested_entry_runtime.state);
		error = vmx_nested_l0_thaw_cancel_intel(vcpu);
		if (error != 0)
			panic("%s: cannot cancel staged nested thaw: %d",
			    __func__, error);
	}
	if (vcpu->nested_hot_failure_detached) {
		if (!(vcpu->nested_entry_runtime.state ==
		    VMX_NESTED_ENTRY_RUNTIME_ABORTED &&
		    vcpu->nested_entry_runtime.rollback_failed &&
		    vcpu->nested_l0_continuation.state ==
		    VMX_NESTED_L0_CONTINUATION_IDLE &&
		    !vcpu->nested_vmcs02_intel.launch.current &&
		    vcpu->nested_hardware_msr_transition ==
		    VMX_NESTED_HARDWARE_MSR_NONE &&
		    vcpu->nested_tsc_aux_residency ==
		    VMX_NESTED_TSC_AUX_L1))
			panic("%s: incomplete recovered hot-entry failure",
			    __func__);
		error = vmx_nested_vmcs02_resources_intel_release(vcpu,
		    &vcpu->nested_vmcs02_resources);
		if (error != 0)
			panic("%s: cannot release detached hot-entry "
			    "resources: %d", __func__, error);
		error = vmx_nested_entry_runtime_reset(
		    &vcpu->nested_entry_runtime,
		    &vcpu->nested_vmcs02_plan.id, true, true);
		if (error != 0)
			panic("%s: cannot retire recovered hot-entry failure: "
			    "%d", __func__, error);
		error = vmx_nested_msr_workspace_end(
		    &vcpu->nested_msr_workspace,
		    vcpu->nested_msr_generation);
		if (error != 0)
			panic("%s: cannot release recovered hot-entry "
			    "workspace: %d", __func__, error);
		if (vcpu->nested_mtf_owner.pending) {
			uint64_t mtf_generation;

			/*
			 * The failed hot entry has no portable rollback owner and
			 * teardown has now retired its runtime and MSR workspace.
			 * Abandon exactly the MTF obligation attached to that VMCS02;
			 * a stale identity remains a fatal ownership defect.
			 */
			mtf_generation =
			    vcpu->nested_mtf_owner.origin_generation;
			error = vmx_nested_mtf_owner_consume(
			    &vcpu->nested_mtf_owner,
			    &vcpu->nested_vmcs02_plan.id, mtf_generation);
			if (error != 0)
				panic("%s: cannot abandon recovered hot-entry "
				    "MTF owner: %d", __func__, error);
		}
		vmx_nested_prepared_values_clear(vcpu);
		vcpu->nested_hot_failure_detached = false;
	}
	if (vcpu->nested_l0_continuation.state ==
	    VMX_NESTED_L0_CONTINUATION_COLD)
		vmx_nested_cold_continuation_discard(vcpu);
	else if (vcpu->nested_l0_continuation.state !=
	    VMX_NESTED_L0_CONTINUATION_IDLE)
		panic("%s: nested L0 continuation escaped a hardware run "
		    "boundary: state %u rollback_failed %d", __func__,
		    vcpu->nested_l0_continuation.state,
		    vcpu->nested_l0_continuation.rollback_failed);
	else if (vcpu->nested_vmcs02_plan_valid) {
		if (vcpu->nested_entry_runtime.state !=
		    VMX_NESTED_ENTRY_RUNTIME_RESOURCES ||
		    vcpu->nested.phase != VMX_NESTED_CONTEXT_ENTRY_PENDING)
			panic("%s: nested plan is not a cancellable prepared "
			    "entry: runtime %u context %u", __func__,
			    vcpu->nested_entry_runtime.state,
			    vcpu->nested.phase);
		vmx_nested_prepared_entry_discard(vcpu);
	}
	error = vmx_nested_context_destroy(&vcpu->nested, true);
	if (error != 0)
		panic("%s: nested context still has active runtime work: %d",
		    __func__, error);
	error = vmx_nested_entry_runtime_validate(
	    &vcpu->nested_entry_runtime);
	if (error != 0 ||
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_IDLE)
		panic("%s: nested entry runtime still active: state %u error %d",
		    __func__, vcpu->nested_entry_runtime.state, error);
	error = vmx_nested_l0_continuation_validate(
	    &vcpu->nested_l0_continuation);
	if (error != 0 ||
	    vcpu->nested_l0_continuation.state !=
	    VMX_NESTED_L0_CONTINUATION_IDLE ||
	    vcpu->nested_l2_portable_valid)
		panic("%s: nested L0 continuation still active: state %u "
		    "portable %d error %d", __func__,
		    vcpu->nested_l0_continuation.state,
		    vcpu->nested_l2_portable_valid, error);
	error = vmx_nested_mtf_owner_validate(&vcpu->nested_mtf_owner);
	if (error != 0 || vcpu->nested_mtf_owner.pending)
		panic("%s: nested MTF owner still active: pending %d error %d",
		    __func__, vcpu->nested_mtf_owner.pending, error);
	error = vmx_nested_msr_workspace_validate(
	    &vcpu->nested_msr_workspace);
	if (error != 0 || vcpu->nested_msr_workspace.active)
		panic("%s: nested MSR workspace still active: error %d",
		    __func__, error);
	if (vcpu->nested_msr_storage != NULL) {
		error = vmx_nested_msr_workspace_unbind(
		    &vcpu->nested_msr_workspace);
		if (error != 0)
			panic("%s: cannot unbind nested MSR workspace: %d",
			    __func__, error);
		free(vcpu->nested_msr_storage, M_VMX);
		vcpu->nested_msr_storage = NULL;
	}
	sx_xlock(&vcpu->vmx->nested_vmcs_sx);
	error = vmx_nested_vmcs_registry_release(
	    &vcpu->vmx->nested_vmcs_registry, vcpu->vcpuid);
	sx_xunlock(&vcpu->vmx->nested_vmcs_sx);
	if (error != 0 && error != ENOENT)
		panic("%s: nested VMCS owner release failed: %d", __func__,
		    error);
	if (vcpu->nested_ept_binding.active) {
		error = vmx_nested_ept_binding_unbind(
		    &vcpu->nested_ept_cache,
		    &vcpu->nested_ept_binding);
		if (error != 0)
			panic("%s: nested EPT active root release failed: %d",
			    __func__, error);
	}
	if (vcpu->nested_vmcs02_leases.active)
		panic("%s: active nested VMCS02 resource lease", __func__);
	error = vmx_nested_ept_cache_destroy(&vcpu->nested_ept_cache);
	if (error != 0)
		panic("%s: referenced nested EPT root during teardown: %d",
		    __func__, error);
	error = vmx_nested_vpid_owner_release(&vcpu->nested_vpid_owner,
	    &vmx_nested_vpid_ops, NULL);
	if (error != 0)
		panic("%s: invalid nested VPID owner during teardown: %d",
		    __func__, error);
	vpid_free(vcpu->state.vpid);
	free(vcpu->pir_desc, M_VMX);
	free(vcpu->apic_page, M_VMX);
	free(vcpu->nested_vmcs02, M_VMX);
	free(vcpu->nested_vmcs_scratch, M_VMX);
	free(vcpu->nested_l1_io_bitmap_scratch, M_VMX);
	free(vcpu->nested_l1_io_bitmap, M_VMX);
	free(vcpu->nested_msr_bitmap_scratch, M_VMX);
	free(vcpu->nested_l1_msr_bitmap, M_VMX);
	free(vcpu->nested_msr_bitmap, M_VMX);
	free(vcpu->vmcs, M_VMX);
	free(vcpu, M_VMX);
}

static void
vmx_cleanup(void *vmi)
{
	struct vmx *vmx = vmi;
	int error;

	if (virtual_interrupt_delivery)
		vm_unmap_mmio(vmx->vm, DEFAULT_APIC_BASE, PAGE_SIZE);

	free(vmx->msr_bitmap, M_VMX);
#ifdef BHYVE_SNAPSHOT
	vmx_nested_snapshot_restore_free(vmx->nested_snapshot_restore);
#endif
	if (vmx->nested_vmcs_registry.initialized) {
		error = vmx_nested_vmcs_registry_destroy(
		    &vmx->nested_vmcs_registry);
		if (error != 0)
			panic("%s: nested VMCS registry destroy failed: %d",
			    __func__, error);
	}
	sx_destroy(&vmx->nested_vmcs_sx);
	free(vmx, M_VMX);

	return;
}

static register_t *
vmxctx_regptr(struct vmxctx *vmxctx, int reg)
{

	switch (reg) {
	case VM_REG_GUEST_RAX:
		return (&vmxctx->guest_rax);
	case VM_REG_GUEST_RBX:
		return (&vmxctx->guest_rbx);
	case VM_REG_GUEST_RCX:
		return (&vmxctx->guest_rcx);
	case VM_REG_GUEST_RDX:
		return (&vmxctx->guest_rdx);
	case VM_REG_GUEST_RSI:
		return (&vmxctx->guest_rsi);
	case VM_REG_GUEST_RDI:
		return (&vmxctx->guest_rdi);
	case VM_REG_GUEST_RBP:
		return (&vmxctx->guest_rbp);
	case VM_REG_GUEST_R8:
		return (&vmxctx->guest_r8);
	case VM_REG_GUEST_R9:
		return (&vmxctx->guest_r9);
	case VM_REG_GUEST_R10:
		return (&vmxctx->guest_r10);
	case VM_REG_GUEST_R11:
		return (&vmxctx->guest_r11);
	case VM_REG_GUEST_R12:
		return (&vmxctx->guest_r12);
	case VM_REG_GUEST_R13:
		return (&vmxctx->guest_r13);
	case VM_REG_GUEST_R14:
		return (&vmxctx->guest_r14);
	case VM_REG_GUEST_R15:
		return (&vmxctx->guest_r15);
	case VM_REG_GUEST_CR2:
		return (&vmxctx->guest_cr2);
	case VM_REG_GUEST_DR0:
		return (&vmxctx->guest_dr0);
	case VM_REG_GUEST_DR1:
		return (&vmxctx->guest_dr1);
	case VM_REG_GUEST_DR2:
		return (&vmxctx->guest_dr2);
	case VM_REG_GUEST_DR3:
		return (&vmxctx->guest_dr3);
	case VM_REG_GUEST_DR6:
		return (&vmxctx->guest_dr6);
	default:
		break;
	}
	return (NULL);
}

static int
vmxctx_getreg(struct vmxctx *vmxctx, int reg, uint64_t *retval)
{
	register_t *regp;

	if ((regp = vmxctx_regptr(vmxctx, reg)) != NULL) {
		*retval = *regp;
		return (0);
	} else
		return (EINVAL);
}

static int
vmxctx_setreg(struct vmxctx *vmxctx, int reg, uint64_t val)
{
	register_t *regp;

	if ((regp = vmxctx_regptr(vmxctx, reg)) != NULL) {
		*regp = val;
		return (0);
	} else
		return (EINVAL);
}

static int
vmx_get_intr_shadow(struct vmx_vcpu *vcpu, int running, uint64_t *retval)
{
	uint64_t gi;
	int error;

	error = vmcs_getreg(vcpu->vmcs, running,
	    VMCS_IDENT(VMCS_GUEST_INTERRUPTIBILITY), &gi);
	*retval = (gi & HWINTR_BLOCKING) ? 1 : 0;
	return (error);
}

static int
vmx_modify_intr_shadow(struct vmx_vcpu *vcpu, int running, uint64_t val)
{
	struct vmcs *vmcs;
	uint64_t gi;
	int error, ident;

	/*
	 * Forcing the vcpu into an interrupt shadow is not supported.
	 */
	if (val) {
		error = EINVAL;
		goto done;
	}

	vmcs = vcpu->vmcs;
	ident = VMCS_IDENT(VMCS_GUEST_INTERRUPTIBILITY);
	error = vmcs_getreg(vmcs, running, ident, &gi);
	if (error == 0) {
		gi &= ~HWINTR_BLOCKING;
		error = vmcs_setreg(vmcs, running, ident, gi);
	}
done:
	VMX_CTR2(vcpu, "Setting intr_shadow to %#lx %s", val,
	    error ? "failed" : "succeeded");
	return (error);
}

static int
vmx_shadow_reg(int reg)
{
	int shreg;

	shreg = -1;

	switch (reg) {
	case VM_REG_GUEST_CR0:
		shreg = VMCS_CR0_SHADOW;
		break;
	case VM_REG_GUEST_CR4:
		shreg = VMCS_CR4_SHADOW;
		break;
	default:
		break;
	}

	return (shreg);
}

static int
vmx_nested_cold_l2(struct vmx_vcpu *vcpu,
    struct vmx_nested_l2_portable_state **state)
{
	const struct vmx_nested_vmcs02_id *id;

	if (vcpu->nested_l0_continuation.state !=
	    VMX_NESTED_L0_CONTINUATION_COLD)
		return (ENOENT);
	id = &vcpu->nested_l0_continuation.id;
	if (!vcpu->nested_l2_portable_valid ||
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_COLD ||
	    vcpu->nested.phase != VMX_NESTED_CONTEXT_GUEST ||
	    !vmx_nested_vmcs02_id_equal(id,
	    &vcpu->nested_entry_runtime.id) ||
	    !vmx_nested_vmcs02_id_equal(id, &vcpu->nested_l2_portable.id))
		return (EPROTO);
	*state = &vcpu->nested_l2_portable;
	return (0);
}

static int
vmx_nested_apic_priority_shared_get(void *arg, uint64_t *value)
{
	struct vmx_vcpu *vcpu;

	vcpu = arg;
	if (vcpu == NULL || value == NULL)
		return (EINVAL);
	*value = vlapic_get_cr8(vm_lapic(vcpu->vcpu));
	return (0);
}

static int
vmx_nested_apic_priority_shared_set(void *arg, uint64_t value)
{
	struct vmx_vcpu *vcpu;

	vcpu = arg;
	if (vcpu == NULL || value > 15)
		return (EINVAL);
	vlapic_set_cr8(vm_lapic(vcpu->vcpu), value);
	return (0);
}

static const struct vmx_nested_apic_priority_ops
vmx_nested_apic_priority_intel_ops = {
	.shared_get = vmx_nested_apic_priority_shared_get,
	.shared_set = vmx_nested_apic_priority_shared_set,
};

static int
vmx_nested_cold_l2_tpr_get(struct vmx_vcpu *vcpu, uint64_t *value)
{
	struct vmx_nested_guest_memory_intel runtime;
	const struct vmx_nested_entry_controls *entry;
	const struct vmx_nested_memory *memory;
	int error;

	if (!vcpu->nested_vmcs02_plan_valid ||
	    !vmx_nested_vmcs02_id_equal(&vcpu->nested_vmcs02_plan.id,
	    &vcpu->nested_l0_continuation.id))
		return (EPROTO);
	entry = &vcpu->nested_vmcs12_snapshot.controls;
	memory = NULL;
	if ((vcpu->nested_vmcs02_plan.image.controls.primary &
	    PROCBASED_USE_TPR_SHADOW) != 0) {
		error = vmx_nested_guest_memory_intel_init(&runtime,
		    vcpu->vcpu);
		if (error != 0)
			return (error);
		memory = vmx_nested_guest_memory_intel_memory(&runtime);
		if (memory == NULL)
			return (EPROTO);
	}
	return (vmx_nested_apic_priority_get(
	    vcpu->nested_vmcs02_plan.image.controls.primary,
	    entry->virtual_apic, memory,
	    &vmx_nested_apic_priority_intel_ops, vcpu, value));
}

static int
vmx_nested_cold_l2_tpr_set(struct vmx_vcpu *vcpu, uint64_t value)
{
	struct vmx_nested_guest_memory_intel runtime;
	const struct vmx_nested_entry_controls *entry;
	const struct vmx_nested_memory *memory;
	int error;

	if (!vcpu->nested_vmcs02_plan_valid ||
	    !vmx_nested_vmcs02_id_equal(&vcpu->nested_vmcs02_plan.id,
	    &vcpu->nested_l0_continuation.id))
		return (EPROTO);
	entry = &vcpu->nested_vmcs12_snapshot.controls;
	memory = NULL;
	if ((vcpu->nested_vmcs02_plan.image.controls.primary &
	    PROCBASED_USE_TPR_SHADOW) != 0) {
		error = vmx_nested_guest_memory_intel_init(&runtime,
		    vcpu->vcpu);
		if (error != 0)
			return (error);
		memory = vmx_nested_guest_memory_intel_memory(&runtime);
		if (memory == NULL)
			return (EPROTO);
	}
	return (vmx_nested_apic_priority_set(
	    vcpu->nested_vmcs02_plan.image.controls.primary,
	    entry->virtual_apic, memory,
	    &vmx_nested_apic_priority_intel_ops, vcpu, value));
}

static int
vmx_getreg(void *vcpui, int reg, uint64_t *retval)
{
	struct vmx_nested_l2_portable_state *l2;
	int running, hostcpu;
	int error;
	struct vmx_vcpu *vcpu = vcpui;
	struct vmx *vmx = vcpu->vmx;

	running = vcpu_is_running(vcpu->vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("vmx_getreg: %s%d is running", vm_name(vmx->vm),
		    vcpu->vcpuid);

	if (vmxctx_getreg(&vcpu->ctx, reg, retval) == 0)
		return (0);
	error = vmx_nested_cold_l2(vcpu, &l2);
	if (error == 0) {
		if (reg == VM_REG_GUEST_TPR)
			return (vmx_nested_cold_l2_tpr_get(vcpu, retval));
		if (reg == VM_REG_GUEST_INTR_SHADOW) {
			*retval = (l2->runtime.arch.interruptibility &
			    HWINTR_BLOCKING) != 0;
			return (0);
		}
		error = vmx_nested_l2_intel_getreg(l2, reg, retval);
		if (error != ENOENT)
			return (error);
		/*
		 * Never fall through to VMCS01 while the architectural owner
		 * is cold L2.  A missing mapping is an incomplete adapter, not
		 * permission to expose L1 state.
		 */
		return (EOPNOTSUPP);
	} else if (error != ENOENT)
		return (error);
	switch (reg) {
	case VM_REG_GUEST_INTR_SHADOW:
		return (vmx_get_intr_shadow(vcpu, running, retval));
	case VM_REG_GUEST_KGS_BASE:
		*retval = vcpu->guest_msrs[IDX_MSR_KGSBASE];
		return (0);
	case VM_REG_GUEST_TPR:
		*retval = vlapic_get_cr8(vm_lapic(vcpu->vcpu));
		return (0);
	}

	return (vmcs_getreg(vcpu->vmcs, running, reg, retval));
}

static int
vmx_setreg(void *vcpui, int reg, uint64_t val)
{
	struct vmx_nested_l2_portable_state *l2;
	int error, hostcpu, running, shadow;
	uint64_t ctls;
	pmap_t pmap;
	struct vmx_vcpu *vcpu = vcpui;
	struct vmx *vmx = vcpu->vmx;

	running = vcpu_is_running(vcpu->vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("vmx_setreg: %s%d is running", vm_name(vmx->vm),
		    vcpu->vcpuid);

	if (vmxctx_setreg(&vcpu->ctx, reg, val) == 0)
		return (0);
	error = vmx_nested_cold_l2(vcpu, &l2);
	if (error == 0) {
		if (reg == VM_REG_GUEST_TPR)
			return (vmx_nested_cold_l2_tpr_set(vcpu, val));
		if (reg == VM_REG_GUEST_INTR_SHADOW) {
			if (val != 0)
				return (EINVAL);
			l2->runtime.arch.interruptibility &= ~HWINTR_BLOCKING;
			return (0);
		}
		error = vmx_nested_l2_intel_setreg(l2, reg, val);
		if (error != ENOENT)
			return (error);
		return (EOPNOTSUPP);
	} else if (error != ENOENT)
		return (error);

	if (reg == VM_REG_GUEST_INTR_SHADOW)
		return (vmx_modify_intr_shadow(vcpu, running, val));

	/* Do not permit user write access to VMCS fields by offset. */
	if (reg < 0)
		return (EINVAL);

	error = vmcs_setreg(vcpu->vmcs, running, reg, val);

	if (error == 0) {
		/*
		 * If the "load EFER" VM-entry control is 1 then the
		 * value of EFER.LMA must be identical to "IA-32e mode guest"
		 * bit in the VM-entry control.
		 */
		if ((entry_ctls & VM_ENTRY_LOAD_EFER) != 0 &&
		    (reg == VM_REG_GUEST_EFER)) {
			vmcs_getreg(vcpu->vmcs, running,
				    VMCS_IDENT(VMCS_ENTRY_CTLS), &ctls);
			if (val & EFER_LMA)
				ctls |= VM_ENTRY_GUEST_LMA;
			else
				ctls &= ~VM_ENTRY_GUEST_LMA;
			vmcs_setreg(vcpu->vmcs, running,
				    VMCS_IDENT(VMCS_ENTRY_CTLS), ctls);
		}

		shadow = vmx_shadow_reg(reg);
		if (shadow > 0) {
			/*
			 * Store the unmodified value in the shadow
			 */
			error = vmcs_setreg(vcpu->vmcs, running,
				    VMCS_IDENT(shadow), val);
		}

		if (reg == VM_REG_GUEST_CR3) {
			/*
			 * Invalidate the guest vcpu's TLB mappings to emulate
			 * the behavior of updating %cr3.
			 *
			 * XXX the processor retains global mappings when %cr3
			 * is updated but vmx_invvpid() does not.
			 */
			pmap = vcpu->ctx.pmap;
			vmx_invvpid(vmx, vcpu, pmap, running);
		}
	}

	return (error);
}

static int
vmx_getdesc(void *vcpui, int reg, struct seg_desc *desc)
{
	struct vmx_nested_l2_portable_state *l2;
	int hostcpu, running;
	int error;
	struct vmx_vcpu *vcpu = vcpui;
	struct vmx *vmx = vcpu->vmx;

	running = vcpu_is_running(vcpu->vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("vmx_getdesc: %s%d is running", vm_name(vmx->vm),
		    vcpu->vcpuid);

	error = vmx_nested_cold_l2(vcpu, &l2);
	if (error == 0) {
		error = vmx_nested_l2_intel_getdesc(l2, reg, desc);
		return (error == ENOENT ? EOPNOTSUPP : error);
	} else if (error != ENOENT)
		return (error);
	return (vmcs_getdesc(vcpu->vmcs, running, reg, desc));
}

static int
vmx_setdesc(void *vcpui, int reg, struct seg_desc *desc)
{
	struct vmx_nested_l2_portable_state *l2;
	int hostcpu, running;
	int error;
	struct vmx_vcpu *vcpu = vcpui;
	struct vmx *vmx = vcpu->vmx;

	running = vcpu_is_running(vcpu->vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("vmx_setdesc: %s%d is running", vm_name(vmx->vm),
		    vcpu->vcpuid);

	error = vmx_nested_cold_l2(vcpu, &l2);
	if (error == 0) {
		error = vmx_nested_l2_intel_setdesc(l2, reg, desc);
		return (error == ENOENT ? EOPNOTSUPP : error);
	} else if (error != ENOENT)
		return (error);
	return (vmcs_setdesc(vcpu->vmcs, running, reg, desc));
}

static int
vmx_getcap(void *vcpui, int type, int *retval)
{
	struct vmx_vcpu *vcpu = vcpui;
	int vcap;
	int ret;

	ret = ENOENT;

	vcap = vcpu->cap.set;

	switch (type) {
	case VM_CAP_HALT_EXIT:
		if (cap_halt_exit)
			ret = 0;
		break;
	case VM_CAP_PAUSE_EXIT:
		if (cap_pause_exit)
			ret = 0;
		break;
	case VM_CAP_MTRAP_EXIT:
		if (cap_monitor_trap)
			ret = 0;
		break;
	case VM_CAP_RDPID:
		if (cap_rdpid)
			ret = 0;
		break;
	case VM_CAP_RDTSCP:
		if (cap_rdtscp)
			ret = 0;
		break;
	case VM_CAP_UNRESTRICTED_GUEST:
		if (cap_unrestricted_guest)
			ret = 0;
		break;
	case VM_CAP_ENABLE_INVPCID:
		if (cap_invpcid)
			ret = 0;
		break;
	case VM_CAP_BPT_EXIT:
	case VM_CAP_IPI_EXIT:
		ret = 0;
		break;
	case VM_CAP_NESTED_VMX:
		if (vmx_nested_guest_exposure_validate() == 0) {
			ret = 0;
			*retval = vmx_nested_guest_enabled(vcpu->vmx) ? 1 : 0;
			return (ret);
		}
		break;
	default:
		break;
	}

	if (ret == 0)
		*retval = (vcap & (1 << type)) ? 1 : 0;

	return (ret);
}

static int
vmx_setcap(void *vcpui, int type, int val)
{
	struct vmx_vcpu *vcpu = vcpui;
	struct vmcs *vmcs = vcpu->vmcs;
	struct vlapic *vlapic;
	uint32_t baseval;
	uint32_t *pptr;
	int error;
	int flag;
	int reg;
	int retval;

	retval = ENOENT;
	pptr = NULL;

	switch (type) {
	case VM_CAP_HALT_EXIT:
		if (cap_halt_exit) {
			retval = 0;
			pptr = &vcpu->cap.proc_ctls;
			baseval = *pptr;
			flag = PROCBASED_HLT_EXITING;
			reg = VMCS_PRI_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_MTRAP_EXIT:
		if (cap_monitor_trap) {
			retval = 0;
			pptr = &vcpu->cap.proc_ctls;
			baseval = *pptr;
			flag = PROCBASED_MTF;
			reg = VMCS_PRI_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_PAUSE_EXIT:
		if (cap_pause_exit) {
			retval = 0;
			pptr = &vcpu->cap.proc_ctls;
			baseval = *pptr;
			flag = PROCBASED_PAUSE_EXITING;
			reg = VMCS_PRI_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_RDPID:
	case VM_CAP_RDTSCP:
		if (cap_rdpid || cap_rdtscp)
			/*
			 * Choose not to support enabling/disabling
			 * RDPID/RDTSCP via libvmmapi since, as per the
			 * discussion in vmx_modinit(), RDPID/RDTSCP are
			 * either always enabled or always disabled.
			 */
			retval = EOPNOTSUPP;
		break;
	case VM_CAP_UNRESTRICTED_GUEST:
		if (cap_unrestricted_guest) {
			retval = 0;
			pptr = &vcpu->cap.proc_ctls2;
			baseval = *pptr;
			flag = PROCBASED2_UNRESTRICTED_GUEST;
			reg = VMCS_SEC_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_ENABLE_INVPCID:
		if (cap_invpcid) {
			retval = 0;
			pptr = &vcpu->cap.proc_ctls2;
			baseval = *pptr;
			flag = PROCBASED2_ENABLE_INVPCID;
			reg = VMCS_SEC_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_BPT_EXIT:
		retval = 0;

		/* Don't change the bitmap if we are tracing all exceptions. */
		if (vcpu->cap.exc_bitmap != 0xffffffff) {
			pptr = &vcpu->cap.exc_bitmap;
			baseval = *pptr;
			flag = (1 << IDT_BP);
			reg = VMCS_EXCEPTION_BITMAP;
		}
		break;
	case VM_CAP_IPI_EXIT:
		retval = 0;

		vlapic = vm_lapic(vcpu->vcpu);
		vlapic->ipi_exit = val;
		break;
	case VM_CAP_NESTED_VMX:
		/*
		 * This is a private VM-wide CPU-model switch, not a bitmask.
		 * Reject noncanonical values before inspecting or changing any
		 * per-vCPU or VM-wide nested state so future extensions cannot be
		 * accidentally interpreted as "enabled" by an older kernel.
		 */
		if (val != 0 && val != 1)
			return (EINVAL);
		if (vcpu->nested.phase != VMX_NESTED_CONTEXT_ROOT ||
		    vcpu->nested.machine.vmxon ||
		    (!val && (vcpu->nested_control_msrs.feature_control &
		    VMX_NESTED_FEATURE_CONTROL_LOCK) != 0)) {
			retval = EBUSY;
			break;
		}
		return (vmx_nested_guest_configure(vcpu->vmx, val == 1));
	case VM_CAP_MASK_HWINTR:
		retval = 0;
		break;
	default:
		break;
	}

	if (retval)
		return (retval);

	if (pptr != NULL) {
		if (val) {
			baseval |= flag;
		} else {
			baseval &= ~flag;
		}
		VMPTRLD(vmcs);
		error = vmwrite(reg, baseval);
		VMCLEAR(vmcs);

		if (error)
			return (error);

		/*
		 * Update optional stored flags, and record
		 * setting
		 */
		*pptr = baseval;
	}

	if (val) {
		vcpu->cap.set |= (1 << type);
	} else {
		vcpu->cap.set &= ~(1 << type);
	}

	return (0);
}

static int
vmx_get_cpu_compat(void *vcpui, struct vm_cpu_compat *compat)
{
	struct vmx_vcpu *vcpu;
	int error;

	vcpu = vcpui;
	if (vcpu == NULL || compat == NULL)
		return (EINVAL);
	if (!vmx_nested_guest_enabled(vcpu->vmx))
		return (0);
	error = vmx_nested_capabilities_signature(
	    &vmx_nested_virtual_capabilities,
	    &compat->nested_capability_signature);
	if (error != 0)
		return (error);
	compat->nested_schema_signature = vmx_nested_vmcs_schema_signature();
	compat->flags |= VM_CPU_COMPAT_F_NESTED_VMX;
	return (0);
}

static struct vmspace *
vmx_vmspace_alloc(vm_offset_t min, vm_offset_t max)
{
	return (ept_vmspace_alloc(min, max));
}

static void
vmx_vmspace_free(struct vmspace *vmspace)
{
	ept_vmspace_free(vmspace);
}

struct vlapic_vtx {
	struct vlapic	vlapic;
	struct pir_desc	*pir_desc;
	struct vmx_vcpu	*vcpu;
	u_int	pending_prio;
};

#define VPR_PRIO_BIT(vpr)	(1 << ((vpr) >> 4))

#define	VMX_CTR_PIR(vlapic, pir_desc, notify, vector, level, msg)	\
do {									\
	VLAPIC_CTR2(vlapic, msg " assert %s-triggered vector %d",	\
	    level ? "level" : "edge", vector);				\
	VLAPIC_CTR1(vlapic, msg " pir0 0x%016lx", pir_desc->pir[0]);	\
	VLAPIC_CTR1(vlapic, msg " pir1 0x%016lx", pir_desc->pir[1]);	\
	VLAPIC_CTR1(vlapic, msg " pir2 0x%016lx", pir_desc->pir[2]);	\
	VLAPIC_CTR1(vlapic, msg " pir3 0x%016lx", pir_desc->pir[3]);	\
	VLAPIC_CTR1(vlapic, msg " notify: %s", notify ? "yes" : "no");	\
} while (0)

/*
 * vlapic->ops handlers that utilize the APICv hardware assist described in
 * Chapter 29 of the Intel SDM.
 */
static int
vmx_set_intr_ready(struct vlapic *vlapic, int vector, bool level)
{
	struct vlapic_vtx *vlapic_vtx;
	struct pir_desc *pir_desc;
	uint64_t mask;
	int idx, notify = 0;

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	pir_desc = vlapic_vtx->pir_desc;

	/*
	 * Keep track of interrupt requests in the PIR descriptor. This is
	 * because the virtual APIC page pointed to by the VMCS cannot be
	 * modified if the vcpu is running.
	 */
	idx = vector / 64;
	mask = 1UL << (vector % 64);
	atomic_set_long(&pir_desc->pir[idx], mask);

	/*
	 * A notification is required whenever the 'pending' bit makes a
	 * transition from 0->1.
	 *
	 * Even if the 'pending' bit is already asserted, notification about
	 * the incoming interrupt may still be necessary.  For example, if a
	 * vCPU is HLTed with a high PPR, a low priority interrupt would cause
	 * the 0->1 'pending' transition with a notification, but the vCPU
	 * would ignore the interrupt for the time being.  The same vCPU would
	 * need to then be notified if a high-priority interrupt arrived which
	 * satisfied the PPR.
	 *
	 * The priorities of interrupts injected while 'pending' is asserted
	 * are tracked in a custom bitfield 'pending_prio'.  Should the
	 * to-be-injected interrupt exceed the priorities already present, the
	 * notification is sent.  The priorities recorded in 'pending_prio' are
	 * cleared whenever the 'pending' bit makes another 0->1 transition.
	 */
	if (atomic_cmpset_long(&pir_desc->pending, 0, 1) != 0) {
		notify = 1;
		vlapic_vtx->pending_prio = 0;
	} else {
		const u_int old_prio = vlapic_vtx->pending_prio;
		const u_int prio_bit = VPR_PRIO_BIT(vector & APIC_TPR_INT);

		if ((old_prio & prio_bit) == 0 && prio_bit > old_prio) {
			atomic_set_int(&vlapic_vtx->pending_prio, prio_bit);
			notify = 1;
		}
	}

	VMX_CTR_PIR(vlapic, pir_desc, notify, vector, level,
	    "vmx_set_intr_ready");
	return (notify);
}

static int
vmx_pending_intr(struct vlapic *vlapic, int *vecptr)
{
	struct vlapic_vtx *vlapic_vtx;
	struct pir_desc *pir_desc;
	struct LAPIC *lapic;
	uint64_t pending, pirval;
	uint8_t ppr, vpr, rvi;
	struct vm_exit *vmexit;
	int i;

	/*
	 * This function is only expected to be called from the 'HLT' exit
	 * handler which does not care about the vector that is pending.
	 */
	KASSERT(vecptr == NULL, ("vmx_pending_intr: vecptr must be NULL"));

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	pir_desc = vlapic_vtx->pir_desc;
	lapic = vlapic->apic_page;

	/*
	 * While a virtual interrupt may have already been
	 * processed the actual delivery maybe pending the
	 * interruptibility of the guest.  Recognize a pending
	 * interrupt by reevaluating virtual interrupts
	 * following Section 30.2.1 in the Intel SDM Volume 3.
	 */
	vmexit = vm_exitinfo(vlapic->vcpu);
	KASSERT(vmexit->exitcode == VM_EXITCODE_HLT,
	    ("vmx_pending_intr: exitcode not 'HLT'"));
	rvi = vmexit->u.hlt.intr_status & APIC_TPR_INT;
	ppr = lapic->ppr & APIC_TPR_INT;
	if (rvi > ppr)
		return (1);

	pending = atomic_load_acq_long(&pir_desc->pending);
	if (!pending)
		return (0);

	/*
	 * If there is an interrupt pending then it will be recognized only
	 * if its priority is greater than the processor priority.
	 *
	 * Special case: if the processor priority is zero then any pending
	 * interrupt will be recognized.
	 */
	if (ppr == 0)
		return (1);

	VLAPIC_CTR1(vlapic, "HLT with non-zero PPR %d", lapic->ppr);

	vpr = 0;
	for (i = 3; i >= 0; i--) {
		pirval = pir_desc->pir[i];
		if (pirval != 0) {
			vpr = (i * 64 + flsl(pirval) - 1) & APIC_TPR_INT;
			break;
		}
	}

	/*
	 * If the highest-priority pending interrupt falls short of the
	 * processor priority of this vCPU, ensure that 'pending_prio' does not
	 * have any stale bits which would preclude a higher-priority interrupt
	 * from incurring a notification later.
	 */
	if (vpr <= ppr) {
		const u_int prio_bit = VPR_PRIO_BIT(vpr);
		const u_int old = vlapic_vtx->pending_prio;

		if (old > prio_bit && (old & prio_bit) == 0) {
			vlapic_vtx->pending_prio = prio_bit;
		}
		return (0);
	}
	return (1);
}

static void
vmx_intr_accepted(struct vlapic *vlapic, int vector)
{

	panic("vmx_intr_accepted: not expected to be called");
}

static void
vmx_set_tmr(struct vlapic *vlapic, int vector, bool level)
{
	struct vlapic_vtx *vlapic_vtx;
	struct vmcs *vmcs;
	uint64_t mask, val;

	KASSERT(vector >= 0 && vector <= 255, ("invalid vector %d", vector));
	KASSERT(!vcpu_is_running(vlapic->vcpu, NULL),
	    ("vmx_set_tmr: vcpu cannot be running"));

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	vmcs = vlapic_vtx->vcpu->vmcs;
	mask = 1UL << (vector % 64);

	VMPTRLD(vmcs);
	val = vmcs_read(VMCS_EOI_EXIT(vector));
	if (level)
		val |= mask;
	else
		val &= ~mask;
	vmcs_write(VMCS_EOI_EXIT(vector), val);
	VMCLEAR(vmcs);
}

static void
vmx_enable_x2apic_mode_ts(struct vlapic *vlapic)
{
	struct vlapic_vtx *vlapic_vtx;
	struct vmx_vcpu *vcpu;
	struct vmcs *vmcs;
	uint32_t proc_ctls;

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	vcpu = vlapic_vtx->vcpu;
	vmcs = vcpu->vmcs;

	proc_ctls = vcpu->cap.proc_ctls;
	proc_ctls &= ~PROCBASED_USE_TPR_SHADOW;
	proc_ctls |= PROCBASED_CR8_LOAD_EXITING;
	proc_ctls |= PROCBASED_CR8_STORE_EXITING;
	vcpu->cap.proc_ctls = proc_ctls;

	VMPTRLD(vmcs);
	vmcs_write(VMCS_PRI_PROC_BASED_CTLS, proc_ctls);
	VMCLEAR(vmcs);
}

static void
vmx_enable_x2apic_mode_vid(struct vlapic *vlapic)
{
	struct vlapic_vtx *vlapic_vtx;
	struct vmx *vmx;
	struct vmx_vcpu *vcpu;
	struct vmcs *vmcs;
	uint32_t proc_ctls2;
	int error __diagused;

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	vcpu = vlapic_vtx->vcpu;
	vmx = vcpu->vmx;
	vmcs = vcpu->vmcs;

	proc_ctls2 = vcpu->cap.proc_ctls2;
	KASSERT((proc_ctls2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES) != 0,
	    ("%s: invalid proc_ctls2 %#x", __func__, proc_ctls2));

	proc_ctls2 &= ~PROCBASED2_VIRTUALIZE_APIC_ACCESSES;
	proc_ctls2 |= PROCBASED2_VIRTUALIZE_X2APIC_MODE;
	vcpu->cap.proc_ctls2 = proc_ctls2;

	VMPTRLD(vmcs);
	vmcs_write(VMCS_SEC_PROC_BASED_CTLS, proc_ctls2);
	VMCLEAR(vmcs);

	if (vlapic->vcpuid == 0) {
		/*
		 * The nested page table mappings are shared by all vcpus
		 * so unmap the APIC access page just once.
		 */
		error = vm_unmap_mmio(vmx->vm, DEFAULT_APIC_BASE, PAGE_SIZE);
		if (error != 0)
			panic("%s: cannot unmap APIC-access page: %d",
			    __func__, error);

		/*
		 * The MSR bitmap is shared by all vcpus so modify it only
		 * once in the context of vcpu 0.
		 */
		error = vmx_allow_x2apic_msrs(vmx);
		if (error != 0)
			panic("%s: cannot update x2APIC MSR bitmap: %d",
			    __func__, error);
	}
}

static void
vmx_post_intr(struct vlapic *vlapic, int hostcpu)
{

	ipi_cpu(hostcpu, pirvec);
}

/*
 * Transfer the pending interrupts in the PIR descriptor to the IRR
 * in the virtual APIC page.
 */
static void
vmx_inject_pir(struct vlapic *vlapic)
{
	struct vlapic_vtx *vlapic_vtx;
	struct pir_desc *pir_desc;
	struct LAPIC *lapic;
	uint64_t val, pirval;
	int rvi, pirbase = -1;
	uint16_t intr_status_old, intr_status_new;

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	pir_desc = vlapic_vtx->pir_desc;
	if (atomic_cmpset_long(&pir_desc->pending, 1, 0) == 0) {
		VLAPIC_CTR0(vlapic, "vmx_inject_pir: "
		    "no posted interrupt pending");
		return;
	}

	pirval = 0;
	pirbase = -1;
	lapic = vlapic->apic_page;

	val = atomic_readandclear_long(&pir_desc->pir[0]);
	if (val != 0) {
		lapic->irr0 |= val;
		lapic->irr1 |= val >> 32;
		pirbase = 0;
		pirval = val;
	}

	val = atomic_readandclear_long(&pir_desc->pir[1]);
	if (val != 0) {
		lapic->irr2 |= val;
		lapic->irr3 |= val >> 32;
		pirbase = 64;
		pirval = val;
	}

	val = atomic_readandclear_long(&pir_desc->pir[2]);
	if (val != 0) {
		lapic->irr4 |= val;
		lapic->irr5 |= val >> 32;
		pirbase = 128;
		pirval = val;
	}

	val = atomic_readandclear_long(&pir_desc->pir[3]);
	if (val != 0) {
		lapic->irr6 |= val;
		lapic->irr7 |= val >> 32;
		pirbase = 192;
		pirval = val;
	}

	VLAPIC_CTR_IRR(vlapic, "vmx_inject_pir");

	/*
	 * Update RVI so the processor can evaluate pending virtual
	 * interrupts on VM-entry.
	 *
	 * It is possible for pirval to be 0 here, even though the
	 * pending bit has been set. The scenario is:
	 * CPU-Y is sending a posted interrupt to CPU-X, which
	 * is running a guest and processing posted interrupts in h/w.
	 * CPU-X will eventually exit and the state seen in s/w is
	 * the pending bit set, but no PIR bits set.
	 *
	 *      CPU-X                      CPU-Y
	 *   (vm running)                (host running)
	 *   rx posted interrupt
	 *   CLEAR pending bit
	 *				 SET PIR bit
	 *   READ/CLEAR PIR bits
	 *				 SET pending bit
	 *   (vm exit)
	 *   pending bit set, PIR 0
	 */
	if (pirval != 0) {
		rvi = pirbase + flsl(pirval) - 1;
		intr_status_old = vmcs_read(VMCS_GUEST_INTR_STATUS);
		intr_status_new = (intr_status_old & 0xFF00) | rvi;
		if (intr_status_new > intr_status_old) {
			vmcs_write(VMCS_GUEST_INTR_STATUS, intr_status_new);
			VLAPIC_CTR2(vlapic, "vmx_inject_pir: "
			    "guest_intr_status changed from 0x%04x to 0x%04x",
			    intr_status_old, intr_status_new);
		}
	}
}

static struct vlapic *
vmx_vlapic_init(void *vcpui)
{
	struct vmx *vmx;
	struct vmx_vcpu *vcpu;
	struct vlapic *vlapic;
	struct vlapic_vtx *vlapic_vtx;

	vcpu = vcpui;
	vmx = vcpu->vmx;

	vlapic = malloc(sizeof(struct vlapic_vtx), M_VLAPIC, M_WAITOK | M_ZERO);
	vlapic->vm = vmx->vm;
	vlapic->vcpu = vcpu->vcpu;
	vlapic->vcpuid = vcpu->vcpuid;
	vlapic->apic_page = (struct LAPIC *)vcpu->apic_page;

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	vlapic_vtx->pir_desc = vcpu->pir_desc;
	vlapic_vtx->vcpu = vcpu;

	if (tpr_shadowing) {
		vlapic->ops.enable_x2apic_mode = vmx_enable_x2apic_mode_ts;
	}

	if (virtual_interrupt_delivery) {
		vlapic->ops.set_intr_ready = vmx_set_intr_ready;
		vlapic->ops.pending_intr = vmx_pending_intr;
		vlapic->ops.intr_accepted = vmx_intr_accepted;
		vlapic->ops.set_tmr = vmx_set_tmr;
		vlapic->ops.enable_x2apic_mode = vmx_enable_x2apic_mode_vid;
	}

	if (posted_interrupts)
		vlapic->ops.post_intr = vmx_post_intr;

	vlapic_init(vlapic);

	return (vlapic);
}

static void
vmx_vlapic_cleanup(struct vlapic *vlapic)
{

	vlapic_cleanup(vlapic);
	free(vlapic, M_VLAPIC);
}

#ifdef BHYVE_SNAPSHOT
/*
 * The VMCS is processor-managed state.  Snapshot records therefore retain an
 * explicit, portable image of the fields this format owns rather than copying
 * the VMCS backing page.
 */
struct vmx_snapshot_vmcs_state {
	uint64_t regs[20];
	struct seg_desc descs[10];
	uint64_t any[7];
};

/* Unpublished ordinary architectural state for one frozen restore vCPU. */
struct vmx_snapshot_arch_vcpu_stage {
	struct vmx_vcpu *vcpu;
	struct vmcs *vmcs;
	struct vmx_snapshot_vmcs_state candidate_vmcs;
	struct vmx_snapshot_vmcs_state rollback_vmcs;
	struct vmxctx ctx;
	struct vm_mtrr mtrr;
	struct pir_desc pir_desc;
	uint64_t guest_msrs[GUEST_MSR_NUM];
	int running;
	bool vmcs_applied;
	bool valid;
};

/* These helpers are used by the restore commit transaction below. */
static int vmx_snapshot_vmcs_state_apply(struct vmcs *vmcs, int running,
    const struct vmx_snapshot_vmcs_state *state);
static void vmx_snapshot_arch_vcpu_publish(
    const struct vmx_snapshot_arch_vcpu_stage *stage);

static bool
vmx_snapshot_pir_desc_valid(const struct pir_desc *pir_desc)
{

	return (pir_desc != NULL && pir_desc->pending <= 1 &&
	    pir_desc->unused[0] == 0 && pir_desc->unused[1] == 0 &&
	    pir_desc->unused[2] == 0);
}

static void
vmx_nested_snapshot_restore_free(struct vmx_nested_snapshot_restore *stage)
{
	int error;

	if (stage == NULL)
		return;
	if (stage->registry_initialized) {
		error = vmx_nested_vmcs_registry_destroy(&stage->registry);
		if (error != 0)
			panic("%s: staged VMCS registry destroy failed: %d",
			    __func__, error);
	}
	if (stage->vcpus != NULL) {
		for (uint16_t i = 0; i < stage->maxcpus; i++) {
			if (stage->vcpus[i].msr_workspace_staged) {
				size_t storage_bytes;

				storage_bytes = (size_t)stage->vcpus[i].msr_workspace.capacity *
				    2 * sizeof(*stage->vcpus[i].msr_storage);
				error = vmx_nested_msr_workspace_unbind(
				    &stage->vcpus[i].msr_workspace);
				if (error != 0)
					panic("%s: staged nested MSR workspace release failed: %d",
					    __func__, error);
				explicit_bzero(stage->vcpus[i].msr_storage,
				    storage_bytes);
				free(stage->vcpus[i].msr_storage, M_VMX);
			}
			if (!stage->vcpus[i].vpid_staged)
				continue;
			error = vmx_nested_vpid_owner_release(
			    &stage->vcpus[i].vpid_owner,
			    &vmx_nested_vpid_ops, NULL);
			if (error != 0)
				panic("%s: staged nested VPID release failed: %d",
				    __func__, error);
		}
		explicit_bzero(stage->vcpus,
		    (size_t)stage->maxcpus * sizeof(*stage->vcpus));
		free(stage->vcpus, M_VMX);
	}
	if (stage->arch_vcpus != NULL) {
		explicit_bzero(stage->arch_vcpus,
		    (size_t)stage->maxcpus * sizeof(*stage->arch_vcpus));
		free(stage->arch_vcpus, M_VMX);
	}
	explicit_bzero(stage, sizeof(*stage));
	free(stage, M_VMX);
}

/*
 * Prove that replacing the VM-wide registry and per-vCPU architectural image
 * cannot strand destination-only runtime ownership.  A frozen vCPU may still
 * have a quiescent L1 VMX context, which the restore intentionally replaces,
 * and the EPT cache may retain unreferenced roots.  Every active callback,
 * reference, hardware transaction, staged handoff, or scratch owner must be
 * absent before publication begins.  Unreferenced EPT roots pass this
 * validation but are discarded in a separate all-vCPU phase: their shadow
 * translations were derived from the pre-restore guest-memory image.
 */
static int
vmx_nested_snapshot_destination_validate(struct vmx_vcpu *vcpu)
{
	int error;

	if (vcpu == NULL || vcpu->vcpu == NULL)
		return (EINVAL);
	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	error = vmx_nested_prepared_owner_validate(vcpu);
	if (error != 0)
		return (error);
	error = vmx_nested_restore_destination_validate(
	    &vcpu->nested_l0_continuation, &vcpu->nested_entry_runtime,
	    &vcpu->nested_msr_workspace, vcpu->nested_vmcs02_plan_valid,
	    vcpu->nested_l2_portable_valid);
	if (error != 0)
		return (error);
	error = vmx_nested_context_quiesce(&vcpu->nested);
	if (error != 0)
		return (error);
	error = vmx_nested_startup_dispatch_validate(
	    &vcpu->nested_startup_dispatch);
	if (error != 0)
		return (error);
	if (vcpu->nested_startup_dispatch.state !=
	    VMX_NESTED_STARTUP_DISPATCH_EMPTY)
		return (EBUSY);
	if (vcpu->nested_l2_thaw_staged.state <
	    VMX_NESTED_L2_THAW_STAGED_IDLE ||
	    vcpu->nested_l2_thaw_staged.state >
	    VMX_NESTED_L2_THAW_STAGED_POISONED ||
	    vcpu->nested_refreeze_staged.state < VMX_NESTED_REFREEZE_IDLE ||
	    vcpu->nested_refreeze_staged.state > VMX_NESTED_REFREEZE_POISONED)
		return (EPROTO);
	if (vcpu->nested_l2_thaw_staged.state !=
	    VMX_NESTED_L2_THAW_STAGED_IDLE ||
	    vcpu->nested_thaw_resources_valid ||
	    vcpu->nested_refreeze_staged.state != VMX_NESTED_REFREEZE_IDLE ||
	    vcpu->nested_hot_failure_detached)
		return (EBUSY);
	error = vmx_nested_ept_binding_validate(&vcpu->nested_ept_binding);
	if (error != 0)
		return (error);
	if (vcpu->nested_ept_binding.active)
		return (EBUSY);
	error = vmx_nested_ept_cache_owner_quiesce(vcpu);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs02_intel_inactive_validate(
	    &vcpu->nested_vmcs02_intel);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs02_lease_owner_validate(
	    &vcpu->nested_vmcs02_leases);
	if (error != 0)
		return (error);
	if (vcpu->nested_vmcs02_leases.active ||
	    vcpu->nested_vmcs02_leases.callback_active ||
	    vcpu->nested_vmcs02_leases.count != 0)
		return (EBUSY);
	error = vmx_nested_vpid_restore_destination_validate(
	    &vcpu->nested_vpid_owner);
	if (error != 0)
		return (error);
	error = vmx_nested_mtf_owner_validate(&vcpu->nested_mtf_owner);
	if (error != 0)
		return (error);
	if (vcpu->nested_mtf_owner.pending)
		return (EBUSY);
	error = vmx_nested_exit_msr_transaction_validate(
	    &vcpu->nested_exit_msr_transaction);
	if (error != 0)
		return (error);
	if (vcpu->nested_exit_msr_transaction.state !=
	    VMX_NESTED_EXIT_MSR_TRANSACTION_IDLE ||
	    vcpu->nested_exit_msr_plan_valid ||
	    vcpu->nested_failed_entry_msr_plan_valid ||
	    vcpu->nested_msr_generation != 0 ||
	    vcpu->nested_entry_msr_count != 0)
		return (EBUSY);
	if (vcpu->nested_hardware_msr_transition <
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_transition >
	    VMX_NESTED_HARDWARE_MSR_EXIT ||
	    vcpu->nested_tsc_aux_residency < VMX_NESTED_TSC_AUX_L1 ||
	    vcpu->nested_tsc_aux_residency > VMX_NESTED_TSC_AUX_L2_PAUSED ||
	    vcpu->nested_tsc_aux_rollback_residency <
	    VMX_NESTED_TSC_AUX_L1 ||
	    vcpu->nested_tsc_aux_rollback_residency >
	    VMX_NESTED_TSC_AUX_L2_PAUSED)
		return (EPROTO);
	if (vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_count != 0 ||
	    vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1 ||
	    vcpu->nested_tsc_aux_rollback_residency !=
	    VMX_NESTED_TSC_AUX_L1)
		return (EBUSY);
	return (0);
}

/*
 * Validate runtime-only source ownership before the ordinary VMCS snapshot
 * writes its first byte.  Active L2 is legal only in the already-detached
 * cold representation; callbacks, staged transitions, CPU-local hardware
 * state, and unpublished plans are never checkpoint data.
 */
static int
vmx_nested_snapshot_source_validate(struct vmx_vcpu *vcpu, bool active_l2)
{
	int error;

	if (vcpu == NULL || vcpu->vcpu == NULL)
		return (EINVAL);
	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	error = vmx_nested_prepared_owner_validate(vcpu);
	if (error != 0)
		return (error);
	if (!active_l2)
		error = vmx_nested_context_quiesce(&vcpu->nested);
	else
		error = vmx_nested_context_guest_continuation_validate(
		    &vcpu->nested, &vcpu->nested_l0_continuation);
	if (error != 0)
		return (error);
	error = vmx_nested_startup_dispatch_validate(
	    &vcpu->nested_startup_dispatch);
	if (error != 0)
		return (error);
	if (vcpu->nested_startup_dispatch.state !=
	    VMX_NESTED_STARTUP_DISPATCH_EMPTY)
		return (EBUSY);
	if (vcpu->nested_l2_thaw_staged.state <
	    VMX_NESTED_L2_THAW_STAGED_IDLE ||
	    vcpu->nested_l2_thaw_staged.state >
	    VMX_NESTED_L2_THAW_STAGED_POISONED ||
	    vcpu->nested_refreeze_staged.state < VMX_NESTED_REFREEZE_IDLE ||
	    vcpu->nested_refreeze_staged.state > VMX_NESTED_REFREEZE_POISONED)
		return (EPROTO);
	if (vcpu->nested_l2_thaw_staged.state !=
	    VMX_NESTED_L2_THAW_STAGED_IDLE ||
	    vcpu->nested_thaw_resources_valid ||
	    vcpu->nested_refreeze_staged.state != VMX_NESTED_REFREEZE_IDLE ||
	    vcpu->nested_hot_failure_detached)
		return (EBUSY);
	error = vmx_nested_ept_binding_validate(&vcpu->nested_ept_binding);
	if (error != 0)
		return (error);
	if (vcpu->nested_ept_binding.active)
		return (EBUSY);
	error = vmx_nested_ept_cache_owner_quiesce(vcpu);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs02_intel_inactive_validate(
	    &vcpu->nested_vmcs02_intel);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs02_lease_owner_validate(
	    &vcpu->nested_vmcs02_leases);
	if (error != 0)
		return (error);
	if (vcpu->nested_vmcs02_leases.active ||
	    vcpu->nested_vmcs02_leases.callback_active ||
	    vcpu->nested_vmcs02_leases.count != 0)
		return (EBUSY);
	error = vmx_nested_vpid_owner_validate(&vcpu->nested_vpid_owner);
	if (error != 0)
		return (error);
	error = vmx_nested_mtf_owner_validate(&vcpu->nested_mtf_owner);
	if (error != 0)
		return (error);
	if (vcpu->nested_mtf_owner.pending)
		return (EBUSY);
	error = vmx_nested_exit_msr_transaction_validate(
	    &vcpu->nested_exit_msr_transaction);
	if (error != 0)
		return (error);
	if (vcpu->nested_exit_msr_transaction.state !=
	    VMX_NESTED_EXIT_MSR_TRANSACTION_IDLE ||
	    vcpu->nested_exit_msr_plan_valid ||
	    vcpu->nested_failed_entry_msr_plan_valid)
		return (EBUSY);
	if (vcpu->nested_hardware_msr_transition <
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_transition >
	    VMX_NESTED_HARDWARE_MSR_EXIT ||
	    vcpu->nested_tsc_aux_residency < VMX_NESTED_TSC_AUX_L1 ||
	    vcpu->nested_tsc_aux_residency > VMX_NESTED_TSC_AUX_L2_PAUSED ||
	    vcpu->nested_tsc_aux_rollback_residency <
	    VMX_NESTED_TSC_AUX_L1 ||
	    vcpu->nested_tsc_aux_rollback_residency >
	    VMX_NESTED_TSC_AUX_L2_PAUSED)
		return (EPROTO);
	if (vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_count != 0 ||
	    vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1 ||
	    vcpu->nested_tsc_aux_rollback_residency !=
	    VMX_NESTED_TSC_AUX_L1)
		return (EBUSY);
	error = vmx_nested_entry_runtime_validate(&vcpu->nested_entry_runtime);
	if (error != 0)
		return (error);
	error = vmx_nested_l0_continuation_validate(
	    &vcpu->nested_l0_continuation);
	if (error != 0)
		return (error);
	error = vmx_nested_msr_workspace_validate(&vcpu->nested_msr_workspace);
	if (error != 0)
		return (error);
	if (!active_l2) {
		if (vcpu->nested_entry_runtime.state !=
		    VMX_NESTED_ENTRY_RUNTIME_IDLE ||
		    vcpu->nested_l0_continuation.state !=
		    VMX_NESTED_L0_CONTINUATION_IDLE ||
		    vcpu->nested_msr_workspace.active)
			return (EBUSY);
	} else if (vcpu->nested.phase != VMX_NESTED_CONTEXT_GUEST ||
	    vcpu->nested_l0_continuation.state !=
	    VMX_NESTED_L0_CONTINUATION_COLD ||
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_COLD ||
	    !vcpu->nested_l2_portable_valid ||
	    vmx_nested_l2_portable_validate(&vcpu->nested_l2_portable) != 0 ||
	    !vcpu->nested_msr_workspace.active ||
	    vcpu->nested_msr_generation == 0 ||
	    vcpu->nested_msr_generation !=
	    vcpu->nested_msr_workspace.generation)
		return (EBUSY);
	return (0);
}

static int
vmx_vm_snapshot(void *vmi, struct vm_snapshot_meta *meta)
{
	struct vmx_nested_snapshot_restore *stage;
	struct vmx *vmx;
	uint8_t header[VMX_NESTED_EXPOSURE_SNAPSHOT_HEADER_SIZE];
	uint8_t length_wire[sizeof(uint32_t)];
	uint8_t *wire;
	size_t size, written;
	uint32_t length;
	bool source_nested_vmx;
	int error;

	vmx = vmi;
	/*
	 * The exposure bit is serialized as guest CPU-model state.  Freeze it
	 * before observing either the header or the VMCS registry so a
	 * concurrent capability request cannot straddle the checkpoint.
	 */
	vmx_nested_guest_config_lock(vmx);
	stage = NULL;
	wire = NULL;
	size = 0;
	written = 0;
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = vmx_nested_exposure_snapshot_header_encode(
		    vmx_nested_guest_enabled(vmx), header, sizeof(header));
		if (error != 0)
			goto out;
		sx_slock(&vmx->nested_vmcs_sx);
		error = vmx_nested_vmcs_registry_state_size(
		    &vmx->nested_vmcs_registry, &size);
		if (error == 0 &&
		    size > VMX_NESTED_VMCS_REGISTRY_STATE_MAX_SIZE)
			error = EOVERFLOW;
		if (error == 0)
			wire = malloc(size, M_VMX, M_NOWAIT | M_ZERO);
		if (error == 0 && wire == NULL)
			error = ENOMEM;
		if (error == 0)
			error = vmx_nested_vmcs_registry_state_encode(
			    &vmx->nested_vmcs_registry, wire, size, &written);
		sx_sunlock(&vmx->nested_vmcs_sx);
		if (error != 0)
			goto out;
		if (written != size) {
			error = EPROTO;
			goto out;
		}
		le32enc(length_wire, (uint32_t)size);
	} else {
		error = vm_snapshot_buf(header, sizeof(header), meta);
		if (error != 0)
			goto out;
		error = vmx_nested_exposure_snapshot_header_decode(header,
		    sizeof(header), &source_nested_vmx);
		if (error != 0)
			goto out;
		error = vmx_nested_exposure_snapshot_validate(
		    &vmx_nested_virtual_capabilities, source_nested_vmx,
		    vmx_nested_guest_enabled(vmx), nested_vmx_allowed != 0);
		if (error != 0)
			goto out;
		error = vm_snapshot_buf(length_wire, sizeof(length_wire),
		    meta);
		if (error != 0)
			goto out;
		length = le32dec(length_wire);
		if (length < VMX_NESTED_VMCS_REGISTRY_STATE_HEADER_SIZE ||
		    length > VMX_NESTED_VMCS_REGISTRY_STATE_MAX_SIZE) {
			error = EPROTO;
			goto out;
		}
		size = length;
		wire = malloc(size, M_VMX, M_NOWAIT | M_ZERO);
		if (wire == NULL) {
			error = ENOMEM;
			goto out;
		}
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = vm_snapshot_buf(header, sizeof(header), meta);
		if (error != 0)
			goto out;
		error = vm_snapshot_buf(length_wire, sizeof(length_wire),
		    meta);
		if (error != 0)
			goto out;
	}
	error = vm_snapshot_buf(wire, size, meta);
	if (error != 0 || meta->op == VM_SNAPSHOT_SAVE)
		goto out;
	if (vmx->nested_snapshot_restore != NULL) {
		error = EBUSY;
		goto out;
	}
	stage = malloc(sizeof(*stage), M_VMX, M_NOWAIT | M_ZERO);
	if (stage == NULL) {
		error = ENOMEM;
		goto out;
	}
	stage->maxcpus = vm_get_maxcpus(vmx->vm);
	stage->vcpus = mallocarray(stage->maxcpus,
	    sizeof(*stage->vcpus), M_VMX, M_NOWAIT | M_ZERO);
	if (stage->vcpus == NULL) {
		error = ENOMEM;
		goto out;
	}
	stage->arch_vcpus = mallocarray(stage->maxcpus,
	    sizeof(*stage->arch_vcpus), M_VMX, M_NOWAIT | M_ZERO);
	if (stage->arch_vcpus == NULL) {
		error = ENOMEM;
		goto out;
	}
	error = vmx_nested_vmcs_registry_init(&stage->registry,
	    &vmx->nested_vmcs_registry.capabilities,
	    vmx->nested_vmcs_registry.limit);
	if (error != 0)
		goto out;
	stage->registry_initialized = true;
	error = vmx_nested_vmcs_registry_state_restore(&stage->registry,
	    wire, size);
	if (error == 0)
		error = vmx_nested_exposure_registry_validate(source_nested_vmx,
		    stage->registry.count);
	if (error != 0)
		goto out;
	vmx->nested_snapshot_restore = stage;
	stage = NULL;
out:
	vmx_nested_snapshot_restore_free(stage);
	if (wire != NULL) {
		explicit_bzero(wire, size);
		free(wire, M_VMX);
	}
	return (error);
}

static int
vmx_vcpu_nested_snapshot(struct vmx_vcpu *vcpu,
    struct vm_snapshot_meta *meta)
{
	struct vmx_nested_entry_environment_capture environment_capture;
	struct vmx_nested_checkpoint_view view;
	struct vmx_nested_field *fields;
	struct vmx_nested_state state;
	struct vmx_nested_vmcs02_resources fixed_resources;
	uint8_t l2_wire[VMX_NESTED_L2_CONT_STATE_SIZE];
	uint8_t length_wire[sizeof(uint32_t)];
	uint8_t *wire;
	bool active_l2;
	size_t l2_written, size, written;
	uint32_t length;
	int error;

	/*
	 * VM_SNAPSHOT_REQ currently reaches this helper through an ioctl which
	 * freezes every vCPU.  Keep that dispatcher policy as a checked contract,
	 * not an implicit synchronization assumption: staging reads VMCS12 owner
	 * state and may bind destination-local scratch which must not race a run.
	 */
	if (vcpu == NULL || meta == NULL)
		return (EINVAL);
	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	fields = NULL;
	wire = NULL;
	active_l2 = false;
	l2_written = 0;
	size = 0;
	written = 0;
	if (meta->op == VM_SNAPSHOT_SAVE) {
		fields = mallocarray(VMX_NESTED_STATE_MAX_FIELDS,
		    sizeof(*fields), M_VMX, M_NOWAIT | M_ZERO);
		if (fields == NULL) {
			error = ENOMEM;
			goto out;
		}
		sx_slock(&vcpu->vmx->nested_vmcs_sx);
		active_l2 = vcpu->nested_vmcs02_plan_valid;
		if (active_l2) {
			error = vmx_nested_checkpoint_active_capture(
			    &vcpu->nested,
			    &vcpu->nested_control_msrs,
			    &vcpu->nested_l0_continuation,
			    &vcpu->nested_entry_runtime,
			    &vcpu->nested_l2_portable,
			    &vcpu->vmx->nested_vmcs_registry,
			    vcpu->vcpuid, fields,
			    VMX_NESTED_STATE_MAX_FIELDS, NULL, 0, &state);
		} else {
			error = vmx_nested_checkpoint_capture(&vcpu->nested,
			    &vcpu->nested_control_msrs,
			    &vcpu->vmx->nested_vmcs_registry, vcpu->vcpuid,
			    fields, VMX_NESTED_STATE_MAX_FIELDS, &state);
		}
		if (error == 0)
			error = vmx_nested_state_size(&state, &size);
		if (error == 0 && size > VMX_NESTED_STATE_MAX_SIZE)
			error = EOVERFLOW;
		if (error == 0)
			wire = malloc(size, M_VMX, M_NOWAIT | M_ZERO);
		if (error == 0 && wire == NULL)
			error = ENOMEM;
		if (error == 0)
			error = vmx_nested_state_encode(&state, wire, size,
			    &written);
		if (error == 0 && active_l2)
			error = vmx_nested_l2_continuation_state_encode(
			    &vcpu->nested_l0_continuation,
			    &vcpu->nested_l2_portable, l2_wire,
			    sizeof(l2_wire), &l2_written);
		sx_sunlock(&vcpu->vmx->nested_vmcs_sx);
		if (error != 0)
			goto out;
		if (written != size) {
			error = EPROTO;
			goto out;
		}
		if (active_l2 && l2_written != sizeof(l2_wire)) {
			error = EPROTO;
			goto out;
		}
		le32enc(length_wire, (uint32_t)size);
	} else {
		struct vmx_nested_snapshot_restore *stage;
		struct vmx_nested_snapshot_vcpu_stage *vcpu_stage;

		stage = vcpu->vmx->nested_snapshot_restore;
		if (stage == NULL || vcpu->vcpuid < 0 ||
		    vcpu->vcpuid >= stage->maxcpus ||
		    vm_vcpu(vcpu->vmx->vm, vcpu->vcpuid) != vcpu->vcpu) {
			error = EPROTO;
			goto out;
		}
		vcpu_stage = &stage->vcpus[vcpu->vcpuid];
		if (vcpu_stage->valid) {
			error = EPROTO;
			goto out;
		}
		error = vm_snapshot_buf(length_wire, sizeof(length_wire),
		    meta);
		if (error != 0)
			goto out;
		length = le32dec(length_wire);
		if (length < VMX_NESTED_STATE_HEADER_SIZE ||
		    length > VMX_NESTED_STATE_MAX_SIZE) {
			error = EPROTO;
			goto out;
		}
		size = length;
		wire = malloc(size, M_VMX, M_NOWAIT | M_ZERO);
		if (wire == NULL) {
			error = ENOMEM;
			goto out;
		}
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = vm_snapshot_buf(length_wire, sizeof(length_wire),
		    meta);
		if (error != 0)
			goto out;
	}
	error = vm_snapshot_buf(wire, size, meta);
	if (error != 0)
		goto out;
	if (meta->op == VM_SNAPSHOT_SAVE) {
		if (active_l2)
			error = vm_snapshot_buf(l2_wire, sizeof(l2_wire), meta);
		goto out;
	}
	memset(&view, 0, sizeof(view));
	error = vmx_nested_state_decode(wire, size, &view.state);
	if (error != 0)
		goto out;
	error = vmx_nested_exposure_restore_validate(
	    &vmx_nested_virtual_capabilities, &view.state,
	    nested_vmx_allowed != 0 && vmx_nested_guest_enabled(vcpu->vmx));
	if (error != 0)
		goto out;
	active_l2 = (view.state.flags &
	    VMX_NESTED_STATE_F_GUEST_MODE) != 0;
	if (active_l2) {
		error = vm_snapshot_buf(l2_wire, sizeof(l2_wire), meta);
		if (error != 0)
			goto out;
		view.l2_wire = l2_wire;
		view.l2_length = sizeof(l2_wire);
	}
	{
		struct vmx_nested_snapshot_restore *stage;
		struct vmx_nested_snapshot_vcpu_stage *vcpu_stage;

		stage = vcpu->vmx->nested_snapshot_restore;
		vcpu_stage = &stage->vcpus[vcpu->vcpuid];
		vcpu_stage->vcpu = vcpu;
		vcpu_stage->context = vcpu->nested;
		vcpu_stage->control = vcpu->nested_control_msrs;
		if (!active_l2) {
			error = vmx_nested_checkpoint_context_restore(
			    &vcpu_stage->context, &vcpu_stage->control,
			    &stage->registry, vcpu->vcpuid, &view, true);
		} else {
			vmx_nested_l0_continuation_init(
			    &vcpu_stage->continuation);
			vmx_nested_entry_runtime_init(&vcpu_stage->runtime);
			error = vmx_nested_checkpoint_active_context_restore(
			    &vcpu_stage->context, &vcpu_stage->control,
			    &vcpu_stage->continuation, &vcpu_stage->runtime,
			    &vcpu_stage->portable, &vcpu_stage->snapshot,
			    &stage->registry, vcpu->vcpuid, &view, true);
			/*
			 * A fresh destination has no MSR scratch binding.  Keep its
			 * bounded host-only allocation in this unpublished stage; a
			 * later decode or VM-wide commit error must not alter the
			 * destination vCPU's ownership.  A destination that already has
			 * an inactive validated workspace reuses that pre-existing
			 * allocation, which is not a restore-side resource acquisition.
			 */
			if (error == 0 && vcpu->nested_msr_storage == NULL) {
				error = vmx_nested_msr_workspace_stage(
				    &stage->registry.capabilities,
				    &vcpu_stage->msr_workspace,
				    &vcpu_stage->msr_storage);
				if (error == 0)
					vcpu_stage->msr_workspace_staged = true;
			} else if (error == 0)
				error = vmx_nested_msr_workspace_ensure(vcpu,
				    &stage->registry.capabilities, false);
			if (error == 0)
				error = vmx_nested_vpid_owner_validate(
				    &vcpu->nested_vpid_owner);
			if (error == 0 &&
			    (vcpu->nested_vpid_owner.active ||
			    vmx_nested_vpid_owner_flush_required(
			    &vcpu->nested_vpid_owner)))
				error = EBUSY;
			if (error == 0) {
				/*
				 * A host VPID is scarce destination runtime state, not
				 * checkpoint data.  Acquire it into the unpublished vCPU
				 * stage so any later decode or VM-wide commit failure can
				 * release it without changing the destination vCPU.
				 */
				vmx_nested_vpid_owner_init(
				    &vcpu_stage->vpid_owner);
				vcpu_stage->vpid_staged = true;
				if (vcpu->state.vpid != 0)
					error = vmx_nested_vpid_owner_acquire(
					    &vcpu_stage->vpid_owner,
					    vcpu->state.vpid,
					    &vmx_nested_vpid_ops, NULL);
			}
			if (error == 0)
				error = vmx_nested_entry_environment_from_vmcs12(
				    &vcpu_stage->snapshot,
				    &vcpu_stage->portable.id,
				    &vmx_nested_hardware_controls,
				    vcpu->state.vpid,
				    vcpu_stage->vpid_owner.effective_vpid,
				    false,
				    &environment_capture);
			if (error == 0)
				error =
				    vmx_nested_entry_environment_intel_capture(
				    vcpu, &environment_capture,
				    &vcpu_stage->environment,
				    &fixed_resources);
			if (error == 0)
				error = vmx_nested_l2_rebuild_plan(
				    &vcpu_stage->snapshot,
				    &vcpu_stage->environment,
				    &vcpu_stage->portable, false,
				    &vcpu_stage->plan);
			if (error == 0) {
				vmx_nested_software_msrs_capture(vcpu,
				    &vcpu_stage->l1_software);
				vcpu_stage->active_l2 = true;
			}
		}
		if (error != 0)
			goto out;
		vcpu_stage->valid = true;
	}
out:
	explicit_bzero(l2_wire, sizeof(l2_wire));
	if (wire != NULL) {
		explicit_bzero(wire, size);
		free(wire, M_VMX);
	}
	if (fields != NULL) {
		explicit_bzero(fields, VMX_NESTED_STATE_MAX_FIELDS *
		    sizeof(*fields));
		free(fields, M_VMX);
	}
	return (error);
}

static int
vmx_vm_snapshot_complete(void *vmi, struct vm_snapshot_meta *meta, int status)
{
	struct vmx_snapshot_arch_vcpu_stage *arch_stage;
	struct vmx_nested_restore_workspace *workspaces;
	struct vmx_nested_snapshot_restore *stage;
	struct vmx_nested_snapshot_vcpu_stage *vcpu_stage;
	struct vmx *vmx;
	uint32_t active_count, valid_count;
	bool vmcs_applied;
	int error;

	vmx = vmi;
	if (meta->op == VM_SNAPSHOT_SAVE)
		return (0);
	active_count = 0;
	valid_count = 0;
	vmcs_applied = false;
	stage = vmx->nested_snapshot_restore;
	vmx->nested_snapshot_restore = NULL;
	if (stage == NULL) {
		error = status == 0 ? EPROTO : 0;
		SDT_PROBE5(vmm, vmx, nested, restore, vmx, error, 0, 0, 0);
		return (error);
	}
	if (status != 0) {
		SDT_PROBE5(vmm, vmx, nested, restore, vmx, status, 0, 0,
		    stage->registry.count);
		vmx_nested_snapshot_restore_free(stage);
		return (0);
	}
	workspaces = mallocarray(stage->maxcpus, sizeof(*workspaces), M_VMX,
	    M_NOWAIT | M_ZERO);
	if (workspaces == NULL) {
		vmx_nested_snapshot_restore_free(stage);
		return (ENOMEM);
	}
	for (uint16_t i = 0; i < stage->maxcpus; i++) {
		struct vcpu *generic_vcpu;

		generic_vcpu = vm_vcpu(vmx->vm, i);
		if (generic_vcpu != NULL &&
		    vcpu_get_state(generic_vcpu, NULL) != VCPU_FROZEN) {
			SDT_PROBE5(vmm, vmx, nested, restore, vmx, EBUSY,
			    active_count, valid_count, stage->registry.count);
			free(workspaces, M_VMX);
			vmx_nested_snapshot_restore_free(stage);
			return (EBUSY);
		}
		if (generic_vcpu == NULL && (stage->vcpus[i].valid ||
		    stage->arch_vcpus == NULL || stage->arch_vcpus[i].valid)) {
			SDT_PROBE5(vmm, vmx, nested, restore, vmx, EPROTO,
			    active_count, valid_count, stage->registry.count);
			free(workspaces, M_VMX);
			vmx_nested_snapshot_restore_free(stage);
			return (EPROTO);
		}
		if (generic_vcpu != NULL && (stage->arch_vcpus == NULL ||
		    !stage->vcpus[i].valid || !stage->arch_vcpus[i].valid ||
		    stage->vcpus[i].vcpu == NULL ||
		    stage->vcpus[i].vcpu->vmx != vmx ||
		    stage->vcpus[i].vcpu->vcpu != generic_vcpu ||
		    stage->vcpus[i].vcpu->vcpuid != i)) {
			SDT_PROBE5(vmm, vmx, nested, restore, vmx, EPROTO,
			    active_count, valid_count, stage->registry.count);
			free(workspaces, M_VMX);
			vmx_nested_snapshot_restore_free(stage);
			return (EPROTO);
		}
		arch_stage = &stage->arch_vcpus[i];
		if (stage->vcpus[i].valid && (arch_stage->vcpu !=
		    stage->vcpus[i].vcpu || arch_stage->vmcs !=
		    arch_stage->vcpu->vmcs)) {
			SDT_PROBE5(vmm, vmx, nested, restore, vmx, EPROTO,
			    active_count, valid_count, stage->registry.count);
			free(workspaces, M_VMX);
			vmx_nested_snapshot_restore_free(stage);
			return (EPROTO);
		}
		if (stage->vcpus[i].valid) {
			valid_count++;
			if (stage->vcpus[i].active_l2)
				active_count++;
			error = vmx_nested_snapshot_destination_validate(
			    stage->vcpus[i].vcpu);
			if (error != 0) {
				SDT_PROBE5(vmm, vmx, nested, restore, vmx,
				    error, active_count, valid_count,
				    stage->registry.count);
				free(workspaces, M_VMX);
				vmx_nested_snapshot_restore_free(stage);
				return (error);
			}
		}
	}
	/*
	 * SDT probes compile away in kernels without KDTRACE_HOOKS.  Keep the
	 * counters live in that configuration as well so the snapshot path
	 * remains warning-clean under the kernel's mandatory -Werror build.
	 */
	(void)active_count;
	(void)valid_count;
	/*
	 * Validate every destination before changing any cache.  Even an
	 * unreferenced nested-EPT root can encode translations derived from L1
	 * page tables that the memory restore replaced.  Destroy all quiescent
	 * roots before registry publication so the first restored L2 entry must
	 * rebuild them from restored guest memory.
	 */
	for (uint16_t i = 0; i < stage->maxcpus; i++) {
		vcpu_stage = &stage->vcpus[i];
		if (!vcpu_stage->valid)
			continue;
		error = vmx_nested_ept_cache_destroy(
		    &vcpu_stage->vcpu->nested_ept_cache);
		if (error != 0) {
			SDT_PROBE5(vmm, vmx, nested, restore, vmx, error,
			    active_count, valid_count, stage->registry.count);
			free(workspaces, M_VMX);
			vmx_nested_snapshot_restore_free(stage);
			return (error);
		}
	}
	/*
	 * Recreate only the destination-local scratch ownership before the
	 * VM-wide registry publication.  Entry-time loads already took effect
	 * in the portable L2 image, so they must not be replayed; the exit
	 * list counts retain bounds for the eventual reflected exit.
	 */
	for (uint16_t i = 0; i < stage->maxcpus; i++) {
		vcpu_stage = &stage->vcpus[i];
		if (!vcpu_stage->valid || !vcpu_stage->active_l2)
			continue;
		workspaces[i].workspace = vcpu_stage->msr_workspace_staged ?
		    &vcpu_stage->msr_workspace :
		    &vcpu_stage->vcpu->nested_msr_workspace;
		workspaces[i].capabilities =
		    &vcpu_stage->snapshot.capabilities;
		workspaces[i].generation = &vcpu_stage->msr_generation;
		workspaces[i].entry_load_count = 0;
		workspaces[i].exit_store_count =
		    vcpu_stage->snapshot.controls.exit_msr_store_count;
		workspaces[i].exit_load_count =
		    vcpu_stage->snapshot.controls.exit_msr_load_count;
		workspaces[i].active = true;
	}
	/*
	 * The nested registry transaction below has a complete failure rollback.
	 * Apply the opaque VMCS fields first, retaining each exact pre-write image;
	 * a nested transaction rejection can therefore restore every prior vCPU
	 * before any software or nested context is published.
	 */
	for (uint16_t i = 0; i < stage->maxcpus; i++) {
		arch_stage = &stage->arch_vcpus[i];
		if (!arch_stage->valid)
			continue;
		error = vmx_snapshot_vmcs_state_apply(arch_stage->vmcs,
		    arch_stage->running, &arch_stage->candidate_vmcs);
		if (error != 0) {
			if (vmx_snapshot_vmcs_state_apply(arch_stage->vmcs,
			    arch_stage->running, &arch_stage->rollback_vmcs) != 0)
				panic("%s: VMCS rollback failed", __func__);
			goto rollback_vmcs;
		}
		arch_stage->vmcs_applied = true;
		vmcs_applied = true;
	}
	sx_xlock(&vmx->nested_vmcs_sx);
	error = vmx_nested_restore_transaction_commit(
	    &vmx->nested_vmcs_registry, &stage->registry, workspaces,
	    stage->maxcpus);
	if (error == 0) {
		for (uint16_t i = 0; i < stage->maxcpus; i++) {
			vcpu_stage = &stage->vcpus[i];
			if (!vcpu_stage->valid)
				continue;
			arch_stage = &stage->arch_vcpus[i];
			vmx_snapshot_arch_vcpu_publish(arch_stage);
			vcpu_stage->vcpu->nested = vcpu_stage->context;
			vcpu_stage->vcpu->nested_control_msrs =
			    vcpu_stage->control;
			if (!vcpu_stage->active_l2)
				continue;
			vcpu_stage->vcpu->nested_l0_continuation =
			    vcpu_stage->continuation;
			vcpu_stage->vcpu->nested_entry_runtime =
			    vcpu_stage->runtime;
			vcpu_stage->vcpu->nested_l2_portable =
			    vcpu_stage->portable;
			vcpu_stage->vcpu->nested_l2_portable_valid = true;
			vcpu_stage->vcpu->nested_portable_generation =
			    vcpu_stage->portable.portable_generation;
			vcpu_stage->vcpu->nested_vmcs12_snapshot =
			    vcpu_stage->snapshot;
			vcpu_stage->vcpu->nested_entry_environment =
			    vcpu_stage->environment;
			vcpu_stage->vcpu->nested_vmcs02_plan =
			    vcpu_stage->plan;
			vcpu_stage->vcpu->nested_l1_software_msrs =
			    vcpu_stage->l1_software;
			vcpu_stage->vcpu->nested_l2_software_msrs =
			    vcpu_stage->portable.software_msrs;
			if (vcpu_stage->msr_workspace_staged) {
				KASSERT(vcpu_stage->vcpu->nested_msr_storage == NULL,
				    ("%s: destination acquired MSR scratch during restore",
				    __func__));
				vcpu_stage->vcpu->nested_msr_workspace =
				    vcpu_stage->msr_workspace;
				vcpu_stage->vcpu->nested_msr_storage =
				    vcpu_stage->msr_storage;
				vcpu_stage->msr_storage = NULL;
				vcpu_stage->msr_workspace_staged = false;
			}
			/* Transfer the already-validated staged host VPID last. */
			vcpu_stage->vcpu->nested_vpid_owner =
			    vcpu_stage->vpid_owner;
			vcpu_stage->vpid_staged = false;
			vcpu_stage->vcpu->nested_msr_generation =
			    vcpu_stage->msr_generation;
			vcpu_stage->vcpu->nested_entry_msr_count = 0;
			vcpu_stage->vcpu->nested_vmcs02_plan_valid = true;
		}
	}
	sx_xunlock(&vmx->nested_vmcs_sx);
	if (error != 0)
		goto rollback_vmcs;
	SDT_PROBE5(vmm, vmx, nested, restore, vmx, 0, active_count,
	    valid_count, vmx->nested_vmcs_registry.count);
	free(workspaces, M_VMX);
	vmx_nested_snapshot_restore_free(stage);
	return (0);

rollback_vmcs:
	if (vmcs_applied) {
		for (uint16_t i = 0; i < stage->maxcpus; i++) {
			arch_stage = &stage->arch_vcpus[i];
			if (!arch_stage->vmcs_applied)
				continue;
			if (vmx_snapshot_vmcs_state_apply(arch_stage->vmcs,
			    arch_stage->running, &arch_stage->rollback_vmcs) != 0)
				panic("%s: VMCS rollback failed", __func__);
			arch_stage->vmcs_applied = false;
		}
	}

	SDT_PROBE5(vmm, vmx, nested, restore, vmx, error, active_count,
	    valid_count, stage->registry.count);
	free(workspaces, M_VMX);
	vmx_nested_snapshot_restore_free(stage);
	return (error);
}

static const int vmx_snapshot_vmcs_regs[] = {
	VM_REG_GUEST_CR0, VM_REG_GUEST_CR3, VM_REG_GUEST_CR4,
	VM_REG_GUEST_DR7, VM_REG_GUEST_RSP, VM_REG_GUEST_RIP,
	VM_REG_GUEST_RFLAGS,
	VM_REG_GUEST_ES, VM_REG_GUEST_CS, VM_REG_GUEST_SS,
	VM_REG_GUEST_DS, VM_REG_GUEST_FS, VM_REG_GUEST_GS,
	VM_REG_GUEST_TR, VM_REG_GUEST_LDTR, VM_REG_GUEST_EFER,
	VM_REG_GUEST_PDPTE0, VM_REG_GUEST_PDPTE1,
	VM_REG_GUEST_PDPTE2, VM_REG_GUEST_PDPTE3,
};

static const int vmx_snapshot_vmcs_descs[] = {
	VM_REG_GUEST_ES, VM_REG_GUEST_CS, VM_REG_GUEST_SS,
	VM_REG_GUEST_DS, VM_REG_GUEST_FS, VM_REG_GUEST_GS,
	VM_REG_GUEST_TR, VM_REG_GUEST_LDTR,
	VM_REG_GUEST_IDTR, VM_REG_GUEST_GDTR,
};

static const int vmx_snapshot_vmcs_any[] = {
	VMCS_GUEST_IA32_SYSENTER_CS, VMCS_GUEST_IA32_SYSENTER_ESP,
	VMCS_GUEST_IA32_SYSENTER_EIP, VMCS_GUEST_INTERRUPTIBILITY,
	VMCS_GUEST_ACTIVITY, VMCS_ENTRY_CTLS, VMCS_EXIT_CTLS,
};

static int
vmx_snapshot_vmcs_state(struct vmcs *vmcs, int running,
    struct vm_snapshot_meta *meta, struct vmx_snapshot_vmcs_state *candidate,
    struct vmx_snapshot_vmcs_state *rollback)
{
	struct seg_desc *desc;
	uint64_t *val;
	int error;
	size_t i;

	for (i = 0; i < nitems(vmx_snapshot_vmcs_regs); i++) {
		val = &candidate->regs[i];
		if (meta->op == VM_SNAPSHOT_SAVE) {
			error = vmcs_getreg(vmcs, running,
			    vmx_snapshot_vmcs_regs[i], val);
		} else if (meta->op == VM_SNAPSHOT_RESTORE) {
			error = vmcs_getreg(vmcs, running,
			    vmx_snapshot_vmcs_regs[i], &rollback->regs[i]);
		} else
			return (EINVAL);
		if (error != 0)
			return (error);
		SNAPSHOT_VAR_OR_LEAVE(*val, meta, error, done);
	}

	for (i = 0; i < nitems(vmx_snapshot_vmcs_descs); i++) {
		desc = &candidate->descs[i];
		if (meta->op == VM_SNAPSHOT_SAVE) {
			error = vmcs_getdesc(vmcs, running,
			    vmx_snapshot_vmcs_descs[i], desc);
		} else {
			error = vmcs_getdesc(vmcs, running,
			    vmx_snapshot_vmcs_descs[i], &rollback->descs[i]);
		}
		if (error != 0)
			return (error);
		SNAPSHOT_VAR_OR_LEAVE(desc->base, meta, error, done);
		SNAPSHOT_VAR_OR_LEAVE(desc->limit, meta, error, done);
		SNAPSHOT_VAR_OR_LEAVE(desc->access, meta, error, done);
	}

	for (i = 0; i < nitems(vmx_snapshot_vmcs_any); i++) {
		val = &candidate->any[i];
		if (meta->op == VM_SNAPSHOT_SAVE) {
			error = vmcs_getany(vmcs, running,
			    vmx_snapshot_vmcs_any[i], val);
		} else {
			error = vmcs_getany(vmcs, running,
			    vmx_snapshot_vmcs_any[i], &rollback->any[i]);
		}
		if (error != 0)
			return (error);
		SNAPSHOT_VAR_OR_LEAVE(*val, meta, error, done);
	}

	return (0);
done:
	return (error);
}

static int
vmx_snapshot_vmcs_state_apply(struct vmcs *vmcs, int running,
    const struct vmx_snapshot_vmcs_state *state)
{
	struct seg_desc desc;
	int error;
	size_t i;

	for (i = 0; i < nitems(vmx_snapshot_vmcs_regs); i++) {
		error = vmcs_setreg(vmcs, running, vmx_snapshot_vmcs_regs[i],
		    state->regs[i]);
		if (error != 0)
			return (error);
	}
	for (i = 0; i < nitems(vmx_snapshot_vmcs_descs); i++) {
		desc = state->descs[i];
		error = vmcs_setdesc(vmcs, running, vmx_snapshot_vmcs_descs[i],
		    &desc);
		if (error != 0)
			return (error);
	}
	for (i = 0; i < nitems(vmx_snapshot_vmcs_any); i++) {
		error = vmcs_setany(vmcs, running, vmx_snapshot_vmcs_any[i],
		    state->any[i]);
		if (error != 0)
			return (error);
	}
	return (0);
}

static void
vmx_snapshot_arch_vcpu_publish(const struct vmx_snapshot_arch_vcpu_stage *stage)
{
	struct vlapic_vtx *vlapic_vtx;
	struct vmx_vcpu *vcpu;

	vcpu = stage->vcpu;
	bcopy(stage->guest_msrs, vcpu->guest_msrs, sizeof(stage->guest_msrs));
	*vcpu->pir_desc = stage->pir_desc;
	/* This notification optimization is destination-local, not wire state. */
	vlapic_vtx = (struct vlapic_vtx *)vm_lapic(vcpu->vcpu);
	vlapic_vtx->pending_prio = 0;
	vcpu->mtrr = stage->mtrr;
	vcpu->ctx.guest_rdi = stage->ctx.guest_rdi;
	vcpu->ctx.guest_rsi = stage->ctx.guest_rsi;
	vcpu->ctx.guest_rdx = stage->ctx.guest_rdx;
	vcpu->ctx.guest_rcx = stage->ctx.guest_rcx;
	vcpu->ctx.guest_r8 = stage->ctx.guest_r8;
	vcpu->ctx.guest_r9 = stage->ctx.guest_r9;
	vcpu->ctx.guest_rax = stage->ctx.guest_rax;
	vcpu->ctx.guest_rbx = stage->ctx.guest_rbx;
	vcpu->ctx.guest_rbp = stage->ctx.guest_rbp;
	vcpu->ctx.guest_r10 = stage->ctx.guest_r10;
	vcpu->ctx.guest_r11 = stage->ctx.guest_r11;
	vcpu->ctx.guest_r12 = stage->ctx.guest_r12;
	vcpu->ctx.guest_r13 = stage->ctx.guest_r13;
	vcpu->ctx.guest_r14 = stage->ctx.guest_r14;
	vcpu->ctx.guest_r15 = stage->ctx.guest_r15;
	vcpu->ctx.guest_cr2 = stage->ctx.guest_cr2;
	vcpu->ctx.guest_dr0 = stage->ctx.guest_dr0;
	vcpu->ctx.guest_dr1 = stage->ctx.guest_dr1;
	vcpu->ctx.guest_dr2 = stage->ctx.guest_dr2;
	vcpu->ctx.guest_dr3 = stage->ctx.guest_dr3;
	vcpu->ctx.guest_dr6 = stage->ctx.guest_dr6;
	/* CPU-local VMCS defaults and VPID cache state never cross restore. */
	vcpu->state.lastcpu = NOCPU;
}

static int
vmx_vcpu_snapshot(void *vcpui, struct vm_snapshot_meta *meta)
{
	struct vmx_snapshot_arch_vcpu_stage *arch_stage;
	struct vmx_nested_snapshot_restore *stage;
	struct vmcs *vmcs;
	struct vmx *vmx;
	struct vmx_vcpu *vcpu;
	struct vmxctx *vmxctx;
	struct vmxctx snapshot_ctx;
	struct vmx_snapshot_vmcs_state rollback_vmcs, snapshot_vmcs;
	struct vm_mtrr snapshot_mtrr;
	struct pir_desc snapshot_pir_desc;
	uint64_t snapshot_guest_msrs[GUEST_MSR_NUM];
	bool active_l2;
	int err, run, hostcpu;
	err = 0;
	if (vcpui == NULL || meta == NULL)
		return (EINVAL);
	vcpu = vcpui;
	/*
	 * Reject loss of the ioctl's all-vCPU freeze before restoring even the
	 * ordinary VMCS and register image.  The nested subrecord guard below is
	 * defense in depth, not the first synchronization check.
	 */
	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	vmx = vcpu->vmx;
	vmcs = vcpu->vmcs;
	/*
	 * A stopped active L2 is represented only by the detached cold
	 * continuation.  No CPU-local VMCS02, EPT/VPID lease, hardware MSR
	 * bank, or thaw transaction may cross the snapshot boundary.
	 */
	active_l2 = vcpu->nested_vmcs02_plan_valid;
	err = vmx_nested_snapshot_source_validate(vcpu, active_l2);
	if (err != 0)
		return (err);
	if (meta->op == VM_SNAPSHOT_SAVE &&
	    (!vmx_snapshot_pir_desc_valid(vcpu->pir_desc) ||
	    !vm_mtrr_validate(&vcpu->mtrr,
	    vm_mtrr_maxphyaddr(cpu_maxphyaddr))))
		return (EINVAL);

	run = vcpu_is_running(vcpu->vcpu, &hostcpu);
	if (run && hostcpu != curcpu) {
		printf("%s: %s%d is running", __func__, vm_name(vmx->vm),
		    vcpu->vcpuid);
		return (EINVAL);
	}

	err = vmx_snapshot_vmcs_state(vmcs, run, meta, &snapshot_vmcs,
	    &rollback_vmcs);
	if (err != 0)
		goto done;

	/* Stage software-owned state through nested-record validation as well. */
	bcopy(vcpu->guest_msrs, snapshot_guest_msrs,
	    sizeof(snapshot_guest_msrs));
	snapshot_pir_desc = *vcpu->pir_desc;
	snapshot_mtrr = vcpu->mtrr;
	snapshot_ctx = vcpu->ctx;
	SNAPSHOT_BUF_OR_LEAVE(snapshot_guest_msrs,
	    sizeof(snapshot_guest_msrs), meta, err, done);

	SNAPSHOT_BUF_OR_LEAVE(&snapshot_pir_desc,
	    sizeof(snapshot_pir_desc), meta, err, done);

	SNAPSHOT_BUF_OR_LEAVE(&snapshot_mtrr,
	    sizeof(snapshot_mtrr), meta, err, done);
	if (!vmx_snapshot_pir_desc_valid(&snapshot_pir_desc) ||
	    !vm_mtrr_validate(&snapshot_mtrr,
	    vm_mtrr_maxphyaddr(cpu_maxphyaddr))) {
		err = EINVAL;
		goto done;
	}

	vmxctx = &snapshot_ctx;
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rdi, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rsi, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rdx, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rcx, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r8, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r9, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rax, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rbx, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rbp, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r10, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r11, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r12, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r13, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r14, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r15, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_cr2, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr0, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr1, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr2, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr3, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr6, meta, err, done);

	err = vmx_vcpu_nested_snapshot(vcpu, meta);
	if (err == 0 && meta->op == VM_SNAPSHOT_RESTORE) {
		stage = vmx->nested_snapshot_restore;
		if (stage == NULL || stage->arch_vcpus == NULL ||
		    vcpu->vcpuid < 0 || vcpu->vcpuid >= stage->maxcpus ||
		    vm_vcpu(vmx->vm, vcpu->vcpuid) != vcpu->vcpu) {
			err = EPROTO;
			goto done;
		}
		arch_stage = &stage->arch_vcpus[vcpu->vcpuid];
		if (arch_stage->valid) {
			err = EPROTO;
			goto done;
		}
		arch_stage->vcpu = vcpu;
		arch_stage->vmcs = vmcs;
		arch_stage->candidate_vmcs = snapshot_vmcs;
		arch_stage->rollback_vmcs = rollback_vmcs;
		arch_stage->ctx = snapshot_ctx;
		arch_stage->mtrr = snapshot_mtrr;
		arch_stage->pir_desc = snapshot_pir_desc;
		bcopy(snapshot_guest_msrs, arch_stage->guest_msrs,
		    sizeof(arch_stage->guest_msrs));
		arch_stage->running = run;
		arch_stage->valid = true;
	}
done:
	return (err);
}

static int
vmx_restore_tsc(void *vcpui, uint64_t offset)
{
	struct vmx_vcpu *vcpu = vcpui;
	struct vmcs *vmcs;
	struct vmx *vmx;
	int error, running, hostcpu;

	vmx = vcpu->vmx;
	vmcs = vcpu->vmcs;

	running = vcpu_is_running(vcpu->vcpu, &hostcpu);
	if (running && hostcpu != curcpu) {
		printf("%s: %s%d is running", __func__, vm_name(vmx->vm),
		    vcpu->vcpuid);
		return (EINVAL);
	}

	if (!running)
		VMPTRLD(vmcs);

	error = vmx_set_tsc_offset(vcpu, offset);

	if (!running)
		VMCLEAR(vmcs);
	return (error);
}
#endif

/*
 * Nested-VMX exposure is experimental and default-off.  When explicitly
 * enabled, this frozen-vCPU callback dispatches guest-memory VMX operands or
 * an EPT12 walk without sleeping in the VMX critical section.
 */
static int
vmx_nested_gpr(uint8_t index)
{
	static const int registers[16] = {
		VM_REG_GUEST_RAX,
		VM_REG_GUEST_RCX,
		VM_REG_GUEST_RDX,
		VM_REG_GUEST_RBX,
		VM_REG_GUEST_RSP,
		VM_REG_GUEST_RBP,
		VM_REG_GUEST_RSI,
		VM_REG_GUEST_RDI,
		VM_REG_GUEST_R8,
		VM_REG_GUEST_R9,
		VM_REG_GUEST_R10,
		VM_REG_GUEST_R11,
		VM_REG_GUEST_R12,
		VM_REG_GUEST_R13,
		VM_REG_GUEST_R14,
		VM_REG_GUEST_R15,
	};

	if (index >= nitems(registers))
		return (-1);
	return (registers[index]);
}

static int
vmx_nested_commit_instruction(void *arg,
    const struct vmx_nested_instruction_handoff_result *result)
{
	struct vmx_vcpu *vcpu;
	uint64_t old_output, old_rflags, old_rip;
	int error, reg, rollback_error;

	vcpu = arg;
	reg = -1;
	old_output = 0;
	error = vm_get_register(vcpu->vcpu, VM_REG_GUEST_RFLAGS,
	    &old_rflags);
	if (error != 0)
		return (error);
	error = vm_get_register(vcpu->vcpu, VM_REG_GUEST_RIP, &old_rip);
	if (error != 0)
		return (error);
	if (result->output_register) {
		reg = vmx_nested_gpr(result->output_register_index);
		if (reg < 0)
			return (EPROTO);
		error = vm_get_register(vcpu->vcpu, reg, &old_output);
		if (error != 0)
			return (error);
		error = vm_set_register(vcpu->vcpu, reg,
		    result->output_value);
		if (error != 0)
			return (error);
	}
	error = vm_set_register(vcpu->vcpu, VM_REG_GUEST_RFLAGS,
	    result->rflags);
	if (error != 0)
		goto rollback_output;
	error = vm_set_register(vcpu->vcpu, VM_REG_GUEST_RIP,
	    old_rip + result->rip_advance);
	if (error == 0)
		return (0);

	rollback_error = vm_set_register(vcpu->vcpu,
	    VM_REG_GUEST_RFLAGS, old_rflags);
	if (rollback_error != 0)
		panic("%s: RFLAGS rollback failed: %d", __func__,
		    rollback_error);
rollback_output:
	if (reg >= 0) {
		rollback_error = vm_set_register(vcpu->vcpu, reg,
		    old_output);
		if (rollback_error != 0)
			panic("%s: GPR rollback failed: %d", __func__,
			    rollback_error);
	}
	return (error);
}

static const int vmx_nested_l1_restore_regs[] = {
	VM_REG_GUEST_CR0,
	VM_REG_GUEST_CR3,
	VM_REG_GUEST_CR4,
	VM_REG_GUEST_DR7,
	VM_REG_GUEST_RSP,
	VM_REG_GUEST_RIP,
	VM_REG_GUEST_RFLAGS,
	VM_REG_GUEST_ES,
	VM_REG_GUEST_CS,
	VM_REG_GUEST_SS,
	VM_REG_GUEST_DS,
	VM_REG_GUEST_FS,
	VM_REG_GUEST_GS,
	VM_REG_GUEST_TR,
	VM_REG_GUEST_LDTR,
	VM_REG_GUEST_EFER,
};

static const int vmx_nested_l1_restore_descs[] = {
	VM_REG_GUEST_ES,
	VM_REG_GUEST_CS,
	VM_REG_GUEST_SS,
	VM_REG_GUEST_DS,
	VM_REG_GUEST_FS,
	VM_REG_GUEST_GS,
	VM_REG_GUEST_TR,
	VM_REG_GUEST_LDTR,
	VM_REG_GUEST_GDTR,
	VM_REG_GUEST_IDTR,
};

static const uint32_t vmx_nested_l1_restore_direct[] = {
	VMCS_GUEST_IA32_SYSENTER_CS,
	VMCS_GUEST_IA32_SYSENTER_ESP,
	VMCS_GUEST_IA32_SYSENTER_EIP,
	VMCS_GUEST_IA32_DEBUGCTL,
	VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
	VMCS_GUEST_ACTIVITY,
	VMCS_GUEST_INTERRUPTIBILITY,
	VMCS_ENTRY_CTLS,
	VMCS_GUEST_PDPTE0,
	VMCS_GUEST_PDPTE1,
	VMCS_GUEST_PDPTE2,
	VMCS_GUEST_PDPTE3,
};

struct vmx_nested_l1_restore_intel {
	struct vmx_vcpu *vcpu;
	const struct vmx_nested_software_msrs *apply_software;
	const struct vmx_nested_pdpte_state *apply_pdpte;
	struct vmx_nested_software_msrs rollback_software;
	struct vmx_nested_vmcs02_id id;
	uint64_t regs[nitems(vmx_nested_l1_restore_regs)];
	struct seg_desc descs[nitems(vmx_nested_l1_restore_descs)];
	uint64_t direct[nitems(vmx_nested_l1_restore_direct)];
	uint64_t pat;
	uint64_t vmcs12_exit_reason;
	uint64_t vmcs12_exit_qualification;
	uint64_t nextrip;
	bool vmcs12_changed;
	bool nextrip_pending;
	bool active;
};

struct vmx_nested_rejected_entry_commit {
	struct vmx_vcpu *vcpu;
	const struct vmx_nested_vmcs12_snapshot *snapshot;
	const struct vmx_nested_entry_environment *environment;
};

struct vmx_nested_entry_event_intel {
	enum {
		VMX_NESTED_ASYNC_SOURCE_NONE = 0,
		VMX_NESTED_ASYNC_SOURCE_NMI,
		VMX_NESTED_ASYNC_SOURCE_EXTINT,
		VMX_NESTED_ASYNC_SOURCE_LAPIC,
	} async_source;
	struct vmx_vcpu *vcpu;
	struct vm_intinfo_snapshot snapshot;
	struct vmx_nested_entry_event_plan plan;
	struct vmx_nested_mtf_plan mtf_plan;
	uint64_t mtf_portable_generation;
	int async_vector;
	bool mtf_valid;
	bool active;
};

static int vmx_nested_software_msrs_rollback(struct vmx_vcpu *,
    enum vmx_nested_hardware_msr_transition);
static void vmx_nested_software_msrs_capture(const struct vmx_vcpu *,
    struct vmx_nested_software_msrs *);
static void vmx_nested_software_msrs_publish(struct vmx_vcpu *,
    const struct vmx_nested_software_msrs *);
static void vmx_nested_software_msrs_commit(struct vmx_vcpu *,
    enum vmx_nested_hardware_msr_transition);
static int vmx_nested_software_msrs_leave_l2(struct vmx_vcpu *, bool *);
static int vmx_nested_capture_reflected_exit_hot(struct vmx_vcpu *,
    struct vmx_nested_exit_information *,
    struct vmx_nested_l2_runtime_state *);

struct vmx_nested_l1_exit_intel {
	struct vmx_nested_l1_restore_intel restore;
	const struct vmx_nested_vmexit_state_input *state_input;
	const struct vmx_nested_exit_information *information;
	uint64_t execution_epoch;
	bool l1_msrs_ready;
};

static int
vmx_nested_l1_direct_set(struct vmx_vcpu *vcpu, uint32_t encoding,
    uint64_t value)
{
	int hostcpu, running;

	running = vcpu_is_running(vcpu->vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("%s: %s%d is running", __func__,
		    vm_name(vcpu->vmx->vm), vcpu->vcpuid);
	return (vmcs_setreg(vcpu->vmcs, running, VMCS_IDENT(encoding),
	    value));
}

static int
vmx_nested_l1_restore_capture(struct vmx_nested_l1_restore_intel *restore)
{
	struct vmx_vcpu *vcpu;
	size_t i;
	int error;

	vcpu = restore->vcpu;
	for (i = 0; i < nitems(vmx_nested_l1_restore_regs); i++) {
		error = vmx_getreg(vcpu, vmx_nested_l1_restore_regs[i],
		    &restore->regs[i]);
		if (error != 0)
			return (error);
	}
	for (i = 0; i < nitems(vmx_nested_l1_restore_descs); i++) {
		error = vmx_getdesc(vcpu, vmx_nested_l1_restore_descs[i],
		    &restore->descs[i]);
		if (error != 0)
			return (error);
	}
	for (i = 0; i < nitems(vmx_nested_l1_restore_direct); i++) {
		error = vmx_getreg(vcpu,
		    VMCS_IDENT(vmx_nested_l1_restore_direct[i]),
		    &restore->direct[i]);
		if (error != 0)
			return (error);
	}
	restore->pat = vcpu->guest_msrs[IDX_MSR_PAT];
	vmx_nested_software_msrs_capture(vcpu,
	    &restore->rollback_software);
	error = vmx_nested_vmcs_registry_read(
	    &vcpu->vmx->nested_vmcs_registry, restore->id.vmcs12_gpa,
	    vcpu->vcpuid, VMCS_EXIT_REASON,
	    &restore->vmcs12_exit_reason);
	if (error == 0)
		error = vmx_nested_vmcs_registry_read(
		    &vcpu->vmx->nested_vmcs_registry, restore->id.vmcs12_gpa,
		    vcpu->vcpuid, VMCS_EXIT_QUALIFICATION,
		    &restore->vmcs12_exit_qualification);
	return (error);
}

static int
vmx_nested_l1_restore_begin(void *arg,
    const struct vmx_nested_vmcs02_id *id)
{
	struct vmx_nested_l1_restore_intel *restore;
	struct vmx_vcpu *vcpu;
	int error;

	restore = arg;
	if (restore == NULL || id == NULL || restore->vcpu == NULL ||
	    restore->active)
		return (EINVAL);
	vcpu = restore->vcpu;
	if (id->vmcs12_gpa != vcpu->nested.machine.current_vmcs_gpa)
		return (ESTALE);
	restore->id = *id;
	restore->vmcs12_changed = false;
	restore->nextrip_pending = false;
	sx_xlock(&vcpu->vmx->nested_vmcs_sx);
	error = vmx_nested_l1_restore_capture(restore);
	if (error != 0) {
		sx_xunlock(&vcpu->vmx->nested_vmcs_sx);
		memset(&restore->id, 0, sizeof(restore->id));
		return (error);
	}
	restore->active = true;
	return (0);
}

static int
vmx_nested_l1_processor_apply(struct vmx_nested_l1_restore_intel *restore,
    const struct vmx_nested_guest_control_state *control,
    const struct vmx_nested_guest_arch_state *arch)
{
	static const int segment_regs[VMX_NESTED_GUEST_SEGMENT_COUNT] = {
		[VMX_NESTED_GUEST_ES] = VM_REG_GUEST_ES,
		[VMX_NESTED_GUEST_CS] = VM_REG_GUEST_CS,
		[VMX_NESTED_GUEST_SS] = VM_REG_GUEST_SS,
		[VMX_NESTED_GUEST_DS] = VM_REG_GUEST_DS,
		[VMX_NESTED_GUEST_FS] = VM_REG_GUEST_FS,
		[VMX_NESTED_GUEST_GS] = VM_REG_GUEST_GS,
		[VMX_NESTED_GUEST_TR] = VM_REG_GUEST_TR,
		[VMX_NESTED_GUEST_LDTR] = VM_REG_GUEST_LDTR,
	};
	const struct vmx_nested_guest_segment *segment;
	struct seg_desc desc;
	struct vmx_vcpu *vcpu;
	size_t i;
	int error;

	if (restore == NULL || !restore->active || control == NULL ||
	    arch == NULL)
		return (EINVAL);
	vcpu = restore->vcpu;
#define	NVMX_L1_SETREG(reg, value) do {				\
	error = vmx_setreg(vcpu, (reg), (value));			\
	if (error != 0)						\
		return (error);						\
} while (0)
#define	NVMX_L1_SETDIRECT(encoding, value) do {			\
	error = vmx_nested_l1_direct_set(vcpu, (encoding), (value));	\
	if (error != 0)						\
		return (error);						\
} while (0)
	NVMX_L1_SETREG(VM_REG_GUEST_CR0, control->cr0);
	NVMX_L1_SETREG(VM_REG_GUEST_CR3, control->cr3);
	NVMX_L1_SETREG(VM_REG_GUEST_CR4, control->cr4);
	NVMX_L1_SETREG(VM_REG_GUEST_DR7, control->dr7);
	NVMX_L1_SETREG(VM_REG_GUEST_EFER, control->efer);
	NVMX_L1_SETDIRECT(VMCS_GUEST_IA32_SYSENTER_CS,
	    control->sysenter_cs);
	NVMX_L1_SETDIRECT(VMCS_GUEST_IA32_SYSENTER_ESP,
	    control->sysenter_esp);
	NVMX_L1_SETDIRECT(VMCS_GUEST_IA32_SYSENTER_EIP,
	    control->sysenter_eip);
	for (i = 0; i < VMX_NESTED_GUEST_SEGMENT_COUNT; i++) {
		segment = &arch->segment[i];
		NVMX_L1_SETREG(segment_regs[i], segment->selector);
		desc.base = segment->base;
		desc.limit = segment->limit;
		desc.access = segment->access;
		error = vmx_setdesc(vcpu, segment_regs[i], &desc);
		if (error != 0)
			return (error);
	}
	desc.base = arch->gdtr_base;
	desc.limit = arch->gdtr_limit;
	desc.access = 0;
	error = vmx_setdesc(vcpu, VM_REG_GUEST_GDTR, &desc);
	if (error != 0)
		return (error);
	desc.base = arch->idtr_base;
	desc.limit = arch->idtr_limit;
	desc.access = 0;
	error = vmx_setdesc(vcpu, VM_REG_GUEST_IDTR, &desc);
	if (error != 0)
		return (error);
	NVMX_L1_SETREG(VM_REG_GUEST_RSP, arch->rsp);
	NVMX_L1_SETREG(VM_REG_GUEST_RIP, arch->rip);
	NVMX_L1_SETREG(VM_REG_GUEST_RFLAGS, arch->rflags);
	NVMX_L1_SETDIRECT(VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
	    arch->pending_debug);
	NVMX_L1_SETDIRECT(VMCS_GUEST_IA32_DEBUGCTL,
	    arch->debugctl);
	NVMX_L1_SETDIRECT(VMCS_GUEST_ACTIVITY, arch->activity);
	NVMX_L1_SETDIRECT(VMCS_GUEST_INTERRUPTIBILITY,
	    arch->interruptibility);
	vcpu->guest_msrs[IDX_MSR_PAT] = control->pat;
	if (restore->apply_pdpte != NULL &&
	    restore->apply_pdpte->active) {
		NVMX_L1_SETDIRECT(VMCS_GUEST_PDPTE0,
		    restore->apply_pdpte->value[0]);
		NVMX_L1_SETDIRECT(VMCS_GUEST_PDPTE1,
		    restore->apply_pdpte->value[1]);
		NVMX_L1_SETDIRECT(VMCS_GUEST_PDPTE2,
		    restore->apply_pdpte->value[2]);
		NVMX_L1_SETDIRECT(VMCS_GUEST_PDPTE3,
		    restore->apply_pdpte->value[3]);
	}
	if (restore->apply_software != NULL)
		vmx_nested_software_msrs_publish(vcpu,
		    restore->apply_software);
	/*
	 * VMCS01 RIP has changed, but defer the machine-independent nextrip
	 * cache until the final commit.  A later transactional failure can
	 * then roll VMCS01 back without also reconstructing hidden core
	 * state.
	 */
	restore->nextrip = arch->rip;
	restore->nextrip_pending = true;
#undef NVMX_L1_SETDIRECT
#undef NVMX_L1_SETREG
	return (0);
}

static int
vmx_nested_l1_restore_apply(void *arg,
    const struct vmx_nested_failed_entry_state_plan *plan)
{

	if (plan == NULL)
		return (EINVAL);
	return (vmx_nested_l1_processor_apply(arg, &plan->l1_control,
	    &plan->l1_arch));
}

static int
vmx_nested_l1_restore_vmcs12(void *arg,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_vmentry_result *failure)
{
	struct vmx_nested_l1_restore_intel *restore;
	int error;

	restore = arg;
	if (restore == NULL || !restore->active ||
	    !vmx_nested_vmcs02_id_equal(id, &restore->id))
		return (ESTALE);
	error = vmx_nested_vmcs_registry_commit_vmentry_failure(
	    &restore->vcpu->vmx->nested_vmcs_registry, id->vmcs12_gpa,
	    restore->vcpu->vcpuid, failure);
	if (error == 0)
		restore->vmcs12_changed = true;
	return (error);
}

static int
vmx_nested_l1_restore_commit(void *arg)
{
	struct vmx_nested_l1_restore_intel *restore;

	restore = arg;
	if (restore == NULL || !restore->active)
		return (EINVAL);
	if (restore->nextrip_pending) {
		/*
		 * VMCS01 RIP was already restored by the transactional machine
		 * adapter.  Publish only the machine-independent next-run
		 * cache here.  Calling vm_set_register() would redispatch
		 * through the current architectural owner and can target a
		 * detached cold L2 rather than VMCS01.
		 */
		restore->vcpu->state.nextrip = restore->nextrip;
		vm_set_nextrip(restore->vcpu->vcpu, restore->nextrip);
		restore->nextrip_pending = false;
	}
	restore->active = false;
	sx_xunlock(&restore->vcpu->vmx->nested_vmcs_sx);
	return (0);
}

static void
vmx_nested_l1_restore_abort(void *arg)
{
	struct vmx_nested_l1_restore_intel *restore;
	struct vmx_vcpu *vcpu;
	size_t i;
	int error;

	restore = arg;
	if (restore == NULL || !restore->active)
		panic("%s: no active L1 restore", __func__);
	vcpu = restore->vcpu;
	vcpu->guest_msrs[IDX_MSR_PAT] = restore->pat;
	vmx_nested_software_msrs_publish(vcpu,
	    &restore->rollback_software);
	for (i = nitems(vmx_nested_l1_restore_descs); i-- > 0;) {
		error = vmx_setdesc(vcpu, vmx_nested_l1_restore_descs[i],
		    &restore->descs[i]);
		if (error != 0)
			panic("%s: descriptor rollback failed: %d", __func__,
			    error);
	}
	for (i = nitems(vmx_nested_l1_restore_regs); i-- > 0;) {
		error = vmx_setreg(vcpu, vmx_nested_l1_restore_regs[i],
		    restore->regs[i]);
		if (error != 0)
			panic("%s: register rollback failed: %d", __func__,
			    error);
	}
	for (i = nitems(vmx_nested_l1_restore_direct); i-- > 0;) {
		error = vmx_nested_l1_direct_set(vcpu,
		    vmx_nested_l1_restore_direct[i], restore->direct[i]);
		if (error != 0)
			panic("%s: VMCS01 rollback failed: %d", __func__,
			    error);
	}
	if (restore->vmcs12_changed) {
		error = vmx_nested_vmcs_registry_write(
		    &vcpu->vmx->nested_vmcs_registry,
		    restore->id.vmcs12_gpa, vcpu->vcpuid,
		    VMCS_EXIT_REASON,
		    restore->vmcs12_exit_reason);
		if (error == 0)
			error = vmx_nested_vmcs_registry_write(
			    &vcpu->vmx->nested_vmcs_registry,
			    restore->id.vmcs12_gpa, vcpu->vcpuid,
			    VMCS_EXIT_QUALIFICATION,
			    restore->vmcs12_exit_qualification);
		if (error != 0)
			panic("%s: VMCS12 rollback failed: %d", __func__,
			    error);
	}
	restore->nextrip_pending = false;
	restore->active = false;
	sx_xunlock(&vcpu->vmx->nested_vmcs_sx);
}

static int
vmx_nested_l1_exit_begin(void *arg,
    const struct vmx_nested_vmcs02_id *id)
{
	struct vmx_nested_l1_exit_intel *exit;
	struct vmx_vcpu *vcpu;
	int error;

	exit = arg;
	if (exit == NULL || exit->state_input == NULL ||
	    exit->information == NULL || exit->execution_epoch == 0 ||
	    exit->l1_msrs_ready)
		return (EINVAL);
	vcpu = exit->restore.vcpu;
	/*
	 * Hot VMCS02 capture is destructive: the run loop has already
	 * captured L2's software-owned MSRs, installed L1's bank, and
	 * committed that CPU-local transition before returning to the frozen
	 * owner.  A cold reflection carries the same value-only invariant
	 * after an earlier freeze detached all CPU-local ownership.  Never
	 * access per-CPU MSRs from this sleepable transaction.
	 */
	if (vcpu == NULL ||
	    (vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED &&
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD) ||
	    vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_count != 0 ||
	    vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1)
		return (EINVAL);
	error = vmx_nested_l1_restore_begin(&exit->restore, id);
	if (error != 0)
		return (error);
	exit->l1_msrs_ready = true;
	return (0);
}

static int
vmx_nested_l1_exit_stage_vmcs12(void *arg,
    const struct vmx_nested_vmcs02_id *id)
{
	struct vmx_nested_l1_exit_intel *exit;
	struct vmx_vcpu *vcpu;

	exit = arg;
	if (exit == NULL || !exit->restore.active || !exit->l1_msrs_ready ||
	    !vmx_nested_vmcs02_id_equal(id, &exit->restore.id))
		return (ESTALE);
	vcpu = exit->restore.vcpu;
	return (vmx_nested_vmcs_registry_prepare_vmexit(
	    &vcpu->vmx->nested_vmcs_registry, id->vmcs12_gpa,
	    vcpu->vcpuid, exit->state_input, exit->information,
	    exit->execution_epoch, vcpu->nested_vmcs_scratch,
	    VMX_NESTED_VMCS_REGION_SIZE));
}

static int
vmx_nested_l1_exit_apply(void *arg,
    const struct vmx_nested_vmexit_state_plan *plan)
{
	struct vmx_nested_l1_exit_intel *exit;

	exit = arg;
	if (exit == NULL || plan == NULL || !exit->l1_msrs_ready)
		return (EINVAL);
	exit->restore.apply_pdpte = &plan->l1_pdpte;
	return (vmx_nested_l1_processor_apply(&exit->restore,
	    &plan->l1_control, &plan->l1_arch));
}

static int
vmx_nested_l1_exit_publish_vmcs12(void *arg,
    const struct vmx_nested_vmcs02_id *id)
{
	struct vmx_nested_l1_exit_intel *exit;
	struct vmx_vcpu *vcpu;

	exit = arg;
	if (exit == NULL || !exit->restore.active || !exit->l1_msrs_ready ||
	    !vmx_nested_vmcs02_id_equal(id, &exit->restore.id))
		return (ESTALE);
	vcpu = exit->restore.vcpu;
	return (vmx_nested_vmcs_registry_publish_vmexit(
	    &vcpu->vmx->nested_vmcs_registry, id->vmcs12_gpa,
	    vcpu->vcpuid, vcpu->nested_vmcs_scratch,
	    VMX_NESTED_VMCS_REGION_SIZE, exit->execution_epoch));
}

static void
vmx_nested_l1_exit_finish(void *arg)
{
	struct vmx_nested_l1_exit_intel *exit;
	int error;

	exit = arg;
	if (exit == NULL || !exit->restore.active || !exit->l1_msrs_ready)
		panic("%s: incomplete nested exit", __func__);
	exit->l1_msrs_ready = false;
	error = vmx_nested_l1_restore_commit(&exit->restore);
	if (error != 0)
		panic("%s: L1 restore commit failed: %d", __func__, error);
}

static void
vmx_nested_l1_exit_abort(void *arg)
{
	struct vmx_nested_l1_exit_intel *exit;

	exit = arg;
	if (exit == NULL || !exit->restore.active)
		panic("%s: no active nested exit", __func__);
	exit->l1_msrs_ready = false;
	vmx_nested_l1_restore_abort(&exit->restore);
}

static const struct vmx_nested_l1_exit_ops
vmx_nested_l1_exit_intel_ops = {
	.begin = vmx_nested_l1_exit_begin,
	.stage_vmcs12 = vmx_nested_l1_exit_stage_vmcs12,
	.apply_l1 = vmx_nested_l1_exit_apply,
	.publish_vmcs12 = vmx_nested_l1_exit_publish_vmcs12,
	.finish = vmx_nested_l1_exit_finish,
	.abort = vmx_nested_l1_exit_abort,
};

struct vmx_nested_outer_exit_intel {
	struct vmx_nested_exit_information information;
	struct vmx_nested_exit_provenance provenance;
	struct vmx_nested_exit_context context;
	enum vmx_nested_outer_exit_dispatch dispatch;
	enum vmx_nested_exit_action action;
};

/*
 * Route one already captured VMCS02 exit without relinquishing VMCS02.
 * vmx_nested_hardware_report_intel() is the sole hardware reader; this stage
 * derives only the provenance the outer VMCS02 owner can know and either
 * returns a complete routing decision or explicitly defers a composed-EPT
 * fault to the frozen software walk.
 */
static int
vmx_nested_exit_intel_prepare(struct vmx_vcpu *vcpu,
    const struct vmx_nested_exit_information *information,
    bool l0_must_handle, struct vmx_nested_outer_exit_intel *exit)
{
	struct vmx_nested_dynamic_exit dynamic;
	struct vmx_nested_outer_exit_facts facts;
	struct vmx_nested_outer_exit_intel candidate;
	struct vmx_nested_exit_context context_candidate;
	struct vmx_nested_exit_policy policy;
	struct vmx_nested_exit_provenance provenance;
	enum vmx_nested_outer_exit_dispatch dispatch;
	enum vmx_nested_exit_action action_candidate;
	const struct vmx_nested_vmcs02_id *id;
	uint32_t gpr;
	int error;

	if (vcpu == NULL || information == NULL || exit == NULL ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_GUEST)
		return (EINVAL);
	id = &vcpu->nested_vmcs02_plan.id;
	if (!vmx_nested_vmcs02_id_equal(id, &vcpu->nested_entry_runtime.id))
		return (ESTALE);
	memset(&facts, 0, sizeof(facts));
	facts.l0_must_handle = l0_must_handle;
	facts.l1_ept_enabled =
	    vcpu->nested_vmcs02_plan.image.ept_enabled;
	facts.l1_preemption_timer_armed =
	    vcpu->nested_vmcs02_plan.image.preemption_timer_enabled &&
	    vcpu->nested_vmcs02_plan.image.preemption_timer.armed;
	error = vmx_nested_outer_exit_prepare(information, &facts,
	    &dispatch, &provenance);
	if (error != 0)
		return (error);
	memset(&candidate, 0, sizeof(candidate));
	candidate.information = *information;
	candidate.provenance = provenance;
	candidate.dispatch = dispatch;
	if (dispatch == VMX_NESTED_OUTER_EXIT_EPT_WALK) {
		*exit = candidate;
		return (0);
	}
	error = vmx_nested_exit_policy_prepare(
	    &vcpu->nested_vmcs12_snapshot.controls,
	    &vcpu->nested_vmcs12_snapshot.execution, &provenance, &policy);
	if (error != 0)
		return (error);
	error = vmx_nested_exit_context_prepare(information,
	    &policy, &context_candidate);
	if (error != 0)
		return (error);

	memset(&dynamic, 0, sizeof(dynamic));
	if (vmx_nested_exit_reason_is_dynamic(context_candidate.reason)) {
		dynamic.controls = &vcpu->nested_vmcs12_snapshot.controls;
		dynamic.execution = &vcpu->nested_vmcs12_snapshot.execution;
		dynamic.io_policy = vcpu->nested_l1_io_bitmap;
		dynamic.msr_policy = vcpu->nested_l1_msr_bitmap;
		dynamic.qualification =
		    information->exit_qualification;
		dynamic.reason = context_candidate.reason;
		if (context_candidate.reason == EXIT_REASON_CR_ACCESS) {
			gpr = (information->exit_qualification >> 8) &
			    0xf;
			dynamic.gpr_value = vmx_get_guest_reg(vcpu, gpr);
		} else if (context_candidate.reason == EXIT_REASON_RDMSR ||
		    context_candidate.reason == EXIT_REASON_WRMSR)
			dynamic.msr_index = (uint32_t)vcpu->ctx.guest_rcx;
		error = vmx_nested_exit_dispatch_prepare(
		    information, &policy, &dynamic,
		    &context_candidate, &action_candidate);
	} else {
		error = vmx_nested_exit_dispatch_prepare(
		    information, &policy, NULL,
		    &context_candidate, &action_candidate);
	}
	if (error != 0)
		return (error);
	candidate.context = context_candidate;
	candidate.action = action_candidate;
	*exit = candidate;
	return (0);
}

struct vmx_nested_captured_exit_commit {
	struct vmx_vcpu *vcpu;
	const struct vmx_nested_exit_information *information;
	const struct vmx_nested_l2_runtime_state *l2_runtime;
};

static const struct vmx_nested_exit_msr_store_ops
vmx_nested_exit_msr_store_virtual_ops = {
	.read = vmx_nested_virtual_msr_read,
};

static bool
vmx_nested_exit_msr_guest_failure(enum vmx_nested_msr_failure failure)
{

	switch (failure) {
	case VMX_NESTED_MSR_COUNT:
	case VMX_NESTED_MSR_ADDRESS:
	case VMX_NESTED_MSR_MEMORY:
	case VMX_NESTED_MSR_RESERVED:
	case VMX_NESTED_MSR_FORBIDDEN:
	case VMX_NESTED_MSR_VALUE:
		return (true);
	case VMX_NESTED_MSR_OK:
	case VMX_NESTED_MSR_PREREQUISITE:
	case VMX_NESTED_MSR_CAPACITY:
	case VMX_NESTED_MSR_RUNTIME:
	default:
		return (false);
	}
}

/*
 * Complete the Intel-ordered VM-exit MSR transaction in the frozen domain.
 * The handoff's L2 runtime and software bank are already value-only, so no
 * per-CPU MSR or VMCS02 access occurs here.  The phase machine makes the
 * guest-memory store boundary retry-safe.
 */
static int
vmx_nested_exit_msrs_prepare(struct vmx_vcpu *vcpu,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_l2_runtime_state *l2_runtime,
    const struct vmx_nested_vmexit_state_plan *base,
    struct vmx_nested_vmexit_state_plan *plan,
    const struct vmx_nested_software_msrs **software)
{
	struct vmx_nested_guest_memory_intel guest_memory;
	struct vmx_nested_guest_arch_state l1_validation_arch, l2_arch;
	struct vmx_nested_guest_control_state l1_validation_control;
	struct vmx_nested_guest_control_state l2_control;
	struct vmx_nested_software_msrs l1_validation_software;
	struct vmx_nested_vmexit_state_plan load_base;
	struct vmx_nested_virtual_msr l1_virtual, l2_virtual;
	struct vmx_nested_msr_policy l1_policy, l2_policy;
	enum vmx_nested_exit_msr_load_outcome load_outcome;
	enum vmx_nested_exit_msr_store_outcome store_outcome;
	enum vmx_nested_msr_failure failure;
	enum vmx_nested_pdpte_failure pdpte_failure;
	struct vmx_nested_exit_msr_transaction *transaction;
	const struct vmx_nested_memory *memory;
	const struct vmx_nested_vmcs12_snapshot *snapshot;
	uint32_t count, failed_entry;
	int error, transition_error;

	if (vcpu == NULL || id == NULL || l2_runtime == NULL ||
	    base == NULL || plan == NULL || software == NULL ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    !vcpu->nested_msr_workspace.active ||
	    vcpu->nested_msr_generation == 0)
		return (EINVAL);
	transaction = &vcpu->nested_exit_msr_transaction;
	snapshot = &vcpu->nested_vmcs12_snapshot;
	error = vmx_nested_exit_msr_transaction_validate(transaction);
	if (error != 0)
		return (error);
	if (transaction->state == VMX_NESTED_EXIT_MSR_TRANSACTION_IDLE) {
		if (vcpu->nested_exit_msr_plan_valid)
			return (EPROTO);
		error = vmx_nested_exit_msr_transaction_begin(transaction,
		    id->execution_epoch,
		    snapshot->controls.exit_msr_store_count,
		    snapshot->controls.exit_msr_load_count);
		if (error != 0)
			return (error);
	}
	if (transaction->generation != id->execution_epoch ||
	    transaction->store_count !=
	    snapshot->controls.exit_msr_store_count ||
	    transaction->load_count !=
	    snapshot->controls.exit_msr_load_count)
		return (ESTALE);
	memory = NULL;
	if (transaction->state ==
	    VMX_NESTED_EXIT_MSR_TRANSACTION_ACTIVE &&
	    transaction->store_count != 0) {
		error = vmx_nested_guest_memory_intel_init(&guest_memory,
		    vcpu->vcpu);
		if (error != 0)
			return (error);
		memory = vmx_nested_guest_memory_intel_memory(&guest_memory);
		if (memory == NULL)
			return (EPROTO);
	}

	if (transaction->state ==
	    VMX_NESTED_EXIT_MSR_TRANSACTION_ACTIVE) {
		l2_control = l2_runtime->control;
		l2_arch = l2_runtime->arch;
		memset(&l2_virtual, 0, sizeof(l2_virtual));
		l2_virtual.capabilities = &snapshot->capabilities;
		l2_virtual.control = &l2_control;
		l2_virtual.arch = &l2_arch;
		l2_virtual.software = &vcpu->nested_l2_software_msrs;
		l2_virtual.syscall_available = true;
		l2_virtual.tsc_aux_available = vmx_have_msr_tsc_aux;
		memset(&l2_policy, 0, sizeof(l2_policy));
		l2_policy.validate_read =
		    vmx_nested_virtual_msr_validate_read;
		l2_policy.arg = &l2_virtual;
		failure = VMX_NESTED_MSR_OK;
		failed_entry = 0;
		store_outcome = VMX_NESTED_EXIT_MSR_STORE_OK;
		error = vmx_nested_exit_msr_store_execute(
		    &snapshot->capabilities,
		    snapshot->controls.exit_msr_store_address,
		    snapshot->controls.exit_msr_store_count,
		    l2_runtime->arch.in_smm, memory, &l2_policy,
		    &vmx_nested_exit_msr_store_virtual_ops, &l2_virtual,
		    &store_outcome, &failure, &failed_entry);
		if (error != 0) {
			transition_error =
			    vmx_nested_exit_msr_transaction_store_result(
			    transaction, store_outcome);
			if (transition_error != 0)
				return (transition_error);
			return (store_outcome ==
			    VMX_NESTED_EXIT_MSR_STORE_ABORT_1_PARTIAL ?
			    ECANCELED : EIO);
		}
		transition_error =
		    vmx_nested_exit_msr_transaction_store_result(transaction,
		    store_outcome);
		if (transition_error != 0)
			return (transition_error);
	}

	if (transaction->state ==
	    VMX_NESTED_EXIT_MSR_TRANSACTION_STORE_COMMITTED) {
		if (memory == NULL && (transaction->load_count != 0 ||
		    vmx_nested_host_pdpte_active(&base->l1_host))) {
			error = vmx_nested_guest_memory_intel_init(
			    &guest_memory, vcpu->vcpu);
			if (error != 0)
				return (error);
			memory = vmx_nested_guest_memory_intel_memory(
			    &guest_memory);
			if (memory == NULL)
				return (EPROTO);
		}
		load_base = *base;
		pdpte_failure = VMX_NESTED_PDPTE_OK;
		error = vmx_nested_host_pdpte_snapshot(
		    &snapshot->capabilities, &load_base.l1_host, memory,
		    &load_base.l1_pdpte, &pdpte_failure);
		if (error != 0) {
			transition_error =
			    vmx_nested_exit_msr_transaction_abort(
			    transaction, 2);
			if (transition_error != 0)
				return (transition_error);
			return (ECANCELED);
		}
		l1_validation_control = load_base.l1_control;
		l1_validation_arch = load_base.l1_arch;
		l1_validation_software = vcpu->nested_l1_software_msrs;
		memset(&l1_virtual, 0, sizeof(l1_virtual));
		l1_virtual.capabilities = &snapshot->capabilities;
		l1_virtual.control = &l1_validation_control;
		l1_virtual.arch = &l1_validation_arch;
		l1_virtual.software = &l1_validation_software;
		l1_virtual.syscall_available = true;
		l1_virtual.tsc_aux_available = vmx_have_msr_tsc_aux;
		memset(&l1_policy, 0, sizeof(l1_policy));
		l1_policy.validate_write =
		    vmx_nested_virtual_msr_validate_write;
		l1_policy.arg = &l1_virtual;
		failure = VMX_NESTED_MSR_OK;
		failed_entry = 0;
		count = 0;
		error = vmx_nested_exit_msr_load_snapshot(
		    &snapshot->capabilities,
		    snapshot->controls.exit_msr_load_address,
		    snapshot->controls.exit_msr_load_count,
		    l2_runtime->arch.in_smm, memory, &l1_policy,
		    vcpu->nested_msr_workspace.plan,
		    vcpu->nested_msr_workspace.capacity, &count, &failure,
		    &failed_entry);
		if (error != 0) {
			load_outcome =
			    vmx_nested_exit_msr_guest_failure(failure) ?
			    VMX_NESTED_EXIT_MSR_LOAD_ABORT_4_ROLLED_BACK :
			    VMX_NESTED_EXIT_MSR_LOAD_HOST_FAILED;
			transition_error =
			    vmx_nested_exit_msr_transaction_load_result(
			    transaction, load_outcome);
			if (transition_error != 0)
				return (transition_error);
			return (load_outcome ==
			    VMX_NESTED_EXIT_MSR_LOAD_ABORT_4_ROLLED_BACK ?
			    ECANCELED : EIO);
		}
		load_outcome = VMX_NESTED_EXIT_MSR_LOAD_HOST_FAILED;
		failed_entry = 0;
		error = vmx_nested_vmexit_msr_load_prepare(
		    &snapshot->capabilities, &load_base,
		    &vcpu->nested_l1_software_msrs, true,
		    vmx_have_msr_tsc_aux, vcpu->nested_msr_workspace.plan,
		    count, vcpu->nested_msr_workspace.rollback,
		    vcpu->nested_msr_workspace.capacity,
		    &vcpu->nested_exit_msr_plan,
		    &vcpu->nested_exit_msr_software, &load_outcome,
		    &failed_entry);
		transition_error =
		    vmx_nested_exit_msr_transaction_load_result(transaction,
		    load_outcome);
		if (transition_error != 0)
			return (transition_error);
		if (error != 0)
			return (load_outcome ==
			    VMX_NESTED_EXIT_MSR_LOAD_ABORT_4_ROLLED_BACK ?
			    ECANCELED : EIO);
		vcpu->nested_exit_msr_plan_valid = true;
	}
	if (transaction->state !=
	    VMX_NESTED_EXIT_MSR_TRANSACTION_LOAD_APPLIED ||
	    !vcpu->nested_exit_msr_plan_valid)
		return (transaction->state ==
		    VMX_NESTED_EXIT_MSR_TRANSACTION_ABORTED ? ECANCELED :
		    EIO);
	*plan = vcpu->nested_exit_msr_plan;
	*software = &vcpu->nested_exit_msr_software;
	return (0);
}

static int
vmx_nested_commit_captured_exit_apply(void *arg,
    const struct vmx_nested_vmcs02_id *commit_id)
{
	struct vmx_nested_captured_exit_commit *commit;
	struct vmx_nested_l1_exit_result result;
	struct vmx_nested_l1_exit_intel exit;
	struct vmx_nested_vmexit_state_input input;
	struct vmx_nested_vmexit_state_plan base_plan, plan;
	const struct vmx_nested_software_msrs *l1_software;
	const struct vmx_nested_vmcs02_id *id;
	const struct vmx_nested_vmcs02_image *image;
	struct vmx_vcpu *vcpu;
	const struct vmx_nested_exit_information *information;
	const struct vmx_nested_l2_runtime_state *l2_runtime;
	int error;

	commit = arg;
	if (commit == NULL || commit_id == NULL || commit->vcpu == NULL ||
	    commit->information == NULL || commit->l2_runtime == NULL)
		return (EINVAL);
	vcpu = commit->vcpu;
	information = commit->information;
	l2_runtime = commit->l2_runtime;
	if (!vcpu->nested_vmcs02_plan_valid)
		return (EINVAL);
	id = &vcpu->nested_vmcs02_plan.id;
	if (!vmx_nested_vmcs02_id_equal(commit_id, id))
		return (ESTALE);
	image = &vcpu->nested_vmcs02_plan.image;
	if ((vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED &&
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD) ||
	    !vmx_nested_vmcs02_id_equal(id, &vcpu->nested_entry_runtime.id))
		return (ESTALE);

	memset(&input, 0, sizeof(input));
	input.l1_host = &image->l1_host;
	input.l2_runtime = l2_runtime;
	input.vmcs12_control = &image->vmcs12_control;
	input.vmcs12_arch = &image->vmcs12_arch;
	input.vmexit = image->vmcs12_vmexit;
	input.vmcs12_vmentry = image->vmcs12_vmentry;
	input.vmcs12_entry_intr_info = image->vmcs12_entry_intr_info;
	input.save_guest_lma = image->save_guest_lma;
	error = vmx_nested_vmexit_state_prepare(&input, &base_plan);
	if (error != 0)
		return (error);
	error = vmx_nested_exit_msrs_prepare(vcpu, id, l2_runtime,
	    &base_plan, &plan, &l1_software);
	if (error != 0)
		return (error);

	memset(&exit, 0, sizeof(exit));
	exit.restore.vcpu = vcpu;
	exit.restore.apply_software = l1_software;
	exit.state_input = &input;
	exit.information = information;
	exit.execution_epoch = id->execution_epoch;
	error = vmx_nested_l1_restore_vmexit(id, &plan,
	    &vmx_nested_l1_exit_intel_ops, &exit, &result);
	if (error != 0)
		return (error);
	error = vmx_nested_exit_msr_transaction_commit(
	    &vcpu->nested_exit_msr_transaction);
	if (error != 0)
		panic("%s: committed L1 exit lost MSR transaction: %d",
		    __func__, error);
	error = vmx_nested_entry_runtime_exit_committed(
	    &vcpu->nested_entry_runtime, id);
	if (error != 0)
		panic("%s: committed exit lost runtime ownership: %d",
		    __func__, error);
	return (0);
}

static int
vmx_nested_publish_exit_abort_intel(void *arg,
    const struct vmx_nested_vmcs02_id *id, uint32_t indicator)
{
	struct vmx_vcpu *vcpu;
	int error;

	vcpu = arg;
	if (vcpu == NULL || id == NULL ||
	    indicator !=
	    vcpu->nested_exit_msr_transaction.abort_indicator ||
	    !vmx_nested_vmcs02_id_equal(id, &vcpu->nested_vmcs02_plan.id))
		return (ESTALE);
	sx_xlock(&vcpu->vmx->nested_vmcs_sx);
	error = vmx_nested_vmcs_registry_set_abort_indicator(
	    &vcpu->vmx->nested_vmcs_registry, id->vmcs12_gpa,
	    vcpu->vcpuid, indicator);
	sx_xunlock(&vcpu->vmx->nested_vmcs_sx);
	return (error);
}

static int
vmx_nested_commit_captured_exit(struct vmx_vcpu *vcpu)
{
	static const struct vmx_nested_vmexit_commit_ops commit_ops = {
		.commit = vmx_nested_commit_captured_exit_apply,
	};
	static const struct vmx_nested_vmexit_abort_ops abort_ops = {
		.publish = vmx_nested_publish_exit_abort_intel,
	};
	struct vmx_nested_captured_exit_commit commit;
	struct vmx_nested_vmexit_handoff_request consumed;
	const struct vmx_nested_vmexit_handoff_request *request;
	const struct vmx_nested_vmcs02_id *id;
	bool cold;
	int error;

	if (vcpu == NULL || !vcpu->nested_vmcs02_plan_valid ||
	    vcpu->nested.internal.kind != VMX_NESTED_INTERNAL_VMEXIT)
		return (EINVAL);
	id = &vcpu->nested_vmcs02_plan.id;
	request = &vcpu->nested.internal.operation.vmexit.request;
	if (!vmx_nested_vmcs02_id_equal(&request->id, id))
		return (ESTALE);
	cold = vcpu->nested_entry_runtime.state ==
	    VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD;
	commit.vcpu = vcpu;
	commit.information = &request->information;
	commit.l2_runtime = &request->l2_runtime;
	error = vmx_nested_context_commit_published_vmexit(&vcpu->nested,
	    true, &commit_ops, &commit, &consumed);
	if (error != 0 &&
	    vcpu->nested_exit_msr_transaction.state ==
	    VMX_NESTED_EXIT_MSR_TRANSACTION_ABORTED) {
		error = vmx_nested_context_abort_published_vmexit(
		    &vcpu->nested, true,
		    vcpu->nested_exit_msr_transaction.abort_indicator,
		    &abort_ops, vcpu, &consumed);
		if (error != 0)
			return (error);
		error = vmx_nested_entry_runtime_exit_committed(
		    &vcpu->nested_entry_runtime, id);
		if (error != 0)
			panic("%s: aborted exit lost runtime ownership: %d",
			    __func__, error);
		if (cold)
			vmx_nested_cold_reflected_entry_release(vcpu);
		else
			vmx_nested_completed_entry_release(vcpu);
		return (0);
	}
	if (error != 0 &&
	    vcpu->nested_exit_msr_transaction.state ==
	    VMX_NESTED_EXIT_MSR_TRANSACTION_POISONED) {
		error = vmx_nested_entry_runtime_exit_poison(
		    &vcpu->nested_entry_runtime, id);
		if (error != 0)
			panic("%s: cannot quarantine poisoned exit: %d",
			    __func__, error);
		return (EIO);
	}
	if (error != 0)
		return (error);
	if (!vmx_nested_vmcs02_id_equal(&consumed.id, id))
		panic("%s: consumed nested exit changed ownership", __func__);
	/*
	 * The reflected exit is now architecturally visible and the context
	 * is back in ROOT.  Release the retained VMCS02 resources without
	 * invoking the ENTRY_PENDING cancellation path: that path belongs
	 * only to a prepared entry which never reached L2.
	 */
	if (cold)
		vmx_nested_cold_reflected_entry_release(vcpu);
	else
		vmx_nested_completed_entry_release(vcpu);
	return (0);
}

static int
vmx_nested_commit_rejected_entry(void *arg,
    const struct vmx_nested_vmentry_resolution *resolution)
{
	static const struct vmx_nested_l1_restore_ops restore_ops = {
		.begin = vmx_nested_l1_restore_begin,
		.apply_l1 = vmx_nested_l1_restore_apply,
		.commit_vmcs12 = vmx_nested_l1_restore_vmcs12,
		.commit = vmx_nested_l1_restore_commit,
		.abort = vmx_nested_l1_restore_abort,
	};
	struct vmx_nested_failed_entry_state_input failed_input;
	struct vmx_nested_failed_entry_state_plan failed_plan;
	const struct vmx_nested_failed_entry_state_plan *apply_plan;
	const struct vmx_nested_software_msrs *apply_software;
	struct vmx_nested_l1_restore_intel restore;
	struct vmx_nested_l1_restore_result restore_result;
	struct vmx_nested_rejected_entry_commit *commit;
	struct vmx_vcpu *vcpu;
	uint64_t old_error, old_rflags, old_rip;
	int error, rollback_error;

	commit = arg;
	if (commit == NULL || commit->vcpu == NULL)
		return (EINVAL);
	vcpu = commit->vcpu;
	if (resolution == NULL ||
	    resolution->id.vmcs12_gpa !=
	    vcpu->nested.machine.current_vmcs_gpa)
		return (ESTALE);

	if (resolution->result.disposition ==
	    VMX_NESTED_VMENTRY_ENTRY_FAILURE) {
		if (commit->snapshot == NULL || commit->environment == NULL)
			return (EINVAL);
		failed_input.l1_host = &commit->snapshot->host;
		failed_input.pre_entry_l1 =
		    &commit->environment->l1_runtime;
		failed_input.vmexit = commit->snapshot->controls.vmexit;
		error = vmx_nested_failed_entry_state_prepare(&failed_input,
		    &failed_plan);
		if (error != 0)
			return (error);
		error = vmx_nested_failed_entry_msrs_prepare(vcpu,
		    &resolution->id, &failed_plan, &apply_plan,
		    &apply_software);
		if (error != 0)
			return (error);
		memset(&restore, 0, sizeof(restore));
		restore.vcpu = vcpu;
		restore.apply_software = apply_software;
		restore.apply_pdpte = &apply_plan->l1_pdpte;
		error = vmx_nested_l1_restore_failed_entry(&resolution->id,
		    apply_plan, &resolution->result, &restore_ops, &restore,
		    &restore_result);
		if (error != 0)
			return (error);
		error = vmx_nested_exit_msr_transaction_commit(
		    &vcpu->nested_exit_msr_transaction);
		if (error != 0)
			panic("%s: failed entry lost MSR transaction: %d",
			    __func__, error);
		return (0);
	}
	if (resolution->result.disposition !=
	    VMX_NESTED_VMENTRY_VMFAIL_VALID)
		return (EPROTO);

	error = vm_get_register(vcpu->vcpu, VM_REG_GUEST_RFLAGS,
	    &old_rflags);
	if (error != 0)
		return (error);
	error = vm_get_register(vcpu->vcpu, VM_REG_GUEST_RIP, &old_rip);
	if (error != 0)
		return (error);

	sx_xlock(&vcpu->vmx->nested_vmcs_sx);
	error = vmx_nested_vmcs_registry_read(
	    &vcpu->vmx->nested_vmcs_registry, resolution->id.vmcs12_gpa,
	    vcpu->vcpuid, VMCS_INSTRUCTION_ERROR, &old_error);
	if (error == 0)
		error = vmx_nested_vmcs_registry_set_instruction_error(
		    &vcpu->vmx->nested_vmcs_registry,
		    resolution->id.vmcs12_gpa, vcpu->vcpuid,
		    resolution->result.instruction_error);
	if (error != 0)
		goto out;
	error = vm_set_register(vcpu->vcpu, VM_REG_GUEST_RFLAGS,
	    resolution->rflags);
	if (error != 0)
		goto rollback_vmcs;
	error = vm_set_register(vcpu->vcpu, VM_REG_GUEST_RIP,
	    old_rip + resolution->rip_advance);
	if (error == 0)
		goto out;

	rollback_error = vm_set_register(vcpu->vcpu,
	    VM_REG_GUEST_RFLAGS, old_rflags);
	if (rollback_error != 0)
		panic("%s: RFLAGS rollback failed: %d", __func__,
		    rollback_error);
rollback_vmcs:
	rollback_error = vmx_nested_vmcs_registry_set_instruction_error(
	    &vcpu->vmx->nested_vmcs_registry, resolution->id.vmcs12_gpa,
	    vcpu->vcpuid, old_error);
	if (rollback_error != 0)
		panic("%s: VMCS12 rollback failed: %d", __func__,
		    rollback_error);
out:
	sx_xunlock(&vcpu->vmx->nested_vmcs_sx);
	return (error);
}

struct vmx_nested_rejected_handoff_commit {
	struct vmx_vcpu *vcpu;
};

/*
 * A failed VM entry performs no VM-exit MSR stores, but it does process the
 * VM-exit MSR-load area after loading ordinary host state.  Snapshot that
 * guest-memory list once and retain the resulting value-only L1 candidate so
 * a later failure publishing VMCS12 can retry without resampling L1 memory.
 */
static int
vmx_nested_failed_entry_msrs_prepare(struct vmx_vcpu *vcpu,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_failed_entry_state_plan *base,
    const struct vmx_nested_failed_entry_state_plan **plan,
    const struct vmx_nested_software_msrs **software)
{
	struct vmx_nested_guest_memory_intel guest_memory;
	struct vmx_nested_guest_arch_state validation_arch;
	struct vmx_nested_guest_control_state validation_control;
	struct vmx_nested_software_msrs validation_software;
	struct vmx_nested_failed_entry_state_plan load_base;
	struct vmx_nested_virtual_msr virtual_msr;
	struct vmx_nested_msr_policy policy;
	enum vmx_nested_exit_msr_load_outcome outcome;
	enum vmx_nested_msr_failure failure;
	enum vmx_nested_pdpte_failure pdpte_failure;
	struct vmx_nested_exit_msr_transaction *transaction;
	const struct vmx_nested_memory *memory;
	const struct vmx_nested_vmcs12_snapshot *snapshot;
	uint32_t count, failed_entry;
	int error, transition_error;

	if (vcpu == NULL || id == NULL || base == NULL || plan == NULL ||
	    software == NULL || !vcpu->nested_vmcs02_plan_valid ||
	    !vcpu->nested_msr_workspace.active ||
	    vcpu->nested_msr_generation == 0)
		return (EINVAL);
	transaction = &vcpu->nested_exit_msr_transaction;
	snapshot = &vcpu->nested_vmcs12_snapshot;
	error = vmx_nested_exit_msr_transaction_validate(transaction);
	if (error != 0)
		return (error);
	if (transaction->state == VMX_NESTED_EXIT_MSR_TRANSACTION_IDLE) {
		if (vcpu->nested_failed_entry_msr_plan_valid)
			return (EPROTO);
		error = vmx_nested_exit_msr_transaction_begin(transaction,
		    id->execution_epoch, 0,
		    snapshot->controls.exit_msr_load_count);
		if (error != 0)
			return (error);
		error = vmx_nested_exit_msr_transaction_store_result(
		    transaction, VMX_NESTED_EXIT_MSR_STORE_OK);
		if (error != 0)
			return (error);
	}
	if (transaction->generation != id->execution_epoch ||
	    transaction->store_count != 0 ||
	    transaction->load_count !=
	    snapshot->controls.exit_msr_load_count)
		return (ESTALE);

	if (transaction->state ==
	    VMX_NESTED_EXIT_MSR_TRANSACTION_STORE_COMMITTED) {
		memory = NULL;
		if (transaction->load_count != 0 ||
		    vmx_nested_host_pdpte_active(&base->l1_host)) {
			error = vmx_nested_guest_memory_intel_init(
			    &guest_memory, vcpu->vcpu);
			if (error != 0)
				return (error);
			memory = vmx_nested_guest_memory_intel_memory(
			    &guest_memory);
			if (memory == NULL)
				return (EPROTO);
		}
		load_base = *base;
		pdpte_failure = VMX_NESTED_PDPTE_OK;
		error = vmx_nested_host_pdpte_snapshot(
		    &snapshot->capabilities, &load_base.l1_host, memory,
		    &load_base.l1_pdpte, &pdpte_failure);
		if (error != 0) {
			transition_error =
			    vmx_nested_exit_msr_transaction_abort(
			    transaction, 2);
			if (transition_error != 0)
				return (transition_error);
			return (ECANCELED);
		}
		validation_control = load_base.l1_control;
		validation_arch = load_base.l1_arch;
		validation_software = vcpu->nested_l1_software_msrs;
		memset(&virtual_msr, 0, sizeof(virtual_msr));
		virtual_msr.capabilities = &snapshot->capabilities;
		virtual_msr.control = &validation_control;
		virtual_msr.arch = &validation_arch;
		virtual_msr.software = &validation_software;
		virtual_msr.syscall_available = true;
		virtual_msr.tsc_aux_available = vmx_have_msr_tsc_aux;
		memset(&policy, 0, sizeof(policy));
		policy.validate_write = vmx_nested_virtual_msr_validate_write;
		policy.arg = &virtual_msr;
		failure = VMX_NESTED_MSR_OK;
		failed_entry = 0;
		count = 0;
		error = vmx_nested_exit_msr_load_snapshot(
		    &snapshot->capabilities,
		    snapshot->controls.exit_msr_load_address,
		    snapshot->controls.exit_msr_load_count,
		    base->l1_arch.in_smm, memory, &policy,
		    vcpu->nested_msr_workspace.plan,
		    vcpu->nested_msr_workspace.capacity, &count, &failure,
		    &failed_entry);
		if (error != 0) {
			outcome = vmx_nested_exit_msr_guest_failure(failure) ?
			    VMX_NESTED_EXIT_MSR_LOAD_ABORT_4_ROLLED_BACK :
			    VMX_NESTED_EXIT_MSR_LOAD_HOST_FAILED;
			transition_error =
			    vmx_nested_exit_msr_transaction_load_result(
			    transaction, outcome);
			if (transition_error != 0)
				return (transition_error);
			return (outcome ==
			    VMX_NESTED_EXIT_MSR_LOAD_ABORT_4_ROLLED_BACK ?
			    ECANCELED : EIO);
		}
		outcome = VMX_NESTED_EXIT_MSR_LOAD_HOST_FAILED;
		failed_entry = 0;
		error = vmx_nested_failed_entry_msr_load_prepare(
		    &snapshot->capabilities, &load_base,
		    &vcpu->nested_l1_software_msrs, true,
		    vmx_have_msr_tsc_aux, vcpu->nested_msr_workspace.plan,
		    count, vcpu->nested_msr_workspace.rollback,
		    vcpu->nested_msr_workspace.capacity,
		    &vcpu->nested_failed_entry_msr_plan,
		    &vcpu->nested_exit_msr_software, &outcome,
		    &failed_entry);
		transition_error =
		    vmx_nested_exit_msr_transaction_load_result(transaction,
		    outcome);
		if (transition_error != 0)
			return (transition_error);
		if (error != 0)
			return (outcome ==
			    VMX_NESTED_EXIT_MSR_LOAD_ABORT_4_ROLLED_BACK ?
			    ECANCELED : EIO);
		vcpu->nested_failed_entry_msr_plan_valid = true;
	}
	if (transaction->state !=
	    VMX_NESTED_EXIT_MSR_TRANSACTION_LOAD_APPLIED ||
	    !vcpu->nested_failed_entry_msr_plan_valid)
		return (transaction->state ==
		    VMX_NESTED_EXIT_MSR_TRANSACTION_ABORTED ? ECANCELED :
		    EIO);
	*plan = &vcpu->nested_failed_entry_msr_plan;
	*software = &vcpu->nested_exit_msr_software;
	return (0);
}

static int
vmx_nested_commit_rejected_handoff_apply(void *arg,
    const struct vmx_nested_vmentry_handoff_request *request)
{
	static const struct vmx_nested_vmentry_resolution_ops
	    rejection_ops = {
		.commit = vmx_nested_commit_rejected_entry,
	};
	struct vmx_nested_rejected_handoff_commit *handoff;
	struct vmx_nested_rejected_entry_commit commit;
	struct vmx_nested_vmentry_resolution resolution;

	handoff = arg;
	if (handoff == NULL || handoff->vcpu == NULL || request == NULL)
		return (EINVAL);
	commit.vcpu = handoff->vcpu;
	commit.snapshot = &handoff->vcpu->nested_vmcs12_snapshot;
	commit.environment = &handoff->vcpu->nested_entry_environment;
	return (vmx_nested_context_resolve_vmentry(
	    &handoff->vcpu->nested, &request->id, &request->result, true,
	    &rejection_ops, &commit, &resolution));
}

static int
vmx_nested_commit_rejected_handoff(struct vmx_vcpu *vcpu)
{
	static const struct vmx_nested_vmentry_handoff_ops handoff_ops = {
		.commit = vmx_nested_commit_rejected_handoff_apply,
	};
	static const struct vmx_nested_vmexit_abort_ops abort_ops = {
		.publish = vmx_nested_publish_exit_abort_intel,
	};
	struct vmx_nested_rejected_handoff_commit commit;
	struct vmx_nested_vmentry_handoff_request consumed;
	const struct vmx_nested_vmentry_handoff_request *request;
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (vcpu == NULL || !vcpu->nested_vmcs02_plan_valid ||
	    vcpu->nested.internal.kind !=
	    VMX_NESTED_INTERNAL_VMENTRY_REJECT)
		return (EINVAL);
	id = &vcpu->nested_vmcs02_plan.id;
	request = &vcpu->nested.internal.operation.vmentry.request;
	if (!vmx_nested_vmcs02_id_equal(&request->id, id))
		return (ESTALE);
	commit.vcpu = vcpu;
	error = vmx_nested_internal_handle_vmentry_reject(
	    &vcpu->nested.internal, id, &handoff_ops, &commit);
	if (error != 0 &&
	    vcpu->nested_exit_msr_transaction.state ==
	    VMX_NESTED_EXIT_MSR_TRANSACTION_ABORTED) {
		error = vmx_nested_context_abort_published_vmentry(
		    &vcpu->nested, true,
		    vcpu->nested_exit_msr_transaction.abort_indicator,
		    &abort_ops, vcpu, &consumed);
		if (error != 0)
			return (error);
		vmx_nested_completed_entry_release(vcpu);
		return (0);
	}
	if (error != 0 && error != EALREADY)
		return (error);
	error = vmx_nested_internal_take_vmentry_reject(
	    &vcpu->nested.internal, id, &consumed);
	if (error != 0)
		return (error);
	if (!vmx_nested_vmcs02_id_equal(&consumed.id, id))
		panic("%s: consumed entry rejection changed ownership",
		    __func__);
	vmx_nested_completed_entry_release(vcpu);
	return (0);
}

struct vmx_nested_late_entry_commit {
	struct vmx_vcpu *vcpu;
};

static int
vmx_nested_commit_late_entry_apply(void *arg,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_vmentry_result *result)
{
	struct vmx_nested_late_entry_commit *late;
	struct vmx_nested_rejected_entry_commit commit;
	struct vmx_nested_vmentry_resolution resolution;

	late = arg;
	if (late == NULL || late->vcpu == NULL || id == NULL ||
	    result == NULL ||
	    result->disposition != VMX_NESTED_VMENTRY_ENTRY_FAILURE)
		return (EINVAL);
	memset(&resolution, 0, sizeof(resolution));
	resolution.id = *id;
	resolution.result = *result;
	commit.vcpu = late->vcpu;
	commit.snapshot = &late->vcpu->nested_vmcs12_snapshot;
	commit.environment = &late->vcpu->nested_entry_environment;
	return (vmx_nested_commit_rejected_entry(&commit, &resolution));
}

static int
vmx_nested_commit_late_entry_handoff(struct vmx_vcpu *vcpu)
{
	static const struct vmx_nested_late_entry_commit_ops commit_ops = {
		.commit = vmx_nested_commit_late_entry_apply,
	};
	static const struct vmx_nested_late_entry_abort_ops abort_ops = {
		.publish = vmx_nested_publish_exit_abort_intel,
	};
	struct vmx_nested_vmentry_handoff_request consumed;
	struct vmx_nested_late_entry_commit commit;
	struct vmx_nested_vmcs02_id expected;
	int error;

	if (vcpu == NULL || !vcpu->nested_vmcs02_plan_valid ||
	    !vcpu->nested_l2_portable_valid ||
	    vcpu->nested.internal.kind !=
	    VMX_NESTED_INTERNAL_LATE_VMENTRY)
		return (EINVAL);
	expected = vcpu->nested_vmcs02_plan.id;
	commit.vcpu = vcpu;
	error = vmx_nested_late_entry_commit(&vcpu->nested,
	    &vcpu->nested_entry_runtime, true, &commit_ops, &commit,
	    &consumed);
	if (error != 0 &&
	    vcpu->nested_exit_msr_transaction.state ==
	    VMX_NESTED_EXIT_MSR_TRANSACTION_ABORTED) {
		error = vmx_nested_late_entry_abort(&vcpu->nested,
		    &vcpu->nested_entry_runtime, true,
		    vcpu->nested_exit_msr_transaction.abort_indicator,
		    &abort_ops, vcpu, &consumed);
		if (error != 0)
			return (error);
		vmx_nested_cold_reflected_entry_release(vcpu);
		return (0);
	}
	if (error != 0)
		return (error);
	if (!vmx_nested_vmcs02_id_equal(&consumed.id, &expected))
		panic("%s: consumed late entry changed ownership", __func__);
	vmx_nested_cold_reflected_entry_release(vcpu);
	return (0);
}

static int
vmx_nested_msr_workspace_ensure(struct vmx_vcpu *vcpu,
    const struct vmx_nested_capabilities *capabilities, bool waitok)
{
	struct vmx_nested_msr_entry *storage;
	uint64_t signature;
	uint32_t capacity;
	int error;

	error = vmx_nested_msr_workspace_capacity(capabilities, &capacity);
	if (error != 0)
		return (error);
	error = vmx_nested_capabilities_signature(capabilities, &signature);
	if (error != 0)
		return (error);
	if (vcpu->nested_msr_storage != NULL) {
		error = vmx_nested_msr_workspace_validate(
		    &vcpu->nested_msr_workspace);
		if (error != 0)
			return (error);
		if (vcpu->nested_msr_workspace.capacity != capacity ||
		    vcpu->nested_msr_workspace.plan !=
		    vcpu->nested_msr_storage ||
		    vcpu->nested_msr_workspace.rollback !=
		    vcpu->nested_msr_storage + capacity)
			return (EPROTO);
		return (vcpu->nested_msr_workspace.capability_signature ==
		    signature ? 0 : ESTALE);
	}

	/*
	 * vmx_handle_internal_exit() runs with the vCPU frozen and outside a
	 * VMX critical section.  Allocate once here; hardware entry later
	 * reuses the bounded arrays without sleeping.
	 */
	storage = mallocarray(capacity, 2 * sizeof(*storage), M_VMX,
	    (waitok ? M_WAITOK : M_NOWAIT) | M_ZERO);
	if (storage == NULL)
		return (ENOMEM);
	error = vmx_nested_msr_workspace_bind(
	    &vcpu->nested_msr_workspace, capabilities, storage,
	    storage + capacity, capacity);
	if (error != 0) {
		free(storage, M_VMX);
		return (error);
	}
	vcpu->nested_msr_storage = storage;
	return (0);
}

/*
 * Allocate a fresh scratch workspace into an unpublished restore stage.
 * The caller transfers both objects to a destination vCPU only after the
 * VM-wide registry replacement succeeds.  This is intentionally separate
 * from vmx_nested_msr_workspace_ensure(), which binds scratch owned by an
 * already-published vCPU on the normal entry path.
 */
#ifdef BHYVE_SNAPSHOT
static int
vmx_nested_msr_workspace_stage(const struct vmx_nested_capabilities *capabilities,
    struct vmx_nested_msr_workspace *workspace,
    struct vmx_nested_msr_entry **storagep)
{
	struct vmx_nested_msr_entry *storage;
	uint32_t capacity;
	int error;

	if (workspace == NULL || storagep == NULL || *storagep != NULL)
		return (EINVAL);
	if (vmx_nested_msr_workspace_validate(workspace) != 0 ||
	    workspace->plan != NULL || workspace->rollback != NULL ||
	    workspace->active)
		return (EPROTO);
	error = vmx_nested_msr_workspace_capacity(capabilities, &capacity);
	if (error != 0)
		return (error);
	storage = mallocarray(capacity, 2 * sizeof(*storage), M_VMX,
	    M_NOWAIT | M_ZERO);
	if (storage == NULL)
		return (ENOMEM);
	error = vmx_nested_msr_workspace_bind(workspace, capabilities, storage,
	    storage + capacity, capacity);
	if (error != 0) {
		explicit_bzero(storage, (size_t)capacity * 2 * sizeof(*storage));
		free(storage, M_VMX);
		return (error);
	}
	*storagep = storage;
	return (0);
}
#endif

static void
vmx_nested_software_msrs_capture(const struct vmx_vcpu *vcpu,
    struct vmx_nested_software_msrs *software)
{

	memset(software, 0, sizeof(*software));
	software->star = vcpu->guest_msrs[IDX_MSR_STAR];
	software->lstar = vcpu->guest_msrs[IDX_MSR_LSTAR];
	software->cstar = vcpu->guest_msrs[IDX_MSR_CSTAR];
	software->sfmask = vcpu->guest_msrs[IDX_MSR_SF_MASK];
	software->kgsbase = vcpu->guest_msrs[IDX_MSR_KGSBASE];
	software->tsc_aux = vcpu->guest_msrs[IDX_MSR_TSC_AUX];
}

static void
vmx_nested_software_msrs_publish(struct vmx_vcpu *vcpu,
    const struct vmx_nested_software_msrs *software)
{

	vcpu->guest_msrs[IDX_MSR_STAR] = software->star;
	vcpu->guest_msrs[IDX_MSR_LSTAR] = software->lstar;
	vcpu->guest_msrs[IDX_MSR_CSTAR] = software->cstar;
	vcpu->guest_msrs[IDX_MSR_SF_MASK] = software->sfmask;
	vcpu->guest_msrs[IDX_MSR_KGSBASE] = software->kgsbase;
	vcpu->guest_msrs[IDX_MSR_TSC_AUX] = software->tsc_aux;
}

static int
vmx_nested_hardware_msr_read(void *arg __unused, uint32_t index,
    uint64_t *value)
{

	if (value == NULL)
		return (EINVAL);
	switch (index) {
	case MSR_STAR:
	case MSR_LSTAR:
	case MSR_CSTAR:
	case MSR_SF_MASK:
	case MSR_KGSBASE:
		break;
	case MSR_TSC_AUX:
		if (!vmx_have_msr_tsc_aux)
			return (ENOTSUP);
		break;
	default:
		return (EINVAL);
	}
	*value = rdmsr(index);
	return (0);
}

static int
vmx_nested_hardware_msr_write(void *arg __unused, uint32_t index,
    uint64_t value)
{

	switch (index) {
	case MSR_STAR:
	case MSR_LSTAR:
	case MSR_CSTAR:
	case MSR_SF_MASK:
	case MSR_KGSBASE:
		break;
	case MSR_TSC_AUX:
		if (!vmx_have_msr_tsc_aux)
			return (ENOTSUP);
		break;
	default:
		return (EINVAL);
	}
	wrmsr(index, value);
	return (0);
}

static const struct vmx_nested_msr_apply_ops
vmx_nested_hardware_msr_ops = {
	.read = vmx_nested_hardware_msr_read,
	.write = vmx_nested_hardware_msr_write,
};

static int
vmx_nested_software_msrs_install(struct vmx_vcpu *vcpu,
    const struct vmx_nested_software_msrs *software,
    const struct vmx_nested_software_msrs *rollback_software,
    enum vmx_nested_hardware_msr_transition transition,
    bool *rollback_complete)
{
	struct vmx_nested_msr_entry entries[
	    VMX_NESTED_SOFTWARE_MSR_COUNT];
	enum vmx_nested_msr_apply_outcome outcome;
	uint32_t count, failed_entry;
	int error;

	if (rollback_complete == NULL)
		return (EINVAL);
	*rollback_complete = true;
	if (vcpu == NULL || software == NULL || rollback_software == NULL ||
	    transition == VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_count != 0)
		return (EINVAL);
	if ((transition == VMX_NESTED_HARDWARE_MSR_ENTRY &&
	    vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1) ||
	    (transition == VMX_NESTED_HARDWARE_MSR_EXIT &&
	    vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L2 &&
	    vcpu->nested_tsc_aux_residency !=
	    VMX_NESTED_TSC_AUX_L2_PAUSED))
		return (EINVAL);
	error = vmx_nested_software_msr_list(software,
	    vmx_have_msr_tsc_aux, entries, nitems(entries), &count);
	if (error != 0)
		return (error);
	error = vmx_nested_msr_list_apply(entries, count,
	    &vmx_nested_hardware_msr_ops, NULL,
	    vcpu->nested_hardware_msr_rollback,
	    nitems(vcpu->nested_hardware_msr_rollback), &outcome,
	    &failed_entry);
	if (error != 0) {
		if (outcome == VMX_NESTED_MSR_APPLY_ROLLBACK_FAILED) {
			*rollback_complete = false;
			return (EIO);
		}
		return (error);
	}
	vcpu->nested_hardware_msr_rollback_software =
	    *rollback_software;
	vcpu->nested_hardware_msr_count = count;
	vcpu->nested_hardware_msr_transition = transition;
	if (transition == VMX_NESTED_HARDWARE_MSR_ENTRY) {
		vcpu->nested_tsc_aux_rollback_residency =
		    VMX_NESTED_TSC_AUX_L1;
		error = vmx_nested_tsc_aux_enter_l2(
		    &vcpu->nested_tsc_aux_residency);
	} else {
		error = vmx_nested_tsc_aux_leave_l2(
		    &vcpu->nested_tsc_aux_residency,
		    &vcpu->nested_tsc_aux_rollback_residency);
	}
	if (error != 0)
		panic("%s: prevalidated TSC_AUX transition failed: %d",
		    __func__, error);
	vmx_nested_software_msrs_publish(vcpu, software);
	/*
	 * L1's architectural bank is now committed, but host execution must
	 * never carry either guest's IA32_TSC_AUX while interrupts are
	 * enabled.  Preserve the L1 value in guest_msrs and restore the
	 * per-CPU host value exactly as the ordinary VMX exit path does.
	 * A later transaction rollback still uses its independently captured
	 * hardware image.
	 */
	if (transition == VMX_NESTED_HARDWARE_MSR_EXIT)
		vmx_msr_guest_exit_tsc_aux(vcpu->vmx, vcpu);
	return (0);
}

static int
vmx_nested_software_msrs_rollback(struct vmx_vcpu *vcpu,
    enum vmx_nested_hardware_msr_transition transition)
{
	uint32_t failed_entry;
	int error;

	if (vcpu == NULL ||
	    transition == VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_transition != transition ||
	    vcpu->nested_hardware_msr_count == 0)
		return (EINVAL);
	error = vmx_nested_msr_list_rollback(
	    vcpu->nested_hardware_msr_rollback,
	    vcpu->nested_hardware_msr_count,
	    &vmx_nested_hardware_msr_ops, NULL, &failed_entry);
	if (error != 0)
		return (error);
	if (transition == VMX_NESTED_HARDWARE_MSR_ENTRY)
		error = vmx_nested_tsc_aux_rollback_enter(
		    &vcpu->nested_tsc_aux_residency);
	else
		error = vmx_nested_tsc_aux_rollback_leave(
		    &vcpu->nested_tsc_aux_residency,
		    vcpu->nested_tsc_aux_rollback_residency);
	if (error != 0)
		panic("%s: hardware rollback lost TSC_AUX residency: %d",
		    __func__, error);
	vmx_nested_software_msrs_publish(vcpu,
	    &vcpu->nested_hardware_msr_rollback_software);
	memset(vcpu->nested_hardware_msr_rollback, 0,
	    sizeof(vcpu->nested_hardware_msr_rollback));
	memset(&vcpu->nested_hardware_msr_rollback_software, 0,
	    sizeof(vcpu->nested_hardware_msr_rollback_software));
	vcpu->nested_hardware_msr_count = 0;
	vcpu->nested_hardware_msr_transition =
	    VMX_NESTED_HARDWARE_MSR_NONE;
	vcpu->nested_tsc_aux_rollback_residency =
	    VMX_NESTED_TSC_AUX_L1;
	return (0);
}

static void
vmx_nested_software_msrs_commit(struct vmx_vcpu *vcpu,
    enum vmx_nested_hardware_msr_transition transition)
{

	if (vcpu == NULL || transition == VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_transition != transition ||
	    vcpu->nested_hardware_msr_count == 0)
		panic("%s: wrong nested MSR transition", __func__);
	memset(vcpu->nested_hardware_msr_rollback, 0,
	    sizeof(vcpu->nested_hardware_msr_rollback));
	memset(&vcpu->nested_hardware_msr_rollback_software, 0,
	    sizeof(vcpu->nested_hardware_msr_rollback_software));
	vcpu->nested_hardware_msr_count = 0;
	vcpu->nested_hardware_msr_transition =
	    VMX_NESTED_HARDWARE_MSR_NONE;
	vcpu->nested_tsc_aux_rollback_residency =
	    VMX_NESTED_TSC_AUX_L1;
}

static int
vmx_nested_software_msrs_leave_l2(struct vmx_vcpu *vcpu,
    bool *rollback_complete)
{
	struct vmx_nested_software_msrs l2;
	int error;

	if (rollback_complete == NULL)
		return (EINVAL);
	*rollback_complete = true;
	if (vcpu == NULL ||
	    vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_count != 0)
		return (EINVAL);
	error = vmx_nested_software_msr_capture(vmx_have_msr_tsc_aux,
	    &vmx_nested_hardware_msr_ops, NULL, &l2);
	if (error != 0)
		return (error);
	if (vcpu->nested_tsc_aux_residency ==
	    VMX_NESTED_TSC_AUX_L2_PAUSED)
		l2.tsc_aux = vcpu->nested_l2_software_msrs.tsc_aux;
	error = vmx_nested_software_msrs_install(vcpu,
	    &vcpu->nested_l1_software_msrs, &l2,
	    VMX_NESTED_HARDWARE_MSR_EXIT, rollback_complete);
	if (error != 0)
		return (*rollback_complete ? error : EIO);
	vcpu->nested_l2_software_msrs = l2;
	return (0);
}

/*
 * IA32_TSC_AUX is the one software-owned MSR which may be rewritten by the
 * interrupt-enabled IPI suspend path.  Switch only that MSR back to the host
 * immediately after a real L2 VM exit, before interrupts can be enabled.
 * L1's architectural value remains in its software bank.  The remainder of
 * the L2 software-owned bank can safely remain resident while the vCPU stays
 * CPU-pinned.
 */
static int
vmx_nested_tsc_aux_pause_l2_intel(struct vmx_vcpu *vcpu)
{
	int error;

	if (vcpu == NULL || curthread->td_critnest == 0 ||
	    vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_count != 0 ||
	    vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L2)
		return (EINVAL);
	if (vmx_have_msr_tsc_aux) {
		vcpu->nested_l2_software_msrs.tsc_aux = rdmsr(MSR_TSC_AUX);
		vmx_msr_guest_exit_tsc_aux(vcpu->vmx, vcpu);
	}
	vcpu->guest_msrs[IDX_MSR_TSC_AUX] =
	    vcpu->nested_l1_software_msrs.tsc_aux;
	error = vmx_nested_tsc_aux_pause_l2(
	    &vcpu->nested_tsc_aux_residency);
	if (error != 0)
		panic("%s: prevalidated TSC_AUX pause failed: %d", __func__,
		    error);
	return (0);
}

/*
 * Called immediately before VMRESUME/VMLAUNCH with interrupts disabled.
 * Host IA32_TSC_AUX is physically resident while L0 handles the exit; L1
 * cannot execute in this interval, so its software bank cannot change.
 * Reinstall the retained L2 value without exposing it to interrupt handling.
 */
static int
vmx_nested_tsc_aux_resume_l2_intel(struct vmx_vcpu *vcpu)
{
	int error;

	if (vcpu == NULL || curthread->td_critnest == 0 ||
	    vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_count != 0 ||
	    vcpu->nested_tsc_aux_residency !=
	    VMX_NESTED_TSC_AUX_L2_PAUSED)
		return (EINVAL);
	if (vmx_have_msr_tsc_aux) {
		vmx_msr_guest_enter_tsc_aux(vcpu->vmx, vcpu);
	}
	vcpu->guest_msrs[IDX_MSR_TSC_AUX] =
	    vcpu->nested_l2_software_msrs.tsc_aux;
	error = vmx_nested_tsc_aux_resume_l2(
	    &vcpu->nested_tsc_aux_residency);
	if (error != 0)
		panic("%s: prevalidated TSC_AUX resume failed: %d", __func__,
		    error);
	return (0);
}

/*
 * Destructively capture a reflected VMCS02 exit while the vCPU remains
 * CPU-pinned.  CPU-local software-owned MSRs are switched to L1 before
 * VMCS02 is cleared, then the transition rollback image is discarded after
 * capture: once VMCS02 has been cleared there is no valid hot L2 execution
 * to roll back to.  The subsequent frozen transaction may retry publishing
 * VMCS12 and L1 architectural state, but must never touch CPU-local MSRs.
 */
static int
vmx_nested_capture_reflected_exit_hot(struct vmx_vcpu *vcpu,
    struct vmx_nested_exit_information *information,
    struct vmx_nested_l2_runtime_state *runtime)
{
	const struct vmx_nested_vmcs02_id *id;
	bool rollback_complete;
	int capture_error, error, poison_error;

	if (vcpu == NULL || information == NULL || runtime == NULL ||
	    curthread->td_critnest == 0 || !vcpu->nested_vmcs02_plan_valid ||
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_GUEST)
		return (EINVAL);
	id = &vcpu->nested_vmcs02_plan.id;
	if (!vmx_nested_vmcs02_id_equal(id, &vcpu->nested_entry_runtime.id))
		return (ESTALE);

	error = vmx_nested_software_msrs_leave_l2(vcpu,
	    &rollback_complete);
	if (error != 0)
		return (rollback_complete ? error : EIO);

	capture_error = vmx_nested_vmcs02_intel_capture_exit(
	    &vcpu->nested_vmcs02_intel, id,
	    vcpu->nested_entry_runtime.resource_generation,
	    vcpu->nested_vmcs02_plan.image.l2_arch.in_smm,
	    information, runtime);

	/*
	 * Both successful and failed destructive capture have restored
	 * VMCS01.  Keep the already installed L1 bank and clear the
	 * CPU-local rollback owner before the outer run loop restores host
	 * MSRs.  L2's captured values remain in nested_l2_software_msrs.
	 */
	vmx_nested_software_msrs_commit(vcpu,
	    VMX_NESTED_HARDWARE_MSR_EXIT);
	if (capture_error != 0) {
		poison_error = vmx_nested_entry_runtime_exit_captured(
		    &vcpu->nested_entry_runtime, id);
		if (poison_error == 0)
			poison_error = vmx_nested_entry_runtime_exit_poison(
			    &vcpu->nested_entry_runtime, id);
		if (poison_error != 0)
			panic("%s: cannot poison destructive capture: %d",
			    __func__, poison_error);
		return (capture_error);
	}
	error = vmx_nested_entry_runtime_exit_captured(
	    &vcpu->nested_entry_runtime, id);
	if (error != 0)
		panic("%s: captured exit lost runtime ownership: %d",
		    __func__, error);
	return (0);
}

/*
 * Convert the already-routed reflected exit into an immutable handoff before
 * the run loop restores host MSRs or crosses the frozen boundary.  Routing
 * only peeked at VMCS02; this function performs the one destructive capture.
 */
static int
vmx_nested_publish_reflected_exit_hot_raw(struct vmx_vcpu *vcpu,
    const struct vmx_nested_exit_information *expected)
{
	struct vmx_nested_exit_information information;
	struct vmx_nested_l2_runtime_state runtime;
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (vcpu == NULL || expected == NULL ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	id = &vcpu->nested_vmcs02_plan.id;
	error = vmx_nested_context_guest_validate(&vcpu->nested, id);
	if (error != 0)
		return (error);
	error = vmx_nested_capture_reflected_exit_hot(vcpu, &information,
	    &runtime);
	if (error != 0)
		return (error);
	if (!vmx_nested_exit_information_equal(&information, expected))
		panic("%s: VMCS02 exit changed between routing and capture",
		    __func__);
	error = vmx_nested_context_publish_vmexit(&vcpu->nested, id,
	    &information, &runtime);
	if (error != 0)
		panic("%s: prevalidated destructive exit publication failed: %d",
		    __func__, error);
	return (0);
}

struct vmx_nested_mtf_publish_intel {
	struct vmx_vcpu *vcpu;
	const struct vmx_nested_exit_information *expected;
};

static int
vmx_nested_publish_mtf_exit_hot(void *arg,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_exit_information *information)
{
	struct vmx_nested_mtf_publish_intel *publish;
	struct vmx_vcpu *vcpu;

	publish = arg;
	if (publish == NULL || publish->vcpu == NULL ||
	    publish->expected == NULL || id == NULL || information == NULL)
		return (EINVAL);
	vcpu = publish->vcpu;
	if ((information->exit_reason & VMX_EXIT_REASON_BASIC_MASK) !=
	    EXIT_REASON_MTF || !information->launched ||
	    (publish->expected->exit_reason & VMX_EXIT_REASON_BASIC_MASK) !=
	    EXIT_REASON_MTF ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    !vmx_nested_vmcs02_id_equal(id, &vcpu->nested_vmcs02_plan.id))
		return (EINVAL);
	/*
	 * The owner proves the basic reason and execution identity.  Preserve
	 * the complete captured hardware image supplied by the routing
	 * transaction, including architecturally permitted bit-26 bus-lock
	 * metadata and any canonical vectoring fields.
	 */
	return (vmx_nested_publish_reflected_exit_hot_raw(vcpu,
	    publish->expected));
}

static int
vmx_nested_publish_reflected_exit_hot(struct vmx_vcpu *vcpu,
    const struct vmx_nested_exit_information *expected)
{
	static const struct vmx_nested_mtf_owner_ops mtf_ops = {
		.publish = vmx_nested_publish_mtf_exit_hot,
	};
	struct vmx_nested_mtf_publish_intel publish;
	const struct vmx_nested_vmcs02_id *id;
	uint64_t generation;
	int error;

	if (vcpu == NULL || expected == NULL ||
	    !vcpu->nested_vmcs02_plan_valid)
		return (EINVAL);
	if (!vcpu->nested_mtf_owner.pending)
		return (vmx_nested_publish_reflected_exit_hot_raw(vcpu,
		    expected));

	id = &vcpu->nested_vmcs02_plan.id;
	generation = vcpu->nested_mtf_owner.origin_generation;
	if ((expected->exit_reason & VMX_EXIT_REASON_BASIC_MASK) ==
	    EXIT_REASON_MTF) {
		/*
		 * The owner constructs the immutable reason-37 image and consumes
		 * itself only after the destructive VMCS02 publication callback
		 * succeeds.  A mismatching hardware image fails stop in the raw
		 * publisher instead of consuming a different MTF generation.
		 */
		publish.vcpu = vcpu;
		publish.expected = expected;
		return (vmx_nested_mtf_owner_reflect(
		    &vcpu->nested_mtf_owner, id, generation, &mtf_ops,
		    &publish));
	}

	error = vmx_nested_publish_reflected_exit_hot_raw(vcpu, expected);
	if (error != 0)
		return (error);
	/* Any architecturally published nested exit cancels pending MTF. */
	error = vmx_nested_mtf_owner_consume(&vcpu->nested_mtf_owner, id,
	    generation);
	if (error != 0)
		panic("%s: published nested exit retained MTF owner: %d",
		    __func__, error);
	return (0);
}

static int
vmx_nested_hardware_entry_install_msrs(void *arg,
    const struct vmx_nested_software_msrs *software,
    bool *rollback_complete)
{
	struct vmx_vcpu *vcpu;

	vcpu = arg;
	return (vmx_nested_software_msrs_install(vcpu, software,
	    &vcpu->nested_l1_software_msrs,
	    VMX_NESTED_HARDWARE_MSR_ENTRY, rollback_complete));
}

static int
vmx_nested_hardware_entry_rollback_msrs(void *arg)
{

	return (vmx_nested_software_msrs_rollback(arg,
	    VMX_NESTED_HARDWARE_MSR_ENTRY));
}

static void
vmx_nested_hardware_entry_commit_msrs(void *arg)
{

	vmx_nested_software_msrs_commit(arg,
	    VMX_NESTED_HARDWARE_MSR_ENTRY);
}

static void
vmx_nested_hardware_entry_commit_vmcs_launch(void *arg)
{
	struct vmx_vcpu *vcpu;
	int error;

	vcpu = arg;
	error = vmx_nested_vmcs02_intel_commit_entered(
	    &vcpu->nested_vmcs02_intel);
	if (error != 0)
		panic("%s: entered L2 without VMCS02 launch ownership: %d",
		    __func__, error);
}

static int
vmx_nested_hardware_entry_program_vmcs02(void *arg,
    const struct vmx_nested_vmcs02_program *program,
    bool *rollback_complete)
{
	struct vmx_nested_vmcs02_apply_result result;
	struct vmx_vcpu *vcpu;
	int error;

	vcpu = arg;
	if (rollback_complete == NULL)
		return (EINVAL);
	*rollback_complete = false;
	error = vmx_nested_vmcs02_program_apply(program,
	    vmx_nested_vmcs02_intel_apply_ops(),
	    &vcpu->nested_vmcs02_intel, &result);
	if (error != 0) {
		/*
		 * begin() may fail after selecting or initializing VMCS02.
		 * Prove the prior selection was restored before the common
		 * state machine releases the associated MSR obligations.
		 */
		*rollback_complete =
		    !vcpu->nested_vmcs02_intel.transaction_active &&
		    !vcpu->nested_vmcs02_intel.launch.current &&
		    vmx_nested_vmcs02_intel_vmcs01_current(
		    &vcpu->nested_vmcs02_intel);
	}
	return (error);
}

static int
vmx_nested_hardware_entry_leave_vmcs02(void *arg)
{
	struct vmx_vcpu *vcpu;

	vcpu = arg;
	return (vmx_nested_vmcs02_intel_leave(
	    &vcpu->nested_vmcs02_intel));
}

static const struct vmx_nested_hardware_entry_ops
vmx_nested_hardware_entry_intel_ops = {
	.install_msrs = vmx_nested_hardware_entry_install_msrs,
	.rollback_msrs = vmx_nested_hardware_entry_rollback_msrs,
	.commit_msrs = vmx_nested_hardware_entry_commit_msrs,
	.commit_vmcs_launch = vmx_nested_hardware_entry_commit_vmcs_launch,
	.program_vmcs02 = vmx_nested_hardware_entry_program_vmcs02,
	.leave_vmcs02 = vmx_nested_hardware_entry_leave_vmcs02,
};

static int
vmx_nested_final_hardware_prepare(struct vmx_vcpu *vcpu,
    const struct vmx_nested_entry_event_plan *event)
{
	struct vmx_nested_entry_environment environment;
	struct vmx_nested_vmcs02_program program;
	struct vmx_nested_vmcs02_plan plan;
	struct vmx_nested_software_msrs software;
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (vcpu == NULL || event == NULL ||
	    !vcpu->nested_vmcs02_plan_valid)
		return (EINVAL);
	/*
	 * VMCS02 carries only L0's hardware MSR areas.  L1's lists are
	 * intentionally left out of hardware and processed from the captured
	 * value-only L2 image by the frozen exit coordinator.
	 */
	id = &vcpu->nested_vmcs02_plan.id;
	error = vmx_nested_entry_environment_intel_final_program(vcpu,
	    event, &environment, &plan, &software, &program);
	if (error != 0)
		return (error);
	error = vmx_nested_vpid_flush(vcpu, &plan.image.vpid);
	if (error != 0)
		return (error);
	error = vmx_nested_hardware_entry_prepare(
	    &vcpu->nested_entry_runtime, id,
	    vcpu->nested_entry_msr_count, &software, &program,
	    &vmx_nested_hardware_entry_intel_ops, vcpu);
	if (error != 0)
		return (error);

	/*
	 * Hardware now owns exactly these final-CPU values.  Publish their
	 * value-only mirrors together so exit capture cannot observe the
	 * earlier preliminary environment.
	 */
	vcpu->nested_entry_environment = environment;
	vcpu->nested_vmcs02_plan = plan;
	vcpu->nested_l2_software_msrs = software;
	return (0);
}

/*
 * Intel residency adapter for a cold L0 continuation.  The generic
 * freeze/thaw machines own ordering and publication; this object owns only
 * one in-flight hardware transaction and is never serialized.
 */
struct vmx_nested_l2_intel_transaction {
	struct vmx_vcpu *vcpu;
	struct vmx_nested_entry_environment environment;
	struct vmx_nested_vmcs02_resources fixed_resources;
	struct vmx_nested_vmcs02_resources resources;
	/*
	 * Hot callbacks borrow the VMM run loop's CPU pin.  This flag says
	 * VMCS access is live; it never owns the caller's critical nesting.
	 */
	bool critical_held;
	bool l1_msrs_installed;
	bool resources_acquired;
};

static int
vmx_nested_l2_intel_clear_unpin(
	struct vmx_nested_l2_intel_transaction *transaction)
{
	int error;

	if (transaction == NULL || transaction->vcpu == NULL)
		return (EINVAL);
	if (!transaction->critical_held)
		return (0);
	if (curthread->td_critnest == 0)
		return (EINVAL);
	error = vmclear(transaction->vcpu->vmcs);
	/*
	 * This flag records a borrowed CPU-pinned current-VMCS residency.
	 * VMCLEAR failure leaves that residency indeterminate, so clearing the
	 * software flag and returning would let the caller drop its CPU pin
	 * with VMCS01 potentially current on the old CPU.  No higher layer can
	 * repair that association after migration.
	 */
	if (error != VM_SUCCESS)
		panic("%s: cannot detach VMCS01: %d", __func__, error);
	transaction->critical_held = false;
	return (0);
}

static int
vmx_nested_l2_intel_capture_software(void *arg,
    struct vmx_nested_software_msrs *software)
{
	struct vmx_nested_l2_intel_transaction *transaction;

	transaction = arg;
	if (transaction == NULL || transaction->vcpu == NULL ||
	    software == NULL || !transaction->critical_held ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	return (vmx_nested_software_msr_capture(vmx_have_msr_tsc_aux,
	    &vmx_nested_hardware_msr_ops, NULL, software));
}

static int
vmx_nested_l2_intel_detach(void *arg,
    const struct vmx_nested_vmcs02_plan *plan, uint64_t generation,
    uint64_t l1_virtual_tsc, struct vmx_nested_l2_capture_values *capture,
    bool *rollback_complete)
{
	struct vmx_nested_l2_intel_transaction *transaction;
	int clear_error, error;

	transaction = arg;
	if (transaction == NULL || transaction->vcpu == NULL ||
	    !transaction->critical_held || curthread->td_critnest == 0)
		return (EINVAL);
	error = vmx_nested_vmcs02_intel_capture_l2(
	    &transaction->vcpu->nested_vmcs02_intel, plan, generation,
	    l1_virtual_tsc, capture, rollback_complete);
	if (error == 0)
		return (0);
	/*
	 * Destructive capture always restores VMCS01.  No retry may retain a
	 * CPU-local current-VMCS association after returning the vCPU to its
	 * frozen owner.
	 */
	clear_error = vmx_nested_l2_intel_clear_unpin(transaction);
	if (clear_error != 0)
		*rollback_complete = false;
	return (clear_error != 0 ? clear_error : error);
}

static int
vmx_nested_l2_intel_install_l1(void *arg,
    const struct vmx_nested_vmcs02_id *id, bool *rollback_complete)
{
	struct vmx_nested_l2_intel_transaction *transaction;
	int clear_error, error;

	transaction = arg;
	if (transaction == NULL || transaction->vcpu == NULL || id == NULL ||
	    rollback_complete == NULL || !transaction->critical_held ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	error = vmx_nested_software_msrs_leave_l2(transaction->vcpu,
	    rollback_complete);
	if (error == 0)
		transaction->l1_msrs_installed = true;
	clear_error = vmx_nested_l2_intel_clear_unpin(transaction);
	if (clear_error != 0) {
		*rollback_complete = false;
		return (clear_error);
	}
	return (error);
}

static bool
vmx_nested_l2_intel_resources_intact(
    const struct vmx_nested_l2_intel_transaction *transaction,
    const struct vmx_nested_vmcs02_id *id, uint64_t generation)
{
	const struct vmx_nested_vmcs02_lease_owner *owner;

	owner = &transaction->vcpu->nested_vmcs02_leases;
	return (owner->active && owner->active_generation == generation &&
	    vmx_nested_vmcs02_id_equal(&owner->id, id) &&
	    (!transaction->vcpu->nested_vmcs02_plan.image.ept_enabled ||
	    transaction->vcpu->nested_ept_binding.active));
}

static int
vmx_nested_l2_intel_release_resources(void *arg,
    const struct vmx_nested_vmcs02_id *id, uint64_t generation,
    bool *rollback_complete)
{
	struct vmx_nested_l2_intel_transaction *transaction;
	int error;

	transaction = arg;
	if (transaction == NULL || transaction->vcpu == NULL || id == NULL ||
	    rollback_complete == NULL || transaction->critical_held ||
	    !transaction->l1_msrs_installed)
		return (EINVAL);
	error = vmx_nested_vmcs02_resources_intel_release(transaction->vcpu,
	    &transaction->vcpu->nested_vmcs02_resources);
	if (error != 0) {
		*rollback_complete = vmx_nested_l2_intel_resources_intact(
		    transaction, id, generation);
		return (error);
	}
	vmx_nested_software_msrs_commit(transaction->vcpu,
	    VMX_NESTED_HARDWARE_MSR_EXIT);
	transaction->l1_msrs_installed = false;
	*rollback_complete = true;
	return (0);
}

static int
vmx_nested_l2_intel_program_existing(
    struct vmx_nested_l2_intel_transaction *transaction,
    const struct vmx_nested_vmcs02_plan *plan,
    const struct vmx_nested_vmcs02_resources *resources)
{
	struct vmx_nested_vmcs02_apply_result result;
	struct vmx_nested_vmcs02_hardware_plan hardware;
	struct vmx_nested_vmcs02_program program;
	int error;

	error = vmx_nested_vmcs02_bind(&plan->image,
	    &transaction->environment.l0_host, resources, &hardware);
	if (error == 0)
		error = vmx_nested_vmcs02_program_build(&hardware, &program);
	if (error == 0)
		error = vmx_nested_vpid_flush(transaction->vcpu,
		    &plan->image.vpid);
	if (error == 0)
		error = vmx_nested_vmcs02_program_apply(&program,
		    vmx_nested_vmcs02_intel_apply_ops(),
		    &transaction->vcpu->nested_vmcs02_intel, &result);
	return (error);
}

static int
vmx_nested_l2_intel_rollback_hot(void *arg,
    const struct vmx_nested_vmcs02_plan *plan,
    const struct vmx_nested_l2_portable_state *portable,
    bool *rollback_complete)
{
	struct vmx_nested_l2_intel_transaction *transaction;
	struct vmx_nested_vmcs02_resources fixed;
	struct vmx_nested_vmcs02_plan rebound;
	int error;

	transaction = arg;
	if (transaction == NULL || transaction->vcpu == NULL ||
	    rollback_complete == NULL || transaction->critical_held ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	*rollback_complete = false;
	error = vmx_nested_entry_environment_intel_rebind_portable(
	    transaction->vcpu, portable, plan,
	    &vmx_nested_hardware_controls, &transaction->environment,
	    &fixed, &rebound);
	if (error != 0)
		return (error);
	transaction->critical_held = true;
	if (vmptrld(transaction->vcpu->vmcs) != VM_SUCCESS) {
		error = EIO;
		goto fail;
	}
	if (transaction->l1_msrs_installed) {
		error = vmx_nested_software_msrs_rollback(transaction->vcpu,
		    VMX_NESTED_HARDWARE_MSR_EXIT);
		if (error != 0)
			goto fail;
		transaction->l1_msrs_installed = false;
	}
	error = vmx_nested_l2_intel_program_existing(transaction, &rebound,
	    &transaction->vcpu->nested_vmcs02_resources);
	if (error != 0)
		goto fail;
	*rollback_complete = true;
	return (0);

fail:
	if (transaction->vcpu->nested_vmcs02_intel.launch.current)
		(void)vmx_nested_vmcs02_intel_leave(
		    &transaction->vcpu->nested_vmcs02_intel);
	if (transaction->vcpu->nested_hardware_msr_transition ==
	    VMX_NESTED_HARDWARE_MSR_NONE) {
		bool msr_rollback_complete;
		int msr_error;

		/*
		 * A failed hot reconstruction must not return to L1 with L2's
		 * software-owned MSR bank still installed.  This cleanup does
		 * not make the architectural continuation retryable.
		 */
		msr_error = vmx_nested_software_msrs_install(
		    transaction->vcpu,
		    &transaction->vcpu->nested_l1_software_msrs,
		    &portable->software_msrs,
		    VMX_NESTED_HARDWARE_MSR_EXIT,
		    &msr_rollback_complete);
		if (msr_error == 0)
			vmx_nested_software_msrs_commit(transaction->vcpu,
			    VMX_NESTED_HARDWARE_MSR_EXIT);
		else
			error = EIO;
	}
	(void)vmx_nested_l2_intel_clear_unpin(transaction);
	if (vmx_nested_l2_intel_resources_intact(transaction, &plan->id,
	    transaction->vcpu->nested_vmcs02_resources.resource_generation))
		(void)vmx_nested_vmcs02_resources_intel_release(
		    transaction->vcpu,
		    &transaction->vcpu->nested_vmcs02_resources);
	return (error);
}

static const struct vmx_nested_l2_freeze_ops
vmx_nested_l2_freeze_intel_ops = {
	.capture_software = vmx_nested_l2_intel_capture_software,
	.detach = vmx_nested_l2_intel_detach,
	.install_l1 = vmx_nested_l2_intel_install_l1,
	.release_resources = vmx_nested_l2_intel_release_resources,
	.rollback_hot = vmx_nested_l2_intel_rollback_hot,
};

static int
vmx_nested_l2_intel_rebind(void *arg,
    const struct vmx_nested_l2_portable_state *portable,
    const struct vmx_nested_vmcs02_plan *unbound,
    struct vmx_nested_vmcs02_plan *rebound)
{
	struct vmx_nested_l2_intel_transaction *transaction;

	transaction = arg;
	return (vmx_nested_entry_environment_intel_rebind_portable(
	    transaction->vcpu, portable, unbound,
	    &vmx_nested_hardware_controls, &transaction->environment,
	    &transaction->fixed_resources, rebound));
}

static int
vmx_nested_l2_intel_acquire(void *arg,
    const struct vmx_nested_vmcs02_plan *plan, uint64_t *generation,
    bool *rollback_complete)
{
	struct vmx_nested_guest_memory_intel memory;
	struct vmx_nested_l2_intel_transaction *transaction;
	int error;

	transaction = arg;
	*rollback_complete = true;
	error = vmx_nested_guest_memory_intel_init(&memory,
	    transaction->vcpu->vcpu);
	if (error == 0)
		error = vmx_nested_vmcs02_resources_intel_reacquire(
		    transaction->vcpu, &plan->image,
		    &transaction->vcpu->nested_vmcs12_snapshot.controls,
		    vmx_nested_guest_memory_intel_memory(&memory),
		    &transaction->fixed_resources, &transaction->resources);
	if (error != 0)
		return (error);
	transaction->resources_acquired = true;
	*generation = transaction->resources.resource_generation;
	return (0);
}

static int
vmx_nested_l2_intel_install_l2(void *arg,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_software_msrs *software,
    bool *rollback_complete)
{
	struct vmx_nested_l2_intel_transaction *transaction;
	int clear_error, error;

	transaction = arg;
	if (transaction == NULL || transaction->vcpu == NULL || id == NULL ||
	    software == NULL || rollback_complete == NULL ||
	    transaction->critical_held || curthread->td_critnest == 0)
		return (EINVAL);
	transaction->critical_held = true;
	if (vmptrld(transaction->vcpu->vmcs) != VM_SUCCESS) {
		error = EIO;
		goto fail;
	}
	error = vmx_nested_software_msrs_install(transaction->vcpu, software,
	    &transaction->vcpu->nested_l1_software_msrs,
	    VMX_NESTED_HARDWARE_MSR_ENTRY, rollback_complete);
	if (error == 0)
		return (0);
fail:
	clear_error = vmx_nested_l2_intel_clear_unpin(transaction);
	if (clear_error != 0) {
		*rollback_complete = false;
		return (clear_error);
	}
	return (error);
}

static int
vmx_nested_l2_intel_program(void *arg,
    const struct vmx_nested_vmcs02_plan *plan, uint64_t generation,
    bool *rollback_complete)
{
	struct vmx_nested_l2_intel_transaction *transaction;
	int error;

	transaction = arg;
	if (!transaction->critical_held ||
	    !transaction->resources_acquired ||
	    transaction->resources.resource_generation != generation)
		return (EINVAL);
	error = vmx_nested_l2_intel_program_existing(transaction, plan,
	    &transaction->resources);
	if (error != 0) {
		*rollback_complete = true;
		return (error);
	}
	vmx_nested_software_msrs_commit(transaction->vcpu,
	    VMX_NESTED_HARDWARE_MSR_ENTRY);
	*rollback_complete = true;
	return (0);
}

static int
vmx_nested_l2_intel_rollback_cold(void *arg,
    const struct vmx_nested_vmcs02_id *id, uint64_t generation,
    bool *rollback_complete)
{
	struct vmx_nested_l2_intel_transaction *transaction;
	int clear_error, error, first_error, release_error;

	transaction = arg;
	*rollback_complete = false;
	first_error = 0;
	if (transaction->critical_held) {
		if (transaction->vcpu->nested_vmcs02_intel.launch.current) {
			error = vmx_nested_vmcs02_intel_leave(
			    &transaction->vcpu->nested_vmcs02_intel);
			if (error != 0 && first_error == 0)
				first_error = error;
		}
		if (transaction->vcpu->nested_hardware_msr_transition ==
		    VMX_NESTED_HARDWARE_MSR_ENTRY) {
			error = vmx_nested_software_msrs_rollback(
			    transaction->vcpu,
			    VMX_NESTED_HARDWARE_MSR_ENTRY);
			if (error != 0 && first_error == 0)
				first_error = error;
		}
		clear_error = vmx_nested_l2_intel_clear_unpin(transaction);
		if (clear_error != 0 && first_error == 0)
			first_error = clear_error;
	}
	if (transaction->resources_acquired) {
		if (transaction->resources.resource_generation != generation ||
		    !vmx_nested_vmcs02_id_equal(&transaction->resources.id, id))
			return (ESTALE);
		release_error = vmx_nested_vmcs02_resources_intel_release(
		    transaction->vcpu, &transaction->resources);
		if (release_error != 0) {
			if (first_error == 0)
				first_error = release_error;
		} else {
			transaction->resources_acquired = false;
		}
	}
	if (first_error != 0)
		return (first_error);
	*rollback_complete = true;
	return (0);
}

/*
 * Staged cold-thaw rollback runs in the same CPU-pinned window as VMCS02
 * programming.  It restores only CPU-local state.  Resource release is a
 * separate frozen callback and must never be smuggled into this path.
 */
static int
vmx_nested_l2_intel_rollback_hot_staged(void *arg,
    const struct vmx_nested_vmcs02_id *id, uint64_t generation,
    bool *rollback_complete)
{
	struct vmx_nested_l2_intel_transaction *transaction;
	int clear_error, error, first_error;

	transaction = arg;
	if (transaction == NULL || transaction->vcpu == NULL || id == NULL ||
	    rollback_complete == NULL || !transaction->critical_held ||
	    !transaction->resources_acquired ||
	    transaction->resources.resource_generation != generation ||
	    !vmx_nested_vmcs02_id_equal(&transaction->resources.id, id))
		return (EINVAL);
	*rollback_complete = false;
	first_error = 0;
	if (transaction->vcpu->nested_vmcs02_intel.launch.current) {
		error = vmx_nested_vmcs02_intel_leave(
		    &transaction->vcpu->nested_vmcs02_intel);
		if (error != 0)
			first_error = error;
	}
	if (transaction->vcpu->nested_hardware_msr_transition ==
	    VMX_NESTED_HARDWARE_MSR_ENTRY) {
		error = vmx_nested_software_msrs_rollback(transaction->vcpu,
		    VMX_NESTED_HARDWARE_MSR_ENTRY);
		if (error != 0 && first_error == 0)
			first_error = error;
	}
	clear_error = vmx_nested_l2_intel_clear_unpin(transaction);
	if (clear_error != 0 && first_error == 0)
		first_error = clear_error;
	if (first_error != 0)
		return (first_error);
	*rollback_complete = true;
	return (0);
}

static const struct vmx_nested_l2_thaw_frozen_ops
vmx_nested_l2_thaw_staged_frozen_intel_ops = {
	.provider_id = UINT64_C(0x494e54454c000001),
	.rebind_runtime = vmx_nested_l2_intel_rebind,
	.acquire_resources = vmx_nested_l2_intel_acquire,
	.release_resources = vmx_nested_l2_intel_rollback_cold,
};

static const struct vmx_nested_l2_thaw_hot_ops
vmx_nested_l2_thaw_staged_hot_intel_ops = {
	.install_l2 = vmx_nested_l2_intel_install_l2,
	.program_vmcs02 = vmx_nested_l2_intel_program,
	.rollback_hot = vmx_nested_l2_intel_rollback_hot_staged,
};

static int
vmx_nested_l2_intel_detach_unentered(void *arg,
    const struct vmx_nested_vmcs02_id *id, uint64_t generation,
    bool *rollback_complete)
{
	struct vmx_nested_l2_intel_transaction *transaction;
	bool msr_complete;
	int error, rollback_error;

	transaction = arg;
	if (transaction == NULL || transaction->vcpu == NULL || id == NULL ||
	    rollback_complete == NULL || !transaction->critical_held ||
	    curthread->td_critnest == 0 ||
	    generation == 0 ||
	    generation != transaction->vcpu->nested_vmcs02_resources.
	    resource_generation ||
	    !vmx_nested_vmcs02_id_equal(id,
	    &transaction->vcpu->nested_vmcs02_resources.id))
		return (EINVAL);
	*rollback_complete = false;
	error = vmx_nested_software_msrs_leave_l2(transaction->vcpu,
	    &msr_complete);
	if (error != 0) {
		*rollback_complete = msr_complete;
		return (msr_complete ? error : EIO);
	}
	transaction->l1_msrs_installed = true;
	error = vmx_nested_vmcs02_intel_leave(
	    &transaction->vcpu->nested_vmcs02_intel);
	if (error != 0) {
		/*
		 * A failed restore of VMCS01 may follow a successful VMCLEAR.
		 * Even if the software-MSR bank can be rolled back, VMCS02
		 * residency is no longer provable, so the transaction is
		 * necessarily quarantined.
		 */
		rollback_error = vmx_nested_software_msrs_rollback(
		    transaction->vcpu, VMX_NESTED_HARDWARE_MSR_EXIT);
		if (rollback_error == 0)
			transaction->l1_msrs_installed = false;
		return (EIO);
	}
	/*
	 * The frozen continuation may run on another CPU.  Complete the
	 * CPU-local MSR transition before publishing the cross-boundary
	 * request; only opaque resource release remains.
	 */
	vmx_nested_software_msrs_commit(transaction->vcpu,
	    VMX_NESTED_HARDWARE_MSR_EXIT);
	transaction->l1_msrs_installed = false;
	*rollback_complete = true;
	return (0);
}

static int
vmx_nested_l2_intel_release_unentered(void *arg,
    const struct vmx_nested_vmcs02_id *id, uint64_t generation,
    bool *rollback_complete)
{
	struct vmx_nested_l2_intel_transaction *transaction;
	int error;

	transaction = arg;
	if (transaction == NULL || transaction->vcpu == NULL || id == NULL ||
	    rollback_complete == NULL || transaction->critical_held ||
	    transaction->l1_msrs_installed ||
	    transaction->vcpu->nested_vmcs02_intel.launch.current ||
	    transaction->vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    transaction->vcpu->nested_tsc_aux_residency !=
	    VMX_NESTED_TSC_AUX_L1 ||
	    curthread->td_critnest != 0)
		return (EINVAL);
	*rollback_complete = false;
	error = vmx_nested_vmcs02_resources_intel_release(transaction->vcpu,
	    &transaction->vcpu->nested_vmcs02_resources);
	if (error != 0) {
		*rollback_complete = vmx_nested_l2_intel_resources_intact(
		    transaction, id, generation);
		return (error);
	}
	*rollback_complete = true;
	return (0);
}

static const struct vmx_nested_refreeze_hot_ops
vmx_nested_refreeze_hot_intel_ops = {
	.provider_id = UINT64_C(0x494e54454c000002),
	.detach_hot = vmx_nested_l2_intel_detach_unentered,
};

static const struct vmx_nested_refreeze_frozen_ops
vmx_nested_refreeze_frozen_intel_ops = {
	.provider_id = UINT64_C(0x494e54454c000002),
	.release_resources = vmx_nested_l2_intel_release_unentered,
};

static int
vmx_nested_l0_freeze_intel(void *arg,
    const struct vmx_nested_vmcs02_id *id, uint64_t *portable_generation,
    bool *rollback_complete)
{
	struct vmx_nested_l2_freeze_input input;
	struct vmx_nested_l2_intel_transaction transaction;
	struct vmx_nested_l2_portable_state portable;
	struct vmx_vcpu *vcpu;
	uint64_t generation, l1_virtual_tsc;
	int error;

	vcpu = arg;
	if (vcpu == NULL || id == NULL || portable_generation == NULL ||
	    rollback_complete == NULL ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    !vmx_nested_vmcs02_id_equal(id, &vcpu->nested_vmcs02_plan.id) ||
	    !vcpu->nested_vmcs02_intel.launch.current ||
	    curthread->td_critnest == 0 ||
	    vcpu->nested_l2_portable_valid)
		return (EINVAL);
	if (vcpu->nested_portable_generation == UINT64_MAX)
		return (EOVERFLOW);
	generation = vcpu->nested_portable_generation + 1;
	l1_virtual_tsc = vmx_nested_tsc_scaled_ticks(rdtsc(),
	    vcpu->nested_entry_environment.tsc.l1_multiplier,
	    vcpu->nested_entry_environment.tsc.l1_offset);
	memset(&transaction, 0, sizeof(transaction));
	transaction.vcpu = vcpu;
	transaction.critical_held = true;
	memset(&input, 0, sizeof(input));
	input.executed_plan = &vcpu->nested_vmcs02_plan;
	input.capabilities = &vcpu->nested_vmcs12_snapshot.capabilities;
	input.resource_generation =
	    vcpu->nested_vmcs02_resources.resource_generation;
	input.portable_generation = generation;
	input.l1_virtual_tsc = l1_virtual_tsc;
	error = vmx_nested_l2_freeze(&input,
	    &vmx_nested_l2_freeze_intel_ops, &transaction, &portable,
	    rollback_complete);
	if (error != 0)
		return (error);
	if (transaction.critical_held ||
	    transaction.l1_msrs_installed)
		return (EPROTO);
	if (vcpu->nested_mtf_owner.pending) {
		/*
		 * The detached portable image is not externally visible yet.
		 * Move the hot obligation into that strictly newer image before
		 * publishing either owner.  Failure here means the already
		 * detached hardware state contradicted its generation-bound
		 * runtime owner and cannot be recovered by returning an error.
		 */
		error = vmx_nested_mtf_owner_put_portable(
		    &vcpu->nested_mtf_owner, &portable,
		    &vcpu->nested_vmcs02_plan);
		if (error != 0)
			panic("%s: cannot refreeze nested MTF owner: %d",
			    __func__, error);
	}

	vcpu->nested_l2_portable = portable;
	vcpu->nested_l2_portable_valid = true;
	vcpu->nested_portable_generation = generation;
	vcpu->nested_l2_software_msrs = portable.software_msrs;
	memset(&vcpu->nested_vmcs02_resources, 0,
	    sizeof(vcpu->nested_vmcs02_resources));
	*portable_generation = generation;
	return (0);
}

static int
vmx_nested_l0_thaw_prepare_intel(struct vmx_vcpu *vcpu,
    const struct vmx_nested_l2_portable_state *portable)
{
	struct vmx_nested_l2_intel_transaction transaction;
	struct vmx_nested_l2_thaw_input input;
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (vcpu == NULL || portable == NULL ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    !vcpu->nested_l2_portable_valid ||
	    vcpu->nested_thaw_resources_valid ||
	    vcpu->nested_l2_thaw_staged.state !=
	    VMX_NESTED_L2_THAW_STAGED_IDLE ||
	    curthread->td_critnest != 0)
		return (EINVAL);
	id = &vcpu->nested_l0_continuation.id;
	memset(&transaction, 0, sizeof(transaction));
	transaction.vcpu = vcpu;
	memset(&input, 0, sizeof(input));
	input.portable = portable;
	input.capabilities = &vcpu->nested_vmcs12_snapshot.capabilities;
	input.frozen_plan = &vcpu->nested_vmcs02_plan;
	error = vmx_nested_l0_continuation_thaw_prepare(
	    &vcpu->nested_l0_continuation, &vcpu->nested_entry_runtime, id,
	    &vcpu->nested_l2_thaw_staged, &input,
	    &vmx_nested_l2_thaw_staged_frozen_intel_ops, &transaction);
	if (error != 0)
		return (error);
	if (!transaction.resources_acquired ||
	    transaction.critical_held ||
	    transaction.resources.resource_generation !=
	    vcpu->nested_l2_thaw_staged.resource_generation) {
		error = vmx_nested_l0_continuation_thaw_cancel_frozen(
		    &vcpu->nested_l0_continuation,
		    &vcpu->nested_entry_runtime, id,
		    &vcpu->nested_l2_thaw_staged,
		    &vmx_nested_l2_thaw_staged_frozen_intel_ops,
		    &transaction);
		if (error != 0)
			panic("%s: cannot unwind invalid frozen thaw: %d",
			    __func__, error);
		return (EPROTO);
	}
	vcpu->nested_thaw_environment = transaction.environment;
	vcpu->nested_thaw_fixed_resources = transaction.fixed_resources;
	vcpu->nested_thaw_resources = transaction.resources;
	vcpu->nested_thaw_resources_valid = true;
	return (0);
}

static int
vmx_nested_l0_thaw_commit_hot_intel(struct vmx_vcpu *vcpu)
{
	struct vmx_nested_l2_intel_transaction transaction;
	struct vmx_nested_entry_environment environment;
	struct vmx_nested_vmcs02_plan plan;
	struct vmx_nested_vmcs02_plan refreshed;
	const struct vmx_nested_vmcs02_id *id;
	uint64_t generation;
	int error;

	if (vcpu == NULL || !vcpu->nested_thaw_resources_valid ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	id = &vcpu->nested_l0_continuation.id;
	/*
	 * Frozen thaw may be prepared on a different CPU.  VMCS01 is current
	 * here on the final execution CPU; refresh all host-derived state and
	 * reject a changed fixed resource before installing L2's MSRs.
	 */
	error =
	    vmx_nested_entry_environment_intel_refresh_portable_current(vcpu,
	    &vcpu->nested_l2_portable, &vcpu->nested_l2_thaw_staged.plan,
	    &vmx_nested_hardware_controls, &vcpu->nested_thaw_resources,
	    &environment, &refreshed);
	if (error != 0)
		return (error);
	vcpu->nested_l2_thaw_staged.plan = refreshed;
	memset(&transaction, 0, sizeof(transaction));
	transaction.vcpu = vcpu;
	transaction.environment = environment;
	transaction.fixed_resources = vcpu->nested_thaw_fixed_resources;
	transaction.resources = vcpu->nested_thaw_resources;
	transaction.resources_acquired = true;
	error = vmx_nested_l0_continuation_thaw_commit_hot(
	    &vcpu->nested_l0_continuation, &vcpu->nested_entry_runtime, id,
	    &vcpu->nested_l2_thaw_staged,
	    &vmx_nested_l2_thaw_staged_hot_intel_ops, &transaction, &plan,
	    &generation);
	if (error != 0)
		return (error);
	if (!transaction.critical_held ||
	    !vcpu->nested_vmcs02_intel.launch.current ||
	    generation != vcpu->nested_thaw_resources.resource_generation)
		panic("%s: successful hot thaw lost hardware ownership",
		    __func__);
	vcpu->nested_entry_environment = environment;
	vcpu->nested_vmcs02_resources = vcpu->nested_thaw_resources;
	vcpu->nested_vmcs02_plan = plan;
	vcpu->nested_l2_software_msrs =
	    vcpu->nested_l2_portable.software_msrs;
	memset(&vcpu->nested_thaw_environment, 0,
	    sizeof(vcpu->nested_thaw_environment));
	memset(&vcpu->nested_thaw_fixed_resources, 0,
	    sizeof(vcpu->nested_thaw_fixed_resources));
	memset(&vcpu->nested_thaw_resources, 0,
	    sizeof(vcpu->nested_thaw_resources));
	vcpu->nested_thaw_resources_valid = false;
	/*
	 * Retain the portable source until VMRESUME produces a real VM exit.
	 * A raw VMfail did not enter L2 and must be able to return to this
	 * exact cold image without inventing state from stale VMCS exit
	 * fields.
	 */
	return (0);
}

static int
vmx_nested_l0_refreeze_unentered_intel(struct vmx_vcpu *vcpu)
{
	struct vmx_nested_l2_intel_transaction transaction;
	struct vmx_nested_refreeze_request request;
	uint64_t generation;
	int error;

	if (vcpu == NULL || curthread->td_critnest == 0 ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    !vcpu->nested_l2_portable_valid ||
	    !vcpu->nested_vmcs02_intel.launch.current ||
	    vcpu->nested_refreeze_staged.state !=
	    VMX_NESTED_REFREEZE_IDLE ||
	    vcpu->nested.internal.kind != VMX_NESTED_INTERNAL_NONE)
		return (EINVAL);
	generation = vcpu->nested_vmcs02_resources.resource_generation;
	memset(&transaction, 0, sizeof(transaction));
	transaction.vcpu = vcpu;
	transaction.environment = vcpu->nested_entry_environment;
	transaction.critical_held = true;
	error = vmx_nested_refreeze_prepare_hot(
	    &vcpu->nested_refreeze_staged,
	    &vcpu->nested_l0_continuation, &vcpu->nested_entry_runtime,
	    &vcpu->nested_vmcs02_plan, &vcpu->nested_l2_portable,
	    generation, &vmx_nested_refreeze_hot_intel_ops, &transaction);
	if (error != 0)
		return (error);
	if (transaction.l1_msrs_installed ||
	    vcpu->nested_vmcs02_intel.launch.current ||
	    vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1)
		panic("%s: successful refreeze retained hot ownership",
		    __func__);
	error = vmx_nested_refreeze_request_build(
	    &vcpu->nested_refreeze_staged, &request);
	if (error != 0)
		panic("%s: detached refreeze cannot build handoff: %d",
		    __func__, error);
	error = vmx_nested_internal_publish_refreeze(
	    &vcpu->nested.internal, &request);
	if (error != 0)
		panic("%s: prevalidated refreeze publication failed: %d",
		    __func__, error);
	return (0);
}

static int
vmx_nested_l0_refreeze_late_entry_intel(struct vmx_vcpu *vcpu,
    const struct vmx_nested_attempt_plan *attempt)
{
	struct vmx_nested_l2_intel_transaction transaction;
	struct vmx_nested_late_entry late;
	struct vmx_nested_refreeze_request request;
	uint64_t generation;
	int error;

	if (vcpu == NULL || attempt == NULL ||
	    vmx_nested_attempt_plan_validate(attempt) != 0 ||
	    curthread->td_critnest == 0 ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    !vcpu->nested_l2_portable_valid ||
	    !vcpu->nested_vmcs02_intel.launch.current ||
	    vcpu->nested_refreeze_staged.state !=
	    VMX_NESTED_REFREEZE_IDLE ||
	    vcpu->nested.internal.kind != VMX_NESTED_INTERNAL_NONE)
		return (EINVAL);
	error = vmx_nested_late_entry_prepare(&vcpu->nested_vmcs02_plan,
	    &vcpu->nested_l2_portable, attempt, &late);
	if (error != 0)
		return (error);
	generation = vcpu->nested_vmcs02_resources.resource_generation;
	memset(&transaction, 0, sizeof(transaction));
	transaction.vcpu = vcpu;
	transaction.environment = vcpu->nested_entry_environment;
	transaction.critical_held = true;
	error = vmx_nested_refreeze_prepare_late_entry_hot(
	    &vcpu->nested_refreeze_staged,
	    &vcpu->nested_l0_continuation, &vcpu->nested_entry_runtime,
	    &vcpu->nested_vmcs02_plan, &vcpu->nested_l2_portable,
	    generation, &late, &vmx_nested_refreeze_hot_intel_ops,
	    &transaction);
	if (error != 0)
		return (error);
	if (transaction.l1_msrs_installed ||
	    vcpu->nested_vmcs02_intel.launch.current ||
	    vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1)
		panic("%s: successful late refreeze retained hot ownership",
		    __func__);
	error = vmx_nested_refreeze_request_build(
	    &vcpu->nested_refreeze_staged, &request);
	if (error != 0)
		panic("%s: detached late refreeze cannot build handoff: %d",
		    __func__, error);
	error = vmx_nested_internal_publish_refreeze(
	    &vcpu->nested.internal, &request);
	if (error != 0)
		panic("%s: prevalidated late refreeze publication failed: %d",
		    __func__, error);
	return (0);
}

static int
vmx_nested_l0_refreeze_commit_frozen_intel(struct vmx_vcpu *vcpu)
{
	struct vmx_nested_l2_intel_transaction transaction;
	struct vmx_nested_continuation_handoff_request continuation;
	struct vmx_nested_refreeze_request request;
	int error;

	if (vcpu == NULL || curthread->td_critnest != 0 ||
	    vcpu->nested.internal.kind != VMX_NESTED_INTERNAL_REFREEZE)
		return (EINVAL);
	request = vcpu->nested.internal.operation.refreeze;
	error = vmx_nested_refreeze_request_validate(
	    &vcpu->nested_refreeze_staged, &request);
	if (error != 0)
		return (error);
	memset(&transaction, 0, sizeof(transaction));
	transaction.vcpu = vcpu;
	error = vmx_nested_refreeze_commit_frozen(
	    &vcpu->nested_refreeze_staged,
	    &vcpu->nested_l0_continuation, &vcpu->nested_entry_runtime,
	    &vcpu->nested_l2_portable, &vmx_nested_refreeze_frozen_intel_ops,
	    &transaction);
	if (error != 0)
		return (error);
	memset(&vcpu->nested_vmcs02_resources, 0,
	    sizeof(vcpu->nested_vmcs02_resources));
	error = vmx_nested_internal_take_refreeze(
	    &vcpu->nested.internal, &request);
	if (error != 0)
		panic("%s: committed refreeze lost handoff ownership: %d",
		    __func__, error);
	if (request.purpose == VMX_NESTED_REFREEZE_LATE_ENTRY) {
		error = vmx_nested_late_entry_publish(&vcpu->nested,
		    &vcpu->nested_entry_runtime, &request.late_entry);
		if (error != 0)
			panic("%s: cold late-entry publication failed: %d",
			    __func__, error);
		return (0);
	}
	if (request.purpose != VMX_NESTED_REFREEZE_RETRY)
		panic("%s: invalid committed refreeze purpose %u", __func__,
		    request.purpose);
	error = vmx_nested_continuation_handoff_request_build(
	    &vcpu->nested_l0_continuation, &continuation);
	if (error != 0)
		panic("%s: cold refreeze cannot build continuation: %d",
		    __func__, error);
	error = vmx_nested_internal_publish_continuation(
	    &vcpu->nested.internal, &continuation);
	if (error != 0)
		panic("%s: cold continuation publication failed: %d",
		    __func__, error);
	return (0);
}

static int
vmx_nested_l0_thaw_cancel_intel(struct vmx_vcpu *vcpu)
{
	struct vmx_nested_l2_intel_transaction transaction;
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (vcpu == NULL || !vcpu->nested_thaw_resources_valid ||
	    curthread->td_critnest != 0)
		return (EINVAL);
	id = &vcpu->nested_l0_continuation.id;
	memset(&transaction, 0, sizeof(transaction));
	transaction.vcpu = vcpu;
	transaction.environment = vcpu->nested_thaw_environment;
	transaction.fixed_resources = vcpu->nested_thaw_fixed_resources;
	transaction.resources = vcpu->nested_thaw_resources;
	transaction.resources_acquired = true;
	error = vmx_nested_l0_continuation_thaw_cancel_frozen(
	    &vcpu->nested_l0_continuation, &vcpu->nested_entry_runtime, id,
	    &vcpu->nested_l2_thaw_staged,
	    &vmx_nested_l2_thaw_staged_frozen_intel_ops, &transaction);
	if (error != 0)
		return (error);
	memset(&vcpu->nested_thaw_environment, 0,
	    sizeof(vcpu->nested_thaw_environment));
	memset(&vcpu->nested_thaw_fixed_resources, 0,
	    sizeof(vcpu->nested_thaw_fixed_resources));
	memset(&vcpu->nested_thaw_resources, 0,
	    sizeof(vcpu->nested_thaw_resources));
	vcpu->nested_thaw_resources_valid = false;
	return (0);
}

static int
vmx_nested_handle_continuation_frozen(void *arg,
    const struct vmx_nested_continuation_handoff_request *request,
    struct vmx_nested_continuation_handoff_result *result)
{
	struct vmx_nested_continuation_handoff_request expected;
	struct vmx_nested_mtf_event_snapshot mtf_snapshot;
	struct vmx_nested_l2_portable_state portable_candidate;
	struct vmx_nested_mtf_input mtf_input;
	struct vmx_nested_mtf_plan mtf_plan;
	struct vm_intinfo_snapshot snapshot;
	struct vmx_nested_l2_portable_state *portable;
	struct vmx_vcpu *vcpu;
	uint64_t instruction_rip, next_rip;
	uint32_t instruction_length;
	bool retired;
	int error;

	vcpu = arg;
	if (vcpu == NULL || request == NULL || result == NULL ||
	    curthread->td_critnest != 0)
		return (EINVAL);
	error = vmx_nested_continuation_handoff_request_build(
	    &vcpu->nested_l0_continuation, &expected);
	if (error != 0)
		return (error);
	if (request->id.state_generation !=
	    expected.id.state_generation ||
	    request->id.execution_epoch != expected.id.execution_epoch ||
	    request->id.vmcs12_gpa != expected.id.vmcs12_gpa ||
	    request->exit_sequence != expected.exit_sequence ||
	    request->portable_generation !=
	    expected.portable_generation ||
	    request->completion != expected.completion)
		return (ESTALE);
	error = vmx_nested_cold_l2(vcpu, &portable);
	if (error != 0)
		return (error);
	if (portable->portable_generation !=
	    request->portable_generation)
		return (ESTALE);

	switch (request->completion) {
	case VMX_NESTED_L0_COMPLETE_RESUME_L2:
		/*
		 * Device emulation advances the architecture-neutral VMM's
		 * decoded completion tuple after VMCS02 has been frozen.  Commit
		 * that exact instruction boundary to the portable L2 image before
		 * thaw constructs a replacement VMCS02.  The hardware exit length
		 * is not authoritative for EPT/MMIO.  vm_restart_instruction()
		 * leaves nextrip at the decoded exit RIP and is therefore a no-op.
		 */
		error = vm_get_instruction_completion(vcpu->vcpu,
		    &instruction_rip, &instruction_length, &next_rip);
		if (error != 0)
			return (error);
		portable_candidate = *portable;
		error = vmx_nested_l2_portable_complete_instruction(
		    &portable_candidate,
		    &vcpu->nested_vmcs12_snapshot.capabilities,
		    &vcpu->nested_vmcs02_plan, instruction_rip,
		    instruction_length, next_rip, &retired);
		if (error != 0)
			return (error);
		if (portable_candidate.mtf_pending) {
			error = vm_entry_intinfo_peek(vcpu->vcpu, &snapshot);
			if (error != 0)
				return (error);
			error = vmx_nested_mtf_snapshot_intel(&snapshot,
			    &mtf_snapshot);
			if (error != 0)
				return (error);
			error = vmx_nested_mtf_input_from_snapshot(&mtf_snapshot,
			    true, false, false, &mtf_input);
			if (error != 0)
				return (error);
			error = vmx_nested_mtf_plan(&mtf_input, &mtf_plan);
			if (error != 0)
				return (error);
			if (mtf_plan.action == VMX_NESTED_MTF_REFLECT) {
				*portable = portable_candidate;
				result->disposition =
				    VMX_NESTED_CONTINUATION_MTF_REFLECTED;
				return (0);
			}
			/*
			 * DEFER is a request to re-run arbitration after the
			 * nested-entry or reinjection blocker clears, not permission
			 * to execute another L2 instruction.  DISCARD likewise needs
			 * authoritative INIT-in-wait-for-SIPI provenance.  Preserve
			 * the complete cold owner until those retry boundaries exist.
			 */
			return (EOPNOTSUPP);
		}
		error = vmx_nested_l0_thaw_prepare_intel(vcpu,
		    &portable_candidate);
		if (error != 0)
			return (error);
		*portable = portable_candidate;
		result->disposition =
		    VMX_NESTED_CONTINUATION_RESUME_PREPARED;
		return (0);
	case VMX_NESTED_L0_COMPLETE_REFLECT_L1:
		result->disposition = VMX_NESTED_CONTINUATION_REFLECTED;
		return (0);
	default:
		return (EPROTO);
	}
}

static bool
vmx_nested_l0_event_needs_instruction_length(uint64_t entry)
{
	uint32_t info, type, vector;

	info = (uint32_t)entry;
	type = info & VM_INTINFO_TYPE;
	vector = VM_INTINFO_VECTOR(info);
	return (type == VM_INTINFO_SWINTR ||
	    type == (UINT32_C(5) << 8) ||
	    type == (UINT32_C(6) << 8) ||
	    (type == VM_INTINFO_HWEXCEPTION &&
	    (vector == IDT_BP || vector == IDT_OF)));
}

static int
vmx_nested_async_event_intel_peek(struct vmx_vcpu *vcpu,
    struct vmx_nested_entry_event_intel *event,
    struct vmx_nested_entry_event_input *entry)
{
	struct vmx_nested_event_input input;
	const struct vmx_nested_vmcs02_image *image;
	uint64_t rflags;
	uint32_t interruptibility;
	int vector;

	if (vcpu == NULL || event == NULL || entry == NULL ||
	    event->async_source != VMX_NESTED_ASYNC_SOURCE_NONE)
		return (EINVAL);
	image = &vcpu->nested_vmcs02_plan.image;
	if (vcpu->nested_entry_runtime.state ==
	    VMX_NESTED_ENTRY_RUNTIME_L0_EXIT) {
		if (!vcpu->nested_vmcs02_intel.launch.current)
			return (ESTALE);
		interruptibility =
		    vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
		rflags = vmcs_read(VMCS_GUEST_RFLAGS);
	} else {
		interruptibility = image->l2_arch.interruptibility;
		rflags = image->l2_arch.rflags;
	}
	memset(&input, 0, sizeof(input));

	/*
	 * Intel's nested-event order places an open NMI window ahead of a
	 * pending NMI, and both ahead of maskable-interrupt work.  A blocked
	 * pending NMI instead requests a window and remains unconsumed.
	 */
	if ((vcpu->nested_vmcs12_snapshot.controls.primary &
	    PROCBASED_NMI_WINDOW_EXITING) != 0 &&
	    (interruptibility & (VMCS_INTERRUPTIBILITY_STI_BLOCKING |
	    VMCS_INTERRUPTIBILITY_MOVSS_BLOCKING |
	    VMCS_INTERRUPTIBILITY_NMI_BLOCKING)) == 0) {
		input.kind = VMX_NESTED_EVENT_NMI;
		input.l1_window_exiting = true;
	} else if (vm_nmi_pending(vcpu->vcpu)) {
		input.kind = VMX_NESTED_EVENT_NMI;
		input.pending = true;
		input.guest_blocked = (interruptibility &
		    (VMCS_INTERRUPTIBILITY_STI_BLOCKING |
		    VMCS_INTERRUPTIBILITY_MOVSS_BLOCKING |
		    VMCS_INTERRUPTIBILITY_NMI_BLOCKING)) != 0;
		input.l1_event_exiting =
		    (vcpu->nested_vmcs12_snapshot.controls.pinbased &
		    PINBASED_NMI_EXITING) != 0;
		input.l1_window_exiting =
		    (vcpu->nested_vmcs12_snapshot.controls.primary &
		    PROCBASED_NMI_WINDOW_EXITING) != 0;
		event->async_source = VMX_NESTED_ASYNC_SOURCE_NMI;
	} else if ((vcpu->nested_vmcs12_snapshot.controls.primary &
	    PROCBASED_INT_WINDOW_EXITING) != 0 &&
	    (rflags & PSL_I) != 0 &&
	    (interruptibility & HWINTR_BLOCKING) == 0) {
		input.kind = VMX_NESTED_EVENT_EXTERNAL_INTERRUPT;
		input.l1_window_exiting = true;
	} else {
		input.kind = VMX_NESTED_EVENT_EXTERNAL_INTERRUPT;
		if (vm_extint_pending(vcpu->vcpu)) {
			vatpic_pending_intr(vcpu->vmx->vm, &vector);
			event->async_source =
			    VMX_NESTED_ASYNC_SOURCE_EXTINT;
		} else if (vlapic_pending_intr(vm_lapic(vcpu->vcpu),
		    &vector)) {
			event->async_source =
			    VMX_NESTED_ASYNC_SOURCE_LAPIC;
		} else {
			return (0);
		}
		if (vector < 0 || vector > 255)
			return (EPROTO);
		event->async_vector = vector;
		input.pending = true;
		input.vector = vector;
		input.vector_valid = true;
		input.guest_blocked = (rflags & PSL_I) == 0 ||
		    (interruptibility & HWINTR_BLOCKING) != 0;
		input.l1_event_exiting =
		    (vcpu->nested_vmcs12_snapshot.controls.pinbased &
		    PINBASED_EXTINT_EXITING) != 0;
		input.l1_window_exiting =
		    (vcpu->nested_vmcs12_snapshot.controls.primary &
		    PROCBASED_INT_WINDOW_EXITING) != 0;
		input.acknowledge_on_exit =
		    (vcpu->nested_vmcs12_snapshot.controls.vmexit &
		    VM_EXIT_ACKNOWLEDGE_INTERRUPT) != 0;
	}
	entry->async_valid = true;
	return (vmx_nested_event_plan(&input, &entry->async_event));
}

/*
 * Snapshot the generic L0 event without consuming it and bind that exact
 * snapshot to the final VMCS02 hardware image.  The caller holds the frozen
 * vCPU with interrupts disabled and VMCS01 current, so the instruction-length
 * field and the generic event sources cannot race this transaction.
 */
static int
vmx_nested_mtf_snapshot_intel(
    const struct vm_intinfo_snapshot *source,
    struct vmx_nested_mtf_event_snapshot *destination)
{
	struct vmx_nested_mtf_event_snapshot candidate;

	if (source == NULL || destination == NULL)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.exitintinfo = source->exitintinfo;
	candidate.exception = source->exception;
	candidate.valid = source->valid;
	candidate.triple_fault = source->triple_fault;
	switch (source->exception_class) {
	case VM_EXCEPTION_NONE:
		candidate.exception_class = VMX_NESTED_EXCEPTION_NONE;
		break;
	case VM_EXCEPTION_FAULT:
		candidate.exception_class = VMX_NESTED_EXCEPTION_FAULT;
		break;
	case VM_EXCEPTION_TRAP:
		candidate.exception_class = VMX_NESTED_EXCEPTION_TRAP;
		break;
	case VM_EXCEPTION_ICEBP:
		candidate.exception_class = VMX_NESTED_EXCEPTION_ICEBP;
		break;
	case VM_EXCEPTION_TASK_SWITCH:
		candidate.exception_class =
		    VMX_NESTED_EXCEPTION_TASK_SWITCH;
		break;
	default:
		return (EINVAL);
	}
	*destination = candidate;
	return (0);
}

static int
vmx_nested_entry_event_intel_plan(struct vmx_vcpu *vcpu,
    struct vmx_nested_entry_event_intel *event, bool prepare_hardware)
{
	struct vmx_nested_mtf_event_snapshot mtf_snapshot;
	struct vmx_nested_mtf_input mtf_input;
	struct vmx_nested_entry_event_input input;
	uint32_t instruction_length;
	int error;

	if (vcpu == NULL || event == NULL || event->active ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	memset(&input, 0, sizeof(input));
	error = vm_entry_intinfo_peek(vcpu->vcpu, &event->snapshot);
	if (error != 0)
		return (error);
	if (vcpu->nested_l2_portable_valid) {
		error = vmx_nested_mtf_snapshot_intel(&event->snapshot,
		    &mtf_snapshot);
		if (error != 0)
			goto fail;
		error = vmx_nested_mtf_input_from_snapshot(&mtf_snapshot,
		    vcpu->nested_l2_portable.mtf_pending, false, false,
		    &mtf_input);
		if (error != 0)
			goto fail;
		/*
		 * This portable owner exists only after L2 entered and L0 froze an
		 * exit.  VMCS12's entry-interruption field is persistent input, not
		 * evidence of a new pending VM entry at this instruction boundary.
		 * Reinjection is already carried by the coherent event snapshot.
		 */
		error = vmx_nested_mtf_plan(&mtf_input, &event->mtf_plan);
		if (error != 0)
			goto fail;
		event->mtf_portable_generation =
		    vcpu->nested_l2_portable.portable_generation;
		event->mtf_valid = true;
		/*
		 * Exposure remains withheld.  Until REFLECT, DEFER, and DISCARD
		 * have complete hot-owner commits, fail closed rather than enter
		 * L2 and discard a pending software MTF owner.
		 */
		if (event->mtf_plan.action != VMX_NESTED_MTF_NONE) {
			error = EOPNOTSUPP;
			goto fail;
		}
	}
	instruction_length = 0;
	if (event->snapshot.valid &&
	    vmx_nested_l0_event_needs_instruction_length(
	    event->snapshot.entry)) {
		/*
		 * A reinjected software event owns VMCS01's saved entry
		 * length.  A newly queued software exception has no retired
		 * instruction and therefore uses zero, which is legal only
		 * when the virtual IA32_VMX_MISC[30] capability says so.
	 */
		if (event->snapshot.entry == event->snapshot.exitintinfo) {
			error =
			    vmx_nested_vmcs02_intel_capture_vmcs01_entry_instruction_length(
			    &vcpu->nested_vmcs02_intel,
			    &instruction_length);
			if (error != 0)
				goto fail;
		}
	}
	input.l0_intinfo = event->snapshot.entry;
	input.l0_instruction_length = instruction_length;
	input.vmcs12_intr_info =
	    vcpu->nested_vmcs02_plan.image.vmcs12_entry_intr_info;
	input.vmcs12_exception_error =
	    vcpu->nested_vmcs02_plan.image.entry_exception_error;
	input.vmcs12_instruction_length =
	    vcpu->nested_vmcs02_plan.image.entry_instruction_length;
	input.vmcs12_event_validated = true;
	input.zero_instruction_length_allowed =
	    (vcpu->nested_vmcs12_snapshot.capabilities.misc &
	    (UINT64_C(1) << 30)) != 0;
	input.l0_valid = event->snapshot.valid;
	input.l0_triple_fault = event->snapshot.triple_fault;
	if (!input.l0_valid && !input.l0_triple_fault &&
	    (input.vmcs12_intr_info & VMCS_INTR_VALID) == 0) {
		error = vmx_nested_async_event_intel_peek(vcpu, event, &input);
		if (error != 0)
			goto fail;
	}
	error = vmx_nested_entry_event_plan(&input, &event->plan);
	if (error != 0)
		goto fail;
	if (prepare_hardware &&
	    event->plan.action != VMX_NESTED_ENTRY_EVENT_SHUTDOWN &&
	    (!event->plan.async_valid ||
	    (event->plan.async_event.action !=
	    VMX_NESTED_EVENT_ACTION_REFLECT_WINDOW &&
	    event->plan.async_event.action !=
	    VMX_NESTED_EVENT_ACTION_REFLECT_EVENT))) {
		error = vmx_nested_final_hardware_prepare(vcpu, &event->plan);
		if (error != 0)
			goto fail;
	}
	event->vcpu = vcpu;
	event->active = true;
	return (0);
fail:
	memset(event, 0, sizeof(*event));
	return (error);
}

static int
vmx_nested_entry_event_intel_prepare(struct vmx_vcpu *vcpu,
    struct vmx_nested_entry_event_intel *event)
{

	return (vmx_nested_entry_event_intel_plan(vcpu, event, true));
}

static int
vmx_nested_resume_reprogram_intel(struct vmx_vcpu *vcpu,
    const struct vmx_nested_entry_event_plan *event)
{
	struct vmx_nested_vmcs02_plan candidate;
	uint64_t old_error, old_info, old_length;
	uint32_t new_primary, old_primary;
	int error, rollback_error;

	if (vcpu == NULL || event == NULL ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    vcpu->nested_l0_continuation.state !=
	    VMX_NESTED_L0_CONTINUATION_HOT ||
	    !vcpu->nested_vmcs02_intel.launch.current ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	error = vmx_nested_entry_event_apply(event,
	    &vcpu->nested_vmcs02_plan, &candidate);
	if (error != 0)
		return (error);

	/*
	 * VMCS02 already contains the live post-exit L2 state.  Reapplying a
	 * complete cached plan here would rewind RIP, interruptibility,
	 * control registers, and the running preemption timer.  A hot retry
	 * changes only entry-event fields and L0's transient window bits.
	 */
	old_primary = vmcs_read(VMCS_PRI_PROC_BASED_CTLS);
	old_info = vmcs_read(VMCS_ENTRY_INTR_INFO);
	old_error = vmcs_read(VMCS_ENTRY_EXCEPTION_ERROR);
	old_length = vmcs_read(VMCS_ENTRY_INST_LENGTH);
	error = vmx_nested_event_window_controls(old_primary,
	    vcpu->nested_entry_environment.l0_controls.primary,
	    vcpu->nested_vmcs12_snapshot.controls.primary,
	    event->async_valid ? &event->async_event : NULL, &new_primary);
	if (error != 0)
		return (error);

	/*
	 * Keep VALID clear until all dependent fields are installed.  On any
	 * VMwrite failure, restore the exact prior image before reporting a
	 * retryable L0 error.
	 */
	error = vmwrite(VMCS_ENTRY_INTR_INFO, 0);
	if (error == VM_SUCCESS)
		error = vmwrite(VMCS_ENTRY_EXCEPTION_ERROR,
		    candidate.image.entry_exception_error);
	if (error == VM_SUCCESS)
		error = vmwrite(VMCS_ENTRY_INST_LENGTH,
		    candidate.image.entry_instruction_length);
	if (error == VM_SUCCESS)
		error = vmwrite(VMCS_PRI_PROC_BASED_CTLS, new_primary);
	if (error == VM_SUCCESS)
		error = vmwrite(VMCS_ENTRY_INTR_INFO,
		    candidate.image.entry_intr_info);
	if (error != VM_SUCCESS) {
		rollback_error = vmwrite(VMCS_ENTRY_INTR_INFO, 0);
		if (rollback_error == VM_SUCCESS)
			rollback_error = vmwrite(VMCS_ENTRY_EXCEPTION_ERROR,
			    old_error);
		if (rollback_error == VM_SUCCESS)
			rollback_error = vmwrite(VMCS_ENTRY_INST_LENGTH,
			    old_length);
		if (rollback_error == VM_SUCCESS)
			rollback_error = vmwrite(VMCS_PRI_PROC_BASED_CTLS,
			    old_primary);
		if (rollback_error == VM_SUCCESS)
			rollback_error = vmwrite(VMCS_ENTRY_INTR_INFO,
			    old_info);
		return (rollback_error == VM_SUCCESS ? EIO : ENXIO);
	}
	vcpu->nested_vmcs02_plan.image.controls.primary = new_primary;
	vcpu->nested_vmcs02_plan.image.entry_intr_info =
	    candidate.image.entry_intr_info;
	vcpu->nested_vmcs02_plan.image.entry_exception_error =
	    candidate.image.entry_exception_error;
	vcpu->nested_vmcs02_plan.image.entry_instruction_length =
	    candidate.image.entry_instruction_length;
	return (0);
}

static int
vmx_nested_l0_resolve_intel(void *arg,
    const struct vmx_nested_vmcs02_id *id,
    enum vmx_nested_l0_completion completion, bool portable)
{
	struct vmx_vcpu *vcpu;

	vcpu = arg;
	if (vcpu == NULL || id == NULL ||
	    completion != VMX_NESTED_L0_COMPLETE_RESUME_L2 || portable ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    !vcpu->nested_vmcs02_intel.launch.current ||
	    !vmx_nested_vmcs02_id_equal(id, &vcpu->nested_vmcs02_plan.id) ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	return (0);
}

static const struct vmx_nested_l0_continuation_ops
vmx_nested_l0_resume_intel_ops = {
	.resolve = vmx_nested_l0_resolve_intel,
};

static const struct vmx_nested_l0_continuation_ops
vmx_nested_hot_ept_intel_ops = {
	.freeze = vmx_nested_l0_freeze_intel,
	.resolve = vmx_nested_l0_resolve_intel,
};

static const struct vmx_nested_l0_continuation_ops
vmx_nested_hot_exit_intel_ops = {
	.freeze = vmx_nested_l0_freeze_intel,
	.resolve = vmx_nested_l0_resolve_intel,
};

/*
 * Bind the value-only hot-EPT transaction to the currently resident VMCS02.
 * The generic coordinator publishes the EPT request before the destructive
 * Intel freeze.  Only a successful cold handoff consumes an exit sequence.
 */
static int
vmx_nested_publish_ept_exit_hot(struct vmx_vcpu *vcpu,
    const struct vmx_nested_exit_information *information)
{
	struct vmx_nested_ept_handoff_id handoff_id;
	const struct vmx_nested_vmcs02_id *id;
	uint64_t exit_sequence;
	int error;

	if (vcpu == NULL || information == NULL ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    !vcpu->nested_vmcs02_intel.launch.current ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	if (vcpu->nested_exit_sequence == UINT64_MAX)
		return (EOVERFLOW);
	id = &vcpu->nested_vmcs02_plan.id;
	exit_sequence = vcpu->nested_exit_sequence + 1;
	error = vmx_nested_hot_ept_publish(&vcpu->nested,
	    &vcpu->nested_l0_continuation, &vcpu->nested_entry_runtime, id,
	    exit_sequence, &vcpu->nested_vmcs12_snapshot.capabilities,
	    information, vcpu->nested_vmcs02_plan.image.ept.eptp,
	    vcpu->nested_vmcs02_plan.image.ept.mode_based_execute,
	    &vmx_nested_hot_ept_intel_ops, vcpu, &handoff_id);
	if (error != 0)
		return (error);
	if (handoff_id.vmcs_generation != id->state_generation ||
	    handoff_id.execution_epoch != id->execution_epoch)
		panic("%s: EPT publication changed execution identity", __func__);
	vcpu->nested_exit_sequence = exit_sequence;
	return (0);
}

static void vmx_nested_entry_event_intel_commit_entered(
    struct vmx_nested_entry_event_intel *);

static int
vmx_nested_l0_resume_prepare_intel(struct vmx_vcpu *vcpu,
    struct vmx_nested_entry_event_intel *event)
{
	if (vcpu == NULL || event == NULL || !event->active ||
	    event->plan.action == VMX_NESTED_ENTRY_EVENT_SHUTDOWN)
		return (EINVAL);
	if (event->plan.async_valid &&
	    (event->plan.async_event.action ==
	    VMX_NESTED_EVENT_ACTION_REFLECT_WINDOW ||
	    event->plan.async_event.action ==
	    VMX_NESTED_EVENT_ACTION_REFLECT_EVENT))
		return (0);
	return (vmx_nested_resume_reprogram_intel(vcpu, &event->plan));
}

static void
vmx_nested_l0_resume_entered_intel(struct vmx_vcpu *vcpu,
    struct vmx_nested_entry_event_intel *event)
{
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (vcpu == NULL || event == NULL || !event->active ||
	    event->plan.action == VMX_NESTED_ENTRY_EVENT_SHUTDOWN)
		panic("%s: invalid resumed-entry transaction", __func__);
	id = &vcpu->nested_vmcs02_plan.id;
	if (!vcpu->nested_l2_portable_valid ||
	    vcpu->nested_l2_portable.portable_generation !=
	    vcpu->nested_l0_continuation.portable_generation ||
	    !vmx_nested_vmcs02_id_equal(&vcpu->nested_l2_portable.id, id))
		panic("%s: resumed L2 lost its portable rollback image", __func__);
	/*
	 * A rebuilt VMCS02 may require VMLAUNCH while a still-resident one
	 * requires VMRESUME.  The successful hardware exit proves that the
	 * selected instruction entered L2; commit that launch owner before
	 * discarding the portable rollback image.
	 */
	error = vmx_nested_vmcs02_intel_commit_entered(
	    &vcpu->nested_vmcs02_intel);
	if (error != 0)
		panic("%s: resumed L2 without launch ownership: %d", __func__,
		    error);
	if (vcpu->nested_l2_portable.mtf_pending) {
		/*
		 * Only a real hardware VM exit proves that L2 entered.  Transfer
		 * the obligation now, before resolving the cold continuation and
		 * destroying its portable rollback image.  Every later failure is
		 * an ownership invariant and therefore fail-stop.
		 */
		error = vmx_nested_mtf_owner_take_portable(
		    &vcpu->nested_mtf_owner, &vcpu->nested_l2_portable,
		    &vcpu->nested_vmcs02_plan,
		    vcpu->nested_l0_continuation.portable_generation);
		if (error != 0)
			panic("%s: entered L2 without MTF ownership: %d",
			    __func__, error);
	}
	error = vmx_nested_l0_continuation_resolve(
	    &vcpu->nested_l0_continuation, &vcpu->nested_entry_runtime, id,
	    &vmx_nested_l0_resume_intel_ops, vcpu);
	if (error != 0)
		panic("%s: entered resumed L2 without continuation ownership: "
		    "%d", __func__, error);
	memset(&vcpu->nested_l2_portable, 0,
	    sizeof(vcpu->nested_l2_portable));
	vcpu->nested_l2_portable_valid = false;
	/*
	 * This is an architectural resume of L2.  The hardware instruction
	 * still comes from the per-VMCS02 launch owner: a VMCS02 rebuilt
	 * after VMCLEAR requires VMLAUNCH, while a still-resident launched
	 * VMCS02 requires VMRESUME.  Consume the L0 event only now: an
	 * actual VM exit proves that hardware entered L2, while VMfail
	 * leaves both owners intact for refreeze.
	 */
	vmx_nested_entry_event_intel_commit_entered(event);
}

static int
vmx_nested_entry_event_intel_commit_shutdown(
    struct vmx_nested_entry_event_intel *event)
{
	int error;

	if (event == NULL || !event->active || event->vcpu == NULL ||
	    event->plan.action != VMX_NESTED_ENTRY_EVENT_SHUTDOWN ||
	    !event->plan.consume_l0)
		return (EINVAL);
	error = vm_entry_intinfo_commit(event->vcpu->vcpu,
	    &event->snapshot);
	if (error != 0)
		return (error);
	memset(event, 0, sizeof(*event));
	return (0);
}

static int
vmx_nested_async_event_intel_commit(
    struct vmx_nested_entry_event_intel *event)
{
	if (!event->plan.async_valid ||
	    !event->plan.async_event.consume_event)
		return (0);
	switch (event->async_source) {
	case VMX_NESTED_ASYNC_SOURCE_NMI:
		if (!vm_nmi_pending(event->vcpu->vcpu))
			return (EAGAIN);
		vm_nmi_clear(event->vcpu->vcpu);
		return (0);
	case VMX_NESTED_ASYNC_SOURCE_EXTINT:
		if (!vm_extint_pending(event->vcpu->vcpu))
			return (EAGAIN);
		vm_extint_clear(event->vcpu->vcpu);
		vatpic_intr_accepted(event->vcpu->vmx->vm,
		    event->async_vector);
		return (0);
	case VMX_NESTED_ASYNC_SOURCE_LAPIC:
		/*
		 * The vCPU run owner is the sole IRR-to-ISR consumer.  A
		 * newly arrived higher-priority vector must not invalidate
		 * the lower vector that hardware has already accepted.
		 */
		vlapic_intr_accepted(vm_lapic(event->vcpu->vcpu),
		    event->async_vector);
		return (0);
	case VMX_NESTED_ASYNC_SOURCE_NONE:
	default:
		return (EPROTO);
	}
}

static int
vmx_nested_entry_event_intel_commit_reflected(
    struct vmx_nested_entry_event_intel *event)
{
	int error;

	if (event == NULL || !event->active || event->vcpu == NULL ||
	    !event->plan.async_valid ||
	    (event->plan.async_event.action !=
	    VMX_NESTED_EVENT_ACTION_REFLECT_WINDOW &&
	    event->plan.async_event.action !=
	    VMX_NESTED_EVENT_ACTION_REFLECT_EVENT) ||
	    event->plan.consume_l0)
		return (EINVAL);
	error = vmx_nested_async_event_intel_commit(event);
	if (error != 0)
		return (error);
	memset(event, 0, sizeof(*event));
	return (0);
}

/*
 * Publish an L1-requested event/window exit that occurs at the boundary of
 * an otherwise successful nested entry.  No VMCS02 instruction has executed:
 * VMCS12 still acquires launched state, while the saved L2 image is the
 * fully composed prospective guest state.
 */
static int
vmx_nested_publish_initial_synthetic_event_intel(
    struct vmx_vcpu *vcpu, struct vmx_nested_entry_event_intel *event)
{
	struct vmx_nested_l2_runtime_state runtime;
	struct vmx_nested_exit_information information;
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (vcpu == NULL || event == NULL || !event->active ||
	    event->vcpu != vcpu || !event->plan.async_valid ||
	    (event->plan.async_event.action !=
	    VMX_NESTED_EVENT_ACTION_REFLECT_WINDOW &&
	    event->plan.async_event.action !=
	    VMX_NESTED_EVENT_ACTION_REFLECT_EVENT) ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    vcpu->nested.phase != VMX_NESTED_CONTEXT_ENTRY_PENDING ||
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_RESOURCES ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	/*
	 * A synthetic successful entry still executes both VM-exit lists.
	 * Publication retains the prospective L2 image; the frozen exit
	 * coordinator performs the ordered list transaction.
	 */
	id = &vcpu->nested_vmcs02_plan.id;
	error = vmx_nested_event_reflected_exit(
	    &event->plan.async_event, &information);
	if (error != 0)
		return (error);
	memset(&runtime, 0, sizeof(runtime));
	runtime.control = vcpu->nested_vmcs02_plan.image.l2_control;
	runtime.arch = vcpu->nested_vmcs02_plan.image.l2_arch;
	if (event->plan.async_event.block_nmi)
		runtime.arch.interruptibility |=
		    VMCS_INTERRUPTIBILITY_NMI_BLOCKING;
	error = vmx_nested_context_publish_synthetic_vmexit(&vcpu->nested,
	    &vcpu->nested_entry_runtime, id, &information, &runtime);
	if (error != 0)
		return (error);
	/*
	 * The frozen publication above was fully prevalidated and is now the
	 * architectural commit point.  With interrupts disabled, this run
	 * owner is the only legal consumer of the snapshotted source.
	 */
	error = vmx_nested_entry_event_intel_commit_reflected(event);
	if (error != 0)
		panic("%s: published synthetic exit lost event ownership: %d",
		    __func__, error);
	return (0);
}

static int
vmx_nested_publish_hot_synthetic_event_intel(
    struct vmx_vcpu *vcpu, struct vmx_nested_entry_event_intel *event)
{
	struct vmx_nested_l2_runtime_state runtime;
	struct vmx_nested_exit_information information;
	const struct vmx_nested_vmcs02_id *id;
	bool rollback_complete;
	int capture_error, error, poison_error;

	if (vcpu == NULL || event == NULL || !event->active ||
	    event->vcpu != vcpu || !event->plan.async_valid ||
	    (event->plan.async_event.action !=
	    VMX_NESTED_EVENT_ACTION_REFLECT_WINDOW &&
	    event->plan.async_event.action !=
	    VMX_NESTED_EVENT_ACTION_REFLECT_EVENT) ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    vcpu->nested.phase != VMX_NESTED_CONTEXT_GUEST ||
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	id = &vcpu->nested_vmcs02_plan.id;
	error = vmx_nested_event_reflected_exit(
	    &event->plan.async_event, &information);
	if (error != 0)
		return (error);

	error = vmx_nested_software_msrs_leave_l2(vcpu,
	    &rollback_complete);
	if (error != 0)
		return (rollback_complete ? error : EIO);
	capture_error = vmx_nested_vmcs02_intel_capture_runtime(
	    &vcpu->nested_vmcs02_intel, id,
	    vcpu->nested_entry_runtime.resource_generation,
	    vcpu->nested_vmcs02_plan.image.l2_arch.in_smm, &runtime);
	vmx_nested_software_msrs_commit(vcpu,
	    VMX_NESTED_HARDWARE_MSR_EXIT);
	if (capture_error != 0) {
		poison_error = vmx_nested_entry_runtime_exit_captured(
		    &vcpu->nested_entry_runtime, id);
		if (poison_error == 0)
			poison_error = vmx_nested_entry_runtime_exit_poison(
			    &vcpu->nested_entry_runtime, id);
		if (poison_error != 0)
			panic("%s: cannot poison synthetic capture: %d",
			    __func__, poison_error);
		return (capture_error);
	}
	if (event->plan.async_event.block_nmi)
		runtime.arch.interruptibility |=
		    VMCS_INTERRUPTIBILITY_NMI_BLOCKING;
	error = vmx_nested_entry_runtime_exit_captured(
	    &vcpu->nested_entry_runtime, id);
	if (error != 0)
		panic("%s: synthetic capture lost runtime ownership: %d",
		    __func__, error);
	error = vmx_nested_context_publish_vmexit(&vcpu->nested, id,
	    &information, &runtime);
	if (error != 0)
		panic("%s: prevalidated synthetic exit publication failed: %d",
		    __func__, error);
	if (vcpu->nested_l0_continuation.state ==
	    VMX_NESTED_L0_CONTINUATION_HOT) {
		error = vmx_nested_l0_continuation_exit_captured(
		    &vcpu->nested_l0_continuation,
		    &vcpu->nested_entry_runtime, id);
		if (error != 0)
			panic("%s: captured synthetic exit retained its "
			    "continuation: %d", __func__, error);
	}
	if (vcpu->nested_mtf_owner.pending) {
		uint64_t mtf_generation;

		/*
		 * An L1-requested window or event exit is an architectural
		 * nested exit even though no additional L2 instruction ran.
		 * Publication is already irrevocable, so cancel the matching
		 * pending MTF now rather than carrying a hot owner into L1.
		 */
		mtf_generation = vcpu->nested_mtf_owner.origin_generation;
		error = vmx_nested_mtf_owner_consume(
		    &vcpu->nested_mtf_owner, id, mtf_generation);
		if (error != 0)
			panic("%s: synthetic exit retained MTF owner: %d",
			    __func__, error);
	}
	error = vmx_nested_entry_event_intel_commit_reflected(event);
	if (error != 0)
		panic("%s: published hot synthetic exit lost event ownership: "
		    "%d", __func__, error);
	return (0);
}

static void
vmx_nested_entry_event_intel_commit_entered(
    struct vmx_nested_entry_event_intel *event)
{
	int error;

	if (event == NULL || !event->active || event->vcpu == NULL ||
	    event->plan.action == VMX_NESTED_ENTRY_EVENT_SHUTDOWN)
		panic("%s: invalid entered-event transaction", __func__);
	if (event->plan.consume_l0) {
		error = vm_entry_intinfo_commit(event->vcpu->vcpu,
		    &event->snapshot);
		if (error != 0)
			panic("%s: entered L2 with stale event snapshot: %d",
			    __func__, error);
	}
	error = vmx_nested_async_event_intel_commit(event);
	if (error != 0)
		panic("%s: entered L2 with stale asynchronous event: %d",
		    __func__, error);
	memset(event, 0, sizeof(*event));
}

static void
vmx_nested_entry_event_intel_abort(
    struct vmx_nested_entry_event_intel *event)
{

	if (event == NULL || !event->active)
		panic("%s: no active event transaction", __func__);
	memset(event, 0, sizeof(*event));
}

static void
vmx_nested_hardware_event_commit(void *arg)
{

	vmx_nested_entry_event_intel_commit_entered(arg);
}

static void
vmx_nested_hardware_event_abort(void *arg)
{

	vmx_nested_entry_event_intel_abort(arg);
}

static const struct vmx_nested_hardware_event_ops
vmx_nested_hardware_event_intel_ops = {
	.commit_entered = vmx_nested_hardware_event_commit,
	.abort = vmx_nested_hardware_event_abort,
};

static int
vmx_nested_hardware_report_intel(struct vmx_vcpu *vcpu, int rc,
    struct vmx_nested_hardware_report_input *input,
    struct vmx_nested_exit_information *exit)
{
	struct vmx_nested_hardware_report_input candidate;
	struct vmx_nested_exit_information exit_candidate;
	enum vmx_nested_hardware_report report;
	const struct vmx_nested_vmcs02_id *id;
	uint32_t instruction_error;
	int expected_launched, error;

	if (vcpu == NULL || input == NULL || exit == NULL ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	id = &vcpu->nested_vmcs02_plan.id;
	error = vmx_nested_vmcs02_intel_entry_instruction(
	    &vcpu->nested_vmcs02_intel, &expected_launched);
	if (error != 0)
		return (error);
	memset(&exit_candidate, 0, sizeof(exit_candidate));
	instruction_error = 0;
	if (rc == VMX_GUEST_VMEXIT) {
		error = vmx_nested_vmcs02_intel_peek_exit(
		    &vcpu->nested_vmcs02_intel, id,
		    vcpu->nested_entry_runtime.resource_generation,
		    &exit_candidate);
		if (error != 0)
			return (error);
		report = VMX_NESTED_HARDWARE_REPORT_VMEXIT;
	} else {
		if ((expected_launched && rc != VMX_VMRESUME_ERROR) ||
		    (!expected_launched && rc != VMX_VMLAUNCH_ERROR))
			return (EPROTO);
		switch (vcpu->ctx.inst_fail_status) {
		case VM_FAIL_VALID:
			report = VMX_NESTED_HARDWARE_REPORT_VMFAIL_VALID;
			instruction_error = vmcs_instruction_error();
			if (instruction_error == 0)
				return (EPROTO);
			break;
		case VM_FAIL_INVALID:
			report = VMX_NESTED_HARDWARE_REPORT_VMFAIL_INVALID;
			break;
		default:
			return (EPROTO);
		}
	}
	error = vmx_nested_hardware_report_prepare(report,
	    report == VMX_NESTED_HARDWARE_REPORT_VMEXIT ?
	    &exit_candidate : NULL, instruction_error, &candidate);
	if (error != 0)
		return (error);
	*input = candidate;
	*exit = exit_candidate;
	return (0);
}

static int
vmx_nested_publish_initial_rejection(struct vmx_vcpu *vcpu,
    const struct vmx_nested_vmentry_result *rejection)
{
	struct vmx_nested_vmentry_handoff_request request;
	int error;

	if (vcpu == NULL || rejection == NULL ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    vcpu->nested.phase != VMX_NESTED_CONTEXT_ENTRY_PENDING ||
	    vcpu->nested.internal.kind != VMX_NESTED_INTERNAL_NONE ||
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_RESOURCES)
		return (EINVAL);
	memset(&request, 0, sizeof(request));
	request.id = vcpu->nested_vmcs02_plan.id;
	request.result = *rejection;
	error = vmx_nested_internal_publish_vmentry_reject(
	    &vcpu->nested.internal, &request);
	if (error != 0)
		return (error);
	return (0);
}

static int
vmx_nested_finish_initial_hardware_attempt(struct vmx_vcpu *vcpu,
    struct vmx_nested_entry_event_intel *event,
    const struct vmx_nested_hardware_report_input *input,
    const struct vmx_nested_exit_information *exit,
    struct vmx_nested_attempt_plan *attempt,
    struct vmx_nested_vmentry_result *rejection,
    enum vmx_nested_hardware_entry_finish_completion *completion)
{
	struct vmx_nested_hardware_report_result report;
	struct vmx_nested_attempt_plan candidate;
	const struct vmx_nested_exit_information *captured_exit;
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (vcpu == NULL || event == NULL || input == NULL ||
	    attempt == NULL || rejection == NULL || completion == NULL ||
	    !event->active ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    (input->report == VMX_NESTED_HARDWARE_REPORT_VMEXIT &&
	    exit == NULL) ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	/*
	 * The completion is evidence for a later owner settlement, not scratch
	 * state inherited from the caller.  Clear it before the fallible report
	 * classification so an error cannot make an old completed inverse appear
	 * to describe this hardware attempt.
	 */
	*completion = VMX_NESTED_HARDWARE_ENTRY_FINISH_NONE;
	id = &vcpu->nested_vmcs02_plan.id;
	/*
	 * vmx_nested_hardware_report_intel() zeroes its caller-owned exit
	 * buffer for VMfail.  Do not pass that non-authoritative buffer to
	 * the value classifier: VMfail deliberately has no VMCS exit image.
	 */
	captured_exit = input->report == VMX_NESTED_HARDWARE_REPORT_VMEXIT ?
	    exit : NULL;
	error = vmx_nested_attempt_classify(VMX_NESTED_ATTEMPT_INITIAL,
	    input, captured_exit, &candidate);
	if (error != 0)
		return (error);
	/*
	 * The classifier's plan is immutable once accepted.  Publish it before
	 * the residency transition so an error from that transition still has an
	 * authoritative hardware-result classification.  The current caller only
	 * consumes it on success; a future common entry owner must combine this
	 * plan with the inverse operation that actually completes after failure.
	 */
	*attempt = candidate;
	memset(&report, 0, sizeof(report));
	switch (candidate.action) {
	case VMX_NESTED_ATTEMPT_INITIAL_EXIT:
		report.disposition = VMX_NESTED_HARDWARE_L2_EXIT;
		report.commit_launch = true;
		break;
	case VMX_NESTED_ATTEMPT_INITIAL_REJECTION:
		report.disposition = VMX_NESTED_HARDWARE_REJECTION;
		report.rejection = candidate.rejection;
		break;
	case VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE:
		report.disposition = VMX_NESTED_HARDWARE_L0_FAILURE;
		break;
	case VMX_NESTED_ATTEMPT_RESUMED_EXIT:
	case VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY:
	case VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE:
		return (EPROTO);
	}
	error = vmx_nested_hardware_entry_finish(&vcpu->nested,
	    &vcpu->nested_entry_runtime, id, &report,
	    &vmx_nested_hardware_entry_intel_ops, vcpu,
	    &vmx_nested_hardware_event_intel_ops, event, completion, rejection);
	/*
	 * A terminal host error may follow a successful unentered rollback.  The
	 * current fail-closed caller still returns that error, but validate the
	 * private completion now so a later common entry-owner settlement cannot
	 * accidentally infer this fact from the resulting clean runtime state.
	 */
	if (error != 0) {
		if (candidate.action == VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE &&
		    *completion != VMX_NESTED_HARDWARE_ENTRY_FINISH_NONE &&
		    *completion !=
		    VMX_NESTED_HARDWARE_ENTRY_FINISH_UNENTERED_ROLLED_BACK)
			return (EPROTO);
		return (error);
	}
	if ((candidate.action == VMX_NESTED_ATTEMPT_INITIAL_EXIT &&
	    *completion != VMX_NESTED_HARDWARE_ENTRY_FINISH_ENTERED) ||
	    (candidate.action == VMX_NESTED_ATTEMPT_INITIAL_REJECTION &&
	    *completion !=
	    VMX_NESTED_HARDWARE_ENTRY_FINISH_UNENTERED_ROLLED_BACK))
		return (EPROTO);
	return (0);
}

/*
 * Finish one hardware attempt made while resuming an L0-owned L2
 * continuation.  A real exit transfers launch, continuation, and event
 * ownership back to the hot runtime.  Neither failed-entry nor raw L0
 * failure entered L2, so both preserve the portable rollback image and
 * detach VMCS02 through the appropriate refreeze transaction.
 */
static int
vmx_nested_finish_resumed_hardware_attempt(struct vmx_vcpu *vcpu,
    struct vmx_nested_entry_event_intel *event,
    const struct vmx_nested_hardware_report_input *input,
    const struct vmx_nested_exit_information *exit,
    struct vmx_nested_attempt_plan *attempt,
    enum vmx_nested_resumed_hardware_attempt_completion *completion)
{
	struct vmx_nested_attempt_plan candidate;
	const struct vmx_nested_exit_information *captured_exit;
	int error;

	if (vcpu == NULL || event == NULL || input == NULL ||
	    attempt == NULL || completion == NULL || !event->active ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    (input->report == VMX_NESTED_HARDWARE_REPORT_VMEXIT &&
	    exit == NULL) ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	/* Do not make a stale caller value look like a completed inverse. */
	*completion = VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_NONE;
	captured_exit = input->report == VMX_NESTED_HARDWARE_REPORT_VMEXIT ?
	    exit : NULL;
	error = vmx_nested_attempt_classify(VMX_NESTED_ATTEMPT_RESUME,
	    input, captured_exit, &candidate);
	if (error != 0)
		return (error);
	/* See the initial-attempt counterpart above. */
	*attempt = candidate;

	switch (candidate.action) {
	case VMX_NESTED_ATTEMPT_RESUMED_EXIT:
		vmx_nested_l0_resume_entered_intel(vcpu, event);
		*completion = VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_ENTERED;
		break;
	case VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY:
		vmx_nested_entry_event_intel_abort(event);
		error = vmx_nested_l0_refreeze_late_entry_intel(vcpu,
		    &candidate);
		if (error != 0)
			return (error);
		*completion =
		    VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_UNENTERED_REFROZEN;
		break;
	case VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE:
		vmx_nested_entry_event_intel_abort(event);
		error = vmx_nested_l0_refreeze_unentered_intel(vcpu);
		if (error != 0)
			return (error);
		*completion =
		    VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_UNENTERED_REFROZEN;
		break;
	case VMX_NESTED_ATTEMPT_INITIAL_EXIT:
	case VMX_NESTED_ATTEMPT_INITIAL_REJECTION:
	case VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE:
		return (EPROTO);
	}
	if ((candidate.action == VMX_NESTED_ATTEMPT_RESUMED_EXIT &&
	    *completion != VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_ENTERED) ||
	    (candidate.action != VMX_NESTED_ATTEMPT_RESUMED_EXIT &&
	    *completion !=
	    VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_UNENTERED_REFROZEN))
		return (EPROTO);
	return (0);
}

/*
 * A later hot VMRESUME has no retained cold image.  VMfail also has no
 * authoritative VM-exit fields, so the only safe outcome is to detach all
 * CPU-local L2 state and return a fatal host error.  Opaque leases remain
 * fenced by the aborted runtime until frozen teardown releases them.
 */
static int
vmx_nested_hot_residency_abort_intel(struct vmx_vcpu *vcpu,
    struct vmx_nested_entry_event_intel *event)
{
	const struct vmx_nested_vmcs02_id *id;
	bool rollback_complete;
	int error;

	if (vcpu == NULL || !vcpu->nested_vmcs02_plan_valid ||
	    vcpu->nested_l2_portable_valid ||
	    vcpu->nested_l0_continuation.state !=
	    VMX_NESTED_L0_CONTINUATION_IDLE ||
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_GUEST ||
	    vcpu->nested_hot_failure_detached ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	id = &vcpu->nested_vmcs02_plan.id;
	if (event != NULL && event->active)
		vmx_nested_entry_event_intel_abort(event);
	error = vmx_nested_entry_runtime_hot_entry_abort(
	    &vcpu->nested_entry_runtime, id);
	if (error != 0)
		return (error);
	if (vcpu->nested_tsc_aux_residency == VMX_NESTED_TSC_AUX_L2) {
		error = vmx_nested_tsc_aux_pause_l2_intel(vcpu);
		if (error != 0)
			panic("%s: cannot pause L2 TSC_AUX during abort: %d",
			    __func__, error);
	} else if (vcpu->nested_tsc_aux_residency !=
	    VMX_NESTED_TSC_AUX_L2_PAUSED)
		panic("%s: abort found invalid TSC_AUX residency %u",
		    __func__, vcpu->nested_tsc_aux_residency);
	error = vmx_nested_software_msrs_leave_l2(vcpu,
	    &rollback_complete);
	if (error != 0 || !rollback_complete)
		panic("%s: cannot restore L1 MSRs during abort: %d/%d",
		    __func__, error, rollback_complete);
	error = vmx_nested_vmcs02_intel_leave(
	    &vcpu->nested_vmcs02_intel);
	if (error != 0)
		panic("%s: cannot restore VMCS01 during abort: %d",
		    __func__, error);
	vmx_nested_software_msrs_commit(vcpu,
	    VMX_NESTED_HARDWARE_MSR_EXIT);
	vcpu->nested_hot_failure_detached = true;
	return (EIO);
}

/*
 * Convert every recoverable run-loop error into a frozen-safe ownership
 * state before vmx_run() drops its CPU pin.  The state machine, rather than
 * the source line, determines the only legal inverse operation.
 *
 * A poisoned adapter transition is not recoverable here: returning would
 * permit migration with uncertain CPU-local ownership.  Such failures are
 * deliberately fail-stop until teardown can prove all obligations complete.
 */
static int
vmx_nested_run_unwind_intel(struct vmx_vcpu *vcpu,
    struct vmx_nested_entry_event_intel *event, int original_error,
    enum vmx_nested_run_unwind_action *actionp)
{
	struct vmx_nested_run_unwind_input input;
	enum vmx_nested_run_unwind_action action;
	const struct vmx_nested_vmcs02_id *id;
	int error;

	/*
	 * Do not leave a caller with an indeterminate action if validation or a
	 * private inverse fails before it becomes safe to publish an outcome.
	 * FAIL_STOP is deliberately not accepted by either owner-composition
	 * helper; callers must treat it as an integrity failure rather than turn
	 * an incomplete cleanup into a guest-visible replay or exit.
	 */
	if (actionp != NULL)
		*actionp = VMX_NESTED_RUN_UNWIND_FAIL_STOP;
	if (vcpu == NULL || original_error == 0 ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	if (event != NULL && event->active)
		vmx_nested_entry_event_intel_abort(event);
	id = &vcpu->nested_vmcs02_plan.id;
	memset(&input, 0, sizeof(input));
	input.runtime_state = vcpu->nested_entry_runtime.state;
	input.continuation_state =
	    vcpu->nested_l0_continuation.state;
	input.portable_valid = vcpu->nested_l2_portable_valid;
	input.detached = vcpu->nested_hot_failure_detached;
	error = vmx_nested_run_unwind_select(&input, &action);
	if (error != 0)
		panic("%s: invalid unwind facts: %d", __func__, error);
	switch (action) {
	case VMX_NESTED_RUN_UNWIND_CLEAN:
		/*
		 * These states own no CPU-local L2 residency.  A staged thaw
		 * remains explicit and may be resumed or cancelled later in
		 * the frozen execution domain.
		 */
		break;
	case VMX_NESTED_RUN_UNWIND_ROLLBACK_INITIAL:
		error = vmx_nested_hardware_entry_rollback(
		    &vcpu->nested_entry_runtime, id,
		    &vmx_nested_hardware_entry_intel_ops, vcpu);
		if (error != 0)
			panic("%s: initial entry rollback failed: %d "
			    "(original %d)", __func__, error, original_error);
		break;
	case VMX_NESTED_RUN_UNWIND_REFREEZE_UNENTERED:
		error = vmx_nested_l0_refreeze_unentered_intel(vcpu);
		if (error != 0)
			panic("%s: cold-entry refreeze failed: %d "
			    "(original %d)", __func__, error, original_error);
		break;
	case VMX_NESTED_RUN_UNWIND_DETACH_FATAL:
		/*
		 * A hot continuation has no retained portable rollback
		 * image.  Detach CPU-local state without consulting possibly
		 * stale VM-exit fields and quarantine its opaque leases.
		 */
		error = vmx_nested_hot_residency_abort_intel(vcpu, event);
		if (error != EIO)
			return (error);
		break;
	case VMX_NESTED_RUN_UNWIND_FREEZE_HOT:
		error = vmx_nested_hot_exit_freeze_publish(
		    &vcpu->nested, &vcpu->nested_l0_continuation,
		    &vcpu->nested_entry_runtime, id,
		    &vmx_nested_hot_exit_intel_ops, vcpu);
		if (error != 0)
			panic("%s: hot-exit freeze failed: %d (original %d)",
			    __func__, error, original_error);
		break;
	case VMX_NESTED_RUN_UNWIND_ALREADY_DETACHED:
		break;
	case VMX_NESTED_RUN_UNWIND_FAIL_STOP:
	default:
		panic("%s: no safe unwind for error %d (runtime %u "
		    "continuation %u)", __func__, original_error,
		    vcpu->nested_entry_runtime.state,
		    vcpu->nested_l0_continuation.state);
	}

	/*
	 * The selected inverse operation is part of the result contract, not
	 * merely a local switch selector.  Publish it only after that inverse
	 * has completed, so a future deferred startup owner cannot compose a
	 * result from an action that failed before making residency safe.
	 */
	if (actionp != NULL)
		*actionp = action;
	return (action == VMX_NESTED_RUN_UNWIND_ALREADY_DETACHED ? EIO :
	    original_error);
}

/*
 * The common startup owner records an admission decision, but it cannot own
 * VMCS02, L2 MSRs, or the portable cold continuation.  Keep the two domains
 * separate: a declined admission first completes the exact Intel-private
 * inverse selected from the live residency state, and only then publishes the
 * previously observed common result.  This helper is deliberately called
 * after the private rollback/refreeze is available and before any operation
 * which would make that inverse ambiguous.
 */
static int
vmx_nested_owner_guard_attempt(struct vmx_vcpu *vcpu,
    struct vmx_nested_entry_event_intel *event,
    struct vmm_startup_entry_owner *owner, bool *enter)
{
	struct vmx_nested_owner_outcome_input input;
	struct vmx_nested_owner_outcome outcome;
	struct vmm_startup_entry_loop_result result;
	struct vmm_startup_entry_runtime_result runtime;
	enum vmx_nested_run_unwind_action action;
	int error, unwind_error;

	if (vcpu == NULL || event == NULL || owner == NULL || enter == NULL ||
	    !event->active)
		return (EINVAL);
	*enter = false;
	memset(&runtime, 0, sizeof(runtime));
	error = vcpu_startup_entry_owner_guard_before_attempt(vcpu->vcpu,
	    owner, &runtime);
	if (error != 0)
		return (error);
	if (runtime.action == VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST) {
		*enter = true;
		return (0);
	}
	if ((runtime.action != VMM_STARTUP_ENTRY_RUNTIME_REPLAY &&
	    runtime.action != VMM_STARTUP_ENTRY_RUNTIME_RETURN_ERROR) ||
	    runtime.error <= 0)
		return (EPROTO);

	/* The guard result is historical; do not take a second observation here. */
	action = VMX_NESTED_RUN_UNWIND_FAIL_STOP;
	unwind_error = vmx_nested_run_unwind_intel(vcpu, event, runtime.error,
	    &action);
	if (action == VMX_NESTED_RUN_UNWIND_FAIL_STOP)
		panic("%s: nested guard unwind did not make residency safe: %d",
		    __func__, unwind_error);
	memset(&input, 0, sizeof(input));
	input.unwind_action = action;
	input.guard_error = runtime.error;
	/* A successful recoverable inverse returns its input error verbatim. */
	input.unwind_error = unwind_error == runtime.error ? 0 : unwind_error;
	error = vmx_nested_owner_outcome_compose(&input, &outcome);
	if (error != 0)
		return (error);
	return (vmx_nested_owner_outcome_resolve_preentry(owner, &outcome,
	    &result));
}

/* Settle an initial or resumed instruction only after its finisher proves it. */
static int
vmx_nested_owner_settle_initial_attempt(struct vmm_startup_entry_owner *owner,
    const struct vmx_nested_attempt_plan *attempt,
    enum vmx_nested_hardware_entry_finish_completion completion)
{
	struct vmx_nested_owner_initial_attempt_input input;
	struct vmx_nested_owner_attempt_outcome outcome;
	struct vmm_startup_entry_loop_result result;
	int error;

	if (owner == NULL || attempt == NULL)
		return (EINVAL);
	memset(&input, 0, sizeof(input));
	input.attempt_action = attempt->action;
	input.completion = completion;
	input.unwind_action = VMX_NESTED_RUN_UNWIND_CLEAN;
	error = vmx_nested_owner_initial_attempt_outcome_compose(&input,
	    &outcome);
	if (error != 0)
		return (error);
	return (vmx_nested_owner_attempt_outcome_settle(owner, &outcome,
	    outcome.disposition == VMX_NESTED_OWNER_ATTEMPT_COMMIT_ENTRY ?
	    NULL : &result));
}

static int
vmx_nested_owner_settle_resumed_attempt(struct vmm_startup_entry_owner *owner,
    const struct vmx_nested_attempt_plan *attempt,
    enum vmx_nested_resumed_hardware_attempt_completion completion)
{
	struct vmx_nested_owner_resumed_attempt_input input;
	struct vmx_nested_owner_attempt_outcome outcome;
	struct vmm_startup_entry_loop_result result;
	int error;

	if (owner == NULL || attempt == NULL)
		return (EINVAL);
	memset(&input, 0, sizeof(input));
	input.attempt_action = attempt->action;
	input.completion = completion;
	input.unwind_action = VMX_NESTED_RUN_UNWIND_CLEAN;
	error = vmx_nested_owner_resumed_attempt_outcome_compose(&input,
	    &outcome);
	if (error != 0)
		return (error);
	return (vmx_nested_owner_attempt_outcome_settle(owner, &outcome,
	    outcome.disposition == VMX_NESTED_OWNER_ATTEMPT_COMMIT_ENTRY ?
	    NULL : &result));
}

/* Publish an L1-visible exit only after the private publication is complete. */
static int
vmx_nested_owner_defer_postentry(struct vmm_startup_entry_owner *owner,
    enum vmx_nested_owner_postentry_route route,
    enum vmx_nested_run_unwind_action action, int backend_error)
{
	struct vmx_nested_owner_exit_outcome_input input;
	struct vmx_nested_owner_exit_outcome outcome;
	struct vmm_startup_entry_loop_result result;
	int error;

	if (owner == NULL)
		return (0);
	memset(&input, 0, sizeof(input));
	input.unwind_action = action;
	input.exit_error = backend_error;
	error = vmx_nested_owner_exit_outcome_compose(&input, &outcome);
	if (error != 0)
		return (error);
	error = vmx_nested_owner_postentry_transition(owner, route,
	    backend_error);
	if (error != 0)
		return (error);
	return (vmx_nested_owner_exit_outcome_resolve_postentry(owner, &outcome,
	    &result));
}

/*
 * Convert a post-unwind error into the only common result compatible with the
 * owner phase.  In particular, an ENTRY_PENDING attempt is never converted
 * to a software VM exit merely because its private inverse succeeded.
 */
static int
vmx_nested_owner_settle_unwind_error(struct vmm_startup_entry_owner *owner,
    enum vmx_nested_run_unwind_action action, int original_error,
    int unwind_error)
{
	struct vmx_nested_owner_exit_outcome_input input;
	struct vmx_nested_owner_exit_outcome outcome;
	struct vmm_startup_entry_loop_result result;
	int terminal, error;

	if (owner == NULL || original_error <= 0 || unwind_error <= 0)
		return (EINVAL);
	terminal = unwind_error == original_error ? original_error :
	    unwind_error;
	switch (owner->phase) {
	case VMM_STARTUP_ENTRY_OWNER_RUNNING:
	case VMM_STARTUP_ENTRY_OWNER_RECHECK:
		return (vmm_startup_entry_owner_fail_before_entry(owner, terminal,
		    &result));
	case VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING:
		if (terminal == EAGAIN)
			terminal = EIO;
		return (vmm_startup_entry_owner_abort_attempt_error(owner, terminal,
		    &result));
	case VMM_STARTUP_ENTRY_OWNER_IN_GUEST:
		memset(&input, 0, sizeof(input));
		input.unwind_action = action;
		input.exit_error = original_error;
		input.unwind_error = unwind_error == original_error ? 0 :
		    unwind_error;
		error = vmx_nested_owner_exit_outcome_compose(&input, &outcome);
		if (error != 0)
			return (error);
		error = vmx_nested_owner_postentry_transition(owner,
		    VMX_NESTED_OWNER_POSTENTRY_DEFER_UNHANDLED, original_error);
		if (error != 0)
			return (error);
		return (vmx_nested_owner_exit_outcome_resolve_postentry(owner,
		    &outcome, &result));
	default:
		return (EPROTO);
	}
}

/* Publish the common outer-VMM stop result without changing interrupt state. */
static void
vmx_nested_publish_host_stop(struct vmx_vcpu *vcpu, register_t rip,
    bool suspended, bool rendezvous, bool reqidle, bool yield, bool debugged,
    bool pvclock)
{

	KASSERT(suspended || rendezvous || reqidle || yield || debugged ||
	    pvclock, ("nested host stop without a pending reason"));
	if (suspended)
		vm_exit_suspended(vcpu->vcpu, rip);
	else if (rendezvous)
		vm_exit_rendezvous(vcpu->vcpu, rip);
	else if (reqidle)
		vm_exit_reqidle(vcpu->vcpu, rip);
	else if (yield) {
		vm_exit_astpending(vcpu->vcpu, rip);
		vmx_astpending_trace(vcpu, rip);
	} else if (debugged)
		vm_exit_debug(vcpu->vcpu, rip);
	else
		vm_exit_pvclock(vcpu->vcpu, rip);
}

static void
vmx_nested_publish_internal_exit(struct vmx_vcpu *vcpu, register_t rip)
{
	struct vm_exit *vmexit;

	vmexit = vm_exitinfo(vcpu->vcpu);
	vmexit->rip = rip;
	vmexit->inst_length = 0;
	vmexit->exitcode = VM_EXITCODE_VMM_INTERNAL;
}

/*
 * Complete one pre-entry software return.  The caller enters with interrupts
 * disabled and private nested state already committed or refrozen; this
 * helper deliberately enables interrupts before publishing the outer exit.
 */
static int
vmx_nested_complete_software_exit(struct vmx_vcpu *vcpu, register_t rip,
    struct vmm_startup_entry_owner *entry_owner, bool suspended)
{
	struct vmm_startup_entry_loop_result owner_result;

	enable_intr();
	if (suspended)
		vm_exit_suspended(vcpu->vcpu, rip);
	else
		vmx_nested_publish_internal_exit(vcpu, rip);
	if (entry_owner == NULL)
		return (0);
	return (vmm_startup_entry_owner_software_exit(entry_owner,
	    &owner_result));
}

enum vmx_nested_planned_event_residency {
	VMX_NESTED_PLANNED_EVENT_INITIAL,
	VMX_NESTED_PLANNED_EVENT_RESUMED,
	VMX_NESTED_PLANNED_EVENT_HOT,
};

static bool
vmx_nested_planned_event_is_synthetic(
    const struct vmx_nested_entry_event_intel *event)
{

	return (event->plan.async_valid &&
	    (event->plan.async_event.action ==
	    VMX_NESTED_EVENT_ACTION_REFLECT_WINDOW ||
	    event->plan.async_event.action ==
	    VMX_NESTED_EVENT_ACTION_REFLECT_EVENT));
}

/*
 * Settle the software-only outcomes shared by initial, cold-resumed, and hot
 * entry paths.  Their only intentional difference is the private inverse
 * needed to return to a portable L1 image after consuming shutdown.
 */
static int
vmx_nested_complete_planned_event(struct vmx_vcpu *vcpu, register_t rip,
    struct vmx_nested_entry_event_intel *event,
    struct vmm_startup_entry_owner *entry_owner,
    enum vmx_nested_planned_event_residency residency, bool *completed)
{
	int error;

	if (vcpu == NULL || event == NULL || completed == NULL ||
	    residency > VMX_NESTED_PLANNED_EVENT_HOT)
		return (EINVAL);
	*completed = false;
	if (event->plan.action == VMX_NESTED_ENTRY_EVENT_SHUTDOWN) {
		error = vmx_nested_entry_event_intel_commit_shutdown(event);
		if (error == 0 && residency == VMX_NESTED_PLANNED_EVENT_RESUMED)
			error = vmx_nested_l0_refreeze_unentered_intel(vcpu);
		if (error == 0 && residency == VMX_NESTED_PLANNED_EVENT_HOT)
			error = vmx_nested_hot_exit_freeze_publish(
			    &vcpu->nested, &vcpu->nested_l0_continuation,
			    &vcpu->nested_entry_runtime,
			    &vcpu->nested_vmcs02_plan.id,
			    &vmx_nested_hot_exit_intel_ops, vcpu);
		if (error != 0)
			return (error);
		error = vmx_nested_complete_software_exit(vcpu, rip, entry_owner,
		    true);
		if (error != 0)
			panic("%s: nested shutdown startup owner: %d", __func__,
			    error);
		*completed = true;
		return (0);
	}
	if (!vmx_nested_planned_event_is_synthetic(event))
		return (0);
	if (residency == VMX_NESTED_PLANNED_EVENT_INITIAL)
		error = vmx_nested_publish_initial_synthetic_event_intel(vcpu,
		    event);
	else
		error = vmx_nested_publish_hot_synthetic_event_intel(vcpu, event);
	if (error != 0)
		return (error);
	error = vmx_nested_complete_software_exit(vcpu, rip, entry_owner, false);
	if (error != 0)
		panic("%s: nested synthetic startup owner: %d", __func__, error);
	*completed = true;
	return (0);
}

static int
vmx_nested_owner_guard_or_exit(struct vmx_vcpu *vcpu, register_t rip,
    struct vmx_nested_entry_event_intel *event,
    struct vmm_startup_entry_owner *entry_owner, bool *completed)
{
	bool enter;
	int error;

	if (vcpu == NULL || event == NULL || completed == NULL)
		return (EINVAL);
	*completed = false;
	if (entry_owner == NULL)
		return (0);
	error = vmx_nested_owner_guard_attempt(vcpu, event, entry_owner, &enter);
	if (error != 0)
		return (error);
	if (enter)
		return (0);
	enable_intr();
	vmx_nested_publish_internal_exit(vcpu, rip);
	*completed = true;
	return (0);
}

static int
vmx_run_nested(struct vmx_vcpu *vcpu, register_t rip, pmap_t pmap,
    struct vm_eventinfo *evinfo, enum vmx_nested_run_target target,
    struct vmm_startup_entry_owner *entry_owner)
{
	struct vmx_nested_entry_event_intel event;
	struct vmx_nested_hardware_report_input report_input;
	struct vmx_nested_hardware_report_result report_result;
	struct vmx_nested_exit_information information;
	struct vmx_nested_attempt_plan attempt;
	struct vmx_nested_outer_exit_intel outer;
	struct vmx_nested_run_pmap run_pmap;
	struct vmx_nested_vmentry_result rejection;
	struct vmm_startup_entry_loop_result owner_result;
	const struct vmx_nested_vmcs02_id *id;
	enum vmx_nested_hardware_entry_finish_completion initial_completion;
	enum vmx_nested_resumed_hardware_attempt_completion resumed_completion;
	enum vmx_nested_run_unwind_action unwind_action;
	struct region_descriptor gdtr, idtr;
	struct vm_exit *vmexit;
	struct vmxctx *vmxctx;
	struct vmx *vmx;
	uint64_t exit_sequence;
	uint32_t exit_reason;
	uint16_t ldt_sel;
	bool completed, debugged, first, hot, pvclock, rendezvous, reqidle,
	    suspended, yield;
	int error, handled, launched, rc;

	if (vcpu == NULL || pmap == NULL || evinfo == NULL ||
	    (target != VMX_NESTED_RUN_L2_INITIAL &&
	    target != VMX_NESTED_RUN_L2_RESUME) ||
	    !vcpu->nested_vmcs02_plan_valid)
		return (EINVAL);
	vmx = vcpu->vmx;
	vmxctx = &vcpu->ctx;
	vmexit = vm_exitinfo(vcpu->vcpu);

	/*
	 * A cold thaw owns resources in the frozen execution domain.  If the
	 * outer VMM must stop before the CPU-pinned commit point, preserve the
	 * explicit CPU-independent stage.  It can be resumed on the eventual
	 * execution CPU or cancelled later in the frozen execution domain;
	 * cancellation is not legal from inside vm_run()'s critical section.
	 */
	suspended = vcpu_suspended(evinfo);
	rendezvous = vcpu_rendezvous_pending(vcpu->vcpu, evinfo);
	reqidle = vcpu_reqidle(evinfo);
	yield = vcpu_should_yield(vcpu->vcpu);
	debugged = vcpu_debugged(vcpu->vcpu);
	pvclock = vpvclock_pending(vcpu->vcpu);
	if (suspended || rendezvous || reqidle || yield || debugged || pvclock) {
		vmx_nested_publish_host_stop(vcpu, rip, suspended, rendezvous,
		    reqidle, yield, debugged, pvclock);
		/*
		 * This is the one nested return provably before guest MSRs, a
		 * VMCS02 selection, an EPT activation, or an L2 event transaction.
		 * It may therefore consume the common owner as a true no-entry
		 * result.  Later paths use the residency-specific owner transaction
		 * after their matching private inverse is available.
		 */
		if (entry_owner != NULL &&
		    vmm_startup_entry_owner_software_exit(entry_owner,
		    &owner_result) != 0)
			panic("%s: nested lifecycle startup owner", __func__);
		return (0);
	}
	vmx_msr_guest_enter(vcpu);
	VMPTRLD(vcpu->vmcs);
	vmcs_write(VMCS_HOST_CR3, rcr3());
	vmx_set_pcpu_defaults(vmx, vcpu, pmap);
	memset(&event, 0, sizeof(event));
	memset(&run_pmap, 0, sizeof(run_pmap));
	first = true;
	hot = false;

	for (;;) {
		disable_intr();

		/*
		 * Once L0 has handled a VMCS02 exit, the exact continuation is
		 * already named.  A host stop freezes it before any return so
		 * VMCS02 and L2 MSRs never escape the CPU-pinned run boundary.
		 */
		suspended = vcpu_suspended(evinfo);
		rendezvous = vcpu_rendezvous_pending(vcpu->vcpu, evinfo);
		reqidle = vcpu_reqidle(evinfo);
		yield = vcpu_should_yield(vcpu->vcpu);
		debugged = vcpu_debugged(vcpu->vcpu);
		pvclock = vpvclock_pending(vcpu->vcpu);
		if (hot && (suspended || rendezvous || reqidle || yield ||
		    debugged || pvclock)) {
			id = &vcpu->nested_vmcs02_plan.id;
			error = vmx_nested_hot_exit_freeze_publish(
			    &vcpu->nested, &vcpu->nested_l0_continuation,
			    &vcpu->nested_entry_runtime, id,
			    &vmx_nested_hot_exit_intel_ops, vcpu);
			if (error != 0)
				goto fail_intr;
			enable_intr();
			vmx_nested_publish_host_stop(vcpu, rip, suspended, rendezvous,
			    reqidle, yield, debugged, pvclock);
			if (entry_owner != NULL &&
			    vmm_startup_entry_owner_software_exit(entry_owner,
			    &owner_result) != 0)
				panic("%s: nested hot lifecycle startup owner", __func__);
			break;
		}

		if (first && target == VMX_NESTED_RUN_L2_INITIAL) {
			error = vmx_nested_run_pmap_prepare(vcpu, pmap,
			    &run_pmap);
			if (error != 0)
				goto fail_intr;
			error = vmx_nested_entry_event_intel_prepare(vcpu,
			    &event);
			if (error != 0)
				goto fail_intr;
			error = vmx_nested_complete_planned_event(vcpu, rip, &event,
			    entry_owner, VMX_NESTED_PLANNED_EVENT_INITIAL, &completed);
			if (error != 0)
				goto fail_intr;
			if (completed)
				break;
			error = vmx_nested_owner_guard_or_exit(vcpu, rip, &event,
			    entry_owner, &completed);
			if (error != 0)
				panic("%s: nested initial startup owner: %d", __func__,
				    error);
			if (completed)
				break;
		} else if (first) {
			int pmap_error;

			error = vmx_nested_l0_thaw_commit_hot_intel(vcpu);
			if (error != 0)
				goto fail_intr;
			error = vmx_nested_run_pmap_prepare(vcpu, pmap,
			    &run_pmap);
			if (error != 0) {
				pmap_error = error;
				error =
				    vmx_nested_l0_refreeze_unentered_intel(vcpu);
				if (error != 0)
					goto fail_intr;
				enable_intr();
				/*
				 * A missing, stale, or mismatched retained EPT
				 * root is an ownership invariant failure, not
				 * the compare-exchange race handled by the
				 * frozen EPT handoff.  The exact cold image is
				 * now safe, but redispatching its continuation
				 * would repeat the same failure without a
				 * state change.  Preserve the original error.
				 */
				error = pmap_error;
				if (entry_owner != NULL &&
				    vmm_startup_entry_owner_fail_before_entry(entry_owner,
				    error, &owner_result) != 0)
					panic("%s: nested pmap startup owner", __func__);
				goto out_error;
			}
			error = vmx_nested_entry_event_intel_plan(vcpu,
			    &event, false);
			if (error != 0)
				goto refreeze_first;
			error = vmx_nested_complete_planned_event(vcpu, rip, &event,
			    entry_owner, VMX_NESTED_PLANNED_EVENT_RESUMED,
			    &completed);
			if (error != 0)
				goto fail_intr;
			if (completed)
				break;
			error = vmx_nested_owner_guard_or_exit(vcpu, rip, &event,
			    entry_owner, &completed);
			if (error != 0)
				panic("%s: nested resumed startup owner: %d", __func__,
				    error);
			if (completed)
				break;
			error = vmx_nested_l0_resume_prepare_intel(vcpu,
			    &event);
			if (error != 0)
				goto refreeze_first;
		} else {
			error = vmx_nested_entry_event_intel_plan(vcpu,
			    &event, false);
			if (error != 0)
				goto fail_intr;
			error = vmx_nested_complete_planned_event(vcpu, rip, &event,
			    entry_owner, VMX_NESTED_PLANNED_EVENT_HOT, &completed);
			if (error != 0)
				goto fail_intr;
			if (completed)
				break;
			error = vmx_nested_owner_guard_or_exit(vcpu, rip, &event,
			    entry_owner, &completed);
			if (error != 0)
				panic("%s: nested hot startup owner: %d", __func__,
				    error);
			if (completed)
				break;
			error = vmx_nested_l0_resume_prepare_intel(vcpu,
			    &event);
			if (error != 0)
				goto fail_intr;
			error = vmx_nested_hot_exit_resume(
			    &vcpu->nested_l0_continuation,
			    &vcpu->nested_entry_runtime,
			    &vcpu->nested_vmcs02_plan.id,
			    &vmx_nested_l0_resume_intel_ops, vcpu);
			if (error != 0)
				goto fail_intr;
			error = vmx_nested_tsc_aux_resume_l2_intel(vcpu);
			if (error != 0)
				goto fail_intr;
		}

		error = vmx_nested_vmcs02_intel_entry_instruction(
		    &vcpu->nested_vmcs02_intel, &launched);
		if (error != 0)
			goto fail_intr;
		sgdt(&gdtr);
		sidt(&idtr);
		ldt_sel = sldt();
		vmx_dr_enter_guest(vmxctx);
		vmx_nested_run_pmap_activate(vmx, &run_pmap);
		id = &vcpu->nested_vmcs02_plan.id;
		SDT_PROBE5(vmm, vmx, nested, entry, vmx, vcpu->vcpuid,
		    id->vmcs12_gpa, id->execution_epoch, launched);
		vmx_run_trace(vcpu);
		rc = vmx_enter_guest(vmxctx, vmx, launched);
		vmx_nested_run_pmap_deactivate(vmx, &run_pmap);
		vmx_dr_leave_guest(vmxctx);
		/*
		 * VM exit restores the descriptor-table bases but not the
		 * saved host limits, and clears LDTR.  Reestablish the complete
		 * host descriptor state before executing any C classifier or
		 * error path, matching the ordinary VMX run loop's residency
		 * boundary.
		 */
		bare_lgdt(&gdtr);
		lidt(&idtr);
		lldt(ldt_sel);
		error = vmx_nested_hardware_report_intel(vcpu, rc,
		    &report_input, &information);
		if (error != 0)
			goto fail_intr;
		if (report_input.report ==
		    VMX_NESTED_HARDWARE_REPORT_VMEXIT)
			SDT_PROBE5(vmm, vmx, nested, vmexit, vmx,
			    vcpu->vcpuid, id->vmcs12_gpa,
			    id->execution_epoch, information.exit_reason);

		memset(&attempt, 0, sizeof(attempt));
		if (first && target == VMX_NESTED_RUN_L2_INITIAL) {
			memset(&rejection, 0, sizeof(rejection));
			initial_completion =
			    VMX_NESTED_HARDWARE_ENTRY_FINISH_NONE;
			error =
			    vmx_nested_finish_initial_hardware_attempt(vcpu,
			    &event, &report_input, &information, &attempt,
			    &rejection, &initial_completion);
			if (error != 0)
				goto fail_intr;
			if ((attempt.action == VMX_NESTED_ATTEMPT_INITIAL_EXIT &&
			    initial_completion !=
			    VMX_NESTED_HARDWARE_ENTRY_FINISH_ENTERED) ||
			    (attempt.action == VMX_NESTED_ATTEMPT_INITIAL_REJECTION &&
			    initial_completion !=
			    VMX_NESTED_HARDWARE_ENTRY_FINISH_UNENTERED_ROLLED_BACK)) {
				error = EPROTO;
				goto fail_intr;
			}
			if (attempt.action ==
			    VMX_NESTED_ATTEMPT_INITIAL_REJECTION) {
				error = vmx_nested_publish_initial_rejection(
				    vcpu, &rejection);
				if (error != 0)
					goto fail_intr;
				if (entry_owner != NULL) {
					error = vmx_nested_owner_settle_initial_attempt(
					    entry_owner, &attempt, initial_completion);
					if (error != 0)
						panic("%s: nested rejection startup owner: %d",
						    __func__, error);
				}
				enable_intr();
				vmexit->rip = rip;
				vmexit->inst_length = 0;
				vmexit->exitcode =
				    VM_EXITCODE_VMM_INTERNAL;
				break;
			}
			if (attempt.action !=
			    VMX_NESTED_ATTEMPT_INITIAL_EXIT) {
				error = EIO;
				goto fail_intr;
			}
			if (entry_owner != NULL) {
				error = vmx_nested_owner_settle_initial_attempt(entry_owner,
				    &attempt, initial_completion);
				if (error != 0)
					panic("%s: nested initial attempt owner: %d",
					    __func__, error);
			}
		} else if (first) {
			resumed_completion =
			    VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_NONE;
			error =
			    vmx_nested_finish_resumed_hardware_attempt(vcpu,
			    &event, &report_input, &information, &attempt,
			    &resumed_completion);
			if (error != 0)
				goto fail_intr;
			if ((attempt.action == VMX_NESTED_ATTEMPT_RESUMED_EXIT &&
			    resumed_completion !=
			    VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_ENTERED) ||
			    (attempt.action != VMX_NESTED_ATTEMPT_RESUMED_EXIT &&
			    resumed_completion !=
			    VMX_NESTED_RESUMED_HARDWARE_ATTEMPT_UNENTERED_REFROZEN)) {
				error = EPROTO;
				goto fail_intr;
			}
			if (entry_owner != NULL) {
				error = vmx_nested_owner_settle_resumed_attempt(entry_owner,
				    &attempt, resumed_completion);
				if (error != 0)
					panic("%s: nested resumed attempt owner: %d",
					    __func__, error);
			}
			if (attempt.action !=
			    VMX_NESTED_ATTEMPT_RESUMED_EXIT) {
				enable_intr();
				vmexit->rip = rip;
				vmexit->inst_length = 0;
				vmexit->exitcode =
				    VM_EXITCODE_VMM_INTERNAL;
				break;
			}
		} else {
			error = vmx_nested_hardware_report_classify(
			    &report_input, &report_result);
			if (error != 0)
				goto fail_intr;
			if (report_result.disposition !=
			    VMX_NESTED_HARDWARE_L2_EXIT) {
				int original_error;

				original_error = EIO;
				error =
				    vmx_nested_hot_residency_abort_intel(vcpu,
				    &event);
				if (entry_owner != NULL &&
				    vmx_nested_owner_settle_unwind_error(entry_owner,
				    VMX_NESTED_RUN_UNWIND_DETACH_FATAL,
				    original_error, error) != 0)
					panic("%s: nested hot abort startup owner",
					    __func__);
				enable_intr();
				goto out_error;
			}
			vmx_nested_entry_event_intel_commit_entered(&event);
			attempt.exit = information;
		}
		first = false;
		hot = false;

		error = vmx_nested_tsc_aux_pause_l2_intel(vcpu);
		if (error != 0)
			goto fail_intr;
		error = vmx_nested_exit_intel_prepare(vcpu,
		    &attempt.exit, false, &outer);
		if (error != 0)
			goto fail_intr;
		if (outer.dispatch ==
		    VMX_NESTED_OUTER_EXIT_EPT_WALK) {
			error = vmx_nested_publish_ept_exit_hot(vcpu,
			    &attempt.exit);
			if (error != 0)
				goto fail_intr;
			error = vmx_nested_owner_defer_postentry(entry_owner,
			    VMX_NESTED_OWNER_POSTENTRY_DEFER_EPT_WALK,
			    VMX_NESTED_RUN_UNWIND_FREEZE_HOT, 0);
			if (error != 0)
				panic("%s: nested EPT exit startup owner: %d",
				    __func__, error);
			enable_intr();
			vmexit->rip = rip;
			vmexit->inst_length = 0;
			vmexit->exitcode = VM_EXITCODE_VMM_INTERNAL;
			break;
		}
		if (outer.action == VMX_NESTED_EXIT_REFLECT_L1) {
			error = vmx_nested_publish_reflected_exit_hot(vcpu,
			    &attempt.exit);
			if (error != 0)
				goto fail_intr;
			error = vmx_nested_owner_defer_postentry(entry_owner,
			    VMX_NESTED_OWNER_POSTENTRY_DEFER_REFLECTION,
			    VMX_NESTED_RUN_UNWIND_CLEAN, 0);
			if (error != 0)
				panic("%s: nested reflected exit startup owner: %d",
				    __func__, error);
			enable_intr();
			vmexit->rip = rip;
			vmexit->inst_length = 0;
			vmexit->exitcode = VM_EXITCODE_VMM_INTERNAL;
			break;
		}

		if (vcpu->nested_exit_sequence == UINT64_MAX) {
			error = EOVERFLOW;
			goto fail_intr;
		}
		id = &vcpu->nested_vmcs02_plan.id;
		exit_sequence = vcpu->nested_exit_sequence + 1;
		error = vmx_nested_hot_exit_begin(&vcpu->nested,
		    &vcpu->nested_l0_continuation,
		    &vcpu->nested_entry_runtime, id, exit_sequence,
		    outer.action);
		if (error != 0)
			goto fail_intr;
		vcpu->nested_exit_sequence = exit_sequence;

		vmexit->rip = rip = vmcs_guest_rip();
		vmexit->inst_length =
		    attempt.exit.exit_instruction_length;
		vmexit->u.vmx.exit_reason = exit_reason =
		    attempt.exit.exit_reason;
		vmexit->u.vmx.exit_qualification =
		    attempt.exit.exit_qualification;
		vcpu->state.nextrip = rip;
		vmx_exit_handle_nmi(vcpu, vmexit);
		enable_intr();
		handled = vmx_exit_process(vmx, vcpu, vmexit);
		vmx_exit_trace(vcpu, rip, exit_reason, handled);

		if (outer.action ==
		    VMX_NESTED_EXIT_HANDLE_L0_THEN_REFLECT_L1 ||
		    !handled) {
			error = vmx_nested_hot_exit_freeze_publish(
			    &vcpu->nested, &vcpu->nested_l0_continuation,
			    &vcpu->nested_entry_runtime, id,
			    &vmx_nested_hot_exit_intel_ops, vcpu);
			if (error != 0) {
				disable_intr();
				goto fail_intr;
			}
			if (outer.action ==
			    VMX_NESTED_EXIT_HANDLE_L0_THEN_REFLECT_L1) {
				vmexit->rip = rip;
				vmexit->inst_length = 0;
				vmexit->exitcode =
				    VM_EXITCODE_VMM_INTERNAL;
			}
			error = vmx_nested_owner_defer_postentry(entry_owner,
			    outer.action == VMX_NESTED_EXIT_HANDLE_L0_THEN_REFLECT_L1 ?
			    VMX_NESTED_OWNER_POSTENTRY_DEFER_REFLECTION :
			    VMX_NESTED_OWNER_POSTENTRY_DEFER_UNHANDLED,
			    VMX_NESTED_RUN_UNWIND_FREEZE_HOT, 0);
			if (error != 0)
				panic("%s: nested frozen exit startup owner: %d",
				    __func__, error);
			break;
		}
		if (entry_owner != NULL &&
		    vmx_nested_owner_postentry_transition(entry_owner,
		    VMX_NESTED_OWNER_POSTENTRY_RECHECK, 0) != 0)
			panic("%s: nested handled exit startup owner", __func__);
		hot = true;
		continue;

refreeze_first:
		/*
		 * This label is shared by pre-admission event planning and by the
		 * fallible resumed-entry preparation which follows admission.  Keep
		 * the original error: refreezing is the private inverse, not proof
		 * that a pending common hardware attempt became a software exit.
		 */
		{
			int entry_error;

			entry_error = error;
		vmx_nested_entry_event_intel_abort(&event);
		error = vmx_nested_l0_refreeze_unentered_intel(vcpu);
		if (error != 0)
			goto fail_intr;
		if (entry_owner != NULL &&
		    entry_owner->phase == VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING) {
			if (entry_error == EAGAIN) {
				if (vmm_startup_entry_owner_abort_attempt(entry_owner,
				    &owner_result) != 0)
					panic("%s: nested retry startup owner", __func__);
				enable_intr();
				vmexit->rip = rip;
				vmexit->inst_length = 0;
				vmexit->exitcode = VM_EXITCODE_VMM_INTERNAL;
				break;
			}
			if (vmm_startup_entry_owner_abort_attempt_error(entry_owner,
			    entry_error, &owner_result) != 0)
				panic("%s: nested refreeze startup owner", __func__);
			enable_intr();
			error = entry_error;
			goto out_error;
		}
		enable_intr();
		vmexit->rip = rip;
		vmexit->inst_length = 0;
		vmexit->exitcode = VM_EXITCODE_VMM_INTERNAL;
		if (entry_owner != NULL &&
			vmm_startup_entry_owner_software_exit(entry_owner,
			&owner_result) != 0)
			panic("%s: nested refreeze startup owner", __func__);
		break;
		}
fail_intr:
		SDT_PROBE5(vmm, vmx, nested, failure, vmx, vcpu->vcpuid,
		    error, vcpu->nested_entry_runtime.state,
		    vcpu->nested_l0_continuation.state);
		{
			int original_error;

			original_error = error;
			unwind_action = VMX_NESTED_RUN_UNWIND_FAIL_STOP;
			error = vmx_nested_run_unwind_intel(vcpu, &event,
			    original_error, &unwind_action);
			if (unwind_action == VMX_NESTED_RUN_UNWIND_FAIL_STOP)
				panic("%s: nested unwind did not make residency safe: %d",
				    __func__, error);
			if (entry_owner != NULL &&
			    vmx_nested_owner_settle_unwind_error(entry_owner,
			    unwind_action, original_error, error) != 0)
				panic("%s: nested unwind startup owner", __func__);
		}
		enable_intr();
		goto out_error;
	}

	if (vcpu->nested_vmcs02_intel.launch.current)
		panic("%s: successful return retained VMCS02 (runtime %u "
		    "continuation %u)", __func__,
		    vcpu->nested_entry_runtime.state,
		    vcpu->nested_l0_continuation.state);
	if (vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_count != 0)
		panic("%s: successful return retained nested MSR transition %u/%u",
		    __func__, vcpu->nested_hardware_msr_transition,
		    vcpu->nested_hardware_msr_count);
	if (vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1)
		panic("%s: successful return retained TSC_AUX residency %u",
		    __func__, vcpu->nested_tsc_aux_residency);
	VMCLEAR(vcpu->vmcs);
	vmx_msr_guest_exit(vcpu);
	return (0);

out_error:
	/*
	 * Every fallible path above either left VMCS01 current or completed
	 * the explicit fail-stop detach.  A live VMCS02 here would make an
	 * ordinary error return unsafe: the thread could migrate with L2
	 * software MSRs and a CPU-local current-VMCS association.  Fail
	 * loudly until that particular edge has an explicit transactional
	 * unwind rather than silently leaking hardware residency.
	 */
	if (vcpu->nested_vmcs02_intel.launch.current)
		panic("%s: error %d retained VMCS02 (runtime %u "
		    "continuation %u)", __func__, error,
		    vcpu->nested_entry_runtime.state,
		    vcpu->nested_l0_continuation.state);
	if (vcpu->nested_hardware_msr_transition !=
	    VMX_NESTED_HARDWARE_MSR_NONE ||
	    vcpu->nested_hardware_msr_count != 0 ||
	    vcpu->nested_tsc_aux_residency != VMX_NESTED_TSC_AUX_L1)
		panic("%s: error %d retained L2 MSRs (transition %u "
		    "count %u TSC_AUX %u)", __func__, error,
		    vcpu->nested_hardware_msr_transition,
		    vcpu->nested_hardware_msr_count,
		    vcpu->nested_tsc_aux_residency);
	VMCLEAR(vcpu->vmcs);
	vmx_msr_guest_exit(vcpu);
	return (error);
}

/*
 * Build the complete value-owned entry transaction while the vCPU is frozen.
 * Guest memory is acquired only when the link pointer, non-EPT PAE PDPTEs,
 * or entry MSR list requires it.  Each required object is read exactly once.
 * The workspace remains active only for a ready plan; its rollback half then
 * belongs to the later hardware-commit path.
 */
static int
vmx_nested_prepare_frozen_entry(struct vmx_vcpu *vcpu,
    const struct vmx_nested_vmcs02_id *entry_id,
    const struct vmx_nested_vmcs12_snapshot *snapshot,
    const struct vmx_nested_entry_environment *environment,
    struct vmx_nested_vmcs02_plan *plan,
    struct vmx_nested_software_msrs *l1_software,
    struct vmx_nested_software_msrs *l2_software, uint64_t *generation,
    uint32_t *entry_msr_count)
{
	struct vmx_nested_guest_memory_intel guest_memory;
	struct vmx_nested_guest_control_state effective_control;
	struct vmx_nested_guest_arch_state effective_arch;
	struct vmx_nested_msr_policy msr_policy;
	struct vmx_nested_virtual_msr virtual_msr;
	struct vmx_nested_vmcs02_input input;
	struct vmx_nested_vmcs02_plan candidate;
	struct vmx_nested_software_msrs software_candidate;
	struct vmx_nested_vmentry_input vmentry;
	enum vmx_nested_msr_apply_outcome outcome;
	uint64_t workspace_generation;
	uint32_t count, failed_entry;
	int end_error, error;

	if (vcpu == NULL || entry_id == NULL || snapshot == NULL ||
	    environment == NULL || plan == NULL || l1_software == NULL ||
	    l2_software == NULL || generation == NULL ||
	    entry_msr_count == NULL)
		return (EINVAL);
	error = vmx_nested_vmcs02_effective_guest_state(
	    &snapshot->capabilities, &snapshot->controls,
	    &environment->l1_runtime, &snapshot->guest_control,
	    &snapshot->guest_arch, &effective_control, &effective_arch);
	if (error != 0)
		return (error);
	vmx_nested_software_msrs_capture(vcpu, &software_candidate);
	memset(&virtual_msr, 0, sizeof(virtual_msr));
	virtual_msr.capabilities = &snapshot->capabilities;
	virtual_msr.control = &effective_control;
	virtual_msr.arch = &effective_arch;
	virtual_msr.software = &software_candidate;
	virtual_msr.syscall_available = true;
	virtual_msr.tsc_aux_available = vmx_have_msr_tsc_aux;
	memset(&msr_policy, 0, sizeof(msr_policy));
	msr_policy.validate_write = vmx_nested_virtual_msr_validate_write;
	msr_policy.validate_read = vmx_nested_virtual_msr_validate_read;
	msr_policy.arg = &virtual_msr;
	error = vmx_nested_vmcs12_vmentry_input(snapshot, NULL, &msr_policy,
	    &vmentry);
	if (error != 0)
		return (error);
	if (vmx_nested_vmentry_memory_required(&vmentry)) {
		error = vmx_nested_guest_memory_intel_init(&guest_memory,
		    vcpu->vcpu);
		if (error != 0)
			return (error);
		vmentry.memory =
		    vmx_nested_guest_memory_intel_memory(&guest_memory);
	}
	error = vmx_nested_entry_environment_bind(environment, entry_id,
	    &snapshot->capabilities, &vmentry, &input);
	if (error != 0)
		return (error);
	error = vmx_nested_msr_workspace_begin(&vcpu->nested_msr_workspace,
	    &snapshot->capabilities, snapshot->controls.entry_msr_load_count,
	    snapshot->controls.exit_msr_store_count,
	    snapshot->controls.exit_msr_load_count, &workspace_generation);
	if (error != 0)
		return (error);
	count = UINT32_MAX;
	error = vmx_nested_vmcs02_prepare_frozen(&input,
	    vcpu->nested_msr_workspace.plan,
	    vcpu->nested_msr_workspace.capacity, &count, &candidate);
	if (error != 0)
		goto fail;
	if (candidate.vmentry.disposition != VMX_NESTED_VMENTRY_READY) {
		error = vmx_nested_msr_workspace_end(
		    &vcpu->nested_msr_workspace, workspace_generation);
		if (error != 0)
			return (error);
		*plan = candidate;
		vmx_nested_software_msrs_capture(vcpu, l1_software);
		*l2_software = software_candidate;
		*generation = 0;
		*entry_msr_count = 0;
		return (0);
	}

	/*
	 * Rebind the already validated list to the final plan image.  This
	 * catches sequential dependencies between duplicate MSR entries that
	 * a side-effect-free per-entry validation pass cannot observe.
	 */
	virtual_msr.control = &candidate.image.l2_control;
	virtual_msr.arch = &candidate.image.l2_arch;
	outcome = VMX_NESTED_MSR_APPLY_OK;
	failed_entry = 0;
	error = vmx_nested_msr_list_apply(vcpu->nested_msr_workspace.plan,
	    count, vmx_nested_virtual_msr_apply_ops(), &virtual_msr,
	    vcpu->nested_msr_workspace.rollback,
	    vcpu->nested_msr_workspace.capacity, &outcome, &failed_entry);
	if (error != 0 &&
	    outcome == VMX_NESTED_MSR_APPLY_WRITE_FAILED_ROLLED_BACK &&
	    error == EINVAL) {
		memset(&candidate.image, 0, sizeof(candidate.image));
		error = vmx_nested_vmentry_msr_apply_failure(failed_entry,
		    VMX_NESTED_MSR_VALUE, &candidate.vmentry);
		if (error != 0)
			goto fail;
		error = vmx_nested_msr_workspace_end(
		    &vcpu->nested_msr_workspace, workspace_generation);
		if (error != 0)
			return (error);
		*plan = candidate;
		vmx_nested_software_msrs_capture(vcpu, l1_software);
		*l2_software = software_candidate;
		*generation = 0;
		*entry_msr_count = 0;
		return (0);
	}
	if (error != 0)
		goto fail;
	*plan = candidate;
	vmx_nested_software_msrs_capture(vcpu, l1_software);
	*l2_software = software_candidate;
	*generation = workspace_generation;
	*entry_msr_count = count;
	return (0);

fail:
	end_error = vmx_nested_msr_workspace_end(
	    &vcpu->nested_msr_workspace, workspace_generation);
	if (end_error != 0)
		panic("%s: cannot release failed MSR workspace: %d", __func__,
		    end_error);
	return (error);
}

static int
vmx_handle_internal_exit(void *vcpui)
{
	static const struct vmx_nested_continuation_handoff_ops
	    continuation_ops = {
		.handle = vmx_nested_handle_continuation_frozen,
	};
	static const struct vmx_nested_instruction_commit_ops commit_ops = {
		.commit = vmx_nested_commit_instruction,
	};
	static const struct vmx_nested_vmentry_resolution_ops
	    rejection_ops = {
		.commit = vmx_nested_commit_rejected_entry,
	};
	struct vmx_nested_instruction_handoff *instruction;
	struct vmx_nested_instruction_handoff_id id;
	struct vmx_nested_instruction_handoff_result result;
	struct vmx_nested_continuation_handoff *continuation;
	struct vmx_nested_continuation_handoff_request continuation_request;
	struct vmx_nested_continuation_handoff_result continuation_result;
	struct vmx_nested_vmcs02_id continuation_id;
	struct vmx_nested_entry_environment entry_environment;
	struct vmx_nested_entry_environment_capture environment_capture;
	struct vmx_nested_vmcs02_plan vmcs02_plan;
	struct vmx_nested_software_msrs l1_software_msrs;
	struct vmx_nested_software_msrs l2_software_msrs;
	struct vmx_nested_vmcs02_resources l0_fixed_resources;
	struct vmx_nested_vmcs02_id entry_id;
	struct vmx_nested_instruction_runtime runtime;
	struct vmx_nested_vmcs12_snapshot vmcs12_snapshot;
	struct vmx_nested_ept_handoff *ept;
	struct vmx_nested_ept_handoff_id ept_id;
	struct vmx_nested_ept_handoff_result ept_result;
	enum vmx_nested_cold_ept_disposition ept_disposition;
	struct vmx_nested_ept_cache_key ept_key;
	struct vmx_nested_ept_runtime ept_runtime;
	struct vmx_nested_guest_memory_intel guest_memory;
	struct vmx_nested_rejected_entry_commit rejection_commit;
	struct vmx_nested_vmcs02_resources vmcs02_resources;
	struct vmx_nested_vmentry_resolution rejection;
	struct vm_guest_paging paging;
	struct vmx_vcpu *vcpu;
	enum vmx_nested_internal_dispatch internal_dispatch;
	bool internal_resolved;
	uint64_t msr_generation;
	uint32_t entry_msr_count;
	void *runtime_root;
	int error;

	vcpu = vcpui;
	error = vmx_nested_context_internal_dispatch(&vcpu->nested, true,
	    &internal_dispatch);
	if (error != 0)
		return (error);
	internal_resolved =
	    internal_dispatch == VMX_NESTED_INTERNAL_DISPATCH_COMMIT;
	if (vcpu->nested.internal.kind == VMX_NESTED_INTERNAL_EPT) {
		if (vcpu->nested_l0_continuation.state ==
		    VMX_NESTED_L0_CONTINUATION_ABORTED ||
		    vcpu->nested_entry_runtime.state ==
		    VMX_NESTED_ENTRY_RUNTIME_ABORTED)
			return (EIO);
		ept = &vcpu->nested.internal.operation.ept;
		ept_id = ept->request.id;
		if (!internal_resolved) {
			ept_key.eptp = ept->request.eptp;
			error = vmx_nested_capabilities_signature(
			    &ept->request.capabilities,
			    &ept_key.capability_signature);
			if (error != 0)
				return (error);
			ept_key.mode_based_execute =
			    ept->request.mode_based_execute;
			error = vmx_nested_ept_binding_resolve(
			    &vcpu->nested_ept_cache,
			    &vcpu->nested_ept_binding, &ept_key,
			    &runtime_root);
			if (error != 0)
				return (error);
			error = vmx_nested_ept_runtime_init(&ept_runtime,
			    vcpu->vcpu, runtime_root);
			if (error != 0)
				return (error);
			error = vmx_nested_internal_handle_ept(
			    &vcpu->nested.internal, &ept_id,
			    vmx_nested_ept_runtime_memory(&ept_runtime),
			    vmx_nested_ept_runtime_ops(), &ept_runtime);
			/*
			 * An L1 EPT entry may change between the load and A/D
			 * compare-exchange.  The handoff has returned to
			 * PENDING without publishing a result, so retain it and
			 * let the ordinary VM_RUN restart boundary retry.  This
			 * also services suspend and rendezvous requests between
			 * attempts instead of spinning in the frozen callback.
			 */
			if (error == EAGAIN)
				return (0);
			if (error != 0)
				return (error);
		}
		if (vcpu->nested_l0_continuation.state ==
		    VMX_NESTED_L0_CONTINUATION_COLD) {
			error = vmx_nested_cold_ept_resolve(&vcpu->nested,
			    &vcpu->nested_l0_continuation,
			    &vcpu->nested_entry_runtime,
			    &vcpu->nested_l2_portable, &ept_disposition);
			if (error != 0)
				return (error);
			if (ept_disposition ==
			    VMX_NESTED_COLD_EPT_REFLECTED)
				return (vmx_nested_commit_captured_exit(vcpu));
			if (ept_disposition !=
			    VMX_NESTED_COLD_EPT_POPULATED)
				return (EPROTO);
			return (vmx_nested_l0_thaw_prepare_intel(vcpu,
			    &vcpu->nested_l2_portable));
		}
		return (vmx_nested_context_commit_ept_population(
		    &vcpu->nested, &ept_id, true, &ept_result));
	}
	if (vcpu->nested.internal.kind == VMX_NESTED_INTERNAL_VMEXIT)
		return (vmx_nested_commit_captured_exit(vcpu));
	if (vcpu->nested.internal.kind ==
	    VMX_NESTED_INTERNAL_VMENTRY_REJECT)
		return (vmx_nested_commit_rejected_handoff(vcpu));
	if (vcpu->nested.internal.kind ==
	    VMX_NESTED_INTERNAL_LATE_VMENTRY)
		return (vmx_nested_commit_late_entry_handoff(vcpu));
	if (vcpu->nested.internal.kind == VMX_NESTED_INTERNAL_REFREEZE)
		return (vmx_nested_l0_refreeze_commit_frozen_intel(vcpu));
	if (vcpu->nested.internal.kind ==
	    VMX_NESTED_INTERNAL_CONTINUATION) {
		continuation =
		    &vcpu->nested.internal.operation.continuation;
		continuation_id = continuation->request.id;
		if (!internal_resolved) {
			error = vmx_nested_internal_handle_continuation(
			    &vcpu->nested.internal, &continuation_id,
			    &continuation_ops, vcpu);
			if (error != 0)
				return (error);
		}
		if (continuation->result.disposition ==
		    VMX_NESTED_CONTINUATION_REFLECTED ||
		    continuation->result.disposition ==
		    VMX_NESTED_CONTINUATION_MTF_REFLECTED) {
			if (continuation->result.disposition ==
			    VMX_NESTED_CONTINUATION_MTF_REFLECTED) {
				error = vmx_nested_cold_mtf_reflect_publish(
				    &vcpu->nested,
				    &vcpu->nested_l0_continuation,
				    &vcpu->nested_entry_runtime,
				    &vcpu->nested_l2_portable,
				    continuation->request.portable_generation);
			} else {
				error = vmx_nested_cold_reflect_publish(
				    &vcpu->nested,
				    &vcpu->nested_l0_continuation,
				    &vcpu->nested_entry_runtime,
				    &vcpu->nested_l2_portable);
			}
			if (error != 0)
				return (error);
			return (vmx_nested_commit_captured_exit(vcpu));
		}
		error = vmx_nested_internal_take_continuation(
		    &vcpu->nested.internal, &continuation_id,
		    &continuation_request, &continuation_result);
		if (error != 0)
			return (error == EINVAL ? EPROTO : error);
		if (continuation_result.disposition !=
		    VMX_NESTED_CONTINUATION_RESUME_PREPARED)
			return (EPROTO);
		return (0);
	}
	if (vcpu->nested.internal.kind !=
	    VMX_NESTED_INTERNAL_INSTRUCTION)
		return (EPROTO);
	instruction = &vcpu->nested.internal.operation.instruction;
	id = instruction->request.id;

	if (!internal_resolved) {
		/*
		 * vmx_run() returns with the hardware VMCS clear.  Load it
		 * only long enough to capture L1 paging state, then let the
		 * frozen runtime use the generic fault-injecting memory
		 * helpers.  A resolved retry must not repeat either action.
		 */
		VMPTRLD(vcpu->vmcs);
		vmx_paging_info(&paging);
		VMCLEAR(vcpu->vmcs);
		error = vmx_nested_instruction_runtime_init(&runtime,
		    vcpu->vcpu, &vcpu->vmx->nested_vmcs_sx,
		    &vcpu->vmx->nested_vmcs_registry,
		    &vcpu->nested_ept_cache, &vcpu->nested_vpid_owner, &paging,
		    &instruction->request.capabilities);
		if (error != 0)
			return (error);
		error = vmx_nested_internal_handle_instruction(
		    &vcpu->nested.internal, &id,
		    vmx_nested_instruction_runtime_ops(), &runtime);
	} else {
		error = EALREADY;
	}
	/*
	 * A frozen commit-stage host failure deliberately leaves the
	 * value-only result resolved.  Retrying the internal exit must reuse
	 * that result rather than execute guest memory or VMCS side effects a
	 * second time.
	 */
	if (error != 0 && error != EALREADY)
		return (error);
	if (instruction->result.disposition ==
	    VMX_NESTED_INSTRUCTION_ENTRY_READY) {
		if (vcpu->nested_entry_runtime.state !=
		    VMX_NESTED_ENTRY_RUNTIME_IDLE ||
		    vcpu->nested_vmcs02_plan_valid)
			return (EBUSY);
		sx_slock(&vcpu->vmx->nested_vmcs_sx);
		error = vmx_nested_vmcs_registry_snapshot(
		    &vcpu->vmx->nested_vmcs_registry,
		    vcpu->nested.machine.current_vmcs_gpa, vcpu->vcpuid,
		    false, &vmcs12_snapshot);
		sx_sunlock(&vcpu->vmx->nested_vmcs_sx);
		if (error != 0)
			return (error);
		/*
		 * The preliminary instruction handler and the frozen snapshot
		 * use the same registry owner but run in separate short lock
		 * windows.  Fail closed if launch state changed between them;
		 * a later retry will reuse the resolved instruction and repeat
		 * only this snapshot/commit stage.
		 */
		if ((instruction->request.operation ==
		    VMX_NESTED_INSTRUCTION_VMLAUNCH &&
		    vmcs12_snapshot.launched) ||
		    (instruction->request.operation ==
		    VMX_NESTED_INSTRUCTION_VMRESUME &&
		    (!vmcs12_snapshot.launched ||
		    vmcs12_snapshot.launch_epoch !=
		    instruction->request.machine.epoch)))
			return (ESTALE);
		error = vmx_nested_msr_workspace_ensure(vcpu,
		    &instruction->request.capabilities, true);
		if (error != 0)
			return (error);
		error = vmx_nested_vpid_ensure(vcpu);
		if (error != 0)
			return (error);
		error = vmx_nested_context_commit_vmentry_instruction(
		    &vcpu->nested, &id, true, &entry_id, &result);
		if (error != 0)
			return (error);
		error = vmx_nested_entry_runtime_begin(
		    &vcpu->nested_entry_runtime, &entry_id);
		if (error != 0) {
			int cancel_error;

			cancel_error = vmx_nested_context_cancel_entry(
			    &vcpu->nested, &entry_id);
			if (cancel_error != 0)
				panic("%s: cannot cancel unpublished nested "
				    "entry: %d", __func__, cancel_error);
			return (error);
		}
		error = vmx_nested_entry_environment_from_vmcs12(
		    &vmcs12_snapshot, &entry_id,
		    &vmx_nested_hardware_controls, vcpu->state.vpid,
		    vcpu->nested_vpid_owner.effective_vpid, false,
		    &environment_capture);
		if (error == 0)
			error = vmx_nested_entry_environment_intel_capture(vcpu,
			    &environment_capture, &entry_environment,
			    &l0_fixed_resources);
		if (error != 0) {
			int cancel_error;

			cancel_error = vmx_nested_entry_runtime_cancel(
			    &vcpu->nested_entry_runtime, &entry_id);
			if (cancel_error != 0)
				panic("%s: cannot cancel nested entry runtime: "
				    "%d", __func__, cancel_error);
			cancel_error = vmx_nested_context_cancel_entry(
			    &vcpu->nested, &entry_id);
			if (cancel_error != 0)
				panic("%s: cannot cancel nested entry after "
				    "environment capture: %d", __func__,
				    cancel_error);
			return (error);
		}
		error = vmx_nested_prepare_frozen_entry(vcpu, &entry_id,
		    &vmcs12_snapshot, &entry_environment, &vmcs02_plan,
		    &l1_software_msrs, &l2_software_msrs, &msr_generation,
		    &entry_msr_count);
		if (error != 0) {
			int cancel_error;

			cancel_error = vmx_nested_entry_runtime_cancel(
			    &vcpu->nested_entry_runtime, &entry_id);
			if (cancel_error != 0)
				panic("%s: cannot cancel failed nested entry "
				    "runtime: %d", __func__, cancel_error);
			cancel_error = vmx_nested_context_cancel_entry(
			    &vcpu->nested, &entry_id);
			if (cancel_error != 0)
				panic("%s: cannot cancel failed nested entry: "
				    "%d", __func__, cancel_error);
			return (error);
		}
		if (vmcs02_plan.vmentry.disposition !=
		    VMX_NESTED_VMENTRY_READY) {
			int cancel_error;

			rejection_commit.vcpu = vcpu;
			rejection_commit.snapshot = &vmcs12_snapshot;
			rejection_commit.environment = &entry_environment;
			error = vmx_nested_context_resolve_vmentry(
			    &vcpu->nested, &entry_id, &vmcs02_plan.vmentry,
			    true, &rejection_ops, &rejection_commit,
			    &rejection);
			if (error != 0)
				return (error);
			cancel_error = vmx_nested_entry_runtime_cancel(
			    &vcpu->nested_entry_runtime, &entry_id);
			if (cancel_error != 0)
				panic("%s: cannot finish rejected nested entry "
				    "runtime: %d", __func__, cancel_error);
			return (0);
		}
		error = vmx_nested_guest_memory_intel_init(&guest_memory,
		    vcpu->vcpu);
		if (error == 0)
			error = vmx_nested_vmcs02_resources_intel_acquire(vcpu,
			    &vmcs02_plan.image, &vmcs12_snapshot.controls,
			    vmx_nested_guest_memory_intel_memory(&guest_memory),
			    &l0_fixed_resources, &vmcs02_resources);
		if (error != 0) {
			int cancel_error, end_error;

			end_error = vmx_nested_msr_workspace_end(
			    &vcpu->nested_msr_workspace, msr_generation);
			if (end_error != 0)
				panic("%s: cannot release entry MSR workspace: "
				    "%d", __func__, end_error);
			cancel_error = vmx_nested_entry_runtime_cancel(
			    &vcpu->nested_entry_runtime, &entry_id);
			if (cancel_error != 0)
				panic("%s: cannot cancel resource-less nested "
				    "entry runtime: %d", __func__, cancel_error);
			cancel_error = vmx_nested_context_cancel_entry(
			    &vcpu->nested, &entry_id);
			if (cancel_error != 0)
				panic("%s: cannot cancel resource-less nested "
				    "entry: %d", __func__, cancel_error);
			return (error);
		}
		error = vmx_nested_entry_runtime_resources(
		    &vcpu->nested_entry_runtime, &entry_id,
		    vmcs02_resources.resource_generation);
		if (error != 0) {
			int cancel_error, end_error, release_error;

			release_error =
			    vmx_nested_vmcs02_resources_intel_release(vcpu,
			    &vmcs02_resources);
			if (release_error != 0)
				panic("%s: cannot release unpublished nested "
				    "resources: %d", __func__, release_error);
			end_error = vmx_nested_msr_workspace_end(
			    &vcpu->nested_msr_workspace, msr_generation);
			if (end_error != 0)
				panic("%s: cannot release unpublished MSR "
				    "workspace: %d", __func__, end_error);
			cancel_error = vmx_nested_entry_runtime_cancel(
			    &vcpu->nested_entry_runtime, &entry_id);
			if (cancel_error != 0)
				panic("%s: cannot cancel unpublished resource "
				    "runtime: %d", __func__, cancel_error);
			cancel_error = vmx_nested_context_cancel_entry(
			    &vcpu->nested, &entry_id);
			if (cancel_error != 0)
				panic("%s: cannot cancel unpublished resource "
				    "entry: %d", __func__, cancel_error);
			return (error);
		}
		vcpu->nested_vmcs12_snapshot = vmcs12_snapshot;
		vcpu->nested_entry_environment = entry_environment;
		vcpu->nested_vmcs02_plan = vmcs02_plan;
		vcpu->nested_l1_software_msrs = l1_software_msrs;
		vcpu->nested_l2_software_msrs = l2_software_msrs;
		vcpu->nested_vmcs02_resources = vmcs02_resources;
		vcpu->nested_msr_generation = msr_generation;
		vcpu->nested_entry_msr_count = entry_msr_count;
		vcpu->nested_vmcs02_plan_valid = true;
		return (0);
	}
	error = vmx_nested_context_commit_instruction(&vcpu->nested, &id,
	    true, &commit_ops, vcpu, &result);
	if (error != 0)
		return (error);
	if (result.disposition == VMX_NESTED_INSTRUCTION_HOST_ERROR)
		return (result.host_error);
	return (0);
}

const struct vmm_ops vmm_ops_intel = {
	.modinit	= vmx_modinit,
	.modcleanup	= vmx_modcleanup,
	.modsuspend	= vmx_modsuspend,
	.modresume	= vmx_modresume,
	.init		= vmx_init,
	.run		= vmx_run,
	.handle_internal_exit = vmx_handle_internal_exit,
	.cleanup	= vmx_cleanup,
	.vcpu_init	= vmx_vcpu_init,
	.startup_kernel_actions_ready = vmx_startup_kernel_actions_ready,
	.vcpu_startup_event_step = vmx_vcpu_startup_event_step,
	.vcpu_event_cleanup_check = vmx_vcpu_event_cleanup_check,
	.vcpu_event_cleanup = vmx_vcpu_event_cleanup,
	.vcpu_cleanup	= vmx_vcpu_cleanup,
	.getreg		= vmx_getreg,
	.setreg		= vmx_setreg,
	.getdesc	= vmx_getdesc,
	.setdesc	= vmx_setdesc,
	.getcap		= vmx_getcap,
	.setcap		= vmx_setcap,
	.get_cpu_compat = vmx_get_cpu_compat,
	.vmspace_alloc	= vmx_vmspace_alloc,
	.vmspace_free	= vmx_vmspace_free,
	.vlapic_init	= vmx_vlapic_init,
	.vlapic_cleanup	= vmx_vlapic_cleanup,
#ifdef BHYVE_SNAPSHOT
	.vm_snapshot	= vmx_vm_snapshot,
	.vcpu_snapshot	= vmx_vcpu_snapshot,
	.vm_snapshot_complete = vmx_vm_snapshot_complete,
	.restore_tsc	= vmx_restore_tsc,
#endif
};
